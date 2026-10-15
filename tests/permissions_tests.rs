//! Real-hook regressions for the opt-in permissions pack. Commands below are
//! JSON input data for dcg; no permission-changing command is ever executed.

use std::fmt::Write as _;
use std::io::Write;
use std::process::{Command, Stdio};

struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new(grants: &[&str]) -> Self {
        let dir = tempfile::tempdir().expect("fixture");
        let config_dir = dir.path().join("home/config/dcg");
        std::fs::create_dir_all(&config_dir).expect("isolated user config");
        std::fs::write(
            dir.path().join("config.toml"),
            "[history]\nenabled = false\n[packs]\nenabled = [\"system.permissions\"]\n",
        )
        .expect("config");
        let mut allowlist = String::new();
        for rule in grants {
            writeln!(
                allowlist,
                "[[allow]]\nrule = \"system.permissions:{rule}\"\nreason = \"test grant\""
            )
            .expect("allowlist entry");
        }
        std::fs::write(config_dir.join("allowlist.toml"), allowlist).expect("allowlist");
        Self { dir }
    }

    fn judge(&self, command: &str) -> (String, String) {
        let home = self.dir.path().join("home");
        let input = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": command },
            "cwd": self.dir.path(),
        });
        let mut child = Command::new(env!("CARGO_BIN_EXE_dcg"))
            .arg("hook")
            .env_clear()
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("APPDATA", home.join("config"))
            .env("LOCALAPPDATA", home.join("local"))
            .env("XDG_DATA_HOME", home.join("data"))
            .env("XDG_CACHE_HOME", home.join("cache"))
            .env("TMPDIR", self.dir.path())
            .env("TMP", self.dir.path())
            .env("TEMP", self.dir.path())
            .env("DCG_CONFIG", self.dir.path().join("config.toml"))
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env(
                "DCG_PENDING_EXCEPTIONS_PATH",
                self.dir.path().join("pending.jsonl"),
            )
            .env(
                "DCG_ALLOW_ONCE_PATH",
                self.dir.path().join("allow_once.jsonl"),
            )
            .env("DCG_SELF_HEAL_HOOK", "0")
            // These assert decisions, not latency. Keep scheduler load from
            // turning a regex fallback into an unrelated timeout decision.
            .env("DCG_HOOK_TIMEOUT_MS", "5000")
            .current_dir(self.dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn hook");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(input.to_string().as_bytes())
            .expect("hook payload");
        let output = child.wait_with_output().expect("hook result");
        assert_eq!(
            output.status.code(),
            Some(0),
            "{command:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if output.stdout.is_empty() {
            return ("allow".to_string(), String::new());
        }
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("hook JSON");
        let hook = &json["hookSpecificOutput"];
        (
            hook["permissionDecision"]
                .as_str()
                .expect("decision")
                .to_string(),
            hook["ruleId"].as_str().unwrap_or_default().to_string(),
        )
    }

    fn denied(&self, command: &str, rule: &str) {
        assert_eq!(
            self.judge(command),
            ("deny".to_string(), format!("system.permissions:{rule}")),
            "{command:?}"
        );
    }

    fn allowed(&self, command: &str) {
        assert_eq!(self.judge(command).0, "allow", "{command:?}");
    }
}

#[test]
fn recursive_options_are_recognized_in_bundles_and_after_operands() {
    let fixture = Fixture::new(&[]);
    for command in [
        "chmod --recursive 755 /etc",
        "chmod 755 --recursive /etc",
        "chmod 755 file -R /etc",
        "chmod 755 /etc -vR",
        "chmod -vR 755 /etc",
        "chmod -Rv 755 /etc",
        "chmod --rec 755 /etc",
        "sudo -u stat /usr/bin/chmod -fvR 755 /etc",
    ] {
        fixture.denied(command, "chmod-recursive-root");
    }
    for command in ["chown -vR nobody /etc", "chown nobody /etc -fRv"] {
        fixture.denied(command, "chown-recursive-root");
    }
    for command in ["chgrp -vR nogroup /etc", "chgrp nogroup /etc --recursive"] {
        fixture.denied(command, "chgrp-recursive-root");
    }
}

#[test]
fn every_chmod_target_must_qualify_for_the_relative_file_exemption() {
    let fixture = Fixture::new(&[]);
    for command in [
        "chmod 777 notes /etc/shadow",
        "chmod 777 /etc/shadow notes",
        "chmod 777 ./notes ~/.ssh/id_rsa",
        "chmod 777 notes $HOME/.ssh/id_rsa",
        "chmod 777 notes \"/etc/shadow\"",
        "chmod 777 -- harmless /etc/shadow",
        "chmod 777 notes \"$extra_targets\"",
        "chmod 0777 /etc",
    ] {
        fixture.denied(command, "chmod-777");
    }
    fixture.denied("chmod 4755 notes ~/bin/tool", "chmod-setuid");
    fixture.denied("chmod 2755 notes /usr/bin/tool", "chmod-setgid");
}

#[test]
fn safe_looking_reference_values_cannot_exempt_the_running_command() {
    let fixture = Fixture::new(&[]);
    for (command, rule) in [
        (
            "chmod -R --reference=\"chmod 777 notes\" /etc",
            "chmod-recursive-root",
        ),
        (
            "chmod --reference 'chmod 777 notes' /etc -vR",
            "chmod-recursive-root",
        ),
        (
            "chown -vR --reference=\"chmod 777 notes\" /etc",
            "chown-recursive-root",
        ),
        (
            "chgrp -vR --reference 'chmod 777 notes' /etc",
            "chgrp-recursive-root",
        ),
        (
            "chmod -vR --reference=\"/opt/a&b\" /etc",
            "chmod-recursive-root",
        ),
        ("chown -vR --from=root nobody /etc", "chown-recursive-root"),
    ] {
        fixture.denied(command, rule);
    }
}

#[test]
fn option_values_and_arguments_after_double_dash_keep_their_roles() {
    let fixture = Fixture::new(&[]);
    for command in [
        "chmod 644 ./notes -- -R /etc",
        "chmod -- -r /etc",
        "chmod --reference='-vR' /etc",
        "chmod -vR --reference=/etc/passwd ./project",
        "chmod -R --reference /etc harmless",
        "chown -vR --reference=/etc/passwd ./project",
        "chown --from=-vR nobody /etc",
        "chown --from root nobody /tmp/file",
        "chgrp --reference '-vR' /etc",
        "chgrp staff -- -vR /etc",
    ] {
        fixture.allowed(command);
    }
}

#[test]
fn routine_relative_files_and_home_project_carve_outs_are_preserved() {
    let fixture = Fixture::new(&[]);
    for command in [
        "chmod 644 file_777",
        "chmod -R 644 file_777",
        "chmod 777 notes.txt",
        "chmod 4755 notes.txt",
        "chmod u+x ./script.sh",
        "chmod 644 notes /etc/shadow",
        "chmod 600 ~/.ssh/id_rsa",
        "chmod -vR 755 /home/user/project",
        "chmod -vR 755 ~/project",
        "chmod -vR 755 $HOME/project",
        "chown -vR nobody /home/user/project",
        "chgrp -vR staff /Users/user/project",
        "chmod -vR 000 '~'",
        "chmod -vR 000 '$HOME'",
    ] {
        fixture.allowed(command);
    }
    fixture.denied("chmod -vR 000 ~", "chmod-recursive-root");
    fixture.denied("chown -vR nobody \"$HOME\"", "chown-recursive-root");
    fixture.denied("chgrp -vR staff /Users/user", "chgrp-recursive-root");
}

#[test]
fn granting_one_permissions_rule_does_not_grant_an_independent_hit() {
    let world_writable_grant = Fixture::new(&["chmod-777"]);
    world_writable_grant.denied("chmod -vR 777 /etc", "chmod-recursive-root");
    world_writable_grant.allowed("chmod 777 /tmp/file");

    let setuid_grant = Fixture::new(&["chmod-setuid"]);
    setuid_grant.denied("chmod 6755 /etc/file", "chmod-setgid");
    setuid_grant.allowed("chmod 4755 /tmp/file");

    let both_grants = Fixture::new(&["chmod-777", "chmod-recursive-root"]);
    both_grants.allowed("chmod -vR 777 /etc");
    both_grants.denied("chown -vR nobody /etc", "chown-recursive-root");
}

#[test]
fn fallback_and_compound_commands_do_not_restore_the_old_exemption() {
    let fixture = Fixture::new(&[]);
    fixture.denied(
        "chmod -vR $(cat modes.txt | head -1) /etc",
        "chmod-recursive-root",
    );
    fixture.denied("true && chmod 755 notes -vR /etc", "chmod-recursive-root");
    fixture.denied("chmod 755 notes; chmod 777 /etc/shadow", "chmod-777");
    fixture.allowed("chmod 600 /root/key; grep -R foo /etc");
    fixture.allowed("printf '%s' 'chmod -vR 755 /etc'");
}

#[test]
fn fallback_keeps_decoding_the_executable_without_proving_safety_from_masked_argv() {
    let fixture = Fixture::new(&[]);
    for executable in [r"ch$'mod'", "'chmod'", "ch\"mod\"", r"ch\mod"] {
        fixture.denied(
            &format!("{executable} -R 755 /etc \"$extra_targets\""),
            "chmod-recursive-root",
        );
        fixture.denied(
            &format!("{executable} 777 notes \"$extra_targets\""),
            "chmod-777",
        );
    }
    fixture.denied("ch$'mod' 777 /etc/shadow", "chmod-777");
    fixture.denied("ch$'own' -R nobody /etc", "chown-recursive-root");
    fixture.denied("ch$'grp' -R staff /etc", "chgrp-recursive-root");
    fixture.denied(
        "sudo -u stat '/usr/bin/chmod' -R 755 /etc \"$extra_targets\"",
        "chmod-recursive-root",
    );
    fixture.allowed("ch$'mod' 600 /root/key; grep -R foo /etc");
    fixture.allowed(r#"printf '%s' "ch\$'mod' -R 755 /etc""#);
}

#[test]
fn protected_aliases_are_enforced_by_the_real_hook() {
    let fixture = Fixture::new(&[]);
    for (executable, operand, rule) in [
        ("chmod", "000", "chmod-recursive-root"),
        ("chown", "nobody", "chown-recursive-root"),
        ("chgrp", "nogroup", "chgrp-recursive-root"),
    ] {
        for target in [
            "/./etc",
            "/tmp/../etc",
            "/home//user",
            "/home/user/project/..",
            "/Users/user/project/..",
            "~/project/..",
            "$HOME/project/..",
            "\"${HOME}/project/..\"",
        ] {
            fixture.denied(&format!("{executable} -R {operand} {target}"), rule);
        }
        for target in [
            "/home/user/project/src/..",
            "~/project/src/..",
            "'$HOME/project/..'",
            "\"~/project/..\"",
        ] {
            fixture.allowed(&format!("{executable} -R {operand} {target}"));
        }
    }
}

#[test]
fn setfacl_hook_tracks_bundled_flags_and_acl_value_roles() {
    let fixture = Fixture::new(&[]);
    for command in [
        "setfacl -bR /tmp/../etc",
        "setfacl --rec --remove-all /home/user/project/..",
        "setfacl -R --modify=u:app:rwx /etc",
        "setfacl -R --remove=u:app /etc",
        "setfacl -RM--test /etc",
        "setfacl --recursive --modify-file=--test /etc",
        "sudo -n /usr/bin/setfacl -bR /./etc",
        "'setfacl' -Rb \"/etc\"",
    ] {
        fixture.denied(command, "setfacl-all");
    }
    for command in [
        "setfacl -M -R /etc",
        "setfacl -M-R /etc",
        "setfacl -R -M /etc/acl ./project",
        "setfacl -R --modify-file '/etc/-R --test' ./project",
        "setfacl -b -- -R /etc",
        "setfacl -Rb /home/user/project",
        "setfacl -Rb '$HOME/project/..'",
        "setfacl -Rb \"~/project/..\"",
    ] {
        fixture.allowed(command);
    }
}

#[test]
fn setfacl_hook_keeps_prior_mutations_when_later_options_terminate_or_test() {
    let fixture = Fixture::new(&[]);
    for prefix in ["setfacl -Rb /etc", "setfacl -bR /tmp/../etc"] {
        for suffix in [
            " --test",
            " --help",
            " --version",
            " --unknown",
            " --restore=/tmp/backup",
            " -M",
            " --test=invalid",
        ] {
            fixture.denied(&format!("{prefix}{suffix}"), "setfacl-all");
        }
    }
    for command in [
        "setfacl --test -Rb /etc",
        "setfacl -hRb /etc",
        "setfacl --version -bR /tmp/../etc",
        "setfacl -b /etc --test -Rb /etc",
    ] {
        fixture.allowed(command);
    }
}

#[test]
fn setfacl_hook_preserves_operation_order_and_compound_boundaries() {
    let fixture = Fixture::new(&[]);
    for command in [
        "setfacl -b ./project -R -b /etc",
        "setfacl -Rb ./project -P -b /etc",
        "setfacl -Rb ./project -- --test /etc",
        "true && setfacl -bR /tmp/../etc",
        "setfacl --test -Rb /etc; setfacl -Rb /etc",
        "setfacl -bR /tmp/../etc; setfacl --test -Rb /etc",
    ] {
        fixture.denied(command, "setfacl-all");
    }
    for command in [
        "setfacl -b ./project -R /etc",
        "setfacl --test -Rb ./project -P /etc",
        "setfacl /tmp/file -Rb /etc",
        "setfacl --test -Rb /etc; printf done",
        "printf '%s' 'setfacl -Rb /etc'",
    ] {
        fixture.allowed(command);
    }
}

#[test]
fn setfacl_rule_grants_do_not_exempt_other_permission_effects() {
    let acl_grant = Fixture::new(&["setfacl-all"]);
    acl_grant.allowed("setfacl -bR /tmp/../etc");
    for command in [
        "chmod -R 000 /etc",
        "setfacl -Rb /etc; chmod -R 000 /etc",
        "chmod -R 000 /etc; setfacl -Rb /etc",
    ] {
        acl_grant.denied(command, "chmod-recursive-root");
    }

    let chmod_grant = Fixture::new(&["chmod-recursive-root"]);
    chmod_grant.allowed("chmod -R 000 /tmp/../etc");
    for command in ["setfacl -Rb /etc", "chmod -R 000 /etc; setfacl -Rb /etc"] {
        chmod_grant.denied(command, "setfacl-all");
    }

    let both_grants = Fixture::new(&["setfacl-all", "chmod-recursive-root"]);
    both_grants.allowed("setfacl -Rb /etc; chmod -R 000 /etc");
    both_grants.denied(
        "setfacl -Rb /etc; chmod -R 000 /etc; chown -R nobody /etc",
        "chown-recursive-root",
    );
}

#[test]
fn setfacl_hook_does_not_assume_gnu_ordering_for_bsd_operands() {
    let fixture = Fixture::new(&[]);
    for command in [
        "setfacl -Rb ./project -P /etc",
        "setfacl -Rb ./project --test -b /etc",
        "setfacl -Rb ./project --help /etc",
        "setfacl -Rb ./project --version /etc",
        "setfacl -Rb ./project -M /tmp/../etc",
        "setfacl -HRb /etc",
        "setfacl -Rb ./project --restore=/tmp/backup /etc",
    ] {
        fixture.denied(command, "setfacl-all");
    }
    for command in [
        "setfacl --test -Rb ./project -P /etc",
        "setfacl --help -Rb /etc",
        "setfacl -hRb /etc",
        "setfacl -Rb ./project -P ./second",
        "setfacl -R -M /etc/acl ./project",
    ] {
        fixture.allowed(command);
    }
}

#[test]
fn symbolic_special_bits_survive_mode_order_and_unresolved_tails() {
    let fixture = Fixture::new(&[]);
    for (mode, rule) in [
        ("u+s", "chmod-setuid"),
        ("u+xs", "chmod-setuid"),
        ("u+rws", "chmod-setuid"),
        ("g+s", "chmod-setgid"),
        ("g+xs", "chmod-setgid"),
        ("g+rs", "chmod-setgid"),
        ("a+s", "chmod-setuid"),
        ("+s", "chmod-setuid"),
        ("a+xs", "chmod-setuid"),
    ] {
        for suffix in ["", " \"$EXTRA\""] {
            fixture.denied(&format!("chmod {mode} /tmp/file{suffix}"), rule);
        }
    }
    for command in [
        "chmod u-s /tmp/file",
        "chmod g-s /tmp/file",
        "chmod a-s /tmp/file",
        "chmod o+s /tmp/file",
        "chmod u+x /tmp/file",
        "chmod u+xs ./file",
    ] {
        fixture.allowed(command);
    }
}

#[test]
fn unresolved_tails_do_not_drop_recursive_alias_or_bundle_checks() {
    let fixture = Fixture::new(&[]);
    for (command, rule) in [
        ("chmod -R 000 /tmp/../etc", "chmod-recursive-root"),
        ("chmod -R 000 /./etc", "chmod-recursive-root"),
        ("chown -R nobody /tmp/../etc", "chown-recursive-root"),
        ("chgrp -R staff /home//user", "chgrp-recursive-root"),
        ("setfacl -bR /etc", "setfacl-all"),
        ("setfacl -bR /tmp/../etc", "setfacl-all"),
        ("setfacl -R -b ~/project/..", "setfacl-all"),
        ("setfacl -R -b \"${HOME}/project/..\"", "setfacl-all"),
    ] {
        for suffix in [" \"$EXTRA\"", " $EXTRA"] {
            fixture.denied(&format!("{command}{suffix}"), rule);
        }
    }
    fixture.denied(
        "true && chmod -R 000 /tmp/../etc \"$EXTRA\"",
        "chmod-recursive-root",
    );
    fixture.denied("'setfacl' -bR /tmp/../etc \"$EXTRA\"", "setfacl-all");
}

#[test]
fn independent_special_bit_grants_remain_separate_in_the_fallback() {
    let recursive_grant = Fixture::new(&["chmod-recursive-root"]);
    recursive_grant.denied("chmod -R 6755 /tmp/../etc \"$EXTRA\"", "chmod-setuid");
    let recursive_uid_grant = Fixture::new(&["chmod-recursive-root", "chmod-setuid"]);
    recursive_uid_grant.denied("chmod -R 6755 /tmp/../etc \"$EXTRA\"", "chmod-setgid");

    let uid_grant = Fixture::new(&["chmod-setuid"]);
    let gid_grant = Fixture::new(&["chmod-setgid"]);
    let both_grants = Fixture::new(&["chmod-setuid", "chmod-setgid"]);
    for mode in ["a+s", "+s", "a+xs"] {
        for suffix in ["", " \"$EXTRA\""] {
            let command = format!("chmod {mode} /tmp/file{suffix}");
            uid_grant.denied(&command, "chmod-setgid");
            gid_grant.denied(&command, "chmod-setuid");
        }
        // A complete invocation may use both exact grants. Do not infer the
        // same safety from an incomplete list of effects in a truncated argv.
        both_grants.allowed(&format!("chmod {mode} /tmp/file"));
    }
    both_grants.denied("chmod -R 6755 /tmp/../etc", "chmod-recursive-root");
}

#[test]
fn complete_permission_operands_retain_scope_and_inert_data_roles() {
    let fixture = Fixture::new(&[]);
    for command in [
        "chmod -R 755 /tmp/./project",
        "chown -R nobody /tmp/project/..",
        "chgrp -R staff /home/user/project/src/..",
        "setfacl -Rb /tmp//project",
        "chmod u+xs ./file",
        "chmod u-s /tmp/file",
        "printf '%s' 'setfacl -bR /tmp/../etc \"$EXTRA\"'",
        "printf '%s' 'chmod a+s /tmp/file'",
    ] {
        fixture.allowed(command);
    }
}
