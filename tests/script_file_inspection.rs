//! Real-binary regressions for opt-in pre-execution script inspection.
//! Candidate programs are only passed to DCG as data, never executed.

use serde_json::{Value, json};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    config: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temp directory");
        let root = directory.path().canonicalize().expect("canonical cwd");
        let config = root.join("policy.toml");
        std::fs::write(
            &config,
            "[general]\nfail_closed = true\nunverified_decision = 'deny'\nself_heal_hook = false\n\
             [policy]\ndefault_mode = 'deny'\n\
             [heredoc]\nenabled = true\nscan_script_files = true\nfallback_on_parse_error = false\nfallback_on_timeout = false\n",
        )
        .expect("write policy");
        std::fs::create_dir(root.join("home")).expect("isolated home");
        Self {
            _directory: directory,
            root,
            config,
        }
    }

    fn write(&self, path: &str, contents: impl AsRef<[u8]>) {
        let path = self.root.join(path);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("fixture parents");
        std::fs::write(path, contents).expect("fixture source");
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_dcg"));
        for (key, _) in std::env::vars().filter(|(key, _)| key.starts_with("DCG_")) {
            command.env_remove(key);
        }
        command
            .current_dir(&self.root)
            .env("HOME", self.root.join("home"))
            .env("XDG_CONFIG_HOME", self.root.join("home/.config"))
            .env("DCG_CONFIG", &self.config)
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env("NO_COLOR", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn run(&self, candidate: &str) -> (Output, Value) {
        let mut child = self
            .command()
            .args([
                "--robot",
                "test",
                "--dialect",
                "posix",
                "--stdin",
                "--enforce-budget",
            ])
            .spawn()
            .expect("start evaluator");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(candidate.as_bytes())
            .expect("candidate as data");
        let output = child.wait_with_output().expect("evaluator output");
        let result = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "{error}: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        (output, result)
    }

    fn denied(&self, candidate: &str) -> Value {
        let (output, result) = self.run(candidate);
        assert_eq!(result["decision"], "deny", "{candidate}: {result}");
        assert_eq!(output.status.code(), Some(1), "{candidate}: {result}");
        result
    }

    fn allowed(&self, candidate: &str) {
        let (output, result) = self.run(candidate);
        assert_eq!(result["decision"], "allow", "{candidate}: {result}");
        assert!(output.status.success(), "{candidate}: {result}");
    }
}

#[test]
fn literal_and_wrapped_shell_launchers_inspect_the_file() {
    let fixture = Fixture::new();
    fixture.write("danger.sh", "#!/bin/sh\ngit reset --hard\n");
    for command in [
        "bash danger.sh",
        "sh ./danger.sh",
        "./danger.sh",
        "env TEST=1 bash danger.sh",
        "command bash danger.sh",
        "exec bash danger.sh",
        "exec -a test bash danger.sh",
        "timeout 5 bash danger.sh",
        "bash -c 'bash danger.sh'",
        "eval 'bash danger.sh'",
        "nice -n 5 bash danger.sh",
        "bash < danger.sh",
        "bash -s < danger.sh",
        "bash 0<danger.sh",
        "source ./danger.sh",
        ". ./danger.sh",
    ] {
        let result = fixture.denied(command);
        assert!(
            result["reason"]
                .as_str()
                .expect("reason")
                .contains("danger.sh"),
            "{command}: {result}"
        );
    }
}

#[test]
fn incident_wrapper_reaches_the_destructive_helper() {
    let fixture = Fixture::new();
    fixture.write(
        "scripts/test-serverbackup-delete.sh",
        "bash scripts/server-backup-delete.sh t /home/clawdbot//\n",
    );
    fixture.write(
        "scripts/server-backup-delete.sh",
        "target_dir=\"$2\"\nssh prod \"rm -rf -- \\\"$target_dir\\\"\"\n",
    );
    let result = fixture.denied("bash scripts/test-serverbackup-delete.sh");
    assert!(
        result["reason"]
            .as_str()
            .expect("reason")
            .contains("server-backup-delete.sh"),
        "{result}"
    );
}

#[test]
fn incident_find_cleanup_is_detected_inside_a_file() {
    let fixture = Fixture::new();
    fixture.write(
        "cleanup.sh",
        "false && T=$(mktemp -d); find $T -type f -delete\n",
    );
    let result = fixture.denied("bash cleanup.sh");
    assert!(
        result["reason"]
            .as_str()
            .expect("reason")
            .contains("cleanup.sh"),
        "{result}"
    );
}

#[test]
fn benign_scripts_and_quoted_documentation_remain_allowed() {
    let fixture = Fixture::new();
    fixture.write(
        "safe file.sh",
        "#!/bin/sh\nprintf '%s\\n' 'git reset --hard'\n",
    );
    fixture.write("wrapper.sh", "bash 'safe file.sh'\n");
    for command in [
        "bash 'safe file.sh'",
        "bash wrapper.sh",
        "printf '%s\\n' 'bash missing.sh'",
        "git status",
        "python3 -c 'print(42)'",
    ] {
        fixture.allowed(command);
    }
}

#[test]
fn python_and_javascript_files_use_existing_ast_rules() {
    let fixture = Fixture::new();
    fixture.write(
        "delete.py",
        "import shutil\nshutil.rmtree('/home/example')\n",
    );
    fixture.write(
        "delete.js",
        "const fs = require('fs');\nfs.rmSync('/home/example', {recursive: true, force: true});\n",
    );
    for command in [
        "python3 delete.py",
        "python3 -O delete.py",
        "node delete.js",
    ] {
        fixture.denied(command);
    }
    fixture.write("safe.py", "print('git reset --hard')\n");
    fixture.allowed("python3 safe.py");
    fixture.write("invalid.py", "git reset --hard\n");
    fixture.denied("python3 invalid.py");
}

#[test]
fn missing_dynamic_and_non_utf8_sources_fail_closed() {
    let fixture = Fixture::new();
    fixture.write("invalid.py", [0xff, 0xfe]);
    for command in [
        "bash missing.sh",
        "bash \"$SCRIPT\"",
        "bash scripts/*.sh",
        "python3 invalid.py",
        "source missing.sh",
        "python3 -m unknown_module",
    ] {
        let result = fixture.denied(command);
        assert_eq!(
            result["rule_id"], "heredoc.script_files:unverified",
            "{command}: {result}"
        );
    }
}

#[test]
fn a_local_namesake_cannot_authorize_a_remote_helper() {
    let fixture = Fixture::new();
    fixture.write("safe.sh", "printf safe\n");
    let result = fixture.denied("ssh prod 'bash ./safe.sh'");
    assert!(
        result["reason"]
            .as_str()
            .expect("reason")
            .contains("remote"),
        "{result}"
    );
    fixture.write("wrapper.sh", "ssh prod 'bash ./safe.sh'\n");
    fixture.denied("bash wrapper.sh");
}

#[test]
fn recursive_helper_cycles_and_depth_limits_fail_closed() {
    let fixture = Fixture::new();
    fixture.write("a.sh", "bash b.sh\n");
    fixture.write("b.sh", "bash a.sh\n");
    let result = fixture.denied("bash a.sh");
    assert!(
        result["reason"].as_str().expect("reason").contains("cycle"),
        "{result}"
    );
    for index in 0..10 {
        fixture.write(
            &format!("depth{index}.sh"),
            format!("bash depth{}.sh\n", index + 1),
        );
    }
    fixture.write("depth10.sh", "printf safe\n");
    fixture.denied("bash depth0.sh");
}

#[test]
fn oversized_files_fail_closed_without_truncation() {
    let fixture = Fixture::new();
    fixture.write("large.sh", "#".repeat(256 * 1024 + 1));
    let result = fixture.denied("bash large.sh");
    assert!(
        result["reason"]
            .as_str()
            .expect("reason")
            .contains("byte limit"),
        "{result}"
    );
}

#[cfg(unix)]
#[test]
fn symlink_files_and_directories_are_refused() {
    let fixture = Fixture::new();
    fixture.write("scripts/safe.sh", "printf safe\n");
    std::os::unix::fs::symlink(
        fixture.root.join("scripts/safe.sh"),
        fixture.root.join("link.sh"),
    )
    .expect("file symlink");
    std::os::unix::fs::symlink(fixture.root.join("scripts"), fixture.root.join("linked"))
        .expect("directory symlink");
    fixture.denied("bash link.sh");
    fixture.denied("bash linked/safe.sh");
}

#[test]
fn file_contents_are_rechecked_on_every_request() {
    let fixture = Fixture::new();
    fixture.write("changed.sh", "printf safe\n");
    fixture.allowed("bash changed.sh");
    fixture.write("changed.sh", "git reset --hard\n");
    fixture.denied("bash changed.sh");
}

#[test]
fn untrusted_project_config_cannot_disable_user_inspection() {
    let fixture = Fixture::new();
    fixture.write(".dcg.toml", "[heredoc]\nscan_script_files = false\n");
    fixture.write("danger.sh", "git reset --hard\n");
    fixture.denied("bash danger.sh");
}

#[test]
fn claude_and_codex_hook_protocols_deny_file_backed_commands() {
    let fixture = Fixture::new();
    fixture.write("danger.sh", "git reset --hard\n");
    for codex in [false, true] {
        let mut input = json!({"tool_name": "Bash", "tool_input": {"command": "bash danger.sh"}, "cwd": fixture.root});
        if codex {
            input["turn_id"] = json!("script-file-regression");
        }
        let mut child = fixture.command().spawn().expect("start hook");
        child
            .stdin
            .take()
            .expect("hook stdin")
            .write_all(input.to_string().as_bytes())
            .expect("hook payload");
        let output = child.wait_with_output().expect("hook result");
        let result: Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stderr)));
        assert_eq!(
            result["hookSpecificOutput"]["permissionDecision"], "deny",
            "{result}"
        );
        assert!(
            output.status.success(),
            "protocol denial exits zero: {result}"
        );
    }
}

#[test]
fn inspection_is_opt_in_for_existing_installations() {
    let fixture = Fixture::new();
    std::fs::write(&fixture.config, "[heredoc]\nscan_script_files = false\n").expect("opt out");
    fixture.allowed("bash missing.sh");
}

#[test]
fn package_scripts_and_lifecycle_hooks_follow_shell_helpers() {
    let fixture = Fixture::new();
    fixture.write("package.json", r#"{"scripts":{"safe":"printf safe","nested":"npm run safe","danger":"bash danger.sh","prebuild":"bash danger.sh","build":"printf build"}}"#);
    fixture.write("danger.sh", "git reset --hard\n");
    fixture.allowed("npm run safe");
    fixture.allowed("npm run nested");
    for command in [
        "npm run danger",
        "npm run build",
        "yarn danger",
        "pnpm run danger",
        "bun run danger",
    ] {
        fixture.denied(command);
    }
}

#[test]
fn make_recipes_follow_helpers_and_refuse_unresolved_expansion() {
    let fixture = Fixture::new();
    fixture.write("Makefile", "build:\n\t@printf safe\n");
    fixture.allowed("make build");
    fixture.write("danger.sh", "git reset --hard\n");
    fixture.write("Makefile", "build:\n\t@bash danger.sh\n");
    fixture.denied("make build");
    fixture.write("Makefile", "build:\n\t$(RUNNER) danger.sh\n");
    fixture.denied("make build");
}

#[test]
fn static_cd_and_environment_launchers_use_the_execution_directory() {
    let fixture = Fixture::new();
    fixture.write("sub/safe.sh", "[ -n yes ] && printf safe\n");
    fixture.write("sub/danger.sh", "git reset --hard\n");
    fixture.allowed("cd sub && bash safe.sh");
    fixture.denied("cd sub && bash danger.sh");
    fixture.denied("uv run bash sub/danger.sh");
    fixture.denied("uv run python3 sub/danger.sh");
    fixture.write("startup.sh", "git reset --hard\n");
    fixture.denied("BASH_ENV=./startup.sh bash sub/safe.sh");
    fixture.denied("env BASH_ENV=./startup.sh bash sub/safe.sh");
}

#[test]
fn preloads_and_runner_modes_cannot_skip_additional_sources() {
    let fixture = Fixture::new();
    fixture.write("safe.js", "console.log('safe');\n");
    fixture.write(
        "preload.js",
        "require('fs').rmSync('/home/example', {recursive: true});\n",
    );
    fixture.denied("node --require ./preload.js safe.js");
    fixture.denied("node --require=./preload.js safe.js");
    fixture.denied("node -r./preload.js safe.js");
    fixture.denied("node --test safe.js preload.js");
}

#[test]
fn file_and_total_byte_limits_fail_closed() {
    let fixture = Fixture::new();
    fixture.write("safe.sh", "printf safe\n");
    fixture.write("many.sh", "bash safe.sh\n".repeat(33));
    fixture.denied("bash many.sh");
    for index in 0..6 {
        fixture.write(
            &format!("part{index}.sh"),
            format!("# {}\nprintf safe\n", "a".repeat(200 * 1024)),
        );
    }
    fixture.write(
        "total.sh",
        (0..6)
            .map(|index| format!("bash part{index}.sh"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    fixture.denied("bash total.sh");
}

#[test]
fn inspection_remains_enabled_when_inline_scanning_is_configured_off() {
    let fixture = Fixture::new();
    fixture.write("policy.toml", "[general]\nunverified_decision = 'deny'\n[heredoc]\nenabled = false\nscan_script_files = true\n");
    fixture.denied("ssh prod 'bash ./missing.sh'");
}

#[test]
fn independent_task_shells_do_not_share_directory_changes() {
    let fixture = Fixture::new();
    fixture.write("sub/helper.sh", "printf safe\n");
    fixture.write("helper.sh", "git reset --hard\n");
    fixture.write(
        "package.json",
        r#"{"scripts":{"prebuild":"cd sub","build":"bash helper.sh"}}"#,
    );
    fixture.denied("npm run build");
    fixture.write("Makefile", "build:\n\tcd sub\n\tbash helper.sh\n");
    fixture.denied("make build");
    fixture.write(
        "Makefile",
        ".ONESHELL:\nbuild:\n\tcd sub\n\tbash helper.sh\n",
    );
    fixture.denied("make build");
}
