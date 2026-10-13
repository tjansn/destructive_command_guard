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
        command
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .current_dir(&self.root)
            .env("HOME", self.root.join("home"))
            .env("USERPROFILE", self.root.join("home"))
            .env("XDG_CONFIG_HOME", self.root.join("home/.config"))
            .env("TMPDIR", &self.root)
            .env("TEMP", &self.root)
            .env("TMP", &self.root)
            .env("DCG_CONFIG", &self.config)
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("DCG_HISTORY_DISABLED", "1")
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

    fn unverified(&self, candidate: &str) {
        let result = self.denied(candidate);
        assert_eq!(
            result["rule_id"], "heredoc.script_files:unverified",
            "{candidate}: {result}"
        );
    }

    fn destructive(&self, candidate: &str, source: &str) {
        let result = self.denied(candidate);
        let rule = result["rule_id"].as_str().expect("destructive rule id");
        assert!(
            !rule.is_empty() && rule != "heredoc.script_files:unverified",
            "{candidate}: {result}"
        );
        assert!(
            result["reason"].as_str().expect("reason").contains(source),
            "missing source {source}: {candidate}: {result}"
        );
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
fn syntax_only_operands_are_data_but_execution_and_siblings_are_inspected() {
    let fixture = Fixture::new();
    fixture.write("danger.sh", "git reset --hard\n");
    fixture.allowed("/bin/bash -n danger.sh");
    fixture.denied("/bin/bash danger.sh");
    fixture.denied("/bin/bash -n danger.sh; git reset --hard");
    fixture.denied("/bin/bash -n +n danger.sh");
    fixture.denied("/bin/bash -nc 'git reset --hard'");
    fixture.write("node", "#!/bin/sh\ngit reset --hard\n");
    fixture.write(
        "danger.js",
        "require('child_process').execSync('git reset --hard');\n",
    );
    fixture.denied("./node --check danger.js");
    fixture.denied("env NODE_OPTIONS=--require=./danger.js node --check danger.js");
    fixture.denied("NODE_OPTIONS=--require=./danger.js node --check danger.js");
    if std::path::Path::new("/opt/homebrew/bin/node").exists() {
        // No candidate is run. A huge syntax operand must not consume AST/file budgets.
        fixture.write(
            "large.js",
            "require('child_process').execSync('git reset --hard');\n".repeat(10_000),
        );
        fixture.allowed("/opt/homebrew/bin/node --check large.js");
        fixture.denied("/opt/homebrew/bin/node danger.js");
        fixture.denied("/opt/homebrew/bin/node --require ./danger.js --check large.js");
    }
}

#[test]
fn builtin_queries_do_not_execute_the_operand_but_substitutions_and_shadowing_do() {
    let fixture = Fixture::new();
    fixture.allowed("command -v dcg");
    fixture.allowed("command -V orca");
    fixture.allowed("command -p -v orca");
    fixture.denied("command git reset --hard");
    fixture.denied("command -v \"$(git reset --hard)\"");
    fixture.denied("command() { git reset --hard; }; command -v dcg");
    fixture.denied("alias command='git reset --hard'; command -v dcg");
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
fn desktop_review_keeps_safe_unverified_and_multi_entry_protocols_closed() {
    let fixture = Fixture::new();
    for (candidate, batch, invalid_cwd, expected, review_reason) in [
        ("printf safe", false, false, "allow", ""),
        (
            "bash missing.sh",
            false,
            false,
            "deny",
            "Die Prüfung ist unvollständig",
        ),
        (
            "git reset --hard HEAD",
            true,
            false,
            "deny",
            "mehrere Befehle",
        ),
        (
            "git reset --hard HEAD",
            false,
            true,
            "deny",
            "kein gültiger absoluter Arbeitsordner",
        ),
    ] {
        let mut input = json!({
            "turn_id": "desktop-review-regression",
            "tool_name": "Bash", "tool_input": {"command": candidate},
            "cwd": fixture.root, "dcg_explicit_verdict": true,
        });
        if invalid_cwd {
            input["cwd"] = json!("relative-directory");
        }
        if batch {
            input["toolCalls"] = json!([
                {"name": "Bash", "args": {"command": "git clean -fd"}}
            ]);
        }
        let mut child = fixture
            .command()
            .arg("--desktop-review")
            .spawn()
            .expect("start hook");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(input.to_string().as_bytes())
            .expect("payload");
        let output = child.wait_with_output().expect("hook output");
        let verdict: Value = serde_json::from_slice(&output.stdout).expect("single valid verdict");
        if expected == "allow" {
            assert_eq!(verdict["dcg_verdict"], "allow");
        } else {
            assert_eq!(verdict["hookSpecificOutput"]["permissionDecision"], "deny");
            assert!(
                verdict["hookSpecificOutput"]["permissionDecisionReason"]
                    .as_str()
                    .expect("blocking reason")
                    .contains(review_reason),
                "missing review diagnostic: {verdict}"
            );
        }
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("Warte auf"),
            "unexpected dialog: {candidate}"
        );
    }
}

#[test]
fn codex_workdir_override_cannot_use_a_safe_session_namesake() {
    let fixture = Fixture::new();
    fixture.write("same.sh", "printf harmless\n");
    fixture.write("other/same.sh", "git reset --hard HEAD\n");
    for workdir in [
        json!(fixture.root.join("other")),
        json!(42),
        json!("relative"),
    ] {
        let input = json!({
            "turn_id": "execution-directory-regression", "tool_name": "Bash",
            "tool_input": {"command": "bash same.sh", "workdir": workdir},
            "cwd": fixture.root,
        });
        let mut child = fixture.command().spawn().expect("start hook");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(input.to_string().as_bytes())
            .expect("payload");
        let output = child.wait_with_output().expect("hook output");
        let verdict: Value = serde_json::from_slice(&output.stdout).expect("valid verdict");
        assert_eq!(verdict["hookSpecificOutput"]["permissionDecision"], "deny");
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
fn finite_node_tests_inspect_explicit_files_and_local_globs() {
    let fixture = Fixture::new();
    fixture.write("tests/first.test.js", "console.log('first');\n");
    fixture.write("tests/second.test.js", "console.log('second');\n");
    fixture.write("tests/nested/third.test.js", "console.log('third');\n");
    // Discovery must only include the explicit finite selection.
    fixture.write(
        "tests/unselected.js",
        "require('child_process').execSync('git reset --hard');\n",
    );
    for candidate in [
        "node --test tests/first.test.js",
        "node --test tests/first.test.js tests/second.test.js",
        "node --test tests/*.test.js",
        "node --test 'tests/*.test.js'",
        "node --test tests/nested/*.test.js",
    ] {
        fixture.allowed(candidate);
    }
    fixture.unverified("node --test tests/missing*.test.js");
}

#[test]
fn finite_node_test_selection_rechecks_changed_test_bytes() {
    let fixture = Fixture::new();
    fixture.write("tests/changed.test.js", "console.log('safe');\n");
    for candidate in [
        "node --test tests/changed.test.js",
        "node --test 'tests/*.test.js'",
    ] {
        fixture.allowed(candidate);
    }
    fixture.write(
        "tests/changed.test.js",
        "require('child_process').execSync('git reset --hard');\n",
    );
    for candidate in [
        "node --test tests/changed.test.js",
        "node --test 'tests/*.test.js'",
    ] {
        fixture.destructive(candidate, "changed.test.js");
    }
}

#[cfg(target_os = "macos")]
#[test]
fn finite_hook_rewrites_only_capable_hosts_and_never_executes_during_the_hook() {
    use destructive_command_guard::confined::Request;
    let fixture = Fixture::new();
    fixture.write(
        "once.test.js",
        "require('node:fs').writeFileSync('executed-marker', 'ran');\n",
    );
    for (agent, capable, rewrite) in [
        ("claude-code", false, true),
        ("pi", true, true),
        ("pi", false, false),
        ("codex-cli", false, false),
        ("opencode", false, false),
    ] {
        let mut input = json!({"tool_name":"Bash", "tool_input":{"command":"node --test once.test.js", "description":"preserve me", "timeout":600_000}, "cwd":fixture.root, "dcg_explicit_verdict":true, "dcg_input_rewrite":capable});
        if agent == "codex-cli" {
            input["turn_id"] = json!("confined-fixture");
        }
        let mut child = fixture.command().args(["--agent", agent]).spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.to_string().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            output["dcg_verdict"],
            if rewrite { "confined" } else { "allow" },
            "{agent}: {output}"
        );
        if rewrite {
            let updated = &output["hookSpecificOutput"]["updatedInput"];
            assert_eq!(updated["description"], "preserve me");
            assert_eq!(updated["timeout"], 600_000);
            let words = shell_words::split(updated["command"].as_str().unwrap()).unwrap();
            let request = Request::decode(words.last().unwrap()).unwrap();
            assert_eq!(request.command, "node --test once.test.js");
            assert_eq!(request.cwd, fixture.root);
        }
        assert!(!fixture.root.join("executed-marker").exists());
        assert!(!fixture.root.join("home/.config/dcg/trials").exists());
    }
}

#[cfg(target_os = "macos")]
#[test]
fn leading_literal_cd_rewrites_from_the_resolved_directory_without_executing() {
    use destructive_command_guard::confined::Request;
    let fixture = Fixture::new();
    fixture.write(
        "nested dir/once.test.js",
        "require('node:fs').writeFileSync('executed-marker', 'ran');\n",
    );
    for candidate in [
        "cd 'nested dir' && node --test once.test.js".to_owned(),
        format!(
            "cd -- {} && node --test once.test.js",
            shell_words::quote(fixture.root.join("nested dir").to_str().unwrap())
        ),
    ] {
        let input = json!({"tool_name":"Bash", "tool_input":{"command":candidate, "timeout":600_000}, "cwd":fixture.root});
        let mut child = fixture
            .command()
            .args(["--agent", "claude-code"])
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.to_string().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        let output: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(output["dcg_verdict"], "confined", "{candidate}: {output}");
        let words = shell_words::split(
            output["hookSpecificOutput"]["updatedInput"]["command"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let request = Request::decode(words.last().unwrap()).unwrap();
        assert_eq!(request.command, candidate);
        assert_eq!(request.cwd, fixture.root);
        assert!(!fixture.root.join("nested dir/executed-marker").exists());
    }
}

#[test]
fn literal_env_diagnostics_offer_bound_review_without_a_command_only_code() {
    let fixture = Fixture::new();
    let result = fixture.denied("env -i HOME=/tmp/fixture PATH=/usr/bin:/bin cargo test");
    let text = result.to_string();
    assert!(text.contains("bound-input-review"), "{text}");
    assert!(text.contains("no reusable trial approval"), "{text}");
    assert!(
        !text.contains("command-local PATH requires desktop review"),
        "{text}"
    );
    assert!(!text.contains("dcg trial run"), "{text}");
    for candidate in [
        "env -i HOME=$HOME PATH=/bin cargo test",
        "env -i HOME=$(pwd) PATH=/bin cargo test",
    ] {
        let text = fixture.denied(candidate).to_string();
        assert!(!text.contains("bound-input-review"), "{text}");
    }
}

#[cfg(unix)]
#[test]
fn literal_environment_does_not_hide_a_definite_script_denial() {
    let fixture = Fixture::new();
    fixture.write(
        "scripts/check.js",
        "require('fs').rmSync('/home/fixture/valuable', {recursive: true, force: true});\n",
    );
    for candidate in [
        "node scripts/check.js",
        "env -i HOME=/tmp/h PATH=/usr/bin:/bin node scripts/check.js",
        "PATH=/usr/bin:/bin node scripts/check.js",
        "env -i HOME=/tmp/h PATH=/usr/bin:/bin node < scripts/check.js",
    ] {
        fixture.destructive(candidate, "scripts/check.js");
    }
}

#[cfg(unix)]
#[test]
fn relative_and_empty_literal_path_entries_cannot_reach_bound_review() {
    let fixture = Fixture::new();
    fixture.write("scripts/check.js", "console.log('safe');\n");
    for path in ["", ".:/usr/bin", ":/usr/bin", "bin:/usr/bin", "/usr/bin:"] {
        let result = fixture.denied(&format!(
            "env -i HOME=/tmp/h PATH={path} node scripts/check.js"
        ));
        let text = result.to_string();
        assert!(text.contains("non-empty absolute directories"), "{text}");
        assert!(!text.contains("bound-input-review"), "{text}");
    }
}

#[cfg(target_os = "macos")]
#[test]
fn definite_findings_cannot_be_hidden_by_a_finite_rewrite() {
    let fixture = Fixture::new();
    fixture.write(
        "danger.test.js",
        "require('child_process').execSync('git reset --hard');\n",
    );
    for candidate in [
        "node --test danger.test.js",
        "cd . && node --test danger.test.js",
    ] {
        let input =
            json!({"tool_name":"Bash","tool_input":{"command":candidate},"cwd":fixture.root});
        let mut child = fixture
            .command()
            .args(["--agent", "claude-code"])
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.to_string().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        let output: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            output["hookSpecificOutput"]["permissionDecision"], "deny",
            "{output}"
        );
        assert!(output["hookSpecificOutput"].get("updatedInput").is_none());
    }
}

#[test]
fn finite_node_imports_resolve_relative_to_the_importing_file() {
    let fixture = Fixture::new();
    // A safe cwd namesake must not replace the source next to the importer.
    fixture.write("helper.js", "console.log('unrelated safe file');\n");
    for source in [
        "import './helper.js';\n",
        "export { value } from './helper.js';\n",
        "const helper = require('./helper.js');\n",
        "import('./helper.js');\n",
    ] {
        fixture.write("tests/entry.test.js", source);
        fixture.write("tests/helper.js", "export const value = 42;\n");
        fixture.allowed("node --test tests/entry.test.js");
        fixture.write(
            "tests/helper.js",
            "require('child_process').execSync('git reset --hard');\n",
        );
        fixture.destructive("node --test tests/entry.test.js", "helper.js");
    }
}

#[test]
fn finite_node_child_helpers_are_inspected_and_computed_children_are_unverified() {
    let fixture = Fixture::new();
    fixture.write(
        "entry.test.js",
        "require('child_process').execFileSync('/bin/bash', ['./helper.sh']);\n",
    );
    fixture.write("helper.sh", "printf safe\n");
    fixture.allowed("node --test entry.test.js");
    fixture.write("helper.sh", "git reset --hard\n");
    fixture.destructive("node --test entry.test.js", "helper.sh");
    for source in [
        "require('child_process').execFileSync(process.env.RUNNER, ['./helper.sh']);\n",
        "require('child_process').execFileSync('/bin/bash', [process.env.HELPER]);\n",
        "require('child_process').execSync(process.env.COMMAND);\n",
    ] {
        fixture.write("entry.test.js", source);
        fixture.unverified("node --test entry.test.js");
    }
}

#[test]
fn finite_node_preloads_are_executable_in_separate_and_attached_forms() {
    let fixture = Fixture::new();
    fixture.write("entry.test.js", "console.log('safe');\n");
    for candidate in [
        "node --require ./preload.js --test entry.test.js",
        "node --require=./preload.js --test entry.test.js",
        "node -r ./preload.js --test entry.test.js",
        "node -r./preload.js --test entry.test.js",
        "node --import ./preload.js --test entry.test.js",
        "node --import=./preload.js --test entry.test.js",
    ] {
        fixture.write("preload.js", "console.log('safe preload');\n");
        fixture.allowed(candidate);
        fixture.write(
            "preload.js",
            "require('child_process').execSync('git reset --hard');\n",
        );
        fixture.destructive(candidate, "preload.js");
    }
}

#[test]
fn finite_node_custom_reporters_are_executable_sources() {
    let fixture = Fixture::new();
    fixture.write("entry.test.js", "console.log('safe');\n");
    for reporter in ["spec", "dot", "tap"] {
        fixture.allowed(&format!(
            "node --test --test-reporter {reporter} entry.test.js"
        ));
        fixture.allowed(&format!(
            "node --test --test-reporter={reporter} entry.test.js"
        ));
    }
    for candidate in [
        "node --test --test-reporter ./reporter.js entry.test.js",
        "node --test --test-reporter=./reporter.js entry.test.js",
    ] {
        fixture.write(
            "reporter.js",
            "export default async function* reporter(source) { for await (const event of source) { yield 'ok'; } }\n",
        );
        fixture.allowed(candidate);
        fixture.write(
            "reporter.js",
            "require('child_process').execSync('git reset --hard');\n",
        );
        fixture.destructive(candidate, "reporter.js");
    }
    for candidate in [
        "node --test --test-reporter dcg-fixture-reporter entry.test.js",
        "node --test --test-reporter=dcg-fixture-reporter entry.test.js",
    ] {
        fixture.unverified(candidate);
    }
}

#[test]
fn npm_finite_tests_inspect_pre_main_and_post_lifecycle_sources() {
    let fixture = Fixture::new();
    fixture.write(
        "package.json",
        r#"{"scripts":{"pretest":"bash before.sh","test":"node --test tests/entry.test.js","posttest":"bash after.sh"}}"#,
    );
    for changed in ["before.sh", "tests/entry.test.js", "after.sh"] {
        fixture.write("before.sh", "printf before\n");
        fixture.write("tests/entry.test.js", "console.log('test');\n");
        fixture.write("after.sh", "printf after\n");
        fixture.allowed("npm test");
        fixture.allowed("npm run test");
        fixture.write(
            changed,
            if std::path::Path::new(changed)
                .extension()
                .is_some_and(|extension| extension == "js")
            {
                "require('child_process').execSync('git reset --hard');\n"
            } else {
                "git reset --hard\n"
            },
        );
        fixture.destructive("npm test", changed);
        fixture.destructive("npm run test", changed);
    }
}

#[test]
fn unresolved_node_runner_modes_and_dependencies_remain_unverified() {
    let fixture = Fixture::new();
    fixture.write("entry.test.js", "console.log('safe');\n");
    for candidate in [
        "node --test",
        "node --watch --test entry.test.js",
        "node --test --watch entry.test.js",
        "node --test --check entry.test.js",
        "node --check --test entry.test.js",
        "node --test --eval 'console.log(42)' entry.test.js",
        "node --test --unknown-runner-option entry.test.js",
    ] {
        fixture.unverified(candidate);
    }
    for source in [
        "import(process.env.MODULE);\n",
        "require(process.env.MODULE);\n",
        "import 'dcg-fixture-external-dependency';\n",
        "require('dcg-fixture-external-dependency');\n",
        "import 'https://invalid.example/helper.js';\n",
    ] {
        fixture.write("entry.test.js", source);
        fixture.unverified("node --test entry.test.js");
    }
}

#[test]
fn definite_node_findings_take_precedence_over_an_unverified_sibling() {
    let fixture = Fixture::new();
    fixture.write("unknown.test.js", "import(process.env.MODULE);\n");
    fixture.write(
        "danger.test.js",
        "require('child_process').execSync('git reset --hard');\n",
    );
    for candidate in [
        "node --test unknown.test.js danger.test.js",
        "node --test danger.test.js unknown.test.js",
        "node --test '*.test.js'",
    ] {
        fixture.destructive(candidate, "danger.test.js");
    }
}

#[test]
fn finite_node_globs_still_obey_file_limits() {
    let fixture = Fixture::new();
    for index in 0..33 {
        fixture.write(&format!("tests/{index}.test.js"), "console.log('safe');\n");
    }
    fixture.unverified("node --test 'tests/*.test.js'");
}

#[test]
fn syntax_only_startup_sources_and_shadowed_queries_remain_inspected() {
    let fixture = Fixture::new();
    fixture.write("syntax.sh", "git reset --hard\n");
    fixture.write("startup.sh", "git reset --hard\n");
    for candidate in [
        "BASH_ENV=./startup.sh /bin/bash -n syntax.sh",
        "env BASH_ENV=./startup.sh /bin/bash -n syntax.sh",
    ] {
        fixture.destructive(candidate, "startup.sh");
    }
    for candidate in [
        "command() { printf safe; }; command -v dcg",
        "alias command='printf safe'; command -V orca",
    ] {
        fixture.unverified(candidate);
    }
    fixture.destructive("command -v \"$(bash startup.sh)\"", "startup.sh");
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

fn version_review_fixture() -> Fixture {
    let fixture = Fixture::new();
    let mut config = std::fs::OpenOptions::new()
        .append(true)
        .open(&fixture.config)
        .expect("open temporary policy");
    writeln!(config, "\n[trial]\nenabled = false").expect("disable trial execution");
    fixture.write("home/.config/dcg/.fixture", "");
    fixture
}

fn version_review_hook(fixture: &Fixture, candidate: &str) -> (Output, Value) {
    let home = fixture.root.join("home");
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcg"))
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("TMPDIR", &fixture.root)
        .env("TEMP", &fixture.root)
        .env("TMP", &fixture.root)
        .env("DCG_CONFIG", &fixture.config)
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_HISTORY_DISABLED", "1")
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_HOOK_TIMEOUT_MS", "30000")
        .env(
            "DCG_PENDING_EXCEPTIONS_PATH",
            fixture.root.join("pending.jsonl"),
        )
        .env("DCG_ALLOW_ONCE_PATH", fixture.root.join("allow-once.jsonl"))
        .env("NO_COLOR", "1")
        .args(["--agent", "claude-code"])
        .current_dir(&fixture.root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run isolated hook without trials or desktop review");
    child
        .stdin
        .take()
        .expect("hook stdin")
        .write_all(
            json!({
                "tool_name": "Bash",
                "tool_input": {"command": candidate},
                "cwd": fixture.root,
            })
            .to_string()
            .as_bytes(),
        )
        .expect("send candidate as inert hook data");
    let output = child.wait_with_output().expect("hook response");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let verdict = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{error}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output, verdict)
}

fn assert_version_review_denial(fixture: &Fixture, candidate: &str) {
    let (output, verdict) = version_review_hook(fixture, candidate);
    let denial = &verdict["hookSpecificOutput"];
    assert_eq!(denial["permissionDecision"], "deny", "{verdict}");
    assert_eq!(
        denial["ruleId"], "heredoc.script_files:unverified",
        "{verdict}"
    );
    for field in ["allowOnceCode", "allowOnceFullHash", "remediation"] {
        assert!(
            denial.get(field).is_none(),
            "ineffective {field}: {verdict}"
        );
    }
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("dcg trial run"), "{text}");
    assert!(!text.contains("dcg allow-once"), "{text}");
    assert!(!text.contains("allowlist add-command"), "{text}");
    assert!(
        !text.contains("have them run the command manually"),
        "{text}"
    );
    assert!(!fixture.root.join("pending.jsonl").exists());
    assert!(
        !fixture
            .root
            .join("home/.config/dcg/verified_trials.json")
            .exists()
    );
}

#[test]
fn unverified_hook_offers_version_review_without_an_ineffective_code() {
    let fixture = version_review_fixture();
    assert_version_review_denial(&fixture, "python3 -m dcg_fixture_inspection");
}

#[test]
fn hook_outcomes_distinguish_findings_limits_and_unavailable_review() {
    let fixture = version_review_fixture();
    fixture.write("oversized.sh", "#".repeat(256 * 1024 + 1));
    for agent in ["claude-code", "codex-cli"] {
        for (candidate, code, remediation, desktop_review) in [
            (
                "git reset --hard",
                "definite-dangerous-operation",
                "reported operation",
                false,
            ),
            (
                "bash missing.sh",
                "unsupported-dynamic",
                "unresolved",
                false,
            ),
            (
                "bash oversized.sh",
                "analysis-limit",
                "resource limit",
                false,
            ),
            (
                "git reset --hard",
                "review-unavailable-or-cancelled",
                "no approval was recorded",
                true,
            ),
        ] {
            let mut input = json!({
                "tool_name": "Bash",
                "tool_input": {"command": candidate},
                "cwd": fixture.root,
            });
            let mut command = fixture.command();
            command.args(["--agent", agent]);
            if agent == "codex-cli" {
                input["turn_id"] = json!("inspection-outcome-fixture");
            }
            if desktop_review {
                // An invalid cwd makes review structurally unavailable while
                // retaining a single-command protocol payload. This fixture
                // must never open a real dialog or authenticate.
                input["cwd"] = json!("relative-directory");
                command.arg("--desktop-review");
            }
            let mut child = command.spawn().expect("start isolated outcome hook");
            child
                .stdin
                .take()
                .expect("hook stdin")
                .write_all(input.to_string().as_bytes())
                .expect("candidate as inert hook data");
            let output = child.wait_with_output().expect("outcome hook result");
            assert!(output.status.success(), "{agent}: {code}");
            let verdict: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
                panic!(
                    "{agent}: {code}: {error}: {}",
                    String::from_utf8_lossy(&output.stderr)
                )
            });
            let denial = &verdict["hookSpecificOutput"];
            assert_eq!(denial["permissionDecision"], "deny", "{verdict}");
            let reason = denial["permissionDecisionReason"].as_str().expect("reason");
            assert!(reason.contains(remediation), "{agent}: {code}: {verdict}");
            if agent == "claude-code" {
                assert_eq!(denial["outcomeCode"], code, "{verdict}");
            } else {
                assert!(reason.contains(&format!("[dcg:{code}]")), "{verdict}");
                assert!(denial.get("outcomeCode").is_none(), "{verdict}");
            }
            assert!(
                !String::from_utf8_lossy(&output.stderr).contains("Warte auf"),
                "fixture unexpectedly attempted desktop review: {agent}: {code}"
            );
        }
    }
}

#[test]
fn unverified_hook_does_not_consume_legacy_command_only_approval() {
    use destructive_command_guard::logging::RedactionConfig;
    use destructive_command_guard::pending_exceptions::{
        AllowOnceEntry, AllowOnceScopeKind, PendingExceptionRecord,
    };

    let fixture = version_review_fixture();
    let candidate = "python3 -m dcg_fixture_inspection";
    let now = chrono::Utc::now();
    let redaction = RedactionConfig::default();
    let cwd = fixture.root.to_string_lossy();
    let pending = PendingExceptionRecord::new(
        now,
        &cwd,
        candidate,
        "legacy review",
        &redaction,
        true,
        None,
    );
    let entry = AllowOnceEntry::from_pending(
        &pending,
        now,
        AllowOnceScopeKind::Project,
        &cwd,
        true,
        false,
        &redaction,
    );
    let bytes = format!("{}\n", serde_json::to_string(&entry).unwrap());
    fixture.write("allow-once.jsonl", &bytes);

    for _ in 0..2 {
        assert_version_review_denial(&fixture, candidate);
        assert_eq!(
            std::fs::read_to_string(fixture.root.join("allow-once.jsonl")).unwrap(),
            bytes
        );
    }
}

#[test]
fn unverified_hook_command_allowlist_cannot_hide_a_destructive_sibling() {
    let fixture = version_review_fixture();
    let candidate = "python3 -m dcg_fixture_inspection; git reset --hard";
    fixture.write(
        "home/.config/dcg/allowlist.toml",
        format!(
            "[[allow]]\ncommand = {}\nreason = 'legacy command-only review'\n",
            serde_json::to_string(candidate).unwrap(),
        ),
    );
    assert_version_review_denial(&fixture, candidate);
}

#[test]
fn definite_git_denial_retains_its_supported_allow_once_code() {
    let fixture = version_review_fixture();
    let (_output, verdict) = version_review_hook(&fixture, "git reset --hard");
    let denial = &verdict["hookSpecificOutput"];
    assert_eq!(denial["permissionDecision"], "deny", "{verdict}");
    assert_eq!(denial["ruleId"], "core.git:reset-hard", "{verdict}");
    assert!(
        denial["allowOnceCode"]
            .as_str()
            .is_some_and(|value| !value.is_empty()),
        "{verdict}"
    );
    assert!(
        denial["remediation"]["allowOnceCommand"]
            .as_str()
            .is_some_and(|value| value.starts_with("dcg allow-once ")),
        "{verdict}"
    );
    assert!(fixture.root.join("pending.jsonl").is_file());
}
