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
        self.run_with_path(candidate, &std::env::var_os("PATH").unwrap_or_default())
    }

    fn run_with_path(&self, candidate: &str, path: &std::ffi::OsStr) -> (Output, Value) {
        let mut child = self
            .command()
            .env("PATH", path)
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
fn routine_pipelines_bind_sources_without_guessing_allowlist_scope() {
    let fixture = Fixture::new();
    fixture.write("safe.sh", "printf ready\n");
    fixture.write("danger.sh", "git reset --hard\n");
    let root = shell_words::quote(fixture.root.to_str().unwrap());
    fixture.allowed(&format!("cd {root} && bash safe.sh | cat"));
    fixture.allowed(&format!("cd -- {root} && bash safe.sh 2>&1 | tail -1"));
    fixture.destructive(&format!("cd {root} && bash danger.sh | cat"), "danger.sh");
    fixture.unverified(&format!("cd {root} | bash safe.sh"));
    fixture.unverified(&format!("cd {root} && eval 'cd /' && bash safe.sh | cat"));
    fixture.unverified(&format!("cd {root} && 'eval' 'cd /' && bash safe.sh | cat"));
    fixture.unverified(&format!("cd {root} && bash safe.sh | cat; cd /"));
    fixture.unverified(&format!("cd {root} && ./safe.sh | cat; cd /"));
    // A substitution runs its own `cd`: the namesake it reaches is not the
    // file beside the leading directory, so that file must not vouch for it.
    fixture.write("other/safe.sh", "git reset --hard\n");
    let other = shell_words::quote(fixture.root.join("other").to_str().unwrap()).into_owned();
    for nested in [
        format!("cd {root} && echo $(cd {other} && bash safe.sh) | cat"),
        format!("cd {root} && echo `cd {other} && bash safe.sh` | cat"),
        format!("cd {root} && cat <(cd {other} && bash safe.sh) | cat"),
    ] {
        fixture.denied(&nested);
    }
    #[cfg(unix)]
    {
        // /bin is a distro-owned symlink on many Linux systems. This probe
        // is about a concrete native executable, not relaxing symlink checks.
        let native = std::fs::canonicalize("/bin/ls").unwrap();
        fixture.allowed(&format!("cd {root} && {} | head -1", native.display()));
        // A native executable may be read without a cwd; a script at an
        // absolute path must not receive a fabricated '/' execution context.
        fixture.unverified(&format!(
            "cd {root} | {}",
            fixture.root.join("safe.sh").display()
        ));
    }
}

#[test]
fn exact_remote_system_queries_do_not_read_local_script_namesakes() {
    let fixture = Fixture::new();
    for query in [
        "/usr/sbin/sysctl hw.model hw.memsize hw.ncpu machdep.cpu.brand_string",
        "/usr/sbin/sysctl -n vm.swapusage",
        "/sbin/sysctl kern.osrelease",
        "/usr/bin/uptime",
        "/usr/bin/memory_pressure -Q",
    ] {
        fixture.allowed(&format!("ssh -o BatchMode=yes mini {query}"));
    }
    for query in [
        "/usr/sbin/sysctl -w kern.hostname=changed",
        "/usr/sbin/sysctl kern.hostname=changed",
        "/usr/bin/memory_pressure -l critical",
        "/tmp/sysctl hw.model",
    ] {
        fixture.unverified(&format!("ssh mini {query}"));
    }
    fixture.denied("ssh mini '/usr/bin/uptime; git reset --hard'");
    fixture.denied("ssh mini '/usr/sbin/sysctl hw.model $(git reset --hard)'");
    fixture.write("remote.sh", "printf ready\n");
    fixture.unverified("ssh mini bash remote.sh");
}

#[test]
fn routine_interpreter_and_browser_data_keeps_its_language_boundary() {
    let fixture = Fixture::new();
    for command in [
        "env | cut -d= -f1 | sort",
        "/usr/bin/env -0 | head -c 1",
        "bash --version | head -1",
        "/bin/bash --help",
        "node --version",
        "python3 --version",
        "python3 -c 's = \"run $(git reset --hard) later\"; print(s)'",
        "node -e 'const s = \"run $(git reset --hard) later\"; console.log(s)'",
        "python3 - <<'PY'\nfrom pathlib import Path\nprint(Path('README.md').read_text())\nPY",
        "agent-browser --session research eval --stdin <<'JS'\n(() => { const text = document.body.innerText; return {text, tables:[...document.querySelectorAll('table')].map(t=>t.outerHTML)}; })()\nJS",
    ] {
        fixture.allowed(command);
    }
    for command in [
        "node -e 'const cp = require(\"child_process\"); const s = \"echo $(git reset --hard)\"; cp.execSync(s)'",
        "python3 -c 'from shutil import rmtree as wipe; wipe(\"/tmp\")'",
        "python3 -c 'import shutil; shutil.rmtree(\"/tmp\")'",
    ] {
        fixture.denied(command);
    }
    fixture.write(
        "alias.py",
        "from shutil import rmtree as wipe\nwipe('/tmp')\n",
    );
    fixture.destructive("python3 alias.py", "alias.py");
    fixture.write("env", "git reset --hard\n");
    fixture.unverified("./env");
    fixture.write(
        "read_only.py",
        "s = 'run $(git reset --hard) later'\nprint(s)\n",
    );
    fixture.write(
        "read_only.js",
        "const s = 'run $(git reset --hard) later'; console.log(s);\n",
    );
    fixture.allowed("python3 read_only.py");
    fixture.allowed("node read_only.js");
    fixture.write(
        "indirect.py",
        "import os\ns = 'echo $(git reset --hard)'\nos.system(s)\n",
    );
    fixture.write(
        "indirect.js",
        "const cp = require('child_process');\nconst s = 'echo $(git reset --hard)';\ncp.execSync(s);\n",
    );
    fixture.denied("python3 indirect.py");
    fixture.destructive("node indirect.js", "indirect.js");
    fixture.unverified("./bash --version");
    fixture.unverified("bash --version safe.sh");
    fixture.denied("bash --version; git reset --hard");
    fixture.denied("node --version; git reset --hard");
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
fn ordinary_sized_interpreter_files_finish_literal_analysis() {
    // Six hundred lines passed the literal check's old fixed 4096-node cap,
    // so every such test or tool run was denied as analysis-limit.
    let fixture = Fixture::new();
    let python = "total = compute(1, 2)\n".repeat(600);
    let javascript = "const total = compute(1, 2);\n".repeat(600);
    fixture.write("large.py", format!("{python}print('done\\n')\n"));
    fixture.write(
        "large.mjs",
        format!("{javascript}console.log('done\\n');\n"),
    );
    fixture.allowed("python3 large.py");
    fixture.allowed("node large.mjs");
    fixture.write(
        "hidden.py",
        format!("{python}s = 'echo `git branch -D main`'\nrun(s)\n"),
    );
    fixture.write(
        "hidden.mjs",
        format!("{javascript}const s = 'echo `git branch -D main`';\nrun(s);\n"),
    );
    fixture.destructive("python3 hidden.py", "hidden.py");
    fixture.destructive("node hidden.mjs", "hidden.mjs");
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
            "[dcg:review-not-started] Keine Desktop-Freigabe möglich: Projektstand, Arbeitsordner und ausführbare Dateien lassen sich für diesen Aufruf nicht genau binden",
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

#[test]
fn ordinary_assignment_prefixes_preserve_static_decisions_with_script_scanning() {
    let fixture = Fixture::new();
    fixture.write("package.json", r#"{"scripts":{"test":"echo safe"}}"#);
    fixture.write("input.txt", "fixture\n");
    // These are tom.10's static allow cases. Exercise the full evaluator with
    // scan_script_files=true, including an unusable PATH in the hook process.
    // The candidates remain data; no npm, Swift, Git or grep command is run.
    for path in [
        "/usr/bin:/bin",
        "",
        ".:/usr/bin",
        ":/usr/bin",
        "bin:/usr/bin",
    ] {
        for (candidate, plain) in [
            ("CI=1 npm test", "npm test"),
            ("GIT_PAGER=cat git log", "git log"),
            ("LC_ALL=C grep fixture input.txt", "grep fixture input.txt"),
            ("TZ=UTC date", "date"),
            ("PI_OFFLINE=1 PI_OS_AGENT=0 swift test", "swift test"),
            ("FOO=$BAR git log", "git log"),
            ("FOO=~/fixture git log", "git log"),
            ("FOO=*.txt git log", "git log"),
            ("FOO={one,two} git log", "git log"),
            ("env FOO=$BAR git log", "git log"),
            ("env -- CI=1 npm test", "npm test"),
            ("CI=1 env TZ=UTC date", "date"),
        ] {
            let (baseline_output, baseline) = fixture.run_with_path(plain, path.as_ref());
            assert_eq!(baseline["decision"], "allow", "{plain}: {baseline}");
            let (output, result) = fixture.run_with_path(candidate, path.as_ref());
            assert_eq!(
                result["decision"], baseline["decision"],
                "{candidate}: {result}"
            );
            assert_eq!(
                result["rule_id"], baseline["rule_id"],
                "{candidate}: {result}"
            );
            assert_eq!(output.status.code(), baseline_output.status.code());
        }
    }
}

#[test]
fn local_preload_prefixes_keep_trial_diagnostics_with_script_scanning() {
    let fixture = Fixture::new();
    fixture.write("package.json", r#"{"scripts":{"build":"echo safe"}}"#);
    for path in ["/usr/bin:/bin", "", ".:/usr/bin"] {
        for candidate in [
            "PYTHONPATH=src pytest",
            "NODE_OPTIONS=--max-old-space-size=4096 npm run build",
            "env PYTHONPATH=src pytest",
            "env NODE_OPTIONS=--max-old-space-size=4096 npm run build",
            "PYTHONPATH=$SOURCE pytest",
            "CI=1 PYTHONPATH=src pytest",
            "CI=1 env CI=1 env PYTHONPATH=src pytest",
        ] {
            let (_, result) = fixture.run_with_path(candidate, path.as_ref());
            assert_eq!(
                result["rule_id"], "heredoc.script_files:unverified",
                "{result}"
            );
            let text = result.to_string();
            assert!(text.contains("dcg trial run"), "{candidate}: {text}");
            assert!(!text.contains("bound-input-review"), "{candidate}: {text}");
            assert!(!text.contains("cannot be approved"), "{candidate}: {text}");
        }
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
        "CI=1 node scripts/check.js",
        "FOO=$BAR node scripts/check.js",
        "PYTHONPATH=src node scripts/check.js",
        "NODE_OPTIONS=--max-old-space-size=4096 node scripts/check.js",
        "env NODE_OPTIONS=--max-old-space-size=4096 node scripts/check.js",
        "env NODE_OPTIONS=--max-old-space-size=4096 node < scripts/check.js",
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

#[cfg(unix)]
#[test]
fn disabled_trials_with_an_unreadable_approval_store_use_one_time_review() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let policy = std::fs::read_to_string(&fixture.config).unwrap();
    std::fs::write(
        &fixture.config,
        format!("{policy}\n[trial]\nenabled = false\n"),
    )
    .unwrap();
    // Remembered script approvals are consulted even with trials disabled, but
    // unreadable approval data neither allows nor remembers anything: review
    // stays one-time and the store is left as it was. The oversized review text
    // guarantees no native dialog opens in this test.
    fixture.write(
        "home/.config/dcg/verified_trials.json",
        "invalid fixture store",
    );
    // Use a real fixture executable: /bin/true does not exist on macOS.
    // The hook only inspects it; disabled trials must not execute it.
    fixture.write("review-fixture.sh", "#!/bin/sh\nprintf safe\n");
    std::fs::set_permissions(
        fixture.root.join("review-fixture.sh"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let candidate = format!(
        "PATH=/usr/bin:/bin ./review-fixture.sh {}",
        "x".repeat(6_000)
    );
    let input = json!({"tool_name":"Bash", "tool_input":{"command":candidate}, "cwd":fixture.root});
    let mut child = fixture
        .command()
        .args(["--agent", "claude-code", "--desktop-review"])
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let verdict: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        verdict["hookSpecificOutput"]["permissionDecision"], "deny",
        "{verdict}"
    );
    let text = verdict.to_string();
    assert!(text.contains("Sandbox trials are disabled"), "{text}");
    assert!(text.contains("one-time desktop review"), "{text}");
    assert_eq!(
        std::fs::read_to_string(fixture.root.join("home/.config/dcg/verified_trials.json"))
            .unwrap(),
        "invalid fixture store"
    );
}

#[test]
fn agents_cannot_forge_confined_receipts_or_redirect_their_trusted_config() {
    use destructive_command_guard::config::ConfinedLoopback;
    use destructive_command_guard::confined::Request;
    let fixture = Fixture::new();
    fixture.write("forged-config.toml", "[trial]\nconfined_loopback = 'all'\n");
    let policy = std::fs::read_to_string(&fixture.config).unwrap();
    std::fs::write(
        &fixture.config,
        format!(
            "{policy}\n[trial]\nconfined_loopback = 'none'\n\
             [overrides]\nallow = ['.*dcg.* run .*']\n\
             [policy.rules]\n'dcg.internal:confined-runner' = 'warn'\n"
        ),
    )
    .unwrap();
    let request = Request::new("node --test", &fixture.root, "/bin/sh".as_ref(), 5)
        .with_loopback(ConfinedLoopback::All);
    let runner = request
        .invocation(env!("CARGO_BIN_EXE_dcg").as_ref())
        .unwrap();
    for prefix in [
        String::new(),
        format!(
            "DCG_CONFIG={} ",
            shell_words::quote(fixture.root.join("forged-config.toml").to_str().unwrap())
        ),
        format!(
            "HOME={} ",
            shell_words::quote(fixture.root.to_str().unwrap())
        ),
    ] {
        let candidate = format!("{prefix}{runner}");
        let result = fixture.denied(&candidate);
        assert_eq!(result["rule_id"], "dcg.internal:confined-runner");
        let input =
            json!({"tool_name":"Bash", "tool_input":{"command":candidate}, "cwd":fixture.root});
        let mut child = fixture
            .command()
            .args(["--agent", "claude-code", "--desktop-review"])
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.to_string().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        let verdict: Value = serde_json::from_slice(&output.stdout).unwrap();
        let decision = &verdict["hookSpecificOutput"];
        assert_eq!(decision["permissionDecision"], "deny", "{verdict}");
        assert_eq!(
            decision["ruleId"], "dcg.internal:confined-runner",
            "{verdict}"
        );
        assert!(decision.get("allowOnceCode").is_none(), "{verdict}");
        assert!(decision.get("updatedInput").is_none(), "{verdict}");
        assert!(verdict.to_string().contains("internal-hook-command"));
    }
    fixture.allowed("dcg test 'dcg run --confined --request fixture'");
    fixture.allowed("printf '%s' 'dcg run --confined --request fixture'");
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
fn a_granted_unverified_helper_cannot_hide_the_rest_of_its_script() {
    let fixture = Fixture::new();
    let root = fixture.root.display().to_string();
    fixture.write(
        "home/.config/dcg/allowlist.toml",
        format!(
            "[[allow]]\nrule = \"heredoc.script_files:unverified\"\nreason = \"project grant\"\n\
             paths = [\"{root}\", \"{root}/**\"]\n"
        ),
    );
    fixture.write("tools/ok.sh", "echo ok\n");
    let hook = |candidate: &str| {
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
        serde_json::from_slice::<Value>(&output.stdout).unwrap_or(Value::Null)
    };
    // A `cd` after the shebang leaves the helper's directory unknown, so the
    // helper stays unverified. The grant may lift only that marker.
    for (name, tail) in [
        ("home.sh", "rm -rf \"$HOME/Documents\"\n"),
        ("reset.sh", "git reset --hard\n"),
    ] {
        fixture.write(
            name,
            format!("#!/bin/sh\ncd {root}/tools\nsh ok.sh\n{tail}"),
        );
        let output = hook(&format!("sh {name}"));
        let decision = &output["hookSpecificOutput"];
        assert_eq!(decision["permissionDecision"], "deny", "{name}: {output}");
        assert_ne!(
            decision["ruleId"], "heredoc.script_files:unverified",
            "{name}: {output}"
        );
    }
    fixture.write(
        "benign.sh",
        format!("#!/bin/sh\ncd {root}/tools\nsh ok.sh\necho done\n"),
    );
    assert_eq!(hook("sh benign.sh"), Value::Null);
}

#[test]
fn a_warned_helper_cannot_hide_the_rest_of_its_script() {
    let fixture = Fixture::new();
    let policy = std::fs::read_to_string(&fixture.config).expect("read policy");
    std::fs::write(
        &fixture.config,
        format!("{policy}[policy.rules]\n\"core.git:stash-drop\" = \"warn\"\n"),
    )
    .expect("write policy");
    fixture.write("tools/drop.sh", "git stash drop\n");
    let (_, result) = fixture.run("sh tools/drop.sh");
    assert_eq!(result["decision"], "warn", "{result}");
    fixture.write("qa.sh", "sh tools/drop.sh\nrm -rf \"$HOME/Documents\"\n");
    fixture.destructive("sh qa.sh", "qa.sh");
    let result = fixture.denied("sh tools/drop.sh; rm -rf \"$HOME/Documents\"");
    assert_ne!(result["rule_id"], "core.git:stash-drop", "{result}");
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
fn bare_node_preloads_inspect_the_export_for_each_cli_spelling() {
    let fixture = Fixture::new();
    fixture.write("package.json", r#"{"name":"fixture"}"#);
    fixture.write("case.test.js", "console.log('fixture');\n");
    fixture.write(
        "node_modules/loader/package.json",
        r#"{"exports":{".":"./entry.cjs"}}"#,
    );
    for option in [
        "--import loader",
        "--import=loader",
        "--require loader",
        "--require=loader",
        "-r loader",
        "-rloader",
    ] {
        let command = format!("node {option} --test case.test.js");
        fixture.write("node_modules/loader/entry.cjs", "console.log('preload');\n");
        fixture.allowed(&command);
        fixture.write(
            "node_modules/loader/entry.cjs",
            "require('child_process').execSync('git reset --hard');\n",
        );
        fixture.denied(&command);
    }
    // Missing packages and private, unexported subpaths remain inconclusive.
    for command in [
        "node --import missing --test case.test.js",
        "node -r loader/private --test case.test.js",
    ] {
        let result = fixture.denied(command);
        assert_eq!(
            result["rule_id"], "heredoc.script_files:unverified",
            "{result}"
        );
    }
    fixture.write(
        "node_modules/loader/package.json",
        r#"{"exports":{"custom":"./danger.cjs","default":"./entry.cjs"}}"#,
    );
    fixture.write(
        "node_modules/loader/entry.cjs",
        "console.log('safe default');",
    );
    fixture.write(
        "node_modules/loader/danger.cjs",
        "require('child_process').execSync('git reset --hard');",
    );
    // The candidate remains data. NODE_OPTIONS must not let the static reader
    // bind the default export while the actual runtime selects custom code.
    let mut child = fixture
        .command()
        .env("NODE_OPTIONS", "--conditions=custom")
        .args(["--robot", "test", "--dialect", "posix", "--stdin"])
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"node --import loader ./case.test.js")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["rule_id"], "heredoc.script_files:unverified");
}

#[test]
fn bare_node_preloads_with_node_addons_stay_unverified() {
    let fixture = Fixture::new();
    fixture.write("package.json", r#"{"name":"fixture"}"#);
    fixture.write("case.test.js", "console.log('fixture');");
    fixture.write(
        "node_modules/loader/package.json",
        r#"{"exports":{"node-addons":"./payload.js","default":"./clean.js"}}"#,
    );
    fixture.write("node_modules/loader/clean.js", "console.log('safe');");
    fixture.write(
        "node_modules/loader/payload.js",
        "require('child_process').execSync('git reset --hard');",
    );
    // Candidates are stdin data only. No execution or rewriting protocol may
    // turn the clean fallback into an ordinary static allow.
    for option in ["--import loader", "--require loader", "-rloader"] {
        fixture.unverified(&format!("node {option} --test case.test.js"));
        fixture.unverified(&format!("node --no-addons {option} --test case.test.js"));
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
                "review-not-started",
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

/// Fork issue #2, Case B, through the Pi bridge's exact arguments and payload:
/// a remote script cannot be inspected, so no dialog is attempted and the
/// denial names that limitation and a next step instead of advising a retry.
/// A remote operation with a definite finding keeps that finding.
#[test]
fn remote_scripts_report_why_review_cannot_start() {
    let fixture = version_review_fixture();
    // The helper directory is a regular file: any dialog attempt fails closed
    // (with a different tag) instead of opening Touch ID during the test.
    for blocker in [
        "home/Library/Application Support/dcg/desktop-review",
        "home/.config/dcg/desktop-review",
    ] {
        fixture.write(blocker, "");
    }
    let hook = |candidate: &str, desktop_review: bool| {
        let input = json!({
            "tool_name": "Bash",
            "tool_input": {"command": candidate},
            "cwd": fixture.root,
            "dcg_explicit_verdict": true,
            "dcg_input_rewrite": true,
        });
        let mut command = fixture.command();
        if desktop_review {
            command.arg("--desktop-review");
        }
        let mut child = command
            .args(["--no-color", "--agent", "pi"])
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.to_string().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        for attempt in ["Warte auf", "Touch-ID-Dialog"] {
            assert!(!stderr.contains(attempt), "{candidate}: {stderr}");
        }
        let verdict: Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("{candidate}: {error}: {stderr}"));
        assert_eq!(
            verdict["hookSpecificOutput"]["permissionDecision"], "deny",
            "{verdict}"
        );
        verdict
    };
    let verdict = hook(
        "ssh -o BatchMode=yes deploy@example.invalid 'readlink /srv/app/current; \
         /usr/libexec/PlistBuddy -c Print:EnvironmentVariables:PUBLIC_ORIGIN /srv/app.plist; \
         launchctl list com.example.app'",
        true,
    );
    let reason = verdict["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(reason.contains("[dcg:review-not-started]"), "{reason}");
    assert!(reason.contains("entfernten Rechnern"), "{reason}");
    assert!(reason.contains("Nächster Schritt"), "{reason}");
    assert!(reason.contains("no approval was recorded"), "{reason}");
    for misleading in [
        "review-unavailable-or-cancelled",
        "zu umfangreich",
        "and retry ",
        "allow-once",
    ] {
        assert!(!reason.contains(misleading), "{misleading}: {reason}");
    }
    let verdict = hook(
        "ssh deploy@example.invalid 'rm -rf /srv/app/releases'",
        false,
    );
    let rule = verdict["hookSpecificOutput"]["ruleId"]
        .as_str()
        .unwrap_or_default();
    assert!(rule.starts_with("core.filesystem:"), "{verdict}");
}

/// Fork issue #2, Case A: a reviewable script larger than the dialog text
/// limit used to make dcg refuse to build the dialog and then report
/// "unavailable, declined or expired". It is now excerpted and the dialog is
/// attempted; the blocked helper makes that attempt fail closed with its own
/// cause instead of opening Touch ID.
#[test]
fn large_reviewable_scripts_reach_the_dialog_and_fail_closed_without_helper() {
    let fixture = version_review_fixture();
    for blocker in [
        "home/Library/Application Support/dcg/desktop-review",
        "home/.config/dcg/desktop-review",
    ] {
        fixture.write(blocker, "");
    }
    let padding = "// isolated server fixture; nothing here runs during the hook\n".repeat(120);
    fixture.write(
        "tests/app.test.mjs",
        format!(
            "{padding}import {{ spawn }} from 'node:child_process';\n\
             const port = 40000 + Math.floor(Math.random() * 1000);\n\
             spawn(process.execPath, ['server' + '.mjs'], {{ env: {{ ...process.env, PORT: String(port) }} }});\n"
        ),
    );
    fixture.write("server.mjs", "console.log('fixture');\n");
    let input = json!({
        "tool_name": "Bash",
        "tool_input": {"command": "node --test tests/app.test.mjs"},
        "cwd": fixture.root,
        "dcg_explicit_verdict": true,
        "dcg_input_rewrite": true,
    });
    let mut child = fixture
        .command()
        .args(["--desktop-review", "--no-color", "--agent", "pi"])
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let verdict: Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| panic!("{error}: {stderr}"));
    assert_eq!(
        verdict["hookSpecificOutput"]["permissionDecision"], "deny",
        "{verdict}"
    );
    let reason = verdict["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(
        reason.contains("[dcg:review-unavailable-or-cancelled]")
            && reason.contains("Touch-ID-Dialog ist nicht verfügbar"),
        "{reason}\n{stderr}"
    );
    for misleading in ["declined or expired", "review-not-started", "and retry "] {
        assert!(!reason.contains(misleading), "{misleading}: {reason}");
    }
    assert!(!fixture.root.join("home/.config/dcg/trials").exists());
}

/// A missing test file cannot be bound, so neither a trial nor a dialog can
/// bind this version. A hook with --desktop-review used to call that "desktop
/// approval unavailable" and advise --desktop-review; it now says no dialog
/// can start and why. A hook without the dialog keeps naming the missing flag.
/// A leading `cd DIR &&` before a pipe binds, and reaches the (blocked) dialog.
#[test]
fn unbindable_versions_report_why_review_cannot_start() {
    let hook = |fixture: &Fixture, desktop_review: bool, test_file: &str| {
        for blocker in [
            "home/Library/Application Support/dcg/desktop-review",
            "home/.config/dcg/desktop-review",
        ] {
            fixture.write(blocker, "");
        }
        fixture.write(
            "tests/app.test.mjs",
            "import { spawn } from 'node:child_process';\n\
             spawn(process.execPath, ['server' + '.mjs'], { env: { ...process.env, PORT: '40000' } });\n",
        );
        fixture.write("server.mjs", "console.log('fixture');\n");
        let candidate = format!(
            "cd '{}' && node --test {test_file} | cat",
            fixture.root.display()
        );
        let input = json!({
            "tool_name": "Bash",
            "tool_input": {"command": candidate},
            "cwd": fixture.root,
            "dcg_explicit_verdict": true,
        });
        let mut command = fixture.command();
        if desktop_review {
            command.arg("--desktop-review");
        }
        let mut child = command
            .args(["--no-color", "--agent", "pi"])
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.to_string().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let verdict: Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("{candidate}: {error}: {stderr}"));
        let denial = &verdict["hookSpecificOutput"];
        assert_eq!(denial["permissionDecision"], "deny", "{verdict}");
        assert_eq!(
            denial["ruleId"], "heredoc.script_files:unverified",
            "{verdict}"
        );
        let reason = denial["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .to_owned();
        for misleading in [
            "desktop approval unavailable",
            "Enable sandbox trials and use a hook",
            "and retry ",
            "allow-once",
        ] {
            assert!(!reason.contains(misleading), "{misleading}: {reason}");
        }
        (reason, stderr)
    };
    let no_dialog = |stderr: &str| {
        for attempt in ["Warte auf", "Touch-ID-Dialog"] {
            assert!(!stderr.contains(attempt), "{stderr}");
        }
    };

    let (reason, stderr) = hook(&version_review_fixture(), true, "tests/missing.test.mjs");
    no_dialog(&stderr);
    assert!(reason.contains("[dcg:review-not-started]"), "{reason}");
    assert!(reason.contains("nicht genau binden"), "{reason}");
    assert!(reason.contains("Nächster Schritt"), "{reason}");
    assert!(reason.contains("no approval was recorded"), "{reason}");
    assert!(!reason.contains("--desktop-review fehlt"), "{reason}");

    // Trials stay enabled here, so the sandbox path reaches the same binding.
    let (reason, stderr) = hook(&Fixture::new(), false, "tests/missing.test.mjs");
    no_dialog(&stderr);
    assert!(
        reason.contains("Cannot bind an exact project version for a sandbox trial"),
        "{reason}"
    );
    assert!(reason.contains("--desktop-review fehlt"), "{reason}");
    assert!(!reason.contains("[dcg:review-"), "{reason}");

    // An existing test file binds through the leading `cd` despite the pipe,
    // so the dialog is tried; the blocked helper makes it fail closed.
    let fixture = version_review_fixture();
    let (reason, _) = hook(&fixture, true, "tests/app.test.mjs");
    assert!(
        reason.contains("[dcg:review-unavailable-or-cancelled]")
            && reason.contains("Touch-ID-Dialog ist nicht verfügbar"),
        "{reason}"
    );
    assert!(!reason.contains("nicht genau binden"), "{reason}");
    assert!(!fixture.root.join("home/.config/dcg/trials").exists());
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
