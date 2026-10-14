//! Filesystem approvals are managed through the real CLI, using temporary state.
#![cfg(unix)]

use destructive_command_guard::{effects, trial_store::TrialStore};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

struct Fixture {
    temp: tempfile::TempDir,
    project: PathBuf,
    home: PathBuf,
    /// The spawned dcg's whole environment. In-process approvals bind against
    /// it too, so both sides fingerprint the same inherited state.
    environment: BTreeMap<OsString, OsString>,
    store: TrialStore,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("project");
        let home = temp.path().join("home");
        fs::create_dir(&project).unwrap();
        fs::create_dir(&home).unwrap();
        fs::write(project.join("input"), "original").unwrap();
        fs::write(
            temp.path().join("config.toml"),
            "[general]\nunverified_decision = 'deny'\n[heredoc]\nscan_script_files = true\n[trial]\nenabled = false\n",
        ).unwrap();
        let home = home.canonicalize().unwrap();
        let environment = environment(temp.path(), &home);
        let store = TrialStore::new(home.join(".config/dcg")).with_environment(environment.clone());
        Self {
            temp,
            project: project.canonicalize().unwrap(),
            home,
            environment,
            store,
        }
    }

    fn process(&self) -> Command {
        let mut process = Command::new(env!("CARGO_BIN_EXE_dcg"));
        process
            .env_clear()
            .envs(&self.environment)
            .current_dir(&self.project);
        process
    }

    fn cli(&self, args: &[&str]) -> String {
        let output = self
            .process()
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn list(&self, scope: &str) -> Vec<serde_json::Value> {
        serde_json::from_str(&self.cli(&["allowlist", "list", scope, "--format", "json"])).unwrap()
    }

    fn hook(&self, command: &str) -> std::process::Output {
        let mut child = self
            .process()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let payload = serde_json::json!({
            "tool_name": "Bash", "cwd": self.project,
            "tool_input": {"command": command, "shell": "/bin/sh"}
        });
        child
            .stdin
            .take()
            .unwrap()
            .write_all(payload.to_string().as_bytes())
            .unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(
            result.status.success(),
            "{command}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        result
    }
}

fn environment(temp: &Path, home: &Path) -> BTreeMap<OsString, OsString> {
    [
        ("PATH", std::env::var_os("PATH").unwrap_or_default()),
        ("HOME", home.into()),
        ("USERPROFILE", home.into()),
        ("XDG_CONFIG_HOME", home.join(".config").into()),
        ("TMPDIR", temp.into()),
        ("TEMP", temp.into()),
        ("TMP", temp.into()),
        ("DCG_CONFIG", temp.join("config.toml").into()),
        ("DCG_SELF_HEAL_HOOK", "0".into()),
        ("DCG_HOOK_TIMEOUT_MS", "10000".into()),
        (
            "DCG_ALLOWLIST_SYSTEM_PATH",
            temp.join("no-system.toml").into(),
        ),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value))
    .collect()
}

#[test]
fn learned_filesystem_cli_lists_removes_and_prunes_separately_from_trials() {
    let fixture = Fixture::new();
    let command = format!("/bin/rm -r '{}'", fixture.project.join("input").display());
    let fingerprint = effects::fingerprint(
        &command,
        &fixture.project,
        "core.filesystem:rm-recursive-general",
        &fixture.environment,
    )
    .unwrap();
    let entry = fixture
        .store
        .approve_learned(&fingerprint, "Approved one unchanged file")
        .unwrap();
    let entries = fixture.list("--user");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["kind"], "learned_filesystem");
    assert_eq!(entries[0]["source"], "user-review");
    assert_eq!(entries[0]["command"], command);
    assert_eq!(entries[0]["cwd"], fixture.project.to_str().unwrap());
    assert_eq!(entries[0]["rule_id"], fingerprint.rule_id);
    assert_eq!(
        entries[0]["operands"][0],
        fingerprint.operands[0].to_str().unwrap()
    );
    assert_eq!(entries[0]["selector"]["type"], "learned_filesystem");
    assert_eq!(entries[0]["selector"]["value"], fingerprint.digest);
    assert_eq!(fixture.list("--project"), entries);
    let unchanged: serde_json::Value =
        serde_json::from_str(&fixture.cli(&["allowlist", "prune", "--user", "--format", "json"]))
            .unwrap();
    assert_eq!(unchanged["pruned"], 0);
    assert_eq!(fixture.list("--user").len(), 1);
    let pretty = fixture.cli(&["allowlist", "list", "--user"]);
    assert!(pretty.contains(&format!("learned_filesystem:{}", entry.fingerprint)));
    assert!(pretty.contains(&format!("Rule: {}", entry.rule_id)));
    fixture.cli(&[
        "allowlist",
        "remove",
        &format!("learned_filesystem:{}", entry.fingerprint),
        "--user",
    ]);
    assert!(fixture.list("--user").is_empty());

    fixture
        .store
        .approve_learned(&fingerprint, "Approved again")
        .unwrap();
    fs::write(fixture.project.join("input"), "changed").unwrap();
    let preview: serde_json::Value = serde_json::from_str(&fixture.cli(&[
        "allowlist",
        "prune",
        "--user",
        "--dry-run",
        "--format",
        "json",
    ]))
    .unwrap();
    assert_eq!(preview["dry_run"], true);
    assert_eq!(preview["pruned"], 1);
    assert_eq!(preview["verified_trials_pruned"], 0);
    assert_eq!(preview["learned_filesystem_pruned"], 1);
    assert_eq!(fixture.list("--user").len(), 1);
    let pruned: serde_json::Value =
        serde_json::from_str(&fixture.cli(&["allowlist", "prune", "--user", "--format", "json"]))
            .unwrap();
    assert_eq!(pruned["dry_run"], false);
    assert_eq!(pruned["learned_filesystem_pruned"], 1);
    assert!(fixture.list("--user").is_empty());
}

#[test]
fn hook_allows_bounded_single_file_move_without_executing_it() {
    let fixture = Fixture::new();
    let source = fixture.home.join("source");
    let destination = fixture.project.join("destination");
    fs::write(&source, "original source").unwrap();
    fs::write(&destination, "original destination").unwrap();
    let command = format!("/bin/mv ~/source '{}'", destination.display());
    let output = fixture.hook(&command);
    assert!(
        output.stdout.is_empty(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(source).unwrap(), "original source");
    assert_eq!(
        fs::read_to_string(destination).unwrap(),
        "original destination"
    );
    assert!(fixture.store.list_learned().unwrap().is_empty());
}

#[test]
fn hook_self_protected_paths_always_require_review_and_never_learn() {
    let fixture = Fixture::new();
    for relative in [
        ".config/dcg/policy.toml",
        "Library/Application Support/dcg/state",
        ".claude/settings.json",
        ".claude/settings.local.json",
        ".codex/hooks.json",
        ".codex/config.toml",
        ".config/opencode/plugins/dcg-guard.js",
        ".opencode/plugins/dcg-guard.js",
        ".grok/hooks/dcg.json",
        ".gemini/config/hooks.json",
        ".pi/agent/extensions/dcg-guard.ts",
    ] {
        let path = fixture.home.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "protected contents").unwrap();
        let command = format!("/bin/rm ~/{}", shell_words::quote(relative));
        for _ in 0..2 {
            let output = fixture.hook(&command);
            let denial: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(
                denial["hookSpecificOutput"]["permissionDecision"], "deny",
                "{relative}: {denial}"
            );
            let reason = denial["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap();
            assert!(
                reason.contains(effects::SELF_PROTECTION),
                "{relative}: {reason}"
            );
            assert!(denial["hookSpecificOutput"].get("allowOnceCode").is_none());
            assert!(fixture.store.list_learned().unwrap().is_empty());
            assert_eq!(fs::read_to_string(&path).unwrap(), "protected contents");
        }
    }
}

#[test]
fn hook_recursive_ancestor_of_managed_configuration_is_never_learned() {
    let fixture = Fixture::new();
    let settings = fixture.home.join("project/.claude/settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "protected contents").unwrap();
    // Managed descendants require review even when addressed through /tmp.
    let command = format!(
        "/bin/rm -r '{}'",
        fixture.temp.path().join("home/project").display()
    );
    for _ in 0..2 {
        let output = fixture.hook(&command);
        let denial: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(denial["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(
            denial["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap()
                .contains(effects::SELF_PROTECTION),
            "{denial}"
        );
        assert!(denial["hookSpecificOutput"].get("allowOnceCode").is_none());
        assert!(fixture.store.list_learned().unwrap().is_empty());
        assert_eq!(fs::read_to_string(&settings).unwrap(), "protected contents");
    }
}

/// A Touch ID script approval holds until a reviewed script changes, through
/// every hook for the project, including one without trials or the dialog.
#[test]
fn approved_scripts_hold_until_a_reviewed_script_changes() {
    let fixture = Fixture::new();
    let script = fixture.project.join("run.sh");
    // The dynamic source keeps static inspection inconclusive.
    fs::write(&script, "printf 'step\\n'\n. \"./lib/${STEP}.sh\"\n").unwrap();
    fs::write(fixture.project.join("notes.txt"), "draft").unwrap();
    let command = "/bin/sh ./run.sh";
    let denied = |output: &std::process::Output| {
        String::from_utf8_lossy(&output.stdout).contains("\"deny\"")
    };
    let unapproved = fixture.hook(command);
    assert!(denied(&unapproved), "{unapproved:?}");

    // What the desktop review records after Touch ID, bound to the same
    // inherited environment as the spawned hook.
    let version = fixture
        .store
        .script_version(command, &fixture.project, std::slice::from_ref(&script))
        .unwrap();
    let entry = fixture.store.approve_scripts(&version, "Touch ID").unwrap();
    for _ in 0..2 {
        let approved = fixture.hook(command);
        assert!(approved.stdout.is_empty(), "{approved:?}");
        assert!(
            String::from_utf8_lossy(&approved.stderr).contains("scripts unchanged"),
            "{approved:?}"
        );
        // Unrelated project edits do not ask again.
        fs::write(fixture.project.join("notes.txt"), "rewritten").unwrap();
    }
    let listed = fixture.list("--user");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["selector"]["type"], "approved_scripts");
    assert_eq!(listed[0]["selector"]["value"], entry.fingerprint);
    assert_eq!(listed[0]["command"], command);
    assert_eq!(listed[0]["scripts"][0], script.to_str().unwrap());

    // Editing the approved script requires review again.
    fs::write(&script, "printf 'changed\\n'\n. \"./lib/${STEP}.sh\"\n").unwrap();
    let changed = fixture.hook(command);
    assert!(denied(&changed), "{changed:?}");
    assert!(!String::from_utf8_lossy(&changed.stderr).contains("scripts unchanged"));
    fixture.cli(&["allowlist", "prune", "--user"]);
    assert!(fixture.store.list_scripts().unwrap().is_empty());
}

/// Fork issue #1: a script whose tar arguments are only known at runtime can
/// be approved like any unverified script, but an approval never covers a
/// tar helper dcg identified in that script.
#[test]
fn approved_scripts_cover_unresolved_tar_values_but_never_a_tar_helper() {
    let fixture = Fixture::new();
    let script = fixture.project.join("archive.py");
    let command = "python3 ./archive.py";
    let approve = |source: &str| {
        fs::write(&script, source).unwrap();
        let version = fixture
            .store
            .script_version(command, &fixture.project, std::slice::from_ref(&script))
            .unwrap();
        fixture.store.approve_scripts(&version, "Touch ID").unwrap();
    };
    let decision = |output: &std::process::Output| {
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        (stdout.contains("\"deny\""), stdout)
    };

    approve(
        "import subprocess, sys\nsubprocess.run(['tar', '-cf', '-', '-C', '/tmp/x', sys.argv[1]])\n",
    );
    let unresolved = fixture.hook(command);
    assert!(!decision(&unresolved).0, "{:?}", decision(&unresolved).1);
    assert!(String::from_utf8_lossy(&unresolved.stderr).contains("scripts unchanged"));

    // Same review route, approved too, but the helper is definite.
    approve("import subprocess\nsubprocess.run(['tar', '-xf', 'a.tar', '--to-command=sh'])\n");
    let helper = fixture.hook(command);
    let (denied, stdout) = decision(&helper);
    assert!(denied, "{stdout}");
    assert!(stdout.contains("tar-exec-unverified"), "{stdout}");
}
