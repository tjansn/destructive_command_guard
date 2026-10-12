//! Real macOS sandbox tests. Every target and every store lives in one TempDir.
//! There are no external requests: the network fixture uses a reserved address
//! with explicit DNS resolution and Seatbelt rejects its connect syscall.

#[cfg(target_os = "macos")]
mod macos {
    use destructive_command_guard::config::TrialConfig;
    use destructive_command_guard::trial::{self, TrialReport, Verdict};
    use destructive_command_guard::trial_store::TrialStore;
    use std::fs;
    use std::io::Write;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::time::Instant;

    struct Fixture {
        temp: tempfile::TempDir,
        project: std::path::PathBuf,
        store: TrialStore,
    }

    impl Fixture {
        fn new(script: &str) -> Self {
            let temp = tempfile::tempdir().unwrap();
            let project_path = temp.path().join("project");
            fs::create_dir(&project_path).unwrap();
            let project = fs::canonicalize(project_path).unwrap();
            fs::write(project.join("run.sh"), script).unwrap();
            fs::write(project.join("source.txt"), "original source").unwrap();
            let store = TrialStore::new(temp.path().join("state"));
            Self {
                temp,
                project,
                store,
            }
        }

        fn run(&self, timeout_secs: u64) -> TrialReport {
            let fingerprint = self
                .store
                .fingerprint("/bin/sh ./run.sh", &self.project, Path::new("/bin/sh"), &[])
                .unwrap();
            trial::run(
                "/bin/sh ./run.sh",
                &fingerprint,
                Path::new("/bin/sh"),
                &TrialConfig {
                    timeout_secs,
                    ..TrialConfig::default()
                },
                self.temp.path(),
            )
        }
    }

    #[test]
    fn safe_build_failing_tests_store_cache_and_source_invalidation() {
        let fixture = Fixture::new("mkdir -p build; cat source.txt > build/out; exit 7");
        let before = fixture
            .store
            .fingerprint(
                "/bin/sh ./run.sh",
                &fixture.project,
                Path::new("/bin/sh"),
                &[],
            )
            .unwrap();
        let report = fixture.run(10);
        eprintln!("{}", report.summary(None));
        assert_eq!(
            report.observations.verdict(),
            Verdict::Safe,
            "{}",
            report.summary(None)
        );
        assert!(!fixture.project.join("build").exists());
        fixture
            .store
            .approve(&before, "trial", &report.summary(None))
            .unwrap();
        let started = Instant::now();
        let current = fixture
            .store
            .fingerprint(
                "/bin/sh ./run.sh",
                &fixture.project,
                Path::new("/bin/sh"),
                &[],
            )
            .unwrap();
        assert!(fixture.store.lookup(&current).unwrap().is_some());
        eprintln!("verified lookup {} ms", started.elapsed().as_millis());
        fs::write(fixture.project.join("source.txt"), "changed source").unwrap();
        let changed = fixture
            .store
            .fingerprint(
                "/bin/sh ./run.sh",
                &fixture.project,
                Path::new("/bin/sh"),
                &[],
            )
            .unwrap();
        assert!(fixture.store.lookup(&changed).unwrap().is_none());
        let repeated = fixture.run(10);
        assert_ne!(report.id, repeated.id);
        assert_eq!(
            repeated.observations.verdict(),
            Verdict::Safe,
            "{}",
            repeated.summary(None)
        );
    }

    #[test]
    fn cli_trial_summary_allowlist_remove_and_prune_lifecycle() {
        let fixture = Fixture::new("mkdir -p build; cat source.txt > build/out");
        let home = fixture.temp.path().join("home");
        fs::create_dir(&home).unwrap();
        let config = fixture.temp.path().join("config.toml");
        fs::write(&config, "[trial]\ntimeout_secs = 10\n").unwrap();
        let cli = |args: &[&str]| {
            let output = Command::new(env!("CARGO_BIN_EXE_dcg"))
                .args(args)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("SHELL", "/bin/sh")
                .env("HOME", &home)
                .env("USERPROFILE", &home)
                .env("XDG_CONFIG_HOME", home.join(".config"))
                .env("TMPDIR", fixture.temp.path())
                .env("TEMP", fixture.temp.path())
                .env("TMP", fixture.temp.path())
                .env("DCG_CONFIG", &config)
                .env("DCG_SELF_HEAL_HOOK", "0")
                .env(
                    "DCG_ALLOWLIST_SYSTEM_PATH",
                    fixture.temp.path().join("no-system.toml"),
                )
                .current_dir(&fixture.project)
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
        };
        let list = || {
            serde_json::from_str::<Vec<serde_json::Value>>(&cli(&[
                "allowlist",
                "list",
                "--user",
                "--format",
                "json",
            ]))
            .unwrap()
        };
        assert!(list().is_empty());
        let summary = cli(&["trial", "run", "--", "/bin/sh", "./run.sh"]);
        assert!(summary.contains(": Safe."), "{summary}");
        let id = summary
            .split_whitespace()
            .nth(2)
            .unwrap()
            .strip_suffix(':')
            .unwrap();
        assert_eq!(cli(&["trial", "show", id]), summary);
        let entries = list();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry["kind"], "verified_trial");
        assert_eq!(entry["source"], "trial");
        assert_eq!(entry["command"], "/bin/sh ./run.sh");
        assert_eq!(entry["project_root"], fixture.project.to_str().unwrap());
        assert_eq!(entry["selector"]["type"], "verified_trial");
        assert_eq!(entry["selector"]["value"], entry["fingerprint"]);
        let fingerprint = entry["fingerprint"].as_str().unwrap();
        cli(&[
            "allowlist",
            "remove",
            &format!("verified_trial:{fingerprint}"),
            "--user",
        ]);
        assert!(list().is_empty());
        assert_eq!(cli(&["trial", "show", id]), summary);

        let repeated = cli(&["trial", "run", "--", "/bin/sh", "./run.sh"]);
        assert!(repeated.contains(": Safe."), "{repeated}");
        let entries = list();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["fingerprint"], fingerprint);
        assert!(!fixture.project.join("build").exists());
        assert_eq!(
            fs::read_to_string(fixture.project.join("source.txt")).unwrap(),
            "original source"
        );
        fs::write(fixture.project.join("source.txt"), "changed source").unwrap();
        let preview: serde_json::Value = serde_json::from_str(&cli(&[
            "allowlist",
            "prune",
            "--user",
            "--dry-run",
            "--format",
            "json",
        ]))
        .unwrap();
        assert_eq!(preview["dry_run"], true);
        assert_eq!(preview["verified_trials_pruned"], 1);
        assert_eq!(list().len(), 1);
        let pruned: serde_json::Value =
            serde_json::from_str(&cli(&["allowlist", "prune", "--user", "--format", "json"]))
                .unwrap();
        assert_eq!(pruned["dry_run"], false);
        assert_eq!(pruned["verified_trials_pruned"], 1);
        assert!(list().is_empty());
    }

    #[test]
    fn child_cannot_delete_outside_victim() {
        let fixture = Fixture::new("");
        let victim = fixture.temp.path().join("outside/victim");
        fs::create_dir_all(&victim).unwrap();
        fs::write(victim.join("keep"), "preserved").unwrap();
        fs::write(
            fixture.project.join("run.sh"),
            format!(
                "/bin/sh -c {}",
                shell_words::quote(&format!(
                    "/bin/rm -rf {}",
                    shell_words::quote(&victim.display().to_string())
                ))
            ),
        )
        .unwrap();
        let report = fixture.run(10);
        assert!(victim.join("keep").exists());
        assert_eq!(
            report.observations.verdict(),
            Verdict::Unsafe,
            "{}",
            report.summary(None)
        );
        assert!(report.summary(None).contains("outside/victim"));
    }

    #[test]
    fn deleting_tracked_source_only_mutates_clone() {
        let fixture = Fixture::new("rm source.txt");
        assert!(
            Command::new("/usr/bin/git")
                .args(["init", "-q"])
                .arg(&fixture.project)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("/usr/bin/git")
                .arg("-C")
                .arg(&fixture.project)
                .args(["add", "source.txt", "run.sh"])
                .status()
                .unwrap()
                .success()
        );
        let report = fixture.run(10);
        assert_eq!(
            report.observations.verdict(),
            Verdict::Unsafe,
            "{}",
            report.summary(None)
        );
        assert_eq!(
            fs::read_to_string(fixture.project.join("source.txt")).unwrap(),
            "original source"
        );
        assert_eq!(report.observations.deleted, ["source.txt"]);
    }

    #[test]
    fn network_attempt_is_inconclusive_and_blocked() {
        let fixture = Fixture::new(
            "/usr/bin/curl --noproxy '*' --resolve example.com:443:192.0.2.1 --connect-timeout 1 https://example.com",
        );
        let report = fixture.run(10);
        assert_eq!(
            report.observations.verdict(),
            Verdict::Inconclusive,
            "{}",
            report.summary(None)
        );
        assert!(
            report
                .observations
                .violations
                .iter()
                .any(|v| v.operation.starts_with("network")),
            "{}",
            report.summary(None)
        );
    }

    #[test]
    fn cloned_git_state_is_not_disposable_build_output() {
        let fixture = Fixture::new("printf changed > .git/config");
        fs::create_dir(fixture.project.join(".git")).unwrap();
        fs::write(fixture.project.join(".git/config"), "original").unwrap();
        let report = fixture.run(10);
        assert_eq!(
            report.observations.verdict(),
            Verdict::Unsafe,
            "{}",
            report.summary(None)
        );
        assert_eq!(
            fs::read_to_string(fixture.project.join(".git/config")).unwrap(),
            "original"
        );
        assert!(report.summary(None).contains(".git/config"));
    }

    #[test]
    fn timeout_kills_group_and_cleans_trial_directory() {
        let fixture = Fixture::new("sleep 30 & wait");
        let report = fixture.run(1);
        assert_eq!(report.observations.verdict(), Verdict::Inconclusive);
        assert!(report.observations.timed_out, "{}", report.summary(None));
        assert!(!fs::read_dir(fixture.temp.path()).unwrap().any(|p| {
            p.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("dcg-trial-")
        }));
    }

    #[test]
    fn outside_process_signal_is_denied() {
        let fixture = Fixture::new("");
        let mut target = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        fs::write(
            fixture.project.join("run.sh"),
            format!("kill -TERM {}", target.id()),
        )
        .unwrap();
        let report = fixture.run(10);
        let survived = target.try_wait().unwrap().is_none();
        let _ = target.kill();
        let _ = target.wait();
        assert!(survived);
        assert_eq!(
            report.observations.verdict(),
            Verdict::Unsafe,
            "{}",
            report.summary(None)
        );
        assert!(
            report
                .observations
                .violations
                .iter()
                .any(|v| v.operation == "signal")
        );
    }

    #[test]
    fn finite_loopback_exchange_is_allowed_and_closes_its_socket() {
        let fixture = Fixture::new(
            "python3 -c 'import socket; s=socket.socket(); s.bind((\"127.0.0.1\",0)); s.listen(1); c=socket.create_connection(s.getsockname()); a,_=s.accept(); a.sendall(b\"ok\"); assert c.recv(2)==b\"ok\"; a.close(); c.close(); s.close()'",
        );
        let report = fixture.run(10);
        assert_eq!(report.exit_code, Some(0), "{}", report.summary(None));
        assert_eq!(
            report.observations.verdict(),
            Verdict::Safe,
            "{}",
            report.summary(None)
        );
    }

    #[test]
    fn detached_child_cannot_earn_a_safe_finite_trial() {
        let fixture = Fixture::new(
            "mkdir -p build; /bin/sleep 30 > build/output 2>&1 < /dev/null & echo $! > build/child.pid",
        );
        let fingerprint = fixture
            .store
            .fingerprint(
                "/bin/sh ./run.sh",
                &fixture.project,
                Path::new("/bin/sh"),
                &[],
            )
            .unwrap();
        let report = trial::run(
            "/bin/sh ./run.sh",
            &fingerprint,
            Path::new("/bin/sh"),
            &TrialConfig {
                timeout_secs: 10,
                keep_artifacts: true,
                ..TrialConfig::default()
            },
            fixture.temp.path(),
        );
        assert_eq!(
            report.observations.verdict(),
            Verdict::Inconclusive,
            "{}",
            report.summary(None)
        );
        let pid: i32 = fs::read_to_string(
            report
                .artifact_dir
                .as_ref()
                .unwrap()
                .join("project/build/child.pid"),
        )
        .unwrap()
        .trim()
        .parse()
        .unwrap();
        let alive = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_ok();
        if alive {
            let status = Command::new("/bin/ps")
                .args(["-p", &pid.to_string(), "-o", "stat="])
                .output()
                .unwrap();
            assert!(
                String::from_utf8_lossy(&status.stdout)
                    .trim()
                    .starts_with('Z'),
                "trial child remains running: {pid}"
            );
        }
        assert!(!fixture.project.join("build").exists());
    }

    fn hook(fixture: &Fixture, command: &str) -> std::process::Output {
        let home = fixture.temp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let config = fixture.temp.path().join("config.toml");
        fs::write(
            &config,
            "[heredoc]\nscan_script_files = true\n[trial]\ntimeout_secs = 10\n",
        )
        .unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_dcg"))
            .env_clear()
            .env("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin")
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("TMPDIR", fixture.temp.path())
            .env("TEMP", fixture.temp.path())
            .env("TMP", fixture.temp.path())
            .env("DCG_CONFIG", &config)
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env(
                "DCG_ALLOWLIST_SYSTEM_PATH",
                fixture.temp.path().join("no-system.toml"),
            )
            .env("DCG_HOOK_TIMEOUT_MS", "10000")
            .current_dir(&fixture.project)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let payload = serde_json::json!({"tool_name":"Bash", "cwd": fixture.project, "tool_input":{"command":command,"shell":"/bin/sh"}});
        child
            .stdin
            .take()
            .unwrap()
            .write_all(payload.to_string().as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    #[test]
    fn hook_unverified_package_allows_safe_and_denies_malicious() {
        let fixture = Fixture::new("mkdir -p build; cat source.txt > build/out");
        fs::write(
            fixture.project.join("package.json"),
            r#"{"scripts":{"test":"node --test test.cjs"}}"#,
        )
        .unwrap();
        fs::write(fixture.project.join("test.cjs"), "const fs = require('node:fs'); if (!fs.existsSync('build')) fs.mkdirSync('build'); fs.writeFileSync('build/out', fs.readFileSync('source.txt'));\n").unwrap();
        let output = hook(&fixture, "npm test");
        assert!(output.status.success());
        assert!(
            output.stdout.is_empty(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("exact version verified"));
        let cached = hook(&fixture, "npm test");
        assert!(cached.stdout.is_empty());
        assert!(String::from_utf8_lossy(&cached.stderr).contains("verified by trial on"));
        assert!(!String::from_utf8_lossy(&cached.stderr).contains("verifying `"));
        fs::write(
            fixture.project.join("test.cjs"),
            "require('node:fs').unlinkSync('source.txt');\n",
        )
        .unwrap();
        let denied = hook(&fixture, "npm test");
        let parsed: serde_json::Value = serde_json::from_slice(&denied.stdout).unwrap();
        assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(
            parsed["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap()
                .contains("deleted source")
        );
        assert!(fixture.project.join("source.txt").exists());
    }

    #[test]
    fn definite_match_after_unverified_command_never_runs_trial() {
        let fixture = Fixture::new("");
        fs::write(
            fixture.project.join("package.json"),
            r#"{"scripts":{"test":"node --test"}}"#,
        )
        .unwrap();
        let output = hook(&fixture, "npm test; git reset --hard");
        assert!(String::from_utf8_lossy(&output.stdout).contains("reset --hard"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("verifying `"));
    }

    #[test]
    fn literal_absolute_cd_maps_into_trial_copy() {
        let fixture = Fixture::new("mkdir -p build; cat source.txt > build/out");
        let command = format!(
            "cd {} && /bin/sh ./run.sh",
            shell_words::quote(&fixture.project.display().to_string())
        );
        let fingerprint = fixture
            .store
            .fingerprint(&command, &fixture.project, Path::new("/bin/sh"), &[])
            .unwrap();
        let report = trial::run(
            &command,
            &fingerprint,
            Path::new("/bin/sh"),
            &TrialConfig::default(),
            fixture.temp.path(),
        );
        assert_eq!(
            report.observations.verdict(),
            Verdict::Safe,
            "{}",
            report.summary(None)
        );
        assert!(!fixture.project.join("build").exists());
    }

    #[test]
    fn warning_sibling_cannot_release_an_unverified_command() {
        let fixture = Fixture::new("printf safe");
        fs::write(
            fixture.project.join("package.json"),
            r#"{"scripts":{"test":"node --test test.mjs"}}"#,
        )
        .unwrap();
        fs::write(fixture.project.join("test.mjs"), "import 'node:test';").unwrap();
        let output = hook(&fixture, "npm test; git stash drop");
        let verdict: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            verdict["hookSpecificOutput"]["permissionDecision"], "deny",
            "{verdict}"
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("heredoc.script_files"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("verifying `"));
    }

    #[test]
    fn preview_service_requests_review_without_starting_or_minting_a_code() {
        let fixture = Fixture::new("printf safe");
        let log = fixture.temp.path().join("preview.log");
        let command = format!(
            "nohup python3 -m http.server 18476 --bind 127.0.0.1 --directory {} > {} 2>&1 < /dev/null &",
            shell_words::quote(&fixture.project.display().to_string()),
            shell_words::quote(&log.display().to_string())
        );
        let output = hook(&fixture, &command);
        let verdict: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let info = &verdict["hookSpecificOutput"];
        assert_eq!(info["permissionDecision"], "deny", "{verdict}");
        let reason = info["permissionDecisionReason"].as_str().unwrap();
        assert!(
            reason.contains("Inconclusive")
                && reason.contains("Background service/job was not started"),
            "{reason}"
        );
        assert!(info.get("allowOnceCode").is_none());
        assert!(!log.exists());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("verifying `"));
    }

    #[test]
    fn relative_site_test_workflow_learns_the_exact_version() {
        let fixture = Fixture::new("printf safe");
        fs::create_dir(fixture.project.join("site")).unwrap();
        fs::write(fixture.project.join("site/check.mjs"), "import fs from 'node:fs'; fs.mkdirSync('build', {recursive: true}); fs.writeFileSync('build/draft.html', '<p>Draft</p>');").unwrap();
        let command = "cd site && node --test check.mjs";
        let first = hook(&fixture, command);
        assert!(
            first.stdout.is_empty(),
            "{}",
            String::from_utf8_lossy(&first.stdout)
        );
        assert!(String::from_utf8_lossy(&first.stderr).contains("verifying `"));
        let second = hook(&fixture, command);
        assert!(second.stdout.is_empty());
        assert!(String::from_utf8_lossy(&second.stderr).contains("verified by trial"));
        assert!(!fixture.project.join("site/build").exists());
    }

    #[test]
    #[ignore = "manual timing probe requires DCG_TRIAL_BENCH_PROJECT pointing to a temporary pi-os copy"]
    fn pi_os_trial_overhead() {
        let root = std::path::PathBuf::from(
            std::env::var_os("DCG_TRIAL_BENCH_PROJECT").expect("temporary benchmark project"),
        );
        let root = fs::canonicalize(root).unwrap();
        let temp_root = fs::canonicalize("/tmp").unwrap();
        assert!(
            root.starts_with(&temp_root),
            "benchmark must use a temporary copy"
        );
        let temp = tempfile::tempdir().unwrap();
        let store = TrialStore::new(temp.path().join("state"));
        let cwd = root.join("node-harness");
        let start = Instant::now();
        let fingerprint = store
            .fingerprint("npm test", &cwd, Path::new("/bin/zsh"), &[])
            .unwrap();
        let cold_ms = start.elapsed().as_millis();
        let start = Instant::now();
        let warm = store
            .fingerprint("npm test", &cwd, Path::new("/bin/zsh"), &[])
            .unwrap();
        let warm_ms = start.elapsed().as_millis();
        assert_eq!(fingerprint.digest, warm.digest);
        let start = Instant::now();
        let report = trial::run(
            "npm test",
            &fingerprint,
            Path::new("/bin/zsh"),
            &TrialConfig {
                timeout_secs: 180,
                ..TrialConfig::default()
            },
            temp.path(),
        );
        eprintln!(
            "PI_OS_TIMING cold_fingerprint_ms={cold_ms} warm_fingerprint_ms={warm_ms} clone_ms={} run_ms={} total_trial_ms={} verdict={:?}",
            report.clone_ms,
            report.run_ms,
            start.elapsed().as_millis(),
            report.observations.verdict()
        );
        eprintln!("{}", report.summary(None));
        assert!(report.run_ms > 0, "trial must actually start");
    }
}

#[cfg(not(target_os = "macos"))]
#[test]
fn macos_integration_unavailable() {
    eprintln!("SKIP native sandbox trials: sandbox-exec integration requires macOS");
}
