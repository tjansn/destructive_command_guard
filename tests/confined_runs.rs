//! Continuing-confinement acceptance tests. Every project, credential, listener
//! victim and runtime directory is disposable fixture data inside one TempDir.
//! These tests execute new fixture programs only, never a blocked user command.

#[cfg(target_os = "macos")]
mod macos {
    use destructive_command_guard::config::ConfinedLoopback;
    use destructive_command_guard::confined::{self, Request, RunResult};
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::{Duration, Instant};

    struct Fixture {
        _directory: tempfile::TempDir,
        root: PathBuf,
        project: PathBuf,
        runtime: PathBuf,
    }

    impl Fixture {
        fn new(body: &str) -> Self {
            let directory = tempfile::tempdir().expect("fixture directory");
            let root = directory.path().canonicalize().expect("canonical root");
            let project = root.join("project");
            let home = root.join("home");
            let runtime = root.join("runtime");
            for path in [&project, &home, &runtime] {
                fs::create_dir(path).expect("fixture subdirectory");
            }
            fs::write(project.join(".gitignore"), "build/\n").expect("ignored build output");
            fs::write(project.join("tracked.txt"), "original tracked source")
                .expect("tracked fixture source");
            fs::write(
                project.join("case.test.cjs"),
                format!(
                    "const test = require('node:test');\n\
                     const assert = require('node:assert/strict');\n\
                     const fs = require('node:fs');\n\
                     test('confined fixture', async () => {{\n{body}\n}});\n"
                ),
            )
            .expect("fixture test source");
            for args in [&["init", "--quiet"][..], &["add", "--", "."][..]] {
                let output = Command::new("/usr/bin/git")
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .env("HOME", &home)
                    .env("USERPROFILE", &home)
                    .env("TMPDIR", &runtime)
                    .env("TEMP", &runtime)
                    .env("TMP", &runtime)
                    .env("GIT_CONFIG_NOSYSTEM", "1")
                    .env("GIT_CONFIG_GLOBAL", "/dev/null")
                    .args([
                        "-c",
                        "core.hooksPath=/dev/null",
                        "-c",
                        "core.fsmonitor=false",
                        "-c",
                        "init.templateDir=",
                    ])
                    .args(args)
                    .current_dir(&project)
                    .stdin(Stdio::null())
                    .output()
                    .expect("initialize fixture repository");
                assert!(
                    output.status.success(),
                    "fixture git {args:?}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Self {
                _directory: directory,
                root,
                project,
                runtime,
            }
        }

        fn run(&self, timeout_secs: u64) -> Result<RunResult, String> {
            self.run_with_loopback(timeout_secs, ConfinedLoopback::None)
        }

        fn run_with_loopback(
            &self,
            timeout_secs: u64,
            loopback: ConfinedLoopback,
        ) -> Result<RunResult, String> {
            confined::run(
                &Request::new(
                    "node --test ./case.test.cjs",
                    &self.project,
                    Path::new("/bin/sh"),
                    timeout_secs,
                )
                .with_loopback(loopback),
                &self.runtime,
                loopback,
            )
        }

        fn replace_body(&self, body: &str) {
            fs::write(
                self.project.join("case.test.cjs"),
                format!(
                    "const test = require('node:test');\n\
                     const assert = require('node:assert/strict');\n\
                     const fs = require('node:fs');\n\
                     test('confined fixture', async () => {{\n{body}\n}});\n"
                ),
            )
            .expect("replace temporary fixture source");
        }
    }

    fn details(result: &RunResult) -> String {
        format!(
            "exit={} timed_out={} elapsed_ms={} violations={:?}\nstdout={}\nstderr={}",
            result.exit_code,
            result.timed_out,
            result.elapsed_ms,
            result.violations,
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        )
    }

    fn assert_violation(result: &RunResult, operation: &str, target: &str) {
        assert_ne!(result.exit_code, 0, "{}", details(result));
        assert!(!result.timed_out, "{}", details(result));
        let kernel_report = result.violations.iter().any(|violation| {
            violation.operation.starts_with(operation) && violation.target.contains(target)
        });
        // The acceptance contract requires an enforced denial and an operation/
        // target in the real result, not infallible logd delivery. Node reports
        // its failed syscall even when the tagged kernel event is omitted.
        // Never manufacture a kernel Violation from this untrusted output.
        let stdout = String::from_utf8_lossy(&result.stdout);
        let stderr = String::from_utf8_lossy(&result.stderr);
        let syscall = match operation {
            "file-write" | "file-read" => "syscall: 'open'",
            "file-link" => "syscall: 'link'",
            "network" => "syscall: 'connect'",
            _ => panic!("unmapped fixture operation {operation}"),
        };
        let reported_syscall = stdout.contains("code: 'EPERM'")
            && stdout.contains(syscall)
            && stdout.contains(target)
            && stderr.contains("[dcg:confined-limit] the command reported a permission error");
        assert!(
            kernel_report || reported_syscall,
            "missing {operation} operation report for {target}: {}",
            details(result)
        );
    }

    #[test]
    fn ignored_build_output_is_real_and_the_fixture_executes_once() {
        let body = "fs.mkdirSync('build', { recursive: true });\n\
             const previous = fs.existsSync('build/count') ? Number(fs.readFileSync('build/count', 'utf8')) : 0;\n\
             fs.writeFileSync('build/count', String(previous + 1));\n\
             fs.writeFileSync('build/output.txt', fs.readFileSync('tracked.txt'));\n\
             assert.equal(previous + 1, 1);\n\
             console.log('fixture-build-complete');";
        // Paired cost measurement uses a separate, disposable copy of this
        // known harmless fixture; each copy executes exactly once.
        let baseline = Fixture::new(body);
        let started = Instant::now();
        let plain = Command::new("node")
            .args(["--test", "case.test.cjs"])
            .current_dir(&baseline.project)
            .env_clear()
            .envs(confined::environment(
                std::env::vars_os(),
                &baseline.root.join("home"),
                &baseline.runtime,
            ))
            .stdin(Stdio::null())
            .output()
            .expect("bounded harmless baseline fixture");
        let baseline_ms = started.elapsed().as_millis();
        assert!(
            plain.status.success(),
            "{}",
            String::from_utf8_lossy(&plain.stderr)
        );
        assert_eq!(
            fs::read_to_string(baseline.project.join("build/count")).unwrap(),
            "1"
        );
        let fixture = Fixture::new(body);
        let result = fixture.run(15).expect("confined fixture build");
        eprintln!(
            "paired fixture cost: baseline={baseline_ms} ms confined={} ms added={} ms",
            result.elapsed_ms,
            result.elapsed_ms.saturating_sub(baseline_ms)
        );
        assert_eq!(result.exit_code, 0, "{}", details(&result));
        assert!(!result.timed_out, "{}", details(&result));
        assert!(result.violations.is_empty(), "{}", details(&result));
        assert_eq!(
            fs::read_to_string(fixture.project.join("build/count")).unwrap(),
            "1"
        );
        assert_eq!(
            fs::read_to_string(fixture.project.join("build/output.txt")).unwrap(),
            "original tracked source"
        );
        assert!(String::from_utf8_lossy(&result.stdout).contains("fixture-build-complete"));
        eprintln!(
            "confined real-workspace fixture build: {} ms",
            result.elapsed_ms
        );
    }

    #[test]
    fn a_failing_test_preserves_the_node_test_runner_exit_status() {
        let fixture = Fixture::new("assert.fail('fixture failure reached the real test runner');");
        let result = fixture.run(15).expect("confined failing fixture test");
        assert_eq!(result.exit_code, 1, "{}", details(&result));
        assert!(!result.timed_out, "{}", details(&result));
        assert!(result.violations.is_empty(), "{}", details(&result));
        assert!(
            String::from_utf8_lossy(&result.stdout)
                .contains("fixture failure reached the real test runner"),
            "{}",
            details(&result)
        );
    }

    #[test]
    fn tracked_source_writes_are_denied_and_reported() {
        let fixture = Fixture::new("fs.writeFileSync('tracked.txt', 'changed');");
        let result = fixture.run(15).expect("tracked-write fixture result");
        assert_violation(&result, "file-write", "tracked.txt");
        assert_eq!(
            fs::read_to_string(fixture.project.join("tracked.txt")).unwrap(),
            "original tracked source"
        );
    }

    #[test]
    fn writes_outside_the_project_leave_the_fixture_victim_unchanged() {
        let fixture = Fixture::new("");
        let victim = fixture.root.join("outside-victim.txt");
        fs::write(&victim, "unchanged fixture victim").unwrap();
        fixture.replace_body(&format!(
            "fs.writeFileSync({}, 'changed');",
            serde_json::to_string(&victim).unwrap()
        ));
        let result = fixture.run(15).expect("outside-write fixture result");
        assert_violation(&result, "file-write", "outside-victim.txt");
        assert_eq!(
            fs::read_to_string(victim).unwrap(),
            "unchanged fixture victim"
        );
    }

    #[test]
    fn fixture_credentials_cannot_be_read_or_copied_into_output() {
        let fixture = Fixture::new("");
        let credential = fixture.root.join("fixture-host/.ssh/private-key");
        fs::create_dir_all(credential.parent().unwrap()).unwrap();
        let marker = "fixture-only-confined-credential-canary";
        fs::write(&credential, marker).unwrap();
        fixture.replace_body(&format!(
            "console.log(fs.readFileSync({}, 'utf8'));",
            serde_json::to_string(&credential).unwrap()
        ));
        let result = fixture.run(15).expect("credential-read fixture result");
        assert_violation(&result, "file-read", "private-key");
        assert!(!String::from_utf8_lossy(&result.stdout).contains(marker));
        assert!(!String::from_utf8_lossy(&result.stderr).contains(marker));
        assert_eq!(fs::read_to_string(credential).unwrap(), marker);
    }

    #[test]
    fn trusted_all_explicitly_accepts_preexisting_loopback_deputies() {
        for loopback in [ConfinedLoopback::None, ConfinedLoopback::All] {
            let fixture = Fixture::new("");
            let victim = fixture.root.join("deputy-victim.txt");
            fs::write(&victim, "unchanged").unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").expect("fixture loopback listener");
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let stopped = Arc::new(AtomicBool::new(false));
            let stop = Arc::clone(&stopped);
            let target = victim.clone();
            let server = std::thread::spawn(move || {
                let started = Instant::now();
                while !stop.load(Ordering::SeqCst) && started.elapsed() < Duration::from_secs(25) {
                    if let Ok((mut stream, _)) = listener.accept() {
                        stream
                            .set_read_timeout(Some(Duration::from_millis(500)))
                            .unwrap();
                        let mut request = [0; 1024];
                        if stream.read(&mut request).unwrap_or(0) > 0 {
                            fs::write(&target, "delegated mutation").unwrap();
                            let _ =
                                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                        }
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            });
            fixture.replace_body(&format!(
            "await new Promise((resolve, reject) => {{\n\
             const request = require('node:http').get('http://{address}/mutate', response => {{ response.resume(); response.on('end', resolve); }});\n\
             request.on('error', reject);\n\
             request.setTimeout(2000, () => request.destroy(new Error('fixture network timeout')));\n\
             }});"
        ));
            let result = fixture.run_with_loopback(15, loopback);
            stopped.store(true, Ordering::SeqCst);
            server.join().expect("join fixture deputy");
            let result = result.expect("loopback deputy fixture result");
            if loopback == ConfinedLoopback::None {
                assert_violation(&result, "network", &format!(":{}", address.port()));
                assert!(
                    String::from_utf8_lossy(&result.stdout).contains("127.0.0.1"),
                    "{}",
                    details(&result)
                );
                assert_eq!(fs::read_to_string(victim).unwrap(), "unchanged");
            } else {
                assert_eq!(result.exit_code, 0, "{}", details(&result));
                assert_eq!(fs::read_to_string(victim).unwrap(), "delegated mutation");
            }
        }
    }

    #[test]
    fn owned_tcp_listeners_require_the_trusted_all_opt_in() {
        for loopback in [ConfinedLoopback::None, ConfinedLoopback::All] {
            for (listen, connect) in [
                ("127.0.0.1", "127.0.0.1"),
                ("::1", "::1"),
                ("127.0.0.1", "::ffff:127.0.0.1"),
            ] {
                let body = format!(
                    "const net = require('node:net');\n\
                     const server = net.createServer(socket => socket.end('fixture response'));\n\
                     await new Promise((resolve, reject) => {{ server.once('error', reject); server.listen(0, '{listen}', resolve); }});\n\
                     try {{\n\
                       const result = await new Promise(resolve => {{\n\
                         const socket = net.connect(server.address().port, '{connect}');\n\
                         socket.setTimeout(2000, () => {{ socket.destroy(); resolve('TIMEOUT'); }});\n\
                         socket.once('data', data => {{ socket.destroy(); resolve(data.toString()); }});\n\
                         socket.once('error', error => resolve(error.code));\n\
                       }});\n\
                       assert.equal(result, '{}');\n\
                     }} finally {{ await new Promise(resolve => server.close(resolve)); }}",
                    if loopback == ConfinedLoopback::All {
                        "fixture response"
                    } else {
                        "EPERM"
                    }
                );
                let fixture = Fixture::new(&body);
                let result = fixture.run_with_loopback(15, loopback).unwrap();
                assert_eq!(
                    result.exit_code,
                    0,
                    "{loopback:?} {connect}: {}",
                    details(&result)
                );
                assert!(!result.timed_out, "{}", details(&result));
                assert!(String::from_utf8_lossy(&result.stderr).contains(loopback.receipt()));
            }
        }
    }

    #[test]
    fn localhost_opt_in_does_not_open_non_loopback_tcp() {
        let fixture = Fixture::new(
            "const result = await new Promise(resolve => {\n\
               const socket = require('node:net').connect(9, '192.0.2.1');\n\
               socket.setTimeout(2000, () => { socket.destroy(); resolve('TIMEOUT'); });\n\
               socket.once('connect', () => { socket.destroy(); resolve('CONNECTED'); });\n\
               socket.once('error', error => resolve(error.code));\n\
             });\n\
             assert.equal(result, 'EPERM');",
        );
        let result = fixture
            .run_with_loopback(15, ConfinedLoopback::All)
            .unwrap();
        assert_eq!(result.exit_code, 0, "{}", details(&result));
        assert!(!result.timed_out);
    }

    #[test]
    fn receipt_cannot_enable_localhost_without_matching_trusted_config() {
        let fixture =
            Fixture::new("fs.mkdirSync('build'); fs.writeFileSync('build/marker', 'executed');");
        let request = Request::new(
            "node --test ./case.test.cjs",
            &fixture.project,
            Path::new("/bin/sh"),
            15,
        )
        .with_loopback(ConfinedLoopback::All);
        let error = confined::run(&request, &fixture.runtime, ConfinedLoopback::None).unwrap_err();
        assert!(error.contains("differs from the confined receipt"));
        assert!(!fixture.project.join("build/marker").exists());
    }

    #[test]
    fn timeout_stops_descendants_before_returning_the_real_result() {
        let fixture = Fixture::new(
            "fs.mkdirSync('build', { recursive: true });\n\
             require('node:child_process').spawn(process.execPath, ['-e', \"const fs = require('node:fs'); const timer = setInterval(() => fs.appendFileSync('build/heartbeat', 'x'), 50); setTimeout(() => clearInterval(timer), 3000);\"], { stdio: 'ignore' });\n\
             await new Promise(resolve => setTimeout(resolve, 5000));",
        );
        let result = fixture.run(1).expect("timeout fixture result");
        assert!(result.timed_out, "{}", details(&result));
        assert_ne!(result.exit_code, 0, "{}", details(&result));
        let heartbeat = fixture.project.join("build/heartbeat");
        let before = fs::read(&heartbeat).expect("fixture child started before deadline");
        std::thread::sleep(Duration::from_millis(250));
        let after = fs::read(&heartbeat).expect("fixture heartbeat remains readable");
        if before != after {
            // The child has its own short lifetime even if supervision fails;
            // keep its disposable output root alive until it exits naturally.
            std::thread::sleep(Duration::from_secs(3));
        }
        assert_eq!(
            before,
            after,
            "descendant survived timeout: {}",
            details(&result)
        );
    }

    #[test]
    fn a_tracked_source_cannot_be_hard_linked_into_an_ignored_write_root() {
        let fixture = Fixture::new(
            "fs.mkdirSync('build', { recursive: true });\n\
             fs.linkSync('tracked.txt', 'build/source-link.txt');",
        );
        let result = fixture.run(15).expect("hard-link fixture result");
        assert_violation(&result, "file-link", "tracked.txt");
        assert!(
            String::from_utf8_lossy(&result.stdout).contains("build/source-link.txt"),
            "{}",
            details(&result)
        );
        assert!(!fixture.project.join("build/source-link.txt").exists());
        assert_eq!(
            fs::read_to_string(fixture.project.join("tracked.txt")).unwrap(),
            "original tracked source"
        );
    }

    #[test]
    fn preexisting_ignored_symlinks_and_hard_links_cannot_create_write_permissions() {
        for symbolic in [true, false] {
            let fixture = Fixture::new("fs.writeFileSync('build/should-not-run', 'changed');");
            // Git's directory-only `build/` pattern excludes a symlink from
            // ignored inputs. This fixture must ignore the alias itself.
            fs::write(fixture.project.join(".gitignore"), "build\n").unwrap();
            let build = fixture.project.join("build");
            let expected = if symbolic {
                let victim = fixture.root.join("outside-directory");
                fs::create_dir(&victim).unwrap();
                std::os::unix::fs::symlink(victim, &build).unwrap();
                "symlink"
            } else {
                fs::create_dir(&build).unwrap();
                fs::hard_link(
                    fixture.project.join("tracked.txt"),
                    build.join("source.txt"),
                )
                .unwrap();
                "hard link"
            };
            let error = fixture
                .run(15)
                .expect_err("aliased ignored output must be rejected before execution");
            assert!(error.contains(expected), "{expected}: {error}");
            assert!(!build.join("should-not-run").exists());
            assert_eq!(
                fs::read_to_string(fixture.project.join("tracked.txt")).unwrap(),
                "original tracked source"
            );
        }
    }

    #[test]
    #[ignore = "requires an explicitly prepared pi-os copy and output path beneath /private/tmp"]
    fn pi_os_confined_acceptance() {
        let temporary = Path::new("/private/tmp").canonicalize().unwrap();
        let project = PathBuf::from(
            std::env::var_os("DCG_CONFINED_BENCH_PROJECT")
                .expect("set DCG_CONFINED_BENCH_PROJECT to a prepared temporary pi-os copy"),
        )
        .canonicalize()
        .expect("canonical temporary benchmark copy");
        assert!(project.starts_with(&temporary) && project != temporary);
        let git = project.join(".git");
        let git_meta = fs::symlink_metadata(&git).expect("fresh temporary repository metadata");
        assert!(git_meta.is_dir() && !git_meta.file_type().is_symlink());
        assert!(git.canonicalize().unwrap().starts_with(&project));
        let cwd = project.join("node-harness").canonicalize().unwrap();
        assert!(cwd.starts_with(&project) && cwd != project);
        let output_path = PathBuf::from(
            std::env::var_os("DCG_CONFINED_BENCH_OUTPUT")
                .expect("set DCG_CONFINED_BENCH_OUTPUT to a new temporary result file"),
        );
        assert!(output_path.is_absolute());
        assert!(
            matches!(fs::symlink_metadata(&output_path), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
            "benchmark result must be a new file, never an existing symlink"
        );
        let output_parent = output_path.parent().unwrap().canonicalize().unwrap();
        assert!(output_parent.starts_with(&temporary) && output_parent != temporary);
        let temp_root = std::env::temp_dir().canonicalize().unwrap();
        assert!(temp_root.starts_with(&temporary) && temp_root != temporary);
        let result = confined::run(
            &Request::new("npm test", &cwd, Path::new("/bin/sh"), 595)
                .with_loopback(ConfinedLoopback::All),
            &temp_root,
            ConfinedLoopback::All,
        )
        .expect("run the prepared temporary pi-os copy under continuing confinement");
        let stdout = String::from_utf8_lossy(&result.stdout);
        let stderr = String::from_utf8_lossy(&result.stderr);
        let report = format!(
            "elapsed_ms={} exit_code={} timed_out={} violations={:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            result.elapsed_ms, result.exit_code, result.timed_out, result.violations
        );
        fs::write(&output_path, &report).expect("persist temporary acceptance output");
        eprintln!(
            "pi-os confined: elapsed_ms={} exit_code={} violations={:?}",
            result.elapsed_ms, result.exit_code, result.violations
        );
        print!("{stdout}");
        eprint!("{stderr}");
        // A real test failure is evidence to report, not a reason to fake an
        // exit-zero acceptance. This check establishes that npm/Node did run.
        assert!(
            stdout.lines().any(|line| line.starts_with("> "))
                || stdout.contains("TAP version")
                || stdout.contains("# tests")
                || stdout.contains("ℹ tests"),
            "the fixture did not reach npm/Node: {report}"
        );
        assert!(
            !result.timed_out,
            "pi-os exceeded the 595-second deadline: {report}"
        );
        assert_eq!(
            result.exit_code, 0,
            "the real pi-os suite did not pass: {report}"
        );
    }
}
