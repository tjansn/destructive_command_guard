//! Execute a finite request once in its real workspace under Seatbelt.
//! No approval is stored and no unconfined fallback exists in this runner.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const PROFILE: &str = "finite-v1";
const COMMAND_CAP: usize = 64 * 1024;

/// Leave the host time to receive diagnostics after the child group is stopped.
/// Claude uses milliseconds (120 seconds by default); Pi uses optional seconds.
pub fn tool_timeout(configured: u64, value: Option<&serde_json::Value>, pi: bool) -> Option<u64> {
    let host_seconds = match value {
        Some(value) => {
            let timeout = value.as_u64()?;
            if pi { timeout } else { timeout / 1000 }
        }
        None if pi => return Some(configured.clamp(1, 600)),
        None => 120,
    };
    Some(configured.clamp(1, 600).min(host_seconds.checked_sub(5)?)).filter(|v| *v > 0)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub profile: String,
    pub command: String,
    pub cwd: PathBuf,
    pub shell: PathBuf,
    pub timeout_secs: u64,
    pub loopback: crate::config::ConfinedLoopback,
}

impl Request {
    pub fn new(command: &str, cwd: &Path, shell: &Path, timeout_secs: u64) -> Self {
        Self {
            profile: PROFILE.to_owned(),
            command: command.to_owned(),
            cwd: cwd.to_path_buf(),
            shell: shell.to_path_buf(),
            timeout_secs: timeout_secs.clamp(1, 600),
            loopback: crate::config::ConfinedLoopback::None,
        }
    }

    pub const fn with_loopback(mut self, loopback: crate::config::ConfinedLoopback) -> Self {
        self.loopback = loopback;
        self
    }

    /// Base64url carries the original command as data, without shell metacharacters.
    pub fn invocation(&self, executable: &Path) -> Result<String, String> {
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        if bytes.len() > COMMAND_CAP * 2 {
            return Err("confined request exceeds its bound".to_owned());
        }
        Ok(format!(
            "{} run --confined --request {}",
            shell_words::quote(executable.to_str().ok_or("non-UTF-8 dcg executable")?),
            URL_SAFE_NO_PAD.encode(bytes)
        ))
    }

    pub fn decode(encoded: &str) -> Result<Self, String> {
        if encoded.len() > COMMAND_CAP * 4 {
            return Err("confined request exceeds its bound".to_owned());
        }
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())
    }

    fn validate(&self) -> Result<(), String> {
        if self.profile != PROFILE
            || self.command.len() > COMMAND_CAP
            || !(1..=600).contains(&self.timeout_secs)
            || !self.cwd.is_absolute()
            || !self.cwd.is_dir()
            || !matches!(
                self.shell.to_str(),
                Some("/bin/sh" | "/bin/bash" | "/bin/zsh")
            )
            || !eligible(&self.command, &self.cwd)
        {
            return Err("request is not a supported finite, local invocation".to_owned());
        }
        Ok(())
    }
}

/// Eligibility is a finite runner contract, not a claim that its tests are safe.
///
/// Unresolved runner sources remain confined for their entire execution.
/// Known definite denials are checked by the hook before rewriting.
pub fn eligible(command: &str, cwd: &Path) -> bool {
    execution(command, cwd).is_some()
}

fn execution(command: &str, cwd: &Path) -> Option<(PathBuf, String)> {
    if finite(command, cwd, 0) {
        return Some((cwd.to_path_buf(), command.to_owned()));
    }
    let (target, inner) =
        crate::invocation::leading_cd(command, cwd, std::env::var_os("CDPATH").as_deref())?;
    finite(&inner, &target, 0).then_some((target, inner))
}

fn finite(command: &str, cwd: &Path, depth: usize) -> bool {
    use crate::heredoc::ScriptLanguage;
    if depth >= 8 || command.len() > COMMAND_CAP {
        return false;
    }
    let ast = ast_grep_core::AstGrep::new(command, ast_grep_language::SupportLang::Bash);
    if ast.root().get_inner_node().has_error() {
        return false;
    }
    let mut pending = vec![ast.root()];
    let mut commands = 0;
    while let Some(node) = pending.pop() {
        match node.kind().as_ref() {
            "program" | "command_name" | "word" | "string" | "raw_string" | "string_content"
            | "\"" | "'" => {}
            "command" => commands += 1,
            _ => return false,
        }
        pending.extend(node.children());
    }
    if commands != 1 {
        return false;
    }
    let Ok(words) = shell_words::split(command) else {
        return false;
    };
    let Some(program) = words.first() else {
        return false;
    };
    let name = program.rsplit('/').next().unwrap_or(program);
    if words.iter().any(|w| {
        w == "&"
            || w.contains("--watch")
            || matches!(
                w.as_str(),
                "watch" | "serve" | "start" | "dev" | "--detach" | "-w"
            )
    }) {
        return false;
    }
    if matches!(name, "npm" | "pnpm" | "yarn") {
        let task = match words.as_slice() {
            [_, task] if matches!(task.as_str(), "test" | "t" | "tst") => "test",
            [_, run, task]
                if run == "run" && matches!(task.as_str(), "test" | "check" | "lint" | "build") =>
            {
                task.as_str()
            }
            _ => return false,
        };
        let path = cwd.join("package.json");
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            return false;
        };
        if !meta.is_file() || meta.len() > 256 * 1024 {
            return false;
        }
        let Ok(bytes) = std::fs::read(path) else {
            return false;
        };
        let Ok(package) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            return false;
        };
        let Some(scripts) = package
            .get("scripts")
            .and_then(serde_json::Value::as_object)
        else {
            return false;
        };
        if !scripts.contains_key(task) {
            return false;
        }
        return [format!("pre{task}"), task.to_owned(), format!("post{task}")]
            .iter()
            .all(|name| {
                scripts
                    .get(name)
                    .is_none_or(|script| script.as_str().is_some_and(|s| finite(s, cwd, depth + 1)))
            });
    }
    // These finite build/lint entrypoints and their dependencies remain kernel
    // confined. Unsupported commands do not inherit this classification.
    if matches!(name, "tsc" | "eslint")
        || (name == "biome"
            && words
                .get(1)
                .is_some_and(|w| matches!(w.as_str(), "check" | "lint" | "format")))
    {
        return words.len() > 1
            && !words
                .iter()
                .any(|w| w.starts_with("--require") || w.starts_with("--import"));
    }
    let language = ScriptLanguage::from_command(name);
    let args: Vec<_> = words.iter().skip(1).map(String::as_str).collect();
    crate::invocation::classify(program, &args, language).is_ok_and(|invocation| {
        invocation.finite_check
            && !invocation.sources.is_empty()
            && invocation.sources.iter().all(|source| {
                let path = Path::new(&source.path);
                !path.is_absolute()
                    && !path
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))
                    && (!source.glob || !source.path.contains("**"))
            })
    })
}

/// Keep real non-secret inputs; remove credentials, preload and startup state.
pub fn environment(
    parent: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    home: &Path,
    temp: &Path,
) -> std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString> {
    let mut result = std::collections::BTreeMap::new();
    for (key, value) in parent {
        let name = key.to_string_lossy().to_ascii_uppercase();
        if [
            "TOKEN",
            "KEY",
            "SECRET",
            "PASSWORD",
            "CREDENTIAL",
            "COOKIE",
            "AUTH",
        ]
        .iter()
        .any(|part| name.contains(part))
            || [
                "AWS_",
                "AZURE_",
                "GOOGLE_",
                "GCP_",
                "DCG_",
                "DYLD_",
                "LD_",
                "BASH_FUNC_",
                "NPM_CONFIG_",
                "GIT_CONFIG_",
            ]
            .iter()
            .any(|prefix| name.starts_with(prefix))
            || matches!(
                name.as_str(),
                "NODE_OPTIONS"
                    | "NODE_PATH"
                    | "NODE_REPL_EXTERNAL_MODULE"
                    | "BASH_ENV"
                    | "ENV"
                    | "ZDOTDIR"
                    | "PYTHONPATH"
                    | "PYTHONHOME"
                    | "RUBYOPT"
                    | "RUBYLIB"
                    | "PERL5OPT"
                    | "PERL5LIB"
                    | "PHP_INI_SCAN_DIR"
                    | "PHPRC"
                    | "SSH_AGENT_PID"
                    | "SSH_AUTH_SOCK"
                    | "DOCKER_HOST"
                    | "KUBECONFIG"
                    | "OPENSSL_CONF"
                    | "OPENSSL_MODULES"
            )
        {
            continue;
        }
        result.insert(key, value);
    }
    for name in ["HOME", "USERPROFILE", "CFFIXED_USER_HOME"] {
        result.insert(name.into(), home.as_os_str().to_owned());
    }
    for name in ["TMPDIR", "TMP", "TEMP"] {
        result.insert(name.into(), temp.as_os_str().to_owned());
    }
    for (name, suffix) in [
        ("XDG_CONFIG_HOME", ".config"),
        ("XDG_CACHE_HOME", ".cache"),
        ("XDG_DATA_HOME", ".local/share"),
        ("XDG_STATE_HOME", ".local/state"),
    ] {
        result.insert(name.into(), home.join(suffix).into_os_string());
    }
    result.insert("npm_config_offline".into(), "true".into());
    result.insert("npm_config_update_notifier".into(), "false".into());
    result
}

#[derive(Debug)]
pub struct RunResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
    pub elapsed_ms: u128,
    pub violations: Vec<crate::trial::Violation>,
    pub timed_out: bool,
}

#[cfg(not(target_os = "macos"))]
pub fn run(
    request: &Request,
    _temporary_root: &Path,
    _trusted_loopback: crate::config::ConfinedLoopback,
) -> Result<RunResult, String> {
    request.validate()?;
    Err("continuing confinement requires macOS Seatbelt".to_owned())
}

#[cfg(target_os = "macos")]
pub fn run(
    request: &Request,
    temporary_root: &Path,
    trusted_loopback: crate::config::ConfinedLoopback,
) -> Result<RunResult, String> {
    request.validate()?;
    if request.loopback != trusted_loopback {
        return Err("trusted localhost policy changed or differs from the confined receipt; command was not started".to_owned());
    }
    native::execute(request, temporary_root).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_invocations_preserve_data_without_interpolation() {
        let request = Request::new(
            "node --check '$(inert);file.js'",
            Path::new("/tmp/project with spaces"),
            Path::new("/bin/sh"),
            5,
        );
        let invocation = request.invocation(Path::new("/tmp/dcg binary")).unwrap();
        let words = shell_words::split(&invocation).unwrap();
        assert_eq!(
            &words[..4],
            ["/tmp/dcg binary", "run", "--confined", "--request"]
        );
        assert!(!words[4].contains(['$', ';', '\'', '"', '`']));
        let decoded = Request::decode(&words[4]).unwrap();
        assert_eq!(decoded.command, request.command);
        assert_eq!(decoded.cwd, request.cwd);
        assert!(Request::decode(&"x".repeat(COMMAND_CAP * 4 + 1)).is_err());
        assert!(Request::decode("not%base64").is_err());
    }

    #[test]
    fn one_leading_cd_resolves_the_finite_command_and_rejects_further_chains() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("literal dir");
        std::fs::create_dir(&target).unwrap();
        let prefix = format!("cd {} && ", shell_words::quote(target.to_str().unwrap()));
        let command = format!("{prefix}node --test case.test.js");
        assert_eq!(
            execution(&command, temp.path()),
            Some((
                target.canonicalize().unwrap(),
                "node --test case.test.js".into()
            ))
        );
        for suffix in [
            "node --test && echo done",
            "cd .. && node --test",
            "node --test; echo done",
            "node --test | cat",
            "node --test &",
            "node --watch --test",
        ] {
            assert!(
                !eligible(&format!("{prefix}{suffix}"), temp.path()),
                "{suffix}"
            );
        }
    }

    #[test]
    fn comments_cannot_create_a_confined_command_that_the_shell_does_not_run() {
        let temp = tempfile::tempdir().unwrap();
        let sub = temp.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(
            sub.join("package.json"),
            r#"{"scripts":{"test":"node --test"}}"#,
        )
        .unwrap();
        assert!(eligible("cd sub && npm test", temp.path()));
        for command in [
            "cd sub # && npm test",
            "cd sub # comment\n&& npm test",
            "cd sub && npm test # comment",
        ] {
            assert!(!eligible(command, temp.path()), "{command}");
            assert!(execution(command, temp.path()).is_none(), "{command}");
            let request = Request::new(command, temp.path(), Path::new("/bin/sh"), 5);
            assert!(request.validate().is_err(), "{command}");
        }
    }

    #[test]
    fn finite_contract_rejects_services_chains_and_dynamic_operands() {
        let dir = tempfile::tempdir().unwrap();
        for source in [
            "node --test test.cjs",
            "node --test --test-concurrency=1 'test/*.ts'",
            "node --check app.js",
            "/bin/bash -n script.sh",
            "tsc -p tsconfig.json",
        ] {
            assert!(eligible(source, dir.path()), "{source}");
        }
        for source in [
            "node --test",
            "node --watch --test test.js",
            "node --test test.js &",
            "node --test test.js; echo next",
            "node --test $FILES",
            "node --test ../external.js",
            "npm start",
            "tsc -w -p .",
            "biome lsp-proxy",
        ] {
            assert!(!eligible(source, dir.path()), "{source}");
        }
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts":{"test":"node --test test.cjs","posttest":"node --check out.js"}}"#,
        )
        .unwrap();
        assert!(eligible("npm test", dir.path()));
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts":{"test":"node --test test.cjs","posttest":"npm start"}}"#,
        )
        .unwrap();
        assert!(!eligible("npm test", dir.path()));
    }

    #[test]
    fn runtime_keeps_real_inputs_but_strips_credentials_and_startup() {
        let values = [
            "DATA_DIR",
            "LANG",
            "PATH",
            "NODE_OPTIONS",
            "AWS_PROFILE",
            "API_TOKEN",
            "PASSWORD",
            "SSH_AUTH_SOCK",
            "LD_PRELOAD",
            "BASH_ENV",
        ];
        let env = environment(
            values.map(|k| (k.into(), "fixture".into())),
            Path::new("/temp/home"),
            Path::new("/temp/tmp"),
        );
        for name in ["DATA_DIR", "LANG", "PATH"] {
            assert_eq!(env.get(std::ffi::OsStr::new(name)).unwrap(), "fixture");
        }
        for name in &values[3..] {
            assert!(!env.contains_key(std::ffi::OsStr::new(name)));
        }
        assert_eq!(env.get(std::ffi::OsStr::new("HOME")).unwrap(), "/temp/home");
    }

    #[test]
    fn execution_budget_respects_host_timeout_units_and_drain_margin() {
        assert_eq!(tool_timeout(600, None, false), Some(115));
        assert_eq!(tool_timeout(600, None, true), Some(600));
        assert_eq!(
            tool_timeout(600, Some(&serde_json::json!(45)), true),
            Some(40)
        );
        assert_eq!(
            tool_timeout(600, Some(&serde_json::json!(45000)), false),
            Some(40)
        );
        assert_eq!(
            tool_timeout(600, Some(&serde_json::json!(5000)), false),
            None
        );
        assert_eq!(
            tool_timeout(600, Some(&serde_json::json!("bad")), true),
            None
        );
    }

    #[test]
    fn rewrite_requires_host_capability_and_preserves_every_input_field() {
        use crate::hook::{self, HookProtocol};
        let raw = serde_json::json!({"tool_name":"Bash", "tool_input":{"command":"node --test test.js", "timeout":12345,"description":"fixture", "custom":null}});
        let input = hook::parse_hook_input(&raw.to_string()).unwrap();
        assert!(hook::supports_confined_rewrite(
            &input,
            HookProtocol::ClaudeCompatible,
            "claude-code"
        ));
        for agent in ["pi", "unknown", "opencode", "codex-cli"] {
            assert!(!hook::supports_confined_rewrite(
                &input,
                HookProtocol::ClaudeCompatible,
                agent
            ));
        }
        assert!(!hook::supports_confined_rewrite(
            &input,
            HookProtocol::Codex,
            "claude-code"
        ));
        let output = hook::confined_rewrite(
            &input,
            "encoded-fixture",
            crate::config::ConfinedLoopback::None,
        )
        .unwrap();
        let mut expected = raw["tool_input"].clone();
        expected["command"] = serde_json::json!("encoded-fixture");
        assert_eq!(output["hookSpecificOutput"]["updatedInput"], expected);
        assert_eq!(output["dcg_verdict"], "confined");
        assert_eq!(output["hookSpecificOutput"]["approvalScope"], "confined");
        assert_eq!(output["hookSpecificOutput"]["confinedLoopback"], "none");
        let open = hook::confined_rewrite(
            &input,
            "encoded-fixture",
            crate::config::ConfinedLoopback::All,
        )
        .unwrap();
        assert_eq!(open["hookSpecificOutput"]["confinedLoopback"], "all");
        assert!(
            open["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap()
                .contains("open to all host services")
        );
        let mut raw = raw;
        raw["dcg_input_rewrite"] = serde_json::json!(true);
        let input = hook::parse_hook_input(&raw.to_string()).unwrap();
        assert!(hook::supports_confined_rewrite(
            &input,
            HookProtocol::ClaudeCompatible,
            "pi"
        ));
    }
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use crate::trial::{LogObserver, capture};
    use std::{
        fs, io,
        process::Command,
        time::{Duration, Instant},
    };
    const OUTPUT_CAP: usize = 8 * 1024 * 1024;
    const PATH_CAP: usize = 100_000;

    fn git(cwd: &Path, args: &[&str]) -> io::Result<Vec<u8>> {
        let output = capture(
            Command::new("/usr/bin/git")
                .args([
                    "-c",
                    "core.fsmonitor=false",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-C",
                ])
                .arg(cwd)
                .args(args)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_OPTIONAL_LOCKS", "0"),
            Duration::from_secs(5),
            16 * 1024 * 1024,
        )?;
        if !output.status.success() || !output.complete || output.timed_out {
            return Err(io::Error::other("bounded Git workspace discovery failed"));
        }
        Ok(output.stdout)
    }

    fn paths(bytes: &[u8], root: &Path) -> io::Result<Vec<PathBuf>> {
        let mut paths = Vec::new();
        for path in bytes.split(|b| *b == 0).filter(|p| !p.is_empty()) {
            let path = Path::new(std::str::from_utf8(path).map_err(io::Error::other)?);
            if path.is_absolute()
                || path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
                || paths.len() >= PATH_CAP
            {
                return Err(io::Error::other("invalid or oversized Git path set"));
            }
            paths.push(root.join(path));
        }
        Ok(paths)
    }

    fn no_hardlinks(path: &Path, remaining: &mut usize) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        *remaining = remaining
            .checked_sub(1)
            .ok_or_else(|| io::Error::other("output tree inspection limit"))?;
        let meta = fs::symlink_metadata(path)?;
        if meta.is_file() && meta.nlink() > 1 {
            return Err(io::Error::other("writable output contains a hard link"));
        }
        if meta.is_dir() {
            for entry in fs::read_dir(path)? {
                no_hardlinks(&entry?.path(), remaining)?;
            }
        }
        Ok(())
    }

    fn boundaries(cwd: &Path) -> io::Result<(PathBuf, Vec<PathBuf>, Vec<PathBuf>)> {
        let root = git(cwd, &["rev-parse", "--show-toplevel"])?;
        let root = PathBuf::from(
            std::str::from_utf8(&root)
                .map_err(io::Error::other)?
                .trim_end(),
        )
        .canonicalize()?;
        let sources = paths(
            &git(&root, &["ls-files", "-co", "--exclude-standard", "-z"])?,
            &root,
        )?;
        let mut writable = paths(
            &git(
                &root,
                &[
                    "ls-files",
                    "--others",
                    "--ignored",
                    "--exclude-standard",
                    "--directory",
                    "-z",
                ],
            )?,
            &root,
        )?;
        // Empty/absent output directories do not appear in ls-files. A
        // directory ignored as a whole cannot re-include descendants in Git.
        for name in ["build", "dist", "target", ".build", ".cache", "coverage"] {
            let candidate = cwd.join(name);
            if let Ok(output) = git(cwd, &["check-ignore", "--no-index", &format!("{name}/")])
                && !output.is_empty()
            {
                writable.push(candidate);
            }
        }
        writable.sort();
        writable.dedup();
        let mut remaining = PATH_CAP;
        for path in &writable {
            if let Ok(meta) = fs::symlink_metadata(path) {
                if meta.file_type().is_symlink() {
                    return Err(io::Error::other("writable root is a symlink"));
                }
                no_hardlinks(path, &mut remaining)?;
            }
        }
        let mut protected = Vec::new();
        for name in [
            ".git",
            ".dcg",
            ".dcg.toml",
            ".claude",
            ".codex",
            ".pi",
            ".gitignore",
            ".gitmodules",
        ] {
            protected.push(root.join(name));
        }
        if let Ok(exe) = std::env::current_exe()
            && let Some(parent) = exe.parent()
        {
            protected.push(parent.to_path_buf());
        }
        if let Some(home) = crate::config::home_dir() {
            for name in [
                ".config/dcg",
                "Library/Application Support/dcg",
                ".claude",
                ".codex",
                ".config/opencode/plugins",
                ".opencode/plugins",
                ".grok/hooks",
                ".copilot/hooks",
                ".pi/agent/extensions",
                ".gemini",
                ".config/agy",
                ".config/crush",
                ".agy",
                ".reasonix",
            ] {
                protected.push(home.join(name));
            }
        }
        // Do not grant a writable ancestor of any protected child: renaming
        // such a directory would relocate source without opening the child.
        writable.retain(|path| {
            !protected
                .iter()
                .chain(&sources)
                .any(|p| p.starts_with(path))
        });
        Ok((root, writable, protected))
    }

    pub(super) fn execute(request: &Request, temporary_root: &Path) -> io::Result<RunResult> {
        let started = Instant::now();
        let (cwd, execution_command) = execution(&request.command, &request.cwd)
            .ok_or_else(|| io::Error::other("finite invocation changed before execution"))?;
        let cwd = cwd.canonicalize()?;
        let (project, writable, protected) = boundaries(&cwd)?;
        let directory = tempfile::Builder::new()
            .prefix("dcg-confined-")
            .tempdir_in(temporary_root)?;
        let root = directory.path().canonicalize()?;
        let home = root.join("home");
        let temp = root.join("tmp");
        fs::create_dir(&home)?;
        fs::create_dir(&temp)?;
        let tag = format!("dcg-confined-{:032x}", rand::random::<u128>());
        let profile = crate::trial_profile::confined_profile(
            &project,
            &home,
            &temp,
            &tag,
            &writable,
            &protected,
            request.loopback,
        );
        if profile.len() > 64 * 1024 {
            return Err(io::Error::other(
                "confinement profile exceeds 64 KiB; command was not started",
            ));
        }
        let write_canary = root.join("write-canary");
        let read_canary = root.join("read-canary");
        let end_canary = root.join("end-canary");
        fs::write(&read_canary, "disposable read boundary fixture")?;
        let mut observer = LogObserver::start(&tag)?;
        for (program, path, read) in [
            ("/usr/bin/touch", &write_canary, false),
            ("/bin/cat", &read_canary, true),
        ] {
            let probe = capture(
                Command::new("/usr/bin/sandbox-exec")
                    .args(["-p", &profile, program])
                    .arg(path),
                Duration::from_secs(5),
                OUTPUT_CAP,
            )?;
            let reports = observer.wait_for(&tag, path)?;
            if probe.status.success()
                || (read && !probe.stdout.is_empty())
                || (!read && path.exists())
                || !reports
                    .iter()
                    .any(|v| v.target.contains(&path.display().to_string()))
            {
                return Err(io::Error::other(format!(
                    "confinement enforcement/reporting probe failed; command was not started (status={}, reports={}): {}",
                    probe.status,
                    reports.len(),
                    String::from_utf8_lossy(&probe.stderr)
                        .chars()
                        .take(1024)
                        .collect::<String>()
                )));
            }
        }
        let remaining = Duration::from_secs(request.timeout_secs)
            .checked_sub(started.elapsed())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                io::Error::other("setup exhausted confinement budget; command was not started")
            })?;
        let mut child = Command::new("/usr/bin/sandbox-exec");
        child.args(["-p", &profile, "/bin/sh", "-c"])
            .arg("ulimit -t \"$1\"; ulimit -f 131072; ulimit -n 256; if [ \"$2\" = /bin/zsh ]; then \"$2\" -f -c \"$3\"; else \"$2\" -c \"$3\"; fi; result=$?; /usr/bin/touch \"$4\" 2>/dev/null; exit \"$result\"")
            .arg("dcg-confined").arg(remaining.as_secs().max(1).to_string()).arg(&request.shell).arg(&execution_command).arg(&end_canary)
            .current_dir(&cwd).env_clear().envs(environment(std::env::vars_os(), &home, &temp));
        let output = capture(&mut child, remaining, OUTPUT_CAP)?;
        let mut issues = Vec::new();
        if output.timed_out {
            issues.push("time limit reached; process group terminated");
        }
        if output.descendants {
            issues.push(
                "remaining descendants terminated; detached/service execution is unsupported",
            );
        }
        if !output.complete {
            issues.push("output exceeded 8 MiB per stream or remained open; retained prefix only");
        }
        if crate::trial::permission_error_reported(&output.stdout, &output.stderr) {
            // Program text is untrusted and never becomes a kernel observation
            // or an approval. Keep it available even if logd omits the event.
            issues.push("the command reported a permission error; its operation and target remain in the command output, independently of possibly incomplete kernel reports");
        }
        let mut violations = observer.wait_for(&tag, &end_canary).unwrap_or_else(|_| {
            issues.push("sandbox reporting became unavailable; real command output follows");
            Vec::new()
        });
        // Child reports can lag the parent's end marker on another kernel
        // reporting thread. Keep the subscriber alive for a bounded drain.
        std::thread::sleep(Duration::from_secs(1));
        for item in observer.observations(&tag).unwrap_or_else(|_| {
            issues.push("sandbox report drain incomplete; real command output follows");
            Vec::new()
        }) {
            if !violations.contains(&item) {
                violations.push(item);
            }
        }
        if !violations
            .iter()
            .any(|v| v.target.contains(&end_canary.display().to_string()))
        {
            issues.push("end-of-run observation marker unavailable");
        }
        violations.retain(|v| {
            ![&write_canary, &read_canary, &end_canary]
                .iter()
                .any(|p| v.target.contains(&p.display().to_string()))
        });
        let mut stderr = output.stderr;
        {
            use std::io::Write as _;
            writeln!(
                stderr,
                "\n[dcg:confined-policy] {}",
                request.loopback.receipt()
            )?;
        }
        for violation in &violations {
            use std::io::Write as _;
            writeln!(
                stderr,
                "\n[dcg:confined-denial] {} {}",
                violation.operation, violation.target
            )?;
        }
        for issue in issues {
            use std::io::Write as _;
            writeln!(stderr, "\n[dcg:confined-limit] {issue}")?;
        }
        use std::os::unix::process::ExitStatusExt;
        let exit_code = if output.timed_out {
            124
        } else {
            output
                .status
                .code()
                .unwrap_or_else(|| 128 + output.status.signal().unwrap_or(1))
        };
        Ok(RunResult {
            stdout: output.stdout,
            stderr,
            exit_code,
            elapsed_ms: started.elapsed().as_millis(),
            violations,
            timed_out: output.timed_out,
        })
    }
}
