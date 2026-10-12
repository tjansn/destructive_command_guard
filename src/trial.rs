//! Synchronous, observed trials for opaque file-backed commands. Absence of
//! observable sandbox evidence is inconclusive, never a safety certificate.

use crate::config::{Config, TrialConfig};
use crate::evaluator::PatternMatch;
use crate::trial_store::{Fingerprint, TrialStore};
use serde::{Deserialize, Serialize};
#[cfg(target_os = "macos")]
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
#[cfg(target_os = "macos")]
use std::collections::BTreeSet;
use std::ffi::OsString;
#[cfg(target_os = "macos")]
use std::fmt::Write as _;
use std::fs;
use std::io;
#[cfg(target_os = "macos")]
use std::io::Read;
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

/// Deliberately exhaustive: inline/remote/SQL unknowns are not trial grants.
pub const TRIAL_RULES: &[(&str, &str)] = &[("heredoc.script_files", "unverified")];
#[cfg(target_os = "macos")]
const OUTPUT_CAP: usize = 64 * 1024;
#[cfg(target_os = "macos")]
const LOG_CAP: usize = 2 * 1024 * 1024;
const ITEM_CAP: usize = 5;

pub fn eligible(info: &PatternMatch) -> bool {
    TRIAL_RULES.iter().any(|(pack, rule)| {
        info.pack_id.as_deref() == Some(pack) && info.pattern_name.as_deref() == Some(rule)
    })
}

/// Map a literal leading absolute `cd DIR &&` into the clone's cwd.
///
/// The original command remains the fingerprint key. Other absolute paths
/// are not rewritten, since text replacement would change script data.
pub fn execution_location(command: &str, cwd: &Path) -> (PathBuf, String) {
    let source = command.trim_start();
    let ast = ast_grep_core::AstGrep::new(source, ast_grep_language::SupportLang::Bash);
    let mut pending = vec![ast.root()];
    while let Some(node) = pending.pop() {
        if node.kind().as_ref() == "command" && node.range().start == 0 {
            let text = node.text();
            if !text.contains(['$', '`', '~'])
                && let Ok(words) = shell_words::split(&text)
                && let [program, path] = words.as_slice()
                && program == "cd"
                && Path::new(path).is_absolute()
                && let Some(rest) = source[node.range().end..].trim_start().strip_prefix("&&")
                && let Ok(target) = fs::canonicalize(path)
                && target.is_dir()
            {
                return (target, rest.trim_start().to_owned());
            }
            break;
        }
        pending.extend(node.children());
    }
    (cwd.to_path_buf(), command.to_owned())
}

/// A detached job has no finite readiness/lifecycle proof. Its shell exiting
/// does not establish that the service completed a representative workload.
#[cfg(any(target_os = "macos", test))]
fn background_job(command: &str) -> bool {
    let ast = ast_grep_core::AstGrep::new(command, ast_grep_language::SupportLang::Bash);
    let mut pending = vec![ast.root()];
    while let Some(node) = pending.pop() {
        if node.kind().as_ref() == "&" {
            return true;
        }
        pending.extend(node.children());
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Safe,
    Unsafe,
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Violation {
    pub operation: String,
    pub target: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Observations {
    pub violations: Vec<Violation>,
    pub deleted: Vec<String>,
    pub modified: Vec<String>,
    pub issues: Vec<String>,
    pub timed_out: bool,
    pub observation_complete: bool,
}

impl Observations {
    pub fn verdict(&self) -> Verdict {
        if !self.deleted.is_empty()
            || self.violations.iter().any(|v| {
                v.operation.starts_with("file-write")
                    || matches!(
                        v.operation.as_str(),
                        "signal" | "appleevent-send" | "user-preference-write"
                    )
            })
        {
            Verdict::Unsafe
        } else if !self.observation_complete
            || self.timed_out
            || !self.violations.is_empty()
            || !self.modified.is_empty()
            || !self.issues.is_empty()
        {
            Verdict::Inconclusive
        } else {
            Verdict::Safe
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrialReport {
    pub id: String,
    pub command: String,
    pub project_root: PathBuf,
    pub observations: Observations,
    pub clone_ms: u128,
    pub run_ms: u128,
    pub exit_code: Option<i32>,
    pub clone_method: String,
    pub artifact_dir: Option<PathBuf>,
}

fn display_text(text: &str, home: Option<&Path>) -> String {
    let text = home.map_or_else(
        || text.to_string(),
        |home| text.replace(&home.to_string_lossy().to_string(), "~"),
    );
    text.chars().filter(|c| !c.is_control()).take(240).collect()
}

impl TrialReport {
    pub fn summary(&self, home: Option<&Path>) -> String {
        let mut lines = vec![format!(
            "dcg trial {}: {:?}. Sandboxed copy of {}. Command: {}",
            self.id,
            self.observations.verdict(),
            display_text(&self.project_root.display().to_string(), home),
            display_text(&crate::redaction::redact_secrets(&self.command), home),
        )];
        let mut categories: Vec<(&str, Vec<String>)> = [
            "blocked write",
            "blocked action",
            "blocked network",
            "blocked other",
        ]
        .into_iter()
        .map(|name| (name, Vec::new()))
        .collect();
        for violation in &self.observations.violations {
            let category = if violation.operation.starts_with("file-write") {
                0
            } else if matches!(
                violation.operation.as_str(),
                "signal" | "appleevent-send" | "user-preference-write"
            ) {
                1
            } else if violation.operation.starts_with("network") {
                2
            } else {
                3
            };
            categories[category]
                .1
                .push(format!("{} {}", violation.operation, violation.target));
        }
        categories.extend([
            ("deleted source", self.observations.deleted.clone()),
            ("changed source", self.observations.modified.clone()),
            ("review needed", self.observations.issues.clone()),
        ]);
        for (category, items) in categories {
            for item in items.iter().take(ITEM_CAP) {
                lines.push(format!("  • {category}: {}", display_text(item, home)));
            }
            if items.len() > ITEM_CAP {
                lines.push(format!(
                    "  • {} additional {category} items",
                    items.len() - ITEM_CAP
                ));
            }
        }
        if self.observations.timed_out {
            lines.push("Trial timed out; process group terminated.".to_owned());
        }
        if !self.observations.observation_complete {
            lines.push("Sandbox observation incomplete; safety cannot be established.".to_owned());
        }
        lines.push(format!(
            "Clone: {} ms ({}); run: {} ms; exit: {:?}. Review: dcg trial show {}",
            self.clone_ms, self.clone_method, self.run_ms, self.exit_code, self.id
        ));
        if self.observations.verdict() != Verdict::Safe {
            lines.push(
                "Not run on the real project. Adjust the command or ask the user.".to_owned(),
            );
        }
        lines.join("\n")
    }
}

/// No broad environment forwarding. NODE_OPTIONS is intentionally excluded:
/// it can inject un-fingerprinted preloads and read credentials at startup.
pub fn trial_environment(
    parent: impl IntoIterator<Item = (OsString, OsString)>,
    home: &Path,
    temp: &Path,
) -> BTreeMap<OsString, OsString> {
    let mut env = BTreeMap::new();
    for (key, value) in parent {
        let name = key.to_string_lossy();
        let upper = name.to_ascii_uppercase();
        if upper.contains("TOKEN") || upper.contains("KEY") || upper.contains("SECRET") {
            continue;
        }
        if matches!(
            name.as_ref(),
            "PATH" | "LANG" | "TERM" | "USER" | "LOGNAME" | "SHELL"
        ) || (name.starts_with("LC_")
            && name.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'))
        {
            env.insert(key, value);
        }
    }
    env.entry("PATH".into())
        .or_insert_with(|| "/usr/bin:/bin:/usr/sbin:/sbin".into());
    env.insert("HOME".into(), home.as_os_str().to_owned());
    env.insert("TMPDIR".into(), temp.as_os_str().to_owned());
    env.insert("CI".into(), "1".into());
    // Suppress package-manager telemetry, update notices and lazy downloads.
    env.insert("npm_config_offline".into(), "true".into());
    env.insert("npm_config_update_notifier".into(), "false".into());
    env
}

/// Parse only reports carrying our unguessable policy tag. Child reports keep
/// the same tag; unrelated system logs never enter the stored summary.
pub fn parse_violations(log: &str, tag: &str) -> Vec<Violation> {
    let mut result = Vec::new();
    for line in log.lines() {
        let value = serde_json::from_str::<serde_json::Value>(line).ok();
        let message = value
            .as_ref()
            .and_then(|v| v.get("eventMessage"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or(line);
        if !message.contains(tag) {
            continue;
        }
        let Some((_, rest)) = message.split_once("deny(") else {
            continue;
        };
        let Some((_, rest)) = rest.split_once(')') else {
            continue;
        };
        let rest = rest.trim();
        let (operation, target) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
        let target = target
            .split(tag)
            .next()
            .unwrap_or(target)
            .trim()
            .trim_end_matches([' ', '(', '[', ':']);
        let violation = Violation {
            operation: operation.to_owned(),
            target: target.to_owned(),
        };
        if !result.contains(&violation) {
            result.push(violation);
        }
    }
    result
}

#[cfg(any(target_os = "macos", test))]
type Manifest = BTreeMap<PathBuf, String>;

#[cfg(any(target_os = "macos", test))]
fn build_location(path: &Path) -> bool {
    path.components().any(|part| {
        matches!(
            part.as_os_str().to_str(),
            Some("build" | "dist" | "target" | ".build" | "__pycache__" | ".cache")
        )
    })
}

#[cfg(target_os = "macos")]
fn walk_files(root: &Path, path: &Path, paths: &mut BTreeSet<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_name() == ".git" {
            continue;
        }
        let ty = entry.file_type()?;
        if ty.is_dir() {
            walk_files(root, &entry.path(), paths)?;
        } else if ty.is_file() || ty.is_symlink() {
            paths.insert(
                entry
                    .path()
                    .strip_prefix(root)
                    .map_err(io::Error::other)?
                    .to_path_buf(),
            );
        } else {
            return Err(io::Error::other("special file in project"));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn protected_paths(root: &Path) -> io::Result<BTreeSet<PathBuf>> {
    let output = capture(
        Command::new("/usr/bin/git")
            .args([
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
            ])
            .args(["-C"])
            .arg(root)
            .args(["ls-files", "-co", "--exclude-standard", "-z"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_OPTIONAL_LOCKS", "0"),
        Duration::from_secs(5),
        16 * 1024 * 1024,
    )?;
    if output.timed_out || !output.complete {
        return Err(io::Error::other(
            "project manifest probe exceeded its bounds",
        ));
    }
    let mut paths = BTreeSet::new();
    if output.status.success() {
        for item in output.stdout.split(|b| *b == 0).filter(|s| !s.is_empty()) {
            let path = PathBuf::from(std::str::from_utf8(item).map_err(io::Error::other)?);
            if path.is_absolute()
                || path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err(io::Error::other("invalid manifest path"));
            }
            paths.insert(path);
        }
    } else {
        walk_files(root, root, &mut paths)?;
        paths.retain(|path| !build_location(path));
    }
    Ok(paths)
}

#[cfg(target_os = "macos")]
fn manifest(root: &Path, paths: &BTreeSet<PathBuf>) -> io::Result<Manifest> {
    let mut result = BTreeMap::new();
    for path in paths {
        let full = root.join(path);
        let metadata = match fs::symlink_metadata(&full) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let mut hasher = Sha256::new();
        if metadata.is_symlink() {
            hasher.update(fs::read_link(&full)?.as_os_str().as_encoded_bytes());
        } else if metadata.is_file() {
            let canonical = fs::canonicalize(&full)?;
            if !canonical.starts_with(root) {
                return Err(io::Error::other(
                    "source parent replaced with external symlink",
                ));
            }
            let mut file = fs::File::open(full)?;
            let mut buffer = [0; 16 * 1024];
            loop {
                let n = file.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
            }
        } else {
            return Err(io::Error::other("source replaced by non-file"));
        }
        let mut hash = String::with_capacity(64);
        for byte in hasher.finalize() {
            let _ = write!(hash, "{byte:02x}");
        }
        result.insert(path.clone(), hash);
    }
    Ok(result)
}

#[cfg(any(target_os = "macos", test))]
fn classify_diff(before: &Manifest, after: &Manifest, observations: &mut Observations) {
    for (path, hash) in before {
        match after.get(path) {
            None => observations.deleted.push(path.display().to_string()),
            Some(new) if new != hash => observations.modified.push(path.display().to_string()),
            _ => {}
        }
    }
    for path in after.keys() {
        if !before.contains_key(path) && !build_location(path) {
            observations.modified.push(path.display().to_string());
        }
    }
}

#[cfg(target_os = "macos")]
fn copy_tree(source: &Path, dest: &Path, remaining: &mut u64, deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        return Err(io::Error::other("fallback copy timed out"));
    }
    fs::create_dir_all(dest)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let to = dest.join(entry.file_name());
        if ty.is_dir() {
            copy_tree(&entry.path(), &to, remaining, deadline)?;
        } else if ty.is_file() {
            *remaining = remaining
                .checked_sub(entry.metadata()?.len())
                .ok_or_else(|| io::Error::other("fallback copy size cap exceeded"))?;
            fs::copy(entry.path(), to)?;
        } else if ty.is_symlink() {
            #[cfg(unix)]
            std::os::unix::fs::symlink(fs::read_link(entry.path())?, to)?;
            #[cfg(not(unix))]
            return Err(io::Error::other("symlink copy unsupported"));
        } else {
            return Err(io::Error::other("special files cannot be cloned"));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
struct Captured {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    timed_out: bool,
    complete: bool,
    descendants: bool,
}

#[cfg(target_os = "macos")]
fn reader(
    stream: impl Read + Send + 'static,
    cap: usize,
) -> std::sync::mpsc::Receiver<(Vec<u8>, bool)> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut stream = stream;
        let mut kept = Vec::new();
        let mut buffer = [0; 8192];
        let mut complete = true;
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    let take = n.min(cap.saturating_sub(kept.len()));
                    kept.extend_from_slice(&buffer[..take]);
                    complete &= take == n;
                }
                Err(_) => {
                    complete = false;
                    break;
                }
            }
        }
        let _ = tx.send((kept, complete));
    });
    rx
}

#[cfg(target_os = "macos")]
struct ProcessGroup(u32);
#[cfg(target_os = "macos")]
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        let _ = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(self.0.cast_signed()),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
}

#[cfg(target_os = "macos")]
fn capture(command: &mut Command, timeout: Duration, cap: usize) -> io::Result<Captured> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    #[cfg(unix)]
    let group = ProcessGroup(child.id());
    let stdout = reader(
        child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("stdout capture"))?,
        cap,
    );
    let stderr = reader(
        child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("stderr capture"))?,
        cap,
    );
    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= timeout {
            timed_out = true;
            #[cfg(unix)]
            {
                let _ = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(child.id().cast_signed()),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
            let _ = child.kill();
            break child.wait()?;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    #[cfg(unix)]
    let descendants =
        nix::sys::signal::killpg(nix::unistd::Pid::from_raw(child.id().cast_signed()), None)
            .is_ok();
    #[cfg(not(unix))]
    let descendants = false;
    #[cfg(unix)]
    drop(group); // descendants cannot continue mutating the clone after diffing
    let (stdout, out_complete) = stdout
        .recv_timeout(Duration::from_secs(1))
        .unwrap_or_default();
    let (stderr, err_complete) = stderr
        .recv_timeout(Duration::from_secs(1))
        .unwrap_or_default();
    Ok(Captured {
        status,
        stdout,
        stderr,
        timed_out,
        complete: out_complete && err_complete,
        descendants,
    })
}

/// macOS 27 emits these events to live subscribers without retaining them for
/// `log show`. Keep a subscriber alive for the complete process lifetime.
#[cfg(target_os = "macos")]
struct LogObserver {
    child: std::process::Child,
    bytes: std::sync::Arc<std::sync::Mutex<(Vec<u8>, bool)>>,
}

#[cfg(target_os = "macos")]
impl LogObserver {
    fn start(tag: &str) -> io::Result<Self> {
        let predicate = format!(
            "(sender == \"Sandbox\" OR subsystem == \"com.apple.sandbox.reporting\") AND eventMessage CONTAINS \"{tag}\""
        );
        let mut child = Command::new("/usr/bin/log")
            .args([
                "stream",
                "--style",
                "ndjson",
                "--level",
                "debug",
                "--predicate",
                &predicate,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let mut stream = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("log stream unavailable"))?;
        let bytes = std::sync::Arc::new(std::sync::Mutex::new((Vec::new(), true)));
        let target = bytes.clone();
        std::thread::spawn(move || {
            let mut buffer = [0; 8192];
            loop {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        let Ok(mut bytes) = target.lock() else { break };
                        let take = n.min(LOG_CAP.saturating_sub(bytes.0.len()));
                        bytes.0.extend_from_slice(&buffer[..take]);
                        bytes.1 &= take == n;
                    }
                    Err(_) => {
                        if let Ok(mut bytes) = target.lock() {
                            bytes.1 = false;
                        }
                        break;
                    }
                }
            }
        });
        // Subscription startup is additionally verified by the denied canary.
        std::thread::sleep(Duration::from_millis(150));
        Ok(Self { child, bytes })
    }

    fn observations(&mut self, tag: &str) -> io::Result<Vec<Violation>> {
        if self.child.try_wait()?.is_some() {
            return Err(io::Error::other("sandbox log subscriber exited"));
        }
        let bytes = self
            .bytes
            .lock()
            .map_err(|_| io::Error::other("sandbox observation unavailable"))?;
        if !bytes.1 {
            return Err(io::Error::other("sandbox observation log exceeded its cap"));
        }
        Ok(parse_violations(&String::from_utf8_lossy(&bytes.0), tag))
    }

    fn wait_for(&mut self, tag: &str, path: &Path) -> io::Result<Vec<Violation>> {
        let started = Instant::now();
        loop {
            let observed = self.observations(tag)?;
            if observed
                .iter()
                .any(|v| v.target.contains(&path.display().to_string()))
                || started.elapsed() > Duration::from_secs(2)
            {
                return Ok(observed);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for LogObserver {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Run only after the caller has checked all remaining static rules. Temporary
/// directories own the cleanup boundary; no paths supplied by a script are removed.
pub fn run(
    command: &str,
    fingerprint: &Fingerprint,
    shell: &Path,
    config: &TrialConfig,
    temporary_root: &Path,
) -> TrialReport {
    let id = format!("{:032x}", rand::random::<u128>());
    let mut report = TrialReport {
        id,
        command: command.to_owned(),
        project_root: fingerprint.project_root.clone(),
        observations: Observations::default(),
        clone_ms: 0,
        run_ms: 0,
        exit_code: None,
        clone_method: "not started".to_owned(),
        artifact_dir: None,
    };
    if let Err(error) = run_inner(
        command,
        fingerprint,
        shell,
        config,
        temporary_root,
        &mut report,
    ) {
        report.observations.issues.push(error.to_string());
    }
    report
}

#[cfg(not(target_os = "macos"))]
fn run_inner(
    _: &str,
    _: &Fingerprint,
    _: &Path,
    _: &TrialConfig,
    _: &Path,
    _: &mut TrialReport,
) -> io::Result<()> {
    Err(io::Error::other(
        "sandbox unavailable: trials require macOS",
    ))
}

#[cfg(target_os = "macos")]
fn run_inner(
    command: &str,
    fingerprint: &Fingerprint,
    shell: &Path,
    config: &TrialConfig,
    temporary_root: &Path,
    report: &mut TrialReport,
) -> io::Result<()> {
    config.validate().map_err(io::Error::other)?;
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(config.timeout_secs))
        .ok_or_else(|| io::Error::other("trial timeout exceeds clock range"))?;
    if !config.enabled {
        return Err(io::Error::other("sandbox trials disabled"));
    }
    let dir = tempfile::Builder::new()
        .prefix("dcg-trial-")
        .tempdir_in(temporary_root)?;
    let root = fs::canonicalize(dir.path())?;
    // keep() transfers ownership before any fallible work, including timeout.
    let _cleanup = if config.keep_artifacts {
        report.artifact_dir = Some(dir.keep());
        None
    } else {
        Some(dir)
    };
    let project = root.join("project");
    let home = root.join("home");
    let temp = root.join("tmp");
    fs::create_dir(&home)?;
    fs::create_dir(&temp)?;
    let before_paths = protected_paths(&fingerprint.project_root)?;
    let started = Instant::now();
    // cp -c invokes clonefile(2), including recursive directory cloning. -P
    // preserves links instead of copying data from outside the workspace.
    let cloned = capture(
        Command::new("/bin/cp")
            .args(["-cR", "-P"])
            .arg(&fingerprint.project_root)
            .arg(&project),
        Duration::from_secs(config.timeout_secs),
        OUTPUT_CAP,
    )?;
    if cloned.timed_out {
        report.observations.timed_out = true;
        return Err(io::Error::other("workspace clone timed out"));
    }
    if cloned.status.success() {
        "clonefile".clone_into(&mut report.clone_method);
    } else {
        // A failed cp can leave a partial tree. Preserve it separately until
        // the owning TempDir cleans up, then perform a bounded plain copy.
        if project.exists() {
            fs::rename(&project, root.join("partial-clone"))?;
        }
        let mut remaining = config.max_copy_bytes;
        copy_tree(
            &fingerprint.project_root,
            &project,
            &mut remaining,
            deadline,
        )?;
        "bounded recursive copy".clone_into(&mut report.clone_method);
    }
    report.clone_ms = started.elapsed().as_millis();
    let before = manifest(&project, &before_paths)?;
    let cwd = project.join(
        fingerprint
            .cwd
            .strip_prefix(&fingerprint.project_root)
            .map_err(io::Error::other)?,
    );
    let tag = format!("dcg-trial-{}", report.id);
    let profile = crate::trial_profile::profile(&project, &home, &temp, &tag);
    let canary_before = root.join("observation-start");
    let canary_after = root.join("observation-end");
    let policy_probe = capture(
        Command::new("/usr/bin/sandbox-exec").args(["-p", &profile, "/usr/bin/true"]),
        Duration::from_secs(5),
        OUTPUT_CAP,
    )?;
    if !policy_probe.status.success() {
        return Err(io::Error::other(format!(
            "sandbox unavailable: {}",
            display_text(&String::from_utf8_lossy(&policy_probe.stderr), None)
        )));
    }
    let mut observer = LogObserver::start(&tag)?;
    let probe = capture(
        Command::new("/usr/bin/sandbox-exec")
            .args(["-p", &profile, "/usr/bin/touch"])
            .arg(&canary_before),
        Duration::from_secs(5),
        OUTPUT_CAP,
    )?;
    if probe.status.success() || canary_before.exists() {
        return Err(io::Error::other(
            "sandbox failed its write-enforcement probe",
        ));
    }
    if !observer
        .wait_for(&tag, &canary_before)?
        .iter()
        .any(|v| v.target.contains(&canary_before.display().to_string()))
    {
        return Err(io::Error::other(
            "sandbox violation reports unavailable; command was not started",
        ));
    }
    eprintln!(
        "dcg: verifying `{}` in a sandboxed copy (≤ {} s)…",
        display_text(&crate::redaction::redact_secrets(command), None),
        config.timeout_secs
    );
    if background_job(command) {
        report.observations.issues.push("Background service/job: readiness, port ownership and complete lifecycle were not verified; no automatic approval".to_owned());
    }
    let started = Instant::now();
    let mut child = Command::new("/usr/bin/sandbox-exec");
    let (_, execution_command) = execution_location(command, &fingerprint.cwd);
    child.args(["-p", &profile, "/bin/sh", "-c"])
        .arg("ulimit -t \"$1\"; ulimit -f 131072; ulimit -n 256; if [ \"$4\" = /bin/zsh ]; then \"$4\" -f -c \"$5\"; else \"$4\" -c \"$5\"; fi; result=$?; /usr/bin/touch \"$3\" 2>/dev/null; exit \"$result\"")
        .arg("dcg-trial").arg(config.timeout_secs.to_string()).arg(&canary_before).arg(&canary_after).arg(shell).arg(&execution_command)
        .current_dir(&cwd).env_clear().envs(trial_environment(std::env::vars_os(), &home, &temp));
    let output = capture(
        &mut child,
        deadline.saturating_duration_since(Instant::now()),
        OUTPUT_CAP,
    )?;
    report.run_ms = started.elapsed().as_millis();
    report.exit_code = output.status.code();
    if report
        .exit_code
        .is_some_and(|code| matches!(code, 126 | 127) || code >= 128)
    {
        report
            .observations
            .issues
            .push("command could not start or ended on a signal".to_owned());
    }
    report.observations.timed_out = output.timed_out;
    if output.descendants {
        report.observations.issues.push("Child processes remained after the command exited; terminated the process group. Service lifecycle is unverified".to_owned());
    }
    if !output.complete {
        report
            .observations
            .issues
            .push("output cap reached or child output remained open".to_owned());
    }
    // Some tools preflight permissions using sandbox_check(), which need not
    // emit a kernel violation. Such failure text is uncertainty, never proof
    // of safety (and is not copied into the persisted report).
    let stderr = String::from_utf8_lossy(&output.stderr);
    if [
        "Operation not permitted",
        "Permission denied",
        "EPERM",
        "EACCES",
    ]
    .iter()
    .any(|text| stderr.contains(text))
    {
        report
            .observations
            .issues
            .push("a permission check failed during the trial".to_owned());
    }
    // Reports are asynchronous. Never treat a missing end marker as clean.
    let mut violations = observer.wait_for(&tag, &canary_after)?;
    // Different kernel threads may deliver a child's reports after the final
    // canary. Drain a quiet interval before classifying the complete run.
    std::thread::sleep(Duration::from_millis(300));
    for violation in observer.observations(&tag)? {
        if !violations.contains(&violation) {
            violations.push(violation);
        }
    }
    let log_complete = [&canary_before, &canary_after].iter().all(|path| {
        violations
            .iter()
            .any(|v| v.target.contains(&path.display().to_string()))
    });
    if canary_before.exists() || canary_after.exists() {
        return Err(io::Error::other(
            "sandbox failed its write-enforcement probe",
        ));
    }
    violations.retain(|v| {
        !v.target.contains(&canary_before.display().to_string())
            && !v.target.contains(&canary_after.display().to_string())
    });
    report.observations.violations = violations;
    report.observations.observation_complete = log_complete;
    let mut after_paths = protected_paths(&project)?;
    after_paths.extend(before_paths);
    let after = manifest(&project, &after_paths)?;
    classify_diff(&before, &after, &mut report.observations);
    // No interpretation of output text or exit status as proof of safety.
    Ok(())
}

/// Manual preverification uses the same static evaluator and exact-version store.
pub fn run_manual(command: &str, cwd: &Path, config: &Config) -> Result<String, String> {
    let (execution_cwd, _) = execution_location(command, cwd);
    let cwd = execution_cwd.as_path();
    let store = TrialStore::user().map_err(|e| e.to_string())?;
    let shell = default_shell();
    let fingerprint = store
        .fingerprint(command, cwd, &shell, &[])
        .map_err(|e| e.to_string())?;
    let allowlists = crate::load_default_allowlists().with_rule_grants(
        TRIAL_RULES,
        "trial residual scan",
        "trial",
    );
    let result = crate::evaluator::evaluate_command(
        command,
        config,
        &crate::packs::REGISTRY.collect_enabled_keywords(&config.enabled_pack_ids()),
        &config.overrides.compile(),
        &allowlists,
    );
    if result.decision != crate::evaluator::EvaluationDecision::Allow {
        return Err(format!(
            "Trial refused: {}",
            result.reason().unwrap_or("static evaluation incomplete")
        ));
    }
    let report = run(
        command,
        &fingerprint,
        &shell,
        &config.trial,
        &std::env::temp_dir(),
    );
    let summary = report.summary(crate::config::home_dir().as_deref());
    store
        .save_summary(&report.id, &summary)
        .map_err(|e| e.to_string())?;
    if report.observations.verdict() == Verdict::Safe {
        let after = store
            .fingerprint(command, cwd, &shell, &[])
            .map_err(|e| e.to_string())?;
        if after.digest != fingerprint.digest {
            return Err("Project changed during trial; no approval recorded".to_owned());
        }
        store
            .approve(&fingerprint, "trial", &summary)
            .map_err(|e| e.to_string())?;
    }
    Ok(summary)
}

pub fn default_shell() -> PathBuf {
    std::env::var_os("SHELL")
        .map(PathBuf::from)
        .filter(|p| {
            matches!(
                p.as_os_str().to_str(),
                Some("/bin/bash" | "/bin/zsh" | "/bin/sh")
            )
        })
        .unwrap_or_else(|| PathBuf::from("/bin/sh"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn trigger_list_is_narrow_and_explicit() {
        assert_eq!(TRIAL_RULES, &[("heredoc.script_files", "unverified")]);
        for rule in [
            "core.git:reset-hard",
            "core.filesystem:rm-rf-general",
            "heredoc.shell:launcher-unverified",
            "heredoc.python:shutil_rmtree",
        ] {
            assert!(!TRIAL_RULES.iter().any(|(p, n)| format!("{p}:{n}") == rule));
        }
    }

    #[test]
    fn environment_removes_credentials_and_injection() {
        let parent = [
            "PATH",
            "LANG",
            "LC_ALL",
            "OPENAI_API_KEY",
            "GITHUB_TOKEN",
            "AWS_REGION",
            "SSH_AUTH_SOCK",
            "NODE_OPTIONS",
            "LC_SECRET",
            "DYLD_INSERT_LIBRARIES",
        ]
        .map(|s| (OsString::from(s), OsString::from("value")));
        let env = trial_environment(parent, Path::new("/trial/home"), Path::new("/trial/tmp"));
        assert_eq!(
            env.get(OsStr::new("HOME")),
            Some(&OsString::from("/trial/home"))
        );
        assert!(env.contains_key(OsStr::new("LC_ALL")));
        for name in [
            "OPENAI_API_KEY",
            "GITHUB_TOKEN",
            "AWS_REGION",
            "SSH_AUTH_SOCK",
            "NODE_OPTIONS",
            "LC_SECRET",
            "DYLD_INSERT_LIBRARIES",
        ] {
            assert!(!env.contains_key(OsStr::new(name)));
        }
    }

    #[test]
    fn violation_log_parser_attributes_children_and_ignores_other_trials() {
        let log = "Sandbox: sh(123) deny(1) file-write-unlink /tmp/victim (dcg-trial-abc)\nSandbox: curl(124) deny(1) network-outbound 1.2.3.4:443 (dcg-trial-abc)\nSandbox: sh(900) deny(1) signal 400 (dcg-trial-other)";
        let parsed = parse_violations(log, "dcg-trial-abc");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].target, "/tmp/victim");
        assert_eq!(parsed[1].operation, "network-outbound");
    }

    #[test]
    fn every_verdict_table_row() {
        let clean = Observations {
            observation_complete: true,
            ..Observations::default()
        };
        assert_eq!(clean.verdict(), Verdict::Safe);
        for operation in [
            "file-write-unlink",
            "file-write-data",
            "file-write-mode",
            "signal",
            "appleevent-send",
        ] {
            let mut o = clean.clone();
            o.violations.push(Violation {
                operation: operation.to_owned(),
                target: "target".to_owned(),
            });
            assert_eq!(o.verdict(), Verdict::Unsafe);
        }
        let mut o = clean.clone();
        o.deleted.push("source".to_owned());
        assert_eq!(o.verdict(), Verdict::Unsafe);
        let mut o = clean.clone();
        o.modified.push("source".to_owned());
        assert_eq!(o.verdict(), Verdict::Inconclusive);
        let mut o = clean.clone();
        o.timed_out = true;
        assert_eq!(o.verdict(), Verdict::Inconclusive);
        let mut o = clean.clone();
        o.violations.push(Violation {
            operation: "network-outbound".to_owned(),
            target: "example.com:443".to_owned(),
        });
        assert_eq!(o.verdict(), Verdict::Inconclusive);
        let mut o = clean;
        o.issues.push("TTY needed".to_owned());
        assert_eq!(o.verdict(), Verdict::Inconclusive);
        assert_eq!(Observations::default().verdict(), Verdict::Inconclusive);
    }

    #[test]
    fn clone_diff_preserves_tracked_build_files() {
        let before = BTreeMap::from([
            (PathBuf::from("source"), "a".to_owned()),
            (PathBuf::from("build/tracked"), "b".to_owned()),
        ]);
        let after = BTreeMap::from([
            (PathBuf::from("source"), "c".to_owned()),
            (PathBuf::from("build/new"), "d".to_owned()),
        ]);
        let mut o = Observations::default();
        classify_diff(&before, &after, &mut o);
        assert_eq!(o.deleted, ["build/tracked"]);
        assert_eq!(o.modified, ["source"]);
    }

    #[test]
    fn explanations_are_bounded_and_do_not_include_contents() {
        let report = TrialReport {
            id: "abc".to_owned(),
            command: "npm test".to_owned(),
            project_root: PathBuf::from("/Users/test/project"),
            observations: Observations {
                deleted: (0..9).map(|i| format!("/Users/test/file{i}")).collect(),
                ..Observations::default()
            },
            clone_ms: 1,
            run_ms: 2,
            exit_code: Some(0),
            clone_method: "copy".to_owned(),
            artifact_dir: None,
        };
        let summary = report.summary(Some(Path::new("/Users/test")));
        assert!(!summary.contains("/Users/test"));
        assert!(summary.contains("~/file0"));
        assert!(summary.contains("4 additional"));
        assert!(!summary.contains("file8"));
    }

    #[test]
    fn background_services_are_not_finite_evidence() {
        assert!(background_job(
            "nohup python3 -m http.server 18476 --bind 127.0.0.1 > /tmp/preview.log 2>&1 < /dev/null &"
        ));
        assert!(background_job("sleep 30 & wait"));
        assert!(!background_job("printf '%s' 'ampersand & is data' && true"));
    }
}
