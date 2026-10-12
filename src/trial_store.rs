//! Exact-version sandbox and filesystem approvals beside the trusted user allowlist.
//!
//! No project file can grant an approval. In the absence of reliable unprivileged
//! read tracing, fingerprints cover the complete non-ignored source manifest,
//! explicitly resolved sources, and executable contents. Metadata only caches
//! content hashes; touching a file does not alter its fingerprint.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ast_grep_core::AstGrep;
use ast_grep_language::SupportLang;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const SCHEMA_VERSION: u32 = 1;
const MAX_STORE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MANIFEST_FILES: usize = 100_000;
const SUMMARY_LIMIT: usize = 8192;
const RECENT_SUMMARIES: usize = 128;

/// Inputs and content digest of one exact command version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    pub digest: String,
    pub project_root: PathBuf,
    pub cwd: PathBuf,
    pub command: String,
    pub shell: PathBuf,
    pub resolved_sources: Vec<PathBuf>,
}

/// A narrow approval that only resolves the script-inspection trigger.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedTrial {
    pub kind: String,
    pub fingerprint: String,
    pub project_root: PathBuf,
    pub cwd: PathBuf,
    pub command: String,
    pub shell: PathBuf,
    pub resolved_sources: Vec<PathBuf>,
    pub created_at: String,
    pub source: String,
    pub summary: String,
}

/// A Touch ID approval bound to one filesystem rule and its operand identities.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LearnedFilesystem {
    pub kind: String,
    pub fingerprint: String,
    pub cwd: PathBuf,
    pub command: String,
    pub rule_id: String,
    pub operands: Vec<PathBuf>,
    pub created_at: String,
    pub source: String,
    pub summary: String,
}

/// Separate counts keep CLI reports clear about the two approval kinds.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PrunedVersions {
    pub verified_trials: usize,
    pub learned_filesystem: usize,
}

impl PrunedVersions {
    #[must_use]
    pub const fn total(self) -> usize {
        self.verified_trials + self.learned_filesystem
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CachedHash {
    size: u64,
    modified_ns: u128,
    identity: String,
    digest: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoreData {
    schema_version: u32,
    #[serde(default)]
    verified_trials: Vec<VerifiedTrial>,
    #[serde(default)]
    learned_filesystem: Vec<LearnedFilesystem>,
    #[serde(default)]
    file_hashes: BTreeMap<String, CachedHash>,
    #[serde(default)]
    summaries: Vec<(String, String)>,
}

impl Default for StoreData {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            verified_trials: Vec::new(),
            learned_filesystem: Vec::new(),
            file_hashes: BTreeMap::new(),
            summaries: Vec::new(),
        }
    }
}

/// The directory must be selected by trusted configuration, never by a project.
#[derive(Debug, Clone)]
pub struct TrialStore {
    directory: PathBuf,
}

impl TrialStore {
    #[must_use]
    pub const fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    /// Use the same trusted user directory as ordinary allowlist entries.
    pub fn user() -> io::Result<Self> {
        let path = crate::allowlist::user_allowlist_path();
        let directory = path
            .parent()
            .filter(|path| path.is_absolute())
            .ok_or_else(|| io::Error::other("no absolute user allowlist directory"))?;
        Ok(Self::new(directory.to_path_buf()))
    }

    /// Compute the fallback source-manifest fingerprint and update its hash cache.
    pub fn fingerprint(
        &self,
        command: &str,
        cwd: &Path,
        shell: &Path,
        resolved_sources: &[PathBuf],
    ) -> io::Result<Fingerprint> {
        self.fingerprint_inner(command, cwd, shell, resolved_sources, true)
    }

    fn fingerprint_inner(
        &self,
        command: &str,
        cwd: &Path,
        shell: &Path,
        resolved_sources: &[PathBuf],
        persist_cache: bool,
    ) -> io::Result<Fingerprint> {
        let cwd = cwd.canonicalize()?;
        let project_root = project_root(&cwd)?;
        let shell = shell.canonicalize()?;
        let sources = resolved_sources
            .iter()
            .map(|source| cwd.join(source).canonicalize())
            .collect::<io::Result<Vec<_>>>()?;
        let manifest = source_manifest(&project_root)?;
        let mut executables = resolved_executables(command, &cwd)?;
        executables.insert(shell.clone());
        executables.extend(sources.iter().cloned());
        resolve_interpreters(&mut executables, &cwd)?;
        self.with_data(|data| {
            let mut hasher = Sha256::new();
            hash_field(&mut hasher, b"dcg-verified-trial-v1");
            hash_field(&mut hasher, path_text(&project_root)?.as_bytes());
            hash_field(
                &mut hasher,
                path_text(cwd.strip_prefix(&project_root).map_err(io::Error::other)?)?.as_bytes(),
            );
            hash_field(
                &mut hasher,
                crate::normalize::normalize_command(command).as_bytes(),
            );
            // Normalization intentionally erases executable prefixes and wrappers
            // elsewhere. Exact approvals must retain their original semantics.
            hash_field(&mut hasher, command.as_bytes());
            hash_field(
                &mut hasher,
                std::env::var_os("PATH")
                    .unwrap_or_default()
                    .as_encoded_bytes(),
            );
            let mut dirty = false;
            for path in &manifest {
                hash_field(&mut hasher, b"source");
                hash_field(&mut hasher, path_text(path)?.as_bytes());
                let digest = cached_hash(&project_root.join(path), &mut data.file_hashes)?;
                dirty |= digest.1;
                hash_field(&mut hasher, digest.0.as_bytes());
                hash_permissions(&mut hasher, &project_root.join(path))?;
            }
            for path in &executables {
                hash_field(&mut hasher, b"executable-or-resolved-source");
                hash_field(&mut hasher, path_text(path)?.as_bytes());
                let digest = cached_hash(path, &mut data.file_hashes)?;
                dirty |= digest.1;
                hash_field(&mut hasher, digest.0.as_bytes());
                hash_permissions(&mut hasher, path)?;
            }
            if data.file_hashes.len() > MAX_MANIFEST_FILES {
                data.file_hashes.clear();
                dirty = true;
            }
            Ok((
                Fingerprint {
                    digest: hex_digest(&hasher.finalize()),
                    project_root,
                    cwd,
                    command: command.to_owned(),
                    shell,
                    resolved_sources: sources,
                },
                dirty && persist_cache,
            ))
        })
    }

    pub fn lookup(&self, current_version: &Fingerprint) -> io::Result<Option<VerifiedTrial>> {
        self.with_data(|data| {
            Ok((
                data.verified_trials
                    .iter()
                    .find(|entry| {
                        let same_digest = entry.fingerprint == current_version.digest;
                        same_digest
                            && entry.project_root == current_version.project_root
                            && entry.cwd == current_version.cwd
                            && entry.command == current_version.command
                            && valid_entry(entry)
                    })
                    .cloned(),
                false,
            ))
        })
    }

    /// Record either an observed safe run or an explicit desktop approval.
    pub fn approve(
        &self,
        fingerprint: &Fingerprint,
        source: &str,
        summary: &str,
    ) -> io::Result<VerifiedTrial> {
        if !matches!(source, "trial" | "user-review") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown verified trial source",
            ));
        }
        let entry = VerifiedTrial {
            kind: "verified_trial".to_owned(),
            fingerprint: fingerprint.digest.clone(),
            project_root: fingerprint.project_root.clone(),
            cwd: fingerprint.cwd.clone(),
            command: fingerprint.command.clone(),
            shell: fingerprint.shell.clone(),
            resolved_sources: fingerprint.resolved_sources.clone(),
            created_at: chrono::Utc::now().to_rfc3339(),
            source: source.to_owned(),
            summary: bounded_summary(summary),
        };
        self.with_data(|data| {
            data.verified_trials
                .retain(|old| old.fingerprint != entry.fingerprint);
            data.verified_trials.push(entry.clone());
            Ok((entry, true))
        })
    }

    pub fn list(&self) -> io::Result<Vec<VerifiedTrial>> {
        self.with_data(|data| {
            Ok((
                data.verified_trials
                    .iter()
                    .filter(|entry| valid_entry(entry))
                    .cloned()
                    .collect(),
                false,
            ))
        })
    }

    pub fn lookup_learned(
        &self,
        current: &crate::effects::OperandFingerprint,
    ) -> io::Result<Option<LearnedFilesystem>> {
        self.with_data(|data| {
            Ok((
                data.learned_filesystem
                    .iter()
                    .find(|entry| {
                        valid_learned_entry(entry)
                            && entry.fingerprint == current.digest
                            && entry.cwd == current.cwd
                            && entry.command == current.command
                            && entry.rule_id == current.rule_id
                            && entry.operands == current.operands
                    })
                    .cloned(),
                false,
            ))
        })
    }

    /// Only desktop review may create a reusable definite-filesystem approval.
    pub fn approve_learned(
        &self,
        fingerprint: &crate::effects::OperandFingerprint,
        summary: &str,
    ) -> io::Result<LearnedFilesystem> {
        // Recheck at the write boundary: unsupported, changed, and dcg-owned
        // operands cannot enter the store even if a caller kept an old digest.
        let current = crate::effects::fingerprint(
            &fingerprint.command,
            &fingerprint.cwd,
            &fingerprint.rule_id,
        )?;
        if current != *fingerprint {
            return Err(io::Error::other(
                "filesystem operands changed during review",
            ));
        }
        let entry = LearnedFilesystem {
            kind: "learned_filesystem".to_owned(),
            fingerprint: fingerprint.digest.clone(),
            cwd: fingerprint.cwd.clone(),
            command: fingerprint.command.clone(),
            rule_id: fingerprint.rule_id.clone(),
            operands: fingerprint.operands.clone(),
            created_at: chrono::Utc::now().to_rfc3339(),
            source: "user-review".to_owned(),
            summary: bounded_summary(summary),
        };
        if !valid_learned_entry(&entry) {
            return Err(io::Error::other("invalid filesystem approval"));
        }
        self.with_data(|data| {
            data.learned_filesystem
                .retain(|old| old.fingerprint != entry.fingerprint);
            data.learned_filesystem.push(entry.clone());
            Ok((entry, true))
        })
    }

    pub fn list_learned(&self) -> io::Result<Vec<LearnedFilesystem>> {
        self.with_data(|data| {
            Ok((
                data.learned_filesystem
                    .iter()
                    .filter(|entry| valid_learned_entry(entry))
                    .cloned()
                    .collect(),
                false,
            ))
        })
    }

    pub fn remove(&self, id: &str) -> io::Result<bool> {
        let id = id.strip_prefix("sha256:").unwrap_or(id);
        self.with_data(|data| {
            let before = data.verified_trials.len() + data.learned_filesystem.len();
            data.verified_trials.retain(|entry| entry.fingerprint != id);
            data.learned_filesystem
                .retain(|entry| entry.fingerprint != id);
            let removed = data.verified_trials.len() + data.learned_filesystem.len() != before;
            Ok((removed, removed))
        })
    }

    /// Remove stale exact versions; there is deliberately no time expiry.
    pub fn prune(&self) -> io::Result<usize> {
        self.prune_at(None, false)
    }

    /// Count or remove stale entries, optionally restricting to one project.
    pub fn prune_at(&self, project: Option<&Path>, dry_run: bool) -> io::Result<usize> {
        self.prune_counts_at(project, dry_run)
            .map(PrunedVersions::total)
    }

    /// Count the two approval kinds separately, using the same pruning operation.
    pub fn prune_counts_at(
        &self,
        project: Option<&Path>,
        dry_run: bool,
    ) -> io::Result<PrunedVersions> {
        let entries = self.list()?;
        let mut stale = BTreeSet::new();
        for entry in entries {
            if project.is_some_and(|project| project != entry.project_root) {
                continue;
            }
            let current = self.fingerprint_inner(
                &entry.command,
                &entry.cwd,
                &entry.shell,
                &entry.resolved_sources,
                !dry_run,
            );
            if !current.is_ok_and(|value| value.digest == entry.fingerprint) {
                stale.insert(entry.fingerprint);
            }
        }
        let mut stale_learned = BTreeSet::new();
        for entry in self.list_learned()? {
            if project.is_some_and(|project| !entry.cwd.starts_with(project)) {
                continue;
            }
            let current = crate::effects::fingerprint(&entry.command, &entry.cwd, &entry.rule_id);
            if !current.is_ok_and(|value| value.digest == entry.fingerprint) {
                stale_learned.insert(entry.fingerprint);
            }
        }
        self.with_data(|data| {
            if dry_run {
                return Ok((
                    PrunedVersions {
                        verified_trials: stale.len(),
                        learned_filesystem: stale_learned.len(),
                    },
                    false,
                ));
            }
            let before = data.verified_trials.len();
            data.verified_trials
                .retain(|entry| !stale.contains(&entry.fingerprint));
            let learned_before = data.learned_filesystem.len();
            data.learned_filesystem
                .retain(|entry| !stale_learned.contains(&entry.fingerprint));
            let removed = PrunedVersions {
                verified_trials: before - data.verified_trials.len(),
                learned_filesystem: learned_before - data.learned_filesystem.len(),
            };
            Ok((removed, removed.total() > 0))
        })
    }

    pub fn save_summary(&self, id: &str, summary: &str) -> io::Result<()> {
        if id.is_empty()
            || id.len() > 128
            || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid trial id",
            ));
        }
        self.with_data(|data| {
            data.summaries.retain(|(old, _)| old != id);
            data.summaries
                .push((id.to_owned(), bounded_summary(summary)));
            if data.summaries.len() > RECENT_SUMMARIES {
                data.summaries
                    .drain(..data.summaries.len() - RECENT_SUMMARIES);
            }
            Ok(((), true))
        })
    }

    pub fn show(&self, id: &str) -> io::Result<Option<String>> {
        self.with_data(|data| {
            Ok((
                data.summaries
                    .iter()
                    .find(|(key, _)| key == id)
                    .map(|(_, summary)| summary.clone()),
                false,
            ))
        })
    }

    fn with_data<T>(
        &self,
        operation: impl FnOnce(&mut StoreData) -> io::Result<(T, bool)>,
    ) -> io::Result<T> {
        fs::create_dir_all(&self.directory)?;
        reject_symlink(&self.directory)?;
        let lock_path = self.directory.join("verified_trials.lock");
        reject_symlink(&lock_path)?;
        let lock = private_options()
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        let started = Instant::now();
        loop {
            match FileExt::try_lock_exclusive(&lock) {
                Ok(()) => break,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if started.elapsed() > Duration::from_millis(500) {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "trial store is busy",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(error),
            }
        }
        let path = self.directory.join("verified_trials.json");
        reject_symlink(&path)?;
        let mut data = match File::open(&path) {
            Ok(file) => {
                if file.metadata()?.len() > MAX_STORE_BYTES {
                    return Err(io::Error::other("trial store exceeds its size limit"));
                }
                let value: StoreData = serde_json::from_reader(file).map_err(io::Error::other)?;
                if value.schema_version != SCHEMA_VERSION {
                    return Err(io::Error::other("unsupported trial store version"));
                }
                value
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => StoreData::default(),
            Err(error) => return Err(error),
        };
        let (result, changed) = operation(&mut data)?;
        if changed {
            self.write_atomic(&path, &data)?;
        }
        // File ownership releases the lock on all success and error paths.
        Ok(result)
    }

    fn write_atomic(&self, path: &Path, data: &StoreData) -> io::Result<()> {
        let bytes = serde_json::to_vec(data).map_err(io::Error::other)?;
        if bytes.len() as u64 > MAX_STORE_BYTES {
            return Err(io::Error::other("trial store exceeds its size limit"));
        }
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let temporary = self.directory.join(format!(
            ".verified-trials-{}-{stamp}.tmp",
            std::process::id()
        ));
        let mut file = private_options().create_new(true).open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(temporary, path)?;
        #[cfg(unix)]
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
}

fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

fn reject_symlink(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(io::Error::other("trial store paths must not be symlinks"))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn valid_entry(entry: &VerifiedTrial) -> bool {
    entry.kind == "verified_trial"
        && matches!(entry.source.as_str(), "trial" | "user-review")
        && entry.fingerprint.len() == 64
        && entry
            .fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        && entry.cwd.starts_with(&entry.project_root)
        && entry.project_root.is_absolute()
}

fn valid_learned_entry(entry: &LearnedFilesystem) -> bool {
    entry.kind == "learned_filesystem"
        && entry.source == "user-review"
        && entry.fingerprint.len() == 64
        && entry
            .fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        && entry.cwd.is_absolute()
        && !entry.command.is_empty()
        && entry.rule_id.starts_with("core.filesystem:")
        && !entry.operands.is_empty()
        && entry.operands.iter().all(|path| path.is_absolute())
}

fn bounded_summary(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .scan(0, |bytes, c| {
            *bytes += c.len_utf8();
            (*bytes <= SUMMARY_LIMIT).then_some(c)
        })
        .collect()
}

fn path_text(path: &Path) -> io::Result<&str> {
    path.to_str()
        .ok_or_else(|| io::Error::other("trial fingerprint requires UTF-8 paths"))
}

fn hash_field(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_le_bytes());
    hash.update(value);
}

fn hash_permissions(hash: &mut Sha256, path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        hash_field(hash, &metadata.permissions().mode().to_le_bytes());
    }
    #[cfg(not(unix))]
    hash_field(hash, &[u8::from(metadata.permissions().readonly())]);
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(result, "{byte:02x}");
    }
    result
}

fn git(root: &Path, args: &[&str]) -> io::Result<std::process::Output> {
    let executable = if cfg!(unix) { "/usr/bin/git" } else { "git" };
    let mut command = Command::new(executable);
    command
        .current_dir(root)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .env("GIT_OPTIONAL_LOCKS", "0")
        // A repository must not execute a configured fsmonitor/hook merely
        // because dcg is enumerating inputs before a sandbox exists.
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
        ])
        .arg("-c")
        .arg(if cfg!(windows) {
            "core.hooksPath=NUL"
        } else {
            "core.hooksPath=/dev/null"
        })
        .args(args);
    bounded_probe(&mut command, Duration::from_secs(2), 16 * 1024 * 1024)
}

fn bounded_probe(
    command: &mut Command,
    timeout: Duration,
    output_limit: u64,
) -> io::Result<std::process::Output> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing git output pipe"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("missing git error pipe"))?;
    let output_reader = std::thread::spawn(move || read_probe_output(stdout, output_limit));
    let error_reader = std::thread::spawn(move || read_probe_output(stderr, 4096));
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if started.elapsed() >= timeout => {
                break Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "git manifest query timed out",
                ));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(2)),
            Err(error) => break Err(error),
        }
    };
    // Stop inherited pipe holders too, so joining the bounded readers cannot
    // leave a hook waiting indefinitely after a failed repository probe.
    #[cfg(unix)]
    {
        let _ = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(child.id().cast_signed()),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
    if status.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let stdout = output_reader
        .join()
        .map_err(|_| io::Error::other("git output reader failed"))?;
    let stderr = error_reader
        .join()
        .map_err(|_| io::Error::other("git error reader failed"))?;
    Ok(std::process::Output {
        status: status?,
        stdout: stdout?,
        stderr: stderr?,
    })
}

fn read_probe_output(reader: impl Read, limit: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::Error::other(
            "git manifest query exceeded its output limit",
        ));
    }
    Ok(bytes)
}

fn optional_git(root: &Path, args: &[&str]) -> io::Result<Option<std::process::Output>> {
    match git(root, args) {
        Ok(output) if output.status.success() => Ok(Some(output)),
        Ok(_) => Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Git work-tree root, or the canonical cwd for a non-Git project.
pub fn project_root(cwd: &Path) -> io::Result<PathBuf> {
    let cwd = cwd.canonicalize()?;
    if let Some(output) = optional_git(&cwd, &["rev-parse", "--show-toplevel"])? {
        let text = String::from_utf8(output.stdout).map_err(io::Error::other)?;
        let root = PathBuf::from(text.trim_end_matches(['\r', '\n'])).canonicalize()?;
        if cwd.starts_with(&root) {
            return Ok(root);
        }
    }
    Ok(cwd)
}

/// Tracked paths relative to the requested directory, without running Git hooks.
pub(crate) fn tracked_files(root: &Path) -> io::Result<BTreeSet<PathBuf>> {
    let output = git(root, &["ls-files", "-z"])?;
    if !output.status.success() {
        return Err(io::Error::other("git tracking information is unavailable"));
    }
    let mut files = BTreeSet::new();
    for raw in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|raw| !raw.is_empty())
    {
        let path = PathBuf::from(std::str::from_utf8(raw).map_err(io::Error::other)?);
        if path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(io::Error::other("invalid git tracking path"));
        }
        files.insert(path);
        if files.len() > MAX_MANIFEST_FILES {
            return Err(io::Error::other("git tracking exceeds its file limit"));
        }
    }
    Ok(files)
}

fn source_manifest(root: &Path) -> io::Result<BTreeSet<PathBuf>> {
    if let Some(output) = optional_git(root, &["ls-files", "-co", "--exclude-standard", "-z"])? {
        let mut files = BTreeSet::new();
        for raw in output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|raw| !raw.is_empty())
        {
            let path = PathBuf::from(std::str::from_utf8(raw).map_err(io::Error::other)?);
            if path.is_absolute()
                || path
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir))
            {
                return Err(io::Error::other("invalid git manifest path"));
            }
            match fs::symlink_metadata(root.join(&path)) {
                Ok(metadata) if metadata.is_dir() => {
                    // Submodules contain executable inputs. Refuse a false exact
                    // approval instead of silently hashing only their gitlink.
                    return Err(io::Error::other(
                        "source manifest contains a submodule directory",
                    ));
                }
                Ok(_) => {
                    files.insert(path);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            if files.len() > MAX_MANIFEST_FILES {
                return Err(io::Error::other("source manifest exceeds its file limit"));
            }
        }
        return Ok(files);
    }
    let mut files = BTreeSet::new();
    collect_files(root, Path::new(""), &mut files)?;
    Ok(files)
}

fn collect_files(root: &Path, relative: &Path, files: &mut BTreeSet<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(root.join(relative))? {
        let entry = entry?;
        if entry.file_name() == ".git" {
            continue;
        }
        let path = relative.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            collect_files(root, &path, files)?;
        } else {
            files.insert(path);
        }
        if files.len() > MAX_MANIFEST_FILES {
            return Err(io::Error::other("source manifest exceeds its file limit"));
        }
    }
    Ok(())
}

fn cached_hash(
    path: &Path,
    cache: &mut BTreeMap<String, CachedHash>,
) -> io::Result<(String, bool)> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        // A source symlink's target can change independently, including outside
        // the clone. The runner cannot certify that as an exact source version.
        return Err(io::Error::other(format!(
            "source manifest contains symlink: {}",
            path.display()
        )));
    }
    if !metadata.is_file() {
        return Err(io::Error::other(
            "source manifest contains a non-regular file",
        ));
    }
    let mut state = file_state(&metadata)?;
    let key = path_text(path)?.to_owned();
    if let Some(cached) = cache.get(&key)
        && cached.size == state.size
        && cached.modified_ns == state.modified_ns
        && cached.identity == state.identity
    {
        return Ok((cached.digest.clone(), false));
    }
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 16_384];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    if file_state(&file.metadata()?)? != state || file_state(&fs::symlink_metadata(path)?)? != state
    {
        return Err(io::Error::other("source file changed while fingerprinting"));
    }
    state.digest = hex_digest(&hash.finalize());
    let digest = state.digest.clone();
    cache.insert(key, state);
    Ok((digest, true))
}

fn file_state(metadata: &fs::Metadata) -> io::Result<CachedHash> {
    #[cfg(unix)]
    let identity = {
        use std::os::unix::fs::MetadataExt;
        format!(
            "{}:{}:{}:{}:{}",
            metadata.dev(),
            metadata.ino(),
            metadata.ctime(),
            metadata.ctime_nsec(),
            metadata.mode()
        )
    };
    #[cfg(not(unix))]
    let identity = format!(
        "{:?}:{}",
        metadata.created().ok(),
        metadata.permissions().readonly()
    );
    Ok(CachedHash {
        size: metadata.len(),
        modified_ns: metadata
            .modified()?
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos(),
        identity,
        digest: String::new(),
    })
}

fn resolved_executables(command: &str, cwd: &Path) -> io::Result<BTreeSet<PathBuf>> {
    let ast = AstGrep::new(command, SupportLang::Bash);
    let mut pending = vec![ast.root()];
    let mut result = BTreeSet::new();
    while let Some(node) = pending.pop() {
        pending.extend(node.children());
        if node.kind().as_ref() == "command" {
            let text = node.text();
            let words = shell_words::split(&text).map_err(io::Error::other)?;
            if words.iter().any(|word| word.starts_with("PATH=")) {
                return Err(io::Error::other(
                    "command-local PATH requires desktop review",
                ));
            }
            let Some(first) = words.iter().find(|word| !word.contains('=')) else {
                continue;
            };
            if first.contains(['$', '`', '*', '?', '[', '{', '~']) {
                return Err(io::Error::other(
                    "dynamic executable cannot be fingerprinted",
                ));
            }
            if matches!(
                first.as_str(),
                "cd" | "echo"
                    | "printf"
                    | "true"
                    | "false"
                    | ":"
                    | "test"
                    | "["
                    | "export"
                    | "unset"
                    | "set"
                    | "read"
                    | "exit"
                    | "return"
                    | "shift"
                    | "umask"
                    | "pwd"
                    | "wait"
                    | "kill"
            ) {
                continue;
            }
            let effective = crate::rebase_recovery::resolve_effective_cwd(
                cwd,
                &command[..node.range().end],
                crate::normalize::ShellDialect::Posix,
            )
            .ok_or_else(|| io::Error::other("dynamic working directory cannot be fingerprinted"))?;
            let path = resolve_executable(first, &effective)?;
            result.insert(path);
            let stripped = crate::normalize::strip_wrapper_prefixes(&text);
            let inner = shell_words::split(&stripped.normalized).map_err(io::Error::other)?;
            if let Some(executable) = inner.first()
                && executable != first
            {
                result.insert(resolve_executable(executable, &effective)?);
            }
        }
    }
    Ok(result)
}

fn resolve_executable(name: &str, cwd: &Path) -> io::Result<PathBuf> {
    if name.contains('/') || name.contains('\\') {
        return cwd.join(name).canonicalize();
    }
    for directory in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        let candidate = cwd.join(directory).join(name);
        if candidate.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if fs::metadata(&candidate)?.permissions().mode() & 0o111 == 0 {
                    continue;
                }
            }
            return candidate.canonicalize();
        }
    }
    Err(io::Error::other(format!(
        "executable cannot be resolved: {name}"
    )))
}

fn resolve_interpreters(paths: &mut BTreeSet<PathBuf>, cwd: &Path) -> io::Result<()> {
    let mut pending: Vec<_> = paths.iter().cloned().collect();
    let mut inspected = BTreeSet::new();
    while let Some(path) = pending.pop() {
        if !inspected.insert(path.clone()) {
            continue;
        }
        if inspected.len() > 512 {
            return Err(io::Error::other("too many resolved trial interpreters"));
        }
        if !fs::metadata(&path)?.is_file() {
            return Err(io::Error::other("trial source is not a regular file"));
        }
        let mut header = [0_u8; 4096];
        let count = File::open(&path)?.read(&mut header)?;
        if !header[..count].starts_with(b"#!") {
            continue;
        }
        let line = header[2..count]
            .split(|byte| *byte == b'\n')
            .next()
            .unwrap_or_default();
        let line = std::str::from_utf8(line).map_err(io::Error::other)?;
        let words = shell_words::split(line).map_err(io::Error::other)?;
        let Some(interpreter) = words.first() else {
            return Err(io::Error::other("empty script interpreter"));
        };
        let interpreter = resolve_executable(interpreter, cwd)?;
        if interpreter.file_name().is_some_and(|name| name == "env") {
            let command = words
                .iter()
                .skip(1)
                .find(|word| {
                    !matches!(
                        word.as_str(),
                        "-S" | "--split-string" | "-i" | "--ignore-environment"
                    ) && !word.contains('=')
                })
                .ok_or_else(|| io::Error::other("env shebang has no interpreter"))?;
            if command.starts_with('-') || command.contains(['$', '`']) {
                return Err(io::Error::other(
                    "dynamic env shebang cannot be fingerprinted",
                ));
            }
            let executable = resolve_executable(command, cwd)?;
            if paths.insert(executable.clone()) {
                pending.push(executable);
            }
        }
        if paths.insert(interpreter.clone()) {
            pending.push(interpreter);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, PathBuf, TrialStore) {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("project");
        fs::create_dir(&project).unwrap();
        fs::write(project.join("run.sh"), "echo safe\n").unwrap();
        fs::write(temp.path().join("shell"), "fixture shell contents").unwrap();
        let store = TrialStore::new(temp.path().join("trusted"));
        (temp, project, store)
    }

    fn fingerprint(store: &TrialStore, project: &Path) -> Fingerprint {
        store
            .fingerprint("echo safe", project, &project.with_file_name("shell"), &[])
            .unwrap()
    }

    #[test]
    fn stable_content_survives_touch_and_invalidates_on_edit() {
        let (_temp, project, store) = fixture();
        let first = fingerprint(&store, &project);
        let source = project.join("run.sh");
        let file = OpenOptions::new().write(true).open(&source).unwrap();
        file.set_modified(SystemTime::now() + Duration::from_secs(5))
            .unwrap();
        assert_eq!(first.digest, fingerprint(&store, &project).digest);
        fs::write(source, "echo evil\n").unwrap();
        assert_ne!(first.digest, fingerprint(&store, &project).digest);
    }

    #[test]
    fn same_size_and_restored_mtime_cannot_reuse_cached_hash() {
        let (_temp, project, store) = fixture();
        let first = fingerprint(&store, &project);
        let source = project.join("run.sh");
        let modified = fs::metadata(&source).unwrap().modified().unwrap();
        fs::write(&source, "echo evil\n").unwrap();
        File::options()
            .write(true)
            .open(source)
            .unwrap()
            .set_modified(modified)
            .unwrap();
        #[cfg(unix)]
        assert_ne!(first.digest, fingerprint(&store, &project).digest);
    }

    #[test]
    fn added_deleted_files_and_command_invalidate() {
        let (_temp, project, store) = fixture();
        let first = fingerprint(&store, &project);
        fs::write(project.join("extra"), "input").unwrap();
        let added = fingerprint(&store, &project);
        assert_ne!(first.digest, added.digest);
        fs::remove_file(project.join("extra")).unwrap();
        assert_eq!(first.digest, fingerprint(&store, &project).digest);
        let changed = store
            .fingerprint("echo other", &project, &first.shell, &[])
            .unwrap();
        assert_ne!(first.digest, changed.digest);
    }

    #[test]
    fn project_and_cwd_are_bound_to_approval() {
        let (_temp, project, store) = fixture();
        let first = fingerprint(&store, &project);
        let other = project.with_file_name("other");
        fs::create_dir(&other).unwrap();
        fs::write(other.join("run.sh"), "echo safe\n").unwrap();
        assert_ne!(first.digest, fingerprint(&store, &other).digest);
    }

    #[cfg(unix)]
    #[test]
    fn permission_changes_invalidate_an_observed_version() {
        use std::os::unix::fs::PermissionsExt;
        let (_temp, project, store) = fixture();
        let before = fingerprint(&store, &project);
        store.approve(&before, "trial", "safe").unwrap();
        let path = project.join("run.sh");
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        fs::set_permissions(path, fs::Permissions::from_mode(mode ^ 0o100)).unwrap();
        let after = fingerprint(&store, &project);
        assert_ne!(before.digest, after.digest);
        assert!(store.lookup(&after).unwrap().is_none());
    }

    #[test]
    fn approval_persists_lists_removes_and_prunes_exact_versions() {
        let (temp, project, store) = fixture();
        let first = fingerprint(&store, &project);
        store.approve(&first, "trial", "safe build writes").unwrap();
        let reopened = TrialStore::new(temp.path().join("trusted"));
        assert_eq!(reopened.lookup(&first).unwrap().unwrap().source, "trial");
        assert_eq!(reopened.list().unwrap().len(), 1);
        assert_eq!(reopened.prune().unwrap(), 0);
        fs::write(project.join("run.sh"), "changed").unwrap();
        assert!(
            reopened
                .lookup(&fingerprint(&reopened, &project))
                .unwrap()
                .is_none()
        );
        assert_eq!(reopened.prune().unwrap(), 1);
        let next = fingerprint(&reopened, &project);
        reopened
            .approve(&next, "user-review", "user approved")
            .unwrap();
        assert!(reopened.remove(&next.digest).unwrap());
        assert!(!reopened.remove(&next.digest).unwrap());
    }

    #[cfg(unix)]
    fn learned_fingerprint(project: &Path) -> crate::effects::OperandFingerprint {
        crate::effects::fingerprint(
            &format!(
                "/bin/rm -r '{}'",
                project.canonicalize().unwrap().join("run.sh").display()
            ),
            &project.canonicalize().unwrap(),
            "core.filesystem:rm-recursive-general",
        )
        .unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn learned_approval_persists_separately_and_removes_by_digest() {
        let (temp, project, store) = fixture();
        let trial = fingerprint(&store, &project);
        store.approve(&trial, "trial", "one observed run").unwrap();
        let learned = learned_fingerprint(&project);
        let approved = store
            .approve_learned(&learned, "user approved one file")
            .unwrap();
        assert_eq!(approved.kind, "learned_filesystem");
        assert_eq!(approved.source, "user-review");
        assert_eq!(approved.command, learned.command);
        assert_eq!(approved.cwd, learned.cwd);
        assert_eq!(approved.rule_id, learned.rule_id);
        assert_eq!(approved.operands, learned.operands);
        assert!(!approved.created_at.is_empty());

        let reopened = TrialStore::new(temp.path().join("trusted"));
        assert_eq!(reopened.lookup_learned(&learned).unwrap(), Some(approved));
        assert_eq!(reopened.list().unwrap().len(), 1);
        assert_eq!(reopened.list_learned().unwrap().len(), 1);
        assert!(
            reopened
                .remove(&format!("sha256:{}", learned.digest))
                .unwrap()
        );
        assert!(!reopened.remove(&learned.digest).unwrap());
        assert!(reopened.list_learned().unwrap().is_empty());
        assert!(reopened.lookup(&trial).unwrap().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn learned_lookup_checks_command_rule_cwd_and_operands_even_with_same_digest() {
        let (_temp, project, store) = fixture();
        let learned = learned_fingerprint(&project);
        store.approve_learned(&learned, "approved").unwrap();
        let mut changed = learned_fingerprint(&project);
        changed.command.push_str(" --other");
        assert!(store.lookup_learned(&changed).unwrap().is_none());
        let mut changed = learned_fingerprint(&project);
        changed.rule_id = "core.filesystem:rm-sensitive-path".to_owned();
        assert!(store.lookup_learned(&changed).unwrap().is_none());
        let mut changed = learned_fingerprint(&project);
        changed.cwd = project.with_file_name("other");
        assert!(store.lookup_learned(&changed).unwrap().is_none());
        let mut changed = learned_fingerprint(&project);
        changed.operands.push(project.join("different"));
        assert!(store.lookup_learned(&changed).unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn learned_approval_rechecks_operands_before_recording() {
        let (_temp, project, store) = fixture();
        let learned = learned_fingerprint(&project);
        fs::write(project.join("run.sh"), "changed during dialog").unwrap();
        assert!(store.approve_learned(&learned, "approved").is_err());
        assert!(store.list_learned().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn learned_prune_counts_stale_kinds_and_dry_run_preserves_store() {
        let (temp, project, store) = fixture();
        let trial = fingerprint(&store, &project);
        store.approve(&trial, "trial", "observed").unwrap();
        let learned = learned_fingerprint(&project);
        store.approve_learned(&learned, "approved").unwrap();
        assert_eq!(store.prune().unwrap(), 0);
        fs::remove_file(project.join("run.sh")).unwrap();
        let path = temp.path().join("trusted/verified_trials.json");
        let before = fs::read(&path).unwrap();
        assert_eq!(
            store
                .prune_counts_at(Some(&trial.project_root), true)
                .unwrap(),
            PrunedVersions {
                verified_trials: 1,
                learned_filesystem: 1,
            }
        );
        assert_eq!(fs::read(path).unwrap(), before);
        assert_eq!(
            store
                .prune_at(Some(&project.join("unrelated")), false)
                .unwrap(),
            0
        );
        assert_eq!(store.prune_at(Some(&trial.project_root), false).unwrap(), 2);
        assert!(store.list().unwrap().is_empty());
        assert!(store.list_learned().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn learned_entries_reject_non_review_sources_and_bound_summaries() {
        let (temp, project, store) = fixture();
        let learned = learned_fingerprint(&project);
        let approved = store
            .approve_learned(&learned, &"é".repeat(10_000))
            .unwrap();
        assert_eq!(approved.summary.len(), SUMMARY_LIMIT);
        let path = temp.path().join("trusted/verified_trials.json");
        let mut data: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        data["learned_filesystem"][0]["source"] = serde_json::json!("trial");
        fs::write(path, serde_json::to_vec(&data).unwrap()).unwrap();
        assert!(store.lookup_learned(&learned).unwrap().is_none());
        assert!(store.list_learned().unwrap().is_empty());
    }

    #[test]
    fn tracked_files_excludes_untracked_files_and_uses_directory_relative_paths() {
        let (_temp, project, _store) = fixture();
        assert!(tracked_files(&project).is_err());
        assert!(
            git(&project, &["init", "--quiet"])
                .unwrap()
                .status
                .success()
        );
        fs::create_dir(project.join("nested")).unwrap();
        fs::write(project.join("nested/tracked"), "tracked contents").unwrap();
        assert!(
            git(&project, &["add", "nested/tracked"])
                .unwrap()
                .status
                .success()
        );
        assert_eq!(
            tracked_files(&project).unwrap(),
            BTreeSet::from([PathBuf::from("nested/tracked")])
        );
        assert_eq!(
            tracked_files(&project.join("nested")).unwrap(),
            BTreeSet::from([PathBuf::from("tracked")])
        );
    }

    #[test]
    fn resolved_external_source_changes_invalidate() {
        let (temp, project, store) = fixture();
        let source = temp.path().join("interpreter");
        fs::write(&source, "version one").unwrap();
        let shell = temp.path().join("shell");
        let before = store
            .fingerprint("echo safe", &project, &shell, std::slice::from_ref(&source))
            .unwrap();
        fs::write(&source, "version two").unwrap();
        let after = store
            .fingerprint("echo safe", &project, &shell, &[source])
            .unwrap();
        assert_ne!(before.digest, after.digest);
    }

    #[test]
    fn summary_storage_is_bounded_and_cannot_escape_directory() {
        let (_temp, _project, store) = fixture();
        store
            .save_summary("trial-one", &"é".repeat(10_000))
            .unwrap();
        assert_eq!(
            store.show("trial-one").unwrap().unwrap().len(),
            SUMMARY_LIMIT
        );
        assert!(store.save_summary("../elsewhere", "bad").is_err());
        assert!(store.show("absent").unwrap().is_none());
    }

    #[test]
    fn corrupt_store_never_grants_approval() {
        let (temp, project, store) = fixture();
        let first = fingerprint(&store, &project);
        store.approve(&first, "trial", "safe").unwrap();
        fs::write(temp.path().join("trusted/verified_trials.json"), "not json").unwrap();
        assert!(store.lookup(&first).is_err());
    }

    #[test]
    fn invalid_approval_source_is_rejected() {
        let (_temp, project, store) = fixture();
        let first = fingerprint(&store, &project);
        assert!(store.approve(&first, "repository", "trust me").is_err());
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn shell_and_script_interpreter_contents_are_versioned() {
        let (temp, project, store) = fixture();
        let shell = temp.path().join("shell");
        let interpreter = temp.path().join("interpreter");
        fs::write(&interpreter, "interpreter version one").unwrap();
        fs::write(
            project.join("run.sh"),
            format!("#!{}\necho safe\n", interpreter.display()),
        )
        .unwrap();
        let first = store
            .fingerprint("./run.sh", &project, &shell, &[])
            .unwrap();
        fs::write(&interpreter, "interpreter version two").unwrap();
        let second = store
            .fingerprint("./run.sh", &project, &shell, &[])
            .unwrap();
        assert_ne!(first.digest, second.digest);
        fs::write(&shell, "shell version two").unwrap();
        let third = store
            .fingerprint("./run.sh", &project, &shell, &[])
            .unwrap();
        assert_ne!(second.digest, third.digest);
    }

    #[test]
    fn dry_run_prune_preserves_store_and_approval() {
        let (temp, project, store) = fixture();
        let first = fingerprint(&store, &project);
        store.approve(&first, "trial", "safe").unwrap();
        fs::write(project.join("run.sh"), "different version").unwrap();
        let path = temp.path().join("trusted/verified_trials.json");
        let before = fs::read(&path).unwrap();
        assert_eq!(store.prune_at(Some(&first.project_root), true).unwrap(), 1);
        assert_eq!(fs::read(path).unwrap(), before);
        assert_eq!(store.list().unwrap().len(), 1);
        assert_eq!(store.prune_at(Some(temp.path()), false).unwrap(), 0);
        assert_eq!(store.prune_at(Some(&first.project_root), false).unwrap(), 1);
    }

    #[test]
    fn warm_fingerprint_does_not_rewrite_hash_cache() {
        let (temp, project, store) = fixture();
        let first = fingerprint(&store, &project);
        let path = temp.path().join("trusted/verified_trials.json");
        let before = fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(first.digest, fingerprint(&store, &project).digest);
        assert_eq!(fs::metadata(path).unwrap().modified().unwrap(), before);
    }

    #[test]
    fn concurrent_approvals_do_not_lose_entries() {
        let (_temp, project, store) = fixture();
        let shell = project.with_file_name("shell");
        let fingerprints: Vec<_> = (0..8)
            .map(|index| {
                store
                    .fingerprint(&format!("echo {index}"), &project, &shell, &[])
                    .unwrap()
            })
            .collect();
        std::thread::scope(|scope| {
            for fingerprint in &fingerprints {
                let store = &store;
                scope.spawn(move || store.approve(fingerprint, "trial", "safe").unwrap());
            }
        });
        assert_eq!(store.list().unwrap().len(), fingerprints.len());
    }

    #[cfg(unix)]
    #[test]
    fn manifest_probe_timeout_is_bounded() {
        let temp = tempfile::tempdir().unwrap();
        let mut command = Command::new("/bin/sh");
        command
            .current_dir(temp.path())
            .args(["-c", "exec /bin/sleep 3"]);
        let started = Instant::now();
        let error = bounded_probe(&mut command, Duration::from_millis(30), 4096).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn manifest_probe_output_is_bounded() {
        let temp = tempfile::tempdir().unwrap();
        let mut command = Command::new("/bin/sh");
        command
            .current_dir(temp.path())
            .args(["-c", "printf 12345"]);
        let error = bounded_probe(&mut command, Duration::from_secs(2), 4).unwrap_err();
        assert!(error.to_string().contains("output limit"));
    }

    #[cfg(unix)]
    #[test]
    fn source_symlinks_fail_closed() {
        let (temp, project, store) = fixture();
        let outside = temp.path().join("outside");
        fs::write(&outside, "source").unwrap();
        std::os::unix::fs::symlink(outside, project.join("link")).unwrap();
        assert!(
            store
                .fingerprint("echo safe", &project, &temp.path().join("shell"), &[])
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn store_symlinks_are_not_followed() {
        let (temp, project, store) = fixture();
        let first = fingerprint(&store, &project);
        let outside = temp.path().join("outside-store");
        fs::write(&outside, "untouched").unwrap();
        fs::rename(
            temp.path().join("trusted/verified_trials.json"),
            temp.path().join("saved-store"),
        )
        .unwrap();
        std::os::unix::fs::symlink(&outside, temp.path().join("trusted/verified_trials.json"))
            .unwrap();
        assert!(store.approve(&first, "trial", "safe").is_err());
        assert_eq!(fs::read_to_string(outside).unwrap(), "untouched");
    }

    #[test]
    fn git_manifest_ignores_build_but_includes_explicit_sources() {
        let (_temp, project, store) = fixture();
        assert!(
            git(&project, &["init", "--quiet"])
                .unwrap()
                .status
                .success()
        );
        fs::write(project.join(".gitignore"), "build/\n").unwrap();
        fs::create_dir(project.join("build")).unwrap();
        let source = project.join("build/dependency");
        fs::write(&source, "one").unwrap();
        let first = fingerprint(&store, &project);
        fs::write(&source, "two").unwrap();
        assert_eq!(first.digest, fingerprint(&store, &project).digest);
        let explicit = store
            .fingerprint(
                "echo safe",
                &project,
                &first.shell,
                std::slice::from_ref(&source),
            )
            .unwrap();
        fs::write(&source, "new").unwrap();
        let updated = store
            .fingerprint("echo safe", &project, &first.shell, &[source])
            .unwrap();
        assert_ne!(explicit.digest, updated.digest);
    }
}
