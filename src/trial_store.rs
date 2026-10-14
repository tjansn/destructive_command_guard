//! Exact-version sandbox and filesystem approvals beside the trusted user allowlist.
//!
//! No project file can grant an approval. In the absence of reliable unprivileged
//! read tracing, fingerprints cover the complete non-ignored source manifest,
//! explicitly resolved sources, and executable contents. Metadata only caches
//! content hashes; touching a file does not alter its fingerprint.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
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
const MAX_RUNTIME_FILES: usize = 8192;
const MAX_RUNTIME_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const PUBLIC_RUNTIME_CONFIGS: [&str; 3] = [
    "/private/etc/ssl/openssl.cnf",
    "/opt/homebrew/etc/openssl@3/openssl.cnf",
    "/usr/local/etc/openssl@3/openssl.cnf",
];

/// Inputs and content digest of one exact command version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    pub digest: String,
    pub project_root: PathBuf,
    pub cwd: PathBuf,
    pub command: String,
    pub shell: PathBuf,
    pub resolved_sources: Vec<PathBuf>,
    pub resolved_executables: Vec<PathBuf>,
    /// False means isolation changed or could not bind a runtime input. Such
    /// requests may be reviewed once, but cannot reuse or create a grant.
    pub reproducible: bool,
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

/// What a Touch ID script approval binds.
///
/// One command in one project directory, the content of every script static
/// inspection resolved for it, the executables it resolves to and the inherited
/// preload variables. Other project files are deliberately not part of it
/// (Tom, 2026-10-14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptVersion {
    pub digest: String,
    pub project_root: PathBuf,
    pub cwd: PathBuf,
    pub command: String,
    pub scripts: Vec<PathBuf>,
    pub executables: Vec<PathBuf>,
}

/// A Touch ID approval that stays valid until one of its scripts changes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovedScripts {
    pub kind: String,
    pub fingerprint: String,
    pub project_root: PathBuf,
    pub cwd: PathBuf,
    pub command: String,
    pub scripts: Vec<PathBuf>,
    pub created_at: String,
    pub source: String,
    pub summary: String,
}

/// Separate counts keep CLI reports clear about the approval kinds.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PrunedVersions {
    pub verified_trials: usize,
    pub learned_filesystem: usize,
    pub approved_scripts: usize,
}

impl PrunedVersions {
    #[must_use]
    pub const fn total(self) -> usize {
        self.verified_trials + self.learned_filesystem + self.approved_scripts
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
    approved_scripts: Vec<ApprovedScripts>,
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
            approved_scripts: Vec::new(),
            file_hashes: BTreeMap::new(),
            summaries: Vec::new(),
        }
    }
}

/// The directory must be selected by trusted configuration, never by a project.
#[derive(Debug, Clone)]
pub struct TrialStore {
    directory: PathBuf,
    /// What fingerprinted commands inherit; see [`crate::trial::agent_environment`].
    environment: BTreeMap<OsString, OsString>,
}

impl TrialStore {
    #[must_use]
    pub fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            environment: crate::trial::agent_environment(),
        }
    }

    /// Bind versions against an explicit inherited environment instead of
    /// dcg's own, e.g. the hermetic environment of a spawned dcg process.
    #[must_use]
    pub fn with_environment(mut self, environment: BTreeMap<OsString, OsString>) -> Self {
        self.environment = environment;
        self
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

    /// Bind a one-time review without reading or writing the approval store.
    pub fn fingerprint_for_review(
        &self,
        command: &str,
        cwd: &Path,
        shell: &Path,
        resolved_sources: &[PathBuf],
    ) -> io::Result<Fingerprint> {
        self.fingerprint_inner(command, cwd, shell, resolved_sources, false)
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
        let parent_environment = &self.environment;
        let search_path = parent_environment
            .get(OsStr::new("PATH"))
            .cloned()
            .unwrap_or_default();
        let (resolved, local_environment) =
            resolved_executables(command, &cwd, parent_environment)?;
        let reviewed_executables = resolved.iter().cloned().collect();
        let mut executables = BTreeSet::new();
        executables.insert(shell.clone());
        executables.extend(sources.iter().cloned());
        resolve_interpreters(&mut executables, &cwd, &search_path)?;
        executables.extend(resolved);
        let (environment_digest, environment_reproduced) = runtime_environment(parent_environment);
        let mut runtime = ignored_runtime_inputs(&project_root);
        let startup = shell_startup_inputs(&shell, parent_environment);
        let public_config = existing_runtime_inputs(PUBLIC_RUNTIME_CONFIGS.map(PathBuf::from));
        // Overrides are bound, but are not the sanitized trial environment.
        let mut reproducible = !local_environment
            && environment_reproduced
            && runtime.complete
            && startup.files.is_empty()
            && startup.complete
            && public_config.complete;
        runtime.files.extend(startup.files);
        runtime.files.extend(public_config.files);
        let calculate = |data: &mut StoreData| {
            let mut hasher = Sha256::new();
            hash_field(&mut hasher, b"dcg-verified-trial-v2");
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
            hash_field(&mut hasher, environment_digest.as_bytes());
            hash_field(&mut hasher, search_path.as_encoded_bytes());
            let mut dirty = false;
            let mut runtime_bytes = 0_u64;
            for (index, path) in runtime.files.iter().enumerate() {
                hash_field(&mut hasher, b"ignored-runtime-or-startup-input");
                hash_field(&mut hasher, path.as_os_str().as_encoded_bytes());
                let metadata = fs::symlink_metadata(path);
                if index >= MAX_RUNTIME_FILES {
                    reproducible = false;
                    break;
                }
                let Ok(metadata) = metadata else {
                    reproducible = false;
                    continue;
                };
                runtime_bytes = runtime_bytes.saturating_add(metadata.len());
                if !metadata.is_file() || runtime_bytes > MAX_RUNTIME_BYTES {
                    reproducible = false;
                    continue;
                }
                match cached_hash_bounded(path, &mut data.file_hashes, metadata.len()) {
                    Ok((digest, changed)) => {
                        dirty |= changed;
                        hash_field(&mut hasher, digest.as_bytes());
                        if hash_permissions(&mut hasher, path).is_err() {
                            reproducible = false;
                        }
                    }
                    Err(_) => reproducible = false,
                }
            }
            hash_field(&mut hasher, &[u8::from(reproducible)]);
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
                    resolved_executables: reviewed_executables,
                    reproducible,
                },
                dirty && persist_cache,
            ))
        };
        if persist_cache {
            self.with_data(calculate)
        } else {
            calculate(&mut StoreData::default()).map(|(fingerprint, _)| fingerprint)
        }
    }

    pub fn lookup(&self, current_version: &Fingerprint) -> io::Result<Option<VerifiedTrial>> {
        if !current_version.reproducible {
            return Ok(None);
        }
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
        if !fingerprint.reproducible {
            return Err(io::Error::other(
                "runtime inputs were not reproduced; one-request review is required",
            ));
        }
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
            &self.environment,
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

    /// Bind `command` in `cwd` to the scripts static inspection resolved for
    /// it. Every script must exist as a regular file: an input that is missing
    /// at review time cannot pass its approval to a file created later.
    pub fn script_version(
        &self,
        command: &str,
        cwd: &Path,
        scripts: &[PathBuf],
    ) -> io::Result<ScriptVersion> {
        let cwd = cwd.canonicalize()?;
        let project_root = project_root(&cwd)?;
        let mut paths = BTreeSet::new();
        for script in scripts {
            let path = cwd.join(script).canonicalize()?;
            if !fs::metadata(&path)?.is_file() {
                return Err(io::Error::other("reviewed script is not a regular file"));
            }
            paths.insert(path);
        }
        if paths.is_empty() {
            return Err(io::Error::other("no reviewed script to bind"));
        }
        let (executables, _) = resolved_executables(command, &cwd, &self.environment)?;
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, b"dcg-approved-scripts-v1");
        hash_field(&mut hasher, path_text(&project_root)?.as_bytes());
        hash_field(
            &mut hasher,
            path_text(cwd.strip_prefix(&project_root).map_err(io::Error::other)?)?.as_bytes(),
        );
        hash_field(&mut hasher, command.as_bytes());
        for path in &paths {
            hash_field(&mut hasher, b"script");
            hash_field(&mut hasher, path_text(path)?.as_bytes());
            hash_field(&mut hasher, script_digest(path)?.as_bytes());
            hash_permissions(&mut hasher, path)?;
        }
        for path in &executables {
            hash_field(&mut hasher, b"executable");
            hash_field(&mut hasher, path_text(path)?.as_bytes());
            // A program inside the project is one of its scripts too.
            if path.starts_with(&project_root) {
                hash_field(&mut hasher, script_digest(path)?.as_bytes());
            }
        }
        for (name, value) in &self.environment {
            if name
                .to_str()
                .is_none_or(crate::invocation::preload_variable)
            {
                hash_field(&mut hasher, name.as_encoded_bytes());
                hash_field(&mut hasher, value.as_encoded_bytes());
            }
        }
        Ok(ScriptVersion {
            digest: hex_digest(&hasher.finalize()),
            project_root,
            cwd,
            command: command.to_owned(),
            scripts: paths.into_iter().collect(),
            executables: executables.into_iter().collect(),
        })
    }

    pub fn lookup_scripts(&self, current: &ScriptVersion) -> io::Result<Option<ApprovedScripts>> {
        self.with_data(|data| {
            Ok((
                data.approved_scripts
                    .iter()
                    .find(|entry| {
                        valid_scripts_entry(entry)
                            && entry.fingerprint == current.digest
                            && entry.project_root == current.project_root
                            && entry.cwd == current.cwd
                            && entry.command == current.command
                            && entry.scripts == current.scripts
                    })
                    .cloned(),
                false,
            ))
        })
    }

    /// Only desktop review may create a script approval. The scripts are
    /// fingerprinted again at the write boundary; a change since the review
    /// rejects the approval instead of remembering unreviewed content.
    pub fn approve_scripts(
        &self,
        version: &ScriptVersion,
        summary: &str,
    ) -> io::Result<ApprovedScripts> {
        let current = self.script_version(&version.command, &version.cwd, &version.scripts)?;
        if current != *version {
            return Err(io::Error::other("scripts changed during review"));
        }
        let entry = ApprovedScripts {
            kind: "approved_scripts".to_owned(),
            fingerprint: version.digest.clone(),
            project_root: version.project_root.clone(),
            cwd: version.cwd.clone(),
            command: version.command.clone(),
            scripts: version.scripts.clone(),
            created_at: chrono::Utc::now().to_rfc3339(),
            source: "user-review".to_owned(),
            summary: bounded_summary(summary),
        };
        if !valid_scripts_entry(&entry) {
            return Err(io::Error::other("invalid script approval"));
        }
        self.with_data(|data| {
            data.approved_scripts
                .retain(|old| old.fingerprint != entry.fingerprint);
            data.approved_scripts.push(entry.clone());
            Ok((entry, true))
        })
    }

    pub fn list_scripts(&self) -> io::Result<Vec<ApprovedScripts>> {
        self.with_data(|data| {
            Ok((
                data.approved_scripts
                    .iter()
                    .filter(|entry| valid_scripts_entry(entry))
                    .cloned()
                    .collect(),
                false,
            ))
        })
    }

    pub fn remove(&self, id: &str) -> io::Result<bool> {
        let id = id.strip_prefix("sha256:").unwrap_or(id);
        self.with_data(|data| {
            let count = |data: &StoreData| {
                data.verified_trials.len()
                    + data.learned_filesystem.len()
                    + data.approved_scripts.len()
            };
            let before = count(data);
            data.verified_trials.retain(|entry| entry.fingerprint != id);
            data.learned_filesystem
                .retain(|entry| entry.fingerprint != id);
            data.approved_scripts
                .retain(|entry| entry.fingerprint != id);
            let removed = count(data) != before;
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
            if !current.is_ok_and(|value| value.reproducible && value.digest == entry.fingerprint) {
                stale.insert(entry.fingerprint);
            }
        }
        let mut stale_learned = BTreeSet::new();
        for entry in self.list_learned()? {
            if project.is_some_and(|project| !entry.cwd.starts_with(project)) {
                continue;
            }
            let current = crate::effects::fingerprint(
                &entry.command,
                &entry.cwd,
                &entry.rule_id,
                &self.environment,
            );
            if !current.is_ok_and(|value| value.digest == entry.fingerprint) {
                stale_learned.insert(entry.fingerprint);
            }
        }
        let mut stale_scripts = BTreeSet::new();
        for entry in self.list_scripts()? {
            if project.is_some_and(|project| project != entry.project_root) {
                continue;
            }
            let current = self.script_version(&entry.command, &entry.cwd, &entry.scripts);
            if !current.is_ok_and(|value| value.digest == entry.fingerprint) {
                stale_scripts.insert(entry.fingerprint);
            }
        }
        self.with_data(|data| {
            if dry_run {
                return Ok((
                    PrunedVersions {
                        verified_trials: stale.len(),
                        learned_filesystem: stale_learned.len(),
                        approved_scripts: stale_scripts.len(),
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
            let scripts_before = data.approved_scripts.len();
            data.approved_scripts
                .retain(|entry| !stale_scripts.contains(&entry.fingerprint));
            let removed = PrunedVersions {
                verified_trials: before - data.verified_trials.len(),
                learned_filesystem: learned_before - data.learned_filesystem.len(),
                approved_scripts: scripts_before - data.approved_scripts.len(),
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

fn valid_scripts_entry(entry: &ApprovedScripts) -> bool {
    entry.kind == "approved_scripts"
        && entry.source == "user-review"
        && entry.fingerprint.len() == 64
        && entry
            .fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        && entry.project_root.is_absolute()
        && entry.cwd.starts_with(&entry.project_root)
        && !entry.command.is_empty()
        && !entry.scripts.is_empty()
        && entry.scripts.iter().all(|path| path.is_absolute())
}

/// Reviewed scripts are hashed in full; an oversized one cannot be bound.
fn script_digest(path: &Path) -> io::Result<String> {
    cached_hash_bounded(path, &mut BTreeMap::new(), MAX_RUNTIME_BYTES).map(|(digest, _)| digest)
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

/// Values are hashed only. Neither the digest preimage nor rejected variable
/// names are written to summaries, errors, or serialized approval records.
fn runtime_environment(parent: &BTreeMap<OsString, OsString>) -> (String, bool) {
    let trial = crate::trial::trial_environment(
        parent
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
        Path::new("/dcg-trial-home"),
        Path::new("/dcg-trial-tmp"),
    );
    let mut hash = Sha256::new();
    let mut reproduced = true;
    for (key, value) in parent {
        hash_field(&mut hash, key.as_encoded_bytes());
        hash_field(&mut hash, value.as_encoded_bytes());
        let relocated_or_control = key.to_str().is_some_and(|name| {
            name.starts_with("DCG_")
                || matches!(
                    name,
                    "HOME"
                        | "USERPROFILE"
                        | "TMPDIR"
                        | "TMP"
                        | "TEMP"
                        | "PWD"
                        | "OLDPWD"
                        | "SHLVL"
                        | "_"
                        | "XDG_CONFIG_HOME"
                        | "XDG_DATA_HOME"
                        | "XDG_CACHE_HOME"
                        | "XDG_STATE_HOME"
                        | "CARGO_HOME"
                        | "RUSTUP_HOME"
                )
        });
        if key == OsStr::new("CFFIXED_USER_HOME")
            || (!relocated_or_control && trial.get(key) != Some(value))
        {
            reproduced = false;
        }
    }
    (hex_digest(&hash.finalize()), reproduced)
}

struct RuntimeInputs {
    files: BTreeSet<PathBuf>,
    complete: bool,
}

fn existing_runtime_inputs(paths: impl IntoIterator<Item = PathBuf>) -> RuntimeInputs {
    let mut inputs = RuntimeInputs {
        files: BTreeSet::new(),
        complete: true,
    };
    for path in paths {
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                inputs.files.insert(path);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => inputs.complete = false,
        }
    }
    inputs
}

/// A lockfile cannot stand in for installed bytes. Hash the ignored dependency
/// files themselves, including native modules and package-local data, up to the
/// explicit byte/file budget. Oversize installations stay review-only.
fn ignored_runtime_inputs(root: &Path) -> RuntimeInputs {
    let mut inputs = RuntimeInputs {
        files: BTreeSet::new(),
        complete: true,
    };
    let output = match optional_git(
        root,
        &[
            "ls-files",
            "--others",
            "--ignored",
            "--exclude-standard",
            "-z",
        ],
    ) {
        Ok(Some(output)) => output,
        Ok(None) => {
            // Non-Git manifests already include every file. A broken repository
            // query must not silently omit inputs from a previously valid repo.
            inputs.complete = !root.join(".git").exists();
            return inputs;
        }
        Err(_) => {
            inputs.complete = false;
            return inputs;
        }
    };
    for raw in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|raw| !raw.is_empty())
    {
        let Ok(text) = std::str::from_utf8(raw) else {
            inputs.complete = false;
            continue;
        };
        let relative = Path::new(text);
        if relative.is_absolute()
            || relative
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            inputs.complete = false;
            continue;
        }
        let path = root.join(relative);
        if runtime_path(relative) || is_executable_file(&path) {
            inputs.files.insert(path);
            if inputs.files.len() > MAX_RUNTIME_FILES {
                inputs.complete = false;
                break;
            }
        }
    }
    inputs
}

fn runtime_path(path: &Path) -> bool {
    if path.components().any(|part| {
        matches!(
            part.as_os_str().to_str(),
            Some("node_modules" | ".venv" | "venv" | "site-packages" | "vendor")
        )
    }) {
        return true;
    }
    let name = path.file_name().and_then(OsStr::to_str).unwrap_or_default();
    name == ".env"
        || name.starts_with(".env.")
        || name.contains("config")
        || matches!(
            name,
            ".npmrc"
                | ".yarnrc"
                | ".nvmrc"
                | ".node-version"
                | ".python-version"
                | ".ruby-version"
                | "Gemfile"
                | "package-lock.json"
                | ".package-lock.json"
                | "npm-shrinkwrap.json"
                | "yarn.lock"
                | "pnpm-lock.yaml"
                | "bun.lock"
                | "bun.lockb"
                | "Cargo.lock"
                | "Gemfile.lock"
                | "poetry.lock"
                | "uv.lock"
                | "Pipfile.lock"
                | "composer.lock"
                | "go.sum"
                | "requirements.txt"
        )
        || matches!(
            path.extension().and_then(OsStr::to_str),
            Some(
                "js" | "cjs"
                    | "mjs"
                    | "ts"
                    | "tsx"
                    | "jsx"
                    | "py"
                    | "pyc"
                    | "rb"
                    | "php"
                    | "sh"
                    | "bash"
                    | "zsh"
                    | "pl"
                    | "lua"
                    | "node"
                    | "wasm"
                    | "json"
                    | "toml"
                    | "yaml"
                    | "yml"
                    | "ini"
                    | "cfg"
                    | "conf"
            )
        )
}

fn is_executable_file(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::symlink_metadata(path)
            .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        matches!(
            path.extension().and_then(OsStr::to_str),
            Some("exe" | "cmd" | "bat" | "ps1")
        )
    }
}

fn shell_startup_inputs(shell: &Path, environment: &BTreeMap<OsString, OsString>) -> RuntimeInputs {
    let mut inputs = RuntimeInputs {
        files: BTreeSet::new(),
        complete: true,
    };
    let names: &[&str] = match shell.file_name().and_then(OsStr::to_str) {
        Some("zsh") => &[".zshenv", ".zprofile", ".zshrc", ".zlogin"],
        Some("bash") => &[".bash_profile", ".bash_login", ".bashrc", ".profile"],
        Some("sh" | "dash" | "ksh") => &[".profile"],
        _ => &[],
    };
    if names.is_empty() {
        return inputs;
    }
    let Some(home) = environment
        .get(OsStr::new("HOME"))
        .or_else(|| environment.get(OsStr::new("USERPROFILE")))
    else {
        inputs.complete = false;
        return inputs;
    };
    existing_runtime_inputs(names.iter().map(|name| Path::new(home).join(name)))
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
    cached_hash_bounded(path, cache, u64::MAX)
}

fn cached_hash_bounded(
    path: &Path,
    cache: &mut BTreeMap<String, CachedHash>,
    byte_limit: u64,
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
    if metadata.len() > byte_limit {
        return Err(io::Error::other("runtime content hash limit exceeded"));
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
    let mut input = (&mut file).take(metadata.len().saturating_add(1));
    let mut total = 0_u64;
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        hash.update(&buffer[..count]);
    }
    if total != metadata.len()
        || file_state(&file.metadata()?)? != state
        || file_state(&fs::symlink_metadata(path)?)? != state
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

fn resolved_executables(
    command: &str,
    cwd: &Path,
    parent: &BTreeMap<OsString, OsString>,
) -> io::Result<(BTreeSet<PathBuf>, bool)> {
    let ast = AstGrep::new(command, SupportLang::Bash);
    let mut pending = vec![ast.root()];
    let mut result = BTreeSet::new();
    let parent_path = parent.get(OsStr::new("PATH")).cloned().unwrap_or_default();
    let mut local_environment = false;
    while let Some(node) = pending.pop() {
        pending.extend(node.children());
        if node.kind().as_ref() == "variable_assignment"
            && node
                .parent()
                .is_none_or(|parent| parent.kind().as_ref() != "command")
            && node.text().split_once('=').is_some_and(|(name, _)| {
                name == "PATH" || crate::invocation::preload_variable(name)
            })
        {
            return Err(io::Error::other(
                "standalone execution environment changes cannot be bound for review",
            ));
        }
        if node.kind().as_ref() == "command" {
            let text = node.text();
            let words = shell_words::split(&text).map_err(io::Error::other)?;
            let bound =
                crate::invocation::bound_environment(&text, parent).map_err(io::Error::other)?;
            if let Some(bound) = &bound {
                bound.ensure_reviewable().map_err(io::Error::other)?;
            }
            if bound.is_none() && words.iter().any(|word| word.starts_with("PATH=")) {
                return Err(io::Error::other(
                    "PATH assignment inside an unsupported wrapper cannot be bound; use a direct literal environment invocation",
                ));
            }
            local_environment |= bound.is_some();
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
            if let Some(bound) = bound {
                if let Some((wrapper, path)) = bound.wrapper {
                    let mut files =
                        BTreeSet::from([resolve_executable(&wrapper, &effective, &path)?]);
                    resolve_interpreters(&mut files, &effective, &path)?;
                    result.extend(files);
                }
                let path = bound
                    .values
                    .get(OsStr::new("PATH"))
                    .cloned()
                    .unwrap_or_default();
                let mut files =
                    BTreeSet::from([resolve_executable(&bound.program, &effective, &path)?]);
                resolve_interpreters(&mut files, &effective, &path)?;
                result.extend(files);
                continue;
            }
            let path = resolve_executable(first, &effective, &parent_path)?;
            let mut files = BTreeSet::from([path]);
            let stripped = crate::normalize::strip_wrapper_prefixes(&text);
            let inner = shell_words::split(&stripped.normalized).map_err(io::Error::other)?;
            if let Some(executable) = inner.first()
                && executable != first
            {
                files.insert(resolve_executable(executable, &effective, &parent_path)?);
            }
            resolve_interpreters(&mut files, &effective, &parent_path)?;
            result.extend(files);
        }
    }
    Ok((result, local_environment))
}

pub(crate) fn resolve_executable(name: &str, cwd: &Path, path: &OsStr) -> io::Result<PathBuf> {
    if name.contains('/') || name.contains('\\') {
        return cwd.join(name).canonicalize();
    }
    for directory in std::env::split_paths(path) {
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

fn resolve_interpreters(
    paths: &mut BTreeSet<PathBuf>,
    cwd: &Path,
    search_path: &OsStr,
) -> io::Result<()> {
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
        let interpreter = resolve_executable(interpreter, cwd, search_path)?;
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
            let executable = resolve_executable(command, cwd, search_path)?;
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

    #[cfg(unix)]
    #[test]
    fn literal_environment_review_binds_values_and_local_path_executable_bytes() {
        use std::os::unix::fs::PermissionsExt;
        let (temp, project, store) = fixture();
        let bin = temp.path().join("bin");
        fs::create_dir(&bin).unwrap();
        let executable = bin.join("cargo");
        fs::write(&executable, "fixture executable one").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let command = format!(
            "/usr/bin/env -i HOME=/tmp/fixture PATH={} cargo test",
            shell_words::quote(bin.to_str().unwrap())
        );
        let capture = |text: &str| {
            store
                .fingerprint(text, &project, &temp.path().join("shell"), &[])
                .unwrap()
        };
        let first = capture(&command);
        assert!(!first.reproducible);
        assert_eq!(
            crate::desktop_review::ApprovalScope::trial(true, first.reproducible),
            crate::desktop_review::ApprovalScope::OneTime
        );
        assert!(
            store
                .approve(&first, "user-review", "one-time review")
                .is_err()
        );
        assert!(store.list().unwrap().is_empty());
        assert_ne!(
            first.digest,
            capture(&command.replace("HOME=/tmp/fixture", "HOME=/tmp/changed")).digest
        );
        fs::write(&executable, "fixture executable two").unwrap();
        assert_ne!(first.digest, capture(&command).digest);
        let (files, bound) = resolved_executables(&command, &project, &BTreeMap::new()).unwrap();
        assert!(bound && files.contains(&executable.canonicalize().unwrap()));
    }

    #[test]
    fn literal_environment_cannot_review_inherited_preloads_or_expansions() {
        let (_temp, project, _) = fixture();
        for name in [
            "DYLD_INSERT_LIBRARIES",
            "LD_PRELOAD",
            "BASH_ENV",
            "NODE_OPTIONS",
            "PYTHONPATH",
        ] {
            let parent = BTreeMap::from([(name.into(), "fixture-only-value".into())]);
            let error =
                resolved_executables("/usr/bin/env -i HOME=/tmp /bin/true", &project, &parent)
                    .unwrap_err();
            assert!(
                error.to_string().contains("inherited preload"),
                "{name}: {error}"
            );
        }
        for command in [
            "PATH=$PATH cargo test",
            "env -i PATH=$(pwd) cargo test",
            "timeout 10 env PATH=/unresolved cargo test",
            "PATH=/bin; cargo test",
            "NODE_OPTIONS=--require=./startup.js; node check.js",
            "/usr/bin/env -i /usr/bin/env NODE_OPTIONS=--require=./startup.js node check.js",
        ] {
            assert!(resolved_executables(command, &project, &BTreeMap::new()).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn local_preloads_keep_trial_resolution_and_bind_their_raw_values() {
        use std::os::unix::fs::PermissionsExt;
        let (temp, project, store) = fixture();
        let executable = project.join("fixture-program");
        fs::write(&executable, "fixture executable").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let program = shell_words::quote(executable.to_str().unwrap());
        for path in ["/usr/bin:/bin", "", ".:/usr/bin", ":/usr/bin"] {
            let parent = BTreeMap::from([(OsString::from("PATH"), OsString::from(path))]);
            for prefix in [
                "CI=1",
                "FOO=$BAR",
                "PYTHONPATH=src",
                "PYTHONPATH=$SOURCE",
                "NODE_OPTIONS=--max-old-space-size=4096",
                "LD_PRELOAD=./preload.so",
                "BASH_ENV=./startup.sh",
                "/usr/bin/env PYTHONPATH=src",
            ] {
                let command = format!("{prefix} {program}");
                let (files, bound) = resolved_executables(&command, &project, &parent).unwrap();
                assert!(!bound, "{command} must remain eligible for a trial");
                assert!(files.contains(&executable.canonicalize().unwrap()));
            }
        }
        let capture = |prefix: &str| {
            store
                .fingerprint(
                    &format!("{prefix} {program}"),
                    &project,
                    &temp.path().join("shell"),
                    &[],
                )
                .unwrap()
        };
        let first = capture("PYTHONPATH=src");
        let changed = capture("PYTHONPATH=other");
        assert_ne!(first.digest, changed.digest);
        assert_eq!(first.reproducible, capture("CI=1").reproducible);
    }

    #[test]
    fn one_time_fingerprint_ignores_existing_grants_and_never_touches_the_store() {
        let (temp, project, store) = fixture();
        let mut version = fingerprint(&store, &project);
        // The fixture grant models an existing approval even when this test
        // process has extra environment inputs that cannot be reproduced.
        version.reproducible = true;
        store
            .approve(&version, "user-review", "existing exact approval")
            .unwrap();
        assert!(store.lookup(&version).unwrap().is_some());
        let path = temp.path().join("trusted/verified_trials.json");
        let saved = fs::read(&path).unwrap();
        let shell = temp.path().join("shell");
        let reviewed = store
            .fingerprint_for_review("echo safe", &project, &shell, &[])
            .unwrap();
        assert_eq!(reviewed.digest, version.digest);
        assert_eq!(
            crate::desktop_review::ApprovalScope::trial(false, reviewed.reproducible),
            crate::desktop_review::ApprovalScope::OneTime
        );
        assert_eq!(fs::read(&path).unwrap(), saved);
        // Even unavailable/corrupt state must not prevent a one-time review.
        fs::write(&path, "invalid fixture store").unwrap();
        assert_eq!(
            store
                .fingerprint_for_review("echo safe", &project, &shell, &[])
                .unwrap(),
            reviewed
        );
        let absent = temp.path().join("absent-store");
        let transient = TrialStore::new(absent.clone());
        assert_eq!(
            transient
                .fingerprint_for_review("echo safe", &project, &shell, &[])
                .unwrap(),
            reviewed
        );
        assert!(!absent.exists());
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
            &crate::trial::agent_environment(),
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
        let scripts = store
            .script_version("sh run.sh", &project, &[project.join("run.sh")])
            .unwrap();
        store.approve_scripts(&scripts, "approved").unwrap();
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
                approved_scripts: 1,
            }
        );
        assert_eq!(fs::read(path).unwrap(), before);
        assert_eq!(
            store
                .prune_at(Some(&project.join("unrelated")), false)
                .unwrap(),
            0
        );
        assert_eq!(store.prune_at(Some(&trial.project_root), false).unwrap(), 3);
        assert!(store.list().unwrap().is_empty());
        assert!(store.list_learned().unwrap().is_empty());
        assert!(store.list_scripts().unwrap().is_empty());
    }

    /// Tom's rule (2026-10-14): a Touch ID approval holds until one of the
    /// reviewed scripts changes; other project files do not invalidate it.
    #[cfg(unix)]
    #[test]
    fn script_approval_survives_other_edits_and_ends_when_a_script_changes() {
        use std::os::unix::fs::PermissionsExt;
        let (_temp, project, store) = fixture();
        fs::write(project.join("helper.sh"), "echo helper\n").unwrap();
        fs::write(project.join("notes.txt"), "draft").unwrap();
        let scripts = [project.join("run.sh"), project.join("helper.sh")];
        let version = || store.script_version("sh run.sh", &project, &scripts);
        let approved = version().unwrap();
        assert!(store.lookup_scripts(&approved).unwrap().is_none());
        let entry = store.approve_scripts(&approved, "Touch ID").unwrap();
        assert_eq!(entry.source, "user-review");
        assert_eq!(store.list_scripts().unwrap(), vec![entry.clone()]);

        // Unrelated project edits, new files and a reordered input list keep it.
        fs::write(project.join("notes.txt"), "rewritten").unwrap();
        fs::write(project.join("new.txt"), "added").unwrap();
        assert_eq!(
            store.lookup_scripts(&version().unwrap()).unwrap(),
            Some(entry.clone())
        );
        let reordered = store
            .script_version(
                "sh run.sh",
                &project,
                &[scripts[1].clone(), scripts[0].clone()],
            )
            .unwrap();
        assert_eq!(reordered, approved);

        // Another command, another directory or one script fewer is not covered.
        let other = store
            .script_version("sh run.sh --force", &project, &scripts)
            .unwrap();
        assert!(store.lookup_scripts(&other).unwrap().is_none());
        fs::create_dir(project.join("sub")).unwrap();
        let elsewhere = store
            .script_version("sh run.sh", &project.join("sub"), &scripts)
            .unwrap();
        assert!(store.lookup_scripts(&elsewhere).unwrap().is_none());
        let fewer = store
            .script_version("sh run.sh", &project, &scripts[..1])
            .unwrap();
        assert!(store.lookup_scripts(&fewer).unwrap().is_none());

        // Content and permission changes of any reviewed script end it.
        fs::write(project.join("helper.sh"), "rm -rf build\n").unwrap();
        assert!(store.lookup_scripts(&version().unwrap()).unwrap().is_none());
        fs::write(project.join("helper.sh"), "echo helper\n").unwrap();
        assert!(store.lookup_scripts(&version().unwrap()).unwrap().is_some());
        fs::set_permissions(project.join("run.sh"), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(store.lookup_scripts(&version().unwrap()).unwrap().is_none());

        // A missing input cannot be bound, so it cannot inherit an approval.
        assert!(
            store
                .script_version("sh run.sh", &project, &[project.join("absent.sh")])
                .is_err()
        );
        assert!(store.script_version("sh run.sh", &project, &[]).is_err());
        assert!(store.remove(&entry.fingerprint).unwrap());
        assert!(store.list_scripts().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn script_approval_binds_preload_variables_and_rejects_changes_during_review() {
        let (_temp, project, store) = fixture();
        let scripts = [project.join("run.sh")];
        let approved = store
            .script_version("sh run.sh", &project, &scripts)
            .unwrap();
        let preloaded = store
            .clone()
            .with_environment(
                crate::trial::agent_environment()
                    .into_iter()
                    .chain([("NODE_OPTIONS".into(), "--require ./hook.js".into())])
                    .collect(),
            )
            .script_version("sh run.sh", &project, &scripts)
            .unwrap();
        assert_ne!(preloaded.digest, approved.digest);
        let ordinary = store
            .clone()
            .with_environment(
                crate::trial::agent_environment()
                    .into_iter()
                    .chain([("EDITOR".into(), "vim".into())])
                    .collect(),
            )
            .script_version("sh run.sh", &project, &scripts)
            .unwrap();
        assert_eq!(ordinary.digest, approved.digest);
        fs::write(
            project.join("run.sh"),
            "echo changed while the dialog was open\n",
        )
        .unwrap();
        assert!(store.approve_scripts(&approved, "Touch ID").is_err());
        assert!(store.list_scripts().unwrap().is_empty());
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
    fn runtime_environment_binds_values_without_forwarding_or_logging_them() {
        let base = BTreeMap::from([
            (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
            (OsString::from("HOME"), OsString::from("/isolated/home")),
            (OsString::from("TMPDIR"), OsString::from("/isolated/tmp")),
            (OsString::from("DCG_SELF_HEAL_HOOK"), OsString::from("0")),
        ]);
        let first = runtime_environment(&base);
        assert!(first.1);
        for name in [
            "NODE_OPTIONS",
            "DATA_DIR",
            "SOME_APPLICATION_SWITCH",
            "API_TOKEN",
            "CFFIXED_USER_HOME",
        ] {
            let mut changed = base.clone();
            changed.insert(name.into(), "private-value-one".into());
            let one = runtime_environment(&changed);
            assert!(!one.1, "{name}");
            assert_ne!(first.0, one.0);
            assert!(!one.0.contains("private-value"));
            changed.insert(name.into(), "private-value-two".into());
            assert_ne!(one.0, runtime_environment(&changed).0);
        }
        let mut changed = base;
        changed.insert("CFFIXED_USER_HOME".into(), "/dcg-trial-home".into());
        assert!(!runtime_environment(&changed).1);
        changed.remove(OsStr::new("CFFIXED_USER_HOME"));
        changed.insert("LANG".into(), "en_US.UTF-8".into());
        assert!(runtime_environment(&changed).1);
        assert_ne!(first.0, runtime_environment(&changed).0);
    }

    #[test]
    fn ignored_runtime_contents_and_lockfiles_invalidate_versions() {
        let (_temp, project, store) = fixture();
        assert!(
            git(&project, &["init", "--quiet"])
                .unwrap()
                .status
                .success()
        );
        fs::write(
            project.join(".gitignore"),
            "node_modules/\n.env\nignored/\npackage-lock.json\n",
        )
        .unwrap();
        fs::create_dir_all(project.join("node_modules/dependency")).unwrap();
        fs::create_dir(project.join("ignored")).unwrap();
        for (path, contents) in [
            ("node_modules/.package-lock.json", "installed version one"),
            (
                "node_modules/dependency/index.js",
                "export const value = 1;",
            ),
            ("package-lock.json", "locked version one"),
            (".env", "DATA_DIR=one"),
            ("ignored/config.json", "{\"value\":1}"),
            ("ignored/helper.py", "print('one')"),
        ] {
            fs::write(project.join(path), contents).unwrap();
        }
        let mut previous = fingerprint(&store, &project);
        for path in [
            "node_modules/dependency/index.js",
            "node_modules/.package-lock.json",
            "package-lock.json",
            ".env",
            "ignored/config.json",
            "ignored/helper.py",
        ] {
            fs::write(project.join(path), "different runtime bytes").unwrap();
            let changed = fingerprint(&store, &project);
            assert_ne!(previous.digest, changed.digest, "{path}");
            previous = changed;
        }
    }

    #[test]
    fn oversized_ignored_dependency_requires_review_and_cannot_be_cached() {
        let (_temp, project, store) = fixture();
        assert!(
            git(&project, &["init", "--quiet"])
                .unwrap()
                .status
                .success()
        );
        fs::write(project.join(".gitignore"), "node_modules/\n").unwrap();
        fs::create_dir(project.join("node_modules")).unwrap();
        File::create(project.join("node_modules/large-module"))
            .unwrap()
            .set_len(MAX_RUNTIME_BYTES + 1)
            .unwrap();
        let version = fingerprint(&store, &project);
        assert!(!version.reproducible);
        for source in ["trial", "user-review"] {
            let error = store
                .approve(&version, source, "approval is one request only")
                .unwrap_err();
            assert!(error.to_string().contains("one-request review"));
        }
        assert!(store.lookup(&version).unwrap().is_none());
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn runtime_hash_budget_applies_to_reads_and_warm_cache_entries() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("runtime-input");
        fs::write(&path, "one").unwrap();
        let mut hashes = BTreeMap::new();
        assert!(cached_hash_bounded(&path, &mut hashes, 3).is_ok());
        assert!(cached_hash_bounded(&path, &mut hashes, 2).is_err());
        fs::write(&path, "more").unwrap();
        assert!(cached_hash_bounded(&path, &mut hashes, 3).is_err());
    }

    #[test]
    fn existing_shell_startup_requires_review_and_is_hashed() {
        let temp = tempfile::tempdir().unwrap();
        let environment =
            BTreeMap::from([(OsString::from("HOME"), temp.path().as_os_str().to_owned())]);
        let absent = shell_startup_inputs(Path::new("/bin/zsh"), &environment);
        assert!(absent.complete && absent.files.is_empty());
        let startup = temp.path().join(".zshenv");
        fs::write(&startup, "export DATA_DIR=elsewhere\n").unwrap();
        let present = shell_startup_inputs(Path::new("/bin/zsh"), &environment);
        assert_eq!(present.files, BTreeSet::from([startup.clone()]));
        let mut hashes = BTreeMap::new();
        let first = cached_hash(&startup, &mut hashes).unwrap().0;
        fs::write(&startup, "export DATA_DIR=changed\n").unwrap();
        assert_ne!(first, cached_hash(&startup, &mut hashes).unwrap().0);
    }

    #[cfg(unix)]
    #[test]
    fn ignored_dependency_symlink_requires_review() {
        let (_temp, project, store) = fixture();
        assert!(
            git(&project, &["init", "--quiet"])
                .unwrap()
                .status
                .success()
        );
        fs::write(project.join(".gitignore"), "node_modules/\n").unwrap();
        fs::create_dir(project.join("node_modules")).unwrap();
        std::os::unix::fs::symlink("../run.sh", project.join("node_modules/link.js")).unwrap();
        assert!(!fingerprint(&store, &project).reproducible);
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
