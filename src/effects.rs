//! Bounded filesystem evidence for literal commands. Never executes a candidate.
//! A version grant resolves one rule, not sibling rules or an entire shell program.

use std::fmt::Write as _;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::time::UNIX_EPOCH;

use sha2::{Digest, Sha256};

use crate::normalize::{NormalizeTokenKind, tokenize_for_normalization};
use crate::trial_store::TrialStore;

const MAX_ENTRIES: usize = 10_000;
const MAX_HASH_BYTES: u64 = 64 * 1024 * 1024;
pub const SELF_PROTECTION: &str = "Änderung an dcg selbst – wird nie gemerkt";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperandFingerprint {
    pub digest: String,
    pub cwd: PathBuf,
    pub command: String,
    pub rule_id: String,
    pub operands: Vec<PathBuf>,
}

#[derive(Debug, Default)]
pub struct Assessment {
    pub allow: bool,
    pub self_protected: bool,
    pub summary: Option<String>,
    pub version: Option<OperandFingerprint>,
}

#[derive(Debug)]
struct Invocation {
    tool: String,
    executable: PathBuf,
    operands: Vec<PathBuf>,
    recursive: bool,
}

fn unsupported(message: &str) -> io::Error {
    io::Error::other(message)
}

/// The deliberately small grammar excludes wrappers, assignments, redirects,
/// substitutions, expansion, optional-argument flags, and relative operands.
fn invocation(command: &str, home: &Path) -> io::Result<Invocation> {
    parse_invocation(command, home, true)
}

fn parse_invocation(command: &str, home: &Path, verify_utility: bool) -> io::Result<Invocation> {
    if command.len() > 16_384
        || command.contains([
            '\n', '\r', '$', '`', '*', '?', '[', ']', '{', '}', '\\', '(', ')', '<', '>',
        ])
    {
        return Err(unsupported("filesystem operands are not bounded literals"));
    }
    let tokens = tokenize_for_normalization(command);
    let words = tokens
        .iter()
        .map(|token| {
            if token.kind != NormalizeTokenKind::Word {
                return Err(unsupported("filesystem effects require one shell segment"));
            }
            let raw = &command[token.byte_range.clone()];
            let decoded = shell_words::split(raw).map_err(io::Error::other)?;
            if decoded.len() != 1 || (decoded[0].starts_with('~') && !raw.starts_with('~')) {
                return Err(unsupported("ambiguous literal operand"));
            }
            Ok(decoded[0].clone())
        })
        .collect::<io::Result<Vec<_>>>()?;
    let first = words.first().ok_or_else(|| unsupported("empty command"))?;
    let tool = first.rsplit('/').next().unwrap_or(first);
    if !matches!(tool, "rm" | "mv" | "cp") {
        return Err(unsupported("no bounded filesystem invocation model"));
    }
    let executable = if verify_utility {
        trusted_utility(first, tool)?
    } else {
        PathBuf::from(first)
    };
    let mut operands = Vec::new();
    let mut options = true;
    let mut recursive = false;
    for word in words.iter().skip(1) {
        if options && word == "--" {
            options = false;
        } else if options && word.starts_with('-') {
            let flags = match tool {
                "rm" => "rRfivId",
                "cp" => "aRrfipnvP",
                _ => "finv",
            };
            if matches!((tool, word.as_str()), ("rm", "--recursive" | "--force")) {
                recursive |= word == "--recursive";
            } else if word.len() < 2 || !word[1..].chars().all(|ch| flags.contains(ch)) {
                return Err(unsupported("filesystem option semantics require review"));
            }
            recursive |= word[1..].contains(['r', 'R', 'a']);
        } else {
            let path = if word == "~" {
                home.to_path_buf()
            } else if let Some(tail) = word.strip_prefix("~/") {
                home.join(tail)
            } else {
                PathBuf::from(word)
            };
            if !path.is_absolute()
                || path
                    .components()
                    .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
            {
                return Err(unsupported(
                    "filesystem operands must be literal absolute or home paths",
                ));
            }
            operands.push(path);
        }
    }
    if operands.is_empty() || operands.len() > 128 || (tool != "rm" && operands.len() != 2) {
        return Err(unsupported("unsupported filesystem operand count"));
    }
    Ok(Invocation {
        tool: tool.to_owned(),
        executable,
        operands,
        recursive,
    })
}

fn trusted_utility(word: &str, tool: &str) -> io::Result<PathBuf> {
    let resolved = if word.contains('/') {
        PathBuf::from(word).canonicalize()?
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|dir| dir.join(word))
            .find(|path| path.is_file())
            .ok_or_else(|| unsupported("utility cannot be resolved"))?
            .canonicalize()?
    };
    if ["/bin", "/usr/bin"].iter().any(|dir| {
        Path::new(dir)
            .join(tool)
            .canonicalize()
            .is_ok_and(|path| path == resolved)
    }) {
        Ok(resolved)
    } else {
        Err(unsupported(
            "utility is not the system filesystem executable",
        ))
    }
}

/// Paths are checked lexically AND after canonicalization for protection only.
/// Canonicalization never supplies evidence for an automatic file effect.
fn touches(path: &Path, protected: &Path) -> bool {
    path.starts_with(protected) || protected.starts_with(path)
}

fn protected_in(path: &Path, home: &Path, executable: &Path) -> bool {
    let mut protected = vec![
        home.join(".config/dcg"),
        home.join("Library/Application Support/dcg"),
        home.join(".codex/hooks.json"),
        home.join(".codex/config.toml"),
        home.join(".config/opencode/plugins"),
        home.join(".opencode/plugins"),
        home.join(".grok/hooks"),
        home.join(".gemini/config/hooks.json"),
        home.join(".pi/agent/extensions/dcg-guard.ts"),
        home.join(".gemini/settings.json"),
        home.join(".copilot/hooks"),
        home.join(".config/agy"),
        home.join(".agy"),
        home.join(".reasonix/settings.json"),
        home.join(".config/crush"),
    ];
    protected.push(executable.to_path_buf());
    if protected.iter().any(|target| {
        touches(path, target)
            || target
                .canonicalize()
                .is_ok_and(|target| touches(path, &target))
    }) {
        return true;
    }
    // Match project-local hook configurations as well as the user's copies.
    let parts: Vec<_> = path.components().collect();
    if parts.windows(2).any(|pair| {
        let a = pair[0].as_os_str().to_string_lossy();
        let b = pair[1].as_os_str().to_string_lossy();
        (a == ".claude" && b.starts_with("settings") && b.ends_with(".json"))
            || (a == ".codex" && matches!(b.as_ref(), "hooks.json" | "config.toml"))
            || (matches!(a.as_ref(), ".grok" | ".copilot") && b == "hooks")
            || (a == ".opencode" && b == "plugins")
    }) || path.ends_with(".claude")
    {
        return true;
    }
    if let Some(parent) = executable.parent() {
        if parent.starts_with(path) {
            return true;
        }
        if let Ok(relative) = path.strip_prefix(parent)
            && relative
                .components()
                .next()
                .is_some_and(|part| part.as_os_str().to_string_lossy().starts_with("dcg"))
        {
            return true;
        }
    }
    #[cfg(unix)]
    if let (Ok(left), Ok(right)) = (fs::symlink_metadata(path), fs::metadata(executable)) {
        use std::os::unix::fs::MetadataExt;
        if left.dev() == right.dev() && left.ino() == right.ino() {
            return true;
        }
    }
    false
}

pub fn protected_operand(path: &Path) -> bool {
    let (Some(home), Ok(executable)) = (crate::config::home_dir(), std::env::current_exe()) else {
        return true;
    };
    if protected_in(path, &home, &executable)
        || path
            .canonicalize()
            .is_ok_and(|real| protected_in(&real, &home, &executable))
    {
        return true;
    }
    if crate::config::user_config_dir().is_some_and(|dir| touches(path, &dir.join("dcg"))) {
        return true;
    }
    // Active configuration overrides expand protection; they cannot remove the defaults.
    [
        "CLAUDE_CONFIG_DIR",
        "CODEX_HOME",
        "DCG_CONFIG",
        "DCG_ALLOWLIST_USER_PATH",
        "OPENCODE_CONFIG_DIR",
    ]
    .iter()
    .any(|key| {
        std::env::var_os(key).is_some_and(|value| {
            let target = PathBuf::from(value);
            target.is_absolute() && touches(path, &target)
        })
    })
}

/// Explicit literal mutations of DCG itself require review even if a broad
/// ordinary allowlist or temporary-directory carve-out would otherwise allow.
pub fn changes_self(command: &str) -> bool {
    crate::config::home_dir()
        .and_then(|home| parse_invocation(command, &home, false).ok())
        .is_some_and(|parsed| {
            let mut remaining = MAX_ENTRIES;
            parsed
                .operands
                .iter()
                .any(|path| protected_tree(path, &mut remaining, 0))
        })
}

// A temporary directory can contain project hook configuration. Inspect names
// without reading contents or following symlinks, even before a temp carve-out.
// An unbounded or unreadable tree cannot establish absence of protected files.
fn protected_tree(path: &Path, remaining: &mut usize, depth: usize) -> bool {
    if protected_operand(path) || *remaining == 0 || depth > 64 {
        return true;
    }
    *remaining -= 1;
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => fs::read_dir(path).map_or(true, |mut entries| {
            entries.any(|entry| {
                entry.map_or(true, |entry| {
                    protected_tree(&entry.path(), remaining, depth + 1)
                })
            })
        }),
        Ok(_) => false,
        Err(error) => error.kind() != io::ErrorKind::NotFound,
    }
}

fn literal_metadata(path: &Path) -> io::Result<Option<Metadata>> {
    let mut prefix = PathBuf::new();
    for part in path.components() {
        prefix.push(part);
        match fs::symlink_metadata(&prefix) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(unsupported("symlink operand or ancestor requires review"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound && prefix == path => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        }
    }
    fs::symlink_metadata(path).map(Some)
}

fn field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}

fn identity(meta: &Metadata) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.push(u8::from(meta.is_dir()));
    bytes.push(u8::from(meta.is_file()));
    bytes.extend(meta.len().to_le_bytes());
    bytes.extend(
        meta.modified()?
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos()
            .to_le_bytes(),
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        bytes.extend(meta.dev().to_le_bytes());
        bytes.extend(meta.ino().to_le_bytes());
        bytes.extend(meta.mode().to_le_bytes());
        bytes.extend(meta.ctime().to_le_bytes());
        bytes.extend(meta.ctime_nsec().to_le_bytes());
    }
    Ok(bytes)
}

#[derive(Default)]
struct Manifest {
    entries: usize,
    hashed_bytes: u64,
    files: usize,
    bytes: u64,
    paths: Vec<PathBuf>,
}

fn bind_path(
    path: &Path,
    hash: &mut Sha256,
    manifest: &mut Manifest,
    depth: usize,
) -> io::Result<()> {
    if protected_operand(path) {
        return Err(unsupported(SELF_PROTECTION));
    }
    manifest.entries += 1;
    if manifest.entries > MAX_ENTRIES || depth > 64 {
        return Err(unsupported("operand manifest limit exceeded"));
    }
    let meta = literal_metadata(path)?.ok_or_else(|| unsupported("operand disappeared"))?;
    let before = identity(&meta)?;
    field(hash, path.as_os_str().as_encoded_bytes());
    field(hash, &before);
    if meta.is_file() {
        manifest.files += 1;
        manifest.bytes = manifest.bytes.saturating_add(meta.len());
        manifest.paths.push(path.to_path_buf());
        if meta.len() <= MAX_HASH_BYTES {
            manifest.hashed_bytes = manifest.hashed_bytes.saturating_add(meta.len());
            if manifest.hashed_bytes > MAX_HASH_BYTES {
                return Err(unsupported("operand content hash limit exceeded"));
            }
            let mut options = OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
            }
            let file: File = options.open(path)?;
            if identity(&file.metadata()?)? != before {
                return Err(unsupported("operand changed while opening"));
            }
            let mut content = Sha256::new();
            let mut stream = file.take(MAX_HASH_BYTES + 1);
            let mut buffer = [0; 16_384];
            let mut total = 0_u64;
            loop {
                let count = stream.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                content.update(&buffer[..count]);
                total += count as u64;
            }
            if total != meta.len() {
                return Err(unsupported("operand size changed while hashing"));
            }
            field(hash, &content.finalize());
        }
    } else if meta.is_dir() {
        let mut children = Vec::new();
        for entry in fs::read_dir(path)? {
            if children.len() >= MAX_ENTRIES.saturating_sub(manifest.entries) {
                return Err(unsupported("operand manifest limit exceeded"));
            }
            children.push(entry?.path());
        }
        children.sort();
        for child in children {
            bind_path(&child, hash, manifest, depth + 1)?;
        }
    } else {
        return Err(unsupported("special-file operand requires review"));
    }
    if identity(&fs::symlink_metadata(path)?)? != before {
        return Err(unsupported("operand changed during inspection"));
    }
    Ok(())
}

fn definite_filesystem_rule(rule_id: &str) -> bool {
    rule_id.starts_with("core.filesystem:")
        && !["unverified", "dynamic", "unknown", "timeout", "parse-error"]
            .iter()
            .any(|part| rule_id.contains(part))
}

pub fn fingerprint(command: &str, cwd: &Path, rule_id: &str) -> io::Result<OperandFingerprint> {
    if !definite_filesystem_rule(rule_id) {
        return Err(unsupported("not a definite filesystem rule"));
    }
    if std::env::vars_os().any(|(key, value)| {
        !value.is_empty() && {
            let key = key.to_string_lossy();
            matches!(
                key.as_ref(),
                "BASH_ENV" | "ENV" | "ZDOTDIR" | "LD_PRELOAD" | "LD_LIBRARY_PATH"
            ) || key.starts_with("BASH_FUNC_")
                || key.starts_with("DYLD_")
        }
    }) {
        return Err(unsupported(
            "inherited startup or preload context requires review",
        ));
    }
    let home = crate::config::home_dir().ok_or_else(|| unsupported("home unavailable"))?;
    let parsed = invocation(command, &home)?;
    if parsed.operands.iter().any(|path| protected_operand(path)) {
        return Err(unsupported(SELF_PROTECTION));
    }
    let cwd = cwd.canonicalize()?;
    let mut hash = Sha256::new();
    field(&mut hash, b"dcg-learned-filesystem-v1");
    for text in [command, rule_id] {
        field(&mut hash, text.as_bytes());
    }
    field(&mut hash, cwd.as_os_str().as_encoded_bytes());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(&cwd)?;
        field(&mut hash, &metadata.dev().to_le_bytes());
        field(&mut hash, &metadata.ino().to_le_bytes());
    }
    field(&mut hash, parsed.executable.as_os_str().as_encoded_bytes());
    field(&mut hash, &identity(&fs::metadata(&parsed.executable)?)?);
    for name in [
        "PATH",
        "BASH_ENV",
        "ENV",
        "ZDOTDIR",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
    ] {
        field(&mut hash, name.as_bytes());
        field(
            &mut hash,
            std::env::var_os(name)
                .unwrap_or_default()
                .as_encoded_bytes(),
        );
    }
    let mut manifest = Manifest::default();
    for (index, path) in parsed.operands.iter().enumerate() {
        if literal_metadata(path)?.is_none() && parsed.tool != "rm" && index == 1 {
            field(&mut hash, b"absent-destination");
            field(&mut hash, path.as_os_str().as_encoded_bytes());
            field(
                &mut hash,
                &identity(&fs::metadata(
                    path.parent()
                        .ok_or_else(|| unsupported("destination has no parent"))?,
                )?)?,
            );
        } else {
            bind_path(path, &mut hash, &mut manifest, 0)?;
        }
    }
    let mut digest = String::with_capacity(64);
    for byte in hash.finalize() {
        let _ = write!(digest, "{byte:02x}");
    }
    Ok(OperandFingerprint {
        digest,
        cwd,
        command: command.to_owned(),
        rule_id: rule_id.to_owned(),
        operands: parsed.operands,
    })
}

fn sensitive_directory(path: &Path, home: &Path) -> bool {
    if path == home || path.parent().is_none() {
        return true;
    }
    if path.strip_prefix(home).is_ok_and(|relative| {
        relative
            .components()
            .any(|part| part.as_os_str().to_string_lossy().starts_with('.'))
    }) {
        return true;
    }
    [
        "/etc", "/usr", "/bin", "/sbin", "/var", "/System", "/Library", "/root", "/dev", "/proc",
        "/sys",
    ]
    .iter()
    .any(|root| path.starts_with(root))
}

fn single_file_effect(parsed: &Invocation, home: &Path) -> bool {
    if !matches!(parsed.tool.as_str(), "mv" | "cp") {
        return false;
    }
    let source = &parsed.operands[0];
    let destination = &parsed.operands[1];
    literal_metadata(source).is_ok_and(|value| value.is_some_and(|meta| meta.is_file()))
        && literal_metadata(destination).is_ok_and(|value| value.is_none_or(|meta| meta.is_file()))
        && source != home
        && !source
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with('.'))
        && (source.parent() == destination.parent()
            || destination
                .parent()
                .is_some_and(|parent| !sensitive_directory(parent, home)))
}

pub fn assess(command: &str, cwd: &Path, rule_id: &str) -> Assessment {
    if changes_self(command) {
        return Assessment {
            self_protected: true,
            summary: Some(SELF_PROTECTION.to_owned()),
            ..Assessment::default()
        };
    }
    let Some(home) = crate::config::home_dir() else {
        return Assessment::default();
    };
    let Ok(parsed) = invocation(command, &home) else {
        return Assessment::default();
    };
    if parsed.operands.iter().any(|path| protected_operand(path)) {
        return Assessment {
            self_protected: true,
            summary: Some(SELF_PROTECTION.to_owned()),
            ..Assessment::default()
        };
    }
    let version = match fingerprint(command, cwd, rule_id) {
        Ok(version) => Some(version),
        Err(error) if error.to_string() == SELF_PROTECTION => {
            return Assessment {
                self_protected: true,
                summary: Some(SELF_PROTECTION.to_owned()),
                ..Assessment::default()
            };
        }
        Err(_) => None,
    };
    let bounded_file = single_file_effect(&parsed, &home);
    let allow = version.is_some()
        && bounded_file
        && matches!(
            rule_id,
            "core.filesystem:mv-sensitive-source-root-home"
                | "core.filesystem:cp-sensitive-then-delete"
        );
    let summary = if bounded_file {
        Some(
            "Ersetzt oder erstellt genau eine reguläre Datei; keine Verzeichnisrekursion."
                .to_owned(),
        )
    } else if parsed.tool == "rm" && parsed.recursive {
        Some(removal_summary(&parsed.operands))
    } else {
        None
    };
    Assessment {
        allow,
        self_protected: false,
        summary,
        version,
    }
}

fn removal_summary(paths: &[PathBuf]) -> String {
    let mut hash = Sha256::new();
    let mut manifest = Manifest::default();
    for path in paths {
        if let Err(error) = bind_path(path, &mut hash, &mut manifest, 0) {
            return format!(
                "Rekursives Löschen: Umfang nicht vollständig bestimmbar ({error}); keine automatische Freigabe."
            );
        }
    }
    let tracked = paths
        .first()
        .and_then(|path| crate::trial_store::project_root(path.parent()?).ok())
        .and_then(|root| {
            crate::trial_store::tracked_files(&root).ok().map(|files| {
                manifest
                    .paths
                    .iter()
                    .filter(|path| {
                        path.strip_prefix(&root)
                            .is_ok_and(|relative| files.contains(relative))
                    })
                    .count()
            })
        });
    let tracked = tracked.map_or_else(
        || "Git-Status unbekannt".to_owned(),
        |count| format!("{count} von Git erfasst"),
    );
    format!(
        "Löscht {} Ziel(e): {} Dateien, {} Bytes, {tracked}. Kein Papierkorb.",
        paths.len(),
        manifest.files,
        manifest.bytes
    )
}

impl Assessment {
    pub fn learned(&self, store: &TrialStore) -> bool {
        !self.self_protected
            && self
                .version
                .as_ref()
                .is_some_and(|version| store.lookup_learned(version).ok().flatten().is_some())
    }

    /// The dialog is injected only in tests. Production passes the existing
    /// nonce-bound biometric review and rechecks operands before AND after it.
    pub fn review_with(&self, store: Option<&TrialStore>, dialog: impl FnOnce() -> bool) -> bool {
        let unchanged = || {
            self.version.as_ref().is_none_or(|version| {
                fingerprint(&version.command, &version.cwd, &version.rule_id)
                    .is_ok_and(|current| current == *version)
            })
        };
        if !unchanged() || !dialog() || !unchanged() {
            return false;
        }
        if !self.self_protected
            && let (Some(store), Some(version)) = (store, self.version.as_ref())
        {
            // Persistence failure cannot expand an approval; it remains one-request.
            let _ = store.approve_learned(
                version,
                self.summary
                    .as_deref()
                    .unwrap_or("Touch ID: exact filesystem operands"),
            );
        }
        true
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    const MOVE: &str = "core.filesystem:mv-sensitive-source-root-home";
    const REMOVE: &str = "core.filesystem:rm-recursive-general";

    fn fixture() -> (tempfile::TempDir, PathBuf, TrialStore) {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let project = root.join("project");
        fs::create_dir(&project).unwrap();
        let store = TrialStore::new(root.join("store"));
        (temporary, project, store)
    }

    fn command(tool: &str, paths: &[&Path]) -> String {
        format!(
            "/bin/{tool} {}",
            paths
                .iter()
                .map(|path| format!("'{}'", path.display()))
                .collect::<Vec<_>>()
                .join(" ")
        )
    }

    #[test]
    fn single_file_moves_and_copies_have_bounded_effects() {
        let (_temp, project, _) = fixture();
        let source = project.join("source");
        let target = project.join("target");
        fs::write(&source, "one file").unwrap();
        for exists in [false, true] {
            if exists {
                fs::write(&target, "previous").unwrap();
            }
            for tool in ["mv", "cp"] {
                let text = command(tool, &[&source, &target]);
                let rule = if tool == "mv" {
                    MOVE
                } else {
                    "core.filesystem:cp-sensitive-then-delete"
                };
                let check = assess(&text, &project, rule);
                assert!(check.allow, "{text}: {check:?}");
                assert!(check.summary.unwrap().contains("genau eine reguläre Datei"));
                // The same observed effect cannot waive a different documented hazard.
                assert!(!assess(&text, &project, "core.filesystem:credential-file-write").allow);
            }
        }
        assert_eq!(fs::read_to_string(source).unwrap(), "one file");
        assert_eq!(fs::read_to_string(target).unwrap(), "previous");
    }

    #[test]
    fn directory_symlink_home_and_dotfile_sources_require_review() {
        let (_temp, project, _) = fixture();
        let folder = project.join("folder");
        fs::create_dir(&folder).unwrap();
        let hidden = project.join(".secrets");
        fs::create_dir(&hidden).unwrap();
        let link = project.join("alias");
        std::os::unix::fs::symlink(&folder, &link).unwrap();
        let file = project.join("file");
        fs::write(&file, "x").unwrap();
        let file_link = project.join("file-alias");
        std::os::unix::fs::symlink(&file, &file_link).unwrap();
        for path in [&folder, &hidden, &link, &file_link, &project] {
            assert!(
                !assess(
                    &command("mv", &[path, &project.join("dest")]),
                    &project,
                    MOVE
                )
                .allow
            );
        }
        let parsed = invocation("/bin/mv ~ /not-created", &project).unwrap();
        assert!(!single_file_effect(&parsed, &project));
        let alias_parent = project.join("linked-parent");
        std::os::unix::fs::symlink(&folder, &alias_parent).unwrap();
        assert!(
            !assess(
                &command("mv", &[&file, &alias_parent.join("new")]),
                &project,
                MOVE
            )
            .allow
        );
    }

    #[test]
    fn shell_expansion_compounds_and_option_reinterpretation_require_review() {
        let (_temp, project, _) = fixture();
        for text in [
            "mv /a /b && rm /c",
            "mv /a /b; true",
            "mv /a /b | cat",
            "(mv /a /b)",
            "mv /a/* /b",
            "mv $SOURCE /b",
            "mv $(echo /a) /b",
            "mv '/a' '~/b'",
            "mv -t /a /b",
            "cp --parents /a /b",
            "rm --help /a",
            "mv ./a ./b",
            "mv /a/../b /c",
            "mv /a /b > /log",
            "sudo mv /a /b",
            "mv /a /b\ntrue",
        ] {
            assert!(invocation(text, &project).is_err(), "{text}");
            assert!(fingerprint(text, &project, MOVE).is_err(), "{text}");
        }
    }

    #[test]
    fn operand_content_size_inode_and_type_changes_invalidate_approval() {
        let (_temp, project, _) = fixture();
        let target = project.join("target");
        fs::write(&target, "aaaa").unwrap();
        let text = command("rm -r", &[&target]);
        let original = fingerprint(&text, &project, REMOVE).unwrap();
        assert_eq!(fingerprint(&text, &project, REMOVE).unwrap(), original);
        fs::write(&target, "bbbb").unwrap();
        let content = fingerprint(&text, &project, REMOVE).unwrap();
        assert_ne!(content, original);
        fs::write(&target, "longer").unwrap();
        let size = fingerprint(&text, &project, REMOVE).unwrap();
        assert_ne!(size, content);
        fs::rename(&target, project.join("saved")).unwrap();
        fs::write(&target, "longer").unwrap();
        let inode = fingerprint(&text, &project, REMOVE).unwrap();
        assert_ne!(inode, size);
        fs::rename(&target, project.join("saved-again")).unwrap();
        fs::create_dir(&target).unwrap();
        assert_ne!(fingerprint(&text, &project, REMOVE).unwrap(), inode);
    }

    #[test]
    fn directory_manifest_binds_descendant_changes() {
        let (_temp, project, _) = fixture();
        let folder = project.join("folder");
        fs::create_dir(&folder).unwrap();
        let child = folder.join("child");
        fs::write(&child, "aaaa").unwrap();
        let text = command("rm -r", &[&folder]);
        let original = fingerprint(&text, &project, REMOVE).unwrap();
        fs::write(&child, "bbbb").unwrap();
        assert_ne!(fingerprint(&text, &project, REMOVE).unwrap(), original);
        std::os::unix::fs::symlink(&child, folder.join("link")).unwrap();
        assert!(fingerprint(&text, &project, REMOVE).is_err());
    }

    #[test]
    fn fake_touch_id_learns_only_an_unchanged_rule_bound_version() {
        let (_temp, project, store) = fixture();
        let target = project.join("target");
        fs::write(&target, "original").unwrap();
        let text = command("rm -r", &[&target]);
        let first = assess(&text, &project, REMOVE);
        assert!(!first.allow && !first.learned(&store));
        assert!(first.review_with(Some(&store), || true));
        assert!(assess(&text, &project, REMOVE).learned(&store));
        assert!(!assess(&text, &project, "core.filesystem:rm-protected-file").learned(&store));
        assert!(!assess(&format!("{text} "), &project, REMOVE).learned(&store));
        fs::write(&target, "changed").unwrap();
        let next = assess(&text, &project, REMOVE);
        assert!(!next.learned(&store));
        assert!(!next.review_with(Some(&store), || false));
        assert_eq!(store.list_learned().unwrap().len(), 1);
    }

    #[test]
    fn mutation_during_review_rejects_the_answer_without_recording() {
        let (_temp, project, store) = fixture();
        let target = project.join("target");
        fs::write(&target, "original").unwrap();
        let text = command("rm -r", &[&target]);
        let check = assess(&text, &project, REMOVE);
        assert!(!check.review_with(Some(&store), || {
            fs::write(&target, "changed").unwrap();
            true
        }));
        assert!(store.list_learned().unwrap().is_empty());
    }

    #[test]
    fn self_protection_covers_all_managed_paths_and_never_records() {
        let (_temp, project, store) = fixture();
        let executable = project.join("bin/dcg");
        fs::create_dir(project.join("bin")).unwrap();
        fs::write(&executable, "binary").unwrap();
        let home = project.join("home");
        fs::create_dir(&home).unwrap();
        let mut paths = vec![
            executable.clone(),
            project.join("bin/dcg-helper"),
            project.join("bin"),
        ];
        paths.extend(
            [
                ".config/dcg/config.toml",
                "Library/Application Support/dcg/verified_trials.json",
                ".claude/settings.json",
                ".claude/settings.local.json",
                ".codex/hooks.json",
                ".codex/config.toml",
                ".config/opencode/plugins/dcg-guard.js",
                ".opencode/plugins/dcg-guard.js",
                ".grok/hooks/dcg.json",
                ".gemini/config/hooks.json",
                ".pi/agent/extensions/dcg-guard.ts",
            ]
            .iter()
            .map(|relative| home.join(relative)),
        );
        for path in paths {
            assert!(
                protected_in(&path, &home, &executable),
                "{}",
                path.display()
            );
            let assessment = Assessment {
                self_protected: true,
                summary: Some(SELF_PROTECTION.to_owned()),
                ..Assessment::default()
            };
            for _ in 0..2 {
                let mut asked = false;
                assert!(!assessment.allow && !assessment.learned(&store));
                assert!(assessment.review_with(Some(&store), || {
                    asked = true;
                    true
                }));
                assert!(asked && store.list_learned().unwrap().is_empty());
            }
        }
        let alias = project.join("not-named-dcg");
        fs::hard_link(&executable, &alias).unwrap();
        assert!(protected_in(&alias, &home, &executable));
    }

    #[test]
    fn recursive_delete_reports_real_counts_and_git_tracking_without_allowing() {
        let (_temp, project, _) = fixture();
        let folder = project.join("folder");
        fs::create_dir(&folder).unwrap();
        fs::write(folder.join("tracked"), "abc").unwrap();
        fs::write(folder.join("untracked"), "defgh").unwrap();
        for args in [vec!["init", "--quiet"], vec!["add", "folder/tracked"]] {
            assert!(
                std::process::Command::new("/usr/bin/git")
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .args(args)
                    .current_dir(&project)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let check = assess(&command("rm -r", &[&folder]), &project, REMOVE);
        assert!(!check.allow);
        let text = check.summary.unwrap();
        assert!(
            text.contains("2 Dateien, 8 Bytes, 1 von Git erfasst"),
            "{text}"
        );
        assert_eq!(fs::read(folder.join("tracked")).unwrap(), b"abc");
    }

    #[test]
    fn oversized_operand_lists_and_special_files_do_not_get_fingerprints() {
        let (_temp, project, _) = fixture();
        let paths = vec![project.as_path(); 129];
        assert!(fingerprint(&command("rm -r", &paths), &project, REMOVE).is_err());
        assert!(fingerprint("/bin/rm /dev/null", &project, REMOVE).is_err());
    }
}
