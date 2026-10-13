//! Local, one-request human approval. No grant file, shell execution or model.
//! A failed/cancelled dialog never changes the original denial.

use crate::evaluator::PatternMatch;
use crate::heredoc::ScriptLanguage;
use crate::normalize::strip_wrapper_prefixes;
use ast_grep_core::AstGrep;
use ast_grep_language::SupportLang;
use fs2::FileExt;
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
#[cfg(target_os = "macos")]
use std::io::Write as _;
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

const MAX_REVIEW_TEXT: usize = 5_000;
const MAX_SOURCE_BYTES: u64 = 256 * 1024;
const DIALOG_SECONDS: u64 = 120;

#[derive(Clone)]
struct ScriptEvidence {
    path: PathBuf,
    source: String,
    digest: [u8; 32],
    cwd: PathBuf,
    shell: bool,
}

thread_local! {
    static EVIDENCE: RefCell<Option<Vec<ScriptEvidence>>> = const { RefCell::new(None) };
    static SOURCE_PATHS: RefCell<Vec<PathBuf>> = const { RefCell::new(Vec::new()) };
    static INCOMPLETE: Cell<bool> = const { Cell::new(false) };
}

/// Captures the actual bytes read by the evaluator on this thread.
pub struct ReviewCapture;

impl ReviewCapture {
    pub fn start() -> Self {
        EVIDENCE.with(|slot| *slot.borrow_mut() = Some(Vec::new()));
        SOURCE_PATHS.with(|slot| slot.borrow_mut().clear());
        INCOMPLETE.with(|value| value.set(false));
        Self
    }

    /// Freeze the evidence for this one pending request.
    pub fn snapshot(&self) -> ReviewSnapshot {
        ReviewSnapshot {
            scripts: EVIDENCE.with(|slot| slot.borrow().clone().unwrap_or_default()),
            source_paths: SOURCE_PATHS.with(|slot| slot.borrow().clone()),
            incomplete: INCOMPLETE.with(Cell::get),
        }
    }
}

impl Drop for ReviewCapture {
    fn drop(&mut self) {
        EVIDENCE.with(|slot| *slot.borrow_mut() = None);
        SOURCE_PATHS.with(|slot| slot.borrow_mut().clear());
    }
}

pub(crate) fn record_script(path: &Path, source: &str, cwd: &Path, language: ScriptLanguage) {
    EVIDENCE.with(|slot| {
        if let Some(evidence) = slot.borrow_mut().as_mut() {
            let digest = Sha256::digest(source.as_bytes()).into();
            if !evidence
                .iter()
                .any(|item| item.path == path && item.digest == digest)
            {
                evidence.push(ScriptEvidence {
                    path: path.to_path_buf(),
                    source: source.to_string(),
                    digest,
                    cwd: cwd.to_path_buf(),
                    shell: language == ScriptLanguage::Bash,
                });
            }
        }
    });
}

pub(crate) fn record_incomplete() {
    INCOMPLETE.with(|value| value.set(true));
}

/// Remember literal inputs even when opening them fails. Missing inputs cannot
/// acquire a reusable approval for a different file created after the review.
pub(crate) fn record_source_path(path: &Path) {
    if EVIDENCE.with(|slot| slot.borrow().is_some()) {
        SOURCE_PATHS.with(|slot| {
            let mut paths = slot.borrow_mut();
            if !paths.iter().any(|existing| existing == path) {
                paths.push(path.to_path_buf());
            }
        });
    }
}

/// No persistent approval is created: the caller may release only this request.
pub struct ReviewSnapshot {
    scripts: Vec<ScriptEvidence>,
    source_paths: Vec<PathBuf>,
    incomplete: bool,
}

/// The authorization scope controls both consent wording and persistence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalScope {
    OneTime,
    ExactVersion,
    LearnedFilesystem,
    Confined,
}

impl ApprovalScope {
    pub const fn trial(enabled: bool, reproducible: bool) -> Self {
        if enabled && reproducible {
            Self::ExactVersion
        } else {
            Self::OneTime
        }
    }

    pub const fn sentence(self) -> &'static str {
        match self {
            Self::OneTime => {
                "Die Freigabe gilt nur für diesen Aufruf. Es wird keine wiederverwendbare Ausnahme gespeichert."
            }
            Self::ExactVersion => {
                "Die Freigabe gilt für diese exakte Befehls- und Projektversion. Geänderte geprüfte Eingaben erfordern erneut eine Prüfung."
            }
            Self::LearnedFilesystem => {
                "Touch ID merkt sich diesen Aufruf, diese Regel und die unveränderten Dateisystemobjekte. Änderungen erfordern erneut eine Prüfung."
            }
            Self::Confined => {
                "Der Befehl läuft einmal unter fortlaufender Sandbox-Begrenzung. Es wird keine Freigabe gespeichert."
            }
        }
    }
}

/// Separate display fields prevent command/source text from posing as an
/// agent, folder or action heading. Full evidence remains available in details.
#[derive(Clone, serde::Serialize)]
pub struct ReviewDescription {
    agent: String,
    host: Option<String>,
    project: String,
    repository: Option<String>,
    cwd: String,
    title: String,
    effect: String,
    warning: Option<String>,
    command: String,
    executables: Vec<String>,
    targets: Vec<String>,
    text: String,
    scope: ApprovalScope,
    scope_text: String,
}

impl ReviewDescription {
    pub fn set_scope(&mut self, scope: ApprovalScope) {
        self.scope = scope;
        self.scope_text = scope.sentence().to_owned();
    }

    /// Add effect evidence. The persistence decision separately supplies scope;
    /// an available manifest alone does not promise a remembered approval.
    pub fn filesystem_effect(&mut self, assessment: &crate::effects::Assessment) {
        if let Some(summary) = &assessment.summary {
            self.effect = visible(summary);
            self.text.push_str("\n\nGeprüfte Dateisystemwirkung:\n");
            self.text.push_str(&visible(summary));
        }
        if assessment.self_protected {
            self.warning = Some(crate::effects::SELF_PROTECTION.to_owned());
        }
    }
}

impl ReviewSnapshot {
    /// Inputs actually opened by static inspection, included in trial versions
    /// even when they are ignored by Git or outside the project manifest.
    pub fn resolved_paths(&self) -> Vec<PathBuf> {
        self.source_paths
            .iter()
            .cloned()
            .chain(self.scripts.iter().map(|item| item.path.clone()))
            .collect()
    }

    fn unchanged(&self) -> bool {
        self.scripts.iter().all(|item| {
            read_regular_source(&item.path)
                .is_some_and(|bytes| Sha256::digest(&bytes).as_slice() == item.digest)
        })
    }

    /// Human-readable effect, working directory, exact command and full small
    /// script sources. Oversized reviews are refused rather than truncated.
    pub fn description(
        &self,
        command: &str,
        cwd: &Path,
        info: &PatternMatch,
        agent: &str,
    ) -> Option<ReviewDescription> {
        if self.incomplete {
            return None;
        }
        let pattern = info.pattern_name.as_deref()?;
        // A human cannot approve "the checked contents" when inspection did
        // not finish or an executable source/target remains unknown.
        if ["unverified", "dynamic", "unknown", "parse-error", "timeout"]
            .iter()
            .any(|word| pattern.contains(word))
        {
            return None;
        }
        let pack = info.pack_id.as_deref()?;
        let effect = effect_description(pack, pattern);
        let mut targets = removal_targets(command, cwd)?;
        for item in &self.scripts {
            if item.shell {
                targets.extend(removal_targets(&item.source, &item.cwd)?);
            }
        }
        targets.sort();
        targets.dedup();
        let title = action_title(pack, pattern, &targets);
        let repository = repository_root(cwd);
        let project = repository
            .as_deref()
            .unwrap_or(cwd)
            .file_name()
            .map_or_else(
                || "/".to_owned(),
                |name| name.to_string_lossy().into_owned(),
            );
        let agent = agent_label(agent);
        let host = host_label(
            std::env::var_os("ORCA_WORKTREE_ID").is_some()
                || std::env::var_os("ORCA_TERMINAL_ID").is_some()
                || std::env::var_os("ORCA_CODEX_HOME").is_some()
                || std::env::var_os("CODEX_HOME").is_some_and(|path| {
                    Path::new(&path)
                        .components()
                        .any(|component| component.as_os_str() == "codex-runtime-home")
                }),
            std::env::var_os("CMUX_WORKSPACE_ID").is_some()
                || std::env::var_os("CMUX_SURFACE_ID").is_some(),
        );
        let mut text = format!(
            "Agent: {agent}\nOberfläche: {}\nProjekt: {}\nRepository: {}\n\nWas soll passieren?\n{title}\n\nWelche Folgen hat das?\n{effect}\n\nArbeitsordner:\n{}\n\nGenauer Aufruf:\n{}\n\nAuslöser der Rückfrage:\n{}\nRegel: {}:{}\n",
            host.as_deref().unwrap_or("Terminal / direkt"),
            visible_inline(&project),
            repository.as_ref().map_or_else(
                || "Kein Git-Repository erkannt".to_owned(),
                |path| visible_inline(&path.display().to_string())
            ),
            visible(&cwd.display().to_string()),
            visible(command),
            effect,
            visible(pack),
            visible(pattern),
        );
        if !targets.is_empty() {
            text.push_str("\nBetroffene Ziele:\n");
            for target in &targets {
                text.push_str("  • ");
                text.push_str(&visible(target));
                text.push('\n');
            }
        }
        if command.contains("ssh ") || command.contains("scp ") {
            text.push_str("\nAchtung: Der Aufruf kann auf einem entfernten Rechner wirken. Host und Ziel im Aufruf prüfen.\n");
        }
        for item in &self.scripts {
            let _ = write!(
                text,
                "\nSkript {} (vollständiger geprüfter Inhalt):\n",
                visible(&item.path.display().to_string()),
            );
            for line in item.source.lines() {
                text.push_str("  | ");
                text.push_str(&visible(line));
                text.push('\n');
                if text.len() > MAX_REVIEW_TEXT {
                    return None;
                }
            }
        }
        let executables =
            crate::invocation::bound_environment(command, &std::env::vars_os().collect())
                .ok()?
                .map_or_else(
                    || Some(Vec::new()),
                    |bound| {
                        bound.ensure_reviewable().ok()?;
                        let path = bound
                            .values
                            .get(std::ffi::OsStr::new("PATH"))
                            .cloned()
                            .unwrap_or_default();
                        let executable =
                            crate::trial_store::resolve_executable(&bound.program, cwd, &path)
                                .ok()?;
                        Some(vec![visible(&executable.display().to_string())])
                    },
                )?;
        for executable in &executables {
            let _ = write!(text, "\nAufgelöste ausführbare Datei:\n{executable}\n");
        }
        (text.len() <= MAX_REVIEW_TEXT).then(|| ReviewDescription {
            agent,
            host,
            project: visible_inline(&project),
            repository: repository.map(|path| visible_inline(&path.display().to_string())),
            cwd: visible_inline(&cwd.display().to_string()),
            title,
            effect: effect.to_owned(),
            warning: (command.contains("ssh ") || command.contains("scp ")).then(|| {
                "Kann auf einem anderen Rechner wirken. Host und Ziel im Aufruf prüfen.".to_owned()
            }),
            command: visible(command),
            executables,
            targets: targets
                .iter()
                .map(|target| visible_inline(target))
                .collect(),
            text,
            scope: ApprovalScope::OneTime,
            scope_text: ApprovalScope::OneTime.sentence().to_owned(),
        })
    }

    /// Show the context first, begin embedded Touch ID without a consent click,
    /// then recheck every captured source byte and cwd identity.
    pub fn request(&self, description: &ReviewDescription, cwd: &Path) -> bool {
        let Some(_lock) = review_lock() else {
            return false;
        };
        self.request_with(description, cwd, native_dialog)
    }

    fn request_with(
        &self,
        description: &ReviewDescription,
        cwd: &Path,
        dialog: impl FnOnce(&ReviewDescription, &str) -> bool,
    ) -> bool {
        let Some(before) = directory_identity(cwd) else {
            return false;
        };
        if !self.unchanged() || description.text.len() > MAX_REVIEW_TEXT {
            return false;
        }
        let nonce = format!("{:032x}", rand::random::<u128>());
        dialog(description, &nonce)
            && self.unchanged()
            && directory_identity(cwd).as_ref() == Some(&before)
    }
}

/// Review an inconclusive trial with its bounded observations.
///
/// Unlike a static
/// review this explicitly asks the user to accept incomplete evidence. The
/// caller must revalidate the exact-version fingerprint after authentication.
pub fn request_trial(
    command: &str,
    cwd: &Path,
    summary: &str,
    agent: &str,
    scope: ApprovalScope,
    fingerprint: &crate::trial_store::Fingerprint,
    evidence: Option<&ReviewSnapshot>,
) -> bool {
    let Some(_lock) = review_lock() else {
        return false;
    };
    let Some(before) = directory_identity(cwd) else {
        return false;
    };
    let Some(description) = trial_description(
        command,
        cwd,
        summary,
        agent,
        scope,
        &fingerprint.resolved_executables,
        evidence,
    ) else {
        return false;
    };
    native_dialog(&description, &format!("{:032x}", rand::random::<u128>()))
        && directory_identity(cwd).as_ref() == Some(&before)
}

fn trial_description(
    command: &str,
    cwd: &Path,
    summary: &str,
    agent: &str,
    scope: ApprovalScope,
    executables: &[PathBuf],
    evidence: Option<&ReviewSnapshot>,
) -> Option<ReviewDescription> {
    let mut text = format!(
        "Arbeitsordner:\n{}\n\nGenauer Aufruf:\n{}\n\n{}\n\nFreigabe trotz unvollständiger Sandbox-Prüfung? Bei unklaren Folgen ablehnen.",
        visible(&cwd.display().to_string()),
        visible(command),
        visible(summary)
    );
    for path in executables {
        let _ = write!(
            text,
            "\n\nAufgelöste ausführbare Datei:\n{}",
            visible(&path.display().to_string())
        );
    }
    if let Some(evidence) = evidence {
        for item in &evidence.scripts {
            let _ = write!(
                text,
                "\n\nSkript {} (vollständiger geprüfter Inhalt):\n",
                visible(&item.path.display().to_string())
            );
            for line in item.source.lines() {
                let _ = writeln!(text, "  | {}", visible(line));
                if text.len() > MAX_REVIEW_TEXT {
                    return None;
                }
            }
        }
    }
    if text.len() > MAX_REVIEW_TEXT {
        return None;
    }
    Some(ReviewDescription {
        agent: agent_label(agent),
        host: None,
        project: visible_inline(&cwd.file_name().unwrap_or_default().to_string_lossy()),
        repository: repository_root(cwd).map(|p| visible_inline(&p.display().to_string())),
        cwd: visible(&cwd.display().to_string()),
        title: if scope == ApprovalScope::OneTime {
            "Genauen Aufruf einmalig prüfen"
        } else {
            "Unvollständigen Sandbox-Test prüfen"
        }
        .to_owned(),
        effect: "Der echte Befehl darf nach Freigabe außerhalb der Sandbox laufen.".to_owned(),
        warning: Some("Ein einzelner Testlauf beweist keine allgemeine Sicherheit.".to_owned()),
        command: visible(command),
        executables: executables
            .iter()
            .map(|path| visible(&path.display().to_string()))
            .collect(),
        targets: Vec::new(),
        text,
        scope,
        scope_text: scope.sentence().to_owned(),
    })
}

fn repository_root(cwd: &Path) -> Option<PathBuf> {
    cwd.ancestors()
        .find(|path| {
            fs::symlink_metadata(path.join(".git"))
                .is_ok_and(|metadata| metadata.is_file() || metadata.is_dir())
        })
        .map(Path::to_path_buf)
}

fn agent_label(agent: &str) -> String {
    match agent {
        "codex" | "codex-cli" => "Codex".to_owned(),
        "claude" | "claude-code" => "Claude Code".to_owned(),
        "pi" => "Pi".to_owned(),
        "unknown" => "Unbekannter Agent".to_owned(),
        other => visible_inline(other),
    }
}

fn host_label(orca: bool, cmux: bool) -> Option<String> {
    match (orca, cmux) {
        (true, true) => Some("Orca · cmux".to_owned()),
        (true, false) => Some("Orca".to_owned()),
        (false, true) => Some("cmux".to_owned()),
        (false, false) => None,
    }
}

fn action_title(pack: &str, pattern: &str, targets: &[String]) -> String {
    if pack == "core.filesystem" && !pattern.contains("truncate") && !pattern.contains("redirect") {
        if let [target] = targets
            && Path::new(target).is_absolute()
            && let Some(name) = Path::new(target)
                .file_name()
                .and_then(|name| name.to_str())
                .map(visible_inline)
            && name.len() <= 80
        {
            return format!("„{name}“ löschen");
        }
        if targets.len() > 1 && targets.iter().all(|target| Path::new(target).is_absolute()) {
            return format!("{} Dateien oder Ordner löschen", targets.len());
        }
    }
    match pack {
        "core.filesystem" if pattern.contains("truncate") || pattern.contains("redirect") => {
            "Dateien überschreiben oder leeren"
        }
        "core.filesystem" => "Dateien oder Ordner löschen",
        "core.git" if pattern.contains("reset-hard") => {
            "Dateien auf einen gespeicherten Stand zurücksetzen"
        }
        "core.git" if pattern.contains("clean") => "Nicht in Git gespeicherte Dateien löschen",
        "core.git" if pattern.contains("branch") => "Lokale Git-Branches verändern",
        "core.git" => "Gespeicherte Arbeit verändern",
        other if other.starts_with("system.disk") => "Datenträger verändern",
        _ => "Daten verändern oder löschen",
    }
    .to_owned()
}

// Literal rm operands are shown in ordinary language as concrete paths.
// Shell expansions require a revised command with literal targets; we never
// pretend the guard knows the future value of a variable or glob.
fn removal_targets(source: &str, cwd: &Path) -> Option<Vec<String>> {
    let ast = AstGrep::new(source, SupportLang::Bash);
    let mut pending = vec![ast.root()];
    let mut targets = Vec::new();
    while let Some(node) = pending.pop() {
        if node.kind().as_ref() == "command" {
            let text = node.text();
            let normalized = strip_wrapper_prefixes(&text);
            let words = shell_words::split(&normalized.normalized).ok()?;
            let tool = words.first().and_then(|word| word.rsplit('/').next());
            if matches!(
                tool,
                Some("rm" | "find" | "unlink" | "truncate" | "git" | "dd")
            ) && text.contains(['$', '`'])
            {
                return None;
            }
            if matches!(tool, Some("rm" | "unlink")) {
                let effective_cwd = crate::rebase_recovery::resolve_effective_cwd(
                    cwd,
                    &source[..node.range().end],
                    crate::normalize::ShellDialect::Posix,
                )?;
                let mut operands = false;
                for word in words.iter().skip(1) {
                    if !operands && word == "--" {
                        operands = true;
                        continue;
                    }
                    if !operands && word.starts_with('-') {
                        continue;
                    }
                    if word.contains(['$', '`', '*', '?', '[', '{', '~']) {
                        return None;
                    }
                    let target = effective_cwd.join(word);
                    targets.push(target.display().to_string());
                }
            } else if tool == Some("git") {
                if let Some(index) = words.iter().position(|word| word == "branch") {
                    for word in words
                        .iter()
                        .skip(index + 1)
                        .filter(|word| !word.starts_with('-'))
                    {
                        targets.push(format!("Git-Branch: {word}"));
                    }
                } else if let Some(index) = words.iter().position(|word| word == "reset") {
                    let target = words
                        .iter()
                        .skip(index + 1)
                        .find(|word| !word.starts_with('-'))
                        .map_or("HEAD", String::as_str);
                    targets.push(format!("Git-Zielstand: {target}"));
                }
            } else if tool == Some("find") && words.iter().any(|word| word == "-delete") {
                let effective_cwd = crate::rebase_recovery::resolve_effective_cwd(
                    cwd,
                    &source[..node.range().end],
                    crate::normalize::ShellDialect::Posix,
                )?;
                let mut found_root = false;
                for word in words
                    .iter()
                    .skip(1)
                    .skip_while(|word| matches!(word.as_str(), "-H" | "-L" | "-P"))
                {
                    if word.starts_with('-') || word == "(" || word == "!" {
                        break;
                    }
                    if word.contains(['$', '`', '*', '?', '[', '{', '~']) {
                        return None;
                    }
                    targets.push(format!(
                        "Suchbereich: {} (Dateien, die den Suchbedingungen entsprechen)",
                        effective_cwd.join(word).display()
                    ));
                    found_root = true;
                }
                if !found_root {
                    targets.push(format!(
                        "Suchbereich: {} (aktueller Ordner und Unterordner)",
                        effective_cwd.display()
                    ));
                }
            }
        }
        pending.extend(node.children());
    }
    Some(targets)
}

fn effect_description(pack: &str, pattern: &str) -> &'static str {
    if pack == "core.filesystem" {
        if pattern.contains("truncate") || pattern.contains("redirect") {
            "Der bisherige Dateiinhalt kann verloren gehen."
        } else {
            "Es wird kein Papierkorb verwendet. Ohne Backup sind die Daten meist verloren."
        }
    } else if pack == "core.git" && pattern.contains("reset-hard") {
        "Nicht in Git gespeicherte Änderungen gehen verloren."
    } else if pack == "core.git" && pattern.contains("clean") {
        "Git kann diese Dateien danach meist nicht wiederherstellen."
    } else if pack == "core.git" && pattern.contains("branch") {
        "Nur dort gespeicherte Arbeit kann schwerer wiederzufinden sein."
    } else if pack == "core.git" {
        "Vorhandene Arbeit oder der bisherige Verlauf können verloren gehen."
    } else if pack.starts_with("system.disk") {
        "Viele Daten können unwiederbringlich verloren gehen."
    } else {
        "Vorhandene Daten oder Ressourcen können verloren gehen."
    }
}

fn visible(text: &str) -> String {
    text.chars().flat_map(|ch| {
        if (ch.is_control() && ch != '\n' && ch != '\t')
            || matches!(ch, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            ch.escape_unicode().collect::<Vec<_>>()
        } else {
            vec![ch]
        }
    }).collect()
}

fn visible_inline(text: &str) -> String {
    visible(text).replace('\n', "\\n").replace('\t', "\\t")
}

fn read_regular_source(path: &Path) -> Option<Vec<u8>> {
    // Reject symlinks in parent components as well as the final component.
    let mut prefix = PathBuf::new();
    for component in path.components() {
        prefix.push(component);
        if fs::symlink_metadata(&prefix).ok()?.file_type().is_symlink() {
            return None;
        }
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let file = options.open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > MAX_SOURCE_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_SOURCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= MAX_SOURCE_BYTES).then_some(bytes)
}

#[derive(PartialEq, Eq)]
struct DirectoryIdentity {
    canonical: PathBuf,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

fn directory_identity(path: &Path) -> Option<DirectoryIdentity> {
    if !path.is_absolute() {
        return None;
    }
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_dir() {
        return None;
    }
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    Some(DirectoryIdentity {
        canonical: fs::canonicalize(path).ok()?,
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
    })
}

fn review_lock() -> Option<File> {
    let directory = crate::config::user_config_dir()?;
    fs::create_dir_all(&directory).ok()?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(directory.join("desktop-review.lock")).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    file.try_lock_exclusive().ok()?;
    Some(file)
}

#[cfg(target_os = "macos")]
const DIALOG_HELPER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/DCG"));

/// Materialize only the exact native program embedded at build time. A corrupt
/// or replaced cache entry is refused, never executed or silently overwritten.
#[cfg(target_os = "macos")]
fn prepare_native_helper_in(base: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    let mut digest = String::with_capacity(64);
    for byte in Sha256::digest(DIALOG_HELPER) {
        let _ = write!(digest, "{byte:02x}");
    }
    let directory = base.join(digest);
    let path = directory.join("DCG");
    let mut prefix = PathBuf::new();
    for component in path.components() {
        prefix.push(component);
        match fs::symlink_metadata(&prefix) {
            Ok(metadata) if metadata.file_type().is_symlink() => return None,
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return None,
            _ => {}
        }
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&directory)
        .ok()?;
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(mut file) => {
            file.write_all(DIALOG_HELPER).ok()?;
            file.sync_all().ok()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return None,
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(&path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o122 != 0o100 {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(DIALOG_HELPER.len() as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes == DIALOG_HELPER).then_some(path)
}

#[cfg(target_os = "macos")]
fn approved_reply(success: bool, output: &str, nonce: &str) -> bool {
    success && output.trim() == format!("approved:{nonce}")
}

#[cfg(target_os = "macos")]
fn native_dialog(description: &ReviewDescription, nonce: &str) -> bool {
    let Some(base) = crate::config::user_config_dir() else {
        return false;
    };
    let Some(helper) = prepare_native_helper_in(&base.join("dcg/desktop-review")) else {
        crate::emit_stderr!(
            "[dcg] Touch-ID-Dialog nicht verfügbar oder verändert. Der Vorgang bleibt gestoppt."
        );
        return false;
    };
    let Ok(payload) =
        serde_json::to_vec(&serde_json::json!({"description": description, "nonce": nonce}))
    else {
        return false;
    };
    if payload.len() > 32_768 {
        return false;
    }
    let Ok(mut child) = Command::new(helper)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    else {
        return false;
    };
    // Full commands and script contents travel through stdin, never through
    // shell interpolation or process-list-visible command-line arguments.
    if child
        .stdin
        .take()
        .is_none_or(|mut stream| stream.write_all(&payload).is_err())
    {
        let _ = child.kill();
        let _ = child.wait();
        return false;
    }
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    if let Some(stream) = child.stderr.take() {
                        let mut error = String::new();
                        let _ = stream.take(2048).read_to_string(&mut error);
                        crate::emit_stderr!(
                            "[dcg] Desktop-Dialog fehlgeschlagen: {}",
                            visible(&error)
                        );
                    }
                    return false;
                }
                let mut output = String::new();
                return child.stdout.take().is_some_and(|stream| {
                    stream.take(129).read_to_string(&mut output).is_ok()
                        && output.len() <= 128
                        && approved_reply(status.success(), &output, nonce)
                });
            }
            Ok(None) if start.elapsed() < Duration::from_secs(DIALOG_SECONDS + 5) => {
                std::thread::sleep(Duration::from_millis(25));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn native_dialog(_: &ReviewDescription, _: &str) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_scope_has_one_truthful_localized_persistence_sentence() {
        assert_eq!(ApprovalScope::trial(true, false), ApprovalScope::OneTime);
        assert_eq!(ApprovalScope::trial(true, true), ApprovalScope::ExactVersion);
        assert_eq!(ApprovalScope::trial(false, true), ApprovalScope::OneTime);
        assert_eq!(ApprovalScope::trial(false, false), ApprovalScope::OneTime);
        let sentences = [
            ApprovalScope::OneTime,
            ApprovalScope::ExactVersion,
            ApprovalScope::LearnedFilesystem,
            ApprovalScope::Confined,
        ]
        .map(ApprovalScope::sentence);
        assert!(sentences[0].contains("keine wiederverwendbare Ausnahme"));
        assert!(sentences[1].contains("exakte Befehls- und Projektversion"));
        assert!(sentences[2].contains("Dateisystemobjekte"));
        assert!(sentences[3].contains("keine Freigabe gespeichert"));
        assert!(
            sentences
                .iter()
                .all(|text| !text.contains("Runtime inputs"))
        );
    }

    #[test]
    fn descriptions_serialize_the_selected_scope_and_preserve_the_full_command() {
        let temp = tempfile::tempdir().unwrap();
        let command = format!("node --test '{}'", "long-but-literal".repeat(20));
        for (scope, wire) in [
            (ApprovalScope::OneTime, "one_time"),
            (ApprovalScope::ExactVersion, "exact_version"),
        ] {
            let mut description = trial_description(
                &command,
                temp.path(),
                "Die Beobachtung ist unvollständig.",
                "claude-code",
                ApprovalScope::OneTime,
                &[PathBuf::from("/usr/bin/node")],
                None,
            )
            .unwrap();
            description.set_scope(scope);
            let json = serde_json::to_value(&description).unwrap();
            assert_eq!(json["scope"], wire);
            assert_eq!(json["scope_text"], scope.sentence());
            assert_eq!(json["command"], command);
            assert_eq!(json["executables"][0], "/usr/bin/node");
            assert!(description.text.contains(&command));
            assert!(description.text.contains(temp.path().to_str().unwrap()));
            assert!(!description.text.contains("Die Freigabe gilt"));
            assert!(!description.text.contains("Runtime inputs"));
        }
        assert!(
            trial_description(
                &"x".repeat(MAX_REVIEW_TEXT),
                temp.path(),
                "Prüfung",
                "pi",
                ApprovalScope::OneTime,
                &[],
                None,
            )
            .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn literal_cargo_review_shows_the_bound_executable_and_source_evidence() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("project");
        fs::create_dir(&project).unwrap();
        let bin = temp.path().join("bin");
        fs::create_dir(&bin).unwrap();
        let cargo = bin.join("cargo");
        fs::write(&cargo, "fixture executable bytes, never executed").unwrap();
        fs::set_permissions(&cargo, fs::Permissions::from_mode(0o700)).unwrap();
        let shell = temp.path().join("shell");
        fs::write(&shell, "fixture shell bytes, never executed").unwrap();
        let source_path = project.join("check.sh");
        fs::write(&source_path, "echo harmless\n").unwrap();
        let capture = ReviewCapture::start();
        record_script(
            &source_path,
            "echo harmless\n",
            &project,
            ScriptLanguage::Bash,
        );
        let evidence = capture.snapshot();
        let command = format!(
            "/usr/bin/env -i HOME=/tmp/h PATH={} cargo test",
            shell_words::quote(bin.to_str().unwrap())
        );
        let store = crate::trial_store::TrialStore::new(temp.path().join("trusted"));
        let version = store
            .fingerprint(&command, &project, &shell, &evidence.resolved_paths())
            .unwrap();
        assert!(!version.reproducible);
        let description = trial_description(
            &command,
            &project,
            "Bitte den genauen Aufruf prüfen.",
            "codex",
            ApprovalScope::OneTime,
            &version.resolved_executables,
            Some(&evidence),
        )
        .unwrap();
        let resolved = cargo.canonicalize().unwrap().display().to_string();
        assert!(description.executables.contains(&resolved));
        assert!(description.text.contains(&resolved));
        assert!(description.text.contains("  | echo harmless"));
        assert_eq!(description.command, command);
        assert_eq!(description.scope, ApprovalScope::OneTime);
    }

    fn match_info(pattern: &str) -> PatternMatch {
        PatternMatch {
            pack_id: Some("core.filesystem".to_string()),
            pattern_name: Some(pattern.to_string()),
            severity: None,
            reason: "recursive deletion".to_string(),
            source: crate::evaluator::MatchSource::Pack,
            matched_span: None,
            matched_text_preview: None,
            explanation: None,
            suggestions: &[],
        }
    }

    #[test]
    fn literal_deletion_has_readable_effect_and_absolute_target() {
        let root = tempfile::tempdir().unwrap();
        let cwd = root.path().canonicalize().unwrap();
        let capture = ReviewCapture::start();
        let snapshot = capture.snapshot();
        let text = snapshot
            .description("rm -rf './old files'", &cwd, &match_info("rm-rf"), "Codex")
            .unwrap();
        assert!(text.text.contains("kein Papierkorb"));
        assert!(
            text.text
                .contains(&cwd.join("./old files").display().to_string())
        );
        assert_eq!(text.command, "rm -rf './old files'");
        assert_eq!(text.title, "„old files“ löschen");
        assert!(!text.title.contains(&cwd.display().to_string()));
        assert!(text.scope_text.contains("keine wiederverwendbare Ausnahme"));
    }

    #[test]
    fn compact_action_keeps_multiple_and_long_targets_complete_in_details() {
        let root = tempfile::tempdir().unwrap();
        let cwd = root.path().canonicalize().unwrap();
        let capture = ReviewCapture::start();
        let snapshot = capture.snapshot();
        let multiple = snapshot
            .description("rm -rf old backup", &cwd, &match_info("rm-rf"), "Codex")
            .unwrap();
        assert_eq!(multiple.title, "2 Dateien oder Ordner löschen");
        for target in ["old", "backup"] {
            assert!(
                multiple
                    .text
                    .contains(&cwd.join(target).display().to_string())
            );
        }
        let long_name = "🗂".repeat(30);
        let long = snapshot
            .description(
                &format!("rm -rf '{long_name}'"),
                &cwd,
                &match_info("rm-rf"),
                "Codex",
            )
            .unwrap();
        assert_eq!(long.title, "Dateien oder Ordner löschen");
        assert!(long.title.len() <= 128);
        assert!(
            long.text
                .contains(&cwd.join(long_name).display().to_string())
        );
    }

    #[test]
    fn dynamic_targets_and_incomplete_checks_cannot_be_approved() {
        let root = tempfile::tempdir().unwrap();
        let cwd = root.path().canonicalize().unwrap();
        let capture = ReviewCapture::start();
        assert!(
            capture
                .snapshot()
                .description("rm -rf $T", &cwd, &match_info("rm-rf"), "Codex")
                .is_none()
        );
        record_incomplete();
        assert!(
            capture
                .snapshot()
                .description("rm -rf ./old", &cwd, &match_info("rm-rf"), "Codex")
                .is_none()
        );
    }

    #[test]
    fn unchanged_request_can_be_approved_or_declined_without_a_grant_file() {
        let root = tempfile::tempdir().unwrap();
        let cwd = root.path().canonicalize().unwrap();
        let capture = ReviewCapture::start();
        let snapshot = capture.snapshot();
        let description = snapshot
            .description("rm -rf old", &cwd, &match_info("rm-rf"), "Codex")
            .unwrap();
        assert!(snapshot.request_with(&description, &cwd, |text, nonce| {
            assert_eq!(nonce.len(), 32);
            assert!(!text.text.contains(nonce));
            assert_eq!(text.agent, "Codex");
            true
        }));
        assert!(!snapshot.request_with(&description, &cwd, |_, _| false));
        assert_eq!(fs::read_dir(cwd).unwrap().count(), 0);
    }

    #[test]
    fn oversized_review_is_refused_without_hiding_source() {
        let root = tempfile::tempdir().unwrap();
        let cwd = root.path().canonicalize().unwrap();
        let capture = ReviewCapture::start();
        record_script(
            &cwd.join("long.sh"),
            &"# long source\n".repeat(500),
            &cwd,
            ScriptLanguage::Bash,
        );
        assert!(
            capture
                .snapshot()
                .description("bash long.sh", &cwd, &match_info("rm-rf"), "Codex")
                .is_none()
        );
    }

    #[test]
    fn symlink_substitution_cannot_use_approval() {
        #[cfg(unix)]
        {
            let root = tempfile::tempdir().unwrap();
            let cwd = root.path().canonicalize().unwrap();
            let real = cwd.join("real.sh");
            let alias = cwd.join("alias.sh");
            fs::write(&real, "git reset --hard HEAD").unwrap();
            let capture = ReviewCapture::start();
            record_script(&alias, "git reset --hard HEAD", &cwd, ScriptLanguage::Bash);
            std::os::unix::fs::symlink(real, alias).unwrap();
            assert!(!capture.snapshot().unchanged());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "manual macOS dialog; no candidate command is executed"]
    fn native_dialog_manual_preview() {
        let capture = ReviewCapture::start();
        let cwd = std::env::current_dir().unwrap();
        let mut description = capture
            .snapshot()
            .description(
                "rm -rf /Beispiel/alter-Ordner",
                &cwd,
                &match_info("rm-rf"),
                "Codex",
            )
            .unwrap();
        description.title = "Harmloser Dialogtest".to_owned();
        description.effect = "Es wird kein Befehl ausgeführt und nichts gelöscht. Finger auflegen testet nur diesen Dialog.".to_owned();
        let approved = native_dialog(&description, "00000000000000000000000000000001");
        eprintln!("Manual preview approved: {approved}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn focus_controller_handles_cancelled_and_stale_biometric_attempts() {
        let root = tempfile::tempdir().unwrap();
        let binary = root.path().join("controller-tests");
        let source = Path::new(env!("CARGO_MANIFEST_DIR"));
        let compiled = Command::new("/usr/bin/swiftc")
            .args([
                "-swift-version",
                "5",
                "-parse-as-library",
                "-warnings-as-errors",
                "-D",
                "DCG_UI_PREVIEW",
            ])
            .arg(source.join("src/desktop_review.swift"))
            .arg(source.join("tests/desktop_review_controller.swift"))
            .arg("-module-cache-path")
            .arg(root.path().join("swift-modules"))
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let output = Command::new(binary).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("13 controller cases passed"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_helper_cache_refuses_modified_bytes_and_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let path = prepare_native_helper_in(&root).unwrap();
        assert_eq!(prepare_native_helper_in(&root), Some(path.clone()));
        fs::write(&path, b"replaced program").unwrap();
        assert!(prepare_native_helper_in(&root).is_none());
        assert_eq!(fs::read(path).unwrap(), b"replaced program");
        let target = root.join("outside");
        fs::create_dir(&target).unwrap();
        let alias = root.join("alias");
        std::os::unix::fs::symlink(&target, &alias).unwrap();
        assert!(prepare_native_helper_in(&alias).is_none());
        assert_eq!(fs::read_dir(target).unwrap().count(), 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_helper_requires_valid_input_and_bound_success_reply() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let helper = prepare_native_helper_in(&root).unwrap();
        for input in ["{}", "null", r#"{"text":"example","nonce":"123456"}"#] {
            let mut child = Command::new(&helper)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(!output.status.success());
            assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "denied");
        }
        let nonce = "00000000000000000000000000000001";
        assert!(approved_reply(true, &format!("approved:{nonce}\n"), nonce));
        assert!(!approved_reply(false, &format!("approved:{nonce}"), nonce));
        for reply in [
            "denied",
            "approved:other",
            "approved:",
            "approved:other\napproved:00000000000000000000000000000001",
        ] {
            assert!(!approved_reply(true, reply, nonce));
        }
    }

    #[test]
    fn changed_script_cannot_use_approval() {
        let root = tempfile::tempdir().unwrap();
        let cwd = root.path().canonicalize().unwrap();
        let script = cwd.join("helper.sh");
        fs::write(&script, "git reset --hard HEAD\n").unwrap();
        let capture = ReviewCapture::start();
        record_script(
            &script,
            "git reset --hard HEAD\n",
            &cwd,
            ScriptLanguage::Bash,
        );
        let snapshot = capture.snapshot();
        assert!(snapshot.unchanged());
        fs::write(script, "git clean -fd\n").unwrap();
        assert!(!snapshot.unchanged());
    }

    #[test]
    fn deletion_targets_follow_static_cd_and_find_scope() {
        let root = tempfile::tempdir().unwrap();
        let cwd = root.path().canonicalize().unwrap();
        fs::create_dir(cwd.join("sub")).unwrap();
        let targets = removal_targets("cd sub && rm -rf old", &cwd).unwrap();
        assert_eq!(targets, vec![cwd.join("sub/old").display().to_string()]);
        let targets = removal_targets("find ./old -type f -delete", &cwd).unwrap();
        assert!(targets[0].contains(&cwd.join("./old").display().to_string()));
        assert!(removal_targets("find $T -type f -delete", &cwd).is_none());
        assert!(removal_targets("git branch -D $BRANCH", &cwd).is_none());
    }

    #[test]
    fn later_sibling_helper_is_bound_even_after_first_denial() {
        let root = tempfile::tempdir().unwrap();
        let cwd = root.path().canonicalize().unwrap();
        fs::write(cwd.join("first.sh"), "git reset --hard HEAD\n").unwrap();
        fs::write(cwd.join("second.sh"), "printf safe\n").unwrap();
        let capture = ReviewCapture::start();
        let result = crate::script_files::evaluate(
            "bash first.sh; bash second.sh",
            Some(&cwd),
            crate::normalize::ShellDialect::Posix,
            false,
            None,
            false,
            |_, _, _| crate::evaluator::EvaluationResult::denied_by_legacy("test finding"),
        );
        assert!(result.is_some());
        let snapshot = capture.snapshot();
        assert_eq!(snapshot.scripts.len(), 2);
        assert!(snapshot.unchanged());
        fs::write(cwd.join("second.sh"), "git clean -fd\n").unwrap();
        assert!(!snapshot.unchanged());
    }

    #[test]
    fn invisible_controls_are_visible_data() {
        assert_eq!(visible("rm \u{202e}\u{1b}safe"), "rm \\u{202e}\\u{1b}safe");
        assert_eq!(visible("a\nb"), "a\nb");
    }

    #[test]
    fn approval_requires_unchanged_script_after_answer() {
        let root = tempfile::tempdir().unwrap();
        let cwd = root.path().canonicalize().unwrap();
        let path = cwd.join("script.sh");
        fs::write(&path, "git reset --hard HEAD").unwrap();
        let capture = ReviewCapture::start();
        record_script(&path, "git reset --hard HEAD", &cwd, ScriptLanguage::Bash);
        let snapshot = capture.snapshot();
        let description = snapshot
            .description("bash script.sh", &cwd, &match_info("rm-rf"), "Codex")
            .unwrap();
        assert!(!snapshot.request_with(&description, &cwd, |_, _| {
            fs::write(&path, "git clean -fd").unwrap();
            true
        }));
    }

    #[test]
    fn context_finds_nested_repo_and_linked_worktree_without_running_git() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().canonicalize().unwrap();
        let cwd = repo.join("src/nested");
        fs::create_dir_all(&cwd).unwrap();
        fs::create_dir(repo.join(".git")).unwrap();
        let capture = ReviewCapture::start();
        let description = capture
            .snapshot()
            .description("rm -rf old", &cwd, &match_info("rm-rf"), "pi")
            .unwrap();
        assert_eq!(description.agent, "Pi");
        assert_eq!(description.repository, Some(repo.display().to_string()));
        assert_eq!(description.cwd, cwd.display().to_string());
        let worktree = repo.join("linked");
        fs::create_dir(&worktree).unwrap();
        fs::write(
            worktree.join(".git"),
            "gitdir: /elsewhere/worktrees/linked\n",
        )
        .unwrap();
        assert_eq!(repository_root(&worktree), Some(worktree));
    }

    #[test]
    fn absent_repo_and_inline_control_characters_are_unambiguous() {
        let root = tempfile::tempdir().unwrap();
        let cwd = root.path().canonicalize().unwrap();
        let capture = ReviewCapture::start();
        let description = capture
            .snapshot()
            .description(
                "rm -rf old",
                &cwd,
                &match_info("rm-rf"),
                "fake\nCodex\u{202e}",
            )
            .unwrap();
        assert!(description.repository.is_none());
        assert_eq!(description.agent, "fake\\nCodex\\u{202e}");
        assert_eq!(agent_label("claude-code"), "Claude Code");
        assert_eq!(host_label(true, true).as_deref(), Some("Orca · cmux"));
        assert_eq!(host_label(false, true).as_deref(), Some("cmux"));
        assert_eq!(host_label(false, false), None);
    }

    #[test]
    fn remote_action_warning_stays_visible_in_compact_summary() {
        let root = tempfile::tempdir().unwrap();
        let cwd = root.path().canonicalize().unwrap();
        let capture = ReviewCapture::start();
        let description = capture
            .snapshot()
            .description(
                "ssh example.test 'rm -rf old'",
                &cwd,
                &match_info("rm-rf"),
                "Codex",
            )
            .unwrap();
        assert!(
            description
                .warning
                .as_deref()
                .unwrap()
                .contains("anderen Rechner")
        );
        assert!(description.text.contains("entfernten Rechner"));
    }
}
