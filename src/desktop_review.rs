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
    static INCOMPLETE: Cell<bool> = const { Cell::new(false) };
}

/// Captures the actual bytes read by the evaluator on this thread.
pub struct ReviewCapture;

impl ReviewCapture {
    pub fn start() -> Self {
        EVIDENCE.with(|slot| *slot.borrow_mut() = Some(Vec::new()));
        INCOMPLETE.with(|value| value.set(false));
        Self
    }

    /// Freeze the evidence for this one pending request.
    pub fn snapshot(&self) -> ReviewSnapshot {
        ReviewSnapshot {
            scripts: EVIDENCE.with(|slot| slot.borrow().clone().unwrap_or_default()),
            incomplete: INCOMPLETE.with(Cell::get),
        }
    }
}

impl Drop for ReviewCapture {
    fn drop(&mut self) {
        EVIDENCE.with(|slot| *slot.borrow_mut() = None);
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

/// No persistent approval is created: the caller may release only this request.
pub struct ReviewSnapshot {
    scripts: Vec<ScriptEvidence>,
    incomplete: bool,
}

impl ReviewSnapshot {
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
    ) -> Option<String> {
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
        let mut text = format!(
            "Agent: {}\n\nWas kann passieren?\n{effect}\n\nArbeitsordner:\n{}\n\nGenauer Aufruf:\n{}\n\nAuslöser der Rückfrage:\n{}\nRegel: {}:{}\n",
            visible(agent),
            visible(&cwd.display().to_string()),
            visible(command),
            visible(&info.reason),
            visible(pack),
            visible(pattern),
        );
        if !targets.is_empty() {
            text.push_str("\nBetroffene Ziele:\n");
            for target in targets {
                text.push_str("  • ");
                text.push_str(&visible(&target));
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
        text.push_str("\nDie Freigabe gilt einmal für den gesamten Aufruf oben, einschließlich weiterer Skriptschritte. Es wird keine dauerhafte Ausnahme angelegt. Bei unklaren Zielen ablehnen.");
        (text.len() <= MAX_REVIEW_TEXT).then_some(text)
    }

    /// Show a local modal dialog, then recheck every captured source byte and
    /// cwd identity. An explicit button AND fresh Touch ID are required.
    pub fn request(&self, description: &str, cwd: &Path) -> bool {
        let Some(_lock) = review_lock() else {
            return false;
        };
        self.request_with(description, cwd, native_dialog)
    }

    fn request_with(
        &self,
        description: &str,
        cwd: &Path,
        dialog: impl FnOnce(&str, &str) -> bool,
    ) -> bool {
        let Some(before) = directory_identity(cwd) else {
            return false;
        };
        if !self.unchanged() || description.len() > MAX_REVIEW_TEXT {
            return false;
        }
        let nonce = format!("{:032x}", rand::random::<u128>());
        let text = format!(
            "{description}\n\nZum Erlauben „Einmal freigeben“ wählen und mit Touch ID bestätigen. Ohne Antwort bleibt der Vorgang nach {DIALOG_SECONDS} Sekunden gestoppt."
        );
        dialog(&text, &nonce)
            && self.unchanged()
            && directory_identity(cwd).as_ref() == Some(&before)
    }
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
            "Vorhandene Dateien können überschrieben oder geleert werden. Der bisherige Inhalt kann dabei verloren gehen."
        } else {
            "Dateien oder Ordner können dauerhaft gelöscht werden. Bei rekursivem Löschen betrifft das auch alle enthaltenen Dateien und Unterordner. Es wird kein Papierkorb verwendet; eine Wiederherstellung benötigt meist ein Backup. Die Ziele stehen im Aufruf bzw. Skript unten."
        }
    } else if pack == "core.git" && pattern.contains("reset-hard") {
        "Nicht gespeicherte Änderungen an von Git verwalteten Dateien werden verworfen. Dateien werden auf den gewählten Git-Stand zurückgesetzt; dabei können Dateien verschwinden. Nicht eingecheckte Arbeit kann verloren gehen."
    } else if pack == "core.git" && pattern.contains("clean") {
        "Git entfernt Dateien und gegebenenfalls Ordner, die nicht in der Versionsverwaltung gespeichert sind. Diese Dateien sind anschließend auch über Git meist nicht wiederherstellbar."
    } else if pack == "core.git" && pattern.contains("branch") {
        "Lokale Git-Branches können gelöscht oder ersetzt werden. Nur darüber erreichbare Arbeit kann schwerer wiederzufinden sein; eine erzwungene Löschung prüft nicht, ob sie bereits übernommen wurde."
    } else if pack == "core.git" {
        "Dieser Git-Aufruf kann vorhandene Arbeit verwerfen oder die Versionsgeschichte verändern. Prüfe den unten genannten Git-Vorgang und seine Ziele."
    } else if pack.starts_with("system.disk") {
        "Datenträger oder Dateisysteme können überschrieben, formatiert oder anderweitig verändert werden. Dabei können sehr viele Daten unwiederbringlich verloren gehen."
    } else {
        "Der Aufruf enthält einen als destruktiv erkannten Vorgang. Vorhandene Daten oder Ressourcen können gelöscht, überschrieben oder verändert werden. Prüfe die konkrete Aktion und ihre Ziele unten."
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
fn native_dialog(text: &str, nonce: &str) -> bool {
    let Some(base) = crate::config::user_config_dir() else {
        return false;
    };
    let Some(helper) = prepare_native_helper_in(&base.join("dcg/desktop-review")) else {
        crate::emit_stderr!(
            "[dcg] Touch-ID-Dialog nicht verfügbar oder verändert. Der Vorgang bleibt gestoppt."
        );
        return false;
    };
    let Ok(payload) = serde_json::to_vec(&serde_json::json!({"text": text, "nonce": nonce})) else {
        return false;
    };
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
fn native_dialog(_: &str, _: &str) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(text.contains("kein Papierkorb"));
        assert!(text.contains(&cwd.join("./old files").display().to_string()));
        assert!(text.contains("rm -rf './old files'"));
        assert!(text.contains("keine dauerhafte Ausnahme"));
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
        assert!(snapshot.request_with("fixture", &cwd, |text, nonce| {
            assert_eq!(nonce.len(), 32);
            assert!(!text.contains(nonce));
            assert!(text.contains("Touch ID"));
            true
        }));
        assert!(!snapshot.request_with("fixture", &cwd, |_, _| false));
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
        let approved = native_dialog(
            "DIES IST EIN HARMLOSER DIALOGTEST.\n\nEs wird kein Befehl ausgeführt und nichts gelöscht.\n\nBeispiel: Ein alter Ordner samt Inhalt würde dauerhaft gelöscht, ohne Papierkorb.\nZiel: /Beispiel/alter-Ordner\n\nZum Testen „Einmal freigeben“ wählen und danach mit dem Finger bestätigen. Du kannst auch ablehnen.",
            "00000000000000000000000000000001",
        );
        eprintln!("Manual preview approved: {approved}");
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
        assert!(!snapshot.request_with("fixture", &cwd, |_, _| {
            fs::write(&path, "git clean -fd").unwrap();
            true
        }));
    }
}
