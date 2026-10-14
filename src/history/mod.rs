//! Command history database for DCG.
//!
//! This module provides SQLite-based history collection and querying for
//! tracking all commands evaluated by DCG across agent sessions.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      HistoryDb                                   │
//! │  (SQLite database for command history and analytics)            │
//! └─────────────────────────────────────────────────────────────────┘
//!                                  │
//!           ┌──────────────────────┼──────────────────────┐
//!           ▼                      ▼                      ▼
//! ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
//! │  commands table │    │  commands_fts   │    │ schema_version  │
//! │  (main storage) │    │  (full-text)    │    │  (migrations)   │
//! └─────────────────┘    └─────────────────┘    └─────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use destructive_command_guard::history::{HistoryDb, CommandEntry, Outcome};
//!
//! let db = HistoryDb::open(None)?; // Uses default path
//! db.log_command(&CommandEntry {
//!     timestamp: chrono::Utc::now(),
//!     agent_type: "claude_code".into(),
//!     working_dir: "/path/to/project".into(),
//!     command: "git status".into(),
//!     outcome: Outcome::Allow,
//!     ..Default::default()
//! })?;
//! ```

mod queue_budget;
mod schema;
mod sqlite;
mod storage_limits;

use crate::config::{HistoryConfig, HistoryRedactionMode, resolve_config_path_value};
use crate::logging::{RedactionConfig, RedactionMode};
use queue_budget::{QueueBudget, Reservation, ReserveError};
use std::env;
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use tracing::{debug, error, trace, warn};

pub use schema::{
    AgentStat, BackupResult, CURRENT_SCHEMA_VERSION, CheckResult, CommandEntry,
    DEFAULT_DB_FILENAME, ExportFilters, ExportOptions, ExportedData, FrequentBlock,
    HistoryAnalyzer, HistoryDb, HistoryError, HistoryStats, InteractiveAllowlistAuditEntry,
    InteractiveAllowlistOptionType, Outcome, OutcomeStats, PackEffectivenessAnalysis,
    PackRecommendation, PathCluster, PatternEffectiveness, PatternStat, PerformanceStats,
    PotentialGap, ProjectStat, RecommendationType, RuleMetrics, RuleTrend, StatsTrends,
    SuggestionAction, SuggestionAuditEntry, SuggestionCandidate,
};
pub use sqlite::{Connection as HistoryConnection, Row as HistoryRow, SqliteValue};

/// Environment variable to override the history database path.
pub const ENV_HISTORY_DB_PATH: &str = "DCG_HISTORY_DB";

/// Environment variable to disable history collection entirely.
pub const ENV_HISTORY_DISABLED: &str = "DCG_HISTORY_DISABLED";

/// Opt in to terse history lifecycle diagnostics on stderr (`1` or `true`).
///
/// These report acknowledgement deadlines and intentional busy drops without
/// recording commands or changing the hook's timeout, retry, or drop policy.
/// They also let subprocess persistence tests distinguish a known best-effort
/// omission from unexplained data loss. Normal robot/hook output stays silent.
pub const ENV_HISTORY_DIAGNOSTICS: &str = "DCG_HISTORY_DIAGNOSTICS";

/// Maximum admitted entries per writer, including entries in its active batch.
pub const MAX_PENDING_HISTORY_ENTRIES: usize = 4096;

/// Maximum retained entry payload per writer (16 MiB), including string
/// capacities and entry structures. This is not a cap on SQLite's page cache,
/// allocator overhead, or the caller's input allocation.
pub const MAX_PENDING_HISTORY_BYTES: usize = 16 * 1024 * 1024;

/// Flush requests have separate capacity; timeout does not release a queued
/// request's slot. Shutdown never needs either an entry or a flush slot.
pub const MAX_PENDING_HISTORY_FLUSHES: usize = 64;

/// Admission result, not a durability acknowledgement. Accepted entries may
/// still be dropped by the existing best-effort storage policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryEnqueueOutcome {
    /// Admitted to the asynchronous writer.
    Queued,
    /// Collection is disabled for this writer.
    Disabled,
    /// Outstanding entries or their retained bytes exhausted the budget.
    QueueFull,
    /// This entry alone exceeds the retained-payload budget.
    EntryTooLarge,
    /// The worker's receiver has disconnected.
    WorkerUnavailable,
}

/// The machine's hostname for the history `hostname` column (#514).
///
/// Resolved once per process and cached: a hook process records at most a few
/// rows, and the lookup is one syscall on Unix and one environment read on
/// Windows, so it never spawns a process. `None` when the platform gives no
/// usable name; a NULL column then means "unknown", as it always has.
#[must_use]
pub fn local_hostname() -> Option<&'static str> {
    static HOSTNAME: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    HOSTNAME
        .get_or_init(|| resolve_local_hostname().and_then(|raw| normalize_hostname(&raw)))
        .as_deref()
}

#[cfg(unix)]
fn resolve_local_hostname() -> Option<String> {
    nix::unistd::gethostname()
        .ok()
        .map(|name| name.to_string_lossy().into_owned())
}

#[cfg(windows)]
fn resolve_local_hostname() -> Option<String> {
    // Windows sets COMPUTERNAME for every process; it is the NetBIOS name,
    // which is what `hostname.exe` prints.
    env::var("COMPUTERNAME").ok()
}

#[cfg(not(any(unix, windows)))]
fn resolve_local_hostname() -> Option<String> {
    None
}

/// Trim a raw hostname and reject one that is empty or contains control
/// characters, so the column never holds a newline or a terminal escape.
fn normalize_hostname(raw: &str) -> Option<String> {
    let name = raw.trim();
    (!name.is_empty() && !name.chars().any(char::is_control)).then(|| name.to_string())
}

fn history_diagnostic(status: &str, detail: std::fmt::Arguments<'_>) {
    if env::var(ENV_HISTORY_DIAGNOSTICS)
        .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
    {
        use std::io::Write as _;
        // Diagnostics must never turn a closed stderr pipe into a hook panic.
        let _ = writeln!(std::io::stderr(), "[dcg-history] status={status} {detail}");
    }
}

/// Whether [`ENV_HISTORY_DISABLED`] is set to `1` or `true` (case-insensitive).
#[must_use]
pub fn history_disabled_by_env() -> bool {
    env::var(ENV_HISTORY_DISABLED)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Which rule selected the history database path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryPathSource {
    /// The `DCG_HISTORY_DB` environment variable.
    Environment,
    /// `[history] database_path` from the loaded configuration.
    Config,
    /// An existing database at the pre-0.15 location beside `config.toml`.
    LegacyConfigDir,
    /// The platform state directory: `$XDG_STATE_HOME/dcg` or
    /// `~/.local/state/dcg` on Unix, `%LOCALAPPDATA%\dcg` on Windows.
    Default,
}

impl HistoryPathSource {
    /// Short human-readable label for diagnostics.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Environment => "DCG_HISTORY_DB",
            Self::Config => "[history] database_path",
            Self::LegacyConfigDir => "legacy config-directory location",
            Self::Default => "default state directory",
        }
    }
}

/// A history database path together with the rule that selected it.
///
/// Every reader and writer of the history database must go through
/// [`ResolvedHistoryPath::resolve`] so the hook, `dcg history`, `dcg stats`,
/// and `dcg doctor` all agree on one file. Precedence, highest first:
///
/// 1. `DCG_HISTORY_DB` (non-empty; `~` expanded, relative paths resolved
///    against the current directory).
/// 2. `[history] database_path` in the effective configuration.
/// 3. An existing `history.db` beside `config.toml` (the location every
///    release before 0.15 wrote to). It is honored, never moved, so an
///    upgrade keeps its data.
/// 4. The platform state directory. History is state, not configuration, so
///    it no longer defaults into `~/.config/dcg`; sandboxes that mount the
///    config directory read-only keep working.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedHistoryPath {
    /// The database file path.
    pub path: PathBuf,
    /// Which rule selected `path`.
    pub source: HistoryPathSource,
}

impl ResolvedHistoryPath {
    /// Resolve the history database path for `config`.
    #[must_use]
    pub fn resolve(config: &HistoryConfig) -> Self {
        Self::from_parts(
            env::var(ENV_HISTORY_DB_PATH).ok().as_deref(),
            config.expanded_database_path(),
            existing_legacy_db_path(),
            default_state_db_path(),
        )
    }

    /// Resolve without a loaded configuration (env, legacy, then default).
    #[must_use]
    pub fn resolve_without_config() -> Self {
        Self::from_parts(
            env::var(ENV_HISTORY_DB_PATH).ok().as_deref(),
            None,
            existing_legacy_db_path(),
            default_state_db_path(),
        )
    }

    fn from_parts(
        env_override: Option<&str>,
        config_path: Option<PathBuf>,
        existing_legacy: Option<PathBuf>,
        default_path: PathBuf,
    ) -> Self {
        let cwd = env::current_dir().ok();
        if let Some(path) =
            env_override.and_then(|raw| resolve_config_path_value(raw, cwd.as_deref()))
        {
            return Self {
                path,
                source: HistoryPathSource::Environment,
            };
        }
        if let Some(path) = config_path {
            return Self {
                path,
                source: HistoryPathSource::Config,
            };
        }
        if let Some(path) = existing_legacy {
            return Self {
                path,
                source: HistoryPathSource::LegacyConfigDir,
            };
        }
        Self {
            path: default_path,
            source: HistoryPathSource::Default,
        }
    }
}

/// The pre-0.15 database location, if a database already exists there.
///
/// Mirrors the config-directory search in `Config::user_config_path`:
/// `$XDG_CONFIG_HOME`, then `~/.config`, then the platform-native config
/// directory. Only an existing *file* counts; an empty directory does not pin
/// new installs to the old location.
fn existing_legacy_db_path() -> Option<PathBuf> {
    let mut bases: Vec<PathBuf> = Vec::with_capacity(3);
    if let Some(xdg) = env::var_os("XDG_CONFIG_HOME") {
        let xdg = PathBuf::from(xdg);
        if xdg.is_absolute() {
            bases.push(xdg);
        }
    }
    if let Some(home) = crate::config::home_dir() {
        bases.push(home.join(".config"));
    }
    if let Some(native) = crate::config::user_config_dir() {
        bases.push(native);
    }
    bases
        .into_iter()
        .map(|base| base.join("dcg").join(DEFAULT_DB_FILENAME))
        .find(|candidate| candidate.is_file())
}

/// The default database location for new installs.
fn default_state_db_path() -> PathBuf {
    state_db_path_from(
        env::var_os("XDG_STATE_HOME").as_deref(),
        crate::config::home_dir().as_deref(),
        crate::config::user_data_local_dir().as_deref(),
    )
}

/// Pure form of [`default_state_db_path`] for tests.
///
/// Unix: `$XDG_STATE_HOME/dcg/history.db` when set to an absolute path, else
/// `~/.local/state/dcg/history.db` (the XDG Base Directory default for state
/// such as logs and history). Windows: `%LOCALAPPDATA%\dcg\history.db`.
fn state_db_path_from(
    xdg_state_home: Option<&std::ffi::OsStr>,
    home: Option<&Path>,
    windows_local_data: Option<&Path>,
) -> PathBuf {
    let home_state = || home.map(|h| h.join(".local").join("state"));
    let base = if cfg!(windows) {
        windows_local_data
            .map(Path::to_path_buf)
            .or_else(home_state)
    } else {
        xdg_state_home
            .map(Path::new)
            .filter(|p| p.is_absolute())
            .map(Path::to_path_buf)
            .or_else(home_state)
    };
    base.unwrap_or_else(|| PathBuf::from(".local").join("state"))
        .join("dcg")
        .join(DEFAULT_DB_FILENAME)
}

struct QueuedHistoryEntry {
    // Drop the payload before releasing its admission capacity.
    entry: Box<CommandEntry>,
    reservation: Reservation,
}

struct ReservedFlush {
    ack: mpsc::Sender<()>,
    reservation: Reservation,
}

impl ReservedFlush {
    fn acknowledge(self) {
        // A caller awakened by the ack must be able to reserve a new flush.
        drop(self.reservation);
        let _ = self.ack.send(());
    }
}

enum HistoryMessage {
    Entry(QueuedHistoryEntry),
    Flush(ReservedFlush),
    Shutdown(mpsc::Sender<()>),
}

fn retained_entry_bytes(entry: &CommandEntry) -> usize {
    [
        Some(&entry.agent_type),
        Some(&entry.working_dir),
        Some(&entry.command),
        entry.pack_id.as_ref(),
        entry.pattern_name.as_ref(),
        entry.rule_id.as_ref(),
        entry.session_id.as_ref(),
        entry.hostname.as_ref(),
        entry.allowlist_layer.as_ref(),
        entry.bypass_code.as_ref(),
    ]
    .into_iter()
    .flatten()
    .fold(
        std::mem::size_of::<CommandEntry>() + std::mem::size_of::<QueuedHistoryEntry>(),
        |total, value| total.saturating_add(value.capacity()),
    )
}

/// Keep reservations with the storage batch, not merely the channel messages.
/// Fields are ordered so unwinding frees entries before returning capacity.
struct PendingHistoryBatch {
    entries: Vec<CommandEntry>,
    reservations: Vec<Reservation>,
}

impl PendingHistoryBatch {
    fn new(batch_size: usize) -> Self {
        let capacity = batch_size.min(MAX_PENDING_HISTORY_ENTRIES);
        Self {
            entries: Vec::with_capacity(capacity),
            reservations: Vec::with_capacity(capacity),
        }
    }

    fn push(&mut self, queued: QueuedHistoryEntry) {
        self.entries.push(*queued.entry);
        self.reservations.push(queued.reservation);
    }

    fn flush(
        &mut self,
        db: &mut HistoryDb,
        db_path: Option<&PathBuf>,
        history_disabled: &mut bool,
        max_size_bytes: u64,
    ) {
        flush_batch_with_recovery(
            db,
            &mut self.entries,
            db_path,
            history_disabled,
            max_size_bytes,
        );
        // All current outcomes empty the batch, including best-effort drops.
        // If a future recovery path retains entries, retain their reservations
        // too rather than allowing unaccounted payloads to accumulate.
        if self.entries.is_empty() {
            self.reservations.clear();
        }
    }
}

/// Configuration for the history worker thread.
#[derive(Clone)]
struct WorkerConfig {
    batch_size: usize,
    flush_interval: Duration,
    auto_prune: bool,
    retention_days: u32,
    prune_check_interval: Duration,
    max_size_bytes: u64,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            batch_size: 50,
            flush_interval: Duration::from_millis(100),
            auto_prune: false,
            retention_days: 90,
            prune_check_interval: Duration::from_secs(24 * 3600),
            max_size_bytes: 500 * 1024 * 1024,
        }
    }
}

impl From<&HistoryConfig> for WorkerConfig {
    fn from(config: &HistoryConfig) -> Self {
        Self {
            batch_size: (config.batch_size.max(1) as usize).min(MAX_PENDING_HISTORY_ENTRIES),
            flush_interval: Duration::from_millis(u64::from(config.batch_flush_interval_ms.max(1))),
            auto_prune: config.auto_prune,
            retention_days: config
                .retention_days
                .clamp(1, HistoryConfig::MAX_RETENTION_DAYS),
            prune_check_interval: Duration::from_secs(
                u64::from(config.prune_check_interval_hours.max(1)) * 3600,
            ),
            max_size_bytes: u64::from(config.max_size_mb.max(1)).saturating_mul(1024 * 1024),
        }
    }
}

#[derive(Clone)]
pub struct HistoryFlushHandle {
    sender: mpsc::Sender<HistoryMessage>,
    budget: Arc<QueueBudget>,
}

impl HistoryFlushHandle {
    fn request_flush(&self) -> Option<mpsc::Receiver<()>> {
        let reservation = self.budget.try_reserve(1).ok()?;
        let (ack_tx, ack_rx) = mpsc::channel();
        self.sender
            .send(HistoryMessage::Flush(ReservedFlush {
                ack: ack_tx,
                reservation,
            }))
            .ok()?;
        Some(ack_rx)
    }

    /// Request a flush and wait up to the hook-safe bounded timeout.
    ///
    /// History is best-effort telemetry, so lock contention or a stalled
    /// storage worker may cause this to return before the write lands.
    pub fn flush_sync(&self) {
        let _ = self.flush_sync_with_timeout(Duration::from_millis(40));
    }

    /// Request a flush and wait for at most `timeout`.
    ///
    /// Returns `true` only when the worker acknowledged that every entry
    /// queued before this request was processed. Processing can intentionally
    /// drop best-effort telemetry; this is not a durability acknowledgement.
    /// Returns `false` on timeout, worker disconnection, or a full flush-request
    /// budget. Entry saturation does not consume the separate flush budget.
    #[must_use]
    pub fn flush_sync_with_timeout(&self, timeout: Duration) -> bool {
        self.request_flush()
            .is_some_and(|ack_rx| ack_rx.recv_timeout(timeout).is_ok())
    }
}

/// Asynchronous history writer with write batching support.
///
/// Entry admission is bounded by count and retained bytes across both the
/// channel and active batch. Saturation drops telemetry without waiting for
/// storage; use [`Self::try_log`] to inspect that admission result.
pub struct HistoryWriter {
    sender: Option<mpsc::Sender<HistoryMessage>>,
    handle: Option<thread::JoinHandle<()>>,
    entry_budget: Option<Arc<QueueBudget>>,
    flush_budget: Option<Arc<QueueBudget>>,
    redaction_mode: HistoryRedactionMode,
    session_id: String,
    wait_for_worker_on_drop: bool,
    drop_wait_deadline: Option<Instant>,
}

impl HistoryWriter {
    /// Create a new history writer.
    ///
    /// The database path is passed to the worker thread, which opens the
    /// connection itself. This keeps all connection use on the dedicated
    /// history thread.
    ///
    /// The writer is disabled when `config.enabled` is false.
    #[must_use]
    pub fn new(db_path: Option<std::path::PathBuf>, config: &HistoryConfig) -> Self {
        let _phase = crate::perf::PhaseTimer::start("history_setup");
        if !config.enabled {
            return Self::disabled();
        }

        // Generate a unique session ID for this writer instance
        let session_id = generate_session_id();

        let (sender, receiver) = mpsc::channel::<HistoryMessage>();
        let worker_config = WorkerConfig::from(config);

        let handle = match thread::Builder::new()
            .name("dcg-history-writer".to_string())
            .spawn(move || {
                match HistoryDb::open(db_path) {
                    Ok(db) => history_worker(db, receiver, worker_config),
                    Err(e) => {
                        error!(error = %e, "Failed to open history DB in worker thread");
                        let status = if is_contention_error(&e) {
                            "busy_drop"
                        } else {
                            "storage_error"
                        };
                        history_diagnostic(status, format_args!("phase=open"));
                        // Dropping the queued messages also releases their reservations.
                        drop(receiver);
                    }
                }
            }) {
            Ok(h) => h,
            Err(e) => {
                // Thread spawn failed - return disabled writer to avoid leaking
                // messages into a channel with no receiver.
                error!(
                    error = %e,
                    "Failed to spawn history writer thread - history collection disabled"
                );
                history_diagnostic("worker_error", format_args!("phase=spawn"));
                return Self::disabled();
            }
        };

        Self {
            sender: Some(sender),
            handle: Some(handle),
            entry_budget: Some(Arc::new(QueueBudget::new(
                MAX_PENDING_HISTORY_ENTRIES,
                MAX_PENDING_HISTORY_BYTES,
            ))),
            flush_budget: Some(Arc::new(QueueBudget::new(
                MAX_PENDING_HISTORY_FLUSHES,
                MAX_PENDING_HISTORY_FLUSHES,
            ))),
            redaction_mode: config.redaction_mode,
            session_id,
            wait_for_worker_on_drop: true,
            drop_wait_deadline: None,
        }
    }

    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            sender: None,
            handle: None,
            entry_budget: None,
            flush_budget: None,
            redaction_mode: HistoryRedactionMode::Pattern,
            session_id: String::new(),
            wait_for_worker_on_drop: true,
            drop_wait_deadline: None,
        }
    }

    /// Get the session ID for this writer instance.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn flush_handle(&self) -> Option<HistoryFlushHandle> {
        self.sender
            .as_ref()
            .zip(self.flush_budget.as_ref())
            .map(|(sender, budget)| HistoryFlushHandle {
                sender: sender.clone(),
                budget: Arc::clone(budget),
            })
    }

    /// Log a command entry asynchronously, dropping it on admission failure.
    pub fn log(&self, entry: CommandEntry) {
        let _ = self.try_log(entry);
    }

    /// Redact and attempt to admit an entry without waiting for the worker.
    ///
    /// Capacity covers the retained, redacted entry and every metadata string's
    /// allocated capacity. A queued result is not a persistence guarantee.
    #[must_use]
    pub fn try_log(&self, mut entry: CommandEntry) -> HistoryEnqueueOutcome {
        let _phase = crate::perf::PhaseTimer::start("history_enqueue_redact");
        let (Some(sender), Some(budget)) = (&self.sender, &self.entry_budget) else {
            return HistoryEnqueueOutcome::Disabled;
        };
        entry.command = redact_for_history(&entry.command, self.redaction_mode);
        if entry.session_id.is_none() && !self.session_id.is_empty() {
            entry.session_id = Some(self.session_id.clone());
        }
        // Every writer path used to leave this NULL, so rows from several
        // machines could not be told apart once merged (#514).
        if entry.hostname.is_none() {
            entry.hostname = local_hostname().map(str::to_string);
        }
        let bytes = retained_entry_bytes(&entry);
        let reservation = match budget.try_reserve(bytes) {
            Ok(reservation) => reservation,
            Err(error) => {
                history_diagnostic(
                    "queue_drop",
                    format_args!("phase=admission reason={error:?} bytes={bytes}"),
                );
                return match error {
                    ReserveError::Full => HistoryEnqueueOutcome::QueueFull,
                    ReserveError::Oversized => HistoryEnqueueOutcome::EntryTooLarge,
                };
            }
        };
        match sender.send(HistoryMessage::Entry(QueuedHistoryEntry {
            entry: Box::new(entry),
            reservation,
        })) {
            Ok(()) => HistoryEnqueueOutcome::Queued,
            Err(error) => {
                warn!(error = %error, "Failed to send history entry - worker thread unavailable");
                HistoryEnqueueOutcome::WorkerUnavailable
            }
        }
    }

    /// Request a flush without waiting for completion. Repeated requests use
    /// bounded control capacity; a saturated request queue drops the request.
    pub fn flush(&self) {
        if let Some(handle) = self.flush_handle() {
            let _ = handle.request_flush();
        }
    }

    /// Request a flush and wait up to the hook-safe bounded timeout.
    pub fn flush_sync(&self) {
        if let Some(handle) = self.flush_handle() {
            handle.flush_sync();
        }
    }

    /// Request a flush and wait for at most `timeout`.
    ///
    /// Returns `true` for a disabled writer or when the storage worker
    /// acknowledges processing before the deadline, not necessarily persistence.
    #[must_use]
    pub fn flush_sync_with_timeout(&self, timeout: Duration) -> bool {
        self.flush_handle()
            .is_none_or(|handle| handle.flush_sync_with_timeout(timeout))
    }

    /// Queue normal worker shutdown without waiting for storage during drop.
    ///
    /// Deadline paths call this only after their protocol response has been
    /// written and flushed. When the worker is still connected, its channel
    /// retains every queued entry followed by `Shutdown`; a wedged database can
    /// no longer keep the hook process alive after the safety budget is already
    /// exhausted.
    pub fn detach_worker_on_drop(&mut self) {
        self.wait_for_worker_on_drop = false;
    }

    /// Bound the normal drop wait to a budget measured from this call.
    ///
    /// Hook mode uses the evaluator's remaining absolute deadline so history
    /// shutdown can never extend a safety decision past its total budget.
    pub fn limit_drop_wait_to(&mut self, timeout: Duration) {
        let now = Instant::now();
        self.drop_wait_deadline = Some(now.checked_add(timeout).unwrap_or(now));
    }
}

impl Drop for HistoryWriter {
    fn drop(&mut self) {
        let _phase = crate::perf::PhaseTimer::start("history_shutdown_wait");
        if let Some(sender) = self.sender.take() {
            let (ack_tx, ack_rx) = mpsc::channel();
            // There is only one shutdown producer. This control message bypasses
            // admission budgets so saturation cannot discard normal shutdown.
            if sender.send(HistoryMessage::Shutdown(ack_tx)).is_ok() && self.wait_for_worker_on_drop
            {
                if let Some(deadline) = self.drop_wait_deadline {
                    // Hook mode never lets best-effort telemetry extend the
                    // guarded decision beyond its absolute deadline.
                    let started = Instant::now();
                    let timeout = deadline.saturating_duration_since(started);
                    let status = match ack_rx.recv_timeout(timeout) {
                        Ok(()) => "shutdown_complete",
                        Err(mpsc::RecvTimeoutError::Timeout) => "shutdown_timeout",
                        Err(mpsc::RecvTimeoutError::Disconnected) => "worker_disconnected",
                    };
                    history_diagnostic(
                        status,
                        format_args!(
                            "timeout_ms={} elapsed_ms={}",
                            timeout.as_millis(),
                            started.elapsed().as_millis()
                        ),
                    );
                } else {
                    // Library and CLI callers without a hook deadline receive
                    // the conventional writer guarantee: queued entries are
                    // drained before Drop returns.
                    let _ = ack_rx.recv();
                }
            }
        }

        if self.wait_for_worker_on_drop && self.drop_wait_deadline.is_none() {
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        } else {
            // Hook deadlines and explicit detach requests must not inherit an
            // unbounded scheduler or storage wait.
            drop(self.handle.take());
        }
    }
}

/// Generate a unique session ID for a writer instance.
fn generate_session_id() -> String {
    use sha2::{Digest, Sha256};
    use std::process;

    let now = chrono::Utc::now();
    let pid = process::id();
    let thread_id = format!("{:?}", thread::current().id());

    let mut hasher = Sha256::new();
    hasher.update(now.timestamp_nanos_opt().unwrap_or(0).to_le_bytes());
    hasher.update(pid.to_le_bytes());
    hasher.update(thread_id.as_bytes());

    let digest = hasher.finalize();
    // Use first 8 bytes for a shorter, more readable ID
    format!(
        "ses-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7]
    )
}

/// No timer is armed for an empty batch unless periodic pruning is enabled.
/// In particular, an expired flush timer must not make an idle or disabled
/// worker poll the channel with a zero timeout forever.
fn history_receive_timeout(
    config: &WorkerConfig,
    batch_empty: bool,
    history_disabled: bool,
    last_flush: Instant,
    last_prune_check: Instant,
    now: Instant,
) -> Option<Duration> {
    if history_disabled {
        return None;
    }
    let flush = (!batch_empty).then(|| {
        config
            .flush_interval
            .saturating_sub(now.saturating_duration_since(last_flush))
    });
    let prune = config.auto_prune.then(|| {
        config
            .prune_check_interval
            .saturating_sub(now.saturating_duration_since(last_prune_check))
    });
    match (flush, prune) {
        (Some(flush), Some(prune)) => Some(flush.min(prune)),
        (Some(timeout), None) | (None, Some(timeout)) => Some(timeout),
        (None, None) => None,
    }
}

#[allow(clippy::needless_pass_by_value)]
fn history_worker(db: HistoryDb, receiver: mpsc::Receiver<HistoryMessage>, config: WorkerConfig) {
    run_history_worker(db, config, |timeout| match timeout {
        Some(timeout) => receiver.recv_timeout(timeout),
        None => receiver
            .recv()
            .map_err(|_| mpsc::RecvTimeoutError::Disconnected),
    });
}

/// Keep receipt of the next message separate from processing it. Besides
/// allowing deterministic mailbox tests with real SQLite, this makes the
/// flush barrier explicit: never consume messages after a flush before its ack.
fn run_history_worker(
    mut db: HistoryDb,
    config: WorkerConfig,
    mut receive: impl FnMut(Option<Duration>) -> Result<HistoryMessage, mpsc::RecvTimeoutError>,
) {
    let mut batch = PendingHistoryBatch::new(config.batch_size);
    let mut last_flush = Instant::now();
    let mut last_prune_check = Instant::now();
    let db_path = db.path().map(std::path::Path::to_path_buf);

    // Reclaim expired rows before deciding whether an existing database is
    // irreducibly over its hard cap. Otherwise a database composed mostly of
    // expired data can disable this long-lived writer even though pruning
    // immediately brings it back under the configured limit.
    if config.auto_prune {
        check_and_prune(&db, config.retention_days);
        last_prune_check = Instant::now();
    }

    let mut history_disabled = match db.enforce_live_size_limit(config.max_size_bytes) {
        Ok(true) => false,
        Ok(false) => {
            warn!(
                max_size_bytes = config.max_size_bytes,
                "History database already exceeds max_size_mb with live data; disabling writes"
            );
            true
        }
        Err(e) => {
            error!(
                error = %e,
                max_size_bytes = config.max_size_bytes,
                "Failed to enforce history max_size_mb; disabling writes"
            );
            history_diagnostic("storage_error", format_args!("phase=size_limit"));
            true
        }
    };

    loop {
        let timeout = history_receive_timeout(
            &config,
            batch.entries.is_empty(),
            history_disabled,
            last_flush,
            last_prune_check,
            Instant::now(),
        );
        // recv_timeout(0) still returns a buffered message. Service an expired
        // timer before receiving again, so a constantly readable channel cannot
        // starve a partial-batch flush or periodic maintenance.
        let message = if timeout == Some(Duration::ZERO) {
            Err(mpsc::RecvTimeoutError::Timeout)
        } else {
            receive(timeout)
        };
        match message {
            Ok(HistoryMessage::Entry(entry)) => {
                if history_disabled {
                    continue;
                }
                if batch.entries.is_empty() {
                    // Measure batch age from its first entry, not worker
                    // startup, and do not postpone it for subsequent entries.
                    last_flush = Instant::now();
                }
                batch.push(entry);

                if batch.entries.len() >= config.batch_size {
                    batch.flush(
                        &mut db,
                        db_path.as_ref(),
                        &mut history_disabled,
                        config.max_size_bytes,
                    );
                    last_flush = Instant::now();
                }
            }
            Ok(HistoryMessage::Flush(request)) => {
                // mpsc is FIFO: every entry queued before this marker has
                // already been handled. Draining *later* messages here makes
                // the barrier a moving target under sustained producers.
                batch.flush(
                    &mut db,
                    db_path.as_ref(),
                    &mut history_disabled,
                    config.max_size_bytes,
                );
                last_flush = Instant::now();
                request.acknowledge();
            }
            Ok(HistoryMessage::Shutdown(ack)) => {
                // HistoryWriter is the only entry producer, and queues this
                // marker after its final entry. Retained flush handles cannot
                // extend shutdown by submitting requests after the marker.
                batch.flush(
                    &mut db,
                    db_path.as_ref(),
                    &mut history_disabled,
                    config.max_size_bytes,
                );
                // This acknowledgement is also a connection-close barrier.
                // Do not add an exclusive TRUNCATE checkpoint to hook shutdown.
                drop(db);
                let _ = ack.send(());
                return;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if !batch.entries.is_empty() && last_flush.elapsed() >= config.flush_interval {
                    batch.flush(
                        &mut db,
                        db_path.as_ref(),
                        &mut history_disabled,
                        config.max_size_bytes,
                    );
                    last_flush = Instant::now();
                }

                if !history_disabled
                    && config.auto_prune
                    && last_prune_check.elapsed() >= config.prune_check_interval
                {
                    check_and_prune(&db, config.retention_days);
                    last_prune_check = Instant::now();
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                debug!("History channel disconnected, performing final flush");
                batch.flush(
                    &mut db,
                    db_path.as_ref(),
                    &mut history_disabled,
                    config.max_size_bytes,
                );
                if let Err(e) = db.checkpoint_truncate() {
                    warn!(error = %e, "WAL checkpoint failed on channel disconnect");
                }
                break;
            }
        }
    }
}

fn recover_history_db(
    db: &mut HistoryDb,
    db_path: Option<&std::path::PathBuf>,
    max_size_bytes: u64,
) -> bool {
    let Some(path) = db_path else {
        return false;
    };

    // Failed COMMIT/ROLLBACK paths can retain a transaction and its writer
    // lock. Release it before opening the replacement, otherwise recovery
    // contends with its own old connection. Never commit partial failed work.
    if !db.connection().is_autocommit() {
        if let Err(error) = db.connection().execute("ROLLBACK;") {
            error!(error = %error, "Cannot roll back history transaction before recovery");
            return false;
        }
    }

    match HistoryDb::open(Some(path.clone())) {
        Ok(recovered_db) => match recovered_db.enforce_live_size_limit(max_size_bytes) {
            Ok(true) => {
                *db = recovered_db;
                true
            }
            Ok(false) => {
                error!(
                    max_size_bytes,
                    path = %path.display(),
                    "Recovered history DB exceeds max_size_mb with live data"
                );
                false
            }
            Err(e) => {
                error!(
                    error = %e,
                    path = %path.display(),
                    "Failed to reapply max_size_mb after history DB recovery"
                );
                false
            }
        },
        Err(e) => {
            error!(
                error = %e,
                path = %path.display(),
                "Failed to recover history DB after fatal storage error"
            );
            false
        }
    }
}

fn flush_batch_with_recovery(
    db: &mut HistoryDb,
    batch: &mut Vec<CommandEntry>,
    db_path: Option<&std::path::PathBuf>,
    history_disabled: &mut bool,
    max_size_bytes: u64,
) {
    if *history_disabled {
        batch.clear();
        return;
    }

    match flush_batch(db, batch, max_size_bytes) {
        FlushOutcome::Success => {}
        FlushOutcome::Contended => {
            batch.clear();
            debug!("History database is busy; dropped best-effort telemetry batch");
            history_diagnostic("busy_drop", format_args!("phase=write"));
        }
        FlushOutcome::CapacityReached => {
            *history_disabled = true;
            batch.clear();
            warn!("History max_size_mb reached; disabling history writes for this process");
            history_diagnostic("storage_error", format_args!("phase=capacity"));
        }
        FlushOutcome::Fatal => {
            history_diagnostic("storage_error", format_args!("phase=recovery"));
            warn!("Detected fatal history storage error; attempting DB recovery");
            if recover_history_db(db, db_path, max_size_bytes) {
                match flush_batch(db, batch, max_size_bytes) {
                    FlushOutcome::Success => {
                        debug!("History DB recovery succeeded");
                    }
                    FlushOutcome::Contended => {
                        batch.clear();
                        debug!(
                            "Recovered history database is busy; dropped best-effort telemetry batch"
                        );
                        history_diagnostic("busy_drop", format_args!("phase=recovery"));
                    }
                    FlushOutcome::Fatal => {
                        *history_disabled = true;
                        batch.clear();
                        error!(
                            "History DB remained unusable after recovery; disabling history writes for this process"
                        );
                    }
                    FlushOutcome::CapacityReached => {
                        *history_disabled = true;
                        batch.clear();
                        warn!(
                            "History max_size_mb reached after storage recovery; disabling history writes"
                        );
                    }
                }
            } else {
                *history_disabled = true;
                batch.clear();
                error!(
                    "History DB recovery unavailable; disabling history writes for this process"
                );
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlushOutcome {
    Success,
    Fatal,
    CapacityReached,
    Contended,
}

fn is_fatal_storage_error(error: &HistoryError) -> bool {
    if matches!(error, HistoryError::IntegrityCheckFailed(_)) {
        return true;
    }
    matches!(
        error,
        HistoryError::Sqlite(rusqlite::Error::SqliteFailure(code, _))
            if matches!(
                code.code,
                rusqlite::ErrorCode::DatabaseCorrupt
                    | rusqlite::ErrorCode::NotADatabase
                    | rusqlite::ErrorCode::SystemIoFailure
                    | rusqlite::ErrorCode::CannotOpen
                    | rusqlite::ErrorCode::OutOfMemory
            )
    )
}

fn is_capacity_error(error: &HistoryError) -> bool {
    matches!(
        error,
        HistoryError::Sqlite(rusqlite::Error::SqliteFailure(code, _))
            if code.code == rusqlite::ErrorCode::DiskFull
    )
}

fn is_contention_error(error: &HistoryError) -> bool {
    matches!(
        error,
        HistoryError::Sqlite(rusqlite::Error::SqliteFailure(code, _))
            if matches!(
                code.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            )
    )
}

/// Flush the batch to the database, rechecking its cap inside each transaction.
fn flush_batch(db: &HistoryDb, batch: &mut Vec<CommandEntry>, max_size_bytes: u64) -> FlushOutcome {
    let _phase = crate::perf::PhaseTimer::start("history_storage_insert");
    if batch.is_empty() {
        return FlushOutcome::Success;
    }
    if !db.connection().is_autocommit() {
        // An INSERT inside a leftover transaction can return Ok without
        // committing anything. Do not retire entries on that false success.
        error!("History connection retained an unfinished transaction; recovery required");
        return FlushOutcome::Fatal;
    }

    let batch_len = batch.len();
    trace!(batch_size = batch_len, "Flushing history batch");

    // Bulk insertion is transactional: an error rolls back its whole prefix.
    // Individual fallback inserts below instead commit one row at a time.
    if batch_len >= 2 {
        match db.log_commands_batch_with_live_limit(batch, max_size_bytes) {
            Ok(()) => {
                trace!(count = batch_len, "Batch insert succeeded");
                batch.clear();
                return FlushOutcome::Success;
            }
            Err(e) => {
                // The storage layer attempts rollback on error, but cannot
                // guarantee that rollback succeeds after a storage failure.
                // Retain the entire batch until that transaction is aborted.
                if !db.connection().is_autocommit() {
                    error!(error = %e, "Failed history batch left an active transaction");
                    return FlushOutcome::Fatal;
                }
                if is_contention_error(&e) {
                    debug!(
                        batch_size = batch_len,
                        "History database is busy; dropping best-effort telemetry batch"
                    );
                    return FlushOutcome::Contended;
                }
                if is_capacity_error(&e) {
                    return FlushOutcome::CapacityReached;
                }
                if is_fatal_storage_error(&e) {
                    error!(
                        error = %e,
                        batch_size = batch_len,
                        "Fatal history storage error in batch insert"
                    );
                    return FlushOutcome::Fatal;
                }
                warn!(
                    error = %e,
                    batch_size = batch_len,
                    "Batch insert failed, falling back to individual inserts"
                );
            }
        }
    }

    flush_individual_entries(batch, |entry| {
        db.log_command_with_live_limit(entry, max_size_bytes)
    })
}

/// Retire the processed prefix even when a later insert stops the batch.
///
/// Successful individual inserts are already committed; replaying them after
/// recovery duplicates history. Permanently rejected entries are processed too
/// and must not reappear when recovery removes a connection-local constraint.
/// Only the terminally failing entry and the unattempted suffix remain. This
/// does not resolve an ambiguous commit of the failing entry itself.
fn flush_individual_entries(
    batch: &mut Vec<CommandEntry>,
    mut insert: impl FnMut(&CommandEntry) -> Result<i64, HistoryError>,
) -> FlushOutcome {
    let mut processed = 0;
    let mut error_count = 0;
    let mut outcome = FlushOutcome::Success;

    for (index, entry) in batch.iter().enumerate() {
        match insert(entry) {
            Ok(_id) => trace!("Inserted history entry"),
            Err(e) => {
                if is_contention_error(&e) {
                    debug!("History database became busy; dropping remaining telemetry");
                    outcome = FlushOutcome::Contended;
                    break;
                }
                if is_capacity_error(&e) {
                    outcome = FlushOutcome::CapacityReached;
                    break;
                }
                if is_fatal_storage_error(&e) {
                    error!(error = %e, "Fatal history storage error in single-row insert");
                    outcome = FlushOutcome::Fatal;
                    break;
                }
                error_count += 1;
                history_diagnostic("storage_error", format_args!("phase=insert"));
                if error_count <= 3 {
                    error!(error = %e, "Failed to insert history entry");
                }
            }
        }
        processed = index + 1;
    }

    // Mutate only after the iteration borrow ends, and shift the suffix once
    // rather than repeatedly removing the first element (quadratic work).
    drop(batch.drain(..processed));
    if error_count > 0 {
        warn!(
            success = processed - error_count,
            failed = error_count,
            remaining = batch.len(),
            "History individual inserts completed with rejected entries"
        );
    }
    outcome
}

/// Check if pruning is needed and perform it.
fn check_and_prune(db: &HistoryDb, retention_days: u32) {
    // Check if enough time has passed since last prune
    match db.should_auto_prune() {
        Ok(true) => {
            debug!(retention_days = retention_days, "Starting auto-prune");
            match db.prune_older_than_days(u64::from(retention_days), false) {
                Ok(pruned_count) => {
                    debug!(pruned = pruned_count, "Auto-prune completed");
                    if pruned_count > 0 {
                        if let Err(e) = db.vacuum() {
                            warn!(error = %e, "Failed to reclaim pages after auto-prune");
                        }
                        if let Err(e) = db.checkpoint_truncate() {
                            warn!(error = %e, "Failed to truncate WAL after auto-prune");
                        }
                    }
                    if let Err(e) = db.record_prune_timestamp() {
                        warn!(error = %e, "Failed to record prune timestamp");
                    }
                }
                Err(e) => {
                    error!(error = %e, "Auto-prune failed");
                }
            }
        }
        Ok(false) => {
            trace!("Auto-prune not needed yet");
        }
        Err(e) => {
            warn!(error = %e, "Failed to check if auto-prune is needed");
        }
    }
}

fn redact_for_history(command: &str, mode: HistoryRedactionMode) -> String {
    match mode {
        HistoryRedactionMode::None => command.to_string(),
        HistoryRedactionMode::Full => "[REDACTED]".to_string(),
        HistoryRedactionMode::Pattern => {
            // Secrets first, then argument truncation: truncation only ever
            // shortens *quoted* arguments, so on its own it leaves bare
            // credentials in the store verbatim (issue #386).
            let secrets_redacted = crate::redaction::redact_secrets(command);
            let config = RedactionConfig {
                enabled: true,
                mode: RedactionMode::Arguments,
                ..Default::default()
            };
            crate::logging::redact_command(&secrets_redacted, &config)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_entry_message(entry: CommandEntry) -> HistoryMessage {
        let budget = Arc::new(QueueBudget::new(1, MAX_PENDING_HISTORY_BYTES));
        let reservation = budget.try_reserve(retained_entry_bytes(&entry)).unwrap();
        HistoryMessage::Entry(QueuedHistoryEntry {
            entry: Box::new(entry),
            reservation,
        })
    }

    fn test_flush_message(ack: mpsc::Sender<()>) -> HistoryMessage {
        let budget = Arc::new(QueueBudget::new(1, 1));
        HistoryMessage::Flush(ReservedFlush {
            ack,
            reservation: budget.try_reserve(1).unwrap(),
        })
    }

    fn recovery_test_entries(commands: &[&str]) -> Vec<CommandEntry> {
        commands
            .iter()
            .map(|command| CommandEntry {
                command: (*command).to_string(),
                ..Default::default()
            })
            .collect()
    }

    fn injected_storage_error(code: i32) -> HistoryError {
        HistoryError::Sqlite(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(code),
            Some("injected between real SQLite inserts".to_string()),
        ))
    }

    fn reject_recovery_test_entry(db: &HistoryDb) {
        db.connection()
            .execute(
                "CREATE TEMP TRIGGER reject_history_probe BEFORE INSERT ON commands
                 WHEN new.command = 'rejected'
                 BEGIN SELECT RAISE(ABORT, 'test entry rejected'); END;",
            )
            .expect("install connection-local rejection trigger");
    }

    fn assert_fts_probe_count(path: &Path, term: &str, expected: i64) {
        let connection =
            rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .expect("open FTS observer");
        // COUNT(*) without MATCH can read the external content table and
        // would not prove that the search index itself was updated.
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM commands_fts WHERE commands_fts MATCH ?1",
                [term],
                |row| row.get(0),
            )
            .expect("query actual FTS postings");
        assert_eq!(count, expected, "unexpected FTS count for {term}");
    }

    #[test]
    fn unfinished_transaction_is_rolled_back_before_recovery_replays_batch() {
        for commands in [&["only"][..], &["prefix", "tail"][..]] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("unfinished-transaction.db");
            let mut db = HistoryDb::open(Some(path.clone())).unwrap();
            let mut batch = recovery_test_entries(commands);
            db.connection().execute("BEGIN IMMEDIATE;").unwrap();
            db.log_command(&batch[0]).unwrap();
            assert!(!db.connection().is_autocommit());
            assert!(persisted_test_commands(&path).is_empty());

            assert_eq!(
                flush_batch(&db, &mut batch, WorkerConfig::default().max_size_bytes),
                FlushOutcome::Fatal
            );
            assert_eq!(
                batch.len(),
                commands.len(),
                "uncommitted entries must remain queued"
            );
            assert_eq!(db.count_commands().unwrap(), 1);

            // Exercise the production recovery path, not a simulated reopen.
            // It must release its own old lock and discard the uncommitted
            // prefix before retrying the full batch exactly once.
            let mut disabled = false;
            flush_batch_with_recovery(
                &mut db,
                &mut batch,
                Some(&path),
                &mut disabled,
                WorkerConfig::default().max_size_bytes,
            );
            assert!(
                !disabled,
                "recovery must not contend with its own transaction"
            );
            assert!(db.connection().is_autocommit());
            assert!(batch.is_empty());
            assert_eq!(persisted_test_commands(&path), commands);
            for command in commands {
                assert_fts_probe_count(&path, command, 1);
            }
        }
    }

    #[test]
    fn failed_bulk_commit_rolls_back_without_replaying_contended_entries() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("commit-contention.db");
        let mut db = HistoryDb::open(Some(path.clone())).unwrap();
        // A rollback-journal reader permits BEGIN IMMEDIATE and the INSERTs,
        // but prevents COMMIT. This tests a different boundary from a competing
        // writer that rejects BEGIN before any entry has been attempted.
        db.connection()
            .execute("PRAGMA journal_mode=DELETE;")
            .unwrap();
        let reader = rusqlite::Connection::open(&path).unwrap();
        reader.execute_batch("BEGIN;").unwrap();
        let before: i64 = reader
            .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))
            .unwrap();
        assert_eq!(before, 0);
        let mut batch = recovery_test_entries(&["droppedfirst", "droppedsecond"]);
        let mut disabled = false;
        let max_size = WorkerConfig::default().max_size_bytes;
        flush_batch_with_recovery(&mut db, &mut batch, Some(&path), &mut disabled, max_size);
        assert!(
            !disabled,
            "ordinary commit contention must not disable the writer"
        );
        assert!(
            db.connection().is_autocommit(),
            "failed COMMIT must be rolled back"
        );
        assert!(batch.is_empty(), "contended telemetry remains best-effort");
        reader.execute_batch("ROLLBACK;").unwrap();
        drop(reader);
        assert!(persisted_test_commands(&path).is_empty());

        batch = recovery_test_entries(&["afterunlock"]);
        flush_batch_with_recovery(&mut db, &mut batch, Some(&path), &mut disabled, max_size);
        assert!(!disabled);
        assert!(batch.is_empty());
        assert_eq!(persisted_test_commands(&path), vec!["afterunlock"]);
        assert_fts_probe_count(&path, "droppedfirst", 0);
        assert_fts_probe_count(&path, "droppedsecond", 0);
        assert_fts_probe_count(&path, "afterunlock", 1);
    }

    #[test]
    fn batch_fallback_keeps_good_rows_and_legitimate_repeated_commands() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fallback-repeated.db");
        let db = HistoryDb::open(Some(path.clone())).unwrap();
        reject_recovery_test_entry(&db);
        let mut batch = recovery_test_entries(&["repeatable", "rejected", "repeatable"]);

        // The first row must be rolled back when the bulk insert hits the
        // trigger. Fallback then commits the two distinct, identical events.
        assert!(db.log_commands_batch(&batch).is_err());
        assert!(db.connection().is_autocommit());
        assert!(persisted_test_commands(&path).is_empty());
        assert_eq!(
            flush_batch(&db, &mut batch, WorkerConfig::default().max_size_bytes),
            FlushOutcome::Success
        );
        assert!(batch.is_empty());
        assert_eq!(
            persisted_test_commands(&path),
            vec!["repeatable", "repeatable"]
        );
        assert_fts_probe_count(&path, "repeatable", 2);
        assert_fts_probe_count(&path, "rejected", 0);
        assert_eq!(
            flush_batch(&db, &mut batch, WorkerConfig::default().max_size_bytes),
            FlushOutcome::Success
        );
        assert_eq!(db.count_commands().unwrap(), 2);
    }

    #[test]
    fn fatal_fallback_recovery_retries_only_the_unprocessed_suffix() {
        let commands = ["prefix", "middle", "tail"];
        for fail_at in 0..commands.len() {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("fallback-recovery.db");
            let mut db = HistoryDb::open(Some(path.clone())).unwrap();
            let mut batch = recovery_test_entries(&commands);
            let mut attempted = 0;
            let result = flush_individual_entries(&mut batch, |entry| {
                let index = attempted;
                attempted += 1;
                if index == fail_at {
                    Err(injected_storage_error(rusqlite::ffi::SQLITE_IOERR))
                } else {
                    db.log_command(entry)
                }
            });
            assert_eq!(result, FlushOutcome::Fatal);
            assert_eq!(attempted, fail_at + 1);
            assert_eq!(persisted_test_commands(&path), commands[..fail_at]);
            assert_eq!(
                batch
                    .iter()
                    .map(|entry| entry.command.as_str())
                    .collect::<Vec<_>>(),
                commands[fail_at..]
            );

            let max_size = WorkerConfig::default().max_size_bytes;
            assert!(recover_history_db(&mut db, Some(&path), max_size));
            let mut disabled = false;
            flush_batch_with_recovery(&mut db, &mut batch, Some(&path), &mut disabled, max_size);
            assert!(!disabled);
            assert!(batch.is_empty());
            assert_eq!(persisted_test_commands(&path), commands);
            for command in commands {
                assert_fts_probe_count(&path, command, 1);
            }
        }
    }

    #[test]
    fn fallback_recovery_cannot_resurrect_a_previously_rejected_entry() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fallback-rejected-prefix.db");
        let mut db = HistoryDb::open(Some(path.clone())).unwrap();
        reject_recovery_test_entry(&db);
        let mut batch = recovery_test_entries(&["committed", "rejected", "pending", "tail"]);
        let result = flush_individual_entries(&mut batch, |entry| {
            if entry.command == "pending" {
                Err(injected_storage_error(rusqlite::ffi::SQLITE_IOERR))
            } else {
                db.log_command(entry)
            }
        });
        assert_eq!(result, FlushOutcome::Fatal);
        assert_eq!(persisted_test_commands(&path), vec!["committed"]);
        assert_eq!(
            batch
                .iter()
                .map(|entry| entry.command.as_str())
                .collect::<Vec<_>>(),
            vec!["pending", "tail"]
        );

        // Reopening removes the TEMP trigger. Retrying the original batch
        // would now duplicate "committed" AND incorrectly insert "rejected".
        let max_size = WorkerConfig::default().max_size_bytes;
        assert!(recover_history_db(&mut db, Some(&path), max_size));
        let mut disabled = false;
        flush_batch_with_recovery(&mut db, &mut batch, Some(&path), &mut disabled, max_size);
        assert!(!disabled);
        assert!(batch.is_empty());
        assert_eq!(
            persisted_test_commands(&path),
            vec!["committed", "pending", "tail"]
        );
        assert_fts_probe_count(&path, "committed", 1);
        assert_fts_probe_count(&path, "rejected", 0);
    }

    #[test]
    fn terminal_fallback_errors_preserve_only_unprocessed_entries() {
        for (code, expected) in [
            (rusqlite::ffi::SQLITE_BUSY, FlushOutcome::Contended),
            (rusqlite::ffi::SQLITE_LOCKED, FlushOutcome::Contended),
            (rusqlite::ffi::SQLITE_FULL, FlushOutcome::CapacityReached),
            (rusqlite::ffi::SQLITE_IOERR, FlushOutcome::Fatal),
        ] {
            let db = HistoryDb::open_in_memory().unwrap();
            let mut batch = recovery_test_entries(&["committed", "pending", "unattempted"]);
            let mut attempted = 0;
            let result = flush_individual_entries(&mut batch, |entry| {
                attempted += 1;
                if entry.command == "pending" {
                    Err(injected_storage_error(code))
                } else {
                    db.log_command(entry)
                }
            });
            assert_eq!(result, expected);
            assert_eq!(attempted, 2);
            assert_eq!(db.count_commands().unwrap(), 1);
            assert_eq!(
                batch
                    .iter()
                    .map(|entry| entry.command.as_str())
                    .collect::<Vec<_>>(),
                vec!["pending", "unattempted"]
            );
        }
    }

    #[test]
    fn individual_flush_handles_empty_and_single_rejected_batches() {
        let db = HistoryDb::open_in_memory().unwrap();
        let mut empty = Vec::new();
        assert_eq!(
            flush_individual_entries(&mut empty, |_| panic!("empty batch must not insert")),
            FlushOutcome::Success
        );
        reject_recovery_test_entry(&db);
        let mut batch = recovery_test_entries(&["rejected"]);
        assert_eq!(
            flush_batch(&db, &mut batch, WorkerConfig::default().max_size_bytes),
            FlushOutcome::Success
        );
        assert!(
            batch.is_empty(),
            "permanently rejected entries are not retried"
        );
        assert_eq!(db.count_commands().unwrap(), 0);
    }

    #[test]
    fn integrity_failures_preserve_entries_for_recovery() {
        let mut batch = recovery_test_entries(&["pending", "unattempted"]);
        assert_eq!(
            flush_individual_entries(&mut batch, |_| {
                Err(HistoryError::IntegrityCheckFailed(
                    "rollback left a transaction active".to_string(),
                ))
            }),
            FlushOutcome::Fatal
        );
        assert_eq!(
            batch.len(),
            2,
            "failed cleanup must not retire the pending entry"
        );
    }

    #[test]
    fn hostname_normalization_rejects_empty_and_control_characters_514() {
        assert_eq!(
            normalize_hostname("  build-01 \n"),
            Some("build-01".to_string())
        );
        assert_eq!(normalize_hostname(""), None);
        assert_eq!(normalize_hostname(" \t\n"), None);
        assert_eq!(normalize_hostname("evil\nhost"), None);
        assert_eq!(normalize_hostname("esc\u{1b}[31m"), None);
    }

    #[test]
    fn local_hostname_is_resolved_once_and_is_never_blank_514() {
        let first = local_hostname();
        if cfg!(unix) {
            assert!(first.is_some(), "gethostname must name a Unix host");
        }
        if let Some(name) = first {
            assert!(!name.is_empty() && name == name.trim());
            // Cached: the same allocation comes back.
            assert!(std::ptr::eq(name, local_hostname().unwrap()));
        }
    }

    #[test]
    fn idle_and_disabled_workers_have_no_flush_poll_timer() {
        let config = WorkerConfig::default();
        let started = Instant::now();
        let much_later = started + Duration::from_secs(7 * 24 * 3600);
        assert_eq!(
            history_receive_timeout(&config, true, false, started, started, much_later),
            None,
            "an expired empty-batch timer must not busy-spin"
        );
        let config = WorkerConfig {
            auto_prune: true,
            ..config
        };
        assert_eq!(
            history_receive_timeout(&config, true, true, started, started, much_later),
            None,
            "a disabled worker must wait for messages, not run maintenance"
        );
    }

    #[test]
    fn pending_batch_timer_expires_without_a_quiet_channel() {
        let config = WorkerConfig::default();
        let started = Instant::now();
        assert_eq!(
            history_receive_timeout(&config, false, false, started, started, started),
            Some(config.flush_interval)
        );
        assert_eq!(
            history_receive_timeout(
                &config,
                false,
                false,
                started,
                started,
                started + config.flush_interval
            ),
            Some(Duration::ZERO),
            "the batch deadline must be serviced even when a message is ready"
        );
    }

    #[test]
    fn idle_pruning_and_batch_flush_use_the_earliest_deadline() {
        let config = WorkerConfig {
            auto_prune: true,
            flush_interval: Duration::from_secs(10),
            prune_check_interval: Duration::from_secs(30),
            ..WorkerConfig::default()
        };
        let started = Instant::now();
        let now = started + Duration::from_secs(25);
        assert_eq!(
            history_receive_timeout(&config, true, false, now, started, now),
            Some(Duration::from_secs(5)),
            "an idle writer must still wake for pruning"
        );
        assert_eq!(
            history_receive_timeout(&config, false, false, now, started, now),
            Some(Duration::from_secs(5)),
            "maintenance must not wait for a younger batch"
        );
        assert_eq!(
            history_receive_timeout(&config, false, false, now, now, now),
            Some(Duration::from_secs(10)),
            "flushing must not wait for a later maintenance check"
        );
    }

    fn persisted_test_commands(path: &Path) -> Vec<String> {
        let connection =
            rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .expect("open read-only observer");
        let mut statement = connection
            .prepare("SELECT command FROM commands ORDER BY id")
            .expect("prepare persisted command query");
        statement
            .query_map([], |row| row.get(0))
            .expect("query persisted commands")
            .collect::<Result<Vec<String>, _>>()
            .expect("read persisted commands")
    }

    #[test]
    fn flush_acknowledges_its_fifo_prefix_before_receiving_more_work() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("flush-prefix.db");
        let db = HistoryDb::open(Some(path.clone())).unwrap();
        let (sender, receiver) = mpsc::channel();
        // More than several batches: a flush must cover *all* prior entries,
        // but neither a later entry nor a later control message.
        for index in 0..257 {
            sender
                .send(test_entry_message(CommandEntry {
                    command: format!("before-{index}"),
                    ..Default::default()
                }))
                .unwrap();
        }
        let (first_tx, first_rx) = mpsc::channel();
        let (empty_tx, empty_rx) = mpsc::channel();
        let (last_tx, last_rx) = mpsc::channel();
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        sender.send(test_flush_message(first_tx)).unwrap();
        sender.send(test_flush_message(empty_tx)).unwrap();
        sender
            .send(test_entry_message(CommandEntry {
                command: "after-marker".to_string(),
                ..Default::default()
            }))
            .unwrap();
        sender.send(test_flush_message(last_tx)).unwrap();
        sender.send(HistoryMessage::Shutdown(shutdown_tx)).unwrap();
        drop(sender);

        let mut received = 0;
        run_history_worker(db, WorkerConfig::default(), |_| {
            match received {
                258 => {
                    first_rx.try_recv().expect("ack before the next receive");
                    let expected: Vec<_> = (0..257).map(|i| format!("before-{i}")).collect();
                    assert_eq!(persisted_test_commands(&path), expected);
                }
                259 => {
                    empty_rx
                        .try_recv()
                        .expect("consecutive empty flush acknowledged");
                }
                261 => {
                    last_rx
                        .try_recv()
                        .expect("later flush acknowledged independently");
                    assert_eq!(persisted_test_commands(&path).len(), 258);
                }
                _ => {}
            }
            received += 1;
            receiver
                .recv()
                .map_err(|_| mpsc::RecvTimeoutError::Disconnected)
        });
        assert_eq!(received, 262);
        shutdown_rx.try_recv().expect("shutdown acknowledged");
        assert_eq!(
            persisted_test_commands(&path).last().unwrap(),
            "after-marker"
        );
    }

    #[test]
    fn expired_batch_flushes_before_receiving_an_already_queued_message() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("ready-channel.db");
        let db = HistoryDb::open(Some(path.clone())).unwrap();
        let (sender, receiver) = mpsc::channel();
        sender
            .send(test_entry_message(CommandEntry {
                command: "timer-flush".to_string(),
                ..Default::default()
            }))
            .unwrap();
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        sender.send(HistoryMessage::Shutdown(shutdown_tx)).unwrap();
        drop(sender);
        let config = WorkerConfig {
            // An already-expired timer makes the ordering deterministic:
            // no sleeps, throughput thresholds, or scheduler assumptions.
            flush_interval: Duration::ZERO,
            ..WorkerConfig::default()
        };
        let mut received = 0;
        run_history_worker(db, config, |timeout| {
            assert_eq!(timeout, None, "empty batches must block rather than poll");
            if received == 1 {
                assert_eq!(persisted_test_commands(&path), vec!["timer-flush"]);
            }
            received += 1;
            receiver
                .recv()
                .map_err(|_| mpsc::RecvTimeoutError::Disconnected)
        });
        assert_eq!(received, 2);
        shutdown_rx.try_recv().unwrap();
    }

    #[test]
    fn shutdown_does_not_acknowledge_requests_queued_after_its_marker() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("shutdown-marker.db");
        let db = HistoryDb::open(Some(path.clone())).unwrap();
        let (sender, receiver) = mpsc::channel();
        sender
            .send(test_entry_message(CommandEntry {
                command: "final-entry".to_string(),
                ..Default::default()
            }))
            .unwrap();
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let (late_tx, late_rx) = mpsc::channel();
        sender.send(HistoryMessage::Shutdown(shutdown_tx)).unwrap();
        sender.send(test_flush_message(late_tx)).unwrap();
        // Retaining this sender models a cloned flush handle at writer drop.
        history_worker(db, receiver, WorkerConfig::default());
        shutdown_rx.try_recv().expect("shutdown completed");
        assert_eq!(
            late_rx.try_recv(),
            Err(mpsc::TryRecvError::Disconnected),
            "late control requests must not extend the shutdown barrier"
        );
        assert_eq!(persisted_test_commands(&path), vec!["final-entry"]);
        // A mode change requires all other connections to be gone. This is
        // checked after the shutdown ack, not after a grace-period sleep.
        let connection = rusqlite::Connection::open(&path).unwrap();
        let mode: String = connection
            .query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))
            .expect("shutdown must close the writer connection");
        assert_eq!(mode, "delete");
        drop(sender);
    }

    #[test]
    fn channel_disconnect_flushes_the_final_partial_batch() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("disconnect.db");
        let db = HistoryDb::open(Some(path.clone())).unwrap();
        let (sender, receiver) = mpsc::channel();
        for index in 0..3 {
            sender
                .send(test_entry_message(CommandEntry {
                    command: format!("last-{index}"),
                    ..Default::default()
                }))
                .unwrap();
        }
        drop(sender);
        history_worker(db, receiver, WorkerConfig::default());
        assert_eq!(
            persisted_test_commands(&path),
            vec!["last-0", "last-1", "last-2"]
        );
    }

    #[test]
    fn flush_timeout_does_not_consume_or_replay_queued_entries() {
        let (sender, receiver) = mpsc::channel();
        let flush = HistoryFlushHandle {
            sender: sender.clone(),
            budget: Arc::new(QueueBudget::new(1, 1)),
        };
        sender
            .send(test_entry_message(CommandEntry {
                command: "queued exactly once".to_string(),
                ..Default::default()
            }))
            .unwrap();

        // No worker is running: this must time out, regardless of host speed.
        assert!(!flush.flush_sync_with_timeout(Duration::ZERO));
        let HistoryMessage::Entry(entry) = receiver.try_recv().unwrap() else {
            panic!("timing out must leave the original entry queued");
        };
        assert_eq!(entry.entry.command, "queued exactly once");
        let HistoryMessage::Flush(request) = receiver.try_recv().unwrap() else {
            panic!("flush request must follow the entry");
        };
        assert!(
            request.ack.send(()).is_err(),
            "expired waiter must be disconnected"
        );
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }

    /// Issue #386: `redaction_mode = "pattern"` is documented as redacting
    /// sensitive values, but for a long time it only truncated *quoted*
    /// arguments, so bare credentials were stored byte-for-byte. Every canary
    /// below is synthetic.
    #[test]
    fn pattern_mode_strips_bare_and_quoted_secrets() {
        let command = "deploy AKIAABCDEFGHIJKLMNOP \
             ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \
             sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ \
             \"sk_live_QUOTEDLONGTOKENQUOTEDLONGTOKENQUOTEDLONGTOKENQUOTEDLONGTOKEN\"";
        let stored = redact_for_history(command, HistoryRedactionMode::Pattern);
        for canary in [
            "AKIAABCDEFGHIJKLMNOP",
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            "sk_live_QUOTEDLONGTOKEN",
            "sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        ] {
            assert!(
                !stored.contains(canary),
                "canary {canary} survived pattern redaction: {stored}"
            );
        }
        assert!(stored.starts_with("deploy "), "{stored}");
    }

    #[test]
    fn none_mode_stores_verbatim_and_full_mode_stores_nothing() {
        let command = "psql postgres://admin:hunter2hunter2@db.internal/app";
        assert_eq!(
            redact_for_history(command, HistoryRedactionMode::None),
            command
        );
        assert_eq!(
            redact_for_history(command, HistoryRedactionMode::Full),
            "[REDACTED]"
        );
        let pattern = redact_for_history(command, HistoryRedactionMode::Pattern);
        assert!(!pattern.contains("hunter2hunter2"), "{pattern}");
    }

    #[test]
    fn worker_config_defensively_clamps_zero_runtime_limits() {
        let history = HistoryConfig {
            retention_days: 0,
            max_size_mb: 0,
            prune_check_interval_hours: 0,
            batch_size: 0,
            batch_flush_interval_ms: 0,
            ..HistoryConfig::default()
        };
        let worker = WorkerConfig::from(&history);
        assert_eq!(worker.retention_days, 1);
        assert_eq!(worker.max_size_bytes, 1024 * 1024);
        assert_eq!(worker.prune_check_interval, Duration::from_secs(3600));
        assert_eq!(worker.batch_size, 1);
        assert_eq!(worker.flush_interval, Duration::from_millis(1));
    }

    #[test]
    fn detached_drop_never_waits_for_history_worker() {
        let (release_tx, release_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            // Bound a future regression: if Drop accidentally rejoins this
            // worker, the test fails after two seconds instead of hanging the
            // entire suite forever.
            let _ = release_rx.recv_timeout(Duration::from_secs(2));
        });
        let mut writer = HistoryWriter {
            sender: None,
            handle: Some(handle),
            entry_budget: None,
            flush_budget: None,
            redaction_mode: HistoryRedactionMode::Pattern,
            session_id: String::new(),
            wait_for_worker_on_drop: true,
            drop_wait_deadline: None,
        };
        writer.detach_worker_on_drop();

        let started = Instant::now();
        drop(writer);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "detached history drop waited for its worker"
        );

        let _ = release_tx.send(());
    }

    // ---- history database path resolution (#381) ----

    fn abs(segments: &[&str]) -> PathBuf {
        let mut path = if cfg!(windows) {
            PathBuf::from(r"C:\")
        } else {
            PathBuf::from("/")
        };
        path.extend(segments);
        path
    }

    #[test]
    fn env_override_beats_config_legacy_and_default() {
        let env_path = abs(&["srv", "env.db"]);
        let resolved = ResolvedHistoryPath::from_parts(
            Some(env_path.to_str().unwrap()),
            Some(abs(&["cfg", "config.db"])),
            Some(abs(&["home", ".config", "dcg", "history.db"])),
            abs(&["home", ".local", "state", "dcg", "history.db"]),
        );
        assert_eq!(resolved.source, HistoryPathSource::Environment);
        assert_eq!(resolved.path, env_path);
    }

    #[test]
    fn blank_env_override_is_ignored() {
        let config_path = abs(&["cfg", "config.db"]);
        let resolved = ResolvedHistoryPath::from_parts(
            Some("   "),
            Some(config_path.clone()),
            None,
            abs(&["default.db"]),
        );
        assert_eq!(resolved.source, HistoryPathSource::Config);
        assert_eq!(resolved.path, config_path);
    }

    #[test]
    fn env_override_expands_tilde_and_relative_paths() {
        let Some(home) = crate::config::home_dir() else {
            return;
        };
        let resolved = ResolvedHistoryPath::from_parts(
            Some("~/dcg-hist.db"),
            None,
            None,
            abs(&["default.db"]),
        );
        assert_eq!(resolved.source, HistoryPathSource::Environment);
        assert_eq!(resolved.path, home.join("dcg-hist.db"));

        let relative =
            ResolvedHistoryPath::from_parts(Some("rel/hist.db"), None, None, abs(&["default.db"]));
        assert!(
            relative.path.is_absolute(),
            "relative DCG_HISTORY_DB must resolve against the working directory: {}",
            relative.path.display()
        );
        assert!(relative.path.ends_with(Path::new("rel").join("hist.db")));
    }

    #[test]
    fn config_beats_legacy_and_default() {
        let config_path = abs(&["cfg", "config.db"]);
        let resolved = ResolvedHistoryPath::from_parts(
            None,
            Some(config_path.clone()),
            Some(abs(&["legacy.db"])),
            abs(&["default.db"]),
        );
        assert_eq!(resolved.source, HistoryPathSource::Config);
        assert_eq!(resolved.path, config_path);
    }

    #[test]
    fn existing_legacy_database_beats_default() {
        let legacy = abs(&["home", ".config", "dcg", "history.db"]);
        let resolved =
            ResolvedHistoryPath::from_parts(None, None, Some(legacy.clone()), abs(&["default.db"]));
        assert_eq!(resolved.source, HistoryPathSource::LegacyConfigDir);
        assert_eq!(resolved.path, legacy);
    }

    #[test]
    fn default_is_used_when_nothing_else_applies() {
        let default = abs(&["home", ".local", "state", "dcg", "history.db"]);
        let resolved = ResolvedHistoryPath::from_parts(None, None, None, default.clone());
        assert_eq!(resolved.source, HistoryPathSource::Default);
        assert_eq!(resolved.path, default);
    }

    #[test]
    fn default_state_path_prefers_xdg_state_home_on_unix() {
        let home = abs(&["home", "u"]);
        let xdg = abs(&["custom", "state"]);
        let local = abs(&["appdata", "local"]);
        let path = state_db_path_from(Some(xdg.as_os_str()), Some(&home), Some(&local));
        if cfg!(windows) {
            assert_eq!(path, local.join("dcg").join(DEFAULT_DB_FILENAME));
        } else {
            assert_eq!(path, xdg.join("dcg").join(DEFAULT_DB_FILENAME));
        }
    }

    #[test]
    fn default_state_path_falls_back_to_home_local_state() {
        let home = abs(&["home", "u"]);
        let expected = home
            .join(".local")
            .join("state")
            .join("dcg")
            .join(DEFAULT_DB_FILENAME);
        assert_eq!(state_db_path_from(None, Some(&home), None), expected);
        // A relative XDG_STATE_HOME is invalid per the spec and must be ignored.
        assert_eq!(
            state_db_path_from(
                Some(std::ffi::OsStr::new("relative/state")),
                Some(&home),
                None
            ),
            expected
        );
    }

    #[test]
    fn default_state_path_never_lands_in_the_config_directory() {
        let home = abs(&["home", "u"]);
        let path = state_db_path_from(None, Some(&home), Some(&abs(&["local"])));
        assert!(
            !path.starts_with(home.join(".config")),
            "history is state, not configuration: {}",
            path.display()
        );
    }

    #[test]
    fn default_state_path_without_home_is_relative_state_dir() {
        let path = state_db_path_from(None, None, None);
        assert_eq!(
            path,
            PathBuf::from(".local")
                .join("state")
                .join("dcg")
                .join(DEFAULT_DB_FILENAME)
        );
    }

    #[test]
    fn source_labels_are_stable() {
        assert_eq!(HistoryPathSource::Environment.describe(), "DCG_HISTORY_DB");
        assert_eq!(
            HistoryPathSource::Config.describe(),
            "[history] database_path"
        );
        assert_eq!(
            serde_json::to_string(&HistoryPathSource::LegacyConfigDir).unwrap(),
            "\"legacy_config_dir\""
        );
    }
}
