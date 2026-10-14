//! WAL-aware size limits for history storage.
//!
//! A WAL reader can keep the main file small while committed database pages
//! live in the WAL. Install and verify SQLite's page limit against the logical
//! database, without making every worker open checkpoint other connections.
//! Recheck under the write transaction: another connection can grow the file
//! after initialization and cause SQLite to raise this connection's page limit.

use super::{CommandEntry, HistoryDb, HistoryError, SqliteValue};

impl HistoryDb {
    /// Install the worker's page cap without a routine TRUNCATE checkpoint.
    ///
    /// As with the synchronous maintenance path, compact a database with free
    /// pages once if it is over budget. Healthy under-budget opens perform only
    /// pragma queries and connection-local configuration. Ordinary WAL close
    /// handling and autocheckpointing remain enabled.
    pub(crate) fn enforce_live_size_limit(&self, max_bytes: u64) -> Result<bool, HistoryError> {
        if self.path().is_none() {
            return Ok(true);
        }
        if !self.connection().is_autocommit() {
            return Err(HistoryError::IntegrityCheckFailed(
                "cannot install a history size limit inside an unfinished transaction".to_string(),
            ));
        }

        let page_size = history_page_size(self)?;
        let max_pages = (max_bytes / page_size).max(1);
        if pragma_integer(self, "PRAGMA main.page_count")? > max_pages
            && pragma_integer(self, "PRAGMA main.freelist_count")? > 0
        {
            self.vacuum()?;
        }

        let installed = install_page_limit(self, max_bytes, page_size)?;
        let journal_limit = (max_bytes / 10).clamp(page_size, 16 * 1024 * 1024);
        self.connection()
            .execute(&format!("PRAGMA main.journal_size_limit={journal_limit}"))?;

        // This is a connection-local logical-page limit, not a promise to
        // immediately shrink a WAL or main file held by an older reader.
        Ok(installed)
    }

    /// Commit one entry only after checking the live cap under the writer lock.
    pub(crate) fn log_command_with_live_limit(
        &self,
        entry: &CommandEntry,
        max_bytes: u64,
    ) -> Result<i64, HistoryError> {
        self.write_with_live_limit(max_bytes, || self.log_command(entry))
    }

    /// Commit a batch atomically, without racing another connection's growth.
    pub(crate) fn log_commands_batch_with_live_limit(
        &self,
        entries: &[CommandEntry],
        max_bytes: u64,
    ) -> Result<(), HistoryError> {
        if entries.is_empty() {
            return Ok(());
        }
        self.write_with_live_limit(max_bytes, || {
            for entry in entries {
                self.log_command(entry)?;
            }
            Ok(())
        })
    }

    fn write_with_live_limit<T>(
        &self,
        max_bytes: u64,
        write: impl FnOnce() -> Result<T, HistoryError>,
    ) -> Result<T, HistoryError> {
        // Never commit or roll back a transaction owned by our caller.
        if !self.connection().is_autocommit() {
            return Err(HistoryError::IntegrityCheckFailed(
                "cannot write capped history inside an unfinished transaction".to_string(),
            ));
        }
        // BEGIN IMMEDIATE establishes write ownership before reading page
        // state. Checking and then starting the transaction leaves a race in
        // which another connection grows beyond the cap between those steps.
        self.connection().execute("BEGIN IMMEDIATE;")?;
        let result = (|| {
            if self.path().is_some()
                && !install_page_limit(self, max_bytes, history_page_size(self)?)?
            {
                return Err(HistoryError::Sqlite(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),
                    Some("history logical database exceeds the configured size limit".to_string()),
                )));
            }
            let value = write()?;
            self.connection().execute("COMMIT;")?;
            Ok(value)
        })();
        if result.is_err() {
            // Preserve the original error unless cleanup leaves a transaction
            // active. In that case even a single-row failure must request
            // recovery: later inserts would not commit independently.
            let rollback = self.connection().execute("ROLLBACK;");
            if !self.connection().is_autocommit() {
                return Err(HistoryError::IntegrityCheckFailed(format!(
                    "capped history rollback left an active transaction: {rollback:?}"
                )));
            }
        }
        result
    }
}

fn history_page_size(db: &HistoryDb) -> Result<u64, HistoryError> {
    let size = pragma_integer(db, "PRAGMA main.page_size")?;
    if size == 0 {
        return Err(HistoryError::IntegrityCheckFailed(
            "SQLite returned a zero history page size".to_string(),
        ));
    }
    Ok(size)
}

fn install_page_limit(
    db: &HistoryDb,
    max_bytes: u64,
    page_size: u64,
) -> Result<bool, HistoryError> {
    let max_pages = (max_bytes / page_size).max(1);
    // SQLite cannot lower this below the current logical page count. It may
    // also raise a previously installed limit when another connection grows
    // the database. Verify the returned value every time, not just at open.
    let installed = pragma_integer(db, &format!("PRAGMA main.max_page_count={max_pages}"))?;
    Ok(installed <= max_pages
        && installed
            .checked_mul(page_size)
            .is_some_and(|bytes| bytes <= max_bytes))
}

fn pragma_integer(db: &HistoryDb, sql: &str) -> Result<u64, HistoryError> {
    let row = db.connection().query_row(sql)?;
    match row.values().first() {
        Some(SqliteValue::Integer(value)) if *value >= 0 => Ok(*value as u64),
        _ => Err(HistoryError::IntegrityCheckFailed(format!(
            "SQLite returned an invalid integer for {sql}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HistoryConfig, HistoryRedactionMode};
    use crate::history::HistoryWriter;
    use std::path::Path;

    const CAP: u64 = 1024 * 1024;

    fn wal_length(path: &Path) -> u64 {
        let mut wal = path.as_os_str().to_os_string();
        wal.push("-wal");
        std::fs::metadata(std::path::PathBuf::from(wal))
            .expect("WAL file")
            .len()
    }

    fn add_payload(db: &HistoryDb) {
        db.connection()
            .execute("CREATE TABLE size_probe(payload BLOB); PRAGMA wal_autocheckpoint=0;")
            .unwrap();
        for _ in 0..32 {
            db.connection()
                .execute("INSERT INTO size_probe VALUES (zeroblob(65536))")
                .unwrap();
        }
    }

    #[test]
    fn under_cap_install_does_not_checkpoint_committed_wal_frames() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("no-checkpoint.db");
        let db = HistoryDb::open(Some(path.clone())).unwrap();
        db.checkpoint_truncate().unwrap();
        db.log_command(&CommandEntry {
            command: "preserved".to_string(),
            ..Default::default()
        })
        .unwrap();
        let main_before = db.file_size().unwrap();
        let wal_before = wal_length(&path);
        assert!(wal_before > 0);

        assert!(db.enforce_live_size_limit(CAP).unwrap());
        assert_eq!(
            wal_length(&path),
            wal_before,
            "cap setup must not drain WAL"
        );
        assert_eq!(db.file_size().unwrap(), main_before);
        assert_eq!(db.count_commands().unwrap(), 1);
        let page_size = pragma_integer(&db, "PRAGMA main.page_size").unwrap();
        assert_eq!(
            pragma_integer(&db, "PRAGMA main.max_page_count").unwrap(),
            CAP / page_size
        );
        assert_eq!(
            pragma_integer(&db, "PRAGMA main.journal_size_limit").unwrap(),
            (CAP / 10).clamp(page_size, 16 * 1024 * 1024)
        );
    }

    #[test]
    fn wal_only_growth_is_rejected_even_when_the_main_file_is_under_cap() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("wal-only-growth.db");
        let db = HistoryDb::open(Some(path.clone())).unwrap();
        db.checkpoint_truncate().unwrap();
        let reader = rusqlite::Connection::open(&path).unwrap();
        reader.execute_batch("BEGIN;").unwrap();
        let count: i64 = reader
            .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
        add_payload(&db);

        assert!(
            db.file_size().unwrap() < CAP,
            "fixture must hide growth in WAL"
        );
        let page_size = pragma_integer(&db, "PRAGMA main.page_size").unwrap();
        assert!(pragma_integer(&db, "PRAGMA main.page_count").unwrap() * page_size > CAP);
        assert!(!db.enforce_live_size_limit(CAP).unwrap());
        assert!(pragma_integer(&db, "PRAGMA main.max_page_count").unwrap() > CAP / page_size);

        // Exercise the real worker initialization path with the same pinned
        // reader. A rejected limit must disable telemetry rather than allowing
        // an insert just because it happens to reuse existing database space.
        let writer = HistoryWriter::new(
            Some(path.clone()),
            &HistoryConfig {
                enabled: true,
                auto_prune: false,
                max_size_mb: 1,
                redaction_mode: HistoryRedactionMode::None,
                ..Default::default()
            },
        );
        writer.log(CommandEntry {
            command: "must not enter an over-cap database".to_string(),
            ..Default::default()
        });
        drop(writer);
        assert_eq!(db.count_commands().unwrap(), 0);
        reader.execute_batch("ROLLBACK;").unwrap();
    }

    #[test]
    fn cap_installation_does_not_need_another_writers_transaction_to_end() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("writer-lock.db");
        let db = HistoryDb::open(Some(path.clone())).unwrap();
        let locker = rusqlite::Connection::open(&path).unwrap();
        locker.execute_batch("BEGIN IMMEDIATE;").unwrap();
        assert!(db.enforce_live_size_limit(CAP).unwrap());
        assert!(db.connection().is_autocommit());
        locker.execute_batch("ROLLBACK;").unwrap();
        db.log_command(&CommandEntry::default()).unwrap();
        assert_eq!(db.count_commands().unwrap(), 1);
    }

    #[test]
    fn over_cap_free_pages_can_still_be_reclaimed() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("reclaim.db");
        let db = HistoryDb::open(Some(path.clone())).unwrap();
        db.log_command(&CommandEntry {
            command: "kept during compaction".to_string(),
            ..Default::default()
        })
        .unwrap();
        add_payload(&db);
        db.connection().execute("DELETE FROM size_probe").unwrap();
        assert!(pragma_integer(&db, "PRAGMA main.freelist_count").unwrap() > 0);
        assert!(db.enforce_live_size_limit(CAP).unwrap());
        assert_eq!(db.count_commands().unwrap(), 1);
        let logical_bytes = pragma_integer(&db, "PRAGMA main.page_count").unwrap()
            * pragma_integer(&db, "PRAGMA main.page_size").unwrap();
        assert!(logical_bytes <= CAP);
    }

    #[test]
    fn installed_limit_rejects_growth_and_retains_committed_rows() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("growth-cap.db");
        let db = HistoryDb::open(Some(path.clone())).unwrap();
        assert!(db.enforce_live_size_limit(CAP).unwrap());
        let mut successes = 0;
        let mut full = false;
        for index in 0..100 {
            match db.log_command(&CommandEntry {
                command: format!("{index}:{}", "x".repeat(64 * 1024)),
                ..Default::default()
            }) {
                Ok(_) => successes += 1,
                Err(HistoryError::Sqlite(rusqlite::Error::SqliteFailure(code, _)))
                    if code.code == rusqlite::ErrorCode::DiskFull =>
                {
                    full = true;
                    break;
                }
                Err(error) => panic!("unexpected storage error: {error}"),
            }
        }
        assert!(full && successes > 0);
        assert_eq!(db.count_commands().unwrap(), successes);
        assert!(db.connection().is_autocommit());
        drop(db);
        assert!(std::fs::metadata(&path).unwrap().len() <= CAP);
        let reopened = HistoryDb::open(Some(path)).unwrap();
        assert_eq!(reopened.count_commands().unwrap(), successes);
    }

    #[test]
    fn unfinished_transactions_are_not_used_to_certify_a_size_limit() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("unfinished.db");
        let db = HistoryDb::open(Some(path)).unwrap();
        db.connection().execute("BEGIN IMMEDIATE;").unwrap();
        assert!(db.enforce_live_size_limit(CAP).is_err());
        assert!(
            !db.connection().is_autocommit(),
            "limit check must not commit caller work"
        );
        db.connection().execute("ROLLBACK;").unwrap();
        assert!(db.enforce_live_size_limit(CAP).unwrap());
    }

    #[test]
    fn memory_databases_keep_the_existing_unlimited_policy() {
        let db = HistoryDb::open_in_memory().unwrap();
        assert!(db.enforce_live_size_limit(0).unwrap());
    }

    #[test]
    fn later_external_growth_cannot_bypass_single_or_batch_write_limits() {
        for batch in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("late-growth.db");
            let db = HistoryDb::open(Some(path.clone())).unwrap();
            assert!(db.enforce_live_size_limit(CAP).unwrap());
            let other = HistoryDb::open(Some(path.clone())).unwrap();
            add_payload(&other);
            // SQLite raises the old connection's maximum as it discovers the
            // larger database. A cap installed only at startup is insufficient.
            let pages = pragma_integer(&db, "PRAGMA main.page_count").unwrap();
            let page_size = history_page_size(&db).unwrap();
            assert!(pages * page_size > CAP);
            assert!(pragma_integer(&db, "PRAGMA main.max_page_count").unwrap() > CAP / page_size);
            let entry = CommandEntry {
                command: "mustremainabsent".to_string(),
                ..Default::default()
            };
            let result = if batch {
                db.log_commands_batch_with_live_limit(&[entry.clone(), entry], CAP)
            } else {
                db.log_command_with_live_limit(&entry, CAP).map(|_| ())
            };
            assert!(matches!(
                result,
                Err(HistoryError::Sqlite(rusqlite::Error::SqliteFailure(code, _)))
                    if code.code == rusqlite::ErrorCode::DiskFull
            ));
            assert!(db.connection().is_autocommit());
            assert_eq!(other.count_commands().unwrap(), 0);
        }
    }

    #[test]
    fn writer_lock_covers_the_limit_check_and_the_entire_insert() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("locked-check.db");
        let db = HistoryDb::open(Some(path.clone())).unwrap();
        let other = rusqlite::Connection::open(&path).unwrap();
        other.busy_timeout(std::time::Duration::ZERO).unwrap();
        db.write_with_live_limit(CAP, || {
            assert!(!db.connection().is_autocommit());
            let attempted = other.execute("CREATE TABLE competing_writer(value TEXT)", []);
            assert!(matches!(
                attempted,
                Err(rusqlite::Error::SqliteFailure(code, _))
                    if code.code == rusqlite::ErrorCode::DatabaseBusy
            ));
            db.log_command(&CommandEntry {
                command: "protected".to_string(),
                ..Default::default()
            })
        })
        .unwrap();
        assert!(db.connection().is_autocommit());
        assert_eq!(db.count_commands().unwrap(), 1);
    }

    #[test]
    fn capped_batch_rolls_back_rejections_and_remains_usable() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("capped-rollback.db");
        let db = HistoryDb::open(Some(path)).unwrap();
        db.connection()
            .execute(
                "CREATE TEMP TRIGGER reject_capped_entry BEFORE INSERT ON commands
                 WHEN new.command = 'rejected'
                 BEGIN SELECT RAISE(ABORT, 'rejected by fixture'); END;",
            )
            .unwrap();
        let good = CommandEntry {
            command: "retained".to_string(),
            ..Default::default()
        };
        let rejected = CommandEntry {
            command: "rejected".to_string(),
            ..Default::default()
        };
        assert!(
            db.log_commands_batch_with_live_limit(&[good.clone(), rejected], CAP)
                .is_err()
        );
        assert!(db.connection().is_autocommit());
        assert_eq!(db.count_commands().unwrap(), 0);
        db.log_command_with_live_limit(&good, CAP).unwrap();
        assert_eq!(db.count_commands().unwrap(), 1);
        let indexed = db
            .connection()
            .query("SELECT rowid FROM commands_fts WHERE commands_fts MATCH 'retained'")
            .unwrap();
        assert_eq!(indexed.len(), 1);
    }

    #[test]
    fn capped_commit_contention_rolls_back_and_does_not_replay() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("capped-commit.db");
        let db = HistoryDb::open(Some(path.clone())).unwrap();
        db.connection()
            .execute("PRAGMA journal_mode=DELETE;")
            .unwrap();
        let observer = rusqlite::Connection::open(&path).unwrap();
        observer.execute_batch("BEGIN;").unwrap();
        let count: i64 = observer
            .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
        let entry = CommandEntry {
            command: "aftercontention".to_string(),
            ..Default::default()
        };
        let result = db.log_command_with_live_limit(&entry, CAP);
        assert!(matches!(
            result,
            Err(HistoryError::Sqlite(rusqlite::Error::SqliteFailure(code, _)))
                if code.code == rusqlite::ErrorCode::DatabaseBusy
        ));
        assert!(db.connection().is_autocommit());
        observer.execute_batch("ROLLBACK;").unwrap();
        assert_eq!(db.count_commands().unwrap(), 0);
        db.log_command_with_live_limit(&entry, CAP).unwrap();
        assert_eq!(db.count_commands().unwrap(), 1);
    }

    #[test]
    fn capped_write_never_owns_an_existing_transaction() {
        let db = HistoryDb::open_in_memory().unwrap();
        db.connection().execute("BEGIN IMMEDIATE;").unwrap();
        let entry = CommandEntry::default();
        db.log_command(&entry).unwrap();
        assert!(db.log_command_with_live_limit(&entry, CAP).is_err());
        assert!(
            db.log_commands_batch_with_live_limit(&[entry.clone(), entry], CAP)
                .is_err()
        );
        assert!(!db.connection().is_autocommit());
        assert_eq!(db.count_commands().unwrap(), 1);
        db.connection().execute("ROLLBACK;").unwrap();
        db.log_command_with_live_limit(&CommandEntry::default(), 0)
            .unwrap();
        assert_eq!(
            db.count_commands().unwrap(),
            1,
            "in-memory writes remain uncapped"
        );
    }

    #[test]
    fn running_writer_stops_after_another_connection_outgrows_its_cap() {
        use crate::history::HistoryEnqueueOutcome;
        use std::time::Duration;

        for batch_size in [1, 50] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("running-writer-cap.db");
            let other = HistoryDb::open(Some(path.clone())).unwrap();
            let writer = HistoryWriter::new(
                Some(path),
                &HistoryConfig {
                    enabled: true,
                    auto_prune: false,
                    max_size_mb: 1,
                    batch_size,
                    redaction_mode: HistoryRedactionMode::None,
                    ..Default::default()
                },
            );
            assert_eq!(
                writer.try_log(CommandEntry {
                    command: "positivecontrol".to_string(),
                    ..Default::default()
                }),
                HistoryEnqueueOutcome::Queued
            );
            // Synchronize startup and prove a real write before external
            // growth. The watchdog is not a throughput/latency requirement.
            assert!(
                writer.flush_sync_with_timeout(Duration::from_secs(30)),
                "startup flush did not complete within the test watchdog"
            );
            assert_eq!(other.count_commands().unwrap(), 1);
            add_payload(&other);
            assert!(
                pragma_integer(&other, "PRAGMA main.page_count").unwrap()
                    * history_page_size(&other).unwrap()
                    > CAP
            );
            for command in ["aftergrowthfirst", "aftergrowthsecond"] {
                assert_eq!(
                    writer.try_log(CommandEntry {
                        command: command.to_string(),
                        ..Default::default()
                    }),
                    HistoryEnqueueOutcome::Queued
                );
            }
            // Normal library shutdown is the persistence barrier, not a sleep.
            drop(writer);
            let rows = other
                .connection()
                .query("SELECT command FROM commands ORDER BY id")
                .unwrap();
            assert_eq!(rows.len(), 1, "only the pre-growth event may persist");
            assert_eq!(
                rows[0].values(),
                &[SqliteValue::Text("positivecontrol".to_string())]
            );
            let unexpected = other
                .connection()
                .query(
                    "SELECT rowid FROM commands_fts WHERE commands_fts MATCH 'aftergrowthfirst OR aftergrowthsecond'",
                )
                .unwrap();
            assert!(unexpected.is_empty());
        }
    }

    #[test]
    fn recovered_worker_rechecks_the_limit_before_its_next_batch() {
        use crate::history::{flush_batch_with_recovery, recover_history_db};

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("recovered-writer-cap.db");
        let mut db = HistoryDb::open(Some(path.clone())).unwrap();
        let other = HistoryDb::open(Some(path.clone())).unwrap();
        db.log_command(&CommandEntry {
            command: "beforerecovery".to_string(),
            ..Default::default()
        })
        .unwrap();
        assert!(recover_history_db(&mut db, Some(&path), CAP));
        // Recovery installed a valid cap, then a different connection grew
        // the file. The retry/write path must not trust the recovered cap.
        add_payload(&other);
        let mut batch = vec![
            CommandEntry {
                command: "recoveryfirst".to_string(),
                ..Default::default()
            },
            CommandEntry {
                command: "recoverysecond".to_string(),
                ..Default::default()
            },
        ];
        let mut disabled = false;
        flush_batch_with_recovery(&mut db, &mut batch, Some(&path), &mut disabled, CAP);
        assert!(
            disabled,
            "a newly over-cap database must disable further writes"
        );
        assert!(batch.is_empty());
        assert!(db.connection().is_autocommit());
        let rows = other
            .connection()
            .query("SELECT command FROM commands ORDER BY id")
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].values(),
            &[SqliteValue::Text("beforerecovery".to_string())]
        );
    }
}
