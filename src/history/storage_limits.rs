//! WAL-aware size limits for the asynchronous history worker.
//!
//! A WAL reader can keep the main file small while committed database pages
//! live in the WAL. Install and verify SQLite's page limit against the logical
//! database, without making every worker open checkpoint other connections.

use super::{HistoryDb, HistoryError, SqliteValue};

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

        let page_size = pragma_integer(self, "PRAGMA main.page_size")?;
        if page_size == 0 {
            return Err(HistoryError::IntegrityCheckFailed(
                "SQLite returned a zero history page size".to_string(),
            ));
        }
        let max_pages = (max_bytes / page_size).max(1);
        if pragma_integer(self, "PRAGMA main.page_count")? > max_pages
            && pragma_integer(self, "PRAGMA main.freelist_count")? > 0
        {
            self.vacuum()?;
        }

        // SQLite cannot lower this below the current logical page count.
        // Inspect the returned value: successful execution alone does not
        // establish that the requested cap was actually installed.
        let installed = pragma_integer(self, &format!("PRAGMA main.max_page_count={max_pages}"))?;
        let journal_limit = (max_bytes / 10).clamp(page_size, 16 * 1024 * 1024);
        self.connection()
            .execute(&format!("PRAGMA main.journal_size_limit={journal_limit}"))?;

        // This is a connection-local logical-page limit, not a promise to
        // immediately shrink a WAL or main file held by an older reader.
        Ok(installed <= max_pages
            && installed
                .checked_mul(page_size)
                .is_some_and(|bytes| bytes <= max_bytes))
    }
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
    use crate::history::{CommandEntry, HistoryWriter};
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
        assert_eq!(wal_length(&path), wal_before, "cap setup must not drain WAL");
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
}
