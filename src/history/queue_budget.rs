//! Nonblocking admission accounting for history messages.
//!
//! Reservations follow the payload through the mailbox, batching and storage.
//! Releasing a reservation on receipt would bound only the channel while a
//! stalled batch could still retain payloads outside that bound. Flush requests
//! use a separate budget so entry saturation cannot prevent a completion barrier.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReserveError {
    Full,
    Oversized,
}

#[derive(Debug)]
pub(super) struct QueueBudget {
    max_entries: usize,
    max_bytes: usize,
    entries: AtomicUsize,
    bytes: AtomicUsize,
}

impl QueueBudget {
    pub(super) const fn new(max_entries: usize, max_bytes: usize) -> Self {
        Self {
            max_entries,
            max_bytes,
            entries: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
        }
    }

    /// Reserve capacity without waiting for the worker or storage.
    /// Concurrent attempts may conservatively reject while another reservation
    /// is being released, but can never exceed either bound.
    pub(super) fn try_reserve(self: &Arc<Self>, bytes: usize) -> Result<Reservation, ReserveError> {
        if bytes > self.max_bytes {
            return Err(ReserveError::Oversized);
        }
        // These counters protect capacity, not publication of payload data.
        // The channel publishes the payload; Relaxed ordering is sufficient
        // for atomic accounting and avoids a global ordering requirement.
        self.entries
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(1).filter(|next| *next <= self.max_entries)
            })
            .map_err(|_| ReserveError::Full)?;
        if self
            .bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.max_bytes)
            })
            .is_err()
        {
            self.entries.fetch_sub(1, Ordering::Relaxed);
            return Err(ReserveError::Full);
        }
        Ok(Reservation {
            budget: Arc::clone(self),
            bytes,
        })
    }

    #[cfg(test)]
    pub(super) fn usage(&self) -> (usize, usize) {
        (
            self.entries.load(Ordering::Relaxed),
            self.bytes.load(Ordering::Relaxed),
        )
    }
}

/// Not Clone: one payload owns one reservation until it is actually discarded.
#[derive(Debug)]
pub(super) struct Reservation {
    budget: Arc<QueueBudget>,
    bytes: usize,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.bytes.fetch_sub(self.bytes, Ordering::Relaxed);
        self.budget.entries.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::{
        CommandEntry, HistoryDb, HistoryEnqueueOutcome, HistoryMessage, HistoryWriter,
        PendingHistoryBatch, WorkerConfig, history_worker,
    };
    use crate::config::HistoryRedactionMode;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn entry_and_byte_limits_are_independent_and_reusable() {
        let budget = Arc::new(QueueBudget::new(2, 10));
        let first = budget.try_reserve(6).unwrap();
        assert_eq!(budget.try_reserve(5).unwrap_err(), ReserveError::Full);
        assert_eq!(
            budget.usage(),
            (1, 6),
            "failed byte admission must release its slot"
        );
        let second = budget.try_reserve(4).unwrap();
        assert_eq!(budget.usage(), (2, 10));
        assert_eq!(budget.try_reserve(0).unwrap_err(), ReserveError::Full);
        drop(first);
        assert_eq!(budget.usage(), (1, 4));
        let replacement = budget.try_reserve(6).unwrap();
        drop((second, replacement));
        assert_eq!(budget.usage(), (0, 0));
    }

    #[test]
    fn oversized_and_overflowing_reservations_do_not_change_usage() {
        let budget = Arc::new(QueueBudget::new(2, 10));
        assert_eq!(budget.try_reserve(11).unwrap_err(), ReserveError::Oversized);
        assert_eq!(budget.usage(), (0, 0));
        let enormous = Arc::new(QueueBudget::new(2, usize::MAX));
        let first = enormous.try_reserve(usize::MAX).unwrap();
        assert_eq!(enormous.try_reserve(1).unwrap_err(), ReserveError::Full);
        assert_eq!(enormous.usage(), (1, usize::MAX));
        drop(first);
        assert_eq!(enormous.usage(), (0, 0));
    }

    #[test]
    fn zero_entry_budget_rejects_without_waiting_for_a_receiver() {
        let budget = Arc::new(QueueBudget::new(0, 10));
        assert_eq!(budget.try_reserve(1).unwrap_err(), ReserveError::Full);
        assert_eq!(budget.usage(), (0, 0));
    }

    #[test]
    fn concurrent_admission_never_exceeds_capacity() {
        use std::sync::Barrier;

        let budget = Arc::new(QueueBudget::new(8, 32));
        let release = Arc::new(Barrier::new(17));
        let (sent, received) = mpsc::channel();
        let observed = std::thread::scope(|scope| {
            for _ in 0..16 {
                let budget = Arc::clone(&budget);
                let release = Arc::clone(&release);
                let sent = sent.clone();
                scope.spawn(move || {
                    let reservation = budget.try_reserve(4);
                    sent.send(reservation.is_ok()).unwrap();
                    // Hold every successful reservation until the observer
                    // checks the exact total. No scheduling deadline is used.
                    release.wait();
                    drop(reservation);
                });
            }
            drop(sent);
            let accepted = received.iter().take(16).filter(|accepted| *accepted).count();
            let usage = budget.usage();
            // Release before asserting so a failing assertion cannot strand
            // scoped workers behind the barrier during panic unwinding.
            release.wait();
            (accepted, usage)
        });
        assert_eq!(observed, (8, (8, 32)));
        assert_eq!(budget.usage(), (0, 0));
    }

    /// No worker is started: queue saturation is deterministic rather than a
    /// race against the scheduler. Tests explicitly deliver or discard messages.
    fn unstarted_writer(
        entries: usize,
        bytes: usize,
        flushes: usize,
    ) -> (HistoryWriter, mpsc::Receiver<HistoryMessage>) {
        let (sender, receiver) = mpsc::channel();
        let writer = HistoryWriter {
            sender: Some(sender),
            handle: None,
            entry_budget: Some(Arc::new(QueueBudget::new(entries, bytes))),
            flush_budget: Some(Arc::new(QueueBudget::new(flushes, flushes))),
            redaction_mode: HistoryRedactionMode::None,
            session_id: "admission-test".to_string(),
            wait_for_worker_on_drop: false,
            drop_wait_deadline: None,
        };
        (writer, receiver)
    }

    #[test]
    fn dequeued_entries_keep_capacity_until_storage_finishes() {
        let (writer, receiver) = unstarted_writer(1, 4096, 2);
        let budget = Arc::clone(writer.entry_budget.as_ref().unwrap());
        assert_eq!(
            writer.try_log(CommandEntry::default()),
            HistoryEnqueueOutcome::Queued
        );
        let HistoryMessage::Entry(entry) = receiver.try_recv().unwrap() else {
            panic!("expected queued entry");
        };
        let mut batch = PendingHistoryBatch::new(4);
        batch.push(entry);
        assert_eq!(budget.usage().0, 1, "dequeue is not completion");
        assert_eq!(
            writer.try_log(CommandEntry::default()),
            HistoryEnqueueOutcome::QueueFull
        );
        let mut db = HistoryDb::open_in_memory().unwrap();
        let mut disabled = false;
        batch.flush(&mut db, None, &mut disabled, WorkerConfig::default().max_size_bytes);
        assert!(!disabled);
        assert_eq!(db.count_commands().unwrap(), 1);
        assert_eq!(budget.usage(), (0, 0));
        assert_eq!(
            writer.try_log(CommandEntry::default()),
            HistoryEnqueueOutcome::Queued
        );
        drop(receiver);
        assert_eq!(budget.usage(), (0, 0), "receiver failure must release queued payloads");
    }

    #[test]
    fn payload_accounting_includes_reserved_metadata_capacity() {
        let (writer, receiver) = unstarted_writer(2, 4096, 2);
        let entry = CommandEntry {
            hostname: Some(String::with_capacity(8192)),
            ..Default::default()
        };
        assert_eq!(writer.try_log(entry), HistoryEnqueueOutcome::EntryTooLarge);
        assert_eq!(writer.entry_budget.as_ref().unwrap().usage(), (0, 0));
        assert!(matches!(receiver.try_recv(), Err(mpsc::TryRecvError::Empty)));
    }

    #[test]
    fn redaction_precedes_retained_payload_accounting() {
        let (mut writer, receiver) = unstarted_writer(1, 4096, 2);
        writer.redaction_mode = HistoryRedactionMode::Full;
        assert_eq!(
            writer.try_log(CommandEntry {
                command: "x".repeat(8192),
                ..Default::default()
            }),
            HistoryEnqueueOutcome::Queued
        );
        let HistoryMessage::Entry(entry) = receiver.try_recv().unwrap() else {
            panic!("expected redacted entry");
        };
        assert_eq!(entry.entry.command, "[REDACTED]");
        drop(entry);
        assert_eq!(writer.entry_budget.as_ref().unwrap().usage(), (0, 0));
    }

    #[test]
    fn disabled_and_disconnected_writers_report_admission_without_leaking() {
        assert_eq!(
            HistoryWriter::disabled().try_log(CommandEntry::default()),
            HistoryEnqueueOutcome::Disabled
        );
        let (writer, receiver) = unstarted_writer(1, 4096, 2);
        drop(receiver);
        assert_eq!(
            writer.try_log(CommandEntry::default()),
            HistoryEnqueueOutcome::WorkerUnavailable
        );
        assert_eq!(writer.entry_budget.as_ref().unwrap().usage(), (0, 0));
        assert!(!writer.flush_sync_with_timeout(Duration::ZERO));
        assert_eq!(writer.flush_budget.as_ref().unwrap().usage(), (0, 0));
    }

    #[test]
    fn expired_flush_waiters_cannot_create_unbounded_control_backlog() {
        let (writer, receiver) = unstarted_writer(1, 4096, 2);
        for _ in 0..100 {
            assert!(!writer.flush_sync_with_timeout(Duration::ZERO));
        }
        assert_eq!(writer.flush_budget.as_ref().unwrap().usage(), (2, 2));
        let first = receiver.try_recv().unwrap();
        let second = receiver.try_recv().unwrap();
        assert!(matches!(first, HistoryMessage::Flush(_)));
        assert!(matches!(second, HistoryMessage::Flush(_)));
        assert!(matches!(receiver.try_recv(), Err(mpsc::TryRecvError::Empty)));
        // The queued request, not the expired waiter, owns its reservation.
        drop((first, second));
        assert_eq!(writer.flush_budget.as_ref().unwrap().usage(), (0, 0));
    }

    #[test]
    fn saturated_entry_and_flush_queues_still_deliver_shutdown_and_exact_rows() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("saturated-history.db");
        let db = HistoryDb::open(Some(path.clone())).unwrap();
        let (writer, receiver) = unstarted_writer(2, 8192, 2);
        let entries = Arc::clone(writer.entry_budget.as_ref().unwrap());
        let flushes = Arc::clone(writer.flush_budget.as_ref().unwrap());
        for command in ["first", "second"] {
            assert_eq!(
                writer.try_log(CommandEntry {
                    command: command.to_string(),
                    ..Default::default()
                }),
                HistoryEnqueueOutcome::Queued
            );
        }
        assert_eq!(
            writer.try_log(CommandEntry::default()),
            HistoryEnqueueOutcome::QueueFull
        );
        for _ in 0..3 {
            writer.flush();
        }
        assert_eq!(flushes.usage(), (2, 2), "flushes have independent capacity");
        // Shutdown has a reserved path; it never needs an entry or flush slot.
        drop(writer);
        history_worker(db, receiver, WorkerConfig::default());
        assert_eq!(entries.usage(), (0, 0));
        assert_eq!(flushes.usage(), (0, 0));
        let reader = rusqlite::Connection::open(&path).unwrap();
        let mut statement = reader.prepare("SELECT command FROM commands ORDER BY id").unwrap();
        let commands = statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(commands, vec!["first", "second"]);
    }
}
