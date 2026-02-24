//! In-memory epoch grace window store for SCP MLS ratcheting.
//!
//! When a group advances to a new epoch via a Commit, the old epoch's key
//! material must be retained briefly so that in-flight messages encrypted under
//! the old epoch can still be decrypted. The [`EpochGraceStore`] tracks which
//! epochs are within this grace window.
//!
//! # Grace window rules (ADR-001, criterion 6)
//!
//! - **Duration:** The shorter of (a) all members have sent a message in the
//!   new epoch, or (b) 30 seconds from local Commit processing time. The
//!   30-second hard ceiling is **not** configurable.
//! - **Storage:** In-memory only, never persisted to disk.
//! - **Indexing:** By epoch number.
//! - **Isolation:** Only `decrypt()` with a matching epoch number may access
//!   the grace store. No other code path should reach it.
//! - **Cleanup:** After the grace window closes, old epoch secrets are
//!   destroyed (forward secrecy). Messages arriving after the window closes
//!   that reference old epochs are unrecoverable — a warning is logged and a
//!   [`StaleEpochMessage`] event is emitted.

use std::collections::HashMap;

use tokio::time::Instant;

/// Hard ceiling for the epoch grace window: 30 seconds.
///
/// This bounds the forward secrecy window. It is intentionally not
/// configurable — see ADR-001 criterion 6.
const GRACE_WINDOW_DURATION: std::time::Duration = std::time::Duration::from_secs(30);

/// In-memory store tracking which epochs are within their grace window.
///
/// Since `OpenMLS` manages the actual cryptographic key material internally,
/// this store acts as a coordination mechanism for the SCP layer: it records
/// which old epochs are still within the grace period so that `decrypt()` can
/// decide whether to attempt decryption with old epoch keys.
///
/// # Thread safety
///
/// This type is **not** `Sync`. It is intended to be used behind a mutex or
/// owned by a single task.
#[derive(Debug)]
pub struct EpochGraceStore {
    /// Map from epoch number to its grace window deadline.
    epochs: HashMap<u64, Instant>,
}

impl EpochGraceStore {
    /// Creates a new, empty grace store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            epochs: HashMap::new(),
        }
    }

    /// Marks an epoch as entering the grace period.
    ///
    /// The epoch will be considered "in grace" until 30 seconds from now.
    /// If the epoch is already tracked, its deadline is **not** extended.
    pub fn add_epoch(&mut self, epoch: u64) {
        // Only insert if not already tracked — don't extend existing deadlines.
        self.epochs
            .entry(epoch)
            .or_insert_with(|| Instant::now() + GRACE_WINDOW_DURATION);
    }

    /// Returns `true` if the given epoch is still within its grace window.
    ///
    /// Returns `false` if the epoch was never tracked or its window has expired.
    #[must_use]
    pub fn is_in_grace(&self, epoch: u64) -> bool {
        self.epochs
            .get(&epoch)
            .is_some_and(|deadline| Instant::now() < *deadline)
    }

    /// Removes all epochs whose grace windows have expired.
    ///
    /// Call this periodically (e.g., before decrypt attempts) to keep the
    /// store clean. Expired epochs are permanently removed — their key
    /// material is no longer accessible for decryption.
    pub fn expire_old_epochs(&mut self) {
        let now = Instant::now();
        self.epochs.retain(|_epoch, deadline| now < *deadline);
    }

    /// Explicitly removes an epoch from the grace store.
    ///
    /// Use this for the member-activity-based closure path: when all members
    /// have sent at least one message in the new epoch, the old epoch's grace
    /// window can be closed early.
    pub fn remove_epoch(&mut self, epoch: u64) {
        self.epochs.remove(&epoch);
    }

    /// Returns the number of epochs currently in the grace store.
    ///
    /// This includes epochs whose windows may have expired but have not yet
    /// been purged by [`expire_old_epochs`](Self::expire_old_epochs).
    #[must_use]
    pub fn len(&self) -> usize {
        self.epochs.len()
    }

    /// Returns `true` if no epochs are currently tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.epochs.is_empty()
    }
}

impl Default for EpochGraceStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Event emitted when a message arrives referencing an epoch whose grace
/// window has already closed.
///
/// The message is unrecoverable — old epoch keys have been destroyed for
/// forward secrecy. Applications should log this event and notify the user
/// that a message was lost.
///
/// See ADR-001 criterion 6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleEpochMessage {
    /// The DID of the sender whose message arrived too late.
    pub sender_did: String,
    /// The epoch number the message was encrypted under.
    pub epoch: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn new_store_is_empty() {
        let store = EpochGraceStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn add_epoch_tracks_it_in_grace() {
        let mut store = EpochGraceStore::new();
        store.add_epoch(1);
        assert!(store.is_in_grace(1));
        assert!(!store.is_in_grace(2));
        assert_eq!(store.len(), 1);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn remove_epoch_makes_it_not_in_grace() {
        let mut store = EpochGraceStore::new();
        store.add_epoch(1);
        assert!(store.is_in_grace(1));

        store.remove_epoch(1);
        assert!(!store.is_in_grace(1));
        assert!(store.is_empty());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn remove_nonexistent_epoch_is_noop() {
        let mut store = EpochGraceStore::new();
        store.remove_epoch(42); // should not panic
        assert!(store.is_empty());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn multiple_epochs_tracked_independently() {
        let mut store = EpochGraceStore::new();
        store.add_epoch(1);
        store.add_epoch(2);
        store.add_epoch(3);

        assert_eq!(store.len(), 3);
        assert!(store.is_in_grace(1));
        assert!(store.is_in_grace(2));
        assert!(store.is_in_grace(3));

        store.remove_epoch(2);
        assert!(store.is_in_grace(1));
        assert!(!store.is_in_grace(2));
        assert!(store.is_in_grace(3));
        assert_eq!(store.len(), 2);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn expire_old_epochs_removes_expired() {
        let mut store = EpochGraceStore::new();
        // Manually insert an epoch with an already-expired deadline.
        store
            .epochs
            .insert(0, Instant::now() - std::time::Duration::from_secs(1));
        store.add_epoch(1); // This one should still be valid.

        assert_eq!(store.len(), 2);
        store.expire_old_epochs();
        assert_eq!(store.len(), 1);
        assert!(!store.is_in_grace(0));
        assert!(store.is_in_grace(1));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn is_in_grace_returns_false_for_expired_epoch() {
        let mut store = EpochGraceStore::new();
        // Insert with past deadline.
        store
            .epochs
            .insert(5, Instant::now() - std::time::Duration::from_secs(1));
        assert!(!store.is_in_grace(5));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn default_creates_empty_store() {
        let store = EpochGraceStore::default();
        assert!(store.is_empty());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn stale_epoch_message_fields() {
        let event = StaleEpochMessage {
            sender_did: "did:dht:z6MkAlice".to_string(),
            epoch: 42,
        };
        assert_eq!(event.sender_did, "did:dht:z6MkAlice");
        assert_eq!(event.epoch, 42);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn add_epoch_does_not_extend_existing_deadline() {
        let mut store = EpochGraceStore::new();
        store.add_epoch(1);

        // Get the original deadline.
        let original_deadline = store.epochs[&1];

        // Adding the same epoch again should not change the deadline.
        store.add_epoch(1);
        assert_eq!(store.epochs[&1], original_deadline);
    }
}
