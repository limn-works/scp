//! Epoch grace window store for SCP MLS ratcheting.
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
//! - **Storage:** Persisted alongside the context snapshot via
//!   [`to_grace_entries`](EpochGraceStore::to_grace_entries) (§23.11). The
//!   in-memory store is the authoritative runtime cache; persisted entries
//!   are loaded on recovery via
//!   [`restore_from_entries`](EpochGraceStore::restore_from_entries) to
//!   reconstruct the grace store after crashes.
//! - **Indexing:** By epoch number.
//! - **Isolation:** Only `decrypt()` with a matching epoch number may access
//!   the grace store. No other code path should reach it.
//! - **Cleanup:** After the grace window closes, old epoch secrets are
//!   destroyed (forward secrecy). Messages arriving after the window closes
//!   that reference old epochs are unrecoverable — a warning is logged and a
//!   [`StaleEpochMessage`] event is emitted.
//!
//! # Capacity bound (SCP-171)
//!
//! The store enforces a maximum capacity ([`MAX_GRACE_EPOCHS`]) to prevent
//! unbounded memory growth from frequent epoch advances. When capacity is
//! reached, the oldest epoch is evicted regardless of its grace window
//! deadline. This bounds the forward secrecy exposure window even under
//! adversarial epoch-advance patterns.
//!
//! # `OpenMLS` key material lifecycle
//!
//! **Important:** This store does NOT hold cryptographic key material. It only
//! tracks epoch numbers and grace window deadlines. Actual MLS key material is
//! managed entirely by `OpenMLS` internally:
//!
//! - `MlsGroup::merge_staged_commit()` and `merge_pending_commit()` call
//!   `delete_previous_epoch_keypairs()` automatically, which removes the
//!   previous epoch's encryption key pairs from the storage provider.
//! - Past epoch message secrets are managed by `OpenMLS`'s `MessageSecretsStore`,
//!   a bounded `VecDeque` controlled by `max_past_epochs` config. SCP sets
//!   `max_past_epochs = 2` (in both `MlsGroupCreateConfig` and
//!   `MlsGroupJoinConfig`) so that the 2 most recent past epochs' message
//!   secrets are retained, aligning with the 30-second sender key grace window
//!   (§9.16.2, §9.7). See issue #324.
//! - Forward secrecy of actual cryptographic material is enforced by `OpenMLS`,
//!   not by this grace store. This store's role is to tell the SCP decrypt path
//!   whether to *attempt* decryption for a given epoch. Evicting an epoch from
//!   this store means the SCP layer will reject messages from that epoch with a
//!   [`StaleEpochMessage`] error, even if `OpenMLS` might still technically
//!   hold the keys (within its 2-epoch past-secrets window).
//!
//! # Epoch expiration callback (SCP-171)
//!
//! The store supports an optional callback ([`OnEpochExpired`]) that fires
//! whenever epochs are expired or evicted. This decouples the grace store
//! from `OpenMLS` types while letting callers react to epoch closures (e.g.,
//! logging, metrics, or triggering additional cleanup). The callback receives
//! a slice of expired epoch numbers.

use std::collections::HashMap;
use std::sync::Arc;

use scp_primitives::{Clock, SystemClock};
use serde::{Deserialize, Serialize};

/// Callback type invoked when epochs are expired or evicted from the grace store.
///
/// Receives a slice of epoch numbers that were just removed. Callers can use
/// this to log forward-secrecy window closures, emit metrics, or perform
/// additional cleanup. The callback must not panic.
///
/// This is a type alias for a boxed closure to keep the grace store decoupled
/// from `OpenMLS` types. The caller (e.g., `process_commit` in `ratchet.rs`)
/// is responsible for translating epoch numbers into any provider-specific
/// key deletion operations if needed.
pub type OnEpochExpired = Box<dyn FnMut(&[u64]) + Send>;

/// A persistable grace window entry for crash recovery (§23.11).
///
/// This struct is serialized to `ProtocolRepository` under
/// `context/{context_id}/grace/{epoch:020d}` and loaded on startup to restore
/// the [`EpochGraceStore`] after crashes. The `expires_at_unix_secs` field
/// records the absolute wall-clock expiration time so that recovery can compare
/// against `now` to determine whether the grace period has elapsed during
/// downtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraceEntry {
    /// The epoch number this grace entry covers.
    pub epoch: u64,
    /// Absolute expiration time as Unix seconds.
    ///
    /// On recovery, compare against `now` — if `now >= expires_at_unix_secs`,
    /// the entry has expired and the old epoch keys MUST be destroyed
    /// (forward secrecy). If `now < expires_at_unix_secs`, retain the keys
    /// and restart the grace timer from this timestamp.
    pub expires_at_unix_secs: u64,
}

/// Hard ceiling for the epoch grace window: 30 seconds, expressed in
/// milliseconds for wall-clock deadline arithmetic.
///
/// This bounds the forward secrecy window. It is intentionally not
/// configurable — see ADR-001 criterion 6.
const GRACE_WINDOW_MILLIS: u64 = 30_000;

/// Maximum number of epochs the grace store will track simultaneously.
///
/// This prevents unbounded memory growth when an attacker triggers frequent
/// epoch advances. When the store is at capacity and a new epoch is added,
/// expired epochs are purged first; if still at capacity, the oldest epoch
/// is evicted regardless of its deadline.
///
/// 100 epochs at 30 seconds each represents ~50 minutes of grace history,
/// which is far more than any legitimate operational need.
pub const MAX_GRACE_EPOCHS: usize = 100;

/// In-memory store tracking which epochs are within their grace window.
///
/// Since `OpenMLS` manages the actual cryptographic key material internally,
/// this store acts as a coordination mechanism for the SCP layer: it records
/// which old epochs are still within the grace period so that `decrypt()` can
/// decide whether to attempt decryption with old epoch keys.
///
/// The store enforces a maximum capacity of [`MAX_GRACE_EPOCHS`] to prevent
/// unbounded growth. See module-level docs for details on capacity enforcement
/// and the `OpenMLS` key material lifecycle.
///
/// # Epoch expiration callback
///
/// An optional [`OnEpochExpired`] callback can be set via
/// [`set_on_epoch_expired`](Self::set_on_epoch_expired). When set, it is
/// invoked with the list of expired/evicted epoch numbers whenever
/// `add_epoch()` or `expire_old_epochs()` removes epochs. This lets callers
/// react to epoch closures without the store needing to know about `OpenMLS`.
///
/// # Thread safety
///
/// This type is **not** `Sync`. It is intended to be used behind a mutex or
/// owned by a single task.
pub struct EpochGraceStore {
    /// Map from epoch number to its grace window deadline, stored as an
    /// absolute wall-clock timestamp in **milliseconds** since the Unix epoch
    /// (read from the injected [`Clock`]). Wall-clock (not monotonic
    /// `Instant`) so the store carries no platform-clock dependency and
    /// compiles to `wasm32` (ADR-057 §Prereq-2). The browser injects a
    /// hardened `Clock`; the native runtime injects [`SystemClock`], giving
    /// identical behavior.
    epochs: HashMap<u64, u64>,
    /// Maximum number of epochs this store will track.
    max_capacity: usize,
    /// Optional callback invoked when epochs are expired or evicted.
    on_epoch_expired: Option<OnEpochExpired>,
    /// Injected time source. Native runtime uses [`SystemClock`]; the browser
    /// client injects its single hardened clock so the grace window cannot be
    /// driven by a second, unhardened time source (ADR-057 §Prereq-1/§Prereq-2).
    clock: Arc<dyn Clock>,
}

// Manual Debug impl because OnEpochExpired (Box<dyn FnMut>) doesn't impl Debug.
impl std::fmt::Debug for EpochGraceStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochGraceStore")
            .field("epochs", &self.epochs)
            .field("max_capacity", &self.max_capacity)
            .field(
                "on_epoch_expired",
                &self.on_epoch_expired.as_ref().map(|_| "<callback>"),
            )
            .field("clock", &"<clock>")
            .finish()
    }
}

impl EpochGraceStore {
    /// Creates a new, empty grace store with the default maximum capacity
    /// of [`MAX_GRACE_EPOCHS`], backed by the production [`SystemClock`].
    ///
    /// Use [`with_clock`](Self::with_clock) to inject a different time source
    /// (e.g., the browser client's hardened clock, or a `TestClock`).
    #[must_use]
    pub fn new() -> Self {
        Self::with_clock_and_capacity(Arc::new(SystemClock), MAX_GRACE_EPOCHS)
    }

    /// Creates a new, empty grace store with a custom maximum capacity, backed
    /// by the production [`SystemClock`].
    ///
    /// Use this in tests to verify capacity enforcement with smaller limits.
    #[must_use]
    pub fn with_max_capacity(max_capacity: usize) -> Self {
        Self::with_clock_and_capacity(Arc::new(SystemClock), max_capacity)
    }

    /// Creates a new, empty grace store backed by the given [`Clock`], with the
    /// default maximum capacity of [`MAX_GRACE_EPOCHS`].
    ///
    /// The native runtime injects [`SystemClock`] (identical to [`new`](Self::new));
    /// an in-browser client injects its single hardened clock so that the grace
    /// window is governed by the same time source as the rest of the protocol
    /// (ADR-057 §Prereq-1/§Prereq-2), never a hidden second clock.
    #[must_use]
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self::with_clock_and_capacity(clock, MAX_GRACE_EPOCHS)
    }

    /// Creates a new, empty grace store with both an injected [`Clock`] and a
    /// custom maximum capacity.
    #[must_use]
    pub fn with_clock_and_capacity(clock: Arc<dyn Clock>, max_capacity: usize) -> Self {
        Self {
            epochs: HashMap::new(),
            max_capacity,
            on_epoch_expired: None,
            clock,
        }
    }

    /// Sets a callback that fires whenever epochs are expired or evicted.
    ///
    /// The callback receives a slice of epoch numbers that were just removed
    /// from the store. It is invoked by both [`add_epoch`](Self::add_epoch)
    /// (which may expire and/or evict epochs) and
    /// [`expire_old_epochs`](Self::expire_old_epochs).
    ///
    /// Only one callback can be active at a time. Setting a new callback
    /// replaces any previously set callback.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// store.set_on_epoch_expired(Box::new(|expired_epochs| {
    ///     for &epoch in expired_epochs {
    ///         tracing::info!(epoch, "grace window closed for epoch");
    ///     }
    /// }));
    /// ```
    pub fn set_on_epoch_expired(&mut self, callback: OnEpochExpired) {
        self.on_epoch_expired = Some(callback);
    }

    /// Marks an epoch as entering the grace period.
    ///
    /// The epoch will be considered "in grace" until 30 seconds from now.
    /// If the epoch is already tracked, its deadline is **not** extended.
    ///
    /// Before inserting, this method purges expired epochs. If the store is
    /// still at capacity after purging, the oldest epoch (by deadline) is
    /// evicted to make room. Returns the list of epoch numbers that were
    /// expired or evicted, so callers can log or react to evictions.
    pub fn add_epoch(&mut self, epoch: u64) -> Vec<u64> {
        // Purge time-expired epochs first.
        // Note: expire_old_epochs() fires the callback for time-expired epochs.
        let mut expired = self.expire_old_epochs();

        // If already tracked, no insertion needed — return what we expired.
        if self.epochs.contains_key(&epoch) {
            return expired;
        }

        // If still at capacity after time-based purge, evict oldest by
        // deadline. Deadlines are wall-clock millis, so epochs added in the
        // same millisecond tie; break ties by lowest epoch number (= entered
        // grace earliest) for deterministic, insertion-order eviction. (The
        // previous monotonic-`Instant` deadlines were strictly increasing per
        // add, so this preserves that "oldest = added-earliest" behavior
        // without depending on sub-millisecond clock resolution.)
        if self.epochs.len() >= self.max_capacity
            && let Some((&oldest_epoch, _)) = self
                .epochs
                .iter()
                .min_by_key(|&(&epoch, &deadline)| (deadline, epoch))
        {
            self.epochs.remove(&oldest_epoch);
            expired.push(oldest_epoch);

            // Fire callback for the capacity-evicted epoch.
            if let Some(ref mut callback) = self.on_epoch_expired {
                callback(&[oldest_epoch]);
            }
        }

        // Deadlines are absolute wall-clock millis (injected `Clock`), not a
        // monotonic `Instant`: wasm32 has no monotonic source. A backward host
        // clock jump after insertion can extend an epoch's grace window slightly;
        // forward-secrecy exposure stays bounded by `MAX_GRACE_EPOCHS` capacity
        // eviction regardless. This inherits the protocol-wide host-clock trust
        // assumption (see `scp_primitives::time`); on the browser target the
        // grace window is governed by the same single hardened `Clock` as the
        // rest of the protocol (ADR-057 §Prereq-1/2), not a hidden second source.
        let deadline = self.clock.now_millis().saturating_add(GRACE_WINDOW_MILLIS);
        self.epochs.entry(epoch).or_insert(deadline);

        expired
    }

    /// Returns `true` if the given epoch is still within its grace window.
    ///
    /// Returns `false` if the epoch was never tracked or its window has expired.
    #[must_use]
    pub fn is_in_grace(&self, epoch: u64) -> bool {
        let now = self.clock.now_millis();
        self.epochs
            .get(&epoch)
            .is_some_and(|deadline| now < *deadline)
    }

    /// Removes all epochs whose grace windows have expired.
    ///
    /// Returns the epoch numbers that were removed. Callers can use this list
    /// to log forward-secrecy window closures or emit events.
    ///
    /// Call this periodically (e.g., before decrypt attempts) to keep the
    /// store clean. Expired epochs are permanently removed — the SCP layer
    /// will no longer attempt decryption for these epochs.
    ///
    /// **Note:** Removing an epoch from this store does not delete `OpenMLS` key
    /// material. `OpenMLS` manages its own key lifecycle internally via
    /// `delete_previous_epoch_keypairs()` (called automatically during commit
    /// merges) and its bounded `MessageSecretsStore`.
    pub fn expire_old_epochs(&mut self) -> Vec<u64> {
        let now = self.clock.now_millis();
        let mut expired = Vec::new();
        self.epochs.retain(|&epoch, deadline| {
            if now < *deadline {
                true
            } else {
                expired.push(epoch);
                false
            }
        });

        // Fire callback for all time-expired epochs.
        if !expired.is_empty()
            && let Some(ref mut callback) = self.on_epoch_expired
        {
            callback(&expired);
        }

        expired
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

    /// Returns the maximum capacity of this store.
    #[must_use]
    pub const fn max_capacity(&self) -> usize {
        self.max_capacity
    }

    // -------------------------------------------------------------------
    // Persistence support (§23.11)
    // -------------------------------------------------------------------

    /// Converts the current in-memory state to a list of persistable
    /// [`GraceEntry`] values.
    ///
    /// Deadlines are already stored as absolute wall-clock millis (from the
    /// injected [`Clock`]), so each entry's `expires_at_unix_secs` is simply
    /// the deadline truncated to seconds — no monotonic-to-wall conversion.
    /// Epochs whose grace window has already expired are excluded.
    ///
    /// Called by the persistence layer after each epoch advance: the returned
    /// entries are persisted alongside the context snapshot in a single write
    /// (§23.11 step 2). On recovery, entries are loaded and fed to
    /// [`restore_from_entries`](Self::restore_from_entries).
    #[must_use]
    pub fn to_grace_entries(&self) -> Vec<GraceEntry> {
        let now_millis = self.clock.now_millis();
        self.epochs
            .iter()
            .filter_map(|(&epoch, &deadline_millis)| {
                if now_millis >= deadline_millis {
                    // Already expired — do not persist.
                    return None;
                }
                Some(GraceEntry {
                    epoch,
                    expires_at_unix_secs: deadline_millis / 1000,
                })
            })
            .collect()
    }

    /// Restores the grace store from persisted [`GraceEntry`] values
    /// loaded on startup (§23.11 recovery-on-startup).
    ///
    /// For each entry:
    /// - If the grace period has expired (current time >= `expires_at_unix_secs`),
    ///   the entry is added to the returned `expired` vec. The caller MUST
    ///   destroy any cached key material for these epochs and delete the
    ///   persisted entry.
    /// - If the grace period has NOT expired, the entry is inserted into
    ///   the in-memory store with a deadline computed from the remaining
    ///   wall-clock time. This ensures the total grace window duration is
    ///   preserved regardless of crash timing.
    ///
    /// After restoring, if the store exceeds [`max_capacity`](Self::max_capacity),
    /// the oldest entries by deadline are evicted until within bounds. This
    /// prevents unbounded growth from stale persisted data.
    ///
    pub fn restore_from_entries(&mut self, entries: &[GraceEntry]) -> Vec<u64> {
        let now_unix = self.clock.now_secs();
        let mut expired = Vec::new();

        for entry in entries {
            if now_unix >= entry.expires_at_unix_secs {
                // Grace period expired during downtime — forward secrecy
                // requires immediate destruction.
                expired.push(entry.epoch);
            } else {
                // Deadlines are absolute wall-clock millis; the persisted form
                // is wall-clock secs, so re-hydrate by promoting to millis.
                // Preserves the absolute expiry across the crash boundary.
                let deadline_millis = entry.expires_at_unix_secs.saturating_mul(1000);
                // Only insert if not already present (idempotent restore).
                self.epochs.entry(entry.epoch).or_insert(deadline_millis);
            }
        }

        // Enforce max_capacity: evict oldest by deadline until within bounds.
        // Break deadline ties by lowest epoch number (see `add_epoch`).
        while self.epochs.len() > self.max_capacity {
            if let Some((&oldest_epoch, _)) = self
                .epochs
                .iter()
                .min_by_key(|&(&epoch, &deadline)| (deadline, epoch))
            {
                self.epochs.remove(&oldest_epoch);
                expired.push(oldest_epoch);

                if let Some(ref mut callback) = self.on_epoch_expired {
                    callback(&[oldest_epoch]);
                }
            } else {
                break;
            }
        }

        expired
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

    /// Current wall-clock time in milliseconds, matching the deadline units
    /// used internally by [`EpochGraceStore`] (all tests use the default
    /// [`SystemClock`], so test fixtures that poke `store.epochs` directly must
    /// build deadlines from the same clock).
    fn test_now_millis() -> u64 {
        SystemClock.now_millis()
    }

    /// Current wall-clock time in seconds, for building [`GraceEntry`] fixtures.
    fn test_now_secs() -> u64 {
        SystemClock.now_secs()
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn new_store_is_empty() {
        let store = EpochGraceStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn new_store_has_default_max_capacity() {
        let store = EpochGraceStore::new();
        assert_eq!(store.max_capacity(), MAX_GRACE_EPOCHS);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn with_max_capacity_sets_custom_limit() {
        let store = EpochGraceStore::with_max_capacity(10);
        assert_eq!(store.max_capacity(), 10);
        assert!(store.is_empty());
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
    fn add_epoch_returns_empty_vec_when_nothing_expired() {
        let mut store = EpochGraceStore::new();
        let expired = store.add_epoch(1);
        assert!(expired.is_empty());
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
    fn expire_old_epochs_removes_expired_and_returns_them() {
        let mut store = EpochGraceStore::new();
        // Manually insert an epoch with an already-expired deadline.
        store.epochs.insert(0, test_now_millis() - 1000);
        store.add_epoch(1); // This one should still be valid.

        // Store has the manually-inserted epoch 0 + epoch 1 from add_epoch.
        // add_epoch(1) calls expire_old_epochs first, which would have
        // expired epoch 0. So we re-insert it to test expire directly.
        store.epochs.insert(0, test_now_millis() - 1000);
        assert_eq!(store.len(), 2);

        let expired = store.expire_old_epochs();
        assert_eq!(store.len(), 1);
        assert!(!store.is_in_grace(0));
        assert!(store.is_in_grace(1));
        assert_eq!(expired, vec![0]);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn expire_old_epochs_returns_empty_vec_when_nothing_expired() {
        let mut store = EpochGraceStore::new();
        store.add_epoch(1);
        let expired = store.expire_old_epochs();
        assert!(expired.is_empty());
        assert_eq!(store.len(), 1);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn is_in_grace_returns_false_for_expired_epoch() {
        let mut store = EpochGraceStore::new();
        // Insert with past deadline.
        store.epochs.insert(5, test_now_millis() - 1000);
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

    #[test]
    #[allow(clippy::unwrap_used)]
    fn add_epoch_calls_expire_before_insert() {
        let mut store = EpochGraceStore::new();
        // Manually insert an expired epoch.
        store.epochs.insert(0, test_now_millis() - 1000);
        assert_eq!(store.len(), 1);

        // Adding a new epoch should expire epoch 0 first.
        let expired = store.add_epoch(1);
        assert!(expired.contains(&0), "expired epoch 0 should be reported");
        assert_eq!(store.len(), 1, "only epoch 1 should remain");
        assert!(store.is_in_grace(1));
        assert!(!store.is_in_grace(0));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn store_never_exceeds_max_capacity() {
        let max = 5;
        let mut store = EpochGraceStore::with_max_capacity(max);

        // Fill the store to capacity.
        for i in 0..max as u64 {
            store.add_epoch(i);
        }
        assert_eq!(store.len(), max);

        // Adding one more should evict the oldest.
        let expired = store.add_epoch(max as u64);
        assert_eq!(store.len(), max, "store must not exceed max_capacity");
        // The evicted epoch should be in the returned list.
        assert_eq!(expired.len(), 1, "exactly one epoch should be evicted");
        assert!(
            !store.is_in_grace(expired[0]),
            "evicted epoch should no longer be in grace"
        );
        assert!(
            store.is_in_grace(max as u64),
            "newly added epoch should be in grace"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn capacity_evicts_oldest_by_deadline() {
        let mut store = EpochGraceStore::with_max_capacity(3);

        // Insert epochs with progressively later deadlines.
        // Epoch 10 gets the earliest deadline, epoch 12 the latest.
        store.epochs.insert(10, test_now_millis() + 5 * 1000);
        store.epochs.insert(11, test_now_millis() + 15 * 1000);
        store.epochs.insert(12, test_now_millis() + 25 * 1000);
        assert_eq!(store.len(), 3);

        // Adding epoch 13 should evict epoch 10 (oldest deadline).
        let expired = store.add_epoch(13);
        assert_eq!(store.len(), 3);
        assert!(
            expired.contains(&10),
            "epoch 10 (oldest deadline) should be evicted"
        );
        assert!(!store.is_in_grace(10));
        assert!(store.is_in_grace(11));
        assert!(store.is_in_grace(12));
        assert!(store.is_in_grace(13));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn exceed_max_capacity_by_many_never_exceeds_limit() {
        let max = 3;
        let mut store = EpochGraceStore::with_max_capacity(max);

        // Add 200 epochs. The store should never exceed max_capacity.
        for i in 0..200_u64 {
            store.add_epoch(i);
            assert!(
                store.len() <= max,
                "store exceeded max_capacity at epoch {i}: len={}",
                store.len()
            );
        }

        // The last `max` epochs should be the ones that remain.
        assert_eq!(store.len(), max);
        assert!(store.is_in_grace(199));
        assert!(store.is_in_grace(198));
        assert!(store.is_in_grace(197));
        assert!(!store.is_in_grace(196));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn capacity_one_store_always_has_latest_epoch() {
        let mut store = EpochGraceStore::with_max_capacity(1);

        for i in 0..10_u64 {
            store.add_epoch(i);
            assert_eq!(store.len(), 1);
            assert!(store.is_in_grace(i));
            if i > 0 {
                assert!(!store.is_in_grace(i - 1));
            }
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    #[allow(
        clippy::disallowed_types,
        reason = "Test-only mock state; actor refactor does not migrate test scaffolding. See ADR-049 §'Disallowed types / methods via clippy.toml' and plan §Commit ladder in `~/.claude/plans/generic-moseying-lightning.md`."
    )]
    fn callback_fires_on_time_expiry() {
        use std::sync::{Arc, Mutex};

        let notified = Arc::new(Mutex::new(Vec::<u64>::new()));
        let notified_clone = Arc::clone(&notified);

        let mut store = EpochGraceStore::new();
        store.set_on_epoch_expired(Box::new(move |epochs| {
            notified_clone.lock().unwrap().extend_from_slice(epochs);
        }));

        // Insert an already-expired epoch.
        store.epochs.insert(5, test_now_millis() - 1000);

        // expire_old_epochs should fire the callback with epoch 5.
        let expired = store.expire_old_epochs();
        assert_eq!(expired, vec![5]);
        assert_eq!(*notified.lock().unwrap(), vec![5]);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    #[allow(
        clippy::disallowed_types,
        reason = "Test-only mock state; actor refactor does not migrate test scaffolding. See ADR-049 §'Disallowed types / methods via clippy.toml' and plan §Commit ladder in `~/.claude/plans/generic-moseying-lightning.md`."
    )]
    fn callback_fires_on_capacity_eviction() {
        use std::sync::{Arc, Mutex};

        let notified = Arc::new(Mutex::new(Vec::<u64>::new()));
        let notified_clone = Arc::clone(&notified);

        let mut store = EpochGraceStore::with_max_capacity(2);
        store.set_on_epoch_expired(Box::new(move |epochs| {
            notified_clone.lock().unwrap().extend_from_slice(epochs);
        }));

        // Fill to capacity.
        store.add_epoch(1);
        store.add_epoch(2);
        assert!(notified.lock().unwrap().is_empty(), "no expiry yet");

        // Adding a third should evict the oldest (epoch 1).
        store.add_epoch(3);
        assert!(
            notified.lock().unwrap().contains(&1),
            "epoch 1 should have been evicted and notified"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    #[allow(
        clippy::disallowed_types,
        reason = "Test-only mock state; actor refactor does not migrate test scaffolding. See ADR-049 §'Disallowed types / methods via clippy.toml' and plan §Commit ladder in `~/.claude/plans/generic-moseying-lightning.md`."
    )]
    fn callback_not_fired_when_nothing_expires() {
        use std::sync::{Arc, Mutex};

        let notified = Arc::new(Mutex::new(Vec::<u64>::new()));
        let notified_clone = Arc::clone(&notified);

        let mut store = EpochGraceStore::new();
        store.set_on_epoch_expired(Box::new(move |epochs| {
            notified_clone.lock().unwrap().extend_from_slice(epochs);
        }));

        store.add_epoch(1);
        store.add_epoch(2);
        let expired = store.expire_old_epochs();

        assert!(expired.is_empty());
        assert!(notified.lock().unwrap().is_empty());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn add_epoch_prefers_time_expiry_over_capacity_eviction() {
        let mut store = EpochGraceStore::with_max_capacity(3);

        // Two expired epochs and one valid.
        store.epochs.insert(0, test_now_millis() - 1000);
        store.epochs.insert(1, test_now_millis() - 1000);
        store.epochs.insert(2, test_now_millis() + 25 * 1000);
        assert_eq!(store.len(), 3);

        // Adding epoch 3: time-expired purge removes 0 and 1, making room
        // without needing to evict the still-valid epoch 2.
        let expired = store.add_epoch(3);
        assert_eq!(store.len(), 2, "should have epochs 2 and 3");
        assert!(expired.contains(&0));
        assert!(expired.contains(&1));
        assert!(!expired.contains(&2), "epoch 2 should not be evicted");
        assert!(store.is_in_grace(2));
        assert!(store.is_in_grace(3));
    }

    // -------------------------------------------------------------------
    // GraceEntry persistence tests (§23.11)
    // -------------------------------------------------------------------

    #[test]
    #[allow(clippy::unwrap_used)]
    fn grace_entry_serialization_roundtrip() {
        let entry = GraceEntry {
            epoch: 42,
            expires_at_unix_secs: 1_700_000_000,
        };
        let bytes = serde_json::to_vec(&entry).unwrap();
        let decoded: GraceEntry = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn to_grace_entries_excludes_expired_epochs() {
        let mut store = EpochGraceStore::new();
        // Insert a live epoch.
        store.add_epoch(5);
        // Insert an expired epoch.
        store.epochs.insert(3, test_now_millis() - 1000);

        let entries = store.to_grace_entries();
        let epochs: Vec<u64> = entries.iter().map(|e| e.epoch).collect();
        assert!(epochs.contains(&5), "live epoch should be included");
        assert!(
            !epochs.contains(&3),
            "expired epoch should be excluded from persistence"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn to_grace_entries_captures_expiration_timestamp() {
        let mut store = EpochGraceStore::new();
        store.add_epoch(10);

        let entries = store.to_grace_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].epoch, 10);
        // The expiration should be roughly now + 30s.
        let now = test_now_secs();
        let diff = entries[0].expires_at_unix_secs.saturating_sub(now);
        assert!(
            diff <= 31,
            "expiration should be ~30s from now, got {diff}s"
        );
        assert!(
            diff >= 28,
            "expiration should be ~30s from now, got {diff}s"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn restore_from_entries_retains_live_entries() {
        let mut store = EpochGraceStore::new();
        let now = test_now_secs();

        let entries = vec![GraceEntry {
            epoch: 7,
            expires_at_unix_secs: now + 20,
        }];

        let expired = store.restore_from_entries(&entries);
        assert!(expired.is_empty(), "entry should still be live");
        assert!(store.is_in_grace(7));
        assert_eq!(store.len(), 1);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn restore_from_entries_expires_old_entries() {
        let mut store = EpochGraceStore::new();
        let now = test_now_secs();

        let entries = vec![GraceEntry {
            epoch: 3,
            // Expired 10 seconds ago.
            expires_at_unix_secs: now.saturating_sub(10),
        }];

        let expired = store.restore_from_entries(&entries);
        assert_eq!(expired, vec![3]);
        assert!(!store.is_in_grace(3));
        assert!(store.is_empty());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn restore_from_entries_mixed_live_and_expired() {
        let mut store = EpochGraceStore::new();
        let now = test_now_secs();

        let entries = vec![
            GraceEntry {
                epoch: 1,
                expires_at_unix_secs: now.saturating_sub(5),
            },
            GraceEntry {
                epoch: 2,
                expires_at_unix_secs: now + 15,
            },
            GraceEntry {
                epoch: 3,
                expires_at_unix_secs: now.saturating_sub(1),
            },
            GraceEntry {
                epoch: 4,
                expires_at_unix_secs: now + 25,
            },
        ];

        let expired = store.restore_from_entries(&entries);
        assert_eq!(expired.len(), 2);
        assert!(expired.contains(&1));
        assert!(expired.contains(&3));
        assert_eq!(store.len(), 2);
        assert!(store.is_in_grace(2));
        assert!(store.is_in_grace(4));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn restore_is_idempotent() {
        let mut store = EpochGraceStore::new();
        let now = test_now_secs();

        let entries = vec![GraceEntry {
            epoch: 5,
            expires_at_unix_secs: now + 20,
        }];

        let expired1 = store.restore_from_entries(&entries);
        assert!(expired1.is_empty());
        assert_eq!(store.len(), 1);

        // Restoring again should not duplicate.
        let expired2 = store.restore_from_entries(&entries);
        assert!(expired2.is_empty());
        assert_eq!(store.len(), 1);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn to_grace_entries_empty_store_returns_empty() {
        let store = EpochGraceStore::new();
        let entries = store.to_grace_entries();
        assert!(entries.is_empty());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn roundtrip_persist_and_restore() {
        // Simulate: add epochs -> persist -> crash -> restore.
        let mut store = EpochGraceStore::new();
        store.add_epoch(10);
        store.add_epoch(11);
        store.add_epoch(12);

        let entries = store.to_grace_entries();
        assert_eq!(entries.len(), 3);

        // Simulate crash: new empty store.
        let mut recovered = EpochGraceStore::new();
        let expired = recovered.restore_from_entries(&entries);
        assert!(expired.is_empty(), "all entries should still be live");
        assert_eq!(recovered.len(), 3);
        assert!(recovered.is_in_grace(10));
        assert!(recovered.is_in_grace(11));
        assert!(recovered.is_in_grace(12));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn restore_from_entries_caps_at_max_capacity() {
        let mut store = EpochGraceStore::with_max_capacity(3);
        let now = test_now_secs();

        // Feed 5 live entries into a store with max_capacity=3.
        let entries: Vec<GraceEntry> = (0..5)
            .map(|i| GraceEntry {
                epoch: i,
                // Each gets progressively later expiration.
                expires_at_unix_secs: now + 10 + i,
            })
            .collect();

        let expired = store.restore_from_entries(&entries);

        // 2 oldest should have been evicted to bring count down to 3.
        assert_eq!(
            store.len(),
            3,
            "store must not exceed max_capacity after restore"
        );
        assert_eq!(expired.len(), 2, "2 epochs should be evicted");
        // Oldest by deadline (epoch 0 and 1) should be evicted.
        assert!(expired.contains(&0));
        assert!(expired.contains(&1));
        assert!(store.is_in_grace(2));
        assert!(store.is_in_grace(3));
        assert!(store.is_in_grace(4));
    }
}
