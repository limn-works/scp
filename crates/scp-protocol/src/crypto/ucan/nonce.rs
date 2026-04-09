//! Per-context nonce tracking for UCAN replay prevention.
//!
//! Implements a [`NonceTracker`] that enforces nonce uniqueness within a single
//! SCP context (spec section 9.5). Nonces use the format
//! `{unix_millis_timestamp}-{16_random_bytes_hex}` — the timestamp prefix
//! enables efficient pruning, while the random suffix ensures uniqueness.
//!
//! # Freshness
//!
//! The nonce timestamp must be within +/- 5 minutes of the current time
//! (matching the clock skew tolerance from section 9.14). Nonces outside this
//! window are rejected immediately without recording.
//!
//! # Pruning
//!
//! Expired entries are pruned automatically every 1000 checks or 10 minutes,
//! whichever comes first. An entry is eligible for pruning when
//! `now > max(token_expiry + 300, first_seen + 86400)`.
//!
//! # Persistence
//!
//! The tracker state can be serialized to and deserialized from bytes for
//! crash recovery via the `Storage` trait (in `scp-platform`).
//!
//! See ADR-016 acceptance criterion 6 in `.docs/adrs/phase-3.md`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::UcanError;
use scp_primitives::Clock;

/// Nonce freshness tolerance: 5 minutes in milliseconds (spec section 9.14).
const NONCE_FRESHNESS_TOLERANCE_MS: u128 = 5 * 60 * 1000;

/// Grace period added to `token_expiry` before pruning: 5 minutes in seconds.
const PRUNE_EXPIRY_GRACE_SECS: u64 = 300;

/// Minimum retention period for any nonce entry: 24 hours in seconds.
const PRUNE_MIN_RETENTION_SECS: u64 = 86_400;

/// Number of `check_and_record` calls between automatic pruning attempts.
const PRUNE_CHECK_INTERVAL: u64 = 1000;

/// Time between automatic pruning attempts: 10 minutes in seconds.
const PRUNE_TIME_INTERVAL_SECS: u64 = 600;

/// Default maximum number of nonces a tracker will hold before rejecting
/// new entries. At ~100 bytes per entry, 100 000 entries consume roughly
/// 10 MB — well within tolerance for a single context.
///
/// `HashMap::retain` pruning is O(n) but at 100 000 entries completes in
/// single-digit microseconds on modern hardware, so it is acceptable here.
const DEFAULT_MAX_CAPACITY: usize = 100_000;

// ---------------------------------------------------------------------------
// Nonce generation
// ---------------------------------------------------------------------------

/// Generates a nonce in the format `{unix_millis_timestamp}-{16_random_bytes_hex}`.
///
/// The timestamp prefix enables efficient pruning of expired nonces. The 16
/// random bytes (32 hex chars) ensure uniqueness even under high concurrency.
/// Uses `OsRng` for cryptographic randomness.
///
/// See ADR-009 acceptance criterion 7 and ADR-016 acceptance criterion 6.
#[must_use]
pub fn generate_nonce(clock: &dyn Clock) -> String {
    let now_millis = clock.now_millis();

    let mut random_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut random_bytes);

    let hex_suffix = hex::encode(random_bytes);
    format!("{now_millis}-{hex_suffix}")
}

// ---------------------------------------------------------------------------
// NonceTracker
// ---------------------------------------------------------------------------

/// Per-context nonce tracker for UCAN replay prevention.
///
/// Tracks seen nonces within a single SCP context. Each nonce is recorded with
/// its `first_seen` timestamp and the associated token's expiry timestamp.
/// Duplicate nonces are rejected as replay attempts.
///
/// Uses the [`Clock`] trait for time, enabling deterministic testing.
///
/// # Capacity
///
/// The tracker enforces a configurable maximum capacity (default:
/// `DEFAULT_MAX_CAPACITY` = 100 000). When at capacity, a prune pass runs
/// before inserting; if no entries can be pruned, the tracker returns
/// [`UcanError::NonceTrackerFull`].
///
/// # Pruning strategy
///
/// An entry is eligible for removal when:
/// ```text
/// now > max(token_expiry + 300, first_seen + 86400)
/// ```
///
/// Pruning runs automatically every 1000 calls to `check_and_record` or
/// every 10 minutes, whichever comes first. It also runs when the tracker
/// reaches capacity.
///
/// `HashMap::retain` is O(n), but at the default capacity of 100 000 entries
/// this completes in single-digit microseconds on modern hardware — well
/// within acceptable latency bounds.
///
/// See ADR-016 acceptance criterion 6.
#[derive(Debug)]
pub struct NonceTracker<C: Clock> {
    /// Map of nonce string to (`first_seen_secs`, `token_expiry_secs`).
    seen: HashMap<String, (u64, u64)>,
    /// The context this tracker is scoped to.
    context_id: String,
    /// Time source for testable time.
    clock: C,
    /// Number of `check_and_record` calls since the last prune.
    checks_since_prune: u64,
    /// Timestamp (seconds) of the last prune operation.
    last_prune_time: u64,
    /// Maximum number of nonces the tracker will hold.
    max_capacity: usize,
}

impl<C: Clock> NonceTracker<C> {
    /// Creates a new nonce tracker for the given context with the default
    /// capacity limit (`DEFAULT_MAX_CAPACITY`).
    ///
    /// The tracker starts empty with zero checks and the prune timer set to
    /// the current clock time.
    #[must_use]
    pub fn new(context_id: String, clock: C) -> Self {
        Self::with_max_capacity(context_id, clock, DEFAULT_MAX_CAPACITY)
    }

    /// Creates a new nonce tracker with an explicit maximum capacity.
    ///
    /// Use this when the default 100 000 limit is not appropriate for the
    /// deployment context.
    #[must_use]
    pub fn with_max_capacity(context_id: String, clock: C, max_capacity: usize) -> Self {
        let now = clock.now_secs();
        Self {
            seen: HashMap::new(),
            context_id,
            clock,
            checks_since_prune: 0,
            last_prune_time: now,
            max_capacity,
        }
    }

    /// Returns the maximum capacity of this tracker.
    #[must_use]
    pub const fn max_capacity(&self) -> usize {
        self.max_capacity
    }

    /// Returns the context ID this tracker is scoped to.
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Returns the number of nonces currently tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Returns `true` if no nonces are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Validates a nonce and records it if new.
    ///
    /// Performs the following checks in order:
    /// 1. **Format** — The nonce must match `{unix_millis}-{32_hex_chars}`.
    /// 2. **Freshness** — The timestamp must be within +/- 5 minutes of now.
    /// 3. **Uniqueness** — The nonce must not have been seen before.
    ///
    /// If all checks pass, the nonce is recorded with `(now_secs, token_expiry)`
    /// and automatic pruning is triggered if the check/time threshold is reached.
    ///
    /// # Errors
    ///
    /// Returns [`UcanError::NonceFormatInvalid`] if the format is wrong.
    /// Returns [`UcanError::NonceTooOld`] if the timestamp is too far in the past.
    /// Returns [`UcanError::NonceFuture`] if the timestamp is too far in the future.
    /// Returns [`UcanError::NonceReused`] if the nonce was already recorded.
    pub fn check_and_record(&mut self, nonce: &str, token_expiry: u64) -> Result<(), UcanError> {
        // 1. Validate nonce format: {unix_millis}-{32_hex_chars}
        let (ts_part, hex_part) = nonce.split_once('-').ok_or_else(|| {
            UcanError::NonceFormatInvalid(format!("missing '-' separator in nonce: {nonce}"))
        })?;

        let nonce_millis: u128 = ts_part.parse().map_err(|_| {
            UcanError::NonceFormatInvalid(format!("non-numeric timestamp in nonce: {ts_part}"))
        })?;

        if hex_part.len() != 32 || !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(UcanError::NonceFormatInvalid(format!(
                "invalid hex suffix in nonce (expected 32 hex chars): {hex_part}"
            )));
        }

        // 2. Freshness check: timestamp within now +/- 5 minutes.
        let now_secs = self.clock.now_secs();
        let now_millis = u128::from(now_secs) * 1000;

        if nonce_millis + NONCE_FRESHNESS_TOLERANCE_MS < now_millis {
            return Err(UcanError::NonceTooOld(nonce.to_owned()));
        }

        if nonce_millis > now_millis + NONCE_FRESHNESS_TOLERANCE_MS {
            return Err(UcanError::NonceFuture(nonce.to_owned()));
        }

        // 3. Replay check.
        if self.seen.contains_key(nonce) {
            return Err(UcanError::NonceReused(nonce.to_owned()));
        }

        // 4. Capacity check: if at capacity, attempt a prune to free space.
        if self.seen.len() >= self.max_capacity {
            self.prune();
            if self.seen.len() >= self.max_capacity {
                return Err(UcanError::NonceTrackerFull(self.max_capacity));
            }
        }

        // Record the nonce.
        self.seen.insert(nonce.to_owned(), (now_secs, token_expiry));

        // Auto-prune check.
        self.checks_since_prune += 1;
        if self.checks_since_prune >= PRUNE_CHECK_INTERVAL
            || now_secs >= self.last_prune_time + PRUNE_TIME_INTERVAL_SECS
        {
            self.prune();
        }

        Ok(())
    }

    /// Removes expired nonce entries.
    ///
    /// An entry is eligible for pruning when:
    /// ```text
    /// now > max(token_expiry + 300, first_seen + 86400)
    /// ```
    ///
    /// This ensures nonces are retained for at least 5 minutes past token
    /// expiry or 24 hours past first observation, whichever is longer.
    pub fn prune(&mut self) {
        let now = self.clock.now_secs();
        self.seen.retain(|_, (first_seen, token_expiry)| {
            let expiry_deadline = token_expiry.saturating_add(PRUNE_EXPIRY_GRACE_SECS);
            let retention_deadline = first_seen.saturating_add(PRUNE_MIN_RETENTION_SECS);
            let deadline = expiry_deadline.max(retention_deadline);
            now <= deadline
        });
        self.checks_since_prune = 0;
        self.last_prune_time = now;
    }

    /// Serializes the tracker state to bytes for persistence.
    ///
    /// The serialized format includes the context ID and all seen nonces with
    /// their timestamps. Use [`from_bytes`](NonceTracker::from_bytes) to
    /// restore from a previously serialized state.
    ///
    /// # Errors
    ///
    /// Returns [`UcanError::MalformedToken`] if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, UcanError> {
        let state = SerializableState {
            context_id: &self.context_id,
            seen: &self.seen,
        };
        serde_json::to_vec(&state)
            .map_err(|e| UcanError::MalformedToken(format!("nonce tracker serialization: {e}")))
    }

    /// Restores tracker state from previously serialized bytes with the
    /// default capacity limit.
    ///
    /// The `clock` argument provides the time source for the restored tracker.
    /// After restoration, a prune pass runs to discard any entries that expired
    /// while the tracker was not running.
    ///
    /// # Errors
    ///
    /// Returns [`UcanError::MalformedToken`] if deserialization fails.
    pub fn from_bytes(data: &[u8], clock: C) -> Result<Self, UcanError> {
        Self::from_bytes_with_capacity(data, clock, DEFAULT_MAX_CAPACITY)
    }

    /// Restores tracker state from previously serialized bytes with an
    /// explicit capacity limit.
    ///
    /// # Errors
    ///
    /// Returns [`UcanError::MalformedToken`] if deserialization fails.
    pub fn from_bytes_with_capacity(
        data: &[u8],
        clock: C,
        max_capacity: usize,
    ) -> Result<Self, UcanError> {
        let state: OwnedSerializableState = serde_json::from_slice(data).map_err(|e| {
            UcanError::MalformedToken(format!("nonce tracker deserialization: {e}"))
        })?;

        let now = clock.now_secs();
        let mut tracker = Self {
            seen: state.seen,
            context_id: state.context_id,
            clock,
            checks_since_prune: 0,
            last_prune_time: now,
            max_capacity,
        };

        // Prune stale entries that expired during downtime.
        tracker.prune();
        Ok(tracker)
    }

    /// Returns the storage key for persisting this tracker's state.
    ///
    /// The key format is `nonce_tracker/{context_id}`, scoped to the context.
    #[must_use]
    pub fn storage_key(&self) -> String {
        format!("nonce_tracker/{}", self.context_id)
    }

    /// Exports the tracker's current entries as a `HashMap<nonce,
    /// (first_seen_secs, token_expiry_secs)>` for embedding in a
    /// `ContextSnapshot`.
    ///
    /// Unlike [`to_bytes`], this returns strongly-typed data that can
    /// be serialized directly as a struct field, avoiding a JSON blob
    /// round-trip inside the snapshot.
    #[must_use]
    pub fn snapshot_entries(&self) -> HashMap<String, (u64, u64)> {
        self.seen.clone()
    }

    /// Reconstructs a tracker from a persisted snapshot of entries.
    ///
    /// Used by the context-restore path so spending-UCAN nonce state
    /// survives process restarts (closes the replay window where a
    /// captured spending UCAN could be replayed after a restart, up to
    /// the `max_total` budget per spec §19.5).
    ///
    /// Any restored entry whose `token_expiry` is already in the past
    /// beyond the prune grace period is dropped on restore so the
    /// tracker starts in a normalized state. The restored tracker
    /// uses the supplied capacity limit (defaulting to
    /// `DEFAULT_MAX_CAPACITY` via [`from_snapshot`]).
    #[must_use]
    pub fn from_snapshot(
        context_id: String,
        clock: C,
        entries: HashMap<String, (u64, u64)>,
    ) -> Self {
        Self::from_snapshot_with_capacity(context_id, clock, entries, DEFAULT_MAX_CAPACITY)
    }

    /// Like [`from_snapshot`] but with an explicit capacity limit.
    ///
    /// If the snapshot contains more entries than `max_capacity`, the
    /// excess is truncated after the post-restore prune pass — this
    /// protects against a poisoned snapshot attempting to force an
    /// unbounded `HashMap` allocation.
    #[must_use]
    pub fn from_snapshot_with_capacity(
        context_id: String,
        clock: C,
        entries: HashMap<String, (u64, u64)>,
        max_capacity: usize,
    ) -> Self {
        let now = clock.now_secs();
        let mut tracker = Self {
            seen: entries,
            context_id,
            clock,
            checks_since_prune: 0,
            last_prune_time: now,
            max_capacity,
        };

        // Drop stale entries so the tracker starts normalized.
        tracker.prune();

        // Defense-in-depth: if a poisoned snapshot somehow exceeded
        // capacity after pruning, truncate deterministically to the
        // capacity bound.
        //
        // Keep policy: retain the entries with the latest
        // `token_expiry` (tie-break by latest `first_seen`, then by
        // nonce string lexicographic order for full determinism).
        // This is strictly better than `HashMap::drain().take()`'s
        // non-deterministic iteration:
        //   - "latest expiry first" keeps the entries most likely
        //     to still correspond to unexpired tokens, which is the
        //     only state that still carries anti-replay value.
        //   - Full determinism eliminates audit ambiguity: two
        //     instances restoring the same oversized snapshot
        //     converge to the same surviving set.
        //
        // In normal operation this path is unreachable: a tracker
        // produced by this codebase never exceeds `max_capacity`
        // (`check_and_record` rejects inserts at capacity), so the
        // sort cost is only ever paid on a snapshot that was tampered
        // or corrupted.
        if tracker.seen.len() > max_capacity {
            let mut all: Vec<(String, (u64, u64))> = tracker.seen.drain().collect();
            all.sort_by(|a, b| {
                // Primary: descending token_expiry.
                b.1.1
                    .cmp(&a.1.1)
                    // Secondary: descending first_seen.
                    .then_with(|| b.1.0.cmp(&a.1.0))
                    // Tertiary: ascending nonce string for total order.
                    .then_with(|| a.0.cmp(&b.0))
            });
            all.truncate(max_capacity);
            tracker.seen = all.into_iter().collect();
        }

        tracker
    }
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

/// Borrowed serialization state (avoids cloning on write).
#[derive(Serialize)]
struct SerializableState<'a> {
    context_id: &'a str,
    seen: &'a HashMap<String, (u64, u64)>,
}

/// Owned deserialization state (needed for restoration).
#[derive(Deserialize)]
struct OwnedSerializableState {
    context_id: String,
    seen: HashMap<String, (u64, u64)>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use scp_primitives::TestClock;

    /// Base timestamp for tests: 2024-01-01 00:00:00 UTC in seconds.
    const BASE_SECS: u64 = 1_704_067_200;

    /// Creates a valid nonce with the given millis timestamp and hex suffix.
    fn make_nonce(millis: u128, hex: &str) -> String {
        format!("{millis}-{hex}")
    }

    /// Creates a valid nonce at the tracker's current time.
    fn make_nonce_now(clock: &TestClock) -> String {
        let millis = u128::from(clock.now_secs()) * 1000;
        make_nonce(millis, "aabbccdd11223344aabbccdd11223344")
    }

    /// Creates a tracker with a `TestClock` set to `BASE_SECS`.
    fn setup() -> (NonceTracker<Arc<TestClock>>, Arc<TestClock>) {
        let clock = Arc::new(TestClock::new(BASE_SECS));
        let tracker = NonceTracker::new("ctx-test".to_owned(), Arc::clone(&clock));
        (tracker, clock)
    }

    // -------------------------------------------------------------------
    // Format validation
    // -------------------------------------------------------------------

    #[test]
    fn check_rejects_nonce_missing_separator() {
        let (mut tracker, _clock) = setup();
        let result = tracker.check_and_record("noseparator", 0);
        assert!(matches!(result, Err(UcanError::NonceFormatInvalid(_))));
    }

    #[test]
    fn check_rejects_nonce_non_numeric_timestamp() {
        let (mut tracker, _clock) = setup();
        let result = tracker.check_and_record("notanumber-aabbccdd11223344aabbccdd11223344", 0);
        assert!(matches!(result, Err(UcanError::NonceFormatInvalid(_))));
    }

    #[test]
    fn check_rejects_nonce_hex_too_short() {
        let (mut tracker, clock) = setup();
        let millis = u128::from(clock.now_secs()) * 1000;
        let nonce = format!("{millis}-aabbccdd112233");
        let result = tracker.check_and_record(&nonce, 0);
        assert!(matches!(result, Err(UcanError::NonceFormatInvalid(_))));
    }

    #[test]
    fn check_rejects_nonce_hex_too_long() {
        let (mut tracker, clock) = setup();
        let millis = u128::from(clock.now_secs()) * 1000;
        let nonce = format!("{millis}-aabbccdd11223344aabbccdd11223344ff");
        let result = tracker.check_and_record(&nonce, 0);
        assert!(matches!(result, Err(UcanError::NonceFormatInvalid(_))));
    }

    #[test]
    fn check_rejects_nonce_hex_with_non_hex_chars() {
        let (mut tracker, clock) = setup();
        let millis = u128::from(clock.now_secs()) * 1000;
        let nonce = format!("{millis}-gghhiidd11223344aabbccdd11223344");
        let result = tracker.check_and_record(&nonce, 0);
        assert!(matches!(result, Err(UcanError::NonceFormatInvalid(_))));
    }

    #[test]
    fn check_accepts_valid_nonce_format() {
        let (mut tracker, clock) = setup();
        let nonce = make_nonce_now(&clock);
        let expiry = clock.now_secs() + 3600;
        assert!(tracker.check_and_record(&nonce, expiry).is_ok());
    }

    // -------------------------------------------------------------------
    // Freshness validation
    // -------------------------------------------------------------------

    #[test]
    fn check_rejects_nonce_too_old() {
        let (mut tracker, clock) = setup();
        // 6 minutes in the past (> 5 minute tolerance).
        let old_millis = u128::from(clock.now_secs()) * 1000 - 6 * 60 * 1000;
        let nonce = make_nonce(old_millis, "aabbccdd11223344aabbccdd11223344");
        let result = tracker.check_and_record(&nonce, 0);
        assert!(matches!(result, Err(UcanError::NonceTooOld(_))));
    }

    #[test]
    fn check_rejects_nonce_from_future() {
        let (mut tracker, clock) = setup();
        // 6 minutes in the future (> 5 minute tolerance).
        let future_millis = u128::from(clock.now_secs()) * 1000 + 6 * 60 * 1000;
        let nonce = make_nonce(future_millis, "aabbccdd11223344aabbccdd11223344");
        let result = tracker.check_and_record(&nonce, 0);
        assert!(matches!(result, Err(UcanError::NonceFuture(_))));
    }

    #[test]
    fn check_accepts_nonce_within_tolerance() {
        let (mut tracker, clock) = setup();
        // 4 minutes in the past (within 5 minute tolerance).
        let millis = u128::from(clock.now_secs()) * 1000 - 4 * 60 * 1000;
        let nonce = make_nonce(millis, "aabbccdd11223344aabbccdd11223344");
        let expiry = clock.now_secs() + 3600;
        assert!(tracker.check_and_record(&nonce, expiry).is_ok());
    }

    #[test]
    fn check_accepts_nonce_at_exact_tolerance_boundary() {
        let (mut tracker, clock) = setup();
        // Exactly 5 minutes in the past.
        let millis = u128::from(clock.now_secs()) * 1000 - NONCE_FRESHNESS_TOLERANCE_MS;
        let nonce = make_nonce(millis, "aabbccdd11223344aabbccdd11223344");
        let expiry = clock.now_secs() + 3600;
        assert!(tracker.check_and_record(&nonce, expiry).is_ok());
    }

    #[test]
    fn check_accepts_nonce_at_future_tolerance_boundary() {
        let (mut tracker, clock) = setup();
        // Exactly 5 minutes in the future.
        let millis = u128::from(clock.now_secs()) * 1000 + NONCE_FRESHNESS_TOLERANCE_MS;
        let nonce = make_nonce(millis, "aabbccdd11223344aabbccdd11223344");
        let expiry = clock.now_secs() + 3600;
        assert!(tracker.check_and_record(&nonce, expiry).is_ok());
    }

    // -------------------------------------------------------------------
    // Duplicate detection
    // -------------------------------------------------------------------

    #[test]
    fn check_rejects_duplicate_nonce() {
        let (mut tracker, clock) = setup();
        let nonce = make_nonce_now(&clock);
        let expiry = clock.now_secs() + 3600;
        assert!(tracker.check_and_record(&nonce, expiry).is_ok());
        let result = tracker.check_and_record(&nonce, expiry);
        assert!(matches!(result, Err(UcanError::NonceReused(_))));
    }

    #[test]
    fn check_records_distinct_nonces() {
        let (mut tracker, clock) = setup();
        let millis = u128::from(clock.now_secs()) * 1000;
        let nonce_a = make_nonce(millis, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1");
        let nonce_b = make_nonce(millis, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2");
        let expiry = clock.now_secs() + 3600;
        assert!(tracker.check_and_record(&nonce_a, expiry).is_ok());
        assert!(tracker.check_and_record(&nonce_b, expiry).is_ok());
        assert_eq!(tracker.len(), 2);
    }

    // -------------------------------------------------------------------
    // Pruning
    // -------------------------------------------------------------------

    #[test]
    fn prune_removes_expired_entries() {
        let (mut tracker, clock) = setup();
        let nonce = make_nonce_now(&clock);
        // Token expires in 1 hour.
        let expiry = clock.now_secs() + 3600;
        tracker.check_and_record(&nonce, expiry).unwrap();
        assert_eq!(tracker.len(), 1);

        // Advance time past max(expiry + 300, first_seen + 86400).
        // first_seen + 86400 = BASE_SECS + 86400 (longer).
        // expiry + 300 = BASE_SECS + 3900.
        // Advance past the larger deadline.
        clock.advance(PRUNE_MIN_RETENTION_SECS + 1);
        tracker.prune();
        assert_eq!(tracker.len(), 0);
    }

    #[test]
    fn prune_retains_entry_within_retention_window() {
        let (mut tracker, clock) = setup();
        let nonce = make_nonce_now(&clock);
        let expiry = clock.now_secs() + 3600;
        tracker.check_and_record(&nonce, expiry).unwrap();

        // Advance 12 hours — still within 24-hour retention.
        clock.advance(12 * 3600);
        tracker.prune();
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn prune_respects_token_expiry_grace_period() {
        let (mut tracker, clock) = setup();
        let nonce = make_nonce_now(&clock);
        // Token expires 25 hours from now (90000s). The expiry + 300 deadline
        // (90300s) exceeds the first_seen + 86400 deadline (86400s), so the
        // expiry grace period should keep the entry alive past 24 hours.
        let expiry = clock.now_secs() + 25 * 3600;
        tracker.check_and_record(&nonce, expiry).unwrap();

        // Advance 24h + 1s past first_seen. The first_seen deadline has passed
        // (86400) but token_expiry + 300 has not (90300), so the entry survives.
        clock.advance(PRUNE_MIN_RETENTION_SECS + 1);
        tracker.prune();
        assert_eq!(tracker.len(), 1);

        // Now advance past expiry + 300 (90300 total from BASE_SECS).
        // We've already advanced 86401, so we need 90300 - 86401 + 1 = 3900 more.
        clock.advance(3900);
        tracker.prune();
        assert_eq!(tracker.len(), 0);
    }

    #[test]
    fn auto_prune_triggers_after_check_interval() {
        let (mut tracker, clock) = setup();

        // Record 999 nonces (below threshold).
        for i in 0..999 {
            let millis = u128::from(clock.now_secs()) * 1000;
            let hex = format!("{i:032x}");
            let nonce = make_nonce(millis, &hex);
            let expiry = clock.now_secs() + 1; // Very short expiry.
            tracker.check_and_record(&nonce, expiry).unwrap();
        }

        // Advance time past all deadlines.
        clock.advance(PRUNE_MIN_RETENTION_SECS + 1);

        // The 1000th check should trigger auto-prune.
        let millis = u128::from(clock.now_secs()) * 1000;
        let nonce = make_nonce(millis, "ff00ff00ff00ff00ff00ff00ff00ff00");
        let expiry = clock.now_secs() + 3600;
        tracker.check_and_record(&nonce, expiry).unwrap();

        // After auto-prune, only the last nonce should remain (the other 999
        // have passed their retention deadlines).
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn auto_prune_triggers_after_time_interval() {
        let (mut tracker, clock) = setup();

        let nonce = make_nonce_now(&clock);
        let expiry = clock.now_secs() + 1; // Very short expiry.
        tracker.check_and_record(&nonce, expiry).unwrap();
        assert_eq!(tracker.len(), 1);

        // Advance past both the prune time interval AND the retention window.
        clock.advance(PRUNE_MIN_RETENTION_SECS + PRUNE_TIME_INTERVAL_SECS + 1);

        // Next check should trigger time-based auto-prune.
        let nonce2 = make_nonce_now(&clock);
        let expiry2 = clock.now_secs() + 3600;
        tracker.check_and_record(&nonce2, expiry2).unwrap();

        // The first nonce should have been pruned.
        assert_eq!(tracker.len(), 1);
    }

    // -------------------------------------------------------------------
    // Serialization / deserialization
    // -------------------------------------------------------------------

    #[test]
    fn serialize_deserialize_roundtrip() {
        let (mut tracker, clock) = setup();
        let nonce = make_nonce_now(&clock);
        let expiry = clock.now_secs() + 3600;
        tracker.check_and_record(&nonce, expiry).unwrap();

        let bytes = tracker.to_bytes().unwrap();
        let restored = NonceTracker::from_bytes(&bytes, Arc::clone(&clock)).unwrap();

        assert_eq!(restored.context_id(), "ctx-test");
        assert_eq!(restored.len(), 1);
    }

    #[test]
    fn deserialize_prunes_expired_entries() {
        let (mut tracker, clock) = setup();
        let nonce = make_nonce_now(&clock);
        let expiry = clock.now_secs() + 1;
        tracker.check_and_record(&nonce, expiry).unwrap();

        let bytes = tracker.to_bytes().unwrap();

        // Advance time past the retention window before restoring.
        clock.advance(PRUNE_MIN_RETENTION_SECS + 1);

        let restored = NonceTracker::from_bytes(&bytes, Arc::clone(&clock)).unwrap();
        assert_eq!(restored.len(), 0);
    }

    #[test]
    fn deserialize_rejects_invalid_bytes() {
        let clock = Arc::new(TestClock::new(BASE_SECS));
        let result = NonceTracker::from_bytes(b"not json", clock);
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------
    // snapshot_entries / from_snapshot (ContextSnapshot persistence path)
    // -------------------------------------------------------------------

    #[test]
    fn snapshot_entries_captures_all_recorded_nonces() {
        let (mut tracker, clock) = setup();
        let now_millis = u128::from(clock.now_secs()) * 1000;
        let n1 = make_nonce(now_millis, "aabbccdd11223344aabbccdd11223344");
        let n2 = make_nonce(now_millis, "11223344aabbccdd11223344aabbccdd");
        let expiry = clock.now_secs() + 3600;
        tracker.check_and_record(&n1, expiry).unwrap();
        tracker.check_and_record(&n2, expiry).unwrap();

        let entries = tracker.snapshot_entries();
        assert_eq!(entries.len(), 2);
        assert!(entries.contains_key(&n1));
        assert!(entries.contains_key(&n2));
    }

    #[test]
    fn snapshot_entries_empty_for_new_tracker() {
        let (tracker, _clock) = setup();
        assert!(tracker.snapshot_entries().is_empty());
    }

    #[test]
    fn from_snapshot_restores_nonce_set_and_rejects_replay() {
        // #1608 follow-up: a captured spending UCAN nonce must not be
        // replayable after a process restart.
        let (mut tracker, clock) = setup();
        let nonce = make_nonce_now(&clock);
        let expiry = clock.now_secs() + 3600;
        tracker.check_and_record(&nonce, expiry).unwrap();

        // Simulate restart: serialize state, drop tracker, restore.
        let entries = tracker.snapshot_entries();
        drop(tracker);
        let mut restored = NonceTracker::from_snapshot("ctx-test".to_owned(), clock, entries);

        assert_eq!(restored.len(), 1, "restored tracker must retain the nonce");

        // Replay the same nonce — must be rejected as a replay attempt.
        let err = restored
            .check_and_record(&nonce, expiry)
            .expect_err("replay of captured nonce must be rejected post-restart");
        assert!(
            matches!(err, UcanError::NonceReused(_)),
            "expected NonceReused, got {err:?}"
        );
    }

    #[test]
    fn from_snapshot_prunes_expired_entries() {
        let (mut tracker, clock) = setup();
        let nonce = make_nonce_now(&clock);
        let short_expiry = clock.now_secs() + 1;
        tracker.check_and_record(&nonce, short_expiry).unwrap();

        let entries = tracker.snapshot_entries();
        drop(tracker);

        // Advance past the retention window before restoring.
        clock.advance(PRUNE_MIN_RETENTION_SECS + 1);

        let restored =
            NonceTracker::from_snapshot("ctx-test".to_owned(), Arc::clone(&clock), entries);
        assert_eq!(
            restored.len(),
            0,
            "stale entries must be pruned on from_snapshot"
        );
    }

    #[test]
    fn from_snapshot_truncates_oversized_snapshot() {
        // A poisoned snapshot attempting to force an unbounded HashMap
        // allocation must be bounded by `max_capacity`.
        let clock = Arc::new(TestClock::new(BASE_SECS));
        let mut oversized: HashMap<String, (u64, u64)> = HashMap::new();
        let now_secs = clock.now_secs();
        let expiry = now_secs + 86_400; // 24h — past the prune min retention floor
        for i in 0..50 {
            // Use a far-future first_seen so the prune pass retains the
            // entry (prune eligibility is based on first_seen + 86_400).
            let key = format!("nonce-{i:04}");
            oversized.insert(key, (now_secs, expiry));
        }

        let restored = NonceTracker::from_snapshot_with_capacity(
            "ctx-test".to_owned(),
            clock,
            oversized,
            /* max_capacity = */ 10,
        );
        assert!(
            restored.len() <= 10,
            "poisoned snapshot must be truncated to max_capacity, got {}",
            restored.len()
        );
    }

    // -------------------------------------------------------------------
    // Storage key
    // -------------------------------------------------------------------

    #[test]
    fn storage_key_includes_context_id() {
        let (tracker, _clock) = setup();
        assert_eq!(tracker.storage_key(), "nonce_tracker/ctx-test");
    }

    // -------------------------------------------------------------------
    // Context ID accessor
    // -------------------------------------------------------------------

    #[test]
    fn context_id_returns_assigned_value() {
        let clock = Arc::new(TestClock::new(BASE_SECS));
        let tracker = NonceTracker::new("my-context-42".to_owned(), clock);
        assert_eq!(tracker.context_id(), "my-context-42");
    }

    // -------------------------------------------------------------------
    // Edge cases
    // -------------------------------------------------------------------

    #[test]
    fn empty_tracker_prune_is_noop() {
        let (mut tracker, _clock) = setup();
        assert!(tracker.is_empty());
        tracker.prune();
        assert!(tracker.is_empty());
    }

    #[test]
    fn nonce_with_uppercase_hex_is_rejected() {
        let (mut tracker, clock) = setup();
        let millis = u128::from(clock.now_secs()) * 1000;
        // Uppercase hex chars — format expects lowercase.
        let nonce = format!("{millis}-AABBCCDD11223344AABBCCDD11223344");
        let expiry = clock.now_secs() + 3600;
        // Uppercase hex is valid hex, so this should be accepted
        // (is_ascii_hexdigit covers both upper and lower).
        assert!(tracker.check_and_record(&nonce, expiry).is_ok());
    }

    #[test]
    fn nonce_with_zero_timestamp_within_tolerance_at_epoch() {
        // Edge case: clock at 0 (epoch), nonce timestamp also 0.
        let clock = Arc::new(TestClock::new(0));
        let mut tracker = NonceTracker::new("ctx-epoch".to_owned(), clock);
        let nonce = make_nonce(0, "aabbccdd11223344aabbccdd11223344");
        assert!(tracker.check_and_record(&nonce, 3600).is_ok());
    }

    // -------------------------------------------------------------------
    // Capacity limits
    // -------------------------------------------------------------------

    #[test]
    fn with_max_capacity_sets_limit() {
        let clock = Arc::new(TestClock::new(BASE_SECS));
        let tracker = NonceTracker::with_max_capacity("ctx-cap".to_owned(), clock, 42);
        assert_eq!(tracker.max_capacity(), 42);
    }

    #[test]
    fn default_max_capacity_is_100_000() {
        let (tracker, _clock) = setup();
        assert_eq!(tracker.max_capacity(), 100_000);
    }

    #[test]
    fn check_accepts_up_to_max_capacity() {
        let clock = Arc::new(TestClock::new(BASE_SECS));
        let mut tracker =
            NonceTracker::with_max_capacity("ctx-cap".to_owned(), Arc::clone(&clock), 5);
        let millis = u128::from(clock.now_secs()) * 1000;
        let expiry = clock.now_secs() + 3600;

        for i in 0..5 {
            let hex = format!("{i:032x}");
            let nonce = make_nonce(millis, &hex);
            assert!(tracker.check_and_record(&nonce, expiry).is_ok());
        }
        assert_eq!(tracker.len(), 5);
    }

    #[test]
    fn check_rejects_when_at_capacity_with_fresh_entries() {
        let clock = Arc::new(TestClock::new(BASE_SECS));
        let mut tracker =
            NonceTracker::with_max_capacity("ctx-cap".to_owned(), Arc::clone(&clock), 3);
        let millis = u128::from(clock.now_secs()) * 1000;
        let expiry = clock.now_secs() + 3600;

        // Fill to capacity.
        for i in 0..3 {
            let hex = format!("{i:032x}");
            let nonce = make_nonce(millis, &hex);
            assert!(tracker.check_and_record(&nonce, expiry).is_ok());
        }

        // One more should fail — all entries are fresh (within retention).
        let nonce = make_nonce(millis, "ff00ff00ff00ff00ff00ff00ff00ff00");
        let result = tracker.check_and_record(&nonce, expiry);
        assert!(
            matches!(result, Err(UcanError::NonceTrackerFull(3))),
            "expected NonceTrackerFull(3), got {result:?}"
        );
    }

    #[test]
    fn check_prunes_expired_entries_when_at_capacity() {
        let clock = Arc::new(TestClock::new(BASE_SECS));
        let mut tracker =
            NonceTracker::with_max_capacity("ctx-cap".to_owned(), Arc::clone(&clock), 3);
        let millis = u128::from(clock.now_secs()) * 1000;

        // Fill to capacity with short-lived entries.
        for i in 0..3 {
            let hex = format!("{i:032x}");
            let nonce = make_nonce(millis, &hex);
            let expiry = clock.now_secs() + 1; // Very short expiry.
            assert!(tracker.check_and_record(&nonce, expiry).is_ok());
        }
        assert_eq!(tracker.len(), 3);

        // Advance time past all retention deadlines.
        clock.advance(PRUNE_MIN_RETENTION_SECS + 1);

        // Now a new nonce should succeed: the capacity check triggers prune,
        // freeing all 3 expired entries.
        let new_millis = u128::from(clock.now_secs()) * 1000;
        let nonce = make_nonce(new_millis, "ff00ff00ff00ff00ff00ff00ff00ff00");
        let expiry = clock.now_secs() + 3600;
        assert!(tracker.check_and_record(&nonce, expiry).is_ok());
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn check_partial_prune_frees_space_at_capacity() {
        let clock = Arc::new(TestClock::new(BASE_SECS));
        let mut tracker =
            NonceTracker::with_max_capacity("ctx-cap".to_owned(), Arc::clone(&clock), 3);
        let millis = u128::from(clock.now_secs()) * 1000;

        // Insert 2 entries with short expiry.
        for i in 0..2 {
            let hex = format!("{i:032x}");
            let nonce = make_nonce(millis, &hex);
            let expiry = clock.now_secs() + 1;
            assert!(tracker.check_and_record(&nonce, expiry).is_ok());
        }

        // Insert 1 entry with long expiry.
        let nonce_long = make_nonce(millis, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa3");
        let long_expiry = clock.now_secs() + PRUNE_MIN_RETENTION_SECS + 3600;
        assert!(tracker.check_and_record(&nonce_long, long_expiry).is_ok());
        assert_eq!(tracker.len(), 3);

        // Advance past 24h retention for the short-lived entries.
        clock.advance(PRUNE_MIN_RETENTION_SECS + 1);

        // New nonce should succeed: prune removes the 2 expired entries.
        let new_millis = u128::from(clock.now_secs()) * 1000;
        let nonce = make_nonce(new_millis, "ff00ff00ff00ff00ff00ff00ff00ff00");
        let expiry = clock.now_secs() + 3600;
        assert!(tracker.check_and_record(&nonce, expiry).is_ok());
        // 1 old long-lived + 1 new = 2
        assert_eq!(tracker.len(), 2);
    }
}
