//! Anti-spam cost escalation via sender velocity tracking.
//!
//! Implements per-sender message rate tracking with a configurable sliding
//! time window. The [`SenderVelocityTracker`] records message timestamps per
//! sender DID and computes the sender's velocity (message count within the
//! window). Expired timestamps are lazily pruned on each query.
//!
//! Velocity integrates with [`PricingFormula`](super::types::PricingFormula)
//! evaluation via the [`PricingMetric::SenderVelocity`](super::types::PricingMetric::SenderVelocity)
//! metric. Step-function escalation applies configurable cost thresholds:
//! normal conversation rates incur negligible cost while spam rates become
//! economically self-limiting.
//!
//! Economic escalation operates independently from participation consequence
//! mechanisms (spec section 7.3.7): an agent might exhaust its spending UCAN
//! before participation suspension triggers, or vice versa.
//!
//! Each DID is tracked independently as a Sybil deterrent — N identities
//! cost N times as much.
//!
//! See spec section 19.7 (Anti-Spam via Cost Escalation) and section 7.3.7
//! (Consequence mechanisms).

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use scp_primitives::DID;

use super::types::Amount;

/// Defense-in-depth cap on per-sender velocity Vec length. If a caller
/// floods a single DID, oldest entries are dropped once this cap is
/// exceeded. The Matrix-style token-bucket limiter prevents legitimate
/// callers from ever reaching this — 4096 leaves four orders of
/// magnitude of headroom over normal conversation rates.
///
/// Exposed at `pub(crate)` visibility so the tests module can reference
/// it without leaking into the public API.
pub(crate) const MAX_VELOCITY_ENTRIES_PER_SENDER: usize = 4096;

/// Maximum acceptable clock-skew tolerance for anti-spam snapshot validation.
///
/// Timestamps more than this far in the future are rejected; `last_refill`
/// values more than this far in the future are clamped to `now`. Five
/// seconds is the same tolerance used elsewhere in governance to bound NTP
/// jitter between honest nodes.
pub const SNAPSHOT_CLOCK_SKEW_TOLERANCE_SECS: u64 = 5;

// ---------------------------------------------------------------------------
// VelocityRollbackToken
// ---------------------------------------------------------------------------

/// Opaque identifier for a single recorded velocity entry.
///
/// Returned by [`SenderVelocityTracker::record_message`] so that a
/// failed downstream operation can roll back its specific entry via
/// [`SenderVelocityTracker::rollback`] — rather than popping "the most
/// recent" entry, which is racy under concurrent senders (RED-805).
///
/// Tokens are monotonically minted per-tracker (never reused) and are
/// **not persisted**: snapshot exports preserve timestamps only, and
/// `from_snapshot` synthesizes fresh sequence numbers for restored
/// entries (which by construction are never legitimate rollback
/// targets — restored history is finalized).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VelocityRollbackToken(u64);

impl VelocityRollbackToken {
    /// Exposes the internal sequence number. Used only in tests and in
    /// the snapshot format sanity checks. External callers should treat
    /// this as opaque.
    #[must_use]
    pub const fn into_inner(self) -> u64 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// SnapshotValidationError (F6)
// ---------------------------------------------------------------------------

/// Error emitted by snapshot validators when a deserialized anti-spam
/// snapshot cannot be reconstructed safely. See spec §19.7.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SnapshotValidationError {
    /// A velocity entry's timestamp is beyond `now + skew_tolerance`.
    /// This is never legitimate — it indicates a tampered snapshot.
    #[error(
        "velocity snapshot for {did}: timestamp {timestamp} exceeds now+{tolerance} (now={now})"
    )]
    VelocityFutureTimestamp {
        /// Stringified sender DID the offending entry belongs to.
        did: String,
        /// The offending timestamp value (seconds since epoch).
        timestamp: u64,
        /// The current wall time used for validation.
        now: u64,
        /// The accepted skew tolerance in seconds.
        tolerance: u64,
    },
    /// A velocity entry sequence number is duplicated within a single
    /// sender's Vec. Indicates malformed state.
    #[error("velocity snapshot for {did}: duplicate sequence {seq}")]
    VelocityDuplicateSeq {
        /// Stringified sender DID.
        did: String,
        /// The duplicated sequence number.
        seq: u64,
    },
    /// A sender's velocity Vec exceeds the hard cap. Rejection prevents
    /// a tampered snapshot from bypassing the per-sender memory bound.
    #[error("velocity snapshot for {did}: entry count {count} exceeds cap {cap}")]
    VelocityEntryCountExceeded {
        /// Stringified sender DID.
        did: String,
        /// The observed entry count.
        count: usize,
        /// The configured maximum entry cap.
        cap: usize,
    },
    /// `HardRateLimitConfig` carries an invalid `burst`.
    #[error("hard rate limit config: burst must be > 0")]
    InvalidBurst,
    /// `HardRateLimitConfig` carries an out-of-range refill rate. Upper
    /// bound prevents multiplication overflow in `try_consume`.
    #[error("hard rate limit config: refill_per_kilosec={rate} out of range")]
    InvalidRefillRate {
        /// The offending refill rate value.
        rate: u64,
    },
    /// `ContextMessagePricingConfig` floor exceeds cap.
    #[error("pricing config: floor ({floor}) exceeds cap ({cap})")]
    PricingFloorExceedsCap {
        /// The configured pricing floor (inner Amount).
        floor: u64,
        /// The configured pricing cap (inner Amount).
        cap: u64,
    },
}

// ---------------------------------------------------------------------------
// EscalationThreshold
// ---------------------------------------------------------------------------

/// A single step in the cost escalation schedule.
///
/// When a sender's velocity (messages within the sliding window) meets or
/// exceeds `velocity_threshold`, the `additional_cost` is added to the base
/// message cost. Thresholds are cumulative: if velocity exceeds multiple
/// thresholds, all corresponding costs are summed.
///
/// See spec section 19.7 for example threshold schedules.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationThreshold {
    /// Minimum velocity (message count in window) that triggers this tier.
    pub velocity_threshold: u64,
    /// Additional cost added when this tier is active.
    pub additional_cost: Amount,
}

// ---------------------------------------------------------------------------
// EscalationConfig
// ---------------------------------------------------------------------------

/// Configuration for step-function cost escalation.
///
/// Defines the thresholds at which additional costs are applied based on
/// sender velocity. Thresholds are evaluated cumulatively — all thresholds
/// whose `velocity_threshold` is met or exceeded by the sender's velocity
/// contribute their `additional_cost`.
///
/// # Example
///
/// From spec section 19.7:
/// ```text
/// base_cost: $0.001
/// thresholds:
///   (10/min, +$0.001)   → elevated: $0.002/msg
///   (50/min, +$0.01)    → high:     $0.012/msg
///   (200/min, +$0.10)   → extreme:  $0.112/msg
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationConfig {
    /// Step-function thresholds, ordered by velocity. Each threshold whose
    /// velocity is met contributes its additional cost.
    pub thresholds: Vec<EscalationThreshold>,
}

impl EscalationConfig {
    /// Returns the spec §19.7 default escalation schedule.
    ///
    /// Tiers (per `Amount(1) = $0.001` milli-cent convention):
    /// - velocity ≥ 10  → +Amount(1)   (elevated)
    /// - velocity ≥ 50  → +Amount(10)  (high)
    /// - velocity ≥ 200 → +Amount(100) (extreme)
    #[must_use]
    pub fn spec_default() -> Self {
        Self {
            thresholds: vec![
                EscalationThreshold {
                    velocity_threshold: 10,
                    additional_cost: Amount(1),
                },
                EscalationThreshold {
                    velocity_threshold: 50,
                    additional_cost: Amount(10),
                },
                EscalationThreshold {
                    velocity_threshold: 200,
                    additional_cost: Amount(100),
                },
            ],
        }
    }

    /// Computes the total additional cost for a given velocity.
    ///
    /// Sums the `additional_cost` of every threshold whose
    /// `velocity_threshold` is less than or equal to `velocity`. Returns
    /// `Amount(0)` if no thresholds are met.
    #[must_use]
    pub fn compute_additional_cost(&self, velocity: u64) -> Amount {
        let mut total = Amount(0);
        for threshold in &self.thresholds {
            if velocity >= threshold.velocity_threshold {
                total = total.saturating_add(threshold.additional_cost);
            }
        }
        total
    }
}

// ---------------------------------------------------------------------------
// SenderVelocityTracker
// ---------------------------------------------------------------------------

/// Thread-safe per-sender message velocity tracker with sliding time window.
///
/// Tracks message timestamps per sender DID within a configurable window
/// duration. Expired messages are lazily pruned on each query. The tracker
/// is `Send + Sync` for use across threads.
///
/// # Thread Safety
///
/// Internal state is protected by a [`std::sync::Mutex`]. This is a
/// synchronous mutex (not `tokio::sync::Mutex`) because the critical
/// sections are short, non-blocking, CPU-only operations with no I/O or
/// await points — a sync mutex is appropriate and avoids async overhead.
///
/// # Sybil Deterrent
///
/// Each DID is tracked independently. N Sybil identities incur N times
/// the cost, compounding with identity creation costs (spec section 19.7).
///
/// See spec section 19.7 and section 7.3.7.
pub struct SenderVelocityTracker {
    /// Sliding window duration in seconds.
    window_secs: u64,
    /// Per-sender message state, protected by a mutex.
    /// Key: sender DID, Value: Vec of `(timestamp, sequence)` tuples where
    /// `sequence` is a tracker-wide monotonic rollback token id.
    state: Mutex<HashMap<DID, Vec<(u64, u64)>>>,
    /// Monotonic counter used to mint unique [`VelocityRollbackToken`]
    /// values. Relaxed ordering is fine — the sequence itself is only
    /// used for identity comparisons within each sender's Vec (which is
    /// already serialized by the state mutex).
    next_seq: AtomicU64,
}

impl SenderVelocityTracker {
    /// Creates a new tracker with the given sliding window duration.
    ///
    /// # Arguments
    ///
    /// * `window_secs` — Duration of the sliding window in seconds. Messages
    ///   older than `now - window_secs` are not counted toward velocity.
    #[must_use]
    pub fn new(window_secs: u64) -> Self {
        Self {
            window_secs,
            state: Mutex::new(HashMap::new()),
            next_seq: AtomicU64::new(0),
        }
    }

    /// Returns the configured sliding window duration in seconds.
    #[must_use]
    pub const fn window_secs(&self) -> u64 {
        self.window_secs
    }

    /// Clears all per-sender velocity data.
    ///
    /// Called on context close/expiry/tombstone so stale velocity data
    /// does not carry over if the context is later restored.
    pub fn clear(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.clear();
    }

    /// Exports the tracker's per-sender timestamp entries for persistence.
    ///
    /// Returns a `HashMap<String, Vec<u64>>` mapping each sender DID to
    /// their recorded message timestamps. Rollback-token sequence numbers
    /// are intentionally **not** persisted — they are local-only identity
    /// markers that have no meaning once the process restarts.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn snapshot_entries(&self) -> HashMap<String, Vec<u64>> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .iter()
            .map(|(did, entries)| {
                (
                    did.as_ref().to_owned(),
                    entries.iter().map(|&(ts, _)| ts).collect(),
                )
            })
            .collect()
    }

    /// Reconstructs a tracker from a persisted snapshot.
    ///
    /// Restores both the sliding window configuration and per-sender timestamp
    /// entries. Used during context restoration to avoid losing velocity state
    /// across process restarts. Each restored entry is assigned a fresh
    /// sequence number drawn from the tracker's counter — these entries will
    /// never be legitimate rollback targets because they predate any
    /// `record_message` call made after restore.
    ///
    /// Callers are expected to have validated the snapshot via
    /// [`Self::validate_and_sanitize_snapshot`] before calling this.
    #[must_use]
    pub fn from_snapshot(window_secs: u64, entries: HashMap<String, Vec<u64>>) -> Self {
        let tracker = Self::new(window_secs);
        {
            let mut state = tracker
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for (did_str, timestamps) in entries {
                let tagged: Vec<(u64, u64)> = timestamps
                    .into_iter()
                    .map(|ts| {
                        let seq = tracker.next_seq.fetch_add(1, Ordering::Relaxed);
                        (ts, seq)
                    })
                    .collect();
                state.insert(DID::from(did_str), tagged);
            }
        }
        tracker
    }

    /// Validates and sanitizes a persisted velocity snapshot before
    /// reconstruction. Rejects future timestamps beyond the skew
    /// tolerance and rejects oversized Vecs. Stale entries (beyond the
    /// sliding window floor) are **clamped-dropped** rather than
    /// rejected because stale data is legitimate snapshot-replay
    /// (no attacker advantage) whereas future data is uniquely an attack.
    ///
    /// Call this before [`Self::from_snapshot`]. Mutates the input to
    /// remove stale entries.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotValidationError::VelocityFutureTimestamp`] if any
    /// entry has a timestamp more than `clock_skew_tolerance` seconds in
    /// the future relative to `now`, and
    /// [`SnapshotValidationError::VelocityEntryCountExceeded`] if any
    /// sender's entry list exceeds [`MAX_VELOCITY_ENTRIES_PER_SENDER`]
    /// after pruning stale entries.
    pub fn validate_and_sanitize_snapshot(
        entries: &mut HashMap<String, Vec<u64>>,
        window_secs: u64,
        now: u64,
        clock_skew_tolerance: u64,
    ) -> Result<(), SnapshotValidationError> {
        let future_bound = now.saturating_add(clock_skew_tolerance);
        let past_bound = now
            .saturating_sub(window_secs)
            .saturating_sub(clock_skew_tolerance);

        for (did, timestamps) in entries.iter_mut() {
            // Reject future timestamps outright.
            for &ts in timestamps.iter() {
                if ts > future_bound {
                    return Err(SnapshotValidationError::VelocityFutureTimestamp {
                        did: did.clone(),
                        timestamp: ts,
                        now,
                        tolerance: clock_skew_tolerance,
                    });
                }
            }
            // Clamp-drop stale entries that are outside the window floor.
            timestamps.retain(|&ts| ts >= past_bound);
            // Reject any Vec that exceeds the hard cap — tampering.
            if timestamps.len() > MAX_VELOCITY_ENTRIES_PER_SENDER {
                return Err(SnapshotValidationError::VelocityEntryCountExceeded {
                    did: did.clone(),
                    count: timestamps.len(),
                    cap: MAX_VELOCITY_ENTRIES_PER_SENDER,
                });
            }
        }
        Ok(())
    }

    /// Records a message from `sender` at the given `timestamp`.
    ///
    /// The timestamp is in seconds since the Unix epoch. Prunes
    /// expired entries on append so free-context traffic (which never
    /// calls [`Self::get_velocity`]) does not grow unbounded. Enforces
    /// a per-sender hard cap as defense-in-depth.
    ///
    /// Returns a [`VelocityRollbackToken`] that identifies this specific
    /// entry so callers can roll it back via [`Self::rollback`] without
    /// racing concurrent senders.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (indicates a prior panic
    /// while holding the lock — an unrecoverable state).
    #[allow(clippy::significant_drop_tightening)] // Lock scopes the prune+append; split would race.
    pub fn record_message(&self, sender: &DID, timestamp: u64) -> VelocityRollbackToken {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cutoff = timestamp.saturating_sub(self.window_secs);
        let entries = state.entry(sender.clone()).or_default();

        // F8: prune expired entries before append so a free-context path
        // (which never calls get_velocity) does not grow unbounded.
        entries.retain(|&(ts, _)| ts >= cutoff);

        // F8: defense-in-depth hard cap. If a pathological caller floods
        // this sender's slot, drop the oldest entries.
        if entries.len() >= MAX_VELOCITY_ENTRIES_PER_SENDER {
            let drop_count = entries.len() + 1 - MAX_VELOCITY_ENTRIES_PER_SENDER;
            entries.drain(0..drop_count);
            tracing::warn!(
                did = %sender.as_ref(),
                cap = MAX_VELOCITY_ENTRIES_PER_SENDER,
                "velocity tracker per-sender cap hit; dropping oldest entries"
            );
        }

        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        entries.push((timestamp, seq));
        VelocityRollbackToken(seq)
    }

    /// Returns the number of messages from `sender` within the current
    /// sliding window ending at `now`.
    ///
    /// Lazily prunes expired messages (timestamps older than
    /// `now - window_secs`) from the sender's record. Returns 0 for
    /// unknown senders.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn get_velocity(&self, sender: &DID, now: u64) -> u64 {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cutoff = now.saturating_sub(self.window_secs);

        state.get_mut(sender).map_or(0, |entries| {
            entries.retain(|&(ts, _)| ts >= cutoff);
            entries.len() as u64
        })
    }

    /// Returns the total number of messages from **all** senders within the
    /// current sliding window ending at `now`.
    ///
    /// This is the aggregate context-level message rate: the sum of every
    /// member's velocity within the tracker's window. Used to populate
    /// [`ObservableMetrics::context_message_rate`](super::policy::ObservableMetrics::context_message_rate)
    /// for pricing formula evaluation (spec §19.4).
    ///
    /// Lazily prunes expired timestamps from every sender's record.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    #[allow(clippy::significant_drop_tightening)] // Lock held for iteration; dropping early is not possible.
    pub fn aggregate_velocity(&self, now: u64) -> u64 {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cutoff = now.saturating_sub(self.window_secs);

        let mut total: u64 = 0;
        for entries in state.values_mut() {
            entries.retain(|&(ts, _)| ts >= cutoff);
            total = total.saturating_add(entries.len() as u64);
        }
        total
    }

    /// Computes the escalated cost for `sender` at time `now`.
    ///
    /// Evaluates the sender's velocity against the provided
    /// [`EscalationConfig`] and returns `base_cost + additional_cost` from
    /// matched thresholds, clamped to `[floor, cap]` if provided.
    ///
    /// This method integrates `SenderVelocity` with `PricingFormula`
    /// evaluation (spec section 19.4). Both payer and receiver evaluate
    /// independently — the velocity is observable by both sides.
    #[must_use]
    pub fn compute_escalated_cost(
        &self,
        sender: &DID,
        now: u64,
        base_cost: Amount,
        config: &EscalationConfig,
        floor: Option<Amount>,
        cap: Option<Amount>,
    ) -> Amount {
        let velocity = self.get_velocity(sender, now);
        let additional = config.compute_additional_cost(velocity);
        let mut cost = base_cost.saturating_add(additional);

        if let Some(f) = floor
            && cost < f
        {
            cost = f;
        }
        if let Some(c) = cap
            && cost > c
        {
            cost = c;
        }
        cost
    }

    /// Removes the specific entry identified by `token` for `sender`,
    /// undoing exactly the [`record_message`](Self::record_message) call
    /// that returned the token.
    ///
    /// Returns `true` if the entry was found and removed. A return of
    /// `false` is not an error: legitimate cases include the entry
    /// having been pruned on a later `get_velocity` / `record_message`
    /// call, or the sender having no entries at all.
    ///
    /// This replaces the old `rollback_last` which popped "the most
    /// recent" entry — a race bug under concurrent senders. See
    /// red-hat finding RED-805 and batch1 plan §F5.
    #[allow(clippy::significant_drop_tightening)] // Lock scopes the entire lookup+mutate.
    pub fn rollback(&self, sender: &DID, token: VelocityRollbackToken) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entries) = state.get_mut(sender)
            && let Some(pos) = entries.iter().position(|&(_, seq)| seq == token.0)
        {
            entries.swap_remove(pos);
            return true;
        }
        false
    }
}

impl std::fmt::Debug for SenderVelocityTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SenderVelocityTracker")
            .field("window_secs", &self.window_secs)
            .field("state", &"<locked>")
            .field("next_seq", &self.next_seq)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// HardRateLimitConfig
// ---------------------------------------------------------------------------

/// Configuration for the Matrix Synapse–style token bucket hard rate limit.
///
/// This is a defense-in-depth cap layered on top of the per-DID economic
/// escalation in spec §19.7. It is independent of cost and is enforced even
/// when no `EconomicPolicy` is configured. Modeled after Matrix Synapse's
/// `rc_message` defaults.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardRateLimitConfig {
    /// Token refill rate expressed as tokens per 1000 seconds (kilo-second).
    /// Matrix's default is 0.2 tokens/sec → `200` tokens/kilo-sec.
    pub refill_per_kilosec: u64,
    /// Maximum tokens a single sender may accumulate (burst capacity).
    /// Matrix default: `10`.
    pub burst: u64,
}

impl HardRateLimitConfig {
    /// Upper bound on `refill_per_kilosec`. Prevents arithmetic overflow
    /// in [`TokenBucketLimiter::try_consume`] when multiplied by elapsed
    /// time. Chosen to leave headroom for any realistic Matrix-style
    /// configuration (the default is 200).
    pub const MAX_REFILL_PER_KILOSEC: u64 = 1_000_000;

    /// Matrix Synapse defaults: 0.2 messages per second, burst 10.
    #[must_use]
    pub const fn matrix_defaults() -> Self {
        Self {
            refill_per_kilosec: 200,
            burst: 10,
        }
    }

    /// Validates the configuration. Called during snapshot restore and
    /// context creation (spec §19.7) to prevent tampered or
    /// nonsensical values from reaching the hot path.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotValidationError::InvalidBurst`] if `burst == 0`
    /// and [`SnapshotValidationError::InvalidRefillRate`] if
    /// `refill_per_kilosec` is zero or exceeds
    /// [`Self::MAX_REFILL_PER_KILOSEC`].
    pub const fn validate(&self) -> Result<(), SnapshotValidationError> {
        if self.burst == 0 {
            return Err(SnapshotValidationError::InvalidBurst);
        }
        if self.refill_per_kilosec == 0 || self.refill_per_kilosec > Self::MAX_REFILL_PER_KILOSEC {
            return Err(SnapshotValidationError::InvalidRefillRate {
                rate: self.refill_per_kilosec,
            });
        }
        Ok(())
    }
}

impl Default for HardRateLimitConfig {
    fn default() -> Self {
        Self::matrix_defaults()
    }
}

// ---------------------------------------------------------------------------
// TokenBucketLimiter
// ---------------------------------------------------------------------------

/// Per-sender token bucket hard rate limiter (defense-in-depth, Matrix-style).
///
/// Each sender DID has an independent token bucket. Each `try_consume` call
/// drains one token; tokens refill at a configurable rate. Tokens are stored
/// in milli-tokens internally so that fractional refill rates work with
/// integer arithmetic.
///
/// This limiter complements the per-DID cost escalation in spec §19.7 by
/// rejecting bursts at the protocol layer regardless of cost: even an actor
/// with infinite budget cannot exceed `burst` messages without waiting for
/// refill. See [`HardRateLimitConfig::matrix_defaults`].
///
/// # Monotonic clock requirement
///
/// Callers MUST pass `now_secs` values that never regress. A regressing
/// clock does NOT corrupt internal state — [`Self::try_consume`] clamps
/// `last_refill` forward so subsequent refills continue to compute
/// against the highest observed timestamp — but refills may be delayed
/// until wall time catches up to the stored timestamp.
pub struct TokenBucketLimiter {
    /// Per-sender state: (`tokens_milli`, `last_refill_secs`).
    state: Mutex<HashMap<DID, (u64, u64)>>,
    config: HardRateLimitConfig,
}

impl TokenBucketLimiter {
    /// Creates a new limiter with the given configuration.
    #[must_use]
    pub fn new(config: HardRateLimitConfig) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            config,
        }
    }

    /// Returns the configuration.
    #[must_use]
    pub const fn config(&self) -> &HardRateLimitConfig {
        &self.config
    }

    /// Maximum tokens (in milli-units) any sender may hold.
    const fn burst_milli(&self) -> u64 {
        self.config.burst.saturating_mul(1000)
    }

    /// Refills the sender's bucket based on elapsed wall time and attempts to
    /// consume one token. Returns `true` if a token was consumed, `false` if
    /// the sender is over their budget.
    ///
    /// Clock-skew-safe: if `now_secs` is less than the stored
    /// `last_refill` (the caller's clock went backwards), elapsed is
    /// treated as zero and `last_refill` is kept at the previous value.
    /// This prevents a non-monotonic clock from corrupting refill
    /// accounting or enabling a spurious-refund-after-the-fact attack.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[allow(clippy::significant_drop_tightening)]
    pub fn try_consume(&self, sender: &DID, now_secs: u64) -> bool {
        let burst_milli = self.burst_milli();
        let refill_rate = self.config.refill_per_kilosec; // tokens per 1000 seconds

        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = state
            .entry(sender.clone())
            .or_insert((burst_milli, now_secs));

        // F7: clock-skew safety. Clamp `effective_now` forward so
        // `last_refill` never regresses.
        let effective_now = now_secs.max(entry.1);
        let elapsed = effective_now.saturating_sub(entry.1);
        let refill = elapsed.saturating_mul(refill_rate);
        entry.0 = entry.0.saturating_add(refill).min(burst_milli);
        entry.1 = effective_now;

        // Consume one token (1000 milli-tokens).
        if entry.0 >= 1000 {
            entry.0 -= 1000;
            true
        } else {
            false
        }
    }

    /// Validates and sanitizes persisted token bucket state. Clamps
    /// `tokens_milli > burst_milli` (legitimate if `burst` was lowered
    /// via governance between snapshots), and clamps `last_refill >
    /// now + skew_tolerance` to `now` (tampering).
    ///
    /// # Errors
    ///
    /// No errors today — all irregularities are clamped. Returns
    /// `Ok(())` unconditionally; kept as `Result` for forward
    /// compatibility when stricter rejection policies are added.
    pub fn validate_and_sanitize_snapshot(
        entries: &mut HashMap<String, (u64, u64)>,
        config: &HardRateLimitConfig,
        now: u64,
        clock_skew_tolerance: u64,
    ) -> Result<(), SnapshotValidationError> {
        let burst_milli = config.burst.saturating_mul(1000);
        let future_bound = now.saturating_add(clock_skew_tolerance);
        for (did, entry) in entries.iter_mut() {
            if entry.0 > burst_milli {
                tracing::warn!(
                    did = %did,
                    tokens_milli = entry.0,
                    burst_milli,
                    "token bucket snapshot tokens exceeded burst; clamping"
                );
                entry.0 = burst_milli;
            }
            if entry.1 > future_bound {
                tracing::warn!(
                    did = %did,
                    last_refill = entry.1,
                    now,
                    "token bucket snapshot last_refill in future; clamping to now"
                );
                entry.1 = now;
            }
        }
        Ok(())
    }

    /// Refunds one token to the sender's bucket (clamped at the burst).
    /// Used to roll back a `try_consume` when a downstream operation fails.
    ///
    /// No-op if the sender has no recorded bucket.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn refund(&self, sender: &DID) {
        let burst_milli = self.burst_milli();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = state.get_mut(sender) {
            entry.0 = entry.0.saturating_add(1000).min(burst_milli);
        }
    }

    /// Exports the per-sender state for persistence.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn snapshot_entries(&self) -> HashMap<String, (u64, u64)> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .iter()
            .map(|(did, entry)| (did.as_ref().to_owned(), *entry))
            .collect()
    }

    /// Reconstructs a limiter from a persisted snapshot.
    #[must_use]
    pub fn from_snapshot(
        config: HardRateLimitConfig,
        entries: HashMap<String, (u64, u64)>,
    ) -> Self {
        let converted: HashMap<DID, (u64, u64)> = entries
            .into_iter()
            .map(|(did_str, entry)| (DID::from(did_str), entry))
            .collect();
        Self {
            state: Mutex::new(converted),
            config,
        }
    }
}

impl std::fmt::Debug for TokenBucketLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenBucketLimiter")
            .field("config", &self.config)
            .field("state", &"<locked>")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// ContextMessagePricingConfig
// ---------------------------------------------------------------------------

/// Spec §19.7 per-DID escalating-cost message pricing configuration.
///
/// Bundles the base cost, escalation schedule, floor/cap clamps, and the
/// hard rate limit (defense-in-depth) for a single context. This is the
/// in-context replacement for the deleted aggregate `RelayPricingConfig`.
///
/// Amount unit convention: `Amount(1) = $0.001` (one milli-cent), per
/// existing test conventions in this module. The spec example
/// `base=$0.001, tiers (10,+$0.001), (50,+$0.01), (200,+$0.10), cap=$1`
/// therefore maps to: `base=Amount(1), (10, +1), (50, +10), (200, +100),
/// cap=Amount(1000)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextMessagePricingConfig {
    /// Base cost per message before escalation.
    pub base_cost: Amount,
    /// Step-function escalation tiers applied based on per-DID velocity.
    pub escalation: EscalationConfig,
    /// Floor (clamps cost upward to at least this value).
    pub floor: Option<Amount>,
    /// Cap (clamps cost downward to at most this value).
    pub cap: Option<Amount>,
    /// Token-bucket hard rate limit (defense-in-depth, independent of cost).
    pub hard_rate_limit: HardRateLimitConfig,
}

impl ContextMessagePricingConfig {
    /// Returns the spec §19.7 default pricing configuration.
    #[must_use]
    pub fn spec_default() -> Self {
        Self {
            base_cost: Amount(1),
            escalation: EscalationConfig::spec_default(),
            floor: Some(Amount(1)),
            cap: Some(Amount(1000)),
            hard_rate_limit: HardRateLimitConfig::matrix_defaults(),
        }
    }

    /// Validates the pricing configuration. Called during context
    /// creation and snapshot restore to prevent invalid configurations
    /// from reaching the hot path.
    ///
    /// # Errors
    ///
    /// - [`SnapshotValidationError::PricingFloorExceedsCap`] if
    ///   `floor > cap` when both are set.
    /// - Any error from [`HardRateLimitConfig::validate`] on the embedded
    ///   hard rate limit.
    pub fn validate(&self) -> Result<(), SnapshotValidationError> {
        self.hard_rate_limit.validate()?;
        if let (Some(floor), Some(cap)) = (self.floor, self.cap)
            && floor.0 > cap.0
        {
            return Err(SnapshotValidationError::PricingFloorExceedsCap {
                floor: floor.0,
                cap: cap.0,
            });
        }
        Ok(())
    }
}

impl Default for ContextMessagePricingConfig {
    fn default() -> Self {
        Self::spec_default()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn did(s: &str) -> DID {
        DID::from(s)
    }

    // --- Velocity tracking ---

    #[test]
    fn velocity_starts_at_zero_for_unknown_sender() {
        let tracker = SenderVelocityTracker::new(60);
        assert_eq!(tracker.get_velocity(&did("did:dht:z6MkUnknown"), 1000), 0);
    }

    #[test]
    fn record_n_messages_returns_n_within_window() {
        let tracker = SenderVelocityTracker::new(60);
        let sender = did("did:dht:z6MkAlice");

        for i in 0..5 {
            tracker.record_message(&sender, 1000 + i);
        }

        assert_eq!(tracker.get_velocity(&sender, 1005), 5);
    }

    #[test]
    fn messages_outside_window_not_counted() {
        let tracker = SenderVelocityTracker::new(60);
        let sender = did("did:dht:z6MkAlice");

        // Record messages at t=100
        tracker.record_message(&sender, 100);
        tracker.record_message(&sender, 101);

        // Record messages at t=200 (within 60s window of t=200)
        tracker.record_message(&sender, 180);
        tracker.record_message(&sender, 190);
        tracker.record_message(&sender, 200);

        // At t=200, window covers (140, 200]. Messages at 100 and 101 are
        // outside the window.
        assert_eq!(tracker.get_velocity(&sender, 200), 3);
    }

    #[test]
    fn expired_messages_pruned_on_query() {
        let tracker = SenderVelocityTracker::new(10);
        let sender = did("did:dht:z6MkAlice");

        tracker.record_message(&sender, 100);
        tracker.record_message(&sender, 105);

        // At t=105, both messages in window
        assert_eq!(tracker.get_velocity(&sender, 105), 2);

        // At t=115, cutoff = 115 - 10 = 105. retain uses `ts >= cutoff`:
        // - message at 100: 100 >= 105 → false → pruned
        // - message at 105: 105 >= 105 → true → retained
        assert_eq!(tracker.get_velocity(&sender, 115), 1);
    }

    #[test]
    fn two_senders_tracked_independently() {
        let tracker = SenderVelocityTracker::new(60);
        let alice = did("did:dht:z6MkAlice");
        let bob = did("did:dht:z6MkBob");

        tracker.record_message(&alice, 1000);
        tracker.record_message(&alice, 1001);
        tracker.record_message(&alice, 1002);

        tracker.record_message(&bob, 1000);

        assert_eq!(tracker.get_velocity(&alice, 1005), 3);
        assert_eq!(tracker.get_velocity(&bob, 1005), 1);
    }

    // --- Aggregate velocity ---

    #[test]
    fn aggregate_velocity_sums_all_senders() {
        let tracker = SenderVelocityTracker::new(60);
        let alice = did("did:dht:z6MkAlice");
        let bob = did("did:dht:z6MkBob");
        let carol = did("did:dht:z6MkCarol");

        tracker.record_message(&alice, 1000);
        tracker.record_message(&alice, 1001);
        tracker.record_message(&alice, 1002);

        tracker.record_message(&bob, 1000);

        tracker.record_message(&carol, 1000);
        tracker.record_message(&carol, 1001);

        // alice=3, bob=1, carol=2 → aggregate=6
        assert_eq!(tracker.aggregate_velocity(1005), 6);
    }

    #[test]
    fn aggregate_velocity_prunes_expired() {
        let tracker = SenderVelocityTracker::new(10);
        let alice = did("did:dht:z6MkAlice");
        let bob = did("did:dht:z6MkBob");

        tracker.record_message(&alice, 100);
        tracker.record_message(&alice, 105);
        tracker.record_message(&bob, 108);

        // At t=112, window is (102, 112]. alice@100 expired, alice@105 alive, bob@108 alive.
        assert_eq!(tracker.aggregate_velocity(112), 2);
    }

    #[test]
    fn aggregate_velocity_zero_for_empty_tracker() {
        let tracker = SenderVelocityTracker::new(60);
        assert_eq!(tracker.aggregate_velocity(1000), 0);
    }

    // --- Step-function escalation ---

    #[test]
    fn escalation_no_thresholds_met() {
        let config = EscalationConfig {
            thresholds: vec![
                EscalationThreshold {
                    velocity_threshold: 10,
                    additional_cost: Amount(1),
                },
                EscalationThreshold {
                    velocity_threshold: 50,
                    additional_cost: Amount(10),
                },
            ],
        };

        // Velocity 5 — below all thresholds
        assert_eq!(config.compute_additional_cost(5), Amount(0));
    }

    #[test]
    fn escalation_first_threshold_met() {
        let config = EscalationConfig {
            thresholds: vec![
                EscalationThreshold {
                    velocity_threshold: 10,
                    additional_cost: Amount(1),
                },
                EscalationThreshold {
                    velocity_threshold: 50,
                    additional_cost: Amount(10),
                },
            ],
        };

        // Velocity 10 — exactly meets first threshold
        assert_eq!(config.compute_additional_cost(10), Amount(1));

        // Velocity 30 — exceeds first, below second
        assert_eq!(config.compute_additional_cost(30), Amount(1));
    }

    #[test]
    fn escalation_all_thresholds_met() {
        let config = EscalationConfig {
            thresholds: vec![
                EscalationThreshold {
                    velocity_threshold: 10,
                    additional_cost: Amount(1),
                },
                EscalationThreshold {
                    velocity_threshold: 50,
                    additional_cost: Amount(10),
                },
                EscalationThreshold {
                    velocity_threshold: 200,
                    additional_cost: Amount(100),
                },
            ],
        };

        // Velocity 200 — meets all thresholds. Costs are cumulative: 1 + 10 + 100 = 111
        assert_eq!(config.compute_additional_cost(200), Amount(111));
    }

    #[test]
    fn step_function_escalation_computes_correct_cost_at_each_threshold() {
        // Spec example from section 19.7:
        // base_cost: $0.001 (1 unit)
        // thresholds: (10, +1), (50, +10), (200, +100)
        //
        // NOTE: window must cover all 200 recorded messages, so we use a
        // 300s window. All record timestamps are within [now-299, now]
        // so F8's prune-on-append does not drop entries mid-test.
        let tracker = SenderVelocityTracker::new(300);
        let sender = did("did:dht:z6MkSpammer");
        let base_cost = Amount(1);
        let config = EscalationConfig {
            thresholds: vec![
                EscalationThreshold {
                    velocity_threshold: 10,
                    additional_cost: Amount(1),
                },
                EscalationThreshold {
                    velocity_threshold: 50,
                    additional_cost: Amount(10),
                },
                EscalationThreshold {
                    velocity_threshold: 200,
                    additional_cost: Amount(100),
                },
            ],
        };

        let now = 10_000;

        // 0 messages: base cost only
        assert_eq!(
            tracker.compute_escalated_cost(&sender, now, base_cost, &config, None, None),
            Amount(1),
        );

        // Record 10 messages (hits first threshold). All timestamps are
        // strictly in the past relative to `now`, so prune-on-append
        // (F8) is a no-op within the 300s window.
        for i in 0..10u64 {
            tracker.record_message(&sender, now - 250 + i);
        }
        assert_eq!(
            tracker.compute_escalated_cost(&sender, now, base_cost, &config, None, None),
            Amount(2), // 1 + 1
        );

        // Record 40 more (total 50, hits second threshold)
        for i in 10..50u64 {
            tracker.record_message(&sender, now - 250 + i);
        }
        assert_eq!(
            tracker.compute_escalated_cost(&sender, now, base_cost, &config, None, None),
            Amount(12), // 1 + 1 + 10
        );

        // Record 150 more (total 200, hits all thresholds)
        for i in 50..200u64 {
            tracker.record_message(&sender, now - 250 + i);
        }
        assert_eq!(
            tracker.compute_escalated_cost(&sender, now, base_cost, &config, None, None),
            Amount(112), // 1 + 1 + 10 + 100
        );
    }

    #[test]
    fn escalated_cost_respects_cap() {
        let tracker = SenderVelocityTracker::new(60);
        let sender = did("did:dht:z6MkSpammer");
        let config = EscalationConfig {
            thresholds: vec![EscalationThreshold {
                velocity_threshold: 1,
                additional_cost: Amount(1000),
            }],
        };

        tracker.record_message(&sender, 100);

        // Cap at 500
        assert_eq!(
            tracker.compute_escalated_cost(
                &sender,
                100,
                Amount(100),
                &config,
                None,
                Some(Amount(500)),
            ),
            Amount(500),
        );
    }

    #[test]
    fn escalated_cost_respects_floor() {
        let tracker = SenderVelocityTracker::new(60);
        let sender = did("did:dht:z6MkSender");
        let config = EscalationConfig {
            thresholds: vec![], // no thresholds
        };

        // Base cost 0, floor 5
        assert_eq!(
            tracker
                .compute_escalated_cost(&sender, 100, Amount(0), &config, Some(Amount(5)), None,),
            Amount(5),
        );
    }

    // --- Thread safety ---

    #[test]
    fn concurrent_access_does_not_corrupt_state() {
        use std::sync::Arc;
        use std::thread;

        // Use a large window so no messages expire during the test.
        let tracker = Arc::new(SenderVelocityTracker::new(10_000));
        let sender = did("did:dht:z6MkConcurrent");
        let messages_per_thread: usize = 100;
        let thread_count: usize = 8;
        let base_ts: u64 = 1000;

        let mut handles = Vec::new();

        for t in 0..thread_count {
            let tracker = Arc::clone(&tracker);
            let sender = sender.clone();
            handles.push(thread::spawn(move || {
                for i in 0..messages_per_thread {
                    let ts = base_ts + (t * messages_per_thread + i) as u64;
                    tracker.record_message(&sender, ts);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Query at a time within the window of all recorded messages.
        let now = base_ts + (thread_count * messages_per_thread) as u64;
        let total = tracker.get_velocity(&sender, now);
        assert_eq!(total, (thread_count * messages_per_thread) as u64);
    }

    // --- Snapshot / restore ---

    #[test]
    fn snapshot_entries_captures_all_senders() {
        let tracker = SenderVelocityTracker::new(60);
        let alice = did("did:dht:z6MkAlice");
        let bob = did("did:dht:z6MkBob");

        tracker.record_message(&alice, 1000);
        tracker.record_message(&alice, 1010);
        tracker.record_message(&bob, 1005);

        let entries = tracker.snapshot_entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries.get("did:dht:z6MkAlice").unwrap(), &vec![1000, 1010]);
        assert_eq!(entries.get("did:dht:z6MkBob").unwrap(), &vec![1005]);
    }

    #[test]
    fn snapshot_entries_empty_for_new_tracker() {
        let tracker = SenderVelocityTracker::new(60);
        assert!(tracker.snapshot_entries().is_empty());
    }

    #[test]
    fn from_snapshot_restores_velocity_state() {
        let mut entries = HashMap::new();
        entries.insert("did:dht:z6MkAlice".to_owned(), vec![1000, 1010, 1020]);
        entries.insert("did:dht:z6MkBob".to_owned(), vec![1005]);

        let restored = SenderVelocityTracker::from_snapshot(120, entries);

        assert_eq!(restored.window_secs(), 120);
        // All timestamps within 120s window of t=1020.
        assert_eq!(restored.get_velocity(&did("did:dht:z6MkAlice"), 1020), 3);
        assert_eq!(restored.get_velocity(&did("did:dht:z6MkBob"), 1020), 1);
    }

    #[test]
    fn from_snapshot_empty_entries() {
        let restored = SenderVelocityTracker::from_snapshot(60, HashMap::new());
        assert_eq!(restored.window_secs(), 60);
        assert_eq!(restored.get_velocity(&did("did:dht:z6MkUnknown"), 1000), 0);
    }

    #[test]
    fn snapshot_roundtrip_preserves_velocity() {
        let tracker = SenderVelocityTracker::new(120);
        let alice = did("did:dht:z6MkAlice");
        let bob = did("did:dht:z6MkBob");

        tracker.record_message(&alice, 500);
        tracker.record_message(&alice, 510);
        tracker.record_message(&alice, 520);
        tracker.record_message(&bob, 505);
        tracker.record_message(&bob, 515);

        // Original velocities at t=520.
        let alice_vel = tracker.get_velocity(&alice, 520);
        let bob_vel = tracker.get_velocity(&bob, 520);

        // Snapshot → restore.
        let entries = tracker.snapshot_entries();
        let restored = SenderVelocityTracker::from_snapshot(120, entries);

        // Velocities should match.
        assert_eq!(restored.get_velocity(&alice, 520), alice_vel);
        assert_eq!(restored.get_velocity(&bob, 520), bob_vel);
        assert_eq!(restored.window_secs(), tracker.window_secs());
    }

    /// Test A: a legacy snapshot captured under the old 3600-second window
    /// is restored into a new 60-second tracker (spec §19.4 normalization).
    /// Entries whose timestamps are within the new 60s window relative to
    /// `now` continue to count toward velocity; entries outside the 60s
    /// window are pruned on the next query.
    #[test]
    fn from_snapshot_normalizes_legacy_window_to_60_seconds() {
        // Legacy tracker used a 3600-second window.
        let legacy = SenderVelocityTracker::new(3600);
        let alice = did("did:dht:z6MkAlice");

        // Record two messages: one recent (within new 60s window), one old
        // (inside the legacy 3600s window but outside the new 60s window).
        legacy.record_message(&alice, 600); // t=600, old relative to t=1000
        legacy.record_message(&alice, 990); // t=990, within last 60s at t=1000

        // Under the legacy window both messages count.
        assert_eq!(legacy.get_velocity(&alice, 1000), 2);

        // Snapshot and restore into the new 60-second window.
        let entries = legacy.snapshot_entries();
        let restored = SenderVelocityTracker::from_snapshot(60, entries);
        assert_eq!(restored.window_secs(), 60);

        // Under the normalized 60s window only the recent message counts;
        // the stale one is pruned on access.
        assert_eq!(restored.get_velocity(&alice, 1000), 1);
    }

    // --- Rollback (F5: token-based) ---

    #[test]
    fn rollback_token_reduces_velocity_by_one() {
        let tracker = SenderVelocityTracker::new(60);
        let sender = did("did:dht:z6MkAlice");

        let _t1 = tracker.record_message(&sender, 1000);
        let _t2 = tracker.record_message(&sender, 1001);
        let t3 = tracker.record_message(&sender, 1002);
        assert_eq!(tracker.get_velocity(&sender, 1005), 3);

        assert!(tracker.rollback(&sender, t3));
        assert_eq!(tracker.get_velocity(&sender, 1005), 2);
    }

    #[test]
    fn rollback_on_unknown_did_is_safe_false() {
        let tracker = SenderVelocityTracker::new(60);
        let unknown = did("did:dht:z6MkUnknown");

        // Mint a token for some OTHER sender so we have one to pass —
        // the value does not need to match any entry on `unknown`.
        let sender = did("did:dht:z6MkAlice");
        let tok = tracker.record_message(&sender, 1000);

        assert!(!tracker.rollback(&unknown, tok));
        assert_eq!(tracker.get_velocity(&unknown, 1000), 0);
    }

    #[test]
    fn rollback_after_pruning_is_safe_false() {
        let tracker = SenderVelocityTracker::new(10);
        let sender = did("did:dht:z6MkAlice");

        let tok = tracker.record_message(&sender, 100);
        // Prune by querying well past the window.
        assert_eq!(tracker.get_velocity(&sender, 200), 0);

        // Rollback on a known sender with the now-pruned entry must
        // return false (not panic, not remove some other entry).
        assert!(!tracker.rollback(&sender, tok));
        assert_eq!(tracker.get_velocity(&sender, 200), 0);
    }

    /// F5: interleaved senders must not race. Rollback of alice's
    /// first token must NOT pop the most-recent entry (which belongs
    /// to a different sender's timeline under concurrent interleaving).
    #[test]
    fn rollback_token_removes_correct_entry_under_interleaving() {
        let tracker = SenderVelocityTracker::new(60);
        let alice = did("did:dht:z6MkAlice");
        let bob = did("did:dht:z6MkBob");

        let t_alice_1 = tracker.record_message(&alice, 1000);
        let _t_bob_1 = tracker.record_message(&bob, 1001);
        let t_alice_2 = tracker.record_message(&alice, 1002);

        assert_eq!(tracker.get_velocity(&alice, 1005), 2);
        assert_eq!(tracker.get_velocity(&bob, 1005), 1);

        // Roll back alice's FIRST entry — t_alice_1 — and confirm that
        // alice still has t_alice_2 and bob is untouched.
        assert!(tracker.rollback(&alice, t_alice_1));
        assert_eq!(tracker.get_velocity(&alice, 1005), 1);
        assert_eq!(tracker.get_velocity(&bob, 1005), 1);

        // The remaining alice entry is t_alice_2; rolling it back
        // leaves alice empty.
        assert!(tracker.rollback(&alice, t_alice_2));
        assert_eq!(tracker.get_velocity(&alice, 1005), 0);
        assert_eq!(tracker.get_velocity(&bob, 1005), 1);
    }

    /// F5: rollback must target the OLDEST entry even after later
    /// `record_message` calls reorder memory. Verifies identity-based
    /// rollback rather than LIFO semantics.
    #[test]
    fn rollback_targets_specific_token_even_after_interleaved_record() {
        let tracker = SenderVelocityTracker::new(60);
        let alice = did("did:dht:z6MkAlice");
        let t1 = tracker.record_message(&alice, 1000);
        let _t2 = tracker.record_message(&alice, 1001);
        let _t3 = tracker.record_message(&alice, 1002);

        // Roll back the OLDEST entry rather than the newest.
        assert!(tracker.rollback(&alice, t1));
        assert_eq!(tracker.get_velocity(&alice, 1005), 2);

        let snap = tracker.snapshot_entries();
        let ts = snap.get(alice.as_ref()).unwrap();
        assert!(!ts.contains(&1000));
        assert!(ts.contains(&1001));
        assert!(ts.contains(&1002));
    }

    // --- F8: prune-on-record + hard cap ---

    /// Without F8, a free context that never calls `get_velocity`
    /// grows the velocity Vec unbounded.
    #[test]
    fn free_context_record_message_prunes_expired_entries() {
        let tracker = SenderVelocityTracker::new(10);
        let alice = did("did:dht:z6MkAlice");
        for t in 0..50u64 {
            tracker.record_message(&alice, t);
        }
        for t in 1_000..1_010u64 {
            tracker.record_message(&alice, t);
        }
        let snap = tracker.snapshot_entries();
        let ts = snap.get(alice.as_ref()).unwrap();
        // Without prune-on-append the Vec would be 60+. With the fix
        // only the last 10 entries (within the 10s window of t=1009) survive.
        assert!(
            ts.len() <= 10,
            "expected prune on append, got len={}",
            ts.len()
        );
    }

    #[test]
    fn velocity_tracker_hard_cap_enforced() {
        // Window = huge so nothing is ever pruned by the window check.
        let tracker = SenderVelocityTracker::new(u64::MAX);
        let alice = did("did:dht:z6MkAlice");
        for t in 0..(MAX_VELOCITY_ENTRIES_PER_SENDER as u64 + 500) {
            tracker.record_message(&alice, t);
        }
        let snap = tracker.snapshot_entries();
        assert_eq!(
            snap.get(alice.as_ref()).unwrap().len(),
            MAX_VELOCITY_ENTRIES_PER_SENDER
        );
    }

    // --- F6: snapshot validation ---

    #[test]
    fn validate_velocity_snapshot_rejects_future_timestamp_beyond_skew() {
        let mut entries = HashMap::new();
        entries.insert("did:dht:z6MkAlice".to_owned(), vec![10_000]);
        // Snapshot claims ts=10_000 but now=100 — far future.
        let err = SenderVelocityTracker::validate_and_sanitize_snapshot(
            &mut entries,
            60,
            100,
            SNAPSHOT_CLOCK_SKEW_TOLERANCE_SECS,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SnapshotValidationError::VelocityFutureTimestamp { .. }
        ));
    }

    #[test]
    fn validate_velocity_snapshot_clamps_stale_entries() {
        let mut entries = HashMap::new();
        // Two stale entries + one fresh entry.
        entries.insert("did:dht:z6MkAlice".to_owned(), vec![1, 2, 950, 990, 999]);
        SenderVelocityTracker::validate_and_sanitize_snapshot(
            &mut entries,
            60, // window_secs
            1000,
            SNAPSHOT_CLOCK_SKEW_TOLERANCE_SECS,
        )
        .unwrap();
        // Stale entries (1, 2) dropped; 950+ survive because window floor =
        // 1000 - 60 - 5 = 935.
        let ts = entries.get("did:dht:z6MkAlice").unwrap();
        assert_eq!(ts, &vec![950, 990, 999]);
    }

    #[test]
    fn validate_velocity_snapshot_rejects_oversized_entry_count() {
        let mut entries = HashMap::new();
        let huge: Vec<u64> = (0..=(MAX_VELOCITY_ENTRIES_PER_SENDER as u64)).collect();
        entries.insert("did:dht:z6MkAlice".to_owned(), huge);
        let err = SenderVelocityTracker::validate_and_sanitize_snapshot(
            &mut entries,
            u64::MAX, // window so nothing clamp-drops by staleness
            MAX_VELOCITY_ENTRIES_PER_SENDER as u64 + 10,
            SNAPSHOT_CLOCK_SKEW_TOLERANCE_SECS,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SnapshotValidationError::VelocityEntryCountExceeded { .. }
        ));
    }

    #[test]
    fn validate_hard_rate_limit_snapshot_clamps_tokens_over_burst() {
        let cfg = HardRateLimitConfig {
            burst: 10,
            refill_per_kilosec: 200,
        };
        let mut entries = HashMap::new();
        entries.insert("did:dht:z6MkAlice".to_owned(), (99_999, 100));
        TokenBucketLimiter::validate_and_sanitize_snapshot(
            &mut entries,
            &cfg,
            100,
            SNAPSHOT_CLOCK_SKEW_TOLERANCE_SECS,
        )
        .unwrap();
        // Clamped to burst_milli = 10 * 1000.
        assert_eq!(entries.get("did:dht:z6MkAlice").unwrap().0, 10_000);
    }

    #[test]
    fn validate_hard_rate_limit_snapshot_clamps_future_last_refill() {
        let cfg = HardRateLimitConfig::matrix_defaults();
        let mut entries = HashMap::new();
        entries.insert("did:dht:z6MkAlice".to_owned(), (5_000, 10_000));
        TokenBucketLimiter::validate_and_sanitize_snapshot(
            &mut entries,
            &cfg,
            100,
            SNAPSHOT_CLOCK_SKEW_TOLERANCE_SECS,
        )
        .unwrap();
        // last_refill clamped to `now` because 10_000 > 100 + 5 skew.
        assert_eq!(entries.get("did:dht:z6MkAlice").unwrap().1, 100);
    }

    #[test]
    fn hard_rate_limit_config_validate_rejects_zero_burst() {
        let cfg = HardRateLimitConfig {
            burst: 0,
            refill_per_kilosec: 200,
        };
        assert!(matches!(
            cfg.validate(),
            Err(SnapshotValidationError::InvalidBurst)
        ));
    }

    #[test]
    fn hard_rate_limit_config_validate_rejects_zero_refill() {
        let cfg = HardRateLimitConfig {
            burst: 10,
            refill_per_kilosec: 0,
        };
        assert!(matches!(
            cfg.validate(),
            Err(SnapshotValidationError::InvalidRefillRate { rate: 0 })
        ));
    }

    #[test]
    fn hard_rate_limit_config_validate_rejects_huge_refill() {
        let cfg = HardRateLimitConfig {
            burst: 10,
            refill_per_kilosec: HardRateLimitConfig::MAX_REFILL_PER_KILOSEC + 1,
        };
        assert!(matches!(
            cfg.validate(),
            Err(SnapshotValidationError::InvalidRefillRate { .. })
        ));
    }

    #[test]
    fn pricing_config_validate_rejects_floor_above_cap() {
        let mut cfg = ContextMessagePricingConfig::spec_default();
        cfg.floor = Some(Amount(100));
        cfg.cap = Some(Amount(10));
        assert!(matches!(
            cfg.validate(),
            Err(SnapshotValidationError::PricingFloorExceedsCap { .. })
        ));
    }

    // --- F7: clock-backwards safety ---

    /// Regression test for the bug where `try_consume` wrote
    /// `entry.1 = now_secs` unconditionally, allowing a backwards clock
    /// to stall future refills and corrupt state.
    #[test]
    fn token_bucket_clock_backwards_does_not_corrupt_state() {
        let limiter = TokenBucketLimiter::new(HardRateLimitConfig {
            burst: 1,
            refill_per_kilosec: 0,
        });
        let alice = did("did:dht:z6MkAlice");

        // Prime at t=100. Burst = 1 → one success then empty.
        assert!(limiter.try_consume(&alice, 100));

        // Clock jumps backward to t=50. With the fix `last_refill`
        // must NOT regress.
        assert!(!limiter.try_consume(&alice, 50));

        let snap = limiter.snapshot_entries();
        let (_tokens, last) = *snap.get(alice.as_ref()).unwrap();
        assert!(last >= 100, "last_refill regressed to {last}");

        // Subsequent calls at the previously-highest timestamp must
        // continue to reject (no spurious refund).
        assert!(!limiter.try_consume(&alice, 100));
    }

    // --- HardRateLimitConfig / TokenBucketLimiter ---

    #[test]
    fn matrix_defaults_match_synapse_rc_message() {
        let cfg = HardRateLimitConfig::matrix_defaults();
        assert_eq!(cfg.refill_per_kilosec, 200);
        assert_eq!(cfg.burst, 10);
    }

    #[test]
    fn token_bucket_consumes_burst_tokens_then_rejects() {
        let limiter = TokenBucketLimiter::new(HardRateLimitConfig::matrix_defaults());
        let sender = did("did:dht:z6MkBurst");
        for _ in 0..10 {
            assert!(limiter.try_consume(&sender, 1000));
        }
        assert!(!limiter.try_consume(&sender, 1000));
    }

    #[test]
    fn token_bucket_refills_over_time() {
        let limiter = TokenBucketLimiter::new(HardRateLimitConfig::matrix_defaults());
        let sender = did("did:dht:z6MkRefill");
        for _ in 0..10 {
            assert!(limiter.try_consume(&sender, 1000));
        }
        assert!(!limiter.try_consume(&sender, 1000));
        // 5 seconds of refill: 5 * 200 = 1000 milli-tokens = 1 full token.
        assert!(limiter.try_consume(&sender, 1005));
        assert!(!limiter.try_consume(&sender, 1005));
    }

    #[test]
    fn token_bucket_refund_returns_a_token() {
        let limiter = TokenBucketLimiter::new(HardRateLimitConfig::matrix_defaults());
        let sender = did("did:dht:z6MkRefund");
        for _ in 0..10 {
            assert!(limiter.try_consume(&sender, 1000));
        }
        assert!(!limiter.try_consume(&sender, 1000));
        limiter.refund(&sender);
        assert!(limiter.try_consume(&sender, 1000));
        assert!(!limiter.try_consume(&sender, 1000));
    }

    #[test]
    fn token_bucket_refund_clamps_at_burst() {
        let limiter = TokenBucketLimiter::new(HardRateLimitConfig::matrix_defaults());
        let sender = did("did:dht:z6MkClamp");
        // Bucket starts at burst (10). Refund without consuming should be a no-op.
        for _ in 0..20 {
            limiter.refund(&sender);
        }
        // Cannot exceed burst.
        for _ in 0..10 {
            assert!(limiter.try_consume(&sender, 1000));
        }
        assert!(!limiter.try_consume(&sender, 1000));
    }

    #[test]
    fn token_bucket_snapshot_roundtrip() {
        let limiter = TokenBucketLimiter::new(HardRateLimitConfig::matrix_defaults());
        let alice = did("did:dht:z6MkAlice");
        let bob = did("did:dht:z6MkBob");
        for _ in 0..3 {
            limiter.try_consume(&alice, 1000);
        }
        for _ in 0..7 {
            limiter.try_consume(&bob, 1000);
        }
        let snap = limiter.snapshot_entries();
        let restored =
            TokenBucketLimiter::from_snapshot(HardRateLimitConfig::matrix_defaults(), snap);
        // Alice has 7 tokens left → 7 successes; Bob has 3.
        for _ in 0..7 {
            assert!(restored.try_consume(&alice, 1000));
        }
        assert!(!restored.try_consume(&alice, 1000));
        for _ in 0..3 {
            assert!(restored.try_consume(&bob, 1000));
        }
        assert!(!restored.try_consume(&bob, 1000));
    }

    // --- ContextMessagePricingConfig ---

    #[test]
    fn context_message_pricing_spec_default_values() {
        let cfg = ContextMessagePricingConfig::spec_default();
        assert_eq!(cfg.base_cost, Amount(1));
        assert_eq!(cfg.floor, Some(Amount(1)));
        assert_eq!(cfg.cap, Some(Amount(1000)));
        assert_eq!(cfg.escalation.thresholds.len(), 3);
        assert_eq!(cfg.escalation.thresholds[0].velocity_threshold, 10);
        assert_eq!(cfg.escalation.thresholds[0].additional_cost, Amount(1));
        assert_eq!(cfg.escalation.thresholds[1].velocity_threshold, 50);
        assert_eq!(cfg.escalation.thresholds[1].additional_cost, Amount(10));
        assert_eq!(cfg.escalation.thresholds[2].velocity_threshold, 200);
        assert_eq!(cfg.escalation.thresholds[2].additional_cost, Amount(100));
        assert_eq!(cfg.hard_rate_limit, HardRateLimitConfig::matrix_defaults());
    }

    #[test]
    fn context_message_pricing_serde_roundtrip() {
        let cfg = ContextMessagePricingConfig::spec_default();
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: ContextMessagePricingConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, cfg);
    }
}
