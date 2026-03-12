//! Per-relay reliability scoring and multi-relay suppression cross-check.
//!
//! Relays are untrusted (spec section 9.9.1). A relay that drops messages,
//! delays delivery, or retains data after deletion requests should be
//! deprioritized. This module provides:
//!
//! - [`ReliabilityScore`] -- per-relay delivery success rate, latency, and
//!   deletion compliance tracked with exponential moving average (EMA) decay.
//! - [`DeliveryOutcome`] -- the result of a single relay operation.
//! - [`update_score`] -- updates a relay's score after each operation.
//! - [`get_score`] -- retrieves the current score for a relay.
//! - [`SuppressionTracker`] -- multi-relay cross-check for suppression
//!   detection (spec section 9.9.2).
//!
//! See ADR-012 in `.docs/adrs/phase-2.md` for the full scoring design.

use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
use std::time::Duration;

use lru::LruCache;

use crate::traits::BlobId;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// EMA smoothing factor (alpha). Controls how quickly recent observations
/// dominate historical ones. Alpha = 0.3 means 30% weight on the newest
/// observation and 70% on the existing average.
const EMA_ALPHA: f64 = 0.3;

/// Success rate threshold below which a relay is flagged for replacement.
const REPLACEMENT_THRESHOLD: f64 = 0.5;

/// Deletion compliance threshold below which a relay is deprioritized for
/// ephemeral contexts (spec section 5.11).
const DELETION_COMPLIANCE_THRESHOLD: f64 = 0.5;

/// Default suppression cross-check window.
const DEFAULT_SUPPRESSION_WINDOW: Duration = Duration::from_secs(30);

/// Maximum number of blobs tracked by `SuppressionTracker` (LRU eviction).
const DEFAULT_SUPPRESSION_CAPACITY: usize = 10_000;

// ---------------------------------------------------------------------------
// ReliabilityScore
// ---------------------------------------------------------------------------

/// Per-relay reliability score.
///
/// Tracks delivery success rates, latency, and deletion compliance for each
/// relay using exponential moving average (EMA) decay so that recent behavior
/// weighs more than historical performance.
///
/// See ADR-012 acceptance criterion 5 for the full scoring design.
#[derive(Debug, Clone)]
pub struct ReliabilityScore {
    /// The relay URL this score tracks.
    pub relay_url: String,
    /// Delivery success rate (0.0 to 1.0), updated via EMA.
    pub delivery_success_rate: f64,
    /// Average latency in milliseconds, updated via EMA.
    pub average_latency_ms: u64,
    /// Deletion compliance rate (0.0 to 1.0), updated via EMA.
    pub deletion_compliance_rate: f64,
    /// Epoch seconds when this score was last updated.
    pub last_updated: u64,
    /// Total number of send attempts.
    pub total_sends: u64,
    /// Total number of send failures.
    pub total_failures: u64,
}

impl ReliabilityScore {
    /// Creates a new `ReliabilityScore` for a relay with perfect initial
    /// scores (benefit of the doubt).
    #[must_use]
    pub const fn new(relay_url: String) -> Self {
        Self {
            relay_url,
            delivery_success_rate: 1.0,
            deletion_compliance_rate: 1.0,
            average_latency_ms: 0,
            last_updated: 0,
            total_sends: 0,
            total_failures: 0,
        }
    }

    /// Returns whether this relay should be flagged for replacement.
    ///
    /// A relay is flagged when its delivery success rate drops below 0.5.
    #[must_use]
    pub fn is_flagged_for_replacement(&self) -> bool {
        self.delivery_success_rate < REPLACEMENT_THRESHOLD
    }

    /// Returns whether this relay should be deprioritized for ephemeral
    /// contexts.
    ///
    /// A relay is deprioritized when its deletion compliance rate drops
    /// below 0.5 (spec section 5.11).
    #[must_use]
    pub fn is_deprioritized_for_ephemeral(&self) -> bool {
        self.deletion_compliance_rate < DELETION_COMPLIANCE_THRESHOLD
    }

    /// Returns the composite score used for relay ranking.
    ///
    /// Higher is better. Combines delivery success rate as the primary
    /// factor.
    #[must_use]
    pub const fn composite_score(&self) -> f64 {
        self.delivery_success_rate
    }
}

// ---------------------------------------------------------------------------
// DeliveryOutcome
// ---------------------------------------------------------------------------

/// The result of a single relay operation, used to update reliability scores.
#[derive(Debug, Clone, Copy)]
pub enum DeliveryOutcome {
    /// The relay successfully delivered/accepted the envelope.
    Success {
        /// Latency of the operation in milliseconds.
        latency_ms: u64,
    },
    /// The relay failed to deliver/accept the envelope.
    Failure,
    /// The relay complied with a deletion request.
    DeletionSuccess,
    /// The relay did not comply with a deletion request.
    DeletionFailure,
}

// ---------------------------------------------------------------------------
// update_score / get_score
// ---------------------------------------------------------------------------

/// Updates a relay's reliability score after an operation.
///
/// Uses exponential moving average (EMA) decay so that recent behavior weighs
/// more than historical. The EMA formula is:
///
/// ```text
/// new_value = alpha * observation + (1 - alpha) * old_value
/// ```
///
/// where `alpha = 0.3`.
///
/// # Arguments
///
/// * `scores` -- the map of relay URL to `ReliabilityScore`.
/// * `relay_url` -- the relay whose score should be updated.
/// * `outcome` -- the delivery outcome to record.
pub fn update_score<S: ::std::hash::BuildHasher>(
    scores: &mut HashMap<String, ReliabilityScore, S>,
    relay_url: &str,
    outcome: DeliveryOutcome,
) {
    let score = scores
        .entry(relay_url.to_owned())
        .or_insert_with(|| ReliabilityScore::new(relay_url.to_owned()));

    match outcome {
        DeliveryOutcome::Success { latency_ms } => {
            score.total_sends += 1;
            // EMA for delivery success rate: observation = 1.0 (success).
            score.delivery_success_rate =
                EMA_ALPHA.mul_add(1.0, (1.0 - EMA_ALPHA) * score.delivery_success_rate);
            // EMA for latency.
            #[allow(clippy::cast_precision_loss)]
            let new_latency = EMA_ALPHA.mul_add(
                latency_ms as f64,
                (1.0 - EMA_ALPHA) * (score.average_latency_ms as f64),
            );
            // Latency ms and EMA values are small positive numbers.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                score.average_latency_ms = new_latency as u64;
            }
        }
        DeliveryOutcome::Failure => {
            score.total_sends += 1;
            score.total_failures += 1;
            // EMA for delivery success rate: observation = 0.0 (failure).
            score.delivery_success_rate =
                EMA_ALPHA.mul_add(0.0, (1.0 - EMA_ALPHA) * score.delivery_success_rate);
        }
        DeliveryOutcome::DeletionSuccess => {
            // EMA for deletion compliance: observation = 1.0 (complied).
            score.deletion_compliance_rate =
                EMA_ALPHA.mul_add(1.0, (1.0 - EMA_ALPHA) * score.deletion_compliance_rate);
        }
        DeliveryOutcome::DeletionFailure => {
            // EMA for deletion compliance: observation = 0.0 (refused).
            score.deletion_compliance_rate =
                EMA_ALPHA.mul_add(0.0, (1.0 - EMA_ALPHA) * score.deletion_compliance_rate);
        }
    }
}

/// Returns the current reliability score for a relay, if it exists.
#[must_use]
pub fn get_score<'a, S: ::std::hash::BuildHasher>(
    scores: &'a HashMap<String, ReliabilityScore, S>,
    relay_url: &str,
) -> Option<&'a ReliabilityScore> {
    scores.get(relay_url)
}

// ---------------------------------------------------------------------------
// SuppressionTracker
// ---------------------------------------------------------------------------

/// Tracks which adapters have delivered each blob within a cross-check window.
///
/// When the merged subscription stream receives an envelope from one relay but
/// not from another within 30 seconds, the lagging relay is marked as
/// potentially adversarial. Blobs delivered by fewer than half the context's
/// relays trigger a suppression warning.
///
/// Uses LRU eviction to bound memory usage to at most
/// `DEFAULT_SUPPRESSION_CAPACITY` (10,000) entries. When the tracker is full,
/// the least-recently-used blob entry is evicted.
///
/// See ADR-012 acceptance criterion 7 (spec section 9.9.2).
pub struct SuppressionTracker {
    /// Per-blob delivery tracking: blob -> (`first_seen_ms`, set of adapter
    /// indices that delivered it). LRU-bounded.
    entries: LruCache<BlobId, (u64, HashSet<usize>)>,
    /// The suppression cross-check window duration.
    window: Duration,
}

/// A suppression warning emitted when a blob was delivered by fewer than
/// half the context's relays within the cross-check window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuppressionWarning {
    /// The blob that triggered the warning.
    pub blob_id: BlobId,
    /// Adapter indices that delivered the blob.
    pub delivered_by: HashSet<usize>,
    /// Total number of relays in the context's relay set.
    pub total_relays: usize,
}

impl SuppressionTracker {
    /// Creates a new `SuppressionTracker` with the default 30-second window
    /// and 10,000 entry LRU capacity.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: LruCache::new(
                NonZeroUsize::new(DEFAULT_SUPPRESSION_CAPACITY).unwrap_or(NonZeroUsize::MIN),
            ),
            window: DEFAULT_SUPPRESSION_WINDOW,
        }
    }

    /// Creates a new `SuppressionTracker` with a custom window duration
    /// and the default 10,000 entry LRU capacity.
    #[must_use]
    pub fn with_window(window: Duration) -> Self {
        Self {
            entries: LruCache::new(
                NonZeroUsize::new(DEFAULT_SUPPRESSION_CAPACITY).unwrap_or(NonZeroUsize::MIN),
            ),
            window,
        }
    }

    /// Returns the LRU capacity of this tracker.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.entries.cap().get()
    }

    /// Returns the number of blobs currently tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the tracker has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Records that an adapter delivered a blob.
    ///
    /// If the tracker is at capacity, the least-recently-used entry is evicted.
    ///
    /// # Arguments
    ///
    /// * `blob_id` -- the blob that was delivered.
    /// * `adapter_index` -- the adapter that delivered it.
    /// * `now_ms` -- the current time in epoch milliseconds.
    pub fn record_delivery(&mut self, blob_id: BlobId, adapter_index: usize, now_ms: u64) {
        if let Some((first_seen, adapters)) = self.entries.get_mut(&blob_id) {
            // Entry exists: just add the adapter (first_seen stays unchanged).
            let _ = *first_seen; // keep original first_seen
            adapters.insert(adapter_index);
        } else {
            let mut adapters = HashSet::new();
            adapters.insert(adapter_index);
            self.entries.put(blob_id, (now_ms, adapters));
        }
    }

    /// Checks all tracked blobs for suppression and returns warnings for any
    /// blob delivered by fewer than half the context's relays after the
    /// cross-check window has elapsed.
    ///
    /// Expired entries (past the window) are removed from the tracker.
    ///
    /// # Arguments
    ///
    /// * `now_ms` -- the current time in epoch milliseconds.
    /// * `total_relays` -- the total number of relays in the context's relay
    ///   set.
    pub fn check_suppressions(
        &mut self,
        now_ms: u64,
        total_relays: usize,
    ) -> Vec<SuppressionWarning> {
        // Duration::as_millis() returns u128 but our window durations are
        // always small (seconds). Truncation is safe here.
        #[allow(clippy::cast_possible_truncation)]
        let window_ms = self.window.as_millis() as u64;
        let mut warnings = Vec::new();
        let mut expired_blobs = Vec::new();

        // Iterate over all entries without promoting (peek).
        for (&blob_id, (first_seen_ms, adapters)) in &self.entries {
            let elapsed = now_ms.saturating_sub(*first_seen_ms);
            if elapsed >= window_ms {
                // Window has elapsed; check delivery count.
                let threshold = total_relays.div_ceil(2); // ceil(total_relays / 2)
                if adapters.len() < threshold {
                    warnings.push(SuppressionWarning {
                        blob_id,
                        delivered_by: adapters.clone(),
                        total_relays,
                    });
                }
                expired_blobs.push(blob_id);
            }
        }

        // Clean up expired entries.
        for blob_id in &expired_blobs {
            self.entries.pop(blob_id);
        }

        warnings
    }
}

impl Default for SuppressionTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------
    // EMA scoring tests
    // -------------------------------------------------------------------

    #[test]
    fn update_score_success_applies_ema_to_delivery_rate() {
        let mut scores = HashMap::new();
        let relay = "wss://relay.example.com/scp/v1";

        // First success: EMA(1.0, 1.0) = 0.3 * 1.0 + 0.7 * 1.0 = 1.0
        update_score(
            &mut scores,
            relay,
            DeliveryOutcome::Success { latency_ms: 50 },
        );
        let s = get_score(&scores, relay).unwrap();
        assert!((s.delivery_success_rate - 1.0).abs() < f64::EPSILON);
        assert_eq!(s.total_sends, 1);
        assert_eq!(s.total_failures, 0);

        // Failure: EMA(0.0, 1.0) = 0.3 * 0.0 + 0.7 * 1.0 = 0.7
        update_score(&mut scores, relay, DeliveryOutcome::Failure);
        let s = get_score(&scores, relay).unwrap();
        assert!((s.delivery_success_rate - 0.7).abs() < 1e-10);
        assert_eq!(s.total_sends, 2);
        assert_eq!(s.total_failures, 1);

        // Another failure: EMA(0.0, 0.7) = 0.3 * 0.0 + 0.7 * 0.7 = 0.49
        update_score(&mut scores, relay, DeliveryOutcome::Failure);
        let s = get_score(&scores, relay).unwrap();
        assert!((s.delivery_success_rate - 0.49).abs() < 1e-10);
        assert_eq!(s.total_sends, 3);
        assert_eq!(s.total_failures, 2);
    }

    #[test]
    fn update_score_ema_latency_smoothing() {
        let mut scores = HashMap::new();
        let relay = "wss://relay.example.com/scp/v1";

        // First: latency 100ms. EMA(100, 0) = 0.3 * 100 + 0.7 * 0 = 30
        update_score(
            &mut scores,
            relay,
            DeliveryOutcome::Success { latency_ms: 100 },
        );
        let s = get_score(&scores, relay).unwrap();
        assert_eq!(s.average_latency_ms, 30);

        // Second: latency 200ms. EMA(200, 30) = 0.3 * 200 + 0.7 * 30 = 81
        update_score(
            &mut scores,
            relay,
            DeliveryOutcome::Success { latency_ms: 200 },
        );
        let s = get_score(&scores, relay).unwrap();
        assert_eq!(s.average_latency_ms, 81);
    }

    #[test]
    fn update_score_deletion_compliance_ema() {
        let mut scores = HashMap::new();
        let relay = "wss://relay.example.com/scp/v1";

        // Start at 1.0. Deletion failure: EMA(0.0, 1.0) = 0.7
        update_score(&mut scores, relay, DeliveryOutcome::DeletionFailure);
        let s = get_score(&scores, relay).unwrap();
        assert!((s.deletion_compliance_rate - 0.7).abs() < 1e-10);

        // Deletion success: EMA(1.0, 0.7) = 0.3 + 0.49 = 0.79
        update_score(&mut scores, relay, DeliveryOutcome::DeletionSuccess);
        let s = get_score(&scores, relay).unwrap();
        assert!((s.deletion_compliance_rate - 0.79).abs() < 1e-10);
    }

    #[test]
    fn relay_below_half_success_rate_flagged_for_replacement() {
        let mut scores = HashMap::new();
        let relay = "wss://bad-relay.example.com/scp/v1";

        // Drive the success rate below 0.5 with repeated failures.
        // Start at 1.0. After each failure: new = 0.7 * old.
        // 1.0 -> 0.7 -> 0.49 -> below 0.5.
        update_score(&mut scores, relay, DeliveryOutcome::Failure);
        update_score(&mut scores, relay, DeliveryOutcome::Failure);
        update_score(&mut scores, relay, DeliveryOutcome::Failure);

        let s = get_score(&scores, relay).unwrap();
        assert!(s.is_flagged_for_replacement());
    }

    #[test]
    fn relay_above_half_success_rate_not_flagged() {
        let mut scores = HashMap::new();
        let relay = "wss://ok-relay.example.com/scp/v1";

        update_score(
            &mut scores,
            relay,
            DeliveryOutcome::Success { latency_ms: 10 },
        );
        update_score(&mut scores, relay, DeliveryOutcome::Failure);

        let s = get_score(&scores, relay).unwrap();
        // After success: 1.0. After failure: 0.7 * 1.0 = 0.7 >= 0.5.
        assert!(!s.is_flagged_for_replacement());
    }

    #[test]
    fn relay_below_half_deletion_compliance_deprioritized_for_ephemeral() {
        let mut scores = HashMap::new();
        let relay = "wss://noncompliant.example.com/scp/v1";

        // Drive deletion compliance below 0.5.
        // 1.0 -> 0.7 -> 0.49.
        update_score(&mut scores, relay, DeliveryOutcome::DeletionFailure);
        update_score(&mut scores, relay, DeliveryOutcome::DeletionFailure);
        update_score(&mut scores, relay, DeliveryOutcome::DeletionFailure);

        let s = get_score(&scores, relay).unwrap();
        assert!(s.is_deprioritized_for_ephemeral());
    }

    #[test]
    fn get_score_returns_none_for_unknown_relay() {
        let scores = HashMap::new();
        assert!(get_score(&scores, "wss://unknown.example.com/scp/v1").is_none());
    }

    // -------------------------------------------------------------------
    // Suppression cross-check tests
    // -------------------------------------------------------------------

    #[test]
    fn cross_check_detects_suppression_when_relay_fails_to_deliver() {
        let mut tracker = SuppressionTracker::with_window(Duration::from_secs(30));
        let blob = BlobId::new([0x01; 32]);

        // 4 relays in the context. Only adapter 0 delivers.
        tracker.record_delivery(blob, 0, 1000);

        // After 30 seconds, check: 1 out of 4 < ceil(4/2) = 2.
        let warnings = tracker.check_suppressions(31_000, 4);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].blob_id, blob);
        assert_eq!(warnings[0].delivered_by.len(), 1);
        assert!(warnings[0].delivered_by.contains(&0));
        assert_eq!(warnings[0].total_relays, 4);
    }

    #[test]
    fn cross_check_no_false_alarm_when_all_relays_deliver() {
        let mut tracker = SuppressionTracker::with_window(Duration::from_secs(30));
        let blob = BlobId::new([0x02; 32]);

        // All 4 relays deliver within the window.
        tracker.record_delivery(blob, 0, 1000);
        tracker.record_delivery(blob, 1, 1500);
        tracker.record_delivery(blob, 2, 2000);
        tracker.record_delivery(blob, 3, 2500);

        // After 30 seconds: 4 out of 4 >= ceil(4/2) = 2.
        let warnings = tracker.check_suppressions(31_000, 4);
        assert!(warnings.is_empty());
    }

    #[test]
    fn cross_check_no_warning_before_window_elapses() {
        let mut tracker = SuppressionTracker::with_window(Duration::from_secs(30));
        let blob = BlobId::new([0x03; 32]);

        // Only one relay delivers.
        tracker.record_delivery(blob, 0, 1000);

        // Check before window elapses (at 20 seconds).
        let warnings = tracker.check_suppressions(21_000, 4);
        assert!(warnings.is_empty());
    }

    #[test]
    fn cross_check_cleans_up_expired_entries() {
        let mut tracker = SuppressionTracker::with_window(Duration::from_secs(30));
        let blob = BlobId::new([0x04; 32]);

        tracker.record_delivery(blob, 0, 1000);
        tracker.record_delivery(blob, 1, 1500);

        // Trigger check after window. This should clean up the entry.
        let _ = tracker.check_suppressions(31_000, 4);

        // Subsequent check should be empty since entries were cleaned up.
        let warnings = tracker.check_suppressions(62_000, 4);
        assert!(warnings.is_empty());
    }

    #[test]
    fn cross_check_exactly_half_relays_deliver_no_warning() {
        let mut tracker = SuppressionTracker::with_window(Duration::from_secs(30));
        let blob = BlobId::new([0x05; 32]);

        // 4 relays, 2 deliver. ceil(4/2) = 2, so 2 >= 2 means no warning.
        tracker.record_delivery(blob, 0, 1000);
        tracker.record_delivery(blob, 1, 1500);

        let warnings = tracker.check_suppressions(31_000, 4);
        assert!(warnings.is_empty());
    }

    #[test]
    fn cross_check_odd_relay_count_threshold() {
        let mut tracker = SuppressionTracker::with_window(Duration::from_secs(30));
        let blob = BlobId::new([0x06; 32]);

        // 3 relays. ceil(3/2) = 2. Only 1 delivers => warning.
        tracker.record_delivery(blob, 0, 1000);

        let warnings = tracker.check_suppressions(31_000, 3);
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn cross_check_odd_relay_count_sufficient_deliveries() {
        let mut tracker = SuppressionTracker::with_window(Duration::from_secs(30));
        let blob = BlobId::new([0x07; 32]);

        // 3 relays. ceil(3/2) = 2. Two deliver => no warning.
        tracker.record_delivery(blob, 0, 1000);
        tracker.record_delivery(blob, 2, 1500);

        let warnings = tracker.check_suppressions(31_000, 3);
        assert!(warnings.is_empty());
    }

    #[test]
    fn cross_check_multiple_blobs_tracked_independently() {
        let mut tracker = SuppressionTracker::with_window(Duration::from_secs(30));
        let blob_a = BlobId::new([0x0A; 32]);
        let blob_b = BlobId::new([0x0B; 32]);

        // Blob A: all 3 relays deliver.
        tracker.record_delivery(blob_a, 0, 1000);
        tracker.record_delivery(blob_a, 1, 1500);
        tracker.record_delivery(blob_a, 2, 2000);

        // Blob B: only 1 relay delivers.
        tracker.record_delivery(blob_b, 0, 1000);

        let warnings = tracker.check_suppressions(31_000, 3);
        // Only blob_b should trigger a warning.
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].blob_id, blob_b);
    }

    // -------------------------------------------------------------------
    // LRU eviction tests
    // -------------------------------------------------------------------

    #[test]
    fn suppression_tracker_has_default_capacity() {
        let tracker = SuppressionTracker::new();
        assert_eq!(tracker.capacity(), DEFAULT_SUPPRESSION_CAPACITY);
    }

    #[test]
    fn suppression_tracker_lru_evicts_oldest_entry() {
        // Create a tiny tracker with capacity 3.
        let mut tracker = SuppressionTracker {
            entries: LruCache::new(NonZeroUsize::new(3).unwrap()),
            window: Duration::from_secs(30),
        };

        let blob_a = BlobId::new([0xA0; 32]);
        let blob_b = BlobId::new([0xB0; 32]);
        let blob_c = BlobId::new([0xC0; 32]);
        let blob_d = BlobId::new([0xD0; 32]);

        // Fill to capacity.
        tracker.record_delivery(blob_a, 0, 1000);
        tracker.record_delivery(blob_b, 0, 2000);
        tracker.record_delivery(blob_c, 0, 3000);
        assert_eq!(tracker.len(), 3);

        // Adding a 4th entry should evict blob_a (oldest/LRU).
        tracker.record_delivery(blob_d, 0, 4000);
        assert_eq!(tracker.len(), 3);

        // blob_a should be evicted -- recording for it again creates a new entry.
        tracker.record_delivery(blob_a, 1, 5000);
        // Now blob_b is the LRU and should have been evicted.
        assert_eq!(tracker.len(), 3);

        // Check that blob_d and blob_c are still tracked (no warning for them).
        let warnings = tracker.check_suppressions(35_000, 2);
        // blob_a has adapter 1, blob_c has adapter 0, blob_d has adapter 0.
        // All have 1 adapter out of 2. ceil(2/2) = 1. 1 >= 1 => no warning.
        assert!(warnings.is_empty());
    }

    #[test]
    fn suppression_tracker_len_and_is_empty() {
        let mut tracker = SuppressionTracker::new();
        assert!(tracker.is_empty());
        assert_eq!(tracker.len(), 0);

        tracker.record_delivery(BlobId::new([0x01; 32]), 0, 1000);
        assert!(!tracker.is_empty());
        assert_eq!(tracker.len(), 1);
    }
}
