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

use scp_identity::DID;

use super::types::Amount;

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
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscalationConfig {
    /// Step-function thresholds, ordered by velocity. Each threshold whose
    /// velocity is met contributes its additional cost.
    pub thresholds: Vec<EscalationThreshold>,
}

impl EscalationConfig {
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
    /// Per-sender message timestamps, protected by a mutex.
    /// Key: sender DID, Value: Vec of timestamps (seconds since epoch).
    state: Mutex<HashMap<DID, Vec<u64>>>,
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
        }
    }

    /// Records a message from `sender` at the given `timestamp`.
    ///
    /// The timestamp is in seconds since the Unix epoch. Messages are
    /// appended to the sender's window; pruning happens lazily on
    /// [`get_velocity`](Self::get_velocity) calls.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (indicates a prior panic
    /// while holding the lock — an unrecoverable state).
    pub fn record_message(&self, sender: &DID, timestamp: u64) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.entry(sender.clone()).or_default().push(timestamp);
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

        state.get_mut(sender).map_or(0, |timestamps| {
            timestamps.retain(|&ts| ts > cutoff);
            timestamps.len() as u64
        })
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
}

impl std::fmt::Debug for SenderVelocityTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SenderVelocityTracker")
            .field("window_secs", &self.window_secs)
            .field("state", &"<locked>")
            .finish()
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

        // At t=115, message at 100 is expired (115 - 10 = 105 cutoff, 100 <= 105)
        // Message at 105 is also expired (105 <= 105, using > cutoff)
        assert_eq!(tracker.get_velocity(&sender, 115), 0);
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
        let tracker = SenderVelocityTracker::new(60);
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

        let now = 1000;

        // 0 messages: base cost only
        assert_eq!(
            tracker.compute_escalated_cost(&sender, now, base_cost, &config, None, None),
            Amount(1),
        );

        // Record 10 messages (hits first threshold)
        for i in 0..10 {
            tracker.record_message(&sender, now - 30 + i);
        }
        assert_eq!(
            tracker.compute_escalated_cost(&sender, now, base_cost, &config, None, None),
            Amount(2), // 1 + 1
        );

        // Record 40 more (total 50, hits second threshold)
        for i in 10..50 {
            tracker.record_message(&sender, now - 30 + i);
        }
        assert_eq!(
            tracker.compute_escalated_cost(&sender, now, base_cost, &config, None, None),
            Amount(12), // 1 + 1 + 10
        );

        // Record 150 more (total 200, hits all thresholds)
        for i in 50..200 {
            tracker.record_message(&sender, now - 30 + i);
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
}
