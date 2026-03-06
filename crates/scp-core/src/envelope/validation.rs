//! Timestamp bounds and sequence monotonicity validation for received envelopes.
//!
//! Implements §9.8.2(a) and §9.8.2(c) from the security model spec:
//!
//! - **Timestamp bounds** — reject envelopes with `created_at` more than
//!   `clock_skew_tolerance` in the future or more than `max_message_age` in the
//!   past.
//! - **Sequence monotonicity** — per-sender sequence numbers must be
//!   monotonically increasing. Any regression is a replay.
//!
//! These checks run after MLS decryption and inner signature verification
//! (i.e., after [`super::open_envelope`] succeeds), before delivering the
//! message to the application layer.

use std::collections::HashMap;

use super::EnvelopeError;
use super::inner::InnerEnvelope;

// ---------------------------------------------------------------------------
// Default constants (§9.8.2)
// ---------------------------------------------------------------------------

/// Default clock skew tolerance: 5 minutes in milliseconds.
///
/// Envelopes with timestamps more than this far in the future are rejected.
/// Spec reference: §9.8.2(c).
pub const DEFAULT_CLOCK_SKEW_TOLERANCE_MS: u64 = 5 * 60 * 1_000;

/// Default maximum message age: 7 days in milliseconds.
///
/// Envelopes with timestamps older than this relative to the local clock are
/// rejected. Configurable per context. Spec reference: §9.8.2(c).
pub const DEFAULT_MAX_MESSAGE_AGE_MS: u64 = 7 * 24 * 60 * 60 * 1_000;

// ---------------------------------------------------------------------------
// TimestampValidator
// ---------------------------------------------------------------------------

/// Configuration for timestamp bounds validation (§9.8.2(c)).
///
/// Validates that an envelope's `timestamp` (Unix milliseconds) is:
/// - Not more than `clock_skew_tolerance_ms` in the future.
/// - Not more than `max_message_age_ms` in the past.
///
/// Both values are configurable per context.
#[derive(Debug, Clone)]
pub struct TimestampValidator {
    /// Maximum allowed clock skew into the future (milliseconds).
    pub clock_skew_tolerance_ms: u64,

    /// Maximum allowed message age in the past (milliseconds).
    pub max_message_age_ms: u64,
}

impl Default for TimestampValidator {
    fn default() -> Self {
        Self {
            clock_skew_tolerance_ms: DEFAULT_CLOCK_SKEW_TOLERANCE_MS,
            max_message_age_ms: DEFAULT_MAX_MESSAGE_AGE_MS,
        }
    }
}

impl TimestampValidator {
    /// Creates a new `TimestampValidator` with custom bounds.
    #[must_use]
    pub const fn new(clock_skew_tolerance_ms: u64, max_message_age_ms: u64) -> Self {
        Self {
            clock_skew_tolerance_ms,
            max_message_age_ms,
        }
    }

    /// Validates the timestamp of an inner envelope against the given local
    /// clock reading.
    ///
    /// # Arguments
    ///
    /// * `envelope` — The verified inner envelope to validate.
    /// * `now_ms` — The current local time in Unix milliseconds. Injected
    ///   rather than read from the system clock to enable deterministic testing
    ///   and allow callers to apply their own clock source.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::TimestampInFuture`] if the envelope's
    /// `timestamp` is more than `clock_skew_tolerance_ms` ahead of `now_ms`.
    ///
    /// Returns [`EnvelopeError::TimestampTooOld`] if the envelope's `timestamp`
    /// is more than `max_message_age_ms` behind `now_ms`.
    pub const fn validate(
        &self,
        envelope: &InnerEnvelope,
        now_ms: u64,
    ) -> Result<(), EnvelopeError> {
        let ts = envelope.timestamp;

        // Future bound: reject timestamps too far in the future.
        if ts > now_ms.saturating_add(self.clock_skew_tolerance_ms) {
            return Err(EnvelopeError::TimestampInFuture {
                envelope_timestamp: ts,
                local_time: now_ms,
                tolerance_ms: self.clock_skew_tolerance_ms,
            });
        }

        // Past bound: reject timestamps too far in the past.
        if now_ms.saturating_sub(ts) > self.max_message_age_ms {
            return Err(EnvelopeError::TimestampTooOld {
                envelope_timestamp: ts,
                local_time: now_ms,
                max_age_ms: self.max_message_age_ms,
            });
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SequenceTracker
// ---------------------------------------------------------------------------

/// Composite key for per-sender sequence tracking: `(context_id, sender_did)`.
type SenderKey = (String, String);

/// Tracks per-sender sequence numbers and timestamps to detect replay attacks
/// (§9.8.2, §9.8.5).
///
/// Each sender in each context maintains a monotonically increasing SCP
/// sequence number and monotonically non-decreasing timestamp. Any envelope
/// with a sequence number ≤ the last seen value, or a timestamp strictly less
/// than the last seen timestamp, from the same sender is rejected.
///
/// Per-sender timestamp monotonicity catches time-shifted replays where an
/// attacker bumps the sequence number but uses an older timestamp (§9.8.2(c)).
///
/// This tracker is separate from the MLS generation number check (which is
/// handled by the MLS layer). It provides an additional SCP-level replay
/// defense.
#[derive(Debug, Clone, Default)]
pub struct SequenceTracker {
    /// Maps `(context_id, sender_did)` to `(highest_sequence, last_timestamp)`.
    last_seen: HashMap<SenderKey, (u64, u64)>,
}

impl SequenceTracker {
    /// Creates a new, empty sequence tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Validates the sequence number and timestamp of an inner envelope and,
    /// if valid, updates the tracker state.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::SequenceRegression`] if the envelope's
    /// `sequence` is ≤ the highest previously seen from the same sender, or
    /// [`EnvelopeError::TimestampRegression`] if the timestamp is strictly
    /// less than the last seen timestamp (§9.8.2(c)).
    pub fn validate_and_advance(&mut self, envelope: &InnerEnvelope) -> Result<(), EnvelopeError> {
        let key = (envelope.context_id.clone(), envelope.sender_did.clone());

        if let Some(&(last_seq, last_ts)) = self.last_seen.get(&key) {
            if envelope.sequence <= last_seq {
                return Err(EnvelopeError::SequenceRegression {
                    sender_did: envelope.sender_did.clone(),
                    context_id: envelope.context_id.clone(),
                    received_sequence: envelope.sequence,
                    last_seen_sequence: last_seq,
                });
            }
            if envelope.timestamp < last_ts {
                return Err(EnvelopeError::TimestampRegression {
                    sender_did: envelope.sender_did.clone(),
                    context_id: envelope.context_id.clone(),
                    received_timestamp: envelope.timestamp,
                    last_seen_timestamp: last_ts,
                });
            }
        }

        self.last_seen
            .insert(key, (envelope.sequence, envelope.timestamp));
        Ok(())
    }

    /// Returns the last seen sequence number for a given sender in a context,
    /// or `None` if no messages have been seen from that sender.
    #[must_use]
    pub fn last_seen_sequence(&self, context_id: &str, sender_did: &str) -> Option<u64> {
        self.last_seen
            .get(&(context_id.to_owned(), sender_did.to_owned()))
            .map(|&(seq, _)| seq)
    }

    /// Resets the tracker state for a specific sender in a context.
    ///
    /// This is intended for use during MLS epoch transitions where sequence
    /// number state may need to be reset.
    pub fn reset_sender(&mut self, context_id: &str, sender_did: &str) {
        self.last_seen
            .remove(&(context_id.to_owned(), sender_did.to_owned()));
    }

    /// Clears all tracked state.
    pub fn clear(&mut self) {
        self.last_seen.clear();
    }
}

// ---------------------------------------------------------------------------
// Convenience: combined validation
// ---------------------------------------------------------------------------

/// Validates both timestamp bounds and sequence monotonicity for a received
/// inner envelope.
///
/// This is the primary entry point for receive-path validation. Call after
/// [`super::open_envelope`] succeeds and before delivering to the application
/// layer.
///
/// # Arguments
///
/// * `envelope` — The verified inner envelope.
/// * `now_ms` — Current local time in Unix milliseconds.
/// * `timestamp_validator` — Timestamp bounds configuration.
/// * `sequence_tracker` — Mutable sequence tracking state.
///
/// # Errors
///
/// Returns the first validation error encountered (timestamp checked before
/// sequence).
pub fn validate_received_envelope(
    envelope: &InnerEnvelope,
    now_ms: u64,
    timestamp_validator: &TimestampValidator,
    sequence_tracker: &mut SequenceTracker,
) -> Result<(), EnvelopeError> {
    timestamp_validator.validate(envelope, now_ms)?;
    sequence_tracker.validate_and_advance(envelope)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use scp_platform::testing::InMemoryKeyCustody;
    use scp_platform::traits::{KeyCustody, KeyType};

    use super::*;
    use crate::envelope::inner::{InnerEnvelopeParams, MessageType, create_inner_envelope};
    use crate::identity::SigningKeyId;

    /// Helper: creates a signed inner envelope with the given timestamp and
    /// sequence. The signature is valid — these tests exercise the validation
    /// layer, not signature verification.
    async fn make_envelope(timestamp: u64, sequence: u64) -> InnerEnvelope {
        let custody = InMemoryKeyCustody::new();
        let key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        create_inner_envelope(
            &InnerEnvelopeParams {
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                generation: 0,
                sequence,
                timestamp,
                message_type: MessageType::Content,
                payload: b"test payload",
                provenance: None,
                signing_key_id: SigningKeyId::Active,
            },
            &custody,
            &key,
        )
        .await
        .unwrap()
    }

    /// Helper: creates a signed inner envelope with a specific sender and
    /// context.
    async fn make_envelope_from(
        context_id: &str,
        sender_did: &str,
        timestamp: u64,
        sequence: u64,
    ) -> InnerEnvelope {
        let custody = InMemoryKeyCustody::new();
        let key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        create_inner_envelope(
            &InnerEnvelopeParams {
                context_id,
                sender_did,
                epoch: 1,
                generation: 0,
                sequence,
                timestamp,
                message_type: MessageType::Content,
                payload: b"test payload",
                provenance: None,
                signing_key_id: SigningKeyId::Active,
            },
            &custody,
            &key,
        )
        .await
        .unwrap()
    }

    // -----------------------------------------------------------------------
    // TimestampValidator tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn timestamp_within_bounds_accepted() {
        let validator = TimestampValidator::default();
        let now = 1_700_000_000_000u64;
        let envelope = make_envelope(now, 1).await;

        assert!(
            validator.validate(&envelope, now).is_ok(),
            "timestamp equal to now should be accepted"
        );
    }

    #[tokio::test]
    async fn timestamp_slightly_in_future_accepted() {
        let validator = TimestampValidator::default();
        let now = 1_700_000_000_000u64;
        // 4 minutes in the future — within 5 minute tolerance.
        let envelope = make_envelope(now + 4 * 60 * 1_000, 1).await;

        assert!(
            validator.validate(&envelope, now).is_ok(),
            "timestamp 4min in future should be accepted (tolerance is 5min)"
        );
    }

    #[tokio::test]
    async fn timestamp_too_far_in_future_rejected() {
        let validator = TimestampValidator::default();
        let now = 1_700_000_000_000u64;
        // 6 minutes in the future — exceeds 5 minute tolerance.
        let envelope = make_envelope(now + 6 * 60 * 1_000, 1).await;

        let result = validator.validate(&envelope, now);
        assert!(
            result.is_err(),
            "timestamp 6min in future should be rejected"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, EnvelopeError::TimestampInFuture { .. }),
            "expected TimestampInFuture, got {err:?}"
        );
    }

    #[tokio::test]
    async fn timestamp_at_exact_future_boundary_accepted() {
        let validator = TimestampValidator::default();
        let now = 1_700_000_000_000u64;
        // Exactly 5 minutes in the future — at boundary, should be accepted.
        let envelope = make_envelope(now + DEFAULT_CLOCK_SKEW_TOLERANCE_MS, 1).await;

        assert!(
            validator.validate(&envelope, now).is_ok(),
            "timestamp exactly at future boundary should be accepted"
        );
    }

    #[tokio::test]
    async fn timestamp_one_ms_past_future_boundary_rejected() {
        let validator = TimestampValidator::default();
        let now = 1_700_000_000_000u64;
        // 5 minutes + 1ms in the future — just past boundary.
        let envelope = make_envelope(now + DEFAULT_CLOCK_SKEW_TOLERANCE_MS + 1, 1).await;

        assert!(
            validator.validate(&envelope, now).is_err(),
            "timestamp 1ms past future boundary should be rejected"
        );
    }

    #[tokio::test]
    async fn timestamp_too_old_rejected() {
        let validator = TimestampValidator::default();
        let now = 1_700_000_000_000u64;
        // 8 days in the past — exceeds 7 day max_message_age.
        let envelope = make_envelope(now - 8 * 24 * 60 * 60 * 1_000, 1).await;

        let result = validator.validate(&envelope, now);
        assert!(result.is_err(), "timestamp 8 days old should be rejected");
        let err = result.unwrap_err();
        assert!(
            matches!(err, EnvelopeError::TimestampTooOld { .. }),
            "expected TimestampTooOld, got {err:?}"
        );
    }

    #[tokio::test]
    async fn timestamp_at_exact_past_boundary_accepted() {
        let validator = TimestampValidator::default();
        let now = 1_700_000_000_000u64;
        // Exactly 7 days in the past — at boundary, should be accepted.
        let envelope = make_envelope(now - DEFAULT_MAX_MESSAGE_AGE_MS, 1).await;

        assert!(
            validator.validate(&envelope, now).is_ok(),
            "timestamp exactly at past boundary should be accepted"
        );
    }

    #[tokio::test]
    async fn timestamp_one_ms_past_age_boundary_rejected() {
        let validator = TimestampValidator::default();
        let now = 1_700_000_000_000u64;
        // 7 days + 1ms in the past — just past boundary.
        let envelope = make_envelope(now - DEFAULT_MAX_MESSAGE_AGE_MS - 1, 1).await;

        assert!(
            validator.validate(&envelope, now).is_err(),
            "timestamp 1ms past age boundary should be rejected"
        );
    }

    #[tokio::test]
    async fn custom_clock_skew_tolerance() {
        // 10 second tolerance.
        let validator = TimestampValidator::new(10_000, DEFAULT_MAX_MESSAGE_AGE_MS);
        let now = 1_700_000_000_000u64;

        // 9 seconds ahead — accepted.
        let ok_envelope = make_envelope(now + 9_000, 1).await;
        assert!(validator.validate(&ok_envelope, now).is_ok());

        // 11 seconds ahead — rejected.
        let bad_envelope = make_envelope(now + 11_000, 2).await;
        assert!(validator.validate(&bad_envelope, now).is_err());
    }

    #[tokio::test]
    async fn custom_max_message_age() {
        // 1 hour max age.
        let validator = TimestampValidator::new(DEFAULT_CLOCK_SKEW_TOLERANCE_MS, 3_600_000);
        let now = 1_700_000_000_000u64;

        // 59 minutes old — accepted.
        let ok_envelope = make_envelope(now - 59 * 60 * 1_000, 1).await;
        assert!(validator.validate(&ok_envelope, now).is_ok());

        // 61 minutes old — rejected.
        let bad_envelope = make_envelope(now - 61 * 60 * 1_000, 2).await;
        assert!(validator.validate(&bad_envelope, now).is_err());
    }

    #[tokio::test]
    async fn timestamp_zero_rejected_when_now_is_large() {
        let validator = TimestampValidator::default();
        let now = 1_700_000_000_000u64;
        let envelope = make_envelope(0, 1).await;

        assert!(
            validator.validate(&envelope, now).is_err(),
            "timestamp 0 should be rejected when now is large"
        );
    }

    // -----------------------------------------------------------------------
    // SequenceTracker tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn sequence_first_message_accepted() {
        let mut tracker = SequenceTracker::new();
        let envelope = make_envelope(1_700_000_000_000, 1).await;

        assert!(
            tracker.validate_and_advance(&envelope).is_ok(),
            "first message from sender should always be accepted"
        );
    }

    #[tokio::test]
    async fn sequence_increasing_accepted() {
        let mut tracker = SequenceTracker::new();

        let env1 = make_envelope(1_700_000_000_000, 1).await;
        let env2 = make_envelope(1_700_000_001_000, 2).await;
        let env3 = make_envelope(1_700_000_002_000, 3).await;

        assert!(tracker.validate_and_advance(&env1).is_ok());
        assert!(tracker.validate_and_advance(&env2).is_ok());
        assert!(tracker.validate_and_advance(&env3).is_ok());
    }

    #[tokio::test]
    async fn sequence_regression_rejected() {
        let mut tracker = SequenceTracker::new();

        let env1 = make_envelope(1_700_000_000_000, 5).await;
        assert!(tracker.validate_and_advance(&env1).is_ok());

        // Sequence 3 < 5 — regression.
        let env2 = make_envelope(1_700_000_001_000, 3).await;
        let result = tracker.validate_and_advance(&env2);
        assert!(result.is_err(), "sequence regression should be rejected");
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                EnvelopeError::SequenceRegression {
                    received_sequence: 3,
                    last_seen_sequence: 5,
                    ..
                }
            ),
            "expected SequenceRegression with received=3, last_seen=5, got {err:?}"
        );
    }

    #[tokio::test]
    async fn sequence_duplicate_rejected() {
        let mut tracker = SequenceTracker::new();

        let env1 = make_envelope(1_700_000_000_000, 5).await;
        assert!(tracker.validate_and_advance(&env1).is_ok());

        // Same sequence number — replay.
        let env2 = make_envelope(1_700_000_001_000, 5).await;
        let result = tracker.validate_and_advance(&env2);
        assert!(result.is_err(), "duplicate sequence should be rejected");
    }

    #[tokio::test]
    async fn sequence_gap_accepted() {
        let mut tracker = SequenceTracker::new();

        let env1 = make_envelope(1_700_000_000_000, 1).await;
        assert!(tracker.validate_and_advance(&env1).is_ok());

        // Sequence 10 > 1 — gap is OK (messages may arrive out of order from
        // different relays, per §9.8.5).
        let env2 = make_envelope(1_700_000_001_000, 10).await;
        assert!(
            tracker.validate_and_advance(&env2).is_ok(),
            "sequence gap (non-consecutive) should be accepted"
        );
    }

    #[tokio::test]
    async fn sequence_independent_per_sender() {
        let mut tracker = SequenceTracker::new();

        let alice1 = make_envelope_from("ctx-1", "did:dht:alice", 1_700_000_000_000, 5).await;
        let bob1 = make_envelope_from("ctx-1", "did:dht:bob", 1_700_000_000_000, 3).await;

        assert!(tracker.validate_and_advance(&alice1).is_ok());
        assert!(tracker.validate_and_advance(&bob1).is_ok());

        // Alice sequence 3 < 5 — regression for Alice.
        let alice2 = make_envelope_from("ctx-1", "did:dht:alice", 1_700_000_001_000, 3).await;
        assert!(
            tracker.validate_and_advance(&alice2).is_err(),
            "Alice's sequence regression should be rejected"
        );

        // Bob sequence 4 > 3 — valid for Bob.
        let bob2 = make_envelope_from("ctx-1", "did:dht:bob", 1_700_000_001_000, 4).await;
        assert!(
            tracker.validate_and_advance(&bob2).is_ok(),
            "Bob's sequence should be independent from Alice's"
        );
    }

    #[tokio::test]
    async fn sequence_independent_per_context() {
        let mut tracker = SequenceTracker::new();

        let ctx1 = make_envelope_from("ctx-1", "did:dht:alice", 1_700_000_000_000, 5).await;
        let ctx2 = make_envelope_from("ctx-2", "did:dht:alice", 1_700_000_000_000, 3).await;

        assert!(tracker.validate_and_advance(&ctx1).is_ok());
        assert!(tracker.validate_and_advance(&ctx2).is_ok());

        // Same sender in ctx-1 with sequence 4 < 5 — rejected.
        let ctx1_replay = make_envelope_from("ctx-1", "did:dht:alice", 1_700_000_001_000, 4).await;
        assert!(
            tracker.validate_and_advance(&ctx1_replay).is_err(),
            "regression in ctx-1 should be rejected"
        );

        // Same sender in ctx-2 with sequence 4 > 3 — accepted.
        let ctx2_ok = make_envelope_from("ctx-2", "did:dht:alice", 1_700_000_001_000, 4).await;
        assert!(
            tracker.validate_and_advance(&ctx2_ok).is_ok(),
            "ctx-2 sequence should be independent from ctx-1"
        );
    }

    #[tokio::test]
    async fn last_seen_sequence_returns_none_for_unknown() {
        let tracker = SequenceTracker::new();
        assert_eq!(tracker.last_seen_sequence("ctx-1", "did:dht:unknown"), None);
    }

    #[tokio::test]
    async fn last_seen_sequence_returns_value_after_advance() {
        let mut tracker = SequenceTracker::new();
        let env = make_envelope(1_700_000_000_000, 42).await;
        tracker.validate_and_advance(&env).unwrap();

        assert_eq!(
            tracker.last_seen_sequence("ctx-1", "did:dht:alice"),
            Some(42)
        );
    }

    #[tokio::test]
    async fn reset_sender_clears_state() {
        let mut tracker = SequenceTracker::new();
        let env = make_envelope(1_700_000_000_000, 10).await;
        tracker.validate_and_advance(&env).unwrap();

        tracker.reset_sender("ctx-1", "did:dht:alice");

        // After reset, sequence 1 should be accepted (previously would have
        // been rejected as regression from 10).
        let env2 = make_envelope(1_700_000_001_000, 1).await;
        assert!(tracker.validate_and_advance(&env2).is_ok());
    }

    #[tokio::test]
    async fn clear_resets_all_state() {
        let mut tracker = SequenceTracker::new();
        let env1 = make_envelope_from("ctx-1", "did:dht:alice", 1_700_000_000_000, 5).await;
        let env2 = make_envelope_from("ctx-2", "did:dht:bob", 1_700_000_000_000, 3).await;
        tracker.validate_and_advance(&env1).unwrap();
        tracker.validate_and_advance(&env2).unwrap();

        tracker.clear();

        assert_eq!(tracker.last_seen_sequence("ctx-1", "did:dht:alice"), None);
        assert_eq!(tracker.last_seen_sequence("ctx-2", "did:dht:bob"), None);
    }

    // -----------------------------------------------------------------------
    // Combined validation tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn validate_received_envelope_all_pass() {
        let validator = TimestampValidator::default();
        let mut tracker = SequenceTracker::new();
        let now = 1_700_000_000_000u64;
        let envelope = make_envelope(now, 1).await;

        assert!(
            validate_received_envelope(&envelope, now, &validator, &mut tracker).is_ok(),
            "valid envelope should pass combined validation"
        );
    }

    #[tokio::test]
    async fn validate_received_envelope_timestamp_fails_first() {
        let validator = TimestampValidator::default();
        let mut tracker = SequenceTracker::new();
        let now = 1_700_000_000_000u64;
        // Future timestamp — should fail timestamp check before sequence check.
        let envelope = make_envelope(now + 10 * 60 * 1_000, 1).await;

        let result = validate_received_envelope(&envelope, now, &validator, &mut tracker);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EnvelopeError::TimestampInFuture { .. }
        ));
    }

    #[tokio::test]
    async fn validate_received_envelope_sequence_fails() {
        let validator = TimestampValidator::default();
        let mut tracker = SequenceTracker::new();
        let now = 1_700_000_000_000u64;

        // Advance sequence to 5.
        let env1 = make_envelope(now, 5).await;
        validate_received_envelope(&env1, now, &validator, &mut tracker).unwrap();

        // Regression to 3 — valid timestamp but bad sequence.
        let env2 = make_envelope(now + 1_000, 3).await;
        let result = validate_received_envelope(&env2, now + 1_000, &validator, &mut tracker);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EnvelopeError::SequenceRegression { .. }
        ));
    }

    #[tokio::test]
    async fn validate_received_envelope_sequence_not_advanced_on_timestamp_failure() {
        let validator = TimestampValidator::default();
        let mut tracker = SequenceTracker::new();
        let now = 1_700_000_000_000u64;

        // First valid envelope at sequence 1.
        let env1 = make_envelope(now, 1).await;
        validate_received_envelope(&env1, now, &validator, &mut tracker).unwrap();

        // Second envelope has future timestamp (rejected) and sequence 2.
        // Sequence should NOT be advanced because timestamp check failed first.
        let env2 = make_envelope(now + 10 * 60 * 1_000, 2).await;
        assert!(validate_received_envelope(&env2, now, &validator, &mut tracker).is_err());

        // Verify sequence was not advanced — last_seen should still be 1.
        assert_eq!(
            tracker.last_seen_sequence("ctx-1", "did:dht:alice"),
            Some(1),
            "sequence should not advance when timestamp validation fails"
        );
    }

    // -----------------------------------------------------------------------
    // Per-sender timestamp monotonicity (§9.8.2(c))
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn timestamp_regression_rejected() {
        let mut tracker = SequenceTracker::new();

        // First envelope: seq=1, ts=1000
        let env1 = make_envelope(1000, 1).await;
        tracker.validate_and_advance(&env1).unwrap();

        // Second envelope: seq=2 (valid), ts=500 (regression)
        let env2 = make_envelope(500, 2).await;
        let result = tracker.validate_and_advance(&env2);
        assert!(result.is_err());
        assert!(
            matches!(
                result.unwrap_err(),
                EnvelopeError::TimestampRegression { .. }
            ),
            "timestamp regression should be rejected per §9.8.2(c)"
        );
    }

    #[tokio::test]
    async fn same_timestamp_accepted() {
        let mut tracker = SequenceTracker::new();

        // Two envelopes with the same timestamp but increasing sequences.
        let env1 = make_envelope(1000, 1).await;
        tracker.validate_and_advance(&env1).unwrap();

        let env2 = make_envelope(1000, 2).await;
        tracker
            .validate_and_advance(&env2)
            .expect("same timestamp with higher sequence should be accepted");
    }

    #[tokio::test]
    async fn increasing_timestamp_accepted() {
        let mut tracker = SequenceTracker::new();

        let env1 = make_envelope(1000, 1).await;
        tracker.validate_and_advance(&env1).unwrap();

        let env2 = make_envelope(2000, 2).await;
        tracker
            .validate_and_advance(&env2)
            .expect("increasing timestamp with higher sequence should be accepted");
    }
}
