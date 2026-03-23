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
//! (i.e., after `open_envelope` succeeds), before delivering the
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
/// `open_envelope` succeeds and before delivering to the application
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
// Tests — async tests requiring scp-runtime (create_inner_envelope) have been
// moved to crates/scp-runtime/tests/envelope_validation_integration.rs
// ---------------------------------------------------------------------------
