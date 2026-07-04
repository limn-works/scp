//! Timestamp bounds, sequence monotonicity, and out-of-order message buffering
//! for received envelopes.
//!
//! Implements §9.8.2(a), §9.8.2(c), and §9.8.5 from the security model spec:
//!
//! - **Timestamp bounds** — reject envelopes with `created_at` more than
//!   `clock_skew_tolerance` in the future or more than `max_message_age` in the
//!   past.
//! - **Sequence monotonicity** — per-sender sequence numbers must be
//!   monotonically increasing. Any regression is a replay.
//! - **Reorder buffer** — messages arriving out of order are buffered (up to
//!   100 per sender per context) and delivered when the gap fills or a 30-second
//!   timeout expires (§9.8.5).
//!
//! These checks run after MLS decryption and inner signature verification
//! (i.e., after `open_envelope` succeeds), before delivering the
//! message to the application layer.

use std::collections::{BTreeMap, HashMap};

use super::EnvelopeError;
use super::inner::InnerEnvelope;

// ---------------------------------------------------------------------------
// Default constants (§9.8.2)
// ---------------------------------------------------------------------------

/// Default clock skew tolerance: 5 minutes in milliseconds.
///
/// Envelopes with timestamps more than this far in the future are rejected.
/// Spec reference: §9.8.2(c).
///
/// Independent knob: shares the protocol-wide §9.14 5-minute skew default with
/// `crypto::ucan::validate::DEFAULT_CLOCK_SKEW_TOLERANCE_SECS` and the trust
/// skew tolerances, but is deliberately a distinct constant, not unified.
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

/// Result of sequence validation (§9.8.5).
///
/// The `SequenceTracker` classifies each envelope into one of three categories:
/// - `Expected` — the sequence is the expected next value; deliver immediately.
/// - `Ahead` — the sequence is ahead of expected (gap detected); buffer it.
/// - Error — the sequence is a replay (returned as `Err`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SequenceCheck {
    /// The envelope's sequence is the expected next value.
    Expected,
    /// The envelope's sequence is ahead of expected — a gap exists (§9.8.5).
    ///
    /// The envelope should be buffered pending delivery of the missing
    /// predecessors. `expected` is the sequence number that was expected.
    Ahead {
        /// The sequence number that was expected.
        expected: u64,
    },
}

/// Tracks per-sender sequence numbers and timestamps to detect replay attacks
/// (§9.8.2, §9.8.5).
///
/// Each sender in each context maintains a monotonically increasing SCP
/// sequence number and monotonically non-decreasing timestamp. Any envelope
/// with a sequence number ≤ the last delivered value, or a timestamp strictly
/// less than the last seen timestamp, from the same sender is rejected.
///
/// Per-sender timestamp monotonicity catches time-shifted replays where an
/// attacker bumps the sequence number but uses an older timestamp (§9.8.2(c)).
///
/// This tracker is separate from the MLS generation number check (which is
/// handled by the MLS layer). It provides an additional SCP-level replay
/// defense.
#[derive(Debug, Clone, Default)]
pub struct SequenceTracker {
    /// Maps `(context_id, sender_did)` to `(next_expected_sequence, last_timestamp)`.
    ///
    /// `next_expected_sequence` is the next sequence number we expect to deliver.
    /// Messages with `sequence < next_expected` are replays. Messages with
    /// `sequence == next_expected` are delivered immediately. Messages with
    /// `sequence > next_expected` are buffered (gap).
    state: HashMap<SenderKey, (u64, u64)>,
}

impl SequenceTracker {
    /// Creates a new, empty sequence tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Validates the sequence number and timestamp of an inner envelope,
    /// returning whether it is the expected next message or ahead (gap).
    ///
    /// This method does NOT advance the tracker state. Call [`Self::advance`] when
    /// the message is actually delivered to the application layer.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::SequenceRegression`] if the envelope's
    /// `sequence` is < the expected next from the same sender, or
    /// [`EnvelopeError::TimestampRegression`] if the timestamp is strictly
    /// less than the last seen timestamp (§9.8.2(c)).
    pub fn validate(&self, envelope: &InnerEnvelope) -> Result<SequenceCheck, EnvelopeError> {
        let key = (envelope.context_id.clone(), envelope.sender_did.clone());

        if let Some(&(next_expected, last_ts)) = self.state.get(&key) {
            if envelope.sequence < next_expected {
                return Err(EnvelopeError::SequenceRegression {
                    sender_did: envelope.sender_did.clone(),
                    context_id: envelope.context_id.clone(),
                    received_sequence: envelope.sequence,
                    last_seen_sequence: next_expected.saturating_sub(1),
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
            if envelope.sequence == next_expected {
                Ok(SequenceCheck::Expected)
            } else {
                Ok(SequenceCheck::Ahead {
                    expected: next_expected,
                })
            }
        } else {
            // First message from this sender: sequence 1 is expected (0 means
            // no messages sent yet). Sequence 0 is invalid — sequences start
            // at 1 and are assigned by the send path's next_sequence_number().
            if envelope.sequence == 0 {
                return Err(EnvelopeError::SequenceRegression {
                    sender_did: envelope.sender_did.clone(),
                    context_id: envelope.context_id.clone(),
                    received_sequence: 0,
                    last_seen_sequence: 0,
                });
            }
            if envelope.sequence == 1 {
                Ok(SequenceCheck::Expected)
            } else {
                Ok(SequenceCheck::Ahead { expected: 1 })
            }
        }
    }

    /// Validates the sequence number and timestamp of an inner envelope and,
    /// if valid, updates the tracker state.
    ///
    /// This is the legacy method that rejects out-of-order messages. Use
    /// [`Self::validate`] + [`Self::advance`] for reorder-buffer-aware validation.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::SequenceRegression`] if the envelope's
    /// `sequence` is < the expected next from the same sender, or
    /// [`EnvelopeError::TimestampRegression`] if the timestamp is strictly
    /// less than the last seen timestamp (§9.8.2(c)).
    pub fn validate_and_advance(&mut self, envelope: &InnerEnvelope) -> Result<(), EnvelopeError> {
        let key = (envelope.context_id.clone(), envelope.sender_did.clone());

        if let Some(&(next_expected, last_ts)) = self.state.get(&key) {
            if envelope.sequence < next_expected {
                return Err(EnvelopeError::SequenceRegression {
                    sender_did: envelope.sender_did.clone(),
                    context_id: envelope.context_id.clone(),
                    received_sequence: envelope.sequence,
                    last_seen_sequence: next_expected.saturating_sub(1),
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

        self.state.insert(
            key,
            (envelope.sequence.saturating_add(1), envelope.timestamp),
        );
        Ok(())
    }

    /// Advances the tracker state after a message is delivered.
    ///
    /// Sets the expected next sequence to `delivered_sequence + 1` and updates
    /// the last-seen timestamp. Call this after the message is delivered to the
    /// application layer (after gap resolution or immediate delivery).
    pub fn advance(
        &mut self,
        context_id: &str,
        sender_did: &str,
        delivered_sequence: u64,
        timestamp: u64,
    ) {
        let key = (context_id.to_owned(), sender_did.to_owned());
        let new_next = delivered_sequence.saturating_add(1);
        match self.state.get_mut(&key) {
            Some(entry) => {
                // Only advance forward — never regress.
                if new_next > entry.0 {
                    entry.0 = new_next;
                }
                if timestamp > entry.1 {
                    entry.1 = timestamp;
                }
            }
            None => {
                self.state.insert(key, (new_next, timestamp));
            }
        }
    }

    /// Returns the expected next sequence number for a given sender in a context,
    /// or `None` if no messages have been seen from that sender.
    #[must_use]
    pub fn expected_sequence(&self, context_id: &str, sender_did: &str) -> Option<u64> {
        self.state
            .get(&(context_id.to_owned(), sender_did.to_owned()))
            .map(|&(next, _)| next)
    }

    /// Returns the last seen (delivered) sequence number for a given sender in
    /// a context, or `None` if no messages have been seen from that sender.
    #[must_use]
    pub fn last_seen_sequence(&self, context_id: &str, sender_did: &str) -> Option<u64> {
        self.state
            .get(&(context_id.to_owned(), sender_did.to_owned()))
            .map(|&(next, _)| next.saturating_sub(1))
    }

    /// Resets the tracker state for a specific sender in a context.
    ///
    /// This is intended for use during MLS epoch transitions where sequence
    /// number state may need to be reset.
    pub fn reset_sender(&mut self, context_id: &str, sender_did: &str) {
        self.state
            .remove(&(context_id.to_owned(), sender_did.to_owned()));
    }

    /// Clears all tracked state.
    pub fn clear(&mut self) {
        self.state.clear();
    }
}

// ---------------------------------------------------------------------------
// ReorderBuffer (§9.8.5)
// ---------------------------------------------------------------------------

/// Default maximum buffered messages per sender per context (§9.8.5).
pub const DEFAULT_REORDER_BUFFER_SIZE: usize = 100;

/// Default gap timeout in milliseconds (§9.8.5): 30 seconds.
pub const DEFAULT_GAP_TIMEOUT_MS: u64 = 30_000;

/// A message buffered pending delivery of its predecessors.
#[derive(Debug, Clone)]
pub struct BufferedMessage {
    /// The verified and decrypted inner envelope.
    pub inner: InnerEnvelope,
    /// The sender's DID.
    pub sender_did: String,
    /// The decrypted plaintext payload (after signature verification and
    /// access key unwrapping).
    pub plaintext: Vec<u8>,
    /// Local clock time (Unix milliseconds) when this message was received
    /// and buffered. Used for gap timeout.
    pub received_at: u64,
}

/// Information about a gap that was force-closed due to timeout or buffer
/// overflow (§9.8.5, §9.9.2).
#[derive(Debug, Clone)]
pub struct GapInfo {
    /// The sender DID.
    pub sender_did: String,
    /// The context ID.
    pub context_id: String,
    /// The expected sequence number (start of gap).
    pub expected_sequence: u64,
    /// The first buffered sequence number (end of gap + 1).
    pub first_buffered_sequence: u64,
    /// The reason the gap was force-closed.
    pub reason: GapCloseReason,
}

/// Why a sequence gap was force-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GapCloseReason {
    /// The gap persisted longer than `gap_timeout_ms` (default 30s).
    Timeout,
    /// The per-sender buffer reached `max_buffer_size` (default 100).
    BufferFull,
}

/// Per-(context, sender) reorder buffer for out-of-order message delivery
/// (§9.8.5).
///
/// Messages arriving ahead of their expected sequence number are buffered
/// here. When the gap fills (the expected sequence arrives), all consecutive
/// buffered messages are delivered in order. If the gap persists beyond
/// `gap_timeout_ms`, buffered messages are force-delivered with a suppression
/// alert.
///
/// The buffer is bounded at `max_buffer_size` per sender per context to
/// prevent resource exhaustion. When the bound is hit, the oldest gap is
/// force-closed.
#[derive(Debug, Clone)]
pub struct ReorderBuffer {
    /// Buffered messages keyed by `(context_id, sender_did)`, then by sequence
    /// number. `BTreeMap` gives us ordered iteration by sequence.
    buffered: HashMap<SenderKey, BTreeMap<u64, BufferedMessage>>,
    /// Maximum messages buffered per sender per context.
    max_buffer_size: usize,
    /// Gap timeout in milliseconds.
    gap_timeout_ms: u64,
}

impl Default for ReorderBuffer {
    fn default() -> Self {
        Self {
            buffered: HashMap::new(),
            max_buffer_size: DEFAULT_REORDER_BUFFER_SIZE,
            gap_timeout_ms: DEFAULT_GAP_TIMEOUT_MS,
        }
    }
}

impl ReorderBuffer {
    /// Creates a new reorder buffer with custom bounds.
    #[must_use]
    pub fn new(max_buffer_size: usize, gap_timeout_ms: u64) -> Self {
        Self {
            buffered: HashMap::new(),
            max_buffer_size: max_buffer_size.max(1),
            gap_timeout_ms,
        }
    }

    /// Buffers a message that arrived ahead of its expected sequence.
    ///
    /// If the per-sender buffer is full (`max_buffer_size`), returns `Some`
    /// with a [`GapInfo`] indicating the force-closed gap, and the messages
    /// that should be delivered. The caller must deliver those messages and
    /// advance the `SequenceTracker`.
    ///
    /// Returns `None` if the message was successfully buffered without
    /// overflow.
    pub fn buffer(&mut self, msg: BufferedMessage) -> Option<(GapInfo, Vec<BufferedMessage>)> {
        let key = (msg.inner.context_id.clone(), msg.sender_did.clone());
        let sender_buf = self.buffered.entry(key).or_default();

        // Reject duplicate sequence (already buffered).
        if sender_buf.contains_key(&msg.inner.sequence) {
            return None;
        }

        let context_id = msg.inner.context_id.clone();
        let sender_did = msg.sender_did.clone();
        sender_buf.insert(msg.inner.sequence, msg);

        // Check buffer overflow.
        if sender_buf.len() > self.max_buffer_size {
            // Force-close the oldest gap: deliver all buffered messages.
            let first_seq = *sender_buf.keys().next().unwrap_or(&0);
            let gap_info = GapInfo {
                sender_did,
                context_id,
                expected_sequence: 0, // Caller should fill from SequenceTracker.
                first_buffered_sequence: first_seq,
                reason: GapCloseReason::BufferFull,
            };
            let messages: Vec<BufferedMessage> = sender_buf.values().cloned().collect();
            sender_buf.clear();
            Some((gap_info, messages))
        } else {
            None
        }
    }

    /// Checks if a gap-filling sequence number unblocks buffered messages.
    ///
    /// After delivering the expected-sequence message, call this to drain
    /// any consecutive buffered messages that can now be delivered.
    ///
    /// Returns the consecutive run of buffered messages starting from
    /// `next_expected_sequence` (inclusive).
    pub fn drain_consecutive(
        &mut self,
        context_id: &str,
        sender_did: &str,
        next_expected_sequence: u64,
    ) -> Vec<BufferedMessage> {
        let key = (context_id.to_owned(), sender_did.to_owned());
        let Some(sender_buf) = self.buffered.get_mut(&key) else {
            return Vec::new();
        };

        let mut result = Vec::new();
        let mut seq = next_expected_sequence;
        while sender_buf.contains_key(&seq) {
            if let Some(msg) = sender_buf.remove(&seq) {
                result.push(msg);
            }
            match seq.checked_add(1) {
                Some(next) => seq = next,
                None => break, // u64::MAX reached — stop to prevent infinite loop
            }
        }

        // Clean up empty maps.
        if sender_buf.is_empty() {
            self.buffered.remove(&key);
        }

        result
    }

    /// Checks for timed-out gaps and returns messages that should be
    /// force-delivered, along with gap information for suppression alerts.
    ///
    /// Call on each `deliver_incoming` invocation with the current time.
    pub fn drain_timed_out(
        &mut self,
        now_ms: u64,
        tracker: &SequenceTracker,
    ) -> Vec<(GapInfo, Vec<BufferedMessage>)> {
        let mut results = Vec::new();
        let keys: Vec<SenderKey> = self.buffered.keys().cloned().collect();

        for key in keys {
            let sender_buf = match self.buffered.get(&key) {
                Some(buf) if !buf.is_empty() => buf,
                _ => continue,
            };

            // Check the oldest buffered message's received_at timestamp.
            let Some(oldest) = sender_buf.values().next() else {
                continue;
            };

            if now_ms.saturating_sub(oldest.received_at) >= self.gap_timeout_ms {
                let (context_id, sender_did) = &key;
                let expected = tracker
                    .expected_sequence(context_id, sender_did)
                    .unwrap_or(1);
                let first_seq = *sender_buf.keys().next().unwrap_or(&0);

                let gap_info = GapInfo {
                    sender_did: sender_did.clone(),
                    context_id: context_id.clone(),
                    expected_sequence: expected,
                    first_buffered_sequence: first_seq,
                    reason: GapCloseReason::Timeout,
                };

                // Key is guaranteed to exist: we just read from it above and
                // the only mutations between reads happen inside this branch.
                if let Some(sender_buf) = self.buffered.get_mut(&key) {
                    let messages: Vec<BufferedMessage> = sender_buf.values().cloned().collect();
                    sender_buf.clear();
                    self.buffered.remove(&key);

                    results.push((gap_info, messages));
                }
            }
        }

        results
    }

    /// Returns the number of buffered messages for a given sender in a context.
    #[must_use]
    pub fn buffered_count(&self, context_id: &str, sender_did: &str) -> usize {
        self.buffered
            .get(&(context_id.to_owned(), sender_did.to_owned()))
            .map_or(0, BTreeMap::len)
    }

    /// Returns the total number of buffered messages across all senders.
    #[must_use]
    pub fn total_buffered(&self) -> usize {
        self.buffered.values().map(BTreeMap::len).sum()
    }

    /// Clears all buffered messages for a given sender in a context.
    pub fn clear_sender(&mut self, context_id: &str, sender_did: &str) {
        self.buffered
            .remove(&(context_id.to_owned(), sender_did.to_owned()));
    }

    /// Clears all buffered state.
    pub fn clear(&mut self) {
        self.buffered.clear();
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
