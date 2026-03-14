//! Offline/sync strategy for SCP contexts.
//!
//! Members offline for extended periods accumulate pending MLS proposals and
//! Commits. When the offline member reconnects, they must reconcile their stale
//! local state with the group's current state. This module implements the
//! three-tier offline/sync strategy defined in ADR-029:
//!
//! - **Tier 1 (Short offline, < 4 hours):** Relay buffering and sequential MLS
//!   catch-up. See [`hours_offline`].
//! - **Tier 2 (Extended offline, 4 hours to 7 days):** State snapshot comparison
//!   and delta sync with selective epoch reconstruction. See [`days_offline`].
//! - **Tier 3 (Long offline, > 7 days):** Forced re-join via MLS group state
//!   reset. See [`weeks_offline`].
//!
//! All tiers use the Merkle event log (ADR-011) as the authoritative state
//! reconciliation mechanism and the relay's store-and-forward capability
//! (ADR-004) as the primary message recovery path.
//!
//! # Module layout
//!
//! - [`conflict_resolution`] — Offline conflict resolution for concurrent
//!   governance changes: metadata first-writer-wins, governance Merkle-ordered
//!   resolution, deadlock detection, and context fork (SCP-124).
//! - [`hours_offline`] — Tier 1 hours-scale offline recovery: relay message
//!   buffer retrieval, MLS epoch catch-up, automatic Update issuance, reorder
//!   buffering, and `KeyPackage` pre-publication for offline member addition.
//! - [`days_offline`] — Tier 2 days-scale offline recovery: state snapshot
//!   capture, delta computation and application, MLS group rebuild via
//!   Welcome-based fast-forward, and multi-device divergence detection.
//! - [`weeks_offline`] — Tier 3 weeks-scale offline recovery: forced re-join
//!   with MLS group state reset, state preservation, in-flight message
//!   handling, and bilateral context recovery (SCP-123).
//!
//! See ADR-029 in `.docs/adrs/phase-6.md`.

pub mod alerts;
pub mod conflict_resolution;
pub mod days_offline;
pub mod hours_offline;
pub mod weeks_offline;

use std::time::Duration;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::crypto::canonical::{CanonicalField, canonical_hash};
use scp_identity::DID;

// ---------------------------------------------------------------------------
// Type aliases for domain clarity
// ---------------------------------------------------------------------------

/// A context identifier string.
///
/// Represented as a plain `String`. This matches the type alias pattern used
/// across `scp-core` modules (`event_log`, `bridge`, `discovery`).
pub type ContextId = String;

/// An Ed25519 signature (64 bytes).
///
/// Stored as a `Vec<u8>` for serde compatibility. This matches the pattern
/// used in the event log module.
pub type Ed25519Signature = Vec<u8>;

// ---------------------------------------------------------------------------
// SyncPolicy (ADR-029)
// ---------------------------------------------------------------------------

/// Configurable sync policy controlling offline recovery behavior.
///
/// Different contexts have different activity patterns — a high-frequency
/// trading chat needs different sync tuning than a weekly project standup.
/// `SyncPolicy` extracts the hardcoded constants from ADR-029 into a
/// configurable struct, following the same pattern as
/// [`CheckpointPolicy`](scp_event_log::checkpoint::CheckpointPolicy).
///
/// Use [`SyncPolicy::default()`] for the standard ADR-029 values. Use the
/// `with_*` builder methods for per-context customization.
///
/// See ADR-029 in `.docs/adrs/phase-6.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncPolicy {
    /// Tier 1 upper bound in seconds.
    pub tier_1_threshold_secs: u64,
    /// Tier 2 upper bound in seconds.
    pub tier_2_threshold_secs: u64,
    /// Gap timeout for the reorder buffer.
    pub gap_timeout: Duration,
    /// Maximum number of messages held in the reorder buffer.
    pub reorder_buffer_capacity: usize,
    /// Maximum number of sequential MLS Commits processed during epoch catch-up.
    pub max_sequential_commits: u64,
    /// Per-Commit processing timeout during epoch catch-up.
    pub commit_process_timeout: Duration,
    /// Timeout for sender key re-acquisition after missed rotations.
    pub sender_key_timeout: Duration,
    /// Multi-device reconnection deduplication window.
    pub reconnection_dedup_window: Duration,
}

impl Default for SyncPolicy {
    fn default() -> Self {
        Self {
            tier_1_threshold_secs: TIER_1_THRESHOLD_SECS,
            tier_2_threshold_secs: TIER_2_THRESHOLD_SECS,
            gap_timeout: GAP_TIMEOUT,
            reorder_buffer_capacity: REORDER_BUFFER_CAPACITY,
            max_sequential_commits: MAX_SEQUENTIAL_COMMITS,
            commit_process_timeout: COMMIT_PROCESS_TIMEOUT,
            sender_key_timeout: SENDER_KEY_TIMEOUT,
            reconnection_dedup_window: RECONNECTION_DEDUP_WINDOW,
        }
    }
}

impl SyncPolicy {
    /// Sets the Tier 1 threshold (short offline upper bound) in seconds.
    #[must_use]
    pub const fn with_tier_1_threshold_secs(mut self, secs: u64) -> Self {
        self.tier_1_threshold_secs = secs;
        self
    }

    /// Sets the Tier 2 threshold (extended offline upper bound) in seconds.
    #[must_use]
    pub const fn with_tier_2_threshold_secs(mut self, secs: u64) -> Self {
        self.tier_2_threshold_secs = secs;
        self
    }

    /// Sets the gap timeout for the reorder buffer.
    #[must_use]
    pub const fn with_gap_timeout(mut self, timeout: Duration) -> Self {
        self.gap_timeout = timeout;
        self
    }

    /// Sets the reorder buffer capacity.
    #[must_use]
    pub const fn with_reorder_buffer_capacity(mut self, capacity: usize) -> Self {
        self.reorder_buffer_capacity = capacity;
        self
    }

    /// Sets the maximum number of sequential MLS Commits for epoch catch-up.
    #[must_use]
    pub const fn with_max_sequential_commits(mut self, max: u64) -> Self {
        self.max_sequential_commits = max;
        self
    }

    /// Sets the per-Commit processing timeout.
    #[must_use]
    pub const fn with_commit_process_timeout(mut self, timeout: Duration) -> Self {
        self.commit_process_timeout = timeout;
        self
    }

    /// Sets the sender key re-acquisition timeout.
    #[must_use]
    pub const fn with_sender_key_timeout(mut self, timeout: Duration) -> Self {
        self.sender_key_timeout = timeout;
        self
    }

    /// Sets the multi-device reconnection deduplication window.
    #[must_use]
    pub const fn with_reconnection_dedup_window(mut self, window: Duration) -> Self {
        self.reconnection_dedup_window = window;
        self
    }

    /// Classifies the offline duration into the appropriate recovery tier.
    #[must_use]
    pub const fn classify_offline_duration(
        &self,
        last_relay_contact: u64,
        now: u64,
    ) -> OfflineTier {
        let duration_secs = now.saturating_sub(last_relay_contact);
        if duration_secs <= self.tier_1_threshold_secs {
            OfflineTier::Short
        } else if duration_secs <= self.tier_2_threshold_secs {
            OfflineTier::Extended
        } else {
            OfflineTier::Long
        }
    }
}

// Legacy constants (ADR-029)

/// Tier 1 upper bound: 4 hours in seconds.
pub const TIER_1_THRESHOLD_SECS: u64 = 14_400;
/// Tier 2 upper bound: 7 days in seconds.
pub const TIER_2_THRESHOLD_SECS: u64 = 604_800;
/// Gap timeout for the reorder buffer: 30 seconds.
pub const GAP_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum number of messages held in the reorder buffer.
pub const REORDER_BUFFER_CAPACITY: usize = 100;
/// Maximum number of sequential MLS Commits processed during epoch catch-up.
pub const MAX_SEQUENTIAL_COMMITS: u64 = 100;
/// Per-Commit processing timeout during epoch catch-up.
pub const COMMIT_PROCESS_TIMEOUT: Duration = Duration::from_secs(5);
/// Timeout for sender key re-acquisition after missed rotations.
pub const SENDER_KEY_TIMEOUT: Duration = Duration::from_secs(60);
/// Multi-device reconnection deduplication window.
pub const RECONNECTION_DEDUP_WINDOW: Duration = Duration::from_secs(30);
/// Maximum event signature failures from a single peer before aborting
/// reconciliation with that peer (§23.13 criterion 2, §23.14).
pub const MAX_PEER_VERIFICATION_FAILURES: u32 = 3;

// ---------------------------------------------------------------------------
// OfflineTier
// ---------------------------------------------------------------------------

/// Classification of offline duration into recovery tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OfflineTier {
    /// Less than 4 hours offline.
    Short,
    /// 4 hours to 7 days offline.
    Extended,
    /// More than 7 days offline.
    Long,
}

impl std::fmt::Display for OfflineTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Short => write!(f, "Short (< 4 hours)"),
            Self::Extended => write!(f, "Extended (4 hours \u{2013} 7 days)"),
            Self::Long => write!(f, "Long (> 7 days)"),
        }
    }
}

/// Classifies the offline duration into the appropriate recovery tier
/// using the default [`SyncPolicy`].
#[must_use]
pub fn classify_offline_duration(last_relay_contact: u64, now: u64) -> OfflineTier {
    SyncPolicy::default().classify_offline_duration(last_relay_contact, now)
}

// ---------------------------------------------------------------------------
// ConsistencyCheckpoint (§9.9.3)
// ---------------------------------------------------------------------------

/// Domain separator for `ConsistencyCheckpoint` canonical hash (§9.18.2, §23.16.1).
pub const CONSISTENCY_CHECKPOINT_DOMAIN_SEPARATOR: &str = "SCP-CHECKPOINT-V1:";

/// A signed consistency checkpoint used by the Relay Consistency Protocol.
///
/// At regular intervals (recommended: every 50 events or every 10 minutes,
/// whichever comes first), each member computes and broadcasts a checkpoint
/// over their local event log state. Other members compare received checkpoints
/// against their own to detect relay equivocation.
///
/// Checkpoints are sent as regular MLS application messages (encrypted,
/// authenticated). See spec §9.9.3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsistencyCheckpoint {
    /// The context this checkpoint belongs to.
    pub context_id: ContextId,
    /// The DID of the member who generated this checkpoint.
    pub sender_did: DID,
    /// Number of events in the sender's local event log.
    pub event_count: u64,
    /// Merkle root hash of the sender's local event log.
    pub merkle_root: [u8; 32],
    /// Current MLS epoch on the sender's device. `None` for Broadcast contexts.
    pub epoch: Option<u64>,
    /// Unix timestamp (seconds) when this checkpoint was generated.
    pub timestamp: u64,
    /// Ed25519 signature over all fields above, signed by the sender's
    /// `#active` or `#agent` verification method key (ADR-039).
    #[serde(with = "serde_bytes")]
    pub signature: Ed25519Signature,
}

impl ConsistencyCheckpoint {
    /// Computes the canonical hash for signing/verification (§23.16.1).
    ///
    /// Field order matches `scp-event-log` `compute_checkpoint_canonical_hash`:
    /// `context_id`, `sender_did`, `event_count`, `merkle_root`, `epoch` (with
    /// presence flag), `timestamp`.
    /// Domain separator: `"SCP-CHECKPOINT-V1:"`.
    #[must_use]
    pub fn canonical_hash(&self) -> [u8; 32] {
        let mut fields: Vec<CanonicalField<'_>> = Vec::with_capacity(8);
        fields.push(CanonicalField::VarBytes(self.context_id.as_bytes()));
        fields.push(CanonicalField::VarBytes(self.sender_did.as_bytes()));
        fields.push(CanonicalField::U64(self.event_count));
        fields.push(CanonicalField::Fixed32(&self.merkle_root));
        match self.epoch {
            Some(epoch) => {
                fields.push(CanonicalField::U8(0x01));
                fields.push(CanonicalField::U64(epoch));
            }
            None => {
                fields.push(CanonicalField::U8(0x00));
            }
        }
        fields.push(CanonicalField::U64(self.timestamp));

        canonical_hash(CONSISTENCY_CHECKPOINT_DOMAIN_SEPARATOR, &fields)
    }
}

// ---------------------------------------------------------------------------
// EquivocationEvidence
// ---------------------------------------------------------------------------

/// Evidence of relay equivocation: two conflicting consistency checkpoints
/// from different members that should agree but don't. See spec §9.9.3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivocationEvidence {
    /// The checkpoint from the local (detecting) member.
    pub local_checkpoint: ConsistencyCheckpoint,
    /// The checkpoint from the remote member whose state diverges.
    pub remote_checkpoint: ConsistencyCheckpoint,
    /// The event count at which divergence was detected.
    pub divergent_event_count: u64,
}

// ---------------------------------------------------------------------------
// EquivocationAlert
// ---------------------------------------------------------------------------

/// Alert raised when relay equivocation is detected.
///
/// Per spec §23.7: "If Merkle roots differ at the same event count,
/// equivocation has occurred [...]. The reconnecting member raises an
/// `EquivocationDetected` alert."
///
/// See spec §9.9.3, §23.7.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivocationAlert {
    /// The context where equivocation was detected.
    pub context_id: ContextId,
    /// The DID of the member who detected the equivocation (local member).
    pub detector_did: DID,
    /// The DID of the remote member whose checkpoint diverges.
    pub divergent_did: DID,
    /// The event count at which Merkle roots diverge.
    pub divergent_event_count: u64,
    /// The local member's Merkle root at the divergent event count.
    pub local_merkle_root: [u8; 32],
    /// The remote member's Merkle root at the divergent event count.
    pub remote_merkle_root: [u8; 32],
    /// Cryptographic evidence: the conflicting checkpoints, if available.
    /// `None` when generated from multi-device divergence detection.
    pub evidence: Option<EquivocationEvidence>,
    /// Unix timestamp (seconds) when the alert was raised.
    pub detected_at: u64,
    /// The MLS epoch on the local device at detection time.
    pub local_epoch: Option<u64>,
}

impl std::fmt::Display for EquivocationAlert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EquivocationDetected in context {} at event count {}: \
             local root {:?} != remote root {:?} (remote DID: {})",
            self.context_id,
            self.divergent_event_count,
            &self.local_merkle_root[..4],
            &self.remote_merkle_root[..4],
            self.divergent_did,
        )
    }
}

// ---------------------------------------------------------------------------
// SyncEvent
// ---------------------------------------------------------------------------

/// Events emitted by the sync subsystem during reconnection and ongoing
/// consistency monitoring.
///
/// Security-critical events MUST NOT be silently discarded (spec §9.9.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncEvent {
    /// Relay equivocation detected. See spec §9.9.3, §23.7.
    EquivocationDetected(Box<EquivocationAlert>),
    /// Sequence gap detected — possible suppression. See spec §9.9.2.
    SequenceGapDetected {
        /// The context where the gap was detected.
        context_id: ContextId,
        /// The DID of the sender with the sequence gap.
        sender_did: DID,
        /// The expected sequence number.
        expected_sequence: u64,
        /// The received sequence number (higher than expected).
        received_sequence: u64,
    },
    /// Consistency checkpoint received from a remote member.
    CheckpointReceived {
        /// The context the checkpoint belongs to.
        context_id: ContextId,
        /// The DID of the member who sent the checkpoint.
        sender_did: DID,
        /// Whether the checkpoint matched the local state.
        consistent: bool,
    },
    /// Outbound queue overflow: oldest messages were dropped to stay within
    /// per-context (1,000) or global (10,000) bounds. See spec section 23.2.
    QueueOverflow(crate::store::queue::QueueOverflowInfo),
}

impl std::fmt::Display for SyncEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EquivocationDetected(alert) => write!(f, "{alert}"),
            Self::SequenceGapDetected {
                context_id,
                sender_did,
                expected_sequence,
                received_sequence,
            } => write!(
                f,
                "SequenceGap in context {context_id}: expected #{expected_sequence} \
                 from {sender_did}, received #{received_sequence}",
            ),
            Self::CheckpointReceived {
                context_id,
                sender_did,
                consistent,
            } => write!(
                f,
                "Checkpoint from {sender_did} in {context_id}: {}",
                if *consistent {
                    "consistent"
                } else {
                    "INCONSISTENT"
                },
            ),
            Self::QueueOverflow(info) => write!(
                f,
                "QueueOverflow in context {}: {} messages dropped ({})",
                info.context_id, info.messages_dropped, info.overflow_kind,
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// SyncError
// ---------------------------------------------------------------------------

/// Errors produced by sync operations.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// Relay catch-up failed (Phase 1 of reconnection protocol).
    #[error("relay catch-up failed for context {context_id}: {reason}")]
    RelayCatchUpFailed {
        /// The context where catch-up failed.
        context_id: ContextId,
        /// Human-readable reason.
        reason: String,
    },
    /// MLS epoch catch-up failed (Phase 2 of reconnection protocol).
    #[error("epoch catch-up failed for context {context_id}: {reason}")]
    EpochCatchUpFailed {
        /// The context where epoch catch-up failed.
        context_id: ContextId,
        /// Human-readable reason.
        reason: String,
    },
    /// Event log sync failed (Phase 3 of reconnection protocol).
    #[error("event log sync failed for context {context_id}: {reason}")]
    EventLogSyncFailed {
        /// The context where event log sync failed.
        context_id: ContextId,
        /// Human-readable reason.
        reason: String,
    },
    /// Sender key re-acquisition timed out (Phase 4 of reconnection protocol).
    #[error("sender key timeout for sender {sender_did} in context {context_id}")]
    SenderKeyTimeout {
        /// The context where the timeout occurred.
        context_id: ContextId,
        /// The DID of the sender whose key could not be obtained.
        sender_did: DID,
    },
    /// MLS Update issuance failed (Phase 5 of reconnection protocol).
    #[error("MLS update failed for context {context_id}: {reason}")]
    MlsUpdateFailed {
        /// The context where the Update failed.
        context_id: ContextId,
        /// Human-readable reason.
        reason: String,
    },
    /// Queue drain failed (Phase 6 of reconnection protocol).
    #[error("queue drain failed for context {context_id}: {reason}")]
    QueueDrainFailed {
        /// The context where the drain failed.
        context_id: ContextId,
        /// Human-readable reason.
        reason: String,
    },
    /// The context was closed or expired while the member was offline.
    #[error("context {context_id} is gone (closed or expired while offline)")]
    ContextGone {
        /// The context that no longer exists.
        context_id: ContextId,
    },
    /// The reorder buffer overflowed.
    #[error("reorder buffer overflow in context {context_id}: {buffered} messages buffered")]
    ReorderBufferOverflow {
        /// The context where the overflow occurred.
        context_id: ContextId,
        /// Number of messages currently buffered.
        buffered: usize,
    },
    /// A Commit in the catch-up sequence was corrupted or failed to process.
    #[error("commit processing failed at epoch {epoch} in context {context_id}: {reason}")]
    CommitProcessingFailed {
        /// The context where processing failed.
        context_id: ContextId,
        /// The epoch of the failing Commit.
        epoch: u64,
        /// Human-readable reason.
        reason: String,
    },
    /// The gap timeout expired before the missing message arrived.
    #[error("gap timeout expired in context {context_id} at sequence {sequence}")]
    GapTimeoutExpired {
        /// The context where the gap occurred.
        context_id: ContextId,
        /// The sequence number of the missing message.
        sequence: u64,
    },
    /// Overall reconnection timed out.
    #[error("reconnection timed out after {elapsed_ms}ms")]
    ReconnectionTimeout {
        /// Milliseconds elapsed before timeout.
        elapsed_ms: u64,
    },
    /// Persisted grace state was inconsistent with MLS group state on
    /// recovery (§23.11).
    ///
    /// This indicates a partial write escaped the transaction boundary.
    /// The SDK discards all grace entries, destroys old epoch key material,
    /// and re-enters the reconnection protocol for the affected context.
    #[error("epoch grace store inconsistency in context {context_id}: {reason}")]
    EpochGraceStoreInconsistency {
        /// The context where the inconsistency was detected.
        context_id: ContextId,
        /// Human-readable description of the inconsistency.
        reason: String,
    },
    /// A `ResetRequest` failed anti-replay validation (invalid signature,
    /// stale timestamp, or replayed nonce). See spec §23.15.
    #[error("reset request rejected in context {context_id} from {sender_did}: {reason}")]
    ResetRequestRejected {
        /// The context where the reset request was rejected.
        context_id: ContextId,
        /// The DID of the sender whose reset request failed validation.
        sender_did: DID,
        /// Human-readable reason for rejection.
        reason: String,
    },
    /// A received consistency checkpoint failed signature verification
    /// (§23.12). Indicates potential relay compromise or peer impersonation.
    #[error("checkpoint signature failure in context {context_id} from {sender_did}: {reason}")]
    CheckpointSignatureFailure {
        /// The context where the checkpoint verification failed.
        context_id: ContextId,
        /// The DID of the checkpoint's claimed author.
        sender_did: DID,
        /// Human-readable reason for the verification failure.
        reason: String,
    },
    /// A received event failed per-event signature verification during
    /// reconciliation (§23.13). The event was rejected and not added to the
    /// local log.
    #[error(
        "event signature failure in context {context_id} at sequence {event_sequence} from {expected_signer}: {reason}"
    )]
    EventSignatureFailure {
        /// The context where the signature failure occurred.
        context_id: ContextId,
        /// The sequence number of the event that failed verification.
        event_sequence: u64,
        /// The DID claimed as the event's signer.
        expected_signer: DID,
        /// Human-readable reason for the verification failure.
        reason: String,
    },
    /// A gap in event sequence numbers could not be filled during
    /// reconciliation (§23.13 criterion 3-4).
    #[error(
        "event gap detected in context {context_id}: missing sequences {missing_start}-{missing_end} (peer: {peer_did})"
    )]
    EventGapDetected {
        /// The context where the gap was detected.
        context_id: ContextId,
        /// Start of the missing sequence range (inclusive).
        missing_start: u64,
        /// End of the missing sequence range (inclusive).
        missing_end: u64,
        /// The DID of the peer that provided the events surrounding the gap.
        peer_did: DID,
    },
    /// Hash chain continuity was broken during reconciliation, indicating
    /// tampering or data loss (§23.13 criterion 5-6).
    #[error("event chain tampered in context {context_id} at sequence {break_sequence}")]
    EventChainTampered {
        /// The context where the chain break was detected.
        context_id: ContextId,
        /// The sequence number at which the hash chain breaks.
        break_sequence: u64,
        /// The expected `prev_hash` (hash of the event at `sequence - 1`).
        expected_prev_hash: [u8; 32],
        /// The `prev_hash` value in the received event that does not match.
        received_prev_hash: [u8; 32],
    },
}

// ---------------------------------------------------------------------------
// CatchUpStatus
// ---------------------------------------------------------------------------

/// Outcome of an MLS epoch catch-up attempt. See ADR-029 section 3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CatchUpStatus {
    /// Sequential Commit processing in progress.
    Processing,
    /// All epochs caught up successfully.
    Complete,
    /// Fell back to Welcome-based fast-forward (skipped epoch range).
    FastForwarded {
        /// First epoch that was skipped.
        skipped_from: u64,
        /// Last epoch that was skipped.
        skipped_to: u64,
    },
    /// Catch-up failed.
    Failed {
        /// Human-readable reason for the failure.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// SyncOutcome
// ---------------------------------------------------------------------------

/// Per-context outcome of the reconnection protocol. See ADR-029.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncOutcome {
    /// Sync has not yet executed. Returned by planning methods; replaced by
    /// a concrete outcome after [`ReconnectionCoordinator::execute`] runs.
    Pending,
    /// All epochs and events caught up via sequential processing.
    FullyCaughtUp,
    /// Caught up via Welcome-based fast-forward (some epochs skipped).
    FastForwarded {
        /// Number of epochs skipped during fast-forward.
        skipped_epochs: u64,
    },
    /// Member underwent group state reset (Tier 3).
    Reset,
    /// Context was closed or expired while offline.
    ContextGone,
    /// Sync failed.
    Failed {
        /// Human-readable reason for the failure.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Checkpoint comparison
// ---------------------------------------------------------------------------

/// Compares a local consistency checkpoint against a received remote
/// checkpoint and returns an `EquivocationAlert` if divergence is detected.
///
/// Returns `None` if context IDs differ (cross-context comparison is
/// meaningless), if event counts differ (one member is behind), or if
/// Merkle roots match (consistent). See spec §9.9.3.
#[must_use]
pub fn compare_checkpoints(
    local: &ConsistencyCheckpoint,
    remote: &ConsistencyCheckpoint,
    now: u64,
) -> Option<EquivocationAlert> {
    if local.context_id != remote.context_id {
        return None;
    }
    if local.event_count != remote.event_count {
        return None;
    }
    if bool::from(local.merkle_root.ct_eq(&remote.merkle_root)) {
        return None;
    }
    Some(EquivocationAlert {
        context_id: local.context_id.clone(),
        detector_did: local.sender_did.clone(),
        divergent_did: remote.sender_did.clone(),
        divergent_event_count: local.event_count,
        local_merkle_root: local.merkle_root,
        remote_merkle_root: remote.merkle_root,
        evidence: Some(EquivocationEvidence {
            local_checkpoint: local.clone(),
            remote_checkpoint: remote.clone(),
            divergent_event_count: local.event_count,
        }),
        detected_at: now,
        local_epoch: local.epoch,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn classify_short_offline_zero_seconds() {
        assert_eq!(
            classify_offline_duration(1_000_000, 1_000_000),
            OfflineTier::Short
        );
    }

    #[test]
    fn classify_short_offline_at_boundary() {
        assert_eq!(
            classify_offline_duration(1_000_000, 1_014_400),
            OfflineTier::Short
        );
    }

    #[test]
    fn classify_extended_offline_just_over_four_hours() {
        assert_eq!(
            classify_offline_duration(1_000_000, 1_014_401),
            OfflineTier::Extended
        );
    }

    #[test]
    fn classify_extended_offline_at_boundary() {
        assert_eq!(
            classify_offline_duration(1_000_000, 1_604_800),
            OfflineTier::Extended
        );
    }

    #[test]
    fn classify_long_offline_just_over_seven_days() {
        assert_eq!(
            classify_offline_duration(1_000_000, 1_604_801),
            OfflineTier::Long
        );
    }

    #[test]
    fn classify_saturating_sub_handles_clock_skew() {
        assert_eq!(
            classify_offline_duration(2_000_000, 1_000_000),
            OfflineTier::Short
        );
    }

    #[test]
    fn offline_tier_display() {
        assert_eq!(OfflineTier::Short.to_string(), "Short (< 4 hours)");
        assert!(OfflineTier::Extended.to_string().contains("7 days"));
        assert_eq!(OfflineTier::Long.to_string(), "Long (> 7 days)");
    }

    #[test]
    fn sync_policy_default_matches_constants() {
        let policy = SyncPolicy::default();
        assert_eq!(policy.tier_1_threshold_secs, TIER_1_THRESHOLD_SECS);
        assert_eq!(policy.tier_2_threshold_secs, TIER_2_THRESHOLD_SECS);
        assert_eq!(policy.gap_timeout, GAP_TIMEOUT);
        assert_eq!(policy.reorder_buffer_capacity, REORDER_BUFFER_CAPACITY);
        assert_eq!(policy.max_sequential_commits, MAX_SEQUENTIAL_COMMITS);
    }

    #[test]
    fn catch_up_status_variants_are_serializable() {
        let statuses = vec![
            CatchUpStatus::Processing,
            CatchUpStatus::Complete,
            CatchUpStatus::FastForwarded {
                skipped_from: 5,
                skipped_to: 50,
            },
            CatchUpStatus::Failed {
                reason: "missing commits".to_owned(),
            },
        ];
        for status in &statuses {
            let json = serde_json::to_string(status);
            assert!(json.is_ok(), "failed to serialize {status:?}");
        }
    }

    // -----------------------------------------------------------------------
    // ConsistencyCheckpoint & compare_checkpoints tests
    // -----------------------------------------------------------------------

    fn make_checkpoint(
        context_id: &str,
        sender_did: &str,
        event_count: u64,
        merkle_root: [u8; 32],
        epoch: Option<u64>,
    ) -> ConsistencyCheckpoint {
        ConsistencyCheckpoint {
            context_id: context_id.to_owned(),
            sender_did: DID::from(sender_did),
            event_count,
            merkle_root,
            epoch,
            timestamp: 1_700_000_000,
            signature: vec![0u8; 64],
        }
    }

    #[test]
    fn consistency_checkpoint_serialization_roundtrip() {
        let cp = make_checkpoint("ctx-1", "did:key:alice", 100, [1u8; 32], Some(10));
        let json = serde_json::to_string(&cp).unwrap();
        let deserialized: ConsistencyCheckpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(cp, deserialized);
    }

    #[test]
    fn compare_checkpoints_cross_context_returns_none() {
        // Two different contexts with same event count but different roots
        // must NOT trigger equivocation — they are independent contexts.
        let local = make_checkpoint("ctx-1", "did:key:alice", 100, [1u8; 32], Some(10));
        let remote = make_checkpoint("ctx-2", "did:key:bob", 100, [2u8; 32], Some(10));
        assert!(compare_checkpoints(&local, &remote, 1_700_000_100).is_none());
    }

    #[test]
    fn compare_checkpoints_consistent() {
        let local = make_checkpoint("ctx-1", "did:key:alice", 100, [1u8; 32], Some(10));
        let remote = make_checkpoint("ctx-1", "did:key:bob", 100, [1u8; 32], Some(10));
        assert!(compare_checkpoints(&local, &remote, 1_700_000_100).is_none());
    }

    #[test]
    fn compare_checkpoints_different_event_counts_not_equivocation() {
        let local = make_checkpoint("ctx-1", "did:key:alice", 95, [1u8; 32], Some(10));
        let remote = make_checkpoint("ctx-1", "did:key:bob", 100, [2u8; 32], Some(10));
        assert!(compare_checkpoints(&local, &remote, 1_700_000_100).is_none());
    }

    #[test]
    fn compare_checkpoints_detects_equivocation() {
        let local = make_checkpoint("ctx-1", "did:key:alice", 100, [1u8; 32], Some(10));
        let remote = make_checkpoint("ctx-1", "did:key:bob", 100, [2u8; 32], Some(10));
        let alert = compare_checkpoints(&local, &remote, 1_700_000_100).unwrap();
        assert_eq!(alert.context_id, "ctx-1");
        assert_eq!(alert.detector_did, DID::from("did:key:alice"));
        assert_eq!(alert.divergent_did, DID::from("did:key:bob"));
        assert_eq!(alert.divergent_event_count, 100);
        assert_eq!(alert.local_merkle_root, [1u8; 32]);
        assert_eq!(alert.remote_merkle_root, [2u8; 32]);
        assert!(alert.evidence.is_some());
    }

    #[test]
    fn compare_checkpoints_evidence_contains_both() {
        let local = make_checkpoint("ctx-1", "did:key:alice", 50, [0xAA; 32], Some(5));
        let remote = make_checkpoint("ctx-1", "did:key:bob", 50, [0xBB; 32], Some(5));
        let alert = compare_checkpoints(&local, &remote, 1_700_001_000).unwrap();
        let evidence = alert.evidence.unwrap();
        assert_eq!(evidence.local_checkpoint, local);
        assert_eq!(evidence.remote_checkpoint, remote);
        assert_eq!(evidence.divergent_event_count, 50);
    }

    #[test]
    fn equivocation_alert_display() {
        let alert = EquivocationAlert {
            context_id: "ctx-1".to_owned(),
            detector_did: DID::from("did:key:alice"),
            divergent_did: DID::from("did:key:bob"),
            divergent_event_count: 100,
            local_merkle_root: [0xAA; 32],
            remote_merkle_root: [0xBB; 32],
            evidence: None,
            detected_at: 1_700_000_000,
            local_epoch: Some(10),
        };
        let s = alert.to_string();
        assert!(s.contains("ctx-1"));
        assert!(s.contains("100"));
        assert!(s.contains("did:key:bob"));
    }

    #[test]
    fn equivocation_alert_serialization_roundtrip() {
        let alert = EquivocationAlert {
            context_id: "ctx-1".to_owned(),
            detector_did: DID::from("did:key:alice"),
            divergent_did: DID::from("did:key:bob"),
            divergent_event_count: 100,
            local_merkle_root: [1u8; 32],
            remote_merkle_root: [2u8; 32],
            evidence: None,
            detected_at: 1_700_000_000,
            local_epoch: Some(10),
        };
        let json = serde_json::to_string(&alert).unwrap();
        let deserialized: EquivocationAlert = serde_json::from_str(&json).unwrap();
        assert_eq!(alert, deserialized);
    }

    #[test]
    fn sync_event_serialization_roundtrip() {
        let events = vec![
            SyncEvent::EquivocationDetected(Box::new(EquivocationAlert {
                context_id: "ctx-1".to_owned(),
                detector_did: DID::from("did:key:alice"),
                divergent_did: DID::from("did:key:bob"),
                divergent_event_count: 100,
                local_merkle_root: [1u8; 32],
                remote_merkle_root: [2u8; 32],
                evidence: None,
                detected_at: 1_700_000_000,
                local_epoch: Some(10),
            })),
            SyncEvent::SequenceGapDetected {
                context_id: "ctx-2".to_owned(),
                sender_did: DID::from("did:key:mallory"),
                expected_sequence: 47,
                received_sequence: 49,
            },
            SyncEvent::CheckpointReceived {
                context_id: "ctx-3".to_owned(),
                sender_did: DID::from("did:key:carol"),
                consistent: true,
            },
            SyncEvent::QueueOverflow(crate::store::queue::QueueOverflowInfo {
                context_id: "ctx-4".to_owned(),
                messages_dropped: 5,
                overflow_kind: crate::store::queue::OverflowKind::PerContext,
            }),
        ];
        for event in &events {
            let json = serde_json::to_string(event).unwrap();
            let deserialized: SyncEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(*event, deserialized);
        }
    }

    #[test]
    fn sync_event_display() {
        let gap = SyncEvent::SequenceGapDetected {
            context_id: "ctx-1".to_owned(),
            sender_did: DID::from("did:key:mallory"),
            expected_sequence: 47,
            received_sequence: 49,
        };
        assert!(gap.to_string().contains("47"));
        assert!(gap.to_string().contains("49"));

        let cp = SyncEvent::CheckpointReceived {
            context_id: "ctx-1".to_owned(),
            sender_did: DID::from("did:key:bob"),
            consistent: false,
        };
        assert!(cp.to_string().contains("INCONSISTENT"));

        let overflow = SyncEvent::QueueOverflow(crate::store::queue::QueueOverflowInfo {
            context_id: "ctx-1".to_owned(),
            messages_dropped: 3,
            overflow_kind: crate::store::queue::OverflowKind::Global,
        });
        assert!(overflow.to_string().contains("QueueOverflow"));
        assert!(overflow.to_string().contains('3'));
    }

    // -----------------------------------------------------------------------
    // MAX_PEER_VERIFICATION_FAILURES constant (§23.14)
    // -----------------------------------------------------------------------

    #[test]
    fn max_peer_verification_failures_matches_spec() {
        assert_eq!(
            MAX_PEER_VERIFICATION_FAILURES, 3,
            "§23.14 defines MAX_PEER_VERIFICATION_FAILURES = 3"
        );
    }

    // -----------------------------------------------------------------------
    // New SyncError variants (§23.15)
    // -----------------------------------------------------------------------

    #[test]
    fn sync_error_reset_request_rejected_display() {
        let err = SyncError::ResetRequestRejected {
            context_id: "ctx-1".to_owned(),
            sender_did: DID::from("did:dht:zMallory"),
            reason: "stale timestamp".to_owned(),
        };
        let s = err.to_string();
        assert!(s.contains("ctx-1"));
        assert!(s.contains("did:dht:zMallory"));
        assert!(s.contains("stale timestamp"));
    }

    #[test]
    fn sync_error_checkpoint_signature_failure_display() {
        let err = SyncError::CheckpointSignatureFailure {
            context_id: "ctx-2".to_owned(),
            sender_did: DID::from("did:dht:zRelay"),
            reason: "unknown signing key".to_owned(),
        };
        let s = err.to_string();
        assert!(s.contains("ctx-2"));
        assert!(s.contains("did:dht:zRelay"));
        assert!(s.contains("unknown signing key"));
    }

    #[test]
    fn sync_error_event_signature_failure_display() {
        let err = SyncError::EventSignatureFailure {
            context_id: "ctx-3".to_owned(),
            event_sequence: 42,
            expected_signer: DID::from("did:dht:zAlice"),
            reason: "invalid signature".to_owned(),
        };
        let s = err.to_string();
        assert!(s.contains("ctx-3"));
        assert!(s.contains("42"));
        assert!(s.contains("did:dht:zAlice"));
        assert!(s.contains("invalid signature"));
    }

    #[test]
    fn sync_error_event_gap_detected_display() {
        let err = SyncError::EventGapDetected {
            context_id: "ctx-4".to_owned(),
            missing_start: 6,
            missing_end: 7,
            peer_did: DID::from("did:dht:zBob"),
        };
        let s = err.to_string();
        assert!(s.contains("ctx-4"));
        assert!(s.contains("6-7"));
        assert!(s.contains("did:dht:zBob"));
    }

    #[test]
    fn sync_error_event_chain_tampered_display() {
        let err = SyncError::EventChainTampered {
            context_id: "ctx-5".to_owned(),
            break_sequence: 100,
            expected_prev_hash: [0xAA; 32],
            received_prev_hash: [0xBB; 32],
        };
        let s = err.to_string();
        assert!(s.contains("ctx-5"));
        assert!(s.contains("100"));
    }

    #[test]
    fn sync_error_new_variants_are_debug_printable() {
        let errors: Vec<SyncError> = vec![
            SyncError::ResetRequestRejected {
                context_id: "ctx-1".to_owned(),
                sender_did: DID::from("did:dht:z1"),
                reason: "stale".to_owned(),
            },
            SyncError::CheckpointSignatureFailure {
                context_id: "ctx-2".to_owned(),
                sender_did: DID::from("did:dht:z2"),
                reason: "bad sig".to_owned(),
            },
            SyncError::EventSignatureFailure {
                context_id: "ctx-3".to_owned(),
                event_sequence: 1,
                expected_signer: DID::from("did:dht:z3"),
                reason: "invalid".to_owned(),
            },
            SyncError::EventGapDetected {
                context_id: "ctx-4".to_owned(),
                missing_start: 5,
                missing_end: 10,
                peer_did: DID::from("did:dht:z4"),
            },
            SyncError::EventChainTampered {
                context_id: "ctx-5".to_owned(),
                break_sequence: 50,
                expected_prev_hash: [0u8; 32],
                received_prev_hash: [1u8; 32],
            },
        ];
        for err in &errors {
            // Verify Debug and Display impls don't panic.
            let _debug = format!("{err:?}");
            let _display = format!("{err}");
        }
    }
}
