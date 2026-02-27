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
//!   and delta sync with selective epoch reconstruction. (Future.)
//! - **Tier 3 (Long offline, > 7 days):** Forced re-join via MLS group state
//!   reset. (Future.)
//!
//! All tiers use the Merkle event log (ADR-011) as the authoritative state
//! reconciliation mechanism and the relay's store-and-forward capability
//! (ADR-004) as the primary message recovery path.
//!
//! # Module layout
//!
//! - [`conflict_resolution`] — Offline conflict resolution for concurrent
//!   governance changes: metadata last-writer-wins, governance Merkle-ordered
//!   resolution, deadlock detection, and context fork (SCP-124).
//! - [`hours_offline`] — Tier 1 hours-scale offline recovery: relay message
//!   buffer retrieval, MLS epoch catch-up, automatic Update issuance, reorder
//!   buffering, and `KeyPackage` pre-publication for offline member addition.
//!
//! See ADR-029 in `.docs/adrs/phase-6.md`.

pub mod conflict_resolution;
pub mod hours_offline;

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::identity::DID;

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
// Constants (ADR-029)
// ---------------------------------------------------------------------------

/// Tier 1 upper bound: 4 hours in seconds.
///
/// Offline durations below this threshold are handled by relay buffering and
/// sequential MLS catch-up. See ADR-029 section 1.
pub const TIER_1_THRESHOLD_SECS: u64 = 14_400;

/// Tier 2 upper bound: 7 days in seconds.
///
/// Offline durations between 4 hours and 7 days use state snapshot comparison
/// and delta sync with selective epoch reconstruction. See ADR-029 section 1.
pub const TIER_2_THRESHOLD_SECS: u64 = 604_800;

/// Gap timeout for the reorder buffer: 30 seconds.
///
/// If a gap in the message sequence is not filled within this duration, the
/// buffer delivers what it has and marks the gap. See spec §9.8.5.
pub const GAP_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum number of messages held in the reorder buffer.
///
/// When the buffer reaches capacity, the oldest buffered messages are delivered
/// in order regardless of gaps. See spec §9.8.5.
pub const REORDER_BUFFER_CAPACITY: usize = 100;

/// Maximum number of sequential MLS Commits processed during epoch catch-up.
///
/// Beyond this limit the SDK falls back to Welcome-based fast-forward.
/// See ADR-029 section 3.
pub const MAX_SEQUENTIAL_COMMITS: u64 = 100;

/// Per-Commit processing timeout during epoch catch-up.
///
/// Commits that fail to process within this duration are logged as
/// `EpochCatchUpFailure` and the SDK falls through to the next recovery
/// source. See ADR-029 section 3.
pub const COMMIT_PROCESS_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for sender key re-acquisition after missed rotations.
///
/// Messages encrypted with missed sender key epochs are buffered until the
/// key is obtained or this timeout expires. See ADR-029 section 2, Phase 4.
pub const SENDER_KEY_TIMEOUT: Duration = Duration::from_secs(60);

/// Multi-device reconnection deduplication window.
///
/// Devices observing another device's reconnection event within this window
/// defer their own MLS Update to avoid redundant epoch advances.
/// See ADR-029 section 7.
pub const RECONNECTION_DEDUP_WINDOW: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// OfflineTier
// ---------------------------------------------------------------------------

/// Classification of offline duration into recovery tiers.
///
/// The tier determines which reconciliation strategy the SDK uses on
/// reconnection. See ADR-029 section 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OfflineTier {
    /// Less than 4 hours offline. Relay buffering and sequential MLS catch-up.
    Short,
    /// 4 hours to 7 days offline. State snapshot comparison and delta sync
    /// with selective epoch reconstruction.
    Extended,
    /// More than 7 days offline. Forced re-join via MLS group state reset.
    Long,
}

impl std::fmt::Display for OfflineTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Short => write!(f, "Short (< 4 hours)"),
            Self::Extended => write!(f, "Extended (4 hours – 7 days)"),
            Self::Long => write!(f, "Long (> 7 days)"),
        }
    }
}

/// Classifies the offline duration into the appropriate recovery tier.
///
/// Uses `saturating_sub` to avoid underflow if timestamps are out of order
/// (SCP does not require synchronized clocks per §9.8.3).
///
/// See ADR-029 section 1.
#[must_use]
pub fn classify_offline_duration(last_relay_contact: u64, now: u64) -> OfflineTier {
    let duration_secs = now.saturating_sub(last_relay_contact);
    match duration_secs {
        0..=14_400 => OfflineTier::Short,
        14_401..=604_800 => OfflineTier::Extended,
        _ => OfflineTier::Long,
    }
}

// ---------------------------------------------------------------------------
// SyncError
// ---------------------------------------------------------------------------

/// Errors produced by sync operations.
///
/// Covers relay catch-up, MLS epoch reconciliation, event log sync, sender
/// key re-acquisition, and queue drain failures. See ADR-029.
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
    #[error(
        "sender key timeout for sender {sender_did} in context {context_id}"
    )]
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
    #[error(
        "commit processing failed at epoch {epoch} in context {context_id}: {reason}"
    )]
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
}

// ---------------------------------------------------------------------------
// CatchUpStatus
// ---------------------------------------------------------------------------

/// Outcome of an MLS epoch catch-up attempt.
///
/// See ADR-029 section 3.
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
    /// Catch-up failed — context may need group reset.
    Failed {
        /// Human-readable reason for the failure.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// SyncOutcome
// ---------------------------------------------------------------------------

/// Per-context outcome of the reconnection protocol.
///
/// See ADR-029 acceptance criterion 2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncOutcome {
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_short_offline_zero_seconds() {
        assert_eq!(
            classify_offline_duration(1_000_000, 1_000_000),
            OfflineTier::Short,
        );
    }

    #[test]
    fn classify_short_offline_one_hour() {
        assert_eq!(
            classify_offline_duration(1_000_000, 1_003_600),
            OfflineTier::Short,
        );
    }

    #[test]
    fn classify_short_offline_at_boundary() {
        // Exactly 4 hours = 14_400 seconds — still Short.
        assert_eq!(
            classify_offline_duration(1_000_000, 1_014_400),
            OfflineTier::Short,
        );
    }

    #[test]
    fn classify_extended_offline_just_over_four_hours() {
        assert_eq!(
            classify_offline_duration(1_000_000, 1_014_401),
            OfflineTier::Extended,
        );
    }

    #[test]
    fn classify_extended_offline_three_days() {
        // 3 days = 259_200 seconds.
        assert_eq!(
            classify_offline_duration(1_000_000, 1_259_200),
            OfflineTier::Extended,
        );
    }

    #[test]
    fn classify_extended_offline_at_boundary() {
        // Exactly 7 days = 604_800 seconds — still Extended.
        assert_eq!(
            classify_offline_duration(1_000_000, 1_604_800),
            OfflineTier::Extended,
        );
    }

    #[test]
    fn classify_long_offline_just_over_seven_days() {
        assert_eq!(
            classify_offline_duration(1_000_000, 1_604_801),
            OfflineTier::Long,
        );
    }

    #[test]
    fn classify_long_offline_thirty_days() {
        // 30 days = 2_592_000 seconds.
        assert_eq!(
            classify_offline_duration(1_000_000, 3_592_000),
            OfflineTier::Long,
        );
    }

    #[test]
    fn classify_saturating_sub_handles_clock_skew() {
        // `now` is before `last_relay_contact` — saturating_sub returns 0.
        // SCP does not require synchronized clocks (§9.8.3).
        assert_eq!(
            classify_offline_duration(2_000_000, 1_000_000),
            OfflineTier::Short,
        );
    }

    #[test]
    fn offline_tier_display() {
        assert_eq!(OfflineTier::Short.to_string(), "Short (< 4 hours)");
        assert_eq!(
            OfflineTier::Extended.to_string(),
            "Extended (4 hours – 7 days)",
        );
        assert_eq!(OfflineTier::Long.to_string(), "Long (> 7 days)");
    }

    #[test]
    fn sync_error_display_messages() {
        let err = SyncError::RelayCatchUpFailed {
            context_id: "ctx-1".to_owned(),
            reason: "connection refused".to_owned(),
        };
        assert!(err.to_string().contains("ctx-1"));
        assert!(err.to_string().contains("connection refused"));
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

    #[test]
    fn gap_timeout_is_thirty_seconds() {
        assert_eq!(GAP_TIMEOUT, Duration::from_secs(30));
    }

    #[test]
    fn reorder_buffer_capacity_is_one_hundred() {
        assert_eq!(REORDER_BUFFER_CAPACITY, 100);
    }

    #[test]
    fn max_sequential_commits_is_one_hundred() {
        assert_eq!(MAX_SEQUENTIAL_COMMITS, 100);
    }
}
