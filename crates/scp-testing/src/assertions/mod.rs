//! Low-level assertion primitives for SCP protocol properties.
//!
//! Each submodule provides pure functions that validate a specific protocol
//! invariant given raw extracted data. These do not depend on any simulator or
//! test harness -- they accept slices, counts, and byte arrays so they can be
//! tested (and used) independently.
//!
//! All functions return `Result<(), AssertionError>` for composability with
//! `?`-based test flows.

#![forbid(unsafe_code)]

mod blocking;
mod delivery;
mod epoch;
mod merkle;
mod ordering;
mod privacy;
mod suppression;

pub use blocking::assert_block_enforced;
pub use delivery::{assert_complete_delivery, assert_delivery_ratio};
pub use epoch::assert_epoch_consistency;
pub use merkle::assert_consistent_merkle_roots;
pub use ordering::assert_correct_ordering;
pub use privacy::assert_pseudonym_unlinkability;
pub use suppression::{assert_no_suppression, assert_suppression_detected};

// ---------------------------------------------------------------------------
// AssertionError
// ---------------------------------------------------------------------------

/// Errors produced by the assertion primitives.
///
/// Each variant captures enough context for a useful test failure message
/// without requiring the caller to format details.
#[derive(Debug, thiserror::Error)]
pub enum AssertionError {
    /// Merkle roots from different members are inconsistent beyond the
    /// allowed drift window.
    #[error("merkle inconsistency: {details}")]
    MerkleInconsistency {
        /// Human-readable description of the divergence.
        details: String,
    },

    /// Not all sent messages were delivered.
    #[error("incomplete delivery: expected {expected}, got {actual}")]
    IncompleteDelivery {
        /// Number of messages sent.
        expected: usize,
        /// Number of messages received.
        actual: usize,
    },

    /// A gap in sequence numbers indicates message suppression by a relay.
    #[error("suppression detected: {evidence}")]
    SuppressionDetected {
        /// Description of the gap(s) found.
        evidence: String,
    },

    /// Expected suppression but the sequence was contiguous.
    #[error("suppression not detected (sequence was contiguous)")]
    SuppressionNotDetected,

    /// Messages arrived out of order.
    #[error("ordering violation: {details}")]
    OrderingViolation {
        /// Description of where the ordering broke.
        details: String,
    },

    /// Two routing IDs from different contexts are identical, meaning the
    /// participant's identity can be linked across contexts.
    #[error("pseudonym linkable between context {context_a} and {context_b}")]
    PseudonymLinkable {
        /// Index of the first matching routing ID.
        context_a: usize,
        /// Index of the second matching routing ID.
        context_b: usize,
    },

    /// A blocked participant was still able to decrypt content.
    #[error("block not enforced: {blocker} -> {blocked}")]
    BlockNotEnforced {
        /// The member who initiated the block.
        blocker: String,
        /// The member who should have been blocked.
        blocked: String,
    },

    /// A member's epoch is too far behind the group maximum.
    #[error("epoch inconsistency for {member}: expected at least {expected_min}, got {actual}")]
    EpochInconsistency {
        /// Identifier of the lagging member.
        member: String,
        /// Minimum acceptable epoch (max - `max_behind`).
        expected_min: u64,
        /// Actual epoch of the member.
        actual: u64,
    },
}
