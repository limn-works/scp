#![forbid(unsafe_code)]

//! Verifiable event log (Merkle tree) for SCP contexts.
//!
//! Every context maintains an append-only Merkle tree of all protocol events.
//! The tree uses SHA-256 hashing following the Certificate Transparency
//! (RFC 6962) structure: leaf nodes are SHA-256 hashes of events, and interior
//! nodes are SHA-256 hashes of their children's concatenated hashes.
//!
//! This crate is the standalone extraction of the event log subsystem from
//! `scp-core`. It depends on `scp-identity` for the [`DID`] newtype and
//! defines an [`EventLogSigner`] trait to abstract signing, removing the
//! direct dependency on `scp-platform`'s `KeyCustody`/`KeyHandle`.
//!
//! See ADR-011 in `.docs/adrs/phase-2.md` for the full design.
//!
//! # Types
//!
//! - [`EventLog`] -- The append-only Merkle tree per context.
//! - [`Event`] -- A protocol event with actor, type, payload, and signature.
//! - [`EventType`] -- The 25 event type variants.
//! - [`EventPayload`] -- Type-specific event data.
//! - [`EventLogError`] -- Error type for event log operations.
//! - [`EventLogSigner`] -- Trait abstracting signing for checkpoint generation.
//!
//! # Operations
//!
//! - [`tree::append`] -- Append an event to the log.
//! - [`tree::root`] -- Get the current Merkle root (O(1)).
//! - [`tree::event_count`] -- Get the number of events in the log.

pub mod checkpoint;
pub mod crypto;
pub mod metrics;
pub mod proof;
pub mod pruning;
pub mod tiered_storage;
pub mod time;
pub mod tree;

#[cfg(any(test, feature = "testing"))]
#[allow(clippy::expect_used)]
pub mod test_helpers;

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

// Re-export DID from scp-identity -- single type across the workspace.
pub use scp_identity::DID;

/// A context identifier string.
///
/// Represented as a plain `String` for Phase 2. This matches the pattern used
/// in the context module (`ContextHandle::context_id: String`).
pub type ContextId = String;

/// An Ed25519 signature (64 bytes).
///
/// Stored as a `Vec<u8>` for serde compatibility. This matches the pattern
/// used in the envelope module (`InnerEnvelope::signature: Vec<u8>`).
pub type Ed25519Signature = Vec<u8>;

// ---------------------------------------------------------------------------
// EventLogSigner trait
// ---------------------------------------------------------------------------

/// Trait abstracting signing for event log checkpoint generation.
///
/// This replaces the direct `KeyCustody`/`KeyHandle` dependency from
/// `scp-platform`, allowing `scp-event-log` to remain independent of
/// platform-specific key custody implementations.
///
/// `scp-core` provides a `KeyCustodySigner` adapter that bridges
/// `KeyCustody`/`KeyHandle` to this trait.
#[async_trait::async_trait]
pub trait EventLogSigner: Send + Sync {
    /// Signs the given message bytes and returns the Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns an error string if signing fails.
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String>;
}

// ---------------------------------------------------------------------------
// EventType
// ---------------------------------------------------------------------------

/// The 25 event type variants for SCP context event logs.
///
/// Every protocol action that mutates context state is represented as one of
/// these variants. See ADR-011 for the full enumeration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    /// Context was created.
    ContextCreated,
    /// Context closure was initiated.
    ContextClosing,
    /// Context was permanently closed.
    ContextClosed,
    /// Context expired due to TTL.
    ContextExpired,
    /// A member joined the context.
    MemberJoined,
    /// A member left the context.
    MemberLeft,
    /// A role was assigned to a member.
    RoleAssigned,
    /// A UCAN token was revoked.
    TokenRevoked,
    /// A message was sent within the context.
    MessageSent,
    /// A tool was registered in the context.
    ToolRegistered,
    /// A tool registration was updated.
    ToolUpdated,
    /// A tool was invoked.
    ToolInvoked,
    /// A tool invocation result was verified.
    ToolVerified,
    /// A tool interface was established.
    ToolInterfaceEstablished,
    /// A governance action was executed.
    GovernanceAction,
    /// A consistency checkpoint was generated.
    ConsistencyCheckpoint,
    /// An absence proof was requested.
    AbsenceProofRequested,
    /// A member was blocked (ADR-007).
    MemberBlocked,
    /// Sender key epoch was advanced (ADR-007).
    KeyEpochAdvance,
    /// A media session was started (ADR-024).
    MediaSessionStarted,
    /// A media session ended (ADR-024).
    MediaSessionEnded,
    /// A payment was received and captured (spec section 19.6.1).
    PaymentReceived,
    /// The context's economic policy was changed through governance
    /// (spec section 19.6.1).
    EconomicPolicyChanged,
    /// A spending UCAN was granted to an agent (spec section 19.6.1).
    SpendingUcanGranted,
    /// A spending UCAN was revoked (spec section 19.6.1).
    SpendingUcanRevoked,
}

// ---------------------------------------------------------------------------
// EventPayload
// ---------------------------------------------------------------------------

/// Type-specific data carried by an event.
///
/// Phase 2 stores the payload as opaque bytes. Future phases will introduce
/// structured payload variants per `EventType`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventPayload {
    /// Opaque payload data. Interpretation depends on the event type.
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Event
// ---------------------------------------------------------------------------

/// A protocol event in the context event log.
///
/// Each event records a single protocol action: who did it (`actor_did`), what
/// they did (`event_type` + `payload`), when (`timestamp`), the position in
/// the log (`sequence`), a hash-chain link to the previous event
/// (`prev_hash`), and an Ed25519 signature over the event content.
///
/// See ADR-011 acceptance criterion 1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// The type of protocol action this event represents.
    pub event_type: EventType,
    /// The DID of the actor who produced this event.
    pub actor_did: DID,
    /// Unix timestamp (seconds) when the event was created.
    pub timestamp: u64,
    /// Monotonic event sequence number within this log (0-indexed).
    pub sequence: u64,
    /// Type-specific event data.
    pub payload: EventPayload,
    /// SHA-256 hash of the previous event (hash chain). For the first event,
    /// this is `[0u8; 32]` (the genesis sentinel).
    pub prev_hash: [u8; 32],
    /// Ed25519 signature over the serialized event content (all fields except
    /// `signature` itself).
    #[serde(with = "serde_bytes")]
    pub signature: Ed25519Signature,
}

// ---------------------------------------------------------------------------
// EventLogError
// ---------------------------------------------------------------------------

/// Errors produced by event log operations.
#[derive(Debug, thiserror::Error)]
pub enum EventLogError {
    /// The event's `prev_hash` does not match the hash of the last leaf in
    /// the log.
    #[error("hash chain broken: prev_hash mismatch at sequence {sequence}")]
    PrevHashMismatch {
        /// The sequence number of the event being appended.
        sequence: u64,
    },

    /// The event's Ed25519 signature is invalid.
    #[error("invalid event signature at sequence {sequence}: {reason}")]
    InvalidSignature {
        /// The sequence number of the event being appended.
        sequence: u64,
        /// Human-readable reason for the failure.
        reason: String,
    },

    /// Serialization of the event failed.
    #[error("event serialization failed: {0}")]
    SerializationFailed(String),

    /// The event sequence number does not match the expected next sequence.
    #[error("sequence mismatch: expected {expected}, got {actual}")]
    SequenceMismatch {
        /// The expected next sequence number.
        expected: u64,
        /// The actual sequence number on the event.
        actual: u64,
    },

    /// The requested leaf index is out of bounds.
    #[error("leaf index {index} out of bounds (log has {count} leaves)")]
    LeafIndexOutOfBounds {
        /// The requested leaf index.
        index: u64,
        /// The total number of leaves in the log.
        count: u64,
    },

    /// The event log is empty.
    #[error("event log is empty")]
    EmptyLog,

    /// An absence proof was requested for a hash that IS present in the log.
    #[error("absence proof requested for event hash that is present in the log")]
    AbsenceProofForPresentEvent,

    /// The signing operation failed during checkpoint generation.
    #[error("signing failed: {0}")]
    SigningFailed(String),

    /// The system clock is unavailable or before the Unix epoch.
    #[error("clock error: {0}")]
    ClockError(#[from] crate::time::ClockError),
}

// ---------------------------------------------------------------------------
// EventLog
// ---------------------------------------------------------------------------

/// An append-only Merkle tree for a single SCP context.
///
/// The tree follows the Certificate Transparency (RFC 6962) structure:
/// - `leaves` stores SHA-256 hashes of serialized events (layer 0).
/// - `tree` stores interior node layers, where each node is the SHA-256 hash
///   of its two children's concatenated hashes.
/// - The Merkle root is always the single element at the top layer.
///
/// A sorted index (`sorted_leaves`) is maintained alongside the append-order
/// tree for future absence proof support.
///
/// See ADR-011 acceptance criterion 1.
pub struct EventLog {
    /// SHA-256 hashes of serialized events, in append order.
    leaves: Vec<[u8; 32]>,
    /// Interior node layers. `tree[0]` is the first interior layer above
    /// leaves, `tree[1]` is the next level up, etc. The root is at the top.
    tree: Vec<Vec<[u8; 32]>>,
    /// The context this event log belongs to.
    context_id: ContextId,
    /// Sorted index of `(leaf_hash, leaf_index)` for absence proof support.
    sorted_leaves: BTreeSet<([u8; 32], u64)>,
}

impl EventLog {
    /// Creates a new empty event log for the given context.
    #[must_use]
    pub const fn new(context_id: ContextId) -> Self {
        Self {
            leaves: Vec::new(),
            tree: Vec::new(),
            context_id,
            sorted_leaves: BTreeSet::new(),
        }
    }

    /// Returns the context ID this event log belongs to.
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Returns the leaf hashes in append order.
    #[must_use]
    pub fn leaves(&self) -> &[[u8; 32]] {
        &self.leaves
    }

    /// Returns the interior node layers.
    #[must_use]
    pub fn tree_layers(&self) -> &[Vec<[u8; 32]>] {
        &self.tree
    }

    /// Returns a reference to the sorted leaf index.
    #[must_use]
    pub const fn sorted_leaves(&self) -> &BTreeSet<([u8; 32], u64)> {
        &self.sorted_leaves
    }

    /// Pushes a pre-computed leaf hash into the log and rebuilds the tree.
    ///
    /// This is used by [`checkpoint::TruncatedEventLog`] to reconstruct a
    /// tail log from existing leaf hashes without re-verifying events.
    /// It bypasses event verification and signature checking.
    ///
    /// **Internal use only.** Not part of the public append API.
    pub(crate) fn push_leaf_raw(&mut self, leaf_hash: [u8; 32]) {
        let leaf_index = self.leaves.len() as u64;
        self.leaves.push(leaf_hash);
        self.sorted_leaves.insert((leaf_hash, leaf_index));
        self.rebuild_tree();
    }

    /// Rebuilds the interior tree from the current leaf layer.
    ///
    /// Called after `push_leaf_raw` to maintain tree invariants.
    /// Delegates to the `tree` module's recompute logic via a full rebuild.
    fn rebuild_tree(&mut self) {
        // Use tree::recompute_raw which handles the full recompute.
        tree::recompute_raw(self);
    }
}
