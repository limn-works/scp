#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Verifiable event log (Merkle tree) for SCP contexts.
//!
//! Every context maintains an append-only Merkle tree of all protocol events.
//! The tree uses SHA-256 hashing following the Certificate Transparency
//! (RFC 6962) structure: leaf nodes are SHA-256 hashes of events, and interior
//! nodes are SHA-256 hashes of their children's concatenated hashes.
//!
//! This crate is the standalone extraction of the event log subsystem from
//! `scp-core`. It depends on `scp-primitives` for the [`DID`] newtype and
//! defines an [`EventLogSigner`] trait to abstract signing, removing the
//! direct dependency on `scp-platform`'s `KeyCustody`/`KeyHandle`.
//!
//! See ADR-011 in `.docs/adrs/phase-2.md` for the full design.
//!
//! # Types
//!
//! - [`EventLog`] -- The append-only Merkle tree per context.
//! - [`Event`] -- A protocol event with actor, type, payload, and signature.
//! - [`EventType`] -- The 77 event type variants.
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
pub mod payload;
pub mod proof;
pub mod pruning;
pub mod system_actors;
pub mod tiered_storage;
pub mod time;
pub mod tree;

#[cfg(any(test, feature = "testing"))]
#[allow(clippy::expect_used)] // Test helper module; panics on invalid setup are intentional.
pub mod test_helpers;

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

// Re-export DID from scp-primitives -- single type across the workspace.
pub use scp_primitives::DID;

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

/// The 77 event type variants for SCP context event logs.
///
/// Every protocol action that mutates context state is represented as one of
/// these variants. See ADR-011 for the base enumeration and ADR-031 for
/// the 8 governance-specific event types. The native↔WASM event-log
/// unification amendment (ADR-011, `.docs/adrs/phase-2.md`) added the 40
/// governance-action-coverage, lifecycle/migration, content-access, economic,
/// consequence-enforcement, commit-broadcast-reconciliation, compromise-recovery,
/// and app-sandbox-binding variants; the cross-context-saga event model
/// (ADR-011 Amendment §6 for `CrossContextToolInvoked`; spec §6.2.4 for
/// `CrossContextDivergenceMarker`) added the 2 `CrossContext*` variants. This is a CLOSED set with no catch-all
/// variant: every protocol action that produces a verifiable Merkle-log entry
/// is one of these variants.
///
/// Governance event payloads are serialized into [`EventPayload`]. The
/// payload fields for each governance event type are documented below;
/// producers serialize them as `MessagePack` into `EventPayload::data`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    /// A governance action was executed (legacy variant, see also
    /// `GovernanceActionExecuted`).
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
    /// (spec section 19.6.1). This event marks the START of the 24-hour
    /// notification period (§19.3). The policy is not yet in effect.
    EconomicPolicyChanged,
    /// A pending economic policy change was applied after the 24-hour
    /// notification period expired (spec section 19.3). The new policy
    /// is now in effect.
    EconomicPolicyApplied,
    /// A spending UCAN was granted to an agent (spec section 19.6.1).
    SpendingUcanGranted,
    /// A spending UCAN was revoked (spec section 19.6.1).
    SpendingUcanRevoked,

    // -------------------------------------------------------------------
    // Governance event types (ADR-031 §8)
    // -------------------------------------------------------------------
    /// A governance proposal was created (ADR-031 §8).
    ///
    /// Durable leaf payload: EMPTY. Both native (`append_context_event`,
    /// `EventPayload::default()`) and WASM append this leaf with no payload so
    /// the leaf preimage is byte-identical across platforms (§9.9.3
    /// native↔WASM parity). The associated data (`proposal_id`,
    /// `proposer_did`, `action`, `voting_deadline`) rides only on the
    /// buffer-only `ContextEvent`, never in the canonical Merkle leaf.
    GovernanceProposalCreated,
    /// A vote was cast on a governance proposal (ADR-031 §8).
    ///
    /// Durable leaf payload: EMPTY (native↔WASM parity, §9.9.3). The
    /// associated data (`proposal_id`, `voter_did`, `vote`) rides only on the
    /// buffer-only `ContextEvent`, never in the canonical Merkle leaf.
    GovernanceVoteCast,
    /// A vote was withdrawn from a governance proposal (ADR-031 §8).
    ///
    /// Durable leaf payload: EMPTY (native↔WASM parity, §9.9.3). The
    /// associated data (`proposal_id`, `voter_did`) rides only on the
    /// buffer-only `ContextEvent`, never in the canonical Merkle leaf.
    GovernanceVoteWithdrawn,
    /// A governance proposal was resolved (approved, rejected, expired)
    /// (ADR-031 §8).
    ///
    /// Durable leaf payload: EMPTY (native↔WASM parity, §9.9.3). The
    /// associated data (`proposal_id`, `status`, `executor_did`,
    /// `resulting_epoch`) rides only on the buffer-only `ContextEvent`, never
    /// in the canonical Merkle leaf.
    GovernanceProposalResolved,
    /// A governance conflict was detected (two proposals landed at the
    /// same event log sequence) (ADR-031 §7).
    ///
    /// Durable leaf payload: EMPTY (native↔WASM parity, §9.9.3). The
    /// associated data (`proposal_a`, `proposal_b`) rides only on the
    /// buffer-only `ContextEvent`, never in the canonical Merkle leaf.
    GovernanceConflictDetected,
    /// A governance conflict was resolved (ADR-031 §7).
    ///
    /// Durable leaf payload: EMPTY (native↔WASM parity, §9.9.3). The
    /// associated data (`winner_id`, `resolution`) rides only on the
    /// buffer-only `ContextEvent`, never in the canonical Merkle leaf.
    GovernanceConflictResolved,
    /// A deadlock recovery was performed (ADR-031 §10).
    ///
    /// Durable leaf payload: EMPTY (native↔WASM parity, §9.9.3). The
    /// associated data (`justification`, `changes`) rides only on the
    /// buffer-only `ContextEvent`, never in the canonical Merkle leaf.
    GovernanceDeadlockRecovery,
    /// A governance action was executed from an approved proposal
    /// (ADR-031 §8).
    ///
    /// Payload fields: `proposal_id`, `action`, `executor_did`,
    /// `resulting_epoch`.
    GovernanceActionExecuted,

    // -------------------------------------------------------------------
    // Provenance event types (issue #586)
    // -------------------------------------------------------------------
    /// Provenance metadata was attached to data leaving a source context.
    ///
    /// Payload: SHA-256 hash of JSON-serialized provenance record (32 bytes).
    ProvenanceAttached,
    /// Provenance metadata was received in a target context.
    ///
    /// Payload: SHA-256 hash of JSON-serialized provenance record (32 bytes).
    ProvenanceReceived,

    // -------------------------------------------------------------------
    // Governance-action-coverage event types (native↔WASM unification;
    // ADR-011 Amendment in `.docs/adrs/phase-2.md`). Each traces to a
    // GovernanceAction (ADR-031 §2) or a §19 / §5.11A / §9.9
    // protocol action. Parameters live in [`EventPayload`], never in the
    // type name.
    // -------------------------------------------------------------------
    /// Admin role was transferred (`TransferAdmin`).
    AdminTransferred,
    /// A spending ceiling modification was applied (`ModifyCeiling`).
    CeilingModified,
    /// A spending ceiling modification entered its delay window
    /// (`ModifyCeiling` delay-window start).
    CeilingModificationPending,
    /// A governance threshold was modified (`ModifyThreshold` §4b).
    ThresholdModified,
    /// A governance signer was added (`AddSigner` §4b).
    SignerAdded,
    /// A governance signer was removed (`RemoveSigner` §4b).
    SignerRemoved,
    /// A child context was created (`CreateChildContext` §5.13); consumed
    /// by §7 trust.
    ChildContextCreated,
    /// A context was promoted (`PromoteContext` §5.10).
    ContextPromoted,
    /// Content keys were rotated (`RotateContentKeys` §9.17 / ADR-038).
    ContentKeysRotated,
    /// A member was reset (`ResetMember` ADR-029 Tier-3; §23 reset).
    MemberReset,
    /// A member's capability was suspended (`SuspendCapability`).
    MemberSuspended,
    /// A member's full access was suspended (`SuspendAccess`).
    MemberSuspendedAll,
    /// A member was unblocked (ADR-007 block reversal; pairs with
    /// [`EventType::MemberBlocked`]).
    MemberUnblocked,
    /// Read access was restored (`RestoreAccess` §5 `ReadAccessRestored`).
    AccessRestored,
    /// Governance configuration was changed (`ReconfigureGovernance` §10).
    GovernanceReconfigured,
    /// A §7 conflict-freeze period expired.
    GovernanceFreezeExpired,
    /// A hard rate limit was modified (`ModifyHardRateLimit` §19.7 D4).
    HardRateLimitModified,
    /// The economic policy was locked (`LockEconomicPolicy` §19.3).
    EconomicPolicyLocked,
    /// A context migration started (`ProposeContextMigration` §5.11A grace
    /// start).
    ContextMigrationStarted,
    /// A tool was removed (`RemoveTool`; pairs with
    /// [`EventType::ToolRegistered`]).
    ToolRemoved,
    /// The pruning policy was modified (`ModifyPruningPolicy` ADR-030 §6).
    PruningPolicyModified,
    /// An MLS commit was broadcast (commit broadcast record §9.9
    /// reconciliation).
    CommitBroadcasted,
    /// A commit broadcast was deferred to the queue (deferred-commit queue
    /// record).
    CommitBroadcastPending,
    // PseudonymAnnounced (§9.10.4) is intentionally NOT a variant: a
    // pseudonym announcement is a per-receiver routing-bootstrap signal, not a
    // convergent durable event. It lives only as `ContextEvent::PseudonymAnnounced`
    // (a receive-buffer notification) — see the ADR-011 Amendment exclusion list
    // in `.docs/adrs/phase-2.md`, alongside MessageReceived and EquivocationDetected.

    // -------------------------------------------------------------------
    // Lifecycle / migration event types (ADR-049 §9; §5.11A). Parameters
    // live in [`EventPayload`], never in the type name.
    // -------------------------------------------------------------------
    /// A context was tombstoned at the terminal stage of migration
    /// (§5.11A.5; `actor_did = "system"`).
    ///
    /// Payload (positional `MessagePack`): `destination_id: String`,
    /// `migration_proposal_id: [u8; 32]`. See [`crate::payload`].
    ContextTombstoned,
    /// A context migration was cancelled (§5.11A; pairs with
    /// [`EventType::ContextMigrationStarted`]).
    ///
    /// Payload (positional `MessagePack`): `original_proposal_id: [u8; 32]`.
    /// See [`crate::payload`].
    ContextMigrationCancelled,
    /// A context TTL was unanimously extended (§5.10).
    ///
    /// Payload (positional `MessagePack`): `old_deadline_unix: u64`,
    /// `new_deadline_unix: u64`, `proposal_id: [u8; 32]`,
    /// `consenting_members: Vec<String>`. See [`crate::payload`].
    TtlExtended,
    /// A context TTL extension was denied (§5.10).
    ///
    /// Payload (positional `MessagePack`): `proposal_id: [u8; 32]`,
    /// `rejecting_members: Vec<String>`. See [`crate::payload`].
    TtlExtensionRejected,

    // -------------------------------------------------------------------
    // Content-access governance event types (ADR-031 §3; §5). Pairs with
    // the existing [`EventType::AccessRestored`] variant.
    // -------------------------------------------------------------------
    /// Read or write access was revoked (`RevokeReadAccess` /
    /// `RevokeWriteAccess`; payload: `target_did`, `scope`).
    AccessRevoked,

    // -------------------------------------------------------------------
    // Economic event types (§19.6.1; ADR-031 §3).
    // -------------------------------------------------------------------
    /// A spend was approved (`ApproveSpend` governance action).
    ///
    /// Payload (positional `MessagePack`): `spender: String`,
    /// `amount: u64`, `purpose: String`. See [`crate::payload`].
    SpendApproved,
    /// A payment capture failed (§19.6.1; payload: cost and capture-failure
    /// detail).
    PaymentCaptureFailed,

    // -------------------------------------------------------------------
    // Consequence-enforcement event types (phase-4 trust engine; §7.3.7).
    // `actor_did` = the consequence-enforcement system actor.
    // -------------------------------------------------------------------
    /// A consequence-enforcement rule trigger fired (§7.3.7; payload:
    /// `member_did`, `rule_index`, `trigger_kind`, `action_type`).
    ConsequenceTriggered,
    /// A consequence action was applied (§7.3.7; payload as above).
    ConsequenceEnforced,
    /// Consequence enforcement failed, e.g. member departed mid-flight
    /// (§7.3.7; payload as above).
    ConsequenceEnforcementFailed,
    /// A consequence-enforcement failure escalated to `SuspendAll`
    /// (§7.3.7; payload as above).
    ConsequenceEscalatedToSuspendAll,

    // -------------------------------------------------------------------
    // MLS commit-broadcast reconciliation outcomes (§9.9.4). Pairs with
    // [`EventType::CommitBroadcasted`] / [`EventType::CommitBroadcastPending`].
    // -------------------------------------------------------------------
    /// A deferred commit broadcast succeeded (§9.9.4; payload: `operation`,
    /// `attempts`).
    CommitBroadcastSucceeded,
    /// A deferred commit broadcast permanently failed (§9.9.4; payload:
    /// `operation`, `reason`, `attempts`).
    CommitBroadcastFailed,

    // -------------------------------------------------------------------
    // Compromise-recovery event type (§9.12 step 2 "MLS Update in all
    // active contexts"). Distinct from the ADR-007 sender-key
    // [`EventType::KeyEpochAdvance`]: this records an MLS *group*-epoch
    // advance (Update + self-Commit, broadcast to members) performed during
    // trust recovery. `actor_did = "system:recovery"`.
    // -------------------------------------------------------------------
    /// An MLS group-epoch advance was performed during trust recovery
    /// (§9.12 step 2).
    ///
    /// Payload (positional `MessagePack`): `old_epoch: u64`,
    /// `new_epoch: u64`. See [`crate::payload`].
    RecoveryEpochAdvanced,

    // -------------------------------------------------------------------
    // App-sandbox binding lifecycle (§8; "App binding and unbinding events
    // are visible in the event log"). Parameters live in [`EventPayload`].
    // -------------------------------------------------------------------
    /// An app was bound to a context (§8).
    ///
    /// Payload (positional `MessagePack`): `app_did: String`,
    /// `app_name: String`, `app_version: String`,
    /// `capabilities: Vec<String>`. See [`crate::payload`].
    AppBound,
    /// An app was unbound from a context (§8).
    ///
    /// Payload (positional `MessagePack`): `app_did: String`. See
    /// [`crate::payload`].
    AppUnbound,

    // -------------------------------------------------------------------
    // Cross-context tool-call saga event types (ADR-011 Amendment §6
    // carve-out; `.docs/adrs/phase-2.md`). UNLIKE the intra-context,
    // per-author `ToolInvoked` emission (excluded as non-convergent under
    // the §2 per-author exclusion), the cross-context tool-call saga records
    // these WITHIN the saga's MLS-Commit phase: they are commit-ordered,
    // convergent, durable leaves — every honest member processing the same
    // saga commit produces the byte-identical leaf (committer-assigned
    // timestamp drawn from B's signed `CrossContextToolReceipt`). The
    // committed-side event id is itself a signed receipt field, so the
    // record is canonical by design. See spec §6.2.4 "Dual event-log
    // recording".
    // -------------------------------------------------------------------
    /// A cross-context tool call was recorded on the CALLER side (spec
    /// §6.2.4 "Dual event-log recording"; ADR-011 Amendment §6 carve-out).
    ///
    /// A convergent, commit-ordered durable leaf — NOT a per-author-excluded
    /// event. Emitted by the caller-side actor at Commit-A referencing the
    /// target context id and the same `nonce` as the target's
    /// [`EventType::ToolInvoked`] record, so an auditor joins the two into one
    /// provenance edge. The committer-assigned leaf timestamp is the target's
    /// signed-receipt `timestamp_ms` (B's staged Prepare-B instant), so two
    /// honest members reconstruct the identical leaf.
    CrossContextToolInvoked,
    /// A one-sided cross-context saga commit was made durably auditable (spec
    /// §6.2.4 "Dual event-log recording"; ADR-011 Amendment §6 carve-out).
    ///
    /// A convergent, commit-ordered durable leaf — NOT a per-author-excluded
    /// event. Emitted on a `NeedsRepair` outcome into each available side's
    /// log, recording which side committed, the `SagaId`, the `nonce`, and the
    /// committed-side event id (a signed `CrossContextDivergenceMarker`
    /// payload). The committer-assigned leaf timestamp is the target's staged
    /// `recorded_timestamp_ms` (the same convergent instant the committed-side
    /// [`EventType::ToolInvoked`] leaf carries), so the marker leaf is
    /// byte-identical across honest members.
    CrossContextDivergenceMarker,
}

// ---------------------------------------------------------------------------
// EventPayload
// ---------------------------------------------------------------------------

/// Type-specific data carried by an event.
///
/// Phase 2 stores the payload as opaque bytes. Future phases will introduce
/// structured payload variants per `EventType`.
///
/// [`Default`] yields an empty payload (`data == []`), the canonical
/// representation for non-parameterized events.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
/// Event payloads are stored alongside hashes for retrieval and provenance
/// verification. See issue #303.
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
    /// Full event payloads stored alongside leaf hashes, indexed by sequence.
    /// Enables `get_event` and `query_events` retrieval (#303, #330).
    events: Vec<Event>,
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
            events: Vec::new(),
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

    /// Returns the stored events.
    #[must_use]
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// Returns the full event at the given sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`EventLogError::LeafIndexOutOfBounds`] if `sequence` is
    /// greater than or equal to the number of events.
    /// Returns [`EventLogError::EmptyLog`] if the log has no events.
    pub fn get_event(&self, sequence: u64) -> Result<&Event, EventLogError> {
        if self.events.is_empty() {
            return Err(EventLogError::EmptyLog);
        }
        let idx = usize::try_from(sequence).map_err(|_| EventLogError::LeafIndexOutOfBounds {
            index: sequence,
            count: self.events.len() as u64,
        })?;
        self.events
            .get(idx)
            .ok_or(EventLogError::LeafIndexOutOfBounds {
                index: sequence,
                count: self.events.len() as u64,
            })
    }

    /// Stores a full event payload alongside the leaf hash.
    ///
    /// Called by [`tree::append`] and [`tree::append_unsigned_event`]
    /// after the event passes verification.
    pub(crate) fn push_event(&mut self, event: Event) {
        self.events.push(event);
    }

    /// Pushes a pre-computed leaf hash into the log and rebuilds the tree.
    ///
    /// This is used by [`checkpoint::TruncatedEventLog`] to reconstruct a
    /// tail log from existing leaf hashes without re-verifying events.
    /// It bypasses event verification and signature checking.
    ///
    /// Also used by FFI bridges to populate the UCAN-state `EventLog` from
    /// `ContextManager` event entries, enabling Merkle inclusion proofs
    /// (e.g., `prove_inclusion`) against the same tree that tracks lifecycle
    /// events.
    ///
    /// # Safety (logical)
    ///
    /// The caller is responsible for ensuring the leaf hash was computed
    /// from a verified event. Injecting arbitrary hashes produces Merkle
    /// proofs for events that never occurred. Only call with hashes from
    /// trusted sources (e.g., `ContextManager`'s `MerkleEventLogProvider`).
    #[doc(hidden)]
    pub fn push_leaf_raw(&mut self, leaf_hash: [u8; 32]) {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn event_type_serialization_roundtrip_all_variants() {
        // Round-trips every variant of the closed taxonomy through serde JSON.
        // The 77-variant count and wire-distinctness are pinned separately in
        // `event_type_taxonomy_is_closed_at_77_distinct_variants`.
        for event_type in all_event_types() {
            let json = serde_json::to_string(&event_type).expect("serialize");
            let deserialized: EventType = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(
                event_type, deserialized,
                "round-trip mismatch for {event_type:?}"
            );
        }
    }
    /// Returns the complete closed `EventType` taxonomy in ADR declaration
    /// order. Used by the round-trip and distinctness coverage tests.
    fn all_event_types() -> Vec<EventType> {
        vec![
            EventType::ContextCreated,
            EventType::ContextClosing,
            EventType::ContextClosed,
            EventType::ContextExpired,
            EventType::MemberJoined,
            EventType::MemberLeft,
            EventType::RoleAssigned,
            EventType::TokenRevoked,
            EventType::MessageSent,
            EventType::ToolRegistered,
            EventType::ToolUpdated,
            EventType::ToolInvoked,
            EventType::ToolVerified,
            EventType::ToolInterfaceEstablished,
            EventType::GovernanceAction,
            EventType::ConsistencyCheckpoint,
            EventType::AbsenceProofRequested,
            EventType::MemberBlocked,
            EventType::KeyEpochAdvance,
            EventType::MediaSessionStarted,
            EventType::MediaSessionEnded,
            EventType::PaymentReceived,
            EventType::EconomicPolicyChanged,
            EventType::EconomicPolicyApplied,
            EventType::SpendingUcanGranted,
            EventType::SpendingUcanRevoked,
            EventType::GovernanceProposalCreated,
            EventType::GovernanceVoteCast,
            EventType::GovernanceVoteWithdrawn,
            EventType::GovernanceProposalResolved,
            EventType::GovernanceConflictDetected,
            EventType::GovernanceConflictResolved,
            EventType::GovernanceDeadlockRecovery,
            EventType::GovernanceActionExecuted,
            EventType::ProvenanceAttached,
            EventType::ProvenanceReceived,
            EventType::AdminTransferred,
            EventType::CeilingModified,
            EventType::CeilingModificationPending,
            EventType::ThresholdModified,
            EventType::SignerAdded,
            EventType::SignerRemoved,
            EventType::ChildContextCreated,
            EventType::ContextPromoted,
            EventType::ContentKeysRotated,
            EventType::MemberReset,
            EventType::MemberSuspended,
            EventType::MemberSuspendedAll,
            EventType::MemberUnblocked,
            EventType::AccessRestored,
            EventType::GovernanceReconfigured,
            EventType::GovernanceFreezeExpired,
            EventType::HardRateLimitModified,
            EventType::EconomicPolicyLocked,
            EventType::ContextMigrationStarted,
            EventType::ToolRemoved,
            EventType::PruningPolicyModified,
            EventType::CommitBroadcasted,
            EventType::CommitBroadcastPending,
            EventType::ContextTombstoned,
            EventType::ContextMigrationCancelled,
            EventType::TtlExtended,
            EventType::TtlExtensionRejected,
            EventType::AccessRevoked,
            EventType::SpendApproved,
            EventType::PaymentCaptureFailed,
            EventType::ConsequenceTriggered,
            EventType::ConsequenceEnforced,
            EventType::ConsequenceEnforcementFailed,
            EventType::ConsequenceEscalatedToSuspendAll,
            EventType::CommitBroadcastSucceeded,
            EventType::CommitBroadcastFailed,
            EventType::RecoveryEpochAdvanced,
            EventType::AppBound,
            EventType::AppUnbound,
            EventType::CrossContextToolInvoked,
            EventType::CrossContextDivergenceMarker,
        ]
    }

    #[test]
    fn event_type_taxonomy_is_closed_at_77_distinct_variants() {
        // Pins the closed-set count and asserts wire-distinctness, independent
        // of the round-trip test (which would otherwise exceed the function
        // line limit).
        let event_types = all_event_types();
        assert_eq!(
            event_types.len(),
            77,
            "closed EventType taxonomy must enumerate exactly 77 variants"
        );

        let mut serialized: Vec<String> = event_types
            .iter()
            .map(|et| serde_json::to_string(et).expect("serialize"))
            .collect();
        serialized.sort();
        serialized.dedup();
        assert_eq!(
            serialized.len(),
            77,
            "all 77 EventType variants must serialize to distinct values"
        );
    }

    #[test]
    fn governance_event_types_are_distinct() {
        // Verify the 8 new governance event types serialize to unique strings.
        let governance_types = [
            EventType::GovernanceProposalCreated,
            EventType::GovernanceVoteCast,
            EventType::GovernanceVoteWithdrawn,
            EventType::GovernanceProposalResolved,
            EventType::GovernanceConflictDetected,
            EventType::GovernanceConflictResolved,
            EventType::GovernanceDeadlockRecovery,
            EventType::GovernanceActionExecuted,
        ];

        let serialized: Vec<String> = governance_types
            .iter()
            .map(|et| serde_json::to_string(et).unwrap())
            .collect();

        // All must be unique.
        let mut unique = serialized.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            serialized.len(),
            unique.len(),
            "governance event types must serialize to unique values"
        );

        // None should equal the legacy GovernanceAction variant.
        let legacy = serde_json::to_string(&EventType::GovernanceAction).unwrap();
        for s in &serialized {
            assert_ne!(
                s, &legacy,
                "governance event type must not collide with legacy GovernanceAction"
            );
        }
    }
}
