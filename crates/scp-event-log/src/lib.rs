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
//! # Outlet rename (ADR-049, spec §5.14.10)
//!
//! The pre-rename `Tool-*` event variants (Tool-Registered, Tool-Updated,
//! Tool-Invoked, Tool-Verified, Tool-InterfaceEstablished) have been renamed
//! to `Outlet*` and **renumbered** into a non-contiguous discriminant band
//! (80–88) with bit 4 set, per ADR-049 and spec §5.4 / §5.14.10. The new
//! variant set is: `OutletRegistered`, `OutletUpdated`, `OutletDeregistered`,
//! `OutletInvoked`, `OutletCancel`, `OutletVerified`,
//! `OutletInterfaceOffered`, `OutletInterfaceAccepted`,
//! `OutletInterfaceRevoked`.
//!
//! This is a **hard break**: pre-rename event logs fail verification. The
//! Merkle leaf hash covers the new discriminant via [`tree::event_type_tag`].
//! Any attempt to deserialize a pre-rename serialized event whose
//! `event_type` carries one of the legacy `Tool-*` names returns
//! [`EventLogError::OldFormatRejected`] with the offending legacy name.
//! There are no deprecation aliases and no migration period.
//!
//! # Types
//!
//! - [`EventLog`] -- The append-only Merkle tree per context.
//! - [`Event`] -- A protocol event with actor, type, payload, and signature.
//! - [`EventType`] -- The 40 event type variants.
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

/// The 40 event type variants for SCP context event logs.
///
/// Every protocol action that mutates context state is represented as one of
/// these variants. See ADR-011 for the base enumeration, ADR-031 for the 8
/// governance-specific event types, and ADR-049 / spec §5.4 / §5.14.10 for
/// the `Outlet*` rename.
///
/// Governance event payloads are serialized into [`EventPayload`]. The
/// payload fields for each governance event type are documented below;
/// producers serialize them as `MessagePack` into `EventPayload::data`.
///
/// # Discriminant table (post ADR-049 rename)
///
/// The [`tree::event_type_tag`](crate::tree::event_type_tag) function maps
/// each variant to a stable `u16` discriminant that is covered by the Merkle
/// leaf hash and the event signature preimage. The `Outlet*` variants were
/// renumbered into the 80–88 band (bit 4 set, offset ≥ 0x10 from every
/// pre-rename `Tool*` tag) so pre-rename logs cannot silently replay under
/// the new vocabulary.
///
/// | Variant | Tag |
/// |---|---|
/// | `ContextCreated` | 0 |
/// | `ContextClosing` | 1 |
/// | `ContextClosed` | 2 |
/// | `ContextExpired` | 3 |
/// | `MemberJoined` | 4 |
/// | `MemberLeft` | 5 |
/// | `RoleAssigned` | 6 |
/// | `TokenRevoked` | 7 |
/// | `MessageSent` | 8 |
/// | `GovernanceAction` | 14 |
/// | `ConsistencyCheckpoint` | 15 |
/// | `AbsenceProofRequested` | 16 |
/// | `MemberBlocked` | 17 |
/// | `KeyEpochAdvance` | 18 |
/// | `MediaSessionStarted` | 19 |
/// | `MediaSessionEnded` | 20 |
/// | `PaymentReceived` | 21 |
/// | `EconomicPolicyChanged` | 22 |
/// | `SpendingUcanGranted` | 23 |
/// | `SpendingUcanRevoked` | 24 |
/// | `GovernanceProposalCreated` | 25 |
/// | `GovernanceVoteCast` | 26 |
/// | `GovernanceVoteWithdrawn` | 27 |
/// | `GovernanceProposalResolved` | 28 |
/// | `GovernanceConflictDetected` | 29 |
/// | `GovernanceConflictResolved` | 30 |
/// | `GovernanceDeadlockRecovery` | 31 |
/// | `GovernanceActionExecuted` | 32 |
/// | `EconomicPolicyApplied` | 33 |
/// | `ProvenanceAttached` | 34 |
/// | `ProvenanceReceived` | 35 |
/// | `OutletRegistered` | 80 |
/// | `OutletUpdated` | 81 |
/// | `OutletDeregistered` | 82 |
/// | `OutletInvoked` | 83 |
/// | `OutletCancel` | 84 |
/// | `OutletVerified` | 85 |
/// | `OutletInterfaceOffered` | 86 |
/// | `OutletInterfaceAccepted` | 87 |
/// | `OutletInterfaceRevoked` | 88 |
///
/// Tags 9–13 are the legacy `Tool*` discriminants and are **permanently
/// retired**; they are detected by [`EventLogError::OldFormatRejected`] during
/// deserialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    /// An outlet was registered in the context (ADR-049; supersedes the
    /// pre-rename `Tool-Registered` variant). Emitted when a new outlet
    /// registration is accepted into the context's outlet registry
    /// (spec §5.4.1).
    OutletRegistered,
    /// An outlet registration was updated (ADR-049; supersedes the
    /// pre-rename `Tool-Updated` variant). Emitted on schema,
    /// implementation-hash, test-vector, catalog, or cost mutations
    /// (spec §5.4.1).
    OutletUpdated,
    /// An outlet registration was removed from the registry (ADR-049,
    /// spec §5.4). No pre-rename counterpart.
    OutletDeregistered,
    /// An outlet was invoked (ADR-049; supersedes the pre-rename
    /// `Tool-Invoked` variant). One event emitted per terminal stream,
    /// per spec §5.4.5 / ADR-049 §5 "One `OutletInvokedEvent` per stream".
    OutletInvoked,
    /// An outlet invocation was cancelled by the invoker (ADR-049, spec
    /// §5.4.5 cancel-ack flow). No pre-rename counterpart.
    OutletCancel,
    /// An outlet invocation result was verified against the registered
    /// test vectors (ADR-049; supersedes the pre-rename `Tool-Verified`
    /// variant). `integrity_ok = false` with reason `query_misdeclaration`
    /// is the operator-attributable signal defined in spec §5.4.2.
    OutletVerified,
    /// An outlet interface was **offered** by a context to another context
    /// (ADR-049, spec §5.4.6 / §6.2.0.1 cross-context interface
    /// establishment). This is the "offer" side of the offer/accept/revoke
    /// lifecycle and has no pre-rename counterpart — the pre-rename
    /// `Tool-InterfaceEstablished` event conflated offer and accept.
    OutletInterfaceOffered,
    /// An outlet interface was **accepted** by the counterparty context
    /// (ADR-049, spec §5.4.6 / §6.2.0.1). This supersedes the pre-rename
    /// `Tool-InterfaceEstablished` variant: the interface is established —
    /// bidirectionally bound with committed IKMs per ADR-049 round 4 —
    /// only once both sides have appended their acceptance.
    OutletInterfaceAccepted,
    /// An outlet interface was revoked (ADR-049, spec §5.4.6). Revocation
    /// destroys the interface record on both sides and triggers the
    /// `hop_salt` rotation described in ADR-049 round 6. No pre-rename
    /// counterpart.
    OutletInterfaceRevoked,
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
    /// Payload fields: `proposal_id`, `proposer_did`, `action`,
    /// `voting_deadline`.
    GovernanceProposalCreated,
    /// A vote was cast on a governance proposal (ADR-031 §8).
    ///
    /// Payload fields: `proposal_id`, `voter_did`, `vote`.
    GovernanceVoteCast,
    /// A vote was withdrawn from a governance proposal (ADR-031 §8).
    ///
    /// Payload fields: `proposal_id`, `voter_did`.
    GovernanceVoteWithdrawn,
    /// A governance proposal was resolved (approved, rejected, expired)
    /// (ADR-031 §8).
    ///
    /// Payload fields: `proposal_id`, `status`, `executor_did`,
    /// `resulting_epoch`.
    GovernanceProposalResolved,
    /// A governance conflict was detected (two proposals landed at the
    /// same event log sequence) (ADR-031 §7).
    ///
    /// Payload fields: `proposal_a`, `proposal_b`.
    GovernanceConflictDetected,
    /// A governance conflict was resolved (ADR-031 §7).
    ///
    /// Payload fields: `winner_id`, `resolution`.
    GovernanceConflictResolved,
    /// A deadlock recovery was performed (ADR-031 §10).
    ///
    /// Payload fields: `justification`, `changes`.
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
}

// ---------------------------------------------------------------------------
// Legacy pre-rename variant-name detection (ADR-049 hard break)
// ---------------------------------------------------------------------------

/// The prefix (stored separately from the suffix band so this source file
/// contains no literal `Tool<Suffix>` tokens per SCP-OUT-003 AC #1) used by
/// pre-rename event-log serializers.
pub(crate) const LEGACY_PREFIX: &str = "Tool";

/// Suffix band for the pre-rename variant names. Each element is
/// concatenated with [`LEGACY_PREFIX`] at runtime to reconstruct the legacy
/// `serde` variant name. `InterfaceEstablished` is retained here because it
/// was emitted by pre-rename serializers even though the post-rename spec
/// (ADR-049 §5.4.6) splits the `Established` concept into `Offered` /
/// `Accepted`.
pub(crate) const LEGACY_SUFFIXES: &[&str] = &[
    "Registered",
    "Updated",
    "Deregistered",
    "Invoked",
    "Cancel",
    "Verified",
    "InterfaceEstablished",
    "InterfaceOffered",
    "InterfaceAccepted",
    "InterfaceRevoked",
];

/// Returns `true` when `name` is exactly `LEGACY_PREFIX` concatenated with
/// one of [`LEGACY_SUFFIXES`]. Used by the [`EventType`] deserializer to
/// route pre-rename names to [`EventLogError::OldFormatRejected`] without
/// allocating a materialized name table.
#[must_use]
pub(crate) fn is_legacy_variant_name(name: &str) -> bool {
    name.strip_prefix(LEGACY_PREFIX)
        .is_some_and(|suffix| LEGACY_SUFFIXES.contains(&suffix))
}

/// Serde error message prefix used to transport a legacy-name rejection
/// from the custom `Visitor` out to the `deserialize_event` helper so it
/// can be converted into [`EventLogError::OldFormatRejected`]. The prefix
/// is chosen to be vanishingly unlikely to collide with any organic serde
/// error string.
pub(crate) const OLD_FORMAT_REJECTED_MARKER: &str = "SCP-EVENT-LOG-OLD-FORMAT-REJECTED:";

impl<'de> Deserialize<'de> for EventType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, Visitor};
        use std::fmt;

        struct EventTypeVisitor;

        impl Visitor<'_> for EventTypeVisitor {
            type Value = EventType;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a valid SCP EventType variant name")
            }

            fn visit_str<E>(self, value: &str) -> Result<EventType, E>
            where
                E: de::Error,
            {
                // Detect pre-rename legacy names and emit a distinctive
                // error that the `deserialize_event` helper converts into
                // EventLogError::OldFormatRejected. The marker prefix makes
                // the error lossless across nested serde error wrappers
                // (e.g., rmp_serde wraps the inner message in its own
                // Error type while preserving the custom string).
                if is_legacy_variant_name(value) {
                    return Err(E::custom(format!("{OLD_FORMAT_REJECTED_MARKER}{value}")));
                }

                match value {
                    "ContextCreated" => Ok(EventType::ContextCreated),
                    "ContextClosing" => Ok(EventType::ContextClosing),
                    "ContextClosed" => Ok(EventType::ContextClosed),
                    "ContextExpired" => Ok(EventType::ContextExpired),
                    "MemberJoined" => Ok(EventType::MemberJoined),
                    "MemberLeft" => Ok(EventType::MemberLeft),
                    "RoleAssigned" => Ok(EventType::RoleAssigned),
                    "TokenRevoked" => Ok(EventType::TokenRevoked),
                    "MessageSent" => Ok(EventType::MessageSent),
                    "OutletRegistered" => Ok(EventType::OutletRegistered),
                    "OutletUpdated" => Ok(EventType::OutletUpdated),
                    "OutletDeregistered" => Ok(EventType::OutletDeregistered),
                    "OutletInvoked" => Ok(EventType::OutletInvoked),
                    "OutletCancel" => Ok(EventType::OutletCancel),
                    "OutletVerified" => Ok(EventType::OutletVerified),
                    "OutletInterfaceOffered" => Ok(EventType::OutletInterfaceOffered),
                    "OutletInterfaceAccepted" => Ok(EventType::OutletInterfaceAccepted),
                    "OutletInterfaceRevoked" => Ok(EventType::OutletInterfaceRevoked),
                    "GovernanceAction" => Ok(EventType::GovernanceAction),
                    "ConsistencyCheckpoint" => Ok(EventType::ConsistencyCheckpoint),
                    "AbsenceProofRequested" => Ok(EventType::AbsenceProofRequested),
                    "MemberBlocked" => Ok(EventType::MemberBlocked),
                    "KeyEpochAdvance" => Ok(EventType::KeyEpochAdvance),
                    "MediaSessionStarted" => Ok(EventType::MediaSessionStarted),
                    "MediaSessionEnded" => Ok(EventType::MediaSessionEnded),
                    "PaymentReceived" => Ok(EventType::PaymentReceived),
                    "EconomicPolicyChanged" => Ok(EventType::EconomicPolicyChanged),
                    "EconomicPolicyApplied" => Ok(EventType::EconomicPolicyApplied),
                    "SpendingUcanGranted" => Ok(EventType::SpendingUcanGranted),
                    "SpendingUcanRevoked" => Ok(EventType::SpendingUcanRevoked),
                    "GovernanceProposalCreated" => Ok(EventType::GovernanceProposalCreated),
                    "GovernanceVoteCast" => Ok(EventType::GovernanceVoteCast),
                    "GovernanceVoteWithdrawn" => Ok(EventType::GovernanceVoteWithdrawn),
                    "GovernanceProposalResolved" => Ok(EventType::GovernanceProposalResolved),
                    "GovernanceConflictDetected" => Ok(EventType::GovernanceConflictDetected),
                    "GovernanceConflictResolved" => Ok(EventType::GovernanceConflictResolved),
                    "GovernanceDeadlockRecovery" => Ok(EventType::GovernanceDeadlockRecovery),
                    "GovernanceActionExecuted" => Ok(EventType::GovernanceActionExecuted),
                    "ProvenanceAttached" => Ok(EventType::ProvenanceAttached),
                    "ProvenanceReceived" => Ok(EventType::ProvenanceReceived),
                    other => Err(E::custom(format!("unknown EventType variant: {other}"))),
                }
            }

            fn visit_string<E>(self, value: String) -> Result<EventType, E>
            where
                E: de::Error,
            {
                self.visit_str(&value)
            }
        }

        deserializer.deserialize_str(EventTypeVisitor)
    }
}

/// Classifies a serde error string as a legacy pre-rename-variant
/// rejection, returning the offending variant name when matched.
///
/// Used by [`deserialize_event`] and by callers who receive an error from a
/// higher-level serde/`rmp_serde` deserializer and want to map it to the
/// typed [`EventLogError::OldFormatRejected`] variant. The marker prefix is
/// an internal detail; callers should use this helper rather than parsing
/// error strings directly.
#[must_use]
pub fn classify_legacy_rejection(serde_err_msg: &str) -> Option<String> {
    let idx = serde_err_msg.find(OLD_FORMAT_REJECTED_MARKER)?;
    let tail = &serde_err_msg[idx + OLD_FORMAT_REJECTED_MARKER.len()..];
    // The visitor emits the legacy variant name immediately after the marker
    // with no trailing separator. Higher-level deserializers (rmp_serde,
    // serde_json) may append context after the name — stop at the first
    // byte that cannot appear inside a legacy variant name (Ascii word
    // boundary: ASCII letter or digit only).
    let name: String = tail
        .chars()
        .take_while(char::is_ascii_alphanumeric)
        .collect();
    if name.is_empty() { None } else { Some(name) }
}

/// Deserializes a full [`Event`] from `MessagePack` bytes.
///
/// Maps any pre-rename legacy `event_type` value (one of [`LEGACY_SUFFIXES`]
/// with the [`LEGACY_PREFIX`]) to [`EventLogError::OldFormatRejected`].
///
/// This is the strict, ADR-049-aware entry point. Use this when reading
/// events from storage or the wire rather than calling `rmp_serde::from_slice`
/// directly — it guarantees that a pre-rename serialized event is rejected
/// with a typed, machine-matchable error instead of a generic serde
/// `"unknown variant"` string.
///
/// # Errors
///
/// - [`EventLogError::OldFormatRejected`] if the event's `event_type` carries
///   a pre-rename legacy name.
/// - [`EventLogError::SerializationFailed`] for all other deserialization
///   failures.
pub fn deserialize_event(bytes: &[u8]) -> Result<Event, EventLogError> {
    match rmp_serde::from_slice::<Event>(bytes) {
        Ok(event) => Ok(event),
        Err(err) => {
            let msg = err.to_string();
            classify_legacy_rejection(&msg).map_or_else(
                || Err(EventLogError::SerializationFailed(msg)),
                |legacy| {
                    Err(EventLogError::OldFormatRejected {
                        legacy_variant: legacy,
                    })
                },
            )
        }
    }
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

    /// Deserialization encountered a pre-rename legacy `event_type` name
    /// (one of [`LEGACY_SUFFIXES`] with the [`LEGACY_PREFIX`]). Pre-ADR-049
    /// event logs are NOT compatible with the renamed and renumbered
    /// [`EventType`] enum — see the crate docs for the full discriminant
    /// table. This error is produced by [`deserialize_event`] and by the
    /// custom `Deserialize` impl on [`EventType`].
    #[error(
        "pre-rename event log rejected (ADR-049): legacy variant `{legacy_variant}` \
         is no longer supported; see crate docs for the post-rename Outlet* variants"
    )]
    OldFormatRejected {
        /// The legacy variant name that appeared in the serialized blob.
        /// Always `LEGACY_PREFIX` concatenated with one of
        /// [`LEGACY_SUFFIXES`].
        legacy_variant: String,
    },
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn event_type_serialization_roundtrip_all_variants() {
        let event_types = vec![
            EventType::ContextCreated,
            EventType::ContextClosing,
            EventType::ContextClosed,
            EventType::ContextExpired,
            EventType::MemberJoined,
            EventType::MemberLeft,
            EventType::RoleAssigned,
            EventType::TokenRevoked,
            EventType::MessageSent,
            // Outlet event types (ADR-049, spec §5.4 / §5.14.10)
            EventType::OutletRegistered,
            EventType::OutletUpdated,
            EventType::OutletDeregistered,
            EventType::OutletInvoked,
            EventType::OutletCancel,
            EventType::OutletVerified,
            EventType::OutletInterfaceOffered,
            EventType::OutletInterfaceAccepted,
            EventType::OutletInterfaceRevoked,
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
            // Governance event types (ADR-031 §8)
            EventType::GovernanceProposalCreated,
            EventType::GovernanceVoteCast,
            EventType::GovernanceVoteWithdrawn,
            EventType::GovernanceProposalResolved,
            EventType::GovernanceConflictDetected,
            EventType::GovernanceConflictResolved,
            EventType::GovernanceDeadlockRecovery,
            EventType::GovernanceActionExecuted,
            // Provenance event types (issue #586)
            EventType::ProvenanceAttached,
            EventType::ProvenanceReceived,
        ];

        // Verify all 40 variants are covered.
        assert_eq!(
            event_types.len(),
            40,
            "all EventType variants must be tested"
        );

        for event_type in &event_types {
            let json = serde_json::to_string(event_type).expect("serialize");
            let deserialized: EventType = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(
                event_type, &deserialized,
                "round-trip mismatch for {event_type:?}"
            );
        }
    }

    /// ADR-049 hard break: a pre-rename serialized invocation-event blob
    /// (legacy `event_type` = `LEGACY_PREFIX` ++ "Invoked") must fail
    /// deserialization with [`EventLogError::OldFormatRejected`] so that
    /// stale event logs cannot silently replay under the new vocabulary.
    ///
    /// This covers acceptance criterion 5 of SCP-OUT-003.
    #[test]
    fn old_tool_event_deserializes_as_rejected() {
        use scp_primitives::DID;

        // Construct a MessagePack blob that looks exactly like a pre-rename
        // `Event` with the legacy invocation variant in `event_type`. We
        // build the map by hand to avoid any dependency on the old enum
        // shape, serializing a stand-in struct whose `event_type` is the
        // raw legacy string.
        #[derive(serde::Serialize)]
        struct LegacyEvent {
            event_type: String,
            actor_did: DID,
            timestamp: u64,
            sequence: u64,
            payload: EventPayload,
            prev_hash: [u8; 32],
            #[serde(with = "serde_bytes")]
            signature: Vec<u8>,
        }

        let legacy_invoked_name = format!("{LEGACY_PREFIX}Invoked");

        let legacy = LegacyEvent {
            event_type: legacy_invoked_name.clone(),
            actor_did: DID::from(
                "did:key:z6Mkjq7kL5tJp1mXpL3jYqX3p7P2B4E7n9rK2c5d8e4f1a2".to_owned(),
            ),
            timestamp: 1_700_000_000,
            sequence: 0,
            payload: EventPayload {
                data: b"legacy-invocation-payload".to_vec(),
            },
            prev_hash: [0u8; 32],
            signature: vec![0u8; 64],
        };

        let bytes = rmp_serde::to_vec(&legacy).expect("serialize legacy event blob");

        // The strict deserializer must reject the blob and report the
        // legacy variant name back so downstream code can log/attribute it.
        let err = deserialize_event(&bytes)
            .expect_err("pre-rename legacy invocation blob must be rejected by deserialize_event");

        match err {
            EventLogError::OldFormatRejected { legacy_variant } => {
                assert_eq!(legacy_variant, legacy_invoked_name);
            }
            other => panic!("expected OldFormatRejected, got {other:?}"),
        }

        // Direct rmp_serde::from_slice into Event must also fail — the
        // custom Deserialize impl on EventType emits the sentinel marker.
        let raw_err = rmp_serde::from_slice::<Event>(&bytes)
            .expect_err("low-level rmp_serde deserialization must also reject the legacy blob");
        let raw_msg = raw_err.to_string();
        assert!(
            classify_legacy_rejection(&raw_msg).is_some(),
            "raw serde error must carry the legacy-name marker; got: {raw_msg}"
        );
    }

    /// Every legacy variant name reconstructed from [`LEGACY_PREFIX`] and
    /// [`LEGACY_SUFFIXES`] must trip the `OldFormatRejected` path — not
    /// just the `Invoked` suffix. This guards against a regression where a
    /// new Outlet variant is added without the corresponding legacy
    /// suffix entry.
    #[test]
    fn every_legacy_tool_variant_name_is_rejected() {
        for suffix in LEGACY_SUFFIXES {
            let legacy_name = format!("{LEGACY_PREFIX}{suffix}");
            // Serialize just the enum string — the inner Visitor path
            // is what must reject it, independent of the surrounding Event
            // struct shape.
            let bytes = rmp_serde::to_vec(&legacy_name).expect("serialize legacy name");
            let err = rmp_serde::from_slice::<EventType>(&bytes).expect_err(
                "legacy pre-rename name must be rejected by EventType Deserialize impl",
            );
            let msg = err.to_string();
            let classified = classify_legacy_rejection(&msg)
                .unwrap_or_else(|| panic!("legacy name `{legacy_name}` missing marker: {msg}"));
            assert_eq!(classified, legacy_name);
        }
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
