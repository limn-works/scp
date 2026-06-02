//! Context lifecycle types for SCP.
//!
//! Pure protocol types: `ContextState`, `ContextError`, `context_id_bytes`, and
//! submodule declarations for moved modules. Async types (`ContextHandle`,
//! builder, manager, providers, ttl, etc.) remain in scp-runtime.

pub mod broadcast;
pub mod broadcast_content;
pub mod builder;
pub mod close;
pub mod governance;
pub mod invitation;
pub mod membership;
pub mod memory_scope;
pub mod metadata;
pub mod nesting;
pub mod outlets;
pub mod params;
pub mod policy;
pub mod promotion;
pub mod roles;
pub mod state_machine;
pub mod templates;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// Re-exports for backward compatibility — downstream code uses `crate::context::X`.
pub use broadcast::{
    AuthorState, BroadcastAdmission, BroadcastContext, BroadcastContextSnapshot, KeyRequestDecision,
};
pub use broadcast_content::{BroadcastContent, BroadcastContentError};
pub use governance::{
    AccessScope, CheckpointAttestationStatus, ConflictResolution, CosignedCheckpoint,
    GovernanceAction, GovernanceContext, GovernanceEngine, GovernanceError, GovernanceEvent,
    GovernanceModelConfig, GovernanceProposal, GovernanceReconfigAction, KeyResolver, ProposalId,
    ProposalStatus, RejectionReason, SignedVote, VoteType, actions_conflict, compute_proposal_id,
    sign_vote, verify_proposal_votes, verify_vote,
};
pub use membership::{MemberInfo, MembershipState};
pub use nesting::{compute_ceiling_intersection, validate_child_ttl, validate_nesting_depth};
pub use outlets::errors::OutletError;
pub use params::{
    BridgeCapability, BridgeDirectionality, BridgeMetadata, Capability, CeilingPolicy, ContextMode,
    ContextParams, FieldVisibility, GovernanceModel, MemoryScope, MetadataVisibilityPolicy,
    MigrationSource, OutletRegistration, ProjectionOverride, ProjectionPolicy, ProjectionRule,
    PromotionPolicy, PublicMetadata, RoleDefinition, RuntimeMetadata, TemplateId,
    decode_protocol_version, encode_protocol_version,
};
pub use roles::{
    CapabilityCeiling, ContextRoleState, RoleAssignment, RoleError, UcanAttestation, UcanToken,
    assign_role, builtin_admin, builtin_author, builtin_broadcast_roles, builtin_member,
    builtin_moderator, builtin_observer, builtin_roles, builtin_subscriber, check_ceiling,
    validate_role_definition,
};
pub use state_machine::transition;
pub use templates::{TemplateError, template_params, validate_against_template};

/// Converts a `context_id` string to a deterministic 32-byte array using SHA-256.
///
/// This is the **canonical** context ID byte representation used across all
/// context operations: builder, manager, TTL, memory scope, and any code that
/// needs a `[u8; 32]` from a context ID string. Using SHA-256 ensures:
/// - Fixed output size regardless of input length (no truncation/collision).
/// - Uniform distribution (suitable as cryptographic key material identifiers).
/// - No information leakage about input length (unlike zero-padding).
///
/// # CRITICAL: All modules MUST use this function.
/// Using raw UTF-8 bytes (truncation/zero-padding) produces different values
/// than SHA-256 for the same input, causing crypto operations to address the
/// wrong MLS groups, sender keys, and event logs.
#[must_use]
pub fn context_id_bytes(context_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(context_id.as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    bytes
}

/// Domain separator for context-based routing IDs.
///
/// Routing IDs are the values relays use to route messages to subscribers.
/// Using a domain separator prevents collisions with raw context ID hashes
/// (used internally for MLS groups, sender keys, event logs) and with
/// DID-based routing IDs (`"scp:did:"` prefix — see `scp-identity`).
const CONTEXT_ROUTING_DOMAIN_SEPARATOR: &[u8] = b"scp:context-routing:";

/// Derives a 32-byte routing ID from a context ID string using
/// domain-separated SHA-256.
///
/// The routing ID is `SHA-256("scp:context-routing:" || context_id)`.
/// This is distinct from [`context_id_bytes`] (raw `SHA-256(context_id)`)
/// which is used for internal crypto keying (MLS groups, sender keys, event
/// logs). The domain separator prevents routing-level collisions with other
/// hash domains.
///
/// Both the send path (`ContextManager::send_message`) and the subscribe
/// path (`context_subscribe`) MUST use this function so that the relay
/// routes messages to the correct subscribers.
#[must_use]
pub fn context_routing_id(context_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CONTEXT_ROUTING_DOMAIN_SEPARATOR);
    hasher.update(context_id.as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    bytes
}

/// Derives a 32-byte routing ID for broadcast contexts using plain SHA-256.
///
/// Broadcast contexts use `SHA-256(context_id)` without the
/// `"scp:context-routing:"` domain separator, per spec §5.14. This matches
/// [`context_id_bytes`] by design — broadcast routing IDs are the raw hash
/// of the context ID string, distinct from the domain-separated
/// [`context_routing_id`] used by encrypted contexts.
#[must_use]
pub fn broadcast_routing_id(context_id: &str) -> [u8; 32] {
    context_id_bytes(context_id)
}

// ---------------------------------------------------------------------------
// ContextState
// ---------------------------------------------------------------------------

/// The seven lifecycle states of an SCP context.
///
/// Valid transitions:
/// - `Creating -> Active` -- MLS group formed, initial parameters committed.
/// - `Active -> Closing` -- Close initiated by admin or governance.
/// - `Active -> Expired` -- TTL elapsed (automatic, no governance override).
/// - `Active -> MigratingOut` -- Migration approved, grace period active (§5.11A).
/// - `Closing -> Closed` -- All members processed final events, keys destroyed.
/// - `MigratingOut -> Tombstoned` -- Grace period expired, context permanently
///   points to destination (§5.11A.5).
/// - `MigratingOut -> Active` -- Migration cancelled before grace period ends.
///
/// `Closed`, `Expired`, and `Tombstoned` are terminal states -- no further
/// transitions are permitted. See ADR-008 and spec §5.11A.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContextState {
    /// Context is being created. MLS group formation and parameter validation
    /// are in progress. If any step fails, the context is dropped without
    /// reaching `Active`.
    Creating,
    /// Context is fully operational. Messages, tool invocations, and membership
    /// changes are permitted according to the context's roles and capabilities.
    Active,
    /// Context closure has been initiated. Members have a window to process
    /// final events and verify summaries before keys are destroyed.
    Closing,
    /// Context is permanently closed. All key material has been destroyed.
    /// Content is unreadable for ephemeral and summary memory scopes.
    Closed,
    /// Context has expired due to TTL elapsing. This is a terminal state
    /// distinct from `Closed` -- TTL expiry skips the cooperative closing
    /// window. See spec section 5.10.
    Expired,
    /// Context migration has been approved and the source context is in a
    /// read-only grace period (§5.11A.4). No new messages, tool invocations,
    /// or governance actions (except migration cancellation) are accepted.
    /// Members can still read existing content.
    MigratingOut,
    /// Context has been permanently tombstoned after migration (§5.11A.5).
    /// Carries a pointer to the destination context. Terminal state.
    Tombstoned,
}

impl std::fmt::Display for ContextState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Creating => write!(f, "Creating"),
            Self::Active => write!(f, "Active"),
            Self::Closing => write!(f, "Closing"),
            Self::Closed => write!(f, "Closed"),
            Self::Expired => write!(f, "Expired"),
            Self::MigratingOut => write!(f, "MigratingOut"),
            Self::Tombstoned => write!(f, "Tombstoned"),
        }
    }
}

// ---------------------------------------------------------------------------
// ContextError
// ---------------------------------------------------------------------------

/// Errors produced by context lifecycle operations.
///
/// Error codes follow the `SCP-CTX-` prefix (range 2000-2999) as defined in
/// `.docs/standards/sdk-common.md`.
#[derive(Debug, thiserror::Error)]
pub enum ContextError {
    /// A state transition was requested that is not permitted by the context
    /// lifecycle state machine. See [`state_machine::transition`] for valid
    /// transitions.
    #[error("invalid context state transition from {from} to {to}")]
    InvalidTransition {
        /// The current state of the context.
        from: ContextState,
        /// The requested target state.
        to: ContextState,
    },

    /// An attempt was made to modify an immutable capability ceiling.
    ///
    /// This error is returned when [`CeilingPolicy::Immutable`] is set and
    /// a ceiling modification is attempted.
    #[error("capability ceiling is immutable and cannot be modified")]
    CeilingImmutable,

    /// An operation was attempted that requires the context to be in the
    /// `Active` state, but the context is in a different state.
    #[error("context is not in Active state")]
    ContextNotActive,

    /// An operation was attempted on a context that has been permanently closed.
    /// All key material has been destroyed and the context cannot be used.
    #[error("context is closed")]
    ContextClosed,

    /// An operation was attempted on a context that has expired due to TTL.
    /// The context is in a terminal state and cannot be used.
    #[error("context has expired")]
    ContextExpired,

    /// Template validation failed: the [`ContextParams`] fields do not match
    /// the template definition. See [`templates::validate_against_template`].
    #[error(transparent)]
    TemplateMismatch(#[from] templates::TemplateError),

    /// A membership operation failed (join, leave).
    #[error("membership operation failed: {0}")]
    MembershipFailed(String),

    /// A crypto operation failed during a membership or messaging operation.
    #[error("crypto operation failed: {0}")]
    CryptoFailed(String),

    /// A transport operation failed during messaging.
    #[error("transport operation failed: {0}")]
    TransportFailed(String),

    /// An event log operation failed.
    #[error("event log operation failed: {0}")]
    EventLogFailed(String),

    /// The sender does not have the required UCAN capability.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// The specified member was not found in the context.
    #[error("member not found: {0}")]
    MemberNotFound(String),

    /// An operation was attempted while the context or subcomponent is in an
    /// unexpected state (e.g., summary window already disputed).
    #[error("invalid state: {0}")]
    InvalidState(String),

    /// A key package validation failed.
    #[error("invalid key package: {0}")]
    InvalidKeyPackage(String),

    /// A governance action would exceed a protocol-level collection size limit
    /// (§5.9). The message includes the limit value for debuggability.
    #[error("limit exceeded: {0}")]
    LimitExceeded(String),

    /// An invalid memory scope was requested for a broadcast context.
    ///
    /// Broadcast contexts only support `MemoryScope::Full` because they lack
    /// MLS group management and cannot deliver the key destruction semantics
    /// required by `Ephemeral` and `Summary` scopes.
    #[error("broadcast contexts only support MemoryScope::Full")]
    InvalidMemoryScopeForBroadcast,

    /// Attempted to restore access that was never revoked (§5.9).
    ///
    /// Restoring read or write access for a member whose access was never
    /// revoked is an error — there is nothing to restore.
    #[error("nothing to restore: {0}")]
    NothingToRestore(String),

    /// An action-payment integration error occurred during a paid action.
    ///
    /// Wraps `IntegrationError` to preserve the specific
    /// error variant (authorization failure, cost insufficient, adapter error,
    /// etc.) rather than type-erasing to a string.
    ///
    /// NOTE: This variant embeds `IntegrationError` from the economy module.
    /// Cross-crate type resolution is deferred to compilation fix phase.
    ///
    /// See spec section 19.2.2.
    #[error("payment integration failed: {0}")]
    IntegrationFailed(String),

    /// A persistence operation failed (store or load).
    ///
    /// Returned when the `ContextPersistence` provider reports an error
    /// during context or broadcast state persistence or restoration.
    #[error("persistence failed: {0}")]
    PersistenceFailed(String),

    /// A governance operation failed (proposal, vote, engine error).
    ///
    /// Returned when the [`GovernanceEngine`] reports an error during
    /// proposal creation, voting, or resolution.
    #[error("governance failed: {0}")]
    GovernanceFailed(String),

    /// Context creation failed due to invalid parameters or internal error.
    #[error("creation failed: {0}")]
    CreationFailed(String),

    /// An operation was attempted on a context that is not registered with
    /// the `ContextManager`. This typically means the context was never
    /// created, was already closed, or the ID is incorrect.
    #[error("context not registered: {0}")]
    ContextNotRegistered(String),

    /// The local SDK's protocol version does not meet the context's minimum
    /// protocol version requirement (spec §13.4).
    ///
    /// The SDK MUST reject attempts to join a context whose
    /// `min_protocol_version` exceeds the SDK's supported version. This is
    /// enforced client-side during the join flow.
    #[error(
        "protocol version incompatible: context requires {required_major}.{required_minor}, \
         SDK supports {supported_major}.{supported_minor}"
    )]
    VersionIncompatible {
        /// The minimum major version the context requires.
        required_major: u8,
        /// The minimum minor version the context requires.
        required_minor: u8,
        /// The major version the SDK supports.
        supported_major: u8,
        /// The minor version the SDK supports.
        supported_minor: u8,
    },

    /// The operation was rejected by the Matrix Synapse–style hard rate
    /// limit layered on top of the per-DID economic escalation (§19.7).
    ///
    /// Defense-in-depth cap: a burst of operations above the token
    /// bucket capacity is rejected regardless of cost, even when no
    /// economic policy is configured. Applies to the messaging, join,
    /// and tool invoke paths. Mapped to the canonical `SCP-ECON-12090`
    /// code through the bridge error translators.
    ///
    /// `resource` identifies which path tripped the limit (`"send"`,
    /// `"join"`, or `"tool_invoke"`) so callers can apply path-specific
    /// back-off strategies. Untyped `PermissionDenied` predated this
    /// variant; the three call sites were migrated as part of D4.
    #[error("SCP-ECON-12090: rate limit exceeded on {resource}: {message}")]
    RateLimited {
        /// The path that tripped the limit (e.g., `"send"`, `"join"`,
        /// `"tool_invoke"`).
        resource: String,
        /// Human-readable explanation of the bucket state.
        message: String,
    },

    /// An imported snapshot attempted to regress a per-sender
    /// monotonic floor (sender-key epoch, spending nonce, etc.)
    /// relative to the local state. Rejected atomically per spec
    /// §23.17 invariants 3 and 4 (import max-merge + append-only
    /// dominance).
    ///
    /// `per_sender_deltas` carries every `(sender_did, local_floor,
    /// incoming_floor)` tuple where `incoming_floor < local_floor`
    /// so the caller can report the exact divergence. The import is
    /// rejected WHOLE — no partial merge is applied, matching the
    /// §23.17 Invariant 3 "reject atomically if any member's floor
    /// would regress" clause.
    #[error(
        "SCP-CTX-2091: snapshot floor regression on {resource}: \
         {} sender(s) would regress",
        .per_sender_deltas.len()
    )]
    SnapshotFloorRegression {
        /// Which monotonic resource class the regression applies to:
        /// `"sender_key_epoch"`, `"spending_nonce"`, etc.
        resource: String,
        /// Per-sender `(did, local_floor, incoming_floor)` tuples
        /// where `incoming_floor < local_floor`.
        per_sender_deltas: Vec<(String, u64, u64)>,
    },

    /// An imported snapshot was rejected for carrying authorization or
    /// trust-state fields that failed validation against the importing
    /// node's policy.
    ///
    /// Distinct from [`Self::SnapshotFloorRegression`], which covers
    /// monotonic per-sender floors. `ImportRejected` covers structural
    /// or semantic violations: tampered consequence rules, attacker-
    /// chosen budget grants, forged approved-proposal entries, cooldown
    /// indices that point at nonexistent rules, etc.
    ///
    /// The `reason` string carries a human-readable explanation suitable
    /// for logging and SDK error messages. Mapped to canonical code
    /// `SCP-CTX-2092` through every FFI bridge translator so callers can
    /// switch on `.code` instead of string-matching.
    #[error("SCP-CTX-2092: snapshot import rejected: {reason}")]
    ImportRejected {
        /// Human-readable explanation of why the import was rejected.
        reason: String,
    },
    /// A previously broadcasted MLS Commit (`RemoveMember`, `RotateContentKeys`,
    /// `ResetMember`, or `LeaveContext`) exceeded the persistent retry budget
    /// and the context is in fail-close state (PR #1606 C6).
    ///
    /// Subsequent context-mutating operations on the affected context return
    /// this error until an operator acknowledges the fault via
    /// `ContextManager::acknowledge_commit_fault`. The local state mutation
    /// already happened, but at least one remote member did not advance
    /// their MLS epoch — preventing further governance from a divergent
    /// epoch is required to avoid silently retaining ejected members.
    #[error(
        "SCP-CTX-2120: commit broadcast fault for operation {operation}: \
         {reason} ({attempts} attempts)"
    )]
    CommitBroadcastFault {
        /// Human-readable label for the operation that failed to broadcast.
        operation: String,
        /// Final transport error or `"max age exceeded"`.
        reason: String,
        /// Total number of send attempts.
        attempts: u32,
    },

    /// A typed §5.4.4 outlet invocation error escaped to the runtime
    /// `Result<…, ContextError>` seam (SCP-OUT-027).
    ///
    /// The wrapped [`OutletError`] preserves the §5.4.4 envelope shape
    /// (`code`, `slug`, `class`, `retry`, `detail`, `pad_nonce`,
    /// `registration_event_id`) so SDKs and bridges can dispatch on the
    /// typed structure rather than parsing free-form `PermissionDenied`
    /// strings.
    ///
    /// `OutletError` is `Box`-wrapped to keep `ContextError` compact —
    /// the typed envelope is ~264 bytes (HMAC + nonce + registration id)
    /// and inlining it inflates every `Result<_, ContextError>` return
    /// across the runtime. Boxing keeps the variant payload at one
    /// pointer (clippy `result_large_err`).
    ///
    /// At this seam the runtime does NOT have access to the per-outlet
    /// `outlet_message_key` / `registration_event_id` — wire-form
    /// HMAC transmission is out of scope at the `Result<…, ContextError>`
    /// boundary (which is consumed by FFI translators and Rust callers,
    /// never serialized as a §5.4.4 wire envelope here). The
    /// `OutletError` is therefore constructed via
    /// [`OutletError::from_invocation_error_template`], which synthesizes
    /// deterministic placeholder values for those fields. Cross-context
    /// wire emission happens at a separate seam (SCP-OUT-029
    /// `wrap_cross_context_error`) where the real per-outlet key is in
    /// scope.
    #[error("{0}")]
    OutletInvocation(Box<OutletError>),

    /// A §5.4.5 streaming-escrow reservation (open-time hold or per-grant
    /// top-up) was rejected because the invoker's available budget — the
    /// `MemberBudgetTracker` remaining, AND-composed with any spending-UCAN
    /// `max_per_action` ceiling (§19.5) — is below the requested escrow.
    ///
    /// The reservation is the authoritative balance gate for streaming:
    /// the hold is DEBITED on `MemberBudgetTracker` under the context lock
    /// at the moment of acceptance, so two concurrent opens cannot both
    /// reserve against the same balance. The unspent portion is refunded
    /// at stream close (`outlet_stream_settle`).
    ///
    /// Maps to `OutletErrorClass::Economic::InsufficientFunds`
    /// (`economic.insufficient-funds`, `SCP-TOOL-6150`) in the §5.4.4
    /// outlet envelope and surfaces through the streaming bridges as
    /// `OpenStreamRejection::InsufficientFunds`. Canonical code
    /// `SCP-ECON-12012`.
    #[error("SCP-ECON-12012: streaming escrow reservation insufficient funds: {0}")]
    EscrowInsufficientFunds(String),

    /// A §5.4.5 streaming-escrow reservation overflowed the `Amount`
    /// (`u64`) field when computing `cost_per_chunk × count` via
    /// `checked_mul`.
    ///
    /// Maps to `OutletErrorClass::Economic::EscrowOverflow`
    /// (`economic.escrow-overflow`, `SCP-TOOL-6150`) and surfaces through
    /// the streaming bridges as `OpenStreamRejection::EscrowOverflow`.
    /// Canonical code `SCP-ECON-12013`.
    #[error("SCP-ECON-12013: streaming escrow reservation overflow: {0}")]
    EscrowOverflow(String),
}

impl From<OutletError> for ContextError {
    fn from(error: OutletError) -> Self {
        Self::OutletInvocation(Box::new(error))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn context_routing_id_is_deterministic() {
        let id1 = context_routing_id("test-ctx");
        let id2 = context_routing_id("test-ctx");
        assert_eq!(id1, id2);
    }

    #[test]
    fn context_routing_id_differs_from_context_id_bytes() {
        // The routing ID MUST differ from the raw context_id_bytes because
        // it uses a domain separator. If they matched, the domain separator
        // would be meaningless.
        let raw = context_id_bytes("test-ctx");
        let routing = context_routing_id("test-ctx");
        assert_ne!(raw, routing);
    }

    #[test]
    fn context_routing_id_different_inputs_produce_different_outputs() {
        let id_a = context_routing_id("ctx-alpha");
        let id_b = context_routing_id("ctx-beta");
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn context_routing_id_uses_domain_separator() {
        // Manually compute what context_routing_id should produce.
        let mut hasher = Sha256::new();
        hasher.update(b"scp:context-routing:");
        hasher.update(b"test-ctx");
        let expected = hasher.finalize();

        let actual = context_routing_id("test-ctx");
        assert_eq!(&actual[..], &expected[..]);
    }

    #[test]
    fn broadcast_routing_id_equals_context_id_bytes() {
        // Broadcast contexts use plain SHA-256(context_id) per spec §5.14,
        // which is the same as context_id_bytes.
        let broadcast = broadcast_routing_id("test-ctx");
        let raw = context_id_bytes("test-ctx");
        assert_eq!(
            broadcast, raw,
            "broadcast_routing_id must equal context_id_bytes"
        );
    }

    #[test]
    fn broadcast_routing_id_differs_from_context_routing_id() {
        // Broadcast routing ID (no domain separator) must differ from
        // encrypted context routing ID (domain-separated).
        let broadcast = broadcast_routing_id("test-ctx");
        let encrypted = context_routing_id("test-ctx");
        assert_ne!(
            broadcast, encrypted,
            "broadcast and encrypted routing IDs must differ"
        );
    }

    #[test]
    fn broadcast_routing_id_is_deterministic() {
        let id1 = broadcast_routing_id("test-ctx");
        let id2 = broadcast_routing_id("test-ctx");
        assert_eq!(id1, id2);
    }
}
