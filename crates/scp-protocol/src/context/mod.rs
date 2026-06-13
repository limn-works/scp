//! Context lifecycle types for SCP.
//!
//! Pure protocol types: `ContextState`, `ContextError`, `context_id_bytes`, and
//! submodule declarations for moved modules. Async types (`ContextHandle`,
//! builder, manager, providers, ttl, etc.) remain in scp-runtime.

pub mod broadcast;
pub mod broadcast_content;
pub mod builder;
pub mod close;
pub mod export;
pub mod governance;
pub mod invitation;
pub mod membership;
pub mod memory_scope;
pub mod metadata;
pub mod nesting;
pub mod params;
pub mod policy;
pub mod promotion;
pub mod roles;
pub mod state_machine;
pub mod templates;
pub mod tools;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// Re-exports for backward compatibility — downstream code uses `crate::context::X`.
pub use broadcast::{
    AuthorState, BroadcastAdmission, BroadcastContext, BroadcastContextSnapshot, KeyRequestDecision,
};
pub use broadcast_content::{BroadcastContent, BroadcastContentError};
pub use export::{EXPORT_SCOPE_TAG_FULL, EXPORT_SCOPE_TAG_PUBLIC};
pub use governance::{
    AccessScope, CheckpointAttestationStatus, ConflictResolution, CosignedCheckpoint,
    GovernanceAction, GovernanceContext, GovernanceEngine, GovernanceError, GovernanceEvent,
    GovernanceModelConfig, GovernanceProposal, GovernanceReconfigAction, KeyResolver, ProposalId,
    ProposalStatus, RejectionReason, SignedVote, VoteType, actions_conflict, compute_proposal_id,
    sign_vote, verify_proposal_votes, verify_vote,
};
pub use membership::{MemberInfo, MembershipState};
pub use nesting::{compute_ceiling_intersection, validate_child_ttl, validate_nesting_depth};
pub use params::{
    BridgeCapability, BridgeDirectionality, BridgeMetadata, Capability, CeilingPolicy, ContextMode,
    ContextParams, FieldVisibility, GovernanceModel, MemoryScope, MetadataVisibilityPolicy,
    MigrationSource, ProjectionOverride, ProjectionPolicy, ProjectionRule, PromotionPolicy,
    PublicMetadata, RoleDefinition, RuntimeMetadata, TemplateId, ToolRegistration,
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
    /// The context's actor exhausted its respawn budget (ADR-049 §10): it
    /// crashed more than the permitted number of times inside the sliding
    /// crash window, so the supervisor stopped respawning it to avoid an
    /// infinite crash-respawn loop. The context is dormant — no actor is
    /// serving it — and operator intervention (clearing the poison and
    /// triggering a fresh respawn, or a process restart that re-runs the
    /// restore-all-contexts path) is required to recover. Reachable from
    /// `Active`; recovers to `Active` only via the operator-driven respawn.
    Poisoned,
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
            Self::Poisoned => write!(f, "Poisoned"),
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
    /// A `ContextExport` was rejected because its format `version` is not the
    /// current signed-export format (spec §23.16.8, §17.5; ADR-050).
    ///
    /// This is the **version gate**: it fires before any signature is checked,
    /// when `version != CURRENT_EXPORT_VERSION`. Pre-signing formats (unsigned
    /// v1, enumerated-subset-signed v2), the pre-scope-binding full-snapshot
    /// format (v3), and any future version are all rejected here.
    ///
    /// Deliberately DISTINCT from [`Self::SnapshotSignatureInvalid`]
    /// (`SCP-CTX-2093`, a *present-but-forged* signature) and from the generic
    /// [`Self::EventLogFailed`]: a caller can tell "the export predates / does
    /// not match the supported signed format" apart from "the signature did not
    /// authenticate the snapshot". Mapped to canonical code `SCP-CTX-2094`
    /// through every FFI bridge translator so callers can switch on `.code`.
    #[error("SCP-CTX-2094: unsupported context export format version: {reason}")]
    ExportVersionUnsupported {
        /// Human-readable explanation including the observed and required
        /// version numbers.
        reason: String,
    },
    /// The Ed25519 signature over an exported context snapshot failed
    /// verification against the exporter DID's resolved verification-method
    /// key (spec §23.16.8).
    ///
    /// Distinct from the event-log Merkle-chain failure (surfaced as
    /// [`Self::EventLogFailed`]) and from the version gate
    /// ([`Self::ExportVersionUnsupported`], `SCP-CTX-2094`): a version error
    /// means the export does not match the current signed format and was
    /// rejected before any signature was checked, whereas this error means the
    /// signature was
    /// present but did not authenticate the embedded snapshot — i.e. the
    /// membership, roles, ceiling, member/suspended capabilities, threshold set
    /// or value, governance model, economic policy, consequence rules,
    /// access-key store, or any other signed snapshot field was forged, or the
    /// exporter key could not be resolved. Mapped to canonical code
    /// `SCP-CTX-2093` through every FFI bridge translator so callers can switch
    /// on `.code`.
    #[error("SCP-CTX-2093: snapshot signature invalid: {reason}")]
    SnapshotSignatureInvalid {
        /// Human-readable explanation of why signature verification failed.
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

    /// A caller-side mailbox send exceeded the 30-second per-command
    /// backpressure deadline (ADR-049 §"Mailbox parameters"). The target
    /// [`ContextActor`](https://example.invalid) is draining slowly or
    /// backed up; the caller's command was never delivered to the actor
    /// and may be retried. Distinct from
    /// [`Self::RateLimited`], which rejects pre-mailbox on capability
    /// grounds.
    ///
    /// Mapped to canonical code `SCP-CTX-2130` through the bridge error
    /// translators.
    #[error("SCP-CTX-2130: actor is busy: {0}")]
    ActorBusy(String),

    /// A handler reached a code path that has not yet been migrated off
    /// the legacy `ContextManager` surface (ADR-049 commit ladder — actor
    /// handlers land incrementally in commits 7-11). The actor skeleton
    /// wires every command variant to a concrete return value rather than
    /// `unimplemented!()` / `todo!()` so the dispatch loop compiles and
    /// test fixtures observe a typed error.
    ///
    /// Production callers MUST NOT observe this variant once commit 12 of
    /// ADR-049 lands — by then every handler has migrated to the actor
    /// path. The CI gates fail the build if this variant is reachable
    /// from non-test code after that commit.
    ///
    /// Mapped to canonical code `SCP-CTX-2131` through the bridge error
    /// translators.
    #[error("SCP-CTX-2131: not implemented: {0}")]
    NotImplemented(String),

    /// A subsystem required for this operation has not been wired up yet.
    /// Distinct from `NotImplemented`: the operation itself exists and is
    /// migrated, but a dependency (e.g. the legacy `ContextManager` bridge
    /// during the commits-7-11 migration window) is absent.
    ///
    /// Mapped to canonical code `SCP-CTX-2132` through the bridge error
    /// translators.
    #[error("SCP-CTX-2132: not initialized: {0}")]
    NotInitialized(String),

    /// A transport operation exceeded its per-call timeout budget while
    /// invoked inside a context actor handler (ADR-049 §7 / plan §"Transport
    /// timeouts inside actor handlers"). Distinct from
    /// [`Self::TransportFailed`]: the transport layer did not return a
    /// typed error — it hung past the deadline and the handler gave up
    /// waiting so other mailbox commands can be drained.
    ///
    /// On timeout, handlers that had not yet committed their in-memory
    /// mutations roll back via RAII (see
    /// [`crate::context::SequenceReservation`](../../context/index.html)
    /// if applicable). Handlers that already mutated state report
    /// [`crate::context::builder::ContextCreationError`]-style partial
    /// success via `Outcome::err_mutated` so the per-context snapshot is
    /// persisted before the timeout error propagates.
    ///
    /// Mapped to canonical code `SCP-CTX-2133` through the bridge error
    /// translators.
    #[error("SCP-CTX-2133: transport timeout: {0}")]
    TransportTimeout(String),

    /// An application-data send into an encrypted multi-member context found
    /// an empty peer pseudonym registry (§9.10.4): no peer has announced its
    /// per-context routing ID yet, so there is nobody to fan the ciphertext
    /// out to.
    ///
    /// Distinct from a transport failure — the send was *aborted before* any
    /// transport call so the economy ticket and sequence reservation are
    /// rolled back, leaving the context unchanged. Raising a typed error
    /// (rather than silently succeeding with zero sends) lets callers
    /// distinguish "peers have not announced yet; retry after the
    /// `PseudonymAnnouncement` bootstrap completes" from a genuine delivery
    /// failure, and prevents the historic silent-drop that masked a
    /// bidirectional bootstrap deadlock.
    ///
    /// Single-member encrypted contexts with an empty registry succeed as a
    /// no-op (nobody to fan out to) — this variant is not raised for them.
    /// Announcements themselves use the shared-RID bootstrap channel and are
    /// never subject to this error.
    ///
    /// Mapped to canonical code `SCP-CTX-2095` through every FFI bridge
    /// translator.
    #[error(
        "SCP-CTX-2095: pseudonym registry empty for context '{context_id}' \
         (member_count={member_count}) — peers have not announced routing IDs; \
         app-data send aborted to avoid silent drop"
    )]
    PseudonymRegistryEmpty {
        /// The affected context ID.
        context_id: String,
        /// Current member count at rejection time.
        member_count: usize,
    },

    /// A per-member pseudonym was requested for a context that does not use
    /// pseudonymous routing — a broadcast context (§5.14). Broadcast contexts
    /// route on the derivable shared `SHA-256(context_id)` RID and carry no
    /// per-member pseudonym state, so there is nothing to return.
    ///
    /// Callers that want to handle both routing strategies should check the
    /// context mode first.
    ///
    /// Mapped to canonical code `SCP-CTX-2096` through every FFI bridge
    /// translator.
    #[error(
        "SCP-CTX-2096: context '{context_id}' is not a pseudonymous context — \
         broadcast contexts have no per-member pseudonym"
    )]
    NotPseudonymousContext {
        /// The affected context ID.
        context_id: String,
    },

    /// The context's actor exceeded its respawn budget (ADR-049 §10): it
    /// crashed more than the permitted number of times inside the sliding
    /// crash window, so the supervisor poisoned the context rather than
    /// respawning it again. No actor is serving the context; every
    /// subsequent per-context dispatch surfaces this error until an
    /// operator clears the poison (which triggers a single fresh respawn)
    /// or the process restarts and re-runs the restore-all-contexts path.
    ///
    /// The payload is the affected context id — never a panic payload (the
    /// supervisor watchdog deliberately discards the panic message, which
    /// could otherwise carry plaintext or key material).
    ///
    /// Mapped to canonical code `SCP-CTX-2134` through a dedicated
    /// translator arm in each non-WASM FFI bridge (`PyO3`, NAPI, `UniFFI`) — not
    /// the generic `SCP-CTX-2001` fallthrough — so a caller can detect a
    /// poisoned context. (WASM has no actor model per ADR-034, so it never
    /// produces this variant.)
    #[error(
        "SCP-CTX-2134: context is poisoned (exceeded respawn budget); \
         operator intervention required: {0}"
    )]
    ContextPoisoned(String),

    /// The context's actor crashed and the supervisor could not respawn it
    /// from the persisted snapshot (ADR-049 §10) — typically because no
    /// snapshot was found (the actor crashed before its first coalesced
    /// persist, so its in-memory state is unrecoverable), or because the
    /// snapshot failed to rehydrate. Distinct from
    /// [`Self::ContextPoisoned`]: the crash budget was not necessarily
    /// exhausted; the respawn itself was impossible this time.
    ///
    /// The payload is the affected context id — never a panic payload.
    ///
    /// Mapped to canonical code `SCP-CTX-2135` through a dedicated translator
    /// arm in each non-WASM FFI bridge (`PyO3`, NAPI, `UniFFI`) — not the generic
    /// `SCP-CTX-2001` fallthrough — so a caller can distinguish an
    /// unrecoverable crash from a poisoned context (`SCP-CTX-2134`) and from a
    /// generic context error. (WASM has no actor model per ADR-034, so it
    /// never produces this variant.)
    #[error("SCP-CTX-2135: context actor crashed and could not be respawned: {0}")]
    ActorCrashed(String),

    /// A join was attempted with a `KeyPackage` whose single-use HPKE init key
    /// was already consumed by a prior completed join (ADR-049 §9 two-anchor
    /// single-use model). The crypto-layer consumed-init-key backstop rejected
    /// the replay durably.
    ///
    /// Distinct from the generic [`Self::InvalidState`] (which also means
    /// "unknown reservation" and other transient state mismatches): a caller
    /// can tell a *security-relevant single-use replay* apart from an ordinary
    /// invalid-state error. The `KeyPackageStoreActor` also uses this variant
    /// to recognize its OWN prior already-completed join when a post-join
    /// tombstone write failed and the confirm is retried — turning the retry
    /// into an idempotent success rather than a permanent replay failure.
    ///
    /// Mapped to canonical code `SCP-CTX-2136` through a dedicated translator
    /// arm in each non-WASM FFI bridge (`PyO3`, NAPI, `UniFFI`) — not the generic
    /// `SCP-CTX-2001` fallthrough — so a caller can detect a single-use replay.
    /// (WASM has no actor model per ADR-034, so it never produces this variant.)
    #[error("SCP-CTX-2136: key package already consumed (init-key replay rejected): {0}")]
    KeyPackageReplay(String),
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
