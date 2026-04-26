//! Tool registration, schema validation, invocation lifecycle, and verification
//! for SCP contexts.
//!
//! Tools are stateless functions scoped to a context (spec section 5.4). They
//! have MCP-compatible JSON Schema interfaces (spec section 8.5), making them
//! interoperable with existing MCP tooling. Every tool registration includes
//! schema, implementation hash, test vectors, and operator DID -- providing
//! verifiable integrity (spec section 7.3.3).
//!
//! See ADR-010 in `.docs/adrs/phase-2.md` for the original design and ADR-049
//! for the streaming-native invocation redesign (§5).
//!
//! # Modules
//!
//! - [`registry`] -- Tool registration storage, `register_outlet`,
//!   `update_outlet`, `verify_outlet`.
//! - [`schema`] -- JSON Schema validation helpers and MCP compatibility.
//! - `invoke` (in `scp-runtime`) -- Outlet invocation with full execution
//!   lifecycle: capability checking, schema validation, timeout, cancellation.
//! - [`lifecycle`] -- Request types, terminal status, cancellation, and event
//!   log integration for outlet invocations.
//! - [`stream`] -- §5.4.5 streaming wire types: `OutletStreamOpen`,
//!   `OutletStreamChunk`, `OutletStreamCredit`, `ChunkPayload`,
//!   `StreamTerminalStatus`. The legacy non-streaming `OutletResponse` was
//!   deleted by SCP-OUT-032.
//!
//! # Types
//!
//! - [`OutletId`] -- Unique identifier for a registered tool.
//! - [`OutletError`] -- Error type for tool operations.
//! - [`OutletRegistration`] -- Full tool registration with schema, hash, test
//!   vectors, and operator DID. (Re-exported from [`registry`].)
//! - [`OutletSchema`] -- MCP-compatible JSON Schema for input/output.
//!   (Re-exported from [`registry`].)
//! - [`OutletTestVector`] -- Known input-output pair for tool verification.
//!   (Re-exported from [`registry`].)
//! - [`OutletRegistry`] -- In-memory tool storage per context.
//!   (Re-exported from [`registry`].)
//! - [`OutletRequest`] -- Tool invocation request. (Re-exported from
//!   [`lifecycle`].)
//! - [`OutletStatus`] -- Invocation terminal status. (Re-exported from
//!   [`lifecycle`].)
//! - [`OutletCancel`] -- Cancellation request. (Re-exported from [`lifecycle`].)
//! - [`OutletStreamOpen`] / [`OutletStreamChunk`] / [`OutletStreamCredit`] /
//!   [`ChunkPayload`] / [`StreamTerminalStatus`] -- §5.4.5 streaming wire
//!   types. (Re-exported from [`stream`].)

pub mod error_codes;
pub mod errors;
pub mod hash;
pub mod integrity;
pub mod interface;
pub mod lifecycle;
pub mod message_catalog;
pub mod registration;
pub mod registry;
pub mod schema;
pub mod stream;
pub mod summary;

use crate::context::roles;

pub use hash::{
    OUTLET_REGISTRATION_V2_DOMAIN, catalog_hash, compute_outlet_registration_canonical_bytes,
    cost_hash, description_hash, outlet_registration_v2_preimage, schema_hash, test_vectors_hash,
};
pub use lifecycle::{
    DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS, OutletCancel, OutletInvokedEvent, OutletRequest,
    OutletStatus, Provenance, sha256_json,
};
pub use message_catalog::{
    CATALOG_MAX_ENTRIES, MessageTemplate, MessageTemplateError, TEMPLATE_MAX_BYTES,
    canonical_catalog_messagepack, empty_catalog_messagepack,
};
pub use registration::{OutletRegistration, RegistrationError};
pub use registry::{
    OutletCost, OutletRegistry, OutletSchema, OutletTestVector, OutletVerificationResult,
    VectorResult, register_outlet, update_outlet, verify_outlet,
};
pub use schema::{SchemaValidationError, validate_schema, validate_value_against_schema};
pub use stream::{
    ChunkPayload, CreditGrantSigningInputs, DEFAULT_CREDIT_WINDOW,
    DEFAULT_STREAM_CREDIT_STALL_SECS, DEFAULT_STREAM_UCAN_RECHECK_SECS, Ed25519Signature, MlsEpoch,
    OpenObservation, OutletStreamChunk, OutletStreamCredit, OutletStreamOpen, RequestId,
    SCP_OUTLET_CAVEAT_BIND_V1, SCP_OUTLET_CHUNK_SIG_V1, SCP_OUTLET_CHUNK_V1, SCP_OUTLET_CREDIT_V1,
    SessionState, StreamRejection, StreamTerminalStatus, compute_caveats_binding,
    compute_chunk_sig_preimage, compute_credit_sig_preimage, evaluate_open_pinning,
    evaluate_revocation_recheck, evaluate_session_open, sign_chunk, sign_credit_grant,
    verify_chunk_signature, verify_credit_signature,
};

// ---------------------------------------------------------------------------
// OutletKind
// ---------------------------------------------------------------------------

/// Structural classification of an outlet (spec §5.4.2).
///
/// Every outlet declares its semantic class at registration time. The
/// classification is structural, not advisory — the runtime enforces it.
///
/// - [`OutletKind::Query`] — read-only, idempotent, semantically cacheable
///   (§5.4.2 cache property; §5.4.3 cache deferred). A Query outlet MUST
///   declare either no cost or `cost.amount == 0` and MUST NOT carry a
///   `cost_formula`. Invocation runs through a `ReadOnlyInvocation` handle
///   that denies writes to context state. UCAN stem: `outlet_query:{id}`.
/// - [`OutletKind::Action`] — may mutate context state. No structural cost
///   floor. Invocation runs through a `MutableInvocation` handle. UCAN stem:
///   `outlet_call:{id}`.
///
/// **Default.** [`OutletKind::Action`] is the fail-safe default per §5.4.2 —
/// an undeclared kind cannot accidentally be treated as read-only. Wire
/// deserialization that omits the `kind` field produces `Action` for the
/// same reason.
///
/// **Wire form.** Serializes as the lowercase string `"query"` or `"action"`
/// (§5.4.2 wire vocabulary). The struct field on
/// [`registry::OutletRegistration`] is named `kind`, so the on-wire
/// representation is `"kind": "query"` or `"kind": "action"`.
///
/// **Canonical preimage.** The §5.4.1 `SCP-OUTLET-REGISTRATION-V2:` preimage
/// includes a fixed-width `kind_byte` between `outlet_id` and `name`:
/// `0x00` for Query, `0x01` for Action.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum OutletKind {
    /// Read-only, idempotent, cacheable. `ReadOnlyInvocation` guard applies
    /// (§5.4.2). UCAN stem: `outlet_query:{id}`.
    Query,
    /// May mutate context state. Never cached (§5.4.2). UCAN stem:
    /// `outlet_call:{id}`. Fail-safe default.
    #[default]
    Action,
}

impl OutletKind {
    /// Returns the canonical 1-byte preimage tag for this kind per §5.4.1.
    ///
    /// - `OutletKind::Query` → `0x00`
    /// - `OutletKind::Action` → `0x01`
    ///
    /// The byte is included verbatim in the
    /// `SCP-OUTLET-REGISTRATION-V2:` canonical preimage between `outlet_id`
    /// and `name`. Adding new variants in the future requires extending the
    /// preimage rule and bumping the domain separator.
    #[must_use]
    pub const fn canonical_byte(self) -> u8 {
        match self {
            Self::Query => 0x00,
            Self::Action => 0x01,
        }
    }
}

// ---------------------------------------------------------------------------
// OutletId
// ---------------------------------------------------------------------------

/// Unique identifier for a registered tool within a context.
///
/// Matches the `OutletId` type alias in `context::roles`, re-defined here for
/// module-local clarity. These are the same underlying type (`String`).
pub type OutletId = String;

use scp_primitives::DID;

// ---------------------------------------------------------------------------
// OutletError
// ---------------------------------------------------------------------------

/// Errors produced by tool registration, update, and verification operations.
///
/// See ADR-010 for error conditions.
#[derive(Debug, thiserror::Error)]
pub enum OutletError {
    /// The registrant does not have the `ToolRegister` capability.
    #[error("registrant \"{did}\" does not have ToolRegister capability")]
    RegistrantNotAuthorized {
        /// The DID that attempted registration without authorization.
        did: String,
    },

    /// The updater is not the tool's operator and does not have admin role.
    #[error("updater \"{did}\" is not the tool operator and lacks admin role")]
    UpdaterNotAuthorized {
        /// The DID that attempted the update without authorization.
        did: String,
    },

    /// The tool's input schema failed validation.
    #[error("invalid input schema: {0}")]
    InvalidInputSchema(#[source] SchemaValidationError),

    /// The tool's output schema failed validation.
    #[error("invalid output schema: {0}")]
    InvalidOutputSchema(#[source] SchemaValidationError),

    /// The implementation hash has an invalid length (must be 32 bytes).
    #[error("implementation hash must be 32 bytes, got {length}")]
    InvalidImplementationHash {
        /// The actual length of the provided hash.
        length: usize,
    },

    /// The operator DID is not resolvable (empty or malformed).
    #[error("operator DID is not resolvable: \"{did}\"")]
    UnresolvableDid {
        /// The DID that failed resolution.
        did: String,
    },

    /// The specified tool was not found in the registry.
    #[error("tool not found: \"{outlet_id}\"")]
    OutletNotFound {
        /// The tool ID that was not found.
        outlet_id: OutletId,
    },

    /// The tool ID in the new registration does not match the existing tool.
    #[error("tool ID mismatch: expected \"{expected}\", got \"{actual}\"")]
    OutletIdMismatch {
        /// The expected tool ID.
        expected: OutletId,
        /// The actual tool ID provided.
        actual: OutletId,
    },

    /// A tool with this ID is already registered.
    #[error("tool already registered: \"{outlet_id}\"")]
    OutletAlreadyRegistered {
        /// The duplicate tool ID.
        outlet_id: OutletId,
    },

    /// A test vector verification failed.
    #[error("test vector verification failed: {message}")]
    VerificationFailed {
        /// Human-readable description of the failure.
        message: String,
    },

    /// The context is not in the Active state.
    #[error("context is not active (current state: {current_state})")]
    ContextNotActive {
        /// The current state of the context.
        current_state: String,
    },

    /// The invoker does not have the required capability.
    #[error("invoker \"{did}\" not authorized for tool \"{outlet_id}\"")]
    InvokerNotAuthorized {
        /// The DID that attempted invocation.
        did: String,
        /// The tool ID.
        outlet_id: String,
    },

    /// Input validation against the tool schema failed.
    #[error("input validation failed: {message}")]
    InputValidationFailed {
        /// Human-readable description of the validation failure.
        message: String,
    },

    /// Tool execution failed.
    #[error("execution failed: {message}")]
    ExecutionFailed {
        /// Human-readable description of the execution failure.
        message: String,
    },

    /// The specified session was not found.
    #[error("session not found: {session_id}")]
    SessionNotFound {
        /// The session ID that was not found.
        session_id: String,
    },

    /// The session has expired.
    #[error("session expired: {session_id}")]
    SessionExpired {
        /// The expired session ID.
        session_id: String,
    },

    /// Admin capability is required for cross-context tool interfaces.
    #[error("admin capability required for tool interface: {did}")]
    InterfaceAdminRequired {
        /// The DID that attempted the operation.
        did: String,
    },

    /// The interface has not been approved by both sides.
    #[error(
        "tool interface not fully approved (source: {source_approved}, target: {target_approved})"
    )]
    InterfaceNotApproved {
        /// Whether the source context approved.
        source_approved: bool,
        /// Whether the target context approved.
        target_approved: bool,
    },

    /// The invoker is not authorized for this cross-context interface.
    #[error("invoker \"{did}\" not authorized for cross-context tool \"{outlet_id}\"")]
    InterfaceInvokerNotAuthorized {
        /// The DID that attempted invocation.
        did: String,
        /// The tool ID.
        outlet_id: String,
    },

    /// Cross-context interface rate limit exceeded.
    #[error(
        "rate limit exceeded: {max_calls} calls per {window_ms}ms (retry after {retry_after_secs}s)"
    )]
    InterfaceRateLimited {
        /// Maximum calls allowed.
        max_calls: u64,
        /// Window duration in milliseconds.
        window_ms: u64,
        /// Seconds until the next call will be accepted (spec §6.2.0.2).
        retry_after_secs: u64,
    },

    /// Context ID mismatch in cross-context interface.
    #[error("context mismatch in tool interface: expected {expected}, got {actual}")]
    InterfaceContextMismatch {
        /// The expected context ID.
        expected: String,
        /// The actual context ID.
        actual: String,
    },

    /// Cross-context interface execution failed.
    #[error("cross-context execution failed: {message}")]
    InterfaceExecutionFailed {
        /// Human-readable description of the failure.
        message: String,
    },

    /// The cross-context tool call chain depth exceeded the maximum.
    #[error("chain depth {depth} exceeds maximum {max_depth}")]
    ChainDepthExceeded {
        /// The current chain depth.
        depth: u8,
        /// The maximum allowed chain depth.
        max_depth: u8,
    },

    /// The per-caller session cap has been reached (spec §6.2.1, §9.2.1, ADR-043).
    #[error(
        "session cap exceeded: calling context \"{source_context}\" has {current} active sessions (max {max})"
    )]
    SessionCapExceeded {
        /// The calling context that hit the cap.
        source_context: String,
        /// Current number of active sessions from this caller.
        current: u32,
        /// Maximum allowed concurrent sessions per caller.
        max: u32,
    },

    /// The tool schema does not meet the specificity floor (spec section 6.2, 9.2.1).
    #[error(
        "schema specificity floor not met: {side} schema has {field_count} distinct fields, minimum {min_fields} required"
    )]
    SchemaSpecificityFloor {
        /// Which schema failed: "input" or "output".
        side: String,
        /// Number of distinct fields found.
        field_count: usize,
        /// Minimum number of fields required.
        min_fields: usize,
    },

    /// Tool registration signature verification failed (M15).
    ///
    /// The `signature` field on a [`OutletRegistration`] is a Ed25519 signature
    /// over the canonical registration bytes. If the signature is non-empty,
    /// it MUST verify against the registrant's signing key.
    #[error("tool registration signature verification failed: {reason}")]
    SignatureVerificationFailed {
        /// Human-readable description of the failure.
        reason: String,
    },

    /// The invoker is not in the outbound policy's `allowed_callers` list (§6.2.0.1).
    #[error("invoker \"{did}\" not in outbound policy allowed_callers for interface")]
    InterfaceCallerNotAllowed {
        /// The DID that was not in the allowed callers list.
        did: String,
    },

    /// The request payload exceeds the outbound policy's `max_payload_bytes` (§6.2.0.1).
    #[error("request payload size {actual} exceeds outbound policy limit {max} bytes")]
    InterfacePayloadTooLarge {
        /// Actual payload size in bytes.
        actual: usize,
        /// Maximum allowed by outbound policy.
        max: u32,
    },

    /// The response payload exceeds the inbound policy's `max_response_bytes` (§6.2.0.1).
    #[error("response payload size {actual} exceeds inbound policy limit {max} bytes")]
    InterfaceResponseTooLarge {
        /// Actual response size in bytes.
        actual: usize,
        /// Maximum allowed by inbound policy.
        max: u32,
    },

    /// A Query outlet violated the §5.4.2 structural cost floor (SCP-OUT-012).
    ///
    /// `OutletKind::Query` outlets MUST declare either no cost or a cost
    /// whose `amount == 0`, AND MUST NOT carry a `cost_formula`. Declaring
    /// a positive cost or a pricing formula on a Query outlet is a
    /// validation failure rejected before the registration reaches the
    /// event log. Maps to `OutletErrorClass::Protocol::QueryCostViolation`
    /// per §5.4.4 (typed class lands with SCP-OUT-036/038).
    #[error("Query outlet cost violation (§5.4.2): {reason}")]
    QueryCostViolation {
        /// Human-readable reason — which sub-rule was violated.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// ToolEvent (event log integration types)
// ---------------------------------------------------------------------------

/// Event payload for a `ToolRegistered` event in the context event log.
///
/// Captures the full registration metadata for auditability. Serialized into
/// the opaque `EventPayload::data` field.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OutletRegisteredEvent {
    /// The registered tool's ID.
    pub outlet_id: OutletId,
    /// The tool name.
    pub name: String,
    /// The tool description.
    pub description: String,
    /// SHA-256 implementation hash.
    pub implementation_hash: [u8; 32],
    /// The operator DID responsible for the tool.
    pub operator_did: DID,
    /// The DID of the registrant who registered the tool.
    pub registrant_did: DID,
    /// Number of test vectors included.
    pub test_vector_count: usize,
}

/// Event payload for a `ToolUpdated` event in the context event log.
///
/// Records old and new implementation hashes and all changed fields.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OutletUpdatedEvent {
    /// The updated tool's ID.
    pub outlet_id: OutletId,
    /// The old implementation hash before the update.
    pub old_implementation_hash: [u8; 32],
    /// The new implementation hash after the update.
    pub new_implementation_hash: [u8; 32],
    /// The DID that performed the update.
    pub updater_did: DID,
    /// Names of fields that changed in this update.
    ///
    /// Possible values: `"name"`, `"description"`, `"schema"`,
    /// `"test_vectors"`, `"implementation_hash"`, `"operator_did"`.
    pub changed_fields: Vec<String>,
}

/// Reason for an `OutletVerifiedEvent` integrity-failure (spec §5.4.2).
///
/// Disambiguates the cause of `integrity_ok == false`:
///
/// - [`OutletVerifiedReason::TestVectorFailed`] — one or more registered test
///   vectors did not match the executor's output. Carries no further detail —
///   the [`OutletVerificationResult`] alongside the event holds the per-vector
///   results.
/// - [`OutletVerifiedReason::QueryMisdeclaration`] — a Query outlet's executor
///   attempted a write through `MutableInvocation` (or invoked through the
///   wrong `OutletExecutor` half), tripping the runtime deny-list. The
///   operator-attributable signal defined in spec §5.4.2 "Misdeclaration
///   signal" — used by participation records (§7.3.2) to attribute the
///   failure to the outlet's `operator_did`. Wire form: `"query-misdeclaration"`
///   so the on-wire string matches the spec's `query_misdeclaration` slug
///   (with the canonical kebab-case rendering used elsewhere in the
///   `OutletErrorClass` slug taxonomy — §5.4.4).
/// - [`OutletVerifiedReason::HandlerPanicked`] — the outlet's executor panicked
///   inside `exec_query` / `exec_action`. The runtime catches the panic via
///   `std::panic::catch_unwind`, recovers, and emits this signal as the §5.4.2
///   parallel of `QueryMisdeclaration`. Per ADR-049 §148 "Every `OutletExecutor`
///   is wrapped in `catch_unwind`. A panic inside an executor maps to
///   `SCP-TOOL-6130` (handler-panic) with an operator-attributable
///   integrity-failure signal." Wire form: `"handler-panicked"`. The signal
///   attributes the failure to the outlet's `operator_did` — panics are a
///   protocol-visible signal of operator-side defect, not an SDK-internal bug.
///   See SCP-OUT-028.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutletVerifiedReason {
    /// At least one registered test vector failed to match the executor's
    /// output during a [`verify_outlet`](registry::verify_outlet) run.
    TestVectorFailed,
    /// A Query outlet's executor attempted to mutate context state through a
    /// write-side handle (or the dispatched executor half returned
    /// `KindMismatch`). Operator-attributable per spec §5.4.2 — wired by the
    /// `ReadOnlyInvocation` deny-list (SCP-OUT-013).
    QueryMisdeclaration,
    /// The outlet's executor panicked inside `exec_query` / `exec_action`.
    /// The runtime catches the panic via `std::panic::catch_unwind`, recovers,
    /// and surfaces the failure as `SCP-TOOL-6130` `execution.handler-panic`.
    /// Operator-attributable per spec §5.4.2 / ADR-049 §148 — wired by the
    /// `invoke_outlet` panic guard (SCP-OUT-028).
    HandlerPanicked,
}

/// Event payload for a `ToolVerified` event in the context event log.
///
/// Records the verification result for auditability. `reason` carries the
/// failure category when `integrity_ok == false`; it is omitted from the
/// wire envelope when `integrity_ok == true` per the spec §5.4.2 invariant
/// that a successful verification has no failure reason to attribute.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OutletVerifiedEvent {
    /// The verified tool's ID.
    pub outlet_id: OutletId,
    /// Number of test vectors that passed.
    pub passed: usize,
    /// Number of test vectors that failed.
    pub failed: usize,
    /// Overall integrity assessment.
    pub integrity_ok: bool,
    /// Categorized reason for `integrity_ok == false` (spec §5.4.2
    /// "Misdeclaration signal"). `None` when `integrity_ok == true` or when
    /// emitted from legacy code paths that pre-date the kebab-case taxonomy.
    /// Always `Some` when the runtime emits an integrity-failure event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<OutletVerifiedReason>,
}

// ---------------------------------------------------------------------------
// Capability check helper
// ---------------------------------------------------------------------------

/// Checks whether a member has the `ToolRegister` capability.
///
/// Delegates to the role system's capability check. This is the integration
/// point between the tools module and the UCAN-based role system (ADR-009).
#[must_use]
pub fn has_outlet_register_capability(role_state: &roles::ContextRoleState, did: &str) -> bool {
    role_state.member_has_capability(did, &roles::Capability::OutletRegister)
}

/// Checks whether a member has admin-level capabilities.
///
/// Used by `update_outlet` to verify the updater is either the tool operator
/// or an admin.
#[must_use]
pub fn has_admin_role(role_state: &roles::ContextRoleState, did: &str) -> bool {
    // Check for the RoleAssign capability as a proxy for admin status,
    // since the admin role includes all capabilities in the ceiling.
    role_state.member_has_capability(did, &roles::Capability::RoleAssign)
}

/// Returns `true` if `did` has tool invocation capability for the given tool.
///
/// Checks for `ToolInvokeAll` (broader) first, then specific `ToolInvoke(outlet_id)`.
#[must_use]
pub fn has_outlet_call_capability(
    role_state: &roles::ContextRoleState,
    did: &str,
    outlet_id: &str,
) -> bool {
    if role_state.member_has_capability(did, &roles::Capability::OutletCallAll) {
        return true;
    }
    role_state.member_has_capability(did, &roles::Capability::OutletCall(outlet_id.to_owned()))
}
