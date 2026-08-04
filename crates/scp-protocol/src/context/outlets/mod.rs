//! Outlet registration, schema validation, invocation lifecycle, and verification
//! for SCP contexts.
//!
//! Outlets are stateless functions scoped to a context (spec section 5.4). They
//! have MCP-compatible JSON Schema interfaces (spec section 8.5), making them
//! interoperable with existing MCP tooling. Every outlet registration includes
//! schema, implementation hash, test vectors, and operator DID -- providing
//! verifiable integrity (spec section 7.3.3).
//!
//! See ADR-010 in `.docs/adrs/phase-2.md` for the original design and ADR-049
//! for the streaming-native invocation redesign (§5).
//!
//! # Modules
//!
//! - [`registry`] -- Outlet registration storage, `register_outlet`,
//!   `update_outlet`, `verify_outlet`.
//! - [`schema`] -- JSON Schema validation helpers and MCP compatibility.
//! - `invoke` (in `scp-runtime`) -- Outlet invocation with full execution
//!   lifecycle: capability checking, schema validation, timeout, cancellation.
//! - [`lifecycle`] -- Request types, terminal status, cancellation, and event
//!   log integration for outlet invocations.
//! - [`stream`] -- §5.4.5 streaming wire types: `OutletStreamOpen`,
//!   `OutletStreamChunk`, `OutletStreamCredit`, `ChunkPayload`,
//!   `StreamTerminalStatus`. The legacy non-streaming `OutletResponse` was
//!   deleted by the streaming-native redesign (ADR-049 §5).
//!
//! # Types
//!
//! - [`OutletId`] -- Unique identifier for a registered outlet.
//! - [`OutletKind`] -- Structural classification (`Query` / `Action`, §5.4.2).
//! - [`OutletError`] -- Error type for outlet operations.
//! - [`OutletRegistration`] -- Full outlet registration with schema, hash, test
//!   vectors, and operator DID. (Re-exported from [`registration`].)
//! - [`OutletSchema`] -- MCP-compatible JSON Schema for input/output.
//!   (Re-exported from [`registry`].)
//! - [`OutletTestVector`] -- Known input-output pair for outlet verification.
//!   (Re-exported from [`registry`].)
//! - [`OutletRegistry`] -- In-memory outlet storage per context.
//!   (Re-exported from [`registry`].)
//! - [`OutletRequest`] -- Outlet invocation request. (Re-exported from
//!   [`lifecycle`].)
//! - [`OutletStatus`] -- Invocation terminal status. (Re-exported from
//!   [`lifecycle`].)
//! - [`OutletCancel`] -- Cancellation request. (Re-exported from [`lifecycle`].)
//! - [`OutletStreamOpen`] / [`OutletStreamChunk`] / [`OutletStreamCredit`] /
//!   [`ChunkPayload`] / [`StreamTerminalStatus`] -- §5.4.5 streaming wire
//!   types. (Re-exported from [`stream`].)

pub mod cross_context_saga;
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

pub use cross_context_saga::{
    CommittedSide, CrossContextDivergenceMarker, CrossContextDivergenceMarkerFields,
    CrossContextOutletReceipt, CrossContextOutletReceiptFields, CrossContextOutletStreamReceipt,
    CrossContextOutletStreamReceiptFields, CrossContextSagaError, XCTX_DIVERGENCE_DOMAIN,
    XCTX_RECEIPT_DOMAIN, XCTX_STREAM_RECEIPT_DOMAIN,
};
pub use hash::{
    OUTLET_REGISTRATION_V2_DOMAIN, catalog_hash, compute_outlet_registration_canonical_bytes,
    cost_hash, description_hash, outlet_registration_v2_preimage, schema_hash, test_vectors_hash,
};
pub use lifecycle::{
    AuditAnomaly, DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS, OutletCancel, OutletInvokedEvent,
    OutletRequest, OutletStatus, Provenance, sha256_json,
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
    CancelSigningInputs, ChunkPayload, CreditGrantSigningInputs, DEFAULT_CREDIT_WINDOW,
    DEFAULT_STREAM_CREDIT_STALL_SECS, DEFAULT_STREAM_UCAN_RECHECK_SECS, Ed25519Signature, MlsEpoch,
    OpenObservation, OutletStreamCancel, OutletStreamChunk, OutletStreamCredit, OutletStreamOpen,
    RequestId, SCP_OUTLET_CANCEL_V1, SCP_OUTLET_CAVEAT_BIND_V1, SCP_OUTLET_CHUNK_SIG_V1,
    SCP_OUTLET_CHUNK_V1, SCP_OUTLET_CREDIT_V1, SessionState, StreamRejection, StreamTerminalStatus,
    compute_cancel_sig_preimage, compute_caveats_binding, compute_chunk_sig_preimage,
    compute_credit_sig_preimage, evaluate_open_pinning, evaluate_revocation_recheck,
    evaluate_session_open, sign_cancel, sign_chunk, sign_credit_grant, verify_cancel_signature,
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

/// Unique identifier for a registered outlet within a context.
///
/// Matches the `OutletId` type alias in `context::roles`, re-defined here for
/// module-local clarity. These are the same underlying type (`String`).
pub type OutletId = String;

use scp_did::DID;

// ---------------------------------------------------------------------------
// OutletError
// ---------------------------------------------------------------------------

/// Errors produced by outlet registration, update, and verification operations.
///
/// See ADR-010 for error conditions.
#[derive(Debug, thiserror::Error)]
pub enum OutletError {
    /// The registrant does not have the `OutletRegister` capability.
    #[error("registrant \"{did}\" does not have OutletRegister capability")]
    RegistrantNotAuthorized {
        /// The DID that attempted registration without authorization.
        did: String,
    },

    /// The updater is not the outlet's operator and does not have admin role.
    #[error("updater \"{did}\" is not the outlet operator and lacks admin role")]
    UpdaterNotAuthorized {
        /// The DID that attempted the update without authorization.
        did: String,
    },

    /// The outlet's input schema failed validation.
    #[error("invalid input schema: {0}")]
    InvalidInputSchema(#[source] SchemaValidationError),

    /// The outlet's output schema failed validation.
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

    /// The specified outlet was not found in the registry.
    #[error("outlet not found: \"{outlet_id}\"")]
    OutletNotFound {
        /// The outlet ID that was not found.
        outlet_id: OutletId,
    },

    /// The outlet ID in the new registration does not match the existing outlet.
    #[error("outlet ID mismatch: expected \"{expected}\", got \"{actual}\"")]
    OutletIdMismatch {
        /// The expected outlet ID.
        expected: OutletId,
        /// The actual outlet ID provided.
        actual: OutletId,
    },

    /// A outlet with this ID is already registered.
    #[error("outlet already registered: \"{outlet_id}\"")]
    OutletAlreadyRegistered {
        /// The duplicate outlet ID.
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
    #[error("invoker \"{did}\" not authorized for outlet \"{outlet_id}\"")]
    InvokerNotAuthorized {
        /// The DID that attempted invocation.
        did: String,
        /// The outlet ID.
        outlet_id: String,
    },

    /// Input validation against the outlet schema failed.
    #[error("input validation failed: {message}")]
    InputValidationFailed {
        /// Human-readable description of the validation failure.
        message: String,
    },

    /// Outlet execution failed.
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

    /// Admin capability is required for cross-context outlet interfaces.
    #[error("admin capability required for outlet interface: {did}")]
    InterfaceAdminRequired {
        /// The DID that attempted the operation.
        did: String,
    },

    /// The interface has not been approved by both sides.
    #[error(
        "outlet interface not fully approved (source: {source_approved}, target: {target_approved})"
    )]
    InterfaceNotApproved {
        /// Whether the source context approved.
        source_approved: bool,
        /// Whether the target context approved.
        target_approved: bool,
    },

    /// The invoker is not authorized for this cross-context interface.
    #[error("invoker \"{did}\" not authorized for cross-context outlet \"{outlet_id}\"")]
    InterfaceInvokerNotAuthorized {
        /// The DID that attempted invocation.
        did: String,
        /// The outlet ID.
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
    #[error("context mismatch in outlet interface: expected {expected}, got {actual}")]
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

    /// The cross-context outlet call chain depth exceeded the maximum.
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

    /// The outlet schema does not meet the specificity floor (spec section 6.2, 9.2.1).
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

    /// Outlet registration signature verification failed (M15).
    ///
    /// The `signature` field on a [`OutletRegistration`] is a Ed25519 signature
    /// over the canonical registration bytes. If the signature is non-empty,
    /// it MUST verify against the registrant's signing key.
    #[error("outlet registration signature verification failed: {reason}")]
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

    /// Canonical serialization (RFC 8785 JCS) of a value failed while computing
    /// a convergent hash (e.g., a outlet-invocation input/output hash).
    ///
    /// A convergent identity/hash must never be silently computed over
    /// defaulted-empty bytes: the error is surfaced instead of substituting an
    /// empty preimage. Unreachable for well-formed `serde_json::Value` inputs
    /// (which always canonicalize), but propagated as defense-in-depth for any
    /// serializable value whose `Serialize` impl can fail.
    #[error("canonicalization failed: {reason}")]
    CanonicalizationFailed {
        /// Human-readable description of the serialization failure.
        reason: String,
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

impl OutletError {
    /// Projects this registration / update / verification error onto the
    /// structured [`OutletErrorSurface`](errors::OutletErrorSurface) with its
    /// §5.4.4 `(class, code, slug, detail, retry)` intact (SCP-OUT-031 PR-2a).
    ///
    /// Single-sources the legacy-enum → §5.4.4 taxonomy mapping so the FFI
    /// bridges never re-derive it. Structured `detail` is extracted where a
    /// variant field maps DIRECTLY onto a typed [`errors::DetailBody`] shape
    /// (schema errors → `FieldViolation`,
    /// [`InterfaceRateLimited`](Self::InterfaceRateLimited) → `TransportRateLimit`);
    /// variants carrying only free-text or identity fields carry `detail = None`
    /// (never a fabricated placeholder). Authorization denials carry no detail
    /// so outlet existence / membership is never leaked.
    // Exhaustive one-arm-per-variant match over a 30+ variant enum: length is
    // the taxonomy, not incidental complexity. Splitting it would only scatter
    // the single-source mapping the doc promises.
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub fn to_surface(&self) -> errors::OutletErrorSurface {
        use crate::context::outlets::error_codes::{
            CODE_EXECUTION_FAULT, CODE_INPUT_VIOLATION, CODE_OUTPUT_VIOLATION,
            CODE_PROTOCOL_SESSION, CODE_PROTOCOL_VIOLATION, CODE_TRANSPORT_FAULT,
            SLUG_AUTHORIZATION_DENIED, SLUG_EXECUTION_HANDLER_PANIC,
            SLUG_EXECUTION_NON_DETERMINISTIC, SLUG_INPUT_SCHEMA_VIOLATION, SLUG_INPUT_TOO_LARGE,
            SLUG_OUTPUT_SCHEMA_VIOLATION, SLUG_OUTPUT_TOO_LARGE,
            SLUG_PROTOCOL_CONTEXT_CLOSED_MID_STREAM, SLUG_PROTOCOL_UNKNOWN_SESSION,
            SLUG_PROTOCOL_VIOLATION, SLUG_QUERY_COST_VIOLATION, SLUG_STRUCTURAL_FLOOR_VIOLATION,
            SLUG_TRANSPORT_CONCURRENT_STREAMS_PER_INVOKER,
            SLUG_TRANSPORT_CROSS_CONTEXT_BRIDGE_FAILURE, SLUG_TRANSPORT_RATE_LIMITED,
        };
        use errors::{DetailBody, OutletErrorSurface};

        match self {
            // Authorization-class denials — collapse onto `authorization.denied`
            // with NO detail so identity / existence / membership is not leaked.
            Self::RegistrantNotAuthorized { .. }
            | Self::UpdaterNotAuthorized { .. }
            | Self::InvokerNotAuthorized { .. }
            | Self::InterfaceAdminRequired { .. }
            | Self::InterfaceNotApproved { .. }
            | Self::InterfaceInvokerNotAuthorized { .. }
            | Self::InterfaceCallerNotAllowed { .. }
            | Self::SignatureVerificationFailed { .. } => {
                OutletErrorSurface::from_class(SLUG_AUTHORIZATION_DENIED, None)
            }

            // Input-class — schema-structure failure carries a FieldViolation;
            // an over-large request payload is `input.too-large`.
            Self::InvalidInputSchema(e) => OutletErrorSurface::from_code(
                CODE_INPUT_VIOLATION,
                SLUG_INPUT_SCHEMA_VIOLATION,
                Some(e.field_violation()),
            ),
            Self::InputValidationFailed { .. } => OutletErrorSurface::from_code(
                CODE_INPUT_VIOLATION,
                SLUG_INPUT_SCHEMA_VIOLATION,
                None,
            ),
            Self::InterfacePayloadTooLarge { .. } => {
                OutletErrorSurface::from_code(CODE_INPUT_VIOLATION, SLUG_INPUT_TOO_LARGE, None)
            }

            // Output-class — the same FieldViolation shape, Output code/slug;
            // an over-large response payload is `output.too-large`.
            Self::InvalidOutputSchema(e) => OutletErrorSurface::from_code(
                CODE_OUTPUT_VIOLATION,
                SLUG_OUTPUT_SCHEMA_VIOLATION,
                Some(e.field_violation()),
            ),
            Self::InterfaceResponseTooLarge { .. } => {
                OutletErrorSurface::from_code(CODE_OUTPUT_VIOLATION, SLUG_OUTPUT_TOO_LARGE, None)
            }

            // Protocol-class registration / validation / classification.
            Self::InvalidImplementationHash { .. }
            | Self::UnresolvableDid { .. }
            | Self::OutletNotFound { .. }
            | Self::OutletIdMismatch { .. }
            | Self::OutletAlreadyRegistered { .. }
            | Self::InterfaceContextMismatch { .. }
            | Self::ChainDepthExceeded { .. }
            | Self::CanonicalizationFailed { .. } => OutletErrorSurface::from_code(
                CODE_PROTOCOL_VIOLATION,
                SLUG_PROTOCOL_VIOLATION,
                None,
            ),
            Self::SchemaSpecificityFloor { .. } => OutletErrorSurface::from_code(
                CODE_PROTOCOL_VIOLATION,
                SLUG_STRUCTURAL_FLOOR_VIOLATION,
                None,
            ),
            Self::QueryCostViolation { .. } => OutletErrorSurface::from_code(
                CODE_PROTOCOL_VIOLATION,
                SLUG_QUERY_COST_VIOLATION,
                None,
            ),

            // Protocol-session lifecycle — context teardown and session state.
            Self::ContextNotActive { .. } => OutletErrorSurface::from_code(
                CODE_PROTOCOL_SESSION,
                SLUG_PROTOCOL_CONTEXT_CLOSED_MID_STREAM,
                None,
            ),
            Self::SessionNotFound { .. } | Self::SessionExpired { .. } => {
                OutletErrorSurface::from_code(
                    CODE_PROTOCOL_SESSION,
                    SLUG_PROTOCOL_UNKNOWN_SESSION,
                    None,
                )
            }

            // Execution-class — handler failure / test-vector mismatch.
            Self::ExecutionFailed { .. } => OutletErrorSurface::from_code(
                CODE_EXECUTION_FAULT,
                SLUG_EXECUTION_HANDLER_PANIC,
                None,
            ),
            Self::VerificationFailed { .. } => OutletErrorSurface::from_code(
                CODE_EXECUTION_FAULT,
                SLUG_EXECUTION_NON_DETERMINISTIC,
                None,
            ),

            // Transport-class — cross-context bridge / rate / concurrency.
            Self::InterfaceRateLimited {
                retry_after_secs, ..
            } => OutletErrorSurface::from_code(
                CODE_TRANSPORT_FAULT,
                SLUG_TRANSPORT_RATE_LIMITED,
                Some(DetailBody::TransportRateLimit {
                    // `retry_after_secs` is a `u64` window hint; the §5.4.4
                    // detail field is a `u32`. Saturate rather than truncate.
                    retry_after_secs: u32::try_from(*retry_after_secs).unwrap_or(u32::MAX),
                }),
            ),
            Self::InterfaceExecutionFailed { .. } => OutletErrorSurface::from_code(
                CODE_TRANSPORT_FAULT,
                SLUG_TRANSPORT_CROSS_CONTEXT_BRIDGE_FAILURE,
                None,
            ),
            Self::SessionCapExceeded { .. } => OutletErrorSurface::from_code(
                CODE_TRANSPORT_FAULT,
                SLUG_TRANSPORT_CONCURRENT_STREAMS_PER_INVOKER,
                None,
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// OutletEvent (event log integration types)
// ---------------------------------------------------------------------------

/// Event payload for a `OutletRegistered` event in the context event log.
///
/// Captures the full registration metadata for auditability. Serialized into
/// the opaque `EventPayload::data` field.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OutletRegisteredEvent {
    /// The registered outlet's ID.
    pub outlet_id: OutletId,
    /// The outlet name.
    pub name: String,
    /// The outlet description.
    pub description: String,
    /// SHA-256 implementation hash.
    pub implementation_hash: [u8; 32],
    /// The operator DID responsible for the outlet.
    pub operator_did: DID,
    /// The DID of the registrant who registered the outlet.
    pub registrant_did: DID,
    /// Number of test vectors included.
    pub test_vector_count: usize,
}

/// Event payload for a `OutletUpdated` event in the context event log.
///
/// Records old and new implementation hashes and all changed fields.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OutletUpdatedEvent {
    /// The updated outlet's ID.
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
///   `SCP-OUTLET-6130` (handler-panic) with an operator-attributable
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
    /// and surfaces the failure as `SCP-OUTLET-6130` `execution.handler-panic`.
    /// Operator-attributable per spec §5.4.2 / ADR-049 §148 — wired by the
    /// `invoke_outlet` panic guard (SCP-OUT-028).
    HandlerPanicked,
}

/// Event payload for a `OutletVerified` event in the context event log.
///
/// Records the verification result for auditability. `reason` carries the
/// failure category when `integrity_ok == false`; it is omitted from the
/// wire envelope when `integrity_ok == true` per the spec §5.4.2 invariant
/// that a successful verification has no failure reason to attribute.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OutletVerifiedEvent {
    /// The verified outlet's ID.
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

/// Checks whether a member has the `OutletRegister` capability.
///
/// Delegates to the role system's capability check. This is the integration
/// point between the outlets module and the UCAN-based role system (ADR-009).
#[must_use]
pub fn has_outlet_register_capability(role_state: &roles::ContextRoleState, did: &str) -> bool {
    role_state.member_has_capability(did, &roles::Capability::OutletRegister)
}

/// Checks whether a member has admin-level capabilities.
///
/// Used by `update_outlet` to verify the updater is either the outlet operator
/// or an admin.
#[must_use]
pub fn has_admin_role(role_state: &roles::ContextRoleState, did: &str) -> bool {
    // Check for the RoleAssign capability as a proxy for admin status,
    // since the admin role includes all capabilities in the ceiling.
    role_state.member_has_capability(did, &roles::Capability::RoleAssign)
}

/// Returns `true` if `did` has Action-outlet call capability for the given outlet.
///
/// Checks for `OutletCallAll` (broader) first, then specific
/// `OutletCall(outlet_id)`. This gates invocation of Action (mutating) outlets;
/// Query (read-only) outlets are gated separately by the `OutletQuery*`
/// capabilities (§5.4.2).
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

/// Returns `true` if `did` has Query-outlet call capability for the given outlet.
///
/// Mirror of [`has_outlet_call_capability`] for the Query-class stem
/// (SCP-OUT-014, spec §5.4.2). Checks for `OutletQueryAll` (broader) first,
/// then specific `OutletQuery(outlet_id)`. The two stems are independent: an
/// `OutletQueryAll` grant must NOT authorize an Action call, and vice versa
/// (§6.2 amplification rule). The runtime selects between the two via the
/// outlet's registered [`OutletKind`] — see [`has_outlet_invocation_capability`].
#[must_use]
pub fn has_outlet_query_capability(
    role_state: &roles::ContextRoleState,
    did: &str,
    outlet_id: &str,
) -> bool {
    if role_state.member_has_capability(did, &roles::Capability::OutletQueryAll) {
        return true;
    }
    role_state.member_has_capability(did, &roles::Capability::OutletQuery(outlet_id.to_owned()))
}

/// Returns `true` if `did` holds the kind-appropriate split capability for
/// invoking an outlet.
///
/// Selects between [`has_outlet_call_capability`] (Action) and
/// [`has_outlet_query_capability`] (Query) based on the outlet's registered
/// [`OutletKind`]. Per spec §5.4.2 the two stems are independent —
/// `OutletQueryAll` must not authorize an Action call and `OutletCallAll` must
/// not authorize a Query call. This is the single dispatch point that keeps the
/// runtime invoke sites from having to branch on kind by hand.
#[must_use]
pub fn has_outlet_invocation_capability(
    role_state: &roles::ContextRoleState,
    did: &str,
    outlet_id: &str,
    kind: OutletKind,
) -> bool {
    match kind {
        OutletKind::Query => has_outlet_query_capability(role_state, did, outlet_id),
        OutletKind::Action => has_outlet_call_capability(role_state, did, outlet_id),
    }
}

// ---------------------------------------------------------------------------
// Tests — legacy OutletError::to_surface (SCP-OUT-031 PR-2a)
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::panic, clippy::too_many_lines)]
mod to_surface_tests {
    use super::*;
    use crate::context::outlets::error_codes::{error_code_to_class, slug_to_class};
    use crate::context::outlets::errors::{DetailBody, OutletErrorClass};
    use crate::context::outlets::schema::SchemaValidationError;

    /// Every legacy `OutletError` variant projects onto a §5.4.4-consistent
    /// surface: `error_code_to_class(code) == class == slug_to_class(slug)`.
    fn assert_consistent(err: &OutletError, want_class: OutletErrorClass) {
        let s = err.to_surface();
        assert_eq!(s.class, want_class, "variant {err:?} class");
        assert_eq!(
            error_code_to_class(&s.code),
            Some(s.class),
            "variant {err:?}: code {} must map to class {:?}",
            s.code,
            s.class
        );
        assert_eq!(
            slug_to_class(&s.slug),
            Some(s.class),
            "variant {err:?}: slug {} must map to class {:?}",
            s.slug,
            s.class
        );
    }

    #[test]
    fn every_legacy_variant_maps_to_a_consistent_surface() {
        let cases: Vec<(OutletError, OutletErrorClass)> = vec![
            (
                OutletError::RegistrantNotAuthorized { did: "d".into() },
                OutletErrorClass::Authorization,
            ),
            (
                OutletError::UpdaterNotAuthorized { did: "d".into() },
                OutletErrorClass::Authorization,
            ),
            (
                OutletError::InvalidInputSchema(SchemaValidationError::MissingTypeField),
                OutletErrorClass::Input,
            ),
            (
                OutletError::InvalidOutputSchema(SchemaValidationError::MissingTypeField),
                OutletErrorClass::Output,
            ),
            (
                OutletError::InvalidImplementationHash { length: 7 },
                OutletErrorClass::Protocol,
            ),
            (
                OutletError::UnresolvableDid { did: "d".into() },
                OutletErrorClass::Protocol,
            ),
            (
                OutletError::OutletNotFound {
                    outlet_id: "o".into(),
                },
                OutletErrorClass::Protocol,
            ),
            (
                OutletError::OutletIdMismatch {
                    expected: "a".into(),
                    actual: "b".into(),
                },
                OutletErrorClass::Protocol,
            ),
            (
                OutletError::OutletAlreadyRegistered {
                    outlet_id: "o".into(),
                },
                OutletErrorClass::Protocol,
            ),
            (
                OutletError::VerificationFailed {
                    message: "m".into(),
                },
                OutletErrorClass::Execution,
            ),
            (
                OutletError::ContextNotActive {
                    current_state: "Closing".into(),
                },
                OutletErrorClass::Protocol,
            ),
            (
                OutletError::InvokerNotAuthorized {
                    did: "d".into(),
                    outlet_id: "o".into(),
                },
                OutletErrorClass::Authorization,
            ),
            (
                OutletError::InputValidationFailed {
                    message: "m".into(),
                },
                OutletErrorClass::Input,
            ),
            (
                OutletError::ExecutionFailed {
                    message: "m".into(),
                },
                OutletErrorClass::Execution,
            ),
            (
                OutletError::SessionNotFound {
                    session_id: "s".into(),
                },
                OutletErrorClass::Protocol,
            ),
            (
                OutletError::SessionExpired {
                    session_id: "s".into(),
                },
                OutletErrorClass::Protocol,
            ),
            (
                OutletError::InterfaceAdminRequired { did: "d".into() },
                OutletErrorClass::Authorization,
            ),
            (
                OutletError::InterfaceNotApproved {
                    source_approved: true,
                    target_approved: false,
                },
                OutletErrorClass::Authorization,
            ),
            (
                OutletError::InterfaceInvokerNotAuthorized {
                    did: "d".into(),
                    outlet_id: "o".into(),
                },
                OutletErrorClass::Authorization,
            ),
            (
                OutletError::InterfaceRateLimited {
                    max_calls: 10,
                    window_ms: 1000,
                    retry_after_secs: 5,
                },
                OutletErrorClass::Transport,
            ),
            (
                OutletError::InterfaceContextMismatch {
                    expected: "a".into(),
                    actual: "b".into(),
                },
                OutletErrorClass::Protocol,
            ),
            (
                OutletError::InterfaceExecutionFailed {
                    message: "m".into(),
                },
                OutletErrorClass::Transport,
            ),
            (
                OutletError::ChainDepthExceeded {
                    depth: 5,
                    max_depth: 4,
                },
                OutletErrorClass::Protocol,
            ),
            (
                OutletError::SessionCapExceeded {
                    source_context: "c".into(),
                    current: 5,
                    max: 4,
                },
                OutletErrorClass::Transport,
            ),
            (
                OutletError::SchemaSpecificityFloor {
                    side: "input".into(),
                    field_count: 0,
                    min_fields: 1,
                },
                OutletErrorClass::Protocol,
            ),
            (
                OutletError::SignatureVerificationFailed { reason: "r".into() },
                OutletErrorClass::Authorization,
            ),
            (
                OutletError::InterfaceCallerNotAllowed { did: "d".into() },
                OutletErrorClass::Authorization,
            ),
            (
                OutletError::InterfacePayloadTooLarge {
                    actual: 100,
                    max: 10,
                },
                OutletErrorClass::Input,
            ),
            (
                OutletError::InterfaceResponseTooLarge {
                    actual: 100,
                    max: 10,
                },
                OutletErrorClass::Output,
            ),
            (
                OutletError::CanonicalizationFailed { reason: "r".into() },
                OutletErrorClass::Protocol,
            ),
            (
                OutletError::QueryCostViolation { reason: "r".into() },
                OutletErrorClass::Protocol,
            ),
        ];
        for (err, want_class) in &cases {
            assert_consistent(err, *want_class);
        }
    }

    #[test]
    fn interface_rate_limited_extracts_transport_rate_limit_detail() {
        let s = OutletError::InterfaceRateLimited {
            max_calls: 10,
            window_ms: 1000,
            retry_after_secs: 42,
        }
        .to_surface();
        match s.detail {
            Some(DetailBody::TransportRateLimit { retry_after_secs }) => {
                assert_eq!(retry_after_secs, 42);
            }
            other => panic!("expected TransportRateLimit, got {other:?}"),
        }
    }

    #[test]
    fn schema_errors_extract_field_violation_detail() {
        let s =
            OutletError::InvalidOutputSchema(SchemaValidationError::MissingTypeField).to_surface();
        assert_eq!(s.class, OutletErrorClass::Output);
        assert!(matches!(s.detail, Some(DetailBody::FieldViolation { .. })));
    }

    #[test]
    fn authorization_denials_carry_no_detail() {
        // Oracle-collapse / privacy: identity-bearing denials must not leak
        // structured detail.
        for err in [
            OutletError::RegistrantNotAuthorized { did: "d".into() },
            OutletError::InvokerNotAuthorized {
                did: "d".into(),
                outlet_id: "o".into(),
            },
        ] {
            let s = err.to_surface();
            assert_eq!(s.class, OutletErrorClass::Authorization);
            assert!(s.detail.is_none(), "auth denial must carry no detail");
        }
    }
}
