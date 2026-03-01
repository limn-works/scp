//! Tool registration, schema validation, invocation lifecycle, and verification
//! for SCP contexts.
//!
//! Tools are stateless functions scoped to a context (spec section 5.4). They
//! have MCP-compatible JSON Schema interfaces (spec section 8.5), making them
//! interoperable with existing MCP tooling. Every tool registration includes
//! schema, implementation hash, test vectors, and operator DID -- providing
//! verifiable integrity (spec section 7.3.3).
//!
//! See ADR-010 in `.docs/adrs/phase-2.md` for the full design.
//!
//! # Modules
//!
//! - [`registry`] -- Tool registration storage, `register_tool`, `update_tool`,
//!   `verify_tool`.
//! - [`schema`] -- JSON Schema validation helpers and MCP compatibility.
//! - [`invoke`] -- Tool invocation with full execution lifecycle:
//!   capability checking, schema validation, timeout, cancellation.
//! - [`lifecycle`] -- Request/response types, status codes, error codes,
//!   cancellation, and event log integration for tool invocations.
//!
//! # Types
//!
//! - [`ToolId`] -- Unique identifier for a registered tool.
//! - [`ToolError`] -- Error type for tool operations.
//! - [`ToolRegistration`] -- Full tool registration with schema, hash, test
//!   vectors, and operator DID. (Re-exported from [`registry`].)
//! - [`ToolSchema`] -- MCP-compatible JSON Schema for input/output.
//!   (Re-exported from [`registry`].)
//! - [`TestVector`] -- Known input-output pair for tool verification.
//!   (Re-exported from [`registry`].)
//! - [`ToolRegistry`] -- In-memory tool storage per context.
//!   (Re-exported from [`registry`].)
//! - [`ToolRequest`] -- Tool invocation request. (Re-exported from
//!   [`lifecycle`].)
//! - [`ToolResponse`] -- Tool invocation response. (Re-exported from
//!   [`lifecycle`].)
//! - [`ToolStatus`] -- Invocation terminal status. (Re-exported from
//!   [`lifecycle`].)
//! - [`ToolExecutionError`] -- Structured execution error. (Re-exported from
//!   [`lifecycle`].)
//! - [`ToolErrorCode`] -- Error code enum. (Re-exported from [`lifecycle`].)
//! - [`ToolCancel`] -- Cancellation request. (Re-exported from [`lifecycle`].)

pub mod interface;
pub mod invoke;
pub mod lifecycle;
pub mod registry;
pub mod schema;
pub mod session;

use crate::context::roles;

pub use invoke::{
    InvocationError, has_tool_invoke_capability, invoke_tool, invoke_tool_with_cancellation,
};
pub use lifecycle::{
    DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS, Provenance, ToolCancel, ToolErrorCode, ToolExecutionError,
    ToolInvokedEvent, ToolRequest, ToolResponse, ToolStatus, sha256_json,
};
pub use registry::{
    TestVector, ToolEconomicMetadata, ToolRegistration, ToolRegistry, ToolSchema,
    ToolVerificationResult, VectorResult, register_tool, update_tool, verify_tool,
};
pub use schema::{SchemaValidationError, validate_schema, validate_value_against_schema};

// ---------------------------------------------------------------------------
// ToolId
// ---------------------------------------------------------------------------

/// Unique identifier for a registered tool within a context.
///
/// Matches the `ToolId` type alias in `context::roles`, re-defined here for
/// module-local clarity. These are the same underlying type (`String`).
pub type ToolId = String;

use crate::identity::DID;

// ---------------------------------------------------------------------------
// ToolError
// ---------------------------------------------------------------------------

/// Errors produced by tool registration, update, and verification operations.
///
/// See ADR-010 for error conditions.
#[derive(Debug, thiserror::Error)]
pub enum ToolError {
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
    #[error("tool not found: \"{tool_id}\"")]
    ToolNotFound {
        /// The tool ID that was not found.
        tool_id: ToolId,
    },

    /// The tool ID in the new registration does not match the existing tool.
    #[error("tool ID mismatch: expected \"{expected}\", got \"{actual}\"")]
    ToolIdMismatch {
        /// The expected tool ID.
        expected: ToolId,
        /// The actual tool ID provided.
        actual: ToolId,
    },

    /// A tool with this ID is already registered.
    #[error("tool already registered: \"{tool_id}\"")]
    ToolAlreadyRegistered {
        /// The duplicate tool ID.
        tool_id: ToolId,
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
    #[error("invoker \"{did}\" not authorized for tool \"{tool_id}\"")]
    InvokerNotAuthorized {
        /// The DID that attempted invocation.
        did: String,
        /// The tool ID.
        tool_id: String,
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
    #[error("invoker \"{did}\" not authorized for cross-context tool \"{tool_id}\"")]
    InterfaceInvokerNotAuthorized {
        /// The DID that attempted invocation.
        did: String,
        /// The tool ID.
        tool_id: String,
    },

    /// Cross-context interface rate limit exceeded.
    #[error("rate limit exceeded: {max_calls} calls per {window_ms}ms")]
    InterfaceRateLimited {
        /// Maximum calls allowed.
        max_calls: u64,
        /// Window duration in milliseconds.
        window_ms: u64,
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

    /// The per-caller session cap has been reached (spec section 6.2.1, 9.2.1).
    #[error(
        "session cap exceeded: calling context \"{source_context}\" has {current} active sessions (max {max})"
    )]
    SessionCapExceeded {
        /// The calling context that hit the cap.
        source_context: String,
        /// Current number of active sessions from this caller.
        current: usize,
        /// Maximum allowed concurrent sessions per caller.
        max: usize,
    },

    /// The tool schema does not meet the specificity floor (spec section 6.2, 9.2.1).
    #[error("schema specificity floor not met: {side} schema has {field_count} distinct fields, minimum {min_fields} required")]
    SchemaSpecificityFloor {
        /// Which schema failed: "input" or "output".
        side: String,
        /// Number of distinct fields found.
        field_count: usize,
        /// Minimum number of fields required.
        min_fields: usize,
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
pub struct ToolRegisteredEvent {
    /// The registered tool's ID.
    pub tool_id: ToolId,
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
pub struct ToolUpdatedEvent {
    /// The updated tool's ID.
    pub tool_id: ToolId,
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

/// Event payload for a `ToolVerified` event in the context event log.
///
/// Records the verification result for auditability.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolVerifiedEvent {
    /// The verified tool's ID.
    pub tool_id: ToolId,
    /// Number of test vectors that passed.
    pub passed: usize,
    /// Number of test vectors that failed.
    pub failed: usize,
    /// Overall integrity assessment.
    pub integrity_ok: bool,
}

// ---------------------------------------------------------------------------
// Capability check helper
// ---------------------------------------------------------------------------

/// Checks whether a member has the `ToolRegister` capability.
///
/// Delegates to the role system's capability check. This is the integration
/// point between the tools module and the UCAN-based role system (ADR-009).
#[must_use]
pub fn has_tool_register_capability(role_state: &roles::ContextRoleState, did: &str) -> bool {
    role_state.member_has_capability(did, &roles::Capability::ToolRegister)
}

/// Checks whether a member has admin-level capabilities.
///
/// Used by `update_tool` to verify the updater is either the tool operator
/// or an admin.
#[must_use]
pub fn has_admin_role(role_state: &roles::ContextRoleState, did: &str) -> bool {
    // Check for the RoleAssign capability as a proxy for admin status,
    // since the admin role includes all capabilities in the ceiling.
    role_state.member_has_capability(did, &roles::Capability::RoleAssign)
}
