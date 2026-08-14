#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Pure sync protocol types and logic for SCP.
//! No tokio, no async, no `OpenMLS`, no scp-platform.

pub mod bridge;
pub mod context;
pub mod crypto;
pub mod discovery;
pub mod economy;
pub mod envelope;
pub mod identity;
pub mod jcs;
pub mod provenance;
pub mod serde_util;
pub mod sync;
pub mod trust;
pub mod uri;

// Outlet surface re-exports (SCP-OUT-002, AC-5). `OutletId` is exported from
// [`context::roles`]; the remaining types come from [`context::outlets`] and
// its submodules. See §5.4.1, §5.4.5, and ADR-049.
//
// Coverage notes:
// - `OutletLifecycleEvent`, `OutletIntegrityStatus`, and `OutletSummary` are
//   umbrella names in the story. The current implementation factors lifecycle
//   into `OutletInvokedEvent` / `OutletRequest` / `OutletStatus` /
//   `OutletCancel` (legacy `OutletResponse` / `OutletErrorCode` /
//   `OutletExecutionError` were deleted by SCP-OUT-032 and replaced by the
//   §5.4.5 streaming wire types and the §5.4.4 `OutletErrorEnvelope`);
//   integrity into `OutletVerificationResult` / `OutletVerificationSchedule`;
//   and summary into `ContextSummary` (shared with other context facets).
//   All the concrete types are re-exported below so every story-named facade
//   is reachable from the crate root.
pub use context::outlets::OutletId;
pub use context::outlets::integrity::OutletVerificationSchedule;
pub use context::outlets::interface::OutletInterface;
pub use context::outlets::message_catalog::{
    CATALOG_MAX_ENTRIES, MessageTemplate, MessageTemplateError, TEMPLATE_MAX_BYTES,
    canonical_catalog_messagepack,
};
pub use context::outlets::registration::{OutletRegistration, RegistrationError};
pub use context::outlets::registry::{
    OutletCost, OutletRegistry, OutletSchema, OutletTestVector, OutletVerificationResult,
};
pub use context::outlets::stream::{
    ChunkPayload, CreditGrantSigningInputs, DEFAULT_CREDIT_WINDOW,
    DEFAULT_STREAM_CREDIT_STALL_SECS, DEFAULT_STREAM_UCAN_RECHECK_SECS, OpenObservation,
    OutletStreamChunk, OutletStreamCredit, OutletStreamOpen, RequestId as OutletRequestId,
    SCP_OUTLET_CAVEAT_BIND_V1, SCP_OUTLET_CHUNK_SIG_V1, SCP_OUTLET_CHUNK_V1, SCP_OUTLET_CREDIT_V1,
    SessionState, StreamRejection, StreamTerminalStatus, compute_caveats_binding,
    compute_chunk_sig_preimage, compute_credit_sig_preimage, evaluate_open_pinning,
    evaluate_revocation_recheck, evaluate_session_open, sign_chunk, sign_credit_grant,
    verify_chunk_signature, verify_credit_signature,
};
pub use context::outlets::{
    OutletCancel, OutletError, OutletInvokedEvent, OutletKind, OutletRegisteredEvent,
    OutletRequest, OutletStatus, OutletUpdatedEvent, OutletVerifiedEvent, OutletVerifiedReason,
};

// Typed §5.4.4 OutletError envelope and supporting types (SCP-OUT-024 / ADR-049
// §4). The `errors` submodule provides the typed envelope struct under that
// path because the crate-root `OutletError` name is currently bound to the
// legacy thiserror enum (re-exported above). Stories SCP-OUT-027 / 036 / 038
// retire the legacy enum and promote the typed envelope to the crate-root
// `OutletError` slot; until that migration lands, downstream code reaches the
// typed envelope via `scp_protocol::context::outlets::errors::OutletError` or
// the convenience alias [`OutletErrorEnvelope`] re-exported below.
pub use context::outlets::errors::{
    CATALOG_KEY_MAX_BYTES, CatalogKey, CatalogKeyError, ContextHop, DetailBody, DetailKind,
    MESSAGE_MAX_BYTES, OUTLET_MESSAGE_KEY_LEN, OutletError as OutletErrorEnvelope,
    OutletErrorClass, OutletErrorConstructionFailed, PAD_NONCE_LEN, REGISTRATION_EVENT_ID_LEN,
    RelayUrlKind, RetryPolicy, WIRE_MESSAGE_LEN, validate_catalog_key, validate_outlet_error_code,
};

// SCP-OUT-025: compact §5.4.4 6100-6199 code allocation + per-class slug
// taxonomy. `error_code_to_class`, `error_code_to_default_slug`,
// `error_code_to_retry_policy`, `slug_to_class`, and `validate_slug` are the
// public lookup functions; the `CODE_*` and `SLUG_*` constants name the
// allocated codes and slugs.
pub use context::outlets::error_codes::{
    ALL_CODES, CODE_AUTHORIZATION_ATTENUATION, CODE_AUTHORIZATION_DENIED,
    CODE_AUTHORIZATION_SALT_ROTATION, CODE_ECONOMIC_FAULT, CODE_EXECUTION_CANCEL_ACK_TIMEOUT,
    CODE_EXECUTION_CREDIT, CODE_EXECUTION_CREDIT_STALL, CODE_EXECUTION_FAULT,
    CODE_GOVERNANCE_FAULT, CODE_INPUT_VIOLATION, CODE_OUTPUT_VIOLATION, CODE_PROTOCOL_SESSION,
    CODE_PROTOCOL_VIOLATION, CODE_TRANSPORT_FAULT, SLUG_PROTOCOL_UNKNOWN_SESSION, SlugError,
    error_code_to_class, error_code_to_default_slug, error_code_to_retry_policy, slug_to_class,
    validate_slug,
};
