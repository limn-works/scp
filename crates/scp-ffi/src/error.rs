//! Unified error hierarchy mapping Rust errors to Python exceptions.
//!
//! Every Rust error type from `scp-core` and `scp-transport` maps to a specific
//! Python exception class. Exception classes form a hierarchy rooted at
//! `scp_sdk.ScpError` (which extends Python's `Exception`).
//!
//! # Exception hierarchy
//!
//! ```text
//! Exception
//! └── ScpError
//!     ├── IdentityError
//!     ├── ContextError
//!     ├── CryptoError
//!     ├── TransportError
//!     ├── UcanError
//!     └── ValidationError
//! ```
//!
//! # Error messages
//!
//! All error messages include actionable detail: what failed, why, and (where
//! possible) what the caller should do to recover. The `Display` implementation
//! on [`ScpPyError`] produces these messages.
//!
//! See ADR-013 in `.docs/adrs/phase-3.md` for the full specification.

use pyo3::prelude::*;

// ---------------------------------------------------------------------------
// Python exception class hierarchy
// ---------------------------------------------------------------------------

// Root exception: scp_sdk.ScpError (extends Python's Exception).
pyo3::create_exception!(
    scp_sdk,
    ScpError,
    pyo3::exceptions::PyException,
    "Base exception for all SCP protocol errors."
);

// Domain-specific exceptions, all rooted at ScpError.
pyo3::create_exception!(
    scp_sdk,
    IdentityError,
    ScpError,
    "An identity operation failed (DID creation, resolution, key rotation)."
);
pyo3::create_exception!(
    scp_sdk,
    ContextError,
    ScpError,
    "A context lifecycle operation failed (create, join, leave, close, send)."
);
pyo3::create_exception!(
    scp_sdk,
    CryptoError,
    ScpError,
    "A cryptographic operation failed (MLS, sender keys, encryption, decryption)."
);
pyo3::create_exception!(
    scp_sdk,
    TransportError,
    ScpError,
    "A transport operation failed (connection, send, subscription)."
);
pyo3::create_exception!(
    scp_sdk,
    UcanError,
    ScpError,
    "A UCAN operation failed (validation, minting, revocation)."
);
pyo3::create_exception!(
    scp_sdk,
    ValidationError,
    ScpError,
    "Input validation failed (malformed data, schema mismatch, constraint violation)."
);

// ---------------------------------------------------------------------------
// ScpPyError enum
// ---------------------------------------------------------------------------

/// Unified error type for the `PyO3` bridge layer.
///
/// Each variant maps one-to-one to a Python exception class in the
/// `scp_sdk` hierarchy. Bridge functions return `Result<T, ScpPyError>`,
/// which `PyO3` converts to a Python exception via the [`From<ScpPyError> for PyErr`]
/// implementation below.
#[derive(Debug)]
pub enum ScpPyError {
    /// An identity operation failed.
    IdentityError(String),
    /// A context lifecycle operation failed.
    ContextError(String),
    /// A cryptographic operation failed.
    CryptoError(String),
    /// A transport operation failed.
    TransportError(String),
    /// A UCAN operation failed.
    UcanError(String),
    /// Input validation failed.
    ValidationError(String),
}

impl std::fmt::Display for ScpPyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IdentityError(msg) => write!(f, "identity error: {msg}"),
            Self::ContextError(msg) => write!(f, "context error: {msg}"),
            Self::CryptoError(msg) => write!(f, "crypto error: {msg}"),
            Self::TransportError(msg) => write!(f, "transport error: {msg}"),
            Self::UcanError(msg) => write!(f, "UCAN error: {msg}"),
            Self::ValidationError(msg) => write!(f, "validation error: {msg}"),
        }
    }
}

impl std::error::Error for ScpPyError {}

// ---------------------------------------------------------------------------
// From<ScpPyError> for PyErr — maps each variant to its Python exception
// ---------------------------------------------------------------------------

impl From<ScpPyError> for PyErr {
    fn from(e: ScpPyError) -> Self {
        match e {
            ScpPyError::IdentityError(msg) => IdentityError::new_err(msg),
            ScpPyError::ContextError(msg) => ContextError::new_err(msg),
            ScpPyError::CryptoError(msg) => CryptoError::new_err(msg),
            ScpPyError::TransportError(msg) => TransportError::new_err(msg),
            ScpPyError::UcanError(msg) => UcanError::new_err(msg),
            ScpPyError::ValidationError(msg) => ValidationError::new_err(msg),
        }
    }
}

// ---------------------------------------------------------------------------
// From<scp-core error types> for ScpPyError
// ---------------------------------------------------------------------------

// Identity errors → ScpPyError::IdentityError

impl From<scp_identity::IdentityError> for ScpPyError {
    fn from(e: scp_identity::IdentityError) -> Self {
        Self::IdentityError(format!(
            "{e} — check DID format, key custody configuration, or DHT connectivity"
        ))
    }
}

// Context errors → ScpPyError::ContextError

impl From<scp_core::context::ContextError> for ScpPyError {
    fn from(e: scp_core::context::ContextError) -> Self {
        Self::ContextError(format!(
            "{e} — verify context state, membership, and permissions"
        ))
    }
}

impl From<scp_core::context::builder::ContextCreationError> for ScpPyError {
    fn from(e: scp_core::context::builder::ContextCreationError) -> Self {
        Self::ContextError(format!(
            "context creation failed: {e} — check context parameters and identity"
        ))
    }
}

impl From<scp_core::context::templates::TemplateError> for ScpPyError {
    fn from(e: scp_core::context::templates::TemplateError) -> Self {
        Self::ContextError(format!(
            "template validation failed: {e} — ensure context params match the template definition"
        ))
    }
}

impl From<scp_core::context::roles::RoleError> for ScpPyError {
    fn from(e: scp_core::context::roles::RoleError) -> Self {
        Self::ContextError(format!(
            "role operation failed: {e} — verify role definitions and member permissions"
        ))
    }
}

impl From<scp_core::context::ttl::TtlError> for ScpPyError {
    fn from(e: scp_core::context::ttl::TtlError) -> Self {
        Self::ContextError(format!(
            "TTL operation failed: {e} — check TTL configuration and context state"
        ))
    }
}

impl From<scp_core::context::promotion::PromotionError> for ScpPyError {
    fn from(e: scp_core::context::promotion::PromotionError) -> Self {
        Self::ContextError(format!(
            "context promotion failed: {e} — verify eligibility and governance rules"
        ))
    }
}

// Tool errors → ScpPyError::ContextError (tools operate within contexts)

impl From<scp_core::context::tools::ToolError> for ScpPyError {
    fn from(e: scp_core::context::tools::ToolError) -> Self {
        Self::ContextError(format!(
            "tool operation failed: {e} — check tool registration, permissions, and input schema"
        ))
    }
}

impl From<scp_core::context::tools::invoke::InvocationError> for ScpPyError {
    fn from(e: scp_core::context::tools::invoke::InvocationError) -> Self {
        Self::ContextError(format!(
            "tool invocation failed: {e} — verify tool ID, input, and caller permissions"
        ))
    }
}

impl From<scp_core::context::tools::schema::SchemaValidationError> for ScpPyError {
    fn from(e: scp_core::context::tools::schema::SchemaValidationError) -> Self {
        Self::ValidationError(format!(
            "schema validation failed: {e} — check input against the tool's JSON Schema"
        ))
    }
}

// Crypto errors → ScpPyError::CryptoError

impl From<scp_core::crypto::mls::error::MlsError> for ScpPyError {
    fn from(e: scp_core::crypto::mls::error::MlsError) -> Self {
        Self::CryptoError(format!(
            "MLS operation failed: {e} — check group state and member key packages"
        ))
    }
}

impl From<scp_core::crypto::sender_keys::SenderKeyError> for ScpPyError {
    fn from(e: scp_core::crypto::sender_keys::SenderKeyError) -> Self {
        Self::CryptoError(format!(
            "sender key operation failed: {e} — verify key material and encryption parameters"
        ))
    }
}

// UCAN errors → ScpPyError::UcanError

impl From<scp_core::crypto::ucan::UcanError> for ScpPyError {
    fn from(e: scp_core::crypto::ucan::UcanError) -> Self {
        Self::UcanError(format!(
            "{e} — check token format, signatures, time bounds, and capability chain"
        ))
    }
}

// Envelope errors → ScpPyError::CryptoError (envelopes are a crypto concern)

impl From<scp_core::envelope::EnvelopeError> for ScpPyError {
    fn from(e: scp_core::envelope::EnvelopeError) -> Self {
        Self::CryptoError(format!(
            "envelope operation failed: {e} — check payload size, signing keys, and encryption state"
        ))
    }
}

// Event log errors → ScpPyError::ContextError (event logs belong to contexts)

impl From<scp_event_log::EventLogError> for ScpPyError {
    fn from(e: scp_event_log::EventLogError) -> Self {
        Self::ContextError(format!(
            "event log operation failed: {e} — verify log integrity and sequence numbers"
        ))
    }
}

// Provenance errors → ScpPyError::ValidationError

impl From<scp_core::provenance::ProvenanceError> for ScpPyError {
    fn from(e: scp_core::provenance::ProvenanceError) -> Self {
        Self::ValidationError(format!(
            "provenance validation failed: {e} — check cross-context chain depth"
        ))
    }
}

// Trust errors → ScpPyError::ValidationError

impl From<scp_core::trust::TrustError> for ScpPyError {
    fn from(e: scp_core::trust::TrustError) -> Self {
        Self::ValidationError(format!(
            "trust evaluation failed: {e} — check event log data and attestation validity"
        ))
    }
}

// URI errors → ScpPyError::ValidationError

impl From<scp_core::uri::ScpUriError> for ScpPyError {
    fn from(e: scp_core::uri::ScpUriError) -> Self {
        Self::ValidationError(format!(
            "invalid SCP URI: {e} — check URI format (scp://relay/context-id)"
        ))
    }
}

// Well-known validation errors → ScpPyError::ValidationError

impl From<scp_core::well_known::WellKnownValidationError> for ScpPyError {
    fn from(e: scp_core::well_known::WellKnownValidationError) -> Self {
        Self::ValidationError(format!(
            "well-known validation failed: {e} — check relay configuration"
        ))
    }
}

// Discovery errors → ScpPyError::ContextError

impl From<scp_core::discovery::DiscoveryError> for ScpPyError {
    fn from(e: scp_core::discovery::DiscoveryError) -> Self {
        Self::ContextError(format!(
            "discovery operation failed: {e} — check relay connectivity and search parameters"
        ))
    }
}

// Bridge errors → ScpPyError::ContextError

impl From<scp_core::bridge::registration::BridgeRegistrationError> for ScpPyError {
    fn from(e: scp_core::bridge::registration::BridgeRegistrationError) -> Self {
        Self::ContextError(format!(
            "bridge registration failed: {e} — verify bridge configuration and permissions"
        ))
    }
}

impl From<scp_core::bridge::shadow::ShadowError> for ScpPyError {
    fn from(e: scp_core::bridge::shadow::ShadowError) -> Self {
        Self::ContextError(format!(
            "shadow context operation failed: {e} — check bridge state and context permissions"
        ))
    }
}

// Transport errors → ScpPyError::TransportError

impl From<scp_transport::TransportError> for ScpPyError {
    fn from(e: scp_transport::TransportError) -> Self {
        Self::TransportError(format!(
            "{e} — check relay URL, network connectivity, and transport configuration"
        ))
    }
}

// serde_json errors → ScpPyError::ValidationError (JSON parse failures)

impl From<serde_json::Error> for ScpPyError {
    fn from(e: serde_json::Error) -> Self {
        Self::ValidationError(format!(
            "JSON serialization/deserialization failed: {e} — check input format"
        ))
    }
}

// ---------------------------------------------------------------------------
// Module registration helper
// ---------------------------------------------------------------------------

/// Registers all SCP exception classes on the given Python module.
///
/// Called from the `_scp_core` module init function in `lib.rs`. This makes
/// the exception classes importable as `from _scp_core import ScpError, ...`
/// and also available in the `scp_sdk` namespace via re-export.
///
/// # Errors
///
/// Returns `PyErr` if adding exception classes to the module fails.
pub fn register_exceptions(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("ScpError", m.py().get_type::<ScpError>())?;
    m.add("IdentityError", m.py().get_type::<IdentityError>())?;
    m.add("ContextError", m.py().get_type::<ContextError>())?;
    m.add("CryptoError", m.py().get_type::<CryptoError>())?;
    m.add("TransportError", m.py().get_type::<TransportError>())?;
    m.add("UcanError", m.py().get_type::<UcanError>())?;
    m.add("ValidationError", m.py().get_type::<ValidationError>())?;
    Ok(())
}
