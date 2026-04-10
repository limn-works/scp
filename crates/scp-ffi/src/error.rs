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
///
/// Every variant carries a `message` (human-readable detail) and `code`
/// (machine-readable `SCP-{CATEGORY}-{NUMBER}` identifier). Error codes
/// follow `.docs/standards/sdk-common.md` and match the napi-rs and `UniFFI`
/// bridges for cross-SDK consistency.
#[derive(Debug)]
pub enum ScpPyError {
    /// An identity operation failed.
    IdentityError {
        /// Human-readable error message.
        message: String,
        /// Stable error code (e.g. `SCP-IDENT-1001`).
        code: String,
    },
    /// A context lifecycle operation failed.
    ContextError {
        /// Human-readable error message.
        message: String,
        /// Stable error code (e.g. `SCP-CTX-2001`).
        code: String,
    },
    /// A cryptographic operation failed.
    CryptoError {
        /// Human-readable error message.
        message: String,
        /// Stable error code (e.g. `SCP-CRYPTO-4001`).
        code: String,
    },
    /// A transport operation failed.
    TransportError {
        /// Human-readable error message.
        message: String,
        /// Stable error code (e.g. `SCP-TRANS-5001`).
        code: String,
    },
    /// A UCAN operation failed.
    UcanError {
        /// Human-readable error message.
        message: String,
        /// Stable error code (e.g. `SCP-PERM-3001`).
        code: String,
    },
    /// Input validation failed.
    ValidationError {
        /// Human-readable error message.
        message: String,
        /// Stable error code (e.g. `SCP-VALID-7001`).
        code: String,
    },
}

impl std::fmt::Display for ScpPyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IdentityError { message, code } => {
                write!(f, "[{code}] identity error: {message}")
            }
            Self::ContextError { message, code } => {
                write!(f, "[{code}] context error: {message}")
            }
            Self::CryptoError { message, code } => {
                write!(f, "[{code}] crypto error: {message}")
            }
            Self::TransportError { message, code } => {
                write!(f, "[{code}] transport error: {message}")
            }
            Self::UcanError { message, code } => {
                write!(f, "[{code}] permission error: {message}")
            }
            Self::ValidationError { message, code } => {
                write!(f, "[{code}] validation error: {message}")
            }
        }
    }
}

impl std::error::Error for ScpPyError {}

// ---------------------------------------------------------------------------
// Constructors — ergonomic helpers for inline error construction
//
// Bridge functions construct errors at dozens of call sites. These helpers
// provide a concise API that pairs a message with the appropriate default
// error code for the category. Functions that need a *specific* code
// (e.g. SCP-IDENT-1005 vs SCP-IDENT-1001) should use the struct literal
// directly.
// ---------------------------------------------------------------------------

impl ScpPyError {
    /// Identity error with the given message and the generic identity code.
    pub fn identity(msg: impl Into<String>) -> Self {
        Self::IdentityError {
            message: msg.into(),
            code: "SCP-IDENT-1001".to_owned(),
        }
    }

    /// Context error with the given message and the generic context code.
    pub fn context(msg: impl Into<String>) -> Self {
        Self::ContextError {
            message: msg.into(),
            code: "SCP-CTX-2001".to_owned(),
        }
    }

    /// Crypto error with the given message and the generic crypto code.
    pub fn crypto(msg: impl Into<String>) -> Self {
        Self::CryptoError {
            message: msg.into(),
            code: "SCP-CRYPTO-4001".to_owned(),
        }
    }

    /// Transport error with the given message and the generic transport code.
    pub fn transport(msg: impl Into<String>) -> Self {
        Self::TransportError {
            message: msg.into(),
            code: "SCP-TRANS-5001".to_owned(),
        }
    }

    /// UCAN/permission error with the given message and the generic UCAN code.
    pub fn ucan(msg: impl Into<String>) -> Self {
        Self::UcanError {
            message: msg.into(),
            code: "SCP-PERM-3001".to_owned(),
        }
    }

    /// Validation error with the given message and the generic validation code.
    pub fn validation(msg: impl Into<String>) -> Self {
        Self::ValidationError {
            message: msg.into(),
            code: "SCP-VALID-7001".to_owned(),
        }
    }
}

// ---------------------------------------------------------------------------
// From<ScpPyError> for PyErr — maps each variant to its Python exception
// ---------------------------------------------------------------------------

impl From<ScpPyError> for PyErr {
    fn from(e: ScpPyError) -> Self {
        // Embed the error code in the message string so the Python wrapper
        // can parse it. Format: "[SCP-CATEGORY-NUMBER] category error: message"
        let formatted = e.to_string();
        match e {
            ScpPyError::IdentityError { .. } => IdentityError::new_err(formatted),
            ScpPyError::ContextError { .. } => ContextError::new_err(formatted),
            ScpPyError::CryptoError { .. } => CryptoError::new_err(formatted),
            ScpPyError::TransportError { .. } => TransportError::new_err(formatted),
            ScpPyError::UcanError { .. } => UcanError::new_err(formatted),
            ScpPyError::ValidationError { .. } => ValidationError::new_err(formatted),
        }
    }
}

// ---------------------------------------------------------------------------
// From<scp-core error types> for ScpPyError
// ---------------------------------------------------------------------------

// Identity errors → ScpPyError::IdentityError

impl From<scp_identity::IdentityError> for ScpPyError {
    fn from(e: scp_identity::IdentityError) -> Self {
        Self::IdentityError {
            message: format!(
                "{e} — check DID format, key custody configuration, or DHT connectivity"
            ),
            code: "SCP-IDENT-1001".to_owned(),
        }
    }
}

// Context errors → ScpPyError::ContextError
//
// Most ContextError variants map to the generic SCP-CTX-2001 envelope.
// A few variants carry typed semantics that the Python binding can
// distinguish programmatically — those are mapped to their canonical
// error codes so callers can `except ScpError` + `.code` check
// without string-matching on the message body.

impl From<scp_core::context::ContextError> for ScpPyError {
    fn from(e: scp_core::context::ContextError) -> Self {
        use scp_core::context::ContextError as CE;
        match &e {
            // Surface the canonical rate-limit code on the typed
            // envelope so callers can `except ScpError` + `.code`
            // check instead of string-matching `SCP-ECON-12090`
            // inside the message body.
            CE::RateLimited { .. } => Self::ContextError {
                message: format!("{e}"),
                code: "SCP-ECON-12090".to_owned(),
            },
            // §23.17: snapshot import regression rejection.
            CE::SnapshotFloorRegression { .. } => Self::ContextError {
                message: format!("{e}"),
                code: "SCP-CTX-2091".to_owned(),
            },
            _ => Self::ContextError {
                message: format!("{e} — verify context state, membership, and permissions"),
                code: "SCP-CTX-2001".to_owned(),
            },
        }
    }
}

impl From<scp_core::context::builder::ContextCreationError> for ScpPyError {
    fn from(e: scp_core::context::builder::ContextCreationError) -> Self {
        Self::ContextError {
            message: format!(
                "context creation failed: {e} — check context parameters and identity"
            ),
            code: "SCP-CTX-2002".to_owned(),
        }
    }
}

impl From<scp_core::context::templates::TemplateError> for ScpPyError {
    fn from(e: scp_core::context::templates::TemplateError) -> Self {
        Self::ContextError {
            message: format!(
                "template validation failed: {e} — ensure context params match the template definition"
            ),
            code: "SCP-CTX-2003".to_owned(),
        }
    }
}

impl From<scp_core::context::roles::RoleError> for ScpPyError {
    fn from(e: scp_core::context::roles::RoleError) -> Self {
        Self::ContextError {
            message: format!(
                "role operation failed: {e} — verify role definitions and member permissions"
            ),
            code: "SCP-CTX-2004".to_owned(),
        }
    }
}

impl From<scp_core::context::ttl::TtlError> for ScpPyError {
    fn from(e: scp_core::context::ttl::TtlError) -> Self {
        Self::ContextError {
            message: format!(
                "TTL operation failed: {e} — check TTL configuration and context state"
            ),
            code: "SCP-CTX-2005".to_owned(),
        }
    }
}

impl From<scp_core::context::promotion::PromotionError> for ScpPyError {
    fn from(e: scp_core::context::promotion::PromotionError) -> Self {
        Self::ContextError {
            message: format!(
                "context promotion failed: {e} — verify eligibility and governance rules"
            ),
            code: "SCP-CTX-2006".to_owned(),
        }
    }
}

// Tool errors → ScpPyError (tools category, matching napi/uniffi bridges)

impl From<scp_core::context::tools::ToolError> for ScpPyError {
    fn from(e: scp_core::context::tools::ToolError) -> Self {
        Self::ContextError {
            message: format!(
                "tool operation failed: {e} — check tool registration, permissions, and input schema"
            ),
            code: "SCP-TOOL-6001".to_owned(),
        }
    }
}

impl From<scp_core::context::tools::invoke::InvocationError> for ScpPyError {
    fn from(e: scp_core::context::tools::invoke::InvocationError) -> Self {
        Self::ContextError {
            message: format!(
                "tool invocation failed: {e} — verify tool ID, input, and caller permissions"
            ),
            code: "SCP-TOOL-6002".to_owned(),
        }
    }
}

impl From<scp_core::context::tools::schema::SchemaValidationError> for ScpPyError {
    fn from(e: scp_core::context::tools::schema::SchemaValidationError) -> Self {
        Self::ValidationError {
            message: format!(
                "schema validation failed: {e} — check input against the tool's JSON Schema"
            ),
            code: "SCP-VALID-7001".to_owned(),
        }
    }
}

// Crypto errors → ScpPyError::CryptoError

impl From<scp_core::crypto::mls::error::MlsError> for ScpPyError {
    fn from(e: scp_core::crypto::mls::error::MlsError) -> Self {
        Self::CryptoError {
            message: format!(
                "MLS operation failed: {e} — check group state and member key packages"
            ),
            code: "SCP-CRYPTO-4001".to_owned(),
        }
    }
}

impl From<scp_core::crypto::sender_keys::SenderKeyError> for ScpPyError {
    fn from(e: scp_core::crypto::sender_keys::SenderKeyError) -> Self {
        Self::CryptoError {
            message: format!(
                "sender key operation failed: {e} — verify key material and encryption parameters"
            ),
            code: "SCP-CRYPTO-4002".to_owned(),
        }
    }
}

// UCAN errors → ScpPyError::UcanError

impl From<scp_core::crypto::ucan::UcanError> for ScpPyError {
    fn from(e: scp_core::crypto::ucan::UcanError) -> Self {
        Self::UcanError {
            message: format!(
                "{e} — check token format, signatures, time bounds, and capability chain"
            ),
            code: "SCP-PERM-3001".to_owned(),
        }
    }
}

// Envelope errors → ScpPyError::CryptoError (envelopes are a crypto concern)

impl From<scp_core::envelope::EnvelopeError> for ScpPyError {
    fn from(e: scp_core::envelope::EnvelopeError) -> Self {
        Self::CryptoError {
            message: format!(
                "envelope operation failed: {e} — check payload size, signing keys, and encryption state"
            ),
            code: "SCP-CRYPTO-4003".to_owned(),
        }
    }
}

// Event log errors → ScpPyError::ContextError (event logs belong to contexts)

impl From<scp_event_log::EventLogError> for ScpPyError {
    fn from(e: scp_event_log::EventLogError) -> Self {
        Self::ContextError {
            message: format!(
                "event log operation failed: {e} — verify log integrity and sequence numbers"
            ),
            code: "SCP-CTX-2007".to_owned(),
        }
    }
}

// Provenance errors → ScpPyError::ValidationError

impl From<scp_core::provenance::ProvenanceError> for ScpPyError {
    fn from(e: scp_core::provenance::ProvenanceError) -> Self {
        Self::ValidationError {
            message: format!("provenance validation failed: {e} — check cross-context chain depth"),
            code: "SCP-VALID-7002".to_owned(),
        }
    }
}

// Trust errors → ScpPyError::ValidationError

impl From<scp_core::trust::TrustError> for ScpPyError {
    fn from(e: scp_core::trust::TrustError) -> Self {
        Self::ValidationError {
            message: format!(
                "trust evaluation failed: {e} — check event log data and attestation validity"
            ),
            code: "SCP-VALID-7003".to_owned(),
        }
    }
}

// URI errors → ScpPyError::ValidationError

impl From<scp_core::uri::ScpUriError> for ScpPyError {
    fn from(e: scp_core::uri::ScpUriError) -> Self {
        Self::ValidationError {
            message: format!("invalid SCP URI: {e} — check URI format (scp://relay/context-id)"),
            code: "SCP-VALID-7004".to_owned(),
        }
    }
}

// Well-known validation errors → ScpPyError::ValidationError

impl From<scp_core::well_known::WellKnownValidationError> for ScpPyError {
    fn from(e: scp_core::well_known::WellKnownValidationError) -> Self {
        Self::ValidationError {
            message: format!("well-known validation failed: {e} — check relay configuration"),
            code: "SCP-VALID-7005".to_owned(),
        }
    }
}

// Discovery errors → ScpPyError::ContextError

impl From<scp_core::discovery::DiscoveryError> for ScpPyError {
    fn from(e: scp_core::discovery::DiscoveryError) -> Self {
        Self::ContextError {
            message: format!(
                "discovery operation failed: {e} — check relay connectivity and search parameters"
            ),
            code: "SCP-CTX-2008".to_owned(),
        }
    }
}

// Bridge errors → ScpPyError::ContextError

impl From<scp_core::bridge::registration::BridgeRegistrationError> for ScpPyError {
    fn from(e: scp_core::bridge::registration::BridgeRegistrationError) -> Self {
        Self::ContextError {
            message: format!(
                "bridge registration failed: {e} — verify bridge configuration and permissions"
            ),
            code: "SCP-CTX-2009".to_owned(),
        }
    }
}

impl From<scp_core::bridge::shadow::ShadowError> for ScpPyError {
    fn from(e: scp_core::bridge::shadow::ShadowError) -> Self {
        Self::ContextError {
            message: format!(
                "shadow context operation failed: {e} — check bridge state and context permissions"
            ),
            code: "SCP-CTX-2010".to_owned(),
        }
    }
}

// Transport errors → ScpPyError::TransportError

impl From<scp_transport::TransportError> for ScpPyError {
    fn from(e: scp_transport::TransportError) -> Self {
        Self::TransportError {
            message: format!(
                "{e} — check relay URL, network connectivity, and transport configuration"
            ),
            code: "SCP-TRANS-5001".to_owned(),
        }
    }
}

// Platform errors → ScpPyError::CryptoError (key custody)

impl From<scp_platform::PlatformError> for ScpPyError {
    fn from(e: scp_platform::PlatformError) -> Self {
        Self::CryptoError {
            message: format!(
                "platform key operation failed: {e} — check key custody configuration"
            ),
            code: "SCP-CRYPTO-4004".to_owned(),
        }
    }
}

// serde_json errors → ScpPyError::ValidationError (JSON parse failures)

impl From<serde_json::Error> for ScpPyError {
    fn from(e: serde_json::Error) -> Self {
        Self::ValidationError {
            message: format!("JSON serialization/deserialization failed: {e} — check input format"),
            code: "SCP-VALID-7006".to_owned(),
        }
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
