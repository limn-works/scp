//! Error hierarchy and mapping for the napi-rs bridge.
//!
//! Rust `Result<T, ScpNapiError>` maps to JS `Promise` rejection. Each variant
//! carries a stable error code string (`SCP-{CATEGORY}-{NUMBER}`) for
//! programmatic handling in TypeScript.
//!
//! The error code categories match `.docs/standards/sdk-common.md`:
//!
//! | Prefix | Range | Category |
//! |--------|-------|----------|
//! | `SCP-IDENT-` | 1000-1999 | Identity errors |
//! | `SCP-CTX-` | 2000-2999 | Context errors |
//! | `SCP-PERM-` | 3000-3999 | UCAN / permission errors |
//! | `SCP-CRYPTO-` | 4000-4999 | Cryptographic errors |
//! | `SCP-TRANS-` | 5000-5999 | Transport errors |
//! | `SCP-TOOL-` | 6000-6999 | Tool errors |
//! | `SCP-VALID-` | 7000-7999 | Validation errors |
//!
//! # napi-rs error model
//!
//! napi-rs maps `napi::Error` (which wraps a `Status` and a reason string) to
//! JS `Error` objects. Functions that return `napi::Result<T>` reject the
//! returned Promise when they fail. `ScpNapiError` implements `Into<napi::Error>`
//! so bridge functions can use `?` to propagate errors.
//!
//! See ADR-022 in `.docs/adrs/phase-4.md`.

use napi::Status;

// ---------------------------------------------------------------------------
// ScpNapiError — unified error type for the napi bridge layer
// ---------------------------------------------------------------------------

/// Unified error type for the napi-rs bridge.
///
/// Each variant maps to one category in the cross-SDK error hierarchy defined
/// in `.docs/standards/sdk-common.md`. The `message` and `code` fields are
/// embedded in the JS `Error` message string so the TypeScript wrapper can
/// parse them into typed `ScpError` subclasses.
///
/// # TypeScript error mapping
///
/// The JS `Error.message` property has the format:
/// `"[{code}] {category} error: {message}"`.
/// The TypeScript SDK parses the bracketed code prefix to select the
/// appropriate `ScpError` subclass.
#[derive(Debug, thiserror::Error)]
pub enum ScpNapiError {
    /// An identity operation failed (DID creation, resolution, key rotation).
    #[error("[{code}] identity error: {message}")]
    Identity {
        /// Human-readable error message.
        message: String,
        /// Stable error code (e.g. `SCP-IDENT-1001`).
        code: String,
    },

    /// A context lifecycle operation failed (create, join, leave, close, send).
    #[error("[{code}] context error: {message}")]
    Context {
        /// Human-readable error message.
        message: String,
        /// Stable error code (e.g. `SCP-CTX-2001`).
        code: String,
    },

    /// A capability or governance permission check failed.
    #[error("[{code}] permission error: {message}")]
    Permission {
        /// Human-readable error message.
        message: String,
        /// Stable error code (e.g. `SCP-PERM-3001`).
        code: String,
    },

    /// A cryptographic operation failed (MLS, sender keys, encryption).
    ///
    /// Messages never include key material or internal crypto state.
    #[error("[{code}] crypto error: {message}")]
    Crypto {
        /// Human-readable error message.
        message: String,
        /// Stable error code (e.g. `SCP-CRYPTO-4001`).
        code: String,
    },

    /// A transport operation failed (connection, send, subscription).
    #[error("[{code}] transport error: {message}")]
    Transport {
        /// Human-readable error message.
        message: String,
        /// Stable error code (e.g. `SCP-TRANS-5001`).
        code: String,
    },

    /// A tool operation failed (registration, invocation, verification).
    #[error("[{code}] tool error: {message}")]
    Tool {
        /// Human-readable error message.
        message: String,
        /// Stable error code (e.g. `SCP-TOOL-6001`).
        code: String,
    },

    /// Input validation failed (malformed data, schema mismatch, constraint violation).
    #[error("[{code}] validation error: {message}")]
    Validation {
        /// Human-readable error message.
        message: String,
        /// Stable error code (e.g. `SCP-VALID-7001`).
        code: String,
    },
}

impl From<ScpNapiError> for napi::Error {
    fn from(e: ScpNapiError) -> Self {
        Self::new(Status::GenericFailure, e.to_string())
    }
}

// ---------------------------------------------------------------------------
// From<scp-core error types> for ScpNapiError
// ---------------------------------------------------------------------------

impl From<scp_core::identity::IdentityError> for ScpNapiError {
    fn from(e: scp_core::identity::IdentityError) -> Self {
        Self::Identity {
            message: format!(
                "{e} — check DID format, key custody configuration, or DHT connectivity"
            ),
            code: "SCP-IDENT-1001".to_owned(),
        }
    }
}

impl From<scp_core::context::ContextError> for ScpNapiError {
    fn from(e: scp_core::context::ContextError) -> Self {
        Self::Context {
            message: format!("{e} — verify context state, membership, and permissions"),
            code: "SCP-CTX-2001".to_owned(),
        }
    }
}

impl From<scp_core::context::builder::ContextCreationError> for ScpNapiError {
    fn from(e: scp_core::context::builder::ContextCreationError) -> Self {
        Self::Context {
            message: format!(
                "context creation failed: {e} — check context parameters and identity"
            ),
            code: "SCP-CTX-2002".to_owned(),
        }
    }
}

impl From<scp_core::context::templates::TemplateError> for ScpNapiError {
    fn from(e: scp_core::context::templates::TemplateError) -> Self {
        Self::Context {
            message: format!(
                "template validation failed: {e} — ensure context params match the template"
            ),
            code: "SCP-CTX-2003".to_owned(),
        }
    }
}

impl From<scp_core::context::roles::RoleError> for ScpNapiError {
    fn from(e: scp_core::context::roles::RoleError) -> Self {
        Self::Context {
            message: format!(
                "role operation failed: {e} — verify role definitions and member permissions"
            ),
            code: "SCP-CTX-2004".to_owned(),
        }
    }
}

impl From<scp_core::context::ttl::TtlError> for ScpNapiError {
    fn from(e: scp_core::context::ttl::TtlError) -> Self {
        Self::Context {
            message: format!(
                "TTL operation failed: {e} — check TTL configuration and context state"
            ),
            code: "SCP-CTX-2005".to_owned(),
        }
    }
}

impl From<scp_core::context::promotion::PromotionError> for ScpNapiError {
    fn from(e: scp_core::context::promotion::PromotionError) -> Self {
        Self::Context {
            message: format!(
                "context promotion failed: {e} — verify eligibility and governance rules"
            ),
            code: "SCP-CTX-2006".to_owned(),
        }
    }
}

impl From<scp_core::context::tools::ToolError> for ScpNapiError {
    fn from(e: scp_core::context::tools::ToolError) -> Self {
        Self::Tool {
            message: format!(
                "tool operation failed: {e} — check tool registration, permissions, and input schema"
            ),
            code: "SCP-TOOL-6001".to_owned(),
        }
    }
}

impl From<scp_core::context::tools::invoke::InvocationError> for ScpNapiError {
    fn from(e: scp_core::context::tools::invoke::InvocationError) -> Self {
        Self::Tool {
            message: format!(
                "tool invocation failed: {e} — verify tool ID, input, and caller permissions"
            ),
            code: "SCP-TOOL-6002".to_owned(),
        }
    }
}

impl From<scp_core::context::tools::schema::SchemaValidationError> for ScpNapiError {
    fn from(e: scp_core::context::tools::schema::SchemaValidationError) -> Self {
        Self::Validation {
            message: format!(
                "schema validation failed: {e} — check input against the tool's JSON Schema"
            ),
            code: "SCP-VALID-7001".to_owned(),
        }
    }
}

impl From<scp_core::crypto::mls::error::MlsError> for ScpNapiError {
    fn from(e: scp_core::crypto::mls::error::MlsError) -> Self {
        Self::Crypto {
            message: format!(
                "MLS operation failed: {e} — check group state and member key packages"
            ),
            code: "SCP-CRYPTO-4001".to_owned(),
        }
    }
}

impl From<scp_core::crypto::sender_keys::SenderKeyError> for ScpNapiError {
    fn from(e: scp_core::crypto::sender_keys::SenderKeyError) -> Self {
        Self::Crypto {
            message: format!(
                "sender key operation failed: {e} — verify key material and encryption parameters"
            ),
            code: "SCP-CRYPTO-4002".to_owned(),
        }
    }
}

impl From<scp_core::crypto::ucan::UcanError> for ScpNapiError {
    fn from(e: scp_core::crypto::ucan::UcanError) -> Self {
        Self::Permission {
            message: format!(
                "{e} — check token format, signatures, time bounds, and capability chain"
            ),
            code: "SCP-PERM-3001".to_owned(),
        }
    }
}

impl From<scp_core::envelope::EnvelopeError> for ScpNapiError {
    fn from(e: scp_core::envelope::EnvelopeError) -> Self {
        Self::Crypto {
            message: format!(
                "envelope operation failed: {e} — check payload size, signing keys, and encryption state"
            ),
            code: "SCP-CRYPTO-4003".to_owned(),
        }
    }
}

impl From<scp_core::event_log::EventLogError> for ScpNapiError {
    fn from(e: scp_core::event_log::EventLogError) -> Self {
        Self::Context {
            message: format!(
                "event log operation failed: {e} — verify log integrity and sequence numbers"
            ),
            code: "SCP-CTX-2007".to_owned(),
        }
    }
}

impl From<scp_core::provenance::ProvenanceError> for ScpNapiError {
    fn from(e: scp_core::provenance::ProvenanceError) -> Self {
        Self::Validation {
            message: format!("provenance validation failed: {e} — check cross-context chain depth"),
            code: "SCP-VALID-7002".to_owned(),
        }
    }
}

impl From<scp_core::trust::TrustError> for ScpNapiError {
    fn from(e: scp_core::trust::TrustError) -> Self {
        Self::Validation {
            message: format!(
                "trust evaluation failed: {e} — check event log data and attestation validity"
            ),
            code: "SCP-VALID-7003".to_owned(),
        }
    }
}

impl From<scp_core::uri::ScpUriError> for ScpNapiError {
    fn from(e: scp_core::uri::ScpUriError) -> Self {
        Self::Validation {
            message: format!("invalid SCP URI: {e} — check URI format (scp://relay/context-id)"),
            code: "SCP-VALID-7004".to_owned(),
        }
    }
}

impl From<scp_core::well_known::WellKnownValidationError> for ScpNapiError {
    fn from(e: scp_core::well_known::WellKnownValidationError) -> Self {
        Self::Validation {
            message: format!("well-known validation failed: {e} — check relay configuration"),
            code: "SCP-VALID-7005".to_owned(),
        }
    }
}

impl From<scp_core::discovery::DiscoveryError> for ScpNapiError {
    fn from(e: scp_core::discovery::DiscoveryError) -> Self {
        Self::Context {
            message: format!(
                "discovery operation failed: {e} — check relay connectivity and search parameters"
            ),
            code: "SCP-CTX-2008".to_owned(),
        }
    }
}

impl From<scp_core::bridge::registration::BridgeRegistrationError> for ScpNapiError {
    fn from(e: scp_core::bridge::registration::BridgeRegistrationError) -> Self {
        Self::Context {
            message: format!(
                "bridge registration failed: {e} — verify bridge configuration and permissions"
            ),
            code: "SCP-CTX-2009".to_owned(),
        }
    }
}

impl From<scp_core::bridge::shadow::ShadowError> for ScpNapiError {
    fn from(e: scp_core::bridge::shadow::ShadowError) -> Self {
        Self::Context {
            message: format!(
                "shadow context operation failed: {e} — check bridge state and context permissions"
            ),
            code: "SCP-CTX-2010".to_owned(),
        }
    }
}

impl From<scp_platform::PlatformError> for ScpNapiError {
    fn from(e: scp_platform::PlatformError) -> Self {
        Self::Crypto {
            message: format!(
                "platform key operation failed: {e} — check key custody configuration"
            ),
            code: "SCP-CRYPTO-4004".to_owned(),
        }
    }
}

impl From<serde_json::Error> for ScpNapiError {
    fn from(e: serde_json::Error) -> Self {
        Self::Validation {
            message: format!("JSON serialization/deserialization failed: {e} — check input format"),
            code: "SCP-VALID-7006".to_owned(),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parses a custody type string into a string the bridge can match on.
///
/// Returns the canonical custody type string or `Err(ScpNapiError::Validation)`.
pub(crate) fn validate_custody_type(custody: &str) -> Result<&str, ScpNapiError> {
    match custody {
        "in_memory" | "platform" | "software" => Ok(custody),
        other => Err(ScpNapiError::Validation {
            message: format!(
                "unknown custody type: {other:?} — expected \"in_memory\", \"platform\", or \"software\""
            ),
            code: "SCP-VALID-7007".to_owned(),
        }),
    }
}
