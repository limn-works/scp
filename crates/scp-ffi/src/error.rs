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
use scp_ffi_common::error_codes as codes;

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

// Cross-context outlet-invocation saga (§6.2.4, ADR-049 §3a) terminal errors.
//
// These three exceptions surface the typed
// `Supervisor::start_cross_context_outlet_invocation_saga` terminal space
// (`SagaError`) WITHOUT the caller having to parse a message string: each
// carries the structured terminal datum the §6.2.4 / ADR-049 §3a contract
// makes load-bearing as a positional Python exception argument (read from
// `e.args`, never re-parsed from the message text):
//
// - `SagaAbortedError(message, code, retry_after_ms)` — a §6.2.4 saga abort,
//   its causes told apart by the code.
//   `retry_after_ms` is the rate-limit back-off hint: an `int` of milliseconds when the tripped limiter can compute one, or
//   `None` (NEVER `0`) when no precise back-off instant exists — `0` would
//   read as "retry immediately" and re-trip the same hard limit. An unavailable
//   participant actor or a plain (non-rate-limit) rejection also carries `None`.
// - `SagaNeedsRepairError(message, code, saga_id)` — Commit-retry exhausted;
//   the saga may have partially committed (a divergence). `saga_id` is the
//   durable operator-repair handle.
// - `SagaBusyError(message, code, contended_context)` — the participant
//   context set overlapped an in-flight saga (§5.15.4). `contended_context`
//   names the shared context id.
//
// `code` is ALSO embedded in the exception message (`"[<code>] …"`) so a
// flattened log line still disambiguates by `grep`.
pyo3::create_exception!(
    scp_sdk,
    SagaAbortedError,
    ScpError,
    "A cross-context outlet-invocation saga aborted (§6.2.4). \
     args = (message, code, retry_after_ms): retry_after_ms is an int of \
     milliseconds or None (never 0)."
);
pyo3::create_exception!(
    scp_sdk,
    SagaNeedsRepairError,
    ScpError,
    "A cross-context outlet-invocation saga exhausted its Commit retries and may \
     have diverged (ADR-049 §3a). args = (message, code, saga_id): saga_id is \
     the durable operator-repair handle."
);
pyo3::create_exception!(
    scp_sdk,
    SagaBusyError,
    ScpError,
    "A cross-context outlet-invocation saga's participant context set overlapped \
     an in-flight saga (§5.15.4). args = (message, code, contended_context)."
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
    /// A §6.2.4 cross-context outlet-invocation saga aborted.
    ///
    /// Maps to the Python `SagaAbortedError`. The code tells its causes
    /// apart. Carries the
    /// rate-limit back-off hint STRUCTURALLY (`retry_after_ms`): `Some(ms)` is
    /// the limiter's computed cooldown; `None` (NEVER `0`) means no precise
    /// back-off instant.
    SagaAborted {
        /// Human-readable detail.
        message: String,
        /// Stable error code.
        code: String,
        /// Rate-limit back-off hint in milliseconds, or `None` (never `0`).
        retry_after_ms: Option<u64>,
    },
    /// A §6.2.4 saga exhausted its Commit retries and may have diverged.
    ///
    /// Maps to the Python `SagaNeedsRepairError`. Carries the durable
    /// `saga_id` operator-repair handle.
    SagaNeedsRepair {
        /// Human-readable detail (carries the `[SCP-SAGA-…]` prefix).
        message: String,
        /// The canonical `SCP-SAGA-13065` code.
        code: String,
        /// The durable saga identifier — the operator-repair handle.
        saga_id: String,
    },
    /// A §6.2.4 saga's participant context set overlapped an in-flight saga.
    ///
    /// Maps to the Python `SagaBusyError`. Carries the contended context id.
    SagaBusy {
        /// Human-readable detail (carries the `[SCP-SAGA-…]` prefix).
        message: String,
        /// The canonical `SCP-SAGA-13066` code.
        code: String,
        /// The shared context id that forced serialization.
        contended_context: String,
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
            // Saga terminals embed their code so a
            // flattened log line still `grep`-disambiguates; the structured
            // datum (retry_after_ms / saga_id / contended_context) rides the
            // exception args, not the message text.
            Self::SagaAborted { message, code, .. } => {
                write!(f, "[{code}] saga aborted: {message}")
            }
            Self::SagaNeedsRepair { message, code, .. } => {
                write!(f, "[{code}] saga needs repair: {message}")
            }
            Self::SagaBusy { message, code, .. } => {
                write!(f, "[{code}] saga busy: {message}")
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
            code: codes::IDENT_1001.to_owned(),
        }
    }

    /// Identity error with the given message and an explicit canonical code.
    /// Used by the §9.10.4 pseudonym-derivation paths to carry the specific
    /// `SCP-IDENT-1054` and `SCP-IDENT-1055` codes instead of the generic
    /// identity code.
    pub fn identity_with_code(msg: impl Into<String>, code: &str) -> Self {
        Self::IdentityError {
            message: msg.into(),
            code: code.to_owned(),
        }
    }

    /// Context error with the given message and the generic context code.
    pub fn context(msg: impl Into<String>) -> Self {
        Self::ContextError {
            message: msg.into(),
            code: codes::CTX_2001.to_owned(),
        }
    }

    /// Crypto error with the given message and the generic crypto code.
    pub fn crypto(msg: impl Into<String>) -> Self {
        Self::CryptoError {
            message: msg.into(),
            code: codes::CRYPTO_4001.to_owned(),
        }
    }

    /// Transport error with the given message and the generic transport code.
    pub fn transport(msg: impl Into<String>) -> Self {
        Self::TransportError {
            message: msg.into(),
            code: codes::TRANS_5001.to_owned(),
        }
    }

    /// UCAN/permission error with the given message and the generic UCAN code.
    pub fn ucan(msg: impl Into<String>) -> Self {
        Self::UcanError {
            message: msg.into(),
            code: codes::PERM_3001.to_owned(),
        }
    }

    /// Validation error with the given message and the generic validation code.
    pub fn validation(msg: impl Into<String>) -> Self {
        Self::ValidationError {
            message: msg.into(),
            code: codes::VALID_7001.to_owned(),
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
            // Saga terminals carry their structured datum as positional
            // exception args so a Python caller reads `retry_after_ms` /
            // `saga_id` / `contended_context` directly from `e.args[2]` —
            // never by re-parsing the message text. `formatted` (carrying the
            // `[<code>]` prefix) is `args[0]`; the code is `args[1]`. `retry_after_ms` maps `None` → Python `None`
            // (NEVER `0`), preserving the §6.2.4 back-off semantics across
            // the FFI boundary.
            ScpPyError::SagaAborted {
                code,
                retry_after_ms,
                ..
            } => SagaAbortedError::new_err((formatted, code, retry_after_ms)),
            ScpPyError::SagaNeedsRepair { code, saga_id, .. } => {
                SagaNeedsRepairError::new_err((formatted, code, saga_id))
            }
            ScpPyError::SagaBusy {
                code,
                contended_context,
                ..
            } => SagaBusyError::new_err((formatted, code, contended_context)),
        }
    }
}

// ---------------------------------------------------------------------------
// From<scp-core error types> for ScpPyError
// ---------------------------------------------------------------------------

// Identity errors → ScpPyError::IdentityError

impl From<scp_identity::IdentityError> for ScpPyError {
    fn from(e: scp_identity::IdentityError) -> Self {
        use scp_identity::IdentityError as IE;
        use scp_platform::PreRotationCustodyError as PE;

        // A custody failure keeps its custody code (key-not-found is
        // SCP-CRYPTO-4006), not the generic identity code.
        let e = match e {
            IE::Platform(pe) => return Self::from(pe),
            other => other,
        };

        if let IE::PreRotation(pre_err) = &e {
            let code = match pre_err {
                PE::HandleNotFound => codes::IDENT_1047,
                PE::Unavailable(_) => codes::IDENT_1048,
                PE::UserDeclined => codes::IDENT_1049,
                PE::Storage(_) => codes::IDENT_1050,
                PE::InvalidCallbackResponse(_) => codes::IDENT_1051,
                PE::CommitmentMismatch => codes::IDENT_1052,
            };
            return Self::IdentityError {
                message: format!("{e}"),
                code: code.to_owned(),
            };
        }

        // `MigrationPublishFailed` is the typed recovery handle from
        // `DidDht::migrate_identity` (phase-1 surface). Structured
        // partial-state plumbing lands in subsequent PRs — this arm only
        // surfaces the code + message body.
        if matches!(&e, IE::MigrationPublishFailed { .. }) {
            return Self::IdentityError {
                message: format!("{e}"),
                code: codes::IDENT_1053.to_owned(),
            };
        }

        Self::IdentityError {
            message: format!(
                "{e} — check DID format, key custody configuration, or DHT connectivity"
            ),
            code: codes::IDENT_1001.to_owned(),
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

/// Extracts a leading `SCP-XXX-NNNN` error code from a message body, if any.
///
/// Several runtime paths surface category-specific error codes inside
/// `PermissionDenied(String)` (e.g. `"SCP-ECON-12010: budget exceeded for
/// ..."`, or the settle-path `"SCP-OUTLET-6089: outlet-economy settle ...
/// found no context"`). Without this parser the bridge would bucket every
/// such error under the generic `SCP-CTX-2001` envelope and Python callers
/// would have to string-match the message body. This helper preserves the
/// existing typed-envelope contract by recovering the embedded code prefix.
///
/// SCP-OUT-031 PR-2a note: outlet INVOCATION errors and the reserve-gate
/// context-not-active condition no longer travel as `PermissionDenied` prose —
/// they are the typed `ContextError::Outlet` / `OutletContextNotActive` arms
/// handled ABOVE this parser. This helper now serves the economy + residual
/// outlet-coded diagnostics only.
///
/// Returns `None` when the message does not start with a recognizable
/// `SCP-` prefix or the prefix does not parse as `LETTERS-DIGITS`.
pub(crate) fn extract_scp_code(message: &str) -> Option<String> {
    let trimmed = message.trim_start();
    let rest = trimmed.strip_prefix("SCP-")?;
    // Find the first ':' or whitespace that terminates the code.
    let end = rest.find(|c: char| c == ':' || c.is_whitespace())?;
    let suffix = &rest[..end];
    // Suffix shape: `<LETTERS>-<DIGITS>`. Reject any other shape so the
    // parser is conservative.
    let (category, number) = suffix.split_once('-')?;
    if category.is_empty()
        || !category.chars().all(|c| c.is_ascii_alphabetic())
        || number.is_empty()
        || !number.chars().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    Some(format!("SCP-{category}-{number}"))
}

impl From<scp_core::context::ContextError> for ScpPyError {
    /// Maps through the shared [`classify_context_error`], so every
    /// `ContextError` variant carries the same code in every binding.
    ///
    /// [`classify_context_error`]: scp_ffi_common::context_error_class::classify_context_error
    fn from(e: scp_core::context::ContextError) -> Self {
        Self::from_context_error(format!("{e}"), &e)
    }
}

impl ScpPyError {
    /// The bridge error for `e`, reported with `message`, by the class and code
    /// the shared `classify_context_error` names. A variant with no dedicated
    /// code ([`ContextErrorClass::Generic`]) reports `SCP-CTX-2001` with a hint.
    ///
    /// [`ContextErrorClass::Generic`]: scp_ffi_common::context_error_class::ContextErrorClass::Generic
    pub(crate) fn from_context_error(message: String, e: &scp_core::context::ContextError) -> Self {
        use scp_ffi_common::context_error_class::{ContextErrorClass as K, classify_context_error};
        match classify_context_error(e) {
            K::Custody(failure) => Self::custody_failure(message, failure),
            // Outlet invocation errors raise ContextError with their §5.4.4
            // code, as every context-class code does.
            K::Context(code) | K::Outlet(code) => Self::ContextError {
                message,
                code: code.to_owned(),
            },
            K::Generic => Self::ContextError {
                message: format!("{message} — verify context state, membership, and permissions"),
                code: codes::CTX_2001.to_owned(),
            },
            K::Validation(code) => Self::ValidationError {
                message,
                code: code.to_owned(),
            },
            K::Crypto(code) => Self::CryptoError {
                message,
                code: code.to_owned(),
            },
            // `PermissionDenied(String)` carries outlet-economy and residual
            // outlet failures with an embedded code. Permission/UCAN-class
            // codes raise UcanError; every other code raises ContextError so
            // call sites that catch ContextError keep working.
            K::PermissionDenied(msg) => {
                let code = extract_scp_code(msg).unwrap_or_else(|| codes::PERM_3001.to_owned());
                if code.starts_with("SCP-PERM-") {
                    Self::UcanError { message, code }
                } else {
                    Self::ContextError { message, code }
                }
            }
        }
    }
}

impl From<scp_core::context::builder::ContextCreationError> for ScpPyError {
    fn from(e: scp_core::context::builder::ContextCreationError) -> Self {
        // The core's empty-ceiling rejection keeps its own validation code
        // (construction.md M2), the one the parser's rejection carries, and a
        // create refused because Supervisor shutdown began keeps SCP-CTX-2138
        // (ADR-049 Decision 16).
        if let scp_core::context::builder::ContextCreationError::StateTransition(
            inner @ (scp_core::context::ContextError::CeilingRequired(_)
            | scp_core::context::ContextError::SupervisorShutDown(_)),
        ) = e
        {
            return inner.into();
        }
        Self::ContextError {
            message: format!(
                "context creation failed: {e} — check context parameters and identity"
            ),
            code: codes::CTX_2002.to_owned(),
        }
    }
}

impl From<scp_core::context::templates::TemplateError> for ScpPyError {
    fn from(e: scp_core::context::templates::TemplateError) -> Self {
        Self::ContextError {
            message: format!(
                "template validation failed: {e} — ensure context params match the template definition"
            ),
            code: codes::CTX_2003.to_owned(),
        }
    }
}

impl From<scp_core::context::roles::RoleError> for ScpPyError {
    fn from(e: scp_core::context::roles::RoleError) -> Self {
        Self::ContextError {
            message: format!(
                "role operation failed: {e} — verify role definitions and member permissions"
            ),
            code: codes::CTX_2004.to_owned(),
        }
    }
}

impl From<scp_core::context::ttl::TtlError> for ScpPyError {
    fn from(e: scp_core::context::ttl::TtlError) -> Self {
        Self::ContextError {
            message: format!(
                "TTL operation failed: {e} — check TTL configuration and context state"
            ),
            code: codes::CTX_2005.to_owned(),
        }
    }
}

impl From<scp_core::context::promotion::PromotionError> for ScpPyError {
    fn from(e: scp_core::context::promotion::PromotionError) -> Self {
        Self::ContextError {
            message: format!(
                "context promotion failed: {e} — verify eligibility and governance rules"
            ),
            code: codes::CTX_2006.to_owned(),
        }
    }
}

// Outlet errors → ScpPyError (outlets category, matching napi/uniffi bridges)

impl From<scp_core::context::outlets::OutletError> for ScpPyError {
    fn from(e: scp_core::context::outlets::OutletError) -> Self {
        Self::ContextError {
            message: format!(
                "outlet operation failed: {e} — check outlet registration, permissions, and input schema"
            ),
            code: codes::OUTLET_6001.to_owned(),
        }
    }
}

impl From<scp_core::context::outlets::invoke::InvocationError> for ScpPyError {
    fn from(e: scp_core::context::outlets::invoke::InvocationError) -> Self {
        Self::ContextError {
            message: format!(
                "outlet invocation failed: {e} — verify outlet ID, input, and caller permissions"
            ),
            code: codes::OUTLET_6002.to_owned(),
        }
    }
}

impl From<scp_core::context::outlets::schema::SchemaValidationError> for ScpPyError {
    fn from(e: scp_core::context::outlets::schema::SchemaValidationError) -> Self {
        Self::ValidationError {
            message: format!(
                "schema validation failed: {e} — check input against the outlet's JSON Schema"
            ),
            code: codes::VALID_7001.to_owned(),
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
            code: codes::CRYPTO_4001.to_owned(),
        }
    }
}

impl From<scp_core::crypto::sender_keys::SenderKeyError> for ScpPyError {
    fn from(e: scp_core::crypto::sender_keys::SenderKeyError) -> Self {
        if let scp_core::crypto::sender_keys::SenderKeyError::Custody(failure) = &e {
            return Self::custody_failure(format!("sender key operation failed: {e}"), failure);
        }
        Self::CryptoError {
            message: format!(
                "sender key operation failed: {e} — verify key material and encryption parameters"
            ),
            code: codes::CRYPTO_4002.to_owned(),
        }
    }
}

// UCAN errors → ScpPyError::UcanError

impl From<scp_core::crypto::ucan::UcanError> for ScpPyError {
    fn from(e: scp_core::crypto::ucan::UcanError) -> Self {
        if let scp_core::crypto::ucan::UcanError::Custody(failure) = &e {
            return Self::custody_failure(format!("UCAN signing failed: {e}"), failure);
        }
        // Canonical UCAN→error-code mapping lives in `scp_ffi_common::ucan_errors`
        // so all three FFI bridges (PyO3/NAPI/UniFFI) stay in lockstep.
        // The cross-bridge parity harness (`OP_UCAN_VALIDATE_MALFORMED`)
        // pins this code; changing it here requires updating the shared
        // mapping and the harness golden-code in the same PR.
        let code = scp_ffi_common::ucan_errors::ucan_error_code(&e).to_owned();
        Self::UcanError {
            message: format!(
                "{e} — check token format, signatures, time bounds, and capability chain"
            ),
            code,
        }
    }
}

// Envelope errors → ScpPyError::CryptoError (envelopes are a crypto concern)

impl From<scp_core::envelope::EnvelopeError> for ScpPyError {
    fn from(e: scp_core::envelope::EnvelopeError) -> Self {
        if let scp_core::envelope::EnvelopeError::Custody(failure) = &e {
            return Self::custody_failure(format!("envelope operation failed: {e}"), failure);
        }
        Self::CryptoError {
            message: format!(
                "envelope operation failed: {e} — check payload size, signing keys, and encryption state"
            ),
            code: codes::CRYPTO_4003.to_owned(),
        }
    }
}

// Event log errors → ScpPyError::ContextError (event logs belong to contexts)

impl From<scp_event_log::EventLogError> for ScpPyError {
    fn from(e: scp_event_log::EventLogError) -> Self {
        if let scp_event_log::EventLogError::Custody(failure) = &e {
            return Self::custody_failure(format!("event log operation failed: {e}"), failure);
        }
        Self::ContextError {
            message: format!(
                "event log operation failed: {e} — verify log integrity and sequence numbers"
            ),
            code: codes::CTX_2007.to_owned(),
        }
    }
}

// Provenance errors → ScpPyError::ValidationError

impl From<scp_core::provenance::ProvenanceError> for ScpPyError {
    fn from(e: scp_core::provenance::ProvenanceError) -> Self {
        Self::ValidationError {
            message: format!("provenance validation failed: {e} — check cross-context chain depth"),
            code: codes::VALID_7002.to_owned(),
        }
    }
}

// Trust errors → ScpPyError::ValidationError

impl From<scp_core::trust::TrustError> for ScpPyError {
    /// The code comes from the shared table, so a challenge refusal carries
    /// its own code on every bridge.
    fn from(e: scp_core::trust::TrustError) -> Self {
        Self::ValidationError {
            message: scp_ffi_common::error_codes::trust_error_message(&e),
            code: scp_ffi_common::error_codes::trust_error_code(&e).to_owned(),
        }
    }
}

// URI errors → ScpPyError::ValidationError

impl From<scp_core::uri::ScpUriError> for ScpPyError {
    fn from(e: scp_core::uri::ScpUriError) -> Self {
        Self::ValidationError {
            message: format!("invalid SCP URI: {e} — check URI format (scp://relay/context-id)"),
            code: codes::VALID_7004.to_owned(),
        }
    }
}

// Well-known validation errors → ScpPyError::ValidationError

impl From<scp_core::well_known::WellKnownValidationError> for ScpPyError {
    fn from(e: scp_core::well_known::WellKnownValidationError) -> Self {
        Self::ValidationError {
            message: format!("well-known validation failed: {e} — check relay configuration"),
            code: codes::VALID_7005.to_owned(),
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
            code: codes::CTX_2008.to_owned(),
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
            code: codes::TRANS_5001.to_owned(),
        }
    }
}

// Platform errors → ScpPyError::CryptoError (key custody)

impl ScpPyError {
    /// A custody failure the runtime carried as a typed
    /// [`CustodyFailure`](scp_crypto::CustodyFailure), coded by
    /// [`custody_failure_code`](scp_ffi_common::error_codes::custody_failure_code).
    pub(crate) fn custody_failure(message: String, e: &scp_crypto::CustodyFailure) -> Self {
        use scp_ffi_common::error_codes::{self as ec, CustodyFailureClass as Class};
        let code = ec::custody_failure_code(e).to_owned();
        match ec::custody_failure_class(e.kind) {
            Class::Identity => Self::IdentityError { message, code },
            Class::Validation => Self::ValidationError { message, code },
            Class::Crypto => Self::CryptoError { message, code },
            Class::Transport => Self::TransportError { message, code },
        }
    }
}

impl ScpPyError {
    /// A failed checkpoint generation: a custody failure keeps its custody code
    /// ([`Self::custody_failure`]), and any other event-log failure is
    /// `SCP-CTX-2001`.
    pub(crate) fn checkpoint_error(e: &scp_event_log::EventLogError) -> Self {
        let message = format!("checkpoint generation failed: {e}");
        match e {
            scp_event_log::EventLogError::Custody(failure) => {
                Self::custody_failure(message, failure)
            }
            _ => Self::context(message),
        }
    }
}

impl From<scp_platform::PlatformError> for ScpPyError {
    fn from(e: scp_platform::PlatformError) -> Self {
        // Every variant takes its code from `custody_failure_code`, so a bare
        // and a wrapped `PlatformError` report the same code. A storage,
        // attestation or push failure is not a key custody failure, so its
        // message is the error's own text and never blames key custody.
        let failure = scp_crypto::CustodyFailure::from(&e);
        let message = if scp_ffi_common::error_codes::is_key_custody_failure(failure.kind) {
            format!("platform key operation failed: {e} — check key custody configuration")
        } else {
            e.to_string()
        };
        Self::custody_failure(message, &failure)
    }
}

// serde_json errors → ScpPyError::ValidationError (JSON parse failures)

impl From<serde_json::Error> for ScpPyError {
    fn from(e: serde_json::Error) -> Self {
        Self::ValidationError {
            message: format!("JSON serialization/deserialization failed: {e} — check input format"),
            code: codes::VALID_7006.to_owned(),
        }
    }
}

// Handle affinity errors → ScpPyError::UcanError (permission class, SCP-PERM-3030)
//
// A handle issued by one PyBridgeInstance cannot be used on another — this
// is the multi-instance security boundary enforced by `CoreFields::check_handle`.
// The check fires at every `#[pyfunction]` entry point that accepts a
// handle (see `pyscp_check_handle!` macro in `runtime` module).

impl From<scp_ffi_common::bridge_instance::HandleAffinityError> for ScpPyError {
    fn from(e: scp_ffi_common::bridge_instance::HandleAffinityError) -> Self {
        Self::UcanError {
            message: e.to_string(),
            code: codes::PERM_3030.to_owned(),
        }
    }
}

// ---------------------------------------------------------------------------
// Module registration helper
// ---------------------------------------------------------------------------

/// Registers all SCP exception classes on the given Python module.
///
/// Called from the `_scp_core` module init function in `lib.rs`. This makes
/// the exception classes importable as
/// `from scp_sdk._scp_core import ScpError, ...`
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
    m.add("SagaAbortedError", m.py().get_type::<SagaAbortedError>())?;
    m.add(
        "SagaNeedsRepairError",
        m.py().get_type::<SagaNeedsRepairError>(),
    )?;
    m.add("SagaBusyError", m.py().get_type::<SagaBusyError>())?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use scp_platform::PreRotationCustodyError;

    fn code_of(e: ScpPyError) -> String {
        match e {
            ScpPyError::IdentityError { code, .. } => code,
            other => panic!("expected IdentityError, got {other:?}"),
        }
    }

    /// The custody error table (ADR-006 2026-09-29, 2026-10-11 and
    /// 2026-10-12 amendments; `sdk-common.md` error codes): for every custody
    /// failure kind, every carrier this bridge maps reports the row's class
    /// and code. The carriers are a `CustodyFailure` inside `EnvelopeError`,
    /// `ContextError` (through `From` and through the supervisor-failure path
    /// a Welcome join, a reserve and an invite take), `SenderKeyError`,
    /// `UcanError` and `EventLogError` (through `From` and through the
    /// checkpoint path), and each bare `PlatformError` of that kind.
    #[test]
    fn custody_failures_carry_the_custody_codes_in_every_carrier() {
        use scp_core::context::ContextError;
        use scp_ffi_common::error_codes::CustodyFailureClass as Class;
        use scp_ffi_common::test_helpers::{custody_code_rows, custody_failure};
        fn class_and_code(e: &ScpPyError) -> (&'static str, String) {
            match e {
                ScpPyError::IdentityError { code, .. } => ("identity", code.clone()),
                ScpPyError::CryptoError { code, .. } => ("crypto", code.clone()),
                ScpPyError::ValidationError { code, .. } => ("validation", code.clone()),
                ScpPyError::TransportError { code, .. } => ("transport", code.clone()),
                other => panic!("not a custody error class: {other:?}"),
            }
        }
        for row in custody_code_rows() {
            let class = match row.class {
                Class::Identity => "identity",
                Class::Crypto => "crypto",
                Class::Validation => "validation",
                Class::Transport => "transport",
            };
            let expected = (class, row.code.to_owned());
            let failure = || custody_failure(row.kind);
            let carriers: [(&str, ScpPyError); 7] = [
                (
                    "EnvelopeError",
                    scp_core::envelope::EnvelopeError::Custody(failure()).into(),
                ),
                ("ContextError", ContextError::Custody(failure()).into()),
                (
                    "ContextError via typed_supervisor_error",
                    match crate::context::typed_supervisor_error(
                        "context_join_from_welcome",
                        &ContextError::Custody(failure()),
                    ) {
                        Some(typed) => typed,
                        None => panic!("{:?} is untyped on the supervisor-failure path", row.kind),
                    },
                ),
                (
                    "SenderKeyError",
                    scp_core::crypto::sender_keys::SenderKeyError::Custody(failure()).into(),
                ),
                (
                    "UcanError",
                    scp_core::crypto::ucan::UcanError::Custody(failure()).into(),
                ),
                (
                    "EventLogError",
                    scp_event_log::EventLogError::Custody(failure()).into(),
                ),
                (
                    "EventLogError via checkpoint_error",
                    ScpPyError::checkpoint_error(&scp_event_log::EventLogError::Custody(failure())),
                ),
            ];
            for (carrier, error) in carriers {
                assert_eq!(
                    class_and_code(&error),
                    expected,
                    "{:?} as a CustodyFailure in {carrier}",
                    row.kind
                );
            }
            for platform_error in row.platform_errors {
                let debug = format!("{platform_error:?}");
                assert_eq!(
                    class_and_code(&platform_error.into()),
                    expected,
                    "{:?} as the bare PlatformError {debug}",
                    row.kind
                );
            }
        }
    }

    #[test]
    fn pre_rotation_handle_not_found_surfaces_typed_code() {
        let err: ScpPyError =
            scp_identity::IdentityError::PreRotation(PreRotationCustodyError::HandleNotFound)
                .into();
        assert_eq!(code_of(err), codes::IDENT_1047);
    }

    #[test]
    fn pre_rotation_unavailable_surfaces_typed_code() {
        let err: ScpPyError = scp_identity::IdentityError::PreRotation(
            PreRotationCustodyError::Unavailable("hardware key not connected".into()),
        )
        .into();
        assert_eq!(code_of(err), codes::IDENT_1048);
    }

    #[test]
    fn pre_rotation_user_declined_surfaces_typed_code() {
        let err: ScpPyError =
            scp_identity::IdentityError::PreRotation(PreRotationCustodyError::UserDeclined).into();
        assert_eq!(code_of(err), codes::IDENT_1049);
    }

    #[test]
    fn pre_rotation_storage_surfaces_typed_code() {
        let err: ScpPyError = scp_identity::IdentityError::PreRotation(
            PreRotationCustodyError::Storage("disk full".into()),
        )
        .into();
        assert_eq!(code_of(err), codes::IDENT_1050);
    }

    #[test]
    fn pre_rotation_invalid_callback_response_surfaces_typed_code() {
        let err: ScpPyError = scp_identity::IdentityError::PreRotation(
            PreRotationCustodyError::InvalidCallbackResponse("handle is empty".into()),
        )
        .into();
        assert_eq!(code_of(err), codes::IDENT_1051);
    }

    #[test]
    fn pre_rotation_commitment_mismatch_surfaces_typed_code() {
        let err: ScpPyError =
            scp_identity::IdentityError::PreRotation(PreRotationCustodyError::CommitmentMismatch)
                .into();
        assert_eq!(code_of(err), codes::IDENT_1052);
    }

    #[test]
    fn non_pre_rotation_identity_errors_keep_generic_envelope() {
        let err: ScpPyError = scp_identity::IdentityError::InvalidDidFormat("bad".into()).into();
        assert_eq!(code_of(err), codes::IDENT_1001);
    }

    /// Extracts the code from a `ScpPyError::ContextError` (or panics).
    fn context_code_of(e: ScpPyError) -> String {
        match e {
            ScpPyError::ContextError { code, .. } => code,
            other => panic!("expected ContextError, got {other:?}"),
        }
    }

    /// §23.16.8 / ADR-050: a signed-context-export signature verification
    /// failure must surface the dedicated SCP-CTX-2093 code, NOT the catch-all
    /// SCP-CTX-2001. This is the documented contract a forged export must hit.
    #[test]
    fn snapshot_signature_invalid_surfaces_ctx_2093() {
        let err: ScpPyError = scp_core::context::ContextError::SnapshotSignatureInvalid {
            reason: "creator signature over snapshot did not verify".to_owned(),
        }
        .into();
        assert_eq!(context_code_of(err), codes::CTX_2093);
    }

    /// §23.16.8 / §17.5 / ADR-050: the export format-version gate must surface
    /// the dedicated SCP-CTX-2094 code, distinct from the SCP-CTX-2093 signature
    /// failure and from the catch-all SCP-CTX-2001. A caller can then tell an
    /// old/unsupported export format apart from a forged signature.
    #[test]
    fn export_version_unsupported_surfaces_ctx_2094() {
        let err: ScpPyError = scp_core::context::ContextError::ExportVersionUnsupported {
            reason: "unsupported export version: 3, required: 4".to_owned(),
        }
        .into();
        assert_eq!(context_code_of(err), codes::CTX_2094);
    }

    /// Defense against regression: an unrelated `ContextError` variant must
    /// still fall through to the catch-all SCP-CTX-2001 — the 2093 arm is
    /// narrow and does not capture generic context failures.
    #[test]
    fn generic_context_error_keeps_ctx_2001() {
        let err: ScpPyError =
            scp_core::context::ContextError::MembershipFailed("nope".to_owned()).into();
        assert_eq!(context_code_of(err), codes::CTX_2001);
    }

    /// ADR-049 §10: `ContextError::ActorBusy` must surface the dedicated
    /// SCP-CTX-2130 code, NOT the catch-all SCP-CTX-2001, as the
    /// NAPI and `UniFFI` translators do. The code reaches Python only where
    /// the failing operation routes its error through this translator.
    #[test]
    fn actor_busy_surfaces_ctx_2130() {
        let err: ScpPyError = scp_core::context::ContextError::ActorBusy("ctx-1".to_owned()).into();
        assert_eq!(context_code_of(err), codes::CTX_2130);
    }

    /// construction.md M2: the core's empty-ceiling rejection, which reaches
    /// the bridge wrapped in `ContextCreationError::StateTransition`, keeps
    /// `SCP-VALID-7005`; every other creation failure keeps `SCP-CTX-2002`.
    #[test]
    fn creation_ceiling_required_keeps_valid_7005() {
        use scp_core::context::builder::ContextCreationError as CCE;
        let err: ScpPyError =
            CCE::StateTransition(scp_core::context::ContextError::CeilingRequired(
                scp_core::context::CeilingDeclaration::Empty,
            ))
            .into();
        match err {
            ScpPyError::ValidationError { code, .. } => assert_eq!(code, codes::VALID_7005),
            other => panic!("expected ValidationError, got {other:?}"),
        }
        let err: ScpPyError =
            CCE::StateTransition(scp_core::context::ContextError::CeilingImmutable).into();
        assert_eq!(context_code_of(err), codes::CTX_2002);
    }

    /// construction.md M2: a create that declared no usable ceiling surfaces
    /// as a validation error, not a context error: an absent or null ceiling
    /// with `SCP-VALID-7004`, an empty one with `SCP-VALID-7005`.
    #[test]
    fn ceiling_required_surfaces_valid_7004_or_7005() {
        use scp_core::context::CeilingDeclaration as D;
        for (declared, expected) in [
            (D::Absent, codes::VALID_7004),
            (D::Null, codes::VALID_7004),
            (D::Empty, codes::VALID_7005),
        ] {
            let err: ScpPyError = scp_core::context::ContextError::CeilingRequired(declared).into();
            match err {
                ScpPyError::ValidationError { code, .. } => {
                    assert_eq!(code, expected, "{declared:?}");
                }
                other => panic!("expected ValidationError, got {other:?}"),
            }
        }
    }

    /// ADR-049 §10: a poisoned context must surface the dedicated
    /// SCP-CTX-2134 code via the translator's dedicated arm, NOT the catch-all
    /// SCP-CTX-2001.
    #[test]
    fn context_poisoned_surfaces_ctx_2134() {
        let err: ScpPyError =
            scp_core::context::ContextError::ContextPoisoned("ctx-1".to_owned()).into();
        assert_eq!(context_code_of(err), codes::CTX_2134);
    }

    /// ADR-049 §10: an unrecoverable actor crash must surface the dedicated
    /// SCP-CTX-2135 code, distinct from the poison code and the catch-all.
    #[test]
    fn actor_crashed_surfaces_ctx_2135() {
        let err: ScpPyError =
            scp_core::context::ContextError::ActorCrashed("ctx-1".to_owned()).into();
        assert_eq!(context_code_of(err), codes::CTX_2135);
    }

    /// ADR-049 §9: a key package single-use replay must surface the dedicated
    /// SCP-CTX-2136 code, distinct from the catch-all and from `InvalidState`.
    #[test]
    fn key_package_replay_surfaces_ctx_2136() {
        let err: ScpPyError =
            scp_core::context::ContextError::KeyPackageReplay("kp".to_owned()).into();
        assert_eq!(context_code_of(err), codes::CTX_2136);
    }

    /// ADR-049 Decision 16: an operation the Supervisor refused because
    /// shutdown began must surface the dedicated SCP-CTX-2138 code, distinct
    /// from the catch-all.
    #[test]
    fn supervisor_shut_down_surfaces_ctx_2138() {
        let err: ScpPyError =
            scp_core::context::ContextError::SupervisorShutDown("spawn".to_owned()).into();
        assert_eq!(context_code_of(err), codes::CTX_2138);
        let err: ScpPyError = scp_core::context::builder::ContextCreationError::StateTransition(
            scp_core::context::ContextError::SupervisorShutDown("spawn".to_owned()),
        )
        .into();
        assert_eq!(context_code_of(err), codes::CTX_2138);
        let err: ScpPyError = scp_core::context::builder::ContextCreationError::StateTransition(
            scp_core::context::ContextError::CeilingImmutable,
        )
        .into();
        assert_eq!(context_code_of(err), codes::CTX_2002);
    }

    /// Spec §17.6 "One Opener per Durable Directory": a held lock and a closed
    /// store carry their registered storage codes, and a generic storage error
    /// is a custody failure, `SCP-CRYPTO-4060`.
    #[test]
    fn storage_platform_errors_carry_registered_codes() {
        let held: ScpPyError = scp_platform::PlatformError::StorageLockHeld {
            dir: "/tmp/scp".to_owned(),
            lock_path: "/tmp/scp/scp.db.lock".to_owned(),
        }
        .into();
        assert!(
            matches!(&held, ScpPyError::ValidationError { code, .. } if code == codes::STORAGE_8005),
            "{held:?}"
        );
        let closed: ScpPyError = scp_platform::PlatformError::StorageClosed.into();
        assert!(
            matches!(&closed, ScpPyError::ValidationError { code, .. } if code == codes::STORAGE_8006),
            "{closed:?}"
        );
        let other: ScpPyError = scp_platform::PlatformError::StorageError("io".to_owned()).into();
        assert!(
            matches!(&other, ScpPyError::CryptoError { code, .. } if code == codes::CRYPTO_4060),
            "{other:?}"
        );
    }

    /// ADR-006's 2026-10-12 amendment: a device attestation failure, each
    /// push failure kind and an unsupported operation reach the caller with
    /// their own registered code, never the key custody code
    /// `SCP-CRYPTO-4060`, and an attestation or push failure's message does
    /// not blame key custody.
    #[test]
    fn attestation_push_and_unsupported_platform_errors_carry_their_own_codes() {
        use scp_platform::{PlatformError, PushFailureKind};
        let push = |kind| PlatformError::PushError {
            kind,
            detail: "x".to_owned(),
        };
        for (error, variant, expected_code, blames_custody) in [
            (
                PlatformError::AttestationError("x".to_owned()),
                "identity",
                codes::ATTEST_9001,
                false,
            ),
            (
                push(PushFailureKind::WakePayloadInvalid),
                "transport",
                codes::TRANS_5080,
                false,
            ),
            (
                push(PushFailureKind::RegistrationRejected),
                "transport",
                codes::TRANS_5081,
                false,
            ),
            (
                push(PushFailureKind::VerifierUnavailable),
                "transport",
                codes::TRANS_5082,
                false,
            ),
            (
                push(PushFailureKind::PlatformUnavailable),
                "transport",
                codes::TRANS_5083,
                false,
            ),
            (
                push(PushFailureKind::ProviderFailed),
                "transport",
                codes::TRANS_5084,
                false,
            ),
            (
                PlatformError::Unsupported("x"),
                "crypto",
                codes::CRYPTO_4061,
                true,
            ),
        ] {
            let debug = format!("{error:?}");
            let (got_variant, message, code) = match ScpPyError::from(error) {
                ScpPyError::IdentityError { message, code } => ("identity", message, code),
                ScpPyError::TransportError { message, code } => ("transport", message, code),
                ScpPyError::CryptoError { message, code } => ("crypto", message, code),
                other => panic!("{debug}: unexpected variant {other:?}"),
            };
            assert_eq!(
                (got_variant, code.as_str()),
                (variant, expected_code),
                "{debug}"
            );
            assert_eq!(
                message.contains("key custody"),
                blames_custody,
                "{debug}: {message}"
            );
        }
    }

    /// Spec §17.6 and ADR-006's SCP-307 amendment: every `PlatformError`
    /// variant reaches the caller with one code, whether it arrives bare or
    /// wrapped in a `CustodyFailure` (here inside `ContextError::Custody`). A
    /// real closed `SqliteStorage` supplies the `StorageClosed`, which must
    /// report `SCP-STORAGE-8006` on the wrapped path, not `SCP-CRYPTO-4060`.
    #[tokio::test]
    async fn platform_errors_keep_one_code_bare_or_wrapped_in_a_custody_failure() {
        use scp_platform::Storage as _;
        fn variant_and_code(e: &ScpPyError) -> (&'static str, String) {
            match e {
                ScpPyError::IdentityError { code, .. } => ("identity", code.clone()),
                ScpPyError::CryptoError { code, .. } => ("crypto", code.clone()),
                ScpPyError::ValidationError { code, .. } => ("validation", code.clone()),
                ScpPyError::TransportError { code, .. } => ("transport", code.clone()),
                other => panic!("unexpected custody error variant: {other:?}"),
            }
        }
        fn push(kind: scp_platform::PushFailureKind) -> scp_platform::PlatformError {
            scp_platform::PlatformError::PushError {
                kind,
                detail: "x".to_owned(),
            }
        }
        fn wrapped(e: &scp_platform::PlatformError) -> ScpPyError {
            scp_core::context::ContextError::Custody(scp_crypto::CustodyFailure::from(e)).into()
        }

        let Ok(dir) = tempfile::tempdir() else {
            panic!("create a tempdir");
        };
        let storage = match scp_platform::sqlite::SqliteStorage::new(dir.path(), &[0x5a; 32]) {
            Ok(storage) => storage,
            Err(e) => panic!("open the store: {e}"),
        };
        if let Err(e) = storage.close() {
            panic!("close the store: {e}");
        }
        let closed = match storage.retrieve("custody/next_id").await {
            Err(e) => e,
            Ok(v) => panic!("a closed store refuses every operation, got {v:?}"),
        };
        assert!(
            matches!(closed, scp_platform::PlatformError::StorageClosed),
            "{closed:?}"
        );
        assert_eq!(
            variant_and_code(&wrapped(&closed)),
            ("validation", codes::STORAGE_8006.to_owned())
        );

        for error in [
            closed,
            scp_platform::PlatformError::StorageLockHeld {
                dir: "/tmp/scp".to_owned(),
                lock_path: "/tmp/scp/scp.db.lock".to_owned(),
            },
            scp_platform::PlatformError::KeyNotFound,
            scp_platform::PlatformError::PseudonymRejected("x".to_owned()),
            scp_platform::PlatformError::WrongKeyType {
                expected: scp_platform::traits::KeyType::Ed25519,
                actual: scp_platform::traits::KeyType::X25519,
            },
            scp_platform::PlatformError::NotIdentityKey,
            scp_platform::PlatformError::StorageError("io".to_owned()),
            scp_platform::PlatformError::AttestationError("x".to_owned()),
            push(scp_platform::PushFailureKind::WakePayloadInvalid),
            push(scp_platform::PushFailureKind::RegistrationRejected),
            push(scp_platform::PushFailureKind::VerifierUnavailable),
            push(scp_platform::PushFailureKind::PlatformUnavailable),
            push(scp_platform::PushFailureKind::ProviderFailed),
            scp_platform::PlatformError::CustodyError("x".to_owned()),
            scp_platform::PlatformError::Unsupported("x"),
        ] {
            let wrapped_error = wrapped(&error);
            let debug = format!("{error:?}");
            let bare: ScpPyError = error.into();
            assert_eq!(
                variant_and_code(&bare),
                variant_and_code(&wrapped_error),
                "{debug}"
            );
        }

        // A storage call raises the two §17.6 conditions too, so a bare one
        // reports the error's own text, never a key-custody diagnosis.
        for (error, expected_code) in [
            (
                scp_platform::PlatformError::StorageClosed,
                codes::STORAGE_8006,
            ),
            (
                scp_platform::PlatformError::StorageLockHeld {
                    dir: "/tmp/scp".to_owned(),
                    lock_path: "/tmp/scp/scp.db.lock".to_owned(),
                },
                codes::STORAGE_8005,
            ),
        ] {
            let expected_message = error.to_string();
            let bare: ScpPyError = error.into();
            match bare {
                ScpPyError::ValidationError { message, code } => {
                    assert_eq!(message, expected_message);
                    assert_eq!(code, expected_code);
                }
                other => panic!("expected a validation error, got {other:?}"),
            }
        }
    }

    /// §5.9: a `RestoreAccess` with nothing to restore must surface the
    /// dedicated SCP-CTX-2137 code, distinct from the catch-all SCP-CTX-2001.
    /// The same code is surfaced by the other bridges for cross-bridge parity.
    #[test]
    fn nothing_to_restore_surfaces_ctx_2137() {
        let err: ScpPyError = scp_core::context::ContextError::NothingToRestore(
            "no suspended capabilities to restore for did:dht:zsubject".to_owned(),
        )
        .into();
        assert_eq!(context_code_of(err), codes::CTX_2137);
    }

    /// SCP-OUT-031 PR-2a (SECURITY): the outlet reserve-gate context-not-active
    /// carrier — which reaches the FFI caller VERBATIM on the unary invoke path,
    /// BEFORE authorization — must surface as the STRUCTURED, state-free
    /// `SCP-OUTLET-6101` Protocol-session surface. The raw lifecycle state
    /// (`Closing` / `Expired` / …) MUST NOT appear in the message, else an
    /// unauthorized caller learns the exact lifecycle state pre-authz.
    #[test]
    fn outlet_context_not_active_surfaces_structured_state_free() {
        let err: ScpPyError = scp_core::context::ContextError::OutletContextNotActive {
            current_state: scp_core::context::ContextState::Closing,
        }
        .into();
        let (message, code) = match err {
            ScpPyError::ContextError { message, code } => (message, code),
            other => panic!("expected ContextError, got {other:?}"),
        };
        assert_eq!(
            code,
            scp_core::context::outlets::error_codes::CODE_PROTOCOL_SESSION
        );
        assert!(
            !message.contains("Closing"),
            "raw lifecycle state must NOT leak to the FFI caller: {message}"
        );
        assert!(
            message.contains("protocol.context-closed-mid-stream"),
            "message must be the structured state-free surface: {message}"
        );
    }

    // ------------------------------------------------------------------
    // Saga terminal → Python exception: the structured datum MUST ride the
    // exception args so a Python caller reads it directly (never by parsing
    // the message text). args = (message, code, structured_field).
    // ------------------------------------------------------------------

    /// `SagaAborted` → `SagaAbortedError` carrying `retry_after_ms` as `args[2]`
    /// (a Python `int` when `Some`).
    #[test]
    fn saga_aborted_maps_to_exception_with_retry_after_ms_arg() {
        Python::with_gil(|py| {
            pyo3::prepare_freethreaded_python();
            let err: PyErr = ScpPyError::SagaAborted {
                message: "rate limited".to_owned(),
                code: "SCP-SAGA-13026".to_owned(),
                retry_after_ms: Some(2500),
            }
            .into();
            assert!(err.is_instance_of::<SagaAbortedError>(py));
            let args = err.value(py).getattr("args").unwrap();
            let code: String = args.get_item(1).unwrap().extract().unwrap();
            assert_eq!(code, "SCP-SAGA-13026");
            let retry: u64 = args.get_item(2).unwrap().extract().unwrap();
            assert_eq!(retry, 2500);
        });
    }

    /// `SagaAborted` with `retry_after_ms = None` → `args[2]` is Python `None`,
    /// NEVER `0`.
    #[test]
    fn saga_aborted_none_retry_is_python_none_not_zero() {
        Python::with_gil(|py| {
            pyo3::prepare_freethreaded_python();
            let err: PyErr = ScpPyError::SagaAborted {
                message: "no back-off".to_owned(),
                code: "SCP-SAGA-13026".to_owned(),
                retry_after_ms: None,
            }
            .into();
            let args = err.value(py).getattr("args").unwrap();
            let retry = args.get_item(2).unwrap();
            assert!(
                retry.is_none(),
                "retry_after_ms None must surface as Python None, not 0"
            );
        });
    }

    /// `SagaNeedsRepair` → `SagaNeedsRepairError` carrying `saga_id` as `args[2]`.
    #[test]
    fn saga_needs_repair_maps_to_exception_with_saga_id_arg() {
        Python::with_gil(|py| {
            pyo3::prepare_freethreaded_python();
            let err: PyErr = ScpPyError::SagaNeedsRepair {
                message: "diverged".to_owned(),
                code: codes::SAGA_13065.to_owned(),
                saga_id: "saga-xyz".to_owned(),
            }
            .into();
            assert!(err.is_instance_of::<SagaNeedsRepairError>(py));
            let args = err.value(py).getattr("args").unwrap();
            let saga_id: String = args.get_item(2).unwrap().extract().unwrap();
            assert_eq!(saga_id, "saga-xyz");
        });
    }

    /// `SagaBusy` → `SagaBusyError` carrying `contended_context` as `args[2]`.
    #[test]
    fn saga_busy_maps_to_exception_with_contended_context_arg() {
        Python::with_gil(|py| {
            pyo3::prepare_freethreaded_python();
            let err: PyErr = ScpPyError::SagaBusy {
                message: "busy".to_owned(),
                code: codes::SAGA_13066.to_owned(),
                contended_context: "ctx-shared".to_owned(),
            }
            .into();
            assert!(err.is_instance_of::<SagaBusyError>(py));
            let args = err.value(py).getattr("args").unwrap();
            let contended: String = args.get_item(2).unwrap().extract().unwrap();
            assert_eq!(contended, "ctx-shared");
        });
    }
}
