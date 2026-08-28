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
//! | `SCP-OUTLET-` | 6000-6999 | Outlet errors |
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
use scp_ffi_common::error_codes as codes;

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

    /// A outlet operation failed (registration, invocation, verification).
    #[error("[{code}] outlet error: {message}")]
    Outlet {
        /// Human-readable error message.
        message: String,
        /// Stable error code (e.g. `SCP-OUTLET-6001`).
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

    /// A §6.2.4 cross-context outlet-invocation saga aborted at a Prepare phase
    /// (ADR-049 §3a).
    ///
    /// This terminal surfaces a §6.2.4 saga `Aborted` and, like its `PyO3` and
    /// `UniFFI` siblings, may be a PERMANENT rejection (authorization / freshness
    /// / rate-limit / co-residency policy denial) OR a RETRYABLE transient (a
    /// rate limit, or a participant actor unavailable to complete the Prepare
    /// exchange) — distinguished by the `SCP-SAGA-*` code.
    ///
    /// napi-rs collapses every `ScpNapiError` to a single `napi::Error` whose
    /// only payload is a message string (the TypeScript SDK reverses the
    /// `[{code}]` prefix into a typed `ScpError`). So the load-bearing
    /// structured datum — the rate-limit back-off hint — is appended to the
    /// message in a machine-parseable `(retry_after_ms=…)` suffix that the TS
    /// wrapper reads. `retry_after_ms` is rendered as a literal `null` when
    /// `None` (NEVER `0`): a `0` would read as "retry immediately" and re-trip
    /// the same hard limit. The field stays `Option<u64>` here so the value is
    /// read STRUCTURALLY off `SagaAbortReason::RateLimited`, never re-parsed.
    #[error(
        "[{code}] saga aborted: {message} (retry_after_ms={})",
        retry_after_ms.map_or_else(|| "null".to_owned(), |v| v.to_string())
    )]
    SagaAborted {
        /// Human-readable detail.
        message: String,
        /// The canonical `SCP-SAGA-13xxx` code.
        code: String,
        /// Rate-limit back-off hint in milliseconds, or `None` (never `0`).
        retry_after_ms: Option<u64>,
    },

    /// A §6.2.4 saga exhausted its Commit retries and may have diverged
    /// (ADR-049 §3a).
    ///
    /// The durable `saga_id` operator-repair handle is appended to the message
    /// in a machine-parseable `(saga_id=…)` suffix for the TS wrapper, and held
    /// STRUCTURALLY in the variant.
    #[error("[{code}] saga needs repair: {message} (saga_id={saga_id})")]
    SagaNeedsRepair {
        /// Human-readable detail.
        message: String,
        /// The canonical `SCP-SAGA-13065` code.
        code: String,
        /// The durable saga identifier — the operator-repair handle.
        saga_id: String,
    },

    /// A §6.2.4 saga's participant context set overlapped an in-flight saga
    /// (§5.15.4).
    ///
    /// The contended context id is appended to the message in a
    /// machine-parseable `(contended_context=…)` suffix for the TS wrapper, and
    /// held STRUCTURALLY in the variant.
    #[error("[{code}] saga busy: {message} (contended_context={contended_context})")]
    SagaBusy {
        /// Human-readable detail.
        message: String,
        /// The canonical `SCP-SAGA-13066` code.
        code: String,
        /// The shared context id that forced serialization.
        contended_context: String,
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

impl From<scp_identity::IdentityError> for ScpNapiError {
    fn from(e: scp_identity::IdentityError) -> Self {
        use scp_identity::IdentityError as IE;
        use scp_platform::PreRotationCustodyError as PE;

        if let IE::PreRotation(pre_err) = &e {
            let code = match pre_err {
                PE::HandleNotFound => codes::IDENT_1047,
                PE::Unavailable(_) => codes::IDENT_1048,
                PE::UserDeclined => codes::IDENT_1049,
                PE::Storage(_) => codes::IDENT_1050,
                PE::InvalidCallbackResponse(_) => codes::IDENT_1051,
                PE::CommitmentMismatch => codes::IDENT_1052,
            };
            return Self::Identity {
                message: format!("{e}"),
                code: code.to_owned(),
            };
        }

        // `MigrationPublishFailed` is the typed recovery handle from
        // `DidDht::migrate_identity` (phase-1 surface). Structured
        // partial-state plumbing lands in subsequent PRs — this arm only
        // surfaces the code + message body.
        if matches!(&e, IE::MigrationPublishFailed { .. }) {
            return Self::Identity {
                message: format!("{e}"),
                code: codes::IDENT_1053.to_owned(),
            };
        }

        Self::Identity {
            message: format!(
                "{e} — check DID format, key custody configuration, or DHT connectivity"
            ),
            code: codes::IDENT_1001.to_owned(),
        }
    }
}

/// Extracts a leading `SCP-XXX-NNNN` error code from a message body, if any.
///
/// Mirrors the `PyO3` bridge's `extract_scp_code` helper. Used to recover
/// economy (12xxx) and outlet-invocation (6xxx) codes embedded inside
/// `ContextError::PermissionDenied(String)` so TypeScript callers can
/// check `.code` instead of string-matching the message body.
pub(crate) fn extract_scp_code(message: &str) -> Option<String> {
    let trimmed = message.trim_start();
    let rest = trimmed.strip_prefix("SCP-")?;
    let end = rest.find(|c: char| c == ':' || c.is_whitespace())?;
    let suffix = &rest[..end];
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

impl From<scp_core::context::ContextError> for ScpNapiError {
    fn from(e: scp_core::context::ContextError) -> Self {
        use scp_core::context::ContextError as CE;
        match &e {
            // Surface the canonical rate-limit code on the typed
            // envelope so TypeScript callers can check `.code`
            // instead of string-matching `SCP-ECON-12090` inside
            // the message body.
            CE::RateLimited { .. } => Self::Context {
                message: format!("{e}"),
                code: codes::ECON_12090.to_owned(),
            },
            // §23.17 snapshot import regression.
            CE::SnapshotFloorRegression { .. } => Self::Context {
                message: format!("{e}"),
                code: codes::CTX_2091.to_owned(),
            },
            // C3: snapshot import structural/semantic rejection.
            CE::ImportRejected { .. } => Self::Context {
                message: format!("{e}"),
                code: codes::CTX_2092.to_owned(),
            },
            // §23.16.8 / ADR-050: signed-context-export signature verification
            // failure (forged/tampered snapshot, exporter_did != creator_did,
            // or unresolvable creator key). Surface the dedicated SCP-CTX-2093
            // contract instead of falling through to the catch-all CTX_2001 so
            // TypeScript callers can distinguish a forged export from a generic
            // context error. The version gate is reported separately (a distinct
            // version error, not this arm), per §23.16.8 / §17.5.
            CE::SnapshotSignatureInvalid { .. } => Self::Context {
                message: format!("{e}"),
                code: codes::CTX_2093.to_owned(),
            },
            // §23.16.8 / §17.5: signed-context-export format-version gate.
            // The snapshot carries an export-format version this build does not
            // support. This is a distinct contract from CTX_2093 (signature
            // verification failure) so a caller can tell "old/unsupported
            // export format" apart from "forged/tampered snapshot".
            CE::ExportVersionUnsupported { .. } => Self::Context {
                message: format!("{e}"),
                code: codes::CTX_2094.to_owned(),
            },
            // §9.10.4: pseudonym registry empty on a multi-member encrypted send.
            CE::PseudonymRegistryEmpty { .. } => Self::Context {
                message: format!("{e}"),
                code: codes::CTX_2095.to_owned(),
            },
            // §9.10.4 / §5.14: per-member pseudonym requested for a broadcast context.
            CE::NotPseudonymousContext { .. } => Self::Context {
                message: format!("{e}"),
                code: codes::CTX_2096.to_owned(),
            },
            // ADR-049 §10: actor poisoned (exceeded the respawn budget).
            // Dedicated SCP-CTX-2134 instead of the CTX_2001 catch-all so a
            // caller can detect "dormant, needs operator recovery".
            CE::ContextPoisoned(_) => Self::Context {
                message: format!("{e}"),
                code: codes::CTX_2134.to_owned(),
            },
            // ADR-049 §10: actor crashed and could not be respawned (lost /
            // corrupt snapshot). Dedicated SCP-CTX-2135 instead of CTX_2001.
            CE::ActorCrashed(_) => Self::Context {
                message: format!("{e}"),
                code: codes::CTX_2135.to_owned(),
            },
            // ADR-049 §9: key package single-use replay rejected by the
            // crypto-layer consumed-init-key backstop. Dedicated SCP-CTX-2136
            // instead of CTX_2001 so a caller can detect a security-relevant
            // single-use replay.
            CE::KeyPackageReplay(_) => Self::Context {
                message: format!("{e}"),
                code: codes::CTX_2136.to_owned(),
            },
            // §5.9: a `RestoreAccess` requested capabilities that were not
            // actually suspended for the member (and the member is not
            // read-excluded with read requested). Dedicated SCP-CTX-2137
            // instead of the CTX_2001 catch-all so a caller can detect a no-op
            // restore. Mirrors the PyO3 bridge for cross-bridge
            // parity.
            CE::NothingToRestore(_) => Self::Context {
                message: format!("{e}"),
                code: codes::CTX_2137.to_owned(),
            },
            // Recover embedded SCP-ECON-/SCP-OUTLET-/SCP-PERM- codes from
            // the runtime's `PermissionDenied(String)` catch-all so the
            // typed-envelope contract holds for outlet-economy failures.
            CE::PermissionDenied(msg) => {
                let code = extract_scp_code(msg).unwrap_or_else(|| codes::PERM_3001.to_owned());
                if code.starts_with("SCP-PERM-") {
                    Self::Permission {
                        message: format!("{e}"),
                        code,
                    }
                } else if code.starts_with("SCP-OUTLET-") {
                    // SCP-OUT-031 PR-2a: outlet INVOCATION errors no longer flow
                    // through this string path — they arrive as the typed
                    // `CE::Outlet` / `CE::OutletContextNotActive` arms above.
                    // This branch is now RESIDUAL: it still catches the handful
                    // of outlet-coded diagnostics the runtime emits as a raw
                    // `PermissionDenied` (e.g. the settle-path `SCP-OUTLET-6089`
                    // "context vanished during settle" carrier in
                    // `supervisor.rs`), so keep it as defense-in-depth.
                    Self::Outlet {
                        message: format!("{e}"),
                        code,
                    }
                } else {
                    Self::Context {
                        message: format!("{e}"),
                        code,
                    }
                }
            }
            // SCP-OUT-031 PR-2a: outlet invocation errors now arrive as the
            // typed `ContextError::Outlet(surface)` (was flattened to
            // `PermissionDenied(String)`). Route to the dedicated `Outlet`
            // variant preserving at least the concrete §5.4.4 code — parity
            // with the pre-PR-2a `SCP-OUTLET-` prefix routing above. The
            // `Display` renders `[code] class: slug`.
            //
            // PR-2b: render the structured surface (class/detail/retry/
            // source_chain) into a richer typed TS error here.
            CE::Outlet(surface) => Self::Outlet {
                message: format!("{e}"),
                code: surface.code.clone(),
            },
            // SCP-OUT-031 PR-2a: the outlet reserve-gate context-not-active
            // carrier. `Display` is the structured, STATE-FREE
            // `[SCP-OUTLET-6101] protocol: protocol.context-closed-mid-stream`
            // — the raw lifecycle `current_state` is NEVER rendered here (this
            // gate runs before authz, so an unauthorized caller must not learn
            // the exact lifecycle state).
            CE::OutletContextNotActive { .. } => Self::Outlet {
                message: format!("{e}"),
                code: scp_core::context::outlets::error_codes::CODE_PROTOCOL_SESSION.to_owned(),
            },
            _ => Self::Context {
                message: format!("{e} — verify context state, membership, and permissions"),
                code: codes::CTX_2001.to_owned(),
            },
        }
    }
}

impl From<scp_core::context::builder::ContextCreationError> for ScpNapiError {
    fn from(e: scp_core::context::builder::ContextCreationError) -> Self {
        Self::Context {
            message: format!(
                "context creation failed: {e} — check context parameters and identity"
            ),
            code: codes::CTX_2002.to_owned(),
        }
    }
}

impl From<scp_core::context::templates::TemplateError> for ScpNapiError {
    fn from(e: scp_core::context::templates::TemplateError) -> Self {
        Self::Context {
            message: format!(
                "template validation failed: {e} — ensure context params match the template"
            ),
            code: codes::CTX_2003.to_owned(),
        }
    }
}

impl From<scp_core::context::roles::RoleError> for ScpNapiError {
    fn from(e: scp_core::context::roles::RoleError) -> Self {
        Self::Context {
            message: format!(
                "role operation failed: {e} — verify role definitions and member permissions"
            ),
            code: codes::CTX_2004.to_owned(),
        }
    }
}

impl From<scp_core::context::ttl::TtlError> for ScpNapiError {
    fn from(e: scp_core::context::ttl::TtlError) -> Self {
        Self::Context {
            message: format!(
                "TTL operation failed: {e} — check TTL configuration and context state"
            ),
            code: codes::CTX_2005.to_owned(),
        }
    }
}

impl From<scp_core::context::promotion::PromotionError> for ScpNapiError {
    fn from(e: scp_core::context::promotion::PromotionError) -> Self {
        Self::Context {
            message: format!(
                "context promotion failed: {e} — verify eligibility and governance rules"
            ),
            code: codes::CTX_2006.to_owned(),
        }
    }
}

impl From<scp_core::context::outlets::OutletError> for ScpNapiError {
    fn from(e: scp_core::context::outlets::OutletError) -> Self {
        Self::Outlet {
            message: format!(
                "outlet operation failed: {e} — check outlet registration, permissions, and input schema"
            ),
            code: codes::OUTLET_6001.to_owned(),
        }
    }
}

impl From<scp_core::context::outlets::invoke::InvocationError> for ScpNapiError {
    fn from(e: scp_core::context::outlets::invoke::InvocationError) -> Self {
        Self::Outlet {
            message: format!(
                "outlet invocation failed: {e} — verify outlet ID, input, and caller permissions"
            ),
            code: codes::OUTLET_6002.to_owned(),
        }
    }
}

impl From<scp_core::context::outlets::schema::SchemaValidationError> for ScpNapiError {
    fn from(e: scp_core::context::outlets::schema::SchemaValidationError) -> Self {
        Self::Validation {
            message: format!(
                "schema validation failed: {e} — check input against the outlet's JSON Schema"
            ),
            code: codes::VALID_7001.to_owned(),
        }
    }
}

impl From<scp_core::crypto::mls::error::MlsError> for ScpNapiError {
    fn from(e: scp_core::crypto::mls::error::MlsError) -> Self {
        Self::Crypto {
            message: format!(
                "MLS operation failed: {e} — check group state and member key packages"
            ),
            code: codes::CRYPTO_4001.to_owned(),
        }
    }
}

impl From<scp_core::crypto::sender_keys::SenderKeyError> for ScpNapiError {
    fn from(e: scp_core::crypto::sender_keys::SenderKeyError) -> Self {
        Self::Crypto {
            message: format!(
                "sender key operation failed: {e} — verify key material and encryption parameters"
            ),
            code: codes::CRYPTO_4002.to_owned(),
        }
    }
}

impl From<scp_core::crypto::ucan::UcanError> for ScpNapiError {
    fn from(e: scp_core::crypto::ucan::UcanError) -> Self {
        // Canonical UCAN→error-code mapping — see `scp-ffi/src/error.rs`
        // for the full rationale. All bridges route through the shared
        // `scp_ffi_common::ucan_errors` module.
        let code = scp_ffi_common::ucan_errors::ucan_error_code(&e).to_owned();
        Self::Permission {
            message: format!(
                "{e} — check token format, signatures, time bounds, and capability chain"
            ),
            code,
        }
    }
}

impl From<scp_core::envelope::EnvelopeError> for ScpNapiError {
    fn from(e: scp_core::envelope::EnvelopeError) -> Self {
        Self::Crypto {
            message: format!(
                "envelope operation failed: {e} — check payload size, signing keys, and encryption state"
            ),
            code: codes::CRYPTO_4003.to_owned(),
        }
    }
}

impl From<scp_event_log::EventLogError> for ScpNapiError {
    fn from(e: scp_event_log::EventLogError) -> Self {
        Self::Context {
            message: format!(
                "event log operation failed: {e} — verify log integrity and sequence numbers"
            ),
            code: codes::CTX_2007.to_owned(),
        }
    }
}

impl From<scp_core::provenance::ProvenanceError> for ScpNapiError {
    fn from(e: scp_core::provenance::ProvenanceError) -> Self {
        Self::Validation {
            message: format!("provenance validation failed: {e} — check cross-context chain depth"),
            code: codes::VALID_7002.to_owned(),
        }
    }
}

impl From<scp_core::trust::TrustError> for ScpNapiError {
    fn from(e: scp_core::trust::TrustError) -> Self {
        Self::Validation {
            message: format!(
                "trust evaluation failed: {e} — check event log data and attestation validity"
            ),
            code: codes::VALID_7003.to_owned(),
        }
    }
}

impl From<scp_core::uri::ScpUriError> for ScpNapiError {
    fn from(e: scp_core::uri::ScpUriError) -> Self {
        Self::Validation {
            message: format!("invalid SCP URI: {e} — check URI format (scp://relay/context-id)"),
            code: codes::VALID_7004.to_owned(),
        }
    }
}

impl From<scp_core::well_known::WellKnownValidationError> for ScpNapiError {
    fn from(e: scp_core::well_known::WellKnownValidationError) -> Self {
        Self::Validation {
            message: format!("well-known validation failed: {e} — check relay configuration"),
            code: codes::VALID_7005.to_owned(),
        }
    }
}

impl From<scp_core::discovery::DiscoveryError> for ScpNapiError {
    fn from(e: scp_core::discovery::DiscoveryError) -> Self {
        Self::Context {
            message: format!(
                "discovery operation failed: {e} — check relay connectivity and search parameters"
            ),
            code: codes::CTX_2008.to_owned(),
        }
    }
}

impl From<scp_core::bridge::registration::BridgeRegistrationError> for ScpNapiError {
    fn from(e: scp_core::bridge::registration::BridgeRegistrationError) -> Self {
        Self::Context {
            message: format!(
                "bridge registration failed: {e} — verify bridge configuration and permissions"
            ),
            code: codes::CTX_2009.to_owned(),
        }
    }
}

impl From<scp_core::bridge::shadow::ShadowError> for ScpNapiError {
    fn from(e: scp_core::bridge::shadow::ShadowError) -> Self {
        Self::Context {
            message: format!(
                "shadow context operation failed: {e} — check bridge state and context permissions"
            ),
            code: codes::CTX_2010.to_owned(),
        }
    }
}

impl From<scp_platform::PlatformError> for ScpNapiError {
    fn from(e: scp_platform::PlatformError) -> Self {
        Self::Crypto {
            message: format!(
                "platform key operation failed: {e} — check key custody configuration"
            ),
            code: codes::CRYPTO_4004.to_owned(),
        }
    }
}

impl From<serde_json::Error> for ScpNapiError {
    fn from(e: serde_json::Error) -> Self {
        Self::Validation {
            message: format!("JSON serialization/deserialization failed: {e} — check input format"),
            code: codes::VALID_7006.to_owned(),
        }
    }
}

impl From<scp_ffi_common::validate::ValidationError> for ScpNapiError {
    fn from(e: scp_ffi_common::validate::ValidationError) -> Self {
        Self::Validation {
            message: e.message,
            code: codes::VALID_7000.to_owned(),
        }
    }
}

impl From<scp_ffi_common::bridge_instance::HandleAffinityError> for ScpNapiError {
    fn from(e: scp_ffi_common::bridge_instance::HandleAffinityError) -> Self {
        // Sanitized message — never exposes the raw ids. PERM_3030 lets
        // callers programmatically distinguish this from other permission
        // errors.
        Self::Permission {
            message: format!("{e}"),
            code: codes::PERM_3030.to_owned(),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Rejects every custody value outside the vocabulary §3.2.2 of the identity
/// spec states, before `build_key_custody` decides what an accepted value
/// reaches.
///
/// §3.2.2 gives a caller `"encrypted_file"` and `"os_keystore"`. A build
/// carrying the `testing` cargo feature additionally accepts `"in_memory"`,
/// which §3.2.2 names a test-harness affordance rather than a value of the
/// vocabulary; a shipped build accepts the string here and declines it in
/// `build_key_custody` with `SCP-IDENT-1008`, so the two builds return
/// different codes for the string and neither returns a custody.
///
/// # Errors
///
/// Returns `ScpNapiError::Validation` carrying `SCP-VALID-7005` for every
/// other string, which includes the five the three bridges once parsed:
/// `platform`, `software`, `file`, `platform_managed`, and `hardware`.
pub(crate) fn validate_custody_type(custody: &str) -> Result<&str, ScpNapiError> {
    match custody {
        "encrypted_file" | "os_keystore" | "in_memory" => Ok(custody),
        // VALID_7005 ("invalid field value") matches the semantic: an
        // unrecognized enum string is a wrong-value error, not the
        // malformed/wrong-shape byte input that VALID_7007 is reserved for
        // (api-design J2, M1). The PyO3 bridge's `build_key_custody` and the
        // UniFFI bridge's `build_key_custody` emit VALID_7005 for this same
        // condition, so a caller who switches on the code string reads one
        // value across all three bridges.
        other => Err(ScpNapiError::Validation {
            message: format!(
                "unknown custody type: {other:?} — §3.2.2 of the identity spec gives a \
                 caller two values, \"encrypted_file\" and \"os_keystore\". The strings \
                 \"platform\", \"software\", \"file\", \"platform_managed\", and \"hardware\" \
                 name no custody backend. Reach the operating system's key store by \
                 passing a KeyCustodyProvider to identityCreateWithCustody(). That call \
                 returns SCP-IDENT-1059 on a shipped build today, because no pre-rotation \
                 custody backend is wired yet, so no shipped build creates an identity."
            ),
            code: codes::VALID_7005.to_owned(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// Regression tests pinning each `PreRotationCustodyError` variant to its
// typed error code on the NAPI bridge. Mirrors the PyO3 tests in
// `crates/scp-ffi/src/error.rs` (same function names, same semantics) so
// any future re-ordering or accidental swap of match arms in the
// `From<scp_identity::IdentityError>` impl above breaks here, not at the
// TypeScript SDK boundary where it would be harder to diagnose.

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use scp_platform::PreRotationCustodyError;

    fn code_of(e: ScpNapiError) -> String {
        match e {
            ScpNapiError::Identity { code, .. } => code,
            other => panic!("expected ScpNapiError::Identity, got {other:?}"),
        }
    }

    #[test]
    fn pre_rotation_handle_not_found_surfaces_typed_code() {
        let err: ScpNapiError =
            scp_identity::IdentityError::PreRotation(PreRotationCustodyError::HandleNotFound)
                .into();
        assert_eq!(code_of(err), codes::IDENT_1047);
    }

    #[test]
    fn pre_rotation_unavailable_surfaces_typed_code() {
        let err: ScpNapiError = scp_identity::IdentityError::PreRotation(
            PreRotationCustodyError::Unavailable("hardware key not connected".into()),
        )
        .into();
        assert_eq!(code_of(err), codes::IDENT_1048);
    }

    #[test]
    fn pre_rotation_user_declined_surfaces_typed_code() {
        let err: ScpNapiError =
            scp_identity::IdentityError::PreRotation(PreRotationCustodyError::UserDeclined).into();
        assert_eq!(code_of(err), codes::IDENT_1049);
    }

    #[test]
    fn pre_rotation_storage_surfaces_typed_code() {
        let err: ScpNapiError = scp_identity::IdentityError::PreRotation(
            PreRotationCustodyError::Storage("disk full".into()),
        )
        .into();
        assert_eq!(code_of(err), codes::IDENT_1050);
    }

    #[test]
    fn pre_rotation_invalid_callback_response_surfaces_typed_code() {
        let err: ScpNapiError = scp_identity::IdentityError::PreRotation(
            PreRotationCustodyError::InvalidCallbackResponse("handle is empty".into()),
        )
        .into();
        assert_eq!(code_of(err), codes::IDENT_1051);
    }

    #[test]
    fn pre_rotation_commitment_mismatch_surfaces_typed_code() {
        let err: ScpNapiError =
            scp_identity::IdentityError::PreRotation(PreRotationCustodyError::CommitmentMismatch)
                .into();
        assert_eq!(code_of(err), codes::IDENT_1052);
    }

    #[test]
    fn non_pre_rotation_identity_errors_keep_generic_envelope() {
        let err: ScpNapiError = scp_identity::IdentityError::InvalidDidFormat("bad".into()).into();
        assert_eq!(code_of(err), codes::IDENT_1001);
    }

    /// Extracts the code from a `ScpNapiError::Context` (or panics).
    fn context_code_of(e: ScpNapiError) -> String {
        match e {
            ScpNapiError::Context { code, .. } => code,
            other => panic!("expected ScpNapiError::Context, got {other:?}"),
        }
    }

    /// ADR-049 §10: a poisoned context must surface the dedicated
    /// SCP-CTX-2134 code, NOT the catch-all SCP-CTX-2001.
    #[test]
    fn context_poisoned_surfaces_ctx_2134() {
        let err: ScpNapiError =
            scp_core::context::ContextError::ContextPoisoned("ctx-1".to_owned()).into();
        assert_eq!(context_code_of(err), codes::CTX_2134);
    }

    /// ADR-049 §10: an unrecoverable actor crash must surface the dedicated
    /// SCP-CTX-2135 code, distinct from the poison code and the catch-all.
    #[test]
    fn actor_crashed_surfaces_ctx_2135() {
        let err: ScpNapiError =
            scp_core::context::ContextError::ActorCrashed("ctx-1".to_owned()).into();
        assert_eq!(context_code_of(err), codes::CTX_2135);
    }

    /// ADR-049 §9: a key package single-use replay must surface the dedicated
    /// SCP-CTX-2136 code, distinct from the catch-all and from `InvalidState`.
    #[test]
    fn key_package_replay_surfaces_ctx_2136() {
        let err: ScpNapiError =
            scp_core::context::ContextError::KeyPackageReplay("kp".to_owned()).into();
        assert_eq!(context_code_of(err), codes::CTX_2136);
    }

    /// §5.9: a `RestoreAccess` with nothing to restore must surface the
    /// dedicated SCP-CTX-2137 code, distinct from the catch-all SCP-CTX-2001.
    /// The same code is surfaced by the `PyO3` bridge for
    /// cross-bridge parity.
    #[test]
    fn nothing_to_restore_surfaces_ctx_2137() {
        let err: ScpNapiError = scp_core::context::ContextError::NothingToRestore(
            "no suspended capabilities to restore for did:dht:zsubject".to_owned(),
        )
        .into();
        assert_eq!(context_code_of(err), codes::CTX_2137);
    }

    /// Regression guard: an unrelated `ContextError` still falls through to
    /// the catch-all SCP-CTX-2001 — the poison/crash arms are narrow.
    #[test]
    fn generic_context_error_keeps_ctx_2001() {
        let err: ScpNapiError =
            scp_core::context::ContextError::MembershipFailed("nope".to_owned()).into();
        assert_eq!(context_code_of(err), codes::CTX_2001);
    }

    /// SCP-OUT-031 PR-2a (SECURITY): the outlet reserve-gate context-not-active
    /// carrier must surface as the STRUCTURED, state-free `SCP-OUTLET-6101`
    /// outlet error — the raw lifecycle state MUST NOT leak to the FFI caller
    /// (this gate runs before authz on the unary invoke path). Cross-bridge
    /// parity with the `PyO3` + `UniFFI` bridges.
    #[test]
    fn outlet_context_not_active_surfaces_structured_state_free() {
        let err: ScpNapiError = scp_core::context::ContextError::OutletContextNotActive {
            current_state: scp_core::context::ContextState::Closing,
        }
        .into();
        let (message, code) = match err {
            ScpNapiError::Outlet { message, code } => (message, code),
            other => panic!("expected ScpNapiError::Outlet, got {other:?}"),
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
            "{message}"
        );
    }
}
