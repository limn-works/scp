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
    ///
    /// The UNSTRUCTURED arm: an outlet-coded diagnostic that does not carry a
    /// §5.4.4 taxonomy (the residual `PermissionDenied("SCP-OUTLET-…")`
    /// settle-path carriers, registration/verification failures). An outlet
    /// error that DOES carry the taxonomy uses [`Self::OutletSurface`].
    #[error("[{code}] outlet error: {message}")]
    Outlet {
        /// Human-readable error message.
        message: String,
        /// Stable error code (e.g. `SCP-OUTLET-6001`).
        code: String,
    },

    /// A §5.4.4 outlet error carrying its full structured taxonomy
    /// (SCP-OUT-031 PR-2b).
    ///
    /// napi-rs cannot carry typed compound fields: every `ScpNapiError`
    /// collapses to a `napi::Error` whose entire payload is a `Status` plus a
    /// message string (see the `From<ScpNapiError> for napi::Error` impl
    /// below). So the structured surface rides ONE blob in a machine-parseable
    /// `(outlet_error_b64=…)` suffix — the same discipline the three saga
    /// terminals use for their `(retry_after_ms=…)` / `(saga_id=…)` /
    /// `(contended_context=…)` data.
    ///
    /// # Why base64, not raw JSON
    ///
    /// The saga suffixes are safe because their bodies are digits or validated
    /// ids — neither can contain `)` or a space, so a decoy inside `{message}`
    /// provably loses. A raw JSON body has no such guarantee: `serde_json`
    /// escapes `"` and `\` but NOT parentheses, so a string field INSIDE the
    /// payload can contain the delimiter — and being after the real one, it
    /// defeats a last-match parse just as a decoy in `{message}` defeats a
    /// first-match parse. Base64's alphabet (`A-Za-z0-9+/=`) contains neither
    /// `(` nor a space, so the delimiter cannot occur inside the body at all
    /// and a LAST-anchored parse is sound by construction. Both parsers — the
    /// Rust `extract_surface_suffix` test helper and the TypeScript one — MUST
    /// be last-anchored; `scp_ffi_common::outlet_error::parse_surface_b64` is
    /// the canonical decoder.
    ///
    /// The decoded blob is `OutletErrorSurface` (`{class, code, slug, retry,
    /// detail, source_chain}`), with the two `u64` detail fields as decimal
    /// strings so JavaScript's `JSON.parse` cannot round them — see the
    /// `scp_ffi_common::outlet_error` module docs. PR-3's TS hierarchy
    /// reconstructs the exact typed error from it, never by re-parsing prose.
    ///
    /// ADDITIVE BY CONSTRUCTION: the `[{code}]` prefix is unchanged and still
    /// leads the message, so the shared TS classifier `mapBridgeError`
    /// (`bindings/typescript/src/errors.ts`), which dispatches on the
    /// START-anchored `/^\[([A-Z]+-[A-Z]+-\d+)\]/`, keeps routing
    /// `SCP-OUTLET-*` to `OutletError` exactly as before. The suffix is only
    /// ever read by a classifier that already matched the prefix.
    ///
    /// `surface_b64` is produced by `scp_ffi_common::outlet_error`, shared with
    /// the `PyO3` bridge, and `code` is copied STRUCTURALLY off the surface —
    /// neither field is ever recovered by parsing the rendered string apart.
    #[error("[{code}] outlet error: {message} (outlet_error_b64={surface_b64})")]
    OutletSurface {
        /// Human-readable detail (carries the `[SCP-OUTLET-…]` prefix).
        message: String,
        /// The §5.4.4 sub-block code (`6100`-`6199`).
        code: String,
        /// Base64 of the canonical `OutletErrorSurface` JSON.
        surface_b64: String,
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

impl ScpNapiError {
    /// Renders a structured §5.4.4 `OutletErrorSurface` onto the typed
    /// [`Self::OutletSurface`] variant (SCP-OUT-031 PR-2b).
    ///
    /// The blob comes from
    /// [`scp_ffi_common::outlet_error::render_surface_b64`] — shared with the
    /// `PyO3` bridge and inverted by
    /// [`scp_ffi_common::outlet_error::parse_surface_b64`]. `code` is read
    /// STRUCTURALLY off the surface, never parsed out of the message.
    #[must_use]
    pub fn from_outlet_surface(
        message: impl Into<String>,
        surface: &scp_core::context::outlets::errors::OutletErrorSurface,
    ) -> Self {
        Self::OutletSurface {
            message: message.into(),
            code: surface.code.clone(),
            surface_b64: scp_ffi_common::outlet_error::render_surface_b64(surface),
        }
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
            // SCP-OUT-031 PR-2b: outlet invocation errors arrive as the typed
            // `ContextError::Outlet(surface)` carrying the §5.4.4
            // class/code/slug/retry/detail/source_chain, and are rendered here
            // in FULL onto `ScpNapiError::OutletSurface` — the canonical JSON
            // suffix the TS SDK reconstructs from. (PR-2a preserved only
            // `surface.code`.)
            CE::Outlet(surface) => Self::from_outlet_surface(format!("{e}"), surface),
            // SCP-OUT-031 PR-2a/2b: the outlet reserve-gate context-not-active
            // carrier. SECURITY — this gate runs BEFORE authorization, so its
            // error reaches an unauthenticated caller. The surface is
            // SYNTHESIZED from the two §5.4.4 constants (`from_code` derives
            // class + retry from the code registry); `current_state` is never
            // read here, so the raw lifecycle state cannot leak into the
            // message OR into the JSON suffix. The caller learns only "not
            // active", never WHICH non-active state.
            CE::OutletContextNotActive { .. } => Self::from_outlet_surface(
                format!("{e}"),
                &scp_core::context::outlets::errors::OutletErrorSurface::from_code(
                    scp_core::context::outlets::error_codes::CODE_PROTOCOL_SESSION,
                    scp_core::context::outlets::error_codes::SLUG_PROTOCOL_CONTEXT_CLOSED_MID_STREAM,
                    None,
                ),
            ),
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

// Typed §5.4.4 `OutletError` WIRE ENVELOPE → the structured TS error
// (SCP-OUT-031 PR-2b).
//
// The CROSS-CONTEXT render seam: `OutletErrorSurface::from_envelope` projects a
// decoded §5.4.4 envelope onto the in-process surface (dropping the HMAC
// `message`, `pad_nonce` and `registration_event_id` — wire-opacity fields a
// cross-context receiver needs for catalog reverse-lookup, not the SDK) and it
// renders through the SAME `from_outlet_surface` the runtime-side arm uses, so
// a TS caller cannot tell (nor needs to tell) which side produced the error.
//
// HONEST STATUS: no runtime code CONSTRUCTS this envelope yet — SCP-OUT-029's
// `wrap_cross_context_error` and the §5.4.4 wire decode are unimplemented, so
// today's only producers are the conformance fixtures. This impl is the render
// half of the seam, exercised by the fixture corpus, and delegates to
// `from_envelope` rather than re-implementing the projection so there is
// nothing to drift when the producer lands.
impl From<scp_core::context::outlets::errors::OutletError> for ScpNapiError {
    fn from(e: scp_core::context::outlets::errors::OutletError) -> Self {
        let surface = scp_ffi_common::outlet_error::surface_from_untrusted_envelope(&e);
        Self::from_outlet_surface(format!("{e}"), &surface)
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

/// Parses a custody type string into a string the bridge can match on.
///
/// Returns the canonical custody type string or `Err(ScpNapiError::Validation)`.
pub(crate) fn validate_custody_type(custody: &str) -> Result<&str, ScpNapiError> {
    match custody {
        "in_memory" | "platform" | "software" => Ok(custody),
        // VALID_7005 ("invalid field value") matches the semantic: an
        // unrecognized enum string is a wrong-value error, not the
        // malformed/wrong-shape byte input that VALID_7007 is reserved for
        // (api-design J2, M1). PyO3's `parse_custody_inner` emits the
        // same class of error (VALID_7001 via `ScpPyError::validation`),
        // both distinct from the narrower 7007.
        other => Err(ScpNapiError::Validation {
            message: format!(
                "unknown custody type: {other:?} — expected \"in_memory\", \"platform\", or \"software\""
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
    use scp_core::context::outlets::errors::OutletErrorSurface;
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

    // ------------------------------------------------------------------
    // SCP-OUT-031 PR-2b — the structured §5.4.4 surface render.
    //
    // napi-rs collapses every error to a message string, so these tests read
    // the surface back out of the machine-parseable `(outlet_error=…)` suffix
    // of the RENDERED string — exactly what the TypeScript SDK does. Nothing is
    // inferred from prose.
    // ------------------------------------------------------------------

    /// The machine-parseable suffix delimiter. The leading space is part of it:
    /// base64 cannot contain a space, so ` (outlet_error_b64=` cannot occur
    /// inside the payload.
    const SUFFIX_DELIMITER: &str = " (outlet_error_b64=";

    /// Extracts the base64 surface blob out of a rendered napi error message the
    /// way the TS SDK must: LAST-anchored on `(outlet_error_b64=`. Last-anchored
    /// is sound here (and would NOT be with a raw-JSON body) because the base64
    /// alphabet excludes `(` and space, so the delimiter cannot appear inside
    /// the payload — a decoy can only precede the genuine one.
    fn extract_surface_suffix(rendered: &str) -> &str {
        let start = rendered
            .rfind(SUFFIX_DELIMITER)
            .unwrap_or_else(|| panic!("no (outlet_error_b64=…) suffix in: {rendered}"));
        let body = &rendered[start + SUFFIX_DELIMITER.len()..];
        body.strip_suffix(')')
            .unwrap_or_else(|| panic!("suffix is not terminal in: {rendered}"))
    }

    /// Rebuilds an `OutletErrorSurface` from the rendered napi message — the
    /// exact reconstruction PR-3's TypeScript hierarchy performs.
    fn reconstruct_surface(err: &ScpNapiError) -> OutletErrorSurface {
        let rendered = err.to_string();
        // The `[{code}]` PREFIX must still lead, or the shared TS classifier
        // `mapBridgeError` (start-anchored on `/^\[([A-Z]+-[A-Z]+-\d+)\]/`)
        // would stop routing this to `OutletError`. The suffix is ADDITIVE.
        assert!(
            rendered.starts_with("[SCP-OUTLET-"),
            "the `[{{code}}]` prefix dispatch must survive: {rendered}"
        );
        scp_ffi_common::outlet_error::parse_surface_b64(extract_surface_suffix(&rendered)).unwrap()
    }

    /// LIVE PATH: a real structured error crosses the actual
    /// `From<ContextError>` impl and EVERY §5.4.4 member survives the collapse
    /// to a string. Asserted against the corpus shared with the `PyO3` and
    /// `UniFFI` bridges, so equality here plus equality there is cross-bridge
    /// parity.
    #[test]
    fn outlet_surface_survives_the_context_error_from_impl() {
        for entry in scp_ffi_common::outlet_error::corpus::parity_surfaces() {
            let err: ScpNapiError =
                scp_core::context::ContextError::Outlet(Box::new(entry.surface.clone())).into();
            // Structural read of the variant field…
            let ScpNapiError::OutletSurface { code, .. } = &err else {
                panic!("expected ScpNapiError::OutletSurface, got {err:?}");
            };
            assert_eq!(code, &entry.surface.code, "{}", entry.name);
            // …and the end-to-end read the TS SDK performs.
            assert_eq!(reconstruct_surface(&err), entry.surface, "{}", entry.name);
        }
    }

    /// LIVE PATH (cross-context): a real §5.4.4 WIRE ENVELOPE crosses the
    /// `From<OutletError>` impl and renders to the same surface
    /// `OutletErrorSurface::from_envelope` projects.
    #[test]
    fn typed_envelope_renders_through_from_envelope() {
        for entry in scp_ffi_common::outlet_error::corpus::parity_surfaces() {
            let envelope =
                scp_ffi_common::outlet_error::corpus::envelope_from_surface(&entry.surface)
                    .unwrap();
            let expected = OutletErrorSurface::from_envelope(&envelope);
            let err: ScpNapiError = envelope.into();
            assert_eq!(reconstruct_surface(&err), expected, "{}", entry.name);
            assert_eq!(reconstruct_surface(&err), entry.surface, "{}", entry.name);
        }
    }

    /// AC10 groundwork: the PR-1 `malformed` fixtures cross the bridge with
    /// their per-class detail mismatch INTACT, so the SDK can reject them.
    #[test]
    fn malformed_detail_mismatch_survives_the_bridge() {
        for (name, surface) in
            scp_ffi_common::outlet_error::corpus::malformed_detail_surfaces().unwrap()
        {
            let err: ScpNapiError =
                scp_core::context::ContextError::Outlet(Box::new(surface.clone())).into();
            let back = reconstruct_surface(&err);
            assert_eq!(back, surface, "{name}");
            assert_ne!(
                back.detail.unwrap().kind(),
                back.class.expected_detail(),
                "{name}: the bridge normalized away the AC10 detail mismatch"
            );
        }
    }

    /// The napi error is ultimately a `napi::Error` whose ONLY payload is the
    /// message string — assert the suffix survives that final collapse, since
    /// that string is literally all the TypeScript SDK receives.
    #[test]
    fn surface_survives_the_collapse_to_napi_error() {
        let surface = OutletErrorSurface::from_code(
            scp_core::context::outlets::error_codes::CODE_TRANSPORT_FAULT,
            scp_core::context::outlets::error_codes::SLUG_TRANSPORT_RATE_LIMITED,
            Some(
                scp_core::context::outlets::errors::DetailBody::TransportRateLimit {
                    retry_after_secs: 45,
                },
            ),
        );
        let napi_err: napi::Error =
            ScpNapiError::from_outlet_surface("rate limited", &surface).into();
        let rendered = &napi_err.reason;
        assert!(rendered.starts_with("[SCP-OUTLET-"), "{rendered}");
        let blob = extract_surface_suffix(rendered);
        assert_eq!(
            scp_ffi_common::outlet_error::parse_surface_b64(blob).unwrap(),
            surface
        );
    }

    /// The suffix framing is sound against a payload that embeds the delimiter:
    /// base64 cannot contain `(` or a space, so a hostile `slug`/`detail` string
    /// cannot forge or shadow the real suffix, and the LAST-anchored parse still
    /// recovers the genuine blob. This is the property the raw-JSON framing
    /// lacked.
    #[test]
    fn hostile_payload_cannot_break_the_suffix_framing() {
        let hostile_message = "decoy (outlet_error_b64=AAAA) still decoy";
        let surface = OutletErrorSurface::from_code(
            scp_core::context::outlets::error_codes::CODE_PROTOCOL_VIOLATION,
            scp_core::context::outlets::error_codes::SLUG_PROTOCOL_VIOLATION,
            Some(scp_core::context::outlets::errors::DetailBody::Protocol {
                // A detail string that embeds the delimiter — it lands INSIDE
                // the base64 body, where it is unrecognizable as a delimiter.
                rule: "x (outlet_error_b64=BBBB) y".to_owned(),
            }),
        );
        let err = ScpNapiError::from_outlet_surface(hostile_message, &surface);
        let rendered = err.to_string();
        // Exactly one real delimiter, and it is the LAST occurrence.
        assert_eq!(
            rendered.rfind(SUFFIX_DELIMITER).unwrap() + SUFFIX_DELIMITER.len(),
            rendered.len() - extract_surface_suffix(&rendered).len() - 1
        );
        assert_eq!(reconstruct_surface(&err), surface);
    }

    /// SCP-OUT-031 PR-2a/2b (SECURITY): the outlet reserve-gate
    /// context-not-active carrier must surface as the STRUCTURED, state-free
    /// `SCP-OUTLET-6101` outlet error — the raw lifecycle state MUST NOT leak to
    /// the FFI caller (this gate runs before authz on the unary invoke path),
    /// not in the message and (PR-2b) not in the JSON suffix either.
    /// Cross-bridge parity with the `PyO3` + `UniFFI` bridges.
    #[test]
    fn outlet_context_not_active_surfaces_structured_state_free() {
        // EVERY non-Active state, derived from an exhaustive match so a new
        // lifecycle variant cannot silently escape this leak test.
        for state in scp_ffi_common::outlet_error::corpus::non_active_context_states() {
            let state_name = format!("{state:?}");
            let err: ScpNapiError = scp_core::context::ContextError::OutletContextNotActive {
                current_state: state,
            }
            .into();
            let ScpNapiError::OutletSurface { message, code, .. } = &err else {
                panic!("expected ScpNapiError::OutletSurface, got {err:?}");
            };
            assert_eq!(
                code,
                scp_core::context::outlets::error_codes::CODE_PROTOCOL_SESSION
            );
            assert!(
                message.contains("protocol.context-closed-mid-stream"),
                "{message}"
            );
            // The FULL rendered string is everything the caller sees.
            let rendered = err.to_string();
            assert!(
                !rendered.contains(&state_name),
                "raw lifecycle state {state_name} leaked to the FFI caller: {rendered}"
            );
            let back = reconstruct_surface(&err);
            assert!(back.detail.is_none());
            assert_eq!(
                back.class,
                scp_core::context::outlets::errors::OutletErrorClass::Protocol
            );
        }
    }
}
