//! napi-rs bridge for UCAN operations.
//!
//! Exposes UCAN token management to JavaScript:
//!
//! - `ucan_validate` — Validate a UCAN token for a required capability.
//! - `ucan_mint` — Mint a new UCAN token for a context member with real
//!   Ed25519 signing delegated to the creator identity's retained
//!   `KeyCustody` (in-memory OR production callback custody).
//! - `ucan_revoke` — Revoke a UCAN token.
//!
//! # Validation pipeline
//!
//! `ucan_validate` delegates to `scp_core::crypto::ucan::validate::validate_ucan`,
//! which implements the full 11-step UCAN validation pipeline from ADR-016:
//!
//! 1. Parse JWT-format UCAN token.
//! 2. Verify Ed25519 signature via DID resolver.
//! 3. Verify delegation chain integrity (proof chain traversal).
//! 4. Verify root issuer is context creator.
//! 5. Verify audience matches presenting agent.
//! 6. Verify token capabilities include the required capability.
//! 7. Verify delegation attenuation (child <= parent capabilities).
//! 8. Verify capability is within context ceiling.
//! 9. Validate nonce (format, freshness, uniqueness).
//! 10. Check revocation list.
//! 11. Verify expiry and time bounds.
//!
//! See ADR-016 (UCAN Enforcement) and ADR-022 in `.docs/adrs/`.

use scp_ffi_common::error_codes as codes;
use std::collections::HashMap;

use napi_derive::napi;
use scp_core::crypto::ucan::mint::{MintParams, mint_ucan};
use scp_ffi_common::validate::{validate_capability_uri, validate_did, validate_ucan_token};

use scp_core::crypto::ucan::UcanError as CoreUcanError;

use scp_core::crypto::ucan::capability::CapabilityUri;
use scp_core::crypto::ucan::validate::{
    CapabilityValidation, DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, ValidationContext, evaluate_ucan,
    parse_ucan, validate_ucan,
};

use scp_ffi_common::{
    BridgeNonceTracker, BridgeProofResolver, BridgeRevocationAuthorizer, BridgeRevocationChecker,
    BridgeRevocationDistributor, BridgeRevocationEventLogger, DispatchDidResolver,
};

use crate::context::NapiContextHandle;
use crate::decrement_handle_count;
use crate::error::ScpNapiError;
use crate::increment_handle_count;
use crate::runtime::NapiBridgeInstance;

// ---------------------------------------------------------------------------
// NapiUcanTokenData — UCAN token metadata record
// ---------------------------------------------------------------------------

/// A UCAN token with metadata accessible to SDK consumers.
///
/// Exposes the token's decoded claims without the raw JWT bytes. The
/// encoded JWT is held internally for future validation operations.
///
/// See ADR-016 and spec section 10 (UCAN).
#[napi(object)]
pub struct NapiUcanTokenData {
    /// Unique token identifier (derived from the UCAN nonce).
    pub token_id: String,
    /// Issuer DID — the entity that created and signed this token.
    pub issuer: String,
    /// Audience DID — the entity this token is delegated to.
    pub audience: String,
    /// Capability URIs granted by this token
    /// (e.g., `"scp:ctx:abc123/messages:write"`).
    pub capabilities: Vec<String>,
    /// Expiry timestamp (seconds since Unix epoch). `null` = no expiry.
    pub expires_at: Option<f64>,
}

// ---------------------------------------------------------------------------
// NapiUcanToken — opaque JS class for UCAN token handles
// ---------------------------------------------------------------------------

/// Opaque handle to a UCAN token.
///
/// Exposes token metadata without leaking raw JWT or signature bytes.
///
/// # JS usage
///
/// ```js
/// const token = await ucanMint(ctx, memberDid, ["scp:ctx:.../messages:write"]);
/// console.log(token.tokenId);        // "ucan-..."
/// console.log(token.capabilities);   // ["scp:ctx:.../messages:write"]
/// ```
#[napi]
pub struct NapiUcanToken {
    /// Stable token metadata.
    pub(crate) data: NapiUcanTokenData,
    /// Raw encoded JWT string — retained for validation and delegation operations.
    encoded: String,
    /// `NapiBridgeInstance` id that minted this token — used for handle
    /// affinity checks at every FFI entry point. Mismatches are rejected
    /// with `SCP-PERM-3030`.
    pub(crate) instance_id: u64,
}

#[napi]
impl NapiUcanToken {
    /// Returns the token's metadata record.
    #[napi(getter, js_name = "tokenData")]
    #[must_use]
    pub fn token_data(&self) -> NapiUcanTokenData {
        NapiUcanTokenData {
            token_id: self.data.token_id.clone(),
            issuer: self.data.issuer.clone(),
            audience: self.data.audience.clone(),
            capabilities: self.data.capabilities.clone(),
            expires_at: self.data.expires_at,
        }
    }

    /// Returns the token's unique ID.
    ///
    /// Exposed as both `id` (matching the SDK `UcanToken` interface) and
    /// `tokenId` (legacy alias for backward compatibility).
    #[napi(getter)]
    #[must_use]
    pub fn id(&self) -> String {
        self.data.token_id.clone()
    }

    /// Returns the token's unique ID (legacy alias for `id`).
    #[napi(getter, js_name = "tokenId")]
    #[must_use]
    pub fn token_id(&self) -> String {
        self.data.token_id.clone()
    }

    /// Returns the encoded JWT string for this token.
    ///
    /// Needed for delegation (`delegateUcan` passes `originalToken.encoded`)
    /// and revocation operations.
    #[napi(getter)]
    #[must_use]
    pub fn encoded(&self) -> String {
        self.encoded.clone()
    }

    /// Returns the issuer DID.
    #[napi(getter)]
    #[must_use]
    pub fn issuer(&self) -> String {
        self.data.issuer.clone()
    }

    /// Returns the audience DID.
    #[napi(getter)]
    #[must_use]
    pub fn audience(&self) -> String {
        self.data.audience.clone()
    }

    /// Returns the list of capability URIs granted by this token.
    #[napi(getter)]
    #[must_use]
    pub fn capabilities(&self) -> Vec<String> {
        self.data.capabilities.clone()
    }

    /// Returns the expiry timestamp (seconds since epoch) or `null` if no expiry.
    #[napi(getter, js_name = "expiresAt")]
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // napi getter cannot be const
    pub fn expires_at(&self) -> Option<f64> {
        self.data.expires_at
    }
}

impl Drop for NapiUcanToken {
    fn drop(&mut self) {
        decrement_handle_count();
    }
}

// ---------------------------------------------------------------------------
// NapiCapabilityValidation
// ---------------------------------------------------------------------------

/// Structured, side-effect-free result of evaluating a UCAN token.
///
/// Mirrors scp-core's [`CapabilityValidation`] — the diagnostic counterpart to
/// the fail-closed `ucan_validate` gate. Each boolean reflects whether the
/// corresponding pipeline stage ran and passed; the pipeline short-circuits, so
/// a field is `true` only if its stage AND every prior stage passed.
///
/// napi-rs auto-camelCases the field names for JavaScript: `tokens_valid` →
/// `tokensValid`, etc.
///
/// Unlike `ucan_validate`, evaluation records NO state (the nonce is probed
/// read-only, never recorded). See ADR-016.
//
// Six per-stage outcome flags are the mandated public shape of this diagnostic,
// mirroring scp-core's `CapabilityValidation`. They are pure data — not
// behavior-selecting flags — so the `struct_excessive_bools` suggestion (a
// state machine / two-variant enums) would obscure the API and break the flat
// named-field shape the SDK trust signal consumes.
#[allow(clippy::struct_excessive_bools)]
#[napi(object)]
#[derive(Debug, Clone, Copy)]
pub struct NapiCapabilityValidation {
    /// Step 1: the token parsed and its header/attestation set validated.
    pub tokens_valid: bool,
    /// Steps 2-7: signature, delegation chain, root issuer, audience, key
    /// scope, capability grant-match, Category-A enforcement, and attenuation
    /// all passed (whole-chain).
    pub signatures_valid: bool,
    /// Step 8: every granted capability is within the context's ceiling.
    pub within_ceiling: bool,
    /// Step 9: nonce format, freshness, and uniqueness passed (probed
    /// read-only — the nonce is NOT recorded).
    pub nonce_valid: bool,
    /// Step 10: the token's revocation CID is not on the revocation list.
    pub not_revoked: bool,
    /// Step 11: `exp`/`nbf` time bounds are valid (within clock-skew tolerance).
    pub time_bounds_valid: bool,
}

impl From<CapabilityValidation> for NapiCapabilityValidation {
    fn from(v: CapabilityValidation) -> Self {
        Self {
            tokens_valid: v.tokens_valid,
            signatures_valid: v.signatures_valid,
            within_ceiling: v.within_ceiling,
            nonce_valid: v.nonce_valid,
            not_revoked: v.not_revoked,
            time_bounds_valid: v.time_bounds_valid,
        }
    }
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of [`ucan_validate`].
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String/Option<Vec>
pub(crate) async fn ucan_validate_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    token: String,
    capability: String,
    presenting_agent_did: String,
    proof_tokens: Option<Vec<String>>,
) -> napi::Result<()> {
    crate::napi_check_handle!(&bi.core, handle);
    validate_ucan_token(&token).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    validate_capability_uri(&capability).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    // FAIL CLOSED (no silent security default): `presenting_agent_did` is a
    // REQUIRED parameter — never defaulted to the token's own `aud` (which would
    // make the step-5 audience check tautological and inflate trust). Validated as
    // a pure input before any state lookup / token parse — mirrors
    // `ucan_evaluate_on`. `validate_did` rejects an empty/whitespace value.
    let agent_did = presenting_agent_did.trim();
    validate_did(agent_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    // Ensure the context's persistent runtime state (RevocationList, NonceTracker)
    // is registered. Uses the same registry as event_log and ucan_revoke.
    crate::runtime::ensure_registered(bi, handle).map_err(napi::Error::from)?;

    // Step 1: Parse the UCAN token using scp-core's parser.
    let parsed_token = parse_ucan(&token).map_err(ScpNapiError::from)?;

    // Parse the required capability URI.
    let required_cap: CapabilityUri =
        capability
            .parse()
            .map_err(|e: CoreUcanError| ScpNapiError::Permission {
                message: format!("invalid capability URI '{capability}': {e}"),
                code: codes::PERM_3001.to_owned(),
            })?;

    // Build proof resolver from optional proof tokens.
    // Uses compute_cid (SHA-256 of encoded JWT) — NOT compute_revocation_cid
    // (which hashes the parsed payload). The CID must match what is stored in
    // the proof chain's `prf` field references.
    let proof_resolver = build_proof_resolver(proof_tokens.as_deref())?;

    let context_id = handle.context_id();

    // Run validation inside with_context to use persistent revocation list
    // and nonce tracker from the runtime registry. This ensures:
    // - Revoked tokens are rejected across calls (persistent RevocationList).
    // - Replayed nonces are detected across calls (persistent NonceTracker).
    crate::runtime::with_context(bi, &context_id, |rt| {
        // Build validation context using persistent runtime state.
        // Use production DID resolver when available (#311), fallback to string-only.
        let production_resolver = crate::runtime::did_resolver(bi);
        let did_resolver =
            DispatchDidResolver::new(production_resolver.map(std::convert::AsRef::as_ref));
        let revocation_checker = BridgeRevocationChecker {
            revocation_list: &rt.core.revocation_list,
        };
        let mut nonce_adapter = BridgeNonceTracker {
            inner: &mut rt.core.nonce_tracker,
        };

        let mut ctx = ValidationContext {
            did_resolver: &did_resolver,
            nonce_tracker: &mut nonce_adapter,
            revocation_checker: &revocation_checker,
            proof_resolver: &proof_resolver,
            ceiling: &rt.core.ceiling_strings,
            context_creator_did: &rt.core.creator_did,
            presenting_agent_did: agent_did,
            clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
            clock: &scp_clock::SystemClock,
        };

        // Execute the full 11-step validation pipeline.
        validate_ucan(&parsed_token, &required_cap, &mut ctx).map_err(ScpNapiError::from)?;

        Ok(())
    })
    .map_err(napi::Error::from)?;

    Ok(())
}

/// Per-bridge-instance implementation of [`ucan_evaluate`].
///
/// Diagnostic, **side-effect-free** counterpart to [`ucan_validate_on`]: runs
/// the same 11-step ADR-016 pipeline via `evaluate_ucan` but returns a
/// structured [`NapiCapabilityValidation`] instead of throwing, and never
/// records the token's nonce (read-only probe).
///
/// `capability` is OPTIONAL: `None` (or empty) evaluates the token's intrinsic
/// validity with no invoked-capability grant-match challenge (mirroring
/// `evaluate_ucan(None, ..)`); `Some` additionally requires the token grants it.
///
/// FAIL CLOSED: `presenting_agent_did` is a REQUIRED (non-optional) parameter (no
/// silent security default). It is never defaulted to the token's own `aud` —
/// defaulting would make the step-5 audience check a tautological self-check
/// (`aud == aud`) that does NOT bind the token to any external subject, so a token
/// addressed to someone else would report `signatures_valid` (trust inflation). An
/// empty/whitespace value is rejected by `validate_did`. The SDK trust path always
/// passes the subject; raw diagnostic callers must pass an explicit presenting agent.
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String/Option<Vec>
pub(crate) async fn ucan_evaluate_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    token: String,
    capability: Option<String>,
    presenting_agent_did: String,
    proof_tokens: Option<Vec<String>>,
) -> napi::Result<NapiCapabilityValidation> {
    crate::napi_check_handle!(&bi.core, handle);
    validate_ucan_token(&token).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    // An empty/whitespace-only capability means "no challenge" — treat it as
    // absent rather than validating it as a (non-empty) URI.
    let capability = capability.filter(|c| !c.trim().is_empty());
    if let Some(ref cap) = capability {
        validate_capability_uri(cap).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    }

    // FAIL CLOSED (no silent security default): `presenting_agent_did` is a
    // REQUIRED parameter — never defaulted to the token's own `aud` (which would
    // make the step-5 audience check tautological and inflate trust). Validated as
    // a pure input before any state lookup. `validate_did` rejects an
    // empty/whitespace value.
    let agent_did = presenting_agent_did.trim();
    validate_did(agent_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    // Ensure the context's persistent runtime state (RevocationList, NonceTracker)
    // is registered. Uses the same registry as event_log and ucan_revoke.
    crate::runtime::ensure_registered(bi, handle).map_err(napi::Error::from)?;

    // Step 1: Parse the UCAN token using scp-core's parser.
    let parsed_token = parse_ucan(&token).map_err(ScpNapiError::from)?;

    // Parse the optional required capability URI. `None` => intrinsic-validity
    // diagnostic (no invoked-capability grant-match challenge).
    let required_cap: Option<CapabilityUri> = capability
        .as_deref()
        .map(|cap| {
            cap.parse::<CapabilityUri>()
                .map_err(|e: CoreUcanError| ScpNapiError::Permission {
                    message: format!("invalid capability URI '{cap}': {e}"),
                    code: codes::PERM_3001.to_owned(),
                })
        })
        .transpose()?;

    // Build proof resolver from optional proof tokens.
    let proof_resolver = build_proof_resolver(proof_tokens.as_deref())?;

    let context_id = handle.context_id();

    // evaluate_ucan takes `&ValidationContext` and is read-only — it probes the
    // nonce tracker via check_replay but never records, so the persistent
    // NonceTracker is not mutated.
    let result = crate::runtime::with_context(bi, &context_id, |rt| {
        let production_resolver = crate::runtime::did_resolver(bi);
        let did_resolver =
            DispatchDidResolver::new(production_resolver.map(std::convert::AsRef::as_ref));
        let revocation_checker = BridgeRevocationChecker {
            revocation_list: &rt.core.revocation_list,
        };
        let mut nonce_adapter = BridgeNonceTracker {
            inner: &mut rt.core.nonce_tracker,
        };

        let ctx = ValidationContext {
            did_resolver: &did_resolver,
            nonce_tracker: &mut nonce_adapter,
            revocation_checker: &revocation_checker,
            proof_resolver: &proof_resolver,
            ceiling: &rt.core.ceiling_strings,
            context_creator_did: &rt.core.creator_did,
            presenting_agent_did: agent_did,
            clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
            clock: &scp_clock::SystemClock,
        };

        Ok(evaluate_ucan(&parsed_token, required_cap.as_ref(), &ctx))
    })
    .map_err(napi::Error::from)?;

    Ok(NapiCapabilityValidation::from(result))
}

/// Per-bridge-instance implementation of [`ucan_mint`].
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String/Vec/Option<Vec>
#[allow(clippy::unused_async)] // napi requires async for Promise return type
pub(crate) async fn ucan_mint_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    member_did: String,
    capabilities: Vec<String>,
    proofs: Option<Vec<String>>,
) -> napi::Result<NapiUcanToken> {
    crate::napi_check_handle!(&bi.core, handle);
    validate_did(&member_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    if let Some(ref tokens) = proofs {
        for t in tokens {
            validate_ucan_token(t).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
        }
    }

    // Extract key custody and signing key from the context handle. Available
    // for any context whose creator identity retains custody — in-memory OR a
    // production callback custody (`identityCreateWithCustody`).
    let custody = handle.in_memory_custody.as_ref().ok_or_else(|| {
        napi::Error::from(ScpNapiError::Identity {
            message: "UCAN minting requires retained signing custody — the context creator \
                  identity has no retained custody (it was externally loaded)"
                .to_owned(),
            code: codes::IDENT_1017.to_owned(),
        })
    })?;
    let signing_key = handle.signing_key.ok_or_else(|| {
        napi::Error::from(ScpNapiError::Identity {
            message: "UCAN minting requires retained signing custody — the context creator \
                  identity has no active signing key"
                .to_owned(),
            code: codes::IDENT_1017.to_owned(),
        })
    })?;

    let creator_did = handle.creator_did();
    let context_id = handle.context_id();

    // Get ceiling from the context handle for mint-time enforcement (#339).
    // Empty ceiling means the user passed `[]` — apply the default ceiling
    // instead of `None` (which would mean unlimited). See #1419.
    let ceiling_strings: std::collections::HashSet<String> = handle.ceiling().into_iter().collect();
    let ceiling = Some(if ceiling_strings.is_empty() {
        scp_core::context::roles::default_ceiling().to_ucan_string_set()
    } else {
        ceiling_strings
    });

    let params = MintParams {
        issuer_did: &creator_did,
        issuer_key: &signing_key,
        audience_did: &member_did,
        context_id: &context_id,
        capabilities: &capabilities,
        lifetime_secs: 3600, // 1 hour default
        not_before: None,
        proofs: proofs.unwrap_or_default(),
        facts: None,
        key_scope: None,
        signing_key_id: None,
        ceiling,
    };

    // Sign the token by delegating to the retained `KeyCustody` via scp-core.
    // napi-rs async functions already run on the tokio runtime, so we can
    // await directly without spawning a separate task.
    let token = mint_ucan(&params, custody.as_ref(), &scp_clock::SystemClock)
        .await
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Permission {
                message: format!("UCAN minting failed: {e}"),
                code: scp_ffi_common::ucan_errors::ucan_error_code(&e).to_owned(),
            })
        })?;

    let data = NapiUcanTokenData {
        token_id: token.payload.nnc.clone(),
        issuer: token.payload.iss.clone(),
        audience: token.payload.aud.clone(),
        capabilities: token.payload.att.iter().map(|a| a.with.clone()).collect(),
        #[allow(clippy::cast_precision_loss)] // Unix timestamp seconds fit in f64 mantissa for centuries.
        expires_at: Some(token.payload.exp as f64),
    };

    increment_handle_count();
    Ok(NapiUcanToken {
        data,
        encoded: token.encoded,
        instance_id: bi.instance_id(),
    })
}

/// Per-bridge-instance implementation of [`ucan_delegate`].
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String/Vec
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
pub(crate) async fn ucan_delegate_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    delegator_did: String,
    delegatee_did: String,
    parent_token: String,
    capabilities: Vec<String>,
) -> napi::Result<NapiUcanToken> {
    crate::napi_check_handle!(&bi.core, handle);
    validate_did(&delegator_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    validate_did(&delegatee_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    validate_ucan_token(&parent_token).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    for cap in &capabilities {
        validate_capability_uri(cap).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    }

    use scp_core::crypto::ucan::Attenuation;
    use scp_core::crypto::ucan::mint::{DelegateParams, delegate_ucan};
    use scp_core::crypto::ucan::validate::parse_ucan;

    // Delegation is available for any context whose delegator identity retains
    // custody — in-memory OR a production callback custody
    // (`identityCreateWithCustody`). The delegator's key is looked up from the
    // identity registry below (NOT the context creator's key).
    let context_id = handle.context_id();

    // Parse the parent token.
    let parsed_parent = parse_ucan(&parent_token).map_err(ScpNapiError::from)?;

    // Defense-in-depth: verify delegator DID matches parent token's audience.
    // The delegator must be the audience of the parent token to form a valid
    // delegation chain (iss/aud linkage). scp-core enforces this too, but
    // catching it at the bridge level provides clearer error messages.
    if delegator_did != parsed_parent.payload.aud {
        return Err(napi::Error::from(ScpNapiError::Permission {
            message: format!(
                "delegator DID '{}' does not match parent token audience '{}'",
                delegator_did, parsed_parent.payload.aud
            ),
            code: codes::PERM_3001.to_owned(),
        }));
    }

    // Build attenuated capabilities from the capability URI strings.
    // Use CapabilityUri::from_str for validated parsing instead of ad-hoc
    // string splitting.
    let attenuations: Vec<Attenuation> = capabilities
        .iter()
        .map(|cap| {
            let cap_uri_str = if cap.starts_with("scp:ctx:") {
                cap.clone()
            } else {
                format!("scp:ctx:{context_id}/{cap}")
            };
            let parsed: CapabilityUri =
                cap_uri_str
                    .parse()
                    .map_err(|e: CoreUcanError| ScpNapiError::Permission {
                        message: format!("invalid capability URI '{cap_uri_str}': {e}"),
                        code: scp_ffi_common::ucan_errors::ucan_error_code(&e).to_owned(),
                    })?;
            Ok(Attenuation {
                with: cap_uri_str,
                can: parsed.action().to_owned(),
            })
        })
        .collect::<Result<Vec<_>, ScpNapiError>>()
        .map_err(napi::Error::from)?;

    // Get ceiling from the context handle for delegation-time enforcement (#339).
    // Empty ceiling means the user passed `[]` — apply the default ceiling
    // instead of `None` (which would mean unlimited). See #1419.
    let ceiling_strings: std::collections::HashSet<String> = handle.ceiling().into_iter().collect();
    let ceiling = Some(if ceiling_strings.is_empty() {
        scp_core::context::roles::default_ceiling().to_ucan_string_set()
    } else {
        ceiling_strings
    });

    // Look up the DELEGATOR's identity from the global identity registry.
    // This is critical: the delegation must be signed with the delegator's
    // Ed25519 key, NOT the context creator's key. The previous code used
    // `handle.signing_key` (the context creator's key), which would produce
    // tokens with invalid signatures when the delegator is not the creator.
    let token = crate::runtime::with_identity(bi, &delegator_did, |entry| {
        let params = DelegateParams {
            parent_token: &parsed_parent,
            delegator_did: &delegator_did,
            delegator_key: &entry.identity.active_signing_key,
            delegatee_did: &delegatee_did,
            attenuated_capabilities: &attenuations,
            lifetime_secs: 3600,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: ceiling.clone(),
        };

        // napi-rs async functions run on the tokio runtime, but
        // `with_identity` holds a DashMap ref guard (sync). Use
        // `tokio::task::block_in_place` to avoid nesting block_on calls.
        let rt_handle = tokio::runtime::Handle::current();
        let result = tokio::task::block_in_place(|| {
            rt_handle.block_on(async {
                delegate_ucan(&params, entry.custody.as_ref(), &scp_clock::SystemClock).await
            })
        });

        result.map_err(ScpNapiError::from)
    })
    .map_err(napi::Error::from)?;

    let data = NapiUcanTokenData {
        token_id: token.payload.nnc.clone(),
        issuer: token.payload.iss.clone(),
        audience: token.payload.aud.clone(),
        capabilities: token.payload.att.iter().map(|a| a.with.clone()).collect(),
        #[allow(clippy::cast_precision_loss)]
        expires_at: Some(token.payload.exp as f64),
    };

    increment_handle_count();
    Ok(NapiUcanToken {
        data,
        encoded: token.encoded,
        instance_id: bi.instance_id(),
    })
}

/// Per-bridge-instance implementation of [`ucan_revoke`].
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub(crate) async fn ucan_revoke_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    token: String,
    revoker_did: String,
) -> napi::Result<()> {
    crate::napi_check_handle!(&bi.core, handle);
    validate_ucan_token(&token).map_err(ScpNapiError::from)?;
    validate_did(&revoker_did).map_err(ScpNapiError::from)?;

    crate::runtime::ensure_registered(bi, handle).map_err(napi::Error::from)?;

    // Parse the token to extract the issuer DID for authorization.
    let parsed = parse_ucan(&token).map_err(ScpNapiError::from)?;

    let context_id = handle.context_id();
    crate::runtime::with_context(bi, &context_id, |rt| {
        use std::cell::RefCell;

        let authorizer = BridgeRevocationAuthorizer {
            issuer_did: parsed.payload.iss.clone(),
            creator_did: rt.core.creator_did.clone(),
        };
        let distributor = BridgeRevocationDistributor;
        let event_log_cell = RefCell::new(&mut rt.core.event_log);
        let event_logger = BridgeRevocationEventLogger {
            event_log: &event_log_cell,
        };

        scp_core::crypto::ucan::revoke::revoke_ucan(
            &mut rt.core.revocation_list,
            &token,
            &revoker_did,
            &authorizer,
            &distributor,
            &event_logger,
        )
        .map_err(ScpNapiError::from)?;

        Ok(())
    })
    .map_err(napi::Error::from)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Builds a [`BridgeProofResolver`] from optional encoded proof token strings.
///
/// Parses each proof token and indexes it by its CID (SHA-256 of the encoded
/// JWT via `compute_cid`) so that the delegation chain verifier can resolve
/// proof references. Uses `compute_cid` (not `compute_revocation_cid`) because
/// the CID must match what was stored in the UCAN `prf` field during minting.
pub(crate) fn build_proof_resolver(
    proof_tokens: Option<&[String]>,
) -> Result<BridgeProofResolver, ScpNapiError> {
    let mut proofs = HashMap::new();

    if let Some(tokens) = proof_tokens {
        for encoded in tokens {
            let token = parse_ucan(encoded).map_err(ScpNapiError::from)?;
            // Use compute_cid (SHA-256 of encoded JWT string) — NOT
            // compute_revocation_cid (SHA-256 of JSON-serialized payload).
            let cid = scp_core::crypto::ucan::mint::compute_cid(&token);
            proofs.insert(cid, token);
        }
    }

    Ok(BridgeProofResolver { proofs })
}

/// Convenience alias that mirrors the `PyO3` bridge naming convention.
///
/// Builds a [`BridgeProofResolver`] from optional encoded proof token strings.
pub(crate) fn build_proof_resolver_from_tokens(
    proof_tokens: Option<&[String]>,
) -> Result<BridgeProofResolver, ScpNapiError> {
    build_proof_resolver(proof_tokens)
}

/// Encodes a byte slice as lowercase hexadecimal.
#[cfg(test)]
fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::iter_on_single_items,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use scp_clock::Clock;
    use scp_core::crypto::ucan::UcanToken;
    use scp_core::crypto::ucan::validate::{
        DidResolver, NonceTracker as NonceTrackerTrait, ProofResolver, RevocationChecker,
    };
    use scp_ffi_common::BridgeDidResolver;

    // -----------------------------------------------------------------------
    // BridgeDidResolver
    // -----------------------------------------------------------------------

    #[test]
    fn bridge_did_resolver_resolves_did_dht() {
        let pk_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let did = format!("did:dht:z{}", zbase32::encode(&pk_bytes));

        let resolver = BridgeDidResolver;
        let result = resolver.resolve_public_key(&did).unwrap();
        assert_eq!(result, pk_bytes);
    }

    #[test]
    fn bridge_did_resolver_resolves_did_key_hex() {
        let pk_bytes: [u8; 32] = [0xab; 32];
        let hex = encode_hex(&pk_bytes);
        let did = format!("did:key:{hex}");

        let resolver = BridgeDidResolver;
        let result = resolver.resolve_public_key(&did).unwrap();
        assert_eq!(result, pk_bytes);
    }

    #[test]
    fn bridge_did_resolver_rejects_unknown_method() {
        let resolver = BridgeDidResolver;
        let result = resolver.resolve_public_key("did:web:example.com");
        assert!(result.is_err());
    }

    #[test]
    fn bridge_did_resolver_rejects_invalid_zbase32() {
        let resolver = BridgeDidResolver;
        let result = resolver.resolve_public_key("did:dht:zinvalid");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // BridgeRevocationChecker
    // -----------------------------------------------------------------------

    #[test]
    fn bridge_revocation_checker_not_revoked() {
        let list = scp_core::crypto::ucan::revoke::RevocationList::new("ctx-test".to_owned());
        let checker = BridgeRevocationChecker {
            revocation_list: &list,
        };
        assert!(!checker.is_revoked("some-cid"));
    }

    #[test]
    fn bridge_revocation_checker_detects_revoked() {
        let mut list = scp_core::crypto::ucan::revoke::RevocationList::new("ctx-test".to_owned());
        list.revoke("revoked-cid".to_owned());
        let checker = BridgeRevocationChecker {
            revocation_list: &list,
        };
        assert!(checker.is_revoked("revoked-cid"));
    }

    // -----------------------------------------------------------------------
    // BridgeProofResolver
    // -----------------------------------------------------------------------

    #[test]
    fn bridge_proof_resolver_returns_stored_token() {
        let token = UcanToken {
            header: scp_core::crypto::ucan::UcanHeader::new(),
            payload: scp_core::crypto::ucan::UcanPayload {
                iss: "did:dht:zCreator".to_owned(),
                aud: "did:dht:zMember".to_owned(),
                exp: 1_700_000_000,
                nbf: None,
                nnc: "0-aabbccdd11223344aabbccdd11223344".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![0u8; 64],
            encoded: "h.p.s".to_owned(),
        };

        let cid = "test-cid".to_owned();
        let resolver = BridgeProofResolver {
            proofs: [(cid.clone(), token.clone())].into_iter().collect(),
        };

        let result = resolver.resolve_proof(&cid).unwrap();
        assert_eq!(result.payload.iss, token.payload.iss);
    }

    #[test]
    fn bridge_proof_resolver_rejects_missing_cid() {
        let resolver = BridgeProofResolver {
            proofs: HashMap::new(),
        };
        let result = resolver.resolve_proof("nonexistent-cid");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // BridgeNonceTracker adapter
    // -----------------------------------------------------------------------

    #[test]
    fn bridge_nonce_tracker_delegates_to_inner() {
        use scp_clock::SystemClock;

        let mut tracker =
            scp_core::crypto::ucan::nonce::NonceTracker::new("ctx-test".to_owned(), SystemClock);

        let now_millis = scp_clock::SystemClock.now_millis();
        let now_secs = now_millis / 1000;
        let nonce = format!("{now_millis}-aabbccdd11223344aabbccdd11223344");
        let expiry = now_secs + 3600;

        let mut adapter = BridgeNonceTracker {
            inner: &mut tracker,
        };

        // First check should succeed.
        assert!(adapter.check_and_record(&nonce, expiry).is_ok());

        // Replay should fail.
        let result = adapter.check_and_record(&nonce, expiry);
        assert!(matches!(result, Err(CoreUcanError::NonceReused(_))));
    }

    // -----------------------------------------------------------------------
    // build_proof_resolver
    // -----------------------------------------------------------------------

    #[test]
    fn build_proof_resolver_handles_empty_input() {
        let resolver = build_proof_resolver(None).unwrap();
        assert!(resolver.proofs.is_empty());
    }

    #[test]
    fn build_proof_resolver_handles_empty_slice() {
        let tokens: Vec<String> = vec![];
        let resolver = build_proof_resolver(Some(&tokens)).unwrap();
        assert!(resolver.proofs.is_empty());
    }

    // -----------------------------------------------------------------------
    // hex encode/decode roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn hex_roundtrip() {
        let bytes = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let hex_str = encode_hex(&bytes);
        let decoded = hex::decode(&hex_str).unwrap();
        assert_eq!(decoded, bytes.to_vec());
    }

    #[test]
    fn hex_decode_rejects_odd_length() {
        let result = hex::decode("abc");
        assert!(result.is_err());
    }

    #[test]
    fn hex_decode_rejects_non_hex() {
        let result = hex::decode("gggg");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Persistent revocation list via runtime registry
    // -----------------------------------------------------------------------

    #[test]
    fn revocation_persists_across_with_context_calls() {
        use crate::runtime;

        let bi = runtime::NapiBridgeInstance::new_napi();
        // Use a unique context ID per test to avoid cross-test interference.
        let context_id = format!("ctx-revoke-persist-{}", uuid::Uuid::new_v4());

        // Manually register a context in the runtime registry.
        runtime::register_test_context(&bi, &context_id, "did:dht:zCreator");

        // First call: revoke a CID.
        runtime::with_context(&bi, &context_id, |rt| {
            rt.core.revocation_list.revoke("revoked-cid-123".to_owned());
            Ok(())
        })
        .unwrap();

        // Second call: verify the revocation persists.
        let is_revoked = runtime::with_context(&bi, &context_id, |rt| {
            Ok(rt.core.revocation_list.is_revoked("revoked-cid-123"))
        })
        .unwrap();

        assert!(
            is_revoked,
            "revoked token must be detected across with_context calls"
        );

        // Unrevoked CIDs should not be affected.
        let other_revoked = runtime::with_context(&bi, &context_id, |rt| {
            Ok(rt.core.revocation_list.is_revoked("other-cid-456"))
        })
        .unwrap();

        assert!(
            !other_revoked,
            "non-revoked token must not be reported as revoked"
        );
    }

    // -----------------------------------------------------------------------
    // Persistent nonce tracker via runtime registry
    // -----------------------------------------------------------------------

    #[test]
    fn nonce_replay_detected_across_with_context_calls() {
        use crate::runtime;

        let bi = runtime::NapiBridgeInstance::new_napi();
        let context_id = format!("ctx-nonce-persist-{}", uuid::Uuid::new_v4());
        runtime::register_test_context(&bi, &context_id, "did:dht:zCreator");

        let now_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let now_secs = (now_millis / 1000) as u64;
        let nonce = format!("{now_millis}-aabbccdd11223344aabbccdd11223344");
        let expiry = now_secs + 3600;

        // First call: record the nonce — should succeed.
        let first_result = runtime::with_context(&bi, &context_id, |rt| {
            rt.core
                .nonce_tracker
                .check_and_record(&nonce, expiry)
                .map_err(|e| crate::error::ScpNapiError::Permission {
                    message: format!("nonce check failed: {e}"),
                    code: codes::PERM_3001.to_owned(),
                })
        });
        assert!(first_result.is_ok(), "first nonce use should succeed");

        // Second call: replay the same nonce — should fail.
        let second_result = runtime::with_context(&bi, &context_id, |rt| {
            rt.core
                .nonce_tracker
                .check_and_record(&nonce, expiry)
                .map_err(|e| crate::error::ScpNapiError::Permission {
                    message: format!("nonce check failed: {e}"),
                    code: codes::PERM_3001.to_owned(),
                })
        });
        assert!(
            second_result.is_err(),
            "replayed nonce must be rejected on second call"
        );

        // A different nonce should succeed.
        let different_nonce = format!("{}-bbccddee22334455bbccddee22334455", now_millis + 1);
        let third_result = runtime::with_context(&bi, &context_id, |rt| {
            rt.core
                .nonce_tracker
                .check_and_record(&different_nonce, expiry)
                .map_err(|e| crate::error::ScpNapiError::Permission {
                    message: format!("nonce check failed: {e}"),
                    code: codes::PERM_3001.to_owned(),
                })
        });
        assert!(third_result.is_ok(), "unique nonce should be accepted");
    }

    // -----------------------------------------------------------------------
    // ucan_revoke wires to persistent state
    // -----------------------------------------------------------------------

    #[test]
    fn revoke_then_check_revocation_list() {
        use crate::runtime;
        use std::cell::RefCell;

        let bi = runtime::NapiBridgeInstance::new_napi();
        let context_id = format!("ctx-revoke-wire-{}", uuid::Uuid::new_v4());
        let creator_did = "did:dht:zCreator";
        runtime::register_test_context(&bi, &context_id, creator_did);

        // Build a deterministic token string for revocation.
        let test_token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsInVjdiI6IjAuMTAuMCJ9.\
            eyJpc3MiOiJkaWQ6ZGh0OnpDcmVhdG9yIiwiYXVkIjoiZGlkOmRodDp6TWVtYmVyIiwiZXhwIjo5OTk5OTk5OTk5LCJubmMiOiIxNjk5OTk5MDAwMDAwLWFhYmJjY2RkMTEyMjMzNDQiLCJhdHQiOltdLCJwcmYiOltdfQ.\
            dGVzdC1zaWduYXR1cmU";

        // Parse outside the closure so the issuer DID can be moved.
        let parsed = parse_ucan(test_token).unwrap();
        let issuer_did = parsed.payload.iss;

        // Simulate the full revocation pipeline via revoke_ucan.
        runtime::with_context(&bi, &context_id, |rt| {
            let authorizer = BridgeRevocationAuthorizer {
                issuer_did: issuer_did.clone(),
                creator_did: rt.core.creator_did.clone(),
            };
            let distributor = BridgeRevocationDistributor;
            let event_log_cell = RefCell::new(&mut rt.core.event_log);
            let event_logger = BridgeRevocationEventLogger {
                event_log: &event_log_cell,
            };

            scp_core::crypto::ucan::revoke::revoke_ucan(
                &mut rt.core.revocation_list,
                test_token,
                creator_did,
                &authorizer,
                &distributor,
                &event_logger,
            )
            .unwrap();

            Ok(())
        })
        .unwrap();

        // Verify revocation is detected by the checker.
        let token_cid = scp_core::crypto::ucan::revoke::compute_revocation_cid(test_token);
        let checker_says_revoked = runtime::with_context(&bi, &context_id, |rt| {
            let checker = BridgeRevocationChecker {
                revocation_list: &rt.core.revocation_list,
            };
            Ok(checker.is_revoked(&token_cid))
        })
        .unwrap();

        assert!(
            checker_says_revoked,
            "token revoked via revoke_ucan must be detected by ucan_validate's revocation checker"
        );

        // Verify a TokenRevoked event was appended to the event log.
        let event_count = runtime::with_context(&bi, &context_id, |rt| {
            Ok(scp_event_log::tree::event_count(&rt.core.event_log))
        })
        .unwrap();
        assert!(
            event_count > 0,
            "event log must contain at least one event after revocation"
        );
    }

    #[test]
    fn revoke_rejects_unauthorized_revoker() {
        use crate::runtime;
        use std::cell::RefCell;

        let bi = runtime::NapiBridgeInstance::new_napi();
        let context_id = format!("ctx-revoke-unauth-{}", uuid::Uuid::new_v4());
        let creator_did = "did:dht:zCreator";
        runtime::register_test_context(&bi, &context_id, creator_did);

        let test_token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsInVjdiI6IjAuMTAuMCJ9.\
            eyJpc3MiOiJkaWQ6ZGh0OnpDcmVhdG9yIiwiYXVkIjoiZGlkOmRodDp6TWVtYmVyIiwiZXhwIjo5OTk5OTk5OTk5LCJubmMiOiIxNjk5OTk5MDAwMDAwLWFhYmJjY2RkMTEyMjMzNDQiLCJhdHQiOltdLCJwcmYiOltdfQ.\
            dGVzdC1zaWduYXR1cmU";

        // Parse outside the closure so the issuer DID can be moved.
        let parsed = parse_ucan(test_token).unwrap();
        let issuer_did = parsed.payload.iss;

        // Attempt revocation by an unauthorized DID (not issuer, not creator).
        let result = runtime::with_context(&bi, &context_id, |rt| {
            let authorizer = BridgeRevocationAuthorizer {
                issuer_did: issuer_did.clone(),
                creator_did: rt.core.creator_did.clone(),
            };
            let distributor = BridgeRevocationDistributor;
            let event_log_cell = RefCell::new(&mut rt.core.event_log);
            let event_logger = BridgeRevocationEventLogger {
                event_log: &event_log_cell,
            };

            let result = scp_core::crypto::ucan::revoke::revoke_ucan(
                &mut rt.core.revocation_list,
                test_token,
                "did:dht:zUnauthorized",
                &authorizer,
                &distributor,
                &event_logger,
            );
            Ok(result)
        })
        .unwrap();

        assert!(
            result.is_err(),
            "revocation by unauthorized DID must be rejected"
        );
    }

    // -----------------------------------------------------------------------
    // Identity registry — delegator != creator regression test (#771)
    //
    // The previous code used `handle.signing_key` (the context creator's key)
    // for all UCAN delegation signing. When the delegator is different from the
    // context creator, this produced tokens with invalid signatures. The fix
    // (in this PR) looks up the delegator's identity via BridgeInstance identity registry.
    // This test verifies the registry correctly distinguishes different DIDs.
    // -----------------------------------------------------------------------

    #[cfg(feature = "allow_in_memory_custody")]
    #[test]
    fn identity_registry_returns_correct_identity_for_different_dids() {
        use std::sync::Arc;

        use crate::identity::OpaqueInMemoryKeyCustody;
        use crate::runtime;
        use scp_identity::DidMethod;
        use scp_platform::testing::InMemoryKeyCustody;

        // Create two distinct identities (creator and delegator).
        let custody_a = Arc::new(crate::custody::NapiKeyCustody::InMemory(
            OpaqueInMemoryKeyCustody(InMemoryKeyCustody::new()),
        ));
        let custody_b = Arc::new(crate::custody::NapiKeyCustody::InMemory(
            OpaqueInMemoryKeyCustody(InMemoryKeyCustody::new()),
        ));
        let pre_rotation_custody_a =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let pre_rotation_custody_b =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());

        let dht_a = scp_identity::DidDht::new();
        let dht_b = scp_identity::DidDht::new();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (identity_a, doc_a, pre_rotation_handle_a) = rt
            .block_on(dht_a.create(&*custody_a, pre_rotation_custody_a.as_ref()))
            .unwrap();
        let (identity_b, doc_b, pre_rotation_handle_b) = rt
            .block_on(dht_b.create(&*custody_b, pre_rotation_custody_b.as_ref()))
            .unwrap();

        // Verify different DIDs were generated.
        assert_ne!(
            identity_a.did, identity_b.did,
            "two identities must have different DIDs"
        );

        let did_a = identity_a.did.clone();
        let did_b = identity_b.did.clone();

        let bi = runtime::NapiBridgeInstance::new_napi();

        // Register both in the global identity registry.
        runtime::register_identity(
            &bi,
            &did_a,
            runtime::NapiIdentityEntry {
                identity: identity_a,
                custody: Arc::clone(&custody_a),
                document: doc_a,
                identity_link_attestations: Vec::new(),
                pre_rotation_handle: pre_rotation_handle_a,
                pre_rotation_custody: pre_rotation_custody_a,
            },
        );
        runtime::register_identity(
            &bi,
            &did_b,
            runtime::NapiIdentityEntry {
                identity: identity_b,
                custody: Arc::clone(&custody_b),
                document: doc_b,
                identity_link_attestations: Vec::new(),
                pre_rotation_handle: pre_rotation_handle_b,
                pre_rotation_custody: pre_rotation_custody_b,
            },
        );

        // Look up identity A — must get A's DID, not B's.
        let looked_up_did_a =
            runtime::with_identity(&bi, &did_a, |entry| Ok(entry.identity.did.clone())).unwrap();
        assert_eq!(
            looked_up_did_a, did_a,
            "registry must return identity A's DID for A's DID"
        );

        // Look up identity B — must get B's DID, not A's.
        let looked_up_did_b =
            runtime::with_identity(&bi, &did_b, |entry| Ok(entry.identity.did.clone())).unwrap();
        assert_eq!(
            looked_up_did_b, did_b,
            "registry must return identity B's DID for B's DID"
        );

        // Cross-check: the custody Arc pointers must be different,
        // confirming different key material is returned for each DID.
        let custody_ptr_a =
            runtime::with_identity(
                &bi,
                &did_a,
                |entry| Ok(Arc::as_ptr(&entry.custody) as usize),
            )
            .unwrap();
        let custody_ptr_b =
            runtime::with_identity(
                &bi,
                &did_b,
                |entry| Ok(Arc::as_ptr(&entry.custody) as usize),
            )
            .unwrap();
        assert_ne!(
            custody_ptr_a, custody_ptr_b,
            "different identities in the registry must have different custody providers — \
             a mismatch here indicates the delegator != creator bug class"
        );

        // Clean up: remove both identities from the registry.
        runtime::remove_identity(&bi, &did_a);
        runtime::remove_identity(&bi, &did_b);
    }

    #[cfg(feature = "allow_in_memory_custody")]
    #[test]
    fn remove_identity_cleans_up_registry() {
        use std::sync::Arc;

        use crate::identity::OpaqueInMemoryKeyCustody;
        use crate::runtime;
        use scp_identity::DidMethod;
        use scp_platform::testing::InMemoryKeyCustody;

        let custody = Arc::new(crate::custody::NapiKeyCustody::InMemory(
            OpaqueInMemoryKeyCustody(InMemoryKeyCustody::new()),
        ));
        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let dht = scp_identity::DidDht::new();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (identity, doc, pre_rotation_handle) = rt
            .block_on(dht.create(&*custody, pre_rotation_custody.as_ref()))
            .unwrap();
        let did = identity.did.clone();

        let bi = runtime::NapiBridgeInstance::new_napi();

        // Register the identity.
        runtime::register_identity(
            &bi,
            &did,
            runtime::NapiIdentityEntry {
                identity,
                custody: Arc::clone(&custody),
                document: doc,
                identity_link_attestations: Vec::new(),
                pre_rotation_handle,
                pre_rotation_custody,
            },
        );

        // Verify it is present.
        assert!(
            runtime::with_identity(&bi, &did, |_| Ok(())).is_ok(),
            "identity should be found after registration"
        );

        // Remove it.
        runtime::remove_identity(&bi, &did);

        // Verify it is gone.
        assert!(
            runtime::with_identity(&bi, &did, |_| Ok(())).is_err(),
            "identity should not be found after remove_identity"
        );
    }

    #[cfg(feature = "allow_in_memory_custody")]
    #[test]
    fn remove_identity_if_present_returns_correct_bool() {
        use std::sync::Arc;

        use crate::identity::OpaqueInMemoryKeyCustody;
        use crate::runtime;
        use scp_identity::DidMethod;
        use scp_platform::testing::InMemoryKeyCustody;

        let custody = Arc::new(crate::custody::NapiKeyCustody::InMemory(
            OpaqueInMemoryKeyCustody(InMemoryKeyCustody::new()),
        ));
        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let dht = scp_identity::DidDht::new();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (identity, doc, pre_rotation_handle) = rt
            .block_on(dht.create(&*custody, pre_rotation_custody.as_ref()))
            .unwrap();
        let did = identity.did.clone();

        let bi = runtime::NapiBridgeInstance::new_napi();

        // Register the identity.
        runtime::register_identity(
            &bi,
            &did,
            runtime::NapiIdentityEntry {
                identity,
                custody: Arc::clone(&custody),
                document: doc,
                identity_link_attestations: Vec::new(),
                pre_rotation_handle,
                pre_rotation_custody,
            },
        );

        // First removal should return true.
        assert!(
            runtime::remove_identity_if_present(&bi, &did),
            "remove_identity_if_present should return true for present identity"
        );

        // Second removal should return false.
        assert!(
            !runtime::remove_identity_if_present(&bi, &did),
            "remove_identity_if_present should return false for absent identity"
        );
    }

    // -----------------------------------------------------------------------
    // Missing-signing-custody → SCP-IDENT-1017
    //
    // A context handle whose creator identity retains no custody (externally
    // loaded: `in_memory_custody` / `signing_key` both `None`) must reject UCAN
    // mint with the canonical missing-signing-custody code, not an overloaded
    // permission/nonce code.
    //
    // NOTE: the NAPI `ucan_delegate_on` path resolves the delegator key from
    // the identity registry (`with_identity`), so its no-custody condition
    // surfaces as the registry-miss SCP-IDENT-1001, not IDENT-1017. The
    // delegate→IDENT-1017 routing is a UniFFI-shaped concern (handle-borne
    // custody) and is covered by the UniFFI inline test.
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ucan_mint_without_retained_custody_returns_ident_1017() {
        let bi = std::sync::Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        let handle = crate::context::NapiContextHandle::test_active_on(
            &bi,
            "ctx-no-custody-mint".to_owned(),
            "did:dht:z6MkCreatorNoCustody".to_owned(),
        );

        let result = ucan_mint_on(
            &bi,
            &handle,
            "did:dht:z6MkMember".to_owned(),
            vec!["messages:write".to_owned()],
            None,
        )
        .await;

        let Err(err) = result else {
            panic!("mint without retained custody must fail")
        };
        let reason = err.reason.clone();
        assert!(
            reason.contains("SCP-IDENT-1017"),
            "expected SCP-IDENT-1017, got: {reason}"
        );
    }

    /// SECURITY (Finding 2). `ucan_evaluate` MUST reject an empty/whitespace
    /// `presenting_agent_did` rather than defaulting to the token's own `aud`.
    /// Omission is impossible — the parameter is a required non-`Option` `String`,
    /// so the type system enforces presence. The check is a pure-input gate before
    /// context lookup / token parse, so a dummy token suffices.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ucan_evaluate_rejects_empty_presenting_agent_did() {
        let bi = std::sync::Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        let handle = crate::context::NapiContextHandle::test_active_on(
            &bi,
            "ctx-eval-fail-closed".to_owned(),
            "did:dht:z6MkCreator".to_owned(),
        );

        let empty = ucan_evaluate_on(
            &bi,
            &handle,
            "header.payload.sig".to_owned(),
            None,
            "   ".to_owned(),
            None,
        )
        .await;
        assert!(
            empty.is_err(),
            "ucan_evaluate must fail closed when presenting_agent_did is empty"
        );
    }

    /// SECURITY (symmetric gate hardening). The ENFORCING `ucan_validate` gate
    /// MUST reject an empty/whitespace `presenting_agent_did` rather than
    /// defaulting to the token's own `aud`. Omission is impossible — the parameter
    /// is a required non-`Option` `String`, so the type system enforces presence.
    /// Pure-input gate before context lookup / token parse, so a dummy token
    /// suffices.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ucan_validate_rejects_empty_presenting_agent_did() {
        let bi = std::sync::Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        let handle = crate::context::NapiContextHandle::test_active_on(
            &bi,
            "ctx-validate-fail-closed".to_owned(),
            "did:dht:z6MkCreator".to_owned(),
        );

        let empty = ucan_validate_on(
            &bi,
            &handle,
            "header.payload.sig".to_owned(),
            "messages:write".to_owned(),
            "   ".to_owned(),
            None,
        )
        .await;
        assert!(
            empty.is_err(),
            "ucan_validate must fail closed when presenting_agent_did is empty"
        );
    }
}
