//! napi-rs bridge for UCAN operations.
//!
//! Exposes UCAN token management to JavaScript:
//!
//! - [`ucan_validate`] — Validate a UCAN token for a required capability.
//! - [`ucan_mint`] — Mint a new UCAN token for a context member with real
//!   Ed25519 signing via `InMemoryKeyCustody`.
//! - [`ucan_revoke`] — Revoke a UCAN token.
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
#[cfg(feature = "allow_in_memory_custody")]
use scp_core::crypto::ucan::mint::{MintParams, mint_ucan};
use scp_ffi_common::validate::{validate_capability_uri, validate_did, validate_ucan_token};

use scp_core::crypto::ucan::UcanError as CoreUcanError;

use scp_core::crypto::ucan::capability::CapabilityUri;
use scp_core::crypto::ucan::validate::{
    DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, ValidationContext, parse_ucan, validate_ucan,
};

use scp_ffi_common::{
    BridgeNonceTracker, BridgeProofResolver, BridgeRevocationAuthorizer, BridgeRevocationChecker,
    BridgeRevocationDistributor, BridgeRevocationEventLogger, DispatchDidResolver,
};

use crate::context::NapiContextHandle;
use crate::decrement_handle_count;
use crate::error::ScpNapiError;
#[cfg(feature = "allow_in_memory_custody")]
use crate::increment_handle_count;
use crate::runtime::{NapiBridgeInstance, default_bridge_instance};

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

    /// Returns the id of the `SCP` instance that minted this token, as a
    /// base-10 string (u64 serialized as string to survive JS number limits).
    #[napi(getter, js_name = "instanceId")]
    #[must_use]
    pub fn instance_id_js(&self) -> String {
        self.instance_id.to_string()
    }
}

impl Drop for NapiUcanToken {
    fn drop(&mut self) {
        decrement_handle_count();
    }
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Validates a UCAN token for a required capability.
///
/// Delegates to `scp_core::crypto::ucan::validate::validate_ucan` for
/// complete UCAN validation including Ed25519 signature verification, proof
/// chain traversal, delegation depth enforcement, audience/issuer chain
/// validation, scope attenuation, nonce uniqueness, revocation checking,
/// and expiry verification.
///
/// # Arguments
///
/// * `handle` — The context the token is presented in.
/// * `token` — The encoded UCAN token string (JWT format).
/// * `capability` — The required capability URI
///   (e.g., `"scp:ctx:abc123/messages:write"`).
/// * `presenting_agent_did` — Optional. The DID of the agent presenting
///   the token. If not provided, the token's `aud` field is used (the
///   presenting agent is assumed to be the token's audience).
/// * `proof_tokens` — Optional. List of encoded parent UCAN token strings
///   for delegation chain verification. Required when validating delegated
///   tokens with non-empty proof chains.
///
/// # Errors
///
/// - Rejects with `SCP-PERM-3001` if validation fails (malformed token,
///   invalid signature, expired, insufficient capabilities, revoked,
///   broken delegation chain).
#[napi]
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String/Option<Vec>
pub async fn ucan_validate(
    handle: &NapiContextHandle,
    token: String,
    capability: String,
    presenting_agent_did: Option<String>,
    proof_tokens: Option<Vec<String>>,
) -> napi::Result<()> {
    let bi = default_bridge_instance()?;
    ucan_validate_on(
        &bi,
        handle,
        token,
        capability,
        presenting_agent_did,
        proof_tokens,
    )
    .await
}

/// Per-bridge-instance implementation of [`ucan_validate`].
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String/Option<Vec>
pub(crate) async fn ucan_validate_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    token: String,
    capability: String,
    presenting_agent_did: Option<String>,
    proof_tokens: Option<Vec<String>>,
) -> napi::Result<()> {
    crate::napi_check_handle!(&bi.core, handle);
    validate_ucan_token(&token).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    validate_capability_uri(&capability).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

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

    // Determine the presenting agent DID: explicit parameter or token audience.
    let agent_did = presenting_agent_did
        .as_deref()
        .unwrap_or(&parsed_token.payload.aud);

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
            clock: &scp_primitives::SystemClock,
        };

        // Execute the full 11-step validation pipeline.
        validate_ucan(&parsed_token, &required_cap, &mut ctx).map_err(ScpNapiError::from)?;

        Ok(())
    })
    .map_err(napi::Error::from)?;

    Ok(())
}

/// Mints a new UCAN token for a context member with real Ed25519 signing.
///
/// Uses the context creator's `InMemoryKeyCustody` and active signing key
/// (retained on the context handle during `context_create`) to produce a
/// properly signed UCAN token via `scp_core::crypto::ucan::mint::mint_ucan`.
///
/// # Arguments
///
/// * `handle` — The context to mint the token for (must have key custody
///   from `context_create` with an `in_memory` identity).
/// * `member_did` — The DID of the member receiving the token.
/// * `capabilities` — List of capability strings to grant (e.g.,
///   `"messages:write"`). Scoped to the context automatically.
///
/// # Returns
///
/// A `Promise<NapiUcanToken>` with the minted token's metadata and a real
/// Ed25519 signature.
///
/// # Errors
///
/// - Rejects with `SCP-VALID-7000` if `member_did` fails [`validate_did`]
///   (empty, malformed `did:{method}:{id}` format, or control characters).
/// - Rejects with `SCP-PERM-3023` if the context does not have key custody
///   (created from an `identity_load` handle without key material).
/// - Rejects with `SCP-PERM-3023` if signing or token construction fails.
#[napi]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String/Vec/Option<Vec>
#[allow(clippy::unused_async)] // napi requires async for Promise return type
pub async fn ucan_mint(
    handle: &NapiContextHandle,
    member_did: String,
    capabilities: Vec<String>,
    proofs: Option<Vec<String>>,
) -> napi::Result<NapiUcanToken> {
    let bi = default_bridge_instance()?;
    ucan_mint_on(&bi, handle, member_did, capabilities, proofs).await
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

    // In-memory custody is only available when `allow_in_memory_custody` is enabled.
    #[cfg(not(feature = "allow_in_memory_custody"))]
    {
        let _ = (bi, &handle, &member_did, &capabilities, &proofs);
        Err(napi::Error::from(ScpNapiError::Permission {
            message: "UCAN minting requires key custody -- the in_memory custody path                       is not available in this build. Enable allow_in_memory_custody                       for dev/desktop use.".to_owned(),
            code: codes::PERM_3023.to_owned(),
        }))
    }

    #[cfg(feature = "allow_in_memory_custody")]
    {
        // Extract key custody and signing key from the context handle.
        let custody = handle.in_memory_custody.as_ref().ok_or_else(|| {
            napi::Error::from(ScpNapiError::Permission {
                message: "UCAN minting requires key custody — create the context with an \
                      in_memory identity (identity_create(\"in_memory\"))"
                    .to_owned(),
                code: codes::PERM_3023.to_owned(),
            })
        })?;
        let signing_key = handle.signing_key.ok_or_else(|| {
            napi::Error::from(ScpNapiError::Permission {
                message: "UCAN minting requires a signing key — the context creator identity \
                      must have an active signing key"
                    .to_owned(),
                code: codes::PERM_3023.to_owned(),
            })
        })?;

        let creator_did = handle.creator_did();
        let context_id = handle.context_id();

        // Get ceiling from the context handle for mint-time enforcement (#339).
        // Empty ceiling means the user passed `[]` — apply the default ceiling
        // instead of `None` (which would mean unlimited). See #1419.
        let ceiling_strings: std::collections::HashSet<String> =
            handle.ceiling().into_iter().collect();
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

        // Sign the token using the real InMemoryKeyCustody via scp-core.
        // napi-rs async functions already run on the tokio runtime, so we
        // can await directly without spawning a separate task.
        let token = mint_ucan(&params, &custody.0, &scp_primitives::SystemClock)
            .await
            .map_err(|e| {
                napi::Error::from(ScpNapiError::Permission {
                    message: format!("UCAN minting failed: {e}"),
                    code: codes::PERM_3023.to_owned(),
                })
            })?;

        let data = NapiUcanTokenData {
        token_id: token.payload.nnc.clone(),
        issuer: token.payload.iss.clone(),
        audience: token.payload.aud.clone(),
        capabilities: token
            .payload
            .att
            .iter()
            .map(|a| a.with.clone())
            .collect(),
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
}

/// Delegates a UCAN token to another member.
///
/// Creates a delegated UCAN from an existing parent token, signed with the
/// delegator's Ed25519 key via the retained `InMemoryKeyCustody`.
/// Delegation enforces attenuation (capabilities can only narrow, never widen).
///
/// # Arguments
///
/// * `handle` — The context the token belongs to.
/// * `delegator_did` — The DID of the entity delegating (must match parent
///   token's audience).
/// * `delegatee_did` — The DID of the entity receiving the delegation.
/// * `parent_token` — The encoded parent UCAN token (JWT format).
/// * `capabilities` — List of capability URI strings to delegate (must be
///   subset of parent's capabilities).
///
/// # Returns
///
/// A `Promise<NapiUcanToken>` with the delegated token's metadata.
///
/// # Errors
///
/// - Rejects with `SCP-VALID-7000` if `delegator_did` or `delegatee_did`
///   fails [`validate_did`] (empty, malformed `did:{method}:{id}` format,
///   or control characters).
/// - Rejects with `SCP-VALID-7000` if `parent_token` fails
///   [`validate_ucan_token`] (empty, too long, or control characters).
/// - Rejects with `SCP-VALID-7000` if any capability URI fails
///   [`validate_capability_uri`] (empty, too long, or control characters).
/// - Rejects with `SCP-PERM-3023` if the context does not have key custody.
/// - Rejects with `SCP-PERM-3023` if delegation fails.
///
/// See ADR-016 criterion 4.
#[napi]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String/Vec
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
pub async fn ucan_delegate(
    handle: &NapiContextHandle,
    delegator_did: String,
    delegatee_did: String,
    parent_token: String,
    capabilities: Vec<String>,
) -> napi::Result<NapiUcanToken> {
    let bi = default_bridge_instance()?;
    ucan_delegate_on(
        &bi,
        handle,
        delegator_did,
        delegatee_did,
        parent_token,
        capabilities,
    )
    .await
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

    #[cfg(not(feature = "allow_in_memory_custody"))]
    {
        let _ = (
            bi,
            &handle,
            &delegator_did,
            &delegatee_did,
            &parent_token,
            &capabilities,
        );
        Err(napi::Error::from(ScpNapiError::Permission {
            message: "UCAN delegation requires key custody -- the in_memory custody path \
                       is not available in this build. Enable allow_in_memory_custody \
                       for dev/desktop use."
                .to_owned(),
            code: codes::PERM_3023.to_owned(),
        }))
    }

    #[cfg(feature = "allow_in_memory_custody")]
    {
        use scp_core::crypto::ucan::Attenuation;
        use scp_core::crypto::ucan::mint::{DelegateParams, delegate_ucan};
        use scp_core::crypto::ucan::validate::parse_ucan;

        let context_id = handle.context_id();

        // Parse the parent token.
        let parsed_parent = parse_ucan(&parent_token).map_err(ScpNapiError::from)?;

        // Defense-in-depth: verify delegator DID matches parent token's audience.
        // The delegator must be the audience of the parent token to form a valid
        // delegation chain (iss/aud linkage). scp-core enforces this too, but
        // catching it at the bridge level provides clearer error messages and
        // matches the WASM bridge's defense-in-depth check.
        if delegator_did != parsed_parent.payload.aud {
            return Err(napi::Error::from(ScpNapiError::Permission {
                message: format!(
                    "delegator DID '{}' does not match parent token audience '{}'",
                    delegator_did, parsed_parent.payload.aud
                ),
                code: codes::PERM_3023.to_owned(),
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
                            code: codes::PERM_3023.to_owned(),
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
        let ceiling_strings: std::collections::HashSet<String> =
            handle.ceiling().into_iter().collect();
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
                    delegate_ucan(&params, &entry.custody.0, &scp_primitives::SystemClock).await
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
}

/// Revokes a UCAN token using the full revocation pipeline.
///
/// Performs the complete UCAN revocation flow from ADR-016:
///
/// 1. **Authorization** -- Verifies the revoker is the token's issuer or the
///    context creator.
/// 2. **Local revocation** -- Adds the token CID to the context's
///    `RevocationList` (fail-closed via `RevocationPending` state).
/// 3. **Distribution** -- Logs the revocation for transport-layer broadcast.
/// 4. **Event logging** -- Appends a `TokenRevoked` event to the context's
///    Merkle event log.
///
/// # Arguments
///
/// * `handle` — The context the token belongs to.
/// * `token` — The full encoded JWT string of the token to revoke.
/// * `revoker_did` — The DID of the entity requesting the revocation. Must
///   be either the token's issuer or the context creator.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2023` if the context runtime is not initialized.
/// - Rejects with `SCP-PERM-3001` if the token cannot be parsed.
/// - Rejects with `SCP-PERM-3001` if the revoker is unauthorized.
///
/// Closes #499.
#[napi]
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn ucan_revoke(
    handle: &NapiContextHandle,
    token: String,
    revoker_did: String,
) -> napi::Result<()> {
    let bi = default_bridge_instance()?;
    ucan_revoke_on(&bi, handle, token, revoker_did).await
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
    use scp_core::crypto::ucan::UcanToken;
    use scp_core::crypto::ucan::validate::{
        DidResolver, NonceTracker as NonceTrackerTrait, ProofResolver, RevocationChecker,
    };
    use scp_ffi_common::BridgeDidResolver;
    use scp_primitives::Clock;

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
        use scp_identity::cache::SystemClock;

        let mut tracker =
            scp_core::crypto::ucan::nonce::NonceTracker::new("ctx-test".to_owned(), SystemClock);

        let now_millis = scp_primitives::SystemClock.now_millis();
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

        let bi = runtime::default_bridge_instance().expect("default bridge");
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

        let bi = runtime::default_bridge_instance().expect("default bridge");
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

        let bi = runtime::default_bridge_instance().expect("default bridge");
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

        let bi = runtime::default_bridge_instance().expect("default bridge");
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
        let custody_a = Arc::new(OpaqueInMemoryKeyCustody(InMemoryKeyCustody::new()));
        let custody_b = Arc::new(OpaqueInMemoryKeyCustody(InMemoryKeyCustody::new()));

        let dht_a = scp_identity::DidDht::new();
        let dht_b = scp_identity::DidDht::new();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (identity_a, doc_a) = rt.block_on(dht_a.create(&custody_a.0)).unwrap();
        let (identity_b, doc_b) = rt.block_on(dht_b.create(&custody_b.0)).unwrap();

        // Verify different DIDs were generated.
        assert_ne!(
            identity_a.did, identity_b.did,
            "two identities must have different DIDs"
        );

        let did_a = identity_a.did.clone();
        let did_b = identity_b.did.clone();

        let bi = runtime::default_bridge_instance().expect("default bridge");

        // Register both in the global identity registry.
        runtime::register_identity(
            &bi,
            &did_a,
            runtime::NapiIdentityEntry {
                identity: identity_a,
                custody: Arc::clone(&custody_a),
                document: doc_a,
                identity_link_attestations: Vec::new(),
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

        let custody = Arc::new(OpaqueInMemoryKeyCustody(InMemoryKeyCustody::new()));
        let dht = scp_identity::DidDht::new();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (identity, doc) = rt.block_on(dht.create(&custody.0)).unwrap();
        let did = identity.did.clone();

        let bi = runtime::default_bridge_instance().expect("default bridge");

        // Register the identity.
        runtime::register_identity(
            &bi,
            &did,
            runtime::NapiIdentityEntry {
                identity,
                custody: Arc::clone(&custody),
                document: doc,
                identity_link_attestations: Vec::new(),
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

        let custody = Arc::new(OpaqueInMemoryKeyCustody(InMemoryKeyCustody::new()));
        let dht = scp_identity::DidDht::new();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (identity, doc) = rt.block_on(dht.create(&custody.0)).unwrap();
        let did = identity.did.clone();

        let bi = runtime::default_bridge_instance().expect("default bridge");

        // Register the identity.
        runtime::register_identity(
            &bi,
            &did,
            runtime::NapiIdentityEntry {
                identity,
                custody: Arc::clone(&custody),
                document: doc,
                identity_link_attestations: Vec::new(),
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
}
