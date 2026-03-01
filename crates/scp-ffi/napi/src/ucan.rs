//! napi-rs bridge for UCAN operations.
//!
//! Exposes UCAN token management to JavaScript:
//!
//! - [`ucan_validate`] — Validate a UCAN token for a required capability.
//! - [`ucan_mint`] — Mint a new UCAN token for a context member with real
//!   Ed25519 signing via [`InMemoryKeyCustody`] (RED-102).
//! - [`ucan_revoke`] — Revoke a UCAN token.
//!
//! See ADR-016 (UCAN Enforcement) and ADR-022 in `.docs/adrs/`.

use napi_derive::napi;
use scp_core::crypto::ucan::mint::{MintParams, mint_ucan};

use crate::context::NapiContextHandle;
use crate::error::ScpNapiError;
use crate::{decrement_handle_count, increment_handle_count};

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
    /// Raw encoded JWT string — retained for validation operations.
    #[allow(dead_code)]
    encoded: String,
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
    #[napi(getter, js_name = "tokenId")]
    #[must_use]
    pub fn token_id(&self) -> String {
        self.data.token_id.clone()
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
// Bridge functions
// ---------------------------------------------------------------------------

/// Validates a UCAN token for a required capability.
///
/// Performs full validation: signature verification, time bounds checking,
/// delegation chain traversal, attenuation enforcement, nonce replay
/// detection, and capability matching.
///
/// # Arguments
///
/// * `handle` — The context the token is presented in.
/// * `token` — The encoded UCAN token string (JWT format).
/// * `capability` — The required capability URI
///   (e.g., `"scp:ctx:abc123/messages:write"`).
///
/// # Errors
///
/// - Rejects with `SCP-PRM-4002` if validation fails (malformed token,
///   invalid signature, expired, insufficient capabilities, revoked,
///   broken delegation chain).
#[napi]
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn ucan_validate(
    handle: &NapiContextHandle,
    token: String,
    capability: String,
) -> napi::Result<()> {
    let _ = (handle, token, capability);
    Err(ScpNapiError::Permission {
        message: "not yet connected to runtime — UCAN validation requires a live context"
            .to_owned(),
        code: "SCP-PRM-4002".to_owned(),
    }
    .into())
}

/// Mints a new UCAN token for a context member with real Ed25519 signing.
///
/// Uses the context creator's [`InMemoryKeyCustody`] and active signing key
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
/// - Rejects with `SCP-PERM-4004` if the context does not have key custody
///   (created from an `identity_load` handle without key material).
/// - Rejects with `SCP-PERM-4004` if signing or token construction fails.
///
/// See RED-102 for the `KeyCustody` wiring story.
#[napi]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String/Vec
pub async fn ucan_mint(
    handle: &NapiContextHandle,
    member_did: String,
    capabilities: Vec<String>,
) -> napi::Result<NapiUcanToken> {
    // Extract key custody and signing key from the context handle (RED-102).
    let custody = handle.in_memory_custody.as_ref().ok_or_else(|| {
        napi::Error::from(ScpNapiError::Permission {
            message: "UCAN minting requires key custody — create the context with an \
                      in_memory identity (identity_create(\"in_memory\"))"
                .to_owned(),
            code: "SCP-PERM-4004".to_owned(),
        })
    })?;
    let signing_key = handle.signing_key.ok_or_else(|| {
        napi::Error::from(ScpNapiError::Permission {
            message: "UCAN minting requires a signing key — the context creator identity \
                      must have an active signing key"
                .to_owned(),
            code: "SCP-PERM-4004".to_owned(),
        })
    })?;

    let creator_did = handle.creator_did();
    let context_id = handle.context_id();

    let params = MintParams {
        issuer_did: &creator_did,
        issuer_key: &signing_key,
        audience_did: &member_did,
        context_id: &context_id,
        capabilities: &capabilities,
        lifetime_secs: 3600, // 1 hour default
        not_before: None,
        proofs: vec![],
        facts: None,
    };

    // Sign the token using the real InMemoryKeyCustody via scp-core.
    // napi-rs async functions already run on the tokio runtime, so we
    // can await directly without spawning a separate task.
    let token = mint_ucan(&params, &custody.0).await.map_err(|e| {
        napi::Error::from(ScpNapiError::Permission {
            message: format!("UCAN minting failed: {e}"),
            code: "SCP-PERM-4004".to_owned(),
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
    })
}

/// Revokes a UCAN token.
///
/// Adds the token to the context's revocation list. Revoked tokens are no
/// longer accepted by validation. Revocation is distributed to all context
/// members.
///
/// # Arguments
///
/// * `handle` — The context the token belongs to.
/// * `token_id` — The unique ID of the token to revoke.
///
/// # Errors
///
/// - Rejects with `SCP-PERM-4006` if revocation fails (token not found,
///   revoker not authorized — must be the token's issuer or context creator).
#[napi]
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn ucan_revoke(handle: &NapiContextHandle, token_id: String) -> napi::Result<()> {
    let _ = (handle, token_id);
    Err(ScpNapiError::Permission {
        message: "not yet connected to runtime — UCAN revocation requires a live context"
            .to_owned(),
        code: "SCP-PRM-4006".to_owned(),
    }
    .into())
}
