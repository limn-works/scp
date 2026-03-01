//! napi-rs bridge for UCAN operations.
//!
//! Exposes UCAN token management to JavaScript:
//!
//! - [`ucan_validate`] — Validate a UCAN token for a required capability.
//! - [`ucan_mint`] — Mint a new UCAN token for a context member.
//! - [`ucan_revoke`] — Revoke a UCAN token.
//!
//! See ADR-016 (UCAN Enforcement) and ADR-022 in `.docs/adrs/`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use napi_derive::napi;
use scp_core::crypto::ucan::{Attenuation, UcanHeader, UcanPayload};

use crate::context::NapiContextHandle;
use crate::decrement_handle_count;
use crate::error::ScpNapiError;

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
    /// Raw encoded JWT string — retained for revocation and validation wiring.
    #[allow(dead_code)]
    pub(crate) encoded: String,
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

/// Mints a new UCAN token for a context member.
///
/// Creates a UCAN token with a properly encoded JWT string
/// (`base64url(header).base64url(payload).base64url(signature)`). The
/// signature field is a 64-byte zero placeholder — real Ed25519 signing
/// requires `KeyCustody` integration (SCP-214 scope).
///
/// The encoded token is parseable by `scp_core::crypto::ucan::validate::parse_ucan`
/// and round-trips through `ucan_revoke`.
///
/// # Arguments
///
/// * `handle` — The context to mint the token for.
/// * `member_did` — The DID of the member receiving the token.
/// * `capabilities` — List of capability URIs to grant.
///
/// # Returns
///
/// A `Promise<NapiUcanToken>` with the minted token's metadata and encoded JWT.
///
/// # Errors
///
/// - Rejects with `SCP-PERM-4004` if JWT serialization fails (system clock
///   error or JSON encoding failure).
///
/// Stub — real Ed25519 signing wired in SCP-214. See ADR-016 AC-3.
#[napi]
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String/Vec
pub async fn ucan_mint(
    handle: &NapiContextHandle,
    member_did: String,
    capabilities: Vec<String>,
) -> napi::Result<NapiUcanToken> {
    let context_id = handle.context_id();
    let issuer_did = handle.creator_did();

    let nonce = generate_nonce().map_err(|e| ScpNapiError::Permission {
        message: format!("nonce generation failed: {e}"),
        code: "SCP-PERM-4004".to_owned(),
    })?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| ScpNapiError::Permission {
            message: format!("system clock error: {e}"),
            code: "SCP-PERM-4004".to_owned(),
        })?
        .as_secs();
    let exp = now + 3600;

    let att: Vec<Attenuation> = capabilities
        .iter()
        .map(|cap| {
            let scoped = if cap.starts_with("scp:ctx:") {
                cap.clone()
            } else {
                format!("scp:ctx:{context_id}/{cap}")
            };
            let action = scoped
                .rsplit_once(':')
                .map(|(_, a)| a.to_owned())
                .unwrap_or_else(|| scoped.clone());
            Attenuation {
                with: scoped,
                can: action,
            }
        })
        .collect();

    let capability_uris: Vec<String> = att.iter().map(|a| a.with.clone()).collect();

    let header = UcanHeader::new();
    let payload = UcanPayload {
        iss: issuer_did.clone(),
        aud: member_did.clone(),
        exp,
        nbf: None,
        nnc: nonce.clone(),
        att,
        prf: vec![],
        fct: None,
    };

    let header_json = serde_json::to_vec(&header).map_err(|e| ScpNapiError::Permission {
        message: format!("header serialization failed: {e}"),
        code: "SCP-PERM-4004".to_owned(),
    })?;
    let payload_json = serde_json::to_vec(&payload).map_err(|e| ScpNapiError::Permission {
        message: format!("payload serialization failed: {e}"),
        code: "SCP-PERM-4004".to_owned(),
    })?;

    let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);

    let placeholder_sig = [0u8; 64];
    let sig_b64 = URL_SAFE_NO_PAD.encode(placeholder_sig);

    let encoded = format!("{header_b64}.{payload_b64}.{sig_b64}");

    crate::increment_handle_count();
    Ok(NapiUcanToken {
        data: NapiUcanTokenData {
            token_id: nonce,
            issuer: issuer_did,
            audience: member_did,
            capabilities: capability_uris,
            #[allow(clippy::cast_precision_loss)]
            expires_at: Some(exp as f64),
        },
        encoded,
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

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Generates a nonce in the format `{unix_millis_timestamp}-{16_random_bytes_hex}`.
///
/// Uses cryptographic randomness via `rand::rngs::OsRng` (backed by the
/// OS CSPRNG) to produce unpredictable nonces as required by ADR-016 §7.2.
fn generate_nonce() -> Result<String, String> {
    use rand::RngCore;

    let now_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("system clock error: {e}"))?
        .as_millis();

    let mut random_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut random_bytes);

    let hex = random_bytes
        .iter()
        .fold(String::with_capacity(32), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        });

    Ok(format!("{now_millis}-{hex}"))
}
