//! napi-rs bridge for UCAN operations.
//!
//! Exposes UCAN token management to JavaScript:
//!
//! - [`ucan_validate`] — Validate a UCAN token using the full 11-step
//!   ADR-016 pipeline with Ed25519 signature verification.
//! - [`ucan_mint`] — Mint a new UCAN token for a context member.
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

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use napi_derive::napi;
use scp_core::crypto::ucan::{Attenuation, UcanHeader, UcanPayload};

use scp_core::crypto::ucan::UcanError as CoreUcanError;
use scp_core::crypto::ucan::UcanToken;
use scp_core::crypto::ucan::capability::CapabilityUri;
use scp_core::crypto::ucan::revoke::compute_revocation_cid;
use scp_core::crypto::ucan::validate::{
    DidResolver, NonceTracker as NonceTrackerTrait, ProofResolver, RevocationChecker,
    ValidationContext, parse_ucan, validate_ucan,
};

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
// Bridge trait implementations for scp-core validation pipeline
// ---------------------------------------------------------------------------

/// Bridge [`DidResolver`] that extracts Ed25519 public keys from DID strings.
///
/// Supports:
/// - `did:dht:z{z-base-32-encoded-pubkey}` — production format.
/// - `did:key:{hex-encoded-pubkey}` — testing format.
///
/// This resolver operates in-memory with no network calls. `did:dht:` DIDs
/// encode the public key directly in the DID string using z-base-32, so
/// resolution is a simple decode operation.
struct BridgeDidResolver;

impl DidResolver for BridgeDidResolver {
    fn resolve_public_key(&self, did: &str) -> Result<[u8; 32], CoreUcanError> {
        if let Some(suffix) = did.strip_prefix("did:dht:z") {
            let decoded = zbase32::decode(suffix).map_err(|_| {
                CoreUcanError::MalformedToken(format!("z-base-32 decode failed for DID: {did}"))
            })?;
            let bytes: [u8; 32] = decoded.try_into().map_err(|v: Vec<u8>| {
                CoreUcanError::MalformedToken(format!(
                    "DID public key must be 32 bytes, got {}",
                    v.len()
                ))
            })?;
            return Ok(bytes);
        }

        if let Some(hex_str) = did.strip_prefix("did:key:") {
            let bytes = decode_hex(hex_str).map_err(|e| {
                CoreUcanError::MalformedToken(format!("hex decode failed for did:key DID: {e}"))
            })?;
            let pk: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
                CoreUcanError::MalformedToken(format!(
                    "DID public key must be 32 bytes, got {}",
                    v.len()
                ))
            })?;
            return Ok(pk);
        }

        Err(CoreUcanError::MalformedToken(format!(
            "unsupported DID method: {did} (expected did:dht: or did:key:)"
        )))
    }
}

/// Bridge [`RevocationChecker`] that wraps the context's [`RevocationList`].
///
/// Holds a reference to the revocation list from the [`ContextRuntime`] and
/// delegates the `is_revoked` check. Uses the content-hash CID format from
/// `scp_core::crypto::ucan::revoke::compute_revocation_cid`.
struct BridgeRevocationChecker<'a> {
    revocation_list: &'a scp_core::crypto::ucan::revoke::RevocationList,
}

impl RevocationChecker for BridgeRevocationChecker<'_> {
    fn is_revoked(&self, token_cid: &str) -> bool {
        self.revocation_list.is_revoked(token_cid)
    }
}

/// Bridge [`ProofResolver`] backed by an in-memory `HashMap`.
///
/// Stores parent UCAN tokens by their CID for delegation chain traversal.
/// The caller can supply proof tokens alongside the token being validated.
struct BridgeProofResolver {
    proofs: HashMap<String, UcanToken>,
}

impl ProofResolver for BridgeProofResolver {
    fn resolve_proof(&self, cid: &str) -> Result<UcanToken, CoreUcanError> {
        self.proofs.get(cid).cloned().ok_or_else(|| {
            CoreUcanError::DelegationChainBroken(format!("proof CID not found: {cid}"))
        })
    }
}

/// Adapter that implements the `validate::NonceTracker` trait for
/// `nonce::NonceTracker<C>`.
///
/// The `nonce::NonceTracker` struct and `validate::NonceTracker` trait have
/// the same `check_and_record` method signature but are separate types. This
/// adapter bridges the two by wrapping a mutable reference to the struct.
struct BridgeNonceTracker<'a, C: scp_core::identity::cache::Clock> {
    inner: &'a mut scp_core::crypto::ucan::nonce::NonceTracker<C>,
}

impl<C: scp_core::identity::cache::Clock> NonceTrackerTrait for BridgeNonceTracker<'_, C> {
    fn check_and_record(&mut self, nonce: &str, token_expiry: u64) -> Result<(), CoreUcanError> {
        self.inner.check_and_record(nonce, token_expiry)
    }
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Validates a UCAN token using the full 11-step ADR-016 pipeline.
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
///
/// # Errors
///
/// - Rejects with `SCP-PERM-3001` if validation fails (malformed token,
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
    crate::runtime::ensure_registered(handle).map_err(napi::Error::from)?;

    let parsed_token = parse_ucan(&token).map_err(ScpNapiError::from)?;

    let required_cap: CapabilityUri =
        capability
            .parse()
            .map_err(|e: CoreUcanError| ScpNapiError::Permission {
                message: format!("invalid capability URI '{capability}': {e}"),
                code: "SCP-PERM-3001".to_owned(),
            })?;

    let agent_did = parsed_token.payload.aud.clone();

    let proof_resolver = BridgeProofResolver {
        proofs: HashMap::new(),
    };

    let context_id = handle.context_id();
    crate::runtime::with_context(&context_id, |rt| {
        let did_resolver = BridgeDidResolver;
        let revocation_checker = BridgeRevocationChecker {
            revocation_list: &rt.revocation_list,
        };
        let mut nonce_adapter = BridgeNonceTracker {
            inner: &mut rt.nonce_tracker,
        };

        let mut ctx = ValidationContext {
            did_resolver: &did_resolver,
            nonce_tracker: &mut nonce_adapter,
            revocation_checker: &revocation_checker,
            proof_resolver: &proof_resolver,
            ceiling: &rt.ceiling_strings,
            context_creator_did: &rt.creator_did,
            presenting_agent_did: &agent_did,
        };

        validate_ucan(&parsed_token, &required_cap, &mut ctx).map_err(ScpNapiError::from)
    })
    .map_err(napi::Error::from)
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
/// Parses the full encoded JWT token, computes its content-hash CID, and
/// adds it to the context's revocation list. Revoked tokens are no longer
/// accepted by validation. In the full runtime, revocation is distributed
/// to all context members via MLS.
///
/// The token is identified by its content-hash CID (SHA-256 of the JSON-
/// serialized payload), matching the identifier used by scp-core's
/// `compute_revocation_cid`. This format is consistent with the CID
/// checked by the full validation pipeline in step 10.
///
/// # Arguments
///
/// * `handle` — The context the token belongs to.
/// * `token` — The full encoded UCAN token string (JWT format).
///
/// # Errors
///
/// - Rejects with `SCP-PERM-3001` if revocation fails (malformed token,
///   context not found).
#[napi]
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn ucan_revoke(handle: &NapiContextHandle, token: String) -> napi::Result<()> {
    crate::runtime::ensure_registered(handle).map_err(napi::Error::from)?;

    let parsed = parse_ucan(&token).map_err(ScpNapiError::from)?;

    let context_id = handle.context_id();
    crate::runtime::with_context(&context_id, |rt| {
        let token_cid = compute_revocation_cid(&parsed.payload);
        rt.revocation_list.revoke(token_cid);
        Ok(())
    })
    .map_err(napi::Error::from)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Encodes a byte slice as a lowercase hex string.
fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

/// Decodes a hex string to bytes.
fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err(format!("hex string has odd length: {}", hex.len()));
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte_str = &hex[i..i + 2];
        let byte =
            u8::from_str_radix(byte_str, 16).map_err(|e| format!("hex decode error: {e}"))?;
        bytes.push(byte);
    }
    Ok(bytes)
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

    #[test]
    fn bridge_nonce_tracker_delegates_to_inner() {
        use scp_core::identity::cache::SystemClock;

        let mut tracker =
            scp_core::crypto::ucan::nonce::NonceTracker::new("ctx-test".to_owned(), SystemClock);

        let now_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let now_secs = (now_millis / 1000) as u64;
        let nonce = format!("{now_millis}-aabbccdd11223344aabbccdd11223344");
        let expiry = now_secs + 3600;

        let mut adapter = BridgeNonceTracker {
            inner: &mut tracker,
        };

        assert!(adapter.check_and_record(&nonce, expiry).is_ok());

        let result = adapter.check_and_record(&nonce, expiry);
        assert!(matches!(result, Err(CoreUcanError::NonceReused(_))));
    }

    #[test]
    fn generate_nonce_produces_valid_format() {
        let nonce = generate_nonce().unwrap();
        let parts: Vec<&str> = nonce.splitn(2, '-').collect();
        assert_eq!(parts.len(), 2);
        assert!(parts[0].parse::<u128>().is_ok());
        assert_eq!(parts[1].len(), 32);
    }

    #[test]
    fn encode_hex_roundtrip() {
        let bytes = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let hex = encode_hex(&bytes);
        let decoded = decode_hex(&hex).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn decode_hex_rejects_odd_length() {
        let result = decode_hex("abc");
        assert!(result.is_err());
    }
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
