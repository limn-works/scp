//! napi-rs bridge for UCAN operations.
//!
//! Exposes UCAN token management to JavaScript:
//!
//! - [`ucan_validate`] — Validate a UCAN token for a required capability.
//! - [`ucan_mint`] — Mint a new UCAN token for a context member with real
//!   Ed25519 signing via [`InMemoryKeyCustody`] (RED-102).
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

use napi_derive::napi;
use scp_core::crypto::ucan::mint::{MintParams, mint_ucan};

use scp_core::crypto::ucan::UcanError as CoreUcanError;

use scp_core::crypto::ucan::capability::CapabilityUri;
use scp_core::crypto::ucan::validate::{
    DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, ValidationContext, parse_ucan, validate_ucan,
};

use scp_ffi_common::{
    BridgeDidResolver, BridgeNonceTracker, BridgeProofResolver, BridgeRevocationChecker,
};

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
    // Ensure the context's persistent runtime state (RevocationList, NonceTracker)
    // is registered. Uses the same registry as event_log and ucan_revoke.
    crate::runtime::ensure_registered(handle).map_err(napi::Error::from)?;

    // Step 1: Parse the UCAN token using scp-core's parser.
    let parsed_token = parse_ucan(&token).map_err(ScpNapiError::from)?;

    // Parse the required capability URI.
    let required_cap: CapabilityUri =
        capability
            .parse()
            .map_err(|e: CoreUcanError| ScpNapiError::Permission {
                message: format!("invalid capability URI '{capability}': {e}"),
                code: "SCP-PERM-3001".to_owned(),
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
    crate::runtime::with_context(&context_id, |rt| {
        // Build validation context using persistent runtime state.
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
            presenting_agent_did: agent_did,
            clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
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
/// Adds the token to the context's persistent revocation list. Revoked tokens
/// are rejected by subsequent `ucan_validate` calls on the same context.
///
/// # Arguments
///
/// * `handle` — The context the token belongs to.
/// * `token` — The full encoded JWT string of the token to revoke.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2023` if the context runtime is not initialized.
/// - Rejects with `SCP-PERM-3001` if the token cannot be parsed.
#[napi]
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn ucan_revoke(handle: &NapiContextHandle, token: String) -> napi::Result<()> {
    crate::runtime::ensure_registered(handle).map_err(napi::Error::from)?;

    // Parse the token to extract its payload for CID computation.
    let parsed = parse_ucan(&token).map_err(ScpNapiError::from)?;

    let context_id = handle.context_id();
    crate::runtime::with_context(&context_id, |rt| {
        // Compute the content-hash CID matching scp-core's format.
        let token_cid = scp_core::crypto::ucan::revoke::compute_revocation_cid(&parsed.payload);
        rt.revocation_list.revoke(token_cid);
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
fn build_proof_resolver(
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

        let now_millis = scp_core::time::now_millis().expect("clock unavailable in test");
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

        // Use a unique context ID per test to avoid cross-test interference.
        let context_id = format!("ctx-revoke-persist-{}", uuid::Uuid::new_v4());

        // Manually register a context in the runtime registry.
        runtime::register_test_context(&context_id, "did:dht:zCreator");

        // First call: revoke a CID.
        runtime::with_context(&context_id, |rt| {
            rt.revocation_list.revoke("revoked-cid-123".to_owned());
            Ok(())
        })
        .unwrap();

        // Second call: verify the revocation persists.
        let is_revoked = runtime::with_context(&context_id, |rt| {
            Ok(rt.revocation_list.is_revoked("revoked-cid-123"))
        })
        .unwrap();

        assert!(
            is_revoked,
            "revoked token must be detected across with_context calls"
        );

        // Unrevoked CIDs should not be affected.
        let other_revoked = runtime::with_context(&context_id, |rt| {
            Ok(rt.revocation_list.is_revoked("other-cid-456"))
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

        let context_id = format!("ctx-nonce-persist-{}", uuid::Uuid::new_v4());
        runtime::register_test_context(&context_id, "did:dht:zCreator");

        let now_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let now_secs = (now_millis / 1000) as u64;
        let nonce = format!("{now_millis}-aabbccdd11223344aabbccdd11223344");
        let expiry = now_secs + 3600;

        // First call: record the nonce — should succeed.
        let first_result = runtime::with_context(&context_id, |rt| {
            rt.nonce_tracker
                .check_and_record(&nonce, expiry)
                .map_err(|e| crate::error::ScpNapiError::Permission {
                    message: format!("nonce check failed: {e}"),
                    code: "SCP-PERM-3001".to_owned(),
                })
        });
        assert!(first_result.is_ok(), "first nonce use should succeed");

        // Second call: replay the same nonce — should fail.
        let second_result = runtime::with_context(&context_id, |rt| {
            rt.nonce_tracker
                .check_and_record(&nonce, expiry)
                .map_err(|e| crate::error::ScpNapiError::Permission {
                    message: format!("nonce check failed: {e}"),
                    code: "SCP-PERM-3001".to_owned(),
                })
        });
        assert!(
            second_result.is_err(),
            "replayed nonce must be rejected on second call"
        );

        // A different nonce should succeed.
        let different_nonce = format!("{}-bbccddee22334455bbccddee22334455", now_millis + 1);
        let third_result = runtime::with_context(&context_id, |rt| {
            rt.nonce_tracker
                .check_and_record(&different_nonce, expiry)
                .map_err(|e| crate::error::ScpNapiError::Permission {
                    message: format!("nonce check failed: {e}"),
                    code: "SCP-PERM-3001".to_owned(),
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

        let context_id = format!("ctx-revoke-wire-{}", uuid::Uuid::new_v4());
        runtime::register_test_context(&context_id, "did:dht:zCreator");

        let token_cid = "revoked-token-cid-abc".to_owned();

        // Simulate what ucan_revoke does: revoke via runtime registry.
        runtime::with_context(&context_id, |rt| {
            rt.revocation_list.revoke(token_cid.clone());
            Ok(())
        })
        .unwrap();

        // Simulate what ucan_validate does: check revocation via runtime registry.
        let checker_says_revoked = runtime::with_context(&context_id, |rt| {
            let checker = BridgeRevocationChecker {
                revocation_list: &rt.revocation_list,
            };
            Ok(checker.is_revoked(&token_cid))
        })
        .unwrap();

        assert!(
            checker_says_revoked,
            "token revoked via ucan_revoke must be detected by ucan_validate's revocation checker"
        );
    }
}
