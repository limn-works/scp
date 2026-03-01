//! UCAN token minting and delegation for SCP.
//!
//! Creates, signs, and delegates UCAN tokens with Ed25519 signatures, nonce
//! generation, and capability attestation construction. Tokens are scoped to a
//! specific context and audience (member DID).
//!
//! # Minting
//!
//! [`mint_ucan`] creates a new root UCAN token signed by the context creator.
//! The token includes a unique nonce, capability attestations scoped to a
//! context, and an Ed25519 signature.
//!
//! # Delegation
//!
//! [`delegate_ucan`] creates a delegated UCAN from an existing parent token.
//! Delegation enforces attenuation (capabilities can only narrow, never widen)
//! and links to the parent via its CID in the proof chain.
//!
//! # CID computation
//!
//! [`compute_cid`] produces a content identifier for a UCAN token, used as the
//! key in proof chains (`prf`) and revocation lists. The CID is a SHA-256 hash
//! of the encoded JWT, multibase-encoded with a `bafyrei` prefix following the
//! CID v1 / raw codec / sha2-256 convention.
//!
//! See ADR-009 in `.docs/adrs/phase-2.md` and ADR-016 in `.docs/adrs/phase-3.md`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use scp_platform::traits::{KeyCustody, KeyHandle};

use super::capability::CapabilityUri;
use super::nonce::generate_nonce;
use super::{Attenuation, UcanError, UcanHeader, UcanPayload, UcanToken};

/// Maximum token lifetime: 24 hours in seconds (spec section 9.5).
const MAX_EXPIRY_SECS: u64 = 24 * 60 * 60;

/// Parameters for minting a new UCAN token.
///
/// Encapsulates the inputs needed by [`mint_ucan`] to create a signed UCAN
/// token. The caller provides the issuer's signing key handle, the audience
/// DID, the context ID, the capabilities to grant, and the desired expiry.
///
/// See ADR-016 acceptance criterion 3.
pub struct MintParams<'a> {
    /// The issuer's DID string (context creator).
    pub issuer_did: &'a str,
    /// Handle to the issuer's Ed25519 signing key (managed by [`KeyCustody`]).
    pub issuer_key: &'a KeyHandle,
    /// The audience DID (the member receiving this token).
    pub audience_did: &'a str,
    /// The context ID this token is scoped to.
    pub context_id: &'a str,
    /// Capabilities to grant, as `{resource}:{action}` strings (e.g.,
    /// `"messages:write"`, `"tool_invoke:assistant"`).
    pub capabilities: &'a [String],
    /// Token lifetime in seconds from now. Must not exceed 24 hours (86400s).
    pub lifetime_secs: u64,
    /// Optional not-before timestamp (Unix seconds). If `None`, the token is
    /// valid immediately.
    pub not_before: Option<u64>,
    /// Optional proof chain CIDs (for delegated tokens).
    pub proofs: Vec<String>,
    /// Optional facts to attach to the token.
    pub facts: Option<serde_json::Value>,
}

/// Returns the current Unix timestamp in seconds.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Mints a new UCAN token with Ed25519 signature.
///
/// Creates a complete UCAN token from the provided parameters: constructs
/// the JWT header and payload, generates a unique nonce, builds capability
/// attestations in the `scp:ctx:{context_id}/{capability}` format, encodes
/// the token as a JWT, and signs it with the issuer's Ed25519 key.
///
/// # Token structure
///
/// The minted token is a JWT with three base64url-encoded segments:
/// `base64url(header).base64url(payload).base64url(signature)`.
///
/// # Expiry constraint
///
/// The `lifetime_secs` must not exceed 24 hours (86400 seconds) per spec
/// section 9.5. If exceeded, returns [`UcanError::ExpiryTooFar`].
///
/// # Errors
///
/// Returns [`UcanError::ExpiryTooFar`] if `lifetime_secs` exceeds 24 hours.
/// Returns [`UcanError::MalformedToken`] if serialization or signing fails.
///
/// See ADR-016 acceptance criterion 3.
pub async fn mint_ucan(
    params: &MintParams<'_>,
    custody: &impl KeyCustody,
) -> Result<UcanToken, UcanError> {
    // Enforce 24-hour maximum expiry.
    if params.lifetime_secs > MAX_EXPIRY_SECS {
        return Err(UcanError::ExpiryTooFar(params.lifetime_secs));
    }

    let now = now_secs();
    let exp = now + params.lifetime_secs;

    // Build attestations from capabilities, scoped to the context.
    // Validate capability format: must be "resource:action".
    let att: Vec<Attenuation> = params
        .capabilities
        .iter()
        .map(|cap| {
            let (_resource, action) = cap.split_once(':').ok_or_else(|| {
                UcanError::MalformedToken(format!(
                    "capability must be in 'resource:action' format, got: {cap}"
                ))
            })?;
            Ok(Attenuation {
                with: format!("scp:ctx:{}/{cap}", params.context_id),
                can: action.to_owned(),
            })
        })
        .collect::<Result<Vec<_>, UcanError>>()?;

    let header = UcanHeader::new();
    let payload = UcanPayload {
        iss: params.issuer_did.to_owned(),
        aud: params.audience_did.to_owned(),
        exp,
        nbf: params.not_before,
        nnc: generate_nonce(),
        att,
        prf: params.proofs.clone(),
        fct: params.facts.clone(),
    };

    // Encode header and payload as base64url JSON.
    let header_json = serde_json::to_vec(&header)
        .map_err(|e| UcanError::MalformedToken(format!("header serialization failed: {e}")))?;
    let payload_json = serde_json::to_vec(&payload)
        .map_err(|e| UcanError::MalformedToken(format!("payload serialization failed: {e}")))?;

    let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);

    // The signing input is `base64url(header).base64url(payload)`.
    let signing_input = format!("{header_b64}.{payload_b64}");

    // Sign with Ed25519 via KeyCustody.
    let sig = custody
        .sign(params.issuer_key, signing_input.as_bytes())
        .await
        .map_err(|e| UcanError::MalformedToken(format!("signing failed: {e}")))?;

    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_bytes());
    let encoded = format!("{signing_input}.{sig_b64}");

    Ok(UcanToken {
        header,
        payload,
        signature: sig.into_bytes(),
        encoded,
    })
}

// ---------------------------------------------------------------------------
// CID computation
// ---------------------------------------------------------------------------

/// Computes the content identifier (CID) for a UCAN token.
///
/// The CID is used as the key in proof chains (`prf` field) and revocation
/// lists. It is computed as the SHA-256 hash of the encoded JWT string,
/// hex-encoded with a `bafyrei` prefix following the CID v1 / raw codec /
/// sha2-256 convention used throughout SCP.
///
/// # Determinism
///
/// The CID is deterministic: the same encoded token always produces the same
/// CID. This is critical for revocation (a revoked CID must match the token
/// it was computed from) and proof chain integrity.
///
/// See ADR-016 acceptance criteria 4 and 5.
#[must_use]
pub fn compute_cid(token: &UcanToken) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.encoded.as_bytes());
    let hash = hasher.finalize();

    let hex = hash.iter().fold(String::with_capacity(64), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{b:02x}");
        acc
    });

    format!("bafyrei{hex}")
}

// ---------------------------------------------------------------------------
// Delegation
// ---------------------------------------------------------------------------

/// Parameters for creating a delegated UCAN token.
///
/// Encapsulates the inputs needed by [`delegate_ucan`] to create a delegated
/// UCAN. The delegator (parent token's audience) delegates a subset of their
/// capabilities to a new delegatee.
///
/// See ADR-016 acceptance criterion 4.
pub struct DelegateParams<'a> {
    /// The parent UCAN token being delegated from. The delegator must be the
    /// audience (`aud`) of this token.
    pub parent_token: &'a UcanToken,
    /// The delegator's DID — must match `parent_token.payload.aud`.
    pub delegator_did: &'a str,
    /// Handle to the delegator's Ed25519 signing key.
    pub delegator_key: &'a KeyHandle,
    /// The delegatee's DID (the entity receiving the delegated capabilities).
    pub delegatee_did: &'a str,
    /// Capabilities to delegate, as full capability URI strings
    /// (`scp:ctx:{context_id}/{resource}:{action}`). Must be a subset of the
    /// parent token's `att` (attenuation, never widening).
    pub attenuated_capabilities: &'a [Attenuation],
    /// Token lifetime in seconds from now. Must not exceed 24 hours (86400s)
    /// and should not exceed the parent token's remaining lifetime.
    pub lifetime_secs: u64,
    /// Optional facts to attach to the delegated token.
    pub facts: Option<serde_json::Value>,
}

/// Creates a delegated UCAN token from a parent token.
///
/// Delegation enforces the following invariants from ADR-016:
///
/// 1. **Delegator identity** — The `delegator_did` must match the parent
///    token's `aud` field. Only the intended audience of a token can delegate
///    it further.
///
/// 2. **Attenuation** — The `attenuated_capabilities` must be a subset of the
///    parent token's `att`. Delegation can only narrow capabilities, never
///    widen them. This prevents privilege escalation through delegation chains.
///
/// 3. **Proof chain** — The delegated token's `prf` field includes the parent
///    token's CID (computed via [`compute_cid`]), linking the delegation chain
///    for verification.
///
/// 4. **Signing** — The delegated token is signed with the delegator's Ed25519
///    key, proving the delegation was authorized by the parent's audience.
///
/// # Errors
///
/// Returns [`UcanError::AudienceMismatch`] if `delegator_did` does not match
/// `parent_token.payload.aud`.
/// Returns [`UcanError::AttenuationViolation`] if any capability in
/// `attenuated_capabilities` is not granted by the parent token.
/// Returns [`UcanError::ExpiryTooFar`] if `lifetime_secs` exceeds 24 hours.
/// Returns [`UcanError::MalformedToken`] if serialization or signing fails.
///
/// See ADR-016 acceptance criterion 4.
pub async fn delegate_ucan(
    params: &DelegateParams<'_>,
    custody: &impl KeyCustody,
) -> Result<UcanToken, UcanError> {
    // Step 1: Verify delegator DID matches parent token's audience.
    if params.delegator_did != params.parent_token.payload.aud {
        return Err(UcanError::AudienceMismatch {
            expected: params.parent_token.payload.aud.clone(),
            actual: params.delegator_did.to_owned(),
        });
    }

    // Step 2: Verify attenuation — all requested capabilities must be a subset
    // of the parent token's capabilities (never widen).
    let parent_caps: Vec<CapabilityUri> = params
        .parent_token
        .payload
        .att
        .iter()
        .filter_map(|att| att.with.parse::<CapabilityUri>().ok())
        .collect();

    for child_att in params.attenuated_capabilities {
        let child_cap: CapabilityUri = child_att.with.parse().map_err(|e: UcanError| {
            UcanError::AttenuationViolation(format!(
                "invalid capability URI '{}': {e}",
                child_att.with
            ))
        })?;

        let is_granted = parent_caps.iter().any(|parent| parent.matches(&child_cap));
        if !is_granted {
            return Err(UcanError::AttenuationViolation(format!(
                "capability '{}' is not granted by the parent token",
                child_att.with
            )));
        }
    }

    // Step 3: Enforce 24-hour maximum expiry.
    if params.lifetime_secs > MAX_EXPIRY_SECS {
        return Err(UcanError::ExpiryTooFar(params.lifetime_secs));
    }

    let now = now_secs();
    let exp = now + params.lifetime_secs;

    // Step 4: Compute the parent token's CID for the proof chain.
    let parent_cid = compute_cid(params.parent_token);

    // Collect parent proofs and append the parent's own CID.
    let mut proofs = params.parent_token.payload.prf.clone();
    proofs.push(parent_cid);

    let header = UcanHeader::new();
    let payload = UcanPayload {
        iss: params.delegator_did.to_owned(),
        aud: params.delegatee_did.to_owned(),
        exp,
        nbf: None,
        nnc: generate_nonce(),
        att: params.attenuated_capabilities.to_vec(),
        prf: proofs,
        fct: params.facts.clone(),
    };

    // Encode header and payload as base64url JSON.
    let header_json = serde_json::to_vec(&header)
        .map_err(|e| UcanError::MalformedToken(format!("header serialization failed: {e}")))?;
    let payload_json = serde_json::to_vec(&payload)
        .map_err(|e| UcanError::MalformedToken(format!("payload serialization failed: {e}")))?;

    let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);

    // The signing input is `base64url(header).base64url(payload)`.
    let signing_input = format!("{header_b64}.{payload_b64}");

    // Sign with the delegator's Ed25519 key via KeyCustody.
    let sig = custody
        .sign(params.delegator_key, signing_input.as_bytes())
        .await
        .map_err(|e| UcanError::MalformedToken(format!("signing failed: {e}")))?;

    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_bytes());
    let encoded = format!("{signing_input}.{sig_b64}");

    Ok(UcanToken {
        header,
        payload,
        signature: sig.into_bytes(),
        encoded,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use scp_platform::testing::InMemoryKeyCustody;
    use scp_platform::traits::KeyType;

    /// Helper: create an `InMemoryKeyCustody`, generate a key, and return both.
    async fn setup_custody() -> (InMemoryKeyCustody, KeyHandle, String) {
        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let pubkey = custody.public_key(&handle).await.unwrap();
        let did = format!("did:dht:z{}", zbase32::encode(pubkey.as_bytes()));
        (custody, handle, did)
    }

    #[tokio::test]
    async fn mint_ucan_produces_valid_jwt_structure() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-abc123",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        // Verify JWT has three segments.
        assert_eq!(
            token.encoded.split('.').count(),
            3,
            "JWT must have 3 segments"
        );

        // Verify header fields.
        assert_eq!(token.header.alg, "EdDSA");
        assert_eq!(token.header.typ, "JWT");
        assert_eq!(token.header.ucv, "0.10.0");

        // Verify payload fields.
        assert_eq!(token.payload.iss, issuer_did);
        assert_eq!(token.payload.aud, "did:dht:z6MkMember");
        assert_eq!(token.payload.att.len(), 1);
        assert_eq!(
            token.payload.att[0].with,
            "scp:ctx:ctx-abc123/messages:write"
        );
        assert_eq!(token.payload.att[0].can, "write");
        assert!(token.payload.nbf.is_none());
        assert!(token.payload.prf.is_empty());

        // Verify signature length (Ed25519 = 64 bytes).
        assert_eq!(token.signature.len(), 64);
    }

    #[tokio::test]
    async fn mint_ucan_signature_verifies_with_issuer_public_key() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:read".to_owned(), "messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkAudience",
            context_id: "ctx-test",
            capabilities: &caps,
            lifetime_secs: 7200,
            not_before: None,
            proofs: vec![],
            facts: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        // Reconstruct signing input from encoded token.
        let parts: Vec<&str> = token.encoded.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);

        // Verify signature using ed25519-dalek directly.
        let pubkey = custody.public_key(&key_handle).await.unwrap();
        let pk_bytes: [u8; 32] = pubkey.as_bytes().try_into().unwrap();
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).unwrap();

        let sig_bytes: [u8; 64] = token.signature.as_slice().try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        assert!(
            verifying_key
                .verify(signing_input.as_bytes(), &signature)
                .is_ok(),
            "Ed25519 signature must verify"
        );
    }

    #[tokio::test]
    async fn mint_ucan_nonce_has_correct_format() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();
        let nonce = &token.payload.nnc;

        // Nonce format: {unix_millis_timestamp}-{32_hex_chars}
        let parts: Vec<&str> = nonce.splitn(2, '-').collect();
        assert_eq!(parts.len(), 2, "nonce must have timestamp-hex format");

        // Timestamp part must be a valid integer.
        let _ts: u128 = parts[0].parse().expect("timestamp must be numeric");

        // Hex part must be exactly 32 hex chars (16 bytes).
        assert_eq!(parts[1].len(), 32, "random suffix must be 32 hex chars");
        assert!(
            parts[1].chars().all(|c| c.is_ascii_hexdigit()),
            "random suffix must be valid hex"
        );
    }

    #[tokio::test]
    async fn mint_ucan_nonces_are_unique() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
        };

        let token1 = mint_ucan(&params, &custody).await.unwrap();
        let token2 = mint_ucan(&params, &custody).await.unwrap();

        assert_ne!(
            token1.payload.nnc, token2.payload.nnc,
            "nonces must be unique"
        );
    }

    #[tokio::test]
    async fn mint_ucan_rejects_expiry_beyond_24h() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: MAX_EXPIRY_SECS + 1,
            not_before: None,
            proofs: vec![],
            facts: None,
        };

        let err = mint_ucan(&params, &custody).await.unwrap_err();
        assert!(matches!(err, UcanError::ExpiryTooFar(_)));
    }

    #[tokio::test]
    async fn mint_ucan_expiry_exactly_24h_succeeds() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: MAX_EXPIRY_SECS,
            not_before: None,
            proofs: vec![],
            facts: None,
        };

        assert!(mint_ucan(&params, &custody).await.is_ok());
    }

    #[tokio::test]
    async fn mint_ucan_multiple_capabilities() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec![
            "messages:read".to_owned(),
            "messages:write".to_owned(),
            "tool_invoke:assistant".to_owned(),
        ];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-multi",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        assert_eq!(token.payload.att.len(), 3);
        assert_eq!(token.payload.att[0].with, "scp:ctx:ctx-multi/messages:read");
        assert_eq!(token.payload.att[0].can, "read");
        assert_eq!(
            token.payload.att[1].with,
            "scp:ctx:ctx-multi/messages:write"
        );
        assert_eq!(token.payload.att[1].can, "write");
        assert_eq!(
            token.payload.att[2].with,
            "scp:ctx:ctx-multi/tool_invoke:assistant"
        );
        assert_eq!(token.payload.att[2].can, "assistant");
    }

    #[tokio::test]
    async fn mint_ucan_with_proofs_and_facts() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: Some(1_700_000_000),
            proofs: vec!["bafyreiabc123".to_owned()],
            facts: Some(serde_json::json!({"role": "member"})),
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        assert_eq!(token.payload.nbf, Some(1_700_000_000));
        assert_eq!(token.payload.prf, vec!["bafyreiabc123"]);
        assert_eq!(
            token.payload.fct,
            Some(serde_json::json!({"role": "member"}))
        );
    }

    #[tokio::test]
    async fn mint_ucan_encoded_token_decodes_correctly() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-decode",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        // Decode the JWT parts and verify they match the struct fields.
        let parts: Vec<&str> = token.encoded.split('.').collect();
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();

        let decoded_header: UcanHeader = serde_json::from_slice(&header_bytes).unwrap();
        let decoded_payload: UcanPayload = serde_json::from_slice(&payload_bytes).unwrap();

        assert_eq!(decoded_header, token.header);
        assert_eq!(decoded_payload, token.payload);
    }

    // -------------------------------------------------------------------
    // compute_cid
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn compute_cid_returns_bafyrei_prefix() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-cid",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();
        let cid = compute_cid(&token);

        assert!(
            cid.starts_with("bafyrei"),
            "CID must start with 'bafyrei' prefix, got: {cid}"
        );
    }

    #[tokio::test]
    async fn compute_cid_is_deterministic() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-cid",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();
        let cid1 = compute_cid(&token);
        let cid2 = compute_cid(&token);

        assert_eq!(cid1, cid2, "CID must be deterministic for the same token");
    }

    #[tokio::test]
    async fn compute_cid_different_tokens_produce_different_cids() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-cid",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
        };

        let token1 = mint_ucan(&params, &custody).await.unwrap();
        let token2 = mint_ucan(&params, &custody).await.unwrap();

        let cid1 = compute_cid(&token1);
        let cid2 = compute_cid(&token2);

        assert_ne!(
            cid1, cid2,
            "different tokens (different nonces) must produce different CIDs"
        );
    }

    #[tokio::test]
    async fn compute_cid_hex_has_correct_length() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-cid",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();
        let cid = compute_cid(&token);

        // "bafyrei" (7 chars) + 64 hex chars (SHA-256) = 71 chars total.
        assert_eq!(cid.len(), 7 + 64, "CID must be 'bafyrei' + 64 hex chars");

        // The hex portion must be valid hex.
        let hex_part = &cid[7..];
        assert!(
            hex_part.chars().all(|c| c.is_ascii_hexdigit()),
            "CID hex portion must be valid hex"
        );
    }

    // -------------------------------------------------------------------
    // delegate_ucan — success cases
    // -------------------------------------------------------------------

    /// Helper: mint a root token from Alice to Bob with given capabilities.
    async fn mint_root_token(
        custody: &InMemoryKeyCustody,
        issuer_key: &KeyHandle,
        issuer_did: &str,
        audience_did: &str,
        context_id: &str,
        capabilities: &[String],
    ) -> UcanToken {
        let params = MintParams {
            issuer_did,
            issuer_key,
            audience_did,
            context_id,
            capabilities,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
        };
        mint_ucan(&params, custody).await.unwrap()
    }

    #[tokio::test]
    async fn delegate_ucan_creates_valid_delegated_token() {
        // Alice creates a root token for Bob.
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:read".to_owned(), "messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Bob delegates a subset to Carol.
        let carol_did = "did:dht:z6MkCarol";
        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:read".to_owned(),
            can: "read".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: carol_did,
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody).await.unwrap();

        // Verify structure.
        assert_eq!(delegated.payload.iss, bob_did);
        assert_eq!(delegated.payload.aud, carol_did);
        assert_eq!(delegated.payload.att.len(), 1);
        assert_eq!(delegated.payload.att[0].with, "scp:ctx:ctx-1/messages:read");
        assert_eq!(delegated.payload.att[0].can, "read");

        // Verify JWT has three segments.
        assert_eq!(
            delegated.encoded.split('.').count(),
            3,
            "delegated JWT must have 3 segments"
        );

        // Verify signature length.
        assert_eq!(delegated.signature.len(), 64);
    }

    #[tokio::test]
    async fn delegate_ucan_proof_chain_contains_parent_cid() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        let parent_cid = compute_cid(&root_token);

        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody).await.unwrap();

        // The proof chain must include the parent CID.
        assert!(
            delegated.payload.prf.contains(&parent_cid),
            "delegated token prf must contain parent CID"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_signature_verifies_with_delegator_key() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody).await.unwrap();

        // Verify signature with Bob's public key.
        let bob_pubkey = bob_custody.public_key(&bob_key).await.unwrap();
        let pk_bytes: [u8; 32] = bob_pubkey.as_bytes().try_into().unwrap();
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).unwrap();

        let parts: Vec<&str> = delegated.encoded.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);

        let sig_bytes: [u8; 64] = delegated.signature.as_slice().try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        assert!(
            verifying_key
                .verify(signing_input.as_bytes(), &signature)
                .is_ok(),
            "delegated token Ed25519 signature must verify with delegator's key"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_preserves_all_parent_capabilities() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec![
            "messages:read".to_owned(),
            "messages:write".to_owned(),
            "tool_invoke:assistant".to_owned(),
        ];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Delegate all capabilities (exact copy, no narrowing).
        let attenuated: Vec<Attenuation> = root_token.payload.att.clone();

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody).await.unwrap();
        assert_eq!(delegated.payload.att.len(), 3);
    }

    #[tokio::test]
    async fn delegate_ucan_narrows_to_single_capability() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec![
            "messages:read".to_owned(),
            "messages:write".to_owned(),
            "tool_invoke:assistant".to_owned(),
        ];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Delegate only messages:read.
        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:read".to_owned(),
            can: "read".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody).await.unwrap();
        assert_eq!(delegated.payload.att.len(), 1);
        assert_eq!(delegated.payload.att[0].with, "scp:ctx:ctx-1/messages:read");
    }

    #[tokio::test]
    async fn delegate_ucan_includes_facts() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: Some(serde_json::json!({"delegated_by": "bob"})),
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody).await.unwrap();
        assert_eq!(
            delegated.payload.fct,
            Some(serde_json::json!({"delegated_by": "bob"}))
        );
    }

    #[tokio::test]
    async fn delegate_ucan_generates_unique_nonces() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
        };

        let d1 = delegate_ucan(&delegate_params, &bob_custody).await.unwrap();
        let d2 = delegate_ucan(&delegate_params, &bob_custody).await.unwrap();

        assert_ne!(
            d1.payload.nnc, d2.payload.nnc,
            "delegated tokens must have unique nonces"
        );
    }

    // -------------------------------------------------------------------
    // delegate_ucan — chained delegation (A -> B -> C)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn delegate_ucan_chained_delegation_accumulates_proof_chain() {
        // Alice -> Bob -> Carol: verify the proof chain grows.
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;
        let (carol_custody, carol_key, carol_did) = setup_custody().await;

        let caps = vec!["messages:read".to_owned(), "messages:write".to_owned()];

        // Alice mints root token for Bob.
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;
        let root_cid = compute_cid(&root_token);
        assert!(root_token.payload.prf.is_empty());

        // Bob delegates to Carol.
        let bob_attenuated = vec![
            Attenuation {
                with: "scp:ctx:ctx-1/messages:read".to_owned(),
                can: "read".to_owned(),
            },
            Attenuation {
                with: "scp:ctx:ctx-1/messages:write".to_owned(),
                can: "write".to_owned(),
            },
        ];

        let bob_delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: &carol_did,
            attenuated_capabilities: &bob_attenuated,
            lifetime_secs: 1800,
            facts: None,
        };

        let bob_to_carol = delegate_ucan(&bob_delegate_params, &bob_custody)
            .await
            .unwrap();
        let bob_to_carol_cid = compute_cid(&bob_to_carol);

        // Bob's delegated token should have root CID in proof chain.
        assert_eq!(bob_to_carol.payload.prf.len(), 1);
        assert!(bob_to_carol.payload.prf.contains(&root_cid));

        // Carol delegates to Dave (further narrowing).
        let carol_attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:read".to_owned(),
            can: "read".to_owned(),
        }];

        let carol_delegate_params = DelegateParams {
            parent_token: &bob_to_carol,
            delegator_did: &carol_did,
            delegator_key: &carol_key,
            delegatee_did: "did:dht:z6MkDave",
            attenuated_capabilities: &carol_attenuated,
            lifetime_secs: 900,
            facts: None,
        };

        let carol_to_dave = delegate_ucan(&carol_delegate_params, &carol_custody)
            .await
            .unwrap();

        // Carol's delegated token should have root CID AND Bob-to-Carol CID.
        assert_eq!(carol_to_dave.payload.prf.len(), 2);
        assert!(carol_to_dave.payload.prf.contains(&root_cid));
        assert!(carol_to_dave.payload.prf.contains(&bob_to_carol_cid));
    }

    // -------------------------------------------------------------------
    // delegate_ucan — error cases
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn delegate_ucan_rejects_delegator_not_matching_parent_audience() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (_bob_custody, _bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Eve (not Bob) tries to delegate.
        let (eve_custody, eve_key, eve_did) = setup_custody().await;

        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &eve_did,
            delegator_key: &eve_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
        };

        let err = delegate_ucan(&delegate_params, &eve_custody)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::AudienceMismatch { .. }),
            "must reject delegator not matching parent aud: {err}"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_rejects_capability_widening() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        // Root token only grants messages:read.
        let caps = vec!["messages:read".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Bob tries to delegate messages:write (not in parent).
        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
        };

        let err = delegate_ucan(&delegate_params, &bob_custody)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::AttenuationViolation(_)),
            "must reject capability widening: {err}"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_rejects_widening_with_extra_capability() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:read".to_owned(), "messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Bob tries to delegate including tool_invoke:assistant (not in parent).
        let attenuated = vec![
            Attenuation {
                with: "scp:ctx:ctx-1/messages:read".to_owned(),
                can: "read".to_owned(),
            },
            Attenuation {
                with: "scp:ctx:ctx-1/tool_invoke:assistant".to_owned(),
                can: "assistant".to_owned(),
            },
        ];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
        };

        let err = delegate_ucan(&delegate_params, &bob_custody)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::AttenuationViolation(_)),
            "must reject widening with extra capability: {err}"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_rejects_different_context_as_widening() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Bob tries to delegate for a different context.
        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-OTHER/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
        };

        let err = delegate_ucan(&delegate_params, &bob_custody)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::AttenuationViolation(_)),
            "must reject delegation for a different context: {err}"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_rejects_expiry_beyond_24h() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: MAX_EXPIRY_SECS + 1,
            facts: None,
        };

        let err = delegate_ucan(&delegate_params, &bob_custody)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::ExpiryTooFar(_)),
            "must reject expiry beyond 24h: {err}"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_rejects_invalid_capability_uri() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        let attenuated = vec![Attenuation {
            with: "not-a-valid-uri".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
        };

        let err = delegate_ucan(&delegate_params, &bob_custody)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::AttenuationViolation(_)),
            "must reject invalid capability URI: {err}"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_empty_capabilities_succeeds() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Delegating zero capabilities is valid attenuation (maximally narrow).
        let attenuated: Vec<Attenuation> = vec![];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody).await.unwrap();
        assert!(delegated.payload.att.is_empty());
    }

    #[tokio::test]
    async fn delegate_ucan_wildcard_parent_grants_specific_child() {
        // A parent token with a wildcard capability should allow delegation to
        // a specific context.
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        // Manually create a root token with a wildcard capability.
        let wildcard_caps = vec![Attenuation {
            with: "scp:ctx:*/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let params = MintParams {
            issuer_did: &alice_did,
            issuer_key: &alice_key,
            audience_did: &bob_did,
            context_id: "*",
            capabilities: &["messages:write".to_owned()],
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
        };
        let mut root_token = mint_ucan(&params, &alice_custody).await.unwrap();
        // Overwrite att to use the explicitly wildcard form.
        root_token.payload.att = wildcard_caps;

        // Bob delegates to Carol for a specific context.
        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-specific/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody).await.unwrap();
        assert_eq!(
            delegated.payload.att[0].with,
            "scp:ctx:ctx-specific/messages:write"
        );
    }
}
