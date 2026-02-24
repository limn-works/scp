//! UCAN token minting for SCP.
//!
//! Creates and signs UCAN tokens with Ed25519 signatures, nonce generation,
//! and capability attestation construction. Tokens are scoped to a specific
//! context and audience (member DID).
//!
//! See ADR-009 in `.docs/adrs/phase-2.md` and ADR-016 in `.docs/adrs/phase-3.md`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use scp_platform::traits::{KeyCustody, KeyHandle};

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

/// Generates a nonce in the format `{unix_millis_timestamp}-{16_random_bytes_hex}`.
///
/// The timestamp prefix enables efficient pruning of expired nonces. The 16
/// random bytes (32 hex chars) ensure uniqueness even under high concurrency.
///
/// See ADR-009 acceptance criterion 7 and ADR-016 acceptance criterion 6.
fn generate_nonce() -> String {
    let now_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    let mut random_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut random_bytes);

    let hex_suffix = random_bytes
        .iter()
        .fold(String::with_capacity(32), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        });

    format!("{now_millis}-{hex_suffix}")
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
    let att: Vec<Attenuation> = params
        .capabilities
        .iter()
        .map(|cap| Attenuation {
            with: format!("scp:ctx:{}/{cap}", params.context_id),
            can: cap.split(':').nth(1).unwrap_or("invoke").to_owned(),
        })
        .collect();

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
}
