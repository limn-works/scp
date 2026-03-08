//! DID-signed bearer token authentication for bridge HTTP endpoints.
//!
//! Implements the authentication layer specified in spec section 12.10.2.
//! Bridge operators authenticate using DID-signed JWTs in the
//! `Authorization: Bearer` header. The node verifies the JWT signature
//! against the operator's DID document (section 3.2).
//!
//! For webhook callbacks (platform to bridge node), Ed25519 signatures in
//! the `X-SCP-Signature` header are verified against the platform's
//! pre-registered public key.
//!
//! # Error Codes
//!
//! | Code | HTTP Status | Description |
//! |------|-------------|-------------|
//! | `BRIDGE_NOT_AUTHORIZED` | 401 | Bearer token invalid or expired |
//! | `BRIDGE_SUSPENDED` | 403 | Bridge is suspended by context governance |
//!
//! See ADR-023 in `.docs/adrs/phase-5.md` and spec section 12.10.3.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode, header};
use axum::middleware::Next;
use axum::response::IntoResponse;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use scp_core::bridge::{BridgeConnector, BridgeStatus};
use scp_identity::dht::decode_multibase_key;
use scp_identity::document::DidDocument;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum allowed JWT token lifetime (1 hour, in seconds).
///
/// Spec section 12.10.2: "Token lifetime MUST NOT exceed 1 hour."
const MAX_TOKEN_LIFETIME_SECS: u64 = 3600;

/// Clock skew tolerance for JWT validation (30 seconds).
///
/// Allows for minor clock differences between bridge operator and node.
const CLOCK_SKEW_TOLERANCE_SECS: u64 = 30;

/// The JWT `alg` header value for Ed25519 signatures (RFC 8037).
const JWT_ALG_EDDSA: &str = "EdDSA";

/// The JWT `typ` header value.
const JWT_TYP: &str = "JWT";

// ---------------------------------------------------------------------------
// Bridge error responses (spec section 12.10.3)
// ---------------------------------------------------------------------------

/// Returns a 401 error response with the `BRIDGE_NOT_AUTHORIZED` error code.
///
/// Used when the bearer token is invalid, expired, or has a bad signature.
/// See spec section 12.10.3.
fn bridge_not_authorized(msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(ApiError {
            error: msg.into(),
            code: "BRIDGE_NOT_AUTHORIZED".to_owned(),
        }),
    )
}

/// Returns a 403 error response with the `BRIDGE_SUSPENDED` error code.
///
/// Used when the bridge has been suspended by context governance.
/// See spec section 12.10.3.
fn bridge_suspended(msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::FORBIDDEN,
        Json(ApiError {
            error: msg.into(),
            code: "BRIDGE_SUSPENDED".to_owned(),
        }),
    )
}

// ---------------------------------------------------------------------------
// JWT structures
// ---------------------------------------------------------------------------

/// JWT header for DID-signed bridge tokens.
///
/// Only the `EdDSA` algorithm (Ed25519) is supported, per spec section 12.10.2.
#[derive(Debug, Deserialize)]
struct JwtHeader {
    /// Algorithm — must be `"EdDSA"` (RFC 8037).
    alg: String,

    /// Type — must be `"JWT"`.
    #[serde(default)]
    typ: Option<String>,

    /// Key ID — optional. If present, specifies the DID document verification
    /// method fragment to use (e.g., `"#active"`).
    #[serde(default)]
    kid: Option<String>,
}

/// JWT claims for bridge operator authentication.
///
/// The payload contains the operator's DID, the target audience (node URL),
/// timestamps, and SCP-specific bridge/context identifiers.
///
/// See spec section 12.10.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeJwtClaims {
    /// Issuer — the bridge operator's DID (e.g., `"did:dht:z6MkOperator..."`).
    pub iss: String,

    /// Audience — the target node URL (e.g., `"https://platform.example.com"`).
    pub aud: String,

    /// Issued At — Unix timestamp (seconds) when the JWT was created.
    pub iat: u64,

    /// Expiration — Unix timestamp (seconds) when the JWT expires.
    pub exp: u64,

    /// The bridge instance identifier this token authenticates for.
    pub scp_bridge_id: String,

    /// The context this bridge is registered in.
    pub scp_context_id: String,
}

/// Validated bridge authentication context extracted by the middleware.
///
/// Stored as a request extension so downstream handlers can access the
/// authenticated bridge identity without re-parsing the JWT.
#[derive(Debug, Clone)]
pub struct BridgeAuthContext {
    /// The verified JWT claims.
    pub claims: BridgeJwtClaims,

    /// The resolved bridge connector from the registry.
    pub bridge: BridgeConnector,
}

// ---------------------------------------------------------------------------
// Bridge lookup trait
// ---------------------------------------------------------------------------

/// Trait for looking up registered bridges and resolving DID documents.
///
/// Implementors provide the bridge registry and DID resolution needed
/// by [`bridge_auth_middleware`]. This decouples the auth layer from
/// specific storage and identity implementations.
pub trait BridgeLookup: Send + Sync + 'static {
    /// Look up a bridge by its ID.
    ///
    /// Returns `None` if no bridge with the given ID is registered.
    fn find_bridge(&self, bridge_id: &str) -> Option<BridgeConnector>;

    /// Resolve a DID document for the given DID string.
    ///
    /// Returns `None` if the DID cannot be resolved. Implementations
    /// MAY cache resolved documents with TTL (spec section 12.10.2).
    fn resolve_did_document(&self, did: &str) -> Option<DidDocument>;

    /// Look up a pre-registered webhook signing public key by key ID.
    ///
    /// Returns the Ed25519 public key bytes for the given platform key ID.
    /// Returns `None` if no key with that ID is registered.
    fn find_webhook_key(&self, key_id: &str) -> Option<[u8; 32]>;

    /// Returns the expected audience (node URL) for JWT validation.
    fn expected_audience(&self) -> &str;
}

// ---------------------------------------------------------------------------
// JWT parsing and verification
// ---------------------------------------------------------------------------

/// Decodes a base64url-encoded JWT segment.
fn decode_jwt_segment(segment: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| format!("invalid base64url encoding: {e}"))
}

/// Parses and verifies a DID-signed JWT bearer token.
///
/// Performs the following checks (spec section 12.10.2):
/// 1. Splits the JWT into header, payload, and signature segments.
/// 2. Validates the header (`alg` must be `EdDSA`).
/// 3. Deserializes the claims payload.
/// 4. Resolves the issuer's DID document.
/// 5. Extracts the signing public key from the DID document.
/// 6. Verifies the Ed25519 signature over `header.payload`.
/// 7. Validates temporal claims (`iat`, `exp`, max lifetime).
///
/// # Errors
///
/// Returns a human-readable error string if any check fails.
fn verify_bridge_jwt(token: &str, lookup: &dyn BridgeLookup) -> Result<BridgeJwtClaims, String> {
    // Step 1: Split into three segments.
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("JWT must have exactly three segments".to_owned());
    }

    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let signature_b64 = parts[2];

    // Step 2: Decode and validate the header.
    let header_bytes = decode_jwt_segment(header_b64)?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| format!("invalid JWT header JSON: {e}"))?;

    if header.alg != JWT_ALG_EDDSA {
        return Err(format!(
            "unsupported JWT algorithm: expected {JWT_ALG_EDDSA}, got {}",
            header.alg
        ));
    }

    if let Some(ref typ) = header.typ
        && !typ.eq_ignore_ascii_case(JWT_TYP)
    {
        return Err(format!(
            "unsupported JWT type: expected {JWT_TYP}, got {typ}"
        ));
    }

    // Step 3: Decode and parse the claims payload.
    let payload_bytes = decode_jwt_segment(payload_b64)?;
    let claims: BridgeJwtClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("invalid JWT payload JSON: {e}"))?;

    // Step 4: Resolve the issuer's DID document.
    let did_doc = lookup
        .resolve_did_document(&claims.iss)
        .ok_or_else(|| format!("could not resolve DID document for issuer: {}", claims.iss))?;

    // Step 5: Extract the signing public key.
    //
    // Use the `kid` header if present (strip the DID prefix if included),
    // otherwise default to `#active` (the Human Signing Key per ADR-039).
    // Extract fragment from kid header. kid may be a full DID URL like
    // "did:dht:z6Mk...#active", just the fragment like "#active", or bare "active".
    // Default to "active" (the Human Signing Key per ADR-039) when kid is absent.
    let fragment = header.kid.as_ref().map_or_else(
        || "active".to_owned(),
        |kid| {
            kid.strip_prefix('#').map_or_else(
                || {
                    kid.rsplit_once('#')
                        .map_or_else(|| kid.clone(), |(_, f)| (*f).to_owned())
                },
                str::to_owned,
            )
        },
    );

    let vm = did_doc
        .verification_method_by_fragment(&fragment)
        .ok_or_else(|| {
            format!(
                "DID document for {} has no verification method with fragment #{fragment}",
                claims.iss
            )
        })?;

    let pub_key_bytes = decode_multibase_key(&vm.public_key_multibase)
        .map_err(|e| format!("failed to decode public key from DID document: {e}"))?;

    let verifying_key = VerifyingKey::from_bytes(&pub_key_bytes)
        .map_err(|e| format!("invalid Ed25519 public key in DID document: {e}"))?;

    // Step 6: Decode and verify the signature.
    let signature_bytes = decode_jwt_segment(signature_b64)?;
    let signature_array: [u8; 64] = signature_bytes.try_into().map_err(|v: Vec<u8>| {
        format!(
            "invalid Ed25519 signature length: expected 64, got {}",
            v.len()
        )
    })?;
    let signature = Signature::from_bytes(&signature_array);

    // The signed message is "header.payload" (the raw base64url segments).
    let signing_input = format!("{header_b64}.{payload_b64}");
    verifying_key
        .verify_strict(signing_input.as_bytes(), &signature)
        .map_err(|e| format!("JWT signature verification failed: {e}"))?;

    // Step 7: Validate temporal claims.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "system clock is before Unix epoch".to_owned())?;

    // Check expiration (with clock skew tolerance).
    if claims.exp + CLOCK_SKEW_TOLERANCE_SECS < now {
        return Err(format!("JWT has expired: exp={}, now={now}", claims.exp));
    }

    // Check that iat is not in the future (with clock skew tolerance).
    if claims.iat > now + CLOCK_SKEW_TOLERANCE_SECS {
        return Err(format!(
            "JWT issued in the future: iat={}, now={now}",
            claims.iat
        ));
    }

    // Check maximum token lifetime (spec: MUST NOT exceed 1 hour).
    let lifetime = claims.exp.saturating_sub(claims.iat);
    if lifetime > MAX_TOKEN_LIFETIME_SECS {
        return Err(format!(
            "JWT lifetime exceeds maximum: {lifetime}s > {MAX_TOKEN_LIFETIME_SECS}s"
        ));
    }

    // Validate audience matches the expected node URL.
    if claims.aud != lookup.expected_audience() {
        return Err(format!(
            "JWT audience mismatch: expected {}, got {}",
            lookup.expected_audience(),
            claims.aud
        ));
    }

    Ok(claims)
}

// ---------------------------------------------------------------------------
// Bridge auth middleware
// ---------------------------------------------------------------------------

/// Axum middleware that validates DID-signed bearer tokens for bridge
/// endpoints.
///
/// Extracts the `Authorization: Bearer <JWT>` header, verifies the JWT
/// signature against the operator's DID document, validates temporal
/// claims, and checks that the bridge is registered and active.
///
/// On success, inserts a [`BridgeAuthContext`] into the request extensions
/// so downstream handlers can access the authenticated bridge identity.
///
/// # Error Responses
///
/// - **401 `BRIDGE_NOT_AUTHORIZED`** — Missing, invalid, or expired token;
///   signature verification failure; bridge not found.
/// - **403 `BRIDGE_SUSPENDED`** — The bridge exists but is suspended by
///   context governance.
///
/// See spec sections 12.10.2 and 12.10.3.
pub async fn bridge_auth_middleware<L: BridgeLookup>(
    State(lookup): State<Arc<L>>,
    mut req: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    // Extract the Authorization header.
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let token = match auth_header {
        Some(value) if value.len() > 7 && value[..7].eq_ignore_ascii_case("bearer ") => &value[7..],
        _ => {
            return bridge_not_authorized("missing or invalid Authorization header")
                .into_response();
        }
    };

    // Verify the JWT.
    let claims = match verify_bridge_jwt(token, lookup.as_ref()) {
        Ok(claims) => claims,
        Err(msg) => {
            return bridge_not_authorized(msg).into_response();
        }
    };

    // Look up the bridge in the registry.
    let Some(bridge) = lookup.find_bridge(&claims.scp_bridge_id) else {
        return bridge_not_authorized(format!("bridge not found: {}", claims.scp_bridge_id))
            .into_response();
    };

    // Validate that the JWT issuer matches the bridge operator.
    if bridge.operator_did != claims.iss {
        return bridge_not_authorized("JWT issuer does not match bridge operator DID")
            .into_response();
    }

    // Validate that the context ID matches.
    if claims.scp_context_id != bridge.registration_context {
        return bridge_not_authorized("JWT context ID does not match bridge registration context")
            .into_response();
    }

    // Check bridge status.
    match bridge.status {
        BridgeStatus::Active => {}
        BridgeStatus::Suspended => {
            return bridge_suspended(format!(
                "bridge {} is suspended by context governance",
                bridge.bridge_id
            ))
            .into_response();
        }
        BridgeStatus::Revoked => {
            return bridge_not_authorized(format!("bridge {} has been revoked", bridge.bridge_id))
                .into_response();
        }
    }

    // Insert the auth context for downstream handlers.
    let auth_ctx = BridgeAuthContext { claims, bridge };
    req.extensions_mut().insert(auth_ctx);

    next.run(req).await.into_response()
}

// ---------------------------------------------------------------------------
// Webhook signature verification
// ---------------------------------------------------------------------------

/// Verifies an Ed25519 webhook signature from an external platform.
///
/// Extracts the `X-SCP-Signature` and `X-SCP-Platform-Key-Id` headers,
/// looks up the platform's pre-registered public key, and verifies the
/// Ed25519 signature over the raw request body.
///
/// See spec section 12.10.2.
///
/// # Errors
///
/// Returns a human-readable error string if verification fails.
pub fn verify_webhook_signature(
    signature_header: &str,
    key_id: &str,
    body: &[u8],
    lookup: &dyn BridgeLookup,
) -> Result<(), String> {
    // Look up the platform's signing key.
    let pub_key_bytes = lookup
        .find_webhook_key(key_id)
        .ok_or_else(|| format!("unknown platform key ID: {key_id}"))?;

    let verifying_key = VerifyingKey::from_bytes(&pub_key_bytes)
        .map_err(|e| format!("invalid platform public key: {e}"))?;

    // Decode the signature from base64url.
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(signature_header)
        .map_err(|e| format!("invalid signature encoding: {e}"))?;

    let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|v: Vec<u8>| {
        format!(
            "invalid Ed25519 signature length: expected 64, got {}",
            v.len()
        )
    })?;
    let signature = Signature::from_bytes(&sig_array);

    verifying_key
        .verify_strict(body, &signature)
        .map_err(|e| format!("webhook signature verification failed: {e}"))
}

/// Axum middleware that validates webhook signatures from external platforms.
///
/// Extracts the `X-SCP-Signature` and `X-SCP-Platform-Key-Id` headers and
/// verifies the Ed25519 signature over the raw request body.
///
/// On success, the request proceeds to the next handler. On failure,
/// returns 401 with error code `BRIDGE_NOT_AUTHORIZED`.
///
/// See spec section 12.10.2.
pub async fn webhook_auth_middleware<L: BridgeLookup>(
    State(lookup): State<Arc<L>>,
    req: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    // Extract required headers.
    let signature_header = match req
        .headers()
        .get("x-scp-signature")
        .and_then(|v| v.to_str().ok())
    {
        Some(s) => s.to_owned(),
        None => {
            return bridge_not_authorized("missing X-SCP-Signature header").into_response();
        }
    };

    let key_id = match req
        .headers()
        .get("x-scp-platform-key-id")
        .and_then(|v| v.to_str().ok())
    {
        Some(k) => k.to_owned(),
        None => {
            return bridge_not_authorized("missing X-SCP-Platform-Key-Id header").into_response();
        }
    };

    // We need to read the body for signature verification, then reconstruct
    // the request for downstream handlers.
    let (parts, body) = req.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return bridge_not_authorized(format!("failed to read request body: {e}"))
                .into_response();
        }
    };

    // Verify the signature.
    if let Err(msg) =
        verify_webhook_signature(&signature_header, &key_id, &body_bytes, lookup.as_ref())
    {
        return bridge_not_authorized(msg).into_response();
    }

    // Reconstruct the request with the body bytes.
    let req = Request::from_parts(parts, Body::from(body_bytes));
    next.run(req).await.into_response()
}

// ---------------------------------------------------------------------------
// JWT creation helper (for testing and bridge operators)
// ---------------------------------------------------------------------------

/// Creates a DID-signed JWT for bridge authentication.
///
/// This is a convenience function for bridge operators to create
/// authentication tokens. The JWT is signed with the operator's
/// Ed25519 signing key.
///
/// # Arguments
///
/// * `claims` — The JWT claims payload.
/// * `signing_key` — The operator's Ed25519 signing key (32 bytes).
///
/// # Errors
///
/// Returns an error string if signing fails.
pub fn create_bridge_jwt(
    claims: &BridgeJwtClaims,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<String, String> {
    use ed25519_dalek::Signer;

    let header = serde_json::json!({
        "alg": JWT_ALG_EDDSA,
        "typ": JWT_TYP
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&header).map_err(|e| format!("header serialization failed: {e}"))?,
    );
    let payload_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(claims).map_err(|e| format!("payload serialization failed: {e}"))?,
    );

    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(format!("{header_b64}.{payload_b64}.{sig_b64}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::middleware;
    use axum::routing::get;
    use ed25519_dalek::SigningKey;
    use http_body_util::BodyExt;
    use rand::rngs::OsRng;
    use scp_core::bridge::{BridgeConnector, BridgeMode, BridgeStatus};
    use scp_identity::document::{DidDocument, VerificationMethod};
    use tower::ServiceExt;

    // -----------------------------------------------------------------------
    // Test BridgeLookup implementation
    // -----------------------------------------------------------------------

    /// Test-only bridge lookup that stores bridges and DID documents in memory.
    struct TestBridgeLookup {
        bridges: Vec<BridgeConnector>,
        did_docs: Vec<(String, DidDocument)>,
        webhook_keys: Vec<(String, [u8; 32])>,
        audience: String,
    }

    impl TestBridgeLookup {
        fn new(audience: &str) -> Self {
            Self {
                bridges: Vec::new(),
                did_docs: Vec::new(),
                webhook_keys: Vec::new(),
                audience: audience.to_owned(),
            }
        }
    }

    impl BridgeLookup for TestBridgeLookup {
        fn find_bridge(&self, bridge_id: &str) -> Option<BridgeConnector> {
            self.bridges
                .iter()
                .find(|b| b.bridge_id == bridge_id)
                .cloned()
        }

        fn resolve_did_document(&self, did: &str) -> Option<DidDocument> {
            self.did_docs
                .iter()
                .find(|(d, _)| d == did)
                .map(|(_, doc)| doc.clone())
        }

        fn find_webhook_key(&self, key_id: &str) -> Option<[u8; 32]> {
            self.webhook_keys
                .iter()
                .find(|(id, _)| id == key_id)
                .map(|(_, key)| *key)
        }

        fn expected_audience(&self) -> &str {
            &self.audience
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn test_did(signing_key: &SigningKey) -> String {
        // Use a deterministic test DID based on key fingerprint.
        let pubkey_hex = hex::encode(signing_key.verifying_key().as_bytes());
        format!("did:dht:z6Mk{}", &pubkey_hex[..16])
    }

    fn test_did_document(did: &str, signing_key: &SigningKey) -> DidDocument {
        let verifying = signing_key.verifying_key();
        let pub_bytes = verifying.as_bytes();
        let multibase = format!("z{}", bs58::encode(pub_bytes).into_string());

        DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: did.to_owned(),
            verification_method: vec![VerificationMethod {
                id: format!("{did}#active"),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: did.to_owned(),
                public_key_multibase: multibase,
            }],
            authentication: vec![format!("{did}#active")],
            assertion_method: vec![format!("{did}#active")],
            service: vec![],
            also_known_as: Vec::new(),
        }
    }

    fn test_bridge(
        bridge_id: &str,
        operator_did: &str,
        context_id: &str,
        status: BridgeStatus,
    ) -> BridgeConnector {
        BridgeConnector {
            bridge_id: bridge_id.to_owned(),
            operator_did: operator_did.into(),
            platform: "discord".to_owned(),
            mode: BridgeMode::Cooperative,
            status,
            registration_context: context_id.to_owned(),
            registered_at: 1_700_000_000,
        }
    }

    fn current_time() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn test_claims(did: &str) -> BridgeJwtClaims {
        let now = current_time();
        BridgeJwtClaims {
            iss: did.to_owned(),
            aud: "https://node.example.com".to_owned(),
            iat: now,
            exp: now + 1800, // 30 minutes
            scp_bridge_id: "bridge-test-001".to_owned(),
            scp_context_id: "ctx-test-001".to_owned(),
        }
    }

    fn test_app(lookup: Arc<TestBridgeLookup>) -> Router {
        Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(middleware::from_fn_with_state(
                lookup,
                bridge_auth_middleware::<TestBridgeLookup>,
            ))
    }

    async fn response_body(resp: axum::response::Response) -> String {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    // -----------------------------------------------------------------------
    // JWT unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn create_and_verify_jwt_roundtrip() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let did = test_did(&signing_key);
        let claims = test_claims(&did);

        let token = create_bridge_jwt(&claims, &signing_key).unwrap();

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup
            .did_docs
            .push((did.clone(), test_did_document(&did, &signing_key)));

        let verified = verify_bridge_jwt(&token, &lookup).unwrap();
        assert_eq!(verified.iss, did);
        assert_eq!(verified.scp_bridge_id, "bridge-test-001");
        assert_eq!(verified.scp_context_id, "ctx-test-001");
    }

    #[test]
    fn reject_expired_jwt() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let did = test_did(&signing_key);
        let mut claims = test_claims(&did);
        // Set expiration to 2 minutes ago (past the clock skew tolerance).
        claims.iat = current_time() - 7200;
        claims.exp = current_time() - 120;

        let token = create_bridge_jwt(&claims, &signing_key).unwrap();

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup
            .did_docs
            .push((did.clone(), test_did_document(&did, &signing_key)));

        let result = verify_bridge_jwt(&token, &lookup);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("expired"),
            "error should mention expiration"
        );
    }

    #[test]
    fn reject_jwt_with_excessive_lifetime() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let did = test_did(&signing_key);
        let mut claims = test_claims(&did);
        // Set lifetime to 2 hours (exceeds 1-hour maximum).
        claims.exp = claims.iat + 7200;

        let token = create_bridge_jwt(&claims, &signing_key).unwrap();

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup
            .did_docs
            .push((did.clone(), test_did_document(&did, &signing_key)));

        let result = verify_bridge_jwt(&token, &lookup);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("lifetime exceeds maximum"),
            "error should mention lifetime"
        );
    }

    #[test]
    fn reject_jwt_with_wrong_key() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let wrong_key = SigningKey::generate(&mut OsRng);
        let did = test_did(&signing_key);
        let claims = test_claims(&did);

        // Sign with the wrong key.
        let token = create_bridge_jwt(&claims, &wrong_key).unwrap();

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup
            .did_docs
            .push((did.clone(), test_did_document(&did, &signing_key)));

        let result = verify_bridge_jwt(&token, &lookup);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("signature verification failed"),
            "error should mention signature failure"
        );
    }

    #[test]
    fn reject_jwt_with_wrong_audience() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let did = test_did(&signing_key);
        let mut claims = test_claims(&did);
        claims.aud = "https://wrong-node.example.com".to_owned();

        let token = create_bridge_jwt(&claims, &signing_key).unwrap();

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup
            .did_docs
            .push((did.clone(), test_did_document(&did, &signing_key)));

        let result = verify_bridge_jwt(&token, &lookup);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("audience mismatch"),
            "error should mention audience mismatch"
        );
    }

    #[test]
    fn reject_jwt_with_future_iat() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let did = test_did(&signing_key);
        let mut claims = test_claims(&did);
        // Set iat far in the future.
        claims.iat = current_time() + 3600;
        claims.exp = claims.iat + 1800;

        let token = create_bridge_jwt(&claims, &signing_key).unwrap();

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup
            .did_docs
            .push((did.clone(), test_did_document(&did, &signing_key)));

        let result = verify_bridge_jwt(&token, &lookup);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("issued in the future"),
            "error should mention future iat"
        );
    }

    #[test]
    fn reject_malformed_jwt() {
        let lookup = TestBridgeLookup::new("https://node.example.com");

        // No segments.
        assert!(verify_bridge_jwt("not-a-jwt", &lookup).is_err());

        // Only two segments.
        assert!(verify_bridge_jwt("header.payload", &lookup).is_err());

        // Four segments.
        assert!(verify_bridge_jwt("a.b.c.d", &lookup).is_err());
    }

    #[test]
    fn reject_unsupported_algorithm() {
        let header = serde_json::json!({"alg": "RS256", "typ": "JWT"});
        let claims = serde_json::json!({"iss": "did:test", "aud": "test", "iat": 0, "exp": 0, "scp_bridge_id": "b", "scp_context_id": "c"});

        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let fake_sig = URL_SAFE_NO_PAD.encode([0u8; 64]);
        let token = format!("{header_b64}.{payload_b64}.{fake_sig}");

        let lookup = TestBridgeLookup::new("test");
        let result = verify_bridge_jwt(&token, &lookup);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unsupported JWT algorithm"));
    }

    // -----------------------------------------------------------------------
    // Middleware integration tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn middleware_accepts_valid_jwt() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let did = test_did(&signing_key);
        let claims = test_claims(&did);
        let token = create_bridge_jwt(&claims, &signing_key).unwrap();

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup
            .did_docs
            .push((did.clone(), test_did_document(&did, &signing_key)));
        lookup.bridges.push(test_bridge(
            "bridge-test-001",
            &did,
            "ctx-test-001",
            BridgeStatus::Active,
        ));
        let lookup = Arc::new(lookup);

        let app = test_app(lookup);
        let req = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(response_body(resp).await, "ok");
    }

    #[tokio::test]
    async fn middleware_rejects_missing_auth_header() {
        let lookup = Arc::new(TestBridgeLookup::new("https://node.example.com"));
        let app = test_app(lookup);

        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = response_body(resp).await;
        assert!(body.contains("BRIDGE_NOT_AUTHORIZED"));
    }

    #[tokio::test]
    async fn middleware_rejects_expired_jwt() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let did = test_did(&signing_key);
        let mut claims = test_claims(&did);
        claims.iat = current_time() - 7200;
        claims.exp = current_time() - 120;
        let token = create_bridge_jwt(&claims, &signing_key).unwrap();

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup
            .did_docs
            .push((did.clone(), test_did_document(&did, &signing_key)));
        lookup.bridges.push(test_bridge(
            "bridge-test-001",
            &did,
            "ctx-test-001",
            BridgeStatus::Active,
        ));
        let lookup = Arc::new(lookup);

        let app = test_app(lookup);
        let req = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = response_body(resp).await;
        assert!(body.contains("BRIDGE_NOT_AUTHORIZED"));
    }

    #[tokio::test]
    async fn middleware_rejects_wrong_key_jwt() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let wrong_key = SigningKey::generate(&mut OsRng);
        let did = test_did(&signing_key);
        let claims = test_claims(&did);
        let token = create_bridge_jwt(&claims, &wrong_key).unwrap();

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup
            .did_docs
            .push((did.clone(), test_did_document(&did, &signing_key)));
        lookup.bridges.push(test_bridge(
            "bridge-test-001",
            &did,
            "ctx-test-001",
            BridgeStatus::Active,
        ));
        let lookup = Arc::new(lookup);

        let app = test_app(lookup);
        let req = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = response_body(resp).await;
        assert!(body.contains("BRIDGE_NOT_AUTHORIZED"));
    }

    #[tokio::test]
    async fn middleware_returns_403_for_suspended_bridge() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let did = test_did(&signing_key);
        let claims = test_claims(&did);
        let token = create_bridge_jwt(&claims, &signing_key).unwrap();

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup
            .did_docs
            .push((did.clone(), test_did_document(&did, &signing_key)));
        lookup.bridges.push(test_bridge(
            "bridge-test-001",
            &did,
            "ctx-test-001",
            BridgeStatus::Suspended,
        ));
        let lookup = Arc::new(lookup);

        let app = test_app(lookup);
        let req = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = response_body(resp).await;
        assert!(body.contains("BRIDGE_SUSPENDED"));
    }

    #[tokio::test]
    async fn middleware_rejects_revoked_bridge() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let did = test_did(&signing_key);
        let claims = test_claims(&did);
        let token = create_bridge_jwt(&claims, &signing_key).unwrap();

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup
            .did_docs
            .push((did.clone(), test_did_document(&did, &signing_key)));
        lookup.bridges.push(test_bridge(
            "bridge-test-001",
            &did,
            "ctx-test-001",
            BridgeStatus::Revoked,
        ));
        let lookup = Arc::new(lookup);

        let app = test_app(lookup);
        let req = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = response_body(resp).await;
        assert!(body.contains("BRIDGE_NOT_AUTHORIZED"));
    }

    #[tokio::test]
    async fn middleware_rejects_operator_did_mismatch() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let did = test_did(&signing_key);
        let claims = test_claims(&did);
        let token = create_bridge_jwt(&claims, &signing_key).unwrap();

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup
            .did_docs
            .push((did.clone(), test_did_document(&did, &signing_key)));
        // Bridge has a different operator DID.
        lookup.bridges.push(test_bridge(
            "bridge-test-001",
            "did:dht:z6MkDifferentOperator",
            "ctx-test-001",
            BridgeStatus::Active,
        ));
        let lookup = Arc::new(lookup);

        let app = test_app(lookup);
        let req = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // -----------------------------------------------------------------------
    // Webhook signature tests
    // -----------------------------------------------------------------------

    #[test]
    fn verify_valid_webhook_signature() {
        use ed25519_dalek::Signer;

        let signing_key = SigningKey::generate(&mut OsRng);
        let pub_key = *signing_key.verifying_key().as_bytes();
        let body = b"webhook payload content";

        let signature = signing_key.sign(body);
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup
            .webhook_keys
            .push(("platform-key-1".to_owned(), pub_key));

        let result = verify_webhook_signature(&sig_b64, "platform-key-1", body, &lookup);
        assert!(result.is_ok());
    }

    #[test]
    fn reject_invalid_webhook_signature() {
        use ed25519_dalek::Signer;

        let signing_key = SigningKey::generate(&mut OsRng);
        let wrong_key = SigningKey::generate(&mut OsRng);
        let pub_key = *signing_key.verifying_key().as_bytes();
        let body = b"webhook payload content";

        // Sign with wrong key.
        let signature = wrong_key.sign(body);
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup
            .webhook_keys
            .push(("platform-key-1".to_owned(), pub_key));

        let result = verify_webhook_signature(&sig_b64, "platform-key-1", body, &lookup);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("signature verification failed")
        );
    }

    #[test]
    fn reject_unknown_webhook_key_id() {
        let body = b"webhook payload";
        let sig_b64 = URL_SAFE_NO_PAD.encode([0u8; 64]);
        let lookup = TestBridgeLookup::new("https://node.example.com");

        let result = verify_webhook_signature(&sig_b64, "unknown-key", body, &lookup);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown platform key ID"));
    }

    #[test]
    fn reject_tampered_webhook_body() {
        use ed25519_dalek::Signer;

        let signing_key = SigningKey::generate(&mut OsRng);
        let pub_key = *signing_key.verifying_key().as_bytes();
        let body = b"original payload";
        let tampered_body = b"tampered payload";

        let signature = signing_key.sign(body);
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup
            .webhook_keys
            .push(("platform-key-1".to_owned(), pub_key));

        let result = verify_webhook_signature(&sig_b64, "platform-key-1", tampered_body, &lookup);
        assert!(result.is_err());
    }
}
