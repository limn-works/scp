//! HTTP handlers for bridge endpoints.
//!
//! Implements the REST API surface for bridge operations such as shadow
//! identity creation. All endpoints require bridge authentication via
//! DID-signed JWT (see [`bridge_auth`](crate::bridge_auth)).
//!
//! See spec section 12.10 and ADR-023 in `.docs/adrs/phase-5.md`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json, Router, routing::post};
use scp_core::bridge::shadow::{CreateShadowParams, ShadowRegistry, create_shadow};
use scp_core::crypto::sender_keys::SenderKeyStore;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::error::ApiError;

// ---------------------------------------------------------------------------
// Shared state for bridge operations
// ---------------------------------------------------------------------------

/// A stored platform identity attestation.
#[derive(Debug, Clone, Serialize)]
pub struct StoredAttestation {
    pub attestation_id: String,
    pub status: String,
    pub bridge_id: String,
    pub platform_handle: String,
    pub platform_user_id: String,
    pub evidence: AttestationEvidence,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Shared state for bridge shadow operations.
///
/// Holds per-context shadow registries, the sender key store, and
/// platform identity attestations, protected by an async `RwLock`
/// for concurrent handler access.
#[derive(Debug)]
pub struct BridgeState {
    /// Per-context shadow registries, keyed by context ID.
    pub registries: RwLock<HashMap<String, ShadowRegistry>>,

    /// Sender key store for shadow identity encryption keys.
    pub sender_key_store: RwLock<SenderKeyStore>,

    /// Platform identity attestations, keyed by attestation ID.
    pub attestations: RwLock<HashMap<String, StoredAttestation>>,
}

impl BridgeState {
    /// Creates a new empty bridge state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            registries: RwLock::new(HashMap::new()),
            sender_key_store: RwLock::new(SenderKeyStore::new()),
            attestations: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for BridgeState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Request body for `POST /v1/scp/bridge/shadow`.
#[derive(Debug, Deserialize)]
pub struct CreateShadowRequest {
    /// The external platform handle (e.g., `"@alice#1234"`).
    pub platform_handle: String,

    /// The platform-specific user identifier, used for idempotency.
    /// If a shadow already exists for this ID on the authenticated bridge,
    /// the existing shadow is returned with HTTP 200.
    pub platform_user_id: String,

    /// Optional metadata associated with the shadow identity.
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// Response body for `POST /v1/scp/bridge/shadow`.
#[derive(Debug, Serialize)]
pub struct CreateShadowResponse {
    /// The unique shadow identity ID.
    pub shadow_id: String,

    /// The external platform handle.
    pub platform_handle: String,

    /// The platform-specific user identifier.
    pub platform_user_id: String,

    /// The role attributed to this shadow (defaults to `"observer"`).
    pub attributed_role: String,

    /// Unix timestamp (seconds) when the shadow was created.
    pub created_at: u64,
}

/// Request body for `POST /v1/scp/bridge/attest`.
#[derive(Debug, Deserialize)]
pub struct AttestRequest {
    /// The user's handle on the external platform.
    pub platform_handle: String,

    /// The platform's internal user identifier.
    pub platform_user_id: String,

    /// Evidence supporting the identity assertion.
    pub attestation_evidence: AttestationEvidence,
}

/// Evidence supporting a platform identity attestation.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AttestationEvidence {
    /// Type of evidence (`platform-verified`, `oauth2`, `signed-challenge`).
    pub evidence_type: String,

    /// How the platform verified the user.
    pub verification_method: String,

    /// Unix timestamp (seconds) of verification.
    pub verified_at: u64,

    /// Confidence level: `"high"`, `"medium"`, or `"low"`.
    pub platform_confidence: String,

    /// Platform-specific trust signals.
    #[serde(default)]
    pub additional_signals: Option<serde_json::Value>,
}

/// Response body for `POST /v1/scp/bridge/attest`.
#[derive(Debug, Serialize)]
pub struct AttestResponse {
    /// The unique attestation ID.
    pub attestation_id: String,

    /// Attestation status (always `"active"` on creation).
    pub status: String,

    /// The user's handle on the external platform.
    pub platform_handle: String,

    /// Unix timestamp (seconds) when the attestation was issued.
    pub issued_at: u64,

    /// Unix timestamp (seconds) when the attestation expires.
    pub expires_at: u64,
}

/// Default attestation TTL: 24 hours in seconds.
const ATTESTATION_TTL_SECS: u64 = 86_400;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Derives a deterministic shadow ID from bridge and platform user IDs.
///
/// The shadow ID is scoped to the bridge to prevent cross-bridge collisions.
fn derive_shadow_id(bridge_id: &str, platform_user_id: &str) -> String {
    format!("shadow:{bridge_id}:{platform_user_id}")
}

/// Handler for `POST /v1/scp/bridge/shadow`.
///
/// Creates a shadow identity for an external platform participant. The
/// handler is idempotent: if a shadow already exists for the given
/// `platform_user_id` on the authenticated bridge, the existing shadow
/// is returned with HTTP 200.
///
/// Requires bridge authentication via the `bridge_auth_middleware`.
/// The authenticated bridge context is extracted from request extensions.
///
/// See SCP-BCH-002 and spec section 12.10.
async fn create_shadow_handler(
    State(bridge_state): State<Arc<BridgeState>>,
    Extension(auth_ctx): Extension<crate::bridge_auth::BridgeAuthContext>,
    Json(body): Json<CreateShadowRequest>,
) -> impl IntoResponse {
    // Validate required fields (serde handles presence, but check emptiness).
    if body.platform_handle.is_empty() {
        return ApiError::bad_request("platform_handle must not be empty").into_response();
    }
    if body.platform_user_id.is_empty() {
        return ApiError::bad_request("platform_user_id must not be empty").into_response();
    }

    let bridge_id = &auth_ctx.claims.scp_bridge_id;
    let context_id = &auth_ctx.claims.scp_context_id;
    let shadow_id = derive_shadow_id(bridge_id, &body.platform_user_id);

    let mut registries = bridge_state.registries.write().await;

    // Ensure a registry exists for this context.
    let registry = registries
        .entry(context_id.clone())
        .or_insert_with(|| ShadowRegistry::new(context_id.clone()));

    // Idempotency: if a shadow with this ID already exists, return 200.
    if let Some(existing) = registry.shadows().iter().find(|s| s.shadow_id == shadow_id) {
        return (
            StatusCode::OK,
            Json(CreateShadowResponse {
                shadow_id: existing.shadow_id.clone(),
                platform_handle: existing.platform_handle.clone(),
                platform_user_id: body.platform_user_id,
                attributed_role: existing.attributed_role.clone(),
                created_at: existing.created_at,
            }),
        )
            .into_response();
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let bridge_mode = auth_ctx.bridge.mode.clone();

    let params = CreateShadowParams {
        shadow_id: &shadow_id,
        bridge_id,
        bridge_mode,
        platform_handle: &body.platform_handle,
        context_member_dids: &[],
        timestamp: now,
    };

    let mut sender_key_store = bridge_state.sender_key_store.write().await;

    match create_shadow(registry, &mut sender_key_store, &params) {
        Ok((shadow, _event)) => (
            StatusCode::CREATED,
            Json(CreateShadowResponse {
                shadow_id: shadow.shadow_id,
                platform_handle: shadow.platform_handle,
                platform_user_id: body.platform_user_id,
                attributed_role: shadow.attributed_role,
                created_at: shadow.created_at,
            }),
        )
            .into_response(),
        Err(e) => ApiError::internal_error(e.to_string()).into_response(),
    }
}

/// Validates the `platform_confidence` field value.
fn is_valid_confidence(value: &str) -> bool {
    matches!(value, "high" | "medium" | "low")
}

/// Handler for `POST /v1/scp/bridge/attest`.
///
/// Creates a platform identity attestation signed by the bridge operator.
/// The attestation asserts the platform's confidence in the mapping between
/// the platform handle and the user.
///
/// Requires bridge authentication via the `bridge_auth_middleware`.
///
/// See SCP-BCH-004 and spec section 12.10.
async fn attest_handler(
    State(bridge_state): State<Arc<BridgeState>>,
    Extension(auth_ctx): Extension<crate::bridge_auth::BridgeAuthContext>,
    Json(body): Json<AttestRequest>,
) -> impl IntoResponse {
    if body.platform_handle.is_empty() {
        return ApiError::bad_request("platform_handle must not be empty").into_response();
    }
    if body.platform_user_id.is_empty() {
        return ApiError::bad_request("platform_user_id must not be empty").into_response();
    }
    if body.attestation_evidence.evidence_type.is_empty() {
        return ApiError::bad_request("attestation_evidence.evidence_type must not be empty")
            .into_response();
    }
    if body.attestation_evidence.verification_method.is_empty() {
        return ApiError::bad_request(
            "attestation_evidence.verification_method must not be empty",
        )
        .into_response();
    }
    if !is_valid_confidence(&body.attestation_evidence.platform_confidence) {
        return ApiError::bad_request(
            "attestation_evidence.platform_confidence must be \"high\", \"medium\", or \"low\"",
        )
        .into_response();
    }

    let bridge_id = &auth_ctx.claims.scp_bridge_id;
    let attestation_id = format!("attest:{bridge_id}:{}", body.platform_user_id);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let stored = StoredAttestation {
        attestation_id: attestation_id.clone(),
        status: "active".to_owned(),
        bridge_id: bridge_id.clone(),
        platform_handle: body.platform_handle.clone(),
        platform_user_id: body.platform_user_id,
        evidence: body.attestation_evidence,
        issued_at: now,
        expires_at: now + ATTESTATION_TTL_SECS,
    };

    let response = AttestResponse {
        attestation_id: stored.attestation_id.clone(),
        status: stored.status.clone(),
        platform_handle: stored.platform_handle.clone(),
        issued_at: stored.issued_at,
        expires_at: stored.expires_at,
    };

    let mut attestations = bridge_state.attestations.write().await;
    attestations.insert(attestation_id, stored);

    (StatusCode::CREATED, Json(response)).into_response()
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Returns an axum [`Router`] serving bridge endpoints.
///
/// The router expects [`BridgeState`] as shared state and
/// [`BridgeAuthContext`] as a request extension (injected by the bridge
/// auth middleware layer applied by the caller).
pub fn bridge_router(state: Arc<BridgeState>) -> Router {
    Router::new()
        .route("/v1/scp/bridge/shadow", post(create_shadow_handler))
        .route("/v1/scp/bridge/attest", post(attest_handler))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use scp_core::bridge::{BridgeConnector, BridgeMode, BridgeStatus};
    use tower::ServiceExt;

    use crate::bridge_auth::{BridgeAuthContext, BridgeJwtClaims};

    fn test_claims() -> BridgeJwtClaims {
        BridgeJwtClaims {
            iss: "did:dht:z6MkTestOperator".to_owned(),
            aud: "https://node.example.com".to_owned(),
            iat: 1_700_000_000,
            exp: 1_700_003_600,
            scp_bridge_id: "bridge-test-001".to_owned(),
            scp_context_id: "ctx-test-001".to_owned(),
        }
    }

    fn test_auth_ctx() -> BridgeAuthContext {
        BridgeAuthContext {
            claims: test_claims(),
            bridge: BridgeConnector {
                bridge_id: "bridge-test-001".to_owned(),
                operator_did: scp_identity::DID("did:dht:z6MkTestOperator".to_owned()),
                platform: "discord".to_owned(),
                mode: BridgeMode::Relay,
                status: BridgeStatus::Active,
                registration_context: "ctx-test-001".to_owned(),
                registered_at: 1_700_000_000,
            },
        }
    }

    /// Builds the router with BridgeAuthContext injected as an extension
    /// (bypasses real auth middleware for unit tests).
    fn test_app(state: Arc<BridgeState>) -> Router {
        let auth_ctx = test_auth_ctx();
        Router::new()
            .route("/v1/scp/bridge/shadow", post(create_shadow_handler))
            .route("/v1/scp/bridge/attest", post(attest_handler))
            .layer(axum::Extension(auth_ctx))
            .with_state(state)
    }

    fn create_request(body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/scp/bridge/shadow")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).expect("test")))
            .expect("test")
    }

    fn attest_request(body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/scp/bridge/attest")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).expect("test")))
            .expect("test")
    }

    async fn response_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.expect("test").to_bytes();
        serde_json::from_slice(&bytes).expect("test")
    }

    #[tokio::test]
    async fn successful_creation_returns_201() {
        let state = Arc::new(BridgeState::new());
        let app = test_app(state);

        let req = create_request(serde_json::json!({
            "platform_handle": "@alice#1234",
            "platform_user_id": "user-alice-001"
        }));

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::CREATED);

        let json = response_json(resp).await;
        assert_eq!(json["platform_handle"], "@alice#1234");
        assert_eq!(json["platform_user_id"], "user-alice-001");
        assert_eq!(json["attributed_role"], "observer");
        assert_eq!(
            json["shadow_id"],
            "shadow:bridge-test-001:user-alice-001"
        );
        assert!(json["created_at"].as_u64().is_some());
    }

    #[tokio::test]
    async fn idempotent_creation_returns_200() {
        let state = Arc::new(BridgeState::new());

        // First creation.
        let app = test_app(Arc::clone(&state));
        let req = create_request(serde_json::json!({
            "platform_handle": "@alice#1234",
            "platform_user_id": "user-alice-001"
        }));
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Second creation with same platform_user_id — should return 200.
        let app = test_app(state);
        let req = create_request(serde_json::json!({
            "platform_handle": "@alice#1234",
            "platform_user_id": "user-alice-001"
        }));
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::OK);

        let json = response_json(resp).await;
        assert_eq!(json["shadow_id"], "shadow:bridge-test-001:user-alice-001");
        assert_eq!(json["attributed_role"], "observer");
    }

    #[tokio::test]
    async fn missing_platform_handle_returns_400() {
        let state = Arc::new(BridgeState::new());
        let app = test_app(state);

        let req = create_request(serde_json::json!({
            "platform_handle": "",
            "platform_user_id": "user-001"
        }));

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn missing_platform_user_id_returns_400() {
        let state = Arc::new(BridgeState::new());
        let app = test_app(state);

        let req = create_request(serde_json::json!({
            "platform_handle": "@alice",
            "platform_user_id": ""
        }));

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn missing_required_fields_returns_400() {
        let state = Arc::new(BridgeState::new());
        let app = test_app(state);

        // Body with no required fields at all.
        let req = create_request(serde_json::json!({}));

        let resp = app.oneshot(req).await.expect("test");
        // serde deserialization failure → 422 (axum default) or 400.
        // axum returns 422 for JSON deserialization errors by default.
        assert!(
            resp.status() == StatusCode::BAD_REQUEST
                || resp.status() == StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    // -----------------------------------------------------------------------
    // Attest endpoint tests
    // -----------------------------------------------------------------------

    fn valid_attest_body() -> serde_json::Value {
        serde_json::json!({
            "platform_handle": "@dave#1234",
            "platform_user_id": "usr_abc123",
            "attestation_evidence": {
                "evidence_type": "platform-verified",
                "verification_method": "oauth2",
                "verified_at": 1_700_000_300,
                "platform_confidence": "high",
                "additional_signals": {
                    "account_age_days": 730,
                    "email_verified": true
                }
            }
        })
    }

    #[tokio::test]
    async fn attest_successful_returns_201() {
        let state = Arc::new(BridgeState::new());
        let app = test_app(state);

        let req = attest_request(valid_attest_body());
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::CREATED);

        let json = response_json(resp).await;
        assert_eq!(json["status"], "active");
        assert_eq!(json["platform_handle"], "@dave#1234");
        assert_eq!(
            json["attestation_id"],
            "attest:bridge-test-001:usr_abc123"
        );
        assert!(json["issued_at"].as_u64().is_some());
        assert!(json["expires_at"].as_u64().is_some());

        let issued = json["issued_at"].as_u64().unwrap();
        let expires = json["expires_at"].as_u64().unwrap();
        assert_eq!(expires - issued, 86_400);
    }

    #[tokio::test]
    async fn attest_stores_attestation() {
        let state = Arc::new(BridgeState::new());
        let app = test_app(Arc::clone(&state));

        let req = attest_request(valid_attest_body());
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::CREATED);

        let attestations = state.attestations.read().await;
        let stored = attestations
            .get("attest:bridge-test-001:usr_abc123")
            .expect("attestation should be stored");
        assert_eq!(stored.platform_handle, "@dave#1234");
        assert_eq!(stored.evidence.evidence_type, "platform-verified");
        assert_eq!(stored.evidence.platform_confidence, "high");
    }

    #[tokio::test]
    async fn attest_empty_handle_returns_400() {
        let state = Arc::new(BridgeState::new());
        let app = test_app(state);

        let req = attest_request(serde_json::json!({
            "platform_handle": "",
            "platform_user_id": "usr_abc123",
            "attestation_evidence": {
                "evidence_type": "platform-verified",
                "verification_method": "oauth2",
                "verified_at": 1_700_000_300,
                "platform_confidence": "high"
            }
        }));

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn attest_empty_user_id_returns_400() {
        let state = Arc::new(BridgeState::new());
        let app = test_app(state);

        let req = attest_request(serde_json::json!({
            "platform_handle": "@dave#1234",
            "platform_user_id": "",
            "attestation_evidence": {
                "evidence_type": "platform-verified",
                "verification_method": "oauth2",
                "verified_at": 1_700_000_300,
                "platform_confidence": "high"
            }
        }));

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn attest_invalid_confidence_returns_400() {
        let state = Arc::new(BridgeState::new());
        let app = test_app(state);

        let req = attest_request(serde_json::json!({
            "platform_handle": "@dave#1234",
            "platform_user_id": "usr_abc123",
            "attestation_evidence": {
                "evidence_type": "platform-verified",
                "verification_method": "oauth2",
                "verified_at": 1_700_000_300,
                "platform_confidence": "very-high"
            }
        }));

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn attest_missing_evidence_returns_422() {
        let state = Arc::new(BridgeState::new());
        let app = test_app(state);

        let req = attest_request(serde_json::json!({
            "platform_handle": "@dave#1234",
            "platform_user_id": "usr_abc123"
        }));

        let resp = app.oneshot(req).await.expect("test");
        assert!(
            resp.status() == StatusCode::BAD_REQUEST
                || resp.status() == StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    #[tokio::test]
    async fn attest_without_additional_signals() {
        let state = Arc::new(BridgeState::new());
        let app = test_app(state);

        let req = attest_request(serde_json::json!({
            "platform_handle": "@dave#1234",
            "platform_user_id": "usr_abc123",
            "attestation_evidence": {
                "evidence_type": "oauth2",
                "verification_method": "oauth2-flow",
                "verified_at": 1_700_000_300,
                "platform_confidence": "medium"
            }
        }));

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::CREATED);

        let json = response_json(resp).await;
        assert_eq!(json["status"], "active");
    }
}
