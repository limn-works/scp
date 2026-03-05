//! Dev API handlers for local development and diagnostics.
//!
//! Provides the `/scp/dev/v1` endpoint family: health, identity, relay
//! status, and context management. All requests require bearer token
//! authentication (spec section 18.10.2). The token is validated using
//! constant-time comparison to prevent timing side-channel attacks.
//!
//! ## Endpoints
//!
//! | Method | Path | Handler |
//! |--------|------|---------|
//! | GET | `/scp/dev/v1/health` | [`health_handler`] |
//! | GET | `/scp/dev/v1/identity` | [`identity_handler`] |
//! | GET | `/scp/dev/v1/relay/status` | [`relay_status_handler`] |
//! | GET | `/scp/dev/v1/contexts` | [`list_contexts_handler`] |
//! | GET | `/scp/dev/v1/contexts/{id}` | [`get_context_handler`] |
//! | POST | `/scp/dev/v1/contexts` | [`create_context_handler`] |
//! | DELETE | `/scp/dev/v1/contexts/{id}` | [`delete_context_handler`] |
//!
//! See spec section 18.10 for the full dev API specification.

use std::sync::Arc;

use axum::Json;
use axum::body::Body;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{Request, StatusCode, header};
use axum::middleware::Next;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::error::ApiError;
use crate::http::NodeState;

// ---------------------------------------------------------------------------
// Bearer auth middleware
// ---------------------------------------------------------------------------

/// Axum middleware that validates bearer token authentication.
///
/// Extracts the `Authorization: Bearer <token>` header from incoming requests
/// and validates it against `expected_token` using constant-time comparison
/// (via [`subtle::ConstantTimeEq`]) to prevent timing side-channel attacks.
///
/// Returns HTTP 401 with a JSON error body if:
/// - The `Authorization` header is missing
/// - The header value is not in `Bearer <token>` format
/// - The provided token does not match the expected token
///
/// See spec section 18.10.2.
pub async fn bearer_auth_middleware(
    req: Request<Body>,
    next: Next,
    expected_token: String,
) -> impl IntoResponse {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    match auth_header {
        // RFC 7235 §2.1: auth-scheme tokens are case-insensitive.
        Some(value) if value.len() > 7 && value[..7].eq_ignore_ascii_case("bearer ") => {
            let provided = &value[7..];
            if bool::from(provided.as_bytes().ct_eq(expected_token.as_bytes())) {
                next.run(req).await.into_response()
            } else {
                ApiError::unauthorized().into_response()
            }
        }
        _ => ApiError::unauthorized().into_response(),
    }
}

// ---------------------------------------------------------------------------
// Host header validation (DNS rebinding protection)
// ---------------------------------------------------------------------------

/// Allowed Host header values for the dev API.
///
/// The dev API is intended for localhost access only (spec section 18.10.1).
/// This middleware rejects requests whose `Host` header does not match a
/// localhost pattern, preventing DNS rebinding attacks where a malicious
/// website resolves to 127.0.0.1 and accesses the dev API through the browser.
const ALLOWED_HOSTS: &[&str] = &["localhost", "127.0.0.1", "[::1]"];

/// Returns true if the `Host` header value is a localhost address,
/// optionally followed by a port (e.g., `localhost:8080`, `127.0.0.1:3000`,
/// `[::1]:8080`).
///
/// Handles RFC 3986 bracket notation for IPv6 addresses — `[::1]:8080`
/// is correctly parsed as hostname `[::1]`, not split on internal colons.
fn is_localhost_host(host: &str) -> bool {
    // IPv6 bracket notation: [::1] or [::1]:port
    let hostname = if host.starts_with('[') {
        // Find the closing bracket; everything up to and including it is the host.
        host.find(']').map_or(host, |end| &host[..=end])
    } else {
        // IPv4 or hostname: split on first ':' to strip port.
        host.split(':').next().unwrap_or(host)
    };
    ALLOWED_HOSTS
        .iter()
        .any(|h| hostname.eq_ignore_ascii_case(h))
}

/// Axum middleware that rejects requests with non-localhost Host headers.
///
/// Prevents DNS rebinding attacks against the dev API (spec section 18.10.1).
/// Returns HTTP 403 if the Host header is missing or does not match a
/// localhost address.
pub async fn localhost_host_middleware(req: Request<Body>, next: Next) -> impl IntoResponse {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok());

    match host {
        Some(h) if is_localhost_host(h) => next.run(req).await.into_response(),
        _ => {
            // No Host header or non-localhost Host — reject.
            ApiError::forbidden("forbidden: dev API only accessible via localhost").into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Security response headers
// ---------------------------------------------------------------------------

/// Axum middleware that sets security response headers on every dev API response.
///
/// Headers applied:
/// - `X-Content-Type-Options: nosniff` — prevents MIME sniffing
/// - `Cache-Control: no-store` — prevents caching of sensitive diagnostics
/// - `X-Frame-Options: DENY` — prevents clickjacking via iframe embedding
///
/// Also rejects CORS preflight (OPTIONS) requests with 403 Forbidden.
/// The dev API is localhost-only and must not be accessible cross-origin.
pub async fn security_headers_middleware(req: Request<Body>, next: Next) -> impl IntoResponse {
    // Reject CORS preflight requests explicitly.
    if req.method() == axum::http::Method::OPTIONS {
        return ApiError::forbidden("forbidden: CORS requests not allowed on dev API")
            .into_response();
    }

    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    headers.insert(
        axum::http::header::X_FRAME_OPTIONS,
        axum::http::HeaderValue::from_static("DENY"),
    );
    response
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Response body for `GET /scp/dev/v1/health`.
///
/// Reports basic health metrics for the running node. Fields that require
/// runtime wiring (e.g., `relay_connections`) use placeholder values until
/// SCP-245 connects real metrics.
///
/// See spec section 18.10.3.
#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    /// Seconds since the node was started.
    pub uptime_seconds: u64,
    /// Number of active relay connections.
    ///
    /// Placeholder (always 0) until SCP-245 wires real connection tracking.
    pub relay_connections: u64,
    /// Storage subsystem status. Currently always `"ok"`.
    pub storage_status: String,
}

/// Response body for `GET /scp/dev/v1/identity`.
///
/// Returns the node operator's DID string and document. The `document` field
/// currently returns the DID string as a placeholder until full
/// [`DidDocument`](scp_core::identity::document::DidDocument) serialization
/// is wired through `NodeState`.
///
/// See spec section 18.10.3.
#[derive(Debug, Clone, Serialize)]
pub struct IdentityResponse {
    /// The operator's DID string (e.g., `did:dht:...`).
    pub did: String,
    /// The DID document. Currently returns the DID string as a placeholder
    /// until the full document is available in `NodeState`.
    pub document: String,
}

/// Response body for `GET /scp/dev/v1/relay/status`.
///
/// Reports relay server status. Fields that require runtime wiring use
/// placeholder values until SCP-245 connects real metrics.
///
/// See spec section 18.10.3.
#[derive(Debug, Clone, Serialize)]
pub struct RelayStatusResponse {
    /// The address the relay server is bound to (e.g., `127.0.0.1:9000`).
    pub bound_addr: String,
    /// Number of active WebSocket connections to the relay.
    ///
    /// Placeholder (always 0) until SCP-245 wires real connection tracking.
    pub active_connections: u64,
    /// Number of blobs stored in the blob storage backend.
    ///
    /// Placeholder (always 0) until SCP-245 wires real blob counting.
    pub blob_count: u64,
}

/// Response body for context endpoints (`GET /scp/dev/v1/contexts` and
/// `GET /scp/dev/v1/contexts/{id}`).
///
/// Represents a registered broadcast context with its metadata. The `mode`
/// field is always `"broadcast"` in the current implementation. The
/// `subscriber_count` field is a placeholder (always 0) until real
/// subscriber tracking is wired.
///
/// See spec section 18.10.3.
#[derive(Debug, Clone, Serialize)]
pub struct ContextResponse {
    /// Context ID (hex-encoded).
    pub id: String,
    /// Human-readable context name (advisory, may be absent).
    pub name: Option<String>,
    /// Context mode. Currently always `"broadcast"`.
    pub mode: String,
    /// Number of active subscribers.
    ///
    /// Placeholder (always 0) until real subscriber tracking is wired.
    pub subscriber_count: u64,
}

impl From<&crate::http::BroadcastContext> for ContextResponse {
    fn from(ctx: &crate::http::BroadcastContext) -> Self {
        Self {
            id: ctx.id.clone(),
            name: ctx.name.clone(),
            mode: "broadcast".to_owned(),
            subscriber_count: 0,
        }
    }
}

/// Request body for `POST /scp/dev/v1/contexts`.
///
/// Registers a new broadcast context. The `id` field is required; `name` is
/// an optional human-readable label.
///
/// See spec section 18.10.3.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateContextRequest {
    /// Context ID (hex-encoded).
    pub id: String,
    /// Human-readable context name (advisory).
    pub name: Option<String>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handler for `GET /scp/dev/v1/health`.
///
/// Returns a [`HealthResponse`] with the node's uptime (computed from
/// [`NodeState::start_time`]), relay connection count, and storage status.
///
/// See spec section 18.10.3.
pub async fn health_handler(State(state): State<Arc<NodeState>>) -> impl IntoResponse {
    let uptime = state.start_time.elapsed().as_secs();

    (
        StatusCode::OK,
        Json(HealthResponse {
            uptime_seconds: uptime,
            // TODO(SCP-245): wire real relay connection count
            relay_connections: 0,
            storage_status: "ok".to_owned(),
        }),
    )
}

/// Handler for `GET /scp/dev/v1/identity`.
///
/// Returns an [`IdentityResponse`] with the node operator's DID string and
/// document. The document field is a placeholder until full `DidDocument`
/// serialization is available in `NodeState`.
///
/// See spec section 18.10.3.
pub async fn identity_handler(State(state): State<Arc<NodeState>>) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(IdentityResponse {
            did: state.did.clone(),
            // TODO: return full DidDocument once it is stored in NodeState
            document: state.did.clone(),
        }),
    )
}

/// Handler for `GET /scp/dev/v1/relay/status`.
///
/// Returns a [`RelayStatusResponse`] with the relay's bound address, active
/// connection count, and blob count. Connection and blob counts are
/// placeholders until SCP-245 wires real metrics.
///
/// See spec section 18.10.3.
pub async fn relay_status_handler(State(state): State<Arc<NodeState>>) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(RelayStatusResponse {
            bound_addr: state.relay_addr.to_string(),
            // TODO(SCP-245): wire real active connection count
            active_connections: 0,
            // TODO(SCP-245): wire real blob count from storage backend
            blob_count: 0,
        }),
    )
}

/// Handler for `GET /scp/dev/v1/contexts`.
///
/// Returns a JSON array of all registered broadcast contexts as
/// [`ContextResponse`] values. Returns an empty array when no contexts
/// are registered.
///
/// See spec section 18.10.3.
pub async fn list_contexts_handler(State(state): State<Arc<NodeState>>) -> impl IntoResponse {
    let responses: Vec<ContextResponse> = state
        .broadcast_contexts
        .read()
        .await
        .values()
        .map(ContextResponse::from)
        .collect();

    (StatusCode::OK, Json(responses))
}

/// Handler for `GET /scp/dev/v1/contexts/{id}`.
///
/// Returns the [`ContextResponse`] for the context matching the given `id`
/// path parameter. Returns HTTP 404 if no context with that ID is
/// registered.
///
/// See spec section 18.10.3.
pub async fn get_context_handler(
    State(state): State<Arc<NodeState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let id = id.to_ascii_lowercase();
    let contexts = state.broadcast_contexts.read().await;
    contexts.get(&id).map_or_else(
        || ApiError::not_found(format!("context {id} not found")).into_response(),
        |ctx| (StatusCode::OK, Json(ContextResponse::from(ctx))).into_response(),
    )
}

/// Maximum allowed length for a context ID (hex-encoded, so 64 chars for 32 bytes).
const MAX_CONTEXT_ID_LEN: usize = 64;
/// Maximum allowed length for a context name.
const MAX_CONTEXT_NAME_LEN: usize = 256;

/// Handler for `POST /scp/dev/v1/contexts`.
///
/// Parses a [`CreateContextRequest`] JSON body and registers a new
/// broadcast context. Returns HTTP 201 Created with the newly created
/// [`ContextResponse`].
///
/// Validates:
/// - `id` is non-empty, ASCII hex only, max 64 chars (32 bytes hex-encoded)
/// - `name` (if present) is max 256 chars, no control characters
/// - No duplicate context ID already registered
///
/// See spec section 18.10.3.
pub async fn create_context_handler(
    State(state): State<Arc<NodeState>>,
    body: Result<Json<CreateContextRequest>, JsonRejection>,
) -> impl IntoResponse {
    // Unwrap JSON body, mapping extraction failures to ApiError (spec §18.10.4).
    let Ok(Json(body)) = body else {
        return ApiError::bad_request("invalid JSON body").into_response();
    };

    // Validate context ID: non-empty, hex-only, bounded length.
    if body.id.is_empty() || body.id.len() > MAX_CONTEXT_ID_LEN {
        return ApiError::bad_request(format!(
            "context id must be 1-{MAX_CONTEXT_ID_LEN} characters"
        ))
        .into_response();
    }
    if !body.id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return ApiError::bad_request("context id must contain only hex characters")
            .into_response();
    }

    // Normalize to lowercase so mixed-case hex values are not treated as distinct.
    let id = body.id.to_ascii_lowercase();

    // Validate context name if present: bounded length, no control chars.
    // Use chars().count() for correct Unicode character counting.
    if let Some(ref name) = body.name {
        if name.chars().count() > MAX_CONTEXT_NAME_LEN {
            return ApiError::bad_request(format!(
                "context name must be at most {MAX_CONTEXT_NAME_LEN} characters"
            ))
            .into_response();
        }
        if name.chars().any(char::is_control) {
            return ApiError::bad_request("context name must not contain control characters")
                .into_response();
        }
    }

    let mut contexts = state.broadcast_contexts.write().await;

    // Reject duplicate context IDs (compared against normalized lowercase).
    if contexts.contains_key(&id) {
        return ApiError::conflict(format!("context {id} already exists")).into_response();
    }

    // Enforce broadcast context limit (mirrors MAX_PROJECTED_CONTEXTS).
    if contexts.len() >= crate::MAX_BROADCAST_CONTEXTS {
        return ApiError::bad_request(format!(
            "broadcast context limit ({}) reached",
            crate::MAX_BROADCAST_CONTEXTS
        ))
        .into_response();
    }

    let ctx = crate::http::BroadcastContext {
        id: id.clone(),
        name: body.name,
    };
    let response = ContextResponse::from(&ctx);
    contexts.insert(id.clone(), ctx);
    drop(contexts);

    // Include Location header per HTTP semantics for 201 Created.
    let location = format!("/scp/dev/v1/contexts/{id}");
    let mut headers = axum::http::HeaderMap::new();
    if let Ok(val) = axum::http::HeaderValue::from_str(&location) {
        headers.insert(axum::http::header::LOCATION, val);
    }

    (StatusCode::CREATED, headers, Json(response)).into_response()
}

/// Handler for `DELETE /scp/dev/v1/contexts/{id}`.
///
/// Removes the broadcast context matching the given `id` path parameter.
/// Returns HTTP 204 No Content on success, or HTTP 404 if no context with
/// that ID is registered.
///
/// See spec section 18.10.3.
pub async fn delete_context_handler(
    State(state): State<Arc<NodeState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let id = id.to_ascii_lowercase();
    let mut contexts = state.broadcast_contexts.write().await;

    if contexts.remove(&id).is_some() {
        StatusCode::NO_CONTENT.into_response()
    } else {
        ApiError::not_found(format!("context {id} not found")).into_response()
    }
}

// ---------------------------------------------------------------------------
// Router constructor
// ---------------------------------------------------------------------------

/// Returns an axum [`Router`] serving the dev API endpoints under
/// `/scp/dev/v1`.
///
/// All routes are protected by bearer token authentication. The `token`
/// parameter is the expected bearer token (format:
/// `scp_local_token_<32 hex chars>`). Requests without a valid
/// `Authorization: Bearer <token>` header receive HTTP 401.
///
/// See spec section 18.10.2.
/// Maximum request body size for the dev API (64 KiB).
/// Prevents unbounded memory allocation from oversized POST bodies.
const DEV_API_MAX_BODY_SIZE: usize = 64 * 1024;

pub fn dev_router(state: Arc<NodeState>, token: String) -> axum::Router {
    use axum::middleware;
    use axum::routing::get;

    let expected = token;
    axum::Router::new()
        .route("/scp/dev/v1/health", get(health_handler))
        .route("/scp/dev/v1/identity", get(identity_handler))
        .route("/scp/dev/v1/relay/status", get(relay_status_handler))
        .route(
            "/scp/dev/v1/contexts",
            get(list_contexts_handler).post(create_context_handler),
        )
        .route(
            "/scp/dev/v1/contexts/{id}",
            get(get_context_handler).delete(delete_context_handler),
        )
        .layer(axum::extract::DefaultBodyLimit::max(DEV_API_MAX_BODY_SIZE))
        // Axum layers are LIFO: last added = outermost = runs first.
        //
        // Execution order (outermost → innermost):
        //   1. Security headers — sets X-Content-Type-Options, Cache-Control,
        //      X-Frame-Options on ALL responses (including auth/host rejections),
        //      and rejects CORS preflight requests.
        //   2. Host check — cheapest rejection, prevents DNS rebinding.
        //   3. Bearer auth — validates token, rejects unauthorized requests.
        //   4. Body limit — enforces 64 KiB max on POST bodies.
        //   5. Route handlers.
        .layer(middleware::from_fn(move |req, next| {
            bearer_auth_middleware(req, next, expected.clone())
        }))
        .layer(middleware::from_fn(localhost_host_middleware))
        .layer(middleware::from_fn(security_headers_middleware))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Instant;

    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use http_body_util::BodyExt;
    use scp_transport::native::storage::BlobStorageBackend;
    use tokio::sync::RwLock;
    use tower::ServiceExt;

    use crate::http::NodeState;

    use super::*;

    /// Valid bearer token used across all dev API tests.
    const TEST_TOKEN: &str = "scp_local_token_abcdef1234567890abcdef1234567890";

    /// Helper: creates an HTTP request builder with `Host: localhost` pre-set.
    /// All dev API test requests must include a localhost Host header for the
    /// DNS-rebinding protection middleware.
    fn localhost_request() -> axum::http::request::Builder {
        Request::builder().header(header::HOST, "localhost")
    }

    /// Creates a test `NodeState` with the given dev token.
    fn test_state(token: &str) -> Arc<NodeState> {
        Arc::new(NodeState {
            did: "did:dht:test123".to_owned(),
            relay_url: "wss://localhost/scp/v1".to_owned(),
            broadcast_contexts: RwLock::new(HashMap::new()),
            relay_addr: "127.0.0.1:9000".parse::<SocketAddr>().unwrap(),
            bridge_secret: zeroize::Zeroizing::new([0u8; 32]),
            dev_token: Some(token.to_owned()),
            dev_bind_addr: Some("127.0.0.1:9100".parse::<SocketAddr>().unwrap()),
            projected_contexts: RwLock::new(HashMap::new()),
            blob_storage: Arc::new(BlobStorageBackend::default()),
            relay_config: scp_transport::native::server::RelayConfig::default(),
            start_time: Instant::now(),
            http_bind_addr: SocketAddr::from(([0, 0, 0, 0], 8443)),
            shutdown_token: tokio_util::sync::CancellationToken::new(),
            cors_origins: None,
            projection_rate_limiter: scp_transport::relay::rate_limit::PublishRateLimiter::new(
                1000,
            ),
            tls_config: None,
            cert_resolver: None,
        })
    }

    #[tokio::test]
    async fn valid_token_passes_middleware() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        let router = dev_router(state, token.to_owned());

        let req = localhost_request()
            .uri("/scp/dev/v1/health")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("uptime_seconds").is_some());
        assert!(json.get("relay_connections").is_some());
        assert!(json.get("storage_status").is_some());
    }

    #[tokio::test]
    async fn invalid_token_returns_401() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        let router = dev_router(state, token.to_owned());

        let req = localhost_request()
            .uri("/scp/dev/v1/health")
            .header(header::AUTHORIZATION, "Bearer wrong_token")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "unauthorized");
        assert_eq!(json["code"], "UNAUTHORIZED");
    }

    #[tokio::test]
    async fn non_localhost_host_returns_403() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        let router = dev_router(state, token.to_owned());

        // DNS rebinding: request with external Host header should be rejected.
        let req = Request::builder()
            .uri("/scp/dev/v1/health")
            .header(header::HOST, "evil.example.com")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "FORBIDDEN");
    }

    #[tokio::test]
    async fn ipv6_localhost_host_accepted() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        let router = dev_router(state, token.to_owned());

        // [::1]:8080 is valid localhost — must not be rejected.
        let req = Request::builder()
            .uri("/scp/dev/v1/health")
            .header(header::HOST, "[::1]:8080")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn ipv6_localhost_host_without_port_accepted() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        let router = dev_router(state, token.to_owned());

        // [::1] without port is also valid localhost.
        let req = Request::builder()
            .uri("/scp/dev/v1/health")
            .header(header::HOST, "[::1]")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_header_returns_401() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        let router = dev_router(state, token.to_owned());

        let req = localhost_request()
            .uri("/scp/dev/v1/health")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "unauthorized");
        assert_eq!(json["code"], "UNAUTHORIZED");
    }

    #[tokio::test]
    async fn identity_handler_returns_did() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        let router = dev_router(state, token.to_owned());

        let req = localhost_request()
            .uri("/scp/dev/v1/identity")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["did"], "did:dht:test123");
        assert!(json.get("document").is_some());
    }

    #[tokio::test]
    async fn relay_status_handler_returns_addr() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        let router = dev_router(state, token.to_owned());

        let req = localhost_request()
            .uri("/scp/dev/v1/relay/status")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["bound_addr"], "127.0.0.1:9000");
        assert_eq!(json["active_connections"], 0);
        assert_eq!(json["blob_count"], 0);
    }

    #[tokio::test]
    async fn all_responses_are_json_content_type() {
        let token = TEST_TOKEN;
        let state = test_state(token);

        let paths = [
            "/scp/dev/v1/health",
            "/scp/dev/v1/identity",
            "/scp/dev/v1/relay/status",
        ];

        for path in paths {
            let router = dev_router(Arc::clone(&state), token.to_owned());
            let req = localhost_request()
                .uri(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap();

            let resp = router.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "path: {path}");

            let content_type = resp
                .headers()
                .get(header::CONTENT_TYPE)
                .expect("missing Content-Type header")
                .to_str()
                .unwrap();
            assert!(
                content_type.contains("application/json"),
                "path {path} has Content-Type: {content_type}"
            );
        }
    }

    // -- Context management endpoint tests --

    #[tokio::test]
    async fn list_contexts_returns_empty_array() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        let router = dev_router(state, token.to_owned());

        let req = localhost_request()
            .uri("/scp/dev/v1/contexts")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json, serde_json::json!([]));
    }

    #[tokio::test]
    async fn list_contexts_returns_registered_contexts() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        state.broadcast_contexts.write().await.insert(
            "aa11bb22".to_owned(),
            crate::http::BroadcastContext {
                id: "aa11bb22".to_owned(),
                name: Some("Test Context".to_owned()),
            },
        );
        let router = dev_router(state, token.to_owned());

        let req = localhost_request()
            .uri("/scp/dev/v1/contexts")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["id"], "aa11bb22");
        assert_eq!(arr[0]["name"], "Test Context");
        assert_eq!(arr[0]["mode"], "broadcast");
        assert_eq!(arr[0]["subscriber_count"], 0);
    }

    #[tokio::test]
    async fn get_context_returns_found() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        state.broadcast_contexts.write().await.insert(
            "abcdef01".to_owned(),
            crate::http::BroadcastContext {
                id: "abcdef01".to_owned(),
                name: Some("My Context".to_owned()),
            },
        );
        let router = dev_router(state, token.to_owned());

        let req = localhost_request()
            .uri("/scp/dev/v1/contexts/abcdef01")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["id"], "abcdef01");
        assert_eq!(json["name"], "My Context");
        assert_eq!(json["mode"], "broadcast");
        assert_eq!(json["subscriber_count"], 0);
    }

    #[tokio::test]
    async fn get_context_returns_404_for_unknown() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        let router = dev_router(state, token.to_owned());

        let req = localhost_request()
            .uri("/scp/dev/v1/contexts/nonexistent")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "NOT_FOUND");
    }

    #[tokio::test]
    async fn create_context_returns_201() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        let router = dev_router(Arc::clone(&state), token.to_owned());

        let req = localhost_request()
            .method("POST")
            .uri("/scp/dev/v1/contexts")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "id": "cc33dd44",
                    "name": "New Context"
                }))
                .unwrap(),
            ))
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["id"], "cc33dd44");
        assert_eq!(json["name"], "New Context");
        assert_eq!(json["mode"], "broadcast");
        assert_eq!(json["subscriber_count"], 0);

        // Verify context was actually stored
        let contexts = state.broadcast_contexts.read().await;
        assert_eq!(contexts.len(), 1);
        assert!(contexts.contains_key("cc33dd44"));
        drop(contexts);
    }

    #[tokio::test]
    async fn create_context_without_name() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        let router = dev_router(state, token.to_owned());

        let req = localhost_request()
            .method("POST")
            .uri("/scp/dev/v1/contexts")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"id":"ee55ff66"}"#))
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["id"], "ee55ff66");
        assert!(json["name"].is_null());
    }

    #[tokio::test]
    async fn delete_context_returns_204() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        state.broadcast_contexts.write().await.insert(
            "d00aed".to_owned(),
            crate::http::BroadcastContext {
                id: "d00aed".to_owned(),
                name: None,
            },
        );
        let router = dev_router(Arc::clone(&state), token.to_owned());

        let req = localhost_request()
            .method("DELETE")
            .uri("/scp/dev/v1/contexts/d00aed")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Verify context was removed
        assert!(state.broadcast_contexts.read().await.is_empty());
    }

    #[tokio::test]
    async fn delete_context_returns_404_for_unknown() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        let router = dev_router(state, token.to_owned());

        let req = localhost_request()
            .method("DELETE")
            .uri("/scp/dev/v1/contexts/nonexistent")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "NOT_FOUND");
    }

    #[tokio::test]
    async fn context_endpoints_require_auth() {
        let token = TEST_TOKEN;
        let state = test_state(token);

        // Test all context endpoints without auth
        let uris_and_methods: Vec<(&str, &str)> = vec![
            ("GET", "/scp/dev/v1/contexts"),
            ("GET", "/scp/dev/v1/contexts/any-id"),
            ("DELETE", "/scp/dev/v1/contexts/any-id"),
        ];

        for (method, uri) in uris_and_methods {
            let router = dev_router(Arc::clone(&state), token.to_owned());
            let req = localhost_request()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .unwrap();

            let resp = router.oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {uri} should require auth"
            );
        }

        // POST with body but no auth
        let router = dev_router(Arc::clone(&state), token.to_owned());
        let req = localhost_request()
            .method("POST")
            .uri("/scp/dev/v1/contexts")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"id":"aabb0011"}"#))
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn create_context_rejects_non_hex_id() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        let router = dev_router(state, token.to_owned());

        let req = localhost_request()
            .method("POST")
            .uri("/scp/dev/v1/contexts")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"id":"not-valid-hex!"}"#))
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "BAD_REQUEST");
    }

    #[tokio::test]
    async fn create_context_rejects_empty_id() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        let router = dev_router(state, token.to_owned());

        let req = localhost_request()
            .method("POST")
            .uri("/scp/dev/v1/contexts")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"id":""}"#))
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_context_rejects_duplicate_id() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        state.broadcast_contexts.write().await.insert(
            "aabb0011".to_owned(),
            crate::http::BroadcastContext {
                id: "aabb0011".to_owned(),
                name: None,
            },
        );
        let router = dev_router(state, token.to_owned());

        let req = localhost_request()
            .method("POST")
            .uri("/scp/dev/v1/contexts")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"id":"aabb0011"}"#))
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "CONFLICT");
    }

    // -- Tests A-I: additional coverage for confirmed findings --

    /// Test A: Wrong bearer token returns 401 with correct error shape.
    #[tokio::test]
    async fn wrong_bearer_token_returns_401_with_error_shape() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        let router = dev_router(state, token.to_owned());

        let req = localhost_request()
            .uri("/scp/dev/v1/health")
            .header(header::AUTHORIZATION, "Bearer wrong_token_here")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let content_type = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("missing Content-Type on 401")
            .to_str()
            .unwrap();
        assert!(
            content_type.contains("application/json"),
            "401 response should be JSON, got: {content_type}"
        );

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "unauthorized");
        assert_eq!(json["code"], "UNAUTHORIZED");
    }

    /// Test B: Case-insensitive bearer scheme (RFC 7235 §2.1).
    #[tokio::test]
    async fn bearer_scheme_case_insensitive() {
        let token = TEST_TOKEN;
        let state = test_state(token);

        // lowercase "bearer"
        let router = dev_router(Arc::clone(&state), token.to_owned());
        let req = localhost_request()
            .uri("/scp/dev/v1/health")
            .header(header::AUTHORIZATION, format!("bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "lowercase 'bearer' should pass"
        );

        // uppercase "BEARER"
        let router = dev_router(Arc::clone(&state), token.to_owned());
        let req = localhost_request()
            .uri("/scp/dev/v1/health")
            .header(header::AUTHORIZATION, format!("BEARER {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "uppercase 'BEARER' should pass"
        );

        // mixed case "BeArEr"
        let router = dev_router(Arc::clone(&state), token.to_owned());
        let req = localhost_request()
            .uri("/scp/dev/v1/health")
            .header(header::AUTHORIZATION, format!("BeArEr {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "mixed case 'BeArEr' should pass"
        );
    }

    /// Test C: Non-bearer auth scheme returns 401.
    #[tokio::test]
    async fn non_bearer_auth_scheme_returns_401() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        let router = dev_router(state, token.to_owned());

        let req = localhost_request()
            .uri("/scp/dev/v1/health")
            .header(header::AUTHORIZATION, "Basic dXNlcjpwYXNz")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "UNAUTHORIZED");
    }

    /// Test D: Context ID exceeding `MAX_CONTEXT_ID_LEN` returns 400.
    #[tokio::test]
    async fn create_context_rejects_oversized_id() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        let router = dev_router(state, token.to_owned());

        let oversized_id = "a".repeat(MAX_CONTEXT_ID_LEN + 1);
        let body_json = serde_json::json!({ "id": oversized_id });

        let req = localhost_request()
            .method("POST")
            .uri("/scp/dev/v1/contexts")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_string(&body_json).unwrap()))
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "BAD_REQUEST");
        assert!(
            json["error"]
                .as_str()
                .unwrap()
                .contains(&MAX_CONTEXT_ID_LEN.to_string()),
            "error message should mention the max length"
        );
    }

    /// Test E: Context name exceeding `MAX_CONTEXT_NAME_LEN` returns 400.
    #[tokio::test]
    async fn create_context_rejects_oversized_name() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        let router = dev_router(state, token.to_owned());

        let oversized_name = "a".repeat(MAX_CONTEXT_NAME_LEN + 1);
        let body_json = serde_json::json!({ "id": "aabb", "name": oversized_name });

        let req = localhost_request()
            .method("POST")
            .uri("/scp/dev/v1/contexts")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_string(&body_json).unwrap()))
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "BAD_REQUEST");
        assert!(
            json["error"]
                .as_str()
                .unwrap()
                .contains(&MAX_CONTEXT_NAME_LEN.to_string()),
            "error message should mention the max length"
        );
    }

    /// Test F: Context name with control characters returns 400.
    #[tokio::test]
    async fn create_context_rejects_control_chars_in_name() {
        let token = TEST_TOKEN;
        let state = test_state(token);

        let names_with_control = [
            "name\x00with_null",
            "name\x1fwith_unit_sep",
            "\ttabbed",
            "new\nline",
        ];

        for bad_name in names_with_control {
            let router = dev_router(Arc::clone(&state), token.to_owned());
            let body_json = serde_json::json!({ "id": "aabb", "name": bad_name });

            let req = localhost_request()
                .method("POST")
                .uri("/scp/dev/v1/contexts")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_string(&body_json).unwrap()))
                .unwrap();

            let resp = router.oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "name with control char should be rejected: {bad_name:?}"
            );

            let body = resp.into_body().collect().await.unwrap().to_bytes();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["code"], "BAD_REQUEST");
        }
    }

    /// Test G: Malformed JSON body returns 400 with JSON error (not plain text).
    #[tokio::test]
    async fn malformed_json_returns_400_with_json_body() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        let router = dev_router(state, token.to_owned());

        // Send {"id": 42} -- number instead of string
        let req = localhost_request()
            .method("POST")
            .uri("/scp/dev/v1/contexts")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"id": 42}"#))
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let content_type = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("missing Content-Type on malformed JSON 400")
            .to_str()
            .unwrap();
        assert!(
            content_type.contains("application/json"),
            "malformed JSON error should be JSON, got: {content_type}"
        );

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "BAD_REQUEST");
        assert!(
            json.get("error").is_some(),
            "error response must include 'error' field"
        );
    }

    /// Test G (cont.): Completely invalid JSON returns 400 with JSON body.
    #[tokio::test]
    async fn invalid_json_syntax_returns_400_with_json_body() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        let router = dev_router(state, token.to_owned());

        let req = localhost_request()
            .method("POST")
            .uri("/scp/dev/v1/contexts")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("not json at all"))
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let content_type = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("missing Content-Type")
            .to_str()
            .unwrap();
        assert!(
            content_type.contains("application/json"),
            "invalid JSON syntax error should be JSON, got: {content_type}"
        );

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "BAD_REQUEST");
    }

    /// Test H: Mixed-case hex context IDs are normalized to lowercase.
    #[tokio::test]
    async fn context_id_normalized_to_lowercase() {
        let token = TEST_TOKEN;
        let state = test_state(token);

        // Create context with uppercase ID.
        let router = dev_router(Arc::clone(&state), token.to_owned());
        let req = localhost_request()
            .method("POST")
            .uri("/scp/dev/v1/contexts")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"id":"AABB","name":"Upper"}"#))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Response should contain normalized lowercase ID.
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["id"], "aabb",
            "created ID should be normalized to lowercase"
        );

        // GET /contexts/aabb should find it.
        let router = dev_router(Arc::clone(&state), token.to_owned());
        let req = localhost_request()
            .uri("/scp/dev/v1/contexts/aabb")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "lowercase lookup should find it"
        );

        // GET /contexts/AABB should also find it (lookup is normalized).
        let router = dev_router(Arc::clone(&state), token.to_owned());
        let req = localhost_request()
            .uri("/scp/dev/v1/contexts/AABB")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "uppercase lookup should also find it (normalized)"
        );

        // Creating with "aabb" should be rejected as duplicate.
        let router = dev_router(Arc::clone(&state), token.to_owned());
        let req = localhost_request()
            .method("POST")
            .uri("/scp/dev/v1/contexts")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"id":"aabb"}"#))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CONFLICT,
            "lowercase duplicate of uppercase should conflict"
        );

        // DELETE /contexts/AaBb should work (normalized).
        let router = dev_router(Arc::clone(&state), token.to_owned());
        let req = localhost_request()
            .method("DELETE")
            .uri("/scp/dev/v1/contexts/AaBb")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NO_CONTENT,
            "mixed-case delete should find the normalized ID"
        );
    }

    /// Sends a request and asserts the response has the expected status and
    /// `application/json` Content-Type (skipped for 204 No Content).
    async fn assert_json_content_type(
        state: &Arc<NodeState>,
        token: &str,
        method: &str,
        path: &str,
        body: Option<&str>,
        expected_status: StatusCode,
        desc: &str,
    ) {
        let router = dev_router(Arc::clone(state), token.to_owned());
        let mut builder = localhost_request()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"));
        if body.is_some() {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
        }
        let req = builder
            .body(body.map_or_else(Body::empty, |b| Body::from(b.to_owned())))
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), expected_status, "{desc}: wrong status");

        if expected_status != StatusCode::NO_CONTENT {
            let content_type = resp
                .headers()
                .get(header::CONTENT_TYPE)
                .unwrap_or_else(|| panic!("{desc}: missing Content-Type header"))
                .to_str()
                .unwrap();
            assert!(
                content_type.contains("application/json"),
                "{desc}: Content-Type should be JSON, got: {content_type}"
            );
        }
    }

    /// Test I (part 1): Success and error endpoints return JSON Content-Type.
    #[tokio::test]
    async fn success_endpoints_return_json_content_type() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        state.broadcast_contexts.write().await.insert(
            "deadbeef".to_owned(),
            crate::http::BroadcastContext {
                id: "deadbeef".to_owned(),
                name: Some("Test".to_owned()),
            },
        );

        let cases: &[(&str, &str, Option<&str>, StatusCode, &str)] = &[
            (
                "GET",
                "/scp/dev/v1/health",
                None,
                StatusCode::OK,
                "health 200",
            ),
            (
                "GET",
                "/scp/dev/v1/identity",
                None,
                StatusCode::OK,
                "identity 200",
            ),
            (
                "GET",
                "/scp/dev/v1/relay/status",
                None,
                StatusCode::OK,
                "relay status 200",
            ),
            (
                "GET",
                "/scp/dev/v1/contexts",
                None,
                StatusCode::OK,
                "list contexts 200",
            ),
            (
                "GET",
                "/scp/dev/v1/contexts/deadbeef",
                None,
                StatusCode::OK,
                "get context 200",
            ),
        ];

        for &(method, path, body, expected_status, desc) in cases {
            assert_json_content_type(&state, token, method, path, body, expected_status, desc)
                .await;
        }
    }

    /// Test I (part 2): Error responses and create/auth return JSON Content-Type.
    #[tokio::test]
    async fn error_and_create_endpoints_return_json_content_type() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        state.broadcast_contexts.write().await.insert(
            "deadbeef".to_owned(),
            crate::http::BroadcastContext {
                id: "deadbeef".to_owned(),
                name: Some("Test".to_owned()),
            },
        );

        let error_cases: &[(&str, &str, Option<&str>, StatusCode, &str)] = &[
            (
                "GET",
                "/scp/dev/v1/contexts/nonexistent",
                None,
                StatusCode::NOT_FOUND,
                "get 404",
            ),
            (
                "DELETE",
                "/scp/dev/v1/contexts/nonexistent",
                None,
                StatusCode::NOT_FOUND,
                "del 404",
            ),
            (
                "POST",
                "/scp/dev/v1/contexts",
                Some(r#"{"id":""}"#),
                StatusCode::BAD_REQUEST,
                "empty 400",
            ),
            (
                "POST",
                "/scp/dev/v1/contexts",
                Some(r#"{"id":"deadbeef"}"#),
                StatusCode::CONFLICT,
                "dup 409",
            ),
        ];

        for &(method, path, body, expected_status, desc) in error_cases {
            assert_json_content_type(&state, token, method, path, body, expected_status, desc)
                .await;
        }

        // POST 201 (create) -- separate because it changes state.
        assert_json_content_type(
            &state,
            token,
            "POST",
            "/scp/dev/v1/contexts",
            Some(r#"{"id":"cafe0001","name":"Test I"}"#),
            StatusCode::CREATED,
            "create 201",
        )
        .await;

        // Unauthenticated 401.
        let router = dev_router(Arc::clone(&state), token.to_owned());
        let req = localhost_request()
            .uri("/scp/dev/v1/health")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "unauth 401");
        let content_type = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("unauth 401: missing Content-Type")
            .to_str()
            .unwrap();
        assert!(
            content_type.contains("application/json"),
            "unauth 401: Content-Type should be JSON, got: {content_type}"
        );
    }

    // -----------------------------------------------------------------------
    // Security headers
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn responses_include_security_headers() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        let router = dev_router(state, token.to_owned());

        let req = localhost_request()
            .uri("/scp/dev/v1/health")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        assert_eq!(
            resp.headers().get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff"
        );
        assert_eq!(
            resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(resp.headers().get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
    }

    #[tokio::test]
    async fn security_headers_on_error_responses() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        let router = dev_router(state, token.to_owned());

        // 401 response should also have security headers.
        let req = localhost_request()
            .uri("/scp/dev/v1/health")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers().get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff"
        );
    }

    #[tokio::test]
    async fn cors_preflight_rejected() {
        let token = TEST_TOKEN;
        let state = test_state(token);
        let router = dev_router(state, token.to_owned());

        let req = Request::builder()
            .method(axum::http::Method::OPTIONS)
            .uri("/scp/dev/v1/health")
            .header(header::HOST, "localhost")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "FORBIDDEN");
    }
}
