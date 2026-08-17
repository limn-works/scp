//! End-to-end proof that a governance-approved bridge registration reaches a
//! node's bridge endpoints (spec §12.2.1, §12.10.2, §12.10.6 step 1).
//!
//! Before this wire existed, `StorageBridgeLookup::register_bridge`,
//! `register_did_document`, and `register_webhook_key` had call sites only in
//! `#[cfg(test)]` code, so a shipped node hydrated an empty cache at startup and
//! answered `BRIDGE_NOT_AUTHORIZED` (401) to every bridge request forever. Every
//! scope rule the handlers enforce sat behind that 401 and never ran.
//!
//! Each test here drives one path a shipped node runs:
//!
//! ```text
//! scp_protocol register_bridge + approve_registration   (governance, §12.2.1)
//!   → ApplicationNode::register_bridge                  (node admission, §12.10.6)
//!     → StorageBridgeLookup                             (the store auth reads)
//!       → http::build_bridge_routers                    (the mounted endpoints)
//!         → bridge_auth_middleware_dyn                  (§12.10.2 bearer token)
//!         → webhook_auth_middleware_dyn                 (§12.10.2 signature)
//! ```
//!
//! `ApplicationNode::dev` is a test-harness constructor gated behind
//! `feature = "testing"` (ADR-062 §Decision 1), so these tests run in the
//! testing lane. What they exercise is not gated: `register_bridge`,
//! `set_bridge_status`, `bridge_lookup`, `bridge_state`, and
//! `build_bridge_routers` all ship in a default build.

#![cfg(feature = "testing")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use scp_core::bridge::BridgeMode;
use scp_core::bridge::registration::{
    ApprovedRegistration, BridgeRegistrationMetadata, BridgeRegistrationRequest, BridgeRegistry,
    approve_registration, register_bridge,
};
use scp_did::{DidDocument, VerificationMethod};
use scp_node::ApplicationNode;
use scp_node::bridge_auth::{BridgeJwtClaims, create_bridge_jwt};
use tower::ServiceExt;

/// The audience `ApplicationNode::dev` gives its bridge tokens: dev runs the
/// `Domain` reach on `localhost`, and the domain build path sets the audience
/// to `https://{domain}` (spec §12.10.2).
const DEV_AUDIENCE: &str = "https://localhost";

/// A bridge operator: a signing key, its DID, and its DID document.
struct Operator {
    signing_key: SigningKey,
    did: String,
    document: DidDocument,
}

impl Operator {
    fn generate() -> Self {
        let signing_key = SigningKey::from_bytes(&rand_seed());
        let public = signing_key.verifying_key();
        let did = format!("did:dht:z6Mk{}", hex::encode(&public.as_bytes()[..8]));
        let multibase = format!("z{}", bs58::encode(public.as_bytes()).into_string());
        let document = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: did.clone(),
            verification_method: vec![VerificationMethod {
                id: format!("{did}#active"),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: did.clone(),
                public_key_multibase: multibase,
            }],
            authentication: vec![format!("{did}#active")],
            assertion_method: vec![format!("{did}#active")],
            service: vec![],
            also_known_as: Vec::new(),
        };
        Self {
            signing_key,
            did,
            document,
        }
    }
}

/// Returns 32 random bytes for an Ed25519 seed.
fn rand_seed() -> [u8; 32] {
    use rand::RngCore;
    let mut seed = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed
}

/// Runs one registration through spec §12.2.1 governance approval.
fn approved(
    bridge_id: &str,
    operator_did: &str,
    context_id: &str,
    platform_key: Option<(&str, [u8; 32])>,
) -> ApprovedRegistration {
    let mut registry = BridgeRegistry::new(context_id.to_owned());
    let request = BridgeRegistrationRequest {
        bridge_id: bridge_id.to_owned(),
        operator_did: operator_did.into(),
        platform: "discord".to_owned(),
        mode: if platform_key.is_some() {
            BridgeMode::Cooperative
        } else {
            BridgeMode::Relay
        },
        context_id: context_id.to_owned(),
        requested_at: 1_700_000_000,
        self_hosted: false,
        webhook_url: platform_key
            .is_some()
            .then(|| "https://platform.example.com/hooks".to_owned()),
        platform_key: platform_key.map(|(_, key)| key),
        platform_key_id: platform_key.map(|(key_id, _)| key_id.to_owned()),
        max_shadows: 10_000,
        metadata: BridgeRegistrationMetadata::default(),
    };
    register_bridge(&mut registry, request).unwrap();
    approve_registration(
        &mut registry,
        bridge_id,
        &"did:dht:z6MkGovernance".into(),
        1_700_000_001,
    )
    .unwrap()
    .0
}

/// Mounts a node's bridge endpoints exactly as `serve()` mounts them.
///
/// The storage type is whatever `ApplicationNode::dev` builds: an
/// `InMemoryStorage` inside an `EncryptingAdapter` inside an `Arc`, which is
/// what satisfies `Node::start`'s sealed `EncryptedStorage` bound.
fn bridge_app(
    node: &ApplicationNode<
        std::sync::Arc<
            scp_platform::encrypting_adapter::EncryptingAdapter<
                scp_platform::in_memory::InMemoryStorage,
            >,
        >,
    >,
) -> Router {
    let lookup = node
        .bridge_lookup()
        .expect("dev node carries a bridge store");
    let (bridge, webhook) =
        scp_node::http::build_bridge_routers(&node.bridge_state(), Some(&lookup));
    bridge.merge(webhook)
}

/// Builds a bearer token for `bridge_id` inside `context_id`.
fn bearer(operator: &Operator, bridge_id: &str, context_id: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let claims = BridgeJwtClaims {
        iss: operator.did.clone(),
        aud: DEV_AUDIENCE.to_owned(),
        iat: now,
        exp: now + 600,
        scp_bridge_id: bridge_id.to_owned(),
        scp_context_id: context_id.to_owned(),
    };
    create_bridge_jwt(&claims, &operator.signing_key).unwrap()
}

/// Builds a `GET /v1/scp/bridge/status` request carrying `token`.
fn status_request(token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri("/v1/scp/bridge/status")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

/// Builds a `POST /v1/scp/bridge/shadow` request carrying `token`.
fn create_shadow_request(token: &str, platform_user_id: &str) -> Request<Body> {
    let body =
        format!(r#"{{"platform_handle":"@dave#1234","platform_user_id":"{platform_user_id}"}}"#);
    Request::builder()
        .method("POST")
        .uri("/v1/scp/bridge/shadow")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

/// Builds a `DELETE /v1/scp/bridge/shadow/{shadow_id}` request.
fn delete_shadow_request(token: &str, shadow_id: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(format!("/v1/scp/bridge/shadow/{shadow_id}"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

/// Builds a webhook request signed per spec §12.10.2:
/// `key_id || 0x00 || timestamp || 0x00 || body`.
fn signed_webhook(
    signing_key: &SigningKey,
    signed_key_id: &str,
    sent_key_id: &str,
) -> Request<Body> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        .to_string();
    let body = r#"{"event_type":"presence","event_id":"evt-1","timestamp":1700000400,"payload":{"platform_user_id":"usr_1","platform_handle":"@dave","status":"online"}}"#;

    let mut payload = Vec::new();
    payload.extend_from_slice(signed_key_id.as_bytes());
    payload.push(0x00);
    payload.extend_from_slice(ts.as_bytes());
    payload.push(0x00);
    payload.extend_from_slice(body.as_bytes());

    let signature = signing_key.sign(&payload);
    Request::builder()
        .method("POST")
        .uri("/v1/scp/bridge/webhook")
        .header(
            "x-scp-signature",
            URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        )
        .header("x-scp-platform-key-id", sent_key_id)
        .header("x-scp-timestamp", ts)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

/// Reads a response body as a string.
async fn body_text(resp: axum::response::Response) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

// ---------------------------------------------------------------------------
// Registration reaches a live request path
// ---------------------------------------------------------------------------

/// A node answers 401 for a bridge nobody registered, and 200 for one admitted
/// through `ApplicationNode::register_bridge`.
///
/// Reverting that admission call leaves the second assertion at 401, which is
/// the state every shipped node was in.
#[tokio::test]
async fn a_registration_admitted_through_a_node_turns_401_into_200() {
    let node = ApplicationNode::dev(0).await.unwrap();
    let operator = Operator::generate();
    let token = bearer(&operator, "bridge-alpha", "ctx-alpha");

    let before = bridge_app(&node)
        .oneshot(status_request(&token))
        .await
        .unwrap();
    assert_eq!(
        before.status(),
        StatusCode::UNAUTHORIZED,
        "an unregistered bridge must not reach any endpoint"
    );

    node.register_bridge(
        approved(
            "bridge-alpha",
            &operator.did,
            "ctx-alpha",
            Some(("pk-alpha", [7_u8; 32])),
        ),
        operator.document.clone(),
    )
    .await
    .unwrap();

    let after = bridge_app(&node)
        .oneshot(status_request(&token))
        .await
        .unwrap();
    assert_eq!(
        after.status(),
        StatusCode::OK,
        "a bridge registered through ApplicationNode::register_bridge must be served"
    );
    let body = body_text(after).await;
    assert!(body.contains("bridge-alpha"), "status body: {body}");
    assert!(
        body.contains("\"status\":\"Active\""),
        "status body: {body}"
    );

    node.shutdown();
}

/// Suspension and revocation reach the same request path (spec §12.2.2).
#[tokio::test]
async fn suspending_then_revoking_a_bridge_closes_its_endpoints() {
    use scp_core::bridge::BridgeStatus;

    let node = ApplicationNode::dev(0).await.unwrap();
    let operator = Operator::generate();
    node.register_bridge(
        approved(
            "bridge-alpha",
            &operator.did,
            "ctx-alpha",
            Some(("pk-alpha", [7_u8; 32])),
        ),
        operator.document.clone(),
    )
    .await
    .unwrap();
    let token = bearer(&operator, "bridge-alpha", "ctx-alpha");

    node.set_bridge_status("bridge-alpha", BridgeStatus::Suspended)
        .await
        .unwrap();
    let suspended = bridge_app(&node)
        .oneshot(status_request(&token))
        .await
        .unwrap();
    assert_eq!(suspended.status(), StatusCode::FORBIDDEN);
    assert!(body_text(suspended).await.contains("BRIDGE_SUSPENDED"));

    node.set_bridge_status("bridge-alpha", BridgeStatus::Revoked)
        .await
        .unwrap();
    let revoked = bridge_app(&node)
        .oneshot(status_request(&token))
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
    assert!(body_text(revoked).await.contains("BRIDGE_NOT_AUTHORIZED"));

    node.shutdown();
}

// ---------------------------------------------------------------------------
// Scope rules run against registrations a node admitted
// ---------------------------------------------------------------------------

/// Two bridges registered on one node, in two contexts, cannot read, delete, or
/// emit as each other's shadow.
///
/// The scope rules under test landed in commit dfe30f64a; this test drives them
/// through registrations a node admitted, rather than through a hand-built
/// lookup, so it fails if admission stops reaching the middleware.
#[tokio::test]
async fn one_bridge_cannot_touch_a_second_bridges_shadow() {
    let node = ApplicationNode::dev(0).await.unwrap();

    let alpha = Operator::generate();
    let beta = Operator::generate();
    node.register_bridge(
        approved(
            "bridge-alpha",
            &alpha.did,
            "ctx-alpha",
            Some(("pk-alpha", [7_u8; 32])),
        ),
        alpha.document.clone(),
    )
    .await
    .unwrap();
    node.register_bridge(
        approved(
            "bridge-beta",
            &beta.did,
            "ctx-beta",
            Some(("pk-beta", [8_u8; 32])),
        ),
        beta.document.clone(),
    )
    .await
    .unwrap();

    let alpha_token = bearer(&alpha, "bridge-alpha", "ctx-alpha");
    let beta_token = bearer(&beta, "bridge-beta", "ctx-beta");

    // Alpha creates a shadow inside its own context.
    let created = bridge_app(&node)
        .oneshot(create_shadow_request(&alpha_token, "usr_alpha"))
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let created_body = body_text(created).await;
    let shadow_id = created_body
        .split("\"shadow_id\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("create response carries a shadow_id")
        .to_owned();

    // Beta's roster never lists alpha's shadow.
    let beta_status = bridge_app(&node)
        .oneshot(status_request(&beta_token))
        .await
        .unwrap();
    assert_eq!(beta_status.status(), StatusCode::OK);
    let beta_body = body_text(beta_status).await;
    assert!(
        !beta_body.contains(&shadow_id),
        "beta's roster leaked alpha's shadow: {beta_body}"
    );
    assert!(beta_body.contains("\"shadow_count\":0"), "{beta_body}");

    // Beta cannot delete alpha's shadow.
    let beta_delete = bridge_app(&node)
        .oneshot(delete_shadow_request(&beta_token, &shadow_id))
        .await
        .unwrap();
    assert_eq!(beta_delete.status(), StatusCode::NOT_FOUND);
    assert!(body_text(beta_delete).await.contains("SHADOW_NOT_FOUND"));

    // Alpha still holds its own shadow, so beta's attempt mutated nothing.
    let alpha_status = bridge_app(&node)
        .oneshot(status_request(&alpha_token))
        .await
        .unwrap();
    assert_eq!(alpha_status.status(), StatusCode::OK);
    assert!(body_text(alpha_status).await.contains(&shadow_id));

    node.shutdown();
}

// ---------------------------------------------------------------------------
// A key id outside a signed payload (spec §12.10.2)
// ---------------------------------------------------------------------------

/// One platform key registered for two bridges: a request signed under one key
/// id must not verify after a caller swaps that header to a second key id.
///
/// Both key identifiers resolve to one Ed25519 public key, so a payload of
/// `timestamp || body` alone would verify under either identifier and let a
/// captured request act inside a second bridge's context. Folding a key id into
/// a signed payload makes each signature valid for exactly one identifier.
#[tokio::test]
async fn swapping_a_platform_key_id_rejects_an_otherwise_valid_webhook() {
    let node = ApplicationNode::dev(0).await.unwrap();

    // One platform serves two contexts, so it registers one key twice.
    let platform_key = SigningKey::from_bytes(&rand_seed());
    let public = *platform_key.verifying_key().as_bytes();

    let alpha = Operator::generate();
    let beta = Operator::generate();
    node.register_bridge(
        approved(
            "bridge-alpha",
            &alpha.did,
            "ctx-alpha",
            Some(("pk-alpha", public)),
        ),
        alpha.document.clone(),
    )
    .await
    .unwrap();
    node.register_bridge(
        approved(
            "bridge-beta",
            &beta.did,
            "ctx-beta",
            Some(("pk-beta", public)),
        ),
        beta.document.clone(),
    )
    .await
    .unwrap();

    // Signed for pk-alpha and sent as pk-alpha: accepted.
    let honest = bridge_app(&node)
        .oneshot(signed_webhook(&platform_key, "pk-alpha", "pk-alpha"))
        .await
        .unwrap();
    assert_eq!(
        honest.status(),
        StatusCode::OK,
        "an honest webhook must pass"
    );

    // Signed for pk-alpha and replayed as pk-beta: rejected, even though one
    // key backs both identifiers.
    let swapped = bridge_app(&node)
        .oneshot(signed_webhook(&platform_key, "pk-alpha", "pk-beta"))
        .await
        .unwrap();
    assert_eq!(
        swapped.status(),
        StatusCode::UNAUTHORIZED,
        "a swapped X-SCP-Platform-Key-Id must not reach a second bridge's context"
    );
    assert!(body_text(swapped).await.contains("BRIDGE_NOT_AUTHORIZED"));

    node.shutdown();
}

/// A webhook key identifier carrying a byte outside printable US-ASCII is
/// rejected before any lookup, so the `0x00` delimiters in a signed payload
/// split it exactly one way (spec §12.2.1, §12.10.2).
#[tokio::test]
async fn a_malformed_platform_key_id_is_rejected() {
    let node = ApplicationNode::dev(0).await.unwrap();
    let platform_key = SigningKey::from_bytes(&rand_seed());
    let operator = Operator::generate();
    node.register_bridge(
        approved(
            "bridge-alpha",
            &operator.did,
            "ctx-alpha",
            Some(("pk-alpha", *platform_key.verifying_key().as_bytes())),
        ),
        operator.document.clone(),
    )
    .await
    .unwrap();

    // A space is a valid HTTP header byte and an invalid key identifier.
    let resp = bridge_app(&node)
        .oneshot(signed_webhook(&platform_key, "pk alpha", "pk alpha"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(body_text(resp).await.contains("BRIDGE_NOT_AUTHORIZED"));

    node.shutdown();
}
