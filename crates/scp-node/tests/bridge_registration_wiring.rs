//! End-to-end proof that an admitted bridge registration reaches a node's
//! bridge endpoints, and that every §12.10.2 scope rule decides on what that
//! admission stored (spec §12.2.1, §12.10.2, §12.10.6 step 1).
//!
//! Each test drives this chain:
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
//! # Why a shipped node runs no part of the first two rows
//!
//! Spec §12.10.6 step 1 states the criterion a bridge node applies before it
//! admits a bridge: among the bridge lifecycle leaves in the event log the node
//! holds as a member of the context, the highest-sequence leaf naming that
//! bridge is a `BridgeRegistered` or `BridgeReactivated` leaf. A node reads
//! admission out of that log and out of no other input, and it refuses a
//! registration that reaches it by any other path. `ApplicationNode` joins no
//! context and derives no such log, so `register_bridge`, `set_bridge_status`,
//! and `rotate_bridge_platform_key` compile only under `feature = "testing"`,
//! and a shipped node answers `BRIDGE_NOT_AUTHORIZED` (401) to every bridge
//! request — which §12.10.6 step 1 gives as the answer for a bridge that fails
//! the criterion.
//!
//! These tests therefore stand in for the governance action the node will
//! execute once it derives that log: they put a bridge in the store the same
//! way the leaf-reading path will, and then assert on the shipped middlewares
//! and handlers, which are not gated. `ApplicationNode::dev`, `bridge_lookup`,
//! `bridge_state`, and `build_bridge_routers` behave here as they do in a
//! shipped build (ADR-062 §Decision 1 keeps `testing` out of every default
//! feature list).

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
use scp_core::bridge::registration::{
    ApprovedRegistration, BridgeRegistrationMetadata, BridgeRegistrationRequest, BridgeRegistry,
    approve_registration, derive_bridge_id, register_bridge,
};
use scp_core::bridge::{BridgeMode, BridgeStatus};
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

/// Maps a seed a test names a bridge by onto a request timestamp.
///
/// Spec §12.2.1 step 3 derives a bridge id from context, operator, platform,
/// and request time, so two bridges a test distinguishes need two request times.
fn seed_requested_at(seed: &str) -> u64 {
    let digest = seed
        .bytes()
        .fold(0_u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b.into()));
    1_700_000_000 + digest % 100_000
}

/// Runs one registration through spec §12.2.1 governance approval.
///
/// `seed` names a bridge; §12.2.1 step 3 derives its id, and a caller reads
/// that id back through `ApprovedRegistration::connector`.
fn approved(
    seed: &str,
    operator_did: &str,
    context_id: &str,
    platform_key: Option<(&str, [u8; 32])>,
) -> ApprovedRegistration {
    let requested_at = seed_requested_at(seed);
    let bridge_id = derive_bridge_id(context_id, operator_did, "discord", requested_at);
    let mut registry = BridgeRegistry::new(context_id.to_owned());
    let request = BridgeRegistrationRequest {
        bridge_id: bridge_id.clone(),
        operator_did: operator_did.into(),
        platform: "discord".to_owned(),
        mode: if platform_key.is_some() {
            BridgeMode::Cooperative
        } else {
            BridgeMode::Relay
        },
        context_id: context_id.to_owned(),
        requested_at,
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
        &bridge_id,
        &"did:dht:z6MkGovernance".into(),
        1_700_000_001,
    )
    .unwrap()
    .0
}

/// Returns the bridge id spec §12.2.1 step 3 derives for `seed`.
fn bridge_id_for(seed: &str, operator_did: &str, context_id: &str) -> String {
    derive_bridge_id(context_id, operator_did, "discord", seed_requested_at(seed))
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
    let bridge_id = bridge_id_for("bridge-alpha", &operator.did, "ctx-alpha");
    let token = bearer(&operator, &bridge_id, "ctx-alpha");

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
    assert!(body.contains(&bridge_id), "status body: {body}");
    assert!(
        body.contains("\"status\":\"Active\""),
        "status body: {body}"
    );

    node.shutdown();
}

/// Suspension and revocation reach the same request path (spec §12.2.2).
#[tokio::test]
async fn suspending_then_revoking_a_bridge_closes_its_endpoints() {
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
    let bridge_id = bridge_id_for("bridge-alpha", &operator.did, "ctx-alpha");
    let token = bearer(&operator, &bridge_id, "ctx-alpha");

    node.set_bridge_status(&bridge_id, BridgeStatus::Suspended)
        .await
        .unwrap();
    let suspended = bridge_app(&node)
        .oneshot(status_request(&token))
        .await
        .unwrap();
    assert_eq!(suspended.status(), StatusCode::FORBIDDEN);
    assert!(body_text(suspended).await.contains("BRIDGE_SUSPENDED"));

    node.set_bridge_status(&bridge_id, BridgeStatus::Revoked)
        .await
        .unwrap();
    let revoked = bridge_app(&node)
        .oneshot(status_request(&token))
        .await
        .unwrap();
    // §12.2.2 step 7: a revoked bridge reads `BRIDGE_FORBIDDEN` on every
    // subsequent API call.
    assert_eq!(revoked.status(), StatusCode::FORBIDDEN);
    assert!(body_text(revoked).await.contains("BRIDGE_FORBIDDEN"));

    node.shutdown();
}

// ---------------------------------------------------------------------------
// Scope rules run against registrations a node admitted
// ---------------------------------------------------------------------------

/// Two bridges registered on one node, in two contexts, cannot read, delete, or
/// emit as each other's shadow.
///
/// `bridge_auth_middleware` computes the scope and `find_scoped_shadow` applies
/// it (spec §12.10.2). This test drives both through registrations a node
/// admitted, rather than through a hand-built lookup, so it fails if admission
/// stops reaching the middleware.
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

    let alpha_token = bearer(
        &alpha,
        &bridge_id_for("bridge-alpha", &alpha.did, "ctx-alpha"),
        "ctx-alpha",
    );
    let beta_token = bearer(
        &beta,
        &bridge_id_for("bridge-beta", &beta.did, "ctx-beta"),
        "ctx-beta",
    );

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

// ---------------------------------------------------------------------------
// Platform key rotation reaches a live request path (spec §12.10.2 step 5)
// ---------------------------------------------------------------------------

/// An `UpdateBridgePlatformKey` rotation installs the incoming key on a live
/// request path, and the outgoing key keeps working for the 24-hour window
/// §12.10.2 step 5 defines.
///
/// A shipped node admits no bridge, because §12.10.6 step 1 reads admission out
/// of a context event log `ApplicationNode` does not hold, so it holds no key to
/// rotate and `rotate_bridge_platform_key` carries the same `feature = "testing"`
/// gate admission carries. This test drives the rotation the node will perform
/// once it reads that log.
#[tokio::test]
async fn a_rotation_installs_the_incoming_key_and_keeps_the_outgoing_one_live() {
    let node = ApplicationNode::dev(0).await.unwrap();
    let operator = Operator::generate();
    let outgoing = SigningKey::from_bytes(&rand_seed());
    let incoming = SigningKey::from_bytes(&rand_seed());

    let approval = approved(
        "bridge-rot",
        &operator.did,
        "ctx-rot",
        Some(("pk-old", *outgoing.verifying_key().as_bytes())),
    );
    let bridge_id = approval.connector().bridge_id.clone();
    node.register_bridge(approval, operator.document.clone())
        .await
        .unwrap();

    // Before the rotation the incoming key names no registered identifier.
    let before = bridge_app(&node)
        .oneshot(signed_webhook(&incoming, "pk-new", "pk-new"))
        .await
        .unwrap();
    assert_eq!(before.status(), StatusCode::UNAUTHORIZED);

    node.rotate_bridge_platform_key(&bridge_id, "pk-new", *incoming.verifying_key().as_bytes())
        .await
        .unwrap();

    let after = bridge_app(&node)
        .oneshot(signed_webhook(&incoming, "pk-new", "pk-new"))
        .await
        .unwrap();
    assert_eq!(
        after.status(),
        StatusCode::OK,
        "the incoming key must authenticate after a rotation"
    );

    // §12.10.2 step 5 accepts either identifier during the window, so the
    // outgoing key still works right after the rotation.
    let outgoing_still_works = bridge_app(&node)
        .oneshot(signed_webhook(&outgoing, "pk-old", "pk-old"))
        .await
        .unwrap();
    assert_eq!(outgoing_still_works.status(), StatusCode::OK);

    // Replaying the identical rotation writes nothing and returns `Ok`, which
    // is how an operator reruns one after a partial failure. Both identifiers
    // keep the state the first rotation left them in.
    node.rotate_bridge_platform_key(&bridge_id, "pk-new", *incoming.verifying_key().as_bytes())
        .await
        .unwrap();
    let after_replay = bridge_app(&node)
        .oneshot(signed_webhook(&incoming, "pk-new", "pk-new"))
        .await
        .unwrap();
    assert_eq!(after_replay.status(), StatusCode::OK);
    let outgoing_after_replay = bridge_app(&node)
        .oneshot(signed_webhook(&outgoing, "pk-old", "pk-old"))
        .await
        .unwrap();
    assert_eq!(outgoing_after_replay.status(), StatusCode::OK);

    // A second bridge cannot claim an identifier this bridge holds.
    let other_operator = Operator::generate();
    let other = SigningKey::from_bytes(&rand_seed());
    let other_approval = approved(
        "bridge-rot-two",
        &other_operator.did,
        "ctx-rot",
        Some(("pk-other", *other.verifying_key().as_bytes())),
    );
    let other_bridge_id = other_approval.connector().bridge_id.clone();
    node.register_bridge(other_approval, other_operator.document.clone())
        .await
        .unwrap();
    let contested = node
        .rotate_bridge_platform_key(
            &other_bridge_id,
            "pk-new",
            *other.verifying_key().as_bytes(),
        )
        .await
        .unwrap_err();
    assert!(
        contested.to_string().contains("pk-new"),
        "expected a refusal naming the contested identifier, got: {contested}"
    );

    node.shutdown();
}

// ---------------------------------------------------------------------------
// Bridge status changes reach a live request path (spec §12.2.2)
// ---------------------------------------------------------------------------

/// Suspending, reactivating, and revoking a bridge each reach a live request
/// path, and §12.2.1 refuses every transition out of `Revoked`.
///
/// §12.10.6 step 1 makes the `BridgeSuspended`, `BridgeReactivated`, and
/// `BridgeRevoked` leaves in a node's own event log the only input from which a
/// node learns of a transition, and `ApplicationNode` derives no such log, so
/// `set_bridge_status` carries the same `feature = "testing"` gate admission
/// carries. This test drives the transitions the node will perform once it reads
/// those leaves.
#[tokio::test]
async fn a_status_change_reaches_the_request_path() {
    let node = ApplicationNode::dev(0).await.unwrap();
    let operator = Operator::generate();
    let platform = SigningKey::from_bytes(&rand_seed());
    let approval = approved(
        "bridge-status",
        &operator.did,
        "ctx-status",
        Some(("pk-status", *platform.verifying_key().as_bytes())),
    );
    let bridge_id = approval.connector().bridge_id.clone();
    node.register_bridge(approval, operator.document.clone())
        .await
        .unwrap();
    let token = bearer(&operator, &bridge_id, "ctx-status");

    // Suspend: bearer and webhook paths both answer 403 BRIDGE_SUSPENDED.
    node.set_bridge_status(&bridge_id, BridgeStatus::Suspended)
        .await
        .unwrap();
    let suspended = bridge_app(&node)
        .oneshot(status_request(&token))
        .await
        .unwrap();
    assert_eq!(suspended.status(), StatusCode::FORBIDDEN);
    assert!(body_text(suspended).await.contains("BRIDGE_SUSPENDED"));
    let suspended_webhook = bridge_app(&node)
        .oneshot(signed_webhook(&platform, "pk-status", "pk-status"))
        .await
        .unwrap();
    assert_eq!(suspended_webhook.status(), StatusCode::FORBIDDEN);

    // Re-applying the status the record already holds changes nothing.
    node.set_bridge_status(&bridge_id, BridgeStatus::Suspended)
        .await
        .unwrap();

    // Reactivate: §12.2.1 `Suspended -> Active` through governance.
    node.set_bridge_status(&bridge_id, BridgeStatus::Active)
        .await
        .unwrap();
    let active = bridge_app(&node)
        .oneshot(status_request(&token))
        .await
        .unwrap();
    assert_eq!(active.status(), StatusCode::OK);

    // Revoke: the bearer path answers 403 BRIDGE_FORBIDDEN (§12.2.2 step 7),
    // and re-revoking a revoked bridge changes nothing.
    node.set_bridge_status(&bridge_id, BridgeStatus::Revoked)
        .await
        .unwrap();
    let revoked = bridge_app(&node)
        .oneshot(status_request(&token))
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::FORBIDDEN);
    assert!(body_text(revoked).await.contains("BRIDGE_FORBIDDEN"));
    // §12.2.2 step 6 destroys a revoked bridge's credentials, so the webhook
    // path answers 401 before it reaches the status check: the signature names
    // a key identifier this node no longer stores.
    let revoked_webhook = bridge_app(&node)
        .oneshot(signed_webhook(&platform, "pk-status", "pk-status"))
        .await
        .unwrap();
    assert_eq!(revoked_webhook.status(), StatusCode::UNAUTHORIZED);
    assert!(
        body_text(revoked_webhook)
            .await
            .contains("BRIDGE_NOT_AUTHORIZED")
    );
    node.set_bridge_status(&bridge_id, BridgeStatus::Revoked)
        .await
        .unwrap();

    // §12.2.1 makes `Revoked` terminal: a transition back to `Active` is
    // refused.
    let err = node
        .set_bridge_status(&bridge_id, BridgeStatus::Active)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("revoked"), "{err}");

    // A transition naming a bridge this node never admitted is refused.
    assert!(
        node.set_bridge_status("bridge-nobody", BridgeStatus::Suspended)
            .await
            .is_err()
    );

    node.shutdown();
}

/// A second admission naming a fresh `platform_key_id` for a bridge that
/// already holds one is refused, so admission never leaves two live webhook
/// keys behind (spec §12.10.6 step 1, §12.10.2 step 5).
#[tokio::test]
async fn re_admitting_a_bridge_under_a_fresh_key_identifier_is_refused() {
    let node = ApplicationNode::dev(0).await.unwrap();
    let operator = Operator::generate();
    let first = SigningKey::from_bytes(&rand_seed());
    let second = SigningKey::from_bytes(&rand_seed());

    node.register_bridge(
        approved(
            "bridge-two-keys",
            &operator.did,
            "ctx-two-keys",
            Some(("pk-1", *first.verifying_key().as_bytes())),
        ),
        operator.document.clone(),
    )
    .await
    .unwrap();

    let err = node
        .register_bridge(
            approved(
                "bridge-two-keys",
                &operator.did,
                "ctx-two-keys",
                Some(("pk-2", *second.verifying_key().as_bytes())),
            ),
            operator.document.clone(),
        )
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("already holds platform key identifier"),
        "expected a refusal naming the stored identifier, got: {err}"
    );

    // The second key authenticates nothing.
    let resp = bridge_app(&node)
        .oneshot(signed_webhook(&second, "pk-2", "pk-2"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    node.shutdown();
}
