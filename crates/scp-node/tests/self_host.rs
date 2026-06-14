//! End-to-end integration test for `scp-node --self-host` (§10.12.8, §18).
//!
//! Exercises the **exact** production self-host wiring in-process, with no real
//! network exposure:
//!
//! * a real [`ApplicationNode`] built over encrypted [`SqliteStorage`] with the
//!   production `.build()` path (NOT `build_for_testing`) and a real
//!   [`SqliteKeyCustody`], on an OS-assigned loopback port, built **without** the
//!   `upnp` feature so no router mapping is attempted (a mock NAT strategy
//!   supplies a fixed STUN tier so no live STUN probe runs either);
//! * an in-process supervisor connected to the node's **own loopback relay** via
//!   the historically fragile `ws://` path — tagged
//!   [`RelayUrlSource::DhtResolved`] and bridge-bearer-authenticated — built
//!   inside [`scp_node::deploy_site`];
//! * the real two-phase broadcast publish for every embedded asset, followed by
//!   [`ApplicationNode::commit_deploy`];
//! * an HTTP `GET /scp/broadcast/<routing_id_hex>/site/index.html` against the
//!   node's real broadcast projection router via [`tower::ServiceExt::oneshot`].
//!
//! This is the same code path the production binary runs (`main.rs`
//! `run_self_host` -> `deploy_and_announce_self_host_site` -> `deploy_site`),
//! minus the binary-only concerns (banner, NAT mapper, serve loop).
//!
//! Provenance: `.docs/guides/self-hosting-a-website-on-scp.md`; specs §10.12.8
//! (Infrastructure & Self-Hosting) + §18 (Addressability & Deployment).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use http_body_util::BodyExt;
use hyper::Request;
use tower::ServiceExt;
use zeroize::Zeroizing;

use scp_identity::DidCache;
use scp_identity::cache::SystemClock;
use scp_identity::dht::DidDht;
use scp_identity::dht_client::InMemoryDhtClient;
use scp_node::{
    ApplicationNodeBuilder, DeploySiteParams, NatStrategy, NodeError, ReachabilityTier,
};
use scp_platform::sqlite::{SqliteKeyCustody, SqliteStorage};

/// Concrete `DidDht` type used in this test (in-memory DHT, system clock).
///
/// An in-memory DHT client means the node's DID document is never published to
/// the live `BitTorrent` Mainline DHT — the test stays fully offline.
type TestDidDht = DidDht<InMemoryDhtClient, SystemClock>;

/// Mock NAT strategy returning a fixed STUN tier.
///
/// The production `--self-host` binary is built without the `upnp` feature, so
/// no router mapping is attempted; supplying this strategy additionally avoids a
/// real STUN probe, keeping the test hermetic. The chosen address is the
/// RFC-5737 `TEST-NET-3` documentation range, never routable.
struct FixedTierNatStrategy;

impl NatStrategy for FixedTierNatStrategy {
    fn select_tier(
        &self,
        _relay_port: u16,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ReachabilityTier, NodeError>> + Send + '_>,
    > {
        Box::pin(async {
            Ok(ReachabilityTier::Stun {
                external_addr: SocketAddr::from(([203, 0, 113, 7], 34567)),
            })
        })
    }
}

/// Derives the deterministic self-host broadcast context id from the node DID,
/// identically to the production binary (`main.rs` `self_host_context_id`).
fn self_host_context_id(node_did: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(node_did.as_bytes()))
}

/// Builds a real `SqliteKeyCustody` over an encrypted `SQLite` database in `dir`.
async fn build_custody(dir: &std::path::Path, key: &[u8; 32]) -> Arc<SqliteKeyCustody> {
    let custody_storage =
        SqliteStorage::new(&dir.join("custody"), key).expect("custody SQLite should open");
    Arc::new(
        SqliteKeyCustody::new(custody_storage)
            .await
            .expect("custody should initialize"),
    )
}

/// The built self-host node plus the handles needed to deploy onto it.
///
/// The `tmp` dir is held to keep the on-disk `SQLite` databases alive for the
/// lifetime of the node; `storage_dir`/`storage_key` are kept so the deploy can
/// open a second (MLS) database under the same encrypted root.
struct BuiltNode {
    node: scp_node::ApplicationNode<SqliteStorage>,
    custody: Arc<SqliteKeyCustody>,
    storage_dir: std::path::PathBuf,
    storage_key: Zeroizing<[u8; 32]>,
    _tmp: tempfile::TempDir,
}

/// Builds a no-domain `ApplicationNode` over real encrypted `SQLite` storage via
/// the production `.build()` path, on OS-assigned loopback ports, with a
/// fixed-tier NAT strategy so no live STUN/UPnP work is attempted.
async fn build_self_host_node() -> BuiltNode {
    let tmp = tempfile::tempdir().expect("tempdir");
    let storage_dir = tmp.path().to_path_buf();
    let storage_key = Zeroizing::new([0x5Au8; 32]);

    // Real encrypted storage + custody (the production `.build()` path).
    let node_storage =
        SqliteStorage::new(&storage_dir, storage_key.as_ref()).expect("node SQLite should open");
    let custody = build_custody(&storage_dir, &storage_key).await;

    // DID method over an in-memory DHT (offline; nothing published).
    let dht_client = Arc::new(InMemoryDhtClient::new());
    let cache = Arc::new(DidCache::new());
    let sign_fn = TestDidDht::make_sign_fn(Arc::clone(&custody));
    let did_method = Arc::new(DidDht::with_client_and_signer(dht_client, cache, sign_fn));

    // `.build()` requires `S: EncryptedStorage`, satisfied by `SqliteStorage`.
    let node = ApplicationNodeBuilder::new()
        .storage(node_storage)
        .no_domain()
        .nat_strategy(Arc::new(FixedTierNatStrategy))
        .generate_identity_with(custody.clone(), did_method)
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .http_bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .build()
        .await
        .expect("no-domain node should build over encrypted SQLite storage");

    assert!(
        node.identity().did().starts_with("did:dht:"),
        "node DID should be a did:dht, got {}",
        node.identity().did()
    );
    assert_ne!(
        node.relay().bound_addr().port(),
        0,
        "loopback relay must be bound to a real OS-assigned port"
    );

    BuiltNode {
        node,
        custody,
        storage_dir,
        storage_key,
        _tmp: tmp,
    }
}

/// Full in-process self-host deploy + HTTP serve, end to end.
///
/// Mirrors the production `--self-host` path: build a no-domain node on real
/// encrypted `SQLite` storage, deploy the embedded site through the supervisor
/// on the node's loopback relay, then fetch `/index.html` back over HTTP.
// A multi-thread runtime is required: the broadcast publish path bridges a
// sync->async transport boundary that a `current_thread` runtime cannot drive
// (this mirrors the production binary's `#[tokio::main]` multi-thread runtime).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn self_host_deploys_embedded_site_and_serves_index_over_http() {
    let BuiltNode {
        node,
        custody,
        storage_dir,
        storage_key,
        _tmp,
    } = build_self_host_node().await;
    let node_did = node.identity().did().to_owned();

    // -- Supervisor MLS storage over a SECOND encrypted SQLite handle, exactly
    //    as the production binary does (`deploy_and_announce_self_host_site`).
    let mls_inner = Arc::new(
        SqliteStorage::new(&storage_dir.join("mls"), storage_key.as_ref())
            .expect("MLS SQLite should open"),
    );
    let mls_storage: Arc<dyn scp_core::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
        Arc::new(
            scp_core::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(mls_inner),
        );

    // -- Embedded default site (index.html + style.css + app.js), with the node
    //    DID injected into the index <head>, just like production.
    let assets = scp_node::embedded_assets(Some(&node_did));
    let expected_count = assets.len();
    let index_body = assets
        .iter()
        .find(|a| a.path == "/index.html")
        .expect("embedded site must include /index.html")
        .body
        .clone();

    let context_id = self_host_context_id(&node_did);
    let signing_key_handle = node.identity().identity().active_signing_key;

    // -- Deploy through the shared production core: this builds the in-process
    //    supervisor on the node's own loopback relay over the ws:// DhtResolved +
    //    bearer path, publishes every asset via the real two-phase broadcast
    //    publish, enables projection, and commits the deploy.
    let deploy_params = DeploySiteParams {
        node_did: node_did.clone(),
        context_id: context_id.clone(),
        deploy_id: "selfhost-deploy-1".to_owned(),
        hostname: "selfhost.scp.local".to_owned(),
        signing_key_handle,
        custody: custody.as_ref(),
        mls_storage,
        assets: &assets,
    };

    let committed = scp_node::deploy_site(&node, deploy_params)
        .await
        .expect("self-host deploy should succeed end to end");
    assert_eq!(
        committed, expected_count,
        "commit_deploy must report exactly the number of published assets"
    );

    // -- Fetch /index.html back over HTTP from the node's real projection router.
    let routing_hex = scp_node::routing_id_hex(&context_id);
    let router = node.broadcast_projection_router();
    let req = Request::builder()
        .uri(format!("/scp/broadcast/{routing_hex}/site/index.html"))
        .body(Body::empty())
        .expect("request should build");

    let resp = router.oneshot(req).await.expect("router should respond");

    // -- 200 OK --
    assert_eq!(
        resp.status(),
        200,
        "GET /site/index.html should return 200 after a committed deploy"
    );

    // -- Content-Type: text/html --
    let content_type = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .expect("Content-Type header must be present")
        .to_str()
        .expect("Content-Type must be valid UTF-8");
    assert_eq!(
        content_type, "text/html",
        "index.html must be served as text/html, got {content_type}"
    );

    // -- Body matches the published index.html exactly (full encrypt -> store ->
    //    commit -> decrypt -> serve round-trip fidelity).
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("body should collect")
        .to_bytes();
    assert_eq!(
        &body[..],
        &index_body[..],
        "served body must byte-match the published index.html asset"
    );

    // -- Sanity: it really is the embedded page, with the injected DID meta.
    let body_str = String::from_utf8(body.to_vec()).expect("index.html is UTF-8");
    assert!(
        body_str.contains("hello, world."),
        "served body should be the embedded hello-world page"
    );
    assert!(
        body_str.contains(&format!("content=\"{node_did}\"")),
        "served index should carry the injected scp-did <meta> tag"
    );
}
