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
//! `run_self_host` -> `deploy_self_host_site` -> `deploy_site`), minus the
//! binary-only concerns (banner, NAT mapper, serve loop).
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
use scp_platform::Storage;
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

    // Persistent, disk-backed blob storage — the SAME wiring the production
    // `--self-host` path uses (`run_self_host_with` calls `.blob_storage(...)`
    // with a SQLite backend under the storage dir). The relay and projection
    // share this `Arc`, so publish -> commit_deploy closes the loop on disk.
    let blob_storage =
        scp_transport::native::storage::BlobStorageBackend::sqlite(&storage_dir.join("blobs"))
            .expect("sqlite blob storage should open");

    // `.build()` requires `S: EncryptedStorage`, satisfied by `SqliteStorage`.
    let node = ApplicationNodeBuilder::new()
        .storage(node_storage)
        .blob_storage(blob_storage)
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

/// Builds a [`scp_node::SelfHostDeployer`] over `built`, mirroring the
/// production `build_self_host_deployer`: a single MLS `SQLite` database under
/// `storage_dir/mls` and one reusable broadcast group.
async fn build_deployer(built: &BuiltNode, context_id: &str) -> scp_node::SelfHostDeployer {
    let node_did = built.node.identity().did().to_owned();
    let mls_inner = Arc::new(
        SqliteStorage::new(&built.storage_dir.join("mls"), built.storage_key.as_ref())
            .expect("MLS SQLite should open"),
    );
    let mls_storage: Arc<dyn scp_core::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
        Arc::new(
            scp_core::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(mls_inner),
        );
    let signing_key_handle = built.node.identity().identity().active_signing_key;
    scp_node::SelfHostDeployer::start(
        &built.node,
        node_did,
        context_id.to_owned(),
        "selfhost.scp.local".to_owned(),
        signing_key_handle,
        mls_storage,
    )
    .await
    .expect("deployer setup should succeed")
}

/// Publishes + commits the embedded site through `deployer` under `deploy_id`,
/// asserting the committed count matches the asset count. Mirrors a single
/// production deploy iteration.
async fn deploy_through(
    deployer: &scp_node::SelfHostDeployer,
    built: &BuiltNode,
    deploy_id: &str,
) -> usize {
    let node_did = built.node.identity().did().to_owned();
    let assets = scp_node::embedded_assets(Some(&node_did));
    let expected = assets.len();
    let committed = deployer
        .deploy(&built.node, deploy_id, built.custody.as_ref(), &assets)
        .await
        .expect("self-host deploy should succeed end to end");
    assert_eq!(
        committed, expected,
        "commit_deploy must report exactly the number of published assets"
    );
    committed
}

/// Fetches `path` from the node's broadcast projection router, returning the
/// HTTP status code.
async fn projection_status(node: &scp_node::ApplicationNode<SqliteStorage>, path: &str) -> u16 {
    let router = node.broadcast_projection_router();
    let req = Request::builder()
        .uri(path)
        .body(Body::empty())
        .expect("request should build");
    router
        .oneshot(req)
        .await
        .expect("router should respond")
        .status()
        .as_u16()
}

/// FIX 1 (security): the self-host PUBLIC surface must expose ONLY the
/// read-only website projection — never the relay upgrade (`/scp/v1`) nor the
/// bridge routes (`/v1/scp/bridge/*`).
///
/// Builds the restricted self-host router via `serve_background_with_surface`
/// against a real bound listener, then asserts over the wire that the site
/// route serves while `/scp/v1` and `/v1/scp/bridge/shadow` are NOT routed
/// (they fall through to the virtual-host fallback -> 404).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn self_host_public_surface_excludes_relay_and_bridge() {
    let built = build_self_host_node().await;
    let node_did = built.node.identity().did().to_owned();
    let context_id = self_host_context_id(&node_did);

    // Deploy so the site route has content to serve.
    let deployer = build_deployer(&built, &context_id).await;
    deploy_through(&deployer, &built, "selfhost-surface-deploy").await;
    let routing_hex = scp_node::routing_id_hex(&context_id);

    // Open the RESTRICTED self-host surface on a real loopback listener.
    let addr = built
        .node
        .serve_background_with_surface(
            Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            scp_node::PublicSurface::SelfHost,
        )
        .await
        .expect("self-host background listener should bind");

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    // -- The website projection route IS reachable (200). --
    let site = client
        .get(format!(
            "{base}/scp/broadcast/{routing_hex}/site/index.html"
        ))
        .send()
        .await
        .expect("site request should complete");
    assert_eq!(
        site.status().as_u16(),
        200,
        "self-host public surface must serve the website projection"
    );

    // -- The relay upgrade `/scp/v1` is NOT routed on the public surface. --
    // A plain GET (no WebSocket upgrade) to a mounted relay route would return
    // 426/400/101-class handling; when the route is absent it falls through to
    // the virtual-host fallback, which 404s for an unregistered host/path.
    let relay = client
        .get(format!("{base}/scp/v1"))
        .send()
        .await
        .expect("relay probe should complete");
    assert_eq!(
        relay.status().as_u16(),
        404,
        "relay upgrade `/scp/v1` must NOT be reachable on the self-host public surface, \
         got {}",
        relay.status()
    );

    // -- The bridge routes `/v1/scp/bridge/*` are NOT routed publicly. --
    let bridge = client
        .post(format!("{base}/v1/scp/bridge/shadow"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .expect("bridge probe should complete");
    assert_eq!(
        bridge.status().as_u16(),
        404,
        "bridge route `/v1/scp/bridge/shadow` must NOT be reachable on the self-host \
         public surface, got {}",
        bridge.status()
    );

    built.node.shutdown();

    // -- Contrast: on the FULL surface, `/scp/v1` IS routed. A plain GET (no
    //    WebSocket upgrade headers) hits the relay upgrade handler's
    //    `WebSocketUpgrade` extractor, which rejects with a non-404 status
    //    (426/400-class) — proving the 404 above is route ABSENCE on the
    //    self-host surface, not a generic rejection that would occur anyway.
    //    A fresh node is used because the prior one has been shut down and
    //    `serve_background` is single-shot.
    let full = build_self_host_node().await;
    let full_addr = full
        .node
        .serve_background_with_surface(
            Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            scp_node::PublicSurface::Full,
        )
        .await
        .expect("full background listener should bind");
    let full_relay = client
        .get(format!("http://{full_addr}/scp/v1"))
        .send()
        .await
        .expect("full relay probe should complete");
    assert_ne!(
        full_relay.status().as_u16(),
        404,
        "on the FULL surface `/scp/v1` must be routed (the WebSocket extractor \
         rejects a plain GET with a non-404 status), proving the self-host 404 is \
         route absence; got {}",
        full_relay.status()
    );
    full.node.shutdown();
}

/// FIX 3 + FIX 4 (correctness): re-deploying the site (as the refresh loop
/// does) against the SAME persistent node — each with a freshly-minted unique
/// deploy id — must succeed and keep the site served, never tripping the
/// `commit_deploy` count-mismatch that a constant deploy id over persistent,
/// within-TTL blobs would cause.
///
/// This also exercises FIX 2 indirectly: the node is built with a persistent
/// `SQLite` blob store (see `build_self_host_node`), so the second deploy
/// commits against on-disk blobs from the first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn self_host_redeploy_with_unique_deploy_ids_keeps_site_served() {
    let built = build_self_host_node().await;
    let node_did = built.node.identity().did().to_owned();
    let context_id = self_host_context_id(&node_did);
    let routing_hex = scp_node::routing_id_hex(&context_id);
    let site_path = format!("/scp/broadcast/{routing_hex}/site/index.html");

    // One deployer reused across both deploys — exactly as the production
    // refresh loop reuses a single `SelfHostDeployer`.
    let deployer = build_deployer(&built, &context_id).await;

    // -- First deploy (initial). --
    deploy_through(&deployer, &built, "selfhost-redeploy-run-1").await;
    assert_eq!(
        projection_status(&built.node, &site_path).await,
        200,
        "site must be served after the first deploy"
    );

    // -- Second deploy (refresh) with a DISTINCT deploy id, against the same
    //    node and the same on-disk blob store still holding run-1's blobs. With
    //    a constant deploy id this would count run-1's stale blobs and fail with
    //    CommitCountMismatch; with a unique id per run it commits cleanly.
    deploy_through(&deployer, &built, "selfhost-redeploy-run-2").await;

    // After the refresh, the site must not only return 200 but serve the
    // correct, fully-decrypted body — proving the reused single-group key still
    // decrypts the freshly-published blobs (no epoch/key divergence across
    // deploys).
    let router = built.node.broadcast_projection_router();
    let resp = router
        .oneshot(
            Request::builder()
                .uri(&site_path)
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("router should respond");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "site must remain served after a refresh deploy with a fresh deploy id"
    );
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("body should collect")
        .to_bytes();
    let expected_index = scp_node::embedded_assets(Some(&node_did))
        .into_iter()
        .find(|a| a.path == "/index.html")
        .expect("embedded site must include /index.html")
        .body;
    assert_eq!(
        &body[..],
        &expected_index[..],
        "served body after refresh must byte-match the embedded index.html"
    );

    // -- The routing id (and thus the site URL) is stable across refreshes. --
    assert_eq!(
        scp_node::routing_id_hex(&context_id),
        routing_hex,
        "the site routing id must be stable across refresh deploys"
    );
}

/// Regression: the production binary's storage wiring must NOT open the root
/// `SQLite` database twice.
///
/// The binary (`main.rs`) opens the root DB once in `init_persistent_storage`
/// and keeps that handle alive for the whole run (the BEP44 `StorageSequenceStore`
/// holds an `Arc` clone). Previously, `build_self_host_node` (and the full-node
/// path) then opened a SECOND `SqliteStorage` on the SAME root directory for the
/// node builder. Because `SqliteStorage` takes a process-exclusive advisory lock
/// on `{dir}/scp.db.lock` for its lifetime, the second open failed with
/// `os error 35` ("already open by another SCP instance") and the binary exited
/// before serving anything. The existing end-to-end tests missed this because
/// they open the root handle exactly once and hand it straight to the builder.
///
/// This test reproduces the binary's wiring exactly:
/// 1. it asserts the FAILURE MODE directly — a naive second `SqliteStorage::new`
///    on the same root, while the first handle is alive, IS rejected; then
/// 2. it asserts the FIX — sharing the single `Arc<SqliteStorage>` between a live
///    sequence-store-like owner AND the node builder lets the node build and
///    serve `index.html`, with exactly one advisory-lock holder.
///
/// Provenance: `.docs/guides/self-hosting-a-website-on-scp.md`; specs §10.12.8.
// Multi-thread runtime required for the broadcast publish path (see the
// end-to-end test above for the rationale).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn self_host_shares_single_root_storage_handle_and_serves() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let storage_dir = tmp.path().to_path_buf();
    let storage_key = Zeroizing::new([0x5Au8; 32]);

    // -- Step 1: open the root DB ONCE, exactly as `init_persistent_storage` does,
    //    and keep the handle alive behind an `Arc`. --
    let root_storage = Arc::new(
        SqliteStorage::new(&storage_dir, storage_key.as_ref())
            .expect("root SQLite should open the first time"),
    );

    // -- Assert the FAILURE MODE: while `root_storage` is alive, a second open of
    //    the SAME root directory MUST be rejected by the advisory lock. This is
    //    precisely what the binary used to do at its second `open_sqlite_or_exit`
    //    call, and is the bug this fix removes. --
    let second_open = SqliteStorage::new(&storage_dir, storage_key.as_ref());
    let err = second_open
        .err()
        .expect("opening the root DB twice (while the first handle lives) must fail");
    let err_str = err.to_string();
    assert!(
        err_str.contains("already open by another SCP instance"),
        "the second root open must be rejected by the advisory lock, got: {err_str}"
    );

    // -- A second, live owner of the SAME handle, standing in for the binary's
    //    BEP44 `StorageSequenceStore` (which holds an `Arc` clone for the whole
    //    run). Keeping this alive across the build proves the node builder shares
    //    the one handle rather than racing a second open. --
    let sequence_store_owner: Arc<SqliteStorage> = Arc::clone(&root_storage);
    // Use it concurrently to prove it is a live, functional handle, not just a
    // dangling reference: write+read a BEP44-style key like the real store does.
    sequence_store_owner
        .store("bep44/seq/test", &1u64.to_be_bytes())
        .await
        .expect("the shared root handle must be usable while the node also holds it");

    // -- Custody + DID method (offline in-memory DHT), as in `build_self_host_node`. --
    let custody = build_custody(&storage_dir, &storage_key).await;
    let dht_client = Arc::new(InMemoryDhtClient::new());
    let cache = Arc::new(DidCache::new());
    let sign_fn = TestDidDht::make_sign_fn(Arc::clone(&custody));
    let did_method = Arc::new(DidDht::with_client_and_signer(dht_client, cache, sign_fn));

    let blob_storage =
        scp_transport::native::storage::BlobStorageBackend::sqlite(&storage_dir.join("blobs"))
            .expect("sqlite blob storage should open");

    // -- Step 2: build the node over the SHARED root handle (`Arc::clone`), exactly
    //    as the fixed `build_self_host_node` does. `Arc<SqliteStorage>` implements
    //    `EncryptedStorage`, so the builder accepts it. This must NOT trip the
    //    advisory-lock conflict because there is only ONE underlying handle. --
    let node = ApplicationNodeBuilder::new()
        .storage(Arc::clone(&root_storage))
        .blob_storage(blob_storage)
        .no_domain()
        .nat_strategy(Arc::new(FixedTierNatStrategy))
        .generate_identity_with(custody.clone(), did_method)
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .http_bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .build()
        .await
        .expect(
            "the node must build over the SHARED root storage handle without a \
             lock conflict (os error 35)",
        );

    // -- Deploy the embedded site and assert it serves end to end. The
    //    sequence-store-like owner is passed in so it stays alive across the
    //    deploy/serve — exactly one advisory-lock holder for the whole test. --
    deploy_embedded_and_assert_serves(
        &node,
        custody.as_ref(),
        &storage_dir,
        &storage_key,
        "selfhost-shared-storage-deploy",
    )
    .await;

    drop(sequence_store_owner);
    node.shutdown();
}

/// Deploys the embedded default site onto `node` and asserts it serves
/// `index.html` (200, `text/html`, hello-world body) back over the projection
/// router. Generic over the node's storage type so it works for both the
/// concrete `SqliteStorage` and the shared `Arc<SqliteStorage>` node.
///
/// The supervisor MLS storage is a `SQLite` database under the distinct `mls/`
/// subdirectory — its own advisory lock, never conflicting with the root DB.
async fn deploy_embedded_and_assert_serves<S>(
    node: &scp_node::ApplicationNode<S>,
    custody: &SqliteKeyCustody,
    storage_dir: &std::path::Path,
    storage_key: &Zeroizing<[u8; 32]>,
    deploy_id: &str,
) where
    S: scp_platform::EncryptedStorage + 'static,
{
    let node_did = node.identity().did().to_owned();
    let context_id = self_host_context_id(&node_did);

    let mls_inner = Arc::new(
        SqliteStorage::new(&storage_dir.join("mls"), storage_key.as_ref())
            .expect("MLS SQLite should open (distinct subdirectory)"),
    );
    let mls_storage: Arc<dyn scp_core::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
        Arc::new(
            scp_core::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(mls_inner),
        );

    let assets = scp_node::embedded_assets(Some(&node_did));
    let expected_count = assets.len();
    let signing_key_handle = node.identity().identity().active_signing_key;
    let committed = scp_node::deploy_site(
        node,
        DeploySiteParams {
            node_did: node_did.clone(),
            context_id: context_id.clone(),
            deploy_id: deploy_id.to_owned(),
            hostname: "selfhost.scp.local".to_owned(),
            signing_key_handle,
            custody,
            mls_storage,
            assets: &assets,
        },
    )
    .await
    .expect("self-host deploy should succeed over the shared-storage node");
    assert_eq!(committed, expected_count, "every asset must be committed");

    let routing_hex = scp_node::routing_id_hex(&context_id);
    let resp = node
        .broadcast_projection_router()
        .oneshot(
            Request::builder()
                .uri(format!("/scp/broadcast/{routing_hex}/site/index.html"))
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("router should respond");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "the shared-storage self-host node must serve index.html"
    );
    let content_type = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert_eq!(content_type, "text/html", "index.html must be text/html");

    let body = resp
        .into_body()
        .collect()
        .await
        .expect("body should collect")
        .to_bytes();
    let body_str = String::from_utf8(body.to_vec()).expect("index.html is UTF-8");
    assert!(
        body_str.contains("hello, world."),
        "served body must be the embedded hello-world page"
    );
}
