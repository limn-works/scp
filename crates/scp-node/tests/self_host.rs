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
//! `run_self_host` -> `run_self_host_with` -> `SelfHostDeployer::deploy`), minus
//! the binary-only concerns (banner, NAT mapper, serve loop).
//!
//! Provenance: `.docs/guides/self-hosting-a-website-on-scp.md`; specs §10.12.8
//! (Infrastructure & Self-Hosting) + §18 (Addressability & Deployment).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;

use scp_transport::native::storage::BlobStorageBackend;

use axum::body::Body;
use http_body_util::BodyExt;
use hyper::Request;
use tower::ServiceExt;
use zeroize::Zeroizing;

use scp_clock::SystemClock;
use scp_dht::InMemoryDhtClient;
use scp_identity::DidCache;
use scp_identity::dht::DidDht;
use scp_node::{
    ApplicationNode, DeploySiteParams, DhtMode, IdentitySource, NatSlot, NatStrategy, Node,
    NodeConfig, NodeError, Reach, ReachabilityTier,
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
    /// The in-memory DHT client backing the node's DID method, retained so the
    /// co-located participant's governance resolver can share it (and the node's
    /// `DidCache`) — exactly as the production `host_site` path wires it. The
    /// node publishes its own DID document into this client at build time, so a
    /// resolver over it resolves the node DID.
    dht_client: Arc<InMemoryDhtClient>,
    /// The node's `DidCache`, shared with the co-located participant resolver
    /// (the cache-level sequence check is the load-bearing anti-rollback guard).
    cache: Arc<DidCache>,
    /// A clone of the blob-storage backend the relay + projection share
    /// (SHB-007). Retained so a test can read the relay's complete view of the
    /// stored broadcast envelopes — exactly what any connecting external
    /// participant can ever retrieve — and assert it is ciphertext.
    blob_storage: scp_transport::native::storage::BlobStorageBackend,
    _tmp: tempfile::TempDir,
}

impl BuiltNode {
    /// Builds the co-located participant's REAL document-derived governance
    /// `KeyResolver` over a `DualLayerResolver` that SHARES this node's DHT
    /// client and `DidCache` (ADR-053 / spec §10.17, SHB-002) — the same shape
    /// the production `host_site` path uses, never the `|_, _| None` stub.
    fn key_resolver(&self) -> scp_core::context::governance::KeyResolver {
        let resolver = Arc::new(scp_identity::DualLayerResolver::new(
            Arc::new(scp_identity::resolver::NoOpRelayQuerier),
            Arc::clone(&self.dht_client),
            Arc::clone(&self.cache),
            Vec::new(),
        ));
        scp_node::colocated_document_vm_key_resolver(resolver, tokio::runtime::Handle::current())
    }
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

    // DID method over an in-memory DHT (offline; nothing published externally).
    // Retain clones of the DHT client + cache so the co-located participant's
    // governance resolver can SHARE them (the node publishes its own DID
    // document into this client at identity-generation time).
    let dht_client = Arc::new(InMemoryDhtClient::new());
    let cache = Arc::new(DidCache::new());
    let sign_fn = TestDidDht::make_sign_fn(Arc::clone(&custody));
    let did_method = Arc::new(DidDht::with_client_and_signer(
        Arc::clone(&dht_client),
        Arc::clone(&cache),
        sign_fn,
    ));

    // Persistent, disk-backed blob storage — the SAME wiring the production
    // `--self-host` path uses (`run_self_host_with` calls `.blob_storage(...)`
    // with a SQLite backend under the storage dir). The relay and projection
    // share this `Arc`, so publish -> commit_deploy closes the loop on disk.
    let blob_storage =
        scp_transport::native::storage::BlobStorageBackend::sqlite(&storage_dir.join("blobs"))
            .expect("sqlite blob storage should open");
    // Retain a clone (the backend is `Arc`-backed and `Clone`) so the test can
    // read the relay's stored view directly (SHB-007 content-isolation proof).
    let blob_storage_handle = blob_storage.clone();

    // `Node::start` requires `S: EncryptedStorage`, satisfied by `SqliteStorage`.
    // `NatTraversal` (no_domain) is a publishing reach → `DhtMode::Production`
    // (M2; advisory in P1). The `FixedTierNatStrategy` is supplied via
    // `NatSlot::Custom`.
    let node = Node::start(NodeConfig {
        nat: NatSlot::Custom(Arc::new(FixedTierNatStrategy)),
        dht: DhtMode::Production,
        bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
        http_bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
        ..NodeConfig::defaults(
            Reach::NatTraversal,
            IdentitySource::Generate {
                custody: custody.clone(),
                did_method,
            },
            node_storage,
            // Explicit durable SQLite blob backend (opened above) as the required
            // selection (SCP-CAPINJECT-010).
            blob_storage,
        )
    })
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
        dht_client,
        cache,
        blob_storage: blob_storage_handle,
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
    let built = build_self_host_node().await;
    // The REAL document-derived governance resolver, sharing the node's cache +
    // DHT client (ADR-053 / spec §10.17, SHB-002).
    let key_resolver = built.key_resolver();
    let BuiltNode {
        node,
        custody,
        storage_dir,
        storage_key,
        dht_client: _dht_client,
        cache: _cache,
        blob_storage: _blob_storage,
        _tmp,
    } = built;
    let node_did = node.identity().did().to_owned();

    // -- Supervisor MLS storage over a SECOND encrypted SQLite handle, exactly
    //    as the production binary does (`deploy_and_announce_self_host_site`).
    let mls_inner = Arc::new(
        SqliteStorage::new(&storage_dir.join("mls"), storage_key.as_ref())
            .expect("MLS SQLite should open"),
    );
    // Durable saga journal + `mls_storage` view bound into one `DurableProviders`
    // over the SAME `Arc<SqliteStorage>`, exactly as the production binary does.
    let durable = scp_core::context::supervisor::DurableProviders::from_handle(mls_inner);

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
        key_resolver,
        custody: custody.as_ref(),
        durable,
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
    let durable = scp_core::context::supervisor::DurableProviders::from_handle(mls_inner);
    let signing_key_handle = built.node.identity().identity().active_signing_key;
    scp_node::SelfHostDeployer::start(
        &built.node,
        node_did,
        context_id.to_owned(),
        "selfhost.scp.local".to_owned(),
        signing_key_handle,
        built.key_resolver(),
        durable,
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

/// Fetches `path` at the origin root over `client`, asserting HTTP 200 and the
/// expected `Content-Type`. Used to verify root-absolute asset references
/// (`/style.css`, `/app.js`) resolve through the default-site root mount.
async fn assert_root_asset(client: &reqwest::Client, base: &str, path: &str, expected_ct: &str) {
    let resp = client
        .get(format!("{base}{path}"))
        .send()
        .await
        .unwrap_or_else(|e| panic!("request for {path} should complete: {e}"));
    assert_eq!(
        resp.status().as_u16(),
        200,
        "GET {path} must resolve at the origin root"
    );
    assert_eq!(
        resp.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some(expected_ct),
        "{path} must be served as {expected_ct}"
    );
}

/// FIX 1 (browser correctness): in `--self-host` mode the single deployed site
/// must be reachable at the ORIGIN ROOT, so a browser loading the embedded
/// `index.html` resolves its root-absolute `/style.css` and `/app.js`.
///
/// After `set_default_site_routing_id`, the virtual-host fallback serves
/// bare-path requests (`GET /`, `GET /style.css`) from the deployed context
/// even when the request `Host` matches no registered hostname (raw-IP access).
/// `GET /` maps to the site `index_path` via `site_handler`. The relay upgrade
/// (`/scp/v1`) still 404s — origin-root mounting must not re-expose it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn self_host_root_mount_serves_index_and_assets() {
    let built = build_self_host_node().await;
    let node_did = built.node.identity().did().to_owned();
    let context_id = self_host_context_id(&node_did);

    // Deploy the embedded site (index.html + style.css + app.js).
    let deployer = build_deployer(&built, &context_id).await;
    deploy_through(&deployer, &built, "selfhost-root-deploy").await;

    // The expected index body (with the injected DID meta), to byte-compare.
    let assets = scp_node::embedded_assets(Some(&node_did));
    let index_body = assets
        .iter()
        .find(|a| a.path == "/index.html")
        .expect("embedded site must include /index.html")
        .body
        .clone();

    // Mount the deployed context at the origin root, exactly as the binary does.
    let routing_id = scp_node::projection::compute_routing_id(&context_id);
    built.node.set_default_site_routing_id(routing_id);

    // Open the restricted self-host surface on a real loopback listener.
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

    // -- GET / -> 200 text/html, body byte-matches the deployed index.html. --
    let root = client
        .get(format!("{base}/"))
        .send()
        .await
        .expect("root request should complete");
    assert_eq!(
        root.status().as_u16(),
        200,
        "GET / must serve the deployed index at the origin root"
    );
    assert_eq!(
        root.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/html"),
        "origin-root index must be served as text/html"
    );
    let root_body = root.bytes().await.expect("root body").to_vec();
    assert_eq!(
        root_body, index_body,
        "GET / body must byte-match the deployed index.html"
    );

    // -- Root-absolute assets resolve with the right content types. --
    assert_root_asset(&client, &base, "/style.css", "text/css").await;
    assert_root_asset(&client, &base, "/app.js", "application/javascript").await;

    // -- The relay upgrade `/scp/v1` must STILL 404 with the root mount on. --
    let relay = client
        .get(format!("{base}/scp/v1"))
        .send()
        .await
        .expect("relay probe should complete");
    assert_eq!(
        relay.status().as_u16(),
        404,
        "origin-root mounting must not re-expose the relay upgrade `/scp/v1`, got {}",
        relay.status()
    );

    // -- An unknown deep path with no default-eligible asset 404s (the default
    //    site has no `/no/such/path`), proving the fallback is content-bounded.
    let missing = client
        .get(format!("{base}/no/such/path"))
        .send()
        .await
        .expect("missing-path probe should complete");
    assert_eq!(
        missing.status().as_u16(),
        404,
        "an unknown path under the default site must 404, got {}",
        missing.status()
    );

    built.node.shutdown();
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

    // -- Custody + DID method (offline in-memory DHT), as in `build_self_host_node`.
    //    Retain clones of the DHT client + cache so the co-located participant's
    //    governance resolver shares them (ADR-053 / spec §10.17, SHB-002). --
    let custody = build_custody(&storage_dir, &storage_key).await;
    let dht_client = Arc::new(InMemoryDhtClient::new());
    let cache = Arc::new(DidCache::new());
    let sign_fn = TestDidDht::make_sign_fn(Arc::clone(&custody));
    let did_method = Arc::new(DidDht::with_client_and_signer(
        Arc::clone(&dht_client),
        Arc::clone(&cache),
        sign_fn,
    ));

    let blob_storage =
        scp_transport::native::storage::BlobStorageBackend::sqlite(&storage_dir.join("blobs"))
            .expect("sqlite blob storage should open");

    // -- Step 2: build the node over the SHARED root handle (`Arc::clone`), exactly
    //    as the fixed `build_self_host_node` does. `Arc<SqliteStorage>` implements
    //    `EncryptedStorage`, so the builder accepts it. This must NOT trip the
    //    advisory-lock conflict because there is only ONE underlying handle. --
    let node = Node::start(NodeConfig {
        nat: NatSlot::Custom(Arc::new(FixedTierNatStrategy)),
        dht: DhtMode::Production,
        bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
        http_bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
        ..NodeConfig::defaults(
            Reach::NatTraversal,
            IdentitySource::Generate {
                custody: custody.clone(),
                did_method,
            },
            Arc::clone(&root_storage),
            // Explicit durable SQLite blob backend (opened above) as the required
            // selection (SCP-CAPINJECT-010).
            blob_storage,
        )
    })
    .await
    .expect(
        "the node must build over the SHARED root storage handle without a \
         lock conflict (os error 35)",
    );

    // -- The REAL document-derived governance resolver over the node's shared
    //    DHT client + cache (ADR-053 / spec §10.17, SHB-002). --
    let key_resolver = {
        let resolver = Arc::new(scp_identity::DualLayerResolver::new(
            Arc::new(scp_identity::resolver::NoOpRelayQuerier),
            Arc::clone(&dht_client),
            Arc::clone(&cache),
            Vec::new(),
        ));
        scp_node::colocated_document_vm_key_resolver(resolver, tokio::runtime::Handle::current())
    };

    // -- Deploy the embedded site and assert it serves end to end. The
    //    sequence-store-like owner is passed in so it stays alive across the
    //    deploy/serve — exactly one advisory-lock holder for the whole test. --
    deploy_embedded_and_assert_serves(
        &node,
        custody.as_ref(),
        &storage_dir,
        &storage_key,
        "selfhost-shared-storage-deploy",
        key_resolver,
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
    key_resolver: scp_core::context::governance::KeyResolver,
) where
    S: scp_platform::EncryptedStorage + 'static,
{
    let node_did = node.identity().did().to_owned();
    let context_id = self_host_context_id(&node_did);

    let mls_inner = Arc::new(
        SqliteStorage::new(&storage_dir.join("mls"), storage_key.as_ref())
            .expect("MLS SQLite should open (distinct subdirectory)"),
    );
    let durable = scp_core::context::supervisor::DurableProviders::from_handle(mls_inner);

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
            key_resolver,
            custody,
            durable,
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

// ---------------------------------------------------------------------------
// FIX A — stable DID across restarts (load-or-create persisted identity)
// ---------------------------------------------------------------------------

/// Builds a no-domain `ApplicationNode` over the encrypted `SQLite` databases in
/// `dir` via the production `.build()` path, using `identity_with_storage` —
/// the exact identity wiring the `--self-host` binary uses
/// (`build_self_host_node` in `main.rs`). The first build over a fresh `dir`
/// creates and persists the identity; subsequent builds over the SAME `dir`
/// reload it, keeping the DID stable.
async fn build_self_host_node_over_dir(dir: &std::path::Path) -> ApplicationNode<SqliteStorage> {
    let storage_key = Zeroizing::new([0x5Au8; 32]);

    let node_storage =
        SqliteStorage::new(dir, storage_key.as_ref()).expect("node SQLite should open");
    let custody = build_custody(dir, &storage_key).await;

    let dht_client = Arc::new(InMemoryDhtClient::new());
    let cache = Arc::new(DidCache::new());
    let sign_fn = TestDidDht::make_sign_fn(Arc::clone(&custody));
    let did_method = Arc::new(DidDht::with_client_and_signer(dht_client, cache, sign_fn));

    let blob_storage =
        scp_transport::native::storage::BlobStorageBackend::sqlite(&dir.join("blobs"))
            .expect("sqlite blob storage should open");

    // The production `--self-host` identity wiring: `IdentitySource::Persisted`
    // load-or-creates from the root storage so the DID is stable across
    // restarts. `NatTraversal` (publishing) → `DhtMode::Production` (M2).
    Node::start(NodeConfig {
        nat: NatSlot::Custom(Arc::new(FixedTierNatStrategy)),
        dht: DhtMode::Production,
        bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
        http_bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
        ..NodeConfig::defaults(
            Reach::NatTraversal,
            IdentitySource::Persisted {
                custody,
                did_method,
            },
            node_storage,
            // Explicit durable SQLite blob backend (opened above) as the required
            // selection (SCP-CAPINJECT-010).
            blob_storage,
        )
    })
    .await
    .expect("no-domain node should build over encrypted SQLite storage")
}

/// FIX A: two sequential builds over ONE storage path must yield the SAME DID.
///
/// This is the in-process analogue of restarting `scp-node --self-host` against
/// the same `--storage-path`: the persisted identity (and custody keyring) live
/// on disk, so the second boot reloads the identity instead of minting a fresh
/// `did:dht`. The first node is fully shut down before the second is built, so
/// the root `SQLite` advisory lock is released between boots, exactly like a
/// real restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn self_host_did_is_stable_across_restarts() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().to_path_buf();

    // -- Boot 1: fresh dir -> creates and persists the identity. --
    let node1 = build_self_host_node_over_dir(&dir).await;
    let did1 = node1.identity().did().to_owned();
    assert!(
        did1.starts_with("did:dht:"),
        "boot 1 DID should be a did:dht, got {did1}"
    );
    // Release the root SQLite advisory lock before re-opening (real restart).
    node1.shutdown();
    drop(node1);

    // -- Boot 2: SAME dir -> reloads the persisted identity. --
    let node2 = build_self_host_node_over_dir(&dir).await;
    let did2 = node2.identity().did().to_owned();
    node2.shutdown();

    assert_eq!(
        did1, did2,
        "self-host DID MUST be stable across restarts over the same storage path \
         (boot 1: {did1}, boot 2: {did2})"
    );
}

/// R2-1 regression (ADR-062 Slice 1): a `{Reach::NatTraversal, DhtMode::Disabled}`
/// self-host node — the documented reachable-but-unpublished config — MUST start
/// cleanly WITHOUT publishing. This is the exact config `build_host_site_node`
/// now produces: the publishing reach selects a routable relay URL while
/// `DhtMode::Disabled` selects the `DisabledDhtClient` AND sets
/// `NodeConfig.dht = Disabled`, so `publish_did_document_for_mode` SKIPS publish.
///
/// Before the fix, `build_host_site_node` re-derived the publish `DhtMode` from
/// `skip_nat` (`skip_nat ? Disabled : Production`), discarding `config.dht`. A
/// `NatTraversal` (`skip_nat` = false) host therefore set `NodeConfig.dht =
/// Production` even though the dispatch had selected the `DisabledDhtClient`, so
/// `publish_did_document_for_mode(Production)` called `DisabledDhtClient::publish()`
/// → `Err(DhtError::Disabled)` and `Node::start` FAILED on a documented-valid
/// config. This test builds that exact `{NatTraversal, Disabled, DisabledDhtClient}`
/// node (with a hermetic fixed-tier NAT strategy so no live STUN work runs) and
/// asserts it starts — proving the selected client `D` and the publish mode agree.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nat_traversal_disabled_dht_node_starts_without_publishing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let storage_dir = tmp.path().to_path_buf();
    let storage_key = Zeroizing::new([0x5Au8; 32]);

    let node_storage =
        SqliteStorage::new(&storage_dir, storage_key.as_ref()).expect("node SQLite should open");
    let custody = build_custody(&storage_dir, &storage_key).await;

    // DHT-layer-off DID method: `DisabledDhtClient::publish` fails closed. The
    // production `dispatch_hosted_site_by_dht_mode` selects EXACTLY this method
    // for `DhtMode::Disabled`.
    let cache = Arc::new(DidCache::new());
    let (did_method, _seq_init) = scp_node::self_host::build_disabled_did_method(cache);

    // `NatTraversal` (skip_nat = false) is a PUBLISHING reach, yet `dht:
    // DhtMode::Disabled` means the node must NOT publish — the reachable-but-
    // unpublished self-host case. With the R2-1 fix `NodeConfig.dht = Disabled`
    // agrees with the `DisabledDhtClient`, so the publish is skipped and the node
    // starts. `FixedTierNatStrategy` (via `NatSlot::Custom`) keeps the probe
    // hermetic.
    let node = Node::start(NodeConfig {
        nat: NatSlot::Custom(Arc::new(FixedTierNatStrategy)),
        dht: DhtMode::Disabled,
        bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
        http_bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
        ..NodeConfig::defaults(
            Reach::NatTraversal,
            IdentitySource::Generate {
                custody: custody.clone(),
                did_method,
            },
            node_storage,
            BlobStorageBackend::in_memory(),
        )
    })
    .await
    .expect(
        "a {NatTraversal, Disabled} node must start cleanly without publishing \
         (DisabledDhtClient::publish is SKIPPED, never invoked)",
    );

    assert!(
        node.identity().did().starts_with("did:dht:"),
        "node DID should be a did:dht, got {}",
        node.identity().did()
    );
    node.shutdown();
}

// ---------------------------------------------------------------------------
// FIX B — skip_nat_probe binds on a loopback relay URL without probing
// ---------------------------------------------------------------------------

/// A NAT strategy that PANICS if `select_tier` is ever called.
///
/// `skip_nat_probe()` must short-circuit before any tier selection, so a node
/// built with it active must never invoke this strategy.
struct PanicOnProbeNatStrategy;

impl NatStrategy for PanicOnProbeNatStrategy {
    fn select_tier(
        &self,
        _relay_port: u16,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ReachabilityTier, NodeError>> + Send + '_>,
    > {
        Box::pin(async {
            panic!("select_tier must NOT be called when skip_nat_probe() is set");
        })
    }
}

/// FIX B: `skip_nat_probe()` must skip the STUN/NAT probe entirely and publish a
/// loopback relay URL.
///
/// The node is built with a NAT strategy that panics if probed; a successful
/// build proves the probe was skipped. The published relay URL must be the
/// loopback fallback (`ws://127.0.0.1:<http_port>/scp/v1`) — the correct posture
/// behind a tunnel/proxy, and what keeps the self-signed cert SANs localhost-only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn skip_nat_probe_uses_loopback_relay_url_without_probing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().to_path_buf();
    let storage_key = Zeroizing::new([0x5Au8; 32]);

    let node_storage =
        SqliteStorage::new(&dir, storage_key.as_ref()).expect("node SQLite should open");
    let custody = build_custody(&dir, &storage_key).await;

    let dht_client = Arc::new(InMemoryDhtClient::new());
    let cache = Arc::new(DidCache::new());
    let sign_fn = TestDidDht::make_sign_fn(Arc::clone(&custody));
    let did_method = Arc::new(DidDht::with_client_and_signer(dht_client, cache, sign_fn));

    let blob_storage =
        scp_transport::native::storage::BlobStorageBackend::sqlite(&dir.join("blobs"))
            .expect("sqlite blob storage should open");

    // A fixed HTTP bind port so we can assert the exact loopback relay URL.
    let http_port = 28444u16;

    // `Reach::Local` skips the NAT probe (the flat-config equivalent of
    // `no_domain().skip_nat_probe()`). Local is non-publishing → `DhtMode::Disabled`
    // (the default). The `PanicOnProbeNatStrategy` is still supplied via
    // `NatSlot::Custom`: a clean build proves `Local` short-circuited the probe
    // before `select_tier` was ever called.
    let node = Node::start(NodeConfig {
        nat: NatSlot::Custom(Arc::new(PanicOnProbeNatStrategy)),
        bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
        http_bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], http_port))),
        ..NodeConfig::defaults(
            Reach::Local,
            IdentitySource::Persisted {
                custody,
                did_method,
            },
            node_storage,
            // Explicit durable SQLite blob backend (opened above) as the required
            // selection (SCP-CAPINJECT-010).
            blob_storage,
        )
    })
    .await
    .expect("no-domain node should build with the NAT probe skipped");

    assert_eq!(
        node.relay_url(),
        format!("ws://127.0.0.1:{http_port}/scp/v1"),
        "skip_nat_probe must publish a loopback relay URL"
    );
    node.shutdown();
}

// ---------------------------------------------------------------------------
// FINDING 7 — self-host serving path: restricted surface + loopback relay seam
// ---------------------------------------------------------------------------

/// FINDING 7 (defense-in-depth, structural): binds the two security invariants
/// of the `--self-host` serving path together so a future refactor cannot
/// silently (1) serve the `Full` surface in place of `SelfHost`, or (2) bind the
/// relay listener on a non-loopback address in no-domain mode.
///
/// Invariant 1 (`PublicSurface::SelfHost`): serving via the restricted surface
/// must NOT route the relay upgrade (`/scp/v1`) — a plain GET 404s (route
/// absent) while the site projection serves — and the SAME GET on the `Full`
/// surface IS routed (non-404, the WebSocket extractor rejecting a plain GET),
/// proving the self-host 404 is genuine route absence, not a generic rejection.
/// (The companion `self_host_public_surface_excludes_relay_and_bridge` covers
/// the bridge routes and the full surface/site detail; this test deliberately
/// keeps the surface half tight and adds the relay-loopback binding the other
/// test lacks.)
///
/// Invariant 2 (loopback relay bind): a no-domain self-host node
/// (`build_self_host_node`, `FixedTierNatStrategy`) must bind its relay listener
/// on a loopback address — the §10.12.8 security seam that keeps the relay
/// reachable only in-process (the in-process supervisor connects over
/// `127.0.0.1`; the relay is never on the public surface).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn self_host_uses_selfhost_surface_and_loopback_relay() {
    let built = build_self_host_node().await;

    // -- Invariant 2: the relay listener is bound on a loopback address. --
    // `build_self_host_node` already asserts the relay port is a real, non-zero
    // OS-assigned port; here we additionally pin that the bind IP is loopback.
    assert!(
        built.node.relay().bound_addr().ip().is_loopback(),
        "no-domain self-host relay must bind a loopback address (got {}), \
         keeping it reachable only in-process (§10.12.8)",
        built.node.relay().bound_addr(),
    );

    // Deploy so the SelfHost site route has content to serve.
    let node_did = built.node.identity().did().to_owned();
    let context_id = self_host_context_id(&node_did);
    let deployer = build_deployer(&built, &context_id).await;
    deploy_through(&deployer, &built, "selfhost-seam-deploy").await;
    let routing_hex = scp_node::routing_id_hex(&context_id);

    // -- Invariant 1a: the RESTRICTED self-host surface serves the site but does
    //    NOT route the relay upgrade. --
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
        "the self-host (restricted) surface must serve the website projection"
    );

    let self_host_relay = client
        .get(format!("{base}/scp/v1"))
        .send()
        .await
        .expect("relay probe should complete");
    assert_eq!(
        self_host_relay.status().as_u16(),
        404,
        "the relay upgrade `/scp/v1` must NOT be routed on the self-host surface, got {}",
        self_host_relay.status()
    );

    built.node.shutdown();

    // -- Invariant 1b: on the FULL surface the SAME GET IS routed (non-404),
    //    proving the 404 above is route ABSENCE on the restricted surface, not a
    //    generic rejection. A fresh node is used because `serve_background` is
    //    single-shot and the prior node is shut down. --
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

// ---------------------------------------------------------------------------
// FINDING 10(b) — ACME is never engaged on a no-domain self-host node
// ---------------------------------------------------------------------------

/// FINDING 10(b) (alignment/coverage): in `--self-host` (no-domain) mode the
/// node serves via self-signed TLS and NEVER provisions ACME — there is no DNS
/// name to validate. The ACME challenge route
/// (`GET /.well-known/acme-challenge/{token}`) is mounted ONLY when the node's
/// ACME challenge state is present (`NodeState::acme_challenges == Some`), which
/// a no-domain node never sets. Since that private state has no public getter,
/// this asserts the observable consequence: a GET to an ACME challenge path on
/// the self-host surface 404s, because the challenge route is absent and the
/// request falls through to the virtual-host fallback.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn self_host_no_domain_skips_acme() {
    let built = build_self_host_node().await;

    // Open the restricted self-host surface (the surface the binary serves).
    let addr = built
        .node
        .serve_background_with_surface(
            Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            scp_node::PublicSurface::SelfHost,
        )
        .await
        .expect("self-host background listener should bind");

    let client = reqwest::Client::new();

    // No ACME challenge route is mounted (no-domain => acme_challenges == None),
    // so the request falls through to the virtual-host fallback and 404s.
    let acme = client
        .get(format!(
            "http://{addr}/.well-known/acme-challenge/some-token"
        ))
        .send()
        .await
        .expect("acme-challenge probe should complete");
    assert_eq!(
        acme.status().as_u16(),
        404,
        "a no-domain self-host node must not serve ACME challenges (ACME is never \
         engaged without a DNS name), got {}",
        acme.status()
    );

    built.node.shutdown();
}

// ===========================================================================
// SHB-007: External participant shape over the existing public surface
// (spec §10.4, §10.12.6, §10.12.11, §10.17, §19.8)
// ===========================================================================

/// The plaintext marker embedded in the default site's `index.html`. If it ever
/// appears in a relay-stored blob, the relay would be carrying cleartext content
/// — which must NEVER happen (content is MLS/broadcast-key encrypted before it
/// reaches the relay).
const SITE_PLAINTEXT_MARKER: &[u8] = b"hello, world.";

/// Deploys the embedded site onto `built` and returns the broadcast
/// `routing_id` the envelopes are stored under (the same routing id the
/// projection serves at `/scp/broadcast/<hex>/site/...`).
async fn deploy_and_routing_id(built: &BuiltNode, deploy_id: &str) -> [u8; 32] {
    let node_did = built.node.identity().did().to_owned();
    let context_id = self_host_context_id(&node_did);
    let deployer = build_deployer(built, &context_id).await;
    deploy_through(&deployer, built, deploy_id).await;
    scp_node::projection::compute_routing_id(&context_id)
}

/// Reads the relay's COMPLETE stored view for `routing_id` — exactly what any
/// connecting relay client can ever retrieve — and asserts NONE of the stored
/// blob bodies contains the site plaintext marker.
///
/// This is the relay's entire content surface: the relay stores and forwards
/// these opaque encrypted blobs (§10.4). Proving they are ciphertext proves the
/// relay can never yield content to a connecting external participant — content
/// access requires the MLS/broadcast key, which the relay never holds (access
/// control is cryptographic: MLS + UCAN).
async fn assert_relay_view_is_ciphertext(built: &BuiltNode, routing_id: &[u8; 32], context: &str) {
    use scp_transport::native::storage::BlobStorage;
    let blobs = built
        .blob_storage
        .query(routing_id, None, 1024)
        .await
        .expect("relay blob query should succeed");
    assert!(
        !blobs.is_empty(),
        "[{context}] the relay must actually hold the deployed broadcast blobs \
         (so the ciphertext assertion is meaningful)"
    );
    for blob in &blobs {
        assert!(
            !contains_subslice(&blob.blob, SITE_PLAINTEXT_MARKER),
            "[{context}] a relay-stored blob contains the site PLAINTEXT marker — the relay \
             must only ever carry MLS/broadcast-key ciphertext, never content"
        );
    }
}

/// Returns `true` if `haystack` contains `needle` as a contiguous subslice.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// The external participant shape works over the EXISTING public surface, and
/// access to that surface is cryptographic — NOT transport-gated (SHB-007, spec
/// §10.4, §10.12.6, §10.12.11, §10.17, §19.8).
///
/// An external (separate-process) SDK participant reaches the node's relay over
/// the existing TLS-terminated [`PublicSurface::Full`] surface — governed by the
/// public-surface selection, the bind address, and the [`TlsMode`] — with NO
/// dedicated admission token or pre-shared secret (relays are anonymous,
/// DHT-auto-discovered dumb pipes; abuse prevention is the relay's existing rate
/// limiting per §10.4 and economics per §19.8, NOT an allowlist). This test
/// proves both halves at once:
///
/// 1. The external shape WORKS: a non-member client connects to the real
///    `/scp/v1` route over the `Full` surface with no token and is accepted.
/// 2. Access stays CRYPTOGRAPHIC: that same client's entire content surface (the
///    relay's stored blobs) is ciphertext. The MLS-member projection path (which
///    holds the broadcast key) decrypts the SAME blobs to plaintext, while the
///    external non-member (the relay's view, holding no key) sees only
///    ciphertext. Reachability is transport; access control is cryptographic.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_participant_access_is_cryptographic() {
    let built = build_self_host_node().await;
    let routing_id = deploy_and_routing_id(&built, "external-participant-deploy").await;

    // The MLS-member projection path (which holds the broadcast key) DOES yield
    // plaintext — content exists and is readable WITH the key.
    let routing_hex = hex::encode(routing_id);
    let status = projection_status(
        &built.node,
        &format!("/scp/broadcast/{routing_hex}/site/index.html"),
    )
    .await;
    assert_eq!(
        status, 200,
        "the MLS-member projection path must serve the deployed content as plaintext"
    );

    // Serve the FULL surface (where `/scp/v1` is mounted) on a real loopback
    // listener — the existing external-participant reachability controls
    // (surface + bind + TLS), with NO admission token.
    let addr = built
        .node
        .serve_background_with_surface(
            Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            scp_node::PublicSurface::Full,
        )
        .await
        .expect("full background listener should bind");

    // The external participant shape WORKS with zero new code: a non-member
    // connects to the real `/scp/v1` route over the `Full` surface with NO
    // token and the upgrade is accepted and proxied.
    let url = format!("ws://{addr}/scp/v1");
    let connected = tokio_tungstenite::connect_async(&url).await;
    assert!(
        connected.is_ok(),
        "an external participant must reach /scp/v1 over the Full public surface \
         with no token, got error: {:?}",
        connected.err()
    );
    drop(connected);

    // Yet that external (non-member) participant's content surface — the relay's
    // entire stored view — is STILL ciphertext. Reaching the relay granted a
    // transport connection, NOT content access: access control stays
    // cryptographic (MLS/broadcast key), independent of transport reachability.
    assert_relay_view_is_ciphertext(&built, &routing_id, "external-participant").await;

    built.node.shutdown();
}
