//! End-to-end integration test for the public [`scp_node::host_site_until`]
//! library API (the reusable core behind `scp-node --self-host`).
//!
//! Drives the FULL host-a-website flow in-process with no real network
//! exposure: a hermetic tempdir storage path, the default `DhtMode::Disabled`
//! (nothing published), plaintext HTTP, NAT probing skipped (no router port opened), an
//! OS-assigned port, and a caller-controlled shutdown. It then
//! performs a real HTTP `GET` against the running listener and asserts a `200`
//! with the deployed site body — proving the new API works end to end
//! (publish -> commit -> HTTP serve), then triggers shutdown and asserts the
//! task returns `Ok(())`.
//!
//! Every run passes `port: 0`: `host_site_until` binds the public listener
//! itself and reports the bound port in [`HostSiteReady::port`], so no test
//! learns a port before the code under test binds it.
//!
//! Provenance: `.docs/guides/self-hosting-a-website-on-scp.md`; specs §10.12.8
//! (Infrastructure & Self-Hosting) + §18 (Addressability & Deployment).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::TcpListener;
use std::time::Duration;

/// The bound on each wait in these tests: the ready signal and the HTTP fetch.
const STEP_DEADLINE: Duration = Duration::from_mins(1);

use scp_node::{HostSiteConfig, HostSiteReady, Reach, TlsMode, host_site_until};

/// Writes a minimal valid site (`index.html` + `style.css`) into `dir`.
///
/// The marker string in `index.html` is asserted in the served response body.
fn write_sample_site(dir: &std::path::Path) {
    std::fs::write(
        dir.join("index.html"),
        "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"/>\
         <title>host_site test</title><link rel=\"stylesheet\" href=\"/style.css\"/></head>\
         <body><h1>host_site works end to end</h1></body></html>\n",
    )
    .expect("write index.html");
    std::fs::write(dir.join("style.css"), "body { font-family: sans-serif; }\n")
        .expect("write style.css");
}

/// Full in-process `host_site_until` run: build a node over a hermetic tempdir,
/// deploy a sample site, serve it over plaintext HTTP on a free loopback port,
/// fetch `/` back, then shut down cleanly.
///
/// A multi-thread runtime is required: the broadcast publish path bridges a
/// sync->async transport boundary that a `current_thread` runtime cannot drive
/// (this mirrors the production binary's `#[tokio::main]` multi-thread runtime).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_site_serves_a_deployed_site_over_http_and_shuts_down() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let storage_dir = tmp.path().join("storage");
    let site_dir = tmp.path().join("site");
    std::fs::create_dir_all(&storage_dir).expect("create storage dir");
    std::fs::create_dir_all(&site_dir).expect("create site dir");
    write_sample_site(&site_dir);

    // -- Caller-controlled shutdown: a oneshot whose receiver future resolves
    //    to `()` when we fire the sender. --
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = async move {
        // A dropped sender (e.g. on panic) also resolves the receiver, so the
        // hosted site never hangs the test.
        let _ = shutdown_rx.await;
    };

    // -- `on_ready` signals (via its own oneshot) once the site is deployed and
    //    serving is imminent, carrying the live-site details. --
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<HostSiteReady>();
    let mut ready_tx = Some(ready_tx);

    let config = HostSiteConfig {
        // Hermetic + offline: plaintext (no TLS dance), Reach::Local (skip NAT,
        // no router port), and the default `DhtMode::Disabled` (nothing
        // published).
        tls: TlsMode::Plaintext,
        site_dir: Some(site_dir.clone()),
        // The OS assigns the port; `HostSiteReady::port` reports it.
        port: 0,
        storage_path: Some(storage_dir.clone()),
        on_ready: Some(Box::new(move |ready: HostSiteReady| {
            if let Some(tx) = ready_tx.take() {
                let _ = tx.send(ready);
            }
        })),
        ..HostSiteConfig::defaults(Reach::Local)
    };

    // -- Spawn the hosted site as a task; it serves until `shutdown` resolves. --
    let handle = tokio::spawn(async move { host_site_until(config, shutdown).await });

    // -- Wait for the ready signal (deploy complete, serving imminent). --
    let mut handle = handle;
    let ready = tokio::select! {
        ready = tokio::time::timeout(STEP_DEADLINE, ready_rx) => ready
            .expect("host_site should reach ready within 60s")
            .expect("on_ready should fire (sender not dropped)"),
        // A failed `host_site_until` drops the ready sender; report its error
        // rather than a bare dropped-sender message.
        result = &mut handle => panic!("host_site_until exited before ready: {result:?}"),
    };
    let port = ready.port;
    assert_ne!(
        port, 0,
        "the ready signal must carry the bound port, not the requested 0"
    );
    assert!(
        ready.node_did.starts_with("did:dht:"),
        "node DID should be a did:dht, got {}",
        ready.node_did
    );
    assert_eq!(ready.asset_count, 2, "the sample site has two assets");
    assert!(ready.plaintext, "the test runs in plaintext mode");

    // -- Real HTTP GET against the running listener. `host_site` binds
    //    `0.0.0.0:<port>`, so connect via loopback. The listener was bound
    //    before `on_ready` fired, so the connection waits in its backlog until
    //    serving starts: one request bounded by `STEP_DEADLINE`, no retry. --
    let client = reqwest::Client::builder()
        .timeout(STEP_DEADLINE)
        .build()
        .expect("build HTTP client");
    let url = format!("http://127.0.0.1:{port}/index.html");
    let resp = client
        .get(&url)
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET {url} failed: {e}"));
    assert_eq!(resp.status().as_u16(), 200, "GET {url} must return 200");
    let body = resp.text().await.expect("response body should read");
    assert!(
        body.contains("host_site works end to end"),
        "served body must be the deployed sample site, got: {body}"
    );

    // -- Trigger shutdown and assert the hosted site returns Ok(()). --
    shutdown_tx.send(()).expect("send shutdown");
    let result = tokio::time::timeout(Duration::from_secs(30), handle)
        .await
        .expect("host_site should shut down within 30s")
        .expect("host_site task should not panic");
    assert!(
        result.is_ok(),
        "host_site_until must return Ok(()) on clean shutdown, got {result:?}"
    );

    // -- The shutdown drained the deployer's Supervisor and closed its MLS
    //    store, so the directory reopens on the first attempt (spec §17.6). --
    assert_mls_store_reopens(&storage_dir);
}

/// Opens `{storage_dir}/mls` once and fails the test unless that first
/// attempt succeeds: the advisory lock must already be released.
fn assert_mls_store_reopens(storage_dir: &std::path::Path) {
    let key = scp_node::self_host::resolve_storage_key(storage_dir).expect("storage key");
    scp_platform::sqlite::SqliteStorage::new(&storage_dir.join("mls"), key.as_ref())
        .expect("the MLS store must reopen on the first attempt after host_site_until returns");
}

/// A failure after the deployer is built (here, an asset path that the
/// initial deploy rejects) still drains the deployer's Supervisor and closes
/// its MLS store before `host_site_until` returns the error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_site_failure_after_deploy_releases_the_mls_store() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let storage_dir = tmp.path().join("storage");
    let site_dir = tmp.path().join("site");
    std::fs::create_dir_all(&storage_dir).expect("create storage dir");
    std::fs::create_dir_all(&site_dir).expect("create site dir");
    write_sample_site(&site_dir);
    // The loader accepts any file name, but a content path rejects every
    // `%`-encoded byte (§18.11.9), so the initial deploy fails after the
    // deployer and its MLS store exist.
    std::fs::write(site_dir.join("bad%20name.css"), "body {}\n").expect("write bad asset");

    let config = HostSiteConfig {
        tls: TlsMode::Plaintext,
        site_dir: Some(site_dir),
        port: 0,
        storage_path: Some(storage_dir.clone()),
        ..HostSiteConfig::defaults(Reach::Local)
    };
    let result = tokio::time::timeout(
        STEP_DEADLINE,
        host_site_until(config, std::future::pending::<()>()),
    )
    .await
    .expect("host_site_until must fail within 60s");
    assert!(
        matches!(result, Err(scp_node::HostSiteError::Deploy(_))),
        "an asset path the content-path rules reject must fail the deploy step, got {result:?}"
    );

    assert_mls_store_reopens(&storage_dir);
}

/// A public port already in use fails `host_site_until` with a serve error at
/// the bind, before any storage is opened, and the error names the address.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_site_held_port_fails_at_the_bind() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let storage_dir = tmp.path().join("storage");
    std::fs::create_dir_all(&storage_dir).expect("create storage dir");

    // Held for the whole run, so the bind cannot succeed.
    let held = TcpListener::bind(("0.0.0.0", 0)).expect("bind a port to hold");
    let port = held.local_addr().expect("local addr").port();

    let config = HostSiteConfig {
        tls: TlsMode::Plaintext,
        port,
        storage_path: Some(storage_dir.clone()),
        ..HostSiteConfig::defaults(Reach::Local)
    };
    let result = tokio::time::timeout(
        STEP_DEADLINE,
        host_site_until(config, std::future::pending::<()>()),
    )
    .await
    .expect("host_site_until must fail within 60s");
    match result {
        Err(scp_node::HostSiteError::Serve(msg)) => assert!(
            msg.contains(&format!("0.0.0.0:{port}")),
            "the bind error must name the held address, got {msg}"
        ),
        other => panic!("a held public port must fail with a serve error, got {other:?}"),
    }
    drop(held);
    assert!(
        !storage_dir.join("scp.db").exists(),
        "the bind must fail before the node store is opened"
    );
}
