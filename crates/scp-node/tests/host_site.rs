//! End-to-end integration test for the public [`scp_node::host_site_until`]
//! library API (the reusable core behind `scp-node --self-host`).
//!
//! Drives the FULL host-a-website flow in-process with no real network
//! exposure: a hermetic tempdir storage path, an in-memory DHT (nothing
//! published), plaintext HTTP, NAT probing skipped (no router port opened), an
//! OS-assigned free loopback port, and a caller-controlled shutdown. It then
//! performs a real HTTP `GET` against the running listener and asserts a `200`
//! with the deployed site body — proving the new API works end to end
//! (publish -> commit -> HTTP serve), then triggers shutdown and asserts the
//! task returns `Ok(())`.
//!
//! Provenance: `.docs/guides/self-hosting-a-website-on-scp.md`; specs §10.12.8
//! (Infrastructure & Self-Hosting) + §18 (Addressability & Deployment).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::TcpListener;
use std::time::Duration;

use scp_node::{DhtMode, HostSiteOptions, HostSiteReady, host_site_until};

/// Reserves an OS-assigned free port on loopback by binding a `TcpListener`,
/// reading its port, then dropping the listener so `host_site` can rebind it.
///
/// A brief race window exists between drop and rebind; a high OS-assigned port
/// makes a collision vanishingly unlikely, and the test connects to the same
/// port `host_site` binds.
fn free_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

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

    let port = free_port();

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

    let opts = HostSiteOptions {
        site_dir: Some(site_dir.clone()),
        port,
        storage_path: Some(storage_dir.clone()),
        // Hermetic + offline: plaintext (no TLS dance), skip NAT (no router
        // port), in-memory DHT (nothing published).
        plaintext: true,
        skip_nat: true,
        dht_mode: DhtMode::Memory,
        on_ready: Some(Box::new(move |ready: HostSiteReady| {
            if let Some(tx) = ready_tx.take() {
                let _ = tx.send(ready);
            }
        })),
        ..Default::default()
    };

    // -- Spawn the hosted site as a task; it serves until `shutdown` resolves. --
    let handle = tokio::spawn(async move { host_site_until(opts, shutdown).await });

    // -- Wait for the ready signal (deploy complete, serving imminent). --
    let ready = tokio::time::timeout(Duration::from_mins(1), ready_rx)
        .await
        .expect("host_site should reach ready within 60s")
        .expect("on_ready should fire (sender not dropped)");
    assert_eq!(ready.port, port, "ready port must match the requested port");
    assert!(
        ready.node_did.starts_with("did:dht:"),
        "node DID should be a did:dht, got {}",
        ready.node_did
    );
    assert_eq!(ready.asset_count, 2, "the sample site has two assets");
    assert!(ready.plaintext, "the test runs in plaintext mode");

    // -- Real HTTP GET against the running listener. `host_site` binds
    //    `0.0.0.0:<port>`, so connect via loopback. The listener opens just
    //    after `on_ready`, so retry briefly to avoid a connect race. --
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/index.html");
    let mut last_err = None;
    let mut body = None;
    for _ in 0..50 {
        match client.get(&url).send().await {
            Ok(resp) if resp.status().as_u16() == 200 => {
                let text = resp.text().await.expect("response body should read");
                body = Some(text);
                break;
            }
            Ok(resp) => {
                last_err = Some(format!("unexpected status {}", resp.status()));
            }
            Err(e) => {
                last_err = Some(e.to_string());
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let body = body.unwrap_or_else(|| {
        panic!("GET {url} never returned 200; last error: {last_err:?}");
    });
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
}
