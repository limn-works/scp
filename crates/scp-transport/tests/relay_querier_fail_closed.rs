//! `TransportRelayQuerier` returns a typed error, not an empty answer, once
//! the relay it is bound to has died (spec
//! `.docs/specs/17-persistence-and-storage.md` §17.17.1 SCP-CAPSEL-8001;
//! `.docs/specs/03-identity.md` §3.10.4 "MUST NOT fabricate").
//!
//! `TransportRelayQuerier` (SCP-RELAYRES-002) is written and not yet selected.
//! The production sites that build a resolver construct `NoOpRelayQuerier`
//! instead: `ensure_did_resolver_initialized_on` in `crates/scp-ffi/src/identity.rs`,
//! `crates/scp-ffi/napi/src/identity.rs`, and `crates/scp-ffi/uniffi/src/bridge.rs`,
//! and `build_shared_cache_key_resolver` in `crates/scp-node/src/self_host.rs`.
//! Every other construction of `NoOpRelayQuerier` sits in test code. ADR-062
//! §Decision 5 classifies `NoOpRelayQuerier` as failing CLOSED: "its `query`
//! returns `Ok(None)` ... and the resolver passes that honest not-found through
//! rather than fabricating a record". SCP-RELAYRES-006 ends the self-host
//! node's use of that type only. The three bridge assemblies keep it until the
//! identity workstream deletes did:dht.
//!
//! The test below holds `TransportRelayQuerier` to SCP-CAPSEL-8001 before any
//! assembly selects it. It covers a query issued after the client has seen the
//! relay die. A query in flight when the relay dies is not covered; the client
//! resolves it Ok at its deadline.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use scp_identity::IdentityError;
use scp_identity::resolution::RelayQuerier;
use scp_transport::native::TransportRelayQuerier;
use scp_transport::native::adapter::NativeRelayAdapter;
use scp_transport::native::server::{RelayConfig, RelayServer};
use scp_transport::native::storage::BlobStorageBackend;
use scp_transport::relay::connection::{RelayUrlSource, SourcedRelayUrl};
use scp_transport::relay::push_gate::{LiveRelayUrl, RelayUrl};

/// How long the client may take to observe the dead socket before the test
/// fails. Loopback teardown is observed in milliseconds; the bound only stops
/// a regression from hanging the test.
const DISCONNECT_DEADLINE: Duration = Duration::from_secs(5);

/// A relay server owning its own runtime on a dedicated thread. `kill` drops
/// that runtime, which cancels every task the server spawned and closes both
/// the listener and every established connection.
struct DedicatedRelay {
    addr: SocketAddr,
    kill: mpsc::Sender<()>,
    thread: std::thread::JoinHandle<()>,
}

impl DedicatedRelay {
    fn start() -> Self {
        let (addr_tx, addr_rx) = mpsc::channel::<SocketAddr>();
        let (kill_tx, kill_rx) = mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build the relay's dedicated runtime");
            let addr = rt.block_on(async {
                let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                    .await
                    .expect("bind the relay listener");
                let port = listener
                    .local_addr()
                    .expect("relay listener address")
                    .port();
                let relay_url = LiveRelayUrl::new(
                    RelayUrl::new(&format!("ws://127.0.0.1:{port}/scp/v1"))
                        .expect("canonical relay URL"),
                );
                let config = RelayConfig {
                    ttl_check_interval: Duration::from_millis(100),
                    delivery_jitter_ms: 0,
                    ..RelayConfig::defaults(relay_url)
                };
                let storage = Arc::new(BlobStorageBackend::in_memory());
                let (handle, addr) = RelayServer::new(config, storage)
                    .start_with_listener(listener)
                    .await
                    .expect("start the relay server");
                // The handle only stops the accept loop; this test kills the
                // whole runtime instead, so nothing needs to hold it.
                drop(handle);
                addr
            });
            addr_tx.send(addr).expect("report the bound address");
            // Keep the runtime pumping the server's tasks until the test kills it.
            rt.block_on(async move {
                while kill_rx.try_recv().is_err() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            });
            drop(rt);
        });
        let addr = addr_rx.recv().expect("receive the bound address");
        Self {
            addr,
            kill: kill_tx,
            thread,
        }
    }

    fn url(&self) -> String {
        format!("ws://{}/scp/v1", self.addr)
    }

    fn kill(self) {
        self.kill.send(()).expect("signal the relay thread to stop");
        self.thread.join().expect("join the relay thread");
    }
}

/// Waits until the adapter's client reports the connection down, failing the
/// test if that does not happen within [`DISCONNECT_DEADLINE`].
async fn await_disconnect(adapter: &NativeRelayAdapter) {
    let deadline = tokio::time::Instant::now() + DISCONNECT_DEADLINE;
    while adapter.is_connected().await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the client did not observe the dead relay within {DISCONNECT_DEADLINE:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// `TransportRelayQuerier` returns the named
/// [`IdentityError::RelayQueryFailed`] for a query issued after its client has
/// seen the relay die.
///
/// This test starts a real `RelayServer`, connects a real `NativeRelayAdapter`
/// to it, binds that adapter into a real `TransportRelayQuerier`, then destroys
/// the server so the connection is genuinely dead. A querier that answered
/// `Ok(candidates)` after its relay died would feed the `RealMultiRelayQuerier`
/// composer records no relay ever served, which is the fabricated answer
/// §3.10.4 forbids.
///
/// The relay server runs on its own tokio runtime in its own thread. Dropping
/// that runtime tears down the listener and every live connection handler at
/// once; `ShutdownHandle::shutdown` alone only stops the accept loop and leaves
/// established connections serving, so it cannot make the resource unavailable.
#[tokio::test]
async fn transport_relay_querier_fails_closed_after_its_relay_dies() {
    let relay = DedicatedRelay::start();
    let url = relay.url();

    // `ws://` is permitted only for a DHT-resolved relay URL, which is what a
    // self-hosted relay behind NAT presents.
    let sourced = SourcedRelayUrl {
        url: url.clone(),
        source: RelayUrlSource::DhtResolved,
    };
    let adapter = Arc::new(
        NativeRelayAdapter::connect_sourced(&sourced, None)
            .await
            .expect("connect the real adapter to the live relay"),
    );
    assert!(
        adapter.is_connected().await,
        "a freshly connected adapter must report a live connection"
    );

    let querier = TransportRelayQuerier::new();
    querier.bind(url.clone(), Arc::clone(&adapter) as _);

    let routing_id = [7u8; 32];

    // While the relay is alive the querier answers with an empty candidate
    // list, so the assertion below cannot pass merely because the querier
    // errors on every call.
    let live = querier
        .query(&url, &routing_id)
        .await
        .expect("a live relay must answer the QUERY");
    assert!(
        live.is_empty(),
        "the relay holds no DID record at this routing id, so it must return no candidates"
    );

    // Destroy the relay, then wait until the client has seen the dead socket.
    relay.kill();
    await_disconnect(&adapter).await;

    match querier.query(&url, &routing_id).await {
        Err(IdentityError::RelayQueryFailed(_)) => {}
        Err(other) => panic!("expected IdentityError::RelayQueryFailed, got {other:?}"),
        Ok(candidates) => panic!(
            "a querier whose relay is gone must fail closed with \
             IdentityError::RelayQueryFailed; it returned {} candidate(s) instead, which \
             would feed the composer records no relay served (§3.10.4)",
            candidates.len()
        ),
    }
}
