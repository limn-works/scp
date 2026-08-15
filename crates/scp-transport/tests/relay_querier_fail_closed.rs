//! The relay querier fails closed when the relay it is bound to goes away
//! (spec `.docs/specs/17-persistence-and-storage.md` §17.17.1 SCP-CAPSEL-8001;
//! `.docs/specs/03-identity-and-did.md` §3.10.2/§3.10.4).
//!
//! `TransportRelayQuerier` is the shipped production arm of the relay-querier
//! capability: it is the only non-test implementation of the `scp-identity`
//! `RelayQuerier` trait, and it answers a DID QUERY over a live relay
//! connection. Its backing resource is that connection.
//!
//! This test starts a real `RelayServer`, connects a real `NativeRelayAdapter`
//! to it, binds that adapter into a real `TransportRelayQuerier`, then destroys
//! the server so the connection is genuinely dead, and asserts the querier
//! returns the named [`IdentityError::RelayQueryFailed`] variant. A querier
//! that answered `Ok(candidates)` after its relay died would feed the
//! `RealMultiRelayQuerier` composer records no relay ever served, which is the
//! fabricated answer §3.10.4 forbids.
//!
//! The relay server runs on its own tokio runtime in its own thread. Dropping
//! that runtime tears down the listener and every live connection handler at
//! once; `ShutdownHandle::shutdown` alone only stops the accept loop and leaves
//! established connections serving, so it cannot make the resource unavailable.

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
                let config = RelayConfig {
                    bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                    ttl_check_interval: Duration::from_millis(100),
                    delivery_jitter_ms: 0,
                    ..RelayConfig::default()
                };
                let storage = Arc::new(BlobStorageBackend::in_memory());
                let (handle, addr) = RelayServer::new(config, storage)
                    .start()
                    .await
                    .expect("bind the relay server");
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

#[tokio::test]
async fn transport_relay_querier_fails_closed_when_its_relay_dies() {
    let relay = DedicatedRelay::start();
    let url = relay.url();

    // `ws://` is permitted only for a DHT-resolved relay URL, which is what a
    // self-hosted relay behind NAT presents.
    let sourced = SourcedRelayUrl {
        url: url.clone(),
        source: RelayUrlSource::DhtResolved,
    };
    let adapter = NativeRelayAdapter::connect_sourced(&sourced, None)
        .await
        .expect("connect the real adapter to the live relay");

    let querier = TransportRelayQuerier::new();
    querier.bind(url.clone(), Arc::new(adapter));

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

    // Destroy the relay: the connection the querier holds is now dead.
    relay.kill();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let result = querier.query(&url, &routing_id).await;

    match result {
        Err(IdentityError::RelayQueryFailed(message)) => {
            assert!(
                !message.is_empty(),
                "the fail-closed relay-query error must carry a diagnostic message"
            );
        }
        Err(other) => panic!("expected IdentityError::RelayQueryFailed, got {other:?}"),
        Ok(candidates) => panic!(
            "a querier whose relay is gone must fail closed with \
             IdentityError::RelayQueryFailed; it returned {} candidate(s) instead, which \
             would feed the composer records no relay served (§3.10.4)",
            candidates.len()
        ),
    }
}
