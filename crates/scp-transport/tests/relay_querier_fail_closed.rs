//! Both relay-querier arms answer without fabricating a DID record — the arm
//! every shipped assembly selects, and the arm none of them selects
//! (spec `.docs/specs/17-persistence-and-storage.md` §17.17.1 SCP-CAPSEL-8001;
//! `.docs/specs/03-identity-and-did.md` §3.10.2/§3.10.4).
//!
//! # Which arm ships, and which does not
//!
//! The relay querier is one of the seven provider capabilities §17.17 of the
//! persistence spec enumerates. Two implementations of it exist outside test
//! code, and they sit at different levels of the resolver stack:
//!
//! - `NoOpRelayQuerier` implements the composer trait `MultiRelayQuerier` and
//!   answers `Ok(None)`. **Every shipped assembly selects it**:
//!   `crates/scp-ffi/src/identity.rs:142`, `crates/scp-ffi/napi/src/identity.rs:196`,
//!   `crates/scp-ffi/uniffi/src/bridge.rs:9475`, and
//!   `crates/scp-node/src/self_host.rs` each construct `Arc::new(NoOpRelayQuerier)`
//!   and hand it to the `DualLayerResolver`.
//! - `TransportRelayQuerier` implements the single-relay trait `RelayQuerier`
//!   and answers a DID QUERY over a live relay connection. **No shipped
//!   assembly constructs it.** Its only construction sites are this file and
//!   `crates/scp-transport/src/native/relay_querier.rs`'s own `mod tests`.
//!   `RealMultiRelayQuerier`, the composer that would wrap it, is likewise
//!   constructed only from test modules.
//!
//! ADR-062, capability injection and prove-absent dev backends, decided that
//! split rather than inheriting it: its Slice 11 states "`NoOpRelayQuerier`
//! stays a shipped production arm, unchanged (the honest not-a-DID-source
//! case)", and its A2↔A4 sequencing paragraph states "The relay resolution
//! layer is `NoOpRelayQuerier` (returns `Ok(None)`) until **issue #482** builds
//! the real `MultiRelayQuerier`". Issue #482, relay DID resolution, is the
//! workstream that will select `TransportRelayQuerier` into the bridges.
//!
//! # What each test below therefore proves, and what it does not
//!
//! `shipped_no_op_relay_querier_answers_the_honest_absent_state` covers the arm
//! that ships. §17.17.2 requires each capability's arm to answer honestly, and
//! for a querier bound to no relay the honest answer is the protocol-supported
//! absent state `Ok(None)`, not a typed error — a resolver that treated
//! "no relay layer configured" as an error would break the `DualLayerResolver`
//! fall-through §3.10.4 defines.
//!
//! `unselected_transport_relay_querier_fails_closed_when_its_relay_dies` covers
//! the arm that does not ship. Deleting `TransportRelayQuerier` from the tree
//! would leave every shipped binary byte-identical and would delete that test
//! along with the type, so the test constrains no shipped behaviour today. It
//! is here for two reasons that hold regardless: it holds the type to
//! SCP-CAPSEL-8001 before #482 wires it into a bridge, and its presence in this
//! file is the record that a production type ships unselected. Read the pair
//! together and the capability's real state is legible: the relay layer answers
//! "I am not a DID source" in every shipped artifact, and the code that would
//! make it a DID source is written, tested, and not yet selected.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use scp_identity::IdentityError;
use scp_identity::resolution::RelayQuerier;
use scp_identity::resolver::{MultiRelayQuerier, NoOpRelayQuerier};
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

/// The arm every shipped assembly selects answers `Ok(None)` — the honest
/// protocol-supported absent state (§17.17.2, ADR-062 §Decision 5). A shipped
/// build has no relay DID-resolution layer until issue #482 lands, so the
/// querier reports that it holds nothing; it never returns a record, and it
/// never turns "no relay layer" into an error that would stop the
/// `DualLayerResolver` from consulting the DHT layer (§3.10.4).
#[tokio::test]
async fn shipped_no_op_relay_querier_answers_the_honest_absent_state() {
    let querier = NoOpRelayQuerier;

    let relay_urls = vec![
        "wss://relay.example.com/scp/v1".to_owned(),
        "wss://relay2.example.com/scp/v1".to_owned(),
    ];

    let answer = querier
        .query("did:dht:z6MkExampleShippedBuild", &relay_urls)
        .await
        .expect("the shipped relay arm reports absence, so it must not error");

    assert!(
        answer.is_none(),
        "the shipped relay arm holds no DID record and must answer Ok(None); returning a record \
         here would hand the resolver a document no relay ever served (§3.10.4)"
    );

    // The same answer with no relay URLs at all: absence does not depend on
    // which relays the caller names.
    let answer_without_relays = querier
        .query("did:dht:z6MkExampleShippedBuild", &[])
        .await
        .expect("the shipped relay arm reports absence, so it must not error");
    assert!(answer_without_relays.is_none());
}

/// `TransportRelayQuerier` — the arm no shipped assembly selects, per this
/// file's module documentation — returns the named
/// [`IdentityError::RelayQueryFailed`] once the relay it is bound to is gone.
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
async fn unselected_transport_relay_querier_fails_closed_when_its_relay_dies() {
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
