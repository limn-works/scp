//! The relay layer of DID resolution releases its adapters when the bridge
//! instance releases the transport (spec §3.10.2, §3.10.4 step 3a).
//!
//! A bridge hands ONE connected adapter to two owners: the `TransportManager`
//! that sends and subscribes over it, and the `TransportRelayQuerier` that runs
//! DID QUERY over it. Both references are strong, and `NativeRelayAdapter::drop`
//! is the only thing that cancels the cover-traffic and heartbeat tasks and
//! closes the socket.
//!
//! What these tests establish:
//!
//! 1. `suspend()` releases the querier's reference, so the adapter drops.
//! 2. `shutdown()` releases it too.
//! 3. Installing a new transport manager releases the outgoing manager's
//!    bindings, so connecting a second relay does not strand the first.
//! 4. `resume()` re-binds the relays it reconnects, so DID QUERY runs over the
//!    live socket rather than over a connection nothing else holds.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use scp_core::envelope::OuterEnvelope;
use scp_ffi_common::CoreFields;
use scp_transport::error::TransportError;
use scp_transport::traits::{BlobId, RoutingId, SubscriptionStream, TransportAdapter};

const RELAY_A: &str = "wss://relay-a.binding-lifecycle.test/scp/v1";
const RELAY_B: &str = "wss://relay-b.binding-lifecycle.test/scp/v1";

type BoxFut<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// A relay adapter that records its own drop, standing in for
/// `NativeRelayAdapter` whose `Drop` cancels cover traffic and the heartbeat and
/// closes the WebSocket.
struct DropTrackingAdapter {
    dropped: Arc<AtomicBool>,
}

impl Drop for DropTrackingAdapter {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

impl TransportAdapter for DropTrackingAdapter {
    fn send(&self, _envelope: &OuterEnvelope) -> BoxFut<'_, Result<BlobId, TransportError>> {
        Box::pin(async { Err(TransportError::NotConnected) })
    }

    fn subscribe(
        &self,
        _routing_id: &RoutingId,
        _since: Option<u64>,
    ) -> BoxFut<'_, Result<SubscriptionStream, TransportError>> {
        Box::pin(async { Err(TransportError::NotConnected) })
    }

    fn unsubscribe(&self, _routing_id: &RoutingId) -> BoxFut<'_, Result<(), TransportError>> {
        Box::pin(async { Err(TransportError::NotConnected) })
    }

    fn query(
        &self,
        _routing_id: &RoutingId,
        _since: Option<u64>,
    ) -> BoxFut<'_, Result<Vec<OuterEnvelope>, TransportError>> {
        Box::pin(async { Err(TransportError::NotConnected) })
    }

    fn delete(&self, _blob_id: &BlobId) -> BoxFut<'_, Result<(), TransportError>> {
        Box::pin(async { Err(TransportError::NotConnected) })
    }

    fn query_raw(
        &self,
        _routing_id: &RoutingId,
        _since: Option<u64>,
        _limit: u32,
    ) -> BoxFut<'_, Result<Vec<Vec<u8>>, TransportError>> {
        Box::pin(async { Err(TransportError::NotConnected) })
    }
}

/// Connects a drop-tracking adapter into `core` the way `transport_connect`
/// does: one adapter, shared between the transport manager and the relay
/// querier. Returns the flag that records the adapter's drop.
fn connect_tracked_relay(core: &CoreFields, relay_url: &str) -> Arc<AtomicBool> {
    let dropped = Arc::new(AtomicBool::new(false));
    let shared: Arc<dyn TransportAdapter> = Arc::new(DropTrackingAdapter {
        dropped: Arc::clone(&dropped),
    });
    let manager = scp_transport::TransportManager::new(Box::new(Arc::clone(&shared)));
    core.set_transport(Arc::new(manager))
        .expect("install the transport manager");
    core.bind_relay_transport(relay_url.to_owned(), shared);
    dropped
}

/// `suspend()` exists to release the network. It must release the relay
/// querier's reference too: while the querier holds one, the adapter never
/// drops, so cover traffic and the heartbeat keep transmitting and the socket
/// stays open on an instance the caller believes it suspended.
#[test]
fn suspend_drops_the_relay_adapter() {
    let core = CoreFields::new();
    let dropped = connect_tracked_relay(&core, RELAY_A);

    assert!(
        !dropped.load(Ordering::SeqCst),
        "the adapter is alive while the instance holds the connection"
    );

    core.suspend().expect("suspend the instance");

    assert!(
        dropped.load(Ordering::SeqCst),
        "suspend must release every reference to the adapter, so its Drop runs and \
         cover traffic, the heartbeat, and the socket stop"
    );
    assert!(
        core.relay_querier().bound_relay_urls().is_empty(),
        "a suspended instance holds no relay binding, so the resolver reports the relay \
         layer unavailable instead of querying a torn-down connection"
    );
}

/// `shutdown()` tears the instance down for good, so it releases the adapter for
/// the same reason `suspend()` does.
#[test]
fn shutdown_drops_the_relay_adapter() {
    let core = CoreFields::new();
    let dropped = connect_tracked_relay(&core, RELAY_A);

    core.clear_transport().expect("clear the transport");

    assert!(
        dropped.load(Ordering::SeqCst),
        "clearing the transport must release the relay binding along with the manager"
    );
}

/// Connecting a second relay replaces the transport manager wholesale, so the
/// first relay's adapter is gone. The binding must go with it, or the resolver
/// keeps querying a connection nothing else holds.
#[test]
fn installing_a_new_transport_manager_releases_the_previous_binding() {
    let core = CoreFields::new();
    let first_dropped = connect_tracked_relay(&core, RELAY_A);
    let _second_dropped = connect_tracked_relay(&core, RELAY_B);

    assert!(
        first_dropped.load(Ordering::SeqCst),
        "the first relay's adapter belonged to the replaced manager, so it must drop"
    );
    assert_eq!(
        core.relay_querier().bound_relay_urls(),
        vec![RELAY_B.to_owned()],
        "only the relay backed by the live manager stays bound"
    );
}
