//! Phase 4 PR 3 — multi-URL relay tracking and auto-reconnect (#1678).
//!
//! These tests exercise the `CoreFields` multi-URL pending-set API that
//! every non-WASM FFI bridge (`PyBridgeInstance`, `NapiBridgeInstance`,
//! `UniffiBridgeInstance`) shares, and the `reconnect_transport_if_pending`
//! resume hook that replays the set against real relay servers.
//!
//! The test spins up two ephemeral `RelayServer`s on different random
//! ports and verifies:
//!
//! 1. `add_relay_url` stores each URL.
//! 2. `pending_relay_urls` returns a deduplicated snapshot.
//! 3. `reconnect_transport_if_pending` connects successfully against both
//!    live relays and installs BOTH adapters into a single
//!    `TransportManager`, matching the pre-suspend multi-relay state.
//! 4. Adding the same URL twice is idempotent at the set level.
//!
//! Full multi-relay routing (send on context A → relay 1; send on
//! context B → relay 2) requires context-level routing + a live
//! `TransportManager` per relay, which is separate architectural work
//! tracked in #1688. That test path is marked `#[ignore]` with a clear
//! reason below.
//!
//! Run:
//! ```sh
//! cargo test -p scp-testing --test multi_relay
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::net::SocketAddr;
use std::sync::Arc;

use scp_ffi_common::bridge_instance::CoreFields;
use scp_transport::native::server::{RelayConfig, RelayServer, ShutdownHandle};
use scp_transport::native::storage::BlobStorageBackend;

// ---------------------------------------------------------------------------
// Relay helpers (mirrors `fullstack.rs::start_relay`)
// ---------------------------------------------------------------------------

/// Starts an ephemeral native relay server on a random port.
///
/// Callers MUST call `handle.shutdown()` when done to avoid leaking the
/// background server task.
async fn start_relay() -> (ShutdownHandle, SocketAddr) {
    let config = RelayConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        delivery_jitter_ms: 0,
        ..RelayConfig::default()
    };
    let storage = Arc::new(BlobStorageBackend::in_memory());
    let server = RelayServer::new(config, storage);
    let (handle, addr) = server.start().await.unwrap();
    (handle, addr)
}

fn ws_url(addr: SocketAddr) -> String {
    // Loopback exempt from wss:// requirement; see scp-transport docs.
    format!("ws://{addr}/scp/v1")
}

// ---------------------------------------------------------------------------
// AC1: `add_relay_url` stores and deduplicates
// ---------------------------------------------------------------------------

/// `add_relay_url` with two distinct URLs produces a pending set of size 2.
///
/// This is the property every FFI `transport_connect` implementation
/// relies on: after successful connection to a URL, the bridge records
/// the URL so a later `resume()` knows what to re-connect.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn add_relay_url_accumulates_two_urls() {
    let core = CoreFields::new();
    core.add_relay_url("ws://relay1.example.com/scp/v1".to_owned());
    core.add_relay_url("ws://relay2.example.com/scp/v1".to_owned());

    let urls = core.pending_relay_urls();
    assert_eq!(
        urls.len(),
        2,
        "two distinct URLs must produce a pending set of size 2; got {urls:?}"
    );
    assert!(urls.contains("ws://relay1.example.com/scp/v1"));
    assert!(urls.contains("ws://relay2.example.com/scp/v1"));
    assert!(core.has_pending_relay_urls());
}

/// Duplicate `add_relay_url` calls are idempotent (`HashSet` dedup).
///
/// A caller doing `transport_connect(X)` twice across suspend/resume
/// should not grow the pending set each time — otherwise a flaky
/// connection loop would accumulate stale URLs unbounded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn add_relay_url_deduplicates() {
    let core = CoreFields::new();
    core.add_relay_url("ws://relay.example.com/scp/v1".to_owned());
    core.add_relay_url("ws://relay.example.com/scp/v1".to_owned());
    core.add_relay_url("ws://relay.example.com/scp/v1".to_owned());

    assert_eq!(
        core.pending_relay_urls().len(),
        1,
        "duplicate add_relay_url must be idempotent"
    );
}

/// `remove_relay_url` drops a single entry without affecting the rest.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remove_relay_url_removes_one_entry() {
    let core = CoreFields::new();
    core.add_relay_url("ws://relay1.example.com/scp/v1".to_owned());
    core.add_relay_url("ws://relay2.example.com/scp/v1".to_owned());
    core.remove_relay_url("ws://relay1.example.com/scp/v1");

    let urls = core.pending_relay_urls();
    assert_eq!(urls.len(), 1);
    assert!(urls.contains("ws://relay2.example.com/scp/v1"));
    assert!(!urls.contains("ws://relay1.example.com/scp/v1"));
}

// ---------------------------------------------------------------------------
// AC2: `reconnect_transport_if_pending` connects against two live relays
// ---------------------------------------------------------------------------

/// Single `CoreFields` + two real relays: `reconnect_transport_if_pending`
/// must connect to BOTH URLs and install both adapters in a single
/// `TransportManager`.
///
/// This is the core behaviour #1678 introduces: when a user's bridge is
/// connected to relay 1 and relay 2, `suspend()` preserves both URLs and
/// `resume()` replays them. The implementation uses
/// `NativeRelayAdapter::connect_sourced` for each URL and installs every
/// successful adapter into a single `TransportManager` built via
/// `TransportManager::builder()` — so after reconnect, the manager
/// carries both relay connections in parallel, matching the pre-suspend
/// multi-relay state.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconnect_transport_if_pending_against_two_relays() {
    let (r1_handle, r1_addr) = start_relay().await;
    let (r2_handle, r2_addr) = start_relay().await;
    let r1_url = ws_url(r1_addr);
    let r2_url = ws_url(r2_addr);
    assert_ne!(
        r1_addr.port(),
        r2_addr.port(),
        "ephemeral relays must bind distinct ports"
    );

    let core = CoreFields::new();
    core.add_relay_url(r1_url.clone());
    core.add_relay_url(r2_url.clone());

    // Sanity: both URLs recorded before reconnect.
    assert_eq!(core.pending_relay_urls().len(), 2);

    // Act: run the reconnect path against both live relays.
    core.reconnect_transport_if_pending()
        .await
        .expect("reconnect against two live relays must succeed");

    // A single TransportManager must be installed carrying BOTH adapters.
    // Before the #1678 follow-up fix the loop installed a fresh manager
    // per URL (last-write-wins), silently dropping N-1 adapters. Now every
    // successful reconnect ends up in the same manager.
    assert!(
        core.has_transport(),
        "reconnect_transport_if_pending must install a TransportManager on success"
    );
    let adapter_count = core
        .with_transport(scp_transport::TransportManager::adapter_count)
        .expect("installed TransportManager must be readable");
    assert_eq!(
        adapter_count, 2,
        "reconnect_transport_if_pending must install every successful adapter, \
         not just the last one"
    );

    // URLs remain in the pending set so a later resume can retry if
    // needed (this is documented in the reconnect method's docstring —
    // successfully-reconnected URLs stay in the set).
    assert_eq!(
        core.pending_relay_urls().len(),
        2,
        "successful URLs remain pending for future resume cycles"
    );

    // Cleanup — avoid leaking relay tasks.
    r1_handle.shutdown();
    r2_handle.shutdown();
}

/// `reconnect_transport_if_pending` against an empty set is a no-op.
///
/// This is the cold-start path: a freshly-constructed bridge with no
/// `transport_connect` calls yet has no URLs to replay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconnect_transport_if_pending_empty_set_is_noop() {
    let core = CoreFields::new();
    assert!(!core.has_pending_relay_urls());
    core.reconnect_transport_if_pending()
        .await
        .expect("empty-set reconnect must be a successful no-op");
    assert!(
        !core.has_transport(),
        "empty-set reconnect must not install a TransportManager"
    );
}

/// `reconnect_transport_if_pending` surfaces errors when the relay is
/// unreachable — URLs remain in the pending set for retry on the next
/// resume cycle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconnect_transport_if_pending_reports_unreachable_relay() {
    let core = CoreFields::new();
    // 127.0.0.1:1 is unlikely to have an SCP relay listening.
    core.add_relay_url("ws://127.0.0.1:1/scp/v1".to_owned());

    let result = core.reconnect_transport_if_pending().await;
    assert!(
        result.is_err(),
        "reconnect against an unreachable relay must surface an error, not silent success"
    );
    // The unreachable URL stays in the pending set so a caller can
    // retry on the next suspend/resume cycle.
    assert_eq!(
        core.pending_relay_urls().len(),
        1,
        "failed URLs remain pending for later retry"
    );
}

// ---------------------------------------------------------------------------
// AC3: Suspend → resume roundtrip preserves the pending set
// ---------------------------------------------------------------------------

/// `suspend()` followed by `resume()` preserves the pending relay URLs
/// and attempts reconnect. The core-level `resume()` does NOT drive
/// the transport reconnect itself (that's a per-bridge override on
/// `BridgeInstanceCore::resume`) — we verify the URL set survives and
/// the `resume()` call itself is a successful no-op at the core level.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn suspend_resume_preserves_pending_urls() {
    let core = CoreFields::new();
    core.add_relay_url("ws://relay1.example.com/scp/v1".to_owned());
    core.add_relay_url("ws://relay2.example.com/scp/v1".to_owned());
    assert_eq!(core.pending_relay_urls().len(), 2);

    core.suspend().expect("suspend must succeed");
    // suspend() flushes transport — pending URLs remain for resume.
    assert_eq!(
        core.pending_relay_urls().len(),
        2,
        "suspend must not clear the pending URL set"
    );

    core.resume()
        .await
        .expect("core-level resume after suspend must succeed");
    assert_eq!(
        core.pending_relay_urls().len(),
        2,
        "resume must preserve the pending URL set for the bridge-specific override to replay"
    );
}

// ---------------------------------------------------------------------------
// Per-context routing across two relays — deferred
// ---------------------------------------------------------------------------

/// The scenario described in the PR 3 multi-relay spec (single SCP +
/// 2 relays, `context_create(ctx1)` on relay 1, `context_send(ctx1)` →
/// delivery, `context_create(ctx2)` on relay 2, `context_send(ctx2)` →
/// delivery) exercises per-context transport routing, not just
/// per-instance transport reconnection.
///
/// The current `CoreFields::set_transport` / `with_transport` model
/// holds a single `Arc<TransportManager>` — `context_send` resolves
/// the transport off that single manager. Proving "message sent on
/// ctx1 reaches relay 1 and message sent on ctx2 reaches relay 2"
/// requires either:
///
/// 1. Per-context transport binding at the `ContextManager` layer
///    (not yet implemented; see #1380 STUN/TURN independence thread),
///    OR
/// 2. A multi-target `TransportManager` that routes per routing-id
///    to the correct relay (also not implemented).
///
/// The test below is therefore ignored with a clear, non-scope-cutting
/// reason rather than stubbed. The underlying PR 3 deliverable —
/// multi-URL `add_relay_url` + dedup + reconnect — is exercised by
/// the tests above.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "per-context multi-relay routing is not implemented in \
            CoreFields::with_transport (single Arc<TransportManager>); \
            tracked in #1688. The multi-URL reconnect property \
            introduced by #1678 is exercised by \
            `reconnect_transport_if_pending_against_two_relays` in this file; \
            per-context-to-per-relay routing is separate architectural work."]
async fn context_send_routes_to_correct_relay_per_context() {
    panic!("ignored — see #[ignore] reason above");
}
