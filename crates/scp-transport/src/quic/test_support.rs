//! Reusable QUIC test harness (in-process listener + matching client).
//!
//! These helpers spin up a real `quinn` QUIC listener bound to a loopback
//! ephemeral port with a self-signed certificate, plus a [`QuicAdapter`] client
//! configured to trust exactly that certificate. They back both the in-module
//! `QuicAdapter` integration tests (`quic/adapter.rs`) and the out-of-crate
//! conformance / migration integration tests (`tests/quic_conformance.rs`,
//! `tests/quic_migration.rs`).
//!
//! # Why this lives in `src/` rather than a `tests/` module
//!
//! Cargo integration tests compile the crate as an *external* dependency, so
//! they can only reach `pub` items. The harness therefore has to be a public
//! module of the crate. It is gated on `#[cfg(feature = "quic")]` (the same
//! gate as the QUIC adapter it exercises) and marked `#[doc(hidden)]` so it
//! never appears in the public API surface — it is test scaffolding, not a
//! supported entry point.
//!
//! The helpers are intentionally permissive about `unwrap`/`expect`: they are
//! test fixtures whose failure should abort the test loudly.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::native::storage::InMemoryBlobStorage;
use crate::profile::TransportProfile;
use crate::quic::adapter::QuicAdapter;
use crate::quic::lifecycle::{QuicLifecycleManager, SessionTicketStore};
use crate::quic::listener::{
    QuicListener, QuicListenerConfig, QuicShutdownHandle, SCP_ALPN, build_server_config,
};
use crate::relay::rate_limit::{self, PublishRateLimiter};
use crate::relay::subscription::{self, SubscriptionRegistry};

/// Builds a self-signed `localhost` server config and returns it alongside the
/// certificate DER so a client can be configured to trust exactly this cert.
#[must_use]
pub fn test_server_config() -> (quinn::ServerConfig, Vec<CertificateDer<'static>>) {
    // Idempotent: harmless if another test already installed the provider.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let server_config =
        build_server_config(vec![cert_der.clone()], PrivateKeyDer::Pkcs8(key_der)).unwrap();
    (server_config, vec![cert_der])
}

/// Builds a `quinn::ClientConfig` trusting exactly the supplied server certs.
///
/// Uses a private root store (NOT the Web PKI bundle) with the SCP ALPN
/// negotiated. This is the test counterpart to the production
/// `build_quic_client_config`, which uses Web PKI roots.
#[must_use]
pub fn test_client_config(server_certs: &[CertificateDer<'static>]) -> quinn::ClientConfig {
    let mut root_store = rustls::RootCertStore::empty();
    for cert in server_certs {
        root_store.add(cert.clone()).unwrap();
    }
    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![SCP_ALPN.to_vec()];

    let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config).unwrap();
    quinn::ClientConfig::new(Arc::new(quic_client_config))
}

/// Starts an in-process QUIC listener bound to `127.0.0.1:0` (ephemeral port)
/// backed by [`InMemoryBlobStorage`] with delivery jitter disabled.
///
/// Returns the shutdown handle, the bound address, the server cert chain (for
/// configuring a matching client), the shared blob storage, and the shared
/// subscription registry.
///
/// Must be called from within a tokio runtime context: the listener spawns its
/// accept loop via [`tokio::spawn`].
#[must_use]
pub fn start_test_listener() -> (
    QuicShutdownHandle,
    SocketAddr,
    Vec<CertificateDer<'static>>,
    Arc<InMemoryBlobStorage>,
    SubscriptionRegistry,
) {
    let (server_config, certs) = test_server_config();
    let storage = Arc::new(InMemoryBlobStorage::new());
    let subscriptions = subscription::new_registry();
    let publish_rate_limiter = PublishRateLimiter::new(100);
    let connection_tracker = rate_limit::new_connection_tracker();

    let config = QuicListenerConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        delivery_jitter_ms: 0,
        ..QuicListenerConfig::default()
    };

    let listener = QuicListener::new(
        config,
        Arc::clone(&storage),
        Arc::clone(&subscriptions),
        publish_rate_limiter,
        connection_tracker,
    );
    let (handle, addr) = listener.start(server_config).unwrap();

    (handle, addr, certs, storage, subscriptions)
}

/// A desktop-profile lifecycle manager with a fresh, empty session ticket store.
#[must_use]
pub fn test_lifecycle() -> QuicLifecycleManager {
    QuicLifecycleManager::new(TransportProfile::Desktop, SessionTicketStore::new())
}

/// Connects a [`QuicAdapter`] to the given address, trusting `certs`, using a
/// fresh desktop lifecycle. Panics if the connection cannot be established.
#[must_use]
pub async fn connect_adapter(addr: SocketAddr, certs: &[CertificateDer<'static>]) -> QuicAdapter {
    let client_config = test_client_config(certs);
    let lifecycle = test_lifecycle();
    QuicAdapter::connect(addr, "localhost", client_config, lifecycle)
        .await
        .expect("failed to connect QuicAdapter")
}

/// Connects a [`QuicAdapter`] to `addr` (trusting `certs`) over a client
/// [`quinn::Endpoint`] that is **returned to the caller** alongside the adapter.
///
/// [`connect_adapter`] hides the endpoint inside `QuicAdapter::connect`, which
/// is the right shape for the conformance suite but useless for a migration
/// test: exercising connection migration requires calling
/// [`quinn::Endpoint::rebind`] on the *client* endpoint to swap its local UDP
/// socket. This helper therefore builds the endpoint explicitly (mirroring
/// `QuicAdapter::connect`'s loopback-IPv4 bind), performs the handshake, and
/// wraps the resulting connection via [`QuicAdapter::from_connection`] so the
/// adapter and the endpoint that drives it are both available.
///
/// # Panics
///
/// Panics if the client endpoint cannot bind or the handshake fails — both
/// abort the test.
#[must_use]
pub async fn connect_adapter_with_endpoint(
    addr: SocketAddr,
    certs: &[CertificateDer<'static>],
) -> (QuicAdapter, quinn::Endpoint) {
    // Bind the client to the loopback IPv4 wildcard, matching the IPv4
    // listener address family that `start_test_listener` binds.
    let mut endpoint =
        quinn::Endpoint::client(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)))
            .expect("client endpoint should bind");
    endpoint.set_default_client_config(test_client_config(certs));

    let connection = endpoint
        .connect(addr, "localhost")
        .expect("connect should be accepted")
        .await
        .expect("handshake should complete");

    let adapter = QuicAdapter::from_connection(connection, test_lifecycle());
    (adapter, endpoint)
}

/// Builds a fully connected [`QuicAdapter`] backed by a fresh in-process QUIC
/// listener, returning it from a **synchronous** call.
///
/// # Why this exists
///
/// The `transport_conformance!` macro evaluates its factory expression
/// *synchronously* — once per generated `#[tokio::test]` — and never `.await`s
/// it (`let adapter = $factory;`). QUIC setup, however, is inherently async:
/// binding a `quinn::Endpoint`, spawning the listener accept loop, and
/// completing the TLS 1.3 handshake all require a tokio runtime. A naive
/// `Handle::current().block_on(...)` inside the factory would panic (you cannot
/// block the current-thread test runtime on itself), and `block_in_place`
/// requires the multi-threaded flavor the macro does not use.
///
/// This helper therefore drives the entire async setup on a **dedicated
/// background OS thread** running its own current-thread runtime. That runtime
/// owns the listener endpoint *and* the client endpoint, so their packet
/// drivers keep running there. The returned [`QuicAdapter`] holds a
/// `quinn::Connection`, which is `Send` and can be polled from the *test's*
/// runtime in the macro body; quinn drives the connection's actual I/O via the
/// endpoint drivers on the background runtime. This cross-runtime split is a
/// supported quinn usage pattern.
///
/// # Lifetime / leak rationale
///
/// The background runtime, the listener shutdown handle, and the storage Arc
/// are intentionally **leaked** (`Box::leak` / `std::mem::forget`) so they live
/// for the remainder of the test binary. If they dropped at the end of this
/// function, the endpoints would close and the connection would die before the
/// conformance test could use it. The `combined_conformance` storage harness
/// leaks its `TempDir` for the same reason: a per-test fixture that must
/// outlive the synchronous factory call. The OS process reclaims everything on
/// exit, so this is a bounded, test-only leak (one listener + one runtime per
/// conformance test case).
///
/// # Panics
///
/// Panics if the background runtime cannot be built, the listener fails to
/// bind, or the client handshake fails — all of which should abort the test.
#[must_use]
pub fn conformance_quic_adapter() -> QuicAdapter {
    // Channel to hand the connected adapter back to the caller's (test) thread.
    let (tx, rx) = std::sync::mpsc::channel::<QuicAdapter>();

    // A dedicated background OS thread owns a current-thread runtime that builds
    // and then *keeps driving* both endpoints. We never join this thread: it
    // parks forever inside `block_on`, so the listener + client endpoint packet
    // drivers (spawned onto this runtime) keep running for the whole test. The
    // thread, its runtime, listener handle, and storage are all effectively
    // leaked for the test binary's lifetime — the OS reclaims them at exit. This
    // mirrors the `combined_conformance` storage harness, which leaks its
    // `TempDir` so a per-test fixture outlives the synchronous factory call.
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build background QUIC runtime");

        runtime.block_on(async move {
            let (handle, addr, certs, storage, _subs) = start_test_listener();
            let adapter = connect_adapter(addr, &certs).await;

            // Hand the connected adapter to the test thread.
            tx.send(adapter)
                .expect("conformance adapter receiver dropped before setup completed");

            // Keep the listener up and storage alive for the test's lifetime;
            // never shut down. Park forever so this current-thread runtime keeps
            // driving the listener accept loop and both endpoints' packet I/O.
            let _keep_listener = handle;
            let _keep_storage = storage;
            std::future::pending::<()>().await;
        }); // ci-allow: block-on: QUIC test harness — synchronous fixture drives an async listener
    });

    rx.recv()
        .expect("background QUIC setup thread terminated before producing an adapter")
}
