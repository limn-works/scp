//! Test-only local HTTPS server that serves a `.well-known/scp` document, plus
//! a matching trusting `reqwest::Client`, for connect-time transport-discovery
//! tests (`discovery.rs`, `selection.rs`).
//!
//! Production discovery never uses any of this — it builds a non-permissive
//! WebPKI-roots client and fetches the real relay's `.well-known/scp`. These
//! helpers exist solely so the *real* fetch + parse + cache + selection path
//! can be exercised against a controlled local `https://` endpoint with a
//! self-signed cert the test client explicitly trusts (no permissive TLS).

#![cfg(all(test, feature = "quic"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// A running local HTTPS server that answers `GET /.well-known/scp` with a
/// fixed JSON body and counts how many requests it served.
pub struct WellKnownServer {
    /// The address the server is bound to (`127.0.0.1:<port>`).
    pub addr: SocketAddr,
    /// PEM-encoded self-signed cert the server presents — load it into the
    /// test client's root store so the fetch is trusted (not permissive).
    pub cert_pem: String,
    /// Number of `.well-known/scp` requests served so far.
    request_count: Arc<AtomicUsize>,
    /// Shutdown signal for the accept loop.
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl WellKnownServer {
    /// Returns the number of `.well-known/scp` requests served so far.
    pub fn request_count(&self) -> usize {
        self.request_count.load(Ordering::SeqCst)
    }

    /// The `wss://` relay URL whose `well_known_url()` maps onto this server.
    pub fn relay_url(&self) -> String {
        format!("wss://{}/scp/v1", self.addr)
    }
}

impl Drop for WellKnownServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

/// Starts a local HTTPS server that serves `body_json` at `/.well-known/scp`
/// with a `200 OK`.
///
/// The server presents a self-signed cert for `127.0.0.1`; the returned
/// `cert_pem` must be loaded into the test client's root store.
pub async fn start_well_known_server(body_json: String) -> WellKnownServer {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        body_json.len(),
        body_json
    );
    start_raw_response_server(response).await
}

/// Starts a local HTTPS server that answers every request with a `302` redirect
/// to `location`, so discovery's no-redirect / `https_only` hardening can be
/// exercised (a hostile relay 30x-bouncing the well-known fetch).
///
/// The redirect carries no body. A discovery client that refuses redirects must
/// surface the `302` as a non-success status and never issue a second request.
pub async fn start_redirect_server(location: &str) -> WellKnownServer {
    let response = format!(
        "HTTP/1.1 302 Found\r\nLocation: {location}\r\n\
         Content-Length: 0\r\nConnection: close\r\n\r\n"
    );
    start_raw_response_server(response).await
}

/// Starts a local HTTPS server that serves a body of exactly `size` bytes at
/// `/.well-known/scp` with a truthful `Content-Length`, so discovery's body cap
/// can be exercised. The body is ASCII filler (not valid SCP JSON), which is
/// irrelevant: an oversized body must be rejected before it is ever parsed.
pub async fn start_oversized_body_server(size: usize) -> WellKnownServer {
    let filler = "a".repeat(size);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
         Content-Length: {size}\r\nConnection: close\r\n\r\n{filler}"
    );
    start_raw_response_server(response).await
}

/// Starts a local HTTPS server that answers every accepted connection with the
/// exact `raw_response` bytes (status line + headers + body), counting served
/// requests. The building block for the convenience servers above.
async fn start_raw_response_server(raw_response: String) -> WellKnownServer {
    // Self-signed cert/key for 127.0.0.1 (so the SNI/hostname check passes).
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_der = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());

    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(rustls::DEFAULT_VERSIONS)
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)
    .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    let request_count = Arc::new(AtomicUsize::new(0));
    let count_for_task = Arc::clone(&request_count);
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();

    let response = Arc::new(raw_response);

    tokio::spawn(async move {
        loop {
            let accept = tokio::select! {
                res = listener.accept() => res,
                _ = &mut shutdown_rx => break,
            };
            let Ok((stream, _peer)) = accept else {
                continue;
            };
            let acceptor = acceptor.clone();
            let count = Arc::clone(&count_for_task);
            let response = Arc::clone(&response);
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                // Read the request line (enough to confirm a request arrived).
                let mut buf = [0u8; 1024];
                let _ = tls.read(&mut buf).await;
                count.fetch_add(1, Ordering::SeqCst);
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.flush().await;
                let _ = tls.shutdown().await;
            });
        }
    });

    WellKnownServer {
        addr,
        cert_pem,
        request_count,
        shutdown: Some(shutdown_tx),
    }
}

/// Builds a `reqwest::Client` that trusts the server's self-signed cert.
///
/// This is the test seam: the client is non-permissive (it validates against
/// the explicitly-added root), it just trusts a local test root instead of the
/// `WebPKI` bundle. It never sets `danger_accept_invalid_certs`.
pub fn trusting_client(cert_pem: &str, timeout: Duration) -> reqwest::Client {
    let cert = reqwest::Certificate::from_pem(cert_pem.as_bytes()).unwrap();
    reqwest::Client::builder()
        .add_root_certificate(cert)
        .timeout(timeout)
        .build()
        .unwrap()
}

/// Builds a trusting `reqwest::Client` that *also* carries the production
/// discovery hardening: no redirects ([`reqwest::redirect::Policy::none`]) and
/// `https_only`. Used by the SSRF/downgrade tests so they exercise the exact
/// hardening flags production's `http_client()` sets, differing only in the
/// trusted root (a local self-signed cert instead of the `WebPKI` bundle).
pub fn hardened_trusting_client(cert_pem: &str, timeout: Duration) -> reqwest::Client {
    let cert = reqwest::Certificate::from_pem(cert_pem.as_bytes()).unwrap();
    reqwest::Client::builder()
        .add_root_certificate(cert)
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .build()
        .unwrap()
}
