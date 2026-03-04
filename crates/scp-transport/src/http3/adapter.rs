//! HTTP/3 server-side handler for SCP relay.
//!
//! Implements the relay's HTTP/3 endpoint per spec section 10.15.1 and
//! ADR-037. The server accepts HTTP/3 connections via QUIC, handles
//! incoming requests (`.well-known/scp`, dev API, broadcast projection),
//! and serves them using the same application logic as HTTP/1.1 and HTTP/2.
//!
//! # Architecture
//!
//! The HTTP/3 server is a thin transport layer that:
//! 1. Accepts QUIC connections via a quinn `Endpoint`
//! 2. Establishes HTTP/3 sessions using the `h3` crate
//! 3. Dispatches incoming HTTP requests to a request handler
//! 4. Injects `Alt-Svc` headers in responses to advertise HTTP/3
//!
//! The actual request handling logic (routing, response generation) is
//! injected via the `RequestHandler` trait, keeping the HTTP/3 transport
//! decoupled from application semantics.
//!
//! See spec section 10.15.1 "Relay HTTP/3 Upgrade Path" for requirements.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use http::Response;
use tracing;

use super::config::Http3Config;
use crate::error::TransportError;
use crate::relay::rate_limit::{self, ConnectionTracker};

/// Maximum number of concurrent HTTP/3 connections before the server
/// starts rejecting new connections. Prevents resource exhaustion from
/// connection floods (BLACK-208 mitigation).
const MAX_CONCURRENT_HTTP3_CONNECTIONS: usize = 1000;

// ---------------------------------------------------------------------------
// Request handler trait
// ---------------------------------------------------------------------------

/// Trait for handling HTTP requests received over HTTP/3.
///
/// Implementations process incoming HTTP requests and produce responses.
/// The same handler can be shared across HTTP/1.1, HTTP/2, and HTTP/3
/// endpoints -- the transport layer is transparent.
///
/// This trait enables the HTTP/3 server to remain transport-only, with
/// application logic injected at construction time.
pub trait RequestHandler: Send + Sync + 'static {
    /// Handles an incoming HTTP request and returns a response.
    ///
    /// The handler receives the HTTP method, URI path, and request headers.
    /// It should return a complete HTTP response including status code,
    /// headers, and body.
    ///
    /// # Arguments
    ///
    /// * `method` -- HTTP method (GET, POST, etc.)
    /// * `uri` -- Request URI path (e.g., `/.well-known/scp`)
    /// * `headers` -- Request headers as key-value pairs
    fn handle(&self, method: &str, uri: &str, headers: &[(String, String)]) -> Response<Vec<u8>>;
}

// ---------------------------------------------------------------------------
// HTTP/3 Server
// ---------------------------------------------------------------------------

/// HTTP/3 server for the SCP relay.
///
/// Accepts HTTP/3 connections via QUIC and dispatches requests to the
/// configured [`RequestHandler`]. Injects `Alt-Svc` headers in all
/// responses to advertise HTTP/3 availability to HTTP/1.1 and HTTP/2
/// clients.
///
/// # Connection coalescing
///
/// Per RFC 9113 section 9.1.1, clients may coalesce connections to
/// origins that share the same IP address and TLS certificate. The
/// HTTP/3 server supports this by using the same TLS certificate for
/// both TCP (HTTP/1.1 + HTTP/2) and UDP (HTTP/3) endpoints. This is
/// configured via [`Http3Config`].
///
/// # Usage
///
/// ```rust,no_run
/// use scp_transport::http3::{Http3Config, Http3Server};
/// use scp_transport::http3::adapter::RequestHandler;
///
/// // Create an HTTP/3 server with a request handler
/// // (TLS certs and handler omitted for brevity)
/// ```
///
/// See spec section 10.15.1 and ADR-037 for the full design.
pub struct Http3Server {
    /// The HTTP/3 configuration including TLS credentials and QUIC
    /// transport parameters.
    config: Http3Config,

    /// The QUIC endpoint for accepting HTTP/3 connections.
    /// `None` until `bind()` is called.
    endpoint: Option<quinn::Endpoint>,

    /// The request handler for processing incoming HTTP requests.
    handler: Arc<dyn RequestHandler>,
}

impl Http3Server {
    /// Creates a new HTTP/3 server with the given configuration and
    /// request handler.
    ///
    /// The server is not yet bound to a socket -- call [`bind`](Self::bind)
    /// to start listening, then [`serve`](Self::serve) to accept connections.
    #[must_use]
    pub fn new(config: Http3Config, handler: Arc<dyn RequestHandler>) -> Self {
        Self {
            config,
            endpoint: None,
            handler,
        }
    }

    /// Returns the server configuration.
    #[must_use]
    pub const fn config(&self) -> &Http3Config {
        &self.config
    }

    /// Returns the bound local address, if the server has been bound.
    #[must_use]
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.endpoint.as_ref().and_then(|ep| ep.local_addr().ok())
    }

    /// Returns the `Alt-Svc` header value for advertising HTTP/3
    /// availability in HTTP/1.1 and HTTP/2 responses.
    ///
    /// This value should be included as an `Alt-Svc` header in all
    /// HTTP/1.1 and HTTP/2 responses served by the relay.
    #[must_use]
    pub fn alt_svc_header_value(&self) -> String {
        self.config.alt_svc().to_header_value()
    }

    /// Returns whether connection coalescing is enabled.
    ///
    /// When enabled, the relay expects clients to coalesce HTTP/3
    /// connections for origins sharing the same IP and TLS certificate.
    /// The relay should use the same certificate for both TCP and UDP
    /// endpoints to enable this behavior.
    #[must_use]
    pub const fn connection_coalescing_enabled(&self) -> bool {
        self.config.connection_coalescing()
    }

    /// Binds the QUIC endpoint to the configured address.
    ///
    /// Creates a quinn `Endpoint` with the TLS credentials and QUIC
    /// transport parameters from the [`Http3Config`]. After binding,
    /// call [`serve`](Self::serve) to start accepting connections.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ConnectionFailed`] if the endpoint
    /// cannot be created (e.g., address in use, invalid TLS config).
    pub fn bind(&mut self) -> Result<SocketAddr, TransportError> {
        let endpoint = self.config.build_endpoint()?;
        let local_addr = endpoint.local_addr().map_err(|e| {
            TransportError::ConnectionFailed(format!("failed to get local address: {e}"))
        })?;

        tracing::info!(
            addr = %local_addr,
            alt_svc = %self.config.alt_svc(),
            "HTTP/3 server bound"
        );

        self.endpoint = Some(endpoint);
        Ok(local_addr)
    }

    /// Starts serving HTTP/3 connections.
    ///
    /// This method runs the HTTP/3 accept loop, spawning a task for each
    /// incoming QUIC connection. Each connection is upgraded to an HTTP/3
    /// session using the `h3` crate, and incoming requests are dispatched
    /// to the configured [`RequestHandler`].
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if the server has not been
    /// bound yet (call [`bind`](Self::bind) first).
    ///
    /// Network I/O errors during connection acceptance are logged and do
    /// not terminate the server.
    pub async fn serve(&self, connection_tracker: ConnectionTracker) -> Result<(), TransportError> {
        let endpoint = self.endpoint.as_ref().ok_or(TransportError::NotConnected)?;
        let active_connections = Arc::new(AtomicUsize::new(0));

        tracing::info!("HTTP/3 server accepting connections");

        loop {
            let incoming = endpoint.accept().await.ok_or_else(|| {
                TransportError::ConnectionFailed("QUIC endpoint closed".to_owned())
            })?;

            // Enforce connection limit: increment first, rollback if over.
            // This avoids a TOCTOU between load and fetch_add.
            let handler = Arc::clone(&self.handler);
            let alt_svc_value = self.alt_svc_header_value();
            let conn_count = Arc::clone(&active_connections);
            let prev = conn_count.fetch_add(1, Ordering::AcqRel);
            if prev >= MAX_CONCURRENT_HTTP3_CONNECTIONS {
                conn_count.fetch_sub(1, Ordering::AcqRel);
                tracing::warn!(
                    current_connections = prev,
                    limit = MAX_CONCURRENT_HTTP3_CONNECTIONS,
                    "HTTP/3: rejecting connection — max concurrent connections reached"
                );
                incoming.refuse();
                continue;
            }

            let tracker = Arc::clone(&connection_tracker);
            tokio::spawn(async move {
                handle_h3_connection(incoming, handler, alt_svc_value, tracker).await;
                conn_count.fetch_sub(1, Ordering::AcqRel);
            });
        }
    }

    /// Gracefully shuts down the HTTP/3 server.
    ///
    /// Closes the QUIC endpoint, which terminates all active connections
    /// with a `NO_ERROR` application error code. In-flight requests may
    /// be interrupted.
    pub fn shutdown(&self) {
        if let Some(endpoint) = &self.endpoint {
            endpoint.close(quinn::VarInt::from_u32(0), b"server shutdown");
            tracing::info!("HTTP/3 server shut down");
        }
    }
}

impl std::fmt::Debug for Http3Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Intentionally omits `handler` (not Debug) -- uses
        // `finish_non_exhaustive()` to signal excluded fields.
        f.debug_struct("Http3Server")
            .field("config", &self.config)
            .field("bound", &self.endpoint.is_some())
            .field("local_addr", &self.local_addr())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Connection handler (extracted from serve() for clippy::too_many_lines)
// ---------------------------------------------------------------------------

/// Handles a single HTTP/3 connection: completes the QUIC handshake,
/// establishes an h3 session, and dispatches incoming requests.
async fn handle_h3_connection(
    incoming: quinn::Incoming,
    handler: Arc<dyn RequestHandler>,
    alt_svc_value: String,
    connection_tracker: ConnectionTracker,
) {
    let conn = match incoming.await {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(error = %e, "HTTP/3: QUIC handshake failed");
            return;
        }
    };

    let remote_ip = conn.remote_address().ip();
    // Best-effort tracking — ignore limit errors since the local
    // AtomicUsize already enforces the HTTP/3-specific cap.
    let _ = rate_limit::register_connection(&connection_tracker, remote_ip, usize::MAX, None).await;

    let h3_conn = h3_quinn::Connection::new(conn);
    let mut h3_session = match h3::server::builder().build(h3_conn).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(error = %e, "HTTP/3: session establishment failed");
            rate_limit::unregister_connection(&connection_tracker, remote_ip).await;
            return;
        }
    };

    loop {
        let resolver = match h3_session.accept().await {
            Ok(Some(resolver)) => resolver,
            Ok(None) => break,
            Err(e) => {
                tracing::debug!(error = %e, "HTTP/3: error accepting request");
                break;
            }
        };

        let handler = Arc::clone(&handler);
        let alt_svc = alt_svc_value.clone();

        tokio::spawn(async move {
            let (req, mut stream) = match resolver.resolve_request().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::debug!(error = %e, "HTTP/3: request resolve failed");
                    return;
                }
            };

            let method = req.method().as_str().to_owned();
            let uri = req.uri().to_string();
            let headers: Vec<(String, String)> = req
                .headers()
                .iter()
                .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap_or("").to_owned()))
                .collect();

            let app_response = handler.handle(&method, &uri, &headers);
            let (parts, body) = app_response.into_parts();

            let mut builder = http::Response::builder().status(parts.status);
            for (key, value) in &parts.headers {
                builder = builder.header(key, value);
            }
            builder = builder.header("alt-svc", &alt_svc);

            let h3_response = match builder.body(()) {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!(error = %e, "HTTP/3: failed to build response");
                    return;
                }
            };

            if let Err(e) = stream.send_response(h3_response).await {
                tracing::debug!(error = %e, "HTTP/3: failed to send response headers");
                return;
            }

            if !body.is_empty()
                && let Err(e) = stream.send_data(Bytes::from(body)).await
            {
                tracing::debug!(error = %e, "HTTP/3: failed to send response body");
                return;
            }

            if let Err(e) = stream.finish().await {
                tracing::debug!(error = %e, "HTTP/3: failed to finish stream");
            }
        });
    }

    rate_limit::unregister_connection(&connection_tracker, remote_ip).await;
}

// ---------------------------------------------------------------------------
// Utility: inject Alt-Svc header into a response
// ---------------------------------------------------------------------------

/// Injects an `Alt-Svc` header into an HTTP response.
///
/// This utility function adds the HTTP/3 advertisement header to
/// responses served over HTTP/1.1 and HTTP/2. The header tells clients
/// that HTTP/3 is available on the specified port.
///
/// Per spec section 10.15.1, all HTTP/1.1 and HTTP/2 responses from the
/// relay should include this header.
///
/// # Arguments
///
/// * `response` -- The HTTP response to modify (mutable)
/// * `alt_svc_value` -- The `Alt-Svc` header value (e.g., `h3=":443"; ma=86400`)
///
/// # Errors
///
/// Returns `TransportError::ProtocolError` if the header value is invalid.
pub fn inject_alt_svc_header(
    response: &mut Response<Vec<u8>>,
    alt_svc_value: &str,
) -> Result<(), TransportError> {
    let header_value = http::HeaderValue::from_str(alt_svc_value)
        .map_err(|e| TransportError::ProtocolError(format!("invalid Alt-Svc header value: {e}")))?;
    response.headers_mut().insert("alt-svc", header_value);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::http3::config::AltSvcHeader;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    /// A no-op request handler for testing.
    struct TestHandler;

    impl RequestHandler for TestHandler {
        fn handle(
            &self,
            method: &str,
            uri: &str,
            _headers: &[(String, String)],
        ) -> Response<Vec<u8>> {
            let body = format!("{method} {uri}").into_bytes();
            Response::builder().status(200).body(body).unwrap()
        }
    }

    fn generate_test_certs() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert);
        let key_der = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
        (vec![cert_der], key_der)
    }

    #[test]
    fn http3_server_creation() {
        let (certs, key) = generate_test_certs();
        let config = Http3Config::new(certs, key);
        let handler: Arc<dyn RequestHandler> = Arc::new(TestHandler);
        let server = Http3Server::new(config, handler);

        assert!(server.local_addr().is_none()); // Not bound yet
        assert!(server.connection_coalescing_enabled());
    }

    #[test]
    fn http3_server_alt_svc_header() {
        let (certs, key) = generate_test_certs();
        let config = Http3Config::new(certs, key).with_alt_svc(AltSvcHeader::new(8443));
        let handler: Arc<dyn RequestHandler> = Arc::new(TestHandler);
        let server = Http3Server::new(config, handler);

        assert_eq!(server.alt_svc_header_value(), "h3=\":8443\"; ma=86400");
    }

    #[tokio::test]
    async fn http3_server_bind_succeeds() {
        let (certs, key) = generate_test_certs();
        // Use port 0 so the OS assigns an available port
        let bind_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
        let config = Http3Config::new(certs, key).with_bind_addr(bind_addr);
        let handler: Arc<dyn RequestHandler> = Arc::new(TestHandler);
        let mut server = Http3Server::new(config, handler);

        let addr = server.bind().unwrap();
        assert_eq!(addr.ip(), std::net::Ipv4Addr::LOCALHOST);
        assert_ne!(addr.port(), 0); // OS assigned a real port
        assert_eq!(server.local_addr(), Some(addr));
    }

    #[tokio::test]
    async fn http3_server_serve_without_bind_returns_not_connected() {
        let (certs, key) = generate_test_certs();
        let config = Http3Config::new(certs, key);
        let handler: Arc<dyn RequestHandler> = Arc::new(TestHandler);
        let server = Http3Server::new(config, handler);

        let tracker = crate::relay::rate_limit::new_connection_tracker();
        let result = server.serve(tracker).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TransportError::NotConnected));
    }

    #[test]
    fn http3_server_shutdown_before_bind_is_noop() {
        let (certs, key) = generate_test_certs();
        let config = Http3Config::new(certs, key);
        let handler: Arc<dyn RequestHandler> = Arc::new(TestHandler);
        let server = Http3Server::new(config, handler);

        // Should not panic
        server.shutdown();
    }

    #[tokio::test]
    async fn http3_server_shutdown_after_bind() {
        let (certs, key) = generate_test_certs();
        let bind_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
        let config = Http3Config::new(certs, key).with_bind_addr(bind_addr);
        let handler: Arc<dyn RequestHandler> = Arc::new(TestHandler);
        let mut server = Http3Server::new(config, handler);

        server.bind().unwrap();
        server.shutdown();
    }

    #[test]
    fn inject_alt_svc_header_adds_header() {
        let mut response = Response::builder()
            .status(200)
            .body(b"hello".to_vec())
            .unwrap();

        inject_alt_svc_header(&mut response, "h3=\":443\"; ma=86400").unwrap();

        assert_eq!(
            response.headers().get("alt-svc").unwrap(),
            "h3=\":443\"; ma=86400"
        );
    }

    #[test]
    fn inject_alt_svc_does_not_overwrite_existing_headers() {
        let mut response = Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(b"{}".to_vec())
            .unwrap();

        inject_alt_svc_header(&mut response, "h3=\":443\"; ma=86400").unwrap();

        // Both headers should be present
        assert!(response.headers().contains_key("content-type"));
        assert!(response.headers().contains_key("alt-svc"));
    }

    #[test]
    fn http3_server_debug_output() {
        let (certs, key) = generate_test_certs();
        let config = Http3Config::new(certs, key);
        let handler: Arc<dyn RequestHandler> = Arc::new(TestHandler);
        let server = Http3Server::new(config, handler);

        let debug = format!("{server:?}");
        assert!(debug.contains("Http3Server"));
        assert!(debug.contains("bound: false"));
    }

    #[test]
    fn request_handler_dispatch() {
        let handler = TestHandler;
        let response = handler.handle("GET", "/.well-known/scp", &[]);
        assert_eq!(response.status(), 200);
        assert_eq!(response.body(), b"GET /.well-known/scp");
    }
}
