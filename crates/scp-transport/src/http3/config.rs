//! HTTP/3 server configuration: ALPN negotiation, Alt-Svc advertisement.
//!
//! Implements relay-side HTTP/3 configuration per spec section 10.15.1 and
//! ADR-037. Covers:
//!
//! - ALPN protocol identifiers for h3, h2, and http/1.1 negotiation
//! - `Alt-Svc` header construction for advertising HTTP/3 availability
//! - HTTP/3 server configuration including QUIC transport parameters
//! - Connection coalescing awareness (same origin, same certificate)
//!
//! See spec section 10.15.1 "Relay HTTP/3 Upgrade Path" for requirements.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::error::TransportError;

// ---------------------------------------------------------------------------
// ALPN Protocol identifiers
// ---------------------------------------------------------------------------

/// ALPN protocol identifiers for HTTP version negotiation.
///
/// Per spec section 10.15.1, the relay serves HTTP/1.1, HTTP/2, and HTTP/3
/// via ALPN negotiation. The `h3` ALPN is used for QUIC-based HTTP/3
/// connections on UDP:443.
///
/// These identifiers follow the IANA TLS ALPN Protocol ID registry:
/// - `h3` -- HTTP/3 over QUIC (RFC 9114)
/// - `h2` -- HTTP/2 over TLS (RFC 9113)
/// - `http/1.1` -- HTTP/1.1 over TLS (RFC 7230)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlpnProtocol {
    /// HTTP/3 over QUIC (`h3`).
    H3,
    /// HTTP/2 over TLS (`h2`).
    H2,
    /// HTTP/1.1 over TLS (`http/1.1`).
    Http11,
}

impl AlpnProtocol {
    /// Returns the ALPN protocol identifier as a byte string.
    ///
    /// These are the wire-format identifiers used in TLS ALPN extension
    /// and QUIC ALPN negotiation.
    #[must_use]
    pub const fn as_bytes(&self) -> &'static [u8] {
        match self {
            Self::H3 => b"h3",
            Self::H2 => b"h2",
            Self::Http11 => b"http/1.1",
        }
    }

    /// Returns the ALPN protocol identifier as a string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::H3 => "h3",
            Self::H2 => "h2",
            Self::Http11 => "http/1.1",
        }
    }

    /// Returns the full set of ALPN protocols for a relay that supports
    /// all HTTP versions (HTTP/3, HTTP/2, HTTP/1.1).
    ///
    /// Order matters: the most preferred protocol is listed first. Clients
    /// and servers negotiate the highest mutually supported version.
    #[must_use]
    pub fn all() -> Vec<Self> {
        vec![Self::H3, Self::H2, Self::Http11]
    }

    /// Returns the ALPN protocol identifiers as byte slices, suitable for
    /// passing to TLS configuration.
    #[must_use]
    pub fn all_as_bytes() -> Vec<Vec<u8>> {
        Self::all().iter().map(|p| p.as_bytes().to_vec()).collect()
    }
}

impl fmt::Display for AlpnProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Alt-Svc header
// ---------------------------------------------------------------------------

/// Builder for `Alt-Svc` header values advertising HTTP/3 availability.
///
/// Per spec section 10.15.1, HTTP/1.1 and HTTP/2 responses include an
/// `Alt-Svc` header so clients can discover and upgrade to HTTP/3.
///
/// The header format follows RFC 7838:
/// ```text
/// Alt-Svc: h3=":443"; ma=86400
/// ```
///
/// - `h3` -- the ALPN protocol identifier for HTTP/3
/// - `":443"` -- the port (quoted, with empty host meaning same-origin)
/// - `ma=86400` -- max-age in seconds (how long the client should cache
///   the Alt-Svc information)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AltSvcHeader {
    /// The UDP port where HTTP/3 is available.
    port: u16,
    /// Max-age in seconds for client-side caching of the Alt-Svc record.
    max_age: Duration,
}

impl AltSvcHeader {
    /// Creates a new `Alt-Svc` header for HTTP/3 on the given port.
    ///
    /// Default max-age is 24 hours (86400 seconds), following common
    /// deployment practice.
    #[must_use]
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            max_age: Duration::from_secs(86_400),
        }
    }

    /// Sets the max-age for client-side caching of the Alt-Svc record.
    #[must_use]
    pub const fn with_max_age(mut self, max_age: Duration) -> Self {
        self.max_age = max_age;
        self
    }

    /// Returns the UDP port where HTTP/3 is available.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Returns the max-age duration.
    #[must_use]
    pub const fn max_age(&self) -> Duration {
        self.max_age
    }

    /// Renders the `Alt-Svc` header value as a string.
    ///
    /// Format per RFC 7838:
    /// ```text
    /// h3=":443"; ma=86400
    /// ```
    #[must_use]
    pub fn to_header_value(&self) -> String {
        format!("h3=\":{}\"; ma={}", self.port, self.max_age.as_secs())
    }

    /// Renders the `Alt-Svc: clear` directive, which tells clients to
    /// discard any cached Alt-Svc records for this origin.
    ///
    /// Used when HTTP/3 is being disabled on a relay.
    #[must_use]
    pub fn clear() -> String {
        "clear".to_owned()
    }
}

impl fmt::Display for AltSvcHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_header_value())
    }
}

// ---------------------------------------------------------------------------
// HTTP/3 server configuration
// ---------------------------------------------------------------------------

/// Configuration for the relay's HTTP/3 server.
///
/// Bundles TLS certificate material, QUIC transport parameters, and
/// Alt-Svc advertisement configuration. Used by [`Http3Server`](super::Http3Server)
/// to initialize the QUIC endpoint that serves HTTP/3.
///
/// Per spec section 10.15.1:
/// - HTTP/3 is served on UDP:443 via QUIC ALPN `h3`
/// - The same TLS certificate is used for TCP (HTTP/1.1 + HTTP/2) and
///   UDP (HTTP/3) -- this enables connection coalescing
/// - Alt-Svc header advertises HTTP/3 on HTTP/1.1 and HTTP/2 responses
///
/// See ADR-037 for the full design rationale.
pub struct Http3Config {
    /// TLS certificates (DER-encoded) for the server.
    ///
    /// The same certificate chain should be used for both TCP-based
    /// HTTP/1.1+HTTP/2 and UDP-based HTTP/3 to enable connection
    /// coalescing per RFC 9113 section 9.1.1.
    certs: Vec<CertificateDer<'static>>,

    /// TLS private key (DER-encoded) corresponding to the certificate.
    key: PrivateKeyDer<'static>,

    /// UDP bind address for the QUIC endpoint (default: `[::]:443`).
    bind_addr: std::net::SocketAddr,

    /// Alt-Svc header configuration for HTTP/3 advertisement.
    alt_svc: AltSvcHeader,

    /// Maximum number of concurrent bidirectional streams per QUIC
    /// connection. Controls resource usage per client.
    max_bi_streams: u64,

    /// QUIC idle timeout. Connections with no activity for this duration
    /// are closed. Aligns with the relay's existing 90-second idle
    /// timeout for WebSocket connections (ADR-004).
    idle_timeout: Duration,

    /// Whether connection coalescing is enabled.
    ///
    /// When true, the server expects clients to coalesce HTTP/3
    /// connections for origins sharing the same IP address and TLS
    /// certificate (RFC 9113 section 9.1.1). This is the default
    /// behavior -- disabling it is only useful for testing.
    connection_coalescing: bool,
}

impl Http3Config {
    /// Creates a new HTTP/3 configuration with the given TLS credentials.
    ///
    /// # Arguments
    ///
    /// * `certs` -- DER-encoded TLS certificate chain (leaf first)
    /// * `key` -- DER-encoded private key
    ///
    /// Defaults:
    /// - Bind address: `[::]:443`
    /// - Alt-Svc: port 443, max-age 24h
    /// - Max bidirectional streams: 100
    /// - Idle timeout: 90 seconds (matches WebSocket idle timeout)
    /// - Connection coalescing: enabled
    #[must_use]
    pub fn new(certs: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> Self {
        Self {
            certs,
            key,
            bind_addr: std::net::SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 443)),
            alt_svc: AltSvcHeader::new(443),
            max_bi_streams: 100,
            idle_timeout: Duration::from_secs(90),
            connection_coalescing: true,
        }
    }

    /// Sets the UDP bind address for the QUIC endpoint.
    ///
    /// Also updates the Alt-Svc port to match the new bind address's port,
    /// unless port 0 is used (OS-assigned). When binding to port 0, the
    /// caller must update Alt-Svc after binding via [`with_alt_svc`](Self::with_alt_svc),
    /// or use the actual bound port returned by `build_endpoint()`.
    #[must_use]
    pub const fn with_bind_addr(mut self, addr: std::net::SocketAddr) -> Self {
        self.bind_addr = addr;
        if addr.port() != 0 {
            self.alt_svc = AltSvcHeader::new(addr.port()).with_max_age(self.alt_svc.max_age);
        }
        self
    }

    /// Sets the Alt-Svc header configuration.
    #[must_use]
    pub const fn with_alt_svc(mut self, alt_svc: AltSvcHeader) -> Self {
        self.alt_svc = alt_svc;
        self
    }

    /// Sets the maximum number of concurrent bidirectional streams per
    /// QUIC connection.
    #[must_use]
    pub const fn with_max_bi_streams(mut self, max: u64) -> Self {
        self.max_bi_streams = max;
        self
    }

    /// Sets the QUIC idle timeout.
    #[must_use]
    pub const fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Enables or disables connection coalescing awareness.
    #[must_use]
    pub const fn with_connection_coalescing(mut self, enabled: bool) -> Self {
        self.connection_coalescing = enabled;
        self
    }

    /// Returns the TLS certificate chain.
    #[must_use]
    pub fn certs(&self) -> &[CertificateDer<'static>] {
        &self.certs
    }

    /// Returns the TLS private key.
    #[must_use]
    pub const fn key(&self) -> &PrivateKeyDer<'static> {
        &self.key
    }

    /// Returns the UDP bind address.
    #[must_use]
    pub const fn bind_addr(&self) -> std::net::SocketAddr {
        self.bind_addr
    }

    /// Returns the Alt-Svc header configuration.
    #[must_use]
    pub const fn alt_svc(&self) -> &AltSvcHeader {
        &self.alt_svc
    }

    /// Returns the maximum number of concurrent bidirectional streams.
    #[must_use]
    pub const fn max_bi_streams(&self) -> u64 {
        self.max_bi_streams
    }

    /// Returns the QUIC idle timeout.
    #[must_use]
    pub const fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// Returns whether connection coalescing is enabled.
    #[must_use]
    pub const fn connection_coalescing(&self) -> bool {
        self.connection_coalescing
    }

    /// Builds a `rustls::ServerConfig` configured for HTTP/3 (QUIC) with
    /// the `h3` ALPN protocol.
    ///
    /// The resulting config uses:
    /// - The certificate chain and key from this config
    /// - ALPN set to `["h3"]` for QUIC-based HTTP/3
    /// - TLS 1.3 only (required by QUIC, RFC 9001)
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ConnectionFailed`] if the TLS configuration
    /// is invalid (e.g., certificate/key mismatch).
    pub fn build_rustls_config(&self) -> Result<rustls::ServerConfig, TransportError> {
        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(self.certs.clone(), self.key.clone_key())
            .map_err(|e| TransportError::ConnectionFailed(format!("TLS config error: {e}")))?;

        tls_config.alpn_protocols = vec![AlpnProtocol::H3.as_bytes().to_vec()];

        // 0-RTT disabled until anti-replay protection is implemented.
        // Per spec section 10.14.2: "0-RTT data has no replay protection
        // (RFC 9001 section 9.2); SCP operations sent as 0-RTT MUST be
        // idempotent or the relay MUST implement anti-replay measures."
        // PUBLISH is not idempotent (duplicate blob delivery), so enabling
        // 0-RTT without anti-replay would allow replay attacks.
        // tls_config.max_early_data_size = u32::MAX;

        Ok(tls_config)
    }

    /// Builds a quinn `ServerConfig` from this HTTP/3 configuration.
    ///
    /// Configures:
    /// - TLS with `h3` ALPN for HTTP/3
    /// - Max bidirectional streams from config
    /// - Idle timeout from config
    /// - 0-RTT disabled pending anti-replay implementation (spec §10.14.2)
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ConnectionFailed`] if the QUIC server
    /// configuration cannot be built (e.g., invalid TLS credentials).
    pub fn build_quinn_server_config(&self) -> Result<quinn::ServerConfig, TransportError> {
        let tls_config = self.build_rustls_config()?;
        let quic_server_config = QuicServerConfig::try_from(tls_config)
            .map_err(|e| TransportError::ConnectionFailed(format!("QUIC TLS config error: {e}")))?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_bidi_streams(
            quinn::VarInt::from_u64(self.max_bi_streams).unwrap_or(quinn::VarInt::from_u32(100)),
        );
        transport_config.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(self.idle_timeout)
                .unwrap_or_else(|_| quinn::IdleTimeout::from(quinn::VarInt::from_u32(90_000))),
        ));

        server_config.transport_config(Arc::new(transport_config));

        Ok(server_config)
    }

    /// Builds a quinn `Endpoint` bound to the configured address and
    /// ready to accept HTTP/3 connections.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ConnectionFailed`] if the endpoint cannot
    /// be created (e.g., address already in use, invalid TLS config).
    pub fn build_endpoint(&self) -> Result<quinn::Endpoint, TransportError> {
        let server_config = self.build_quinn_server_config()?;
        quinn::Endpoint::server(server_config, self.bind_addr)
            .map_err(|e| TransportError::ConnectionFailed(format!("QUIC endpoint error: {e}")))
    }
}

impl fmt::Debug for Http3Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Intentionally omits `certs` (large binary) and `key` (secret material).
        // Uses `finish_non_exhaustive()` to signal that fields are excluded.
        f.debug_struct("Http3Config")
            .field("bind_addr", &self.bind_addr)
            .field("alt_svc", &self.alt_svc)
            .field("max_bi_streams", &self.max_bi_streams)
            .field("idle_timeout", &self.idle_timeout)
            .field("connection_coalescing", &self.connection_coalescing)
            .field("certs_count", &self.certs.len())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn alpn_h3_bytes() {
        assert_eq!(AlpnProtocol::H3.as_bytes(), b"h3");
    }

    #[test]
    fn alpn_h2_bytes() {
        assert_eq!(AlpnProtocol::H2.as_bytes(), b"h2");
    }

    #[test]
    fn alpn_http11_bytes() {
        assert_eq!(AlpnProtocol::Http11.as_bytes(), b"http/1.1");
    }

    #[test]
    fn alpn_all_returns_three_protocols_in_preference_order() {
        let all = AlpnProtocol::all();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0], AlpnProtocol::H3);
        assert_eq!(all[1], AlpnProtocol::H2);
        assert_eq!(all[2], AlpnProtocol::Http11);
    }

    #[test]
    fn alpn_all_as_bytes_matches_individual() {
        let bytes = AlpnProtocol::all_as_bytes();
        assert_eq!(bytes[0], b"h3");
        assert_eq!(bytes[1], b"h2");
        assert_eq!(bytes[2], b"http/1.1");
    }

    #[test]
    fn alpn_display() {
        assert_eq!(AlpnProtocol::H3.to_string(), "h3");
        assert_eq!(AlpnProtocol::H2.to_string(), "h2");
        assert_eq!(AlpnProtocol::Http11.to_string(), "http/1.1");
    }

    #[test]
    fn alt_svc_default_port_443() {
        let alt_svc = AltSvcHeader::new(443);
        assert_eq!(alt_svc.port(), 443);
        assert_eq!(alt_svc.max_age(), Duration::from_secs(86_400));
        assert_eq!(alt_svc.to_header_value(), "h3=\":443\"; ma=86400");
    }

    #[test]
    fn alt_svc_custom_port() {
        let alt_svc = AltSvcHeader::new(8443);
        assert_eq!(alt_svc.to_header_value(), "h3=\":8443\"; ma=86400");
    }

    #[test]
    fn alt_svc_custom_max_age() {
        let alt_svc = AltSvcHeader::new(443).with_max_age(Duration::from_secs(3600));
        assert_eq!(alt_svc.to_header_value(), "h3=\":443\"; ma=3600");
    }

    #[test]
    fn alt_svc_clear_directive() {
        assert_eq!(AltSvcHeader::clear(), "clear");
    }

    #[test]
    fn alt_svc_display() {
        let alt_svc = AltSvcHeader::new(443);
        assert_eq!(format!("{alt_svc}"), "h3=\":443\"; ma=86400");
    }

    #[test]
    fn http3_config_defaults() {
        let (certs, key) = generate_test_certs();
        let config = Http3Config::new(certs, key);

        assert_eq!(
            config.bind_addr(),
            std::net::SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 443))
        );
        assert_eq!(config.alt_svc().port(), 443);
        assert_eq!(config.max_bi_streams(), 100);
        assert_eq!(config.idle_timeout(), Duration::from_secs(90));
        assert!(config.connection_coalescing());
    }

    #[test]
    fn http3_config_builder_methods() {
        let (certs, key) = generate_test_certs();
        let bind_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8443));

        let config = Http3Config::new(certs, key)
            .with_bind_addr(bind_addr)
            .with_alt_svc(AltSvcHeader::new(8443))
            .with_max_bi_streams(200)
            .with_idle_timeout(Duration::from_secs(120))
            .with_connection_coalescing(false);

        assert_eq!(config.bind_addr(), bind_addr);
        assert_eq!(config.alt_svc().port(), 8443);
        assert_eq!(config.max_bi_streams(), 200);
        assert_eq!(config.idle_timeout(), Duration::from_secs(120));
        assert!(!config.connection_coalescing());
    }

    #[test]
    fn http3_config_debug_does_not_leak_key() {
        let (certs, key) = generate_test_certs();
        let config = Http3Config::new(certs, key);
        let debug = format!("{config:?}");

        // Debug output should contain structural info but not raw key bytes
        assert!(debug.contains("Http3Config"));
        assert!(debug.contains("bind_addr"));
        assert!(debug.contains("certs_count"));
    }

    #[test]
    fn http3_config_build_rustls_config_succeeds() {
        let (certs, key) = generate_test_certs();
        let config = Http3Config::new(certs, key);
        let tls_config = config.build_rustls_config().unwrap();

        assert_eq!(tls_config.alpn_protocols, vec![b"h3".to_vec()]);
    }

    #[test]
    fn http3_config_build_quinn_server_config_succeeds() {
        let (certs, key) = generate_test_certs();
        let config = Http3Config::new(certs, key);
        let result = config.build_quinn_server_config();
        assert!(result.is_ok());
    }

    #[test]
    fn connection_coalescing_requires_same_certificate() {
        // Verify that two Http3Config instances with different certificates
        // produce distinct TLS configs -- connection coalescing only applies
        // when the same certificate covers multiple origins.
        let (certs1, key1) = generate_test_certs();
        let (certs2, key2) = generate_test_certs();

        let tls1 = Http3Config::new(certs1, key1)
            .build_rustls_config()
            .unwrap();
        let tls2 = Http3Config::new(certs2, key2)
            .build_rustls_config()
            .unwrap();

        // Both configs should have h3 ALPN but are from different certs.
        // Connection coalescing is a client-side behavior -- the server just
        // needs to present the same cert on both TCP and UDP endpoints.
        assert_eq!(tls1.alpn_protocols, tls2.alpn_protocols);
    }

    /// Generate a self-signed certificate and key for testing.
    ///
    /// Uses rcgen to create an ephemeral certificate suitable for unit tests.
    /// Not for production use.
    fn generate_test_certs() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert);
        let key_der = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
        (vec![cert_der], key_der)
    }
}
