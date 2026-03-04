//! Shared DTLS stream implementation for UDP and CoAP adapters.
//!
//! Provides [`DtlsStream`] wrapping `openssl::ssl::SslStream<ConnectedUdpSocket>`
//! for DTLS-encrypted communication over UDP. Both client-side (adapter) and
//! server-side (listener) DTLS are supported.
//!
//! # Async Integration
//!
//! The OpenSSL DTLS implementation is blocking. Async integration uses
//! `tokio::task::spawn_blocking` for the DTLS handshake (which involves
//! multiple UDP round-trips). Send/recv also use `spawn_blocking` since
//! DTLS operations are fast and constrained devices do not require high
//! throughput (§10.16.3).
//!
//! See ADR-037 in `.docs/adrs/phase-2.md` for the transport binding design.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use openssl::ssl::{Ssl, SslContext, SslStream};
use tokio::sync::Mutex;
use tracing::debug;

use crate::error::TransportError;

/// Read timeout for the blocking UDP socket during DTLS operations.
///
/// Prevents indefinite blocking on recv if the remote peer disappears.
/// Constrained devices have high-latency links, so 10 seconds is generous.
const DTLS_RECV_TIMEOUT: Duration = Duration::from_secs(10);

/// A connected UDP socket wrapper implementing [`Read`] and [`Write`].
///
/// OpenSSL's `SslStream` requires a type implementing `Read + Write`.
/// A "connected" `std::net::UdpSocket` (via `connect()`) supports `recv()`
/// and `send()` which map naturally to `Read::read` and `Write::write`.
#[derive(Debug)]
pub struct ConnectedUdpSocket(pub UdpSocket);

impl Read for ConnectedUdpSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.recv(buf)
    }
}

impl Write for ConnectedUdpSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.send(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A DTLS-encrypted stream over a connected UDP socket.
///
/// Wraps `openssl::ssl::SslStream<ConnectedUdpSocket>` to provide
/// encrypted datagram send/recv. Created via [`DtlsStream::connect`]
/// (client-side) or [`DtlsStream::accept`] (server-side).
pub struct DtlsStream {
    inner: SslStream<ConnectedUdpSocket>,
}

impl DtlsStream {
    /// Performs a client-side DTLS handshake to the given relay address.
    ///
    /// Creates a connected UDP socket, wraps it in OpenSSL's DTLS layer,
    /// and performs the handshake. This is a blocking operation.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ConnectionFailed`] if the socket cannot be
    /// bound/connected or the DTLS handshake fails.
    pub fn connect(ssl_ctx: &SslContext, relay_addr: SocketAddr) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| {
            TransportError::ConnectionFailed(format!("failed to bind UDP socket: {e}"))
        })?;

        socket.connect(relay_addr).map_err(|e| {
            TransportError::ConnectionFailed(format!(
                "failed to connect UDP socket to {relay_addr}: {e}"
            ))
        })?;

        // Set a read timeout to prevent blocking forever during handshake.
        socket
            .set_read_timeout(Some(DTLS_RECV_TIMEOUT))
            .map_err(|e| {
                TransportError::ConnectionFailed(format!("failed to set read timeout: {e}"))
            })?;

        let connected = ConnectedUdpSocket(socket);

        let ssl = Ssl::new(ssl_ctx).map_err(|e| {
            TransportError::ConnectionFailed(format!("failed to create SSL object: {e}"))
        })?;

        let stream = ssl
            .connect(connected)
            .map_err(|e| TransportError::ConnectionFailed(format!("DTLS handshake failed: {e}")))?;

        debug!(relay = %relay_addr, "DTLS client handshake complete");

        Ok(Self { inner: stream })
    }

    /// Performs a server-side DTLS accept on a connected UDP socket.
    ///
    /// The caller provides a `std::net::UdpSocket` that has been connected
    /// to the remote client address. This is a blocking operation.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ConnectionFailed`] if the DTLS accept fails.
    pub fn accept(ssl_ctx: &SslContext, socket: UdpSocket) -> Result<Self, TransportError> {
        // Set a read timeout to prevent blocking forever during handshake.
        socket
            .set_read_timeout(Some(DTLS_RECV_TIMEOUT))
            .map_err(|e| {
                TransportError::ConnectionFailed(format!("failed to set read timeout: {e}"))
            })?;

        let connected = ConnectedUdpSocket(socket);

        let ssl = Ssl::new(ssl_ctx).map_err(|e| {
            TransportError::ConnectionFailed(format!("failed to create SSL object: {e}"))
        })?;

        let stream = ssl
            .accept(connected)
            .map_err(|e| TransportError::ConnectionFailed(format!("DTLS accept failed: {e}")))?;

        debug!("DTLS server accept complete");

        Ok(Self { inner: stream })
    }

    /// Sends encrypted data over the DTLS stream.
    ///
    /// The data is encrypted by OpenSSL and sent as a DTLS record via the
    /// underlying connected UDP socket.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::SendFailed`] if the write fails.
    pub fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.inner
            .write_all(data)
            .map_err(|e| TransportError::SendFailed(format!("DTLS send failed: {e}")))
    }

    /// Receives and decrypts data from the DTLS stream.
    ///
    /// Reads a single DTLS record, decrypts it, and returns the plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ProtocolError`] if the read fails.
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        self.inner
            .read(buf)
            .map_err(|e| TransportError::ProtocolError(format!("DTLS recv failed: {e}")))
    }
}

/// Async DTLS session wrapping a [`DtlsStream`] for use with tokio.
///
/// All blocking DTLS operations are dispatched to `tokio::task::spawn_blocking`
/// to avoid blocking the async runtime. The inner `DtlsStream` is protected
/// by a `Mutex` for shared access.
///
/// This is appropriate for constrained device transports where throughput
/// is inherently low (§10.16.3).
pub struct AsyncDtlsSession {
    inner: Arc<Mutex<DtlsStream>>,
}

impl AsyncDtlsSession {
    /// Performs an async client-side DTLS handshake.
    ///
    /// The handshake involves multiple UDP round-trips and is dispatched
    /// to a blocking thread via `tokio::task::spawn_blocking`.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ConnectionFailed`] if the handshake fails.
    pub async fn connect(
        ssl_ctx: SslContext,
        relay_addr: SocketAddr,
    ) -> Result<Self, TransportError> {
        let stream = tokio::task::spawn_blocking(move || DtlsStream::connect(&ssl_ctx, relay_addr))
            .await
            .map_err(|e| {
                TransportError::ConnectionFailed(format!("DTLS handshake task panicked: {e}"))
            })??;

        Ok(Self {
            inner: Arc::new(Mutex::new(stream)),
        })
    }

    /// Performs an async server-side DTLS accept.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ConnectionFailed`] if the accept fails.
    pub async fn accept(ssl_ctx: SslContext, socket: UdpSocket) -> Result<Self, TransportError> {
        let stream = tokio::task::spawn_blocking(move || DtlsStream::accept(&ssl_ctx, socket))
            .await
            .map_err(|e| {
                TransportError::ConnectionFailed(format!("DTLS accept task panicked: {e}"))
            })??;

        Ok(Self {
            inner: Arc::new(Mutex::new(stream)),
        })
    }

    /// Sends encrypted data asynchronously.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::SendFailed`] if the send fails.
    pub async fn send(&self, data: Vec<u8>) -> Result<(), TransportError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut stream = inner.blocking_lock();
            stream.send(&data)
        })
        .await
        .map_err(|e| TransportError::SendFailed(format!("DTLS send task panicked: {e}")))?
    }

    /// Receives and decrypts data asynchronously.
    ///
    /// Returns the decrypted datagram payload.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ProtocolError`] if the recv fails.
    #[allow(clippy::significant_drop_tightening)] // lock guard must outlive recv
    pub async fn recv(&self) -> Result<Vec<u8>, TransportError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut stream = inner.blocking_lock();
            let mut buf = vec![0u8; 65535];
            let n = stream.recv(&mut buf)?;
            buf.truncate(n);
            Ok(buf)
        })
        .await
        .map_err(|e| TransportError::ProtocolError(format!("DTLS recv task panicked: {e}")))?
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::ssl::{SslMethod, SslVerifyMode, SslVersion};
    use openssl::x509::X509;

    /// Builds a client DTLS context (no certificate verification).
    ///
    /// Matches production cipher settings: DTLS 1.2 minimum, ECDHE-ECDSA-AES-GCM only.
    fn build_test_client_ctx() -> SslContext {
        let mut builder = SslContext::builder(SslMethod::dtls()).unwrap();
        builder.set_verify(SslVerifyMode::NONE);
        builder
            .set_min_proto_version(Some(SslVersion::DTLS1_2))
            .unwrap();
        builder
            .set_cipher_list("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256")
            .unwrap();
        builder.build()
    }

    /// Builds a server DTLS context with a self-signed ECDSA P-256 certificate.
    ///
    /// Uses `SslContext::builder(SslMethod::dtls())` directly rather than
    /// `SslAcceptor::mozilla_intermediate_v5` — the latter configures TLS 1.3
    /// cipher suites that are incompatible with DTLSv1.2.
    fn build_test_server_ctx() -> SslContext {
        let mut builder = SslContext::builder(SslMethod::dtls()).unwrap();
        builder.set_verify(SslVerifyMode::NONE);
        builder
            .set_min_proto_version(Some(SslVersion::DTLS1_2))
            .unwrap();
        builder
            .set_cipher_list("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256")
            .unwrap();

        // Generate an ECDSA P-256 key pair (compatible with DTLSv1.2 cipher suites).
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(ec_key).unwrap();

        let mut x509_builder = X509::builder().unwrap();
        x509_builder.set_pubkey(&pkey).unwrap();

        let mut name = openssl::x509::X509Name::builder().unwrap();
        name.append_entry_by_text("CN", "test-dtls").unwrap();
        let name = name.build();
        x509_builder.set_subject_name(&name).unwrap();
        x509_builder.set_issuer_name(&name).unwrap();

        let not_before = openssl::asn1::Asn1Time::days_from_now(0).unwrap();
        let not_after = openssl::asn1::Asn1Time::days_from_now(1).unwrap();
        x509_builder.set_not_before(&not_before).unwrap();
        x509_builder.set_not_after(&not_after).unwrap();
        x509_builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        let cert = x509_builder.build();

        builder.set_private_key(&pkey).unwrap();
        builder.set_certificate(&cert).unwrap();

        builder.build()
    }

    /// Creates a pair of connected UDP sockets with read timeouts set.
    fn connected_socket_pair() -> (UdpSocket, UdpSocket) {
        let sock_a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();
        sock_a.connect(addr_b).unwrap();
        sock_b.connect(addr_a).unwrap();
        sock_a
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        sock_b
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        (sock_a, sock_b)
    }

    #[test]
    fn connected_udp_socket_read_write() {
        let (socket_a, socket_b) = connected_socket_pair();

        let mut writer = ConnectedUdpSocket(socket_a);
        let mut reader = ConnectedUdpSocket(socket_b);

        let msg = b"hello dtls";
        let written = writer.write(msg).unwrap();
        assert_eq!(written, msg.len());

        let mut buf = [0u8; 64];
        let read = reader.read(&mut buf).unwrap();
        assert_eq!(&buf[..read], msg);
    }

    #[tokio::test]
    async fn dtls_client_server_roundtrip() {
        // Create a pair of connected UDP sockets, then perform a DTLS
        // handshake: client on one side, server accept on the other.
        let (sock_a, sock_b) = connected_socket_pair();

        let client_ctx = build_test_client_ctx();
        let server_ctx = build_test_server_ctx();

        // Spawn client and server handshakes concurrently on blocking threads.
        let client_handle = tokio::task::spawn_blocking(move || {
            let connected = ConnectedUdpSocket(sock_a);
            let ssl = Ssl::new(&client_ctx).unwrap();
            ssl.connect(connected).unwrap()
        });

        let server_handle = tokio::task::spawn_blocking(move || {
            let connected = ConnectedUdpSocket(sock_b);
            let ssl = Ssl::new(&server_ctx).unwrap();
            ssl.accept(connected).unwrap()
        });

        let (client_result, server_result) = tokio::join!(client_handle, server_handle);

        let mut client_stream = client_result.unwrap();
        let mut server_stream = server_result.unwrap();

        // Client sends, server receives.
        let msg = b"hello from client";
        client_stream.write_all(msg).unwrap();

        let mut buf = [0u8; 256];
        let n = server_stream.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], msg);

        // Server sends, client receives.
        let reply = b"hello from server";
        server_stream.write_all(reply).unwrap();

        let n = client_stream.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], reply);
    }

    #[tokio::test]
    async fn async_dtls_session_roundtrip() {
        let (sock_e, sock_f) = connected_socket_pair();

        let cc = build_test_client_ctx();
        let sc = build_test_server_ctx();

        let client_h = tokio::task::spawn_blocking(move || {
            let connected = ConnectedUdpSocket(sock_e);
            let ssl = Ssl::new(&cc).unwrap();
            ssl.connect(connected).unwrap()
        });
        let server_h = tokio::task::spawn_blocking(move || {
            let connected = ConnectedUdpSocket(sock_f);
            let ssl = Ssl::new(&sc).unwrap();
            ssl.accept(connected).unwrap()
        });

        let (client_ssl, server_ssl) = tokio::join!(client_h, server_h);
        let client_ssl = client_ssl.unwrap();
        let server_ssl = server_ssl.unwrap();

        // Wrap in `AsyncDtlsSession` manually by constructing `DtlsStream`.
        let client_session = AsyncDtlsSession {
            inner: Arc::new(Mutex::new(DtlsStream { inner: client_ssl })),
        };
        let server_session = AsyncDtlsSession {
            inner: Arc::new(Mutex::new(DtlsStream { inner: server_ssl })),
        };

        // Send from client, receive on server.
        let payload = b"async dtls test".to_vec();
        client_session.send(payload.clone()).await.unwrap();
        let received = server_session.recv().await.unwrap();
        assert_eq!(received, payload);

        // Send from server, receive on client.
        let reply = b"async reply".to_vec();
        server_session.send(reply.clone()).await.unwrap();
        let received = client_session.recv().await.unwrap();
        assert_eq!(received, reply);
    }
}
