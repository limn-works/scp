//! Lightweight, stateless STUN service for SCP relays.
//!
//! Any SCP relay MAY serve as a STUN endpoint (spec section 10.12.3).
//! STUN is lightweight (stateless, single UDP socket, minimal CPU) and
//! can coexist with the relay's WebSocket endpoint.
//!
//! This module implements a minimal RFC 8489 STUN server that handles
//! Binding requests and returns XOR-MAPPED-ADDRESS responses. No
//! per-client state is maintained.
//!
//! Bootstrap relays (section 18.5.1) MUST include at least one
//! STUN-capable relay. Self-hosted relays that achieve public
//! reachability MAY also offer STUN service.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::net::UdpSocket;
use tracing::{debug, trace, warn};

// ---------------------------------------------------------------------------
// Constants — RFC 8489
// ---------------------------------------------------------------------------

/// STUN magic cookie (RFC 8489 section 6).
const MAGIC_COOKIE: u32 = 0x2112_A442;

/// STUN message header size: type (2) + length (2) + magic cookie (4) + transaction ID (12).
const STUN_HEADER_LEN: usize = 20;

/// STUN Binding Request message type (RFC 8489 section 14.1).
const BINDING_REQUEST: u16 = 0x0001;

/// STUN Binding Success Response message type (RFC 8489 section 14.1).
const BINDING_RESPONSE: u16 = 0x0101;

/// XOR-MAPPED-ADDRESS attribute type (RFC 8489 section 14.2).
const XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// Address family: IPv4 (RFC 8489 section 14.1).
const FAMILY_IPV4: u8 = 0x01;

/// Address family: IPv6 (RFC 8489 section 14.1).
const FAMILY_IPV6: u8 = 0x02;

/// Default STUN port (RFC 8489 section 18.4).
const DEFAULT_STUN_PORT: u16 = 3478;

/// Maximum UDP datagram size we accept for STUN messages.
/// STUN messages are small; 576 bytes covers any valid request.
const MAX_STUN_MSG: usize = 576;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors returned by [`StunService`].
#[derive(Debug, thiserror::Error)]
pub enum StunServiceError {
    /// Failed to bind the UDP socket.
    #[error("failed to bind UDP socket on port {port}: {source}")]
    BindFailed { port: u16, source: std::io::Error },

    /// An I/O error occurred while receiving or sending a datagram.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The STUN service is disabled in the configuration.
    #[error("STUN service is disabled")]
    Disabled,
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for the relay's STUN service (spec section 10.12.3).
///
/// STUN service is optional on any SCP relay. When enabled, the relay
/// binds a UDP socket on the configured port and responds to RFC 8489
/// Binding requests with XOR-MAPPED-ADDRESS.
#[derive(Debug, Clone)]
pub struct StunServiceConfig {
    /// Whether STUN service is enabled on this relay.
    pub enabled: bool,

    /// UDP port for STUN service. Defaults to 3478 (standard STUN port,
    /// RFC 8489 section 18.4).
    pub port: u16,

    /// Bind address for the UDP socket. Defaults to `0.0.0.0` (all interfaces).
    pub bind_address: IpAddr,
}

impl Default for StunServiceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: DEFAULT_STUN_PORT,
            bind_address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }
}

// ---------------------------------------------------------------------------
// StunService
// ---------------------------------------------------------------------------

/// A lightweight, stateless STUN server for SCP relays.
///
/// Handles RFC 8489 Binding requests and returns XOR-MAPPED-ADDRESS
/// responses. Completely stateless: no per-client tracking, no session
/// state. Any SCP relay MAY serve as a STUN endpoint (spec section
/// 10.12.3).
pub struct StunService {
    config: StunServiceConfig,
}

impl StunService {
    /// Creates a new STUN service with the given configuration.
    #[must_use]
    pub const fn new(config: StunServiceConfig) -> Self {
        Self { config }
    }

    /// Returns a reference to the service configuration.
    #[must_use]
    pub const fn config(&self) -> &StunServiceConfig {
        &self.config
    }

    /// Runs the STUN service, binding a UDP socket and looping to handle
    /// incoming STUN Binding requests.
    ///
    /// This method runs indefinitely until cancelled or an unrecoverable
    /// I/O error occurs. It is designed to be spawned as a background task.
    ///
    /// Returns [`StunServiceError::Disabled`] immediately if the service
    /// is not enabled in the configuration.
    ///
    /// # Errors
    ///
    /// Returns [`StunServiceError::Disabled`] if `config.enabled` is false.
    /// Returns [`StunServiceError::BindFailed`] if the UDP socket cannot bind.
    /// Returns [`StunServiceError::Io`] on unrecoverable I/O errors during
    /// receive/send.
    pub async fn run(&self) -> Result<(), StunServiceError> {
        if !self.config.enabled {
            return Err(StunServiceError::Disabled);
        }

        let bind_addr = SocketAddr::new(self.config.bind_address, self.config.port);
        let socket =
            UdpSocket::bind(bind_addr)
                .await
                .map_err(|e| StunServiceError::BindFailed {
                    port: self.config.port,
                    source: e,
                })?;

        debug!(
            port = self.config.port,
            bind = %bind_addr,
            "STUN service started"
        );

        let mut buf = [0u8; MAX_STUN_MSG];
        loop {
            let (len, src) = socket.recv_from(&mut buf).await?;
            self.handle_packet(&socket, &buf[..len], src).await;
        }
    }

    /// Runs the STUN service on an already-bound UDP socket.
    ///
    /// Useful for testing where the caller wants to control the socket
    /// (e.g., to pick an ephemeral port). Loops indefinitely.
    ///
    /// Returns [`StunServiceError::Disabled`] immediately if the service
    /// is not enabled in the configuration.
    ///
    /// # Errors
    ///
    /// Returns [`StunServiceError::Disabled`] if `config.enabled` is false.
    /// Returns [`StunServiceError::Io`] on unrecoverable I/O errors during
    /// receive/send.
    pub async fn run_on_socket(&self, socket: &UdpSocket) -> Result<(), StunServiceError> {
        if !self.config.enabled {
            return Err(StunServiceError::Disabled);
        }

        debug!("STUN service started on provided socket");

        let mut buf = [0u8; MAX_STUN_MSG];
        loop {
            let (len, src) = socket.recv_from(&mut buf).await?;
            self.handle_packet(socket, &buf[..len], src).await;
        }
    }

    /// Processes a single incoming UDP packet.
    ///
    /// If the packet is a valid STUN Binding Request, constructs and
    /// sends a Binding Response with XOR-MAPPED-ADDRESS derived from
    /// the source address. Invalid or non-STUN packets are silently
    /// dropped (stateless server, no error responses for garbage).
    async fn handle_packet(&self, socket: &UdpSocket, data: &[u8], src: SocketAddr) {
        let Some(request) = parse_binding_request(data) else {
            trace!(src = %src, len = data.len(), "dropped non-STUN or invalid packet");
            return;
        };

        let response = build_binding_response(&request.transaction_id, src);
        if let Err(e) = socket.send_to(&response, src).await {
            warn!(src = %src, error = %e, "failed to send STUN Binding Response");
        } else {
            debug!(src = %src, "sent STUN Binding Response");
        }
    }
}

// ---------------------------------------------------------------------------
// STUN message parsing (server-side, minimal)
// ---------------------------------------------------------------------------

/// A parsed STUN Binding Request — only the transaction ID is needed
/// for the server to construct a response.
struct StunBindingRequest {
    transaction_id: [u8; 12],
}

/// Parses a raw datagram as a STUN Binding Request (RFC 8489).
///
/// Returns `None` if:
/// - The packet is shorter than the 20-byte STUN header.
/// - The message type is not Binding Request (0x0001).
/// - The magic cookie does not match 0x2112A442.
/// - The two most-significant bits of the first byte are not zero
///   (RFC 8489 section 6 multiplexing rule).
fn parse_binding_request(data: &[u8]) -> Option<StunBindingRequest> {
    if data.len() < STUN_HEADER_LEN {
        return None;
    }

    // RFC 8489 section 6: the most significant 2 bits of every STUN
    // message MUST be zeroes. This distinguishes STUN from other
    // protocols multiplexed on the same port.
    if data[0] & 0xC0 != 0 {
        return None;
    }

    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != BINDING_REQUEST {
        return None;
    }

    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if cookie != MAGIC_COOKIE {
        return None;
    }

    let mut transaction_id = [0u8; 12];
    transaction_id.copy_from_slice(&data[8..20]);

    Some(StunBindingRequest { transaction_id })
}

/// Builds a STUN Binding Response with a single XOR-MAPPED-ADDRESS
/// attribute reflecting the client's source address (RFC 8489 sections
/// 14.1, 14.2).
///
/// The response is self-contained — no allocation beyond the returned
/// `Vec<u8>`.
fn build_binding_response(transaction_id: &[u8; 12], src: SocketAddr) -> Vec<u8> {
    let attr_payload = encode_xor_mapped_address(src, transaction_id);
    // Attribute: type (2) + length (2) + payload
    let attr_len = 4 + attr_payload.len();
    // STUN header message-length = total bytes after the 20-byte header
    let msg_len = attr_len;

    // Safety: STUN attribute payloads are at most 20 bytes (IPv6),
    // so msg_len and attr_payload.len() always fit in u16.
    #[allow(clippy::cast_possible_truncation)]
    let msg_len_u16 = msg_len as u16;
    // STUN attribute payloads are always < 65535 bytes.
    #[allow(clippy::cast_possible_truncation)]
    let attr_payload_len_u16 = attr_payload.len() as u16;

    let mut buf = Vec::with_capacity(STUN_HEADER_LEN + msg_len);

    // -- Header --
    buf.extend_from_slice(&BINDING_RESPONSE.to_be_bytes()); // message type
    buf.extend_from_slice(&msg_len_u16.to_be_bytes()); // message length
    buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes()); // magic cookie
    buf.extend_from_slice(transaction_id); // transaction ID

    // -- XOR-MAPPED-ADDRESS attribute --
    buf.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes()); // attr type
    buf.extend_from_slice(&attr_payload_len_u16.to_be_bytes()); // attr length
    buf.extend_from_slice(&attr_payload);

    buf
}

/// Encodes the XOR-MAPPED-ADDRESS attribute value (RFC 8489 section 14.2).
///
/// Layout: 1 byte reserved (0x00), 1 byte family, 2 bytes X-Port,
/// 4 bytes (IPv4) or 16 bytes (IPv6) X-Address.
///
/// - `X-Port` = port XOR (`magic_cookie` >> 16)
/// - `X-Address` (IPv4) = addr XOR `magic_cookie`
/// - `X-Address` (IPv6) = addr XOR (`magic_cookie` || `transaction_id`)
fn encode_xor_mapped_address(src: SocketAddr, transaction_id: &[u8; 12]) -> Vec<u8> {
    let x_port = (src.port()) ^ ((MAGIC_COOKIE >> 16) as u16);
    let cookie_bytes = MAGIC_COOKIE.to_be_bytes();

    match src.ip() {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            let x_addr = [
                octets[0] ^ cookie_bytes[0],
                octets[1] ^ cookie_bytes[1],
                octets[2] ^ cookie_bytes[2],
                octets[3] ^ cookie_bytes[3],
            ];
            let mut out = Vec::with_capacity(8);
            out.push(0x00); // reserved
            out.push(FAMILY_IPV4);
            out.extend_from_slice(&x_port.to_be_bytes());
            out.extend_from_slice(&x_addr);
            out
        }
        IpAddr::V6(ipv6) => {
            let octets = ipv6.octets();
            // XOR key = magic_cookie (4 bytes) || transaction_id (12 bytes) = 16 bytes
            let mut xor_key = [0u8; 16];
            xor_key[..4].copy_from_slice(&cookie_bytes);
            xor_key[4..].copy_from_slice(transaction_id);
            let mut x_addr = [0u8; 16];
            for i in 0..16 {
                x_addr[i] = octets[i] ^ xor_key[i];
            }
            let mut out = Vec::with_capacity(20);
            out.push(0x00); // reserved
            out.push(FAMILY_IPV6);
            out.extend_from_slice(&x_port.to_be_bytes());
            out.extend_from_slice(&x_addr);
            out
        }
    }
}

/// Decodes an XOR-MAPPED-ADDRESS attribute value back into a `SocketAddr`.
///
/// This is the inverse of [`encode_xor_mapped_address`] and is used in
/// tests to verify round-trip correctness.
#[cfg(test)]
fn decode_xor_mapped_address(data: &[u8], transaction_id: &[u8; 12]) -> Option<SocketAddr> {
    use std::net::Ipv6Addr;

    if data.len() < 4 {
        return None;
    }
    let family = data[1];
    let x_port = u16::from_be_bytes([data[2], data[3]]);
    let port = x_port ^ ((MAGIC_COOKIE >> 16) as u16);
    let cookie_bytes = MAGIC_COOKIE.to_be_bytes();

    match family {
        FAMILY_IPV4 if data.len() >= 8 => {
            let addr = Ipv4Addr::new(
                data[4] ^ cookie_bytes[0],
                data[5] ^ cookie_bytes[1],
                data[6] ^ cookie_bytes[2],
                data[7] ^ cookie_bytes[3],
            );
            Some(SocketAddr::new(IpAddr::V4(addr), port))
        }
        FAMILY_IPV6 if data.len() >= 20 => {
            let mut xor_key = [0u8; 16];
            xor_key[..4].copy_from_slice(&cookie_bytes);
            xor_key[4..].copy_from_slice(transaction_id);
            let mut octets = [0u8; 16];
            for i in 0..16 {
                octets[i] = data[4 + i] ^ xor_key[i];
            }
            let addr = Ipv6Addr::from(octets);
            Some(SocketAddr::new(IpAddr::V6(addr), port))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use std::time::Duration;
    use tokio::time::timeout;

    /// Builds a minimal STUN Binding Request with the given transaction ID.
    fn build_binding_request(transaction_id: &[u8; 12]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(STUN_HEADER_LEN);
        buf.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes()); // length = 0 (no attributes)
        buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(transaction_id);
        buf
    }

    // -- Unit tests for encoding/decoding --

    #[test]
    fn xor_mapped_address_ipv4_round_trip() {
        let addr: SocketAddr = "192.168.1.42:12345".parse().unwrap();
        let txn_id = [1u8; 12];
        let encoded = encode_xor_mapped_address(addr, &txn_id);
        let decoded = decode_xor_mapped_address(&encoded, &txn_id).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn xor_mapped_address_ipv6_round_trip() {
        let addr: SocketAddr = "[2001:db8::1]:54321".parse().unwrap();
        let txn_id = [0xAB; 12];
        let encoded = encode_xor_mapped_address(addr, &txn_id);
        let decoded = decode_xor_mapped_address(&encoded, &txn_id).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn parse_binding_request_valid() {
        let txn_id = [7u8; 12];
        let data = build_binding_request(&txn_id);
        let req = parse_binding_request(&data).unwrap();
        assert_eq!(req.transaction_id, txn_id);
    }

    #[test]
    fn parse_binding_request_too_short() {
        assert!(parse_binding_request(&[0u8; 10]).is_none());
    }

    #[test]
    fn parse_binding_request_wrong_type() {
        let txn_id = [0u8; 12];
        let mut data = build_binding_request(&txn_id);
        // Change message type to something other than Binding Request
        data[0] = 0x01;
        data[1] = 0x11; // Binding Indication, not Request
        assert!(parse_binding_request(&data).is_none());
    }

    #[test]
    fn parse_binding_request_wrong_cookie() {
        let txn_id = [0u8; 12];
        let mut data = build_binding_request(&txn_id);
        // Corrupt the magic cookie
        data[4] = 0xFF;
        assert!(parse_binding_request(&data).is_none());
    }

    #[test]
    fn parse_binding_request_high_bits_set() {
        let txn_id = [0u8; 12];
        let mut data = build_binding_request(&txn_id);
        // Set the two most-significant bits (RFC 8489 multiplexing violation)
        data[0] |= 0x80;
        assert!(parse_binding_request(&data).is_none());
    }

    #[test]
    fn build_response_has_correct_header() {
        let txn_id = [3u8; 12];
        let src: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let resp = build_binding_response(&txn_id, src);

        // Message type
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), BINDING_RESPONSE);
        // Magic cookie
        assert_eq!(
            u32::from_be_bytes([resp[4], resp[5], resp[6], resp[7]]),
            MAGIC_COOKIE
        );
        // Transaction ID
        assert_eq!(&resp[8..20], &txn_id);
    }

    #[test]
    fn build_response_contains_xor_mapped_address() {
        let txn_id = [0x42; 12];
        let src: SocketAddr = "172.16.0.99:9999".parse().unwrap();
        let resp = build_binding_response(&txn_id, src);

        // After the 20-byte header, we have the attribute
        let attr_type = u16::from_be_bytes([resp[20], resp[21]]);
        assert_eq!(attr_type, XOR_MAPPED_ADDRESS);

        let attr_len = u16::from_be_bytes([resp[22], resp[23]]) as usize;
        let attr_data = &resp[24..24 + attr_len];
        let decoded = decode_xor_mapped_address(attr_data, &txn_id).unwrap();
        assert_eq!(decoded, src);
    }

    // -- Integration tests using real UDP sockets --

    #[tokio::test]
    async fn stun_binding_request_returns_correct_xor_mapped_address() {
        // Bind the STUN service on an ephemeral port.
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let service = StunService::new(StunServiceConfig {
            enabled: true,
            port: server_addr.port(),
            bind_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        });

        // Spawn the service as a background task.
        let handle = tokio::spawn(async move {
            let _ = service.run_on_socket(&server_socket).await;
        });

        // Give the service a moment to start receiving.
        tokio::task::yield_now().await;

        // Send a Binding Request from a client socket.
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let txn_id = [0xDE; 12];
        let request = build_binding_request(&txn_id);
        client.send_to(&request, server_addr).await.unwrap();

        // Receive the response.
        let mut resp_buf = [0u8; MAX_STUN_MSG];
        let (resp_len, _) = timeout(Duration::from_secs(2), client.recv_from(&mut resp_buf))
            .await
            .expect("timed out waiting for STUN response")
            .unwrap();

        let resp = &resp_buf[..resp_len];

        // Verify header.
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), BINDING_RESPONSE);
        assert_eq!(
            u32::from_be_bytes([resp[4], resp[5], resp[6], resp[7]]),
            MAGIC_COOKIE
        );
        assert_eq!(&resp[8..20], &txn_id);

        // Verify XOR-MAPPED-ADDRESS matches our client address.
        let attr_type = u16::from_be_bytes([resp[20], resp[21]]);
        assert_eq!(attr_type, XOR_MAPPED_ADDRESS);
        let attr_len = u16::from_be_bytes([resp[22], resp[23]]) as usize;
        let attr_data = &resp[24..24 + attr_len];
        let decoded = decode_xor_mapped_address(attr_data, &txn_id).unwrap();
        assert_eq!(decoded, client_addr);

        handle.abort();
    }

    #[tokio::test]
    async fn stun_service_disabled_returns_error() {
        let service = StunService::new(StunServiceConfig {
            enabled: false,
            ..StunServiceConfig::default()
        });

        let result = service.run().await;
        assert!(result.is_err());
        assert!(
            matches!(result, Err(StunServiceError::Disabled)),
            "expected Disabled error"
        );
    }

    #[tokio::test]
    async fn stun_service_disabled_on_socket_returns_error() {
        let service = StunService::new(StunServiceConfig {
            enabled: false,
            ..StunServiceConfig::default()
        });

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let result = service.run_on_socket(&socket).await;
        assert!(matches!(result, Err(StunServiceError::Disabled)));
    }

    #[tokio::test]
    async fn non_stun_packets_silently_dropped() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let service = StunService::new(StunServiceConfig {
            enabled: true,
            port: server_addr.port(),
            bind_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        });

        let handle = tokio::spawn(async move {
            let _ = service.run_on_socket(&server_socket).await;
        });

        tokio::task::yield_now().await;

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Send garbage data (not a STUN message).
        client
            .send_to(b"hello, this is not STUN", server_addr)
            .await
            .unwrap();

        // The server should NOT respond. Wait briefly to confirm silence.
        let mut resp_buf = [0u8; MAX_STUN_MSG];
        let result = timeout(Duration::from_millis(200), client.recv_from(&mut resp_buf)).await;
        assert!(
            result.is_err(),
            "expected timeout — no response for garbage"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn invalid_stun_wrong_cookie_silently_dropped() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let service = StunService::new(StunServiceConfig {
            enabled: true,
            port: server_addr.port(),
            bind_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        });

        let handle = tokio::spawn(async move {
            let _ = service.run_on_socket(&server_socket).await;
        });

        tokio::task::yield_now().await;

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Build a STUN-shaped packet with a wrong magic cookie.
        let txn_id = [0u8; 12];
        let mut bad_request = build_binding_request(&txn_id);
        bad_request[4] = 0xFF; // corrupt magic cookie

        client.send_to(&bad_request, server_addr).await.unwrap();

        let mut resp_buf = [0u8; MAX_STUN_MSG];
        let result = timeout(Duration::from_millis(200), client.recv_from(&mut resp_buf)).await;
        assert!(
            result.is_err(),
            "expected timeout — no response for wrong cookie"
        );

        handle.abort();
    }

    #[test]
    fn default_config_is_disabled() {
        let config = StunServiceConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.port, DEFAULT_STUN_PORT);
        assert_eq!(config.bind_address, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }
}
