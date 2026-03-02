//! Minimal STUN binding request/response codec (RFC 8489) and NAT keepalive.
//!
//! Implements only the subset of STUN required for NAT type probing:
//!
//! - **Binding Request** (type `0x0001`): 20-byte header, no attributes.
//! - **Binding Response** (type `0x0101`): parse `XOR-MAPPED-ADDRESS` (type
//!   `0x0020`) to extract the external IP:port.
//! - **Binding Indication** (type `0x0011`): 20-byte header, no attributes,
//!   no response expected. Used for 25-second keepalive (spec 10.12.3).
//!
//! XOR-MAPPED-ADDRESS decoding per RFC 8489 section 14.2:
//! - Port XOR-ed with upper 16 bits of magic cookie (`0x2112`).
//! - IPv4 address XOR-ed with magic cookie (`0x2112A442`).
//! - IPv6 address XOR-ed with magic cookie + transaction ID (16 bytes).
//!
//! See spec section 10.12.3 for the STUN probing protocol.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;

use rand::RngCore;
use tokio::net::UdpSocket;
use tracing::{debug, warn};

use crate::TransportError;

// ---------------------------------------------------------------------------
// Constants (RFC 8489)
// ---------------------------------------------------------------------------

/// STUN magic cookie (RFC 8489 section 6).
const MAGIC_COOKIE: u32 = 0x2112_A442;

/// STUN message type: Binding Request.
const BINDING_REQUEST: u16 = 0x0001;

/// STUN message type: Binding Success Response.
const BINDING_RESPONSE: u16 = 0x0101;

/// STUN message type: Binding Indication (no response expected).
const BINDING_INDICATION: u16 = 0x0011;

/// STUN attribute type: XOR-MAPPED-ADDRESS.
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// STUN attribute type: MAPPED-ADDRESS (fallback, non-XOR).
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;

/// STUN header size: 20 bytes (2 type + 2 length + 4 cookie + 12 txn ID).
const STUN_HEADER_SIZE: usize = 20;

/// Transaction ID size: 12 bytes.
const TRANSACTION_ID_SIZE: usize = 12;

/// Address family: IPv4.
const FAMILY_IPV4: u8 = 0x01;

/// Address family: IPv6.
const FAMILY_IPV6: u8 = 0x02;

/// Default timeout for STUN binding request/response round-trip.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);

/// Keepalive interval per spec 10.12.3: 25 seconds.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(25);

/// Maximum STUN message size we accept (RFC 8489 recommends path MTU;
/// we cap at 576 bytes which covers any valid Binding Response).
const MAX_STUN_MSG_SIZE: usize = 576;

// ---------------------------------------------------------------------------
// STUN message encoding
// ---------------------------------------------------------------------------

/// Generates a random 12-byte transaction ID.
fn new_transaction_id() -> [u8; TRANSACTION_ID_SIZE] {
    let mut id = [0u8; TRANSACTION_ID_SIZE];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

/// Encodes a STUN Binding Request (20 bytes, no attributes).
#[must_use]
pub fn encode_binding_request(
    transaction_id: &[u8; TRANSACTION_ID_SIZE],
) -> [u8; STUN_HEADER_SIZE] {
    let mut buf = [0u8; STUN_HEADER_SIZE];
    // Message type (2 bytes).
    buf[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    // Message length (2 bytes) -- 0, no attributes.
    buf[2..4].copy_from_slice(&0u16.to_be_bytes());
    // Magic cookie (4 bytes).
    buf[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    // Transaction ID (12 bytes).
    buf[8..20].copy_from_slice(transaction_id);
    buf
}

/// Encodes a STUN Binding Indication (20 bytes, no attributes, no response
/// expected). Used for NAT keepalive (spec 10.12.3).
#[must_use]
pub fn encode_binding_indication() -> [u8; STUN_HEADER_SIZE] {
    let txn_id = new_transaction_id();
    let mut buf = [0u8; STUN_HEADER_SIZE];
    buf[0..2].copy_from_slice(&BINDING_INDICATION.to_be_bytes());
    buf[2..4].copy_from_slice(&0u16.to_be_bytes());
    buf[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    buf[8..20].copy_from_slice(&txn_id);
    buf
}

// ---------------------------------------------------------------------------
// STUN message decoding
// ---------------------------------------------------------------------------

/// Parsed external address from a STUN Binding Response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StunBindingResponse {
    /// External IP:port as seen by the STUN server.
    pub mapped_addr: SocketAddr,
    /// Transaction ID from the response (must match the request).
    pub transaction_id: [u8; TRANSACTION_ID_SIZE],
}

/// Parses a STUN Binding Response and extracts the external address.
///
/// Returns the mapped address from `XOR-MAPPED-ADDRESS` (preferred) or
/// `MAPPED-ADDRESS` (fallback).
///
/// # Errors
///
/// Returns [`TransportError::ProtocolError`] if the response is malformed,
/// is not a Binding Response, or contains no address attribute.
#[allow(clippy::similar_names)]
pub fn decode_binding_response(buf: &[u8]) -> Result<StunBindingResponse, TransportError> {
    if buf.len() < STUN_HEADER_SIZE {
        return Err(TransportError::ProtocolError(
            "STUN response too short".into(),
        ));
    }

    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != BINDING_RESPONSE {
        return Err(TransportError::ProtocolError(format!(
            "expected STUN Binding Response (0x0101), got 0x{msg_type:04x}"
        )));
    }

    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(TransportError::ProtocolError(
            "STUN magic cookie mismatch".into(),
        ));
    }

    let mut transaction_id = [0u8; TRANSACTION_ID_SIZE];
    transaction_id.copy_from_slice(&buf[8..20]);

    // Ensure the buffer contains all declared attributes.
    let attrs_end = STUN_HEADER_SIZE + msg_len;
    if buf.len() < attrs_end {
        return Err(TransportError::ProtocolError(
            "STUN response truncated (declared length exceeds buffer)".into(),
        ));
    }

    // Walk attributes looking for XOR-MAPPED-ADDRESS or MAPPED-ADDRESS.
    let mut xor_addr: Option<SocketAddr> = None;
    let mut mapped_addr: Option<SocketAddr> = None;
    let mut offset = STUN_HEADER_SIZE;

    while offset + 4 <= attrs_end {
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        let attr_start = offset + 4;
        let attr_end = attr_start + attr_len;

        if attr_end > attrs_end {
            break; // Malformed attribute -- stop scanning.
        }

        let attr_data = &buf[attr_start..attr_end];

        if attr_type == ATTR_XOR_MAPPED_ADDRESS {
            xor_addr = Some(decode_xor_mapped_address(attr_data, &transaction_id)?);
        } else if attr_type == ATTR_MAPPED_ADDRESS && xor_addr.is_none() {
            mapped_addr = Some(decode_mapped_address(attr_data)?);
        }

        // Attributes are padded to 4-byte boundaries (RFC 8489 section 14).
        let padded_len = (attr_len + 3) & !3;
        offset = attr_start + padded_len;
    }

    let addr = xor_addr.or(mapped_addr).ok_or_else(|| {
        TransportError::ProtocolError(
            "STUN Binding Response contains no XOR-MAPPED-ADDRESS or MAPPED-ADDRESS".into(),
        )
    })?;

    Ok(StunBindingResponse {
        mapped_addr: addr,
        transaction_id,
    })
}

/// Decodes an `XOR-MAPPED-ADDRESS` attribute value (RFC 8489 section 14.2).
fn decode_xor_mapped_address(
    data: &[u8],
    transaction_id: &[u8; TRANSACTION_ID_SIZE],
) -> Result<SocketAddr, TransportError> {
    // Minimum: 1 (reserved) + 1 (family) + 2 (port) + 4 (IPv4 addr) = 8.
    if data.len() < 8 {
        return Err(TransportError::ProtocolError(
            "XOR-MAPPED-ADDRESS attribute too short".into(),
        ));
    }

    let family = data[1];
    let xor_port = u16::from_be_bytes([data[2], data[3]]);
    let port = xor_port ^ (MAGIC_COOKIE >> 16) as u16;

    match family {
        FAMILY_IPV4 => {
            let xor_ip = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            let ip = Ipv4Addr::from(xor_ip ^ MAGIC_COOKIE);
            Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        FAMILY_IPV6 => {
            if data.len() < 20 {
                return Err(TransportError::ProtocolError(
                    "XOR-MAPPED-ADDRESS IPv6 attribute too short".into(),
                ));
            }
            // XOR with magic cookie (4 bytes) + transaction ID (12 bytes).
            let mut xor_key = [0u8; 16];
            xor_key[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            xor_key[4..16].copy_from_slice(transaction_id);

            let mut ip_bytes = [0u8; 16];
            for i in 0..16 {
                ip_bytes[i] = data[4 + i] ^ xor_key[i];
            }
            let ip = Ipv6Addr::from(ip_bytes);
            Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
        }
        _ => Err(TransportError::ProtocolError(format!(
            "unknown address family in XOR-MAPPED-ADDRESS: 0x{family:02x}"
        ))),
    }
}

/// Decodes a `MAPPED-ADDRESS` attribute value (RFC 8489 section 14.1).
fn decode_mapped_address(data: &[u8]) -> Result<SocketAddr, TransportError> {
    if data.len() < 8 {
        return Err(TransportError::ProtocolError(
            "MAPPED-ADDRESS attribute too short".into(),
        ));
    }

    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]);

    match family {
        FAMILY_IPV4 => {
            let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        FAMILY_IPV6 => {
            if data.len() < 20 {
                return Err(TransportError::ProtocolError(
                    "MAPPED-ADDRESS IPv6 attribute too short".into(),
                ));
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&data[4..20]);
            let ip = Ipv6Addr::from(ip_bytes);
            Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
        }
        _ => Err(TransportError::ProtocolError(format!(
            "unknown address family in MAPPED-ADDRESS: 0x{family:02x}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// STUN binding request/response round-trip
// ---------------------------------------------------------------------------

/// Sends a STUN Binding Request over UDP and waits for the response.
///
/// Returns the parsed response containing the external address. Uses
/// `timeout` for the round-trip (default: 3 seconds per spec 10.12.3).
///
/// # Errors
///
/// Returns [`TransportError::SendFailed`] if the UDP send fails,
/// [`TransportError::Timeout`] if no valid response arrives within the
/// timeout, or [`TransportError::ProtocolError`] if the response is
/// malformed.
pub async fn stun_binding_request(
    socket: &UdpSocket,
    server: SocketAddr,
    timeout: Option<Duration>,
) -> Result<StunBindingResponse, TransportError> {
    let txn_id = new_transaction_id();
    let request = encode_binding_request(&txn_id);
    let timeout = timeout.unwrap_or(DEFAULT_TIMEOUT);

    socket
        .send_to(&request, server)
        .await
        .map_err(|e| TransportError::SendFailed(format!("STUN send to {server}: {e}")))?;

    let mut buf = [0u8; MAX_STUN_MSG_SIZE];

    let recv_future = async {
        loop {
            let (len, from) = socket.recv_from(&mut buf).await.map_err(|e| {
                TransportError::ConnectionFailed(format!("STUN recv from {server}: {e}"))
            })?;

            // Validate sender -- ignore packets from unexpected sources.
            if from != server {
                debug!(
                    expected = %server,
                    got = %from,
                    "ignoring STUN response from unexpected source"
                );
                continue;
            }

            let response = decode_binding_response(&buf[..len])?;

            // Validate transaction ID.
            if response.transaction_id != txn_id {
                debug!("ignoring STUN response with mismatched transaction ID");
                continue;
            }

            return Ok(response);
        }
    };

    tokio::time::timeout(timeout, recv_future)
        .await
        .map_err(|_| TransportError::Timeout)?
}

// ---------------------------------------------------------------------------
// NAT keepalive
// ---------------------------------------------------------------------------

/// Maintains NAT mapping by sending periodic STUN Binding Indications.
///
/// Per spec 10.12.3, a 25-second keepalive prevents NAT mapping expiry
/// (typical NAT timeout: 30-120 seconds). The keepalive is a STUN Binding
/// Indication (type `0x0011`) -- no response is expected.
///
/// Only active for non-symmetric NATs. For symmetric NATs, hole punching
/// is not viable and keepalive is unnecessary (traffic goes through a
/// bridge relay instead).
pub struct NatKeepalive {
    /// The UDP socket used for keepalive packets.
    socket: UdpSocket,
    /// The STUN server to send keepalives to.
    server: SocketAddr,
}

impl NatKeepalive {
    /// Creates a new keepalive sender.
    ///
    /// Use [`send_keepalive`](Self::send_keepalive) for a single keepalive
    /// packet, or spawn [`run_keepalive_loop`] as a background task for
    /// continuous keepalive.
    pub const fn new(socket: UdpSocket, server: SocketAddr) -> Self {
        Self { socket, server }
    }

    /// Returns the keepalive interval (25 seconds per spec 10.12.3).
    #[must_use]
    pub const fn interval() -> Duration {
        KEEPALIVE_INTERVAL
    }

    /// Returns the STUN server address.
    #[must_use]
    pub const fn server(&self) -> SocketAddr {
        self.server
    }

    /// Sends a single STUN Binding Indication keepalive packet.
    ///
    /// Returns `Ok(())` on success. Errors are non-fatal -- a missed
    /// keepalive may cause NAT mapping expiry but does not invalidate
    /// the session.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::SendFailed`] if the UDP send fails.
    pub async fn send_keepalive(&self) -> Result<(), TransportError> {
        let indication = encode_binding_indication();
        self.socket
            .send_to(&indication, self.server)
            .await
            .map_err(|e| {
                TransportError::SendFailed(format!("STUN keepalive to {}: {e}", self.server))
            })?;
        debug!(server = %self.server, "sent STUN keepalive indication");
        Ok(())
    }
}

/// Runs a keepalive loop that sends STUN Binding Indications at the
/// 25-second interval specified in spec 10.12.3. Runs indefinitely --
/// abort the spawned task to stop.
///
/// This is the recommended way to run keepalives -- spawn this as a
/// tokio task and abort it when keepalive is no longer needed.
pub async fn run_keepalive_loop(socket: &UdpSocket, server: SocketAddr) {
    let mut interval = tokio::time::interval(KEEPALIVE_INTERVAL);
    // The first tick completes immediately -- skip it since we just
    // completed the STUN probe.
    interval.tick().await;

    loop {
        interval.tick().await;
        let indication = encode_binding_indication();
        match socket.send_to(&indication, server).await {
            Ok(_) => {
                debug!(server = %server, "sent STUN keepalive indication");
            }
            Err(e) => {
                warn!(server = %server, error = %e, "STUN keepalive send failed");
                // Non-fatal: continue trying. The NAT mapping may expire
                // but the next successful send will re-establish it.
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Test helpers (exposed to sibling modules under #[cfg(test)])
// ---------------------------------------------------------------------------

/// Test helper module for building STUN messages. Available only in test
/// builds so that `nat::mod` tests can construct mock STUN responses.
#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
pub mod tests_helper {
    use super::*;

    /// Builds a STUN Binding Response with a single XOR-MAPPED-ADDRESS
    /// attribute for the given address and transaction ID.
    #[must_use]
    pub fn build_binding_response(
        addr: SocketAddr,
        transaction_id: &[u8; TRANSACTION_ID_SIZE],
    ) -> Vec<u8> {
        let attr_data = encode_xor_mapped_address_value(addr, transaction_id);
        let attr_len = attr_data.len() as u16;
        let padded_attr_len = ((attr_data.len() + 3) & !3) as u16;

        // Total attributes section: 4 (attr header) + padded_attr_len.
        let msg_len = 4 + padded_attr_len;

        let mut buf = Vec::with_capacity(STUN_HEADER_SIZE + msg_len as usize);

        // Header.
        buf.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        buf.extend_from_slice(&msg_len.to_be_bytes());
        buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(transaction_id);

        // Attribute header.
        buf.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        buf.extend_from_slice(&attr_len.to_be_bytes());
        buf.extend_from_slice(&attr_data);

        // Padding to 4-byte boundary.
        let padding = (4 - (attr_data.len() % 4)) % 4;
        buf.extend(std::iter::repeat_n(0u8, padding));

        buf
    }

    /// Encodes an XOR-MAPPED-ADDRESS attribute value for test construction.
    fn encode_xor_mapped_address_value(
        addr: SocketAddr,
        transaction_id: &[u8; TRANSACTION_ID_SIZE],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(0x00); // Reserved.

        match addr {
            SocketAddr::V4(v4) => {
                data.push(FAMILY_IPV4);
                let xor_port = v4.port() ^ (MAGIC_COOKIE >> 16) as u16;
                data.extend_from_slice(&xor_port.to_be_bytes());
                let ip_bits: u32 = (*v4.ip()).into();
                let xor_ip = ip_bits ^ MAGIC_COOKIE;
                data.extend_from_slice(&xor_ip.to_be_bytes());
            }
            SocketAddr::V6(v6) => {
                data.push(FAMILY_IPV6);
                let xor_port = v6.port() ^ (MAGIC_COOKIE >> 16) as u16;
                data.extend_from_slice(&xor_port.to_be_bytes());
                let ip_bytes = v6.ip().octets();
                let mut xor_key = [0u8; 16];
                xor_key[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                xor_key[4..16].copy_from_slice(transaction_id);
                for i in 0..16 {
                    data.push(ip_bytes[i] ^ xor_key[i]);
                }
            }
        }
        data
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    use tests_helper::build_binding_response;

    // -- Binding Request encoding -------------------------------------------

    #[test]
    fn binding_request_is_20_bytes() {
        let txn_id = [0xAA; TRANSACTION_ID_SIZE];
        let req = encode_binding_request(&txn_id);
        assert_eq!(req.len(), STUN_HEADER_SIZE);
    }

    #[test]
    fn binding_request_has_correct_type() {
        let txn_id = [0x01; TRANSACTION_ID_SIZE];
        let req = encode_binding_request(&txn_id);
        let msg_type = u16::from_be_bytes([req[0], req[1]]);
        assert_eq!(msg_type, BINDING_REQUEST);
    }

    #[test]
    fn binding_request_has_magic_cookie() {
        let txn_id = [0x02; TRANSACTION_ID_SIZE];
        let req = encode_binding_request(&txn_id);
        let cookie = u32::from_be_bytes([req[4], req[5], req[6], req[7]]);
        assert_eq!(cookie, MAGIC_COOKIE);
    }

    #[test]
    fn binding_request_has_zero_length() {
        let txn_id = [0x03; TRANSACTION_ID_SIZE];
        let req = encode_binding_request(&txn_id);
        let len = u16::from_be_bytes([req[2], req[3]]);
        assert_eq!(len, 0);
    }

    #[test]
    fn binding_request_embeds_transaction_id() {
        let txn_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let req = encode_binding_request(&txn_id);
        assert_eq!(&req[8..20], &txn_id);
    }

    // -- Binding Indication encoding ----------------------------------------

    #[test]
    fn binding_indication_is_20_bytes() {
        let ind = encode_binding_indication();
        assert_eq!(ind.len(), STUN_HEADER_SIZE);
    }

    #[test]
    fn binding_indication_has_correct_type() {
        let ind = encode_binding_indication();
        let msg_type = u16::from_be_bytes([ind[0], ind[1]]);
        assert_eq!(msg_type, BINDING_INDICATION);
    }

    #[test]
    fn binding_indication_has_magic_cookie() {
        let ind = encode_binding_indication();
        let cookie = u32::from_be_bytes([ind[4], ind[5], ind[6], ind[7]]);
        assert_eq!(cookie, MAGIC_COOKIE);
    }

    // -- Binding Response decoding ------------------------------------------

    #[test]
    fn decode_ipv4_xor_mapped_address() {
        let txn_id = [0x11; TRANSACTION_ID_SIZE];
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 42), 32891));

        let response = build_binding_response(addr, &txn_id);
        let parsed = decode_binding_response(&response).expect("should parse");

        assert_eq!(parsed.mapped_addr, addr);
        assert_eq!(parsed.transaction_id, txn_id);
    }

    #[test]
    fn decode_ipv6_xor_mapped_address() {
        let txn_id = [0x22; TRANSACTION_ID_SIZE];
        let addr = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            8080,
            0,
            0,
        ));

        let response = build_binding_response(addr, &txn_id);
        let parsed = decode_binding_response(&response).expect("should parse");

        assert_eq!(parsed.mapped_addr, addr);
        assert_eq!(parsed.transaction_id, txn_id);
    }

    #[test]
    fn decode_rejects_too_short() {
        let result = decode_binding_response(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn decode_rejects_wrong_message_type() {
        let txn_id = [0x33; TRANSACTION_ID_SIZE];
        let mut response = build_binding_response(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1234)),
            &txn_id,
        );
        // Overwrite type to Binding Request.
        response[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
        assert!(decode_binding_response(&response).is_err());
    }

    #[test]
    fn decode_rejects_wrong_magic_cookie() {
        let txn_id = [0x44; TRANSACTION_ID_SIZE];
        let mut response = build_binding_response(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1234)),
            &txn_id,
        );
        // Corrupt magic cookie.
        response[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        assert!(decode_binding_response(&response).is_err());
    }

    #[test]
    fn decode_rejects_response_with_no_address_attribute() {
        let txn_id = [0x55; TRANSACTION_ID_SIZE];
        // Construct a Binding Response with zero-length body (no attributes).
        let mut buf = vec![0u8; STUN_HEADER_SIZE];
        buf[0..2].copy_from_slice(&BINDING_RESPONSE.to_be_bytes());
        buf[2..4].copy_from_slice(&0u16.to_be_bytes());
        buf[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf[8..20].copy_from_slice(&txn_id);

        assert!(decode_binding_response(&buf).is_err());
    }

    // -- Keepalive ----------------------------------------------------------

    #[tokio::test]
    async fn keepalive_fires_at_25_second_interval() {
        // Use tokio's time mocking to verify the interval without real delays.
        tokio::time::pause();

        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let recv_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let server_addr = recv_socket.local_addr().expect("local_addr");

        // Verify the interval constant.
        assert_eq!(NatKeepalive::interval(), Duration::from_secs(25));

        // Create the keepalive and test timing via manual interval + send.
        let keepalive = NatKeepalive::new(socket, server_addr);

        let start = tokio::time::Instant::now();
        let mut interval = tokio::time::interval(KEEPALIVE_INTERVAL);
        interval.tick().await; // First tick is immediate.

        // Advance time by 25 seconds.
        tokio::time::advance(KEEPALIVE_INTERVAL).await;
        interval.tick().await;

        let elapsed = start.elapsed();
        assert!(
            elapsed >= KEEPALIVE_INTERVAL,
            "keepalive should fire at 25s, elapsed: {elapsed:?}"
        );

        // Send a keepalive and verify the recv side gets a Binding Indication.
        keepalive.send_keepalive().await.expect("send keepalive");

        let mut buf = [0u8; MAX_STUN_MSG_SIZE];
        let (len, _from) = recv_socket.recv_from(&mut buf).await.expect("recv");

        assert_eq!(len, STUN_HEADER_SIZE);
        let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
        assert_eq!(msg_type, BINDING_INDICATION);
    }

    #[tokio::test]
    async fn send_keepalive_sends_binding_indication() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let recv_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let server_addr = recv_socket.local_addr().expect("local_addr");

        let keepalive = NatKeepalive::new(socket, server_addr);
        keepalive.send_keepalive().await.expect("send keepalive");

        let mut buf = [0u8; MAX_STUN_MSG_SIZE];
        let (len, _) = recv_socket.recv_from(&mut buf).await.expect("recv");

        // Verify it's a STUN Binding Indication.
        assert_eq!(len, STUN_HEADER_SIZE);
        let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
        assert_eq!(msg_type, BINDING_INDICATION);

        // Verify magic cookie.
        let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        assert_eq!(cookie, MAGIC_COOKIE);

        // Verify zero length (no attributes).
        let msg_len = u16::from_be_bytes([buf[2], buf[3]]);
        assert_eq!(msg_len, 0);
    }

    // -- STUN binding request round-trip with mock server -------------------

    #[tokio::test]
    async fn stun_binding_request_returns_external_addr() {
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind server");
        let server_addr = server_socket.local_addr().expect("server addr");

        // The "external address" our mock STUN server will report.
        let external_addr =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 32891));

        // Spawn mock STUN server.
        let server_handle = tokio::spawn(async move {
            let mut buf = [0u8; MAX_STUN_MSG_SIZE];
            let (len, from) = server_socket.recv_from(&mut buf).await.expect("recv");

            // Parse the incoming Binding Request.
            assert_eq!(len, STUN_HEADER_SIZE);
            let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
            assert_eq!(msg_type, BINDING_REQUEST);

            let mut txn_id = [0u8; TRANSACTION_ID_SIZE];
            txn_id.copy_from_slice(&buf[8..20]);

            // Build and send a Binding Response.
            let response = build_binding_response(external_addr, &txn_id);
            server_socket
                .send_to(&response, from)
                .await
                .expect("send response");
        });

        // Send the request and verify the response.
        let result =
            stun_binding_request(&client_socket, server_addr, Some(Duration::from_secs(5)))
                .await
                .expect("stun request");

        assert_eq!(result.mapped_addr, external_addr);

        server_handle.await.expect("server task");
    }

    #[tokio::test]
    async fn stun_binding_request_times_out() {
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        // Send to an address where nobody is listening.
        let server_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1));

        tokio::time::pause();

        let result_handle = tokio::spawn(async move {
            stun_binding_request(
                &client_socket,
                server_addr,
                Some(Duration::from_millis(100)),
            )
            .await
        });

        tokio::time::advance(Duration::from_millis(200)).await;

        let result = result_handle.await.expect("task");
        assert!(
            matches!(result, Err(TransportError::Timeout)),
            "expected timeout, got: {result:?}"
        );
    }

    // -- Keepalive interval constant ----------------------------------------

    #[test]
    fn keepalive_interval_is_25_seconds() {
        assert_eq!(NatKeepalive::interval(), Duration::from_secs(25));
    }
}
