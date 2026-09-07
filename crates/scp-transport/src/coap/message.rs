//! CoAP message types and serialization for SCP operations.
//!
//! This module maps SCP operations to CoAP messages per spec section 10.16.2.
//! CoAP (RFC 7252) framing is provided by the `coap-lite` crate. SCP-specific
//! concerns:
//!
//! - URI pattern: `/scp/{hex(routing_id)}` with optional path/query segments
//! - Content format: `application/msgpack` (112) for blob payloads
//! - Confirmable (CON) messages for PUBLISH and DELETE (at-least-once)
//! - Non-confirmable (NON) messages permitted for QUERY when loss is acceptable
//! - Observe option (RFC 7641) for lightweight subscription
//!
//! See ADR-037 in `.docs/adrs/phase-2.md` for the transport binding design.

use coap_lite::{CoapOption, MessageClass, MessageType, Packet, RequestType, ResponseType};

use crate::error::TransportError;
use scp_relay_client::sanitize_relay_text;

/// URI prefix for all SCP CoAP resources (section 10.16.2 point 1).
pub const SCP_COAP_URI_PREFIX: &str = "scp";

/// CoAP content-format identifier for `application/msgpack`.
///
/// Registered in the IANA CoAP Content-Formats registry. Used as the
/// Content-Format option value for all SCP blob payloads.
pub const CONTENT_FORMAT_MSGPACK: u16 = 112;

/// CoAP Observe option number (RFC 7641).
/// Note: `coap_lite::CoapOption::Observe` is used directly in code, but this
/// constant documents the raw option number for reference.
pub const OBSERVE_OPTION: u16 = 6;

/// CoAP Observe register value (RFC 7641 section 2).
const OBSERVE_REGISTER: u8 = 0;

/// Supported CoAP methods for SCP operations.
///
/// Maps to the CoAP method codes defined in RFC 7252 section 12.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoapMethod {
    /// POST -- maps to SCP PUBLISH (section 10.16.2 point 1).
    Post,
    /// GET -- maps to SCP QUERY (section 10.16.2 point 1).
    Get,
    /// DELETE -- maps to SCP DELETE (section 10.16.2 point 1).
    Delete,
}

impl CoapMethod {
    /// Returns the `coap_lite::RequestType` for this method.
    #[must_use]
    pub const fn to_request_type(self) -> RequestType {
        match self {
            Self::Post => RequestType::Post,
            Self::Get => RequestType::Get,
            Self::Delete => RequestType::Delete,
        }
    }
}

/// CoAP content format for SCP payloads.
///
/// SCP always uses `application/msgpack` (112) for blob payloads, aligning
/// with ADR-004's `MessagePack` wire format across all transport bindings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoapContentFormat {
    /// `application/msgpack` -- the standard content format for SCP blobs.
    ApplicationMsgpack,
}

impl CoapContentFormat {
    /// Returns the IANA content-format number.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::ApplicationMsgpack => CONTENT_FORMAT_MSGPACK,
        }
    }

    /// Encodes the content-format as bytes for the CoAP Content-Format option.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn to_option_bytes(self) -> Vec<u8> {
        let val = self.as_u16();
        if val == 0 {
            vec![0]
        } else if val <= 0xFF {
            vec![val as u8]
        } else {
            vec![(val >> 8) as u8, val as u8]
        }
    }
}

/// Builder for CoAP request packets used by the [`CoapAdapter`](super::CoapAdapter).
///
/// Constructs well-formed CoAP request packets for SCP operations following
/// the URI patterns and message types specified in section 10.16.2.
pub struct CoapRequestBuilder;

impl CoapRequestBuilder {
    /// Builds a CoAP POST request for PUBLISH (section 10.16.2 point 1).
    ///
    /// URI: `POST /scp/{hex(routing_id)}`
    /// Message type: Confirmable (CON) for at-least-once delivery (section 10.16.2 point 3).
    /// Content-Format: application/msgpack (112).
    /// Payload: MessagePack-encoded outer envelope blob.
    ///
    /// # Arguments
    ///
    /// * `message_id` -- CoAP message ID for matching responses.
    /// * `token` -- CoAP token for request/response correlation.
    /// * `routing_id` -- 32-byte routing ID (hex-encoded in the URI).
    /// * `blob` -- MessagePack-serialized outer envelope.
    #[must_use]
    pub fn publish(message_id: u16, token: &[u8], routing_id: &[u8; 32], blob: &[u8]) -> Packet {
        let mut packet = Packet::new();
        packet.header.set_version(1);
        packet.header.message_id = message_id;
        packet.header.set_type(MessageType::Confirmable);
        packet.header.code = MessageClass::Request(RequestType::Post);
        packet.set_token(token.to_vec());

        // URI-Path options: "scp", hex(routing_id)
        let routing_hex = hex::encode(routing_id);
        packet.add_option(CoapOption::UriPath, SCP_COAP_URI_PREFIX.as_bytes().to_vec());
        packet.add_option(CoapOption::UriPath, routing_hex.into_bytes());

        // Content-Format: application/msgpack (112)
        packet.add_option(
            CoapOption::ContentFormat,
            CoapContentFormat::ApplicationMsgpack.to_option_bytes(),
        );

        packet.payload = blob.to_vec();

        packet
    }

    /// Builds a CoAP GET request for QUERY (section 10.16.2 point 1).
    ///
    /// URI: `GET /scp/{hex(routing_id)}?since={timestamp}&limit={n}`
    /// Message type: Confirmable (CON) by default. Callers may use NON when
    /// loss is acceptable (section 10.16.2 point 3).
    ///
    /// # Arguments
    ///
    /// * `message_id` -- CoAP message ID for matching responses.
    /// * `token` -- CoAP token for request/response correlation.
    /// * `routing_id` -- 32-byte routing ID (hex-encoded in the URI).
    /// * `since` -- Optional epoch-seconds filter for stored envelopes.
    /// * `limit` -- Optional maximum number of results.
    /// * `confirmable` -- If `true`, uses CON; if `false`, uses NON.
    #[must_use]
    pub fn query(
        message_id: u16,
        token: &[u8],
        routing_id: &[u8; 32],
        since: Option<u64>,
        limit: Option<u32>,
        confirmable: bool,
    ) -> Packet {
        let mut packet = Packet::new();
        packet.header.set_version(1);
        packet.header.message_id = message_id;
        packet.header.set_type(if confirmable {
            MessageType::Confirmable
        } else {
            MessageType::NonConfirmable
        });
        packet.header.code = MessageClass::Request(RequestType::Get);
        packet.set_token(token.to_vec());

        // URI-Path options: "scp", hex(routing_id)
        let routing_hex = hex::encode(routing_id);
        packet.add_option(CoapOption::UriPath, SCP_COAP_URI_PREFIX.as_bytes().to_vec());
        packet.add_option(CoapOption::UriPath, routing_hex.into_bytes());

        // URI-Query options: since, limit
        if let Some(ts) = since {
            let query_str = format!("since={ts}");
            packet.add_option(CoapOption::UriQuery, query_str.into_bytes());
        }
        if let Some(n) = limit {
            let query_str = format!("limit={n}");
            packet.add_option(CoapOption::UriQuery, query_str.into_bytes());
        }

        // Accept: application/msgpack (112)
        packet.add_option(
            CoapOption::Accept,
            CoapContentFormat::ApplicationMsgpack.to_option_bytes(),
        );

        packet
    }

    /// Builds a CoAP DELETE request for blob deletion (section 10.16.2 point 1).
    ///
    /// URI: `DELETE /scp/{hex(routing_id)}/{hex(blob_id)}`
    /// Message type: Confirmable (CON) for at-least-once delivery (section 10.16.2 point 3).
    ///
    /// # Arguments
    ///
    /// * `message_id` -- CoAP message ID for matching responses.
    /// * `token` -- CoAP token for request/response correlation.
    /// * `routing_id` -- 32-byte routing ID (hex-encoded in the URI).
    /// * `blob_id` -- 32-byte blob ID (hex-encoded in the URI).
    #[must_use]
    pub fn delete(
        message_id: u16,
        token: &[u8],
        routing_id: &[u8; 32],
        blob_id: &[u8; 32],
    ) -> Packet {
        let mut packet = Packet::new();
        packet.header.set_version(1);
        packet.header.message_id = message_id;
        packet.header.set_type(MessageType::Confirmable);
        packet.header.code = MessageClass::Request(RequestType::Delete);
        packet.set_token(token.to_vec());

        // URI-Path options: "scp", hex(routing_id), hex(blob_id)
        let routing_hex = hex::encode(routing_id);
        let blob_hex = hex::encode(blob_id);
        packet.add_option(CoapOption::UriPath, SCP_COAP_URI_PREFIX.as_bytes().to_vec());
        packet.add_option(CoapOption::UriPath, routing_hex.into_bytes());
        packet.add_option(CoapOption::UriPath, blob_hex.into_bytes());

        packet
    }

    /// Builds a CoAP GET request with Observe registration for lightweight
    /// subscription (section 10.16.2 point 2, RFC 7641).
    ///
    /// URI: `GET /scp/{hex(routing_id)}`
    /// Observe option: Register (0)
    /// Message type: Confirmable (CON).
    ///
    /// The server pushes new blobs as notifications. This is best-effort --
    /// the server MAY stop notifying at any time, and the client must
    /// re-register.
    ///
    /// # Arguments
    ///
    /// * `message_id` -- CoAP message ID for matching responses.
    /// * `token` -- CoAP token for correlating notifications.
    /// * `routing_id` -- 32-byte routing ID (hex-encoded in the URI).
    #[must_use]
    pub fn observe(message_id: u16, token: &[u8], routing_id: &[u8; 32]) -> Packet {
        let mut packet = Packet::new();
        packet.header.set_version(1);
        packet.header.message_id = message_id;
        packet.header.set_type(MessageType::Confirmable);
        packet.header.code = MessageClass::Request(RequestType::Get);
        packet.set_token(token.to_vec());

        // Observe: Register (0) -- RFC 7641 section 2
        packet.add_option(CoapOption::Observe, vec![OBSERVE_REGISTER]);

        // URI-Path options: "scp", hex(routing_id)
        let routing_hex = hex::encode(routing_id);
        packet.add_option(CoapOption::UriPath, SCP_COAP_URI_PREFIX.as_bytes().to_vec());
        packet.add_option(CoapOption::UriPath, routing_hex.into_bytes());

        // Accept: application/msgpack (112)
        packet.add_option(
            CoapOption::Accept,
            CoapContentFormat::ApplicationMsgpack.to_option_bytes(),
        );

        packet
    }

    /// Builds a CoAP RST (Reset) packet to deregister an Observe subscription
    /// (RFC 7641 section 3.6).
    ///
    /// Sent in response to a notification to tell the server to stop sending
    /// notifications for this observation.
    ///
    /// # Arguments
    ///
    /// * `message_id` -- The message ID from the notification being rejected.
    /// * `token` -- The token from the original Observe registration.
    #[must_use]
    pub fn observe_deregister(message_id: u16, token: &[u8]) -> Packet {
        let mut packet = Packet::new();
        packet.header.set_version(1);
        packet.header.message_id = message_id;
        packet.header.set_type(MessageType::Reset);
        packet.header.code = MessageClass::Empty;
        packet.set_token(token.to_vec());
        packet
    }
}

/// Parser for CoAP response packets received by the [`CoapAdapter`](super::CoapAdapter).
///
/// Extracts SCP-relevant information from CoAP responses: response codes,
/// content-format validation, Observe sequence numbers, and payload extraction.
pub struct CoapResponseParser;

impl CoapResponseParser {
    /// Parses a raw CoAP datagram into a `coap_lite::Packet`.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ProtocolError`] if the datagram is not a
    /// valid CoAP packet.
    pub fn parse(data: &[u8]) -> Result<Packet, TransportError> {
        Packet::from_bytes(data)
            .map_err(|e| TransportError::ProtocolError(format!("invalid CoAP packet: {e}")))
    }

    /// Returns `true` if the response indicates success (2.xx class).
    #[must_use]
    pub const fn is_success(packet: &Packet) -> bool {
        matches!(packet.header.code, MessageClass::Response(r) if is_success_code(r))
    }

    /// Returns `true` if the response carries an Observe notification
    /// (has Observe option with a sequence number).
    #[must_use]
    pub fn is_observe_notification(packet: &Packet) -> bool {
        packet.get_option(CoapOption::Observe).is_some()
    }

    /// Extracts the Observe sequence number from a notification, if present.
    ///
    /// The sequence number is encoded as a variable-length unsigned integer
    /// in the Observe option (RFC 7641 section 4).
    #[must_use]
    pub fn observe_sequence(packet: &Packet) -> Option<u32> {
        let observe_values = packet.get_option(CoapOption::Observe)?;
        let bytes = observe_values.front()?;
        Some(decode_uint(bytes))
    }

    /// Extracts the Content-Format option value from a response, if present.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // CoAP content-format is u16 by spec
    pub fn content_format(packet: &Packet) -> Option<u16> {
        let cf_values = packet.get_option(CoapOption::ContentFormat)?;
        let bytes = cf_values.front()?;
        Some(decode_uint(bytes) as u16)
    }

    /// Validates that the response Content-Format is `application/msgpack` (112).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ProtocolError`] if the Content-Format is
    /// present but not `application/msgpack`.
    pub fn validate_content_format(packet: &Packet) -> Result<(), TransportError> {
        if let Some(cf) = Self::content_format(packet)
            && cf != CONTENT_FORMAT_MSGPACK
        {
            return Err(TransportError::ProtocolError(format!(
                "unexpected CoAP Content-Format: expected {CONTENT_FORMAT_MSGPACK} \
                 (application/msgpack), got {cf}"
            )));
        }
        Ok(())
    }

    /// Extracts a human-readable error description from a CoAP error response.
    ///
    /// For error responses (4.xx, 5.xx), the payload may contain a
    /// diagnostic message. Returns the response code and optional message.
    #[must_use]
    pub fn error_description(packet: &Packet) -> String {
        let code = format!("{:?}", packet.header.code);
        if packet.payload.is_empty() {
            code
        } else {
            let msg = String::from_utf8_lossy(&packet.payload);
            // The payload is server-supplied diagnostic text; render it inert
            // before it reaches a log or a `TransportError`.
            format!("{code}: {}", sanitize_relay_text(&msg))
        }
    }

    /// Extracts the CoAP Block2 option to detect block-wise transfers
    /// (RFC 7959).
    ///
    /// Returns `(block_num, more_blocks, block_size)` if the Block2 option
    /// is present. Used for reassembling large payloads that exceed a single
    /// CoAP datagram.
    #[must_use]
    pub fn block2_option(packet: &Packet) -> Option<BlockOption> {
        // Block2 option number is 23 in CoAP
        let block_values = packet.get_option(CoapOption::Block2)?;
        let bytes = block_values.front()?;
        Some(BlockOption::decode(bytes))
    }
}

/// Decoded CoAP Block option (RFC 7959).
///
/// Used for block-wise transfer of large payloads that exceed a single CoAP
/// datagram. The constrained device profile typically has MTU constraints
/// (~1200 bytes for common networks per section 10.16.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockOption {
    /// Block number (0-indexed).
    pub num: u32,
    /// Whether more blocks follow.
    pub more: bool,
    /// Block size as a power of 2 (actual size = 2^(szx+4)).
    pub szx: u8,
}

impl BlockOption {
    /// Decodes a Block option from its wire bytes (RFC 7959 section 2.2).
    ///
    /// The option value is 0-3 bytes encoding:
    /// - Bits 0-2: SZX (size exponent, block size = 2^(SZX+4))
    /// - Bit 3: M (more blocks)
    /// - Bits 4+: NUM (block number)
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self {
                num: 0,
                more: false,
                szx: 0,
            };
        }

        let val = decode_uint(bytes);
        let szx = (val & 0x07) as u8;
        let more = (val & 0x08) != 0;
        let num = val >> 4;

        Self { num, more, szx }
    }

    /// Encodes this Block option to wire bytes (RFC 7959 section 2.2).
    ///
    /// Block numbers larger than 2^28 - 1 (20-bit NUM field limit per
    /// RFC 7959) are saturated to `u32::MAX >> 4` to avoid silent truncation.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let max_num = u32::MAX >> 4; // Maximum representable block number
        let num = self.num.min(max_num);
        let val = (num << 4) | (u32::from(self.more) << 3) | u32::from(self.szx);
        encode_uint(val)
    }

    /// Returns the actual block size in bytes (2^(SZX+4)).
    ///
    /// SZX is clamped to the RFC 7959 section 2.2 maximum of 6 to prevent
    /// shift overflow on malformed or untrusted input.
    #[must_use]
    pub fn block_size(&self) -> usize {
        // SZX must be 0-6 per RFC 7959 section 2.2
        let szx = self.szx.min(6);
        1 << (szx as usize + 4)
    }
}

/// Decodes a variable-length unsigned integer from CoAP option bytes.
///
/// CoAP options encode unsigned integers in network byte order with no
/// leading zeros (RFC 7252 section 3.2). Input is clamped to 4 bytes
/// (u32 range); excess bytes are ignored to prevent overflow panics.
fn decode_uint(bytes: &[u8]) -> u32 {
    let mut val: u32 = 0;
    // Clamp to 4 bytes to prevent u32 shift overflow (panics in debug).
    for &b in bytes.iter().take(4) {
        val = (val << 8) | u32::from(b);
    }
    val
}

/// Encodes an unsigned integer to the minimal CoAP option byte representation.
fn encode_uint(val: u32) -> Vec<u8> {
    if val == 0 {
        return vec![];
    }
    let bytes = val.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
    bytes[start..].to_vec()
}

/// Returns `true` if the `ResponseType` is a success code (2.xx).
const fn is_success_code(code: ResponseType) -> bool {
    matches!(
        code,
        ResponseType::Created
            | ResponseType::Deleted
            | ResponseType::Valid
            | ResponseType::Changed
            | ResponseType::Content
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // ---- CoapMethod tests ----

    #[test]
    fn coap_method_to_request_type() {
        assert_eq!(CoapMethod::Post.to_request_type(), RequestType::Post);
        assert_eq!(CoapMethod::Get.to_request_type(), RequestType::Get);
        assert_eq!(CoapMethod::Delete.to_request_type(), RequestType::Delete);
    }

    // ---- CoapContentFormat tests ----

    #[test]
    fn content_format_msgpack_is_112() {
        assert_eq!(CoapContentFormat::ApplicationMsgpack.as_u16(), 112);
    }

    #[test]
    fn content_format_option_bytes() {
        let bytes = CoapContentFormat::ApplicationMsgpack.to_option_bytes();
        // 112 fits in one byte
        assert_eq!(bytes, vec![112]);
    }

    // ---- CoapRequestBuilder: PUBLISH ----

    #[test]
    fn publish_builds_correct_packet() {
        let routing_id = [0xAA; 32];
        let blob = vec![0x01, 0x02, 0x03];
        let token = vec![0xDE, 0xAD];

        let packet = CoapRequestBuilder::publish(42, &token, &routing_id, &blob);

        // Confirmable POST
        assert_eq!(packet.header.get_type(), MessageType::Confirmable);
        assert_eq!(packet.header.code, MessageClass::Request(RequestType::Post));
        assert_eq!(packet.header.message_id, 42);
        assert_eq!(packet.get_token(), &token);

        // URI-Path: "scp", hex(routing_id)
        let paths: Vec<Vec<u8>> = packet
            .get_option(CoapOption::UriPath)
            .unwrap()
            .iter()
            .cloned()
            .collect();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0], b"scp");
        assert_eq!(paths[1], hex::encode(routing_id).into_bytes());

        // Content-Format: 112 (application/msgpack)
        let cf: Vec<Vec<u8>> = packet
            .get_option(CoapOption::ContentFormat)
            .unwrap()
            .iter()
            .cloned()
            .collect();
        assert_eq!(cf.len(), 1);
        assert_eq!(cf[0], vec![112]);

        // Payload
        assert_eq!(packet.payload, blob);
    }

    // ---- CoapRequestBuilder: QUERY ----

    #[test]
    fn query_builds_correct_packet_confirmable() {
        let routing_id = [0xBB; 32];
        let token = vec![0x01];

        let packet =
            CoapRequestBuilder::query(100, &token, &routing_id, Some(1000), Some(10), true);

        assert_eq!(packet.header.get_type(), MessageType::Confirmable);
        assert_eq!(packet.header.code, MessageClass::Request(RequestType::Get));

        // URI-Query options
        let queries: Vec<Vec<u8>> = packet
            .get_option(CoapOption::UriQuery)
            .unwrap()
            .iter()
            .cloned()
            .collect();
        assert_eq!(queries.len(), 2);
        assert_eq!(queries[0], b"since=1000");
        assert_eq!(queries[1], b"limit=10");
    }

    #[test]
    fn query_non_confirmable() {
        let routing_id = [0xCC; 32];
        let token = vec![0x02];

        let packet = CoapRequestBuilder::query(101, &token, &routing_id, None, None, false);

        assert_eq!(packet.header.get_type(), MessageType::NonConfirmable);
    }

    #[test]
    fn query_without_since_or_limit() {
        let routing_id = [0xDD; 32];
        let token = vec![0x03];

        let packet = CoapRequestBuilder::query(102, &token, &routing_id, None, None, true);

        // No URI-Query options
        assert!(packet.get_option(CoapOption::UriQuery).is_none());
    }

    // ---- CoapRequestBuilder: DELETE ----

    #[test]
    fn delete_builds_correct_packet() {
        let routing_id = [0xEE; 32];
        let blob_id = [0xFF; 32];
        let token = vec![0x04];

        let packet = CoapRequestBuilder::delete(200, &token, &routing_id, &blob_id);

        assert_eq!(packet.header.get_type(), MessageType::Confirmable);
        assert_eq!(
            packet.header.code,
            MessageClass::Request(RequestType::Delete)
        );

        // URI-Path: "scp", hex(routing_id), hex(blob_id)
        let paths: Vec<Vec<u8>> = packet
            .get_option(CoapOption::UriPath)
            .unwrap()
            .iter()
            .cloned()
            .collect();
        assert_eq!(paths.len(), 3);
        assert_eq!(paths[0], b"scp");
        assert_eq!(paths[1], hex::encode(routing_id).into_bytes());
        assert_eq!(paths[2], hex::encode(blob_id).into_bytes());
    }

    // ---- CoapRequestBuilder: Observe ----

    #[test]
    fn observe_builds_correct_packet() {
        let routing_id = [0x11; 32];
        let token = vec![0x05, 0x06];

        let packet = CoapRequestBuilder::observe(300, &token, &routing_id);

        assert_eq!(packet.header.get_type(), MessageType::Confirmable);
        assert_eq!(packet.header.code, MessageClass::Request(RequestType::Get));

        // Observe option: Register (0)
        let observe: Vec<Vec<u8>> = packet
            .get_option(CoapOption::Observe)
            .unwrap()
            .iter()
            .cloned()
            .collect();
        assert_eq!(observe.len(), 1);
        assert_eq!(observe[0], vec![0]);

        // Accept: application/msgpack
        let accept: Vec<Vec<u8>> = packet
            .get_option(CoapOption::Accept)
            .unwrap()
            .iter()
            .cloned()
            .collect();
        assert_eq!(accept.len(), 1);
        assert_eq!(accept[0], vec![112]);
    }

    #[test]
    fn observe_deregister_builds_reset() {
        let token = vec![0x07];
        let packet = CoapRequestBuilder::observe_deregister(301, &token);

        assert_eq!(packet.header.get_type(), MessageType::Reset);
        assert_eq!(packet.header.code, MessageClass::Empty);
        assert_eq!(packet.get_token(), &token);
    }

    // ---- CoapResponseParser ----

    #[test]
    fn parse_valid_packet() {
        let mut packet = Packet::new();
        packet.header.set_version(1);
        packet.header.message_id = 42;
        packet.header.set_type(MessageType::Acknowledgement);
        packet.header.code = MessageClass::Response(ResponseType::Content);
        let raw = packet.to_bytes().unwrap();

        let parsed = CoapResponseParser::parse(&raw).unwrap();
        assert_eq!(parsed.header.message_id, 42);
    }

    #[test]
    fn parse_invalid_packet() {
        let result = CoapResponseParser::parse(&[0xFF]);
        assert!(result.is_err());
    }

    #[test]
    fn is_success_for_2xx_codes() {
        let success_codes = [
            ResponseType::Created,
            ResponseType::Deleted,
            ResponseType::Valid,
            ResponseType::Changed,
            ResponseType::Content,
        ];
        for code in &success_codes {
            let mut packet = Packet::new();
            packet.header.code = MessageClass::Response(*code);
            assert!(
                CoapResponseParser::is_success(&packet),
                "expected success for {code:?}"
            );
        }
    }

    #[test]
    fn is_not_success_for_error_codes() {
        let mut packet = Packet::new();
        packet.header.code = MessageClass::Response(ResponseType::NotFound);
        assert!(!CoapResponseParser::is_success(&packet));
    }

    #[test]
    fn observe_sequence_extraction() {
        let mut packet = Packet::new();
        packet.header.code = MessageClass::Response(ResponseType::Content);
        packet.add_option(CoapOption::Observe, vec![0, 5]); // sequence 5

        assert_eq!(CoapResponseParser::observe_sequence(&packet), Some(5));
    }

    #[test]
    fn observe_notification_detection() {
        let mut with_observe = Packet::new();
        with_observe.add_option(CoapOption::Observe, vec![1]);
        assert!(CoapResponseParser::is_observe_notification(&with_observe));

        let without_observe = Packet::new();
        assert!(!CoapResponseParser::is_observe_notification(
            &without_observe
        ));
    }

    #[test]
    fn content_format_extraction() {
        let mut packet = Packet::new();
        packet.add_option(CoapOption::ContentFormat, vec![112]);
        assert_eq!(CoapResponseParser::content_format(&packet), Some(112));
    }

    #[test]
    fn validate_content_format_success() {
        let mut packet = Packet::new();
        packet.add_option(CoapOption::ContentFormat, vec![112]);
        assert!(CoapResponseParser::validate_content_format(&packet).is_ok());
    }

    #[test]
    fn validate_content_format_wrong() {
        let mut packet = Packet::new();
        packet.add_option(CoapOption::ContentFormat, vec![0]); // text/plain
        let result = CoapResponseParser::validate_content_format(&packet);
        assert!(result.is_err());
        match result.unwrap_err() {
            TransportError::ProtocolError(msg) => {
                assert!(msg.contains("112"));
            }
            other => panic!("expected ProtocolError, got: {other:?}"),
        }
    }

    #[test]
    fn validate_content_format_absent_ok() {
        let packet = Packet::new();
        assert!(CoapResponseParser::validate_content_format(&packet).is_ok());
    }

    #[test]
    fn error_description_with_payload() {
        let mut packet = Packet::new();
        packet.header.code = MessageClass::Response(ResponseType::NotFound);
        packet.payload = b"resource not found".to_vec();
        let desc = CoapResponseParser::error_description(&packet);
        assert!(desc.contains("NotFound"));
        assert!(desc.contains("resource not found"));
    }

    #[test]
    fn error_description_empty_payload() {
        let mut packet = Packet::new();
        packet.header.code = MessageClass::Response(ResponseType::InternalServerError);
        let desc = CoapResponseParser::error_description(&packet);
        assert!(desc.contains("InternalServerError"));
    }

    // ---- BlockOption tests ----

    #[test]
    fn block_option_decode_empty() {
        let block = BlockOption::decode(&[]);
        assert_eq!(block.num, 0);
        assert!(!block.more);
        assert_eq!(block.szx, 0);
    }

    #[test]
    fn block_option_decode_single_byte() {
        // Block 0, more=true, SZX=2 (64 bytes) -> 0b0000_1010 = 0x0A
        let block = BlockOption::decode(&[0x0A]);
        assert_eq!(block.num, 0);
        assert!(block.more);
        assert_eq!(block.szx, 2);
        assert_eq!(block.block_size(), 64); // 2^(2+4) = 64
    }

    #[test]
    fn block_option_decode_multi_byte() {
        // Block 1, more=false, SZX=6 (1024 bytes) -> val = (1<<4) | 6 = 0x16
        let block = BlockOption::decode(&[0x16]);
        assert_eq!(block.num, 1);
        assert!(!block.more);
        assert_eq!(block.szx, 6);
        assert_eq!(block.block_size(), 1024); // 2^(6+4) = 1024
    }

    #[test]
    fn block_option_encode_roundtrip() {
        let original = BlockOption {
            num: 3,
            more: true,
            szx: 5,
        };
        let encoded = original.encode();
        let decoded = BlockOption::decode(&encoded);
        assert_eq!(original, decoded);
    }

    #[test]
    fn block_size_calculations() {
        // SZX=0 -> 16 bytes, SZX=1 -> 32, SZX=2 -> 64, ..., SZX=6 -> 1024
        assert_eq!(
            BlockOption {
                num: 0,
                more: false,
                szx: 0
            }
            .block_size(),
            16
        );
        assert_eq!(
            BlockOption {
                num: 0,
                more: false,
                szx: 1
            }
            .block_size(),
            32
        );
        assert_eq!(
            BlockOption {
                num: 0,
                more: false,
                szx: 2
            }
            .block_size(),
            64
        );
        assert_eq!(
            BlockOption {
                num: 0,
                more: false,
                szx: 3
            }
            .block_size(),
            128
        );
        assert_eq!(
            BlockOption {
                num: 0,
                more: false,
                szx: 4
            }
            .block_size(),
            256
        );
        assert_eq!(
            BlockOption {
                num: 0,
                more: false,
                szx: 5
            }
            .block_size(),
            512
        );
        assert_eq!(
            BlockOption {
                num: 0,
                more: false,
                szx: 6
            }
            .block_size(),
            1024
        );
    }

    // ---- Serialization roundtrip ----

    #[test]
    fn publish_packet_serializes_and_deserializes() {
        let routing_id = [0x42; 32];
        let blob = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let token = vec![0x01, 0x02, 0x03, 0x04];

        let packet = CoapRequestBuilder::publish(1000, &token, &routing_id, &blob);
        let bytes = packet.to_bytes().unwrap();
        let parsed = CoapResponseParser::parse(&bytes).unwrap();

        assert_eq!(parsed.header.message_id, 1000);
        assert_eq!(parsed.get_token(), &token);
        assert_eq!(parsed.payload, blob);
    }

    #[test]
    fn query_packet_serializes_and_deserializes() {
        let routing_id = [0x55; 32];
        let token = vec![0x10];

        let packet =
            CoapRequestBuilder::query(2000, &token, &routing_id, Some(500), Some(20), true);
        let bytes = packet.to_bytes().unwrap();
        let parsed = CoapResponseParser::parse(&bytes).unwrap();

        assert_eq!(parsed.header.message_id, 2000);
        assert_eq!(parsed.header.code, MessageClass::Request(RequestType::Get));
    }

    #[test]
    fn delete_packet_serializes_and_deserializes() {
        let routing_id = [0x77; 32];
        let blob_id = [0x88; 32];
        let token = vec![0x20];

        let packet = CoapRequestBuilder::delete(3000, &token, &routing_id, &blob_id);
        let bytes = packet.to_bytes().unwrap();
        let parsed = CoapResponseParser::parse(&bytes).unwrap();

        assert_eq!(parsed.header.message_id, 3000);
        assert_eq!(
            parsed.header.code,
            MessageClass::Request(RequestType::Delete)
        );
    }

    #[test]
    fn observe_packet_serializes_and_deserializes() {
        let routing_id = [0x99; 32];
        let token = vec![0x30, 0x31];

        let packet = CoapRequestBuilder::observe(4000, &token, &routing_id);
        let bytes = packet.to_bytes().unwrap();
        let parsed = CoapResponseParser::parse(&bytes).unwrap();

        assert_eq!(parsed.header.message_id, 4000);
        // Should have Observe option
        assert!(parsed.get_option(CoapOption::Observe).is_some());
    }
}
