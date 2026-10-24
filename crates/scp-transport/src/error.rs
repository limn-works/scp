//! Transport-level error types.
//!
//! [`TransportError`] covers all failure modes that transport adapters can
//! encounter: connection failures, send failures, subscription errors,
//! disconnection, timeouts, and protocol-level errors.
//!
//! See ADR-005 in `.docs/adrs/phase-1.md` for the transport abstraction design.

/// Transport-level errors returned by [`TransportAdapter`](crate::TransportAdapter) methods.
///
/// Each variant represents a distinct failure mode. Adapters map their
/// transport-specific errors into these variants so that callers get a
/// uniform error surface regardless of the underlying transport.
#[derive(Debug, Clone, thiserror::Error)]
pub enum TransportError {
    /// The adapter could not establish or maintain a connection to the
    /// remote transport endpoint.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    /// Sending an envelope failed after the connection was established.
    #[error("send failed: {0}")]
    SendFailed(String),

    /// The relay answered a request with `ERR` (ADR-004). `code` is the
    /// relay's error code, kept as a number so a caller can act on it: a
    /// `4xxx` code means the same request will fail again, and a `5xxx` code
    /// means a retry or another relay may succeed (ADR-004 client rules).
    /// `msg` is the relay's text after
    /// [`sanitize_relay_text`](scp_relay_client::sanitize_relay_text), because
    /// the relay is untrusted and chooses it.
    #[error("relay error {code}: {msg}")]
    RelayRejected {
        /// The relay's ADR-004 error code.
        code: u16,
        /// The relay's error text, sanitized.
        msg: String,
    },

    /// A subscription request could not be fulfilled.
    #[error("subscription failed: {0}")]
    SubscriptionFailed(String),

    /// The adapter is not currently connected to the transport.
    #[error("not connected")]
    NotConnected,

    /// An operation timed out before completing.
    #[error("timeout")]
    Timeout,

    /// A protocol-level error occurred (e.g., unexpected message format,
    /// version mismatch).
    #[error("protocol error: {0}")]
    ProtocolError(String),

    /// A received blob's content does not match its declared `blob_id`.
    ///
    /// The relay provided a `blob_id` (SHA-256 hash) that does not match
    /// `SHA-256(blob)`. This indicates a malicious or buggy relay returning
    /// mismatched content.
    #[error("blob integrity error: expected {expected}, got {actual}")]
    BlobIntegrityError {
        /// The `blob_id` declared by the relay (hex-encoded).
        expected: String,
        /// The SHA-256 hash of the actual blob content (hex-encoded).
        actual: String,
    },

    /// The requested operation is not supported by this transport adapter.
    ///
    /// Some adapters do not support all five `TransportAdapter` methods.
    /// For example, UDP/DTLS (section 10.16.1) cannot maintain long-lived
    /// subscription streams — callers should poll via `query()` instead.
    ///
    /// See SCP-261 and spec section 10.16.1 point 6.
    #[error("not supported: {0}")]
    NotSupported(String),

    /// A received or reassembled payload exceeds the adapter's configured
    /// maximum size.
    ///
    /// This protects constrained devices from memory exhaustion during
    /// operations like CoAP block-wise reassembly (RFC 7959) where a
    /// malicious or misconfigured server could send arbitrarily large
    /// payloads.
    #[error("payload too large: {0}")]
    PayloadTooLarge(String),

    /// A blob the relay delivered is not one ADR-002 outer envelope over a
    /// non-empty payload (`scp_protocol::envelope::MalformedFrame`), refused
    /// before any MLS work. Held in an `Arc` because `TransportError` is
    /// `Clone` and the frame error is not. The message names no detail of the
    /// blob, which is relay-supplied and which some decoders echo in their
    /// `Display`; the detail stays on the typed `source()`.
    #[error("the relay delivered a malformed frame")]
    MalformedFrame(#[source] std::sync::Arc<scp_core::envelope::MalformedFrame>),
}

impl From<scp_core::envelope::MalformedFrame> for TransportError {
    fn from(e: scp_core::envelope::MalformedFrame) -> Self {
        Self::MalformedFrame(std::sync::Arc::new(e))
    }
}
