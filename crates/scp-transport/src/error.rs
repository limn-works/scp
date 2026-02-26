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
}
