//! Protocol-specific error types for the SCP native relay.
//!
//! Defines [`ProtocolErrorCode`] constants covering client errors (4xxx) and
//! server errors (5xxx), plus the [`NativeProtocolError`] type for protocol
//! violations detected during serialization, deserialization, or validation.
//!
//! See ADR-004 in `.docs/adrs/phase-1.md` for the full error code specification.

/// Protocol error codes for the SCP native relay.
///
/// Client errors (4xxx) indicate the request is invalid and MUST NOT be
/// retried as-is. Server errors (5xxx) indicate a transient condition and
/// MAY be retried with exponential backoff or by switching relays.
///
/// Codes are extensible within their ranges. Unknown codes MUST be handled
/// by category (4xxx = do not retry, 5xxx = retry with backoff).
pub mod code {
    // -----------------------------------------------------------------------
    // Client errors (4xxx) -- do not retry same request
    // -----------------------------------------------------------------------

    /// The message could not be parsed (malformed `MessagePack`, missing `op`).
    pub const INVALID_MESSAGE: u16 = 4000;

    /// The `op` field contains an unrecognized operation.
    pub const UNKNOWN_OP: u16 = 4001;

    /// A required field is missing from the message.
    pub const MISSING_FIELD: u16 = 4002;

    /// A field value is invalid (wrong type, out of range, wrong length).
    pub const INVALID_FIELD: u16 = 4003;

    /// The blob exceeds the maximum allowed size (256 KB).
    pub const BLOB_TOO_LARGE: u16 = 4010;

    /// The `blob_ttl` exceeds the maximum allowed value (604800 seconds / 7 days).
    pub const TTL_TOO_LONG: u16 = 4011;

    /// The `limit` in a QUERY exceeds the maximum allowed value (1000).
    pub const LIMIT_EXCEEDED: u16 = 4012;

    /// The client is sending too many requests and has been rate-limited.
    pub const RATE_LIMITED: u16 = 4020;

    /// The client has too many active subscriptions on this connection.
    pub const TOO_MANY_SUBSCRIPTIONS: u16 = 4021;

    /// The relay does not support the BRIDGE operation (section 10.12.4).
    /// The client should try a different relay that has `supports_bridge: true`.
    pub const BRIDGE_NOT_SUPPORTED: u16 = 4030;

    /// The bridge registration limit has been exceeded for this connection.
    pub const BRIDGE_LIMIT_EXCEEDED: u16 = 4031;

    /// The target routing ID is not registered on this bridge relay.
    pub const BRIDGE_TARGET_NOT_FOUND: u16 = 4032;

    /// The relay supports bridge operations but the bridge service is not yet
    /// integrated into the relay server. The client should retry later.
    pub const BRIDGE_NOT_INTEGRATED: u16 = 4033;

    // -----------------------------------------------------------------------
    // Server errors (5xxx) -- retry with backoff or switch relay
    // -----------------------------------------------------------------------

    /// An unexpected internal error occurred on the relay.
    pub const INTERNAL_ERROR: u16 = 5000;

    /// The relay's storage is full and cannot accept new blobs.
    pub const STORAGE_FULL: u16 = 5001;

    /// The relay is shutting down. Clients should reconnect to another relay.
    pub const SHUTTING_DOWN: u16 = 5002;

    /// Returns `true` if the error code indicates a client error (4xxx).
    ///
    /// Client errors mean the request is invalid and MUST NOT be retried as-is.
    #[must_use]
    pub const fn is_client_error(code: u16) -> bool {
        code >= 4000 && code < 5000
    }

    /// Returns `true` if the error code indicates a server error (5xxx).
    ///
    /// Server errors indicate a transient condition and MAY be retried with
    /// exponential backoff or by switching relays.
    #[must_use]
    pub const fn is_server_error(code: u16) -> bool {
        code >= 5000 && code < 6000
    }
}

/// Protocol-level errors for the SCP native relay.
///
/// These errors occur during message validation, serialization, or
/// deserialization -- before or after the message reaches the wire.
#[derive(Debug, Clone, thiserror::Error)]
pub enum NativeProtocolError {
    /// A message failed serialization to `MessagePack`.
    #[error("serialization failed: {0}")]
    SerializationFailed(String),

    /// A message failed deserialization from `MessagePack`.
    #[error("deserialization failed: {0}")]
    DeserializationFailed(String),

    /// A constraint validation failed on a client message.
    #[error("validation failed: {0}")]
    ValidationFailed(String),
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::code;

    #[test]
    fn client_error_codes_are_in_4xxx_range() {
        let client_codes = [
            code::INVALID_MESSAGE,
            code::UNKNOWN_OP,
            code::MISSING_FIELD,
            code::INVALID_FIELD,
            code::BLOB_TOO_LARGE,
            code::TTL_TOO_LONG,
            code::LIMIT_EXCEEDED,
            code::RATE_LIMITED,
            code::TOO_MANY_SUBSCRIPTIONS,
            code::BRIDGE_NOT_SUPPORTED,
            code::BRIDGE_LIMIT_EXCEEDED,
            code::BRIDGE_TARGET_NOT_FOUND,
            code::BRIDGE_NOT_INTEGRATED,
        ];

        for c in client_codes {
            assert!(
                code::is_client_error(c),
                "code {c} should be a client error"
            );
            assert!(
                !code::is_server_error(c),
                "code {c} should not be a server error"
            );
        }
    }

    #[test]
    fn server_error_codes_are_in_5xxx_range() {
        let server_codes = [
            code::INTERNAL_ERROR,
            code::STORAGE_FULL,
            code::SHUTTING_DOWN,
        ];

        for c in server_codes {
            assert!(
                code::is_server_error(c),
                "code {c} should be a server error"
            );
            assert!(
                !code::is_client_error(c),
                "code {c} should not be a client error"
            );
        }
    }

    #[test]
    fn is_client_error_boundaries() {
        assert!(!code::is_client_error(3999));
        assert!(code::is_client_error(4000));
        assert!(code::is_client_error(4999));
        assert!(!code::is_client_error(5000));
    }

    #[test]
    fn is_server_error_boundaries() {
        assert!(!code::is_server_error(4999));
        assert!(code::is_server_error(5000));
        assert!(code::is_server_error(5999));
        assert!(!code::is_server_error(6000));
    }

    #[test]
    fn error_code_constants_match_specification() {
        assert_eq!(code::INVALID_MESSAGE, 4000);
        assert_eq!(code::UNKNOWN_OP, 4001);
        assert_eq!(code::MISSING_FIELD, 4002);
        assert_eq!(code::INVALID_FIELD, 4003);
        assert_eq!(code::BLOB_TOO_LARGE, 4010);
        assert_eq!(code::TTL_TOO_LONG, 4011);
        assert_eq!(code::LIMIT_EXCEEDED, 4012);
        assert_eq!(code::RATE_LIMITED, 4020);
        assert_eq!(code::TOO_MANY_SUBSCRIPTIONS, 4021);
        assert_eq!(code::BRIDGE_NOT_SUPPORTED, 4030);
        assert_eq!(code::BRIDGE_LIMIT_EXCEEDED, 4031);
        assert_eq!(code::BRIDGE_TARGET_NOT_FOUND, 4032);
        assert_eq!(code::BRIDGE_NOT_INTEGRATED, 4033);
        assert_eq!(code::INTERNAL_ERROR, 5000);
        assert_eq!(code::STORAGE_FULL, 5001);
        assert_eq!(code::SHUTTING_DOWN, 5002);
    }

    #[test]
    fn native_protocol_error_display() {
        use super::NativeProtocolError;

        let err = NativeProtocolError::SerializationFailed("bad data".to_string());
        assert_eq!(err.to_string(), "serialization failed: bad data");

        let err = NativeProtocolError::DeserializationFailed("corrupt".to_string());
        assert_eq!(err.to_string(), "deserialization failed: corrupt");

        let err = NativeProtocolError::ValidationFailed("blob too large".to_string());
        assert_eq!(err.to_string(), "validation failed: blob too large");
    }
}
