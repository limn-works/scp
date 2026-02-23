//! Error codes and error types for the SCP native relay protocol.
//!
//! Error codes follow ADR-004: client errors in the 4xxx range, server errors
//! in the 5xxx range. Clients MUST handle unknown codes by category: 4xxx = do
//! not retry, 5xxx = retry with backoff or switch relay.

// ---------------------------------------------------------------------------
// Client error codes (4xxx) -- do not retry the same request
// ---------------------------------------------------------------------------

/// The message could not be parsed (invalid `MessagePack`, missing `op`, etc.).
pub const INVALID_MESSAGE: u16 = 4000;

/// The `op` field contains an unrecognized operation.
pub const UNKNOWN_OP: u16 = 4001;

/// A required field is missing from the message.
pub const MISSING_FIELD: u16 = 4002;

/// A field has an invalid value (wrong type, out of range, etc.).
pub const INVALID_FIELD: u16 = 4003;

/// The blob exceeds the maximum allowed size (262 144 bytes).
pub const BLOB_TOO_LARGE: u16 = 4010;

/// The requested `blob_ttl` exceeds the maximum (604 800 seconds / 7 days).
pub const TTL_TOO_LONG: u16 = 4011;

/// A query `limit` exceeds the relay maximum (default 1 000).
pub const LIMIT_EXCEEDED: u16 = 4012;

/// The client has been rate-limited.
pub const RATE_LIMITED: u16 = 4020;

/// The client has too many active subscriptions on this connection.
pub const TOO_MANY_SUBSCRIPTIONS: u16 = 4021;

// ---------------------------------------------------------------------------
// Server error codes (5xxx) -- retry with backoff or switch relay
// ---------------------------------------------------------------------------

/// An unexpected internal error occurred on the relay.
pub const INTERNAL_ERROR: u16 = 5000;

/// The relay's blob storage is full; try again later or use another relay.
pub const STORAGE_FULL: u16 = 5001;

/// The relay is shutting down; reconnect to a different instance.
pub const SHUTTING_DOWN: u16 = 5002;

/// Classifies an error code into a category for retry decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    /// Client error (4xxx): do not retry the same request.
    Client,
    /// Server error (5xxx): retry with backoff or switch relay.
    Server,
    /// Unrecognized category.
    Unknown,
}

/// Returns the [`ErrorCategory`] for a given numeric error code.
///
/// All codes in the 4000-4999 range are client errors. All codes in the
/// 5000-5999 range are server errors. Everything else is unknown.
#[must_use]
pub const fn error_category(code: u16) -> ErrorCategory {
    match code {
        4000..=4999 => ErrorCategory::Client,
        5000..=5999 => ErrorCategory::Server,
        _ => ErrorCategory::Unknown,
    }
}

/// Protocol-level errors that can occur during message processing.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// `MessagePack` serialization failed.
    #[error("serialization failed: {0}")]
    Serialization(#[from] rmp_serde::encode::Error),

    /// `MessagePack` deserialization failed.
    #[error("deserialization failed: {0}")]
    Deserialization(#[from] rmp_serde::decode::Error),

    /// A binary field has an invalid length (expected 32 bytes).
    #[error("invalid binary field length: expected {expected}, got {actual}")]
    InvalidBinaryLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        actual: usize,
    },

    /// A `blob_ttl` value is out of the allowed range (1..=604800).
    #[error("blob_ttl {value} out of range 1..=604800")]
    BlobTtlOutOfRange {
        /// The invalid TTL value.
        value: u32,
    },

    /// A blob exceeds the maximum allowed size (262 144 bytes).
    #[error("blob size {size} exceeds maximum {max}")]
    BlobTooLarge {
        /// Actual blob size.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// A correlation `ref` string exceeds the maximum length (64 bytes).
    #[error("ref too long: {length} bytes, maximum 64")]
    RefTooLong {
        /// Actual ref length.
        length: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_category_classifies_client_codes() {
        assert_eq!(error_category(INVALID_MESSAGE), ErrorCategory::Client);
        assert_eq!(error_category(UNKNOWN_OP), ErrorCategory::Client);
        assert_eq!(error_category(MISSING_FIELD), ErrorCategory::Client);
        assert_eq!(error_category(INVALID_FIELD), ErrorCategory::Client);
        assert_eq!(error_category(BLOB_TOO_LARGE), ErrorCategory::Client);
        assert_eq!(error_category(TTL_TOO_LONG), ErrorCategory::Client);
        assert_eq!(error_category(LIMIT_EXCEEDED), ErrorCategory::Client);
        assert_eq!(error_category(RATE_LIMITED), ErrorCategory::Client);
        assert_eq!(
            error_category(TOO_MANY_SUBSCRIPTIONS),
            ErrorCategory::Client
        );
    }

    #[test]
    fn error_category_classifies_server_codes() {
        assert_eq!(error_category(INTERNAL_ERROR), ErrorCategory::Server);
        assert_eq!(error_category(STORAGE_FULL), ErrorCategory::Server);
        assert_eq!(error_category(SHUTTING_DOWN), ErrorCategory::Server);
    }

    #[test]
    fn error_category_classifies_unknown_codes() {
        assert_eq!(error_category(0), ErrorCategory::Unknown);
        assert_eq!(error_category(3999), ErrorCategory::Unknown);
        assert_eq!(error_category(6000), ErrorCategory::Unknown);
    }

    #[test]
    fn error_category_handles_boundary_values() {
        assert_eq!(error_category(4000), ErrorCategory::Client);
        assert_eq!(error_category(4999), ErrorCategory::Client);
        assert_eq!(error_category(5000), ErrorCategory::Server);
        assert_eq!(error_category(5999), ErrorCategory::Server);
    }

    #[test]
    fn error_category_handles_unknown_codes_within_ranges() {
        // Future extensibility: unknown codes within valid ranges
        assert_eq!(error_category(4500), ErrorCategory::Client);
        assert_eq!(error_category(5500), ErrorCategory::Server);
    }

    #[test]
    fn error_code_constants_have_correct_values() {
        // Client errors
        assert_eq!(INVALID_MESSAGE, 4000);
        assert_eq!(UNKNOWN_OP, 4001);
        assert_eq!(MISSING_FIELD, 4002);
        assert_eq!(INVALID_FIELD, 4003);
        assert_eq!(BLOB_TOO_LARGE, 4010);
        assert_eq!(TTL_TOO_LONG, 4011);
        assert_eq!(LIMIT_EXCEEDED, 4012);
        assert_eq!(RATE_LIMITED, 4020);
        assert_eq!(TOO_MANY_SUBSCRIPTIONS, 4021);

        // Server errors
        assert_eq!(INTERNAL_ERROR, 5000);
        assert_eq!(STORAGE_FULL, 5001);
        assert_eq!(SHUTTING_DOWN, 5002);
    }
}
