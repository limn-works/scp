//! Tool invocation lifecycle types: request, response, cancellation, and status.
//!
//! Every tool invocation follows a defined lifecycle with explicit states,
//! timeouts, and error handling. Tool execution errors are returned in
//! [`ToolResponse::error`], not as protocol-level errors. Schema validation
//! failures are caught by the SDK, not the tool.
//!
//! See ADR-010 in `.docs/adrs/phase-2.md` for the full design.
//!
//! # Types
//!
//! - [`ToolRequest`] -- A tool invocation request sent as an MLS application
//!   message.
//! - [`ToolResponse`] -- A tool invocation response.
//! - [`ToolStatus`] -- The four terminal statuses of a tool invocation.
//! - [`ToolExecutionError`] -- Structured execution error with retryable hint.
//! - [`ToolErrorCode`] -- Error code enum covering all tool error categories.
//! - [`ToolCancel`] -- Cancellation request referencing a pending invocation.

use serde::{Deserialize, Serialize};

use scp_primitives::Clock;

use crate::economy::types::Amount;
use crate::provenance::DataProvenance;
use scp_primitives::DID;

/// Type alias for tool invocation provenance.
///
/// Uses the existing [`DataProvenance`] from the provenance module to carry
/// verifiable origin metadata on every tool response. See protocol tenet 1:
/// "Provenance everywhere."
pub type Provenance = DataProvenance;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default timeout for tool invocations in milliseconds (30 seconds).
pub const DEFAULT_TIMEOUT_MS: u32 = 30_000;

/// Hard protocol maximum timeout in milliseconds (5 minutes / 300 seconds).
pub const MAX_TIMEOUT_MS: u32 = 300_000;

// ---------------------------------------------------------------------------
// ToolRequest
// ---------------------------------------------------------------------------

/// A tool invocation request, sent as an MLS application message.
///
/// Contains all metadata needed to dispatch a tool invocation including
/// caller-specified timeout, optional session context, and cross-context
/// chain depth.
///
/// See ADR-010 acceptance criterion 2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRequest {
    /// UUID v4, unique per invocation.
    pub request_id: String,
    /// The tool to invoke.
    pub tool_id: String,
    /// The DID of the invoker.
    pub invoker_did: DID,
    /// The input to pass to the tool.
    pub input: serde_json::Value,
    /// Caller-specified timeout in milliseconds.
    ///
    /// Default: [`DEFAULT_TIMEOUT_MS`] (30,000ms).
    /// Maximum: configurable per-context, hard protocol maximum
    /// [`MAX_TIMEOUT_MS`] (300,000ms / 5 minutes).
    pub timeout_ms: u32,
    /// Optional session ID for stateful tool sessions (spec section 6.2.1).
    pub session_id: Option<String>,
    /// Cross-context chain depth (0 for direct calls).
    pub chain_depth: u8,
    /// Unix timestamp (milliseconds since epoch) when the request was created.
    pub timestamp: u64,
}

impl ToolRequest {
    /// Creates a new `ToolRequest` with the given parameters and a generated
    /// UUID v4 request ID.
    ///
    /// Uses [`DEFAULT_TIMEOUT_MS`] as the default timeout and 0 as the default
    /// chain depth.
    pub fn new(
        tool_id: String,
        invoker_did: DID,
        input: serde_json::Value,
        clock: &dyn Clock,
    ) -> Self {
        Self {
            request_id: uuid::Uuid::new_v4().to_string(),
            tool_id,
            invoker_did,
            input,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            session_id: None,
            chain_depth: 0,
            timestamp: clock.now_millis(),
        }
    }

    /// Clamps the timeout to the given context maximum, respecting the hard
    /// protocol maximum ([`MAX_TIMEOUT_MS`]).
    ///
    /// If `context_max_ms` exceeds the protocol maximum, the protocol maximum
    /// is used. If the request's `timeout_ms` exceeds the effective maximum,
    /// it is clamped down.
    pub fn clamp_timeout(&mut self, context_max_ms: u32) {
        let effective_max = context_max_ms.min(MAX_TIMEOUT_MS);
        self.timeout_ms = self.timeout_ms.min(effective_max);
    }
}

// ---------------------------------------------------------------------------
// ToolResponse
// ---------------------------------------------------------------------------

/// A tool invocation response, sent as an MLS application message.
///
/// Contains the invocation result, timing information, and provenance metadata.
/// Tool execution errors are returned in the [`error`](Self::error) field, not
/// as protocol-level errors.
///
/// See ADR-010 acceptance criterion 3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResponse {
    /// Matches the [`ToolRequest::request_id`].
    pub request_id: String,
    /// Terminal status of the invocation.
    pub status: ToolStatus,
    /// The tool's output, present on [`ToolStatus::Success`].
    pub output: Option<serde_json::Value>,
    /// Structured error, present on non-success statuses.
    pub error: Option<ToolExecutionError>,
    /// Wall-clock execution time in milliseconds.
    pub execution_time_ms: u64,
    /// Provenance metadata for this response.
    pub provenance: Provenance,
}

// ---------------------------------------------------------------------------
// ToolStatus
// ---------------------------------------------------------------------------

/// Terminal status of a tool invocation.
///
/// See ADR-010 acceptance criterion 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolStatus {
    /// Tool executed successfully and produced output.
    Success,
    /// Tool execution failed with an error.
    Error,
    /// Tool execution timed out before producing a response.
    Timeout,
    /// Tool execution was cancelled by the invoker.
    Cancelled,
}

impl std::fmt::Display for ToolStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => write!(f, "Success"),
            Self::Error => write!(f, "Error"),
            Self::Timeout => write!(f, "Timeout"),
            Self::Cancelled => write!(f, "Cancelled"),
        }
    }
}

// ---------------------------------------------------------------------------
// ToolExecutionError
// ---------------------------------------------------------------------------

/// Structured tool execution error.
///
/// Returned in [`ToolResponse::error`] for non-success invocations. The
/// [`retryable`](Self::retryable) field indicates whether the caller should
/// attempt the invocation again.
///
/// See ADR-010 acceptance criterion 5.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolExecutionError {
    /// Categorized error code.
    pub code: ToolErrorCode,
    /// Human-readable error description.
    pub message: String,
    /// Whether the caller should retry the invocation.
    pub retryable: bool,
}

// ---------------------------------------------------------------------------
// ToolErrorCode
// ---------------------------------------------------------------------------

/// Categorized error codes for tool invocation failures.
///
/// Covers the full range of failure modes from validation through execution.
///
/// See ADR-010 acceptance criterion 6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolErrorCode {
    /// Input did not pass the tool's input schema validation.
    InputValidationFailed,
    /// Output did not pass the tool's output schema validation.
    OutputValidationFailed,
    /// Tool execution failed with an internal error.
    ExecutionFailed,
    /// Tool execution timed out.
    Timeout,
    /// Tool execution was cancelled.
    Cancelled,
    /// Invocation was rejected due to rate limiting.
    RateLimited,
    /// The requested tool was not found in the registry.
    ToolNotFound,
    /// The invoker does not have the required capability.
    PermissionDenied,
    /// An unexpected internal error occurred.
    InternalError,
}

impl std::fmt::Display for ToolErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InputValidationFailed => write!(f, "InputValidationFailed"),
            Self::OutputValidationFailed => write!(f, "OutputValidationFailed"),
            Self::ExecutionFailed => write!(f, "ExecutionFailed"),
            Self::Timeout => write!(f, "Timeout"),
            Self::Cancelled => write!(f, "Cancelled"),
            Self::RateLimited => write!(f, "RateLimited"),
            Self::ToolNotFound => write!(f, "ToolNotFound"),
            Self::PermissionDenied => write!(f, "PermissionDenied"),
            Self::InternalError => write!(f, "InternalError"),
        }
    }
}

// ---------------------------------------------------------------------------
// ToolCancel
// ---------------------------------------------------------------------------

/// Cancellation request for a pending tool invocation.
///
/// The invoker MAY send a `ToolCancel` referencing the `request_id` of a
/// pending invocation. Cancellation is best-effort: if the tool responds
/// with [`ToolStatus::Success`] before the cancel is processed, the success
/// response takes precedence.
///
/// See ADR-010 cancellation protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCancel {
    /// The request ID of the invocation to cancel.
    pub request_id: String,
    /// The DID of the invoker requesting cancellation.
    pub invoker_did: DID,
    /// Unix timestamp (milliseconds since epoch) when the cancel was issued.
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// ToolInvokedEvent (event log integration)
// ---------------------------------------------------------------------------

/// Event payload for a `ToolInvoked` event in the context event log.
///
/// Records tool invocation metadata without full input/output (which may be
/// large). Only content hashes are stored. See ADR-010 event log recording.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInvokedEvent {
    /// The request ID of the invocation.
    pub request_id: String,
    /// The tool that was invoked.
    pub tool_id: String,
    /// The DID of the invoker.
    pub invoker_did: DID,
    /// Terminal status of the invocation.
    pub status: ToolStatus,
    /// Wall-clock execution time in milliseconds.
    pub execution_time_ms: u64,
    /// SHA-256 hash of the input (hex-encoded).
    pub input_hash: String,
    /// SHA-256 hash of the output (hex-encoded), if output was produced.
    pub output_hash: Option<String>,
    /// Cost attributed to this invocation (§19.3). `None` for free contexts
    /// or tools without per-invocation cost. Value is in the context's
    /// economic policy currency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<Amount>,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Computes a SHA-256 hash of a JSON value's RFC 8785 (JCS) canonical
/// representation.
///
/// The value is serialized to a JCS-canonical JSON string, then hashed with
/// SHA-256. Returns the hash as a lowercase hex string.
#[must_use]
pub fn sha256_json(value: &serde_json::Value) -> String {
    use sha2::{Digest, Sha256};

    // RFC 8785 JCS canonical serialization for cross-implementation
    // deterministic hashing. Falls back to empty string on error (should
    // not happen for valid JSON).
    let bytes = crate::jcs::to_string(value).unwrap_or_default();
    let hash = Sha256::digest(bytes.as_bytes());
    hex::encode(hash)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn tool_request_new_generates_uuid_v4() {
        let request = ToolRequest::new(
            "tool-1".to_owned(),
            "did:dht:z6MkInvoker".into(),
            serde_json::json!({"x": 1}),
            &scp_primitives::SystemClock,
        );
        // UUID v4 format: 8-4-4-4-12 hex digits.
        assert_eq!(request.request_id.len(), 36);
        assert!(request.request_id.contains('-'));
        assert_eq!(request.timeout_ms, DEFAULT_TIMEOUT_MS);
        assert_eq!(request.chain_depth, 0);
        assert!(request.session_id.is_none());
        assert!(request.timestamp > 0);
    }

    #[test]
    fn tool_request_clamp_timeout_below_context_max() {
        let mut request = ToolRequest::new(
            "tool-1".to_owned(),
            "did:dht:z6MkInvoker".into(),
            serde_json::json!({}),
            &scp_primitives::SystemClock,
        );
        request.timeout_ms = 10_000;
        request.clamp_timeout(60_000);
        assert_eq!(request.timeout_ms, 10_000);
    }

    #[test]
    fn tool_request_clamp_timeout_above_context_max() {
        let mut request = ToolRequest::new(
            "tool-1".to_owned(),
            "did:dht:z6MkInvoker".into(),
            serde_json::json!({}),
            &scp_primitives::SystemClock,
        );
        request.timeout_ms = 120_000;
        request.clamp_timeout(60_000);
        assert_eq!(request.timeout_ms, 60_000);
    }

    #[test]
    fn tool_request_clamp_timeout_respects_protocol_maximum() {
        let mut request = ToolRequest::new(
            "tool-1".to_owned(),
            "did:dht:z6MkInvoker".into(),
            serde_json::json!({}),
            &scp_primitives::SystemClock,
        );
        request.timeout_ms = 600_000;
        // Context max is above protocol max -- should clamp to protocol max.
        request.clamp_timeout(999_999);
        assert_eq!(request.timeout_ms, MAX_TIMEOUT_MS);
    }

    #[test]
    fn tool_status_display() {
        assert_eq!(format!("{}", ToolStatus::Success), "Success");
        assert_eq!(format!("{}", ToolStatus::Error), "Error");
        assert_eq!(format!("{}", ToolStatus::Timeout), "Timeout");
        assert_eq!(format!("{}", ToolStatus::Cancelled), "Cancelled");
    }

    #[test]
    fn tool_error_code_display() {
        assert_eq!(
            format!("{}", ToolErrorCode::InputValidationFailed),
            "InputValidationFailed"
        );
        assert_eq!(
            format!("{}", ToolErrorCode::PermissionDenied),
            "PermissionDenied"
        );
        assert_eq!(format!("{}", ToolErrorCode::Timeout), "Timeout");
    }

    #[test]
    fn tool_status_serialization_roundtrip() {
        for status in [
            ToolStatus::Success,
            ToolStatus::Error,
            ToolStatus::Timeout,
            ToolStatus::Cancelled,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let deserialized: ToolStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, deserialized);
        }
    }

    #[test]
    fn tool_error_code_serialization_roundtrip() {
        let codes = [
            ToolErrorCode::InputValidationFailed,
            ToolErrorCode::OutputValidationFailed,
            ToolErrorCode::ExecutionFailed,
            ToolErrorCode::Timeout,
            ToolErrorCode::Cancelled,
            ToolErrorCode::RateLimited,
            ToolErrorCode::ToolNotFound,
            ToolErrorCode::PermissionDenied,
            ToolErrorCode::InternalError,
        ];
        for code in codes {
            let json = serde_json::to_string(&code).unwrap();
            let deserialized: ToolErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(code, deserialized);
        }
    }

    #[test]
    fn tool_request_serialization_roundtrip() {
        let request = ToolRequest {
            request_id: "abc-123".to_owned(),
            tool_id: "tool-1".to_owned(),
            invoker_did: "did:dht:z6MkInvoker".into(),
            input: serde_json::json!({"a": 1}),
            timeout_ms: 5_000,
            session_id: Some("sess-1".to_owned()),
            chain_depth: 2,
            timestamp: 1_000_000,
        };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: ToolRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.request_id, "abc-123");
        assert_eq!(deserialized.tool_id, "tool-1");
        assert_eq!(deserialized.timeout_ms, 5_000);
        assert_eq!(deserialized.chain_depth, 2);
        assert_eq!(deserialized.session_id.as_deref(), Some("sess-1"));
    }

    #[test]
    fn tool_cancel_serialization_roundtrip() {
        let cancel = ToolCancel {
            request_id: "req-1".to_owned(),
            invoker_did: "did:dht:z6MkInvoker".into(),
            timestamp: 999,
        };
        let json = serde_json::to_string(&cancel).unwrap();
        let deserialized: ToolCancel = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.request_id, "req-1");
        assert_eq!(deserialized.invoker_did, "did:dht:z6MkInvoker");
        assert_eq!(deserialized.timestamp, 999);
    }

    #[test]
    fn sha256_json_produces_64_char_hex() {
        let value = serde_json::json!({"hello": "world"});
        let hash = sha256_json(&value);
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sha256_json_deterministic() {
        let value = serde_json::json!({"a": 1, "b": 2});
        let hash1 = sha256_json(&value);
        let hash2 = sha256_json(&value);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn sha256_json_different_inputs_produce_different_hashes() {
        let hash1 = sha256_json(&serde_json::json!({"a": 1}));
        let hash2 = sha256_json(&serde_json::json!({"a": 2}));
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn tool_execution_error_serialization_roundtrip() {
        let error = ToolExecutionError {
            code: ToolErrorCode::ExecutionFailed,
            message: "something broke".to_owned(),
            retryable: true,
        };
        let json = serde_json::to_string(&error).unwrap();
        let deserialized: ToolExecutionError = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.code, ToolErrorCode::ExecutionFailed);
        assert_eq!(deserialized.message, "something broke");
        assert!(deserialized.retryable);
    }

    #[test]
    fn tool_invoked_event_serialization_roundtrip() {
        let event = ToolInvokedEvent {
            request_id: "req-1".to_owned(),
            tool_id: "tool-1".to_owned(),
            invoker_did: "did:dht:z6MkInvoker".into(),
            status: ToolStatus::Success,
            execution_time_ms: 42,
            input_hash: "abcd".to_owned(),
            output_hash: Some("efgh".to_owned()),
            cost: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: ToolInvokedEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.request_id, "req-1");
        assert_eq!(deserialized.status, ToolStatus::Success);
        assert_eq!(deserialized.execution_time_ms, 42);
    }

    #[test]
    fn default_timeout_is_30_seconds() {
        assert_eq!(DEFAULT_TIMEOUT_MS, 30_000);
    }

    #[test]
    fn max_timeout_is_5_minutes() {
        assert_eq!(MAX_TIMEOUT_MS, 300_000);
    }
}
