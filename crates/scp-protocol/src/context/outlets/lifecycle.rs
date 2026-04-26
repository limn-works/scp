//! Tool invocation lifecycle types: request, status, cancellation.
//!
//! Every tool invocation is a stream by construction (§5.4.5). The legacy
//! non-streaming response type (`OutletResponse`) was deleted by SCP-OUT-032
//! and is replaced by the §5.4.5 wire types in [`super::stream`]:
//! `OutletStreamOpen` / `OutletStreamChunk` / `OutletStreamCredit` /
//! `ChunkPayload`. The §5.4.4 typed `OutletError` envelope
//! ([`super::errors::OutletError`]) replaces the legacy
//! `OutletExecutionError` / `OutletErrorCode` shape.
//!
//! See ADR-049 §5 (streaming-native invocation) and §4 (typed error
//! envelope).
//!
//! # Types
//!
//! - [`OutletRequest`] -- A tool invocation request sent as an MLS application
//!   message.
//! - [`OutletStatus`] -- The four terminal statuses of a tool invocation.
//! - [`OutletCancel`] -- Cancellation request referencing a pending invocation.

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
// OutletRequest
// ---------------------------------------------------------------------------

/// A tool invocation request, sent as an MLS application message.
///
/// Contains all metadata needed to dispatch a tool invocation including
/// caller-specified timeout, optional session context, and cross-context
/// chain depth.
///
/// See ADR-010 acceptance criterion 2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutletRequest {
    /// UUID v4, unique per invocation.
    pub request_id: String,
    /// The tool to invoke.
    pub outlet_id: String,
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

impl OutletRequest {
    /// Creates a new `OutletRequest` with the given parameters and a generated
    /// UUID v4 request ID.
    ///
    /// Uses [`DEFAULT_TIMEOUT_MS`] as the default timeout and 0 as the default
    /// chain depth.
    pub fn new(
        outlet_id: String,
        invoker_did: DID,
        input: serde_json::Value,
        clock: &dyn Clock,
    ) -> Self {
        Self {
            request_id: uuid::Uuid::new_v4().to_string(),
            outlet_id,
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
// OutletStatus
// ---------------------------------------------------------------------------

/// Terminal status of a tool invocation.
///
/// See ADR-010 acceptance criterion 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutletStatus {
    /// Tool executed successfully and produced output.
    Success,
    /// Tool execution failed with an error.
    Error,
    /// Tool execution timed out before producing a response.
    Timeout,
    /// Tool execution was cancelled by the invoker.
    Cancelled,
}

impl std::fmt::Display for OutletStatus {
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
// OutletCancel
// ---------------------------------------------------------------------------

/// Cancellation request for a pending tool invocation.
///
/// The invoker MAY send a `OutletCancel` referencing the `request_id` of a
/// pending invocation. Cancellation is best-effort: if the tool responds
/// with [`OutletStatus::Success`] before the cancel is processed, the success
/// response takes precedence.
///
/// See ADR-010 cancellation protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutletCancel {
    /// The request ID of the invocation to cancel.
    pub request_id: String,
    /// The DID of the invoker requesting cancellation.
    pub invoker_did: DID,
    /// Unix timestamp (milliseconds since epoch) when the cancel was issued.
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// OutletInvokedEvent (event log integration)
// ---------------------------------------------------------------------------

/// Event payload for a `ToolInvoked` event in the context event log.
///
/// Records tool invocation metadata without full input/output (which may be
/// large). Only content hashes are stored. See ADR-010 event log recording.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutletInvokedEvent {
    /// The request ID of the invocation.
    pub request_id: String,
    /// The tool that was invoked.
    pub outlet_id: String,
    /// The DID of the invoker.
    pub invoker_did: DID,
    /// Terminal status of the invocation.
    pub status: OutletStatus,
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
        let request = OutletRequest::new(
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
        let mut request = OutletRequest::new(
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
        let mut request = OutletRequest::new(
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
        let mut request = OutletRequest::new(
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
        assert_eq!(format!("{}", OutletStatus::Success), "Success");
        assert_eq!(format!("{}", OutletStatus::Error), "Error");
        assert_eq!(format!("{}", OutletStatus::Timeout), "Timeout");
        assert_eq!(format!("{}", OutletStatus::Cancelled), "Cancelled");
    }

    #[test]
    fn tool_status_serialization_roundtrip() {
        for status in [
            OutletStatus::Success,
            OutletStatus::Error,
            OutletStatus::Timeout,
            OutletStatus::Cancelled,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let deserialized: OutletStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, deserialized);
        }
    }

    #[test]
    fn tool_request_serialization_roundtrip() {
        let request = OutletRequest {
            request_id: "abc-123".to_owned(),
            outlet_id: "tool-1".to_owned(),
            invoker_did: "did:dht:z6MkInvoker".into(),
            input: serde_json::json!({"a": 1}),
            timeout_ms: 5_000,
            session_id: Some("sess-1".to_owned()),
            chain_depth: 2,
            timestamp: 1_000_000,
        };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: OutletRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.request_id, "abc-123");
        assert_eq!(deserialized.outlet_id, "tool-1");
        assert_eq!(deserialized.timeout_ms, 5_000);
        assert_eq!(deserialized.chain_depth, 2);
        assert_eq!(deserialized.session_id.as_deref(), Some("sess-1"));
    }

    #[test]
    fn tool_cancel_serialization_roundtrip() {
        let cancel = OutletCancel {
            request_id: "req-1".to_owned(),
            invoker_did: "did:dht:z6MkInvoker".into(),
            timestamp: 999,
        };
        let json = serde_json::to_string(&cancel).unwrap();
        let deserialized: OutletCancel = serde_json::from_str(&json).unwrap();
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
    fn tool_invoked_event_serialization_roundtrip() {
        let event = OutletInvokedEvent {
            request_id: "req-1".to_owned(),
            outlet_id: "tool-1".to_owned(),
            invoker_did: "did:dht:z6MkInvoker".into(),
            status: OutletStatus::Success,
            execution_time_ms: 42,
            input_hash: "abcd".to_owned(),
            output_hash: Some("efgh".to_owned()),
            cost: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: OutletInvokedEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.request_id, "req-1");
        assert_eq!(deserialized.status, OutletStatus::Success);
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
