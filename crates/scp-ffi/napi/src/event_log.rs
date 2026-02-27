//! napi-rs bridge for event log operations.
//!
//! Exposes event log queries and Merkle proof verification:
//!
//! - [`event_log_query`] — Query the context event log with optional filters.
//! - [`event_log_verify`] — Verify a claim against the event log (Merkle proof).
//!
//! See ADR-011 (Event Log) and ADR-022 in `.docs/adrs/`.

use napi_derive::napi;

use crate::context::NapiContextHandle;
use crate::error::ScpNapiError;

// ---------------------------------------------------------------------------
// NapiEvent — protocol event record
// ---------------------------------------------------------------------------

/// A protocol event from the context event log.
///
/// See ADR-011 (Event Log) and spec section 13 (Event Log).
#[napi(object)]
pub struct NapiEvent {
    /// The event type (e.g., `"ContextCreated"`, `"MessageSent"`, `"ToolInvoked"`).
    pub event_type: String,
    /// DID of the actor who produced this event.
    pub actor_did: String,
    /// Unix timestamp (seconds since epoch) when the event was created.
    pub timestamp: f64,
    /// Event-specific data serialized as a JSON string.
    pub payload_json: String,
    /// Monotonic sequence number within the log.
    pub sequence: f64,
}

// ---------------------------------------------------------------------------
// NapiProof — Merkle proof record
// ---------------------------------------------------------------------------

/// A Merkle proof from the event log.
///
/// See ADR-011 (Event Log).
#[napi(object)]
pub struct NapiProof {
    /// `true` if the claim was verified successfully.
    pub verified: bool,
    /// The proof type: `"inclusion"` or `"absence"`.
    pub proof_type: String,
    /// Proof details serialized as a JSON string (Merkle path or sorted
    /// neighbors).
    pub details_json: String,
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Queries the context event log with optional filter criteria.
///
/// # Arguments
///
/// * `handle` — The context whose event log to query (must be `"active"`).
/// * `filter_json` — Optional JSON string with filter parameters:
///   `event_type`, `actor_did`, `after_sequence`, `before_sequence`,
///   `after_timestamp`, `before_timestamp`, `limit`. Pass `null` to return
///   all events (up to the default limit).
///
/// # Returns
///
/// A `Promise<NapiEvent[]>` resolving to the matching events.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2023` when not yet connected to the runtime.
/// - Rejects with `SCP-VALID-7000` if `filter_json` is not valid JSON.
#[napi]
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
pub async fn event_log_query(
    handle: &NapiContextHandle,
    filter_json: Option<String>,
) -> napi::Result<Vec<NapiEvent>> {
    let _ = (handle, filter_json);
    Err(ScpNapiError::Context {
        message: "not yet connected to runtime — event log query requires a live context"
            .to_owned(),
        code: "SCP-CTX-2023".to_owned(),
    }
    .into())
}

/// Verifies a claim against the context event log (Merkle proof).
///
/// Generates and verifies an inclusion or absence proof for the given claim.
///
/// # Arguments
///
/// * `handle` — The context whose event log to verify against.
/// * `claim_json` — JSON string describing the claim:
///   - `"type"`: `"inclusion"` or `"absence"`
///   - `"leaf_index"` (for inclusion): event position in the log
///   - `"event_hash"` (for absence): hex-encoded hash to prove absent
///
/// # Returns
///
/// A `Promise<NapiProof>` with the verification result and Merkle proof
/// details.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2025` when not yet connected to the runtime.
/// - Rejects with `SCP-VALID-7000` if `claim_json` is not valid JSON or
///   contains unrecognized proof type.
#[napi]
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn event_log_verify(
    handle: &NapiContextHandle,
    claim_json: String,
) -> napi::Result<NapiProof> {
    let _ = (handle, claim_json);
    Err(ScpNapiError::Context {
        message: "not yet connected to runtime — event log verification requires a live context"
            .to_owned(),
        code: "SCP-CTX-2025".to_owned(),
    }
    .into())
}
