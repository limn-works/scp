//! `wasm-bindgen` bridge for event log queries and verification.
//!
//! Exposes SCP event log operations to JavaScript:
//!
//! - [`event_log_query`] — Query the context event log with optional filters.
//! - [`event_log_verify`] — Verify a claim against the event log (Merkle
//!   inclusion/absence proofs).
//!
//! # Types
//!
//! - [`WasmEvent`] — A protocol event (type, actor, timestamp, payload as
//!   JSON, sequence number).
//! - [`WasmProof`] — A verification proof (verified flag, proof type,
//!   details as JSON).
//!
//! # Bridge stub behavior
//!
//! All functions are bridge stubs returning typed errors. The full event log
//! implementation (Merkle tree, cryptographic proofs, log replay) is in
//! scp-core/event_log and will be connected in a future story when
//! WASM-compatible scp-core bindings are available.
//!
//! See ADR-022 in `.docs/adrs/phase-4.md` and ADR-011 (event log) for the
//! full specification.

use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::context::WasmContextHandle;
use crate::error::ScpWasmError;

// ---------------------------------------------------------------------------
// WasmEvent
// ---------------------------------------------------------------------------

/// A protocol event from the context event log.
///
/// Each event records a single protocol action: what happened (`event_type`),
/// who did it (`actor_did`), when (`timestamp`), the event data (`payload_json`
/// as a JSON string), and its position in the log (`sequence`).
///
/// # JS usage
///
/// ```js
/// const events = await event_log_query(contextId, filterJson);
/// for (const evt of events) {
///     console.log(evt.eventType, evt.actorDid, evt.sequence);
///     const payload = JSON.parse(evt.payloadJson);
/// }
/// ```
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmEvent {
    /// The event type (e.g., `"ContextCreated"`, `"MessageSent"`,
    /// `"ToolInvoked"`).
    event_type: String,
    /// The DID of the actor who produced this event.
    actor_did: String,
    /// Unix timestamp (seconds since epoch) when the event was created.
    timestamp: f64,
    /// Event-specific data serialized as a JSON string.
    payload_json: String,
    /// Monotonic event sequence number within the log (0-indexed).
    sequence: u64,
}

#[wasm_bindgen]
impl WasmEvent {
    /// Returns the event type string.
    #[wasm_bindgen(getter, js_name = "eventType")]
    pub fn event_type(&self) -> String {
        self.event_type.clone()
    }

    /// Returns the DID of the actor who produced this event.
    #[wasm_bindgen(getter, js_name = "actorDid")]
    pub fn actor_did(&self) -> String {
        self.actor_did.clone()
    }

    /// Returns the event timestamp as seconds since Unix epoch.
    #[wasm_bindgen(getter)]
    pub fn timestamp(&self) -> f64 {
        self.timestamp
    }

    /// Returns the event payload as a JSON string.
    ///
    /// The TypeScript SDK parses this with `JSON.parse()`.
    #[wasm_bindgen(getter, js_name = "payloadJson")]
    pub fn payload_json(&self) -> String {
        self.payload_json.clone()
    }

    /// Returns the monotonic sequence number of this event in the log.
    #[wasm_bindgen(getter)]
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

// ---------------------------------------------------------------------------
// WasmProof
// ---------------------------------------------------------------------------

/// A verification proof from the event log.
///
/// Returned by [`event_log_verify`]. Contains the verification result, the
/// proof type (`"inclusion"` or `"absence"`), and proof details as a JSON
/// string (Merkle path for inclusion, sorted neighbors for absence).
///
/// # JS usage
///
/// ```js
/// const proof = await event_log_verify(contextId, claimJson);
/// console.log(proof.verified);   // true
/// console.log(proof.proofType);  // "inclusion"
/// const details = JSON.parse(proof.detailsJson);
/// ```
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmProof {
    /// `true` if the claim was verified successfully.
    verified: bool,
    /// The proof type: `"inclusion"` or `"absence"`.
    proof_type: String,
    /// Proof details serialized as a JSON string.
    details_json: String,
}

#[wasm_bindgen]
impl WasmProof {
    /// Returns `true` if the claim was verified successfully.
    #[wasm_bindgen(getter)]
    pub fn verified(&self) -> bool {
        self.verified
    }

    /// Returns the proof type (`"inclusion"` or `"absence"`).
    #[wasm_bindgen(getter, js_name = "proofType")]
    pub fn proof_type(&self) -> String {
        self.proof_type.clone()
    }

    /// Returns the proof details as a JSON string.
    ///
    /// For inclusion proofs: a Merkle path array.
    /// For absence proofs: sorted neighbor hashes.
    #[wasm_bindgen(getter, js_name = "detailsJson")]
    pub fn details_json(&self) -> String {
        self.details_json.clone()
    }
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Queries the context event log.
///
/// Returns events matching the optional filter criteria. All events are
/// returned if no filter is provided.
///
/// # Arguments
///
/// * `context` — The context handle whose event log to query.
/// * `filter_json` — An optional JSON string with filter parameters:
///   - `"eventType"` (`string`): Filter by event type name.
///   - `"actorDid"` (`string`): Filter by actor DID.
///   - `"afterSequence"` (`number`): Only events after this sequence.
///   - `"beforeSequence"` (`number`): Only events before this sequence.
///   - `"afterTimestamp"` (`number`): Only events after this timestamp.
///   - `"beforeTimestamp"` (`number`): Only events before this timestamp.
///   - `"limit"` (`number`): Maximum number of events to return.
///
/// # Returns
///
/// `Promise<string>` — resolves to a JSON array of serialized events.
/// The TypeScript SDK deserializes and maps to typed `Event` objects.
///
/// # Errors
///
/// - Rejects with `[SCP-VALID-7000]` if `filter_json` is malformed.
/// - Rejects with `[SCP-CTX-2000]` if the event log is not accessible.
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn event_log_query(context: &WasmContextHandle, filter_json: Option<String>) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        // Validate filter JSON if provided.
        if let Some(ref filter) = filter_json {
            let _f: serde_json::Value = serde_json::from_str(filter)
                .map_err(|e| ScpWasmError::Validation(format!(
                    "filter_json is not valid JSON: {e}"
                ))
                .into_js())?;
        }

        let _ = context_id;

        Err(ScpWasmError::Context(
            "not yet connected to runtime — event log query requires a live context handle \
             wired to scp-core"
                .to_owned(),
        )
        .into_js()
        .into())
    })
}

/// Verifies a claim against the context event log.
///
/// Generates and verifies a Merkle proof for the given claim. Supports
/// both inclusion proofs (proving an event IS in the log) and absence
/// proofs (proving an event is NOT in the log).
///
/// # Arguments
///
/// * `context` — The context handle whose event log to verify against.
/// * `claim_json` — A JSON string describing the claim:
///   - `"type"` (`"inclusion" | "absence"`): Proof type.
///   - `"leafIndex"` (`number`): For inclusion proofs, the event's position.
///   - `"eventHash"` (`string`): For absence proofs, the hex-encoded hash.
///
/// # Returns
///
/// `Promise<WasmProof>` — resolves to the verification proof.
///
/// # Errors
///
/// - Rejects with `[SCP-VALID-7000]` if `claim_json` is malformed.
/// - Rejects with `[SCP-CTX-2000]` if verification fails (empty log,
///   invalid index, not connected to runtime).
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn event_log_verify(context: &WasmContextHandle, claim_json: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        // Validate claim_json.
        let _claim: serde_json::Value = serde_json::from_str(&claim_json)
            .map_err(|e| ScpWasmError::Validation(format!(
                "claim_json is not valid JSON: {e}"
            ))
            .into_js())?;

        let _ = context_id;

        Err(ScpWasmError::Context(
            "not yet connected to runtime — event log verification requires a live context \
             handle wired to scp-core"
                .to_owned(),
        )
        .into_js()
        .into())
    })
}
