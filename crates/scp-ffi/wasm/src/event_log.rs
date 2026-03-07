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
//! # WASM-local implementation
//!
//! All functions delegate to the WASM-local event log (`WasmEventLog`) in
//! `runtime.rs`. Events are stored as Merkle tree leaves (SHA-256 hashes).
//! Event metadata (type, actor, timestamp, payload) is stored alongside
//! each leaf for query support. Proofs use RFC 6962 Merkle tree structure.
//!
//! See ADR-022 in `.docs/adrs/phase-4.md` and ADR-011 (event log) for the
//! full specification.

use js_sys::Promise;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::context::WasmContextHandle;
use crate::error::ScpWasmError;
use crate::runtime;

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
    #[must_use]
    #[wasm_bindgen(getter, js_name = "eventType")]
    pub fn event_type(&self) -> String {
        self.event_type.clone()
    }

    /// Returns the DID of the actor who produced this event.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "actorDid")]
    pub fn actor_did(&self) -> String {
        self.actor_did.clone()
    }

    /// Returns the event timestamp as seconds since Unix epoch.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn timestamp(&self) -> f64 {
        self.timestamp
    }

    /// Returns the event payload as a JSON string.
    ///
    /// The TypeScript SDK parses this with `JSON.parse()`.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "payloadJson")]
    pub fn payload_json(&self) -> String {
        self.payload_json.clone()
    }

    /// Returns the monotonic sequence number of this event in the log.
    #[must_use]
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
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn verified(&self) -> bool {
        self.verified
    }

    /// Returns the proof type (`"inclusion"` or `"absence"`).
    #[must_use]
    #[wasm_bindgen(getter, js_name = "proofType")]
    pub fn proof_type(&self) -> String {
        self.proof_type.clone()
    }

    /// Returns the proof details as a JSON string.
    ///
    /// For inclusion proofs: a Merkle path array.
    /// For absence proofs: sorted neighbor hashes.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "detailsJson")]
    pub fn details_json(&self) -> String {
        self.details_json.clone()
    }
}

// ---------------------------------------------------------------------------
// Event metadata storage (stored alongside Merkle tree leaves)
// ---------------------------------------------------------------------------

/// Metadata for an event stored in the WASM-local event log.
///
/// The `WasmEventLog` in `runtime.rs` stores only leaf hashes (for Merkle
/// proofs). This struct stores the full event metadata needed for queries.
/// The event metadata registry is per-context, keyed by sequence number.
#[derive(Debug, Clone)]
pub struct EventMetadata {
    /// The event type string.
    pub event_type: String,
    /// The actor DID.
    pub actor_did: String,
    /// Unix timestamp (seconds since epoch).
    pub timestamp: f64,
    /// Event payload as a JSON string.
    pub payload_json: String,
    /// Sequence number (0-indexed).
    pub sequence: u64,
}

// ---------------------------------------------------------------------------
// Per-context event metadata registry
// ---------------------------------------------------------------------------

use std::cell::RefCell;
use std::collections::HashMap;

thread_local! {
    /// Per-context event metadata, keyed by context ID.
    /// Each context maps sequence number to `EventMetadata`.
    static EVENT_METADATA: RefCell<HashMap<String, Vec<EventMetadata>>> =
        RefCell::new(HashMap::new());
}

/// Appends an event to both the Merkle tree and the metadata registry.
///
/// This is the canonical way to add events from within the WASM bridge.
/// Computes `SHA-256(0x00 || canonical_json(event))` as the leaf hash
/// (RFC 6962 domain separation).
///
/// # Errors
///
/// Returns an error if the context is not registered in the runtime.
pub fn append_event(
    context_id: &str,
    event_type: &str,
    actor_did: &str,
    payload_json: &str,
) -> Result<u64, ScpWasmError> {
    let timestamp = now_secs();

    // Compute the leaf hash: SHA-256(0x00 || event_type || actor_did || payload)
    let mut hasher = Sha256::new();
    hasher.update([0x00]); // RFC 6962 leaf domain separator
    hasher.update(event_type.as_bytes());
    hasher.update(actor_did.as_bytes());
    hasher.update(payload_json.as_bytes());
    let leaf_hash: [u8; 32] = hasher.finalize().into();

    // Append to the Merkle tree in the runtime registry.
    let sequence = runtime::with_context(context_id, |rt| {
        let seq = rt.event_log.event_count();
        rt.event_log.append_leaf(leaf_hash);
        Ok(seq)
    })?;

    // Store metadata for query support.
    EVENT_METADATA.with(|reg| {
        let mut map = reg.borrow_mut();
        let entries = map.entry(context_id.to_owned()).or_default();
        entries.push(EventMetadata {
            event_type: event_type.to_owned(),
            actor_did: actor_did.to_owned(),
            timestamp,
            payload_json: payload_json.to_owned(),
            sequence,
        });
    });

    Ok(sequence)
}

/// Removes event metadata for a context (called on context close).
pub fn remove_event_metadata(context_id: &str) {
    EVENT_METADATA.with(|reg| {
        reg.borrow_mut().remove(context_id);
    });
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
/// - Rejects with `[SCP-CTX-2007]` if the event log is not accessible.
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn event_log_query(context: &WasmContextHandle, filter_json: Option<String>) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        // Parse filter if provided.
        let filter: Option<serde_json::Value> = match filter_json {
            Some(ref json_str) => {
                let f: serde_json::Value = serde_json::from_str(json_str).map_err(|e| {
                    ScpWasmError::Validation {
                        message: format!("filter_json is not valid JSON: {e}"),
                        code: "SCP-VALID-7000".to_owned(),
                    }
                    .into_js()
                })?;
                Some(f)
            }
            None => None,
        };

        // Verify the context exists in the runtime registry.
        runtime::with_context(&context_id, |_rt| Ok(())).map_err(ScpWasmError::into_js)?;

        // Query event metadata.
        let events_json = EVENT_METADATA.with(|reg| {
            let map = reg.borrow();
            let entries = map.get(&context_id);
            let empty = Vec::new();
            let all_events = entries.unwrap_or(&empty);

            // Apply filters.
            let mut filtered: Vec<&EventMetadata> = all_events.iter().collect();

            if let Some(ref f) = filter {
                if let Some(event_type) = f.get("eventType").and_then(serde_json::Value::as_str) {
                    filtered.retain(|e| e.event_type == event_type);
                }
                if let Some(actor_did) = f.get("actorDid").and_then(serde_json::Value::as_str) {
                    filtered.retain(|e| e.actor_did == actor_did);
                }
                if let Some(after_seq) = f.get("afterSequence").and_then(serde_json::Value::as_u64)
                {
                    filtered.retain(|e| e.sequence > after_seq);
                }
                if let Some(before_seq) =
                    f.get("beforeSequence").and_then(serde_json::Value::as_u64)
                {
                    filtered.retain(|e| e.sequence < before_seq);
                }
                if let Some(after_ts) = f.get("afterTimestamp").and_then(serde_json::Value::as_f64)
                {
                    filtered.retain(|e| e.timestamp > after_ts);
                }
                if let Some(before_ts) =
                    f.get("beforeTimestamp").and_then(serde_json::Value::as_f64)
                {
                    filtered.retain(|e| e.timestamp < before_ts);
                }
                if let Some(limit) = f.get("limit").and_then(serde_json::Value::as_u64) {
                    #[allow(clippy::cast_possible_truncation)]
                    filtered.truncate(limit as usize);
                }
            }

            // Serialize to JSON array.
            let json_events: Vec<serde_json::Value> = filtered
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "eventType": e.event_type,
                        "actorDid": e.actor_did,
                        "timestamp": e.timestamp,
                        "payloadJson": e.payload_json,
                        "sequence": e.sequence,
                    })
                })
                .collect();

            serde_json::to_string(&json_events).unwrap_or_else(|_| "[]".to_owned())
        });

        Ok(JsValue::from_str(&events_json))
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
/// - Rejects with `[SCP-CTX-2007]` if verification fails (empty log,
///   invalid index).
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn event_log_verify(context: &WasmContextHandle, claim_json: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        // Parse the claim.
        let claim: serde_json::Value = serde_json::from_str(&claim_json).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("claim_json is not valid JSON: {e}"),
                code: "SCP-VALID-7000".to_owned(),
            }
            .into_js()
        })?;

        let claim_type = claim
            .get("type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ScpWasmError::Validation {
                    message: "missing or non-string 'type' field in claim".to_owned(),
                    code: "SCP-VALID-7000".to_owned(),
                }
                .into_js()
            })?;

        let proof = runtime::with_context(&context_id, |rt| match claim_type {
            "inclusion" => build_inclusion_proof(rt, &claim),
            "absence" => build_absence_proof(rt, &claim),
            other => Err(ScpWasmError::Validation {
                message: format!(
                    "unsupported claim type: {other:?} — must be \"inclusion\" or \"absence\""
                ),
                code: "SCP-VALID-7000".to_owned(),
            }),
        })
        .map_err(ScpWasmError::into_js)?;

        Ok(JsValue::from(proof))
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Builds an inclusion proof result from the event log.
fn build_inclusion_proof(
    rt: &runtime::WasmContextRuntime,
    claim: &serde_json::Value,
) -> Result<WasmProof, ScpWasmError> {
    let leaf_index = claim
        .get("leafIndex")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| ScpWasmError::Validation {
            message: "missing or non-numeric 'leafIndex' for inclusion proof".to_owned(),
            code: "SCP-VALID-7000".to_owned(),
        })?;

    let inclusion_proof =
        runtime::prove_inclusion(&rt.event_log, leaf_index).map_err(|e| ScpWasmError::Context {
            message: format!("inclusion proof failed: {e}"),
            code: "SCP-CTX-2007".to_owned(),
        })?;

    let verified = runtime::verify_inclusion(&inclusion_proof);

    let path_json: Vec<serde_json::Value> = inclusion_proof
        .path
        .iter()
        .map(|step| {
            serde_json::json!({
                "siblingHash": runtime::encode_hex(&step.sibling_hash),
                "direction": match step.direction {
                    runtime::Direction::Left => "left",
                    runtime::Direction::Right => "right",
                },
            })
        })
        .collect();

    let details = serde_json::json!({
        "leafIndex": inclusion_proof.leaf_index,
        "leafHash": runtime::encode_hex(&inclusion_proof.leaf_hash),
        "root": runtime::encode_hex(&inclusion_proof.root),
        "path": path_json,
    });

    Ok(WasmProof {
        verified,
        proof_type: "inclusion".to_owned(),
        details_json: serde_json::to_string(&details).unwrap_or_else(|_| "{}".to_owned()),
    })
}

/// Builds an absence proof result from the event log.
fn build_absence_proof(
    rt: &runtime::WasmContextRuntime,
    claim: &serde_json::Value,
) -> Result<WasmProof, ScpWasmError> {
    let event_hash_hex = claim
        .get("eventHash")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ScpWasmError::Validation {
            message: "missing or non-string 'eventHash' for absence proof".to_owned(),
            code: "SCP-VALID-7000".to_owned(),
        })?;

    let event_hash =
        runtime::decode_hex_hash(event_hash_hex).map_err(|e| ScpWasmError::Validation {
            message: format!("invalid eventHash: {e}"),
            code: "SCP-VALID-7000".to_owned(),
        })?;

    let absence_proof =
        runtime::prove_absence(&rt.event_log, &event_hash).map_err(|e| ScpWasmError::Context {
            message: format!("absence proof failed: {e}"),
            code: "SCP-CTX-2007".to_owned(),
        })?;

    let lower_valid = absence_proof
        .lower
        .as_ref()
        .is_none_or(|l| runtime::verify_inclusion(&l.inclusion_proof));
    let upper_valid = absence_proof
        .upper
        .as_ref()
        .is_none_or(|u| runtime::verify_inclusion(&u.inclusion_proof));
    let verified = lower_valid && upper_valid;

    let details = serde_json::json!({
        "queryHash": runtime::encode_hex(&absence_proof.query_hash),
        "root": runtime::encode_hex(&absence_proof.root),
        "leafCount": absence_proof.leaf_count,
        "lowerHash": absence_proof.lower.as_ref().map(|l| runtime::encode_hex(&l.leaf_hash)),
        "upperHash": absence_proof.upper.as_ref().map(|u| runtime::encode_hex(&u.leaf_hash)),
    });

    Ok(WasmProof {
        verified,
        proof_type: "absence".to_owned(),
        details_json: serde_json::to_string(&details).unwrap_or_else(|_| "{}".to_owned()),
    })
}

/// Returns the current Unix timestamp in seconds.
fn now_secs() -> f64 {
    js_sys::Date::now() / 1000.0
}
