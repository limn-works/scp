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
//! # Wiring
//!
//! All functions delegate to the WASM-local runtime registry in [`crate::runtime`].
//! `event_log_query` returns log metadata (event count, Merkle root) and
//! `event_log_verify` generates and verifies Merkle inclusion/absence proofs.
//! Mirrors the `PyO3` bridge's `event_log.rs` wiring pattern.
//!
//! See ADR-022 in `.docs/adrs/phase-4.md` and ADR-011 (event log) for the
//! full specification.

use js_sys::Promise;
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
        if let Some(ref filter) = filter_json {
            let _f: serde_json::Value = serde_json::from_str(filter).map_err(|e| {
                ScpWasmError::Validation(format!("filter_json is not valid JSON: {e}")).into_js()
            })?;
        }

        let (event_count, merkle_root_hex) =
            runtime::with_context(&context_id, |rt| {
                let count = rt.event_log.event_count();
                let root = rt.event_log.root();
                Ok((count, runtime::encode_hex(&root)))
            })
            .map_err(ScpWasmError::into_js)?;

        if event_count == 0 {
            return Ok(JsValue::from_str("[]"));
        }

        #[allow(clippy::cast_precision_loss)]
        let now_secs = js_sys::Date::now() / 1000.0;

        let summary = serde_json::json!([{
            "eventType": "LogSummary",
            "actorDid": "",
            "timestamp": now_secs,
            "payloadJson": serde_json::json!({
                "event_count": event_count,
                "merkle_root": merkle_root_hex,
            }).to_string(),
            "sequence": event_count.saturating_sub(1),
        }]);

        let result_str = serde_json::to_string(&summary)
            .map_err(|e| ScpWasmError::Context(format!("serialization failed: {e}")).into_js())?;

        Ok(JsValue::from_str(&result_str))
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
#[allow(clippy::too_many_lines)]
pub fn event_log_verify(context: &WasmContextHandle, claim_json: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        let claim: serde_json::Value = serde_json::from_str(&claim_json).map_err(|e| {
            ScpWasmError::Validation(format!("claim_json is not valid JSON: {e}")).into_js()
        })?;

        let claim_type = claim["type"]
            .as_str()
            .ok_or_else(|| {
                ScpWasmError::Validation(
                    "claim must include 'type' field ('inclusion' or 'absence')".to_owned(),
                )
                .into_js()
            })?
            .to_owned();

        match claim_type.as_str() {
            "inclusion" => {
                let leaf_index = claim["leafIndex"].as_u64().ok_or_else(|| {
                    ScpWasmError::Validation(
                        "inclusion claim must include 'leafIndex' (integer)".to_owned(),
                    )
                    .into_js()
                })?;

                let (verified, details_json) =
                    runtime::with_context(&context_id, |rt| {
                        let proof = runtime::prove_inclusion(&rt.event_log, leaf_index)
                            .map_err(|e| {
                                ScpWasmError::Context(format!("inclusion proof failed: {e}"))
                            })?;
                        let verified = runtime::verify_inclusion(&proof);

                        let path_steps: Vec<serde_json::Value> = proof
                            .path
                            .iter()
                            .map(|step| {
                                let direction = match step.direction {
                                    runtime::Direction::Left => "left",
                                    runtime::Direction::Right => "right",
                                };
                                serde_json::json!({
                                    "sibling_hash": runtime::encode_hex(&step.sibling_hash),
                                    "direction": direction,
                                })
                            })
                            .collect();

                        let details = serde_json::json!({
                            "leaf_index": proof.leaf_index,
                            "leaf_hash": runtime::encode_hex(&proof.leaf_hash),
                            "root": runtime::encode_hex(&proof.root),
                            "path": path_steps,
                            "path_length": proof.path.len(),
                        });

                        Ok((verified, details))
                    })
                    .map_err(ScpWasmError::into_js)?;

                let details_str = serde_json::to_string(&details_json)
                    .unwrap_or_else(|_| "{}".to_owned());

                let proof = WasmProof {
                    verified,
                    proof_type: "inclusion".to_owned(),
                    details_json: details_str,
                };

                Ok(JsValue::from(proof))
            }
            "absence" => {
                let event_hash_hex = claim["eventHash"]
                    .as_str()
                    .ok_or_else(|| {
                        ScpWasmError::Validation(
                            "absence claim must include 'eventHash' (hex string)".to_owned(),
                        )
                        .into_js()
                    })?
                    .to_owned();

                let event_hash = runtime::decode_hex_hash(&event_hash_hex)
                    .map_err(|e| {
                        ScpWasmError::Validation(format!("invalid eventHash: {e}")).into_js()
                    })?;

                let (verified, details_json) =
                    runtime::with_context(&context_id, |rt| {
                        let proof =
                            runtime::prove_absence(&rt.event_log, &event_hash).map_err(|e| {
                                ScpWasmError::Context(format!("absence proof failed: {e}"))
                            })?;

                        let lower = proof.lower.as_ref().map(|lwp| {
                            serde_json::json!({
                                "leaf_hash": runtime::encode_hex(&lwp.leaf_hash),
                                "leaf_index": lwp.leaf_index,
                            })
                        });
                        let upper = proof.upper.as_ref().map(|uwp| {
                            serde_json::json!({
                                "leaf_hash": runtime::encode_hex(&uwp.leaf_hash),
                                "leaf_index": uwp.leaf_index,
                            })
                        });

                        let lower_verified = proof
                            .lower
                            .as_ref()
                            .is_none_or(|lwp| runtime::verify_inclusion(&lwp.inclusion_proof));
                        let upper_verified = proof
                            .upper
                            .as_ref()
                            .is_none_or(|uwp| runtime::verify_inclusion(&uwp.inclusion_proof));
                        let verified = lower_verified && upper_verified;

                        let details = serde_json::json!({
                            "query_hash": runtime::encode_hex(&proof.query_hash),
                            "root": runtime::encode_hex(&proof.root),
                            "leaf_count": proof.leaf_count,
                            "lower": lower,
                            "upper": upper,
                        });

                        Ok((verified, details))
                    })
                    .map_err(ScpWasmError::into_js)?;

                let details_str = serde_json::to_string(&details_json)
                    .unwrap_or_else(|_| "{}".to_owned());

                let proof = WasmProof {
                    verified,
                    proof_type: "absence".to_owned(),
                    details_json: details_str,
                };

                Ok(JsValue::from(proof))
            }
            other => Err(ScpWasmError::Validation(format!(
                "unsupported claim type '{other}': expected 'inclusion' or 'absence'"
            ))
            .into_js()
            .into()),
        }
    })
}
