//! `wasm-bindgen` bridge for event log queries and verification.
//!
//! All operations delegate to [`WasmContextManager`](crate::manager::WasmContextManager)
//! via [`with_manager`](crate::manager::with_manager). No local state management.
//!
//! See ADR-034 in `.docs/adrs/phase-4.md` and issue #389.

use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::context::WasmContextHandle;
use crate::error::ScpWasmError;
use crate::manager::with_manager;

// ---------------------------------------------------------------------------
// WasmEvent
// ---------------------------------------------------------------------------

/// A protocol event from the context event log.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmEvent {
    event_type: String,
    actor_did: String,
    timestamp: f64,
    payload_json: String,
    sequence: u64,
}

#[wasm_bindgen]
impl WasmEvent {
    #[must_use]
    #[wasm_bindgen(getter, js_name = "eventType")]
    pub fn event_type(&self) -> String {
        self.event_type.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = "actorDid")]
    pub fn actor_did(&self) -> String {
        self.actor_did.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn timestamp(&self) -> f64 {
        self.timestamp
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = "payloadJson")]
    pub fn payload_json(&self) -> String {
        self.payload_json.clone()
    }

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
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmProof {
    verified: bool,
    proof_type: String,
    details_json: String,
}

#[wasm_bindgen]
impl WasmProof {
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn verified(&self) -> bool {
        self.verified
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = "proofType")]
    pub fn proof_type(&self) -> String {
        self.proof_type.clone()
    }

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
/// Delegates to `WasmContextManager::event_log_query`. Returns a JSON string
/// with `eventCount` and `merkleRoot` fields.
#[wasm_bindgen]
pub fn event_log_query(context: &WasmContextHandle, filter_json: Option<String>) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        // Validate filter JSON if provided.
        if let Some(ref filter) = filter_json {
            let _f: serde_json::Value = serde_json::from_str(filter).map_err(|e| {
                ScpWasmError::Validation {
                    message: format!("filter_json is not valid JSON: {e}"),
                    code: "SCP-VALID-7000".to_owned(),
                }
                .into_js()
            })?;
        }

        let (count, root) =
            with_manager(|mgr| mgr.event_log_query(&context_id)).map_err(ScpWasmError::into_js)?;

        let result = serde_json::json!({
            "eventCount": count,
            "merkleRoot": root,
        });

        let json_str = serde_json::to_string(&result).map_err(|e| {
            ScpWasmError::Context {
                message: format!("serialization failed: {e}"),
                code: "SCP-CTX-2007".to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from_str(&json_str))
    })
}

/// Verifies a claim against the context event log.
///
/// Delegates to `WasmContextManager::event_log_prove_inclusion` or
/// `event_log_prove_absence` based on the claim type.
#[wasm_bindgen]
pub fn event_log_verify(context: &WasmContextHandle, claim_json: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        let claim: serde_json::Value = serde_json::from_str(&claim_json).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("claim_json is not valid JSON: {e}"),
                code: "SCP-VALID-7000".to_owned(),
            }
            .into_js()
        })?;

        let proof_type = claim["type"].as_str().unwrap_or("inclusion");

        let result = match proof_type {
            "inclusion" => {
                let leaf_index = claim["leafIndex"].as_u64().ok_or_else(|| {
                    ScpWasmError::Validation {
                        message: "inclusion claim requires 'leafIndex' (number)".to_owned(),
                        code: "SCP-VALID-7000".to_owned(),
                    }
                    .into_js()
                })?;

                with_manager(|mgr| mgr.event_log_prove_inclusion(&context_id, leaf_index))
                    .map_err(ScpWasmError::into_js)?
            }
            "absence" => {
                let event_hash_hex = claim["eventHash"].as_str().ok_or_else(|| {
                    ScpWasmError::Validation {
                        message: "absence claim requires 'eventHash' (hex string)".to_owned(),
                        code: "SCP-VALID-7000".to_owned(),
                    }
                    .into_js()
                })?;

                let event_hash = crate::runtime::decode_hex_hash(event_hash_hex).map_err(|e| {
                    ScpWasmError::Validation {
                        message: format!("invalid eventHash: {e}"),
                        code: "SCP-VALID-7000".to_owned(),
                    }
                    .into_js()
                })?;

                with_manager(|mgr| mgr.event_log_prove_absence(&context_id, &event_hash))
                    .map_err(ScpWasmError::into_js)?
            }
            other => {
                return Err(ScpWasmError::Validation {
                    message: format!(
                        "unsupported proof type '{other}' — expected 'inclusion' or 'absence'"
                    ),
                    code: "SCP-VALID-7000".to_owned(),
                }
                .into_js()
                .into());
            }
        };

        let verified = result["verified"].as_bool().unwrap_or(false);
        let details_json = serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_owned());

        Ok(JsValue::from(WasmProof {
            verified,
            proof_type: proof_type.to_owned(),
            details_json,
        }))
    })
}
