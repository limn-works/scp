//! `wasm-bindgen` bridge for event log queries and verification.
//!
//! All operations delegate to [`WasmContextManager`](crate::manager::WasmContextManager)
//! via [`with_manager`](crate::manager::with_manager). No local state management.
//!
//! See ADR-034 in `.docs/adrs/phase-4.md` and issue #389.

use js_sys::Promise;
use sha2::Digest as _;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use scp_ffi_common::validate::validate_did;

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
// WasmCheckpoint
// ---------------------------------------------------------------------------

/// A signed consistency checkpoint from the context event log.
///
/// See ADR-011 acceptance criterion 8 and ADR-030.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmCheckpoint {
    context_id: String,
    sender_did: String,
    event_count: u64,
    merkle_root: String,
    epoch: Option<u64>,
    timestamp: f64,
    signature: String,
}

#[wasm_bindgen]
impl WasmCheckpoint {
    #[must_use]
    #[wasm_bindgen(getter, js_name = "contextId")]
    pub fn context_id(&self) -> String {
        self.context_id.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = "senderDid")]
    pub fn sender_did(&self) -> String {
        self.sender_did.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = "eventCount")]
    pub fn event_count(&self) -> u64 {
        self.event_count
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = "merkleRoot")]
    pub fn merkle_root(&self) -> String {
        self.merkle_root.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn epoch(&self) -> Option<u64> {
        self.epoch
    }

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn timestamp(&self) -> f64 {
        self.timestamp
    }

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> String {
        self.signature.clone()
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

/// Generates a consistency checkpoint from the current event log state.
///
/// Retrieves the event log's Merkle root and event count, then returns an
/// unsigned checkpoint. Signing requires JS-side key custody (`WebCrypto`);
/// the TypeScript SDK wrapper signs the checkpoint data.
///
/// # Arguments
///
/// * `context` — The context whose event log to checkpoint.
/// * `identity_did` — The DID of the identity generating the checkpoint.
/// * `epoch` — The current MLS epoch (pass 0 for Broadcast contexts).
///
/// # Returns
///
/// A `Promise<WasmCheckpoint>` with the checkpoint data. The `signature`
/// field contains the hex-encoded canonical checkpoint payload that must be
/// signed by the TypeScript SDK via `SubtleCrypto.sign`.
///
/// See ADR-011 acceptance criterion 8 and ADR-030.
#[wasm_bindgen]
pub fn event_log_checkpoint(
    context: &WasmContextHandle,
    identity_did: String,
    epoch: f64,
) -> Promise {
    if let Err(e) = validate_did(&identity_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = context.context_id();
    future_to_promise(async move {
        let (event_count, merkle_root_hex) =
            with_manager(|mgr| mgr.event_log_query(&context_id)).map_err(ScpWasmError::into_js)?;

        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let epoch_u64 = epoch as u64;

        let now = js_sys::Date::now();
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let timestamp_secs = (now / 1000.0) as u64;

        // Build canonical checkpoint payload for signing.
        // Format: context_id || sender_did || event_count(be) || merkle_root(hex) || epoch(be) || timestamp(be)
        let mut signing_payload = Vec::new();
        signing_payload.extend_from_slice(context_id.as_bytes());
        signing_payload.extend_from_slice(identity_did.as_bytes());
        signing_payload.extend_from_slice(&event_count.to_be_bytes());
        signing_payload.extend_from_slice(merkle_root_hex.as_bytes());
        signing_payload.extend_from_slice(&epoch_u64.to_be_bytes());
        signing_payload.extend_from_slice(&timestamp_secs.to_be_bytes());

        // The signature field contains the hex-encoded signing payload.
        // The TypeScript SDK wrapper must sign this payload via SubtleCrypto
        // and replace this field with the actual signature.
        let payload_hash = sha2::Sha256::digest(&signing_payload);
        let payload_hex = payload_hash
            .iter()
            .fold(String::with_capacity(64), |mut acc, b| {
                use std::fmt::Write;
                let _ = write!(acc, "{b:02x}");
                acc
            });

        Ok(JsValue::from(WasmCheckpoint {
            context_id,
            sender_did: identity_did,
            event_count,
            merkle_root: merkle_root_hex,
            epoch: Some(epoch_u64),
            #[allow(clippy::cast_precision_loss)]
            timestamp: timestamp_secs as f64,
            signature: payload_hex,
        }))
    })
}
