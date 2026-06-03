//! `wasm-bindgen` bridge for event log queries and verification.
//!
//! All operations delegate to [`WasmContextManager`](crate::manager::WasmContextManager)
//! via [`with_manager`](crate::manager::with_manager). No local state management.
//!
//! See ADR-034 in `.docs/adrs/phase-4.md` and issue #389.

use js_sys::Promise;
use scp_ffi_common::error_codes as codes;
use sha2::Digest as _;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use scp_ffi_common::validate::validate_did;

use crate::context::WasmContextHandle;
use crate::error::ScpWasmError;
use crate::manager::with_manager;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Validates that an f64 epoch value is non-negative and finite, returning it as u64.
///
/// Returns a [`ScpWasmError`] with `SCP-VALID-7040` if the value is negative, NaN,
/// or infinite. Call sites convert to `JsValue` via `.map_err(|e| e.into_js().into())`.
/// This separation allows native-target tests to exercise the validation logic
/// without invoking wasm-bindgen.
fn validate_non_negative_epoch(value: f64) -> Result<u64, ScpWasmError> {
    if value < 0.0 || !value.is_finite() {
        return Err(ScpWasmError::Validation {
            message: format!("epoch must be non-negative, got {value}"),
            code: codes::VALID_7040.to_owned(),
        });
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(value as u64)
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
    /// Returns whether the proof verification succeeded.
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
    #[must_use]
    #[wasm_bindgen(getter, js_name = "detailsJson")]
    pub fn details_json(&self) -> String {
        self.details_json.clone()
    }
}

// ---------------------------------------------------------------------------
// WasmCheckpoint
// ---------------------------------------------------------------------------

/// An unsigned consistency checkpoint from the context event log.
///
/// The `signing_payload_hash` field contains the SHA-256 hash of the
/// canonical signing payload. The TypeScript SDK wrapper must sign this
/// hash via `SubtleCrypto` to produce the final signed checkpoint.
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
    signing_payload_hash: String,
}

#[wasm_bindgen]
impl WasmCheckpoint {
    /// Returns the context ID this checkpoint belongs to.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "contextId")]
    pub fn context_id(&self) -> String {
        self.context_id.clone()
    }

    /// Returns the DID of the identity that generated the checkpoint.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "senderDid")]
    pub fn sender_did(&self) -> String {
        self.sender_did.clone()
    }

    /// Returns the number of events in the log at checkpoint time.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "eventCount")]
    pub fn event_count(&self) -> u32 {
        u32::try_from(self.event_count).unwrap_or(u32::MAX)
    }

    /// Returns the Merkle root hash as a hex string.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "merkleRoot")]
    pub fn merkle_root(&self) -> String {
        self.merkle_root.clone()
    }

    /// Returns the MLS epoch at checkpoint time, or `undefined` if unset.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn epoch(&self) -> Option<u32> {
        self.epoch.map(|e| u32::try_from(e).unwrap_or(u32::MAX))
    }

    /// Returns the checkpoint timestamp as seconds since the Unix epoch.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn timestamp(&self) -> f64 {
        self.timestamp
    }

    /// Returns the SHA-256 hash of the canonical signing payload (hex).
    ///
    /// The TypeScript SDK must sign this hash via `SubtleCrypto` to produce
    /// the final signed checkpoint.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "signingPayloadHash")]
    pub fn signing_payload_hash(&self) -> String {
        self.signing_payload_hash.clone()
    }
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Extracts the `limit` field from a parsed JSON filter object.
///
/// The filter JSON uses camelCase keys matching the TypeScript `EventFilter`
/// interface. Only `limit` is extracted and applied — both WASM and NAPI
/// bridges produce a single synthetic `LogSummary` event, so field-level
/// filters (`eventType`, `actorDid`, `afterSequence`, `beforeSequence`)
/// are not meaningful and are not parsed.
fn extract_filter(filter: Option<&serde_json::Value>) -> ParsedFilter {
    let Some(f) = filter else {
        return ParsedFilter::default();
    };
    #[allow(clippy::cast_possible_truncation)]
    ParsedFilter {
        limit: f
            .get("limit")
            .and_then(serde_json::Value::as_u64)
            .map(|l| l as usize),
    }
}

/// Parsed filter criteria for event log queries.
///
/// Only `limit` is meaningful — both WASM and NAPI bridges produce a
/// single synthetic `LogSummary` event, so field-level filters
/// (`eventType`, `actorDid`, `afterSequence`, `beforeSequence`) are not
/// applicable and are not parsed.
#[derive(Default)]
struct ParsedFilter {
    limit: Option<usize>,
}

/// Queries the context event log.
///
/// Delegates to `WasmContextManager::event_log_query`. Returns a JSON array of
/// event objects matching the TypeScript `Event` interface. When events exist,
/// returns a `LogSummary` event carrying event count and Merkle root in
/// `payloadJson`, consistent with the NAPI bridge.
///
/// Only the `limit` filter field is extracted and applied — both WASM and NAPI
/// bridges produce a single synthetic `LogSummary` event, so field-level
/// filters (`eventType`, `actorDid`, `afterSequence`, `beforeSequence`) are
/// not meaningful and are not parsed. The filter JSON uses camelCase to match
/// the TypeScript `EventFilter` interface directly — the WASM bridge receives
/// JSON from `JSON.stringify(filter)` without `snake_case` conversion (unlike
/// the NAPI bridge where the TypeScript wrapper converts keys).
#[wasm_bindgen]
pub fn event_log_query(context: &WasmContextHandle, filter_json: Option<String>) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        // Validate filter JSON if provided.
        let filter: Option<serde_json::Value> = match filter_json {
            Some(ref json_str) => {
                let parsed: serde_json::Value = serde_json::from_str(json_str).map_err(|e| {
                    ScpWasmError::Validation {
                        message: format!("filter_json is not valid JSON: {e}"),
                        code: codes::VALID_7000.to_owned(),
                    }
                    .into_js()
                })?;
                Some(parsed)
            }
            None => None,
        };

        let parsed = extract_filter(filter.as_ref());

        let event_type_filter = filter
            .as_ref()
            .and_then(|f| f.get("eventType").or_else(|| f.get("event_type")))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let actor_did_filter = filter
            .as_ref()
            .and_then(|f| f.get("actorDid").or_else(|| f.get("actor_did")))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let after_sequence = filter
            .as_ref()
            .and_then(|f| f.get("afterSequence").or_else(|| f.get("after_sequence")))
            .and_then(serde_json::Value::as_u64);
        let before_sequence = filter
            .as_ref()
            .and_then(|f| f.get("beforeSequence").or_else(|| f.get("before_sequence")))
            .and_then(serde_json::Value::as_u64);

        let events = with_manager(|mgr| mgr.event_log_query_events(&context_id))
            .map_err(ScpWasmError::into_js)?;

        // Empty log → empty array.
        if events.is_empty() {
            return Ok(JsValue::from_str("[]"));
        }

        let result: Vec<serde_json::Value> = events
            .into_iter()
            .filter(|ev| {
                event_type_filter
                    .as_deref()
                    .is_none_or(|want| ev.get("eventType").and_then(|v| v.as_str()) == Some(want))
            })
            .filter(|ev| {
                actor_did_filter
                    .as_deref()
                    .is_none_or(|want| ev.get("actorDid").and_then(|v| v.as_str()) == Some(want))
            })
            .filter(|ev| {
                let seq = ev
                    .get("sequence")
                    .and_then(serde_json::Value::as_f64)
                    .unwrap_or(0.0);
                #[allow(
                    clippy::cast_precision_loss,
                    clippy::cast_sign_loss,
                    clippy::cast_possible_truncation
                )]
                let seq_u64 = if seq < 0.0 { 0 } else { seq as u64 };
                after_sequence.is_none_or(|lo| seq_u64 > lo)
                    && before_sequence.is_none_or(|hi| seq_u64 < hi)
            })
            .take(parsed.limit.unwrap_or(usize::MAX))
            .collect();

        let json_str = serde_json::to_string(&result).map_err(|e| {
            ScpWasmError::Context {
                message: format!("serialization failed: {e}"),
                code: codes::CTX_2007.to_owned(),
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
                code: codes::VALID_7000.to_owned(),
            }
            .into_js()
        })?;

        let proof_type = claim["type"].as_str().unwrap_or("inclusion");

        let result = match proof_type {
            "inclusion" => {
                let leaf_index = claim["leafIndex"].as_u64().ok_or_else(|| {
                    ScpWasmError::Validation {
                        message: "inclusion claim requires 'leafIndex' (number)".to_owned(),
                        code: codes::VALID_7000.to_owned(),
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
                        code: codes::VALID_7000.to_owned(),
                    }
                    .into_js()
                })?;

                let event_hash = crate::runtime::decode_hex_hash(event_hash_hex).map_err(|e| {
                    ScpWasmError::Validation {
                        message: format!("invalid eventHash: {e}"),
                        code: codes::VALID_7000.to_owned(),
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
                    code: codes::VALID_7000.to_owned(),
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
    checkpoint_promise(context, identity_did, epoch)
}

/// Generates a consistency checkpoint scoped to a member DID.
///
/// Identical in behaviour to [`event_log_checkpoint`]: the WASM bridge has no
/// `Identity` opaque object and no DID-keyed registry — it already operates
/// purely on the `did` string, deferring Ed25519 signing to the JS-side
/// `WebCrypto` custody. The `did` names the member the checkpoint is attributed
/// to and is recorded as `sender_did` in the returned `WasmCheckpoint`. This
/// is the WASM port of the NAPI/PyO3 `event_log_checkpoint_by_did` entry point,
/// requiring no `scp-runtime` dependency (the canonical payload is built from
/// `scp_event_log` Merkle state alone, per ADR-034).
///
/// # Arguments
///
/// * `context` — The context whose event log to checkpoint.
/// * `did` — The DID of the member generating the checkpoint.
/// * `epoch` — The current MLS epoch (pass 0 for Broadcast contexts).
///
/// # Returns
///
/// A `Promise<WasmCheckpoint>` whose `signingPayloadHash` field must be signed
/// by the TypeScript SDK via `SubtleCrypto.sign`.
///
/// See ADR-011 acceptance criterion 8 and ADR-030.
#[wasm_bindgen]
pub fn event_log_checkpoint_by_did(
    context: &WasmContextHandle,
    did: String,
    epoch: f64,
) -> Promise {
    checkpoint_promise(context, did, epoch)
}

/// Shared checkpoint-generation body for [`event_log_checkpoint`] and
/// [`event_log_checkpoint_by_did`].
///
/// Both WASM checkpoint entry points are scoped to a member DID string (WASM
/// has no `Identity` object), so they share this implementation: validate the
/// DID, snapshot the event log's Merkle root + event count, build the canonical
/// `SCP-CHECKPOINT-V1` payload, and return its SHA-256 hash for JS-side signing.
fn checkpoint_promise(context: &WasmContextHandle, identity_did: String, epoch: f64) -> Promise {
    if let Err(e) = validate_did(&identity_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = context.context_id();
    future_to_promise(async move {
        let (event_count, merkle_root_hex) =
            with_manager(|mgr| mgr.event_log_query(&context_id)).map_err(ScpWasmError::into_js)?;

        let epoch_u64 =
            validate_non_negative_epoch(epoch).map_err(|e| JsValue::from(e.into_js()))?;

        let timestamp_secs = crate::time::now_secs();

        // Build canonical checkpoint payload for signing, matching native Rust's
        // compute_checkpoint_canonical_hash in scp-event-log/src/checkpoint.rs.
        // Format: "SCP-CHECKPOINT-V1:" || BE32(len(ctx)) || ctx || BE32(len(did)) || did
        //         || event_count_BE || merkle_root(raw 32 bytes) || epoch_flag || [epoch_BE] || timestamp_BE
        let ctx_bytes = context_id.as_bytes();
        let did_bytes = identity_did.as_bytes();

        // Decode the hex merkle root to raw bytes for cross-platform compatibility.
        let merkle_root_bytes: [u8; 32] = {
            let decoded = hex::decode(&merkle_root_hex).map_err(|e| {
                ScpWasmError::Validation {
                    message: format!("invalid merkle root hex: {e}"),
                    code: codes::VALID_7000.to_owned(),
                }
                .into_js()
            })?;
            if decoded.len() != 32 {
                return Err(ScpWasmError::Validation {
                    message: format!("merkle root must be 32 bytes, got {}", decoded.len()),
                    code: codes::VALID_7000.to_owned(),
                }
                .into_js()
                .into());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&decoded);
            arr
        };

        let mut signing_payload = Vec::new();
        signing_payload.extend_from_slice(b"SCP-CHECKPOINT-V1:");
        #[allow(clippy::cast_possible_truncation)]
        signing_payload.extend_from_slice(&(ctx_bytes.len() as u32).to_be_bytes());
        signing_payload.extend_from_slice(ctx_bytes);
        #[allow(clippy::cast_possible_truncation)]
        signing_payload.extend_from_slice(&(did_bytes.len() as u32).to_be_bytes());
        signing_payload.extend_from_slice(did_bytes);
        signing_payload.extend_from_slice(&event_count.to_be_bytes());
        signing_payload.extend_from_slice(&merkle_root_bytes);
        // epoch_flag: 0x01 if Some, 0x00 if None (always Some here since we accept epoch param).
        signing_payload.push(0x01);
        signing_payload.extend_from_slice(&epoch_u64.to_be_bytes());
        signing_payload.extend_from_slice(&timestamp_secs.to_be_bytes());

        // Compute SHA-256 hash of the canonical signing payload. The
        // TypeScript SDK wrapper must sign this hash via SubtleCrypto.
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
            signing_payload_hash: payload_hex,
        }))
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use scp_ffi_common::error_codes as codes;

    // -----------------------------------------------------------------------
    // validate_non_negative_epoch — returns ScpWasmError (no JsValue)
    // -----------------------------------------------------------------------

    #[test]
    fn validate_epoch_accepts_zero() {
        assert_eq!(validate_non_negative_epoch(0.0).unwrap(), 0);
    }

    #[test]
    fn validate_epoch_accepts_positive() {
        assert_eq!(validate_non_negative_epoch(42.0).unwrap(), 42);
    }

    #[test]
    fn validate_epoch_rejects_negative() {
        let result = validate_non_negative_epoch(-1.0);
        assert!(result.is_err(), "negative epoch should error");
    }

    #[test]
    fn validate_epoch_rejects_negative_infinity() {
        let result = validate_non_negative_epoch(f64::NEG_INFINITY);
        assert!(result.is_err(), "NEG_INFINITY epoch should error");
    }

    #[test]
    fn validate_epoch_rejects_f64_min() {
        let result = validate_non_negative_epoch(f64::MIN);
        assert!(result.is_err(), "f64::MIN epoch should error");
    }

    #[test]
    fn validate_epoch_rejects_nan() {
        let result = validate_non_negative_epoch(f64::NAN);
        assert!(result.is_err(), "NaN epoch should error");
    }

    #[test]
    fn validate_epoch_rejects_positive_infinity() {
        let result = validate_non_negative_epoch(f64::INFINITY);
        assert!(result.is_err(), "INFINITY epoch should error");
    }

    #[test]
    fn validate_epoch_error_contains_code() {
        let result = validate_non_negative_epoch(-42.0);
        let err = result.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains(codes::VALID_7040),
            "error should contain SCP-VALID-7040, got: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // JSON output structure — validates the serialized event format
    // -----------------------------------------------------------------------

    /// Helper: builds an event JSON value matching the bridge output shape
    /// (`WasmContextManager::event_log_query_events`). Fields mirror the
    /// TypeScript `Event` interface: `eventType`, `actorDid`, `timestamp`,
    /// `payloadJson`, `sequence`.
    fn build_event(
        event_type: &str,
        actor_did: &str,
        timestamp: f64,
        sequence: f64,
    ) -> serde_json::Value {
        serde_json::json!({
            "eventType": event_type,
            "actorDid": actor_did,
            "timestamp": timestamp,
            "payloadJson": "",
            "sequence": sequence,
        })
    }

    #[test]
    fn json_output_has_required_event_fields() {
        let event = build_event("ContextCreated", "did:dht:zabc", 1_700_000_000.0, 0.0);
        assert_eq!(event["eventType"], "ContextCreated");
        assert_eq!(event["actorDid"], "did:dht:zabc");
        assert_eq!(event["timestamp"], 1_700_000_000.0);
        assert_eq!(event["sequence"], 0.0);
        assert_eq!(event["payloadJson"], "");
    }

    #[test]
    fn json_output_wraps_in_array() {
        let event = build_event("ContextCreated", "", 100.0, 0.0);
        let events = vec![&event];
        let serialized = serde_json::to_string(&events).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["eventType"], "ContextCreated");
    }

    #[test]
    fn json_output_empty_array_when_no_events() {
        let events: Vec<&serde_json::Value> = vec![];
        let serialized = serde_json::to_string(&events).unwrap();
        assert_eq!(serialized, "[]");
    }

    // -----------------------------------------------------------------------
    // extract_filter — camelCase filter field extraction
    // -----------------------------------------------------------------------

    #[test]
    fn extract_filter_none_returns_defaults() {
        let parsed = extract_filter(None);
        assert!(parsed.limit.is_none());
    }

    #[test]
    fn extract_filter_extracts_limit() {
        let filter = Some(serde_json::json!({
            "eventType": "MessageSent",
            "actorDid": "did:dht:z1234",
            "afterSequence": 5,
            "beforeSequence": 10,
            "limit": 3,
        }));
        let parsed = extract_filter(filter.as_ref());
        assert_eq!(parsed.limit, Some(3));
    }

    #[test]
    fn extract_filter_ignores_non_limit_fields() {
        let filter = Some(serde_json::json!({ "eventType": "MessageSent" }));
        let parsed = extract_filter(filter.as_ref());
        assert!(parsed.limit.is_none());
    }
}
