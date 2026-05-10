//! `wasm-bindgen` streaming bridge for outlets — `SCP-OUT-037` (WASM
//! portion).
//!
//! Mirrors the `PyO3` (`crates/scp-ffi/src/outlet_stream.rs`), NAPI
//! (`crates/scp-ffi/napi/src/outlet_stream.rs`), and `UniFFI`
//! (`crates/scp-ffi/uniffi/src/outlet_stream.rs`) streaming modules.
//! Exposes §5.4.5 progressive-output streaming to browser TypeScript:
//!
//! - [`outlet_invoke_stream`] — Opens a §5.4.5 stream session and returns a
//!   [`WasmOutletInvocationStream`] JS class whose async `next()` method
//!   yields one chunk per call (or `null` on terminal / close) and whose
//!   `requestId` getter exposes the §5.4.5 16-byte `request_id` rendered
//!   as 32-char lowercase hex.
//! - [`outlet_stream_grant_credit`] — Signs and applies an
//!   `OutletStreamCredit` grant against an active stream identified by
//!   `request_id_hex`.
//! - [`outlet_stream_cancel`] — Applies an `OutletCancel` against an
//!   active stream identified by `request_id_hex`.
//! - [`verify_chunk_signature`] — Pure helper that verifies a chunk's
//!   `SCP-OUTLET-CHUNK-SIG-V1:` signature byte-for-byte per §5.4.5.
//! - [`compute_caveats_binding`] — Pure helper that recomputes the
//!   `SCP-OUTLET-CAVEAT-BIND-V1:` 32-byte binding per §5.4.5.
//!
//! # ADR-034 constraints (WASM bridge re-implementation)
//!
//! WASM cannot depend on `scp-runtime` (tokio multi-thread). The
//! streaming pipeline therefore re-uses the existing local invocation
//! path (the same one [`crate::manager::WasmContextManager::invoke_outlet_one_shot`]
//! uses) and pre-materialises the chunk queue at open time. `next()` is
//! a JS Promise that resolves synchronously off the queue; the async
//! shape is preserved so the SDK consumer code that targets the NAPI
//! bridge runs unchanged on WASM (`while ((c = await stream.next()) !==
//! null) { ... }`).
//!
//! Active sessions live on the `WasmContextManager` (per ADR-048 §1 —
//! per-bridge state, not a process-global) keyed by 32-char lowercase
//! hex `request_id`. Cleanup happens when `next()` returns `None`
//! (queue drained) or when `outlet_stream_cancel` flips the session to
//! cancelled (queue cleared, terminated flag set, entry retained until
//! the next `next()` call evicts it).

use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use scp_ffi_common::error_codes as codes;
use scp_ffi_common::validate::{validate_did, validate_outlet_id, validate_ucan_token};

use scp_protocol::context::outlets::error_codes::CODE_PROTOCOL_SESSION;
use scp_protocol::context::outlets::stream::{
    self as proto_stream, ChunkPayload, OutletStreamChunk,
};
use scp_protocol::trust::caveats::InvocationCaveats;

use crate::context::WasmContextHandle;
use crate::error::ScpWasmError;
use crate::manager::with_manager;

// ---------------------------------------------------------------------------
// WasmOutletInvocationStream — JS async-iterator-shaped class
// ---------------------------------------------------------------------------

/// JS class returned by [`outlet_invoke_stream`].
///
/// Exposes:
///
/// - `requestId` — 32-char lowercase hex of the §5.4.5 16-byte
///   `request_id`. The SDK uses this to address the stream from
///   [`outlet_stream_grant_credit`] / [`outlet_stream_cancel`].
/// - `done` — synchronous getter that flips `true` once a terminal
///   chunk has been observed or the queue is drained.
/// - `next()` — async method returning a `Promise` that resolves to
///   the next chunk record JSON object (`JsValue`) or `null` at
///   end-of-stream.
///
/// The TypeScript SDK wraps an instance of this class with an
/// `AsyncIterable` adapter that surfaces `Symbol.asyncIterator` (the
/// `wasm-bindgen` macro does not expose Symbol-keyed methods directly).
///
/// Iteration ends when the receiver closes OR after a terminal chunk
/// (`End`, `Error { terminal: true }`) is yielded; subsequent `next()`
/// calls return `null`.
#[wasm_bindgen(js_name = "OutletInvocationStream")]
pub struct WasmOutletInvocationStream {
    /// 16-byte `request_id` rendered as 32-char lowercase hex. Cloned
    /// onto the stream so the SDK can read it without an extra
    /// per-chunk decode.
    request_id_hex: String,
}

#[wasm_bindgen]
impl WasmOutletInvocationStream {
    /// Returns the §5.4.5 16-byte `request_id` of the open stream as a
    /// 32-char lowercase hex string. The SDK uses this to address the
    /// stream from `outletStreamGrantCredit` / `outletStreamCancel`.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "requestId")]
    pub fn request_id(&self) -> String {
        self.request_id_hex.clone()
    }

    /// Returns `true` once a terminal chunk has been observed (or the
    /// queue has been drained by the JS-side iterator). After this
    /// flips `true`, subsequent `next()` calls resolve to `null`
    /// immediately.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn done(&self) -> bool {
        let request_id_hex = self.request_id_hex.clone();
        with_manager(|mgr| Ok(mgr.outlet_stream_is_done(&request_id_hex))).unwrap_or(true)
    }

    /// Asynchronously yields the next chunk, or `null` once the stream
    /// is closed.
    ///
    /// Resolves to `null` when:
    ///
    /// - the queue is drained (clean shutdown), OR
    /// - a previous call already observed a terminal chunk
    ///   (`End` / `Error { terminal: true }`), OR
    /// - the session was evicted (e.g. by an explicit cancel).
    ///
    /// Returns the chunk as a JS object whose shape mirrors the §5.4.5
    /// wire form on a per-variant basis (discriminator key
    /// `payloadType`, plus variant-specific fields). Numeric fields
    /// (`sequence`, `executionTimeMs`) are surfaced as JS `number`
    /// because per-stream sequences are bounded by `credit_window`
    /// (default 32) and execution time in millis is far below
    /// `Number.MAX_SAFE_INTEGER` (`2^53` ms ≈ 285 000 years).
    ///
    /// # Errors
    ///
    /// Returns a `Promise` rejection only if a chunk fails to
    /// JCS-serialise (`SCP-TOOL-6006`). All runtime failure modes
    /// (cancel, executor error) flow through normally as
    /// `payloadType = "error"` chunks — the iterator does NOT throw
    /// for runtime errors emitted as terminal `Error` chunks.
    #[wasm_bindgen]
    pub fn next(&self) -> Promise {
        let request_id_hex = self.request_id_hex.clone();
        future_to_promise(async move {
            let chunk_opt = with_manager(|mgr| Ok(mgr.outlet_stream_next(&request_id_hex)))
                .map_err(ScpWasmError::into_js)?;
            match chunk_opt {
                None => Ok(JsValue::NULL),
                Some(chunk) => Ok(chunk_to_js(&chunk).map_err(ScpWasmError::into_js)?),
            }
        })
    }
}

/// Sets `key` on `object` to `value`. Wraps the `Reflect::set` boilerplate
/// so per-variant chunk converters stay readable. Returns
/// `ScpWasmError::Tool` on the rare case where the JS engine rejects
/// the set (the keys here are fresh-Object writes, so the path is
/// effectively unreachable in practice).
fn set_field(object: &js_sys::Object, key: &str, value: &JsValue) -> Result<(), ScpWasmError> {
    js_sys::Reflect::set(object, &JsValue::from_str(key), value)
        .map_err(|_| reflect_set_error())
        .map(|_| ())
}

/// Sets a string-typed field on `object`. Convenience over `set_field`.
fn set_str(object: &js_sys::Object, key: &str, value: &str) -> Result<(), ScpWasmError> {
    set_field(object, key, &JsValue::from_str(value))
}

/// Populates the variant-specific fields for a `Data` chunk.
fn fill_data_fields(
    object: &js_sys::Object,
    value: &serde_json::Value,
) -> Result<(), ScpWasmError> {
    set_str(object, "payloadType", "data")?;
    let value_json = serde_json::to_string(value).map_err(|e| ScpWasmError::Tool {
        message: format!("failed to serialise data value: {e}"),
        code: codes::TOOL_6006.to_owned(),
    })?;
    set_str(object, "valueJson", &value_json)
}

/// Populates the variant-specific fields for a `Progress` chunk.
fn fill_progress_fields(
    object: &js_sys::Object,
    pct: u16,
    note: Option<&str>,
) -> Result<(), ScpWasmError> {
    set_str(object, "payloadType", "progress")?;
    set_field(object, "pct", &JsValue::from_f64(f64::from(pct)))?;
    if let Some(n) = note {
        set_str(object, "note", n)?;
    }
    Ok(())
}

/// Populates the variant-specific fields for an `End` chunk.
fn fill_end_fields(
    object: &js_sys::Object,
    aggregate: &serde_json::Value,
    provenance: &scp_protocol::provenance::DataProvenance,
    execution_time_ms: u64,
) -> Result<(), ScpWasmError> {
    set_str(object, "payloadType", "end")?;
    let aggregate_json = serde_json::to_string(aggregate).map_err(|e| ScpWasmError::Tool {
        message: format!("failed to serialise aggregate: {e}"),
        code: codes::TOOL_6006.to_owned(),
    })?;
    let provenance_json = serde_json::to_string(provenance).map_err(|e| ScpWasmError::Tool {
        message: format!("failed to serialise provenance: {e}"),
        code: codes::TOOL_6006.to_owned(),
    })?;
    set_str(object, "aggregateJson", &aggregate_json)?;
    set_str(object, "provenanceJson", &provenance_json)?;
    #[allow(clippy::cast_precision_loss)]
    let exec_ms_js = JsValue::from_f64(execution_time_ms as f64);
    set_field(object, "executionTimeMs", &exec_ms_js)
}

/// Populates the variant-specific fields for an `Error` chunk.
fn fill_error_fields(
    object: &js_sys::Object,
    code: &str,
    message: &str,
    terminal: bool,
) -> Result<(), ScpWasmError> {
    set_str(object, "payloadType", "error")?;
    set_str(object, "code", code)?;
    set_str(object, "message", message)?;
    set_field(object, "terminal", &JsValue::from_bool(terminal))
}

/// Converts a runtime [`OutletStreamChunk`] into a JS object whose
/// shape mirrors the §5.4.5 wire form on a per-variant basis (matches
/// the NAPI bridge's `NapiOutletStreamChunk` field names).
fn chunk_to_js(chunk: &OutletStreamChunk) -> Result<JsValue, ScpWasmError> {
    let request_id_arr = js_sys::Uint8Array::from(chunk.request_id.as_slice());
    let sig_arr = js_sys::Uint8Array::from(chunk.sig.as_slice());

    let object = js_sys::Object::new();
    set_field(&object, "requestId", &request_id_arr)?;
    #[allow(clippy::cast_precision_loss)]
    let sequence_js = JsValue::from_f64(chunk.sequence as f64);
    set_field(&object, "sequence", &sequence_js)?;
    set_field(&object, "sig", &sig_arr)?;

    match &chunk.payload {
        ChunkPayload::Data { value } => fill_data_fields(&object, value)?,
        ChunkPayload::Progress { pct, note } => {
            fill_progress_fields(&object, *pct, note.as_deref())?;
        }
        ChunkPayload::End {
            aggregate,
            provenance,
            execution_time_ms,
        } => fill_end_fields(&object, aggregate, provenance, *execution_time_ms)?,
        ChunkPayload::Error {
            code,
            message,
            terminal,
        } => fill_error_fields(&object, code, message, *terminal)?,
    }
    Ok(JsValue::from(object))
}

/// Builds a uniform `ScpWasmError::Tool` for the rare case where
/// `js_sys::Reflect::set` fails. The set is into a freshly-created
/// `Object` whose key has not been frozen, so this path should never
/// be reachable in practice — but we surface a clean error rather
/// than panicking. `SCP-TOOL-6006` mirrors the chunk-serialisation
/// error class because both come from the same chunk-conversion
/// boundary.
fn reflect_set_error() -> ScpWasmError {
    ScpWasmError::Tool {
        message: "failed to set chunk field on JS object".to_owned(),
        code: codes::TOOL_6006.to_owned(),
    }
}

// ---------------------------------------------------------------------------
// outletInvokeStream — open the stream
// ---------------------------------------------------------------------------

/// Opens a §5.4.5 streaming outlet invocation and returns a JS
/// `Promise<OutletInvocationStream>` whose `next()` method yields
/// chunks one at a time.
///
/// The WASM bridge re-uses the existing local invocation pipeline
/// that [`crate::outlets::outlet_invoke`] uses, but emits a per-chunk
/// stream (`Data` + terminal `End`, or terminal `Error`) instead of an
/// aggregate JSON return. Chunks are pre-materialised into a
/// per-session queue at open time because WASM cannot run an async
/// executor (ADR-034 — no scp-runtime).
///
/// # Arguments
///
/// * `context` — Hosting [`WasmContextHandle`] (the bridge re-runs
///   handle-affinity validation against the manager's active
///   contexts).
/// * `outlet_id` — Outlet to invoke.
/// * `input_json` — JSON string matching the outlet's input schema.
/// * `identity_did` — Invoker DID. Used as both `invoker_did` and the
///   chunk-signing identity (the WASM bridge has no out-of-process
///   operator — see module-level note).
/// * `ucan_token` — UCAN authorising the invocation. Validated under
///   the WASM-local 11-step pipeline before the stream is opened.
/// * `caveats_binding_hex` — 32-byte `caveats_binding` rendered as
///   64-char lowercase hex. The SDK computes this via
///   [`compute_caveats_binding`] before opening.
/// * `stream_epoch` — Hosting context's MLS epoch counter at open
///   acceptance, pinned in the session record. Provided by the SDK so
///   the credit-grant signing path can commit it into the
///   `SCP-OUTLET-CREDIT-V1:` preimage.
///
/// # Errors
///
/// * `SCP-VALID-7000` — invalid `outlet_id` / `identity_did` /
///   `ucan_token` shape, or `caveats_binding_hex` not 64 hex chars.
/// * `SCP-PERM-3000` — UCAN authorisation rejected.
/// * `SCP-TOOL-6002` — outlet not registered, input schema mismatch,
///   or chunk JCS canonicalisation failed.
/// * `SCP-CTX-2000` — context not active.
/// * `SCP-ECON-12096` — context has a paid economic policy (the WASM
///   bridge fails closed on paid contexts per the existing
///   `outlet_invoke` precondition).
#[wasm_bindgen(js_name = "outletInvokeStream")]
#[allow(clippy::too_many_arguments)]
pub fn outlet_invoke_stream(
    context: &WasmContextHandle,
    outlet_id: String,
    input_json: String,
    identity_did: String,
    ucan_token: String,
    caveats_binding_hex: String,
    stream_epoch: f64,
    _proof_tokens: Option<Vec<JsValue>>,
    credit_window: Option<u32>,
    _estimated_chunk_count: Option<u32>,
) -> Promise {
    // Mirror `outlet_invoke`'s fail-closed gate — the WASM bridge
    // cannot enforce paid-context billing on the streaming path either.
    {
        let context_id_check = context.context_id();
        let has_paid_policy =
            with_manager(|mgr| mgr.context_has_paid_policy(&context_id_check)).unwrap_or(false);
        if has_paid_policy {
            return future_to_promise(async move {
                Err(ScpWasmError::Context {
                    message: "WASM bridge cannot enforce tool payment for paid contexts. \
                              Use a native (Python/Node/Swift/Kotlin) client for paid streaming."
                        .to_owned(),
                    code: codes::ECON_12096.to_owned(),
                }
                .into_js()
                .into())
            });
        }
    }

    if let Err(e) = validate_outlet_id(&outlet_id) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    if let Err(e) = validate_did(&identity_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    if let Err(e) = validate_ucan_token(&ucan_token) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = context.context_id();
    future_to_promise(async move {
        // Decode caveats_binding hex up front so the SDK gets a clean
        // ValidationError before any registry inserts happen.
        let caveats_binding =
            decode_caveats_binding(&caveats_binding_hex).map_err(ScpWasmError::into_js)?;

        // §5.4.5 stream_epoch is a u64 MLS epoch counter. Reject
        // negative / non-finite / fractional / out-of-range floats at
        // the FFI boundary so the SDK sees a clean ValidationError.
        let stream_epoch_u64 = validate_stream_epoch(stream_epoch)?;

        // Look up the outlet's kind so the WASM-local UCAN validator
        // checks the correct split capability stem (SCP-OUT-014).
        let outlet_kind_for_ucan = with_manager(|mgr| mgr.outlet_kind(&context_id, &outlet_id))
            .map_err(ScpWasmError::into_js)?;

        // Re-validate the UCAN under the full 11-step pipeline
        // (defence in depth — matches `outlet_invoke`).
        crate::ucan::validate_outlet_ucan_wasm(
            &context_id,
            &outlet_id,
            outlet_kind_for_ucan,
            &ucan_token,
            &identity_did,
        )
        .map_err(|e| {
            ScpWasmError::Permission {
                message: format!("UCAN authorization failed for tool '{outlet_id}': {e}"),
                code: codes::PERM_3000.to_owned(),
            }
            .into_js()
        })?;

        let parsed_input: serde_json::Value = serde_json::from_str(&input_json).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("input_json is not valid JSON: {e}"),
                code: codes::VALID_7000.to_owned(),
            }
            .into_js()
        })?;

        // Export the invoker's signing key from the local identity
        // registry. The key is moved into the per-session record and
        // dropped (zeroed) when the session is evicted from the
        // registry.
        let invoker_signing_key =
            crate::identity::export_signing_key(&identity_did).map_err(ScpWasmError::into_js)?;

        // §5.4.5 credit-based backpressure: default to
        // `stream_window_default` (32) when the SDK does not declare an
        // explicit window. The value is pinned in the per-session
        // record at acceptance.
        let effective_credit_window =
            credit_window.unwrap_or(scp_protocol::context::outlets::stream::DEFAULT_CREDIT_WINDOW);

        let request_id_hex = with_manager(|mgr| {
            mgr.open_outlet_stream(crate::manager::OpenOutletStreamParams {
                context_id: &context_id,
                outlet_id: &outlet_id,
                input_json: &parsed_input,
                identity_did: &identity_did,
                caveats_binding,
                stream_epoch: stream_epoch_u64,
                invoker_signing_key,
                credit_window: effective_credit_window,
            })
        })
        .map_err(ScpWasmError::into_js)?;

        Ok(JsValue::from(WasmOutletInvocationStream { request_id_hex }))
    })
}

// ---------------------------------------------------------------------------
// outletStreamGrantCredit
// ---------------------------------------------------------------------------

/// Signs and applies an `OutletStreamCredit` grant against an active
/// stream identified by `request_id_hex`.
///
/// Returns a JS `Promise<number>` resolving to the new running total
/// of granted credits (`u32`).
///
/// # Errors
///
/// * `SCP-TOOL-6101` — `grant == 0` (uniform `protocol.invalid-grant`
///   rule per §5.4.5 round-6).
/// * `SCP-TOOL-6101` — `request_id_hex` does not match any active
///   stream registry entry (`protocol.unknown-session`).
#[wasm_bindgen(js_name = "outletStreamGrantCredit")]
pub fn outlet_stream_grant_credit(
    request_id_hex: String,
    caller_did: String,
    grant: u32,
) -> Promise {
    future_to_promise(async move {
        let total =
            with_manager(|mgr| mgr.outlet_stream_grant_credit(&request_id_hex, &caller_did, grant))
                .map_err(ScpWasmError::into_js)?;
        Ok(JsValue::from_f64(f64::from(total)))
    })
}

// ---------------------------------------------------------------------------
// outletStreamCancel
// ---------------------------------------------------------------------------

/// Applies an `OutletCancel` to an active stream identified by
/// `request_id_hex`.
///
/// Returns a JS `Promise<number | null>` resolving to the recorded
/// `cancel_ack_seq` when the cancel was recorded, or `null` if the
/// stream had already terminated when the cancel arrived (idempotent
/// per §5.4.5).
///
/// # Errors
///
/// * `SCP-TOOL-6101` — `request_id_hex` does not match any active
///   stream registry entry.
#[wasm_bindgen(js_name = "outletStreamCancel")]
pub fn outlet_stream_cancel(request_id_hex: String, caller_did: String) -> Promise {
    future_to_promise(async move {
        let recorded = with_manager(|mgr| mgr.outlet_stream_cancel(&request_id_hex, &caller_did))
            .map_err(ScpWasmError::into_js)?;
        Ok(recorded.map_or(JsValue::NULL, |seq| {
            #[allow(clippy::cast_precision_loss)]
            let seq_js = JsValue::from_f64(seq as f64);
            seq_js
        }))
    })
}

// ---------------------------------------------------------------------------
// outletStreamTerminate — receiver-side revocation re-check (§5.4.5)
// ---------------------------------------------------------------------------

/// Forces a terminal `Error{terminal:true}` chunk into the active stream
/// identified by `request_id_hex` (§5.4.5 receiver-side revocation
/// re-check, `RevokedMidStream` / `SCP-TOOL-6110`).
///
/// Routes through
/// [`crate::manager::WasmContextManager::outlet_stream_terminate`] —
/// because WASM has no executor pump, the manager pushes a synthetic
/// terminal chunk into the pre-materialised queue under the per-session
/// signing key. The next `outlet_stream_next` delivers the synthetic
/// terminal; the one after that resolves to `None` and evicts the
/// session.
///
/// The SDK framework's periodic UCAN re-check loop calls this whenever
/// it observes the opening UCAN has been revoked since stream open.
///
/// Returns a JS `Promise<void>` — resolves on success, rejects only when
/// the `request_id_hex` does not match any active session.
///
/// # Errors
///
/// * `SCP-TOOL-6101` — `request_id_hex` does not match any active
///   stream registry entry (`protocol.unknown-session`).
#[wasm_bindgen(js_name = "outletStreamTerminate")]
pub fn outlet_stream_terminate(
    request_id_hex: String,
    caller_did: String,
    slug: String,
    code: String,
    message: String,
) -> Promise {
    future_to_promise(async move {
        with_manager(|mgr| {
            mgr.outlet_stream_terminate(&request_id_hex, &caller_did, &slug, &code, &message)
        })
        .map_err(ScpWasmError::into_js)?;
        Ok(JsValue::UNDEFINED)
    })
}

// ---------------------------------------------------------------------------
// verifyChunkSignature — pure helper
// ---------------------------------------------------------------------------

/// Verifies a chunk's `SCP-OUTLET-CHUNK-SIG-V1:` signature.
///
/// `chunk_json` is the canonical-JSON-encoded [`OutletStreamChunk`] —
/// the bridge accepts the full chunk encoded as JSON and reconstructs
/// the typed struct so the verification path covers exactly the bytes
/// the operator signed. All five inputs match the §5.4.5 preimage
/// block byte-for-byte.
///
/// Returns a JS `Promise<boolean>` resolving to `true` if the
/// signature verifies, `false` otherwise. Rejects only on malformed
/// inputs (non-32-byte pubkey / `caveats_binding`, malformed JSON).
#[wasm_bindgen(js_name = "verifyChunkSignature")]
pub fn verify_chunk_signature(
    chunk_json: String,
    operator_pk: Vec<u8>,
    context_id: String,
    outlet_id: String,
    caveats_binding: Vec<u8>,
) -> Promise {
    future_to_promise(async move {
        let chunk: OutletStreamChunk = serde_json::from_str(&chunk_json).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("malformed chunk JSON: {e}"),
                code: codes::VALID_7000.to_owned(),
            }
            .into_js()
        })?;
        let pk_array: [u8; 32] = operator_pk.as_slice().try_into().map_err(|_| {
            ScpWasmError::Validation {
                message: format!(
                    "operator_pk must be exactly 32 bytes, got {}",
                    operator_pk.len()
                ),
                code: codes::VALID_7000.to_owned(),
            }
            .into_js()
        })?;
        let cb_array: [u8; 32] = caveats_binding.as_slice().try_into().map_err(|_| {
            ScpWasmError::Validation {
                message: format!(
                    "caveats_binding must be exactly 32 bytes, got {}",
                    caveats_binding.len()
                ),
                code: codes::VALID_7000.to_owned(),
            }
            .into_js()
        })?;
        let pk = ed25519_dalek::VerifyingKey::from_bytes(&pk_array).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("operator_pk is not a valid Ed25519 public key: {e}"),
                code: codes::VALID_7000.to_owned(),
            }
            .into_js()
        })?;
        Ok(JsValue::from_bool(proto_stream::verify_chunk_signature(
            &chunk,
            &pk,
            &context_id,
            &outlet_id,
            &cb_array,
        )))
    })
}

// ---------------------------------------------------------------------------
// computeCaveatsBinding — pure helper
// ---------------------------------------------------------------------------

/// Recomputes the §5.4.5 `caveats_binding` 32-byte SHA-256 over the
/// `SCP-OUTLET-CAVEAT-BIND-V1:` preimage.
///
/// Inputs match the §5.4.5 preimage block byte-for-byte:
/// `len_be32(ucan_cid) || ucan_cid || request_id || len_be32(invoker_did)
/// || invoker_did || estimated_chunk_count_be ||
/// len_be32(canonical_jcs_caveats) || canonical_jcs(caveats)`.
///
/// `effective_caveats_json` is the SDK-canonicalised JSON object of
/// the narrowed [`InvocationCaveats`] — the bridge re-runs JCS over
/// it so the caller does not need an in-language JCS implementation.
///
/// Returns a JS `Promise<Uint8Array>` resolving to the 32-byte hash.
#[wasm_bindgen(js_name = "computeCaveatsBinding")]
pub fn compute_caveats_binding(
    ucan_cid: Vec<u8>,
    request_id: Vec<u8>,
    invoker_did: String,
    estimated_chunk_count: u32,
    effective_caveats_json: String,
) -> Promise {
    future_to_promise(async move {
        let request_id_array: [u8; 16] = request_id.as_slice().try_into().map_err(|_| {
            ScpWasmError::Validation {
                message: format!(
                    "request_id must be exactly 16 bytes, got {}",
                    request_id.len()
                ),
                code: codes::VALID_7000.to_owned(),
            }
            .into_js()
        })?;
        let caveats_value: serde_json::Value = serde_json::from_str(&effective_caveats_json)
            .map_err(|e| {
                ScpWasmError::Validation {
                    message: format!("invalid effective_caveats JSON: {e}"),
                    code: codes::VALID_7000.to_owned(),
                }
                .into_js()
            })?;
        let caveats: InvocationCaveats = serde_json::from_value(caveats_value).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("effective_caveats does not match InvocationCaveats: {e}"),
                code: codes::VALID_7000.to_owned(),
            }
            .into_js()
        })?;
        // §5.4.5 requires JCS canonicalisation of effective_caveats
        // before hashing — the bridge runs canonicalisation here so
        // SDK callers do not need an in-language JCS implementation.
        let caveats_jcs = scp_protocol::jcs::to_vec(&caveats).map_err(|e| {
            ScpWasmError::Tool {
                message: format!("failed to JCS-canonicalise caveats: {e}"),
                code: codes::TOOL_6006.to_owned(),
            }
            .into_js()
        })?;
        let binding = proto_stream::compute_caveats_binding(
            &ucan_cid,
            &request_id_array,
            &invoker_did,
            estimated_chunk_count,
            &caveats_jcs,
        );
        Ok(JsValue::from(js_sys::Uint8Array::from(&binding[..])))
    })
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Decodes a 64-char lowercase hex string into a 32-byte
/// `caveats_binding`. Returns `ScpWasmError::Validation` on bad hex /
/// length.
fn decode_caveats_binding(hex_str: &str) -> Result<[u8; 32], ScpWasmError> {
    let bytes = hex::decode(hex_str).map_err(|e| ScpWasmError::Validation {
        message: format!("caveats_binding_hex must be 64 hex characters: {e}"),
        code: codes::VALID_7000.to_owned(),
    })?;
    let len = bytes.len();
    bytes.try_into().map_err(|_| ScpWasmError::Validation {
        message: format!("caveats_binding must decode to 32 bytes, got {len}"),
        code: codes::VALID_7000.to_owned(),
    })
}

/// Validates an `f64` MLS epoch counter (or `next_seq` cancel-input)
/// and converts it to `u64`.
///
/// JS `number` cannot represent `u64` losslessly past `2^53`. The
/// bridge surfaces `u64` protocol values as `f64` for ergonomic JS
/// consumption but rejects negative / non-finite / fractional /
/// out-of-range floats with `Validation` so SDK callers see a clean
/// error instead of a silently-truncated value. Mirrors
/// `validate_stream_epoch` in the NAPI bridge byte-for-byte.
fn validate_stream_epoch(value: f64) -> Result<u64, JsValue> {
    if !value.is_finite() {
        return Err(ScpWasmError::Validation {
            message: format!("stream_epoch must be a finite number, got {value}"),
            code: codes::VALID_7000.to_owned(),
        }
        .into_js()
        .into());
    }
    if value < 0.0 {
        return Err(ScpWasmError::Validation {
            message: format!("stream_epoch must be non-negative, got {value}"),
            code: codes::VALID_7000.to_owned(),
        }
        .into_js()
        .into());
    }
    if value.fract() != 0.0 {
        return Err(ScpWasmError::Validation {
            message: format!("stream_epoch must be an integer, got {value}"),
            code: codes::VALID_7000.to_owned(),
        }
        .into_js()
        .into());
    }
    #[allow(clippy::cast_precision_loss)]
    let max_safe = (1u64 << 53) as f64;
    if value > max_safe {
        return Err(ScpWasmError::Validation {
            message: format!(
                "stream_epoch {value} exceeds Number.MAX_SAFE_INTEGER (2^53); \
                 pass via BigInt-aware path when this is needed"
            ),
            code: codes::VALID_7000.to_owned(),
        }
        .into_js()
        .into());
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(value as u64)
}

// `CODE_PROTOCOL_SESSION` is referenced from manager.rs error paths;
// the import here keeps the streaming bridge module self-documenting
// about which §5.4.5 error codes are surfaced from this surface.
const _SESSION_CODE_USED_BY_MANAGER: &str = CODE_PROTOCOL_SESSION;
