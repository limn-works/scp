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
//! per-bridge state, not a process-global) keyed by the composite
//! `(context_id, request_id_hex)` pair (SCP-OUT-037 W2 — a
//! `request_id_hex` minted in one context can never address a session
//! in another). Cleanup happens when `next()` returns `None` (queue
//! drained) or when a cancel flips the session to cancelled (the next
//! `next()` pull surfaces a signed synthetic terminal, clears the
//! queue, and the entry is evicted on the pull after that).
//!
//! SCP-OUT-037 W1: the session holds NO secret key material — only the
//! invoker's public verifying key is pinned. Every chunk / credit-grant
//! / cancel / terminate signature is produced on-demand via
//! `crate::identity::with_signing_key`, which materialises a transient
//! `SigningKey` for one signing op and drops (zeroes) it immediately.

use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use scp_ffi_common::error_codes as codes;
use scp_ffi_common::validate::{
    validate_did, validate_outlet_id, validate_request_id_hex, validate_ucan_token,
};

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
    /// Hosting context id pinned at open. SCP-OUT-037 W2: the per-bridge
    /// session registry is keyed by `(context_id, request_id_hex)`, so
    /// `next()` / `done` / `Drop` build the full composite key from this
    /// plus `request_id_hex`.
    context_id: String,
    /// 16-byte `request_id` rendered as 32-char lowercase hex. Cloned
    /// onto the stream so the SDK can read it without an extra
    /// per-chunk decode.
    request_id_hex: String,
}

impl Drop for WasmOutletInvocationStream {
    /// §5.4.5 HIGH-wave-3 Fix B — evict the per-bridge session entry
    /// on drop so a wrapper GC'd by the JS host without being drained
    /// to terminal (exception path, V8 GC, awaiting-only consumption
    /// that never observes a terminal chunk) does NOT leak the
    /// [`crate::manager::WasmOutletStreamSession`] (the pre-materialised
    /// chunk queue and the admission slot held on the per-context
    /// `WasmStreamAdmissionTracker`).
    ///
    /// SCP-OUT-037 W1: the session holds no secret key material (only
    /// the public verifying key), so this `Drop` is about releasing the
    /// admission slot and evicting the queue, not scrubbing a key.
    ///
    /// SCP-OUT-037 W3: eviction routes through
    /// [`crate::manager::WasmContextManager::evict_stream_and_release`],
    /// which removes the session under the composite
    /// `(context_id, request_id_hex)` key and releases its admission
    /// slot exactly once (behind the session's `admission_released`
    /// guard). When [`Self::next`] already drained the queue, observed a
    /// terminal chunk, or `outlet_stream_terminate` already released the
    /// slot, this `Drop` becomes a no-op: the `remove` finds nothing (or
    /// the `admission_released` flag short-circuits the release), so the
    /// slot is never double-released.
    fn drop(&mut self) {
        let key = (self.context_id.clone(), self.request_id_hex.clone());
        let _ = with_manager(|mgr| {
            mgr.evict_stream_and_release(&key);
            Ok(())
        });
    }
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
        let context_id = self.context_id.clone();
        let request_id_hex = self.request_id_hex.clone();
        with_manager(|mgr| Ok(mgr.outlet_stream_is_done(&context_id, &request_id_hex)))
            .unwrap_or(true)
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
        let context_id = self.context_id.clone();
        let request_id_hex = self.request_id_hex.clone();
        future_to_promise(async move {
            let chunk_opt =
                with_manager(|mgr| Ok(mgr.outlet_stream_next(&context_id, &request_id_hex)))
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
    estimated_chunk_count: Option<u32>,
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

        // SCP-OUT-037 W4: do NOT echo the serde error (`{e}`) — it can
        // reflect raw `input_json` bytes back to the caller (covert
        // channel / log-injection surface per ADR-049 §4). Surface a
        // fixed, input-free message and keep the VALID_7000 code so SDK
        // error handling is unchanged.
        let parsed_input: serde_json::Value = serde_json::from_str(&input_json).map_err(|_| {
            ScpWasmError::Validation {
                message: "input_json is not valid JSON".to_owned(),
                code: codes::VALID_7000.to_owned(),
            }
            .into_js()
        })?;

        // SCP-OUT-037 W1: the invoker signing key is NOT exported here.
        // `open_outlet_stream` signs the materialised chunks on-demand
        // via `with_signing_key` (transient key, dropped immediately)
        // and pins only the public verifying key on the session — no
        // long-lived `SigningKey` is retained on the streaming path.

        // §5.4.5 credit-based backpressure: default to
        // `stream_window_default` (32) when the SDK does not declare an
        // explicit window. The value is pinned in the per-session
        // record at acceptance.
        let effective_credit_window =
            credit_window.unwrap_or(scp_protocol::context::outlets::stream::DEFAULT_CREDIT_WINDOW);

        // §5.4.5:758 cumulative billable-chunk ceiling (HIGH-2 / R3) +
        // §7.3.8 streaming caveat enforcement. The WASM bridge parses the
        // action UCAN's VALIDATED-NARROWED `nb` caveats (same recovery as
        // the single-shot path) and:
        //
        // - enforces the synchronous non-counter local set (`input_schema`
        //   / `amount_max_per_call` / `allowed_adapters` /
        //   `allowed_target_dids`) via `check_invocation_local`,
        // - FAILS CLOSED on the durable-state-requiring caveats
        //   (`rate_window` / `amount_max_cumulative`) WASM cannot enforce
        //   without a counter store (ADR-034), and
        // - pins the HARD billable-chunk ceiling to the VALIDATED `max_calls`
        //   (a within-stream chunk ceiling the native path folds statelessly
        //   via `enforce_estimated_chunk_count_bound`), REJECTING an
        //   over-declared `estimated_chunk_count > max_calls` rather than
        //   silently clamping it.
        //
        // The SDK-supplied `caveats_binding` is NOT trusted as a control
        // here — on WASM it is an opaque value never recomputed against the
        // validated `nb`. Enforcement comes from the parsed validated `nb`.
        let max_calls =
            enforce_stream_open_caveats(&ucan_token, &parsed_input, estimated_chunk_count)
                .map_err(ScpWasmError::into_js)?;

        let request_id_hex = with_manager(|mgr| {
            mgr.open_outlet_stream(crate::manager::OpenOutletStreamParams {
                context_id: &context_id,
                outlet_id: &outlet_id,
                input_json: &parsed_input,
                identity_did: &identity_did,
                caveats_binding,
                stream_epoch: stream_epoch_u64,
                credit_window: effective_credit_window,
                max_calls,
            })
        })
        .map_err(ScpWasmError::into_js)?;

        Ok(JsValue::from(WasmOutletInvocationStream {
            context_id,
            request_id_hex,
        }))
    })
}

// ---------------------------------------------------------------------------
// outletStreamGrantCredit
// ---------------------------------------------------------------------------

/// Signs and applies an `OutletStreamCredit` grant against an active
/// stream identified by the `(context, request_id_hex)` pair.
///
/// SCP-OUT-037 W2: `context` pins the hosting context so a
/// `request_id_hex` minted in another context cannot address this
/// stream. Returns a JS `Promise<number>` resolving to the new running
/// total of granted credits (`u32`).
///
/// # Errors
///
/// * `SCP-VALID-7000` — `request_id_hex` is not 32 lowercase hex
///   characters, or `caller_did` is not a well-formed DID.
/// * `SCP-TOOL-6101` — `grant == 0` (uniform `protocol.invalid-grant`
///   rule per §5.4.5 round-6).
/// * `SCP-TOOL-6101` — `(context, request_id_hex)` does not match any
///   active stream registry entry (`protocol.unknown-session`).
/// * `SCP-PERM-3001` — `caller_did` is not the stream's pinned invoker.
#[wasm_bindgen(js_name = "outletStreamGrantCredit")]
pub fn outlet_stream_grant_credit(
    context: &WasmContextHandle,
    request_id_hex: String,
    caller_did: String,
    grant: u32,
) -> Promise {
    // SCP-OUT-037 W4: validate the addressing inputs at the FFI boundary
    // before they are used to key the registry or echoed in any error.
    if let Err(e) = validate_request_id_hex(&request_id_hex) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    if let Err(e) = validate_did(&caller_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = context.context_id();
    future_to_promise(async move {
        let total = with_manager(|mgr| {
            mgr.outlet_stream_grant_credit(&context_id, &request_id_hex, &caller_did, grant)
        })
        .map_err(ScpWasmError::into_js)?;
        Ok(JsValue::from_f64(f64::from(total)))
    })
}

// ---------------------------------------------------------------------------
// outletStreamCancel
// ---------------------------------------------------------------------------

/// Applies an `OutletCancel` to an active stream identified by the
/// `(context, request_id_hex)` pair.
///
/// SCP-OUT-037 W2: `context` pins the hosting context. Returns a JS
/// `Promise<number | null>` resolving to the recorded `cancel_ack_seq`
/// when the cancel was recorded, or `null` if the stream had already
/// terminated when the cancel arrived (idempotent per §5.4.5).
///
/// # Errors
///
/// * `SCP-VALID-7000` — `request_id_hex` is not 32 lowercase hex
///   characters, or `caller_did` is not a well-formed DID.
/// * `SCP-TOOL-6101` — `(context, request_id_hex)` does not match any
///   active stream registry entry.
/// * `SCP-PERM-3001` — `caller_did` is not the stream's pinned invoker.
#[wasm_bindgen(js_name = "outletStreamCancel")]
pub fn outlet_stream_cancel(
    context: &WasmContextHandle,
    request_id_hex: String,
    caller_did: String,
) -> Promise {
    // SCP-OUT-037 W4: validate the addressing inputs at the FFI boundary.
    if let Err(e) = validate_request_id_hex(&request_id_hex) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    if let Err(e) = validate_did(&caller_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = context.context_id();
    future_to_promise(async move {
        let recorded =
            with_manager(|mgr| mgr.outlet_stream_cancel(&context_id, &request_id_hex, &caller_did))
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

/// Wire-stable integer code for the `RevokedMidStream` variant of
/// [`scp_protocol::context::outlets::stream::TerminateReason`].
///
/// What the WASM bridge accepts on the `outletStreamTerminate` surface.
/// The TypeScript SDK exports these constants so callers reference them
/// by name (`TERMINATE_REASON_REVOKED_MID_STREAM`) rather than magic
/// numbers. New variants MUST allocate a fresh monotonically-increasing
/// code; reusing a retired code would silently re-route past stream-
/// termination call sites.
pub const TERMINATE_REASON_REVOKED_MID_STREAM: u32 = 0;
/// `execution.cancel-ack-timeout` wire-stable code (§5.4.5).
pub const TERMINATE_REASON_CANCEL_ACK_TIMEOUT: u32 = 1;
/// `execution.credit-stall` wire-stable code (§5.4.5).
pub const TERMINATE_REASON_CREDIT_STALL: u32 = 2;
/// `protocol.context-closed-mid-stream` wire-stable code (§5.4.5
/// round 8 — `SCP-TOOL-6101`, Protocol class). The hosting context was
/// closed or the operator evicted/left while the stream was active.
pub const TERMINATE_REASON_CONTEXT_CLOSED_MID_STREAM: u32 = 3;
/// `execution.credit-exhausted` wire-stable code (§5.4.5:758 —
/// `SCP-TOOL-6131`, Execution class).
///
/// The HARD cumulative billable-chunk ceiling (`min(credit_window,
/// max_calls)`) was reached: no further billable chunk may flow regardless
/// of executor behavior, and no credit grant can raise the cap. Lets the
/// receiver-side framework re-check loop surface the same terminal cause
/// the lazy `outlet_stream_next` gate emits internally.
pub const TERMINATE_REASON_CREDIT_EXHAUSTED: u32 = 4;

fn terminate_reason_from_u32(
    code: u32,
) -> Result<scp_protocol::context::outlets::stream::TerminateReason, ScpWasmError> {
    use scp_protocol::context::outlets::stream::TerminateReason;
    // Total over the §5.4.5 closed `TerminateReason` set: every protocol
    // variant has a wire-stable WASM code, so the WASM bridge can surface
    // any framework-initiated termination cause the native bridges can —
    // including the R3 `CreditExhausted` (`SCP-TOOL-6131`) the TypeScript
    // `TerminateReasonSlug` exhaustiveness check depends on. New protocol
    // variants MUST allocate a fresh monotonically-increasing code here;
    // reusing a retired code would silently re-route past callers.
    match code {
        TERMINATE_REASON_REVOKED_MID_STREAM => Ok(TerminateReason::RevokedMidStream),
        TERMINATE_REASON_CANCEL_ACK_TIMEOUT => Ok(TerminateReason::CancelAckTimeout),
        TERMINATE_REASON_CREDIT_STALL => Ok(TerminateReason::CreditStall),
        TERMINATE_REASON_CONTEXT_CLOSED_MID_STREAM => Ok(TerminateReason::ContextClosedMidStream),
        TERMINATE_REASON_CREDIT_EXHAUSTED => Ok(TerminateReason::CreditExhausted),
        _ => Err(ScpWasmError::Validation {
            message: format!(
                "unknown TerminateReason code {code}; expected 0 (RevokedMidStream), \
                 1 (CancelAckTimeout), 2 (CreditStall), 3 (ContextClosedMidStream), or \
                 4 (CreditExhausted) (§5.4.4 closed set)"
            ),
            code: codes::VALID_7000.to_owned(),
        }),
    }
}

/// Forces a terminal `Error{terminal:true}` chunk into the active stream
/// identified by `request_id_hex` (§5.4.5 framework-initiated stream
/// termination).
///
/// Routes through
/// [`crate::manager::WasmContextManager::outlet_stream_terminate`] —
/// because WASM has no executor pump, the manager pushes a synthetic
/// terminal chunk into the pre-materialised queue under the per-session
/// signing key. The next `outlet_stream_next` delivers the synthetic
/// terminal; the one after that resolves to `None` and evicts the
/// session.
///
/// `reason` is a wire-stable `u32` code matching one of:
/// - [`TERMINATE_REASON_REVOKED_MID_STREAM`] (0) — periodic UCAN
///   re-check observed token revoked since stream open.
/// - [`TERMINATE_REASON_CANCEL_ACK_TIMEOUT`] (1) — executor failed to
///   emit a terminal chunk within `stream_cancel_ack_secs`.
/// - [`TERMINATE_REASON_CREDIT_STALL`] (2) — credit window remained at
///   zero past `stream_credit_stall_secs`.
/// - [`TERMINATE_REASON_CONTEXT_CLOSED_MID_STREAM`] (3) — hosting context
///   closed or operator evicted/left while the stream was active.
/// - [`TERMINATE_REASON_CREDIT_EXHAUSTED`] (4) — §5.4.5:758 HARD
///   cumulative billable-chunk ceiling reached; no further billable chunk
///   may flow and no grant can raise the cap.
///
/// Unknown codes are rejected with a `Validation` error. The canonical
/// §5.4.4 slug + code carried by the synthetic chunk are derived
/// from the matched enum — never caller-supplied. `message_override`
/// (the only caller-controlled string) is appended as a human suffix
/// after the canonical slug prefix; passing `null` / `undefined`
/// uses the spec's default message.
///
/// Returns a JS `Promise<void>` — resolves on success.
///
/// # Errors
///
/// * `SCP-VALID-7000` — `request_id_hex` is not 32 lowercase hex
///   characters, `caller_did` is not a well-formed DID, or `reason` is
///   not in the closed `TerminateReason` set.
/// * `SCP-TOOL-6101` — `(context, request_id_hex)` does not match any
///   active stream registry entry (`protocol.unknown-session`).
/// * `SCP-PERM-3001` — `caller_did` is not the stream's pinned invoker.
#[wasm_bindgen(js_name = "outletStreamTerminate")]
pub fn outlet_stream_terminate(
    context: &WasmContextHandle,
    request_id_hex: String,
    caller_did: String,
    reason: u32,
    message_override: Option<String>,
) -> Promise {
    // SCP-OUT-037 W4: validate the addressing inputs at the FFI boundary.
    if let Err(e) = validate_request_id_hex(&request_id_hex) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    if let Err(e) = validate_did(&caller_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = context.context_id();
    future_to_promise(async move {
        let reason_variant = terminate_reason_from_u32(reason).map_err(ScpWasmError::into_js)?;
        with_manager(|mgr| {
            mgr.outlet_stream_terminate(
                &context_id,
                &request_id_hex,
                &caller_did,
                reason_variant,
                message_override.as_deref(),
            )
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
        // SCP-OUT-037 W4: do NOT echo the serde error (`{e}`) — it can
        // reflect raw `chunk_json` bytes (covert channel / log-injection
        // per ADR-049 §4). Fixed, input-free message; keep VALID_7000.
        let chunk: OutletStreamChunk = serde_json::from_str(&chunk_json).map_err(|_| {
            ScpWasmError::Validation {
                message: "chunk_json is not a valid OutletStreamChunk".to_owned(),
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
        // SCP-OUT-037 W4: scrub serde `{e}` echoes — they can reflect
        // raw `effective_caveats_json` bytes (ADR-049 §4). Fixed,
        // input-free messages; keep VALID_7000.
        let caveats_value: serde_json::Value = serde_json::from_str(&effective_caveats_json)
            .map_err(|_| {
                ScpWasmError::Validation {
                    message: "effective_caveats_json is not valid JSON".to_owned(),
                    code: codes::VALID_7000.to_owned(),
                }
                .into_js()
            })?;
        let caveats: InvocationCaveats = serde_json::from_value(caveats_value).map_err(|_| {
            ScpWasmError::Validation {
                message: "effective_caveats_json does not match the InvocationCaveats shape"
                    .to_owned(),
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

/// Enforces the §7.3.8 caveat set that the WASM bridge is capable of
/// enforcing on a STREAMING outlet open, from the action UCAN's
/// VALIDATED-NARROWED `nb` caveat set, and returns the HARD billable-chunk
/// ceiling (`max_billable`) the session must pin.
///
/// # Parity with the native streaming bridges
///
/// The native (`PyO3` / `NAPI` / `UniFFI`) streaming path extracts
/// `ucan_token.payload.nb` into `effective_caveats` and hands it to the
/// runtime's `open_outlet_stream`, which:
///
/// - folds `max_calls` into the EFFECTIVE billable-chunk ceiling (the
///   runtime's `effective_max_billable_chunks` in
///   `crates/scp-runtime/src/context/outlets/stream.rs`) and REJECTS an
///   over-declared estimate via that module's
///   `enforce_estimated_chunk_count_bound` (`estimated_chunk_count >
///   min(credit_window, max_calls)` → `EstimateExceedsBound`), and
/// - runs the synchronous [`InvocationCaveats::check_invocation_local`]
///   gate plus the durable counter CAS for the three counter-bearing
///   caveats (`max_calls` / `amount_max_cumulative` / `rate_window`).
///
/// # What the WASM bridge enforces here
///
/// WASM has no async runtime and NO durable counter store (ADR-034), so:
///
/// 1. **Synchronous non-counter caveats** (`input_schema` /
///    `amount_max_per_call` / `allowed_adapters` / `allowed_target_dids`)
///    are enforced via `check_invocation_local` with `estimated_cost = 0`,
///    `negotiated_adapter = None`, and `target_did = None` — the WASM
///    streaming open is in-context (no cross-context peer-DID parameter on
///    the `outletInvokeStream` surface), exactly mirroring the in-context
///    single-shot path.
/// 2. **`max_calls`** is a WITHIN-stream chunk ceiling enforceable WITHOUT
///    durable state — it bounds the chunk COUNT of THIS stream, not a
///    cross-invocation counter. The bridge REJECTS an over-declared
///    `estimated_chunk_count > max_calls` (mirroring the native
///    `EstimateExceedsBound` reject — never a silent clamp) and pins
///    `max_billable = min(estimated_chunk_count, max_calls)` as the HARD
///    cumulative cap on billable `Data` chunks.
/// 3. **`rate_window` and `amount_max_cumulative`** require durable
///    cross-invocation state WASM does not have — they FAIL CLOSED (reject
///    the open). `amount_max_cumulative` is doubly moot (WASM rejects paid
///    contexts up front with `SCP-ECON-12096`), but failing closed here is
///    what guarantees a `rate_window`-bearing token is never silently
///    admitted on the streaming path.
///
/// `max_calls` is NOT lumped into the blanket
/// [`InvocationCaveats::has_counter_bearing_caveat`] fail-closed rejection
/// the single-shot path uses: a single-shot invocation counts as "the one
/// call", so any `max_calls` it carries is a cross-invocation count WASM
/// cannot track and must reject; a STREAM, by contrast, is the unit
/// `max_calls` was authored to bound (the native streaming path enforces it
/// statelessly as the chunk ceiling), so the bridge enforces it directly
/// rather than rejecting.
///
/// Returns the `max_billable` ceiling (`Some(n)` when a `max_calls` caveat
/// is present and was satisfied by the declared estimate; `None` when no
/// `max_calls` caveat exists — unbounded, matching the runtime's
/// `max_billable = None` semantics). The returned ceiling is the value the
/// session pins; `outlet_stream_next` terminates the stream once
/// `billed_emitted` reaches it.
///
/// # Errors
///
/// * `ScpWasmError::Permission` (`SCP-PERM-3000`) — a synchronous caveat
///   rejected, `estimated_chunk_count > max_calls`, or a counter-bearing
///   caveat (`rate_window` / `amount_max_cumulative`) the WASM bridge
///   cannot enforce is present (fail-closed).
fn enforce_stream_open_caveats(
    ucan_token: &str,
    input: &serde_json::Value,
    estimated_chunk_count: Option<u32>,
) -> Result<Option<u32>, ScpWasmError> {
    use scp_protocol::economy::types::Amount;

    // Recover the VALIDATED-NARROWED `nb`. The token was already parsed and
    // validated by `validate_outlet_ucan_wasm` above; re-parse to read its
    // `nb`. A token with no `nb` carries no caveats — the legacy
    // unbounded-but-SDK-advisory behaviour (no `max_calls` → `None`).
    let parsed = scp_protocol::crypto::ucan::validate::parse_ucan(ucan_token).map_err(|e| {
        ScpWasmError::Permission {
            message: format!("failed to parse action UCAN: {e}"),
            code: codes::PERM_3000.to_owned(),
        }
    })?;
    let Some(caveats) = parsed.payload.nb.as_ref() else {
        // No caveats at all — no `max_calls` ceiling to pin (unbounded,
        // matching the runtime's `max_billable = None`).
        return Ok(None);
    };

    // FAIL CLOSED on the durable-state-requiring caveats WASM cannot
    // enforce (`rate_window` / `amount_max_cumulative`). `max_calls` is
    // deliberately EXCLUDED from this gate — it is enforceable statelessly
    // as the within-stream chunk ceiling below.
    if caveats.rate_window.is_some() || caveats.amount_max_cumulative.is_some() {
        return Err(ScpWasmError::Permission {
            message: "stream open rejected: action UCAN carries a durable counter-bearing \
                      caveat (rate_window / amount_max_cumulative) that the WASM bridge \
                      cannot enforce — no durable counter store (ADR-034). Failing closed \
                      (§7.3.8 authorization.denied)."
                .to_owned(),
            code: codes::PERM_3000.to_owned(),
        });
    }

    // Synchronous non-counter caveats: input_schema / amount_max_per_call /
    // allowed_adapters / allowed_target_dids. In-context streaming open —
    // no cross-context target DID and no negotiated adapter, parity with the
    // in-context single-shot path (`estimated_cost: 0`).
    caveats
        .check_invocation_local(input, Amount::new(0), None, None)
        .map_err(|e| ScpWasmError::Permission {
            message: format!("stream open rejected by §7.3.8 caveat ({}): {e}", e.slug()),
            code: codes::PERM_3000.to_owned(),
        })?;

    // `max_calls` (within-stream chunk ceiling). When present, REJECT an
    // over-declared estimate (`estimated_chunk_count > max_calls`) rather
    // than silently clamping — mirroring the native
    // `enforce_estimated_chunk_count_bound` → `EstimateExceedsBound` reject.
    // Pin `max_billable = min(estimated_chunk_count, max_calls)`; the
    // declared estimate is NOT used as the ceiling when a validated
    // `max_calls` exists.
    let Some(raw_max_calls) = caveats.max_calls else {
        // No `max_calls` caveat — unbounded ceiling (runtime parity).
        return Ok(None);
    };
    // Coerce the `u64` caveat to the session's `u32` ceiling, matching the
    // runtime's `u32::try_from(n).unwrap_or(u32::MAX)` saturation.
    let max_calls_u32 = u32::try_from(raw_max_calls).unwrap_or(u32::MAX);
    match estimated_chunk_count {
        Some(declared) if declared > max_calls_u32 => Err(ScpWasmError::Permission {
            message: format!(
                "stream open rejected: estimated_chunk_count ({declared}) exceeds the \
                 validated max_calls caveat ({max_calls_u32}) (§7.3.8 / §5.4.5 \
                 input.estimate-exceeds-bound)"
            ),
            code: codes::PERM_3000.to_owned(),
        }),
        // Declared estimate within bound — pin min(estimate, max_calls).
        Some(declared) => Ok(Some(declared.min(max_calls_u32))),
        // No declared estimate — the validated `max_calls` IS the ceiling
        // (runtime parity: `declared.unwrap_or(max_calls)`).
        None => Ok(Some(max_calls_u32)),
    }
}

/// Decodes a 64-char lowercase hex string into a 32-byte
/// `caveats_binding`. Returns `ScpWasmError::Validation` on bad hex /
/// length.
fn decode_caveats_binding(hex_str: &str) -> Result<[u8; 32], ScpWasmError> {
    // SCP-OUT-037 W4: `hex::FromHexError` Display includes the offending
    // character / position — echoing it reflects raw input bytes back to
    // the caller (ADR-049 §4). Surface a fixed, input-free message and
    // keep VALID_7000.
    let bytes = hex::decode(hex_str).map_err(|_| ScpWasmError::Validation {
        message: "caveats_binding_hex must be 64 lowercase hex characters".to_owned(),
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

// ---------------------------------------------------------------------------
// Tests — SCP-OUT-037 W4 (parse-error scrub on pure helpers)
// ---------------------------------------------------------------------------
//
// The `#[wasm_bindgen]` control-plane functions return JS `Promise`s and
// require a JS host to drive end-to-end (the request_id_hex / caller_did
// boundary validation and context-keyed routing are exercised through
// `bindings/typescript` integration tests against the built WASM
// package). What IS unit-testable natively here are the pure parse
// helpers and the shared validator the bridge calls — W4's core
// guarantee is that none of these echo raw input bytes back to the
// caller.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// W4: a malformed `caveats_binding_hex` is rejected with
    /// `VALID_7000` and the error message contains NO raw input bytes
    /// (the previous `: {e}` echo of `hex::FromHexError` reflected the
    /// offending character/position).
    #[test]
    fn w4_decode_caveats_binding_error_is_input_free() {
        // Non-hex characters that, if echoed, would appear verbatim.
        let malicious = "ZZZZ<script>alert(1)</script>padpadpadpadpadpadpadpadpadpadpad";
        let err = decode_caveats_binding(malicious).unwrap_err();
        match err {
            ScpWasmError::Validation { code, message } => {
                assert_eq!(code, codes::VALID_7000);
                assert!(
                    !message.contains("script") && !message.contains('Z'),
                    "W4: error message must NOT echo raw input bytes, got: {message}"
                );
            }
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    /// W4: the shared `validate_request_id_hex` (called at the top of
    /// grant/cancel/terminate before the `request_id` is used to key the
    /// registry) rejects a malformed `request_id`, and the bridge maps
    /// it to `VALID_7000`. This pins the validator the bridge funnels
    /// through; the validator's full character/length matrix lives in
    /// `scp-ffi-common`.
    #[test]
    fn w4_request_id_hex_rejection_maps_to_valid_7000() {
        // Right length (32), wrong alphabet.
        let bad_alphabet = "g".repeat(REQUEST_ID_HEX_LEN_FOR_TEST);
        let err = ScpWasmError::from(validate_request_id_hex(&bad_alphabet).unwrap_err());
        match err {
            ScpWasmError::Validation { code, .. } => {
                assert_eq!(
                    code,
                    codes::VALID_7000,
                    "W4: malformed request_id maps to VALID_7000 at the bridge boundary"
                );
            }
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    /// W4: the length branch of `validate_request_id_hex` reports only a
    /// character COUNT, never the raw input content — so a too-short
    /// `request_id` carrying injection-shaped bytes cannot be reflected.
    /// (The alphabet branch's `{s:?}` echo for a *correct-length* string
    /// is the shared validator's contract in `scp-ffi-common`, bounded
    /// to 32 chars and outside the WASM bridge's scope; the WASM W4
    /// guarantee covers the bridge's own parse helpers and the
    /// length/control branches it relies on.)
    #[test]
    fn w4_request_id_hex_length_branch_is_input_free() {
        let too_short = "<script>xx"; // 10 chars, wrong length
        let err = ScpWasmError::from(validate_request_id_hex(too_short).unwrap_err());
        match err {
            ScpWasmError::Validation { code, message } => {
                assert_eq!(code, codes::VALID_7000);
                assert!(
                    !message.contains("script"),
                    "length-branch message must not echo the raw input, got: {message}"
                );
            }
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    /// Local mirror of `scp_ffi_common::validate::REQUEST_ID_HEX_LEN`
    /// (32) for the alphabet-branch test fixture — keeps the test
    /// self-contained without re-exporting the const through the bridge.
    const REQUEST_ID_HEX_LEN_FOR_TEST: usize = 32;

    // -----------------------------------------------------------------------
    // enforce_stream_open_caveats — §7.3.8 / §5.4.5 streaming-open caveat
    // enforcement (WASM subset). The helper is the native-testable core of
    // the `outlet_invoke_stream` `#[wasm_bindgen]` entry point (which returns
    // a JS Promise and needs a JS host). It parses the VALIDATED-NARROWED
    // `nb` from the UCAN token, enforces the synchronous non-counter caveats,
    // clamps the billable ceiling to `max_calls` (rejecting an over-declared
    // estimate), and FAILS CLOSED on the durable counter-bearing caveats WASM
    // cannot enforce (`rate_window` / `amount_max_cumulative`, ADR-034).
    // -----------------------------------------------------------------------

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use scp_protocol::crypto::ucan::{Attenuation, UcanHeader, UcanPayload};
    use scp_protocol::economy::types::Amount;
    use scp_protocol::trust::caveats::{InvocationCaveats, RateWindow};

    /// Builds a structurally-valid JWT-encoded UCAN carrying the given `nb`
    /// caveats. `parse_ucan` (which `enforce_stream_open_caveats` calls)
    /// decodes only — it does NOT verify the signature (that happens in the
    /// separate validation pipeline `validate_outlet_ucan_wasm` runs before
    /// this helper), so a dummy 64-byte signature is sufficient for the
    /// parse-and-enforce path under test.
    fn token_with_caveats(nb: Option<InvocationCaveats>) -> String {
        let header = UcanHeader::new();
        let payload = UcanPayload {
            iss: "did:key:zIssuer".to_owned(),
            aud: "did:key:zAudience".to_owned(),
            exp: 9_999_999_999,
            nbf: None,
            nnc: "0-00000000000000000000000000000000".to_owned(),
            att: vec![Attenuation {
                with: "scp:ctx:test/outlet_call:*".to_owned(),
                can: "*".to_owned(),
            }],
            prf: Vec::new(),
            fct: None,
            nb,
        };
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let sig_b64 = URL_SAFE_NO_PAD.encode([0u8; 64]);
        format!("{header_b64}.{payload_b64}.{sig_b64}")
    }

    #[test]
    fn stream_open_caveats_no_nb_is_unbounded() {
        // A token with no `nb` carries no caveats — no max_calls ceiling to
        // pin (None = unbounded, runtime `max_billable = None` parity).
        let token = token_with_caveats(None);
        let ceiling =
            enforce_stream_open_caveats(&token, &serde_json::json!({}), Some(10)).unwrap();
        assert_eq!(ceiling, None, "no nb → unbounded ceiling");
    }

    #[test]
    fn stream_open_caveats_empty_nb_is_unbounded() {
        // An explicit-but-empty caveat set has no max_calls → unbounded.
        let token = token_with_caveats(Some(InvocationCaveats::empty()));
        let ceiling =
            enforce_stream_open_caveats(&token, &serde_json::json!({}), Some(10)).unwrap();
        assert_eq!(ceiling, None, "empty nb → unbounded ceiling");
    }

    #[test]
    fn stream_open_caveats_pins_ceiling_to_max_calls() {
        // A valid in-bounds open: estimated_chunk_count (3) <= max_calls (5).
        // The pinned ceiling MUST be min(estimate, max_calls) = 3.
        let token = token_with_caveats(Some(InvocationCaveats {
            max_calls: Some(5),
            ..InvocationCaveats::empty()
        }));
        let ceiling = enforce_stream_open_caveats(&token, &serde_json::json!({}), Some(3)).unwrap();
        assert_eq!(
            ceiling,
            Some(3),
            "in-bounds estimate pins min(estimate, max_calls)"
        );
    }

    #[test]
    fn stream_open_caveats_no_estimate_pins_max_calls() {
        // No declared estimate: the validated max_calls IS the ceiling
        // (runtime `declared.unwrap_or(max_calls)` parity).
        let token = token_with_caveats(Some(InvocationCaveats {
            max_calls: Some(7),
            ..InvocationCaveats::empty()
        }));
        let ceiling = enforce_stream_open_caveats(&token, &serde_json::json!({}), None).unwrap();
        assert_eq!(
            ceiling,
            Some(7),
            "absent estimate → max_calls is the ceiling"
        );
    }

    #[test]
    fn stream_open_caveats_rejects_estimate_over_max_calls() {
        // The HIGH gap: an over-declared estimate (8 > max_calls 2) MUST be
        // REJECTED, not silently clamped — native EstimateExceedsBound parity.
        let token = token_with_caveats(Some(InvocationCaveats {
            max_calls: Some(2),
            ..InvocationCaveats::empty()
        }));
        let err = enforce_stream_open_caveats(&token, &serde_json::json!({}), Some(8)).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("estimate") && msg.contains("max_calls"),
            "over-declared estimate must be rejected (not clamped): {msg}"
        );
    }

    #[test]
    fn stream_open_caveats_rate_window_fails_closed() {
        // rate_window is a durable counter-bearing caveat WASM cannot enforce
        // (no counter store, ADR-034) → fail closed on the open.
        let token = token_with_caveats(Some(InvocationCaveats {
            rate_window: Some(RateWindow {
                max: 5,
                window_secs: 60,
            }),
            ..InvocationCaveats::empty()
        }));
        let err = enforce_stream_open_caveats(&token, &serde_json::json!({}), Some(3)).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("counter-bearing") && msg.contains("rate_window"),
            "rate_window must fail closed on the streaming open: {msg}"
        );
    }

    #[test]
    fn stream_open_caveats_amount_max_cumulative_fails_closed() {
        // amount_max_cumulative is counter-bearing → fail closed (doubly moot
        // since WASM rejects paid contexts up front, but the gate guarantees
        // it can never be silently admitted).
        let token = token_with_caveats(Some(InvocationCaveats {
            amount_max_cumulative: Some(Amount::new(1000)),
            ..InvocationCaveats::empty()
        }));
        let err = enforce_stream_open_caveats(&token, &serde_json::json!({}), Some(3)).unwrap_err();
        assert!(format!("{err:?}").contains("counter-bearing"));
    }

    #[test]
    fn stream_open_caveats_input_schema_rejects_off_schema_input() {
        // Synchronous input_schema caveat: narrowed schema requires integer
        // `n` >= 10. Conforming input is admitted; off-schema input rejected.
        let nb = InvocationCaveats {
            input_schema: Some(serde_json::json!({
                "type": "object",
                "properties": { "n": { "type": "integer", "minimum": 10 } },
                "required": ["n"]
            })),
            max_calls: Some(4),
            ..InvocationCaveats::empty()
        };
        let token = token_with_caveats(Some(nb));
        // Conforming input within bound → admitted, ceiling pinned.
        let ceiling =
            enforce_stream_open_caveats(&token, &serde_json::json!({ "n": 10 }), Some(2)).unwrap();
        assert_eq!(ceiling, Some(2));
        // Off-schema input → rejected.
        let err = enforce_stream_open_caveats(&token, &serde_json::json!({ "n": 1 }), Some(2))
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("PERM-3000") || msg.to_lowercase().contains("caveat"),
            "off-schema input must be rejected: {msg}"
        );
    }

    #[test]
    fn stream_open_caveats_allowed_target_dids_rejects_in_context_open() {
        // allowed_target_dids on an IN-CONTEXT streaming open (target_did =
        // None): a non-empty allow-list opts the chain into target-restricted
        // operation, so an open with no target DID is rejected — parity with
        // check_invocation_local's "absent target against a non-empty list is
        // a rejection" rule.
        let allowed = scp_event_log::DID::from("did:key:allowed".to_owned());
        let token = token_with_caveats(Some(InvocationCaveats {
            allowed_target_dids: Some(vec![allowed]),
            ..InvocationCaveats::empty()
        }));
        let err = enforce_stream_open_caveats(&token, &serde_json::json!({}), Some(2)).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("PERM-3000") || msg.to_lowercase().contains("caveat"),
            "allowed_target_dids must bite on the in-context open: {msg}"
        );
    }
}
