//! NAPI streaming bridge for outlets — `SCP-OUT-037` (NAPI portion).
//!
//! Mirrors the `PyO3` streaming module at
//! `crates/scp-ffi/src/outlet_stream.rs`. Exposes §5.4.5 progressive-output
//! streaming to TypeScript / Node.js / Bun:
//!
//! - [`context_outlet_invoke_stream`] — Opens a §5.4.5 stream session and
//!   returns a [`NapiOutletInvocationStream`] class whose async `next()`
//!   yields one [`OutletStreamChunk`] per call (or `None` at terminal /
//!   close) and whose `request_id` getter exposes the §5.4.5 16-byte
//!   `request_id` rendered as 32-char lowercase hex.
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
//! Active streams are tracked in a per-bridge `outlet_stream_registry` on
//! [`crate::runtime::NapiBridgeInstance`] (NOT a process-global — ADR-048
//! §1) keyed by the §5.4.5 16-byte `request_id` (rendered as 32-char
//! lowercase hex at the FFI boundary). Each entry holds the
//! [`scp_runtime::context::outlets::dispatch::StreamSessionHandle`]
//! returned by
//! [`scp_runtime::context::manager::ContextManager::open_outlet_stream`]
//! plus the local monotonic-grant counter and the credit-grant signing
//! material.
//!
//! Cleanup: each entry is removed from the registry when the streaming
//! pump task observes a terminal chunk (End / Error{terminal:true}) or
//! when the receiver closes — see [`NapiOutletInvocationStream::next`]
//! below.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use dashmap::DashMap;
use ed25519_dalek::SigningKey;
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use scp_core::context::outlets::stream::{
    self as proto_stream, ChunkPayload, CreditGrantSigningInputs, OutletStreamChunk,
    OutletStreamCredit,
};
use scp_ffi_common::error_codes as codes;
use scp_protocol::trust::caveats::InvocationCaveats;
use serde_json::Value;
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::mpsc;

use crate::context::NapiContextHandle;
use crate::error::ScpNapiError;

// ---------------------------------------------------------------------------
// Stream registry
// ---------------------------------------------------------------------------

/// One entry in the per-bridge stream registry.
///
/// Holds the [`scp_runtime::context::outlets::dispatch::StreamSessionHandle`]
/// (the runtime control surface), the local monotonic-grant counter
/// (strictly increasing per §5.4.5), and the §5.4.5
/// `SCP-OUTLET-CREDIT-V1:` preimage inputs that every grant signature
/// must commit to: the pinned `(context_id, outlet_id, stream_epoch,
/// caveats_binding)` plus the invoker's `SigningKey`.
pub(crate) struct StreamRegistryEntry {
    /// Control-plane handle returned by the runtime at open. Wrapped in
    /// an outer `Mutex` so the FFI grant/cancel calls can take
    /// exclusive ownership of `apply_credit_grant` /
    /// `apply_outlet_cancel` while the streaming pump task drains the
    /// receiver concurrently. (The handle's own state is already
    /// inner-mutex protected; this guard is here purely so the FFI
    /// path can call `&self` methods on the handle without contending
    /// with itself across worker threads.)
    pub handle: Mutex<scp_runtime::context::outlets::dispatch::StreamSessionHandle>,
    /// Strictly-monotonic counter incremented on every accepted grant
    /// (§5.4.5 round-5 grant signature preimage). Initial state is
    /// `0`; the first grant uses `1` and so on so the first
    /// `seen_seq` in the runtime tracker advances from `None` to
    /// `Some(1)`.
    pub monotonic_seq: Mutex<u64>,
    /// Hosting context id pinned at acceptance — committed into every
    /// `SCP-OUTLET-CREDIT-V1:` grant preimage.
    pub context_id: String,
    /// Outlet id pinned at acceptance — committed into every grant
    /// preimage.
    pub outlet_id: String,
    /// MLS epoch counter pinned at acceptance — committed into every
    /// grant preimage.
    pub stream_epoch: u64,
    /// 32-byte `caveats_binding` pinned at acceptance — committed into
    /// every grant preimage.
    pub caveats_binding: [u8; 32],
    /// Invoker's Ed25519 signing key — used to sign every grant. The
    /// runtime tracker pins the corresponding verifying key at open;
    /// every grant signature must verify under that pinned key.
    pub invoker_signing_key: SigningKey,
    /// Pinned invoker DID. The control-plane bridge functions
    /// (`grant_credit`, `cancel`, `terminate`) verify `caller_did`
    /// matches this before signing. CRITICAL #1 fix.
    pub invoker_did: String,
    /// 16-byte `request_id` (the registry key in raw form).
    pub request_id: [u8; 16],
}

/// Returns a reference to the per-bridge stream registry on the
/// default [`crate::runtime::NapiBridgeInstance`]. Per ADR-048 the
/// registry lives on the bridge instance (not as a process-global)
/// so multi-instance fallback / shutdown clearing works uniformly.
fn registry() -> Result<Arc<DashMap<String, Arc<StreamRegistryEntry>>>, ScpNapiError> {
    let bi =
        crate::runtime::default_bridge_instance_raw().ok_or_else(|| ScpNapiError::Context {
            message: "bridge instance not initialised".to_owned(),
            code: codes::CTX_2000.to_owned(),
        })?;
    Ok(Arc::clone(bi.outlet_stream_registry()))
}

/// Renders a `request_id` (16 raw bytes) as 32-char lowercase hex —
/// the registry key. Stable across all calls because `hex::encode`
/// emits lowercase digits without separators.
fn request_id_hex(request_id: &[u8; 16]) -> String {
    hex::encode(request_id)
}

/// Removes an entry from the registry — called by the streaming pump
/// task on terminal-chunk emission. Idempotent: missing keys are a
/// no-op so a duplicate cancel + terminal cannot double-evict. A
/// missing bridge instance is also a no-op (during shutdown the
/// instance may already be gone; the entry it would have evicted is
/// already gone with it).
pub(crate) fn evict_request(request_id_hex: &str) {
    if let Ok(reg) = registry() {
        reg.remove(request_id_hex);
    }
}

// ---------------------------------------------------------------------------
// JS-shaped chunk record
// ---------------------------------------------------------------------------

/// One chunk yielded by [`NapiOutletInvocationStream::next`].
///
/// Mirrors the §5.4.5 wire form on a per-variant basis so SDK callers
/// can branch on `payload_type` and read variant fields directly
/// without an extra translation step. Discriminator is `payloadType`
/// (the SDK-friendly `camelCase` variant of the wire `@type`
/// discriminator).
///
/// `sequence` and `execution_time_ms` are protocol-level `u64` values;
/// the bridge surfaces them as `f64` because:
/// - `sequence` is bounded by `credit_window` (default 32) and per-
///   stream resets, so practical values stay well inside
///   `Number.MAX_SAFE_INTEGER` (`2^53`).
/// - `execution_time_ms` is wall-clock millis; `2^53` ms ≈ 285,000
///   years, so the lossless range covers any conceivable invocation.
/// This convention matches the NAPI event-log bridge's `sequence: f64`
/// shape so SDK consumers see one numeric type across event log and
/// stream surfaces.
#[napi(object, js_name = "OutletStreamChunk")]
pub struct NapiOutletStreamChunk {
    /// 16-byte §5.4.5 `request_id` of the stream this chunk belongs to.
    pub request_id: Buffer,
    /// Strictly-monotonic per-stream chunk sequence number. Advances
    /// by one per emitted chunk. Mapped from runtime `u64` to JS
    /// `number` (see struct doc).
    pub sequence: f64,
    /// 64-byte `SCP-OUTLET-CHUNK-SIG-V1:` Ed25519 signature.
    pub sig: Buffer,
    /// Discriminator: `"data"` / `"progress"` / `"end"` / `"error"`.
    pub payload_type: String,
    /// `data` payload — JSON-encoded payload value.
    pub value_json: Option<String>,
    /// `progress` payload — completion percentage in `[0.0, 1.0]`.
    pub pct: Option<f64>,
    /// `progress` payload — optional human-readable note.
    pub note: Option<String>,
    /// `end` payload — JSON-encoded aggregate output value.
    pub aggregate_json: Option<String>,
    /// `end` payload — JSON-encoded per-chunk provenance block.
    pub provenance_json: Option<String>,
    /// `end` payload — total wall-clock execution time in
    /// milliseconds. Mapped from runtime `u64` to JS `number` (see
    /// struct doc).
    pub execution_time_ms: Option<f64>,
    /// `error` payload — stable error code (e.g.
    /// `SCP-AUTH-7100`).
    pub code: Option<String>,
    /// `error` payload — human-readable error message.
    pub message: Option<String>,
    /// `error` payload — `true` for terminal errors that close the
    /// stream, `false` for non-terminal warnings.
    pub terminal: Option<bool>,
}

/// Converts a runtime [`OutletStreamChunk`] to the JS-facing shape.
fn chunk_to_napi(chunk: &OutletStreamChunk) -> Result<NapiOutletStreamChunk, ScpNapiError> {
    // `chunk.sequence` is a runtime `u64`. Cast through `f64` matches
    // the JS-side numeric convention; `2^53` is the lossless ceiling
    // and per-stream sequences are bounded by `credit_window` so the
    // practical maximum is far below that.
    #[allow(clippy::cast_precision_loss)]
    let sequence = chunk.sequence as f64;
    let request_id = Buffer::from(chunk.request_id.to_vec());
    let sig = Buffer::from(chunk.sig.to_vec());
    // Variant-specific fields. Bracketed in their own scope so the
    // outer construction is one expression — avoids the clippy
    // `assigning_clones` warning (the prior version mutated a
    // pre-built struct field-by-field).
    let (
        payload_type,
        value_json,
        pct,
        note,
        aggregate_json,
        provenance_json,
        execution_time_ms,
        code,
        message,
        terminal,
    ) = match &chunk.payload {
        ChunkPayload::Data { value } => (
            "data".to_owned(),
            Some(
                serde_json::to_string(value).map_err(|e| ScpNapiError::Tool {
                    message: format!("failed to serialise data value: {e}"),
                    code: codes::TOOL_6006.to_owned(),
                })?,
            ),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        ChunkPayload::Progress { pct, note } => (
            "progress".to_owned(),
            None,
            Some(f64::from(*pct)),
            note.clone(),
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        ChunkPayload::End {
            aggregate,
            provenance,
            execution_time_ms,
        } => {
            let aggregate_json =
                serde_json::to_string(aggregate).map_err(|e| ScpNapiError::Tool {
                    message: format!("failed to serialise aggregate: {e}"),
                    code: codes::TOOL_6006.to_owned(),
                })?;
            let provenance_json =
                serde_json::to_string(provenance).map_err(|e| ScpNapiError::Tool {
                    message: format!("failed to serialise provenance: {e}"),
                    code: codes::TOOL_6006.to_owned(),
                })?;
            // Same `u64 -> f64` cast as `sequence`. `2^53` ms is
            // ~285,000 years; any realistic invocation fits.
            #[allow(clippy::cast_precision_loss)]
            let exec_ms = *execution_time_ms as f64;
            (
                "end".to_owned(),
                None,
                None,
                None,
                Some(aggregate_json),
                Some(provenance_json),
                Some(exec_ms),
                None,
                None,
                None,
            )
        }
        ChunkPayload::Error {
            code,
            message,
            terminal,
        } => (
            "error".to_owned(),
            None,
            None,
            None,
            None,
            None,
            None,
            Some(code.clone()),
            Some(message.clone()),
            Some(*terminal),
        ),
    };
    Ok(NapiOutletStreamChunk {
        request_id,
        sequence,
        sig,
        payload_type,
        value_json,
        pct,
        note,
        aggregate_json,
        provenance_json,
        execution_time_ms,
        code,
        message,
        terminal,
    })
}

// ---------------------------------------------------------------------------
// NapiOutletInvocationStream — async iterator class handed back to JS
// ---------------------------------------------------------------------------

/// JS class returned by [`context_outlet_invoke_stream`].
///
/// Exposes an async `next()` method that resolves to either the next
/// [`NapiOutletStreamChunk`] or `null` (signalling end-of-stream),
/// plus a synchronous `requestId` getter exposing the §5.4.5 16-byte
/// `request_id` as a 32-char lowercase hex string.
///
/// The TypeScript SDK wraps an instance of this class in an
/// `AsyncIterable` adapter (see `bindings/typescript/src/outlets.ts`)
/// that surfaces `Symbol.asyncIterator` per AC3 — the napi-rs `#[napi]`
/// macro does not currently expose Symbol-keyed methods directly, so
/// the iterator-protocol shim lives in TypeScript.
///
/// Iteration ends when the receiver closes OR after a terminal chunk
/// (`End`, `Error { terminal: true }`) is yielded; subsequent `next()`
/// calls return `null`.
#[napi(js_name = "OutletInvocationStream")]
pub struct NapiOutletInvocationStream {
    /// Receiver wrapped in an `Arc<TokioMutex<Option<_>>>` so that
    /// concurrent `next()` calls serialize on the lock and the receiver
    /// can be dropped explicitly when the stream terminates (the
    /// `Option` toggles to `None` so further calls do not race against
    /// a closed receiver).
    rx: Arc<TokioMutex<Option<mpsc::Receiver<OutletStreamChunk>>>>,
    /// 16-byte `request_id` rendered as hex. Kept on the iterator so
    /// the SDK can surface it without re-decoding chunks.
    request_id_hex: String,
    /// `true` after the pump observed a terminal chunk and the
    /// iterator must stop. Survives the receiver being dropped.
    terminated: Arc<std::sync::atomic::AtomicBool>,
}

#[napi]
impl NapiOutletInvocationStream {
    /// Returns the §5.4.5 16-byte `request_id` of the open stream as a
    /// 32-char lowercase hex string. The SDK uses this to address the
    /// stream from the control-plane methods (`grantCredit`, `cancel`).
    #[napi(getter, js_name = "requestId")]
    #[must_use]
    pub fn request_id(&self) -> String {
        self.request_id_hex.clone()
    }

    /// Returns `true` once a terminal chunk has been observed (or the
    /// receiver has been closed). After this flips `true`, subsequent
    /// `next()` calls resolve to `null` immediately.
    #[napi(getter)]
    #[must_use]
    pub fn done(&self) -> bool {
        self.terminated.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Asynchronously yields the next chunk, or `null` once the stream
    /// is closed.
    ///
    /// Resolves to `null` (not undefined) when:
    /// - the receiver was closed by the runtime pump task (clean
    ///   shutdown), OR
    /// - a previous call already observed a terminal chunk
    ///   (`End` / `Error { terminal: true }`).
    ///
    /// The TypeScript SDK adapter maps `null` to `{ value: undefined,
    /// done: true }` to satisfy the JS async-iterator protocol.
    ///
    /// # Errors
    ///
    /// Returns a `Tool`-class error if the chunk fails to serialise
    /// (`SCP-TOOL-6006`). All other failure modes (cancel, executor
    /// error, terminal error chunk) flow through normally as
    /// `payload_type = "error"` chunks — the iterator does NOT throw
    /// for runtime errors emitted as terminal `Error` chunks.
    #[napi]
    pub async fn next(&self) -> napi::Result<Option<NapiOutletStreamChunk>> {
        // Fast path: already terminated. Returning early avoids
        // taking the receiver lock and matches the PyO3 bridge's
        // `__anext__` short-circuit.
        if self.terminated.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(None);
        }
        let chunk_opt = {
            let mut rx_lock = self.rx.lock().await;
            match rx_lock.as_mut() {
                Some(rx) => rx.recv().await,
                None => None,
            }
        };
        match chunk_opt {
            None => {
                // Receiver closed — clean shutdown.
                self.terminated
                    .store(true, std::sync::atomic::Ordering::Release);
                evict_request(&self.request_id_hex);
                // Drop the receiver so any future `next()` calls that
                // race past the `terminated` check still observe a
                // closed slot.
                let mut rx_lock = self.rx.lock().await;
                rx_lock.take();
                Ok(None)
            }
            Some(chunk) => {
                let is_terminal = matches!(
                    chunk.payload,
                    ChunkPayload::End { .. } | ChunkPayload::Error { terminal: true, .. }
                );
                if is_terminal {
                    self.terminated
                        .store(true, std::sync::atomic::Ordering::Release);
                    evict_request(&self.request_id_hex);
                }
                let napi_chunk = chunk_to_napi(&chunk).map_err(napi::Error::from)?;
                Ok(Some(napi_chunk))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// context_outlet_invoke_stream — open the stream
// ---------------------------------------------------------------------------

/// Opens a §5.4.5 streaming outlet invocation and returns a
/// [`NapiOutletInvocationStream`] async iterator class.
///
/// Calls
/// [`scp_runtime::context::manager::ContextManager::open_outlet_stream`]
/// directly so the returned `StreamSessionHandle` is registered for
/// later `grantCredit` / `cancel` lookups by `request_id`.
///
/// # Arguments
///
/// * `handle` — Hosting [`NapiContextHandle`]; the bridge re-runs
///   handle-affinity validation against the bridge instance that
///   created it.
/// * `outlet_id` — Outlet to invoke.
/// * `input_json` — JSON string matching the outlet's input schema.
/// * `identity_did` — Invoker DID. Used as both `invoker_did` and
///   `origin_invoker_did` in `OpenStreamParams`.
/// * `ucan_token` — UCAN authorising the invocation. The bridge
///   re-runs the 11-step ADR-016 pipeline at open via
///   [`super::outlets::validate_outlet_invocation_ucan`].
/// * `caveats_binding_hex` — 32-byte `caveats_binding` rendered as
///   64-char lowercase hex. The SDK computes this via
///   [`compute_caveats_binding`] before opening.
/// * `stream_epoch` — Hosting context's MLS epoch counter at open
///   acceptance, pinned in the runtime's stream record. Provided by
///   the SDK so the credit-grant signing path can commit it into the
///   `SCP-OUTLET-CREDIT-V1:` preimage.
/// * `proof_tokens` — Optional encoded parent UCANs for delegation
///   chain traversal (ADR-016 step 3).
/// * `credit_window` — Initial credit-window size; defaults to §5.4.5
///   `DEFAULT_CREDIT_WINDOW` when `null`.
/// * `estimated_chunk_count` — Optional invoker-declared upper bound
///   on billable chunks; routes into the §5.4.5 escrow-at-open
///   computation.
///
/// # Errors
///
/// Rejects with `SCP-CTX-...` mapped to the §5.4.4 sub-block code
/// when the open is rejected by admission caps, escrow, or
/// estimate-bound checks. Rejects with `SCP-PERM-3001` on
/// UCAN-validation failure.
#[napi(js_name = "contextOutletInvokeStream")]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::needless_pass_by_value)]
pub async fn context_outlet_invoke_stream(
    handle: &NapiContextHandle,
    outlet_id: String,
    input_json: String,
    identity_did: String,
    ucan_token: String,
    caveats_binding_hex: String,
    stream_epoch: f64,
    proof_tokens: Option<Vec<String>>,
    credit_window: Option<u32>,
    estimated_chunk_count: Option<u32>,
) -> napi::Result<NapiOutletInvocationStream> {
    crate::napi_check_handle!(handle);
    scp_ffi_common::validate::validate_outlet_id(&outlet_id)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    scp_ffi_common::validate::validate_did(&identity_did)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    scp_ffi_common::validate::validate_ucan_token(&ucan_token)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    if let Some(tokens) = proof_tokens.as_ref() {
        for t in tokens {
            scp_ffi_common::validate::validate_ucan_token(t)
                .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
        }
    }

    let context_id = handle.context_id();
    crate::runtime::ensure_registered(handle)?;

    // Decode caveats_binding hex up front so the SDK gets a clean
    // ValidationError before any registry inserts happen.
    let caveats_binding = decode_caveats_binding(&caveats_binding_hex)?;

    // Parse input JSON once.
    let input_value: Value = serde_json::from_str(&input_json).map_err(|e| {
        napi::Error::from(ScpNapiError::Tool {
            message: format!("invalid input JSON: {e}"),
            code: codes::TOOL_6002.to_owned(),
        })
    })?;

    // Re-validate the UCAN under the full 11-step pipeline (defence
    // in depth — the runtime also validates at open, but doing it
    // here ensures the bridge surfaces a clean `Permission` error
    // before allocating any per-stream state).
    let proof_resolver = crate::ucan::build_proof_resolver_from_tokens(proof_tokens.as_deref())
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Permission {
                message: format!("failed to build proof resolver: {e}"),
                code: codes::PERM_3001.to_owned(),
            })
        })?;
    super::outlets::validate_outlet_invocation_ucan_napi(
        &context_id,
        &outlet_id,
        &identity_did,
        &ucan_token,
        &proof_resolver,
    )
    .map_err(napi::Error::from)?;

    // Snapshot the bridge-owned outlet registry + handler closure +
    // role state. Cloning the registry once is cheap and avoids
    // holding the bridge UCAN-state DashMap shard lock across the
    // runtime's three-phase lock split.
    let context_id_for_executor = context_id.clone();
    let outlet_id_for_executor = outlet_id.clone();
    let identity_for_executor = identity_did.clone();
    let (registry_snapshot, handler, role_state) =
        crate::runtime::with_context(&context_id, |st| {
            Ok((
                st.outlet_registry.clone(),
                st.outlet_handlers.get(&outlet_id).cloned(),
                st.role_state.clone(),
            ))
        })
        .map_err(napi::Error::from)?;

    let signing_key = resolve_invoker_signing_key(&identity_did).await?;
    let signing_key_arc = Arc::new(signing_key.clone());

    let executor: Arc<dyn scp_runtime::context::outlets::invoke::OutletExecutor> =
        Arc::new(ClosureExecutor {
            ctx_id: context_id_for_executor,
            outlet_id: outlet_id_for_executor,
            invoker_did: identity_for_executor,
            handler,
        });

    // §5.4.5 stream_epoch is a `u64` MLS epoch counter. Reject negative
    // / non-finite / out-of-range floats at the FFI boundary so the SDK
    // sees a clean ValidationError instead of an opaque runtime
    // rejection.
    let stream_epoch_u64 = validate_stream_epoch(stream_epoch)?;
    let params = build_open_stream_params(
        context_id.clone(),
        outlet_id.clone(),
        identity_did.clone(),
        stream_epoch_u64,
        caveats_binding,
        credit_window,
        estimated_chunk_count,
        signing_key.verifying_key(),
        Arc::clone(&signing_key_arc),
    );
    // §5.4.5 admission tracker MUST persist across successive opens
    // within a single context — fetch (or lazily create) the per-context
    // tracker on the bridge instance so the caps actually trip.
    crate::runtime::ensure_bridge_instance();
    let admission = crate::runtime::default_bridge_instance_raw()
        .ok_or_else(|| {
            napi::Error::from(ScpNapiError::Context {
                message: "bridge instance not initialised".to_owned(),
                code: codes::CTX_2000.to_owned(),
            })
        })?
        .outlet_stream_admission_for_context(&context_id);

    let invoker_did_typed: scp_primitives::DID = identity_did.clone().into();
    let outlet_id_typed = scp_core::context::outlets::OutletId::from(outlet_id.as_str());
    let manager = crate::runtime::context_manager()?;

    let mut runtime_handle = manager
        .open_outlet_stream(
            &context_id,
            &registry_snapshot,
            &role_state,
            &outlet_id_typed,
            input_value,
            &invoker_did_typed,
            None,
            executor,
            None,
            None,
            None,
            params,
            admission,
        )
        .await
        .map_err(|rejection| {
            napi::Error::from(ScpNapiError::Context {
                message: format!(
                    "stream open rejected: {} ({})",
                    rejection.slug(),
                    rejection.error_code()
                ),
                code: rejection.error_code().to_owned(),
            })
        })?;

    let receiver = runtime_handle.receiver().ok_or_else(|| {
        napi::Error::from(ScpNapiError::Context {
            message: "stream handle has no receiver".to_owned(),
            code: codes::CTX_2000.to_owned(),
        })
    })?;
    let request_id = *runtime_handle.request_id();
    let request_id_hex_str = request_id_hex(&request_id);

    register_stream_entry(StreamRegistryEntry {
        handle: Mutex::new(runtime_handle),
        monotonic_seq: Mutex::new(0),
        context_id: context_id.clone(),
        outlet_id: outlet_id.clone(),
        stream_epoch: stream_epoch_u64,
        caveats_binding,
        invoker_signing_key: signing_key,
        invoker_did: identity_did.clone(),
        request_id,
    })?;

    Ok(NapiOutletInvocationStream {
        rx: Arc::new(TokioMutex::new(Some(receiver))),
        request_id_hex: request_id_hex_str,
        terminated: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    })
}

/// Builds the §5.4.5 [`scp_runtime::context::outlets::dispatch::OpenStreamParams`]
/// for an outlet stream open.
///
/// Uses 0-cost / `u64::MAX` balance because the bridge does not yet
/// wire the §19 economy pipeline into the streaming path; SCP-OUT-038
/// is the SDK story that promotes the streaming bridge to the
/// economy-aware variant. Mirrors the `PyO3` bridge defaults so all
/// FFI-level streaming opens behave identically until OUT-038 lands.
#[allow(clippy::too_many_arguments)]
fn build_open_stream_params(
    context_id: String,
    outlet_id: String,
    invoker_did: String,
    stream_epoch: u64,
    caveats_binding: [u8; 32],
    credit_window: Option<u32>,
    estimated_chunk_count: Option<u32>,
    invoker_pk: ed25519_dalek::VerifyingKey,
    operator_signing_key: std::sync::Arc<ed25519_dalek::SigningKey>,
) -> scp_runtime::context::outlets::dispatch::OpenStreamParams {
    let credit_window_value =
        credit_window.unwrap_or(scp_protocol::context::outlets::stream::DEFAULT_CREDIT_WINDOW);
    scp_runtime::context::outlets::dispatch::OpenStreamParams {
        identity: scp_runtime::context::outlets::stream::StreamIdentity {
            context_id,
            outlet_id,
            stream_epoch,
            caveats_binding,
        },
        caps: scp_runtime::context::outlets::stream::AdmissionCaps {
            per_invoker: 8,
            per_origin_invoker: 16,
            per_outlet: 128,
        },
        invoker_did: invoker_did.clone(),
        origin_invoker_did: invoker_did,
        cost_per_chunk: scp_protocol::economy::types::Amount::new(0),
        available_balance: scp_protocol::economy::types::Amount::new(u64::MAX),
        declared_estimated_chunk_count: estimated_chunk_count,
        credit_window: credit_window_value,
        caveats: InvocationCaveats::empty(),
        invoker_pk,
        // Native FFI bridges: invoker == operator in the local
        // single-context streaming path. See PyO3 bridge for full
        // rationale (§5.4.5 / §6.2.0.5).
        operator_signing_key: Some(operator_signing_key),
        stream_credit_stall_secs:
            scp_protocol::context::outlets::stream::DEFAULT_STREAM_CREDIT_STALL_SECS,
        stream_cancel_ack_secs: 5,
    }
}

/// Inserts an entry into the per-bridge stream registry, keyed by the
/// 32-char lowercase hex `request_id`.
fn register_stream_entry(entry: StreamRegistryEntry) -> napi::Result<()> {
    let reg = registry().map_err(napi::Error::from)?;
    let key = request_id_hex(&entry.request_id);
    reg.insert(key, Arc::new(entry));
    Ok(())
}

// ---------------------------------------------------------------------------
// outlet_stream_grant_credit
// ---------------------------------------------------------------------------

/// Signs and applies an `OutletStreamCredit` grant against an active
/// stream identified by `request_id_hex`.
///
/// Per §5.4.5 round-5 the credit signature commits to the pinned
/// stream identity (`context_id`, `outlet_id`, `stream_epoch`,
/// `caveats_binding`) plus the strictly-monotonic `monotonic_seq`.
/// This function reads the local counter from the registry entry,
/// constructs the grant, signs it under the invoker's pinned signing
/// key, and forwards it to
/// [`scp_runtime::context::outlets::dispatch::StreamSessionHandle::apply_credit_grant`].
///
/// # Errors
///
/// * `ValidationError` — `grant == 0` (round-6 uniform `InvalidGrant`
///   rule).
/// * `Context` (slug `protocol.unknown-session`, code
///   [`codes::CODE_PROTOCOL_SESSION`]) — the `request_id_hex` does
///   not match any active stream registry entry.
/// * `Context` — the runtime tracker rejected the grant (replay,
///   identity mismatch, escrow overflow, insufficient funds).
#[napi(js_name = "outletStreamGrantCredit")]
#[allow(clippy::needless_pass_by_value)]
pub fn outlet_stream_grant_credit(
    request_id_hex: String,
    caller_did: String,
    grant: u32,
) -> napi::Result<u32> {
    if grant == 0 {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: "invalid grant 0: must be in (0, 2^32 - 1] (protocol.invalid-grant)"
                .to_owned(),
            code: scp_protocol::context::outlets::error_codes::CODE_PROTOCOL_SESSION.to_owned(),
        }));
    }
    scp_ffi_common::validate::validate_did(&caller_did)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    let entry = lookup_entry_authenticated(&request_id_hex, &caller_did)?;

    // Reserve the next monotonic_seq under a critical section so two
    // racing grant calls cannot collide. Bumping the counter BEFORE
    // signing means a runtime rejection (e.g., replay / mismatch)
    // leaves the counter advanced — a subsequent retry from the SDK
    // MUST present a fresh grant with the next monotonic_seq, NOT
    // the same value we just signed. This matches the §5.4.5
    // strict-monotonicity invariant: any seq accepted OR rejected by
    // the runtime at this point is "consumed" from the SDK's
    // perspective.
    let next_seq = {
        let mut guard = entry
            .monotonic_seq
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = guard.checked_add(1).ok_or_else(|| {
            napi::Error::from(ScpNapiError::Context {
                message: "monotonic_seq overflow: stream has issued u64::MAX grants".to_owned(),
                code: codes::CTX_2000.to_owned(),
            })
        })?;
        *guard
    };

    let credit = sign_credit_grant(&entry, grant, next_seq);

    let handle_guard = entry
        .handle
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let new_total = handle_guard
        .apply_credit_grant(&credit, scp_protocol::economy::types::Amount::new(u64::MAX))
        .map_err(|grant_err| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("credit grant rejected: {grant_err:?}"),
                code: codes::CTX_2000.to_owned(),
            })
        })?;
    Ok(new_total)
}

/// Constructs and signs an [`OutletStreamCredit`] for `entry`.
fn sign_credit_grant(
    entry: &StreamRegistryEntry,
    grant: u32,
    monotonic_seq: u64,
) -> OutletStreamCredit {
    let inputs = CreditGrantSigningInputs {
        context_id: entry.context_id.as_str(),
        outlet_id: entry.outlet_id.as_str(),
        request_id: &entry.request_id,
        grant,
        monotonic_seq,
        stream_epoch: entry.stream_epoch,
        caveats_binding: &entry.caveats_binding,
    };
    let sig = proto_stream::sign_credit_grant(&entry.invoker_signing_key, &inputs);
    OutletStreamCredit {
        request_id: entry.request_id,
        grant,
        monotonic_seq,
        sig,
    }
}

// ---------------------------------------------------------------------------
// outlet_stream_cancel
// ---------------------------------------------------------------------------

/// Applies a signed `OutletStreamCancel` to an active stream by
/// `request_id_hex` (round-7 cancel-auth).
///
/// Builds and signs the cancel under the entry's pinned identity +
/// the invoker's signing key, then forwards to
/// [`scp_runtime::context::outlets::dispatch::StreamSessionHandle::apply_outlet_cancel`].
/// A returning `Some(seq)` indicates the cancel was recorded; `None`
/// means the stream was already terminal at cancel receipt (the
/// runtime ignored the cancel per §5.4.5 idempotency).
///
/// # Errors
///
/// * `Context` (slug `protocol.unknown-session`) — `request_id_hex`
///   does not match any active stream.
/// * `Context` (slug `authorization.denied`) — runtime rejected the
///   cancel signature (cannot happen via this bridge under normal
///   operation; surfaces only on key-rotation drift).
#[napi(js_name = "outletStreamCancel")]
#[allow(clippy::needless_pass_by_value)]
pub fn outlet_stream_cancel(
    request_id_hex: String,
    caller_did: String,
) -> napi::Result<Option<f64>> {
    scp_ffi_common::validate::validate_did(&caller_did)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    let entry = lookup_entry_authenticated(&request_id_hex, &caller_did)?;
    // §5.4.5 next-emission cursor MUST come from runtime state, not
    // caller input. CRITICAL #3 fix — caller-supplied `next_seq`
    // forges `cancel_ack_seq`.
    let next_seq_u64 = {
        let handle_guard = entry
            .handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        handle_guard.current_next_emission_seq()
    };
    let cancel = sign_cancel_for_entry(&entry, next_seq_u64);
    let handle_guard = entry
        .handle
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let recorded = handle_guard.apply_outlet_cancel(&cancel).map_err(|err| {
        napi::Error::from(ScpNapiError::Context {
            message: format!(
                "cancel rejected ({}): {err:?}",
                scp_runtime::context::outlets::stream::cancel_error_to_slug(err)
            ),
            code: scp_runtime::context::outlets::stream::cancel_error_to_code(err).to_owned(),
        })
    })?;
    // Map `Option<u64>` back to `Option<f64>` for the JS surface.
    // Same lossless ceiling argument as `chunk.sequence` —
    // `cancel_ack_seq` is bounded by the chunk-sequence space, which
    // is bounded by `credit_window`.
    #[allow(clippy::cast_precision_loss)]
    Ok(recorded.map(|seq| seq as f64))
}

// ---------------------------------------------------------------------------
// outletStreamTerminate — receiver-side revocation re-check (§5.4.5)
// ---------------------------------------------------------------------------

/// Forces a terminal `Error{terminal:true}` chunk into the active stream
/// identified by `request_id_hex` (§5.4.5 receiver-side revocation
/// re-check, `RevokedMidStream` / `SCP-TOOL-6110`).
///
/// Routes through
/// [`scp_runtime::context::outlets::dispatch::StreamSessionHandle::terminate_with_error`]
/// — the runtime pump emits a synthetic terminal chunk under the pinned
/// operator key and runs settlement (admission release, escrow refund,
/// `OutletInvokedEvent` emission) identically to other framework-emitted
/// closes.
///
/// The SDK framework's periodic UCAN re-check loop calls this whenever
/// it observes the opening UCAN has been revoked since stream open.
///
/// # Errors
///
/// * `Context` (slug `protocol.unknown-session`) — `request_id_hex`
///   does not match any active stream.
/// * `Context` — the runtime rejected the termination because the pump
///   has already emitted a terminal chunk
///   ([`scp_runtime::context::outlets::dispatch::TerminateError::AlreadyTerminated`])
///   or another terminate is already pending
///   ([`scp_runtime::context::outlets::dispatch::TerminateError::AlreadyPending`]).
#[napi(js_name = "outletStreamTerminate")]
#[allow(clippy::needless_pass_by_value)]
pub fn outlet_stream_terminate(
    request_id_hex: String,
    caller_did: String,
    slug: String,
    code: String,
    message: String,
) -> napi::Result<()> {
    scp_ffi_common::validate::validate_did(&caller_did)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    let entry = lookup_entry_authenticated(&request_id_hex, &caller_did)?;
    let handle_guard = entry
        .handle
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    handle_guard
        .terminate_with_error(&slug, &code, &message)
        .map_err(|err| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("terminate rejected: {err}"),
                code: code.clone(),
            })
        })?;
    Ok(())
}

/// Builds and signs an `OutletStreamCancel` for `entry` against
/// `next_seq` (mirrors [`sign_credit_grant`]).
fn sign_cancel_for_entry(
    entry: &StreamRegistryEntry,
    next_seq: u64,
) -> scp_protocol::context::outlets::stream::OutletStreamCancel {
    use scp_protocol::context::outlets::stream::{
        CancelSigningInputs, OutletStreamCancel, sign_cancel,
    };
    let inputs = CancelSigningInputs {
        context_id: entry.context_id.as_str(),
        outlet_id: entry.outlet_id.as_str(),
        request_id: &entry.request_id,
        next_seq,
        caveats_binding: &entry.caveats_binding,
    };
    let sig = sign_cancel(&entry.invoker_signing_key, &inputs);
    OutletStreamCancel {
        request_id: entry.request_id,
        next_seq,
        sig,
    }
}

// ---------------------------------------------------------------------------
// verify_chunk_signature — pure helper
// ---------------------------------------------------------------------------

/// Verifies a chunk's `SCP-OUTLET-CHUNK-SIG-V1:` signature.
///
/// `chunk_json` is the canonical-JSON-encoded [`OutletStreamChunk`]
/// (the bridge accepts the full chunk encoded as JSON and reconstructs
/// the typed struct so the verification path covers exactly the bytes
/// the operator signed). All five inputs match the §5.4.5 preimage
/// block byte-for-byte.
///
/// Returns `true` if the signature verifies, `false` otherwise. Never
/// throws for a bad signature — only for malformed inputs (non-32-byte
/// pubkey / `caveats_binding`, malformed JSON).
#[napi(js_name = "verifyChunkSignature")]
#[allow(clippy::needless_pass_by_value)]
pub fn verify_chunk_signature(
    chunk_json: String,
    operator_pk: Buffer,
    context_id: String,
    outlet_id: String,
    caveats_binding: Buffer,
) -> napi::Result<bool> {
    let chunk: OutletStreamChunk = serde_json::from_str(&chunk_json).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("malformed chunk JSON: {e}"),
            code: codes::VALID_7000.to_owned(),
        })
    })?;
    let pk_array: [u8; 32] = operator_pk.as_ref().try_into().map_err(|_| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!(
                "operator_pk must be exactly 32 bytes, got {}",
                operator_pk.len()
            ),
            code: codes::VALID_7000.to_owned(),
        })
    })?;
    let caveats_binding_array: [u8; 32] = caveats_binding.as_ref().try_into().map_err(|_| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!(
                "caveats_binding must be exactly 32 bytes, got {}",
                caveats_binding.len()
            ),
            code: codes::VALID_7000.to_owned(),
        })
    })?;
    let pk = ed25519_dalek::VerifyingKey::from_bytes(&pk_array).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("operator_pk is not a valid Ed25519 public key: {e}"),
            code: codes::VALID_7000.to_owned(),
        })
    })?;
    Ok(proto_stream::verify_chunk_signature(
        &chunk,
        &pk,
        &context_id,
        &outlet_id,
        &caveats_binding_array,
    ))
}

// ---------------------------------------------------------------------------
// compute_caveats_binding — pure helper
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
/// Returns the 32-byte hash as a `Buffer`.
#[napi(js_name = "computeCaveatsBinding")]
#[allow(clippy::needless_pass_by_value)]
pub fn compute_caveats_binding(
    ucan_cid: Buffer,
    request_id: Buffer,
    invoker_did: String,
    estimated_chunk_count: u32,
    effective_caveats_json: String,
) -> napi::Result<Buffer> {
    let request_id_array: [u8; 16] = request_id.as_ref().try_into().map_err(|_| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!(
                "request_id must be exactly 16 bytes, got {}",
                request_id.len()
            ),
            code: codes::VALID_7000.to_owned(),
        })
    })?;
    let caveats_value: Value = serde_json::from_str(&effective_caveats_json).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("invalid effective_caveats JSON: {e}"),
            code: codes::VALID_7000.to_owned(),
        })
    })?;
    let caveats: InvocationCaveats = serde_json::from_value(caveats_value).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("effective_caveats does not match InvocationCaveats: {e}"),
            code: codes::VALID_7000.to_owned(),
        })
    })?;
    // §5.4.5 requires JCS canonicalization of `effective_caveats`
    // before hashing — the bridge runs canonicalisation here so SDK
    // callers do not need an in-language JCS implementation. `serde`
    // is already configured on `InvocationCaveats` to skip-`None`-
    // fields per the round-5 omit-none convention (cross-SDK
    // byte-for-byte match).
    let caveats_jcs = scp_protocol::jcs::to_vec(&caveats).map_err(|e| {
        napi::Error::from(ScpNapiError::Tool {
            message: format!("failed to JCS-canonicalise caveats: {e}"),
            code: codes::TOOL_6006.to_owned(),
        })
    })?;
    let binding = proto_stream::compute_caveats_binding(
        ucan_cid.as_ref(),
        &request_id_array,
        &invoker_did,
        estimated_chunk_count,
        &caveats_jcs,
    );
    Ok(Buffer::from(binding.to_vec()))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Validates an `f64` MLS epoch counter and converts it to `u64`.
///
/// Mirrors `event_log::validate_non_negative_epoch` — the NAPI bridge
/// surfaces u64 protocol values as `f64` for ergonomic JS consumption,
/// but rejects negative / non-finite / fractional / out-of-range
/// floats with `Validation` so SDK callers see a clean error instead
/// of an opaque runtime rejection on the eventually-truncated value.
fn validate_stream_epoch(epoch: f64) -> napi::Result<u64> {
    if !epoch.is_finite() {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: format!("stream_epoch must be a finite number, got {epoch}"),
            code: codes::VALID_7000.to_owned(),
        }));
    }
    if epoch < 0.0 {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: format!("stream_epoch must be non-negative, got {epoch}"),
            code: codes::VALID_7000.to_owned(),
        }));
    }
    if epoch.fract() != 0.0 {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: format!("stream_epoch must be an integer, got {epoch}"),
            code: codes::VALID_7000.to_owned(),
        }));
    }
    // 2^53 is the lossless upper bound for f64; refuse silently
    // truncated integers.
    #[allow(clippy::cast_precision_loss)]
    let max_safe = (1u64 << 53) as f64;
    if epoch > max_safe {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: format!(
                "stream_epoch {epoch} exceeds Number.MAX_SAFE_INTEGER (2^53); pass via BigInt-aware path when this is needed"
            ),
            code: codes::VALID_7000.to_owned(),
        }));
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(epoch as u64)
}

fn decode_caveats_binding(hex_str: &str) -> napi::Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("caveats_binding_hex must be 64 hex characters: {e}"),
            code: codes::VALID_7000.to_owned(),
        })
    })?;
    let len = bytes.len();
    bytes.try_into().map_err(|_| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("caveats_binding must decode to 32 bytes, got {len}"),
            code: codes::VALID_7000.to_owned(),
        })
    })
}

fn lookup_entry(request_id_hex: &str) -> napi::Result<Arc<StreamRegistryEntry>> {
    // Ensure the default bridge instance exists so the registry exists
    // — this lets the unknown-session error path surface even when no
    // stream has ever been opened (e.g., a test or stale handle on the
    // SDK side calling `cancel` without prior `invoke_stream`). Mirrors
    // the `PyO3` bridge's `lookup_entry`.
    crate::runtime::ensure_bridge_instance();
    let reg = registry().map_err(napi::Error::from)?;
    reg.get(request_id_hex)
        .map(|kv| Arc::clone(kv.value()))
        .ok_or_else(|| {
            napi::Error::from(ScpNapiError::Context {
                message: format!(
                    "stream '{request_id_hex}' not found in registry (protocol.unknown-session)"
                ),
                code: scp_protocol::context::outlets::error_codes::CODE_PROTOCOL_SESSION.to_owned(),
            })
        })
}

/// Looks up the stream entry and verifies `caller_did` matches the
/// pinned `invoker_did`. CRITICAL #1 fix — without this gate, any
/// in-process code with a `request_id_hex` could drain credit, cancel,
/// or terminate any concurrent stream because the bridge wields the
/// invoker's signing key.
fn lookup_entry_authenticated(
    request_id_hex: &str,
    caller_did: &str,
) -> napi::Result<Arc<StreamRegistryEntry>> {
    let entry = lookup_entry(request_id_hex)?;
    if entry.invoker_did != caller_did {
        return Err(napi::Error::from(ScpNapiError::Context {
            message: format!(
                "caller {caller_did} is not the pinned invoker for stream '{request_id_hex}' \
                 (authorization.denied)"
            ),
            code: codes::PERM_3001.to_owned(),
        }));
    }
    Ok(entry)
}

async fn resolve_invoker_signing_key(identity_did: &str) -> napi::Result<SigningKey> {
    // `with_identity` looks up the per-identity entry in the bridge's
    // identity registry. We clone out the `Arc<custody>` and the key
    // handle, drop the DashMap lock, then run the async export
    // outside the lock — the same two-phase pattern used by the
    // link-attestation signer in `identity.rs`.
    let (custody, key_handle) = crate::runtime::with_identity(identity_did, |entry| {
        Ok((
            Arc::clone(&entry.custody),
            entry.identity.active_signing_key,
        ))
    })?;
    let signing_key = custody
        .0
        .export_ed25519_signing_key(&key_handle)
        .await
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Identity {
                message: format!("failed to export invoker signing key: {e}"),
                code: codes::IDENT_1041.to_owned(),
            })
        })?;
    Ok(signing_key)
}

// ---------------------------------------------------------------------------
// ClosureExecutor — adapter from a NAPI-handler closure to `OutletExecutor`
// ---------------------------------------------------------------------------

/// Adapter that lets the existing NAPI [`crate::runtime::OutletHandler`]
/// closure satisfy the runtime's
/// [`scp_runtime::context::outlets::invoke::OutletExecutor`] trait
/// without touching the `outlet_invoke` path. `exec_action_stream` and
/// `exec_query_stream` defer to the registered handler when present and
/// fall back to schema-only echo mode when no handler is registered
/// (matching `outlet_invoke`'s contract).
struct ClosureExecutor {
    ctx_id: String,
    outlet_id: String,
    invoker_did: String,
    handler: Option<crate::runtime::OutletHandler>,
}

#[async_trait]
impl scp_runtime::context::outlets::invoke::OutletExecutor for ClosureExecutor {
    async fn exec_query_stream(
        &self,
        _ctx: &scp_runtime::context::outlets::invoke::ReadOnlyInvocation<'_>,
        input: serde_json::Value,
        tx: mpsc::Sender<ChunkPayload>,
    ) -> Result<(), scp_runtime::context::outlets::invoke::OutletExecutorError> {
        self.run_handler_one_shot(input, tx).await
    }

    async fn exec_action_stream(
        &self,
        _ctx: &mut scp_runtime::context::outlets::invoke::MutableInvocation<'_>,
        input: serde_json::Value,
        tx: mpsc::Sender<ChunkPayload>,
    ) -> Result<(), scp_runtime::context::outlets::invoke::OutletExecutorError> {
        self.run_handler_one_shot(input, tx).await
    }
}

impl ClosureExecutor {
    async fn run_handler_one_shot(
        &self,
        input: serde_json::Value,
        tx: mpsc::Sender<ChunkPayload>,
    ) -> Result<(), scp_runtime::context::outlets::invoke::OutletExecutorError> {
        let result = self.handler.as_ref().map_or_else(
            || {
                Ok(serde_json::json!({
                    "tool": self.outlet_id,
                    "context": self.ctx_id,
                    "status": "validated",
                    "input_valid": true,
                    "invoker_did": self.invoker_did,
                    "validated_input": input.clone(),
                }))
            },
            |handler| {
                handler(input.clone())
                    .map_err(|e| format!("tool handler for '{}' failed: {}", self.outlet_id, e))
            },
        );
        match result {
            Ok(value) => {
                let _ = tx.send(ChunkPayload::Data { value }).await;
                Ok(())
            }
            Err(e) => Err(scp_runtime::context::outlets::invoke::OutletExecutorError::Failed(e)),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use scp_protocol::context::outlets::stream::{ChunkPayload, OutletStreamChunk, sign_chunk};

    /// Helper: deterministic signing key for repeatable test vectors.
    fn fixed_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }

    /// `verify_chunk_signature` round-trips a freshly signed chunk and
    /// returns `true`. Tampering with any preimage component flips the
    /// result to `false`. Covers AC10.
    #[test]
    fn verify_chunk_signature_roundtrips_signed_chunk() {
        let signing = fixed_signing_key();
        let request_id: [u8; 16] = [0x11; 16];
        let caveats_binding: [u8; 32] = [0xAB; 32];
        let payload = ChunkPayload::Data {
            value: serde_json::json!({"tick": 7}),
        };
        let sig = sign_chunk(
            &signing,
            "ctx-stream",
            "outlet-x",
            &request_id,
            42,
            &caveats_binding,
            &payload,
        )
        .expect("sign_chunk");

        let chunk = OutletStreamChunk {
            request_id,
            sequence: 42,
            payload,
            sig,
        };
        let chunk_json = serde_json::to_string(&chunk).expect("serialise chunk");
        let pk_bytes = signing.verifying_key().as_bytes().to_vec();
        let cb_bytes = caveats_binding.to_vec();

        // Signature verifies under the right preimage.
        let ok = verify_chunk_signature(
            chunk_json.clone(),
            Buffer::from(pk_bytes.clone()),
            "ctx-stream".to_owned(),
            "outlet-x".to_owned(),
            Buffer::from(cb_bytes.clone()),
        )
        .expect("verify ok");
        assert!(ok, "freshly signed chunk must verify");

        // Tampering with context_id flips the result.
        let bad_ctx = verify_chunk_signature(
            chunk_json.clone(),
            Buffer::from(pk_bytes.clone()),
            "ctx-other".to_owned(),
            "outlet-x".to_owned(),
            Buffer::from(cb_bytes),
        )
        .expect("verify call");
        assert!(!bad_ctx, "tampered context_id must NOT verify");

        // Tampering with caveats_binding flips the result.
        let bad_binding: [u8; 32] = [0xCD; 32];
        let bad_b = verify_chunk_signature(
            chunk_json,
            Buffer::from(pk_bytes),
            "ctx-stream".to_owned(),
            "outlet-x".to_owned(),
            Buffer::from(bad_binding.to_vec()),
        )
        .expect("verify call");
        assert!(!bad_b, "tampered caveats_binding must NOT verify");
    }

    /// `verify_chunk_signature` rejects a 31-byte `caveats_binding` with
    /// `Validation` error. Pure-input validation cover.
    #[test]
    fn verify_chunk_signature_rejects_short_caveats_binding() {
        let signing = fixed_signing_key();
        let chunk = OutletStreamChunk {
            request_id: [0x00; 16],
            sequence: 0,
            payload: ChunkPayload::Data {
                value: serde_json::json!({}),
            },
            sig: [0u8; 64],
        };
        let chunk_json = serde_json::to_string(&chunk).expect("serialise chunk");

        let short_binding = vec![0u8; 31];
        let result = verify_chunk_signature(
            chunk_json,
            Buffer::from(signing.verifying_key().as_bytes().to_vec()),
            "ctx".to_owned(),
            "outlet".to_owned(),
            Buffer::from(short_binding),
        );
        assert!(result.is_err(), "31-byte caveats_binding must be rejected");
    }

    /// `compute_caveats_binding` is deterministic — same inputs produce
    /// the same 32 bytes. Covers AC11 self-consistency.
    #[test]
    fn compute_caveats_binding_is_deterministic() {
        let ucan_cid: Vec<u8> = b"bafyreigh1234567890abcdef".to_vec();
        let request_id_bytes: Vec<u8> = vec![0x77; 16];
        let invoker_did = "did:dht:z6MkInvoker".to_owned();
        let caveats_json = "{\"maxCalls\":10}".to_owned();
        let a = compute_caveats_binding(
            Buffer::from(ucan_cid.clone()),
            Buffer::from(request_id_bytes.clone()),
            invoker_did.clone(),
            100,
            caveats_json.clone(),
        )
        .expect("compute a");
        let a_bytes = a.as_ref().to_vec();
        let b = compute_caveats_binding(
            Buffer::from(ucan_cid.clone()),
            Buffer::from(request_id_bytes.clone()),
            invoker_did.clone(),
            100,
            caveats_json.clone(),
        )
        .expect("compute b");
        assert_eq!(
            a_bytes,
            b.as_ref().to_vec(),
            "binding must be deterministic"
        );
        assert_eq!(a_bytes.len(), 32, "binding is 32 bytes");

        // Changing one input flips bytes.
        let c = compute_caveats_binding(
            Buffer::from(ucan_cid.clone()),
            Buffer::from(request_id_bytes.clone()),
            invoker_did,
            101, // different chunk count
            caveats_json.clone(),
        )
        .expect("compute c");
        assert_ne!(
            a_bytes,
            c.as_ref().to_vec(),
            "different estimated_chunk_count must flip bytes"
        );

        // Changing invoker_did flips bytes.
        let d = compute_caveats_binding(
            Buffer::from(ucan_cid),
            Buffer::from(request_id_bytes),
            "did:dht:z6MkOther".to_owned(),
            100,
            caveats_json,
        )
        .expect("compute d");
        assert_ne!(
            a_bytes,
            d.as_ref().to_vec(),
            "different invoker_did must flip bytes"
        );
    }

    /// `compute_caveats_binding` rejects a 15-byte `request_id` with
    /// `Validation` error.
    #[test]
    fn compute_caveats_binding_rejects_short_request_id() {
        let short = vec![0u8; 15];
        let result = compute_caveats_binding(
            Buffer::from(b"cid".to_vec()),
            Buffer::from(short),
            "did:dht:x".to_owned(),
            1,
            "{}".to_owned(),
        );
        assert!(result.is_err(), "15-byte request_id must be rejected");
    }

    /// `outlet_stream_grant_credit` rejects `grant == 0` with
    /// `Validation` error per OUT-031 round-6 uniform `InvalidGrant` rule.
    #[test]
    fn grant_credit_rejects_zero_grant() {
        let result =
            outlet_stream_grant_credit("00".repeat(16), "did:dht:z6MkInvoker".to_owned(), 0);
        assert!(result.is_err(), "grant=0 must be rejected");
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains("invalid grant 0") || err_str.contains("protocol.invalid-grant"),
            "error must mention invalid-grant: {err_str}"
        );
    }

    /// `outlet_stream_cancel` returns `Context` error when the
    /// `request_id_hex` does not match any registry entry.
    #[test]
    fn cancel_returns_unknown_session_for_missing_request() {
        // Use a fresh hex that is unlikely to match any other test's
        // active stream (registry is process-global per default
        // bridge instance — see ADR-048).
        let result = outlet_stream_cancel("ee".repeat(16), "did:dht:z6MkInvoker".to_owned());
        assert!(result.is_err(), "missing request_id must be rejected");
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains("not found") || err_str.contains("unknown-session"),
            "error must mention unknown-session: {err_str}"
        );
    }
}
