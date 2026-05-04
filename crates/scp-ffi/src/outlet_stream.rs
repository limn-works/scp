//! `PyO3` streaming bridge for outlets — `SCP-OUT-037` (`PyO3` portion).
//!
//! Exposes §5.4.5 progressive-output streaming to Python:
//!
//! - [`py_outlet_invoke_stream`] — Opens a §5.4.5 stream session and
//!   returns a Python async iterator (`__aiter__` / `__anext__`)
//!   yielding [`OutletStreamChunk`] dicts.
//! - [`py_outlet_stream_grant_credit`] — Signs and applies an
//!   `OutletStreamCredit` grant against an active stream identified by
//!   `request_id`.
//! - [`py_outlet_stream_cancel`] — Applies an `OutletCancel` against an
//!   active stream identified by `request_id`.
//! - [`py_verify_chunk_signature`] — Pure helper that verifies a
//!   chunk's `SCP-OUTLET-CHUNK-SIG-V1:` signature byte-for-byte per
//!   §5.4.5.
//! - [`py_compute_caveats_binding`] — Pure helper that recomputes the
//!   `SCP-OUTLET-CAVEAT-BIND-V1:` 32-byte binding per §5.4.5.
//!
//! Active streams are tracked in a per-bridge `StreamRegistry` keyed by
//! the §5.4.5 16-byte `request_id` (rendered as 32-char lowercase hex
//! at the FFI boundary). Each entry holds the [`StreamSessionHandle`]
//! returned by [`scp_runtime::context::manager::ContextManager::open_outlet_stream`]
//! plus the local monotonic-grant counter and the credit-grant signing
//! material.
//!
//! Cleanup: each entry is removed from the registry when the runtime
//! pump emits a terminal chunk (End / Error{terminal:true} / Cancelled)
//! — the streaming pump task that bridges chunks from the runtime to
//! the Python asyncio queue handles eviction.

use std::sync::{Arc, Mutex};

use dashmap::DashMap;
use ed25519_dalek::SigningKey;
use pyo3::exceptions::{PyRuntimeError, PyStopAsyncIteration};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use scp_core::context::outlets::stream::{
    self as proto_stream, ChunkPayload, CreditGrantSigningInputs, OutletStreamChunk,
    OutletStreamCredit,
};
use scp_protocol::trust::caveats::InvocationCaveats;
use serde_json::Value;
use tokio::sync::Mutex as TokioMutex;

use crate::error::ScpPyError;
use crate::validate;

// ---------------------------------------------------------------------------
// Stream registry
// ---------------------------------------------------------------------------

/// One entry in the per-bridge stream registry.
///
/// Holds the `StreamSessionHandle` (the runtime control surface), the
/// local monotonic-grant counter (strictly increasing per §5.4.5), and
/// the §5.4.5 `SCP-OUTLET-CREDIT-V1:` preimage inputs that every grant
/// signature must commit to: the pinned `(context_id, outlet_id,
/// stream_epoch, caveats_binding)` plus the invoker's `SigningKey`.
pub(crate) struct StreamRegistryEntry {
    /// Control-plane handle returned by the runtime at open. Wrapped in
    /// an outer `Mutex` so the FFI grant/cancel calls can take
    /// exclusive ownership of `apply_credit_grant` /
    /// `apply_outlet_cancel` while the streaming pump task drains the
    /// receiver concurrently. (The handle's own `state` is already
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
    /// 16-byte `request_id` (the registry key in raw form) so the
    /// pump task and the close path can look up by either the hex
    /// string (registry key) or the typed wire form.
    pub request_id: [u8; 16],
}

/// Returns a reference to the per-bridge stream registry on the
/// default [`crate::runtime::PyBridgeInstance`]. Per ADR-048 the
/// registry lives on the bridge instance (not as a process-global)
/// so multi-instance fallback / shutdown clearing works uniformly.
///
/// Returns an error if the bridge instance has not been initialised
/// — the streaming bridge functions all require it (and
/// `context_outlet_invoke_stream` calls
/// `crate::runtime::ensure_bridge_instance` upstream of this call).
fn registry() -> Result<Arc<DashMap<String, Arc<StreamRegistryEntry>>>, ScpPyError> {
    let bi = crate::runtime::bridge_instance_raw()
        .ok_or_else(|| ScpPyError::context("bridge instance not initialised"))?;
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
// PyOutletInvocationStream — async iterator handed back to Python
// ---------------------------------------------------------------------------

/// Python async iterator yielding [`OutletStreamChunk`] dicts.
///
/// Construction wraps a `tokio::sync::mpsc::Receiver<OutletStreamChunk>`
/// in an `Arc<TokioMutex>` so the iterator's `__anext__` future can
/// take the lock asynchronously (no blocking the asyncio event loop).
/// The iterator returns `StopAsyncIteration` when the receiver closes
/// or after a terminal `End` / `Error{terminal:true}` chunk is yielded.
#[pyclass(name = "OutletInvocationStream")]
pub struct PyOutletInvocationStream {
    rx: Arc<TokioMutex<Option<tokio::sync::mpsc::Receiver<OutletStreamChunk>>>>,
    /// 16-byte `request_id` rendered as hex. Kept on the iterator so
    /// the SDK can surface it without re-decoding chunks.
    request_id_hex: String,
    /// `true` after the pump observed a terminal chunk and the
    /// iterator must stop. Survives the receiver being dropped.
    terminated: Arc<std::sync::atomic::AtomicBool>,
}

#[pymethods]
impl PyOutletInvocationStream {
    /// Returns the §5.4.5 16-byte `request_id` of the open stream as a
    /// 32-char lowercase hex string. The SDK uses this to address the
    /// stream from the control-plane methods (`grant_credit`,
    /// `cancel`).
    #[getter]
    fn request_id(&self) -> &str {
        &self.request_id_hex
    }

    /// `__aiter__` — returns self, per the Python async-iterator
    /// protocol. `PyO3`'s auto-generated `__iter__` would only cover the
    /// sync iterator protocol; the async variant must be implemented
    /// explicitly.
    const fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    /// `__anext__` — returns a Python coroutine that resolves to the
    /// next [`OutletStreamChunk`] dict, or raises
    /// `StopAsyncIteration` when the stream closes.
    ///
    /// The coroutine is built by `pyo3-async-runtimes` from a Rust
    /// `async` block that takes the receiver mutex, polls the tokio
    /// channel via the global runtime, and converts the chunk to a
    /// Python dict on the GIL once it lands. A terminal `End` /
    /// `Error{terminal:true}` chunk is the iterator's last yielded
    /// value: subsequent `__anext__` calls observe `terminated == true`
    /// and raise `StopAsyncIteration`.
    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let rx = Arc::clone(&self.rx);
        let terminated = Arc::clone(&self.terminated);
        let request_id_hex_owned = self.request_id_hex.clone();
        if terminated.load(std::sync::atomic::Ordering::Acquire) {
            return Err(PyStopAsyncIteration::new_err(()));
        }
        // Drive the channel poll on the global tokio runtime via
        // `block_on`. The `pyo3-async-runtimes` integration would let
        // us return a tokio future converted to a Python awaitable
        // directly, but the bridge does not pull that crate in (and
        // adding it for one call site is overkill); instead we follow
        // the same pattern as `py_context_receive`'s `__anext__` — the
        // caller is expected to invoke us via `asyncio.to_thread` so
        // `block_on` does not stall the asyncio event loop.
        let rt = crate::runtime()?;
        let chunk_opt = py.allow_threads(|| {
            rt.block_on(async move {
                let mut rx_lock = rx.lock().await;
                match rx_lock.as_mut() {
                    Some(rx_inner) => rx_inner.recv().await,
                    None => None,
                }
            })
        });
        match chunk_opt {
            None => {
                terminated.store(true, std::sync::atomic::Ordering::Release);
                evict_request(&request_id_hex_owned);
                Err(PyStopAsyncIteration::new_err(()))
            }
            Some(chunk) => {
                let is_terminal = matches!(
                    chunk.payload,
                    ChunkPayload::End { .. } | ChunkPayload::Error { terminal: true, .. }
                );
                if is_terminal {
                    terminated.store(true, std::sync::atomic::Ordering::Release);
                    evict_request(&request_id_hex_owned);
                }
                let dict = chunk_to_py_dict(py, &chunk)?;
                Ok(dict.into_any())
            }
        }
    }
}

/// Converts a runtime [`OutletStreamChunk`] to a Python dict.
///
/// The shape mirrors the §5.4.5 wire form on a per-variant basis so
/// SDK callers can branch on `payload_type` and read variant fields
/// directly without an extra translation step. Discriminator key is
/// `payload_type` (the SDK-friendly `snake_case` variant of the wire
/// `@type` discriminator).
fn chunk_to_py_dict<'py>(
    py: Python<'py>,
    chunk: &OutletStreamChunk,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("request_id", PyBytes::new(py, &chunk.request_id))?;
    dict.set_item("sequence", chunk.sequence)?;
    dict.set_item("sig", PyBytes::new(py, &chunk.sig))?;
    match &chunk.payload {
        ChunkPayload::Data { value } => {
            dict.set_item("payload_type", "data")?;
            dict.set_item("value", crate::types::json_to_py_dict(py, value)?)?;
        }
        ChunkPayload::Progress { pct, note } => {
            dict.set_item("payload_type", "progress")?;
            dict.set_item("pct", *pct)?;
            if let Some(n) = note {
                dict.set_item("note", n)?;
            } else {
                dict.set_item("note", py.None())?;
            }
        }
        ChunkPayload::End {
            aggregate,
            provenance,
            execution_time_ms,
        } => {
            dict.set_item("payload_type", "end")?;
            dict.set_item("aggregate", crate::types::json_to_py_dict(py, aggregate)?)?;
            let provenance_json = serde_json::to_value(provenance)
                .map_err(|e| ScpPyError::context(format!("provenance serialisation: {e}")))?;
            dict.set_item(
                "provenance",
                crate::types::json_to_py_dict(py, &provenance_json)?,
            )?;
            dict.set_item("execution_time_ms", *execution_time_ms)?;
        }
        ChunkPayload::Error {
            code,
            message,
            terminal,
        } => {
            dict.set_item("payload_type", "error")?;
            dict.set_item("code", code)?;
            dict.set_item("message", message)?;
            dict.set_item("terminal", *terminal)?;
        }
    }
    Ok(dict)
}

// ---------------------------------------------------------------------------
// context_outlet_invoke_stream — open the stream
// ---------------------------------------------------------------------------

/// Opens a §5.4.5 streaming outlet invocation and returns the Python
/// async iterator that yields [`OutletStreamChunk`] dicts.
///
/// Calls [`scp_runtime::context::manager::ContextManager::open_outlet_stream`]
/// directly so the returned [`StreamSessionHandle`] is registered for
/// later `grant_credit` / `cancel` lookups by `request_id`.
///
/// # Arguments
///
/// * `context_id` — Hosting context id.
/// * `outlet_id` — Outlet to invoke.
/// * `input` — Python dict matching the outlet's input schema.
/// * `identity_did` — Invoker DID. Used as both `invoker_did` and
///   `origin_invoker_did` in [`OpenStreamParams`] (the bridge does not
///   currently surface a delegation chain).
/// * `ucan_token` — UCAN authorising the invocation. The bridge
///   re-runs the 11-step ADR-016 pipeline at open via
///   [`super::outlets::validate_outlet_ucan`].
/// * `caveats_binding_hex` — 32-byte `caveats_binding` rendered as
///   64-char lowercase hex. The SDK computes this via
///   [`py_compute_caveats_binding`] before opening.
/// * `stream_epoch` — Hosting context's MLS epoch counter at open
///   acceptance, pinned in the runtime's stream record. Provided by
///   the SDK so the credit-grant signing path can commit it into the
///   `SCP-OUTLET-CREDIT-V1:` preimage.
/// * `credit_window` — Initial credit-window size; defaults to
///   §5.4.5 [`DEFAULT_CREDIT_WINDOW`] when `None`.
/// * `estimated_chunk_count` — Upper bound on billable chunks; routes
///   into the §5.4.5 escrow-at-open computation.
///
/// # Returns
///
/// A [`PyOutletInvocationStream`] suitable for `async for chunk in
/// stream:` consumption. The stream's `request_id` attribute is the
/// hex of the §5.4.5 16-byte `request_id` and is the lookup key for
/// the control-plane functions
/// [`py_outlet_stream_grant_credit`] / [`py_outlet_stream_cancel`].
///
/// # Errors
///
/// Raises `ContextError` with the §5.4.4 sub-block code when the open
/// is rejected by admission caps, escrow, or estimate-bound checks.
/// `UcanError` on UCAN-validation failure.
#[pyfunction]
#[pyo3(name = "context_outlet_invoke_stream")]
#[pyo3(signature = (
    context_id,
    outlet_id,
    input,
    identity_did,
    ucan_token,
    caveats_binding_hex,
    stream_epoch,
    proof_tokens=None,
    credit_window=None,
    estimated_chunk_count=None,
))]
#[allow(clippy::needless_pass_by_value)]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)] // round-7 operator-key plumbing extends the open path
pub fn py_outlet_invoke_stream(
    context_id: &str,
    outlet_id: &str,
    input: &Bound<'_, PyDict>,
    identity_did: &str,
    ucan_token: &str,
    caveats_binding_hex: &str,
    stream_epoch: u64,
    proof_tokens: Option<Vec<String>>,
    credit_window: Option<u32>,
    estimated_chunk_count: Option<u32>,
) -> PyResult<PyOutletInvocationStream> {
    validate_inputs(
        context_id,
        outlet_id,
        identity_did,
        ucan_token,
        proof_tokens.as_deref(),
    )?;
    // Ensure the default bridge instance exists so the stream registry
    // is reachable. `with_context` below will fail with a clean
    // ContextError if the bridge has not been initialised, but we want
    // the stream-registry insert at the end of this function to succeed
    // unconditionally — calling ensure here is defensive (idempotent).
    crate::runtime::ensure_bridge_instance();
    let caveats_binding = decode_caveats_binding(caveats_binding_hex)?;
    let input_json = crate::types::py_dict_to_json(input)?;

    // Re-validate the UCAN under the full 11-step pipeline (defence in
    // depth — the runtime also validates at open, but doing it here
    // ensures the bridge surfaces a clean `UcanError` before allocating
    // any per-stream state).
    super::outlets::validate_outlet_ucan(
        context_id,
        outlet_id,
        ucan_token,
        identity_did,
        proof_tokens.as_ref(),
    )?;

    // Snapshot the bridge-owned outlet registry + handler closure.
    let (registry_snapshot, handler) = crate::runtime::with_context(context_id, |rt| {
        Ok((
            rt.outlet_registry.clone(),
            rt.outlet_handlers.get(outlet_id).cloned(),
        ))
    })?;
    let role_state = crate::runtime::with_context(context_id, |rt| Ok(rt.role_state.clone()))?;
    let signing_key = resolve_invoker_signing_key(identity_did)?;

    let ctx_id_owned = context_id.to_owned();
    let outlet_id_owned = outlet_id.to_owned();
    let identity_did_owned = identity_did.to_owned();
    let executor: Arc<dyn scp_runtime::context::outlets::invoke::OutletExecutor> =
        Arc::new(ClosureExecutor {
            ctx_id: ctx_id_owned.clone(),
            outlet_id: outlet_id_owned.clone(),
            invoker_did: identity_did_owned.clone(),
            handler,
        });

    let signing_key_arc = Arc::new(signing_key.clone());
    let params = build_open_stream_params(
        ctx_id_owned.clone(),
        outlet_id_owned.clone(),
        identity_did_owned.clone(),
        stream_epoch,
        caveats_binding,
        credit_window,
        estimated_chunk_count,
        signing_key.verifying_key(),
        Arc::clone(&signing_key_arc),
    );
    let admission = Arc::new(std::sync::Mutex::new(
        scp_runtime::context::outlets::stream::StreamAdmissionTracker::new(),
    ));

    let invoker_did_typed: scp_primitives::DID = identity_did_owned.into();
    let outlet_id_typed = scp_core::context::outlets::OutletId::from(outlet_id_owned.as_str());
    let manager = crate::runtime::context_manager()?;
    let rt = crate::runtime()?;

    let mut handle = rt
        .block_on(async {
            manager
                .open_outlet_stream(
                    &ctx_id_owned,
                    &registry_snapshot,
                    &role_state,
                    &outlet_id_typed,
                    input_json,
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
        })
        .map_err(|rejection| {
            ScpPyError::context(format!(
                "stream open rejected: {} ({})",
                rejection.slug(),
                rejection.error_code()
            ))
        })?;

    let receiver = handle
        .receiver()
        .ok_or_else(|| ScpPyError::context("stream handle has no receiver"))?;
    let request_id = *handle.request_id();
    let request_id_hex_str = request_id_hex(&request_id);

    register_stream_entry(StreamRegistryEntry {
        handle: Mutex::new(handle),
        monotonic_seq: Mutex::new(0),
        context_id: ctx_id_owned,
        outlet_id: outlet_id_owned,
        stream_epoch,
        caveats_binding,
        invoker_signing_key: signing_key,
        request_id,
    })?;

    Ok(PyOutletInvocationStream {
        rx: Arc::new(TokioMutex::new(Some(receiver))),
        request_id_hex: request_id_hex_str,
        terminated: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    })
}

/// Validates the §5.4.5 string + token inputs at the FFI boundary.
fn validate_inputs(
    context_id: &str,
    outlet_id: &str,
    identity_did: &str,
    ucan_token: &str,
    proof_tokens: Option<&[String]>,
) -> PyResult<()> {
    validate::validate_context_id(context_id)?;
    validate::validate_outlet_id(outlet_id)?;
    validate::validate_did(identity_did)?;
    validate::validate_ucan_token(ucan_token)?;
    if let Some(tokens) = proof_tokens {
        for t in tokens {
            validate::validate_ucan_token(t)?;
        }
    }
    Ok(())
}

/// Builds the §5.4.5 [`OpenStreamParams`] for an outlet stream open.
///
/// Uses 0-cost / `u64::MAX` balance because the bridge does not yet
/// wire the §19 economy pipeline into the streaming path; SCP-OUT-038
/// is the SDK story that promotes the streaming bridge to the
/// economy-aware variant.
///
/// The `operator_signing_key` is the round-7 wire-signing key the
/// dispatch pump uses to sign every chunk it emits under
/// `SCP-OUTLET-CHUNK-SIG-V1:`. In the local-context invocation case
/// (the only case this bridge implements today) the SDK that opens
/// the stream is also the executor — so the operator key is the
/// invoker's own signing key. Native bridges always pass `Some`;
/// `None` is reserved for legacy / test callers.
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
        // Native FFI bridges run the executor in-process — the
        // "operator" (chunk signer) and the "invoker" (UCAN holder)
        // are the same key custody-side. The cross-context bridge
        // path that distinguishes these two roles is the §6.2.0.5
        // re-encryption boundary; this single-context streaming path
        // is the degenerate case where invoker == operator.
        operator_signing_key: Some(operator_signing_key),
        stream_credit_stall_secs:
            scp_protocol::context::outlets::stream::DEFAULT_STREAM_CREDIT_STALL_SECS,
        stream_cancel_ack_secs: 5,
    }
}

/// Inserts an entry into the per-bridge stream registry, keyed by the
/// 32-char lowercase hex `request_id`.
fn register_stream_entry(entry: StreamRegistryEntry) -> PyResult<()> {
    let reg = registry()?;
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
/// [`StreamSessionHandle::apply_credit_grant`].
///
/// # Errors
///
/// * `ValidationError` — `grant == 0` (round-6 uniform `InvalidGrant`
///   rule).
/// * `ContextError` (slug `protocol.unknown-session`) — the
///   `request_id_hex` does not match any active stream registry
///   entry.
/// * `ContextError` — the runtime tracker rejected the grant (replay,
///   identity mismatch, escrow overflow, insufficient funds).
#[pyfunction]
#[pyo3(name = "outlet_stream_grant_credit")]
pub fn py_outlet_stream_grant_credit(request_id_hex: &str, grant: u32) -> PyResult<u32> {
    if grant == 0 {
        return Err(ScpPyError::ValidationError {
            message: "invalid grant 0: must be in (0, 2^32 - 1] (protocol.invalid-grant)"
                .to_owned(),
            code: scp_protocol::context::outlets::error_codes::CODE_PROTOCOL_SESSION.to_owned(),
        }
        .into());
    }
    let entry = lookup_entry(request_id_hex)?;

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
            ScpPyError::context("monotonic_seq overflow: stream has issued u64::MAX grants")
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
            ScpPyError::context(format!("credit grant rejected: {grant_err:?}"))
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

/// Applies a signed [`OutletStreamCancel`] to an active stream by
/// `request_id_hex` (round-7 cancel-auth tightening).
///
/// The bridge builds the [`OutletStreamCancel`] under the registry
/// entry's pinned `(context_id, outlet_id, caveats_binding)` triple,
/// signs it with the invoker's signing key (mirroring `grant_credit`),
/// and forwards it to
/// [`StreamSessionHandle::apply_outlet_cancel`]. The runtime verifies
/// the signature under the same pinned `invoker_pk` it uses for credit
/// grants — an unsigned-or-tampered cancel is rejected as
/// `OutletErrorClass::Authorization::AuthorizationFailed`.
///
/// A returning `Some(seq)` indicates the cancel was recorded; `None`
/// means the stream was already terminal at cancel receipt (the
/// runtime ignored the cancel per §5.4.5 idempotency).
///
/// # Errors
///
/// * `ContextError` (slug `protocol.unknown-session`) — `request_id_hex`
///   does not match any active stream.
/// * `ContextError` (slug `authorization.denied`, code
///   `SCP-TOOL-6110`) — the cancel signature does not verify under
///   the pinned invoker key (cannot happen via this bridge path under
///   normal operation; surfaces if the bridge's signing key has been
///   rotated out from under the runtime's pinned identity).
#[pyfunction]
#[pyo3(name = "outlet_stream_cancel")]
#[pyo3(signature = (request_id_hex, next_seq=None))]
pub fn py_outlet_stream_cancel(
    request_id_hex: &str,
    next_seq: Option<u64>,
) -> PyResult<Option<u64>> {
    let entry = lookup_entry(request_id_hex)?;
    let cancel = sign_cancel_for_entry(&entry, next_seq.unwrap_or(0));
    let handle_guard = entry
        .handle
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let recorded = handle_guard
        .apply_outlet_cancel(&cancel)
        .map_err(|cancel_err| {
            // Round-7: route the granular CancelError to the §5.4.4
            // collapsed `authorization.denied` slug + code.
            ScpPyError::ContextError {
                message: format!(
                    "cancel rejected ({}): {cancel_err:?}",
                    scp_runtime::context::outlets::stream::cancel_error_to_slug(cancel_err)
                ),
                code: scp_runtime::context::outlets::stream::cancel_error_to_code(cancel_err)
                    .to_owned(),
            }
        })?;
    Ok(recorded)
}

/// Builds and signs an [`OutletStreamCancel`] for `entry` against
/// `next_seq`. Mirrors [`sign_credit_grant`].
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
/// `chunk_json_bytes` is the canonical-JCS-encoded
/// [`OutletStreamChunk`] (the bridge accepts the full chunk encoded as
/// JSON and reconstructs the typed struct so the verification path
/// covers exactly the bytes the operator signed). All five inputs
/// match the §5.4.5 preimage block byte-for-byte.
///
/// Returns `True` if the signature verifies, `False` otherwise. Never
/// raises for a bad signature — only for malformed inputs (non-32-byte
/// pubkey / `caveats_binding`, malformed JSON).
#[pyfunction]
#[pyo3(name = "verify_chunk_signature")]
pub fn py_verify_chunk_signature(
    chunk_json: &str,
    operator_pk_bytes: &[u8],
    context_id: &str,
    outlet_id: &str,
    caveats_binding_bytes: &[u8],
) -> PyResult<bool> {
    let chunk: OutletStreamChunk =
        serde_json::from_str(chunk_json).map_err(|e| ScpPyError::ValidationError {
            message: format!("malformed chunk JSON: {e}"),
            code: scp_ffi_common::error_codes::VALID_7000.to_owned(),
        })?;
    let pk_array: [u8; 32] =
        operator_pk_bytes
            .try_into()
            .map_err(|_| ScpPyError::ValidationError {
                message: format!(
                    "operator_pk must be exactly 32 bytes, got {}",
                    operator_pk_bytes.len()
                ),
                code: scp_ffi_common::error_codes::VALID_7000.to_owned(),
            })?;
    let caveats_binding: [u8; 32] =
        caveats_binding_bytes
            .try_into()
            .map_err(|_| ScpPyError::ValidationError {
                message: format!(
                    "caveats_binding must be exactly 32 bytes, got {}",
                    caveats_binding_bytes.len()
                ),
                code: scp_ffi_common::error_codes::VALID_7000.to_owned(),
            })?;
    let pk = ed25519_dalek::VerifyingKey::from_bytes(&pk_array).map_err(|e| {
        ScpPyError::ValidationError {
            message: format!("operator_pk is not a valid Ed25519 public key: {e}"),
            code: scp_ffi_common::error_codes::VALID_7000.to_owned(),
        }
    })?;
    Ok(proto_stream::verify_chunk_signature(
        &chunk,
        &pk,
        context_id,
        outlet_id,
        &caveats_binding,
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
/// the narrowed [`InvocationCaveats`] — the bridge re-runs JCS over it
/// so the caller does not need an in-language JCS implementation.
///
/// Returns the 32-byte hash as Python bytes.
#[pyfunction]
#[pyo3(name = "compute_caveats_binding")]
pub fn py_compute_caveats_binding(
    py: Python<'_>,
    ucan_cid: &[u8],
    request_id_bytes: &[u8],
    invoker_did: &str,
    estimated_chunk_count: u32,
    effective_caveats_json: &str,
) -> PyResult<PyObject> {
    let request_id: [u8; 16] =
        request_id_bytes
            .try_into()
            .map_err(|_| ScpPyError::ValidationError {
                message: format!(
                    "request_id must be exactly 16 bytes, got {}",
                    request_id_bytes.len()
                ),
                code: scp_ffi_common::error_codes::VALID_7000.to_owned(),
            })?;
    let caveats_value: Value =
        serde_json::from_str(effective_caveats_json).map_err(|e| ScpPyError::ValidationError {
            message: format!("invalid effective_caveats JSON: {e}"),
            code: scp_ffi_common::error_codes::VALID_7000.to_owned(),
        })?;
    let caveats: InvocationCaveats =
        serde_json::from_value(caveats_value).map_err(|e| ScpPyError::ValidationError {
            message: format!("effective_caveats does not match InvocationCaveats: {e}"),
            code: scp_ffi_common::error_codes::VALID_7000.to_owned(),
        })?;
    // §5.4.5 requires JCS canonicalization of `effective_caveats` before
    // hashing — the bridge runs canonicalisation here so SDK callers do
    // not need an in-language JCS implementation. `serde` is already
    // configured on `InvocationCaveats` to skip-`None`-fields per the
    // round-5 omit-none convention (cross-SDK byte-for-byte match).
    let caveats_jcs = scp_protocol::jcs::to_vec(&caveats)
        .map_err(|e| ScpPyError::context(format!("failed to JCS-canonicalise caveats: {e}")))?;
    let binding = proto_stream::compute_caveats_binding(
        ucan_cid,
        &request_id,
        invoker_did,
        estimated_chunk_count,
        &caveats_jcs,
    );
    Ok(PyBytes::new(py, &binding).unbind().into_any())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn decode_caveats_binding(hex_str: &str) -> PyResult<[u8; 32]> {
    let bytes = hex::decode(hex_str).map_err(|e| ScpPyError::ValidationError {
        message: format!("caveats_binding_hex must be 64 hex characters: {e}"),
        code: scp_ffi_common::error_codes::VALID_7000.to_owned(),
    })?;
    bytes
        .try_into()
        .map_err(|got: Vec<u8>| ScpPyError::ValidationError {
            message: format!("caveats_binding must decode to 32 bytes, got {}", got.len()),
            code: scp_ffi_common::error_codes::VALID_7000.to_owned(),
        })
        .map_err(Into::into)
}

fn lookup_entry(request_id_hex: &str) -> PyResult<Arc<StreamRegistryEntry>> {
    // Ensure the default bridge instance exists so the registry exists
    // — this lets the unknown-session error path surface even when no
    // stream has ever been opened (e.g., a test or stale handle on the
    // SDK side calling `cancel` without prior `invoke_stream`).
    crate::runtime::ensure_bridge_instance();
    let reg = registry()?;
    reg.get(request_id_hex)
        .map(|kv| Arc::clone(kv.value()))
        .ok_or_else(|| {
            ScpPyError::ContextError {
                message: format!(
                    "stream '{request_id_hex}' not found in registry (protocol.unknown-session)"
                ),
                code: scp_protocol::context::outlets::error_codes::CODE_PROTOCOL_SESSION.to_owned(),
            }
            .into()
        })
}

fn resolve_invoker_signing_key(identity_did: &str) -> PyResult<SigningKey> {
    let rt = crate::runtime()?;
    crate::runtime::with_identity(identity_did, |entry| {
        let handle = entry.identity.active_signing_key;
        let custody = entry.custody.clone();
        rt.block_on(async move { custody.export_ed25519_signing_key(&handle).await })
            .map_err(|e| ScpPyError::context(format!("failed to export invoker signing key: {e}")))
    })
    .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

// ---------------------------------------------------------------------------
// ClosureExecutor — adapter from a Python-handler closure to `OutletExecutor`
// ---------------------------------------------------------------------------

/// Adapter that lets the existing `PyO3` `OutletHandler` closure satisfy
/// the runtime's [`OutletExecutor`] trait without touching the
/// `py_outlet_invoke` path. `exec_action_stream` and
/// `exec_query_stream` defer to the registered Python handler when
/// present and fall back to schema-only echo mode when no handler is
/// registered (matching `py_outlet_invoke`'s contract).
struct ClosureExecutor {
    ctx_id: String,
    outlet_id: String,
    invoker_did: String,
    handler: Option<crate::runtime::OutletHandler>,
}

#[async_trait::async_trait]
impl scp_runtime::context::outlets::invoke::OutletExecutor for ClosureExecutor {
    async fn exec_query_stream(
        &self,
        _ctx: &scp_runtime::context::outlets::invoke::ReadOnlyInvocation<'_>,
        input: serde_json::Value,
        tx: tokio::sync::mpsc::Sender<ChunkPayload>,
    ) -> Result<(), scp_runtime::context::outlets::invoke::OutletExecutorError> {
        self.run_handler_one_shot(input, tx).await
    }

    async fn exec_action_stream(
        &self,
        _ctx: &mut scp_runtime::context::outlets::invoke::MutableInvocation<'_>,
        input: serde_json::Value,
        tx: tokio::sync::mpsc::Sender<ChunkPayload>,
    ) -> Result<(), scp_runtime::context::outlets::invoke::OutletExecutorError> {
        self.run_handler_one_shot(input, tx).await
    }
}

impl ClosureExecutor {
    async fn run_handler_one_shot(
        &self,
        input: serde_json::Value,
        tx: tokio::sync::mpsc::Sender<ChunkPayload>,
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
// Module registration
// ---------------------------------------------------------------------------

/// Registers the streaming bridge functions and classes on `_scp_core`.
pub fn register_outlet_stream(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyOutletInvocationStream>()?;
    m.add_function(wrap_pyfunction!(py_outlet_invoke_stream, m)?)?;
    m.add_function(wrap_pyfunction!(py_outlet_stream_grant_credit, m)?)?;
    m.add_function(wrap_pyfunction!(py_outlet_stream_cancel, m)?)?;
    m.add_function(wrap_pyfunction!(py_verify_chunk_signature, m)?)?;
    m.add_function(wrap_pyfunction!(py_compute_caveats_binding, m)?)?;
    Ok(())
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

        // Signature verifies under the right preimage.
        let ok = py_verify_chunk_signature(
            &chunk_json,
            signing.verifying_key().as_bytes(),
            "ctx-stream",
            "outlet-x",
            &caveats_binding,
        )
        .expect("verify ok");
        assert!(ok, "freshly signed chunk must verify");

        // Tampering with context_id flips the result.
        let bad_ctx = py_verify_chunk_signature(
            &chunk_json,
            signing.verifying_key().as_bytes(),
            "ctx-other",
            "outlet-x",
            &caveats_binding,
        )
        .expect("verify call");
        assert!(!bad_ctx, "tampered context_id must NOT verify");

        // Tampering with caveats_binding flips the result.
        let bad_binding: [u8; 32] = [0xCD; 32];
        let bad_b = py_verify_chunk_signature(
            &chunk_json,
            signing.verifying_key().as_bytes(),
            "ctx-stream",
            "outlet-x",
            &bad_binding,
        )
        .expect("verify call");
        assert!(!bad_b, "tampered caveats_binding must NOT verify");
    }

    /// `verify_chunk_signature` rejects a 31-byte `caveats_binding` with
    /// `ValidationError`. Pure-input validation cover.
    #[test]
    fn verify_chunk_signature_rejects_short_caveats_binding() {
        let signing = fixed_signing_key();
        // Construct a minimal valid chunk JSON.
        let chunk = OutletStreamChunk {
            request_id: [0x00; 16],
            sequence: 0,
            payload: ChunkPayload::Data {
                value: serde_json::json!({}),
            },
            sig: [0u8; 64],
        };
        let chunk_json = serde_json::to_string(&chunk).expect("serialise chunk");

        let short_binding = [0u8; 31];
        let result = py_verify_chunk_signature(
            &chunk_json,
            signing.verifying_key().as_bytes(),
            "ctx",
            "outlet",
            &short_binding,
        );
        assert!(result.is_err(), "31-byte caveats_binding must be rejected");
    }

    /// `compute_caveats_binding` is deterministic — same inputs produce
    /// the same 32 bytes. Covers AC11 self-consistency.
    #[test]
    fn compute_caveats_binding_is_deterministic() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let ucan_cid = b"bafyreigh1234567890abcdef";
            let request_id: [u8; 16] = [0x77; 16];
            let invoker_did = "did:dht:z6MkInvoker";
            let caveats_json = "{\"maxCalls\":10}";
            let a = py_compute_caveats_binding(
                py,
                ucan_cid,
                &request_id,
                invoker_did,
                100,
                caveats_json,
            )
            .expect("compute a")
            .extract::<Vec<u8>>(py)
            .expect("bytes a");
            let b = py_compute_caveats_binding(
                py,
                ucan_cid,
                &request_id,
                invoker_did,
                100,
                caveats_json,
            )
            .expect("compute b")
            .extract::<Vec<u8>>(py)
            .expect("bytes b");
            assert_eq!(a, b, "binding must be deterministic");
            assert_eq!(a.len(), 32, "binding is 32 bytes");

            // Changing one input flips bytes.
            let c = py_compute_caveats_binding(
                py,
                ucan_cid,
                &request_id,
                invoker_did,
                101, // different chunk count
                caveats_json,
            )
            .expect("compute c")
            .extract::<Vec<u8>>(py)
            .expect("bytes c");
            assert_ne!(a, c, "different estimated_chunk_count must flip bytes");

            // Changing invoker_did flips bytes.
            let d = py_compute_caveats_binding(
                py,
                ucan_cid,
                &request_id,
                "did:dht:z6MkOther",
                100,
                caveats_json,
            )
            .expect("compute d")
            .extract::<Vec<u8>>(py)
            .expect("bytes d");
            assert_ne!(a, d, "different invoker_did must flip bytes");
        });
    }

    /// `compute_caveats_binding` rejects a 15-byte `request_id` with
    /// `ValidationError`.
    #[test]
    fn compute_caveats_binding_rejects_short_request_id() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let short = [0u8; 15];
            let result = py_compute_caveats_binding(py, b"cid", &short, "did:dht:x", 1, "{}");
            assert!(result.is_err(), "15-byte request_id must be rejected");
        });
    }

    /// `outlet_stream_grant_credit` rejects `grant == 0` with
    /// `ValidationError` per OUT-031 round-6 uniform `InvalidGrant` rule.
    #[test]
    fn grant_credit_rejects_zero_grant() {
        let result = py_outlet_stream_grant_credit("00".repeat(16).as_str(), 0);
        assert!(result.is_err(), "grant=0 must be rejected");
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains("invalid grant 0") || err_str.contains("protocol.invalid-grant"),
            "error must mention invalid-grant: {err_str}"
        );
    }

    /// `outlet_stream_cancel` returns `ContextError` when the
    /// `request_id_hex` does not match any registry entry.
    #[test]
    fn cancel_returns_unknown_session_for_missing_request() {
        let result = py_outlet_stream_cancel("ff".repeat(16).as_str(), Some(0));
        assert!(result.is_err(), "missing request_id must be rejected");
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains("not found") || err_str.contains("unknown-session"),
            "error must mention unknown-session: {err_str}"
        );
    }
}
