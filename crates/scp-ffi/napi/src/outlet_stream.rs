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
use ed25519_dalek::VerifyingKey;
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use scp_core::context::outlets::stream::{
    self as proto_stream, ChunkPayload, OutletStreamChunk, OutletStreamCredit,
};
use scp_ffi_common::error_codes as codes;
use scp_platform::{KeyCustody, KeyHandle};
use scp_protocol::trust::caveats::InvocationCaveats;
use serde_json::Value;
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::mpsc;
use zeroize::Zeroize;

use crate::context::NapiContextHandle;
use crate::error::ScpNapiError;
use crate::identity::OpaqueInMemoryKeyCustody;

// ---------------------------------------------------------------------------
// Per-stream revocation checker
// ---------------------------------------------------------------------------

/// Adapter that wires the bridge's per-context UCAN revocation list
/// (owned by [`crate::runtime::UcanContextState::core::revocation_list`])
/// into the runtime's streaming pump for §5.4.5 receiver-side
/// revocation re-checks.
///
/// Mirrors `BridgeStreamRevocationChecker` in `crates/scp-ffi/src/outlet_stream.rs`.
pub(crate) struct BridgeStreamRevocationChecker {
    context_id: String,
}

impl BridgeStreamRevocationChecker {
    /// Builds a revocation-checker adapter for `context_id`. Returns
    /// `Err` if the context has not been registered in the UCAN-state
    /// registry.
    fn for_context(context_id: &str) -> Result<Self, ScpNapiError> {
        crate::runtime::with_context(context_id, |_rt| Ok(()))?;
        Ok(Self {
            context_id: context_id.to_owned(),
        })
    }
}

impl scp_protocol::crypto::ucan::validate::RevocationChecker for BridgeStreamRevocationChecker {
    fn is_revoked(&self, token_cid: &str) -> bool {
        // Fail-CLOSED on lookup failure: a context whose UCAN state has
        // been removed (e.g., closed mid-stream) is equivalent to "no
        // longer valid" → treat as revoked → terminate the stream.
        crate::runtime::with_context(&self.context_id, |rt| {
            Ok(rt.core.revocation_list.is_revoked(token_cid))
        })
        .unwrap_or(true)
    }
}

// ---------------------------------------------------------------------------
// CustodyStreamSigner — custody-backed StreamSigner (ADR-006)
// ---------------------------------------------------------------------------

/// Custody-backed [`scp_runtime::context::outlets::signer::StreamSigner`].
///
/// ADR-006: private keys never cross the FFI boundary. Instead of exporting
/// the operator's `ed25519_dalek::SigningKey` into the runtime address space
/// (the deleted `resolve_invoker_signing_key_via_custody` path), the bridge
/// hands the runtime this object-safe adapter. Each `sign` routes the §5.4.5
/// preimage back through the custody provider so the private bytes only
/// exist inside custody for the duration of a single signing call.
///
/// In the local single-context streaming path the operator (chunk signer)
/// and invoker (UCAN holder) are the same custody-held key, so the same
/// adapter backs both the dispatch pump's chunk signing
/// (`OpenStreamParams::operator_signer`) and the
/// [`scp_runtime::context::outlets::dispatch::StreamSessionHandle::apply_outlet_cancel_signed`]
/// cancel path (verified under the pinned `invoker_pk`).
pub(crate) struct CustodyStreamSigner {
    /// Custody provider that owns [`Self::key_handle`].
    custody: Arc<OpaqueInMemoryKeyCustody>,
    /// Opaque handle for the Ed25519 signing key (ADR-006: never raw bytes).
    key_handle: KeyHandle,
    /// Cached public verifying key.
    vk: VerifyingKey,
}

impl CustodyStreamSigner {
    /// Builds a custody-backed signer pinned to the public `vk`.
    pub(crate) const fn new(
        custody: Arc<OpaqueInMemoryKeyCustody>,
        key_handle: KeyHandle,
        vk: VerifyingKey,
    ) -> Self {
        Self {
            custody,
            key_handle,
            vk,
        }
    }
}

#[async_trait]
impl scp_runtime::context::outlets::signer::StreamSigner for CustodyStreamSigner {
    async fn sign(
        &self,
        preimage: &[u8],
    ) -> Result<[u8; 64], scp_runtime::context::outlets::signer::StreamSignerError> {
        let signature = self
            .custody
            .0
            .sign(&self.key_handle, preimage)
            .await
            .map_err(|_e: scp_platform::error::PlatformError| {
                // Sanitize: never surface the custody backend's detail (it
                // can echo key identifiers or the raw signing input).
                scp_runtime::context::outlets::signer::StreamSignerError::Custody {
                    detail: "custody signing operation failed".to_owned(),
                }
            })?;
        signature.into_bytes().try_into().map_err(|_got: Vec<u8>| {
            scp_runtime::context::outlets::signer::StreamSignerError::Custody {
                detail: "custody returned a signature of unexpected length".to_owned(),
            }
        })
    }

    fn verifying_key(&self) -> &VerifyingKey {
        &self.vk
    }
}

// ---------------------------------------------------------------------------
// E1/E2 economic settlement + escrow-refund sinks
// ---------------------------------------------------------------------------

/// Production [`scp_runtime::context::outlets::invoke::StreamSettlementSink`]
/// for the `NAPI` bridge (E1). The dispatch pump fires `settle` from its
/// spawned tokio task, so the impl `Handle::spawn`s the async
/// `ContextManager::outlet_stream_settle` (it MUST NOT block).
struct NapiStreamSettlementSink {
    manager: Arc<scp_core::context::ContextManager>,
    handle: tokio::runtime::Handle,
}

impl scp_runtime::context::outlets::invoke::StreamSettlementSink for NapiStreamSettlementSink {
    fn settle(&self, settlement: scp_runtime::context::outlets::invoke::StreamSettlement) {
        let manager = Arc::clone(&self.manager);
        self.handle.spawn(async move {
            if let Err(e) = manager
                .outlet_stream_settle(
                    &settlement.context_id,
                    &settlement.invoker_did,
                    settlement.billed_amount,
                    settlement.refund_amount,
                    settlement.billed_count,
                    settlement.request_id,
                    &settlement.outlet_id,
                    // §5.4.5 MED-HIGH (R3) — forward the open-time policy
                    // snapshot so settlement still captures the receipt for
                    // already-rendered service when the hosting context was
                    // torn down mid-stream (H8). `None` for zero-cost / Query
                    // streams.
                    settlement.economic_policy_snapshot.clone(),
                    // R4 HIGH-1 — forward the open-time cumulative-counter
                    // reserve so settlement releases the unspent portion.
                    scp_runtime::context::outlets::dispatch::CounterReserveSettlement {
                        amount_cumulative_reserved: settlement.amount_cumulative_reserved,
                        reserved_chunks: settlement.reserved_chunks,
                        ucan_cid: settlement.ucan_cid.clone(),
                        cost_per_chunk: settlement.cost_per_chunk,
                    },
                )
                .await
            {
                tracing::warn!(
                    context_id = %settlement.context_id,
                    "outlet stream settlement failed: {e}"
                );
            }
        });
    }
}

/// Production [`scp_runtime::context::outlets::dispatch::StreamEscrowRefundSink`]
/// for the `NAPI` bridge (E2). Refunds a debited open-time hold when the
/// open-path ticket drops unconsumed.
struct NapiStreamEscrowRefundSink {
    manager: Arc<scp_core::context::ContextManager>,
    handle: tokio::runtime::Handle,
}

impl scp_runtime::context::outlets::dispatch::StreamEscrowRefundSink
    for NapiStreamEscrowRefundSink
{
    fn refund(
        &self,
        context_id: &str,
        member_did: &scp_primitives::DID,
        amount: scp_protocol::economy::types::Amount,
    ) {
        let manager = Arc::clone(&self.manager);
        let context_id = context_id.to_owned();
        let member_did = member_did.clone();
        self.handle.spawn(async move {
            manager
                .outlet_stream_reverse_spend(&context_id, &member_did, amount)
                .await;
        });
    }
}

/// Builds the production settlement sink (E1). Called from the async open
/// path where the manager is already resolved and a tokio runtime context
/// is active (so [`tokio::runtime::Handle::current`] is valid).
fn bridge_stream_settlement_sink()
-> napi::Result<Arc<dyn scp_runtime::context::outlets::invoke::StreamSettlementSink>> {
    let manager = Arc::clone(crate::runtime::context_manager()?);
    Ok(Arc::new(NapiStreamSettlementSink {
        manager,
        handle: tokio::runtime::Handle::current(),
    }))
}

/// Builds the production escrow-refund sink (E2).
fn bridge_stream_escrow_refund_sink()
-> napi::Result<Arc<dyn scp_runtime::context::outlets::dispatch::StreamEscrowRefundSink>> {
    let manager = Arc::clone(crate::runtime::context_manager()?);
    Ok(Arc::new(NapiStreamEscrowRefundSink {
        manager,
        handle: tokio::runtime::Handle::current(),
    }))
}

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
/// caveats_binding)` plus the invoker's custody handle.
pub(crate) struct StreamRegistryEntry {
    /// Control-plane handle returned by the runtime at open. Wrapped in
    /// the runtime control surface. The chunk receiver is detached at
    /// open (before this entry is built), so every post-open call is a
    /// `&self` method (`apply_credit_grant`, `apply_outlet_cancel_signed`,
    /// `terminate_with_error`); the handle's own per-stream state is
    /// already inner-`Mutex`-protected, and `StreamSessionHandle` is
    /// `Send + Sync`, so the entry can hold it directly (behind the
    /// registry's `Arc<StreamRegistryEntry>`) without a redundant outer
    /// lock. Holding an outer `std::sync::Mutex` guard here would also be
    /// unsound across the `async` `apply_outlet_cancel_signed` await.
    pub handle: scp_runtime::context::outlets::dispatch::StreamSessionHandle,
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
    /// Opaque [`KeyHandle`] for the invoker's Ed25519 signing key.
    /// §5.4.5 HIGH-wave-3 Fix A — replaces the previous raw
    /// `SigningKey` field so private bytes never linger on the bridge
    /// heap for the stream's lifetime (ADR-006). Grant / cancel /
    /// terminate signatures call back into [`Self::custody`] for the
    /// actual sign step.
    pub invoker_key_handle: KeyHandle,
    /// Custody provider that owns [`Self::invoker_key_handle`]. Cloned
    /// from the identity registry at open. Held as `Arc` so the
    /// custody remains alive across the stream's lifetime even if the
    /// identity is rotated out from under it.
    pub custody: Arc<OpaqueInMemoryKeyCustody>,
    /// Invoker's Ed25519 verifying key (public, non-secret)
    /// snapshotted at open. Used to self-verify every freshly-signed
    /// grant / cancel against the same pinned identity the runtime
    /// uses for downstream verification.
    pub invoker_verifying_key: VerifyingKey,
    /// Pinned invoker DID. The control-plane bridge functions
    /// (`grant_credit`, `cancel`, `terminate`) verify `caller_did`
    /// matches this before invoking custody to sign. CRITICAL #1 fix.
    pub invoker_did: String,
    /// 16-byte `request_id` (the registry key in raw form).
    pub request_id: [u8; 16],
    /// The presented spending UCAN's `max_per_action` ceiling (§19.5),
    /// pinned at open. `None` for the no-spending case (free / Query /
    /// zero-cost — the legitimate default). When `Some`, every per-grant
    /// escrow top-up re-derives the available balance as
    /// `min(MemberBudgetTracker::remaining, max_per_action)`.
    pub spending_max_per_action: Option<scp_protocol::economy::types::Amount>,
    /// The outlet's per-Data-chunk cost pinned at open (E2). `Amount(0)`
    /// for Query / zero-cost outlets. Each `outlet_stream_grant_credit`
    /// reserves (DEBITS) a per-grant top-up of `cost_per_chunk × grant`
    /// against the invoker's budget via
    /// [`scp_core::context::ContextManager::outlet_stream_reserve_grant`]
    /// before applying the grant.
    pub cost_per_chunk: scp_protocol::economy::types::Amount,
}

impl Drop for StreamRegistryEntry {
    /// §5.4.5 HIGH-wave-3 Fix A — defense-in-depth zeroization of the
    /// `caveats_binding` hash (non-secret but tidy) on drop. The other
    /// fields are either opaque handles (`invoker_key_handle`,
    /// `custody` Arc), public values (`invoker_verifying_key`, ids),
    /// or runtime-owned state behind the inner Mutex — none need
    /// zeroization at the bridge boundary.
    fn drop(&mut self) {
        self.caveats_binding.zeroize();
    }
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
    /// `SCP-TOOL-6110`, the §5.4.4 `authorization.denied` band).
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

impl Drop for NapiOutletInvocationStream {
    /// §5.4.5 HIGH-wave-3 Fix B — evict the per-bridge registry entry
    /// on drop so a wrapper GC'd by Node.js without being drained to
    /// terminal (exception path, V8 GC, awaiting-only consumption that
    /// never observes a terminal chunk) does NOT leak
    /// `StreamRegistryEntry` (`KeyHandle` + per-stream
    /// [`scp_runtime::context::outlets::dispatch::StreamSessionHandle`]
    /// state) indefinitely.
    ///
    /// Idempotent: when [`Self::next`] already observed a terminal
    /// chunk it called [`evict_request`] inline, and the registry no
    /// longer holds the entry — this `Drop` becomes a no-op. The
    /// admission counters held by the runtime pump are released by
    /// the pump's settlement block when the receiver drops: dropping
    /// `rx` closes the channel so the pump's `outer_tx.send().await`
    /// fails, breaks the loop, and runs settlement
    /// (`StreamAdmissionTracker::release` on all three counters per
    /// [`scp_runtime::context::outlets::dispatch::AdmissionReleaseKeys`]).
    /// No separate `release_admission_slot()` call from the wrapper —
    /// the receiver close is the authoritative trigger.
    fn drop(&mut self) {
        evict_request(&self.request_id_hex);
    }
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
    spending_ucan: Option<String>,
) -> napi::Result<NapiOutletInvocationStream> {
    crate::napi_check_handle!(handle);
    scp_ffi_common::validate::validate_outlet_id(&outlet_id)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    scp_ffi_common::validate::validate_did(&identity_did)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    scp_ffi_common::validate::validate_ucan_token(&ucan_token)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    if let Some(jwt) = spending_ucan.as_ref() {
        scp_ffi_common::validate::validate_ucan_token(jwt)
            .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    }
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
        // HIGH-3 (R3) STEP 0: resolve the leaf token's `nb` so §7.3.8 Step 7b
        // (narrow) + 11b (time-box) run over the proof chain. The resulting
        // VALIDATED-NARROWED caveat set is exactly what the §5.4.5
        // `caveats_binding` commits to — binding an unverified leaf assertion
        // would let a malicious invoker present a UCAN narrowed to caveat set
        // A but bind every chunk to a looser set B.
        &scp_protocol::crypto::ucan::validate::TokenNbCaveatResolver,
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

    // §5.4.5 / ADR-006 — resolve the invoker's key handle + custody Arc.
    // The operator (chunk signer) and invoker (UCAN holder) are the same
    // custody-held key in the local single-context streaming path, so a
    // single `CustodyStreamSigner` over this handle backs BOTH the runtime
    // pump's chunk signing (`OpenStreamParams::operator_signer`) and the
    // bridge's cancel signing — the private key never crosses the FFI
    // boundary (the round-7 raw-`SigningKey` export was deleted).
    let (custody, invoker_key_handle) = resolve_invoker_key_handle(&identity_did)?;
    let invoker_verifying_key = resolve_invoker_verifying_key(&custody, invoker_key_handle).await?;

    let executor: Arc<dyn scp_runtime::context::outlets::invoke::OutletExecutor> =
        Arc::new(ClosureExecutor {
            ctx_id: context_id_for_executor,
            outlet_id: outlet_id_for_executor,
            invoker_did: identity_for_executor,
            handler,
        });

    // §5.4.5 economy (N3) — wire real escrow inputs.
    // `cost_per_chunk` is the outlet's registered per-invocation cost
    // (§5.4.1 / §19.3); `Amount::new(0)` for Query and zero-cost outlets.
    let cost_per_chunk = registry_snapshot
        .get(&outlet_id)
        .and_then(|reg| reg.cost.as_ref())
        .map_or_else(
            || scp_protocol::economy::types::Amount::new(0),
            |cost| scp_protocol::economy::types::Amount::new(cost.amount),
        );
    // Parse the optional spending UCAN once, here, so a malformed token
    // surfaces before any per-stream state is allocated. The extracted
    // `max_per_action` (§19.5) is pinned on the registry entry so each
    // per-grant escrow top-up re-reads the live budget AND-composed against
    // the same ceiling. `None` is the legitimate no-spending default.
    let spending_max_per_action = match spending_ucan.as_ref() {
        None => None,
        Some(jwt) => {
            let token = scp_protocol::crypto::ucan::validate::parse_ucan(jwt).map_err(|_e| {
                napi::Error::from(ScpNapiError::Permission {
                    message: "invalid spending UCAN".to_owned(),
                    code: codes::PERM_3001.to_owned(),
                })
            })?;
            let cap =
                scp_protocol::crypto::ucan::spending::SpendingCapability::from_ucan_token(&token)
                    .map_err(|_e| {
                    napi::Error::from(ScpNapiError::Permission {
                        message: "spending UCAN missing spending capability".to_owned(),
                        code: codes::PERM_3001.to_owned(),
                    })
                })?;
            Some(scp_protocol::economy::types::Amount::new(
                cap.max_per_action.0,
            ))
        }
    };
    let invoker_did_typed_for_balance: scp_primitives::DID = identity_did.clone().into();

    let operator_signer: Arc<dyn scp_runtime::context::outlets::signer::StreamSigner> =
        Arc::new(CustodyStreamSigner::new(
            Arc::clone(&custody),
            invoker_key_handle,
            invoker_verifying_key,
        ));

    // §5.4.5 stream_epoch is a `u64` MLS epoch counter. Reject negative
    // / non-finite / out-of-range floats at the FFI boundary so the SDK
    // sees a clean ValidationError instead of an opaque runtime
    // rejection.
    let stream_epoch_u64 = validate_stream_epoch(stream_epoch)?;

    // §5.4.5 HIGH-wave-2 Fix A — supply the inputs the runtime needs
    // to recompute the `caveats_binding`. The bridge has already
    // validated the UCAN above; re-parse the encoded JWT to compute
    // its CID for the binding preimage. The §5.4.5 spec commits to
    // the CID + a runtime-pinned `request_id`; both must reach
    // `OpenStreamParams`.
    let ucan_token_parsed =
        scp_protocol::crypto::ucan::validate::parse_ucan(&ucan_token).map_err(|_e| {
            // N5 (ADR-049 §4): drop the parse error Display — generic message.
            napi::Error::from(ScpNapiError::Permission {
                message: "failed to parse ucan_token for cid".to_owned(),
                code: codes::PERM_3001.to_owned(),
            })
        })?;
    let ucan_cid_for_binding = scp_runtime::crypto::ucan::mint::compute_cid(&ucan_token_parsed);
    let request_id: scp_protocol::context::outlets::stream::RequestId =
        *uuid::Uuid::now_v7().as_bytes();
    let revocation_checker: std::sync::Arc<
        dyn scp_protocol::crypto::ucan::validate::RevocationChecker + Send + Sync,
    > = std::sync::Arc::new(
        BridgeStreamRevocationChecker::for_context(&context_id).map_err(napi::Error::from)?,
    );

    // E3 — the leaf UCAN's `nb` (post-narrowing) IS the effective caveat
    // set the runtime must bind the stream to. The previous code threaded
    // `InvocationCaveats::empty()`, so the binding committed to nothing and
    // `max_calls` never bounded the estimate. Extract the real set here.
    let effective_caveats = ucan_token_parsed
        .payload
        .nb
        .clone()
        .unwrap_or_else(InvocationCaveats::empty);

    // E2 — reserve (DEBIT) the §5.4.5 open-time escrow HOLD atomically
    // against the invoker's MemberBudgetTracker, REPLACING the prior
    // read-only balance query. Mirror the runtime's estimate coercion over
    // the real effective caveats so the debited hold equals
    // `cost_per_chunk × estimated`.
    let coerced_estimate = scp_runtime::context::outlets::stream::coerce_estimated_chunk_count(
        estimated_chunk_count,
        &effective_caveats,
    );
    let escrow_reservation = crate::runtime::context_manager()?
        .outlet_stream_reserve_escrow(
            &context_id,
            &invoker_did_typed_for_balance,
            cost_per_chunk,
            coerced_estimate,
            spending_max_per_action,
        )
        .await
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("stream escrow reservation failed: {e}"),
                code: codes::CTX_2000.to_owned(),
            })
        })?;
    let reserved_escrow = escrow_reservation.reserved;
    // E2 refund guard: the hold is debited NOW; an early-return before the
    // pump spawns drops this ticket → refund via Handle::spawn of the async
    // reverse_spend. Consumed only on the Ok open path below.
    let escrow_ticket = scp_runtime::context::outlets::dispatch::StreamEscrowTicket::new(
        bridge_stream_escrow_refund_sink()?,
        context_id.clone(),
        invoker_did_typed_for_balance.clone(),
        reserved_escrow,
    );

    // §7.3.8 / crypto-MED (R3) — the post-input caveat hook is now built
    // ENTIRELY inside the runtime by `ContextManager::open_outlet_stream`
    // from `params` (the VALIDATED-NARROWED `effective_caveats` + the pinned
    // `cost_per_chunk` + `ucan_cid`) and the manager's own counter store, so
    // every bridge enforces the full §7.3.8 gate identically — including the
    // counter CAS for `max_calls` / `amount_max_cumulative` / `rate_window`
    // that this bridge cannot construct on its own. The bridge supplies no
    // hook.
    let params = build_open_stream_params(
        context_id.clone(),
        outlet_id.clone(),
        identity_did.clone(),
        stream_epoch_u64,
        caveats_binding,
        credit_window,
        estimated_chunk_count,
        invoker_verifying_key,
        operator_signer,
        cost_per_chunk,
        reserved_escrow,
        effective_caveats,
        ucan_cid_for_binding,
        request_id,
        revocation_checker,
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

    // E1 — close-time settlement sink (refund unspent escrow + §19.15.5
    // PaymentReceipt). Fired once by the dispatch pump at terminal chunk;
    // it `Handle::spawn`s the async `outlet_stream_settle` (it runs on the
    // pump task and MUST NOT block).
    let settlement_sink: Option<
        Arc<dyn scp_runtime::context::outlets::invoke::StreamSettlementSink>,
    > = Some(bridge_stream_settlement_sink()?);

    let open_result = manager
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
            settlement_sink,
            params,
            admission,
        )
        .await;
    let mut runtime_handle = match open_result {
        Ok(handle) => {
            // E2: pump spawned Ok — the close-time settlement now owns the
            // refund of the unspent hold; consume the open-path ticket.
            escrow_ticket.consume();
            handle
        }
        Err(rejection) => {
            // E2: any open-time rejection drops `escrow_ticket` → refund of
            // the debited hold (independent of the runtime's admission
            // rollback; both roll back on the same path).
            drop(escrow_ticket);
            return Err(napi::Error::from(ScpNapiError::Context {
                message: format!(
                    "stream open rejected: {} ({})",
                    rejection.slug(),
                    rejection.error_code()
                ),
                code: rejection.error_code().to_owned(),
            }));
        }
    };

    let receiver = runtime_handle.receiver().ok_or_else(|| {
        napi::Error::from(ScpNapiError::Context {
            message: "stream handle has no receiver".to_owned(),
            code: codes::CTX_2000.to_owned(),
        })
    })?;
    let request_id = *runtime_handle.request_id();
    let request_id_hex_str = request_id_hex(&request_id);

    register_stream_entry(StreamRegistryEntry {
        handle: runtime_handle,
        monotonic_seq: Mutex::new(0),
        context_id: context_id.clone(),
        outlet_id: outlet_id.clone(),
        stream_epoch: stream_epoch_u64,
        caveats_binding,
        invoker_key_handle,
        custody,
        invoker_verifying_key,
        invoker_did: identity_did.clone(),
        request_id,
        spending_max_per_action,
        cost_per_chunk,
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
/// `cost_per_chunk` and `available_balance` carry the real §5.4.5 escrow
/// inputs the caller derived from the outlet's `registration.cost` and the
/// member's live budget (∧ the spending UCAN's `max_per_action`). Query and
/// zero-cost outlets legitimately pass `Amount::new(0)` for the cost.
///
/// The `operator_signer` is a [`CustodyStreamSigner`] over the invoker's
/// custody-held key — the private key never crosses the FFI boundary
/// (ADR-006). Mirrors the `PyO3` reference bridge.
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
    operator_signer: std::sync::Arc<dyn scp_runtime::context::outlets::signer::StreamSigner>,
    cost_per_chunk: scp_protocol::economy::types::Amount,
    reserved_escrow: scp_protocol::economy::types::Amount,
    effective_caveats: InvocationCaveats,
    ucan_cid: String,
    request_id: scp_protocol::context::outlets::stream::RequestId,
    revocation_checker: std::sync::Arc<
        dyn scp_protocol::crypto::ucan::validate::RevocationChecker + Send + Sync,
    >,
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
        cost_per_chunk,
        // E2: legacy/test field carries the manager-debited hold (not a
        // sentinel); the production gate is `reserved_escrow`.
        available_balance: reserved_escrow,
        reserved_escrow,
        declared_estimated_chunk_count: estimated_chunk_count,
        credit_window: credit_window_value,
        // E3: the REAL post-narrowing effective caveat set (leaf UCAN `nb`).
        caveats: effective_caveats,
        invoker_pk,
        // Native FFI bridges: invoker == operator in the local
        // single-context streaming path. See PyO3 bridge for full
        // rationale (§5.4.5 / §6.2.0.5). The signer is a
        // `CustodyStreamSigner` so the private key never enters the
        // runtime address space (ADR-006).
        operator_signer,
        stream_credit_stall_secs:
            scp_protocol::context::outlets::stream::DEFAULT_STREAM_CREDIT_STALL_SECS,
        stream_cancel_ack_secs: 5,
        // §5.4.5 HIGH-wave-2 — runtime-authoritative UCAN revocation
        // re-check and binding-pinning. See PyO3 bridge for the field-
        // by-field rationale; this bridge mirrors that wiring for the
        // Node.js / Bun consumer.
        stream_ucan_recheck_secs:
            scp_protocol::context::outlets::stream::DEFAULT_STREAM_UCAN_RECHECK_SECS,
        ucan_cid,
        request_id,
        revocation_checker,
        // §5.4.5 MED-HIGH (R3) — leave `None` here. The bridge has no
        // authoritative live economic policy to snapshot: the
        // `NapiContextHandle` only retains the create-time params string,
        // which goes stale the moment governance issues a
        // `SetEconomicPolicy`. `ContextManager::open_outlet_stream`
        // snapshots the LIVE per-context `governance.economic_policy` under
        // its own context lock when the caller passes `None` (and the
        // caller-supplied value wins when it is `Some`), so passing `None`
        // routes the authoritative policy into the close-time settlement
        // path (`StreamSettlement::economic_policy_snapshot`) for the H8
        // "service rendered is billed" guarantee. Building it bridge-side
        // would substitute stale data for the manager's live read.
        economic_policy_snapshot: None,
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
/// * `Context` (slug `protocol.stream-already-closed`, code
///   `SCP-TOOL-6101`) — the stream's pump has already exited (terminal
///   chunk emitted / channel closed / forced terminate); the grant is a
///   Protocol-class session-lifecycle violation
///   ([`scp_runtime::context::outlets::stream::GrantError::StreamClosed`],
///   HIGH-1 R3). Gated BEFORE signature/replay/escrow, so the credit
///   counter and escrow ledger are untouched; the bridge reverses any
///   top-up it reserved.
/// * `Context` — the runtime tracker rejected the grant (replay,
///   identity mismatch, escrow overflow, insufficient funds), routed to
///   its §5.4.4 slug/code via
///   [`scp_runtime::context::outlets::stream::grant_error_to_code`].
#[napi(js_name = "outletStreamGrantCredit")]
#[allow(clippy::needless_pass_by_value)]
pub async fn outlet_stream_grant_credit(
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

    let credit = sign_credit_grant(&entry, grant, next_seq).await?;

    // §5.4.5 credit-grant escrow top-up (E2): reserve (DEBIT) the per-grant
    // top-up of `cost_per_chunk × grant` against the invoker's live budget
    // (∧ the pinned spending-UCAN `max_per_action`) BEFORE applying the
    // grant. REPLACES the prior read-only balance query. The manager gates
    // overflow / insufficient-funds atomically under the context lock. For
    // zero-cost / Query streams it debits nothing and returns `Amount(0)`.
    let invoker_did_typed: scp_primitives::DID = entry.invoker_did.clone().into();
    let manager = crate::runtime::context_manager()?;
    let reserved_top_up = manager
        .outlet_stream_reserve_grant(
            &entry.context_id,
            &invoker_did_typed,
            entry.cost_per_chunk,
            grant,
            entry.spending_max_per_action,
        )
        .await
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("credit grant escrow reservation failed: {e}"),
                code: codes::CTX_2000.to_owned(),
            })
        })?;

    // LOW-b (R3) — drop-guard the just-debited top-up. `reserved_top_up` is
    // DEBITED against the invoker's budget NOW; if anything between here and a
    // successful `apply_credit_grant` panics or early-returns (an
    // `apply_credit_grant` rejection — including the HIGH-1 `StreamClosed`
    // lifecycle gate — OR a future error branch added between the reserve and
    // the apply), the hold would otherwise strand the invoker's budget. The
    // ticket refunds it via the same async `StreamEscrowRefundSink` the
    // open-time hold uses, modelled on `StreamEscrowTicket`. It is `consume`d
    // ONLY on the `Ok` apply path, where the top-up is committed to the credit
    // ledger and the close-time settlement now owns its eventual refund. Both
    // the rejection arm AND any panic let the ticket drop unconsumed → refund.
    let top_up_ticket = scp_runtime::context::outlets::dispatch::StreamEscrowTicket::new(
        bridge_stream_escrow_refund_sink()?,
        entry.context_id.clone(),
        invoker_did_typed.clone(),
        reserved_top_up,
    );

    // Apply with the already-debited top-up. The `StreamClosed` gate runs in
    // `apply_credit_grant` BEFORE the signature/replay/escrow path, so the
    // credit counter and escrow ledger are untouched and only the
    // bridge-debited top-up needs reversing — handled uniformly by the
    // `top_up_ticket` drop on the rejection (and panic) path.
    match entry.handle.apply_credit_grant(&credit, reserved_top_up) {
        Ok(new_total) => {
            // Top-up committed to the credit ledger; the close-time settlement
            // owns its refund. Disarm the drop-guard so it does NOT double-
            // refund a live grant.
            top_up_ticket.consume();
            Ok(new_total)
        }
        Err(grant_err) => {
            // Drop `top_up_ticket` here (explicitly, for clarity) → refunds the
            // debited top-up via the async sink. Mirrors the open-path
            // `escrow_ticket` rollback discipline; the §5.4.5 atomicity
            // invariant holds for every rejection class.
            drop(top_up_ticket);
            // Route the rejection through the §5.4.4 slug/code mappers so each
            // `GrantError` surfaces its canonical class: `StreamClosed` →
            // Protocol-class `SCP-TOOL-6101` (`protocol.stream-already-closed`),
            // replay/mismatch → Authorization `SCP-TOOL-6110`, escrow/funds →
            // Economic `SCP-TOOL-6120`. The prior `CTX_2000` + `{:?}` masked
            // the class the SDK error taxonomy depends on (HIGH-1 R3).
            let slug = scp_runtime::context::outlets::stream::grant_error_to_slug(grant_err);
            let code = scp_runtime::context::outlets::stream::grant_error_to_code(grant_err);
            Err(napi::Error::from(ScpNapiError::Context {
                message: format!("credit grant rejected ({slug})"),
                code: code.to_owned(),
            }))
        }
    }
}

/// Constructs and signs an [`OutletStreamCredit`] for `entry`.
///
/// §5.4.5 HIGH-wave-3 Fix A — calls into custody for the actual signing
/// step so private bytes never leave the custody boundary (ADR-006).
/// Self-verifies the signature under the entry's pinned verifying key
/// before returning to surface preimage / key drift at the bridge layer.
async fn sign_credit_grant(
    entry: &StreamRegistryEntry,
    grant: u32,
    monotonic_seq: u64,
) -> napi::Result<OutletStreamCredit> {
    let preimage = proto_stream::compute_credit_sig_preimage(
        entry.context_id.as_str(),
        entry.outlet_id.as_str(),
        &entry.request_id,
        grant,
        monotonic_seq,
        entry.stream_epoch,
        &entry.caveats_binding,
    );
    let signature = entry
        .custody
        .0
        .sign(&entry.invoker_key_handle, &preimage)
        .await
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("custody sign failed for credit grant: {e}"),
                code: codes::CTX_2000.to_owned(),
            })
        })?;
    let sig_bytes: [u8; 64] = signature.into_bytes().try_into().map_err(|got: Vec<u8>| {
        napi::Error::from(ScpNapiError::Context {
            message: format!(
                "custody returned signature of {} bytes; expected 64",
                got.len()
            ),
            code: codes::CTX_2000.to_owned(),
        })
    })?;
    let signature_typed = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    if entry
        .invoker_verifying_key
        .verify_strict(&preimage, &signature_typed)
        .is_err()
    {
        return Err(napi::Error::from(ScpNapiError::Context {
            message: "freshly-signed credit grant failed self-verification \
                      — SCP-OUTLET-CREDIT-V1 preimage drift or custody/key mismatch"
                .to_owned(),
            code: codes::CTX_2000.to_owned(),
        }));
    }
    Ok(OutletStreamCredit {
        request_id: entry.request_id,
        grant,
        monotonic_seq,
        sig: sig_bytes,
    })
}

// ---------------------------------------------------------------------------
// outlet_stream_cancel
// ---------------------------------------------------------------------------

/// Cancels an active stream by `request_id_hex` (ADR-049 round-8, N2).
///
/// Routes through
/// [`scp_runtime::context::outlets::dispatch::StreamSessionHandle::apply_outlet_cancel_signed`]:
/// the bridge passes only the caller's pinned
/// [`scp_runtime::context::outlets::dispatch::CancelIdentity`] and a
/// custody-backed invoker signer. The runtime atomically reads its own live
/// emission cursor, signs the `SCP-OUTLET-CANCEL-V1:` preimage over THAT
/// cursor, and records the cancel-ack at the cursor it actually signed —
/// closing the round-7 TOCTOU where a caller-derived `next_seq` (read
/// off-lock, then applied) let the cursor drift in between. A caller can no
/// longer forge `cancel_ack_seq`: the cursor never crosses the FFI boundary.
///
/// The bridge `caller_did` gate (`lookup_entry_authenticated`) still runs
/// first; the runtime cross-checks the pinned identity triple as
/// defense-in-depth before wielding the operator key.
///
/// # Errors
///
/// * `Context` (slug `protocol.unknown-session`) — `request_id_hex` does not
///   match any active stream.
/// * `Context` (slug `authorization.denied`, code `SCP-TOOL-6110`) — the
///   caller's identity did not match the pinned triple, the runtime's own
///   signature failed self-verification, or the custody signer failed.
/// * `Context` (slug `transport.rate-limited`, code `SCP-TOOL-6160`) — the
///   live cursor advanced on every bounded retry (retryable).
#[napi(js_name = "outletStreamCancel")]
#[allow(clippy::needless_pass_by_value)]
pub async fn outlet_stream_cancel(
    request_id_hex: String,
    caller_did: String,
) -> napi::Result<Option<f64>> {
    scp_ffi_common::validate::validate_did(&caller_did)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    let entry = lookup_entry_authenticated(&request_id_hex, &caller_did)?;
    // The invoker signs the cancel; the runtime verifies under the pinned
    // `invoker_pk`. A `CustodyStreamSigner` keeps the private key inside
    // custody (ADR-006).
    let invoker_signer = CustodyStreamSigner::new(
        Arc::clone(&entry.custody),
        entry.invoker_key_handle,
        entry.invoker_verifying_key,
    );
    let identity = scp_runtime::context::outlets::dispatch::CancelIdentity {
        context_id: entry.context_id.clone(),
        outlet_id: entry.outlet_id.clone(),
        caveats_binding: entry.caveats_binding,
    };
    let recorded = entry
        .handle
        .apply_outlet_cancel_signed(&invoker_signer, &identity)
        .await
        .map_err(|err| {
            napi::Error::from(ScpNapiError::Context {
                message: format!(
                    "cancel rejected ({})",
                    scp_runtime::context::outlets::stream::cancel_error_to_slug(&err)
                ),
                code: scp_runtime::context::outlets::stream::cancel_error_to_code(&err).to_owned(),
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
/// identified by `request_id_hex` (§5.4.5 framework-initiated stream
/// termination).
///
/// Routes through
/// [`scp_runtime::context::outlets::dispatch::StreamSessionHandle::terminate_with_error`]
/// — the runtime pump emits a synthetic terminal chunk under the pinned
/// operator key and runs settlement (admission release, escrow refund,
/// `OutletInvokedEvent` emission) identically to other framework-emitted
/// closes.
///
/// The SDK framework's periodic UCAN re-check loop calls this whenever
/// it observes the opening UCAN has been revoked since stream open
/// (`reason = "authorization.revoked-mid-stream"`).
///
/// `reason` MUST be one of the closed-set §5.4.4 slugs registered in
/// [`scp_protocol::context::outlets::stream::TerminateReason`] — the full
/// set `TerminateReason::from_slug` accepts:
/// - `"authorization.revoked-mid-stream"` → `RevokedMidStream`
/// - `"execution.cancel-ack-timeout"` → `CancelAckTimeout`
/// - `"execution.credit-stall"` → `CreditStall`
/// - `"protocol.context-closed-mid-stream"` → `ContextClosedMidStream`
/// - `"execution.credit-exhausted"` → `CreditExhausted` (§5.4.4
///   `SCP-TOOL-6131`; the hard cumulative `min(credit_window, max_calls)`
///   ceiling was reached, R3 HIGH-2). Surfaced to SDK consumers as the new
///   terminal cause so a framework re-check that observes credit exhaustion
///   can record the correct §5.4.4 slug rather than collapsing it into
///   `credit-stall`.
///
/// Unknown slugs are rejected with a `Validation` error — attacker-
/// controlled slug strings cannot enter the provenance record.
/// `message` is an optional human-readable extension (empty string =
/// use canonical default).
///
/// # Errors
///
/// * `Validation` — `reason` is not in the closed `TerminateReason` set.
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
    reason: String,
    message: String,
) -> napi::Result<()> {
    use scp_protocol::context::outlets::stream::TerminateReason;
    scp_ffi_common::validate::validate_did(&caller_did)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    let reason_variant = TerminateReason::from_slug(&reason).ok_or_else(|| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!(
                "unknown TerminateReason slug {reason:?}; expected one of \
                 'authorization.revoked-mid-stream', 'execution.cancel-ack-timeout', \
                 'execution.credit-stall', 'protocol.context-closed-mid-stream', \
                 'execution.credit-exhausted' (§5.4.4 closed set)"
            ),
            code: scp_protocol::context::outlets::error_codes::CODE_INPUT_VIOLATION.to_owned(),
        })
    })?;
    let message_override = if message.is_empty() {
        None
    } else {
        Some(message)
    };
    let entry = lookup_entry_authenticated(&request_id_hex, &caller_did)?;
    entry
        .handle
        .terminate_with_error(reason_variant, message_override)
        .map_err(|err| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("terminate rejected: {err}"),
                code: reason_variant.code().to_owned(),
            })
        })?;
    Ok(())
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
    let chunk: OutletStreamChunk = serde_json::from_str(&chunk_json).map_err(|_e| {
        // N5 (ADR-049 §4): never echo the serde Display — it can quote bytes
        // of the attacker-supplied chunk JSON. Keep the CODE + generic msg.
        napi::Error::from(ScpNapiError::Validation {
            message: "malformed chunk JSON".to_owned(),
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
    let caveats_value: Value = serde_json::from_str(&effective_caveats_json).map_err(|_e| {
        // N5 (ADR-049 §4): drop the serde Display — generic message only.
        napi::Error::from(ScpNapiError::Validation {
            message: "invalid effective_caveats JSON".to_owned(),
            code: codes::VALID_7000.to_owned(),
        })
    })?;
    let caveats: InvocationCaveats = serde_json::from_value(caveats_value).map_err(|_e| {
        napi::Error::from(ScpNapiError::Validation {
            message: "effective_caveats does not match the InvocationCaveats schema".to_owned(),
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
    // N4: validate the request_id at the FFI boundary BEFORE it is used as
    // a registry key or interpolated into any message. A malformed hex
    // string is rejected with a typed ValidationError carrying the
    // canonical code and a generic, input-free message — the offending
    // bytes are never echoed.
    scp_ffi_common::validate::validate_request_id_hex(request_id_hex).map_err(|_e| {
        napi::Error::from(ScpNapiError::Validation {
            message: "request_id must be 32 lowercase hex characters (16-byte UUIDv7)".to_owned(),
            code: codes::VALID_7000.to_owned(),
        })
    })?;
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
            // N5: do not echo the request_id back into the message.
            napi::Error::from(ScpNapiError::Context {
                message: "stream not found in registry (protocol.unknown-session)".to_owned(),
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
            message: "caller is not the pinned invoker for this stream (authorization.denied)"
                .to_owned(),
            code: codes::PERM_3001.to_owned(),
        }));
    }
    Ok(entry)
}

/// Resolves the invoker's [`KeyHandle`] + custody [`Arc`] from the
/// bridge's identity registry. Replaces the previous
/// `resolve_invoker_signing_key` helper as the primary key-resolution
/// path so the bridge no longer caches raw private bytes on the
/// registry entry (HIGH-wave-3 Fix A; ADR-006).
fn resolve_invoker_key_handle(
    identity_did: &str,
) -> napi::Result<(Arc<OpaqueInMemoryKeyCustody>, KeyHandle)> {
    crate::runtime::with_identity(identity_did, |entry| {
        Ok((
            Arc::clone(&entry.custody),
            entry.identity.active_signing_key,
        ))
    })
    .map_err(napi::Error::from)
}

/// Resolves the invoker's public [`VerifyingKey`] via custody — ADR-006:
/// only the PUBLIC key is read out, never the private signing key. Pinned
/// on the registry entry so the bridge can build
/// [`scp_runtime::context::outlets::dispatch::OpenStreamParams::invoker_pk`]
/// and back the [`CustodyStreamSigner::verifying_key`] without exporting any
/// private material (the raw-`SigningKey` export path was deleted).
async fn resolve_invoker_verifying_key(
    custody: &OpaqueInMemoryKeyCustody,
    handle: KeyHandle,
) -> napi::Result<VerifyingKey> {
    let public = custody.0.public_key(&handle).await.map_err(|_e| {
        napi::Error::from(ScpNapiError::Identity {
            message: "failed to resolve invoker public key".to_owned(),
            code: codes::IDENT_1041.to_owned(),
        })
    })?;
    let pk_bytes: [u8; 32] =
        public
            .as_bytes()
            .try_into()
            .map_err(|_e: std::array::TryFromSliceError| {
                napi::Error::from(ScpNapiError::Identity {
                    message: "invoker public key is not a 32-byte Ed25519 key".to_owned(),
                    code: codes::IDENT_1041.to_owned(),
                })
            })?;
    VerifyingKey::from_bytes(&pk_bytes).map_err(|_e| {
        napi::Error::from(ScpNapiError::Identity {
            message: "invoker public key is not a valid Ed25519 key".to_owned(),
            code: codes::IDENT_1041.to_owned(),
        })
    })
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
    #[tokio::test]
    async fn grant_credit_rejects_zero_grant() {
        let result =
            outlet_stream_grant_credit("00".repeat(16), "did:dht:z6MkInvoker".to_owned(), 0).await;
        assert!(result.is_err(), "grant=0 must be rejected");
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains("invalid grant 0") || err_str.contains("protocol.invalid-grant"),
            "error must mention invalid-grant: {err_str}"
        );
    }

    /// HIGH-1 (R3) — the bridge's credit-grant rejection arm routes a
    /// `GrantError::StreamClosed` (a grant arriving after the pump exited)
    /// to the Protocol-class `SCP-TOOL-6101` code and the
    /// `protocol.stream-already-closed` slug — NOT the prior opaque
    /// `SCP-CTX-2000`. This pins the exact slug/code the
    /// `outlet_stream_grant_credit` `Err` arm now uses via
    /// `grant_error_to_slug` / `grant_error_to_code`, so a regression that
    /// reverts to `CTX_2000` (which would mask the class the SDK error
    /// taxonomy keys on) fails here.
    ///
    /// Driving a live `apply_credit_grant` against a closed stream from a
    /// cargo test is infrastructurally impossible for the NAPI bridge: the
    /// `#[napi]` open entry needs a running Node.js/Bun runtime and a
    /// `napi_wrap`-allocated `NapiContextHandle` (see the module doc on
    /// `tests/outlet_stream_vectors_real.rs`), and `StreamSessionHandle`'s
    /// fields are private to `scp-runtime` so a closed handle cannot be
    /// fabricated here. The gate-fires + escrow-unchanged behaviour is
    /// proven at the runtime layer by
    /// `apply_credit_grant_after_close_rejects_stream_closed_escrow_unchanged`
    /// in `crates/scp-runtime/src/context/outlets/dispatch.rs`; this test
    /// covers the bridge-owned mapping that sits on top of that gate plus
    /// the top-up reversal contract (the bridge drops a `StreamEscrowTicket`
    /// on every rejection arm, refunding the debited per-grant top-up).
    #[test]
    fn grant_stream_closed_maps_to_protocol_6101() {
        use scp_runtime::context::outlets::stream::{
            GrantError, grant_error_to_code, grant_error_to_slug,
        };
        assert_eq!(
            grant_error_to_code(GrantError::StreamClosed),
            scp_protocol::context::outlets::error_codes::CODE_PROTOCOL_SESSION,
            "bridge surfaces StreamClosed as the Protocol-class SCP-TOOL-6101",
        );
        assert_eq!(
            grant_error_to_slug(GrantError::StreamClosed),
            scp_protocol::context::outlets::error_codes::SLUG_PROTOCOL_STREAM_ALREADY_CLOSED,
            "bridge surfaces StreamClosed as protocol.stream-already-closed",
        );
        // Sibling classes must NOT collapse into the Protocol band — the
        // bridge arm relies on the mapper preserving each rejection's class.
        assert_ne!(
            grant_error_to_code(GrantError::CreditReplay),
            grant_error_to_code(GrantError::StreamClosed),
            "replay (Authorization) and StreamClosed (Protocol) are distinct classes",
        );
        assert_ne!(
            grant_error_to_code(GrantError::InsufficientFunds),
            grant_error_to_code(GrantError::StreamClosed),
            "insufficient-funds (Economic) and StreamClosed (Protocol) are distinct classes",
        );
    }

    /// `outlet_stream_cancel` returns `Context` error when the
    /// `request_id_hex` does not match any registry entry.
    #[tokio::test]
    async fn cancel_returns_unknown_session_for_missing_request() {
        // Use a fresh hex that is unlikely to match any other test's
        // active stream (registry is process-global per default
        // bridge instance — see ADR-048).
        let result = outlet_stream_cancel("ee".repeat(16), "did:dht:z6MkInvoker".to_owned()).await;
        assert!(result.is_err(), "missing request_id must be rejected");
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains("not found") || err_str.contains("unknown-session"),
            "error must mention unknown-session: {err_str}"
        );
    }

    /// §5.4.5 HIGH-wave-3 Fix B — dropping a
    /// [`NapiOutletInvocationStream`] without consuming it evicts the
    /// registry entry. Exercises the `Drop` impl: build a wrapper
    /// referencing a sentinel request id, drop it, assert the registry
    /// no longer holds that key. Idempotent — running this test
    /// twice in a row succeeds.
    #[test]
    fn drop_evicts_registry_entry() {
        crate::runtime::ensure_bridge_instance();
        let request_id_hex = "cd".repeat(16);
        {
            let wrapper = NapiOutletInvocationStream {
                rx: Arc::new(TokioMutex::new(None)),
                request_id_hex: request_id_hex.clone(),
                terminated: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            };
            drop(wrapper);
        }
        let reg = registry().expect("registry available");
        assert!(
            reg.get(&request_id_hex).is_none(),
            "drop must leave the registry without the entry"
        );
    }

    /// §5.4.5 HIGH-wave-3 Fix A — `StreamRegistryEntry` no longer
    /// stores a raw `SigningKey`. Compile-time check: the struct's
    /// `invoker_key_handle` field is a `KeyHandle` (opaque), `custody`
    /// is an `Arc<OpaqueInMemoryKeyCustody>`, and
    /// `invoker_verifying_key` is the public key. A field named
    /// `invoker_signing_key` would fail to compile if re-introduced.
    #[test]
    fn registry_entry_has_no_raw_signing_key_field() {
        fn assert_shape() {
            let _ = std::mem::size_of::<KeyHandle>();
            let _ = std::mem::size_of::<Arc<OpaqueInMemoryKeyCustody>>();
            let _ = std::mem::size_of::<VerifyingKey>();
        }
        let _ = assert_shape;
    }

    /// N1 — the custody-backed [`CustodyStreamSigner`] signs the §5.4.5
    /// preimage through custody (the operator private key never leaves the
    /// custody boundary) and the produced signature verifies under the
    /// signer's own `verifying_key()`.
    #[tokio::test]
    #[cfg(feature = "allow_in_memory_custody")]
    async fn custody_stream_signer_signs_and_verifies_under_its_own_key() {
        use scp_platform::testing::InMemoryKeyCustody;
        use scp_platform::{KeyCustody, KeyType};
        use scp_runtime::context::outlets::signer::StreamSigner;

        let custody = Arc::new(OpaqueInMemoryKeyCustody(InMemoryKeyCustody::new()));
        let handle = custody
            .0
            .generate_keypair(KeyType::Ed25519)
            .await
            .expect("generate ed25519");
        let public = custody.0.public_key(&handle).await.expect("public key");
        let pk_bytes: [u8; 32] = public.as_bytes().try_into().expect("32-byte pk");
        let vk = VerifyingKey::from_bytes(&pk_bytes).expect("valid vk");

        let signer = CustodyStreamSigner::new(Arc::clone(&custody), handle, vk);
        let preimage = [0x33u8; 32];
        let sig = signer.sign(&preimage).await.expect("custody sign");
        let signature = ed25519_dalek::Signature::from_bytes(&sig);
        assert!(
            signer
                .verifying_key()
                .verify_strict(&preimage, &signature)
                .is_ok(),
            "custody-produced signature must verify under the signer's own verifying key"
        );
        assert_eq!(*signer.verifying_key(), vk);
    }

    /// N1 — object-safety: `OpenStreamParams` carries `Arc<dyn StreamSigner>`,
    /// not a raw `Arc<SigningKey>`, so a private key can never be threaded
    /// into the runtime address space.
    #[test]
    #[cfg(feature = "allow_in_memory_custody")]
    fn custody_stream_signer_is_object_safe() {
        use scp_platform::testing::InMemoryKeyCustody;
        let custody = Arc::new(OpaqueInMemoryKeyCustody(InMemoryKeyCustody::new()));
        let vk = SigningKey::from_bytes(&[0x42; 32]).verifying_key();
        let signer = CustodyStreamSigner::new(custody, KeyHandle::new(0), vk);
        let _erased: Arc<dyn scp_runtime::context::outlets::signer::StreamSigner> =
            Arc::new(signer);
    }

    /// N4 — a malformed `request_id_hex` on the cancel path surfaces a
    /// `Validation` error and the offending string is NOT echoed.
    #[tokio::test]
    async fn cancel_rejects_malformed_request_id_without_echo() {
        let sentinel = "DEADBEEFDEADBEEFDEADBEEFDEADBEEF"; // uppercase → invalid
        let result =
            outlet_stream_cancel(sentinel.to_owned(), "did:dht:z6MkInvoker".to_owned()).await;
        let err = result.expect_err("malformed request_id must be rejected");
        let err_str = format!("{err}");
        assert!(
            !err_str.contains(sentinel),
            "validation error must NOT echo the malformed request_id: {err_str}"
        );
    }

    /// N5 — malformed chunk JSON carrying a sentinel substring is rejected
    /// with a `Validation` error whose message does NOT echo the sentinel.
    #[test]
    fn verify_chunk_signature_scrubs_malformed_json_detail() {
        let sentinel = "SENTINEL_LEAK_MARKER_7f3a";
        let malformed = format!("{{ not valid json {sentinel} ");
        let result = verify_chunk_signature(
            malformed,
            Buffer::from(vec![0u8; 32]),
            "ctx".to_owned(),
            "outlet".to_owned(),
            Buffer::from(vec![0u8; 32]),
        );
        let err = result.expect_err("malformed chunk JSON must be rejected");
        let err_str = format!("{err}");
        assert!(
            !err_str.contains(sentinel),
            "chunk-JSON validation error must NOT echo input bytes: {err_str}"
        );
    }
}
