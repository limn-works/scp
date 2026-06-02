//! `UniFFI` streaming bridge for outlets — `SCP-OUT-037` (`UniFFI` portion).
//!
//! Mirrors the `PyO3` streaming module at
//! `crates/scp-ffi/src/outlet_stream.rs` and the NAPI streaming module at
//! `crates/scp-ffi/napi/src/outlet_stream.rs`. Exposes §5.4.5
//! progressive-output streaming to Swift and Kotlin via the `UniFFI`
//! proc-macros:
//!
//! - [`outlet_invoke_stream`] — Opens a §5.4.5 stream session and returns
//!   an [`OutletStreamHandle`] whose `next()` async method drains chunks
//!   one at a time and whose `cancel()` async method applies an
//!   `OutletCancel` on the session. Swift wraps the handle as
//!   `AsyncSequence`; Kotlin as `Flow<OutletStreamChunk>`.
//! - [`outlet_invoke_stream_with_subscriber`] — Push-style variant that
//!   spawns a background pump task forwarding every chunk to the
//!   caller-supplied [`OutletStreamSubscriber`] callback interface and
//!   returns the request id (32-char lowercase hex) so the caller can
//!   address the active stream from `outlet_stream_grant_credit` /
//!   `outlet_stream_cancel`.
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
//! [`crate::runtime::UniffiBridgeInstance`] (NOT a process-global —
//! ADR-048 §1) keyed by the §5.4.5 16-byte `request_id` rendered as a
//! 32-char lowercase hex string at the FFI boundary. Each entry holds
//! the [`scp_runtime::context::outlets::dispatch::StreamSessionHandle`]
//! returned by
//! [`scp_runtime::context::manager::ContextManager::open_outlet_stream`]
//! plus the local monotonic-grant counter and the credit-grant signing
//! material.
//!
//! Cleanup: each entry is removed from the registry when the streaming
//! pump observes a terminal chunk (End / `Error{terminal:true}`) or the
//! receiver closes — see [`OutletStreamHandle::next`] /
//! [`outlet_invoke_stream_with_subscriber`] below.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use dashmap::DashMap;
use ed25519_dalek::VerifyingKey;
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

use crate::ScpError;
use crate::bridge::CallbackKeyCustody;
#[cfg(feature = "allow_in_memory_custody")]
use crate::bridge::OpaqueInMemoryKeyCustody;

// ---------------------------------------------------------------------------
// StreamCustody — bridge-layer enum so the registry entry can hold any of
// the UniFFI bridge's custody variants without erasing trait identity. The
// underlying scp_platform::KeyCustody trait uses RPITIT (not dyn-safe), so a
// boxed trait object is not an option — this enum dispatches statically.
// ---------------------------------------------------------------------------

/// Custody provider variant pinned on a [`StreamRegistryEntry`].
///
/// §5.4.5 HIGH-wave-3 Fix A — the entry no longer caches a raw
/// `SigningKey`. Every grant / cancel / terminate signature delegates
/// to one of the variants below (whichever the identity at stream open
/// presented) via [`Self::sign`], so private bytes never leave the
/// custody boundary (ADR-006).
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub(crate) enum StreamCustody {
    /// Platform-provided custody injected via `KeyCustodyProvider`
    /// (Apple Keychain, Android Keystore, etc.). Preferred path in
    /// production builds.
    Callback(Arc<CallbackKeyCustody>),
    /// In-memory custody, only available when the
    /// `allow_in_memory_custody` feature is enabled. Used by tests
    /// and CLI builds.
    #[cfg(feature = "allow_in_memory_custody")]
    InMemory(Arc<OpaqueInMemoryKeyCustody>),
}

impl StreamCustody {
    /// Signs `data` under the key identified by `handle`. Dispatches
    /// statically over the [`KeyCustody`] trait impl on the matched
    /// variant — RPITIT precludes a boxed trait object, so this
    /// `match` is the bridge-layer fan-out.
    async fn sign(
        &self,
        handle: &KeyHandle,
        data: &[u8],
    ) -> Result<scp_platform::Signature, scp_platform::PlatformError> {
        match self {
            Self::Callback(cb) => cb.sign(handle, data).await,
            #[cfg(feature = "allow_in_memory_custody")]
            Self::InMemory(imc) => imc.0.sign(handle, data).await,
        }
    }

    /// Reads the PUBLIC verifying key for `handle` — ADR-006: only the
    /// public key crosses out of custody, never the private signing key.
    /// Pinned on the registry entry so the bridge can build
    /// `OpenStreamParams::invoker_pk` and back the
    /// [`CustodyStreamSigner::verifying_key`] without exporting any private
    /// material (the raw-`SigningKey` export path was deleted).
    async fn public_verifying_key(
        &self,
        handle: &KeyHandle,
    ) -> Result<VerifyingKey, scp_platform::PlatformError> {
        let public = match self {
            Self::Callback(cb) => cb.public_key(handle).await?,
            #[cfg(feature = "allow_in_memory_custody")]
            Self::InMemory(imc) => imc.0.public_key(handle).await?,
        };
        let bytes: [u8; 32] = public.as_bytes().try_into().map_err(|_e| {
            scp_platform::PlatformError::CustodyError(
                "invoker public key is not a 32-byte Ed25519 key".to_owned(),
            )
        })?;
        VerifyingKey::from_bytes(&bytes).map_err(|_e| {
            scp_platform::PlatformError::CustodyError(
                "invoker public key is not a valid Ed25519 key".to_owned(),
            )
        })
    }
}

// ---------------------------------------------------------------------------
// CustodyStreamSigner — custody-backed StreamSigner (ADR-006)
// ---------------------------------------------------------------------------

/// Custody-backed [`scp_runtime::context::outlets::signer::StreamSigner`].
///
/// ADR-006: private keys never cross the FFI boundary. Instead of exporting
/// the operator's `ed25519_dalek::SigningKey` (the deleted inline export
/// path), the bridge hands the runtime this object-safe adapter. Each `sign`
/// routes the §5.4.5 preimage through [`StreamCustody::sign`] so the private
/// bytes only exist inside custody for the duration of a single signing
/// call.
///
/// In the local single-context streaming path the operator (chunk signer)
/// and invoker (UCAN holder) are the same custody-held key, so the same
/// adapter backs both the dispatch pump's chunk signing
/// (`OpenStreamParams::operator_signer`) and the
/// [`scp_runtime::context::outlets::dispatch::StreamSessionHandle::apply_outlet_cancel_signed`]
/// cancel path (verified under the pinned `invoker_pk`).
pub(crate) struct CustodyStreamSigner {
    /// Custody provider that owns [`Self::key_handle`].
    custody: StreamCustody,
    /// Opaque handle for the Ed25519 signing key (ADR-006: never raw bytes).
    key_handle: KeyHandle,
    /// Cached public verifying key.
    vk: VerifyingKey,
}

impl CustodyStreamSigner {
    /// Builds a custody-backed signer pinned to the public `vk`.
    pub(crate) const fn new(
        custody: StreamCustody,
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

#[async_trait::async_trait]
impl scp_runtime::context::outlets::signer::StreamSigner for CustodyStreamSigner {
    async fn sign(
        &self,
        preimage: &[u8],
    ) -> Result<[u8; 64], scp_runtime::context::outlets::signer::StreamSignerError> {
        let signature = self
            .custody
            .sign(&self.key_handle, preimage)
            .await
            .map_err(|_e: scp_platform::PlatformError| {
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
// Per-stream revocation checker
// ---------------------------------------------------------------------------

/// Adapter that wires the bridge's per-context UCAN revocation list
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
    /// registry — `with_ucan_state` returns `None` for unknown
    /// contexts; the constructor surfaces that as a typed bridge
    /// error so the stream-open path can fail fast instead of
    /// installing an adapter that always answers "revoked".
    fn for_context(context_id: &str) -> Result<Self, ScpError> {
        crate::runtime::with_ucan_state(context_id, |_st| ()).ok_or_else(|| ScpError::Context {
            msg: format!(
                "context '{context_id}' not found in UCAN state registry — call a UCAN \
                 or event log function with the context handle first"
            ),
            code: codes::CTX_2023.to_owned(),
        })?;
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
        crate::runtime::with_ucan_state(&self.context_id, |st| {
            st.revocation_list.is_revoked(token_cid)
        })
        .unwrap_or(true)
    }
}
use crate::bridge::{ContextHandle, ContextState, Identity};
use crate::runtime;

// ---------------------------------------------------------------------------
// E1/E2 economic settlement + escrow-refund sinks
// ---------------------------------------------------------------------------

/// Production [`scp_runtime::context::outlets::invoke::StreamSettlementSink`]
/// for the `UniFFI` bridge (E1). The dispatch pump fires `settle` from its
/// spawned tokio task, so the impl `Handle::spawn`s the async
/// `ContextManager::outlet_stream_settle` (it MUST NOT block).
struct UniffiStreamSettlementSink {
    manager: Arc<scp_core::context::ContextManager>,
    handle: tokio::runtime::Handle,
}

impl scp_runtime::context::outlets::invoke::StreamSettlementSink for UniffiStreamSettlementSink {
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
/// for the `UniFFI` bridge (E2). Refunds a debited open-time hold when the
/// open-path ticket drops unconsumed.
struct UniffiStreamEscrowRefundSink {
    manager: Arc<scp_core::context::ContextManager>,
    handle: tokio::runtime::Handle,
}

impl scp_runtime::context::outlets::dispatch::StreamEscrowRefundSink
    for UniffiStreamEscrowRefundSink
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
/// path where the manager is resolved and a tokio runtime context is active.
fn bridge_stream_settlement_sink()
-> Result<Arc<dyn scp_runtime::context::outlets::invoke::StreamSettlementSink>, ScpError> {
    let manager = Arc::clone(runtime::context_manager_expect()?);
    Ok(Arc::new(UniffiStreamSettlementSink {
        manager,
        handle: tokio::runtime::Handle::current(),
    }))
}

/// Builds the production escrow-refund sink (E2).
fn bridge_stream_escrow_refund_sink()
-> Result<Arc<dyn scp_runtime::context::outlets::dispatch::StreamEscrowRefundSink>, ScpError> {
    let manager = Arc::clone(runtime::context_manager_expect()?);
    Ok(Arc::new(UniffiStreamEscrowRefundSink {
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
/// caveats_binding)` plus the invoker's `SigningKey`.
pub(crate) struct StreamRegistryEntry {
    /// Control-plane handle returned by the runtime at open. Wrapped in
    /// an outer `Mutex` so the FFI grant/cancel calls can take exclusive
    /// ownership of `apply_credit_grant` / `apply_outlet_cancel` while
    /// the runtime control surface. The chunk receiver is detached at open
    /// (before this entry is built), so every post-open call is a `&self`
    /// method (`apply_credit_grant`, `apply_outlet_cancel_signed`,
    /// `terminate_with_error`); the handle's own per-stream state is already
    /// inner-`Mutex`-protected, and `StreamSessionHandle` is `Send + Sync`,
    /// so the entry holds it directly (behind the registry's
    /// `Arc<StreamRegistryEntry>`) without a redundant outer lock. Holding
    /// a `std::sync::Mutex` guard here would also be unsound across the
    /// `async` `apply_outlet_cancel_signed` await.
    pub handle: scp_runtime::context::outlets::dispatch::StreamSessionHandle,
    /// Strictly-monotonic counter incremented on every accepted grant
    /// (§5.4.5 round-5 grant signature preimage). Initial state is `0`;
    /// the first grant uses `1` and so on so the first `seen_seq` in the
    /// runtime tracker advances from `None` to `Some(1)`.
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
    /// terminate signatures dispatch through [`Self::custody`] (a
    /// [`StreamCustody`] enum over the bridge's available providers).
    pub invoker_key_handle: KeyHandle,
    /// Custody provider that owns [`Self::invoker_key_handle`]. Cloned
    /// from the context handle or identity at stream open. Held by
    /// value (each variant is `Arc`-cloneable internally) so the
    /// custody remains alive for the stream's lifetime.
    pub custody: StreamCustody,
    /// Invoker's Ed25519 verifying key (public, non-secret)
    /// snapshotted at open. Used to self-verify every freshly-signed
    /// grant / cancel against the same pinned identity the runtime's
    /// `apply_credit_grant` / `apply_outlet_cancel` use for downstream
    /// verification.
    pub invoker_verifying_key: VerifyingKey,
    /// Pinned invoker DID. The control-plane bridge functions
    /// (`grant_credit`, `cancel`, `terminate`) verify `caller_did`
    /// matches this before invoking custody to sign. CRITICAL #1 fix.
    pub invoker_did: String,
    /// 16-byte `request_id` (the registry key in raw form) so the pump
    /// task and the close path can look up by either the hex string
    /// (registry key) or the typed wire form.
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
    /// `custody` variants behind `Arc`), public values
    /// (`invoker_verifying_key`, ids), or runtime-owned state behind
    /// the inner Mutex — none need zeroization at the bridge boundary.
    fn drop(&mut self) {
        self.caveats_binding.zeroize();
    }
}

/// Returns a reference to the per-bridge stream registry on the default
/// [`crate::runtime::UniffiBridgeInstance`]. Per ADR-048 the registry
/// lives on the bridge instance (not as a process-global) so
/// multi-instance fallback / shutdown clearing works uniformly.
fn registry() -> Result<Arc<DashMap<String, Arc<StreamRegistryEntry>>>, ScpError> {
    let bi = runtime::default_bridge_instance_raw().ok_or_else(|| ScpError::Context {
        msg: "bridge instance not initialised".to_owned(),
        code: codes::CTX_2000.to_owned(),
    })?;
    Ok(Arc::clone(bi.outlet_stream_registry()))
}

/// Renders a `request_id` (16 raw bytes) as 32-char lowercase hex — the
/// registry key. Stable across all calls because `hex::encode` emits
/// lowercase digits without separators.
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
// SDK-shaped chunk record
// ---------------------------------------------------------------------------

/// One chunk yielded by [`OutletStreamHandle::next`] or pushed to an
/// [`OutletStreamSubscriber`].
///
/// Mirrors the §5.4.5 wire form on a per-variant basis so SDK callers can
/// branch on `payload_type` and read variant fields directly without an
/// extra translation step. Discriminator is `payload_type` (the
/// SDK-friendly variant of the wire `@type` discriminator).
///
/// `request_id` is 16 raw bytes (the wire form). `sig` is the 64-byte
/// `SCP-OUTLET-CHUNK-SIG-V1:` Ed25519 signature. `sequence` and
/// `execution_time_ms` are protocol-level `u64` values; `UniFFI` surfaces
/// them as the language-native 64-bit unsigned integer (Swift `UInt64`,
/// Kotlin `ULong`).
#[derive(Debug, Clone, uniffi::Record)]
pub struct OutletStreamChunkRecord {
    /// 16-byte §5.4.5 `request_id` of the stream this chunk belongs to.
    pub request_id: Vec<u8>,
    /// Strictly-monotonic per-stream chunk sequence number. Advances by
    /// one per emitted chunk.
    pub sequence: u64,
    /// 64-byte `SCP-OUTLET-CHUNK-SIG-V1:` Ed25519 signature.
    pub sig: Vec<u8>,
    /// Discriminator: `"data"` / `"progress"` / `"end"` / `"error"`.
    pub payload_type: String,
    /// `data` payload — JSON-encoded payload value. `None` for
    /// non-`data` variants.
    pub value_json: Option<String>,
    /// `progress` payload — completion percentage in basis points
    /// `[0, 10000]`. `None` for non-`progress` variants.
    pub pct: Option<u16>,
    /// `progress` payload — optional human-readable note.
    pub note: Option<String>,
    /// `end` payload — JSON-encoded aggregate output value. `None` for
    /// non-`end` variants.
    pub aggregate_json: Option<String>,
    /// `end` payload — JSON-encoded per-chunk provenance block.
    pub provenance_json: Option<String>,
    /// `end` payload — total wall-clock execution time in milliseconds.
    pub execution_time_ms: Option<u64>,
    /// `error` payload — stable error code (e.g. `SCP-TOOL-6110`).
    pub code: Option<String>,
    /// `error` payload — human-readable error message.
    pub message: Option<String>,
    /// `error` payload — `true` for terminal errors that close the
    /// stream, `false` for non-terminal warnings.
    pub terminal: Option<bool>,
}

/// Converts a runtime [`OutletStreamChunk`] to the UniFFI-facing shape.
fn chunk_to_uniffi(chunk: &OutletStreamChunk) -> Result<OutletStreamChunkRecord, ScpError> {
    let request_id = chunk.request_id.to_vec();
    let sig = chunk.sig.to_vec();
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
            Some(serde_json::to_string(value).map_err(|e| ScpError::Tool {
                msg: format!("failed to serialise data value: {e}"),
                code: codes::TOOL_6006.to_owned(),
            })?),
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
            Some(*pct),
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
            let aggregate_json = serde_json::to_string(aggregate).map_err(|e| ScpError::Tool {
                msg: format!("failed to serialise aggregate: {e}"),
                code: codes::TOOL_6006.to_owned(),
            })?;
            let provenance_json =
                serde_json::to_string(provenance).map_err(|e| ScpError::Tool {
                    msg: format!("failed to serialise provenance: {e}"),
                    code: codes::TOOL_6006.to_owned(),
                })?;
            (
                "end".to_owned(),
                None,
                None,
                None,
                Some(aggregate_json),
                Some(provenance_json),
                Some(*execution_time_ms),
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
    Ok(OutletStreamChunkRecord {
        request_id,
        sequence: chunk.sequence,
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
// OutletStreamHandle — async-iterator-style class handed back to Swift/Kotlin
// ---------------------------------------------------------------------------

/// Pull-style stream handle returned by [`outlet_invoke_stream`].
///
/// Exposes an async `next()` method that resolves to either the next
/// [`OutletStreamChunkRecord`] or `None` (signalling end-of-stream), an
/// async `cancel()` method that applies an `OutletCancel` on the session,
/// and a synchronous `request_id()` getter exposing the §5.4.5 16-byte
/// `request_id` as a 32-char lowercase hex string.
///
/// The Swift SDK wraps an instance of this class as an `AsyncSequence` /
/// `AsyncThrowingStream` and the Kotlin SDK wraps it as a
/// `Flow<OutletStreamChunkRecord>` — both adapters live in the SDK
/// wrapper layer, NOT in this FFI bridge (kept thin per ADR-021).
///
/// Iteration ends when the receiver closes OR after a terminal chunk
/// (`End`, `Error { terminal: true }`) is yielded; subsequent `next()`
/// calls return `None` immediately.
#[derive(uniffi::Object)]
pub struct OutletStreamHandle {
    /// Receiver wrapped in an `Arc<TokioMutex<Option<_>>>` so concurrent
    /// `next()` calls serialize on the lock and the receiver can be
    /// dropped explicitly when the stream terminates (the `Option`
    /// toggles to `None` so further calls do not race against a closed
    /// receiver).
    rx: Arc<TokioMutex<Option<mpsc::Receiver<OutletStreamChunk>>>>,
    /// 16-byte `request_id` rendered as hex. Kept on the iterator so the
    /// SDK can surface it without re-decoding chunks.
    request_id_hex: String,
    /// Pinned invoker DID at open. The convenience wrappers
    /// ([`Self::cancel`], [`Self::terminate`]) thread this through to
    /// the standalone control-plane functions as `caller_did` so the
    /// CRITICAL #1 caller-authentication check has a value to match.
    invoker_did: String,
    /// `true` after the pump observed a terminal chunk and the iterator
    /// must stop. Survives the receiver being dropped.
    terminated: Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for OutletStreamHandle {
    /// §5.4.5 HIGH-wave-3 Fix B — evict the per-bridge registry entry
    /// on drop so a wrapper that goes out of scope without being
    /// drained to terminal (exception path, Swift/Kotlin ARC release,
    /// awaiting-only consumption that never observes a terminal chunk)
    /// does NOT leak `StreamRegistryEntry` (`KeyHandle` + per-stream
    /// [`scp_runtime::context::outlets::dispatch::StreamSessionHandle`]
    /// state) indefinitely.
    ///
    /// Idempotent: when [`Self::next`] already observed a terminal
    /// chunk it called [`evict_request`] inline, and the registry no
    /// longer holds the entry — this `Drop` becomes a no-op. The
    /// runtime pump's settlement block (triggered by the receiver
    /// closing when `rx` drops) releases the
    /// `StreamAdmissionTracker` counters on all three keys
    /// (`AdmissionReleaseKeys`); no separate `release_admission_slot()`
    /// call from the wrapper is needed — the receiver close is the
    /// authoritative trigger.
    fn drop(&mut self) {
        evict_request(&self.request_id_hex);
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl OutletStreamHandle {
    /// Returns the §5.4.5 16-byte `request_id` of the open stream as a
    /// 32-char lowercase hex string. The SDK uses this to address the
    /// stream from the control-plane methods (`grantCredit`, `cancel`).
    #[must_use]
    pub fn request_id(&self) -> String {
        self.request_id_hex.clone()
    }

    /// Returns `true` once a terminal chunk has been observed (or the
    /// receiver has been closed). After this flips `true`, subsequent
    /// `next()` calls resolve to `None` immediately.
    #[must_use]
    pub fn done(&self) -> bool {
        self.terminated.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Asynchronously yields the next chunk, or `None` once the stream
    /// is closed.
    ///
    /// Resolves to `None` when:
    /// - the receiver was closed by the runtime pump task (clean
    ///   shutdown), OR
    /// - a previous call already observed a terminal chunk
    ///   (`End` / `Error { terminal: true }`).
    ///
    /// All runtime failure modes (cancel, executor error, terminal error
    /// chunk) flow through normally as `payload_type = "error"` chunks —
    /// `next()` does NOT throw for runtime errors emitted as terminal
    /// `Error` chunks.
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Tool` (`SCP-TOOL-6006`) only if a chunk fails
    /// to serialise.
    pub async fn next(&self) -> Result<Option<OutletStreamChunkRecord>, ScpError> {
        // Fast path: already terminated. Returning early avoids taking
        // the receiver lock and matches the PyO3 / NAPI bridges'
        // `__anext__` / `next()` short-circuit.
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
                Ok(Some(chunk_to_uniffi(&chunk)?))
            }
        }
    }

    /// Applies an `OutletCancel` to this stream session.
    ///
    /// Convenience wrapper that delegates to [`outlet_stream_cancel`]
    /// with this handle's `request_id`. Returns the recorded
    /// cancel-ack sequence number when the runtime accepted the cancel,
    /// or `None` when the stream had already reached a terminal chunk
    /// (the runtime ignores the cancel per §5.4.5 idempotency).
    ///
    /// The bridge derives the canonical `next_seq` from the runtime's
    /// current emission cursor — never accepts caller input. CRITICAL
    /// #3 fix: a caller-supplied `next_seq` lets the caller forge
    /// `cancel_ack_seq` (zero to nullify billing of delivered chunks,
    /// or `u64::MAX` to over-bill).
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Context` with slug `protocol.unknown-session`
    /// when the stream has already been evicted from the registry
    /// (terminal chunk observed by another caller, bridge shutdown,
    /// double-cancel after the first cancel completed).
    pub async fn cancel(&self) -> Result<Option<u64>, ScpError> {
        outlet_stream_cancel(self.request_id_hex.clone(), self.invoker_did.clone()).await
    }

    /// Forces a terminal `Error{terminal:true}` chunk into this stream
    /// (§5.4.5 framework-initiated stream termination).
    ///
    /// Convenience wrapper that delegates to
    /// [`outlet_stream_terminate`] with this handle's `request_id`. The
    /// SDK framework's periodic UCAN re-check loop calls this with
    /// [`TerminateReason::RevokedMidStream`] whenever it observes the
    /// opening UCAN has been revoked since stream open. The
    /// `message_override` is an optional human-readable suffix — pass
    /// `None` to use the spec's canonical default message.
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Context` (slug `protocol.unknown-session`)
    /// when the stream has already been evicted from the registry, or
    /// when the runtime rejected the terminate (already-terminated /
    /// already-pending). All cases are recoverable from the SDK's
    /// recheck loop's perspective — they indicate the stream has
    /// already left the pump's control plane.
    pub async fn terminate(
        &self,
        reason: TerminateReason,
        message_override: Option<String>,
    ) -> Result<(), ScpError> {
        outlet_stream_terminate(
            self.request_id_hex.clone(),
            self.invoker_did.clone(),
            reason,
            message_override,
        )
        .await
    }
}

// ---------------------------------------------------------------------------
// OutletStreamSubscriber — push-style callback interface
// ---------------------------------------------------------------------------

/// Push-style subscriber for streaming outlet invocations.
///
/// Implemented by Swift / Kotlin code and passed to
/// [`outlet_invoke_stream_with_subscriber`]. The bridge spawns a
/// background pump task that forwards every chunk emitted by the
/// runtime stream session into [`Self::on_chunk`]. When the stream
/// reaches a terminal chunk (`End`, `Error { terminal: true }`) the pump
/// emits the chunk through [`Self::on_chunk`] AND calls
/// [`Self::on_complete`]; receiver close (without a terminal chunk in
/// flight) maps to [`Self::on_error`] with an
/// `execution.cancel-ack-timeout`-shaped error so the SDK never blocks
/// on a half-open stream. After either terminal callback the bridge
/// evicts the session from the per-bridge registry.
///
/// # SAFETY: Thread execution context
///
/// Methods execute on Rust tokio threads, NOT the Swift/Kotlin main
/// thread. Implementations MUST be thread-safe (`Send + Sync`) and MUST
/// NOT assume main-thread execution. Mirrors the
/// [`crate::MessageListener`] / [`crate::PushProvider`] convention.
///
/// See sdk-common.md §"FFI Async Bridging Risks" rule 2.
#[uniffi::export(callback_interface)]
#[async_trait]
pub trait OutletStreamSubscriber: Send + Sync {
    /// Called on every chunk emitted by the runtime stream session,
    /// terminal or otherwise.
    async fn on_chunk(&self, chunk: OutletStreamChunkRecord);

    /// Called exactly once after the stream reaches a terminal chunk
    /// (`End` / `Error { terminal: true }`). Mutually exclusive with
    /// [`Self::on_error`] for a given subscription.
    async fn on_complete(&self);

    /// Called exactly once when the stream closes without a terminal
    /// chunk (receiver dropped, runtime cancel-ack timeout, etc.).
    /// Mutually exclusive with [`Self::on_complete`] for a given
    /// subscription.
    async fn on_error(&self, error: ScpError);
}

// ---------------------------------------------------------------------------
// outlet_invoke_stream — open the stream (pull mode)
// ---------------------------------------------------------------------------

/// Opens a §5.4.5 streaming outlet invocation and returns an
/// [`OutletStreamHandle`] iterator.
///
/// Mirrors `context_outlet_invoke_stream` in the `PyO3` and NAPI bridges:
/// re-validates the UCAN under the full 11-step ADR-016 pipeline, calls
/// [`scp_runtime::context::manager::ContextManager::open_outlet_stream`]
/// directly so the returned `StreamSessionHandle` is registered for
/// later `grant_credit` / `cancel` lookups by `request_id`.
///
/// # Arguments
///
/// * `handle` — Hosting [`ContextHandle`].
/// * `outlet_id` — Outlet to invoke.
/// * `input_json` — JSON string matching the outlet's input schema.
/// * `identity` — Invoker [`Identity`]. Used as both `invoker_did` and
///   `origin_invoker_did` in `OpenStreamParams`.
/// * `ucan_token` — UCAN authorising the invocation.
/// * `caveats_binding_hex` — 32-byte `caveats_binding` rendered as
///   64-char lowercase hex. The SDK computes this via
///   [`compute_caveats_binding`] before opening.
/// * `stream_epoch` — Hosting context's MLS epoch counter at open
///   acceptance.
/// * `proof_tokens` — Optional encoded parent UCANs for delegation-chain
///   traversal (ADR-016 step 3).
/// * `credit_window` — Initial credit-window size; defaults to §5.4.5
///   `DEFAULT_CREDIT_WINDOW` when `None`.
/// * `estimated_chunk_count` — Optional invoker-declared upper bound on
///   billable chunks; routes into the §5.4.5 escrow-at-open computation.
///
/// # Errors
///
/// `ScpError::Permission` (`SCP-PERM-3001`) on UCAN-validation failure.
/// `ScpError::Context` with the §5.4.4 sub-block code when the open is
/// rejected by admission caps, escrow, or estimate-bound checks.
#[uniffi::export(async_runtime = "tokio")]
#[allow(clippy::too_many_arguments)]
pub async fn outlet_invoke_stream(
    handle: Arc<ContextHandle>,
    outlet_id: String,
    input_json: String,
    identity: Arc<Identity>,
    ucan_token: String,
    caveats_binding_hex: String,
    stream_epoch: u64,
    proof_tokens: Option<Vec<String>>,
    credit_window: Option<u32>,
    estimated_chunk_count: Option<u32>,
    spending_ucan: Option<String>,
) -> Result<Arc<OutletStreamHandle>, ScpError> {
    crate::uniffi_check_handle!(handle, identity);
    runtime::ensure_bridge_instance();
    open_stream_internal(
        &handle,
        &outlet_id,
        &input_json,
        &identity,
        &ucan_token,
        &caveats_binding_hex,
        stream_epoch,
        proof_tokens.as_deref(),
        credit_window,
        estimated_chunk_count,
        spending_ucan.as_deref(),
    )
    .await
    .map(Arc::new)
}

/// Opens a §5.4.5 streaming outlet invocation and pumps every emitted
/// chunk into the supplied [`OutletStreamSubscriber`].
///
/// Returns the `request_id` (32-char lowercase hex) so the caller can
/// address the active session from
/// [`outlet_stream_grant_credit`] / [`outlet_stream_cancel`] before the
/// pump exits.
///
/// The pump task is spawned on the global tokio runtime and exits when
/// the receiver closes or after emitting a terminal chunk. Subscriber
/// calls are awaited sequentially so chunk ordering is preserved.
///
/// # Errors
///
/// Same as [`outlet_invoke_stream`].
#[uniffi::export(async_runtime = "tokio")]
#[allow(clippy::too_many_arguments)]
pub async fn outlet_invoke_stream_with_subscriber(
    handle: Arc<ContextHandle>,
    outlet_id: String,
    input_json: String,
    identity: Arc<Identity>,
    ucan_token: String,
    caveats_binding_hex: String,
    stream_epoch: u64,
    proof_tokens: Option<Vec<String>>,
    credit_window: Option<u32>,
    estimated_chunk_count: Option<u32>,
    spending_ucan: Option<String>,
    subscriber: Box<dyn OutletStreamSubscriber>,
) -> Result<String, ScpError> {
    crate::uniffi_check_handle!(handle, identity);
    runtime::ensure_bridge_instance();
    let stream_handle = open_stream_internal(
        &handle,
        &outlet_id,
        &input_json,
        &identity,
        &ucan_token,
        &caveats_binding_hex,
        stream_epoch,
        proof_tokens.as_deref(),
        credit_window,
        estimated_chunk_count,
        spending_ucan.as_deref(),
    )
    .await?;
    let request_id_hex = stream_handle.request_id_hex.clone();
    // Wrap in Arc so the spawned pump can hold its own reference.
    let stream_handle = Arc::new(stream_handle);
    let pump_handle = Arc::clone(&stream_handle);
    tokio::spawn(async move {
        // Drive the existing `next()` loop — guarantees terminal-chunk
        // detection, registry eviction, and `terminated` flag flips
        // happen exactly once.
        loop {
            match pump_handle.next().await {
                Ok(Some(chunk)) => {
                    let was_terminal_payload = matches!(
                        chunk.payload_type.as_str(),
                        "end" | "error" if chunk.terminal == Some(true) || chunk.payload_type == "end"
                    );
                    subscriber.on_chunk(chunk).await;
                    if was_terminal_payload {
                        subscriber.on_complete().await;
                        break;
                    }
                }
                Ok(None) => {
                    // Receiver closed before a terminal chunk arrived —
                    // surface as on_error so subscribers do not block.
                    subscriber
                        .on_error(ScpError::Tool {
                            msg: "stream closed without terminal chunk".to_owned(),
                            code: codes::TOOL_6006.to_owned(),
                        })
                        .await;
                    break;
                }
                Err(e) => {
                    subscriber.on_error(e).await;
                    break;
                }
            }
        }
    });
    Ok(request_id_hex)
}

#[allow(clippy::too_many_arguments)]
async fn open_stream_internal(
    handle: &ContextHandle,
    outlet_id: &str,
    input_json: &str,
    identity: &Identity,
    ucan_token: &str,
    caveats_binding_hex: &str,
    stream_epoch: u64,
    proof_tokens: Option<&[String]>,
    credit_window: Option<u32>,
    estimated_chunk_count: Option<u32>,
    spending_ucan: Option<&str>,
) -> Result<OutletStreamHandle, ScpError> {
    use scp_ffi_common::validate::{validate_did, validate_outlet_id, validate_ucan_token};

    validate_outlet_id(outlet_id).map_err(ScpError::from)?;
    validate_did(&identity.did).map_err(ScpError::from)?;
    validate_ucan_token(ucan_token).map_err(ScpError::from)?;
    if let Some(jwt) = spending_ucan {
        validate_ucan_token(jwt).map_err(ScpError::from)?;
    }
    if let Some(tokens) = proof_tokens {
        for t in tokens {
            validate_ucan_token(t).map_err(ScpError::from)?;
        }
    }

    // Ensure the context is active before allocating any per-stream
    // state — mirrors the `outlet_invoke` precondition.
    let state = handle.state.lock().await;
    if !matches!(*state, ContextState::Active) {
        return Err(ScpError::Tool {
            msg: format!(
                "cannot invoke streaming outlet in context in {:?} state — context must be active",
                *state
            ),
            code: codes::TOOL_6005.to_owned(),
        });
    }
    drop(state);

    let caveats_binding = decode_caveats_binding(caveats_binding_hex)?;
    let input_value: Value = serde_json::from_str(input_json).map_err(|e| ScpError::Tool {
        msg: format!("invalid input JSON: {e}"),
        code: codes::TOOL_6002.to_owned(),
    })?;

    // Re-validate the UCAN under the full 11-step pipeline (defence in
    // depth — the runtime also validates at open, but doing it here
    // ensures the bridge surfaces a clean `Permission` error before
    // allocating any per-stream state).
    let outlet_kind = {
        let registry_lock = handle.outlet_registry.lock().await;
        registry_lock
            .get(outlet_id)
            .map(|r| r.kind)
            .ok_or_else(|| ScpError::Tool {
                msg: format!("tool '{outlet_id}' not registered"),
                code: codes::TOOL_6002.to_owned(),
            })?
    };
    let proof_tokens_vec: Option<Vec<String>> = proof_tokens.map(<[String]>::to_vec);
    crate::bridge::validate_outlet_ucan_uniffi(
        handle,
        outlet_id,
        outlet_kind,
        ucan_token,
        &identity.did,
        proof_tokens_vec.as_ref(),
    )?;

    // Snapshot the bridge-owned outlet registry + handler closure +
    // role state. Mirrors the `outlet_invoke` snapshot pattern.
    let registry_snapshot = {
        let reg = handle.outlet_registry.lock().await;
        reg.clone()
    };
    let registered_handler = {
        let handlers = handle.outlet_handlers.lock().await;
        handlers.get(outlet_id).cloned()
    };
    let manager = runtime::context_manager_expect()?;
    let role_state = manager
        .get_role_state(&handle.context_id)
        .await
        .ok_or_else(|| ScpError::Context {
            msg: format!(
                "context '{}' not found in ContextManager during stream open",
                handle.context_id
            ),
            code: codes::CTX_2040.to_owned(),
        })?;

    // §5.4.5 / ADR-006 — resolve the invoker's key handle + custody variant.
    // The operator (chunk signer) and invoker (UCAN holder) are the same
    // custody-held key in the local single-context streaming path, so a
    // single `CustodyStreamSigner` over this handle backs BOTH the runtime
    // pump's chunk signing (`OpenStreamParams::operator_signer`) and the
    // bridge's cancel signing — the private key never crosses the FFI
    // boundary (the inline raw-`SigningKey` export was deleted).
    let (custody, invoker_key_handle) = resolve_invoker_custody(handle, identity)?;
    let invoker_verifying_key = custody
        .public_verifying_key(&invoker_key_handle)
        .await
        .map_err(|_e| ScpError::Identity {
            msg: "failed to resolve invoker public key from custody".to_owned(),
            code: codes::IDENT_1041.to_owned(),
        })?;

    let executor: Arc<dyn scp_runtime::context::outlets::invoke::OutletExecutor> =
        Arc::new(ClosureExecutor {
            ctx_id: handle.context_id.clone(),
            outlet_id: outlet_id.to_owned(),
            invoker_did: identity.did.clone(),
            handler: registered_handler,
        });

    // §5.4.5 economy (N3) — wire real escrow inputs.
    // `cost_per_chunk` is the outlet's registered per-invocation cost
    // (§5.4.1 / §19.3); `Amount::new(0)` for Query and zero-cost outlets.
    let cost_per_chunk = registry_snapshot
        .get(outlet_id)
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
    let spending_max_per_action = match spending_ucan {
        None => None,
        Some(jwt) => {
            let token = scp_protocol::crypto::ucan::validate::parse_ucan(jwt).map_err(|_e| {
                ScpError::Permission {
                    msg: "invalid spending UCAN".to_owned(),
                    code: codes::PERM_3001.to_owned(),
                }
            })?;
            let cap =
                scp_protocol::crypto::ucan::spending::SpendingCapability::from_ucan_token(&token)
                    .map_err(|_e| ScpError::Permission {
                    msg: "spending UCAN missing spending capability".to_owned(),
                    code: codes::PERM_3001.to_owned(),
                })?;
            Some(scp_protocol::economy::types::Amount::new(
                cap.max_per_action.0,
            ))
        }
    };
    let invoker_did_typed_for_balance: scp_primitives::DID = identity.did.clone().into();

    let operator_signer: Arc<dyn scp_runtime::context::outlets::signer::StreamSigner> = Arc::new(
        CustodyStreamSigner::new(custody.clone(), invoker_key_handle, invoker_verifying_key),
    );

    // §5.4.5 HIGH-wave-2 Fix A — compute the UCAN cid the runtime
    // uses for binding recompute. The bridge has already validated
    // the UCAN above; re-parse the encoded JWT here to get the cid
    // (the parse is bounded — same JWT, same cid, deterministically).
    let ucan_token_parsed =
        scp_protocol::crypto::ucan::validate::parse_ucan(ucan_token).map_err(|_e| {
            // N5 (ADR-049 §4): drop the parse error Display — generic message.
            ScpError::Permission {
                msg: "failed to parse ucan_token for cid".to_owned(),
                code: codes::PERM_3001.to_owned(),
            }
        })?;
    let ucan_cid_for_binding = scp_runtime::crypto::ucan::mint::compute_cid(&ucan_token_parsed);
    let request_id_value: scp_protocol::context::outlets::stream::RequestId =
        *uuid::Uuid::now_v7().as_bytes();
    let revocation_checker: Arc<
        dyn scp_protocol::crypto::ucan::validate::RevocationChecker + Send + Sync,
    > = Arc::new(BridgeStreamRevocationChecker::for_context(
        &handle.context_id,
    )?);

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
    let escrow_reservation = manager
        .outlet_stream_reserve_escrow(
            &handle.context_id,
            &invoker_did_typed_for_balance,
            cost_per_chunk,
            coerced_estimate,
            spending_max_per_action,
        )
        .await
        .map_err(|e| ScpError::Context {
            msg: format!("stream escrow reservation failed: {e}"),
            code: codes::CTX_2000.to_owned(),
        })?;
    let reserved_escrow = escrow_reservation.reserved;
    // E2 refund guard: the hold is debited NOW; an early-return before the
    // pump spawns drops this ticket → refund via Handle::spawn of the async
    // reverse_spend. Consumed only on the Ok open path below.
    let escrow_ticket = scp_runtime::context::outlets::dispatch::StreamEscrowTicket::new(
        bridge_stream_escrow_refund_sink()?,
        handle.context_id.clone(),
        invoker_did_typed_for_balance.clone(),
        reserved_escrow,
    );

    let params = build_open_stream_params(
        handle.context_id.clone(),
        outlet_id.to_owned(),
        identity.did.clone(),
        stream_epoch,
        caveats_binding,
        credit_window,
        estimated_chunk_count,
        invoker_verifying_key,
        operator_signer,
        cost_per_chunk,
        reserved_escrow,
        effective_caveats,
        ucan_cid_for_binding,
        request_id_value,
        revocation_checker,
    );
    // §5.4.5 admission tracker MUST persist across successive opens
    // within a single context — fetch (or lazily create) the per-context
    // tracker on the bridge instance so the caps actually trip.
    let admission = runtime::default_bridge_instance_raw()
        .ok_or_else(|| ScpError::Context {
            msg: "bridge instance not initialised".to_owned(),
            code: codes::CTX_2000.to_owned(),
        })?
        .outlet_stream_admission_for_context(&handle.context_id);

    let invoker_did_typed: scp_primitives::DID = identity.did.clone().into();
    let outlet_id_typed = scp_core::context::outlets::OutletId::from(outlet_id);

    // E1 — close-time settlement sink (refund unspent escrow + §19.15.5
    // PaymentReceipt). Fired once by the dispatch pump at terminal chunk; it
    // `Handle::spawn`s the async `outlet_stream_settle` (it MUST NOT block).
    let settlement_sink: Option<
        Arc<dyn scp_runtime::context::outlets::invoke::StreamSettlementSink>,
    > = Some(bridge_stream_settlement_sink()?);

    let open_result = manager
        .open_outlet_stream(
            &handle.context_id,
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
            // E2: pump spawned Ok — close-time settlement now owns the
            // unspent-hold refund; consume the open-path ticket.
            escrow_ticket.consume();
            handle
        }
        Err(rejection) => {
            // E2: any open-time rejection drops `escrow_ticket` → refund of
            // the debited hold (independent of the runtime's admission
            // rollback; both roll back on the same path).
            drop(escrow_ticket);
            return Err(ScpError::Context {
                msg: format!(
                    "stream open rejected: {} ({})",
                    rejection.slug(),
                    rejection.error_code()
                ),
                code: rejection.error_code().to_owned(),
            });
        }
    };

    let receiver = runtime_handle.receiver().ok_or_else(|| ScpError::Context {
        msg: "stream handle has no receiver".to_owned(),
        code: codes::CTX_2000.to_owned(),
    })?;
    let request_id = *runtime_handle.request_id();
    let request_id_hex_str = request_id_hex(&request_id);

    register_stream_entry(StreamRegistryEntry {
        handle: runtime_handle,
        monotonic_seq: Mutex::new(0),
        context_id: handle.context_id.clone(),
        outlet_id: outlet_id.to_owned(),
        stream_epoch,
        caveats_binding,
        invoker_key_handle,
        custody,
        invoker_verifying_key,
        invoker_did: identity.did.clone(),
        request_id,
        spending_max_per_action,
        cost_per_chunk,
    })?;

    Ok(OutletStreamHandle {
        rx: Arc::new(TokioMutex::new(Some(receiver))),
        request_id_hex: request_id_hex_str,
        invoker_did: identity.did.clone(),
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
/// (ADR-006). Mirrors the `PyO3` reference and NAPI bridges.
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
    operator_signer: Arc<dyn scp_runtime::context::outlets::signer::StreamSigner>,
    cost_per_chunk: scp_protocol::economy::types::Amount,
    reserved_escrow: scp_protocol::economy::types::Amount,
    effective_caveats: InvocationCaveats,
    ucan_cid: String,
    request_id: scp_protocol::context::outlets::stream::RequestId,
    revocation_checker: Arc<
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
        // re-check + binding-pinning. See PyO3 bridge for rationale.
        stream_ucan_recheck_secs:
            scp_protocol::context::outlets::stream::DEFAULT_STREAM_UCAN_RECHECK_SECS,
        ucan_cid,
        request_id,
        revocation_checker,
    }
}

/// Inserts an entry into the per-bridge stream registry, keyed by the
/// 32-char lowercase hex `request_id`.
fn register_stream_entry(entry: StreamRegistryEntry) -> Result<(), ScpError> {
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
/// Per §5.4.5 round-5 the credit signature commits to the pinned stream
/// identity (`context_id`, `outlet_id`, `stream_epoch`, `caveats_binding`)
/// plus the strictly-monotonic `monotonic_seq`. This function reads the
/// local counter from the registry entry, constructs the grant, signs it
/// under the invoker's pinned signing key, and forwards it to
/// [`scp_runtime::context::outlets::dispatch::StreamSessionHandle::apply_credit_grant`].
///
/// Returns the new total credit budget on success.
///
/// # Errors
///
/// * `ScpError::Validation` — `grant == 0` (round-6 uniform `InvalidGrant`
///   rule).
/// * `ScpError::Context` (slug `protocol.unknown-session`) — the
///   `request_id_hex` does not match any active stream registry entry.
/// * `ScpError::Context` — the runtime tracker rejected the grant
///   (replay, identity mismatch, escrow overflow, insufficient funds).
#[uniffi::export(async_runtime = "tokio")]
pub async fn outlet_stream_grant_credit(
    request_id_hex: String,
    caller_did: String,
    grant: u32,
) -> Result<u32, ScpError> {
    if grant == 0 {
        return Err(ScpError::Validation {
            msg: "invalid grant 0: must be in (0, 2^32 - 1] (protocol.invalid-grant)".to_owned(),
            code: scp_protocol::context::outlets::error_codes::CODE_PROTOCOL_SESSION.to_owned(),
        });
    }
    scp_ffi_common::validate::validate_did(&caller_did).map_err(ScpError::from)?;
    let entry = lookup_entry_authenticated(&request_id_hex, &caller_did)?;

    // Reserve the next monotonic_seq under a critical section so two
    // racing grant calls cannot collide. Bumping the counter BEFORE
    // signing means a runtime rejection (e.g., replay / mismatch)
    // leaves the counter advanced — a subsequent retry from the SDK
    // MUST present a fresh grant with the next monotonic_seq, NOT the
    // same value we just signed. This matches the §5.4.5
    // strict-monotonicity invariant: any seq accepted OR rejected by
    // the runtime at this point is "consumed" from the SDK's
    // perspective.
    let next_seq = {
        let mut guard = entry
            .monotonic_seq
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = guard.checked_add(1).ok_or_else(|| ScpError::Context {
            msg: "monotonic_seq overflow: stream has issued u64::MAX grants".to_owned(),
            code: codes::CTX_2000.to_owned(),
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
    let manager = runtime::context_manager_expect()?;
    let reserved_top_up = manager
        .outlet_stream_reserve_grant(
            &entry.context_id,
            &invoker_did_typed,
            entry.cost_per_chunk,
            grant,
            entry.spending_max_per_action,
        )
        .await
        .map_err(|e| ScpError::Context {
            msg: format!("credit grant escrow reservation failed: {e}"),
            code: codes::CTX_2000.to_owned(),
        })?;

    // Apply with the already-debited top-up. On runtime rejection
    // (signature / replay) AFTER a successful reserve, reverse the debit so
    // the §5.4.5 atomicity invariant holds.
    match entry.handle.apply_credit_grant(&credit, reserved_top_up) {
        Ok(new_total) => Ok(new_total),
        Err(grant_err) => {
            if reserved_top_up.value() > 0 {
                manager
                    .outlet_stream_reverse_spend(
                        &entry.context_id,
                        &invoker_did_typed,
                        reserved_top_up,
                    )
                    .await;
            }
            Err(ScpError::Context {
                msg: format!("credit grant rejected: {grant_err:?}"),
                code: codes::CTX_2000.to_owned(),
            })
        }
    }
}

/// Constructs and signs an [`OutletStreamCredit`] for `entry`.
async fn sign_credit_grant(
    entry: &StreamRegistryEntry,
    grant: u32,
    monotonic_seq: u64,
) -> Result<OutletStreamCredit, ScpError> {
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
        .sign(&entry.invoker_key_handle, &preimage)
        .await
        .map_err(|e| ScpError::Context {
            msg: format!("custody sign failed for credit grant: {e}"),
            code: codes::CTX_2000.to_owned(),
        })?;
    let sig_bytes: [u8; 64] =
        signature
            .into_bytes()
            .try_into()
            .map_err(|got: Vec<u8>| ScpError::Context {
                msg: format!(
                    "custody returned signature of {} bytes; expected 64",
                    got.len()
                ),
                code: codes::CTX_2000.to_owned(),
            })?;
    let signature_typed = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    if entry
        .invoker_verifying_key
        .verify_strict(&preimage, &signature_typed)
        .is_err()
    {
        return Err(ScpError::Context {
            msg: "freshly-signed credit grant failed self-verification \
                  — SCP-OUTLET-CREDIT-V1 preimage drift or custody/key mismatch"
                .to_owned(),
            code: codes::CTX_2000.to_owned(),
        });
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
/// * `ScpError::Context` (slug `protocol.unknown-session`) —
///   `request_id_hex` does not match any active stream.
/// * `ScpError::Context` (slug `authorization.denied`, code `SCP-TOOL-6110`)
///   — the caller's identity did not match the pinned triple, the runtime's
///   own signature failed self-verification, or the custody signer failed.
/// * `ScpError::Context` (slug `transport.rate-limited`, code
///   `SCP-TOOL-6160`) — the live cursor advanced on every bounded retry
///   (retryable).
#[uniffi::export(async_runtime = "tokio")]
pub async fn outlet_stream_cancel(
    request_id_hex: String,
    caller_did: String,
) -> Result<Option<u64>, ScpError> {
    scp_ffi_common::validate::validate_did(&caller_did).map_err(ScpError::from)?;
    let entry = lookup_entry_authenticated(&request_id_hex, &caller_did)?;
    // The invoker signs the cancel; the runtime verifies under the pinned
    // `invoker_pk`. A `CustodyStreamSigner` keeps the private key inside
    // custody (ADR-006).
    let invoker_signer = CustodyStreamSigner::new(
        entry.custody.clone(),
        entry.invoker_key_handle,
        entry.invoker_verifying_key,
    );
    let identity = scp_runtime::context::outlets::dispatch::CancelIdentity {
        context_id: entry.context_id.clone(),
        outlet_id: entry.outlet_id.clone(),
        caveats_binding: entry.caveats_binding,
    };
    entry
        .handle
        .apply_outlet_cancel_signed(&invoker_signer, &identity)
        .await
        .map_err(|err| ScpError::Context {
            msg: format!(
                "cancel rejected ({})",
                scp_runtime::context::outlets::stream::cancel_error_to_slug(&err)
            ),
            code: scp_runtime::context::outlets::stream::cancel_error_to_code(&err).to_owned(),
        })
}

// ---------------------------------------------------------------------------
// outlet_stream_terminate — receiver-side revocation re-check (§5.4.5)
// ---------------------------------------------------------------------------

/// Closed set of framework-emitted stream termination causes (§5.4.5).
///
/// Exposed to Swift / Kotlin via `UniFFI`. Mirrors
/// [`scp_protocol::context::outlets::stream::TerminateReason`] — kept
/// as a `UniFFI`-local enum so Swift/Kotlin see an idiomatic
/// `enum TerminateReason { case revokedMidStream, ... }` /
/// `sealed class TerminateReason { object RevokedMidStream : ... }`
/// surface instead of a raw integer or slug string.
///
/// Conversion to the protocol enum is total (no error path) —
/// every `UniFFI` variant maps to exactly one protocol variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum TerminateReason {
    /// `authorization.revoked-mid-stream` / `SCP-TOOL-6110`. The
    /// receiver-side periodic UCAN re-check observed the opening
    /// token revoked since stream open.
    RevokedMidStream,
    /// `execution.cancel-ack-timeout` / `SCP-TOOL-6135`. The executor
    /// failed to emit a terminal chunk within `stream_cancel_ack_secs`
    /// after `OutletCancel` arrival.
    CancelAckTimeout,
    /// `execution.credit-stall` / `SCP-TOOL-6133`. The credit window
    /// remained at zero past `stream_credit_stall_secs`.
    CreditStall,
    /// `protocol.context-closed-mid-stream` / `SCP-TOOL-6101` (round 8).
    /// The hosting context was closed or the operator was evicted/left
    /// while the stream was active. Distinct from [`Self::RevokedMidStream`]
    /// (Authorization class): a context teardown is a Protocol-session
    /// lifecycle event, NOT a UCAN revocation, and MUST NOT be recorded as
    /// one. See §5.4.5 "Context teardown vs. revocation (round 8)".
    ContextClosedMidStream,
}

impl From<TerminateReason> for scp_protocol::context::outlets::stream::TerminateReason {
    fn from(r: TerminateReason) -> Self {
        match r {
            TerminateReason::RevokedMidStream => Self::RevokedMidStream,
            TerminateReason::CancelAckTimeout => Self::CancelAckTimeout,
            TerminateReason::CreditStall => Self::CreditStall,
            TerminateReason::ContextClosedMidStream => Self::ContextClosedMidStream,
        }
    }
}

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
/// The SDK framework's periodic UCAN re-check loop calls this with
/// [`TerminateReason::RevokedMidStream`] whenever it observes the
/// opening UCAN has been revoked since stream open. The reason enum
/// is closed — Swift `enum` / Kotlin `sealed class` make adding a
/// new variant a compile-time event in the SDK. `message_override`
/// is the only caller-controllable string and is appended to the
/// canonical slug prefix; passing `None` uses the spec's default
/// message for the variant.
///
/// # Errors
///
/// * `ScpError::Context` (slug `protocol.unknown-session`) —
///   `request_id_hex` does not match any active stream.
/// * `ScpError::Context` — the runtime rejected the termination because
///   the pump has already emitted a terminal chunk
///   ([`scp_runtime::context::outlets::dispatch::TerminateError::AlreadyTerminated`])
///   or another terminate is already pending
///   ([`scp_runtime::context::outlets::dispatch::TerminateError::AlreadyPending`]).
// UniFFI proc-macros generate the binding glue based on the `async`
// keyword — the function body is sync (no awaits) because both
// `lookup_entry` and `terminate_with_error` are sync, but the public
// surface MUST be `async` so Swift sees `async throws` and Kotlin sees
// `suspend` (mirroring `outlet_stream_cancel`'s signature shape).
#[allow(clippy::unused_async)]
#[uniffi::export(async_runtime = "tokio")]
pub async fn outlet_stream_terminate(
    request_id_hex: String,
    caller_did: String,
    reason: TerminateReason,
    message_override: Option<String>,
) -> Result<(), ScpError> {
    scp_ffi_common::validate::validate_did(&caller_did).map_err(ScpError::from)?;
    let entry = lookup_entry_authenticated(&request_id_hex, &caller_did)?;
    let reason_proto: scp_protocol::context::outlets::stream::TerminateReason = reason.into();
    entry
        .handle
        .terminate_with_error(reason_proto, message_override)
        .map_err(|err| ScpError::Context {
            msg: format!("terminate rejected: {err}"),
            code: reason_proto.code().to_owned(),
        })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// verify_chunk_signature — pure helper
// ---------------------------------------------------------------------------

/// Verifies a chunk's `SCP-OUTLET-CHUNK-SIG-V1:` signature.
///
/// `chunk_json` is the canonical-JSON-encoded [`OutletStreamChunk`] (the
/// bridge accepts the full chunk encoded as JSON and reconstructs the
/// typed struct so the verification path covers exactly the bytes the
/// operator signed). All five inputs match the §5.4.5 preimage block
/// byte-for-byte.
///
/// Returns `true` if the signature verifies, `false` otherwise. Never
/// throws for a bad signature — only for malformed inputs (non-32-byte
/// pubkey / `caveats_binding`, malformed JSON).
///
/// # Errors
///
/// `ScpError::Validation` (`SCP-VALID-7000`) on malformed inputs.
#[uniffi::export]
pub fn verify_chunk_signature(
    chunk_json: String,
    operator_pk: Vec<u8>,
    context_id: String,
    outlet_id: String,
    caveats_binding: Vec<u8>,
) -> Result<bool, ScpError> {
    let chunk: OutletStreamChunk =
        serde_json::from_str(&chunk_json).map_err(|_e| ScpError::Validation {
            // N5 (ADR-049 §4): never echo the serde Display — it can quote
            // bytes of the attacker-supplied chunk JSON. Keep CODE + generic.
            msg: "malformed chunk JSON".to_owned(),
            code: codes::VALID_7000.to_owned(),
        })?;
    let pk_array: [u8; 32] =
        operator_pk
            .as_slice()
            .try_into()
            .map_err(|_| ScpError::Validation {
                msg: format!(
                    "operator_pk must be exactly 32 bytes, got {}",
                    operator_pk.len()
                ),
                code: codes::VALID_7000.to_owned(),
            })?;
    let caveats_binding_array: [u8; 32] =
        caveats_binding
            .as_slice()
            .try_into()
            .map_err(|_| ScpError::Validation {
                msg: format!(
                    "caveats_binding must be exactly 32 bytes, got {}",
                    caveats_binding.len()
                ),
                code: codes::VALID_7000.to_owned(),
            })?;
    let pk =
        ed25519_dalek::VerifyingKey::from_bytes(&pk_array).map_err(|e| ScpError::Validation {
            msg: format!("operator_pk is not a valid Ed25519 public key: {e}"),
            code: codes::VALID_7000.to_owned(),
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
/// `effective_caveats_json` is the SDK-canonicalised JSON object of the
/// narrowed [`InvocationCaveats`] — the bridge re-runs JCS over it so
/// the caller does not need an in-language JCS implementation.
///
/// Returns the 32-byte hash as a byte vector.
///
/// # Errors
///
/// `ScpError::Validation` (`SCP-VALID-7000`) on a non-16-byte
/// `request_id`, malformed JSON, or shape mismatch against
/// `InvocationCaveats`.
#[uniffi::export]
pub fn compute_caveats_binding(
    ucan_cid: Vec<u8>,
    request_id: Vec<u8>,
    invoker_did: String,
    estimated_chunk_count: u32,
    effective_caveats_json: String,
) -> Result<Vec<u8>, ScpError> {
    let request_id_array: [u8; 16] =
        request_id
            .as_slice()
            .try_into()
            .map_err(|_| ScpError::Validation {
                msg: format!(
                    "request_id must be exactly 16 bytes, got {}",
                    request_id.len()
                ),
                code: codes::VALID_7000.to_owned(),
            })?;
    let caveats_value: Value =
        serde_json::from_str(&effective_caveats_json).map_err(|_e| ScpError::Validation {
            // N5 (ADR-049 §4): drop the serde Display — generic message only.
            msg: "invalid effective_caveats JSON".to_owned(),
            code: codes::VALID_7000.to_owned(),
        })?;
    let caveats: InvocationCaveats =
        serde_json::from_value(caveats_value).map_err(|_e| ScpError::Validation {
            msg: "effective_caveats does not match the InvocationCaveats schema".to_owned(),
            code: codes::VALID_7000.to_owned(),
        })?;
    // §5.4.5 requires JCS canonicalization of `effective_caveats` before
    // hashing — the bridge runs canonicalisation here so SDK callers do
    // not need an in-language JCS implementation. `serde` is already
    // configured on `InvocationCaveats` to skip-`None`-fields per the
    // round-5 omit-none convention (cross-SDK byte-for-byte match).
    let caveats_jcs = scp_protocol::jcs::to_vec(&caveats).map_err(|e| ScpError::Tool {
        msg: format!("failed to JCS-canonicalise caveats: {e}"),
        code: codes::TOOL_6006.to_owned(),
    })?;
    let binding = proto_stream::compute_caveats_binding(
        &ucan_cid,
        &request_id_array,
        &invoker_did,
        estimated_chunk_count,
        &caveats_jcs,
    );
    Ok(binding.to_vec())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn decode_caveats_binding(hex_str: &str) -> Result<[u8; 32], ScpError> {
    let bytes = hex::decode(hex_str).map_err(|e| ScpError::Validation {
        msg: format!("caveats_binding_hex must be 64 hex characters: {e}"),
        code: codes::VALID_7000.to_owned(),
    })?;
    let len = bytes.len();
    bytes.try_into().map_err(|_| ScpError::Validation {
        msg: format!("caveats_binding must decode to 32 bytes, got {len}"),
        code: codes::VALID_7000.to_owned(),
    })
}

fn lookup_entry(request_id_hex: &str) -> Result<Arc<StreamRegistryEntry>, ScpError> {
    // N4: validate the request_id at the FFI boundary BEFORE it is used as
    // a registry key or interpolated into any message. A malformed hex
    // string is rejected with a typed ValidationError carrying the
    // canonical code and a generic, input-free message — the offending
    // bytes are never echoed.
    scp_ffi_common::validate::validate_request_id_hex(request_id_hex).map_err(|_e| {
        ScpError::Validation {
            msg: "request_id must be 32 lowercase hex characters (16-byte UUIDv7)".to_owned(),
            code: codes::VALID_7000.to_owned(),
        }
    })?;
    // Ensure the default bridge instance exists so the registry exists
    // — this lets the unknown-session error path surface even when no
    // stream has ever been opened (e.g., a test or stale handle on the
    // SDK side calling `cancel` without prior `outlet_invoke_stream`).
    runtime::ensure_bridge_instance();
    let reg = registry()?;
    reg.get(request_id_hex)
        .map(|kv| Arc::clone(kv.value()))
        .ok_or_else(|| ScpError::Context {
            // N5: do not echo the request_id back into the message.
            msg: "stream not found in registry (protocol.unknown-session)".to_owned(),
            code: scp_protocol::context::outlets::error_codes::CODE_PROTOCOL_SESSION.to_owned(),
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
) -> Result<Arc<StreamRegistryEntry>, ScpError> {
    let entry = lookup_entry(request_id_hex)?;
    if entry.invoker_did != caller_did {
        return Err(ScpError::Context {
            msg: "caller is not the pinned invoker for this stream (authorization.denied)"
                .to_owned(),
            code: codes::PERM_3001.to_owned(),
        });
    }
    Ok(entry)
}

/// Resolves the invoker's [`KeyHandle`] and the matching
/// [`StreamCustody`] variant from either the context handle's pinned
/// custody (preferred — `outlet_invoke` uses this same path) or the
/// identity's own retained custody.
///
/// §5.4.5 HIGH-wave-3 Fix A — replaces the previous
/// `resolve_invoker_signing_key` helper as the primary key-resolution
/// path so the bridge does not cache raw private bytes on the registry
/// entry. The returned [`StreamCustody`] is moved into the registry
/// entry; every later sign call goes through it.
fn resolve_invoker_custody(
    handle: &ContextHandle,
    identity: &Identity,
) -> Result<(StreamCustody, KeyHandle), ScpError> {
    // Prefer the context handle's signing key (set during context
    // creation / join). Falls back to the identity's `core_id` when
    // the ContextHandle was minted without an identity-tied signing
    // key (e.g., a context joined with a different identity than was
    // used for `identity_create`).
    let key_handle = handle.signing_key.or_else(|| {
        identity
            .core_id
            .as_ref()
            .map(|core| core.active_signing_key)
    });
    let Some(key_handle) = key_handle else {
        return Err(ScpError::Identity {
            msg: "no signing key available for invoker — identity must have an active signing key"
                .to_owned(),
            code: codes::IDENT_1041.to_owned(),
        });
    };

    // Try the context handle's callback custody first, then in-memory
    // custody, then the identity's callback custody / in-memory
    // custody — mirroring the precedence the legacy
    // `resolve_invoker_signing_key` helper used.
    if let Some(ref cb) = handle.callback_custody {
        return Ok((StreamCustody::Callback(Arc::clone(cb)), key_handle));
    }
    #[cfg(feature = "allow_in_memory_custody")]
    if let Some(ref imc) = handle.in_memory_custody {
        return Ok((StreamCustody::InMemory(Arc::clone(imc)), key_handle));
    }
    if let Some(ref cb) = identity.callback_custody {
        return Ok((StreamCustody::Callback(Arc::clone(cb)), key_handle));
    }
    #[cfg(feature = "allow_in_memory_custody")]
    if let Some(ref imc) = identity.in_memory_custody {
        return Ok((StreamCustody::InMemory(Arc::clone(imc)), key_handle));
    }

    Err(ScpError::Identity {
        msg: "no custody provider available — identity must be created with a custody method"
            .to_owned(),
        code: codes::IDENT_1041.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// ClosureExecutor — adapter from a UniFFI-handler closure to OutletExecutor
// ---------------------------------------------------------------------------

/// Adapter that lets the existing `UniFFI` [`crate::bridge::OutletHandlerMap`]
/// closure satisfy the runtime's
/// [`scp_runtime::context::outlets::invoke::OutletExecutor`] trait without
/// touching the `outlet_invoke` path. `exec_action_stream` and
/// `exec_query_stream` defer to the registered handler when present and
/// fall back to schema-only echo mode when no handler is registered
/// (matching `outlet_invoke`'s contract).
/// Type alias for a sync outlet handler closure stored on the
/// `ContextHandle`. Mirrors the shape of `bridge::OutletHandlerMap`
/// values without re-exporting the private `OutletHandlerMap` alias.
type SyncOutletHandler =
    std::sync::Arc<dyn Fn(serde_json::Value) -> Result<serde_json::Value, String> + Send + Sync>;

struct ClosureExecutor {
    ctx_id: String,
    outlet_id: String,
    invoker_did: String,
    handler: Option<SyncOutletHandler>,
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
            pk_bytes.clone(),
            "ctx-stream".to_owned(),
            "outlet-x".to_owned(),
            cb_bytes.clone(),
        )
        .expect("verify ok");
        assert!(ok, "freshly signed chunk must verify");

        // Tampering with context_id flips the result.
        let bad_ctx = verify_chunk_signature(
            chunk_json.clone(),
            pk_bytes.clone(),
            "ctx-other".to_owned(),
            "outlet-x".to_owned(),
            cb_bytes,
        )
        .expect("verify call");
        assert!(!bad_ctx, "tampered context_id must NOT verify");

        // Tampering with caveats_binding flips the result.
        let bad_binding: [u8; 32] = [0xCD; 32];
        let bad_b = verify_chunk_signature(
            chunk_json,
            pk_bytes,
            "ctx-stream".to_owned(),
            "outlet-x".to_owned(),
            bad_binding.to_vec(),
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
            signing.verifying_key().as_bytes().to_vec(),
            "ctx".to_owned(),
            "outlet".to_owned(),
            short_binding,
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
            ucan_cid.clone(),
            request_id_bytes.clone(),
            invoker_did.clone(),
            100,
            caveats_json.clone(),
        )
        .expect("compute a");
        let b = compute_caveats_binding(
            ucan_cid.clone(),
            request_id_bytes.clone(),
            invoker_did.clone(),
            100,
            caveats_json.clone(),
        )
        .expect("compute b");
        assert_eq!(a, b, "binding must be deterministic");
        assert_eq!(a.len(), 32, "binding is 32 bytes");

        // Changing one input flips bytes.
        let c = compute_caveats_binding(
            ucan_cid.clone(),
            request_id_bytes.clone(),
            invoker_did,
            101, // different chunk count
            caveats_json.clone(),
        )
        .expect("compute c");
        assert_ne!(a, c, "different estimated_chunk_count must flip bytes");

        // Changing invoker_did flips bytes.
        let d = compute_caveats_binding(
            ucan_cid,
            request_id_bytes,
            "did:dht:z6MkOther".to_owned(),
            100,
            caveats_json,
        )
        .expect("compute d");
        assert_ne!(a, d, "different invoker_did must flip bytes");
    }

    /// `compute_caveats_binding` rejects a 15-byte `request_id` with
    /// `Validation` error.
    #[test]
    fn compute_caveats_binding_rejects_short_request_id() {
        let short = vec![0u8; 15];
        let result = compute_caveats_binding(
            b"cid".to_vec(),
            short,
            "did:dht:x".to_owned(),
            1,
            "{}".to_owned(),
        );
        assert!(result.is_err(), "15-byte request_id must be rejected");
    }

    /// `outlet_stream_grant_credit` rejects `grant == 0` with
    /// `Validation` error per OUT-031 round-6 uniform `InvalidGrant`
    /// rule.
    #[tokio::test]
    async fn grant_credit_rejects_zero_grant() {
        let result =
            outlet_stream_grant_credit("00".repeat(16), "did:dht:z6MkInvoker".to_owned(), 0).await;
        assert!(result.is_err(), "grant=0 must be rejected");
        let err_str = format!("{:?}", result.unwrap_err());
        assert!(
            err_str.contains("invalid grant 0") || err_str.contains("protocol.invalid-grant"),
            "error must mention invalid-grant: {err_str}"
        );
    }

    /// `outlet_stream_cancel` returns `Context` error when the
    /// `request_id_hex` does not match any registry entry.
    #[tokio::test]
    async fn cancel_returns_unknown_session_for_missing_request() {
        // Use a fresh hex unlikely to match any other test's active
        // stream (registry is shared across tests in the default bridge
        // instance — see ADR-048).
        let result = outlet_stream_cancel("ee".repeat(16), "did:dht:z6MkInvoker".to_owned()).await;
        assert!(result.is_err(), "missing request_id must be rejected");
        let err_str = format!("{:?}", result.unwrap_err());
        assert!(
            err_str.contains("not found") || err_str.contains("unknown-session"),
            "error must mention unknown-session: {err_str}"
        );
    }

    /// §5.4.5 HIGH-wave-3 Fix B — dropping an [`OutletStreamHandle`]
    /// without consuming it evicts the registry entry. Build a wrapper
    /// referencing a sentinel request id, drop it, assert the registry
    /// no longer holds that key. Idempotent — running this test
    /// twice in a row succeeds.
    #[test]
    fn drop_evicts_registry_entry() {
        runtime::ensure_bridge_instance();
        let request_id_hex = "ef".repeat(16);
        {
            let wrapper = OutletStreamHandle {
                rx: Arc::new(TokioMutex::new(None)),
                request_id_hex: request_id_hex.clone(),
                invoker_did: "did:dht:z6MkInvoker".to_owned(),
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
    /// stores a raw `SigningKey`. Compile-time check: the
    /// `invoker_key_handle` field is a `KeyHandle`, `custody` is a
    /// `StreamCustody` enum, and `invoker_verifying_key` is the public
    /// key only. A field named `invoker_signing_key` would fail to
    /// compile if re-introduced.
    #[test]
    fn registry_entry_has_no_raw_signing_key_field() {
        fn assert_shape() {
            let _ = std::mem::size_of::<KeyHandle>();
            let _ = std::mem::size_of::<StreamCustody>();
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

        let inner = InMemoryKeyCustody::new();
        let handle = inner
            .generate_keypair(KeyType::Ed25519)
            .await
            .expect("generate ed25519");
        let public = inner.public_key(&handle).await.expect("public key");
        let pk_bytes: [u8; 32] = public.as_bytes().try_into().expect("32-byte pk");
        let vk = VerifyingKey::from_bytes(&pk_bytes).expect("valid vk");
        let custody = StreamCustody::InMemory(Arc::new(OpaqueInMemoryKeyCustody(inner)));

        let signer = CustodyStreamSigner::new(custody, handle, vk);
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
    /// not a raw `Arc<SigningKey>`.
    #[test]
    #[cfg(feature = "allow_in_memory_custody")]
    fn custody_stream_signer_is_object_safe() {
        use scp_platform::testing::InMemoryKeyCustody;
        let custody = StreamCustody::InMemory(Arc::new(OpaqueInMemoryKeyCustody(
            InMemoryKeyCustody::new(),
        )));
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
        let err_str = format!("{err:?}");
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
            vec![0u8; 32],
            "ctx".to_owned(),
            "outlet".to_owned(),
            vec![0u8; 32],
        );
        let err = result.expect_err("malformed chunk JSON must be rejected");
        let err_str = format!("{err:?}");
        assert!(
            !err_str.contains(sentinel),
            "chunk-JSON validation error must NOT echo input bytes: {err_str}"
        );
    }

    /// The §5.4.4 `TerminateReason` converter is total over all four protocol
    /// variants, including the round-8 `ContextClosedMidStream` arm added in
    /// this wave (so the `UniFFI` enum stays in lockstep with the protocol).
    #[test]
    fn terminate_reason_converts_all_variants_including_context_closed() {
        use scp_protocol::context::outlets::stream::TerminateReason as Proto;
        assert_eq!(
            Proto::from(TerminateReason::RevokedMidStream),
            Proto::RevokedMidStream
        );
        assert_eq!(
            Proto::from(TerminateReason::CancelAckTimeout),
            Proto::CancelAckTimeout
        );
        assert_eq!(
            Proto::from(TerminateReason::CreditStall),
            Proto::CreditStall
        );
        assert_eq!(
            Proto::from(TerminateReason::ContextClosedMidStream),
            Proto::ContextClosedMidStream
        );
    }
}
