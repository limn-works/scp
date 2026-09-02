//! `UniFFI` (Swift / Kotlin) bridge for §5.4.5 streaming-native outlet
//! invocation (SCP-OUT-037, sub-chunk C8b).
//!
//! Mirrors the CANONICAL `PyO3` reference bridge
//! (`crates/scp-ffi/src/outlet_stream.rs`, C7) and the native-async NAPI bridge
//! (`crates/scp-ffi/napi/src/outlet_stream.rs`, C8a): same operation names, same
//! semantics, same two CRITICAL invariants. It wraps the runtime control surface
//! [`Supervisor::open_outlet_stream`](scp_core::context::supervisor::Supervisor::open_outlet_stream)
//! and [`StreamSessionHandle`] into six [`Scp`](crate::scp::Scp) methods plus two
//! pure 1:1 wrappers:
//!
//! - [`crate::scp::Scp::outlet_stream_open`] — open a stream (Commit-transition:
//!   returns a `StreamHandleId` PROMPTLY; NEVER blocks until terminal).
//! - [`crate::scp::Scp::outlet_stream_poll_next`] — drain one chunk
//!   (`None` == closed).
//! - [`crate::scp::Scp::outlet_stream_grant_credit`] — apply an invoker-signed
//!   grant.
//! - [`crate::scp::Scp::outlet_stream_cancel`] — sign+apply a cancel at the
//!   runtime-derived cursor.
//! - [`crate::scp::Scp::outlet_stream_terminate`] — force a framework terminal.
//! - [`crate::scp::Scp::outlet_stream_verify_chunk_signature`] /
//!   [`crate::scp::Scp::outlet_stream_compute_caveats_binding`] — pure wrappers.
//!
//! # The `UniFFI` async model
//!
//! `UniFFI` exposes these as `#[uniffi::export(async_runtime = "tokio")]` async
//! methods — so, like NAPI, there is NO `block_on`, NO GIL, and NONE of the
//! `PyO3` reference's `Python::allow_threads` GIL-deadlock machinery. Every
//! method offloads its core onto the dedicated bridge [`crate::runtime()`] pool
//! via `runtime().spawn(...).await` (mirroring every other `UniFFI` outlet op —
//! `outlet_invoke`, the cross-context saga) so the pump the open spawns, and the
//! actor-mailbox reserves the grants dispatch, all run on the SAME runtime the
//! supervisor lives on. The one hazard we DO still guard is holding a `DashMap`
//! shard guard across an `.await`: every control-plane op clones the `Arc`s it
//! needs OUT of the registry guard and drops the guard BEFORE awaiting (the
//! DashMap-ref-across-await hazard — the C8a discipline).
//!
//! # Two CRITICAL invariants enforced here
//!
//! - **CRITICAL #1 (caller == pinned invoker).** `invoker_did` is pinned in the
//!   per-instance [`StreamEntry`] at open. Every control-plane call
//!   (`grant_credit`, `cancel`, `terminate`) rejects a `caller_did` that is not
//!   the pinned invoker with `SCP-PERM-3001` BEFORE touching runtime state.
//! - **CRITICAL #3 (runtime-derived cancel cursor).** The bridge NEVER supplies
//!   a `next_seq`. `outlet_stream_cancel_impl` calls
//!   [`StreamSessionHandle::apply_outlet_cancel_signed`], which reads the
//!   runtime's own live emission cursor and signs the `SCP-OUTLET-CANCEL-V1:`
//!   preimage over it internally — closing the forged-cursor billing surface.
//!
//! # Per-instance, never a global
//!
//! The stream registry is a per-instance field on
//! [`UniffiBridgeInstance`](crate::runtime::UniffiBridgeInstance)
//! (`outlet_stream_registry`), NOT a `static` — `check-no-bridge-globals.sh` /
//! `check-handle-affinity.sh` forbid the alternative. A stream opened on one
//! instance is invisible to another, and instance shutdown drops every live
//! stream with the `Arc`.
//!
//! # Co-resident custody
//!
//! Chunk signatures are produced by the OUTLET OPERATOR's key and cancel /
//! credit signatures by the INVOKER's key. Both are resolved by DID through this
//! bridge instance's identity custody registry (the operator identity + the
//! invoker identity must be locally hosted). This mirrors the co-resident
//! single-tenant constraint of the cross-context saga export in `bridge.rs`.

use std::sync::Arc;

use dashmap::DashMap;
use ed25519_dalek::VerifyingKey;
use scp_platform::KeyHandle;
use scp_platform::error::PlatformError;
use scp_platform::traits::KeyCustody;
use tokio::sync::mpsc;

use scp_core::context::outlets::stream::{
    MlsEpoch, OutletStreamChunk, OutletStreamCredit, TerminateReason, compute_caveats_binding,
    compute_credit_sig_preimage, verify_chunk_signature,
};
use scp_core::context::outlets::{
    AdmissionCaps, CancelIdentity, OpenStreamParams, OpenStreamRejection, OutletExecutor,
    OutletExecutorError, StreamIdentity, StreamSessionHandle, StreamSigner,
    StreamSignerCustodyCategory, StreamSignerError, cancel_error_to_code, grant_error_to_code,
};

use scp_ffi_common::error_codes as codes;
use scp_ffi_common::streaming_saga::{
    StreamingSagaEntry, drive_recover_truncated_close, serialize_saga_chunk,
};
use scp_ffi_common::validate::{
    validate_context_id, validate_did, validate_outlet_id, validate_ucan_token,
};

use crate::ScpError;
use crate::bridge::{
    ContextHandle, UniffiKeyCustody, decode_asserted_nonce, enforce_caller_principal_binding,
    identity_custody_registry, map_saga_error, resolve_uniffi_signing_key,
    validate_outlet_ucan_uniffi,
};
use crate::runtime::UniffiBridgeInstance;
use crate::scp::Scp;

/// Outlet handler function type — identical to `bridge.rs::OutletHandlerMap`'s
/// value type. The single-shot handler an [`OutletExecutor`] wraps.
type OutletHandler =
    Arc<dyn Fn(serde_json::Value) -> Result<serde_json::Value, String> + Send + Sync>;

// ---------------------------------------------------------------------------
// StreamEntry — the per-instance registry value
// ---------------------------------------------------------------------------

/// One live stream tracked in
/// [`UniffiBridgeInstance::outlet_stream_registry`](crate::runtime::UniffiBridgeInstance).
///
/// Splits the control plane (the `handle`) from the data plane (the detached
/// `receiver`) behind INDEPENDENT async locks so a `poll_next` parked in
/// `receiver.recv()` (awaiting the executor's next chunk) never blocks a
/// concurrent `grant_credit` / `cancel` / `terminate` — the grant is exactly
/// what unblocks a credit-stalled executor to PRODUCE that chunk, so serializing
/// the two would deadlock.
pub struct StreamEntry {
    /// Runtime control surface. `tokio::sync::Mutex` because
    /// [`StreamSessionHandle`] is `!Sync` (it structurally holds the
    /// [`mpsc::Receiver`] type even after the value is detached) and the cancel
    /// method is `async` — the mutex is safe to hold across its `.await`, and it
    /// serializes only the (brief) control-plane ops.
    handle: Arc<tokio::sync::Mutex<StreamSessionHandle>>,
    /// Detached chunk receiver (data plane). Independent lock from `handle`.
    receiver: Arc<tokio::sync::Mutex<mpsc::Receiver<OutletStreamChunk>>>,
    /// The invoker DID pinned at open (CRITICAL #1). Every control-plane call
    /// verifies `caller_did == invoker_did`.
    invoker_did: String,
    /// Hosting context id pinned at open (for the [`CancelIdentity`] and the
    /// §5.4.5 `SCP-OUTLET-CREDIT-V1:` grant preimage).
    context_id: String,
    /// Outlet id pinned at open (for the [`CancelIdentity`] and the credit
    /// preimage).
    outlet_id: String,
    /// 32-byte `caveats_binding` pinned at open (for the [`CancelIdentity`] and
    /// the credit preimage).
    caveats_binding: [u8; 32],
    /// The stream's 16-byte `request_id` pinned at open — bound into every
    /// [`OutletStreamCredit`] grant preimage this bridge signs internally.
    request_id: [u8; 16],
    /// The hosting context's MLS epoch captured at open (§6.2.1.1(e)) — the SAME
    /// value pinned in the runtime `StreamIdentity`. Bound into the credit
    /// preimage; the runtime rejects a grant whose epoch disagrees.
    stream_epoch: MlsEpoch,
    /// Per-Data-chunk cost pinned at open — the multiplier for the grant-time
    /// escrow reserve (`cost_per_chunk × grant`). `Amount(0)` for Query /
    /// zero-cost outlets (no top-up).
    cost_per_chunk: scp_core::economy::Amount,
    // NOTE: the §5.4.5 `monotonic_seq` grant counter is NOT held here. It lives
    // exclusively in durable `Storage` under
    // `context/{context_id}/stream_credit_counter/{request_id}` (SCP-OUT-034
    // AC31) so it survives an SDK restart mid-stream and never regresses.
    // `grant_credit` reads/increments/persists it via
    // `ProtocolRepoVariant::next_stream_credit_seq`.
}

// ---------------------------------------------------------------------------
// BridgeCustodyStreamSigner — custody-backed operator/invoker signer
// ---------------------------------------------------------------------------

/// Custody-backed [`StreamSigner`]. The signing key never enters the runtime
/// address space — the 32-byte preimage is signed through the platform
/// [`KeyCustody`] boundary (ADR-006). Used for BOTH the operator chunk signer
/// (pinned into [`OpenStreamParams`] at open) and the invoker cancel/credit
/// signer (resolved at control-plane time). Both are local identities hosted by
/// this bridge instance's identity custody registry.
struct BridgeCustodyStreamSigner {
    /// The custody provider for the signing identity.
    custody: Arc<UniffiKeyCustody>,
    /// The active signing-key handle inside custody.
    handle: KeyHandle,
    /// Cached verifying key (the public half — no secret material).
    verifying_key: VerifyingKey,
}

#[async_trait::async_trait]
impl StreamSigner for BridgeCustodyStreamSigner {
    async fn sign(&self, preimage: &[u8]) -> Result<[u8; 64], StreamSignerError> {
        // Ed25519 over the 32-byte digest verbatim — custody does NOT re-hash
        // the §5.4.5 preimage (it is already the domain-separated digest).
        let sig =
            self.custody
                .sign(&self.handle, preimage)
                .await
                .map_err(|err: PlatformError| {
                    // Never leak key material / preimage / backend handles into
                    // the error — map to the bounded category (ADR-006 / ADR-061).
                    StreamSignerError::Custody {
                        category: StreamSignerCustodyCategory::from(&err),
                    }
                })?;
        <[u8; 64]>::try_from(sig.as_bytes()).map_err(|_| {
            // A well-formed Ed25519 signature is always 64 bytes; a shorter one
            // is a backend invariant violation, not a leakable detail.
            StreamSignerError::Custody {
                category: StreamSignerCustodyCategory::BackendFault,
            }
        })
    }

    fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

/// Resolves a custody-backed [`StreamSigner`] for a locally-hosted identity DID
/// (its Active Signing Key), reading the per-instance identity custody registry
/// (typed over [`UniffiKeyCustody`], so this resolves in BARE production builds
/// over callback custody, not only `testing` builds).
///
/// Clones the custody `Arc` + key handle OUT of the identity-registry shard
/// guard, then performs the (potentially slow) `public_key` export OFF the guard
/// — the same clone-then-drop discipline as
/// [`crate::bridge`]'s `resolve_local_custody_verifying_key`.
async fn resolve_stream_signer(
    bi: &Arc<UniffiBridgeInstance>,
    identity_did: &str,
) -> Result<BridgeCustodyStreamSigner, ScpError> {
    let (custody, handle) = {
        let registry = identity_custody_registry(bi);
        let entry = registry
            .get(identity_did)
            .ok_or_else(|| ScpError::Context {
                msg: format!(
                    "no local identity custody for '{identity_did}' — streaming outlet signing \
                 requires the operator and invoker identities to be hosted by this bridge \
                 instance (co-resident single-tenant constraint)"
                ),
                // Hosted-identity (channel-auth) rejection — SAME code as the NAPI
                // and PyO3 bridges surface for "identity not hosted here"
                // (SCP-OUT-047 pass-3a cross-bridge alignment).
                code: codes::CTX_2001.to_owned(),
            })?;
        let (custody, key_handle) = entry.value();
        (Arc::clone(custody), *key_handle)
    };
    let public_key = custody
        .public_key(&handle)
        .await
        .map_err(|e| ScpError::Context {
            msg: format!("failed to resolve stream signing key for '{identity_did}': {e}"),
            code: codes::CTX_2001.to_owned(),
        })?;
    let verifying_key = scp_ffi_common::export_verify::verifying_key_from_public_key(&public_key)
        .ok_or_else(|| ScpError::Context {
        msg: format!(
            "identity '{identity_did}' active signing key is not a valid Ed25519 verifying key"
        ),
        code: codes::CTX_2001.to_owned(),
    })?;
    Ok(BridgeCustodyStreamSigner {
        custody,
        handle,
        verifying_key,
    })
}

// ---------------------------------------------------------------------------
// UniffiStreamRevocationChecker — LIVE per-context revocation view
// ---------------------------------------------------------------------------

/// [`RevocationChecker`](scp_core::crypto::ucan::validate::RevocationChecker)
/// giving the runtime pump a LIVE view of this instance's per-context revocation
/// list, so the §5.4.5 authoritative UCAN-revocation re-check timer
/// (`stream_ucan_recheck_secs`) observes revocations that land AFTER the stream
/// opened — not a stale open-time snapshot.
///
/// Holds an `Arc` clone of the per-instance UCAN-state registry and the hosting
/// context id; `is_revoked` does a brief (sync, no-`await`) `DashMap` lookup per
/// tick. A vanished context returns `false` — the separate
/// context-closed-mid-stream termination path handles substrate loss.
struct UniffiStreamRevocationChecker {
    states: Arc<DashMap<String, crate::runtime::UcanContextState>>,
    context_id: String,
}

impl scp_core::crypto::ucan::validate::RevocationChecker for UniffiStreamRevocationChecker {
    fn is_revoked(&self, token_cid: &str) -> bool {
        self.states
            .get(&self.context_id)
            .is_some_and(|state| state.revocation_list.is_revoked(token_cid))
    }
}

// ---------------------------------------------------------------------------
// UniffiStreamExecutor — adapts the registered single-shot handler
// ---------------------------------------------------------------------------

/// [`OutletExecutor`] wrapping the context's registered outlet handler (an
/// `Arc<dyn Fn(Value) -> Result<Value, String>>`) — identical dispatch semantics
/// to the non-streaming `outlet_invoke` executor.
///
/// The handler is single-shot: it returns one aggregate value. The default
/// `exec_*_stream` trait methods turn that into a degenerate one-`Data`-chunk
/// stream, and the framework appends the terminal `End`. When no handler is
/// registered, the executor echoes validated metadata (matching
/// `outlet_invoke`'s schema-only fallback).
struct UniffiStreamExecutor {
    handler: Option<OutletHandler>,
    outlet_id: String,
    context_id: String,
    invoker_did: String,
}

impl UniffiStreamExecutor {
    fn run(&self, input: serde_json::Value) -> Result<serde_json::Value, OutletExecutorError> {
        match &self.handler {
            Some(handler) => handler(input).map_err(OutletExecutorError::Failed),
            None => Ok(serde_json::json!({
                "outlet": self.outlet_id,
                "context": self.context_id,
                "status": "validated",
                "input_valid": true,
                "invoker_did": self.invoker_did,
                "validated_input": input,
            })),
        }
    }
}

#[async_trait::async_trait]
impl OutletExecutor for UniffiStreamExecutor {
    async fn exec_query(
        &self,
        _ctx: &scp_core::context::outlets::ReadOnlyInvocation<'_>,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, OutletExecutorError> {
        self.run(input)
    }

    async fn exec_action(
        &self,
        _ctx: &mut scp_core::context::outlets::MutableInvocation<'_>,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, OutletExecutorError> {
        self.run(input)
    }
}

// ---------------------------------------------------------------------------
// Error mapping — every code is a canonical SCP-OUTLET-/SCP-PERM- literal
// ---------------------------------------------------------------------------

/// Maps an [`OpenStreamRejection`] onto the bridge error surface, carrying the
/// rejection's own §5.4.4 `SCP-OUTLET-NNNN` code verbatim.
fn open_rejection_to_err(rejection: &OpenStreamRejection) -> ScpError {
    ScpError::Outlet {
        msg: format!(
            "outlet stream open rejected ({}): {}",
            rejection.error_code(),
            rejection.slug()
        ),
        code: rejection.error_code().to_owned(),
    }
}

/// The `SCP-PERM-3001` rejection for a control-plane call whose `caller_did` is
/// not the invoker pinned at open (CRITICAL #1).
fn caller_not_invoker_err(caller_did: &str, invoker_did: &str) -> ScpError {
    ScpError::Permission {
        msg: format!(
            "caller '{caller_did}' is not the invoker '{invoker_did}' pinned at stream open — \
             only the opening invoker may steer the stream (§5.4.5 CRITICAL #1)"
        ),
        code: codes::PERM_3001.to_owned(),
    }
}

/// The control-plane "no active outlet stream" rejection for an unknown, stale,
/// typo'd, or already-evicted `handle_id`. Shared by every control-plane lookup
/// AND by [`outlet_stream_poll_next_impl`] so a bad handle is a DISTINCT error
/// from a genuine terminal (which `poll_next` reports as `None`) — conflating the
/// two would let a caller mistake a typo for a clean stream end.
fn no_active_stream_err(handle_id: &str) -> ScpError {
    ScpError::Context {
        msg: format!("no active outlet stream '{handle_id}'"),
        code: codes::CTX_2001.to_owned(),
    }
}

/// Shared control handle for a live stream (the runtime control surface behind
/// its own async lock).
type ControlHandle = Arc<tokio::sync::Mutex<StreamSessionHandle>>;

/// Looks up a live stream, verifies the caller is the pinned invoker (CRITICAL
/// #1), and clones the `Arc`s + pinned identity OUT of the `DashMap` shard guard
/// so no reference is held across the subsequent `.await` (the
/// DashMap-ref-across-await hazard).
fn authorized_control(
    bi: &Arc<UniffiBridgeInstance>,
    handle_id: &str,
    caller_did: &str,
) -> Result<(ControlHandle, String, String, [u8; 32]), ScpError> {
    let entry = bi
        .outlet_stream_registry
        .get(handle_id)
        .ok_or_else(|| no_active_stream_err(handle_id))?;
    if caller_did != entry.invoker_did {
        return Err(caller_not_invoker_err(caller_did, &entry.invoker_did));
    }
    Ok((
        Arc::clone(&entry.handle),
        entry.context_id.clone(),
        entry.outlet_id.clone(),
        entry.caveats_binding,
    ))
}

// ---------------------------------------------------------------------------
// Open — outlet_stream_open_impl
// ---------------------------------------------------------------------------

/// §5.4.5 streaming outlet open. Validates the UCAN at the bridge (mirroring
/// `outlet_invoke`), reserves+spawns the pump via
/// [`Supervisor::open_outlet_stream`](scp_core::context::supervisor::Supervisor::open_outlet_stream),
/// and stores the returned handle in the per-instance registry keyed by the
/// stream's `request_id` (hex). Returns the `StreamHandleId` PROMPTLY — the open
/// is the Commit transition, NOT a block-until-terminal.
///
/// Reads the outlet registry + handler directly off the owned, instance-affine
/// [`ContextHandle`] (the `UniFFI` bridge holds them per-context on the handle,
/// exactly as `outlet_invoke` does — NOT via a runtime `with_context` snapshot).
#[allow(clippy::too_many_arguments)] // Flat §5.4.5 open envelope — agent-first named params.
#[allow(clippy::too_many_lines)] // UCAN validate + caveat binding + full OpenStreamParams build.
pub(crate) async fn outlet_stream_open_impl(
    bi: &Arc<UniffiBridgeInstance>,
    handle: &ContextHandle,
    outlet_id: String,
    input_json: String,
    caller_did: String,
    ucan_token: String,
    proof_tokens: Option<Vec<String>>,
    spending_ucan: Option<String>,
    timeout_ms: Option<u32>,
    estimated_chunk_count: Option<u32>,
) -> Result<String, ScpError> {
    validate_outlet_id(&outlet_id)?;
    validate_did(&caller_did)?;
    validate_ucan_token(&ucan_token)?;
    if let Some(ref jwt) = spending_ucan {
        validate_ucan_token(jwt)?;
    }
    if let Some(ref tokens) = proof_tokens {
        for t in tokens {
            validate_ucan_token(t)?;
        }
    }

    let context_id = handle.context_id.clone();

    let input_value: serde_json::Value =
        serde_json::from_str(&input_json).map_err(|e| ScpError::Outlet {
            msg: format!("invalid input JSON: {e}"),
            code: codes::OUTLET_6002.to_owned(),
        })?;

    // Snapshot the bridge-owned per-handle outlet registry once (cheap Vec of
    // registrations); every subsequent outlet field is read off this clone, so
    // the handle's `outlet_registry` mutex is released before the runtime call.
    let registry = { handle.outlet_registry.lock().await.clone() };
    let registration = registry.get(&outlet_id).ok_or_else(|| ScpError::Outlet {
        msg: format!("outlet '{outlet_id}' not registered in context '{context_id}'"),
        code: codes::OUTLET_6002.to_owned(),
    })?;
    // §5.4.2: caller-supplied semantic class selects the invocation capability
    // stem (`outlet_query:` vs `outlet_call:`).
    let outlet_kind = registration.kind;
    // Cost per Data chunk from the outlet's registered cost (§5.4.1). `Amount(0)`
    // for Query / zero-cost outlets. The reserve/settle economy is the manager's
    // concern; `available_balance` / `reserved_escrow` are NOT consulted on the
    // production open path.
    let cost_per_chunk = registration
        .cost
        .as_ref()
        .map_or(scp_core::economy::Amount::new(0), |c| c.amount);
    // The OPERATOR signs every chunk that crosses the outer wire.
    let operator_did = registration.operator_did.0.clone();

    // Primary authorization: the full 11-step ADR-016 UCAN pipeline over the
    // bridge-owned per-context UCAN state — IDENTICAL to `outlet_invoke`. The
    // stream is validated ONCE at open (§5.4.5 "UCAN check locus"); chunks do not
    // re-present.
    crate::bridge::validate_outlet_ucan_uniffi(
        bi,
        handle,
        &outlet_id,
        outlet_kind,
        &ucan_token,
        &caller_did,
        proof_tokens.as_ref(),
    )
    .await?;

    // §7.3.8 effective-caveat resolution from the VALIDATED invocation UCAN's
    // narrowed `nb` — mirrors `outlet_invoke`. `ucan_cid` keys the owned Class-S
    // counters and anchors the §5.4.5 caveats binding.
    let invocation_ucan =
        scp_core::crypto::ucan::validate::parse_ucan(&ucan_token).map_err(|e| {
            ScpError::Permission {
                msg: format!("invalid invocation UCAN for '{outlet_id}': {e}"),
                code: codes::PERM_3001.to_owned(),
            }
        })?;
    let ucan_cid = scp_core::crypto::ucan::revoke::compute_revocation_cid(&invocation_ucan.encoded);
    let caveats = {
        use scp_core::crypto::ucan::validate::CaveatResolver as _;
        scp_core::crypto::ucan::validate::TokenNbCaveatResolver
            .resolve_caveats(&invocation_ucan)
            .unwrap_or_else(scp_core::trust::caveats::InvocationCaveats::empty)
    };
    let has_caveats = caveats != scp_core::trust::caveats::InvocationCaveats::empty();

    // §5.4.5 caveats binding. The runtime RECOMPUTES this at open from
    // `(ucan_cid, request_id, invoker_did, declared_estimate.unwrap_or(0),
    // JCS(caveats))` and rejects a mismatch — so every input MUST agree with what
    // we pin here (dispatch.rs `verify_caveats_binding_at_open`).
    let request_id: [u8; 16] = *uuid::Uuid::now_v7().as_bytes();
    let caveats_jcs = caveats
        .to_canonical_json_bytes()
        .map_err(|e| ScpError::Context {
            msg: format!("failed to canonicalize effective caveats: {e}"),
            code: codes::CTX_2001.to_owned(),
        })?;
    let caveats_binding = compute_caveats_binding(
        ucan_cid.as_bytes(),
        &request_id,
        &caller_did,
        estimated_chunk_count.unwrap_or(0),
        &caveats_jcs,
    );

    // Resolve the operator (chunk signer) + invoker (grant/cancel verifier) keys
    // through custody. Both must be co-resident local identities.
    let operator_signer: Arc<dyn StreamSigner> =
        Arc::new(resolve_stream_signer(bi, &operator_did).await?);
    let invoker_pk = *resolve_stream_signer(bi, &caller_did)
        .await?
        .verifying_key();

    // Snapshot the registered handler (an `Arc<dyn Fn>` — cloning is a refcount
    // bump) off the owned handle.
    let handler = { handle.outlet_handlers.lock().await.get(&outlet_id).cloned() };

    // Clone the supervisor `Arc` out of the borrow so it outlives the later
    // `bi`-borrowing calls and the `'static` executor.
    let supervisor = Arc::clone(bi.context_manager_or_error()?);
    let stream_epoch = supervisor.local_mls_epoch(&context_id).await.unwrap_or(0);

    let executor: Arc<dyn OutletExecutor> = Arc::new(UniffiStreamExecutor {
        handler,
        outlet_id: outlet_id.clone(),
        context_id: context_id.clone(),
        invoker_did: caller_did.clone(),
    });

    // LIVE revocation view for the runtime's authoritative re-check timer.
    let revocation_checker: Arc<
        dyn scp_core::crypto::ucan::validate::RevocationChecker + Send + Sync,
    > = Arc::new(UniffiStreamRevocationChecker {
        states: Arc::clone(bi.ucan_registry()),
        context_id: context_id.clone(),
    });

    let identity = StreamIdentity {
        context_id: context_id.clone(),
        outlet_id: outlet_id.clone(),
        stream_epoch,
        caveats_binding,
    };

    // The caps + the four timing/window policy fields are SERVER POLICY: the
    // orchestrator OVERWRITES them from the hosting context's `ContextParams`
    // (§5.4.5 / SCP-OUT-034), so the values supplied here are placeholders the
    // runtime discards. We pass conservative zero/one sentinels.
    let params = OpenStreamParams {
        identity,
        caps: AdmissionCaps {
            per_invoker: 0,
            per_origin_invoker: 0,
            per_outlet: 0,
        },
        invoker_did: caller_did.clone(),
        // Direct (non-cross-context) open: the immediate invoker IS the origin
        // invoker. Cross-context stream forwarding is separate future work.
        origin_invoker_did: caller_did.clone(),
        cost_per_chunk,
        available_balance: scp_core::economy::Amount::new(0),
        reserved_escrow: scp_core::economy::Amount::new(0),
        declared_estimated_chunk_count: estimated_chunk_count,
        credit_window: 0,
        caveats: caveats.clone(),
        invoker_pk,
        operator_signer,
        stream_credit_stall_secs: 0,
        stream_cancel_ack_secs: 0,
        stream_ucan_recheck_secs: 0,
        ucan_cid: ucan_cid.clone(),
        request_id,
        revocation_checker,
        economic_policy_snapshot: None,
    };

    // The §7.3.8 value-caveat binding drives the post-input hook + counter
    // reservation. `None` when the token narrows to nothing.
    let value_caveat_binding = if has_caveats {
        Some(scp_core::context::outlets::InvocationCaveatBinding { caveats, ucan_cid })
    } else {
        None
    };

    let outlet_id_typed: scp_core::context::outlets::OutletId = outlet_id.clone();
    let invoker_did_typed: scp_did::DID = caller_did.clone().into();
    let mut stream_handle = supervisor
        .open_outlet_stream(
            &context_id,
            &registry,
            &outlet_id_typed,
            input_value,
            &invoker_did_typed,
            timeout_ms,
            executor,
            None,
            None,
            None,
            value_caveat_binding,
            params,
        )
        .await
        .map_err(|rejection| open_rejection_to_err(&rejection))?;

    // Detach the receiver (data plane) into its own lock so `poll_next` never
    // contends with the control plane.
    //
    // INVARIANT: `open_outlet_stream` always returns a fresh handle whose
    // receiver has NOT yet been taken (`StreamSessionHandle::receiver` is
    // `self.receiver.take()`, called exactly once — here — per handle), so this
    // is `Some` on the happy path. The `None` arm is therefore UNREACHABLE under
    // the runtime's postcondition; it exists purely as a fund-safety backstop.
    // `receiver()` is the ONLY fallible step AFTER the irreversible reserve+spawn,
    // so a bare `?` here would strand a spawned, ALREADY-BILLING pump with no
    // registry entry. Instead we force the pump to a terminal (which releases its
    // escrow via the pump's close-time settlement) before surfacing the error.
    let Some(receiver) = stream_handle.receiver() else {
        let _ = stream_handle.terminate_with_error(TerminateReason::ContextClosedMidStream, None);
        return Err(ScpError::Context {
            msg: "stream handle returned without a chunk receiver (runtime invariant \
                  violation) — pump terminated to release escrow"
                .to_owned(),
            code: codes::CTX_2001.to_owned(),
        });
    };

    let handle_id = hex::encode(request_id);
    bi.outlet_stream_registry.insert(
        handle_id.clone(),
        StreamEntry {
            handle: Arc::new(tokio::sync::Mutex::new(stream_handle)),
            receiver: Arc::new(tokio::sync::Mutex::new(receiver)),
            invoker_did: caller_did,
            context_id,
            outlet_id,
            caveats_binding,
            request_id,
            stream_epoch,
            cost_per_chunk,
        },
    );
    Ok(handle_id)
}

// ---------------------------------------------------------------------------
// poll_next
// ---------------------------------------------------------------------------

/// Drains one chunk from a live stream, awaiting the pump until a chunk arrives
/// or the stream closes. Returns the JSON-serialized [`OutletStreamChunk`] bytes,
/// or `None` at the channel-closed sentinel. This is the primitive the Swift /
/// Kotlin SDK's async iterator wraps.
///
/// # Async model (no GIL)
///
/// `UniFFI` bridges this to a Swift/Kotlin async call on the tokio runtime —
/// there is no GIL, so the `PyO3` reference's `allow_threads` deadlock does not
/// apply. The one hazard we DO guard: the receiver `Arc` is cloned OUT of the
/// `DashMap` shard guard and the guard is DROPPED before `recv().await`, so no
/// shard lock is held across the `.await` (the DashMap-ref-across-await hazard).
///
/// # Handle lifecycle
///
/// - **Unknown / evicted `handle_id`** → a DISTINCT [`no_active_stream_err`],
///   NEVER `None` — a stale or typo'd handle must not masquerade as a clean
///   terminal.
/// - **Terminal chunk** (`End` / `Error{terminal:true}`) → returned to the caller
///   AND the entry is EVICTED immediately, so a caller that reads to terminal but
///   never performs the trailing `None`-drain does not leak the registry entry.
/// - **`None`** (channel closed with no terminal chunk — an abnormal close such
///   as a pump panic dropping the sender) → the entry is evicted and `None` is
///   returned as the terminal sentinel.
pub(crate) async fn outlet_stream_poll_next_impl(
    bi: &Arc<UniffiBridgeInstance>,
    handle_id: &str,
) -> Result<Option<Vec<u8>>, ScpError> {
    // Clone the receiver `Arc` OUT of the DashMap shard guard BEFORE awaiting recv
    // — never hold a DashMap ref across the `.await`. An unknown handle is a
    // distinct error, not a terminal.
    let receiver = {
        let Some(entry) = bi.outlet_stream_registry.get(handle_id) else {
            return Err(no_active_stream_err(handle_id));
        };
        Arc::clone(&entry.receiver)
    };
    let chunk = receiver.lock().await.recv().await;
    if let Some(chunk) = chunk {
        // Evict on the TERMINAL chunk so a run-to-terminal-without-draining caller
        // cannot leak the entry. The pump releases the admission counter + escrow
        // at the same terminal, so eviction here only reclaims the bridge-side
        // registry slot.
        if chunk.payload.is_terminal() {
            bi.outlet_stream_registry.remove(handle_id);
        }
        let bytes = serde_json::to_vec(&chunk).map_err(|e| ScpError::Context {
            msg: format!("failed to serialize stream chunk: {e}"),
            code: codes::CTX_2001.to_owned(),
        })?;
        Ok(Some(bytes))
    } else {
        // Abnormal terminal: the pump dropped the sender without a terminal chunk.
        // Evict so the handle + any residual control state drop with the entry.
        bi.outlet_stream_registry.remove(handle_id);
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// grant_credit
// ---------------------------------------------------------------------------

/// Grants `grant` additional billable chunks of credit to a live stream. The
/// bridge SIGNS the [`OutletStreamCredit`] INTERNALLY under the pinned invoker's
/// custody key (mirroring how `cancel` signs internally) and auto-assigns the
/// §5.4.5 `monotonic_seq` from a DURABLE per-stream cursor — so no SDK ever
/// needs the invoker key (ADR-006) or a caller-tracked replay counter, and the
/// public surface is a plain `u32`.
///
/// CRITICAL #1: rejects a `caller_did` that is not the pinned invoker with
/// `SCP-PERM-3001` before touching runtime state.
///
/// # Crash-safe `monotonic_seq` (SCP-OUT-034 AC31)
///
/// The seq is sourced from durable `Storage` under
/// `context/{context_id}/stream_credit_counter/{request_id}` via
/// [`ProtocolRepoVariant::next_stream_credit_seq`](scp_ffi_common::bridge_runtime::ProtocolRepoVariant::next_stream_credit_seq),
/// NOT an in-memory counter: read the cursor, persist `+1` before signing, use
/// the pre-increment value. An SDK restart mid-stream reloads the persisted
/// cursor, so a resumed grant's seq is strictly greater than any prior in-flight
/// value and the runtime `CreditTracker` never rejects it as `CreditReplay`. The
/// read-modify-write and the grant apply run under the SAME per-stream control
/// lock, so concurrent self-grants receive strictly-ordered seqs.
///
/// # Escrow / money-conservation
///
/// A grant EXTENDS the billable credit window, so it MUST be backed by a
/// corresponding escrow debit or the operator could bill beyond debited funds.
/// This routes through the runtime reserve/apply/reverse discipline:
///
/// 1. `Supervisor::outlet_stream_reserve_grant` DEBITS `cost_per_chunk × grant`
///    from the invoker's member budget (`InsufficientFunds` / `EscrowOverflow`
///    reject BEFORE any credit is applied).
/// 2. `apply_credit_grant(credit, reserved)` extends the pump's escrow ledger by
///    exactly the debited hold.
/// 3. On ANY apply rejection the debited hold is REVERSED via
///    `outlet_stream_reverse_grant`.
///
/// So `billed + refund == reserved` holds across open + every grant. The
/// fund-safety BACKSTOP that no quantity of grants can over-bill is the invoker's
/// CAVEAT CEILING — the §5.4.5 cumulative billable ceiling
/// `min(credit_window, max_calls)` pinned in the pump's `CreditTracker`
/// (`max_billable`), which clamps every replenishment.
pub(crate) async fn outlet_stream_grant_credit_impl(
    bi: &Arc<UniffiBridgeInstance>,
    handle_id: &str,
    caller_did: &str,
    grant: u32,
) -> Result<(), ScpError> {
    validate_did(caller_did)?;

    // Look up the live stream, verify caller == pinned invoker (CRITICAL #1), and
    // copy/clone every pinned field the credit preimage + reserve need OUT of the
    // DashMap shard guard so no ref is held across the `.await`. The
    // `monotonic_seq` is NOT assigned here — it comes from the durable per-stream
    // cursor below (SCP-OUT-034 AC31).
    let (handle, context_id, outlet_id, caveats_binding, request_id, stream_epoch, cost_per_chunk) = {
        let entry = bi
            .outlet_stream_registry
            .get(handle_id)
            .ok_or_else(|| no_active_stream_err(handle_id))?;
        if caller_did != entry.invoker_did {
            return Err(caller_not_invoker_err(caller_did, &entry.invoker_did));
        }
        (
            Arc::clone(&entry.handle),
            entry.context_id.clone(),
            entry.outlet_id.clone(),
            entry.caveats_binding,
            entry.request_id,
            entry.stream_epoch,
            entry.cost_per_chunk,
        )
    };

    // Resolve the invoker's custody-backed signer (the key never enters the
    // runtime address space — ADR-006). Done off the DashMap ref.
    let signer = resolve_stream_signer(bi, caller_did).await?;

    let supervisor = Arc::clone(bi.context_manager_or_error()?);
    let invoker_did_typed: scp_did::DID = caller_did.to_owned().into();

    // Hold the per-stream control lock across the WHOLE grant — the durable seq
    // read-modify-write, the sign, the reserve, and the apply. This serializes
    // seq-assign with apply so two concurrent self-grants receive
    // strictly-ordered seqs; the data plane uses the SEPARATE `receiver` lock, so
    // a `poll_next` parked awaiting a chunk is never blocked by this hold.
    let handle_guard = handle.lock().await;

    // 0. Crash-safe `monotonic_seq` (SCP-OUT-034 AC31): read the durable
    //    per-stream cursor on this instance's `Storage` backend, persist `+1`
    //    BEFORE signing, and use the pre-increment value. An SDK restart
    //    mid-stream reloads the persisted cursor, so a resumed grant's seq never
    //    regresses below any prior in-flight value and the runtime
    //    `CreditTracker` never rejects it as `CreditReplay`.
    let monotonic_seq = bi
        .protocol_repository
        .next_stream_credit_seq(&context_id, &request_id)
        .await
        .map_err(|e| ScpError::Context {
            msg: format!("failed to assign durable monotonic_seq: {e}"),
            code: codes::CTX_2001.to_owned(),
        })?;

    // §5.4.5 SCP-OUTLET-CREDIT-V1 preimage over the pinned stream identity (now
    // that the durable seq is known).
    let preimage = compute_credit_sig_preimage(
        &context_id,
        &outlet_id,
        &request_id,
        grant,
        monotonic_seq,
        stream_epoch,
        &caveats_binding,
    );

    // 1. Sign the credit grant through custody.
    let sig = signer
        .sign(&preimage)
        .await
        .map_err(|e| ScpError::Context {
            msg: format!("failed to sign credit grant: {e:?}"),
            code: codes::CTX_2001.to_owned(),
        })?;
    let credit = OutletStreamCredit {
        request_id,
        grant,
        monotonic_seq,
        sig,
    };

    // 2. Reserve (DEBIT) the incremental escrow BEFORE extending credit. A reject
    //    here (InsufficientFunds / EscrowOverflow) leaves the credit window
    //    unchanged — no billing authorized.
    let reserved = supervisor
        .outlet_stream_reserve_grant(
            &context_id,
            &invoker_did_typed,
            request_id,
            cost_per_chunk,
            grant,
        )
        .await
        .map_err(ScpError::from)?;

    // 3. Apply the signed grant against the debited hold. On rejection, REVERSE
    //    the reserve (CREDIT budget + un-bump the durable record, atomically) so
    //    the debit is not stranded (money-conservation). A `reverse_err` is
    //    logged-and-swallowed (the original grant error is the caller-facing
    //    outcome); the reverse is applied IN MEMORY regardless of the persist
    //    outcome (`commit_class_s_keep`), so the credit is never lost.
    //    Applied under the already-held `handle_guard` — never re-lock `handle`
    //    (the tokio `Mutex` is not reentrant, so a second `handle.lock().await`
    //    would deadlock).
    let apply = handle_guard.apply_credit_grant(&credit, reserved);
    match apply {
        Ok(_new_total) => Ok(()),
        Err(grant_err) => {
            if let Err(reverse_err) = supervisor
                .outlet_stream_reverse_grant(&context_id, &invoker_did_typed, request_id, reserved)
                .await
            {
                tracing::warn!(
                    handle_id = %handle_id,
                    %reverse_err,
                    "outlet_stream_grant_credit: grant apply rejected AND the escrow reverse \
                     failed — reverse applied in memory (run loop retries the persist); an Err \
                     here means the context has no live actor (being torn down), so its budget \
                     + crash-recovery record are moot"
                );
            }
            Err(ScpError::Outlet {
                msg: format!("credit grant rejected: {grant_err:?}"),
                code: grant_error_to_code(grant_err).to_owned(),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// cancel
// ---------------------------------------------------------------------------

/// Signs and applies a stream cancel at the RUNTIME-DERIVED cursor. CRITICAL #1
/// (caller == invoker) + CRITICAL #3 (no caller `next_seq`): the runtime reads
/// its own live emission cursor and signs the `SCP-OUTLET-CANCEL-V1:` preimage
/// internally. The cancel signer is the INVOKER's custody key (the runtime
/// self-verifies the signature under the pinned `invoker_pk`).
pub(crate) async fn outlet_stream_cancel_impl(
    bi: &Arc<UniffiBridgeInstance>,
    handle_id: &str,
    caller_did: &str,
) -> Result<(), ScpError> {
    validate_did(caller_did)?;
    let (handle, context_id, outlet_id, caveats_binding) =
        authorized_control(bi, handle_id, caller_did)?;
    let signer = resolve_stream_signer(bi, caller_did).await?;
    let cancel_identity = CancelIdentity {
        context_id,
        outlet_id,
        caveats_binding,
    };
    handle
        .lock()
        .await
        .apply_outlet_cancel_signed(&signer, &cancel_identity)
        .await
        .map_err(|e| ScpError::Outlet {
            msg: format!("stream cancel rejected: {e:?}"),
            code: cancel_error_to_code(&e).to_owned(),
        })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// terminate
// ---------------------------------------------------------------------------

/// Forces a framework terminal chunk under the pinned operator key. CRITICAL #1:
/// caller must be the pinned invoker. The `slug` selects a closed-set
/// [`TerminateReason`] (free-form slugs are rejected — attacker input cannot
/// enter the provenance record); `message` is a non-canonical human suffix.
///
/// The canonical `code` is DERIVED internally from the reason
/// ([`TerminateReason::code`]) — it is a pure function of `slug`, so accepting it
/// as a parameter only created a way for a caller to disagree with the reason.
/// Dropping it makes the code unforgeable-by-construction and the signature
/// agent-authable from `slug` alone.
///
/// # Auth asymmetry (co-resident threat model)
///
/// `terminate` authorizes on the CRITICAL #1 assertion ALONE, whereas
/// `grant_credit` carries an invoker Ed25519 signature and `cancel` self-verifies
/// a custody-produced signature. `terminate` needs no signature because the
/// terminal chunk it forces is signed by the OPERATOR key, not attributed to the
/// invoker, and it can only ever CLOSE the stream. Under the co-resident
/// single-tenant constraint the assertion gate is sufficient. The asymmetry is
/// intentional, not an oversight.
pub(crate) async fn outlet_stream_terminate_impl(
    bi: &Arc<UniffiBridgeInstance>,
    handle_id: &str,
    caller_did: &str,
    slug: &str,
    message: &str,
) -> Result<(), ScpError> {
    validate_did(caller_did)?;
    let reason = TerminateReason::from_slug(slug).ok_or_else(|| ScpError::Validation {
        msg: format!("unknown terminate slug '{slug}' — must be a §5.4.4 stream-terminal slug"),
        code: codes::VALID_7001.to_owned(),
    })?;
    let (handle, _ctx, _outlet, _binding) = authorized_control(bi, handle_id, caller_did)?;
    let message_override = (!message.is_empty()).then(|| message.to_owned());
    // `AlreadyPending` / `AlreadyTerminated` are the documented idempotent
    // outcomes (the SDK treats them as "stream already closing") — surface both as
    // success so a receiver-side recheck loop stops cleanly.
    let _ = handle
        .lock()
        .await
        .terminate_with_error(reason, message_override);
    Ok(())
}

// ---------------------------------------------------------------------------
// Pure protocol wrappers (1:1)
// ---------------------------------------------------------------------------

/// Verifies a chunk's operator signature (pure; §5.4.5). `chunk_bytes` is the
/// JSON-serialized [`OutletStreamChunk`]; `operator_pk` / `caveats_binding` are
/// 32-byte values.
pub(crate) fn outlet_stream_verify_chunk_signature_impl(
    chunk_bytes: &[u8],
    operator_pk: &[u8],
    context_id: &str,
    outlet_id: &str,
    caveats_binding: &[u8],
) -> Result<bool, ScpError> {
    let chunk: OutletStreamChunk =
        serde_json::from_slice(chunk_bytes).map_err(|e| ScpError::Validation {
            msg: format!("invalid OutletStreamChunk bytes: {e}"),
            code: codes::VALID_7001.to_owned(),
        })?;
    let pk_bytes = <[u8; 32]>::try_from(operator_pk).map_err(|_| ScpError::Validation {
        msg: "operator_pk must be 32 bytes".to_owned(),
        code: codes::VALID_7001.to_owned(),
    })?;
    let operator_verifying_key =
        VerifyingKey::from_bytes(&pk_bytes).map_err(|e| ScpError::Validation {
            msg: format!("operator_pk is not a valid key: {e}"),
            code: codes::VALID_7001.to_owned(),
        })?;
    let binding = <[u8; 32]>::try_from(caveats_binding).map_err(|_| ScpError::Validation {
        msg: "caveats_binding must be 32 bytes".to_owned(),
        code: codes::VALID_7001.to_owned(),
    })?;
    Ok(verify_chunk_signature(
        &chunk,
        &operator_verifying_key,
        context_id,
        outlet_id,
        &binding,
    ))
}

/// Computes the §5.4.5 `caveats_binding` (pure 1:1 wrapper). `request_id` is 16
/// bytes; `effective_caveats_jcs` is the RFC 8785 JCS of the effective caveats.
/// Returns the 32-byte binding.
pub(crate) fn outlet_stream_compute_caveats_binding_impl(
    ucan_cid: &[u8],
    request_id: &[u8],
    invoker_did: &str,
    estimated_chunk_count: u32,
    effective_caveats_jcs: &[u8],
) -> Result<Vec<u8>, ScpError> {
    let request_id = <[u8; 16]>::try_from(request_id).map_err(|_| ScpError::Validation {
        msg: "request_id must be 16 bytes".to_owned(),
        code: codes::VALID_7001.to_owned(),
    })?;
    let binding = compute_caveats_binding(
        ucan_cid,
        &request_id,
        invoker_did,
        estimated_chunk_count,
        effective_caveats_jcs,
    );
    Ok(binding.to_vec())
}

// ---------------------------------------------------------------------------
// Cross-context streaming saga (§5.4.5, §6.2.4, SCP-OUT-047) — open / poll /
// recover. The streaming ANALOG of the unary cross-context saga export in
// `bridge.rs`, sharing its `enforce_caller_principal_binding`,
// `resolve_uniffi_signing_key`, `validate_outlet_ucan_uniffi`, `map_saga_error`,
// and `decode_asserted_nonce` verbatim, and the SAME `UniffiStreamExecutor` /
// `resolve_stream_signer` / `UniffiStreamRevocationChecker` this module already
// defines. Mirrors the CANONICAL `PyO3` reference bridge's cross-context
// section.
//
// Like the `UniFFI` unary cross-context saga (and the 037 same-context open)
// this is HANDLE-based: the caller/target contexts cross the FFI boundary as
// instance-affine `ContextHandle`s (NOT context-id strings, as in the
// string-based `PyO3` bridge — the target's outlet registry lives ONLY on its
// handle here) so `check_handle` enforces handle affinity. The logical param
// order matches the reference: caller ctx, target ctx, caller_did, outlet,
// input, nonce, timestamp, chain_depth, ucan, proofs, proof_id, timeout,
// estimated_chunk_count.
// ---------------------------------------------------------------------------

/// The control-plane "no active cross-context streaming saga" rejection for an
/// unknown, stale, typo'd, or already-evicted saga id. DISTINCT from a genuine
/// terminal (which `poll_next` reports as `None`).
fn no_active_saga_err(saga_id: &str) -> ScpError {
    ScpError::Context {
        msg: format!("no active cross-context streaming saga '{saga_id}'"),
        code: codes::CTX_2001.to_owned(),
    }
}

/// Resolves the TARGET context's raw Ed25519 Active Signing Key from a
/// context-id STRING (the streaming-saga RECOVER path has no `ContextHandle`,
/// only the `target_context_id` pinned in the registry entry). Reads the
/// context creator DID off the supervisor actor, then exports that identity's
/// Active Signing Key from this instance's identity custody registry
/// (co-resident single-tenant). The key never enters the runtime autonomously
/// (ADR-006) — it is resolved per-call here and passed to the seal.
///
/// The creator DID comes from the actor rather than from the per-context UCAN
/// state, because this call chooses the authority a streaming saga signs as. An
/// `AdminTransferred` governance action moves that authority, and the UCAN
/// state's copy would keep signing as the previous holder.
async fn resolve_context_active_signing_key_by_id(
    bi: &Arc<UniffiBridgeInstance>,
    context_id: &str,
) -> Result<ed25519_dalek::SigningKey, ScpError> {
    let creator_did = bi.live_role_state(context_id).await?.creator_did;
    let (custody, key_handle) = {
        let registry = identity_custody_registry(bi);
        let entry = registry.get(&creator_did).ok_or_else(|| ScpError::Context {
            msg: format!(
                "no local identity custody for context creator '{creator_did}' — streaming-saga \
                 reconnect recovery requires the target context's creator identity to be hosted by \
                 this bridge instance (co-resident single-tenant constraint)"
            ),
            // Hosted-identity (channel-auth) rejection — SAME code the NAPI and
            // PyO3 bridges surface (SCP-OUT-047 pass-3a cross-bridge alignment).
            code: codes::CTX_2001.to_owned(),
        })?;
        let (custody, key_handle) = entry.value();
        (Arc::clone(custody), *key_handle)
    };
    custody
        .export_ed25519_signing_key(&key_handle)
        .await
        .map_err(|e| ScpError::Context {
            msg: format!("failed to export Active Signing Key for context '{context_id}': {e}"),
            // INTENTIONALLY DISTINCT from the CTX_2001 "not hosted here" siblings
            // above: the identity IS hosted, but the custody export operation
            // itself failed (a crypto/custody operational fault, not a hosting /
            // channel-auth class) — kept as CTX_2040.
            code: codes::CTX_2040.to_owned(),
        })
}

/// §5.4.5 / §6.2.4 cross-context streaming-saga open (SCP-OUT-047). The
/// streaming sibling of the unary cross-context saga export and
/// [`outlet_stream_open_impl`]: it validates the invocation UCAN at the bridge
/// (once, at open) against the TARGET context, drives
/// [`Supervisor::start_cross_context_streaming_outlet_invocation_saga`](scp_core::context::supervisor::Supervisor::start_cross_context_streaming_outlet_invocation_saga)
/// to the Commit-transition, and stores the promptly-returned receiver in the
/// per-instance saga registry keyed by the durable `saga_id`. Returns the
/// `saga_id` string PROMPTLY (AC1 — the Commit-transition, NOT a
/// block-until-terminal; the seal pumps off-mailbox).
///
/// Body ORDER is security-critical (identical to the `PyO3` reference):
///   (a) validate inputs;
///   (b) `enforce_caller_principal_binding` on the CALLER axis (§6.2.4 Caller
///       authentication / ADR-049 §3a) BEFORE anything irreversible;
///   (c) `validate_outlet_ucan_uniffi` against the TARGET context B, then resolve
///       the effective §7.3.8 caveats + `ucan_cid` and compute the §5.4.5
///       `caveats_binding` from a FRESH `request_id`;
///   (d) resolve `SagaSigningKeys { target, caller }` from each handle's Active
///       Signing Key (via custody — the key never enters the runtime, ADR-006);
///   (e) build the executor over the TARGET handler;
///   (f) drive the saga to the Commit-transition;
///   (g) register the receiver and return the `saga_id`.
#[allow(clippy::too_many_arguments)] // Flat §6.2.4 streaming envelope — agent-first named params.
#[allow(clippy::too_many_lines)] // UCAN validate + caveat binding + full OpenStreamParams + saga drive.
pub(crate) async fn outlet_streaming_saga_open_impl(
    bi: &Arc<UniffiBridgeInstance>,
    source_handle: &ContextHandle,
    target_handle: &ContextHandle,
    caller_did: String,
    outlet_registration_id: String,
    input_json: String,
    asserted_nonce_hex: String,
    timestamp_ms: u64,
    chain_depth: u8,
    ucan_token: String,
    proof_tokens: Option<Vec<String>>,
    ucan_proof_id: Option<String>,
    timeout_ms: Option<u32>,
    estimated_chunk_count: Option<u32>,
) -> Result<String, ScpError> {
    let caller_context_id = source_handle.context_id.clone();
    let target_context_id = target_handle.context_id.clone();

    // Both contexts MUST be Active before this money-moving open touches any
    // state. Read the AUTHORITATIVE lifecycle state from the per-context
    // supervisor actor (`read_context_state`) — NOT the bridge-cached
    // `ContextHandle::state`, which LAGS: on close the core handle flips to
    // `Closing` immediately, but the FFI cache stays `Active` until the async
    // finalize completes. A stale-cache read would let a `Closing` context (actor
    // alive, members intact) pass this gate and DEBIT ESCROW. Mirrors the PyO3
    // reference's authoritative `read_context_state`. A missing actor (`None`) is
    // treated as non-active (fail-closed). Codes match NAPI/PyO3: OUTLET_6010
    // (caller axis) / OUTLET_6011 (target axis). Checked BEFORE input validation,
    // the caller-principal binding, and the saga drive, so a non-active context is
    // rejected before any receiver is ever handed out (§5.3 lifecycle / §6.2.4).
    //
    // TARGET axis: DEFENSE-IN-DEPTH (#2196). CALLER/source axis: still primary.
    // The runtime streaming-saga reserve path (`reserve_outlet_stream_economy`)
    // NOW carries its own fail-closed `ContextState::Active` gate
    // (`ensure_context_active`, the FIRST predicate before any escrow debit) that
    // surfaces the canonical SCP-OUTLET-6080 "context not active". That reserve
    // runs on the TARGET context (where the escrow moves), so the runtime gate is
    // now the PRIMARY money-protecting barrier for the target axis and this
    // bridge's target-axis check (OUTLET_6011) is demoted to defense-in-depth.
    // The reserve does NOT run on the CALLER/source context, so this bridge's
    // caller-axis check (OUTLET_6010) remains the authoritative gate stopping a
    // non-active source from initiating the saga.
    let supervisor = Arc::clone(bi.context_manager_or_error()?);
    let source_state = supervisor.read_context_state(&caller_context_id).await;
    if !matches!(source_state, Some(scp_core::context::ContextState::Active)) {
        return Err(ScpError::Outlet {
            msg: format!(
                "cannot start cross-context streaming saga: caller context in {source_state:?} state"
            ),
            code: codes::OUTLET_6010.to_owned(),
        });
    }
    let target_state = supervisor.read_context_state(&target_context_id).await;
    if !matches!(target_state, Some(scp_core::context::ContextState::Active)) {
        return Err(ScpError::Outlet {
            msg: format!(
                "cannot start cross-context streaming saga: target context in {target_state:?} state"
            ),
            code: codes::OUTLET_6011.to_owned(),
        });
    }

    // ----- (a) validate inputs ------------------------------------------------
    validate_context_id(&caller_context_id)?;
    validate_context_id(&target_context_id)?;
    validate_did(&caller_did)?;
    validate_outlet_id(&outlet_registration_id)?;
    validate_ucan_token(&ucan_token)?;
    // NOTE (SCP-OUT-047 review F3): NO `spending_ucan` on the streaming-saga open
    // (the cross-context escrow is B-side; spending authorization is carried by
    // `ucan_proof_id`, resolved target-side at Prepare-B, exactly as the unary
    // sibling does).
    if let Some(ref tokens) = proof_tokens {
        for t in tokens {
            validate_ucan_token(t)?;
        }
    }
    let asserted_nonce = decode_asserted_nonce(&asserted_nonce_hex)?;
    let input_value: serde_json::Value =
        serde_json::from_str(&input_json).map_err(|e| ScpError::Outlet {
            msg: format!("invalid input JSON: {e}"),
            code: codes::OUTLET_6002.to_owned(),
        })?;

    // ----- (b) caller-principal binding (CALLER axis) — BEFORE anything else --
    //
    // Runs before ANY outlet read or state mutation, so an unauthenticated caller
    // is rejected before it can touch B's state (identical to the `PyO3`
    // reference's ordering). `supervisor` was resolved above for the authoritative
    // lifecycle gate; reuse it.
    enforce_caller_principal_binding(bi, &supervisor, &caller_context_id, &caller_did).await?;

    // ----- (c) validate the invocation UCAN against the TARGET context --------
    //
    // The outlet lives in the operating context B, so its registered kind +
    // per-context UCAN state are B's — IDENTICAL to `outlet_stream_open_impl`,
    // just rebased onto the TARGET handle. Validated ONCE at open (§5.4.5 "UCAN
    // check locus").
    //
    // Snapshot the TARGET handle's per-context outlet registry once (cheap Vec of
    // registrations); every subsequent outlet field is read off this clone, so
    // the handle's `outlet_registry` mutex is released before the runtime call.
    let registry = { target_handle.outlet_registry.lock().await.clone() };
    let registration = registry
        .get(&outlet_registration_id)
        .ok_or_else(|| ScpError::Outlet {
            msg: format!(
                "outlet '{outlet_registration_id}' not registered in context '{target_context_id}'"
            ),
            code: codes::OUTLET_6002.to_owned(),
        })?;
    let outlet_kind = registration.kind;
    let cost_per_chunk = registration
        .cost
        .as_ref()
        .map_or(scp_core::economy::Amount::new(0), |c| c.amount);
    let operator_did = registration.operator_did.0.clone();
    validate_outlet_ucan_uniffi(
        bi,
        target_handle,
        &outlet_registration_id,
        outlet_kind,
        &ucan_token,
        &caller_did,
        proof_tokens.as_ref(),
    )
    .await?;

    // §7.3.8 effective-caveat resolution from the VALIDATED invocation UCAN's
    // narrowed `nb`. `ucan_cid` keys the owned Class-S counters and anchors the
    // §5.4.5 caveats binding.
    let invocation_ucan =
        scp_core::crypto::ucan::validate::parse_ucan(&ucan_token).map_err(|e| {
            ScpError::Permission {
                msg: format!("invalid invocation UCAN for '{outlet_registration_id}': {e}"),
                code: codes::PERM_3001.to_owned(),
            }
        })?;
    let ucan_cid = scp_core::crypto::ucan::revoke::compute_revocation_cid(&invocation_ucan.encoded);
    let caveats = {
        use scp_core::crypto::ucan::validate::CaveatResolver as _;
        scp_core::crypto::ucan::validate::TokenNbCaveatResolver
            .resolve_caveats(&invocation_ucan)
            .unwrap_or_else(scp_core::trust::caveats::InvocationCaveats::empty)
    };
    let has_caveats = caveats != scp_core::trust::caveats::InvocationCaveats::empty();

    // §5.4.5 caveats binding — the runtime RECOMPUTES this at open and rejects a
    // mismatch (identical to the same-context open).
    let request_id: [u8; 16] = *uuid::Uuid::now_v7().as_bytes();
    let caveats_jcs = caveats
        .to_canonical_json_bytes()
        .map_err(|e| ScpError::Context {
            msg: format!("failed to canonicalize effective caveats: {e}"),
            code: codes::CTX_2001.to_owned(),
        })?;
    let caveats_binding = compute_caveats_binding(
        ucan_cid.as_bytes(),
        &request_id,
        &caller_did,
        estimated_chunk_count.unwrap_or(0),
        &caveats_jcs,
    );

    // The OPERATOR (of the target outlet) signs every chunk; the INVOKER (caller)
    // pubkey verifies grants + cancels. Both resolved through this instance's
    // custody (co-resident single-tenant).
    let operator_signer: Arc<dyn StreamSigner> =
        Arc::new(resolve_stream_signer(bi, &operator_did).await?);
    let invoker_pk = *resolve_stream_signer(bi, &caller_did)
        .await?
        .verifying_key();

    // Snapshot the registered handler (an `Arc<dyn Fn>`) off the TARGET handle.
    let handler = {
        target_handle
            .outlet_handlers
            .lock()
            .await
            .get(&outlet_registration_id)
            .cloned()
    };
    let stream_epoch = supervisor
        .local_mls_epoch(&target_context_id)
        .await
        .unwrap_or(0);

    let executor: Arc<dyn OutletExecutor> = Arc::new(UniffiStreamExecutor {
        handler,
        outlet_id: outlet_registration_id.clone(),
        context_id: target_context_id.clone(),
        invoker_did: caller_did.clone(),
    });

    // LIVE revocation view (B's per-context list) for the runtime pump's
    // authoritative re-check timer.
    let revocation_checker: Arc<
        dyn scp_core::crypto::ucan::validate::RevocationChecker + Send + Sync,
    > = Arc::new(UniffiStreamRevocationChecker {
        states: Arc::clone(bi.ucan_registry()),
        context_id: target_context_id.clone(),
    });

    let identity = StreamIdentity {
        context_id: target_context_id.clone(),
        outlet_id: outlet_registration_id.clone(),
        stream_epoch,
        caveats_binding,
    };

    // The caps + the four timing/window policy fields are SERVER POLICY: the
    // saga's `open_outlet_stream_phase1` OVERWRITES them AUTHORITATIVELY from the
    // TARGET context's `ContextParams` — placeholders the runtime discards
    // (identical to the same-context open).
    let params = OpenStreamParams {
        identity,
        caps: AdmissionCaps {
            per_invoker: 0,
            per_origin_invoker: 0,
            per_outlet: 0,
        },
        invoker_did: caller_did.clone(),
        // The immediate invoker IS the origin invoker on this co-resident open.
        origin_invoker_did: caller_did.clone(),
        cost_per_chunk,
        available_balance: scp_core::economy::Amount::new(0),
        reserved_escrow: scp_core::economy::Amount::new(0),
        declared_estimated_chunk_count: estimated_chunk_count,
        credit_window: 0,
        caveats: caveats.clone(),
        invoker_pk,
        operator_signer,
        stream_credit_stall_secs: 0,
        stream_cancel_ack_secs: 0,
        stream_ucan_recheck_secs: 0,
        ucan_cid: ucan_cid.clone(),
        request_id,
        revocation_checker,
        economic_policy_snapshot: None,
    };

    // §7.3.8 value-caveat binding — `Some` iff the token carries caveats.
    let value_caveat_binding = if has_caveats {
        Some(scp_core::context::outlets::InvocationCaveatBinding { caveats, ucan_cid })
    } else {
        None
    };

    // ----- (d) signing keys: each co-resident context's Active Signing Key ----
    //
    // Resolved DIRECTLY from the owned, instance-affine handles (mirrors the
    // unary saga export). Each context signs its own side under its registered
    // Active Signing Key.
    let target_signing_key = resolve_uniffi_signing_key(target_handle).await?;
    let caller_signing_key = resolve_uniffi_signing_key(source_handle).await?;

    // ----- Chokepoint (ADR-056): id STRING → [u8; 32] -------------------------
    let caller_context_bytes = scp_core::context::state::context_id_to_bytes(&caller_context_id);
    let target_context_bytes = scp_core::context::state::context_id_to_bytes(&target_context_id);

    let outlet_id_typed: scp_core::context::outlets::OutletId = outlet_registration_id.clone();
    let caller_did_typed: scp_did::DID = caller_did.clone().into();

    // ----- (f) drive the saga to the Commit-transition ------------------------
    //
    // `await` resolves at the Commit-transition (AC1) — the seal task is SPAWNED,
    // so this returns the receiver PROMPTLY. Box the multi-phase saga future so
    // it does not bloat this method's own future (`clippy::large_futures`).
    let handle = Box::pin(
        supervisor.start_cross_context_streaming_outlet_invocation_saga(
            caller_context_bytes,
            target_context_bytes,
            caller_did_typed,
            outlet_registration_id.clone(),
            ucan_proof_id,
            &registry,
            &outlet_id_typed,
            input_value,
            chain_depth,
            asserted_nonce,
            timestamp_ms,
            timeout_ms,
            executor,
            value_caveat_binding,
            scp_core::context::supervisor::SagaSigningKeys {
                target: &target_signing_key,
                caller: &caller_signing_key,
            },
            params,
        ),
    )
    .await
    .map_err(map_saga_error)?;

    // ----- (g) register the promptly-returned receiver ------------------------
    let saga_id = handle.saga_id;
    let receiver = handle.receiver;
    let handle_id = saga_id.0.clone();
    bi.outlet_streaming_saga_registry.insert(
        handle_id.clone(),
        StreamingSagaEntry {
            receiver: Arc::new(tokio::sync::Mutex::new(receiver)),
            saga_id,
            target_context_id,
            invoker_did: caller_did,
            request_id,
        },
    );
    Ok(handle_id)
}

/// Drains one chunk from a live cross-context streaming saga, awaiting the seal
/// task until a chunk arrives or the stream closes. Returns the JSON-serialized
/// [`OutletStreamChunk`] bytes (A's plaintext operator-signed frame, forwarded
/// verbatim), or `None` at the channel-closed sentinel.
///
/// Mirrors [`outlet_stream_poll_next_impl`]: an unknown/evicted saga id is a
/// DISTINCT [`no_active_saga_err`] (never `None`), and a terminal chunk EVICTS
/// the entry so a run-to-terminal caller cannot leak it. Takes NO `caller_did`:
/// possession of the `saga_id` handle IS the read capability.
pub(crate) async fn outlet_streaming_saga_poll_next_impl(
    bi: &Arc<UniffiBridgeInstance>,
    saga_id: &str,
) -> Result<Option<Vec<u8>>, ScpError> {
    let receiver = {
        let Some(entry) = bi.outlet_streaming_saga_registry.get(saga_id) else {
            return Err(no_active_saga_err(saga_id));
        };
        Arc::clone(&entry.receiver)
    };
    let chunk = receiver.lock().await.recv().await;
    if let Some(chunk) = chunk {
        let (bytes, terminal) = serialize_saga_chunk(&chunk).map_err(|e| ScpError::Context {
            msg: format!("failed to serialize saga stream chunk: {e}"),
            code: codes::CTX_2001.to_owned(),
        })?;
        if terminal {
            bi.outlet_streaming_saga_registry.remove(saga_id);
        }
        Ok(Some(bytes))
    } else {
        // Abnormal terminal: the seal task dropped the sender without a terminal
        // chunk. Evict so the receiver + entry drop.
        bi.outlet_streaming_saga_registry.remove(saga_id);
        Ok(None)
    }
}

/// Key-bearing in-session reconnect/repair truncated-close for a cross-context
/// streaming saga (SCP-OUT-046 #136 AC7). AUTHENTICATES the reconnect caller and
/// supplies the TARGET's Active Signing Key to
/// [`Supervisor::recover_streaming_saga_truncated_close`](scp_core::context::supervisor::Supervisor::recover_streaming_saga_truncated_close)
/// via the shared [`drive_recover_truncated_close`] driver. Seals B's durable
/// prefix and resolves the saga `Committed` WITHOUT re-opening the stream or
/// re-invoking the executor.
///
/// This is IN-SESSION reconnect/repair of a seal that stalled or went
/// `NeedsRepair` while THIS bridge process is still ALIVE (e.g. a client
/// reconnects to the same live node). The saga registry is per-instance and
/// IN-MEMORY, so this does NOT survive a process/node restart — cross-restart
/// recovery replays the durable saga journal via a separate operator path
/// (§17.16), NOT this FFI surface.
///
/// Auth (TWO gates, both required, in order):
///   1. `caller_did` MUST be an identity THIS bridge instance hosts (the
///      co-resident channel-authenticated principal, §6.2.4).
///   2. `caller_did` MUST equal the `invoker_did` pinned at open (CRITICAL #1 —
///      recovery is MONEY-MOVING, so it carries the SAME `SCP-PERM-3001` invoker
///      gate as the same-context grant/cancel/terminate siblings). The
///      hosted-identity check ALONE would let ANY co-resident identity settle a
///      stranger's saga.
///
/// The Active Signing Key is resolved PER-CALL from the target context's custody
/// (never envelope-asserted) and never before BOTH gates pass. On success the
/// registry entry is EVICTED (the saga is now Committed).
pub(crate) async fn outlet_streaming_saga_recover_truncated_close_impl(
    bi: &Arc<UniffiBridgeInstance>,
    saga_id: &str,
    caller_did: &str,
) -> Result<(), ScpError> {
    validate_did(caller_did)?;

    // Authenticate the reconnect caller: it MUST be an identity hosted by this
    // bridge instance (§6.2.4 Caller authentication), never an envelope-asserted
    // value.
    if !identity_custody_registry(bi).contains_key(caller_did) {
        return Err(ScpError::Context {
            msg: format!(
                "caller_did '{caller_did}' is not an identity hosted by this bridge instance — \
                 the streaming-saga reconnect recovery caller MUST be the channel-authenticated \
                 principal (§6.2.4 Caller authentication), not an envelope-asserted value"
            ),
            // Hosted-identity (channel-auth) rejection — SAME code the NAPI and
            // PyO3 bridges surface (SCP-OUT-047 pass-3a cross-bridge alignment).
            code: codes::CTX_2001.to_owned(),
        });
    }

    // Look up the live saga entry for the durable `saga_id`, pinning its target
    // context, the `SagaId`, and the `invoker_did` pinned at open.
    let (saga_id_typed, target_context_id, invoker_did) = {
        let Some(entry) = bi.outlet_streaming_saga_registry.get(saga_id) else {
            return Err(no_active_saga_err(saga_id));
        };
        (
            entry.saga_id.clone(),
            entry.target_context_id.clone(),
            entry.invoker_did.clone(),
        )
    };

    // CRITICAL #1: recovery is MONEY-MOVING, so ONLY the invoker pinned at open
    // may drive it — the SAME `SCP-PERM-3001` gate the same-context siblings
    // enforce. Rejected BEFORE the signing key is resolved or the driver runs, so
    // a non-invoker never triggers a settle and the entry is left INTACT.
    if caller_did != invoker_did {
        return Err(caller_not_invoker_err(caller_did, &invoker_did));
    }

    // Resolve the TARGET context's Active Signing Key per-call from custody
    // (never envelope-asserted) and seal via the shared recovery driver.
    let target_key = resolve_context_active_signing_key_by_id(bi, &target_context_id).await?;
    let signing_key =
        scp_core::context::actor::commands::SigningKeyBytes::from_signing_key(&target_key);
    let supervisor = Arc::clone(bi.context_manager_or_error()?);
    drive_recover_truncated_close(&supervisor, saga_id_typed, &target_context_id, signing_key)
        .await
        .map_err(map_saga_error)?;

    // Evict on SUCCESS: the saga is now `Committed` and its prefix sealed.
    bi.outlet_streaming_saga_registry.remove(saga_id);
    Ok(())
}

// ---------------------------------------------------------------------------
// Scp methods — the #[uniffi::export] surface (Swift / Kotlin)
// ---------------------------------------------------------------------------

/// Maps a tokio `JoinError` from the `runtime().spawn` offload onto the bridge
/// error surface (mirrors every other `UniFFI` outlet op's join-error tail).
fn join_err(e: tokio::task::JoinError) -> ScpError {
    ScpError::Outlet {
        msg: format!("tokio task join error during outlet stream op: {e}"),
        code: codes::OUTLET_6006.to_owned(),
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl Scp {
    /// Opens a §5.4.5 streaming outlet invocation, returning a `StreamHandleId`
    /// PROMPTLY (Commit transition — never block-until-terminal).
    ///
    /// The UCAN is validated ONCE at open via the full 11-step ADR-016 pipeline;
    /// the invoker (`caller_did`) is pinned for the stream's lifetime. Drive the
    /// stream via `outletStreamPollNext` / `_grantCredit` / `_cancel` /
    /// `_terminate` with the SAME `caller_did`.
    ///
    /// Named `outlet_stream_open` (not `outlet_invoke_stream`) so the whole
    /// streaming surface groups under the `outlet_stream_*` prefix (agent-first
    /// API design).
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Permission` if authorization fails. Returns
    /// `ScpError::Outlet` carrying a `SCP-OUTLET-NNNN` code if the open is
    /// rejected (admission caps, escrow, caveats binding, node pump ceiling, or a
    /// §7.3.8 caveat).
    #[allow(clippy::too_many_arguments)]
    pub async fn outlet_stream_open(
        &self,
        handle: Arc<ContextHandle>,
        outlet_id: String,
        input_json: String,
        caller_did: String,
        ucan_token: String,
        proof_tokens: Option<Vec<String>>,
        spending_ucan: Option<String>,
        timeout_ms: Option<u32>,
        estimated_chunk_count: Option<u32>,
    ) -> Result<String, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        crate::runtime()
            .spawn(async move {
                outlet_stream_open_impl(
                    &bi,
                    &handle,
                    outlet_id,
                    input_json,
                    caller_did,
                    ucan_token,
                    proof_tokens,
                    spending_ucan,
                    timeout_ms,
                    estimated_chunk_count,
                )
                .await
            })
            .await
            .map_err(join_err)?
    }

    /// Drains one chunk from a live stream, awaiting until a chunk arrives or the
    /// stream closes. Returns the JSON-serialized `OutletStreamChunk` bytes, or
    /// `None` at the terminal (which evicts the stream).
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Context` for an unknown/evicted `handle_id` (a DISTINCT
    /// error, NEVER `None`) or if chunk serialization fails.
    pub async fn outlet_stream_poll_next(
        &self,
        handle_id: String,
    ) -> Result<Option<Vec<u8>>, ScpError> {
        let bi = Arc::clone(&self.inner);
        crate::runtime()
            .spawn(async move { outlet_stream_poll_next_impl(&bi, &handle_id).await })
            .await
            .map_err(join_err)?
    }

    /// Grants `grant` additional billable chunks of credit to a live stream. The
    /// bridge signs the `OutletStreamCredit` internally under the pinned invoker's
    /// custody key and auto-assigns the monotonic sequence, so the caller supplies
    /// only a `u32` — no key access, no replay-counter tracking. The grant debits
    /// `cost_per_chunk × grant` of escrow first (money-conservation), reversing it
    /// if the grant apply then rejects.
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Permission` with `SCP-PERM-3001` if `caller_did` is not
    /// the pinned invoker; an escrow rejection (`InsufficientFunds` /
    /// `EscrowOverflow`) if the top-up debit fails; `SCP-OUTLET-NNNN` if the grant
    /// apply is rejected (bad signature, replay, or the stream already closed).
    pub async fn outlet_stream_grant_credit(
        &self,
        handle_id: String,
        caller_did: String,
        grant: u32,
    ) -> Result<(), ScpError> {
        let bi = Arc::clone(&self.inner);
        crate::runtime()
            .spawn(async move {
                outlet_stream_grant_credit_impl(&bi, &handle_id, &caller_did, grant).await
            })
            .await
            .map_err(join_err)?
    }

    /// Signs and applies a stream cancel at the runtime-derived cursor (CRITICAL
    /// #3 — the bridge never supplies a `next_seq`).
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Permission` with `SCP-PERM-3001` if `caller_did` is not
    /// the pinned invoker; `SCP-OUTLET-6110` on a signature/identity mismatch;
    /// `SCP-OUTLET-6160` (retryable) if the cursor advanced past the bounded retry
    /// budget.
    pub async fn outlet_stream_cancel(
        &self,
        handle_id: String,
        caller_did: String,
    ) -> Result<(), ScpError> {
        let bi = Arc::clone(&self.inner);
        crate::runtime()
            .spawn(async move { outlet_stream_cancel_impl(&bi, &handle_id, &caller_did).await })
            .await
            .map_err(join_err)?
    }

    /// Forces a framework terminal chunk. `slug` selects a closed-set terminal
    /// reason; the canonical `code` is derived internally from the reason;
    /// `message` is a human suffix.
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Permission` with `SCP-PERM-3001` if `caller_did` is not
    /// the pinned invoker; `ScpError::Validation` if `slug` is not a
    /// stream-terminal slug.
    pub async fn outlet_stream_terminate(
        &self,
        handle_id: String,
        caller_did: String,
        slug: String,
        message: String,
    ) -> Result<(), ScpError> {
        let bi = Arc::clone(&self.inner);
        crate::runtime()
            .spawn(async move {
                outlet_stream_terminate_impl(&bi, &handle_id, &caller_did, &slug, &message).await
            })
            .await
            .map_err(join_err)?
    }

    /// Pure wrapper: verifies a chunk's operator signature (§5.4.5).
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Validation` if a byte argument is malformed.
    // Uniform async FFI surface: the body is pure/sync, but the method stays
    // `async` so the whole `outlet_stream_*` surface has one call shape across
    // Swift/Kotlin (every sibling op is async).
    #[allow(clippy::unused_async)]
    pub async fn outlet_stream_verify_chunk_signature(
        &self,
        chunk_bytes: Vec<u8>,
        operator_pk: Vec<u8>,
        context_id: String,
        outlet_id: String,
        caveats_binding: Vec<u8>,
    ) -> Result<bool, ScpError> {
        outlet_stream_verify_chunk_signature_impl(
            &chunk_bytes,
            &operator_pk,
            &context_id,
            &outlet_id,
            &caveats_binding,
        )
    }

    /// Pure wrapper: computes the §5.4.5 `caveats_binding` (32 bytes).
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Validation` if `request_id` is not 16 bytes.
    // Uniform async FFI surface: the body is pure/sync, but the method stays
    // `async` so the whole `outlet_stream_*` surface has one call shape across
    // Swift/Kotlin (every sibling op is async).
    #[allow(clippy::unused_async)]
    pub async fn outlet_stream_compute_caveats_binding(
        &self,
        ucan_cid: Vec<u8>,
        request_id: Vec<u8>,
        invoker_did: String,
        estimated_chunk_count: u32,
        effective_caveats_jcs: Vec<u8>,
    ) -> Result<Vec<u8>, ScpError> {
        outlet_stream_compute_caveats_binding_impl(
            &ucan_cid,
            &request_id,
            &invoker_did,
            estimated_chunk_count,
            &effective_caveats_jcs,
        )
    }

    // ===== §5.4.5 / §6.2.4 cross-context streaming saga (SCP-OUT-047) =====

    /// Opens a §5.4.5 / §6.2.4 CROSS-CONTEXT streaming outlet invocation as a
    /// saga (SCP-OUT-047), returning the durable `saga_id` PROMPTLY (the
    /// Commit-transition — NOT a block-until-terminal; the seal pumps
    /// off-mailbox). Drive the stream via `outletStreamingSagaPollNext` with the
    /// returned `saga_id`.
    ///
    /// The invocation UCAN is validated ONCE at open via the full 11-step
    /// ADR-016 pipeline against the TARGET context B (`target_handle`).
    /// `caller_did` is bound to this bridge instance's channel-authenticated
    /// principal (§6.2.4) and must be a member of `source_handle`'s context — a
    /// mismatch returns `ScpError::SagaAborted` (SCP-SAGA-13050) BEFORE the saga
    /// runs, so the receiver is never handed out.
    ///
    /// # Errors
    ///
    /// Returns `ScpError::SagaAborted` (SCP-SAGA-13050) if the caller-principal
    /// binding fails; `ScpError::Permission` if authorization fails; a saga
    /// terminal error (`SagaAborted` / `SagaNeedsRepair` / `SagaBusy`) if the
    /// Prepare/Commit-transition is rejected; `ScpError::Validation` if an
    /// id/DID/outlet-id is malformed or `asserted_nonce_hex` is not 16 bytes.
    #[allow(clippy::too_many_arguments)]
    pub async fn outlet_streaming_saga_open(
        &self,
        source_handle: Arc<ContextHandle>,
        target_handle: Arc<ContextHandle>,
        caller_did: String,
        outlet_registration_id: String,
        input_json: String,
        asserted_nonce_hex: String,
        timestamp_ms: u64,
        chain_depth: u8,
        ucan_token: String,
        proof_tokens: Option<Vec<String>>,
        ucan_proof_id: Option<String>,
        timeout_ms: Option<u32>,
        estimated_chunk_count: Option<u32>,
    ) -> Result<String, ScpError> {
        // Per-instance handle affinity: both participant handles MUST have been
        // minted by THIS bridge instance (mirrors the unary saga export).
        self.inner
            .core
            .check_handle(source_handle.instance_id())
            .map_err(ScpError::from)?;
        self.inner
            .core
            .check_handle(target_handle.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        crate::runtime()
            .spawn(async move {
                outlet_streaming_saga_open_impl(
                    &bi,
                    &source_handle,
                    &target_handle,
                    caller_did,
                    outlet_registration_id,
                    input_json,
                    asserted_nonce_hex,
                    timestamp_ms,
                    chain_depth,
                    ucan_token,
                    proof_tokens,
                    ucan_proof_id,
                    timeout_ms,
                    estimated_chunk_count,
                )
                .await
            })
            .await
            .map_err(join_err)?
    }

    /// Drains one chunk from a live cross-context streaming saga, awaiting until
    /// a chunk arrives or the stream closes. Returns the JSON-serialized
    /// `OutletStreamChunk` bytes (A's plaintext operator-signed frame), or `None`
    /// at the terminal (which evicts the saga stream).
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Context` for an unknown/evicted `saga_id` (a DISTINCT
    /// error, NEVER `None`) or if chunk serialization fails.
    pub async fn outlet_streaming_saga_poll_next(
        &self,
        saga_id: String,
    ) -> Result<Option<Vec<u8>>, ScpError> {
        let bi = Arc::clone(&self.inner);
        crate::runtime()
            .spawn(async move { outlet_streaming_saga_poll_next_impl(&bi, &saga_id).await })
            .await
            .map_err(join_err)?
    }

    /// Key-bearing in-session reconnect/repair truncated-close for a cross-context
    /// streaming saga (SCP-OUT-046 #136 AC7): seals the durable prefix with the
    /// TARGET context's Active Signing Key (resolved per-call from custody) and
    /// resolves the saga `Committed` WITHOUT re-opening the stream or re-invoking
    /// the executor. Recovers a seal that stalled / went `NeedsRepair` while THIS
    /// bridge process is still alive; the saga registry is per-instance and
    /// in-memory, so it does NOT survive a process/node restart (cross-restart
    /// recovery is a separate durable-journal operator path, §17.16).
    /// `caller_did` must be an identity hosted by this bridge instance (§6.2.4
    /// channel-auth) AND the invoker pinned at open (CRITICAL #1 — recovery is
    /// money-moving). On success the saga registry entry is evicted.
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Context` if `caller_did` is not hosted by this instance
    /// or the `saga_id` is unknown; `ScpError::Permission` with `SCP-PERM-3001`
    /// if `caller_did` is hosted but is not the pinned invoker; a saga terminal
    /// error (`SagaNeedsRepair`) if the seal cannot complete.
    pub async fn outlet_streaming_saga_recover_truncated_close(
        &self,
        saga_id: String,
        caller_did: String,
    ) -> Result<(), ScpError> {
        let bi = Arc::clone(&self.inner);
        crate::runtime()
            .spawn(async move {
                outlet_streaming_saga_recover_truncated_close_impl(&bi, &saga_id, &caller_did).await
            })
            .await
            .map_err(join_err)?
    }
}

// ---------------------------------------------------------------------------
// Test-only registry seam (SCP-OUT-047 — recover invoker gate)
// ---------------------------------------------------------------------------

/// TEST-ONLY helpers on [`Scp`]. NOT a `#[uniffi::export]` block, so nothing
/// here is exposed to Swift/Kotlin or counted by the bridge-symmetry gate.
/// Gated on the same test/testing features as `Scp::new_in_memory_for_test`.
#[cfg(any(test, feature = "testing"))]
impl Scp {
    /// Injects a live cross-context streaming-saga registry entry pinned to
    /// `invoker_did`, so the recover invoker-gate (CRITICAL #1) can be exercised
    /// without driving a full committed cross-context saga (whose actor-state /
    /// budget injection has no bridge-public wiring — same rationale as the
    /// unary-saga bridge tests). The receiver's sender is dropped immediately
    /// (recover never polls it).
    pub fn insert_test_streaming_saga_entry(
        &self,
        saga_id: &str,
        target_context_id: &str,
        invoker_did: &str,
    ) {
        let (_tx, rx) = mpsc::channel(1);
        self.inner.outlet_streaming_saga_registry.insert(
            saga_id.to_owned(),
            StreamingSagaEntry {
                receiver: Arc::new(tokio::sync::Mutex::new(rx)),
                saga_id: scp_core::context::supervisor::SagaId(saga_id.to_owned()),
                target_context_id: target_context_id.to_owned(),
                invoker_did: invoker_did.to_owned(),
                request_id: [0u8; 16],
            },
        );
    }

    /// TEST-ONLY: reports whether a streaming-saga registry entry for `saga_id`
    /// is still present — lets a test assert the recover invoker-gate rejection
    /// did NOT evict a stranger's saga.
    #[must_use]
    pub fn test_streaming_saga_entry_present(&self, saga_id: &str) -> bool {
        self.inner
            .outlet_streaming_saga_registry
            .contains_key(saga_id)
    }
}

#[cfg(test)]
mod tests;
