//! `PyO3` reference bridge for §5.4.5 streaming-native outlet invocation
//! (SCP-OUT-037, sub-chunk C7).
//!
//! This is the CANONICAL bridge shape the other three native bridges
//! (NAPI / `UniFFI` / WASM — C8/C9) mirror. It wraps the runtime control
//! surface [`Supervisor::open_outlet_stream`](scp_core::context::supervisor::Supervisor::open_outlet_stream)
//! and [`StreamSessionHandle`] into six `PyScp` methods plus two pure 1:1
//! wrappers:
//!
//! - [`PyScp::outlet_stream_open`] — open a stream (Commit-transition:
//!   returns a `StreamHandleId` PROMPTLY; NEVER blocks until terminal).
//! - [`PyScp::outlet_stream_poll_next`] — drain one chunk (`None` == closed).
//! - [`PyScp::outlet_stream_grant_credit`] — apply an invoker-signed grant.
//! - [`PyScp::outlet_stream_cancel`] — sign+apply a cancel at the
//!   runtime-derived cursor.
//! - [`PyScp::outlet_stream_terminate`] — force a framework terminal.
//! - [`PyScp::outlet_stream_verify_chunk_signature`] /
//!   [`PyScp::outlet_stream_compute_caveats_binding`] — pure wrappers.
//!
//! # Two CRITICAL invariants enforced here
//!
//! - **CRITICAL #1 (caller == pinned invoker).** `invoker_did` is pinned in
//!   the per-instance [`StreamEntry`] at open. Every control-plane call
//!   (`grant_credit`, `cancel`, `terminate`) rejects a `caller_did` that is
//!   not the pinned invoker with `SCP-PERM-3001` BEFORE touching runtime
//!   state. Authorization to open a stream is NOT authorization for a
//!   different principal to steer it.
//! - **CRITICAL #3 (runtime-derived cancel cursor).** The bridge NEVER
//!   supplies a `next_seq`. `outlet_stream_cancel` calls
//!   [`StreamSessionHandle::apply_outlet_cancel_signed`], which reads the
//!   runtime's own live emission cursor
//!   ([`StreamSessionHandle::current_next_emission_seq`]) and signs the
//!   `SCP-OUTLET-CANCEL-V1:` preimage over it internally — closing the
//!   forged-cursor billing surface.
//!
//! # Per-instance, never a global
//!
//! The stream registry is a per-instance field on
//! [`PyBridgeInstance`](crate::runtime::PyBridgeInstance)
//! (`outlet_stream_registry`), NOT a `static` — `check-no-bridge-globals.sh`
//! / `check-handle-affinity.sh` forbid the alternative. A stream opened on
//! one instance is invisible to another, and instance shutdown drops every
//! live stream with the `Arc`.
//!
//! # Co-resident custody
//!
//! Chunk signatures are produced by the OUTLET OPERATOR's key and cancel
//! signatures by the INVOKER's key. Both are resolved through this bridge
//! instance's custody registry (the operator identity + the invoker
//! identity must be locally hosted). This mirrors the co-resident
//! single-tenant constraint of the cross-context saga export in `outlets.rs`.

use std::sync::Arc;

use dashmap::DashMap;
use ed25519_dalek::VerifyingKey;
use pyo3::prelude::*;
use scp_platform::KeyHandle;
use scp_platform::error::PlatformError;
use scp_platform::traits::KeyCustody;
use tokio::sync::mpsc;

use scp_core::context::outlets::stream::{
    OutletStreamChunk, OutletStreamCredit, TerminateReason, compute_caveats_binding,
    compute_credit_sig_preimage, verify_chunk_signature,
};
use scp_core::context::outlets::{
    AdmissionCaps, CancelIdentity, OpenStreamParams, OpenStreamRejection, OutletExecutor,
    OutletExecutorError, StreamIdentity, StreamSessionHandle, StreamSigner,
    StreamSignerCustodyCategory, StreamSignerError, cancel_error_to_code, grant_error_to_code,
};

use crate::custody::FfiKeyCustody;
use crate::error::ScpPyError;
use crate::runtime::{OutletHandler, PyBridgeInstance};
use crate::validate;

// ---------------------------------------------------------------------------
// StreamEntry — the per-instance registry value
// ---------------------------------------------------------------------------

/// One live stream tracked in
/// [`PyBridgeInstance::outlet_stream_registry`](crate::runtime::PyBridgeInstance).
///
/// Splits the control plane (the `handle`) from the data plane (the detached
/// `receiver`) behind INDEPENDENT async locks so a `poll_next` parked in
/// `receiver.recv()` (awaiting the executor's next chunk) never blocks a
/// concurrent `grant_credit` / `cancel` / `terminate` — the grant is exactly
/// what unblocks a credit-stalled executor to PRODUCE that chunk, so
/// serializing the two would deadlock.
pub struct StreamEntry {
    /// Runtime control surface. `tokio::sync::Mutex` because
    /// [`StreamSessionHandle`] is `!Sync` (it structurally holds the
    /// [`mpsc::Receiver`] type even after the value is detached) and the
    /// cancel method is `async` — the mutex is safe to hold across its
    /// `.await`, and it serializes only the (brief) control-plane ops.
    handle: Arc<tokio::sync::Mutex<StreamSessionHandle>>,
    /// Detached chunk receiver (data plane). Independent lock from `handle`.
    receiver: Arc<tokio::sync::Mutex<mpsc::Receiver<OutletStreamChunk>>>,
    /// The invoker DID pinned at open (CRITICAL #1). Every control-plane
    /// call verifies `caller_did == invoker_did`.
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
    /// The hosting context's MLS epoch captured at open (§6.2.1.1(e)) — the
    /// SAME value pinned in the runtime `StreamIdentity`. Bound into the credit
    /// preimage; the runtime rejects a grant whose epoch disagrees.
    stream_epoch: scp_core::context::outlets::stream::MlsEpoch,
    /// Per-Data-chunk cost pinned at open — the multiplier for the grant-time
    /// escrow reserve (`cost_per_chunk × grant`). `Amount(0)` for Query /
    /// zero-cost outlets (no top-up).
    cost_per_chunk: scp_core::economy::Amount,
    /// Per-stream monotonic grant counter (§5.4.5 `monotonic_seq`, starts at 0).
    /// The bridge assigns each internally-signed grant a strictly-increasing
    /// value via `fetch_add`, so callers never track or forge it — closing the
    /// caller-tracked-`monotonic_seq` unauthorability the pre-signed grant
    /// required.
    grant_seq: std::sync::atomic::AtomicU64,
}

// ---------------------------------------------------------------------------
// BridgeCustodyStreamSigner — custody-backed operator/invoker signer
// ---------------------------------------------------------------------------

/// Custody-backed [`StreamSigner`]. The signing key never enters the runtime
/// address space — the 32-byte preimage is signed through the platform
/// [`KeyCustody`] boundary (ADR-006). Used for BOTH the operator chunk signer
/// (pinned into [`OpenStreamParams`] at open) and the invoker cancel signer
/// (resolved at cancel time). Both are local identities hosted by this bridge
/// instance.
struct BridgeCustodyStreamSigner {
    /// The custody provider for the signing identity.
    custody: Arc<FfiKeyCustody>,
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
                    // Never leak key material / preimage / backend handles into the
                    // error — map to the bounded category (ADR-006 / ADR-061).
                    StreamSignerError::Custody {
                        category: StreamSignerCustodyCategory::from(&err),
                    }
                })?;
        <[u8; 64]>::try_from(sig.as_bytes()).map_err(|_| {
            // A well-formed Ed25519 signature is always 64 bytes; a shorter
            // one is a backend invariant violation, not a leakable detail.
            StreamSignerError::Custody {
                category: StreamSignerCustodyCategory::BackendFault,
            }
        })
    }

    fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

/// Resolves a custody-backed [`StreamSigner`] for a locally-hosted identity
/// DID (its Active Signing Key).
///
/// Clones the custody `Arc` + key handle OUT of the identity-registry shard
/// guard, then performs the (potentially slow) `public_key` export OFF the
/// guard — the same clone-then-drop discipline as
/// [`crate::context::resolve_signing_key`] (issue #1940).
fn resolve_stream_signer(
    bi: &PyBridgeInstance,
    identity_did: &str,
) -> PyResult<BridgeCustodyStreamSigner> {
    let rt = crate::runtime()?;
    let (custody, handle) = crate::runtime::with_identity(bi, identity_did, |entry| {
        Ok((entry.custody.clone(), entry.identity.active_signing_key))
    })?;
    let public_key = rt
        .block_on(async { custody.public_key(&handle).await })
        .map_err(|e| {
            ScpPyError::context(format!(
                "failed to resolve stream signing key for '{identity_did}': {e}"
            ))
        })?;
    let verifying_key = scp_ffi_common::export_verify::verifying_key_from_public_key(&public_key)
        .ok_or_else(|| {
        ScpPyError::context(format!(
            "identity '{identity_did}' active signing key is not a valid Ed25519 verifying key"
        ))
    })?;
    Ok(BridgeCustodyStreamSigner {
        custody,
        handle,
        verifying_key,
    })
}

// ---------------------------------------------------------------------------
// BridgeStreamRevocationChecker — LIVE per-context revocation view
// ---------------------------------------------------------------------------

/// [`RevocationChecker`](scp_core::crypto::ucan::validate::RevocationChecker)
/// giving the runtime pump a LIVE view of this instance's per-context
/// revocation list, so the §5.4.5 authoritative UCAN-revocation re-check
/// timer (`stream_ucan_recheck_secs`) observes revocations that land AFTER
/// the stream opened — not a stale open-time snapshot.
///
/// Holds an `Arc` clone of the per-instance FFI bridge-state registry and
/// the hosting context id; `is_revoked` does a brief (sync, no-`await`)
/// `DashMap` lookup per tick. A vanished context returns `false` — the
/// separate context-closed-mid-stream termination path (round 8) handles
/// substrate loss.
struct BridgeStreamRevocationChecker {
    states: Arc<DashMap<String, crate::runtime::FfiBridgeState>>,
    context_id: String,
}

impl scp_core::crypto::ucan::validate::RevocationChecker for BridgeStreamRevocationChecker {
    fn is_revoked(&self, token_cid: &str) -> bool {
        self.states
            .get(&self.context_id)
            .is_some_and(|state| state.revocation_list.is_revoked(token_cid))
    }
}

// ---------------------------------------------------------------------------
// BridgeStreamExecutor — adapts the registered single-shot handler
// ---------------------------------------------------------------------------

/// [`OutletExecutor`] wrapping the context's registered outlet handler (an
/// `Arc<dyn Fn(Value) -> Result<Value, String>>`) — identical dispatch
/// semantics to the non-streaming `outlet_invoke` executor.
///
/// The handler is single-shot: it returns one aggregate value. The default
/// `exec_*_stream` trait methods turn that into a degenerate one-`Data`-chunk
/// stream via `one_shot_to_stream`, and the framework appends the terminal
/// `End`. A richer streaming-native Python handler surface (yielding multiple
/// chunks) is an SDK concern layered on `poll_next` — the primitive here is
/// complete for the single-shot contract. When no handler is registered, the
/// executor echoes validated metadata (matching `outlet_invoke`'s schema-only
/// fallback).
struct BridgeStreamExecutor {
    handler: Option<OutletHandler>,
    outlet_id: String,
    context_id: String,
    invoker_did: String,
}

impl BridgeStreamExecutor {
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
impl OutletExecutor for BridgeStreamExecutor {
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
fn open_rejection_to_err(rejection: &OpenStreamRejection) -> ScpPyError {
    ScpPyError::ContextError {
        message: format!(
            "outlet stream open rejected ({}): {}",
            rejection.error_code(),
            rejection.slug()
        ),
        code: rejection.error_code().to_owned(),
    }
}

/// The `SCP-PERM-3001` rejection for a control-plane call whose `caller_did`
/// is not the invoker pinned at open (CRITICAL #1).
fn caller_not_invoker_err(caller_did: &str, invoker_did: &str) -> ScpPyError {
    ScpPyError::ContextError {
        message: format!(
            "caller '{caller_did}' is not the invoker '{invoker_did}' pinned at stream open — \
             only the opening invoker may steer the stream (§5.4.5 CRITICAL #1)"
        ),
        code: scp_ffi_common::error_codes::PERM_3001.to_owned(),
    }
}

/// Looks up a live stream and verifies the caller is the pinned invoker,
/// returning the shared control handle + pinned identity fields.
///
/// Shared control handle for a live stream (the runtime control surface behind
/// its own async lock).
type ControlHandle = Arc<tokio::sync::Mutex<StreamSessionHandle>>;

/// The control-plane "no active outlet stream" rejection for an unknown,
/// stale, typo'd, or already-evicted `handle_id`. Shared by every
/// control-plane lookup ([`authorized_control`]) AND by
/// [`outlet_stream_poll_next_impl`] so a bad handle is a DISTINCT error from a
/// genuine terminal (which `poll_next` reports as `None`) — conflating the two
/// would let a caller mistake a typo for a clean stream end.
fn no_active_stream_err(handle_id: &str) -> ScpPyError {
    ScpPyError::context(format!("no active outlet stream '{handle_id}'"))
}

/// Clones the `Arc`s OUT of the `DashMap` shard guard so no reference is held
/// across the subsequent `block_on` (the DashMap-ref-across-await hazard).
fn authorized_control(
    bi: &PyBridgeInstance,
    handle_id: &str,
    caller_did: &str,
) -> PyResult<(ControlHandle, String, String, [u8; 32])> {
    let entry = bi
        .outlet_stream_registry
        .get(handle_id)
        .ok_or_else(|| no_active_stream_err(handle_id))?;
    if caller_did != entry.invoker_did {
        return Err(caller_not_invoker_err(caller_did, &entry.invoker_did).into());
    }
    Ok((
        Arc::clone(&entry.handle),
        entry.context_id.clone(),
        entry.outlet_id.clone(),
        entry.caveats_binding,
    ))
}

// ---------------------------------------------------------------------------
// Open — outlet_stream_open
// ---------------------------------------------------------------------------

/// §5.4.5 streaming outlet open. Validates the UCAN at the bridge (mirroring
/// `outlet_invoke_impl`), reserves+spawns the pump via
/// [`Supervisor::open_outlet_stream`](scp_core::context::supervisor::Supervisor::open_outlet_stream),
/// and stores the returned handle in the per-instance registry keyed by the
/// stream's `request_id` (hex). Returns the `StreamHandleId` PROMPTLY —
/// the open is the Commit transition, NOT a block-until-terminal.
#[allow(clippy::too_many_arguments)] // Flat §5.4.5 open envelope — agent-first named params.
#[allow(clippy::needless_pass_by_value)] // PyO3 owned Option params.
#[allow(clippy::too_many_lines)] // UCAN validate + caveat binding + full OpenStreamParams build.
fn outlet_stream_open_impl(
    bi: &PyBridgeInstance,
    context_id: &str,
    outlet_id: &str,
    input: &Bound<'_, pyo3::types::PyDict>,
    caller_did: &str,
    ucan_token: &str,
    proof_tokens: Option<Vec<String>>,
    spending_ucan: Option<&str>,
    timeout_ms: Option<u32>,
    estimated_chunk_count: Option<u32>,
) -> PyResult<String> {
    validate::validate_context_id(context_id)?;
    validate::validate_outlet_id(outlet_id)?;
    validate::validate_did(caller_did)?;
    validate::validate_ucan_token(ucan_token)?;
    if let Some(jwt) = spending_ucan {
        validate::validate_ucan_token(jwt)?;
    }
    if let Some(ref tokens) = proof_tokens {
        for t in tokens {
            validate::validate_ucan_token(t)?;
        }
    }
    let input_json = crate::types::py_dict_to_json(input)?;

    // Primary authorization: the full 11-step ADR-016 UCAN pipeline over the
    // bridge-owned per-context UCAN state — IDENTICAL to `outlet_invoke_impl`.
    // The stream is validated ONCE at open (§5.4.5 "UCAN check locus");
    // chunks do not re-present.
    crate::outlets::validate_outlet_ucan(
        bi,
        context_id,
        outlet_id,
        ucan_token,
        caller_did,
        proof_tokens.as_ref(),
    )?;

    // §7.3.8 effective-caveat resolution from the VALIDATED invocation UCAN's
    // narrowed `nb` — mirrors `outlet_invoke_impl`. `ucan_cid` keys the owned
    // Class-S counters and anchors the §5.4.5 caveats binding.
    let invocation_ucan = scp_core::crypto::ucan::validate::parse_ucan(ucan_token)
        .map_err(|e| ScpPyError::ucan(format!("invalid invocation UCAN for '{outlet_id}': {e}")))?;
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
    // JCS(caveats))` and rejects a mismatch — so every input MUST agree with
    // what we pin here (dispatch.rs `verify_caveats_binding_at_open`).
    let request_id: [u8; 16] = *uuid::Uuid::now_v7().as_bytes();
    let caveats_jcs = caveats.to_canonical_json_bytes().map_err(|e| {
        ScpPyError::context(format!("failed to canonicalize effective caveats: {e}"))
    })?;
    let caveats_binding = compute_caveats_binding(
        ucan_cid.as_bytes(),
        &request_id,
        caller_did,
        estimated_chunk_count.unwrap_or(0),
        &caveats_jcs,
    );

    // Cost per Data chunk from the outlet's registered cost (§5.4.1). The
    // reserve/settle economy is the manager's concern; `available_balance` /
    // `reserved_escrow` are NOT consulted on the production open path (the
    // orchestrator sources the debited hold from its in-actor reserve).
    let cost_per_chunk = crate::runtime::with_context(bi, context_id, |rt| {
        let registration = rt.outlet_registry.get(outlet_id).ok_or_else(|| {
            ScpPyError::context(format!(
                "outlet '{outlet_id}' not registered in context '{context_id}'"
            ))
        })?;
        Ok(registration
            .cost
            .as_ref()
            .map_or(scp_core::economy::Amount::new(0), |c| c.amount))
    })?;

    // The OPERATOR signs every chunk that crosses the outer wire; the INVOKER
    // pubkey verifies grants + cancels. Resolve both through custody.
    let operator_did = crate::runtime::with_context(bi, context_id, |rt| {
        rt.outlet_registry
            .get(outlet_id)
            .map(|r| r.operator_did.0.clone())
            .ok_or_else(|| ScpPyError::context(format!("outlet '{outlet_id}' not registered")))
    })?;
    let operator_signer: Arc<dyn StreamSigner> =
        Arc::new(resolve_stream_signer(bi, &operator_did)?);
    let invoker_pk = *resolve_stream_signer(bi, caller_did)?.verifying_key();

    // Snapshot the registry + handler under the context guard, OUTSIDE the
    // runtime call (lock-split discipline from `outlet_invoke_impl`).
    let (registry, handler) = crate::runtime::with_context(bi, context_id, |rt| {
        Ok((
            rt.outlet_registry.clone(),
            rt.outlet_handlers.get(outlet_id).cloned(),
        ))
    })?;

    let stream_epoch = {
        let supervisor = crate::runtime::supervisor(bi)?;
        let rt = crate::runtime()?;
        rt.block_on(supervisor.local_mls_epoch(context_id))
            .unwrap_or(0)
    };

    let executor: Arc<dyn OutletExecutor> = Arc::new(BridgeStreamExecutor {
        handler,
        outlet_id: outlet_id.to_owned(),
        context_id: context_id.to_owned(),
        invoker_did: caller_did.to_owned(),
    });

    // LIVE revocation view for the runtime's authoritative re-check timer.
    let revocation_checker: Arc<
        dyn scp_core::crypto::ucan::validate::RevocationChecker + Send + Sync,
    > = Arc::new(BridgeStreamRevocationChecker {
        states: Arc::clone(&bi.ffi_bridge_state),
        context_id: context_id.to_owned(),
    });

    let identity = StreamIdentity {
        context_id: context_id.to_owned(),
        outlet_id: outlet_id.to_owned(),
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
        invoker_did: caller_did.to_owned(),
        // Direct (non-cross-context) open: the immediate invoker IS the origin
        // invoker. Cross-context stream forwarding — which would carry a
        // distinct origin — is separate future work (parity with the saga's
        // co-resident constraint).
        origin_invoker_did: caller_did.to_owned(),
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
    // reservation. `None` when the token narrows to nothing (parity with the
    // non-streaming free path).
    let value_caveat_binding = if has_caveats {
        Some(scp_core::context::outlets::InvocationCaveatBinding { caveats, ucan_cid })
    } else {
        None
    };

    let supervisor = crate::runtime::supervisor(bi)?;
    let outlet_id_typed: scp_core::context::outlets::OutletId = outlet_id.to_owned();
    let invoker_did_typed: scp_did::DID = caller_did.to_owned().into();
    let rt = crate::runtime()?;
    let mut handle = rt
        .block_on(async {
            supervisor
                .open_outlet_stream(
                    context_id,
                    &registry,
                    &outlet_id_typed,
                    input_json,
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
        })
        .map_err(|rejection| open_rejection_to_err(&rejection))?;

    // Detach the receiver (data plane) into its own lock so `poll_next` never
    // contends with the control plane.
    //
    // INVARIANT: `open_outlet_stream` always returns a fresh handle whose
    // receiver has NOT yet been taken (`StreamSessionHandle::receiver` is
    // `self.receiver.take()`, called exactly once — here — per handle), so this
    // is `Some` on the happy path. The `None` arm is therefore UNREACHABLE
    // under the runtime's postcondition; it exists purely as a fund-safety
    // backstop. `receiver()` is the ONLY fallible step AFTER the irreversible
    // reserve+spawn, so a bare `?` here would strand a spawned, ALREADY-BILLING
    // pump with no registry entry — nothing could ever drive `poll_next`,
    // `cancel`, or `terminate` against it, and its escrow would never settle.
    // Instead we force the pump to a terminal (which releases its escrow via
    // the pump's close-time settlement) before surfacing the error.
    let Some(receiver) = handle.receiver() else {
        // Unreachable: wind the pump down so its debited escrow is refunded
        // rather than stranded. `ContextClosedMidStream` is the least inaccurate
        // terminal — from the caller's view the consumer substrate failed to
        // attach.
        let _ = handle.terminate_with_error(TerminateReason::ContextClosedMidStream, None);
        return Err(ScpPyError::context(
            "stream handle returned without a chunk receiver (runtime invariant \
             violation) — pump terminated to release escrow"
                .to_owned(),
        )
        .into());
    };

    let handle_id = hex::encode(request_id);
    bi.outlet_stream_registry.insert(
        handle_id.clone(),
        StreamEntry {
            handle: Arc::new(tokio::sync::Mutex::new(handle)),
            receiver: Arc::new(tokio::sync::Mutex::new(receiver)),
            invoker_did: caller_did.to_owned(),
            context_id: context_id.to_owned(),
            outlet_id: outlet_id.to_owned(),
            caveats_binding,
            request_id,
            stream_epoch,
            cost_per_chunk,
            // §5.4.5 `monotonic_seq` starts at 0; the first grant's `fetch_add`
            // returns 0, the next 1, and so on — strictly increasing.
            grant_seq: std::sync::atomic::AtomicU64::new(0),
        },
    );
    Ok(handle_id)
}

// ---------------------------------------------------------------------------
// poll_next
// ---------------------------------------------------------------------------

/// Drains one chunk from a live stream, blocking on the global runtime until a
/// chunk arrives or the stream closes. Returns the JSON-serialized
/// [`OutletStreamChunk`] bytes, or `None` at the channel-closed sentinel. This
/// is the primitive the Python SDK's async iterator wraps.
///
/// # GIL / deadlock (CRITICAL)
///
/// The blocking `recv()` is wrapped in [`Python::allow_threads`] so the Python
/// GIL is RELEASED while `poll_next` parks. The streaming pump runs the
/// context's registered Python outlet handler on a detached tokio task, and
/// that handler REACQUIRES the GIL (`mcp.rs` `Python::with_gil`) to produce the
/// very chunk this call awaits. If `poll_next` held the GIL across `recv()`,
/// the consumer would park holding the GIL while the producer blocks trying to
/// take it — a guaranteed interpreter deadlock on the happy path. Releasing the
/// GIL here lets the producer run. Everything touching `Py`/`Bound` values
/// (there is nothing here) stays OUTSIDE `allow_threads`; the closure returns a
/// plain `Ungil` [`OutletStreamChunk`].
///
/// # Handle lifecycle
///
/// - **Unknown / evicted `handle_id`** → a DISTINCT [`no_active_stream_err`]
///   (matching the control-plane "no active outlet stream" contract), NEVER
///   `None` — a stale or typo'd handle must not masquerade as a clean terminal.
/// - **Terminal chunk** (`End` / `Error{terminal:true}`) → returned to the
///   caller AND the entry is EVICTED immediately, so a caller that reads the
///   stream to its terminal but never performs the trailing `None`-drain does
///   not leak the registry entry. A subsequent poll on the same handle then
///   surfaces [`no_active_stream_err`] (the stream is genuinely gone).
/// - **`None`** (channel closed with no terminal chunk — an abnormal close such
///   as a pump panic dropping the sender) → the entry is evicted and `None` is
///   returned as the terminal sentinel.
fn outlet_stream_poll_next_impl(
    py: Python<'_>,
    bi: &PyBridgeInstance,
    handle_id: &str,
) -> PyResult<Option<Vec<u8>>> {
    // Clone the receiver `Arc` OUT of the DashMap shard guard BEFORE the
    // blocking recv — never hold a DashMap ref across the `.await`
    // (the DashMap-ref-across-await hazard). An unknown handle is a distinct
    // error, not a terminal.
    let receiver = {
        let Some(entry) = bi.outlet_stream_registry.get(handle_id) else {
            return Err(no_active_stream_err(handle_id).into());
        };
        Arc::clone(&entry.receiver)
    };
    let rt = crate::runtime()?;
    // Release the GIL across the blocking recv (see the CRITICAL note above).
    let chunk = py.allow_threads(|| rt.block_on(async { receiver.lock().await.recv().await }));
    if let Some(chunk) = chunk {
        // Evict on the TERMINAL chunk so a run-to-terminal-without-draining
        // caller cannot leak the entry. The pump releases the admission counter
        // + escrow at the same terminal, so eviction here only reclaims the
        // bridge-side registry slot.
        if chunk.payload.is_terminal() {
            bi.outlet_stream_registry.remove(handle_id);
        }
        let bytes = serde_json::to_vec(&chunk)
            .map_err(|e| ScpPyError::context(format!("failed to serialize stream chunk: {e}")))?;
        Ok(Some(bytes))
    } else {
        // Abnormal terminal: the pump dropped the sender without a terminal
        // chunk. Evict so the handle + any residual control state drop with the
        // entry.
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
/// §5.4.5 `monotonic_seq` from the per-`StreamEntry` counter — so no SDK ever
/// needs the invoker key (ADR-006) or a caller-tracked replay counter, and the
/// public surface is a plain `u32`.
///
/// CRITICAL #1: rejects a `caller_did` that is not the pinned invoker with
/// `SCP-PERM-3001` before touching runtime state.
///
/// # Escrow / money-conservation
///
/// A grant EXTENDS the billable credit window, so it MUST be backed by a
/// corresponding escrow debit or the operator could bill beyond debited funds.
/// This routes through the runtime reserve/apply/reverse discipline:
///
/// 1. `Supervisor::outlet_stream_reserve_grant` DEBITS `cost_per_chunk × grant`
///    from the invoker's member budget (spec §5.4.5 "Credit-grant escrow
///    top-up"; `InsufficientFunds` / `EscrowOverflow` reject BEFORE any credit
///    is applied).
/// 2. `apply_credit_grant(credit, reserved)` extends the pump's escrow ledger by
///    exactly the debited hold.
/// 3. On ANY apply rejection (signature / replay / stream-closed) the debited
///    hold is REVERSED via `outlet_stream_reverse_grant`.
///
/// So `billed + refund == reserved` holds across open + every grant. The
/// fund-safety BACKSTOP that no quantity of grants can over-bill is the
/// invoker's CAVEAT CEILING — the §5.4.5:758 cumulative billable ceiling
/// `min(credit_window, max_calls)` pinned in the pump's `CreditTracker`
/// (`max_billable`), which clamps every replenishment. It is NOT `billed ≤
/// reserved` (which does not hold once grants extend the window — that is
/// exactly why each grant debits incrementally here).
fn outlet_stream_grant_credit_impl(
    py: Python<'_>,
    bi: &PyBridgeInstance,
    handle_id: &str,
    caller_did: &str,
    grant: u32,
) -> PyResult<()> {
    validate::validate_did(caller_did)?;

    // Look up the live stream, verify caller == pinned invoker (CRITICAL #1),
    // and copy/clone every pinned field the credit preimage + reserve need OUT
    // of the DashMap shard guard so no ref is held across the block_on (the
    // DashMap-ref-across-await hazard). The monotonic grant counter is bumped
    // here under the guard (a sync atomic op) — the first grant gets seq 0.
    //
    // NOTE: `monotonic_seq` is assigned here under the DashMap guard, but the
    // grant is APPLIED later under the SEPARATE per-handle lock. So two
    // concurrent self-grants (same handle_id, same invoker) can be assigned
    // seqs N and N+1 here, then apply in the opposite order under the handle
    // lock — the runtime's `CreditTracker` then rejects the lower seq as
    // `CreditReplay` (SCP-OUTLET-6110). This is fund-safe (the rejected grant's
    // reserve is reversed on the apply-reject path below), only spuriously
    // failing one of a racing pair; a well-behaved single-threaded caller never
    // races its own grants. If strict FIFO grant admission is ever required,
    // serialize seq-assign + apply under the handle lock.
    let (
        handle,
        context_id,
        outlet_id,
        caveats_binding,
        request_id,
        stream_epoch,
        cost_per_chunk,
        monotonic_seq,
    ) = {
        let entry = bi
            .outlet_stream_registry
            .get(handle_id)
            .ok_or_else(|| no_active_stream_err(handle_id))?;
        if caller_did != entry.invoker_did {
            return Err(caller_not_invoker_err(caller_did, &entry.invoker_did).into());
        }
        let monotonic_seq = entry
            .grant_seq
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        (
            Arc::clone(&entry.handle),
            entry.context_id.clone(),
            entry.outlet_id.clone(),
            entry.caveats_binding,
            entry.request_id,
            entry.stream_epoch,
            entry.cost_per_chunk,
            monotonic_seq,
        )
    };

    // Resolve the invoker's custody-backed signer (the key never enters the
    // runtime address space — ADR-006). Done off the DashMap ref.
    let signer = resolve_stream_signer(bi, caller_did)?;
    // §5.4.5 SCP-OUTLET-CREDIT-V1 preimage over the pinned stream identity.
    let preimage = compute_credit_sig_preimage(
        &context_id,
        &outlet_id,
        &request_id,
        grant,
        monotonic_seq,
        stream_epoch,
        &caveats_binding,
    );

    let supervisor = crate::runtime::supervisor(bi)?.clone();
    let invoker_did_typed: scp_did::DID = caller_did.to_owned().into();
    let rt = crate::runtime()?;

    // Sign (via custody) → reserve (DEBIT) → apply → reverse-on-reject, all with
    // the GIL released: the reserve routes through the actor mailbox and the
    // apply wakes the pump, which reacquires the GIL to produce chunks (the same
    // deadlock surface as `poll_next`). Every value below is `Ungil` (Arc /
    // String / arrays / DID / the plain `ScpPyError`); the `PyErr` conversion
    // happens outside `allow_threads`.
    let outcome: Result<(), ScpPyError> = py.allow_threads(|| {
        rt.block_on(async {
            // 1. Sign the credit grant through custody.
            let sig = signer
                .sign(&preimage)
                .await
                .map_err(|e| ScpPyError::context(format!("failed to sign credit grant: {e:?}")))?;
            let credit = OutletStreamCredit {
                request_id,
                grant,
                monotonic_seq,
                sig,
            };

            // 2. Reserve (DEBIT) the incremental escrow BEFORE extending credit.
            //    A reject here (InsufficientFunds / EscrowOverflow) leaves the
            //    credit window unchanged — no billing authorized.
            let reserved = supervisor
                .outlet_stream_reserve_grant(
                    &context_id,
                    &invoker_did_typed,
                    request_id,
                    cost_per_chunk,
                    grant,
                )
                .await
                .map_err(ScpPyError::from)?;

            // 3. Apply the signed grant against the debited hold. On rejection,
            //    REVERSE the reserve (CREDIT budget + un-bump the durable record,
            //    atomically) so the debit is not stranded (money-conservation).
            //    A `reverse_err` is logged-and-swallowed (the original grant
            //    error is the caller-facing outcome). It is safe in BOTH of its
            //    two forms, because the reverse runs under `commit_class_s_keep`
            //    which applies the budget-credit + record-un-bump IN MEMORY
            //    regardless of the persist outcome:
            //    - `PersistenceFailed` on a LIVE actor: the reverse HAS been
            //      applied in memory; only the durable write failed, and the
            //      actor run loop retries it (KEEP semantics). The credit is not
            //      lost.
            //    - `ContextNotRegistered`: the context has no live actor (being
            //      torn down), so its owned budget + crash-recovery record are
            //      moot anyway.
            //    There is NO sweep that would otherwise reconcile a stranded
            //    grant top-up, so the in-memory KEEP is the load-bearing
            //    safety mechanism, not any later reconcile.
            let apply = handle.lock().await.apply_credit_grant(&credit, reserved);
            match apply {
                Ok(_new_total) => Ok(()),
                Err(grant_err) => {
                    if let Err(reverse_err) = supervisor
                        .outlet_stream_reverse_grant(
                            &context_id,
                            &invoker_did_typed,
                            request_id,
                            reserved,
                        )
                        .await
                    {
                        tracing::warn!(
                            handle_id = %handle_id,
                            %reverse_err,
                            "outlet_stream_grant_credit: grant apply rejected AND the escrow \
                             reverse failed — reverse applied in memory (run loop retries the \
                             persist); an Err here means the context has no live actor (being \
                             torn down), so its budget + crash-recovery record are moot"
                        );
                    }
                    Err(ScpPyError::ContextError {
                        message: format!("credit grant rejected: {grant_err:?}"),
                        code: grant_error_to_code(grant_err).to_owned(),
                    })
                }
            }
        })
    });
    outcome.map_err(PyErr::from)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// cancel
// ---------------------------------------------------------------------------

/// Signs and applies a stream cancel at the RUNTIME-DERIVED cursor. CRITICAL
/// #1 (caller == invoker) + CRITICAL #3 (no caller `next_seq`): the runtime
/// reads its own live emission cursor and signs the `SCP-OUTLET-CANCEL-V1:`
/// preimage internally. The cancel signer is the INVOKER's custody key (the
/// runtime self-verifies the signature under the pinned `invoker_pk`).
fn outlet_stream_cancel_impl(
    py: Python<'_>,
    bi: &PyBridgeInstance,
    handle_id: &str,
    caller_did: &str,
) -> PyResult<()> {
    validate::validate_did(caller_did)?;
    let (handle, context_id, outlet_id, caveats_binding) =
        authorized_control(bi, handle_id, caller_did)?;
    let signer = resolve_stream_signer(bi, caller_did)?;
    let cancel_identity = CancelIdentity {
        context_id,
        outlet_id,
        caveats_binding,
    };
    let rt = crate::runtime()?;
    // Release the GIL across the runtime handle op (defense-in-depth). The
    // cancel signs via custody (no GIL) and wakes the pump — which reacquires
    // the GIL to produce its terminal chunk — so holding the GIL here while the
    // woken pump blocks on it is the same deadlock surface as `poll_next`. The
    // `StreamSignerError` inside the closure is `Ungil`; the caller-side signer
    // resolution (its own `block_on` never touches Python) stays outside.
    let cancel_result = py.allow_threads(|| {
        rt.block_on(async {
            handle
                .lock()
                .await
                .apply_outlet_cancel_signed(&signer, &cancel_identity)
                .await
        })
    });
    cancel_result.map_err(|e| ScpPyError::ContextError {
        message: format!("stream cancel rejected: {e:?}"),
        code: cancel_error_to_code(&e).to_owned(),
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// terminate
// ---------------------------------------------------------------------------

/// Forces a framework terminal chunk under the pinned operator key. CRITICAL
/// #1: caller must be the pinned invoker. The `slug` selects a closed-set
/// [`TerminateReason`] (free-form slugs are rejected — attacker input cannot
/// enter the provenance record); `message` is a non-canonical human suffix.
///
/// The canonical `code` is DERIVED internally from the reason
/// ([`TerminateReason::code`]) — it is a pure function of `slug`, so accepting
/// it as a parameter only created a way for a caller to disagree with the
/// reason (and forced every SDK to hard-code the slug→code table). Dropping it
/// makes the code unforgeable-by-construction and the signature agent-authable
/// from `slug` alone.
///
/// # Auth asymmetry (co-resident threat model)
///
/// `terminate` authorizes on the CRITICAL #1 assertion ALONE (`caller_did ==
/// pinned invoker`), whereas `grant_credit` carries an invoker Ed25519
/// signature over the credit preimage and `cancel` self-verifies a
/// custody-produced signature under the pinned `invoker_pk`. `terminate` needs
/// no signature because the terminal chunk it forces is signed by the OPERATOR
/// key (the framework-forced `Error{terminal:true}`), not attributed to the
/// invoker, and it can only ever CLOSE the stream (it cannot bill, extend
/// credit, or move the cancel-ack cursor). Under the co-resident single-tenant
/// constraint (operator + invoker both locally hosted, per the module header)
/// the assertion gate is sufficient: the only principal who could reach this
/// bridge instance is already trusted to host both keys. The asymmetry is
/// intentional, not an oversight.
fn outlet_stream_terminate_impl(
    py: Python<'_>,
    bi: &PyBridgeInstance,
    handle_id: &str,
    caller_did: &str,
    slug: &str,
    message: &str,
) -> PyResult<()> {
    validate::validate_did(caller_did)?;
    let reason = TerminateReason::from_slug(slug).ok_or_else(|| {
        ScpPyError::validation(format!(
            "unknown terminate slug '{slug}' — must be a §5.4.4 stream-terminal slug"
        ))
    })?;
    let (handle, _ctx, _outlet, _binding) = authorized_control(bi, handle_id, caller_did)?;
    let message_override = (!message.is_empty()).then(|| message.to_owned());
    let rt = crate::runtime()?;
    // Release the GIL across the runtime handle op (defense-in-depth; the forced
    // terminal wakes the pump, which reacquires the GIL). `AlreadyPending` /
    // `AlreadyTerminated` are the documented idempotent outcomes (the SDK treats
    // them as "stream already closing") — surface both as success so a
    // receiver-side recheck loop stops cleanly.
    let _ = py.allow_threads(|| {
        rt.block_on(async {
            handle
                .lock()
                .await
                .terminate_with_error(reason, message_override)
        })
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// Pure protocol wrappers (1:1)
// ---------------------------------------------------------------------------

/// Verifies a chunk's operator signature (pure; §5.4.5). `chunk_bytes` is the
/// JSON-serialized [`OutletStreamChunk`]; `operator_pk` / `caveats_binding`
/// are 32-byte values.
fn outlet_stream_verify_chunk_signature_impl(
    chunk_bytes: &[u8],
    operator_pk: &[u8],
    context_id: &str,
    outlet_id: &str,
    caveats_binding: &[u8],
) -> PyResult<bool> {
    let chunk: OutletStreamChunk = serde_json::from_slice(chunk_bytes)
        .map_err(|e| ScpPyError::validation(format!("invalid OutletStreamChunk bytes: {e}")))?;
    let pk_bytes = <[u8; 32]>::try_from(operator_pk)
        .map_err(|_| ScpPyError::validation("operator_pk must be 32 bytes".to_owned()))?;
    let operator_verifying_key = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|e| ScpPyError::validation(format!("operator_pk is not a valid key: {e}")))?;
    let binding = <[u8; 32]>::try_from(caveats_binding)
        .map_err(|_| ScpPyError::validation("caveats_binding must be 32 bytes".to_owned()))?;
    Ok(verify_chunk_signature(
        &chunk,
        &operator_verifying_key,
        context_id,
        outlet_id,
        &binding,
    ))
}

/// Computes the §5.4.5 `caveats_binding` (pure 1:1 wrapper). `request_id` is
/// 16 bytes; `effective_caveats_jcs` is the RFC 8785 JCS of the effective
/// caveats. Returns the 32-byte binding.
fn outlet_stream_compute_caveats_binding_impl(
    ucan_cid: &[u8],
    request_id: &[u8],
    invoker_did: &str,
    estimated_chunk_count: u32,
    effective_caveats_jcs: &[u8],
) -> PyResult<Vec<u8>> {
    let request_id = <[u8; 16]>::try_from(request_id)
        .map_err(|_| ScpPyError::validation("request_id must be 16 bytes".to_owned()))?;
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
// PyScp methods
// ---------------------------------------------------------------------------

#[pymethods]
impl crate::scp::PyScp {
    /// Opens a §5.4.5 streaming outlet invocation, returning a
    /// `StreamHandleId` PROMPTLY (Commit transition — never block-until-terminal).
    ///
    /// The UCAN is validated ONCE at open via the full 11-step ADR-016
    /// pipeline; the invoker is pinned for the stream's lifetime. Drive the
    /// stream via `outlet_stream_poll_next` / `_grant_credit` / `_cancel` /
    /// `_terminate` with the SAME `caller_did`.
    ///
    /// Named `outlet_stream_open` (not `outlet_invoke_stream`) so the whole
    /// streaming surface groups under the `outlet_stream_*` prefix — an agent
    /// searching that prefix finds the opener alongside `poll_next` /
    /// `grant_credit` / `cancel` / `terminate` (agent-first API design).
    ///
    /// # Errors
    ///
    /// Raises `UcanError` if authorization fails. Raises `ContextError`
    /// carrying a `SCP-OUTLET-NNNN` code if the open is rejected (admission
    /// caps, escrow, caveats binding, node pump ceiling, or a §7.3.8 caveat).
    #[pyo3(name = "outlet_stream_open")]
    #[pyo3(signature = (
        context_id, outlet_id, input, caller_did, ucan_token,
        proof_tokens=None, spending_ucan=None, timeout_ms=None, estimated_chunk_count=None,
    ))]
    #[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
    pub fn outlet_stream_open(
        &self,
        context_id: &str,
        outlet_id: &str,
        input: &Bound<'_, pyo3::types::PyDict>,
        caller_did: &str,
        ucan_token: &str,
        proof_tokens: Option<Vec<String>>,
        spending_ucan: Option<&str>,
        timeout_ms: Option<u32>,
        estimated_chunk_count: Option<u32>,
    ) -> PyResult<String> {
        outlet_stream_open_impl(
            &self.inner,
            context_id,
            outlet_id,
            input,
            caller_did,
            ucan_token,
            proof_tokens,
            spending_ucan,
            timeout_ms,
            estimated_chunk_count,
        )
    }

    /// Drains one chunk from a live stream, blocking until a chunk arrives or
    /// the stream closes. Returns the JSON-serialized `OutletStreamChunk`
    /// bytes, or `None` at the terminal (which evicts the stream).
    ///
    /// # Errors
    ///
    /// Raises `ContextError` if chunk serialization fails.
    #[pyo3(name = "outlet_stream_poll_next")]
    pub fn outlet_stream_poll_next(
        &self,
        py: Python<'_>,
        handle_id: &str,
    ) -> PyResult<Option<Vec<u8>>> {
        outlet_stream_poll_next_impl(py, &self.inner, handle_id)
    }

    /// Grants `grant` additional billable chunks of credit to a live stream.
    /// The bridge signs the `OutletStreamCredit` internally under the pinned
    /// invoker's custody key and auto-assigns the monotonic sequence, so the
    /// caller supplies only a `u32` — no key access, no replay-counter tracking.
    /// The grant debits `cost_per_chunk × grant` of escrow first
    /// (money-conservation), reversing it if the grant apply then rejects.
    ///
    /// # Errors
    ///
    /// Raises `ContextError` with `SCP-PERM-3001` if `caller_did` is not the
    /// pinned invoker; an escrow rejection (`InsufficientFunds` /
    /// `EscrowOverflow`) if the top-up debit fails; `SCP-OUTLET-NNNN` if the
    /// grant apply is rejected (bad signature, replay, or the stream already
    /// closed).
    #[pyo3(name = "outlet_stream_grant_credit")]
    pub fn outlet_stream_grant_credit(
        &self,
        py: Python<'_>,
        handle_id: &str,
        caller_did: &str,
        grant: u32,
    ) -> PyResult<()> {
        outlet_stream_grant_credit_impl(py, &self.inner, handle_id, caller_did, grant)
    }

    /// Signs and applies a stream cancel at the runtime-derived cursor
    /// (CRITICAL #3 — the bridge never supplies a `next_seq`).
    ///
    /// # Errors
    ///
    /// Raises `ContextError` with `SCP-PERM-3001` if `caller_did` is not the
    /// pinned invoker; `SCP-OUTLET-6110` on a signature/identity mismatch;
    /// `SCP-OUTLET-6160` (retryable) if the cursor advanced past the bounded
    /// retry budget.
    #[pyo3(name = "outlet_stream_cancel")]
    pub fn outlet_stream_cancel(
        &self,
        py: Python<'_>,
        handle_id: &str,
        caller_did: &str,
    ) -> PyResult<()> {
        outlet_stream_cancel_impl(py, &self.inner, handle_id, caller_did)
    }

    /// Forces a framework terminal chunk. `slug` selects a closed-set
    /// terminal reason; the canonical `code` is derived internally from the
    /// reason; `message` is a human suffix.
    ///
    /// # Errors
    ///
    /// Raises `ContextError` with `SCP-PERM-3001` if `caller_did` is not the
    /// pinned invoker; `ValidationError` if `slug` is not a stream-terminal
    /// slug.
    #[pyo3(name = "outlet_stream_terminate")]
    pub fn outlet_stream_terminate(
        &self,
        py: Python<'_>,
        handle_id: &str,
        caller_did: &str,
        slug: &str,
        message: &str,
    ) -> PyResult<()> {
        outlet_stream_terminate_impl(py, &self.inner, handle_id, caller_did, slug, message)
    }

    /// Pure wrapper: verifies a chunk's operator signature (§5.4.5).
    ///
    /// # Errors
    ///
    /// Raises `ValidationError` if a byte argument is malformed.
    #[pyo3(name = "outlet_stream_verify_chunk_signature")]
    pub fn outlet_stream_verify_chunk_signature(
        &self,
        chunk_bytes: &[u8],
        operator_pk: &[u8],
        context_id: &str,
        outlet_id: &str,
        caveats_binding: &[u8],
    ) -> PyResult<bool> {
        outlet_stream_verify_chunk_signature_impl(
            chunk_bytes,
            operator_pk,
            context_id,
            outlet_id,
            caveats_binding,
        )
    }

    /// Pure wrapper: computes the §5.4.5 `caveats_binding` (32 bytes).
    ///
    /// # Errors
    ///
    /// Raises `ValidationError` if `request_id` is not 16 bytes.
    #[pyo3(name = "outlet_stream_compute_caveats_binding")]
    pub fn outlet_stream_compute_caveats_binding(
        &self,
        ucan_cid: &[u8],
        request_id: &[u8],
        invoker_did: &str,
        estimated_chunk_count: u32,
        effective_caveats_jcs: &[u8],
    ) -> PyResult<Vec<u8>> {
        outlet_stream_compute_caveats_binding_impl(
            ucan_cid,
            request_id,
            invoker_did,
            estimated_chunk_count,
            effective_caveats_jcs,
        )
    }
}
