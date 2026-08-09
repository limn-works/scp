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
    // NOTE: the §5.4.5 `monotonic_seq` grant counter is NOT held here. It lives
    // exclusively in durable `Storage` under
    // `context/{context_id}/stream_credit_counter/{request_id}` (SCP-OUT-034
    // AC31) so it survives an SDK restart mid-stream and never regresses — an
    // in-memory `AtomicU64` reset to 0 on restart, re-issuing low seqs the
    // runtime `CreditTracker` rejects as `CreditReplay`. `grant_credit` reads,
    // increments, and persists it via
    // `scp_ffi_common::outlet_stream_credit::next_grant_monotonic_seq`.
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
/// §5.4.5 `monotonic_seq` from a DURABLE per-stream cursor — so no SDK ever
/// needs the invoker key (ADR-006) or a caller-tracked replay counter, and the
/// public surface is a plain `u32`.
///
/// CRITICAL #1: rejects a `caller_did` that is not the pinned invoker with
/// `SCP-PERM-3001` before touching runtime state.
///
/// # Crash-safe `monotonic_seq` (SCP-OUT-034 AC31)
///
/// The seq is sourced from durable [`Storage`](scp_platform::traits::Storage) under
/// `context/{context_id}/stream_credit_counter/{request_id}`, NOT an in-memory
/// counter: read the cursor, persist `+1` before signing, use the pre-increment
/// value (via
/// [`next_grant_monotonic_seq`](scp_ffi_common::outlet_stream_credit::next_grant_monotonic_seq)).
/// An SDK restart mid-stream reloads the persisted cursor, so a resumed grant's
/// seq is strictly greater than any prior in-flight value and the runtime
/// `CreditTracker` never rejects it as `CreditReplay`. The read-modify-write and
/// the grant apply run under the SAME per-stream control lock, so concurrent
/// self-grants receive strictly-ordered seqs.
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
// Durable-seq RMW + custody sign + reserve + apply + reverse-on-reject, plus the
// GIL-release plumbing, is one linear money-conservation sequence best read top
// to bottom — splitting it would hide the ordering invariant it exists to make
// legible.
#[allow(clippy::too_many_lines)]
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
    // DashMap-ref-across-await hazard). The `monotonic_seq` is NOT assigned here
    // — it comes from the durable per-stream cursor below (SCP-OUT-034 AC31).
    let (handle, context_id, outlet_id, caveats_binding, request_id, stream_epoch, cost_per_chunk) = {
        let entry = bi
            .outlet_stream_registry
            .get(handle_id)
            .ok_or_else(|| no_active_stream_err(handle_id))?;
        if caller_did != entry.invoker_did {
            return Err(caller_not_invoker_err(caller_did, &entry.invoker_did).into());
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

    // Clone the durable storage backend OUT of the instance (cheap `Arc` clone)
    // so the crash-safe `monotonic_seq` read-modify-write can run inside
    // `allow_threads`. The same backend that holds the event log / snapshots —
    // guaranteed present once a stream is open (storage-before-supervisor,
    // §17.6). Absent ⇒ fail closed rather than fabricate a non-durable seq.
    let storage = bi.storage_provider().cloned().ok_or_else(|| {
        ScpPyError::context(
            "no durable storage backend for stream credit counter (storage-before-supervisor \
             invariant violated)"
                .to_owned(),
        )
    })?;

    // Resolve the invoker's custody-backed signer (the key never enters the
    // runtime address space — ADR-006). Done off the DashMap ref.
    let signer = resolve_stream_signer(bi, caller_did)?;

    let supervisor = crate::runtime::supervisor(bi)?.clone();
    let invoker_did_typed: scp_did::DID = caller_did.to_owned().into();
    let rt = crate::runtime()?;

    // Durable-seq → sign (via custody) → reserve (DEBIT) → apply →
    // reverse-on-reject, all with the GIL released: the reserve routes through
    // the actor mailbox and the apply wakes the pump, which reacquires the GIL
    // to produce chunks (the same deadlock surface as `poll_next`). Every value
    // below is `Ungil` (Arc / String / arrays / DID / the plain `ScpPyError`);
    // the `PyErr` conversion happens outside `allow_threads`.
    let outcome: Result<(), ScpPyError> = py.allow_threads(|| {
        rt.block_on(async {
            // Hold the per-stream control lock across the WHOLE grant: the
            // durable seq read-modify-write, the sign, the reserve, and the
            // apply. This serializes seq-assign with apply so two concurrent
            // self-grants receive strictly-ordered seqs (fixing the prior
            // assign-under-DashMap-then-apply-under-handle-lock race), and — the
            // data plane uses the SEPARATE `receiver` lock, so a `poll_next`
            // parked awaiting a chunk is never blocked by this hold.
            let handle_guard = handle.lock().await;

            // 0. Crash-safe `monotonic_seq` (SCP-OUT-034 AC31): read the durable
            //    per-stream cursor, persist `+1` BEFORE signing, and use the
            //    pre-increment value. An SDK restart mid-stream reloads the
            //    persisted cursor, so the resumed grant's seq never regresses
            //    below any prior in-flight value.
            let monotonic_seq = scp_ffi_common::outlet_stream_credit::next_grant_monotonic_seq(
                &storage,
                &context_id,
                &request_id,
            )
            .await
            .map_err(|e| {
                ScpPyError::context(format!("failed to assign durable monotonic_seq: {e}"))
            })?;

            // §5.4.5 SCP-OUTLET-CREDIT-V1 preimage over the pinned stream
            // identity (now that the durable seq is known).
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
            //    Applied under the already-held `handle_guard` (the control lock
            //    acquired at the top of this block) — never re-lock `handle`
            //    here (the tokio `Mutex` is not reentrant, so a second
            //    `handle.lock().await` would deadlock).
            let apply = handle_guard.apply_credit_grant(&credit, reserved);
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
// Cross-context streaming saga (§5.4.5, §6.2.4, SCP-OUT-047) — open / poll /
// recover. The streaming ANALOG of the unary cross-context saga export in
// `outlets.rs`, sharing its `enforce_caller_principal_binding`,
// `resolve_context_signing_key`, `validate_outlet_ucan`, and `map_saga_error`
// verbatim, and the SAME `BridgeStreamExecutor` / `resolve_stream_signer` /
// `BridgeStreamRevocationChecker` this module already defines.
// ---------------------------------------------------------------------------

/// The control-plane "no active cross-context streaming saga" rejection for an
/// unknown, stale, typo'd, or already-evicted saga id. Shared by
/// [`outlet_streaming_saga_poll_next_impl`] and
/// [`outlet_streaming_saga_recover_truncated_close_impl`]. DISTINCT from a
/// genuine terminal (which `poll_next` reports as `None`) so a bad handle is
/// never mistaken for a clean stream end.
fn no_active_saga_err(saga_id: &str) -> ScpPyError {
    ScpPyError::context(format!(
        "no active cross-context streaming saga '{saga_id}'"
    ))
}

/// §5.4.5 / §6.2.4 cross-context streaming-saga open (SCP-OUT-047). The
/// streaming sibling of [`outlet_invoke_cross_context_saga`](crate::outlets)
/// and [`outlet_stream_open_impl`]: it validates the invocation UCAN at the
/// bridge (once, at open), drives
/// [`Supervisor::start_cross_context_streaming_outlet_invocation_saga`](scp_core::context::supervisor::Supervisor::start_cross_context_streaming_outlet_invocation_saga)
/// to the Commit-transition, and stores the promptly-returned receiver in the
/// per-instance saga registry keyed by the durable `saga_id`. Returns the
/// `saga_id` string PROMPTLY (AC1 — the Commit-transition, NOT a
/// block-until-terminal; the seal pumps off-mailbox).
///
/// Body ORDER is security-critical:
///   (a) validate inputs;
///   (b) `enforce_caller_principal_binding` on the CALLER axis (§6.2.4 Caller
///       authentication / ADR-049 §3a channel-auth) BEFORE anything
///       irreversible — the saga never observes an unauthenticated caller;
///   (c) `validate_outlet_ucan` against the TARGET context B (where the outlet
///       is registered), then resolve the effective §7.3.8 caveats + `ucan_cid`
///       and compute the §5.4.5 `caveats_binding` from a FRESH `request_id`;
///   (d) resolve `SagaSigningKeys { target, caller }` from each context's
///       Active Signing Key (via custody — the key never enters the runtime,
///       ADR-006);
///   (e) build the executor over the TARGET handler;
///   (f) drive the saga to the Commit-transition;
///   (g) register the receiver and return the `saga_id`.
///
/// SECURITY: the §5.4.5 `CrossContextVerificationDescriptor`
/// (`operator_pk` / `operating_context_id` / `outlet_id` / `caveats_binding` /
/// `expected_request_id`) is built RUNTIME-SIDE inside the saga method from
/// `phase1.params` — this bridge passes NONE of those from the caller/envelope.
/// `operator_signer` is resolved from the TARGET operator's custody,
/// `caveats_binding` is recomputed from the VALIDATED UCAN, and `request_id` is
/// freshly minted here (the runtime rejects a binding that does not match its
/// own recompute).
#[allow(clippy::too_many_arguments)] // Flat §6.2.4 streaming envelope — agent-first named params.
#[allow(clippy::needless_pass_by_value)] // PyO3 owned Option params.
#[allow(clippy::too_many_lines)] // UCAN validate + caveat binding + full OpenStreamParams + saga drive.
fn outlet_streaming_saga_open_impl(
    bi: &PyBridgeInstance,
    caller_context_id: &str,
    target_context_id: &str,
    caller_did: &str,
    outlet_registration_id: &str,
    input: &Bound<'_, pyo3::types::PyDict>,
    asserted_nonce_hex: &str,
    timestamp_ms: u64,
    chain_depth: u8,
    ucan_token: &str,
    proof_tokens: Option<Vec<String>>,
    ucan_proof_id: Option<String>,
    timeout_ms: Option<u32>,
    estimated_chunk_count: Option<u32>,
) -> PyResult<String> {
    // ----- (a) validate inputs ------------------------------------------------
    validate::validate_context_id(caller_context_id)?;
    validate::validate_context_id(target_context_id)?;
    validate::validate_outlet_id(outlet_registration_id)?;
    validate::validate_did(caller_did)?;
    validate::validate_ucan_token(ucan_token)?;
    // NOTE (SCP-OUT-047 review F3): the streaming-saga open carries NO
    // `spending_ucan`. The cross-context streaming escrow is B-side (§5.4.5
    // "Cross-context economy" — the invoker pays via the TARGET context's stream
    // escrow), and spending authorization for the outlet is carried by
    // `ucan_proof_id` (resolved target-side at Prepare-B), exactly as the unary
    // `outlet_invoke_cross_context_saga` sibling does. A `spending_ucan` JWT here
    // was validated-then-dropped — genuinely inert on this path — so it is not
    // accepted (no footgun in the streaming-saga template).
    if let Some(ref tokens) = proof_tokens {
        for t in tokens {
            validate::validate_ucan_token(t)?;
        }
    }
    let asserted_nonce = crate::outlets::decode_asserted_nonce(asserted_nonce_hex)?;
    let input_json = crate::types::py_dict_to_json(input)?;

    let supervisor = crate::runtime::supervisor(bi)?;
    let rt = crate::runtime()?;

    // ----- (a2) lifecycle gate: both contexts MUST be Active ------------------
    //
    // TARGET axis: DEFENSE-IN-DEPTH (#2196). CALLER/source axis: still primary.
    //
    // The runtime streaming-saga open path
    // (`start_cross_context_streaming_outlet_invocation_saga` →
    // `open_outlet_stream_phase1(&target_hex, ...)` → `reserve_outlet_stream_economy`)
    // NOW carries its own fail-closed `ContextState::Active` gate
    // (`ensure_context_active`, the FIRST predicate before any escrow debit)
    // surfacing the canonical `SCP-OUTLET-6080` "context not active". That
    // reserve runs on the TARGET context (the money moves there), so the runtime
    // gate is now the PRIMARY money-protecting barrier for the TARGET axis and
    // this bridge's target-axis check (`OUTLET_6011`) is demoted to
    // defense-in-depth. The reserve does NOT run on the CALLER/source context,
    // so this bridge's caller-axis check (`OUTLET_6010`) remains the authoritative
    // gate stopping a Closing / Expired / MigratingOut source from initiating a
    // money-moving cross-context streaming saga (§5.3 lifecycle / §6.2.4).
    // Retained regardless: both checks reject at the edge with bridge-native
    // codes before the drive even starts.
    //
    // PyO3 is string-keyed (no `ContextHandle`), so the authoritative lifecycle
    // state is read from the per-context supervisor actor via
    // `read_context_state` — the equivalent of the NAPI/UniFFI handle-state
    // guard. Checked BEFORE the caller-principal binding and the saga drive, so a
    // non-active context is rejected before any escrow debit or receiver hand-out.
    // Codes match NAPI/UniFFI: `OUTLET_6010` (caller axis) / `OUTLET_6011`
    // (target axis). A missing actor (`None`) is treated as non-active.
    //
    // SCP-OUT-031 PR-2a: STATE-FREE messages. These read the AUTHORITATIVE
    // supervisor state and run BEFORE the caller-principal binding, so the
    // pre-fix prose handed an unauthenticated caller the live lifecycle state.
    // The guards are retained; only the interpolation is removed.
    let caller_state = rt.block_on(supervisor.read_context_state(caller_context_id));
    if !matches!(caller_state, Some(scp_core::context::ContextState::Active)) {
        return Err(ScpPyError::ContextError {
            message: "cannot start cross-context streaming saga: caller context must be active"
                .to_owned(),
            code: scp_ffi_common::error_codes::OUTLET_6010.to_owned(),
        }
        .into());
    }
    let target_state = rt.block_on(supervisor.read_context_state(target_context_id));
    if !matches!(target_state, Some(scp_core::context::ContextState::Active)) {
        return Err(ScpPyError::ContextError {
            message: "cannot start cross-context streaming saga: target context must be active"
                .to_owned(),
            code: scp_ffi_common::error_codes::OUTLET_6011.to_owned(),
        }
        .into());
    }

    // ----- (b) caller-principal binding (CALLER axis) — BEFORE the saga runs --
    crate::outlets::enforce_caller_principal_binding(
        bi,
        supervisor,
        rt,
        caller_context_id,
        caller_did,
    )?;

    // ----- (c) validate the invocation UCAN against the TARGET context --------
    //
    // The outlet lives in the operating context B, so its registered kind +
    // per-context UCAN state (revocation list, nonce tracker, ceiling, proof
    // chain) are B's — IDENTICAL to `outlet_stream_open_impl`, just rebased onto
    // `target_context_id`. Validated ONCE at open (§5.4.5 "UCAN check locus").
    crate::outlets::validate_outlet_ucan(
        bi,
        target_context_id,
        outlet_registration_id,
        ucan_token,
        caller_did,
        proof_tokens.as_ref(),
    )?;

    let invocation_ucan =
        scp_core::crypto::ucan::validate::parse_ucan(ucan_token).map_err(|e| {
            ScpPyError::ucan(format!(
                "invalid invocation UCAN for '{outlet_registration_id}': {e}"
            ))
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
    // JCS(caveats))` and rejects a mismatch — so every input MUST agree with
    // what we pin here (identical to the same-context open).
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

    // ----- Outlet registration data (from the TARGET context B) ---------------
    let cost_per_chunk = crate::runtime::with_context(bi, target_context_id, |rt| {
        let registration = rt.outlet_registry.get(outlet_registration_id).ok_or_else(|| {
            ScpPyError::context(format!(
                "outlet '{outlet_registration_id}' not registered in context '{target_context_id}'"
            ))
        })?;
        Ok(registration
            .cost
            .as_ref()
            .map_or(scp_core::economy::Amount::new(0), |c| c.amount))
    })?;
    let operator_did = crate::runtime::with_context(bi, target_context_id, |rt| {
        rt.outlet_registry
            .get(outlet_registration_id)
            .map(|r| r.operator_did.0.clone())
            .ok_or_else(|| {
                ScpPyError::context(format!("outlet '{outlet_registration_id}' not registered"))
            })
    })?;
    let (registry, handler) = crate::runtime::with_context(bi, target_context_id, |rt| {
        Ok((
            rt.outlet_registry.clone(),
            rt.outlet_handlers.get(outlet_registration_id).cloned(),
        ))
    })?;

    // The OPERATOR (of the target outlet) signs every chunk that crosses the
    // outer wire; the INVOKER (caller) pubkey verifies grants + cancels. Both
    // resolved through this instance's custody (co-resident single-tenant).
    let operator_signer: Arc<dyn StreamSigner> =
        Arc::new(resolve_stream_signer(bi, &operator_did)?);
    let invoker_pk = *resolve_stream_signer(bi, caller_did)?.verifying_key();

    let stream_epoch = {
        let supervisor = crate::runtime::supervisor(bi)?;
        let rt = crate::runtime()?;
        rt.block_on(supervisor.local_mls_epoch(target_context_id))
            .unwrap_or(0)
    };

    let executor: Arc<dyn OutletExecutor> = Arc::new(BridgeStreamExecutor {
        handler,
        outlet_id: outlet_registration_id.to_owned(),
        context_id: target_context_id.to_owned(),
        invoker_did: caller_did.to_owned(),
    });

    // LIVE revocation view (B's per-context list) for the runtime pump's
    // authoritative re-check timer.
    let revocation_checker: Arc<
        dyn scp_core::crypto::ucan::validate::RevocationChecker + Send + Sync,
    > = Arc::new(BridgeStreamRevocationChecker {
        states: Arc::clone(&bi.ffi_bridge_state),
        context_id: target_context_id.to_owned(),
    });

    let identity = StreamIdentity {
        context_id: target_context_id.to_owned(),
        outlet_id: outlet_registration_id.to_owned(),
        stream_epoch,
        caveats_binding,
    };

    // The caps + the four timing/window policy fields are SERVER POLICY: the
    // saga's `open_outlet_stream_phase1` OVERWRITES them AUTHORITATIVELY from the
    // TARGET context's `ContextParams` (§5.4.5 / SCP-OUT-034), so the values here
    // are placeholders the runtime discards — identical to the same-context open.
    let params = OpenStreamParams {
        identity,
        caps: AdmissionCaps {
            per_invoker: 0,
            per_origin_invoker: 0,
            per_outlet: 0,
        },
        invoker_did: caller_did.to_owned(),
        // The immediate invoker IS the origin invoker on this co-resident open
        // (parity with the same-context path + the saga's co-resident constraint).
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

    // §7.3.8 value-caveat binding — `Some` iff the token carries caveats (do NOT
    // pass `None` when caveats are present: that would drop the per-edge narrow +
    // counter reservation the pump enforces). `ucan_cid` present iff caveats are,
    // by construction.
    let value_caveat_binding = if has_caveats {
        Some(scp_core::context::outlets::InvocationCaveatBinding { caveats, ucan_cid })
    } else {
        None
    };

    // ----- (d) signing keys: each co-resident context's Active Signing Key ----
    let target_signing_key = crate::outlets::resolve_context_signing_key(bi, target_context_id)?;
    let caller_signing_key = crate::outlets::resolve_context_signing_key(bi, caller_context_id)?;

    // ----- Chokepoint (ADR-056): id STRING → [u8; 32] -------------------------
    let caller_context_bytes = scp_core::context::state::context_id_to_bytes(caller_context_id);
    let target_context_bytes = scp_core::context::state::context_id_to_bytes(target_context_id);

    let outlet_id_typed: scp_core::context::outlets::OutletId = outlet_registration_id.to_owned();
    let caller_did_typed: scp_did::DID = caller_did.to_owned().into();

    // ----- (f) drive the saga to the Commit-transition ------------------------
    //
    // `block_on` resolves at the Commit-transition (AC1) — the seal task is
    // SPAWNED, so this returns the receiver PROMPTLY, before the stream drains.
    // PyO3 calls are sync and the Python SDK wrapper invokes us off
    // `asyncio.to_thread`, so we are not inside a tokio context (matches the
    // unary saga export).
    let supervisor = crate::runtime::supervisor(bi)?.clone();
    let rt = crate::runtime()?;
    let handle = rt
        .block_on(async {
            supervisor
                .start_cross_context_streaming_outlet_invocation_saga(
                    caller_context_bytes,
                    target_context_bytes,
                    caller_did_typed,
                    outlet_registration_id.to_owned(),
                    ucan_proof_id,
                    &registry,
                    &outlet_id_typed,
                    input_json,
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
                )
                .await
        })
        .map_err(crate::outlets::map_saga_error)?;

    // ----- (g) register the promptly-returned receiver ------------------------
    //
    // Destructured by field (the fields are `pub`) so the runtime type need not
    // be named. The registry key is the durable `saga_id` string.
    let saga_id = handle.saga_id;
    let receiver = handle.receiver;
    let handle_id = saga_id.0.clone();
    bi.outlet_streaming_saga_registry.insert(
        handle_id.clone(),
        scp_ffi_common::streaming_saga::StreamingSagaEntry {
            receiver: Arc::new(tokio::sync::Mutex::new(receiver)),
            saga_id,
            target_context_id: target_context_id.to_owned(),
            invoker_did: caller_did.to_owned(),
            request_id,
        },
    );
    Ok(handle_id)
}

/// Drains one chunk from a live cross-context streaming saga, blocking on the
/// global runtime until a chunk arrives or the stream closes. Returns the
/// JSON-serialized [`OutletStreamChunk`] bytes (A's plaintext operator-signed
/// chunk, forwarded verbatim), or `None` at the channel-closed sentinel.
///
/// Mirrors [`outlet_stream_poll_next_impl`]: the GIL is RELEASED across the
/// blocking `recv()` (the seal task runs the Python outlet handler, which
/// reacquires the GIL to produce the chunk this call awaits — holding the GIL
/// here would deadlock), an unknown/evicted saga id is a DISTINCT
/// [`no_active_saga_err`] (never `None`), and a terminal chunk EVICTS the entry
/// so a run-to-terminal caller cannot leak it.
///
/// The chunk is A's plaintext operator-signed frame. A downstream SDK consumer
/// composes this with the EXISTING A-context messaging to re-seal it for A's
/// other members (§5.4.5:568); no new primitive is introduced here.
///
/// Takes NO `caller_did`: the receiver is a single-consumer channel handed to
/// the opener at the Commit-transition, so possession of the `saga_id` handle IS
/// the read capability — there is no per-poll principal to re-authorize (mirrors
/// the same-context [`outlet_stream_poll_next_impl`]).
fn outlet_streaming_saga_poll_next_impl(
    py: Python<'_>,
    bi: &PyBridgeInstance,
    saga_id: &str,
) -> PyResult<Option<Vec<u8>>> {
    // Clone the receiver `Arc` OUT of the DashMap shard guard BEFORE the blocking
    // recv — never hold a DashMap ref across the `.await`.
    let receiver = {
        let Some(entry) = bi.outlet_streaming_saga_registry.get(saga_id) else {
            return Err(no_active_saga_err(saga_id).into());
        };
        Arc::clone(&entry.receiver)
    };
    let rt = crate::runtime()?;
    // Release the GIL across the blocking recv (see the deadlock note above).
    let chunk = py.allow_threads(|| rt.block_on(async { receiver.lock().await.recv().await }));
    if let Some(chunk) = chunk {
        let (bytes, terminal) = scp_ffi_common::streaming_saga::serialize_saga_chunk(&chunk)
            .map_err(|e| {
                ScpPyError::context(format!("failed to serialize saga stream chunk: {e}"))
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

// NO live control plane for the cross-context saga stream. Unlike the
// same-context surface (which has `grant_credit` / `cancel` / `terminate`), the
// cross-context saga stream has NO live mid-stream grant/cancel channel: per
// §6.2.5 / SCP-OUT-046 the cross-context stream runs with
// `cancel_ack_ceiling = u64::MAX` and no live-cancel is specced. If/when a live
// mid-stream `OutletCancel` channel is specced for the cross-context path,
// SCP-OUT-047 owns adding the corresponding control-plane exports here; until
// then the only lifecycle operations are open → poll → (in-session
// reconnect/repair) recover.

/// Key-bearing in-session reconnect/repair truncated-close for a cross-context
/// streaming saga (SCP-OUT-046 #136 AC7). The FFI-reconnect surface that
/// AUTHENTICATES the caller and supplies the TARGET's Active Signing Key to
/// [`Supervisor::recover_streaming_saga_truncated_close`](scp_core::context::supervisor::Supervisor::recover_streaming_saga_truncated_close)
/// via the shared [`drive_recover_truncated_close`](scp_ffi_common::streaming_saga::drive_recover_truncated_close)
/// driver. Seals B's durable prefix and resolves the saga `Committed` WITHOUT
/// re-opening the stream or re-invoking the executor.
///
/// This is IN-SESSION reconnect/repair of a seal that stalled or went
/// `NeedsRepair` while THIS bridge process is still ALIVE (e.g. a client
/// disconnects and reconnects to the same live node). The saga registry is
/// per-instance and IN-MEMORY, so this does NOT survive a process/node restart —
/// cross-restart recovery replays the durable saga journal via a separate
/// operator path (§17.16), NOT this FFI surface.
///
/// Auth (TWO gates, both required):
///   1. `caller_did` MUST be an identity THIS bridge instance hosts (the
///      co-resident channel-authenticated principal, §6.2.4) — the reconnect leg
///      is not a free envelope assertion.
///   2. `caller_did` MUST equal the `invoker_did` pinned at open (CRITICAL #1).
///      Recovery is MONEY-MOVING — it bills the invoker / credits the operator
///      over B's durable prefix and marks the saga `Committed` — so it carries
///      the SAME invoker gate as the same-context `grant_credit` / `cancel` /
///      `terminate` siblings (reject `SCP-PERM-3001`). The hosted-identity check
///      ALONE would let ANY co-resident identity settle a stranger's saga.
///
/// The Active Signing Key is resolved PER-CALL from the target context's custody
/// (the runtime holds none autonomously, ADR-006) — NEVER envelope-asserted, and
/// never resolved before BOTH gates pass. On success the registry entry is
/// EVICTED (the saga is now Committed; a second recover surfaces "no active saga"
/// rather than re-driving the settle).
fn outlet_streaming_saga_recover_truncated_close_impl(
    bi: &PyBridgeInstance,
    saga_id: &str,
    caller_did: &str,
) -> PyResult<()> {
    validate::validate_did(caller_did)?;

    // Authenticate the reconnect caller: it MUST be an identity hosted by this
    // bridge instance (the co-resident channel-authenticated principal, §6.2.4).
    if !crate::runtime::identity_registry_contains(bi, caller_did) {
        return Err(ScpPyError::context(format!(
            "caller_did '{caller_did}' is not an identity hosted by this bridge instance — the \
             streaming-saga reconnect recovery caller MUST be the channel-authenticated principal \
             (§6.2.4 Caller authentication), not an envelope-asserted value"
        ))
        .into());
    }

    // Look up the live saga entry for the durable `saga_id`, pinning its target
    // context (whose Active Signing Key seals the receipt), the `SagaId`, and the
    // `invoker_did` pinned at open.
    let (saga_id_typed, target_context_id, invoker_did) = {
        let Some(entry) = bi.outlet_streaming_saga_registry.get(saga_id) else {
            return Err(no_active_saga_err(saga_id).into());
        };
        (
            entry.saga_id.clone(),
            entry.target_context_id.clone(),
            entry.invoker_did.clone(),
        )
    };

    // CRITICAL #1: recovery is MONEY-MOVING (bills the invoker / credits the
    // operator over B's durable prefix, marks the saga `Committed`), so ONLY the
    // invoker pinned at open may drive it — the SAME `SCP-PERM-3001` gate the
    // same-context grant/cancel/terminate siblings enforce. Rejected BEFORE the
    // signing key is resolved or the recovery driver runs, so a non-invoker
    // never triggers a settle.
    if caller_did != invoker_did {
        return Err(caller_not_invoker_err(caller_did, &invoker_did).into());
    }

    // Resolve the TARGET context's Active Signing Key per-call from custody
    // (never envelope-asserted) and seal via the shared recovery driver.
    let target_key = crate::outlets::resolve_context_signing_key(bi, &target_context_id)?;
    let signing_key =
        scp_core::context::actor::commands::SigningKeyBytes::from_signing_key(&target_key);
    let supervisor = crate::runtime::supervisor(bi)?.clone();
    let rt = crate::runtime()?;
    rt.block_on(async {
        scp_ffi_common::streaming_saga::drive_recover_truncated_close(
            &supervisor,
            saga_id_typed,
            &target_context_id,
            signing_key,
        )
        .await
    })
    .map_err(crate::outlets::map_saga_error)?;

    // Evict on SUCCESS (MUST FIX #2): the saga is now `Committed` and its prefix
    // sealed. Without this the entry would self-clean only on the next
    // `poll_next` (a bounded leak), and a stale second recover would re-drive the
    // settle — after eviction it surfaces "no active saga" instead.
    bi.outlet_streaming_saga_registry.remove(saga_id);
    Ok(())
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

    /// Opens a §5.4.5 / §6.2.4 CROSS-CONTEXT streaming outlet invocation as a
    /// saga (SCP-OUT-047), returning the durable `saga_id` PROMPTLY (the
    /// Commit-transition — NOT a block-until-terminal; the seal pumps
    /// off-mailbox). Drive the stream via `outlet_streaming_saga_poll_next` with
    /// the returned `saga_id`.
    ///
    /// The invocation UCAN is validated ONCE at open via the full 11-step
    /// ADR-016 pipeline against the TARGET context B. `caller_did` is bound to
    /// this bridge instance's channel-authenticated principal (§6.2.4) and must
    /// be a member of `caller_context_id` — a mismatch raises `SagaAbortedError`
    /// BEFORE the saga runs, so the receiver is never handed out.
    ///
    /// # Errors
    ///
    /// Raises `SagaAbortedError` (SCP-SAGA-13050) if the caller-principal
    /// binding fails; `UcanError` if authorization fails; a saga terminal error
    /// (`SagaAbortedError` / `SagaNeedsRepairError` / `SagaBusyError`) if the
    /// Prepare/Commit-transition is rejected; `ValidationError` if an
    /// id/DID/outlet-id is malformed or `asserted_nonce_hex` is not 16 bytes.
    #[pyo3(name = "outlet_streaming_saga_open")]
    #[pyo3(signature = (
        caller_context_id, target_context_id, caller_did, outlet_registration_id,
        input, asserted_nonce_hex, timestamp_ms, chain_depth, ucan_token,
        proof_tokens=None, ucan_proof_id=None, timeout_ms=None,
        estimated_chunk_count=None,
    ))]
    #[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
    pub fn outlet_streaming_saga_open(
        &self,
        caller_context_id: &str,
        target_context_id: &str,
        caller_did: &str,
        outlet_registration_id: &str,
        input: &Bound<'_, pyo3::types::PyDict>,
        asserted_nonce_hex: &str,
        timestamp_ms: u64,
        chain_depth: u8,
        ucan_token: &str,
        proof_tokens: Option<Vec<String>>,
        ucan_proof_id: Option<String>,
        timeout_ms: Option<u32>,
        estimated_chunk_count: Option<u32>,
    ) -> PyResult<String> {
        outlet_streaming_saga_open_impl(
            &self.inner,
            caller_context_id,
            target_context_id,
            caller_did,
            outlet_registration_id,
            input,
            asserted_nonce_hex,
            timestamp_ms,
            chain_depth,
            ucan_token,
            proof_tokens,
            ucan_proof_id,
            timeout_ms,
            estimated_chunk_count,
        )
    }

    /// Drains one chunk from a live cross-context streaming saga, blocking until
    /// a chunk arrives or the stream closes. Returns the JSON-serialized
    /// `OutletStreamChunk` bytes (A's plaintext operator-signed frame), or
    /// `None` at the terminal (which evicts the saga stream).
    ///
    /// # Errors
    ///
    /// Raises `ContextError` for an unknown/evicted `saga_id` (DISTINCT from a
    /// clean terminal, which returns `None`) or if chunk serialization fails.
    #[pyo3(name = "outlet_streaming_saga_poll_next")]
    pub fn outlet_streaming_saga_poll_next(
        &self,
        py: Python<'_>,
        saga_id: &str,
    ) -> PyResult<Option<Vec<u8>>> {
        outlet_streaming_saga_poll_next_impl(py, &self.inner, saga_id)
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
    /// Raises `ContextError` if `caller_did` is not hosted by this instance or
    /// the `saga_id` is unknown; `ContextError` with `SCP-PERM-3001` if
    /// `caller_did` is hosted but is not the pinned invoker; a saga terminal
    /// error (`SagaNeedsRepairError`) if the seal cannot complete (the saga stays
    /// unresolved for a later retry).
    #[pyo3(name = "outlet_streaming_saga_recover_truncated_close")]
    pub fn outlet_streaming_saga_recover_truncated_close(
        &self,
        saga_id: &str,
        caller_did: &str,
    ) -> PyResult<()> {
        outlet_streaming_saga_recover_truncated_close_impl(&self.inner, saga_id, caller_did)
    }
}

// ---------------------------------------------------------------------------
// Test-only registry seam (SCP-OUT-047 review — recover invoker gate)
// ---------------------------------------------------------------------------

/// TEST-ONLY helpers on [`PyScp`](crate::scp::PyScp). NOT a `#[pymethods]` block,
/// so nothing here is exported to Python or counted by the bridge-symmetry gate.
/// Gated on the same test/testing features as `PyScp::new_in_memory_for_test`.
#[cfg(any(test, feature = "testing"))]
impl crate::scp::PyScp {
    /// Injects a live cross-context streaming-saga registry entry pinned to
    /// `invoker_did`, so the recover invoker-gate (CRITICAL #1) can be exercised
    /// without driving a full committed cross-context saga (whose
    /// actor-state/budget injection has no bridge-public wiring — same rationale
    /// as the unary-saga bridge tests). The receiver's sender is dropped
    /// immediately (recover never polls it).
    pub fn insert_test_streaming_saga_entry(
        &self,
        saga_id: &str,
        target_context_id: &str,
        invoker_did: &str,
    ) {
        let (_tx, rx) = mpsc::channel(1);
        self.inner.outlet_streaming_saga_registry.insert(
            saga_id.to_owned(),
            scp_ffi_common::streaming_saga::StreamingSagaEntry {
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
    /// did NOT evict a stranger's saga (and that a successful recover DOES evict).
    #[must_use]
    pub fn test_streaming_saga_entry_present(&self, saga_id: &str) -> bool {
        self.inner
            .outlet_streaming_saga_registry
            .contains_key(saga_id)
    }

    /// TEST-ONLY: reports whether the streaming-saga registry has NO live
    /// entries — lets a test assert a rejected open (e.g. the non-active-context
    /// guard) started NO saga and handed out NO receiver.
    #[must_use]
    pub fn test_streaming_saga_registry_is_empty(&self) -> bool {
        self.inner.outlet_streaming_saga_registry.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Crash-safe monotonic_seq (SCP-OUT-034 AC31)
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod monotonic_seq_crash_safety_tests {
    use scp_ffi_common::outlet_stream_credit::next_grant_monotonic_seq;
    use scp_platform::sqlite::SqliteStorage;

    /// SCP-OUT-034 AC31: an SDK restart mid-stream must NOT regress the §5.4.5
    /// `monotonic_seq`. This exercises the EXACT durable-cursor code
    /// `outlet_stream_grant_credit` uses (`next_grant_monotonic_seq`) against a
    /// real on-disk `SQLCipher` database that is genuinely dropped (the SDK
    /// process dying) and reopened from the same path — so the in-memory stream
    /// registry / any in-memory counter is truly gone and the resumed seq can
    /// only come from durable storage.
    #[tokio::test]
    async fn sdk_restart_midstream_does_not_regress_monotonic_seq() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0x42u8; 32];
        let ctx = "ctx-crash";
        let request_id = [0x9Au8; 16];

        // --- Session 1: open durable storage, issue several grants mid-stream,
        //     capturing the assigned (strictly-increasing) in-flight seqs. ---
        let mut in_flight = Vec::new();
        {
            let storage = SqliteStorage::new(dir.path(), &key).unwrap();
            for _ in 0..3 {
                let seq = next_grant_monotonic_seq(&storage, ctx, &request_id)
                    .await
                    .unwrap();
                in_flight.push(seq);
            }
            // Release the advisory lock exactly as `SCP.shutdown()` does before
            // the handle drops at the end of this scope. After this block the
            // storage — and any in-memory state — is GONE.
            storage.close();
        }
        assert_eq!(in_flight, vec![0, 1, 2], "grants advance strictly by one");
        let prior_max = *in_flight.iter().max().unwrap();

        // --- Simulated SDK restart: a brand-new storage handle over the SAME
        //     on-disk database. No in-memory seq survives the drop; the cursor
        //     is reloaded purely from durable storage. ---
        let storage2 = SqliteStorage::new(dir.path(), &key).unwrap();
        let resumed = next_grant_monotonic_seq(&storage2, ctx, &request_id)
            .await
            .unwrap();

        // AC31: the resumed seq is STRICTLY greater than every prior in-flight
        // value — so the runtime `CreditTracker` accepts it rather than
        // rejecting it as `CreditReplay`.
        assert!(
            resumed > prior_max,
            "resumed monotonic_seq {resumed} must strictly exceed prior in-flight max {prior_max}"
        );
        assert_eq!(resumed, 3, "the cursor continues from the persisted value");
        storage2.close();
    }
}
