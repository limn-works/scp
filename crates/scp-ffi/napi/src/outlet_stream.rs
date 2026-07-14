//! napi-rs bridge for §5.4.5 streaming-native outlet invocation
//! (SCP-OUT-037, sub-chunk C8a).
//!
//! Mirrors the CANONICAL `PyO3` reference bridge
//! (`crates/scp-ffi/src/outlet_stream.rs`, C7): same operation names, same
//! semantics, same two CRITICAL invariants. It wraps the runtime control
//! surface [`Supervisor::open_outlet_stream`](scp_core::context::supervisor::Supervisor::open_outlet_stream)
//! and [`StreamSessionHandle`] into six `Scp` methods plus two pure 1:1
//! wrappers:
//!
//! - [`outlet_stream_open_on`] — open a stream (Commit-transition: returns a
//!   `StreamHandleId` PROMPTLY; NEVER blocks until terminal).
//! - [`outlet_stream_poll_next_on`] — drain one chunk (`None` == closed).
//! - [`outlet_stream_grant_credit_on`] — apply an invoker-signed grant.
//! - [`outlet_stream_cancel_on`] — sign+apply a cancel at the runtime-derived
//!   cursor.
//! - [`outlet_stream_terminate_on`] — force a framework terminal.
//! - [`outlet_stream_verify_chunk_signature_impl`] /
//!   [`outlet_stream_compute_caveats_binding_impl`] — pure wrappers.
//!
//! # The one thing that differs from the `PyO3` reference: the async model
//!
//! napi-rs bridges a Rust `async fn` future directly to a JS `Promise` on the
//! module tokio runtime — there is NO `block_on`, NO GIL, and therefore NONE of
//! the `Python::allow_threads` GIL-deadlock machinery the `PyO3` reference
//! needs. `poll_next` / `grant_credit` / `cancel` / `terminate` are native
//! `async fn`s that `await` the chunk receiver / actor mailbox directly. The
//! equivalent hazard we DO still guard is holding a `DashMap` shard guard across
//! an `.await`: every control-plane op clones the `Arc`s it needs OUT of the
//! registry guard and drops the guard BEFORE awaiting (the
//! DashMap-ref-across-await hazard).
//!
//! # Two CRITICAL invariants enforced here
//!
//! - **CRITICAL #1 (caller == pinned invoker).** `invoker_did` is pinned in the
//!   per-instance [`StreamEntry`] at open. Every control-plane call
//!   (`grant_credit`, `cancel`, `terminate`) rejects a `caller_did` that is not
//!   the pinned invoker with `SCP-PERM-3001` BEFORE touching runtime state.
//! - **CRITICAL #3 (runtime-derived cancel cursor).** The bridge NEVER supplies
//!   a `next_seq`. `outlet_stream_cancel_on` calls
//!   [`StreamSessionHandle::apply_outlet_cancel_signed`], which reads the
//!   runtime's own live emission cursor and signs the `SCP-OUTLET-CANCEL-V1:`
//!   preimage over it internally — closing the forged-cursor billing surface.
//!
//! # Per-instance, never a global
//!
//! The stream registry is a per-instance field on
//! [`NapiBridgeInstance`](crate::runtime::NapiBridgeInstance)
//! (`outlet_stream_registry`), NOT a `static` — `check-no-bridge-globals.sh` /
//! `check-handle-affinity.sh` forbid the alternative. A stream opened on one
//! instance is invisible to another, and instance shutdown drops every live
//! stream with the `Arc`.
//!
//! # Co-resident custody
//!
//! Chunk signatures are produced by the OUTLET OPERATOR's key and cancel
//! signatures by the INVOKER's key. Both are resolved through this bridge
//! instance's identity registry (the operator identity + the invoker identity
//! must be locally hosted). This mirrors the co-resident single-tenant
//! constraint of the cross-context saga export in `outlets.rs`.

use std::sync::Arc;

use dashmap::DashMap;
use ed25519_dalek::VerifyingKey;
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

use scp_ffi_common::error_codes as codes;
use scp_ffi_common::validate::{validate_did, validate_outlet_id, validate_ucan_token};

use crate::context::NapiContextHandle;
use crate::error::ScpNapiError;
use crate::runtime::{NapiBridgeInstance, OutletHandler};

// ---------------------------------------------------------------------------
// StreamEntry — the per-instance registry value
// ---------------------------------------------------------------------------

/// One live stream tracked in
/// [`NapiBridgeInstance::outlet_stream_registry`](crate::runtime::NapiBridgeInstance).
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
    stream_epoch: scp_core::context::outlets::stream::MlsEpoch,
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
/// this bridge instance.
struct BridgeCustodyStreamSigner {
    /// The custody provider for the signing identity.
    custody: Arc<crate::custody::NapiKeyCustody>,
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
/// (its Active Signing Key).
///
/// Clones the custody `Arc` + key handle OUT of the identity-registry shard
/// guard (sync), then performs the (potentially slow) `public_key` export OFF
/// the guard — the same clone-then-drop discipline as the saga export's
/// `resolve_context_signing_key`.
async fn resolve_stream_signer(
    bi: &NapiBridgeInstance,
    identity_did: &str,
) -> Result<BridgeCustodyStreamSigner, ScpNapiError> {
    let (custody, handle) = crate::runtime::with_identity(bi, identity_did, |entry| {
        Ok((entry.custody.clone(), entry.identity.active_signing_key))
    })?;
    let public_key = custody
        .public_key(&handle)
        .await
        .map_err(|e| ScpNapiError::Context {
            message: format!("failed to resolve stream signing key for '{identity_did}': {e}"),
            code: codes::CTX_2001.to_owned(),
        })?;
    let verifying_key = scp_ffi_common::export_verify::verifying_key_from_public_key(&public_key)
        .ok_or_else(|| ScpNapiError::Context {
        message: format!(
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
// NapiStreamRevocationChecker — LIVE per-context revocation view
// ---------------------------------------------------------------------------

/// [`RevocationChecker`](scp_core::crypto::ucan::validate::RevocationChecker)
/// giving the runtime pump a LIVE view of this instance's per-context
/// revocation list, so the §5.4.5 authoritative UCAN-revocation re-check timer
/// (`stream_ucan_recheck_secs`) observes revocations that land AFTER the stream
/// opened — not a stale open-time snapshot.
///
/// Holds an `Arc` clone of the per-instance UCAN-state registry and the hosting
/// context id; `is_revoked` does a brief (sync, no-`await`) `DashMap` lookup per
/// tick. A vanished context returns `false` — the separate
/// context-closed-mid-stream termination path handles substrate loss.
struct NapiStreamRevocationChecker {
    states: Arc<DashMap<String, crate::runtime::UcanContextState>>,
    context_id: String,
}

impl scp_core::crypto::ucan::validate::RevocationChecker for NapiStreamRevocationChecker {
    fn is_revoked(&self, token_cid: &str) -> bool {
        self.states
            .get(&self.context_id)
            .is_some_and(|state| state.core.revocation_list.is_revoked(token_cid))
    }
}

// ---------------------------------------------------------------------------
// NapiStreamExecutor — adapts the registered single-shot handler
// ---------------------------------------------------------------------------

/// [`OutletExecutor`] wrapping the context's registered outlet handler (an
/// `Arc<dyn Fn(Value) -> Result<Value, String>>`) — identical dispatch
/// semantics to the non-streaming `outlet_invoke` executor.
///
/// The handler is single-shot: it returns one aggregate value. The default
/// `exec_*_stream` trait methods turn that into a degenerate one-`Data`-chunk
/// stream, and the framework appends the terminal `End`. When no handler is
/// registered, the executor echoes validated metadata (matching
/// `outlet_invoke`'s schema-only fallback).
struct NapiStreamExecutor {
    handler: Option<OutletHandler>,
    outlet_id: String,
    context_id: String,
    invoker_did: String,
}

impl NapiStreamExecutor {
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
impl OutletExecutor for NapiStreamExecutor {
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
fn open_rejection_to_err(rejection: &OpenStreamRejection) -> ScpNapiError {
    ScpNapiError::Outlet {
        message: format!(
            "outlet stream open rejected ({}): {}",
            rejection.error_code(),
            rejection.slug()
        ),
        code: rejection.error_code().to_owned(),
    }
}

/// The `SCP-PERM-3001` rejection for a control-plane call whose `caller_did` is
/// not the invoker pinned at open (CRITICAL #1).
fn caller_not_invoker_err(caller_did: &str, invoker_did: &str) -> ScpNapiError {
    ScpNapiError::Permission {
        message: format!(
            "caller '{caller_did}' is not the invoker '{invoker_did}' pinned at stream open — \
             only the opening invoker may steer the stream (§5.4.5 CRITICAL #1)"
        ),
        code: codes::PERM_3001.to_owned(),
    }
}

/// The control-plane "no active outlet stream" rejection for an unknown, stale,
/// typo'd, or already-evicted `handle_id`. Shared by every control-plane lookup
/// AND by [`outlet_stream_poll_next_on`] so a bad handle is a DISTINCT error
/// from a genuine terminal (which `poll_next` reports as `None`) — conflating
/// the two would let a caller mistake a typo for a clean stream end.
fn no_active_stream_err(handle_id: &str) -> ScpNapiError {
    ScpNapiError::Context {
        message: format!("no active outlet stream '{handle_id}'"),
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
    bi: &NapiBridgeInstance,
    handle_id: &str,
    caller_did: &str,
) -> Result<(ControlHandle, String, String, [u8; 32]), ScpNapiError> {
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
// Open — outlet_stream_open_on
// ---------------------------------------------------------------------------

/// §5.4.5 streaming outlet open. Validates the UCAN at the bridge (mirroring
/// `outlet_invoke_on`), reserves+spawns the pump via
/// [`Supervisor::open_outlet_stream`](scp_core::context::supervisor::Supervisor::open_outlet_stream),
/// and stores the returned handle in the per-instance registry keyed by the
/// stream's `request_id` (hex). Returns the `StreamHandleId` PROMPTLY — the open
/// is the Commit transition, NOT a block-until-terminal.
#[allow(clippy::too_many_arguments)] // Flat §5.4.5 open envelope — agent-first named params.
#[allow(clippy::needless_pass_by_value)] // napi-rs owned String/Option params.
#[allow(clippy::too_many_lines)] // UCAN validate + caveat binding + full OpenStreamParams build.
pub(crate) async fn outlet_stream_open_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    outlet_id: String,
    input_json: String,
    caller_did: String,
    ucan_token: String,
    proof_tokens: Option<Vec<String>>,
    spending_ucan: Option<String>,
    timeout_ms: Option<u32>,
    estimated_chunk_count: Option<u32>,
) -> napi::Result<String> {
    crate::napi_check_handle!(&bi.core, handle);
    validate_outlet_id(&outlet_id).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    validate_did(&caller_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    validate_ucan_token(&ucan_token).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    if let Some(ref jwt) = spending_ucan {
        validate_ucan_token(jwt).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    }
    if let Some(ref tokens) = proof_tokens {
        for t in tokens {
            validate_ucan_token(t).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
        }
    }

    let context_id = handle.context_id();
    crate::runtime::ensure_registered(bi, handle).map_err(napi::Error::from)?;

    let input_json_value: serde_json::Value = serde_json::from_str(&input_json).map_err(|e| {
        napi::Error::from(ScpNapiError::Outlet {
            message: format!("invalid input JSON: {e}"),
            code: codes::OUTLET_6002.to_owned(),
        })
    })?;

    // Primary authorization: the full 11-step ADR-016 UCAN pipeline over the
    // bridge-owned per-context UCAN state — IDENTICAL to `outlet_invoke_on`. The
    // stream is validated ONCE at open (§5.4.5 "UCAN check locus"); chunks do
    // not re-present.
    let proof_resolver = crate::ucan::build_proof_resolver_from_tokens(proof_tokens.as_deref())
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Permission {
                message: format!("failed to build proof resolver: {e}"),
                code: codes::PERM_3001.to_owned(),
            })
        })?;
    crate::outlets::validate_ucan_for_outlet(
        bi,
        &context_id,
        &outlet_id,
        &caller_did,
        &ucan_token,
        &proof_resolver,
    )
    .map_err(napi::Error::from)?;

    // §7.3.8 effective-caveat resolution from the VALIDATED invocation UCAN's
    // narrowed `nb` — mirrors `outlet_invoke_on`. `ucan_cid` keys the owned
    // Class-S counters and anchors the §5.4.5 caveats binding.
    let invocation_ucan =
        scp_core::crypto::ucan::validate::parse_ucan(&ucan_token).map_err(|e| {
            napi::Error::from(ScpNapiError::Permission {
                message: format!("invalid invocation UCAN for '{outlet_id}': {e}"),
                code: codes::PERM_3001.to_owned(),
            })
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
    // what we pin here (dispatch.rs `verify_caveats_binding_at_open`).
    let request_id: [u8; 16] = *uuid::Uuid::now_v7().as_bytes();
    let caveats_jcs = caveats.to_canonical_json_bytes().map_err(|e| {
        napi::Error::from(ScpNapiError::Context {
            message: format!("failed to canonicalize effective caveats: {e}"),
            code: codes::CTX_2001.to_owned(),
        })
    })?;
    let caveats_binding = compute_caveats_binding(
        ucan_cid.as_bytes(),
        &request_id,
        &caller_did,
        estimated_chunk_count.unwrap_or(0),
        &caveats_jcs,
    );

    // Cost per Data chunk from the outlet's registered cost (§5.4.1). The
    // reserve/settle economy is the manager's concern; `available_balance` /
    // `reserved_escrow` are NOT consulted on the production open path.
    let cost_per_chunk = crate::runtime::with_context(bi, &context_id, |rt| {
        let registration =
            rt.outlet_registry
                .get(&outlet_id)
                .ok_or_else(|| ScpNapiError::Outlet {
                    message: format!(
                        "outlet '{outlet_id}' not registered in context '{context_id}'"
                    ),
                    code: codes::OUTLET_6002.to_owned(),
                })?;
        Ok(registration
            .cost
            .as_ref()
            .map_or(scp_core::economy::Amount::new(0), |c| c.amount))
    })
    .map_err(napi::Error::from)?;

    // The OPERATOR signs every chunk that crosses the outer wire; the INVOKER
    // pubkey verifies grants + cancels. Resolve both through custody.
    let operator_did = crate::runtime::with_context(bi, &context_id, |rt| {
        rt.outlet_registry
            .get(&outlet_id)
            .map(|r| r.operator_did.0.clone())
            .ok_or_else(|| ScpNapiError::Outlet {
                message: format!("outlet '{outlet_id}' not registered"),
                code: codes::OUTLET_6002.to_owned(),
            })
    })
    .map_err(napi::Error::from)?;
    let operator_signer: Arc<dyn StreamSigner> = Arc::new(
        resolve_stream_signer(bi, &operator_did)
            .await
            .map_err(napi::Error::from)?,
    );
    let invoker_pk = *resolve_stream_signer(bi, &caller_did)
        .await
        .map_err(napi::Error::from)?
        .verifying_key();

    // Snapshot the registry + handler under the context guard, OUTSIDE the
    // runtime call (lock-split discipline from `outlet_invoke_on`).
    let (registry, handler) = crate::runtime::with_context(bi, &context_id, |rt| {
        Ok((
            rt.outlet_registry.clone(),
            rt.outlet_handlers.get(&outlet_id).cloned(),
        ))
    })
    .map_err(napi::Error::from)?;

    let supervisor = crate::runtime::supervisor(bi)?.clone();
    let stream_epoch = supervisor.local_mls_epoch(&context_id).await.unwrap_or(0);

    let executor: Arc<dyn OutletExecutor> = Arc::new(NapiStreamExecutor {
        handler,
        outlet_id: outlet_id.clone(),
        context_id: context_id.clone(),
        invoker_did: caller_did.clone(),
    });

    // LIVE revocation view for the runtime's authoritative re-check timer.
    let revocation_checker: Arc<
        dyn scp_core::crypto::ucan::validate::RevocationChecker + Send + Sync,
    > = Arc::new(NapiStreamRevocationChecker {
        states: Arc::clone(&bi.ucan_registry),
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
            input_json_value,
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
        .map_err(|rejection| napi::Error::from(open_rejection_to_err(&rejection)))?;

    // Detach the receiver (data plane) into its own lock so `poll_next` never
    // contends with the control plane.
    //
    // INVARIANT: `open_outlet_stream` always returns a fresh handle whose
    // receiver has NOT yet been taken (`StreamSessionHandle::receiver` is
    // `self.receiver.take()`, called exactly once — here — per handle), so this
    // is `Some` on the happy path. The `None` arm is therefore UNREACHABLE under
    // the runtime's postcondition; it exists purely as a fund-safety backstop.
    // `receiver()` is the ONLY fallible step AFTER the irreversible
    // reserve+spawn, so a bare `?` here would strand a spawned, ALREADY-BILLING
    // pump with no registry entry. Instead we force the pump to a terminal
    // (which releases its escrow via the pump's close-time settlement) before
    // surfacing the error.
    let Some(receiver) = stream_handle.receiver() else {
        let _ = stream_handle.terminate_with_error(TerminateReason::ContextClosedMidStream, None);
        return Err(napi::Error::from(ScpNapiError::Context {
            message: "stream handle returned without a chunk receiver (runtime invariant \
                      violation) — pump terminated to release escrow"
                .to_owned(),
            code: codes::CTX_2001.to_owned(),
        }));
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
/// or the stream closes. Returns the JSON-serialized [`OutletStreamChunk`]
/// bytes, or `None` at the channel-closed sentinel. This is the primitive the
/// TypeScript SDK's async iterator wraps.
///
/// # Async model (no GIL)
///
/// napi-rs bridges this `async fn` to a JS Promise on the module runtime — there
/// is no GIL, so the `PyO3` reference's `allow_threads` deadlock does not apply.
/// The one hazard we DO guard: the receiver `Arc` is cloned OUT of the `DashMap`
/// shard guard and the guard is DROPPED before `recv().await`, so no shard lock
/// is held across the `.await` (the DashMap-ref-across-await hazard).
///
/// # Handle lifecycle
///
/// - **Unknown / evicted `handle_id`** → a DISTINCT [`no_active_stream_err`],
///   NEVER `None` — a stale or typo'd handle must not masquerade as a clean
///   terminal.
/// - **Terminal chunk** (`End` / `Error{terminal:true}`) → returned to the
///   caller AND the entry is EVICTED immediately, so a caller that reads to
///   terminal but never performs the trailing `None`-drain does not leak the
///   registry entry.
/// - **`None`** (channel closed with no terminal chunk — an abnormal close such
///   as a pump panic dropping the sender) → the entry is evicted and `None` is
///   returned as the terminal sentinel.
pub(crate) async fn outlet_stream_poll_next_on(
    bi: &NapiBridgeInstance,
    handle_id: &str,
) -> napi::Result<Option<Vec<u8>>> {
    // Clone the receiver `Arc` OUT of the DashMap shard guard BEFORE awaiting
    // recv — never hold a DashMap ref across the `.await`. An unknown handle is a
    // distinct error, not a terminal.
    let receiver = {
        let Some(entry) = bi.outlet_stream_registry.get(handle_id) else {
            return Err(napi::Error::from(no_active_stream_err(handle_id)));
        };
        Arc::clone(&entry.receiver)
    };
    let chunk = receiver.lock().await.recv().await;
    if let Some(chunk) = chunk {
        // Evict on the TERMINAL chunk so a run-to-terminal-without-draining
        // caller cannot leak the entry. The pump releases the admission counter +
        // escrow at the same terminal, so eviction here only reclaims the
        // bridge-side registry slot.
        if chunk.payload.is_terminal() {
            bi.outlet_stream_registry.remove(handle_id);
        }
        let bytes = serde_json::to_vec(&chunk).map_err(|e| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("failed to serialize stream chunk: {e}"),
                code: codes::CTX_2001.to_owned(),
            })
        })?;
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
/// fund-safety BACKSTOP that no quantity of grants can over-bill is the
/// invoker's CAVEAT CEILING — the §5.4.5 cumulative billable ceiling
/// `min(credit_window, max_calls)` pinned in the pump's `CreditTracker`
/// (`max_billable`), which clamps every replenishment.
pub(crate) async fn outlet_stream_grant_credit_on(
    bi: &NapiBridgeInstance,
    handle_id: &str,
    caller_did: &str,
    grant: u32,
) -> napi::Result<()> {
    validate_did(caller_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

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
            return Err(napi::Error::from(caller_not_invoker_err(
                caller_did,
                &entry.invoker_did,
            )));
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
    let signer = resolve_stream_signer(bi, caller_did)
        .await
        .map_err(napi::Error::from)?;

    let supervisor = crate::runtime::supervisor(bi)?.clone();
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
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("failed to assign durable monotonic_seq: {e}"),
                code: codes::CTX_2001.to_owned(),
            })
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
    let sig = signer.sign(&preimage).await.map_err(|e| {
        napi::Error::from(ScpNapiError::Context {
            message: format!("failed to sign credit grant: {e:?}"),
            code: codes::CTX_2001.to_owned(),
        })
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
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

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
            Err(napi::Error::from(ScpNapiError::Outlet {
                message: format!("credit grant rejected: {grant_err:?}"),
                code: grant_error_to_code(grant_err).to_owned(),
            }))
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
pub(crate) async fn outlet_stream_cancel_on(
    bi: &NapiBridgeInstance,
    handle_id: &str,
    caller_did: &str,
) -> napi::Result<()> {
    validate_did(caller_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    let (handle, context_id, outlet_id, caveats_binding) =
        authorized_control(bi, handle_id, caller_did).map_err(napi::Error::from)?;
    let signer = resolve_stream_signer(bi, caller_did)
        .await
        .map_err(napi::Error::from)?;
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
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Outlet {
                message: format!("stream cancel rejected: {e:?}"),
                code: cancel_error_to_code(&e).to_owned(),
            })
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
/// `grant_credit` carries an invoker Ed25519 signature and `cancel`
/// self-verifies a custody-produced signature. `terminate` needs no signature
/// because the terminal chunk it forces is signed by the OPERATOR key, not
/// attributed to the invoker, and it can only ever CLOSE the stream. Under the
/// co-resident single-tenant constraint the assertion gate is sufficient. The
/// asymmetry is intentional, not an oversight.
pub(crate) async fn outlet_stream_terminate_on(
    bi: &NapiBridgeInstance,
    handle_id: &str,
    caller_did: &str,
    slug: &str,
    message: &str,
) -> napi::Result<()> {
    validate_did(caller_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    let reason = TerminateReason::from_slug(slug).ok_or_else(|| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!(
                "unknown terminate slug '{slug}' — must be a §5.4.4 stream-terminal slug"
            ),
            code: codes::VALID_7001.to_owned(),
        })
    })?;
    let (handle, _ctx, _outlet, _binding) =
        authorized_control(bi, handle_id, caller_did).map_err(napi::Error::from)?;
    let message_override = (!message.is_empty()).then(|| message.to_owned());
    // `AlreadyPending` / `AlreadyTerminated` are the documented idempotent
    // outcomes (the SDK treats them as "stream already closing") — surface both
    // as success so a receiver-side recheck loop stops cleanly.
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
) -> Result<bool, ScpNapiError> {
    let chunk: OutletStreamChunk =
        serde_json::from_slice(chunk_bytes).map_err(|e| ScpNapiError::Validation {
            message: format!("invalid OutletStreamChunk bytes: {e}"),
            code: codes::VALID_7001.to_owned(),
        })?;
    let pk_bytes = <[u8; 32]>::try_from(operator_pk).map_err(|_| ScpNapiError::Validation {
        message: "operator_pk must be 32 bytes".to_owned(),
        code: codes::VALID_7001.to_owned(),
    })?;
    let operator_verifying_key =
        VerifyingKey::from_bytes(&pk_bytes).map_err(|e| ScpNapiError::Validation {
            message: format!("operator_pk is not a valid key: {e}"),
            code: codes::VALID_7001.to_owned(),
        })?;
    let binding = <[u8; 32]>::try_from(caveats_binding).map_err(|_| ScpNapiError::Validation {
        message: "caveats_binding must be 32 bytes".to_owned(),
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
) -> Result<Vec<u8>, ScpNapiError> {
    let request_id = <[u8; 16]>::try_from(request_id).map_err(|_| ScpNapiError::Validation {
        message: "request_id must be 16 bytes".to_owned(),
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

#[cfg(test)]
mod tests;
