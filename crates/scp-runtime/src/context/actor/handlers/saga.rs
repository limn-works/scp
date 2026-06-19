//! Saga-phase handlers — see
//! [`SagaPhaseMessage`](crate::context::actor::commands::SagaPhaseMessage)
//! and spec §6.2.4 (cross-context tool-invocation saga).
//!
//! # What runs here (slice 3b)
//!
//! The supervisor FSM dispatches per-phase messages to a participant actor.
//! This slice lands the two Prepare handlers, each running on a LOCAL actor:
//!
//! - **Prepare-A** ([`prepare_a`]) — on the caller-context actor. Validates the
//!   caller holds `tool:interface` and is in `OutboundPolicy.allowed_callers`,
//!   stages (not applies) the outbound rate-limit decrement + escrow
//!   reservation via the existing
//!   [`reserve_tool_economy`](crate::context::tools_helpers::reserve_tool_economy)
//!   mechanism, Class-S sync-persists fail-closed, and replies the `Send`
//!   reservation handles for the FSM to hold (RAII release on abort).
//!
//! - **Prepare-B** ([`prepare_b`]) — on the target-context actor. In order:
//!   (1) resolves `ucan_proof_id` from B's own UCAN store and re-runs the full
//!   §7 validation RE-BOUND to the carried `caller_did` + `tool_registration_id`
//!   (the confused-deputy defense), (2) inbound policy, (3) input
//!   schema-specificity floor (§9.2.1), (4) target-context binding, (5)
//!   freshness (§9.14 skew + B's nonce-dedup cache), (6) chain-depth. Then it
//!   captures B-controlled provenance (`recorded_timestamp_ms` = B's clock,
//!   `recorded_nonce` = staged copy, `recorded_chain_depth` = incoming + 1),
//!   stages the eight-field
//!   [`CrossContextToolInvocationPrepared`] into `saga_pending`, and Class-S
//!   sync-persists fail-closed before replying.
//!
//! The Commit / Abort / divergence-marker arms are dispatched in later slices;
//! their handler bodies return [`ContextError::NotImplemented`] here. The
//! supervisor FSM that *drives* these messages to the two local actors is a
//! later slice too — these handlers are compiled-but-not-yet-driven.
//!
//! # Error band
//!
//! Prepare-phase rejections surface as typed [`ContextError`]s carrying
//! `SCP-SAGA-13xxx` codes (the `13000-13999` saga band, ADR-049 §3a). The
//! caller-asserted timestamp / chain-depth are NEVER recorded — they feed only
//! the freshness check and the `+1` re-derivation base (spec §6.2.4).

use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::crypto::ucan::UcanToken;
use scp_protocol::crypto::ucan::validate::{
    DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, InMemoryNonceTracker, ValidationContext,
};

use scp_protocol::context::tools::cross_context_saga::{
    CommittedSide, CrossContextDivergenceMarker, CrossContextToolReceipt,
};

use crate::context::actor::commands::{
    CommitBReserveOutcome, CommitBReserveReply, CommitBSettleOutcome, CommitBSettleReply,
    PreparedAFields, PreparedBFields, SagaPhaseMessage, SigningKeyBytes,
};
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::PerContextState;
use crate::context::economy_logic::{ContextRevocationChecker, KeyResolverDidResolver};
use crate::context::messaging_helpers::persist_state_fail_closed;
use crate::context::supervisor::saga_journal::SagaId;
use crate::context::supervisor::saga_prepared_state::{
    CommittedToolInvocation, CrossContextToolInvocationPrepared, SagaPreparedState,
};
use crate::context::tools_helpers::reserve_tool_economy;

/// Lightweight [`Outcome`]-error projection of a real [`ContextError`].
///
/// The actor only inspects `Outcome::mutated` for dirty-tracking; the canonical
/// error goes to the caller's oneshot. This mirrors the per-handler
/// `outcome_error_sketch` shape across the actor handler modules (the error
/// type is intentionally not `Clone`, so the real error is moved into the reply
/// and a faithful sketch is returned to the actor).
fn outcome_error_sketch(err: &ContextError) -> ContextError {
    match err {
        ContextError::PermissionDenied(msg) => ContextError::PermissionDenied(msg.clone()),
        ContextError::PersistenceFailed(msg) => ContextError::PersistenceFailed(msg.clone()),
        ContextError::RateLimited { resource, message } => ContextError::RateLimited {
            resource: resource.clone(),
            message: message.clone(),
        },
        ContextError::NotImplemented(msg) => ContextError::NotImplemented(msg.clone()),
        other => ContextError::CryptoFailed(format!("{other}")),
    }
}

/// Lowercase-hex encode a raw 32-byte context-id digest (the wire / role-state
/// id-form, never the `"standing-"`-prefixed display string — spec §6.2.4
/// id-form rule).
fn hex_context_id(id: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in id {
        use std::fmt::Write as _;
        // `write!` to a `String` is infallible; the result is discarded.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Dispatch a [`SagaPhaseMessage`] against actor state.
pub async fn dispatch(
    state: &mut PerContextState,
    deps: &ActorDeps,
    cmd: SagaPhaseMessage,
) -> Outcome<()> {
    match cmd {
        // Prepare arms (slice 3b) route to a dedicated helper to keep this
        // router within the per-function line budget.
        prepare @ (SagaPhaseMessage::PrepareA { .. } | SagaPhaseMessage::PrepareB { .. }) => {
            dispatch_prepare_phase(state, deps, prepare).await
        }
        // Commit (split) / Abort / divergence-marker arms (slice 4).
        other => dispatch_commit_phase(state, deps, other).await,
    }
}

/// Dispatch the Prepare-A / Prepare-B saga phases (slice 3b). Split out of
/// [`dispatch`] so each router stays within the per-function line budget.
async fn dispatch_prepare_phase(
    state: &mut PerContextState,
    deps: &ActorDeps,
    cmd: SagaPhaseMessage,
) -> Outcome<()> {
    match cmd {
        SagaPhaseMessage::PrepareA {
            caller_context_id,
            caller_did,
            tool_registration_id,
            declared_cost,
            reply,
        } => {
            prepare_a(
                state,
                deps,
                &caller_context_id,
                &caller_did,
                &tool_registration_id,
                declared_cost,
                reply,
            )
            .await
        }
        SagaPhaseMessage::PrepareB {
            saga_id,
            caller_context_id,
            target_context_id,
            caller_did,
            tool_registration_id,
            ucan_proof_id,
            input,
            asserted_chain_depth,
            asserted_nonce,
            asserted_timestamp_ms,
            reply,
        } => {
            let req = PrepareBRequest {
                saga_id,
                caller_context_id,
                target_context_id,
                caller_did,
                tool_registration_id,
                ucan_proof_id,
                input,
                asserted_chain_depth,
                asserted_nonce,
                asserted_timestamp_ms,
            };
            prepare_b(state, deps, req, reply).await
        }
        // Commit-side phases are matched in `dispatch` and never routed here.
        // The `dispatch` router partitions Prepare vs Commit before calling
        // this helper, so these arms are statically unreachable; return a typed
        // error (NEVER panic — ADR-049 §10 handler panic ban) rather than
        // `unreachable!`, routing each phase's reply to its typed sender.
        SagaPhaseMessage::CommitBReserve { reply, .. } => misrouted_reserve(reply),
        SagaPhaseMessage::CommitBSettle { reply, .. } => misrouted_settle(reply),
        SagaPhaseMessage::CommitA { reply, .. }
        | SagaPhaseMessage::Abort { reply, .. }
        | SagaPhaseMessage::EmitDivergenceMarker { reply, .. } => misrouted_unit(reply),
    }
}

/// Dispatch the Commit (split reserve/settle), Abort, and divergence-marker
/// saga phases (slice 4). Split out of [`dispatch`] to keep each router within
/// the per-function line budget.
async fn dispatch_commit_phase(
    state: &mut PerContextState,
    deps: &ActorDeps,
    cmd: SagaPhaseMessage,
) -> Outcome<()> {
    match cmd {
        SagaPhaseMessage::CommitBReserve { saga_id, reply } => {
            commit_b_reserve(state, &saga_id, reply)
        }
        SagaPhaseMessage::CommitBSettle {
            saga_id,
            output_bytes,
            target_signing_key,
            reply,
        } => {
            commit_b_settle(
                state,
                deps,
                &saga_id,
                output_bytes,
                &target_signing_key,
                reply,
            )
            .await
        }
        SagaPhaseMessage::CommitA {
            saga_id,
            reservation,
            caller_context_id,
            caller_did,
            target_context_id,
            nonce,
            receipt,
            output_bytes,
            reply,
        } => {
            let req = CommitARequest {
                saga_id,
                reservation: *reservation,
                caller_context_id,
                caller_did,
                target_context_id,
                nonce,
                receipt,
                output_bytes,
            };
            commit_a(state, deps, req, reply).await
        }
        SagaPhaseMessage::Abort {
            saga_id,
            reservation,
            reply,
        } => abort(state, deps, &saga_id, reservation.map(|b| *b), reply).await,
        SagaPhaseMessage::EmitDivergenceMarker {
            saga_id,
            nonce,
            committed_side,
            committed_event_id,
            signing_key,
            reply,
        } => emit_divergence_marker(
            state,
            deps,
            &saga_id,
            nonce,
            committed_side,
            &committed_event_id,
            &signing_key,
            reply,
        ),
        // Prepare arms are matched in `dispatch` and never routed here. They
        // are statically unreachable; return a typed error per their reply
        // shape (NEVER panic — ADR-049 §10 handler panic ban).
        SagaPhaseMessage::PrepareA { reply, .. } => {
            let err = misrouted_err("PrepareA");
            let sketch = outcome_error_sketch(&err);
            let _ = reply.send(Err(err));
            Outcome::err(sketch)
        }
        SagaPhaseMessage::PrepareB { reply, .. } => {
            let err = misrouted_err("PrepareB");
            let sketch = outcome_error_sketch(&err);
            let _ = reply.send(Err(err));
            Outcome::err(sketch)
        }
    }
}

/// Typed error for a statically-unreachable mis-routed saga phase (the
/// `dispatch` router partitions Prepare vs Commit, so neither helper should
/// ever see the other's phases). Returning this — never `panic!`/`unreachable!`
/// — keeps the handler panic ban (ADR-049 §10) intact even on an impossible
/// branch.
fn misrouted_err(phase: &str) -> ContextError {
    ContextError::InvalidState(format!(
        "SCP-SAGA-13038: saga phase '{phase}' reached the wrong dispatch helper \
         (router partition invariant violated)"
    ))
}

/// Mis-route reply for [`SagaPhaseMessage::CommitBReserve`]'s typed sender.
fn misrouted_reserve(reply: CommitBReserveReply) -> Outcome<()> {
    let err = misrouted_err("CommitBReserve");
    let sketch = outcome_error_sketch(&err);
    let _ = reply.send(Err(err));
    Outcome::err(sketch)
}

/// Mis-route reply for [`SagaPhaseMessage::CommitBSettle`]'s typed sender.
fn misrouted_settle(reply: CommitBSettleReply) -> Outcome<()> {
    let err = misrouted_err("CommitBSettle");
    let sketch = outcome_error_sketch(&err);
    let _ = reply.send(Err(err));
    Outcome::err(sketch)
}

/// Mis-route reply for a unit-reply saga phase's typed sender.
fn misrouted_unit(reply: tokio::sync::oneshot::Sender<Result<(), ContextError>>) -> Outcome<()> {
    let err = misrouted_err("CommitA/Abort/EmitDivergenceMarker");
    let sketch = outcome_error_sketch(&err);
    let _ = reply.send(Err(err));
    Outcome::err(sketch)
}

// ---------------------------------------------------------------------------
// Prepare-A — caller-context actor
// ---------------------------------------------------------------------------

/// Prepare-A handler (spec §6.2.4 "Prepare", caller side). Runs on the LOCAL
/// caller-context actor on owned state.
///
/// Validates that the caller holds `tool:interface` and is in the interface's
/// `OutboundPolicy.allowed_callers`, then stages (does NOT apply) the outbound
/// rate-limit decrement + escrow reservation of `declared_cost` via the
/// existing reserve mechanism. The resulting `Send` [`ToolEconomyReservation`]
/// is a `#[must_use]` RAII carrier the FSM holds — its drop releases the held
/// escrow/rate-limit on every terminal non-commit path. The staged saga state
/// is Class-S sync-persisted fail-closed BEFORE the reply, so a crash in the
/// coalesce window cannot acknowledge a Prepare-A whose reservation did not
/// durably land.
async fn prepare_a(
    state: &mut PerContextState,
    deps: &ActorDeps,
    caller_context_id: &[u8; 32],
    caller_did: &DID,
    tool_registration_id: &str,
    _declared_cost: u64,
    reply: tokio::sync::oneshot::Sender<Result<PreparedAFields, ContextError>>,
) -> Outcome<()> {
    let context_id_hex = hex_context_id(caller_context_id);

    // 1. Caller must hold `tool:interface` AND be in the interface's outbound
    //    allowed_callers (empty = any member). REUSES the role-state capability
    //    surface (`member_has_capability`) and the `OutboundPolicy.allowed_callers`
    //    enforcement shape `invoke_cross_context` uses for the single-context path.
    if let Err(err) = validate_outbound_caller(state, caller_did, tool_registration_id) {
        let sketch = outcome_error_sketch(&err);
        let _ = reply.send(Err(err));
        return Outcome::err(sketch);
    }

    // 2. Stage (not apply) the outbound rate-limit decrement + escrow
    //    reservation via the existing reserve mechanism. The reservation holds
    //    the escrow/rate-limit; apply happens at Commit-A settle (slice 4).
    //    No spending UCAN is presented on the OUTBOUND leg — the inbound
    //    `require_spending_ucan` gate and §7 proof live on B's Prepare-B side.
    let now_secs = deps.clock.now_secs();
    let reservation = match reserve_tool_economy(
        state,
        deps,
        &context_id_hex,
        caller_did,
        None,
        now_secs,
    )
    .await
    {
        Ok(reservation) => reservation,
        Err(err) => {
            // reserve_tool_economy rolls back its own staged bookkeeping on
            // every failure branch, so no apply leaked — reply the typed error.
            let sketch = outcome_error_sketch(&err);
            let _ = reply.send(Err(err));
            return Outcome::err(sketch);
        }
    };

    // 3. Class-S sync-persist fail-closed BEFORE replying (ADR-049 §9): the
    //    reserve mutated actor-owned velocity / rate-limit / budget bookkeeping;
    //    a crash in the coalesce window must not acknowledge a Prepare-A whose
    //    staged reservation did not durably land. On persist failure the
    //    reservation is ROLLED BACK (the §6.2.4 "Reservation release on every
    //    terminal path" RAII contract: the ToolEconomyTicket MUST be settled or
    //    rolled back, never merely dropped) so the staged escrow/rate-limit/
    //    velocity/budget are released — nothing applied.
    if let Err(persist_err) = persist_state_fail_closed(state, deps, &context_id_hex) {
        crate::context::tools_helpers::rollback_tool_economy(state, deps, reservation.ticket).await;
        let sketch = outcome_error_sketch(&persist_err);
        let _ = reply.send(Err(persist_err));
        return Outcome::err_mutated(sketch);
    }

    let _ = reply.send(Ok(PreparedAFields { reservation }));
    Outcome::ok_mutated(())
}

/// Validate the Prepare-A outbound caller gate: the caller holds
/// `tool:interface` and is in the established interface's
/// `OutboundPolicy.allowed_callers` (empty = any holder). Returns a typed
/// `SCP-SAGA-13xxx` rejection otherwise.
fn validate_outbound_caller(
    state: &PerContextState,
    caller_did: &DID,
    tool_registration_id: &str,
) -> Result<(), ContextError> {
    use scp_protocol::context::roles::Capability;

    // `tool:interface` capability (the caller is authorized to USE interfaces).
    if !state
        .role_state
        .member_has_capability(caller_did.as_ref(), &Capability::ToolInterface)
    {
        return Err(ContextError::PermissionDenied(format!(
            "SCP-SAGA-13010: caller '{caller_did}' lacks tool:interface capability \
             for cross-context invocation"
        )));
    }

    // Outbound policy: the interface whose source tool is this registration.
    // `allowed_callers` empty ⇒ any member with the capability above.
    if let Some(interface) = state
        .governance
        .tool_interfaces
        .iter()
        .find(|i| i.tool_id == tool_registration_id)
        && let Some(outbound) = interface.outbound_policy.as_ref()
        && !outbound.allowed_callers.is_empty()
        && !outbound.allowed_callers.contains(caller_did)
    {
        return Err(ContextError::PermissionDenied(format!(
            "SCP-SAGA-13011: caller '{caller_did}' not in outbound allowed_callers \
             for tool '{tool_registration_id}'"
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Prepare-B — target-context actor
// ---------------------------------------------------------------------------

/// Owned inputs for [`prepare_b`], grouped to keep the handler signature within
/// the clippy argument budget. Mirrors the
/// [`SagaPhaseMessage::PrepareB`](crate::context::actor::commands::SagaPhaseMessage::PrepareB)
/// payload (minus the reply channel).
struct PrepareBRequest {
    saga_id: crate::context::supervisor::saga_journal::SagaId,
    caller_context_id: [u8; 32],
    target_context_id: [u8; 32],
    caller_did: DID,
    tool_registration_id: String,
    ucan_proof_id: Option<String>,
    input: serde_json::Value,
    asserted_chain_depth: u8,
    asserted_nonce: [u8; 16],
    asserted_timestamp_ms: u64,
}

/// Prepare-B handler (spec §6.2.4 "Prepare", target side). Runs on the LOCAL
/// target-context actor on owned state.
///
/// Validation order (spec §6.2.4): (1) §7 UCAN re-bind / confused-deputy,
/// (2) inbound policy, (3) input schema-specificity floor, (4) target-context
/// binding, (5) freshness, (6) chain-depth. Then it captures B-controlled
/// provenance, stages the eight-field prepared into `saga_pending`, and
/// Class-S sync-persists fail-closed before replying. Any check failure ⇒ typed
/// rejection with no staging.
async fn prepare_b(
    state: &mut PerContextState,
    deps: &ActorDeps,
    req: PrepareBRequest,
    reply: tokio::sync::oneshot::Sender<Result<PreparedBFields, ContextError>>,
) -> Outcome<()> {
    // Run every read-only check first (no state mutation, no `.await` holding a
    // `&PerContextState` borrow). Helper returns the inputs needed to stage.
    if let Err(err) = run_prepare_b_checks(state, deps, &req) {
        let sketch = outcome_error_sketch(&err);
        let _ = reply.send(Err(err));
        return Outcome::err(sketch);
    }

    // All checks passed. Capture B-controlled, replay-deterministic provenance:
    //   recorded_timestamp_ms = B's OWN clock NOW (never the caller's send time)
    //   recorded_nonce        = B's staged COPY of the wire nonce
    //   recorded_chain_depth  = incoming + 1 (B re-derives; never the asserted)
    let recorded_timestamp_ms = deps.clock.now_millis();
    let recorded_nonce = req.asserted_nonce;
    let recorded_chain_depth = req.asserted_chain_depth.saturating_add(1);
    let now_secs = deps.clock.now_secs();

    // Record the accepted nonce in B's dedup cache (freshness state lives on B).
    state.xctx_nonce_dedup.record(req.asserted_nonce, now_secs);

    // Stage the eight-field public-metadata projection into saga_pending.
    let prepared = CrossContextToolInvocationPrepared {
        caller_context_id: req.caller_context_id,
        target_context_id: req.target_context_id,
        caller_did: req.caller_did.clone(),
        tool_registration_id: req.tool_registration_id.clone(),
        // The journal projection carries a string proof id; an ungated tool
        // has no proof — the empty string is the "no proof" sentinel for the
        // public projection (the wire field is `<string|null>`).
        ucan_proof_id: req.ucan_proof_id.clone().unwrap_or_default(),
        recorded_timestamp_ms,
        recorded_nonce,
        recorded_chain_depth,
    };
    state.saga_pending.insert(
        req.saga_id.clone(),
        SagaPreparedState::CrossContextToolInvocation(prepared),
    );

    // Class-S sync-persist fail-closed BEFORE replying (ADR-049 §9 line 144):
    // a crash that rolled the staged slot back behind an acked Prepare-B would
    // orphan the supervisor saga journal's reservation linkage. On persist
    // failure, roll the staged slot + nonce back and surface the error.
    let target_hex = hex_context_id(&req.target_context_id);
    if let Err(persist_err) = persist_state_fail_closed(state, deps, &target_hex) {
        state.saga_pending.remove(&req.saga_id);
        let sketch = outcome_error_sketch(&persist_err);
        let _ = reply.send(Err(persist_err));
        // The nonce stays recorded (fail-closed direction for replay
        // protection — un-recording would re-open the replay window the dedup
        // cache exists to close). Report mutated so the partial state persists.
        return Outcome::err_mutated(sketch);
    }

    let _ = reply.send(Ok(PreparedBFields {
        recorded_timestamp_ms,
        recorded_nonce,
        recorded_chain_depth,
    }));
    Outcome::ok_mutated(())
}

/// Run the six read-only Prepare-B checks in spec order. Returns `Ok(())` if
/// every check passes; a typed `SCP-SAGA-13xxx` rejection otherwise. Performs
/// no state mutation, so the caller stages only on success.
fn run_prepare_b_checks(
    state: &mut PerContextState,
    deps: &ActorDeps,
    req: &PrepareBRequest,
) -> Result<(), ContextError> {
    // (1) Confused-deputy: resolve the UCAN proof from B's OWN store and re-run
    //     full §7 validation RE-BOUND to caller_did + tool_registration_id.
    validate_ucan_rebind(state, deps, req)?;

    // (2) Inbound policy: require_spending_ucan (the gated-proof requirement is
    //     satisfied by (1) above when a proof is present). Source-role / inbound
    //     rate are advisory at this layer (enforced source-side / by the
    //     per-interface RateLimit, per §6.2.0.1) — the binding inbound gate here
    //     is `require_spending_ucan`.
    validate_inbound_policy(state, req)?;

    // (3) Input schema specificity floor (§9.2.1): degenerate broad-schema
    //     input is rejected at Prepare-B.
    validate_input_specificity(state, req)?;

    // (4) Target-context binding: the asserted target_context_id MUST equal B's
    //     own context (spec §6.2.4 "Target-context binding").
    if req.target_context_id != state.context_id {
        return Err(ContextError::PermissionDenied(format!(
            "SCP-SAGA-13014: target_context_id mismatch — invocation targets a \
             different context than this executing actor (tool \
             '{}')",
            req.tool_registration_id
        )));
    }

    // (5) Freshness / anti-replay: reject if the asserted send-time is outside
    //     §9.14 skew OR the nonce is already in B's TTL dedup cache.
    validate_freshness(state, deps, req)?;

    // (6) Chain-depth: reject if asserted_chain_depth + 1 would exceed the
    //     context-configured max (spec §6.2.4 "Chain-depth enforcement").
    validate_chain_depth(state, req)?;

    Ok(())
}

/// (1) Confused-deputy defense (spec §6.2.4 normative (1)). Resolves
/// `ucan_proof_id` from B's OWN UCAN store and re-runs the full §7 validation
/// RE-BOUND to the carried `caller_did` (audience) + `tool_registration_id`
/// (capability). REUSES the single-context
/// [`validate_ucan`](scp_protocol::crypto::ucan::validate::validate_ucan)
/// pipeline through the same DID/revocation adapters the spending-UCAN path
/// uses, so a stronger proof delegated to a DIFFERENT principal is rejected
/// (audience mismatch) exactly as the single-context path would reject it.
///
/// An ungated tool carries `ucan_proof_id = None` and presents no proof — there
/// is nothing to confuse, so the check is a no-op for that case.
fn validate_ucan_rebind(
    state: &PerContextState,
    deps: &ActorDeps,
    req: &PrepareBRequest,
) -> Result<(), ContextError> {
    use scp_protocol::crypto::ucan::capability::CapabilityUri;
    use scp_protocol::crypto::ucan::validate::{ProofResolver, validate_ucan};

    let Some(proof_id) = req.ucan_proof_id.as_deref() else {
        return Ok(()); // ungated tool — no proof to re-bind
    };

    // Resolve the proof from B's OWN store (the index, NOT proof bytes).
    let token: UcanToken = state
        .xctx_ucan_proofs
        .resolve_proof(proof_id)
        .map_err(|e| {
            ContextError::PermissionDenied(format!(
                "SCP-SAGA-13012: ucan_proof_id '{proof_id}' not resolvable in target \
                 UCAN store: {e}"
            ))
        })?;

    // Required capability bound to B's OWN context + THIS tool + tool_invoke.
    let target_hex = hex_context_id(&req.target_context_id);
    let required_cap =
        CapabilityUri::new(target_hex, "tool_invoke", req.tool_registration_id.clone());

    // The ceiling URI set + B's context-creator are taken from B's role state.
    let ceiling = state.role_state.ceiling.to_ucan_string_set();
    let creator_did = state.role_state.creator_did.clone();
    let revoked = state.governance.revoked_spending_ucan_cids.clone();

    let did_resolver = KeyResolverDidResolver::new(&deps.key_resolver);
    let revocation_checker = ContextRevocationChecker {
        revoked_cids: &revoked,
    };
    // The cross-context ENVELOPE replay is owned by B's `xctx_nonce_dedup`
    // (freshness check below); the UCAN's OWN nonce is a long-lived
    // delegation-proof concern, so a fresh per-validation tracker is correct
    // here — re-validating the SAME stored proof on a later legitimate
    // invocation must not falsely trip UCAN-nonce replay.
    let mut nonce_tracker = InMemoryNonceTracker::new();

    let mut ctx = ValidationContext {
        did_resolver: &did_resolver,
        nonce_tracker: &mut nonce_tracker,
        revocation_checker: &revocation_checker,
        // B's store doubles as the delegation-chain proof resolver.
        proof_resolver: &state.xctx_ucan_proofs,
        ceiling: &ceiling,
        context_creator_did: &creator_did,
        // CONFUSED-DEPUTY BINDING: the presenting principal is the carried
        // caller_did. validate_ucan step 5 rejects (AudienceMismatch) if the
        // resolved proof's audience is a DIFFERENT principal.
        presenting_agent_did: req.caller_did.as_ref(),
        clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
        clock: deps.clock.as_ref(),
    };

    validate_ucan(&token, &required_cap, &mut ctx).map_err(|e| {
        ContextError::PermissionDenied(format!(
            "SCP-SAGA-13013: UCAN re-validation failed (re-bound to caller_did \
             '{}' + tool '{}'): {e}",
            req.caller_did, req.tool_registration_id
        ))
    })
}

/// (2) Inbound policy: when the interface requires a spending UCAN, a proof
/// MUST be present (and was validated in step (1)).
fn validate_inbound_policy(
    state: &PerContextState,
    req: &PrepareBRequest,
) -> Result<(), ContextError> {
    if let Some(interface) = state
        .governance
        .tool_interfaces
        .iter()
        .find(|i| i.tool_id == req.tool_registration_id)
        && let Some(inbound) = interface.inbound_policy.as_ref()
        && inbound.require_spending_ucan
        && req.ucan_proof_id.is_none()
    {
        return Err(ContextError::PermissionDenied(format!(
            "SCP-SAGA-13015: inbound policy requires a spending UCAN but none was \
             carried for tool '{}'",
            req.tool_registration_id
        )));
    }
    Ok(())
}

/// (3) Input schema specificity floor + input conformance (§9.2.1, §6.2.4
/// normative (2)). REUSES the single-context
/// [`validate_specificity_floor`](scp_protocol::context::tools::schema::validate_specificity_floor)
/// against the target tool's REGISTERED schemas — degenerate broad-schema tools
/// that function as arbitrary message channels are rejected — and then
/// validates the carried `input` value against the registered input schema (the
/// same `validate_value_against_schema` the single-context tool path applies).
fn validate_input_specificity(
    state: &PerContextState,
    req: &PrepareBRequest,
) -> Result<(), ContextError> {
    use scp_protocol::context::tools::schema::{
        validate_specificity_floor, validate_value_against_schema,
    };

    let Some(registration) = state
        .governance
        .registered_tools
        .iter()
        .find(|t| t.tool_id == req.tool_registration_id)
    else {
        return Err(ContextError::PermissionDenied(format!(
            "SCP-SAGA-13016: tool '{}' not found in target registry",
            req.tool_registration_id
        )));
    };

    // Floor: degenerate broad-schema tools are rejected (independent of the
    // concrete input value).
    validate_specificity_floor(
        &registration.schema.input_schema,
        &registration.schema.output_schema,
    )
    .map_err(|(side, fields)| {
        ContextError::PermissionDenied(format!(
            "SCP-SAGA-13017: input schema specificity floor not met for tool '{}' \
             ({side} schema has {fields} fields)",
            req.tool_registration_id
        ))
    })?;

    // Conformance: the carried input value MUST validate against the registered
    // input schema (§6.2.4 normative (2)).
    validate_value_against_schema(&req.input, &registration.schema.input_schema).map_err(|msg| {
        ContextError::PermissionDenied(format!(
            "SCP-SAGA-13021: input does not conform to registered schema for tool \
             '{}': {msg}",
            req.tool_registration_id
        ))
    })
}

/// (5) Freshness / anti-replay (spec §6.2.4). Rejects if the caller-asserted
/// send-time is outside §9.14 clock-skew tolerance OR the nonce is already in
/// B's TTL dedup cache. Performs the dedup READ only; the accept-path record
/// happens in [`prepare_b`] after every check passes.
fn validate_freshness(
    state: &mut PerContextState,
    deps: &ActorDeps,
    req: &PrepareBRequest,
) -> Result<(), ContextError> {
    let now_ms = deps.clock.now_millis();
    let skew_ms = DEFAULT_CLOCK_SKEW_TOLERANCE_SECS.saturating_mul(1000);
    let delta_ms = now_ms.abs_diff(req.asserted_timestamp_ms);
    if delta_ms > skew_ms {
        return Err(ContextError::PermissionDenied(format!(
            "SCP-SAGA-13018: invocation timestamp outside §9.14 skew tolerance \
             (Δ={delta_ms}ms > {skew_ms}ms) for tool '{}'",
            req.tool_registration_id
        )));
    }

    let now_secs = deps.clock.now_secs();
    if state
        .xctx_nonce_dedup
        .is_replayed(&req.asserted_nonce, now_secs)
    {
        return Err(ContextError::PermissionDenied(format!(
            "SCP-SAGA-13019: invocation nonce already seen in target dedup cache \
             (replay) for tool '{}'",
            req.tool_registration_id
        )));
    }
    Ok(())
}

/// (6) Chain-depth enforcement (spec §6.2.4). Rejects if the re-derived inbound
/// depth (`asserted + 1`) would exceed the context-configured `max_chain_depth`
/// (default 8 via
/// [`effective_max_chain_depth`](scp_protocol::provenance::attach::effective_max_chain_depth)).
fn validate_chain_depth(
    state: &PerContextState,
    req: &PrepareBRequest,
) -> Result<(), ContextError> {
    use scp_protocol::provenance::attach::effective_max_chain_depth;

    let max_depth = effective_max_chain_depth(state.handle.params().max_chain_depth);
    // B re-derives depth = incoming + 1; reject if that would exceed the cap.
    if u16::from(req.asserted_chain_depth) + 1 > u16::from(max_depth) {
        return Err(ContextError::PermissionDenied(format!(
            "SCP-SAGA-13020: chain depth {} +1 exceeds max_chain_depth {max_depth} \
             for tool '{}'",
            req.asserted_chain_depth, req.tool_registration_id
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Commit-B — target-context actor (split reserve / settle, spec §6.2.4)
// ---------------------------------------------------------------------------

/// Derive the `SagaId`-stable `ToolInvoked` event-log entry id (spec §6.2.4
/// "`SagaId`-idempotent event-log append"). The id MUST be reproducible from
/// durable state on a replayed Commit — it is a signed receipt-preimage field —
/// so it is derived deterministically from the `SagaId` rather than minted from
/// a fresh counter. The `ToolInvoked:` prefix matches the §5.16 event-name
/// convention so the §6.2.4 auditor can recognise the entry type.
fn tool_invoked_event_id(saga_id: &SagaId) -> String {
    format!("ToolInvoked:{}", saga_id.0)
}

/// Commit-B reserve half (spec §6.2.4 "Commit", split-execution model). Runs on
/// the LOCAL target actor. Confirms the staged prepared + session reservation
/// are present and decides whether the FSM must run the executor.
///
/// Idempotency (§6.2.4 / §17.16.4): if this `SagaId`'s output was already
/// captured (a replayed Commit), reply [`CommitBReserveOutcome::AlreadyCommitted`]
/// with the STORED output + receipt + event id — the tool is NEVER re-invoked.
/// Otherwise the staged `saga_pending` slot for this `SagaId` MUST be a
/// cross-context tool invocation; reply [`CommitBReserveOutcome::ReadyToExecute`].
///
/// Read-only — no mutation, no Class-S persist.
fn commit_b_reserve(
    state: &PerContextState,
    saga_id: &SagaId,
    reply: CommitBReserveReply,
) -> Outcome<()> {
    // Replay short-circuit: a prior Commit-B already captured the output.
    if let Some(committed) = state.xctx_committed_outputs.get(saga_id) {
        let receipt = match jcs_receipt_bytes(&committed.receipt) {
            Ok(bytes) => bytes,
            Err(err) => {
                let sketch = outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                return Outcome::err(sketch);
            }
        };
        let _ = reply.send(Ok(CommitBReserveOutcome::AlreadyCommitted {
            receipt,
            output_bytes: committed.output_bytes.clone(),
            tool_invoked_event_id: committed.tool_invoked_event_id.clone(),
        }));
        return Outcome::ok(());
    }

    // Not yet committed: the staged prepared MUST be present (Prepare-B ran).
    if let Some(SagaPreparedState::CrossContextToolInvocation(_)) = state.saga_pending.get(saga_id)
    {
        let _ = reply.send(Ok(CommitBReserveOutcome::ReadyToExecute));
        return Outcome::ok(());
    }
    let err = ContextError::InvalidState(format!(
        "SCP-SAGA-13030: Commit-B reserve for saga '{}' found no staged cross-context \
         tool-invocation prepared state (Prepare-B never ran, or the slot was rolled back)",
        saga_id.0
    ));
    let sketch = outcome_error_sketch(&err);
    let _ = reply.send(Err(err));
    Outcome::err(sketch)
}

/// Commit-B settle half (spec §6.2.4 "Commit", target side). Runs on the LOCAL
/// target actor with the executor's captured `output_bytes`.
///
/// On the FIRST settle: canonicalizes the output to JCS, signs the
/// [`CrossContextToolReceipt`] over the STAGED `recorded_nonce` /
/// `recorded_chain_depth` / `recorded_timestamp_ms` + `output_hash` + the
/// `SagaId`-stable `tool_invoked_event_id` using the target's Active Signing
/// Key, durably captures the receipt + output keyed by `SagaId`, appends
/// `ToolInvoked` to the local log, clears the staged `saga_pending` slot,
/// Class-S sync-persists fail-closed, and replies. On a REPLAY (output already
/// captured) re-emits the STORED bytes verbatim — no re-invoke, no re-append,
/// no re-sign.
async fn commit_b_settle(
    state: &mut PerContextState,
    deps: &ActorDeps,
    saga_id: &SagaId,
    output_bytes: Vec<u8>,
    target_signing_key: &SigningKeyBytes,
    reply: CommitBSettleReply,
) -> Outcome<()> {
    // Replay: re-emit the stored capture byte-for-byte; never re-invoke / re-sign.
    if let Some(committed) = state.xctx_committed_outputs.get(saga_id) {
        return reemit_committed_settle(committed, reply);
    }

    match commit_b_first_settle(state, deps, saga_id, &output_bytes, target_signing_key) {
        Ok(outcome) => {
            let _ = reply.send(Ok(outcome));
            Outcome::ok_mutated(())
        }
        // `mutated` is reported by the settle body itself: a pre-append failure
        // (no staged slot, signing) leaves state untouched; an at/after-append
        // failure (then rolled back) still touched the event log, so the actor
        // must persist. This is precise — never code-string-sniffed.
        Err((mutated, err)) => {
            let sketch = outcome_error_sketch(&err);
            let _ = reply.send(Err(err));
            if mutated {
                Outcome::err_mutated(sketch)
            } else {
                Outcome::err(sketch)
            }
        }
    }
}

/// Re-emit a durably-captured Commit-B settle on a replay (spec §6.2.4
/// "Crash recovery §17.16.4"): the stored receipt + output are returned
/// verbatim. The tool is NOT re-invoked and nothing is re-signed.
fn reemit_committed_settle(
    committed: &CommittedToolInvocation,
    reply: CommitBSettleReply,
) -> Outcome<()> {
    match jcs_receipt_bytes(&committed.receipt) {
        Ok(receipt) => {
            let _ = reply.send(Ok(CommitBSettleOutcome {
                receipt,
                output_bytes: committed.output_bytes.clone(),
                tool_invoked_event_id: committed.tool_invoked_event_id.clone(),
            }));
            Outcome::ok(())
        }
        Err(err) => {
            let sketch = outcome_error_sketch(&err);
            let _ = reply.send(Err(err));
            Outcome::err(sketch)
        }
    }
}

/// First (non-replay) Commit-B settle: sign the receipt over the STAGED
/// provenance + captured output, append `ToolInvoked`, durably capture the
/// output keyed by `SagaId`, clear the staged slot, and Class-S persist
/// fail-closed. Returns the settle outcome (the caller sends the reply).
///
/// On a persist failure the durable capture + staged slot are rolled back so a
/// retried settle re-runs cleanly. The error is returned as `(mutated, err)`:
/// `mutated == false` for the pre-append failures (no staged slot — 13031; or
/// receipt signing — 13032-13034), `true` once the `ToolInvoked` append has
/// run (the event log was touched even if the durable capture was rolled back).
fn commit_b_first_settle(
    state: &mut PerContextState,
    deps: &ActorDeps,
    saga_id: &SagaId,
    output_bytes: &[u8],
    target_signing_key: &SigningKeyBytes,
) -> Result<CommitBSettleOutcome, (bool, ContextError)> {
    // The staged prepared carries the B-recorded provenance the receipt
    // preimage MUST be signed over (never re-read from the wire).
    let Some(SagaPreparedState::CrossContextToolInvocation(prepared)) =
        state.saga_pending.get(saga_id)
    else {
        return Err((
            false,
            ContextError::InvalidState(format!(
                "SCP-SAGA-13031: Commit-B settle for saga '{}' found no staged cross-context \
                 tool-invocation prepared state",
                saga_id.0
            )),
        ));
    };

    // Build the signed receipt from STAGED provenance + the captured output.
    // Pre-append: a signing failure leaves state untouched (mutated = false).
    let event_id = tool_invoked_event_id(saga_id);
    let receipt = build_signed_receipt(prepared, output_bytes, &event_id, target_signing_key)
        .map_err(|e| (false, e))?;
    // The receipt's JCS output bytes are the canonical preimage A re-hashes.
    let canonical_output = receipt.output_jcs.clone();

    // Snapshot the fields the ToolInvoked record needs before we drop the
    // `&prepared` borrow by mutating state. `recorded_chain_depth` /
    // `recorded_timestamp_ms` are B's staged values (never re-read from wire).
    let caller_did_str = prepared.caller_did.0.clone();
    let target_context_id = prepared.target_context_id;
    let caller_context_id = prepared.caller_context_id;
    let tool_registration_id = prepared.tool_registration_id.clone();
    let target_hex = hex_context_id(&target_context_id);

    // Append `ToolInvoked` to the local (target) log (spec §6.2.4 "Commit"):
    // caller ctx id / caller DID actor / B's re-derived depth + staged
    // timestamp. The SagaId-stable event id makes the append idempotent — a
    // replay short-circuits before reaching here.
    let tool_invoked_payload = serde_json::json!({
        "saga_id": saga_id.0,
        "tool_invoked_event_id": event_id,
        "caller_context_id": hex_context_id(&caller_context_id),
        "tool_registration_id": tool_registration_id,
        "chain_depth": receipt.chain_depth,
        "timestamp_ms": receipt.timestamp_ms,
    });
    // At-append onward: the event log is touched, so any failure is `mutated`.
    deps.event_log
        .append_context_event_with_payload(
            &target_context_id,
            &event_id,
            &caller_did_str,
            Some(&tool_invoked_payload),
        )
        .map_err(|e| (true, e))?;

    // Durably capture the output + signed receipt keyed by SagaId (§6.2.4
    // "Exactly-once execution with durable output capture") and clear the
    // staged slot (the session reservation is now applied via the capture).
    state.xctx_committed_outputs.insert(
        saga_id.clone(),
        CommittedToolInvocation {
            receipt: receipt.clone(),
            output_bytes: canonical_output.clone(),
            tool_invoked_event_id: event_id.clone(),
        },
    );
    state.saga_pending.remove(saga_id);

    // Class-S sync-persist fail-closed BEFORE acking (ADR-049 §9): the durable
    // output capture MUST land before the caller learns Commit-B succeeded, or a
    // crash in the coalesce window would re-invoke the tool on replay. On
    // persist failure roll the capture + slot back so a retry re-runs settle.
    if let Err(persist_err) = persist_state_fail_closed(state, deps, &target_hex) {
        state.xctx_committed_outputs.remove(saga_id);
        state.saga_pending.insert(
            saga_id.clone(),
            SagaPreparedState::CrossContextToolInvocation(reprepare_from_receipt(
                &receipt,
                &tool_registration_id,
            )),
        );
        return Err((true, persist_err));
    }

    // The capture + persist landed; serializing the receipt for the reply is a
    // pure encode of already-committed state — a failure here is `mutated`.
    let receipt_bytes = jcs_receipt_bytes(&receipt).map_err(|e| (true, e))?;
    Ok(CommitBSettleOutcome {
        receipt: receipt_bytes,
        output_bytes: canonical_output,
        tool_invoked_event_id: event_id,
    })
}

/// Sign the [`CrossContextToolReceipt`] over the staged B-recorded provenance +
/// `SHA-256(jcs(output))` + the `SagaId`-stable event id, using the target's
/// Active Signing Key (spec §6.2.4 "Receipt / response return path"). The
/// output is canonicalized to JCS so the receipt is self-verifying (the
/// verifier re-hashes the carried bytes with no re-canonicalization step).
fn build_signed_receipt(
    prepared: &CrossContextToolInvocationPrepared,
    output_bytes: &[u8],
    event_id: &str,
    target_signing_key: &SigningKeyBytes,
) -> Result<CrossContextToolReceipt, ContextError> {
    // Canonicalize the executor output to JCS — the exact bytes the preimage
    // hashes and the receipt carries (Output canonicalization obligation).
    let output_value: serde_json::Value = serde_json::from_slice(output_bytes).map_err(|e| {
        ContextError::CryptoFailed(format!(
            "SCP-SAGA-13032: Commit-B tool output is not valid JSON, cannot canonicalize \
             for the receipt: {e}"
        ))
    })?;
    let output_jcs = scp_protocol::jcs::to_vec(&output_value).map_err(|e| {
        ContextError::CryptoFailed(format!(
            "SCP-SAGA-13033: Commit-B receipt output JCS canonicalization failed: {e}"
        ))
    })?;

    let signing_key = target_signing_key.to_signing_key();
    CrossContextToolReceipt::sign(
        &signing_key,
        prepared.caller_context_id,
        prepared.target_context_id,
        prepared.caller_did.0.clone(),
        prepared.recorded_nonce,
        prepared.tool_registration_id.clone(),
        output_jcs,
        event_id.to_owned(),
        prepared.recorded_chain_depth,
        prepared.recorded_timestamp_ms,
    )
    .map_err(|e| {
        ContextError::CryptoFailed(format!(
            "SCP-SAGA-13034: Commit-B receipt signing failed: {e}"
        ))
    })
}

/// Reconstruct the staged [`CrossContextToolInvocationPrepared`] from a built
/// receipt, used ONLY to roll the `saga_pending` slot back on a Commit-B
/// persist failure (so a retry re-runs settle cleanly). Every field is
/// recoverable from the receipt (which is built from the staged prepared).
fn reprepare_from_receipt(
    receipt: &CrossContextToolReceipt,
    tool_registration_id: &str,
) -> CrossContextToolInvocationPrepared {
    CrossContextToolInvocationPrepared {
        caller_context_id: receipt.caller_context_id,
        target_context_id: receipt.target_context_id,
        caller_did: DID(receipt.caller_did.clone()),
        tool_registration_id: tool_registration_id.to_owned(),
        // The UCAN proof id is not carried on the receipt; the rolled-back slot
        // only needs to be a well-formed cross-context prepared so a retried
        // settle re-signs. The proof was already validated at Prepare-B and the
        // re-signed receipt does not depend on it.
        ucan_proof_id: String::new(),
        recorded_timestamp_ms: receipt.timestamp_ms,
        recorded_nonce: receipt.nonce,
        recorded_chain_depth: receipt.chain_depth,
    }
}

/// JCS-encode a [`CrossContextToolReceipt`] to the wire bytes the FSM forwards.
fn jcs_receipt_bytes(receipt: &CrossContextToolReceipt) -> Result<Vec<u8>, ContextError> {
    scp_protocol::jcs::to_vec(receipt).map_err(|e| {
        ContextError::CryptoFailed(format!(
            "SCP-SAGA-13035: Commit-B receipt serialization failed: {e}"
        ))
    })
}

// ---------------------------------------------------------------------------
// Commit-A — caller-context actor (spec §6.2.4)
// ---------------------------------------------------------------------------

/// Owned inputs for [`commit_a`], grouped to keep the handler signature within
/// the clippy argument budget.
struct CommitARequest {
    saga_id: SagaId,
    reservation: PreparedAFields,
    caller_context_id: [u8; 32],
    caller_did: DID,
    target_context_id: [u8; 32],
    nonce: [u8; 16],
    receipt: Vec<u8>,
    output_bytes: Vec<u8>,
}

/// Commit-A handler (spec §6.2.4 "Commit", caller side). Runs on the LOCAL
/// caller-context actor.
///
/// Settles the escrow + outbound-rate-limit reservation staged at Prepare-A
/// (§19.2.2), appends `CrossContextToolInvoked` referencing the target ctx id +
/// the SAME `nonce` (the join key between the two records, §6.2.4 "Dual
/// event-log recording"), Class-S sync-persists fail-closed, and acks.
/// Idempotent by `SagaId`: a replay re-acks without re-settling or re-appending
/// (the reservation's RAII ticket is consumed, so a true double-settle cannot
/// occur — but the durable marker is the idempotency witness).
async fn commit_a(
    state: &mut PerContextState,
    deps: &ActorDeps,
    req: CommitARequest,
    reply: tokio::sync::oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    use crate::context::tools_helpers::{ToolSettleRequest, settle_tool_economy};

    let caller_hex = hex_context_id(&req.caller_context_id);

    // Idempotency: a prior Commit-A already recorded this saga. Re-ack as a
    // no-op; the reservation handed back on replay is released (RAII) rather
    // than double-settled. (`xctx_committed_invocations` records committed A-side
    // sagas; absent ⇒ first Commit-A.)
    if state.xctx_committed_invocations.contains(&req.saga_id) {
        crate::context::tools_helpers::rollback_tool_economy(
            state,
            deps,
            req.reservation.reservation.ticket,
        )
        .await;
        let _ = reply.send(Ok(()));
        return Outcome::ok(());
    }

    // Settle (capture) the escrow + outbound rate-limit reservation. The
    // reservation was staged at Prepare-A and held by the FSM; Commit-A applies
    // it via the existing single-context settle/capture path (§19.2.2).
    let settle_request = ToolSettleRequest::Capture {
        generation: req.reservation.reservation.generation,
        ticket: req.reservation.reservation.ticket,
    };
    if let Err(err) =
        settle_tool_economy(state, deps, &caller_hex, &req.caller_did, settle_request).await
    {
        let sketch = outcome_error_sketch(&err);
        let _ = reply.send(Err(err));
        return Outcome::err_mutated(sketch);
    }

    // Append `CrossContextToolInvoked` to the local (caller) log: references the
    // target ctx id + the SAME nonce as B's `ToolInvoked` so an auditor joins
    // the two records into one provenance edge (spec §6.2.4 "Dual event-log
    // recording"). The output hash links the record to the verified receipt.
    let event_name = format!("CrossContextToolInvoked:{}", req.saga_id.0);
    let invoked_payload = serde_json::json!({
        "saga_id": req.saga_id.0,
        "target_context_id": hex_context_id(&req.target_context_id),
        "nonce": hex_nonce(&req.nonce),
        "output_hash": hex_output_hash(&req.output_bytes),
        "receipt_len": req.receipt.len(),
    });
    if let Err(err) = deps.event_log.append_context_event_with_payload(
        &req.caller_context_id,
        &event_name,
        req.caller_did.as_ref(),
        Some(&invoked_payload),
    ) {
        let sketch = outcome_error_sketch(&err);
        let _ = reply.send(Err(err));
        return Outcome::err_mutated(sketch);
    }

    // Record the committed A-side saga (the idempotency witness) and Class-S
    // persist fail-closed before acking: a crash that rolled the settle/marker
    // back behind an acked Commit-A would double-settle on replay.
    state.xctx_committed_invocations.insert(req.saga_id.clone());
    if let Err(persist_err) = persist_state_fail_closed(state, deps, &caller_hex) {
        state.xctx_committed_invocations.remove(&req.saga_id);
        let sketch = outcome_error_sketch(&persist_err);
        let _ = reply.send(Err(persist_err));
        return Outcome::err_mutated(sketch);
    }

    let _ = reply.send(Ok(()));
    Outcome::ok_mutated(())
}

// ---------------------------------------------------------------------------
// Abort — either side (spec §6.2.4 "Reservation release on every terminal path")
// ---------------------------------------------------------------------------

/// Abort handler (spec §6.2.4 "Reservation release on every terminal path").
/// Runs on EITHER side's local actor.
///
/// RAII-releases the staged reservations — escrow / outbound-RL on the CALLER
/// side (handed back via `reservation`, rolled back through the existing
/// rollback path); the tool-session on the TARGET side is released by clearing
/// the staged `saga_pending` slot (B stages no `ToolEconomyTicket`). Class-S
/// sync-persists fail-closed and acks. Idempotent: if the saga is already
/// terminal (no slot, no reservation) it is a clean no-op.
async fn abort(
    state: &mut PerContextState,
    deps: &ActorDeps,
    saga_id: &SagaId,
    reservation: Option<PreparedAFields>,
    reply: tokio::sync::oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let context_hex = hex_context_id(&state.context_id);

    // CALLER side: release the held escrow + outbound-RL reservation (RAII).
    if let Some(prepared) = reservation {
        crate::context::tools_helpers::rollback_tool_economy(
            state,
            deps,
            prepared.reservation.ticket,
        )
        .await;
    }

    // TARGET side: clear the staged tool-session slot (releases the session
    // reservation). Idempotent — a missing slot is a clean no-op.
    let had_slot = state.saga_pending.remove(saga_id).is_some();

    // If nothing was staged and no reservation was handed back, the saga was
    // already terminal — ack without a (redundant) persist.
    if !had_slot {
        let _ = reply.send(Ok(()));
        return Outcome::ok(());
    }

    // Class-S sync-persist fail-closed before acking: the cleared slot MUST
    // durably land so a crash respawn does not re-stage a stale saga.
    if let Err(persist_err) = persist_state_fail_closed(state, deps, &context_hex) {
        let sketch = outcome_error_sketch(&persist_err);
        let _ = reply.send(Err(persist_err));
        return Outcome::err_mutated(sketch);
    }

    let _ = reply.send(Ok(()));
    Outcome::ok_mutated(())
}

// ---------------------------------------------------------------------------
// EmitDivergenceMarker — either side (spec §6.2.4 "Dual event-log recording")
// ---------------------------------------------------------------------------

/// Emit a signed [`CrossContextDivergenceMarker`] into the LOCAL event log on a
/// `NeedsRepair` outcome (spec §6.2.4 "Dual event-log recording"). Runs on the
/// LOCAL actor; the emitting side's Active Signing Key is passed per-call (the
/// actor holds no key).
///
/// The marker records which side committed, the `SagaId`, the `nonce`, and the
/// committed-side event id — making a one-sided commit durably auditable rather
/// than a silent repudiation primitive. Class-S sync-persists fail-closed.
// Sync: the body performs only synchronous event-log append + Class-S persist,
// so it does not `.await`. Keeping it sync lets it take a shared
// `&PerContextState` borrow (which is `!Send`) without making the actor future
// `!Send` — a shared ref held across an `.await` would poison the actor task.
#[allow(clippy::too_many_arguments)]
fn emit_divergence_marker(
    state: &PerContextState,
    deps: &ActorDeps,
    saga_id: &SagaId,
    nonce: [u8; 16],
    committed_side: CommittedSide,
    committed_event_id: &str,
    signing_key: &SigningKeyBytes,
    reply: tokio::sync::oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let context_hex = hex_context_id(&state.context_id);

    let key = signing_key.to_signing_key();
    let marker = match CrossContextDivergenceMarker::sign(
        &key,
        saga_id.0.clone(),
        nonce,
        committed_side,
        committed_event_id.to_owned(),
    ) {
        Ok(m) => m,
        Err(e) => {
            let err = ContextError::CryptoFailed(format!(
                "SCP-SAGA-13036: divergence-marker signing failed for saga '{}': {e}",
                saga_id.0
            ));
            let sketch = outcome_error_sketch(&err);
            let _ = reply.send(Err(err));
            return Outcome::err(sketch);
        }
    };

    // Serialize the signed marker as the event payload so an auditor can verify
    // it directly from the log entry.
    let marker_payload = match serde_json::to_value(&marker) {
        Ok(v) => v,
        Err(e) => {
            let err = ContextError::CryptoFailed(format!(
                "SCP-SAGA-13037: divergence-marker serialization failed for saga '{}': {e}",
                saga_id.0
            ));
            let sketch = outcome_error_sketch(&err);
            let _ = reply.send(Err(err));
            return Outcome::err(sketch);
        }
    };
    let event_name = format!("CrossContextDivergenceMarker:{}", saga_id.0);
    if let Err(err) = deps.event_log.append_context_event_with_payload(
        &state.context_id,
        &event_name,
        "",
        Some(&marker_payload),
    ) {
        let sketch = outcome_error_sketch(&err);
        let _ = reply.send(Err(err));
        return Outcome::err(sketch);
    }

    // Class-S sync-persist fail-closed: the divergence record is the durable
    // audit witness operator-repair relies on; it MUST land before acking.
    if let Err(persist_err) = persist_state_fail_closed(state, deps, &context_hex) {
        let sketch = outcome_error_sketch(&persist_err);
        let _ = reply.send(Err(persist_err));
        return Outcome::err_mutated(sketch);
    }

    let _ = reply.send(Ok(()));
    Outcome::ok_mutated(())
}

/// Lowercase-hex encode a 16-byte nonce (the join key between the two
/// event-log records, recorded on both for the §6.2.4 auditor).
fn hex_nonce(nonce: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in nonce {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Lowercase-hex of `SHA-256(jcs(output))` — the verifiable link from the
/// caller's `CrossContextToolInvoked` record to the receipt's `output_hash`
/// without journaling the (possibly large/sensitive) output (§6.2.4).
fn hex_output_hash(output_bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest: [u8; 32] = Sha256::digest(output_bytes).into();
    let mut s = String::with_capacity(64);
    for b in &digest {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;

    use scp_identity::DID;
    use scp_platform::testing::{InMemoryKeyCustody, InMemoryStorage};
    use scp_platform::traits::{KeyCustody, KeyType};
    use scp_protocol::context::ContextError;
    use scp_protocol::context::governance::KeyResolver;
    use scp_protocol::context::roles::Capability;
    use scp_protocol::context::tools::registry::{ToolRegistration, ToolSchema};
    use scp_protocol::crypto::ucan::UcanToken;
    use tokio::sync::oneshot;

    use crate::crypto::ucan::mint::{MintParams, mint_ucan};

    use super::*;
    use crate::context::actor::deps::ActorDeps;
    use crate::context::actor::state::PerContextState;
    use crate::context::persistence::ContextPersistence;
    use crate::context::supervisor::saga_journal::SagaId;
    use crate::context::supervisor::supervisor::Supervisor;

    const CALLER: &str = "did:dht:z6MkCallerPrincipalXX";
    const OTHER: &str = "did:dht:z6MkOtherPrincipalXXX";
    const TOOL: &str = "calculator-v1";

    // --- test event-log / persistence stubs -------------------------------

    struct TestEventLog;
    impl crate::context::builder::ContextEventLogProvider for TestEventLog {
        fn init_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        fn append_event(
            &self,
            _id: &[u8; 32],
            _event: &str,
            _actor: &str,
            _payload: Option<&serde_json::Value>,
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        fn destroy_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
    }

    /// Persistence that accepts every write (success path).
    struct OkPersistence;
    /// Persistence whose `persist_context` ALWAYS fails (fail-closed path).
    struct FailPersistence;

    macro_rules! impl_persistence {
        ($ty:ty, $persist:expr) => {
            impl ContextPersistence for $ty {
                fn persist_context(
                    &self,
                    _: &str,
                    _: &crate::context::state::ContextSnapshot,
                ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                    $persist
                }
                fn load_context(
                    &self,
                    _: &str,
                ) -> Result<
                    Option<crate::context::state::ContextSnapshot>,
                    Box<dyn std::error::Error + Send + Sync>,
                > {
                    Ok(None)
                }
                fn persist_broadcast(
                    &self,
                    _: &str,
                    _: &scp_protocol::context::broadcast::BroadcastContextSnapshot,
                ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                    Ok(())
                }
                fn load_broadcast(
                    &self,
                    _: &str,
                ) -> Result<
                    Option<scp_protocol::context::broadcast::BroadcastContextSnapshot>,
                    Box<dyn std::error::Error + Send + Sync>,
                > {
                    Ok(None)
                }
                fn delete_context(
                    &self,
                    _: &str,
                ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                    Ok(())
                }
                fn list_persisted_contexts(
                    &self,
                ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
                    Ok(Vec::new())
                }
            }
        };
    }
    impl_persistence!(OkPersistence, Ok(()));
    impl_persistence!(FailPersistence, Err("induced persist failure".into()));

    // --- deps + state fixtures --------------------------------------------

    /// Build an `ActorDeps` whose `key_resolver` resolves `issuer_did` to
    /// `issuer_key` and whose persistence is `persistence`.
    async fn build_deps(
        issuer_did: String,
        issuer_key: ed25519_dalek::VerifyingKey,
        persistence: Box<dyn ContextPersistence>,
    ) -> ActorDeps {
        let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
            "did:dht:z6MktestSagaActor".to_owned(),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
            Box::new(TestEventLog);
        let key_resolver: KeyResolver = Arc::new(move |did: &DID| {
            if did.as_ref() == issuer_did {
                Some(issuer_key)
            } else {
                None
            }
        });
        let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
            Arc::new(
                crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                    InMemoryStorage::new(),
                )),
            );
        let supervisor = Supervisor::with_providers(
            crypto,
            transport,
            event_log,
            key_resolver,
            Some(persistence),
            None,
            None,
            None,
            mls_storage,
        );
        supervisor
            .build_actor_deps(&DID("did:example:saga-test-owner".to_owned()))
            .await
            .expect("build_actor_deps")
    }

    /// An encrypted state whose `context_id == [ctx_byte; 32]`, with `member`
    /// holding `ToolInterface`, `creator_did = creator`, and a registered tool
    /// `TOOL` with a 2-field input schema (passes the specificity floor).
    async fn target_state(ctx_byte: u8, creator: &str, member: &str) -> PerContextState {
        let mut st = PerContextState::new_for_test_encrypted(
            [ctx_byte; 32],
            1_700_000_000,
            DID(creator.to_owned()),
        );
        st.handle
            .transition_to(&scp_protocol::context::ContextState::Active)
            .await
            .expect("active");
        // creator_did binds the UCAN root issuer (validate_ucan step 4).
        st.role_state.creator_did = creator.to_owned();
        // Grant the caller ToolInterface + ToolInvokeAll so both the outbound
        // capability gate and the ceiling (tool_invoke:*) admit the proof.
        st.role_state.members.insert(member.to_owned());
        let mut caps = HashSet::new();
        caps.insert(Capability::ToolInterface);
        caps.insert(Capability::ToolInvokeAll);
        st.role_state
            .member_capabilities
            .insert(member.to_owned(), caps);
        st.role_state.ceiling = scp_protocol::context::roles::CapabilityCeiling::new([
            Capability::ToolInterface,
            Capability::ToolInvokeAll,
        ]);
        st.governance.registered_tools.push(ToolRegistration {
            tool_id: TOOL.to_owned(),
            name: "Calculator".to_owned(),
            description: "adds".to_owned(),
            schema: ToolSchema {
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": { "a": {"type": "number"}, "b": {"type": "number"} }
                }),
                output_schema: serde_json::json!({
                    "type": "object",
                    "properties": { "result": {"type": "number"} }
                }),
            },
            implementation_hash: [0xAA; 32],
            test_vectors: vec![],
            operator_did: DID(creator.to_owned()),
            cost: None,
            registered_at: 0,
            signature: Vec::new(),
        });
        st
    }

    /// Mint a UCAN with `tool_invoke:TOOL` capability, issued by `creator`
    /// (the context creator = root issuer) to `audience`, scoped to the hex
    /// of `[ctx_byte; 32]`. Returns the issuer pubkey + the token.
    async fn mint_tool_ucan(
        ctx_byte: u8,
        creator_did: &str,
        creator_key: &scp_platform::traits::KeyHandle,
        custody: &InMemoryKeyCustody,
        audience: &str,
    ) -> UcanToken {
        let ctx_hex = hex_context_id(&[ctx_byte; 32]);
        let caps = vec![format!("tool_invoke:{TOOL}")];
        let params = MintParams {
            issuer_did: creator_did,
            issuer_key: creator_key,
            audience_did: audience,
            context_id: &ctx_hex,
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };
        mint_ucan(&params, custody, &scp_primitives::SystemClock)
            .await
            .expect("mint")
    }

    fn valid_input() -> serde_json::Value {
        serde_json::json!({ "a": 1, "b": 2 })
    }

    fn prepare_b_request(
        ctx_byte: u8,
        ucan_proof_id: Option<String>,
        asserted_chain_depth: u8,
        now_ms: u64,
    ) -> PrepareBRequest {
        PrepareBRequest {
            saga_id: SagaId("saga-xctx-1".to_owned()),
            caller_context_id: [0x99; 32],
            target_context_id: [ctx_byte; 32],
            caller_did: DID(CALLER.to_owned()),
            tool_registration_id: TOOL.to_owned(),
            ucan_proof_id,
            input: valid_input(),
            asserted_chain_depth,
            asserted_nonce: [0x42; 16],
            asserted_timestamp_ms: now_ms,
        }
    }

    // --- Prepare-A tests --------------------------------------------------

    #[tokio::test]
    async fn prepare_a_accepts_stages_and_persists() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0x11, OTHER, CALLER).await;
        // Prepare-A runs on the CALLER context; the caller is a member here.
        st.role_state.creator_did = CALLER.to_owned();
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        let (tx, rx) = oneshot::channel();
        let out = prepare_a(
            &mut st,
            &deps,
            &[0x11; 32],
            &DID(CALLER.to_owned()),
            TOOL,
            5,
            tx,
        )
        .await;
        assert!(out.result.is_ok(), "prepare_a outcome: {:?}", out.result);
        let prepared = rx.await.unwrap().expect("prepared-A");
        // The reservation handle is the Send carrier the FSM holds; the FSM
        // settles it on Commit-A or releases it on a terminal non-commit path.
        // This test stands in for that terminal release (RAII contract,
        // §6.2.4 "Reservation release on every terminal path") by rolling the
        // reservation back — dropping a live ToolEconomyTicket is a balance-
        // invariant violation by design.
        crate::context::tools_helpers::rollback_tool_economy(
            &mut st,
            &deps,
            prepared.reservation.ticket,
        )
        .await;
    }

    #[tokio::test]
    async fn prepare_a_rejects_caller_without_tool_interface() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0x11, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();
        // Strip the ToolInterface capability.
        st.role_state
            .member_capabilities
            .insert(CALLER.to_owned(), HashSet::new());
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        let (tx, rx) = oneshot::channel();
        let _ = prepare_a(
            &mut st,
            &deps,
            &[0x11; 32],
            &DID(CALLER.to_owned()),
            TOOL,
            5,
            tx,
        )
        .await;
        let err = rx.await.unwrap().expect_err("must reject");
        assert!(matches!(err, ContextError::PermissionDenied(m) if m.contains("SCP-SAGA-13010")));
    }

    #[tokio::test]
    async fn prepare_a_rejects_caller_not_in_allowed_callers() {
        use scp_protocol::context::tools::interface::{OutboundPolicy, ToolInterface};
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0x11, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();
        // Establish an interface whose allowed_callers excludes the caller.
        st.governance.tool_interfaces.push(ToolInterface {
            source_context: hex_context_id(&[0x11; 32]),
            target_context: hex_context_id(&[0x22; 32]),
            tool_id: TOOL.to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: Some(OutboundPolicy {
                allowed_callers: vec![DID(OTHER.to_owned())],
                ..OutboundPolicy::default()
            }),
            inbound_policy: None,
        });
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        let (tx, rx) = oneshot::channel();
        let _ = prepare_a(
            &mut st,
            &deps,
            &[0x11; 32],
            &DID(CALLER.to_owned()),
            TOOL,
            5,
            tx,
        )
        .await;
        let err = rx.await.unwrap().expect_err("must reject");
        assert!(matches!(err, ContextError::PermissionDenied(m) if m.contains("SCP-SAGA-13011")));
    }

    #[tokio::test]
    async fn prepare_a_fail_closed_persist_returns_err_without_applying() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0x11, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(FailPersistence),
        )
        .await;

        let (tx, rx) = oneshot::channel();
        let out = prepare_a(
            &mut st,
            &deps,
            &[0x11; 32],
            &DID(CALLER.to_owned()),
            TOOL,
            5,
            tx,
        )
        .await;
        assert!(out.result.is_err());
        let err = rx.await.unwrap().expect_err("persist must fail-close");
        assert!(matches!(err, ContextError::PersistenceFailed(_)));
    }

    // --- Prepare-B tests --------------------------------------------------

    #[tokio::test]
    async fn prepare_b_accepts_stages_all_eight_b_recorded_fields() {
        let custody = InMemoryKeyCustody::new();
        let creator_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let creator_pk = custody.public_key(&creator_handle).await.unwrap();
        let creator_did = format!("did:dht:z{}", zbase32::encode(creator_pk.as_bytes()));
        let creator_verifying_key =
            ed25519_dalek::VerifyingKey::from_bytes(creator_pk.as_bytes().try_into().unwrap())
                .unwrap();

        let mut st = target_state(0x33, &creator_did, CALLER).await;
        // The proof is delegated to the CALLER (correct principal).
        let token = mint_tool_ucan(0x33, &creator_did, &creator_handle, &custody, CALLER).await;
        st.xctx_ucan_proofs
            .proofs
            .insert("proof-1".to_owned(), token);
        let deps = build_deps(creator_did, creator_verifying_key, Box::new(OkPersistence)).await;
        let now_ms = deps.clock.now_millis();

        let (tx, rx) = oneshot::channel();
        let req = prepare_b_request(0x33, Some("proof-1".to_owned()), 2, now_ms);
        let out = prepare_b(&mut st, &deps, req, tx).await;
        assert!(out.result.is_ok(), "prepare_b: {:?}", out.result);
        let fields = rx.await.unwrap().expect("prepared-B");

        // B re-derived chain depth = incoming(2) + 1.
        assert_eq!(fields.recorded_chain_depth, 3);
        // B staged its copy of the wire nonce.
        assert_eq!(fields.recorded_nonce, [0x42; 16]);
        // recorded_timestamp_ms is B's own clock (NOT the caller-asserted ts).
        assert!(fields.recorded_timestamp_ms >= now_ms);

        // The eight-field prepared was staged into saga_pending with B-recorded
        // provenance, NOT the caller-asserted advisory depth.
        let staged = st
            .saga_pending
            .get(&SagaId("saga-xctx-1".to_owned()))
            .unwrap();
        match staged {
            SagaPreparedState::CrossContextToolInvocation(p) => {
                assert_eq!(p.target_context_id, [0x33; 32]);
                assert_eq!(p.caller_did, DID(CALLER.to_owned()));
                assert_eq!(p.tool_registration_id, TOOL);
                assert_eq!(p.ucan_proof_id, "proof-1");
                assert_eq!(p.recorded_chain_depth, 3);
                assert_eq!(p.recorded_nonce, [0x42; 16]);
            }
            // `SagaPreparedState` is non-Debug (§9.4.3 barrier), so name the
            // wrong arm without formatting it.
            SagaPreparedState::StandingPairCreate(_)
            | SagaPreparedState::BroadcastHostingHandshake(_) => {
                panic!("wrong staged variant — expected CrossContextToolInvocation")
            }
        }
    }

    #[tokio::test]
    async fn prepare_b_confused_deputy_audience_mismatch_is_rejected() {
        // The UCAN is VALID and grants tool_invoke:TOOL — but it is delegated to
        // a DIFFERENT principal (OTHER) than the carried caller_did (CALLER). A
        // confused-deputy attempt: the carried caller references a stronger
        // proof in B's store delegated to someone else. MUST be rejected.
        let custody = InMemoryKeyCustody::new();
        let creator_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let creator_pk = custody.public_key(&creator_handle).await.unwrap();
        let creator_did = format!("did:dht:z{}", zbase32::encode(creator_pk.as_bytes()));
        let creator_verifying_key =
            ed25519_dalek::VerifyingKey::from_bytes(creator_pk.as_bytes().try_into().unwrap())
                .unwrap();

        let mut st = target_state(0x44, &creator_did, CALLER).await;
        // Proof audience = OTHER, NOT the carried caller_did (CALLER).
        let token = mint_tool_ucan(0x44, &creator_did, &creator_handle, &custody, OTHER).await;
        st.xctx_ucan_proofs
            .proofs
            .insert("proof-other".to_owned(), token);
        let deps = build_deps(creator_did, creator_verifying_key, Box::new(OkPersistence)).await;
        let now_ms = deps.clock.now_millis();

        let (tx, rx) = oneshot::channel();
        let req = prepare_b_request(0x44, Some("proof-other".to_owned()), 1, now_ms);
        let out = prepare_b(&mut st, &deps, req, tx).await;
        assert!(
            out.result.is_err(),
            "confused-deputy proof must be rejected"
        );
        let err = rx.await.unwrap().expect_err("must reject");
        assert!(
            matches!(&err, ContextError::PermissionDenied(m) if m.contains("SCP-SAGA-13013")),
            "expected SCP-SAGA-13013 confused-deputy rejection, got {err:?}"
        );
        // Nothing staged — the slot stays empty on rejection.
        assert!(st.saga_pending.is_empty());
    }

    #[tokio::test]
    async fn prepare_b_rejects_stale_timestamp() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let mut st = target_state(0x55, OTHER, CALLER).await;
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();
        // 1 hour in the past — far outside the §9.14 5-minute skew.
        let stale_ms = now_ms.saturating_sub(60 * 60 * 1000);

        let (tx, rx) = oneshot::channel();
        let req = prepare_b_request(0x55, None, 1, stale_ms);
        let _ = prepare_b(&mut st, &deps, req, tx).await;
        let err = rx.await.unwrap().expect_err("stale ts must reject");
        assert!(matches!(err, ContextError::PermissionDenied(m) if m.contains("SCP-SAGA-13018")));
    }

    #[tokio::test]
    async fn prepare_b_rejects_duplicate_nonce() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let mut st = target_state(0x66, OTHER, CALLER).await;
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();
        // Pre-seed the dedup cache with the request nonce.
        st.xctx_nonce_dedup
            .record([0x42; 16], deps.clock.now_secs());

        let (tx, rx) = oneshot::channel();
        let req = prepare_b_request(0x66, None, 1, now_ms);
        let _ = prepare_b(&mut st, &deps, req, tx).await;
        let err = rx.await.unwrap().expect_err("dup nonce must reject");
        assert!(matches!(err, ContextError::PermissionDenied(m) if m.contains("SCP-SAGA-13019")));
    }

    #[tokio::test]
    async fn prepare_b_rejects_chain_depth_overflow() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let mut st = target_state(0x77, OTHER, CALLER).await;
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();
        // Default max_chain_depth is 8; incoming 8 → 8+1 = 9 > 8 ⇒ reject.
        let (tx, rx) = oneshot::channel();
        let req = prepare_b_request(0x77, None, 8, now_ms);
        let _ = prepare_b(&mut st, &deps, req, tx).await;
        let err = rx.await.unwrap().expect_err("depth overflow must reject");
        assert!(matches!(err, ContextError::PermissionDenied(m) if m.contains("SCP-SAGA-13020")));
    }

    #[tokio::test]
    async fn prepare_b_rejects_target_context_mismatch() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let mut st = target_state(0x88, OTHER, CALLER).await;
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();
        // Build a request whose target_context_id is a DIFFERENT context.
        let mut req = prepare_b_request(0x88, None, 1, now_ms);
        req.target_context_id = [0xEE; 32];

        let (tx, rx) = oneshot::channel();
        let _ = prepare_b(&mut st, &deps, req, tx).await;
        let err = rx.await.unwrap().expect_err("target mismatch must reject");
        assert!(matches!(err, ContextError::PermissionDenied(m) if m.contains("SCP-SAGA-13014")));
    }

    #[tokio::test]
    async fn prepare_b_rejects_degenerate_broad_input_schema() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let mut st = target_state(0x99, OTHER, CALLER).await;
        // Replace the registered tool's schemas with degenerate broad ones
        // (zero declared fields on both sides ⇒ below the specificity floor).
        if let Some(reg) = st
            .governance
            .registered_tools
            .iter_mut()
            .find(|t| t.tool_id == TOOL)
        {
            reg.schema.input_schema = serde_json::json!({ "type": "object" });
            reg.schema.output_schema = serde_json::json!({ "type": "object" });
        }
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();

        let (tx, rx) = oneshot::channel();
        let req = prepare_b_request(0x99, None, 1, now_ms);
        let _ = prepare_b(&mut st, &deps, req, tx).await;
        let err = rx
            .await
            .unwrap()
            .expect_err("degenerate schema must reject");
        assert!(matches!(err, ContextError::PermissionDenied(m) if m.contains("SCP-SAGA-13017")));
    }

    #[tokio::test]
    async fn prepare_b_fail_closed_persist_returns_err() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let mut st = target_state(0xAA, OTHER, CALLER).await;
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(FailPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();

        let (tx, rx) = oneshot::channel();
        // Ungated tool (no proof) so every other check passes and we reach the
        // Class-S persist, which fails.
        let req = prepare_b_request(0xAA, None, 1, now_ms);
        let out = prepare_b(&mut st, &deps, req, tx).await;
        assert!(out.result.is_err());
        let err = rx.await.unwrap().expect_err("persist must fail-close");
        assert!(matches!(err, ContextError::PersistenceFailed(_)));
        // The staged slot was rolled back on persist failure.
        assert!(st.saga_pending.is_empty());
    }

    // --- Commit-B / Commit-A / Abort tests --------------------------------

    /// A target signing key wrapped for the per-call receipt-signing argument.
    fn signing_key_bytes(seed: u8) -> SigningKeyBytes {
        SigningKeyBytes::from_signing_key(&ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
    }

    /// Stage a Prepare-B slot for `saga_id` by running the real `prepare_b`
    /// (ungated tool) so Commit-B has the B-recorded provenance to sign over.
    async fn stage_prepared_b(
        st: &mut PerContextState,
        deps: &ActorDeps,
        ctx_byte: u8,
        saga_id: &str,
        now_ms: u64,
    ) {
        let mut req = prepare_b_request(ctx_byte, None, 2, now_ms);
        req.saga_id = SagaId(saga_id.to_owned());
        let (tx, rx) = oneshot::channel();
        let out = prepare_b(st, deps, req, tx).await;
        assert!(out.result.is_ok(), "stage prepare_b: {:?}", out.result);
        rx.await.unwrap().expect("prepared-B staged");
    }

    #[tokio::test]
    async fn commit_b_reserve_then_settle_stages_output_appends_and_signs() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let mut st = target_state(0xC1, OTHER, CALLER).await;
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();
        let saga = SagaId("saga-commit-b-1".to_owned());
        stage_prepared_b(&mut st, &deps, 0xC1, &saga.0, now_ms).await;

        // Reserve: slot present, not yet committed ⇒ ReadyToExecute.
        let (tx, rx) = oneshot::channel();
        let out = commit_b_reserve(&st, &saga, tx);
        assert!(out.result.is_ok());
        assert!(matches!(
            rx.await.unwrap().expect("reserve"),
            CommitBReserveOutcome::ReadyToExecute
        ));

        // Settle: capture output, append ToolInvoked, sign a verifiable receipt.
        let target_key = signing_key_bytes(0x55);
        let output = br#"{"result":42}"#.to_vec();
        let (tx, rx) = oneshot::channel();
        let out = commit_b_settle(&mut st, &deps, &saga, output.clone(), &target_key, tx).await;
        assert!(out.result.is_ok(), "settle: {:?}", out.result);
        let settled = rx.await.unwrap().expect("settled");

        // The receipt verifies against the target's signing key.
        let receipt: CrossContextToolReceipt =
            serde_json::from_slice(&settled.receipt).expect("receipt json");
        receipt
            .verify(&target_key.to_signing_key().verifying_key())
            .expect("receipt verifies against target signing key");
        // The receipt is signed over B's STAGED provenance: re-derived depth 3
        // (incoming 2 + 1) and the staged wire nonce.
        assert_eq!(receipt.chain_depth, 3);
        assert_eq!(receipt.nonce, [0x42; 16]);
        assert_eq!(receipt.tool_invoked_event_id, settled.tool_invoked_event_id);
        // The output was captured durably and the staged slot cleared.
        assert!(st.xctx_committed_outputs.contains_key(&saga));
        assert!(st.saga_pending.is_empty());
    }

    #[tokio::test]
    async fn commit_b_settle_replay_re_emits_identical_receipt_without_re_append() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let mut st = target_state(0xC2, OTHER, CALLER).await;
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();
        let saga = SagaId("saga-commit-b-replay".to_owned());
        stage_prepared_b(&mut st, &deps, 0xC2, &saga.0, now_ms).await;

        let target_key = signing_key_bytes(0x66);
        let output = br#"{"result":7}"#.to_vec();

        let (tx, rx) = oneshot::channel();
        commit_b_settle(&mut st, &deps, &saga, output.clone(), &target_key, tx).await;
        let first = rx.await.unwrap().expect("first settle");
        // Capture the durable event id; a replay must reproduce it.
        let captured_event_id = st
            .xctx_committed_outputs
            .get(&saga)
            .unwrap()
            .tool_invoked_event_id
            .clone();

        // Replay: a DIFFERENT output + a DIFFERENT key would re-sign divergently
        // if the tool were re-invoked — but the replay re-emits the STORED
        // capture, so the receipt + event id are byte-for-byte identical.
        let (tx, rx) = oneshot::channel();
        let out = commit_b_settle(
            &mut st,
            &deps,
            &saga,
            br#"{"result":999}"#.to_vec(),
            &signing_key_bytes(0x77),
            tx,
        )
        .await;
        assert!(out.result.is_ok());
        let replay = rx.await.unwrap().expect("replay settle");

        assert_eq!(
            first.receipt, replay.receipt,
            "receipt must be identical on replay"
        );
        assert_eq!(
            first.output_bytes, replay.output_bytes,
            "stored output re-emitted"
        );
        assert_eq!(replay.tool_invoked_event_id, captured_event_id);
        // Reserve on a committed saga short-circuits to AlreadyCommitted.
        let (tx, rx) = oneshot::channel();
        commit_b_reserve(&st, &saga, tx);
        assert!(matches!(
            rx.await.unwrap().expect("reserve replay"),
            CommitBReserveOutcome::AlreadyCommitted { .. }
        ));
    }

    #[tokio::test]
    async fn commit_b_settle_canonicalizes_output_so_receipt_self_verifies() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let mut st = target_state(0xC3, OTHER, CALLER).await;
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();
        let saga = SagaId("saga-commit-b-jcs".to_owned());
        stage_prepared_b(&mut st, &deps, 0xC3, &saga.0, now_ms).await;

        let target_key = signing_key_bytes(0x88);
        // Non-canonical (pretty-printed, reordered keys) output — the handler
        // re-canonicalizes so the receipt's output_jcs is the hashed preimage.
        let output = br#"{ "b": 2, "a": 1 }"#.to_vec();
        let (tx, rx) = oneshot::channel();
        commit_b_settle(&mut st, &deps, &saga, output, &target_key, tx).await;
        let settled = rx.await.unwrap().expect("settled");
        let receipt: CrossContextToolReceipt =
            serde_json::from_slice(&settled.receipt).expect("receipt json");
        // Self-verifying: output_hash recomputes from the carried JCS bytes.
        receipt
            .verify(&target_key.to_signing_key().verifying_key())
            .expect("self-verifying receipt");
        assert_eq!(receipt.output_jcs, br#"{"a":1,"b":2}"#.to_vec());
    }

    #[tokio::test]
    async fn commit_a_settles_escrow_and_appends_invoked_idempotently() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        // Prepare-A runs on the CALLER context.
        let mut st = target_state(0xC4, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        // Stage Prepare-A to obtain the held reservation (FSM carries it).
        let (tx, rx) = oneshot::channel();
        prepare_a(
            &mut st,
            &deps,
            &[0xC4; 32],
            &DID(CALLER.to_owned()),
            TOOL,
            5,
            tx,
        )
        .await;
        let prepared_a = rx.await.unwrap().expect("prepared-A");

        let saga = SagaId("saga-commit-a-1".to_owned());
        let nonce = [0x42; 16];
        let req = CommitARequest {
            saga_id: saga.clone(),
            reservation: prepared_a,
            caller_context_id: [0xC4; 32],
            caller_did: DID(CALLER.to_owned()),
            target_context_id: [0xEE; 32],
            nonce,
            receipt: br#"{"sig":"x"}"#.to_vec(),
            output_bytes: br#"{"result":1}"#.to_vec(),
        };
        let (tx, rx) = oneshot::channel();
        let out = commit_a(&mut st, &deps, req, tx).await;
        assert!(out.result.is_ok(), "commit_a: {:?}", out.result);
        rx.await.unwrap().expect("commit-a ack");
        // The committed A-side saga is the idempotency witness.
        assert!(st.xctx_committed_invocations.contains(&saga));

        // Replay: a fresh reservation handed back is released (RAII); re-ack
        // without re-settling (the witness short-circuits).
        let (tx2, rx2) = oneshot::channel();
        prepare_a(
            &mut st,
            &deps,
            &[0xC4; 32],
            &DID(CALLER.to_owned()),
            TOOL,
            5,
            tx2,
        )
        .await;
        let replay_reservation = rx2.await.unwrap().expect("prepared-A replay");
        let replay_req = CommitARequest {
            saga_id: saga.clone(),
            reservation: replay_reservation,
            caller_context_id: [0xC4; 32],
            caller_did: DID(CALLER.to_owned()),
            target_context_id: [0xEE; 32],
            nonce,
            receipt: br#"{"sig":"x"}"#.to_vec(),
            output_bytes: br#"{"result":1}"#.to_vec(),
        };
        let (tx, rx) = oneshot::channel();
        let out = commit_a(&mut st, &deps, replay_req, tx).await;
        assert!(out.result.is_ok());
        rx.await.unwrap().expect("commit-a replay ack");
    }

    #[tokio::test]
    async fn abort_b_side_releases_session_by_clearing_slot() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let mut st = target_state(0xC5, OTHER, CALLER).await;
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();
        let saga = SagaId("saga-abort-b".to_owned());
        stage_prepared_b(&mut st, &deps, 0xC5, &saga.0, now_ms).await;
        assert!(!st.saga_pending.is_empty());

        // Abort on the B side (no reservation): clears the staged slot.
        let (tx, rx) = oneshot::channel();
        let out = abort(&mut st, &deps, &saga, None, tx).await;
        assert!(out.result.is_ok(), "abort: {:?}", out.result);
        rx.await.unwrap().expect("abort ack");
        assert!(st.saga_pending.is_empty());

        // Idempotent: a second abort on the now-terminal saga is a clean no-op.
        let (tx, rx) = oneshot::channel();
        let out = abort(&mut st, &deps, &saga, None, tx).await;
        assert!(out.result.is_ok());
        rx.await.unwrap().expect("abort idempotent ack");
    }

    #[tokio::test]
    async fn abort_a_side_releases_escrow_reservation() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0xC6, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        // The caller starts with a finite budget; reserve, then abort releases it.
        let (tx, rx) = oneshot::channel();
        prepare_a(
            &mut st,
            &deps,
            &[0xC6; 32],
            &DID(CALLER.to_owned()),
            TOOL,
            5,
            tx,
        )
        .await;
        let prepared_a = rx.await.unwrap().expect("prepared-A");

        // No staged slot on A (B stages the slot); abort releases the held
        // escrow/rate-limit reservation via the rollback path and acks.
        let saga = SagaId("saga-abort-a".to_owned());
        let (tx, rx) = oneshot::channel();
        let out = abort(&mut st, &deps, &saga, Some(prepared_a), tx).await;
        assert!(out.result.is_ok(), "abort-a: {:?}", out.result);
        rx.await.unwrap().expect("abort-a ack");
    }

    #[tokio::test]
    async fn emit_divergence_marker_appends_verifiable_marker() {
        use scp_protocol::context::tools::cross_context_saga::CrossContextDivergenceMarker;
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let st = target_state(0xC7, OTHER, CALLER).await;
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        let signing = signing_key_bytes(0x99);
        let saga = SagaId("saga-divergence".to_owned());
        let (tx, rx) = oneshot::channel();
        let out = emit_divergence_marker(
            &st,
            &deps,
            &saga,
            [0xAB; 16],
            CommittedSide::Target,
            "evt-committed-9",
            &signing,
            tx,
        );
        assert!(out.result.is_ok(), "emit: {:?}", out.result);
        rx.await.unwrap().expect("emit ack");

        // The marker the handler signed verifies against the emitting key.
        let marker = CrossContextDivergenceMarker::sign(
            &signing.to_signing_key(),
            saga.0.clone(),
            [0xAB; 16],
            CommittedSide::Target,
            "evt-committed-9".to_owned(),
        )
        .expect("marker");
        marker
            .verify(&signing.to_signing_key().verifying_key())
            .expect("marker verifies");
    }

    #[tokio::test]
    async fn commit_b_reserve_without_staged_slot_is_rejected() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let st = target_state(0xC8, OTHER, CALLER).await;
        // `commit_b_reserve` is a sync, deps-less read-only check.
        let _deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let (tx, rx) = oneshot::channel();
        let out = commit_b_reserve(&st, &SagaId("never-prepared".to_owned()), tx);
        assert!(out.result.is_err());
        let err = rx.await.unwrap().expect_err("must reject");
        assert!(matches!(err, ContextError::InvalidState(m) if m.contains("SCP-SAGA-13030")));
    }

    #[tokio::test]
    async fn commit_b_settle_fail_closed_rolls_back_capture() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let mut st = target_state(0xC9, OTHER, CALLER).await;
        // Stage with a passing persistence, then swap to a failing one for settle.
        let ok_deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = ok_deps.clock.now_millis();
        let saga = SagaId("saga-settle-failclose".to_owned());
        stage_prepared_b(&mut st, &ok_deps, 0xC9, &saga.0, now_ms).await;

        let fail_deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(FailPersistence),
        )
        .await;
        let (tx, rx) = oneshot::channel();
        let out = commit_b_settle(
            &mut st,
            &fail_deps,
            &saga,
            br#"{"result":1}"#.to_vec(),
            &signing_key_bytes(0xAA),
            tx,
        )
        .await;
        assert!(out.result.is_err());
        let err = rx.await.unwrap().expect_err("persist must fail-close");
        assert!(matches!(err, ContextError::PersistenceFailed(_)));
        // The capture was rolled back; the staged slot restored for a retry.
        assert!(!st.xctx_committed_outputs.contains_key(&saga));
        assert!(st.saga_pending.contains_key(&saga));
    }
}
