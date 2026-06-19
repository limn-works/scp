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

use crate::context::actor::commands::{PreparedAFields, PreparedBFields, SagaPhaseMessage};
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::PerContextState;
use crate::context::economy_logic::{ContextRevocationChecker, KeyResolverDidResolver};
use crate::context::messaging_helpers::persist_state_fail_closed;
use crate::context::supervisor::saga_prepared_state::{
    CrossContextToolInvocationPrepared, SagaPreparedState,
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
        // Commit / Abort / divergence-marker bodies land in later slices. The
        // dispatch `match` stays exhaustive so a new phase is a compile error.
        SagaPhaseMessage::CommitB { reply, .. }
        | SagaPhaseMessage::CommitA { reply, .. }
        | SagaPhaseMessage::Abort { reply, .. }
        | SagaPhaseMessage::EmitDivergenceMarker { reply, .. } => not_implemented_unit(reply),
    }
}

/// Reply `NotImplemented` on a `Result<(), _>` oneshot and return the same
/// error in the [`Outcome`]. Used by the slice-4/6 phase arms.
fn not_implemented_unit(
    reply: tokio::sync::oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let err = || {
        ContextError::NotImplemented(
            "saga Commit/Abort/divergence-marker handler — lands in a later \
             slice of the cross-context tool-invocation saga"
                .to_owned(),
        )
    };
    let _ = reply.send(Err(err()));
    Outcome::err(err())
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

    #[tokio::test]
    async fn dispatch_commit_phase_arms_are_not_implemented() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let mut st = target_state(0xBB, OTHER, CALLER).await;
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        let (tx, rx) = oneshot::channel();
        let out = dispatch(
            &mut st,
            &deps,
            SagaPhaseMessage::CommitB {
                saga_id: SagaId("s".to_owned()),
                reply: tx,
            },
        )
        .await;
        assert!(matches!(out.result, Err(ContextError::NotImplemented(_))));
        assert!(matches!(
            rx.await.unwrap(),
            Err(ContextError::NotImplemented(_))
        ));
    }
}
