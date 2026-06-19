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
    CommittedSide, CrossContextDivergenceMarker, CrossContextDivergenceMarkerFields,
    CrossContextToolReceipt, CrossContextToolReceiptFields,
};

use crate::context::actor::commands::{
    CommitBReserveOutcome, CommitBReserveReply, CommitBSettleOutcome, CommitBSettleReply,
    PreparedAFields, PreparedBFields, SagaPhaseMessage, SigningKeyBytes,
};
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::{Outcome, outcome_error_sketch};
use crate::context::actor::state::PerContextState;
use crate::context::economy_logic::{ContextRevocationChecker, KeyResolverDidResolver};
use crate::context::messaging_helpers::persist_state_fail_closed;
use crate::context::supervisor::saga_journal::SagaId;
use crate::context::supervisor::saga_prepared_state::{
    CommittedToolInvocation, CrossContextToolInvocationPrepared, SagaPreparedState,
};
use crate::context::tools_helpers::reserve_tool_economy;

/// Eviction TTL for B's per-target cross-context-saga nonce-dedup cache
/// ([`PerContextState::xctx_nonce_dedup`]).
///
/// Set to **strictly more than** the §9.14 clock-skew tolerance the Prepare-B
/// freshness check applies (`DEFAULT_CLOCK_SKEW_TOLERANCE_SECS`) — here exactly
/// twice it. The two windows must NOT be coterminous: were the dedup TTL equal
/// to the skew tolerance, a `nonce` recorded at the trailing edge of its
/// freshness window could expire from the dedup cache while a replay carrying a
/// *refreshed* `asserted_timestamp_ms` is still inside the freshness window —
/// slipping past both gates (BLACK-XCTX-01). With the TTL strictly exceeding
/// the skew tolerance, any envelope that passes the freshness check has its
/// `nonce` still remembered by the dedup cache, closing the coterminous-window
/// gap for the in-window case. See the *Freshness / anti-replay* clause of
/// spec §6.2.4 for the forward obligation this leaves for an untrusted
/// cross-node transport.
pub(crate) const SAGA_NONCE_DEDUP_TTL_SECS: u64 = DEFAULT_CLOCK_SKEW_TOLERANCE_SECS * 2;

/// Runtime configuration ceiling for an interface's inbound §6.2.0.2 rate
/// (`InboundPolicy::max_calls_per_minute`) — the highest inbound rate B will
/// admit at Prepare-B before rejecting the interface as cache-eviction-unsafe
/// (spec §6.2.4 "Cache-eviction bound", normative "Sizing relative to the
/// configured ceiling").
///
/// Derived from the dedup cache capacity, the saga dedup TTL window
/// ([`SAGA_NONCE_DEDUP_TTL_SECS`] = 600s = 10 min), and the required ≥2× safety
/// margin: at this per-minute rate the worst-case distinct-nonce volume over
/// the TTL window stays at or below half the
/// [`NONCE_DEDUP_CAPACITY`](scp_protocol::crypto::sender_keys::NONCE_DEDUP_CAPACITY)
/// (10 000), so a sustained in-budget inbound stream can NEVER fill the cache
/// and evict a still-within-TTL `nonce` — TTL expiry, not capacity eviction,
/// bounds the replay window. `500/min × 10 min × 2 = 10 000 = capacity`. A
/// higher ceiling would let in-budget traffic erode the replay bound, so an
/// interface configuring an inbound rate above this is REJECTED at Prepare-B
/// (`consume_inbound_interface_rate_limit`, `SCP-SAGA-13027`). The
/// `nonce_dedup_replay_bound_holds` test asserts this derivation mechanically.
pub(crate) const MAX_SAFE_INBOUND_CALLS_PER_MINUTE: u64 = 500;

/// Lowercase-hex encode a raw 32-byte context-id digest (the wire / role-state
/// id-form, never the `"standing-"`-prefixed display string — spec §6.2.4
/// id-form rule).
///
/// Delegates to [`hex::encode`] (the same lowercase encoding the supervisor side
/// of this path uses) so caller / target context ids render byte-identically
/// across both layers — a divergence here would split a saga's log lines.
fn hex_context_id(id: &[u8; 32]) -> String {
    hex::encode(id)
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
            reply,
        } => {
            prepare_a(
                state,
                deps,
                &caller_context_id,
                &caller_did,
                &tool_registration_id,
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
            caller_source_role,
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
                caller_source_role,
            };
            prepare_b(state, deps, req, reply).await
        }
        // Commit-side phases are matched in `dispatch` and never routed here.
        // The `dispatch` router partitions Prepare vs Commit before calling
        // this helper, so these arms are statically unreachable; return a typed
        // error (NEVER panic — ADR-049 §10 handler panic ban) rather than
        // `unreachable!`, routing each phase's reply to its typed sender.
        SagaPhaseMessage::CommitBReserve { reply, .. } => misrouted(reply, "CommitBReserve"),
        SagaPhaseMessage::CommitBSettle { reply, .. } => misrouted(reply, "CommitBSettle"),
        SagaPhaseMessage::CommitACheckWitness { reply, .. } => {
            misrouted(reply, "CommitACheckWitness")
        }
        SagaPhaseMessage::CommitA { reply, .. } => misrouted(reply, "CommitA"),
        SagaPhaseMessage::Abort { reply, .. } => misrouted(reply, "Abort"),
        SagaPhaseMessage::EmitDivergenceMarker { reply, .. } => {
            misrouted(reply, "EmitDivergenceMarker")
        }
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
        SagaPhaseMessage::CommitACheckWitness { saga_id, reply } => {
            commit_a_check_witness(state, &saga_id, reply)
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
        SagaPhaseMessage::PrepareA { reply, .. } => misrouted(reply, "PrepareA"),
        SagaPhaseMessage::PrepareB { reply, .. } => misrouted(reply, "PrepareB"),
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

/// Mis-route reply for ANY saga phase's typed `oneshot` sender. Every saga
/// phase reply is an `oneshot::Sender<Result<T, ContextError>>`; this single
/// generic collapses the per-phase reply helpers (which were byte-identical
/// except the reply payload type `T` and the phase label) into one. The
/// statically-unreachable mis-routed branch sends the typed error to its sender
/// and returns `Outcome::err` — NEVER `panic!`/`unreachable!` (ADR-049 §10
/// handler panic ban).
fn misrouted<T>(
    reply: tokio::sync::oneshot::Sender<Result<T, ContextError>>,
    phase: &str,
) -> Outcome<()> {
    let err = misrouted_err(phase);
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
/// rate-limit decrement + escrow reservation via the existing reserve
/// mechanism. The escrow amount is the tool's REGISTERED per-invocation cost —
/// [`reserve_tool_economy`] derives it from the caller context's economy policy
/// / tool registry via `economy_pre_check`, NEVER from any caller-asserted
/// value (a caller must not declare its own cheaper cost; spec §6.2.4 / §19.3).
/// The resulting `Send` [`ToolEconomyReservation`] is a `#[must_use]` RAII
/// carrier the FSM holds — its drop releases the held escrow/rate-limit on every
/// terminal non-commit path. The staged saga state is Class-S sync-persisted
/// fail-closed BEFORE the reply, so a crash in the coalesce window cannot
/// acknowledge a Prepare-A whose reservation did not durably land.
async fn prepare_a(
    state: &mut PerContextState,
    deps: &ActorDeps,
    caller_context_id: &[u8; 32],
    caller_did: &DID,
    tool_registration_id: &str,
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

    // 2. Consume the §6.2.0.2 per-interface + per-caller sliding-window budget
    //    on the OUTBOUND interface (spec §6.2.4 "Prepare", "Initiation consumes
    //    budget; no terminal outcome refunds it"). This is the binding
    //    constraint behind the §6.2.4 "Cache-eviction bound": a single caller's
    //    TTL-window budget sized far below the dedup-cache capacity is what
    //    forecloses a flood from evicting a still-within-TTL nonce. The consume
    //    is non-refundable at initiation — once the sliding window is
    //    incremented it is NEVER decremented back on any terminal outcome
    //    (Aborted / timeout / NeedsRepair), so a caller that stalls or diverges
    //    sagas burns its own quota. REUSES the same `RateLimit` /
    //    `PerCallerRateLimit::check_and_increment` sliding-window mechanism the
    //    single-context `invoke_cross_context` path consumes (spec §6.2.0.2).
    if let Err(err) =
        consume_outbound_interface_rate_limit(state, deps, caller_did, tool_registration_id)
    {
        // The §6.2.0.2 consume is non-refundable: if it incremented the window
        // and THEN this branch is reached, the increment stays. (In practice a
        // rejection here means the window was NOT incremented — `RateLimited`
        // is the over-budget case where the call is denied.) Persist so any
        // partial increment durably lands (fail-closed direction), then reply.
        let _ = persist_state_fail_closed(state, deps, &context_id_hex);
        let sketch = outcome_error_sketch(&err);
        let _ = reply.send(Err(err));
        return Outcome::err_mutated(sketch);
    }

    // 3. Stage (not apply) the escrow reservation + the actor-owned
    //    velocity/budget/hard-rate-limit bookkeeping via the existing reserve
    //    mechanism. The reservation holds the escrow; apply happens at Commit-A
    //    settle. The escrow amount is the tool's REGISTERED per-invocation cost
    //    (derived by `reserve_tool_economy` from the economy policy / tool
    //    registry via `economy_pre_check`), NEVER a caller-asserted value — a
    //    caller must not declare its own cheaper cost. No spending UCAN is
    //    presented on the OUTBOUND leg — the inbound `require_spending_ucan`
    //    gate and §7 proof live on B's Prepare-B side.
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
            // reserve_tool_economy rolls back its OWN staged bookkeeping on
            // every failure branch, so no escrow/velocity/budget leaked. The
            // §6.2.0.2 budget consumed above is NOT rolled back (non-refundable
            // at initiation); persist so it durably lands, then reply.
            let _ = persist_state_fail_closed(state, deps, &context_id_hex);
            let sketch = outcome_error_sketch(&err);
            let _ = reply.send(Err(err));
            return Outcome::err_mutated(sketch);
        }
    };

    // 4. Class-S sync-persist fail-closed BEFORE replying (ADR-049 §9): the
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

/// Consume one §6.2.0.2 sliding-window budget unit on the OUTBOUND interface for
/// `tool_registration_id` — both the per-interface (`rate_limit`) AND the
/// per-caller (`per_caller_rate_limit`) windows, exactly as the single-context
/// [`invoke_cross_context`](scp_protocol::context::tools::interface::invoke_cross_context)
/// path consumes them. Returns [`ContextError::RateLimited`] (the over-budget
/// case) without incrementing the OTHER window when either is exhausted.
///
/// The consume is the §6.2.4 "Initiation consumes budget" point: each
/// initiation increments the caller's sliding window, and NO terminal outcome
/// decrements it back (the increment is non-refundable). This is the binding
/// constraint behind the §6.2.4 "Cache-eviction bound" — a per-caller budget
/// sized far below the dedup-cache capacity forecloses a flood from evicting a
/// still-within-TTL nonce.
///
/// An interface with no configured limit (`None`) is unbounded by design and
/// consumes nothing; the per-interface limit is checked first, then the
/// per-caller limit, so an exhausted per-interface window short-circuits before
/// the per-caller window is touched (matching `invoke_cross_context` order).
fn consume_outbound_interface_rate_limit(
    state: &mut PerContextState,
    deps: &ActorDeps,
    caller_did: &DID,
    tool_registration_id: &str,
) -> Result<(), ContextError> {
    let clock = deps.clock.as_ref();

    let Some(interface) = state
        .governance
        .tool_interfaces
        .iter_mut()
        .find(|i| i.tool_id == tool_registration_id)
    else {
        // No interface row for this tool. The target-axis authorize-before-
        // reserve gate already proved an established interface exists for the
        // (caller, target, tool) triple before the saga reserved, so a missing
        // row here is not the unauthorized-target case; there is simply no
        // configured §6.2.0.2 window to consume (unbounded by design).
        return Ok(());
    };

    // Per-interface sliding window first (spec §6.2.0.2, `invoke_cross_context`
    // order): a single per-interface check_and_increment is the consume.
    if let Some(rate_limit) = interface.rate_limit.as_mut()
        && !rate_limit.check_and_increment(clock)
    {
        let retry_after_secs = rate_limit.retry_after_secs(clock);
        return Err(ContextError::RateLimited {
            resource: "tool_interface".to_owned(),
            message: format!(
                "SCP-SAGA-13023: per-interface §6.2.0.2 rate limit exceeded for tool \
                 '{tool_registration_id}' (retry after {retry_after_secs}s)"
            ),
        });
    }

    // Per-caller sliding window, independent of the per-interface window.
    if let Some(per_caller) = interface.per_caller_rate_limit.as_mut()
        && !per_caller.check_and_increment(caller_did, clock)
    {
        let retry_after_secs = per_caller.retry_after_secs_for(caller_did, clock);
        return Err(ContextError::RateLimited {
            resource: "tool_interface_caller".to_owned(),
            message: format!(
                "SCP-SAGA-13024: per-caller §6.2.0.2 rate limit exceeded for caller \
                 '{caller_did}' on tool '{tool_registration_id}' (retry after \
                 {retry_after_secs}s)"
            ),
        });
    }

    Ok(())
}

/// Consume one §6.2.0.2 sliding-window unit on B's INBOUND interface window at
/// Prepare-B (spec §6.2.4 "Prepare-B validates `InboundPolicy` (… inbound rate
/// …)"; §6.2.0 effective `min(outbound, inbound)`). The OUTBOUND window is
/// consumed by the caller (A) at Prepare-A; this is the symmetric TARGET-side
/// (B-owned) window, so both ends enforce their respective per-interface limit
/// and the effective rate is their `min`.
///
/// The window is materialized LAZILY from
/// [`InboundPolicy::max_calls_per_minute`](scp_protocol::context::tools::interface::InboundPolicy)
/// into `ToolInterface::inbound_rate_limit` the first time B prepares an
/// invocation over the interface, then carried with the interface so the
/// window state persists. An interface with no inbound policy (unbounded by
/// design) consumes nothing.
///
/// The consume is NON-REFUNDABLE — consistent with the §6.2.4
/// "initiation-consumes" discipline: an exhausted window rejects with a typed
/// `SCP-SAGA-13026` and NO terminal outcome decrements it back.
///
/// **Config-time eviction guard (spec §6.2.4 "Cache-eviction bound", normative
/// "Sizing relative to the configured ceiling").** Before materializing the
/// window, the configured inbound rate is checked against
/// [`MAX_SAFE_INBOUND_CALLS_PER_MINUTE`]: an interface whose configured inbound
/// rate over the dedup-TTL window would approach `NONCE_DEDUP_CAPACITY` (the
/// ≥2× margin) is REJECTED (`SCP-SAGA-13027`) — a high inbound ceiling must not
/// erode the replay bound the §6.2.4 dedup cache provides. This makes the
/// eviction bound a mechanical function of the configured ceiling at runtime,
/// not merely a `cfg(test)` invariant.
fn consume_inbound_interface_rate_limit(
    state: &mut PerContextState,
    deps: &ActorDeps,
    tool_registration_id: &str,
) -> Result<(), ContextError> {
    use scp_protocol::context::tools::interface::{DEFAULT_WINDOW_SECONDS, RateLimit};

    let clock = deps.clock.as_ref();

    let Some(interface) = state
        .governance
        .tool_interfaces
        .iter_mut()
        .find(|i| i.tool_id == tool_registration_id)
    else {
        // No interface row ⇒ no configured inbound window to consume (the
        // authorize-before-reserve gate already proved an established interface
        // exists; a missing row here is the unbounded-by-design case).
        return Ok(());
    };

    // No inbound policy ⇒ unbounded inbound by design; consume nothing.
    let Some(inbound) = interface.inbound_policy.as_ref() else {
        return Ok(());
    };
    let max_per_min = u64::from(inbound.max_calls_per_minute);

    // Config-time eviction guard (spec §6.2.4 "Sizing relative to the configured
    // ceiling"): an inbound ceiling whose TTL-window volume approaches the dedup
    // capacity (below the ≥2× margin) would let in-budget traffic evict a
    // still-within-TTL nonce. Reject such an interface rather than admit it.
    if max_per_min > MAX_SAFE_INBOUND_CALLS_PER_MINUTE {
        return Err(ContextError::PermissionDenied(format!(
            "SCP-SAGA-13027: interface inbound rate {max_per_min}/min for tool \
             '{tool_registration_id}' exceeds the cache-eviction-safe ceiling \
             ({MAX_SAFE_INBOUND_CALLS_PER_MINUTE}/min): its dedup-TTL-window volume would \
             approach the nonce-dedup capacity and erode the §6.2.4 replay bound"
        )));
    }

    // Materialize the inbound window lazily from the inbound policy (same
    // RateLimit mechanism + default 60s window the outbound side uses).
    let window = interface.inbound_rate_limit.get_or_insert_with(|| {
        RateLimit::new(
            max_per_min,
            std::time::Duration::from_secs(DEFAULT_WINDOW_SECONDS),
            clock,
        )
    });

    if !window.check_and_increment(clock) {
        let retry_after_secs = window.retry_after_secs(clock);
        return Err(ContextError::RateLimited {
            resource: "tool_interface_inbound".to_owned(),
            message: format!(
                "SCP-SAGA-13026: per-interface §6.2.0.2 INBOUND rate limit exceeded at Prepare-B \
                 for tool '{tool_registration_id}' (retry after {retry_after_secs}s)"
            ),
        });
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
    /// Channel-authenticated caller role in the caller context (NOT
    /// envelope-asserted); enforced against `InboundPolicy.allowed_source_roles`.
    caller_source_role: Option<String>,
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
        // cache exists to close). The persist just FAILED, so this recorded
        // nonce did NOT durably land; report mutated so the actor flags the
        // in-memory mutation as diverged-from-durable (it does not claim the
        // state persisted).
        return Outcome::err_mutated(sketch);
    }

    let _ = reply.send(Ok(PreparedBFields {
        recorded_timestamp_ms,
        recorded_nonce,
        recorded_chain_depth,
    }));
    Outcome::ok_mutated(())
}

/// Run the Prepare-B checks in spec order. Returns `Ok(())` if every check
/// passes; a typed `SCP-SAGA-13xxx` rejection otherwise.
///
/// All checks except the inbound-rate consume are read-only. Step (2b) consumes
/// B's INBOUND §6.2.0.2 sliding window — a NON-REFUNDABLE mutation that, by the
/// "initiation-consumes" discipline, stays consumed even if a LATER check
/// rejects (an arrival reaching the inbound-rate gate is inbound load whether or
/// not it ultimately validates). It runs as part of the InboundPolicy gate, so
/// it precedes the freshness/chain-depth checks deliberately.
fn run_prepare_b_checks(
    state: &mut PerContextState,
    deps: &ActorDeps,
    req: &PrepareBRequest,
) -> Result<(), ContextError> {
    // (1) Confused-deputy: resolve the UCAN proof from B's OWN store and re-run
    //     full §7 validation RE-BOUND to caller_did + tool_registration_id.
    validate_ucan_rebind(state, deps, req)?;

    // (2) Inbound policy: source role + require_spending_ucan (the gated-proof
    //     requirement is satisfied by (1) above when a proof is present). The
    //     third InboundPolicy axis — inbound RATE — is consumed LAST (step 7),
    //     because it is the only state-MUTATING gate: all the read-only
    //     rejections below must fire first so a rejected call never consumes
    //     (and durably persists) the inbound window.
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

    // (7) Inbound RATE (the ONLY mutating check — runs LAST): consume B's INBOUND
    //     §6.2.0.2 sliding window (spec §6.2.4 "Prepare-B validates InboundPolicy
    //     (… inbound rate …)"; §6.2.0 effective min(outbound,inbound)). The
    //     TARGET-side counterpart to Prepare-A's outbound consume; non-refundable.
    //     ALSO enforces the cache-eviction config guard (rejects a configured
    //     inbound ceiling above MAX_SAFE_INBOUND_CALLS_PER_MINUTE before
    //     materializing the window) so a high inbound rate cannot erode the
    //     §6.2.4 replay bound. Placed last so every read-only reject above fires
    //     before any window mutation — a rejected call never consumes the budget,
    //     and the only successful-consume mutation is followed by the staging +
    //     Class-S persist in `prepare_b` (the window durably lands). The
    //     over-budget / over-ceiling reject paths do NOT mutate (no increment),
    //     so an `Outcome::err` (un-persisted) on those is correct.
    consume_inbound_interface_rate_limit(state, deps, &req.tool_registration_id)?;

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

/// (2a) Inbound policy — source role + `require_spending_ucan` (spec §6.2.4
/// "Prepare-B... validates `InboundPolicy` (source role, inbound rate,
/// `require_spending_ucan`)"). Two binding gates at this layer:
///
/// - **`allowed_source_roles`** — the channel-authenticated caller's role
///   (`req.caller_source_role`, resolved supervisor-side from the caller
///   context, NEVER envelope-asserted) MUST be in the allow-set. Empty allow-set
///   = any role (matching the `InboundPolicy` default). A caller whose
///   authenticated role is absent from a non-empty allow-set is rejected.
/// - **`require_spending_ucan`** — when set, a proof MUST be present (validated
///   in step (1)).
///
/// The third InboundPolicy axis — the per-interface INBOUND **rate** — is
/// consumed separately in [`consume_inbound_interface_rate_limit`] (step (2b) of
/// `run_prepare_b_checks`), because it is a state mutation (a non-refundable
/// sliding-window decrement) and this function is read-only.
fn validate_inbound_policy(
    state: &PerContextState,
    req: &PrepareBRequest,
) -> Result<(), ContextError> {
    let Some(interface) = state
        .governance
        .tool_interfaces
        .iter()
        .find(|i| i.tool_id == req.tool_registration_id)
    else {
        return Ok(());
    };
    let Some(inbound) = interface.inbound_policy.as_ref() else {
        return Ok(());
    };

    // `allowed_source_roles`: empty = any role. A non-empty allow-set requires
    // the channel-authenticated caller's role to be present.
    if !inbound.allowed_source_roles.is_empty() {
        let role_allowed = req
            .caller_source_role
            .as_ref()
            .is_some_and(|role| inbound.allowed_source_roles.iter().any(|r| r == role));
        if !role_allowed {
            return Err(ContextError::PermissionDenied(format!(
                "SCP-SAGA-13025: caller role {} is not in inbound allowed_source_roles \
                 for tool '{}'",
                req.caller_source_role
                    .as_deref()
                    .map_or_else(|| "<none>".to_owned(), |r| format!("'{r}'")),
                req.tool_registration_id
            )));
        }
    }

    // `require_spending_ucan`: a gated interface demands a proof (validated in
    // step (1) when present).
    if inbound.require_spending_ucan && req.ucan_proof_id.is_none() {
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
///
/// **Window relationship (BLACK-XCTX-01).** The nonce-dedup TTL
/// ([`SAGA_NONCE_DEDUP_TTL_SECS`]) STRICTLY exceeds this freshness check's
/// skew tolerance (`DEFAULT_CLOCK_SKEW_TOLERANCE_SECS`), so a `nonce` recorded
/// at the trailing edge of its freshness window is still remembered by the
/// dedup cache through the rest of that window — a replay carrying a *refreshed*
/// `asserted_timestamp_ms` therefore still hits the dedup gate rather than
/// slipping past a coterminous (equal-length) window.
///
/// **Forward obligation (untrusted transport).** `asserted_timestamp_ms` is
/// caller-asserted and, in the co-resident SDK seam this code implements, the
/// caller leg is **channel-authenticated** (`caller_did`/`caller_context_id`
/// are the transport-leg identity, not envelope-asserted — see the §6.2.4
/// *Cache-eviction bound* clause) and there is no capturable wire envelope, so
/// exactly-once-per-envelope holds by construction. A future cross-node
/// child-bridge transport carrying this envelope over an UNTRUSTED link does
/// NOT satisfy that by construction: the longer-than-skew window bounds, but
/// does not eliminate, a replay that refreshes the timestamp once the original
/// `nonce` finally ages out. Before such a transport ships, the asserted
/// timestamp MUST be AUTHENTICATED/BOUND — signed by the caller, or the dedup
/// keyed so a replay cannot refresh the freshness window. This forward
/// obligation is recorded in the spec §6.2.4 *Freshness / anti-replay* clause,
/// mirroring the ADR-049 §3a forward-obligation discipline.
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
    // MOVE the staged slot OUT up front so we own the original
    // `SagaPreparedState` — on a persist-failure rollback we RE-INSERT the owned
    // original verbatim (no lossy reconstruction). The slot is restored on every
    // failure path below, so a rejected settle leaves `saga_pending` exactly as
    // it was found.
    let removed = state.saga_pending.remove(saga_id);
    let Some(SagaPreparedState::CrossContextToolInvocation(prepared)) = removed else {
        // Not a cross-context staged slot (or absent): put back whatever we
        // removed (an unrelated variant) and reject. `mutated = false` — the
        // remove+reinsert is a no-op round-trip.
        if let Some(other) = removed {
            state.saga_pending.insert(saga_id.clone(), other);
        }
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
    // Pre-append: a signing failure leaves state untouched (mutated = false) —
    // re-insert the owned original first.
    let event_id = tool_invoked_event_id(saga_id);
    let receipt = match build_signed_receipt(&prepared, output_bytes, &event_id, target_signing_key)
    {
        Ok(r) => r,
        Err(e) => {
            state.saga_pending.insert(
                saga_id.clone(),
                SagaPreparedState::CrossContextToolInvocation(prepared),
            );
            return Err((false, e));
        }
    };
    // The receipt's JCS output bytes are the canonical preimage A re-hashes.
    let canonical_output = receipt.output_jcs.clone();

    // Snapshot the fields the ToolInvoked record needs. `recorded_chain_depth` /
    // `recorded_timestamp_ms` are B's staged values (never re-read from wire).
    let caller_did_str = prepared.caller_did.0.clone();
    let target_context_id = prepared.target_context_id;
    let caller_context_id = prepared.caller_context_id;
    let tool_registration_id = prepared.tool_registration_id.clone();
    let target_hex = hex_context_id(&target_context_id);

    // Order matters (provenance-integrity): the durable output capture +
    // Class-S persist land BEFORE the `ToolInvoked` event-log append. The
    // event log is a SEPARATE provider not covered by `persist_state_fail_closed`
    // and the append is NOT provider-idempotent, so appending FIRST would
    // double-append on a persist-failure retry: a persist failure rolls the
    // capture back and re-stages the slot, the next reserve reports
    // `ReadyToExecute`, and `commit_b_first_settle` re-runs — re-appending a
    // SECOND `ToolInvoked` for one saga. Appending only after the capture +
    // persist succeed makes a persist failure leave NO orphan log entry, so the
    // retry produces exactly one `ToolInvoked`.

    // Durably capture the output + signed receipt keyed by SagaId (§6.2.4
    // "Exactly-once execution with durable output capture"). The staged slot was
    // already removed up front (the session reservation is now applied via the
    // capture). No event-log mutation yet — a failure before the append is
    // recoverable by re-inserting the owned staged slot.
    state.xctx_committed_outputs.insert(
        saga_id.clone(),
        CommittedToolInvocation {
            receipt: receipt.clone(),
            output_bytes: canonical_output.clone(),
            tool_invoked_event_id: event_id.clone(),
        },
    );

    // Class-S sync-persist fail-closed BEFORE acking (ADR-049 §9): the durable
    // output capture MUST land before the caller learns Commit-B succeeded, or a
    // crash in the coalesce window would re-invoke the tool on replay. On persist
    // failure roll the capture back and RE-INSERT the OWNED original staged slot
    // verbatim so a retry re-runs settle. No `ToolInvoked` was appended yet, so
    // the retry cannot double-append. `mutated = false`: nothing durable landed
    // (the in-memory capture was just rolled back, no event-log touch).
    if let Err(persist_err) = persist_state_fail_closed(state, deps, &target_hex) {
        state.xctx_committed_outputs.remove(saga_id);
        state.saga_pending.insert(
            saga_id.clone(),
            SagaPreparedState::CrossContextToolInvocation(prepared),
        );
        return Err((false, persist_err));
    }

    // Append `ToolInvoked` to the local (target) log (spec §6.2.4 "Commit"):
    // caller ctx id / caller DID actor / B's re-derived depth + staged
    // timestamp. Runs ONLY after the capture + persist landed, so it appears
    // exactly once across retries.
    let tool_invoked_payload = serde_json::json!({
        "saga_id": saga_id.0,
        "tool_invoked_event_id": event_id,
        "caller_context_id": hex_context_id(&caller_context_id),
        "tool_registration_id": tool_registration_id,
        "chain_depth": receipt.chain_depth,
        "timestamp_ms": receipt.timestamp_ms,
    });
    if let Err(e) = deps.event_log.append_context_event_with_payload(
        &target_context_id,
        &event_id,
        &caller_did_str,
        Some(&tool_invoked_payload),
    ) {
        // The append failed AFTER the capture+persist landed. Roll the capture
        // back and re-stage the owned slot, then RE-PERSIST so the rolled-back
        // state is durable — otherwise the next reserve would see the
        // already-persisted capture, report `AlreadyCommitted`, and SKIP the
        // append forever (a missing `ToolInvoked`). With the compensating
        // re-persist, the retry sees `ReadyToExecute` and re-runs settle,
        // appending exactly once. If the compensating persist ALSO fails the
        // capture stays durable (a genuine fail-closed terminal — the operator /
        // crash-recovery sweep reconciles), reported `mutated`.
        state.xctx_committed_outputs.remove(saga_id);
        state.saga_pending.insert(
            saga_id.clone(),
            SagaPreparedState::CrossContextToolInvocation(prepared),
        );
        if let Err(persist_err) = persist_state_fail_closed(state, deps, &target_hex) {
            return Err((true, persist_err));
        }
        return Err((false, e));
    }

    // The capture + persist + append all landed; serializing the receipt for the
    // reply is a pure encode of already-committed state — a failure here is
    // `mutated`.
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
        CrossContextToolReceiptFields {
            caller_context_id: prepared.caller_context_id,
            target_context_id: prepared.target_context_id,
            caller_did: prepared.caller_did.0.clone(),
            nonce: prepared.recorded_nonce,
            tool_registration_id: prepared.tool_registration_id.clone(),
            output_jcs,
            tool_invoked_event_id: event_id.to_owned(),
            chain_depth: prepared.recorded_chain_depth,
            timestamp_ms: prepared.recorded_timestamp_ms,
        },
    )
    .map_err(|e| {
        ContextError::CryptoFailed(format!(
            "SCP-SAGA-13034: Commit-B receipt signing failed: {e}"
        ))
    })
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
        // GENERATION-CHECKED rollback of the handed-back reservation: if this
        // actor was despawned+respawned between Prepare-A and this replayed
        // Commit-A, refunding against the new instance's owned state would
        // corrupt the WRONG context. On a mismatch the helper voids only the
        // external escrow and consumes the ticket (mirrors `settle_tool_economy`).
        crate::context::tools_helpers::rollback_tool_economy_generation_checked(
            state,
            deps,
            req.reservation.reservation.generation,
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

    // Order matters (provenance-integrity), mirroring `commit_b_first_settle`:
    // the idempotency witness + Class-S persist land BEFORE the
    // `CrossContextToolInvoked` event-log append. The event log is a SEPARATE
    // provider not covered by `persist_state_fail_closed` and the append is NOT
    // provider-idempotent, so appending FIRST (the inverse, B-side-documented
    // hazard) would leave a DURABLE A-side `CrossContextToolInvoked` orphan when
    // the post-append persist fails: the witness is rolled back, but the log
    // entry already landed — an A-without-B record that B's log denies and that
    // `divergence_marker_plan` (keyed off the B-committed event id) would not
    // surface, a silent one-sided A-record. Appending only AFTER the witness +
    // persist succeed makes a persist failure leave NO orphan log entry.

    // Record the committed A-side saga (the idempotency witness) and Class-S
    // persist fail-closed BEFORE the append: a crash that rolled the settle/marker
    // back behind an acked Commit-A would double-settle on replay. On persist
    // failure roll the witness back; the settle already mutated owned economy
    // (`mutated = true`) but NO `CrossContextToolInvoked` was appended, so there
    // is no orphan log entry — the FSM retry re-acks from the (now-absent) witness
    // and the saga resolves correctly with no silent one-sided A-record.
    state.xctx_committed_invocations.insert(req.saga_id.clone());
    if let Err(persist_err) = persist_state_fail_closed(state, deps, &caller_hex) {
        state.xctx_committed_invocations.remove(&req.saga_id);
        let sketch = outcome_error_sketch(&persist_err);
        let _ = reply.send(Err(persist_err));
        return Outcome::err_mutated(sketch);
    }

    // Append `CrossContextToolInvoked` to the local (caller) log: references the
    // target ctx id + the SAME nonce as B's `ToolInvoked` so an auditor joins
    // the two records into one provenance edge (spec §6.2.4 "Dual event-log
    // recording"). The output hash links the record to the verified receipt.
    // Runs ONLY after the witness + persist landed.
    let event_name = format!("CrossContextToolInvoked:{}", req.saga_id.0);
    let invoked_payload = serde_json::json!({
        "saga_id": req.saga_id.0,
        "target_context_id": hex_context_id(&req.target_context_id),
        "nonce": hex::encode(req.nonce),
        "output_hash": hex_output_hash(&req.output_bytes),
        "receipt_len": req.receipt.len(),
    });
    if let Err(err) = deps.event_log.append_context_event_with_payload(
        &req.caller_context_id,
        &event_name,
        req.caller_did.as_ref(),
        Some(&invoked_payload),
    ) {
        // The append failed AFTER the witness + persist landed. Roll the witness
        // back and RE-PERSIST so the rolled-back state is durable — otherwise the
        // next Commit-A would see the already-persisted witness, re-ack as
        // committed, and SKIP the append forever (a missing
        // `CrossContextToolInvoked`). With the compensating re-persist, a retry
        // re-runs Commit-A and appends exactly once. If the compensating persist
        // ALSO fails the witness stays durable (a genuine fail-closed terminal —
        // the operator / crash-recovery sweep reconciles), reported `mutated`.
        // Mirrors `commit_b_first_settle`'s append-failure compensation.
        state.xctx_committed_invocations.remove(&req.saga_id);
        if let Err(persist_err) = persist_state_fail_closed(state, deps, &caller_hex) {
            let sketch = outcome_error_sketch(&persist_err);
            let _ = reply.send(Err(persist_err));
            return Outcome::err_mutated(sketch);
        }
        let sketch = outcome_error_sketch(&err);
        let _ = reply.send(Err(err));
        return Outcome::err_mutated(sketch);
    }

    let _ = reply.send(Ok(()));
    Outcome::ok_mutated(())
}

/// Commit-A witness check (spec §17.16.4). Runs on the LOCAL caller-context
/// actor. READ-ONLY: reports whether this `SagaId`'s Commit-A is already durably
/// recorded in `xctx_committed_invocations`. The FSM calls this to resolve a
/// Commit-A whose ACK was lost AFTER the handler durably committed (the held
/// reservation is gone, so a fresh `CommitA` send cannot re-drive it). A `true`
/// reply IS the idempotent A-side re-ack — the saga resolves to `Committed`
/// rather than a spurious `NeedsRepair`. No mutation, no Class-S persist.
fn commit_a_check_witness(
    state: &PerContextState,
    saga_id: &SagaId,
    reply: tokio::sync::oneshot::Sender<Result<bool, ContextError>>,
) -> Outcome<()> {
    let recorded = state.xctx_committed_invocations.contains(saga_id);
    let _ = reply.send(Ok(recorded));
    Outcome::ok(())
}

// ---------------------------------------------------------------------------
// Abort — either side (spec §6.2.4 "Reservation release on every terminal path")
// ---------------------------------------------------------------------------

/// Abort handler (spec §6.2.4 "Reservation release on every terminal path").
/// Runs on EITHER side's local actor.
///
/// RAII-releases the staged reservations — escrow / outbound-RL on the CALLER
/// side (handed back via `reservation`, rolled back through the existing
/// generation-checked rollback path); the tool-session on the TARGET side is
/// released by clearing the staged `saga_pending` slot (B stages no
/// `ToolEconomyTicket`). Class-S sync-persists fail-closed whenever an
/// OWNED-state mutation occurred — the caller refund (the rollback ran against
/// matching-generation owned state) OR a cleared target slot — then acks.
/// Persisting the caller refund is mandatory: Prepare-A durably persisted the
/// matching deduction, so skipping the refund persist would permanently
/// over-charge the caller on a crash-after-ack (the saga is Aborted, nothing
/// re-drives it). Idempotent: an already-terminal saga (no slot) on which the
/// generation-mismatch path ran (no owned mutation) — or a bare re-Abort with
/// no reservation and no slot — is a clean no-op with no redundant persist.
async fn abort(
    state: &mut PerContextState,
    deps: &ActorDeps,
    saga_id: &SagaId,
    reservation: Option<PreparedAFields>,
    reply: tokio::sync::oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let context_hex = hex_context_id(&state.context_id);

    // CALLER side: release the held escrow + outbound-RL reservation (RAII).
    // Route through the GENERATION-CHECKED rollback: an actor despawn+respawn
    // (e.g. an import replace) between Prepare-A and this in-flight Abort would
    // otherwise let the unconditional rollback refund velocity / budget /
    // hard-rate-limit into the WRONG (respawned) instance's owned state. On a
    // generation MISMATCH the helper voids only the external escrow and consumes
    // the ticket, mirroring `settle_tool_economy`'s guard (the prior instance's
    // local bookkeeping died with it).
    //
    // `rollback_tool_economy_generation_checked` returns whether the LOCAL
    // rollback ran (`true` = generations matched ⇒ this actor's OWNED velocity /
    // budget / hard-rate-limit were mutated back; `false` = generation mismatch
    // ⇒ only the EXTERNAL escrow was voided, owned state untouched). We MUST
    // persist when the local rollback ran, because Prepare-A durably persisted
    // the matching DEDUCTION — without persisting the refund, a crash after this
    // ack loses the in-memory refund while the deduction survives, permanently
    // over-charging the caller (the saga is Aborted, so nothing re-drives it).
    let local_rollback_ran = match reservation {
        Some(prepared) => {
            crate::context::tools_helpers::rollback_tool_economy_generation_checked(
                state,
                deps,
                prepared.reservation.generation,
                prepared.reservation.ticket,
            )
            .await
        }
        None => false,
    };

    // TARGET side: clear the staged tool-session slot (releases the session
    // reservation). Idempotent — a missing slot is a clean no-op.
    let had_slot = state.saga_pending.remove(saga_id).is_some();

    // Persist if EITHER the caller-side owned economy was refunded
    // (`local_rollback_ran`) OR a target-side slot was cleared (`had_slot`):
    // both are owned-state mutations whose loss on a crash-after-ack would
    // corrupt durable state — an unpersisted caller refund permanently
    // over-charges (the deduction WAS persisted at Prepare-A); an unpersisted
    // slot clear re-stages a stale saga on respawn. The ONLY no-persist path is
    // the generation-mismatch caller Abort with no slot (`local_rollback_ran ==
    // false && !had_slot`): the mismatch voids external escrow + consumes the
    // ticket WITHOUT touching this instance's owned state (the prior instance's
    // bookkeeping died with it), so there is no owned mutation to persist, and
    // an idempotent already-terminal Abort is likewise a clean no-op.
    if !local_rollback_ran && !had_slot {
        let _ = reply.send(Ok(()));
        return Outcome::ok(());
    }

    // Class-S sync-persist fail-closed before acking: the refunded economy
    // and/or cleared slot MUST durably land so a crash respawn neither
    // over-charges the caller nor re-stages a stale saga.
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
        CrossContextDivergenceMarkerFields {
            saga_id: saga_id.0.clone(),
            nonce,
            committed_side,
            committed_event_id: committed_event_id.to_owned(),
        },
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

/// Lowercase-hex of `SHA-256(jcs(output))` — the verifiable link from the
/// caller's `CrossContextToolInvoked` record to the receipt's `output_hash`
/// without journaling the (possibly large/sensitive) output (§6.2.4).
fn hex_output_hash(output_bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest: [u8; 32] = Sha256::digest(output_bytes).into();
    hex::encode(digest)
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

    /// Defense-in-depth: the §6.2.4 per-target nonce dedup cache
    /// ([`PerContextState::xctx_nonce_dedup`]) must be bounded by its TTL
    /// (`NONCE_EXPIRY_SECS`), never by capacity eviction, for the replay
    /// guarantee to hold. The worst-case number of distinct nonces a caller can
    /// land within the TTL window is the configured inbound accept rate
    /// (`InboundPolicy::max_calls_per_minute`) scaled to the window. Assert that
    /// (a) the DEFAULT inbound ceiling holds with a ≥2× margin, and (b) the
    /// documented configuration ceiling [`MAX_SAFE_INBOUND_CALLS_PER_MINUTE`]
    /// still holds with a ≥2× margin — so a config-time check (or this
    /// invariant) catches a future high ceiling before it erodes the bound.
    #[test]
    fn nonce_dedup_replay_bound_holds() {
        use scp_protocol::context::tools::interface::DEFAULT_PER_INTERFACE_CALLS_PER_MINUTE;
        use scp_protocol::crypto::sender_keys::NONCE_DEDUP_CAPACITY;

        // The bound is computed against the SAGA dedup TTL — the cache this
        // invariant protects is `PerContextState::xctx_nonce_dedup`, which is
        // built with `SAGA_NONCE_DEDUP_TTL_SECS` (strictly longer than the
        // freshness skew tolerance, BLACK-XCTX-01), NOT the sender-key
        // `NONCE_EXPIRY_SECS`. A longer window admits more nonces, so the safe
        // per-minute ceiling is correspondingly lower.
        const {
            assert!(
                SAGA_NONCE_DEDUP_TTL_SECS > DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
                "the saga dedup TTL must strictly exceed the freshness skew tolerance \
                 so an in-window envelope's nonce is always still remembered"
            );
        }

        // Distinct nonces a caller can land within one TTL window at a given
        // per-minute accept ceiling.
        let window_minutes = SAGA_NONCE_DEDUP_TTL_SECS / 60;
        assert_eq!(
            window_minutes, 10,
            "saga dedup TTL window is 10 minutes (600s)"
        );

        let capacity = NONCE_DEDUP_CAPACITY as u64;

        let worst_case_default = u64::from(DEFAULT_PER_INTERFACE_CALLS_PER_MINUTE) * window_minutes;
        assert!(
            worst_case_default.saturating_mul(2) <= capacity,
            "default inbound ceiling ({DEFAULT_PER_INTERFACE_CALLS_PER_MINUTE}/min ⇒ \
             {worst_case_default} nonces over the TTL) must leave a ≥2× margin under the \
             {capacity}-entry dedup capacity, else eviction (not TTL) bounds replay",
        );

        let worst_case_ceiling = MAX_SAFE_INBOUND_CALLS_PER_MINUTE * window_minutes;
        assert!(
            worst_case_ceiling.saturating_mul(2) <= capacity,
            "the documented inbound ceiling ({MAX_SAFE_INBOUND_CALLS_PER_MINUTE}/min ⇒ \
             {worst_case_ceiling} nonces over the TTL) must leave a ≥2× margin under the \
             {capacity}-entry dedup capacity; raise the cache capacity before raising this \
             ceiling",
        );
    }

    /// FIX 4 (test/prod TTL parity): the handler-test fixture
    /// (`new_for_test_*` → `new_for_test_with_mode`) MUST seed the PRODUCTION
    /// saga dedup TTL (`SAGA_NONCE_DEDUP_TTL_SECS`), not `NonceDedup::new()`'s
    /// default 300s (which equals the skew tolerance — the coterminous window the
    /// spec FORBIDS). Without this, handler tests would run a different
    /// anti-replay window than production. Also asserts the `debug_assert`
    /// helper the spawn / restore sites call accepts the fixture's cache.
    #[tokio::test]
    async fn test_fixture_seeds_production_saga_dedup_ttl() {
        let st = target_state(0x5B, OTHER, CALLER).await;
        assert_eq!(
            st.xctx_nonce_dedup.ttl_secs(),
            SAGA_NONCE_DEDUP_TTL_SECS,
            "the test fixture must seed the production saga dedup TTL, not NonceDedup::new()'s \
             default (which is coterminous with the skew tolerance)"
        );
    }

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

    /// Event log that COUNTS `ToolInvoked:`-prefixed appends — used to assert a
    /// Commit-B persist-retry produces EXACTLY ONE `ToolInvoked` (FIX 3).
    struct CountingEventLog {
        tool_invoked_appends: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl crate::context::builder::ContextEventLogProvider for CountingEventLog {
        fn init_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        fn append_event(
            &self,
            _id: &[u8; 32],
            event: &str,
            _actor: &str,
            _payload: Option<&serde_json::Value>,
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            if event.starts_with("ToolInvoked:") {
                self.tool_invoked_appends
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(())
        }
        fn destroy_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
    }

    /// Persistence that FAILS its first `persist_context` call, then SUCCEEDS —
    /// drives the Commit-B persist-failure-then-retry path (FIX 3).
    struct FailFirstPersistence {
        calls: std::sync::atomic::AtomicUsize,
    }
    impl ContextPersistence for FailFirstPersistence {
        fn persist_context(
            &self,
            _: &str,
            _: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 0 {
                Err("induced first-persist failure".into())
            } else {
                Ok(())
            }
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
        fn delete_context(&self, _: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        fn list_persisted_contexts(
            &self,
        ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(Vec::new())
        }
    }

    /// Persistence that SUCCEEDS every call EXCEPT the `fail_at` (0-based) call,
    /// which FAILS — drives the Commit-A witness-persist-failure path: Prepare-A's
    /// own persists (reserve + Prepare-A tail) succeed, then the Commit-A
    /// idempotency-witness persist fails, proving the `CrossContextToolInvoked`
    /// append is sequenced AFTER (and gated on) that persist.
    struct FailNthPersistence {
        calls: std::sync::atomic::AtomicUsize,
        fail_at: usize,
    }
    impl ContextPersistence for FailNthPersistence {
        fn persist_context(
            &self,
            _: &str,
            _: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == self.fail_at {
                Err("induced nth-persist failure".into())
            } else {
                Ok(())
            }
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
        fn delete_context(&self, _: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        fn list_persisted_contexts(
            &self,
        ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(Vec::new())
        }
    }

    /// Event log that COUNTS `CrossContextToolInvoked:`-prefixed appends (the
    /// A-side record) — used to assert a Commit-A whose witness-persist FAILS
    /// appends NO `CrossContextToolInvoked` orphan (the append is gated behind
    /// the successful witness persist).
    struct CrossContextCountingEventLog {
        xctx_invoked_appends: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl crate::context::builder::ContextEventLogProvider for CrossContextCountingEventLog {
        fn init_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        fn append_event(
            &self,
            _id: &[u8; 32],
            event: &str,
            _actor: &str,
            _payload: Option<&serde_json::Value>,
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            if event.starts_with("CrossContextToolInvoked:") {
                self.xctx_invoked_appends
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(())
        }
        fn destroy_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
    }

    /// Persistence SPY: accepts every write but records the number of
    /// `persist_context` calls through a shared counter, so a test can assert a
    /// handler actually performed its Class-S persist (FIX 1: the caller-side
    /// abort refund MUST durably land). The counter is `Arc`-shared so the test
    /// reads it after the spy has been boxed into `ActorDeps`.
    struct SpyPersistence {
        persist_calls: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl ContextPersistence for SpyPersistence {
        fn persist_context(
            &self,
            _: &str,
            _: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.persist_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
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
        fn delete_context(&self, _: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        fn list_persisted_contexts(
            &self,
        ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(Vec::new())
        }
    }

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

    /// Like [`build_deps`] but with caller-supplied event-log + persistence
    /// providers, so a test can observe event-log appends and drive a
    /// fail-once persistence (FIX 3 Commit-B persist-retry).
    async fn build_deps_with_providers(
        issuer_did: String,
        issuer_key: ed25519_dalek::VerifyingKey,
        event_log: Box<dyn crate::context::builder::ContextEventLogProvider>,
        persistence: Box<dyn ContextPersistence>,
    ) -> ActorDeps {
        let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
            "did:dht:z6MktestSagaActor".to_owned(),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
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
        prepare_b_request_with_role(ctx_byte, ucan_proof_id, asserted_chain_depth, now_ms, None)
    }

    fn prepare_b_request_with_role(
        ctx_byte: u8,
        ucan_proof_id: Option<String>,
        asserted_chain_depth: u8,
        now_ms: u64,
        caller_source_role: Option<String>,
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
            caller_source_role,
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
            inbound_rate_limit: None,
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
            tx,
        )
        .await;
        assert!(out.result.is_err());
        let err = rx.await.unwrap().expect_err("persist must fail-close");
        assert!(matches!(err, ContextError::PersistenceFailed(_)));
    }

    /// FIX C (escrow reserves the REGISTERED cost, never a caller-asserted one).
    /// `prepare_a` no longer takes any caller-supplied cost — the escrow amount
    /// is derived entirely by `reserve_tool_economy` from the context's own
    /// economic policy. With the default (no policy ⇒ free) policy the reserve
    /// deducts NOTHING from the caller's budget, proving no caller-asserted
    /// positive cost can leak into the reservation. The compile-time absence of
    /// a cost parameter on `prepare_a` is the structural half of this guard.
    #[tokio::test]
    async fn prepare_a_escrow_uses_registered_cost_not_caller_value() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0x11, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();
        // No economic policy is configured ⇒ the REGISTERED cost is 0; the
        // reserve must deduct exactly the registered (policy-derived) amount.
        let budget_before = st
            .governance
            .budget_tracker
            .remaining(&DID(CALLER.to_owned()))
            .0;
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
            tx,
        )
        .await;
        assert!(out.result.is_ok(), "prepare_a outcome: {:?}", out.result);
        let prepared = rx.await.unwrap().expect("prepared-A");

        // The registered cost is 0, so the budget is untouched — no
        // caller-asserted positive cost was reserved.
        let budget_after = st
            .governance
            .budget_tracker
            .remaining(&DID(CALLER.to_owned()))
            .0;
        assert_eq!(
            budget_before, budget_after,
            "the escrow reservation must reserve the REGISTERED (policy-derived) cost — \
             with no policy that is 0, so the budget must be untouched"
        );

        crate::context::tools_helpers::rollback_tool_economy(
            &mut st,
            &deps,
            prepared.reservation.ticket,
        )
        .await;
    }

    /// FIX B.1 (§6.2.0.2 per-interface sliding-window budget consumed at
    /// initiation, non-refundable). An interface whose per-interface `rate_limit`
    /// is already exhausted (max_calls = 0) rejects Prepare-A with a typed
    /// `RateLimited` (SCP-SAGA-13023) BEFORE the escrow reserve runs — the
    /// initiation-consumes-budget gate.
    #[tokio::test]
    async fn prepare_a_rejects_when_per_interface_rate_budget_exhausted() {
        use scp_protocol::context::tools::interface::{RateLimit, ToolInterface};
        use std::time::Duration;
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0x11, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        // A per-interface §6.2.0.2 window with ZERO budget (no calls, no burst)
        // is already exhausted, so the consume rejects at initiation.
        let zero_budget = RateLimit::with_burst(
            0,
            Duration::from_mins(1),
            0,
            Duration::from_secs(1),
            deps.clock.as_ref(),
        );
        st.governance.tool_interfaces.push(ToolInterface {
            source_context: hex_context_id(&[0x11; 32]),
            target_context: hex_context_id(&[0x22; 32]),
            tool_id: TOOL.to_owned(),
            rate_limit: Some(zero_budget),
            inbound_rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: None,
        });

        let (tx, rx) = oneshot::channel();
        let _ = prepare_a(
            &mut st,
            &deps,
            &[0x11; 32],
            &DID(CALLER.to_owned()),
            TOOL,
            tx,
        )
        .await;
        let err = rx.await.unwrap().expect_err("over-budget must reject");
        assert!(
            matches!(err, ContextError::RateLimited { ref message, .. } if message.contains("SCP-SAGA-13023")),
            "expected per-interface §6.2.0.2 RateLimited (SCP-SAGA-13023), got {err:?}"
        );
    }

    /// FIX B.1 — per-CALLER §6.2.0.2 window. An interface whose per-caller window
    /// is exhausted (max_calls_per_caller = 0) rejects Prepare-A with
    /// `RateLimited` (SCP-SAGA-13024), independent of the per-interface window.
    #[tokio::test]
    async fn prepare_a_rejects_when_per_caller_rate_budget_exhausted() {
        use scp_protocol::context::tools::interface::{PerCallerRateLimit, ToolInterface};
        use std::time::Duration;
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0x11, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        let zero_caller_budget =
            PerCallerRateLimit::with_burst(0, Duration::from_mins(1), 0, Duration::from_secs(1));
        st.governance.tool_interfaces.push(ToolInterface {
            source_context: hex_context_id(&[0x11; 32]),
            target_context: hex_context_id(&[0x22; 32]),
            tool_id: TOOL.to_owned(),
            rate_limit: None,
            inbound_rate_limit: None,
            per_caller_rate_limit: Some(zero_caller_budget),
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: None,
        });

        let (tx, rx) = oneshot::channel();
        let _ = prepare_a(
            &mut st,
            &deps,
            &[0x11; 32],
            &DID(CALLER.to_owned()),
            TOOL,
            tx,
        )
        .await;
        let err = rx
            .await
            .unwrap()
            .expect_err("over-caller-budget must reject");
        assert!(
            matches!(err, ContextError::RateLimited { ref message, .. } if message.contains("SCP-SAGA-13024")),
            "expected per-caller §6.2.0.2 RateLimited (SCP-SAGA-13024), got {err:?}"
        );
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

    /// FIX B.2 (`InboundPolicy.allowed_source_roles` enforced at Prepare-B). An
    /// ungated tool whose interface restricts `allowed_source_roles` to a set
    /// that does NOT contain the channel-authenticated caller's role rejects
    /// with SCP-SAGA-13025 and stages nothing — the role is evaluated against
    /// the supervisor-resolved `caller_source_role`, never an envelope value.
    #[tokio::test]
    async fn prepare_b_rejects_caller_role_not_in_allowed_source_roles() {
        use scp_protocol::context::tools::interface::{InboundPolicy, ToolInterface};
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        // Ungated tool (no UCAN proof) on the TARGET context 0x55.
        let mut st = target_state(0x55, OTHER, CALLER).await;
        st.governance.tool_interfaces.push(ToolInterface {
            source_context: hex_context_id(&[0x99; 32]),
            target_context: hex_context_id(&[0x55; 32]),
            tool_id: TOOL.to_owned(),
            rate_limit: None,
            inbound_rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: Some(InboundPolicy {
                allowed_source_roles: vec!["admin".to_owned()],
                ..InboundPolicy::default()
            }),
        });
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();

        // The channel-authenticated caller role is "member", NOT in {admin}.
        let req = prepare_b_request_with_role(0x55, None, 2, now_ms, Some("member".to_owned()));
        let (tx, rx) = oneshot::channel();
        let _ = prepare_b(&mut st, &deps, req, tx).await;
        let err = rx
            .await
            .unwrap()
            .expect_err("disallowed source role must reject");
        assert!(
            matches!(err, ContextError::PermissionDenied(ref m) if m.contains("SCP-SAGA-13025")),
            "expected allowed_source_roles rejection (SCP-SAGA-13025), got {err:?}"
        );
        // Nothing was staged.
        assert!(
            !st.saga_pending
                .contains_key(&SagaId("saga-xctx-1".to_owned())),
            "a rejected Prepare-B must not stage a prepared slot"
        );
    }

    /// FIX B.2 — the allow path: a caller whose channel-authenticated role IS in
    /// `allowed_source_roles` is admitted (the inbound gate does not over-block).
    #[tokio::test]
    async fn prepare_b_accepts_caller_role_in_allowed_source_roles() {
        use scp_protocol::context::tools::interface::{InboundPolicy, ToolInterface};
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0x56, OTHER, CALLER).await;
        st.governance.tool_interfaces.push(ToolInterface {
            source_context: hex_context_id(&[0x99; 32]),
            target_context: hex_context_id(&[0x56; 32]),
            tool_id: TOOL.to_owned(),
            rate_limit: None,
            inbound_rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: Some(InboundPolicy {
                allowed_source_roles: vec!["member".to_owned(), "admin".to_owned()],
                ..InboundPolicy::default()
            }),
        });
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();

        let req = prepare_b_request_with_role(0x56, None, 2, now_ms, Some("member".to_owned()));
        let (tx, rx) = oneshot::channel();
        let out = prepare_b(&mut st, &deps, req, tx).await;
        assert!(out.result.is_ok(), "prepare_b: {:?}", out.result);
        rx.await.unwrap().expect("an allowed role must be admitted");
    }

    /// Push a `TOOL` interface with the given inbound `max_calls_per_minute`
    /// onto `st` (target context `ctx_byte`), approved both sides — the fixture
    /// for the inbound-rate consume tests.
    fn push_inbound_interface(st: &mut PerContextState, ctx_byte: u8, inbound_per_min: u32) {
        use scp_protocol::context::tools::interface::{InboundPolicy, ToolInterface};
        st.governance.tool_interfaces.push(ToolInterface {
            source_context: hex_context_id(&[0x99; 32]),
            target_context: hex_context_id(&[ctx_byte; 32]),
            tool_id: TOOL.to_owned(),
            rate_limit: None,
            inbound_rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: Some(InboundPolicy {
                max_calls_per_minute: inbound_per_min,
                ..InboundPolicy::default()
            }),
        });
    }

    /// FIX 3 (B-side inbound rate enforced). Prepare-B consumes B's OWN INBOUND
    /// §6.2.0.2 sliding window; once it is exhausted the consume rejects with a
    /// typed `SCP-SAGA-13026`. The window is materialized lazily from
    /// `InboundPolicy.max_calls_per_minute` and the consume is non-refundable.
    #[tokio::test]
    async fn prepare_b_inbound_rate_limit_rejects_when_exhausted() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0x57, OTHER, CALLER).await;
        // Inbound ceiling 1/min: base allows 1 call, then up to the default
        // burst allowance (5) within the burst window, then rejects.
        push_inbound_interface(&mut st, 0x57, 1);
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        // Drain the base + burst budget (1 base + 5 burst = 6 admitted).
        for i in 0..6 {
            consume_inbound_interface_rate_limit(&mut st, &deps, TOOL)
                .unwrap_or_else(|e| panic!("call {i} within budget must be admitted: {e:?}"));
        }
        // The next consume exhausts the window ⇒ typed SCP-SAGA-13026.
        let err = consume_inbound_interface_rate_limit(&mut st, &deps, TOOL)
            .expect_err("inbound window exhausted must reject");
        assert!(
            matches!(err, ContextError::RateLimited { ref message, .. } if message.contains("SCP-SAGA-13026")),
            "expected inbound-rate rejection (SCP-SAGA-13026), got {err:?}"
        );
    }

    /// FIX 3 (cache-eviction config guard, runtime — NOT cfg(test)). An interface
    /// whose configured inbound rate exceeds the eviction-safe ceiling
    /// (`MAX_SAFE_INBOUND_CALLS_PER_MINUTE`) is REJECTED at Prepare-B with a typed
    /// `SCP-SAGA-13027` BEFORE the window is materialized — a high inbound ceiling
    /// (e.g. the §6.2.0.2-permitted 6000/min) must not erode the §6.2.4 replay
    /// bound. This is the runtime config guard the spec requires, not merely the
    /// `nonce_dedup_replay_bound_holds` cfg(test) invariant.
    #[tokio::test]
    async fn prepare_b_inbound_rate_above_eviction_ceiling_is_rejected() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0x58, OTHER, CALLER).await;
        // 6000/min is §6.2.0.2-permissible but far above the eviction-safe
        // ceiling (500/min) — its TTL-window volume would approach the dedup
        // capacity and erode the replay bound.
        let over_ceiling = u32::try_from(MAX_SAFE_INBOUND_CALLS_PER_MINUTE + 1).unwrap();
        push_inbound_interface(&mut st, 0x58, over_ceiling);
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        let err = consume_inbound_interface_rate_limit(&mut st, &deps, TOOL)
            .expect_err("an inbound ceiling above the eviction-safe limit must reject");
        assert!(
            matches!(err, ContextError::PermissionDenied(ref m) if m.contains("SCP-SAGA-13027")),
            "expected cache-eviction config-guard rejection (SCP-SAGA-13027), got {err:?}"
        );
        // The guard fires BEFORE materializing the window — nothing was created.
        let iface = st
            .governance
            .tool_interfaces
            .iter()
            .find(|i| i.tool_id == TOOL)
            .expect("interface present");
        assert!(
            iface.inbound_rate_limit.is_none(),
            "the config guard must reject BEFORE materializing the inbound window"
        );
    }

    /// FIX 3 (boundary): an inbound rate EXACTLY at the eviction-safe ceiling is
    /// admitted (the guard rejects only ABOVE it), confirming the guard does not
    /// over-block the maximum safe configuration.
    #[tokio::test]
    async fn prepare_b_inbound_rate_at_eviction_ceiling_is_admitted() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0x59, OTHER, CALLER).await;
        let at_ceiling = u32::try_from(MAX_SAFE_INBOUND_CALLS_PER_MINUTE).unwrap();
        push_inbound_interface(&mut st, 0x59, at_ceiling);
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        consume_inbound_interface_rate_limit(&mut st, &deps, TOOL)
            .expect("the maximum safe inbound ceiling must be admitted");
    }

    /// FIX 3 (end-to-end): an accepted Prepare-B over an interface with a
    /// (safe) inbound policy materializes B's inbound window and consumes one
    /// unit — proving the consume is wired into the Prepare-B path, not just the
    /// standalone helper.
    #[tokio::test]
    async fn prepare_b_through_path_materializes_and_consumes_inbound_window() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0x5A, OTHER, CALLER).await;
        // Ungated tool with a safe inbound ceiling.
        push_inbound_interface(&mut st, 0x5A, 60);
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();

        let req = prepare_b_request_with_role(0x5A, None, 2, now_ms, Some("member".to_owned()));
        let (tx, rx) = oneshot::channel();
        let out = prepare_b(&mut st, &deps, req, tx).await;
        assert!(out.result.is_ok(), "prepare_b: {:?}", out.result);
        rx.await.unwrap().expect("prepared-B");

        // The inbound window was materialized and one unit consumed.
        let iface = st
            .governance
            .tool_interfaces
            .iter()
            .find(|i| i.tool_id == TOOL)
            .expect("interface present");
        let window = iface
            .inbound_rate_limit
            .as_ref()
            .expect("Prepare-B materialized B's inbound window");
        assert_eq!(
            window.current_count, 1,
            "Prepare-B consumed exactly one inbound unit"
        );
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

    /// FIX 4 (BLACK-624-01): the nonce-dedup replay protection SURVIVES a crash.
    /// A `CrossContextToolInvoke` whose nonce was accepted, then the actor
    /// crashes and restores from its snapshot, then the SAME envelope is
    /// re-submitted under a FRESH `SagaId`, MUST be rejected by the rehydrated
    /// nonce-dedup cache. Before this fix the cache reinitialized EMPTY on
    /// restore, so a crash inside the 5-minute TTL re-opened the replay.
    ///
    /// We accept a nonce via `prepare_b`, project the live state to a snapshot
    /// (the Class-S persistence path), simulate restore by rehydrating a FRESH
    /// state's nonce-dedup from that snapshot (mirroring `restore_context`), then
    /// re-submit the same nonce under a new `SagaId` — it is rejected.
    #[tokio::test]
    async fn nonce_dedup_survives_crash_and_blocks_fresh_saga_replay() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let mut st = target_state(0x6A, OTHER, CALLER).await;
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();
        let now_secs = deps.clock.now_secs();

        // Accept the envelope under its original SagaId — records the nonce.
        let replay_nonce = [0x42u8; 16];
        let mut first = prepare_b_request(0x6A, None, 2, now_ms);
        first.saga_id = SagaId("original-saga".to_owned());
        first.asserted_nonce = replay_nonce;
        let (tx, rx) = oneshot::channel();
        let out = prepare_b(&mut st, &deps, first, tx).await;
        assert!(out.result.is_ok(), "first prepare_b: {:?}", out.result);
        rx.await.unwrap().expect("first prepare_b accepts");
        assert!(
            st.xctx_nonce_dedup.entries().contains_key(&replay_nonce),
            "the accepted nonce was recorded"
        );

        // Project the live state to its Class-S snapshot — the persisted form a
        // restore rehydrates from. The nonce-dedup cache must be carried.
        let snapshot = crate::context::messaging_helpers::build_snapshot_from_state(&st);
        assert!(
            snapshot.xctx_nonce_dedup.contains_key(&replay_nonce),
            "the nonce-dedup cache MUST be in the Class-S snapshot (crash-surviving)"
        );

        // Simulate restore: a FRESH actor state whose nonce-dedup is rehydrated
        // from the snapshot (mirrors `restore_context`'s
        // `NonceDedup::from_entries_with_ttl` — the saga dedup TTL, strictly
        // longer than the freshness skew tolerance, is preserved on restore).
        let mut restored = target_state(0x6A, OTHER, CALLER).await;
        restored.xctx_nonce_dedup =
            scp_protocol::crypto::sender_keys::NonceDedup::from_entries_with_ttl(
                snapshot.xctx_nonce_dedup,
                SAGA_NONCE_DEDUP_TTL_SECS,
            );

        // Re-submit the SAME envelope under a FRESH SagaId after the "crash".
        let mut replay = prepare_b_request(0x6A, None, 2, now_ms);
        replay.saga_id = SagaId("fresh-replay-saga".to_owned());
        replay.asserted_nonce = replay_nonce;
        let _ = now_secs; // freshness uses the clock; nonce dedup is the gate here.
        let (tx, rx) = oneshot::channel();
        let out = prepare_b(&mut restored, &deps, replay, tx).await;
        assert!(out.result.is_err(), "fresh-SagaId replay must be rejected");
        let err = rx.await.unwrap().expect_err("replay rejected");
        assert!(
            matches!(err, ContextError::PermissionDenied(m) if m.contains("SCP-SAGA-13019")),
            "the rehydrated nonce-dedup cache MUST reject the cross-crash fresh-SagaId replay"
        );
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

    /// Provenance-integrity (regression): a Commit-A whose idempotency-witness
    /// Class-S persist FAILS must NOT durably append the A-side
    /// `CrossContextToolInvoked` record. The append is sequenced AFTER (and gated
    /// on) the witness persist — mirroring `commit_b_first_settle` — so a persist
    /// failure leaves NO orphan A-side "the call happened" record that B's log
    /// denies (the silent one-sided A-record / reverse-direction repudiation
    /// primitive the append-before-persist inverse produced). The handler returns
    /// `Err`/`mutated` (the escrow settle ran) and the witness is not left set, so
    /// the FSM retry re-acks from the absent witness and resolves correctly.
    #[tokio::test]
    async fn commit_a_witness_persist_failure_appends_no_invoked_orphan() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        // Prepare-A runs on the CALLER context.
        let mut st = target_state(0xC7, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();

        // Stage Prepare-A with an Ok persistence to obtain the held reservation
        // (the FSM carries it) — the reserve + Prepare-A tail persists must
        // succeed so the reservation lands.
        let stage_deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let (tx, rx) = oneshot::channel();
        prepare_a(
            &mut st,
            &stage_deps,
            &[0xC7; 32],
            &DID(CALLER.to_owned()),
            TOOL,
            tx,
        )
        .await;
        let prepared_a = rx.await.unwrap().expect("prepared-A");

        // Commit-A deps: a counting event log (observes the A-side append) + a
        // persistence whose FIRST call (the Commit-A witness persist) FAILS. The
        // escrow capture itself performs no payment (test deps carry no payment
        // adapter), so the only persist Commit-A drives is the witness persist.
        let xctx_invoked_appends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let commit_deps = build_deps_with_providers(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(CrossContextCountingEventLog {
                xctx_invoked_appends: Arc::clone(&xctx_invoked_appends),
            }),
            Box::new(FailNthPersistence {
                calls: std::sync::atomic::AtomicUsize::new(0),
                fail_at: 0,
            }),
        )
        .await;

        let saga = SagaId("saga-commit-a-witness-failclose".to_owned());
        let req = CommitARequest {
            saga_id: saga.clone(),
            reservation: prepared_a,
            caller_context_id: [0xC7; 32],
            caller_did: DID(CALLER.to_owned()),
            target_context_id: [0xEE; 32],
            nonce: [0x42; 16],
            receipt: br#"{"sig":"x"}"#.to_vec(),
            output_bytes: br#"{"result":1}"#.to_vec(),
        };
        let (tx, rx) = oneshot::channel();
        let out = commit_a(&mut st, &commit_deps, req, tx).await;

        // The witness persist failed: the handler returns Err and reports
        // `mutated` (the escrow settle ran before the failed persist).
        assert!(out.result.is_err(), "witness persist must fail-close");
        assert!(
            out.mutated,
            "the escrow settle mutated owned economy ⇒ mutated"
        );
        let err = rx
            .await
            .unwrap()
            .expect_err("commit-a must fail-close on witness persist");
        assert!(matches!(err, ContextError::PersistenceFailed(_)));

        // No orphan A-side record: the `CrossContextToolInvoked` append is gated
        // behind the (failed) witness persist, so it NEVER ran.
        assert_eq!(
            xctx_invoked_appends.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a witness-persist failure must NOT append CrossContextToolInvoked \
             (append is sequenced after the witness persist)"
        );
        // The witness is not left set — a retry re-acks from the absent witness.
        assert!(
            !st.xctx_committed_invocations.contains(&saga),
            "the rolled-back witness must not survive a persist failure"
        );
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

    /// FIX 1 (regression): a CALLER-side abort that refunds the held economy
    /// reservation MUST Class-S PERSIST that refund — Prepare-A durably
    /// persisted the matching DEDUCTION, so without a refund persist a
    /// crash-after-ack loses the in-memory refund while the deduction survives,
    /// permanently over-charging the caller (the saga is Aborted, nothing
    /// re-drives it). Prepare-A never stages a `saga_pending` slot on the caller
    /// (only Prepare-B does), so the old `had_slot`-gated persist short-circuited
    /// to `Outcome::ok(())` with NO persist on this exact path. This drives the
    /// abort through a PERSISTENCE SPY and asserts (a) `persist_context` was
    /// invoked, and (b) the hard-rate-limit token + velocity the reserve consumed
    /// are durably restored. The existing `abort_a_side_releases_escrow_reservation`
    /// uses `OkPersistence` and asserts only the ack — it cannot catch this.
    #[tokio::test]
    async fn abort_a_side_persists_caller_refund() {
        use std::sync::atomic::Ordering;

        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0xC8, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();
        let persist_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(SpyPersistence {
                persist_calls: Arc::clone(&persist_calls),
            }),
        )
        .await;

        let caller = DID(CALLER.to_owned());
        // The token-bucket burst capacity, in the limiter's internal milli-token
        // units (1000 milli-tokens per token) — a fresh caller starts FULL and a
        // reserve drains exactly one token; a refund restores it.
        let burst_milli = st.governance.hard_rate_limit.config().burst * 1000;
        // Observe pre-reserve velocity for `caller`.
        let now_secs = deps.clock.now_secs();
        let velocity_before = st
            .governance
            .velocity_tracker
            .get_velocity(&caller, now_secs);

        // Prepare-A consumes a hard-rate-limit token + records velocity (and
        // persists the deduction once via the spy).
        let (tx, rx) = oneshot::channel();
        prepare_a(&mut st, &deps, &[0xC8; 32], &caller, TOOL, tx).await;
        let prepared_a = rx.await.unwrap().expect("prepared-A");

        // Reserve actually moved owned economy state (else the test proves
        // nothing): the hard-rate-limit token bucket dropped exactly one token
        // below full burst, and velocity rose.
        let hrl_after_reserve = st
            .governance
            .hard_rate_limit
            .snapshot_entries()
            .get(CALLER)
            .map(|(tokens, _)| *tokens)
            .expect("reserve created a hard-rate-limit entry for the caller");
        assert!(
            hrl_after_reserve < burst_milli,
            "reserve must have consumed a hard-rate-limit token \
             (burst_milli={burst_milli}, after_reserve={hrl_after_reserve})"
        );
        let velocity_after_reserve = st
            .governance
            .velocity_tracker
            .get_velocity(&caller, now_secs);
        assert!(
            velocity_after_reserve > velocity_before,
            "reserve must have recorded velocity \
             (before={velocity_before}, after_reserve={velocity_after_reserve})"
        );

        // Reset the persist counter so we measure ONLY the abort's persist.
        persist_calls.store(0, Ordering::SeqCst);

        // Caller-side abort (no staged slot — Prepare-A stages none). The refund
        // runs against MATCHING generation, so it mutates owned economy state
        // and MUST persist.
        let saga = SagaId("saga-abort-a-persist".to_owned());
        let (tx, rx) = oneshot::channel();
        let out = abort(&mut st, &deps, &saga, Some(prepared_a), tx).await;
        assert!(out.result.is_ok(), "abort-a: {:?}", out.result);
        assert!(out.mutated, "the abort refunded owned state ⇒ mutated");
        rx.await.unwrap().expect("abort-a ack");

        // (a) the refund was Class-S persisted — the core regression assertion.
        assert!(
            persist_calls.load(Ordering::SeqCst) >= 1,
            "caller-side abort MUST persist the refunded economy (Prepare-A persisted the \
             matching deduction; skipping this persist permanently over-charges the caller \
             on a crash-after-ack)"
        );

        // (b) the refund durably restored the consumed hard-rate-limit token
        // (back to full burst) and rolled the velocity back to its pre-reserve
        // value.
        let hrl_after_abort = st
            .governance
            .hard_rate_limit
            .snapshot_entries()
            .get(CALLER)
            .map(|(tokens, _)| *tokens)
            .expect("hard-rate-limit entry present after abort");
        assert_eq!(
            hrl_after_abort, burst_milli,
            "abort must refund the consumed hard-rate-limit token (restore to full burst)"
        );
        assert!(
            hrl_after_abort > hrl_after_reserve,
            "the abort refund restored a token the reserve had consumed \
             (after_reserve={hrl_after_reserve}, after_abort={hrl_after_abort})"
        );
        let velocity_after_abort = st
            .governance
            .velocity_tracker
            .get_velocity(&caller, now_secs);
        assert_eq!(
            velocity_after_abort, velocity_before,
            "abort must roll back the recorded velocity"
        );
    }

    /// FIX 2 (confused-deputy): the abort handler rolls back the held
    /// reservation through the GENERATION-CHECKED path. If the actor was
    /// despawned+respawned (generation bumped) between Prepare-A and an
    /// in-flight Abort, the rollback MUST NOT refund velocity/budget/rate-limit
    /// against the new instance's owned state — it voids only the external
    /// escrow and consumes the ticket (no panic). A MATCHING generation rolls
    /// back locally as before.
    #[tokio::test]
    async fn rollback_generation_checked_voids_external_not_local_on_mismatch() {
        use crate::context::tools_helpers::rollback_tool_economy_generation_checked;

        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0xD1, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        // Reservation made at the live generation (0).
        let (tx, rx) = oneshot::channel();
        prepare_a(
            &mut st,
            &deps,
            &[0xD1; 32],
            &DID(CALLER.to_owned()),
            TOOL,
            tx,
        )
        .await;
        let prepared_match = rx.await.unwrap().expect("prepared-A (match)");
        let gen_match = prepared_match.reservation.generation;
        assert_eq!(
            gen_match, st.generation,
            "reservation made at live generation"
        );

        // Generations MATCH ⇒ local rollback runs.
        let ran_local = rollback_tool_economy_generation_checked(
            &mut st,
            &deps,
            prepared_match.reservation.generation,
            prepared_match.reservation.ticket,
        )
        .await;
        assert!(ran_local, "matching generation must run the local rollback");

        // A second reservation, then SIMULATE a despawn+respawn by bumping the
        // live generation. The reservation now carries the STALE generation.
        let (tx, rx) = oneshot::channel();
        prepare_a(
            &mut st,
            &deps,
            &[0xD1; 32],
            &DID(CALLER.to_owned()),
            TOOL,
            tx,
        )
        .await;
        let prepared_stale = rx.await.unwrap().expect("prepared-A (stale)");
        let stale_gen = prepared_stale.reservation.generation;
        st.generation = st.generation.wrapping_add(1);
        assert_ne!(
            stale_gen, st.generation,
            "the respawn bumped the live generation past the reservation's"
        );

        // Generations MISMATCH ⇒ external-only (local untouched), ticket consumed
        // (no unbalanced-drop panic). Routing through the saga `abort` handler
        // would call `rollback_tool_economy` directly without this guard.
        let ran_local = rollback_tool_economy_generation_checked(
            &mut st,
            &deps,
            stale_gen,
            prepared_stale.reservation.ticket,
        )
        .await;
        assert!(
            !ran_local,
            "a generation mismatch must NOT run the local rollback (confused-deputy guard)"
        );
        // Reaching here without a Drop panic ⇒ the ticket was consumed on the
        // external-only path.
    }

    /// FIX 2 end-to-end: the saga `abort` handler tolerates a
    /// generation-mismatched reservation (despawn+respawn between Prepare-A and
    /// Abort) without panicking on the ticket's unbalanced-drop guard, and acks.
    #[tokio::test]
    async fn abort_a_side_with_stale_generation_does_not_panic() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0xD2, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        let (tx, rx) = oneshot::channel();
        prepare_a(
            &mut st,
            &deps,
            &[0xD2; 32],
            &DID(CALLER.to_owned()),
            TOOL,
            tx,
        )
        .await;
        let prepared = rx.await.unwrap().expect("prepared-A");

        // Simulate the despawn+respawn: bump the live generation past the
        // reservation's.
        st.generation = st.generation.wrapping_add(1);

        let saga = SagaId("saga-abort-stale-gen".to_owned());
        let (tx, rx) = oneshot::channel();
        let out = abort(&mut st, &deps, &saga, Some(prepared), tx).await;
        assert!(out.result.is_ok(), "abort with stale gen: {:?}", out.result);
        rx.await.unwrap().expect("abort ack");
        // No panic ⇒ the generation-checked rollback voided external + consumed.
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
            CrossContextDivergenceMarkerFields {
                saga_id: saga.0.clone(),
                nonce: [0xAB; 16],
                committed_side: CommittedSide::Target,
                committed_event_id: "evt-committed-9".to_owned(),
            },
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

    /// FIX 3 (provenance-integrity): a Commit-B persist FAILURE followed by a
    /// successful RETRY appends EXACTLY ONE `ToolInvoked`. The `ToolInvoked`
    /// event-log append (a separate, non-idempotent provider) is sequenced AFTER
    /// the durable capture + Class-S persist succeed, so a persist failure leaves
    /// no orphan log entry to double-append on retry.
    #[tokio::test]
    async fn commit_b_persist_retry_appends_tool_invoked_exactly_once() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let mut st = target_state(0xCD, OTHER, CALLER).await;
        let saga = SagaId("saga-persist-retry-once".to_owned());

        // Stage Prepare-B with an Ok persistence + a throwaway event log (the
        // stage append is a `Prepared`-class event, not `ToolInvoked`).
        let stage_deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = stage_deps.clock.now_millis();
        stage_prepared_b(&mut st, &stage_deps, 0xCD, &saga.0, now_ms).await;

        // Settle deps: a counting event log + a persistence that FAILS the first
        // call then succeeds. Both providers live behind the same shared counter.
        let tool_invoked_appends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let settle_deps = build_deps_with_providers(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(CountingEventLog {
                tool_invoked_appends: Arc::clone(&tool_invoked_appends),
            }),
            Box::new(FailFirstPersistence {
                calls: std::sync::atomic::AtomicUsize::new(0),
            }),
        )
        .await;
        let output = br#"{"result":7}"#.to_vec();
        let signing = signing_key_bytes(0xAA);

        // FIRST settle: the persist fails BEFORE the append — capture rolled back,
        // staged slot restored, and (FIX 3) NO `ToolInvoked` appended.
        let (tx, rx) = oneshot::channel();
        let out = commit_b_settle(&mut st, &settle_deps, &saga, output.clone(), &signing, tx).await;
        assert!(
            out.result.is_err(),
            "first settle must fail-close on persist"
        );
        let err = rx.await.unwrap().expect_err("first settle persist failure");
        assert!(matches!(err, ContextError::PersistenceFailed(_)));
        assert_eq!(
            tool_invoked_appends.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a persist failure must NOT append ToolInvoked (append is sequenced after persist)"
        );
        assert!(!st.xctx_committed_outputs.contains_key(&saga));
        assert!(st.saga_pending.contains_key(&saga));

        // RETRY settle on the SAME deps (the persistence now succeeds): capture
        // lands, persist succeeds, and `ToolInvoked` appends EXACTLY ONCE.
        let (tx, rx) = oneshot::channel();
        let out = commit_b_settle(&mut st, &settle_deps, &saga, output, &signing, tx).await;
        assert!(
            out.result.is_ok(),
            "retry settle must succeed: {:?}",
            out.result
        );
        rx.await.unwrap().expect("retry settle ack");
        assert_eq!(
            tool_invoked_appends.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a persist-failure-then-retry Commit-B must append ToolInvoked EXACTLY ONCE"
        );
        assert!(st.xctx_committed_outputs.contains_key(&saga));
        assert!(!st.saga_pending.contains_key(&saga));
    }

    /// FIX 6 (simplifier): a Commit-B settle persist-failure rollback RE-INSERTS
    /// the OWNED ORIGINAL staged slot verbatim — no lossy reconstruction. The
    /// deleted `reprepare_from_receipt` rebuilt the slot from the receipt and
    /// DROPPED `ucan_proof_id` (the receipt does not carry it), so a gated tool's
    /// restored slot lost its proof index. This stages a slot with a non-empty
    /// `ucan_proof_id`, fails the settle persist, and asserts the restored slot
    /// preserves the proof index byte-for-byte.
    #[tokio::test]
    async fn commit_b_settle_persist_failure_restores_full_original_slot() {
        use crate::context::supervisor::saga_prepared_state::{
            CrossContextToolInvocationPrepared, SagaPreparedState,
        };

        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let mut st = target_state(0xCB, OTHER, CALLER).await;
        let saga = SagaId("saga-settle-restore-full".to_owned());

        // Stage a slot DIRECTLY with a non-empty `ucan_proof_id` (a gated tool's
        // proof index) — the field the lossy inverse used to drop.
        let original = CrossContextToolInvocationPrepared {
            caller_context_id: [0xCC; 32],
            target_context_id: [0xCB; 32],
            caller_did: DID(CALLER.to_owned()),
            tool_registration_id: TOOL.to_owned(),
            ucan_proof_id: "gated-proof-index-42".to_owned(),
            recorded_timestamp_ms: 1_700_000_000_000,
            recorded_nonce: [0x42; 16],
            recorded_chain_depth: 3,
        };
        st.saga_pending.insert(
            saga.clone(),
            SagaPreparedState::CrossContextToolInvocation(original),
        );

        // Settle with a FAILING persistence: the capture rolls back and the slot
        // is re-inserted.
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
            br#"{"result":5}"#.to_vec(),
            &signing_key_bytes(0xBB),
            tx,
        )
        .await;
        assert!(out.result.is_err());
        let err = rx.await.unwrap().expect_err("persist must fail-close");
        assert!(matches!(err, ContextError::PersistenceFailed(_)));

        // The restored slot preserves the FULL original — including the
        // `ucan_proof_id` the deleted lossy inverse would have dropped.
        let restored = st.saga_pending.get(&saga).expect("slot restored");
        let SagaPreparedState::CrossContextToolInvocation(p) = restored else {
            panic!("restored slot must be a cross-context prepared");
        };
        assert_eq!(
            p.ucan_proof_id, "gated-proof-index-42",
            "the restored slot must preserve ucan_proof_id (no lossy reconstruction)"
        );
        assert_eq!(p.recorded_nonce, [0x42; 16]);
        assert_eq!(p.recorded_chain_depth, 3);
        assert!(!st.xctx_committed_outputs.contains_key(&saga));
    }
}
