//! Governance proposal, vote, execute, and dispatch operations —
//! free-function logic hoisted out of the deleted `manager/` directory
//! in ADR-049 commit 12.

use scp_did::DID;
use scp_protocol::context::membership::{ContextEvent, ReceiveBuffer};
use scp_protocol::context::params::Capability;
use scp_protocol::trust::consequence::{ConsequenceRule, TriggeredConsequence};

use super::actor::class_s::{ClassSCommitToken, ConsequenceRoleStateMut};
// Re-export the consequence split (defined in `class_s`) for the consequence
// callers that reach it via this module's path. `pub(in crate::context)` matches
// the type's `pub(crate)` effective reach within the context module tree without
// tripping `redundant_pub_crate` (the module itself is private to `context`).
pub(in crate::context) use super::actor::class_s::ConsequenceStateSplit;
use super::state::{context_id_to_bytes, emit_event_into};

// ---------------------------------------------------------------------------
// Consequence enforcement — synthetic actor DID + shared wire-stable labels
// ---------------------------------------------------------------------------
//
// The `CommitRetryOutcome` / `CommitRetryOutcomeKind` types that previously
// lived here for a legacy forwarder are gone — the active definitions are in
// `governance_helpers.rs` (the `process_pending_commits` retry pipeline).
// Removed in the post-review-round-1 phase 1 fix-up of ADR-049.

/// Synthetic actor DID recorded for durable consequence event log entries
/// (H4, PR #1606). Consequence enforcement is performed by the local node's
/// governance engine, not by any specific member, so the actor field is set
/// to a stable system sentinel rather than the affected member's DID. This
/// also satisfies the `WarningCount` trigger's `actor_did != subject_did`
/// requirement so subsequent rule evaluation can match prior enforcements
/// against the same target.
pub(super) const CONSEQUENCE_ACTOR_DID: &str =
    scp_event_log::system_actors::SYSTEM_CONSEQUENCE_ACTOR;

// The canonical wire-stable `trigger_kind` / `action_type` labels and the
// durable consequence-leaf payload bytes are produced by SHARED code so all
// honest members emit byte-identical Merkle-leaf preimages
// (§9.9.3 convergence): `scp_protocol::trust::consequence::{trigger_kind_str,
// consequence_action_type}` for the labels and
// `scp_event_log::payload::consequence_event_payload` for the JSON bytes.
use scp_event_log::payload::consequence_event_payload;
use scp_protocol::trust::consequence::{
    consequence_action_type, convergent_consequence_timestamp, trigger_kind_str,
};

/// Best-effort durable append of one consequence event log entry. A failed
/// append is logged via `tracing::warn!` but never blocks the matching
/// `receive_buffer.push(...)` call — the receive buffer remains a useful
/// in-session signal even when the durable log is unavailable. Returns
/// nothing because the failure mode is observed via tracing, not callers.
///
/// `payload` is the shared [`consequence_event_payload`] output — JSON bytes
/// wrapped in an [`scp_event_log::EventPayload`]. The consequence engine reads
/// `target_did` back out of these bytes via
/// `scp_protocol::trust::consequence::payload_target_is`.
async fn append_consequence_event(
    event_log: &dyn crate::context::builder::ContextEventLogProvider,
    context_id: &str,
    context_id_bytes: &[u8; 32],
    event_type: scp_event_log::EventType,
    member_did: &DID,
    payload: scp_event_log::EventPayload,
    // Convergent leaf timestamp: the `timestamp` of the convergent triggering
    // event (see [`convergent_consequence_timestamp`]). Copied identically by
    // every member, never a per-member evaluation `now()` (§7.3.1, §9.9.3).
    trigger_timestamp_secs: u64,
) {
    if let Err(e) = event_log
        .append_context_event_with_payload(
            context_id_bytes,
            event_type,
            CONSEQUENCE_ACTOR_DID,
            payload,
            trigger_timestamp_secs,
        )
        .await
    {
        tracing::warn!(
            context_id,
            member = %member_did,
            event = ?event_type,
            error = %e,
            "failed to append consequence event to durable event log"
        );
    }
}

// `ConsequenceStateSplit` (the consequence-engine split) is DEFINED in
// `super::actor::class_s` and RE-EXPORTED here (`use` above). It is its own
// struct — NOT an alias of `ClassCSplit` (ADR-049 §9 / RED-CS3 / R1): its
// `role_state` is the consequence-only `ConsequenceRoleStateMut`, the one role
// view that exposes the downward-authorization GROW mutators
// (`suspend_capabilities` / `suspend_all`) and the demotion (`system_assign_role`).
// Best-effort callers receive `ClassCSplit` (via `ClassCMut::split_class_c`),
// whose `RoleStateClassCMut` has NO GROW, so a best-effort downward-auth GROW with
// no fail-closed persist is a COMPILE error by construction (BLACK-CS-03 closed).
// The consequence sites build this split via `ClassCMut::consequence_split` (cell
// path) or `ConsequenceStateSplit::from_state` (cell-free governance-helper path);
// the cell-holding caller persists any applied GROW / demotion FAIL-CLOSED before
// acking — `enforce_triggered_consequences` returns the downward-auth flag it acts
// on (RED-CS3).

/// Borrowed inputs for `enforce_triggered_consequences`. Bundling the
/// providers, scope identifiers, and pre-evaluated rule data into one
/// struct keeps the public function signature within the
/// `clippy::too_many_arguments` budget while preserving the explicit
/// names that callers (`messaging.rs`, `outlets.rs`, `governance.rs`,
/// the periodic timer) need at construction time.
pub struct EnforceConsequencesCtx<'a> {
    pub context_id: &'a str,
    pub member_did: &'a DID,
    pub now: u64,
    pub triggered: &'a [TriggeredConsequence],
    pub rules: &'a [ConsequenceRule],
    pub clock: &'a dyn scp_clock::Clock,
    pub event_log: &'a dyn crate::context::builder::ContextEventLogProvider,
    /// Optional broadcast channel for event propagation from free
    /// functions that lack `&self` access to `ContextManager`.
    pub event_tx: Option<
        &'a tokio::sync::broadcast::Sender<(
            String,
            scp_protocol::context::membership::ContextEvent,
        )>,
    >,
}

/// Enforces a set of pre-evaluated triggered consequences.
///
/// Separated from the former `dispatch_consequences` so callers that need
/// `evaluate_consequence_rules` visible in their own file (for pipeline
/// wiring AST gates) can call evaluate + enforce as two distinct steps.
///
/// The `rules` field on [`EnforceConsequencesCtx`] should be the same slice
/// used for evaluation. When called from `dispatch_consequences`, the
/// already-cloned rules are passed to avoid a second clone.
///
/// **Durability invariant (H4; durability gated per ADR-051 §6 / phase-2.md
/// ADR-011 amendment "Consequence emission"):** a consequence leaf is a durable
/// Merkle entry **iff its trigger is convergent** — `WarningCount` / `Custom`
/// (governance counts), tested via
/// [`is_convergent_trigger`](scp_protocol::trust::consequence::is_convergent_trigger).
/// `MessageVelocity` / `OutletRateExceeded` are non-convergent (a rate needs a
/// clock the protocol neither has nor needs); their consequences are
/// **buffer-only** — local enforcement still runs and the `ContextEvent` is
/// still emitted, but **no durable leaf** is minted, because a per-receiver,
/// velocity-derived leaf would diverge across honest members and break §9.9.3.
/// When a leaf IS durable, it is appended via `event_log` BEFORE the matching
/// `ctx.receive_buffer.push(...)` call: a crash between the append and the
/// buffer push leaves the Merkle-anchored record intact (the buffer is
/// in-memory and capped at 1000, so its loss is not a non-repudiation gap; the
/// durable log is the system of record). The receive buffer pushes are always
/// performed — they are useful for in-session SDK observation and, for
/// non-durable consequences, are the sole surfacing. The
/// `checkpoint_events_since` counter is incremented only when a durable leaf is
/// actually appended, so it matches the true durable-leaf count (a §9.9.3
/// checkpoint-position drift otherwise).
///
/// **Downward-authorization fail-closed contract (ADR-049 §9, RED-CS3):** the
/// `obligation` sink is ARMED (populated with a [`ClassSCommitToken`]) iff at
/// least one triggered consequence performed a **downward-authorization
/// mutation** that reduced a member's effective authority (`member_has_capability`
/// = `member_capabilities` − `suspended_capabilities`). There are TWO such
/// mutations and the sink covers BOTH: (1) a `suspended_capabilities` GROW
/// (`suspend_capabilities` / `suspend_all`, i.e. `SuspendCapability` /
/// `SuspendAccess` / the H10 `SuspendAll` escalation), and (2) an `AssignRole`
/// `member_capabilities` REPLACEMENT (`system_assign_role`) — a demotion shrinks
/// the member's granted set. The arming is done BY the GROW methods themselves
/// (each takes the same `&mut Option<ClassSCommitToken>` sink as a required
/// parameter — GAP-A closed), so a downward-auth mutation cannot be applied
/// WITHOUT arming the owed persist. EVALUATION itself (cooldowns, velocity ticks,
/// event emission, the `checkpoint_events_since` bump, durable Merkle appends)
/// stays best-effort / coalesced — it is the hot per-message path and is NOT
/// persisted synchronously here. Only the rare downward-auth OUTCOME must be
/// durable fail-closed before the actor acks, because a coalesce-window crash
/// would otherwise restore the pre-mutation role state and silently re-grant the
/// removed authority. The in-memory mutation is applied here; the cell-holding
/// caller, after the borrowing view drops, discharges any populated sink with a
/// fail-closed persist of the already-mutated state (keep-direction: the
/// suspension / demotion STAYS on persist failure). When the sink stays `None`,
/// no downward-auth transition occurred and the caller's ordinary coalesced
/// persist is sufficient.
///
/// The returned `bool` mirrors whether the sink was armed (the RED-CS3b
/// engine-level downward-auth signal); it is retained for callers / tests that
/// observe the signal directly, but the obligation arming itself is now carried by
/// the sink, not by the caller reacting to the return value.
#[must_use]
pub async fn enforce_triggered_consequences(
    state: &mut ConsequenceStateSplit<'_>,
    args: &EnforceConsequencesCtx<'_>,
    obligation: &mut Option<ClassSCommitToken>,
) -> bool {
    let context_id_bytes = context_id_to_bytes(args.context_id);
    let mut downward_auth_applied = false;
    for consequence in args.triggered {
        downward_auth_applied |= process_one_triggered_consequence(
            state,
            args,
            &context_id_bytes,
            consequence,
            obligation,
        )
        .await;
    }
    downward_auth_applied
}

/// Single-consequence body of [`enforce_triggered_consequences`].
/// Extracted so the public function stays under `clippy::too_many_lines`.
///
/// Returns `true` iff THIS consequence performed a downward-authorization
/// mutation owing a fail-closed persist (ADR-049 §9): a `suspended_capabilities`
/// GROW (the success-path `SuspendCapability` / `SuspendAccess`, or the H10
/// failure escalation to `SuspendAll`) OR an `AssignRole` `member_capabilities`
/// replacement (a demotion shrinks the member's effective authority). The caller
/// OR-accumulates this across the triggered set to decide whether a fail-closed
/// persist of the already-mutated state is owed.
async fn process_one_triggered_consequence(
    state: &mut ConsequenceStateSplit<'_>,
    args: &EnforceConsequencesCtx<'_>,
    context_id_bytes: &[u8; 32],
    consequence: &TriggeredConsequence,
    obligation: &mut Option<ClassSCommitToken>,
) -> bool {
    let member_did = args.member_did;
    let now = args.now;

    // Cooldown tracking: skip if this rule fired within its window. The cooldown
    // map is a Class-C governance field reached through the field-granular
    // `GovernanceClassCMut` accessor (the view holds no whole `&mut GovernanceState`
    // and cannot reach `governance.class_s`).
    if let Some(&last_fired) = state
        .governance
        .cooldown_until_mut()
        .get(&consequence.rule_index)
        && now < last_fired
    {
        return false;
    }

    // TOCTOU/ghost guard: skip entirely if the member is absent AND
    // there is no evidence that the member ever participated. Members
    // who left mid-flight after accumulating real evidence still emit
    // `ConsequenceTriggered` so observers see the behavioral signal.
    let member_present = state.membership.contains(member_did);
    if !member_present && consequence.evidence.is_empty() {
        tracing::debug!(
            member = %member_did,
            "skipping consequence: ghost DID with no evidence"
        );
        return false;
    }

    let action_type = consequence_action_type(&consequence.action);
    let rule = args.rules.get(consequence.rule_index);
    let trigger_kind = rule.map_or_else(|| "Unknown".to_owned(), |r| trigger_kind_str(&r.trigger));

    // Durability gate (ADR-051 §6 / phase-2.md ADR-011 amendment "Consequence
    // emission"): a consequence leaf is a durable Merkle entry ONLY when its
    // trigger input is convergent — `WarningCount` / `Custom` (governance
    // counts), keyed on the enum via `is_convergent_trigger`, never on a string.
    // `MessageVelocity` / `OutletRateExceeded` are non-convergent (a rate needs a
    // clock the protocol has none of), so their consequences are buffer-only
    // `ContextEvent`s — local enforcement still runs, but no durable leaf is
    // minted (a leaf would diverge across honest members and break §9.9.3). A
    // missing or unresolvable rule is treated as non-durable (fail-safe).
    let durable =
        rule.is_some_and(|r| scp_protocol::trust::consequence::is_convergent_trigger(&r.trigger));

    // Always emit `ConsequenceTriggered` into the receive buffer + event_tx
    // (regardless of member presence). The durable Merkle leaf is gated on
    // `durable`; the buffer push and `event_tx` notification are unconditional.
    emit_consequence_triggered(
        state,
        args,
        context_id_bytes,
        consequence,
        &trigger_kind,
        action_type,
        durable,
    )
    .await;

    if !member_present {
        // Member left between evaluation and enforcement: emit a failed
        // Enforced record and skip the actual mutation.
        tracing::debug!(
            member = %member_did,
            "skipping consequence enforcement: member is no longer present"
        );
        emit_absent_member_enforcement_failed(
            state,
            args,
            context_id_bytes,
            consequence,
            &trigger_kind,
            action_type,
            durable,
        )
        .await;
        return false;
    }

    let enforcement = dispatch_enforcement_action(
        &mut state.role_state,
        member_did,
        consequence,
        args.clock,
        args.context_id,
        obligation,
    );

    if !enforcement.success {
        emit_failure_escalation(
            state,
            args,
            consequence,
            &trigger_kind,
            action_type,
            durable,
            obligation,
        )
        .await;
        // The H10 escalation unconditionally applies `suspend_all` (a Class-S
        // `suspended_capabilities` mutation), so this path always owes a
        // fail-closed persist regardless of which action originally failed.
        return true; // skip cooldown recording — failed action doesn't count
    }

    // Record cooldown: prevent re-firing within the rule's window. Written
    // through the field-granular `GovernanceClassCMut` accessor (Class-C; a
    // coalesce-window rollback of a cooldown tick is acceptable — it is not a
    // Class-S replay/authorization witness).
    if let Some(rule) = args.rules.get(consequence.rule_index) {
        state.governance.cooldown_until_mut().insert(
            consequence.rule_index,
            now.saturating_add(rule.window.as_secs()),
        );
    }

    emit_consequence_enforced_success(
        state,
        args,
        context_id_bytes,
        consequence,
        &trigger_kind,
        action_type,
        durable,
    )
    .await;

    // `true` iff this successful action reduced the member's effective authority
    // and therefore owes a fail-closed persist (ADR-049 §9): a
    // `suspended_capabilities` GROW (`SuspendCapability` / `SuspendAccess`) OR an
    // `AssignRole` `member_capabilities` REPLACEMENT. `member_capabilities` is an
    // authorization input — an `AssignRole` demotion is a downward-auth change, NOT
    // a coalesce-safe "structural role state" mutation, which is exactly the
    // misconception that left an earlier demotion-rollback window open.
    enforcement.downward_auth
}

/// Emits a `ConsequenceTriggered` event. When `durable`, appends the durable
/// Merkle leaf (and bumps `checkpoint_events_since`) BEFORE the matching
/// receive-buffer push (H4 ordering invariant); when `!durable` (a
/// velocity/rate-triggered, non-convergent consequence — ADR-051 §6), the
/// durable leaf and counter bump are suppressed and only the `ContextEvent` is
/// surfaced.
async fn emit_consequence_triggered(
    state: &mut ConsequenceStateSplit<'_>,
    args: &EnforceConsequencesCtx<'_>,
    context_id_bytes: &[u8; 32],
    consequence: &TriggeredConsequence,
    trigger_kind: &str,
    action_type: &str,
    durable: bool,
) {
    if durable {
        let payload = consequence_event_payload(
            args.member_did.as_ref(),
            consequence.rule_index,
            trigger_kind,
            action_type,
        );
        append_consequence_event(
            args.event_log,
            args.context_id,
            context_id_bytes,
            scp_event_log::EventType::ConsequenceTriggered,
            args.member_did,
            payload,
            convergent_consequence_timestamp(consequence),
        )
        .await;
        *state.checkpoint_events_since += 1;
    }
    let event = ContextEvent::ConsequenceTriggered {
        context_id: args.context_id.to_owned(),
        member_did: args.member_did.clone(),
        rule_index: consequence.rule_index,
        trigger_type: trigger_kind.to_owned(),
        action_type: action_type.to_owned(),
    };
    emit_event_into(state.receive_buffer, event, args.context_id, args.event_tx);
}

/// Emits a `ConsequenceEnforcementFailed` durable entry plus the matching
/// `ConsequenceEnforced { success: false }` receive-buffer push for the
/// "member-departed-mid-flight" path. Separate from
/// [`emit_failure_escalation`] because no escalation is applied when the
/// member is absent — there is nothing to escalate against.
async fn emit_absent_member_enforcement_failed(
    state: &mut ConsequenceStateSplit<'_>,
    args: &EnforceConsequencesCtx<'_>,
    context_id_bytes: &[u8; 32],
    consequence: &TriggeredConsequence,
    trigger_kind: &str,
    action_type: &str,
    durable: bool,
) {
    if durable {
        let payload = consequence_event_payload(
            args.member_did.as_ref(),
            consequence.rule_index,
            trigger_kind,
            action_type,
        );
        append_consequence_event(
            args.event_log,
            args.context_id,
            context_id_bytes,
            scp_event_log::EventType::ConsequenceEnforcementFailed,
            args.member_did,
            payload,
            convergent_consequence_timestamp(consequence),
        )
        .await;
        *state.checkpoint_events_since += 1;
    }
    let event = ContextEvent::ConsequenceEnforced {
        context_id: args.context_id.to_owned(),
        member_did: args.member_did.clone(),
        action_type: action_type.to_owned(),
        success: false,
    };
    emit_event_into(state.receive_buffer, event, args.context_id, args.event_tx);
}

/// Emits a `ConsequenceEnforced { success: true }` durable entry plus the
/// matching receive-buffer push for the success path.
async fn emit_consequence_enforced_success(
    state: &mut ConsequenceStateSplit<'_>,
    args: &EnforceConsequencesCtx<'_>,
    context_id_bytes: &[u8; 32],
    consequence: &TriggeredConsequence,
    trigger_kind: &str,
    action_type: &str,
    durable: bool,
) {
    if durable {
        let payload = consequence_event_payload(
            args.member_did.as_ref(),
            consequence.rule_index,
            trigger_kind,
            action_type,
        );
        append_consequence_event(
            args.event_log,
            args.context_id,
            context_id_bytes,
            scp_event_log::EventType::ConsequenceEnforced,
            args.member_did,
            payload,
            convergent_consequence_timestamp(consequence),
        )
        .await;
        *state.checkpoint_events_since += 1;
    }
    let event = ContextEvent::ConsequenceEnforced {
        context_id: args.context_id.to_owned(),
        member_did: args.member_did.clone(),
        action_type: action_type.to_owned(),
        success: true,
    };
    emit_event_into(state.receive_buffer, event, args.context_id, args.event_tx);
}

/// Outcome of a single [`dispatch_enforcement_action`] call.
///
/// `success` is the pre-existing enforced/failed signal that gates the H10
/// escalation and cooldown recording. `downward_auth` is the ADR-049 §9
/// signal: `true` iff the action REDUCED the member's effective authority and
/// therefore owes a fail-closed persist before the actor acks.
///
/// "Effective authority" is `member_has_capability` =
/// `member_capabilities` − `suspended_capabilities`. There are TWO ways an
/// enforcement action shrinks it, and `downward_auth` covers BOTH:
///
/// 1. **`suspended_capabilities` GROW** — `suspend_capabilities` / `suspend_all`
///    add to the denied set. This is the capability-suspension direction
///    (`SuspendCapability` with a non-empty set, `SuspendAccess`, and the H10
///    `SuspendAll` escalation).
/// 2. **`member_capabilities` REPLACEMENT** — `AssignRole` →
///    [`ConsequenceRoleStateMut::system_assign_role`](crate::context::actor::class_s::ConsequenceRoleStateMut::system_assign_role)
///    REPLACES `member_capabilities[member]` with
///    the new role's capability set. On a
///    DEMOTION (e.g. admin→member) this is a downward-auth shrink: the member
///    loses capabilities they previously held.
///
/// A coalesce-window crash (the ~50ms `COALESCE_INTERVAL` best-effort persist)
/// would restore the pre-mutation role state from the snapshot, silently
/// re-granting the just-removed authority. So any action in either category
/// MUST be persisted fail-closed (keep-direction). `downward_auth` is the flag
/// the caller OR-accumulates to decide between the fail-closed persist (when
/// any `true`) and the ordinary coalesced persist (when all `false`).
///
/// The two fields are distinct: an empty `SuspendCapability` neither succeeds
/// nor reduces authority (`success: false`, `downward_auth: false`), while an
/// `AssignRole` always owes a fail-closed persist (`downward_auth: true`)
/// because over-persisting a promotion is harmless (a coalesce-loss of a
/// promotion is upward — the member temporarily lacks a capability they will
/// regain, the safe direction).
struct EnforcementOutcome {
    /// Whether the action was enforced (vs. failed → H10 escalation).
    success: bool,
    /// Whether the action reduced the member's effective authority (a
    /// `suspended_capabilities` GROW or a `member_capabilities` replacement),
    /// and therefore owes a fail-closed persist (ADR-049 §9).
    downward_auth: bool,
}

/// Per-arm enforcement dispatch. Each match arm calls a named function as
/// an `expression_statement` so the pipeline wiring gates can detect the
/// `call_expression` per-variant.
fn dispatch_enforcement_action(
    role_state: &mut ConsequenceRoleStateMut<'_>,
    member_did: &DID,
    consequence: &TriggeredConsequence,
    clock: &dyn scp_clock::Clock,
    context_id: &str,
    obligation: &mut Option<ClassSCommitToken>,
) -> EnforcementOutcome {
    match &consequence.action {
        scp_protocol::trust::consequence::ConsequenceAction::Enforcement(severity) => {
            use scp_protocol::trust::consequence::EnforcementSeverity;
            match severity {
                EnforcementSeverity::SuspendCapability { capabilities } => {
                    // A non-empty suspend GROWS `suspended_capabilities`
                    // (success ⟺ downward_auth here); an empty set does neither.
                    // The GROW method arms `obligation` on a real mutation.
                    let suspended = enforce_suspend(
                        role_state,
                        member_did,
                        capabilities,
                        obligation,
                        context_id,
                    );
                    EnforcementOutcome {
                        success: suspended,
                        downward_auth: suspended,
                    }
                }
                EnforcementSeverity::SuspendAccess => {
                    // SuspendAccess: suspend all capabilities via role_state — a
                    // `suspended_capabilities` GROW, so it is downward-auth. The
                    // GROW method arms `obligation` when it inserts a suspension.
                    role_state.suspend_all(member_did.as_ref(), obligation, context_id);
                    EnforcementOutcome {
                        success: true,
                        downward_auth: true,
                    }
                }
                EnforcementSeverity::RevokeAccess { .. }
                | EnforcementSeverity::RemoveMember { .. } => {
                    // RevokeAccess and RemoveMember should not reach the
                    // consequence dispatch path without the opt-in flag.
                    // If they do, escalate to SuspendAccess as a safe
                    // fallback.
                    tracing::error!(
                        context_id,
                        member = %member_did,
                        severity = ?severity,
                        "RevokeAccess/RemoveMember reached consequence dispatch; \
                         this should have been rejected at validation time"
                    );
                    EnforcementOutcome {
                        success: false,
                        downward_auth: false,
                    }
                }
            }
        }
        scp_protocol::trust::consequence::ConsequenceAction::AssignRole { to_role } => {
            // AssignRole → `system_assign_role` REPLACES
            // `member_capabilities[member]` with the new role's capability set
            // (roles.rs `system_assign_role`). On a DEMOTION (e.g. admin→member)
            // this is a downward-auth SHRINK of the member's effective authority
            // (`member_has_capability` = `member_capabilities` −
            // `suspended_capabilities`), so it MUST be persisted fail-closed: a
            // coalesce-window crash would restore the pre-demotion (HIGHER)
            // `member_capabilities` from the snapshot and silently re-grant the
            // removed authority. `downward_auth: true` UNCONDITIONALLY is both
            // correct and the simplest correct option — over-persisting a
            // PROMOTION is harmless: a coalesce-loss of a promotion is upward
            // (the member temporarily lacks a capability they will regain, the
            // safe direction). We deliberately do NOT diff capability sets to
            // detect demotion-vs-promotion; unconditional `true` is sound and
            // simpler. (The SHRINK-only `prune_suspensions_to_role_grants` that
            // `system_assign_role` also runs is incidental — it rolls back in
            // lockstep with the same-persist `member_capabilities` replacement.)
            EnforcementOutcome {
                success: enforce_assign_role(
                    role_state, member_did, to_role, clock, obligation, context_id,
                ),
                downward_auth: true,
            }
        }
    }
}

/// Enforces a `SuspendCapability` consequence action on a member.
///
/// Suspends typed capabilities by adding them to the member's suspended set
/// in `ContextRoleState`. The suspension-aware `member_has_capability`
/// check in the `send_message` and `deliver_incoming` gates will then
/// reject operations requiring those capabilities.
///
/// With the B1 unification, capabilities are typed [`Capability`] values
/// (no string parsing needed). The previous string-based
/// `parse_suspension_capability` round-trip is eliminated.
///
/// Returns `true` iff it actually mutated `suspended_capabilities` (a non-empty
/// `caps`); an empty `caps` is a no-op and returns `false`. This doubles as the
/// downward-auth fail-closed signal (ADR-049 §9): a mutation owes a fail-closed
/// persist, a no-op does not.
fn enforce_suspend(
    role_state: &mut ConsequenceRoleStateMut<'_>,
    member_did: &DID,
    caps: &[Capability],
    obligation: &mut Option<ClassSCommitToken>,
    context_id: &str,
) -> bool {
    if caps.is_empty() {
        return false;
    }
    role_state.suspend_capabilities(
        member_did.as_ref(),
        caps.iter().cloned(),
        obligation,
        context_id,
    );
    true
}

/// Enforces an `AssignRole` consequence action on a member.
///
/// Assigns the member to the specified role (best-effort — role may not exist).
/// Uses the injected clock (via `now` parameter) instead of `SystemClock` to
/// keep all governance timing consistent with the `ContextManager`'s clock.
///
/// Uses [`ConsequenceRoleStateMut::system_assign_role`](crate::context::actor::class_s::ConsequenceRoleStateMut::system_assign_role) which bypasses the `RoleAssign`
/// capability check — the governance engine must be able to demote members
/// regardless of which member (if any) currently holds `RoleAssign`.
fn enforce_assign_role(
    role_state: &mut ConsequenceRoleStateMut<'_>,
    member_did: &DID,
    to_role: &str,
    clock: &dyn scp_clock::Clock,
    obligation: &mut Option<ClassSCommitToken>,
    context_id: &str,
) -> bool {
    role_state
        .system_assign_role(member_did.as_ref(), to_role, clock, obligation, context_id)
        .is_ok()
}

/// H10 + H4: when enforcement fails, escalate to `SuspendAll` AND emit two
/// durable event log entries (`ConsequenceEnforcementFailed` then
/// `ConsequenceEscalatedToSuspendAll`) so an audit can reconstruct
/// (a) which action failed and (b) that escalation was applied.
async fn emit_failure_escalation(
    state: &mut ConsequenceStateSplit<'_>,
    args: &EnforceConsequencesCtx<'_>,
    consequence: &TriggeredConsequence,
    trigger_kind: &str,
    action_type: &str,
    durable: bool,
    obligation: &mut Option<ClassSCommitToken>,
) {
    let context_id = args.context_id;
    let member_did = args.member_did;
    // Recomputed from `args.context_id` (a pure SHA-256) on this RARE
    // failure-escalation path rather than threaded as a parameter — keeps the
    // signature within the `clippy::too_many_arguments` budget without bundling.
    let context_id_bytes = &context_id_to_bytes(context_id);
    tracing::warn!(
        context_id,
        member = %member_did,
        action_type,
        "consequence enforcement failed — escalating to SuspendAll"
    );

    // H10: escalate to SuspendAll when enforcement fails. The local enforcement
    // (and its cooldown skip so the escalation fires immediately) is unconditional
    // — independent of whether the trigger is convergent. The GROW method arms
    // `obligation` so the escalation's suspension is persisted fail-closed.
    state
        .role_state
        .suspend_all(member_did.as_ref(), obligation, context_id);

    // The two audit records (failure then escalation) are durable Merkle leaves
    // only for convergent triggers (ADR-051 §6); for a velocity/rate trigger
    // they are suppressed (the `ContextEvent` below still surfaces the outcome).
    if durable {
        // First the failure record, then the escalation record. Both go to
        // the durable log before the receive buffer push.
        let failed_payload = consequence_event_payload(
            member_did.as_ref(),
            consequence.rule_index,
            trigger_kind,
            action_type,
        );
        append_consequence_event(
            args.event_log,
            context_id,
            context_id_bytes,
            scp_event_log::EventType::ConsequenceEnforcementFailed,
            member_did,
            failed_payload,
            convergent_consequence_timestamp(consequence),
        )
        .await;
        *state.checkpoint_events_since += 1;
        let escalation_payload = consequence_event_payload(
            member_did.as_ref(),
            consequence.rule_index,
            trigger_kind,
            "SuspendAll",
        );
        append_consequence_event(
            args.event_log,
            context_id,
            context_id_bytes,
            scp_event_log::EventType::ConsequenceEscalatedToSuspendAll,
            member_did,
            escalation_payload,
            convergent_consequence_timestamp(consequence),
        )
        .await;
        *state.checkpoint_events_since += 1;
    }
    let event = ContextEvent::ConsequenceEnforced {
        context_id: context_id.to_owned(),
        member_did: member_did.clone(),
        action_type: "SuspendAll(escalated)".to_owned(),
        success: true,
    };
    emit_event_into(state.receive_buffer, event, context_id, args.event_tx);
}

/// Collects event history for consequence evaluation and participation
/// record computation (ADR-017), merging the durable event log with the
/// recent receive buffer.
///
/// This is the native runtime's thin adapter over the shared, convergence-
/// critical [`scp_protocol::trust::consequence::merge_consequence_events`]: it
/// acquires Source 1 (the persisted event log) from the
/// [`ContextEventLogProvider`](crate::context::builder::ContextEventLogProvider)
/// and Source 2 (the receive buffer) from `receive_buffer`, then delegates the
/// projection + buffer-gate merge so all honest members produce byte-identical
/// merged event sets (§9.9.3 equivocation detection). All constants, the
/// `EventType` projection, and the buffer-gate logic live in that shared
/// function — see it for the CONVERGENCE INVARIANT documentation.
///
/// Each persisted `scp_event_log::Event` includes `actor_did` for proper
/// attribution; event-log entries use their real timestamps while receive-
/// buffer events use estimated timestamps (spaced 1 second apart backwards from
/// `now`).
///
/// **Known limitation:** The receive buffer is capped at 1000 events
/// (`ReceiveBuffer::DEFAULT_BUFFER_CAPACITY`). Long-running contexts lose
/// older history, which means participation records and consequence evaluation
/// only reflect recent activity.
///
/// Takes a borrowed [`ReceiveBuffer`] directly so the caller may build it from
/// sub-borrows of the unified [`PerContextState`](crate::context::actor::state::PerContextState) (ADR-049 §Decision 1) without
/// holding the whole state across the merge.
///
/// Returns `(merged_events, convergent_now)` where `convergent_now` is the max
/// timestamp of the **Source-1 durable log entries**, computed BEFORE the buffer
/// merge. This is the convergent window anchor for convergent-trigger consequence
/// rules in
/// [`evaluate_consequence_rules`](scp_protocol::trust::consequence::evaluate_consequence_rules):
/// it must derive from the convergent log alone, never from the merged set
/// (which mixes in Source-2 buffer events carrying local-clock estimated
/// timestamps and would therefore be skew-dependent and unsound). An empty log
/// has no convergent-trigger evidence, so `convergent_now` falls back to `now`
/// (the window is then irrelevant: no convergent events can match it).
pub fn event_log_entries_for_consequences(
    receive_buffer: &ReceiveBuffer,
    context_id: &str,
    now: u64,
    event_log: &dyn crate::context::builder::ContextEventLogProvider,
) -> (Vec<scp_event_log::Event>, u64) {
    // Source 1: Full event log history (persisted, with real timestamps and
    // actor_did). Acquired here from the provider; an unreadable/empty log
    // yields an empty slice (the merge then reflects only Source 2).
    //
    // ADR-056: key by the canonical digest (matches the event log init in
    // `builder::create_context` and `state.context_id`), not a re-hash of the
    // hex id — `context_id_to_bytes` resolves a real 64-hex id to its digest.
    let context_id_bytes = context_id_to_bytes(context_id);
    let log_entries = match event_log.event_log_entries(&context_id_bytes) {
        Ok(Some(entries)) => entries,
        Ok(None) | Err(_) => Vec::new(),
    };

    // Convergent window anchor: max timestamp of the Source-1 durable log,
    // captured BEFORE the merge. Empty log -> `now` fallback (sound: no
    // convergent-trigger evidence exists to anchor).
    //
    // SECURITY (accepted limitation — convergent, not yet non-forgeable):
    // these Source-1 leaf timestamps are committer-assigned (`proposal.created_at`,
    // signature-bound but proposer-chosen and NOT future-bounded). Anchoring on
    // their max makes the evidence window CONVERGENT — every honest member selects
    // the identical evidence set, eliminating the prior local-clock divergence that
    // caused false-positive §9.9.3 equivocation against honest members. It does NOT,
    // on its own, stop a malicious committer/quorum from future-dating governance
    // actions in EITHER direction: (amplification) widen this window to sweep in
    // extra evidence and mint a convergent `ConsequenceTriggered` against a victim,
    // OR (suppression) push the max far ahead so `window_start` slides PAST genuine
    // older evidence, dropping an attacker's own earned warnings out of the window
    // to evade a consequence. Both share this root and the same fix.
    // That residual is admin/quorum-gated (the governance actions
    // are real, signed, and attributable) and is the open tail of the convergent-
    // wall-clock RFC: bounding committer-assigned timestamps non-forgeably (BFT
    // median-time / accountability) is deferred to that work. A local-clock ceiling
    // here would reintroduce the divergence this fix removes (the consequence
    // outcome is a convergent durable leaf, not a local application gate), so it is
    // deliberately NOT applied.
    let convergent_now = log_entries.iter().map(|e| e.timestamp).max().unwrap_or(now);

    // Source 2: the receive buffer. Delegate the convergence-critical merge
    // (projection + buffer gates) to the shared function so all honest members
    // stay byte-identical.
    let merged = scp_protocol::trust::consequence::merge_consequence_events(
        &log_entries,
        receive_buffer.event_log_entries(),
        now,
    );

    (merged, convergent_now)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod convergence_tests {
    //! Durability-discriminator proof for the consequence-leaf convergence gate
    //! (ADR-051 §6 / phase-2.md ADR-011 amendment "Consequence emission"):
    //! a velocity/rate-triggered consequence (`MessageVelocity`) emits a
    //! `ContextEvent` but mints NO durable Merkle leaf (root unchanged), while a
    //! governance-count-triggered consequence (`WarningCount`) DOES mint durable
    //! leaves (root changes). Keyed on the enum via `is_convergent_trigger`,
    //! never on a string.

    use super::{ConsequenceStateSplit, EnforceConsequencesCtx, enforce_triggered_consequences};
    use crate::context::actor::state::PerContextState;
    use crate::context::builder::ContextEventLogProvider;
    use crate::context::providers::MerkleEventLogProvider;
    use scp_clock::SystemClock;
    use scp_did::DID;
    use scp_protocol::context::membership::ContextEvent;
    use scp_protocol::trust::consequence::{
        ConsequenceAction, ConsequenceRule, ConsequenceTrigger, EnforcementSeverity,
        TriggeredConsequence,
    };
    use std::time::Duration;
    use tokio::sync::broadcast;

    const ADMIN: &str = "did:dht:z6MkAdminConverge";
    const SUBJECT: &str = "did:dht:z6MkSubjectConverge";
    const CTX_BYTES: [u8; 32] = [0x7au8; 32];

    /// Builds a rule with the given trigger and a `SuspendAccess` action
    /// (`SuspendAccess` always succeeds via `role_state.suspend_all`, so the
    /// success path — `emit_consequence_enforced_success` — is exercised; both
    /// it and the prior `emit_consequence_triggered` are durability-gated).
    fn rule(trigger: ConsequenceTrigger) -> ConsequenceRule {
        ConsequenceRule {
            trigger,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendAccess),
            threshold: 1,
            window: Duration::from_hours(1),
        }
    }

    /// Drives one already-triggered consequence through the enforcement chain
    /// against a fresh `PerContextState` + a `scp_event_log`-backed provider,
    /// returning `(merkle_root_delta_nonzero, consequence_triggered_event_seen)`.
    async fn run_one(trigger: ConsequenceTrigger) -> (bool, bool) {
        let mut state = PerContextState::new_for_test_encrypted(
            CTX_BYTES,
            1_700_000_000,
            DID(ADMIN.to_owned()),
        );
        // The subject must be a member for enforcement to run; a non-member
        // would only emit `ConsequenceTriggered` and bail.
        state
            .membership
            .add_member(DID(SUBJECT.to_owned()), "member".to_owned(), Vec::new());

        // ADR-056: the enforcement chain keys event-log storage by the
        // canonical digest of the context-id STRING — for a real 64-hex id
        // (`hex(CTX_BYTES)`) that is the DECODED digest `CTX_BYTES` itself, NOT
        // `SHA-256(hex(CTX_BYTES))`. The test provider must init/query that
        // exact digest — otherwise the durable append targets a different,
        // uninitialised context and is silently dropped.
        let context_id_str = hex::encode(CTX_BYTES);
        let storage_key = crate::context::state::context_id_to_bytes(&context_id_str);

        let event_log = MerkleEventLogProvider::new();
        event_log
            .init_event_log(&storage_key)
            .await
            .expect("init log");
        let root_before = event_log
            .event_log_merkle_root(&storage_key)
            .expect("root before");

        let (tx, mut rx) = broadcast::channel(16);
        let clock = SystemClock;
        let rules = vec![rule(trigger)];
        let triggered = vec![TriggeredConsequence {
            rule_index: 0,
            action: rules[0].action.clone(),
            evidence: Vec::new(),
        }];

        {
            let mut split = ConsequenceStateSplit::from_state(&mut state);
            // The `rule()` helper's action is `SuspendAccess`, which always
            // mutates `suspended_capabilities` for a present member, so the
            // downward-auth obligation sink must be ARMED (ADR-049 §9).
            let mut obligation = None;
            let suspended = enforce_triggered_consequences(
                &mut split,
                &EnforceConsequencesCtx {
                    context_id: &context_id_str,
                    member_did: &DID(SUBJECT.to_owned()),
                    now: 1_700_000_100,
                    triggered: &triggered,
                    rules: &rules,
                    clock: &clock,
                    event_log: &event_log,
                    event_tx: Some(&tx),
                },
                &mut obligation,
            )
            .await;
            assert!(
                suspended,
                "SuspendAccess against a present member applies a suspension"
            );
            let token =
                obligation.expect("a SuspendAccess GROW arms the fail-closed obligation sink");
            // No persistence backend is wired in this convergence-discriminator
            // test, so defuse the obligation instead of driving a real persist.
            token.defuse_for_test();
        }

        let root_after = event_log
            .event_log_merkle_root(&storage_key)
            .expect("root after");

        // A `ConsequenceTriggered` ContextEvent must always be surfaced,
        // regardless of durability.
        let mut saw_triggered = false;
        while let Ok((_ctx, event)) = rx.try_recv() {
            if matches!(event, ContextEvent::ConsequenceTriggered { .. }) {
                saw_triggered = true;
            }
        }

        (root_before != root_after, saw_triggered)
    }

    #[tokio::test]
    async fn velocity_triggered_consequence_adds_no_durable_leaf() {
        let (root_changed, saw_triggered) = run_one(ConsequenceTrigger::MessageVelocity).await;
        assert!(
            !root_changed,
            "a MessageVelocity-triggered consequence is non-convergent (ADR-051 §6) \
             and MUST NOT mint a durable Merkle leaf — the root must be unchanged"
        );
        assert!(
            saw_triggered,
            "a non-durable consequence MUST still surface a ConsequenceTriggered \
             ContextEvent (local enforcement is unchanged)"
        );
    }

    #[tokio::test]
    async fn warning_count_triggered_consequence_adds_durable_leaf() {
        let (root_changed, saw_triggered) = run_one(ConsequenceTrigger::WarningCount).await;
        assert!(
            root_changed,
            "a WarningCount-triggered consequence is convergent (ADR-051 §6) and \
             MUST mint durable Merkle leaves — the root must change"
        );
        assert!(
            saw_triggered,
            "a durable consequence also surfaces its ConsequenceTriggered ContextEvent"
        );
    }

    #[tokio::test]
    async fn outlet_rate_triggered_consequence_adds_no_durable_leaf() {
        // The second non-convergent trigger — same posture as MessageVelocity.
        let (root_changed, _) = run_one(ConsequenceTrigger::OutletRateExceeded).await;
        assert!(
            !root_changed,
            "a OutletRateExceeded-triggered consequence is non-convergent (ADR-051 §6) \
             and MUST NOT mint a durable Merkle leaf"
        );
    }

    #[tokio::test]
    async fn custom_triggered_consequence_adds_durable_leaf() {
        // The second convergent trigger — same posture as WarningCount.
        let (root_changed, _) = run_one(ConsequenceTrigger::Custom("abuse".to_owned())).await;
        assert!(
            root_changed,
            "a Custom-triggered consequence is convergent (ADR-051 §6) and MUST \
             mint durable Merkle leaves"
        );
    }

    // -- EL01: convergent-source soundness for consequence evaluation ----------

    use super::event_log_entries_for_consequences;
    use scp_event_log::EventType;
    use scp_protocol::context::membership::ReceiveBuffer;

    /// Builds a [`MerkleEventLogProvider`] seeded with the SAME convergent
    /// durable history every honest member observes: one `GovernanceAction`
    /// targeting `SUBJECT` (the `WarningCount` bucket). This is the only
    /// source from which convergent governance/consequence events may be drawn.
    async fn convergent_log() -> (MerkleEventLogProvider, String) {
        let context_id_str = hex::encode(CTX_BYTES);
        let storage_key = crate::context::state::context_id_to_bytes(&context_id_str);
        let log = MerkleEventLogProvider::new();
        log.init_event_log(&storage_key).await.expect("init log");
        log.append_context_event_with_payload(
            &storage_key,
            EventType::GovernanceAction,
            ADMIN,
            scp_event_log::EventPayload {
                data: serde_json::to_vec(&serde_json::json!({ "target_did": SUBJECT }))
                    .expect("encode target payload"),
            },
            1_700_000_000,
        )
        .await
        .expect("append governance action");
        (log, context_id_str)
    }

    /// A member-local receive buffer carrying `message_count` per-author
    /// `MessageSent` events PLUS one `GovernanceActionExecuted` `ContextEvent`
    /// (the convergent event that is ALSO mirrored into the durable log).
    /// Differing `message_count` simulates members with different local
    /// activity / buffer lengths.
    fn buffer_with_local_activity(message_count: usize) -> ReceiveBuffer {
        let mut buffer = ReceiveBuffer::new();
        for seq in 0..message_count {
            buffer.push(ContextEvent::MessageSent {
                sender_did: DID(SUBJECT.to_owned()),
                sequence_number: seq as u64,
                payload: Vec::new(),
            });
        }
        // The same convergent governance event each honest member buffers
        // locally after it is durably logged. Before the EL01 fix this was
        // re-projected from the buffer and double-counted depending on
        // buffer length; after the fix it is ignored here (Source 1 only).
        buffer.push(ContextEvent::GovernanceActionExecuted {
            proposal_id: [0x11u8; 32],
            action_summary: "SuspendMember".to_owned(),
            executor_did: DID(ADMIN.to_owned()),
            resulting_epoch: Some(1),
            target_did: Some(DID(SUBJECT.to_owned())),
        });
        buffer
    }

    /// Counts the `GovernanceAction`-bucket events (the bucket `WarningCount` /
    /// `Custom` triggers match) in the merged consequence-evaluation event list.
    async fn governance_bucket_count(buffer: &ReceiveBuffer) -> usize {
        let (log, ctx) = convergent_log().await;
        let (merged, _convergent_now) =
            event_log_entries_for_consequences(buffer, &ctx, 1_700_000_100, &log);
        merged
            .iter()
            .filter(|e| e.event_type == EventType::GovernanceAction)
            .count()
    }

    /// EL01 regression pin: two honest members with the SAME durable
    /// governance history but DIFFERENT receive-buffer lengths MUST compute the
    /// SAME governance-bucket count from `event_log_entries_for_consequences`,
    /// so a `WarningCount` / `Custom` consequence fires (or not) identically and
    /// mints the SAME durable `ConsequenceTriggered` leaf — preserving the
    /// §9.9.3 convergence guarantee. Before the fix, the buffer's
    /// `GovernanceActionExecuted` projection was double-counted on the quiet
    /// member and skipped on the busy one (dedup keyed on member-local
    /// `buffer_len`), diverging the count and the durable leaf.
    #[tokio::test]
    async fn convergent_governance_count_is_independent_of_buffer_length() {
        // Member A: quiet (2 local messages). Member B: busy (50 local messages).
        let quiet = governance_bucket_count(&buffer_with_local_activity(2)).await;
        let busy = governance_bucket_count(&buffer_with_local_activity(50)).await;

        assert_eq!(
            quiet, busy,
            "EL01: governance-bucket count for consequence evaluation MUST be \
             identical across members regardless of receive-buffer length — a \
             convergent event must be sourced only from the durable log, never \
             re-projected from the per-member buffer (§9.9.3; ADR-051 §6)"
        );

        // Non-vacuity: the durable log holds exactly ONE GovernanceAction, so
        // the convergent count MUST be exactly 1 — the buffer's
        // GovernanceActionExecuted ContextEvent contributes nothing. If the
        // convergent buffer arm were re-introduced, the busy member would count
        // 2 (durable + buffer) and the quiet member's dedup would differ,
        // breaking the equality above.
        assert_eq!(
            quiet, 1,
            "EL01: exactly the single durable GovernanceAction must be counted; \
             the per-member buffer must contribute zero convergent events"
        );
    }

    /// Pins that the per-author `MessageSent` events DO flow from the buffer
    /// (the velocity/rate path must keep working), so the EL01 fix narrowed the
    /// buffer projection without disabling it. Uses an EMPTY durable log so the
    /// `last_log_ts > 0` dedup gate is bypassed and the buffer source is
    /// isolated (the durable provider stamps appends with the real system
    /// clock, which would otherwise dedup all buffer events against it).
    #[tokio::test]
    async fn per_author_messages_still_flow_from_buffer() {
        let context_id_str = hex::encode(CTX_BYTES);
        let storage_key = crate::context::state::context_id_to_bytes(&context_id_str);
        let log = MerkleEventLogProvider::new();
        log.init_event_log(&storage_key).await.expect("init log");

        let buffer = buffer_with_local_activity(3);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let (merged, _convergent_now) =
            event_log_entries_for_consequences(&buffer, &context_id_str, now, &log);
        let message_count = merged
            .iter()
            .filter(|e| e.event_type == EventType::MessageSent)
            .count();
        assert!(
            message_count > 0,
            "MessageSent is per-author and excluded from the durable log, so the \
             receive buffer MUST remain its source for velocity/rate evaluation"
        );
        // And no convergent governance event leaked from the buffer (the
        // durable log is empty, so the count must be zero).
        let gov_count = merged
            .iter()
            .filter(|e| e.event_type == EventType::GovernanceAction)
            .count();
        assert_eq!(
            gov_count, 0,
            "EL01: the buffer's GovernanceActionExecuted must NOT be projected \
             into the consequence event list (convergent events come only from \
             the durable log)"
        );
    }
}
