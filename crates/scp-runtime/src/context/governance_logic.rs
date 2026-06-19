//! Governance proposal, vote, execute, and dispatch operations —
//! free-function logic hoisted out of the deleted `manager/` directory
//! in ADR-049 commit 12.

use scp_identity::DID;
use scp_protocol::context::membership::{ContextEvent, MembershipState, ReceiveBuffer};
use scp_protocol::context::params::Capability;
use scp_protocol::context::roles;
use scp_protocol::context::roles::ContextRoleState;
use scp_protocol::trust::consequence::{ConsequenceRule, TriggeredConsequence};

use super::state::{GovernanceState, PerContextState, context_id_to_bytes, emit_event_into};

// ---------------------------------------------------------------------------
// RuntimeConsequenceDispatcher — bridges PerContextState to the shared trait
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
pub(super) const CONSEQUENCE_ACTOR_DID: &str = "system";

/// Formats a [`ConsequenceTrigger`] into the canonical wire-stable string
/// used both in `ContextEvent::ConsequenceTriggered.trigger_type` and in the
/// structured durable event log payload (H4, PR #1606).
///
/// The format is intentionally simple and forward-compatible:
/// `MessageVelocity`, `ToolRateExceeded`, `WarningCount`, or `Custom:<key>`.
/// Downstream rules and audit consumers parse on the `Custom:` prefix.
fn trigger_kind_str(trigger: &scp_protocol::trust::consequence::ConsequenceTrigger) -> String {
    use scp_protocol::trust::consequence::ConsequenceTrigger;
    match trigger {
        ConsequenceTrigger::MessageVelocity => "MessageVelocity".to_owned(),
        ConsequenceTrigger::ToolRateExceeded => "ToolRateExceeded".to_owned(),
        ConsequenceTrigger::WarningCount => "WarningCount".to_owned(),
        ConsequenceTrigger::Custom(key) => format!("Custom:{key}"),
    }
}

/// Builds the structured JSON payload for a `ConsequenceTriggered` /
/// `ConsequenceEnforced` / `ConsequenceEnforcementFailed` /
/// `ConsequenceEscalatedToSuspendAll` durable event log entry (H4, PR #1606).
///
/// The shape matches the H4 spec:
/// ```json
/// {
///   "target_did": "did:key:alice",
///   "rule_index": 3,
///   "trigger_kind": "MessageVelocity" | "WarningCount" | "Custom:..."
///                   | "ToolRateExceeded",
///   "action_type": "SuspendCapability" | "SuspendAccess" | "SuspendAll"
///                  | "RevokeAccess" | "RemoveMember" | "AssignRole"
/// }
/// ```
///
/// `target_did` mirrors the `payload_target_is` convention used by the
/// `WarningCount` trigger so subsequent rule evaluation can match these
/// entries against the affected member, closing the recursive blind spot
/// from the white-hat review.
fn consequence_event_payload(
    target_did: &DID,
    rule_index: usize,
    trigger_kind: &str,
    action_type: &str,
) -> serde_json::Value {
    serde_json::json!({
        "target_did": target_did.as_ref(),
        "rule_index": rule_index,
        "trigger_kind": trigger_kind,
        "action_type": action_type,
    })
}

/// Best-effort durable append of one consequence event log entry. A failed
/// append is logged via `tracing::warn!` but never blocks the matching
/// `receive_buffer.push(...)` call — the receive buffer remains a useful
/// in-session signal even when the durable log is unavailable. Returns
/// nothing because the failure mode is observed via tracing, not callers.
fn append_consequence_event(
    event_log: &dyn crate::context::builder::ContextEventLogProvider,
    context_id: &str,
    context_id_bytes: &[u8; 32],
    event_type: scp_event_log::EventType,
    member_did: &DID,
    payload: &serde_json::Value,
) {
    // Consequence-enforcement records keep a JSON-object payload (rule_index,
    // trigger_kind, action_type, target_did) because the consequence engine
    // reads target_did out of it via `payload_target_is`, which decodes both
    // JSON objects and the typed positional structs. Wrap the JSON bytes in an
    // EventPayload for the typed event-log substrate.
    let payload = scp_event_log::EventPayload {
        data: serde_json::to_vec(payload).unwrap_or_default(),
    };
    if let Err(e) = event_log.append_context_event_with_payload(
        context_id_bytes,
        event_type,
        CONSEQUENCE_ACTOR_DID,
        payload,
    ) {
        tracing::warn!(
            context_id,
            member = %member_did,
            event = ?event_type,
            error = %e,
            "failed to append consequence event to durable event log"
        );
    }
}

/// Field-disjoint mutable borrows of the per-context state needed by
/// the consequence-enforcement chain.
///
/// Both [`super::state::PerContextState`] (legacy) and
/// [`crate::context::actor::state::PerContextState`] (actor) implement
/// the same `governance: GovernanceState`, `role_state: ContextRoleState`,
/// `membership: MembershipState`, `receive_buffer: ReceiveBuffer`, and
/// `checkpoint_events_since: u64` fields with identical types. Splitting
/// the borrows here lets the enforcement helpers stay generic over the
/// parent state struct while preserving Rust's ability to disjointly
/// borrow each subfield (a single trait method returning `&mut Self`
/// would block the multiple mutable borrows the body actually needs).
///
/// ADR-049 Phase 2A.7 — added so the actor-shape `messaging_helpers`
/// can drive the same enforcement pipeline as the legacy
/// `&Supervisor`-shape `messaging_helpers_legacy` without duplicating
/// the ~300 lines of consequence dispatch + escalation logic.
pub struct ConsequenceStateSplit<'a> {
    pub governance: &'a mut GovernanceState,
    pub role_state: &'a mut ContextRoleState,
    pub membership: &'a MembershipState,
    pub receive_buffer: &'a mut ReceiveBuffer,
    pub checkpoint_events_since: &'a mut u64,
}

impl<'a> ConsequenceStateSplit<'a> {
    /// Build a split-borrow from the unified [`PerContextState`]
    /// (ADR-049 §Decision 1 — single `PerContextState`).
    pub const fn from_state(ctx: &'a mut PerContextState) -> Self {
        Self {
            governance: &mut ctx.governance,
            role_state: &mut ctx.role_state,
            membership: &ctx.membership,
            receive_buffer: &mut ctx.receive_buffer,
            checkpoint_events_since: &mut ctx.checkpoint_events_since,
        }
    }
}

/// Borrowed inputs for `enforce_triggered_consequences`. Bundling the
/// providers, scope identifiers, and pre-evaluated rule data into one
/// struct keeps the public function signature within the
/// `clippy::too_many_arguments` budget while preserving the explicit
/// names that callers (`messaging.rs`, `tools.rs`, `governance.rs`,
/// the periodic timer) need at construction time.
pub struct EnforceConsequencesCtx<'a> {
    pub context_id: &'a str,
    pub member_did: &'a DID,
    pub now: u64,
    pub triggered: &'a [TriggeredConsequence],
    pub rules: &'a [ConsequenceRule],
    pub clock: &'a dyn scp_primitives::Clock,
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
/// Separated from [`dispatch_consequences`] so callers that need
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
/// `MessageVelocity` / `ToolRateExceeded` are non-convergent (a rate needs a
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
pub fn enforce_triggered_consequences(
    state: &mut ConsequenceStateSplit<'_>,
    args: &EnforceConsequencesCtx<'_>,
) {
    let context_id_bytes = context_id_to_bytes(args.context_id);
    for consequence in args.triggered {
        process_one_triggered_consequence(state, args, &context_id_bytes, consequence);
    }
}

/// Single-consequence body of [`enforce_triggered_consequences`].
/// Extracted so the public function stays under `clippy::too_many_lines`.
fn process_one_triggered_consequence(
    state: &mut ConsequenceStateSplit<'_>,
    args: &EnforceConsequencesCtx<'_>,
    context_id_bytes: &[u8; 32],
    consequence: &TriggeredConsequence,
) {
    let member_did = args.member_did;
    let now = args.now;

    // Cooldown tracking: skip if this rule fired within its window.
    if let Some(&last_fired) = state.governance.cooldown_until.get(&consequence.rule_index)
        && now < last_fired
    {
        return;
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
        return;
    }

    let action_type = consequence_action_type(&consequence.action);
    let rule = args.rules.get(consequence.rule_index);
    let trigger_kind = rule.map_or_else(|| "Unknown".to_owned(), |r| trigger_kind_str(&r.trigger));

    // Durability gate (ADR-051 §6 / phase-2.md ADR-011 amendment "Consequence
    // emission"): a consequence leaf is a durable Merkle entry ONLY when its
    // trigger input is convergent — `WarningCount` / `Custom` (governance
    // counts), keyed on the enum via `is_convergent_trigger`, never on a string.
    // `MessageVelocity` / `ToolRateExceeded` are non-convergent (a rate needs a
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
    );

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
        );
        return;
    }

    let success = dispatch_enforcement_action(
        state.role_state,
        member_did,
        consequence,
        args.clock,
        args.context_id,
    );

    if !success {
        emit_failure_escalation(
            state,
            args,
            context_id_bytes,
            consequence,
            &trigger_kind,
            action_type,
            durable,
        );
        return; // skip cooldown recording — failed action doesn't count
    }

    // Record cooldown: prevent re-firing within the rule's window.
    if let Some(rule) = args.rules.get(consequence.rule_index) {
        state.governance.cooldown_until.insert(
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
    );
}

/// Resolves the `action_type` string label for a [`TriggeredConsequence`].
const fn consequence_action_type(
    action: &scp_protocol::trust::consequence::ConsequenceAction,
) -> &'static str {
    match action {
        scp_protocol::trust::consequence::ConsequenceAction::Enforcement(sev) => sev.variant_name(),
        scp_protocol::trust::consequence::ConsequenceAction::AssignRole { .. } => "AssignRole",
    }
}

/// Emits a `ConsequenceTriggered` event. When `durable`, appends the durable
/// Merkle leaf (and bumps `checkpoint_events_since`) BEFORE the matching
/// receive-buffer push (H4 ordering invariant); when `!durable` (a
/// velocity/rate-triggered, non-convergent consequence — ADR-051 §6), the
/// durable leaf and counter bump are suppressed and only the `ContextEvent` is
/// surfaced.
fn emit_consequence_triggered(
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
            args.member_did,
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
            &payload,
        );
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
fn emit_absent_member_enforcement_failed(
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
            args.member_did,
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
            &payload,
        );
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
fn emit_consequence_enforced_success(
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
            args.member_did,
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
            &payload,
        );
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

/// Per-arm enforcement dispatch. Each match arm calls a named function as
/// an `expression_statement` so the pipeline wiring gates can detect the
/// `call_expression` per-variant.
fn dispatch_enforcement_action(
    role_state: &mut ContextRoleState,
    member_did: &DID,
    consequence: &TriggeredConsequence,
    clock: &dyn scp_primitives::Clock,
    context_id: &str,
) -> bool {
    match &consequence.action {
        scp_protocol::trust::consequence::ConsequenceAction::Enforcement(severity) => {
            use scp_protocol::trust::consequence::EnforcementSeverity;
            match severity {
                EnforcementSeverity::SuspendCapability { capabilities } => {
                    enforce_suspend(role_state, member_did, capabilities)
                }
                EnforcementSeverity::SuspendAccess => {
                    // SuspendAccess: suspend all capabilities via role_state.
                    role_state.suspend_all(member_did.as_ref());
                    true
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
                    false
                }
            }
        }
        scp_protocol::trust::consequence::ConsequenceAction::AssignRole { to_role } => {
            enforce_assign_role(role_state, member_did, to_role, clock)
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
fn enforce_suspend(
    role_state: &mut ContextRoleState,
    member_did: &DID,
    caps: &[Capability],
) -> bool {
    if caps.is_empty() {
        return false;
    }
    role_state.suspend_capabilities(member_did.as_ref(), caps.iter().cloned());
    true
}

/// Enforces an `AssignRole` consequence action on a member.
///
/// Assigns the member to the specified role (best-effort — role may not exist).
/// Uses the injected clock (via `now` parameter) instead of `SystemClock` to
/// keep all governance timing consistent with the `ContextManager`'s clock.
///
/// Uses [`roles::system_assign_role`] which bypasses the `RoleAssign`
/// capability check — the governance engine must be able to demote members
/// regardless of which member (if any) currently holds `RoleAssign`.
fn enforce_assign_role(
    role_state: &mut ContextRoleState,
    member_did: &DID,
    to_role: &str,
    clock: &dyn scp_primitives::Clock,
) -> bool {
    roles::system_assign_role(role_state, member_did, to_role, clock).is_ok()
}

/// H10 + H4: when enforcement fails, escalate to `SuspendAll` AND emit two
/// durable event log entries (`ConsequenceEnforcementFailed` then
/// `ConsequenceEscalatedToSuspendAll`) so an audit can reconstruct
/// (a) which action failed and (b) that escalation was applied.
fn emit_failure_escalation(
    state: &mut ConsequenceStateSplit<'_>,
    args: &EnforceConsequencesCtx<'_>,
    context_id_bytes: &[u8; 32],
    consequence: &TriggeredConsequence,
    trigger_kind: &str,
    action_type: &str,
    durable: bool,
) {
    let context_id = args.context_id;
    let member_did = args.member_did;
    tracing::warn!(
        context_id,
        member = %member_did,
        action_type,
        "consequence enforcement failed — escalating to SuspendAll"
    );

    // H10: escalate to SuspendAll when enforcement fails. The local enforcement
    // (and its cooldown skip so the escalation fires immediately) is unconditional
    // — independent of whether the trigger is convergent.
    state.role_state.suspend_all(member_did.as_ref());

    // The two audit records (failure then escalation) are durable Merkle leaves
    // only for convergent triggers (ADR-051 §6); for a velocity/rate trigger
    // they are suppressed (the `ContextEvent` below still surfaces the outcome).
    if durable {
        // First the failure record, then the escalation record. Both go to
        // the durable log before the receive buffer push.
        let failed_payload = consequence_event_payload(
            member_did,
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
            &failed_payload,
        );
        *state.checkpoint_events_since += 1;
        let escalation_payload = consequence_event_payload(
            member_did,
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
            &escalation_payload,
        );
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

/// Serializes an optional target DID into JSON payload bytes for event log
/// consumption by consequence triggers and participation records.
fn target_did_to_payload(did: Option<&DID>) -> Vec<u8> {
    did.map(|d| {
        serde_json::to_vec(&serde_json::json!({"target_did": d.as_ref()})).unwrap_or_default()
    })
    .unwrap_or_default()
}

/// Maximum age (in seconds) for receive-buffer events used in consequence
/// evaluation. Events estimated to be older than this are discarded as
/// stale, preventing manipulation via timestamp back-dating.
const MAX_BUFFER_EVENT_AGE_SECS: u64 = 3600; // 1 hour

/// Maximum clock skew tolerance (in seconds) for buffer event timestamps.
/// Events with estimated timestamps more than this far in the future are
/// discarded.
const MAX_FUTURE_TOLERANCE_SECS: u64 = 5;

/// Maximum number of receive-buffer events consumed per consequence evaluation
/// cycle. Caps the cost of evaluation and prevents an attacker from flooding
/// the buffer to drive synthetic high event counts (e.g. inflating a
/// `WarningCount` trigger by queuing thousands of messages before governance
/// runs). Events beyond this cap are simply not fed into the evaluator;
/// the persisted event log (Source 1) covers all durable history.
const MAX_BUFFER_EVENTS_FOR_EVAL: usize = 100;

/// Collects event history for consequence evaluation and participation
/// record computation (ADR-017), merging the durable event log with the
/// recent receive buffer.
///
/// Combines two sources:
/// 1. **Event log history** — full persisted history from the
///    `ContextEventLogProvider`. Each `scp_event_log::Event` includes
///    `actor_did`, enabling proper attribution.
/// 2. **Receive buffer events** — recent in-memory events that may not
///    yet be in the event log (the event log is appended after the
///    operation, but the receive buffer is updated inside the lock).
///
/// Events from the event log use their real timestamps. Receive buffer
/// events use estimated timestamps (spaced 1 second apart backwards from
/// `now`). The merge deduplicates by preferring event log entries (which
/// have accurate timestamps and hashes) over buffer estimates.
///
/// Each persisted `scp_event_log::Event` carries a typed `EventType` from the
/// closed taxonomy. This function projects those variants onto the coarse
/// trigger buckets `matches_trigger` understands (governance/consequence
/// variants collapse to `EventType::GovernanceAction`; operational variants
/// map to their velocity buckets) and passes the canonical payload bytes
/// through unchanged. Recent receive-buffer events are merged in on top.
///
/// **Known limitation:** The receive buffer is capped at 1000 events
/// (`ReceiveBuffer::DEFAULT_BUFFER_CAPACITY`). Long-running contexts lose
/// older history, which means participation records and consequence evaluation
/// only reflect recent activity.
///
/// Takes a borrowed [`ReceiveBuffer`] directly so the caller may build it from
/// sub-borrows of the unified [`PerContextState`] (ADR-049 §Decision 1) without
/// holding the whole state across the merge.
#[allow(clippy::too_many_lines)]
pub fn event_log_entries_for_consequences(
    receive_buffer: &ReceiveBuffer,
    context_id: &str,
    now: u64,
    event_log: &dyn crate::context::builder::ContextEventLogProvider,
) -> Vec<scp_event_log::Event> {
    let mut events = Vec::new();

    // Source 1: Full event log history (persisted, with real timestamps and actor_did).
    let context_id_bytes = scp_protocol::context::context_id_bytes(context_id);
    if let Ok(Some(entries)) = event_log.event_log_entries(&context_id_bytes) {
        for (seq, entry) in entries.iter().enumerate() {
            use scp_event_log::EventType;
            // Project the entry's typed `EventType` onto the coarse trigger
            // buckets that `matches_trigger` understands. The event log now
            // stores the real closed-taxonomy variant, so we map governance
            // and consequence-enforcement variants down to
            // `EventType::GovernanceAction` (the bucket the `WarningCount` /
            // `Custom` triggers match), and operational variants to their
            // velocity buckets. Mapping consequence events into the
            // governance bucket closes the recursive blind spot from the
            // white-hat review (H4): subsequent rule evaluation can see prior
            // consequence enforcement, enabling rules like "if member has
            // been auto-suspended N times, demote".
            let event_type = match entry.event_type {
                // DORMANT: per ADR-051 §6 / the phase-2.md ADR-011 amendment
                // exclusion taxonomy §2, `MessageSent` / `ToolInvoked` are
                // per-author, non-convergent events no longer appended to the
                // durable log — Source 1 will not yield them in the interim.
                // Velocity / tool-rate evaluation continues to read them from
                // the receive buffer (Source 2, below), which is correct and
                // intended (local, per-receiver flow control needs no
                // convergence). These arms re-activate when ADR-051 §2's causal
                // DAG re-enters application events into the canonical log.
                EventType::MessageSent => EventType::MessageSent,
                EventType::MemberJoined => EventType::MemberJoined,
                EventType::MemberLeft => EventType::MemberLeft,
                EventType::RoleAssigned => EventType::RoleAssigned,
                EventType::ToolRegistered | EventType::ToolRemoved | EventType::ToolInvoked => {
                    EventType::ToolInvoked
                }
                EventType::GovernanceAction
                | EventType::GovernanceProposalCreated
                | EventType::GovernanceVoteCast
                | EventType::GovernanceVoteWithdrawn
                | EventType::GovernanceProposalResolved
                | EventType::GovernanceDeadlockRecovery
                | EventType::GovernanceConflictDetected
                | EventType::GovernanceConflictResolved
                | EventType::GovernanceActionExecuted
                | EventType::AccessRevoked
                | EventType::ConsequenceTriggered
                | EventType::ConsequenceEnforced
                | EventType::ConsequenceEnforcementFailed
                | EventType::ConsequenceEscalatedToSuspendAll => EventType::GovernanceAction,
                _ => continue, // Skip event types not relevant to consequence evaluation
            };
            // The event already carries its canonical payload bytes (typed
            // positional MessagePack for promoted variants, JSON for the
            // remaining untyped ones). `payload_target_is` / `payload_starts_with`
            // decode both encodings, so pass the bytes through unchanged.
            events.push(scp_event_log::Event {
                event_type,
                actor_did: entry.actor_did.clone(),
                timestamp: entry.timestamp,
                sequence: seq as u64,
                payload: entry.payload.clone(),
                prev_hash: [0u8; 32],
                signature: Vec::new(),
            });
        }
    }

    // Source 2: Receive buffer events (recent, may not be in event log yet).
    // Only add buffer events that are not already covered by the event log.
    // We use a simple heuristic: if the event log already has events, we
    // only add buffer events whose estimated timestamp is newer than the
    // last event log entry.
    let last_log_ts = events.last().map_or(0, |e| e.timestamp);
    let all_buffer_events = receive_buffer.event_log_entries();
    let buffer_len = all_buffer_events.len() as u64;
    let next_seq = events.len() as u64;

    // Track how many buffer-derived events we've accepted so far. Once
    // MAX_BUFFER_EVENTS_FOR_EVAL is reached, stop adding more.
    // This cap prevents an attacker from flooding the buffer to inflate
    // synthetic event counts (e.g. triggering a `WarningCount` consequence
    // prematurely). The persisted event log (Source 1) covers all durable
    // history; the buffer is only a short-term supplement.
    let mut buffer_events_accepted: usize = 0;

    for (idx, ctx_event) in all_buffer_events.iter().enumerate() {
        let (event_type, actor_did, payload_data) = match ctx_event {
            ContextEvent::MessageSent { sender_did, .. }
            | ContextEvent::MessageReceived { sender_did, .. } => (
                scp_event_log::EventType::MessageSent,
                sender_did.clone(),
                Vec::new(),
            ),
            ContextEvent::MemberJoined { member_did, .. } => (
                scp_event_log::EventType::MemberJoined,
                member_did.clone(),
                Vec::new(),
            ),
            ContextEvent::MemberLeft { member_did } => (
                scp_event_log::EventType::MemberLeft,
                member_did.clone(),
                Vec::new(),
            ),
            ContextEvent::GovernanceActionExecuted {
                executor_did,
                target_did,
                ..
            } => (
                scp_event_log::EventType::GovernanceAction,
                executor_did.clone(),
                target_did_to_payload(target_did.as_ref()),
            ),
            _ => continue,
        };
        // Oldest event gets `now - (buffer_len - 1)`, newest gets `now`.
        let estimated_ts =
            now.saturating_sub(buffer_len.saturating_sub(1).saturating_sub(idx as u64));

        // Skip buffer events that are likely already covered by the event log.
        if estimated_ts <= last_log_ts && last_log_ts > 0 {
            continue;
        }

        // Defense in depth: reject buffer events with estimated timestamps too far
        // in the future. Currently the estimation formula guarantees
        // estimated_ts <= now, so this never triggers — but it guards against
        // future changes to the formula.
        if estimated_ts > now.saturating_add(MAX_FUTURE_TOLERANCE_SECS) {
            continue;
        }

        // Reject buffer events with timestamps too far in the past (M18).
        if now.saturating_sub(estimated_ts) > MAX_BUFFER_EVENT_AGE_SECS {
            continue;
        }

        // M-R cap: stop once we've accepted MAX_BUFFER_EVENTS_FOR_EVAL events
        // from the buffer. Additional events are not fed to the evaluator.
        if buffer_events_accepted >= MAX_BUFFER_EVENTS_FOR_EVAL {
            break;
        }
        buffer_events_accepted += 1;

        events.push(scp_event_log::Event {
            event_type,
            actor_did,
            timestamp: estimated_ts,
            sequence: next_seq + idx as u64,
            payload: scp_event_log::EventPayload { data: payload_data },
            prev_hash: [0u8; 32],
            signature: Vec::new(),
        });
    }
    events
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
    use scp_identity::DID;
    use scp_primitives::SystemClock;
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
    fn run_one(trigger: ConsequenceTrigger) -> (bool, bool) {
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

        // The enforcement chain keys event-log storage by
        // `context_id_bytes(context_id_str)` (a SHA-256 of the hex string, NOT
        // the raw 32-byte id), so the test provider must init/query that exact
        // derived key — otherwise the durable append targets a different,
        // uninitialised context and is silently dropped.
        let context_id_str = hex::encode(CTX_BYTES);
        let storage_key = scp_protocol::context::context_id_bytes(&context_id_str);

        let event_log = MerkleEventLogProvider::new();
        event_log.init_event_log(&storage_key).expect("init log");
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
            enforce_triggered_consequences(
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
            );
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

    #[test]
    fn velocity_triggered_consequence_adds_no_durable_leaf() {
        let (root_changed, saw_triggered) = run_one(ConsequenceTrigger::MessageVelocity);
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

    #[test]
    fn warning_count_triggered_consequence_adds_durable_leaf() {
        let (root_changed, saw_triggered) = run_one(ConsequenceTrigger::WarningCount);
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

    #[test]
    fn tool_rate_triggered_consequence_adds_no_durable_leaf() {
        // The second non-convergent trigger — same posture as MessageVelocity.
        let (root_changed, _) = run_one(ConsequenceTrigger::ToolRateExceeded);
        assert!(
            !root_changed,
            "a ToolRateExceeded-triggered consequence is non-convergent (ADR-051 §6) \
             and MUST NOT mint a durable Merkle leaf"
        );
    }

    #[test]
    fn custom_triggered_consequence_adds_durable_leaf() {
        // The second convergent trigger — same posture as WarningCount.
        let (root_changed, _) = run_one(ConsequenceTrigger::Custom("abuse".to_owned()));
        assert!(
            root_changed,
            "a Custom-triggered consequence is convergent (ADR-051 §6) and MUST \
             mint durable Merkle leaves"
        );
    }
}
