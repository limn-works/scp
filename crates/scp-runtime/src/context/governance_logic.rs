//! Governance proposal, vote, execute, and dispatch operations —
//! free-function logic hoisted out of the deleted `manager/` directory
//! in ADR-049 commit 12.

use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::governance::GovernanceAction;
use scp_protocol::context::membership::{ContextEvent, MembershipState, ReceiveBuffer};
use scp_protocol::context::params::{Capability, GovernanceModel};
use scp_protocol::context::roles;
use scp_protocol::context::roles::ContextRoleState;
use scp_protocol::trust::consequence::{
    ConsequenceRule, TriggeredConsequence, evaluate_consequence_rules,
};

use super::state::{GovernanceState, PerContextState, context_id_to_bytes, emit_event_into};

// ---------------------------------------------------------------------------
// RuntimeConsequenceDispatcher — bridges PerContextState to the shared trait
// ---------------------------------------------------------------------------
//
// The `CommitRetryOutcome` / `CommitRetryOutcomeKind` types that previously
// lived here for a legacy forwarder are gone — the active definitions are in
// `governance_helpers.rs` (the `process_pending_commits` retry pipeline).
// Removed in the post-review-round-1 phase 1 fix-up of ADR-049.

/// Evaluates consequence rules against a member and dispatches enforcement
/// actions (capability suspension, access revocation, role demotion).
///
/// Emits `ConsequenceTriggered` and `ConsequenceEnforced` events to the
/// receive buffer for SDK observability (ADR-017, #1531).
///
/// This is a convenience entry point that evaluates rules and enforces the
/// results. For callers that need the evaluate step visible in their own
/// file (pipeline wiring gates), use [`evaluate_consequence_rules`] +
/// [`enforce_triggered_consequences`] directly.
///
/// Time-based consequences (rules that should trigger after a duration of
/// inactivity) are also evaluated by the governance timeout task's periodic
/// tick (Phase 4 in [`start_governance_timeout_task`](ContextManager::start_governance_timeout_task)),
/// so they fire even when no user action occurs (#1531).
pub fn dispatch_consequences(
    ctx: &mut PerContextState,
    context_id: &str,
    member_did: &DID,
    now: u64,
    clock: &dyn scp_primitives::Clock,
    event_log: &dyn crate::context::builder::ContextEventLogProvider,
    event_tx: Option<
        &tokio::sync::broadcast::Sender<(String, scp_protocol::context::membership::ContextEvent)>,
    >,
) {
    if ctx.governance.consequence_rules.is_empty() {
        return;
    }

    // Clone rules to release the borrow on ctx before mutating it.
    let rules: Vec<ConsequenceRule> = ctx.governance.consequence_rules.clone();

    // Collect event log entries for consequence evaluation (ADR-017).
    let events = event_log_entries_for_consequences(&ctx.receive_buffer, context_id, now, event_log);

    // Evaluate which consequences are triggered.
    let triggered: Vec<TriggeredConsequence> =
        evaluate_consequence_rules(&rules, &events, member_did.as_ref(), now);

    // Enforce the triggered consequences, passing the already-cloned rules
    // to avoid cloning again inside enforce_triggered_consequences.
    let mut split = ConsequenceStateSplit::from_state(ctx);
    enforce_triggered_consequences(
        &mut split,
        &EnforceConsequencesCtx {
            context_id,
            member_did,
            now,
            triggered: &triggered,
            rules: &rules,
            clock,
            event_log,
            event_tx,
        },
    );
}

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
    event_name: &'static str,
    member_did: &DID,
    payload: &serde_json::Value,
) {
    if let Err(e) = event_log.append_context_event_with_payload(
        context_id_bytes,
        event_name,
        CONSEQUENCE_ACTOR_DID,
        Some(payload),
    ) {
        tracing::warn!(
            context_id,
            member = %member_did,
            event = event_name,
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
    /// (ADR-049 §Decision 1 — single PerContextState).
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
/// **Durability invariant (H4, PR #1606):** Every consequence event is
/// appended to the durable Merkle event log via `event_log` BEFORE the
/// matching `ctx.receive_buffer.push(...)` call. The order matters: a crash
/// between the append and the buffer push leaves the Merkle-anchored record
/// intact (the buffer is in-memory and capped at 1000, so its loss is not a
/// non-repudiation gap; the durable log is the system of record). The
/// receive buffer pushes remain because they are still useful for
/// in-session SDK observation.
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
    let trigger_kind = args
        .rules
        .get(consequence.rule_index)
        .map_or_else(|| "Unknown".to_owned(), |r| trigger_kind_str(&r.trigger));

    // Always emit `ConsequenceTriggered` (durable + buffer) regardless
    // of whether the member is still present.
    emit_consequence_triggered(
        state,
        args,
        context_id_bytes,
        consequence,
        &trigger_kind,
        action_type,
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

/// Emits a `ConsequenceTriggered` durable event log entry followed by
/// the matching receive-buffer push (H4 ordering invariant).
fn emit_consequence_triggered(
    state: &mut ConsequenceStateSplit<'_>,
    args: &EnforceConsequencesCtx<'_>,
    context_id_bytes: &[u8; 32],
    consequence: &TriggeredConsequence,
    trigger_kind: &str,
    action_type: &str,
) {
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
        "ConsequenceTriggered",
        args.member_did,
        &payload,
    );
    *state.checkpoint_events_since += 1;
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
) {
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
        "ConsequenceEnforcementFailed",
        args.member_did,
        &payload,
    );
    *state.checkpoint_events_since += 1;
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
) {
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
        "ConsequenceEnforced",
        args.member_did,
        &payload,
    );
    *state.checkpoint_events_since += 1;
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
) {
    let context_id = args.context_id;
    let member_did = args.member_did;
    tracing::warn!(
        context_id,
        member = %member_did,
        action_type,
        "consequence enforcement failed — escalating to SuspendAll"
    );

    // H10: escalate to SuspendAll when enforcement fails.
    // Skip cooldown on failure so the escalation fires immediately.
    state.role_state.suspend_all(member_did.as_ref());

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
        "ConsequenceEnforcementFailed",
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
        "ConsequenceEscalatedToSuspendAll",
        member_did,
        &escalation_payload,
    );
    *state.checkpoint_events_since += 1;
    let event = ContextEvent::ConsequenceEnforced {
        context_id: context_id.to_owned(),
        member_did: member_did.clone(),
        action_type: "SuspendAll(escalated)".to_owned(),
        success: true,
    };
    emit_event_into(state.receive_buffer, event, context_id, args.event_tx);
}

/// Converts receive buffer events into `scp_event_log::Event` format for
/// consequence rule evaluation and participation record computation.
///
/// This bridges the gap between the in-memory receive buffer (which tracks
/// recent context events) and the event log types expected by the trust
/// evaluation functions.
///
/// **Known limitation (#1594):** The receive buffer is capped at 1000 events
/// (`ReceiveBuffer::DEFAULT_BUFFER_CAPACITY`). Long-running contexts lose
/// older history, which means participation records and consequence evaluation
/// only reflect recent activity.
///
/// **Why the Merkle event log cannot be used as a replacement:**
/// `ContextEventLogProvider::event_log_entries()` returns `EventLogEntry`,
/// Collects event history for consequence evaluation and participation
/// record computation (ADR-017, #1530, #1531, #1594).
///
/// Combines two sources:
/// 1. **Event log history** — full persisted history from the
///    `ContextEventLogProvider`. Each `EventLogEntry` includes `actor_did`
///    (#1594), enabling proper attribution.
/// 2. **Receive buffer events** — recent in-memory events that may not
///    yet be in the event log (the event log is appended after the
///    operation, but the receive buffer is updated inside the lock).
///
/// Events from the event log use their real timestamps. Receive buffer
/// events use estimated timestamps (spaced 1 second apart backwards from
/// `now`). The merge deduplicates by preferring event log entries (which
/// have accurate timestamps and hashes) over buffer estimates.
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
/// record computation (ADR-017, #1530, #1531, #1594).
///
/// Combines two sources:
/// 1. **Event log history** — full persisted history from the
///    `ContextEventLogProvider`. Each `EventLogEntry` includes `actor_did`
///    (#1594), enabling proper attribution.
/// 2. **Receive buffer events** — recent in-memory events that may not
///    yet be in the event log (the event log is appended after the
///    operation, but the receive buffer is updated inside the lock).
///
/// Events from the event log use their real timestamps. Receive buffer
/// events use estimated timestamps (spaced 1 second apart backwards from
/// `now`). The merge deduplicates by preferring event log entries (which
/// have accurate timestamps and hashes) over buffer estimates.
///
/// **Known limitation (#1594):** The receive buffer is capped at 1000 events
/// (`ReceiveBuffer::DEFAULT_BUFFER_CAPACITY`). Long-running contexts lose
/// older history, which means participation records and consequence evaluation
/// only reflect recent activity.
///
/// **Why the Merkle event log cannot be used as a replacement:**
/// `ContextEventLogProvider::event_log_entries()` returns `EventLogEntry`,
/// not the raw `scp_event_log::Event` that consequence rules consume. The
/// conversion is done here, bridging the gap between the two formats.
/// Event-log + receive-buffer merge used by consequence enforcement
/// (ADR-017, #1531). Takes a borrowed [`ReceiveBuffer`] directly so the
/// caller may build it from sub-borrows of the unified
/// [`PerContextState`] (ADR-049 §Decision 1) without holding the whole
/// state across the merge.
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
            let event_type = match entry.event.as_str() {
                "MessageSent" | "MessageReceived" => scp_event_log::EventType::MessageSent,
                "MemberJoined" => scp_event_log::EventType::MemberJoined,
                "MemberLeft" => scp_event_log::EventType::MemberLeft,
                "RoleAssigned" => scp_event_log::EventType::RoleAssigned,
                "ToolRegistered" | "ToolRemoved" | "ToolInvoked" => {
                    scp_event_log::EventType::ToolInvoked
                }
                // Governance actions and consequence enforcement records
                // both feed the WarningCount trigger via the
                // EventType::GovernanceAction match arm in
                // `matches_trigger`. Mapping consequence events to this
                // bucket closes the recursive blind spot from the
                // white-hat review (H4): subsequent rule evaluation can
                // see prior consequence enforcement, enabling rules like
                // "if member has been auto-suspended N times, demote".
                "GovernanceAction"
                | "GovernanceProposalCreated"
                | "GovernanceVoteCast"
                | "GovernanceVoteWithdrawn"
                | "GovernanceProposalResolved"
                | "GovernanceDeadlockRecovery"
                | "GovernanceConflictDetected"
                | "GovernanceConflictResolved"
                | "GovernanceActionExecuted"
                | "ConsequenceTriggered"
                | "ConsequenceEnforced"
                | "ConsequenceEnforcementFailed"
                | "ConsequenceEscalatedToSuspendAll" => scp_event_log::EventType::GovernanceAction,
                _ => continue, // Skip event types not relevant to consequence evaluation
            };
            // Convert structured JSON payload to EventPayload bytes.
            // The payload is serialized as JSON bytes for consumption by
            // extract_target_did_from_payload and payload_target_is.
            let payload_data = entry
                .payload
                .as_ref()
                .and_then(|v| serde_json::to_vec(v).ok())
                .unwrap_or_default();
            events.push(scp_event_log::Event {
                event_type,
                actor_did: DID(entry.actor_did.clone()),
                timestamp: entry.timestamp,
                sequence: seq as u64,
                payload: scp_event_log::EventPayload { data: payload_data },
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

/// Checks whether a proposer is eligible to submit a governance proposal.
///
/// Composite gate combining independent eligibility signals:
/// 1. **Pending removal** — defense-in-depth: members with an approved
///    `RemoveMember` proposal targeting them cannot submit new proposals.
/// 2. **Participation threshold** — members whose participation record
///    shows a net-negative governance ratio (more actions against than by)
///    are blocked. See [`scp_protocol::trust::participation::meets_threshold`].
///
/// Refreshes the participation cache before checking by calling
/// `compute_participation_record` with recent events from the receive buffer.
///
/// Note: "standing" in the spec refers to persistent bilateral contact-graph
/// contexts (§5.12.4-6), which is unrelated to this check. Do not reuse the
/// word for the participation/eligibility model.
pub fn check_proposer_eligibility(
    ctx: &mut PerContextState,
    proposer_did: &DID,
    now: u64,
    event_log: &dyn crate::context::builder::ContextEventLogProvider,
) -> Result<(), ContextError> {
    // Check for pending ejection (existing defense-in-depth).
    for (proposal, _seq, _ts) in ctx.governance.approved_proposals.values() {
        if let GovernanceAction::RemoveMember { did, .. } = &proposal.action
            && did == proposer_did
        {
            return Err(ContextError::PermissionDenied(
                "member has a pending ejection — cannot propose governance actions".into(),
            ));
        }
    }

    // SingleAdmin: the sole authority is always eligible. Participation
    // thresholds and earned capacity limits are multi-party governance
    // concepts — rate-limiting the only admin is nonsensical.
    if matches!(ctx.handle.params().governance, GovernanceModel::SingleAdmin) {
        return Ok(());
    }

    // Refresh participation record from recent events before checking the
    // participation threshold (#1530). Skip recomputation if a cached record
    // already exists — the cache is populated on first check and updated when
    // participation events occur (messaging, governance, tools, lifecycle).
    let context_id = ctx.handle.context_id().to_owned();
    if !ctx
        .governance
        .participation_cache
        .contains_key(proposer_did.as_ref())
    {
        let context_id_bytes = context_id_to_bytes(&context_id);
        let merkle_root = event_log
            .event_log_merkle_root(&context_id_bytes)
            .unwrap_or([0u8; 32]);
        let events = event_log_entries_for_consequences(&ctx.receive_buffer, &context_id, now, event_log);
        if !events.is_empty() {
            match scp_protocol::trust::participation::compute_participation_record(
                &events,
                proposer_did.as_ref(),
                &context_id,
                merkle_root,
                now,
            ) {
                Err(e) => {
                    // Fail-closed: if participation record computation fails,
                    // log a warning and deny the proposal. This prevents
                    // silently passing members with corrupted participation data.
                    tracing::warn!(
                        proposer = %proposer_did,
                        error = %e,
                        "compute_participation_record failed — denying proposal"
                    );
                    return Err(ContextError::PermissionDenied(
                    "SCP-GOV-11021: participation record computation failed — cannot verify proposer eligibility"
                        .into(),
                ));
                }
                Ok(record) => {
                    // Participation evaluation uses participation_count and
                    // governance_actions to determine eligibility (#1530).
                    // Only cache records with actual participation — new members
                    // with zero participation should not be blocked before they
                    // participate.
                    if record.participation_count > 0 {
                        tracing::trace!(
                            participation_count = record.participation_count,
                            governance_actions_by = record.governance_actions_by.len(),
                            governance_actions_against = record.governance_actions_against.len(),
                            "participation evaluation for proposer"
                        );
                        ctx.governance
                            .participation_cache
                            .insert(proposer_did.to_string(), record);
                    }
                }
            }
        }
    } // end if !participation_cache.contains_key

    // Check participation records for eligibility (#1530).
    if let Some(record) = ctx
        .governance
        .participation_cache
        .get(proposer_did.as_ref())
        && !scp_protocol::trust::participation::meets_threshold(record)
    {
        return Err(ContextError::PermissionDenied(
            "member participation below threshold — cannot propose governance actions (SCP-GOV-11020)"
                .into(),
        ));
    }

    // Earned capacity enforcement (§9.3): when the context has a sybil_policy,
    // evaluate the proposer's identity depth to determine their governance
    // proposal rate limit, then check recent proposals against that limit.
    if let Some(sybil_policy) = ctx.handle.params().sybil_policy.as_ref() {
        let assessment =
            super::lifecycle_logic::build_identity_assessment(proposer_did, &ctx.governance, now);
        let (_level, capacity) =
            scp_protocol::trust::sybil::evaluate_earned_capacity(&assessment, sybil_policy, now);

        let window_secs = capacity.governance_proposal_window_secs;
        let max_proposals = capacity.max_governance_proposals_per_window;
        let window_start = now.saturating_sub(window_secs);

        // Count proposals within the sliding window for this member.
        let timestamps = ctx
            .governance
            .proposal_timestamps
            .entry(proposer_did.to_string())
            .or_default();

        // Evict stale entries outside the window.
        timestamps.retain(|&ts| ts > window_start);

        #[allow(clippy::cast_possible_truncation)]
        let recent_count = timestamps.len() as u32;
        if recent_count >= max_proposals {
            return Err(ContextError::PermissionDenied(format!(
                "earned capacity limit reached: {recent_count}/{max_proposals} governance proposals \
                 in {window_secs}s window (SCP-GOV-11030)"
            )));
        }
    }

    Ok(())
}
