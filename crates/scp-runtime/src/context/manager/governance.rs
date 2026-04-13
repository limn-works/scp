//! Governance proposal, vote, execute, and dispatch operations.

use super::{
    AccessScope, Arc, CEILING_CHANGE_NOTIFICATION_PERIOD_SECS, Capability, CapabilityCeiling,
    Clock, CommitFaultMarker, CommitOperation, ConsequenceRule, ContentKeysRotatedResult,
    ContextError, ContextEvent, ContextManager, ContextParams, ContextState, DID,
    ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS, EXECUTED_PROPOSALS_TTL_SECS, EconomicPolicy,
    GovernanceAction, GovernanceActionResult, GovernanceContext, GovernanceEvent, GovernanceModel,
    GovernanceProposal, GovernanceReconfiguredResult, HashSet, MAX_COMMIT_AGE_SECS,
    MAX_COMMIT_RETRIES, MAX_PENDING_COMMITS, MAX_REGISTERED_TOOLS, MAX_THRESHOLD_SIGNERS,
    MAX_TOOL_INTERFACES, MigrationProposedResult, MigrationState, MlsImpact,
    PendingCeilingModification, PendingCommit, PendingEconomicPolicyChange, PerContextState,
    ProposalId, ProposalOutcome, ProposalStatus, PruningPolicy, RestoreAccessResult, RevokeResult,
    SuspendMemberResult, ToolInterface, ToolRegistration, TriggeredConsequence, classify_action,
    collect_active_voters, commit_retry_backoff, context_id_to_bytes, evaluate_consequence_rules,
    generate_mls_operations, instrument, process_pending_proposals, push_welcome_event,
    require_active, require_migrating_out, roles, update_detection_state,
};

// ---------------------------------------------------------------------------
// RuntimeConsequenceDispatcher — bridges PerContextState to the shared trait
// ---------------------------------------------------------------------------

// PR #1606 C6 helper types — outcome of attempting to retry a single
// pending commit. Lifted out of `process_pending_commits_static` to satisfy
// `clippy::items_after_statements`.
struct CommitRetryOutcome {
    index: usize,
    kind: CommitRetryOutcomeKind,
}

enum CommitRetryOutcomeKind {
    Success {
        attempts: u32,
        operation: CommitOperation,
    },
    Retry {
        error: String,
        next_attempt_at: u64,
        new_retry_count: u32,
        operation: CommitOperation,
    },
    Failed {
        reason: String,
        attempts: u32,
        operation: CommitOperation,
    },
}

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
pub(super) fn dispatch_consequences(
    ctx: &mut PerContextState,
    context_id: &str,
    member_did: &DID,
    now: u64,
    clock: &dyn scp_primitives::Clock,
    event_log: &dyn super::super::builder::ContextEventLogProvider,
) {
    if ctx.governance.consequence_rules.is_empty() {
        return;
    }

    // Clone rules to release the borrow on ctx before mutating it.
    let rules: Vec<ConsequenceRule> = ctx.governance.consequence_rules.clone();

    // Collect event log entries for consequence evaluation (ADR-017).
    let events = event_log_entries_for_consequences(ctx, context_id, now, event_log);

    // Evaluate which consequences are triggered.
    let triggered: Vec<TriggeredConsequence> =
        evaluate_consequence_rules(&rules, &events, member_did.as_ref(), now);

    // Enforce the triggered consequences, passing the already-cloned rules
    // to avoid cloning again inside enforce_triggered_consequences.
    enforce_triggered_consequences(
        ctx,
        &EnforceConsequencesCtx {
            context_id,
            member_did,
            now,
            triggered: &triggered,
            rules: &rules,
            clock,
            event_log,
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
    event_log: &dyn super::super::builder::ContextEventLogProvider,
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

/// Borrowed inputs for `enforce_triggered_consequences`. Bundling the
/// providers, scope identifiers, and pre-evaluated rule data into one
/// struct keeps the public function signature within the
/// `clippy::too_many_arguments` budget while preserving the explicit
/// names that callers (`messaging.rs`, `tools.rs`, `governance.rs`,
/// the periodic timer) need at construction time.
pub(super) struct EnforceConsequencesCtx<'a> {
    pub context_id: &'a str,
    pub member_did: &'a DID,
    pub now: u64,
    pub triggered: &'a [TriggeredConsequence],
    pub rules: &'a [ConsequenceRule],
    pub clock: &'a dyn scp_primitives::Clock,
    pub event_log: &'a dyn super::super::builder::ContextEventLogProvider,
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
pub(super) fn enforce_triggered_consequences(
    ctx: &mut PerContextState,
    args: &EnforceConsequencesCtx<'_>,
) {
    let context_id_bytes = context_id_to_bytes(args.context_id);
    for consequence in args.triggered {
        process_one_triggered_consequence(ctx, args, &context_id_bytes, consequence);
    }
}

/// Single-consequence body of [`enforce_triggered_consequences`].
/// Extracted so the public function stays under `clippy::too_many_lines`.
fn process_one_triggered_consequence(
    ctx: &mut PerContextState,
    args: &EnforceConsequencesCtx<'_>,
    context_id_bytes: &[u8; 32],
    consequence: &TriggeredConsequence,
) {
    let member_did = args.member_did;
    let now = args.now;

    // Cooldown tracking: skip if this rule fired within its window.
    if let Some(&last_fired) = ctx.governance.cooldown_until.get(&consequence.rule_index)
        && now < last_fired
    {
        return;
    }

    // TOCTOU/ghost guard: skip entirely if the member is absent AND
    // there is no evidence that the member ever participated. Members
    // who left mid-flight after accumulating real evidence still emit
    // `ConsequenceTriggered` so observers see the behavioral signal.
    let member_present = ctx.membership.contains(member_did);
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
        ctx,
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
            ctx,
            args,
            context_id_bytes,
            consequence,
            &trigger_kind,
            action_type,
        );
        return;
    }

    let success =
        dispatch_enforcement_action(ctx, member_did, consequence, args.clock, args.context_id);

    if !success {
        emit_failure_escalation(
            ctx,
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
        ctx.governance.cooldown_until.insert(
            consequence.rule_index,
            now.saturating_add(rule.window.as_secs()),
        );
    }

    emit_consequence_enforced_success(
        ctx,
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
    ctx: &mut PerContextState,
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
    ctx.checkpoint_events_since += 1;
    ctx.receive_buffer.push(ContextEvent::ConsequenceTriggered {
        context_id: args.context_id.to_owned(),
        member_did: args.member_did.clone(),
        rule_index: consequence.rule_index,
        trigger_type: trigger_kind.to_owned(),
        action_type: action_type.to_owned(),
    });
}

/// Emits a `ConsequenceEnforcementFailed` durable entry plus the matching
/// `ConsequenceEnforced { success: false }` receive-buffer push for the
/// "member-departed-mid-flight" path. Separate from
/// [`emit_failure_escalation`] because no escalation is applied when the
/// member is absent — there is nothing to escalate against.
fn emit_absent_member_enforcement_failed(
    ctx: &mut PerContextState,
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
    ctx.checkpoint_events_since += 1;
    ctx.receive_buffer.push(ContextEvent::ConsequenceEnforced {
        context_id: args.context_id.to_owned(),
        member_did: args.member_did.clone(),
        action_type: action_type.to_owned(),
        success: false,
    });
}

/// Emits a `ConsequenceEnforced { success: true }` durable entry plus the
/// matching receive-buffer push for the success path.
fn emit_consequence_enforced_success(
    ctx: &mut PerContextState,
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
    ctx.checkpoint_events_since += 1;
    ctx.receive_buffer.push(ContextEvent::ConsequenceEnforced {
        context_id: args.context_id.to_owned(),
        member_did: args.member_did.clone(),
        action_type: action_type.to_owned(),
        success: true,
    });
}

/// Per-arm enforcement dispatch. Each match arm calls a named function as
/// an `expression_statement` so the pipeline wiring gates can detect the
/// `call_expression` per-variant.
fn dispatch_enforcement_action(
    ctx: &mut PerContextState,
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
                    enforce_suspend(ctx, member_did, capabilities)
                }
                EnforcementSeverity::SuspendAccess => {
                    // SuspendAccess: suspend all capabilities via role_state.
                    ctx.role_state.suspend_all(member_did.as_ref());
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
            enforce_assign_role(ctx, member_did, to_role, clock)
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
fn enforce_suspend(ctx: &mut PerContextState, member_did: &DID, caps: &[Capability]) -> bool {
    if caps.is_empty() {
        return false;
    }
    ctx.role_state
        .suspend_capabilities(member_did.as_ref(), caps.iter().cloned());
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
    ctx: &mut PerContextState,
    member_did: &DID,
    to_role: &str,
    clock: &dyn scp_primitives::Clock,
) -> bool {
    roles::system_assign_role(&mut ctx.role_state, member_did, to_role, clock).is_ok()
}

/// H10 + H4: when enforcement fails, escalate to `SuspendAll` AND emit two
/// durable event log entries (`ConsequenceEnforcementFailed` then
/// `ConsequenceEscalatedToSuspendAll`) so an audit can reconstruct
/// (a) which action failed and (b) that escalation was applied.
fn emit_failure_escalation(
    ctx: &mut PerContextState,
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
    ctx.role_state.suspend_all(member_did.as_ref());

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
    ctx.checkpoint_events_since += 1;
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
    ctx.checkpoint_events_since += 1;
    ctx.receive_buffer.push(ContextEvent::ConsequenceEnforced {
        context_id: context_id.to_owned(),
        member_did: member_did.clone(),
        action_type: "SuspendAll(escalated)".to_owned(),
        success: true,
    });
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
#[allow(clippy::too_many_lines)]
pub(super) fn event_log_entries_for_consequences(
    ctx: &PerContextState,
    context_id: &str,
    now: u64,
    event_log: &dyn super::super::builder::ContextEventLogProvider,
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
    let all_buffer_events = ctx.receive_buffer.event_log_entries();
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
fn check_proposer_eligibility(
    ctx: &mut PerContextState,
    proposer_did: &DID,
    now: u64,
    event_log: &dyn super::super::builder::ContextEventLogProvider,
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
        let events = event_log_entries_for_consequences(ctx, &context_id, now, event_log);
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
            super::lifecycle::build_identity_assessment(proposer_did, &ctx.governance, now);
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

#[allow(clippy::significant_drop_tightening)]
impl ContextManager {
    /// Executes an approved governance action on a broadcast context.
    ///
    /// This is the sole entry point for governance-gated operations. The caller
    /// must provide a [`GovernanceProposal`] that has been approved through the
    /// context's governance model (e.g., `SingleAdminEngine::propose()` for
    /// single-admin contexts, or `ThresholdEngine::approve()` reaching quorum).
    ///
    /// Supports all [`GovernanceAction`] variants. Actions that modify context
    /// state do so under the context write lock and emit appropriate events.
    ///
    /// # Errors
    ///
    /// - [`ContextError::PermissionDenied`] if the proposal is not in
    ///   `Approved` status.
    /// - [`ContextError::PermissionDenied`] if the context's ceiling does not
    ///   include `MemberBan` (for `Revoke`/`RestoreAccess`/`SuspendMember`).
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    #[instrument(skip_all, fields(context_id))]
    pub async fn execute_governance_action(
        &self,
        context_id: &str,
        proposal: &GovernanceProposal,
    ) -> Result<GovernanceActionResult, ContextError> {
        // Gate: only approved proposals can be executed.
        if !matches!(proposal.status, ProposalStatus::Approved) {
            return Err(ContextError::PermissionDenied(format!(
                "governance proposal is not approved (status: {:?})",
                proposal.status
            )));
        }

        // Gate: proposal must target this context.
        if proposal.context_id != context_id {
            return Err(ContextError::PermissionDenied(format!(
                "governance proposal targets context '{}' but was submitted to '{}'",
                proposal.context_id, context_id
            )));
        }

        // PR #1606 C6 fail-close gate: if the persistent commit retry queue
        // exhausted its budget for a previous mutation, refuse new governance
        // actions until an operator acknowledges the fault. Without this
        // gate, an ejected member could remain in the MLS group while local
        // governance keeps advancing on a divergent epoch.
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let guard = ctx_arc.lock().await;
                let ctx = &*guard;
                Self::check_commit_fault(ctx)?;
            }
        }

        // Atomically check replay AND mark as executed before dispatch.
        // This prevents TOCTOU races where concurrent callers both pass the
        // replay check before either records the proposal as executed.
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                if ctx
                    .governance
                    .executed_proposals
                    .contains_key(&proposal.proposal_id)
                {
                    return Err(ContextError::PermissionDenied(
                        "governance proposal has already been executed".into(),
                    ));
                }
                let now = self.clock.now_secs();
                // Evict entries older than the TTL before inserting.
                ctx.governance
                    .executed_proposals
                    .retain(|_, ts| now.saturating_sub(*ts) < EXECUTED_PROPOSALS_TTL_SECS);
                ctx.governance
                    .executed_proposals
                    .insert(proposal.proposal_id, now);
            } else {
                return Err(ContextError::ContextNotRegistered(context_id.to_owned()));
            }
        }

        // Governance action costing: no PaidActionType::GovernanceAction
        // variant exists yet. Governance actions are free until the economy
        // spec adds a governance cost tier. Tracked by #1537.

        let result = match self.dispatch_governance_action(context_id, proposal).await {
            Ok(r) => r,
            Err(e) => {
                // Roll back the executed marker on dispatch failure so the
                // proposal can be retried (e.g. after a transient crypto error).
                if let Some(entry) = self.contexts.get(context_id) {
                    let ctx_arc = Arc::clone(entry.value());
                    drop(entry);
                    let mut guard = ctx_arc.lock().await;
                    let ctx = &mut *guard;
                    ctx.governance
                        .executed_proposals
                        .remove(&proposal.proposal_id);
                }
                return Err(e);
            }
        };

        // Post-dispatch: MLS coordination, event emission, checkpoint
        // triggering, and cleanup are in a helper to stay within line limits.
        self.finalize_governance_action(context_id, proposal)
            .await?;

        Ok(result)
    }

    /// Post-dispatch finalization for an executed governance action.
    ///
    /// Handles MLS epoch coordination (ADR-031 §8), event emission
    /// (PRD SCP-269/SCP-270), checkpoint cosignature triggering (ADR-031 §9),
    /// and cleanup of approved proposals (ADR-031 §7).
    ///
    /// Extracted from [`execute_governance_action`] to keep that method
    /// focused on validation and dispatch.
    #[allow(clippy::too_many_lines)]
    async fn finalize_governance_action(
        &self,
        context_id: &str,
        proposal: &GovernanceProposal,
    ) -> Result<(), ContextError> {
        // For MLS-mutating actions (AddMember, RemoveMember, Revoke,
        // ResetMember), increment the epoch counter, place the old epoch into
        // the grace store (§23.11), record the coordination in the
        // EpochCoordinator (ADR-031 §8, issue #630), and report the new epoch.
        // Non-MLS actions leave the epoch unchanged and report None.
        let resulting_epoch = if classify_action(&proposal.action) == MlsImpact::MembershipChange {
            // Generate the MLS operation from the approved proposal to link
            // governance approval to the concrete MLS mutation (issue #630).
            let mls_op = generate_mls_operations(proposal)
                .map_err(|e| ContextError::GovernanceFailed(e.to_string()))?;

            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                let old_epoch = ctx.epoch.mls_epoch;
                ctx.epoch.mls_epoch = old_epoch.saturating_add(1);
                // Place the old epoch into the grace window so in-flight
                // messages encrypted under it can still be decrypted for
                // up to 30 seconds (ADR-001 criterion 6, §23.11).
                let _expired = ctx.epoch.grace_store.add_epoch(old_epoch);

                // Record the governance-MLS coordination for audit trail
                // (ADR-031 §8, issue #630). The EpochCoordinator creates an
                // auditable link between the governance proposal and the MLS
                // epoch transition.
                if let Some(operation) = mls_op {
                    let timestamp = self.clock.now_secs();
                    // Best-effort: log but do not fail if recording fails
                    // (epoch_after > epoch_before is guaranteed by saturating_add).
                    let _ = ctx.epoch.coordinator.record_coordination(
                        proposal.proposal_id,
                        old_epoch,
                        ctx.epoch.mls_epoch,
                        operation,
                        timestamp,
                    );
                }

                Some(ctx.epoch.mls_epoch)
            } else {
                None
            }
        } else {
            None
        };

        // Construct the structured GovernanceEvent::GovernanceActionExecuted
        // and emit it to both the Merkle event log and the receive buffer
        // (ADR-031 §8, PRD SCP-269/SCP-270).
        let executed_event = GovernanceEvent::GovernanceActionExecuted {
            proposal_id: proposal.proposal_id,
            action: Box::new(proposal.action.clone()),
            executor_did: proposal.proposer_did.clone(),
            resulting_epoch,
        };

        // Append to Merkle event log using the standard governance event
        // label path (same pattern as propose/approve/reject/withdraw).
        // Include structured payload with target_did and action_type so
        // consequence triggers (WarningCount, Custom) and participation records
        // can identify the target and classify whether the action is adverse
        // (H18: standing-deflation filter).
        let context_id_bytes = context_id_to_bytes(context_id);
        let action_variant = proposal.action.variant_name();
        let payload = Some(proposal.action.target_did().map_or_else(
            || serde_json::json!({"action_type": action_variant}),
            |d| serde_json::json!({"target_did": d.as_ref(), "action_type": action_variant}),
        ));
        self.event_log.append_context_event_with_payload(
            &context_id_bytes,
            Self::governance_event_label(&executed_event),
            proposal.proposer_did.as_ref(),
            payload.as_ref(),
        )?;

        // Single lock acquisition for all post-event-log state mutations
        // (#1428 — eliminates TOCTOU window from multiple lock acquisitions).
        {
            let action_summary = proposal.action.variant_name().to_owned();
            let target_did = proposal.action.target_did().cloned();
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                // Checkpoint tracking: count the GovernanceActionExecuted event.
                ctx.checkpoint_events_since += 1;

                // 1. Push GovernanceActionExecuted to receive buffer so SDK
                //    consumers observe outcomes with rich context.
                ctx.receive_buffer
                    .push(ContextEvent::GovernanceActionExecuted {
                        proposal_id: proposal.proposal_id,
                        action_summary,
                        executor_did: proposal.proposer_did.clone(),
                        resulting_epoch,
                        target_did,
                    });

                // 2. Trigger checkpoint cosignature collection for multi-admin
                //    contexts (ADR-031 §9, issue #630). SingleAdmin contexts
                //    emit no event because they require no cosignatures
                //    (quorum is 0).
                let (required_signers, minimum_count) =
                    ctx.governance.engine.checkpoint_cosignature_requirements();
                if minimum_count > 0 {
                    ctx.receive_buffer
                        .push(ContextEvent::CheckpointCosignatureRequired {
                            proposal_id: proposal.proposal_id,
                            required_signers,
                            minimum_count,
                            at_epoch: ctx.epoch.mls_epoch,
                        });
                }

                // 3. Remove the executed proposal from approved_proposals so
                //    it no longer participates in conflict detection
                //    (ADR-031 §7). Replay prevention is already handled by
                //    `executed_proposals`.
                ctx.governance
                    .approved_proposals
                    .remove(&proposal.proposal_id);

                // Evaluate consequence rules after governance action (ADR-017, #1531).
                // Evaluate for both the proposer and the target (if different).
                // WarningCount triggers match events where the *target* DID
                // appears in the payload, so skipping the target would miss
                // accumulating warnings against them.
                dispatch_consequences(
                    ctx,
                    context_id,
                    &proposal.proposer_did,
                    self.clock.now_secs(),
                    &*self.clock,
                    &*self.event_log,
                );
                if let Some(target) = proposal.action.target_did()
                    && target != &proposal.proposer_did
                {
                    dispatch_consequences(
                        ctx,
                        context_id,
                        target,
                        self.clock.now_secs(),
                        &*self.clock,
                        &*self.event_log,
                    );
                }

                // Update participation record after governance action (#1530).
                // Reuse the same event log entries for participation (finding #46).
                let gov_events = event_log_entries_for_consequences(
                    ctx,
                    context_id,
                    self.clock.now_secs(),
                    &*self.event_log,
                );
                let gov_merkle = self
                    .event_log
                    .event_log_merkle_root(&context_id_bytes)
                    .unwrap_or([0u8; 32]);
                if !gov_events.is_empty()
                    && let Ok(record) =
                        scp_protocol::trust::participation::compute_participation_record(
                            &gov_events,
                            proposal.proposer_did.as_ref(),
                            context_id,
                            gov_merkle,
                            self.clock.now_secs(),
                        )
                    && record.participation_count > 0
                {
                    ctx.governance
                        .participation_cache
                        .insert(proposal.proposer_did.to_string(), record);
                }

                // 4. Persist the updated context state (best-effort).
                if self.has_persistence() {
                    let snapshot = Self::snapshot_context(ctx);
                    self.persist_context_snapshot(context_id, snapshot);
                }
            }
        }

        Ok(())
    }

    /// Dispatches an approved governance action to its implementation method.
    ///
    /// Separated from [`execute_governance_action`] to keep the public entry
    /// point focused on validation while this method handles the 28-action
    /// dispatch.
    #[allow(clippy::too_many_lines)]
    async fn dispatch_governance_action(
        &self,
        context_id: &str,
        proposal: &GovernanceProposal,
    ) -> Result<GovernanceActionResult, ContextError> {
        let pid = proposal.proposal_id;
        let actor = proposal.proposer_did.as_ref();
        match &proposal.action {
            GovernanceAction::SuspendCapability { did, capabilities } => {
                self.execute_suspend_member(context_id, did, capabilities, pid, actor)
                    .await?;
                Ok(GovernanceActionResult::MemberSuspended(
                    SuspendMemberResult {
                        did: did.clone(),
                        capabilities: capabilities.clone(),
                    },
                ))
            }
            GovernanceAction::SuspendAccess { did } => {
                // Suspend all capabilities for the member.
                let snapshot = {
                    let ctx_arc = self
                        .get_context_arc(context_id)
                        .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
                    let mut guard = ctx_arc.lock().await;
                    let ctx = &mut *guard;
                    require_active(&ctx.handle)?;

                    if !ctx.role_state.ceiling.contains(&Capability::MemberBan) {
                        return Err(ContextError::PermissionDenied(
                            "member:ban (MemberBan) capability not in ceiling".to_owned(),
                        ));
                    }
                    if !ctx.membership.contains(did) {
                        return Err(ContextError::MemberNotFound(did.to_string()));
                    }

                    ctx.role_state.suspend_all(did.as_ref());

                    ctx.receive_buffer
                        .push(ContextEvent::CapabilitiesSuspended {
                            did: did.clone(),
                            capabilities: vec![], // all — indicated by empty
                        });

                    if self.has_persistence() {
                        Some(Self::snapshot_context(ctx))
                    } else {
                        None
                    }
                };

                if let Some(snapshot) = snapshot {
                    self.persist_context_snapshot(context_id, snapshot);
                }
                let context_id_bytes = context_id_to_bytes(context_id);
                self.event_log.append_context_event(
                    &context_id_bytes,
                    "MemberSuspendedAll",
                    actor,
                )?;
                {
                    if let Some(entry) = self.contexts.get(context_id) {
                        let ctx_arc = Arc::clone(entry.value());
                        drop(entry);
                        let mut guard = ctx_arc.lock().await;
                        let ctx = &mut *guard;
                        ctx.checkpoint_events_since += 1;
                    }
                }
                Ok(GovernanceActionResult::Executed)
            }
            GovernanceAction::RevokeAccess { did, access } => {
                let r = self
                    .execute_revoke(context_id, did, *access, pid, actor)
                    .await?;
                Ok(GovernanceActionResult::AccessRevoked(RevokeResult {
                    did: did.clone(),
                    access: *access,
                    rotated_author_count: r,
                }))
            }
            GovernanceAction::RestoreAccess { did, capabilities } => {
                self.execute_restore_access(context_id, did, capabilities, pid, actor)
                    .await?;
                Ok(GovernanceActionResult::AccessRestored(
                    RestoreAccessResult {
                        did: did.clone(),
                        capabilities: capabilities.clone(),
                    },
                ))
            }
            GovernanceAction::PromoteContext => {
                self.execute_promote_context(context_id, &proposal.approvals, pid, actor)
                    .await?;
                Ok(GovernanceActionResult::ContextPromoted)
            }
            // ExtendTtl needs proposal.approvals for unanimity override
            // (ADR-031 §4d, spec §5.10).
            GovernanceAction::ExtendTtl { additional_secs } => {
                self.execute_extend_ttl(
                    context_id,
                    *additional_secs,
                    &proposal.approvals,
                    pid,
                    actor,
                )
                .await?;
                Ok(GovernanceActionResult::TtlExtended)
            }
            GovernanceAction::SetEconomicPolicy { policy } => {
                self.execute_set_economic_policy(context_id, policy, pid, actor)
                    .await?;
                Ok(GovernanceActionResult::Executed)
            }
            GovernanceAction::ApproveSpend {
                spender,
                amount,
                purpose,
            } => {
                self.execute_approve_spend(context_id, spender, *amount, purpose, pid, actor)
                    .await?;
                Ok(GovernanceActionResult::Executed)
            }
            GovernanceAction::LockEconomicPolicy => {
                self.execute_lock_economic_policy(context_id, pid, actor)
                    .await?;
                Ok(GovernanceActionResult::Executed)
            }
            GovernanceAction::ModifyHardRateLimit { new_config } => {
                self.execute_modify_hard_rate_limit(context_id, new_config, pid, actor)
                    .await?;
                Ok(GovernanceActionResult::Executed)
            }
            // SuspendCapability, SuspendAccess, RevokeAccess are handled above.
            // Remaining actions dispatched to context-level handler.
            GovernanceAction::AddMember { .. }
            | GovernanceAction::RemoveMember { .. }
            | GovernanceAction::ChangeRole { .. }
            | GovernanceAction::RegisterTool { .. }
            | GovernanceAction::RemoveTool { .. }
            | GovernanceAction::ModifyCeiling { .. }
            | GovernanceAction::CloseContext { .. }
            | GovernanceAction::TransferAdmin { .. }
            | GovernanceAction::CreateChildContext { .. }
            | GovernanceAction::ModifyPruningPolicy { .. }
            | GovernanceAction::AddSigner { .. }
            | GovernanceAction::RemoveSigner { .. }
            | GovernanceAction::ModifyThreshold { .. }
            | GovernanceAction::EstablishToolInterface { .. }
            | GovernanceAction::ResetMember { .. }
            | GovernanceAction::ResolveConflict { .. }
            | GovernanceAction::RotateContentKeys { .. }
            | GovernanceAction::ReconfigureGovernance { .. }
            | GovernanceAction::ProposeContextMigration { .. }
            | GovernanceAction::CancelContextMigration => {
                self.dispatch_context_governance_action(context_id, &proposal.action, pid, actor)
                    .await
            }
        }
    }

    /// Dispatches context-level governance actions to their implementation
    /// methods, returning typed [`GovernanceActionResult`] variants.
    ///
    /// Split into two methods to stay within the line limit:
    /// - This method handles membership, roles, settings, and structural
    ///   actions (13 variants).
    /// - [`dispatch_content_governance_action`] handles content access,
    ///   key rotation, conflict resolution, and reconfiguration (9 variants).
    #[allow(clippy::too_many_lines)]
    async fn dispatch_context_governance_action(
        &self,
        context_id: &str,
        action: &GovernanceAction,
        pid: ProposalId,
        actor_did: &str,
    ) -> Result<GovernanceActionResult, ContextError> {
        match action {
            GovernanceAction::AddMember { did, role } => {
                self.execute_add_member(context_id, did, role, pid, actor_did)
                    .await?;
                Ok(GovernanceActionResult::MemberAdded)
            }
            GovernanceAction::RemoveMember { did, .. } => {
                self.execute_remove_member(context_id, did, pid, actor_did)
                    .await?;
                Ok(GovernanceActionResult::MemberRemoved)
            }
            GovernanceAction::ChangeRole { did, new_role } => {
                self.execute_change_role(context_id, did, new_role, pid, actor_did)
                    .await?;
                Ok(GovernanceActionResult::RoleChanged)
            }
            GovernanceAction::RegisterTool { registration } => {
                self.execute_register_tool(context_id, registration, pid, actor_did)
                    .await?;
                Ok(GovernanceActionResult::ToolRegistered)
            }
            GovernanceAction::RemoveTool { tool_id } => {
                self.execute_remove_tool(context_id, tool_id, pid, actor_did)
                    .await?;
                Ok(GovernanceActionResult::ToolRemoved)
            }
            GovernanceAction::ModifyCeiling { new_ceiling } => {
                self.execute_modify_ceiling(context_id, new_ceiling, pid, actor_did)
                    .await?;
                Ok(GovernanceActionResult::CeilingModified)
            }
            GovernanceAction::CloseContext { reason } => {
                self.execute_close_context(context_id, reason.as_deref(), pid, actor_did)
                    .await?;
                Ok(GovernanceActionResult::ContextClosed)
            }
            GovernanceAction::TransferAdmin { new_admin } => {
                self.execute_transfer_admin(context_id, new_admin, pid, actor_did)
                    .await?;
                Ok(GovernanceActionResult::AdminTransferred)
            }
            GovernanceAction::CreateChildContext { params } => {
                self.execute_create_child_context(context_id, params, pid, actor_did)
                    .await?;
                Ok(GovernanceActionResult::ChildContextCreated)
            }
            GovernanceAction::ModifyPruningPolicy { new_policy } => {
                self.execute_modify_pruning_policy(context_id, new_policy, pid, actor_did)
                    .await?;
                Ok(GovernanceActionResult::PruningPolicyModified)
            }
            GovernanceAction::ProposeContextMigration {
                new_context_params,
                reason,
                grace_period_secs,
                auto_invite,
            } => {
                let result = self
                    .execute_propose_context_migration(
                        context_id,
                        new_context_params,
                        reason,
                        *grace_period_secs,
                        *auto_invite,
                        pid,
                        actor_did,
                    )
                    .await?;
                Ok(GovernanceActionResult::MigrationProposed(result))
            }
            GovernanceAction::CancelContextMigration => {
                self.execute_cancel_context_migration(context_id, pid, actor_did)
                    .await?;
                Ok(GovernanceActionResult::MigrationCancelled)
            }
            // Content access, structural, and reconfiguration actions
            // are dispatched by the companion method.
            GovernanceAction::AddSigner { .. }
            | GovernanceAction::RemoveSigner { .. }
            | GovernanceAction::ModifyThreshold { .. }
            | GovernanceAction::EstablishToolInterface { .. }
            | GovernanceAction::ResetMember { .. }
            | GovernanceAction::ResolveConflict { .. }
            | GovernanceAction::RotateContentKeys { .. }
            | GovernanceAction::ReconfigureGovernance { .. } => {
                self.dispatch_content_governance_action(context_id, action, pid, actor_did)
                    .await
            }
            // SuspendMember, Revoke, RestoreAccess, PromoteContext, ExtendTtl,
            // economic, and rate-limit actions are handled in
            // dispatch_governance_action.
            GovernanceAction::PromoteContext
            | GovernanceAction::ExtendTtl { .. }
            | GovernanceAction::SuspendCapability { .. }
            | GovernanceAction::SuspendAccess { .. }
            | GovernanceAction::RevokeAccess { .. }
            | GovernanceAction::RestoreAccess { .. }
            | GovernanceAction::SetEconomicPolicy { .. }
            | GovernanceAction::ApproveSpend { .. }
            | GovernanceAction::LockEconomicPolicy
            | GovernanceAction::ModifyHardRateLimit { .. } => {
                unreachable!("handled in dispatch_governance_action")
            }
        }
    }

    /// Dispatches content access, structural, and reconfiguration governance
    /// actions. Companion to [`dispatch_context_governance_action`].
    #[allow(clippy::too_many_lines)]
    async fn dispatch_content_governance_action(
        &self,
        context_id: &str,
        action: &GovernanceAction,
        pid: ProposalId,
        actor_did: &str,
    ) -> Result<GovernanceActionResult, ContextError> {
        match action {
            GovernanceAction::AddSigner { did } => {
                self.execute_add_signer(context_id, did, pid, actor_did)
                    .await?;
                Ok(GovernanceActionResult::SignerAdded)
            }
            GovernanceAction::RemoveSigner { did } => {
                self.execute_remove_signer(context_id, did, pid, actor_did)
                    .await?;
                Ok(GovernanceActionResult::SignerRemoved)
            }
            GovernanceAction::ModifyThreshold { new_threshold } => {
                self.execute_modify_threshold(context_id, *new_threshold, pid, actor_did)
                    .await?;
                Ok(GovernanceActionResult::ThresholdModified)
            }
            GovernanceAction::EstablishToolInterface { interface } => {
                self.execute_establish_tool_interface(context_id, interface, pid, actor_did)
                    .await?;
                Ok(GovernanceActionResult::ToolInterfaceEstablished)
            }
            GovernanceAction::ResetMember { did, reason } => {
                self.execute_reset_member(context_id, did, reason, pid, actor_did)
                    .await?;
                Ok(GovernanceActionResult::MemberReset)
            }
            GovernanceAction::ResolveConflict {
                proposal_a,
                proposal_b,
                resolution,
            } => {
                self.execute_resolve_conflict(
                    context_id, proposal_a, proposal_b, resolution, pid, actor_did,
                )
                .await?;
                Ok(GovernanceActionResult::ConflictResolved)
            }
            GovernanceAction::RotateContentKeys { reason } => {
                self.execute_rotate_content_keys(context_id, reason.as_deref(), pid, actor_did)
                    .await?;
                Ok(GovernanceActionResult::ContentKeysRotated(
                    ContentKeysRotatedResult {
                        reason: reason.clone(),
                    },
                ))
            }
            GovernanceAction::ReconfigureGovernance {
                changes,
                justification,
            } => {
                self.execute_reconfigure_governance(
                    context_id,
                    changes,
                    justification,
                    pid,
                    actor_did,
                )
                .await?;
                Ok(GovernanceActionResult::GovernanceReconfigured(
                    GovernanceReconfiguredResult {
                        changes_applied: changes.len(),
                    },
                ))
            }
            // Variants handled by dispatch_governance_action or
            // dispatch_context_governance_action — exhaustive listing
            // for compile-time coverage (no wildcard).
            GovernanceAction::PromoteContext
            | GovernanceAction::ExtendTtl { .. }
            | GovernanceAction::SuspendCapability { .. }
            | GovernanceAction::SuspendAccess { .. }
            | GovernanceAction::RevokeAccess { .. }
            | GovernanceAction::RestoreAccess { .. }
            | GovernanceAction::SetEconomicPolicy { .. }
            | GovernanceAction::ApproveSpend { .. }
            | GovernanceAction::LockEconomicPolicy
            | GovernanceAction::AddMember { .. }
            | GovernanceAction::RemoveMember { .. }
            | GovernanceAction::ChangeRole { .. }
            | GovernanceAction::RegisterTool { .. }
            | GovernanceAction::RemoveTool { .. }
            | GovernanceAction::ModifyCeiling { .. }
            | GovernanceAction::CloseContext { .. }
            | GovernanceAction::TransferAdmin { .. }
            | GovernanceAction::CreateChildContext { .. }
            | GovernanceAction::ModifyPruningPolicy { .. }
            | GovernanceAction::ProposeContextMigration { .. }
            | GovernanceAction::CancelContextMigration
            | GovernanceAction::ModifyHardRateLimit { .. } => {
                unreachable!(
                    "action variant handled by dispatch_governance_action \
                     or dispatch_context_governance_action"
                )
            }
        }
    }

    /// Builds a [`GovernanceContext`] snapshot for the governance engine from
    /// the current per-context state.
    fn build_governance_context(ctx: &PerContextState, clock: &dyn Clock) -> GovernanceContext {
        let members: Vec<(DID, String)> = ctx
            .membership
            .members()
            .map(|m| (m.did.clone(), m.role_name.clone()))
            .collect();
        let admin_dids: Vec<DID> = ctx
            .membership
            .members()
            .filter(|m| m.role_name == "admin")
            .map(|m| m.did.clone())
            .collect();
        GovernanceContext {
            context_id: ctx.handle.context_id().to_owned(),
            members,
            admin_dids,
            current_epoch: Some(ctx.epoch.mls_epoch),
            now: clock.now_secs(),
        }
    }

    /// Proposes a governance action on a context.
    ///
    /// Creates a proposal through the context's governance engine. For
    /// `SingleAdmin` contexts, the proposal is auto-approved and the
    /// action is immediately executed. For multi-party governance models,
    /// the proposal enters `Pending` status and waits for votes.
    ///
    /// # Arguments
    ///
    /// * `context_id` -- The context to propose on.
    /// * `action` -- The governance action to propose.
    /// * `proposer_did` -- The DID of the proposer.
    /// * `signing_key` -- Ed25519 key for signing the proposer's implicit vote.
    ///
    /// # Returns
    ///
    /// The created [`GovernanceProposal`] (which may already be `Approved` for
    /// `SingleAdmin` contexts) and any [`GovernanceEvent`]s produced.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::GovernanceFailed`] if the proposer lacks authority or
    ///   the action is invalid.
    #[instrument(skip_all, fields(context_id))]
    pub async fn propose_governance_action(
        &self,
        context_id: &str,
        proposer_did: &DID,
        action: GovernanceAction,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<
        (
            GovernanceProposal,
            Vec<GovernanceEvent>,
            Option<GovernanceActionResult>,
        ),
        ContextError,
    > {
        self.propose_governance_action_inner(context_id, proposer_did, action, signing_key)
            .await
    }

    /// Inner implementation of proposal submission with auto-execution.
    ///
    /// Returns the proposal, events, and optional execution result. The
    /// execution result is `Some` when the proposal was auto-approved
    /// (`SingleAdmin`) and the action was successfully executed.
    #[allow(clippy::too_many_lines)]
    async fn propose_governance_action_inner(
        &self,
        context_id: &str,
        proposer_did: &DID,
        action: GovernanceAction,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<
        (
            GovernanceProposal,
            Vec<GovernanceEvent>,
            Option<GovernanceActionResult>,
        ),
        ContextError,
    > {
        let (proposal, events, should_execute, invalidated_by_conflict, in_freeze, conflict_events) = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;

            // CancelContextMigration is allowed during MigratingOut (§5.11A);
            // all other actions require Active state.
            if matches!(action, GovernanceAction::CancelContextMigration) {
                require_migrating_out(&ctx.handle)?;
            } else {
                require_active(&ctx.handle)?;
            }

            // Presence-only members (read + write both suspended) lose
            // GovernancePropose capability (§5.9, ADR-038, spec §05-contexts).
            // Eligibility for the specific governance role/signer set is
            // checked by the governance engine itself; this layer only
            // enforces the presence-only state — a member who can neither
            // read nor write content cannot propose governance actions on
            // content they cannot see.
            if ctx
                .role_state
                .suspended_capabilities
                .get(proposer_did.as_ref())
                .is_some_and(|s| {
                    s.contains(&Capability::MessagesRead) && s.contains(&Capability::MessagesWrite)
                })
            {
                return Err(ContextError::PermissionDenied(
                    "presence-only members cannot propose governance actions".into(),
                ));
            }

            // Eligibility check: verify proposer satisfies pending-removal
            // and participation gates before allowing new proposals (#1530).
            check_proposer_eligibility(ctx, proposer_did, self.clock.now_secs(), &*self.event_log)?;

            // SCP-272: Check and auto-resolve expired governance freezes (48-hour timeout).
            let freeze_events = self.check_and_resolve_expired_freezes(ctx);
            if !freeze_events.is_empty() {
                let cid_bytes = context_id_to_bytes(context_id);
                for event in &freeze_events {
                    if let GovernanceEvent::ConflictResolved { .. } = event {
                        self.event_log.append_context_event(
                            &cid_bytes,
                            "GovernanceFreezeExpired",
                            proposer_did.as_ref(),
                        )?;
                        ctx.checkpoint_events_since += 1;
                    }
                }
            }

            // SCP-272: Block new proposals (except ResolveConflict) while governance is frozen.
            if ctx.governance.freeze.is_some()
                && !matches!(action, GovernanceAction::ResolveConflict { .. })
            {
                return Err(ContextError::GovernanceFailed(
                    "governance is frozen due to simultaneous conflict — only ResolveConflict proposals are accepted".into(),
                ));
            }

            let gov_ctx = Self::build_governance_context(ctx, &*self.clock);

            let (proposal, events) = ctx
                .governance
                .engine
                .propose(proposer_did, action, &gov_ctx, signing_key)
                .map_err(|e| ContextError::GovernanceFailed(e.to_string()))?;

            // Record proposal timestamp for earned capacity rate limiting (§9.3).
            ctx.governance
                .proposal_timestamps
                .entry(proposer_did.to_string())
                .or_default()
                .push(self.clock.now_secs());

            let should_execute = proposal.status == ProposalStatus::Approved;

            let conflict_events = if should_execute {
                self.detect_and_handle_conflicts(ctx, &proposal)
            } else {
                Vec::new()
            };

            // Check if the proposal was invalidated by conflict detection
            let invalidated_by_conflict = conflict_events.iter().any(|e| {
                matches!(e, GovernanceEvent::ConflictResolved { loser_id, .. } if *loser_id == proposal.proposal_id)
            });

            let in_freeze = ctx.governance.freeze.is_some();

            (
                proposal,
                events,
                should_execute,
                invalidated_by_conflict,
                in_freeze,
                conflict_events,
            )
        };
        // Lock dropped.

        // Emit conflict events to the event log.
        if !conflict_events.is_empty() {
            let context_id_bytes = context_id_to_bytes(context_id);
            let mut conflict_event_count: u64 = 0;
            for event in &conflict_events {
                match event {
                    GovernanceEvent::ConflictDetected { .. } => {
                        self.event_log.append_context_event(
                            &context_id_bytes,
                            "GovernanceConflictDetected",
                            proposer_did.as_ref(),
                        )?;
                        conflict_event_count += 1;
                    }
                    GovernanceEvent::ConflictResolved { .. } => {
                        self.event_log.append_context_event(
                            &context_id_bytes,
                            "GovernanceConflictResolved",
                            proposer_did.as_ref(),
                        )?;
                        conflict_event_count += 1;
                    }
                    _ => {}
                }
            }
            if conflict_event_count > 0
                && let Some(entry) = self.contexts.get(context_id)
            {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += conflict_event_count;
            }
        }

        // If the proposal was auto-approved (SingleAdmin), execute immediately
        // — unless it was invalidated by conflict or governance is frozen.
        let execution_result = if should_execute && !invalidated_by_conflict && !in_freeze {
            Some(
                self.execute_governance_action(context_id, &proposal)
                    .await?,
            )
        } else {
            None
        };

        // Persist context state after proposal creation.
        if self.has_persistence()
            && let Some(entry) = self.contexts.get(context_id)
        {
            let ctx_arc = Arc::clone(entry.value());
            drop(entry);
            let guard = ctx_arc.lock().await;
            let ctx = &*guard;
            let snapshot = Self::snapshot_context(ctx);
            self.persist_context_snapshot(context_id, snapshot);
        }

        Ok((proposal, events, execution_result))
    }

    /// Casts a vote on a pending governance proposal.
    ///
    /// Submits an approval or rejection vote through the context's governance
    /// engine. If the vote causes the proposal to reach quorum (approved) or
    /// become impossible to approve (rejected), the proposal transitions to
    /// its terminal state. When approved, the action is auto-executed.
    ///
    /// # Arguments
    ///
    /// * `context_id` -- The context containing the proposal.
    /// * `proposal_id` -- The ID of the proposal to vote on.
    /// * `voter_did` -- The DID of the voter.
    /// * `approve` -- `true` for approval, `false` for rejection.
    /// * `signing_key` -- Ed25519 key for signing the vote.
    ///
    /// # Returns
    ///
    /// The updated [`ProposalStatus`] and any [`GovernanceEvent`]s produced.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::GovernanceFailed`] if the voter is not eligible,
    ///   already voted, or the proposal is not pending.
    #[allow(clippy::too_many_lines)]
    #[instrument(skip_all, fields(context_id))]
    pub async fn vote_on_proposal(
        &self,
        context_id: &str,
        proposal_id: &ProposalId,
        voter_did: &DID,
        approve: bool,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(ProposalStatus, Vec<GovernanceEvent>), ContextError> {
        let (status, events, proposal_for_execution, conflict_events) = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;

            require_active(&ctx.handle)?;

            // Suspended members lose GovernanceVote capability (§5.9,
            // ADR-038). The runtime layer only enforces the suspension
            // overlay here; role-based eligibility (signer set, admin
            // status) is checked by the governance engine itself, which
            // returns `GovernanceFailed` for non-eligible voters.
            //
            // Presence-only members (both MessagesRead and MessagesWrite
            // suspended) also lose GovernanceVote per spec §05-contexts.
            let suspended = ctx
                .role_state
                .suspended_capabilities
                .get(voter_did.as_ref());
            if suspended.is_some_and(|s| s.contains(&Capability::GovernanceVote)) {
                return Err(ContextError::PermissionDenied(
                    "member does not have governance:vote capability".into(),
                ));
            }
            if suspended.is_some_and(|s| {
                s.contains(&Capability::MessagesRead) && s.contains(&Capability::MessagesWrite)
            }) {
                return Err(ContextError::PermissionDenied(
                    "presence-only members cannot vote on governance proposals".into(),
                ));
            }

            let gov_ctx = Self::build_governance_context(ctx, &*self.clock);

            let (status, events) = if approve {
                ctx.governance
                    .engine
                    .approve(proposal_id, voter_did, &gov_ctx, signing_key)
                    .map_err(|e| ContextError::GovernanceFailed(e.to_string()))?
            } else {
                ctx.governance
                    .engine
                    .reject(proposal_id, voter_did, &gov_ctx, signing_key)
                    .map_err(|e| ContextError::GovernanceFailed(e.to_string()))?
            };

            // If the proposal just became Approved, grab a clone for conflict detection and execution.
            let proposal_for_execution = if status == ProposalStatus::Approved {
                ctx.governance.engine.get_proposal(proposal_id).cloned()
            } else {
                None
            };

            // If we have a newly approved proposal, check for conflicts with other approved proposals
            let conflict_events = proposal_for_execution
                .as_ref()
                .map_or_else(Vec::new, |proposal| {
                    self.detect_and_handle_conflicts(ctx, proposal)
                });

            (status, events, proposal_for_execution, conflict_events)
        };
        // Lock dropped.

        // Emit conflict events to the event log (mirrors propose_governance_action_inner).
        if !conflict_events.is_empty() {
            let context_id_bytes = context_id_to_bytes(context_id);
            let mut conflict_event_count: u64 = 0;
            for event in &conflict_events {
                match event {
                    GovernanceEvent::ConflictDetected { .. } => {
                        self.event_log.append_context_event(
                            &context_id_bytes,
                            "GovernanceConflictDetected",
                            voter_did.as_ref(),
                        )?;
                        conflict_event_count += 1;
                    }
                    GovernanceEvent::ConflictResolved { .. } => {
                        self.event_log.append_context_event(
                            &context_id_bytes,
                            "GovernanceConflictResolved",
                            voter_did.as_ref(),
                        )?;
                        conflict_event_count += 1;
                    }
                    _ => {}
                }
            }
            if conflict_event_count > 0
                && let Some(entry) = self.contexts.get(context_id)
            {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += conflict_event_count;
            }
        }

        // Check if the proposal was invalidated by conflict detection.
        let invalidated_by_conflict = conflict_events.iter().any(|e| {
            matches!(e, GovernanceEvent::ConflictResolved { loser_id, .. } if *loser_id == *proposal_id)
        });

        // Auto-execute if the proposal was just approved and we're not in governance freeze
        // — unless it was invalidated by conflict.
        if let Some(proposal) = proposal_for_execution {
            // Check if we're in governance freeze before executing
            let in_freeze = {
                if let Some(ctx_entry) = self.contexts.get(context_id) {
                    let ctx_arc = Arc::clone(ctx_entry.value());
                    drop(ctx_entry);
                    let guard = ctx_arc.lock().await;
                    let ctx = &*guard;
                    ctx.governance.freeze.is_some()
                } else {
                    false
                }
            };

            if !in_freeze && !invalidated_by_conflict {
                self.execute_governance_action(context_id, &proposal)
                    .await?;
            }
        }

        // Persist context state after vote.
        if self.has_persistence()
            && let Some(entry) = self.contexts.get(context_id)
        {
            let ctx_arc = Arc::clone(entry.value());
            drop(entry);
            let guard = ctx_arc.lock().await;
            let ctx = &*guard;
            let snapshot = Self::snapshot_context(ctx);
            self.persist_context_snapshot(context_id, snapshot);
        }

        Ok((status, events))
    }

    /// Retrieves a governance proposal by ID.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] if the context is not registered.
    /// - [`ContextError::GovernanceFailed`] if the proposal is not found.
    #[instrument(skip_all, fields(context_id))]
    pub async fn get_proposal(
        &self,
        context_id: &str,
        proposal_id: &ProposalId,
    ) -> Result<GovernanceProposal, ContextError> {
        let ctx_arc = self
            .get_context_arc(context_id)
            .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
        let guard = ctx_arc.lock().await;
        let ctx = &*guard;

        ctx.governance
            .engine
            .get_proposal(proposal_id)
            .cloned()
            .ok_or_else(|| {
                ContextError::GovernanceFailed(format!(
                    "proposal not found: {}",
                    hex::encode(proposal_id)
                ))
            })
    }

    /// Lists all governance proposals for a context.
    ///
    /// Returns both pending and resolved proposals tracked by the governance
    /// engine. Note that engines only retain proposals in memory; for durable
    /// access, proposals should be queried from the event log.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] if the context is not registered.
    #[instrument(skip_all, fields(context_id))]
    pub async fn list_proposals(
        &self,
        context_id: &str,
    ) -> Result<Vec<GovernanceProposal>, ContextError> {
        let ctx_arc = self
            .get_context_arc(context_id)
            .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
        let guard = ctx_arc.lock().await;
        let ctx = &*guard;

        Ok(ctx.governance.engine.list_proposals())
    }

    /// Submits a new governance proposal with capability validation.
    ///
    /// Validates that the proposer holds the `GovernancePropose` capability
    /// (UCAN) before delegating to the governance engine. The
    /// suspension-aware `member_has_capability` check rejects both members
    /// whose role does not grant the capability AND members whose
    /// capability is currently suspended (e.g., presence-only members per
    /// spec §05-contexts and ADR-038). Returns a [`ProposalOutcome`]
    /// containing the proposal, its status, and an optional execution result.
    ///
    /// For `SingleAdmin`, the proposal is simultaneously created and approved
    /// (ADR-031 section 4a). The action is auto-executed and the result is
    /// returned in `ProposalOutcome::execution_result`. For multi-admin
    /// models, the proposal enters `Pending` status and `execution_result`
    /// is `None` until the proposal is approved via votes.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::ContextNotRegistered`] if the context is not registered.
    /// - [`ContextError::PermissionDenied`] if the proposer lacks
    ///   `GovernancePropose` capability.
    #[instrument(skip_all, fields(context_id))]
    pub async fn propose_governance_action_checked(
        &self,
        context_id: &str,
        proposer_did: &DID,
        action: GovernanceAction,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<ProposalOutcome, ContextError> {
        // Validate capability before delegating. The suspension-aware
        // member_has_capability also rejects presence-only members whose
        // GovernancePropose capability has been suspended (§5.9, ADR-038).
        {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let guard = ctx_arc.lock().await;
            let ctx = &*guard;

            if !ctx
                .role_state
                .member_has_capability(proposer_did.as_ref(), &Capability::GovernancePropose)
            {
                return Err(ContextError::PermissionDenied(format!(
                    "member {proposer_did} does not have governance:propose capability"
                )));
            }
        }
        // Lock dropped.

        let (proposal, _events, execution_result) = self
            .propose_governance_action_inner(context_id, proposer_did, action, signing_key)
            .await?;

        let status = proposal.status.clone();
        Ok(ProposalOutcome {
            proposal,
            status,
            execution_result,
        })
    }

    /// Casts an approval vote on a pending governance proposal.
    ///
    /// Validates that the voter holds the `GovernanceVote` capability (UCAN)
    /// before delegating to the governance engine. Events are recorded in the
    /// context event log and the action is auto-executed if quorum is reached.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::ContextNotRegistered`] if the context is not registered.
    /// - [`ContextError::PermissionDenied`] if the voter lacks `GovernanceVote`
    ///   capability or the engine rejects the vote.
    #[instrument(skip_all, fields(context_id))]
    pub async fn approve_governance_proposal(
        &self,
        context_id: &str,
        proposal_id: &ProposalId,
        voter_did: &DID,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<ProposalStatus, ContextError> {
        // Validate capability before delegating.
        {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let guard = ctx_arc.lock().await;
            let ctx = &*guard;

            if !ctx
                .role_state
                .member_has_capability(voter_did.as_ref(), &Capability::GovernanceVote)
            {
                return Err(ContextError::PermissionDenied(format!(
                    "member {voter_did} does not have governance:vote capability"
                )));
            }
        }
        // Lock dropped.

        let (status, _events) = self
            .vote_on_proposal(context_id, proposal_id, voter_did, true, signing_key)
            .await?;

        Ok(status)
    }

    /// Casts a rejection vote on a pending governance proposal.
    ///
    /// Validates that the voter holds the `GovernanceVote` capability (UCAN)
    /// before delegating to the governance engine. Events are recorded in the
    /// context event log.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::ContextNotRegistered`] if the context is not registered.
    /// - [`ContextError::PermissionDenied`] if the voter lacks `GovernanceVote`
    ///   capability or the engine rejects the vote.
    #[instrument(skip_all, fields(context_id))]
    pub async fn reject_governance_proposal(
        &self,
        context_id: &str,
        proposal_id: &ProposalId,
        voter_did: &DID,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<ProposalStatus, ContextError> {
        // Validate capability before delegating.
        {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let guard = ctx_arc.lock().await;
            let ctx = &*guard;

            if !ctx
                .role_state
                .member_has_capability(voter_did.as_ref(), &Capability::GovernanceVote)
            {
                return Err(ContextError::PermissionDenied(format!(
                    "member {voter_did} does not have governance:vote capability"
                )));
            }
        }
        // Lock dropped.

        let (status, _events) = self
            .vote_on_proposal(context_id, proposal_id, voter_did, false, signing_key)
            .await?;

        Ok(status)
    }

    /// Withdraws a previously cast vote on a pending governance proposal.
    ///
    /// The voter must have already voted on this proposal. No signing key
    /// is required -- withdrawal is the voter's privileged operation on
    /// their own vote (per the `GovernanceEngine::withdraw_vote` trait).
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::ContextNotRegistered`] if the context is not registered.
    /// - [`ContextError::PermissionDenied`] if the engine rejects the
    ///   withdrawal (proposal not found, voter hasn't voted, etc.).
    #[instrument(skip_all, fields(context_id))]
    pub async fn withdraw_governance_vote(
        &self,
        context_id: &str,
        proposal_id: &ProposalId,
        voter_did: &DID,
    ) -> Result<ProposalStatus, ContextError> {
        let (status, events) = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            let gov_ctx = Self::build_governance_context(ctx, &*self.clock);
            ctx.governance
                .engine
                .withdraw_vote(proposal_id, voter_did, &gov_ctx)
                .map_err(|e| ContextError::PermissionDenied(e.to_string()))?
        };

        let context_id_bytes = context_id_to_bytes(context_id);
        let mut event_count: u64 = 0;
        for event in &events {
            self.event_log.append_context_event(
                &context_id_bytes,
                Self::governance_event_label(event),
                voter_did.as_ref(),
            )?;
            event_count += 1;
        }
        if event_count > 0
            && let Some(entry) = self.contexts.get(context_id)
        {
            let ctx_arc = Arc::clone(entry.value());
            drop(entry);
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            ctx.checkpoint_events_since += event_count;
        }

        // Persist context state after withdrawal.
        if self.has_persistence()
            && let Some(entry) = self.contexts.get(context_id)
        {
            let ctx_arc = Arc::clone(entry.value());
            drop(entry);
            let guard = ctx_arc.lock().await;
            let ctx = &*guard;
            let snapshot = Self::snapshot_context(ctx);
            self.persist_context_snapshot(context_id, snapshot);
        }

        Ok(status)
    }

    /// Executes a `SuspendMember` governance action.
    ///
    /// Suspends specific capabilities for a member via the role state's
    /// `suspend_capabilities` method. The member remains in the context
    /// but the suspended capabilities are blocked at the application-level
    /// gates (`send_message`, `deliver_incoming`, etc.).
    ///
    /// Requires the `MemberBan` capability in the context's ceiling (§5.3).
    async fn execute_suspend_member(
        &self,
        context_id: &str,
        did: &DID,
        capabilities: &[Capability],
        _proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            if !ctx.role_state.ceiling.contains(&Capability::MemberBan) {
                return Err(ContextError::PermissionDenied(
                    "member:ban (MemberBan) capability not in ceiling".to_owned(),
                ));
            }
            if !ctx.membership.contains(did) {
                return Err(ContextError::MemberNotFound(did.to_string()));
            }

            ctx.role_state
                .suspend_capabilities(did.as_ref(), capabilities.iter().cloned());

            // Emit a capability-precise suspension event carrying the
            // exact capability list so consumers can render accurate
            // UI and so the event payload matches the underlying
            // role_state mutation.
            ctx.receive_buffer
                .push(ContextEvent::CapabilitiesSuspended {
                    did: did.clone(),
                    capabilities: capabilities.to_vec(),
                });

            if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            }
        };

        if let Some(snapshot) = snapshot {
            self.persist_context_snapshot(context_id, snapshot);
        }
        self.event_log
            .append_context_event(&context_id_bytes, "MemberSuspended", actor_did)?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }
        Ok(())
    }

    /// Executes a `Revoke` governance action — cryptographic key destruction.
    ///
    /// Works in both broadcast and encrypted contexts (ADR-038, §9.17):
    /// - **Write scope**: suspends write capabilities and destroys sender/broadcast
    ///   keys so the member cannot publish. In broadcast mode, also calls
    ///   `block_author` for key rotation.
    /// - **Read scope**: destroys access keys and adds to CEK exclusion list.
    ///   In broadcast mode, bans the subscriber with key rotation.
    /// - **Both scope**: applies both write and read revocation.
    ///
    /// Additionally suspends the corresponding capabilities via `role_state`
    /// so application-level gates also block the member.
    ///
    /// Requires the `MemberBan` capability in the context's ceiling (§5.3).
    ///
    /// Returns the number of rotated authors (for broadcast contexts).
    #[allow(clippy::too_many_lines)]
    async fn execute_revoke(
        &self,
        context_id: &str,
        did: &DID,
        access: AccessScope,
        _proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<usize, ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let (rotated_count, ctx_snapshot, bc_snapshot, needs_sender_key_rotation) = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            if !ctx.role_state.ceiling.contains(&Capability::MemberBan) {
                return Err(ContextError::PermissionDenied(
                    "member:ban (MemberBan) capability not in ceiling".to_owned(),
                ));
            }
            if !ctx.membership.contains(did) {
                return Err(ContextError::MemberNotFound(did.to_string()));
            }

            let mut rotated = 0usize;
            let mut bc_snap = None;

            // Write revocation: suspend write capabilities and, in
            // broadcast contexts, block the author so the BroadcastContext
            // also rejects new publishes and key requests for the blocked
            // author. Spec §05-contexts §5.9: revocation removes publishing
            // authority. Historical messages remain decryptable by
            // subscribers who already cached the broadcast key.
            if matches!(access, AccessScope::Write | AccessScope::Both) {
                ctx.role_state
                    .suspend_capabilities(did.as_ref(), [Capability::MessagesWrite]);

                if let Some(ref mut bc) = ctx.broadcast_context {
                    match bc.block_author(&did.0) {
                        Ok(_) | Err(ContextError::MemberNotFound(_)) => {}
                        Err(e) => return Err(e),
                    }
                    if self.has_persistence() {
                        bc_snap = Some(bc.to_snapshot());
                    }
                }

                ctx.receive_buffer
                    .push(ContextEvent::WriteAccessRevoked { did: did.clone() });
            }

            // Read revocation: suspend read capabilities + destroy access keys.
            if matches!(access, AccessScope::Read | AccessScope::Both) {
                ctx.role_state
                    .suspend_capabilities(did.as_ref(), [Capability::MessagesRead]);

                // CEK exclusion list for cryptographic enforcement.
                ctx.access.read_exclusion_list.insert(did.clone());

                // Broadcast mode: ban subscriber with key rotation. The
                // target may be an author rather than a subscriber — in
                // that case the read-side ban is a no-op (authors are
                // handled by `block_author` under `Both`).
                if let Some(ref mut bc) = ctx.broadcast_context {
                    match bc.governance_ban_subscriber(&did.0, access) {
                        Ok(r) => {
                            rotated = r.rotated_authors.len();
                        }
                        Err(ContextError::MemberNotFound(_)) => {}
                        Err(e) => return Err(e),
                    }
                    if self.has_persistence() {
                        bc_snap = Some(bc.to_snapshot());
                    }
                } else {
                    // Encrypted mode: destroy the member's access key.
                    ctx.access.access_key_store.remove(context_id, did.as_ref());
                }

                ctx.receive_buffer
                    .push(ContextEvent::ReadAccessRevoked { did: did.clone() });
                ctx.receive_buffer
                    .push(ContextEvent::AccessKeyRevoked { did: did.clone() });
            }

            // Encrypted non-broadcast mode: Write and Both revocations need a
            // sender key rotation so the revoked member cannot decrypt future
            // messages at the sender-key layer (defense-in-depth per §9.17).
            // Broadcast mode handles key rotation through its own block_author /
            // governance_ban_subscriber paths above, so we only rotate here for
            // encrypted contexts. Read-only revocations do not need rotation
            // because the member was never an encryptor.
            let rotate = matches!(access, AccessScope::Write | AccessScope::Both)
                && ctx.broadcast_context.is_none();

            let snap = if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            };
            (rotated, snap, bc_snap, rotate)
        };

        if let Some(ctx_snapshot) = ctx_snapshot {
            self.persist_context_snapshot(context_id, ctx_snapshot);
        }
        if let Some(ref bc_snap) = bc_snapshot {
            self.persist_broadcast_snapshot(context_id, bc_snap);
        }
        self.event_log.append_context_event_with_payload(
            &context_id_bytes,
            "AccessRevoked",
            actor_did,
            Some(&serde_json::json!({"target_did": did.as_ref()})),
        )?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }

        // H7: Rotate sender key after write-side revocation so the revoked
        // member cannot decrypt future messages at the sender-key layer
        // (defense-in-depth per §9.17). Non-fatal: MLS membership is unchanged
        // during revoke, so rotation failure does not leave the group in an
        // inconsistent state — warn and continue.
        if needs_sender_key_rotation {
            if let Err(e) = self.crypto.rotate_sender_key(&context_id_bytes) {
                tracing::warn!(
                    context_id = %context_id,
                    error = %e,
                    "rotate_sender_key failed after access revocation"
                );
            }
            if let Err(e) = self.drain_and_deliver_sender_keys(context_id, &context_id_bytes) {
                tracing::warn!(
                    context_id = %context_id,
                    error = %e,
                    "drain_and_deliver_sender_keys failed after access revocation"
                );
            }
        }

        Ok(rotated_count)
    }

    /// Executes a `RestoreAccess` governance action.
    ///
    /// Restores previously suspended capabilities and, for read revocations,
    /// generates a new access key (forward-only restoration, §9.16.8).
    /// Content encrypted during the revocation period remains permanently
    /// inaccessible.
    ///
    /// Requires the `MemberBan` capability in the context's ceiling (§5.3).
    async fn execute_restore_access(
        &self,
        context_id: &str,
        did: &DID,
        capabilities: &[Capability],
        _proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let (ctx_snapshot, bc_snapshot) = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            if !ctx.role_state.ceiling.contains(&Capability::MemberBan) {
                return Err(ContextError::PermissionDenied(
                    "member:ban (MemberBan) capability not in ceiling".to_owned(),
                ));
            }

            // Determine whether anything is actually suspended for this member.
            // Per spec §05-contexts §5.9: restore on a never-revoked member is
            // an error (NothingToRestore).
            let suspended_set = ctx.role_state.suspended_capabilities.get(did.as_ref());
            let nothing_suspended_for_request =
                suspended_set.is_none_or(|set| !capabilities.iter().any(|c| set.contains(c)));
            // Read-side: also check exclusion list (CEK exclusion).
            let read_excluded = ctx.access.read_exclusion_list.contains(did);
            let read_requested = capabilities.contains(&Capability::MessagesRead);
            if nothing_suspended_for_request && !(read_requested && read_excluded) {
                return Err(ContextError::NothingToRestore(format!(
                    "no suspended capabilities to restore for {did}"
                )));
            }

            // Restore the specified capabilities.
            ctx.role_state
                .restore_capabilities(did.as_ref(), capabilities);

            // If read capability is being restored, also restore access keys
            // and remove from exclusion list.
            let has_read = capabilities.contains(&Capability::MessagesRead);
            let bc_snap = if has_read {
                ctx.access.read_exclusion_list.remove(did);

                // Broadcast mode: unban subscriber.
                let snap = ctx.broadcast_context.as_mut().and_then(|bc| {
                    bc.governance_unban_subscriber(&did.0);
                    if self.has_persistence() {
                        Some(bc.to_snapshot())
                    } else {
                        None
                    }
                });

                // Encrypted mode: generate new access key (forward-only).
                if ctx.broadcast_context.is_none() {
                    let restored_key = scp_protocol::crypto::access_keys::generate_access_key(
                        context_id,
                        did.as_ref(),
                    );
                    ctx.access
                        .access_key_store
                        .set(context_id, did.as_ref(), restored_key);
                }

                ctx.receive_buffer
                    .push(ContextEvent::ReadAccessRestored { did: did.clone() });
                ctx.receive_buffer.push(ContextEvent::AccessKeyRestored {
                    did: did.clone(),
                    new_epoch: 1,
                });

                snap
            } else {
                None
            };

            if capabilities.contains(&Capability::MessagesWrite) {
                ctx.receive_buffer
                    .push(ContextEvent::WriteAccessRestored { did: did.clone() });
            }

            let snap = if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            };
            (snap, bc_snap)
        };

        if let Some(ctx_snapshot) = ctx_snapshot {
            self.persist_context_snapshot(context_id, ctx_snapshot);
        }
        if let Some(ref bc_snap) = bc_snapshot {
            self.persist_broadcast_snapshot(context_id, bc_snap);
        }
        self.event_log
            .append_context_event(&context_id_bytes, "AccessRestored", actor_did)?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }

        Ok(())
    }

    async fn execute_add_member(
        &self,
        context_id: &str,
        did: &DID,
        role: &str,
        _proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            // Crypto: add to MLS group under lock to prevent partial-failure
            // window (phantom MLS member if state mutation fails).
            let add_output = self
                .crypto
                .add_member(&context_id_bytes, did, None)
                .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

            // Add to role state.
            ctx.role_state.members.insert(did.to_string());
            // H2: Use system_assign_role to bypass the RoleAssign capability
            // check. The governance engine has already authorized this action
            // via quorum — re-checking RoleAssign against the creator would
            // silently 500-out approved proposals whenever the creator has
            // been demoted, removed, or never held RoleAssign. See
            // `enforce_assign_role` (line 74) for the matching consequence
            // path that already uses this pattern.
            let tokens = roles::system_assign_role(&mut ctx.role_state, did, role, &*self.clock)
                .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;
            // creator_did is still consumed below by push_welcome_event for
            // the WelcomeGenerated provenance field.
            let creator_did = ctx.role_state.creator_did.clone();

            // Add to membership tracking.
            ctx.membership
                .add_member(did.clone(), role.to_owned(), tokens);

            // Generate access key for the new member (§9.17.2 step 1).
            let access_key =
                scp_protocol::crypto::access_keys::generate_access_key(context_id, did.as_ref());
            ctx.access
                .access_key_store
                .set(context_id, did.as_ref(), access_key);

            ctx.receive_buffer.push(ContextEvent::MemberJoined {
                member_did: did.clone(),
                role_name: role.to_owned(),
            });

            // Emit WelcomeGenerated event if the add produced a Welcome message.
            push_welcome_event(
                &mut ctx.receive_buffer,
                context_id,
                &DID(creator_did),
                did,
                add_output,
            );

            if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            }
        };

        if let Some(snapshot) = snapshot {
            self.persist_context_snapshot(context_id, snapshot);
        }
        self.event_log
            .append_context_event(&context_id_bytes, "MemberJoined", actor_did)?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }
        Ok(())
    }

    async fn execute_remove_member(
        &self,
        context_id: &str,
        did: &DID,
        _proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let (remove_output, snapshot) = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            if !ctx.membership.contains(did) {
                return Err(ContextError::MemberNotFound(did.to_string()));
            }

            // H9: MLS group removal FIRST (hard security boundary). If this
            // fails, we abort without touching sender keys. MLS removal is
            // the cryptographic enforcement that prevents the removed member
            // from decrypting future group messages.
            let remove_output = self
                .crypto
                .remove_member(&context_id_bytes, did)
                .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

            // Sender key cleanup is best-effort: log failures but do not
            // propagate. The MLS removal above is the hard boundary; sender
            // key removal is defense-in-depth for the independent sender key
            // confidentiality layer (§9.16).
            if let Err(e) = self
                .crypto
                .remove_member_sender_key(&context_id_bytes, did.as_ref())
            {
                tracing::warn!(
                    context_id,
                    member = %did,
                    error = %e,
                    "remove_member_sender_key failed after MLS removal — \
                     sender key layer may retain stale key"
                );
            }

            // Rotate the local sender key so the removed member cannot
            // decrypt future messages (§9.16.4). Generates a fresh key,
            // increments the epoch, and HPKE-seals to remaining members.
            //
            // Non-fatal: MLS removal above is the hard security boundary.
            // If rotation fails after MLS removal succeeded, returning Err
            // would leave the system inconsistent (member removed from MLS
            // but governance action appears to have failed).
            if let Err(e) = self.crypto.rotate_sender_key(&context_id_bytes) {
                tracing::warn!(
                    context_id,
                    error = %e,
                    "rotate_sender_key failed after member removal — \
                     remaining members retain old sender key"
                );
            }

            ctx.membership.remove_member(did);
            ctx.role_state.members.remove(did.as_ref());
            ctx.role_state.assignments.remove(did.as_ref());
            ctx.role_state.member_capabilities.remove(did.as_ref());

            // Destroy the removed member's access key (§9.17.2, ADR-038).
            ctx.access.access_key_store.remove(context_id, did.as_ref());

            ctx.receive_buffer.push(ContextEvent::MemberLeft {
                member_did: did.clone(),
            });

            (
                remove_output,
                if self.has_persistence() {
                    Some(Self::snapshot_context(ctx))
                } else {
                    None
                },
            )
        };

        // Broadcast the MLS Commit to remaining members so they can
        // advance their group epoch and ratchet key material. PR #1606 C6:
        // on transport failure, the commit is durably enqueued for retry
        // and the context fail-closes only after MAX_COMMIT_RETRIES /
        // MAX_COMMIT_AGE_SECS exhaust.
        self.try_broadcast_commit_or_enqueue(
            context_id,
            remove_output.commit_bytes,
            CommitOperation::RemoveMember {
                target_did: did.clone(),
            },
            actor_did,
        )
        .await?;

        // Drain pending sender key distribution messages queued by
        // rotate_sender_key, MLS-encrypt, and deliver via transport (§9.16.2).
        if let Err(e) = self.drain_and_deliver_sender_keys(context_id, &context_id_bytes) {
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to deliver rotated sender keys after member removal"
            );
        }

        if let Some(snapshot) = snapshot {
            self.persist_context_snapshot(context_id, snapshot);
        }
        self.event_log
            .append_context_event(&context_id_bytes, "MemberLeft", actor_did)?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }
        Ok(())
    }

    async fn execute_change_role(
        &self,
        context_id: &str,
        did: &DID,
        new_role: &str,
        _proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            if !ctx.membership.contains(did) {
                return Err(ContextError::MemberNotFound(did.to_string()));
            }

            // Re-assign via the role engine (validates role exists, updates
            // assignments and member_capabilities).
            //
            // H2: Use system_assign_role to bypass the RoleAssign capability
            // check. The governance engine has already authorized this action
            // via quorum — re-checking RoleAssign against the creator would
            // silently 500-out approved proposals whenever the creator has
            // been demoted, removed, or never held RoleAssign. See
            // `enforce_assign_role` (line 74) for the matching consequence
            // path that already uses this pattern.
            let tokens =
                roles::system_assign_role(&mut ctx.role_state, did, new_role, &*self.clock)
                    .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

            // Update membership tracking with new role.
            if let Some(info) = ctx.membership.get_mut(did) {
                new_role.clone_into(&mut info.role_name);
                info.tokens = tokens;
            }

            if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            }
        };

        if let Some(snapshot) = snapshot {
            self.persist_context_snapshot(context_id, snapshot);
        }
        self.event_log
            .append_context_event(&context_id_bytes, "RoleAssigned", actor_did)?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }
        Ok(())
    }

    /// Registers a tool in the context. Requires `ToolRegister` in the
    /// context's ceiling (§5.3). Without this capability in the ceiling,
    /// the context does not support tool registration.
    pub(super) async fn execute_register_tool(
        &self,
        context_id: &str,
        registration: &ToolRegistration,
        _proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            // Gate: ceiling must include ToolRegister (§5.3, #339).
            if !ctx.role_state.ceiling.contains(&Capability::ToolRegister) {
                return Err(ContextError::PermissionDenied(
                    "context ceiling does not include tool registration capability".into(),
                ));
            }

            if ctx.governance.registered_tools.len() >= MAX_REGISTERED_TOOLS {
                return Err(ContextError::LimitExceeded(format!(
                    "registered tool limit of {MAX_REGISTERED_TOOLS} exceeded"
                )));
            }
            ctx.governance.registered_tools.push(registration.clone());
            if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            }
        };

        if let Some(snapshot) = snapshot {
            self.persist_context_snapshot(context_id, snapshot);
        }
        self.event_log
            .append_context_event(&context_id_bytes, "ToolRegistered", actor_did)?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }
        Ok(())
    }

    async fn execute_remove_tool(
        &self,
        context_id: &str,
        tool_id: &str,
        _proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            ctx.governance
                .registered_tools
                .retain(|t| t.tool_id != tool_id);
            if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            }
        };

        if let Some(snapshot) = snapshot {
            self.persist_context_snapshot(context_id, snapshot);
        }
        self.event_log
            .append_context_event(&context_id_bytes, "ToolRemoved", actor_did)?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }
        Ok(())
    }

    async fn execute_modify_ceiling(
        &self,
        context_id: &str,
        new_ceiling: &[Capability],
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            if !matches!(
                ctx.handle.params().ceiling_policy,
                scp_protocol::context::params::CeilingPolicy::Governed
            ) {
                return Err(ContextError::PermissionDenied(
                    "ceiling_policy is not Governed".to_owned(),
                ));
            }

            // Check for existing pending modification.
            if ctx.governance.pending_ceiling_modification.is_some() {
                return Err(ContextError::PermissionDenied(
                    "a ceiling modification is already pending notification period".to_owned(),
                ));
            }

            // M7: Instead of applying immediately, enter notification period.
            // Members are notified and may leave before the expansion takes effect.
            let now = self.clock.now_secs();
            let effective_at = now + CEILING_CHANGE_NOTIFICATION_PERIOD_SECS;
            ctx.governance.pending_ceiling_modification = Some(PendingCeilingModification {
                new_capabilities: new_ceiling.to_vec(),
                notified_at: now,
                effective_at,
                proposal_id,
            });

            // §5.3.2 step 2: "All current members receive a
            // CeilingChangeNotification message."
            ctx.receive_buffer
                .push(ContextEvent::CeilingChangeNotification {
                    new_capabilities: new_ceiling.to_vec(),
                    notified_at: now,
                    effective_at,
                    proposal_id,
                });

            if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            }
        };

        if let Some(snapshot) = snapshot {
            self.persist_context_snapshot(context_id, snapshot);
        }
        self.event_log.append_context_event(
            &context_id_bytes,
            "CeilingModificationPending",
            actor_did,
        )?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }
        Ok(())
    }

    /// Applies a pending ceiling modification after the notification period.
    ///
    /// Called periodically or on demand to check if the notification period
    /// has expired and apply the pending ceiling change (M7, §5.3.2).
    ///
    /// Returns `true` if a pending modification was applied, `false` if there
    /// was no pending modification or the notification period has not yet expired.
    ///
    /// # Errors
    ///
    /// Returns `ContextError` if the context is not found or is not active.
    #[instrument(skip_all, fields(context_id))]
    pub async fn apply_pending_ceiling_modification(
        &self,
        context_id: &str,
        current_timestamp: u64,
    ) -> Result<bool, ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let (applied, snapshot) = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            let pending = match &ctx.governance.pending_ceiling_modification {
                Some(p) if p.is_effective(current_timestamp) => p.clone(),
                _ => return Ok(false),
            };

            // Apply the pending ceiling.
            ctx.role_state.ceiling =
                CapabilityCeiling::new(pending.new_capabilities.iter().cloned());
            ctx.governance.pending_ceiling_modification = None;

            let snap = if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            };
            (true, snap)
        };

        if applied {
            if let Some(snapshot) = snapshot {
                self.persist_context_snapshot(context_id, snapshot);
            }
            self.event_log
                .append_context_event(&context_id_bytes, "CeilingModified", "")?;
            {
                if let Some(entry) = self.contexts.get(context_id) {
                    let ctx_arc = Arc::clone(entry.value());
                    drop(entry);
                    let mut guard = ctx_arc.lock().await;
                    let ctx = &mut *guard;
                    ctx.checkpoint_events_since += 1;
                }
            }
        }

        Ok(applied)
    }

    async fn execute_close_context(
        &self,
        context_id: &str,
        _reason: Option<&str>,
        _proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        // Extract handle under lock, then drop lock before the async
        // transition to avoid holding the global contexts mutex across .await.
        let handle = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let guard = ctx_arc.lock().await;
            let ctx = &*guard;
            require_active(&ctx.handle)?;
            ctx.handle.clone()
        };

        // Transition to Closing via the state machine (no lock held).
        handle
            .transition_to(&ContextState::Closing)
            .await
            .map_err(|_| {
                ContextError::PermissionDenied("cannot transition to Closing".to_owned())
            })?;

        // Re-acquire lock for cleanup and snapshot.
        let snapshot = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;

            // Cancel TTL timer and governance timeout task if active.
            ctx.ttl.timer.cancel();
            ctx.governance.timeout_task.cancel();
            // Drop broadcast context state -- keys are zeroed by Zeroize.
            ctx.broadcast_context = None;

            // M7: Participation decay on governance-driven close (#1530).
            ctx.governance.decay_participation();

            if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            }
        };

        if let Some(snapshot) = snapshot {
            self.persist_context_snapshot(context_id, snapshot);
        }
        self.event_log
            .append_context_event(&context_id_bytes, "ContextClosing", actor_did)?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }
        Ok(())
    }

    /// Extends the context's TTL. Requires unanimous consent from ALL
    /// current members regardless of governance model — protocol-level
    /// override per ADR-031 §4d and spec §5.10.
    async fn execute_extend_ttl(
        &self,
        context_id: &str,
        additional_secs: u64,
        approvals: &[scp_protocol::context::governance::SignedVote],
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let (snapshot, new_remaining, handle, old_deadline, new_deadline, consenting_members) = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            // Unanimity check: TTL extension requires consent from ALL
            // current members (§5.10) because unilateral extension would
            // violate the ephemeral contract. This is a protocol-level
            // override that applies regardless of governance model.
            let member_dids: std::collections::HashSet<&str> =
                ctx.membership.member_dids().map(|d| &**d).collect();
            let approval_dids: std::collections::HashSet<&str> =
                approvals.iter().map(|v| &*v.voter_did).collect();
            let missing: Vec<&str> = member_dids.difference(&approval_dids).copied().collect();
            if !missing.is_empty() {
                // §5.10.1 step 6: Record TTLExtensionRejected event with
                // proposal ID and rejecting member DIDs.
                let rejecting_members: Vec<&str> = missing.clone();
                let rejected_payload = serde_json::json!({
                    "event": "TTLExtensionRejected",
                    "proposal_id": hex::encode(proposal_id),
                    "rejecting_members": rejecting_members,
                });
                self.event_log.append_context_event(
                    &context_id_bytes,
                    &rejected_payload.to_string(),
                    actor_did,
                )?;
                ctx.checkpoint_events_since += 1;
                return Err(ContextError::PermissionDenied(format!(
                    "TTL extension requires unanimous consent — {} of {} members have not approved",
                    missing.len(),
                    member_dids.len()
                )));
            }

            // Collect consenting member DIDs for the structured event
            // payload (§5.10.1 step 5).
            let consenting: Vec<String> = approval_dids.iter().map(|d| (*d).to_owned()).collect();

            // Cancel the existing TTL timer task so it does not fire at
            // the original deadline.
            ctx.ttl.timer.cancel();

            // Capture old deadline before mutation for structured event.
            let old_dl = ctx.ttl.timer.deadline_unix_secs.unwrap_or(0);

            // Extend the TTL deadline and compute the remaining duration
            // for the replacement timer task.
            let remaining_secs = ctx.ttl.timer.deadline_unix_secs.as_mut().map(|deadline| {
                *deadline = deadline.saturating_add(additional_secs);
                let now = self.clock.now_secs();
                deadline.saturating_sub(now)
            });

            // Capture new deadline after mutation.
            let new_dl = ctx.ttl.timer.deadline_unix_secs.unwrap_or(0);

            // Reset the cancel signal so the replacement timer task can be
            // cancelled independently of the old one.
            ctx.ttl.timer.cancel = Arc::new(tokio::sync::Notify::new());
            ctx.ttl.timer.task = None;

            let h = ctx.handle.clone();
            let snap = if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            };
            (snap, remaining_secs, h, old_dl, new_dl, consenting)
        };

        // Respawn the TTL timer with the updated remaining duration.
        if let Some(secs) = new_remaining {
            self.spawn_ttl_timer(context_id, std::time::Duration::from_secs(secs), handle)
                .await;
        }

        if let Some(snapshot) = snapshot {
            self.persist_context_snapshot(context_id, snapshot);
        }

        // §5.10.1 step 5: Record TTLExtended event with structured payload
        // containing old deadline, new deadline, proposal ID, and
        // consenting members.
        let extended_payload = serde_json::json!({
            "event": "TTLExtended",
            "old_deadline_unix": old_deadline,
            "new_deadline_unix": new_deadline,
            "proposal_id": hex::encode(proposal_id),
            "consenting_members": consenting_members,
        });
        self.event_log.append_context_event(
            &context_id_bytes,
            &extended_payload.to_string(),
            actor_did,
        )?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }
        Ok(())
    }

    async fn execute_transfer_admin(
        &self,
        context_id: &str,
        new_admin: &DID,
        _proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            if !ctx.membership.contains(new_admin) {
                return Err(ContextError::MemberNotFound(new_admin.to_string()));
            }

            // Demote current admins, promote new admin via role engine.
            //
            // H2: Use system_assign_role to bypass the RoleAssign capability
            // check. The governance engine has already authorized this action
            // via quorum, and TransferAdmin is structurally a self-modifying
            // operation: even when the creator is the current admin, the
            // first iteration below demotes them — causing the *second*
            // iteration (or the new-admin promotion) to fail
            // `AssignerNotAuthorized` if it still required `RoleAssign` on the
            // creator. The same root cause applies as in execute_change_role
            // and execute_add_member; see `enforce_assign_role` for the
            // matching consequence path.
            // Find and demote current admin(s).
            let current_admins: Vec<String> = ctx
                .role_state
                .assignments
                .iter()
                .filter(|(_, a)| a.role_name == "admin")
                .map(|(did, _)| did.clone())
                .collect();
            for admin_did in &current_admins {
                roles::system_assign_role(&mut ctx.role_state, admin_did, "member", &*self.clock)
                    .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;
                if let Some(info) = ctx.membership.get_mut(admin_did) {
                    "member".clone_into(&mut info.role_name);
                }
            }
            // Promote new admin.
            let tokens =
                roles::system_assign_role(&mut ctx.role_state, new_admin, "admin", &*self.clock)
                    .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;
            if let Some(info) = ctx.membership.get_mut(new_admin) {
                "admin".clone_into(&mut info.role_name);
                info.tokens = tokens;
            }

            if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            }
        };

        if let Some(snapshot) = snapshot {
            self.persist_context_snapshot(context_id, snapshot);
        }
        self.event_log
            .append_context_event(&context_id_bytes, "AdminTransferred", actor_did)?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }
        Ok(())
    }

    /// Creates a child context from this parent. Requires `ChildContextCreate`
    /// in the parent context's ceiling (§5.3, §5.13).
    async fn execute_create_child_context(
        &self,
        context_id: &str,
        _params: &ContextParams,
        _proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);
        // Validate parent context is active and ceiling allows child creation.
        {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let guard = ctx_arc.lock().await;
            let ctx = &*guard;
            require_active(&ctx.handle)?;

            // Gate: ceiling must include ChildContextCreate (§5.3, §5.13, #339).
            if !ctx
                .role_state
                .ceiling
                .contains(&Capability::ChildContextCreate)
            {
                return Err(ContextError::PermissionDenied(
                    "context ceiling does not include child context creation capability".into(),
                ));
            }
        }
        // Child context creation is delegated to `create_context` by the
        // caller with the parent_context_id field set. This method records
        // the governance event on the parent.
        self.event_log
            .append_context_event(&context_id_bytes, "ChildContextCreated", actor_did)?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }
        Ok(())
    }

    async fn execute_modify_pruning_policy(
        &self,
        context_id: &str,
        new_policy: &PruningPolicy,
        _proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        // Validate retention multipliers are non-zero.
        let structural_mul_bp = new_policy
            .event_type_retention
            .structural_retention_multiplier;
        if structural_mul_bp == 0 {
            return Err(ContextError::PermissionDenied(
                "structural_retention_multiplier must be > 0".to_owned(),
            ));
        }
        let operational_mul_bp = new_policy
            .event_type_retention
            .operational_retention_multiplier;
        if operational_mul_bp == 0 {
            return Err(ContextError::PermissionDenied(
                "operational_retention_multiplier must be > 0".to_owned(),
            ));
        }

        // Validate protocol minimum: 30 days for time-based retention (ADR-030).
        if let Some(ref tb) = new_policy.time_based
            && tb.retention_secs < 2_592_000
        {
            return Err(ContextError::PermissionDenied(
                "time_based.retention_secs must be >= 2,592,000 (30 days)".to_owned(),
            ));
        }
        // ADR-030: structural event retention floor is 90 days (7,776,000 seconds).
        // effective = retention_secs * multiplier_bp / 10000
        if let Some(ref tb) = new_policy.time_based {
            let effective = tb
                .retention_secs
                .saturating_mul(u64::from(structural_mul_bp))
                / 10_000;
            if effective < 7_776_000 {
                return Err(ContextError::PermissionDenied(
                    "effective structural event retention must be >= 7,776,000 seconds (90 days)"
                        .to_owned(),
                ));
            }
        }

        let snapshot = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            ctx.governance.pruning_policy = Some(new_policy.clone());
            if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            }
        };

        if let Some(snapshot) = snapshot {
            self.persist_context_snapshot(context_id, snapshot);
        }
        self.event_log.append_context_event(
            &context_id_bytes,
            "PruningPolicyModified",
            actor_did,
        )?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }
        Ok(())
    }

    /// Adds a signer to the threshold set and mints `GovernanceVote` +
    /// `GovernancePropose` UCANs for the new signer (ADR-031 §6).
    pub(super) async fn execute_add_signer(
        &self,
        context_id: &str,
        did: &DID,
        _proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            if !ctx.membership.contains(did) {
                return Err(ContextError::MemberNotFound(did.to_string()));
            }
            if ctx.governance.threshold_signers.contains(did) {
                return Err(ContextError::PermissionDenied(format!(
                    "DID is already a signer: {did}"
                )));
            }
            if ctx.governance.threshold_signers.len() >= MAX_THRESHOLD_SIGNERS {
                return Err(ContextError::LimitExceeded(format!(
                    "threshold signer limit of {MAX_THRESHOLD_SIGNERS} exceeded"
                )));
            }
            ctx.governance.threshold_signers.push(did.clone());

            // ADR-031 §6: mint GovernanceVote + GovernancePropose UCANs
            // for the new signer so they can participate in governance.
            let creator_did = ctx.role_state.creator_did.clone();
            let capabilities = [Capability::GovernancePropose, Capability::GovernanceVote];
            for cap in &capabilities {
                let att = roles::UcanAttestation {
                    with: format!("scp:ctx:{context_id}/{cap}"),
                    can: "invoke".to_owned(),
                };
                let nonce = scp_protocol::crypto::ucan::nonce::generate_nonce(&*self.clock);
                let token = roles::UcanToken {
                    iss: creator_did.clone(),
                    aud: did.to_string(),
                    att: vec![att],
                    nnc: nonce,
                };
                // Grant the capability to the new signer.
                ctx.role_state
                    .member_capabilities
                    .entry(did.to_string())
                    .or_default()
                    .insert(cap.clone());
                // Record the token in membership tracking.
                if let Some(info) = ctx.membership.get_mut(did) {
                    info.tokens.push(token);
                }
            }

            if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            }
        };

        if let Some(snapshot) = snapshot {
            self.persist_context_snapshot(context_id, snapshot);
        }
        self.event_log
            .append_context_event(&context_id_bytes, "SignerAdded", actor_did)?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }
        Ok(())
    }

    /// Removes a signer from the threshold set, revokes their governance
    /// UCANs, and validates threshold <= remaining signers (ADR-031 §6).
    async fn execute_remove_signer(
        &self,
        context_id: &str,
        did: &DID,
        _proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            let before = ctx.governance.threshold_signers.len();
            ctx.governance.threshold_signers.retain(|s| s != did);
            if ctx.governance.threshold_signers.len() == before {
                return Err(ContextError::MemberNotFound(did.to_string()));
            }
            // ADR-031 §6: if removing would make threshold > signers.len(), reject.
            if ctx.governance.threshold_value > 0 {
                let remaining =
                    u32::try_from(ctx.governance.threshold_signers.len()).unwrap_or(u32::MAX);
                if ctx.governance.threshold_value > remaining {
                    // Undo the removal before returning.
                    ctx.governance.threshold_signers.push(did.clone());
                    return Err(ContextError::PermissionDenied(format!(
                        "removing signer would leave {remaining} signers < threshold {}",
                        ctx.governance.threshold_value
                    )));
                }
            }

            // ADR-031 §6: revoke GovernanceVote + GovernancePropose
            // capabilities from the removed signer. The DID remains a
            // context member but loses governance authority.
            if let Some(caps) = ctx.role_state.member_capabilities.get_mut(did.as_ref()) {
                caps.retain(|c| {
                    !matches!(
                        c,
                        Capability::GovernancePropose | Capability::GovernanceVote
                    )
                });
            }
            // Remove governance UCAN tokens from membership tracking.
            if let Some(info) = ctx.membership.get_mut(did) {
                info.tokens.retain(|t| {
                    !t.att.iter().any(|a| {
                        a.with.contains("governance:propose") || a.with.contains("governance:vote")
                    })
                });
            }

            if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            }
        };

        if let Some(snapshot) = snapshot {
            self.persist_context_snapshot(context_id, snapshot);
        }
        self.event_log
            .append_context_event(&context_id_bytes, "SignerRemoved", actor_did)?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }
        Ok(())
    }

    async fn execute_modify_threshold(
        &self,
        context_id: &str,
        new_threshold: u32,
        _proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            let signer_count =
                u32::try_from(ctx.governance.threshold_signers.len()).unwrap_or(u32::MAX);
            if new_threshold == 0 || new_threshold > signer_count {
                return Err(ContextError::PermissionDenied(format!(
                    "threshold must be 1..={signer_count}, got {new_threshold}"
                )));
            }
            ctx.governance.threshold_value = new_threshold;
            if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            }
        };

        if let Some(snapshot) = snapshot {
            self.persist_context_snapshot(context_id, snapshot);
        }
        self.event_log
            .append_context_event(&context_id_bytes, "ThresholdModified", actor_did)?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }
        Ok(())
    }

    /// Establishes a cross-context tool interface. Requires `ToolInterface`
    /// in the context's ceiling (§5.3, §6.2). Without this capability in the
    /// ceiling, the context does not support tool interface exposure.
    pub(super) async fn execute_establish_tool_interface(
        &self,
        context_id: &str,
        interface: &ToolInterface,
        _proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            // Gate: ceiling must include ToolInterface (§5.3, §6.2, #339).
            if !ctx.role_state.ceiling.contains(&Capability::ToolInterface) {
                return Err(ContextError::PermissionDenied(
                    "context ceiling does not include tool interface capability".into(),
                ));
            }

            if ctx.governance.tool_interfaces.len() >= MAX_TOOL_INTERFACES {
                return Err(ContextError::LimitExceeded(format!(
                    "tool interface limit of {MAX_TOOL_INTERFACES} exceeded"
                )));
            }
            ctx.governance.tool_interfaces.push(interface.clone());
            if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            }
        };

        if let Some(snapshot) = snapshot {
            self.persist_context_snapshot(context_id, snapshot);
        }
        self.event_log.append_context_event(
            &context_id_bytes,
            "ToolInterfaceEstablished",
            actor_did,
        )?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }
        Ok(())
    }

    async fn execute_reset_member(
        &self,
        context_id: &str,
        did: &DID,
        _reason: &str,
        _proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);
        {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let guard = ctx_arc.lock().await;
            let ctx = &*guard;
            require_active(&ctx.handle)?;

            if !ctx.membership.contains(did) {
                return Err(ContextError::MemberNotFound(did.to_string()));
            }
        }
        // Member reset = leave + immediately re-join (ADR-029 §Tier 3).
        // Step 1: Remove from MLS group (destroys stale leaf node).
        let remove_output = self
            .crypto
            .remove_member(&context_id_bytes, did)
            .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;
        // Step 2: Re-add to MLS group with fresh key material.
        let add_output = self
            .crypto
            .add_member(&context_id_bytes, did, None)
            .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

        // Broadcast the MLS Commits so remaining members can process
        // the remove and re-add epoch changes. PR #1606 C6: each commit
        // is enqueued on transport failure and retried by the governance
        // timeout task with exponential backoff.
        self.try_broadcast_commit_or_enqueue(
            context_id,
            remove_output.commit_bytes,
            CommitOperation::ResetMember {
                target_did: did.clone(),
                is_remove: true,
            },
            actor_did,
        )
        .await?;
        self.try_broadcast_commit_or_enqueue(
            context_id,
            add_output.commit_bytes,
            CommitOperation::ResetMember {
                target_did: did.clone(),
                is_remove: false,
            },
            actor_did,
        )
        .await?;

        // H5: Sender key rotation after MLS reset — remove the reset
        // member's stale sender key, rotate our own key, and distribute
        // new key material to remaining members (§9.16.4). This ensures
        // the reset member cannot decrypt messages sent with the old key.
        if let Err(e) = self
            .crypto
            .remove_member_sender_key(&context_id_bytes, did.as_ref())
        {
            tracing::warn!(
                context_id,
                member = %did,
                error = %e,
                "remove_member_sender_key failed after MLS reset — \
                 sender key layer may retain stale key"
            );
        }
        if let Err(e) = self.crypto.rotate_sender_key(&context_id_bytes) {
            tracing::warn!(
                context_id,
                error = %e,
                "rotate_sender_key failed after MLS reset"
            );
        }

        // Drain pending sender key distribution messages, MLS-encrypt,
        // and deliver via transport (same pattern as lifecycle leave).
        if let Err(e) = self.drain_and_deliver_sender_keys(context_id, &context_id_bytes) {
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to deliver rotated sender keys after member reset"
            );
        }

        self.event_log
            .append_context_event(&context_id_bytes, "MemberReset", actor_did)?;

        // Track the epoch reset so the governance timeout task can invalidate
        // this member's votes on pending proposals (ADR-031 §5, ADR-029 Tier 3).
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
                ctx.governance.pending_epoch_resets.push(did.clone());
            }
        }

        Ok(())
    }

    async fn execute_resolve_conflict(
        &self,
        context_id: &str,
        proposal_a: &ProposalId,
        proposal_b: &ProposalId,
        resolution: &scp_protocol::context::governance::ConflictResolution,
        _proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            // Gate: context must be in governance freeze state to resolve
            // a conflict (ADR-031 §7). The freeze was triggered by
            // detect_and_handle_conflicts when simultaneous proposals landed.
            // Validate that the proposals being resolved match the ones that
            // caused the freeze — otherwise an admin could clear a freeze by
            // referencing arbitrary proposal IDs.
            let (freeze_a, freeze_b, _) = ctx.governance.freeze.ok_or_else(|| {
                ContextError::PermissionDenied(
                    "context is not in governance freeze state — no conflict to resolve".into(),
                )
            })?;
            let proposals_match = (*proposal_a == freeze_a && *proposal_b == freeze_b)
                || (*proposal_a == freeze_b && *proposal_b == freeze_a);
            if !proposals_match {
                return Err(ContextError::PermissionDenied(
                    "ResolveConflict proposals do not match the governance freeze".into(),
                ));
            }

            // Validate that the two proposals actually conflict using the
            // sync::conflict_resolution module (issue #630). Look up the
            // proposals from the approved set or executed set to obtain
            // their actions for conflict verification.
            let action_a = ctx
                .governance
                .approved_proposals
                .get(proposal_a)
                .map(|(p, _, _)| &p.action);
            let action_b = ctx
                .governance
                .approved_proposals
                .get(proposal_b)
                .map(|(p, _, _)| &p.action);

            let (Some(act_a), Some(act_b)) = (action_a, action_b) else {
                return Err(ContextError::PermissionDenied(
                    "one or both conflict proposals are not in the approved set — \
                     cannot verify conflict"
                        .into(),
                ));
            };

            // Retrieve proposer DIDs for conflict validation.
            let proposer_a = &ctx.governance.approved_proposals[proposal_a].0.proposer_did;
            let proposer_b = &ctx.governance.approved_proposals[proposal_b].0.proposer_did;
            if !scp_protocol::sync::conflict_resolution::actions_conflict(
                act_a, proposer_a, act_b, proposer_b,
            ) {
                return Err(ContextError::PermissionDenied(
                    "the specified proposals do not conflict per \
                     sync::conflict_resolution::actions_conflict"
                        .into(),
                ));
            }

            // Mark the conflicting proposal(s) as executed (invalidated) so
            // they cannot be replayed. For AcceptProposal the loser is
            // invalidated; the winner is left unexecuted so it can proceed
            // through normal `execute_governance_action`. For InvalidateBoth,
            // both are invalidated.
            match resolution {
                scp_protocol::context::governance::ConflictResolution::AcceptProposal {
                    winner_id,
                } => {
                    // Validate that winner_id is one of the two proposals.
                    let loser = if *winner_id == *proposal_a {
                        proposal_b
                    } else if *winner_id == *proposal_b {
                        proposal_a
                    } else {
                        return Err(ContextError::PermissionDenied(format!(
                            "winner_id {winner_id:?} is not one of the conflicting proposals"
                        )));
                    };
                    // Only invalidate the loser — the winner remains eligible
                    // for normal execution.
                    let now = self.clock.now_secs();
                    ctx.governance.executed_proposals.insert(*loser, now);
                }
                scp_protocol::context::governance::ConflictResolution::InvalidateBoth => {
                    let now = self.clock.now_secs();
                    ctx.governance.executed_proposals.insert(*proposal_a, now);
                    ctx.governance.executed_proposals.insert(*proposal_b, now);
                }
            }

            // Clear governance freeze now that the conflict is resolved.
            ctx.governance.freeze = None;

            if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            }
        };

        if let Some(snapshot) = snapshot {
            self.persist_context_snapshot(context_id, snapshot);
        }
        self.event_log.append_context_event(
            &context_id_bytes,
            "GovernanceConflictResolved",
            actor_did,
        )?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }
        Ok(())
    }

    /// Executes a context promotion (§5.10).
    ///
    /// Contexts with `PromotionPolicy::NoPromotion` MUST reject `PromoteContext`
    /// regardless of governance approval. This is a protocol-level invariant:
    /// the promotion policy is immutable after creation and overrides any
    /// governance decision. Only contexts created with
    /// `PromotionPolicy::Promotable` can be promoted.
    ///
    /// On success: TTL is removed, memory scope transitions to `Full`, existing
    /// event log and key material are preserved.
    async fn execute_promote_context(
        &self,
        context_id: &str,
        approvals: &[scp_protocol::context::governance::SignedVote],
        _proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            if !matches!(
                ctx.handle.params().promotion_policy,
                scp_protocol::context::params::PromotionPolicy::Promotable
            ) {
                return Err(ContextError::PermissionDenied(
                    "context promotion_policy is not Promotable".to_owned(),
                ));
            }

            // Unanimity check: promotion requires consent from ALL current
            // members (§5.10) because promotion changes the opt-in contract
            // (ephemeral → persistent). This is a protocol-level override
            // that applies regardless of governance model.
            let member_dids: std::collections::HashSet<&str> =
                ctx.membership.member_dids().map(|d| &**d).collect();
            let approval_dids: std::collections::HashSet<&str> =
                approvals.iter().map(|v| &*v.voter_did).collect();
            let missing: Vec<&str> = member_dids.difference(&approval_dids).copied().collect();
            if !missing.is_empty() {
                return Err(ContextError::PermissionDenied(format!(
                    "promotion requires unanimous consent — {} of {} members have not approved",
                    missing.len(),
                    member_dids.len()
                )));
            }

            // Promote: cancel TTL timer and transition memory scope (§5.10).
            // "On promotion: TTL is removed, memory scope transitions from
            // ephemeral to full, existing event log and key material are
            // preserved."
            ctx.ttl.timer.cancel();
            ctx.ttl.timer.deadline_unix_secs = None;
            ctx.handle.promote_memory_scope();

            if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            }
        };

        if let Some(snapshot) = snapshot {
            self.persist_context_snapshot(context_id, snapshot);
        }
        self.event_log
            .append_context_event(&context_id_bytes, "ContextPromoted", actor_did)?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }
        Ok(())
    }

    /// Revokes a member's write access per §9.17 and ADR-038.
    ///
    /// Scope differentiation:
    /// - `AccessScope::Both`: destroys the target's sender/broadcast key AND revokes
    ///   write capability. Historical content by the target may be
    ///   suppressed by the access key layer.
    /// - `AccessScope::Write`: revokes write capability only. No key destruction
    ///   — existing broadcast keys remain for historical decryption.
    ///
    /// Redundancy: revoke-when-already-revoked is a no-op (§5.9).
    /// The member remains in the context (membership/access decoupling).
    /// Rotates all access keys context-wide per §9.17 and ADR-038.
    ///
    /// In broadcast mode: rotates every author's broadcast key (epoch
    /// advance + new random key). In encrypted mode: emits event to
    /// signal the MLS layer to issue an Update + Commit.
    ///
    /// All members receive new access keys. Historical content remains
    /// accessible with old keys (retained by the store).
    async fn execute_rotate_content_keys(
        &self,
        context_id: &str,
        reason: Option<&str>,
        _proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let (epoch_output, snapshot, bc_snapshot) = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            let (epoch_out, bc_snap) = if let Some(ref mut bc) = ctx.broadcast_context {
                // Rotate every author's broadcast key (epoch advance + new key).
                bc.rotate_all_author_keys()?;
                let snap = if self.has_persistence() {
                    Some(bc.to_snapshot())
                } else {
                    None
                };
                (None, snap)
            } else {
                // Encrypted mode: advance MLS epoch via propose_update (#1548).
                let epoch_out = self.crypto.advance_epoch(&context_id_bytes)?;

                // Encrypted mode: regenerate per-member access keys at a new
                // epoch (§9.17.2 step 6, ADR-038). MLS key rotation and access
                // key rotation are independent — MLS handles group secrets,
                // access keys handle per-member CEK wrapping.
                let member_dids: Vec<String> =
                    ctx.membership.member_dids().map(|d| d.0.clone()).collect();
                let current_epoch = ctx
                    .access
                    .access_key_store
                    .get_all(context_id)
                    .values()
                    .map(scp_protocol::crypto::access_keys::AccessKey::epoch)
                    .max()
                    .unwrap_or(0);
                let did_refs: Vec<&str> = member_dids.iter().map(String::as_str).collect();
                let rotation = crate::crypto::access_keys::lifecycle::rotate_all_access_keys(
                    context_id,
                    &did_refs,
                    current_epoch,
                )
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
                for new_key in rotation.new_keys {
                    let did = new_key.member_did().to_owned();
                    ctx.access.access_key_store.set(context_id, &did, new_key);
                }
                (Some(epoch_out), None)
            };

            // Emit content keys rotated event to receive buffer.
            ctx.receive_buffer.push(ContextEvent::ContentKeysRotated {
                reason: reason.map(String::from),
            });

            let snap = if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            };
            (epoch_out, snap, bc_snap)
        };

        // Broadcast the MLS epoch advance Commit to all members (encrypted mode).
        // PR #1606 C6: enqueue for persistent retry on transport failure.
        if let Some(epoch_out) = epoch_output {
            self.try_broadcast_commit_or_enqueue(
                context_id,
                epoch_out.commit_bytes,
                CommitOperation::RotateContentKeys {
                    reason: reason.map(String::from),
                },
                actor_did,
            )
            .await?;
        }

        if let Some(snapshot) = snapshot {
            self.persist_context_snapshot(context_id, snapshot);
        }
        if let Some(ref snap) = bc_snapshot {
            self.persist_broadcast_snapshot(context_id, snap);
        }

        self.event_log
            .append_context_event(&context_id_bytes, "ContentKeysRotated", actor_did)?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }
        Ok(())
    }

    async fn execute_reconfigure_governance(
        &self,
        context_id: &str,
        changes: &[scp_protocol::context::governance::GovernanceReconfigAction],
        justification: &scp_protocol::context::governance::DeadlockJustification,
        _proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        if changes.is_empty() {
            return Err(ContextError::PermissionDenied(
                "reconfigure_governance requires at least one change".to_owned(),
            ));
        }
        if justification.unavailable_dids.is_empty() && justification.missed_windows.is_empty() {
            return Err(ContextError::PermissionDenied(
                "deadlock justification must provide evidence (unavailable_dids or missed_windows)"
                    .to_owned(),
            ));
        }

        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            // Save state for rollback — the loop below mutates ctx in-place,
            // and any mid-loop or post-loop error must restore the original
            // state to prevent in-memory corruption.
            let original_signers = ctx.governance.threshold_signers.clone();
            let original_threshold = ctx.governance.threshold_value;

            // Apply each reconfiguration action in order (ADR-031 §10).
            let reconfigure_result: Result<(), ContextError> = (|| {
                for change in changes {
                    match change {
                        scp_protocol::context::governance::GovernanceReconfigAction::RemoveInactiveSigner {
                            did,
                        } => {
                            ctx.governance.threshold_signers.retain(|s| s != did);
                        }
                        scp_protocol::context::governance::GovernanceReconfigAction::ReduceThreshold {
                            new_threshold,
                        } => {
                            let signer_count =
                                u32::try_from(ctx.governance.threshold_signers.len()).unwrap_or(u32::MAX);
                            if *new_threshold == 0 || *new_threshold > signer_count {
                                return Err(ContextError::PermissionDenied(format!(
                                    "reconfigured threshold must be 1..={signer_count}, got {new_threshold}"
                                )));
                            }
                            ctx.governance.threshold_value = *new_threshold;
                        }
                    }
                }

                // Post-loop invariant: threshold must still be satisfiable after
                // all removals and reductions (ADR-031 §10).
                if ctx.governance.threshold_value > 0 {
                    let remaining =
                        u32::try_from(ctx.governance.threshold_signers.len()).unwrap_or(u32::MAX);
                    if ctx.governance.threshold_value > remaining {
                        return Err(ContextError::PermissionDenied(format!(
                            "reconfiguration left {remaining} signers < threshold {}",
                            ctx.governance.threshold_value,
                        )));
                    }
                }

                Ok(())
            })();

            if let Err(e) = reconfigure_result {
                // Rollback: restore original state before returning error.
                ctx.governance.threshold_signers = original_signers;
                ctx.governance.threshold_value = original_threshold;
                return Err(e);
            }

            if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            }
        };

        if let Some(snapshot) = snapshot {
            self.persist_context_snapshot(context_id, snapshot);
        }
        self.event_log.append_context_event(
            &context_id_bytes,
            "GovernanceReconfigured",
            actor_did,
        )?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }
        Ok(())
    }

    /// Stages an economic policy change with a 24-hour notification period
    /// (§19.3, ADR-033).
    ///
    /// The new policy is NOT applied immediately. Instead, it enters a
    /// notification period during which the previous policy remains in effect.
    /// Members are notified via [`ContextEvent::EconomicPolicyChangeNotification`]
    /// and may leave before the new pricing applies.
    ///
    /// Call [`apply_pending_economic_policy_change`](Self::apply_pending_economic_policy_change)
    /// after the notification period expires to apply the change.
    ///
    /// # Errors
    ///
    /// - [`ContextError::PermissionDenied`] if the existing policy is locked
    ///   or an economic policy change is already pending.
    /// - [`ContextError::ContextNotRegistered`] if the context is not registered.
    /// - [`ContextError::ContextNotActive`] if the context is not active.
    async fn execute_set_economic_policy(
        &self,
        context_id: &str,
        policy: &EconomicPolicy,
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        // Validate that pricing formula only references available metrics.
        scp_protocol::economy::policy::validate_economic_policy_metrics(Some(policy))
            .map_err(|e| ContextError::PermissionDenied(format!("invalid economic policy: {e}")))?;

        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            // Check if existing policy is locked.
            if let Some(existing) = &ctx.governance.economic_policy
                && existing.locked
            {
                return Err(ContextError::PermissionDenied(
                    "economic policy is locked and cannot be changed".to_owned(),
                ));
            }

            // Reject if an economic policy change is already pending.
            if ctx.governance.pending_economic_policy_change.is_some() {
                return Err(ContextError::PermissionDenied(
                    "an economic policy change is already pending notification period".to_owned(),
                ));
            }

            // §19.3: Stage the change with a 24-hour notification period.
            let now = self.clock.now_secs();
            let effective_at = now + ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS;
            ctx.governance.pending_economic_policy_change = Some(PendingEconomicPolicyChange {
                new_policy: policy.clone(),
                notified_at: now,
                effective_at,
                proposal_id,
            });

            // §19.3: Notify all members of the pending change.
            ctx.receive_buffer
                .push(ContextEvent::EconomicPolicyChangeNotification {
                    notified_at: now,
                    effective_at,
                    proposal_id,
                });

            if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            }
        };

        if let Some(snapshot) = snapshot {
            self.persist_context_snapshot(context_id, snapshot);
        }
        self.event_log.append_context_event(
            &context_id_bytes,
            "EconomicPolicyChanged",
            actor_did,
        )?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }
        Ok(())
    }

    /// Applies a pending economic policy change if its notification period
    /// has expired (§19.3).
    ///
    /// Returns `true` if the pending change was applied, `false` if there
    /// was no pending change or the notification period has not yet expired.
    ///
    /// # Errors
    ///
    /// Returns `ContextError` if the context is not found or is not active.
    #[instrument(skip_all, fields(context_id))]
    pub async fn apply_pending_economic_policy_change(
        &self,
        context_id: &str,
        current_timestamp: u64,
    ) -> Result<bool, ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let (applied, snapshot) = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            let pending = match &ctx.governance.pending_economic_policy_change {
                Some(p) if p.is_effective(current_timestamp) => p.clone(),
                _ => return Ok(false),
            };

            // Apply the pending policy.
            ctx.governance.economic_policy = Some(pending.new_policy);
            ctx.governance.pending_economic_policy_change = None;

            let snap = if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            };
            (true, snap)
        };

        if applied {
            if let Some(snapshot) = snapshot {
                self.persist_context_snapshot(context_id, snapshot);
            }
            self.event_log
                .append_context_event(&context_id_bytes, "EconomicPolicyApplied", "")?;
            {
                if let Some(entry) = self.contexts.get(context_id) {
                    let ctx_arc = Arc::clone(entry.value());
                    drop(entry);
                    let mut guard = ctx_arc.lock().await;
                    let ctx = &mut *guard;
                    ctx.checkpoint_events_since += 1;
                }
            }
        }

        Ok(applied)
    }

    /// Approves a spending authorization for a member (§19.5, ADR-033).
    ///
    /// Grants the approved `amount` to the spender's cumulative budget via
    /// [`MemberBudgetTracker::grant`] and records the approval in the event
    /// log. Budget enforcement (checking remaining balance before tool
    /// invocations) is handled at the tool invocation layer.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] if the context is not registered
    ///   or the spender is not a member.
    /// - [`ContextError::ContextNotActive`] if the context is not active.
    async fn execute_approve_spend(
        &self,
        context_id: &str,
        spender: &DID,
        amount: scp_protocol::economy::types::Amount,
        purpose: &str,
        _proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            // Verify the spender is a member of the context.
            if !ctx.membership.contains(spender.as_ref()) {
                return Err(ContextError::MemberNotFound(spender.to_string()));
            }

            // Grant the approved budget to the member's cumulative tracker.
            ctx.governance.budget_tracker.grant(spender, amount);

            if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            }
        };

        if let Some(snapshot) = snapshot {
            self.persist_context_snapshot(context_id, snapshot);
        }
        let payload = serde_json::json!({
            "event": "SpendApproved",
            "spender": spender.as_ref(),
            "amount": amount,
            "purpose": purpose,
        });
        self.event_log
            .append_context_event(&context_id_bytes, &payload.to_string(), actor_did)?;
        Ok(())
    }

    /// Locks the economic policy, making it immutable (§19.3).
    ///
    /// # Errors
    ///
    /// - [`ContextError::PermissionDenied`] if no economic policy is set or
    ///   the policy is already locked.
    /// - [`ContextError::ContextNotRegistered`] if the context is not registered.
    /// - [`ContextError::ContextNotActive`] if the context is not active.
    async fn execute_lock_economic_policy(
        &self,
        context_id: &str,
        _proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            match &mut ctx.governance.economic_policy {
                None => {
                    return Err(ContextError::PermissionDenied(
                        "cannot lock economic policy: no policy is set".to_owned(),
                    ));
                }
                Some(policy) if policy.locked => {
                    return Err(ContextError::PermissionDenied(
                        "economic policy is already locked".to_owned(),
                    ));
                }
                Some(policy) => {
                    policy.locked = true;
                }
            }

            if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            }
        };

        if let Some(snapshot) = snapshot {
            self.persist_context_snapshot(context_id, snapshot);
        }
        self.event_log.append_context_event(
            &context_id_bytes,
            "EconomicPolicyLocked",
            actor_did,
        )?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }
        Ok(())
    }

    /// Executes a `ModifyHardRateLimit` governance action (D4, §19.7).
    ///
    /// Replaces the context's `TokenBucketLimiter` configuration with a
    /// new `HardRateLimitConfig`, preserving per-sender bucket state so
    /// active senders are not given a spurious free burst. The new
    /// config is validated at execution time to prevent a malformed
    /// config from reaching the limiter hot path.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] if the context is not registered.
    /// - [`ContextError::ContextNotActive`] if the context is not active.
    /// - [`ContextError::GovernanceFailed`] if `new_config` fails validation.
    async fn execute_modify_hard_rate_limit(
        &self,
        context_id: &str,
        new_config: &scp_protocol::economy::antispam::HardRateLimitConfig,
        _proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        // Validate BEFORE touching per-context state so a malformed
        // proposal cannot corrupt the active limiter.
        new_config.validate().map_err(|e| {
            ContextError::GovernanceFailed(format!(
                "ModifyHardRateLimit: new config failed validation: {e}"
            ))
        })?;

        let snapshot = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            // Preserve per-sender bucket state across the reconfigure
            // and eagerly clamp `tokens_milli > new_burst_milli` before
            // handing the state to `from_snapshot`. `from_snapshot`
            // itself does not clamp; without this sanitize step a
            // sender holding more tokens than the NEW burst could
            // consume them before refill applies `.min(burst_milli)`,
            // granting a free burst up to the old cap when the limit
            // tightens.
            let mut preserved_state = ctx.governance.hard_rate_limit.snapshot_entries();
            scp_protocol::economy::antispam::TokenBucketLimiter::validate_and_sanitize_snapshot(
                &mut preserved_state,
                new_config,
                self.clock.now_secs(),
                scp_protocol::economy::antispam::SNAPSHOT_CLOCK_SKEW_TOLERANCE_SECS,
            )
            .map_err(|e| {
                ContextError::GovernanceFailed(format!(
                    "ModifyHardRateLimit: preserved state sanitization failed: {e}"
                ))
            })?;
            ctx.governance.hard_rate_limit =
                scp_protocol::economy::antispam::TokenBucketLimiter::from_snapshot(
                    new_config.clone(),
                    preserved_state,
                );

            if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            }
        };

        if let Some(snapshot) = snapshot {
            self.persist_context_snapshot(context_id, snapshot);
        }
        self.event_log.append_context_event(
            &context_id_bytes,
            "HardRateLimitModified",
            actor_did,
        )?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }
        Ok(())
    }

    /// Executes a `ProposeContextMigration` governance action (§5.11A).
    ///
    /// On approval, creates the destination context with `migration_source`
    /// metadata (§5.11A.2), transitions the source context to `MigratingOut`,
    /// stores migration state, and emits migration events.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] if the context is not registered.
    /// - [`ContextError::ContextNotActive`] if the context is not active.
    /// - [`ContextError::InvalidTransition`] if the state transition fails.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn execute_propose_context_migration(
        &self,
        context_id: &str,
        new_context_params: &scp_protocol::context::params::ContextParams,
        reason: &str,
        grace_period_secs: u64,
        auto_invite: bool,
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<MigrationProposedResult, ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        // Generate a deterministic destination context ID from the source
        // context ID and proposal ID.
        let destination_context_id = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(b"SCP-MIGRATION-DEST:");
            hasher.update(context_id.as_bytes());
            hasher.update(proposal_id);
            hex::encode(hasher.finalize())
        };

        let now = self.clock.now_secs();
        let grace_period_end = now.saturating_add(grace_period_secs);

        // Prepare destination params with migration_source metadata
        // (§5.11A.2). The destination is a fully independent context with
        // its own ID, MLS group, event log, and key material.
        let mut dest_params = new_context_params.clone();
        dest_params.migration_source = Some(scp_protocol::context::params::MigrationSource {
            source_context_id: context_id.to_owned(),
            proposal_id,
        });

        // Validate source state, transition to MigratingOut, and set
        // migration state — all under ONE lock acquisition to prevent a
        // race where another task observes the source as Active between
        // destination creation and the state transition (F4).
        let (creator_did, snapshot, buffer_len_before_migration) = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            require_active(&ctx.handle)?;

            // Check no migration is already in progress.
            if ctx.migration_state.is_some() {
                return Err(ContextError::PermissionDenied(
                    "context migration is already in progress".to_owned(),
                ));
            }

            // Resolve the creator DID from the source context's membership.
            let creator = ctx
                .membership
                .members()
                .find(|m| m.role_name == "admin")
                .map(|m| m.did.clone())
                .ok_or_else(|| {
                    ContextError::PermissionDenied(
                        "no admin found in source context for destination creation".to_owned(),
                    )
                })?;

            // Transition to MigratingOut inside the lock so that
            // migration_state and handle state are always consistent.
            ctx.handle
                .transition_to(&ContextState::MigratingOut)
                .await
                .map_err(|_| {
                    ContextError::PermissionDenied("cannot transition to MigratingOut".to_owned())
                })?;

            ctx.migration_state = Some(MigrationState {
                destination_context_id: destination_context_id.clone(),
                reason: reason.to_owned(),
                grace_period_end,
                auto_invite,
                proposal_id,
            });

            // Record buffer length before pushing migration events so
            // rollback can truncate back to this point without destroying
            // events pushed by concurrent operations.
            let buffer_len_before_migration = ctx.receive_buffer.len();

            // Emit ContextMigrationProposed event to receive buffer.
            ctx.receive_buffer
                .push(ContextEvent::ContextMigrationProposed {
                    destination_context_id: destination_context_id.clone(),
                    reason: reason.to_owned(),
                    grace_period_secs,
                    auto_invite,
                    proposal_id,
                });

            // Emit ContextMigrationStarted event to receive buffer.
            ctx.receive_buffer
                .push(ContextEvent::ContextMigrationStarted {
                    destination_context_id: destination_context_id.clone(),
                    grace_period_end,
                });

            let snap = if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            };

            (creator, snap, buffer_len_before_migration)
        };

        // Create the destination context AFTER the source has been
        // transitioned to MigratingOut. If creation fails, roll back.
        if let Err(e) = self
            .create_context(destination_context_id.clone(), dest_params, creator_did)
            .await
        {
            // Roll back: revert source to Active and clear migration state.
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                let _ = ctx.handle.transition_to(&ContextState::Active).await;
                ctx.migration_state = None;
                // Remove only the migration events we pushed, preserving
                // any events added by concurrent operations.
                ctx.receive_buffer.truncate(buffer_len_before_migration);
            }
            return Err(ContextError::PermissionDenied(format!(
                "failed to create destination context: {e}"
            )));
        }

        if let Some(snapshot) = snapshot {
            self.persist_context_snapshot(context_id, snapshot);
        }
        self.event_log.append_context_event(
            &context_id_bytes,
            "ContextMigrationStarted",
            actor_did,
        )?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }

        Ok(MigrationProposedResult {
            destination_context_id,
            grace_period_end,
        })
    }

    /// Cancels an in-progress context migration (§5.11A).
    ///
    /// Returns the context from `MigratingOut` to `Active` state, clears
    /// migration state, and emits a cancellation event.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] if the context is not registered.
    /// - [`ContextError::PermissionDenied`] if the context is not migrating.
    /// - [`ContextError::InvalidTransition`] if the state transition fails.
    async fn execute_cancel_context_migration(
        &self,
        context_id: &str,
        _proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        // Transition and state mutation happen under the same lock to prevent
        // a race where migration_state is cleared but the state transition
        // back to Active fails (F4).
        let (original_proposal_id, snapshot) = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;

            // Must be in MigratingOut state.
            let state = ctx
                .handle
                .try_read_state()
                .ok_or(ContextError::ContextNotActive)?;
            if state != ContextState::MigratingOut {
                return Err(ContextError::PermissionDenied(
                    "context is not in MigratingOut state — cannot cancel migration".to_owned(),
                ));
            }

            // Transition back to Active inside the lock.
            ctx.handle
                .transition_to(&ContextState::Active)
                .await
                .map_err(|_| {
                    ContextError::PermissionDenied(
                        "cannot transition from MigratingOut to Active".to_owned(),
                    )
                })?;

            let migration = ctx.migration_state.take().ok_or_else(|| {
                ContextError::PermissionDenied(
                    "no migration state found despite MigratingOut state".to_owned(),
                )
            })?;
            let original_pid = migration.proposal_id;

            ctx.receive_buffer
                .push(ContextEvent::ContextMigrationCancelled {
                    original_proposal_id: original_pid,
                });

            let snapshot = if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            };
            (original_pid, snapshot)
        };

        if let Some(snapshot) = snapshot {
            self.persist_context_snapshot(context_id, snapshot);
        }
        self.event_log.append_context_event(
            &context_id_bytes,
            &format!(
                "ContextMigrationCancelled:{}",
                hex::encode(original_proposal_id)
            ),
            actor_did,
        )?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }
        Ok(())
    }

    /// Tombstones a context after migration grace period expiry (§5.11A.5).
    ///
    /// Transitions the context from `MigratingOut` to `Tombstoned`,
    /// cancels timers, drops broadcast state, and emits the tombstone event.
    /// This is called by the application layer when it detects the grace
    /// period has expired.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] if the context is not registered.
    /// - [`ContextError::PermissionDenied`] if the context is not migrating
    ///   or the grace period has not expired.
    #[instrument(skip_all, fields(context_id))]
    pub async fn tombstone_migrated_context(&self, context_id: &str) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let now = self.clock.now_secs();

        // State transition and mutation happen under the same lock to prevent
        // a race where migration_state is cleared but the transition to
        // Tombstoned fails.
        let (destination_id, migration_pid, snapshot) = {
            let ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;

            let state = ctx
                .handle
                .try_read_state()
                .ok_or(ContextError::ContextNotActive)?;
            if state != ContextState::MigratingOut {
                return Err(ContextError::PermissionDenied(
                    "context is not in MigratingOut state — cannot tombstone".to_owned(),
                ));
            }

            let migration = ctx.migration_state.as_ref().ok_or_else(|| {
                ContextError::PermissionDenied(
                    "no migration state found despite MigratingOut state".to_owned(),
                )
            })?;

            // Check grace period has expired.
            if now < migration.grace_period_end {
                return Err(ContextError::PermissionDenied(format!(
                    "migration grace period has not expired (ends at {}, now {})",
                    migration.grace_period_end, now
                )));
            }

            let dest_id = migration.destination_context_id.clone();
            let m_pid = migration.proposal_id;

            // Transition to Tombstoned inside the lock.
            ctx.handle
                .transition_to(&ContextState::Tombstoned)
                .await
                .map_err(|_| {
                    ContextError::PermissionDenied(
                        "cannot transition from MigratingOut to Tombstoned".to_owned(),
                    )
                })?;

            // Emit tombstone event.
            ctx.receive_buffer.push(ContextEvent::ContextTombstoned {
                destination_context_id: dest_id.clone(),
                migration_proposal_id: m_pid,
            });

            // Cancel TTL timer and governance timeout task.
            ctx.ttl.timer.cancel();
            ctx.governance.timeout_task.cancel();
            // Drop broadcast context state.
            ctx.broadcast_context = None;
            // Clear migration state.
            ctx.migration_state = None;
            // M7: Participation decay on tombstone (#1530).
            ctx.governance.decay_participation();

            let snapshot = if self.has_persistence() {
                Some(Self::snapshot_context(ctx))
            } else {
                None
            };
            (dest_id, m_pid, snapshot)
        };

        if let Some(snapshot) = snapshot {
            self.persist_context_snapshot(context_id, snapshot);
        }
        self.event_log.append_context_event(
            &context_id_bytes,
            &format!(
                "ContextTombstoned:{}:{}",
                destination_id,
                hex::encode(migration_pid)
            ),
            "",
        )?;
        {
            if let Some(entry) = self.contexts.get(context_id) {
                let ctx_arc = Arc::clone(entry.value());
                drop(entry);
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }
        Ok(())
    }

    /// Returns the migration state for a context, if any.
    ///
    /// Returns `None` if the context is not registered or not migrating.
    #[instrument(skip_all, fields(context_id))]
    pub async fn migration_state(&self, context_id: &str) -> Option<MigrationState> {
        let ctx_entry = self.contexts.get(context_id)?;
        let ctx_arc = Arc::clone(ctx_entry.value());
        drop(ctx_entry);
        let guard = ctx_arc.lock().await;
        let ctx = &*guard;
        ctx.migration_state.clone()
    }

    /// Translates governance events from timeout processing into
    /// [`ContextEvent`]s for the receive buffer (ADR-031 §5, §10).
    fn translate_timeout_events(
        result_events: &[GovernanceEvent],
        mls_epoch: u64,
        conditions: &[crate::context::governance::timeout::DeadlockCondition],
        recovery_in_progress: bool,
    ) -> Vec<ContextEvent> {
        let mut ctx_events = Vec::new();
        for event in result_events {
            let ctx_event = match event {
                GovernanceEvent::ProposalResolved {
                    proposal_id,
                    status,
                } => ContextEvent::ProposalTimedOut {
                    proposal_id: *proposal_id,
                    resolution_summary: format!("ProposalResolved({status:?})"),
                    resulting_epoch: Some(mls_epoch),
                },
                GovernanceEvent::VoteWithdrawn {
                    proposal_id,
                    voter_did,
                } => ContextEvent::VoteWithdrawn {
                    proposal_id: *proposal_id,
                    voter_did: voter_did.clone(),
                },
                GovernanceEvent::GovernanceActionExecuted {
                    proposal_id,
                    action,
                    executor_did,
                    resulting_epoch,
                } => ContextEvent::GovernanceActionExecuted {
                    proposal_id: *proposal_id,
                    action_summary: action.variant_name().to_owned(),
                    executor_did: executor_did.clone(),
                    resulting_epoch: *resulting_epoch,
                    target_did: action.target_did().cloned(),
                },
                // These variants are not expected from timeout processing;
                // listed explicitly so the compiler warns on new variants.
                GovernanceEvent::ProposalCreated { .. }
                | GovernanceEvent::VoteCast { .. }
                | GovernanceEvent::DeadlockRecovery { .. }
                | GovernanceEvent::ConflictDetected { .. }
                | GovernanceEvent::ConflictResolved { .. } => continue,
            };
            ctx_events.push(ctx_event);
        }

        if !conditions.is_empty() && !recovery_in_progress {
            for condition in conditions {
                let summary = match condition {
                    crate::context::governance::timeout::DeadlockCondition::ThresholdInsufficient {
                        ..
                    } => "ThresholdInsufficient",
                    crate::context::governance::timeout::DeadlockCondition::MajorityUnresponsive {
                        ..
                    } => "MajorityUnresponsive",
                    crate::context::governance::timeout::DeadlockCondition::UnanimityOffline { .. } => {
                        "UnanimityOffline"
                    }
                };
                ctx_events.push(ContextEvent::DeadlockDetected {
                    condition_summary: summary.to_owned(),
                    resulting_epoch: Some(mls_epoch),
                });
            }
        }

        ctx_events
    }

    /// Starts the governance timeout background task for a context (ADR-031 §5).
    ///
    /// The task runs a 60-second interval loop that:
    /// 1. Checks active proposals for timeout expiry via `resolve()`.
    /// 2. Detects proposer/voter departures and adjusts tallies.
    /// 3. Detects deadlock conditions and emits recovery events.
    /// 4. Evaluates consequence rules for all members (#1531).
    /// 5. Drains the persistent MLS commit broadcast retry queue (PR #1606 C6).
    ///
    /// The task stops when the context is no longer `Active` or when
    /// cancelled via [`GovernanceTimeoutTask::cancel()`].
    #[allow(clippy::too_many_lines)] // Five-phase task spawn closure; phases are factored into helper methods.
    pub(super) async fn start_governance_timeout_task(&self, context_id: &str) {
        let contexts = Arc::clone(&self.contexts);
        let clock = Arc::clone(&self.clock);
        let event_log = Arc::clone(&self.event_log);
        // PR #1606 C6: capture the transport so the commit retry phase can
        // re-attempt MLS Commit broadcasts without needing a `&self` reference
        // (the spawned task does not own the manager).
        let transport = Arc::clone(&self.transport);
        let ctx_id = context_id.to_owned();

        // Lock ordering: task_set before contexts (consistent with spawn_ttl_timer).
        let mut task_set = self.task_set.lock().await;
        let Some(ctx_entry) = self.contexts.get(&ctx_id) else {
            return;
        };
        let ctx_arc = Arc::clone(ctx_entry.value());
        drop(ctx_entry);
        let mut guard = ctx_arc.lock().await;
        let ctx = &mut *guard;

        ctx.governance.timeout_task.start_in(&mut task_set, {
            let ctx_id = ctx_id.clone();
            let clock = Arc::clone(&clock);
            let event_log = Arc::clone(&event_log);
            let transport = Arc::clone(&transport);
            move || {
                let contexts = Arc::clone(&contexts);
                let clock = Arc::clone(&clock);
                let event_log = Arc::clone(&event_log);
                let transport_for_retry = Arc::clone(&transport);
                let event_log_for_retry = Arc::clone(&event_log);
                let clock_for_retry = Arc::clone(&clock);
                let ctx_id = ctx_id.clone();
                async move {
                    // Phase 1: Acquire lock, snapshot data, process proposals,
                    // detect deadlock, release lock.
                    let (result, conditions, mls_epoch, recovery_in_progress) = {
                        let Some(ctx_entry) = contexts.get(&ctx_id) else {
                            return false; // Context removed — stop the loop.
                        };
                        let ctx_arc = Arc::clone(ctx_entry.value());
                        drop(ctx_entry);
                        let mut guard = ctx_arc.lock().await;
                        let ctx = &mut *guard;

                        // Use blocking async read — `try_read_state()` returns
                        // `None` on transient write-contention which would
                        // permanently stop this task.
                        if !matches!(
                            ctx.handle.state().await,
                            scp_protocol::context::ContextState::Active
                        ) {
                            return false; // No longer active — stop the loop.
                        }

                        let gov_ctx = Self::build_governance_context(ctx, &*clock);
                        // Detect departed members since last tick.
                        let current_members: HashSet<DID> =
                            ctx.membership.members().map(|m| m.did.clone()).collect();
                        let departed: Vec<DID> = ctx
                            .governance
                            .last_known_members
                            .difference(&current_members)
                            .cloned()
                            .collect();
                        ctx.governance.last_known_members = current_members;

                        // Evict stale cache entries to prevent unbounded growth
                        // of participation_cache and cooldown_until (#1530).
                        ctx.governance.evict_stale_entries(clock.now_secs());

                        // Drain epoch-reset members accumulated since last tick
                        // (ADR-031 §5: votes from reset members are invalidated).
                        let epoch_resets: Vec<DID> =
                            std::mem::take(&mut ctx.governance.pending_epoch_resets);

                        let mls_epoch = ctx.epoch.mls_epoch;
                        let recovery_in_progress = ctx.governance.deadlock.recovery_in_progress;

                        // Snapshot active voters BEFORE processing proposals so
                        // voters on about-to-resolve proposals are still visible.
                        let active_voters = collect_active_voters(ctx.governance.engine.as_ref());

                        // Process pending proposals for timeout/departures/epoch resets.
                        let result = process_pending_proposals(
                            ctx.governance.engine.as_mut(),
                            &gov_ctx,
                            &departed,
                            &epoch_resets,
                        );

                        // Update deadlock detection state before detecting
                        // deadlock so missed-window counters reflect this tick.
                        update_detection_state(
                            &mut ctx.governance.deadlock,
                            ctx.governance.engine.as_ref(),
                            &gov_ctx,
                            &active_voters,
                        );

                        // Detect deadlock conditions (ADR-031 §10).
                        let conditions = crate::context::governance::timeout::detect_deadlock(
                            ctx.governance.engine.as_ref(),
                            &gov_ctx,
                            &ctx.governance.deadlock,
                        );

                        (result, conditions, mls_epoch, recovery_in_progress)
                        // Lock dropped here.
                    };

                    // Phase 2: Build context events (no lock needed).
                    let ctx_events = Self::translate_timeout_events(
                        &result.events,
                        mls_epoch,
                        &conditions,
                        recovery_in_progress,
                    );

                    // Phase 3: Write results back and update recovery state.
                    let needs_write = !ctx_events.is_empty()
                        || (conditions.is_empty() && recovery_in_progress)
                        || (!conditions.is_empty() && !recovery_in_progress);
                    if needs_write && let Some(ctx_entry) = contexts.get(&ctx_id) {
                        let ctx_arc = Arc::clone(ctx_entry.value());
                        drop(ctx_entry);
                        let mut guard = ctx_arc.lock().await;
                        let ctx = &mut *guard;
                        for ctx_event in ctx_events {
                            ctx.receive_buffer.push(ctx_event);
                        }
                        // Reset recovery_in_progress when deadlock conditions
                        // clear so future deadlocks can be detected.
                        if conditions.is_empty() && recovery_in_progress {
                            ctx.governance.deadlock.recovery_in_progress = false;
                        } else if !conditions.is_empty() && !recovery_in_progress {
                            ctx.governance.deadlock.recovery_in_progress = true;
                        }
                    }

                    // Phase 4: Periodic consequence evaluation (#1531).
                    Self::evaluate_periodic_consequences(&contexts, &ctx_id, &*clock, &*event_log)
                        .await;

                    // Phase 5 (PR #1606 C6): drain the persistent MLS
                    // commit retry queue. Retries any pending commits
                    // whose backoff timer has elapsed and either dequeues
                    // them on success or marks the context fail-closed
                    // when the retry budget is exhausted.
                    //
                    // Note: this phase needs `&self` (transport, event log,
                    // clock) which the closure captures via Self in the
                    // outer task. The outer task does not have a `self`
                    // reference, so we delegate to the static helper
                    // `process_pending_commits_static` that takes the same
                    // bag of providers the closure already captures.
                    Self::process_pending_commits_static(
                        &contexts,
                        &ctx_id,
                        Arc::clone(&transport_for_retry),
                        Arc::clone(&event_log_for_retry),
                        Arc::clone(&clock_for_retry),
                    )
                    .await;

                    true // Continue the loop.
                }
            }
        });
    }

    /// Phase 4 of the governance timeout task: evaluates consequence rules for
    /// all members (#1531).
    ///
    /// Time-based rules (e.g., "if no messages in 1 hour, downgrade role") must
    /// fire even when no user action occurs. Evaluates all members on every
    /// tick. Early return when no rules are configured (the common case).
    async fn evaluate_periodic_consequences(
        contexts: &Arc<super::DashMap<String, Arc<super::Mutex<PerContextState>>>>,
        ctx_id: &str,
        clock: &dyn Clock,
        event_log: &dyn super::super::builder::ContextEventLogProvider,
    ) {
        // M9: Clone data under lock, drop lock for evaluation, reacquire
        // for enforcement. This prevents holding the contexts lock for
        // the entire evaluation duration (which includes event log I/O).
        let now = clock.now_secs();
        let (rules, member_dids, events) = {
            let Some(ctx_entry) = contexts.get(ctx_id) else {
                return;
            };
            let ctx_arc = Arc::clone(ctx_entry.value());
            drop(ctx_entry);
            let guard = ctx_arc.lock().await;
            let ctx = &*guard;
            let rules = ctx.governance.consequence_rules.clone();
            if rules.is_empty() {
                return;
            }
            let member_dids: Vec<DID> = ctx.membership.members().map(|m| m.did.clone()).collect();
            let events = event_log_entries_for_consequences(ctx, ctx_id, now, event_log);
            (rules, member_dids, events)
        };
        // Lock dropped — pure evaluation with no lock held.
        let mut results: Vec<(DID, Vec<TriggeredConsequence>)> = Vec::new();
        for member_did in member_dids {
            let triggered = evaluate_consequence_rules(&rules, &events, member_did.as_ref(), now);
            if !triggered.is_empty() {
                results.push((member_did, triggered));
            }
        }
        if results.is_empty() {
            return;
        }
        // Reacquire lock for enforcement.
        let Some(ctx_entry) = contexts.get(ctx_id) else {
            return;
        };
        let ctx_arc = Arc::clone(ctx_entry.value());
        drop(ctx_entry);
        let mut guard = ctx_arc.lock().await;
        let ctx = &mut *guard;
        let ctx = &mut *ctx;
        for (member_did, triggered) in &results {
            enforce_triggered_consequences(
                ctx,
                &EnforceConsequencesCtx {
                    context_id: ctx_id,
                    member_did,
                    now,
                    triggered,
                    rules: &rules,
                    clock,
                    event_log,
                },
            );
        }
    }

    /// Detects and handles conflicts when a proposal becomes approved (ADR-031 §7).
    ///
    /// Checks if the newly approved proposal conflicts with any other approved
    /// proposals. Handles sequential conflicts (lower monotonic sequence
    /// number wins) and simultaneous conflicts (governance freeze).
    ///
    /// # H10: monotonic seq, not wall-clock timestamp
    ///
    /// Sequence numbers come from
    /// [`GovernanceState::next_proposal_seq`], a strictly monotonic
    /// per-context counter persisted in the snapshot. Previously this
    /// function used `clock.now_secs()` (1-second granularity) as the
    /// sequence. Two proposals approved within the same wall-clock
    /// second compared as `Equal`, which routed them into a 48-hour
    /// governance freeze. With `GovernancePropose` capability, an
    /// attacker could race a conflicting proposal against any defensive
    /// admin action and brick governance for two days. The monotonic
    /// counter eliminates that collision window: every approved
    /// proposal receives a strictly unique seq, even within the same
    /// wall-clock second and even across process restarts (the counter
    /// is persisted).
    ///
    /// The wall-clock timestamp is still recorded in the third tuple
    /// slot (`approved_at_unix_secs`) and on the freeze record so audit
    /// consumers and the 48-hour freeze-expiry timer continue to work
    /// against real time.
    ///
    /// # Arguments
    /// * `ctx` - The context state containing approved proposals
    /// * `new_proposal` - The newly approved proposal to check for conflicts
    ///
    /// # Returns
    /// A vector of governance events to emit (empty if no conflicts)
    #[allow(clippy::unused_self)] // method for API consistency within ContextManager
    pub(super) fn detect_and_handle_conflicts(
        &self,
        ctx: &mut PerContextState,
        new_proposal: &GovernanceProposal,
    ) -> Vec<GovernanceEvent> {
        use scp_protocol::context::governance::{GovernanceEvent, actions_conflict};

        let mut events = Vec::new();
        // Wall-clock timestamp — used ONLY for the audit slot of
        // `approved_proposals` and for the freeze start time. Never
        // used for sequence comparison (H10).
        let current_timestamp = self.clock.now_secs();

        // H10: assign the monotonic seq for the new proposal up front,
        // and bump the counter immediately so any nested or concurrent
        // call cannot reuse it. `saturating_add` matches the rest of
        // the runtime — wraparound is impossible in practice (u64 at
        // 1 proposal/sec exceeds the heat death of the universe), and
        // saturating semantics prevent any DoS vector even under
        // pathological forged input.
        let new_seq = ctx.governance.next_proposal_seq;
        ctx.governance.next_proposal_seq = ctx.governance.next_proposal_seq.saturating_add(1);

        // Check for conflicts with existing approved proposals
        let mut conflicts = Vec::new();
        for (existing_id, (existing_proposal, existing_seq, existing_timestamp)) in
            &ctx.governance.approved_proposals
        {
            if actions_conflict(
                &new_proposal.action,
                &new_proposal.proposer_did,
                &existing_proposal.action,
                &existing_proposal.proposer_did,
            ) {
                conflicts.push((
                    *existing_id,
                    *existing_seq,
                    *existing_timestamp,
                    existing_proposal.clone(),
                ));
            }
        }

        // Handle conflicts. `new_seq` is strictly greater than every
        // existing `existing_seq` (the counter is monotonic and we
        // bumped it above), so the `Equal` arm is now mathematically
        // unreachable from a real call site. The only way it could
        // fire is via a synthesized `existing_seq` equal to the
        // pre-bump counter — i.e. via tampered persistence. We keep
        // the arm as defense-in-depth: a corrupted snapshot still
        // routes into the freeze rather than silently dropping a
        // proposal, which preserves the existing 48-hour
        // resolution-window invariant for that pathological case.
        for (conflicting_id, conflicting_seq, _conflicting_timestamp, _conflicting_proposal) in
            conflicts
        {
            match new_seq.cmp(&conflicting_seq) {
                std::cmp::Ordering::Equal => {
                    // Simultaneous conflict — only reachable via
                    // tampered persistence (see above). Enter
                    // governance freeze with the wall-clock start
                    // time so the 48-hour expiry works against real
                    // time, not the monotonic counter.
                    ctx.governance.freeze =
                        Some((new_proposal.proposal_id, conflicting_id, current_timestamp));
                    events.push(GovernanceEvent::ConflictDetected {
                        proposal_a: new_proposal.proposal_id,
                        proposal_b: conflicting_id,
                    });
                }
                std::cmp::Ordering::Less => {
                    // Lower seq wins — the new proposal supersedes
                    // the existing one. With the monotonic counter,
                    // `new_seq` is always strictly greater than
                    // every `existing_seq` produced by this code
                    // path, so this branch is only reachable via
                    // tampered persistence (an attacker-supplied
                    // snapshot with `existing_seq > next_proposal_seq`).
                    // Behavior is preserved as-is for spec
                    // consistency — the runtime always honors
                    // "lower seq wins" regardless of source.
                    ctx.governance.approved_proposals.remove(&conflicting_id);
                    events.push(GovernanceEvent::ConflictResolved {
                        winner_id: new_proposal.proposal_id,
                        loser_id: conflicting_id,
                    });
                }
                std::cmp::Ordering::Greater => {
                    // The normal sequential-conflict case: an earlier
                    // proposal already exists (lower seq → earlier),
                    // so it wins and the new proposal is invalidated.
                    // We do NOT add the new proposal to
                    // `approved_proposals`, but the monotonic counter
                    // has already been bumped — by design, every
                    // conflict-detection invocation consumes a seq
                    // slot regardless of outcome, so sequence
                    // numbers are stable across retries and never
                    // reused.
                    events.push(GovernanceEvent::ConflictResolved {
                        winner_id: conflicting_id,
                        loser_id: new_proposal.proposal_id,
                    });
                    return events; // Don't add the new proposal
                }
            }
        }

        // Add the new proposal to approved proposals if not invalidated.
        // Tuple layout (see `GovernanceState::approved_proposals` doc):
        //   .0 = the proposal itself
        //   .1 = monotonic seq (for conflict resolution — H10)
        //   .2 = wall-clock unix seconds at approval (audit only)
        if !events.iter().any(|e| matches!(e, GovernanceEvent::ConflictResolved { loser_id, .. } if *loser_id == new_proposal.proposal_id)) {
            ctx.governance.approved_proposals.insert(
                new_proposal.proposal_id,
                (new_proposal.clone(), new_seq, current_timestamp)
            );
        }

        events
    }

    /// Checks for and resolves expired governance freezes (ADR-031 §7).
    ///
    /// If a governance freeze has been active for more than 48 hours (172800 seconds)
    /// without resolution, both conflicting proposals are invalidated and the freeze
    /// is lifted.
    ///
    /// # Arguments
    /// * `ctx` - The context state to check for expired freezes
    ///
    /// # Returns
    /// A vector of governance events to emit (empty if no expired freezes)
    #[allow(clippy::unused_self)] // method for API consistency within ContextManager
    fn check_and_resolve_expired_freezes(&self, ctx: &mut PerContextState) -> Vec<GovernanceEvent> {
        use scp_protocol::context::governance::GovernanceEvent;

        const FREEZE_TIMEOUT_SECONDS: u64 = 48 * 60 * 60; // 48 hours

        let current_timestamp = self.clock.now_secs();

        if let Some((proposal_a, proposal_b, freeze_start)) = ctx.governance.freeze
            && current_timestamp.saturating_sub(freeze_start) >= FREEZE_TIMEOUT_SECONDS
        {
            // Timeout reached - invalidate both proposals and lift freeze
            ctx.governance.approved_proposals.remove(&proposal_a);
            ctx.governance.approved_proposals.remove(&proposal_b);
            ctx.governance.freeze = None;

            // Both proposals were invalidated by timeout — emit one event
            // per invalidated proposal using the real proposal IDs so
            // downstream consumers can identify exactly which proposals expired.
            return vec![
                GovernanceEvent::ConflictResolved {
                    winner_id: proposal_b,
                    loser_id: proposal_a,
                },
                GovernanceEvent::ConflictResolved {
                    winner_id: proposal_a,
                    loser_id: proposal_b,
                },
            ];
        }

        Vec::new()
    }

    /// Returns the event-log label string for a [`GovernanceEvent`] variant.
    ///
    /// Used when appending governance events to the Merkle event log. Each
    /// variant maps to a deterministic string label so event consumers can
    /// filter by type without deserializing the full event.
    const fn governance_event_label(event: &GovernanceEvent) -> &'static str {
        match event {
            GovernanceEvent::ProposalCreated { .. } => "GovernanceProposalCreated",
            GovernanceEvent::VoteCast { .. } => "GovernanceVoteCast",
            GovernanceEvent::VoteWithdrawn { .. } => "GovernanceVoteWithdrawn",
            GovernanceEvent::ProposalResolved { .. } => "GovernanceProposalResolved",
            GovernanceEvent::DeadlockRecovery { .. } => "GovernanceDeadlockRecovery",
            GovernanceEvent::ConflictDetected { .. } => "GovernanceConflictDetected",
            GovernanceEvent::ConflictResolved { .. } => "GovernanceConflictResolved",
            GovernanceEvent::GovernanceActionExecuted { .. } => "GovernanceActionExecuted",
        }
    }

    // -----------------------------------------------------------------------
    // PR #1606 C6: persistent MLS Commit broadcast retry queue
    // -----------------------------------------------------------------------

    /// Returns `Err(CommitBroadcastFault)` if the context has an active
    /// commit fault marker (PR #1606 C6), otherwise `Ok(())`.
    ///
    /// Called by every governance executor that mutates context state. While
    /// the marker is set, the context is fail-closed: no further mutations
    /// are accepted until an operator clears the marker via
    /// [`acknowledge_commit_fault`](Self::acknowledge_commit_fault).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CommitBroadcastFault`] if the context has an
    /// active fault marker.
    pub(super) fn check_commit_fault(ctx: &PerContextState) -> Result<(), ContextError> {
        if let Some(ref marker) = ctx.commit_fault {
            return Err(ContextError::CommitBroadcastFault {
                operation: marker.operation.label(),
                reason: marker.reason.clone(),
                attempts: marker.retry_count,
            });
        }
        Ok(())
    }

    /// Attempts to broadcast an MLS Commit and, on transport failure,
    /// enqueues the commit in the persistent retry queue (PR #1606 C6).
    ///
    /// On success: appends `CommitBroadcasted` to the durable event log.
    /// On failure: appends a `PendingCommit` to `ctx.pending_commits`,
    /// emits [`ContextEvent::CommitBroadcastPending`] to the receive
    /// buffer, and writes `CommitBroadcastPending` to the durable event log.
    ///
    /// Acquires the contexts mutex internally — callers must NOT hold it.
    /// Returns `Ok(())` even on transport failure: the persistent queue
    /// makes broadcast loss recoverable, so callers should not abort the
    /// caller-visible operation. The mutation that produced this commit
    /// has already been applied locally.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotRegistered`] if the context is
    /// not registered.
    /// Returns [`ContextError::EventLogFailed`] if the durable event log
    /// append fails (rare; persistence is best-effort, but a failed log
    /// append indicates a deeper subsystem fault).
    pub(super) async fn try_broadcast_commit_or_enqueue(
        &self,
        context_id: &str,
        commit_bytes: Vec<u8>,
        operation: CommitOperation,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        if commit_bytes.is_empty() {
            // No-op: nothing to broadcast (e.g., broadcast-mode contexts).
            return Ok(());
        }
        let routing_id = scp_protocol::context::context_routing_id(context_id);
        // First attempt: try to send immediately.
        match self.transport.send_message(&routing_id, &commit_bytes) {
            Ok(()) => {
                let context_id_bytes = context_id_to_bytes(context_id);
                self.event_log.append_context_event(
                    &context_id_bytes,
                    "CommitBroadcasted",
                    actor_did,
                )?;
                {
                    if let Some(entry) = self.contexts.get(context_id) {
                        let ctx_arc = Arc::clone(entry.value());
                        drop(entry);
                        let mut guard = ctx_arc.lock().await;
                        let ctx = &mut *guard;
                        ctx.checkpoint_events_since += 1;
                    }
                }
                Ok(())
            }
            Err(e) => {
                let now = self.clock.now_secs();
                let error_str = e.to_string();
                let backoff = commit_retry_backoff(1);
                let pending = PendingCommit {
                    commit_bytes,
                    routing_id,
                    operation: operation.clone(),
                    first_attempt_at: now,
                    retry_count: 1,
                    last_error: Some(error_str.clone()),
                    next_attempt_at: now.saturating_add(backoff),
                };
                let label = operation.label();
                let context_id_bytes = context_id_to_bytes(context_id);
                {
                    let ctx_arc = self
                        .get_context_arc(context_id)
                        .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
                    let mut guard = ctx_arc.lock().await;
                    let ctx = &mut *guard;
                    // N2: Cap the pending commits queue to prevent unbounded
                    // memory growth during sustained transport outages.
                    if ctx.pending_commits.len() >= MAX_PENDING_COMMITS {
                        ctx.commit_fault = Some(CommitFaultMarker {
                            operation: operation.clone(),
                            reason: format!(
                                "pending commit queue full ({MAX_PENDING_COMMITS} entries)"
                            ),
                            retry_count: 1,
                            failed_at: now,
                        });
                        ctx.receive_buffer
                            .push(ContextEvent::CommitBroadcastFailed {
                                operation: label.clone(),
                                reason: format!("queue full ({MAX_PENDING_COMMITS}): {error_str}"),
                                attempts: 1,
                            });
                        return Ok(());
                    }
                    ctx.pending_commits.push_back(pending);
                    ctx.receive_buffer
                        .push(ContextEvent::CommitBroadcastPending {
                            operation: label.clone(),
                            error: error_str.clone(),
                            attempt: 1,
                        });
                }
                self.event_log.append_context_event(
                    &context_id_bytes,
                    "CommitBroadcastPending",
                    actor_did,
                )?;
                {
                    if let Some(entry) = self.contexts.get(context_id) {
                        let ctx_arc = Arc::clone(entry.value());
                        drop(entry);
                        let mut guard = ctx_arc.lock().await;
                        let ctx = &mut *guard;
                        ctx.checkpoint_events_since += 1;
                    }
                }
                tracing::warn!(
                    context_id = %context_id,
                    operation = %label,
                    error = %error_str,
                    "MLS commit broadcast failed; enqueued for persistent retry (PR #1606 C6)"
                );
                Ok(())
            }
        }
    }

    /// Instance-method wrapper around
    /// [`process_pending_commits_static`](Self::process_pending_commits_static)
    /// that uses the manager's own providers.
    ///
    /// Called from tests and from any path that holds a `&self` reference.
    /// The spawned governance timeout task uses the static helper directly
    /// because it does not own the manager.
    #[allow(dead_code)] // Used by tests; production path uses the static helper.
    pub(super) async fn process_pending_commits(&self, context_id: &str) {
        Self::process_pending_commits_static(
            &self.contexts,
            context_id,
            Arc::clone(&self.transport),
            Arc::clone(&self.event_log),
            Arc::clone(&self.clock),
        )
        .await;
    }

    /// Processes the per-context MLS Commit retry queue (PR #1606 C6).
    ///
    /// Called periodically from
    /// [`start_governance_timeout_task`](Self::start_governance_timeout_task).
    /// Walks `ctx.pending_commits`, retries any commits whose
    /// `next_attempt_at <= now`, and either:
    /// 1. Dequeues on success (emits `CommitBroadcastSucceeded`).
    /// 2. Updates retry count + next attempt on failure (emits
    ///    `CommitBroadcastPending` with the new attempt count).
    /// 3. Marks the context fail-closed and emits `CommitBroadcastFailed`
    ///    when `retry_count >= MAX_COMMIT_RETRIES` or
    ///    `now - first_attempt_at >= MAX_COMMIT_AGE_SECS`.
    ///
    /// All transport sends happen with the contexts lock RELEASED to
    /// avoid holding the lock across I/O.
    pub(super) async fn process_pending_commits_static(
        contexts: &Arc<super::DashMap<String, Arc<super::Mutex<PerContextState>>>>,
        context_id: &str,
        transport: Arc<dyn super::ContextTransportProvider>,
        event_log: Arc<dyn super::ContextEventLogProvider>,
        clock: Arc<dyn Clock>,
    ) {
        // Snapshot the queue under lock.
        let snapshot: Vec<PendingCommit> = {
            let Some(ctx_entry) = contexts.get(context_id) else {
                return;
            };
            let ctx_arc = Arc::clone(ctx_entry.value());
            drop(ctx_entry);
            let guard = ctx_arc.lock().await;
            let ctx = &*guard;
            // If a fault marker is already set, do not retry — the queue
            // is frozen until an operator acknowledges.
            if ctx.commit_fault.is_some() {
                return;
            }
            ctx.pending_commits.iter().cloned().collect()
        };
        if snapshot.is_empty() {
            return;
        }
        let now = clock.now_secs();
        // Phase A (no lock held): retry each pending entry whose backoff has
        // elapsed and classify the outcome.
        let outcomes = Self::compute_commit_retry_outcomes(&snapshot, now, transport.as_ref());
        if outcomes.is_empty() {
            return;
        }
        // Phase B (lock held): apply the outcomes to the queue.
        let context_id_bytes = context_id_to_bytes(context_id);
        let event_log_writes =
            Self::apply_commit_retry_outcomes(contexts, context_id, outcomes, &*clock).await;
        // Phase C (no lock held): append durable event log entries.
        let mut retry_event_count: u64 = 0;
        for label in event_log_writes {
            if let Err(e) = event_log.append_context_event(&context_id_bytes, label, "system") {
                tracing::warn!(
                    context_id = %context_id,
                    error = %e,
                    "failed to append commit retry event to durable log"
                );
            }
            retry_event_count += 1;
        }
        if retry_event_count > 0
            && let Some(ctx_entry) = contexts.get(context_id)
        {
            let ctx_arc = Arc::clone(ctx_entry.value());
            drop(ctx_entry);
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            ctx.checkpoint_events_since += retry_event_count;
        }
    }

    /// Phase A of [`process_pending_commits_static`]: classifies each
    /// pending commit whose backoff has elapsed as `Success`, `Retry`,
    /// or `Failed`. Returns one outcome per processed entry (entries whose
    /// `next_attempt_at` is still in the future are skipped).
    fn compute_commit_retry_outcomes(
        snapshot: &[PendingCommit],
        now: u64,
        transport: &dyn super::ContextTransportProvider,
    ) -> Vec<CommitRetryOutcome> {
        let mut outcomes: Vec<CommitRetryOutcome> = Vec::new();
        for (idx, pending) in snapshot.iter().enumerate() {
            if now < pending.next_attempt_at {
                continue;
            }
            // Age budget check. If we're past MAX_COMMIT_AGE_SECS, force-fail
            // without making another network call.
            let age = now.saturating_sub(pending.first_attempt_at);
            if age >= MAX_COMMIT_AGE_SECS {
                outcomes.push(CommitRetryOutcome {
                    index: idx,
                    kind: CommitRetryOutcomeKind::Failed {
                        reason: format!("max age exceeded ({age}s >= {MAX_COMMIT_AGE_SECS}s)"),
                        attempts: pending.retry_count,
                        operation: pending.operation.clone(),
                    },
                });
                continue;
            }
            // Attempt the send.
            match transport.send_message(&pending.routing_id, &pending.commit_bytes) {
                Ok(()) => {
                    outcomes.push(CommitRetryOutcome {
                        index: idx,
                        kind: CommitRetryOutcomeKind::Success {
                            attempts: pending.retry_count,
                            operation: pending.operation.clone(),
                        },
                    });
                }
                Err(e) => {
                    let new_retry_count = pending.retry_count.saturating_add(1);
                    if new_retry_count > MAX_COMMIT_RETRIES {
                        outcomes.push(CommitRetryOutcome {
                            index: idx,
                            kind: CommitRetryOutcomeKind::Failed {
                                reason: e.to_string(),
                                attempts: new_retry_count,
                                operation: pending.operation.clone(),
                            },
                        });
                    } else {
                        let backoff = commit_retry_backoff(new_retry_count);
                        outcomes.push(CommitRetryOutcome {
                            index: idx,
                            kind: CommitRetryOutcomeKind::Retry {
                                error: e.to_string(),
                                next_attempt_at: now.saturating_add(backoff),
                                new_retry_count,
                                operation: pending.operation.clone(),
                            },
                        });
                    }
                }
            }
        }
        outcomes
    }

    /// Phase B of [`process_pending_commits_static`]: applies the outcomes
    /// to `PerContextState::pending_commits` under lock. Pushes receive
    /// buffer events and returns the labels that should be appended to
    /// the durable event log.
    async fn apply_commit_retry_outcomes(
        contexts: &Arc<super::DashMap<String, Arc<super::Mutex<PerContextState>>>>,
        context_id: &str,
        outcomes: Vec<CommitRetryOutcome>,
        clock: &dyn Clock,
    ) -> Vec<&'static str> {
        let mut event_log_writes: Vec<&'static str> = Vec::new();
        let Some(ctx_entry) = contexts.get(context_id) else {
            return event_log_writes;
        };
        let ctx_arc = Arc::clone(ctx_entry.value());
        drop(ctx_entry);
        let mut guard = ctx_arc.lock().await;
        let ctx = &mut *guard;
        let queue_len = ctx.pending_commits.len();
        // Apply outcomes by their snapshot index. The queue is only mutated
        // by this task (success/failed removals) and by new enqueue calls
        // (which append to the end), so prefix indices remain stable
        // between Phase A and Phase B.
        let mut to_remove: Vec<usize> = Vec::new();
        for outcome in outcomes {
            if outcome.index >= queue_len {
                continue;
            }
            match outcome.kind {
                CommitRetryOutcomeKind::Success {
                    attempts,
                    operation,
                } => {
                    ctx.receive_buffer
                        .push(ContextEvent::CommitBroadcastSucceeded {
                            operation: operation.label(),
                            attempts,
                        });
                    event_log_writes.push("CommitBroadcastSucceeded");
                    to_remove.push(outcome.index);
                }
                CommitRetryOutcomeKind::Retry {
                    error,
                    next_attempt_at,
                    new_retry_count,
                    operation,
                } => {
                    if let Some(entry) = ctx.pending_commits.get_mut(outcome.index) {
                        entry.retry_count = new_retry_count;
                        entry.next_attempt_at = next_attempt_at;
                        entry.last_error = Some(error.clone());
                    }
                    ctx.receive_buffer
                        .push(ContextEvent::CommitBroadcastPending {
                            operation: operation.label(),
                            error,
                            attempt: new_retry_count,
                        });
                    event_log_writes.push("CommitBroadcastPending");
                }
                CommitRetryOutcomeKind::Failed {
                    reason,
                    attempts,
                    operation,
                } => {
                    let now_failed = clock.now_secs();
                    ctx.commit_fault = Some(CommitFaultMarker {
                        operation: operation.clone(),
                        reason: reason.clone(),
                        failed_at: now_failed,
                        retry_count: attempts,
                    });
                    ctx.receive_buffer
                        .push(ContextEvent::CommitBroadcastFailed {
                            operation: operation.label(),
                            reason,
                            attempts,
                        });
                    event_log_writes.push("CommitBroadcastFailed");
                    to_remove.push(outcome.index);
                }
            }
        }
        // Remove successful/failed entries in reverse-index order so earlier
        // indices stay valid.
        to_remove.sort_unstable_by(|a, b| b.cmp(a));
        for idx in to_remove {
            ctx.pending_commits.remove(idx);
        }
        event_log_writes
    }

    /// Acknowledges a commit broadcast fault and clears the fail-close
    /// marker so the context can accept further mutations (PR #1606 C6).
    ///
    /// This is the operator-driven recovery path. It does NOT re-attempt
    /// the failed commit — that data is already lost (or unrecoverable
    /// from the local node's perspective). Callers SHOULD reach out to
    /// remaining members through an out-of-band channel to verify whether
    /// the failed commit's effect (member removal, key rotation) needs to
    /// be re-applied.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotRegistered`] if the context is not
    /// registered. Returns [`ContextError::InvalidState`] if no fault
    /// marker is set.
    #[instrument(skip_all, fields(context_id))]
    pub async fn acknowledge_commit_fault(
        &self,
        context_id: &str,
    ) -> Result<CommitFaultMarker, ContextError> {
        let ctx_arc = self
            .get_context_arc(context_id)
            .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
        let mut guard = ctx_arc.lock().await;
        let ctx = &mut *guard;
        let marker = ctx.commit_fault.take().ok_or_else(|| {
            ContextError::InvalidState(format!(
                "context {context_id} has no commit fault to acknowledge"
            ))
        })?;
        Ok(marker)
    }
}
