//! Governance proposal, vote, execute, and dispatch operations.

use super::{
    AccessScope, Arc, Capability, Clock, CommitFaultMarker, CommitOperation, ConsequenceRule,
    ContextError, ContextEvent, ContextManager, ContextParams, DID, EconomicPolicy,
    GovernanceAction, GovernanceActionResult, GovernanceContext, GovernanceEvent, GovernanceModel,
    GovernanceProposal, HashSet, MAX_COMMIT_AGE_SECS, MAX_COMMIT_RETRIES, MigrationProposedResult,
    MigrationState, PendingCommit, PerContextState, ProposalId, ProposalOutcome, ProposalStatus,
    PruningPolicy, ToolInterface, ToolRegistration, TriggeredConsequence, collect_active_voters,
    commit_retry_backoff, context_id_to_bytes, evaluate_consequence_rules, instrument,
    process_pending_proposals, roles, update_detection_state,
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
pub fn dispatch_consequences(
    ctx: &mut PerContextState,
    context_id: &str,
    member_did: &DID,
    now: u64,
    clock: &dyn scp_primitives::Clock,
    event_log: &dyn super::super::builder::ContextEventLogProvider,
    event_tx: Option<&tokio::sync::broadcast::Sender<(String, super::ContextEvent)>>,
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
pub struct EnforceConsequencesCtx<'a> {
    pub context_id: &'a str,
    pub member_did: &'a DID,
    pub now: u64,
    pub triggered: &'a [TriggeredConsequence],
    pub rules: &'a [ConsequenceRule],
    pub clock: &'a dyn scp_primitives::Clock,
    pub event_log: &'a dyn super::super::builder::ContextEventLogProvider,
    /// Optional broadcast channel for event propagation from free
    /// functions that lack `&self` access to [`ContextManager`].
    pub event_tx: Option<&'a tokio::sync::broadcast::Sender<(String, super::ContextEvent)>>,
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
    let event = ContextEvent::ConsequenceTriggered {
        context_id: args.context_id.to_owned(),
        member_did: args.member_did.clone(),
        rule_index: consequence.rule_index,
        trigger_type: trigger_kind.to_owned(),
        action_type: action_type.to_owned(),
    };
    ctx.emit_event(event, args.context_id, args.event_tx);
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
    let event = ContextEvent::ConsequenceEnforced {
        context_id: args.context_id.to_owned(),
        member_did: args.member_did.clone(),
        action_type: action_type.to_owned(),
        success: false,
    };
    ctx.emit_event(event, args.context_id, args.event_tx);
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
    let event = ContextEvent::ConsequenceEnforced {
        context_id: args.context_id.to_owned(),
        member_did: args.member_did.clone(),
        action_type: action_type.to_owned(),
        success: true,
    };
    ctx.emit_event(event, args.context_id, args.event_tx);
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
    let event = ContextEvent::ConsequenceEnforced {
        context_id: context_id.to_owned(),
        member_did: member_did.clone(),
        action_type: "SuspendAll(escalated)".to_owned(),
        success: true,
    };
    ctx.emit_event(event, context_id, args.event_tx);
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
pub fn event_log_entries_for_consequences(
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
pub fn check_proposer_eligibility(
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
// ADR-049 commit 12c.3b: hoisting every governance-domain method body into
// [`crate::context::governance_helpers`] leaves many inherent forwarders
// reached only from hoisted free-function siblings (via the direct
// `governance_helpers::X(mgr, ...)` form, not via `mgr.X(...)`). The
// forwarders are retained for signature stability during the
// commits-10-to-12 migration window — deleted in commit 12f alongside
// every other `ContextManager` governance surface. Until then, the
// `dead_code` lint fires on the internal transitives
// (`finalize_governance_action`, `dispatch_*_governance_action`,
// `propose_governance_action_inner`, `vote_on_proposal_inner`, every
// `execute_*` helper). Block-level `#[allow(dead_code)]` mirrors the
// 12c.2 lifecycle pattern at scale — individual annotations on 30+
// methods would be noisy without adding safety.
#[allow(dead_code)]
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
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_governance_action — Supervisor must be attached"
                    .to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_governance_action(&sup, context_id, proposal)
            .await
    }

    /// Post-dispatch finalization for an executed governance action.
    ///
    /// Handles MLS epoch coordination (ADR-031 §8), event emission
    /// (PRD SCP-269/SCP-270), checkpoint cosignature triggering (ADR-031 §9),
    /// and cleanup of approved proposals (ADR-031 §7).
    ///
    /// Extracted from [`execute_governance_action`] to keep that method
    /// focused on validation and dispatch.
    #[allow(clippy::too_many_lines, clippy::option_if_let_else)]
    pub(crate) async fn finalize_governance_action(
        &self,
        context_id: &str,
        proposal: &GovernanceProposal,
        ctx_gen: &super::ContextGeneration,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::finalize_governance_action — Supervisor must be attached"
                    .to_owned(),
            )
        })?;
        crate::context::governance_helpers::finalize_governance_action(
            &sup, context_id, proposal, ctx_gen,
        )
        .await
    }

    /// Dispatches an approved governance action to its implementation method.
    ///
    /// Separated from [`execute_governance_action`] to keep the public entry
    /// point focused on validation while this method handles the 28-action
    /// dispatch.
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn dispatch_governance_action(
        &self,
        context_id: &str,
        proposal: &GovernanceProposal,
    ) -> Result<GovernanceActionResult, ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::dispatch_governance_action — Supervisor must be attached"
                    .to_owned(),
            )
        })?;
        crate::context::governance_helpers::dispatch_governance_action(&sup, context_id, proposal)
            .await
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
    pub(crate) async fn dispatch_context_governance_action(
        &self,
        context_id: &str,
        action: &GovernanceAction,
        pid: ProposalId,
        actor_did: &str,
    ) -> Result<GovernanceActionResult, ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::dispatch_context_governance_action — Supervisor must be attached"
                    .to_owned(),
            )
        })?;
        crate::context::governance_helpers::dispatch_context_governance_action(
            &sup, context_id, action, pid, actor_did,
        )
        .await
    }

    /// Dispatches content access, structural, and reconfiguration governance
    /// actions. Companion to [`dispatch_context_governance_action`].
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn dispatch_content_governance_action(
        &self,
        context_id: &str,
        action: &GovernanceAction,
        pid: ProposalId,
        actor_did: &str,
    ) -> Result<GovernanceActionResult, ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::dispatch_content_governance_action — Supervisor must be attached"
                    .to_owned(),
            )
        })?;
        crate::context::governance_helpers::dispatch_content_governance_action(
            &sup, context_id, action, pid, actor_did,
        )
        .await
    }

    /// Builds a [`GovernanceContext`] snapshot for the governance engine from
    /// the current per-context state.
    pub(crate) fn build_governance_context(
        ctx: &PerContextState,
        clock: &dyn Clock,
    ) -> GovernanceContext {
        crate::context::governance_helpers::build_governance_context(ctx, clock)
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
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::propose_governance_action — Supervisor must be attached"
                    .to_owned(),
            )
        })?;
        // Box::pin — the hoisted body's locals (proposal context, governance
        // engine snapshot, MLS coordination future) cross clippy's 16 KB
        // stack budget for async futures. Heap-allocate per-call.
        Box::pin(
            crate::context::governance_helpers::propose_governance_action(
                &sup,
                context_id,
                proposer_did,
                action,
                signing_key,
            ),
        )
        .await
    }

    /// Inner implementation of proposal submission with auto-execution.
    ///
    /// Returns the proposal, events, and optional execution result. The
    /// execution result is `Some` when the proposal was auto-approved
    /// (`SingleAdmin`) and the action was successfully executed.
    ///
    /// When `check_propose_capability` is `true`, the `GovernancePropose`
    /// capability is verified under the same lock as the proposal submission,
    /// eliminating the TOCTOU race in `propose_governance_action_checked`.
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn propose_governance_action_inner(
        &self,
        context_id: &str,
        proposer_did: &DID,
        action: GovernanceAction,
        signing_key: &ed25519_dalek::SigningKey,
        check_propose_capability: bool,
    ) -> Result<
        (
            GovernanceProposal,
            Vec<GovernanceEvent>,
            Option<GovernanceActionResult>,
        ),
        ContextError,
    > {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::propose_governance_action_inner — Supervisor must be attached"
                    .to_owned(),
            )
        })?;
        crate::context::governance_helpers::propose_governance_action_inner(
            &sup,
            context_id,
            proposer_did,
            action,
            signing_key,
            check_propose_capability,
        )
        .await
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
    #[instrument(skip_all, fields(context_id))]
    pub async fn vote_on_proposal(
        &self,
        context_id: &str,
        proposal_id: &ProposalId,
        voter_did: &DID,
        approve: bool,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(ProposalStatus, Vec<GovernanceEvent>), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::vote_on_proposal — Supervisor must be attached".to_owned(),
            )
        })?;
        // Box::pin — the hoisted body's state crosses clippy's 16-KB
        // async-future budget (governance + MLS coordinator locals).
        Box::pin(crate::context::governance_helpers::vote_on_proposal(
            &sup,
            context_id,
            proposal_id,
            voter_did,
            approve,
            signing_key,
        ))
        .await
    }

    /// Inner vote implementation. When `check_vote_capability` is `true`,
    /// additionally verifies `GovernanceVote` via `member_has_capability`
    /// under the same lock as the vote (eliminates the TOCTOU window from
    /// the previous separate lock block in `approve_governance_proposal` /
    /// `reject_governance_proposal`).
    #[allow(clippy::too_many_lines)]
    #[instrument(skip_all, fields(context_id))]
    pub(crate) async fn vote_on_proposal_inner(
        &self,
        context_id: &str,
        proposal_id: &ProposalId,
        voter_did: &DID,
        approve: bool,
        signing_key: &ed25519_dalek::SigningKey,
        check_vote_capability: bool,
    ) -> Result<(ProposalStatus, Vec<GovernanceEvent>), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::vote_on_proposal_inner — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::governance_helpers::vote_on_proposal_inner(
            &sup,
            context_id,
            proposal_id,
            voter_did,
            approve,
            signing_key,
            check_vote_capability,
        )
        .await
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
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::get_proposal — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::governance_helpers::get_proposal(&sup, context_id, proposal_id).await
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
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::list_proposals — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::governance_helpers::list_proposals(&sup, context_id).await
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
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::propose_governance_action_checked — Supervisor must be attached"
                    .to_owned(),
            )
        })?;
        // Box::pin — see sibling `propose_governance_action`. The
        // `_checked` variant additionally carries a UCAN capability
        // verification future, so its frame is at least as large.
        Box::pin(
            crate::context::governance_helpers::propose_governance_action_checked(
                &sup,
                context_id,
                proposer_did,
                action,
                signing_key,
            ),
        )
        .await
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
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::approve_governance_proposal — Supervisor must be attached"
                    .to_owned(),
            )
        })?;
        // Box::pin — see `vote_on_proposal` for the 16-KB budget rationale.
        Box::pin(
            crate::context::governance_helpers::approve_governance_proposal(
                &sup,
                context_id,
                proposal_id,
                voter_did,
                signing_key,
            ),
        )
        .await
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
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::reject_governance_proposal — Supervisor must be attached"
                    .to_owned(),
            )
        })?;
        // Box::pin — see `vote_on_proposal` for the 16-KB budget rationale.
        Box::pin(
            crate::context::governance_helpers::reject_governance_proposal(
                &sup,
                context_id,
                proposal_id,
                voter_did,
                signing_key,
            ),
        )
        .await
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
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::withdraw_governance_vote — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::governance_helpers::withdraw_governance_vote(
            &sup,
            context_id,
            proposal_id,
            voter_did,
        )
        .await
    }

    /// Executes a `SuspendMember` governance action.
    ///
    /// Suspends specific capabilities for a member via the role state's
    /// `suspend_capabilities` method. The member remains in the context
    /// but the suspended capabilities are blocked at the application-level
    /// gates (`send_message`, `deliver_incoming`, etc.).
    ///
    /// Requires the `MemberBan` capability in the context's ceiling (§5.3).
    pub(crate) async fn execute_suspend_member(
        &self,
        context_id: &str,
        did: &DID,
        capabilities: &[Capability],
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_suspend_member — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_suspend_member(
            &sup,
            context_id,
            did,
            capabilities,
            proposal_id,
            actor_did,
        )
        .await
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
    pub(crate) async fn execute_revoke(
        &self,
        context_id: &str,
        did: &DID,
        access: AccessScope,
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<usize, ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_revoke — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_revoke(
            &sup,
            context_id,
            did,
            access,
            proposal_id,
            actor_did,
        )
        .await
    }

    /// Executes a `RestoreAccess` governance action.
    ///
    /// Restores previously suspended capabilities and, for read revocations,
    /// generates a new access key (forward-only restoration, §9.16.8).
    /// Content encrypted during the revocation period remains permanently
    /// inaccessible.
    ///
    /// Requires the `MemberBan` capability in the context's ceiling (§5.3).
    pub(crate) async fn execute_restore_access(
        &self,
        context_id: &str,
        did: &DID,
        capabilities: &[Capability],
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_restore_access — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_restore_access(
            &sup,
            context_id,
            did,
            capabilities,
            proposal_id,
            actor_did,
        )
        .await
    }

    pub(crate) async fn execute_add_member(
        &self,
        context_id: &str,
        did: &DID,
        role: &str,
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_add_member — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_add_member(
            &sup,
            context_id,
            did,
            role,
            proposal_id,
            actor_did,
        )
        .await
    }

    pub(crate) async fn execute_remove_member(
        &self,
        context_id: &str,
        did: &DID,
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_remove_member — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_remove_member(
            &sup,
            context_id,
            did,
            proposal_id,
            actor_did,
        )
        .await
    }

    pub(crate) async fn execute_change_role(
        &self,
        context_id: &str,
        did: &DID,
        new_role: &str,
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_change_role — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_change_role(
            &sup,
            context_id,
            did,
            new_role,
            proposal_id,
            actor_did,
        )
        .await
    }

    /// Registers a tool in the context. Requires `ToolRegister` in the
    /// context's ceiling (§5.3). Without this capability in the ceiling,
    /// the context does not support tool registration.
    pub(crate) async fn execute_register_tool(
        &self,
        context_id: &str,
        registration: &ToolRegistration,
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_register_tool — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_register_tool(
            &sup,
            context_id,
            registration,
            proposal_id,
            actor_did,
        )
        .await
    }

    pub(crate) async fn execute_remove_tool(
        &self,
        context_id: &str,
        tool_id: &str,
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_remove_tool — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_remove_tool(
            &sup,
            context_id,
            tool_id,
            proposal_id,
            actor_did,
        )
        .await
    }

    pub(crate) async fn execute_modify_ceiling(
        &self,
        context_id: &str,
        new_ceiling: &[Capability],
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_modify_ceiling — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_modify_ceiling(
            &sup,
            context_id,
            new_ceiling,
            proposal_id,
            actor_did,
        )
        .await
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
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::apply_pending_ceiling_modification — Supervisor must be attached"
                    .to_owned(),
            )
        })?;
        crate::context::governance_helpers::apply_pending_ceiling_modification(
            &sup,
            context_id,
            current_timestamp,
        )
        .await
    }

    #[allow(clippy::option_if_let_else)]
    pub(crate) async fn execute_close_context(
        &self,
        context_id: &str,
        reason: Option<&str>,
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_close_context — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_close_context(
            &sup,
            context_id,
            reason,
            proposal_id,
            actor_did,
        )
        .await
    }

    /// Extends the context's TTL. Requires unanimous consent from ALL
    /// current members regardless of governance model — protocol-level
    /// override per ADR-031 §4d and spec §5.10.
    pub(crate) async fn execute_extend_ttl(
        &self,
        context_id: &str,
        additional_secs: u64,
        approvals: &[scp_protocol::context::governance::SignedVote],
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_extend_ttl — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_extend_ttl(
            &sup,
            context_id,
            additional_secs,
            approvals,
            proposal_id,
            actor_did,
        )
        .await
    }

    pub(crate) async fn execute_transfer_admin(
        &self,
        context_id: &str,
        new_admin: &DID,
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_transfer_admin — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_transfer_admin(
            &sup,
            context_id,
            new_admin,
            proposal_id,
            actor_did,
        )
        .await
    }

    /// Creates a child context from this parent. Requires `ChildContextCreate`
    /// in the parent context's ceiling (§5.3, §5.13).
    pub(crate) async fn execute_create_child_context(
        &self,
        context_id: &str,
        params: &ContextParams,
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_create_child_context — Supervisor must be attached"
                    .to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_create_child_context(
            &sup,
            context_id,
            params,
            proposal_id,
            actor_did,
        )
        .await
    }

    pub(crate) async fn execute_modify_pruning_policy(
        &self,
        context_id: &str,
        new_policy: &PruningPolicy,
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_modify_pruning_policy — Supervisor must be attached"
                    .to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_modify_pruning_policy(
            &sup,
            context_id,
            new_policy,
            proposal_id,
            actor_did,
        )
        .await
    }

    /// Adds a signer to the threshold set and mints `GovernanceVote` +
    /// `GovernancePropose` UCANs for the new signer (ADR-031 §6).
    pub(crate) async fn execute_add_signer(
        &self,
        context_id: &str,
        did: &DID,
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_add_signer — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_add_signer(
            &sup,
            context_id,
            did,
            proposal_id,
            actor_did,
        )
        .await
    }

    /// Removes a signer from the threshold set, revokes their governance
    /// UCANs, and validates threshold <= remaining signers (ADR-031 §6).
    pub(crate) async fn execute_remove_signer(
        &self,
        context_id: &str,
        did: &DID,
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_remove_signer — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_remove_signer(
            &sup,
            context_id,
            did,
            proposal_id,
            actor_did,
        )
        .await
    }

    pub(crate) async fn execute_modify_threshold(
        &self,
        context_id: &str,
        new_threshold: u32,
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_modify_threshold — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_modify_threshold(
            &sup,
            context_id,
            new_threshold,
            proposal_id,
            actor_did,
        )
        .await
    }

    /// Establishes a cross-context tool interface. Requires `ToolInterface`
    /// in the context's ceiling (§5.3, §6.2). Without this capability in the
    /// ceiling, the context does not support tool interface exposure.
    pub(crate) async fn execute_establish_tool_interface(
        &self,
        context_id: &str,
        interface: &ToolInterface,
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_establish_tool_interface — Supervisor must be attached"
                    .to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_establish_tool_interface(
            &sup,
            context_id,
            interface,
            proposal_id,
            actor_did,
        )
        .await
    }

    pub(crate) async fn execute_reset_member(
        &self,
        context_id: &str,
        did: &DID,
        reason: &str,
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_reset_member — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_reset_member(
            &sup,
            context_id,
            did,
            reason,
            proposal_id,
            actor_did,
        )
        .await
    }

    pub(crate) async fn execute_resolve_conflict(
        &self,
        context_id: &str,
        proposal_a: &ProposalId,
        proposal_b: &ProposalId,
        resolution: &scp_protocol::context::governance::ConflictResolution,
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_resolve_conflict — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_resolve_conflict(
            &sup,
            context_id,
            proposal_a,
            proposal_b,
            resolution,
            proposal_id,
            actor_did,
        )
        .await
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
    pub(crate) async fn execute_promote_context(
        &self,
        context_id: &str,
        approvals: &[scp_protocol::context::governance::SignedVote],
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_promote_context — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_promote_context(
            &sup,
            context_id,
            approvals,
            proposal_id,
            actor_did,
        )
        .await
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
    pub(crate) async fn execute_rotate_content_keys(
        &self,
        context_id: &str,
        reason: Option<&str>,
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_rotate_content_keys — Supervisor must be attached"
                    .to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_rotate_content_keys(
            &sup,
            context_id,
            reason,
            proposal_id,
            actor_did,
        )
        .await
    }

    pub(crate) async fn execute_reconfigure_governance(
        &self,
        context_id: &str,
        changes: &[scp_protocol::context::governance::GovernanceReconfigAction],
        justification: &scp_protocol::context::governance::DeadlockJustification,
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_reconfigure_governance — Supervisor must be attached"
                    .to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_reconfigure_governance(
            &sup,
            context_id,
            changes,
            justification,
            proposal_id,
            actor_did,
        )
        .await
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
    pub(crate) async fn execute_set_economic_policy(
        &self,
        context_id: &str,
        policy: &EconomicPolicy,
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_set_economic_policy — Supervisor must be attached"
                    .to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_set_economic_policy(
            &sup,
            context_id,
            policy,
            proposal_id,
            actor_did,
        )
        .await
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
        let sup = self.supervisor().ok_or_else(|| ContextError::NotInitialized("ContextManager::apply_pending_economic_policy_change — Supervisor must be attached".to_owned()))?;
        crate::context::governance_helpers::apply_pending_economic_policy_change(
            &sup,
            context_id,
            current_timestamp,
        )
        .await
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
    pub(crate) async fn execute_approve_spend(
        &self,
        context_id: &str,
        spender: &DID,
        amount: scp_protocol::economy::types::Amount,
        purpose: &str,
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_approve_spend — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_approve_spend(
            &sup,
            context_id,
            spender,
            amount,
            purpose,
            proposal_id,
            actor_did,
        )
        .await
    }

    /// Locks the economic policy, making it immutable (§19.3).
    ///
    /// # Errors
    ///
    /// - [`ContextError::PermissionDenied`] if no economic policy is set or
    ///   the policy is already locked.
    /// - [`ContextError::ContextNotRegistered`] if the context is not registered.
    /// - [`ContextError::ContextNotActive`] if the context is not active.
    pub(crate) async fn execute_lock_economic_policy(
        &self,
        context_id: &str,
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_lock_economic_policy — Supervisor must be attached"
                    .to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_lock_economic_policy(
            &sup,
            context_id,
            proposal_id,
            actor_did,
        )
        .await
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
    pub(crate) async fn execute_modify_hard_rate_limit(
        &self,
        context_id: &str,
        new_config: &scp_protocol::economy::antispam::HardRateLimitConfig,
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_modify_hard_rate_limit — Supervisor must be attached"
                    .to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_modify_hard_rate_limit(
            &sup,
            context_id,
            new_config,
            proposal_id,
            actor_did,
        )
        .await
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
    pub(crate) async fn execute_propose_context_migration(
        &self,
        context_id: &str,
        new_contextparams: &scp_protocol::context::params::ContextParams,
        reason: &str,
        grace_period_secs: u64,
        auto_invite: bool,
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<MigrationProposedResult, ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_propose_context_migration — Supervisor must be attached"
                    .to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_propose_context_migration(
            &sup,
            context_id,
            new_contextparams,
            reason,
            grace_period_secs,
            auto_invite,
            proposal_id,
            actor_did,
        )
        .await
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
    pub(crate) async fn execute_cancel_context_migration(
        &self,
        context_id: &str,
        proposal_id: ProposalId,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::execute_cancel_context_migration — Supervisor must be attached"
                    .to_owned(),
            )
        })?;
        crate::context::governance_helpers::execute_cancel_context_migration(
            &sup,
            context_id,
            proposal_id,
            actor_did,
        )
        .await
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
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::tombstone_migrated_context — Supervisor must be attached"
                    .to_owned(),
            )
        })?;
        crate::context::governance_helpers::tombstone_migrated_context(&sup, context_id).await
    }

    /// Returns the migration state for a context, if any.
    ///
    /// Returns `None` if the context is not registered or not migrating.
    #[instrument(skip_all, fields(context_id))]
    pub async fn migration_state(&self, context_id: &str) -> Option<MigrationState> {
        // ADR-049 commit 12c.9c — `Option`-returning forwarder: a
        // missing supervisor collapses to `None`.
        let sup = self.supervisor()?;
        crate::context::governance_helpers::migration_state(&sup, context_id).await
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
    pub(crate) async fn start_governance_timeout_task(&self, context_id: &str) {
        let contexts = self.contexts_arc();
        let clock = Arc::clone(&self.clock);
        let event_log = Arc::clone(&self.event_log);
        // PR #1606 C6: capture the transport so the commit retry phase can
        // re-attempt MLS Commit broadcasts without needing a `&self` reference
        // (the spawned task does not own the manager).
        let transport = Arc::clone(&self.transport);
        let event_tx = self.event_tx.clone();
        let ctx_id = context_id.to_owned();

        // Lock ordering: task_set before contexts (consistent with spawn_ttl_timer).
        let mut task_set = self.task_set.lock().await;
        let Ok(ctx_arc) = self.get_context_arc(&ctx_id) else {
            return;
        };
        let mut guard = ctx_arc.lock().await;
        let ctx = &mut *guard;

        ctx.governance.timeout_task.start_in(&mut task_set, {
            let ctx_id = ctx_id.clone();
            let clock = Arc::clone(&clock);
            let event_log = Arc::clone(&event_log);
            let transport = Arc::clone(&transport);
            let event_tx = event_tx.clone();
            move || {
                let contexts = Arc::clone(&contexts);
                let clock = Arc::clone(&clock);
                let event_log = Arc::clone(&event_log);
                let event_tx = event_tx.clone();
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

                        // Use try_read_state() to avoid deadlock: the per-context
                        // Mutex is already held, and handle.state().await would
                        // await on the ContextHandle RwLock, deadlocking against
                        // any task holding the RwLock write and waiting for this
                        // Mutex.
                        let current_state = ctx.handle.try_read_state();
                        if !matches!(
                            current_state,
                            Some(scp_protocol::context::ContextState::Active)
                        ) {
                            // None = write-contended, try again next tick.
                            // Not Active = context closing, stop the loop.
                            return current_state.is_none(); // true = continue, false = stop
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
                            ctx.emit_event(ctx_event, &ctx_id, event_tx.as_ref());
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
                    Self::evaluate_periodic_consequences(
                        &contexts,
                        &ctx_id,
                        &*clock,
                        &*event_log,
                        event_tx.as_ref(),
                    )
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
                        event_tx.clone(),
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
        event_tx: Option<&tokio::sync::broadcast::Sender<(String, super::ContextEvent)>>,
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
                    event_tx,
                },
            );
        }
    }

    /// Returns the event-log label string for a [`GovernanceEvent`] variant.
    ///
    /// Used when appending governance events to the Merkle event log. Each
    /// variant maps to a deterministic string label so event consumers can
    /// filter by type without deserializing the full event.
    pub(crate) const fn governance_event_label(event: &GovernanceEvent) -> &'static str {
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
    pub(crate) fn check_commit_fault(ctx: &PerContextState) -> Result<(), ContextError> {
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
    pub(crate) async fn try_broadcast_commit_or_enqueue(
        &self,
        context_id: &str,
        commit_bytes: Vec<u8>,
        operation: CommitOperation,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::try_broadcast_commit_or_enqueue — Supervisor must be attached"
                    .to_owned(),
            )
        })?;
        crate::context::governance_helpers::try_broadcast_commit_or_enqueue(
            &sup,
            context_id,
            commit_bytes,
            operation,
            actor_did,
        )
        .await
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
        let contexts = self.contexts_arc();
        Self::process_pending_commits_static(
            &contexts,
            context_id,
            Arc::clone(&self.transport),
            Arc::clone(&self.event_log),
            Arc::clone(&self.clock),
            self.event_tx.clone(),
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
        event_tx: Option<tokio::sync::broadcast::Sender<(String, super::ContextEvent)>>,
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
        let event_log_writes = Self::apply_commit_retry_outcomes(
            contexts,
            context_id,
            outcomes,
            &*clock,
            event_tx.as_ref(),
        )
        .await;
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
        event_tx: Option<&tokio::sync::broadcast::Sender<(String, super::ContextEvent)>>,
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
                    ctx.emit_event(
                        ContextEvent::CommitBroadcastSucceeded {
                            operation: operation.label(),
                            attempts,
                        },
                        context_id,
                        event_tx,
                    );
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
                    ctx.emit_event(
                        ContextEvent::CommitBroadcastPending {
                            operation: operation.label(),
                            error,
                            attempt: new_retry_count,
                        },
                        context_id,
                        event_tx,
                    );
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
                    ctx.emit_event(
                        ContextEvent::CommitBroadcastFailed {
                            operation: operation.label(),
                            reason,
                            attempts,
                        },
                        context_id,
                        event_tx,
                    );
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
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::acknowledge_commit_fault — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::governance_helpers::acknowledge_commit_fault(&sup, context_id).await
    }
}
