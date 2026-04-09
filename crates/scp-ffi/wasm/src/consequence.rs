//! Consequence rule evaluation and enforcement for the WASM bridge
//! (ADR-017, #1531).
//!
//! This module wraps
//! [`scp_protocol::trust::consequence::evaluate_consequence_rules`] with
//! WASM-local state mutation so that consequence rules declared at context
//! creation are actually enforced inside the WASM bridge's
//! [`crate::manager::PerContextState`].
//!
//! # Why this module exists
//!
//! The runtime bridge (`scp-runtime`) evaluates consequence rules in
//! `crates/scp-runtime/src/context/manager/governance.rs`, calling
//! `enforce_triggered_consequences` at every mutation site the plan
//! identifies (send, governance dispatch). The WASM bridge cannot depend on
//! scp-runtime per ADR-034 (tokio multi-thread unavailable on
//! `wasm32-unknown-unknown`), but it CAN depend on `scp-protocol` directly,
//! and `evaluate_consequence_rules` lives there as a pure sync function.
//!
//! WASM therefore re-implements `enforce_triggered_consequences` locally
//! against the WASM-specific `PerContextState` layout (no `ContextRoleState`,
//! a flat `suspended_capabilities: HashMap<String, HashSet<String>>` map,
//! a simple hardcoded role-to-capability resolver) while calling the shared
//! scp-protocol `evaluate_consequence_rules` for the rule-matching logic.
//!
//! # Call sites
//!
//! - [`crate::manager::WasmContextManager::send_message`] — after appending
//!   `MessageSent` to the event log, dispatch consequences for the sender so
//!   rate-based rules (e.g., message velocity) fire.
//! - [`crate::manager::WasmContextManager::execute_governance_action`] —
//!   after emitting `GovernanceActionExecuted`, dispatch consequences for
//!   the executor and the action's `target_did` so governance-driven rules
//!   fire.

use scp_protocol::trust::consequence::{
    ConsequenceAction, ConsequenceRule, TriggeredConsequence, evaluate_consequence_rules,
    parse_suspension_capability,
};

use crate::manager::{MemberEntry, PerContextState};

/// Evaluates consequence rules declared on `ctx` against `ctx.event_log`
/// for `subject_did`, enforces any triggered consequences by mutating
/// `ctx.suspended_capabilities` / `ctx.members`, and pushes
/// `ConsequenceTriggered` / `ConsequenceEnforced` events onto the receive
/// buffer.
///
/// This function is a no-op if `ctx.consequence_rules` is empty or if the
/// subject has neither membership nor evidence in the event log (ghost DID
/// guard, mirroring the runtime).
///
/// # Parameters
///
/// - `ctx` — the per-context state to evaluate against and mutate.
/// - `context_id` — the context ID, embedded in emitted events.
/// - `subject_did` — the DID being evaluated (e.g., the message sender).
/// - `now_secs` — the current Unix second, used for rule time windows and
///   cooldown tracking.
///
/// # Returns
///
/// The number of `ConsequenceTriggered` events emitted. Useful for tests
/// and for callers that want to know whether the subject's state mutated.
pub fn dispatch_consequences_for_subject(
    ctx: &mut PerContextState,
    context_id: &str,
    subject_did: &str,
    now_secs: u64,
) -> usize {
    // Fast path: no rules declared.
    if ctx.consequence_rules().is_empty() {
        return 0;
    }

    // Clone rules so we can mutate `ctx` freely below without tripping the
    // borrow checker. This matches `scp_runtime::context::manager::governance::
    // dispatch_consequences` which does the same.
    let rules: Vec<ConsequenceRule> = ctx.consequence_rules().to_vec();

    // Evaluate against the full event log (pure sync, no side effects).
    // scp_event_log::EventLog::events() stores the full Event payload, so
    // WASM has direct access to the data `evaluate_consequence_rules` needs.
    let triggered: Vec<TriggeredConsequence> = {
        let events = ctx.event_log_events();
        evaluate_consequence_rules(&rules, events, subject_did, now_secs)
    };

    enforce_triggered(ctx, context_id, subject_did, now_secs, &triggered, &rules)
}

/// Enforces a pre-evaluated set of triggered consequences against the WASM
/// per-context state.
///
/// Mirrors `scp_runtime::context::manager::governance::
/// enforce_triggered_consequences`, adapted to WASM's flat
/// `suspended_capabilities: HashMap<String, HashSet<String>>` layout and
/// simple member role model (no `ContextRoleState`).
///
/// Returns the count of triggered rules that were actually dispatched (i.e.,
/// passed the cooldown and ghost-DID guards).
fn enforce_triggered(
    ctx: &mut PerContextState,
    context_id: &str,
    subject_did: &str,
    now_secs: u64,
    triggered: &[TriggeredConsequence],
    rules: &[ConsequenceRule],
) -> usize {
    use scp_event_log::DID;
    use scp_protocol::context::membership::ContextEvent;

    let mut dispatched = 0usize;

    for consequence in triggered {
        // Cooldown: skip if this rule fired within its window.
        if let Some(&last_fired) = ctx.cooldown_until_get(consequence.rule_index)
            && now_secs < last_fired
        {
            continue;
        }

        // Ghost DID guard: if the subject is absent AND there is no evidence
        // of prior participation, skip entirely. Mirrors runtime.
        let member_present = ctx.members_contains(subject_did);
        if !member_present && consequence.evidence.is_empty() {
            continue;
        }

        let action_type = match &consequence.action {
            ConsequenceAction::Suspend { .. } => "Suspend",
            ConsequenceAction::SuspendAll => "SuspendAll",
            ConsequenceAction::AssignRole { .. } => "AssignRole",
        };
        let trigger_type = rules
            .get(consequence.rule_index)
            .map_or_else(|| "Unknown".to_owned(), |r| format!("{:?}", r.trigger));

        ctx.push_event_pub(ContextEvent::ConsequenceTriggered {
            context_id: context_id.to_owned(),
            member_did: DID::from(subject_did.to_owned()),
            rule_index: consequence.rule_index,
            trigger_type,
            action_type: action_type.to_owned(),
        });

        // Emit-and-skip for absent members, mirroring runtime behavior.
        if !member_present {
            ctx.push_event_pub(ContextEvent::ConsequenceEnforced {
                context_id: context_id.to_owned(),
                member_did: DID::from(subject_did.to_owned()),
                action_type: action_type.to_owned(),
                success: false,
            });
            dispatched += 1;
            continue;
        }

        let success = match &consequence.action {
            ConsequenceAction::Suspend { capabilities } => {
                apply_suspend(ctx, subject_did, capabilities)
            }
            ConsequenceAction::SuspendAll => apply_suspend_all(ctx, subject_did),
            ConsequenceAction::AssignRole { to_role } => {
                apply_assign_role(ctx, subject_did, to_role)
            }
        };

        if !success {
            // Escalate to SuspendAll on enforcement failure, matching runtime.
            // Skip cooldown so the escalation fires immediately.
            let _ = apply_suspend_all(ctx, subject_did);
            ctx.push_event_pub(ContextEvent::ConsequenceEnforced {
                context_id: context_id.to_owned(),
                member_did: DID::from(subject_did.to_owned()),
                action_type: "SuspendAll(escalated)".to_owned(),
                success: true,
            });
            dispatched += 1;
            continue;
        }

        // Record cooldown: prevent re-firing within the rule's window.
        if let Some(rule) = rules.get(consequence.rule_index) {
            ctx.cooldown_until_insert(
                consequence.rule_index,
                now_secs.saturating_add(rule.window.as_secs()),
            );
        }

        ctx.push_event_pub(ContextEvent::ConsequenceEnforced {
            context_id: context_id.to_owned(),
            member_did: DID::from(subject_did.to_owned()),
            action_type: action_type.to_owned(),
            success,
        });
        dispatched += 1;
    }

    dispatched
}

/// Enforces `ConsequenceAction::Suspend` by adding each capability string
/// to the subject's suspended set. Unknown capability names are ignored
/// (matching runtime; validation is supposed to have rejected them at
/// context creation time via `ConsequenceRule::validate`).
///
/// Returns `true` if at least one capability was successfully applied.
fn apply_suspend(ctx: &mut PerContextState, subject_did: &str, caps: &[String]) -> bool {
    let mut applied = false;
    for cap_name in caps {
        // Parse defensively so we get the same normalization as the runtime
        // (e.g., "write" → Capability::MessagesWrite → "messages:write").
        let Some(capability) = parse_suspension_capability(cap_name) else {
            continue;
        };
        // WASM's `suspended_capabilities` uses the `Display` format, which
        // matches `member_has_capability` lookup in `PerContextState`.
        let key = capability.to_string();
        ctx.suspended_capabilities_insert(subject_did, key);
        applied = true;
    }
    applied
}

/// Enforces `ConsequenceAction::SuspendAll` by computing every capability
/// the subject could exercise via their current role, intersected with the
/// context ceiling, and adding all of them to the subject's suspended set.
///
/// This mirrors `ContextRoleState::suspend_all` on the runtime side: it
/// copies the member's effective capability set into the suspended set.
/// In WASM, the effective set is role-derived (no `ContextRoleState`), so
/// we iterate the candidate capabilities and keep the ones
/// `member_has_capability` would grant.
fn apply_suspend_all(ctx: &mut PerContextState, subject_did: &str) -> bool {
    // Candidate capability set: all strings WASM's `member_has_capability`
    // may grant across roles. Kept as a fixed list (matching the hardcoded
    // role-to-capability table in `PerContextState::member_has_capability`)
    // so this function does not silently miss new capabilities when they're
    // added to the resolver.
    const CANDIDATE_CAPABILITIES: &[&str] = &[
        "messages:read",
        "messages:write",
        "tool_invoke:*",
        "member:remove",
        "governance:propose",
    ];

    let mut applied = false;
    for cap in CANDIDATE_CAPABILITIES {
        if ctx.member_has_capability_pub(subject_did, cap) {
            ctx.suspended_capabilities_insert(subject_did, (*cap).to_owned());
            applied = true;
        }
    }
    applied
}

/// Enforces `ConsequenceAction::AssignRole` by mutating the subject's
/// `MemberEntry.role` in place. Returns `true` if the subject is a
/// known member and the role was updated.
///
/// In WASM, roles are stored as free-form strings on `MemberEntry`; there
/// is no separate "role exists" check (the runtime's role definitions
/// live in `ContextRoleState`, which WASM does not replicate). Assigning a
/// role that is not recognized by `member_has_capability` simply results
/// in the member losing all capabilities — which is an acceptable
/// degradation for a forcibly-applied consequence.
fn apply_assign_role(ctx: &mut PerContextState, subject_did: &str, to_role: &str) -> bool {
    ctx.members_get_mut(subject_did).is_some_and(|entry| {
        let MemberEntry { role, .. } = entry;
        to_role.clone_into(role);
        true
    })
}

// NOTE: `PerContextState` accessors used by this module
// (`consequence_rules`, `event_log_events`, `members_contains`,
// `members_get_mut`, `push_event_pub`, `member_has_capability_pub`,
// `suspended_capabilities_insert`, `cooldown_until_get`,
// `cooldown_until_insert`) are defined in `manager.rs` in the same
// `impl PerContextState` block that owns the private fields, because
// Rust's privacy rules scope field access to the defining module.
