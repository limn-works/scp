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
    ConsequenceDispatcher, ConsequenceRule, TriggeredConsequence, enforce_triggered,
    evaluate_consequence_rules,
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

    // Evaluate against the merged event history (pure sync, no side effects):
    // the durable Merkle log (convergent events) plus the recent receive
    // buffer (per-author local `ContextEvent`s). This mirrors the native
    // runtime's `event_log_entries_for_consequences`. After the ADR-011
    // amendment exclusion taxonomy (`.docs/adrs/phase-2.md` §2) removed the
    // per-author `MessageSent` / `ToolInvoked` Merkle leaves, velocity and
    // tool-rate triggers MUST read those events from the receive buffer
    // (Source 2) — local, per-receiver flow control needs no convergence.
    let triggered: Vec<TriggeredConsequence> = {
        let events = merged_consequence_events(ctx, now_secs);
        evaluate_consequence_rules(&rules, &events, subject_did, now_secs)
    };

    let mut dispatcher = WasmConsequenceDispatcher { ctx };
    enforce_triggered(
        &mut dispatcher,
        context_id,
        subject_did,
        now_secs,
        &triggered,
        &rules,
    )
}

/// Maximum age (seconds) for receive-buffer events used in consequence
/// evaluation. Events estimated older than this are discarded as stale,
/// preventing manipulation via timestamp back-dating. Mirrors the native
/// runtime's `MAX_BUFFER_EVENT_AGE_SECS`.
const MAX_BUFFER_EVENT_AGE_SECS: u64 = 3600;

/// Maximum clock-skew tolerance (seconds) for buffer-event timestamps. Events
/// estimated more than this far in the future are discarded. Mirrors the
/// native runtime's `MAX_FUTURE_TOLERANCE_SECS`.
const MAX_FUTURE_TOLERANCE_SECS: u64 = 5;

/// Maximum number of receive-buffer events consumed per consequence-evaluation
/// cycle. Caps evaluation cost and prevents an attacker from flooding the
/// buffer to drive synthetic high counts (e.g. inflating a `WarningCount`
/// trigger). Mirrors the native runtime's `MAX_BUFFER_EVENTS_FOR_EVAL`.
const MAX_BUFFER_EVENTS_FOR_EVAL: usize = 100;

/// Encodes a governance target DID into the JSON payload shape the shared
/// `WarningCount` / `Custom` trigger matcher decodes (`{"target_did": "..."}`).
/// Mirrors the native runtime's `target_did_to_payload`.
fn target_did_to_payload(did: Option<&scp_event_log::DID>) -> Vec<u8> {
    did.map(|d| {
        serde_json::to_vec(&serde_json::json!({ "target_did": d.as_ref() })).unwrap_or_default()
    })
    .unwrap_or_default()
}

/// Collects the event history for consequence evaluation, merging the durable
/// Merkle log with the recent receive buffer — the WASM analogue of the native
/// runtime's `event_log_entries_for_consequences`.
///
/// Two sources are combined:
///
/// 1. **Durable log** ([`PerContextState::event_log_events`]) — convergent,
///    commit-ordered events with real timestamps and `actor_did` (governance,
///    membership, lifecycle, consequence-enforcement records). Per the ADR-011
///    amendment exclusion taxonomy (`.docs/adrs/phase-2.md` §2) this no longer
///    contains the per-author `MessageSent` / `ToolInvoked` leaves.
///
/// 2. **Receive buffer** ([`PerContextState::event_buffer_events`]) — recent
///    local `ContextEvent`s, including the per-author `MessageSent` that
///    velocity triggers need. Buffer events use estimated timestamps spaced one
///    second apart backwards from `now`, and are bounded by
///    [`MAX_BUFFER_EVENTS_FOR_EVAL`], [`MAX_BUFFER_EVENT_AGE_SECS`], and
///    [`MAX_FUTURE_TOLERANCE_SECS`] to cap cost and resist back-dating /
///    flooding manipulation.
///
/// Event types are projected onto the coarse trigger buckets the shared
/// `matches_trigger` understands (governance / consequence variants collapse to
/// [`scp_event_log::EventType::GovernanceAction`]).
fn merged_consequence_events(ctx: &PerContextState, now_secs: u64) -> Vec<scp_event_log::Event> {
    use scp_event_log::{Event, EventPayload, EventType};
    use scp_protocol::context::membership::ContextEvent;

    let mut events: Vec<Event> = Vec::new();

    // Source 1: durable Merkle log. Project each entry's typed `EventType`
    // onto the bucket `matches_trigger` understands. Governance and
    // consequence-enforcement variants collapse to `GovernanceAction` so that
    // `WarningCount` / `Custom` triggers (and recursive consequence rules) can
    // observe prior governance and prior enforcement.
    for entry in ctx.event_log_events() {
        let event_type = match entry.event_type {
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
            _ => continue,
        };
        events.push(Event {
            event_type,
            actor_did: entry.actor_did.clone(),
            timestamp: entry.timestamp,
            sequence: events.len() as u64,
            payload: entry.payload.clone(),
            prev_hash: [0u8; 32],
            signature: Vec::new(),
        });
    }

    // Source 2: receive buffer (recent local `ContextEvent`s). Only accept
    // events newer than the last durable entry to avoid double-counting.
    let last_log_ts = events.last().map_or(0, |e| e.timestamp);
    let buffer = ctx.event_buffer_events();
    let buffer_len = buffer.len() as u64;
    let next_seq = events.len() as u64;
    let mut buffer_events_accepted: usize = 0;

    for (idx, ctx_event) in buffer.iter().enumerate() {
        let (event_type, actor_did, payload_data) = match ctx_event {
            ContextEvent::MessageSent { sender_did, .. }
            | ContextEvent::MessageReceived { sender_did, .. } => {
                (EventType::MessageSent, sender_did.clone(), Vec::new())
            }
            ContextEvent::MemberJoined { member_did, .. } => {
                (EventType::MemberJoined, member_did.clone(), Vec::new())
            }
            ContextEvent::MemberLeft { member_did } => {
                (EventType::MemberLeft, member_did.clone(), Vec::new())
            }
            ContextEvent::GovernanceActionExecuted {
                executor_did,
                target_did,
                ..
            } => (
                EventType::GovernanceAction,
                executor_did.clone(),
                target_did_to_payload(target_did.as_ref()),
            ),
            _ => continue,
        };

        // Oldest buffer event gets `now - (buffer_len - 1)`, newest gets `now`.
        let estimated_ts =
            now_secs.saturating_sub(buffer_len.saturating_sub(1).saturating_sub(idx as u64));

        // Skip buffer events likely already covered by the durable log.
        if estimated_ts <= last_log_ts && last_log_ts > 0 {
            continue;
        }
        // Reject implausibly-future estimates (defense in depth).
        if estimated_ts > now_secs.saturating_add(MAX_FUTURE_TOLERANCE_SECS) {
            continue;
        }
        // Reject stale estimates (back-dating defense).
        if now_secs.saturating_sub(estimated_ts) > MAX_BUFFER_EVENT_AGE_SECS {
            continue;
        }
        // Cap the number of buffer events fed to the evaluator (flood defense).
        if buffer_events_accepted >= MAX_BUFFER_EVENTS_FOR_EVAL {
            break;
        }
        buffer_events_accepted += 1;

        events.push(Event {
            event_type,
            actor_did,
            timestamp: estimated_ts,
            sequence: next_seq + idx as u64,
            payload: EventPayload { data: payload_data },
            prev_hash: [0u8; 32],
            signature: Vec::new(),
        });
    }

    events
}

// ---------------------------------------------------------------------------
// WasmConsequenceDispatcher — bridges PerContextState to the shared trait
// ---------------------------------------------------------------------------

/// Implements [`ConsequenceDispatcher`] for the WASM bridge's `PerContextState`.
///
/// The WASM bridge uses a flat `suspended_capabilities: HashMap<String, HashSet<String>>`
/// rather than the runtime's `ContextRoleState`, and a simple member role
/// model (role stored as a string on `MemberEntry`).
struct WasmConsequenceDispatcher<'a> {
    ctx: &'a mut PerContextState,
}

impl ConsequenceDispatcher for WasmConsequenceDispatcher<'_> {
    fn is_member_present(&self, subject_did: &str) -> bool {
        self.ctx.members_contains(subject_did)
    }

    fn suspend_capabilities(
        &mut self,
        subject_did: &str,
        caps: &[scp_protocol::context::roles::Capability],
    ) -> bool {
        apply_suspend(self.ctx, subject_did, caps)
    }

    fn suspend_all(&mut self, subject_did: &str) -> bool {
        apply_suspend_all(self.ctx, subject_did)
    }

    fn assign_role(&mut self, subject_did: &str, to_role: &str) -> bool {
        apply_assign_role(self.ctx, subject_did, to_role)
    }

    fn push_event(&mut self, event: scp_protocol::context::membership::ContextEvent) {
        self.ctx.push_event_pub(event);
    }

    fn get_cooldown(&self, rule_index: usize) -> Option<u64> {
        self.ctx.cooldown_until_get(rule_index).copied()
    }

    fn set_cooldown(&mut self, rule_index: usize, until: u64) {
        self.ctx.cooldown_until_insert(rule_index, until);
    }
}

/// Enforces `EnforcementSeverity::SuspendCapability` by adding each
/// typed capability to the subject's suspended set.
///
/// Returns `true` if at least one capability was successfully applied.
fn apply_suspend(
    ctx: &mut PerContextState,
    subject_did: &str,
    caps: &[scp_protocol::context::roles::Capability],
) -> bool {
    if caps.is_empty() {
        return false;
    }
    for cap in caps {
        // WASM's `suspended_capabilities` uses the `Display` format, which
        // matches `member_has_capability` lookup in `PerContextState`.
        ctx.suspended_capabilities_insert(subject_did, cap.to_string());
    }
    true
}

/// Enforces `ConsequenceAction::Enforcement(EnforcementSeverity::SuspendAccess)` by computing every capability
/// the subject could exercise via their current role, intersected with the
/// context ceiling, and adding all of them to the subject's suspended set.
///
/// This mirrors `ContextRoleState::suspend_all` on the runtime side: it
/// copies the member's effective capability set into the suspended set.
/// In WASM, the effective set is role-derived (no `ContextRoleState`), so
/// we iterate the candidate capabilities and keep the ones
/// `member_has_capability` would grant.
fn apply_suspend_all(ctx: &mut PerContextState, subject_did: &str) -> bool {
    // Suspend every capability the context's ceiling grants. This
    // matches the runtime's `ContextRoleState::suspend_all` which
    // copies the member's full effective set into the suspended set.
    // Using the ceiling (not a hardcoded list) ensures no capability
    // is silently missed when new variants are added.
    let all_capabilities: Vec<String> = ctx.ceiling_strings_pub().iter().cloned().collect();
    let mut applied = false;
    for cap in &all_capabilities {
        if ctx.member_has_capability_pub(subject_did, cap) {
            ctx.suspended_capabilities_insert(subject_did, cap.clone());
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// Covers `dispatch_consequences_for_subject`, the shared `enforce_triggered`
// (via `WasmConsequenceDispatcher`), and the `apply_*` helpers. Tests run on the native target via
// `make_bare_per_context_state` (in `manager.rs`), which avoids
// `crate::time::now_secs` — that function requires the WASM JS runtime and
// panics on native. Where timestamps matter (event log entries, `now_secs`
// for cooldown math) the test supplies them explicitly.
//
// **Variants not covered**: `ConsequenceAction::{RevokeAccess, RemoveMember}` do not exist.
// The WASM consequence model (shared with scp-protocol) exposes only
// `Suspend`, `SuspendAll`, and `AssignRole` as consequence-triggerable
// actions. Cryptographic key destruction and MLS ejection are
// governance-only paths — they are never triggered via a consequence rule,
// so they have no dispatcher in this module to test. See
// `scp_protocol::trust::consequence::ConsequenceAction` for the closed set.

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{
        WasmConsequenceDispatcher, apply_assign_role, apply_suspend, apply_suspend_all,
        dispatch_consequences_for_subject,
    };
    use crate::manager::make_bare_per_context_state;
    use scp_event_log::{DID as LogDID, EventType};
    use scp_protocol::context::roles::Capability;
    use scp_protocol::trust::consequence::{
        ConsequenceAction, ConsequenceEvidence, ConsequenceRule, ConsequenceTrigger,
        EnforcementSeverity, TriggeredConsequence, enforce_triggered,
    };
    use std::time::Duration;

    /// Builds a single `ConsequenceEvidence` entry. Tests use this to populate
    /// `TriggeredConsequence.evidence` without having to put matching events
    /// into the event log (which would require wiring event-log state).
    fn make_evidence(sequence: u64, actor: &str) -> ConsequenceEvidence {
        ConsequenceEvidence {
            event_sequence: sequence,
            timestamp: 1000,
            actor_did: LogDID::from(actor.to_owned()),
            event_type: EventType::MessageSent,
        }
    }

    /// Helper: builds a minimal `ConsequenceRule` bound to `MessageVelocity`
    /// with a threshold of 1 (so a single matching event fires it).
    fn rule(action: ConsequenceAction) -> ConsequenceRule {
        ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action,
            threshold: 1,
            window: Duration::from_mins(1),
        }
    }

    // --------------------- dispatch_consequences_for_subject --------------

    /// **E2-1:** empty rule set → fast-path return of 0, no mutation.
    #[test]
    fn dispatch_no_rules_configured_returns_zero() {
        let mut ctx = make_bare_per_context_state("ctx", "did:test:admin");
        let dispatched = dispatch_consequences_for_subject(&mut ctx, "ctx", "did:test:admin", 1000);
        assert_eq!(dispatched, 0);
        // No mutation of suspended state.
        assert!(ctx.test_suspended_capabilities("did:test:admin").is_none());
    }

    /// **E2-2:** rules configured but `evaluate_consequence_rules` returns no
    /// triggered consequences (event log is empty → threshold not met) →
    /// dispatch returns 0 and does not mutate.
    #[test]
    fn dispatch_no_triggering_events_returns_zero() {
        let mut ctx = make_bare_per_context_state("ctx", "did:test:admin");
        ctx.test_push_consequence_rule(rule(ConsequenceAction::Enforcement(
            EnforcementSeverity::SuspendAccess,
        )));
        // Event log is empty, so MessageVelocity count is 0 < threshold(1).
        let dispatched = dispatch_consequences_for_subject(&mut ctx, "ctx", "did:test:admin", 1000);
        assert_eq!(dispatched, 0);
        assert!(ctx.test_suspended_capabilities("did:test:admin").is_none());
    }

    /// **E2-3:** rule triggers end-to-end through dispatch: event log has the
    /// matching `MessageSent` events, the rule fires, the `Suspend` action is
    /// applied, and the subject's capability check flips to `false`.
    #[test]
    fn dispatch_suspend_end_to_end_blocks_capability() {
        let mut ctx = make_bare_per_context_state("ctx", "did:test:admin");
        ctx.test_insert_ceiling("messages:write");
        ctx.test_insert_ceiling("messages:read");

        ctx.test_push_consequence_rule(rule(ConsequenceAction::Enforcement(
            EnforcementSeverity::SuspendCapability {
                capabilities: vec![Capability::MessagesWrite],
            },
        )));
        // Two MessageSent events inside the 60s window (threshold=1, so 1+
        // is enough).
        ctx.test_append_log_event_at(EventType::MessageSent, "did:test:admin", 990, b"hi");
        ctx.test_append_log_event_at(EventType::MessageSent, "did:test:admin", 995, b"hi");

        let dispatched = dispatch_consequences_for_subject(&mut ctx, "ctx", "did:test:admin", 1000);
        assert_eq!(dispatched, 1);
        assert!(!ctx.member_has_capability_pub("did:test:admin", "messages:write"));
        // Other capabilities still allowed — Suspend is targeted.
        assert!(ctx.member_has_capability_pub("did:test:admin", "messages:read"));
        let suspended = ctx.test_suspended_capabilities("did:test:admin").unwrap();
        assert!(suspended.contains("messages:write"));
    }

    /// **E2-3b:** the velocity trigger fires from the RECEIVE BUFFER, not the
    /// durable Merkle log. After the ADR-011 amendment exclusion taxonomy
    /// (`.docs/adrs/phase-2.md` §2), `send_message` no longer appends a
    /// `MessageSent` Merkle leaf — it surfaces a local
    /// `ContextEvent::MessageSent` via `push_event`. This pins that
    /// `dispatch_consequences_for_subject` still observes those per-author
    /// events through `merged_consequence_events`' receive-buffer source, so
    /// velocity rules keep firing (matching native flow control). The durable
    /// event log is intentionally left EMPTY here.
    #[test]
    fn dispatch_velocity_fires_from_receive_buffer_not_durable_log() {
        use scp_protocol::context::membership::ContextEvent;

        let mut ctx = make_bare_per_context_state("ctx", "did:test:admin");
        ctx.test_insert_ceiling("messages:write");
        ctx.test_insert_ceiling("messages:read");

        ctx.test_push_consequence_rule(rule(ConsequenceAction::Enforcement(
            EnforcementSeverity::SuspendCapability {
                capabilities: vec![Capability::MessagesWrite],
            },
        )));

        // Surface two per-author sends as LOCAL ContextEvents only (exactly
        // what `send_message` does now) — NO durable leaf is appended.
        ctx.push_event_pub(ContextEvent::MessageSent {
            sender_did: LogDID("did:test:admin".to_owned()),
            sequence_number: 0,
            payload: b"hi".to_vec(),
        });
        ctx.push_event_pub(ContextEvent::MessageSent {
            sender_did: LogDID("did:test:admin".to_owned()),
            sequence_number: 1,
            payload: b"hi".to_vec(),
        });

        // Precondition: the durable Merkle log is empty (no per-author leaf).
        assert!(
            ctx.event_log_events().is_empty(),
            "per-author sends must NOT append durable Merkle leaves"
        );

        let dispatched = dispatch_consequences_for_subject(&mut ctx, "ctx", "did:test:admin", 1000);
        assert_eq!(
            dispatched, 1,
            "velocity rule must fire from the receive-buffer MessageSent events"
        );
        assert!(!ctx.member_has_capability_pub("did:test:admin", "messages:write"));
        let suspended = ctx.test_suspended_capabilities("did:test:admin").unwrap();
        assert!(suspended.contains("messages:write"));
    }

    // --------------------- enforce_triggered direct-drive ----------------

    /// **E2-4:** `apply_suspend` via `enforce_triggered` adds each capability to
    /// the subject's suspended set and returns 1.
    #[test]
    fn enforce_triggered_suspend_adds_capabilities() {
        let mut ctx = make_bare_per_context_state("ctx", "did:test:admin");
        ctx.test_insert_ceiling("messages:write");
        ctx.test_insert_ceiling("messages:read");

        let rules = vec![rule(ConsequenceAction::Enforcement(
            EnforcementSeverity::SuspendCapability {
                capabilities: vec![
                    scp_protocol::context::roles::Capability::MessagesWrite,
                    scp_protocol::context::roles::Capability::MessagesRead,
                ],
            },
        ))];
        let triggered = vec![TriggeredConsequence {
            rule_index: 0,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendCapability {
                capabilities: vec![
                    scp_protocol::context::roles::Capability::MessagesWrite,
                    scp_protocol::context::roles::Capability::MessagesRead,
                ],
            }),
            evidence: vec![make_evidence(0, "did:test:admin")],
        }];

        let dispatched = {
            let mut dispatcher = WasmConsequenceDispatcher { ctx: &mut ctx };
            enforce_triggered(
                &mut dispatcher,
                "ctx",
                "did:test:admin",
                1000,
                &triggered,
                &rules,
            )
        };
        assert_eq!(dispatched, 1);
        assert!(!ctx.member_has_capability_pub("did:test:admin", "messages:write"));
        assert!(!ctx.member_has_capability_pub("did:test:admin", "messages:read"));
    }

    /// **E2-5:** `apply_suspend_all` via `enforce_triggered` adds every
    /// admin-granted candidate capability to the suspended set (admin has
    /// the full ceiling, so all candidate caps land in `suspended_capabilities`).
    #[test]
    fn enforce_triggered_suspend_all_blocks_full_candidate_set() {
        let mut ctx = make_bare_per_context_state("ctx", "did:test:admin");
        // Ceiling contains every candidate capability used by apply_suspend_all.
        for cap in [
            "messages:read",
            "messages:write",
            "tool_invoke:*",
            "member:remove",
            "governance:propose",
        ] {
            ctx.test_insert_ceiling(cap);
        }

        let rules = vec![rule(ConsequenceAction::Enforcement(
            EnforcementSeverity::SuspendAccess,
        ))];
        let triggered = vec![TriggeredConsequence {
            rule_index: 0,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendAccess),
            evidence: vec![make_evidence(0, "did:test:admin")],
        }];

        let dispatched = {
            let mut dispatcher = WasmConsequenceDispatcher { ctx: &mut ctx };
            enforce_triggered(
                &mut dispatcher,
                "ctx",
                "did:test:admin",
                1000,
                &triggered,
                &rules,
            )
        };
        assert_eq!(dispatched, 1);
        // All candidate caps must now return false.
        for cap in [
            "messages:read",
            "messages:write",
            "tool_invoke:*",
            "member:remove",
            "governance:propose",
        ] {
            assert!(
                !ctx.member_has_capability_pub("did:test:admin", cap),
                "expected {cap} to be suspended"
            );
        }
    }

    /// **E2-6:** `apply_assign_role` updates the target member's role in-place.
    #[test]
    fn enforce_triggered_assign_role_mutates_member_role() {
        let mut ctx = make_bare_per_context_state("ctx", "did:test:admin");
        ctx.test_insert_member("did:test:bob", "member");

        let rules = vec![rule(ConsequenceAction::AssignRole {
            to_role: "observer".to_owned(),
        })];
        let triggered = vec![TriggeredConsequence {
            rule_index: 0,
            action: ConsequenceAction::AssignRole {
                to_role: "observer".to_owned(),
            },
            evidence: vec![make_evidence(0, "did:test:bob")],
        }];

        assert_eq!(ctx.test_member_role("did:test:bob"), Some("member"));
        let dispatched = {
            let mut dispatcher = WasmConsequenceDispatcher { ctx: &mut ctx };
            enforce_triggered(
                &mut dispatcher,
                "ctx",
                "did:test:bob",
                1000,
                &triggered,
                &rules,
            )
        };
        assert_eq!(dispatched, 1);
        assert_eq!(ctx.test_member_role("did:test:bob"), Some("observer"));
    }

    /// **E2-7:** cooldown suppression — a second dispatch within the rule's
    /// cooldown window is skipped without mutation.
    #[test]
    fn enforce_triggered_cooldown_suppresses_second_call() {
        let mut ctx = make_bare_per_context_state("ctx", "did:test:admin");
        ctx.test_insert_ceiling("messages:write");

        let rules = vec![rule(ConsequenceAction::Enforcement(
            EnforcementSeverity::SuspendCapability {
                capabilities: vec![Capability::MessagesWrite],
            },
        ))];
        let triggered = vec![TriggeredConsequence {
            rule_index: 0,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendCapability {
                capabilities: vec![Capability::MessagesWrite],
            }),
            evidence: vec![make_evidence(0, "did:test:admin")],
        }];

        // First dispatch at t=1000 — fires and records cooldown_until =
        // 1000 + 60 = 1060.
        let dispatched1 = {
            let mut dispatcher = WasmConsequenceDispatcher { ctx: &mut ctx };
            enforce_triggered(
                &mut dispatcher,
                "ctx",
                "did:test:admin",
                1000,
                &triggered,
                &rules,
            )
        };
        assert_eq!(dispatched1, 1);

        // Second dispatch at t=1030 — inside the cooldown window → skipped.
        let dispatched2 = {
            let mut dispatcher = WasmConsequenceDispatcher { ctx: &mut ctx };
            enforce_triggered(
                &mut dispatcher,
                "ctx",
                "did:test:admin",
                1030,
                &triggered,
                &rules,
            )
        };
        assert_eq!(dispatched2, 0);

        // Third dispatch at t=1100 — cooldown expired → fires again.
        let dispatched3 = {
            let mut dispatcher = WasmConsequenceDispatcher { ctx: &mut ctx };
            enforce_triggered(
                &mut dispatcher,
                "ctx",
                "did:test:admin",
                1100,
                &triggered,
                &rules,
            )
        };
        assert_eq!(dispatched3, 1);
    }

    /// **E2-8:** ghost DID guard — a subject that is neither in `members` nor
    /// referenced in `evidence` is skipped without emitting any event.
    #[test]
    fn enforce_triggered_ghost_did_no_evidence_skipped() {
        let mut ctx = make_bare_per_context_state("ctx", "did:test:admin");
        let rules = vec![rule(ConsequenceAction::Enforcement(
            EnforcementSeverity::SuspendAccess,
        ))];
        let triggered = vec![TriggeredConsequence {
            rule_index: 0,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendAccess),
            evidence: vec![], // <- no evidence
        }];

        // Subject "ghost" is not in members, and the evidence vec is empty —
        // so the ghost-DID guard fires and the consequence is skipped entirely.
        let dispatched = {
            let mut dispatcher = WasmConsequenceDispatcher { ctx: &mut ctx };
            enforce_triggered(
                &mut dispatcher,
                "ctx",
                "did:test:ghost",
                1000,
                &triggered,
                &rules,
            )
        };
        assert_eq!(dispatched, 0);
        assert!(ctx.test_suspended_capabilities("did:test:ghost").is_none());
    }

    /// **E2-9:** ghost DID with evidence — the subject is not in `members` but
    /// evidence is present, so we emit `ConsequenceTriggered` /
    /// `ConsequenceEnforced { success: false }` and count the dispatch but do
    /// not mutate any state. Multiple triggered consequences are counted.
    #[test]
    fn enforce_triggered_ghost_did_with_evidence_emits_and_skips() {
        let mut ctx = make_bare_per_context_state("ctx", "did:test:admin");
        let rules = vec![
            rule(ConsequenceAction::Enforcement(
                EnforcementSeverity::SuspendAccess,
            )),
            rule(ConsequenceAction::AssignRole {
                to_role: "observer".to_owned(),
            }),
        ];
        let triggered = vec![
            TriggeredConsequence {
                rule_index: 0,
                action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendAccess),
                evidence: vec![make_evidence(0, "did:test:ghost")],
            },
            TriggeredConsequence {
                rule_index: 1,
                action: ConsequenceAction::AssignRole {
                    to_role: "observer".to_owned(),
                },
                evidence: vec![make_evidence(1, "did:test:ghost")],
            },
        ];

        let dispatched = {
            let mut dispatcher = WasmConsequenceDispatcher { ctx: &mut ctx };
            enforce_triggered(
                &mut dispatcher,
                "ctx",
                "did:test:ghost",
                1000,
                &triggered,
                &rules,
            )
        };
        // Both consequences are counted (ghost-with-evidence takes the
        // emit-and-skip branch which still increments `dispatched`).
        assert_eq!(dispatched, 2);
        // But no suspension/role mutation on the ghost DID.
        assert!(ctx.test_suspended_capabilities("did:test:ghost").is_none());
        assert_eq!(ctx.test_member_role("did:test:ghost"), None);
    }

    // --------------------- apply_* unit tests ----------------------------

    /// **E2-10:** `apply_assign_role` returns false (not true) when the subject
    /// is not a member at all, so `enforce_triggered` would escalate to
    /// `SuspendAll` on failure.
    #[test]
    fn apply_assign_role_returns_false_for_absent_member() {
        let mut ctx = make_bare_per_context_state("ctx", "did:test:admin");
        // "did:test:alice" is NOT a member of ctx.
        let applied = apply_assign_role(&mut ctx, "did:test:alice", "observer");
        assert!(!applied);
        assert_eq!(ctx.test_member_role("did:test:alice"), None);
    }

    /// **E2-11:** `apply_suspend` ignores unknown capability names (matching
    /// `parse_suspension_capability` — unknown names return `None`) and still
    /// returns `true` if at least one valid capability was applied.
    #[test]
    fn apply_suspend_ignores_unknown_capability_names() {
        let mut ctx = make_bare_per_context_state("ctx", "did:test:admin");
        ctx.test_insert_ceiling("messages:write");

        let applied = apply_suspend(
            &mut ctx,
            "did:test:admin",
            &[
                Capability::Custom("not-a-real-capability".to_owned()),
                Capability::MessagesWrite,
            ],
        );
        assert!(applied);
        let suspended = ctx.test_suspended_capabilities("did:test:admin").unwrap();
        // Custom capabilities use Display format; MessagesWrite is "messages:write"
        assert!(suspended.contains("messages:write"));
        assert!(!suspended.contains("not-a-real-capability"));
    }

    /// **E2-12:** `apply_suspend_all` is a no-op (returns false) for a member
    /// with an empty ceiling — no capabilities to suspend.
    #[test]
    fn apply_suspend_all_noop_for_empty_ceiling() {
        let mut ctx = make_bare_per_context_state("ctx", "did:test:admin");
        // Ceiling is empty by default → admin has no capabilities → nothing
        // to suspend.
        let applied = apply_suspend_all(&mut ctx, "did:test:admin");
        assert!(!applied);
        assert!(ctx.test_suspended_capabilities("did:test:admin").is_none());
    }
}
