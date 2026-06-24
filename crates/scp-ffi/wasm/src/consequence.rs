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
//! against the WASM bridge's `PerContextState`, which now holds the SAME shared
//! `scp_protocol::context::roles::ContextRoleState` the native runtime uses
//! (members, role assignments, ceiling, per-member capabilities, suspensions),
//! while calling the shared scp-protocol `evaluate_consequence_rules` for the
//! rule-matching logic.
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

use crate::manager::PerContextState;

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
        // Convergent window anchor for convergent-trigger rules: max timestamp of
        // the Source-1 durable log (`event_log_events`), taken BEFORE the buffer
        // merge — never from the merged set, which mixes in Source-2 buffer events
        // carrying local-clock estimated timestamps. This mirrors the native
        // runtime's `event_log_entries_for_consequences` `convergent_now` so both
        // produce a byte-identical durable `ConsequenceTriggered` leaf under skewed
        // local clocks (§9.9.3). Empty log -> `now_secs` fallback (no convergent-
        // trigger evidence exists to anchor).
        let convergent_now = ctx
            .event_log_events()
            .iter()
            .map(|e| e.timestamp)
            .max()
            .unwrap_or(now_secs);
        let events = merged_consequence_events(ctx, now_secs);
        evaluate_consequence_rules(&rules, &events, subject_did, now_secs, convergent_now)
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

/// Collects the event history for consequence evaluation, merging the durable
/// Merkle log with the recent receive buffer — the WASM adapter over the
/// shared, convergence-critical
/// [`scp_protocol::trust::consequence::merge_consequence_events`].
///
/// It acquires the two sources from the WASM-local `PerContextState`
/// ([`PerContextState::event_log_events`] for Source 1,
/// [`PerContextState::event_buffer_events`] for Source 2) and delegates the
/// `EventType` projection + buffer-gate merge to the shared function so the
/// WASM bridge and the native runtime produce byte-identical merged event sets
/// (§9.9.3 equivocation detection). All constants, the projection match, the
/// buffer gates, and the CONVERGENCE INVARIANT documentation live in that
/// shared function — see it for the rationale.
fn merged_consequence_events(ctx: &PerContextState, now_secs: u64) -> Vec<scp_event_log::Event> {
    scp_protocol::trust::consequence::merge_consequence_events(
        ctx.event_log_events(),
        ctx.event_buffer_events(),
        now_secs,
    )
}

// ---------------------------------------------------------------------------
// WasmConsequenceDispatcher — bridges PerContextState to the shared trait
// ---------------------------------------------------------------------------

/// Implements [`ConsequenceDispatcher`] for the WASM bridge's `PerContextState`,
/// which holds the shared `scp_protocol::context::roles::ContextRoleState` —
/// the same role/ceiling/suspension representation as the native runtime.
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

    fn append_durable_consequence_leaf(
        &mut self,
        event_type: scp_event_log::EventType,
        subject_did: &str,
        rule_index: usize,
        trigger_kind: &str,
        action_type: &str,
        trigger_timestamp_secs: u64,
    ) {
        // Mint the durable Merkle leaf via the shared payload builder so the
        // preimage is byte-identical to the native runtime's
        // (`scp_event_log::payload::consequence_event_payload`, actor "system").
        // The shared `enforce_triggered` loop only invokes this for
        // convergent-trigger consequences (ADR-051 §6) and BEFORE the matching
        // `push_event` (H4 ordering), mirroring native's `emit_*` functions.
        // `trigger_timestamp_secs` is the convergent triggering-event timestamp
        // (shared `convergent_consequence_timestamp`), so the leaf timestamp is
        // byte-identical to native (§7.3.1, §9.9.3).
        self.ctx.append_consequence_leaf(
            event_type,
            subject_did,
            rule_index,
            trigger_kind,
            action_type,
            trigger_timestamp_secs,
        );
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
    // Suspend the typed capabilities directly through the shared
    // `ContextRoleState::suspend_capabilities` (no string round-trip).
    ctx.suspend_capabilities_typed(subject_did, caps);
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

/// Enforces `ConsequenceAction::AssignRole` by re-assigning the subject's role
/// through the shared [`ContextRoleState::system_assign_role`]. Returns `true`
/// only if the subject is a member AND the target role is defined in the
/// context's `role_definitions` (and within the ceiling).
///
/// This is the #1886 fix on the consequence path: `system_assign_role`
/// validates the role against `role_definitions` before applying it, so an
/// undefined / out-of-ceiling role now returns `false` (the shared
/// `enforce_triggered` then escalates to `SuspendAll`) instead of silently
/// accepting a free-form role string that would strip the member's
/// capabilities. Matches the native runtime's consequence behavior.
fn apply_assign_role(ctx: &mut PerContextState, subject_did: &str, to_role: &str) -> bool {
    ctx.role_state_system_assign_role(subject_did, to_role)
        .is_ok()
}

// NOTE: `PerContextState` accessors used by this module
// (`consequence_rules`, `event_log_events`, `members_contains`,
// `role_state_system_assign_role`, `push_event_pub`,
// `member_has_capability_pub`, `suspend_capabilities_typed`,
// `suspended_capabilities_insert`, `ceiling_strings_pub`,
// `cooldown_until_get`, `cooldown_until_insert`) are defined in `manager.rs`
// in the same `impl PerContextState` block that owns the shared
// `role_state`, because Rust's privacy rules scope field access to the
// defining module.

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
        dispatch_consequences_for_subject, merged_consequence_events,
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

    /// **E2-11:** `apply_suspend` stores each capability in canonical UCAN form
    /// (`Capability::ucan_capability_name`) and returns `true` when at least one
    /// capability is applied — including a `Custom` capability, which is
    /// canonicalized (not stored as its bare `Display` string).
    #[test]
    fn apply_suspend_canonicalizes_custom_capability_names() {
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
        // Stored in canonical UCAN form: a no-colon `Custom` → concrete
        // `name:name` (see roles.rs `ucan_resource_action`), NOT the bare
        // Display string.
        assert!(suspended.contains("messages:write"));
        assert!(suspended.contains("not-a-real-capability:not-a-real-capability"));
        assert!(!suspended.contains("not-a-real-capability"));
    }

    /// Regression: `apply_suspend` must store the canonical UCAN form so the
    /// suspension is actually ENFORCED by `member_has_capability`.
    ///
    /// Capabilities whose `Display` spelling differs from their UCAN form
    /// (`Bridging` → `"bridging"` vs `"bridging:*"`; `ToolInvokeAll` →
    /// `"tool:invoke:*"` vs `"tool_invoke:*"`) exposed the bug: `apply_suspend`
    /// stored the `Display` string, but `member_has_capability` (and
    /// `apply_suspend_all`) key off the UCAN form, so the suspended entry never
    /// matched the lookup key and the capability stayed GRANTED. This pins that
    /// an admin (who would otherwise hold every in-ceiling capability) is
    /// actually denied the suspended caps. Before the fix this test fails
    /// because the suspension is silently ignored.
    #[test]
    fn apply_suspend_enforces_capabilities_with_divergent_display_form() {
        let mut ctx = make_bare_per_context_state("ctx", "did:test:admin");
        // Admin grants any in-ceiling capability, so seed the ceiling with the
        // UCAN-form spellings the role check looks up.
        ctx.test_insert_ceiling("bridging:*");
        ctx.test_insert_ceiling("tool_invoke:*");

        // Sanity: before suspension the admin holds both caps.
        assert!(ctx.member_has_capability_pub("did:test:admin", "bridging:*"));
        assert!(ctx.member_has_capability_pub("did:test:admin", "tool_invoke:*"));

        let applied = apply_suspend(
            &mut ctx,
            "did:test:admin",
            &[Capability::Bridging, Capability::ToolInvokeAll],
        );
        assert!(applied);

        // The suspended set must hold the canonical UCAN form, NOT the Display
        // form — otherwise the lookup below would never match.
        let suspended = ctx.test_suspended_capabilities("did:test:admin").unwrap();
        assert!(suspended.contains("bridging:*"));
        assert!(suspended.contains("tool_invoke:*"));
        assert!(!suspended.contains("bridging"));
        assert!(!suspended.contains("tool:invoke:*"));

        // The actual enforcement check: both caps are now DENIED.
        assert!(!ctx.member_has_capability_pub("did:test:admin", "bridging:*"));
        assert!(!ctx.member_has_capability_pub("did:test:admin", "tool_invoke:*"));
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

    // ----------------- EL01: convergent-source soundness -----------------

    const SUBJECT: &str = "did:test:subject";

    /// Builds a context whose durable Merkle log holds exactly ONE
    /// `GovernanceAction` targeting `SUBJECT` (the convergent `WarningCount`
    /// bucket), then pushes `message_count` per-author `MessageSent` events
    /// PLUS one `GovernanceActionExecuted` `ContextEvent` into the receive
    /// buffer. Differing `message_count` simulates members with different
    /// local activity / buffer lengths.
    fn ctx_with_local_activity(message_count: usize) -> super::PerContextState {
        use scp_protocol::context::membership::ContextEvent;

        let mut ctx = make_bare_per_context_state("ctx", "did:test:admin");
        // Durable convergent governance event (the only source from which a
        // convergent event may be drawn).
        let payload = serde_json::to_vec(&serde_json::json!({ "target_did": SUBJECT })).unwrap();
        ctx.test_append_log_event_at(EventType::GovernanceAction, "did:test:admin", 990, &payload);

        for seq in 0..message_count {
            ctx.push_event_pub(ContextEvent::MessageSent {
                sender_did: LogDID(SUBJECT.to_owned()),
                sequence_number: seq as u64,
                payload: Vec::new(),
            });
        }
        // The same convergent governance event each honest member buffers
        // locally after it is durably logged. Before the EL01 fix this was
        // re-projected from the buffer and double-counted depending on buffer
        // length; after the fix it is ignored here (Source 1 only).
        ctx.push_event_pub(ContextEvent::GovernanceActionExecuted {
            proposal_id: [0x11u8; 32],
            action_summary: "SuspendMember".to_owned(),
            executor_did: LogDID("did:test:admin".to_owned()),
            resulting_epoch: Some(1),
            target_did: Some(LogDID(SUBJECT.to_owned())),
        });
        ctx
    }

    fn governance_bucket_count(ctx: &super::PerContextState) -> usize {
        merged_consequence_events(ctx, 1000)
            .iter()
            .filter(|e| e.event_type == EventType::GovernanceAction)
            .count()
    }

    /// **EL01 (WASM mirror):** two honest members with the SAME durable
    /// governance history but DIFFERENT receive-buffer lengths MUST compute the
    /// SAME governance-bucket count from `merged_consequence_events`, so a
    /// `WarningCount` / `Custom` consequence fires (or not) identically and
    /// mints the SAME durable leaf — preserving the §9.9.3 convergence
    /// guarantee. Before the fix, the buffer's `GovernanceActionExecuted`
    /// projection was double-counted on the quiet member and skipped on the
    /// busy one (dedup keyed on member-local `buffer_len`).
    #[test]
    fn convergent_governance_count_is_independent_of_buffer_length() {
        let quiet = governance_bucket_count(&ctx_with_local_activity(2));
        let busy = governance_bucket_count(&ctx_with_local_activity(50));

        assert_eq!(
            quiet, busy,
            "EL01: governance-bucket count MUST be identical across members \
             regardless of receive-buffer length — convergent events come only \
             from the durable log, never the per-member buffer (§9.9.3; ADR-051 §6)"
        );
        // Non-vacuity: exactly the single durable GovernanceAction is counted;
        // the buffer's GovernanceActionExecuted contributes zero.
        assert_eq!(
            quiet, 1,
            "EL01: exactly the single durable GovernanceAction must be counted; \
             the per-member buffer must contribute zero convergent events"
        );
    }

    /// Pins that per-author `MessageSent` events DO still flow from the buffer
    /// (velocity/rate must keep working) — the EL01 fix narrowed the buffer
    /// projection without disabling it.
    #[test]
    fn per_author_messages_still_flow_from_buffer() {
        let ctx = ctx_with_local_activity(3);
        let message_count = merged_consequence_events(&ctx, 1000)
            .iter()
            .filter(|e| e.event_type == EventType::MessageSent)
            .count();
        assert!(
            message_count > 0,
            "MessageSent is per-author and excluded from the durable log, so the \
             receive buffer MUST remain its source for velocity/rate evaluation"
        );
    }
}

// ===========================================================================
// Cross-impl leaf-byte parity (WASM side) — §9.9.3
//
// These assert the WASM bridge's REAL leaf-payload producer paths reproduce the
// SAME canonical fixture bytes that the native scp-runtime test
// (`crates/scp-runtime/tests/wasm_conformance.rs`,
// `cross_impl_*_leaf_bytes`) pins from native's real producer paths. The split
// is necessary because the scp-runtime test crate cannot dev-depend on this
// wasm cdylib. Each side drives its OWN production code against the same known
// answer; together they prove the two impls emit byte-identical leaves.
// ===========================================================================
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod cross_impl_leaf_parity {
    /// `GovernanceActionExecuted`: WASM's real value extraction + shared
    /// `GovernanceActionExecutedPayload` + `encode_payload` (the exact code at
    /// `manager.rs`'s `execute_governance_action` append site) MUST reproduce
    /// the positional-MessagePack fixture the native test pins.
    #[test]
    fn cross_impl_governance_action_executed_leaf_bytes_wasm() {
        use scp_protocol::context::governance::GovernanceAction;

        // Same logical action as the native fixture: RemoveMember(BOB).
        let action = GovernanceAction::RemoveMember {
            did: scp_event_log::DID::from("did:dht:z6MkBobConverge".to_owned()),
            reason: None,
        };
        // The EXACT extraction the WASM append site performs.
        let target_did = action
            .target_did()
            .map(|d| d.as_ref().to_owned())
            .unwrap_or_default();
        let action_type = action.variant_name().to_owned();

        let payload = scp_event_log::payload::encode_payload(
            &scp_event_log::payload::GovernanceActionExecutedPayload {
                target_did,
                action_type,
            },
        )
        .unwrap()
        .data;

        // Positional MessagePack 2-element fixarray. Decoding recovers the
        // native fixture's fields exactly — proving byte parity with native.
        let decoded: scp_event_log::payload::GovernanceActionExecutedPayload =
            scp_event_log::payload::decode_payload(&scp_event_log::EventPayload {
                data: payload.clone(),
            })
            .unwrap();
        assert_eq!(decoded.target_did, "did:dht:z6MkBobConverge");
        assert_eq!(decoded.action_type, "RemoveMember");
        assert_eq!(payload[0] & 0xf0, 0x90, "must be a MessagePack fixarray");
        assert_eq!(payload[0] & 0x0f, 2, "fixarray of 2 fields");
    }

    /// `TokenRevoked`: WASM's real producer (the same
    /// `scp_protocol::crypto::ucan::revoke::token_revoked_payload` call its
    /// `ucan_revoke` makes) MUST reproduce the native fixture JSON bytes.
    #[test]
    fn cross_impl_token_revoked_leaf_bytes_wasm() {
        let payload = scp_protocol::crypto::ucan::revoke::token_revoked_payload(
            "ctx-revoke-x",
            "bafyTokenCidExample",
            "did:dht:z6MkRevoker",
        );
        // SORTED-key JSON (serde_json BTreeMap; no preserve_order) — identical
        // to the native test's pinned fixture.
        let expected =
            br#"{"context_id":"ctx-revoke-x","revoker_did":"did:dht:z6MkRevoker","token_cid":"bafyTokenCidExample"}"#;
        assert_eq!(payload, expected);
    }

    /// Convergent `ConsequenceTriggered`: WASM's real producer (the same
    /// `consequence_event_payload` + shared label functions its
    /// `WasmConsequenceDispatcher::append_durable_consequence_leaf` uses) MUST
    /// reproduce the native fixture JSON bytes.
    #[test]
    fn cross_impl_consequence_triggered_leaf_bytes_wasm() {
        use scp_protocol::trust::consequence::{
            ConsequenceAction, ConsequenceTrigger, EnforcementSeverity, consequence_action_type,
            trigger_kind_str,
        };

        let trigger = ConsequenceTrigger::WarningCount;
        let action = ConsequenceAction::Enforcement(EnforcementSeverity::SuspendAccess);
        let trigger_kind = trigger_kind_str(&trigger);
        let action_type = consequence_action_type(&action);

        let payload = scp_event_log::payload::consequence_event_payload(
            "did:dht:z6MkSubject",
            3,
            &trigger_kind,
            action_type,
        );
        let expected =
            br#"{"action_type":"SuspendAccess","rule_index":3,"target_did":"did:dht:z6MkSubject","trigger_kind":"WarningCount"}"#;
        assert_eq!(payload.data, expected);
    }

    /// `GovernanceProposalCreated` / `GovernanceVoteCast` /
    /// `GovernanceVoteWithdrawn`: the WASM bridge's durable leaf MUST carry an
    /// EMPTY payload, matching native's `append_context_event`
    /// (`EventPayload::default()`). The native test
    /// `cross_impl_governance_proposal_vote_leaf_is_empty` pins the SAME empty
    /// leaf from native's real producer path.
    ///
    /// The production append sites pass `b""` (the `proposal_id` rides only in
    /// the buffer-only `ContextEvent`). This test drives the WASM append path
    /// with that production payload and asserts the landed leaf is empty; it ALSO
    /// proves the regression is detectable by appending the pre-fix
    /// `proposal_id.as_bytes()` payload to a parallel log and asserting the two
    /// Merkle roots DIVERGE — i.e. a leaf that stamped the `proposal_id` would
    /// produce a different `tree::root` and false-positive §9.9.3 equivocation
    /// against native.
    #[test]
    fn cross_impl_governance_proposal_vote_leaf_is_empty_wasm() {
        use crate::manager::make_bare_per_context_state;
        use scp_event_log::EventType;

        const GOVERNANCE_PROPOSAL_VOTE_EVENTS: [EventType; 3] = [
            EventType::GovernanceProposalCreated,
            EventType::GovernanceVoteCast,
            EventType::GovernanceVoteWithdrawn,
        ];
        let proposal_id = "prop-converge-001";
        let actor = "did:dht:z6MkProposer";

        // Production path: append each governance event with the EMPTY payload
        // the real `append_log_event` call sites now pass.
        let mut empty_state = make_bare_per_context_state("ctx-gov-empty", actor);
        for event_type in GOVERNANCE_PROPOSAL_VOTE_EVENTS {
            empty_state.test_append_log_event_at(event_type, actor, 1_700_000_000, b"");
        }

        // Every durable governance leaf carries an empty payload — byte-parity
        // with native's `append_context_event`.
        for event_type in GOVERNANCE_PROPOSAL_VOTE_EVENTS {
            let logged = empty_state
                .event_log_events()
                .iter()
                .find(|e| e.event_type == event_type);
            assert!(
                logged.is_some_and(|e| e.payload.data.is_empty()),
                "{event_type:?} WASM canonical leaf MUST be present with an EMPTY \
                 payload (§9.9.3)"
            );
        }

        // Regression detector: a parallel log that stamps `proposal_id.as_bytes()`
        // (the pre-fix WASM behavior) MUST yield a DIFFERENT Merkle root, proving
        // the empty-payload fix is load-bearing for native↔WASM convergence.
        let mut stamped_state = make_bare_per_context_state("ctx-gov-stamped", actor);
        for event_type in GOVERNANCE_PROPOSAL_VOTE_EVENTS {
            stamped_state.test_append_log_event_at(
                event_type,
                actor,
                1_700_000_000,
                proposal_id.as_bytes(),
            );
        }
        assert_ne!(
            empty_state.test_event_log_root(),
            stamped_state.test_event_log_root(),
            "stamping proposal_id into the leaf MUST diverge the Merkle root — the \
             empty-payload parity with native is what prevents a §9.9.3 \
             false-positive equivocation across platforms"
        );
    }

    /// Drives the REAL WASM governance production handlers end-to-end and
    /// asserts the durable Merkle leaves they append carry an EMPTY payload.
    ///
    /// The sibling test `cross_impl_governance_proposal_vote_leaf_is_empty_wasm`
    /// feeds a hand-written `b""` through the test-only append path, so it
    /// cannot catch a regression at the production call sites
    /// (`WasmContextManager::propose_governance_action`,
    /// `approve_governance_proposal`, `withdraw_governance_vote`) where the
    /// `b""` argument actually lives. This test calls those handlers directly
    /// so that flipping any of them back to `proposal_id.as_bytes()` (the
    /// pre-fix WASM behavior that bit native↔WASM parity twice) fails the
    /// build instead of leaving the synthetic test green.
    ///
    /// A 4-member `majority` context has quorum 3. The proposer's own vote is
    /// approval #1 and a single additional approval is #2 — both below quorum —
    /// so the proposal stays `Pending` and no `execute_governance_action`
    /// fires, keeping all three append sites (`GovernanceProposalCreated`,
    /// `GovernanceVoteCast`, `GovernanceVoteWithdrawn`) reachable for real on
    /// the native test target.
    #[test]
    fn real_governance_handlers_append_empty_leaves_wasm() {
        use crate::manager::{WasmContextManager, make_bare_per_context_state};
        use scp_event_log::{DID, EventType};
        use scp_protocol::context::governance::GovernanceAction;
        // `scp_event_log::DID` (re-exported from `scp_primitives`) is the same
        // type `GovernanceAction::AddSigner.did` expects.

        let context_id = "ctx-gov-real";
        let proposer = "did:dht:z6MkProposer";
        let voter = "did:dht:z6MkVoter";

        // Build a 4-member majority context (quorum = 3) so neither the
        // proposer's vote nor one extra approval reaches quorum: the proposal
        // stays Pending and no execution fires.
        let mut ctx = make_bare_per_context_state(context_id, proposer);
        ctx.test_set_governance("majority");
        ctx.test_insert_member(voter, "admin");
        ctx.test_insert_member("did:dht:z6MkMemberC", "admin");
        ctx.test_insert_member("did:dht:z6MkMemberD", "admin");
        // Admins resolve capabilities through the ceiling — admit the
        // governance propose/vote capabilities the handlers gate on.
        ctx.test_insert_ceiling("governance:propose");
        ctx.test_insert_ceiling("governance:vote");

        let mut mgr = WasmContextManager::new();
        mgr.test_insert_context(context_id, ctx);

        // A valid 64-char (32-byte) hex id. The execute path hex-decodes
        // proposal_id into a [u8; 32] via the strict `parse_proposal_id_bytes`,
        // which requires exactly 32 bytes; the id is also the pending-proposal
        // map key. Any well-formed 64-char hex works for both roles.
        let proposal_id = "deadbeef000000000000000000000000000000000000000000000000000000ff";
        let action = GovernanceAction::AddSigner {
            did: DID::from("did:dht:z6MkNewSigner".to_owned()),
        };

        // 1. Real propose handler → GovernanceProposalCreated leaf (b"").
        let propose_result = mgr
            .propose_governance_action(context_id, proposer, proposal_id, &action)
            .unwrap();
        assert_eq!(
            propose_result
                .get("status")
                .and_then(serde_json::Value::as_str),
            Some("Pending"),
            "1-of-3 quorum must leave the proposal Pending so no execution fires"
        );

        // 2. Real vote-cast handler → GovernanceVoteCast leaf (b"").
        let approve_result = mgr
            .approve_governance_proposal(context_id, proposal_id, voter)
            .unwrap();
        assert_eq!(
            approve_result
                .get("status")
                .and_then(serde_json::Value::as_str),
            Some("Pending"),
            "2-of-3 quorum must still leave the proposal Pending"
        );

        // 3. Real vote-withdraw handler → GovernanceVoteWithdrawn leaf (b"").
        mgr.withdraw_governance_vote(context_id, proposal_id, voter)
            .unwrap();

        // Every durable governance leaf the real handlers appended must carry
        // an EMPTY payload — byte-parity with native's `append_context_event`
        // (§9.9.3). A regression that stamps `proposal_id.as_bytes()` at any of
        // the three call sites fails this assertion.
        let logged = mgr.test_context_event_log_events(context_id);
        for event_type in [
            EventType::GovernanceProposalCreated,
            EventType::GovernanceVoteCast,
            EventType::GovernanceVoteWithdrawn,
        ] {
            let leaf = logged.iter().find(|e| e.event_type == event_type);
            assert!(
                leaf.is_some_and(|e| e.payload.data.is_empty()),
                "{event_type:?} durable leaf from the REAL handler MUST be present \
                 with an EMPTY payload (§9.9.3 native↔WASM parity)"
            );
        }
    }

    /// Reconstructs the native-reference leaf bytes for a single system event
    /// from the SHARED `scp_event_log` primitives — the exact preimage native's
    /// real producer (`ttl.rs`'s `handle_ttl_expiry` / `finalize_close`) feeds
    /// `tree::append_unsigned_event`: `Event { event_type, actor_did,
    /// timestamp, sequence: 0, payload: empty, prev_hash: GENESIS, signature:
    /// [] }`. The leaf hash is `SHA-256(0x00 ‖ rmp_serde(Event))`, so a single
    /// such append's `tree::root` is exactly that leaf hash. The WASM real
    /// producer must reproduce this byte-for-byte.
    #[cfg(test)]
    fn native_reference_single_system_leaf_root(
        context_id: &str,
        event_type: scp_event_log::EventType,
        actor_did: &str,
        timestamp: u64,
    ) -> [u8; 32] {
        // A system leaf is exactly a payload leaf with an EMPTY payload — the
        // `EventPayload { data: Vec::new() }` an empty `&[]` produces is
        // byte-identical, so forward to the payload reference to keep a single
        // source of preimage truth.
        native_reference_single_payload_leaf_root(context_id, event_type, actor_did, timestamp, &[])
    }

    /// Reconstructs the native-reference leaf bytes for a single
    /// payload-bearing event (e.g. `GovernanceActionExecuted`) from the SHARED
    /// `scp_event_log` primitives — the exact preimage native's real producer
    /// (`finalize_governance_action`) feeds `tree::append_unsigned_event`. Same
    /// shape as [`native_reference_single_system_leaf_root`] but with a non-empty
    /// payload, so the full leaf bytes (`actor_did` + payload + timestamp) are
    /// pinned, not just the `actor_did` field.
    #[cfg(test)]
    fn native_reference_single_payload_leaf_root(
        context_id: &str,
        event_type: scp_event_log::EventType,
        actor_did: &str,
        timestamp: u64,
        payload: &[u8],
    ) -> [u8; 32] {
        use scp_event_log::tree::{append_unsigned_event, root};
        use scp_event_log::{DID, Event, EventLog, EventPayload};

        let mut log = EventLog::new(context_id.to_owned());
        let event = Event {
            event_type,
            actor_did: DID::from(actor_did.to_owned()),
            timestamp,
            sequence: 0,
            payload: EventPayload {
                data: payload.to_vec(),
            },
            prev_hash: scp_event_log::tree::GENESIS_PREV_HASH,
            signature: Vec::new(),
        };
        append_unsigned_event(&mut log, &event).expect("reference payload leaf append");
        root(&log)
    }

    /// §9.9.3 native↔WASM DIRECT-EXECUTE `GovernanceActionExecuted` parity.
    /// The direct-FFI execute entry (`context_execute_governance`) stamps the
    /// proposal's PROPOSER as the leaf `actor_did` (the executor) — NOT the
    /// caller (`initiator_did`) — matching the native direct-execute handler
    /// (`handle_execute_governance_action_actor`), which sets
    /// `executor_did = proposal.proposer_did`. This drives the exact manager
    /// call the fixed direct entry performs (auth subject = caller, executor =
    /// `proposal_proposer_did(...)`) and pins the FULL single-leaf root against
    /// the native-reference leaf bytes, with a non-vacuity control proving the
    /// PRE-FIX caller-stamp diverged.
    #[test]
    fn cross_impl_governance_action_executed_direct_stamps_proposer_wasm() {
        use crate::manager::{WasmContextManager, make_bare_per_context_state};
        use scp_event_log::{DID, EventType};
        use scp_protocol::context::governance::{
            GovernanceAction, GovernanceProposal, ProposalStatus, SignedVote, VoteType,
        };

        let context_id = "ctx-gov-direct-executor";
        let proposer = "did:dht:z6MkDirectProposer";
        let caller = "did:dht:z6MkDirectCaller"; // distinct from proposer
        // Valid 64-char (32-byte) hex; the execute path requires exactly 32
        // bytes via the strict `parse_proposal_id_bytes`.
        let proposal_id = "feedface000000000000000000000000000000000000000000000000000000ff";
        let created_at = 1_700_500_500_u64;

        // SingleAdmin context: a non-proposer admin triggers the direct-execute
        // entry. The bridge resolves the proposal's proposer and uses it for the
        // executor (leaf actor_did) AND the consequence subject; the caller DID
        // is present as a context member only to prove it is NOT what ends up on
        // the leaf. The leaf actor_did must still be the proposer.
        let mut ctx = make_bare_per_context_state(context_id, proposer);
        ctx.test_insert_member(caller, "admin");
        ctx.test_insert_member("did:dht:z6MkDirectTarget", "member");
        ctx.test_insert_ceiling("role:assign");

        // A target distinct from both proposer and caller keeps the leaf actor
        // unambiguously the proposer.
        let action = GovernanceAction::ChangeRole {
            did: DID::from("did:dht:z6MkDirectTarget".to_owned()),
            new_role: "observer".to_owned(),
        };

        let proposal_id_bytes: [u8; 32] = {
            let bytes = hex::decode(proposal_id).unwrap();
            let mut arr = [0u8; 32];
            let len = bytes.len().min(32);
            arr[..len].copy_from_slice(&bytes[..len]);
            arr
        };
        // Track the proposal as Approved (the direct-execute precondition).
        let proposal = GovernanceProposal {
            proposal_id: proposal_id_bytes,
            context_id: context_id.to_owned(),
            proposer_did: DID::from(proposer.to_owned()),
            action: action.clone(),
            status: ProposalStatus::Approved,
            created_at,
            voting_deadline: created_at + 3600,
            approvals: vec![SignedVote {
                voter_did: DID::from(proposer.to_owned()),
                vote: VoteType::Approve,
                timestamp: created_at,
                signature: Vec::new(),
            }],
            rejections: Vec::new(),
            created_at_epoch: None,
        };
        ctx.test_insert_resolved_proposal(proposal_id.to_owned(), proposal);

        let mut mgr = WasmContextManager::new();
        mgr.test_insert_context(context_id, ctx);

        // EXACTLY what the shipped `context_execute_governance` direct entry
        // does: it resolves the tracked proposal's proposer and passes that
        // proposer for BOTH the auth-subject (initiator) and the executor — the
        // caller-supplied DID is never forwarded to `execute_governance_action`.
        let resolved_proposer = mgr
            .proposal_proposer_did(context_id, proposal_id)
            .expect("proposer resolvable");
        assert_eq!(resolved_proposer, proposer);
        mgr.execute_governance_action(
            context_id,
            &resolved_proposer,
            &resolved_proposer,
            proposal_id,
        )
        .expect("direct execute");

        let logged = mgr.test_context_event_log_events(context_id);
        let executed_leaf = logged
            .iter()
            .find(|e| e.event_type == EventType::GovernanceActionExecuted)
            .expect("GovernanceActionExecuted leaf present after direct execute");
        assert_eq!(
            executed_leaf.actor_did.as_ref(),
            proposer,
            "direct-execute GovernanceActionExecuted leaf actor_did MUST be the proposal's \
             proposer (the executor), NOT the caller (§9.9.3; native direct handler stamps \
             proposal.proposer_did)"
        );
        assert_eq!(executed_leaf.timestamp, created_at);

        // Full-leaf-bytes parity: the WASM real-producer root equals the
        // native-reference leaf reconstructed from the shared primitives with
        // the proposer actor, the convergent created_at, and the shared
        // GovernanceActionExecutedPayload bytes.
        let payload = WasmContextManager::encode_governance_action_executed_payload(
            &action,
            action.target_did(),
        )
        .expect("payload encodes");
        assert_eq!(
            mgr.test_context_event_log_root(context_id),
            native_reference_single_payload_leaf_root(
                context_id,
                EventType::GovernanceActionExecuted,
                proposer,
                created_at,
                &payload,
            ),
            "WASM direct-execute leaf MUST be byte-identical to native's proposer-stamped \
             reference leaf (§9.9.3 cross-bridge convergence)"
        );
        // Non-vacuity: the PRE-FIX caller (initiator) stamp would diverge.
        assert_ne!(
            mgr.test_context_event_log_root(context_id),
            native_reference_single_payload_leaf_root(
                context_id,
                EventType::GovernanceActionExecuted,
                caller,
                created_at,
                &payload,
            ),
            "the pre-fix caller-stamped actor_did MUST diverge from the aligned proposer-stamped \
             leaf"
        );
    }

    /// §9.9.3 native↔WASM `ContextClosed` TTL-DEADLINE parity. A TTL-driven
    /// close MUST stamp the CONVERGENT TTL deadline (`creation + ttl`) on the
    /// `ContextClosed` leaf — NOT each member's local `now()` — matching native
    /// `finalize_close`, which stamps `deadline_unix_secs` (= `creation + ttl`)
    /// for a timer-armed context. Pins the full single-leaf root against the
    /// native-reference leaf, with a non-vacuity control proving the PRE-FIX
    /// `now_secs()` behavior diverged.
    #[test]
    fn cross_impl_context_closed_stamps_convergent_ttl_deadline_wasm() {
        use crate::manager::{WasmContextManager, make_bare_per_context_state};
        use scp_event_log::EventType;

        let context_id = "ctx-close-ttl-deadline";
        let creation = 1_700_000_000_u64;
        let ttl = 86_400_u64;
        let convergent_deadline = creation + ttl;

        let mut state = make_bare_per_context_state(context_id, "did:dht:zcreator");
        state.test_set_creation_timestamp_secs(creation);
        state.test_set_ttl_seconds(Some(ttl));
        // `finalize_close` requires the `closing` state.
        state.test_set_state("closing");

        let mut mgr = WasmContextManager::new();
        mgr.test_insert_context(context_id, state);
        mgr.finalize_close(context_id)
            .expect("real WASM finalize_close producer");

        let leaves = mgr.test_context_event_log_events(context_id);
        let close_leaf = leaves
            .iter()
            .find(|e| e.event_type == EventType::ContextClosed)
            .expect("ContextClosed leaf present after finalize_close");
        assert_eq!(
            close_leaf.timestamp, convergent_deadline,
            "TTL-driven ContextClosed leaf MUST stamp the convergent creation+ttl deadline, \
             NOT local now() (§9.9.3)"
        );

        // Full-leaf-bytes parity at the convergent deadline.
        assert_eq!(
            mgr.test_context_event_log_root(context_id),
            native_reference_single_system_leaf_root(
                context_id,
                EventType::ContextClosed,
                "system:close",
                convergent_deadline,
            ),
            "WASM ContextClosed real-producer leaf MUST be byte-identical to native's reference \
             leaf at the convergent TTL deadline (§9.9.3 cross-bridge convergence)"
        );
        // Non-vacuity: the PRE-FIX `now_secs()` timestamp would diverge from the
        // convergent deadline (the test clock's `now` is not `creation + ttl`).
        let local_now = crate::time::now_secs();
        assert_ne!(
            local_now, convergent_deadline,
            "test precondition: local now must differ from the convergent deadline"
        );
        assert_ne!(
            mgr.test_context_event_log_root(context_id),
            native_reference_single_system_leaf_root(
                context_id,
                EventType::ContextClosed,
                "system:close",
                local_now,
            ),
            "the pre-fix now()-stamped close leaf MUST diverge from the convergent-deadline leaf"
        );
    }

    /// §9.9.3 native↔WASM SYSTEM-LEAF parity. The WASM bridge's REAL producers
    /// (`handle_ttl_expiry` → `ContextExpired`, `finalize_close` →
    /// `ContextClosed`) MUST stamp the SAME descriptive `actor_did` sentinels
    /// native's `ttl.rs` stamps (`"system:timer"` / `"system:close"`), at the
    /// same convergent timestamp — so the same event produces a byte-identical
    /// leaf hash and therefore an identical single-leaf Merkle root.
    ///
    /// A non-vacuity control proves the assertion bites: a leaf reconstructed
    /// with the PRE-FIX sentinels (`""` for expiry, `"system"` for close) yields
    /// a DIFFERENT root, i.e. the old WASM bytes diverged from native.
    #[test]
    fn cross_impl_system_leaf_actor_did_parity_wasm() {
        use crate::manager::{WasmContextManager, make_bare_per_context_state};
        use scp_event_log::EventType;

        // ---- ContextExpired (TTL fire) ----
        let creation = 1_700_000_000_u64;
        let ttl = 86_400_u64;
        let expiry_ts = creation + ttl; // the convergent deadline WASM stamps.

        let expiry_ctx = "ctx-sysleaf-expiry";
        let mut expiry_state = make_bare_per_context_state(expiry_ctx, "did:dht:zcreator");
        expiry_state.test_set_creation_timestamp_secs(creation);
        expiry_state.test_set_ttl_seconds(Some(ttl));
        let mut expiry_mgr = WasmContextManager::new();
        expiry_mgr.test_insert_context(expiry_ctx, expiry_state);
        expiry_mgr
            .handle_ttl_expiry(expiry_ctx)
            .expect("real WASM ttl-expiry producer");

        let expiry_leaves = expiry_mgr.test_context_event_log_events(expiry_ctx);
        let expiry_leaf = expiry_leaves
            .iter()
            .find(|e| e.event_type == EventType::ContextExpired)
            .expect("ContextExpired leaf present after handle_ttl_expiry");
        assert_eq!(
            expiry_leaf.actor_did.as_ref(),
            "system:timer",
            "WASM ContextExpired leaf MUST stamp the native sentinel \"system:timer\" (§9.9.3)"
        );
        assert_eq!(expiry_leaf.timestamp, expiry_ts);

        // The WASM real-producer root equals the native-reference single-leaf
        // root reconstructed from the shared primitives.
        assert_eq!(
            expiry_mgr.test_context_event_log_root(expiry_ctx),
            native_reference_single_system_leaf_root(
                expiry_ctx,
                EventType::ContextExpired,
                "system:timer",
                expiry_ts,
            ),
            "WASM ContextExpired real-producer leaf MUST be byte-identical to native's \
             \"system:timer\" reference leaf (§9.9.3 cross-bridge convergence)"
        );
        // Non-vacuity: the PRE-FIX empty sentinel would diverge.
        assert_ne!(
            expiry_mgr.test_context_event_log_root(expiry_ctx),
            native_reference_single_system_leaf_root(
                expiry_ctx,
                EventType::ContextExpired,
                "",
                expiry_ts,
            ),
            "the pre-fix empty actor_did MUST diverge from the aligned \"system:timer\" leaf"
        );

        // ---- ContextClosed (finalize close) ----
        let close_ctx = "ctx-sysleaf-close";
        let mut close_state = make_bare_per_context_state(close_ctx, "did:dht:zcreator");
        // `finalize_close` requires the context to be in the `closing` state.
        close_state.test_set_state("closing");
        let mut close_mgr = WasmContextManager::new();
        close_mgr.test_insert_context(close_ctx, close_state);
        close_mgr
            .finalize_close(close_ctx)
            .expect("real WASM finalize_close producer");

        let close_leaves = close_mgr.test_context_event_log_events(close_ctx);
        let close_leaf = close_leaves
            .iter()
            .find(|e| e.event_type == EventType::ContextClosed)
            .expect("ContextClosed leaf present after finalize_close");
        assert_eq!(
            close_leaf.actor_did.as_ref(),
            "system:close",
            "WASM ContextClosed leaf MUST stamp the native sentinel \"system:close\" (§9.9.3)"
        );

        // `finalize_close` stamps `now_secs()`; pin the parity + non-vacuity at
        // that landed timestamp (read back from the real leaf) so the leaf-byte
        // comparison is independent of the test clock.
        let close_ts = close_leaf.timestamp;
        assert_eq!(
            close_mgr.test_context_event_log_root(close_ctx),
            native_reference_single_system_leaf_root(
                close_ctx,
                EventType::ContextClosed,
                "system:close",
                close_ts,
            ),
            "WASM ContextClosed real-producer leaf MUST be byte-identical to native's \
             \"system:close\" reference leaf (§9.9.3 cross-bridge convergence)"
        );
        // Non-vacuity: the PRE-FIX `"system"` sentinel would diverge.
        assert_ne!(
            close_mgr.test_context_event_log_root(close_ctx),
            native_reference_single_system_leaf_root(
                close_ctx,
                EventType::ContextClosed,
                "system",
                close_ts,
            ),
            "the pre-fix \"system\" actor_did MUST diverge from the aligned \"system:close\" leaf"
        );
    }

    /// §9.9.3 native↔WASM `GovernanceActionExecuted` EXECUTOR-stamp parity.
    /// Drives the REAL WASM quorum-approval handlers: a 3-member `majority`
    /// context (quorum = 2) where the proposer's self-vote is approval #1
    /// (Pending) and a SECOND admin's approval is #2 — crossing quorum and
    /// committing the action. The committing member (the quorum-crossing VOTER)
    /// — NOT the proposer — MUST be stamped as the `GovernanceActionExecuted`
    /// leaf `actor_did` (ADR-031 §8 "executor DID" / §7.3.1 "committing member"
    /// / ADR-051 §6). Native's `vote_on_proposal_inner` stamps the same voter;
    /// stamping the proposer (the pre-fix behavior) would diverge the leaf.
    #[test]
    fn cross_impl_governance_action_executed_stamps_executor_wasm() {
        use crate::manager::{WasmContextManager, make_bare_per_context_state};
        use scp_event_log::{DID, EventType};
        use scp_protocol::context::governance::GovernanceAction;

        let context_id = "ctx-gov-executor";
        let proposer = "did:dht:z6MkProposer";
        let voter = "did:dht:z6MkVoter";

        // 3-member majority: quorum = 3/2 + 1 = 2. Proposer self-vote = #1
        // (Pending); the voter's approval = #2 → crosses quorum → executes,
        // with the VOTER as the committing member.
        let mut ctx = make_bare_per_context_state(context_id, proposer);
        ctx.test_set_governance("majority");
        ctx.test_insert_member(proposer, "admin");
        ctx.test_insert_member(voter, "admin");
        ctx.test_insert_member("did:dht:z6MkMemberC", "admin");
        ctx.test_insert_ceiling("governance:propose");
        ctx.test_insert_ceiling("governance:vote");
        // A target action distinct from both proposer and voter keeps the
        // leaf actor (executor) unambiguously the voter, not the target.
        ctx.test_insert_ceiling("role:assign");

        let mut mgr = WasmContextManager::new();
        mgr.test_insert_context(context_id, ctx);

        // Valid 64-char (32-byte) hex; the execute path requires exactly 32
        // bytes via the strict `parse_proposal_id_bytes`.
        let proposal_id = "deadbeef000000000000000000000000000000000000000000000000000000ff";
        let action = GovernanceAction::ChangeRole {
            did: DID::from("did:dht:z6MkMemberC".to_owned()),
            new_role: "observer".to_owned(),
        };

        let propose_result = mgr
            .propose_governance_action(context_id, proposer, proposal_id, &action)
            .unwrap();
        assert_eq!(
            propose_result
                .get("status")
                .and_then(serde_json::Value::as_str),
            Some("Pending"),
            "proposer self-vote (1 of quorum 2) must leave the proposal Pending"
        );

        let approve_result = mgr
            .approve_governance_proposal(context_id, proposal_id, voter)
            .unwrap();
        assert_eq!(
            approve_result
                .get("status")
                .and_then(serde_json::Value::as_str),
            Some("Approved"),
            "voter approval crosses majority quorum (2 of 2) and commits the action"
        );

        let logged = mgr.test_context_event_log_events(context_id);
        let executed_leaf = logged
            .iter()
            .find(|e| e.event_type == EventType::GovernanceActionExecuted)
            .expect("GovernanceActionExecuted leaf present after quorum-crossing approval");
        assert_eq!(
            executed_leaf.actor_did.as_ref(),
            voter,
            "the GovernanceActionExecuted leaf actor_did MUST be the quorum-crossing executor \
             (voter), NOT the proposer (§9.9.3 native↔WASM convergence; ADR-031 §8 executor DID)"
        );
        assert_ne!(
            executed_leaf.actor_did.as_ref(),
            proposer,
            "non-vacuity: proposer != voter, so stamping the proposer would be a distinct \
             (divergent) leaf actor_did"
        );
    }

    /// §9.9.3 native↔WASM ACCEPT-decision parity: an eligible voter who holds
    /// `governance:vote` but LACKS the action capability (`role:assign`, here
    /// suspended) crosses quorum and the action executes, minting EXACTLY ONE
    /// `GovernanceActionExecuted` leaf with the voter as actor.
    ///
    /// This is the exact regression the per-member execute-time capability check
    /// caused: native `execute_governance_action` performs NO per-member action
    /// check (only status / context-id / replay / commit-fault), so native mints
    /// one leaf. WASM previously gated on
    /// `member_has_capability(voter, role:assign)` at execute, which a
    /// vote-eligible-but-action-suspended voter fails — minting zero where native
    /// mints one. `ChangeRole` has NO native per-action ceiling gate, so removing
    /// the per-member check converges the decision: both mint exactly one leaf.
    #[test]
    fn cross_impl_nonadmin_voter_crosses_quorum_mints_one_leaf_wasm() {
        use crate::manager::{WasmContextManager, make_bare_per_context_state};
        use scp_event_log::{DID, EventType};
        use scp_protocol::context::governance::GovernanceAction;

        let context_id = "ctx-gov-vote-only-voter";
        let proposer = "did:dht:z6MkProposer";
        let voter = "did:dht:z6MkVoter";

        // 3-member majority: quorum = 3/2 + 1 = 2. Proposer self-vote = #1
        // (Pending); the voter's approval = #2 → crosses quorum → executes.
        let mut ctx = make_bare_per_context_state(context_id, proposer);
        ctx.test_set_governance("majority");
        ctx.test_insert_member(proposer, "admin");
        ctx.test_insert_member(voter, "admin");
        ctx.test_insert_member("did:dht:z6MkMemberC", "admin");
        ctx.test_insert_ceiling("governance:propose");
        ctx.test_insert_ceiling("governance:vote");
        ctx.test_insert_ceiling("role:assign");
        // The voter is an ELIGIBLE VOTER (governance:vote intact) but LACKS the
        // action capability: `role:assign` is suspended for them. The pre-fix
        // per-member execute check tested exactly `member_has_capability(voter,
        // role:assign)`, which now returns false (suspension is checked first),
        // so it would have rejected and minted 0 leaves. `governance:vote` is
        // NOT suspended, so voting still succeeds.
        ctx.test_insert_suspended_capability(voter, "role:assign");

        let mut mgr = WasmContextManager::new();
        mgr.test_insert_context(context_id, ctx);

        // Valid 64-char (32-byte) hex; the execute path requires exactly 32
        // bytes via the strict `parse_proposal_id_bytes`.
        let proposal_id = "deadbeef000000000000000000000000000000000000000000000000000000ff";
        let action = GovernanceAction::ChangeRole {
            did: DID::from("did:dht:z6MkMemberC".to_owned()),
            new_role: "observer".to_owned(),
        };

        mgr.propose_governance_action(context_id, proposer, proposal_id, &action)
            .expect("propose by an admin proposer with governance:propose succeeds");

        let approve_result = mgr
            .approve_governance_proposal(context_id, proposal_id, voter)
            .expect("vote-eligible voter (governance:vote intact) crosses quorum and commits");
        assert_eq!(
            approve_result
                .get("status")
                .and_then(serde_json::Value::as_str),
            Some("Approved"),
            "voter approval crosses majority quorum (2 of 2) and commits the action"
        );

        let logged = mgr.test_context_event_log_events(context_id);
        let executed: Vec<_> = logged
            .iter()
            .filter(|e| e.event_type == EventType::GovernanceActionExecuted)
            .collect();
        assert_eq!(
            executed.len(),
            1,
            "a vote-eligible voter lacking the action capability MUST still mint EXACTLY ONE \
             GovernanceActionExecuted leaf — identical to native, which has no per-member \
             execute-time check (§9.9.3; ADR-031 §8)"
        );
        assert_eq!(
            executed[0].actor_did.as_ref(),
            voter,
            "the single GovernanceActionExecuted leaf actor_did is the quorum-crossing voter \
             (executor), matching native"
        );
    }

    /// §9.9.3 native↔WASM REJECT-decision parity: a governance action whose
    /// required capability is NOT in the context ceiling is rejected IDENTICALLY
    /// on both bridges — no `GovernanceActionExecuted` leaf is minted.
    ///
    /// `RevokeAccess` is gated on `member:ban` in native's `execute_revoke`
    /// (`governance_helpers.rs`) via `ceiling.contains(&Capability::MemberBan)`.
    /// `member:ban` is absent from the default ceiling, so native rejects when it
    /// is not explicitly added. WASM now mirrors this with a per-action
    /// CONTEXT-CEILING gate in `dispatch_governance_action`, so both reject and
    /// neither mints a leaf.
    #[test]
    fn cross_impl_out_of_ceiling_action_rejected_wasm() {
        use crate::manager::{WasmContextManager, make_bare_per_context_state};
        use scp_event_log::DID;
        use scp_event_log::EventType;
        use scp_protocol::context::governance::{AccessScope, GovernanceAction};

        let context_id = "ctx-gov-out-of-ceiling";
        let admin = "did:dht:z6MkAdmin";
        let target = "did:dht:z6MkTarget";

        // SingleAdmin governance (quorum 0): the admin proposer auto-executes on
        // propose, so the dispatch ceiling gate fires synchronously and the
        // propose call surfaces the rejection.
        let mut ctx = make_bare_per_context_state(context_id, admin);
        ctx.test_set_governance("single_admin");
        ctx.test_insert_member(admin, "admin");
        ctx.test_insert_member(target, "member");
        ctx.test_insert_ceiling("governance:propose");
        ctx.test_insert_ceiling("governance:vote");
        // Deliberately DO NOT insert "member:ban" into the ceiling — this is the
        // out-of-ceiling condition. Native's `execute_revoke` rejects the same
        // way (`ceiling.contains(&Capability::MemberBan)` is false).

        let mut mgr = WasmContextManager::new();
        mgr.test_insert_context(context_id, ctx);

        let action = GovernanceAction::RevokeAccess {
            did: DID::from(target.to_owned()),
            access: AccessScope::Both,
        };

        let result = mgr.propose_governance_action(
            context_id,
            admin,
            "cafebabe000000000000000000000000000000000000000000000000000000ff",
            &action,
        );
        assert!(
            result.is_err(),
            "an out-of-ceiling RevokeAccess (member:ban not in ceiling) MUST be rejected — \
             identical to native's per-action ceiling gate (§9.9.3; ADR-031 §8)"
        );

        let logged = mgr.test_context_event_log_events(context_id);
        let executed = logged
            .iter()
            .filter(|e| e.event_type == EventType::GovernanceActionExecuted)
            .count();
        assert_eq!(
            executed, 0,
            "a rejected out-of-ceiling action MUST mint ZERO GovernanceActionExecuted leaves on \
             both bridges"
        );
    }

    /// §9.9.3 native↔WASM REJECT-decision parity for `CreateChildContext`.
    ///
    /// Native gates `CreateChildContext` on `Capability::ChildContextCreate` in
    /// `execute_create_child_context` (`governance_helpers.rs`) via
    /// `ceiling.contains(&Capability::ChildContextCreate)`. The capability is
    /// absent from the default ceiling, so an out-of-ceiling proposal is
    /// rejected and mints ZERO leaves. WASM previously returned `None` (ungated)
    /// for this action — executing it where native rejected — a §9.9.3
    /// divergence AND a security gap (running an action outside the ceiling).
    /// WASM now mirrors native: `dispatch_ceiling_capability` returns
    /// `Some("context_child:create")` (the `ucan_capability_name()` form that
    /// `ceiling_strings` stores).
    #[test]
    fn cross_impl_out_of_ceiling_create_child_context_rejected_wasm() {
        use crate::manager::{WasmContextManager, make_bare_per_context_state};
        use scp_event_log::EventType;
        use scp_protocol::context::governance::GovernanceAction;

        let context_id = "ctx-gov-child-out-of-ceiling";
        let admin = "did:dht:z6MkAdmin";

        let mut ctx = make_bare_per_context_state(context_id, admin);
        ctx.test_set_governance("single_admin");
        ctx.test_insert_member(admin, "admin");
        ctx.test_insert_ceiling("governance:propose");
        ctx.test_insert_ceiling("governance:vote");
        // Deliberately DO NOT insert "context_child:create" — the out-of-ceiling
        // condition. Native's `execute_create_child_context` rejects the same way.

        let mut mgr = WasmContextManager::new();
        mgr.test_insert_context(context_id, ctx);

        // Shape mirrors the dispatch-roundtrip fixture in manager.rs tests.
        let action: GovernanceAction = serde_json::from_value(serde_json::json!({
            "CreateChildContext": {"params": {
                "mode": "Encrypted", "ceiling": [], "ceiling_policy": "Immutable",
                "promotion_policy": "NoPromotion", "roles": [], "tools": [],
                "ttl": null, "memory_scope": "Ephemeral", "governance": "SingleAdmin",
                "template_id": null
            }}
        }))
        .expect("CreateChildContext action deserializes");

        let result = mgr.propose_governance_action(
            context_id,
            admin,
            "cafef00d000000000000000000000000000000000000000000000000000000ff",
            &action,
        );
        assert!(
            result.is_err(),
            "an out-of-ceiling CreateChildContext (context_child:create not in ceiling) MUST be \
             rejected — identical to native's per-action ceiling gate (§9.9.3; ADR-031 §8)"
        );

        let logged = mgr.test_context_event_log_events(context_id);
        let executed = logged
            .iter()
            .filter(|e| e.event_type == EventType::GovernanceActionExecuted)
            .count();
        assert_eq!(
            executed, 0,
            "a rejected out-of-ceiling CreateChildContext MUST mint ZERO GovernanceActionExecuted \
             leaves on both bridges"
        );
    }

    /// §9.9.3 native↔WASM ACCEPT-decision parity for `CreateChildContext`: with
    /// `context_child:create` IN the ceiling, the single-admin propose auto-
    /// executes and mints EXACTLY ONE `GovernanceActionExecuted` leaf — matching
    /// native, whose `execute_create_child_context` ceiling check passes.
    #[test]
    fn cross_impl_in_ceiling_create_child_context_executes_wasm() {
        use crate::manager::{WasmContextManager, make_bare_per_context_state};
        use scp_event_log::EventType;
        use scp_protocol::context::governance::GovernanceAction;

        let context_id = "ctx-gov-child-in-ceiling";
        let admin = "did:dht:z6MkAdmin";

        let mut ctx = make_bare_per_context_state(context_id, admin);
        ctx.test_set_governance("single_admin");
        ctx.test_insert_member(admin, "admin");
        ctx.test_insert_ceiling("governance:propose");
        ctx.test_insert_ceiling("governance:vote");
        // In-ceiling: the UCAN-format string `ceiling_strings` stores for
        // `ChildContextCreate` (`Capability::ucan_capability_name()`).
        ctx.test_insert_ceiling("context_child:create");

        let mut mgr = WasmContextManager::new();
        mgr.test_insert_context(context_id, ctx);

        let action: GovernanceAction = serde_json::from_value(serde_json::json!({
            "CreateChildContext": {"params": {
                "mode": "Encrypted", "ceiling": [], "ceiling_policy": "Immutable",
                "promotion_policy": "NoPromotion", "roles": [], "tools": [],
                "ttl": null, "memory_scope": "Ephemeral", "governance": "SingleAdmin",
                "template_id": null
            }}
        }))
        .expect("CreateChildContext action deserializes");

        mgr.propose_governance_action(
            context_id,
            admin,
            "cafef00d000000000000000000000000000000000000000000000000000000ff",
            &action,
        )
        .expect("in-ceiling CreateChildContext auto-executes on single-admin propose");

        let logged = mgr.test_context_event_log_events(context_id);
        let executed = logged
            .iter()
            .filter(|e| e.event_type == EventType::GovernanceActionExecuted)
            .count();
        assert_eq!(
            executed, 1,
            "an in-ceiling CreateChildContext MUST mint EXACTLY ONE GovernanceActionExecuted leaf \
             — identical to native (§9.9.3; ADR-031 §8)"
        );
    }

    /// §9.9.3 native↔WASM REJECT-decision parity for `EstablishToolInterface`.
    ///
    /// Native gates this on `Capability::ToolInterface` in
    /// `execute_establish_tool_interface` (`governance_helpers.rs`) via
    /// `ceiling.contains(&Capability::ToolInterface)`. Absent from the default
    /// ceiling, so an out-of-ceiling proposal is rejected and mints ZERO leaves.
    /// WASM previously returned `None` (ungated) — the same divergence/security
    /// gap as `CreateChildContext`. WASM now returns `Some("tool:interface")`.
    #[test]
    fn cross_impl_out_of_ceiling_establish_tool_interface_rejected_wasm() {
        use crate::manager::{WasmContextManager, make_bare_per_context_state};
        use scp_event_log::EventType;
        use scp_protocol::context::governance::GovernanceAction;

        let context_id = "ctx-gov-iface-out-of-ceiling";
        let admin = "did:dht:z6MkAdmin";

        let mut ctx = make_bare_per_context_state(context_id, admin);
        ctx.test_set_governance("single_admin");
        ctx.test_insert_member(admin, "admin");
        ctx.test_insert_ceiling("governance:propose");
        ctx.test_insert_ceiling("governance:vote");
        // Deliberately DO NOT insert "tool:interface" — the out-of-ceiling
        // condition. Native's `execute_establish_tool_interface` rejects likewise.

        let mut mgr = WasmContextManager::new();
        mgr.test_insert_context(context_id, ctx);

        let action: GovernanceAction = serde_json::from_value(serde_json::json!({
            "EstablishToolInterface": {"interface": {
                "source_context": "ctx-src", "target_context": "ctx-tgt",
                "tool_id": "tool-1", "rate_limit": null, "per_caller_rate_limit": null,
                "approved_by_source": false, "approved_by_target": false,
                "outbound_policy": null, "inbound_policy": null
            }}
        }))
        .expect("EstablishToolInterface action deserializes");

        let result = mgr.propose_governance_action(
            context_id,
            admin,
            "cafef00d000000000000000000000000000000000000000000000000000000ff",
            &action,
        );
        assert!(
            result.is_err(),
            "an out-of-ceiling EstablishToolInterface (tool:interface not in ceiling) MUST be \
             rejected — identical to native's per-action ceiling gate (§9.9.3; ADR-031 §8)"
        );

        let logged = mgr.test_context_event_log_events(context_id);
        let executed = logged
            .iter()
            .filter(|e| e.event_type == EventType::GovernanceActionExecuted)
            .count();
        assert_eq!(
            executed, 0,
            "a rejected out-of-ceiling EstablishToolInterface MUST mint ZERO \
             GovernanceActionExecuted leaves on both bridges"
        );
    }

    /// §9.9.3 native↔WASM ACCEPT-decision parity for `EstablishToolInterface`:
    /// with `tool:interface` IN the ceiling, the single-admin propose auto-
    /// executes and mints EXACTLY ONE `GovernanceActionExecuted` leaf — matching
    /// native, whose `execute_establish_tool_interface` ceiling check passes.
    #[test]
    fn cross_impl_in_ceiling_establish_tool_interface_executes_wasm() {
        use crate::manager::{WasmContextManager, make_bare_per_context_state};
        use scp_event_log::EventType;
        use scp_protocol::context::governance::GovernanceAction;

        let context_id = "ctx-gov-iface-in-ceiling";
        let admin = "did:dht:z6MkAdmin";

        let mut ctx = make_bare_per_context_state(context_id, admin);
        ctx.test_set_governance("single_admin");
        ctx.test_insert_member(admin, "admin");
        ctx.test_insert_ceiling("governance:propose");
        ctx.test_insert_ceiling("governance:vote");
        // In-ceiling: `Capability::ToolInterface` is 2-segment, so its
        // `ucan_capability_name()` form equals its `name()` form: "tool:interface".
        ctx.test_insert_ceiling("tool:interface");

        let mut mgr = WasmContextManager::new();
        mgr.test_insert_context(context_id, ctx);

        let action: GovernanceAction = serde_json::from_value(serde_json::json!({
            "EstablishToolInterface": {"interface": {
                "source_context": "ctx-src", "target_context": "ctx-tgt",
                "tool_id": "tool-1", "rate_limit": null, "per_caller_rate_limit": null,
                "approved_by_source": false, "approved_by_target": false,
                "outbound_policy": null, "inbound_policy": null
            }}
        }))
        .expect("EstablishToolInterface action deserializes");

        mgr.propose_governance_action(
            context_id,
            admin,
            "cafef00d000000000000000000000000000000000000000000000000000000ff",
            &action,
        )
        .expect("in-ceiling EstablishToolInterface auto-executes on single-admin propose");

        let logged = mgr.test_context_event_log_events(context_id);
        let executed = logged
            .iter()
            .filter(|e| e.event_type == EventType::GovernanceActionExecuted)
            .count();
        assert_eq!(
            executed, 1,
            "an in-ceiling EstablishToolInterface MUST mint EXACTLY ONE GovernanceActionExecuted \
             leaf — identical to native (§9.9.3; ADR-031 §8)"
        );
    }
}
