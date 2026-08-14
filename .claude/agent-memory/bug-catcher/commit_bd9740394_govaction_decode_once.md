---
name: commit-bd9740394-govaction-decode-once
description: CLEAN review — record_governance_action consolidated double-decode to single decode_payload; behavior-preserving, proven equivalent to project_payload path
metadata:
  type: project
---

Commit bd9740394 (branch c3c-ts-work) consolidates record_governance_action in
crates/scp-protocol/src/trust/participation.rs to decode GovernanceActionExecutedPayload at most once.

**VERDICT: CLEAN. Exactly behavior-preserving vs bb066a519.**

Why equivalent:
- OLD subject branch: `project_payload(&event.event_type,&payload).target_did.map(Into::into)`.
  project_payload's GovernanceActionExecuted arm = `decode_payload::<GovActionExecutedPayload>(payload).ok().and_then(|p| non_empty(p.target_did))`,
  where `non_empty(s) = if s.is_empty() {None} else {Some(s)}`.
- NEW `target` = `decode_payload(...).ok().as_ref().and_then(|p| (!p.target_did.is_empty()).then(|| p.target_did.clone()))`.
- `(!s.is_empty()).then(|| s.clone())` ≡ `non_empty(s)`. Identical for empty/undecodable/non-empty.

No event-type dispatch divergence: record_governance_action is called ONLY from the
`EventType::GovernanceActionExecuted` arm (participation.rs:176), so OLD project_payload always took
the GovernanceActionExecuted match arm — same as NEW unconditional decode. The `_ => default()` arm
was never reachable from this call site.

Critical edge (is_subject=true + undecodable payload → still push w/ None): PRESERVED. decoded=None →
target=None → unconditional push in `if is_subject` block. No let-else dropped it.

against-branch guard: `target.as_deref()==Some(subject_did) && decoded.as_ref().is_some_and(...)`.
target=Some implies decoded=Some, so is_some_and never short-circuits incorrectly. empty action_type →
is_adverse_action_type returns true (conservative). Correct.

Ownership: only one of the two branches executes; `target.map(Into::into)` move is fine in each.

Tests: 69 participation unit tests pass. clippy -p scp-protocol --all-targets -D warnings clean.
GAP (non-blocking): no dedicated test for is_subject=true + UNDECODABLE payload → push-with-None
(the critical edge). by-empty-target covered (compute_tracks_governance_actions_by_subject), empty
action_type covered (empty_action_type_governance_action_counts_as_adverse). project_payload import
still used at lines 188/205/219 (subject_did for other event types) — no dead import.
