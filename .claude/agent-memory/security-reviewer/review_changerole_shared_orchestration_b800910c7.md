---
name: review-changerole-shared-orchestration-b800910c7
description: Security review of feat/changerole-shared-orchestration (#1877 slice 1) — ChangeRole orchestration unified into shared sync trait/body in scp-protocol; native+WASM route through it; WASM gains missing RoleAssigned leaf. CLEAN, zero findings.
metadata:
  type: project
---

# feat/changerole-shared-orchestration @ b800910c7 — CLEAN, ZERO FINDINGS

First #1877 convergence slice. Extracts ChangeRole governance orchestration into a single
sync body `scp_protocol::context::orchestration::orchestrate_change_role` over new traits
`ContextStateView`/`ContextStateMut` (state_view.rs). Native (governance_helpers.rs
`NativeChangeRoleState`) and WASM (manager.rs `WasmChangeRoleState`) each impl the trait
and call the shared body. NO MLS/crypto/key/transport changes (ChangeRole = pure state +
one Merkle leaf).

**Why:** drift between two independent transcriptions of the same governance logic surfaces
as divergent Merkle leaves → false §9.9.3 cross-platform equivocation. WASM previously did
NOT append the RoleAssigned durable leaf at all; now it does, byte-identical to native.

**Verified (all 4 categories clean):**
- AUTH BOUNDARY PRESERVED. Orchestration ordering is `is_active → has_member → assign_role
  → persist_fail_closed → append_leaf`. Reject-before-mutate: guards run BEFORE any commit.
  Native old code ran require_active+membership INSIDE commit_class_s_keep closure (Err →
  no persist); new code runs them outside the commit → strictly cleaner fail-closed, same
  net effect (commit_class_s_keep@class_s.rs:2589 persists only on Ok). ChangeRole is
  engine-approved before dispatch; orchestration touches neither quorum nor capability.
- WASM ACTIVE-CHECK REROUTE (require_active_context_mut → require_context_mut + check in
  shared body): inactive_error() emits IDENTICAL CTX_2013 msg
  `"context '{id}' is in '{state}' state — must be 'active'"` as require_active_context_mut
  (manager.rs:5965). member_not_found → CTX_2015 `"member '{did}' not found"` identical to
  prior inline. Fail-closed: is_active checked before assign_role mutates. (execute_governance_action
  already active-checks at proposal-resolve @3221; net behavior unchanged.)
- CONVERGENCE: WASM append_log_event (manager.rs:489) builds same Event{type,actor,ts,seq,
  empty payload,prev_hash GENESIS-or-last,empty sig} via shared append_unsigned_event that
  native uses through append_context_event_with_payload(EventPayload::default()) (builder.rs:213).
  RoleAssigned leaf = empty payload, actor=executor, convergent ts. native_reference two-leaf
  root test proves byte parity by construction.
- UNTRUSTED INPUT: none new. action/created_at come from TRACKED proposal
  (tracked.action.clone()/tracked.created_at @3247-3248), executor_did = committing-member
  param (SCP-1866 resolution). did/new_role ride engine-tracked action. No caller value
  reaches the leaf. No new panic (native assign_role err → MembershipFailed(e.to_string),
  same as old). No info leak.
- NATIVE persist_fail_closed = no-op (correct): ClassSCell exposes no &mut PerContextState
  outside a persisting combinator (no DerefMut/state_mut), so assign_role does assign+persist
  atomically inside ONE commit_class_s_keep; the trait's separate persist hook is the
  permitted infallible no-op. checkpoint counter increments once-per-leaf inside append_leaf
  (= old single post-append increment).
- WASM append_leaf returns Ok unconditionally; the error swallow lives in append_log_event
  (console.error). PRE-EXISTING WASM pattern for ALL leaf appends (MemberLeft, GAE, …), not
  introduced here; "never fails" since seq+prev_hash computed from current state. Non-finding.

**Tests RAN green:** scp-protocol orchestration unit (3: rejects-inactive-no-mutate,
rejects-absent-member-no-mutate, assign→persist→append order); scp-runtime wasm_conformance
change_role (3 incl cross_impl_change_role_leaf_is_empty_and_precedes_executed); scp-ffi-wasm
cross_impl (16 incl real-path cross_impl_role_assigned_leaf_bytes_wasm driving
execute_governance_action end-to-end); scp-runtime --lib governance (40). clippy
scp-protocol/scp-runtime --all-targets + scp-ffi-wasm wasm32 clean.
