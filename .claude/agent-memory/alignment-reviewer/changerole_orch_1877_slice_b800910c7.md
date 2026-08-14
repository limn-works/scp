---
name: changerole-orch-1877-slice-b800910c7
description: ALIGNED review of #1877 first production convergence slice (ChangeRole shared sync orchestration trait in scp-protocol) at b800910c7
metadata:
  type: project
---

# #1877 ChangeRole shared-orchestration slice @ `b800910c7` (2026-06-24) — ALIGNED

Branch `feat/changerole-shared-orchestration`, reviewed `git diff origin/main..HEAD` (7 files +891/-72). Verdict ALIGNED, 0 blocking, 0 material, 1 informational.

**What it is:** FIRST production slice of #1877 (collapse the native↔WASM "convergence tax"). Adds `scp-protocol/context/orchestration/{mod.rs,state_view.rs}`: sync wasm-safe `ContextStateView`/`ContextStateMut` traits + generic `orchestrate_change_role`. Native `execute_change_role` (governance_helpers.rs:1386-1506, `NativeChangeRoleState`) and WASM ChangeRole dispatch arm (manager.rs:1257-1360 + ~3413) both implement the trait and call the shared body. Closes #206 per-action-leaf gap for ChangeRole — WASM now emits the `RoleAssigned` durable leaf native always emitted.

**Why ALIGNED (verified):**
- Trait in scp-protocol, sync, wasm-safe — exactly #1877 "Proposed direction". Deps only scp-event-log + core; `cargo check --target wasm32` clean for both scp-protocol and scp-ffi-wasm.
- Native byte-identity: prior inline used `append_context_event(RoleAssigned)` which delegates (builder.rs:187-202) to `append_event(...EventPayload::default())` — identical leaf to new `append_context_event_with_payload(...default())`. Ordering preserved incl. ADR-049 §9 FC persist riding inside assign_role's `commit_class_s_keep` (persist_fail_closed is a justified no-op on native — cell hands out no &mut outside a persisting combinator).
- #206/#1885 parity: WASM RoleAssigned leaf = empty payload + EXECUTOR did + CONVERGENT proposal_created_at (threaded via dispatch_governance_action), appended BEFORE GovernanceActionExecuted. Same pattern #1885 set for RemoveMember/MemberLeft.
- GOTCHA confirmed benign: manager.rs:1818 `now_secs()` MemberLeft is the voluntary `leave_context` path (leaver IS committer), NOT the governance dispatch_remove_member path (manager.rs:3671 uses convergent timestamp_secs). Two different MemberLeft sites — correctly distinguished.
- `require_active_context_mut`→`require_context_mut` swap in WASM arm correctly justified: orchestration does the active check + emits same CTX_2013, so outer check would double-check + diverge rejection point.
- Honest tracking: RoleAssigned REMOVED from `wasm_native_full_governance_eventtype_parity_pending` ignore-list + doc (wasm_conformance.rs); ~40 other events stay. No over-claim.
- Tests pass: 3 orchestration unit tests; native `cross_impl_change_role_leaf_is_empty_and_precedes_executed`; WASM real-path `cross_impl_role_assigned_leaf_bytes_wasm` (drives production execute_governance_action, asserts full 2-leaf root parity vs native reference). No #NNNN in any changed source/test.

**DOA-risk resolved (key judgment):** #1877 issue COMMENT (author's spike verdict) plans a richer `HardActionContext` for the membership family (RemoveMember/AddMember): one combined trait single `&mut` (no RefCell split), `RemoveOutcome{committed,degraded}` for partial-failure (irreversible-MLS-evict vs best-effort-rotation asymmetry — "single biggest design decision for hard class"), and `assign_role` SPLIT OUT of the shared supertrait. Current slice is COMPATIBLE not conflicting: already single combined &mut trait; assign_role is on THIS ChangeRole-specific trait (core op, not shared-supertrait dead weight); `Result<(),E>` is correct (no MLS asymmetry for ChangeRole). Incremental ChangeRole-now/HardActionContext-later is the right call — issue's own phasing names ChangeRole as the prototype. NOT a DOA decision.

**1 informational:** `ContextStateView::event_count()` is on the public trait but consumed only by cross-bridge parity tests (orchestration body never calls it). Doc is honest; both bridges impl non-trivially. If a future HardActionContext ADR formalizes the surface, consider a test-only accessor instead of a production-View method. Not actionable now.

**Scope correct:** ChangeRole ONLY. RemoveMember (parity via #1885), AddMember (named next slice — still missing MLS add + MemberJoined leaf per spike) are separate slices, not gaps here.
