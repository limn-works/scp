---
name: adr049-d7-async-hoist-failclosed-downgrade
description: ADR-049 D7 PR-3 async-transport hoist — where fail-closed→coalesced safety-state downgrades hide when a sync trait goes async; exhaustive site-set method
metadata:
  type: project
---

ADR-049 Decision-7 PR-3 (`aea8ee8c1`) made `ContextTransportProvider` async. Any transport
send that on `main` lived INSIDE a synchronous fail-closed persist closure
(`commit_class_s_keep`) had to be HOISTED OUT (can't await in a sync closure). If the
state write capturing the send's outcome was hoisted with it into a COALESCED (≤50ms
actor-tick / `class_c_view` / `ClassCMut`) view, that silently downgrades a fail-closed
safety gate — a crash-durability regression.

**Why:** the commit-broadcast helper `try_broadcast_commit_or_enqueue` (split by the fix
`b45f9de5a` into async `try_broadcast_commit` + sync `apply_broadcast_failure`) sets the
`commit_fault` gate + `pending_commits` retry on broadcast FAILURE. Those are the ONLY
re-delivery of an MLS-Commit + the gate blocking send/lifecycle/governance. Coalesced ⇒ a
crash in the window loses both ⇒ silent permanent group desync.

**How to apply (exhaustive-site-set method for any sync→async trait conversion):**
1. Enumerate every call site of the hoisted op across ALL of `crates/` (grep old + new name).
2. For EACH, read `main` (`git show <main>:<file>`) to classify the pre-change durability:
   `commit_class_s_keep`/`persist_state_fail_closed` = FAIL-CLOSED; `class_c_view`/
   `ClassCMut`/`commit_class_c_best_effort` = already COALESCED (no regression possible).
3. Sites fail-closed on main MUST be re-fail-closed (apply inside a 2nd `commit_class_s_keep`).
   Sites coalesced on main correctly STAY coalesced.
4. Widen scope: grep EVERY `deps.transport.*` send in the crate; for each, check the state
   write AFTER it — writes-no-state (warn-only recovery/heartbeat sends), best-effort-by-design
   (create `publish_context`, `apply_broadcast_publish`, periodic retry drain), or fail-closed-
   BEFORE-send (send path: nonce token `.commit()` precedes `encrypt_and_send`, `finalize_send`
   fail-closed after) are all NOT regressions. Only outcome-fed fail-closed safety state matters.

**Verified result @HEAD (`167c23078`):** site set EXHAUSTIVE + correct. 6 broadcast calls / 5
fns. Fail-closed on main & re-fail-closed: `execute_remove_member`,
`execute_rotate_content_keys` (governance_helpers.rs), `leave_context` (lifecycle_helpers.rs).
Coalesced on main & kept coalesced (NOT regressions): `execute_add_member`
(`commit_class_c_best_effort`), `execute_reset_member` (signature is `ClassCMut`, ×2 broadcasts).
No other transport send fed previously-fail-closed state. Zero stale
`try_broadcast_commit_or_enqueue` refs in source (only in backend agent-memory logs).

**Non-blocking OBSERVATION (inherent to D7, not a missed site):** the fix necessarily SPLITS
what was one atomic persist on main into TWO fail-closed persists — persist#1 {mutation} →
async broadcast → persist#2 {marker+pending_commit}. A crash BETWEEN them leaves the mutation
durable but the retry/gate not (op returns Err, unacknowledged). This is forced (broadcast
result unknowable until after persist#1) and identical across all 3 sites. Could be hardened by
persisting `pending_commits` OPTIMISTICALLY in persist#1 pre-broadcast (idempotent re-broadcast
on spurious retry), clearing on success. Reported regression class (≤50ms coalesced) IS fully
fixed. See [[adr049-d7-transport-async-pr3]] (sibling PR-3 review) and [[adr049-contextinner-arcswap-sync-state]].
