---
name: adr049-pr6-read-authority-switch
description: Interrogation of ADR-049 PR-6 atomic read-authority switch — member-granular prune divergence, F-3 debug_assert, and the structural-vs-runtime test gap
metadata:
  type: project
---

ADR-049 PR-6 (branch `feat/adr049-pr6-atomic-read-authority-switch`, commit b61618887)
switched the Class-M anti-replay floor read-authority from provider mirrors to the
Supervisor-owned registry, deleting the provider twins. Interrogated four decisions.

**Verdicts (all premises re-derived from code, not the plan's assertions):**

- **§6 member-granular prune divergence — SOUND (not escalation).** The 6 `remove_member_floors`
  seams are co-located 1:1 with the pre-existing provider `remove_member_sender_key` prune
  (governance_helpers.rs:1406/2538, lifecycle_helpers.rs:292/973/1004/1039), so removal-path
  coverage is IDENTICAL — no membership path misses a seam. Only dropped behavior is the
  provider's opportunistic whole-membership D3 sweep of RE-POPULATED floors. Residual liveness
  edge: a straggler key-distribution (seam 2, messaging_helpers.rs:2976) from a just-removed
  member can re-populate that member's floor post-prune; a later rejoin at a lower epoch would
  be over-rejected. FAIL-SAFE (monotonic-high floor can only over-reject, never admit replay)
  and narrow; the old sweep never guaranteed closure either (only at next removal). Coherent
  fix IF ever worth closing = reset the incoming member's floor on the ADD/welcome path, NOT
  resurrect the membership sweep (which re-couples registry to membership, violating the whole
  PR-6 premise). Seam-1 (app-msg) re-population is closed by sender-key removal at the prune.

- **F-3 debug_assert_ne — SOUND (not a corner cut).** messaging_helpers.rs:2951. It's a
  dev-time logic tripwire, not the load-bearing security mechanism; a release violation
  degrades to fail-closed over-rejection (reads local send scalar as overshoot ceiling →
  rejects). Precondition (local_did as remote sender) needs true self-loopback or MLS-auth
  break. Map-split would ripple through merge/export/blob format — simplify tenet supports the
  assert.

- **Test strategy — REAL GAP (the one actionable finding).** Plan §9 mandated 5 integration
  tests; only 2 landed: cold-restart D2 (supervisor.rs:18370, strong) + BUG-1 untrusted-import
  rollback. MISSING: FAIL-CLOSED-BLOCKS (drive a real replayed Application envelope through
  `decrypt_and_dispatch`, assert Err + no OpenedEnvelope) and CATCH-UP-AFTER-LAG (F-2). AND the
  pre-existing provider runtime tests `test_recv_epoch_reorder_still_rejected` /
  `test_recv_epoch_ceiling_*` were DELETED. Net: D1 recv-seam fail-closed rejection has NO
  runtime test — `decrypt_and_dispatch` is called only from production `deliver_incoming`
  (messaging_helpers.rs:1463), never a test. Seam→primitive link proven ONLY by source-text
  `fn_body_contains` in pipeline_wiring.rs. A wrong-floor-value bug at the seam would pass both
  the primitive unit test and the structural assertion yet fail to reject a real replay.

- **Overall premise — SOUND.** Restore-guard merge direction correct (incoming=blob, guard on
  `incoming.is_empty()`, rollback-on-Err — lifecycle_helpers.rs:1746+). D2 close correctly
  wired. The divergence from plan intent is in EVIDENCE (missing runtime tests), not in the
  security mechanism.

**Reusable lesson:** structural `fn_body_contains` assertions prove a call is *present* in a
seam body but not that it's *fed the right value* or that control-flow rejects at runtime.
When a security seam's e2e runtime test is deleted and replaced only by a structural
assertion + a primitive unit test, the wiring-correctness gap between them is exactly where a
mis-mapped-argument bug hides. See [[MEMORY]].
