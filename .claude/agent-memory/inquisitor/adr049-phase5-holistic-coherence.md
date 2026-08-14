---
name: adr049-phase5-holistic-coherence
description: ADR-049 actor-per-context Phase-5 FINAL holistic cross-slice re-review @f2d4e7d0f — the accumulated 12-PR model COHERES; findings are all sediment/paperwork, not load-bearing design
metadata:
  type: project
---

# ADR-049 Phase-5 holistic re-review (@f2d4e7d0f, worktree scp-wt-phase5)

Verdict: the actor-per-context model COHERES across slices. The hard parts hang together
as ONE model despite ~12 isolated-reviewed PRs. Findings are all in the scaffolding/paperwork
layer — no security/correctness defect, no design incoherence.

**Why:** interrogated whether accumulated decisions still tell one story. They do.
**How to apply:** on future ADR-049 touches, the four load-bearing decisions below are
CONFIRMED sound — don't re-litigate. The two open findings are drift-cleanup, low severity.

## Confirmed SOUND across slices
- **Class-S/Class-C split (Probe 1).** Principled downward-auth→fail-closed / upward-neutral→
  coalesced. All 7 production broadcast sites classified consistently: 4 fail-closed via
  `keep_broadcast_failure` (execute_remove_member, execute_rotate_content_keys, leave_context,
  recovery_advance_epoch) + 3 best-effort via `apply_broadcast_failure`(class_c_view) (add,
  reset×2). `CommitBroadcastBorrows{pending_commits,commit_fault,receive_buffer}` disjoint-field
  claim holds exactly. Each best-effort site carries an honest per-site residual note (add: upward,
  re-addable; reset: net-neutral key refresh, Class-M membership). No migration-artifact misclass.
- **Send-discipline (Probe 2).** One rule ("does a spawned future await it?"). 11 `impl Future +
  Send + use<...>` precise-capture terminals; sole `?Send` = RecoveryBackend, VERIFIED never
  spawned (only `.block_on(execute_recovery)` at 3 FFI bridges: uniffi/napi/pyo3). Principled.
- **Migration completeness (Probe 3).** `struct ContextManager` FULLY deleted (type-level);
  `&Supervisor` queries shim removed (only tombstone comments). supervisor/ decomposed concerns
  into modules (key_package_actor, saga_journal, saga_prepared_state, handle). supervisor.rs
  itself is 23.8k LOC but is the actor-fleet registry/spawn/poison concern — coherent-but-large,
  not a god-object (98 fn/impl seams, ~240 LOC/fn). Not an inquisitor soundness finding.
- **Gates (Probe 4).** Retired scanners genuinely gone (check-class-s-fail-closed.sh absent;
  deleted compile-witnesses role_view_grow_resolves_to_trait / best_effort_view_has_no_whole_mut_
  accessor survive ONLY as tombstone comments in class_s.rs:3865). ClassSCell type boundary
  genuinely replaced the source-text scanner as ADR claims. Live gates are positive/bounded
  (per-file block-in-place ratchet, handler-no-panic, positive-allowlist class_s tripwires).
  No superseded gate still live-enforcing.

## Open findings (QUESTION-level, drift cleanup — NOT security/correctness)
Root cause: ADR-049 "Phase-2A finalization Step E" (delete `_legacy` shims + transitional twins)
was DECLARED but never fully executed. Migration completed FUNCTIONALLY (live code uses the new
split helpers) but scaffolding + its describing comments/ratchet-prose were left as sediment =
phantom provenance (a reader trusting the comments builds a false model of what's live).
1. `context/economy_helpers.rs` — `complete_paid_action` is DEAD outside tests (only test-body
   callers ~4230/4335) yet its comment claims it's the live "SEND-path surface
   (messaging_helpers::capture_send_payment)"; the real send path calls the split helpers
   (capture_and_verify_paid_action + surface_paid_action_receipt) directly. A tested-but-unused
   wrapper. `void_paid_action` is LIVE (6 production callers in lifecycle join-tail 937-1146) yet
   carries `#[allow(dead_code)]` + "Transitional Phase 2A... until those domains migrate" comment
   = false allow + false transitional label on load-bearing code.
2. `ratchet/block-in-place-count.json` — informational fields stale: `crates.scp-runtime: 14` vs
   actual file-sum 8; `_breakdown`/`_context` describe 6 phantom tools_helpers.rs block sites
   (grep=0) + a nonexistent `tools_helpers_legacy.rs`. Informational-only (checker line 102:
   `files` map is AUTHORITATIVE, `crates` tolerated) so NOT an enforcement break — doc rot in
   the enforcement artifact's own paperwork.
