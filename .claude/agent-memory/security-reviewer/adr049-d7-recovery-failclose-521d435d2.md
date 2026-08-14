---
name: adr049-d7-recovery-failclose-521d435d2
description: ADR-049 D7 PR-3 round-2 — recovery_advance_epoch (§9.12) fail-close broadcast + keep_broadcast_failure extract + reset comment honesty. SECOND-ZERO clean.
metadata:
  type: project
---

# ADR-049 D7 PR-3 round-2 (chore/adr049-d7-transport, worktree scp-wt-d7-transport) -- 2026-07-07 -- SECOND ZERO, NO NEW CRIT/HIGH/MEDIUM

Follow-on to `adr049-d7-commit-fault-failclose.md` (b45f9de5a). Round-1 findings addressed. Re-review verdict: CLEAN.

Commits reviewed: 418b1569a (extract keep_broadcast_failure), 521d435d2 (recovery §9.12 fail-close), 5058ac1b1 (reset comment honesty), e3b30309f (tests).

## Recovery fail-close (521d435d2) — VERIFIED FAIL-CLOSED on every axis
- `recovery_advance_epoch` (trust_recovery_helpers.rs ~236-262) now routes epoch-advance Commit through `try_broadcast_commit` + `keep_broadcast_failure` (`.await?`), replacing warn-and-drop. Identical shape to remove/rotate/leave.
- Q1 no-ack-without-delivery-or-durable-queue: 3 paths — (A) broadcast Ok → delivered; (B) broadcast fail + persist Ok → pending_commits durable, retry guaranteed; (C) broadcast fail + persist FAIL → keep_broadcast_failure returns Err(PersistenceFailed) via `?`, recovery NOT acked. No silent-success path.
- Q2 fail-open check: `commit_class_s_keep` (class_s.rs ~2803) is KEEP-direction — on persist failure returns Err WITHOUT undoing mutation, marker RETAINED in memory, error propagates. Fail-CLOSED confirmed.
- Q3 no self-deadlock: recovery_advance_epoch does NOT call check_commit_fault. commit_fault gates only send (messaging_helpers:913), governance dispatch (governance_helpers:5220), leave/lifecycle (lifecycle_helpers:244). Recovery can run even when context is fault-gated — GOOD (post-compromise recovery must work in fault state). commit_fault set only on queue-full.
- Terminal retry exhaustion (apply_commit_retry_outcomes, handlers/governance.rs:1043 Failed arm) sets commit_fault (fail-close) + removes entry — NO silent drop even after MAX_COMMIT_AGE_SECS/MAX_COMMIT_RETRIES. Retry drain short-circuits if commit_fault already set (won't redrive until acknowledged).

## keep_broadcast_failure extract (418b1569a) — behavior-preserving
- Collapses 3 byte-identical inline blocks. New `ClassSMut::commit_broadcast_borrows()` mirrors `ClassCMut::commit_broadcast_borrows()` — same 3 disjoint fields (pending_commits/commit_fault/receive_buffer). Both run inside commit_class_s_keep which persists whole `&self.state` fail-closed. Identical scope. No regression. New fieldless `CommitOperation::RecoveryAdvanceEpoch` variant + label() arm; retry drain (compute_commit_retry_outcomes) is operation-agnostic (re-sends commit_bytes, clones op for observability only) — no exhaustive-match gap.

## Reset comment (5058ac1b1) — HONEST
- execute_reset_member (governance_helpers.rs ~2460) does remove_member THEN add_member for SAME did — same-member key refresh, member stays authorized. Comment's 3 justifications (net-neutral vs RemoveMember / §9 Class-M / pre-async ClassCMut parity) accurate. Residual ("old possibly-compromised keys decrypt until re-delivery") honestly stated with "be honest". No misleading claim.

## Carried residuals (not blockers, pre-existing)
- TEST-GAP (same MEDIUM as b45f9de5a): no e2e test at actual recovery_advance_epoch site — cfg(test) no-crypto pipeline serializes Commit to empty bytes → try_broadcast_commit short-circuits None before enqueue. Helpers unit-pinned individually (keep_broadcast_failure FailPersistence→Err+retained; RecoveryAdvanceEpoch tag). Honestly documented as module NOTE. Wiring is trivial `if let Some(f)=try_broadcast_commit{keep_broadcast_failure().await?}`.
- OBS empty-bytes fail-OPEN branch: try_broadcast_commit returns None on empty commit_bytes → no broadcast, no enqueue, recovery acks. Safe ONLY because production MLS crypto never yields empty Commit. Shared invariant across all 4 sites, pre-existing, unchanged.
- INQUIRY (upstream, not code): IF reset is ever the remediation path for a compromised-but-retained member key, Class-M/best-effort classification deserves a spec-level second look. Spec→code flow, not a diff blocker. Comment already flags residual.
