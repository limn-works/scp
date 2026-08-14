---
name: adr049-2g-delete-placeholders-28b2c5f47
description: ADR-049 Phase 2G PR deleting dead actor-mailbox Placeholder command variants + DEFERRED-commit-11 ADR de-stale @ 28b2c5f47 — ALIGNED, 1 scope observation
metadata:
  type: project
---

# ADR-049 Phase 2G — delete Placeholder variants @ `28b2c5f47` (branch chore/2g-delete-placeholder-variants) — ALIGNED, 1 OBSERVATION

Single commit, 15 files +212/-419. Deletes 8 dead actor-mailbox `Placeholder` command variants (Lifecycle/Governance/Broadcast/Economy/TrustRecovery/Standing/TtlClose/Tools — zero producers, only defs+match arms) + the 8 single-caller `reply_not_implemented` helpers + skeleton_dispatch_* arms + supervisor dispatch/target-extraction arms + `sub_enum_placeholders_carry_reply_channels` witness test. Messaging Placeholder (test-only smoke target) repointed to real read-only `QueriesCommand::MemberCount`; two supervisor poison tests use `MessagingCommand::DrainEvents` (mutating but harmless — rejected pre-exec when poisoned, drains empty buffer on recovered actor; commit is honest about this).

VERIFIED ALIGNED:
- **DEFERRED-commit-11-saga-use-cases.md** reworded text drops the deleted `handlers/standing.rs reply_not_implemented` pointer. Grep: 0 `reply_not_implemented` refs anywhere in .docs/ or scp-runtime/src. New text: full standing-pair protocol "(peer KeyPackage fetch + add_member + Welcome + consent-on-receipt) remains unwired per §5.15.8" — matches §5.15.8:1715 flow VERBATIM and §5.15.8:1719 "not yet wired ... no live divergence to reconcile." Does NOT claim wired; does NOT contradict spec. Resolves existing drift, creates none.
- commands.rs/mod.rs module docs reworded present-tense, claim "only remaining NotImplemented producer is the test-only `skeleton_dispatch` path" — ACCURATE: `new_skeleton` is `pub(in crate::context)`, called ONLY from `mod tests` (mod.rs:1436/1462/1479/1503). NotImplemented count in commands.rs=2 (doc/skeleton refs only). 0 Placeholder command variants remain (lifecycle_helpers.rs:2615 "Placeholder" hit = unrelated word usage in a comment).
- trust_recovery handler doc reworded: RecoveryNotifyContact arm = "direct-path twin" not rejection stub — consistent (it always had a real handler; Placeholder was the sole NotImplemented).

OBSERVATION (scope, not a defect): Plan `generic-moseying-lightning.md` line 50 (2026-07-01, freshest) defines **2G/#18 = TWO deliverables**: (a) delete take-and-merge `send_tracker` shim + (b) resolve residual Placeholder/NotImplemented in commands.rs. This PR delivers (b) fully; (a) is UNTOUCHED and STILL LIVE — messaging.rs:272-303 confirms the wire sequence is still driven by `MembershipState::next_sequence_number` with `send_tracker` running in parallel (reserve+commit+manual rollback), Phase-2A-finalization makes send_tracker authoritative. So this PR is a legit SLICE of #18. Commit body does NOT use "Closes #18" (honest scope, no false-completion) — ensure #18 stays OPEN for the send_tracker half.

GOTCHA: Read tool on the giant supervisor.rs diff via persisted-output file (69KB) needed offset paging. §5.15.8 lives at 05-contexts.md:1709.
