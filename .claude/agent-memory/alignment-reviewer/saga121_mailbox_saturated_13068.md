---
name: saga121-mailbox-saturated-13068
description: Issue #121 MailboxSaturated retryable saga terminal (SCP-SAGA-13068) — ALIGNED at fb4c2584c (review-fix resolved the prior target-vs-participant finding)
metadata:
  type: project
---

# Issue #121 — MailboxSaturated saga terminal (SCP-SAGA-13068) — ALIGNED, 0 findings (2026-06-30)

Branch `fix/121-mailbox-saturated-saga-terminal`. Review chain: docs `4cfb643c6` → feat `693d94a1c` → review-fix `fb4c2584c` (= final). Net `git diff 5a67b771d fb4c2584c` = 5 files +296/-26. GOTCHA: worktree may be checked out at a sibling commit (e.g. 1620de983, ceiling work that nets to zero vs this base) — diff resolves the same saga 5-file set regardless.

Change: transient Prepare-phase `ContextError::ActorBusy` in §6.2.4 xctx-tool saga lifts to NEW `SagaAbortReason::MailboxSaturated { retry_after_ms: Option<u64> }` (code 13068, retryable) instead of `_ => Rejected` + `unwrap_or(13067)`. `lift_run_saga_error` resolves `(reason, code)` by STRUCTURAL variant match (no message parse); MailboxSaturated HARDCODES 13068 (ActorBusy from channel send carries no `saga_code`). FFI `decompose_saga_error` folds `RateLimited | MailboxSaturated => retry_after_ms` (exhaustive over the 3-variant enum). Commit-phase ActorBusy can't reach the arm — `needs_repair` guard short-circuits to NeedsRepair BEFORE the match, so an ActorBusy with needs_repair==false is provably Prepare-only. 13068 is next sequential in supervisor partition 13050-13099 (ECON holds 13000-13049, no contention).

**ALIGNED:** ADR §3a transient/retryable/optional-retry/distinct-from-Rejected-and-SagaBusy description matches core enum + FFI mapping EXACTLY. Spec §6.2.4 "retryable clean abort, neither side committed, all-or-nothing as a Prepare timeout" matches lift producing Aborted + RAII reservation release. Provenance one-way: docs committed before code; #121 GitHub issue + ADR-049 §3a + spec §6.2.4 + sdk-common registry (no PRD story, acceptable per CLAUDE.md).

**PRIOR LOW FINDING NOW RESOLVED:** At `693d94a1c` the ADR §3a / registry / enum-rustdoc said "the **target** participant actor's mailbox" while the code lifts ANY `ContextError::ActorBusy(_)` (caller-side Prepare-A / authorize gates route through the CALLER mailbox too). Review-fix `fb4c2584c` BROADENED ADR §3a "target" → "a participant actor" and removed a residual "never-delivered" over-claim. Final state: all four surfaces (ADR/spec/registry/enum-rustdoc) say "a/participant actor" — scope-consistent with the generic lift arm. grep confirms no "never delivered" wording remains.

**Minor observation (non-blocking, NOT a defect):** `ContextError::ActorBusy` (handle.rs:130-143) has 3 sub-cases — mailbox-full, inbox-closed, AND "actor dropped reply channel before replying" (delivered-but-no-reply). Terminal name "MailboxSaturated" + one-liners compress to "saturated or closed," slightly narrower than the full domain. Classification stays SOUND (neither side committed at saga level; retryable is the safe direction; message string carries precise cause) and code-level docs ARE precise — enum rustdoc parenthesizes "(a ContextError::ActorBusy on a Prepare-phase send)" and the test docstring enumerates "full or closed inbox, or a dropped reply channel." Acceptable name compression.

**How to apply:** #121 is land-ready on alignment grounds at fb4c2584c. No carry-forward items.
