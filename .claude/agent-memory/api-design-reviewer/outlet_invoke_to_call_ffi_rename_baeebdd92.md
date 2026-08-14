---
name: outlet-invoke-to-call-ffi-rename-baeebdd92
description: PR-3 stale-capability-name migration (OutletInvoke→OutletCall) in outlet FFI error strings/docs @baeebdd92 — APPROVED, prior concern resolved
metadata:
  type: project
---

Follow-up to [[outlet_query_call_split_pr3]]. Commit baeebdd92 (branch feat/outlet-report-pr3, worktree scp-wt-outlet-pr3) migrated FFI-layer error strings + doc-comments that named the DELETED `OutletInvoke` grantable capability to `OutletCall` (the actual enum variant, roles.rs:86 `OutletCall(OutletId)` / :88 `OutletCallAll`).

**Verdict: APPROVED.** Prior stale-name concern RESOLVED. No new API-surface findings.

**Why / verified (don't re-flag):**
- FFI error strings + docs now name `OutletCall` in all 3 target files: mcp.rs:794 (PyO3 log), outlets.rs:880/:1338/:1433/:2007, uniffi/bridge.rs:4680. Zero residual capability-name `OutletInvoke` (only `OutletInvokedEvent` event refs remain, which are correct).
- `git grep OutletInvoke` remaining hits ALL legitimate non-capability: `OutletInvokedEvent`/`OutletInvoked` (event struct, ADR-010 event-log), `CrossContextOutletInvoke` (saga envelope name), `outlet_invoke`/`dispatchOutletInvoke` (conformance OP verb), `lastOutletInvoke*`/`TestScpOutletInvoke`/`inner class OutletInvoke` (test fixtures), roles.rs:5877 intentional negation ("does NOT have variants OutletInvoke"). No `Capability::OutletInvoke`/`Self::OutletInvoke`/`[OutletInvoke]` enum refs anywhere.
- Dead-arm deletion at roles.rs:~228 is a genuine no-op: deleted `if n=="outlet:invoke:*"||n=="outlet_invoke:*" {None}` is DOMINATED by the surviving `starts_with("outlet:invoke:")||starts_with("outlet_invoke:")` guard at :225 (the wildcard strings start with those prefixes). Hard-reject intact + COVERED by test out014_no_outlet_invoke_variant_remains (roles.rs:5875) asserting all 4 stem forms → None.
- context.rs:8402 test-comment fix is factually correct: `"not-a-capability"` hits NO hard-break/exact arm → catch-all roles.rs:286 `Some(Custom(name))` → Some(not malformed); deny is no-matching-grant vs `outlet:query:*`. Prior comment "Malformed…fail-closed" was subtly wrong.
- Kotlin ConsequenceRule.kt:99 doc-link `[OutletCall]` now resolves (data class OutletCall at :120; prior `[OutletInvoke]` was a stale/broken KDoc link). `[Custom]` also resolves (:129).
- TS integration.test.ts:220 comment updated OutletInvoke→OutletCall (cosmetic, matches wire encoding).

Diff was exactly 7 files / +13 -13, all rename+doc+dead-code, no behavioral/signature change.
