---
name: adr049-2g-placeholder-deletion-partb-9b19a8974
description: ADR-049 Phase 2G part (b) Placeholder-variant deletion + de-stale review @ 9b19a8974 — ALIGNED
metadata:
  type: project
---

# ADR-049 2G part (b) Placeholder deletion @ `9b19a8974` (2026-07-02) — ALIGNED

Branch `chore/2g-delete-placeholder-variants`, worktree `2g-placeholders`. Diff `origin/main...HEAD` = 20 files +658/-848.

**Verdict: ALIGNED. 0 blocking, 1 minor terminology observation.**

Scope: deletes 8 dead non-messaging `Placeholder` command variants (Lifecycle/Governance/Broadcast/Economy/TrustRecovery/Standing/TtlClose/Tools — zero producers, only variant defs + match arms) + migrates the 9th (messaging) smoke-test Placeholder to real read-only `QueriesCommand::MemberCount` (handle.rs `smoke_query`). All 9 `Placeholder {` variant defs removed. Plan `generic-moseying-lightning.md:413` 2G = "delete send_tracker shim + resolve 9 Placeholder variants (implement or delete)." Part (a) send_tracker shim DEFERRED to #18 — no closing keyword, scope-split HONEST.

**Verified:**
- Citation fixes correct vs `.docs/specs/05-contexts.md`: §5.12.4 (Context Creation runtime op, line 879) → §5.12.6 (The Contact Graph, line 1003) at commands.rs:739 + mod.rs:2813; §5.15.7 (Send-Sequence Reservation, line 1699) → §5.12.6/§5.15.8 (Standing-Pair Creation, line 1709) at standing.rs:3. All accurate.
- DEFERRED-commit-11 doc consistent w/ §5.15.8: verbatim quote "the standing-pair creation path is not yet wired" exists (spec:1719); protocol enumeration (peer KeyPackage fetch + add_member + Welcome + consent-on-receipt) matches spec §5.15.8 (1756/1775). Dropped the deleted `reply_not_implemented`/handlers/standing.rs pointer. All `InitiateStandingPairCreate`/`InitiateCrossContextToolInvocation`/`MutationStateView` refs appear only in removed/since-deleted framing.
- Residual `ContextManager` refs in deps.rs (11) + supervisor.rs (9) are deliberate "Formerly/deleted" historical provenance notes — correctly RETAINED, not stale. state.rs residuals OUT OF SCOPE (12b/c/d field-migration cluster, separate follow-up). `MutationStateView` fully gone.

**GOTCHA (why the shim wording is NOT a contradiction):** two distinct "shim" concepts. (1) `dispatch_from_shim` = HANDLER-side entry point, DELETED Phase 2A finalization (messaging.rs:11-15 correct). (2) "supervisor-side dispatch shim" = live `dispatch_*_command`/`dispatch_*_direct` layer, established terminology (mod.rs:84/219/674, commands.rs:252). commands.rs:177/2228 "legacy Supervisor dispatch-shim surface" references concept (2) = LIVE, no contradiction.

**MINOR observation:** commands.rs:177-178 + 2226-2228 say unmigrated ops (sender-key rotation, distribute/remove, access-key mgmt) "stay on / route through the legacy Supervisor dispatch-shim surface." But those ops are NOT command variants (grep RotateSenderKey/etc in commands.rs = empty) — they're direct free-fns in queries_helpers.rs/provider.rs/key_protocol.rs, called direct from FFI, so they don't traverse the command-dispatch shim at all. Precise wording = "direct Supervisor method surface." Low severity; defensible under loose codebase usage of "dispatch shim." Sibling standing.rs:15 uses the precise term "supervisor-direct through Supervisor::dispatch_standing_direct".
