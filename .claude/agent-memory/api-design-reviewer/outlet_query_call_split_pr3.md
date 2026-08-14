---
name: outlet-query-call-split-pr3
description: PR-3 outlet-redesign capability split (OutletQuery/OutletCall) API review — feat/outlet-report-pr3, latest tip 1ffe476e5
metadata:
  type: project
---

Outlet-redesign PR-3 (`feat/outlet-report-pr3`, worktree scp-wt-outlet-pr3). Split `ToolInvoke` → `OutletQuery`(read)/`OutletCall`(action).

## Round 2 @ tip 1ffe476e5 (2026-07-10) — NEEDS REVISION (down from prior; only stale-name residuals left)

**Prior 3 MODERATEs ALL RESOLVED:**
- MOD-1 (constants lacked read/mutate docs): FIXED. All 4 SDKs now carry byte-consistent per-symbol docs — "Query outlet capability — read-only; never billed." / "Action outlet capability — the outlet may mutate state and may incur cost (billable)." on BOTH the `OUTLET_QUERY_ALL`/`OUTLET_CALL_ALL` constants AND the `outletQuery()`/`outletCall()` helpers. Python types.py:234/236/259/271, TS types.ts:30/32/54/65, Swift Types.swift:111/113/133/141, Kotlin Types.kt:43/46/66/74.
- MOD-2 (duplicate predicate `has_outlet_invoke_capability`): FIXED. `has_outlet_invoke_capability` + `check_outlet_invoke` GONE everywhere (grep crates/+bindings/ = zero). Single authority = scp-protocol `has_outlet_call_capability` (mod.rs:597); runtime invoke.rs:1116 is a thin delegating wrapper (doc'd "single source of truth ... cannot drift"). Sandbox method renamed `check_outlet_call` (app_sandbox.rs:551, correctly checks OutletCallAll then OutletCall).
- FFI error hint (prior LOW #6): FIXED + broadened. ALL ceiling/role parse sites across ALL 3 bridges + shared common/src/context_params.rs now append `(use "outlet:call:*" for actions, "outlet:query:*" for reads)`. 11 sites, uniform.

**VERIFIED SOUND (don't re-flag):**
- `Capability::new -> Option` (roles.rs:220) unchanged-sound. Hard-reject arms (225-239) before prefix split.
- `CapabilityCeiling::contains` (roles.rs:722) is a clean shared authority: wildcard-implies-specific symmetric for query+call; query/call DISJOINT + explicitly doc'd (OutletQueryAll does NOT cover OutletCall(id)). Good misuse-resistance.
- UCAN `with`-URI ability segment `outlet_call`/`outlet_query` (underscore, via CapabilityUri::new, e.g. invoke.rs:1164, capability.rs) is the CORRECT wire form, distinct from SDK cap-string `outlet:call:` — NOT stale. Don't flag.
- Operation method name `outletInvoke`/`outletInvokeCrossContext`/`outletInvokeCrossContextSaga` uniform ×4 SDKs — settled verb vocabulary orthogonal to the capability rename. `OutletInvokedEvent` = legit event-type name (not the cap stem). Don't flag either.

**REMAINING (Round 2):**
- MODERATE (consistency/discoverability): FFI-layer defense-in-depth capability-lack error strings STILL name the deleted `OutletInvoke` capability — a concept a dev can no longer grant. PyO3 outlets.rs:880 + :1433 ("does not have OutletInvoke capability"), PyO3 mcp.rs:794 + UniFFI bridge.rs:4680 ("agent lacks OutletInvoke capability"). Core layer was migrated (outlets_helpers.rs:1371 "lacks OutletCall(id)", invoke.rs:57 "OutletCall(..)/OutletCallAll") — FFI bridges were NOT. NAPI has no such string (delegates to runtime). MOD-2's rename fix stopped at the core; the FFI happy-path error text is the developer-facing surface and drifts. Also 2 doc-comments outlets.rs:1338 + :2007 "must hold `OutletInvoke` capability". Fix: s/OutletInvoke/OutletCall/ in those 4 strings + 2 docs.
- LOW (dead code): roles.rs:228 `if n == "outlet:invoke:*" || n == "outlet_invoke:*"` is UNREACHABLE — both already caught by the starts_with at :225. Harmless (fail-closed) but misleads that `*` needs special handling. Delete.
- LOW #7 (carryover, unchanged): `accept_tool_interface_with_kind` (interface.rs:1615) still "tool" in a pub fn name post-rename.
- LOW #4 (carryover, unchanged): Python mixed idiom — enum constants need `.value` (examples/outlet_invocation.py:42 `OUTLET_CALL_ALL.value`) but builders return bare str (`outlet_call("x")`).
- LOW #3 (carryover): container 4-way drift — TS `Capabilities` plural (collides w/ pre-existing `Capability` interface) vs Swift `Capability` struct + nested `.Name` enum vs Python/Kotlin flat.
- OBS (non-finding): method `outletInvoke(...)` but authorizing cap is `outletCall("id")` — verb seam (invoke op / call cap). Deliberate, defensible.
