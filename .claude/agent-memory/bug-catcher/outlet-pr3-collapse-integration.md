---
name: outlet-pr3-collapse-integration
description: CLEAN review of feat/outlet-report-pr3 rebase-integration commit 2f45eefa6 (outlet re-port landing on main) — resolvers, Capability::new Option fallout, event-name preservation, saga economy
metadata:
  type: project
---

# Outlet PR-3 collapse rebase-integration review (branch feat/outlet-report-pr3 @2f45eefa6)

**VERDICT: NO BUGS FOUND.** Build (core+runtime+event-log) exit 0; persistence_ordering (2), broadcast handler (13), saga handler (45) tests all pass.

**Why:** built on prior [[outlet-pr3-capability-migration]] review; this is the same re-port rebased onto main + a 3-file integration commit.

## What was verified
- **Integration commit 2f45eefa6** (broadcast/mod.rs tests, broadcast.rs handler, persistence_ordering.rs):
  - `caveat_resolver: &NoCaveatResolver` on broadcast-subscribe handler (broadcast.rs:231) = CORRECT. Broadcast subscription is NOT an outlet-invocation path; §7.3.8 caveats only scope to outlet_query/outlet_call stems (`is_outlet_stem`). Backward-compat caveat-free resolution is right.
  - `nb: None` in handler test UcanPayload = CORRECT (non-outlet caps, no caveats intended). `nb: Option<InvocationCaveats>` in ucan/mod.rs:425.
  - `.expect("known capability")` on `Capability::new("messages:read"/"messages:write"/"governance:propose")` CANNOT panic — all valid built-ins → always Some. `Capability::new` (roles.rs:220) returns None ONLY for hard-break forms (outlet_invoke:/tool_invoke:/tool_register/tool_interface) and malformed §5.4.2.1 outlet suffixes.
- **Resolver semantics (all sites correct):** outlet-invocation gates → `TokenNbCaveatResolver` (saga.rs:1226 xctx re-validation, ffi/napi/uniffi outlets.rs, mcp.rs:749); generic validate/evaluate → `NoCaveatResolver` (ffi/napi ucan.rs, uniffi bridge.rs:14709/14872). My old note "saga.rs:1202 NoCaveatResolver skips caveats" is now STALE — wired to TokenNb. invoke.rs:1854 NoCaveatResolver is inside `#[cfg(test)]`.
- **Capability::new Option fallout — no silent should-hard-fail drops:**
  - 5 `filter_map(Capability::new)` sites = fail-closed bool checks (check_scoped_capability/sandbox_check_capability; drop only narrows granted set) or test seeds.
  - Ceiling-normalization `filter_map(|s| Capability::new(s).map(|c| c.ucan_capability_name()))` in napi/runtime.rs:1610, pyo3 ffi/runtime.rs:1532 are PRECEDED by a hard-fail loop (`ok_or_else(..)?` + `validate_as_ceiling_entry()?`) → None branch unreachable. uniffi build_ucan_context_state (runtime.rs:1113) = post-creation cache rebuild, defensive skip is fine (authoritative validation already ran at context_create). Asymmetry (napi/pyo3 error-loop vs uniffi filter) is by lifecycle position, not a bug.
  - No broadening: bare `Custom("payments")` → `ucan_resource_action` = `("payments","payments")` = `payments:payments` (concrete), NOT `payments:*` (roles.rs:447-464, test `ucan_resource_action_custom_no_colons_does_not_widen_to_wildcard`).
- **Event-record names preserved:** ToolInvoked / CrossContextToolInvoked (EventType enum tags 11/76 unchanged), tool_invocation_count. `"ToolInvoked:"` prefix producer (saga.rs:1469 + supervisor.rs:6819 `format!`) matches consumer (supervisor.rs:20368 `strip_prefix("ToolInvoked:")`).
- **Saga economy:** pure rename tool_economy→outlet_economy (reserve/rollback/settle + RAII carrier `OutletEconomyReservation`/`OutletEconomyTicket`). Builds; `commit_b_persist_retry_appends_tool_invoked_exactly_once` passes.
