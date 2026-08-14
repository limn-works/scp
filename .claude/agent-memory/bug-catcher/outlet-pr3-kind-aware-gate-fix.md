# outlet-report-pr3 kind-aware invocation gate FIX (03e089202, review of prior HIGH)

Confirming pass on the fix that closes the earlier HIGH (split OutletQuery/OutletCall gate not wired into all invocation-authorization surfaces). Diff dc915e273..03e089202.

**VERDICT: fix is CORRECT and COMPLETE on production code.** All 6 sites now call `has_outlet_invocation_capability(role_state, did, outlet_id, kind)` which dispatches Query→has_outlet_query_capability / Action→has_outlet_call_capability (scp-protocol/mod.rs:638, thin runtime wrapper invoke.rs:1159). Stems independent (verified).

Sites verified:
- session.rs:359 reads `registry.get(outlet_id).map_or(Action,kind)` — correct.
- interface.rs:1808 (cross-context) reads `target_registry` kind — CORRECT authority: sig doc line 1680 "Target context tool registry"; outlet is registered in target, source member holds the cap in source role_state. map_or(Action) default → step-6 existence check (order: authz-before-existence-disclosure, fine).
- outlets.rs:922 (PyO3 xctx SOURCE gate) reads target kind via `with_context(target).ok_or(NotFound)` (UCAN already guaranteed existence) — correct.
- outlets.rs:1519 (PyO3 session) reads rt.outlet_registry — correct.
- mcp.rs:807 reads rt.outlet_registry — correct. PRIMARY UCAN gate above it (validate_outlet_invocation_ucan, mcp.rs:~767) is ALSO kind-aware (passes outlet_kind_for_ucan) → role-state check is genuine defense-in-depth.
- uniffi bridge.rs:4713 reads handle.outlet_registry.blocking_lock().

**blocking_lock @ bridge.rs:4718 — NOT a deadlock.** Scoped guard `{ let handle=registry.get(ctx)?; let registry=handle.outlet_registry.blocking_lock(); ... }` drops at block end. Mirrors 3 existing precedents in SAME McpUniFfiBridgeProvider trait (4565 context_tools, 4613 validate_capability UCAN block, 4767 invoke_tool). Not nested inside another outlet_registry guard (4613's guard is block-scoped, dropped before 4718). Sync trait method (validate_capability) — blocking_lock legal here. Builds clean. Minor redundancy: kind read twice in validate_capability (4613 UCAN + 4718 role-state), 2 lock acquisitions — not a bug.

**TS scp.ts outletRegister fix — CORRECT.** `#native` = raw napi addon (`addon.SCP`, NativeScpInstance) NOT the native.ts wrapper → conversion IS necessary (pre-fix passed clean OutletDefinition straight to raw addon expecting NapiOutletDefinition → napi deser failure on missing inputSchemaJson/operatorDid). napiDef matches native.ts:794 field-for-field: name/description/kind/inputSchemaJson/outputSchemaJson/operatorDid/testVectorsJson/implementationHash(Array.from)/cost{amount,currency,payee,costFormula}. Matches Rust NapiOutletDefinition + NapiOutletCost. tsc --noEmit passes.

**Completeness (#6): ZERO invocation gates left on bare Action stem.** grep has_outlet_call_capability across crates → only: def, internal Action-branch dispatch inside has_outlet_invocation_capability, re-export (scp-core lib.rs:127), tests. Core invoke_outlet / invoke_outlet_execute_and_validate / invoke_outlet_with_cancellation (invoke.rs 266/462/698) were ALREADY kind-aware (prior PR). NAPI outlet_invoke_on delegates to core (no separate role gate). app_sandbox check_outlet_call (551) = test-only, no prod callers, not on invoke path (pre-existing, OOS). No WASM outlet crate.

**Tests: session.rs test GENUINE** (invoke_query_session_denied_with_call_cap_allowed_with_query_cap — calls real invoke_session, exercises gate at session.rs:359; both passed). **mcp.rs test WEAK (LOW):** ffi_bridge_provider_validate_capability_query_kind_selects_query_stem does NOT call validate_capability — reconstructs registry-read + helper dispatch inline; would NOT catch a regression of mcp.rs:807 back to has_outlet_call_capability. Honest comment admits it (validate_capability needs full 11-step UCAN to reach role gate). By extension none of the 4 FFI-site wirings (outlets.rs 922/1519, mcp.rs 807, uniffi 4713) have a direct regression test. Mitigated: primary UCAN gate at each FFI site is already kind-aware, so a role-state regression is still caught by the primary layer. Net LOW.
