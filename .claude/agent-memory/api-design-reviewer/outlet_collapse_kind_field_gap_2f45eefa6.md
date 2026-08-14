---
name: outlet-collapse-kind-field-gap-2f45eefa6
description: Collapsed outlet re-port @2f45eefa6 — MAJOR OutletKind field missing from SDK OutletDefinition ×4, Query half decorative
metadata:
  type: project
---

Collapsed outlet re-port landing on main (`feat/outlet-report-pr3` @ `2f45eefa6`, worktree scp-wt-outlet-pr3). API-design re-review focused on OutletQuery/OutletCall SDK surface. **NEEDS REVISION — 1 MAJOR.**

## MAJOR (misuse-resistance + spec violation): `kind` (OutletKind) absent from SDK `OutletDefinition` ×4 → OutletQuery half is a decorative trap
- Core `OutletRegistration` has REQUIRED `kind: OutletKind` (registration.rs:149), `Query`(0x00)/`Action`(0x01), committed to §5.4.1 V2 canonical preimage (kind_byte), gates §5.4.2 Query cost-floor.
- SDK `OutletDefinition` (Python outlets.py:102, TS types.ts:690, Swift UniFFI, Kotlin Types.kt:209) has **NO kind field**. TS builder `defineOutletDefinition` (outlets.ts:38) params have no kind. `grep kind` in all 4 OutletDefinition = zero.
- ALL 3 bridges HARDCODE `kind: OutletKind::default()` (=Action): PyO3 outlets.rs:283, NAPI outlets.rs:255, UniFFI bridge.rs:12733. Input kind (even a raw dict `{"kind":"query"}` via Python's untyped register) is IGNORED.
- Runtime invoke path (invoke.rs) ALWAYS checks `has_outlet_call_capability` (:258/:449/:684); does NOT branch on kind. NO `has_outlet_query_capability` fn exists anywhere (grep=0). No query-invoke operation. So OutletQuery cap is never consumed at invoke — only referenced in policy/templates/caveats/mint ceiling+delegation validation.
- **Spec §5.4.2:274 EXPLICIT: "SDKs SHOULD surface `kind` as a required field in application APIs even though the wire format tolerates absence."** All 4 SDKs violate this. Query feature (§5.4.2:253-276: cost floor, ReadOnlyInvocation guard, chain-amplification rule) is fully live in spec+core but UNREACHABLE from SDK. Only §5.4.3 shared cache is deferred — kind is NOT deferred.
- MISUSE SCENARIO (answers task Q1 — surface is anti-misuse-resistant): agent reads well-crafted `outletQuery()` docstring "Query outlet capability — read-only; never billed", registers a read-only outlet (no way to declare Query), grants `outletQuery("weather")` — collaborator's `outletInvoke` FAILS authz because outlet silently registered Action requiring `outletCall`. The one capability the docs steer you to for a read-only outlet is the one guaranteed NOT to work. Worse than no split — actively teaches a broken pattern.

## MODERATE (cross-binding parity): register-method typing drift + orphaned Python type
- `outletRegister` definition param: Swift/Kotlin typed `OutletDefinition`; Python `dict[str,Any]` (scp.py:2578, PyO3 native takes `&Bound<PyDict>`); TS `unknown` (scp.ts:2032). 2-typed/2-untyped split.
- Python `OutletDefinition` dataclass is EXPORTED + documented (outlets.py:102 w/ construction example) but `outlet_register` takes a dict and no OutletDefinition→dict conversion exists → orphaned public type; the documented happy-path constructor is not accepted by the register method.

## SOUND (don't re-flag)
- Capability-string builders `outletQuery`/`outletCall` byte-consistent ×4 (Python types.py:256/268, TS types.ts:58/69, Swift Types.swift:136/144, Kotlin Types.kt:70/78); docstrings byte-identical.
- Operation names uniform ×4: outletInvoke/outletInvokeCrossContext/outletInvokeCrossContextSaga, outletRegister/Verify, outletSession{Create,Invoke,Close}, outletInterface{Expose,Accept,Revoke}.
- Legacy tool:invoke hard-reject SCP-OUT-014 (spec §5.4.2.1:289) — core-layer, no tool:invoke constant left in bindings.
- FFI OutletInvoke→OutletCall stale-string rename (baeebdd92) already landed — no residual.

## LOW carryover (from outlet_query_call_split_pr3)
- TS `outletQuery`/`outletCall` = module free functions vs Capability-attached statics in Python/Swift/Kotlin (container drift).
- Python `.value` on enum constants vs bare-str builders (mixed idiom).
