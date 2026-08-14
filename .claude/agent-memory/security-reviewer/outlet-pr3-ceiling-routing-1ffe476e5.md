---
name: outlet-pr3-ceiling-routing-1ffe476e5
description: Audit of outlet PR-3 review-fix delta 7512e2159..1ffe476e5 — routes 3 FFI capability-check helpers through CapabilityCeiling::contains, closing the OutletQueryAll asymmetry MEDIUM from 7512e2159. ZERO findings.
metadata:
  type: project
---

# Outlet PR-3 FFI ceiling-routing (7512e2159..1ffe476e5, feat/outlet-report-pr3) -- 2026-07-10 -- ZERO FINDINGS

Diff routes 3 FFI scoped-capability helpers through shared `CapabilityCeiling::contains` (roles.rs:722) instead of hand-rolled match arms:
- py_check_scoped_capability (scp-ffi/src/context.rs:1861)
- check_scoped_capability_inner (scp-ffi/napi/src/context.rs:5035)
- sandbox_check_capability (scp-ffi/uniffi/src/bridge.rs:8133)

**THIS DIFF RESOLVES the MEDIUM I filed in [[outlet-pr3-origin-kind-saga-7512e2159]]** (the 3 helpers missed the OutletQueryAll⊇OutletQuery arm). Now single-source-of-truth via CapabilityCeiling — structural drift prevention.

REGRESSION-SAFE (verified line-by-line): old arms were exact-match + `OutletCall(_)⇐OutletCallAll`. `contains` preserves BOTH verbatim + adds `OutletQuery(_)⇐OutletQueryAll` (the intended symmetry, widens only within under-granted query family). Non-outlet caps (Custom/roles/media/etc.) hit exact-match fall-through in both old+new = bit-identical. OutletQuery/OutletCall are the ONLY 2 parameterized enum variants → contains cannot leak any other family.

FAIL-CLOSED intact: malformed `required` → None → `return false`; malformed `granted` → filter_map(Capability::new) drops BEFORE ceiling build (reduces allowed = fail-closed dir); strict parser (roles.rs:273) rejects bad outlet suffixes to None not Custom. contains final arm = false.

DISJOINTNESS: contains uses early `return self.capabilities.contains(&OutletQueryAll/CallAll)` inside each `if let` → query required never consults CallAll & vice versa. Wildcards themselves non-parameterized (exact-only). §5.4.2 query≠call by construction.

PARITY: all 3 helpers semantically identical (PyO3 only omits module-scoped `use HashSet`).

TEST scoped_capability_check_honors_both_wildcard_families_fail_closed (context.rs:8363) asserts exact/call:*⊇/query:*⊇/cross-family-deny-both-dirs/no-match-deny/malformed-deny via real PyO3 entry. Ran: 1 passed.

Rename check_outlet_invoke→check_outlet_call (app_sandbox.rs:551) clean — 0 stale callers across crates/+bindings/, gate body untouched. caveats.rs change = doc-only (§7.3.8 value-caveat unwired, no live divergence, mint emits no value-caveats).
