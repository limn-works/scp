---
name: outlet-pr3-caveat-deferral-1ffe476e5
description: §7.3.8 value-caveat deferral annotation on feat/outlet-report-pr3 — SHIP, 0 findings; resolves the §7.3.8 MODERATE from the 7512e2159 reconcile entry
metadata:
  type: project
---

# outlet PR-3 §7.3.8 value-caveat deferral annotation @ 1ffe476e5 (feat/outlet-report-pr3, 2026-07-10) — SHIP, 0 findings

Focus diff `7512e2159..1ffe476e5` (commit 1ffe476e5). RESOLVES the §7.3.8 MODERATE flagged in [[outlet_pr3_reconcile_7512e2159]] (ITEM3: §7.3.8 lacked the deferral marker siblings use). Annotation now added — verdict SHIP.

**What changed:** annotates §7.3.8 of `.docs/specs/07-trust-validation-and-capabilities.md`. Reframes caveat enforcement "three points → four points", splits LIVE `origin_kind` family (Step 7b per-edge attenuation, Step 7c leaf/terminus stem-consistency, Step 11b time-box) from DEFERRED value-caveat family (post-input checks in `invoke_outlet` + `CaveatCounterStore`). Adds deferral markers to the post-input bullet AND the `CaveatCounterStore` paragraph. Also fixes `caveats.rs:~793` comment that referenced a phantom `enforce_caveat_invocation` fn.

**All 4 verify points PASS (every claim checked vs code):**
- LIVE steps REAL in `crates/scp-protocol/src/crypto/ucan/validate.rs`: `verify_attenuation`/narrow (~1698, 7b), `verify_leaf_outlet_stem_consistency` (807/1154, 7c), `verify_caveat_time_box` (880-917→CaveatTimeBoxViolation, 11b).
- `CaveatCounterStore` ABSENT this branch (grep = only the spec-ref comment). `check_invocation_local` DEFINED+tested @caveats.rs:811 but ZERO production callers (only tests 4206-4300) = unwired, matches annotation. `enforce_caveat_invocation` = zero matches anywhere (phantom fn the old comment referenced — correctly removed).
- "NO LIVE DIVERGENCE" TRUE + structurally provable: BOTH mint paths emit only origin_kind. `build_root_caveats` (mint.rs:277) "never emits populated caveat set", returns None. `build_delegated_caveats` (mint.rs:235) = `InvocationCaveats{origin_kind: inherited, ..parent_effective}` — only origin_kind set, value fields inherit from parent_effective=empty() for root → no in-circulation token can carry a value-caveat. Stronger than siblings (names the mechanism).
- NO over-correction: reference `origin/feat/outlet-redesign` FULLY implements CaveatCounterStore (scp-protocol+scp-runtime+all 4 FFI bridges) + counter-backed enforcement + get_caveat_counter reads → value-caveat model IS decided end-state, PR-3 = legit slice. Annotation preserves complete design prose, only stamps impl status.

**Convention match:** uses §5.4.3 idiom ("deferred… executes live"; @05-contexts.md:293) + §5.15.8 idiom ("spec leads here… not yet wired… no live divergence"; @05-contexts.md:1839) verbatim, plus structural proof. No stranded "three points" ref remains.

**Artifact-flow:** COMPLIANT one-way. Spec leads code with honest impl-status qualifier = opposite of phantom provenance; before the change caveats.rs cited nonexistent fn, after both spec+code honest. VERDICT ALIGNED / SHIP / 0 findings.
