---
name: pr2141-delta-d2c056ea4
description: PR #2141 alignment delta review at d2c056ea4 — prefix-strip fix + identity_remove_if_present parity + error-code fixture corrections; ALIGNED
metadata:
  type: project
---

# PR #2141 delta @ d2c056ea4 (fix/sdk-coverage-fail-closed-and-parity, /tmp/scp-2141, 2026-08-01) — ALIGNED

Delta since prior ALIGNED review 40a7a8eca = 3 code commits (76bbeabfc, e9adb42a2) + docs (d2c056ea4). ONLY touches: errors.py, scp.py, 2 py tests, 1 ts test, 3 lesson docs. **Matrix + check-sdk-coverage.py UNCHANGED since last review** (confirmed via git diff --name-only) → questions on ALIASES philosophy/matrix correctness carry prior ALIGNED verdicts; coverage gate re-run GREEN (0 errors).

Three real fixes, all gate-verified:
1. **_coded_bridge_error prefix-strip** (errors.py:327-334): now strips leading `[SCP-xxx-nnn] ` via `raw_msg[match.end():].lstrip()` before constructing SDK exc, so ScpError.__str__ (which re-prepends `f"[{code}]"`) no longer DOUBLES the bracket. Real bug: previously str(err)=`[SCP-CTX-2023] [SCP-CTX-2023] context error...`. .code preserved, round-trips cleanly. isinstance(ScpError) early-return unaffected; saga-terminal path (args-positional) is separate, unaffected.
2. **identity_remove_if_present wrapped** (scp.py:904) with _coded_bridge_error — completes parity with sibling identity_remove (the "wrap-sibling-methods-together" lesson). test_real_ffi now expects typed SDK ValidationError not raw _scp_core.ValidationError.
3. **TS fixture error-code corrections** (scp-typed-errors.test.ts): GOV-6001→GOV-11001, OUTLET-4002→OUTLET-6002, WEIRD-9999→UNKNOWN-9999. Old codes were PREFIX/RANGE MISMATCHES (GOV-6001 sat in OUTLET band 6000-6999; OUTLET-4002 in CRYPTO band 4000-4999) + WEIRD non-canonical category. All 5 flagged by scripts/check-error-codes.sh (a real enforcement gate). Range table lives in error_codes.rs:11-32. **check-error-codes.sh now PASSES** (3386 occurrences). OUTLET_6002 has real const (error_codes.rs:652); GOV-11001 in-range (no dedicated const, but gate validates prefix↔band not const-existence — mock fixture only needs well-formed code for mapBridgeError prefix-dispatch).

Doc changes (already blessed prior passes): sdk-common.md PermissionError→UcanPermissionError rename (matches actual class name, applies anti-shadow rationale to TS too — TS imports UcanPermissionError confirmed); sketch.md withinCeiling struct expanded to real 6-field ADR-059 struct. Both downstream docs describing as-built typed surface — artifact-flow OK. 3 new lesson docs (evergreen learnings, allowed).

STANDING CONSIDER (carried, non-blocking, unchanged): Python per-method _coded_bridge_error wrapping is non-convergent (grew again: +identity_remove_if_present); TS convergent fix tracked #2157, Python NOT tracked. NOT fail-open (unmapped py methods still raise exc carrying [SCP-CODE]), NOT completeness-tenet violation. NOT the non-convergent-enforcement anti-pattern either — the 20+ PR passes each fixed a DISTINCT real defect (regex anchor, prefix strip, twin deletes, range fixes), not the same bypass respelled.
