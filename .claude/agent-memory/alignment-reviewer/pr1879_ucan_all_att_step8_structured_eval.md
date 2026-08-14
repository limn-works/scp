---
name: pr1879-ucan-all-att-step8-structured-eval
description: PR #1879 C2 of UCAN all-att ceiling stack — validate_ucan step 8 over ALL attestations + mint-time enforcement + side-effect-free evaluate_ucan; ALIGNED, 0 findings
metadata:
  type: project
---

PR #1879 `feat/ucan-all-att-and-structured-eval` @ 63dc89094, base origin/main, 2026-06-23. ALIGNED, ZERO findings.

**Stack position:** C2 of a 3-PR stack. C1 = spec clarification ALREADY MERGED (§7.2.1 step 8 = ceiling over ALL attestations; see [[pr1875_ucan_ceiling_all_attestations]]). C2 = THIS (core-only). C3 = future bridge/SDK PR wiring `evaluate_ucan` to an SDK trust signal.

**Scope (clean):** only `crates/scp-protocol/{context/roles.rs, crypto/ucan/capability.rs, crypto/ucan/validate.rs}` + runtime integration test + pipeline_wiring. ZERO FFI/SDK/bridge/enforcement-config files. Confirmed `git diff --name-only` has no ffi|bindings/|napi|wasm|uniffi|pyo3|sdk-capability hits.

**Q1 spec match — PASS.** validate.rs:607 step 8 = `verify_ceiling_compliance(&granted_caps, ctx.ceiling)?` (full parsed att set), placed at step 8 BEFORE nonce record at step 9 (line 611 `check_and_record`). Matches spec line 81 verbatim ("entire attestation set (att) is checked; a token carrying any out-of-ceiling attestation is rejected even if the invoked capability is itself within the ceiling"). Spec UNTOUCHED by this PR (already on main from C1).

**Q2 scope boundary — coherent atomic, NOT half-wired.** `evaluate_ucan` + `CapabilityValidation` have ZERO consumers outside validate.rs + integration test, NOT re-exported at crate root — deliberate C3 deferral. NOT a half-done violation because PR title + body + commit ALL explicitly frame "Core + tests only — no FFI bridge or SDK surface touched (that is a follow-up PR)" and list bridge encapsulation + ceiling-string normalization as "Noted follow-ups (out of scope)". Integration checklist's "core fn without FFI = half-done" only bites when COMPLETE is claimed; here it's staged.

**Q3 pipeline_wiring assertion — PASS.** New `ucan_step8_enforces_ceiling_over_all_att` (pipeline_wiring.rs): POSITIVE pin `fn_body_contains(validate_ucan, "verify_ceiling_compliance(&granted_caps,")` AND NEGATIVE forbid `fn_body_contains(validate_ucan, "verify_ceiling_compliance(std::slice::from_ref(required_capability)")`. Uses brace-matched `fn_body_contains` so scoped to the fn body not whole file. Ratchet 42→43 (expanding, allowed).

**Q4 mint-time consistency — PASS, REAL.** `validate_role_definition(&role_def, &state.ceiling)?` called BEFORE `mint_role_tokens` in BOTH `assign_role` (roles.rs ~1067) AND `system_assign_role` (~1136), before any state mutation. validate_role_definition (roles.rs:1270) iterates EVERY cap in the role → `CapabilityOutsideCeiling` on first out-of-ceiling = producer-side all-att counterpart. Matches spec line 68 "same all-attestations rule applies at mint time". Tests prove rejection on both paths w/ no partial state (no tokens, no member_capabilities, no assignments) using `new_unchecked` to simulate the bypassable path. Also scrubbed stale "Phase 2 stub ... SCP-024" doc on mint_role_tokens → now "complete design decision, not a stub" (matches spec "complete — not deferred").

**Q5 over-reach — NONE.** capability.rs change is test-ONLY (multi-colon custom URI fail-closed unit test); `verify_ceiling_compliance` logic unchanged (already iterated all caps).

**evaluate_ucan side-effect-free — verified.** Takes `&ValidationContext` (shared ref → cannot call `&mut self` `record`); uses read-only `check_replay` at step 9; reuses same helpers (parse_granted_caps/verify_root_issuer/verify_audience/verify_ceiling_compliance) as the gate so they can't drift. Nonce-isolation regression test asserts evaluate-twice keeps nonce vs validate-twice → NonceReused.

Integration tests are genuine behavioral (not string-search games): the "ceiling_violation_does_not_consume_nonce" test rejects then proves a fresh valid token reusing the same nonce still succeeds = nonce never burned (step 8 before step 9, the security-critical ordering).

LESSON: for a staged stack PR, the "core fn without FFI export = half-done" rule does NOT fire when the PR explicitly frames the fn as staged for a named follow-up; check PR body/commit framing before flagging an orphaned-core finding.
