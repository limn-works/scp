---
name: sdk-coverage-failclosed-parity-b27ef7bff
description: ALIGNED verdict for fix/sdk-coverage-fail-closed-and-parity at b27ef7bff (clean base, fail-closed gate + §9.12 citations + PERM-3030 + ADR-051)
metadata:
  type: project
---

# fix/sdk-coverage-fail-closed-and-parity @ b27ef7bff (2026-06-21) — ALIGNED, APPROVED

Branch HEAD `b27ef7bff`. merge-base == origin/main == `1f1ea7cd2`, 0 behind / 55 ahead — CLEAN base, NO phantom-deletion trap (contrast prior ad51633f3 stale-base illusion). 75 files +5073/-563. This is the same multi-round work reviewed at 27d82895e/44eaf5d05/ed14e6c77/0219e5c12 etc., now at a fresh commit; reviewed independently and fresh.

**Verdict: APPROVED. 0 blocking, 0 material. 1 non-blocking pre-existing note.**

6 changes all verified:
1. **Fail-closed gate** (check-sdk-coverage.py): removed suffix/substring matching (let ~23 fabricated names pass via verb collision); domain-prefix-ONLY candidate gen (no bare op_name/camel/pascal); ALIASES = positive CLOSED whitelist (sound direction per non-convergent-enforcement tenet); 3 new error modes — missing-SDK-key, unexpected-cell-value, all-exempted-no-verified. all-exempted check is the anti-bypass guard (prevents coverage_exemptions becoming unbounded prose bypass — requires ≥1 statically-verified SDK). Gate RAN: 223 ops, 0 errors, 1 documented coverage-exempt, EXIT 0. Self-tests 11/11, ruff clean. CI wires gate self-tests before the gate (ci.yml).
2. **§9.12 citation fixes** all 4 bridges: migration DidRotationEvent distribution was wrongly cited `§3.2.1 step 4b` (phantom — §3.2.1 has no such step about rotation events). Corrected to `§9.12, ADR-003 §4b`. VERIFIED against spec: 03-identity.md:28 "Identity Key migration... creates a new DID" cites §9.12/ADR-003§4b; §3.2.1 = DID-PRESERVING custody swap. Distinction is correct in both directions.
3. **PERM-3030 re-raise** Python+TS trust evaluators before UCAN classify. VERIFIED: ADR-048 §4 defines SCP-PERM-3030 = handle-affinity (cross-instance handle misuse) "caught at boundary rather than corrupting silently." Absorbing it into a false all-False trust verdict would mask the programming bug. Python comment cites TS trust.ts:461 (accurate). Parity confirmed.
4. **DiscoveryResult TypedDict** narrowed to Literal kind/layer (§22.7/§22.11.3), matches TS ResolutionLayer union. Python ruff clean.
5. **ADR-051** Proposed/Phase6, no impl. Grounded in real code (PyO3 identity.rs:819-824, UniFFI bridge.rs) + real spec §9.7.4.1 §3-§6. Separate PreRotationCustodyProvider (not new methods on KeyCustodyProvider) structurally enforces §3 isolation. Respects no-migration-prerelease/no-tracking-issue/artifact-flow. Open Qs escalated for human review.
6. **4 lesson files** (prompt said 2; actually 4: coverage-gates-fail-closed, identity-migration-9.12-not-3.2.1, mock-test-must-not-invert, fromhandle-must-surface-fields). All accurate, all cross-refs resolve.

Bonus verified: BehavioralRecord contexts_participated=1 → default 0 (REMOVES fabricated value — data not computable at this layer; aligns "never fabricate"). MLS provider.rs = doc-only, strips stale "default impl/Production providers MUST override" trait-language (now inherent methods, no crypto-trait) + ContextManager→actor (ADR-049). test-guard.ts = fail-closed positive allowlist (NODE_ENV test|dev|BUN_TEST), frozen-at-load, Object.hasOwn anti-prototype-pollution. Only enforcement file touched = check-sdk-coverage.py itself (ADDS assertions = legitimate per policy). No pipeline_wiring/ffi_conformance/ratchet/baseline/allowlist touched. Matrix changes honesty-improving (rotate_key exemption text corrected — false value pre-existing; Bridge register TS true→false tightening; add_relay_url kotlin coverage_exemption = real tree-sitter-kotlin UniFFI-backtick grammar gap). Rust scp-runtime builds clean, TS tsc clean (main+test).

NON-BLOCKING NOTE: pre-existing `#1549,ADR-048` (17×) and `#632,spec §9.12` (3× in internal/wasm.ts + native.ts) issue-refs in TS source — appear as diff `+` only because surrounding lines were re-touched; NOT introduced by this branch (all present on origin/main). Violate no-issue-refs-in-code convention but out of authored scope; future cleanup candidate.
