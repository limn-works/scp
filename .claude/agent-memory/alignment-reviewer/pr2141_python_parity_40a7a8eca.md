---
name: pr2141-python-parity-40a7a8eca
description: PR #2141 clean-pass @ 40a7a8eca — Python typed-error parity completion (outlets + 5 identity), ALIGNED, 1 CONSIDER (Python non-convergence untracked)
metadata:
  type: project
---

# PR #2141 clean-pass @ 40a7a8eca (fix/sdk-coverage-fail-closed-and-parity, /tmp/scp-review-r25, 2026-07-16) — ALIGNED; 1 CONSIDER

Delta since my prior review (28623a226) = ONLY 2 commits, 4 files: errors.py (__all__), outlets.py, scp.py, test_outlets.py. trust.py/scp.ts/sketch.md/runtime.rs/check-sdk-coverage.py UNCHANGED since 28623a226 (already ALIGNED).

**Why:** completes Python typed-error parity to match TS. 95bf99be4 swaps outlets.py `_translate_bridge_error`→`_coded_bridge_error` (4 sites) + wraps 5 identity key-mutation methods (rotate_key/add_agent_key/rotate_agent_key/remove_agent_key/migrate) whose TS counterparts got error-mapping via getBridge in 28623a226. 40a7a8eca repoints test_outlets.py (prior commit broke pytest collection by deleting imported symbol).

**How to apply:** all 5 review questions ALIGNED:
1. Private-symbol exclusion = 5 sites (check-sdk-coverage.py:1145,1154,1170,1200,1211): excludes `_`-prefixed from AVAILABLE symbol set → ALIASES referencing a private helper FAIL the gate (fail-closed, matches PR intent + ADR-059 closed-allowlist). Gate PASS 235 ops/0 err; self-test 23 pass.
2. 13 `_coded_bridge_error(exc)` call sites in scp.py (verified). `_coded_bridge_error` = strict superset of deleted `_translate_bridge_error` (same BRIDGE_ERROR_MAP class-name dispatch + adds [SCP-CAT-NNNN] code extraction via anchored _SCP_CODE_RE). SINGLE mapping chokepoint = satisfies ADR-059 (phase-2.md:1996) Decision 4 (ADR forbids scattered STRING-CLASSIFICATION ladders, not scattered try/catch delegating to one function). 5 identity methods SYMMETRIC with TS (both route errors — Python _coded_bridge_error, TS getBridge Proxy at scp.ts:812-869).
3. eventLogQuery excluded from getBridge migration = CORRECT: Bridge.eventLogQuery (bridge.ts:413) expects `filter: EventFilter | undefined` (object); SDK public eventLogQuery(handle, filterJson?: string) takes JSON STRING → genuine shape mismatch. Still wrapped in explicit try/catch→mapBridgeError (scp.ts:2451) so error-mapping parity PRESERVED; only the routing mechanism differs. Spec doesn't dictate routing.
4. ucan-validate lesson restructure ACCURATE vs ADR-059: intrinsic-mode skips step-6 grant-match + read-only nonce check_replay (ADR Decision 2a, phase-2.md:1992), closed-allowlist>open-denylist (ADR Rationale "Closed, not open"), distinct error codes CTX-2023 vs PERM-3001 (Decision 4), self-consistency-NOT-authorization, bare `*` rejected at URI-parse (Decision 2a). Historical sections properly marked superseded-by-ADR-059.
5. No unmet ACs. errors.py __all__ drop of `_coded_bridge_error` = self-consistent with gate's private-symbol exclusion (direct imports unaffected; only `import *` affected, no consumer uses it). Tests: 64 outlet/parity pass + 23 gate self-test pass. test_outlets dropped "OutletError" parametrize case (dead BRIDGE_ERROR_MAP entry, bridge never raises native OutletError) — negligible, offset by 3 new anchor/code-extraction assertions.

**CONSIDER (carried from 28623a226, now reinforced):** Python per-method try/catch wrapping is the non-convergent pattern CLAUDE.md warns of. TS has #2157 (OPEN) to apply wrapBridgeErrors to `this.#native` at construction (convergent by construction). Python grew 5→13 per-method wraps with NO equivalent tracking issue. NOT a fail-open (unwrapped Python methods still throw raw native exc carrying [SCP-CODE] in message, just not typed as specific SDK exception) — DX/convergence gap, not correctness. Suggest: file Python analog of #2157 or add a __getattr__/decorator chokepoint on _native.

VERDICT: no BLOCKER/SHOULD-FIX. LGTM.
