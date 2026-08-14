---
name: sdk-coverage-failclosed-parity-44eaf5d05
description: Final review of fix/sdk-coverage-fail-closed-and-parity @ 44eaf5d05 — all prior findings resolved, gate passes, verdict ALIGNED 0 blocking
metadata:
  type: project
---

# fix/sdk-coverage-fail-closed-and-parity @ 44eaf5d05 (2026-06-20) — ALIGNED, 0 blocking

8 commits over base 0c8f0b065. Builds on prior rounds (f6caeb5dd ALIGNED+2 cites, 27d82895e ALIGNED+1 LOW). Last 4 commits (58cf17955, 6ca818220, 57399e64f, 44eaf5d05) resolved EVERY prior finding:
- §9.3 trust miscitation (trust.ts:92/:392 + types.ts:785) → ALL now §7.2–7.5. The types.ts:785 LOW leftover the 27d82895e commit missed is FIXED here. (Remaining §9.3 in types.ts:49/:69 = Consequence rules/ADR-017 governance — a DIFFERENT legit §9.3, pre-existing.)
- identityMigrate HIGH (NEW-DID semantics): identity-lifecycle.test.ts:176 now asserts `migrated.did).not.toBe(identity.did)`; doc cites "§3.2.1 (Identity Key migration)"; step-4b fabrication removed.
- #1531 issue-ref gone from trust.ts.
- assertTestHookAllowed (scp.ts:2726): hardened negative-denylist → positive allowlist (NODE_ENV=test|development|BUN_TEST). Closed-allowlist = aligns with CLAUDE.md anti-non-convergence guidance. Good defense-in-depth (red-hat RED-PR5-001/007). __setNativeForTests/replaceNativeWithMock REMOVED (black-hat BLACK-PR5-003 footgun).
- coverage gate 44eaf5d05: all `.text.decode()` → `(node.text or b"").decode()` (tree-sitter types .text Optional[bytes]) — correct null-safety at all walker sites. coverage_exemptions non-empty validation (check-sdk-coverage.py:1106-1110) = closed-allowlist tightening.
- scp.py __exit__/__aexit__: `del exc_type, exc, tb` satisfies Pyright reportUnusedVariable while keeping proper dunder param names — correct.

## Verified clean on branch worktree
- Gate: EXIT 0, 221 ops, unmatched-true=0, false-w/o-exempt=0, all-exempted=0, coverage-exempt=1 (kotlin addRelay generated-file). Fail-closed teeth intact.
- Python ruff: clean. TS biome lint: clean (54 files). tsc --noEmit + test tsconfig: clean.
- TS tests: 60 pass / 4 fail — the 4 fails are ENVIRONMENTAL (Real-NAPI describe; addon present but built WITHOUT allow_in_memory_custody → identityCreate("in_memory") throws SCP-IDENT-1008). NOT this diff's defect; CI builds with custody feature.
- MLS provider.rs doc edits: stale "ContextManager mutex"→ADR-049 per-context actor (real in codebase); removed "default impl/override this" (no crypto trait exists — grep empty, inherent methods). Accurate.
- ADR-051 (Proposed): substrate-isolation gap diagnosis still accurate vs §9.7.4.1 §3-§6; nothing in PR implements it; correct artifact-flow (ADR before code).

## LOW (informational, non-blocking, CARRIED)
1. Real-NAPI test probe (identity-lifecycle.test.ts:120-127) gates on METHOD PRESENCE (`typeof identityRotateKey === "function"`) but not on custody-creation success. When addon is built sans allow_in_memory_custody, tests run-then-fail instead of skipping. Pre-existing harness pattern, not introduced. Robustness nit: probe could attempt identityCreate("in_memory") in the try and gate on it.
2. ADR-051 coverage_exemptions cites build-generated (non-git-tracked) Kotlin path; true post-`cargo build -p scp-ffi-uniffi` but unverifiable from source. (Same LOW as 8c0713499; gate's all-exempted check requires ≥1 verified anchor so this exemption can't stand alone.)

## Reusable
- Positive-allowlist test-hook gate (NODE_ENV in {test,development} or BUN_TEST) is the canonical misuse-resistant shape — undefined/staging/production all blocked. Matches the closed-allowlist principle; cite as good example.
- When a multi-round PR's last commits are lint/test-hygiene only, RUN the actual CI lint+typecheck+gate on the branch worktree — the commits exist BECAUSE of tsc/ruff/pyright diagnostics; verifying they're now clean is the review.
