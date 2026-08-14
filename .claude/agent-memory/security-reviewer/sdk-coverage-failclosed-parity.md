---
name: sdk-coverage-failclosed-parity
description: Security review of fix/sdk-coverage-fail-closed-and-parity TS SDK branch (trust.ts, test-guard, bridge.ts, check-sdk-coverage.py)
metadata:
  type: project
---

# Branch fix/sdk-coverage-fail-closed-and-parity — security review (2026-06-20)

Reviewed: trust.ts, internal/test-guard.ts, internal/bridge.ts, scp.ts, scripts/check-sdk-coverage.py.

**Why:** SDK coverage gate fail-closed + TS/py parity (identity lifecycle + payment receipts) + UCAN error classification.

**How to apply:** Verdict CLEAN with LOW observations. Branch is ~19 commits behind main (alignment-reviewer note) — REBASE before merge; the given `git diff origin/main..HEAD` renders main's newer work as phantom deletions.

Key security improvements (positive):
- test-guard.ts: env decision FROZEN at module load (IIFE), runtime process.env mutation cannot flip. Uses Object.hasOwn (prototype-pollution resistant). Fail-CLOSED: missing process/env -> false.
- assertTestEnvironment replaces old assertTestHookAllowed which was fail-OPEN (only blocked NODE_ENV==="production"; staging/unset/typo all passed). New gate: only test|development|BUN_TEST pass. Strict improvement for __constructScpWithNativeForTests + __setBridgeForTests (supply-chain bridge-swap seams).
- trust.ts evaluateTrust: optimistic-then-classify; re-throws non-UCAN ([SCP-PERM]) errors and handle-affinity (SCP-PERM-3030) instead of swallowing. eventLogQuery only swallows [SCP-CTX] errors. Good fail-closed-ish: on classify, all 6 fields derived from __PASSED_BEFORE set (failing+later fields = false).
- check-sdk-coverage.py: fail-closed (true w/o symbol + no coverage_exemption = ERROR); removed suffix/substring matching (prevented ~23 fabricated names passing); all-exempted guard requires >=1 statically-verified SDK.

LOW observations (not blockers):
- trust.ts __classifyUcanError uses startsWith on attacker-influenceable? NO — error text is from Rust UcanError Display, not user JSON. Prefix order: SIGNATURE_CHAIN before TOKEN_PARSE so "malformed token: DID not found" routes to signatures correctly. Sound.
- "development" treated as test env in isTestEnvironment — intentional (matches dev affordance) but means dev builds expose test seams. Acceptable per design; seams throw in prod.
