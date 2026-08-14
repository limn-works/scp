---
name: pr1874-coverage-gate-honest-naming
description: PR #1874 check-sdk-coverage.py reached convergent+honest fail-closed form; APPROVED from simplifier axis
metadata:
  type: project
---

PR #1874 (`fix/sdk-coverage-fail-closed`, HEAD f7ec3a784) — `scripts/check-sdk-coverage.py` final convergence round. APPROVED, no BLOCKER.

Resolution of the long-running fail-closed-gate concern (see [[project_sdk_coverage_failclosed_converged]] and the MEMORY.md "Fail-closed gate soundness" note).

**What's now true (reference shape for fail-closed name-existence gates):**
- Matcher is positive closed form: exact `ALIASES` membership OR exact auto-generated DOMAIN-PREFIXED candidate. No suffix/substring/bare-name candidate. Test 9 mutation-guards re-adding a bare candidate.
- Gate is HONEST: it verifies a symbol OF THE EXPECTED NAME exists, NOT that it implements the op (aliases map many matrix ops to one shared dispatcher e.g. governance execute_* -> executeGovernanceAction). All 4 locations say name-existence: module docstring (~L4-13), `_check_operation_in_sdk` docstring (~L1458), ALIASES header (~L92-94), and `.docs/lessons/coverage-gates-must-fail-closed.md`. The old "implementing symbol"/"corresponding code" overclaim is gone.
- ALIASES header (~L96-105) explains WHY bare-named/sub-domain-prefixed ops (scpid_*, identity_remove, relay_start_in_memory) need explicit aliases + "Do NOT simplify by deleting these — re-opens a fail-closed gap."
- Defensive guards (shape check, non-dict exemption guards, per-file extractor try/except, floor guard, all-exempted guard) are each fail-closed-only and each covered by exactly one negative self-test (17 tests, all green). Proportionate, not gold-plated.

**Why:** prior rounds kept re-spelling a suffix-matcher/escape-hatch bypass; this round closes it AND corrects the dishonest "implements the operation" claim.

**How to apply:** treat this as the canonical convergent fail-closed gate. Replacing the hand-maintained ALIASES table with generated binding manifests is a known SEPARATE follow-up — do NOT block #1874 on it; the table is verified green by the gate + self-tests.
