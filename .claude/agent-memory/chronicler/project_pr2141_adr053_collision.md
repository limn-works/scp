---
name: project-pr2141-adr053-collision
description: PR #2141 @d2c056ea4 introduces an ADR-053 number collision + stranded substrate-isolation correction; and a TOOL/OUTLET category error in a lesson
metadata:
  type: project
---

Chronicler review of PR #2141 (`fix/sdk-coverage-fail-closed-and-parity`) at HEAD `d2c056ea4`, 2026-08-01 (worktree `/tmp/scp-2141`, detached HEAD).

**Finding 1 — CRITICAL: ADR-053 number collision + stranded correction.**
The branch adds `.docs/adrs/ADR-053-pre-rotation-custody-substrate-isolation.md`. On `origin/main` that decision was RENUMBERED to **ADR-054**, and ADR-053 now belongs to "Node Is Infrastructure; Participation Is an SDK Client" (`.docs/adrs/phase-2.md:1906`, referenced by `.docs/prds/self-host-binary.json`). Consequences of merging as-is:
- Number collision: two decisions both claim ADR-053.
- Content duplicate: `ADR-053-*custody*` ≈ `ADR-054-*custody*` (same title, near-identical body).
- **Stranded fix:** the PR's stated correction — substrate isolation "structurally encouraged … foreign-implementation obligation" instead of "enforced by the type system" — exists ONLY in the stale ADR-053 file (line ~99). Canonical `ADR-054-…:109` STILL says "enforced by the type system." Branch did NOT touch ADR-054 (`git diff origin/main..HEAD` empty for that file). Main's ADR-054 is also strictly newer (has 2026-07-14 residence amendment + ADR-055 WASM-removal amendment + core-trait-mapping refinement that the 053 file lacks).
- Correct resolution: DELETE the ADR-053 custody file; apply the "structurally encouraged" correction to ADR-054:109; repoint lesson `custody-substrate-isolation-holds-at-rest-not-in-transit.md` (cites "ADR-053" and links the stale path at lines 3/10/81) to ADR-054; update PR body ("ADR-053 corrected" → ADR-054).

**Finding 2 — lesson factual error.**
`.docs/lessons/test-error-code-fixtures-must-pass-conformance-gate.md` lists recognized categories as `…TRANS|TOOL|VALID…`. `scripts/check-error-codes.sh` actually recognizes **OUTLET** (range 6000-6999), NOT TOOL (case stmt line 58; regex lines 203/267). The lesson also omits the `SCP-TEST` sentinel (line 79, allowlisted alongside `SCP-UNKNOWN`).

**Otherwise accurate:** the three d2c056ea4 error lessons (wrap-error-sibling-methods-together, test-error-code-fixtures, python-bridge-error-message-strip-double-bracket) match impl. Minor: strip lesson snippet shows `_CODE_RE.match(raw_msg)` but real code is `_SCP_CODE_RE.search(raw_msg)` (regex anchored `^\s*`, so functionally equal). errors.py `__str__` = `f"[{self.code}] {self.message}"` (line 52) confirms the double-bracket rationale. `identity_remove_if_present` is wrapped with `_coded_bridge_error` (scp.py). Commit messages conventional and accurate (d2c056ea4 = exactly 3 lesson files).
