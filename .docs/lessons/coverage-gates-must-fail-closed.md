# Coverage Gates Must Fail Closed, and Must Not Match Symbols by Suffix/Substring

**Date:** 2026-06-20
**Source:** branch `fix/sdk-coverage-fail-closed-and-parity` — rewrite of `scripts/check-sdk-coverage.py`

## The Rule

A capability/coverage gate that only **warns** when a matrix says "supported" but no
implementing symbol can be found is not enforcement — it is a suggestion. Real parity
gaps survive a warning. A coverage gate MUST exit non-zero unless, for every cell the
matrix marks `true`, it finds **either** a statically verified implementing symbol **or**
a reasoned, provenance-citing exemption.

A coverage gate MUST NOT match symbols by suffix or substring. Loose matching admits
fabricated names: a cell can claim an operation that does not exist and still "pass"
because some unrelated symbol happens to end with the same suffix.

## Context

The original `check-sdk-coverage.py` had two latent failures that let cross-SDK parity
gaps (TypeScript identity-lifecycle methods, Python economy/discovery functions) ship
undetected:

1. **Warn-only on unmatched `true` cells.** A matrix cell marked `true` for an SDK that
   had no implementing symbol produced a WARNING and a passing exit code. This is exactly
   why TS parity gaps survived — the gate "passed" while the capability was absent.

2. **Suffix/substring symbol matching.** The extractor matched a matrix operation against
   any SDK symbol sharing a suffix. ~23 fabricated/non-existent operation names passed the
   gate via suffix collision with real-but-unrelated symbols.

## The Fix

- **Fail-closed flip:** a `true` cell with no verified symbol **and** no
  `coverage_exemptions[sdk]` entry → ERROR, exit 1 (was WARN/pass).
- **Exact symbol verification:** removed suffix/substring matching. A match requires a
  verified symbol from the `ALIASES` whitelist (extracted via tree-sitter, not raw text).
- **`coverage_exemptions` escape hatch:** a per-SDK keyed map carrying a reason for cells
  that are genuinely present but not statically matchable (e.g. Kotlin `addRelay` lives
  only in the generated, non-git-tracked UniFFI binding whose backtick-quoted,
  `@Throws`-annotated override methods the tree-sitter-kotlin grammar won't surface as
  clean `function_declaration` nodes). Every exemption must cite durable provenance
  (ADR / spec § / generated-file path + verification command).
- **All-exempted guard:** at least one SDK per operation must be statically verified — an
  operation cannot be exempted across the board (that would re-open the warn-only hole).
- **Gate self-tests:** `scripts/test_check_sdk_coverage.py` negative-tests the gate itself
  (strip an exemption OR fabricate a `true` op → both must exit 1). CI runs the self-tests
  **before** the gate, so the extractor's own null-safety is guarded.
- `scripts/check-sdk-coverage.py` added to the CLAUDE.md "NEVER modify enforcement files"
  list — it is now load-bearing.

## The Lesson

When you add or rewrite a coverage/capability gate, design it closed by construction:

1. Default verdict is FAIL. A cell passes only by producing a verified symbol or a
   provenance-citing exemption. Never let "couldn't find it" resolve to "probably fine."
2. Match exactly (whitelist of permitted symbols), never by suffix/substring — loose
   matching lets fabricated capability claims slip through.
3. Give the gate negative self-tests and run them in CI before the gate, so a regression
   in the extractor can't silently weaken the gate to warn-only.
4. Exemptions are not free passes: each must cite an ADR, spec section, or a generated
   artifact path plus the command to verify it. An all-SDK exemption is itself a finding.

See also `.docs/lessons/enforcement-wiring-gap.md` (enforcement helpers must be *called*,
not just defined) and `.docs/lessons/ast-gate-checks-definition-not-name-resolution.md`
(positive whitelist over open denylist).
