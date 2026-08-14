---
name: pr2141-sdk-error-mapping
description: PR #2141 typed-error parity — coverage-gate change is convergent (NOT blocker); real finding is 14× repeated Python import+try/except boilerplate + wrap-asymmetry (14/183 py, 5/194 ts)
metadata:
  type: project
---

PR #2141 (`fix/sdk-coverage-fail-closed-and-parity`) simplifier review.

**No BLOCKER.** The `check-sdk-coverage.py` change is tiny (adds private-symbol
`_`-prefix exclusion for TS/Python parity) — convergent, bounded, consistent with
the prior "check-sdk-coverage fail-closed audited clean" verdict. `mapBridgeError`
(TS) and `_coded_bridge_error` (Python) anchor the `^\s*\[SCP-...\]` code regex to
start — sound, not a growing denylist. Python side is a genuine DRY win: two
duplicate helpers (`_translate_bridge_error` in outlets.py, `_coded_bridge_error`
in trust.py) collapsed to one in `errors.py`. scp.ts migrates ~10 methods off ugly
`as unknown as {...}` casts onto typed `getBridge()` — net simplification.

**Real findings (MINOR, recurring):**
- `scp.py`: 14 methods each carry an identical local `from scp_sdk.errors import
  _coded_bridge_error` + 3-line try/except. errors.py imports only `re` (no cycle);
  scp.py already imports ScpError from it at top level — so the local imports are
  pure boilerplate. Hoist to the existing top-level import.
- **Wrap-asymmetry:** only 14 of 183 `asyncio.to_thread` calls (py) and 5 of 194
  `this.#native.` calls (ts) are wrapped with error-mapping. The typed-error mapping
  is applied to a subset, not uniformly. That inconsistency is the real smell — a
  small `_native_call(fn, *args)` helper would make "wrap everything" cheap+uniform.
  Route to completionist/alignment for the coverage decision.

**Why:** SDK wrapper methods are thin delegators; the per-method error-translation
boilerplate is the dominant repetition in these files.
**How to apply:** On future SDK-wrapper parity PRs, expect this boilerplate; prefer
a single wrapper helper over per-method try/except, and check wrap-coverage is
uniform rather than spot-applied.
