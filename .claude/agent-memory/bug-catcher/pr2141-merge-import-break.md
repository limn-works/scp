---
name: pr2141-merge-import-break
description: PR #2141 merge (fix/sdk-coverage-fail-closed-and-parity + origin/main) left scp.py importing a class main deleted from economy.py — whole Python SDK unimportable
metadata:
  type: project
---

# PR #2141 merge-conflict mis-resolution — Python SDK unimportable (BLOCKER)

At merge HEAD `e78795e90` (merge commit `3e8a29707`, parents feature `5d118e1a2` + main `bc446456`):
`bindings/python/scp_sdk/scp.py:58` = `from scp_sdk.economy import PaymentReceiptVerificationResult`
but `economy.py` at HEAD does NOT define that class. → `import scp_sdk` raises ImportError
(`__init__.py:154` → `scp.py:58`). ALL Python tests fail at collection; whole SDK dead.

**Root cause (co-dependent files split across merge sides):**
- Feature parent `5d118e1a2`: economy.py DEFINES class (1), scp.py IMPORTS it (1). Consistent.
- Main parent `bc446456`: economy.py DROPS class (0), scp.py DROPS import (0) — main refactored
  `verify_payment_receipts` to return plain `dict[str, Any]`. Consistent.
- Merge kept FEATURE scp.py (import + typed method `economy_verify_payment_receipts` -> PaymentReceiptVerificationResult)
  but MAIN economy.py (no class). Opposite sides → break.

**Fix (follow main-side decision):** delete scp.py:58 import; change return annotation
scp.py:2173 `-> PaymentReceiptVerificationResult` to `-> dict[str, Any]` (matches the actual
`return json.loads(raw)` runtime value + economy.py free fn); fix docstring at 2187. `dict[str,Any]`
+ `Any` + `from __future__ import annotations` all already present in scp.py.

**LESSON:** on any big merge, `python3.12 -c "import scp_sdk"` is a 1-line smoke test that catches
this entire class instantly. A clean coverage-script pass (exit 0) does NOT imply the SDK imports.
The committed matrix/alias fixes were correct; this break was orthogonal and NOT flagged by any gate.

## UPDATE @ HEAD bc3d88eef (re-review 2026-07-16)
- Import break above RESOLVED: no `PaymentReceiptVerificationResult` anywhere; scp.py economy_verify_payment_receipts returns `dict[str,Any]` via `json.loads(raw)`. Both scp.py+trust.py parse clean. Gate PASS (0 errors, 235 ops), 23/23 coverage tests pass, TS `bun run check` clean.
- **NEW BLOCKER (formatting):** `scripts/check-sdk-coverage.py:1217-1219` has THREE blank lines between `_extract_python_symbols` return and `def _extract_typescript_symbols`. `ruff format --check .` (ci.yml:654, repo-root, covers scripts/, no root ruff config/exclude) rejects it → python-lint job RED. Proven version-independent: origin/main version "already formatted" under ruff 0.15.4, PR version "would reformat" with the ONLY diff being 3→2 blank lines (universal black/ruff rule). Fix: delete one blank line.
- CONSIDER: economy_verify_payment_receipts docstring says each per-receipt dict has receipt_id/ok/valid/result, but Err entries (verification_results_to_json receipt.rs:198-201) carry only {ok:false, error} — `entry["valid"]` KeyErrors on a failed receipt. Doc overstates the per-entry contract.
- **LESSON2:** on a merged branch, `ruff format --check .` (or `--diff <file>`) is the fast CI-parity check; a hand-added blank line in an enforcement SCRIPT (not bindings/python) still breaks the root-level python-lint job. Compare against `git show origin/main:<file>` to separate PR-introduced format diffs from local ruff-version skew (other unchanged scripts showed skew noise; the target file did not).
