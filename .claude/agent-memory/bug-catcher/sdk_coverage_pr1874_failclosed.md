# PR #1874 — check-sdk-coverage.py fail-closed hardening review (f7ec3a784)

Branch fix/sdk-coverage-fail-closed. Makes the SDK capability-coverage gate fail-closed:
top-level shape guard (non-dict matrix / non-list `capabilities`), non-dict
`exemptions`/`coverage_exemptions` guards, unexpected-cell-value guard, missing-SDK-key
guard, floor guard (total_ops==0 → exit 1), extractor wrapped in try/except per-file,
`_node_text` decodes errors="replace". Adds scripts/test_check_sdk_coverage.py (17 tests).

## Verified GOOD
- All 17 tests pass; gate exits 0 on the real matrix; CI runs test suite before gate.
- Floor guard intact: empty `capabilities: []` → floor guard exit 1; missing key → shape
  guard exit 1 (shape runs before floor, both fail closed).
- `_node_text` errors="replace" is behavior-identical for valid UTF-8 (`['hello']`);
  binary/invalid source yields reduced/empty symbol set, no crash → fail-closed.
- Negative tests assert exit 1 AND a specific error phrase (mutation-robust). Bare-name
  regression test (test 9) and unmatched-true (test 2) are well-isolated.

## LOW finding (reported, not blocking)
Shape guard validates ONLY the top-level (matrix is dict, `capabilities` is list). It does
NOT validate elements: a non-dict element of `capabilities`, a non-list `operations`, or a
non-dict `op` all raise an uncaught `AttributeError` ("'str'/'int' object has no attribute
'get'") with a full Python traceback. Exit code is still 1 (Python default on uncaught
exception) so NOT fail-open — but contradicts the PR's stated criterion "no remaining
uncaught traceback for a malformed matrix" + the docstring's "never an uncaught traceback".
Lines: main() loop at ~1553 `for domain_entry in matrix.get("capabilities", [])` →
`domain_entry.get(...)`; `domain_entry.get("operations", [])` → iteration; `op.get(...)`.
Fix: `isinstance` guards on domain_entry/operations/op emitting clean ERROR + errors+=1
(or skip), same pattern as the exemptions guards already added.
