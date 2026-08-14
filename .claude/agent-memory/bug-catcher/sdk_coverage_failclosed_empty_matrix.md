---
name: sdk-coverage-failclosed-empty-matrix
description: check-sdk-coverage.py fails OPEN on empty/missing capabilities array (returns PASS) — gap in the fail-closed gate
metadata:
  type: project
---

# check-sdk-coverage.py empty-matrix fail-open (MEDIUM)

On branch `fix/sdk-coverage-fail-closed-and-parity` (614f0eb17), the coverage gate's
`main()` iterates `matrix.get("capabilities", [])`. If that array is empty or the
top-level `capabilities` key is missing (valid JSON, truncated/corrupted/renamed key),
the loop never runs: `total_ops=0, errors=0` → prints "PASS" and `return 0`.

**Why:** Verified empirically by monkeypatching MATRIX_PATH to `{"capabilities":[]}` and
`{}` — both return 0 (PASS). Real matrix has 223 ops / 21 domains.

**Fix:** add a floor guard after the loop, e.g. `if total_ops == 0: print FAIL; return 1`
(or a sane minimum like `< 200`). A coverage gate that passes on an empty matrix defeats
its own purpose.

**How to apply:** Flag whenever reviewing this gate or similar "iterate-and-count-errors"
validators — the zero-input case is the classic fail-open hole. The AST-extraction path is
already fail-closed (empty symbol set → unmatched_true errors; missing grammar → import
sys.exit(1)); only the matrix-iteration path has the hole.

Related: [[sdk-coverage-broadcast-open-key-gap]]
