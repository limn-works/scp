---
name: nttest-brace-state-machine
description: Wave-18 NTTEST classifier-free brace-depth reframe in check-class-s-fail-closed.sh — review findings, robust vs gaps
metadata:
  type: project
---

# check-class-s-fail-closed.sh — NTTEST wave-18 brace-depth reframe

Reviewed commit d21e699fd (branch chore/fuzz-pin-nightly worktree xctx-saga), diff 5d9993af4..d21e699fd.

**What it does:** Replaced item-kind enumerator `is_column0_item_start` with classifier-free
`is_column0_code_line` + a brace-depth state machine tracking the trailing `#[cfg(test)] mod {`
body. After the module's `}` returns depth to base, ANY column-0 non-blank/non-comment/non-attr
line fires NTTEST (un-scanned vacuum). Closed the real black-hat gap: path-qualified item macro
`foo::bar! {}` (the `::` broke the old single-ident macro regex).

**Verdict: correct and robust on cargo-fmt-clean code.** Verified via extracted-harness fuzzing:
- multi-line string/raw-string braces in module body → carried correctly (no premature close)
- nested `mod inner {}` → does NOT close outer module early
- multi-line attr before/after gate, between two modules → handled
- pending_test_gate survives multi-line attr carry
- degenerate single-line `mod x {}` → handled
- attributed/multi-line-attributed production resume → NTTEST fires
- fixture 46 (path macro) is non-vacuous (old regex genuinely missed it)

**Two LOW edge cases (pre-existing, non-regressing, fmt-defended — NOT bugs in practice):**
- `} fn prod() {...}` (module close + production on ONE line): `in_test_module` branch counts
  depth→0, sets after_test_module, unconditional `next` discards rest of line → no NTTEST, prod
  unscanned. Pre-wave-18 `is_column0_item_start` ALSO missed this (line starts with `}`).
- `)] fn prod() {...}` (multi-line attr closer + production on ONE line): attr-carry `next`
  discards rest of line. Same class.
- Both require non-rustfmt'd code; grep of real tree shows ZERO occurrences (rustfmt puts `}`/`)]`
  on own line). Fail-closed direction is over-alert, not hide. Only worth a one-line fix if hardening.

**One LOW false-positive:** a MULTI-LINE `#[cfg(all(test,\n ...))]` gate is not recognized by
`is_column0_reopening_test_gate` (needs `#[cfg(all(test` on one physical line) → module body
scanned as production (over-alert HIT). rustfmt keeps such gates single-line; pre-existing.

**Harness technique:** truncate script before the `if [[ ! -d "$SCAN_DIR" ]]` auto-run guard,
append `true`, `source` it, call `scan_file <abs-path>` directly. MUST use absolute fixture paths
(awk CWD differs). NO_CLASS_S_SELFTEST=1 not needed when sourcing truncated lib.
