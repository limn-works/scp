#!/usr/bin/env python3.12
"""Detect falsy-vs-`is not None` bugs on Optional collections in scp_sdk.

Background (H14 / M16): the Python SDK historically used `if x else None`
or `x or []` / `x or {}` on parameters that are typed `Optional[list[...]]`
or `Optional[dict[...]]`. That collapses an explicit empty collection to
`None`, which destroys the semantic distinction the spec preserves at the
FFI boundary (e.g. an empty `trusted_dids` list is "auto-reject everyone",
not "no policy"). The correct form is always `if x is not None`.

This check parses every `bindings/python/scp_sdk/**/*.py` file with the
`ast` module and flags:

  1. `IfExp` nodes whose `test` is a bare `Name` (e.g. `x if x else None`).
  2. `BoolOp(Or, [Name, List|Dict literal])` nodes (e.g. `x or []`).
  3. `If` statements whose `test` is a bare `Name` referenced as a list/dict
     local in the surrounding function -- not handled here (too noisy
     without type info); the IfExp / BoolOp forms catch the bridge-call
     sites that matter.

A site is exempt if the line (or the line immediately above the start of
the relevant expression) contains the marker `# falsy-ok:`. Use that
marker only when the bridge call is observationally identical for empty
and `None` AND a comment explaining why is included.

Exit code 0 = clean. Exit code 1 = at least one violation. The script
prints a one-line diagnostic per violation in the format:

    <file>:<line>:<col>: <pattern> -- use `is not None` (or add `# falsy-ok:` with rationale)

Run from the repo root:

    python3.12 scripts/check-python-falsy-optionals.py
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SDK_ROOT = REPO_ROOT / "bindings" / "python" / "scp_sdk"
EXEMPT_MARKER = "# falsy-ok:"


EXEMPT_LOOKBACK = 10


def line_or_prev_has_marker(source_lines: list[str], lineno: int) -> bool:
    """Return True if `# falsy-ok:` appears on or near the given line.

    `lineno` is 1-indexed (matching `ast` line numbers). The lookback
    window is `EXEMPT_LOOKBACK` lines above the flagged line so callers
    can prefix a short rationale block (or attach the marker just above
    a multi-line call expression where the AST flags an inner argument
    line). The marker is also accepted on the flagged line itself.

    The check intentionally does NOT require the marker to live in a
    contiguous comment block: the AST often flags an inner expression
    (e.g. inside a multi-line call), and the natural place to put the
    rationale is above the call statement, not above the inner line.
    """
    idx = lineno - 1
    n = len(source_lines)
    if not (0 <= idx < n):
        return False
    if EXEMPT_MARKER in source_lines[idx]:
        return True
    start = max(0, idx - EXEMPT_LOOKBACK)
    return any(EXEMPT_MARKER in source_lines[i] for i in range(start, idx))


class FalsyOptionalChecker(ast.NodeVisitor):
    """Visit a single module and collect violations."""

    def __init__(self, path: Path, source_lines: list[str]) -> None:
        self.path = path
        self.source_lines = source_lines
        self.violations: list[tuple[int, int, str]] = []

    def visit_IfExp(self, node: ast.IfExp) -> None:  # noqa: N802 -- AST API
        # Pattern: <body> if <name> else <orelse>
        # The bug shape is `<expr-using-x> if x else <fallback>` where `x`
        # is a bare Name. `if x is not None else <fallback>` is the fix.
        if isinstance(node.test, ast.Name) and not line_or_prev_has_marker(
            self.source_lines, node.lineno
        ):
            self.violations.append(
                (
                    node.lineno,
                    node.col_offset,
                    f"falsy IfExp on bare name `{node.test.id}`",
                )
            )
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:  # noqa: N802 -- AST API
        # Pattern: `x or []` / `x or {}` / `x or ()` -- a Name on the LHS
        # or'd with an empty literal collection.
        if (
            isinstance(node.op, ast.Or)
            and len(node.values) == 2
            and isinstance(node.values[0], ast.Name)
            and self._is_empty_collection_literal(node.values[1])
            and not line_or_prev_has_marker(self.source_lines, node.lineno)
        ):
            self.violations.append(
                (
                    node.lineno,
                    node.col_offset,
                    f"falsy `or` on bare name `{node.values[0].id}`",
                )
            )
        self.generic_visit(node)

    @staticmethod
    def _is_empty_collection_literal(node: ast.expr) -> bool:
        if isinstance(node, ast.List | ast.Tuple | ast.Set) and not node.elts:
            return True
        if isinstance(node, ast.Dict) and not node.keys:
            return True
        return False


def check_file(path: Path) -> list[str]:
    source = path.read_text(encoding="utf-8")
    source_lines = source.splitlines()
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        return [f"{path}:{exc.lineno}:{exc.offset}: parse error: {exc.msg}"]
    checker = FalsyOptionalChecker(path, source_lines)
    checker.visit(tree)
    rel = path.relative_to(REPO_ROOT)
    return [
        f"{rel}:{line}:{col}: {msg} -- "
        f"use `is not None` (or add `{EXEMPT_MARKER} <rationale>` if empty and absent are equivalent)"
        for (line, col, msg) in checker.violations
    ]


def main() -> int:
    if not SDK_ROOT.exists():
        print(f"error: {SDK_ROOT} does not exist", file=sys.stderr)
        return 2

    all_violations: list[str] = []
    files = sorted(SDK_ROOT.rglob("*.py"))
    if not files:
        print(f"error: no Python files found under {SDK_ROOT}", file=sys.stderr)
        return 2

    for path in files:
        all_violations.extend(check_file(path))

    if all_violations:
        print(
            "Falsy-vs-`is not None` violations on Optional collections "
            "(see scripts/check-python-falsy-optionals.py header):",
            file=sys.stderr,
        )
        for v in all_violations:
            print(f"  {v}", file=sys.stderr)
        print(
            f"\n{len(all_violations)} violation(s). "
            "See the `evaluate_invitation` method in bindings/python/scp_sdk/scp.py "
            "for the canonical fix.",
            file=sys.stderr,
        )
        return 1

    print(f"OK: scanned {len(files)} files under {SDK_ROOT.relative_to(REPO_ROOT)}; no violations.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
