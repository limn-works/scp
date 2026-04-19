#!/usr/bin/env python3
"""Enforce that every top-level ``export (async) function`` in the
TypeScript SDK that routes through the process-wide default bridge
calls ``deprecatedDefaultInstance(<name>)`` at the top of its body.

Provenance: simplifier review of #1549 Phase 4 PR 1 (ADR-048), which
flagged inline ``deprecatedDefaultInstance("…")`` calls at the top of
every free function as a "forgot-to-add-the-line" footgun. We picked the
lightweight enforcement path (this gate) over a higher-order function
refactor to avoid touching dozens of call sites and potentially breaking
the exported SDK shape; this script ensures no new free function in a
deprecation-bearing module slips through without the call.

Files in :data:`SKIP_FILES` export free functions that intentionally do
NOT route through the default bridge — pure helpers, static class
members, or re-exports. Keep the list tiny; most free functions in the
SDK DO route through the default bridge.
"""

from __future__ import annotations

import pathlib
import re
import sys

# Resolve against the repo root (two levels up from scripts/) so the
# script works regardless of the caller's CWD.
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "bindings" / "typescript" / "src"

# Files allowed to skip the check because their free functions are pure
# helpers (no default-bridge routing).
SKIP_FILES: frozenset[str] = frozenset(
    {
        # Index / re-export.
        "index.ts",
        # Pure JSON / error helpers — no bridge calls.
        "errors.ts",
        # Pure synchronous validators + builder helpers (no FFI).
        "types.ts",
        # Pure context-param helpers; any FFI-backed func that lands
        # here later must pull in `deprecatedDefaultInstance` and be
        # removed from this allowlist.
        "event-log.ts",
        # Class-based APIs only (Identity.create, etc.) — deprecation
        # happens on each static method, not on free functions.
        "identity.ts",
        # Server lifecycle — caller constructs a Relay/Node explicitly
        # and owns its state; no default-bridge routing.
        "server.ts",
        # Storage helper for prefix math; no bridge calls.
        "storage/wasm-sqlite.ts",
        # Transport helpers operate on a passed-in TransportManager.
        "transport.ts",
        # Internal utilities.
        "internal/bridge.ts",
        "internal/deprecation.ts",
        "internal/json-utils.ts",
        "internal/native.ts",
        "internal/wasm.ts",
        # SCP class itself — the class's constructor and static
        # factories have their own deprecation path; free-function
        # checks don't apply.
        "scp.ts",
    }
)

EXPORT_FUNCTION_RE = re.compile(
    r"^export (?:async )?function ([A-Za-z_][A-Za-z0-9_]*)\s*\("
)
DEPRECATION_CALL = "deprecatedDefaultInstance("
# Markers that indicate a function body routes through the default
# bridge. If *none* of these appear in the function body, the function
# is a pure helper (validator, builder, JSON mapper) and doesn't need
# the deprecation call — the check skips it.
DEFAULT_BRIDGE_MARKERS = ("getBridge(", "getBridgeSync(")
# Window of lines to search for the deprecation call / bridge markers
# after a function declaration. 80 lines is comfortably longer than any
# current function body in the SDK.
SEARCH_WINDOW = 80


def _extract_body(lines: list[str], start_idx: int) -> str:
    """Return the function body starting at ``start_idx`` up to the
    matching closing brace (or ``SEARCH_WINDOW`` lines, whichever is
    shorter). Simple brace counting — good enough for the current SDK
    surface; if a function nests template literals with unbalanced
    braces we'll still catch the first ~80 lines which contain the
    relevant routing calls.
    """
    depth = 0
    started = False
    collected: list[str] = []
    for line in lines[start_idx : start_idx + SEARCH_WINDOW]:
        collected.append(line)
        for ch in line:
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
                if started and depth == 0:
                    return "\n".join(collected)
    return "\n".join(collected)


def check_file(path: pathlib.Path) -> list[str]:
    """Return a list of ``"file:lineno: message"`` strings for violations."""
    violations: list[str] = []
    text = path.read_text(encoding="utf-8").splitlines(keepends=False)
    for idx, line in enumerate(text):
        match = EXPORT_FUNCTION_RE.match(line)
        if not match:
            continue
        name = match.group(1)
        # Test-only underscored hooks don't need deprecation.
        if name.startswith("_"):
            continue
        body = _extract_body(text, idx)
        # Skip pure helpers — those that don't call through the default
        # bridge at all. If the body never touches `getBridge()` /
        # `getBridgeSync()`, there's no default-instance routing and
        # the deprecation warning would be misleading.
        if not any(marker in body for marker in DEFAULT_BRIDGE_MARKERS):
            continue
        if DEPRECATION_CALL not in body:
            violations.append(
                f"{path}:{idx + 1}: `export function {name}` routes "
                f"through the default bridge but is missing "
                f'`deprecatedDefaultInstance("{name}")` at the top of '
                "its body — add the call, or add the file to SKIP_FILES "
                "if this function intentionally does not route through "
                "the default bridge."
            )
    return violations


def main() -> int:
    if not SRC_DIR.is_dir():
        print(
            f"FAIL: {SRC_DIR} does not exist — run from the repo root.",
            file=sys.stderr,
        )
        return 2
    all_violations: list[str] = []
    for path in sorted(SRC_DIR.rglob("*.ts")):
        rel = path.relative_to(SRC_DIR).as_posix()
        if rel in SKIP_FILES:
            continue
        # Skip .d.ts declarations — no bodies.
        if path.name.endswith(".d.ts"):
            continue
        all_violations.extend(check_file(path))
    if all_violations:
        for msg in all_violations:
            print(msg, file=sys.stderr)
        print(
            "\nFAIL: one or more free functions in the TypeScript SDK "
            'are missing `deprecatedDefaultInstance(<name>)` at the top '
            "of their body. Add the call, or — if the function is a "
            "pure helper that does NOT route through the default bridge "
            "— add its file to SKIP_FILES in "
            "`scripts/check-ts-deprecation-calls.py`.",
            file=sys.stderr,
        )
        return 1
    print(
        "check-ts-deprecation-calls.py: all free functions call "
        "deprecatedDefaultInstance()"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
