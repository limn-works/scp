#!/usr/bin/env python3.12
"""CI gate: a bridge never blocks a host-runtime thread on an actor reply
while holding that runtime's lock (ADR-049 Decision 7a, "Host threads").

A context actor may be waiting on the host for a custody callback, so a
bridge thread that holds the host's lock (the Python GIL, the JS thread)
while it blocks on that actor deadlocks the two.

---------------------------------------------------------------------------
RULES
---------------------------------------------------------------------------
Both rules flag every `.block_on(...)` method call in PRODUCTION code, and
every macro invocation whose token stream carries `.block_on`. A site is
allowed only when it carries the directive

    // ci-allow: bridge-block-on: <reason>

on the line that holds the `.block_on` call, on the call expression's first
or last line, or on the line directly above the call. The reason is required
and states why the site cannot deadlock: it waits on no context actor, or
its caller already released the host lock. Reviewers check each reason
against its call.

  PyO3 (`crates/scp-ffi/src/`): every site outside `actor_wait.rs` fails
  unless it carries the directive. `actor_wait::block_on_released` is the one
  wait that releases the GIL.

  napi (`crates/scp-ffi/napi/src/`): every site needs the directive, and a
  per-file count ratchet over the production sites
  (`ratchet/bridge-block-on-count.json`) lets the counts only fall, so a new
  sync `#[napi]` actor wait cannot land silently. napi exposes every
  production actor wait as `async`.

Test code is skipped: files under a `tests/` directory, `mod` items gated on
`cfg(test)` or named `tests`, and functions carrying `#[test]`,
`#[tokio::test]` or a `cfg(test)` gate.

The tree-sitter scanner and its `cfg(test)` parsing are those of
`scripts/check-block-in-place.py`, which excludes `crates/scp-ffi/**`, so
the two gates do not overlap.

---------------------------------------------------------------------------
USAGE
---------------------------------------------------------------------------
    python3.12 scripts/check-bridge-block-on.py              # real scan
    python3.12 scripts/check-bridge-block-on.py --self-test  # fixture
    python3.12 scripts/check-bridge-block-on.py --list       # every site
    python3.12 scripts/check-bridge-block-on.py --check-file FILE
        # scan FILE under the PyO3 rule and fail on any violation

Exit codes: 0 pass, 1 violation or self-test failure, 2 invocation error.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCANNER_PATH = REPO_ROOT / "scripts" / "check-block-in-place.py"
RATCHET_FILE = REPO_ROOT / "ratchet" / "bridge-block-on-count.json"
FIXTURE_FILE = REPO_ROOT / "scripts" / "tests" / "bridge-block-on-fixture.rs"

PYO3_ROOT = "crates/scp-ffi/src/"
PYO3_HELPER = "crates/scp-ffi/src/actor_wait.rs"
NAPI_ROOT = "crates/scp-ffi/napi/src/"

DIRECTIVE_RE = re.compile(r"//\s*ci-allow:\s*bridge-block-on(?::\s*(.*?))?\s*$")


def _load_scanner():
    spec = importlib.util.spec_from_file_location("check_block_in_place", SCANNER_PATH)
    if spec is None or spec.loader is None:
        sys.stderr.write(f"error: cannot load {SCANNER_PATH}\n")
        sys.exit(2)
    module = importlib.util.module_from_spec(spec)
    # `@dataclass` resolves its class's module through `sys.modules`.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SCANNER = _load_scanner()


@dataclass
class Site:
    """One `.block_on` site in production code."""

    file: str
    line: int
    snippet: str
    reason: str | None  # the directive's reason, None when absent


def _line(source_lines: list[str], line_1: int) -> str:
    if 1 <= line_1 <= len(source_lines):
        return source_lines[line_1 - 1]
    return ""


def _fn_is_test(node, source: bytes) -> bool:
    """True when a function_item carries `#[test]`, `#[tokio::test]`, or a
    `cfg` attribute that gates on `test`."""
    sibling = node.prev_sibling
    while sibling is not None:
        if sibling.type == "attribute_item":
            text = SCANNER.node_text(sibling, source)
            body = re.sub(r"\s+", "", text)
            if re.match(r"#\[(?:[A-Za-z_]+::)*test(?:\(.*\))?\]$", body):
                return True
            for m in re.finditer(r"cfg(?:_attr)?\((.*)\)", text, flags=re.DOTALL):
                if SCANNER._cfg_gates_on_test(m.group(1)):
                    return True
            sibling = sibling.prev_sibling
            continue
        if sibling.type in ("line_comment", "block_comment"):
            sibling = sibling.prev_sibling
            continue
        break
    return False


def _macro_carries_block_on(node, source: bytes) -> bool:
    return re.search(r"\.\s*block_on\b", SCANNER.node_text(node, source)) is not None


def scan(path: Path, rel: str) -> tuple[list[Site], list[str]]:
    """Return the production `.block_on` sites in one file, and the
    malformed-directive errors."""
    source = path.read_bytes()
    source_lines = source.decode("utf-8", errors="replace").splitlines()
    tree = SCANNER.PARSER.parse(source)
    sites: list[Site] = []
    errors: list[str] = []

    def directive_for(node, anchor_line: int) -> str | None:
        start = node.start_point[0] + 1
        end = node.end_point[0] + 1
        found: str | None = None
        for line_1 in sorted({anchor_line, start, end, start - 1, anchor_line - 1}):
            m = DIRECTIVE_RE.search(_line(source_lines, line_1))
            if m is None:
                continue
            reason = (m.group(1) or "").strip()
            if not reason:
                errors.append(f"{rel}:{line_1}: `ci-allow: bridge-block-on` without a reason")
                continue
            found = reason
        return found

    def record(node, anchor_line: int) -> None:
        snippet = SCANNER.node_text(node, source).splitlines()[0].strip()[:90]
        sites.append(Site(rel, anchor_line, snippet, directive_for(node, anchor_line)))

    def walk(node, in_test: bool) -> None:
        test = in_test
        if node.type == "mod_item":
            name_node = node.child_by_field_name("name")
            name = SCANNER.node_text(name_node, source) if name_node is not None else ""
            if SCANNER.has_test_cfg_attribute(node, source) or name == "tests":
                test = True
        elif node.type == "function_item" and _fn_is_test(node, source):
            test = True
        if not test:
            if node.type == "call_expression" and SCANNER._call_is_block_on(node, source):
                field = node.child_by_field_name("function").child_by_field_name("field")
                record(node, field.start_point[0] + 1)
            elif node.type == "macro_invocation" and _macro_carries_block_on(node, source):
                record(node, node.start_point[0] + 1)
                # The token tree is not parsed as calls, so stop here.
                return
        for child in node.children:
            walk(child, test)

    walk(tree.root_node, False)
    return sites, errors


def production_files(root: str) -> list[str]:
    base = REPO_ROOT / root
    out = []
    for path in sorted(base.rglob("*.rs")):
        rel = path.relative_to(REPO_ROOT).as_posix()
        if "/tests/" in rel:
            continue
        out.append(rel)
    return out


def load_ratchet() -> dict[str, int]:
    try:
        data = json.loads(RATCHET_FILE.read_text())
    except FileNotFoundError:
        sys.stderr.write(f"error: ratchet file {RATCHET_FILE} missing\n")
        sys.exit(2)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"error: ratchet file {RATCHET_FILE} is not JSON: {e}\n")
        sys.exit(2)
    files = data.get("files")
    if not isinstance(files, dict):
        sys.stderr.write(f"error: {RATCHET_FILE} has no `files` map\n")
        sys.exit(2)
    return {str(k): int(v) for k, v in files.items()}


def check_pyo3_sites(sites: list[Site]) -> list[str]:
    return [
        f"{s.file}:{s.line}: `.block_on` outside `actor_wait::block_on_released` "
        f"without `// ci-allow: bridge-block-on: <reason>`: {s.snippet}"
        for s in sites
        if s.reason is None
    ]


def real_scan(list_all: bool) -> int:
    failures: list[str] = []
    pyo3_count = 0
    for rel in production_files(PYO3_ROOT):
        if rel == PYO3_HELPER:
            continue
        sites, errors = scan(REPO_ROOT / rel, rel)
        failures.extend(errors)
        failures.extend(check_pyo3_sites(sites))
        pyo3_count += len(sites)
        if list_all:
            for s in sites:
                print(f"pyo3 {s.file}:{s.line}: {s.reason or '<no directive>'}")

    ratchet = load_ratchet()
    napi_counts: dict[str, int] = {}
    for rel in production_files(NAPI_ROOT):
        sites, errors = scan(REPO_ROOT / rel, rel)
        failures.extend(errors)
        if sites:
            napi_counts[rel] = len(sites)
        for s in sites:
            if s.reason is None:
                failures.append(
                    f"{s.file}:{s.line}: napi `.block_on` without "
                    f"`// ci-allow: bridge-block-on: <reason>`: {s.snippet}"
                )
            if list_all:
                print(f"napi {s.file}:{s.line}: {s.reason or '<no directive>'}")
    for rel, count in sorted(napi_counts.items()):
        budget = ratchet.get(rel, 0)
        if count > budget:
            failures.append(
                f"{rel}: {count} production `.block_on` sites, ratchet allows {budget}"
            )
        elif count < budget:
            print(f"note: {rel}: {count} sites, ratchet {budget} can drop")
    for rel, budget in sorted(ratchet.items()):
        if rel not in napi_counts and budget > 0:
            print(f"note: {rel}: 0 sites, ratchet {budget} can drop")

    if failures:
        for f in failures:
            print(f"FAIL {f}")
        print(f"check-bridge-block-on: {len(failures)} violation(s)")
        return 1
    print(
        f"check-bridge-block-on: OK ({pyo3_count} PyO3 and "
        f"{sum(napi_counts.values())} napi production sites, each with a reason)"
    )
    return 0


def check_file(path: Path, quiet: bool = False) -> int:
    sites, errors = scan(path, path.as_posix())
    failures = errors + check_pyo3_sites(sites)
    if not quiet:
        for f in failures:
            print(f"FAIL {f}")
    return 1 if failures else 0


def self_test() -> int:
    """The fixture names each function `flag_*` (must be flagged), `allow_*`
    (directive with a reason), `test_*` (test code, never seen), or
    `bad_directive_*` (directive without a reason: an error)."""
    sites, errors = scan(FIXTURE_FILE, "fixture")
    source = FIXTURE_FILE.read_bytes()
    tree = SCANNER.PARSER.parse(source)
    ranges: dict[str, tuple[int, int]] = {}

    def collect(node) -> None:
        if node.type == "function_item":
            name = SCANNER.node_text(node.child_by_field_name("name"), source)
            ranges[name] = (node.start_point[0] + 1, node.end_point[0] + 1)
        for child in node.children:
            collect(child)

    collect(tree.root_node)

    def sites_in(name: str) -> list[Site]:
        lo, hi = ranges[name]
        return [s for s in sites if lo <= s.line <= hi]

    problems: list[str] = []
    for name in ranges:
        found = sites_in(name)
        violations = [s for s in found if s.reason is None]
        if name.startswith("flag_") and not violations:
            problems.append(f"{name}: a bare `.block_on` was not flagged")
        if name.startswith("allow_") and (not found or violations):
            problems.append(f"{name}: a directive with a reason was not honoured")
        if name.startswith("test_") and found:
            problems.append(f"{name}: test code was scanned")
        if name.startswith("bad_directive_"):
            lo, hi = ranges[name]
            if not any(lo - 1 <= int(e.split(":")[1]) <= hi for e in errors):
                problems.append(f"{name}: a directive without a reason was accepted")
    expected = {"flag_", "allow_", "test_", "bad_directive_"}
    seen = {p for p in expected for n in ranges if n.startswith(p)}
    for prefix in expected - seen:
        problems.append(f"fixture has no `{prefix}*` case")
    if check_file(FIXTURE_FILE, quiet=True) == 0:
        problems.append("--check-file passed a fixture that holds violations")
    if problems:
        for p in problems:
            print(f"SELF-TEST FAIL {p}")
        return 1
    print(f"check-bridge-block-on self-test: OK ({len(ranges)} fixture functions)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--check-file", type=Path)
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.check_file is not None:
        return check_file(args.check_file)
    return real_scan(args.list)


if __name__ == "__main__":
    sys.exit(main())
