#!/usr/bin/env python3.12
# ruff: noqa: E501
"""AST-based CI gate banning `block_in_place` / `.block_on(...)` in the
actor-refactor scope (ADR-049).

---------------------------------------------------------------------------
PREREQUISITES
---------------------------------------------------------------------------
    pip install tree-sitter tree-sitter-rust

Python 3.12+. Runs offline; no network access required.

---------------------------------------------------------------------------
WHAT THIS CHECKS
---------------------------------------------------------------------------
Parses every `.rs` file in scope to a tree-sitter AST and flags:

  (1) Call to `tokio::task::block_in_place` by ANY path — including
      aliased imports (`use tokio::task::block_in_place as bip; bip(...)`)
      and re-exported paths. Detection is structural: any identifier
      that resolves to `block_in_place` at a call site is flagged.

  (2) Method call `.block_on(...)` on any expression. We do NOT resolve
      types; approximation is "any `.block_on(...)` call". Callers opt
      out with an inline allow-list directive (see below).

  (3) `Runtime::new()` construction — commonly paired with `.block_on(...)`
      to build an ad-hoc sync bridge. Flagged the same way.

---------------------------------------------------------------------------
SCOPE
---------------------------------------------------------------------------
All `.rs` files under `crates/scp-*/src/` EXCEPT:

  - `crates/scp-runtime/src/crypto/mls/storage.rs` — OpenMLS upstream
    `StorageProvider` trait is sync; the adapter uses `spawn_blocking`
    per op but retains `block_in_place` at one shim boundary. Allowed
    wholesale.
  - `crates/scp-ffi/**` — PyO3 / UniFFI / NAPI sync bindings require a
    sync-async bridge at the FFI boundary. Whole directory excluded.

Within scope, test code is excluded via two mechanisms:

  - Files whose path contains `/tests/` (e.g.
    `crates/scp-runtime/src/context/manager/tests/messaging.rs`). Test
    submodules are allowed to use sync-in-async bridges freely — that is
    their job.
  - Per-item AST check: any call inside a `mod NAME { ... }` whose
    preceding attribute is `#[cfg(test)]`, or whose name is literally
    `tests`, is treated as test code and ignored.

---------------------------------------------------------------------------
INLINE ALLOW-LIST
---------------------------------------------------------------------------
A single call site may be allow-listed by placing the directive

    // ci-allow: block-on: <reason-text>

on the same source line as the offending call. Example:

    let doc = rt.block_on(fetch()); // ci-allow: block-on: HTTP/3 sync trait

The reason text is REQUIRED — an empty reason fails the check. The
reason is free-form; reviewers gate for correctness.

---------------------------------------------------------------------------
RATCHET
---------------------------------------------------------------------------
The actor-per-context refactor (ADR-049) deletes ~30 of these sites
across multiple commits. We cannot fail the build on the current count.
Instead, a per-crate baseline is kept in

    ratchet/block-in-place-count.json

The gate FAILS if any crate's count exceeds its baseline; it PASSES if
the count is equal or lower; a LOWER count is reported as
"ratchet can drop" (a future commit should tighten the baseline).

Ratchet baselines count ONLY sites that are NOT allow-listed — an
allow-listed site is silently ignored in both current and baseline
counts. This means the baseline decreases as work is completed, and a
new non-allow-listed site fails the gate immediately.

---------------------------------------------------------------------------
SELF-TEST
---------------------------------------------------------------------------
Run with `--self-test` to exercise the scanner against a fixture file
that contains every known bypass pattern. CI runs `--self-test` before
the real scan so the gate fails loudly if the scanner is weakened.

Fixture: `scripts/tests/block-in-place-fixture.rs`.

---------------------------------------------------------------------------
USAGE
---------------------------------------------------------------------------
    python3.12 scripts/check-block-in-place.py           # real scan
    python3.12 scripts/check-block-in-place.py --self-test
    python3.12 scripts/check-block-in-place.py --list    # list all hits

Exit codes:
    0  — no new violations beyond ratchet baseline
    1  — a crate exceeds its baseline, or an allow-list directive is
         missing a reason, or `--self-test` did not catch all fixtures
    2  — invocation error (missing baseline file, invalid JSON, etc.)

See ADR-049 for design context.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    import tree_sitter_rust as ts_rust
    from tree_sitter import Language, Parser
except ImportError:
    sys.stderr.write(
        "error: tree-sitter / tree-sitter-rust not installed.\n"
        "       pip install tree-sitter tree-sitter-rust\n"
    )
    sys.exit(2)

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
RATCHET_FILE = REPO_ROOT / "ratchet" / "block-in-place-count.json"
FIXTURE_FILE = REPO_ROOT / "scripts" / "tests" / "block-in-place-fixture.rs"

# Scope: `crates/scp-*/src/` except these exact paths / prefixes.
# Paths are relative to REPO_ROOT and use forward slashes on all platforms.
EXCLUDED_FILES = {
    "crates/scp-runtime/src/crypto/mls/storage.rs",
}
EXCLUDED_PREFIXES = (
    "crates/scp-ffi/",
)

# Directive: single-line inline allow-list.
#
# Match `// ci-allow: block-on: <reason>` anywhere on the line. We also
# accept the shorter form `// ci-allow: block-on` (no reason) only to
# detect and reject it — empty allow-lists are forbidden.
ALLOW_RE = re.compile(r"//\s*ci-allow:\s*block-on(?::\s*(.*))?\s*$")

# TTY coloring
if sys.stdout.isatty() and "NO_COLOR" not in os.environ:
    C_RED = "\033[31m"
    C_GREEN = "\033[32m"
    C_YELLOW = "\033[33m"
    C_DIM = "\033[2m"
    C_RESET = "\033[0m"
else:
    C_RED = C_GREEN = C_YELLOW = C_DIM = C_RESET = ""

# -----------------------------------------------------------------------------
# Parser setup
# -----------------------------------------------------------------------------

RUST_LANG = Language(ts_rust.language())
PARSER = Parser(RUST_LANG)


# -----------------------------------------------------------------------------
# Data types
# -----------------------------------------------------------------------------


@dataclass
class Hit:
    """One offending call site."""

    file: str  # repo-relative path
    line: int  # 1-indexed
    kind: str  # "block_in_place" | "block_on" | "runtime_new"
    snippet: str  # short code excerpt
    allow_reason: str | None  # non-None if allow-listed


# -----------------------------------------------------------------------------
# AST helpers
# -----------------------------------------------------------------------------


def has_test_cfg_attribute(node, source: bytes) -> bool:
    """True if the mod_item is preceded by `#[cfg(test)]`.

    Tree-sitter places attribute_item nodes as preceding siblings of the
    mod_item, not as children. Walk back past any intervening comments.
    """
    sibling = node.prev_sibling
    while sibling is not None:
        if sibling.type == "attribute_item":
            text = source[sibling.start_byte : sibling.end_byte].decode(
                "utf-8", errors="replace"
            )
            if "cfg(" in text and "test" in text:
                return True
            # Non-cfg attribute (e.g. #[allow]): keep walking back.
            sibling = sibling.prev_sibling
            continue
        if sibling.type in ("line_comment", "block_comment"):
            sibling = sibling.prev_sibling
            continue
        break
    return False


def node_text(node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _collect_aliased_block_in_place(root, source: bytes) -> set[str]:
    """Find `use tokio::task::block_in_place as alias;` imports.

    Returns the set of aliases. The real name is ALWAYS flagged — this
    set captures locally-bound shorter names that defeat a naive grep.
    """
    aliases: set[str] = set()

    def walk(node) -> None:
        if node.type == "use_declaration":
            txt = node_text(node, source)
            # Handle multiline and grouped imports by looking at the full
            # text. The grammar-correct way is to walk scoped_use_list
            # nodes, but string matching the trailing `as NAME` is robust
            # and simple.
            for m in re.finditer(
                r"(?:tokio::task::|task::|::)?block_in_place\s+as\s+([A-Za-z_][A-Za-z0-9_]*)",
                txt,
            ):
                aliases.add(m.group(1))
            # Also catch the "bare" form: `use tokio::task::block_in_place as X;`
            # which the regex above already covers.
        for c in node.children:
            walk(c)

    walk(root)
    return aliases


def _call_is_block_in_place(call_node, source: bytes, aliases: set[str]) -> bool:
    """True if `call_node` (a call_expression) invokes block_in_place."""
    fn = call_node.child_by_field_name("function")
    if fn is None:
        return False
    # Determine the "tail identifier" of the call's function. For
    # `tokio::task::block_in_place(...)` we want `block_in_place`.
    # For `bip(...)` we want `bip`.
    if fn.type == "scoped_identifier":
        name_node = fn.child_by_field_name("name")
        if name_node is not None:
            return node_text(name_node, source) == "block_in_place"
    if fn.type == "identifier":
        nm = node_text(fn, source)
        return nm == "block_in_place" or nm in aliases
    if fn.type == "field_expression":
        # e.g. `self.tokio.block_in_place(...)` — extremely rare, still catch.
        f = fn.child_by_field_name("field")
        if f is not None and node_text(f, source) == "block_in_place":
            return True
    return False


def _call_is_block_on(call_node, source: bytes) -> bool:
    """True if `call_node` is a `.block_on(...)` method call."""
    fn = call_node.child_by_field_name("function")
    if fn is None or fn.type != "field_expression":
        return False
    field = fn.child_by_field_name("field")
    if field is None:
        return False
    return node_text(field, source) == "block_on"


def _call_is_runtime_new(call_node, source: bytes) -> bool:
    """True if `call_node` is `Runtime::new(...)` or `tokio::runtime::Runtime::new(...)`."""
    fn = call_node.child_by_field_name("function")
    if fn is None:
        return False
    if fn.type != "scoped_identifier":
        return False
    name_node = fn.child_by_field_name("name")
    path_node = fn.child_by_field_name("path")
    if name_node is None or path_node is None:
        return False
    if node_text(name_node, source) != "new":
        return False
    path_txt = node_text(path_node, source).strip()
    # Accept either `Runtime::new` or `tokio::runtime::Runtime::new`.
    return path_txt.endswith("Runtime")


# -----------------------------------------------------------------------------
# Line extraction / allow-list
# -----------------------------------------------------------------------------


def _extract_line_text(source: bytes, line_1indexed: int) -> str:
    """Return the full source line at 1-indexed line number."""
    # Splitting bytes → str once and indexing is simpler than byte offsets.
    text = source.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if 1 <= line_1indexed <= len(lines):
        return lines[line_1indexed - 1]
    return ""


def _check_allow_directive(line_text: str) -> tuple[bool, str | None, str | None]:
    """Parse an inline allow-list directive.

    Returns (present, reason_or_none, error_or_none). `present` is True if
    the directive keyword appears. `reason` is non-empty if the directive
    carries a reason. `error` is non-None if the directive is malformed
    (present but empty reason).
    """
    m = ALLOW_RE.search(line_text)
    if m is None:
        return (False, None, None)
    reason = (m.group(1) or "").strip()
    if not reason:
        return (True, None, "allow-list directive present but reason is empty")
    return (True, reason, None)


# -----------------------------------------------------------------------------
# Per-file scan
# -----------------------------------------------------------------------------


def scan_file(rel_path: str) -> tuple[list[Hit], list[str]]:
    """Return (hits, errors) for one file.

    `hits` is the list of all call sites (both allow-listed and not).
    `errors` is non-empty when a malformed directive is found.
    """
    errors: list[str] = []
    hits: list[Hit] = []
    full_path = REPO_ROOT / rel_path
    source = full_path.read_bytes()
    tree = PARSER.parse(source)
    aliases = _collect_aliased_block_in_place(tree.root_node, source)

    def walk(node, in_test: bool) -> None:
        tctx = in_test
        if node.type == "mod_item":
            name_node = node.child_by_field_name("name")
            nm = node_text(name_node, source) if name_node is not None else ""
            if has_test_cfg_attribute(node, source) or nm == "tests":
                tctx = True

        if node.type == "call_expression" and not tctx:
            kind: str | None = None
            if _call_is_block_in_place(node, source, aliases):
                kind = "block_in_place"
            elif _call_is_block_on(node, source):
                kind = "block_on"
            elif _call_is_runtime_new(node, source):
                kind = "runtime_new"

            if kind is not None:
                line_1 = node.start_point[0] + 1
                snippet = node_text(node, source).splitlines()[0][:80]
                # Directive must be on the SAME source line as the call
                # site's START, not the opening paren. tree-sitter points
                # call_expression at the identifier.
                line_text = _extract_line_text(source, line_1)
                # For multiline calls the directive may live on any line
                # of the call expression. We accept it on the first or
                # last line of the call.
                last_line_1 = node.end_point[0] + 1
                last_line_text = (
                    _extract_line_text(source, last_line_1)
                    if last_line_1 != line_1
                    else ""
                )
                present1, reason1, err1 = _check_allow_directive(line_text)
                present2, reason2, err2 = _check_allow_directive(last_line_text)
                if err1:
                    errors.append(f"{rel_path}:{line_1}: {err1}")
                if err2:
                    errors.append(f"{rel_path}:{last_line_1}: {err2}")
                allow_reason = reason1 or reason2
                hits.append(
                    Hit(
                        file=rel_path,
                        line=line_1,
                        kind=kind,
                        snippet=snippet,
                        allow_reason=allow_reason if (present1 or present2) else None,
                    )
                )

        for c in node.children:
            walk(c, tctx)

    walk(tree.root_node, False)
    return (hits, errors)


# -----------------------------------------------------------------------------
# In-scope file enumeration
# -----------------------------------------------------------------------------


def in_scope_files() -> list[str]:
    """Enumerate every `.rs` file under `crates/scp-*/src/`, minus exclusions
    and minus test-path files.

    Paths returned are repo-relative with `/` separators.
    """
    out: list[str] = []
    crates_dir = REPO_ROOT / "crates"
    if not crates_dir.is_dir():
        return out
    for crate_name in sorted(os.listdir(crates_dir)):
        if not crate_name.startswith("scp-"):
            continue
        src_dir = crates_dir / crate_name / "src"
        if not src_dir.is_dir():
            continue
        for root, _, files in os.walk(src_dir):
            for fname in files:
                if not fname.endswith(".rs"):
                    continue
                abs_path = Path(root) / fname
                rel = abs_path.relative_to(REPO_ROOT).as_posix()
                if rel in EXCLUDED_FILES:
                    continue
                if any(rel.startswith(p) for p in EXCLUDED_PREFIXES):
                    continue
                # Skip test-path files. Test submodules live under
                # `**/tests/**` and are intentionally allowed to sync-bridge.
                parts = rel.split("/")
                if "tests" in parts:
                    continue
                out.append(rel)
    return sorted(out)


def crate_of(rel_path: str) -> str:
    """Return the crate name (e.g. 'scp-runtime') for a repo-relative path."""
    parts = rel_path.split("/")
    # Expect: crates/<crate>/src/...
    if len(parts) >= 2 and parts[0] == "crates":
        return parts[1]
    return "unknown"


# -----------------------------------------------------------------------------
# Main scan + ratchet comparison
# -----------------------------------------------------------------------------


def load_baseline() -> dict[str, int]:
    if not RATCHET_FILE.is_file():
        sys.stderr.write(
            f"{C_RED}error:{C_RESET} ratchet file missing: {RATCHET_FILE}\n"
        )
        sys.stderr.write(
            "Create it with the current counts per crate. See ADR-049.\n"
        )
        sys.exit(2)
    try:
        data = json.loads(RATCHET_FILE.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        sys.stderr.write(
            f"{C_RED}error:{C_RESET} failed to parse {RATCHET_FILE}: {exc}\n"
        )
        sys.exit(2)
    crates = data.get("crates", {})
    if not isinstance(crates, dict):
        sys.stderr.write(
            f"{C_RED}error:{C_RESET} {RATCHET_FILE} missing 'crates' object\n"
        )
        sys.exit(2)
    return {str(k): int(v) for k, v in crates.items()}


def do_real_scan(verbose: bool) -> int:
    baseline = load_baseline()
    total_hits: list[Hit] = []
    total_errors: list[str] = []
    files = in_scope_files()
    for rel in files:
        hits, errors = scan_file(rel)
        total_hits.extend(hits)
        total_errors.extend(errors)

    if total_errors:
        sys.stderr.write(
            f"{C_RED}error:{C_RESET} malformed allow-list directives:\n"
        )
        for e in total_errors:
            sys.stderr.write(f"  {e}\n")
        return 1

    # Count non-allow-listed hits per crate.
    by_crate: dict[str, int] = {}
    for h in total_hits:
        if h.allow_reason is not None:
            continue
        c = crate_of(h.file)
        by_crate[c] = by_crate.get(c, 0) + 1

    if verbose:
        print(f"{C_DIM}in-scope files: {len(files)}{C_RESET}")
        print(f"{C_DIM}total call sites: {len(total_hits)}{C_RESET}")
        allow_n = sum(1 for h in total_hits if h.allow_reason is not None)
        print(f"{C_DIM}allow-listed: {allow_n}{C_RESET}")
        print()

    # Compare to baseline.
    all_crates: set[str] = set(baseline.keys()) | set(by_crate.keys())
    fail = False
    for crate in sorted(all_crates):
        counted = by_crate.get(crate, 0)
        base = baseline.get(crate)
        if base is None:
            sys.stderr.write(
                f"  {C_RED}[{crate}]{C_RESET} counted={counted} "
                f"baseline={C_RED}MISSING{C_RESET} (add to ratchet)\n"
            )
            fail = True
            continue
        if counted > base:
            sys.stderr.write(
                f"  {C_RED}[{crate}]{C_RESET} counted={counted} "
                f"baseline={base} "
                f"{C_RED}(+{counted - base}, FAIL){C_RESET}\n"
            )
            sys.stderr.write("    unratcheted sites:\n")
            for h in total_hits:
                if crate_of(h.file) != crate or h.allow_reason is not None:
                    continue
                sys.stderr.write(
                    f"      {C_DIM}{h.file}:{h.line}{C_RESET}  "
                    f"{C_YELLOW}{h.kind}{C_RESET}  "
                    f"{C_DIM}{h.snippet}{C_RESET}\n"
                )
            fail = True
        elif counted < base:
            print(
                f"  {C_GREEN}[{crate}]{C_RESET} counted={counted} "
                f"baseline={base} "
                f"{C_GREEN}(-{base - counted} — ratchet can drop){C_RESET}"
            )
        else:
            print(
                f"  {C_GREEN}[{crate}]{C_RESET} counted={counted} "
                f"baseline={base} (OK)"
            )

    if fail:
        sys.stderr.write(
            f"\n{C_RED}FAILED{C_RESET}: block-in-place ratchet violated.\n\n"
            "To fix:\n"
            "  1. Delete the offending call (preferred — this is the whole point\n"
            "     of the actor refactor).\n"
            "  2. Or add an inline allow-list directive on the call site line:\n"
            "       // ci-allow: block-on: <reason describing why it's correct>\n"
            "\n"
            "Do NOT bump the ratchet to accept a new violation. See ADR-049.\n"
        )
        return 1

    print(f"\n{C_GREEN}PASSED{C_RESET}: block-in-place scan within ratchet.\n")
    return 0


# -----------------------------------------------------------------------------
# Self-test
# -----------------------------------------------------------------------------


# Fixture patterns we MUST catch. Each entry is a pattern descriptor that the
# self-test validates against the scanner output.
#
# Each descriptor is:
#   ("kind", "line_contains_substring" | "function_name:line_contains")
#
# The "function_name:..." form locates the hit inside a specific fn body by
# the fn's line range, so that calls whose own source line does not contain
# the fn name (closures, nested fns, one-line method calls) can still be
# asserted. The scanner walks into closures and nested fns; the self-test
# proves that by asserting a hit lives inside the named function.
REQUIRED_FIXTURE_PATTERNS: list[tuple[str, str]] = [
    # 1. Plain `tokio::task::block_in_place`
    ("block_in_place", "plain_block_in_place:tokio::task::block_in_place"),
    # 2. Aliased: `use tokio::task::block_in_place as bip; bip(...)`
    ("block_in_place", "aliased_block_in_place:bip"),
    # 3. Stored Handle .block_on
    ("block_on", "stored_handle_block_on:self.handle.block_on"),
    # 4. Multi-line .block_on chain
    ("block_on", "multiline_block_on:.block_on"),
    # 5. Handle::current().block_on
    ("block_on", "handle_current_block_on:Handle::current().block_on"),
    # 6. Inside a closure (closure body calls .block_on)
    ("block_on", "closure_block_on:.block_on"),
    # 7. Inside a nested fn
    ("block_on", "with_nested_fn:.block_on"),
    # 8. Runtime::new() construction
    ("runtime_new", "runtime_new_then_block_on:Runtime::new"),
]


def _fn_line_ranges(fixture_path: Path) -> dict[str, tuple[int, int]]:
    """Parse the fixture and return {fn_name: (start_line_1, end_line_1)}
    for every `fn` item (free fn, method, or nested fn).
    """
    source = fixture_path.read_bytes()
    tree = PARSER.parse(source)
    ranges: dict[str, tuple[int, int]] = {}

    def walk(node) -> None:
        if node.type == "function_item":
            name = node.child_by_field_name("name")
            if name is not None:
                nm = node_text(name, source)
                ranges[nm] = (node.start_point[0] + 1, node.end_point[0] + 1)
        for c in node.children:
            walk(c)

    walk(tree.root_node)
    return ranges


def do_self_test() -> int:
    if not FIXTURE_FILE.is_file():
        sys.stderr.write(
            f"{C_RED}error:{C_RESET} fixture missing: {FIXTURE_FILE}\n"
        )
        return 2

    # Scan the fixture as though it were in-scope. Bypass the scope filter
    # by calling scan_file directly with its relative path.
    rel = FIXTURE_FILE.relative_to(REPO_ROOT).as_posix()
    hits, errors = scan_file(rel)

    if errors:
        sys.stderr.write(
            f"{C_RED}self-test FAILED{C_RESET}: fixture has malformed directives:\n"
        )
        for e in errors:
            sys.stderr.write(f"  {e}\n")
        return 1

    fn_ranges = _fn_line_ranges(FIXTURE_FILE)
    fixture_bytes = FIXTURE_FILE.read_bytes()

    # Every pattern must match at least one non-allow-listed hit.
    missing: list[str] = []
    for expected_kind, descriptor in REQUIRED_FIXTURE_PATTERNS:
        fn_name, substr = descriptor.split(":", 1)
        rng = fn_ranges.get(fn_name)
        if rng is None:
            missing.append(f"fixture is missing fn {fn_name!r} — pattern {descriptor!r}")
            continue
        start, end = rng
        # `substr` may appear on the call's start line, its snippet, or
        # anywhere on a line within the call's source range (multi-line
        # method chains). We conservatively check every line in the fn
        # body since the hit is constrained to `start <= h.line <= end`.
        fixture_text = fixture_bytes.decode("utf-8", errors="replace")
        all_fixture_lines = fixture_text.splitlines()
        fn_body_text = "\n".join(
            all_fixture_lines[start - 1 : end]
        )  # lines are 1-indexed

        matched = any(
            h.kind == expected_kind
            and h.allow_reason is None
            and start <= h.line <= end
            and substr in fn_body_text
            for h in hits
        )
        if not matched:
            missing.append(
                f"expected {expected_kind} inside fn {fn_name} "
                f"(lines {start}-{end}) containing {substr!r}"
            )

    # Assert the allow-listed fixture sites are tagged, not counted.
    allowlisted_sites = [h for h in hits if h.allow_reason is not None]
    expected_allow_count = 2

    failed = False
    if missing:
        sys.stderr.write(
            f"{C_RED}self-test FAILED{C_RESET}: scanner missed "
            f"{len(missing)} fixture pattern(s):\n"
        )
        for m in missing:
            sys.stderr.write(f"  - {m}\n")
        failed = True

    if len(allowlisted_sites) < expected_allow_count:
        sys.stderr.write(
            f"{C_RED}self-test FAILED{C_RESET}: expected >={expected_allow_count} "
            f"allow-listed hits in fixture, got {len(allowlisted_sites)}\n"
        )
        failed = True

    # Assert the allow-list reason parser REJECTS an empty directive.
    # This is a separate, inline unit check — we synthesize a single line
    # and feed it through _check_allow_directive.
    _, _, err_empty = _check_allow_directive("foo(); // ci-allow: block-on")
    _, _, err_missing_colon = _check_allow_directive("foo(); // ci-allow: block-on: ")
    _, good_reason, err_good = _check_allow_directive(
        "foo(); // ci-allow: block-on: real reason text"
    )
    if err_empty is None or err_missing_colon is None:
        sys.stderr.write(
            f"{C_RED}self-test FAILED{C_RESET}: allow-list directive without "
            "reason was accepted (it must be rejected).\n"
        )
        failed = True
    if err_good is not None or good_reason != "real reason text":
        sys.stderr.write(
            f"{C_RED}self-test FAILED{C_RESET}: allow-list directive with "
            f"reason was rejected or parsed incorrectly (reason={good_reason!r}, "
            f"err={err_good!r}).\n"
        )
        failed = True

    if failed:
        return 1

    non_allowed = [h for h in hits if h.allow_reason is None]
    print(
        f"{C_GREEN}self-test PASSED{C_RESET}: "
        f"caught {len(non_allowed)} violation(s) across "
        f"{len(REQUIRED_FIXTURE_PATTERNS)} required patterns; "
        f"{len(allowlisted_sites)} correctly allow-listed; "
        f"empty-reason directives correctly rejected.\n"
    )
    return 0


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(
        description="AST-based block_in_place / block_on CI gate for ADR-049."
    )
    ap.add_argument("--self-test", action="store_true", help="run fixture self-test")
    ap.add_argument(
        "--list",
        action="store_true",
        help="list every call site (allow-listed and not); do not fail on ratchet",
    )
    ap.add_argument(
        "-v", "--verbose", action="store_true", help="print scan statistics"
    )
    args = ap.parse_args()

    if args.self_test:
        return do_self_test()

    if args.list:
        files = in_scope_files()
        for rel in files:
            hits, _ = scan_file(rel)
            for h in hits:
                tag = (
                    f"{C_GREEN}ALLOW{C_RESET}"
                    if h.allow_reason is not None
                    else f"{C_YELLOW}COUNT{C_RESET}"
                )
                print(f"{tag} {h.file}:{h.line} {h.kind} {h.snippet}")
        return 0

    return do_real_scan(verbose=args.verbose)


if __name__ == "__main__":
    sys.exit(main())
