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
      Also flags fn-pointer rebinds:
          `let f = tokio::task::block_in_place; f(|| {})`
      is caught because `f` is tracked through `let_declaration` nodes
      (including transitive rebinds `let g = f;`).

  (2) Method call `.block_on(...)` on any expression. We do NOT resolve
      types; approximation is "any `.block_on(...)` call". Callers opt
      out with an inline allow-list directive (see below).

  (3) `Runtime::new()` construction — commonly paired with `.block_on(...)`
      to build an ad-hoc sync bridge. Flagged the same way. Type
      aliases defeat path.endswith("Runtime"), so the scanner also
      tracks `type X = Runtime;` and `use ... Runtime as X;` aliases
      (including transitive `type Y = X;`).

  (4) `macro_rules!` DEFINITIONS whose body text contains
      `block_in_place` or `.block_on` — a macro that wraps a sync
      bridge primitive. Flagged so reviewers see the wrapper.

  (5) `macro_invocation` sites whose TOKEN STREAM contains
      `block_in_place` or `.block_on` — pass-through macros that smuggle
      the primitive through the caller's token stream. Token-stream
      approximation; false positives can be allow-listed inline.

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
Instead, a PER-FILE baseline is kept in

    ratchet/block-in-place-count.json

The gate FAILS if any file's count exceeds its baseline entry; it
PASSES if the count is equal or lower; a LOWER count is reported as
"ratchet can drop" (a future commit should tighten the baseline).

Per-FILE enforcement (not per-crate) is deliberate: a per-crate
aggregate is gameable — an attacker can delete a legit site and add a
new one within the same crate without detection. Per-file gating forces
every new site to land in a file that already carries budget. A file
missing from the baseline has an implicit budget of 0; any hit in a new
file fails the gate immediately.

The `crates` map in the ratchet file is informational only (human
summary); enforcement lives in `files`.

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
    line: int  # 1-indexed (start)
    end_line: int  # 1-indexed (end; equals `line` for single-line hits)
    kind: str  # "block_in_place" | "bare_block_in_place" | "block_on" | "runtime_new" | "macro_invocation" | "macro_definition"
    snippet: str  # short code excerpt
    allow_reason: str | None  # non-None if allow-listed


# -----------------------------------------------------------------------------
# AST helpers
# -----------------------------------------------------------------------------


def _cfg_gates_on_test(cfg_body: str) -> bool:
    """Return True iff a `#[cfg(...)]` body gates on `test` being present.

    Accepts:
      cfg(test)
      cfg(all(test, ...))
      cfg(any(test, ...))
      cfg(all(test, any(..., ...)))
      ...

    Rejects:
      cfg(not(test))                    — production-only; MUST NOT exclude
      cfg(feature = "test")             — crate feature flag, not cfg(test)
      cfg(feature = "testing")          — same
      cfg(all(not(test), feature = X))  — still production-only

    Strategy: strip strings, remove `feature = "..."` predicates, then scan
    for the bare `test` token. A `test` inside `not(...)` is rejected by
    substring-checking the normalized form for `not(test)` and for any
    surrounding `not(` whose matching close paren is after the `test`
    token.
    """
    # Normalize whitespace.
    s = re.sub(r"\s+", "", cfg_body)
    # Drop string-valued predicates entirely — `feature = "test"` is NOT
    # `cfg(test)`. Match both `key="value"` (after whitespace strip) and
    # `key = "value"` variants. This is conservative: any predicate whose
    # right-hand side is a quoted string is discarded.
    s = re.sub(r'[A-Za-z_][A-Za-z0-9_]*="[^"]*"', "", s)
    # Find the bare `test` token — preceded by `(` or `,` and followed by
    # `)` or `,`. This rejects `testing` (followed by letters), `feature`
    # (different name), and similar.
    for m in re.finditer(r"(?:^|[(,])test(?:[),]|$)", s):
        test_idx = m.start() + (0 if m.group().startswith("t") else 1)
        # If any `not(` opens before this position and closes after it,
        # the `test` token is negated — reject.
        prefix = s[:test_idx]
        # Find all `not(` occurrences in the prefix; for each, determine
        # whether its matching `)` is after `test_idx`.
        for nm in re.finditer(r"not\(", prefix):
            open_pos = nm.end() - 1  # the `(` position
            depth = 1
            i = open_pos + 1
            while i < len(s) and depth > 0:
                if s[i] == "(":
                    depth += 1
                elif s[i] == ")":
                    depth -= 1
                i += 1
            close_pos = i - 1
            if close_pos > test_idx:
                # `test` is inside this `not(...)`. Not a test gate.
                break
        else:
            # No enclosing `not(...)` — this `test` token is an effective
            # test gate.
            return True
    return False


def has_test_cfg_attribute(node, source: bytes) -> bool:
    """True if the mod_item is preceded by a cfg attribute that positively
    gates on `test`. Rejects `cfg(not(test))`, `cfg(feature = "test")`,
    and other false-positive forms. See `_cfg_gates_on_test`.

    Tree-sitter places attribute_item nodes as preceding siblings of the
    mod_item, not as children. Walk back past any intervening comments.
    """
    sibling = node.prev_sibling
    while sibling is not None:
        if sibling.type == "attribute_item":
            text = source[sibling.start_byte : sibling.end_byte].decode(
                "utf-8", errors="replace"
            )
            # Extract every cfg(...) body in the attribute (handles
            # `#[cfg_attr(test, ...)]` too by treating it as a cfg gate
            # if its first predicate is a test gate).
            for m in re.finditer(r"cfg(?:_attr)?\((.*)\)", text, flags=re.DOTALL):
                body = m.group(1)
                if _cfg_gates_on_test(body):
                    return True
            # Non-cfg attribute (e.g. #[allow]) or non-test cfg: keep
            # walking back.
            sibling = sibling.prev_sibling
            continue
        if sibling.type in ("line_comment", "block_comment"):
            sibling = sibling.prev_sibling
            continue
        break
    return False


def node_text(node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _ident_resolves_to_block_in_place(node, source: bytes, aliases: set[str]) -> bool:
    """True if `node` is an identifier/scoped_identifier whose tail name
    is `block_in_place` or already in the alias set."""
    if node is None:
        return False
    if node.type == "identifier":
        return node_text(node, source) in (aliases | {"block_in_place"})
    if node.type == "scoped_identifier":
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            return node_text(name_node, source) == "block_in_place"
    return False


def _collect_aliased_block_in_place(root, source: bytes) -> set[str]:
    """Find every local name that resolves to `block_in_place`.

    Covers:
      (1) `use tokio::task::block_in_place as alias;`                    — import alias
      (2) `let name = tokio::task::block_in_place;`                      — fn-pointer rebind
      (3) `let name: _ = tokio::task::block_in_place;`                   — same, typed
      (4) `let name = alias;` where `alias` is already a known alias     — transitive rebind

    The real name `block_in_place` is always flagged; this set captures
    locally-bound shorter names that defeat a naive grep.

    Transitive rebinds are handled by repeated passes until the set
    stabilizes — the order of let-bindings and imports matters.
    """
    aliases: set[str] = set()

    # Pass 1: collect `use ... as NAME` import aliases by regex. This is
    # grammar-free and robust for grouped/multiline imports.
    def walk_uses(node) -> None:
        if node.type == "use_declaration":
            txt = node_text(node, source)
            for m in re.finditer(
                r"(?:tokio::task::|task::|::)?block_in_place\s+as\s+([A-Za-z_][A-Za-z0-9_]*)",
                txt,
            ):
                aliases.add(m.group(1))
        for c in node.children:
            walk_uses(c)

    walk_uses(root)

    # Pass 2+: walk `let_declaration` nodes repeatedly until the alias
    # set stops growing. This captures transitive rebinds
    # (let a = block_in_place; let b = a;).
    def walk_lets(node) -> bool:
        changed = False
        if node.type == "let_declaration":
            pat = node.child_by_field_name("pattern")
            val = node.child_by_field_name("value")
            if (
                pat is not None
                and pat.type == "identifier"
                and val is not None
                and _ident_resolves_to_block_in_place(val, source, aliases)
            ):
                name = node_text(pat, source)
                if name not in aliases:
                    aliases.add(name)
                    changed = True
        for c in node.children:
            if walk_lets(c):
                changed = True
        return changed

    # Fixed-point iteration. Bound at a small iteration count to prevent
    # pathological files from hanging the check.
    for _ in range(8):
        if not walk_lets(root):
            break

    return aliases


def _collect_runtime_aliases(root, source: bytes) -> set[str]:
    """Find every local name that aliases `Runtime` (or
    `tokio::runtime::Runtime`).

    Covers:
      `type R = Runtime;`
      `type R = tokio::runtime::Runtime;`
      `use tokio::runtime::Runtime as R;`
      `type R2 = R;` (transitive) where R is already a known alias

    Returns the set of alias names. The real name `Runtime` is always
    flagged by the base `_call_is_runtime_new` check; this set captures
    locally-bound names that would otherwise evade `path.endswith('Runtime')`.
    """
    aliases: set[str] = set()

    # Pass 1: `use ... Runtime as NAME` imports.
    def walk_uses(node) -> None:
        if node.type == "use_declaration":
            txt = node_text(node, source)
            for m in re.finditer(
                r"(?:tokio::runtime::|runtime::|::)?Runtime\s+as\s+([A-Za-z_][A-Za-z0-9_]*)",
                txt,
            ):
                aliases.add(m.group(1))
        for c in node.children:
            walk_uses(c)

    walk_uses(root)

    # Pass 2+: `type X = Runtime;` and transitive aliases.
    def walk_types(node) -> bool:
        changed = False
        if node.type == "type_item":
            name_node = node.child_by_field_name("name")
            type_node = node.child_by_field_name("type")
            if name_node is not None and type_node is not None:
                rhs_tail: str | None = None
                if type_node.type == "type_identifier":
                    rhs_tail = node_text(type_node, source)
                elif type_node.type == "scoped_type_identifier":
                    inner_name = type_node.child_by_field_name("name")
                    if inner_name is not None:
                        rhs_tail = node_text(inner_name, source)
                # Match "Runtime" directly or an already-known alias.
                if rhs_tail is not None and (
                    rhs_tail == "Runtime" or rhs_tail in aliases
                ):
                    name = node_text(name_node, source)
                    if name not in aliases:
                        aliases.add(name)
                        changed = True
        for c in node.children:
            if walk_types(c):
                changed = True
        return changed

    for _ in range(8):
        if not walk_types(root):
            break

    return aliases


def _is_bare_block_in_place_reference(
    node, source: bytes, aliases: set[str]
) -> bool:
    """True if `node` is a `scoped_identifier` or bare `identifier`
    that names `block_in_place` (or a known alias) AND is used as a
    VALUE EXPRESSION rather than as a call callee, a let binding's
    right-hand side, or an import path.

    This catches bare-expression bypasses that a call-site-only scanner
    misses:

      - `fn get_ptr() -> fn() { tokio::task::block_in_place }`
        — return-position bare fn pointer.
      - `let pair = (tokio::task::block_in_place, 0); pair.0(|| ());`
        — tuple literal element (no `let x = ...` direct binding).
      - `struct S { f: fn() } let _ = S { f: tokio::task::block_in_place };`
        — struct-field initializer expression.
      - `let arr = [tokio::task::block_in_place]; arr[0](|| ());`
        — array literal element.
      - `let x = tokio::task::block_in_place as fn(fn());`
        — type-cast expression value (the scoped_identifier is the
        cast's `value`, NOT the `let`'s `value`, so the existing
        rebind path does not catch this).

    The node must NOT be:

      (1) The callee (`function` field) of a `call_expression` — that
          is the classic call-site case and is caught by
          `_call_is_block_in_place`.
      (2) The `value` field of a `let_declaration` whose `pattern` is a
          plain identifier — that is the fn-pointer rebind path and is
          caught by `_collect_aliased_block_in_place` (which then
          rewrites `aliases`, and subsequent `alias(...)` call sites
          are caught by `_call_is_block_in_place`).
      (3) Anywhere inside a `use_declaration` — `use tokio::task::block_in_place`
          (and its `... as alias;` form) are imports, not usages.
      (4) Inside a `scoped_identifier`'s `path` component — we only
          flag the OUTER scoped_identifier whose `name` is
          `block_in_place`; inner path nodes are traversal noise.
      (5) Inside a `macro_invocation` or `macro_rules_definition` /
          `macro_definition` body — those are already flagged whole by
          `_macro_body_contains_sync_bridge` at the macro node level,
          and per-leaf bare-expression flagging would double-count.

    Identifiers that are NOT the tail of a path are filtered by the
    `scoped_identifier`-parent check: `tokio` and `task` in
    `tokio::task::block_in_place` have a `scoped_identifier` parent,
    so they would collide unless we only match when the node is a
    top-level `scoped_identifier` (whose `name` is `block_in_place`)
    or a stand-alone `identifier` whose parent is not a
    `scoped_identifier`.
    """
    # Filter 1: shape. Only scoped_identifier/identifier leaves.
    if node.type == "scoped_identifier":
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return False
        if node_text(name_node, source) != "block_in_place":
            return False
        # Reject if this scoped_identifier is itself the PATH of a
        # larger scoped_identifier (extremely unusual in Rust syntax,
        # but cheap to guard).
        parent = node.parent
        if parent is not None and parent.type == "scoped_identifier":
            path_field = parent.child_by_field_name("path")
            if path_field is not None and path_field == node:
                return False
    elif node.type == "identifier":
        name = node_text(node, source)
        if name != "block_in_place" and name not in aliases:
            return False
        # Reject path components of scoped_identifier (e.g. `tokio` or
        # `task` in `tokio::task::block_in_place`) — they have a
        # `scoped_identifier` parent. The ONLY scoped_identifier-parent
        # position we care about is the `name` field of a
        # scoped_identifier whose OWN name is `block_in_place`, and
        # that's already handled by the `scoped_identifier` branch
        # above.
        if node.parent is not None and node.parent.type == "scoped_identifier":
            return False
    else:
        return False

    # Filter 2: parent-chain rejection.
    parent = node.parent
    # (1) Callee of a call — existing call-site logic handles it.
    if parent is not None and parent.type == "call_expression":
        fn_field = parent.child_by_field_name("function")
        if fn_field is not None and fn_field == node:
            return False
    # (2) Direct value of a let binding — existing rebind logic handles it.
    if parent is not None and parent.type == "let_declaration":
        val_field = parent.child_by_field_name("value")
        if val_field is not None and val_field == node:
            return False

    # (3) Inside a use_declaration, (5) inside a macro. Walk ancestors.
    ancestor = parent
    while ancestor is not None:
        if ancestor.type == "use_declaration":
            return False
        if ancestor.type in (
            "macro_invocation",
            "macro_definition",
            "macro_rules_definition",
        ):
            return False
        ancestor = ancestor.parent

    return True


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


def _call_is_runtime_new(
    call_node, source: bytes, runtime_aliases: set[str]
) -> bool:
    """True if `call_node` is `Runtime::new(...)`,
    `tokio::runtime::Runtime::new(...)`, or `ALIAS::new(...)` where
    `ALIAS` was bound via `type ALIAS = Runtime;` or
    `use ... Runtime as ALIAS;`.
    """
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
    # Accept `Runtime::new`, `tokio::runtime::Runtime::new`, and any
    # `ALIAS::new` where ALIAS is a known runtime alias. The alias
    # comparison is on the full path_txt (e.g. `R`) AND on its tail
    # segment (e.g. `m::R` → `R`).
    if path_txt.endswith("Runtime"):
        return True
    tail = path_txt.rsplit("::", 1)[-1]
    return path_txt in runtime_aliases or tail in runtime_aliases


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


def _macro_body_contains_sync_bridge(node, source: bytes) -> bool:
    """True if the text of `node` contains `block_in_place` (as an
    identifier) or `.block_on` (as a method receiver). Used for macro
    invocations and macro_rules definitions.

    Approximation: string matching over the node's token stream. We
    check both the bare identifier and the scoped forms. False-positives
    are acceptable and can be squelched with the inline allow-list
    directive.
    """
    txt = node_text(node, source)
    if re.search(r"\bblock_in_place\b", txt):
        return True
    if re.search(r"\.\s*block_on\b", txt):
        return True
    return False


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
    runtime_aliases = _collect_runtime_aliases(tree.root_node, source)

    def record_hit(node, kind: str, tctx: bool) -> None:
        if tctx:
            return
        line_1 = node.start_point[0] + 1
        last_line_1 = node.end_point[0] + 1
        snippet = node_text(node, source).splitlines()[0][:80]
        # Directive must be on the SAME source line as the call
        # site's START, or the last line of the call expression for
        # multiline forms.
        line_text = _extract_line_text(source, line_1)
        last_line_text = (
            _extract_line_text(source, last_line_1) if last_line_1 != line_1 else ""
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
                end_line=last_line_1,
                kind=kind,
                snippet=snippet,
                allow_reason=allow_reason if (present1 or present2) else None,
            )
        )

    def walk(node, in_test: bool) -> None:
        tctx = in_test
        if node.type == "mod_item":
            name_node = node.child_by_field_name("name")
            nm = node_text(name_node, source) if name_node is not None else ""
            if has_test_cfg_attribute(node, source) or nm == "tests":
                tctx = True

        if not tctx:
            if node.type == "call_expression":
                kind: str | None = None
                if _call_is_block_in_place(node, source, aliases):
                    kind = "block_in_place"
                elif _call_is_block_on(node, source):
                    kind = "block_on"
                elif _call_is_runtime_new(node, source, runtime_aliases):
                    kind = "runtime_new"
                if kind is not None:
                    record_hit(node, kind, tctx)
            elif node.type == "macro_invocation":
                # Pass-through macros that carry `block_in_place` or
                # `.block_on` as tokens. Token-stream approximation; false
                # positives can be allow-listed inline.
                if _macro_body_contains_sync_bridge(node, source):
                    record_hit(node, "macro_invocation", tctx)
            elif node.type in ("macro_definition", "macro_rules_definition"):
                # `macro_rules! name { ... }` definition whose body wraps
                # a sync-bridge primitive. Any subsequent invocation will
                # expand to a hit; also flag the definition so the
                # wrapper itself is visible.
                if _macro_body_contains_sync_bridge(node, source):
                    record_hit(node, "macro_definition", tctx)
            elif node.type in ("scoped_identifier", "identifier"):
                # Bare-expression bypass: `block_in_place` (or an alias)
                # used as a value — in a tuple literal, struct-field
                # init, array literal, return-position expression,
                # type-cast expression, etc. The existing call-site and
                # let-rebind detectors miss these because there is no
                # `call_expression` parent and no direct `let x = ...`
                # binding. See `_is_bare_block_in_place_reference` for
                # the full exclusion set (callee / let-value / use /
                # path-component / macro).
                if _is_bare_block_in_place_reference(node, source, aliases):
                    record_hit(node, "bare_block_in_place", tctx)

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


def load_baseline() -> tuple[dict[str, int], dict[str, int]]:
    """Load the ratchet. Returns (per_file, per_crate_summary).

    Per-file is the authoritative enforcement granularity: any file
    whose non-allow-listed count exceeds its baseline entry fails the
    gate. The per-crate summary is informational — an attacker who
    deletes a legit site and adds a new one within the same crate would
    leave the crate aggregate unchanged but move detection into a new
    file, which the per-file gate catches.

    Schema:
      {
        "files":   { "crates/x/src/a.rs": 3, ... },   # AUTHORITATIVE
        "crates":  { "scp-runtime": 36, ... }         # human summary
      }

    A file missing from `files` has an implicit baseline of 0 — any hit
    in a new file fails the gate. The `crates` map is tolerated for
    backward compatibility but is NOT used for enforcement.
    """
    if not RATCHET_FILE.is_file():
        sys.stderr.write(
            f"{C_RED}error:{C_RESET} ratchet file missing: {RATCHET_FILE}\n"
        )
        sys.stderr.write(
            "Create it with the current per-file counts. See ADR-049.\n"
        )
        sys.exit(2)
    try:
        data = json.loads(RATCHET_FILE.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        sys.stderr.write(
            f"{C_RED}error:{C_RESET} failed to parse {RATCHET_FILE}: {exc}\n"
        )
        sys.exit(2)
    files = data.get("files")
    if not isinstance(files, dict):
        sys.stderr.write(
            f"{C_RED}error:{C_RESET} {RATCHET_FILE} missing 'files' object "
            f"(per-file baseline is required; per-crate aggregate is gameable).\n"
        )
        sys.exit(2)
    per_file = {str(k): int(v) for k, v in files.items()}
    crates = data.get("crates", {})
    per_crate = (
        {str(k): int(v) for k, v in crates.items()}
        if isinstance(crates, dict)
        else {}
    )
    return (per_file, per_crate)


def do_real_scan(verbose: bool) -> int:
    per_file_baseline, per_crate_summary = load_baseline()
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

    # Count non-allow-listed hits per FILE and per crate (summary only).
    per_file_count: dict[str, int] = {}
    by_crate: dict[str, int] = {}
    for h in total_hits:
        if h.allow_reason is not None:
            continue
        per_file_count[h.file] = per_file_count.get(h.file, 0) + 1
        c = crate_of(h.file)
        by_crate[c] = by_crate.get(c, 0) + 1

    if verbose:
        print(f"{C_DIM}in-scope files: {len(files)}{C_RESET}")
        print(f"{C_DIM}total call sites: {len(total_hits)}{C_RESET}")
        allow_n = sum(1 for h in total_hits if h.allow_reason is not None)
        print(f"{C_DIM}allow-listed: {allow_n}{C_RESET}")
        print()

    # PER-FILE enforcement. Any file whose count exceeds its baseline
    # fails. Files with a counted drop are reported "can drop". Files in
    # the baseline with 0 current hits are silently fine (they've been
    # fully cleaned up).
    fail = False
    all_files: set[str] = set(per_file_baseline.keys()) | set(
        per_file_count.keys()
    )
    drops: list[tuple[str, int, int]] = []
    for rel in sorted(all_files):
        counted = per_file_count.get(rel, 0)
        base = per_file_baseline.get(rel, 0)  # missing => implicit 0
        if counted > base:
            sys.stderr.write(
                f"  {C_RED}[{rel}]{C_RESET} counted={counted} "
                f"baseline={base} "
                f"{C_RED}(+{counted - base}, FAIL){C_RESET}\n"
            )
            sys.stderr.write("    unratcheted sites:\n")
            for h in total_hits:
                if h.file != rel or h.allow_reason is not None:
                    continue
                sys.stderr.write(
                    f"      {C_DIM}{h.file}:{h.line}{C_RESET}  "
                    f"{C_YELLOW}{h.kind}{C_RESET}  "
                    f"{C_DIM}{h.snippet}{C_RESET}\n"
                )
            fail = True
        elif counted < base:
            drops.append((rel, base, counted))

    # Per-crate summary, for humans. Not used for enforcement — only
    # reported so reviewers can see the overall trend.
    if not fail:
        print(f"{C_DIM}per-crate summary (informational):{C_RESET}")
        all_crates: set[str] = set(per_crate_summary.keys()) | set(by_crate.keys())
        for crate in sorted(all_crates):
            counted = by_crate.get(crate, 0)
            base = per_crate_summary.get(crate, 0)
            if counted < base:
                print(
                    f"  {C_GREEN}[{crate}]{C_RESET} counted={counted} "
                    f"baseline_summary={base} "
                    f"{C_GREEN}(-{base - counted}){C_RESET}"
                )
            elif counted == base:
                print(
                    f"  {C_GREEN}[{crate}]{C_RESET} counted={counted} "
                    f"baseline_summary={base} (OK)"
                )
            else:
                # Per-file gate already passed, so crate-level increases
                # here are fine (e.g. new file with 0 baseline).
                print(
                    f"  {C_DIM}[{crate}]{C_RESET} counted={counted} "
                    f"baseline_summary={base} "
                    f"{C_DIM}(+{counted - base}, ok — per-file gate is authoritative){C_RESET}"
                )

    # Report per-file drops so reviewers can tighten the baseline in a
    # follow-up commit.
    if drops:
        print(f"\n{C_GREEN}ratchet can drop for {len(drops)} file(s):{C_RESET}")
        for rel, base, counted in drops:
            print(
                f"  {C_GREEN}[{rel}]{C_RESET} counted={counted} "
                f"baseline={base} "
                f"{C_GREEN}(-{base - counted}){C_RESET}"
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
    # 9. fn-pointer rebind: `let f = tokio::task::block_in_place; f(|| ...)`
    ("block_in_place", "fn_pointer_rebind_block_in_place:fn_ptr"),
    # 10. Runtime type alias: `type R = Runtime; R::new().block_on(...)`
    #     — the inner `R::new()` must be caught via alias; the outer
    #     `.block_on` is ALSO caught but that is Pattern 3-style.
    ("runtime_new", "runtime_type_alias_block_on:R::new"),
    # 11. macro_rules! definition wrapping a sync bridge.
    ("macro_definition", "__macro_rules_defined_at_module_scope:sync_bridge"),
    # 12. Invocation of a pass-through macro whose TOKEN STREAM carries
    #     `block_in_place` as an argument — the macro body is clean but
    #     the invocation site isn't.
    ("macro_invocation", "macro_invocation_site:block_in_place"),
    # 13. Production-only module: `#[cfg(not(test))] mod prod_only { ... }`
    #     must NOT be excluded as test code. The call inside it must be
    #     caught.
    ("block_on", "production_only_cfg_not_test:.block_on"),
    # 14. Tuple-literal bare reference: `(tokio::task::block_in_place, 0)`
    #     — the primitive is a value inside a tuple_expression. Neither
    #     `_call_is_block_in_place` (no call_expression parent) nor
    #     `_collect_aliased_block_in_place` (no direct `let x = ...`
    #     binding) catch this; `_is_bare_block_in_place_reference`
    #     must.
    ("bare_block_in_place", "tuple_literal_bare_ref:tokio::task::block_in_place"),
    # 15. Return-position bare fn pointer: fn body is a single
    #     expression resolving to `tokio::task::block_in_place`. No
    #     call, no let — caught only by the bare-reference walker.
    ("bare_block_in_place", "return_position_bare_fn_ptr:tokio::task::block_in_place"),
    # 16. Struct-field initializer bare reference: field in a
    #     `struct_expression` is set to the bare primitive. Same
    #     category as 14–15 (no call, no direct let) and must be
    #     flagged by the bare-reference walker.
    ("bare_block_in_place", "struct_field_init_bare_ref:tokio::task::block_in_place"),
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


def _mod_line_ranges(fixture_path: Path) -> dict[str, tuple[int, int]]:
    """Parse the fixture and return {mod_name: (start_line_1, end_line_1)}
    for every `mod NAME { ... }` item. Used to anchor patterns on
    modules that are NOT inside a fn (e.g. #[cfg(not(test))] mod prod).
    """
    source = fixture_path.read_bytes()
    tree = PARSER.parse(source)
    ranges: dict[str, tuple[int, int]] = {}

    def walk(node) -> None:
        if node.type == "mod_item":
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
    mod_ranges = _mod_line_ranges(FIXTURE_FILE)
    fixture_bytes = FIXTURE_FILE.read_bytes()
    fixture_source_lines = fixture_bytes.decode("utf-8", errors="replace").splitlines()

    # Every pattern must match at least one non-allow-listed hit. Unlike
    # the earlier version, the substring assertion is tied to the hit's
    # own source range (lines h.line..h.end_line) — NOT the whole fn body.
    # This closes a weakness where the fixture coincidentally mentioned
    # `substr` elsewhere in the fn and the assertion passed even if the
    # hit itself did not carry the pattern.
    missing: list[str] = []
    for expected_kind, descriptor in REQUIRED_FIXTURE_PATTERNS:
        anchor, substr = descriptor.split(":", 1)
        # Anchor may be a fn name OR a mod name. Prefer fn; fall back to
        # mod. This lets us anchor #[cfg(not(test))] mod patterns.
        rng = fn_ranges.get(anchor) or mod_ranges.get(anchor)
        if rng is None:
            missing.append(
                f"fixture is missing fn/mod {anchor!r} — pattern {descriptor!r}"
            )
            continue
        start, end = rng

        def hit_source_contains(h: Hit, needle: str) -> bool:
            # Hit's source range is [h.line, h.end_line] inclusive,
            # 1-indexed. Check whether any line in that range contains
            # `needle`. This is tight to the hit, not to the fn body.
            lo = max(1, h.line)
            hi = min(len(fixture_source_lines), h.end_line)
            for ln in range(lo, hi + 1):
                if needle in fixture_source_lines[ln - 1]:
                    return True
            return False

        matched = any(
            h.kind == expected_kind
            and h.allow_reason is None
            and start <= h.line <= end
            and hit_source_contains(h, substr)
            for h in hits
        )
        if not matched:
            missing.append(
                f"expected {expected_kind} inside {anchor} "
                f"(lines {start}-{end}) with hit source containing {substr!r}"
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
