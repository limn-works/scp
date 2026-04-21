#!/usr/bin/env python3.12
# ENFORCEMENT FILE: This script and its baseline
# (.docs/standards/call-invariants-baseline.json) are enforcement files.
# See CLAUDE.md "NEVER modify enforcement files" — will be added to that
# list in the merge commit that lands this PR. Modifications that weaken
# or remove existing assertions require human approval; adding NEW rules
# (expanding coverage) is always fine.
"""check-call-invariants.py — Enforce declarative call-precedence rules.

Rules live in ``.docs/standards/sdk-capability-matrix.json`` under the
``call_invariants`` array. Each rule declares:

* ``caller_matches``: regex that must fullmatch Rust fn names at the
  bridge/runtime boundary (e.g. ``^(py_)?context_send$``). Use ``fullmatch``
  semantics — partial matches are rejected so sloppy patterns like
  ``context_send`` don't quietly capture unrelated helpers.
* ``required_callee``: identifier that must appear as a direct call inside
  the matching function body.
* ``scope``: ``same-function`` (default) or
  ``same-function-or-direct-callee`` (allow one hop into a private helper
  defined in the same file).
* ``min_occurrences``: optional integer; the callee must appear at least
  N times (default 1).
* ``applies_to``: list drawn from ``BRIDGE_ROOTS`` keys.
* ``evidence``: must contain at least one of ``pipeline_wiring_test`` or
  ``code_sites`` (non-empty). Stub rules with neither are rejected at
  load time. Each ``code_sites`` entry is validated: its file path must
  exist, and if the entry uses ``<path>:<line>`` form (line is a pure
  integer), the file must have at least that many lines.

Also enforces the **rule-id ratchet** in
``.docs/standards/call-invariants-baseline.json``: every entry in
``required_rule_ids`` must appear in the matrix's ``call_invariants[].rule_id``
set. This prevents a PR from swapping a critical rule for a trivial one while
keeping the rule count constant. Adding new rules beyond the baseline is
always fine; retiring a rule requires explicit human approval per CLAUDE.md
enforcement-file policy.

Layer-B scope:
- This tool enforces *named-callee precedence* rules. Surface-area parity
  (bridge export symmetry) is owned by Layer A's ``check-cross-layer.sh``.
- Transitive call-graph scope is out of scope; ``same-function-or-direct-callee``
  covers one hop into a private helper. Deeper chains should be verified by
  the Rust ``pipeline_wiring.rs`` integration tests (the pipeline assertions
  in ``crates/scp-testing/tests/integration/pipeline_wiring.rs``).

Rule-id renames:
- Renaming a ``rule_id`` is equivalent to *retirement + new rule*, even if
  the new name is obviously similar (``foo-on-bar`` → ``foo-at-bar``). The PR
  performing a rename MUST also update CLAUDE.md's enforcement-files list so
  reviewers see the change. A rename that touches only the matrix and the
  baseline in the same commit is a RED FLAG — reviewers should block.
- The baseline pins ``required_rule_ids_digest`` (SHA-256 over the sorted
  ``required_rule_ids`` list); the validator re-computes the digest at
  startup and hard-fails on mismatch. A rename that does not bump the
  digest in the same commit fails here mechanically. Bumping the digest
  counts as an enforcement-file modification and must be reviewed as such.

Parse-error allowlist ratchet:
- ``KNOWN_PARSE_ERROR_FILES`` is a tiny, literal frozenset in this file.
  An adversary could silently append entries to smuggle broken Rust past
  the validator, so the baseline pins both the entry count
  (``parse_error_allowlist_count``) and the exact path list
  (``parse_error_allowlist_paths``). Growing the allowlist without
  bumping the baseline in the same commit is a hard failure; shrinking
  is always fine (a tree-sitter upgrade may have fixed the limitation).
- Each allowlist path is also checked for existence — a stale entry
  (file renamed / deleted) is a hard failure so coverage gaps don't
  rot unnoticed.

Exit codes:
    0 — all rules pass.
    1 — violation, stub rule, missing evidence target, ratchet regression,
        malformed JSON, or unreadable source file.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import tree_sitter_rust as tsr
from tree_sitter import Language, Node, Parser

RUST_LANG = Language(tsr.language())
PARSER = Parser(RUST_LANG)

REPO_ROOT = Path(__file__).resolve().parent.parent
MATRIX_PATH = REPO_ROOT / ".docs" / "standards" / "sdk-capability-matrix.json"
BASELINE_PATH = REPO_ROOT / ".docs" / "standards" / "call-invariants-baseline.json"
PIPELINE_WIRING_PATH = (
    REPO_ROOT
    / "crates"
    / "scp-testing"
    / "tests"
    / "integration"
    / "pipeline_wiring.rs"
)

# Where each applies_to key maps in the repo. Keep in sync with the matrix.
BRIDGE_ROOTS: dict[str, str] = {
    "pyo3": "crates/scp-ffi/src",
    "napi": "crates/scp-ffi/napi/src",
    "uniffi": "crates/scp-ffi/uniffi/src",
    "wasm": "crates/scp-ffi/wasm/src",
    "runtime": "crates/scp-runtime/src",
}

VALID_SCOPES = {"same-function", "same-function-or-direct-callee"}

# Known-benign tree-sitter-rust parse-error files. Tree-sitter-rust cannot
# parse ``extern "C" { pub type X; }`` opaque-type declarations used by
# wasm-bindgen — but ``cargo check`` accepts them as valid Rust. Each entry
# here MUST:
#
#  1. Be a path under a bridge root (BRIDGE_ROOTS), relative to REPO_ROOT.
#  2. Come with a short comment explaining *why* tree-sitter fails on it,
#     so future reviewers can judge whether a new exemption is justified.
#
# Any .rs file NOT in this set that fails to parse is a hard fail — an
# adversary could otherwise commit a subtle syntax error near a rule's
# critical callee site to silently disable enforcement. Adding to this
# allowlist is a real waiver and should be caught in code review.
KNOWN_PARSE_ERROR_FILES: frozenset[str] = frozenset(
    {
        # wasm-bindgen extern "C" opaque types (pub type JsMessageCallback;)
        "crates/scp-ffi/wasm/src/context.rs",
        "crates/scp-ffi/wasm/src/custody.rs",
        "crates/scp-ffi/wasm/src/storage.rs",
    }
)


@dataclass(frozen=True)
class FnRecord:
    """A parsed Rust function: its name, location, and body node."""

    name: str
    path: Path
    line: int
    body: Node
    source: bytes


@dataclass(frozen=True)
class Violation:
    bridge: str
    rule_id: str
    path: str
    line: int
    fn_name: str
    reason: str


# --------------------------------------------------------------------------
# Rust parsing helpers
# --------------------------------------------------------------------------


def _cfg_predicate_is_test_gated(token_tree: Node, source: bytes) -> bool:
    """Return True iff the parsed ``cfg(...)`` predicate selects for ``test``.

    ``token_tree`` is the tree-sitter node for the parenthesised argument of
    ``cfg(...)`` — i.e. the child of an ``attribute`` whose identifier is
    ``cfg``. The predicate is "test-gated" iff it implies ``test`` (the item
    is compiled ONLY when ``test`` is on). Semantics:

    - bare ``test`` identifier NOT under ``not(...)`` -> test-gated.
    - ``all(A, B)`` compiles iff ``A && B`` -> test-gated iff ANY child is
      test-gated (a single test-gated predicate forces the conjunction).
    - ``any(A, B)`` compiles iff ``A || B`` -> test-gated iff EVERY child is
      test-gated (any non-test child could activate the item in production).
    - ``not(...)`` -> recurse with ``under_not`` flipped. A bare ``test``
      inside ``not(...)`` means "compile when NOT under cfg(test)" — i.e.
      production-only — so do NOT report test-gated.
    - any other identifier / token is ignored (platform flags, features).

    Conflating ``all`` and ``any`` with a single ``.any()`` fold misclassifies
    patterns like ``cfg(all(any(feature = "x", test), not(test)))`` — which is
    production-only — as test-gated, silently excluding production fns from
    call-invariant enforcement. MINOR-1 filed for the old naive scanner.
    """

    def walk(tt: Node, under_not: bool, op: str) -> bool:
        # Collect each child-predicate's test-gated status, then fold
        # with the outer op (``any`` for the implicit top-level / ``all``
        # context, ``all`` for an explicit ``any(...)``).
        child_results: list[bool] = []
        i = 0
        children = tt.children
        while i < len(children):
            child = children[i]
            if child.type == "identifier":
                name = source[child.start_byte : child.end_byte].decode(
                    "utf-8", errors="replace"
                )
                # Peek at the next non-trivia sibling to see if this
                # identifier introduces a nested predicate (``all(...)``,
                # ``any(...)``, ``not(...)``) or is a bare option.
                j = i + 1
                while j < len(children) and children[j].type in (
                    "line_comment",
                    "block_comment",
                ):
                    j += 1
                nested = (
                    children[j]
                    if j < len(children) and children[j].type == "token_tree"
                    else None
                )
                if nested is not None:
                    if name == "not":
                        # `not(...)` is satisfied iff its inner is not,
                        # so it implies `test` only if the inner is a
                        # contradiction — we conservatively never
                        # classify `not(...)` as test-gated.
                        child_results.append(walk(nested, not under_not, "all"))
                    elif name == "all":
                        child_results.append(walk(nested, under_not, "all"))
                    elif name == "any":
                        child_results.append(walk(nested, under_not, "any"))
                    else:
                        # Unknown predicate keyword with args (e.g. cfg_attr):
                        # skip — we're only interpreting standard cfg syntax.
                        pass
                    i = j + 1
                    continue
                # Bare identifier: test-gated only if it is literally
                # `test` and we are NOT inside a `not(...)`.
                child_results.append(name == "test" and not under_not)
            elif child.type == "token_tree":
                # Stray nested token_tree with no leading identifier —
                # recurse defensively so pathological trees don't hide a
                # `test` identifier. Inherit the outer op.
                child_results.append(walk(child, under_not, op))
            i += 1
        if not child_results:
            return False
        return all(child_results) if op == "any" else any(child_results)

    # Top-level cfg(...) is an implicit conjunction (it carries a single
    # predicate; if that predicate is a bare `test`, the conjunction is
    # trivially test-gated — matching `all(...)` fold semantics).
    return walk(token_tree, under_not=False, op="all")


def _attribute_is_test_cfg(attr_item: Node, source: bytes) -> bool:
    """Return True iff ``attr_item`` is a ``#[cfg(...)]`` selecting ``test``.

    Handles ``#[cfg(test)]``, ``#[cfg(all(test, ...))]``,
    ``#[cfg(any(test, ...))]``. Rejects ``#[cfg(not(test))]`` (which gates
    for production) and ``#[cfg(all(not(test), ...))]``.

    Non-cfg attributes return False.
    """
    # attribute_item -> `#`, `[`, attribute, `]`. The attribute node has
    # identifier (attr name) + optional token_tree (args).
    attribute = None
    for child in attr_item.children:
        if child.type == "attribute":
            attribute = child
            break
    if attribute is None:
        return False

    attr_name: str | None = None
    token_tree: Node | None = None
    for child in attribute.children:
        if child.type == "identifier" and attr_name is None:
            attr_name = source[child.start_byte : child.end_byte].decode(
                "utf-8", errors="replace"
            )
        elif child.type == "scoped_identifier" and attr_name is None:
            # e.g. ``#[cfg_attr(...)]`` via a path — not a bare ``cfg``.
            attr_name = _tail_identifier(child, source)
        elif child.type == "token_tree":
            token_tree = child

    if attr_name != "cfg" or token_tree is None:
        return False
    return _cfg_predicate_is_test_gated(token_tree, source)


def _has_test_cfg_attribute(node: Node, source: bytes) -> bool:
    """Return True if any preceding sibling attribute is ``#[cfg(test)]``.

    Walks preceding sibling ``attribute_item`` nodes (attributes appear as
    siblings before the item they gate in tree-sitter's Rust grammar) and
    uses :func:`_attribute_is_test_cfg` to correctly interpret ``cfg``
    predicates — so ``#[cfg(not(test))]`` is treated as production-only,
    not test-gated (round-4 fix for MINOR-1). Comments between attributes
    and the item are skipped.
    """
    sibling = node.prev_sibling
    while sibling is not None:
        if sibling.type == "attribute_item":
            if _attribute_is_test_cfg(sibling, source):
                return True
        elif sibling.type in ("line_comment", "block_comment"):
            sibling = sibling.prev_sibling
            continue
        else:
            break
        sibling = sibling.prev_sibling
    return False


def _function_name(node: Node, source: bytes) -> str | None:
    for child in node.children:
        if child.type == "identifier":
            return source[child.start_byte : child.end_byte].decode(
                "utf-8", errors="replace"
            )
    return None


def _function_body(node: Node) -> Node | None:
    for child in node.children:
        if child.type == "block":
            return child
    return None


def _walk_functions(
    root: Node,
    source: bytes,
    path: Path,
    in_test: bool = False,
) -> list[FnRecord]:
    """Return every ``function_item`` outside ``#[cfg(test)]`` gated modules.

    A function is test-gated when ANY enclosing item carries ``#[cfg(test)]``:
    ``mod_item`` (test-only modules), ``impl_item`` (test-only impl blocks
    like ``#[cfg(test)] impl Foo { fn bar() { ... } }``), or ``trait_item``
    (test-only traits with default methods like
    ``#[cfg(test)] trait Foo { fn helper() { ... } }``). Without these
    checks, a method defined inside a test-only impl or trait would be
    treated as production code and its calls scanned as the production call
    graph (round-5 fix for MAJOR-1, round-6 extension for trait_item).
    Note that ``_call_is_test_cfg_gated`` stops walking at the enclosing
    function body, so it cannot see a containing-item cfg attribute from
    the other direction — exclusion must happen here at walk time.
    """
    out: list[FnRecord] = []
    test_ctx = in_test

    if root.type in ("mod_item", "impl_item", "trait_item") and _has_test_cfg_attribute(
        root, source
    ):
        test_ctx = True

    if root.type == "function_item" and not test_ctx:
        # Respect function-level #[cfg(test)] attributes as well.
        if not _has_test_cfg_attribute(root, source):
            name = _function_name(root, source)
            body = _function_body(root)
            if name is not None and body is not None:
                out.append(
                    FnRecord(
                        name=name,
                        path=path,
                        line=root.start_point[0] + 1,
                        body=body,
                        source=source,
                    )
                )

    for child in root.children:
        out.extend(_walk_functions(child, source, path, test_ctx))
    return out


def _extract_callee_identifier(call_node: Node, source: bytes) -> str | None:
    """Return the tail identifier of a call expression.

    Given ``a.b.c(x)`` return ``c``. Given ``path::to::func(x)`` return
    ``func``. Given a bare ``func(x)`` return ``func``.
    """
    func = call_node.child_by_field_name("function")
    if func is None:
        return None
    return _tail_identifier(func, source)


def _tail_identifier(node: Node, source: bytes) -> str | None:
    """Recursively drill to the rightmost identifier of a path/field expr."""
    if node.type == "identifier":
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
    if node.type == "field_expression":
        field = node.child_by_field_name("field")
        if field is not None and field.type == "field_identifier":
            return source[field.start_byte : field.end_byte].decode(
                "utf-8", errors="replace"
            )
    if node.type == "scoped_identifier":
        name = node.child_by_field_name("name")
        if name is not None:
            return _tail_identifier(name, source)
    if node.type == "generic_function":
        func = node.child_by_field_name("function")
        if func is not None:
            return _tail_identifier(func, source)
    # Fallback: scan children for the last identifier / field_identifier.
    last = None
    for child in node.children:
        if child.type in ("identifier", "field_identifier"):
            last = child
    if last is not None:
        return source[last.start_byte : last.end_byte].decode("utf-8", errors="replace")
    return None


def _macro_callee(macro_node: Node, source: bytes) -> str | None:
    """Return the macro name for a ``macro_invocation`` node."""
    for child in macro_node.children:
        if child.type == "identifier":
            return source[child.start_byte : child.end_byte].decode(
                "utf-8", errors="replace"
            )
        if child.type == "scoped_identifier":
            tail = _tail_identifier(child, source)
            if tail is not None:
                return tail
    return None


# Node types that, when found as ancestors of a call, can carry a preceding
# ``#[cfg(test)]`` attribute inside a block/module. Kept narrow to avoid
# false positives: only items and block-level statements may be attribute-
# gated. Expression-level attributes are accepted as ``attribute_item`` at
# statement position only.
_CFG_GATEABLE_TYPES = frozenset(
    {
        "expression_statement",
        "let_declaration",
        "function_item",
        "const_item",
        "static_item",
        "use_declaration",
        "mod_item",
        "impl_item",
        "trait_item",
        "struct_item",
        "enum_item",
        "type_item",
        "macro_definition",
        "foreign_mod_item",
    }
)


def _call_is_test_cfg_gated(call_node: Node, body: Node, source: bytes) -> bool:
    """Return True if ``call_node`` sits under a ``#[cfg(test)]`` statement.

    Walks up from the call toward ``body`` (the enclosing fn body). For
    each ancestor whose type is in ``_CFG_GATEABLE_TYPES``, check its
    preceding siblings for a ``#[cfg(test)]`` attribute using the proper
    predicate walker. Any test-gated ancestor up to the function body
    means the call is test-only code (round-4 fix for MINOR-2).

    Stops at ``body`` (inclusive of its descendants, exclusive of body
    itself) so an attribute on the outer function is not double-counted —
    ``_walk_functions`` already excludes test-gated functions.

    Round-6 note: tree-sitter's Python binding returns a fresh ``Node``
    wrapper on every ``.parent`` access, so identity comparison
    (``is not body``) is always True and the loop would walk past the fn
    body up to ``source_file``. Use the stable ``Node.id`` attribute
    (integer identity of the underlying C node) instead.
    """
    body_id = body.id
    node: Node | None = call_node
    while node is not None and node.id != body_id:
        if node.type in _CFG_GATEABLE_TYPES and _has_test_cfg_attribute(node, source):
            return True
        node = node.parent
    return False


def _collect_calls(body: Node, source: bytes) -> list[tuple[str, int]]:
    """Return ``(callee_name, line)`` pairs for every direct call in body.

    Includes both function calls (``call_expression``) and macro
    invocations (``macro_invocation``). A macro ``foo!(...)`` is counted as
    a call to ``foo`` so rules can cite macros like
    ``ensure_bridge_instance`` uniformly.

    Calls that live inside a ``#[cfg(test)]``-gated statement / item are
    excluded — otherwise a production rule requiring ``init_context_manager``
    would be spuriously satisfied by an adjacent ``#[cfg(test)] init_...()``
    call (MINOR-2). Test-only cfg branches are not part of the production
    call graph this validator enforces.
    """
    out: list[tuple[str, int]] = []
    stack: list[Node] = [body]
    while stack:
        node = stack.pop()
        if node.type == "call_expression":
            name = _extract_callee_identifier(node, source)
            if name is not None and not _call_is_test_cfg_gated(node, body, source):
                out.append((name, node.start_point[0] + 1))
        elif node.type == "macro_invocation":
            name = _macro_callee(node, source)
            if name is not None and not _call_is_test_cfg_gated(node, body, source):
                out.append((name, node.start_point[0] + 1))
        stack.extend(node.children)
    return out


# --------------------------------------------------------------------------
# Code-site parsing
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class CodeSite:
    """A parsed ``code_sites`` entry.

    Entries take one of two shapes:

    * ``<path>`` — just a file path, no line anchor.
    * ``<path>:<line> <rest...>`` — path with explicit line number.
    * ``<path>:<symbol> <rest...>`` — path with a symbol anchor; the
      ``symbol`` is any token that is not a pure integer. Line is None.

    Anything after the first whitespace is a human-readable note and is
    ignored by validation.
    """

    raw: str
    path: Path
    line: int | None  # None when the anchor is a symbol, not a line number


def _parse_code_site(entry: object) -> CodeSite | None:
    """Parse a ``code_sites`` entry into ``(path, optional line)``.

    ``entry`` is accepted as ``object`` because it originates from raw JSON
    (``list`` items are untyped). Returns None if the entry is empty / not
    a string — both are real runtime possibilities when the matrix is
    malformed.
    """
    if not isinstance(entry, str):
        return None
    text = entry.strip()
    if not text:
        return None

    # Split off any trailing human note (anything after the first space).
    head, _, _ = text.partition(" ")

    # head is "<path>" or "<path>:<anchor>". Because Windows-style paths
    # don't occur in this repo, first ":" separates path from anchor.
    if ":" in head:
        path_str, _, anchor = head.partition(":")
    else:
        path_str, anchor = head, ""

    if not path_str:
        return None

    path = REPO_ROOT / path_str
    line: int | None = None
    if anchor:
        # If the anchor is a pure integer, treat it as a line number.
        # Otherwise it's a symbol reference — valid but unverified.
        if anchor.isdigit():
            line = int(anchor)
    return CodeSite(raw=entry, path=path, line=line)


def _validate_code_sites(rule_id: str, sites: list) -> list[str]:
    """Validate that every code_sites entry points at a real path/line.

    Does not verify that ``required_callee`` actually appears at the cited
    location — that's the job of the Rust walk. A cited line is a strong
    hint, not a contract. We emit a soft warning (stderr, not a failure)
    when the ±10 line window around the cited line does not mention the
    rule's ``required_callee`` substring, so bitrot surfaces without
    blocking.
    """
    errors: list[str] = []
    for entry in sites:
        site = _parse_code_site(entry)
        if site is None:
            errors.append(
                f"{rule_id}: code_sites entry is not a non-empty string: {entry!r}"
            )
            continue
        if not site.path.is_file():
            try:
                rel = site.path.relative_to(REPO_ROOT)
            except ValueError:
                rel = site.path
            errors.append(
                f"{rule_id}: code_sites path does not exist: '{rel}' "
                f"(from entry '{site.raw}')"
            )
            continue
        if site.line is not None:
            try:
                total_lines = sum(1 for _ in site.path.open("rb"))
            except OSError as exc:
                errors.append(
                    f"{rule_id}: code_sites path is unreadable: '{site.path}' ({exc})"
                )
                continue
            if site.line < 1 or site.line > total_lines:
                try:
                    rel = site.path.relative_to(REPO_ROOT)
                except ValueError:
                    rel = site.path
                errors.append(
                    f"{rule_id}: code_sites line {site.line} is out of range "
                    f"for '{rel}' (file has {total_lines} line(s)) — "
                    f"from entry '{site.raw}'"
                )
    return errors


def _warn_code_site_bitrot(rule_id: str, required_callee: str, sites: list) -> None:
    """Emit a non-fatal warning if the cited window doesn't mention the callee.

    Callees may be wrapped in macros, helper functions, or method calls on
    aliased types, so this is a best-effort hint. Never fails the run.
    """
    for entry in sites:
        site = _parse_code_site(entry)
        if site is None or site.line is None or not site.path.is_file():
            continue
        try:
            with site.path.open(encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            # Swallow — hard validation already runs in _validate_code_sites.
            continue
        lo = max(0, site.line - 11)  # 1-indexed line; window is [line-10, line+10]
        hi = min(len(lines), site.line + 10)
        window = "".join(lines[lo:hi])
        if required_callee not in window:
            try:
                rel = site.path.relative_to(REPO_ROOT)
            except ValueError:
                rel = site.path
            print(
                f"WARN: {rule_id}: required_callee '{required_callee}' not found "
                f"within +-10 lines of {rel}:{site.line} (may be wrapped in a "
                f"macro/alias; verify manually if bitrot is suspected)",
                file=sys.stderr,
            )


# --------------------------------------------------------------------------
# Rule validation
# --------------------------------------------------------------------------


def _validate_rule_shape(rule: dict, index: int) -> list[str]:
    """Return a list of error strings for structural problems in ``rule``."""
    errors: list[str] = []
    rid = rule.get("rule_id", f"<rule #{index}>")

    for field in ("rule_id", "description", "applies_to", "pattern", "evidence"):
        if field not in rule:
            errors.append(f"{rid}: missing required field '{field}'")

    applies_to = rule.get("applies_to")
    if isinstance(applies_to, list):
        for target in applies_to:
            if target not in BRIDGE_ROOTS:
                errors.append(
                    f"{rid}: applies_to contains unknown target "
                    f"'{target}' (valid: {sorted(BRIDGE_ROOTS)})"
                )
    elif applies_to is not None:
        errors.append(f"{rid}: applies_to must be a list")

    pattern = rule.get("pattern", {})
    if not isinstance(pattern, dict):
        errors.append(f"{rid}: pattern must be an object")
    else:
        for field in ("caller_matches", "required_callee"):
            if field not in pattern:
                errors.append(f"{rid}: pattern.{field} is required")
        caller_re = pattern.get("caller_matches")
        if isinstance(caller_re, str):
            try:
                re.compile(caller_re)
            except re.error as exc:
                errors.append(
                    f"{rid}: pattern.caller_matches is not a valid regex: {exc}"
                )
        scope = pattern.get("scope", "same-function")
        if scope not in VALID_SCOPES:
            errors.append(
                f"{rid}: pattern.scope='{scope}' not in {sorted(VALID_SCOPES)}"
            )
        min_occ = pattern.get("min_occurrences", 1)
        if not isinstance(min_occ, int) or min_occ < 1:
            errors.append(f"{rid}: pattern.min_occurrences must be a positive int")

    evidence = rule.get("evidence", {})
    if not isinstance(evidence, dict):
        errors.append(f"{rid}: evidence must be an object")
    else:
        # Stub-rule rejection: at least one of pipeline_wiring_test or
        # code_sites must carry real content.
        pw_test = evidence.get("pipeline_wiring_test")
        code_sites = evidence.get("code_sites")
        has_pw = isinstance(pw_test, str) and pw_test.strip()
        has_sites = isinstance(code_sites, list) and any(
            isinstance(s, str) and s.strip() for s in code_sites
        )
        if not (has_pw or has_sites):
            errors.append(
                f"{rid}: stub rule rejected — evidence must include a "
                f"non-empty pipeline_wiring_test or code_sites entry"
            )
        # Validate that each code_sites entry resolves to a real file/line.
        if isinstance(code_sites, list) and code_sites:
            errors.extend(_validate_code_sites(rid, code_sites))

    return errors


def _pipeline_test_exists(test_name: str) -> bool:
    """Return True iff pipeline_wiring.rs defines ``fn <test_name>``.

    We do a textual scan rather than a full tree-sitter parse — the test
    file is stable enough and the regex is unambiguous (``fn`` at start of
    line, exact identifier match).
    """
    if not PIPELINE_WIRING_PATH.is_file():
        return False
    text = PIPELINE_WIRING_PATH.read_text(encoding="utf-8", errors="replace")
    pattern = re.compile(rf"^\s*fn\s+{re.escape(test_name)}\s*\(", re.MULTILINE)
    return bool(pattern.search(text))


# --------------------------------------------------------------------------
# Rule checking
# --------------------------------------------------------------------------


class UnreadableSourceError(Exception):
    """Raised when a Rust source file under a bridge root cannot be read.

    We refuse to silently skip unreadable files because a symlink loop,
    permission flip, or bad checkout could otherwise disable enforcement
    for an entire file with no visible signal.
    """


class BridgeParseError(Exception):
    """Raised when an unexpected Rust file fails tree-sitter parsing.

    We refuse to silently WARN on parse errors: an adversary could
    otherwise commit a subtle syntax error near a rule's critical callee
    site and the rule would pass with 0 violations. Known-benign cases
    (e.g. wasm-bindgen extern "C" opaque types) are explicitly allowlisted
    in ``KNOWN_PARSE_ERROR_FILES`` with comments; everything else is a
    hard fail that the caller must diagnose with ``cargo check``.
    """

    def __init__(self, unexpected: list[str]) -> None:
        self.unexpected = unexpected
        super().__init__(f"{len(unexpected)} Rust file(s) failed tree-sitter parsing")


def _load_bridge_functions(
    bridge: str,
    parse_error_paths: list[str],
) -> list[FnRecord]:
    """Parse every .rs file under the bridge root; return production fns.

    ``parse_error_paths`` is populated with any file whose parse tree
    contains error nodes — the caller is responsible for turning that list
    into a hard fail (modulo the ``KNOWN_PARSE_ERROR_FILES`` allowlist).

    Raises :class:`UnreadableSourceError` if any file cannot be read.
    """
    root_dir = REPO_ROOT / BRIDGE_ROOTS[bridge]
    if not root_dir.is_dir():
        return []
    records: list[FnRecord] = []
    for path in sorted(root_dir.rglob("*.rs")):
        # Unreadable sources are a hard fail: wrap OSError in a clean
        # domain error so the entrypoint can emit a clear stderr message
        # instead of a raw stack trace.
        try:
            source = path.read_bytes()
        except OSError as exc:
            try:
                rel = path.relative_to(REPO_ROOT)
            except ValueError:
                rel = path
            raise UnreadableSourceError(
                f"cannot read bridge source '{rel}': {exc.__class__.__name__}: {exc}"
            ) from exc
        tree = PARSER.parse(source)
        if tree.root_node.has_error:
            try:
                rel_str = str(path.relative_to(REPO_ROOT))
            except ValueError:
                rel_str = str(path)
            parse_error_paths.append(rel_str)
        records.extend(_walk_functions(tree.root_node, source, path))
    return records


def _check_rule_in_bridge(
    rule: dict,
    bridge: str,
    fns: list[FnRecord],
) -> list[Violation]:
    rid = rule["rule_id"]
    pattern = rule["pattern"]
    caller_re = re.compile(pattern["caller_matches"])
    required = pattern["required_callee"]
    scope = pattern.get("scope", "same-function")
    min_occ = int(pattern.get("min_occurrences", 1))

    # Index helpers by (path, name) so scope="same-function-or-direct-callee"
    # can look up a private helper defined in the same file.
    by_path_name: dict[tuple[Path, str], FnRecord] = {
        (fn.path, fn.name): fn for fn in fns
    }

    violations: list[Violation] = []
    for fn in fns:
        # Use fullmatch so sloppy patterns like ".*" or "context_send" must
        # match the whole function name instead of silently matching any
        # function containing the substring.
        if not caller_re.fullmatch(fn.name):
            continue

        direct_calls = _collect_calls(fn.body, fn.source)
        direct_hits = sum(1 for name, _ in direct_calls if name == required)

        total_hits = direct_hits
        if scope == "same-function-or-direct-callee" and total_hits < min_occ:
            # Allow one hop: if this function calls a private helper
            # defined in the same file, sum the helper's direct hits too.
            for name, _ in direct_calls:
                helper = by_path_name.get((fn.path, name))
                if helper is None or helper is fn:
                    continue
                helper_calls = _collect_calls(helper.body, helper.source)
                total_hits += sum(1 for hn, _ in helper_calls if hn == required)
                if total_hits >= min_occ:
                    break

        if total_hits < min_occ:
            try:
                rel = fn.path.relative_to(REPO_ROOT)
            except ValueError:
                rel = fn.path
            reason = (
                f"required callee '{required}' appears {total_hits} "
                f"time(s); rule requires >= {min_occ} (scope={scope})"
            )
            violations.append(
                Violation(
                    bridge=bridge,
                    rule_id=rid,
                    path=str(rel),
                    line=fn.line,
                    fn_name=fn.name,
                    reason=reason,
                )
            )
    return violations


# --------------------------------------------------------------------------
# Entrypoint
# --------------------------------------------------------------------------


def _load_json(path: Path) -> dict:
    """Load JSON with a clean error message instead of a stack trace."""
    try:
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        print(f"ERROR: file not found: {path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        try:
            rel = path.relative_to(REPO_ROOT)
        except ValueError:
            rel = path
        print(
            f"ERROR: malformed JSON in {rel}: {exc.msg} "
            f"(line {exc.lineno}, column {exc.colno})",
            file=sys.stderr,
        )
        sys.exit(1)


def _run() -> int:
    matrix = _load_json(MATRIX_PATH)
    baseline = _load_json(BASELINE_PATH)

    rules = matrix.get("call_invariants", [])
    if not isinstance(rules, list):
        print("ERROR: matrix.call_invariants must be a list", file=sys.stderr)
        return 1

    # Rule-id ratchet: every baseline-required rule_id must appear in the
    # matrix. Adding new rules is fine; retiring one requires human
    # approval (see baseline note + CLAUDE.md enforcement-files list).
    required_ids = baseline.get("required_rule_ids", [])
    if not isinstance(required_ids, list) or not all(
        isinstance(r, str) for r in required_ids
    ):
        print(
            "ERROR: call-invariants-baseline.json: required_rule_ids must be "
            "a list of strings",
            file=sys.stderr,
        )
        return 1

    matrix_rule_ids: set[str] = set()
    for rule in rules:
        if isinstance(rule, dict):
            rid = rule.get("rule_id")
            if isinstance(rid, str):
                matrix_rule_ids.add(rid)

    # Ratchet digest: a stable SHA-256 over the sorted required_rule_ids.
    # Printing this at the top of every run makes rename-style swaps
    # (e.g. ``foo-on-bar`` → ``foo-at-bar`` changed in matrix+baseline in
    # the same PR) visible in any diff or CI log. A rename changes the
    # digest; reviewers who see the delta should treat it as a red flag
    # and verify the rename was intentional and documented per CLAUDE.md.
    sorted_ids = sorted(required_ids)
    digest = hashlib.sha256("\n".join(sorted_ids).encode("utf-8")).hexdigest()[:16]
    computed_digest = f"sha256:{digest}"
    print(
        f"call-invariants ratchet: {len(sorted_ids)} required rule_id(s), "
        f"digest {computed_digest}"
    )

    # Digest ratchet: the baseline must pin the expected digest so that a
    # silent rename (e.g. ``foo-on-bar`` → ``foo-at-bar`` touching only the
    # matrix + baseline's required_rule_ids list) is caught mechanically,
    # not just via reviewer eyeballs. ``required_rule_ids_digest`` is a
    # required field — missing or wrong values are hard failures. Updating
    # the digest in the same commit as a rename counts as a modification
    # of an enforcement file per CLAUDE.md and must be reviewed accordingly.
    expected_digest = baseline.get("required_rule_ids_digest")
    if not isinstance(expected_digest, str) or not expected_digest.strip():
        print(
            "ERROR: call-invariants-baseline.json: required_rule_ids_digest "
            "is required (expected a 'sha256:<hex>' string). Compute the "
            "digest with: "
            'python3.12 -c "import hashlib,json; '
            "b=json.load(open('.docs/standards/call-invariants-baseline.json'));"
            "print('sha256:'+hashlib.sha256('\\n'.join(sorted(b['required_rule_ids']))"
            '.encode()).hexdigest()[:16])" '
            "and record it in the baseline.",
            file=sys.stderr,
        )
        return 1
    if expected_digest != computed_digest:
        print(
            f"RATCHET VIOLATION: required_rule_ids digest mismatch. "
            f"Expected {expected_digest}, got {computed_digest}. If you "
            f"intentionally renamed a rule, update the digest in "
            f"call-invariants-baseline.json in THIS commit; reviewers "
            f"will treat the digest change as enforcement-file "
            f"modification requiring approval.",
            file=sys.stderr,
        )
        return 1

    # KNOWN_PARSE_ERROR_FILES ratchet: the allowlist is a frozenset literal
    # in this script, so an adversary could silently append entries to
    # smuggle broken Rust past the validator. The baseline pins both the
    # count (fast-to-notice in diffs) and the exact path list (defends
    # against a same-size swap). Shrinking is always fine — a tree-sitter
    # upgrade may have fixed the underlying limitation — but growing
    # requires a deliberate ratchet bump in the same commit so review
    # catches it. Also assert every allowlisted path still resolves to a
    # real file; a stale entry is a silent coverage hole.
    expected_count = baseline.get("parse_error_allowlist_count")
    expected_paths_raw = baseline.get("parse_error_allowlist_paths")
    if not isinstance(expected_count, int):
        print(
            "ERROR: call-invariants-baseline.json: parse_error_allowlist_count "
            "must be an integer matching the size of KNOWN_PARSE_ERROR_FILES "
            "in scripts/check-call-invariants.py.",
            file=sys.stderr,
        )
        return 1
    if not isinstance(expected_paths_raw, list) or not all(
        isinstance(p, str) for p in expected_paths_raw
    ):
        print(
            "ERROR: call-invariants-baseline.json: parse_error_allowlist_paths "
            "must be a list of strings matching KNOWN_PARSE_ERROR_FILES in "
            "scripts/check-call-invariants.py.",
            file=sys.stderr,
        )
        return 1
    expected_paths: set[str] = set(expected_paths_raw)

    if len(KNOWN_PARSE_ERROR_FILES) != expected_count:
        print(
            f"ENFORCEMENT ERROR: KNOWN_PARSE_ERROR_FILES ratchet violated — "
            f"removing entries is fine, adding requires human approval and "
            f"ratchet bump. Expected {expected_count} entry/ies (per "
            f"call-invariants-baseline.json parse_error_allowlist_count), "
            f"found {len(KNOWN_PARSE_ERROR_FILES)} in "
            f"scripts/check-call-invariants.py.",
            file=sys.stderr,
        )
        return 1

    if set(KNOWN_PARSE_ERROR_FILES) != expected_paths:
        added = sorted(set(KNOWN_PARSE_ERROR_FILES) - expected_paths)
        removed = sorted(expected_paths - set(KNOWN_PARSE_ERROR_FILES))
        print(
            "ENFORCEMENT ERROR: KNOWN_PARSE_ERROR_FILES ratchet violated — "
            "path list diverges from call-invariants-baseline.json "
            "parse_error_allowlist_paths. Removing entries is fine, adding "
            "requires human approval and ratchet bump.",
            file=sys.stderr,
        )
        if added:
            print("  Added (not in baseline):", file=sys.stderr)
            for p in added:
                print(f"    + {p}", file=sys.stderr)
        if removed:
            print("  Removed (still in baseline):", file=sys.stderr)
            for p in removed:
                print(f"    - {p}", file=sys.stderr)
        return 1

    stale_entries = [
        p for p in sorted(KNOWN_PARSE_ERROR_FILES) if not (REPO_ROOT / p).is_file()
    ]
    if stale_entries:
        print(
            "ENFORCEMENT ERROR: stale allowlist entries — either restore "
            "the file(s) or remove from KNOWN_PARSE_ERROR_FILES AND from "
            "call-invariants-baseline.json's parse_error_allowlist_paths / "
            "parse_error_allowlist_count in the same commit:",
            file=sys.stderr,
        )
        for p in stale_entries:
            print(
                f"  - stale allowlist entry {p} — either restore the file "
                f"or remove from allowlist.",
                file=sys.stderr,
            )
        return 1

    missing_ids = [r for r in required_ids if r not in matrix_rule_ids]
    if missing_ids:
        print(
            "RATCHET VIOLATION: the following required rule(s) have been "
            "removed from sdk-capability-matrix.json:",
            file=sys.stderr,
        )
        for rid in missing_ids:
            print(f"  - required rule '{rid}' has been removed.", file=sys.stderr)
        print(
            "To retire an enforced invariant, human approval is required: "
            "remove the rule_id from call-invariants-baseline.json's "
            "required_rule_ids AND from sdk-capability-matrix.json's "
            "call_invariants[] AND update CLAUDE.md's enforcement-files "
            "list in the same PR.",
            file=sys.stderr,
        )
        return 1

    # Shape / stub / evidence-target validation — fail fast before parsing
    # any Rust so we never hide a bad rule behind a parse error.
    shape_errors: list[str] = []
    for idx, rule in enumerate(rules):
        shape_errors.extend(_validate_rule_shape(rule, idx))

    # Verify pipeline_wiring_test (when declared) points at a real test.
    for rule in rules:
        ev = rule.get("evidence", {}) if isinstance(rule, dict) else {}
        pw = ev.get("pipeline_wiring_test") if isinstance(ev, dict) else None
        if isinstance(pw, str) and pw.strip():
            if not _pipeline_test_exists(pw):
                shape_errors.append(
                    f"{rule.get('rule_id', '<unknown>')}: evidence.pipeline_wiring_test "
                    f"'{pw}' points to nonexistent test in {PIPELINE_WIRING_PATH.relative_to(REPO_ROOT)}"
                )

    if shape_errors:
        print("ERROR: call_invariants rule set is invalid:", file=sys.stderr)
        for err in shape_errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    # Soft-warn about possible bitrot in cited code_sites. Non-fatal: the
    # callee may be wrapped in a macro/alias that evades textual search.
    for rule in rules:
        ev = rule.get("evidence", {}) if isinstance(rule, dict) else {}
        sites = ev.get("code_sites") if isinstance(ev, dict) else None
        pattern = rule.get("pattern", {}) if isinstance(rule, dict) else {}
        required = pattern.get("required_callee") if isinstance(pattern, dict) else None
        rid = (
            rule.get("rule_id", "<unknown>") if isinstance(rule, dict) else "<unknown>"
        )
        if isinstance(sites, list) and isinstance(required, str):
            _warn_code_site_bitrot(rid, required, sites)

    # Cache parsed bridges only for the ones we'll touch.
    targets_needed: set[str] = set()
    for rule in rules:
        targets_needed.update(rule["applies_to"])

    parse_error_paths: list[str] = []
    try:
        bridge_fns: dict[str, list[FnRecord]] = {
            b: _load_bridge_functions(b, parse_error_paths) for b in targets_needed
        }
    except UnreadableSourceError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    # Hard-fail on tree-sitter parse errors in bridge files, except for the
    # explicit ``KNOWN_PARSE_ERROR_FILES`` allowlist. An adversary could
    # otherwise commit a subtle syntax error near a rule's critical callee
    # site and the rule would pass with 0 violations. Any file that
    # ``cargo check`` accepts but tree-sitter rejects must either be in
    # the allowlist (with a comment) or be a real bug that blocks the run.
    unexpected_parse_errors = [
        p for p in parse_error_paths if p not in KNOWN_PARSE_ERROR_FILES
    ]
    if unexpected_parse_errors:
        print(
            "ERROR: Rust parse errors in the following file(s) — refusing "
            "to enforce call-invariants (a silent pass here could hide a "
            "rule bypass):",
            file=sys.stderr,
        )
        for p in unexpected_parse_errors:
            print(f"  - {p}", file=sys.stderr)
        print(
            "Run `cargo check` to diagnose. If cargo accepts the file but "
            "tree-sitter does not, add the path to KNOWN_PARSE_ERROR_FILES "
            "in this script with a comment explaining the tree-sitter "
            "limitation — that addition is a reviewed waiver, not a fix.",
            file=sys.stderr,
        )
        return 1

    # For allowlisted files we still surface a single INFO line so the
    # waiver stays visible in CI output (and so removing the allowlist
    # entry after a tree-sitter upgrade is obviously safe).
    for p in parse_error_paths:
        if p in KNOWN_PARSE_ERROR_FILES:
            print(
                f"INFO: tree-sitter parse errors in {p} (known-benign, "
                f"see KNOWN_PARSE_ERROR_FILES); rule enforcement may be "
                f"incomplete for items defined after the first error node.",
                file=sys.stderr,
            )

    all_violations: list[Violation] = []
    for rule in rules:
        for bridge in rule["applies_to"]:
            all_violations.extend(
                _check_rule_in_bridge(rule, bridge, bridge_fns[bridge])
            )

    if all_violations:
        by_bridge: dict[str, list[Violation]] = {}
        for v in all_violations:
            by_bridge.setdefault(v.bridge, []).append(v)
        print(
            f"ERROR: {len(all_violations)} call-invariant violation(s) "
            f"across {len(by_bridge)} bridge(s):",
            file=sys.stderr,
        )
        for bridge in sorted(by_bridge):
            print(f"\n[{bridge}]", file=sys.stderr)
            for v in by_bridge[bridge]:
                print(
                    f"  {v.path}:{v.line}:{v.fn_name}  [{v.rule_id}] {v.reason}",
                    file=sys.stderr,
                )
        return 1

    print(
        f"call-invariants check passed: {len(rules)} rule(s) verified across "
        f"{len(targets_needed)} target(s) "
        f"({', '.join(sorted(targets_needed))})."
    )
    return 0


if __name__ == "__main__":
    sys.exit(_run())
