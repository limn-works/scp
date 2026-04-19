#!/usr/bin/env python3.12
# ruff: noqa: E501
"""AST check: enforce `OwnedIdentityDid` capability-token invariants.

---------------------------------------------------------------------------
PREREQUISITES
---------------------------------------------------------------------------
    pip install tree-sitter tree-sitter-rust

Python 3.12+. Runs offline; no network access required.

---------------------------------------------------------------------------
WHAT THIS CHECKS
---------------------------------------------------------------------------
If the `OwnedIdentityDid` type exists anywhere in `crates/scp-runtime/src/`:

  (A) It MUST be declared only in
      `crates/scp-runtime/src/context/supervisor/identity_capability.rs`.
      Any other location is a capability-leak: a handler or other
      runtime module that can name the type's constructor path can
      fabricate tokens and bypass cross-identity isolation.

  (B) The declaration MUST be `pub(super)`. `pub(crate)` lets any module
      in `scp-runtime` construct the type and defeats the capability
      boundary; `pub` leaks it to downstream crates. See ADR-049
      §"Cross-identity isolation: `OwnedIdentityDid` capability tag".

  (C) The declaration MUST NOT carry `#[derive(...)]` listing ANY of:
      Clone, Copy, Serialize, Deserialize, Default, Hash, PartialEq,
      Eq, Borrow, From, Into, Debug, Display, Deref, AsRef.
      The intent of each non-derive is documented in ADR-049:
        - Clone/Copy: leaks the capability.
        - Serialize/Deserialize: smuggles it across trust boundaries.
        - Default/From/Into: fabrication without the constructor.
        - Hash/PartialEq/Eq: identity set-semantics are not a use case;
          the cap is by-value only at call sites.
        - Borrow/AsRef/Deref: erodes the `&OwnedIdentityDid` contract.
        - Debug/Display: accidental logging of identity tokens.

The check PASSES SILENTLY if `OwnedIdentityDid` does not exist yet —
commit 5 of the actor refactor introduces the type. Until then, this
gate is a tripwire that fires the moment the type lands in the wrong
place or with the wrong shape.

---------------------------------------------------------------------------
SCOPE
---------------------------------------------------------------------------
Walks every `.rs` file under `crates/scp-runtime/src/` (including tests
and submodules). Finds every `struct OwnedIdentityDid` or `enum
OwnedIdentityDid` declaration.

---------------------------------------------------------------------------
USAGE
---------------------------------------------------------------------------
    python3.12 scripts/check-owned-identity-did.py

Exit codes:
    0  — type not yet declared, OR declared correctly
    1  — type is declared in the wrong file, with wrong visibility, or
         with a forbidden derive
    2  — invocation error

See ADR-049 for design context.
"""

from __future__ import annotations

import os
import sys
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
SCAN_DIR = REPO_ROOT / "crates" / "scp-runtime" / "src"
REQUIRED_PATH = "crates/scp-runtime/src/context/supervisor/identity_capability.rs"
TYPE_NAME = "OwnedIdentityDid"

FORBIDDEN_DERIVES = frozenset(
    {
        "Clone",
        "Copy",
        "Serialize",
        "Deserialize",
        "Default",
        "Hash",
        "PartialEq",
        "Eq",
        "Borrow",
        "From",
        "Into",
        "Debug",
        "Display",
        "Deref",
        "AsRef",
    }
)

# TTY coloring
if sys.stdout.isatty() and "NO_COLOR" not in os.environ:
    C_RED = "\033[31m"
    C_GREEN = "\033[32m"
    C_YELLOW = "\033[33m"
    C_DIM = "\033[2m"
    C_RESET = "\033[0m"
else:
    C_RED = C_GREEN = C_YELLOW = C_DIM = C_RESET = ""

RUST_LANG = Language(ts_rust.language())
PARSER = Parser(RUST_LANG)


# -----------------------------------------------------------------------------
# AST helpers
# -----------------------------------------------------------------------------


def node_text(node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _visibility_of(node, source: bytes) -> str:
    """Return the visibility modifier of a struct/enum node as a string.

    Returns '' (empty) for a private item, 'pub' for pub, 'pub(super)' etc.
    Tree-sitter puts visibility_modifier as the first child of struct_item
    when present.
    """
    for c in node.children:
        if c.type == "visibility_modifier":
            return node_text(c, source).strip()
    return ""


def _preceding_derives(node, source: bytes) -> list[str]:
    """Return the union of derive identifiers from every #[derive(...)]
    attribute that precedes this item, handling comment interleavings.
    """
    derives: list[str] = []
    sibling = node.prev_sibling
    while sibling is not None:
        if sibling.type == "attribute_item":
            txt = node_text(sibling, source)
            # Match `#[derive(...)]` and extract identifiers.
            # Use a simple state machine to avoid regex edge cases with
            # nested parens (rare in derive lists but possible with
            # `derive(serde::Serialize)`).
            stripped = txt.strip()
            if stripped.startswith("#[derive(") or stripped.startswith(
                "#![derive("
            ):
                # Find the matching close paren.
                open_idx = stripped.index("(")
                depth = 1
                i = open_idx + 1
                while i < len(stripped) and depth > 0:
                    if stripped[i] == "(":
                        depth += 1
                    elif stripped[i] == ")":
                        depth -= 1
                    i += 1
                inner = stripped[open_idx + 1 : i - 1]
                for raw in inner.split(","):
                    name = raw.strip()
                    # Handle paths like `serde::Serialize` — last segment.
                    if "::" in name:
                        name = name.rsplit("::", 1)[-1]
                    if name:
                        derives.append(name)
            sibling = sibling.prev_sibling
            continue
        if sibling.type in ("line_comment", "block_comment"):
            sibling = sibling.prev_sibling
            continue
        break
    return derives


# -----------------------------------------------------------------------------
# Scan
# -----------------------------------------------------------------------------


def find_declarations() -> list[tuple[str, int, str, list[str]]]:
    """Return every (rel_path, line, visibility, derives) for a
    struct/enum/type declaration named `OwnedIdentityDid`.
    """
    out: list[tuple[str, int, str, list[str]]] = []
    if not SCAN_DIR.is_dir():
        return out
    for root, _, files in os.walk(SCAN_DIR):
        for fname in files:
            if not fname.endswith(".rs"):
                continue
            full = Path(root) / fname
            rel = full.relative_to(REPO_ROOT).as_posix()
            source = full.read_bytes()
            tree = PARSER.parse(source)

            def walk(node) -> None:
                # struct, enum, or type alias named OwnedIdentityDid.
                if node.type in ("struct_item", "enum_item", "type_item"):
                    name_node = node.child_by_field_name("name")
                    if name_node is not None:
                        name = node_text(name_node, source)
                        if name == TYPE_NAME:
                            vis = _visibility_of(node, source)
                            derives = _preceding_derives(node, source)
                            out.append((rel, node.start_point[0] + 1, vis, derives))
                for c in node.children:
                    walk(c)

            walk(tree.root_node)
    return out


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------


def main() -> int:
    decls = find_declarations()
    if not decls:
        # Type does not yet exist — this is the pre-commit-5 state.
        print(
            f"{C_DIM}owned-identity-did check:{C_RESET} "
            f"type {TYPE_NAME!r} not declared yet "
            f"{C_DIM}(commit 5 of the actor PR introduces it){C_RESET}"
        )
        return 0

    fail = False

    # (A) Location check: all declarations must live at REQUIRED_PATH.
    for rel, line, _, _ in decls:
        if rel != REQUIRED_PATH:
            sys.stderr.write(
                f"{C_RED}FAIL{C_RESET}: {rel}:{line}: "
                f"{TYPE_NAME} must be declared in {REQUIRED_PATH}, "
                f"not {rel}. See ADR-049 §'Cross-identity isolation'.\n"
            )
            fail = True

    # (B) Visibility check: every declaration must be pub(super).
    for rel, line, vis, _ in decls:
        if vis != "pub(super)":
            sys.stderr.write(
                f"{C_RED}FAIL{C_RESET}: {rel}:{line}: "
                f"{TYPE_NAME} visibility is {vis or 'private'!r}; "
                f"must be 'pub(super)'. "
                f"'pub(crate)' lets any handler fabricate tokens; "
                f"'pub' leaks the capability to downstream crates.\n"
            )
            fail = True

    # (C) Derive check: no forbidden derives may be present.
    for rel, line, _, derives in decls:
        bad = [d for d in derives if d in FORBIDDEN_DERIVES]
        if bad:
            sys.stderr.write(
                f"{C_RED}FAIL{C_RESET}: {rel}:{line}: "
                f"{TYPE_NAME} has forbidden derive(s): {', '.join(sorted(set(bad)))}.\n"
                f"       Forbidden: {', '.join(sorted(FORBIDDEN_DERIVES))}.\n"
                f"       See ADR-049 §'Cross-identity isolation'.\n"
            )
            fail = True

    if fail:
        sys.stderr.write(
            f"\n{C_RED}owned-identity-did check FAILED{C_RESET} "
            f"({len(decls)} declaration(s) found).\n"
        )
        return 1

    print(
        f"{C_GREEN}owned-identity-did check PASSED{C_RESET}: "
        f"{len(decls)} declaration(s) in {REQUIRED_PATH}, "
        f"all pub(super), no forbidden derives."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
