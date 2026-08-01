#!/usr/bin/env python3.12
# ruff: noqa: E501
"""AST check: enforce `BridgeInstanceCore` default-method lifecycle contract.

---------------------------------------------------------------------------
PREREQUISITES
---------------------------------------------------------------------------
    pip install tree-sitter tree-sitter-rust

Python 3.12+. Runs offline; no network access required.

---------------------------------------------------------------------------
WHAT THIS CHECKS
---------------------------------------------------------------------------
The actor refactor (ADR-049) defines `suspend`, `resume`, and `shutdown`
as DEFAULT methods on the `BridgeInstanceCore` trait. Per-bridge concrete
structs (`PyBridgeInstance`, `NapiBridgeInstance`, `UniffiBridgeInstance`)
inherit the default implementations and override only the bridge-specific
extension points (`pre_suspend_hook`, `post_suspend_hook`,
`pre_shutdown_hook`, `post_shutdown_hook`). This eliminates the
cross-bridge drift flagged by PR #1543.

This check scans the three bridge source trees and flags any `impl` block
that defines `fn suspend`, `fn resume`, or `fn shutdown` on any of the
three concrete bridge types. Extension-hook overrides are allowed.

---------------------------------------------------------------------------
ACTIVATION
---------------------------------------------------------------------------
The check "kicks in" only once `BridgeInstanceCore` defines DEFAULT
bodies for all three lifecycle methods (`suspend`, `resume`, `shutdown`).
Today the trait provides defaults for `suspend` and `resume`, but
`shutdown` is abstract (each bridge implements its own variant). When
commit 6 of the actor refactor lands, `shutdown` gains a default body
too — and at that moment the per-bridge impls become drift, which is
exactly what this check catches.

Pre-commit-6: the check notices that `shutdown` has no default on the
trait and passes silently (bridges MUST impl `shutdown` locally). Once
all three methods are defaults, it enforces the ban on per-bridge
overrides. This avoids a failing gate during commit 3 while keeping
the enforcement teeth for commit 6 onward.

The check also passes silently if none of the three bridge types exist
yet.

FAIL-LOUD: if the trait `BridgeInstanceCore` cannot be found anywhere
under the known bridge roots (see BRIDGE_ROOTS below), the check EXITS
1 with a diagnostic. A silent-pass on a missing trait would let a
rename or relocation invalidate the gate without detection.

---------------------------------------------------------------------------
SCOPE
---------------------------------------------------------------------------
Walks every `.rs` file under:

  - crates/scp-ffi/src/         (PyO3)
  - crates/scp-ffi/napi/src/    (NAPI)
  - crates/scp-ffi/uniffi/src/  (UniFFI)
  - crates/scp-ffi/common/src/  (shared bridge core)

For each file, parses to tree-sitter AST and walks `impl_item` nodes.
For every impl whose type is one of the forbidden types, flags any
method declaration whose name is `suspend`, `resume`, or `shutdown`.

---------------------------------------------------------------------------
USAGE
---------------------------------------------------------------------------
    python3.12 scripts/check-bridge-instance-lifecycle.py

Exit codes:
    0  — no per-bridge lifecycle override found
    1  — one or more bridges re-implement a lifecycle method
    2  — invocation error

See ADR-049 §"BridgeInstance actor integration" for the lifecycle
contract.
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

# Per-bridge source roots. Every `.rs` in these directories is scanned.
BRIDGE_ROOTS = [
    REPO_ROOT / "crates" / "scp-ffi" / "src",
    REPO_ROOT / "crates" / "scp-ffi" / "napi" / "src",
    REPO_ROOT / "crates" / "scp-ffi" / "uniffi" / "src",
    REPO_ROOT / "crates" / "scp-ffi" / "common" / "src",
]

# Types whose `impl` blocks must NOT redefine lifecycle methods.
FORBIDDEN_IMPL_TYPES = frozenset(
    {
        "PyBridgeInstance",
        "NapiBridgeInstance",
        "UniffiBridgeInstance",
    }
)

# Method names that must come from the `BridgeInstanceCore` default.
LIFECYCLE_METHODS = frozenset({"suspend", "resume", "shutdown"})

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


def _impl_target_type_name(impl_node, source: bytes) -> str | None:
    """Return the name of the type being impl'd.

    Tree-sitter `impl_item`:
      - inherent impl:  `impl Foo { ... }`   — `type` field = Foo
      - trait impl:     `impl Trait for Foo` — `trait` field = Trait,
                                                `type` field = Foo

    We care about the concrete type (Foo in both forms). Tree-sitter
    exposes it on field "type".
    """
    type_node = impl_node.child_by_field_name("type")
    if type_node is None:
        return None
    # For generics like `Foo<T>`, grab the base identifier.
    # Walk down to the first identifier / type_identifier.
    return _leading_identifier(type_node, source)


def _leading_identifier(node, source: bytes) -> str | None:
    """Return the first identifier/type_identifier token within `node`."""
    if node.type in ("type_identifier", "identifier"):
        return node_text(node, source)
    # generic_type: <base>::<generics>. Use the 'type' field.
    for field in ("type",):
        t = node.child_by_field_name(field)
        if t is not None:
            r = _leading_identifier(t, source)
            if r is not None:
                return r
    # Fall back: first child that is an identifier.
    for c in node.children:
        r = _leading_identifier(c, source)
        if r is not None:
            return r
    return None


def _types_found_anywhere() -> set[str]:
    """Return the set of FORBIDDEN_IMPL_TYPES names that appear as a
    struct/enum declaration anywhere in the bridge trees. Used to decide
    whether we're in the pre-commit state (silent pass) or not.
    """
    found: set[str] = set()
    for root in BRIDGE_ROOTS:
        if not root.is_dir():
            continue
        for dirpath, _, files in os.walk(root):
            for fname in files:
                if not fname.endswith(".rs"):
                    continue
                full = Path(dirpath) / fname
                source = full.read_bytes()
                tree = PARSER.parse(source)

                def walk(node) -> None:
                    if node.type in ("struct_item", "enum_item"):
                        name = node.child_by_field_name("name")
                        if name is not None:
                            nm = node_text(name, source)
                            if nm in FORBIDDEN_IMPL_TYPES:
                                found.add(nm)
                    for c in node.children:
                        walk(c)

                walk(tree.root_node)
    return found


def _trait_methods_with_defaults(trait_name: str) -> tuple[set[str], bool]:
    """Return (defaults, trait_found) for the named trait, across the
    bridge source trees.

    `defaults` is the set of method names that have DEFAULT bodies (i.e.
    `function_item` with a `body` child inside the trait body).
    `trait_found` is True iff at least one `trait <name>` declaration
    was seen ANYWHERE in the bridge trees — it is independent of
    whether any method has a default.

    A trait method has a default body iff its function_signature_item
    has a `body` child (in tree-sitter Rust grammar, `function_item`
    with a body is the default form; `function_signature_item` is
    abstract).
    """
    defaults: set[str] = set()
    trait_found = False
    for root in BRIDGE_ROOTS:
        if not root.is_dir():
            continue
        for dirpath, _, files in os.walk(root):
            for fname in files:
                if not fname.endswith(".rs"):
                    continue
                full = Path(dirpath) / fname
                source = full.read_bytes()
                tree = PARSER.parse(source)

                def walk(node) -> None:
                    nonlocal trait_found
                    if node.type == "trait_item":
                        name_node = node.child_by_field_name("name")
                        if (
                            name_node is not None
                            and node_text(name_node, source) == trait_name
                        ):
                            trait_found = True
                            body = node.child_by_field_name("body")
                            if body is not None:
                                for item in body.children:
                                    if item.type == "function_item":
                                        # function_item WITH a body = default method
                                        fn_name_node = item.child_by_field_name("name")
                                        fn_body = item.child_by_field_name("body")
                                        if (
                                            fn_name_node is not None
                                            and fn_body is not None
                                        ):
                                            defaults.add(
                                                node_text(fn_name_node, source)
                                            )
                                    # function_signature_item = abstract method (no default)
                    for c in node.children:
                        walk(c)

                walk(tree.root_node)
    return (defaults, trait_found)


def find_violations() -> list[tuple[str, int, str, str]]:
    """Return (rel_path, line, type_name, method_name) for each
    offending method impl.
    """
    out: list[tuple[str, int, str, str]] = []
    for root in BRIDGE_ROOTS:
        if not root.is_dir():
            continue
        for dirpath, _, files in os.walk(root):
            for fname in files:
                if not fname.endswith(".rs"):
                    continue
                full = Path(dirpath) / fname
                rel = full.relative_to(REPO_ROOT).as_posix()
                source = full.read_bytes()
                tree = PARSER.parse(source)

                def walk(node) -> None:
                    if node.type == "impl_item":
                        type_name = _impl_target_type_name(node, source)
                        if type_name in FORBIDDEN_IMPL_TYPES:
                            # Walk the declaration_list body for function_item nodes.
                            body = node.child_by_field_name("body")
                            if body is not None:
                                for item in body.children:
                                    if item.type == "function_item":
                                        name_node = item.child_by_field_name("name")
                                        if name_node is not None:
                                            fn_name = node_text(name_node, source)
                                            if fn_name in LIFECYCLE_METHODS:
                                                out.append(
                                                    (
                                                        rel,
                                                        item.start_point[0] + 1,
                                                        type_name,
                                                        fn_name,
                                                    )
                                                )
                    # Recurse into nested impls (rare but possible in macros).
                    for c in node.children:
                        walk(c)

                walk(tree.root_node)
    return out


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------


def main() -> int:
    # (1) Locate the BridgeInstanceCore trait anywhere in the bridge
    # trees. If it is missing entirely, fail loudly — a silent-pass on
    # "trait moved" is a real risk: the trait could be renamed or
    # relocated and the lifecycle-override ban would evaporate.
    trait_defaults, trait_found = _trait_methods_with_defaults("BridgeInstanceCore")
    if not trait_found:
        sys.stderr.write(
            f"{C_RED}error:{C_RESET} trait `BridgeInstanceCore` not found "
            f"in any known bridge path.\n"
        )
        sys.stderr.write("Searched roots:\n")
        for r in BRIDGE_ROOTS:
            sys.stderr.write(f"  - {r}\n")
        sys.stderr.write(
            "\nIf the trait has been renamed or relocated, update\n"
            "`BRIDGE_ROOTS` in this script AND rename the trait\n"
            "constant below. Silent-pass behavior on a missing trait\n"
            "would let the lifecycle-override ban evaporate — we do NOT\n"
            "tolerate that. See ADR-049 §'BridgeInstance actor integration'.\n"
        )
        return 1

    present = _types_found_anywhere()
    if not present:
        print(
            f"{C_DIM}bridge-instance-lifecycle check:{C_RESET} "
            f"none of {{{', '.join(sorted(FORBIDDEN_IMPL_TYPES))}}} exist yet "
            f"{C_DIM}(commit 6 of the actor PR + cozy-fluttering-rose Phase 4 introduce them){C_RESET}"
        )
        return 0

    # (2) Check that all three lifecycle methods have DEFAULT bodies on
    # BridgeInstanceCore. If any is still abstract, the check does not
    # kick in — bridges are REQUIRED to implement the abstract ones,
    # and flagging those as "drift" would be a false positive.
    missing_defaults = LIFECYCLE_METHODS - trait_defaults
    if missing_defaults:
        print(
            f"{C_DIM}bridge-instance-lifecycle check:{C_RESET} "
            f"trait `BridgeInstanceCore` has no default for "
            f"{{{', '.join(sorted(missing_defaults))}}} — bridges must impl "
            f"locally. {C_DIM}Check activates when commit 6 lands the defaults.{C_RESET}"
        )
        return 0

    violations = find_violations()
    if violations:
        sys.stderr.write(
            f"{C_RED}FAIL{C_RESET}: per-bridge concrete type re-implements a "
            f"lifecycle method that is a `BridgeInstanceCore` default.\n"
        )
        sys.stderr.write(
            f"       Lifecycle methods (suspend/resume/shutdown) belong on\n"
            f"       the trait as default methods. Bridges override only the\n"
            f"       extension hooks (pre_*_hook / post_*_hook).\n"
            f"       See ADR-049 §'BridgeInstance actor integration'.\n\n"
        )
        for rel, line, type_name, fn_name in violations:
            sys.stderr.write(
                f"  {C_DIM}{rel}:{line}{C_RESET}  "
                f"impl {C_YELLOW}{type_name}{C_RESET} "
                f"{{ fn {C_RED}{fn_name}{C_RESET}(...) }}\n"
            )
        sys.stderr.write(
            f"\n{C_RED}bridge-instance-lifecycle check FAILED{C_RESET} "
            f"({len(violations)} violation(s)).\n"
        )
        return 1

    print(
        f"{C_GREEN}bridge-instance-lifecycle check PASSED{C_RESET}: "
        f"types {{{', '.join(sorted(present))}}} inherit default suspend/resume/shutdown."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
