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

  (D) A `#[derive(...)]` is not the only way to expand the interface.
      A manual `impl Trait for OwnedIdentityDid { ... }` block for any
      of the forbidden traits above has the same effect — the check
      flags manual impls by walking `impl_item` nodes.

  (E) Every field on the struct MUST be private (no `pub`,
      `pub(crate)`, or `pub(super)` on any field). A tuple-struct field
      like `struct OwnedIdentityDid(pub(crate) DidId)` lets handlers
      reach into the inner type and bypass the capability boundary.

  (F) The type MUST be a `struct` (or `enum`); a `type OwnedIdentityDid
      = Did` alias erases the nominal distinction and gives every
      consumer of `Did` equivalent power, defeating the capability.
      Type aliases named `OwnedIdentityDid` are banned outright.

The check PASSES SILENTLY if `OwnedIdentityDid` does not exist yet —
commit 5 of the actor refactor introduces the type. Until then, this
gate is a tripwire that fires the moment the type lands in the wrong
place or with the wrong shape.

---------------------------------------------------------------------------
SCOPE
---------------------------------------------------------------------------
Walks every `.rs` file under `crates/scp-runtime/src/` (including tests
and submodules). Finds every `struct OwnedIdentityDid` or `enum
OwnedIdentityDid` declaration, every `impl ... for OwnedIdentityDid`
block, and every `type OwnedIdentityDid = ...` alias.

---------------------------------------------------------------------------
SELF-TEST
---------------------------------------------------------------------------
Run with `--self-test` to exercise the scanner against a fixture file
that contains every known bypass pattern (manual impl, pub field,
type alias, wrong location, wrong visibility, forbidden derive). CI
runs `--self-test` before the real scan so the gate fails loudly if
the scanner is weakened.

Fixture: `scripts/tests/owned-identity-did-fixture.rs`.

---------------------------------------------------------------------------
USAGE
---------------------------------------------------------------------------
    python3.12 scripts/check-owned-identity-did.py
    python3.12 scripts/check-owned-identity-did.py --self-test

Exit codes:
    0  — type not yet declared, OR declared correctly
    1  — type is declared in the wrong file, with wrong visibility,
         with a forbidden derive / manual impl / public field, or as
         a type alias; OR --self-test did not catch all bypasses
    2  — invocation error

See ADR-049 for design context.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
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
FIXTURE_FILE = REPO_ROOT / "scripts" / "tests" / "owned-identity-did-fixture.rs"
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

# Forbidden manual-impl traits. This mirrors FORBIDDEN_DERIVES; any
# trait whose `derive` is banned is also banned via `impl`. The scanner
# also matches the common `impl Trait<...>` forms with a single type
# parameter (`From<Did>`, `Into<Did>`, `Borrow<str>`, etc.).
FORBIDDEN_IMPL_TRAITS = frozenset(FORBIDDEN_DERIVES)

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
# Struct field visibility
# -----------------------------------------------------------------------------


def _public_fields(node, source: bytes) -> list[tuple[int, str]]:
    """For a `struct_item`, return a list of (line, visibility_text) for
    every field whose visibility is NOT default-private.

    Handles both:
      - `struct S { pub(crate) field: T }`               named fields
      - `struct S(pub Did);`                             tuple fields
      - `struct S(pub(crate) Did, pub Did, Did);`        multi-field tuple
      - Unit struct `struct S;`                           — no fields

    Tree-sitter-rust grammar note (0.21+): named fields wrap each field
    in a `field_declaration` node inside `field_declaration_list`, with
    the `visibility_modifier` as a CHILD of `field_declaration`. Tuple
    fields, however, do NOT use an `ordered_field_declaration` wrapper —
    `ordered_field_declaration_list` has `visibility_modifier` and
    `type_identifier` (or other type nodes) as DIRECT children, separated
    by `,` punctuation. A `visibility_modifier` direct child of the list
    therefore marks a pub tuple field, even though there is no wrapper
    node to attach it to. Earlier versions of this scanner looked for an
    `ordered_field_declaration` wrapper and missed every tuple pub-field
    bypass such as `pub(super) struct OwnedIdentityDid(pub(crate) Did);`.
    """
    if node.type != "struct_item":
        return []
    publics: list[tuple[int, str]] = []
    body = node.child_by_field_name("body")
    if body is None:
        return []
    if body.type == "field_declaration_list":
        # Named fields: `{ field: T, pub(crate) field: T }`. The grammar
        # emits a `field_declaration` wrapper per field, with its own
        # `visibility_modifier` child for pub fields.
        for child in body.children:
            if child.type == "field_declaration":
                for grand in child.children:
                    if grand.type == "visibility_modifier":
                        publics.append(
                            (
                                child.start_point[0] + 1,
                                node_text(grand, source).strip(),
                            )
                        )
                        break
    elif body.type == "ordered_field_declaration_list":
        # Tuple fields: tree-sitter-rust 0.21+ emits
        #   `ordered_field_declaration_list` → (`(`, (`visibility_modifier`?, type_node, `,`?)*, `)`)
        # with NO `ordered_field_declaration` wrapper per field. Every
        # DIRECT `visibility_modifier` child of the list therefore
        # corresponds to exactly one pub tuple field. Record each one.
        for child in body.children:
            if child.type == "visibility_modifier":
                publics.append(
                    (
                        child.start_point[0] + 1,
                        node_text(child, source).strip(),
                    )
                )
    return publics


# -----------------------------------------------------------------------------
# Impl target detection
# -----------------------------------------------------------------------------


def _impl_for_owned_identity_did(
    impl_node, source: bytes
) -> tuple[str | None, int] | None:
    """If `impl_node` is `impl Trait for OwnedIdentityDid { ... }`,
    return (trait_name, line). If it's `impl OwnedIdentityDid { ... }`
    (inherent impl, not a trait impl), return (None, line). If it is
    not an impl targeting OwnedIdentityDid, return None.

    The `trait` field in tree-sitter-rust holds the trait; `type` holds
    the concrete target.
    """
    type_node = impl_node.child_by_field_name("type")
    if type_node is None:
        return None
    # Find the tail identifier of the type. For `OwnedIdentityDid` and
    # `OwnedIdentityDid<T>` (generic, shouldn't happen here but cheap
    # to support), the tail is a type_identifier.
    tail: str | None = None
    if type_node.type == "type_identifier":
        tail = node_text(type_node, source)
    elif type_node.type == "generic_type":
        t = type_node.child_by_field_name("type")
        if t is not None and t.type == "type_identifier":
            tail = node_text(t, source)
    elif type_node.type == "scoped_type_identifier":
        name = type_node.child_by_field_name("name")
        if name is not None:
            tail = node_text(name, source)
    if tail != TYPE_NAME:
        return None

    trait_node = impl_node.child_by_field_name("trait")
    if trait_node is None:
        return (None, impl_node.start_point[0] + 1)

    # Extract the trait name. Forms:
    #   `Clone`                          type_identifier
    #   `From<Did>`                       generic_type(name=From, ...)
    #   `std::borrow::Borrow<str>`        generic_type around scoped
    #   `serde::Serialize`                scoped_type_identifier
    trait_name: str | None = None
    if trait_node.type == "type_identifier":
        trait_name = node_text(trait_node, source)
    elif trait_node.type == "generic_type":
        t = trait_node.child_by_field_name("type")
        if t is not None:
            if t.type == "type_identifier":
                trait_name = node_text(t, source)
            elif t.type == "scoped_type_identifier":
                name = t.child_by_field_name("name")
                if name is not None:
                    trait_name = node_text(name, source)
    elif trait_node.type == "scoped_type_identifier":
        name = trait_node.child_by_field_name("name")
        if name is not None:
            trait_name = node_text(name, source)
    return (trait_name, impl_node.start_point[0] + 1)


# -----------------------------------------------------------------------------
# Scan
# -----------------------------------------------------------------------------


def _scan_root(scan_dir: Path, repo_root: Path) -> tuple[
    list[tuple[str, int, str, list[str], list[tuple[int, str]], str]],
    list[tuple[str, int, str | None]],
]:
    """Walk scan_dir and return (decls, impls).

    decls: list of (rel_path, line, visibility, derives, public_fields,
                    kind) where kind is 'struct' | 'enum' | 'type_alias'.
    impls: list of (rel_path, line, trait_name) where trait_name is None
           for inherent impls (which are permitted) and non-None for
           trait impls (which are rejected if the trait is forbidden).
    """
    decls: list[tuple[str, int, str, list[str], list[tuple[int, str]], str]] = []
    impls: list[tuple[str, int, str | None]] = []
    if not scan_dir.is_dir():
        return decls, impls
    for root, _, files in os.walk(scan_dir):
        for fname in files:
            if not fname.endswith(".rs"):
                continue
            full = Path(root) / fname
            rel = full.relative_to(repo_root).as_posix()
            source = full.read_bytes()
            tree = PARSER.parse(source)

            def walk(node) -> None:
                if node.type in ("struct_item", "enum_item", "type_item"):
                    name_node = node.child_by_field_name("name")
                    if name_node is not None:
                        name = node_text(name_node, source)
                        if name == TYPE_NAME:
                            vis = _visibility_of(node, source)
                            derives = _preceding_derives(node, source)
                            pubs = _public_fields(node, source)
                            kind = {
                                "struct_item": "struct",
                                "enum_item": "enum",
                                "type_item": "type_alias",
                            }[node.type]
                            decls.append(
                                (
                                    rel,
                                    node.start_point[0] + 1,
                                    vis,
                                    derives,
                                    pubs,
                                    kind,
                                )
                            )
                if node.type == "impl_item":
                    hit = _impl_for_owned_identity_did(node, source)
                    if hit is not None:
                        trait_name, line = hit
                        impls.append((rel, line, trait_name))
                for c in node.children:
                    walk(c)

            walk(tree.root_node)
    return decls, impls


def find_declarations():
    return _scan_root(SCAN_DIR, REPO_ROOT)


# -----------------------------------------------------------------------------
# Enforcement
# -----------------------------------------------------------------------------


def _enforce(
    decls: list[tuple[str, int, str, list[str], list[tuple[int, str]], str]],
    impls: list[tuple[str, int, str | None]],
    required_path: str,
    stream=sys.stderr,
) -> bool:
    """Apply checks A-F. Returns True on FAIL, False on PASS. Writes
    diagnostics to `stream`. Caller must decide exit code and final
    messaging.
    """
    fail = False

    # (F) Type alias ban. Runs FIRST because an alias invalidates all
    # other checks on that declaration.
    for rel, line, _, _, _, kind in decls:
        if kind == "type_alias":
            stream.write(
                f"{C_RED}FAIL{C_RESET}: {rel}:{line}: "
                f"{TYPE_NAME} is declared as a `type` alias; it MUST be "
                f"a `struct` (or `enum`). A type alias erases the nominal "
                f"distinction and defeats the capability. "
                f"See ADR-049 §'Cross-identity isolation'.\n"
            )
            fail = True

    # (A) Location: every decl must live at REQUIRED_PATH.
    for rel, line, _, _, _, _ in decls:
        if rel != required_path:
            stream.write(
                f"{C_RED}FAIL{C_RESET}: {rel}:{line}: "
                f"{TYPE_NAME} must be declared in {required_path}, "
                f"not {rel}. See ADR-049 §'Cross-identity isolation'.\n"
            )
            fail = True

    # (B) Visibility: pub(super) only.
    for rel, line, vis, _, _, _ in decls:
        if vis != "pub(super)":
            stream.write(
                f"{C_RED}FAIL{C_RESET}: {rel}:{line}: "
                f"{TYPE_NAME} visibility is {vis or 'private'!r}; "
                f"must be 'pub(super)'. "
                f"'pub(crate)' lets any handler fabricate tokens; "
                f"'pub' leaks the capability to downstream crates.\n"
            )
            fail = True

    # (C) Forbidden derives.
    for rel, line, _, derives, _, _ in decls:
        bad = [d for d in derives if d in FORBIDDEN_DERIVES]
        if bad:
            stream.write(
                f"{C_RED}FAIL{C_RESET}: {rel}:{line}: "
                f"{TYPE_NAME} has forbidden derive(s): {', '.join(sorted(set(bad)))}.\n"
                f"       Forbidden: {', '.join(sorted(FORBIDDEN_DERIVES))}.\n"
                f"       See ADR-049 §'Cross-identity isolation'.\n"
            )
            fail = True

    # (D) Manual impls of forbidden traits.
    for rel, line, trait_name in impls:
        if trait_name is None:
            # Inherent impl (`impl OwnedIdentityDid { ... }`). Allowed —
            # this is where the constructor lives.
            continue
        if trait_name in FORBIDDEN_IMPL_TRAITS:
            stream.write(
                f"{C_RED}FAIL{C_RESET}: {rel}:{line}: "
                f"manual `impl {trait_name} for {TYPE_NAME}` — this trait "
                f"is forbidden (same semantics as a banned derive). "
                f"Forbidden: {', '.join(sorted(FORBIDDEN_IMPL_TRAITS))}. "
                f"See ADR-049 §'Cross-identity isolation'.\n"
            )
            fail = True

    # (E) Public fields on struct.
    for rel, line, _, _, pubs, kind in decls:
        if kind != "struct":
            continue
        for field_line, vis in pubs:
            stream.write(
                f"{C_RED}FAIL{C_RESET}: {rel}:{field_line}: "
                f"{TYPE_NAME} has a public field with visibility "
                f"{vis!r}. All fields MUST be private. A {vis} field on "
                f"this type lets handlers reach the inner DidId and "
                f"bypass the capability boundary. "
                f"See ADR-049 §'Cross-identity isolation'.\n"
            )
            fail = True

    return fail


# -----------------------------------------------------------------------------
# Self-test
# -----------------------------------------------------------------------------


# Descriptor: (label, substring-in-stderr). Each entry names a distinct
# enforcement failure mode that MUST be triggered by the fixture. The
# substring is matched against the captured stderr diagnostics from
# `_enforce`. If a bypass fixture doesn't surface the expected
# substring, the scanner has regressed on that mode.
REQUIRED_FIXTURE_FAILURES: list[tuple[str, str]] = [
    ("forbidden_derive", "forbidden derive"),
    ("manual_impl_clone", "manual `impl Clone"),
    ("manual_impl_from", "manual `impl From"),
    # Named-struct public field — the fixture's named-struct case uses
    # `pub(crate)`. Asserts the field_declaration_list path still works.
    ("public_named_field", "public field with visibility 'pub(crate)'"),
    # Tuple-struct public field — the fixture's tuple-struct case uses
    # `pub(super)`. Asserts the NEW tuple-field detection (direct
    # `visibility_modifier` children of `ordered_field_declaration_list`,
    # no wrapper) catches `struct OwnedIdentityDid(pub(super) Did);`.
    # Before the tree-sitter-rust 0.21+ fix, this was silently missed.
    ("public_tuple_field", "public field with visibility 'pub(super)'"),
    ("type_alias", "declared as a `type` alias"),
    ("wrong_visibility", "visibility is"),
    ("wrong_location", "must be declared in"),
]


def do_self_test() -> int:
    """Compile the bypass fixture into a temp `crates/scp-runtime/src/`
    layout, run the scanner, and assert every known bypass surfaces as
    a failure.

    The fixture contains multiple declarations and impls across both
    the required-path location (to trigger visibility/derive/impl/field
    failures) and a wrong location (to trigger the location check). The
    scanner re-runs with `scan_dir` rooted at the temp location.
    """
    if not FIXTURE_FILE.is_file():
        sys.stderr.write(
            f"{C_RED}error:{C_RESET} fixture missing: {FIXTURE_FILE}\n"
        )
        return 2

    # Stage the fixture into a temp directory matching the real layout.
    # The fixture file declares the required path `…/supervisor/identity_capability.rs`
    # AND a wrong-location file `…/context/handlers/bad.rs`. Split the
    # fixture by a sentinel at compile time.
    fixture_text = FIXTURE_FILE.read_text()
    # Sentinel-driven split: each file block begins with
    #     // @file: <rel-path-under-scp-runtime-src>
    # on its own line. The block runs until the next @file: or EOF.
    blocks: dict[str, list[str]] = {}
    current: list[str] | None = None
    current_name: str | None = None
    for line in fixture_text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith("// @file:"):
            if current is not None and current_name is not None:
                blocks[current_name] = current
            current_name = stripped[len("// @file:") :].strip()
            current = []
            continue
        if current is not None:
            current.append(line)
    if current is not None and current_name is not None:
        blocks[current_name] = current

    if not blocks:
        sys.stderr.write(
            f"{C_RED}self-test FAILED{C_RESET}: fixture has no `// @file:` "
            f"blocks.\n"
        )
        return 1

    import io

    with tempfile.TemporaryDirectory() as tmp:
        tmp_root = Path(tmp)
        src_root = tmp_root / "crates" / "scp-runtime" / "src"
        for rel_under_src, lines in blocks.items():
            dst = src_root / rel_under_src
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text("".join(lines))

        # Reconfigure to point at the fixture temp root.
        fx_scan = src_root
        fx_required = "crates/scp-runtime/src/context/supervisor/identity_capability.rs"
        decls, impls = _scan_root(fx_scan, tmp_root)
        # Capture stderr to inspect.
        buf = io.StringIO()
        fail = _enforce(decls, impls, fx_required, stream=buf)
        diag = buf.getvalue()

    if not fail:
        sys.stderr.write(
            f"{C_RED}self-test FAILED{C_RESET}: fixture did NOT trigger "
            f"any enforcement failure — scanner is broken or fixture is "
            f"wrong.\n"
        )
        return 1

    missing: list[str] = []
    for label, substr in REQUIRED_FIXTURE_FAILURES:
        if substr not in diag:
            missing.append(f"{label}: expected substring {substr!r} not in diagnostics")

    if missing:
        sys.stderr.write(
            f"{C_RED}self-test FAILED{C_RESET}: "
            f"{len(missing)} bypass pattern(s) not detected:\n"
        )
        for m in missing:
            sys.stderr.write(f"  - {m}\n")
        sys.stderr.write("\nActual diagnostics:\n")
        sys.stderr.write(diag)
        return 1

    print(
        f"{C_GREEN}owned-identity-did self-test PASSED{C_RESET}: "
        f"fixture triggered {len(REQUIRED_FIXTURE_FAILURES)} distinct "
        f"enforcement modes (derive, manual-impl Clone + From, "
        f"public named field, public tuple field, type alias, "
        f"wrong visibility, wrong location)."
    )
    return 0


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "AST check for OwnedIdentityDid capability invariants (ADR-049). "
            "Pre-commit-5 this passes silently."
        )
    )
    ap.add_argument("--self-test", action="store_true", help="run fixture self-test")
    args = ap.parse_args()

    if args.self_test:
        return do_self_test()

    decls, impls = find_declarations()
    if not decls and not impls:
        # Type does not yet exist — this is the pre-commit-5 state.
        print(
            f"{C_DIM}owned-identity-did check:{C_RESET} "
            f"type {TYPE_NAME!r} not declared yet "
            f"{C_DIM}(commit 5 of the actor PR introduces it){C_RESET}"
        )
        return 0

    fail = _enforce(decls, impls, REQUIRED_PATH, stream=sys.stderr)

    if fail:
        sys.stderr.write(
            f"\n{C_RED}owned-identity-did check FAILED{C_RESET} "
            f"({len(decls)} declaration(s), {len(impls)} impl(s) found).\n"
        )
        return 1

    print(
        f"{C_GREEN}owned-identity-did check PASSED{C_RESET}: "
        f"{len(decls)} declaration(s) in {REQUIRED_PATH}, "
        f"all pub(super), no forbidden derives, no forbidden impls, "
        f"no public fields, not a type alias."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
