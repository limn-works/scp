#!/usr/bin/env python3.12
# ruff: noqa: E501
"""Frozen-shape positive-whitelist gate for the `OwnedIdentityDid` capability token.

`OwnedIdentityDid` (ADR-049 §5, spec §9.4.1) is a capability token proving an
actor's identity owns it. Its unforgeability is enforced BY THE TYPE SYSTEM: the
sole arbitrary-`DID` constructor `issue_for_actor` is `pub(super)`, the `did`
field is private (so no struct literal outside the defining module), the crate
is `#![forbid(unsafe_code)]`, and the supervisor module is
`#![deny(unsafe_code)]`. No compiling, type-system-evading forgery reachable
from outside the module exists — the boundary holds without any gate.

This gate is DEFENSE-IN-DEPTH ONLY. It asserts that
`crates/scp-runtime/src/context/supervisor/identity_capability.rs` matches a
FROZEN DEFINITION SHAPE via a POSITIVE item / attribute / signature WHITELIST:
it enumerates the file's module-level items and rejects ANY item kind that is
not on the small permitted list, then asserts the exact shape of the one struct
and the one inherent impl. Because every check is a positive assertion about the
DEFINITION, deviations are rejected BY CONSTRUCTION — there is no per-forgery
denylist to extend, so the gate is convergent (closed by construction) rather
than the non-convergent denylist-by-name it replaced.

What makes the positive whitelist sound where a denylist was not: the prior
design banned forgeries by matching their NAME (e.g. "an fn literally named
`forge`"), which a Rust `type` alias (`type Cap = OwnedIdentityDid;`) or a
path-qualified impl (`impl self::OwnedIdentityDid`) or a `///` doc-comment
interleaved before a `#[derive(Clone)]` could all evade. The positive whitelist
instead rejects forgeries by their ITEM KIND and exact grammar shape: a stray
`type_item`, a second `impl_item`, a `#[derive(...)]` anywhere on the struct —
none of these are on the permitted list, so aliasing / path-qualification /
comment-interleaving cannot evade them.

Construction confinement — that a token can only be minted via `issue_for_actor`
or a struct literal INSIDE this module — is guaranteed by the TYPE SYSTEM
(`pub(super)` constructor + private field + `deny(unsafe_code)`), NOT by
source-text analysis. THEREFORE THIS GATE DOES NOT AND WILL NOT INSPECT ANY CALL
SITE, BUILD SITE, OR MINT ARGUMENT, nor approximate the compiler's own
scope-and-binding analysis in an AST walker. That whole class of USE-SITE name
resolution is the compiler's job; the relevant lesson under `.docs/lessons/`
records why approximating it in tree-sitter is an unbounded arms race and was
deleted. The line drawn here is: bounded definition-SIDE shape assertions over a
single file are sound and kept; use-site name resolution is forbidden.

COMPLETE CHECK SET (definition shape only), scanning identity_capability.rs:
  A1. Module-item whitelist (the categorical closer). The ONLY permitted
      module-level item kinds are: any number of `use_declaration`; EXACTLY ONE
      `struct_item` named `OwnedIdentityDid`; EXACTLY ONE inherent `impl_item`
      targeting `OwnedIdentityDid`; EXACTLY ONE `mod_item` named `tests`
      carrying `#[cfg(test)]`. ANY other module-level item (`type_item`, a
      second struct/enum/union, a free `function_item`, a second `impl_item`
      — trait or path-qualified inherent, a `trait_item`, `const_item`,
      `static_item`, `macro_definition`/`macro_invocation`, extra `mod_item`)
      is REJECTED by KIND, never by name — so aliasing / path-qualification
      cannot evade it.
  A2. The one struct's exact shape: name-visibility EXACTLY
      `pub(in crate::context)`; exactly one field `did`, PRIVATE; field type
      `DID`. Every attribute on the struct (read from the grammar, SKIPPING
      interleaved comments) must be a BARE single-segment inert built-in
      (`allow` / `cfg` / `doc`); any `derive` or any path-qualified /
      proc-macro / unknown attribute is rejected.
  A3. The one impl's exact shape: it is INHERENT (no trait); its target, after
      stripping any leading path to the final segment, is `OwnedIdentityDid`;
      it contains EXACTLY {issue_for_actor, reissue, as_did} — no more, no
      fewer. Per-method exact signature: `issue_for_actor` is `pub(super)`,
      ONE by-value param, returns `Self`/`OwnedIdentityDid`; `reissue` is
      `pub(in crate::context)`, params EXACTLY `&self`, returns
      `Self`/`OwnedIdentityDid`; `as_did` is `pub(in crate::context)`, params
      EXACTLY `&self`, returns `&DID`. Each method's attributes must be inert
      built-ins (`allow` / `must_use` / `cfg` / `inline` / `doc`).
  A4. No construction outside the allowlisted method bodies (belt-and-braces
      on top of A1's ban on free fns / aliases).
  A5. `deny(unsafe_code)` / `forbid(unsafe_code)` present in `supervisor/mod.rs`
      via REAL inner-attribute parse — a commented-out or string occurrence
      does NOT satisfy it; extra lints (`deny(unsafe_code, missing_docs)`) DO.

PREREQUISITES: pip install tree-sitter tree-sitter-rust (already in CI).
Python 3.12+, offline.

USAGE:
    python3.12 scripts/check-owned-identity-did.py             # real scan
    python3.12 scripts/check-owned-identity-did.py --self-test  # fixtures

Exit 0 = shape valid. Exit 1 = a definition-shape violation. Exit 2 =
environment error.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_FILE = REPO_ROOT / "scripts" / "tests" / "owned-identity-did-fixture.rs"

# Subtree scanned only to locate the canonical files.
SUPERVISOR_SUBTREE = (
    REPO_ROOT / "crates" / "scp-runtime" / "src" / "context" / "supervisor"
)
# The one file whose definition shape is asserted.
CAP_FILE = SUPERVISOR_SUBTREE / "identity_capability.rs"
# The file that must carry deny(unsafe_code).
MOD_FILE = SUPERVISOR_SUBTREE / "mod.rs"

TYPE_NAME = "OwnedIdentityDid"
REQUIRED_STRUCT_VIS = "pub(in crate::context)"
ALLOWED_METHODS = ("issue_for_actor", "reissue", "as_did")

# Inert, bare, single-segment built-in attributes the gate tolerates. Anything
# not in these sets — a `derive`, a path-qualified attr, a proc-macro attr — is
# rejected by construction (A2 / A3). `derive` is deliberately ABSENT: the real
# struct has none, so the simplest sound rule is to reject any derive outright,
# which closes `#[derive(Clone)]` (and every other forbidden derive) without a
# per-trait denylist.
STRUCT_INERT_ATTRS = frozenset({"allow", "cfg", "doc"})
METHOD_INERT_ATTRS = frozenset({"allow", "must_use", "cfg", "inline", "doc"})

# Named only to make rejection messages actionable; the actual rule (A2) is
# "any derive is rejected", not a denylist lookup.
FORBIDDEN_DERIVES_FOR_MESSAGE = (
    "Clone, Copy, Serialize, Deserialize, Default, From, Into, Hash, "
    "PartialEq, Eq, PartialOrd, Ord, Borrow, AsRef, Deref, Debug, Display"
)

try:
    import tree_sitter_rust
    from tree_sitter import Language, Node, Parser
except ImportError as exc:  # pragma: no cover - environment guard
    sys.stderr.write(
        "error: tree-sitter / tree-sitter-rust not installed.\n"
        "       pip install tree-sitter tree-sitter-rust\n"
        f"       ({exc})\n"
    )
    sys.exit(2)

_RUST = Language(tree_sitter_rust.language())

C_RED = "\033[31m"
C_GREEN = "\033[32m"
C_RESET = "\033[0m"


def _parser() -> Parser:
    p = Parser()
    p.language = _RUST
    return p


def _text(node: Node, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _norm_vis(node: Node | None, src: bytes) -> str:
    """Normalized visibility string ("" for inherited-private)."""
    if node is None:
        return ""
    return " ".join(_text(node, src).split())


def _vis_node(node: Node) -> Node | None:
    """First `visibility_modifier` child of any item (struct / fn / field).

    Single DRY accessor: in tree-sitter-rust a struct's, function's, and
    field's visibility are each the first `visibility_modifier` child of the
    respective item node.
    """
    for child in node.children:
        if child.type == "visibility_modifier":
            return child
    return None


def _struct_name(struct: Node, src: bytes) -> str:
    name = struct.child_by_field_name("name")
    return _text(name, src) if name is not None else ""


def _final_type_segment(text: str) -> str:
    """Final path segment of a (possibly path-qualified, possibly generic) type.

    `self::OwnedIdentityDid` -> `OwnedIdentityDid`;
    `crate::context::OwnedIdentityDid` -> `OwnedIdentityDid`;
    `OwnedIdentityDid<T>` -> `OwnedIdentityDid`.
    """
    base = text.split("<", 1)[0].strip()
    return base.split("::")[-1].strip() if base else ""


def _impl_type_name(impl_item: Node, src: bytes) -> str:
    t = impl_item.child_by_field_name("type")
    return _final_type_segment(_text(t, src)) if t is not None else ""


def _impl_trait_name(impl_item: Node, src: bytes) -> str | None:
    tr = impl_item.child_by_field_name("trait")
    if tr is None:
        return None
    return _final_type_segment(_text(tr, src))


def _fn_name(fn: Node, src: bytes) -> str:
    n = fn.child_by_field_name("name")
    return _text(n, src) if n is not None else ""


def _mod_name(mod: Node, src: bytes) -> str:
    n = mod.child_by_field_name("name")
    return _text(n, src) if n is not None else ""


def _fn_params(fn: Node) -> Node | None:
    return fn.child_by_field_name("parameters")


def _fn_param_kinds(fn: Node) -> list[str]:
    """Ordered list of the function's actual parameter node kinds.

    Returns the sequence of `self_parameter` / `parameter` (and any other
    parameter-bearing node kind) in declaration order, ignoring punctuation.
    """
    params = _fn_params(fn)
    if params is None:
        return []
    return [c.type for c in params.children if c.type not in ("(", ")", ",")]


def _fn_return_text(fn: Node, src: bytes) -> str:
    ret = fn.child_by_field_name("return_type")
    return " ".join(_text(ret, src).split()) if ret is not None else ""


def _walk(node: Node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


# --- Attribute grammar helpers (read from the tree, not from adjacency) ------


def _preceding_attr_items(item: Node) -> list[Node]:
    """`attribute_item` siblings that decorate `item`.

    In tree-sitter-rust, outer attributes are SEPARATE `attribute_item`
    siblings preceding the item within the same parent. Crucially, comments
    (`line_comment` / `block_comment`, including `///` doc-comments) also
    appear as siblings and may be INTERLEAVED between an attribute and its
    item. We therefore walk backwards SKIPPING comments rather than stopping
    at the first non-attribute sibling — so a `///` doc-comment cannot hide a
    `#[derive(Clone)]` from the check.
    """
    parent = item.parent
    if parent is None:
        return []
    siblings = parent.children
    try:
        idx = siblings.index(item)
    except ValueError:
        return []
    attrs: list[Node] = []
    j = idx - 1
    while j >= 0:
        sib = siblings[j]
        if sib.type == "attribute_item":
            attrs.append(sib)
        elif sib.type in ("line_comment", "block_comment"):
            pass  # skip interleaved comments — do NOT stop the run
        else:
            break
        j -= 1
    return attrs


def _attr_node(attr_item: Node) -> Node | None:
    """The inner `attribute` node of an `#[..]` / `#![..]` item."""
    for c in attr_item.children:
        if c.type == "attribute":
            return c
    return None


def _attr_path_is_bare(attr: Node) -> tuple[bool, str]:
    """(is_bare_single_segment, path_text) for an `attribute` node.

    Bare means the meta-path is a single `identifier` (e.g. `allow`,
    `must_use`) — NOT a `scoped_identifier` (`foo::bar`, a path-qualified or
    proc-macro attribute). Returns the path text for messages.
    """
    for c in attr.children:
        if c.type == "identifier":
            return True, c.text.decode("utf-8", "replace")
        if c.type in ("scoped_identifier", "scoped_type_identifier"):
            return False, c.text.decode("utf-8", "replace")
    # Unknown / unexpected meta shape — treat as not-bare (reject).
    return False, "".join(ch.text.decode("utf-8", "replace") for ch in attr.children)


def _attr_token_tree(attr: Node) -> Node | None:
    for c in attr.children:
        if c.type == "token_tree":
            return c
    return None


def _attr_args(attr: Node) -> list[str]:
    """Comma-separated identifier args inside an attribute's `token_tree`.

    e.g. `derive(Clone, Copy)` -> ["Clone", "Copy"];
         `deny(unsafe_code, missing_docs)` -> ["unsafe_code", "missing_docs"].
    """
    tt = _attr_token_tree(attr)
    if tt is None:
        return []
    return [
        c.text.decode("utf-8", "replace") for c in tt.children if c.type == "identifier"
    ]


def _check_inert_attrs(
    item: Node,
    src: bytes,
    allowed: frozenset[str],
    owner_label: str,
) -> list[str]:
    """Assert every attribute on `item` is a bare inert built-in in `allowed`.

    Rejects (by construction): any `derive(...)` (closes every forbidden
    derive at once), any path-qualified / proc-macro attribute
    (`scoped_identifier` meta-path), and any bare attribute not in `allowed`.
    """
    out: list[str] = []
    for attr_item in _preceding_attr_items(item):
        attr = _attr_node(attr_item)
        if attr is None:
            out.append(
                f"{owner_label} carries an unparseable attribute "
                f"`{_text(attr_item, src)}`"
            )
            continue
        is_bare, path = _attr_path_is_bare(attr)
        if not is_bare:
            out.append(
                f"{owner_label} carries non-inert attribute "
                f"`#[{path}...]` — only bare single-segment built-ins "
                f"({', '.join(sorted(allowed))}) are permitted "
                f"(path-qualified / proc-macro attributes are rejected)"
            )
            continue
        if path == "derive":
            derived = _attr_args(attr)
            out.append(
                f"{owner_label} carries `#[derive({', '.join(derived)})]` — "
                f"NO derive is permitted (forbidden: "
                f"{FORBIDDEN_DERIVES_FOR_MESSAGE})"
            )
            continue
        if path not in allowed:
            out.append(
                f"{owner_label} carries attribute `#[{path}]` — not in the "
                f"inert allowlist ({', '.join(sorted(allowed))})"
            )
    return out


# --- deny(unsafe_code) presence via real parse (A5) --------------------------


def _has_deny_unsafe_code(mod_src: bytes) -> bool:
    """True iff `mod.rs` has a real inner attr `#![deny|forbid(unsafe_code)]`.

    Parsed from the tree (`inner_attribute_item` whose meta-path is `deny` or
    `forbid` and whose args contain `unsafe_code`), so a commented-out or
    string-literal occurrence does NOT satisfy it, while extra lints
    (`deny(unsafe_code, missing_docs)`) DO.
    """
    root = _parser().parse(mod_src).root_node
    for n in _walk(root):
        if n.type != "inner_attribute_item":
            continue
        attr = _attr_node(n)
        if attr is None:
            continue
        is_bare, path = _attr_path_is_bare(attr)
        if not is_bare or path not in ("deny", "forbid"):
            continue
        if "unsafe_code" in _attr_args(attr):
            return True
    return False


# --- A1: module-item whitelist ----------------------------------------------

# Module-level item node kinds that are NEVER permitted (rejected by KIND).
# Listed for clear messages; the rule is positive (only the four allowed kinds
# pass), so this list need not be exhaustive — any unlisted disallowed kind
# still fails the positive check below.
_DISALLOWED_KIND_LABEL = {
    "type_item": "a `type` alias (closes `type Cap = OwnedIdentityDid;`)",
    "enum_item": "an `enum`",
    "union_item": "a `union`",
    "function_item": "a free `fn` (closes the aliased free-fn minter)",
    "trait_item": "a `trait`",
    "const_item": "a `const`",
    "static_item": "a `static`",
    "macro_definition": "a `macro_rules!` definition",
    "macro_invocation": "a top-level macro invocation",
}

# Module-level kinds that are pure noise (skipped, never counted).
_IGNORED_MODULE_KINDS = frozenset(
    {
        "line_comment",
        "block_comment",
        "attribute_item",  # decorate the following item; validated there
        "inner_attribute_item",  # #![...] file-level inner attrs are fine
        "shebang",
    }
)


def _mod_has_cfg_test(mod: Node, src: bytes) -> bool:
    for attr_item in _preceding_attr_items(mod):
        attr = _attr_node(attr_item)
        if attr is None:
            continue
        is_bare, path = _attr_path_is_bare(attr)
        if is_bare and path == "cfg" and "test" in _attr_args(attr):
            return True
    return False


def _enforce(cap_src_path: Path, mod_src_path: Path) -> list[str]:
    """Run every definition-shape check. Return a list of failures (empty = ok)."""
    failures: list[str] = []
    parser = _parser()

    if not cap_src_path.is_file():
        return [f"capability file missing: {cap_src_path}"]
    src = cap_src_path.read_bytes()
    root = parser.parse(src).root_node

    # === A1: module-item whitelist (the categorical closer) ===
    struct_items: list[Node] = []
    inherent_impls: list[Node] = []
    test_mods: list[Node] = []

    for item in root.children:
        kind = item.type
        if kind in _IGNORED_MODULE_KINDS:
            continue
        if kind == "use_declaration":
            continue  # any number permitted
        if kind == "struct_item":
            if _struct_name(item, src) != TYPE_NAME:
                failures.append(
                    f"module-level `struct {_struct_name(item, src)}` is not "
                    f"permitted — the only struct may be `{TYPE_NAME}`"
                )
            else:
                struct_items.append(item)
            continue
        if kind == "impl_item":
            trait_name = _impl_trait_name(item, src)
            tgt = _impl_type_name(item, src)
            if trait_name is not None:
                # A trait impl is a SECOND impl item — rejected by A1/A3.
                failures.append(
                    f"trait impl `impl {trait_name} for {tgt or '?'}` is not "
                    f"permitted — the only impl may be the single inherent "
                    f"`impl {TYPE_NAME}` (closes manual `impl Clone`, etc.)"
                )
            elif tgt != TYPE_NAME:
                failures.append(
                    f"inherent `impl {tgt}` targets a type other than "
                    f"`{TYPE_NAME}` — not permitted at module level"
                )
            else:
                inherent_impls.append(item)
            continue
        if kind == "mod_item":
            name = _mod_name(item, src)
            if name != "tests":
                failures.append(
                    f"module-level `mod {name}` is not permitted — the only "
                    f"`mod` may be `tests` (and it must carry `#[cfg(test)]`)"
                )
            elif not _mod_has_cfg_test(item, src):
                failures.append(
                    "`mod tests` is present but does NOT carry `#[cfg(test)]`; "
                    "only a cfg(test) test module is permitted"
                )
            else:
                test_mods.append(item)
            continue
        # Any other module-level item kind is rejected BY KIND.
        label = _DISALLOWED_KIND_LABEL.get(kind, f"a `{kind}`")
        failures.append(
            f"module-level item of kind `{kind}` is not permitted "
            f"({label}); the only permitted module-level items are "
            f"`use` declarations, one `struct {TYPE_NAME}`, one inherent "
            f"`impl {TYPE_NAME}`, and one `#[cfg(test)] mod tests`"
        )

    # Cardinality of the permitted kinds.
    if len(struct_items) == 0:
        failures.append(
            f"no `struct {TYPE_NAME}` found in {cap_src_path.name} "
            f"(renamed / removed capability type)"
        )
        return failures
    if len(struct_items) > 1:
        failures.append(
            f"{len(struct_items)} `struct {TYPE_NAME}` definitions; exactly "
            f"one is permitted"
        )
    if len(inherent_impls) > 1:
        failures.append(
            f"{len(inherent_impls)} inherent `impl {TYPE_NAME}` blocks; "
            f"exactly one is permitted (a second block can smuggle an extra "
            f"constructor)"
        )
    if len(test_mods) > 1:
        failures.append(
            f"{len(test_mods)} `#[cfg(test)] mod tests`; at most one permitted"
        )

    struct = struct_items[0]

    # === A2: the one struct's exact shape ===
    vis = _norm_vis(_vis_node(struct), src)
    if vis != REQUIRED_STRUCT_VIS:
        shown = vis if vis else "<inherited-private>"
        failures.append(
            f"struct `{TYPE_NAME}` visibility is `{shown}`; must be exactly "
            f"`{REQUIRED_STRUCT_VIS}` (never `pub`, `pub(crate)`, `pub(super)`)"
        )

    body = struct.child_by_field_name("body")
    if body is None or body.type != "field_declaration_list":
        failures.append(
            f"`{TYPE_NAME}` must be a braced struct with exactly one private "
            f"field `did: DID` (tuple/unit forms are rejected)"
        )
    else:
        fields = [c for c in body.children if c.type == "field_declaration"]
        if len(fields) != 1:
            failures.append(
                f"`{TYPE_NAME}` must have exactly one field; found {len(fields)}"
            )
        for fld in fields:
            fname_node = fld.child_by_field_name("name")
            fname = _text(fname_node, src) if fname_node is not None else "?"
            fvis = _vis_node(fld)
            if fvis is not None:
                failures.append(
                    f"field `{fname}` has visibility "
                    f"`{_norm_vis(fvis, src)}`; the field MUST be private "
                    f"(no visibility modifier) so no struct-literal "
                    f"construction is possible outside this module"
                )
            if fname != "did":
                failures.append(
                    f"`{TYPE_NAME}`'s field is named `{fname}`; expected `did`"
                )
            ftype_node = fld.child_by_field_name("type")
            ftype = (
                _final_type_segment(_text(ftype_node, src))
                if ftype_node is not None
                else "?"
            )
            if ftype != "DID":
                failures.append(
                    f"`{TYPE_NAME}`'s field `{fname}` has type `{ftype}`; "
                    f"expected `DID`"
                )

    # A2: struct attributes — inert built-ins only, no derive.
    failures.extend(
        _check_inert_attrs(struct, src, STRUCT_INERT_ATTRS, f"struct `{TYPE_NAME}`")
    )

    # === A3: the one impl's exact shape ===
    inherent_fns: list[Node] = []
    for impl_item in inherent_impls:
        decl = impl_item.child_by_field_name("body")
        if decl is None:
            continue
        inherent_fns.extend(c for c in decl.children if c.type == "function_item")

    seen_names: list[str] = []
    fn_by_name: dict[str, Node] = {}
    for fn in inherent_fns:
        name = _fn_name(fn, src)
        seen_names.append(name)
        fn_by_name.setdefault(name, fn)
        if name not in ALLOWED_METHODS:
            failures.append(
                f"unexpected inherent fn `{name}` on `{TYPE_NAME}`; the "
                f"inherent API is a closed allowlist "
                f"{{{', '.join(ALLOWED_METHODS)}}} — adding any other "
                f"inherent fn (the SOLE-MINTER invariant) is rejected"
            )

    for required in ALLOWED_METHODS:
        count = seen_names.count(required)
        if count == 0:
            failures.append(
                f"required inherent fn `{required}` is missing from `{TYPE_NAME}`"
            )
        elif count > 1:
            failures.append(
                f"inherent fn `{required}` is defined {count} times; expected once"
            )

    # Per-method EXACT signature: (required_vis, exact_param_kinds, return_set).
    method_spec = {
        "issue_for_actor": (
            "pub(super)",
            ["parameter"],  # exactly one by-value param (not &self)
            {"Self", TYPE_NAME},
        ),
        "reissue": (
            REQUIRED_STRUCT_VIS,
            ["self_parameter"],  # EXACTLY &self, nothing else
            {"Self", TYPE_NAME},
        ),
        "as_did": (
            REQUIRED_STRUCT_VIS,
            ["self_parameter"],  # EXACTLY &self
            {"&DID", "& DID"},
        ),
    }
    for name, (req_vis, want_params, ret_set) in method_spec.items():
        fn = fn_by_name.get(name)
        if fn is None:
            continue
        v = _norm_vis(_vis_node(fn), src) or "<inherited-private>"
        if v != req_vis:
            failures.append(f"`{name}` visibility is `{v}`; must be `{req_vis}`")
        params = _fn_param_kinds(fn)
        if params != want_params:
            failures.append(
                f"`{name}` parameter list is {params or '()'}; must be exactly "
                f"{want_params} "
                + (
                    "(closes the aliased-DID-param minter without resolving the alias)"
                    if name == "reissue"
                    else ""
                )
            )
        ret = _fn_return_text(fn, src)
        ret_norm = _final_type_segment(ret) if "::" in ret and "&" not in ret else ret
        if ret not in ret_set and ret_norm not in {
            _final_type_segment(r) for r in ret_set
        }:
            failures.append(
                f"`{name}` returns `{ret or '()'}`; must be one of {sorted(ret_set)}"
            )
        # Per-method attributes: inert built-ins only.
        failures.extend(
            _check_inert_attrs(fn, src, METHOD_INERT_ATTRS, f"method `{name}`")
        )

    # === A4: no construction outside the three allowlisted method bodies ===
    # (Largely subsumed by A1 banning free fns / aliases; kept as a belt. The
    # cfg(test) `mod tests` is non-production and may CALL issue_for_actor — but
    # struct-LITERAL construction is still confined to the allowlisted bodies.)
    allowlisted_bodies = []
    for fn in inherent_fns:
        if _fn_name(fn, src) in ALLOWED_METHODS:
            blk = fn.child_by_field_name("body")
            if blk is not None:
                allowlisted_bodies.append((blk.start_byte, blk.end_byte))

    def _inside_allowlisted(node: Node) -> bool:
        return any(
            start <= node.start_byte and node.end_byte <= end
            for (start, end) in allowlisted_bodies
        )

    for n in _walk(root):
        if n.type != "struct_expression":
            continue
        ty = n.child_by_field_name("name")
        if ty is None:
            continue
        ty_text = _final_type_segment(_text(ty, src))
        if ty_text not in (TYPE_NAME, "Self"):
            continue
        if _inside_allowlisted(n):
            continue
        failures.append(
            f"struct-literal construction `{ty_text} {{ .. }}` outside the "
            f"allowlisted methods of `{TYPE_NAME}`; the only constructors are "
            f"{{{', '.join(ALLOWED_METHODS)}}}"
        )

    # === A5: deny(unsafe_code) in supervisor/mod.rs (real parse) ===
    if not mod_src_path.is_file():
        failures.append(f"supervisor mod.rs missing: {mod_src_path}")
    elif not _has_deny_unsafe_code(mod_src_path.read_bytes()):
        failures.append(
            f"{mod_src_path.name} must contain a real inner attribute "
            f"`#![deny(unsafe_code)]` (or `#![forbid(unsafe_code)]`); a "
            f"commented-out or string occurrence does not count"
        )

    return failures


def _scan_real() -> int:
    failures = _enforce(CAP_FILE, MOD_FILE)
    if failures:
        sys.stderr.write(
            f"{C_RED}owned-identity-did definition-shape gate FAILED{C_RESET}\n"
        )
        for f in failures:
            sys.stderr.write(f"  {C_RED}-{C_RESET} {f}\n")
        return 1
    sys.stdout.write(
        f"{C_GREEN}owned-identity-did gate PASSED{C_RESET}: "
        f"`{TYPE_NAME}` definition shape matches the frozen whitelist.\n"
    )
    return 0


# ---------------------------------------------------------------------------
# Self-test: drive the kernel against per-fixture files. Each `// @file:`
# block declares `[REJECT]` (must fail) or `[ACCEPT]` (must pass). A trailing
# `mod=<stub>` token on the header selects an alternate supervisor/mod.rs stub
# (for the A5 deny-parse fixtures); default is a stub that satisfies A5.
# ---------------------------------------------------------------------------
def _parse_fixtures() -> list[tuple[str, str, str, str]]:
    """Return (name, verdict, mod_stub_key, body) for each `// @file:` block."""
    text = FIXTURE_FILE.read_text()
    blocks: list[tuple[str, str, str, list[str]]] = []
    name: str | None = None
    verdict: str | None = None
    mod_key = "default"
    buf: list[str] = []
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith("// @file:"):
            if name is not None and verdict is not None:
                blocks.append((name, verdict, mod_key, buf))
            header = stripped[len("// @file:") :].strip()
            parts = header.split()
            name = parts[0]
            verdict = "ACCEPT" if "[ACCEPT]" in header else "REJECT"
            mod_key = "default"
            for tok in parts[1:]:
                if tok.startswith("mod="):
                    mod_key = tok[len("mod=") :]
            buf = []
        else:
            buf.append(line)
    if name is not None and verdict is not None:
        blocks.append((name, verdict, mod_key, buf))
    return [(n, v, m, "".join(b)) for (n, v, m, b) in blocks]


# Supervisor/mod.rs stubs selectable per-fixture via `mod=<key>` on the header.
#   - "default": a real `#![deny(unsafe_code)]` so A5 is satisfied and is NEVER
#     the cause of a [REJECT] (each REJECT isolates one identity_capability.rs
#     violation).
#   - "deny_commented": the deny is COMMENTED OUT — exercises A5's false-neg
#     guard (a fixture pairing this with an otherwise-real-shape body must be
#     REJECTED, proving the real parse ignores commented attributes).
#   - "deny_extra_lints": `#![deny(unsafe_code, missing_docs)]` — exercises A5's
#     false-pos guard (extra lints must STILL satisfy the check).
_MOD_RS_STUBS = {
    "default": "#![deny(unsafe_code)]\n",
    "deny_commented": "// #![deny(unsafe_code)]\n",
    "deny_extra_lints": "#![deny(unsafe_code, missing_docs)]\n",
}


def do_self_test() -> int:
    if not FIXTURE_FILE.is_file():
        sys.stderr.write(f"{C_RED}error:{C_RESET} fixture missing: {FIXTURE_FILE}\n")
        return 2

    fixtures = _parse_fixtures()
    if not fixtures:
        sys.stderr.write(
            f"{C_RED}self-test FAILED{C_RESET}: fixture has no `// @file:` blocks\n"
        )
        return 1

    n_reject = sum(1 for _, v, _, _ in fixtures if v == "REJECT")
    n_accept = sum(1 for _, v, _, _ in fixtures if v == "ACCEPT")
    if n_accept < 1:
        sys.stderr.write(
            f"{C_RED}self-test FAILED{C_RESET}: no [ACCEPT] positive fixture\n"
        )
        return 1
    if n_reject < 1:
        sys.stderr.write(f"{C_RED}self-test FAILED{C_RESET}: no [REJECT] fixtures\n")
        return 1

    mismatches: list[str] = []
    for name, verdict, mod_key, body in fixtures:
        stub = _MOD_RS_STUBS.get(mod_key)
        if stub is None:
            mismatches.append(f"{name} (unknown mod stub key `{mod_key}`)")
            sys.stdout.write(
                f"  [{C_RED}MISMATCH{C_RESET}] {verdict:6s} {name} "
                f"(unknown mod stub key `{mod_key}`)\n"
            )
            continue
        with tempfile.TemporaryDirectory() as tmp:
            sup = (
                Path(tmp) / "crates" / "scp-runtime" / "src" / "context" / "supervisor"
            )
            sup.mkdir(parents=True)
            cap = sup / "identity_capability.rs"
            mod = sup / "mod.rs"
            cap.write_text(body)
            mod.write_text(stub)
            failures = _enforce(cap, mod)
            rejected = bool(failures)
            expected_reject = verdict == "REJECT"
            ok = rejected == expected_reject
            status = f"{C_GREEN}ok{C_RESET}" if ok else f"{C_RED}MISMATCH{C_RESET}"
            detail = ""
            if not ok:
                if expected_reject:
                    detail = " (expected REJECT but ACCEPTED)"
                else:
                    detail = (
                        " (expected ACCEPT but REJECTED: " + "; ".join(failures) + ")"
                    )
                mismatches.append(name + detail)
            sys.stdout.write(f"  [{status}] {verdict:6s} {name}{detail}\n")

    if mismatches:
        sys.stderr.write(
            f"{C_RED}self-test FAILED{C_RESET}: "
            f"{len(mismatches)} fixture(s) misbehaved:\n"
        )
        for m in mismatches:
            sys.stderr.write(f"  {C_RED}-{C_RESET} {m}\n")
        return 1

    sys.stdout.write(
        f"{C_GREEN}owned-identity-did self-test PASSED{C_RESET}: "
        f"{n_reject} forgeries REJECTED, {n_accept} positive(s) ACCEPTED.\n"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=("Frozen-shape positive-whitelist gate for OwnedIdentityDid.")
    )
    ap.add_argument("--self-test", action="store_true", help="run fixture self-test")
    args = ap.parse_args()
    if args.self_test:
        return do_self_test()
    return _scan_real()


if __name__ == "__main__":
    raise SystemExit(main())
