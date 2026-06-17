#!/usr/bin/env python3.12
# ruff: noqa: E501
"""Definition-shape gate for the `OwnedIdentityDid` capability token.

`OwnedIdentityDid` (ADR-049 §5, spec §9.4.1) is a capability token proving
an actor's identity owns it. Its unforgeability is enforced BY THE TYPE
SYSTEM: the sole arbitrary-`DID` constructor `issue_for_actor` is
`pub(super)`, the `did` field is private (so no struct literal outside the
defining module), and the supervisor module is `#![deny(unsafe_code)]`. No
compiling, type-system-evading forgery reachable from outside the module
exists — the boundary holds without any gate.

This gate is DEFENSE-IN-DEPTH ONLY. It checks the type DEFINITION shape of
`OwnedIdentityDid` in
`crates/scp-runtime/src/context/supervisor/identity_capability.rs`, plus one
presence assertion (`deny(unsafe_code)` in `supervisor/mod.rs`).

Construction confinement — that a token can only be minted via
`issue_for_actor` or a struct literal INSIDE this module — is guaranteed by
the type system (`pub(super)` constructor + private field +
`deny(unsafe_code)`), NOT by source-text analysis. THEREFORE THIS GATE DOES
NOT AND WILL NOT INSPECT ANY CALL SITE, CONSTRUCTION SITE, OR MINT
ARGUMENT, nor approximate the compiler's own scope-and-binding analysis in
an AST walker. That whole class of reasoning is the compiler's job; the
relevant lesson under `.docs/lessons/` records why approximating it in
tree-sitter is an unbounded arms race and was deleted.

The gate's residual value is the SOLE-MINTER invariant — the one thing the
type system does not prevent is an insider adding a SECOND arbitrary-`DID`
constructor inside the module. A closed inherent-method allowlist by NAME
catches exactly that.

COMPLETE CHECK SET (definition shape only), scanning identity_capability.rs:
  1. Exactly one `struct OwnedIdentityDid` in the file; defined as a struct
     nowhere else in the supervisor subtree.
  2. Struct name-visibility is EXACTLY `pub(in crate::context)`.
  3. Exactly one field `did`, with NO visibility modifier (private).
  4. Closed inherent-method allowlist BY NAME: the inherent impl contains
     EXACTLY {issue_for_actor, reissue, as_did} — no more, no fewer.
  5. Per-method shape: issue_for_actor is `pub(super)`, by-value `DID`
     param, no `&self`; reissue / as_did are `pub(in crate::context)`,
     `&self`, no raw `DID` param.
  6. No forbidden derives on the struct.
  7. No forbidden trait impls; no second inherent impl block.
  8. No other constructor: outside the three allowlisted method bodies, no
     `OwnedIdentityDid {..}` / `Self {..}` literal and no other item
     returning the capability type.
  9. `deny(unsafe_code)` / `forbid(unsafe_code)` present in
     `supervisor/mod.rs`.

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

# Subtree scanned for stray struct definitions (check 1).
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

FORBIDDEN_TRAITS = frozenset(
    {
        "Clone",
        "Copy",
        "Serialize",
        "Deserialize",
        "Default",
        "From",
        "Into",
        "Hash",
        "PartialEq",
        "Eq",
        "PartialOrd",
        "Ord",
        "Borrow",
        "AsRef",
        "Deref",
        "Debug",
        "Display",
    }
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


def _struct_vis_node(struct: Node) -> Node | None:
    for child in struct.children:
        if child.type == "visibility_modifier":
            return child
    return None


def _fn_vis_node(fn: Node) -> Node | None:
    for child in fn.children:
        if child.type == "visibility_modifier":
            return child
    return None


def _named_field_list(struct: Node) -> Node | None:
    return struct.child_by_field_name("body")


def _struct_name(struct: Node, src: bytes) -> str:
    name = struct.child_by_field_name("name")
    return _text(name, src) if name is not None else ""


def _impl_type_name(impl_item: Node, src: bytes) -> str:
    t = impl_item.child_by_field_name("type")
    return _text(t, src) if t is not None else ""


def _impl_trait_name(impl_item: Node, src: bytes) -> str | None:
    tr = impl_item.child_by_field_name("trait")
    if tr is None:
        return None
    # Strip generics / path: take the final identifier segment.
    raw = _text(tr, src).split("<")[0].strip()
    return raw.split("::")[-1] if raw else None


def _fn_name(fn: Node, src: bytes) -> str:
    n = fn.child_by_field_name("name")
    return _text(n, src) if n is not None else ""


def _fn_params(fn: Node) -> Node | None:
    return fn.child_by_field_name("parameters")


def _fn_has_self(fn: Node) -> bool:
    params = _fn_params(fn)
    if params is None:
        return False
    return any(c.type == "self_parameter" for c in params.children)


def _fn_takes_raw_did(fn: Node, src: bytes) -> bool:
    """True if any non-self parameter's TYPE is the raw DID type token.

    Matches the DID type by exact identifier `DID` / `Did` / a future
    `DidId`-style alias (a token beginning `Did` or `DID`), restricted to
    the parameter TYPE — never the parameter name — so an ordinary `did:`
    name does not false-match.
    """
    params = _fn_params(fn)
    if params is None:
        return False
    for child in params.children:
        if child.type != "parameter":
            continue
        ty = child.child_by_field_name("type")
        if ty is None:
            continue
        for tok in _type_tokens(_text(ty, src)):
            if tok == "DID" or tok.startswith("Did"):
                return True
    return False


def _type_tokens(text: str) -> list[str]:
    tok: list[str] = []
    cur: list[str] = []
    for ch in text:
        if ch.isalnum() or ch == "_":
            cur.append(ch)
        else:
            if cur:
                tok.append("".join(cur))
                cur = []
    if cur:
        tok.append("".join(cur))
    return tok


def _walk(node: Node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def _derives(attr_item: Node, src: bytes) -> list[str]:
    """Identifiers inside any `derive(...)` group within an attribute item.

    Handles both `#[derive(...)]` and `#[cfg_attr(..., derive(...))]` by
    scanning the attribute text for every balanced `derive( ... )` group.
    """
    text = _text(attr_item, src)
    out: list[str] = []
    idx = 0
    needle = "derive"
    while True:
        pos = text.find(needle, idx)
        if pos == -1:
            break
        idx = pos + len(needle)
        # Skip whitespace, require an opening paren.
        j = idx
        while j < len(text) and text[j].isspace():
            j += 1
        if j >= len(text) or text[j] != "(":
            continue
        # Ensure `derive` is a standalone word (not e.g. `myderive`).
        if pos > 0 and (text[pos - 1].isalnum() or text[pos - 1] == "_"):
            continue
        depth = 0
        k = j
        while k < len(text):
            if text[k] == "(":
                depth += 1
            elif text[k] == ")":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        inner = text[j + 1 : k]
        for tok in inner.replace("(", " ").replace(")", " ").split(","):
            name = tok.strip().split("::")[-1].strip()
            if name:
                out.append(name)
        idx = k + 1
    return out


def _enforce(cap_src_path: Path, mod_src_path: Path, subtree: Path) -> list[str]:
    """Run every definition-shape check. Return a list of failures (empty = ok)."""
    failures: list[str] = []
    parser = _parser()

    if not cap_src_path.is_file():
        return [f"capability file missing: {cap_src_path}"]
    src = cap_src_path.read_bytes()
    root = parser.parse(src).root_node

    # --- Collect struct definitions named OwnedIdentityDid in this file ---
    struct_defs = [
        n
        for n in _walk(root)
        if n.type == "struct_item" and _struct_name(n, src) == TYPE_NAME
    ]

    # Check 1a: exactly one in this file.
    if len(struct_defs) == 0:
        failures.append(
            f"no `struct {TYPE_NAME}` found in {cap_src_path.name} "
            f"(renamed / removed capability type)"
        )
        return failures
    if len(struct_defs) > 1:
        failures.append(
            f"{len(struct_defs)} `struct {TYPE_NAME}` definitions in "
            f"{cap_src_path.name}; exactly one is permitted"
        )
    struct = struct_defs[0]

    # Check 1b: not defined as a struct anywhere else in the supervisor subtree.
    for other in sorted(subtree.rglob("*.rs")):
        if other.resolve() == cap_src_path.resolve():
            continue
        otext = other.read_bytes()
        oroot = parser.parse(otext).root_node
        for n in _walk(oroot):
            if n.type == "struct_item" and _struct_name(n, otext) == TYPE_NAME:
                rel = other.relative_to(subtree)
                failures.append(
                    f"`struct {TYPE_NAME}` also defined in supervisor/{rel}; "
                    f"the capability type must be declared only in "
                    f"{cap_src_path.name}"
                )

    # Check 2: struct name-visibility EXACTLY pub(in crate::context).
    vis = _norm_vis(_struct_vis_node(struct), src)
    if vis != REQUIRED_STRUCT_VIS:
        shown = vis if vis else "<inherited-private>"
        failures.append(
            f"struct `{TYPE_NAME}` visibility is `{shown}`; must be exactly "
            f"`{REQUIRED_STRUCT_VIS}` (never `pub`, `pub(crate)`, `pub(super)`)"
        )

    # Check 3: exactly one field `did`, private (no visibility modifier).
    body = _named_field_list(struct)
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
            fvis = next(
                (c for c in fld.children if c.type == "visibility_modifier"),
                None,
            )
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

    # Check 6: no forbidden derives on the struct.
    for attr in _struct_outer_attrs(struct):
        for d in _derives(attr, src):
            if d in FORBIDDEN_TRAITS:
                failures.append(f"`{TYPE_NAME}` carries forbidden derive `{d}`")

    # --- Walk impls of OwnedIdentityDid ---
    inherent_impls: list[Node] = []
    for n in _walk(root):
        if n.type != "impl_item":
            continue
        if _impl_type_name(n, src) != TYPE_NAME:
            continue
        trait_name = _impl_trait_name(n, src)
        if trait_name is None:
            inherent_impls.append(n)
        else:
            # Check 7: forbidden manual trait impls.
            if trait_name in FORBIDDEN_TRAITS:
                failures.append(
                    f"manual `impl {trait_name} for {TYPE_NAME}` is forbidden"
                )

    # Check 7: at most one inherent impl block.
    if len(inherent_impls) > 1:
        failures.append(
            f"{len(inherent_impls)} inherent `impl {TYPE_NAME}` blocks; "
            f"exactly one is permitted (a second block can smuggle an extra "
            f"constructor)"
        )

    # Check 4 + 5: closed inherent-method allowlist by name, with per-method shape.
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
        if seen_names.count(required) == 0:
            failures.append(
                f"required inherent fn `{required}` is missing from `{TYPE_NAME}`"
            )
        elif seen_names.count(required) > 1:
            failures.append(
                f"inherent fn `{required}` is defined "
                f"{seen_names.count(required)} times; expected once"
            )

    # Per-method shape checks. Spec: (required_vis, wants_self, wants_did).
    # `wants_did=True` => must take a raw `DID`; False => must NOT.
    method_spec = {
        "issue_for_actor": ("pub(super)", False, True),
        "reissue": (REQUIRED_STRUCT_VIS, True, False),
        "as_did": (REQUIRED_STRUCT_VIS, True, False),
    }
    for name, (req_vis, wants_self, wants_did) in method_spec.items():
        fn = fn_by_name.get(name)
        if fn is None:
            continue
        v = _norm_vis(_fn_vis_node(fn), src) or "<inherited-private>"
        if v != req_vis:
            failures.append(f"`{name}` visibility is `{v}`; must be `{req_vis}`")
        if wants_self and not _fn_has_self(fn):
            failures.append(f"`{name}` must take `&self`")
        if not wants_self and _fn_has_self(fn):
            failures.append(f"`{name}` must not take `&self`")
        takes_did = _fn_takes_raw_did(fn, src)
        if wants_did and not takes_did:
            failures.append(f"`{name}` must take a by-value `DID` parameter")
        if not wants_did and takes_did:
            failures.append(
                f"`{name}` must NOT take a raw `DID` parameter "
                f"(only `issue_for_actor` may mint from a raw DID)"
            )

    # Check 8: no construction outside the three allowlisted method bodies.
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
        ty_text = _text(ty, src)
        if ty_text not in (TYPE_NAME, "Self"):
            continue
        if _inside_allowlisted(n):
            continue
        failures.append(
            f"struct-literal construction `{ty_text} {{ .. }}` outside the "
            f"allowlisted methods of `{TYPE_NAME}`; the only constructors are "
            f"{{{', '.join(ALLOWED_METHODS)}}}"
        )

    # Check 8 (cont.): no OTHER item (free fn / trait-impl method) returns the
    # capability type. Inherent allowlisted fns are exempt; everything else in
    # the file that returns OwnedIdentityDid/Self is a hidden constructor.
    for fn in _walk(root):
        if fn.type != "function_item":
            continue
        if fn in inherent_fns:
            continue
        ret = fn.child_by_field_name("return_type")
        if ret is None:
            continue
        ret_text = _text(ret, src)
        if TYPE_NAME in _type_tokens(ret_text):
            # `Self` is context-dependent; a free fn returning `Self` is a
            # parse oddity, but `OwnedIdentityDid` by name is unambiguous.
            fname = _fn_name(fn, src)
            failures.append(
                f"fn `{fname}` outside the inherent allowlist returns "
                f"`{TYPE_NAME}` — a hidden constructor path"
            )

    # Check 9: deny(unsafe_code) in supervisor/mod.rs.
    if not mod_src_path.is_file():
        failures.append(f"supervisor mod.rs missing: {mod_src_path}")
    else:
        mtext = mod_src_path.read_text("utf-8", "replace")
        compact = "".join(mtext.split())
        if (
            "#![deny(unsafe_code)]" not in compact
            and "#![forbid(unsafe_code)]" not in compact
        ):
            failures.append(
                f"{mod_src_path.name} must contain inner attribute "
                f"`#![deny(unsafe_code)]` (or `#![forbid(unsafe_code)]`)"
            )

    return failures


def _struct_outer_attrs(struct: Node) -> list[Node]:
    """Outer-attribute nodes immediately preceding the struct.

    In tree-sitter-rust, a struct's outer attributes are siblings that
    precede the `struct_item` within the same parent (node type begins with
    "attribute"). Collect the contiguous run directly above the struct so
    its derives can be inspected (check 6).
    """
    parent = struct.parent
    if parent is None:
        return []
    siblings = parent.children
    try:
        idx = siblings.index(struct)
    except ValueError:
        return []
    attrs: list[Node] = []
    j = idx - 1
    while j >= 0 and siblings[j].type.startswith("attribute"):
        attrs.append(siblings[j])
        j -= 1
    return attrs


def _scan_real() -> int:
    failures = _enforce(CAP_FILE, MOD_FILE, SUPERVISOR_SUBTREE)
    if failures:
        sys.stderr.write(
            f"{C_RED}owned-identity-did definition-shape gate FAILED{C_RESET}\n"
        )
        for f in failures:
            sys.stderr.write(f"  {C_RED}-{C_RESET} {f}\n")
        return 1
    sys.stdout.write(
        f"{C_GREEN}owned-identity-did gate PASSED{C_RESET}: "
        f"`{TYPE_NAME}` definition shape is sound.\n"
    )
    return 0


# ---------------------------------------------------------------------------
# Self-test: drive the kernel against per-fixture files. Each `// @file:`
# block declares `[REJECT]` (must fail) or `[ACCEPT]` (must pass).
# ---------------------------------------------------------------------------
def _parse_fixtures() -> list[tuple[str, str, str]]:
    """Return (name, verdict, body) for each `// @file:` block."""
    text = FIXTURE_FILE.read_text()
    blocks: list[tuple[str, str, list[str]]] = []
    name: str | None = None
    verdict: str | None = None
    buf: list[str] = []
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith("// @file:"):
            if name is not None and verdict is not None:
                blocks.append((name, verdict, buf))
            header = stripped[len("// @file:") :].strip()
            parts = header.split()
            name = parts[0]
            verdict = "REJECT"
            if "[ACCEPT]" in header:
                verdict = "ACCEPT"
            elif "[REJECT]" in header:
                verdict = "REJECT"
            buf = []
        else:
            buf.append(line)
    if name is not None and verdict is not None:
        blocks.append((name, verdict, buf))
    return [(n, v, "".join(b)) for (n, v, b) in blocks]


# A minimal supervisor/mod.rs that carries deny(unsafe_code), so the
# presence check (9) is satisfied for every fixture and is NOT the cause of
# any [REJECT] — each REJECT fixture isolates exactly one definition-shape
# violation in identity_capability.rs.
_MOD_RS_STUB = "#![deny(unsafe_code)]\n"


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

    n_reject = sum(1 for _, v, _ in fixtures if v == "REJECT")
    n_accept = sum(1 for _, v, _ in fixtures if v == "ACCEPT")
    if n_accept < 1:
        sys.stderr.write(
            f"{C_RED}self-test FAILED{C_RESET}: no [ACCEPT] positive fixture\n"
        )
        return 1
    if n_reject < 1:
        sys.stderr.write(f"{C_RED}self-test FAILED{C_RESET}: no [REJECT] fixtures\n")
        return 1

    mismatches: list[str] = []
    for name, verdict, body in fixtures:
        with tempfile.TemporaryDirectory() as tmp:
            sup = (
                Path(tmp) / "crates" / "scp-runtime" / "src" / "context" / "supervisor"
            )
            sup.mkdir(parents=True)
            cap = sup / "identity_capability.rs"
            mod = sup / "mod.rs"
            cap.write_text(body)
            mod.write_text(_MOD_RS_STUB)
            failures = _enforce(cap, mod, sup)
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
        description=("Definition-shape gate for the OwnedIdentityDid capability token.")
    )
    ap.add_argument("--self-test", action="store_true", help="run fixture self-test")
    args = ap.parse_args()
    if args.self_test:
        return do_self_test()
    return _scan_real()


if __name__ == "__main__":
    raise SystemExit(main())
