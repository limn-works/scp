#!/usr/bin/env python3.12
"""generate-pyi.py — Regenerate/normalize the ``_scp_core`` type stub.

The hand-maintained stub ``bindings/python/scp_sdk/_scp_core.pyi`` has
repeatedly drifted from the real PyO3 exports (missing methods, transposed
adjacent ``str`` parameters that are invisible to mypy/pyright). This tool
makes the **Rust source the single source of truth** for the Python-visible
signature surface and mechanically reconciles the stub against it.

Source of truth
---------------
The authoritative signatures are the PyO3 exports in ``crates/scp-ffi/src``:

* Every ``#[pymethods] impl PyScp`` method (the ``SCP`` class surface).
* Every module-level ``#[pyfunction]`` registered via ``wrap_pyfunction!``.

PyO3 binds positional parameters by *declaration order* (absent a
``#[pyo3(signature = ...)]``), so the Rust parameter order and arity are the
ground truth. Runtime introspection of the built extension is deliberately
NOT used: PyO3 does not emit ``__text_signature__`` for every export (e.g.
``check_capability_requirements`` has none), so it cannot recover full arity,
and it would require a heavy ``maturin develop`` build inside the CI check.
Parsing the Rust source with tree-sitter is complete, deterministic, and
matches the existing enforcement scripts (``check-call-invariants.py`` etc.).

What it does
------------
For every ``SCP`` method and module free function in the stub whose
parameters are *named* (variadic ``*args, **kwargs`` catch-alls opt out), the
tool rewrites the positional parameter list into the authoritative Rust order,
carrying each parameter's hand-authored annotation and default **by name** (so
a transposition auto-heals and the types follow their parameter). New Rust
parameters are added as ``Any``; removed parameters are dropped. Every other
line of the stub — the header, exception hierarchy, value classes, property
blocks, docstrings, and section comments — is preserved verbatim. The result
is then normalized with ``ruff format``.

It also asserts **set parity**: every exported symbol must have a stub, and
every stubbed symbol (outside the small, justified allowlists below) must be a
real export. A missing or extra symbol is a hard error.

Modes
-----
* ``generate-pyi.py`` (default): rewrite the committed stub in place.
* ``generate-pyi.py --check``: verify the committed stub already equals the
  regenerated output (and passes set parity) without modifying it; exit 1 on
  any difference. Used by ``scripts/check-pyi-generated.sh`` in CI.

This file is an ENFORCEMENT tool (see CLAUDE.md). Weakening the parity
assertions or growing the allowlists to hide real drift requires human
approval; adding coverage is always fine.
"""

from __future__ import annotations

import argparse
import ast
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import tree_sitter_rust as tsr
from tree_sitter import Language, Node, Parser

REPO = Path(__file__).resolve().parent.parent
FFI_SRC = REPO / "crates" / "scp-ffi" / "src"
PY_ROOT = REPO / "bindings" / "python"
PYI_PATH = PY_ROOT / "scp_sdk" / "_scp_core.pyi"

RUST = Language(tsr.language())
PARSER = Parser(RUST)

# The PyO3 GIL token parameter (`py: Python<'_>`) is never Python-visible.
_GIL_TYPE = re.compile(r"^\s*&?\s*Python\b")

# Stub symbols that are intentionally NOT one-to-one with a current PyO3
# export. Each entry is load-bearing and justified; do not extend to paper
# over real drift (that is the exact failure mode this tool exists to catch).
#
# ``evaluate_invitation`` exists at module level purely as a documented
# placeholder pointing callers at the live ``SCP.evaluate_invitation`` method
# (its stub body says so). It carries a variadic ``*args, **kwargs`` signature
# and is therefore already excluded from parameter reconciliation; it is
# allow-listed here only so set-parity does not demand a matching free
# function export.
STUB_ONLY_FREE_FUNCTIONS: frozenset[str] = frozenset({"evaluate_invitation"})


# ---------------------------------------------------------------------------
# Rust source of truth
# ---------------------------------------------------------------------------


@dataclass
class RustFn:
    """A Python-visible PyO3 export extracted from the Rust source."""

    py_name: str
    params: list[str]  # ordered, GIL token / receiver excluded
    optional: set[str] = field(default_factory=set)
    is_static: bool = False
    is_getter: bool = False
    is_new: bool = False


def _text(src: bytes, node: Node) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _leading_attrs(children: list[Node], idx: int, src: bytes) -> list[str]:
    """Return the ``#[...]`` attribute texts immediately preceding ``children[idx]``."""
    attrs: list[str] = []
    j = idx - 1
    while j >= 0 and children[j].type in (
        "attribute_item",
        "line_comment",
        "block_comment",
    ):
        if children[j].type == "attribute_item":
            attrs.append(_text(src, children[j]))
        j -= 1
    return attrs


def _pyo3_name(attrs: list[str]) -> str | None:
    for a in attrs:
        m = re.search(r'name\s*=\s*"([^"]+)"', a)
        if m:
            return m.group(1)
    return None


def _pyo3_signature_optionals(attrs: list[str]) -> set[str]:
    """Names that carry a default in ``#[pyo3(signature = (...))]`` (optional)."""
    for a in attrs:
        m = re.search(r"signature\s*=\s*\((.*)\)", a, re.DOTALL)
        if not m:
            continue
        out: set[str] = set()
        for tok in _split_top_level(m.group(1)):
            tok = tok.strip()
            if not tok or tok.startswith("*") or tok == "/":
                continue
            eq = _top_level_eq(tok)
            if eq is not None:
                out.add(tok[:eq].strip().lstrip("*").strip())
        return out
    return set()


def _split_top_level(s: str) -> list[str]:
    """Split on commas that are not nested in (), [], <>, {} or strings."""
    out: list[str] = []
    depth = 0
    buf = []
    quote = None
    for ch in s:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            buf.append(ch)
            continue
        if ch in "([<{":
            depth += 1
        elif ch in ")]>}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if buf:
        out.append("".join(buf))
    return out


def _top_level_eq(tok: str) -> int | None:
    depth = 0
    quote = None
    i = 0
    while i < len(tok):
        ch = tok[i]
        if quote:
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "\"'":
            quote = ch
        elif ch in "([<{":
            depth += 1
        elif ch in ")]>}":
            depth -= 1
        elif ch == "=" and depth == 0:
            # not == or =>
            if tok[i : i + 2] not in ("==", "=>") and (
                i == 0 or tok[i - 1] not in "=!<>"
            ):
                return i
        i += 1
    return None


def _fn_params(fn: Node, src: bytes) -> list[str]:
    params_node = fn.child_by_field_name("parameters")
    names: list[str] = []
    if params_node is None:
        return names
    for p in params_node.named_children:
        if p.type == "self_parameter":
            continue
        if p.type != "parameter":
            continue
        pat = p.child_by_field_name("pattern")
        typ = p.child_by_field_name("type")
        if pat is None:
            continue
        name = _text(src, pat).strip()
        if name in ("self", "cls"):
            continue
        if typ is not None and _GIL_TYPE.match(_text(src, typ)):
            continue
        names.append(name)
    return names


def collect_rust() -> tuple[dict[str, RustFn], dict[str, RustFn]]:
    """Return ``(scp_methods, free_functions)`` keyed by Python-visible name."""
    scp_methods: dict[str, RustFn] = {}
    free_defs: dict[str, RustFn] = {}  # rust fn name -> RustFn (all top-level fns)
    registered: set[str] = set()

    for path in sorted(FFI_SRC.glob("*.rs")):
        src = path.read_bytes()
        for m in re.finditer(rb"wrap_pyfunction!\s*\(\s*([A-Za-z0-9_]+)", src):
            registered.add(m.group(1).decode())
        tree = PARSER.parse(src)
        _walk_items(
            tree.root_node.children, src, scp_methods, free_defs, in_scp_impl=False
        )

    free_functions: dict[str, RustFn] = {}
    for rust_name in registered:
        fn = free_defs.get(rust_name)
        if fn is None:
            # Registered but definition not found by tree-sitter — should not
            # happen; surface loudly rather than silently dropping coverage.
            raise SystemExit(
                f"error: wrap_pyfunction!({rust_name}) has no locatable fn definition"
            )
        free_functions[fn.py_name] = fn
    return scp_methods, free_functions


def _walk_items(
    children: list[Node],
    src: bytes,
    scp_methods: dict[str, RustFn],
    free_defs: dict[str, RustFn],
    *,
    in_scp_impl: bool,
) -> None:
    for i, node in enumerate(children):
        if node.type == "impl_item":
            attrs = _leading_attrs(children, i, src)
            is_pymethods = any("pymethods" in a for a in attrs)
            type_node = node.child_by_field_name("type")
            type_name = _text(src, type_node).strip() if type_node else ""
            is_scp = type_name.split("::")[-1] == "PyScp"
            body = node.child_by_field_name("body")
            if body is not None:
                _walk_items(
                    body.children,
                    src,
                    scp_methods,
                    free_defs,
                    in_scp_impl=(is_pymethods and is_scp),
                )
        elif node.type == "function_item":
            attrs = _leading_attrs(children, i, src)
            name_node = node.child_by_field_name("name")
            rust_name = _text(src, name_node).strip() if name_node else ""
            py_name = _pyo3_name(attrs) or rust_name
            params = _fn_params(node, src)
            optional = _pyo3_signature_optionals(attrs)
            rec = RustFn(
                py_name=py_name,
                params=params,
                optional=optional,
                is_static=any("staticmethod" in a for a in attrs),
                is_getter=any(a.strip() == "#[getter]" for a in attrs),
                is_new=any(a.strip() == "#[new]" for a in attrs),
            )
            if in_scp_impl:
                scp_methods[py_name] = rec
            else:
                free_defs[rust_name] = rec


# ---------------------------------------------------------------------------
# Stub (.pyi) reconciliation
# ---------------------------------------------------------------------------


def _line_col_to_offset(text: str) -> list[int]:
    offsets = [0]
    for line in text.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    return offsets


def _pos(offsets: list[int], lineno: int, col: int) -> int:
    return offsets[lineno - 1] + col


def _param_span(text: str, def_start: int) -> tuple[int, int]:
    """Return (open_paren+1, close_paren) offsets for the def at ``def_start``."""
    i = text.index("(", def_start)
    depth = 0
    j = i
    while j < len(text):
        ch = text[j]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i + 1, j
        j += 1
    raise ValueError("unbalanced parentheses in def signature")


@dataclass
class Mismatch:
    kind: str
    detail: str


def reconcile(
    pyi_text: str,
    scp_methods: dict[str, RustFn],
    free_functions: dict[str, RustFn],
) -> tuple[str, list[Mismatch]]:
    """Return (rewritten_text, set_parity_mismatches)."""
    tree = ast.parse(pyi_text)
    offsets = _line_col_to_offset(pyi_text)
    edits: list[tuple[int, int, str]] = []  # (start, end, replacement)
    mismatches: list[Mismatch] = []

    pyi_scp_methods: set[str] = set()
    pyi_scp_props: set[str] = set()
    pyi_free: set[str] = set()

    def is_decorated(node: ast.FunctionDef, name: str) -> bool:
        for d in node.decorator_list:
            if isinstance(d, ast.Name) and d.id == name:
                return True
        return False

    def carry(node: ast.FunctionDef, rust: RustFn, has_receiver: bool) -> None:
        # Skip variadic catch-alls: they intentionally opt out of typed arity.
        if (
            node.args.vararg
            or node.args.kwarg
            or node.args.posonlyargs
            or node.args.kwonlyargs
        ):
            return
        current = list(node.args.args)
        receiver: list[ast.arg] = []
        if current and current[0].arg in ("self", "cls"):
            receiver = [current[0]]
            current = current[1:]
        # Positional (index-aligned) view of the hand-authored stub params,
        # receiver excluded. ``stub_ann[i]`` / ``stub_default[i]`` describe the
        # i-th non-receiver stub parameter.
        stub_ann: list[str] = [
            (ast.unparse(a.annotation) if a.annotation else "Any") for a in current
        ]
        ndefaults = len(node.args.defaults)
        stub_default: list[str | None] = [None] * (len(current) - ndefaults) + [
            ast.unparse(d) for d in node.args.defaults
        ]
        # By-name views. A transposition preserves NAMES, so a by-name lookup
        # carries each param's annotation/default to its new position — the
        # transposition auto-heals with zero type loss.
        default_for: dict[str, str] = {
            a.arg: d for a, d in zip(current, stub_default) if d is not None
        }
        ann_for: dict[str, str] = {a.arg: ann for a, ann in zip(current, stub_ann)}
        # A pure RENAME (same arity, different name) has no by-name match, so it
        # would otherwise drop the hand-authored type to ``Any``. When the arity
        # is unchanged, fall back to the POSITIONAL stub annotation/default so a
        # rename keeps its precise type (e.g. ``str``) rather than degrading.
        # When arity differs, a param was genuinely added/removed and positional
        # alignment is ambiguous, so unmatched params correctly stay ``Any``.
        same_arity = len(current) == len(rust.params)

        pieces: list[str] = []
        for r in receiver:
            pieces.append(
                r.arg + (f": {ast.unparse(r.annotation)}" if r.annotation else "")
            )
        for i, name in enumerate(rust.params):
            if name in ann_for:
                ann = ann_for[name]
                default = default_for.get(name)
            elif same_arity:
                ann = stub_ann[i]
                default = stub_default[i]
            else:
                ann = "Any"
                default = None
            piece = f"{name}: {ann}"
            if default is not None:
                piece += f" = {default}"
            elif name in rust.optional:
                piece += " = ..."
            pieces.append(piece)

        start, end = _param_span(pyi_text, _pos(offsets, node.lineno, node.col_offset))
        edits.append((start, end, ", ".join(pieces)))
        _ = has_receiver

    # -- SCP class methods --
    scp_class = next(
        (n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "SCP"), None
    )
    if scp_class is None:
        raise SystemExit("error: could not find `class SCP` in stub")
    for node in scp_class.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        name = node.name
        if is_decorated(node, "property"):
            pyi_scp_props.add(name)
            continue
        if name.startswith("__") and name.endswith("__"):
            continue  # structural dunder (__new__, __repr__) — preserved verbatim
        pyi_scp_methods.add(name)
        rust = scp_methods.get(name)
        if rust is None:
            mismatches.append(
                Mismatch("extra-method", f"SCP.{name} has no PyO3 export")
            )
            continue
        carry(node, rust, has_receiver=not rust.is_static)

    # -- module free functions --
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        name = node.name
        pyi_free.add(name)
        rust = free_functions.get(name)
        if rust is None:
            if name in STUB_ONLY_FREE_FUNCTIONS:
                continue
            mismatches.append(
                Mismatch("extra-function", f"{name}() has no PyO3 export")
            )
            continue
        carry(node, rust, has_receiver=False)

    # -- set parity: every export must have a stub --
    rust_method_names = {
        n for n, r in scp_methods.items() if not r.is_getter and not r.is_new
    }
    rust_method_names.discard("__repr__")
    rust_getter_names = {n for n, r in scp_methods.items() if r.is_getter}
    for miss in sorted(rust_method_names - pyi_scp_methods):
        mismatches.append(
            Mismatch("missing-method", f"SCP.{miss} exported but absent from stub")
        )
    for miss in sorted(rust_getter_names - pyi_scp_props):
        mismatches.append(
            Mismatch("missing-property", f"SCP.{miss} getter absent from stub")
        )
    for extra in sorted(pyi_scp_props - rust_getter_names):
        mismatches.append(
            Mismatch("extra-property", f"SCP.{extra} property has no PyO3 getter")
        )
    for miss in sorted(set(free_functions) - pyi_free):
        mismatches.append(
            Mismatch("missing-function", f"{miss}() exported but absent from stub")
        )

    # Apply edits back-to-front so offsets stay valid.
    out = pyi_text
    for start, end, repl in sorted(edits, key=lambda e: e[0], reverse=True):
        out = out[:start] + repl + out[end:]
    return out, mismatches


# ---------------------------------------------------------------------------
# Formatting + driver
# ---------------------------------------------------------------------------


def ruff_format(text: str) -> str:
    # Format under the Python package root so ruff discovers
    # ``bindings/python/pyproject.toml`` (line-length 100). The temp file must
    # NOT live in ``scp_sdk/`` — that directory contains a ``types.py`` that
    # shadows the stdlib when it is the process cwd, breaking ``-m ruff``.
    with tempfile.NamedTemporaryFile(
        "w", suffix=".pyi", delete=False, dir=PY_ROOT
    ) as tf:
        tf.write(text)
        tmp = Path(tf.name)
    try:
        subprocess.run(
            [sys.executable, "-m", "ruff", "format", "--quiet", tmp.name],
            check=True,
            cwd=PY_ROOT,
        )
        return tmp.read_text()
    finally:
        tmp.unlink(missing_ok=True)


def build() -> tuple[str, list[Mismatch]]:
    scp_methods, free_functions = collect_rust()
    pyi_text = PYI_PATH.read_text()
    rewritten, mismatches = reconcile(pyi_text, scp_methods, free_functions)
    return ruff_format(rewritten), mismatches


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Regenerate/verify the _scp_core type stub."
    )
    ap.add_argument(
        "--check",
        action="store_true",
        help="verify the committed stub matches the regenerated output; do not write.",
    )
    args = ap.parse_args()

    generated, mismatches = build()
    if mismatches:
        sys.stderr.write(
            "error: _scp_core.pyi is not in signature parity with PyO3 exports:\n"
        )
        for m in sorted(mismatches, key=lambda x: (x.kind, x.detail)):
            sys.stderr.write(f"  [{m.kind}] {m.detail}\n")
        sys.stderr.write(
            "\nFix the stub (or the export), then run `python3.12 scripts/generate-pyi.py`.\n"
        )
        return 1

    current = PYI_PATH.read_text()
    if args.check:
        if current != generated:
            sys.stderr.write(
                "error: _scp_core.pyi is out of date with the PyO3 signatures.\n"
                "Run `python3.12 scripts/generate-pyi.py` and commit the result.\n\n"
            )
            _print_diff(current, generated)
            return 1
        print("_scp_core.pyi is in sync with the PyO3 export signatures.")
        return 0

    if current != generated:
        PYI_PATH.write_text(generated)
        print(f"regenerated {PYI_PATH.relative_to(REPO)}")
    else:
        print(f"{PYI_PATH.relative_to(REPO)} already up to date")
    return 0


def _print_diff(a: str, b: str) -> None:
    import difflib

    diff = difflib.unified_diff(
        a.splitlines(keepends=True),
        b.splitlines(keepends=True),
        fromfile="committed/_scp_core.pyi",
        tofile="regenerated/_scp_core.pyi",
    )
    sys.stderr.writelines(diff)


if __name__ == "__main__":
    raise SystemExit(main())
