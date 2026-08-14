#!/usr/bin/env python3.12
# check-no-mutable-module-globals.py — CI gate forbidding new mutable
# module-level globals in the Python SDK (`bindings/python/scp_sdk/`).
#
# ---------------------------------------------------------------------------
# WHAT THIS CHECKS
# ---------------------------------------------------------------------------
# Phase 4 (#1549) removed the process-wide default `SCP` instance and the
# `_bridge: Optional[Bridge] = None` fallback pattern across the SDK. This
# gate prevents the pattern from creeping back in.
#
# An AST walk inspects every `.py` file under `bindings/python/scp_sdk/`.
# For each top-level (module-scope) assignment, if the target is a simple
# name and the value is NOT a known immutable shape, the assignment fails
# unless:
#
#   - The name is on the explicit ALLOWLIST below (each allowlist entry
#     is documented with a one-line rationale).
#   - The name is a dunder convention constant (`__all__`, `__version__`,
#     `__author__`, ...).
#   - The name is ALL_UPPERCASE (constant convention, including dunders).
#   - The value is a pure-constant constructor (see IMMUTABLE_CALL_NAMES).
#   - The target is a type alias (`_Bridge: TypeAlias = ...`).
#
# `if TYPE_CHECKING:` blocks and docstrings are skipped: nothing assigned
# only for type analysis reaches runtime.
#
# Tests (`bindings/python/tests/`) are NOT scanned — fixtures are allowed.
#
# ---------------------------------------------------------------------------
# HOW TO FIX A FAILURE
# ---------------------------------------------------------------------------
# The usual cause: a new `_foo: SomeType | None = None` at module scope, or
# a `_bar = {}` / `_bar = []` introduced as a lazy cache.
#
#   1. Move the state onto an explicit class (preferred — `SCP` / `Context` /
#      a module-level dataclass). This is the pattern every per-instance
#      piece of state already follows.
#   2. If the state is genuinely a process-global (e.g. the `_sync_loop`
#      daemon thread, the `_emitted` deprecation dedup set), add the fully-
#      qualified name to the ALLOWLIST below AND add a comment on the
#      assignment in the source explaining why.
#
# Do NOT rename the variable to ALL_CAPS just to silence this gate — the
# name convention is a signal that a human reviewer will check.
#
# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
#   python3.12 scripts/check-no-mutable-module-globals.py
#
# Exit codes:
#   0  — all module-level assignments are allowed
#   1  — one or more new mutable module-level globals were introduced
#   2  — invocation error (root directory missing)

from __future__ import annotations

import ast
import pathlib
import sys
from collections.abc import Iterable
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Fully-qualified allowlist entries — `<module path relative to SCAN_ROOT>::<name>`.
# Each entry must have a rationale comment.
ALLOWLIST: frozenset[str] = frozenset(
    {
        # sync.py — the SCP SDK owns a single background daemon event loop
        # used by `run_sync()`. The loop is created lazily on first call,
        # runs in a daemon thread that dies with the process, and exists
        # precisely because asyncio cannot nest. Documented in ADR-014 AC 6.
        "sync.py::_sync_loop",
        "sync.py::_sync_loop_lock",
        # scp.py — type alias (discriminated union over storage-config
        # dataclasses). Not mutable state — `X | Y` evaluates to a
        # `types.UnionType` whose `__class__` methods do not mutate the
        # global. Dispatched on by `SCP.with_storage` at construction time.
        "scp.py::StorageConfig",
    }
)

# Names of callables whose return value is, by convention, immutable or
# effectively frozen for our purposes.
IMMUTABLE_CALL_NAMES: frozenset[str] = frozenset(
    {
        "frozenset",
        "tuple",
        "namedtuple",
        "getLogger",
        "TypeVar",
        "ParamSpec",
        "NewType",
        "IntEnum",
        "Enum",
        "StrEnum",
        "Flag",
        "IntFlag",
        # `re.compile` returns a compiled pattern object that is effectively
        # immutable — no public API mutates it.
        "compile",
    }
)

# Attribute names whose wrapped call is treated as producing an immutable
# value regardless of the called expression shape (e.g. `typing.Final[...]`
# subscript is itself a type annotation target, handled elsewhere).
IMMUTABLE_ATTR_NAMES: frozenset[str] = IMMUTABLE_CALL_NAMES

# Relative path to the SDK root. Resolved against the repo root (the parent
# of this scripts/ directory) at runtime.
SCAN_ROOT_REL = "bindings/python/scp_sdk"


# ---------------------------------------------------------------------------
# Violation reporting
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Violation:
    """A single disallowed module-level assignment."""

    file: pathlib.Path
    line: int
    name: str
    reason: str


# ---------------------------------------------------------------------------
# Immutability heuristic
# ---------------------------------------------------------------------------


def _is_immutable_constant(node: ast.AST) -> bool:
    """True iff *node* is a value we can prove is immutable at runtime.

    This is intentionally conservative: when in doubt, return False so the
    gate fires and a human reviewer makes the call.
    """
    # Literals
    if isinstance(node, ast.Constant):
        return True

    # Unary minus / plus on a literal: `-1`, `+42`
    if isinstance(node, ast.UnaryOp) and isinstance(
        node.op, (ast.USub, ast.UAdd, ast.Invert)
    ):
        return _is_immutable_constant(node.operand)

    # BinOp between constants: `"0" * 64`, `1 << 8`, `A + B` where both
    # operands are immutable.
    if isinstance(node, ast.BinOp):
        return _is_immutable_constant(node.left) and _is_immutable_constant(node.right)

    # Tuples of immutable values: `(1, 2, 3)`, `("a", "b")`
    if isinstance(node, ast.Tuple):
        return all(_is_immutable_constant(elt) for elt in node.elts)

    # Bare `frozenset(...)`, `tuple(...)`, `re.compile(...)`, ...
    if isinstance(node, ast.Call):
        callee = node.func
        name: str | None = None
        if isinstance(callee, ast.Name):
            name = callee.id
        elif isinstance(callee, ast.Attribute):
            name = callee.attr
        if name in IMMUTABLE_CALL_NAMES:
            return True
        # Class construction where the class name is ALL_CAPS (not typical
        # in Python but allowed) is NOT assumed immutable.
        return False

    # Name reference to another module-level constant: `FOO = OTHER_CONST`.
    # Assumed immutable — the reviewer already cleared OTHER_CONST.
    if isinstance(node, ast.Name):
        if node.id.isupper() or (node.id.startswith("_") and node.id.isupper()):
            return True
        # Standard library sentinels.
        return node.id in {"None", "True", "False", "Ellipsis"}

    # Subscript access: `Final[int]`, `tuple[int, ...]` etc. Treated as
    # immutable — these never resolve to a runtime mutable container by
    # themselves; a full type-alias assignment is detected via the
    # AnnAssign annotation pathway.
    if isinstance(node, ast.Subscript):
        return True

    # Attribute access: `some.CONST` — we assume Title/ALL_CAPS attribute
    # references are constants. Conservative otherwise.
    if isinstance(node, ast.Attribute):
        return node.attr.isupper() or node.attr[:1].isupper()

    return False


def _is_type_alias(node: ast.AnnAssign) -> bool:
    """True iff *node* looks like a type-alias assignment.

    Matches two shapes:
        X: TypeAlias = ...
        X: "TypeAlias" = ...
    Only the annotation is inspected — the RHS can be anything legal for a
    type expression. (Mutable containers as type expressions don't exist.)
    """
    ann = node.annotation
    if isinstance(ann, ast.Name) and ann.id == "TypeAlias":
        return True
    if (
        isinstance(ann, ast.Constant)
        and isinstance(ann.value, str)
        and ann.value.strip() == "TypeAlias"
    ):
        return True
    if isinstance(ann, ast.Attribute) and ann.attr == "TypeAlias":
        return True
    return False


def _is_dunder_or_upper(name: str) -> bool:
    """True iff *name* is a dunder convention or fully uppercase (constant)."""
    if name.startswith("__") and name.endswith("__"):
        return True
    stripped = name.lstrip("_")
    return bool(stripped) and stripped.isupper()


def _is_in_type_checking(node: ast.stmt) -> bool:
    """Return True iff *node* sits inside an `if TYPE_CHECKING:` block.

    Only directly-contained children are checked — we walk from the module
    root and skip the whole branch, so this helper is unused in that mode.
    Present for defensive symmetry.
    """
    # ast does not store parent pointers; the walker below handles this by
    # skipping `If` bodies gated on TYPE_CHECKING. This helper is here so a
    # future caller can use it.
    return False


# ---------------------------------------------------------------------------
# Module walker
# ---------------------------------------------------------------------------


def _iter_module_level_statements(tree: ast.Module) -> Iterable[ast.stmt]:
    """Yield every top-level statement that is NOT inside an
    ``if TYPE_CHECKING:`` block.

    Nested classes/functions are intentionally NOT descended — their
    members are naturally scoped. Only the module body is our concern.
    """
    for stmt in tree.body:
        if isinstance(stmt, ast.If):
            test = stmt.test
            # `if TYPE_CHECKING:` or `if typing.TYPE_CHECKING:` — skip
            # entirely. Orelse branches are still yielded (they execute at
            # runtime when TYPE_CHECKING is False).
            is_type_checking = (
                isinstance(test, ast.Name) and test.id == "TYPE_CHECKING"
            ) or (isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING")
            if is_type_checking:
                # The `orelse` branch runs at import; scan it but not the body.
                yield from stmt.orelse
                continue
        yield stmt


def _check_assign(
    stmt: ast.Assign,
    file_rel: str,
    violations: list[Violation],
) -> None:
    """Validate a plain `a = expr` assignment at module scope."""
    for target in stmt.targets:
        if not isinstance(target, ast.Name):
            # Tuple/attr/subscript targets at module scope — rare; ignore.
            continue
        name = target.id
        key = f"{file_rel}::{name}"
        if key in ALLOWLIST:
            continue
        if _is_dunder_or_upper(name):
            continue
        if _is_immutable_constant(stmt.value):
            continue
        violations.append(
            Violation(
                file=pathlib.Path(file_rel),
                line=stmt.lineno,
                name=name,
                reason="mutable module-level assignment",
            )
        )


def _annotation_suggests_mutable_binding(ann: ast.expr) -> bool:
    """True iff the annotation *ann* implies the runtime value is a mutable
    binding (e.g. ``Optional[X]`` / ``X | None`` / ``list[...]`` / ``dict[...]``).

    The caller uses this to reject ``_foo: X | None = None`` — a lazy-cache
    pattern that is mechanically indistinguishable from the removed
    ``DEFAULT_BRIDGE_INSTANCE`` shape.
    """
    # `X | None` / `Optional[X]`
    if isinstance(ann, ast.BinOp) and isinstance(ann.op, ast.BitOr):
        for side in (ann.left, ann.right):
            if isinstance(side, ast.Constant) and side.value is None:
                return True
            if isinstance(side, ast.Name) and side.id == "None":
                return True
    if isinstance(ann, ast.Subscript):
        base = ann.value
        name = None
        if isinstance(base, ast.Name):
            name = base.id
        elif isinstance(base, ast.Attribute):
            name = base.attr
        if name in {"Optional", "Union", "list", "List", "dict", "Dict", "set", "Set"}:
            return True
    if isinstance(ann, ast.Name):
        # Bare `list`, `dict`, `set` — a mutable container is assigned.
        if ann.id in {"list", "dict", "set"}:
            return True
    return False


def _check_ann_assign(
    stmt: ast.AnnAssign,
    file_rel: str,
    violations: list[Violation],
) -> None:
    """Validate an annotated `a: T = expr` assignment at module scope."""
    if stmt.value is None:
        # Pure annotation (forward declaration) — no runtime value.
        return
    if not isinstance(stmt.target, ast.Name):
        return
    if _is_type_alias(stmt):
        return
    name = stmt.target.id
    key = f"{file_rel}::{name}"
    if key in ALLOWLIST:
        return
    if _is_dunder_or_upper(name):
        return
    # Lazy-cache detector: if the annotation says "this may be None" or
    # "this is a mutable container", the binding is rebindable at runtime
    # — reject regardless of the initializer's apparent immutability.
    if _annotation_suggests_mutable_binding(stmt.annotation):
        violations.append(
            Violation(
                file=pathlib.Path(file_rel),
                line=stmt.lineno,
                name=name,
                reason="rebindable module-level binding (Optional / list / dict / set)",
            )
        )
        return
    if _is_immutable_constant(stmt.value):
        return
    violations.append(
        Violation(
            file=pathlib.Path(file_rel),
            line=stmt.lineno,
            name=name,
            reason="mutable annotated module-level assignment",
        )
    )


def _scan_file(path: pathlib.Path, root: pathlib.Path) -> list[Violation]:
    """Return every violation in *path*, with paths reported relative to *root*."""
    rel_path = str(path.relative_to(root))
    source = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        return [
            Violation(
                file=pathlib.Path(rel_path),
                line=exc.lineno or 0,
                name="<parse-error>",
                reason=f"SyntaxError: {exc.msg}",
            )
        ]

    violations: list[Violation] = []
    for stmt in _iter_module_level_statements(tree):
        if isinstance(stmt, ast.Assign):
            _check_assign(stmt, rel_path, violations)
        elif isinstance(stmt, ast.AnnAssign):
            _check_ann_assign(stmt, rel_path, violations)
    return violations


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _repo_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent.parent


def _tty_colors() -> tuple[str, str, str, str, str]:
    if sys.stdout.isatty():
        return (
            "\033[31m",  # red
            "\033[32m",  # green
            "\033[33m",  # yellow
            "\033[2m",  # dim
            "\033[0m",  # reset
        )
    return ("", "", "", "", "")


def main() -> int:
    repo = _repo_root()
    scan_root = repo / SCAN_ROOT_REL
    if not scan_root.is_dir():
        print(f"error: scan root does not exist: {scan_root}", file=sys.stderr)
        return 2

    red, green, yellow, dim, reset = _tty_colors()

    violations: list[Violation] = []
    for py_file in sorted(scan_root.rglob("*.py")):
        # Skip any `tests/` subfolder defensively (tests live elsewhere, but
        # future reshuffles should not accidentally bring them into scope).
        if "tests" in py_file.parts:
            continue
        violations.extend(_scan_file(py_file, scan_root))

    print()
    print(f"{dim}mutable module-global scan (bindings/python/scp_sdk/):{reset}")

    if not violations:
        print(f"{green}PASSED{reset}: no mutable module-level globals.")
        return 0

    print(
        f"{red}FAILED{reset}: {len(violations)} disallowed module-level assignment(s).",
        file=sys.stderr,
    )
    print(file=sys.stderr)
    for v in violations:
        print(
            f"  {dim}{v.file}:{v.line}{reset}  {yellow}{v.name}{reset}  "
            f"({dim}{v.reason}{reset})",
            file=sys.stderr,
        )
    print(file=sys.stderr)
    print("A new module-level assignment must either:", file=sys.stderr)
    print("  1. live on a class (SCP / Context / a dataclass),", file=sys.stderr)
    print(
        "     or be passed in via constructor injection (preferred), or",
        file=sys.stderr,
    )
    print("  2. be added to the ALLOWLIST in", file=sys.stderr)
    print(
        "     scripts/check-no-mutable-module-globals.py with a justifying",
        file=sys.stderr,
    )
    print("     comment, AND a comment on the assignment itself.", file=sys.stderr)
    print(file=sys.stderr)
    print("ALL_CAPS names are assumed to be immutable constants by", file=sys.stderr)
    print("convention — do NOT rename to silence this gate.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
