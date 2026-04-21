"""Unit tests for ``scripts/check-call-invariants.py`` cfg-predicate walkers.

Covers the round-5 regression tests for:

* ``_cfg_predicate_is_test_gated`` — parses ``cfg(...)`` token trees with
  ``under_not`` bookkeeping. Round-4's MINOR-1 fix replaced a naive
  substring check that treated ``#[cfg(not(test))]`` as test-gated.
* ``_attribute_is_test_cfg`` — routes ``#[cfg(...)]`` attributes through
  the predicate walker; rejects non-cfg attributes.
* ``_call_is_test_cfg_gated`` — walks up from a call expression through
  gateable ancestors up to the fn body.
* ``_walk_functions`` — excludes functions inside ``#[cfg(test)]`` modules
  *and* ``#[cfg(test)]`` impl blocks (round-5 MAJOR-1 fix).

Rust is parsed with the real ``tree_sitter_rust`` grammar; we never stub
the parser because the walkers key off actual node types.

Run with:

    python3.12 -m pytest scripts/tests/call-invariants/ -v

All cases must pass. CI wires this into the ``sdk-coverage`` job.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

# Load ``scripts/check-call-invariants.py`` as a module. Its hyphenated
# filename is not a valid Python identifier, so direct ``import`` won't
# work. ``importlib.util`` is the supported way to load such files and it
# keeps this test file decoupled from the script's deployment location.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT_PATH = _REPO_ROOT / "scripts" / "check-call-invariants.py"
_SPEC = importlib.util.spec_from_file_location("check_call_invariants", _SCRIPT_PATH)
assert _SPEC is not None and _SPEC.loader is not None, (
    f"failed to locate {_SCRIPT_PATH}"
)
_MOD = importlib.util.module_from_spec(_SPEC)
sys.modules["check_call_invariants"] = _MOD
_SPEC.loader.exec_module(_MOD)

PARSER = _MOD.PARSER


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse(src: str):
    """Parse a Rust source snippet and return the tree-sitter tree."""
    source = src.encode("utf-8")
    tree = PARSER.parse(source)
    assert not tree.root_node.has_error, f"tree-sitter failed to parse snippet:\n{src}"
    return tree, source


def _first_attribute_item(root):
    """Return the first ``attribute_item`` node in the tree."""
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "attribute_item":
            return node
        stack.extend(node.children)
    return None


def _eval_attribute(src: str) -> bool:
    """Parse ``src`` and return ``_attribute_is_test_cfg`` on its first attr."""
    tree, source = _parse(src + "\nfn __anchor() {}\n")
    attr = _first_attribute_item(tree.root_node)
    assert attr is not None, f"no attribute_item found in:\n{src}"
    return _MOD._attribute_is_test_cfg(attr, source)


# ---------------------------------------------------------------------------
# _cfg_predicate_is_test_gated / _attribute_is_test_cfg
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "attr_src,expected,label",
    [
        ("#[cfg(test)]", True, "bare_test"),
        ("#[cfg(not(test))]", False, "not_test_is_production"),
        ("#[cfg(all(test, unix))]", True, "all_with_test"),
        ('#[cfg(any(test, feature="x"))]', True, "any_with_test"),
        ("#[cfg(all(not(test), unix))]", False, "all_not_test_is_production"),
        # any(not(test), feature="y") — production path exists (when feature y
        # AND NOT test). Conservatively: production-reachable, NOT test-gated.
        ('#[cfg(any(not(test), feature="y"))]', False, "any_not_test_production"),
        ("#[cfg(not(not(test)))]", True, "double_not_test"),
        # all(not(all(test, unix)), ...) — the outer not wraps a predicate
        # containing test, flipping it to production. NOT test-gated.
        (
            "#[cfg(all(not(all(test, unix))))]",
            False,
            "not_wraps_all_with_test_production",
        ),
        ('#[cfg(feature = "x")]', False, "feature_only"),
        # cfg_attr is conditional attribute application, NOT a gate.
        # _attribute_is_test_cfg must return False because attr_name != "cfg".
        ("#[cfg_attr(test, deprecated)]", False, "cfg_attr_is_not_a_gate"),
    ],
    ids=lambda p: p if isinstance(p, str) else repr(p),
)
def test_attribute_is_test_cfg(attr_src: str, expected: bool, label: str) -> None:
    """Round-trip every documented case through the real tree-sitter parser."""
    actual = _eval_attribute(attr_src)
    assert actual is expected, (
        f"{label}: {attr_src!r} expected={expected}, got={actual}"
    )


# ---------------------------------------------------------------------------
# _walk_functions — MAJOR-1 regression (cfg(test) on impl blocks)
# ---------------------------------------------------------------------------


def _walk(src: str) -> list[str]:
    """Return the names of all production functions ``_walk_functions`` emits."""
    tree, source = _parse(src)
    records = _MOD._walk_functions(tree.root_node, source, Path("<test>.rs"))
    return [fn.name for fn in records]


def test_walk_functions_excludes_cfg_test_impl_block() -> None:
    """A method in ``#[cfg(test)] impl Foo { ... }`` must NOT be scanned.

    Before the round-5 fix, ``_walk_functions`` only checked ``mod_item``
    for a test-cfg attribute, so methods inside a test-only impl block
    were classified as production. ``_call_is_test_cfg_gated`` stops at
    the enclosing fn body and cannot see the impl's cfg attribute, so
    exclusion must happen at walk time.
    """
    src = """
struct Foo;
impl Foo {
    fn production_method(&self) {}
}

#[cfg(test)]
impl Foo {
    fn test_only_method(&self) {
        required_callee();
    }
}
"""
    names = _walk(src)
    assert "production_method" in names
    assert "test_only_method" not in names, (
        "method in #[cfg(test)] impl block leaked into production walk — "
        "MAJOR-1 regression"
    )


def test_walk_functions_respects_cfg_not_test_impl_block() -> None:
    """``#[cfg(not(test))] impl Foo { fn m() }`` IS production."""
    src = """
struct Foo;
#[cfg(not(test))]
impl Foo {
    fn production_only_method(&self) {}
}
"""
    names = _walk(src)
    assert "production_only_method" in names, (
        "cfg(not(test)) on impl block must NOT exclude the method"
    )


def test_walk_functions_excludes_cfg_test_trait_block() -> None:
    """A default method in ``#[cfg(test)] trait Foo { ... }`` must NOT be scanned.

    Round-6 MINOR-1 fix: the root-type gate in ``_walk_functions`` previously
    only checked ``mod_item`` and ``impl_item``. A ``trait_item`` with default
    methods (``#[cfg(test)] trait Foo { fn helper() { ... } }``) leaked into
    the production walk. ``_call_is_test_cfg_gated`` stops at the enclosing
    fn body, so it cannot see the trait's cfg attribute — exclusion must
    happen at walk time just like ``impl_item``.
    """
    src = """
trait RealTrait {
    fn production_default(&self) {}
}

#[cfg(test)]
trait TestTrait {
    fn should_be_skipped(&self) {
        forbidden_callee();
    }
}
"""
    names = _walk(src)
    assert "production_default" in names
    assert "should_be_skipped" not in names, (
        "default method in #[cfg(test)] trait block leaked into production "
        "walk — round-6 MINOR-1 regression"
    )


def test_walk_functions_excludes_cfg_test_module() -> None:
    """Existing behavior preserved: methods in ``#[cfg(test)] mod`` excluded."""
    src = """
fn prod() {}

#[cfg(test)]
mod tests {
    fn helper() {}
}
"""
    names = _walk(src)
    assert "prod" in names
    assert "helper" not in names


def test_walk_functions_handles_cfg_test_on_function_directly() -> None:
    """A function-level ``#[cfg(test)] fn m()`` is excluded."""
    src = """
#[cfg(test)]
fn test_only() {}

fn prod() {}
"""
    names = _walk(src)
    assert "prod" in names
    assert "test_only" not in names


def test_walk_functions_handles_nested_cfg_test_impl_in_mod() -> None:
    """Nested case: ``#[cfg(test)] impl`` inside a non-test module."""
    src = """
mod regular {
    struct Foo;
    impl Foo {
        fn prod_method(&self) {}
    }

    #[cfg(test)]
    impl Foo {
        fn test_method(&self) {
            forbidden();
        }
    }
}
"""
    names = _walk(src)
    assert "prod_method" in names
    assert "test_method" not in names


# ---------------------------------------------------------------------------
# _call_is_test_cfg_gated — statement-level test exclusion
# ---------------------------------------------------------------------------


def test_call_is_test_cfg_gated_stops_at_fn_body() -> None:
    """Walker must stop at the enclosing fn body (round-6 MINOR-2 fix).

    tree-sitter's Python binding returns a fresh ``Node`` wrapper on every
    ``.parent`` access, so the old ``node is not body`` stop condition was
    always True — the loop walked past the fn body up to ``source_file``.

    Repro: nested fn ``inner`` inside ``#[cfg(test)] fn outer()``. The
    ``#[cfg(test)]`` attribute keeps ``outer`` out of the production walk,
    but ``inner`` is walked separately (function-level test_ctx is not
    propagated through function_item). A call inside ``inner`` should
    belong to ``inner``'s production call graph — ``_call_is_test_cfg_gated``
    must stop walking at ``inner``'s body and NOT reach ``outer``'s
    function_item (which carries the cfg(test) attr).

    Before the fix: the walker escaped ``inner``'s body, found
    ``outer``'s cfg(test) attribute, and wrongly filtered ``my_call``
    out of ``inner``'s call graph.
    """
    src = """
#[cfg(test)]
fn outer() {
    fn inner() {
        my_call();
    }
}
"""
    tree, source = _parse(src)
    records = _MOD._walk_functions(tree.root_node, source, Path("<test>.rs"))
    inner = next((r for r in records if r.name == "inner"), None)
    assert inner is not None, (
        "nested fn inside #[cfg(test)] fn outer must still be walked — "
        "cfg(test) on function_item does not propagate through nested fns"
    )
    names = [n for n, _ in _MOD._collect_calls(inner.body, source)]
    assert "my_call" in names, (
        "call inside nested inner fn was wrongly excluded — walker escaped "
        "inner's body and matched outer's cfg(test) attribute. This is the "
        "round-6 MINOR-2 regression: `node is not body` never terminated "
        "because tree-sitter issues fresh Node wrappers on every .parent "
        "access."
    )


def test_call_is_test_cfg_gated_statement_level() -> None:
    """``#[cfg(test)]`` on an expression statement inside a prod fn.

    ``_collect_calls`` already uses ``_call_is_test_cfg_gated`` to filter
    such calls out of the production call graph.
    """
    src = """
fn prod() {
    allowed();
    #[cfg(test)]
    forbidden();
}
"""
    tree, source = _parse(src)
    # Find the fn body.
    stack = [tree.root_node]
    body = None
    while stack:
        node = stack.pop()
        if node.type == "function_item":
            body = _MOD._function_body(node)
            break
        stack.extend(node.children)
    assert body is not None

    calls = _MOD._collect_calls(body, source)
    names = [n for n, _ in calls]
    assert "allowed" in names
    assert "forbidden" not in names, (
        "call guarded by #[cfg(test)] must be excluded from production call graph"
    )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
