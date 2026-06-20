"""Self-tests for check-sdk-coverage.py.

Covers:
  1. Gate exits 0 (PASS) on the real matrix.
  2. Gate exits 1 when a true entry has no matching symbol and no exemption.
  3. _extract_python_symbols correctly extracts a function name via tree-sitter.
  4. _extract_python_symbols handles class with method names.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Locate the script under test
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "check-sdk-coverage.py"

# ---------------------------------------------------------------------------
# Load extraction helpers directly for unit tests.
#
# The script filename uses hyphens (check-sdk-coverage.py) which is not a
# valid Python module name, so we load it via importlib.
# ---------------------------------------------------------------------------

_spec = importlib.util.spec_from_file_location("check_sdk_coverage", SCRIPT)
assert _spec is not None and _spec.loader is not None
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)  # type: ignore[attr-defined]

_extract_python_symbols = _mod._extract_python_symbols


# ---------------------------------------------------------------------------
# Test 1: Gate passes on the real matrix
# ---------------------------------------------------------------------------


def test_gate_passes_on_real_matrix() -> None:
    """Running the gate against the live matrix must exit 0."""
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"Gate exited {result.returncode} on the real matrix.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


# ---------------------------------------------------------------------------
# Test 2: Gate exits 1 on a synthetic matrix with unmatched true entry
# ---------------------------------------------------------------------------


def test_gate_fails_on_unmatched_true_entry(tmp_path: Path) -> None:
    """A `true` cell with no matching symbol and no coverage_exemption exits 1."""
    synthetic_matrix = {
        "capabilities": [
            {
                "domain": "Fake",
                "operations": [
                    {
                        "name": "nonexistent_operation_zzzzzz",
                        "python": True,
                    }
                ],
            }
        ]
    }
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps(synthetic_matrix), encoding="utf-8")

    # Point the gate at our synthetic matrix by monkey-patching MATRIX_PATH.
    # The script reads it from a module-level constant, so we drive it via
    # a small wrapper script that loads the gate module and patches the path
    # before calling main().
    script_path = str(SCRIPT)
    matrix_path = str(matrix_file)
    wrapper = tmp_path / "run_with_matrix.py"
    wrapper.write_text(
        textwrap.dedent(f"""\
            import sys
            import importlib.util
            from pathlib import Path

            _spec = importlib.util.spec_from_file_location("check_sdk_coverage", {script_path!r})
            _mod = importlib.util.module_from_spec(_spec)
            _spec.loader.exec_module(_mod)

            _mod.MATRIX_PATH = Path({matrix_path!r})
            sys.exit(_mod.main())
        """),
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(wrapper)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1, (
        f"Gate should have exited 1 for unmatched true entry, got {result.returncode}.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "ERROR" in result.stdout or "FAIL" in result.stdout


# ---------------------------------------------------------------------------
# Test 3: _extract_python_symbols returns the correct name for a bare function
# ---------------------------------------------------------------------------


def test_extract_python_symbols_simple_function() -> None:
    """_extract_python_symbols extracts 'hello' from 'def hello(): pass'."""
    try:
        import tree_sitter_python as tspython
        from tree_sitter import Language, Parser
    except ImportError:
        pytest.skip("tree-sitter-python not installed")

    parser = Parser(Language(tspython.language()))
    source = b"def hello(): pass"
    tree = parser.parse(source)
    symbols = _extract_python_symbols(tree.root_node)
    assert "hello" in symbols, f"Expected 'hello' in symbols, got: {symbols}"


# ---------------------------------------------------------------------------
# Test 4: _extract_python_symbols handles class with method
# ---------------------------------------------------------------------------


def test_extract_python_symbols_class_method() -> None:
    """_extract_python_symbols collects class name and method names."""
    try:
        import tree_sitter_python as tspython
        from tree_sitter import Language, Parser
    except ImportError:
        pytest.skip("tree-sitter-python not installed")

    parser = Parser(Language(tspython.language()))
    source = b"class Foo:\n    def bar(self): pass\n"
    tree = parser.parse(source)
    symbols = _extract_python_symbols(tree.root_node)
    assert "Foo" in symbols, f"Expected 'Foo' in symbols, got: {symbols}"
    assert "bar" in symbols, f"Expected 'bar' in symbols, got: {symbols}"
    assert "Foo.bar" in symbols, f"Expected 'Foo.bar' in symbols, got: {symbols}"
