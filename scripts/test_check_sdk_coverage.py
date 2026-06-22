"""Self-tests for check-sdk-coverage.py.

Covers:
  1. Gate exits 0 (PASS) on the real matrix.
  2. Gate exits 1 when a true entry has no matching symbol and no exemption
     (unmatched-true path, isolated from missing-SDK-key errors).
  3. _extract_python_symbols correctly extracts a function name via tree-sitter.
  4. _extract_python_symbols handles class with method names.
  5. Gate exits 0 when a true entry has a valid coverage_exemption and at
     least one other SDK is statically verified.
  6. Gate exits 1 when every true cell for an op has a coverage_exemption but
     none is statically verified (all-exempted guard).
  7. Gate exits 1 when a cell value is neither a boolean nor null (e.g. the
     string "true" instead of a JSON boolean true).
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
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
# Wrapper-script builder
#
# All integration tests drive the gate via a subprocess wrapper so they can
# patch module-level constants (MATRIX_PATH, SDK_PATHS) before calling main().
# ---------------------------------------------------------------------------

_SCRIPT_PATH_STR = str(SCRIPT)


def _build_wrapper(
    tmp_path: Path,
    matrix_path: Path,
    sdk_paths: dict[str, Path] | None = None,
) -> Path:
    """Write a wrapper script that patches MATRIX_PATH (and optionally
    SDK_PATHS) before invoking main(), and return its path.

    Parameters
    ----------
    tmp_path:
        Directory in which to write the wrapper.
    matrix_path:
        Synthetic matrix JSON file to use.
    sdk_paths:
        Optional mapping of SDK name → directory to use instead of the real
        SDK source trees. Only the keys listed here are replaced; omitted keys
        retain the gate's built-in defaults (which point at the live source).
    """
    patch_sdk_paths_lines: list[str] = []
    if sdk_paths:
        patch_sdk_paths_lines.append("_mod.SDK_PATHS.update({")
        for sdk, path in sdk_paths.items():
            patch_sdk_paths_lines.append(f"    {sdk!r}: Path({str(path)!r}),")
        patch_sdk_paths_lines.append("})")

    # Build the wrapper body as a list of lines to avoid indentation issues
    # when injecting the optional SDK_PATHS patch block.
    body_lines = [
        "import sys",
        "import importlib.util",
        "from pathlib import Path",
        "",
        f"_spec = importlib.util.spec_from_file_location('check_sdk_coverage', {_SCRIPT_PATH_STR!r})",
        "_mod = importlib.util.module_from_spec(_spec)",
        "_spec.loader.exec_module(_mod)",
        "",
        f"_mod.MATRIX_PATH = Path({str(matrix_path)!r})",
    ]
    if patch_sdk_paths_lines:
        body_lines.extend(patch_sdk_paths_lines)
    body_lines.append("sys.exit(_mod.main())")

    wrapper = tmp_path / "run_with_matrix.py"
    wrapper.write_text("\n".join(body_lines) + "\n", encoding="utf-8")
    return wrapper


def _run_wrapper(wrapper: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(wrapper)],
        capture_output=True,
        text=True,
    )


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
#
# Previous version: had only `python: True` and omitted typescript/kotlin/swift
# entirely, producing 3 missing-SDK-key errors AND 1 unmatched-true error.
# The test passed even when the unmatched-true branch was deleted (the
# missing-SDK-key errors alone drove returncode=1).
#
# Fixed version: gives all 4 SDK keys.  python=True (no matching symbol, no
# exemption).  The other three are false with valid exemptions.  The ONLY
# error path that can fire is the unmatched-true check for python.
# ---------------------------------------------------------------------------


def test_gate_fails_on_unmatched_true_entry(tmp_path: Path) -> None:
    """A `true` cell with no matching symbol and no coverage_exemption exits 1.

    All four SDK keys are present so missing-SDK-key errors cannot mask the
    property under test.  The three false cells each carry a valid exemption
    so the only possible failure is the unmatched-true path for python.
    """
    synthetic_matrix = {
        "capabilities": [
            {
                "domain": "Fake",
                "operations": [
                    {
                        "name": "nonexistent_operation_zzzzzz",
                        # python: true but the symbol won't exist anywhere
                        "python": True,
                        # Other SDKs: false + valid exemption string (no errors expected)
                        "typescript": False,
                        "kotlin": False,
                        "swift": False,
                        "exemptions": {
                            "typescript": "Not yet implemented in TypeScript SDK",
                            "kotlin": "Not yet implemented in Kotlin SDK",
                            "swift": "Not yet implemented in Swift SDK",
                        },
                    }
                ],
            }
        ]
    }
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps(synthetic_matrix), encoding="utf-8")

    wrapper = _build_wrapper(tmp_path, matrix_file)
    result = _run_wrapper(wrapper)

    assert result.returncode == 1, (
        f"Gate should have exited 1 for unmatched true entry, got {result.returncode}.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    # The gate prints this specific per-operation error line for unmatched-true cells.
    # Assert on the exact phrase from the error branch (not the summary label, which
    # appears on every run regardless of error count).
    assert "no matching SDK symbol was found" in result.stdout, (
        f"Expected unmatched-true error phrase 'no matching SDK symbol was found' in stdout.\n"
        f"stdout:\n{result.stdout}"
    )


# ---------------------------------------------------------------------------
# Test 2b: Gate exits 1 when a required SDK key is missing entirely
# ---------------------------------------------------------------------------


def test_gate_fails_on_missing_sdk_key(tmp_path: Path) -> None:
    """An op that omits a required SDK key entirely must fail.

    The gate distinguishes a missing key (authoring gap — never evaluated for
    that SDK) from an explicit false entry (deliberate exemption).  A missing
    key must produce a specific error and exit 1, regardless of other entries.
    """
    synthetic_matrix = {
        "capabilities": [
            {
                "domain": "Fake",
                "operations": [
                    {
                        "name": "missing_key_op_zzzzzz",
                        # swift key is entirely absent — not false, not true
                        "python": False,
                        "typescript": False,
                        "kotlin": False,
                        # "swift" key deliberately omitted
                        "exemptions": {
                            "python": "Not yet implemented in Python SDK",
                            "typescript": "Not yet implemented in TypeScript SDK",
                            "kotlin": "Not yet implemented in Kotlin SDK",
                        },
                    }
                ],
            }
        ]
    }
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps(synthetic_matrix), encoding="utf-8")

    wrapper = _build_wrapper(tmp_path, matrix_file)
    result = _run_wrapper(wrapper)

    assert result.returncode == 1, (
        f"Gate should have exited 1 for missing SDK key, got {result.returncode}.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    # The gate prints a per-op error that names the missing SDK key.
    assert "missing SDK key" in result.stdout or "'swift'" in result.stdout, (
        f"Expected missing-SDK-key error phrase in stdout.\nstdout:\n{result.stdout}"
    )


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


# ---------------------------------------------------------------------------
# Test 5: Gate passes when a true entry has a valid coverage_exemption and
#          at least one other SDK is statically verified.
#
# Setup:
#   - python=True  — symbol NOT in the fake Python source; carries a
#     coverage_exemptions entry with a non-empty reason.
#   - typescript=True — symbol IS in the fake TypeScript source (statically
#     verified); no exemption needed.
#   - kotlin=False, swift=False — each with a valid exemption.
#
# The gate must exit 0: python's true cell is legitimately exempted, and
# typescript provides the required ground-truth static verification, so the
# all-exempted guard does not fire.
# ---------------------------------------------------------------------------


def test_gate_passes_with_valid_coverage_exemption(tmp_path: Path) -> None:
    """Gate exits 0 when a true cell has a valid coverage_exemption and
    another SDK provides static verification."""
    # Create a fake TypeScript source file that exports the operation symbol.
    # The gate no longer accepts bare camelCase ("verifiedOpZzz"); it requires
    # the domain-prefixed form.  For domain="Fake", op="verified_op_zzz" the
    # auto-generated camelCase candidate is "fakeVerifiedOpZzz"
    # (_to_camel("fake_verified_op_zzz")).
    ts_src_dir = tmp_path / "ts_src"
    ts_src_dir.mkdir()
    ts_file = ts_src_dir / "index.ts"
    ts_file.write_text(
        "export function fakeVerifiedOpZzz(): void {}\n",
        encoding="utf-8",
    )

    # Create an empty Python source dir (python symbol will NOT be found).
    py_src_dir = tmp_path / "py_src"
    py_src_dir.mkdir()

    synthetic_matrix = {
        "capabilities": [
            {
                "domain": "Fake",
                "operations": [
                    {
                        "name": "verified_op_zzz",
                        # python: true but symbol absent — covered by exemption
                        "python": True,
                        # typescript: true and symbol IS present in fake source
                        "typescript": True,
                        "kotlin": False,
                        "swift": False,
                        "exemptions": {
                            "kotlin": "Not yet implemented in Kotlin SDK",
                            "swift": "Not yet implemented in Swift SDK",
                        },
                        "coverage_exemptions": {
                            "python": "Symbol is generated at runtime by the PyO3 bridge — not statically extractable",
                        },
                    }
                ],
            }
        ]
    }
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps(synthetic_matrix), encoding="utf-8")

    wrapper = _build_wrapper(
        tmp_path,
        matrix_file,
        sdk_paths={"python": py_src_dir, "typescript": ts_src_dir},
    )
    result = _run_wrapper(wrapper)

    assert result.returncode == 0, (
        f"Gate should have exited 0 for a valid coverage_exemption + "
        f"statically-verified typescript, got {result.returncode}.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


# ---------------------------------------------------------------------------
# Test 6: Gate exits 1 when ALL true cells have coverage_exemptions and
#          none is statically verified (all-exempted guard).
#
# Setup:
#   - python=True  — symbol absent; carries a coverage_exemptions entry.
#   - typescript=True — symbol also absent; carries a coverage_exemptions entry.
#   - kotlin=False, swift=False — each with a valid exemption.
#
# No SDK is statically verified, so the all-exempted guard must fire
# and the gate must exit 1.
# ---------------------------------------------------------------------------


def test_gate_fails_on_all_exempted_with_none_verified(tmp_path: Path) -> None:
    """Gate exits 1 when every true cell carries a coverage_exemption but
    none is statically verified."""
    # Both Python and TypeScript source dirs are empty — no symbols extractable.
    py_src_dir = tmp_path / "py_src"
    py_src_dir.mkdir()
    ts_src_dir = tmp_path / "ts_src"
    ts_src_dir.mkdir()

    synthetic_matrix = {
        "capabilities": [
            {
                "domain": "Fake",
                "operations": [
                    {
                        "name": "all_exempted_op_zzz",
                        "python": True,
                        "typescript": True,
                        "kotlin": False,
                        "swift": False,
                        "exemptions": {
                            "kotlin": "Not yet implemented in Kotlin SDK",
                            "swift": "Not yet implemented in Swift SDK",
                        },
                        "coverage_exemptions": {
                            "python": "Generated binding — not statically extractable",
                            "typescript": "Generated binding — not statically extractable",
                        },
                    }
                ],
            }
        ]
    }
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps(synthetic_matrix), encoding="utf-8")

    wrapper = _build_wrapper(
        tmp_path,
        matrix_file,
        sdk_paths={"python": py_src_dir, "typescript": ts_src_dir},
    )
    result = _run_wrapper(wrapper)

    assert result.returncode == 1, (
        f"Gate should have exited 1 for all-exempted op with no static verification, "
        f"got {result.returncode}.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    # Verify the all-exempted guard fired (not a different error).
    assert "all SDKs claiming coverage" in result.stdout.lower() or "all-exempted" in result.stdout.lower(), (
        f"Expected all-exempted guard error phrase in stdout.\nstdout:\n{result.stdout}"
    )


# ---------------------------------------------------------------------------
# Test 7: Gate exits 1 when a false entry's exemption reason is a non-string
#          (e.g. a dict) or an empty/blank string.
#
# Setup:
#   - python=True  — valid, a symbol IS present.
#   - typescript=False — exemption value is a dict object (invalid format).
#   - kotlin=False — exemption is an empty string (invalid).
#   - swift=False — valid exemption string.
#
# The gate must reject the dict and blank exemption reasons.
# ---------------------------------------------------------------------------


def test_gate_fails_on_invalid_false_entry_exemption_reason(tmp_path: Path) -> None:
    """Gate exits 1 when a false entry has a non-string or blank exemption reason."""
    ts_src_dir = tmp_path / "ts_src"
    ts_src_dir.mkdir()
    ts_file = ts_src_dir / "index.ts"
    # Provide a real symbol so python=True is statically verified.
    ts_file.write_text(
        "export function invalidExemptOpZzz(): void {}\n",
        encoding="utf-8",
    )

    synthetic_matrix = {
        "capabilities": [
            {
                "domain": "Fake",
                "operations": [
                    {
                        "name": "invalid_exempt_op_zzz",
                        "python": False,
                        # typescript=True with symbol present (static verification)
                        "typescript": True,
                        "kotlin": False,
                        "swift": False,
                        "exemptions": {
                            # dict object — invalid, must be a string
                            "python": {"reason": "Not implemented"},
                            # blank string — invalid
                            "kotlin": "   ",
                            # valid string
                            "swift": "Not yet implemented in Swift SDK",
                        },
                    }
                ],
            }
        ]
    }
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps(synthetic_matrix), encoding="utf-8")

    wrapper = _build_wrapper(
        tmp_path,
        matrix_file,
        sdk_paths={"typescript": ts_src_dir},
    )
    result = _run_wrapper(wrapper)

    assert result.returncode == 1, (
        f"Gate should have exited 1 for invalid exemption reasons, "
        f"got {result.returncode}.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    # Assert both invalid cases are independently flagged — not just one.
    assert "exemptions.python" in result.stdout and "must be a non-empty string" in result.stdout, (
        f"Expected error for dict-valued 'exemptions.python' in stdout.\nstdout:\n{result.stdout}"
    )
    assert "exemptions.kotlin" in result.stdout, (
        f"Expected error for blank-string 'exemptions.kotlin' in stdout.\nstdout:\n{result.stdout}"
    )


# ---------------------------------------------------------------------------
# Test 8: Gate exits 1 when a cell value is not a boolean or null
#
# A typo'd string "true" (instead of JSON boolean true) must be rejected.
# The gate's else-branch fires, emits "unexpected cell value", and exits 1.
# This test is mutation-robust: removing the else-branch causes the string
# cell to fall through silently, making returncode 0 and the assertion fail.
# ---------------------------------------------------------------------------


def test_gate_fails_on_unexpected_cell_value(tmp_path: Path) -> None:
    """A cell value that is not a boolean or null must be rejected.

    The string ``"true"`` is a common authoring mistake (JSON requires bare
    ``true``, not the quoted form).  Without the else-branch, this silently
    falls through and the capability appears unchecked.  With the branch,
    the gate emits an 'unexpected cell value' error and exits 1.
    """
    synthetic_matrix = {
        "capabilities": [
            {
                "domain": "Fake",
                "operations": [
                    {
                        "name": "cell_value_op_zzz",
                        # python uses the string "true" — a typo that must be rejected
                        "python": "true",
                        "typescript": False,
                        "kotlin": False,
                        "swift": False,
                        "exemptions": {
                            "typescript": "Not yet implemented in TypeScript SDK",
                            "kotlin": "Not yet implemented in Kotlin SDK",
                            "swift": "Not yet implemented in Swift SDK",
                        },
                    }
                ],
            }
        ]
    }
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps(synthetic_matrix), encoding="utf-8")

    wrapper = _build_wrapper(tmp_path, matrix_file)
    result = _run_wrapper(wrapper)

    assert result.returncode == 1, (
        f"Gate should have exited 1 for unexpected cell value, got {result.returncode}.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "unexpected cell value" in result.stdout, (
        f"Expected 'unexpected cell value' error phrase in stdout.\nstdout:\n{result.stdout}"
    )
