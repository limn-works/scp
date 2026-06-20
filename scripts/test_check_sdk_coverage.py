"""Self-tests for check-sdk-coverage.py.

Covers:
  1.  Gate exits 0 (PASS) on the real matrix.
  2.  Gate exits 1 when a true entry has no matching symbol and no exemption
      (unmatched-true path, isolated from missing-SDK-key errors).
  2b. Gate exits 1 when a matrix SDK key is missing from the cell object
      (missing-SDK-key path).
  3.  _extract_python_symbols correctly extracts a function name via tree-sitter.
  4.  _extract_python_symbols handles class with method names.
  5.  Gate exits 0 when a true entry has a valid coverage_exemption and at
      least one other SDK is statically verified.
  6.  Gate exits 1 when every true cell for an op has a coverage_exemption but
      none is statically verified (all-exempted guard).
  7.  Gate exits 1 when a cell's coverage_exemptions reason is blank or missing.
  8.  Gate exits 1 when a cell value is neither a boolean nor null (e.g. the
      string "true" instead of a JSON boolean true).
  9.  A bare op-name symbol does not satisfy a domain-prefixed operation
      (regression guard for the domain-prefix-only enforcement).
  10. ALIASES entries enable non-standard SDK symbol names to satisfy coverage.
  11. The absence of an ALIASES entry causes coverage to fail for symbols that
      require explicit mapping.
  12. Empty / missing 'capabilities' fail closed (floor + shape guards).
  13. Matrix file not found / malformed JSON / wrong top-level shape / non-dict
      coverage_exemptions all exit 1 with a clean diagnostic (no traceback).
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
    assert (
        "all SDKs claiming coverage" in result.stdout.lower()
        or "all-exempted" in result.stdout.lower()
    ), f"Expected all-exempted guard error phrase in stdout.\nstdout:\n{result.stdout}"


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
    # Provide the domain-prefixed symbol so typescript=True is statically
    # verified.  For domain="Fake", op="invalid_exempt_op_zzz" the
    # auto-generated candidate is "fakeInvalidExemptOpZzz".  The bare form
    # "invalidExemptOpZzz" is NOT a valid candidate after the domain-prefix
    # enforcement change, so only the prefixed form satisfies the gate.
    ts_file.write_text(
        "export function fakeInvalidExemptOpZzz(): void {}\n",
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
    assert (
        "exemptions.python" in result.stdout
        and "must be a non-empty string" in result.stdout
    ), (
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


# ---------------------------------------------------------------------------
# Test 9: Gate exits 1 when only the bare camelCase form is exported
#          (domain-prefix-only enforcement regression test)
#
# The PR's core security fix removed bare-name candidates from
# _check_operation_in_sdk.  Before the fix, exporting only the bare camel
# form ("verifiedOpZzz") was accepted as coverage for "Fake/verified_op_zzz"
# because the old code checked the bare camelCase candidate.  After the fix,
# only the domain-prefixed form ("fakeVerifiedOpZzz") is accepted.
#
# This test MUST FAIL if bare-name candidates are re-added to
# _check_operation_in_sdk (mutation-robustness property).
# ---------------------------------------------------------------------------


def test_bare_name_does_not_satisfy_domain_prefixed_op(tmp_path: Path) -> None:
    """Exporting only the bare camelCase form must NOT satisfy a domain-prefixed op.

    For domain="Fake", op="verified_op_zzz" the required SDK symbol is
    "fakeVerifiedOpZzz" (domain-prefixed camelCase).  A file that exports only
    "verifiedOpZzz" (bare form, no domain prefix) must cause the gate to exit 1
    with 'no matching SDK symbol was found'.

    Mutation test: re-adding a bare-camel candidate to _check_operation_in_sdk
    would make this test fail (the bare form would satisfy the check and the
    gate would exit 0 instead of 1).
    """
    ts_src_dir = tmp_path / "ts_src"
    ts_src_dir.mkdir()
    ts_file = ts_src_dir / "index.ts"
    # Export ONLY the bare camel form — NOT the domain-prefixed "fakeVerifiedOpZzz".
    ts_file.write_text(
        "export function verifiedOpZzz(): void {}\n",
        encoding="utf-8",
    )

    synthetic_matrix = {
        "capabilities": [
            {
                "domain": "Fake",
                "operations": [
                    {
                        "name": "verified_op_zzz",
                        # typescript: True — symbol must be statically found
                        "typescript": True,
                        # Other SDKs: false + valid exemptions (no noise from them)
                        "python": False,
                        "kotlin": False,
                        "swift": False,
                        "exemptions": {
                            "python": "Not yet implemented in Python SDK",
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

    wrapper = _build_wrapper(
        tmp_path,
        matrix_file,
        sdk_paths={"typescript": ts_src_dir},
    )
    result = _run_wrapper(wrapper)

    assert result.returncode == 1, (
        f"Gate should have exited 1: bare 'verifiedOpZzz' must not satisfy "
        f"domain-prefixed op 'Fake/verified_op_zzz'. Got {result.returncode}.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "no matching SDK symbol was found" in result.stdout, (
        f"Expected 'no matching SDK symbol was found' in stdout.\n"
        f"stdout:\n{result.stdout}"
    )


# ---------------------------------------------------------------------------
# Test 10: ALIASES table enables non-standard symbol names
#
# When an op's SDK symbol does not follow the auto-generated naming convention,
# an explicit ALIASES entry allows the gate to find it.  This test verifies:
#   a) With the alias present: gate exits 0 (custom symbol satisfies coverage)
#   b) Without the alias:      gate exits 1 (custom symbol is not found)
# ---------------------------------------------------------------------------


def test_aliases_enable_non_standard_symbol_names(tmp_path: Path) -> None:
    """ALIASES table entries enable coverage for non-standard symbol names.

    Without an alias, a TypeScript export named "myCustomSymbol" does NOT
    satisfy "Fake/custom_op" (which would need "fakeCustomOp" by convention).
    With an alias mapping ("Fake", "custom_op") -> {"typescript": ["myCustomSymbol"]},
    the gate accepts it and exits 0.
    """
    ts_src_dir = tmp_path / "ts_src"
    ts_src_dir.mkdir()
    ts_file = ts_src_dir / "index.ts"
    # Export a non-standard symbol name (not the auto-generated "fakeCustomOp").
    ts_file.write_text(
        "export function myCustomSymbol(): void {}\n",
        encoding="utf-8",
    )

    synthetic_matrix = {
        "capabilities": [
            {
                "domain": "Fake",
                "operations": [
                    {
                        "name": "custom_op",
                        "typescript": True,
                        "python": False,
                        "kotlin": False,
                        "swift": False,
                        "exemptions": {
                            "python": "Not yet implemented in Python SDK",
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

    # --- Part a: WITH the alias → gate must exit 0 ---
    wrapper_with_alias = tmp_path / "run_with_alias.py"
    wrapper_with_alias.write_text(
        "\n".join(
            [
                "import sys",
                "import importlib.util",
                "from pathlib import Path",
                "",
                f"_spec = importlib.util.spec_from_file_location('check_sdk_coverage', {_SCRIPT_PATH_STR!r})",
                "_mod = importlib.util.module_from_spec(_spec)",
                "_spec.loader.exec_module(_mod)",
                "",
                f"_mod.MATRIX_PATH = Path({str(matrix_file)!r})",
                f"_mod.SDK_PATHS.update({{'typescript': Path({str(ts_src_dir)!r})}})",
                # Inject a custom alias so "myCustomSymbol" satisfies "Fake/custom_op"
                "_mod.ALIASES[('Fake', 'custom_op')] = {'typescript': ['myCustomSymbol']}",
                "sys.exit(_mod.main())",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    result_with = subprocess.run(
        [sys.executable, str(wrapper_with_alias)],
        capture_output=True,
        text=True,
    )
    assert result_with.returncode == 0, (
        f"Gate should exit 0 when ALIASES maps 'myCustomSymbol' for Fake/custom_op. "
        f"Got {result_with.returncode}.\n"
        f"stdout:\n{result_with.stdout}\nstderr:\n{result_with.stderr}"
    )

    # --- Part b: WITHOUT the alias → gate must exit 1 ---
    wrapper_no_alias = tmp_path / "run_no_alias.py"
    wrapper_no_alias.write_text(
        "\n".join(
            [
                "import sys",
                "import importlib.util",
                "from pathlib import Path",
                "",
                f"_spec = importlib.util.spec_from_file_location('check_sdk_coverage', {_SCRIPT_PATH_STR!r})",
                "_mod = importlib.util.module_from_spec(_spec)",
                "_spec.loader.exec_module(_mod)",
                "",
                f"_mod.MATRIX_PATH = Path({str(matrix_file)!r})",
                f"_mod.SDK_PATHS.update({{'typescript': Path({str(ts_src_dir)!r})}})",
                # No alias added: "myCustomSymbol" is not a valid candidate for "Fake/custom_op"
                "sys.exit(_mod.main())",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    result_without = subprocess.run(
        [sys.executable, str(wrapper_no_alias)],
        capture_output=True,
        text=True,
    )
    assert result_without.returncode == 1, (
        f"Gate should exit 1 when no ALIASES entry maps 'myCustomSymbol' for Fake/custom_op. "
        f"Got {result_without.returncode}.\n"
        f"stdout:\n{result_without.stdout}\nstderr:\n{result_without.stderr}"
    )
    assert "no matching SDK symbol was found" in result_without.stdout, (
        f"Expected 'no matching SDK symbol was found' in stdout.\n"
        f"stdout:\n{result_without.stdout}"
    )


# ---------------------------------------------------------------------------
# Test 12: Gate exits 1 on an empty/missing "capabilities" array (floor guard)
#
# An empty matrix produces total_ops=0 and errors=0. Without the floor guard
# the gate would print PASS and exit 0 — silently disabling coverage
# enforcement against a truncated or empty matrix. The guard must make this
# fail-closed (exit 1).
# ---------------------------------------------------------------------------


def test_gate_fails_on_empty_capabilities(tmp_path: Path) -> None:
    """An empty 'capabilities' array must fail the gate, not pass it."""
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps({"capabilities": []}), encoding="utf-8")

    wrapper = _build_wrapper(tmp_path, matrix_file)
    result = _run_wrapper(wrapper)

    assert result.returncode == 1, (
        f"Gate should have exited 1 on an empty matrix, got {result.returncode}.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "zero operations" in result.stderr, (
        f"Expected the empty-matrix floor-guard message in stderr.\n"
        f"stderr:\n{result.stderr}"
    )


def test_gate_fails_on_missing_capabilities_key(tmp_path: Path) -> None:
    """A matrix object lacking the 'capabilities' key must also fail closed.

    A missing 'capabilities' key is a shape violation: the top-level shape
    check fires before the floor guard and emits the shape diagnostic.
    """
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps({}), encoding="utf-8")

    wrapper = _build_wrapper(tmp_path, matrix_file)
    result = _run_wrapper(wrapper)

    assert result.returncode == 1, (
        f"Gate should have exited 1 on a matrix missing 'capabilities', "
        f"got {result.returncode}.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "must be an object with a 'capabilities' array" in result.stderr, (
        f"Expected the matrix-shape diagnostic in stderr.\nstderr:\n{result.stderr}"
    )


# ---------------------------------------------------------------------------
# Test 13: Gate exits 1 (clean diagnostic, not a traceback) when the matrix
#          file is missing, malformed, or structurally wrong.
# ---------------------------------------------------------------------------


def test_gate_fails_on_matrix_file_not_found(tmp_path: Path) -> None:
    """Pointing MATRIX_PATH at a nonexistent file must exit 1 cleanly."""
    missing = tmp_path / "does_not_exist.json"
    wrapper = _build_wrapper(tmp_path, missing)
    result = _run_wrapper(wrapper)

    assert result.returncode == 1, (
        f"Gate should have exited 1 for a missing matrix file, "
        f"got {result.returncode}.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "not found" in result.stderr.lower(), (
        f"Expected a 'not found' diagnostic in stderr.\nstderr:\n{result.stderr}"
    )
    assert "Traceback" not in result.stderr, (
        f"Missing matrix must not surface a Python traceback.\nstderr:\n{result.stderr}"
    )


def test_gate_fails_on_malformed_json_matrix(tmp_path: Path) -> None:
    """A matrix file containing invalid JSON must exit 1 cleanly (no traceback)."""
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text("{ this is not valid json ]", encoding="utf-8")

    wrapper = _build_wrapper(tmp_path, matrix_file)
    result = _run_wrapper(wrapper)

    assert result.returncode == 1, (
        f"Gate should have exited 1 for malformed JSON, got {result.returncode}.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "could not parse matrix" in result.stderr, (
        f"Expected the parse-failure diagnostic in stderr.\nstderr:\n{result.stderr}"
    )
    assert "Traceback" not in result.stderr, (
        f"Malformed JSON must not surface a Python traceback.\nstderr:\n{result.stderr}"
    )


def test_gate_fails_on_matrix_that_is_a_list(tmp_path: Path) -> None:
    """A matrix whose top-level value is a list (not an object) must fail closed."""
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps([{"domain": "Fake"}]), encoding="utf-8")

    wrapper = _build_wrapper(tmp_path, matrix_file)
    result = _run_wrapper(wrapper)

    assert result.returncode == 1, (
        f"Gate should have exited 1 for a list-valued matrix, "
        f"got {result.returncode}.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "must be an object with a 'capabilities' array" in result.stderr, (
        f"Expected the matrix-shape diagnostic in stderr.\nstderr:\n{result.stderr}"
    )


def test_gate_fails_on_non_dict_coverage_exemptions(tmp_path: Path) -> None:
    """A 'coverage_exemptions' value that is not an object must fail closed.

    A non-dict coverage_exemptions block would make membership/.items()
    accesses raise; the gate must instead emit a clean ERROR and exit 1.
    """
    synthetic_matrix = {
        "capabilities": [
            {
                "domain": "Fake",
                "operations": [
                    {
                        "name": "bad_cov_exempt_op_zzz",
                        "python": False,
                        "typescript": False,
                        "kotlin": False,
                        "swift": False,
                        "exemptions": {
                            "python": "Not yet implemented in Python SDK",
                            "typescript": "Not yet implemented in TypeScript SDK",
                            "kotlin": "Not yet implemented in Kotlin SDK",
                            "swift": "Not yet implemented in Swift SDK",
                        },
                        # Invalid: must be an object, not a string.
                        "coverage_exemptions": "this should be a dict",
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
        f"Gate should have exited 1 for non-dict coverage_exemptions, "
        f"got {result.returncode}.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "'coverage_exemptions' must be an" in result.stdout, (
        f"Expected the non-dict coverage_exemptions diagnostic in stdout.\n"
        f"stdout:\n{result.stdout}"
    )
    assert "Traceback" not in result.stderr, (
        f"Non-dict coverage_exemptions must not surface a traceback.\n"
        f"stderr:\n{result.stderr}"
    )


def test_gate_fails_on_non_dict_capabilities_entry(tmp_path: Path) -> None:
    """A non-dict element of 'capabilities' must fail closed without a traceback.

    A string (or other non-object) capabilities entry would make the
    .get("domain")/.get("operations") accesses raise; the gate must instead
    emit a clean ERROR and exit 1.
    """
    synthetic_matrix = {"capabilities": ["this should be an object"]}
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps(synthetic_matrix), encoding="utf-8")

    wrapper = _build_wrapper(tmp_path, matrix_file)
    result = _run_wrapper(wrapper)

    assert result.returncode == 1, (
        f"Gate should have exited 1 for a non-dict capabilities entry, "
        f"got {result.returncode}.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "capabilities entry must be an object" in result.stdout, (
        f"Expected the non-dict capabilities-entry diagnostic in stdout.\n"
        f"stdout:\n{result.stdout}"
    )
    assert "Traceback" not in result.stderr, (
        f"A non-dict capabilities entry must not surface a traceback.\n"
        f"stderr:\n{result.stderr}"
    )


def test_gate_fails_on_non_list_operations(tmp_path: Path) -> None:
    """A non-list 'operations' value must fail closed without a traceback.

    A string (or other non-array) operations value would make the iteration
    below raise (or iterate characters); the gate must instead emit a clean
    ERROR and exit 1.
    """
    synthetic_matrix = {"capabilities": [{"domain": "Fake", "operations": "nope"}]}
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps(synthetic_matrix), encoding="utf-8")

    wrapper = _build_wrapper(tmp_path, matrix_file)
    result = _run_wrapper(wrapper)

    assert result.returncode == 1, (
        f"Gate should have exited 1 for a non-list 'operations', "
        f"got {result.returncode}.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "'operations' must be an array" in result.stdout, (
        f"Expected the non-list operations diagnostic in stdout.\n"
        f"stdout:\n{result.stdout}"
    )
    assert "Traceback" not in result.stderr, (
        f"A non-list 'operations' must not surface a traceback.\n"
        f"stderr:\n{result.stderr}"
    )


def test_gate_fails_on_non_dict_operation_entry(tmp_path: Path) -> None:
    """A non-dict element of 'operations' must fail closed without a traceback.

    An integer (or other non-object) operation entry would make the
    .get("name")/.keys() accesses raise; the gate must instead emit a clean
    ERROR and exit 1.
    """
    synthetic_matrix = {"capabilities": [{"domain": "Fake", "operations": [123]}]}
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps(synthetic_matrix), encoding="utf-8")

    wrapper = _build_wrapper(tmp_path, matrix_file)
    result = _run_wrapper(wrapper)

    assert result.returncode == 1, (
        f"Gate should have exited 1 for a non-dict operation entry, "
        f"got {result.returncode}.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "operation entry must be an object" in result.stdout, (
        f"Expected the non-dict operation-entry diagnostic in stdout.\n"
        f"stdout:\n{result.stdout}"
    )
    assert "Traceback" not in result.stderr, (
        f"A non-dict operation entry must not surface a traceback.\n"
        f"stderr:\n{result.stderr}"
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
    assert "must be a non-empty string" in result.stdout, (
        f"Expected 'must be a non-empty string' in stdout.\nstdout:\n{result.stdout}"
    )
