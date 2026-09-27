"""A present-but-unloadable `_scp_core` must be reported apart from an absent one.

Python raises `ImportError` for both causes, so every `except ImportError:
pytest.skip(...)` guard under `bindings/python/tests` skips on a broken artifact
exactly as it skips on a missing one — a job that downloaded a broken PyO3
extension then exits 0 over zero executed assertions. `scp_sdk._extension`
separates the causes by asking whether an extension file is present — on the import
path, and in the `scp_sdk` package directory for a file another interpreter built —
and raises `EXTENSION_LOAD_FAILED_CODE` for a load failure so the guards let it through.

These tests import no native symbol: they drive the separation with
`sys.modules["scp_sdk._scp_core"] = None`, which makes the loader's import raise
`ImportError` whether or not the compiled extension exists in this environment.
"""

from __future__ import annotations

import ast
import importlib
import importlib.machinery
import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

from scp_sdk import _extension
from scp_sdk.errors import ScpError

#: A filename no interpreter running this suite imports: ``_scp_core`` plus an
#: interpreter tag naming CPython 0.0, plus the POSIX dynamic-library suffix.
#: ``importlib.util.find_spec`` asks for ``_scp_core`` followed by one of
#: ``importlib.machinery.EXTENSION_SUFFIXES`` and this name is none of those, so
#: only a directory scan finds it. A wheel built by another interpreter installs
#: a file of exactly this shape.
FOREIGN_TAGGED_EXTENSION = "_scp_core.cpython-000-scp-test.so"

#: Every SDK module whose bridge accessor must route through
#: :func:`scp_sdk._extension.native_module`. Each one carried its own copy of the
#: `import _scp_core` / `except ImportError` block, and each copy reported a load
#: failure with the absence code.
BRIDGE_ACCESSORS = [
    ("scp_sdk.bridge", "_bridge"),
    ("scp_sdk.context", "_bridge"),
    ("scp_sdk.discovery", "_bridge"),
    ("scp_sdk.economy", "_bridge"),
    ("scp_sdk.media", "_bridge"),
    ("scp_sdk.scp", "_native_mod"),
    ("scp_sdk.sync", "_bridge"),
    ("scp_sdk.trust", "_bridge"),
]


@pytest.fixture
def blocked_import(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the loader's ``import scp_sdk._scp_core`` raise ``ImportError``.

    ``None`` in ``sys.modules`` is the documented way to make an import fail
    without touching the filesystem, so this reproduces a ``dlopen`` failure and
    an absent extension alike — which is the point: the exception is identical and
    only :func:`scp_sdk._extension.extension_is_installed` tells them apart.
    """
    monkeypatch.setitem(sys.modules, _extension.EXTENSION_MODULE, None)


def test_a_top_level_scp_core_on_the_path_never_stands_in_for_the_package_module(
    blocked_import: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """With the package's extension absent, a stray top-level ``_scp_core`` is not loaded.

    A bare ``import _scp_core`` searches all of ``sys.path`` once
    ``scp_sdk/__init__.py`` has registered no alias, so an old build left in the
    working directory or on ``PYTHONPATH`` would load in place of the package's
    module, which the probe never examined. The loader must instead report the
    absence the probe reports.
    """
    (tmp_path / "_scp_core.py").write_text("STRAY_BUILD = True\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, "_scp_core", raising=False)
    monkeypatch.setattr(_extension, "extension_is_installed", lambda: False)
    with pytest.raises(ScpError) as caught:
        _extension.native_module()
    assert caught.value.code == _extension.EXTENSION_ABSENT_CODE
    assert "_scp_core" not in sys.modules


def test_absent_extension_raises_the_absence_code(
    blocked_import: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_extension, "extension_is_installed", lambda: False)
    with pytest.raises(ScpError) as caught:
        _extension.native_module()
    assert caught.value.code == _extension.EXTENSION_ABSENT_CODE


def test_present_extension_that_fails_to_load_raises_the_load_failure_code(
    blocked_import: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_extension, "extension_is_installed", lambda: True)
    with pytest.raises(ScpError) as caught:
        _extension.native_module()
    assert caught.value.code == _extension.EXTENSION_LOAD_FAILED_CODE


def test_load_failure_is_not_an_import_error(
    blocked_import: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The loader's load-failure error is an `ScpError`, never an `ImportError`."""
    monkeypatch.setattr(_extension, "extension_is_installed", lambda: True)
    with pytest.raises(ScpError) as caught:
        _extension.native_module()
    assert not isinstance(caught.value, ImportError)


@pytest.fixture
def package_reimport(blocked_import: None, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Re-execute ``scp_sdk/__init__.py`` with the extension import blocked.

    A real-FFI module guard runs ``from scp_sdk import _scp_core``, which reaches
    the extension through the package's own ``try/except ImportError`` rather than
    through :func:`scp_sdk._extension.native_module`. Removing the ``_scp_core``
    attribute makes that ``from`` import load the submodule again, so the blocked
    ``sys.modules`` entry raises inside the package's ``try`` block.
    """
    import scp_sdk

    monkeypatch.delattr(scp_sdk, "_scp_core", raising=False)
    monkeypatch.delitem(sys.modules, "_scp_core", raising=False)
    return lambda: importlib.reload(scp_sdk)


def test_package_import_raises_the_load_failure_code_for_a_present_extension(
    package_reimport: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``import scp_sdk`` fails with ``SCP-VALID-7082`` over a present broken extension.

    That error is not an ``ImportError``, so a module guard's
    ``from scp_sdk import _scp_core`` reports a collection error instead of
    skipping. A package that went back to ``except ImportError: pass`` would let
    the guard's own import raise ``ImportError`` and skip.
    """
    monkeypatch.setattr(_extension, "extension_is_installed", lambda: True)
    with pytest.raises(ScpError) as caught:
        package_reimport()
    assert caught.value.code == _extension.EXTENSION_LOAD_FAILED_CODE
    assert not isinstance(caught.value, ImportError)


def test_package_import_succeeds_without_an_extension(
    package_reimport: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no extension file present, the pure-Python package still imports."""
    monkeypatch.setattr(_extension, "extension_is_installed", lambda: False)
    package_reimport()
    assert "_scp_core" not in sys.modules


@pytest.mark.parametrize(("module_name", "accessor"), BRIDGE_ACCESSORS)
def test_every_bridge_accessor_reports_a_load_failure_as_a_load_failure(
    module_name: str,
    accessor: str,
    blocked_import: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No SDK module keeps a private copy that calls a load failure an absence."""
    monkeypatch.setattr(_extension, "extension_is_installed", lambda: True)
    module: Any = importlib.import_module(module_name)
    with pytest.raises(ScpError) as caught:
        getattr(module, accessor)()
    assert caught.value.code == _extension.EXTENSION_LOAD_FAILED_CODE


@pytest.mark.parametrize(("module_name", "accessor"), BRIDGE_ACCESSORS)
def test_every_bridge_accessor_reports_an_absence_as_an_absence(
    module_name: str,
    accessor: str,
    blocked_import: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_extension, "extension_is_installed", lambda: False)
    module: Any = importlib.import_module(module_name)
    with pytest.raises(ScpError) as caught:
        getattr(module, accessor)()
    assert caught.value.code == _extension.EXTENSION_ABSENT_CODE


# ---------------------------------------------------------------------------
# The probe itself: which present files it sees
# ---------------------------------------------------------------------------


def test_find_spec_cannot_see_a_module_built_for_another_interpreter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The negative control the file scan exists for.

    `importlib.util.find_spec` matches a filename against
    `importlib.machinery.EXTENSION_SUFFIXES`, which holds the suffixes *this*
    interpreter imports. A wheel another interpreter built installs
    `_scp_core.cpython-311-x86_64-linux-gnu.so`, whose name matches none of
    them. This test puts such a file in a real package on `sys.path` and shows
    `find_spec` reporting absence over it, then shows the same call finding an
    untagged `_scp_core.so` in the same directory.
    """
    package = tmp_path / "scp_probe_control_pkg"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / FOREIGN_TAGGED_EXTENSION).write_bytes(b"")
    monkeypatch.syspath_prepend(str(tmp_path))
    importlib.invalidate_caches()

    assert importlib.util.find_spec("scp_probe_control_pkg._scp_core") is None

    (package / f"_scp_core{importlib.machinery.EXTENSION_SUFFIXES[-1]}").write_bytes(b"")
    importlib.invalidate_caches()
    assert importlib.util.find_spec("scp_probe_control_pkg._scp_core") is not None


@pytest.fixture
def package_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the file scan at an empty directory and return it.

    :func:`scp_sdk._extension.extension_file_on_disk` reads the directory
    holding `_extension.py`, which it takes from that module's `__file__`, so
    rebinding `__file__` moves the scan onto `tmp_path` without touching the
    installed package.
    """
    monkeypatch.setattr(_extension, "__file__", str(tmp_path / "_extension.py"))
    return tmp_path


def test_the_file_scan_sees_a_module_built_for_another_interpreter(
    package_directory: Path,
) -> None:
    """The fail-open this separation exists to close.

    Without the scan the probe answers False here, `reject_load_failure`
    returns, `native_module` raises the absence code, and every
    `except ImportError: pytest.skip(...)` guard skips over a present but
    unloadable artifact.
    """
    (package_directory / FOREIGN_TAGGED_EXTENSION).write_bytes(b"")
    assert _extension.extension_file_on_disk() is True


def test_the_file_scan_sees_an_untagged_module(package_directory: Path) -> None:
    (package_directory / "_scp_core.so").write_bytes(b"")
    assert _extension.extension_file_on_disk() is True


def test_the_file_scan_reports_absence_over_an_empty_package(
    package_directory: Path,
) -> None:
    assert _extension.extension_file_on_disk() is False


@pytest.mark.parametrize(
    "filename",
    [
        "_scp_core_helper.so",
        "_scp_core.py",
        "_scp_core",
        "scp.py",
        "libscp_core.so",
    ],
)
def test_the_file_scan_reports_absence_over_a_file_that_is_not_the_extension(
    package_directory: Path, filename: str
) -> None:
    """The scan admits only ``_scp_core`` + optional tag + dynamic-library suffix."""
    (package_directory / filename).write_bytes(b"")
    assert _extension.extension_file_on_disk() is False


def test_the_file_scan_reports_absence_when_the_directory_does_not_exist(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(_extension, "__file__", str(tmp_path / "gone" / "_extension.py"))
    assert _extension.extension_file_on_disk() is False


@pytest.fixture
def unresolvable_module_name(monkeypatch: pytest.MonkeyPatch) -> str:
    """Make :func:`importlib.util.find_spec` answer ``None`` for the probed name.

    The probe asks `find_spec` first and the file scan second, so a test of the
    scan's contribution needs `find_spec` to find nothing. Rebinding
    `EXTENSION_MODULE` to a submodule of `scp_sdk` that no file provides does
    that with the real `find_spec`, which keeps the test honest about which of
    the two looks answered.
    """
    name = "scp_sdk._scp_core_probe_fixture"
    monkeypatch.setattr(_extension, "EXTENSION_MODULE", name)
    assert importlib.util.find_spec(name) is None
    return name


def test_the_probe_reports_a_module_built_for_another_interpreter_as_present(
    package_directory: Path, unresolvable_module_name: str
) -> None:
    leaf = unresolvable_module_name.rpartition(".")[2]
    (package_directory / f"{leaf}.cpython-000-scp-test.so").write_bytes(b"")
    assert _extension.extension_is_installed() is True


def test_the_probe_reports_absence_when_neither_look_finds_a_file(
    package_directory: Path, unresolvable_module_name: str
) -> None:
    assert _extension.extension_is_installed() is False


def test_a_module_built_for_another_interpreter_raises_the_load_failure_code(
    blocked_import: None, package_directory: Path, unresolvable_module_name: str
) -> None:
    """End to end: the scenario the finding named reaches `EXTENSION_LOAD_FAILED_CODE`.

    A PyO3 artifact built by one interpreter lands in a job running another.
    The `.so` is present, `import _scp_core` fails, and the code must report a
    load failure so the fixture in `conftest.py` fails the job instead of
    skipping it.
    """
    leaf = unresolvable_module_name.rpartition(".")[2]
    (package_directory / f"{leaf}.cpython-000-scp-test.so").write_bytes(b"")
    with pytest.raises(ScpError) as caught:
        _extension.native_module()
    assert caught.value.code == _extension.EXTENSION_LOAD_FAILED_CODE


# ---------------------------------------------------------------------------
# One loader, no private copies
# ---------------------------------------------------------------------------


#: The leaf name of the extension module, as an import statement spells it.
EXTENSION_LEAF = "_scp_core"

#: Every file under ``scp_sdk`` permitted to import the extension, mapped to the
#: number of import statements it is permitted to hold. ``_extension.py`` holds
#: the one loader. ``__init__.py`` registers the extension under its bare name
#: and hands the failure to ``reject_load_failure``, which tells a load failure
#: apart from an absence. This mapping is the whole permission: a file it does
#: not name, and a second import inside a file it does name, are both offenders.
PERMITTED_EXTENSION_IMPORTS = {"__init__.py": 1, "_extension.py": 1}


def _count_extension_imports(source: str) -> int:
    """Count the statements in ``source`` that import the extension.

    Walks the parsed syntax tree rather than matching the source text, so the
    count covers every spelling an author can write: ``import _scp_core``,
    ``from scp_sdk import _scp_core``, ``from . import _scp_core``,
    ``import scp_sdk._scp_core`` and ``from scp_sdk._scp_core import SCP``. A
    pattern over the text counts the one spelling its author wrote it for and
    passes every other spelling, which is the hole this function closes.
    """
    total = 0
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [alias.name for alias in node.names] + [node.module or ""]
        else:
            continue
        if any(name == EXTENSION_LEAF or name.endswith(f".{EXTENSION_LEAF}") for name in names):
            total += 1
    return total


def test_the_loader_is_the_only_sdk_module_that_imports_the_extension() -> None:
    """CRITERION: the files in `PERMITTED_EXTENSION_IMPORTS`, and no others,
    import ``_scp_core``, each exactly as many times as that mapping states.

    `BRIDGE_ACCESSORS` above is written by hand, so it holds the accessors
    somebody remembered to list and says nothing about a module added later. A
    module that keeps its own ``_scp_core`` import and its own
    ``except ImportError`` block reports a load failure as an absence, which is
    the defect this file exists to keep out, and it does so whether or not
    anyone lists it.

    This assertion reads the package's source instead of its list, and compares
    the whole per-file count against the mapping, so a new importer fails the
    assertion whichever spelling it uses and whichever file it sits in.
    """
    package_directory = Path(_extension.__file__).parent
    counts = {
        path.relative_to(package_directory).as_posix(): _count_extension_imports(path.read_text())
        for path in package_directory.rglob("*.py")
    }
    importers = {name: count for name, count in counts.items() if count}
    assert importers == PERMITTED_EXTENSION_IMPORTS


@pytest.mark.parametrize(
    "source",
    [
        "import _scp_core\n",
        "from scp_sdk import _scp_core\n",
        "from scp_sdk import SCP, _scp_core\n",
        "from . import _scp_core\n",
        "import scp_sdk._scp_core\n",
        "import scp_sdk._scp_core as core\n",
        "from scp_sdk._scp_core import SCP\n",
        "from _scp_core import SCP\n",
        "def _bridge():\n    from scp_sdk import _scp_core\n    return _scp_core\n",
    ],
)
def test_the_detector_counts_every_spelling_of_the_import(source: str) -> None:
    """NEGATIVE CONTROL: the scan above fails on the spellings the SDK uses.

    The scan it guards passes when it finds nothing, so a scan that reads no
    spelling passes for the wrong reason. Each source below is one statement an
    author can write to reach the extension, including the
    ``from scp_sdk import _scp_core`` form that ``scp_sdk/__init__.py`` writes
    and that the pattern this scan replaced did not match.
    """
    assert _count_extension_imports(source) == 1


@pytest.mark.parametrize(
    "source",
    [
        "import _scp_core_helper\n",
        "from scp_sdk import _scp_core_helper\n",
        "from json import loads\n",
        '"""A docstring naming import _scp_core."""\n',
        'MESSAGE = "import _scp_core"\n',
    ],
)
def test_the_detector_counts_no_statement_that_imports_something_else(source: str) -> None:
    """A name that starts with the extension's name is a different module, and
    prose that quotes the statement imports nothing."""
    assert _count_extension_imports(source) == 0


# ---------------------------------------------------------------------------
# A loaded extension that lacks an export
# ---------------------------------------------------------------------------


@pytest.fixture
def stale_extension(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Install a loaded ``scp_sdk._scp_core`` that exports one name, ``present``.

    It stands in for a stale or partial build: the module imports, and every
    export an SDK wrapper calls beyond ``present`` is missing from it.
    """
    import types

    import scp_sdk

    module = types.ModuleType(_extension.EXTENSION_MODULE)
    module.present = lambda: "called"  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, _extension.EXTENSION_MODULE, module)
    monkeypatch.setattr(scp_sdk, "_scp_core", module, raising=False)
    return module


def test_a_missing_export_raises_the_load_failure_code(stale_extension: Any) -> None:
    native = _extension.native_module()
    assert native.present() == "called"
    with pytest.raises(ScpError) as caught:
        native.scpid_challenge
    assert caught.value.code == _extension.EXTENSION_LOAD_FAILED_CODE
    assert "scpid_challenge" in caught.value.message


def test_a_probe_for_an_optional_export_still_reads_absence(stale_extension: Any) -> None:
    """``hasattr`` and ``getattr(..., default)`` keep working on the returned object.

    ``scp_sdk/event_log.py`` probes ``init_pyo3_log`` and ``scp_sdk/scp.py`` probes
    ``identity_verify_device_attestation`` with ``hasattr``; each needs ``False``
    for a name the build lacks, not an exception.
    """
    native = _extension.native_module()
    assert not hasattr(native, "init_pyo3_log")
    assert getattr(native, "SCP", None) is None


@pytest.mark.parametrize(("module_name", "accessor"), BRIDGE_ACCESSORS)
def test_every_bridge_accessor_reports_a_missing_export_with_the_load_failure_code(
    stale_extension: Any, module_name: str, accessor: str
) -> None:
    """Each SDK accessor hands its wrappers an object that raises the registered code."""
    bridge = getattr(importlib.import_module(module_name), accessor)()
    with pytest.raises(ScpError) as caught:
        bridge.evaluate_provenance_quality
    assert caught.value.code == _extension.EXTENSION_LOAD_FAILED_CODE


async def test_a_wrapper_call_on_a_stale_build_raises_the_load_failure_code(
    stale_extension: Any,
) -> None:
    """End to end through one SDK wrapper: ``SCP.scpid_challenge`` on a stale build."""
    from scp_sdk.scp import SCP

    with pytest.raises(ScpError) as caught:
        await SCP.scpid_challenge(object.__new__(SCP), "https://example.test")
    assert caught.value.code == _extension.EXTENSION_LOAD_FAILED_CODE
