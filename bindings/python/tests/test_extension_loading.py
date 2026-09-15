"""A present-but-unloadable `_scp_core` must be reported apart from an absent one.

Python raises `ImportError` for both causes, so every `except ImportError:
pytest.skip(...)` guard under `bindings/python/tests` skips on a broken artifact
exactly as it skips on a missing one — a job that downloaded a broken PyO3
extension then exits 0 over zero executed assertions. `scp_sdk._extension`
separates the causes by asking whether an extension file is present — on the import
path, and in the `scp_sdk` package directory for a file another interpreter built —
and raises `SCP-UNKNOWN-0002` for a load failure so the guards let it through.

These tests import no native symbol: they drive the separation with
`sys.modules["_scp_core"] = None`, which makes `import _scp_core` raise
`ImportError` whether or not the compiled extension exists in this environment.
"""

from __future__ import annotations

import importlib
import importlib.machinery
import importlib.util
import re
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
    """Make a bare ``import _scp_core`` raise ``ImportError``.

    ``None`` in ``sys.modules`` is the documented way to make an import fail
    without touching the filesystem, so this reproduces a ``dlopen`` failure and
    an absent extension alike — which is the point: the exception is identical and
    only :func:`scp_sdk._extension.extension_is_installed` tells them apart.
    """
    monkeypatch.setitem(sys.modules, "_scp_core", None)


def test_absent_extension_raises_the_absence_code(
    blocked_import: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_extension, "extension_is_installed", lambda: False)
    with pytest.raises(ScpError) as caught:
        _extension.native_module()
    assert caught.value.code == "SCP-UNKNOWN-0001"


def test_present_extension_that_fails_to_load_raises_the_load_failure_code(
    blocked_import: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_extension, "extension_is_installed", lambda: True)
    with pytest.raises(ScpError) as caught:
        _extension.native_module()
    assert caught.value.code == "SCP-UNKNOWN-0002"


def test_load_failure_is_not_an_import_error(
    blocked_import: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The module-level `except ImportError: pytest.skip(...)` guards must not catch it.

    Seven test modules under `bindings/python/tests` guard their imports that way.
    An `ScpError` is not an `ImportError`, so a broken artifact reaches pytest as a
    collection error instead of a silent skip.
    """
    monkeypatch.setattr(_extension, "extension_is_installed", lambda: True)
    with pytest.raises(ScpError) as caught:
        _extension.native_module()
    assert not isinstance(caught.value, ImportError)


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
    assert caught.value.code == "SCP-UNKNOWN-0002"


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
    assert caught.value.code == "SCP-UNKNOWN-0001"


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
    """End to end: the scenario the finding named reaches `SCP-UNKNOWN-0002`.

    A PyO3 artifact built by one interpreter lands in a job running another.
    The `.so` is present, `import _scp_core` fails, and the code must report a
    load failure so the fixture in `conftest.py` fails the job instead of
    skipping it.
    """
    leaf = unresolvable_module_name.rpartition(".")[2]
    (package_directory / f"{leaf}.cpython-000-scp-test.so").write_bytes(b"")
    with pytest.raises(ScpError) as caught:
        _extension.native_module()
    assert caught.value.code == "SCP-UNKNOWN-0002"


# ---------------------------------------------------------------------------
# One loader, no private copies
# ---------------------------------------------------------------------------


def test_the_loader_is_the_only_sdk_module_that_imports_the_extension() -> None:
    """CRITERION: exactly one module under ``scp_sdk`` imports ``_scp_core``.

    `BRIDGE_ACCESSORS` above is written by hand, so it holds the accessors
    somebody remembered to list and says nothing about a module added later. A
    module that keeps its own `import _scp_core` / `except ImportError` block
    reports a load failure as an absence, which is the defect this file
    exists to keep out, and it does so whether or not anyone lists it.

    This assertion reads the package's source instead of its list: every
    `.py` file under `scp_sdk` other than `_extension.py` must contain no
    `import _scp_core` statement. `scp_sdk/__init__.py` registers the
    extension under its bare name with `from scp_sdk import _scp_core`, which
    is a different statement and passes.
    """
    package_directory = Path(_extension.__file__).parent
    statement = re.compile(r"^\s*import _scp_core\b", re.MULTILINE)
    offenders = sorted(
        path.name
        for path in package_directory.rglob("*.py")
        if path.name != "_extension.py" and statement.search(path.read_text())
    )
    assert offenders == []
