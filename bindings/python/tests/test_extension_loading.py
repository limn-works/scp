"""A present-but-unloadable `_scp_core` must be reported apart from an absent one.

Python raises `ImportError` for both causes, so every `except ImportError:
pytest.skip(...)` guard under `bindings/python/tests` skips on a broken artifact
exactly as it skips on a missing one — a job that downloaded a broken PyO3
extension then exits 0 over zero executed assertions. `scp_sdk._extension`
separates the causes by asking whether the extension file sits on the import path,
and raises `SCP-UNKNOWN-0002` for a load failure so the guards let it through.

These tests import no native symbol: they drive the separation with
`sys.modules["_scp_core"] = None`, which makes `import _scp_core` raise
`ImportError` whether or not the compiled extension exists in this environment.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from typing import Any

import pytest

from scp_sdk import _extension
from scp_sdk.errors import ScpError

#: Every SDK module whose bridge accessor must route through
#: :func:`scp_sdk._extension.native_module`. Each one carried its own copy of the
#: `import _scp_core` / `except ImportError` block, and each copy reported a load
#: failure with the absence code.
BRIDGE_ACCESSORS = [
    ("scp_sdk.bridge", "_bridge"),
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


def test_extension_is_installed_agrees_with_the_import_path() -> None:
    """The probe locates the extension file without executing it."""
    found = importlib.util.find_spec(_extension.EXTENSION_MODULE) is not None
    assert _extension.extension_is_installed() is found
