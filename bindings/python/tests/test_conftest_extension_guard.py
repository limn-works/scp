"""Guard the `scp` fixture's skip condition in bindings/python/tests/conftest.py.

The fixture skips when the native extension is not installed and re-raises every
other construction failure. Skipping on a construction failure the extension can
still produce — a libpython mismatch, a panic in bridge initialisation — would let
a CI job that downloaded a broken PyO3 artifact exit 0 over zero executed
assertions, which is the `zero-test` shape scripts/tests/ci-gate/ci_gate_selftest.py
names.

Python raises `ImportError` for an absent extension and for a present one whose
`dlopen` failed alike, so the tests below drive
`scp_sdk._extension.reject_load_failure` — the function that separates the two
causes — rather than hand-building an exception and asserting against it. An
assertion over a shape the fixture never receives passes without exercising the
scenario it names.

These tests import no native symbol, so they run wherever the pure-Python SDK
imports and cannot themselves be skipped by a missing extension.
"""

from __future__ import annotations

import pytest

from scp_sdk import _extension
from scp_sdk.errors import ScpError, StorageError, ValidationError
from tests.conftest import extension_is_absent


def test_not_installed_error_is_absence() -> None:
    """`SCP-UNKNOWN-0001` is the code `native_module` raises when absent."""
    assert extension_is_absent(ScpError("not installed", code="SCP-UNKNOWN-0001"))


def test_absent_extension_classifies_as_absence(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no extension file on the path, the import failure means absence.

    `reject_load_failure` returns, which lets `native_module` raise
    `SCP-UNKNOWN-0001`, and the fixture skips on that.
    """
    monkeypatch.setattr(_extension, "extension_is_installed", lambda: False)
    assert (
        _extension.reject_load_failure(ModuleNotFoundError("No module named '_scp_core'")) is None
    )


def test_present_but_unloadable_extension_is_not_absence(monkeypatch: pytest.MonkeyPatch) -> None:
    """A present extension whose `dlopen` failed must fail the job, not skip it.

    This is the case an `except ImportError` guard cannot tell from absence: the
    file is installed, so `reject_load_failure` raises the error the fixture
    re-raises. Asserting on a raw `ImportError` instead would test a shape the
    fixture never receives, because `native_module` converts every load failure
    into an `ScpError` before any guard sees it.
    """
    monkeypatch.setattr(_extension, "extension_is_installed", lambda: True)
    for exc in (
        ImportError("libpython3.12.so.1.0: cannot open shared object file"),
        ImportError("undefined symbol: PyUnicode_AsUTF8AndSize"),
    ):
        with pytest.raises(ScpError) as caught:
            _extension.reject_load_failure(exc)
        assert caught.value.code == "SCP-UNKNOWN-0002"
        assert not extension_is_absent(caught.value)


def test_loaded_without_scp_class_is_not_absence() -> None:
    """`_native_cls` reports a partial build with the load-failure code."""
    assert not extension_is_absent(
        ScpError("_scp_core loaded but does not export the SCP class", code="SCP-UNKNOWN-0002")
    )


def test_other_scp_error_codes_are_not_absence() -> None:
    """A built extension that fails to open storage must fail the test, not skip it."""
    assert not extension_is_absent(ValidationError("bad storage dict"))
    assert not extension_is_absent(StorageError("sqlcipher refused the key"))
    assert not extension_is_absent(ScpError("unknown", code="SCP-UNKNOWN-0000"))


def test_non_scp_exceptions_are_not_absence() -> None:
    """A PyO3 panic reaches the fixture unwrapped and must fail the test."""
    assert not extension_is_absent(RuntimeError("panic in bridge init"))
    assert not extension_is_absent(BaseException("bare"))
