"""Guard the `scp` fixture's skip condition in bindings/python/tests/conftest.py.

The fixture skips when the native extension is not installed and re-raises every
other construction failure. Skipping on a construction failure the extension can
still produce — a libpython mismatch, a panic in bridge initialisation — would let
a CI job that downloaded a broken PyO3 artifact exit 0 over zero executed
assertions, which is the `zero-test` shape scripts/tests/ci-gate/ci_gate_selftest.py
names.

These tests import no native symbol, so they run wherever the pure-Python SDK
imports and cannot themselves be skipped by a missing extension.
"""

from __future__ import annotations

from scp_sdk.errors import ScpError, StorageError, ValidationError
from tests.conftest import extension_is_absent


def test_not_installed_error_is_absence() -> None:
    """`SCP-UNKNOWN-0001` is the code `_native_mod`/`_native_cls` raise when absent."""
    assert extension_is_absent(ScpError("not installed", code="SCP-UNKNOWN-0001"))


def test_other_scp_error_codes_are_not_absence() -> None:
    """A built extension that fails to open storage must fail the test, not skip it."""
    assert not extension_is_absent(ValidationError("bad storage dict"))
    assert not extension_is_absent(StorageError("sqlcipher refused the key"))
    assert not extension_is_absent(ScpError("unknown", code="SCP-UNKNOWN-0000"))


def test_non_scp_exceptions_are_not_absence() -> None:
    """A PyO3 error or an interpreter-level failure reaches the fixture unwrapped."""
    assert not extension_is_absent(RuntimeError("panic in bridge init"))
    assert not extension_is_absent(ImportError("libpython3.12.so.1.0: not found"))
    assert not extension_is_absent(BaseException("bare"))
