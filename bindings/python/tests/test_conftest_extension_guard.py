"""Guard the `scp` fixture's skip condition and its teardown in
bindings/python/tests/conftest.py.

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

The teardown test at the end of this file guards the other half of the fixture:
a teardown that calls the coroutine function `SCP.shutdown` from its synchronous
`finally` block builds a coroutine nothing runs, so no test in the suite shuts its
native instance down. That test replaces `scp_sdk.SCP` with a recording stand-in.

These tests import no native symbol, so they run wherever the pure-Python SDK
imports and cannot themselves be skipped by a missing extension.
"""

from __future__ import annotations

import inspect

import pytest

import scp_sdk
from scp_sdk import _extension
from scp_sdk.errors import ScpError, StorageError, ValidationError
from scp_sdk.scp import SCP as RealSCP
from tests import conftest
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


def test_fixture_teardown_uses_the_synchronous_shutdown_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The `scp` fixture's teardown must shut its instance down, not build a coroutine.

    `scp_sdk.SCP.shutdown` is a coroutine function, so the fixture's synchronous
    teardown cannot call it: the call returns a coroutine that nothing runs, every
    test's native instance stays alive for the rest of the pytest process, and no
    test in the suite exercises the shutdown path. `SCP.__exit__` is the
    synchronous path, and this test drives the fixture's generator to exhaustion —
    which runs the `finally` block — and reads which path the teardown took off a
    stand-in that records both.

    The stand-in replaces `scp_sdk.SCP`, so this test needs no native extension and
    runs wherever the pure-Python SDK imports.
    """
    assert inspect.iscoroutinefunction(RealSCP.shutdown), (
        "this test guards the fixture against calling a coroutine function from a "
        "synchronous teardown; SCP.shutdown is no longer one, so re-read conftest"
    )

    class _RecordingScp:
        """Records which of the two shutdown paths the fixture's teardown took."""

        def __init__(self, storage: dict[str, str]) -> None:
            self.storage = storage
            self.exit_calls: list[tuple[object, object, object]] = []
            self.coroutines_built = 0

        async def shutdown(self, timeout: float = 5.0) -> None:
            self.coroutines_built += 1

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            self.exit_calls.append((exc_type, exc, tb))

    monkeypatch.setattr(scp_sdk, "SCP", _RecordingScp)

    # `@pytest.fixture` wraps the generator function and exposes the original as
    # `__wrapped__`, which is the only handle on the fixture body a test can call.
    fixture_body = conftest.scp.__wrapped__  # type: ignore[attr-defined]
    generator = fixture_body()
    instance = next(generator)
    with pytest.raises(StopIteration):
        next(generator)

    assert instance.exit_calls == [(None, None, None)], (
        "the scp fixture's teardown must call SCP.__exit__ so the native instance "
        f"actually shuts down; recorded __exit__ calls: {instance.exit_calls}"
    )
    assert instance.coroutines_built == 0, (
        "the teardown called the coroutine function SCP.shutdown, which builds a "
        "coroutine nothing runs and leaves the native instance alive"
    )
