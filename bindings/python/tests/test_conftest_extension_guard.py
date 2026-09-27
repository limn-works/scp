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

import ast
import inspect
import sys
from pathlib import Path
from typing import Any

import pytest

import scp_sdk
from scp_sdk import _extension
from scp_sdk.errors import ScpError, StorageError, ValidationError
from scp_sdk.scp import SCP as RealSCP
from tests import conftest
from tests.conftest import extension_is_absent


def test_not_installed_error_is_absence() -> None:
    """`EXTENSION_ABSENT_CODE` is the code `native_module` raises when absent."""
    assert extension_is_absent(ScpError("not installed", code=_extension.EXTENSION_ABSENT_CODE))


def test_native_load_codes_are_the_registered_shared_codes() -> None:
    """Both codes are registered in-range codes the ts-native SDK also throws.

    `.docs/standards/sdk-common.md` registers `SCP-VALID-7081` and
    `SCP-VALID-7082`, and `bindings/typescript/src/internal/native.ts` throws
    the same literals, so a skip guard in either SDK keys on one registered
    code per condition rather than on an unregistered sentinel.
    """
    assert _extension.EXTENSION_ABSENT_CODE == "SCP-VALID-7081"
    assert _extension.EXTENSION_LOAD_FAILED_CODE == "SCP-VALID-7082"


def test_absent_extension_classifies_as_absence(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no extension file on the path, the import failure means absence.

    `reject_load_failure` returns, which lets `native_module` raise
    `EXTENSION_ABSENT_CODE`, and the fixture skips on that.
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
        assert caught.value.code == _extension.EXTENSION_LOAD_FAILED_CODE
        assert not extension_is_absent(caught.value)


def test_loaded_without_scp_class_is_not_absence() -> None:
    """`_native_cls` reports a partial build with the load-failure code."""
    assert not extension_is_absent(
        ScpError(
            "_scp_core loaded but does not export the SCP class",
            code=_extension.EXTENSION_LOAD_FAILED_CODE,
        )
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


def test_fixture_fails_on_a_package_import_error_instead_of_skipping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An ``ImportError`` from ``from scp_sdk import SCP`` fails the `scp` fixture.

    An absent extension no longer raises ``ImportError`` from that import, so the
    only cause left is a defect in the pure-Python package. Removing the ``SCP``
    attribute makes ``from scp_sdk import SCP`` raise ``ImportError`` the way a
    renamed symbol does. A fixture that caught it would raise
    ``pytest.skip.Exception``, which pytest reports as a skip rather than a
    failure, so this test catches that exception and fails on it explicitly.
    """
    monkeypatch.delattr(scp_sdk, "SCP")
    fixture_body = conftest.scp.__wrapped__  # type: ignore[attr-defined]
    try:
        with pytest.raises(ImportError):
            next(fixture_body())
    except pytest.skip.Exception as skipped:
        pytest.fail(f"the scp fixture skipped over a package ImportError: {skipped}")


def _raise(exc: BaseException) -> Any:
    raise exc


def test_module_guard_skips_only_when_the_loader_reports_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An absent extension is the one case a real-FFI module guard skips on."""
    monkeypatch.setattr(
        _extension,
        "native_module",
        lambda: _raise(ValidationError("not installed", code=_extension.EXTENSION_ABSENT_CODE)),
    )
    reason = conftest.skip_reason_if_extension_absent(ImportError("No module named '_scp_core'"))
    assert "not installed" in reason


def test_module_guard_raises_the_loader_error_for_a_present_unloadable_extension(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A present extension whose `dlopen` failed fails collection instead of skipping."""
    monkeypatch.setitem(sys.modules, _extension.EXTENSION_MODULE, None)
    monkeypatch.setattr(_extension, "extension_is_installed", lambda: True)
    with pytest.raises(ScpError) as caught:
        conftest.skip_reason_if_extension_absent(ImportError("undefined symbol"))
    assert caught.value.code == _extension.EXTENSION_LOAD_FAILED_CODE


@pytest.mark.parametrize(
    "guard_error",
    [
        AttributeError("module '_scp_core' has no attribute 'SCP'"),
        ScpError("built without testing", code=_extension.EXTENSION_LOAD_FAILED_CODE),
        RuntimeError("panic in bridge init"),
    ],
)
def test_module_guard_reraises_its_own_error_when_the_extension_loads(
    monkeypatch: pytest.MonkeyPatch, guard_error: Exception
) -> None:
    """An extension that loads without an export the module calls fails collection.

    The loader succeeds here, so the guard's error is not absence: a missing
    `SCP` class, a missing `testing`-gated method, or a panic in the probe's
    construction is re-raised. `.docs/standards/sdk-common.md` registers that
    case under `SCP-VALID-7082` and says a skip guard fails on it.
    """
    monkeypatch.setattr(_extension, "native_module", lambda: object())
    with pytest.raises(type(guard_error)) as caught:
        conftest.skip_reason_if_extension_absent(guard_error)
    assert caught.value is guard_error


def _skip_site_reasons(source: str) -> list[ast.expr | None]:
    """The reason expression of every skip site in ``source`` that can gate a module or test.

    Three spellings gate a module or a test on the native extension: a
    ``pytest.skip(reason, allow_module_level=True)`` call, a ``skipif`` marker
    (its ``reason=`` keyword), and a ``pytest.importorskip(...)`` call. An
    ``importorskip`` call yields ``None``, because it takes its skip decision
    from its own import rather than from the loader, so the scan counts every
    one as an offender. A skip inside a fixture or a test body without
    ``allow_module_level`` is not collected: the bridge-parity runner fixtures
    skip on an unbuilt Kotlin or Swift runner, which is not the extension.
    """
    reasons: list[ast.expr | None] = []
    for node in ast.walk(ast.parse(source)):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        keywords = {kw.arg: kw.value for kw in node.keywords}
        if node.func.attr == "importorskip":
            reasons.append(None)
        elif node.func.attr == "skipif":
            reasons.append(keywords.get("reason"))
        elif node.func.attr == "skip":
            module_level = keywords.get("allow_module_level")
            if not (isinstance(module_level, ast.Constant) and module_level.value is True):
                continue
            reasons.append(node.args[0] if node.args else None)
    return reasons


def _is_absence_call(expr: ast.expr | None) -> bool:
    return (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Name)
        and expr.func.id == "skip_reason_if_extension_absent"
    )


def _is_absence_reason(reason: ast.expr | None, source: str = "") -> bool:
    """Whether ``reason`` comes from ``skip_reason_if_extension_absent``.

    A direct call qualifies. So does a module variable (optionally written
    ``name or ""``, the form a ``skipif`` marker needs) when every value
    ``source`` assigns to it is ``None`` or a direct call and at least one is a
    call: the ``_NATIVE_SKIP_REASON`` shape in ``test_join_from_welcome.py``.
    """
    if _is_absence_call(reason):
        return True
    if isinstance(reason, ast.BoolOp) and isinstance(reason.op, ast.Or):
        reason = reason.values[0]
    if not isinstance(reason, ast.Name) or not source:
        return False
    values = [
        node.value
        for node in ast.walk(ast.parse(source))
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and node.value is not None
        and any(
            isinstance(t, ast.Name) and t.id == reason.id
            for t in (node.targets if isinstance(node, ast.Assign) else [node.target])
        )
    ]
    return any(_is_absence_call(v) for v in values) and all(
        _is_absence_call(v) or (isinstance(v, ast.Constant) and v.value is None) for v in values
    )


def _scanned_test_files() -> list[Path]:
    return sorted(Path(conftest.__file__).parent.rglob("*.py"))


def test_every_module_level_skip_takes_its_reason_from_the_absence_check() -> None:
    """CRITERION: every skip site under `bindings/python/tests` that can gate a
    module or a test on the native extension — `pytest.skip(...,
    allow_module_level=True)`, a `skipif` marker, `pytest.importorskip` — takes
    its reason from `skip_reason_if_extension_absent`, so no module or test
    skips over a present extension that failed to load or lacks an export it
    calls. The walk is recursive, so `tests/bridge_parity/` is covered."""
    offenders = []
    for path in _scanned_test_files():
        source = path.read_text()
        if not all(_is_absence_reason(r, source) for r in _skip_site_reasons(source)):
            offenders.append(str(path.relative_to(Path(conftest.__file__).parent)))
    assert offenders == []


def test_the_skip_scan_reads_the_bridge_parity_package() -> None:
    """The scan's file set includes the subpackage the bridge-parity jobs run."""
    tests_dir = Path(conftest.__file__).parent
    scanned = {path.relative_to(tests_dir).parts[0] for path in _scanned_test_files()}
    assert "bridge_parity" in scanned


def test_the_skip_scan_accepts_the_skipif_shape_that_consults_the_loader() -> None:
    """POSITIVE CONTROL: the `skipif` guard in test_join_from_welcome.py passes."""
    source = (Path(conftest.__file__).parent / "test_join_from_welcome.py").read_text()
    reasons = _skip_site_reasons(source)
    assert reasons
    assert all(_is_absence_reason(r, source) for r in reasons)


@pytest.mark.parametrize(
    "source",
    [
        'pytest.importorskip("_scp_core")\n',
        "def test_x():\n    pytest.importorskip('scp_sdk._scp_core')\n",
        "_HAS = hasattr(_scp_core, 'x')\n"
        "native = pytest.mark.skipif(not _HAS, reason='no native')\n",
        "_REASON = None\ntry:\n    import x\nexcept Exception:\n"
        "    _REASON = 'not available'\n"
        "native = pytest.mark.skipif(_REASON is not None, reason=_REASON or '')\n",
    ],
)
def test_the_skip_scan_rejects_importorskip_and_a_hand_written_skipif(source: str) -> None:
    """NEGATIVE CONTROL: the other skip spellings fail the scan unless they consult the loader."""
    reasons = _skip_site_reasons(source)
    assert len(reasons) == 1
    assert not _is_absence_reason(reasons[0], source)


def test_the_skip_scan_rejects_a_hand_written_reason() -> None:
    """NEGATIVE CONTROL: the guard shape the absence check replaced fails the scan."""
    source = (
        "try:\n    from scp_sdk import _scp_core\n"
        "except (ImportError, AttributeError):\n"
        '    pytest.skip("not available", allow_module_level=True)\n'
    )
    reasons = _skip_site_reasons(source)
    assert len(reasons) == 1
    assert not _is_absence_reason(reasons[0], source)
