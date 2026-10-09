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

The teardown test guards the other half of the fixture: a teardown that calls the
coroutine function `SCP.shutdown` from its synchronous `finally` block builds a
coroutine nothing runs, so no test in the suite shuts its native instance down.
That test replaces `scp_sdk.SCP` with a recording stand-in.

The module-guard tests drive `skip_reason_if_extension_absent`, the helper every
real-FFI module guard calls, and the scan at the end of this file reads every
skip site in the Python test trees and fails when one skips on anything but the
loader's SCP-VALID-7081 answer.

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


class _SkipSiteCollector(ast.NodeVisitor):
    """Collect every skip site in one module with the function that encloses it.

    A skip site is any spelling that can skip a module or a test: a ``.skip(...)``
    call (``pytest.skip`` in a module, a fixture or a test body, and the
    ``pytest.mark.skip(...)`` marker), a ``.skipif(...)`` marker, a
    ``.importorskip(...)`` call, and a bare ``pytest.mark.skip`` attribute used as
    a decorator or a ``pytestmark`` value. Each site is recorded as
    ``(enclosing function name or "<module>", reason expression)``. A site whose
    reason the scan cannot trace records ``None``: an ``importorskip``, which
    decides from its own import, and an unconditional bare marker.
    """

    def __init__(self) -> None:
        self.sites: list[tuple[str, ast.expr | None]] = []
        self._scope: list[str] = []
        self._called: set[int] = set()

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._scope.append(node.name)
        self.generic_visit(node)
        self._scope.pop()

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def _where(self) -> str:
        return self._scope[-1] if self._scope else "<module>"

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute):
            self._called.add(id(node.func))
            keywords = {kw.arg: kw.value for kw in node.keywords}
            attr = node.func.attr
            if attr == "importorskip":
                self.sites.append((self._where(), None))
            elif attr == "skipif":
                self.sites.append((self._where(), keywords.get("reason")))
            elif attr == "skip":
                reason = node.args[0] if node.args else keywords.get("reason", keywords.get("msg"))
                self.sites.append((self._where(), reason))
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # A bare ``pytest.mark.skip`` skips unconditionally. ``visit_Call`` records
        # a call's ``func`` in ``_called`` before visiting it, so a called
        # ``mark.skip(...)`` is not counted a second time here.
        if (
            node.attr == "skip"
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "mark"
            and id(node) not in self._called
        ):
            self.sites.append((self._where(), None))
        self.generic_visit(node)


def _skip_sites(source: str) -> list[tuple[str, ast.expr | None]]:
    """Every skip site in ``source`` as ``(enclosing function, reason expression)``."""
    collector = _SkipSiteCollector()
    collector.visit(ast.parse(source))
    return collector.sites


def _skip_site_reasons(source: str) -> list[ast.expr | None]:
    """The reason expression of every skip site in ``source``."""
    return [reason for _, reason in _skip_sites(source)]


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


#: The repository root: ``bindings/python/tests/conftest.py`` sits three levels below it.
_REPO_ROOT = Path(conftest.__file__).resolve().parents[3]

#: Skip sites whose reason does not come from ``skip_reason_if_extension_absent``,
#: keyed by ``(repository-relative file, enclosing function)``, with the exact
#: number of such sites in that function. The scan fails when the sites it finds
#: differ from this table in either direction, so a new site fails and so does an
#: entry whose site was removed.
_NON_LOADER_SKIP_SITES: dict[tuple[str, str], int] = {
    # The ``scp`` fixture skips only after ``extension_is_absent(exc)`` returned
    # True, which is the SCP-VALID-7081 test itself; it re-raises every other
    # construction failure.
    ("bindings/python/tests/conftest.py", "scp"): 1,
    # The bridge-parity runner fixtures skip on an unbuilt Kotlin or Swift runner
    # binary, or for Swift on a host that is not macOS. Neither is the Python
    # extension: the runners load the UniFFI library, not ``_scp_core``.
    ("bindings/python/tests/bridge_parity/conftest.py", "kotlin_runner"): 1,
    ("bindings/python/tests/bridge_parity/conftest.py", "swift_runner"): 2,
}


def _scanned_test_files() -> list[Path]:
    """Every Python test file that imports the SDK: ``bindings/python/tests``
    (recursively, so ``bridge_parity/`` is included) and the repository-root
    ``tests/`` directory, which holds
    ``tests/integration/phase3_integration_test.py``."""
    roots = (Path(conftest.__file__).resolve().parent, _REPO_ROOT / "tests")
    return sorted(path for root in roots for path in root.rglob("*.py"))


def _non_loader_skip_sites(paths: list[Path], root: Path) -> dict[tuple[str, str], int]:
    """Count, per ``(file relative to root, enclosing function)``, the skip sites
    in ``paths`` whose reason does not come from ``skip_reason_if_extension_absent``."""
    counts: dict[tuple[str, str], int] = {}
    for path in paths:
        source = path.read_text()
        for where, reason in _skip_sites(source):
            if _is_absence_reason(reason, source):
                continue
            key = (path.relative_to(root).as_posix(), where)
            counts[key] = counts.get(key, 0) + 1
    return counts


def test_every_skip_site_takes_its_reason_from_the_absence_check() -> None:
    """CRITERION: every skip site in a Python test file that imports the SDK —
    under `bindings/python/tests` (including `bridge_parity/`) or the
    repository-root `tests/` — takes its reason from
    `skip_reason_if_extension_absent`, so no module or test skips over a present
    extension that failed to load (SCP-VALID-7082) or lacks an export it calls.
    The only exceptions are the sites `_NON_LOADER_SKIP_SITES` names; each one is
    conditioned on SCP-VALID-7081 by other means or gates on something other than
    the Python extension."""
    found = _non_loader_skip_sites(_scanned_test_files(), _REPO_ROOT)
    assert found == _NON_LOADER_SKIP_SITES, (
        "skip sites that do not consult skip_reason_if_extension_absent differ from "
        f"the reviewed table; found {found}, expected {_NON_LOADER_SKIP_SITES}"
    )


def test_the_skip_scan_reports_a_planted_non_conforming_file(tmp_path: Path) -> None:
    """POSITIVE CONTROL: a file on disk with a hand-written skip reason is reported.

    This drives the file-reading and counting path the criterion test uses over a
    directory that holds one conforming and one non-conforming module, so a scan
    that stopped reading files or stopped classifying reasons fails here.
    """
    (tmp_path / "test_ok.py").write_text(
        "try:\n    from scp_sdk import _scp_core\n"
        "except Exception as _exc:\n"
        "    pytest.skip(skip_reason_if_extension_absent(_exc), allow_module_level=True)\n"
    )
    (tmp_path / "test_planted.py").write_text(
        "def test_x():\n    pytest.skip('no native')\n\n"
        "@pytest.mark.skip\ndef test_y():\n    pass\n"
    )
    found = _non_loader_skip_sites(sorted(tmp_path.glob("*.py")), tmp_path)
    # A decorator is attributed to the function it decorates.
    assert found == {("test_planted.py", "test_x"): 1, ("test_planted.py", "test_y"): 1}


def test_the_skip_scan_reads_the_repository_root_tests() -> None:
    """The scan's file set includes the Phase 3 integration test, which sits
    outside `bindings/python/tests` and gates its real-bridge class on a
    `skipif` marker."""
    scanned = {path.relative_to(_REPO_ROOT).as_posix() for path in _scanned_test_files()}
    assert "tests/integration/phase3_integration_test.py" in scanned


def test_the_skip_scan_reads_the_bridge_parity_package() -> None:
    """The scan's file set includes the subpackage the bridge-parity jobs run."""
    tests_dir = Path(conftest.__file__).resolve().parent
    scanned = {
        path.relative_to(tests_dir).parts[0]
        for path in _scanned_test_files()
        if path.is_relative_to(tests_dir)
    }
    assert "bridge_parity" in scanned


def test_the_skip_scan_accepts_the_skipif_shape_that_consults_the_loader() -> None:
    """The `skipif` guard in test_join_from_welcome.py passes the scan."""
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
        "def test_x():\n    pytest.skip('native extension missing')\n",
        "@pytest.mark.skip(reason='no native')\ndef test_x():\n    pass\n",
        "pytestmark = pytest.mark.skip\n",
    ],
)
def test_the_skip_scan_rejects_skips_that_do_not_consult_the_loader(source: str) -> None:
    """NEGATIVE CONTROL: every other skip spelling fails the scan."""
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
