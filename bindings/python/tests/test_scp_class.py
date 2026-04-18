"""Tests for the SCP #[pyclass] exposed by the PyO3 bridge (#1549 Phase 4 PR 1 + PR 3).

The SCP class wraps `PyBridgeInstance` and is the Python-facing entry
point for the multi-instance refactor.  Each test verifies:

1. `SCP()` constructs successfully (fresh instance).
2. `SCP.default_instance()` returns the process-global default,
   stable across calls.
3. `SCP.instance_id` is monotonic across new instances.
4. Native `SCP.suspend()` / `.resume()` / `.shutdown(timeout)` drive
   the lifecycle without errors. (Native `.resume()` is sync-callable;
   internally it uses `py.allow_threads(|| rt.block_on(...))`.)
5. PR 3: the SDK wrapper's `.resume()` is `async def` and delegates
   to the native call via `asyncio.to_thread` — see #1549 PR 3
   (#1678).
6. PR 3: `SCP(storage={"type": "sqlite", "path": str, "key": bytes})`
   forwards the dict to the native `with_storage` staticmethod.

Requires the native _scp_core extension built via maturin.
"""

from __future__ import annotations

import math
from itertools import pairwise
from typing import Any
from unittest.mock import MagicMock

import pytest

try:
    from scp_sdk import _scp_core
except (ImportError, AttributeError):
    pytest.skip(
        "Native _scp_core extension not available — run maturin develop first",
        allow_module_level=True,
    )

from scp_sdk.scp import SCP as WrapperSCP

SCP = _scp_core.SCP


def test_scp_constructs_successfully() -> None:
    """`SCP()` must return an instance with a nonzero instance_id."""
    scp = SCP()
    assert scp.instance_id > 0, "new SCP instance must have a monotonic nonzero id"


def test_default_instance_returns_stable_id() -> None:
    """Two calls to `SCP.default_instance()` must share the same instance_id.

    The wrapper objects are distinct Python objects, but they wrap the
    same `Arc<PyBridgeInstance>` so `instance_id` is identical.
    """
    a = SCP.default_instance()
    b = SCP.default_instance()
    assert a.instance_id == b.instance_id
    assert a.instance_id > 0


def test_instance_id_is_monotonic_across_new_instances() -> None:
    """Each `SCP()` call produces a strictly greater instance_id."""
    ids = [SCP().instance_id for _ in range(3)]
    for earlier, later in pairwise(ids):
        assert later > earlier, f"expected monotonic ids, got {ids}"


def test_new_instances_have_distinct_id_from_default() -> None:
    """Fresh `SCP()` instances must NOT share the default's id."""
    fresh = SCP()
    default = SCP.default_instance()
    assert fresh.instance_id != default.instance_id, (
        "SCP() must allocate a fresh instance, not reuse the default"
    )


def test_suspend_resume_shutdown_lifecycle() -> None:
    """suspend/resume/shutdown must all succeed on a fresh instance."""
    scp = SCP()
    scp.suspend()
    scp.resume()
    # Native `SCP.shutdown` takes unsigned milliseconds after the
    # #1549 Phase 4 unit unification. 1 s = 1000 ms.
    scp.shutdown(1000)


def test_shutdown_is_idempotent() -> None:
    """A second `shutdown()` call is a documented no-op."""
    scp = SCP()
    scp.shutdown(1000)
    scp.shutdown(1000)  # Must not raise.


def test_with_storage_in_memory_constructs_instance() -> None:
    """`SCP.with_storage({'type': 'in_memory'})` returns a fresh instance."""
    scp = SCP.with_storage({"type": "in_memory"})
    assert scp.instance_id > 0


def test_with_storage_rejects_unknown_type() -> None:
    """`SCP.with_storage({'type': 'bogus'})` raises the _scp_core ValidationError.

    The PyO3 layer raises its own `_scp_core.ValidationError` class; the
    pure-Python `scp_sdk.ValidationError` wrapper is applied downstream
    by the SDK facade. This test exercises the bridge directly so it
    asserts against the native exception class.
    """
    with pytest.raises(_scp_core.ValidationError):
        SCP.with_storage({"type": "bogus"})


def test_repr_contains_instance_id() -> None:
    """`repr(SCP())` must contain the instance_id for debugging."""
    scp = SCP()
    assert str(scp.instance_id) in repr(scp)


def _make_wrapper_with_mock() -> tuple[WrapperSCP, Any]:
    """Build an SDK-level `SCP` wrapper with a mocked `_native` handle.

    The wrapper's `shutdown()` does the float-seconds → u64-millis clamp
    before delegating to `_native.shutdown(millis)`. Mocking lets us
    observe the exact millis value without spinning up a real tokio
    runtime or caring about teardown.
    """
    wrapper = WrapperSCP.__new__(WrapperSCP)
    mock_native = MagicMock()
    wrapper._native = mock_native
    return wrapper, mock_native


def test_shutdown_infinity_maps_to_max_millis() -> None:
    """`math.inf` must clamp to u64::MAX — "wait forever" — not abort.

    Regression test for round 5 RED-2001: the previous clamp ordering
    (`if not math.isfinite(timeout) or timeout <= 0: millis = 0`) caught
    `math.inf` in the first branch and collapsed it to 0, which on the
    Rust side means "abort in-flight tasks immediately". The docstring
    promises the opposite.
    """
    wrapper, mock_native = _make_wrapper_with_mock()
    wrapper.shutdown(timeout=math.inf)
    mock_native.shutdown.assert_called_once_with(0xFFFFFFFF_FFFFFFFF)


def test_shutdown_negative_infinity_maps_to_abort() -> None:
    """`-math.inf` must NOT be treated as wait-forever.

    The Infinity-is-wait-forever exemption is deliberately asymmetric:
    only the positive branch maps to u64::MAX. `-inf` is a
    nonsensical timeout and falls through to the abort branch.
    """
    wrapper, mock_native = _make_wrapper_with_mock()
    wrapper.shutdown(timeout=-math.inf)
    mock_native.shutdown.assert_called_once_with(0)


def test_shutdown_nan_maps_to_abort() -> None:
    """`math.nan` must clamp to 0 (abort) — NaN is not orderable.

    Ordered comparisons against NaN always return False, so `nan <= 0`
    is False. `math.isfinite(nan)` is also False — that is how we trap it.
    """
    wrapper, mock_native = _make_wrapper_with_mock()
    wrapper.shutdown(timeout=math.nan)
    mock_native.shutdown.assert_called_once_with(0)


def test_shutdown_negative_maps_to_abort() -> None:
    """Negative timeouts collapse to 0 (abort immediately)."""
    wrapper, mock_native = _make_wrapper_with_mock()
    wrapper.shutdown(timeout=-1.5)
    mock_native.shutdown.assert_called_once_with(0)


def test_shutdown_zero_maps_to_abort() -> None:
    """A zero-second timeout maps to 0 millis — an explicit abort."""
    wrapper, mock_native = _make_wrapper_with_mock()
    wrapper.shutdown(timeout=0.0)
    mock_native.shutdown.assert_called_once_with(0)


def test_shutdown_overflow_clamps_to_max_millis() -> None:
    """Values that would overflow u64::MAX milliseconds clamp cleanly."""
    wrapper, mock_native = _make_wrapper_with_mock()
    # 1e18 seconds → 1e21 ms, well past u64::MAX (~1.8e19).
    wrapper.shutdown(timeout=1.0e18)
    mock_native.shutdown.assert_called_once_with(0xFFFFFFFF_FFFFFFFF)


def test_shutdown_finite_value_rounds_to_nearest_ms() -> None:
    """Fractional seconds preserve ms resolution via `round()`.

    Regression guard for the round 2 fix (floor → round): 0.2505 s =
    250.5 ms; `round()` yields 250 (banker's rounding half-to-even for
    exact halves, but this value rounds deterministically).
    """
    wrapper, mock_native = _make_wrapper_with_mock()
    wrapper.shutdown(timeout=0.2505)
    mock_native.shutdown.assert_called_once_with(250)


@pytest.mark.asyncio
async def test_wrapper_resume_is_async_and_delegates_to_native() -> None:
    """`WrapperSCP.resume()` must be awaitable and delegate to `_native.resume`.

    Phase 4 PR 3 (#1549, #1678) flipped the wrapper from a blocking
    ``def resume(self)`` to ``async def resume(self)`` so transport
    reconnect work can happen off the asyncio event loop. The wrapper
    uses ``asyncio.to_thread`` internally — we verify the call path by
    checking the mock was invoked exactly once (argumentless), which
    is what ``to_thread(self._native.resume)`` produces.
    """
    wrapper, mock_native = _make_wrapper_with_mock()
    coro = wrapper.resume()
    # Must be a coroutine, not a direct call result — asserts the
    # signature change stuck.
    import inspect

    assert inspect.iscoroutine(coro), (
        "WrapperSCP.resume() must return a coroutine after PR 3's async flip"
    )
    await coro
    mock_native.resume.assert_called_once_with()


def test_wrapper_with_storage_sqlite_passes_config_through() -> None:
    """`SCP(storage={'type': 'sqlite', ...})` must forward the dict to `with_storage`.

    We inspect the native class lookup path: constructing a wrapper
    normally would load the real _scp_core module. Instead we patch
    the private ``_native_cls`` helper so the wrapper receives a mock
    class, and assert ``with_storage`` is called with our exact dict.
    """
    from unittest.mock import patch

    mock_cls = MagicMock()
    mock_cls.with_storage.return_value = MagicMock(instance_id=42)
    sqlite_cfg = {
        "type": "sqlite",
        "path": "/tmp/scp-test",
        "key": b"\x00" * 32,
    }
    with patch("scp_sdk.scp._native_cls", return_value=mock_cls):
        wrapper = WrapperSCP(storage=sqlite_cfg)
    mock_cls.with_storage.assert_called_once_with(sqlite_cfg)
    assert wrapper.instance_id == 42
