"""Cross-bridge runtime parity tests.

For each OpSpec in SEED_OPS and each alt-bridge in the bridge matrix:

  1. Run the op on the in-process PyO3 bridge, normalize the output.
  2. Run the op via the appropriate runner subprocess on the alt
     bridge, normalize the output.
  3. Assert the two normalized dicts are equal; on failure, show a
     unified diff of the two dicts so the divergence is obvious.

Known divergences are declared on `OpSpec.xfail_bridges` and surface as
`@pytest.mark.xfail(strict=True)` — the test still runs but an
unexpected pass is also a failure. That way the xfail list stays a live
snapshot of what's broken; when a bridge is fixed upstream, removing
the xfail tag is the forcing function.

The bridge matrix currently covers NAPI, WASM, UniFFI-Kotlin, and
UniFFI-Swift as alt bridges against the PyO3 reference. Each alt
bridge is served by its own long-lived runner subprocess:

  - napi / wasm     → `bun_runner` (Bun, `node_bridge_runner.ts`)
  - uniffi-kotlin   → `kotlin_runner` (JVM, `kotlin_bridge_runner/`)
  - uniffi-swift    → `swift_runner` (executable, `swift_bridge_runner/`)

The test surface is the op library x the bridge matrix — adding a new
op adds N more parametrized test cases where N = number of alt bridges.
See ADR-046.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from .normalizer import normalize
from .runner_client import BridgeMode, RunnerClient
from .seed_operations import SEED_OPS, OpContext, OpSpec

pytestmark = pytest.mark.parity


# Single source of truth for the bridge matrix. Each entry binds an
# alt-bridge wire name (the `bridgeMode` field on the JSON-RPC request)
# to the pytest fixture that spawns the runner responsible for that
# bridge. Adding a new bridge = one entry here, one fixture in
# conftest.py, one runner binary.
_BRIDGE_MATRIX: tuple[tuple[BridgeMode, str], ...] = (
    ("napi", "bun_runner"),
    ("wasm", "bun_runner"),
    ("uniffi-kotlin", "kotlin_runner"),
    ("uniffi-swift", "swift_runner"),
)


def _diff(a: dict[str, Any], b: dict[str, Any]) -> str:
    """Render a side-by-side JSON diff for test-failure output."""
    left = json.dumps(a, indent=2, sort_keys=True)
    right = json.dumps(b, indent=2, sort_keys=True)
    if left == right:
        return "(no textual diff — equality failure is structural)"
    return f"--- py\n{left}\n\n+++ alt\n{right}\n"


def _resolve(d: dict[str, Any], path: str) -> Any:
    """Walk a dotted path through nested dicts.

    Used to apply `OpSpec.expected_values` assertions after the
    canonical equality check. Raises AssertionError with a caller-
    meaningful message if any segment is missing or traverses a
    non-dict — both are bugs in the op definition that should surface
    loudly rather than None out.
    """
    parts = path.split(".")
    cur: Any = d
    for idx, part in enumerate(parts):
        if not isinstance(cur, dict):
            traversed = ".".join(parts[:idx]) or "<root>"
            raise AssertionError(
                f"expected_values path {path!r}: cannot descend into non-dict at {traversed!r} "
                f"(got {type(cur).__name__})"
            )
        if part not in cur:
            raise AssertionError(
                f"expected_values path {path!r}: missing key {part!r} at segment {idx} "
                f"(available: {sorted(cur.keys())!r})"
            )
        cur = cur[part]
    return cur


@pytest.fixture(scope="session")
def op_context() -> OpContext:
    """Provides the PyO3 module and a per-session scratch dict."""
    # Import lazily so the module is only loaded when a parity test
    # actually runs — avoids coupling the rest of the Python test
    # suite to the PyO3 build availability.
    import scp_sdk._scp_core as scp_core  # type: ignore[import-not-found]

    return OpContext(scp_core=scp_core, scratch={})


def _pytest_param_for(
    op: OpSpec,
    alt_bridge: BridgeMode,
    runner_fixture: str,
) -> Any:
    """Build a pytest.param for (op, alt_bridge), applying xfail when declared."""
    marks: list[Any] = []
    if alt_bridge in op.xfail_bridges:
        reason = op.xfail_reason or f"{op.name} xfailed for {alt_bridge}"
        marks.append(pytest.mark.xfail(strict=True, reason=reason))
    return pytest.param(
        op,
        alt_bridge,
        runner_fixture,
        marks=marks,
        id=f"{alt_bridge}-{op.name}",
    )


_PARITY_CASES = [
    _pytest_param_for(op, bridge, runner_fixture)
    for op in SEED_OPS
    for bridge, runner_fixture in _BRIDGE_MATRIX
]


@pytest.mark.parametrize(("op", "alt_bridge", "runner_fixture"), _PARITY_CASES)
def test_parity(
    op: OpSpec,
    alt_bridge: BridgeMode,
    runner_fixture: str,
    op_context: OpContext,
    request: pytest.FixtureRequest,
) -> None:
    """Assert that PyO3 and the alt bridge produce the same canonical output.

    The `runner_fixture` parameter names the pytest fixture that
    spawns the subprocess for this alt bridge. Resolving it via
    `request.getfixturevalue` keeps the matrix extensible — a new
    bridge entry in `_BRIDGE_MATRIX` picks up its runner automatically
    without edits here.
    """
    # 1. PyO3 (in-process)
    py_raw = op.py_call(op_context)
    py_canonical = normalize(py_raw, op.schema)

    # 2. Alt bridge (via a runner subprocess)
    runner: RunnerClient = request.getfixturevalue(runner_fixture)
    args = op.node_call.get("args", {})
    assert isinstance(args, dict), f"op.node_call.args must be a dict, got {type(args).__name__}"
    node_op = op.node_call.get("op", op.name)
    response = runner.call(op=str(node_op), args=args, mode=alt_bridge)

    assert response.get("ok") is True, (
        f"alt bridge '{alt_bridge}' returned an error for op '{op.name}': {response.get('error')}"
    )

    alt_raw_obj = response.get("result", {})
    assert isinstance(alt_raw_obj, dict), (
        f"alt bridge '{alt_bridge}' returned non-dict result: {type(alt_raw_obj).__name__}"
    )
    alt_canonical = normalize(alt_raw_obj, op.schema)

    # 3. Compare
    assert py_canonical == alt_canonical, (
        f"parity divergence for op '{op.name}' between PyO3 and "
        f"{alt_bridge}:\n{_diff(py_canonical, alt_canonical)}"
    )

    # 4. Absolute-value pins (spec-level commitments, not just parity).
    # Guards against joint drift: if PyO3 and the alt bridge both
    # changed to the same wrong value, step 3 would pass but the spec
    # would be silently violated. See OpSpec.expected_values.
    for path, expected in op.expected_values:
        actual = _resolve(py_canonical, path)
        assert actual == expected, f"{op.name} {path}: got {actual!r}, expected {expected!r}"
        # Also check the alt side — both sides agreed (step 3), but if
        # expected_values is ever invoked for an xfail'd field,
        # checking each side independently keeps the error message
        # precise.
        alt_actual = _resolve(alt_canonical, path)
        assert alt_actual == expected, (
            f"{op.name} {path} (alt={alt_bridge}): got {alt_actual!r}, expected {expected!r}"
        )
