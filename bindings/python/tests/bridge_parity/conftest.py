"""pytest fixtures for the bridge parity harness.

The session-scoped `bun_runner` fixture spawns the long-lived Bun
subprocess at the start of the parity session and tears it down at the
end. One subprocess is shared across all parity tests in the run for
startup amortization, but a per-function `parity_reset` autouse fixture
sends a `reset` RPC before each test so module-global bridge caches in
the runner do not leak state between tests.

The child's environment is explicitly filtered — it does NOT inherit
the parent's full env. Secrets that might be present in a developer
shell or CI runner (GITHUB_TOKEN, ANTHROPIC_API_KEY, ANTHROPIC_*,
AWS_*, etc.) are intentionally not forwarded. Only the minimal set
needed for Bun to find Node binaries, resolve TLS certs, and report
locale/time is passed through.

See ADR-046.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from .runner_client import RunnerClient

# Directory containing the runner script (resolved relative to this file).
HELPERS_DIR = Path(__file__).resolve().parent / "helpers"
RUNNER_SCRIPT = HELPERS_DIR / "node_bridge_runner.ts"

# Repository root is four parents up:
# bindings/python/tests/bridge_parity/conftest.py -> bindings/python/tests/bridge_parity
# -> bindings/python/tests -> bindings/python -> bindings -> repo root
_REPO_ROOT = Path(__file__).resolve().parents[4]
_TYPESCRIPT_DIR = _REPO_ROOT / "bindings" / "typescript"

# Graceful-shutdown budget (how long we wait for the child after sending
# a shutdown request before sending SIGTERM).
GRACEFUL_SHUTDOWN_SECS = 5.0

# Minimal env keys forwarded to the Bun child. Everything else — in
# particular anything that looks like a credential — is intentionally
# stripped. Keep this list small; add keys only when a concrete test
# failure requires them.
#
# Deliberately EXCLUDED:
#   - NODE_OPTIONS: honored by Bun/Node and can inject code via
#     `--require /path/to/evil.js`. If a test needs specific runtime
#     flags, pass them as argv (e.g. `bun --max-old-space-size=...`),
#     never via env.
#   - NODE_PATH: Node/Bun honor this as a module-resolution prefix
#     searched BEFORE the normal node_modules lookup. An attacker with
#     env-write access to the runner could point it at a directory
#     containing a malicious `@limn-works/scp-ts-*` shadow and have
#     Bun load that in preference to the real package. The runner
#     resolves bridges via an explicit relative path
#     (`bindings/typescript/node_modules/@limn-works/scp-ts-*`) and
#     does not need NODE_PATH for legitimate resolution.
#   - TMPDIR/TEMP/TMP: the harness does not create temp files of its
#     own; Bun falls back to system defaults. If a future test needs
#     an isolated tempdir, create one with `tempfile.mkdtemp()` and
#     inject it into the sanitized env explicitly.
#   - BUN_INSTALL: hijacks Bun's resolution of its own install root.
#     CI's `oven-sh/setup-bun@v2` sets PATH; local dev's
#     `shutil.which("bun")` handles the rest. `$BUN` (below) is the
#     sanctioned override for pointing at a specific binary.
_ALLOWED_ENV_KEYS: tuple[str, ...] = (
    # Binary resolution.
    "PATH",
    "HOME",
    # Bun/Node resolution and caches.
    "BUN",
    "BUN_RUNTIME_TRANSPILER_CACHE_PATH",
    "NODE_EXTRA_CA_CERTS",
    # Locale / time — needed for deterministic string formatting.
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    # mise-managed toolchain roots (used on developer machines).
    "MISE_DATA_DIR",
    "MISE_CACHE_DIR",
    # Proxy config, if the dev is behind one.
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    # TLS trust on macOS CI runners.
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
)


def _locate_bun() -> str:
    """Resolve the `bun` executable.

    Honors `$BUN` as an explicit override (used by CI to point at a
    specific toolchain version), otherwise searches PATH. Raises a
    clear error if bun is not available — do not silently fall back to
    npx, which would defeat the "no auto-fallback" principle in
    ADR-046.
    """
    bun = os.environ.get("BUN")
    if bun:
        if not Path(bun).exists():
            raise RuntimeError(f"$BUN is set to '{bun}' which does not exist")
        return bun
    found = shutil.which("bun")
    if found is None:
        raise RuntimeError(
            "bun is not installed or not on PATH. "
            "Install via `curl -fsSL https://bun.sh/install | bash` or "
            "set $BUN to point at a bun binary."
        )
    return found


def _sanitized_env() -> dict[str, str]:
    """Filter the parent env down to the allowlist, preserving case."""
    parent = os.environ
    child: dict[str, str] = {}
    for key in _ALLOWED_ENV_KEYS:
        val = parent.get(key)
        if val is not None:
            child[key] = val
    return child


@pytest.fixture(scope="session")
def bun_runner() -> Iterator[RunnerClient]:
    """Spawn the long-lived Bun bridge runner for the parity test session.

    The subprocess reads length-prefixed JSON-RPC requests on stdin and
    writes length-prefixed responses on stdout. `stderr` is inherited so
    runner errors are visible in pytest output.

    The fixture sends a graceful `shutdown` op at teardown; if the child
    does not exit within `GRACEFUL_SHUTDOWN_SECS`, it is SIGTERM'd.
    """
    if not RUNNER_SCRIPT.exists():
        raise FileNotFoundError(f"runner script not found: {RUNNER_SCRIPT}")

    bun = _locate_bun()

    # cwd = bindings/typescript so that `@limn-works/scp-ts-wasm` and
    # `@limn-works/scp-ts-napi-*` resolve via its node_modules tree.
    # Bun (and Node) walk upward from cwd looking for node_modules; the
    # helpers/ dir has none. The runner script is specified by absolute
    # path so cwd does not affect its resolution.
    proc = subprocess.Popen(
        [bun, "run", str(RUNNER_SCRIPT)],
        cwd=str(_TYPESCRIPT_DIR),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=None,  # inherit — show runner errors directly in pytest output
        bufsize=0,  # unbuffered — writes must flush immediately
        env=_sanitized_env(),
    )

    client = RunnerClient(proc=proc)
    try:
        yield client
    finally:
        client.shutdown()
        deadline = time.monotonic() + GRACEFUL_SHUTDOWN_SECS
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            time.sleep(0.05)
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


@pytest.fixture(autouse=True)
def parity_reset(request: pytest.FixtureRequest) -> None:
    """Reset the runner's module-global bridge caches before each parity test.

    The bun_runner is session-scoped for startup amortization, but the
    runner module-level caches (`napiBridge`, `wasmBridge`) accumulate
    state across calls. Without this fixture, test order would affect
    outcomes and later tests could observe earlier tests' state.

    Only active for tests carrying the `parity` marker — other tests in
    the suite are unaffected.
    """
    if request.node.get_closest_marker("parity") is None:
        return
    runner = request.getfixturevalue("bun_runner")
    runner.reset()
