"""pytest fixtures for the bridge parity harness.

The parity suite drives three runner subprocesses, one per non-PyO3
bridge surface:

- `bun_runner` — Bun/Node.js, dispatches to NAPI and WASM bridges.
- `kotlin_runner` — JVM process, dispatches to the UniFFI Kotlin
  bindings.
- `swift_runner` — macOS-only executable, dispatches to the UniFFI
  Swift bindings.

Each runner fixture is **session-scoped** for startup amortization and
**lazy** — the subprocess is spawned only when a test that needs that
bridge is actually collected. A per-function `parity_reset` autouse
fixture sends a `reset` RPC before each parity test so module-global
bridge caches don't leak state across tests.

The Kotlin and Swift runners are gated behind environment variables
(`SCP_PARITY_KOTLIN_RUNNER`, `SCP_PARITY_SWIFT_RUNNER`) that point at a
built runner binary. When unset, the corresponding bridge modes are
skipped with a clear reason. CI sets both; local dev can run partial
matrices without building every toolchain.

Child environments are explicitly filtered — they do NOT inherit the
parent's full env. Secrets that might be present in a developer shell
or CI runner (GITHUB_TOKEN, ANTHROPIC_API_KEY, ANTHROPIC_*, AWS_*, etc.)
are intentionally not forwarded. Only the minimal set needed for the
runtime to find binaries, resolve TLS certs, and report locale/time is
passed through.

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

# Directory containing the runner scripts (resolved relative to this file).
HELPERS_DIR = Path(__file__).resolve().parent / "helpers"
RUNNER_SCRIPT = HELPERS_DIR / "node_bridge_runner.ts"
KOTLIN_RUNNER_DIR = HELPERS_DIR / "kotlin_bridge_runner"
SWIFT_RUNNER_DIR = HELPERS_DIR / "swift_bridge_runner"

# Repository root is four parents up:
# bindings/python/tests/bridge_parity/conftest.py -> bridge_parity -> tests
# -> python -> bindings -> repo root
_REPO_ROOT = Path(__file__).resolve().parents[4]
_TYPESCRIPT_DIR = _REPO_ROOT / "bindings" / "typescript"

# Graceful-shutdown budget (how long we wait for a child after sending
# a shutdown request before escalating to SIGTERM / SIGKILL).
GRACEFUL_SHUTDOWN_SECS = 5.0

# Minimal env keys forwarded to child runners. Everything else — in
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
#     env-write access could point it at a directory containing a
#     malicious shadow package. The Bun runner resolves bridges via
#     explicit relative paths and does not need NODE_PATH for
#     legitimate resolution.
#   - TMPDIR/TEMP/TMP: the harness does not create temp files of its
#     own; runtimes fall back to system defaults. If a future test
#     needs an isolated tempdir, create one with `tempfile.mkdtemp()`
#     and inject it into the sanitized env explicitly.
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
    # JVM — needs JAVA_HOME for the JDK, plus library path for JNA to
    # find the UniFFI cdylib. LD_LIBRARY_PATH for Linux,
    # DYLD_LIBRARY_PATH / DYLD_FALLBACK_LIBRARY_PATH for macOS.
    "JAVA_HOME",
    "LD_LIBRARY_PATH",
    "DYLD_LIBRARY_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
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


def _sanitized_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Filter the parent env down to the allowlist, preserving case.

    Callers may pass an `extra` mapping for per-runner additions (e.g.
    the Kotlin runner needs JNA to find the UniFFI cdylib and so
    benefits from an explicit library path).
    """
    parent = os.environ
    child: dict[str, str] = {}
    for key in _ALLOWED_ENV_KEYS:
        val = parent.get(key)
        if val is not None:
            child[key] = val
    if extra is not None:
        child.update(extra)
    return child


def _popen_runner(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
) -> subprocess.Popen[bytes]:
    """Shared spawn helper: unbuffered stdin/stdout, inherited stderr."""
    return subprocess.Popen(
        argv,
        cwd=str(cwd),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=None,  # inherit — show runner errors directly in pytest output
        bufsize=0,  # unbuffered — writes must flush immediately
        env=env,
    )


def _teardown_runner(
    client: RunnerClient,
    proc: subprocess.Popen[bytes],
) -> None:
    """Best-effort graceful shutdown, escalating to SIGTERM / SIGKILL."""
    client.shutdown()
    deadline = time.monotonic() + GRACEFUL_SHUTDOWN_SECS
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return
        time.sleep(0.05)
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


# ----------------------------------------------------------------------
# Bun (NAPI + WASM) runner
# ----------------------------------------------------------------------


@pytest.fixture(scope="session")
def bun_runner() -> Iterator[RunnerClient]:
    """Spawn the long-lived Bun bridge runner for the parity test session.

    The subprocess reads length-prefixed JSON-RPC requests on stdin and
    writes length-prefixed responses on stdout. `stderr` is inherited so
    runner errors are visible in pytest output.
    """
    if not RUNNER_SCRIPT.exists():
        raise FileNotFoundError(f"runner script not found: {RUNNER_SCRIPT}")

    bun = _locate_bun()

    # cwd = bindings/typescript so that `@limn-works/scp-ts-wasm` and
    # `@limn-works/scp-ts-napi-*` resolve via its node_modules tree.
    # Bun (and Node) walk upward from cwd looking for node_modules; the
    # helpers/ dir has none. The runner script is specified by absolute
    # path so cwd does not affect its resolution.
    proc = _popen_runner(
        [bun, "run", str(RUNNER_SCRIPT)],
        cwd=_TYPESCRIPT_DIR,
        env=_sanitized_env(),
    )
    client = RunnerClient(proc=proc)
    try:
        yield client
    finally:
        _teardown_runner(client, proc)


# ----------------------------------------------------------------------
# Kotlin runner (UniFFI)
# ----------------------------------------------------------------------


def _kotlin_runner_binary() -> Path | None:
    """Resolve the Kotlin runner binary.

    Preference order:
      1. $SCP_PARITY_KOTLIN_RUNNER — explicit override, used by CI.
      2. The default installDist output under the runner project.
    Returns None if neither is set AND no default binary exists; that
    causes the `uniffi-kotlin` parity cases to be skipped.
    """
    env_path = os.environ.get("SCP_PARITY_KOTLIN_RUNNER")
    if env_path:
        p = Path(env_path)
        if not p.exists():
            raise RuntimeError(
                f"$SCP_PARITY_KOTLIN_RUNNER is set to '{env_path}' which does not exist"
            )
        return p
    default = (
        KOTLIN_RUNNER_DIR
        / "build"
        / "install"
        / "kotlin-bridge-runner"
        / "bin"
        / "kotlin-bridge-runner"
    )
    return default if default.exists() else None


@pytest.fixture(scope="session")
def kotlin_runner() -> Iterator[RunnerClient]:
    """Spawn the long-lived Kotlin (UniFFI) bridge runner.

    Gated by `SCP_PARITY_KOTLIN_RUNNER` or a pre-built installDist
    output under `helpers/kotlin_bridge_runner/build/install/`. Skips
    with a clear reason when neither is available.

    JNA loads the UniFFI cdylib via the JVM library path. CI exports
    `LD_LIBRARY_PATH` pointing at the Rust target directory; locally,
    run `./gradlew -p . installDist` with the same env set before
    starting the tests.
    """
    binary = _kotlin_runner_binary()
    if binary is None:
        pytest.skip(
            "Kotlin parity runner not built. Set SCP_PARITY_KOTLIN_RUNNER "
            "or run installDist under helpers/kotlin_bridge_runner/."
        )

    proc = _popen_runner(
        [str(binary)],
        cwd=KOTLIN_RUNNER_DIR,
        env=_sanitized_env(),
    )
    client = RunnerClient(proc=proc)
    try:
        yield client
    finally:
        _teardown_runner(client, proc)


# ----------------------------------------------------------------------
# Swift runner (UniFFI, macOS-only)
# ----------------------------------------------------------------------


def _swift_runner_binary() -> Path | None:
    """Resolve the Swift runner binary.

    Preference order:
      1. $SCP_PARITY_SWIFT_RUNNER — explicit override, used by CI.
      2. swift build --configuration release output.
      3. swift build --configuration debug output.
    Returns None if no binary is found; causes `uniffi-swift` parity
    cases to be skipped.
    """
    env_path = os.environ.get("SCP_PARITY_SWIFT_RUNNER")
    if env_path:
        p = Path(env_path)
        if not p.exists():
            raise RuntimeError(
                f"$SCP_PARITY_SWIFT_RUNNER is set to '{env_path}' which does not exist"
            )
        return p
    for config in ("release", "debug"):
        candidate = SWIFT_RUNNER_DIR / ".build" / config / "swift-bridge-runner"
        if candidate.exists():
            return candidate
    return None


@pytest.fixture(scope="session")
def swift_runner() -> Iterator[RunnerClient]:
    """Spawn the long-lived Swift (UniFFI) bridge runner (macOS only)."""
    import sys

    if sys.platform != "darwin":
        pytest.skip(
            "Swift parity runner is macOS-only (UniFFI Swift binaries "
            "ship as an .xcframework targeting Apple platforms)."
        )
    binary = _swift_runner_binary()
    if binary is None:
        pytest.skip(
            "Swift parity runner not built. Set SCP_PARITY_SWIFT_RUNNER "
            "or run `swift build` under helpers/swift_bridge_runner/."
        )

    proc = _popen_runner(
        [str(binary)],
        cwd=SWIFT_RUNNER_DIR,
        env=_sanitized_env(),
    )
    client = RunnerClient(proc=proc)
    try:
        yield client
    finally:
        _teardown_runner(client, proc)


# ----------------------------------------------------------------------
# Per-test reset
# ----------------------------------------------------------------------


@pytest.fixture(autouse=True)
def parity_reset(request: pytest.FixtureRequest) -> None:
    """Reset the active parity runner's caches before each parity test.

    Runner fixtures are session-scoped for startup amortization, but
    runner module-level state accumulates across calls. Without a reset
    between tests, test order would affect outcomes and later tests
    could observe earlier tests' state.

    Only the runner fixture the current test has actually requested via
    its parameter list is reset — we do NOT force-start runners that
    aren't needed. The test file's `_PARITY_CASES` parametrize grid
    attaches a single runner fixture name per case, so this walks the
    test's own fixture closure rather than scanning all known runners.

    Only active for tests carrying the `parity` marker; other tests in
    the suite are unaffected.
    """
    if request.node.get_closest_marker("parity") is None:
        return
    runner_fixtures = {"bun_runner", "kotlin_runner", "swift_runner"}
    requested = set(request.fixturenames) & runner_fixtures
    for fixture_name in requested:
        runner = request.getfixturevalue(fixture_name)
        runner.reset()
