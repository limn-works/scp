"""Tests for the falsy-vs-`is not None` lint guard and the SDK call sites
that historically had the bug (H14 / M16).

The lint guard is `scripts/check-python-falsy-optionals.py`. This test
file verifies:

1. The guard exits 0 on the current tree (no regressions).
2. The guard exits 1 and points at the correct line when a known buggy
   pattern is reintroduced.
3. The `# falsy-ok:` exemption marker silences a flagged site.
4. `scp_sdk.ucan.mint` -- the historical falsy site -- correctly
   distinguishes empty proofs (`[]`) from absent proofs (`None`).

The lint guard tests use a temp file fed via the script's CLI rather
than mutating the real source tree.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
LINT_SCRIPT = REPO_ROOT / "scripts" / "check-python-falsy-optionals.py"


def _run_lint_against_tmp_sdk(
    tmp_path: Path, file_contents: str
) -> subprocess.CompletedProcess[str]:
    """Stage `file_contents` as a fake scp_sdk module and invoke the lint.

    The script resolves SDK_ROOT relative to its own location, so we
    create a copy of the script with a patched SDK_ROOT pointing at the
    tmp tree. This isolates the test from the real source tree.
    """
    fake_sdk = tmp_path / "bindings" / "python" / "scp_sdk"
    fake_sdk.mkdir(parents=True)
    (fake_sdk / "module_under_test.py").write_text(file_contents)

    fake_scripts = tmp_path / "scripts"
    fake_scripts.mkdir()
    fake_script = fake_scripts / "check-python-falsy-optionals.py"
    shutil.copy(LINT_SCRIPT, fake_script)
    return subprocess.run(
        [sys.executable, str(fake_script)],
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )


class TestLintGuardOnRepo:
    """The lint guard must pass on the current source tree."""

    def test_lint_passes_on_current_tree(self) -> None:
        result = subprocess.run(
            [sys.executable, str(LINT_SCRIPT)],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        assert result.returncode == 0, (
            f"Lint guard failed on current tree:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )


class TestLintGuardCatchesBugs:
    """The lint guard must flag every known falsy-bug shape."""

    def test_catches_if_else_on_bare_name(self, tmp_path: Path) -> None:
        contents = textwrap.dedent(
            """
            def f(x: list[int] | None = None) -> object:
                return x if x else None
            """
        )
        result = _run_lint_against_tmp_sdk(tmp_path, contents)
        assert result.returncode == 1
        assert "falsy IfExp on bare name `x`" in result.stderr

    def test_catches_or_with_empty_list(self, tmp_path: Path) -> None:
        contents = textwrap.dedent(
            """
            import json

            def f(items: list[int] | None = None) -> str:
                return json.dumps(items or [])
            """
        )
        result = _run_lint_against_tmp_sdk(tmp_path, contents)
        assert result.returncode == 1
        assert "falsy `or` on bare name `items`" in result.stderr

    def test_catches_or_with_empty_dict(self, tmp_path: Path) -> None:
        contents = textwrap.dedent(
            """
            def f(d: dict[str, int] | None = None) -> dict[str, int]:
                return d or {}
            """
        )
        result = _run_lint_against_tmp_sdk(tmp_path, contents)
        assert result.returncode == 1
        assert "falsy `or` on bare name `d`" in result.stderr

    def test_falsy_ok_marker_silences_violation(self, tmp_path: Path) -> None:
        contents = textwrap.dedent(
            """
            def f(d: dict[str, int] | None = None) -> dict[str, int]:
                return d or {}  # falsy-ok: empty and absent are equivalent here
            """
        )
        result = _run_lint_against_tmp_sdk(tmp_path, contents)
        assert result.returncode == 0, result.stderr

    def test_correct_form_passes(self, tmp_path: Path) -> None:
        contents = textwrap.dedent(
            """
            def f(d: dict[str, int] | None = None) -> dict[str, int]:
                return d if d is not None else {}
            """
        )
        result = _run_lint_against_tmp_sdk(tmp_path, contents)
        assert result.returncode == 0, result.stderr


def _make_mock_ucan_bridge() -> MagicMock:
    bridge = MagicMock()
    token = MagicMock()
    token.token_id = "fake-token-id"
    token.issuer = "did:dht:zAlice"
    token.audience = "did:dht:zBob"
    token.expires_at = None
    token.capabilities = ["messages:read"]
    token.proofs = []
    bridge.ucan_mint.return_value = token
    return bridge


class TestUcanMintProofsFalsy:
    """H14: :meth:`SCP.ucan_mint` must distinguish empty proofs from ``None``.

    Phase 4 PR 5 Agent B+C (#1549) moved the ``mint`` free function from
    :mod:`scp_sdk.ucan` onto :meth:`SCP.ucan_mint`. The SDK must still
    forward an empty list verbatim so the bridge sees ``[]`` (declares
    "no proofs") rather than ``None`` (declares "proofs not specified").

    These tests are ``async def`` so pytest-asyncio (auto mode) drives
    them on its own event loop. Do NOT use ``asyncio.run()`` here — it
    would close the running loop and break sibling tests.
    """

    async def test_empty_proofs_passes_empty_list(self) -> None:
        from scp_sdk.scp import SCP

        bridge = _make_mock_ucan_bridge()
        scp = MagicMock()
        scp._native = bridge

        await SCP.ucan_mint(
            scp,
            "ctx-1",
            "did:dht:zBob",
            ["messages:read"],
            [],
        )

        # Positional args to ucan_mint: context, audience, capabilities, proofs
        call_args = bridge.ucan_mint.call_args[0]
        assert call_args[3] == [], f"empty proofs must be passed as `[]`, got {call_args[3]!r}"

    async def test_none_proofs_passes_none(self) -> None:
        from scp_sdk.scp import SCP

        bridge = _make_mock_ucan_bridge()
        scp = MagicMock()
        scp._native = bridge

        await SCP.ucan_mint(
            scp,
            "ctx-1",
            "did:dht:zBob",
            ["messages:read"],
            None,
        )

        call_args = bridge.ucan_mint.call_args[0]
        assert call_args[3] is None

    async def test_populated_proofs_passes_list(self) -> None:
        from scp_sdk.scp import SCP

        bridge = _make_mock_ucan_bridge()
        scp = MagicMock()
        scp._native = bridge

        await SCP.ucan_mint(
            scp,
            "ctx-1",
            "did:dht:zBob",
            ["messages:read"],
            ["parent-token-cid-1", "parent-token-cid-2"],
        )

        call_args = bridge.ucan_mint.call_args[0]
        assert call_args[3] == ["parent-token-cid-1", "parent-token-cid-2"]


@pytest.mark.parametrize("_unused", [None])  # keep mypy happy with file-level pytest import
def test_module_imports(_unused: object) -> None:
    """Sanity check: this test module imports cleanly."""
    assert LINT_SCRIPT.exists(), f"Lint script missing: {LINT_SCRIPT}"
