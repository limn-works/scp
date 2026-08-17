"""Runs the quick start from ``bindings/python/README.md`` end to end.

``fixtures/readme_quickstart.py`` holds the README block verbatim. This test
runs it as its own process with ``SCP_KEY_PASSPHRASE`` and a scratch ``HOME``
set, which is what a reader does from a shell — and what the README's own
``export`` line tells them to do. Running it in-process would not do: the Rust
side reads the native process environment, and ``HOME`` decides where the
encrypted key file lands, so this must not write into a developer's own
``~/.scp``.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("_scp_core", reason="native extension not built")

_FIXTURE = Path(__file__).parent / "fixtures" / "readme_quickstart.py"


def test_readme_quickstart_runs_end_to_end(tmp_path: Path) -> None:
    """The README block exits 0 and prints a DID."""
    env = dict(os.environ)
    env["HOME"] = str(tmp_path)
    env["SCP_KEY_PASSPHRASE"] = "quickstart-passphrase"

    result = subprocess.run(
        [sys.executable, str(_FIXTURE)],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, f"the README quick start must run end to end:\n{result.stderr}"
    assert "DID: did:" in result.stdout, (
        f"the README quick start must print a DID, got: {result.stdout!r}"
    )
