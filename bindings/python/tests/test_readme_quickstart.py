"""Runs the code examples in ``bindings/python/README.md``.

``extract_block`` reads the first ``python`` code block under a README heading.
Each test writes the block for one heading, unchanged, to a scratch file and
runs that file in a child interpreter, so an edit that leaves a README block
unable to run fails here. The child process is the reader's shell: each block
ends in ``asyncio.run(main())``, which cannot run inside the event loop
pytest-asyncio owns.

Every SDK test run builds the extension with the ``testing`` feature. The
quick start uses ``CustodyType.ENCRYPTED_FILE``, so the child runs with
``HOME`` set to the test's scratch directory and ``SCP_KEY_PASSPHRASE`` set,
and the key file lands there.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import skip_reason_if_extension_absent

try:
    from scp_sdk import _scp_core  # noqa: F401 — confirms the native module loads
except Exception as _exc:
    pytest.skip(skip_reason_if_extension_absent(_exc), allow_module_level=True)

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent
_README = _PACKAGE_ROOT / "README.md"
_QUICK_START = "Quick Start"
_ERROR_HANDLING = "Error Handling"
_FENCE_OPEN = "```python\n"
_FENCE_CLOSE = "\n```\n"


def extract_block(readme_text: str, heading: str) -> str:
    """Return the first ``python`` block after the ``## {heading}`` line.

    Raises ``AssertionError`` when the README has no such heading or block, so a
    README that drops the example fails the test instead of running nothing.
    """
    marker = f"\n## {heading}\n"
    assert marker in readme_text, f"the README has no '## {heading}' heading"
    after_heading = readme_text.split(marker, 1)[1]
    assert _FENCE_OPEN in after_heading, f"the {heading} section has no python block"
    body = after_heading.split(_FENCE_OPEN, 1)[1]
    assert _FENCE_CLOSE in body, f"the {heading} python block has no closing fence"
    return body.split(_FENCE_CLOSE, 1)[0] + "\n"


def run_readme_block(heading: str, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    """Run the README block under ``heading`` in a child interpreter."""
    script = tmp_path / "readme_block.py"
    script.write_text(extract_block(_README.read_text(), heading))
    env = dict(os.environ)
    env["HOME"] = str(tmp_path)
    env["SCP_KEY_PASSPHRASE"] = "readme-quickstart-test-passphrase"
    env["PYTHONPATH"] = os.pathsep.join(
        [str(_PACKAGE_ROOT), *filter(None, [env.get("PYTHONPATH")])]
    )
    return subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
        timeout=120,
        check=False,
    )


def test_extract_block_reads_the_block_under_the_heading() -> None:
    """The extractor returns the python block under the heading, not an earlier one."""
    text = (
        "# T\n\n```python\nprint('before')\n```\n\n"
        "### Quick Start\n\n```python\nprint('h3')\n```\n\n"
        "## Quick Start\n\nProse.\n\n```python\nprint('quick')\n```\n\n"
        "```python\nprint('after')\n```\n"
    )
    assert extract_block(text, _QUICK_START) == "print('quick')\n"


def test_readme_quickstart_runs(tmp_path: Path) -> None:
    """The Quick Start block exits 0 and prints the DID and context it created."""
    result = run_readme_block(_QUICK_START, tmp_path)
    assert result.returncode == 0, f"the README quick start failed:\n{result.stderr}"
    assert "DID: did:" in result.stdout, f"no DID in output: {result.stdout!r}"
    assert "Context: " in result.stdout, f"no context in output: {result.stdout!r}"
    assert "(active)" in result.stdout, f"the context is not active: {result.stdout!r}"
    assert (tmp_path / ".scp" / "keys.bin").is_file(), "the encrypted key file was not written"


def test_readme_error_handling_catches_the_typed_error(tmp_path: Path) -> None:
    """The Error Handling block exits 0 after its ``except`` clause caught the error.

    The printed code proves the ``except IdentityError`` clause ran: had
    ``identity_create`` raised anything else, the child would exit non-zero.
    """
    result = run_readme_block(_ERROR_HANDLING, tmp_path)
    assert result.returncode == 0, f"the README error example failed:\n{result.stderr}"
    assert result.stdout.startswith("[SCP-IDENT-1116] "), (
        f"the except clause did not run: {result.stdout!r}"
    )
