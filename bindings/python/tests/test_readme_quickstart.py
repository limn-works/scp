"""Runs the quick start in ``bindings/python/README.md``.

The ``quickstart_script`` fixture reads the first ``python`` code block under
the README's ``## Quick Start`` heading and writes it, unchanged, to a scratch
file. The test runs that file in a child interpreter, so an edit that leaves
the README block unable to run fails here. The child process is the reader's
shell: the block ends in ``asyncio.run(main())``, which cannot run inside the
event loop pytest-asyncio owns.

The block uses ``CustodyType.IN_MEMORY``, which only a ``testing`` build
accepts; every SDK test run builds the extension with that feature.
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
_HEADING = "\n## Quick Start\n"
_FENCE_OPEN = "```python\n"
_FENCE_CLOSE = "\n```\n"


def extract_quickstart(readme_text: str) -> str:
    """Return the first ``python`` block after the Quick Start heading.

    Raises ``AssertionError`` when the README has no such heading or block, so a
    README that drops the quick start fails the test instead of running nothing.
    """
    assert _HEADING in readme_text, "the README has no '## Quick Start' heading"
    after_heading = readme_text.split(_HEADING, 1)[1]
    assert _FENCE_OPEN in after_heading, "the Quick Start section has no python block"
    body = after_heading.split(_FENCE_OPEN, 1)[1]
    assert _FENCE_CLOSE in body, "the Quick Start python block has no closing fence"
    return body.split(_FENCE_CLOSE, 1)[0] + "\n"


@pytest.fixture
def quickstart_script(tmp_path: Path) -> Path:
    """Write the README's Quick Start block to ``tmp_path`` and return its path."""
    script = tmp_path / "readme_quickstart.py"
    script.write_text(extract_quickstart(_README.read_text()))
    return script


def test_extract_quickstart_reads_the_block_under_the_heading() -> None:
    """The extractor returns the python block under the heading, not an earlier one."""
    text = (
        "# T\n\n```python\nprint('before')\n```\n\n"
        "## Quick Start\n\nProse.\n\n```python\nprint('quick')\n```\n\n"
        "```python\nprint('after')\n```\n"
    )
    assert extract_quickstart(text) == "print('quick')\n"


def test_readme_quickstart_runs(quickstart_script: Path) -> None:
    """The README block exits 0 and prints the DID and context it created."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(_PACKAGE_ROOT), *filter(None, [env.get("PYTHONPATH")])]
    )
    result = subprocess.run(
        [sys.executable, str(quickstart_script)],
        capture_output=True,
        text=True,
        env=env,
        cwd=quickstart_script.parent,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, f"the README quick start failed:\n{result.stderr}"
    assert "DID: did:" in result.stdout, f"no DID in output: {result.stdout!r}"
    assert "Context: " in result.stdout, f"no context in output: {result.stdout!r}"
    assert "(active)" in result.stdout, f"the context is not active: {result.stdout!r}"
