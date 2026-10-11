"""Every identity-creating ``SCP`` method takes custody as a required argument
and names no default key store (SCP-294).

A type checker rejects the omission; an untyped caller that passes nothing or
``None`` gets an ``IdentityError`` carrying ``SCP-IDENT-1116`` before any bridge
call.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from scp_sdk.errors import IdentityError, ValidationError
from scp_sdk.scp import CUSTODY_REQUIRED_CODE, SCP
from scp_sdk.types import CustodyType

METHODS = ("identity_create", "identity_create_with_agent_key", "identity_create_with_custody")

#: The remedy each method's SCP-IDENT-1116 message must open with: the
#: argument that method takes, never the other method's argument.
REMEDIES = {
    "identity_create": "pass CustodyType.FILE",
    "identity_create_with_agent_key": "pass CustodyType.FILE",
    "identity_create_with_custody": "pass a KeyCustodyProvider",
}
SDK_ROOT = Path(__file__).resolve().parents[1]


def _scp_with_mock_native() -> tuple[SCP, MagicMock]:
    scp = SCP.__new__(SCP)
    native = MagicMock()
    scp._native = native
    return scp, native


def test_code_is_ident_1116() -> None:
    assert CUSTODY_REQUIRED_CODE == "SCP-IDENT-1116"


def test_custody_type_carries_exactly_the_pyo3_bridge_strings() -> None:
    assert {member.value for member in CustodyType} == {"file", "in_memory"}


@pytest.mark.asyncio
@pytest.mark.parametrize("method", METHODS)
@pytest.mark.parametrize("args", [(), (None,)], ids=["nothing", "None"])
async def test_absent_custody_raises_ident_1116_before_any_bridge_call(
    method: str, args: tuple[object, ...]
) -> None:
    scp, native = _scp_with_mock_native()

    with pytest.raises(IdentityError) as excinfo:
        await getattr(scp, method)(*args)

    assert excinfo.value.code == "SCP-IDENT-1116"
    message = excinfo.value.message
    assert message.startswith(f"{method}() requires a custody argument")
    assert f"store: {REMEDIES[method]}" in message
    for other in set(REMEDIES.values()) - {REMEDIES[method]}:
        assert other not in message
    getattr(native, method).assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["identity_create", "identity_create_with_agent_key"])
async def test_non_string_custody_raises_valid_7005_before_any_bridge_call(method: str) -> None:
    scp, native = _scp_with_mock_native()

    with pytest.raises(ValidationError) as excinfo:
        await getattr(scp, method)(42)

    assert excinfo.value.code == "SCP-VALID-7005"
    getattr(native, method).assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["identity_create", "identity_create_with_agent_key"])
@pytest.mark.parametrize(
    ("custody", "sent"),
    [(CustodyType.FILE, "file"), (CustodyType.IN_MEMORY, "in_memory"), ("file", "file")],
)
async def test_named_custody_reaches_the_bridge(method: str, custody: object, sent: str) -> None:
    scp, native = _scp_with_mock_native()

    await getattr(scp, method)(custody)

    getattr(native, method).assert_called_once_with(sent)


@pytest.mark.asyncio
async def test_custody_keyword_is_accepted() -> None:
    scp, native = _scp_with_mock_native()

    await scp.identity_create(custody=CustodyType.FILE)

    native.identity_create.assert_called_once_with("file")


def test_mypy_rejects_an_omitted_custody(tmp_path: Path) -> None:
    # mypy is a dev dependency (pyproject `dev` extra) and job python-test installs
    # it, so a missing mypy fails this test rather than skipping it.
    probe = tmp_path / "probe.py"
    probe.write_text(
        textwrap.dedent(
            """
            from scp_sdk.scp import SCP
            from scp_sdk.types import CustodyType

            async def f(scp: SCP) -> None:
                await scp.identity_create(CustodyType.FILE)
                await scp.identity_create()
                await scp.identity_create_with_agent_key()
            """
        )
    )
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "mypy",
            "--no-incremental",
            "--follow-imports=silent",
            "--ignore-missing-imports",
            str(probe),
        ],
        capture_output=True,
        text=True,
        cwd=SDK_ROOT,
    )
    needle = 'Missing positional argument "custody"'
    missing = [line for line in result.stdout.splitlines() if needle in line]
    assert len(missing) == 2, result.stdout + result.stderr
