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

from scp_sdk import _scp_core
from scp_sdk.errors import IdentityError, ValidationError
from scp_sdk.scp import CUSTODY_REQUIRED_CODE, SCP
from scp_sdk.types import CustodyType
from tests._native_doubles import native_identity
from tests.harness_custody import create_in_memory_identity

METHODS = ("identity_create", "identity_create_with_agent_key", "identity_create_with_custody")

#: The remedy each method's SCP-IDENT-1116 message must open with: the
#: argument that method takes, never the other method's argument.
REMEDIES = {
    "identity_create": "pass CustodyType.ENCRYPTED_FILE",
    "identity_create_with_agent_key": "pass CustodyType.ENCRYPTED_FILE",
    "identity_create_with_custody": "pass a KeyCustodyProvider",
}
SDK_ROOT = Path(__file__).resolve().parents[1]


def _scp_with_mock_native() -> tuple[SCP, MagicMock]:
    scp = SCP.__new__(SCP)
    native = MagicMock()
    # The factories wrap the bridge's return in Identity, which accepts only a
    # PyIdentity, so the mocked bridge returns a PyIdentity double.
    native.identity_create.return_value = native_identity()
    native.identity_create_with_agent_key.return_value = native_identity()
    scp._native = native
    return scp, native


def test_code_is_ident_1116() -> None:
    assert CUSTODY_REQUIRED_CODE == "SCP-IDENT-1116"


def test_custody_type_carries_the_two_request_values_and_nothing_else() -> None:
    # Spec 03 section 3.2.2: an SDK's custody type carries encrypted_file and
    # os_keystore and no other member; the testing-build affordance in_memory
    # stays outside it.
    assert {member.value for member in CustodyType} == {"encrypted_file", "os_keystore"}
    assert CustodyType.ENCRYPTED_FILE.value == "encrypted_file"
    assert CustodyType.OS_KEYSTORE.value == "os_keystore"


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
    [
        (CustodyType.ENCRYPTED_FILE, "encrypted_file"),
        (CustodyType.OS_KEYSTORE, "os_keystore"),
        ("encrypted_file", "encrypted_file"),
    ],
)
async def test_named_custody_reaches_the_bridge(method: str, custody: object, sent: str) -> None:
    scp, native = _scp_with_mock_native()

    await getattr(scp, method)(custody)

    getattr(native, method).assert_called_once_with(sent)


@pytest.mark.asyncio
async def test_custody_keyword_is_accepted() -> None:
    scp, native = _scp_with_mock_native()

    await scp.identity_create(custody=CustodyType.ENCRYPTED_FILE)

    native.identity_create.assert_called_once_with("encrypted_file")


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
                await scp.identity_create(CustodyType.ENCRYPTED_FILE)
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


# ---------------------------------------------------------------------------
# The request vocabulary against the real bridge (spec 03 section 3.2.2). The
# suite runs against a build carrying the bridge's testing feature. Identity
# creation propagates the bridge's native exceptions unchanged, so these tests
# assert the native class and the code that opens its message.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["identity_create", "identity_create_with_agent_key"])
async def test_encrypted_file_creates_an_identity_reporting_encrypted_file(
    scp: SCP, method: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("SCP_KEY_PASSPHRASE", "custody-vocabulary-test-passphrase")

    identity = await getattr(scp, method)(CustodyType.ENCRYPTED_FILE)

    assert identity.custody_type is CustodyType.ENCRYPTED_FILE
    assert (tmp_path / ".scp" / "keys.bin").exists()


@pytest.mark.asyncio
async def test_in_memory_harness_creates_an_identity_reporting_the_raw_string(scp: SCP) -> None:
    # No CustodyType member names in_memory, so Identity.custody_type returns
    # the raw string the testing bridge reports.
    identity = await create_in_memory_identity(scp)

    assert identity.custody_type == "in_memory"


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["identity_create", "identity_create_with_agent_key"])
async def test_encrypted_file_without_a_passphrase_raises_valid_7001(
    scp: SCP, method: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("SCP_KEY_PASSPHRASE", raising=False)

    with pytest.raises(_scp_core.ValidationError, match=r"^\[SCP-VALID-7001\] ") as excinfo:
        await getattr(scp, method)(CustodyType.ENCRYPTED_FILE)

    assert "SCP_KEY_PASSPHRASE" in str(excinfo.value)
    assert not (tmp_path / ".scp").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["identity_create", "identity_create_with_agent_key"])
async def test_os_keystore_without_a_provider_raises_ident_1003(scp: SCP, method: str) -> None:
    with pytest.raises(_scp_core.IdentityError, match=r"^\[SCP-IDENT-1003\] ") as excinfo:
        await getattr(scp, method)(CustodyType.OS_KEYSTORE)

    assert "identity_create_with_custody" in str(excinfo.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["identity_create", "identity_create_with_agent_key"])
@pytest.mark.parametrize("custody", ["platform", "software", "file", "callback", "keychain"])
async def test_a_string_outside_the_vocabulary_raises_valid_7005(
    scp: SCP, method: str, custody: str
) -> None:
    with pytest.raises(_scp_core.ValidationError, match=r"^\[SCP-VALID-7005\] ") as excinfo:
        await getattr(scp, method)(custody)

    assert '"encrypted_file"' in str(excinfo.value)
    assert '"os_keystore"' in str(excinfo.value)


@pytest.mark.parametrize("custody", ["encrypted_file", "os_keystore", "platform"])
def test_a_seed_without_in_memory_raises_valid_7009_before_the_request_is_read(
    scp: SCP, custody: str
) -> None:
    # The SDK takes no seed, so the raw bridge carries this row of the table.
    with pytest.raises(_scp_core.ValidationError, match=r"^\[SCP-VALID-7009\] "):
        scp._native.identity_create(custody, bytes(32))


@pytest.mark.asyncio
@pytest.mark.parametrize("call", ["positional", "keyword"])
async def test_load_with_custody_given_none_raises_ident_1116_before_any_bridge_call(
    call: str,
) -> None:
    scp, native = _scp_with_mock_native()

    with pytest.raises(IdentityError) as excinfo:
        if call == "positional":
            await scp.identity_load_with_custody("did:dht:z6MkLoadNeedsProvider", None)  # type: ignore[arg-type]
        else:
            await scp.identity_load_with_custody(
                did="did:dht:z6MkLoadNeedsProvider",
                provider=None,  # type: ignore[arg-type]
            )

    assert excinfo.value.code == "SCP-IDENT-1116"
    assert excinfo.value.message.startswith(
        "identity_load_with_custody() requires a custody argument"
    )
    assert "store: pass a KeyCustodyProvider" in excinfo.value.message
    native.identity_load_with_custody.assert_not_called()
