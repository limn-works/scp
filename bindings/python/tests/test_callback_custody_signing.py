"""Callback-custody signing through the PyO3 bridge (ADR-049 Decision 7a).

Governance signs through the identity's custody, so a Python provider's
``sign`` runs while the bridge waits on the context actor. These tests prove
the wait releases the GIL: a Python ``sign`` completes, and a second thread's
non-signing call proceeds while the first thread's ``sign`` sleeps. If the
bridge held the GIL while waiting, the second thread's call would block the
first thread's callback, and the proposal would fail at the 30-second signing
budget with ``SCP-CRYPTO-4061``.

Requires the native extension built with ``testing``::

    maturin develop --release --features testing
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from typing import Any

import pytest

from tests.conftest import skip_reason_if_extension_absent

try:
    from scp_sdk import _scp_core  # noqa: F401
except Exception as _exc:
    pytest.skip(skip_reason_if_extension_absent(_exc), allow_module_level=True)

from tests.test_identity_create_with_custody import _FakeKeychain

_GOVERNANCE_PARAMS = {
    "ceiling": ["governance:propose", "member:ban", "messages:read", "messages:write"],
    "memory_scope": "ephemeral",
    "governance": "single_admin",
}

# Every bridge call must finish well inside the 30-second signing budget.
_DEADLINE_S = 10.0


class _SlowSignKeychain(_FakeKeychain):
    """A keychain whose ``sign`` announces itself, then sleeps in Python.

    ``armed`` is set by the test just before the call under test, so the
    signs made while creating the identity and context do not trip it.
    """

    def __init__(self) -> None:
        super().__init__()
        self.armed = False
        self.signing = threading.Event()
        self.sign_calls = 0

    def sign(self, key_id: str, message: bytes) -> bytes:
        self.sign_calls += 1
        if self.armed:
            self.signing.set()
            time.sleep(0.2)
        return super().sign(key_id, message)


def _suspend_action(did: str) -> str:
    return json.dumps({"SuspendCapability": {"did": did, "capabilities": ["MessagesWrite"]}})


def _as_dict(response: Any) -> dict[str, Any]:
    return json.loads(response) if isinstance(response, str) else dict(response)


async def _owner_and_context(scp, provider: _FakeKeychain):  # type: ignore[no-untyped-def]
    identity = await scp.identity_create_with_custody(provider)
    ctx = await scp.context_create(identity.did, _GOVERNANCE_PARAMS)
    return identity, ctx


@pytest.mark.asyncio
async def test_governance_propose_signs_through_a_python_provider(scp) -> None:
    """A provider whose ``sign`` runs in Python signs a proposal within the
    deadline, and the single-admin proposal executes."""
    provider = _SlowSignKeychain()
    identity, ctx = await _owner_and_context(scp, provider)
    before = provider.sign_calls

    response = _as_dict(
        await asyncio.wait_for(
            scp.governance_propose(ctx, identity.did, _suspend_action(identity.did)),
            timeout=_DEADLINE_S,
        )
    )

    assert response["status"] == "Approved", response
    assert provider.sign_calls > before, "the proposal never reached the provider's sign"


# A lone member's send into an encrypted context addresses no one and signs
# nothing (§9.10.4), so the send test uses a broadcast context, where every
# send carries a signed broadcast envelope. The loopback transport delivers the
# envelope without a relay.
_BROADCAST_PARAMS = {
    "ceiling": ["messages:read", "messages:write"],
    "memory_scope": "full",
    "mode": "broadcast",
}


@pytest.mark.asyncio
async def test_context_send_signs_through_a_python_provider(scp) -> None:
    """A provider whose ``sign`` runs in Python signs a broadcast send's
    envelope within the deadline."""
    provider = _SlowSignKeychain()
    identity = await scp.identity_create_with_custody(provider)
    await scp.configure_local_transport(identity.did)
    ctx = await scp.context_create(identity.did, _BROADCAST_PARAMS)
    before = provider.sign_calls

    await asyncio.wait_for(
        scp.context_send(ctx, identity.did, b"python-signed send"),
        timeout=_DEADLINE_S,
    )

    assert provider.sign_calls > before, "the send never reached the provider's sign"


@pytest.mark.asyncio
async def test_broadcast_publish_signs_through_a_python_provider(scp) -> None:
    """A broadcast publish signs its envelope inside the actor turn through
    the provider's ``sign`` (ADR-049 Decision 7a), within the deadline."""
    provider = _SlowSignKeychain()
    identity = await scp.identity_create_with_custody(provider)
    await scp.configure_local_transport(identity.did)
    ctx = await scp.context_create(identity.did, _BROADCAST_PARAMS)
    before = provider.sign_calls

    await asyncio.wait_for(
        scp.broadcast_publish(ctx, identity.did, b"python-signed publish"),
        timeout=_DEADLINE_S,
    )

    assert provider.sign_calls > before, "the publish never reached the provider's sign"


@pytest.mark.asyncio
async def test_trust_create_challenge_signs_through_a_python_provider(scp) -> None:
    """A challenge request is signed through the verifier's provider, whose
    ``sign`` runs in Python, within the deadline (spec 07 §7.3.4)."""
    from scp_sdk.trust import ExactMatch, TestCase

    provider = _SlowSignKeychain()
    verifier = await scp.identity_create_with_custody(provider)
    # Not a second _FakeKeychain: its seeds derive from the key id, so it
    # would mint the verifier's DID and replace the verifier's registry entry.
    subject = await scp.identity_create("in_memory")
    assert subject.did != verifier.did
    cases = [
        TestCase(
            test_id=f"t{i}",
            input={"i": i},
            expected=ExactMatch(value=True),
            category="basic",
            weight=500,
        )
        for i in range(20)
    ]
    provider.armed = True
    before = provider.sign_calls

    result = await asyncio.wait_for(
        scp.trust_create_challenge(
            verifier.did, subject.did, "scp:capability:schema-validation/v1", cases
        ),
        timeout=_DEADLINE_S,
    )

    assert provider.sign_calls > before, "the request never reached the provider's sign"
    assert provider.signing.is_set()
    assert json.loads(result["challenge_json"])["verifier"] == verifier.did


@pytest.mark.asyncio
async def test_non_signing_call_proceeds_while_another_thread_signs(scp) -> None:
    """Thread A proposes; its ``sign`` sleeps in Python. Thread B, started once
    A is inside ``sign``, reads the member count. Both finish within the
    deadline, and A's proposal exists."""
    provider = _SlowSignKeychain()
    identity, ctx = await _owner_and_context(scp, provider)
    provider.armed = True

    results: dict[str, Any] = {}
    errors: dict[str, BaseException] = {}

    def thread_a() -> None:
        try:
            results["a"] = asyncio.run(
                scp.governance_propose(ctx, identity.did, _suspend_action(identity.did))
            )
        except BaseException as exc:
            errors["a"] = exc

    def thread_b() -> None:
        try:
            if not provider.signing.wait(timeout=_DEADLINE_S):
                raise AssertionError("thread A never entered the provider's sign")
            results["b"] = asyncio.run(scp.context_member_count(ctx))
        except BaseException as exc:
            errors["b"] = exc

    a = threading.Thread(target=thread_a, name="propose")
    b = threading.Thread(target=thread_b, name="member-count")
    a.start()
    b.start()
    a.join(timeout=_DEADLINE_S)
    b.join(timeout=_DEADLINE_S)

    assert not a.is_alive(), "governance_propose did not finish: the bridge held the GIL"
    assert not b.is_alive(), "context_member_count did not finish while A signed"
    assert not errors, errors
    assert results["b"] == 1, results
    proposal = _as_dict(results["a"])
    assert proposal["status"] == "Approved", proposal
    assert proposal["proposal_id"], proposal
