"""Test-harness custody: reaching the in-memory key store the SDK cannot name.

Section 3.2.2 of the identity spec, "The Custody Vocabulary", states that a
caller names one of two backends, ``"encrypted_file"`` and ``"os_keystore"``,
and that the vocabulary "holds no third value". It states separately that a
build carrying the bridge's ``testing`` cargo feature "additionally accepts the
string ``in_memory`` at the bridge, which reaches that test-only backend", that
the string "is a test-harness affordance and not a value of this vocabulary",
and that "no SDK enum spells it, a test that needs it passes the raw string to
the bridge".

:meth:`scp_sdk.SCP.identity_create` therefore takes a
:class:`scp_sdk.types.CustodyType`, which spells only the two vocabulary
values, and the helpers below reach the PyO3 bridge directly with the raw
string. Each one wraps the handle the bridge returns the same way the SDK
method does, so a test reads an :class:`scp_sdk.identity.Identity` either way.
"""

from __future__ import annotations

import asyncio
from typing import Any

from scp_sdk.identity import Identity

#: The raw custody string a ``testing`` build accepts for the in-memory key
#: store. A build without that cargo feature answers it with
#: ``SCP-IDENT-1008`` and builds nothing.
TEST_HARNESS_CUSTODY = "in_memory"


async def create_in_memory_identity(scp: Any, seed: bytes | None = None) -> Identity:
    """Create an identity whose keys live in the test-only in-memory key store.

    ``seed`` is the ADR-046 cross-bridge parity seed; pass ``None`` to let the
    in-memory backend draw from the OS RNG.
    """
    args = (TEST_HARNESS_CUSTODY,) if seed is None else (TEST_HARNESS_CUSTODY, seed)
    raw = await asyncio.to_thread(scp._native.identity_create, *args)
    return Identity(raw)


async def create_in_memory_identity_with_agent_key(scp: Any) -> Identity:
    """Create an identity carrying an ``#agent`` signing key (ADR-039, the
    shared-DID agent binding) in the test-only in-memory key store.
    """
    raw = await asyncio.to_thread(scp._native.identity_create_with_agent_key, TEST_HARNESS_CUSTODY)
    return Identity(raw)
