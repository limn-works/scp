"""Test-harness custody: the in-memory key store, which the SDK cannot name.

Spec 03 section 3.2.2 states that an SDK's custody type carries
``encrypted_file`` and ``os_keystore`` and no other member, and that
``in_memory`` is a testing-build affordance, "never a peer of the two request
values". :class:`scp_sdk.types.CustodyType` therefore has no in-memory member,
and these helpers pass the raw string to the PyO3 bridge instead of going
through :meth:`scp_sdk.SCP.identity_create`.

Only a bridge built with the ``testing`` cargo feature
(``maturin develop --features testing``) accepts the string. A bridge built
without it answers ``SCP-IDENT-1008`` and builds nothing, so a test that calls
these helpers fails on a shipped build instead of reaching a weaker backend.

This module sits under ``tests/``, which no wheel packages, and
``scp_sdk`` neither imports nor re-exports it.
"""

from __future__ import annotations

import asyncio
from typing import Any

from scp_sdk import SCP
from scp_sdk.identity import Identity

#: The raw custody string a ``testing`` bridge build accepts for the in-memory
#: key store (spec 03 section 3.2.2).
IN_MEMORY_CUSTODY = "in_memory"


def create_in_memory_native_identity(native: Any, seed: bytes | None = None) -> Any:
    """Create an in-memory identity on a raw ``_scp_core.SCP`` and return its
    native ``PyIdentity`` handle.

    For a synchronous fixture that holds the native instance, not an
    :class:`scp_sdk.SCP`.  ``seed`` is the ADR-046 cross-bridge parity seed;
    ``None`` lets the in-memory backend draw its keys from the OS RNG.
    """
    if seed is None:
        return native.identity_create(IN_MEMORY_CUSTODY)
    return native.identity_create(IN_MEMORY_CUSTODY, seed)


async def create_in_memory_identity(scp: SCP, seed: bytes | None = None) -> Identity:
    """Create an identity whose keys live in the test-only in-memory key store.

    ``seed`` is the ADR-046 cross-bridge parity seed; ``None`` lets the
    in-memory backend draw its keys from the OS RNG.
    """
    raw = await asyncio.to_thread(create_in_memory_native_identity, scp._native, seed)
    return Identity(raw)


async def create_in_memory_identity_with_agent_key(scp: SCP) -> Identity:
    """Create an identity carrying an ``#agent`` signing key (ADR-039) in the
    test-only in-memory key store.
    """
    raw = await asyncio.to_thread(scp._native.identity_create_with_agent_key, IN_MEMORY_CUSTODY)
    return Identity(raw)
