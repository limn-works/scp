"""Test doubles for the extension's native handle classes.

:class:`scp_sdk.Context` accepts only the extension's ``PyContextHandle`` and
:class:`scp_sdk.Identity` only its ``PyIdentity``. A ``MagicMock`` specced on
that class passes the ``isinstance`` check and raises on any attribute the
class does not define, so a unit test that builds a wrapper around a double
reads only attributes the real handle has.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from scp_sdk._extension import native_module


def native_context_handle(
    context_id: str = "ctx-test-abc123", state: str = "active", **attrs: Any
) -> MagicMock:
    """Return a ``PyContextHandle`` double carrying ``context_id`` and ``state``."""
    return MagicMock(
        spec=native_module().PyContextHandle, context_id=context_id, state=state, **attrs
    )


def native_identity(did: str = "did:dht:z6MkAlice", **attrs: Any) -> MagicMock:
    """Return a ``PyIdentity`` double carrying ``did``."""
    return MagicMock(spec=native_module().PyIdentity, did=did, **attrs)
