"""SCP full-stack test-network node handle.

:meth:`scp_sdk.SCP.fullstack_create_node` returns a :class:`FullStackNode`,
and every other ``SCP.fullstack_*`` method takes one. The node lives on the
in-process full-stack network that the bridge keeps for end-to-end MLS
tests; it is not an SCP :class:`~scp_sdk.server.Node` server.
"""

from __future__ import annotations

from typing import Any


class FullStackNode:
    """Opaque handle to a node on the bridge's in-process full-stack network.

    Construct via :meth:`scp_sdk.SCP.fullstack_create_node`. Pass the
    object itself to the ``SCP.fullstack_*`` methods.
    """

    __slots__ = ("_raw_handle",)

    def __init__(self, handle: Any) -> None:
        self._raw_handle = handle

    @property
    def did(self) -> str:
        """The DID the node was created for."""
        return self._raw_handle.did  # type: ignore[no-any-return]

    def __repr__(self) -> str:
        return f"FullStackNode(did={self.did!r})"
