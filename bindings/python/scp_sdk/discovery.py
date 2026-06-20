"""Discovery operations for the SCP Python SDK.

Provides functions for parsing SCP addresses, creating discovery queries,
normalizing addresses, and discovering contexts from DIDs or ``scp://`` URIs.

All operations delegate to the ``_scp_core`` PyO3 bridge layer.

See ADR-020 in ``.docs/adrs/phase-4.md`` and spec section 22 (Addressing).
"""

from __future__ import annotations

from typing import Any

from scp_sdk.errors import ScpError


def _bridge() -> Any:
    """Return the ``_scp_core`` extension module, imported lazily.

    Used for pure discovery helpers (``discovery_parse_address``,
    ``discovery_create_query``, ``discovery_normalize_address``,
    ``context_discover``) that do not require an :class:`SCP` instance.
    Stateful operations (petname, handle, scope, address_resolve)
    take an explicit :class:`scp_sdk.SCP` and dispatch on its
    ``_native`` handle.
    """
    try:
        import _scp_core  # type: ignore[import-not-found]

        return _scp_core
    except ImportError as exc:
        raise ScpError(
            "The _scp_core extension module is not installed. "
            "Install scp-python with: pip install scp-python",
            code="SCP-UNKNOWN-0001",
        ) from exc


def parse_address(address: str) -> dict[str, Any]:
    """Parse an SCP address string into its components.

    Returns a dict with ``type`` (one of ``"DiscoveryHandle"``,
    ``"DomainHandle"``, ``"AttestationHandle"``, ``"Unscoped"``)
    and type-specific fields.

    Args:
        address: The address string to parse
            (e.g., ``"alice@cooking-community"``).

    Returns:
        A dict with address type and fields.

    Raises:
        ValidationError: If the address is malformed.
    """
    bridge = _bridge()
    result = bridge.discovery_parse_address(address)
    if isinstance(result, str):
        import json

        return json.loads(result)
    return dict(result)


def create_query(
    *,
    capabilities: list[str] | None = None,
    keywords: list[str] | None = None,
    min_history_secs: int | None = None,
) -> str:
    """Create a discovery query as a JSON string.

    Args:
        capabilities: Optional list of capability strings to filter by.
        keywords: Optional list of keywords for free-text search.
        min_history_secs: Optional minimum participation history in seconds.

    Returns:
        A JSON string representing the discovery query.
    """
    bridge = _bridge()
    return bridge.discovery_create_query(capabilities, keywords, min_history_secs)


def normalize_address(address: str) -> str:
    """Normalize an address string per SCP addressing rules.

    Lowercases and trims whitespace.

    Args:
        address: The address string to normalize.

    Returns:
        The normalized address string.
    """
    bridge = _bridge()
    return bridge.discovery_normalize_address(address)


async def discover_contexts(_scp: Any, query: str) -> list[dict[str, Any]]:
    """Discover contexts advertised by a DID or named by an ``scp://`` URI.

    For a ``did:`` query the bridge resolves the DID document and projects its
    advertised contexts, which may involve network (DHT) resolution. For an
    ``scp://`` URI the bridge performs a local parse. Both paths are dispatched
    to a worker thread via :func:`asyncio.to_thread` to keep the event loop
    free regardless of bridge implementation.

    Takes an explicit ``scp`` instance for cross-SDK consistency with
    ``discoverContexts(scp, query)`` in TypeScript and other SDK bindings.

    Args:
        _scp: An active :class:`~scp_sdk.SCP` instance. Accepted for
            cross-SDK parity with TypeScript's ``discoverContexts(scp, query)``,
            which dispatches per-instance via ``getBridge(scp)``. In Python,
            ``context_discover`` is a module-level ``#[pyfunction]`` rather than
            an instance method, so dispatch goes through the module bridge
            (``_bridge().context_discover(query)``). The parameter is intentionally
            unused — the leading underscore signals this.
        query: A ``did:`` identifier or an ``scp://`` context URI.

    Returns:
        A list of discovery-result dicts, each describing a discoverable
        context. May be empty if the target advertises none.

    Raises:
        ValidationError: If ``query`` is neither a DID nor an ``scp://`` URI.
        ContextError: If DID resolution or URI parsing fails.
    """
    import asyncio

    bridge = _bridge()
    results = await asyncio.to_thread(bridge.context_discover, query)
    return [dict(item) for item in results]


__all__ = [
    "create_query",
    "discover_contexts",
    "normalize_address",
    "parse_address",
]
