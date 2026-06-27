"""Discovery operations for the SCP Python SDK.

Provides functions for parsing SCP addresses, creating discovery queries,
normalizing addresses, and discovering contexts from DIDs or ``scp://`` URIs.

All operations delegate to the ``_scp_core`` PyO3 bridge layer.

See ADR-020 in ``.docs/adrs/phase-4.md`` and spec section 22 (Addressing).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from scp_sdk.errors import ScpError

if TYPE_CHECKING:
    pass


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


def discover(query: str) -> list[dict[str, Any]]:
    """Discover contexts from a DID or an ``scp://`` URI.

    Delegates to the ``_scp_core`` ``context_discover`` bridge op, which
    combines client-side sources (local runtime registry, known-contexts
    registry, and an optional relay probe when a transport is connected)
    and deduplicates by context ID. The relay is a dumb blob store with no
    identity-to-context mapping; discovery is purely client-side (see
    spec §5.14.11, §18.2.2, §18.4).

    Args:
        query: Either a DID (``did:...``) to resolve the contexts a member
            participates in, or an ``scp://`` URI to resolve directly.

    Returns:
        A list of result dicts. Each contains ``context_id`` and ``source``
        (``"local"`` / ``"relay"`` / ``"local+relay"``), ``relay_active``,
        plus optional ``creator_did`` / ``member_count`` / ``tool_count``.

    Raises:
        ValidationError: If the query is neither a DID nor an ``scp://`` URI.
        ContextError: If DID resolution or URI parsing fails.
    """
    bridge = _bridge()
    results = bridge.context_discover(query)
    return [dict(r) for r in results]


#: Alias for :func:`discover` matching the cross-SDK ``discover_contexts``
#: capability name (TypeScript ``discoverContexts``); both spellings refer to
#: the same client-side context discovery op.
discover_contexts = discover


# ---------------------------------------------------------------------------
# Petname operations (spec section 22.4)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Handle registry operations (spec section 22.3.1)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Address resolution (spec section 22.8)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Scope registry operations (spec section 22.3.5, ADR-043)
# ---------------------------------------------------------------------------


__all__ = [
    "create_query",
    "discover",
    "discover_contexts",
    "normalize_address",
    "parse_address",
]
