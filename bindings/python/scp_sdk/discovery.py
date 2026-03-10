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
    """Return the ``_scp_core`` extension module, imported lazily."""
    try:
        import _scp_core  # type: ignore[import-not-found]

        return _scp_core
    except ImportError as exc:
        raise ScpError(
            "The _scp_core extension module is not installed. "
            "Install scp-sdk with: pip install scp-sdk",
            code="SCP-UNKNOWN-0001",
        ) from exc


def parse_address(address: str) -> dict[str, Any]:
    """Parse an SCP address string into its components.

    Returns a dict with ``type`` (one of ``"discovery_handle"``,
    ``"domain_handle"``, ``"attestation_handle"``, ``"unscoped"``)
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
    return dict(bridge.discovery_parse_address(address))


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
    """Discover contexts from a DID string or ``scp://`` URI.

    Detects whether the query is a DID or an ``scp://`` URI and delegates
    to the appropriate core discovery function.

    Args:
        query: A DID string (e.g., ``"did:dht:z6Mk..."``) or an
            ``scp://`` URI.

    Returns:
        A list of dicts, each with ``context_id``, ``relay_urls``,
        ``publisher_did``, ``discovery_source``, ``mode``, and
        ``metadata_summary``.

    Raises:
        ContextError: If DID resolution or URI parsing fails.
        ValidationError: If the query is neither a DID nor an
            ``scp://`` URI.
    """
    bridge = _bridge()
    return [dict(r) for r in bridge.context_discover(query)]


__all__ = [
    "create_query",
    "discover",
    "normalize_address",
    "parse_address",
]
