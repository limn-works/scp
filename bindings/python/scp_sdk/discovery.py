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
    "normalize_address",
    "parse_address",
]
