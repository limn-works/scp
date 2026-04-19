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
    from scp_sdk.scp import SCP


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


def discover(scp: SCP, query: str) -> list[dict[str, Any]]:
    """Discover contexts from a DID string or ``scp://`` URI.

    Detects whether the query is a DID or an ``scp://`` URI and delegates
    to the appropriate core discovery function.

    Args:
        scp: The :class:`scp_sdk.SCP` instance that owns the discovery state.
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
    native = scp._native
    raw = native.context_discover(query)
    if isinstance(raw, str):
        import json

        return json.loads(raw)
    return [dict(r) for r in raw]


# ---------------------------------------------------------------------------
# Petname operations (spec section 22.4)
# ---------------------------------------------------------------------------


def petname_set(scp: SCP, owner_did: str, target_did: str, name: str) -> None:
    """Assign a petname to a DID within the owner's local namespace.

    Args:
        scp: The :class:`scp_sdk.SCP` instance that owns the petname map.
        owner_did: DID of the identity that owns this petname map.
        target_did: DID to assign the petname to.
        name: The petname string.

    Raises:
        ValidationError: If ``owner_did`` is empty.
    """
    scp._native.petname_set(owner_did, target_did, name)


def petname_remove(scp: SCP, owner_did: str, target_did: str) -> None:
    """Remove a petname from a DID.

    Args:
        scp: The :class:`scp_sdk.SCP` instance that owns the petname map.
        owner_did: DID of the identity that owns this petname map.
        target_did: DID to remove the petname from.

    Raises:
        ValidationError: If ``owner_did`` is empty.
    """
    scp._native.petname_remove(owner_did, target_did)


def petname_set_context(scp: SCP, owner_did: str, context_id: str, name: str) -> None:
    """Assign a petname to a context within the owner's local namespace.

    Args:
        scp: The :class:`scp_sdk.SCP` instance that owns the petname map.
        owner_did: DID of the identity that owns this petname map.
        context_id: Context ID to assign the petname to.
        name: The petname string.

    Raises:
        ValidationError: If ``owner_did`` is empty.
    """
    scp._native.petname_set_context(owner_did, context_id, name)


def petname_remove_context(scp: SCP, owner_did: str, context_id: str) -> None:
    """Remove a petname from a context.

    Args:
        scp: The :class:`scp_sdk.SCP` instance that owns the petname map.
        owner_did: DID of the identity that owns this petname map.
        context_id: Context ID to remove the petname from.

    Raises:
        ValidationError: If ``owner_did`` is empty.
    """
    scp._native.petname_remove_context(owner_did, context_id)


def petname_resolve_did(scp: SCP, owner_did: str, name: str) -> list[str]:
    """Resolve a petname to a list of DIDs.

    Args:
        scp: The :class:`scp_sdk.SCP` instance that owns the petname map.
        owner_did: DID of the identity that owns this petname map.
        name: The petname to resolve.

    Returns:
        A list of DID strings matching the petname.

    Raises:
        ValidationError: If ``owner_did`` is empty.
    """
    return list(scp._native.petname_resolve_did(owner_did, name))


def petname_resolve_context(scp: SCP, owner_did: str, name: str) -> list[str]:
    """Resolve a petname to a list of context IDs.

    Args:
        scp: The :class:`scp_sdk.SCP` instance that owns the petname map.
        owner_did: DID of the identity that owns this petname map.
        name: The petname to resolve.

    Returns:
        A list of context ID strings matching the petname.

    Raises:
        ValidationError: If ``owner_did`` is empty.
    """
    return list(scp._native.petname_resolve_context(owner_did, name))


def petname_get_for_did(scp: SCP, owner_did: str, target_did: str) -> str | None:
    """Get the petname assigned to a DID, if any.

    Args:
        scp: The :class:`scp_sdk.SCP` instance that owns the petname map.
        owner_did: DID of the identity that owns this petname map.
        target_did: DID to look up.

    Returns:
        The petname string, or ``None`` if no petname is assigned.

    Raises:
        ValidationError: If ``owner_did`` is empty.
    """
    return scp._native.petname_get_for_did(owner_did, target_did)


def petname_get_for_context(scp: SCP, owner_did: str, context_id: str) -> str | None:
    """Get the petname assigned to a context, if any.

    Args:
        scp: The :class:`scp_sdk.SCP` instance that owns the petname map.
        owner_did: DID of the identity that owns this petname map.
        context_id: Context ID to look up.

    Returns:
        The petname string, or ``None`` if no petname is assigned.

    Raises:
        ValidationError: If ``owner_did`` is empty.
    """
    return scp._native.petname_get_for_context(owner_did, context_id)


# ---------------------------------------------------------------------------
# Handle registry operations (spec section 22.3.1)
# ---------------------------------------------------------------------------


def handle_register(
    scp: SCP,
    discovery_context_id: str,
    handle: str,
    target_json: str,
    registrant_did: str,
    *,
    description: str | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """Register a handle in a context with discovery tools.

    Args:
        scp: The :class:`scp_sdk.SCP` instance that owns the registry.
        discovery_context_id: ID of the context.
        handle: The handle string to register.
        target_json: JSON string describing the target. Must have a
            ``"type"`` field (``"identity"`` or ``"context"``).
        registrant_did: DID of the registrant.
        description: Optional human-readable description.
        tags: Optional list of tag strings.

    Returns:
        A dict with the registration result.

    Raises:
        ValidationError: If ``target_json`` is malformed.
    """
    import json

    result = scp._native.handle_register(
        discovery_context_id, handle, target_json, registrant_did, description, tags
    )
    return json.loads(result)


def handle_lookup(
    scp: SCP,
    discovery_context_id: str,
    handle: str,
    *,
    type_filter: str | None = None,
) -> dict[str, Any]:
    """Look up a handle in a context with discovery tools.

    Args:
        scp: The :class:`scp_sdk.SCP` instance that owns the registry.
        discovery_context_id: ID of the context.
        handle: The handle string to look up.
        type_filter: Optional filter: ``"identity"`` or ``"context"``.

    Returns:
        A dict with a ``results`` list of matching handle entries.
    """
    import json

    result = scp._native.handle_lookup(discovery_context_id, handle, type_filter)
    return json.loads(result)


def handle_deregister(
    scp: SCP,
    discovery_context_id: str,
    handle: str,
    did: str,
) -> dict[str, Any]:
    """Deregister a handle from a context with discovery tools.

    Args:
        scp: The :class:`scp_sdk.SCP` instance that owns the registry.
        discovery_context_id: ID of the context.
        handle: The handle string to deregister.
        did: DID of the registrant requesting deregistration.

    Returns:
        A dict with a ``removed`` boolean.
    """
    import json

    result = scp._native.handle_deregister(discovery_context_id, handle, did)
    return json.loads(result)


# ---------------------------------------------------------------------------
# Address resolution (spec section 22.8)
# ---------------------------------------------------------------------------


def address_resolve(
    scp: SCP,
    owner_did: str,
    address: str,
    *,
    known_contexts_json: str | None = None,
) -> list[dict[str, Any]]:
    """Resolve a human-readable address via multi-path resolution.

    Uses the petname layer first, then handle registries, then attestation
    and domain layers per the resolution pipeline (spec section 22.8).

    Args:
        scp: The :class:`scp_sdk.SCP` instance that owns the registries.
        owner_did: DID of the identity whose petname map to consult.
        address: The address string to resolve
            (e.g., ``"alice@cooking-community"``).
        known_contexts_json: Optional JSON object mapping context IDs to
            names. If ``None``, uses all registered contexts with discovery tools.

    Returns:
        A list of ``AddressResolution`` dicts, each with ``type``
        (``"Identity"`` or ``"Context"``), trust level, and resolution
        path metadata.

    Raises:
        ValidationError: If ``owner_did`` is empty or address parsing fails.
    """
    import json

    result = scp._native.address_resolve(owner_did, address, known_contexts_json)
    return json.loads(result)


# ---------------------------------------------------------------------------
# Scope registry operations (spec section 22.3.5, ADR-043)
# ---------------------------------------------------------------------------


def scope_register(
    scp: SCP,
    scope_context_id: str,
    name: str,
    target_context_id: str,
    relay_urls: list[str],
    registrant_did: str,
    *,
    description: str | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """Register a scope name in a scope registry.

    Scope tools use independent structs and separate storage from handle tools.
    The target is context-only by construction (no identity variant).

    Args:
        scp: The :class:`scp_sdk.SCP` instance that owns the registry.
        scope_context_id: ID of the context hosting the scope registry.
        name: Scope name to register (``[a-z0-9-]``, max 64 chars).
        target_context_id: Context ID the scope name resolves to.
        relay_urls: Relay URLs for the target context.
        registrant_did: DID of the registrant.
        description: Optional human-readable description.
        tags: Optional list of tag strings.

    Returns:
        A dict with ``status`` (``"registered"``, ``"conflict"``, or
        ``"updated"``) and optional ``entry_id``.

    Raises:
        ValidationError: If the scope name or relay URLs are invalid.
    """
    import json

    result = scp._native.scope_register(
        scope_context_id,
        name,
        target_context_id,
        relay_urls,
        registrant_did,
        description,
        tags,
    )
    return json.loads(result)


def scope_lookup(
    scp: SCP,
    scope_context_id: str,
    name: str,
) -> dict[str, Any]:
    """Look up a scope name in a scope registry.

    Args:
        scp: The :class:`scp_sdk.SCP` instance that owns the registry.
        scope_context_id: ID of the context hosting the scope registry.
        name: The scope name to look up.

    Returns:
        A dict with a ``results`` list of matching scope entries.
    """
    import json

    result = scp._native.scope_lookup(scope_context_id, name)
    return json.loads(result)


def scope_deregister(
    scp: SCP,
    scope_context_id: str,
    name: str,
    did: str,
) -> dict[str, Any]:
    """Deregister a scope name from a scope registry.

    Args:
        scp: The :class:`scp_sdk.SCP` instance that owns the registry.
        scope_context_id: ID of the context hosting the scope registry.
        name: The scope name to deregister.
        did: DID of the registrant requesting deregistration.

    Returns:
        A dict with a ``removed`` boolean.
    """
    import json

    result = scp._native.scope_deregister(scope_context_id, name, did)
    return json.loads(result)


__all__ = [
    "address_resolve",
    "create_query",
    "discover",
    "handle_deregister",
    "handle_lookup",
    "handle_register",
    "normalize_address",
    "parse_address",
    "petname_get_for_context",
    "petname_get_for_did",
    "petname_remove",
    "petname_remove_context",
    "petname_resolve_context",
    "petname_resolve_did",
    "petname_set",
    "petname_set_context",
    "scope_deregister",
    "scope_lookup",
    "scope_register",
]
