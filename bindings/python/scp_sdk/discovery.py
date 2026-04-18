"""Discovery operations for the SCP Python SDK.

Provides functions for parsing SCP addresses, creating discovery queries,
normalizing addresses, and discovering contexts from DIDs or ``scp://`` URIs.

All operations delegate to the ``_scp_core`` PyO3 bridge layer.

See ADR-020 in ``.docs/adrs/phase-4.md`` and spec section 22 (Addressing).
"""

from __future__ import annotations

from typing import Any

from scp_sdk._deprecation import deprecated_default_instance
from scp_sdk.errors import ScpError


def _bridge() -> Any:
    """Return the ``_scp_core`` extension module, imported lazily."""
    try:
        import _scp_core  # type: ignore[import-not-found]

        return _scp_core
    except ImportError as exc:
        raise ScpError(
            "The _scp_core extension module is not installed. "
            "Install scp-python with: pip install scp-python",
            code="SCP-UNKNOWN-0001",
        ) from exc


@deprecated_default_instance
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


@deprecated_default_instance
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


@deprecated_default_instance
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


@deprecated_default_instance
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
    raw = bridge.context_discover(query)
    if isinstance(raw, str):
        import json

        return json.loads(raw)
    return [dict(r) for r in raw]


# ---------------------------------------------------------------------------
# Petname operations (spec section 22.4)
# ---------------------------------------------------------------------------


@deprecated_default_instance
def petname_set(owner_did: str, target_did: str, name: str) -> None:
    """Assign a petname to a DID within the owner's local namespace.

    Args:
        owner_did: DID of the identity that owns this petname map.
        target_did: DID to assign the petname to.
        name: The petname string.

    Raises:
        ValidationError: If ``owner_did`` is empty.
    """
    bridge = _bridge()
    bridge.petname_set(owner_did, target_did, name)


@deprecated_default_instance
def petname_remove(owner_did: str, target_did: str) -> None:
    """Remove a petname from a DID.

    Args:
        owner_did: DID of the identity that owns this petname map.
        target_did: DID to remove the petname from.

    Raises:
        ValidationError: If ``owner_did`` is empty.
    """
    bridge = _bridge()
    bridge.petname_remove(owner_did, target_did)


@deprecated_default_instance
def petname_set_context(owner_did: str, context_id: str, name: str) -> None:
    """Assign a petname to a context within the owner's local namespace.

    Args:
        owner_did: DID of the identity that owns this petname map.
        context_id: Context ID to assign the petname to.
        name: The petname string.

    Raises:
        ValidationError: If ``owner_did`` is empty.
    """
    bridge = _bridge()
    bridge.petname_set_context(owner_did, context_id, name)


@deprecated_default_instance
def petname_remove_context(owner_did: str, context_id: str) -> None:
    """Remove a petname from a context.

    Args:
        owner_did: DID of the identity that owns this petname map.
        context_id: Context ID to remove the petname from.

    Raises:
        ValidationError: If ``owner_did`` is empty.
    """
    bridge = _bridge()
    bridge.petname_remove_context(owner_did, context_id)


@deprecated_default_instance
def petname_resolve_did(owner_did: str, name: str) -> list[str]:
    """Resolve a petname to a list of DIDs.

    Args:
        owner_did: DID of the identity that owns this petname map.
        name: The petname to resolve.

    Returns:
        A list of DID strings matching the petname.

    Raises:
        ValidationError: If ``owner_did`` is empty.
    """
    bridge = _bridge()
    return list(bridge.petname_resolve_did(owner_did, name))


@deprecated_default_instance
def petname_resolve_context(owner_did: str, name: str) -> list[str]:
    """Resolve a petname to a list of context IDs.

    Args:
        owner_did: DID of the identity that owns this petname map.
        name: The petname to resolve.

    Returns:
        A list of context ID strings matching the petname.

    Raises:
        ValidationError: If ``owner_did`` is empty.
    """
    bridge = _bridge()
    return list(bridge.petname_resolve_context(owner_did, name))


@deprecated_default_instance
def petname_get_for_did(owner_did: str, target_did: str) -> str | None:
    """Get the petname assigned to a DID, if any.

    Args:
        owner_did: DID of the identity that owns this petname map.
        target_did: DID to look up.

    Returns:
        The petname string, or ``None`` if no petname is assigned.

    Raises:
        ValidationError: If ``owner_did`` is empty.
    """
    bridge = _bridge()
    return bridge.petname_get_for_did(owner_did, target_did)


@deprecated_default_instance
def petname_get_for_context(owner_did: str, context_id: str) -> str | None:
    """Get the petname assigned to a context, if any.

    Args:
        owner_did: DID of the identity that owns this petname map.
        context_id: Context ID to look up.

    Returns:
        The petname string, or ``None`` if no petname is assigned.

    Raises:
        ValidationError: If ``owner_did`` is empty.
    """
    bridge = _bridge()
    return bridge.petname_get_for_context(owner_did, context_id)


# ---------------------------------------------------------------------------
# Handle registry operations (spec section 22.3.1)
# ---------------------------------------------------------------------------


@deprecated_default_instance
def handle_register(
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
    bridge = _bridge()
    import json

    result = bridge.handle_register(
        discovery_context_id, handle, target_json, registrant_did, description, tags
    )
    return json.loads(result)


@deprecated_default_instance
def handle_lookup(
    discovery_context_id: str,
    handle: str,
    *,
    type_filter: str | None = None,
) -> dict[str, Any]:
    """Look up a handle in a context with discovery tools.

    Args:
        discovery_context_id: ID of the context.
        handle: The handle string to look up.
        type_filter: Optional filter: ``"identity"`` or ``"context"``.

    Returns:
        A dict with a ``results`` list of matching handle entries.
    """
    bridge = _bridge()
    import json

    result = bridge.handle_lookup(discovery_context_id, handle, type_filter)
    return json.loads(result)


@deprecated_default_instance
def handle_deregister(
    discovery_context_id: str,
    handle: str,
    did: str,
) -> dict[str, Any]:
    """Deregister a handle from a context with discovery tools.

    Args:
        discovery_context_id: ID of the context.
        handle: The handle string to deregister.
        did: DID of the registrant requesting deregistration.

    Returns:
        A dict with a ``removed`` boolean.
    """
    bridge = _bridge()
    import json

    result = bridge.handle_deregister(discovery_context_id, handle, did)
    return json.loads(result)


# ---------------------------------------------------------------------------
# Address resolution (spec section 22.8)
# ---------------------------------------------------------------------------


@deprecated_default_instance
def address_resolve(
    owner_did: str,
    address: str,
    *,
    known_contexts_json: str | None = None,
) -> list[dict[str, Any]]:
    """Resolve a human-readable address via multi-path resolution.

    Uses the petname layer first, then handle registries, then attestation
    and domain layers per the resolution pipeline (spec section 22.8).

    Args:
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
    bridge = _bridge()
    import json

    result = bridge.address_resolve(owner_did, address, known_contexts_json)
    return json.loads(result)


# ---------------------------------------------------------------------------
# Scope registry operations (spec section 22.3.5, ADR-043)
# ---------------------------------------------------------------------------


@deprecated_default_instance
def scope_register(
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
    bridge = _bridge()
    import json

    result = bridge.scope_register(
        scope_context_id,
        name,
        target_context_id,
        relay_urls,
        registrant_did,
        description,
        tags,
    )
    return json.loads(result)


@deprecated_default_instance
def scope_lookup(
    scope_context_id: str,
    name: str,
) -> dict[str, Any]:
    """Look up a scope name in a scope registry.

    Args:
        scope_context_id: ID of the context hosting the scope registry.
        name: The scope name to look up.

    Returns:
        A dict with a ``results`` list of matching scope entries.
    """
    bridge = _bridge()
    import json

    result = bridge.scope_lookup(scope_context_id, name)
    return json.loads(result)


@deprecated_default_instance
def scope_deregister(
    scope_context_id: str,
    name: str,
    did: str,
) -> dict[str, Any]:
    """Deregister a scope name from a scope registry.

    Args:
        scope_context_id: ID of the context hosting the scope registry.
        name: The scope name to deregister.
        did: DID of the registrant requesting deregistration.

    Returns:
        A dict with a ``removed`` boolean.
    """
    bridge = _bridge()
    import json

    result = bridge.scope_deregister(scope_context_id, name, did)
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
