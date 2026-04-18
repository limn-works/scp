"""Provenance operations for the SCP Python SDK.

Provides functions for evaluating provenance quality, attaching provenance
metadata at cross-context boundaries, and checking chain depth limits.

All operations delegate to the ``_scp_core`` PyO3 bridge layer.

See spec section 24 (Provenance System) and ADR-019.
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
def evaluate_provenance_quality(
    *,
    source_context: str | None = None,
    source_type: str = "persistent",
    context_state: str = "unknown",
    counterparties: list[str] | None = None,
) -> int:
    """Evaluate the provenance quality tier for a data provenance record.

    Returns an integer (0--3) representing the quality tier:

    - ``0`` -- No provenance.
    - ``1`` -- Ephemeral, known parties.
    - ``2`` -- Summary verified.
    - ``3`` -- Persistent, verifiable.

    Args:
        source_context: Source context ID (optional).
        source_type: ``"persistent"``, ``"ephemeral"``, or ``"summary"``.
        context_state: ``"active"``, ``"closed_with_summary_verified"``,
            ``"closed_with_summary_unverified"``, ``"closed_ephemeral"``,
            or ``"unknown"``.
        counterparties: Optional list of counterparty DID strings.

    Returns:
        Quality tier as an integer (0--3).

    Raises:
        ValidationError: If *source_type* or *context_state* is invalid.
    """
    bridge = _bridge()
    return bridge.evaluate_provenance_quality(
        source_context,
        source_type,
        context_state,
        counterparties,
    )


@deprecated_default_instance
def attach(
    source_context_id: str,
    source_type: str,
    memory_scope: str,
    members: list[str],
    target_context_id: str,
    actor_did: str,
    *,
    existing_chain_depth: int | None = None,
) -> dict[str, Any]:
    """Attach provenance metadata when data crosses a context boundary.

    Records dual events in the event log: ``ProvenanceAttached`` in the
    source context and ``ProvenanceReceived`` in the target context.

    Returns a dict with the provenance record fields: ``source_context``,
    ``source_type``, ``chain_depth``, ``counterparties``, ``age_secs``,
    ``memory_scope``, ``chain_path``, ``purpose``.

    Args:
        source_context_id: ID of the source context.
        source_type: ``"persistent"``, ``"ephemeral"``, or ``"summary"``.
        memory_scope: ``"full"``, ``"summary"``, or ``"ephemeral"``.
        members: List of member DID strings from the source context.
        target_context_id: ID of the target context.
        actor_did: DID of the actor performing the attachment.
        existing_chain_depth: Chain depth of existing provenance (if any).

    Returns:
        A dict with provenance record fields.

    Raises:
        ValidationError: If *source_type* or *memory_scope* is invalid.
    """
    bridge = _bridge()
    return dict(
        bridge.provenance_attach(
            source_context_id,
            source_type,
            memory_scope,
            members,
            target_context_id,
            actor_did,
            existing_chain_depth,
        )
    )


@deprecated_default_instance
def check_chain_depth(
    chain_depth: int,
    *,
    max_depth: int | None = None,
) -> bool:
    """Check whether a provenance chain depth is within the allowed limit.

    Args:
        chain_depth: The current chain depth to check.
        max_depth: Optional custom maximum depth (default: 3).

    Returns:
        ``True`` if within limit, ``False`` otherwise.
    """
    bridge = _bridge()
    return bridge.provenance_check_chain_depth(chain_depth, max_depth)


__all__ = [
    "attach",
    "check_chain_depth",
    "evaluate_provenance_quality",
]
