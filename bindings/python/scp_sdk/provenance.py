"""Provenance operations for the SCP Python SDK.

Provides functions for evaluating provenance quality, attaching provenance
metadata at cross-context boundaries, and checking chain depth limits.

All operations delegate to the ``_scp_core`` PyO3 bridge layer.

See spec section 24 (Provenance System) and ADR-019.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scp_sdk.scp import SCP


def evaluate_provenance_quality(
    scp: SCP,
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
        scp: The :class:`scp_sdk.SCP` instance that owns the provenance state.
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
    return scp._native.evaluate_provenance_quality(
        source_context,
        source_type,
        context_state,
        counterparties,
    )


def attach(
    scp: SCP,
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
        scp: The :class:`scp_sdk.SCP` instance that owns the provenance state.
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
    return dict(
        scp._native.provenance_attach(
            source_context_id,
            source_type,
            memory_scope,
            members,
            target_context_id,
            actor_did,
            existing_chain_depth,
        )
    )


def check_chain_depth(
    scp: SCP,
    chain_depth: int,
    *,
    max_depth: int | None = None,
) -> bool:
    """Check whether a provenance chain depth is within the allowed limit.

    Args:
        scp: The :class:`scp_sdk.SCP` instance that owns the provenance state.
        chain_depth: The current chain depth to check.
        max_depth: Optional custom maximum depth (default: 3).

    Returns:
        ``True`` if within limit, ``False`` otherwise.
    """
    return scp._native.provenance_check_chain_depth(chain_depth, max_depth)


__all__ = [
    "attach",
    "check_chain_depth",
    "evaluate_provenance_quality",
]
