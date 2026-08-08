"""Event log data types for the SCP Python SDK.

Phase 4 PR 5 Agent B+C (#1549) deleted the :class:`EventLog` namespace
class. Every event-log operation — query, verify, checkpoint, signed
checkpoint — lives on :class:`scp_sdk.SCP` as
:meth:`~scp_sdk.SCP.event_log_query`,
:meth:`~scp_sdk.SCP.event_log_verify`, and
:meth:`~scp_sdk.SCP.event_log_checkpoint`.

Only the data classes (:class:`Event`, :class:`Proof`, :class:`Checkpoint`,
:class:`SignedCheckpoint`) remain. They hold no :class:`SCP` reference
and can be safely passed across API boundaries.

See ``.docs/adrs/phase-3.md`` ADR-014 acceptance criterion 8 for the
underlying design and ADR-048 for the façade consolidation rationale.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("scp_sdk")

# Standard library practice: add NullHandler so that library logging
# never causes "No handlers could be found" warnings when the
# application hasn't configured logging.
logger.addHandler(logging.NullHandler())


def _init_pyo3_log_bridge() -> None:
    """Forward Rust ``tracing`` output to Python logging via pyo3 log bridge.

    Attempts to import ``_scp_core`` and call its log bridge
    initializer.  If the extension is not installed or does not expose
    a log bridge function, this is a silent no-op.

    The bridge maps Rust ``tracing`` levels to Python logging levels:

    - ``TRACE``/``DEBUG`` -> ``logging.DEBUG``
    - ``INFO``  -> ``logging.INFO``
    - ``WARN``  -> ``logging.WARNING``
    - ``ERROR`` -> ``logging.ERROR``

    Users control the verbosity via the standard Python API::

        logging.getLogger("scp_sdk").setLevel(logging.DEBUG)
    """
    try:
        import _scp_core  # type: ignore[import-not-found]

        if hasattr(_scp_core, "init_pyo3_log"):
            _scp_core.init_pyo3_log()
    except (ImportError, Exception):
        # Extension not installed or log bridge not available -- this
        # is expected during development or testing without the Rust
        # extension compiled.
        pass


# Eagerly attempt to initialize the pyo3 log bridge on first import.
_init_pyo3_log_bridge()


# ---------------------------------------------------------------------------
# Internal helpers for bridge payload extraction
# ---------------------------------------------------------------------------

_EMPTY_ROOT_HASH = "0" * 64


def _extract_root_hash(events: list[Any]) -> str:
    """Extract the Merkle root hash from bridge query results.

    The bridge ``event_log_query`` returns a single ``LogSummary`` event
    whose ``payload`` dict contains a ``merkle_root`` key with the
    hex-encoded Merkle root of the event log (RFC 6962 structure).

    Returns the hex-encoded root hash, or the empty-tree sentinel
    (64 zero characters) if the root cannot be extracted.
    """
    for event in events:
        payload = getattr(event, "payload", None)
        if payload is None:
            continue

        if isinstance(payload, dict):
            root = payload.get("merkle_root")
            if isinstance(root, str) and len(root) == 64:
                return root

    return _EMPTY_ROOT_HASH


def _extract_event_count(events: list[Any]) -> int:
    """Extract the total event count from bridge query results.

    The bridge ``event_log_query`` returns a ``LogSummary`` event whose
    ``payload`` dict contains an ``event_count`` key with the total
    number of events in the log.

    Returns the event count, or ``len(events)`` as a fallback.
    """
    for event in events:
        payload = getattr(event, "payload", None)
        if payload is None:
            continue

        if isinstance(payload, dict):
            count = payload.get("event_count")
            if isinstance(count, int):
                return count

    return len(events)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class Event:
    """A single protocol event from the context event log.

    Each event records a protocol action: what happened
    (``event_type``), who did it (``actor_did``), when (``timestamp``),
    the event data (``payload``), and its position in the log
    (``sequence``).

    Mirrors ``PyEvent`` from ``_scp_core``.
    """

    #: The event type (e.g., ``"ContextCreated"``, ``"MemberJoined"``,
    #: ``"GovernanceActionExecuted"``).
    event_type: str

    #: The DID of the actor who produced this event.
    actor_did: str

    #: Unix timestamp (seconds since epoch).
    timestamp: float

    #: Event-specific data as a JSON-compatible object.
    payload: Any

    #: Monotonic sequence number within the log (0-indexed).
    sequence: int


@dataclass
class Proof:
    """A Merkle proof from the event log.

    Carries the proof type and the proof material. Mirrors ``PyProof`` from
    ``_scp_core``.

    **There is no ``verified`` field.** This type used to carry
    ``verified: bool``. It was a constant ``True`` on every success path: the
    bridge generated the proof and then "verified" that same proof against the
    same snapshot, so the check was tautological and only success-vs-raise ever
    carried information. A boolean named ``verified`` that no independent
    verifier computed is a false guarantee, so it is gone —
    :meth:`~scp_sdk.scp.SCP.event_log_verify` raising IS the negative answer.

    Real verification is done by the recipient from :attr:`details`, which
    carries the full Merkle material for both proof types: the leaf hash, the
    sibling path with per-step direction, and the root the path reaches. An
    absence answer carries the same complete material for BOTH bracketing
    neighbours (under ``details["lower"]["inclusion_proof"]`` and
    ``details["upper"]["inclusion_proof"]``).

    An ``"absence"`` answer lets a recipient check that both bracketing leaves
    really are in the tree the reported ``root`` commits to, and that the
    queried hash sorts strictly between them. It does NOT establish that the two
    neighbours are *adjacent* in sorted order: the log's Merkle root commits to
    append order, and the sorted index the neighbours are drawn from is local
    state the root does not cover.
    """

    #: The proof type: ``"inclusion"`` or ``"absence"``.
    proof_type: str

    #: Proof material: the Merkle path (inclusion) or the two sorted neighbours
    #: with their own inclusion proofs (absence).
    details: Any


@dataclass
class Checkpoint:
    """A snapshot of the event log state at a point in time.

    Used for incremental synchronization and consistency verification.
    """

    #: The context this checkpoint belongs to.
    context_id: str

    #: The sequence number of the last event included in this checkpoint.
    sequence: int

    #: Unix timestamp when the checkpoint was created.
    timestamp: float

    #: Root hash of the event log Merkle tree at this point.
    root_hash: str

    #: Total number of events in the log at checkpoint time.
    event_count: int = 0


@dataclass
class SignedCheckpoint:
    """A cryptographically signed consistency checkpoint.

    Generated by the Rust bridge via ``event_log_checkpoint``. Contains
    an Ed25519 signature over the canonical checkpoint fields, enabling
    equivocation detection between context members.

    See ADR-011 acceptance criterion 8 and ADR-030.
    """

    #: The context this checkpoint belongs to.
    context_id: str

    #: The DID of the member who generated this checkpoint.
    sender_did: str

    #: The number of events in the log at checkpoint time.
    event_count: int

    #: The Merkle root hash at checkpoint time, hex-encoded.
    merkle_root: str

    #: Current MLS epoch. ``None`` for Broadcast contexts.
    epoch: int | None

    #: Unix timestamp (seconds) when the checkpoint was generated.
    timestamp: int

    #: Ed25519 signature over the canonical checkpoint fields, hex-encoded.
    signature: str


__all__ = [
    "Checkpoint",
    "Event",
    "Proof",
    "SignedCheckpoint",
]
