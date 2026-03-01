"""Event log query API for the SCP Python SDK.

Provides the :class:`EventLog` class for querying, verifying, and
checkpointing context event logs.  Wraps the ``_scp_core`` bridge
functions ``event_log_query`` and ``event_log_verify`` (see ADR-013 S7).

Supporting dataclasses:

- :class:`Event` -- A single protocol event from the context event log.
- :class:`Proof` -- A verification proof (inclusion or absence).
- :class:`Checkpoint` -- A snapshot of the event log state at a point in time.

See ``.docs/adrs/phase-3.md`` ADR-014 acceptance criterion 8 for the
design and ``.docs/standards/python.md`` for coding conventions.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

from scp_sdk.errors import ContextError

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
# Lazy bridge import helper
# ---------------------------------------------------------------------------


def _bridge() -> Any:
    """Return the ``_scp_core`` extension module, imported lazily."""
    try:
        import _scp_core  # type: ignore[import-not-found]

        return _scp_core
    except ImportError as exc:
        raise ContextError(
            "The _scp_core extension module is not installed. "
            "Install scp-sdk with: pip install scp-sdk",
            code="SCP-CTX-2001",
        ) from exc


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

    #: The event type (e.g., ``"ContextCreated"``, ``"MessageSent"``).
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
    """A verification proof from the event log.

    Contains the verification result, the type of proof (inclusion or
    absence), and proof details.

    Mirrors ``PyProof`` from ``_scp_core``.
    """

    #: ``True`` if the claim was verified successfully.
    verified: bool

    #: The proof type: ``"inclusion"`` or ``"absence"``.
    proof_type: str

    #: Proof details (Merkle path for inclusion, sorted neighbors for absence).
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


# ---------------------------------------------------------------------------
# EventLog class
# ---------------------------------------------------------------------------


class EventLog:
    """Query and verify the event log for an SCP context.

    Wraps ``_scp_core.event_log_query`` and ``_scp_core.event_log_verify``
    bridge functions.  Instantiated with a ``context_id`` that identifies
    which context's event log to operate on.

    Example::

        log = EventLog(context_id="ctx_abc123")
        events = await log.query(event_type="MessageSent", actor="did:dht:z6Mk...")
        proof = await log.verify({"type": "inclusion", "leaf_index": 0})
        cp = await log.checkpoint()
    """

    def __init__(self, context_id: str) -> None:
        self._context_id = context_id

    @property
    def context_id(self) -> str:
        """The ID of the context this event log belongs to."""
        return self._context_id

    async def query(
        self,
        query_filter: str | None = None,
        since: float | None = None,
        actor: str | None = None,
        event_type: str | None = None,
    ) -> list[Event]:
        """Query the event log with optional filters.

        Args:
            query_filter: General-purpose filter string.
            since: Only return events after this Unix timestamp.
            actor: Only return events from this actor DID.
            event_type: Only return events of this type.

        Returns:
            A list of :class:`Event` objects matching the criteria.

        Raises:
            ContextError: If the query fails or the context is unavailable.
        """
        filter_dict: dict[str, Any] = {}
        if query_filter is not None:
            filter_dict["filter"] = query_filter
        if since is not None:
            filter_dict["after_timestamp"] = since
        if actor is not None:
            filter_dict["actor_did"] = actor
        if event_type is not None:
            filter_dict["event_type"] = event_type

        logger.debug(
            "Querying event log for context %s with filter %r",
            self._context_id,
            filter_dict,
        )

        bridge = _bridge()
        raw_events = bridge.event_log_query(
            self._context_id,
            filter_dict if filter_dict else None,
        )

        return [
            Event(
                event_type=e.event_type,
                actor_did=e.actor_did,
                timestamp=e.timestamp,
                payload=e.payload,
                sequence=e.sequence,
            )
            for e in raw_events
        ]

    async def verify(self, claim: dict[str, Any]) -> Proof:
        """Verify a claim against the event log.

        Generates and verifies a Merkle proof for the given claim.
        Supports both inclusion proofs (proving an event IS in the log)
        and absence proofs (proving an event is NOT in the log).

        Args:
            claim: A dict describing the claim to verify.  Keys:
                ``"type"`` (``"inclusion"`` or ``"absence"``),
                ``"leaf_index"`` (int, for inclusion),
                ``"event_hash"`` (str, for absence).

        Returns:
            A :class:`Proof` with the verification result.

        Raises:
            ContextError: If verification fails or the context is unavailable.
        """
        logger.debug(
            "Verifying claim against event log for context %s: %r",
            self._context_id,
            claim,
        )

        bridge = _bridge()
        raw_proof = bridge.event_log_verify(self._context_id, claim)

        return Proof(
            verified=raw_proof.verified,
            proof_type=raw_proof.proof_type,
            details=raw_proof.details,
        )

    async def checkpoint(self) -> Checkpoint:
        """Create a checkpoint of the current event log state.

        Returns a :class:`Checkpoint` capturing the log's current root
        hash, sequence number, and event count.  Useful for incremental
        synchronization and consistency verification.

        Returns:
            A :class:`Checkpoint` snapshot.

        Raises:
            ContextError: If the checkpoint cannot be created.
        """
        logger.debug(
            "Creating checkpoint for event log in context %s",
            self._context_id,
        )

        # Query all events to derive the checkpoint from current state.
        # A dedicated bridge function may be added in the future; for now
        # we derive from the query results.
        bridge = _bridge()
        events = bridge.event_log_query(self._context_id, None)

        last_seq = events[-1].sequence if events else 0
        return Checkpoint(
            context_id=self._context_id,
            sequence=last_seq,
            timestamp=time.time(),
            root_hash="",  # Populated by runtime when bridge supports it
            event_count=len(events),
        )


__all__ = [
    "Checkpoint",
    "Event",
    "EventLog",
    "Proof",
]
