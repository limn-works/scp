"""Shared types for the SCP Python SDK.

Contains dataclasses and enums used across multiple SDK modules:
``Message``, ``Provenance``, ``Capability``, ``MemoryScope``,
``SourceType``, ``DiscoveryMethod``, and ``ProvenanceQuality``.

All types mirror their Rust counterparts in ``scp-core`` and carry full
PEP 484 type annotations.  See ``.docs/adrs/phase-3.md`` ADR-014 for
the wrapper design and ``.docs/standards/python.md`` for coding
conventions.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class MemoryScope(enum.Enum):
    """Memory scope for a context, controlling data retention after close.

    Mirrors ``scp_core::context::MemoryScope``.
    """

    #: All data destroyed on close; keys destroyed immediately.
    EPHEMERAL = "ephemeral"
    #: Verified summary generated during closing window, then keys destroyed.
    SUMMARY = "summary"
    #: All data and keys retained after close.
    FULL = "full"


class SourceType(enum.Enum):
    """Current data-availability status of the source context.

    Mirrors ``scp_core::provenance::SourceType``.
    """

    #: Source context is still open and verifiable.
    PERSISTENT = "persistent"
    #: Source context has closed and keys have been destroyed.
    EPHEMERAL = "ephemeral"
    #: Source context has closed and a verified summary is available.
    SUMMARY = "summary"


class DiscoveryMethod(enum.Enum):
    """How the data source was discovered.

    Mirrors ``scp_core::provenance::DiscoveryMethod``.
    """

    #: Discovered through shared membership in a context.
    SHARED_CONTEXT = "shared_context"
    #: Discovered through a discovery registry context.
    REGISTRY = "registry"
    #: No protocol-level discovery path.
    NONE = "none"


class ProvenanceQuality(enum.Enum):
    """Provenance quality evaluation tiers (spec section 7.7.2).

    Ordered from lowest to highest quality.  Mirrors
    ``scp_core::provenance::ProvenanceQuality``.
    """

    #: Data without protocol-level origin tracking.
    NO_PROVENANCE = 0
    #: Ephemeral source, known counterparties, not independently verifiable.
    EPHEMERAL_KNOWN_PARTIES = 1
    #: Source closed with summary scope; partial verifiability.
    SUMMARY_VERIFIED = 2
    #: Source persistent and active; independently verifiable.
    PERSISTENT_VERIFIABLE = 3


class Capability(enum.Enum):
    """Protocol-defined capabilities within an SCP context.

    Mirrors ``scp_core::context::roles::Capability``.  Parameterised
    variants (``ToolInvoke(tool_id)``, ``Custom(name)``) are represented
    as string values prefixed with their variant name.
    """

    MESSAGES_READ = "MessagesRead"
    MESSAGES_WRITE = "MessagesWrite"
    TOOL_INVOKE_ALL = "ToolInvokeAll"
    TOOL_REGISTER = "ToolRegister"
    MEMBER_INVITE = "MemberInvite"
    MEMBER_REMOVE = "MemberRemove"
    ROLE_ASSIGN = "RoleAssign"
    GOVERNANCE_PROPOSE = "GovernancePropose"
    GOVERNANCE_VOTE = "GovernanceVote"
    CONTEXT_CLOSE = "ContextClose"
    CHILD_CONTEXT_CREATE = "ChildContextCreate"

    @staticmethod
    def tool_invoke(tool_id: str) -> str:
        """Return the capability string for invoking a specific tool.

        Since Python enums cannot carry per-instance data, parameterised
        capabilities are represented as plain strings.
        """
        return f"ToolInvoke({tool_id})"

    @staticmethod
    def custom(name: str) -> str:
        """Return the capability string for a custom capability."""
        return f"Custom({name})"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class Provenance:
    """Data provenance metadata (spec section 7.7.1).

    Mirrors ``scp_core::provenance::DataProvenance``.  Attached
    automatically when data crosses context boundaries.
    """

    #: Context from which this data originated.
    source_context: str

    #: Current data-availability status of the source context.
    source_type: SourceType

    #: DIDs of the parties involved in the source context.
    counterparties: list[str] = field(default_factory=list)

    #: Optional human-readable purpose description.
    purpose: str | None = None

    #: How the data source was discovered.
    discovery_method: DiscoveryMethod = DiscoveryMethod.NONE

    #: Age of the data in seconds at the time provenance was attached.
    age_secs: float = 0.0

    #: Memory scope of the source context.
    memory_scope: MemoryScope = MemoryScope.FULL

    #: Number of cross-context hops (max 3 by default).
    chain_depth: int = 0

    #: Ordered list of intermediary context IDs when ``chain_depth > 0``.
    chain_path: list[str] | None = None


@dataclass
class Message:
    """An SCP message received from a context.

    Mirrors the message surface defined in ADR-014 acceptance criterion 4.
    """

    #: DID of the sender.
    sender_did: str

    #: Message payload (text or binary).
    content: str | bytes

    #: Unix timestamp (seconds since epoch).
    timestamp: float

    #: Monotonically increasing sequence number within the context.
    sequence: int

    #: Identifier of the context this message belongs to.
    context_id: str

    #: Optional provenance metadata for cross-context data.
    provenance: Provenance | None = None


__all__ = [
    "Capability",
    "DiscoveryMethod",
    "MemoryScope",
    "Message",
    "Provenance",
    "ProvenanceQuality",
    "SourceType",
]
