"""Shared types for the SCP Python SDK.

Contains dataclasses and enums used across multiple SDK modules:
``Message``, ``Provenance``, ``Capability``, ``CustodyType``,
``BridgeMode``, ``ShadowStatus``, ``ContextMode``,
``CeilingPolicy``, ``PromotionPolicy``, ``MemoryScope``,
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


class CustodyType(enum.Enum):
    """Key custody method for identity key management (spec section 3.2).

    Determines where cryptographic keys are stored and managed.
    Mirrors ``scp_core::identity::CustodyType``.

    The bridge layer accepts both ``"file"`` and ``"platform"`` for
    file-backed custody (:attr:`FILE` and :attr:`PLATFORM` respectively).
    ``"platform"`` is a backward-compatible alias — both resolve to
    ``FileKeyCustody`` (Argon2id + AES-256-GCM encrypted key file at
    ``$HOME/.scp/keys.bin``).  Prefer :attr:`FILE` for new code.

    See SCP-294a.
    """

    #: Encrypted file-backed key custody (Argon2id + AES-256-GCM).
    #: Canonical name for what was previously called ``"platform"``.
    #: Requires the ``SCP_KEY_PASSPHRASE`` environment variable.
    FILE = "file"
    #: Backward-compatible alias for :attr:`FILE`.  Both resolve to
    #: ``FileKeyCustody`` in the bridge layer.  Prefer :attr:`FILE`
    #: for new code.
    PLATFORM = "platform"
    #: Ephemeral in-memory key store, suitable for testing or short-lived
    #: agents.  Keys are lost on process exit.
    IN_MEMORY = "in_memory"


class BridgeMode(enum.Enum):
    """Bridge operating mode (spec section 12.2).

    Determines how a bridge connector relays messages between an
    external platform and an SCP context.
    Mirrors ``scp_core::bridge::BridgeMode``.
    """

    #: Messages forwarded verbatim.  Bridge is a transparent pipe.
    RELAY = "relay"
    #: Bridge controls external-side identity and can act on behalf
    #: of participants.
    PUPPET = "puppet"
    #: Bridge exposes a programmatic API rather than a chat interface.
    API = "api"
    #: Both SCP and external participants have equal agency.
    COOPERATIVE = "cooperative"


class ShadowStatus(enum.Enum):
    """Shadow identity provenance status (spec section 12.2).

    Indicates how a bridged participant's identity was established.
    Used for trust evaluation.
    """

    #: Identity is a shadow -- no verified link to external identity.
    SHADOW = "shadow"
    #: External participant has completed an identity claim verification.
    CLAIMED = "claimed"


class ContextMode(enum.Enum):
    """Context processing mode (spec section 5.1).

    Determines the encryption strategy. Immutable after creation.
    Mirrors ``scp_core::context::ContextMode``.
    """

    #: MLS-backed encryption with forward secrecy (default).
    ENCRYPTED = "encrypted"
    #: Per-author AES-256-GCM broadcast keys, no MLS. Unlimited subscribers.
    BROADCAST = "broadcast"


class CeilingPolicy(enum.Enum):
    """Ceiling mutability policy (spec section 5.3).

    Declared at creation, immutable thereafter.
    Mirrors ``scp_core::context::CeilingPolicy``.
    """

    #: Ceiling is fixed at creation (default, security-conservative).
    IMMUTABLE = "immutable"
    #: Ceiling can be modified through governance (narrowing only).
    GOVERNED = "governed"


class PromotionPolicy(enum.Enum):
    """Context promotion policy (spec section 5.10).

    Declared at creation, immutable thereafter.
    Mirrors ``scp_core::context::PromotionPolicy``.
    """

    #: Context cannot be promoted.
    NO_PROMOTION = "no_promotion"
    #: Context can be promoted through governance approval.
    PROMOTABLE = "promotable"


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
    #: No protocol-level discovery path (out-of-band introduction).
    OUT_OF_BAND = "out_of_band"
    #: Backward-compatible alias for ``OUT_OF_BAND``.
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


class MemberRole(enum.Enum):
    """Role assigned to a member within a context (spec section 5.5).

    Mirrors ``scp_core::context::roles::Role``.
    """

    #: Context administrator with full governance capabilities.
    ADMIN = "Admin"
    #: Moderator with messaging, moderation, and governance proposal capabilities.
    MODERATOR = "Moderator"
    #: Regular participant with standard capabilities.
    MEMBER = "Member"
    #: Read-only observer with no write capabilities.
    OBSERVER = "Observer"
    #: Custom role defined by context governance.
    CUSTOM = "Custom"

    @classmethod
    def from_bridge(cls, raw: str) -> MemberRole:
        """Parse a bridge-layer role string into a :class:`MemberRole`.

        The bridge returns a Rust debug representation. This method
        normalises known variants and falls back to :attr:`CUSTOM` for
        unrecognised strings.
        """
        normalised = raw.strip().strip('"')
        for member in cls:
            if normalised == member.value or normalised.lower() == member.value.lower():
                return member
        return cls.CUSTOM


class Capability(enum.Enum):
    """Protocol-defined capabilities within an SCP context.

    Mirrors ``scp_core::context::roles::Capability``. Values use the
    SDK-facing colon-separated format expected by ``Capability::new`` in
    Rust (e.g. ``"messages:write"``, ``"outlet:call:*"``). Parameterised
    variants (``OutletQuery(outlet_id)``, ``OutletCall(outlet_id)``,
    ``Custom(name)``) are produced by the :meth:`outlet_query`,
    :meth:`outlet_call`, and :meth:`custom` static helpers.

    The pre-rename ``tool:invoke:*`` / ``tool:register`` /
    ``tool:interface`` and the intermediate ``outlet:invoke:*`` stems are
    deleted with no transitional alias (ADR-049 §1, SCP-OUT-014).
    """

    MESSAGES_READ = "messages:read"
    MESSAGES_WRITE = "messages:write"
    OUTLET_QUERY_ALL = "outlet:query:*"
    OUTLET_CALL_ALL = "outlet:call:*"
    OUTLET_REGISTER = "outlet:register"
    MEMBER_INVITE = "member:invite"
    MEMBER_REMOVE = "member:remove"
    ROLE_ASSIGN = "role:assign"
    GOVERNANCE_PROPOSE = "governance:propose"
    GOVERNANCE_VOTE = "governance:vote"
    CONTEXT_CLOSE = "context:close"
    CHILD_CONTEXT_CREATE = "context:child:create"
    OUTLET_INTERFACE = "outlet:interface"
    BRIDGING = "bridging"
    MEDIA_VOICE = "media:voice"
    MEDIA_VIDEO = "media:video"
    MEDIA_SCREEN_SHARE = "media:screen_share"
    MEMBER_BAN = "member:ban"
    METADATA_EDIT = "metadata:edit"

    @staticmethod
    def outlet_query(outlet_id: str) -> str:
        """Return the capability string for invoking a specific Query outlet.

        Since Python enums cannot carry per-instance data, parameterised
        capabilities are represented as plain strings. Per spec §5.4.2.1
        the suffix must match ``^[a-z0-9_-]{1,128}$``.
        """
        return f"outlet:query:{outlet_id}"

    @staticmethod
    def outlet_call(outlet_id: str) -> str:
        """Return the capability string for invoking a specific Action outlet.

        Per spec §5.4.2.1 the suffix must match ``^[a-z0-9_-]{1,128}$``.
        """
        return f"outlet:call:{outlet_id}"

    @staticmethod
    def custom(name: str) -> str:
        """Return the capability string for a custom capability."""
        return name


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
    discovery_method: DiscoveryMethod = DiscoveryMethod.OUT_OF_BAND

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
    "BridgeMode",
    "Capability",
    "CeilingPolicy",
    "ContextMode",
    "CustodyType",
    "DiscoveryMethod",
    "MemberRole",
    "MemoryScope",
    "Message",
    "PromotionPolicy",
    "Provenance",
    "ProvenanceQuality",
    "ShadowStatus",
    "SourceType",
]
