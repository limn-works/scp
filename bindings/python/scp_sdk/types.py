"""Shared types for the SCP Python SDK.

Contains dataclasses and enums used across multiple SDK modules:
``Message``, ``Provenance``, ``Capability``, ``CustodyType``,
``ContextMode``, ``CeilingPolicy``, ``PromotionPolicy``, ``MemoryScope``,
``SourceType``, ``DiscoveryMethod``, and ``ProvenanceQuality``.

All types mirror their Rust counterparts in ``scp-core`` and carry full
PEP 484 type annotations.  See ``.docs/adrs/phase-3.md`` ADR-014 for
the wrapper design and ``.docs/standards/python.md`` for coding
conventions.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field

from scp_sdk.errors import UnknownGovernanceOutcomeError

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class CustodyType(enum.Enum):
    """The custody request value of spec 03 section 3.2.2: the backend that holds
    a new identity's private keys.

    :meth:`scp_sdk.SCP.identity_create` and
    :meth:`scp_sdk.SCP.identity_create_with_agent_key` send the value to the
    PyO3 bridge, and :attr:`scp_sdk.Identity.custody_type` reports the value an
    identity was created with.  The bridge answers every string outside the
    vocabulary, ``"platform"``, ``"software"``, ``"file"`` and ``"callback"``
    included, with ``SCP-VALID-7005``, and falls back to no other backend.

    The type has two members, ``ENCRYPTED_FILE`` and ``OS_KEYSTORE``, and no
    other (spec 03 section 3.2.2).

    No SDK method defaults custody: the caller names the key store, and a call
    that passes none raises ``IdentityError`` carrying ``SCP-IDENT-1116``
    before any bridge call (SCP-294).

    The bridge raises its own exceptions as native ``_scp_core`` classes whose
    message opens with the code:

    - ``ValidationError`` with ``SCP-VALID-7005`` for a string outside the
      vocabulary.
    - ``IdentityError`` with ``SCP-IDENT-1003`` for ``OS_KEYSTORE`` without a
      provider.
    - ``ValidationError`` with ``SCP-VALID-7001`` for ``ENCRYPTED_FILE`` when
      ``HOME`` is unset, empty or relative, or ``SCP_KEY_PASSPHRASE`` is unset
      or empty.

    A build without the ``testing`` feature has no pre-rotation custody
    backend, so an identity-creating call that passes these checks raises
    ``IdentityError`` with ``SCP-IDENT-1059`` (ADR-062 Decision 6), a call to
    :meth:`scp_sdk.SCP.identity_create_with_custody` included.  Only a
    ``testing`` build opens the key file, and it raises ``SCP-IDENT-1008`` when
    it cannot create ``$HOME/.scp`` or open the key file.
    """

    #: ``FileKeyCustody``: an encrypted key file at ``$HOME/.scp/keys.bin``
    #: (Argon2id key derivation, AES-256-GCM), sealed under the passphrase in
    #: ``SCP_KEY_PASSPHRASE``.  The class docstring lists the errors the bridge
    #: raises for it on each build.
    ENCRYPTED_FILE = "encrypted_file"
    #: The host operating system's key store, reached only through a
    #: :class:`scp_sdk.scp.KeyCustodyProvider` passed to
    #: :meth:`scp_sdk.SCP.identity_create_with_custody`.  It promises no
    #: hardware backing.  The class docstring lists the errors the bridge raises
    #: for it on each build.
    OS_KEYSTORE = "os_keystore"


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


#: A custom role name ``validate_role_name`` in
#: ``crates/scp-protocol/src/context/roles.rs`` admits: 1 to 64 bytes of
#: lowercase ASCII letters, digits, hyphens, and underscores, neither starting
#: nor ending with a hyphen or underscore.
_CUSTOM_ROLE_NAME = re.compile(r"[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?")


@dataclass(frozen=True)
class CustomRole:
    """A role a context's governance defined (spec section 5.5).

    Attributes:
        name: The role's name as governance defined it, for example
            ``"night-shift-reviewer"``.
    """

    name: str


class MemberRole(enum.Enum):
    """A protocol-defined role a member holds within a context (spec section 5.5).

    The six members carry the six names ``RESERVED_ROLE_NAMES`` in
    ``crates/scp-protocol/src/context/roles.rs`` reserves. No custom role may
    take any of them, so a member holding one of these names holds the
    protocol-defined role of that name. :meth:`from_bridge` reports every other
    role as a :class:`CustomRole` carrying its name.
    """

    #: Context administrator with full governance capabilities.
    ADMIN = "Admin"
    #: Moderator with messaging, moderation, and governance proposal capabilities.
    MODERATOR = "Moderator"
    #: Regular participant with standard capabilities.
    MEMBER = "Member"
    #: Read-only observer with no write capabilities.
    OBSERVER = "Observer"
    #: Broadcast author: writes messages and holds the outlet capabilities.
    AUTHOR = "Author"
    #: Broadcast subscriber: the role a broadcast subscribe assigns; reads only.
    SUBSCRIBER = "Subscriber"

    @classmethod
    def from_bridge(cls, raw: str) -> MemberRole | CustomRole:
        """Parse a bridge-layer role name.

        Every bridge reports ``RoleAssignment.role_name``, which stores a
        built-in role in lowercase (``"author"``) and a custom role under the
        name governance gave it. Matching is exact.

        Raises:
            UnknownGovernanceOutcomeError: ``raw`` is neither a built-in role
                name nor a name ``validate_role_name`` admits for a custom
                role (code ``SCP-GOV-11040``).
        """
        for member in cls:
            if raw == member.value.lower():
                return member
        if _CUSTOM_ROLE_NAME.fullmatch(raw) is None:
            msg = (
                f"bridge reported role name {raw!r}, which is neither a built-in "
                "nor a valid custom role name"
            )
            raise UnknownGovernanceOutcomeError(msg, raw_outcome=raw)
        return CustomRole(name=raw)


class Capability(enum.Enum):
    """Protocol-defined capabilities within an SCP context.

    Mirrors ``scp_core::context::roles::Capability``. Values use the
    SDK-facing colon-separated format expected by ``Capability::new`` in
    Rust (e.g. ``"messages:write"``, ``"outlet:call:*"``). Parameterised
    variants (``OutletQuery(outlet_id)``, ``OutletCall(outlet_id)``,
    ``Custom(name)``) are produced by the :meth:`outlet_query`,
    :meth:`outlet_call`, and :meth:`custom` static helpers.

    The pre-rename outlet-prefixed capability stems (invoke / register /
    interface) are deleted with no transitional alias; the protocol
    hard-rejects them at construction time (ADR-049 §1).
    """

    MESSAGES_READ = "messages:read"
    MESSAGES_WRITE = "messages:write"
    #: Query outlet capability — read-only; never billed.
    OUTLET_QUERY_ALL = "outlet:query:*"
    #: Action outlet capability — the outlet may mutate state and may incur
    #: cost (billable).
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
    MEDIA_VOICE = "media:voice"
    MEDIA_VIDEO = "media:video"
    MEDIA_SCREEN_SHARE = "media:screen_share"
    MEMBER_BAN = "member:ban"
    METADATA_EDIT = "metadata:edit"

    @staticmethod
    def outlet_query(outlet_id: str) -> str:
        """Return the capability string for invoking a specific Query outlet.

        Query outlet capability — read-only; never billed.

        Since Python enums cannot carry per-instance data, parameterised
        capabilities are represented as plain strings. Per spec §5.4.2.1
        the suffix must match ``^[a-z0-9_-]{1,128}$``.
        """
        return f"outlet:query:{outlet_id}"

    @staticmethod
    def outlet_call(outlet_id: str) -> str:
        """Return the capability string for invoking a specific Action outlet.

        Action outlet capability — the outlet may mutate state and may
        incur cost (billable).

        Since Python enums cannot carry per-instance data, parameterised
        capabilities are represented as plain strings. Per spec §5.4.2.1
        the suffix must match ``^[a-z0-9_-]{1,128}$``.
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
    "Capability",
    "CeilingPolicy",
    "ContextMode",
    "CustodyType",
    "CustomRole",
    "DiscoveryMethod",
    "MemberRole",
    "MemoryScope",
    "Message",
    "PromotionPolicy",
    "Provenance",
    "ProvenanceQuality",
    "SourceType",
]
