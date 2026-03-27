"""SCP Context class with async context manager support.

Wraps the ``_scp_core`` PyO3 bridge functions for context lifecycle,
messaging, and tool invocation.  Resource lifecycle is managed via
``async with`` -- the context manager ensures cleanup (leave context
if still active) on ``__aexit__``.

``receive()`` returns an :class:`AsyncIterator[Message]
<collections.abc.AsyncIterator>` backed by a bounded receive buffer
(default 1,000 events, oldest-drop overflow, ``BufferOverflow`` warning
event emitted on overflow).

See ``.docs/adrs/phase-3.md`` ADR-014 acceptance criterion 2 and
``.docs/standards/sdk-common.md`` §Receive stream buffer tests for the
canonical design.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import unicodedata
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from scp_sdk.errors import ContextError, ValidationError
from scp_sdk.types import (
    Capability,
    CeilingPolicy,
    ContextMode,
    MemberRole,
    MemoryScope,
    Message,
    PromotionPolicy,
)

if TYPE_CHECKING:
    from scp_sdk.identity import Identity

logger = logging.getLogger("scp_sdk")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Default receive buffer capacity (events).
_DEFAULT_BUFFER_SIZE: int = 1_000

#: Minimum configurable buffer size.
_MIN_BUFFER_SIZE: int = 100

#: Maximum configurable buffer size.
_MAX_BUFFER_SIZE: int = 10_000

#: Maximum content path length in bytes.
_MAX_CONTENT_PATH_BYTES: int = 1024

#: Maximum deploy ID length in bytes.
_MAX_DEPLOY_ID_BYTES: int = 128


# ---------------------------------------------------------------------------
# Client-side validation helpers (SCP-297, spec §18.11.9)
# ---------------------------------------------------------------------------


def _is_unicode_formatting(ch: str) -> bool:
    """Return True for Unicode formatting/invisible characters.

    Mirrors the Rust ``is_unicode_formatting`` helper. Covers NBSP, Ogham
    space, typographic spaces, zero-width chars, bidi controls, word joiners,
    invisible operators, BOM, and non-characters.
    """
    cp = ord(ch)
    return (
        cp == 0x00A0  # NBSP
        or cp == 0x1680  # Ogham space mark
        or 0x2000 <= cp <= 0x200F  # Typographic spaces + ZWSP..RLM
        or cp in (0x2028, 0x2029)  # Line/paragraph separators
        or 0x202A <= cp <= 0x202F  # Bidi controls + narrow no-break space
        or cp == 0x205F  # Medium mathematical space
        or 0x2060 <= cp <= 0x206F  # Word joiner, invisible operators
        or cp == 0x3000  # Ideographic space
        or cp == 0xFEFF  # BOM / ZWNBSP
        or cp in (0xFFFE, 0xFFFF)  # Non-characters
    )


def validate_content_path(path: str) -> None:
    """Validate a content path before FFI crossing (SCP-297).

    Mirrors the Rust ``ContentPath::new`` validation from
    ``crates/scp-core/src/context/broadcast_content.rs``.

    Raises:
        ValidationError: If the path is invalid, with a message
            describing the specific violation.
    """
    # NFC-normalize before validation (Fix 3)
    path = unicodedata.normalize("NFC", path)
    if not path.startswith("/"):
        raise ValidationError(
            "ContentPath must start with '/'",
            code="SCP-VALID-7010",
        )
    if len(path.encode("utf-8")) > _MAX_CONTENT_PATH_BYTES:
        raise ValidationError(
            f"ContentPath exceeds {_MAX_CONTENT_PATH_BYTES} bytes",
            code="SCP-VALID-7010",
        )
    if "\\" in path:
        raise ValidationError(
            "ContentPath must not contain backslashes",
            code="SCP-VALID-7010",
        )
    if "%" in path:
        raise ValidationError(
            "ContentPath must not contain percent-encoded bytes",
            code="SCP-VALID-7010",
        )
    if "?" in path:
        raise ValidationError(
            "ContentPath must not contain query strings ('?')",
            code="SCP-VALID-7010",
        )
    if "#" in path:
        raise ValidationError(
            "ContentPath must not contain fragments ('#')",
            code="SCP-VALID-7010",
        )
    if "\0" in path:
        raise ValidationError(
            "ContentPath must not contain null bytes",
            code="SCP-VALID-7010",
        )
    for ch in path:
        cp = ord(ch)
        # C0 controls (U+0000-U+001F), DEL (U+007F), and C1 controls (U+0080-U+009F)
        if cp <= 0x1F or cp == 0x7F or (0x80 <= cp <= 0x9F):
            raise ValidationError(
                f"ContentPath must not contain control character U+{cp:04X}",
                code="SCP-VALID-7010",
            )
    # Reject non-ASCII whitespace, bidi, and formatting characters
    for ch in path:
        if not ch.isascii() and (
            unicodedata.category(ch) in ("Cc", "Zs") or _is_unicode_formatting(ch)
        ):
            raise ValidationError(
                f"ContentPath must not contain non-ASCII whitespace/formatting U+{ord(ch):04X}",
                code="SCP-VALID-7010",
            )
    if "//" in path:
        raise ValidationError(
            "ContentPath must not contain '//'",
            code="SCP-VALID-7010",
        )
    if len(path) > 1 and path.endswith("/"):
        raise ValidationError(
            "ContentPath must not have trailing slash (except root '/')",
            code="SCP-VALID-7010",
        )
    for segment in path.split("/")[1:]:
        if segment == ".":
            raise ValidationError(
                "ContentPath must not contain '.' segments",
                code="SCP-VALID-7010",
            )
        if segment == "..":
            raise ValidationError(
                "ContentPath must not contain '..' segments (directory traversal)",
                code="SCP-VALID-7010",
            )


def _is_mime_tchar(ch: str) -> bool:
    """Return True if ``ch`` is a valid RFC 7230 tchar (minus ``%``).

    tchar = ALPHA / DIGIT / ``!`` / ``#`` / ``$`` / ``&`` / ``'`` /
    ``*`` / ``+`` / ``-`` / ``.`` / ``^`` / ``_`` / backtick / ``|`` / ``~``
    """
    return ch.isascii() and (ch.isalnum() or ch in "!#$&'*+-.^_`|~")


def validate_mime_type(content_type: str) -> None:
    """Validate a MIME type before FFI crossing (SCP-297).

    Mirrors the Rust ``MimeType::new`` validation from
    ``crates/scp-core/src/context/broadcast_content.rs``.

    Raises:
        ValidationError: If the MIME type is invalid, with a message
            describing the specific violation.
    """
    if not content_type:
        raise ValidationError(
            "MimeType must not be empty",
            code="SCP-VALID-7011",
        )
    for ch in content_type:
        cp = ord(ch)
        # C0 controls (U+0000-U+001F), DEL (U+007F), and C1 controls (U+0080-U+009F)
        if cp <= 0x1F or cp == 0x7F or (0x80 <= cp <= 0x9F):
            raise ValidationError(
                f"MimeType must not contain control character U+{cp:04X}",
                code="SCP-VALID-7011",
            )
    if ";" in content_type:
        raise ValidationError(
            "MimeType must not contain parameters (';' not allowed)",
            code="SCP-VALID-7011",
        )
    if content_type.count("/") != 1:
        raise ValidationError(
            "MimeType must be 'type/subtype' (exactly one '/')",
            code="SCP-VALID-7011",
        )
    type_part, subtype_part = content_type.split("/", 1)
    if not type_part or not subtype_part:
        raise ValidationError(
            "MimeType type and subtype must both be non-empty",
            code="SCP-VALID-7011",
        )
    # RFC 7230 §3.2.6 tchar validation
    if not all(_is_mime_tchar(c) for c in type_part):
        raise ValidationError(
            "MimeType type part contains invalid characters",
            code="SCP-VALID-7011",
        )
    if not all(_is_mime_tchar(c) for c in subtype_part):
        raise ValidationError(
            "MimeType subtype part contains invalid characters",
            code="SCP-VALID-7011",
        )


def validate_deploy_id(deploy_id: str) -> None:
    """Validate a deploy ID before FFI crossing (SCP-297).

    Mirrors the Rust ``validate_deploy_id`` from
    ``crates/scp-core/src/context/broadcast_content.rs``.

    Raises:
        ValidationError: If the deploy ID is invalid, with a message
            describing the specific violation.
    """
    if not deploy_id:
        raise ValidationError(
            "deploy_id must not be empty",
            code="SCP-VALID-7012",
        )
    if len(deploy_id.encode("utf-8")) > _MAX_DEPLOY_ID_BYTES:
        raise ValidationError(
            f"deploy_id exceeds {_MAX_DEPLOY_ID_BYTES} bytes",
            code="SCP-VALID-7012",
        )
    if not all(c.isascii() and (c.isalnum() or c in "-_") for c in deploy_id):
        raise ValidationError(
            "deploy_id must be ASCII alphanumeric, '-', or '_'",
            code="SCP-VALID-7012",
        )


# ---------------------------------------------------------------------------
# Membership dataclass
# ---------------------------------------------------------------------------


@dataclass
class Membership:
    """Represents a participant's membership in a context.

    Returned by :meth:`Context.join`.
    """

    #: DID of the member.
    did: str

    #: Role assigned to the member within the context.
    role: str

    #: Identifier of the context the member joined.
    context_id: str


# ---------------------------------------------------------------------------
# AssetEntry and PublishResult — broadcast content delivery (SCP-290)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AssetEntry:
    """An asset to publish to a broadcast context (SCP-290, spec §18.11.8).

    Typed struct to prevent positional transposition of path/content_type/body.
    """

    #: Validated URL path (e.g., ``/index.html``, ``/styles.css``).
    path: str

    #: Validated MIME type (e.g., ``text/html``, ``text/css``).
    content_type: str

    #: Raw content bytes.
    body: bytes


@dataclass(frozen=True)
class PublishResult:
    """Result of publishing an asset to a broadcast context (SCP-290).

    Returned by :meth:`Context.broadcast_publish_asset` and
    :meth:`Context.broadcast_publish_assets`.
    """

    #: Hex-encoded SHA-256 of the serialized broadcast envelope.
    blob_id: str

    #: Hex-encoded SHA-256 of the asset body.
    etag: str

    #: Deploy ID grouping this asset into an atomic deploy.
    deploy_id: str


@dataclass(frozen=True)
class BatchPublishResult:
    """Result of publishing multiple assets to a broadcast context (SCP-292).

    Returned by :meth:`Context.broadcast_publish_assets`.
    """

    #: Individual publish results for each asset.
    results: list[PublishResult]

    #: Shared deploy ID for the batch.
    deploy_id: str


# ---------------------------------------------------------------------------
# SiteConfig — broadcast projection site configuration (SCP-293)
# ---------------------------------------------------------------------------

# RFC 1123 label pattern: alphanumeric + hyphens, 1-63 chars, no leading/trailing hyphens.
_HOSTNAME_LABEL_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")

# CSP keywords that must never appear in a CSP override.
_CSP_FORBIDDEN_KEYWORDS: tuple[str, ...] = (
    "unsafe-eval",
    "unsafe-inline",
    "unsafe-hashes",
)


def _validate_hostname(hostname: str) -> None:
    """Validate *hostname* per RFC 1123.

    Raises :class:`ValueError` if the hostname is invalid.
    """
    if not hostname:
        raise ValueError("hostname must not be empty")
    if len(hostname) > 253:
        raise ValueError("hostname exceeds 253 characters")
    for label in hostname.split("."):
        if not label or len(label) > 63:
            raise ValueError(f"invalid hostname label: '{label}'")
        if not _HOSTNAME_LABEL_RE.match(label):
            raise ValueError(f"hostname label contains invalid characters: '{label}'")


def _validate_csp(csp: str) -> None:
    """Validate a CSP override string.

    Rejects ``unsafe-eval``, ``unsafe-inline``, ``unsafe-hashes``, bare
    ``*``, ``data:``, and ``blob:`` as sources.

    Raises :class:`ValueError` if the CSP is invalid.
    """
    lower = csp.lower()
    for keyword in _CSP_FORBIDDEN_KEYWORDS:
        if keyword in lower:
            raise ValueError(f"CSP must not contain '{keyword}'")
    for token in lower.split():
        if token == "*":
            raise ValueError("CSP must not contain bare wildcard '*'")
        if token == "data:":
            raise ValueError("CSP must not contain 'data:' source")
        if token == "blob:":
            raise ValueError("CSP must not contain 'blob:' source")


@dataclass(frozen=True)
class SiteConfig:
    """Node-local site configuration for broadcast projection (spec §18.11.12).

    Passed to ``enable_site_projection`` to configure path-based HTTP serving
    of broadcast content.  NOT part of governance — deployment concern only.

    Mirrors ``scp_node::projection::SiteConfig``.

    Construction validates ``hostname``, ``deploy_retention_count``, and
    ``csp_override``.  Invalid values raise :class:`ValueError`.
    """

    #: Virtual host hostname (e.g., ``"mysite.example.com"``).
    #: RFC 1123 validated.
    hostname: str

    #: Default path for directory requests (default: ``"/index.html"``).
    index_path: str = "/index.html"

    #: Maximum assets per deploy (default: 10,000).
    max_assets_per_deploy: int = 10_000

    #: Maximum total deploy size in bytes (default: 536,870,912 = 512 MiB).
    max_deploy_size_bytes: int = 536_870_912

    #: Number of deploys to retain (default: 2, max 8).
    deploy_retention_count: int = 2

    #: Optional CSP override. Validated: no ``unsafe-eval``, ``unsafe-inline``,
    #: ``unsafe-hashes``, bare ``*``, ``data:``, ``blob:``.
    csp_override: str | None = None

    def __post_init__(self) -> None:
        _validate_hostname(self.hostname)
        if self.max_assets_per_deploy < 1:
            raise ValueError("max_assets_per_deploy must be >= 1")
        if self.max_deploy_size_bytes < 1:
            raise ValueError("max_deploy_size_bytes must be >= 1")
        if not isinstance(self.deploy_retention_count, int) or not (
            1 <= self.deploy_retention_count <= 8
        ):
            raise ValueError(
                f"deploy_retention_count must be an integer between 1 and 8, "
                f"got {self.deploy_retention_count}"
            )
        if self.csp_override is not None:
            _validate_csp(self.csp_override)


# ---------------------------------------------------------------------------
# Projection parameter validation (SCP-296 post-merge audit)
# ---------------------------------------------------------------------------

#: Regex for a valid 64-character hex string (32 bytes).
_HEX_64_RE = re.compile(r"^[0-9a-fA-F]{64}$")

#: Valid admission policy values accepted by the FFI bridge (lowercase canonical).
_VALID_ADMISSION_POLICIES: frozenset[str] = frozenset({"open", "gated"})


def validate_admission(admission: str) -> None:
    """Validate an admission policy string before FFI.

    Accepts both casings (``"open"``/``"Open"``, ``"gated"``/``"Gated"``)
    because the Rust bridge normalizes via ``.to_lowercase()``.

    Args:
        admission: Must be ``"open"``/``"Open"`` or ``"gated"``/``"Gated"``.

    Raises:
        ValueError: If *admission* is not a recognized policy.
    """
    if admission.lower() not in _VALID_ADMISSION_POLICIES:
        msg = f'admission must be "open" or "gated" (case-insensitive), got "{admission}"'
        raise ValueError(msg)


def validate_broadcast_key_hex(broadcast_key_hex: str) -> None:
    """Validate a broadcast key hex string before FFI.

    The broadcast key must be exactly 64 hex characters (32 bytes).

    Args:
        broadcast_key_hex: Hex-encoded 32-byte AES-256 broadcast key.

    Raises:
        ValueError: If the string is not a valid 64-char hex string.
    """
    if not _HEX_64_RE.match(broadcast_key_hex):
        raise ValueError("broadcast_key_hex must be exactly 64 hex characters (32 bytes)")


# ---------------------------------------------------------------------------
# _ReceiveIterator -- AsyncIterator with buffer semantics
# ---------------------------------------------------------------------------


class _ReceiveIterator(AsyncIterator[Message]):
    """Async iterator over incoming messages from an SCP context.

    Wraps the bridge-level ``PyMessageReceiver`` which returns
    ``asyncio.Future`` objects from ``__anext__``.  Each await yields
    control back to the asyncio event loop so other coroutines can
    make progress while waiting for messages.

    Buffering is managed at the Rust bridge level (capacity 1000,
    oldest-drop).  See ``deliver_message`` in ``runtime.rs``.
    """

    def __init__(self, bridge_receiver: Any) -> None:
        self._receiver = bridge_receiver
        # Buffering is handled at the Rust bridge level (bounded channel
        # with oldest-drop overflow).  No Python-side buffer needed.
        self._closed = False

    def __aiter__(self) -> _ReceiveIterator:
        return self

    async def __anext__(self) -> Message:
        if self._closed:
            raise StopAsyncIteration

        # Await the bridge receiver's __anext__, which returns an
        # asyncio.Future that resolves when a message arrives on the
        # tokio channel.  This yields control to the asyncio event loop
        # so other coroutines can make progress while waiting (fixes #138).
        raw = await self._receiver.__anext__()

        if raw is None:
            # Channel closed (sender dropped) -- stop iteration.
            self._closed = True
            raise StopAsyncIteration

        return Message(
            sender_did=raw.sender_did,
            content=raw.payload,
            timestamp=raw.timestamp,
            # sequence not available from bridge; hardcoded to 0 until event log integration
            sequence=0,
            context_id=raw.context_id,
        )

    def close(self) -> None:
        """Mark the iterator as closed; subsequent iteration will stop."""
        self._closed = True


# ---------------------------------------------------------------------------
# Context class
# ---------------------------------------------------------------------------


class Context:
    """An SCP context with async context manager support.

    Wraps the ``_scp_core`` bridge functions for context lifecycle,
    messaging, and tool invocation.  Use :meth:`create` to construct
    instances.

    Attributes:
        context_id: Unique identifier for this context.
        state: Lifecycle state (``'creating'``, ``'active'``,
            ``'closing'``, ``'closed'``, ``'expired'``).
    """

    def __init__(self, handle: Any, creator_did: str) -> None:
        self._handle = handle
        self._creator_did = creator_did

    # -- Properties ---------------------------------------------------------

    @property
    def context_id(self) -> str:
        """Unique identifier for this context."""
        return self._handle.context_id

    @property
    def state(self) -> str:
        """Current lifecycle state of the context."""
        return self._handle.state

    # -- Factory ------------------------------------------------------------

    @classmethod
    async def create(
        cls,
        creator: Identity,
        ceiling: list[Capability | str],
        tools: list[Any] | None = None,
        roles: dict[str, list[str]] | None = None,
        ttl: float | None = None,
        memory_scope: MemoryScope | str = MemoryScope.FULL,
        governance: str = "single_admin",
        mode: ContextMode | str = ContextMode.ENCRYPTED,
        ceiling_policy: CeilingPolicy | str = CeilingPolicy.IMMUTABLE,
        promotion_policy: PromotionPolicy | str = PromotionPolicy.NO_PROMOTION,
        template_id: str | None = None,
        economic_policy: str | None = None,
        consequence_rules: list | None = None,
    ) -> Context:
        """Create a new SCP context.

        Args:
            creator: The identity creating the context.
            ceiling: Capability ceiling -- maximum capabilities any
                participant can hold.  Accepts :class:`Capability` enum
                members, raw strings, or a mix of both.
            tools: Optional list of tool definitions to register.
            roles: Optional mapping of role names to capability lists.
            ttl: Optional time-to-live in seconds.
            memory_scope: Memory scope.  Accepts a :class:`MemoryScope`
                enum member or a raw string (``'ephemeral'``,
                ``'summary'``, ``'full'``).  Defaults to
                :attr:`MemoryScope.FULL`.
            governance: Governance model.  Defaults to
                ``'single_admin'``.
            mode: Context mode (spec section 5.1).  Accepts a
                :class:`ContextMode` enum member or a raw string
                (``'encrypted'``, ``'broadcast'``).  Defaults to
                :attr:`ContextMode.ENCRYPTED`.
            ceiling_policy: Ceiling mutability policy (spec section 5.3).
                Accepts a :class:`CeilingPolicy` enum member or a raw
                string (``'immutable'``, ``'governed'``).  Defaults to
                :attr:`CeilingPolicy.IMMUTABLE`.
            promotion_policy: Promotion policy (spec section 5.10).
                Accepts a :class:`PromotionPolicy` enum member or a raw
                string (``'no_promotion'``, ``'promotable'``).  Defaults
                to :attr:`PromotionPolicy.NO_PROMOTION`.
            template_id: Optional well-known template identifier
                (spec section 5.14).  When present, all other fields
                must match the template definition.
            economic_policy: Optional economic policy as a JSON string
                (spec section 19).  ``None`` means free context.
            consequence_rules: Optional list of consequence rule
                dictionaries (spec section 9.3, issue #1531).
                ``None`` means no consequence rules.

        Returns:
            A new :class:`Context` in the ``'active'`` state.

        Raises:
            ContextError: If context creation fails.
            ValidationError: If parameters are invalid.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        ceiling_strs = [c.value if isinstance(c, Capability) else c for c in ceiling]
        scope_str = memory_scope.value if isinstance(memory_scope, MemoryScope) else memory_scope
        mode_str = mode.value if isinstance(mode, ContextMode) else mode
        ceiling_policy_str = (
            ceiling_policy.value if isinstance(ceiling_policy, CeilingPolicy) else ceiling_policy
        )
        promotion_policy_str = (
            promotion_policy.value
            if isinstance(promotion_policy, PromotionPolicy)
            else promotion_policy
        )

        params: dict[str, Any] = {
            "ceiling": ceiling_strs,
            "roles": roles or {},
            "tools": [t.name for t in tools] if tools else [],
            "ttl": ttl,
            "memory_scope": scope_str,
            "governance": governance,
            "mode": mode_str,
            "ceiling_policy": ceiling_policy_str,
            "promotion_policy": promotion_policy_str,
            "template_id": template_id,
            "economic_policy": economic_policy,
            "consequence_rules": json.dumps(consequence_rules) if consequence_rules else None,
        }

        handle = await asyncio.to_thread(_scp_core.py_context_create, creator.did, params)
        return cls(handle=handle, creator_did=creator.did)

    # -- Lifecycle ----------------------------------------------------------

    async def join(
        self,
        identity: Identity,
        spending_ucan_jwt: str | None = None,
    ) -> Membership:
        """Join this context with the given identity.

        Args:
            identity: The identity joining the context.
            spending_ucan_jwt: Optional spending UCAN JWT for
                AND-composition with join cost (spec section 19).

        Returns:
            A :class:`Membership` representing the new participant.

        Raises:
            ContextError: If the context is not active.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        await asyncio.to_thread(
            _scp_core.py_context_join,
            self._handle,
            identity.did,
            spending_ucan_jwt,
        )
        return Membership(
            did=identity.did,
            role="member",
            context_id=self.context_id,
        )

    async def leave(self, identity: Identity) -> None:
        """Leave this context with the given identity.

        Args:
            identity: The identity leaving the context.

        Raises:
            ContextError: If the context is not active.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        await asyncio.to_thread(_scp_core.py_context_leave, self._handle, identity.did)

    async def close(self, identity: Identity) -> None:
        """Close this context.

        Requires admin role or ``ContextClose`` capability.

        Args:
            identity: The identity initiating the close.

        Raises:
            ContextError: If the context is not active.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        await asyncio.to_thread(_scp_core.py_context_close, self._handle, identity.did)

    # -- Messaging ----------------------------------------------------------

    async def send(
        self,
        message: str | bytes,
        identity: Identity | None = None,
        spending_ucan_jwt: str | None = None,
    ) -> None:
        """Send a message to this context.

        Args:
            message: The message payload (text or binary).
            identity: The sending identity.  Defaults to the context
                creator if not specified.
            spending_ucan_jwt: Optional spending UCAN JWT for
                AND-composition with message cost (spec section 19).

        Raises:
            ContextError: If the context is not active.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        sender_did = identity.did if identity is not None else self._creator_did
        await asyncio.to_thread(
            _scp_core.py_context_send,
            self._handle,
            sender_did,
            message,
            spending_ucan_jwt,
        )

    async def receive(self) -> AsyncIterator[Message]:
        """Return an async iterator of incoming messages.

        The iterator is backed by a bounded buffer (default 1,000
        events).  When the consumer falls behind, the oldest
        unconsumed event is dropped and a ``BufferOverflow`` warning
        is emitted.

        Returns:
            An :class:`AsyncIterator[Message]
            <collections.abc.AsyncIterator>`.

        Raises:
            ContextError: If the context is not active.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        bridge_receiver = await asyncio.to_thread(_scp_core.py_context_receive, self._handle)
        return _ReceiveIterator(bridge_receiver)

    # -- Tool invocation ----------------------------------------------------

    async def invoke(
        self,
        tool: str,
        input: dict[str, Any],
        ucan_token: str,
        identity: Identity | None = None,
        proof_tokens: list[str] | None = None,
    ) -> dict[str, Any]:
        """Invoke a tool registered in this context.

        Requires a valid UCAN token authorizing the invocation.  The
        token must contain a ``tool_invoke:{tool_id}`` or
        ``tool_invoke:*`` capability scoped to this context.  See
        spec section 6.2, section 8, and ADR-016 for UCAN enforcement.

        .. versionchanged:: 0.2.0
            ``ucan_token`` is now a required positional parameter
            (previously tool invocation did not require UCAN
            authorization).  This is a **breaking change** -- callers
            that previously used ``Context.invoke(tool, input)`` or
            ``Context.invoke(tool, input, identity=...)`` must now
            pass the UCAN token as the third positional argument:
            ``Context.invoke(tool, input, ucan_token)``.
            ``proof_tokens`` was also added as an optional keyword
            argument for delegation chain resolution.

        Args:
            tool: The tool identifier.
            input: Input data as a JSON-compatible dict.
            ucan_token: JWT-encoded UCAN token authorizing the
                invocation.  Validated using the full 11-step ADR-016
                pipeline.
            identity: The invoking identity.  Defaults to the context
                creator if not specified.
            proof_tokens: Optional list of additional UCAN proof
                tokens for delegation chain resolution.

        Returns:
            The tool's output as a JSON-compatible dict.

        Raises:
            ContextError: If the context is not active or the tool is
                not found.
            ToolError: If tool execution fails.
            UcanError: If the UCAN token is invalid, expired, revoked,
                or lacks the required tool invocation capability.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        invoker_did = identity.did if identity is not None else self._creator_did
        result = await asyncio.to_thread(
            _scp_core.tool_invoke,
            self.context_id,
            tool,
            input,
            invoker_did,
            ucan_token,
            proof_tokens,
        )
        return result

    # -- Membership queries -------------------------------------------------

    async def member_count(self) -> int | None:
        """Return the number of members in this context.

        Returns:
            The member count, or ``None`` if the context is not registered.

        Raises:
            ContextError: If the bridge is unavailable.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        result = await asyncio.to_thread(_scp_core.py_context_member_count, self._handle)
        return int(result) if result is not None else None

    async def is_member(self, did: str) -> bool:
        """Check whether a DID is a member of this context.

        Args:
            did: The DID to check.

        Returns:
            ``True`` if the DID is a member.

        Raises:
            ContextError: If the bridge is unavailable.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        return await asyncio.to_thread(_scp_core.py_context_is_member, self._handle, did)

    async def member_dids(self) -> list[str]:
        """Return all member DIDs in this context.

        Returns:
            A list of DID strings.

        Raises:
            ContextError: If the bridge is unavailable.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        return await asyncio.to_thread(_scp_core.py_context_member_dids, self._handle)

    async def member_role(self, did: str) -> MemberRole | None:
        """Return the role of a member in this context.

        Args:
            did: The DID of the member.

        Returns:
            A :class:`MemberRole` enum member, or ``None`` if the
            member is not found.

        Raises:
            ContextError: If the bridge is unavailable.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        raw = await asyncio.to_thread(_scp_core.py_context_member_role, self._handle, did)
        if raw is None:
            return None
        return MemberRole.from_bridge(raw)

    # -- Economic policy ----------------------------------------------------

    async def set_economic_policy(self, policy_json: str) -> None:
        """Set the economic policy for this context (spec section 19).

        Validates the JSON against the ``EconomicPolicy`` schema before
        storing.

        Args:
            policy_json: The economic policy as a JSON string.

        Raises:
            ContextError: If the bridge is unavailable.
            ValidationError: If the JSON is invalid or does not conform
                to the ``EconomicPolicy`` schema.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        await asyncio.to_thread(_scp_core.py_set_economic_policy, self._handle, policy_json)

    async def get_economic_policy(self) -> str | None:
        """Return the economic policy for this context as a JSON string.

        Returns:
            The economic policy JSON, or ``None`` if no policy is set.

        Raises:
            ContextError: If the bridge is unavailable.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        return await asyncio.to_thread(_scp_core.py_get_economic_policy, self._handle)

    # -- Broadcast operations -----------------------------------------------

    async def broadcast_subscribe(self, subscriber_did: str) -> None:
        """Subscribe a DID to this broadcast context.

        For open broadcast contexts, any DID can subscribe. For gated
        contexts, a valid ``messages:read`` UCAN is required.

        Args:
            subscriber_did: The DID subscribing to broadcasts.

        Raises:
            ContextError: If the context is not active or not broadcast.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        await asyncio.to_thread(_scp_core.py_broadcast_subscribe, self._handle, subscriber_did)

    async def broadcast_unsubscribe(
        self,
        subscriber_did: str,
        *,
        rotate_keys: bool = False,
    ) -> None:
        """Unsubscribe a DID from this broadcast context.

        Args:
            subscriber_did: The DID to unsubscribe.
            rotate_keys: When ``True``, all authors rotate their
                broadcast keys after unsubscription.

        Raises:
            ContextError: If the context is not active or not broadcast.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        await asyncio.to_thread(
            _scp_core.py_broadcast_unsubscribe, self._handle, subscriber_did, rotate_keys
        )

    async def broadcast_publish(
        self,
        payload: bytes,
        identity: Identity | None = None,
    ) -> None:
        """Publish a message to this broadcast context.

        The payload is encrypted with the author's broadcast key.

        Args:
            payload: The raw message payload.
            identity: The publishing identity. Defaults to the context
                creator if not specified.

        Raises:
            ContextError: If the context is not active or not broadcast.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        author_did = identity.did if identity is not None else self._creator_did
        await asyncio.to_thread(_scp_core.py_broadcast_publish, self._handle, author_did, payload)

    async def broadcast_publish_asset(
        self,
        asset: AssetEntry,
        identity: Identity | None = None,
        deploy_id: str | None = None,
    ) -> PublishResult:
        """Publish a single asset to this broadcast context (SCP-290).

        Constructs a BroadcastContent from the asset entry, computes an ETag,
        and publishes via the structured content path.

        Args:
            asset: The asset entry containing path, content_type, and body.
            identity: The publishing identity. Defaults to the context
                creator if not specified.
            deploy_id: Optional deploy ID to group assets into atomic deploys.

        Returns:
            A PublishResult with blob_id and etag.

        Raises:
            ContextError: If the context is not active or not broadcast.
            ValidationError: If path, content_type, or deploy_id is invalid (SCP-297).
        """
        # SCP-297: Client-side validation before FFI crossing.
        validate_content_path(asset.path)
        validate_mime_type(asset.content_type)
        if deploy_id is not None:
            validate_deploy_id(deploy_id)

        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        author_did = identity.did if identity is not None else self._creator_did
        result = await asyncio.to_thread(
            _scp_core.py_broadcast_publish_asset,
            self._handle,
            author_did,
            asset.path,
            asset.content_type,
            asset.body,
            deploy_id,
        )
        return PublishResult(
            blob_id=result["blob_id"],
            etag=result["etag"],
            deploy_id=result["deploy_id"],
        )

    async def broadcast_publish_assets(
        self,
        assets: list[AssetEntry],
        identity: Identity | None = None,
        deploy_id: str | None = None,
    ) -> BatchPublishResult:
        """Publish multiple assets to this broadcast context (SCP-290, SCP-292).

        All assets are published with the same deploy_id (auto-generated if
        not provided).

        Args:
            assets: List of AssetEntry objects to publish.
            identity: The publishing identity. Defaults to the context
                creator if not specified.
            deploy_id: Optional deploy ID to group assets into atomic deploys.

        Returns:
            A BatchPublishResult with results and the shared deploy_id.

        Raises:
            ContextError: If any asset fails validation or publish.
            ValidationError: If any path, content_type, or deploy_id is invalid (SCP-297).
        """
        # SCP-297: Client-side validation before FFI crossing.
        for asset in assets:
            validate_content_path(asset.path)
            validate_mime_type(asset.content_type)
        if deploy_id is not None:
            validate_deploy_id(deploy_id)

        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        author_did = identity.did if identity is not None else self._creator_did
        asset_tuples = [(a.path, a.content_type, a.body) for a in assets]
        batch = await asyncio.to_thread(
            _scp_core.py_broadcast_publish_assets,
            self._handle,
            author_did,
            asset_tuples,
            deploy_id,
        )
        # Bridge returns {"results": [...], "deploy_id": "..."}.
        shared_deploy_id = batch["deploy_id"]
        results = [
            PublishResult(
                blob_id=r["blob_id"],
                etag=r["etag"],
                deploy_id=r["deploy_id"],
            )
            for r in batch["results"]
        ]
        return BatchPublishResult(results=results, deploy_id=shared_deploy_id)

    async def broadcast_block_subscriber(
        self,
        subscriber_did: str,
        blocker_did: str | None = None,
    ) -> None:
        """Block a subscriber's read access in this broadcast context.

        Args:
            subscriber_did: The DID of the subscriber to block.
            blocker_did: The DID of the blocker. Defaults to the
                context creator if not specified.

        Raises:
            ContextError: If the operation fails.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        blocker = blocker_did if blocker_did is not None else self._creator_did
        await asyncio.to_thread(
            _scp_core.py_broadcast_block_subscriber, self._handle, subscriber_did, blocker
        )

    async def broadcast_unblock_subscriber(
        self,
        subscriber_did: str,
        unblocker_did: str | None = None,
    ) -> None:
        """Unblock a previously blocked subscriber in this broadcast context.

        Forward-only restoration (section 9.16.8): the unblocked subscriber
        can request the current key on next pull but cannot decrypt content
        from the block period.

        Args:
            subscriber_did: The DID of the subscriber to unblock.
            unblocker_did: The DID of the author performing the unblock.
                Defaults to the context creator if not specified.

        Raises:
            ContextError: If the operation fails.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        unblocker = unblocker_did if unblocker_did is not None else self._creator_did
        await asyncio.to_thread(
            _scp_core.py_broadcast_unblock_subscriber,
            self._handle,
            subscriber_did,
            unblocker,
        )

    async def broadcast_handle_key_request(
        self,
        author_did: str,
        requester_did: str,
    ) -> str:
        """Handle a broadcast key request from a subscriber.

        Args:
            author_did: The DID of the author handling the request.
            requester_did: The DID of the requester.

        Returns:
            A string describing the key request decision.

        Raises:
            ContextError: If the operation fails.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        return await asyncio.to_thread(
            _scp_core.py_broadcast_handle_key_request,
            self._handle,
            author_did,
            requester_did,
        )

    async def broadcast_subscriber_count(self) -> int | None:
        """Return the number of broadcast subscribers for this context.

        Returns:
            The subscriber count, or ``None`` if the context is not
            a broadcast context.

        Raises:
            ContextError: If the bridge is unavailable.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        result = await asyncio.to_thread(_scp_core.py_broadcast_subscriber_count, self._handle)
        return int(result) if result is not None else None

    async def broadcast_is_subscriber(self, did: str) -> bool:
        """Check whether a DID is a broadcast subscriber.

        Args:
            did: The DID to check.

        Returns:
            ``True`` if the DID is a subscriber.

        Raises:
            ContextError: If the bridge is unavailable.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        return await asyncio.to_thread(_scp_core.py_broadcast_is_subscriber, self._handle, did)

    async def broadcast_admission(self) -> str | None:
        """Return the broadcast admission policy for this context.

        Returns:
            The policy as a string (``'Open'`` or ``'Gated'``), or
            ``None`` if not a broadcast context.

        Raises:
            ContextError: If the bridge is unavailable.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        return await asyncio.to_thread(_scp_core.py_broadcast_admission, self._handle)

    # -- Async context manager ----------------------------------------------

    async def __aenter__(self) -> Context:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        """Cleanup: leave context if still active, then destroy local state.

        When the context is in the ``'active'`` state, this method
        performs *participant departure* (sends a ``MemberLeft`` event)
        followed by local crypto-state destruction.  If the context has
        already been left or closed, only local cleanup runs.

        For *admin-level* context closure (which terminates the context
        for all participants and destroys the MLS group), call
        :meth:`close` explicitly before exiting the ``async with``
        block.

        Errors during cleanup are logged but never raised -- callers
        must not be penalized for disposing resources.  After this
        method returns, all local state (sender keys, MLS epoch state,
        transport handles) is released regardless of whether the remote
        leave operation succeeded.
        """
        try:
            if self.state == "active":
                try:
                    import _scp_core

                    await asyncio.to_thread(
                        _scp_core.py_context_leave, self._handle, self._creator_did
                    )
                except Exception:
                    logger.debug(
                        "cleanup: failed to leave context %s",
                        self.context_id,
                        exc_info=True,
                    )
        finally:
            self._destroy_local_state()

    # -- Local cleanup -------------------------------------------------------

    def _destroy_local_state(self) -> None:
        """Release local crypto state (sender keys, MLS epoch, handles).

        Called unconditionally at the end of ``__aexit__`` to satisfy
        the resource lifecycle invariant: after dispose returns, all
        local state is released regardless of remote operation outcomes.

        Errors during destruction are logged but never raised.
        """
        try:
            import _scp_core

            if hasattr(_scp_core, "py_context_destroy_local"):
                _scp_core.py_context_destroy_local(self._handle)
        except Exception:
            logger.debug(
                "cleanup: failed to destroy local state for context %s",
                self.context_id,
                exc_info=True,
            )

    # -- Finalizer (GC safety for long-running processes) -------------------

    def __del__(self) -> None:
        """Release registry resources if the context was not properly closed.

        Called by the garbage collector when the ``Context`` object is
        reclaimed.  This is a last-resort cleanup for processes that do
        not use ``async with`` or forget to call :meth:`close`.

        Errors are silently suppressed -- ``__del__`` must never raise.
        """
        try:
            # Capture handle in a local variable to avoid TOCTOU race:
            # _handle could become None between the check and the use.
            handle = getattr(self, "_handle", None)
            if handle is None:
                return

            creator_did = getattr(self, "_creator_did", None)
            if creator_did is None:
                return

            # Check state via the handle directly (not self.state which
            # re-reads self._handle, re-introducing the race).
            try:
                state = handle.state
            except Exception:
                return

            if state == "active":
                try:
                    import _scp_core

                    _scp_core.py_context_close(handle, creator_did)
                except Exception:
                    # Best-effort: context may already be closed, or
                    # interpreter may be shutting down.
                    pass
        except Exception:
            pass

    # -- Representation -----------------------------------------------------

    def __repr__(self) -> str:
        return f"Context(context_id={self.context_id!r}, state={self.state!r})"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScopedHandle:
    """Capability-restricted context handle (spec section 8.4.2).

    Wraps a context with a whitelist of allowed capabilities. All protocol
    operations must check the whitelist before proceeding. An app cannot
    access protocol operations beyond its declared capabilities.

    Once created, a ``ScopedHandle`` cannot gain additional capabilities
    (no escalation guarantee, spec 8.4.2 rule 4).
    """

    context: Context
    granted_capabilities: tuple[str, ...]
    app_did: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "granted_capabilities", tuple(self.granted_capabilities))

    def has_capability(self, capability: str) -> bool:
        """Check whether a given capability is allowed."""
        import _scp_core

        return _scp_core.py_check_scoped_capability(self.granted_capabilities, capability)

    def check_capability(self, capability: str) -> None:
        """Raise :class:`ContextError` if the capability is not granted."""
        if not self.has_capability(capability):
            msg = f"capability denied: {capability} not granted to app {self.app_did}"
            raise ContextError(msg)


def validate_capability_declaration(
    declaration_json: str,
    ceiling_capabilities: list[str],
    role_capabilities: list[str],
) -> dict[str, Any]:
    """Validate a capability declaration against a context ceiling and role.

    Returns a dict with ``valid`` (bool), ``granted_capabilities`` (list of str),
    ``error`` (str or None), and ``app_did`` (str).

    See spec sections 8.4.1 and 8.4.2.
    """
    import json

    import _scp_core

    result_json = _scp_core.py_validate_capability_declaration(
        declaration_json, ceiling_capabilities, role_capabilities
    )
    return json.loads(result_json)


def evaluate_invitation(
    params_json: str,
    inviter_did: str,
    identity_did: str,
    *,
    policy_json: str | None = None,
    spending_json: str | None = None,
    trusted_dids: list[str] | None = None,
) -> str:
    """Evaluate a context invitation through the sequential pipeline.

    Runs the 4-step evaluation pipeline:

    1. **Template check** -- validates params match the claimed template.
    2. **Economic policy check** -- verifies spending capability for paid
       contexts.
    3. **Auto-accept check** -- evaluates trust, TTL cap, and rate limit
       against a matching auto-accept policy.
    4. **Agent prompt** -- falls through if no auto-accept matches.

    Args:
        params_json: JSON-serialized ``ContextParams`` from the invitation.
        inviter_did: DID string of the identity sending the invitation.
        identity_did: DID string of the local identity receiving the
            invitation. Used to key the rate limit tracker.
        policy_json: Optional JSON-serialized ``AutoAcceptPolicy``. If
            ``None``, the pipeline always falls through to prompt-agent.
        spending_json: Optional JSON-serialized ``SpendingContext``.
            Required when the context has an economic policy requiring
            payment.
        trusted_dids: Optional list of DID strings representing identities
            trusted by the local identity (e.g., shared-context peers).

    Returns:
        ``"auto_accept"`` if the pipeline decided to auto-accept,
        ``"prompt_agent"`` if the agent should be prompted.

    Raises:
        ScpError: If input validation or pipeline evaluation fails.

    Example::

        decision = evaluate_invitation(
            params_json=invitation.params_json,
            inviter_did="did:dht:z6MkBob...",
            identity_did="did:dht:z6MkAlice...",
            policy_json=my_policy_json,
            trusted_dids=["did:dht:z6MkBob..."],
        )
        if decision == "auto_accept":
            await context.join(invitation)

    See ``.docs/standards/sdk-common.md`` "Invitation evaluation" and
    ``.docs/specs/19-economic-governance.md`` sections 19.3, 19.14.
    """
    import json

    import _scp_core

    trusted_dids_json = json.dumps(trusted_dids) if trusted_dids else None
    return _scp_core.evaluate_invitation(
        params_json,
        inviter_did,
        identity_did,
        policy_json,
        spending_json,
        trusted_dids_json,
    )


def metadata_record_to_json(
    context_id: str,
    sequence: int,
    signer_did: str,
    timestamp: int,
    structural: dict[str, Any],
    operational: dict[str, Any],
    signature_hex: str,
) -> str:
    """Serialize a MetadataRecord to a JSON string (spec section 5.7.2).

    Args:
        context_id: The context this metadata describes.
        sequence: Monotonically increasing sequence number (starts at 1).
        signer_did: DID of the admin who signed this record.
        timestamp: Unix timestamp in milliseconds.
        structural: Structural metadata dict (always visible).
        operational: Operational metadata dict (visibility-governed).
        signature_hex: Ed25519 signature as hex string (128 hex chars).

    Returns:
        JSON string of the MetadataRecord.

    Raises:
        ValidationError: If any input is malformed.
    """
    import _scp_core

    return _scp_core.metadata_record_to_json(
        context_id,
        sequence,
        signer_did,
        timestamp,
        json.dumps(structural),
        json.dumps(operational),
        signature_hex,
    )


def metadata_record_from_json(json_str: str) -> dict[str, Any]:
    """Deserialize a MetadataRecord from a JSON string (spec section 5.7.2).

    Args:
        json_str: JSON string of a MetadataRecord.

    Returns:
        Parsed MetadataRecord as a dict.

    Raises:
        ValidationError: If the JSON is malformed or does not match the schema.
    """
    import _scp_core

    validated = _scp_core.metadata_record_from_json(json_str)
    return json.loads(validated)


def template_get_params(template_id: str) -> dict[str, Any]:
    """Get the canonical ContextParams for a well-known template (spec section 5.12.1).

    Args:
        template_id: One of ``BilateralEphemeral``, ``BilateralPersistent``,
            ``Coordination``, ``GroupDiscussion``, ``PublicBroadcast``,
            ``GatedBroadcast``, ``scp:template/tool-interface``,
            ``PaidService``, ``PaidBroadcast``, ``HandleRegistry``.

    Returns:
        ContextParams as a dict.

    Raises:
        ValidationError: If the template ID is not recognized.
    """
    import _scp_core

    result = _scp_core.template_get_params(template_id)
    return json.loads(result)


def validate_against_template(params: dict[str, Any]) -> str | None:
    """Validate that ContextParams match their template definition.

    When ``params`` contains a ``template_id``, every field is compared
    against the canonical template definition.

    Args:
        params: ContextParams dict to validate.

    Returns:
        ``None`` on success, or a string error message on validation failure.

    Raises:
        ValidationError: If the params dict cannot be serialized to JSON.
    """
    import _scp_core

    return _scp_core.validate_against_template(json.dumps(params))


def validate_context_params(params: dict[str, Any]) -> str | None:
    """Validate cross-field invariants for ContextParams regardless of template.

    Currently enforces: ``projection_policy`` must be ``None`` for
    ``Encrypted`` contexts.

    Args:
        params: ContextParams dict to validate.

    Returns:
        ``None`` on success, or a string error message on validation failure.

    Raises:
        ValidationError: If the params dict cannot be serialized to JSON.
    """
    import _scp_core

    return _scp_core.validate_context_params(json.dumps(params))


__all__ = [
    "Context",
    "Membership",
    "ScopedHandle",
    "evaluate_invitation",
    "metadata_record_from_json",
    "metadata_record_to_json",
    "template_get_params",
    "validate_against_template",
    "validate_capability_declaration",
    "validate_context_params",
]
