"""SCP Context types.

Phase 4 PR 5 Agent B+C (#1549) collapsed :class:`Context` into a pure
handle wrapper. Every lifecycle/messaging/governance operation that used
to live on :class:`Context` is now a method on :class:`scp_sdk.SCP`.

Typical call-sites shape::

    from scp_sdk import SCP

    with SCP(storage={"type": "in_memory"}) as scp:
        identity = await scp.identity_create("in_memory")
        ctx = await scp.context_create(identity.did, {"ceiling": ["core:send_message"]})
        await scp.context_send(ctx._raw_handle, identity.did, b"hello")

Data classes (:class:`AssetEntry`, :class:`BatchPublishResult`,
:class:`Membership`, :class:`PublishResult`, :class:`SiteConfig`) and
pure validators (``validate_admission``, ``validate_content_path``,
``validate_mime_type``, ``validate_deploy_id``,
``validate_broadcast_key_hex``) remain at module scope — they take no
:class:`SCP` argument.

See ``.docs/adrs/phase-3.md`` ADR-014 for the underlying API design and
ADR-048 for the façade consolidation rationale.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from scp_sdk.errors import ContextError, ValidationError

if TYPE_CHECKING:
    from scp_sdk.outlets import Outlets
    from scp_sdk.scp import SCP


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

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

    Returned by :meth:`scp_sdk.SCP.context_join`.
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

    Returned by :meth:`scp_sdk.SCP.broadcast_publish_asset` and
    :meth:`scp_sdk.SCP.broadcast_publish_assets`.
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

    Returned by :meth:`scp_sdk.SCP.broadcast_publish_assets`.
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
# Context handle wrapper
# ---------------------------------------------------------------------------


class Context:
    """An SCP context handle.

    Pure handle wrapper. The underlying ``PyContextHandle`` is produced by
    :meth:`scp_sdk.SCP.context_create` (and related factory methods). All
    lifecycle, messaging, outlet, broadcast, and governance operations now
    live on :class:`scp_sdk.SCP` — pass ``ctx._raw_handle`` into the
    per-op methods.

    Attributes:
        context_id: Unique identifier for this context.
        state: Lifecycle state (``'creating'``, ``'active'``,
            ``'closing'``, ``'closed'``, ``'expired'``).
        identity_did: DID of the identity this context is scoped to —
            typically the creator's DID, but callers can set it via
            :meth:`_from_handle` to track a different actor.
    """

    __slots__ = ("_raw_handle", "_scp", "identity_did")

    def __init__(self, handle: Any, identity_did: str = "", scp: SCP | None = None) -> None:
        """Wrap a ``PyContextHandle`` bridge handle.

        Users should not call this directly. Use
        :meth:`scp_sdk.SCP.context_create`,
        :meth:`scp_sdk.SCP.context_import`, or related factories.

        ``scp`` is the owning :class:`scp_sdk.SCP` instance; it backs the
        :attr:`outlets` accessor (whose control plane dispatches to the SCP
        native bridge). Factory methods pass it; a bare ``Context(handle)`` for
        pure handle inspection may omit it.
        """
        self._raw_handle = handle
        self.identity_did = identity_did
        self._scp = scp

    @classmethod
    def _from_handle(cls, _scp: SCP | None, raw: Any, identity_did: str = "") -> Context:
        """Internal constructor used by :class:`scp_sdk.SCP` methods."""
        return cls(raw, identity_did=identity_did, scp=_scp)

    @property
    def context_id(self) -> str:
        """Unique identifier for this context."""
        return self._raw_handle.context_id

    @property
    def state(self) -> str:
        """Current lifecycle state of the context."""
        return self._raw_handle.state

    @property
    def outlets(self) -> Outlets:
        """The outlet accessor for this context (§5.4.5, SCP-OUT-038).

        Exposes the single public invocation verb —
        ``ctx.outlets.invoke(outlet_id, input, ucan_token=...)`` — returning an
        :class:`~scp_sdk.outlets.InvocationHandle` that is both awaitable (the
        aggregated result) and async-iterable (per-chunk streaming).

        Raises :class:`~scp_sdk.errors.ContextError` if this ``Context`` was
        created without an owning :class:`scp_sdk.SCP` instance (a bare
        ``Context(handle)`` used only for handle inspection).
        """
        from scp_sdk.outlets import Outlets

        if self._scp is None:
            raise ContextError(
                "Context has no bound SCP instance; obtain the context from an "
                "SCP factory method (e.g. scp.context_create) to use ctx.outlets",
                code="SCP-CTX-2000",
            )
        return Outlets(
            native=self._scp._native,
            context_id=self.context_id,
            default_caller_did=self.identity_did,
        )

    def __repr__(self) -> str:
        return f"Context(context_id={self.context_id!r}, state={self.state!r})"


# ---------------------------------------------------------------------------
# Helpers that remain module-scoped — pure Rust-bridge utilities
# ---------------------------------------------------------------------------


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
            ``GatedBroadcast``, ``scp:template/outlet-interface``,
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
    "AssetEntry",
    "BatchPublishResult",
    "Context",
    "Membership",
    "PublishResult",
    "SiteConfig",
    "metadata_record_from_json",
    "metadata_record_to_json",
    "template_get_params",
    "validate_admission",
    "validate_against_template",
    "validate_broadcast_key_hex",
    "validate_content_path",
    "validate_context_params",
    "validate_deploy_id",
    "validate_mime_type",
]
