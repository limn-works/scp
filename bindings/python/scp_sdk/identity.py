"""SCP Identity types.

Phase 4 PR 5 Agent B+C (#1549) collapsed :class:`Identity` into a
pure handle wrapper exposing safe metadata only. Every operation that
used to live on :class:`Identity` as a classmethod or instance method
is now a method on :class:`scp_sdk.SCP` (see ADR-048 and
``scp_sdk.scp.SCP``).

Call sites shape::

    from scp_sdk import SCP, Identity
    from scp_sdk.types import CustodyType

    with SCP() as scp:
        identity = await scp.identity_create(CustodyType.IN_MEMORY)
        # identity is an Identity wrapper — use identity.did / identity.custody_type
        rotated = await scp.identity_rotate_key(identity._raw_handle)

:class:`DIDDocument`, :class:`IdentityAttestation`, and
:class:`RevocationStatus` are pure data classes; they hold no SCP
reference.

See ``.docs/adrs/phase-3.md`` ADR-014 for the underlying API design
and ADR-048 for the façade consolidation rationale.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from scp_sdk.errors import ValidationError
from scp_sdk.types import CustodyType

if TYPE_CHECKING:
    from scp_sdk.scp import SCP


# ---------------------------------------------------------------------------
# DIDDocument
# ---------------------------------------------------------------------------


@dataclass
class DIDDocument:
    """A resolved DID Document.

    Mirrors the ``PyDIDDocument`` returned by
    :meth:`scp_sdk.SCP.identity_resolve`. Fields are extracted from the
    opaque bridge object into a pure-Python dataclass for ergonomic
    access.
    """

    #: The DID string this document describes.
    id: str

    #: Verification methods (list of dicts with ``id``, ``type``,
    #: ``controller``, ``public_key_multibase``).
    verification_methods: list[dict[str, Any]] = field(default_factory=list)

    #: Service entries (list of dicts with ``id``, ``type``,
    #: ``service_endpoint``).
    services: list[dict[str, Any]] = field(default_factory=list)

    #: Alternative identifiers for the DID subject.
    also_known_as: list[str] = field(default_factory=list)

    #: Authentication method references.
    authentication: list[str] = field(default_factory=list)

    #: Assertion method references.
    assertion_methods: list[str] = field(default_factory=list)


def _bridge_doc_to_dataclass(bridge_doc: Any) -> DIDDocument:
    """Convert a ``PyDIDDocument`` bridge object to a :class:`DIDDocument`."""
    return DIDDocument(
        id=bridge_doc.id,
        verification_methods=list(bridge_doc.verification_methods),
        services=list(bridge_doc.services),
        also_known_as=list(bridge_doc.also_known_as),
        authentication=list(bridge_doc.authentication),
        assertion_methods=list(bridge_doc.assertion_methods),
    )


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


class Identity:
    """An SCP identity handle.

    Pure handle wrapper: stores the opaque ``PyIdentity`` raw handle
    produced by the bridge and exposes the safe metadata fields
    (``did``, ``custody_type``, ``agent_public_key_multibase``).

    Construct via :meth:`scp_sdk.SCP.identity_create`,
    :meth:`~scp_sdk.SCP.identity_load`,
    :meth:`~scp_sdk.SCP.identity_create_with_agent_key`, and friends —
    those methods return ``Identity`` instances already wrapped.

    All mutating/effectful operations (``rotate_key``, ``add_agent_key``,
    ``attest_device``, ``execute_recovery``, attestation lifecycle, etc.)
    live as methods on :class:`scp_sdk.SCP`. Pass ``identity._raw_handle``
    when the SCP-level method needs the opaque bridge handle.
    """

    __slots__ = ("_raw_handle",)

    def __init__(self, handle: Any) -> None:
        """Wrap a ``PyIdentity`` bridge handle.

        Users should not call this directly — use the ``scp.identity_*``
        factory methods.
        """
        self._raw_handle = handle

    @classmethod
    def _from_handle(cls, _scp: SCP | None, raw: Any) -> Identity:
        """Internal constructor used by :class:`scp_sdk.SCP` methods.

        The ``_scp`` parameter is accepted for call-site symmetry across
        handle types but not stored — :class:`Identity` holds no SCP
        reference.
        """
        return cls(raw)

    # -- Properties ----------------------------------------------------------

    @property
    def did(self) -> str:
        """The DID string for this identity (e.g. ``"did:dht:z6Mk..."``)."""
        return self._raw_handle.did

    @property
    def custody_type(self) -> CustodyType | str:
        """The custody type used for this identity.

        Returns a :class:`~scp_sdk.types.CustodyType` enum member when
        the value matches a known variant, otherwise the raw string.
        """
        raw = self._raw_handle.custody
        try:
            return CustodyType(raw)
        except ValueError:
            return raw

    @property
    def agent_public_key_multibase(self) -> str | None:
        """The multibase-encoded ``#agent`` verification method key.

        Returns ``None`` when this identity does not have an agent key
        (see :meth:`scp_sdk.SCP.identity_add_agent_key`). Present only
        when the underlying bridge handle exposes the accessor — older
        builds may return ``None`` for either reason.
        """
        return getattr(self._raw_handle, "agent_public_key_multibase", None)

    # -- Dunder methods ------------------------------------------------------

    def __repr__(self) -> str:
        return f"Identity(did={self.did!r}, custody_type={self.custody_type!r})"

    def __str__(self) -> str:
        return self.did


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_finite_int(value: object, field_name: str) -> int:
    """Coerce *value* to a non-negative integer, raising :class:`ValidationError` on:

    - ``bool`` (since ``isinstance(True, int)`` is ``True`` silently)
    - ``str`` (cross-SDK divergence: TypeScript ``Number.isFinite`` rejects strings)
    - non-integer ``float`` (silent truncation: ``1.5`` → ``1``)
    - NaN/Infinity floats (not representable as int)
    - negative integers (Unix timestamps are non-negative)

    Whole-number floats (e.g. ``1700000000.0``) are accepted and coerced to
    ``int`` because JSON parsers commonly deserialize integer fields as floats,
    and lossless coercion is correct behavior at a deserialization boundary.

    Raises ``ValidationError`` with code ``SCP-VALID-7005`` ("Invalid
    field value") to match the TypeScript SDK's behavior — both bridges
    parse the same wire format and should surface the same error type
    and code so cross-language consumers can handle them uniformly.
    """
    if isinstance(value, bool):
        raise ValidationError(
            f"{field_name} must be a finite integer, got bool",
            "SCP-VALID-7005",
        )
    if isinstance(value, str):
        raise ValidationError(
            f"{field_name} must be a number, got str",
            "SCP-VALID-7005",
        )
    if not isinstance(value, (int, float)):
        raise ValidationError(
            f"{field_name} must be a number, got {type(value).__name__}",
            "SCP-VALID-7005",
        )
    if isinstance(value, float):
        import math

        if not math.isfinite(value):
            raise ValidationError(
                f"{field_name} must be a finite integer: {value} is not finite",
                "SCP-VALID-7005",
            )
        if value != int(value):
            raise ValidationError(
                f"{field_name} must be an integer, got non-integer float {value!r}",
                "SCP-VALID-7005",
            )
    result = int(value)  # type: ignore[arg-type]
    if result < 0:
        raise ValidationError(
            f"{field_name} must be non-negative, got {result}",
            "SCP-VALID-7005",
        )
    return result


# ---------------------------------------------------------------------------
# RevocationStatus
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RevocationStatus:
    """Revocation status for an identity attestation (§3.5).

    Mirrors the Rust ``RevocationStatus`` enum:

    - ``Active`` -> ``RevocationStatus(status="active")``
    - ``Revoked { revoked_at, reason }`` ->
      ``RevocationStatus(status="revoked", revoked_at=..., reason=...)``
    """

    #: Status string: ``"active"`` or ``"revoked"``.
    status: str

    #: Unix timestamp (seconds) when the attestation was revoked.
    #: Only present when ``status == "revoked"``.
    revoked_at: int | None = None

    #: Optional human-readable revocation reason.
    #: Only present when ``status == "revoked"``.
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.status == "revoked" and self.revoked_at is None:
            raise ValueError("RevocationStatus with status='revoked' requires revoked_at")
        if self.status not in ("active", "revoked"):
            raise ValueError(
                f"Invalid revocation status: {self.status!r} (expected 'active' or 'revoked')"
            )
        if self.revoked_at is not None:
            object.__setattr__(self, "revoked_at", _parse_finite_int(self.revoked_at, "revoked_at"))


# ---------------------------------------------------------------------------
# IdentityAttestation
# ---------------------------------------------------------------------------


@dataclass
class IdentityAttestation:
    """An identity link attestation binding a DID to an external platform (§3.5).

    Pure data class. Creation, listing, removal, renewal, and verification
    live on :class:`scp_sdk.SCP` as
    :meth:`~scp_sdk.SCP.create_identity_link_attestation`,
    :meth:`~scp_sdk.SCP.identity_link_attestations`,
    :meth:`~scp_sdk.SCP.remove_identity_link_attestation`,
    :meth:`~scp_sdk.SCP.identity_renew_attestation`, and
    :meth:`~scp_sdk.SCP.verify_identity_link_attestation`.

    The ``id`` is deterministically derived as
    ``hex(SHA-256(issuer || platform || handle || issued_at))``.
    """

    #: Deterministic attestation ID.
    id: str

    #: Platform identifier (e.g. ``"github.com"``).
    platform: str

    #: Platform handle or username.
    platform_handle: str

    #: DID verification method that signed this attestation
    #: (e.g. ``"did:dht:z6Mk...#active"``).
    verification_method: str

    #: Unix timestamp (seconds) when the evidence was last verified.
    verified_at: int

    #: Revocation status (``"active"`` or ``"revoked"`` with metadata).
    revocation_status: RevocationStatus = field(
        default_factory=lambda: RevocationStatus(status="active")
    )

    #: Optional platform-assigned unique identifier.
    platform_id: str | None = None

    def __post_init__(self) -> None:
        self.verified_at = _parse_finite_int(self.verified_at, "verified_at")

    def _to_bridge_dict(self) -> dict[str, Any]:
        """Convert to a dict for bridge serialization."""
        rs = self.revocation_status
        if rs.status == "revoked":
            rs_value: dict[str, Any] = {"Revoked": {}}
            if rs.revoked_at is not None:
                rs_value["Revoked"]["revoked_at"] = rs.revoked_at
            if rs.reason is not None:
                rs_value["Revoked"]["reason"] = rs.reason
        else:
            rs_value = "Active"  # type: ignore[assignment]

        d: dict[str, Any] = {
            "id": self.id,
            "platform": self.platform,
            "platform_handle": self.platform_handle,
            "verification_method": self.verification_method,
            "verified_at": self.verified_at,
            "revocation_status": rs_value,
        }
        if self.platform_id is not None:
            d["platform_id"] = self.platform_id
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> IdentityAttestation:
        """Construct from a dict returned by the bridge."""
        raw_rs = data.get("revocation_status", "active")
        if isinstance(raw_rs, dict) and "Revoked" in raw_rs:
            revoked_data = raw_rs["Revoked"]
            revoked_at_raw = revoked_data.get("revoked_at")
            if revoked_at_raw is None:
                raise ValueError("Bridge returned Revoked status without revoked_at timestamp")
            rs = RevocationStatus(
                status="revoked",
                revoked_at=_parse_finite_int(revoked_at_raw, "revoked_at"),
                reason=revoked_data.get("reason"),
            )
        elif isinstance(raw_rs, str) and raw_rs.lower() == "active":
            rs = RevocationStatus(status="active")
        elif isinstance(raw_rs, str) and raw_rs.lower() == "revoked":
            raise ValueError("Bridge returned bare 'revoked' string without revocation metadata")
        else:
            raise ValueError(f"Unknown revocation status from bridge: {raw_rs!r}")

        return cls(
            id=data["id"],
            platform=data["platform"],
            platform_handle=data["platform_handle"],
            verification_method=data["verification_method"],
            verified_at=_parse_finite_int(data["verified_at"], "verified_at"),
            revocation_status=rs,
            platform_id=data.get("platform_id"),
        )

    def __repr__(self) -> str:
        return (
            f"IdentityAttestation(id={self.id!r}, platform={self.platform!r}, "
            f"handle={self.platform_handle!r}, status={self.revocation_status.status!r})"
        )


__all__ = [
    "DIDDocument",
    "Identity",
    "IdentityAttestation",
    "RevocationStatus",
]
