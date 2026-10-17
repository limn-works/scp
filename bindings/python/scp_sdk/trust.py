"""Trust evaluation for the SCP Python SDK.

Provides :func:`evaluate_trust` and the :class:`TrustEvaluation`
dataclass for assessing the trustworthiness of a participant within
an SCP context.  Trust evaluation is a four-layer model:

1. **Protocol Enforcement** -- mechanical pass/fail (UCAN validity,
   signatures, capability ceiling, nonce, revocation, and expiry).
2. **Behavioral Validation** -- verified facts from the event log
   (participation history, governance actions, outlet usage).
3. **Attestation Authenticity** -- verified signatures and evidence
   freshness from attestations.

:func:`evaluate_trust` returns these first three layers as a
:class:`TrustEvaluation` (the same shape across all four SDKs). The Layer-4
trust-evaluation inputs (endorsements, challenge results, consequence
structures) are gathered separately via :func:`aggregate_trust_input`.

See ``.docs/sketch.md`` section ``SCP.Trust.evaluate`` and
``.docs/adrs/phase-3.md`` ADR-014 for the SDK design. The structured
``ucan_evaluate`` consumption (Layer 1 / :class:`CapabilityValidation`) is
governed by ``.docs/adrs/phase-2.md`` ADR-059 and
``.docs/specs/07-trust-validation-and-capabilities.md`` §7.2.4: the SDK
consumes the typed per-stage result and never reverse-engineers which check
failed by parsing error prose.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import asdict, dataclass, field, fields
from typing import TYPE_CHECKING, Any, TypedDict

from scp_sdk._extension import native_module
from scp_sdk.errors import ContextError, ScpError, ValidationError, _coded_bridge_error

if TYPE_CHECKING:
    from scp_sdk.identity import Identity
    from scp_sdk.scp import SCP

logger = logging.getLogger("scp_sdk")

#: Stable error code (spec §7.3.2) the core surfaces when a context has no
#: recorded participation facts yet (an empty event log). :func:`evaluate_trust`
#: branches Layer 2 on this STRUCTURED code — never on error prose — folding
#: "no facts yet" into a zeroed behavioral record while letting every other
#: failure propagate. Maps from ``ContextError::NoParticipationFacts``.
NO_PARTICIPATION_FACTS_CODE = "SCP-CTX-2076"


# ---------------------------------------------------------------------------
# Lazy bridge import helper
# ---------------------------------------------------------------------------


def _bridge() -> Any:
    """Return the ``_scp_core`` extension module, imported lazily."""
    return native_module()


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class CapabilityValidation:
    """Layer 1: Protocol enforcement results (mechanical, pass/fail).

    All fields must be ``True`` for the subject to be considered
    protocol-compliant.

    These six per-stage booleans are the canonical structured result of
    the read-only ``ucan_evaluate`` diagnostic (spec §7.2.4, ADR-059):
    one boolean per pipeline-stage group of the 11-step ADR-016 pipeline.
    They are populated directly from the bridge's structured result --
    never reverse-engineered by parsing error prose. The result is
    strictly ordered and short-circuiting: a field is ``True`` only if its
    stage ran *and* passed, so the first failing stage and every later
    stage are ``False``.
    """

    #: UCAN tokens parse and have valid structure (step 1).
    tokens_valid: bool = False

    #: Signatures, the full delegation chain, root issuer, audience, key
    #: scope, Category-A enforcement, and attenuation verify (steps 2-7). The
    #: invoked-capability grant-match (step 6) is included ONLY when a
    #: challenge capability is supplied; in the diagnostic's intrinsic-validity
    #: mode (the mode :func:`evaluate_trust` uses — no challenge), step 6 is
    #: SKIPPED and this field reflects only the structural checks, not
    #: grant-match.
    signatures_valid: bool = False

    #: Requested capabilities are within the context's ceiling (step 8).
    within_ceiling: bool = False

    #: Nonce validation passed (step 9: no reuse, not stale, valid format).
    #: Probed read-only by the diagnostic -- the nonce is NOT recorded.
    nonce_valid: bool = False

    #: No tokens have been revoked (step 10).
    not_revoked: bool = False

    #: Token time bounds are valid (step 11: not expired, not pre-dated,
    #: valid range).
    time_bounds_valid: bool = False

    @property
    def all_valid(self) -> bool:
        """``True`` iff every per-stage check passed.

        The one obvious correct happy-path call: collapses the six per-stage
        booleans with a logical AND so consumers do not hand-roll the
        conjunction (and cannot silently omit a field when a new stage is
        added). A token is protocol-compliant only when all six are ``True``.

        SECURITY: this is a DIAGNOSTIC, NEVER an authorization decision. It
        reports that the UCAN tokens are *intrinsically well-formed and valid*;
        it does NOT authorize any action. In intrinsic mode (capability =
        ``None`` — no challenge capability supplied, the mode
        :func:`evaluate_trust` uses), the invoked-capability grant-match
        (step 6) is SKIPPED, so ``all_valid`` (and ``signatures_valid`` /
        ``within_ceiling``) being ``True`` does NOT assert that any specific
        capability is granted. The diagnostic is also read-only: the nonce is
        probed but NOT consumed, so the evaluated tokens remain replayable
        against the enforcing path — another reason this is never an
        authorization decision. To gate an action, pass the concrete capability
        to ``ucan_evaluate`` (which then includes grant-match in
        ``signatures_valid``) — or use the enforcing UCAN validation path
        (which consumes the nonce). Treating ``all_valid`` as "the agent may
        do X" is a security error.
        """
        return (
            self.tokens_valid
            and self.signatures_valid
            and self.within_ceiling
            and self.nonce_valid
            and self.not_revoked
            and self.time_bounds_valid
        )


@dataclass
class BehavioralRecord:
    """Layer 2: the participation facts (§7.3.2) for a subject in a context.

    The scalar projection of scp-core's ``ParticipationRecord``, computed
    ONCE in the shared Rust core and surfaced through the PyO3
    ``participation_record`` op (``_scp_core.SCP.participation_record`` →
    ``PyParticipationRecord``). The SDK RECEIVES these facts rather than
    re-aggregating event-log collections client-side — eliminating
    cross-binding divergence by construction. Mirrors the TypeScript SDK
    ``BehavioralRecord`` interface and the Rust ``ParticipationFacts`` 1:1.

    The six leaf-derived facts (participation duration, governance actions
    against/by, context creation, role progression, outlet invocation count)
    come from the context's convergent Merkle event log.
    ``attestation_count`` is the one exception: it is a credential-layer fact
    (§7.4), NOT event-log-derived and NOT covered by ``event_log_root``, and
    is **verifier-relative** (two agents may compute different counts from
    different accessible attestation sets). ``outlet_invocation_count_anchored``
    stays ``False`` until ADR-051 makes ``OutletInvoked`` a convergent leaf.
    """

    #: The DID whose participation is summarized.
    subject_did: str = ""

    #: Total seconds of context participation (§7.3.2).
    participation_duration_secs: int = 0

    #: Count of governance actions taken against this identity (the subject is
    #: the projected target).
    governance_actions_against: int = 0

    #: Count of governance actions initiated by this identity.
    governance_actions_by: int = 0

    #: Total outlet invocations across all outlet types.
    outlet_invocation_count: int = 0

    #: Whether ``outlet_invocation_count`` is anchored in the canonical Merkle
    #: log. ``False`` until ADR-051 makes ``OutletInvoked`` a convergent leaf —
    #: consumers MUST NOT treat the count as Merkle-proven while this is
    #: ``False``.
    outlet_invocation_count_anchored: bool = False

    #: Number of contexts created by the subject (``ChildContextCreated``).
    context_creation_count: int = 0

    #: Number of role transitions for the subject (``RoleAssigned``).
    role_progression_count: int = 0

    #: Number of accessible, currently-valid credential-layer attestations
    #: (§7.4) for the subject. Verifier-relative; NOT a context-event count.
    attestation_count: int = 0

    #: Whether ``attestation_count`` is anchored in / verifiable against a
    #: context Merkle root. Always ``False``: it is a credential-layer,
    #: verifier-relative fact (§7.4), never a context-event-log count (§7.3.2).
    #: The parallel of ``outlet_invocation_count_anchored`` — consumers MUST NOT
    #: treat the count as Merkle-proven while this is ``False``.
    attestation_count_anchored: bool = False

    #: Unix timestamp (seconds) when the record was computed.
    computed_at: int = 0

    #: Merkle root (hex) of the event log at computation time.
    event_log_root: str = ""


@dataclass
class AttestationSummary:
    """Layer 3: A summary of an attestation for the subject.

    The canonical 4-field shape shared 1:1 with the TypeScript, Swift, and
    Kotlin SDKs' ``AttestationSummary`` — identical across all four bindings
    (Agent-first API design tenet).
    """

    #: Attestation type.
    type: str

    #: Issuer DID.
    issuer: str

    #: Whether the attestation is currently valid.
    valid: bool

    #: Whether the attestation has been revoked.
    revoked: bool


@dataclass
class TrustEvaluation:
    """Complete trust evaluation result for a subject in a context.

    Surfaces the first three layers of the trust model: protocol enforcement
    (Layer 1), behavioral validation (Layer 2), and attestation authenticity
    (Layer 3). The agent/client decides what to do with this information — the
    protocol provides the data, not the verdict. This shape is identical across
    all four SDKs (Python/TypeScript/Swift/Kotlin) for the ``evaluate_trust``
    op (Agent-first API design tenet).

    The Layer-4 trust-evaluation inputs (endorsements, challenge results,
    consequence structures) are NOT part of this op's result — they are gathered
    separately via :func:`aggregate_trust_input`, which returns the raw
    ``TrustInput`` the core aggregates.

    See ``.docs/sketch.md`` section ``SCP.Trust.evaluate``.
    """

    #: DID of the evaluated subject.
    subject_did: str

    #: ID of the context the evaluation applies to.
    context_id: str

    #: Layer 1: Protocol enforcement (mechanical pass/fail).
    capability_validation: CapabilityValidation = field(
        default_factory=CapabilityValidation,
    )

    #: Layer 2: Behavioral validation (verified facts). Always a record, never
    #: ``None`` — a context with no recorded participation facts yet (an empty
    #: event log) yields a zeroed :class:`BehavioralRecord` (all counts 0,
    #: ``*_anchored`` ``False``), so this field is non-null and identical in
    #: shape to the TypeScript SDK's ``behavioralRecord``.
    behavioral_record: BehavioralRecord = field(default_factory=BehavioralRecord)

    #: Layer 3: Attestation authenticity (verified signatures).
    attestations: list[AttestationSummary] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Participation types (spec §7.3.2.1, SCP-BA-004)
# ---------------------------------------------------------------------------

#: Valid participation fact category names, matching the Rust
#: ``ParticipationFact`` enum variants in ``scp-core``.
PARTICIPATION_FACT_VARIANTS: frozenset[str] = frozenset(
    {
        "ParticipationDuration",
        "GovernanceActionsAgainst",
        "GovernanceActionsBy",
        "OutletInvocationCount",
        "ContextCreationCount",
        "RoleProgressionCount",
        "AttestationCount",
    }
)

#: Valid participation threshold operator names, matching the Rust
#: ``ParticipationThreshold`` enum variants in ``scp-core``.
PARTICIPATION_THRESHOLD_OPERATORS: frozenset[str] = frozenset(
    {
        "GreaterThan",
        "LessThan",
        "AtLeast",
        "AtMost",
        "Equals",
    }
)


@dataclass
class ParticipationFact:
    """Which category of participation fact to evaluate for admission.

    Each variant corresponds to one of the 7 fact categories in a
    :class:`ParticipationProfile`. See §7.3.2.1.

    Valid ``name`` values (matching Rust ``ParticipationFact`` enum):

    - ``"ParticipationDuration"`` -- total seconds of context participation.
    - ``"GovernanceActionsAgainst"`` -- actions taken against the identity.
    - ``"GovernanceActionsBy"`` -- actions initiated by the identity.
    - ``"OutletInvocationCount"`` -- total outlet invocations.
    - ``"ContextCreationCount"`` -- number of contexts created.
    - ``"RoleProgressionCount"`` -- number of role transitions.
    - ``"AttestationCount"`` -- number of attestation events.
    """

    #: The participation fact variant name.
    name: str

    def __post_init__(self) -> None:
        if self.name not in PARTICIPATION_FACT_VARIANTS:
            msg = (
                f"Invalid ParticipationFact name {self.name!r}. "
                f"Valid: {sorted(PARTICIPATION_FACT_VARIANTS)}"
            )
            raise ValueError(msg)


@dataclass
class ParticipationThreshold:
    """Comparison operator and value for participation admission thresholds.

    Used in :class:`RequireParticipation` to specify the comparison a
    fact value must satisfy. See §7.3.2.1.

    Valid ``operator`` values (matching Rust ``ParticipationThreshold`` enum):

    - ``"GreaterThan"`` -- value must be strictly greater than ``value``.
    - ``"LessThan"`` -- value must be strictly less than ``value``.
    - ``"AtLeast"`` -- value must be >= ``value``.
    - ``"AtMost"`` -- value must be <= ``value``.
    - ``"Equals"`` -- value must equal ``value`` exactly.
    """

    #: The threshold operator name.
    operator: str

    #: The threshold comparison value.
    value: int

    def __post_init__(self) -> None:
        if self.operator not in PARTICIPATION_THRESHOLD_OPERATORS:
            msg = (
                f"Invalid ParticipationThreshold operator {self.operator!r}. "
                f"Valid: {sorted(PARTICIPATION_THRESHOLD_OPERATORS)}"
            )
            raise ValueError(msg)
        if self.value < 0:
            msg = (
                f"ParticipationThreshold.value must be non-negative "
                f"(Rust type is u64), got {self.value}"
            )
            raise ValueError(msg)
        if self.value > 0xFFFF_FFFF_FFFF_FFFF:
            msg = (
                f"ParticipationThreshold.value must be <= 18446744073709551615 "
                f"(Rust type is u64), got {self.value}"
            )
            raise ValueError(msg)


@dataclass
class ParticipationProfile:
    """A context-hosted participation profile attesting to a member's
    verifiable participation facts.

    Produced by contexts for opted-in members. The profile is signed
    by a context-specific Ed25519 key (derived with domain separation)
    so that verifiers cannot correlate which contexts share a signer.

    See §7.3.2.1.
    """

    #: DID of the member this profile is about.
    subject_did: str

    #: Total seconds of context participation.
    participation_duration_secs: int = 0

    #: Count of governance actions taken against this identity.
    governance_actions_against: int = 0

    #: Count of governance actions initiated by this identity.
    governance_actions_by: int = 0

    #: Total outlet invocations across all outlet types.
    outlet_invocation_count: int = 0

    #: Whether ``outlet_invocation_count`` is anchored in the canonical Merkle
    #: log. ``False`` until ADR-051 makes ``OutletInvoked`` a convergent leaf:
    #: the count is computed from per-author local events, not the Merkle log
    #: (§7.3.2; ADR-011 amendment exclusion taxonomy §2). Consumers MUST NOT
    #: treat the count as Merkle-proven while this is ``False``.
    outlet_invocation_count_anchored: bool = False

    #: Number of contexts created.
    context_creation_count: int = 0

    #: Number of role transitions.
    role_progression_count: int = 0

    #: Number of attestation events.
    attestation_count: int = 0

    #: Unix timestamp (seconds) of the last update to this profile.
    updated_at: int = 0

    #: Merkle root of the context's event log at profile computation
    #: time. 32-byte array as a list of integers.
    event_log_root: list[int] = field(default_factory=lambda: [0] * 32)

    #: Context-specific Ed25519 public key used to sign this profile.
    #: 32-byte array as a list of integers.
    signer_public_key: list[int] = field(default_factory=lambda: [0] * 32)

    #: Ed25519 signature over all fields except this one.
    #: 64-byte array as a list of integers.
    signature: list[int] = field(default_factory=lambda: [0] * 64)

    def __post_init__(self) -> None:
        # Non-negative validation for u64 numeric fields.
        _u64_fields = (
            "participation_duration_secs",
            "governance_actions_against",
            "governance_actions_by",
            "outlet_invocation_count",
            "context_creation_count",
            "role_progression_count",
            "attestation_count",
            "updated_at",
        )
        for name in _u64_fields:
            val = getattr(self, name)
            if val < 0:
                msg = (
                    f"ParticipationProfile.{name} must be non-negative "
                    f"(Rust type is u64), got {val}"
                )
                raise ValueError(msg)
            if val > 0xFFFF_FFFF_FFFF_FFFF:
                msg = (
                    f"ParticipationProfile.{name} must be <= 18446744073709551615 "
                    f"(Rust type is u64), got {val}"
                )
                raise ValueError(msg)

        # Byte array length validation.
        _byte_fields: list[tuple[str, int]] = [
            ("event_log_root", 32),
            ("signer_public_key", 32),
            ("signature", 64),
        ]
        for name, expected_len in _byte_fields:
            arr = getattr(self, name)
            if len(arr) != expected_len:
                msg = (
                    f"ParticipationProfile.{name} must be exactly {expected_len} "
                    f"elements, got {len(arr)}"
                )
                raise ValueError(msg)
            for i, elem in enumerate(arr):
                if not (0 <= elem <= 255):
                    msg = f"ParticipationProfile.{name}[{i}] must be 0-255, got {elem}"
                    raise ValueError(msg)

    def _to_bridge_dict(self) -> dict[str, Any]:
        """Convert to a dict matching the Rust ``ParticipationProfile``
        serde JSON representation."""
        return {
            "subject_did": self.subject_did,
            "participation_duration_secs": self.participation_duration_secs,
            "governance_actions_against": self.governance_actions_against,
            "governance_actions_by": self.governance_actions_by,
            "outlet_invocation_count": self.outlet_invocation_count,
            "outlet_invocation_count_anchored": self.outlet_invocation_count_anchored,
            "context_creation_count": self.context_creation_count,
            "role_progression_count": self.role_progression_count,
            "attestation_count": self.attestation_count,
            "updated_at": self.updated_at,
            "event_log_root": self.event_log_root,
            "signer_public_key": self.signer_public_key,
            "signature": self.signature,
        }


@dataclass
class RequireParticipation:
    """A participation admission requirement declared by a context.

    Contexts include one or more ``RequireParticipation`` entries in
    their ``ContextParams`` admission requirements. Each entry
    specifies a participation fact, a threshold, a freshness
    requirement, and a minimum number of independent source contexts.

    See §7.3.2.1.
    """

    #: Which participation category to evaluate.
    fact: ParticipationFact

    #: Comparison operator and value.
    threshold: ParticipationThreshold

    #: Maximum age in seconds for the profile's ``updated_at``
    #: timestamp. Profiles older than this are rejected.
    #: SDK convenience default: 3600 (1 hour).
    max_age_secs: int = 3600

    #: Minimum number of independent source contexts (distinct
    #: ``signer_public_key`` values) required.
    #: SDK convenience default: 1. Rust type is u32 (max 4294967295).
    min_contexts: int = 1

    def __post_init__(self) -> None:
        if self.max_age_secs < 0:
            msg = (
                f"RequireParticipation.max_age_secs must be non-negative "
                f"(Rust type is u64), got {self.max_age_secs}"
            )
            raise ValueError(msg)
        if self.max_age_secs > 0xFFFF_FFFF_FFFF_FFFF:
            msg = (
                f"RequireParticipation.max_age_secs must be <= 18446744073709551615 "
                f"(Rust type is u64), got {self.max_age_secs}"
            )
            raise ValueError(msg)
        if self.min_contexts < 0:
            msg = (
                f"RequireParticipation.min_contexts must be non-negative "
                f"(Rust type is u32), got {self.min_contexts}"
            )
            raise ValueError(msg)
        if self.min_contexts > 0xFFFF_FFFF:
            msg = (
                f"RequireParticipation.min_contexts must be <= 4294967295 "
                f"(Rust type is u32), got {self.min_contexts}"
            )
            raise ValueError(msg)

    def _to_bridge_dict(self) -> dict[str, Any]:
        """Convert to a dict matching the Rust ``RequireParticipation``
        serde JSON representation."""
        return {
            "fact": self.fact.name,
            "threshold": {self.threshold.operator: self.threshold.value},
            "max_age_secs": self.max_age_secs,
            "min_contexts": self.min_contexts,
        }


# ---------------------------------------------------------------------------
# Capability admission types (spec §7.3.4.4, SCP-ACR-008, ADR-058)
# ---------------------------------------------------------------------------

#: The code a malformed capability requirement carries, the bridge's
#: ``AdmissionError::InvalidRequirement`` code (spec 07 §7.3.4.4). A
#: :class:`ChallengeVerified` without a trusted verifier raises it when it is
#: constructed, and the bridge raises it for the same defect.
INVALID_REQUIREMENT_CODE = "SCP-VALID-7150"


@dataclass(frozen=True)
class RetryCap:
    """The most retries and the least cooldown a context accepts from a
    challenger's standard (spec 07 §7.3.4.4).

    A record graded under more retries or a shorter cooldown does not meet the
    requirement.
    """

    #: The most retries the challenger's standard may allow.
    max_retries: int
    #: The shortest cooldown, in seconds, the challenger's standard may set.
    min_cooldown_secs: int

    def __post_init__(self) -> None:
        _require_uint("RetryCap.max_retries", self.max_retries, 32)
        _require_uint("RetryCap.min_cooldown_secs", self.min_cooldown_secs, 32)


@dataclass(frozen=True)
class SelfAttested:
    """A requirement the agent meets by listing ``capability`` among its own
    capabilities; no challenge record is needed (spec 07 §7.3.4.4)."""

    #: The capability URI the agent must declare.
    capability: str

    def __post_init__(self) -> None:
        _require_str("SelfAttested.capability", self.capability)

    def _to_bridge_dict(self) -> dict[str, Any]:
        """Convert to the Rust ``RawCapabilityRequirement`` serde JSON shape."""
        return {
            "capability": self.capability,
            "verification_level": "SelfAttested",
            "trusted_verifiers": [],
            "retry_cap": None,
        }


@dataclass(frozen=True)
class ChallengeVerified:
    """A requirement the agent meets only with a passing challenge record
    signed by one of ``trusted_verifiers`` (spec 07 §7.3.4.4).

    Raises:
        ValidationError: :data:`INVALID_REQUIREMENT_CODE` (``SCP-VALID-7150``)
            when ``trusted_verifiers`` is empty, because a record from no
            verifier can meet the requirement.
    """

    #: The capability URI the record must name.
    capability: str
    #: DIDs of the challengers whose records count. At least one.
    trusted_verifiers: list[str]
    #: The retry and cooldown bounds a record's standard must meet;
    #: ``None`` leaves only the capability definition's bounds.
    retry_cap: RetryCap | None = None

    def __post_init__(self) -> None:
        _require_str("ChallengeVerified.capability", self.capability)
        if not isinstance(self.trusted_verifiers, list) or not all(
            isinstance(v, str) for v in self.trusted_verifiers
        ):
            msg = (
                "ChallengeVerified.trusted_verifiers must be a list of DID strings, "
                f"got {self.trusted_verifiers!r}"
            )
            raise ValidationError(msg, INVALID_REQUIREMENT_CODE)
        if not self.trusted_verifiers:
            msg = "ChallengeVerified.trusted_verifiers must name at least one verifier"
            raise ValidationError(msg, INVALID_REQUIREMENT_CODE)
        if self.retry_cap is not None and not isinstance(self.retry_cap, RetryCap):
            msg = f"ChallengeVerified.retry_cap must be a RetryCap, got {self.retry_cap!r}"
            raise ValidationError(msg, INVALID_REQUIREMENT_CODE)

    def _to_bridge_dict(self) -> dict[str, Any]:
        """Convert to the Rust ``RawCapabilityRequirement`` serde JSON shape."""
        return {
            "capability": self.capability,
            "verification_level": "ChallengeVerified",
            "trusted_verifiers": list(self.trusted_verifiers),
            "retry_cap": None
            if self.retry_cap is None
            else {
                "max_retries": self.retry_cap.max_retries,
                "min_cooldown_secs": self.retry_cap.min_cooldown_secs,
            },
        }


#: One admission requirement of a context (spec 07 §7.3.4.4): a capability
#: the agent declares (:class:`SelfAttested`), or one a trusted challenger
#: graded (:class:`ChallengeVerified`). Pass a list of them to
#: :meth:`scp_sdk.SCP.context_create` under ``params["capability_requirements"]``,
#: or to :meth:`scp_sdk.SCP.governance_modify_capability_requirements`.
CapabilityRequirement = SelfAttested | ChallengeVerified


def _encode_capability_requirements(requirements: Any, where: str) -> str:
    """Encode ``requirements`` as the JSON array the bridge reads.

    Raises:
        ValidationError: :data:`INVALID_REQUIREMENT_CODE` before any bridge
            call when ``requirements`` is not a list of
            :class:`SelfAttested` and :class:`ChallengeVerified`; a JSON
            string or a list of dicts is refused.
    """
    if not isinstance(requirements, list) or not all(
        isinstance(r, SelfAttested | ChallengeVerified) for r in requirements
    ):
        msg = f"{where} must be a list of SelfAttested and ChallengeVerified, got {requirements!r}"
        raise ValidationError(msg, INVALID_REQUIREMENT_CODE)
    return json.dumps([r._to_bridge_dict() for r in requirements])


#: Signed fields of a :class:`ChallengeVerification` that hold a 32-byte digest
#: or id as 64 lowercase hex characters.
_RECORD_HEX_FIELDS = (
    "verification_id",
    "definition_digest",
    "suite_digest",
    "challenge_id",
    "response_digest",
)
_RECORD_U32_FIELDS = (
    "attempt",
    "max_retries",
    "cooldown_secs",
    "pass_threshold_bps",
    "min_category_cases",
    "test_count",
    "pass_count",
)
_RECORD_U64_FIELDS = ("challenge_created_at", "challenge_expires_at", "timestamp", "expires_at")


@dataclass
class ChallengeVerification:
    """A signed record that a challenger graded a subject's response (spec 07
    §7.3.4, ADR-017).

    Mirrors the Rust ``ChallengeVerification`` struct.
    :meth:`scp_sdk.SCP.trust_grade_response` returns one; pass a list of them
    to :meth:`scp_sdk.SCP.check_capability_requirements` to meet
    ``ChallengeVerified`` requirements.

    The verifier's signature covers every field, so a record with any field
    altered fails verification.
    """

    #: The record's id, as 64 lowercase hex characters.
    verification_id: str
    #: DID of the challenger that graded the response.
    verifier: str
    #: DID of the subject that answered.
    subject: str
    #: The capability URI that was tested.
    capability_uri: str
    #: Digest of the capability definition, as 64 lowercase hex characters.
    definition_digest: str
    #: Digest of the graded test cases, as 64 lowercase hex characters.
    suite_digest: str
    #: The graded request's id, as 64 lowercase hex characters.
    challenge_id: str
    #: The attempt this record grades, starting at 1.
    attempt: int
    #: Digest of the graded response, as 64 lowercase hex characters.
    response_digest: str
    #: Retries the challenger's standard allowed.
    max_retries: int
    #: Cooldown in seconds the challenger's standard set between attempts.
    cooldown_secs: int
    #: Score in basis points needed to pass.
    pass_threshold_bps: int
    #: Least cases per category the standard required.
    min_category_cases: int
    #: Whether the subject passed.
    passed: bool
    #: Score in basis points, 0-10000.
    score: int
    #: Number of test cases graded.
    test_count: int
    #: Number of test cases the subject passed.
    pass_count: int
    #: Unix timestamp (seconds) when the request was created.
    challenge_created_at: int
    #: Unix timestamp (seconds) when the request expired.
    challenge_expires_at: int
    #: Unix timestamp (seconds) of the grading.
    timestamp: int
    #: Unix timestamp (seconds) when the record expires.
    expires_at: int
    #: The context the challenge was administered for.
    context_id: str
    #: The verifier's 64-byte signature as a list of integers.
    verifier_signature: list[int]

    def __post_init__(self) -> None:
        for name in _RECORD_HEX_FIELDS:
            _require_lower_hex_32(f"ChallengeVerification.{name}", getattr(self, name))
        for name in _RECORD_U32_FIELDS:
            _require_uint(f"ChallengeVerification.{name}", getattr(self, name), 32)
        for name in _RECORD_U64_FIELDS:
            _require_uint(f"ChallengeVerification.{name}", getattr(self, name), 64)
        for name in ("verifier", "subject", "capability_uri", "context_id"):
            _require_str(f"ChallengeVerification.{name}", getattr(self, name))
        if not isinstance(self.passed, bool):
            msg = f"ChallengeVerification.passed must be a bool, got {self.passed!r}"
            raise ValueError(msg)
        if (
            isinstance(self.score, bool)
            or not isinstance(self.score, int)
            or not 0 <= self.score <= 10_000
        ):
            msg = (
                "ChallengeVerification.score must be basis points in [0, 10000], "
                f"got {self.score!r}"
            )
            raise ValueError(msg)
        _require_signature("ChallengeVerification.verifier_signature", self.verifier_signature)

    def _to_bridge_dict(self) -> dict[str, Any]:
        """Convert to the Rust ``ChallengeVerification`` serde JSON shape."""
        return {f.name: getattr(self, f.name) for f in fields(self)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ChallengeVerification:
        """Build a record from the Rust ``ChallengeVerification`` serde JSON
        shape, the inverse of the bridge projection.

        Raises:
            ValueError: If a field is absent, unknown, or fails the checks of
                the constructor.
        """
        return cls(**_exact_fields(cls, data))


def _exact_fields(cls: Any, data: Any) -> dict[str, Any]:
    """Return ``data`` when its keys are exactly ``cls``'s field names."""
    name = cls.__name__
    if not isinstance(data, dict):
        msg = f"{name} must be a JSON object, got {data!r}"
        raise ValueError(msg)
    expected = {f.name for f in fields(cls)}
    missing = sorted(expected - set(data))
    unknown = sorted(set(data) - expected)
    if missing or unknown:
        msg = f"{name} fields do not match: missing {missing}, unknown {unknown}"
        raise ValueError(msg)
    return data


def _require_str(name: str, value: Any) -> None:
    """Raise ``ValueError`` unless ``value`` is a string."""
    if not isinstance(value, str):
        msg = f"{name} must be a string, got {value!r}"
        raise ValueError(msg)


def _require_lower_hex_32(name: str, value: Any) -> None:
    """Raise ``ValueError`` unless ``value`` is 64 lowercase hex characters."""
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
    ):
        msg = f"{name} must be 64 lowercase hex characters, got {value!r}"
        raise ValueError(msg)


def _require_uint(name: str, value: Any, bits: int) -> None:
    """Raise ``ValueError`` unless ``value`` is an int in ``[0, 2**bits)``."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < (1 << bits):
        msg = f"{name} must be an integer in [0, {(1 << bits) - 1}] (Rust u{bits}), got {value!r}"
        raise ValueError(msg)


def _require_signature(name: str, value: Any) -> None:
    """Raise ``ValueError`` unless ``value`` is a list of 64 byte values."""
    if not isinstance(value, list) or len(value) != 64:
        size = len(value) if isinstance(value, list) else type(value).__name__
        msg = f"{name} must be exactly 64 elements, got {size}"
        raise ValueError(msg)
    for i, elem in enumerate(value):
        if isinstance(elem, bool) or not isinstance(elem, int) or not 0 <= elem <= 255:
            msg = f"{name}[{i}] must be 0-255, got {elem!r}"
            raise ValueError(msg)


def structured_to_capability_validation(result: Any) -> CapabilityValidation:
    """Map a bridge ``CapabilityValidation`` record onto the SDK dataclass.

    The bridge's structured ``ucan_evaluate`` result (PyO3
    ``PyCapabilityValidation``) exposes the same six snake_case booleans as
    the SDK :class:`CapabilityValidation`. This reads them directly -- the
    per-check breakdown comes from the structured record, never from parsing
    error prose (spec §7.2.4, ADR-059 Decision 3).
    """
    return CapabilityValidation(
        tokens_valid=bool(result.tokens_valid),
        signatures_valid=bool(result.signatures_valid),
        within_ceiling=bool(result.within_ceiling),
        nonce_valid=bool(result.nonce_valid),
        not_revoked=bool(result.not_revoked),
        time_bounds_valid=bool(result.time_bounds_valid),
    )


async def evaluate_trust(
    scp: SCP,
    context_id: str,
    subject_did: str,
    capability_tokens: list[str] | None = None,
) -> TrustEvaluation:
    """Evaluate the trustworthiness of a participant in a context.

    Performs the four-layer trust evaluation model:

    1. **Protocol enforcement** — evaluates each UCAN token via the
       read-only, structured ``ucan_evaluate`` diagnostic (spec §7.2.4):
       it returns a :class:`CapabilityValidation` of six per-stage
       booleans without throwing on capability outcomes and without
       recording nonce state. The six fields are AND-combined across the
       token set, so a single token failing a stage makes that aggregate
       field ``False``.
    2. **Behavioral validation** — queries the event log for the
       subject's participation history.
    3. **Attestation authenticity** — verifies signatures and evidence
       freshness for any attestations the subject presents.

    The returned :class:`TrustEvaluation` surfaces these three layers (the
    same shape across all four SDKs). The Layer-4 trust-evaluation inputs
    (endorsements, challenge results, consequence structures) are gathered
    separately via :func:`aggregate_trust_input`.

    SECURITY: the behavioral record's ``attestation_count`` (and challenge
    results, where consumed) are authentic-but-self-mintable signals — an
    issuer/verifier is self-certifying, so a subject can mint them from DIDs it
    controls. They MUST NOT be a sole trust or admission factor; use the
    threshold/independence path (§7.3.5) for Sybil resistance.

    Layer 1 consumes the structured bridge result directly (ADR-059): it
    does not reverse-engineer *which* check failed by parsing error prose.
    The diagnostic is non-throwing for capability outcomes; it raises
    for malformed FFI inputs (e.g. a ``context_id`` with control
    characters), which propagate to the caller.

    Raises :class:`~scp_sdk.errors.ContextError` carrying ``SCP-CTX-2023`` when
    the context is not active.

    This module-level function consumes the :class:`SCP` instance to
    dispatch the ``ucan_evaluate`` (Layer 1) and ``participation_record``
    (Layer 2) bridge calls. The callers already receive the :class:`SCP`
    instance by value (matching the ADR-048 explicit-instance pattern).

    Args:
        scp: The :class:`~scp_sdk.SCP` instance to dispatch bridge calls on.
        context_id: The ID of the context to evaluate trust within.
        subject_did: The DID of the participant to evaluate.
        capability_tokens: Optional list of UCAN token strings to
            evaluate as part of the evaluation.

    Returns:
        A :class:`TrustEvaluation` with Layers 1-3 populated.
    """
    logger.debug(
        "Evaluating trust for %s in context %s",
        subject_did,
        context_id,
    )

    bridge = _bridge()
    # `_bridge()` is the seam tests use to inject a mock — patching
    # `scp_sdk.trust._bridge` returns a mock whose `ucan_evaluate` /
    # `participation_record` attributes stand in for the live bridge. In
    # production `_bridge()` returns the real `_scp_core` module (which no
    # longer exposes those free functions after Phase 4 PR 4), so we route
    # through the :class:`SCP` instance.
    if hasattr(bridge, "_mock_name"):
        instance: Any = bridge
    else:
        instance = scp._native

    # Layer 1: evaluate capability tokens if provided.
    cap_validation = CapabilityValidation()
    if capability_tokens:
        # Start from the all-True identity element for the boolean AND, then
        # conjoin each token's structured result. An empty token list keeps
        # the dataclass default (all False); a non-empty list begins all-True
        # because no failing stage has been observed yet.
        cap_validation.tokens_valid = True
        cap_validation.signatures_valid = True
        cap_validation.within_ceiling = True
        cap_validation.nonce_valid = True
        cap_validation.not_revoked = True
        cap_validation.time_bounds_valid = True

        for token in capability_tokens:
            # The structured diagnostic reads bools; it does NOT throw on
            # capability outcomes. Malformed FFI input (bad context_id /
            # token) and a context the supervisor does not report ``Active``
            # (``ContextError``, ``SCP-CTX-2023``) raise, re-raised as coded SDK
            # exceptions as ``_participation_record_from`` does.
            #
            # No challenge capability is supplied: trust evaluation assesses
            # each token's GENERAL (intrinsic) validity — signatures, ceiling,
            # nonce, revocation, time bounds — not whether it grants one
            # specific capability. Passing a concrete URI here (or the old
            # ``"*"`` sentinel, which the real bridge rejects) would wrongly
            # impose an invoked-capability grant-match the caller never asked
            # for. See ADR-059 / spec §7.2.4: the diagnostic's challenge
            # capability is optional, and ``None`` means intrinsic-validity.
            #
            # ``subject_did`` is passed as the presenting agent so the step-5
            # audience check evaluates the token against the DID under
            # assessment. ``presenting_agent_did`` is REQUIRED and fail-closed:
            # the bridge REJECTS an absent or empty value with a validation error
            # rather than defaulting to the token's OWN ``aud``
            # (crates/scp-ffi/src/ucan.rs). Defaulting would turn the audience
            # check into the tautology ``aud == aud`` — reporting
            # ``signatures_valid`` for a token addressed to someone else (trust
            # inflation) — so the bridge refuses to assume it. The TS canonical
            # API passes the subject the same way; this keeps an identical shape
            # across bindings (Agent-first API design tenet).
            try:
                result = await asyncio.to_thread(
                    instance.ucan_evaluate, context_id, token, None, subject_did
                )
            except Exception as exc:  # PyO3 raises native Scp*Error
                raise _coded_bridge_error(exc) from exc
            per_token = structured_to_capability_validation(result)
            cap_validation.tokens_valid &= per_token.tokens_valid
            cap_validation.signatures_valid &= per_token.signatures_valid
            cap_validation.within_ceiling &= per_token.within_ceiling
            cap_validation.nonce_valid &= per_token.nonce_valid
            cap_validation.not_revoked &= per_token.not_revoked
            cap_validation.time_bounds_valid &= per_token.time_bounds_valid

    # Layer 2: RECEIVE the behavioral record from the shared Rust core. The
    # core gathers the FULL event log and flattens the participation facts
    # (§7.3.2) ONCE in `Supervisor::participation_record`; the SDK never
    # re-aggregates event-log collections, so every binding observes identical
    # facts for the same context/subject (the divergence the old client-side
    # classify suffered).
    #
    # No cached attestations are supplied: `evaluate_trust` takes no attestation
    # set, so `attestation_count` reflects only what the bridge can source from
    # its own persistent trust store (verifier-relative, §7.3.2). This honestly
    # passes nothing rather than fabricating attestations.
    #
    # A context with no convergent events yet makes the core surface
    # `NoParticipationFacts` as a `ContextError` carrying the dedicated
    # `SCP-CTX-2076` code. That is not a failure for a trust evaluation (it means
    # "no recorded facts"), so it is folded into a ZEROED behavioral record —
    # branching on the STRUCTURED code, never on error prose (ADR-059). Any other
    # error (NotInitialized, a provider failure, malformed input) is genuine and
    # MUST propagate — the prior blanket `except ContextError` masked them.
    try:
        behavioral = await asyncio.to_thread(
            _participation_record_from, instance, context_id, subject_did, "[]"
        )
    except ContextError as exc:
        if exc.code != NO_PARTICIPATION_FACTS_CODE:
            raise
        logger.debug(
            "No recorded participation facts for %s; using a zeroed behavioral record",
            subject_did,
        )
        behavioral = BehavioralRecord(subject_did=subject_did)

    return TrustEvaluation(
        subject_did=subject_did,
        context_id=context_id,
        capability_validation=cap_validation,
        behavioral_record=behavioral,
    )


# ---------------------------------------------------------------------------
# Cached-attestation wire DTOs (ADR-017 §7.4.1)
#
# Pass-through input types for seeding the bridge's trust store. Unlike the
# modeled OUTPUT dataclasses above (camelCase-modeled, projected FROM the
# bridge), these mirror the serde-canonical snake_case the Rust core
# deserializes. They are TypedDicts — dicts at runtime — so they
# ``json.dumps`` straight onto the wire and a raw ``dict`` literal still
# satisfies the same shape. This is the Python analogue of the TypeScript
# SDK's ``CachedAttestation`` / ``CachedAttestationEnvelope`` interfaces, so
# the typed input is identical across bindings (Agent-first API design tenet).
# ---------------------------------------------------------------------------


class _CachedAttestationEnvelopeRequired(TypedDict):
    """Required fields of a wire-format attestation envelope."""

    #: Unique attestation identifier.
    id: str
    #: Attestation type (serde tag, e.g. ``"IdentityLink"``).
    attestation_type: str
    #: DID of the attestation issuer.
    issuer: str
    #: DID of the attestation subject.
    subject: str
    #: Type-specific claim data.
    claim: Any
    #: Unix timestamp (seconds) when the attestation was issued.
    issued_at: int
    #: Current revocation status (serde-tagged).
    revocation_status: Any
    #: Ed25519 signature over the attestation content (64 bytes as ints).
    signature: list[int]


class CachedAttestationEnvelope(_CachedAttestationEnvelopeRequired, total=False):
    """Wire-format attestation envelope (ADR-017 §7.4.1).

    A pass-through DTO whose field names are the serde-canonical snake_case the
    Rust core deserializes, NOT the camelCase the SDK uses for core-modeled
    types. Mirrors the TypeScript SDK ``CachedAttestationEnvelope`` 1:1.
    """

    #: Optional evidence supporting the attestation
    #: (``{"evidence_type": str, "data": Any}``).
    evidence: dict[str, Any] | None
    #: Optional expiry timestamp (seconds).
    expires_at: int | None
    #: Optional renewal interval (``std::time::Duration`` → ``{secs, nanos}``).
    renewal_interval: dict[str, int] | None
    #: Timestamp (seconds) of the last renewal, if renewable.
    renewed_at: int | None


class CachedAttestation(TypedDict):
    """A verified attestation with cache TTL metadata (ADR-017).

    Pass a list of these to :func:`participation_record` (or
    :func:`aggregate_trust_input`) to seed the bridge's trust store before it
    sources the subject's verified set. Mirrors the Rust ``CachedAttestation``
    and the TypeScript SDK ``CachedAttestation`` 1:1. A raw ``dict`` of the
    same shape is also accepted (a ``TypedDict`` is a ``dict`` at runtime).
    """

    #: The verified attestation envelope.
    attestation: CachedAttestationEnvelope
    #: Unix timestamp (seconds) when the attestation was last verified.
    verified_at: int
    #: Time-to-live in seconds for the cache entry.
    ttl_secs: int


# ---------------------------------------------------------------------------
# Trust-aggregation wire DTOs (§7.3, ADR-058)
#
# Pass-through input types for :func:`aggregate_trust_input`, in the same
# family as the cached-attestation DTOs above: field names are the
# serde-canonical snake_case the Rust core deserializes, and a raw ``dict`` of
# the same shape is also accepted. Mirror the TypeScript SDK
# ``EventLogEntry`` / ``ThresholdRequirement`` / ``AttestorInfo`` interfaces
# and the Swift/Kotlin models 1:1 (Agent-first API design tenet).
# ---------------------------------------------------------------------------

#: Valid attestation-type names, matching the Rust ``AttestationType`` enum
#: variants (ADR-017). These are both attestation-envelope ``attestation_type``
#: values and the map keys of ``threshold_requirements`` / ``attestor_sets``.
ATTESTATION_TYPES: frozenset[str] = frozenset(
    {
        "IdentityLink",
        "CapabilityDelegation",
        "OutletIntegrity",
        "AgentCapability",
        "Endorsement",
        "RoleAssignment",
        "ContextEndorsement",
        "ParticipationWitness",
    }
)


class EventLogEntryPayload(TypedDict):
    """Type-specific data carried by an :class:`EventLogEntry`.

    Mirrors the Rust ``EventPayload`` (``scp-event-log``): opaque payload
    bytes as a JSON number array. An empty ``data`` list is the canonical
    representation for non-parameterized events.
    """

    #: Opaque payload bytes (as ints). Interpretation depends on the event type.
    data: list[int]


class EventLogEntry(TypedDict):
    """A full signed protocol event in a context event log (ADR-011).

    The serde wire shape of the Rust ``Event`` (``scp-event-log``) the bridge
    deserializes for :func:`aggregate_trust_input` (``Vec<Event>``) — the
    INPUT wire form, distinct from the projected event the event-log query
    surface returns (which omits the hash-chain and signature fields).
    """

    #: Event type — a Rust ``EventType`` variant name (e.g. ``"MessageSent"``).
    event_type: str
    #: DID of the actor who produced this event.
    actor_did: str
    #: Unix timestamp (seconds) when the event was created.
    timestamp: int
    #: Monotonic event sequence number within the log (0-indexed).
    sequence: int
    #: Type-specific event data.
    payload: EventLogEntryPayload
    #: SHA-256 hash of the previous event (hash chain), exactly 32 bytes as
    #: ints. ``[0] * 32`` for the first event (genesis sentinel).
    prev_hash: list[int]
    #: Ed25519 signature over the serialized event content (64 bytes as ints).
    signature: list[int]


class _ThresholdRequirementRequired(TypedDict):
    """Required fields of a wire-format threshold requirement."""

    #: The minimum number of valid attestations required (N).
    required_count: int
    #: The total number of attestors in the set (M). Must be >= ``required_count``.
    total_attestors: int
    #: Minimum independence score, in [0.0, 1.0].
    independence_threshold: float


class ThresholdRequirement(_ThresholdRequirementRequired, total=False):
    """N-of-M threshold requirement for attestation verification (§7.3.5).

    Mirrors the Rust ``ThresholdRequirement`` struct (ADR-017). The three
    penalty fields carry Rust serde defaults (0.1 / 0.5 / 0.2) when omitted —
    the bridge deserializer fills them in.
    """

    #: Independence penalty per shared context membership. Default: 0.1.
    shared_context_penalty: float
    #: Maximum total shared-context penalty for a single pair. Default: 0.5.
    shared_context_penalty_cap: float
    #: Independence penalty per mutual endorsement direction. Default: 0.2.
    mutual_endorsement_penalty: float


class _AttestorInfoRequired(TypedDict):
    """Required fields of a wire-format attestor descriptor."""

    #: The DID of the attestor.
    did: str
    #: Context IDs the attestor is a member of.
    context_memberships: list[str]
    #: DIDs this attestor has endorsed (mutual endorsements reduce independence).
    endorsements: list[str]


class AttestorInfo(_AttestorInfoRequired, total=False):
    """Information about an attestor used for independence scoring (§7.3.5).

    Mirrors the Rust ``AttestorInfo`` struct (ADR-017). The optional
    ``attestation`` is a full attestation envelope
    (:class:`CachedAttestationEnvelope`); only attestations matching the
    required type are considered.
    """

    #: The attestation provided by this attestor, if any.
    attestation: CachedAttestationEnvelope | None


def _encode_aggregate_trust_wire(
    events: list[EventLogEntry] | list[dict[str, Any]],
    merkle_root: list[int],
    consequence_rules: list[dict[str, Any]] | None,
    threshold_requirements: dict[str, ThresholdRequirement] | dict[str, Any] | None,
    attestor_sets: dict[str, list[AttestorInfo]] | dict[str, Any] | None,
    cached_attestations: list[CachedAttestation] | list[dict[str, Any]] | None,
    challenge_results: list[ChallengeVerification] | list[dict[str, Any]] | None,
) -> tuple[str, str, str, str, str, str, str]:
    """Validate and serialize the typed aggregation inputs to the serde wire.

    The single serialization point shared by :func:`aggregate_trust_input` and
    :meth:`scp_sdk.SCP.aggregate_trust_input` (ADR-058), so both surfaces emit
    byte-identical wire JSON. Uses ``is not None`` (never a falsy check) to
    keep the distinction between an explicit empty collection ("no rules
    apply") and an absent parameter.

    Raises:
        ValueError: If ``merkle_root`` is not exactly 32 elements, or a
            ``threshold_requirements`` / ``attestor_sets`` key is not a valid
            :data:`ATTESTATION_TYPES` name — failing at the SDK boundary with
            a field-named error instead of a bridge deserialization error.
    """
    if len(merkle_root) != 32:
        msg = (
            f"aggregate_trust_input merkle_root must be exactly 32 elements, got {len(merkle_root)}"
        )
        raise ValueError(msg)
    for param_name, mapping in (
        ("threshold_requirements", threshold_requirements),
        ("attestor_sets", attestor_sets),
    ):
        if mapping is not None:
            for key in mapping:
                if key not in ATTESTATION_TYPES:
                    msg = (
                        f"Invalid {param_name} key {key!r}: not an AttestationType. "
                        f"Valid: {sorted(ATTESTATION_TYPES)}"
                    )
                    raise ValueError(msg)

    events_json = json.dumps(events)
    merkle_root_json = json.dumps(merkle_root)
    consequence_rules_json = (
        json.dumps(consequence_rules) if consequence_rules is not None else "[]"
    )
    threshold_requirements_json = (
        json.dumps(threshold_requirements) if threshold_requirements is not None else "{}"
    )
    attestor_sets_json = json.dumps(attestor_sets) if attestor_sets is not None else "{}"
    cached_attestations_json = (
        json.dumps(cached_attestations) if cached_attestations is not None else "[]"
    )
    challenge_results_json = (
        json.dumps(
            [
                c._to_bridge_dict() if isinstance(c, ChallengeVerification) else c
                for c in challenge_results
            ]
        )
        if challenge_results is not None
        else "[]"
    )
    return (
        events_json,
        merkle_root_json,
        consequence_rules_json,
        threshold_requirements_json,
        attestor_sets_json,
        cached_attestations_json,
        challenge_results_json,
    )


def _participation_record_from(
    instance: Any,
    context_id: str,
    subject_did: str,
    cached_attestations_json: str,
) -> BehavioralRecord:
    """Call the bridge ``participation_record`` op and project the typed result.

    Shared by :func:`participation_record` and :func:`evaluate_trust` so the
    PyParticipationRecord → :class:`BehavioralRecord` projection lives in ONE
    place. ``instance`` is the resolved bridge handle (the mock seam in tests
    or ``scp._native`` in production).
    """
    try:
        record = instance.participation_record(context_id, subject_did, cached_attestations_json)
    except Exception as exc:  # PyO3 raises native Scp*Error; mock seam may raise SDK errors
        # Re-raise as a coded SDK exception so callers (and :func:`evaluate_trust`)
        # branch on the STRUCTURED ``.code`` — e.g. the empty-log
        # ``SCP-CTX-2076`` — never on error prose.
        raise _coded_bridge_error(exc) from exc
    return BehavioralRecord(
        subject_did=record.subject_did,
        participation_duration_secs=record.participation_duration_secs,
        governance_actions_against=record.governance_actions_against,
        governance_actions_by=record.governance_actions_by,
        outlet_invocation_count=record.outlet_invocation_count,
        outlet_invocation_count_anchored=record.outlet_invocation_count_anchored,
        context_creation_count=record.context_creation_count,
        role_progression_count=record.role_progression_count,
        attestation_count=record.attestation_count,
        attestation_count_anchored=record.attestation_count_anchored,
        computed_at=record.computed_at,
        event_log_root=record.event_log_root,
    )


async def participation_record(
    scp: SCP,
    context_id: str,
    subject_did: str,
    cached_attestations: list[CachedAttestation] | list[dict[str, Any]] | None = None,
) -> BehavioralRecord:
    """Compute the participation record (§7.3.2) for a subject in a context.

    The shared Rust core gathers the FULL context event log and flattens the
    participation facts ONCE (``Supervisor::participation_record``), and the
    PyO3 bridge sources the subject's accessible, currently-valid attestations
    from its own persistent trust store (seeded by ``cached_attestations``).
    The SDK RECEIVES the flattened :class:`BehavioralRecord` — it never
    re-aggregates event-log collections, so every binding observes identical
    facts for the same context/subject.

    ``attestation_count`` is a credential-layer fact (§7.4): it is NOT a
    context-event count and NOT Merkle-anchored, and is verifier-relative
    (computed from the attestations the bridge can access). Pass the subject's
    accessible attestations as ``cached_attestations`` to populate it; the
    default (``None`` → ``"[]"``) honestly reports only what the bridge's trust
    store already holds — it never fabricates attestations.

    THREAT MODEL: ``attestation_count`` is Sybil-inflatable by self-issuance —
    one operator can self-issue (or co-issue across DIDs it controls)
    arbitrarily many *authentic* attestations. It is a credential-layer claim
    count, NOT a standalone trust score; Sybil resistance comes from the
    threshold/independence path (§7.3.5) and DeviceAttestation binding (§9.3),
    not the count itself. Separately, the membership/role-derived facts
    (participation duration, governance actions, role progression) are
    committer-local — verifier-relative, not independently Merkle-verifiable —
    until ADR-051 receive-side replication lands. In particular,
    ``participation_duration_secs`` for the context creator (founder) is
    derived from the creator-assigned context-creation timestamp — it is
    creator-timestamp-trusting and committer-local until that replication
    lands (no independent receiver corroborates the creator's clock).

    Args:
        scp: The :class:`~scp_sdk.SCP` instance to dispatch the bridge call on.
        context_id: The context the participation is scoped to.
        subject_did: The DID whose participation facts are computed.
        cached_attestations: Optional list of :class:`CachedAttestation` (typed)
            or raw equivalently-shaped dicts to seed the bridge's trust store
            before sourcing the subject's verified set.

    Returns:
        The flattened participation facts as a :class:`BehavioralRecord`.

    Raises:
        ScpError: On malformed FFI input or a behavioral compute failure (e.g.
            an empty event log, surfaced as a :class:`ContextError`).
    """
    bridge = _bridge()
    instance: Any = bridge if hasattr(bridge, "_mock_name") else scp._native
    cached_json = json.dumps(cached_attestations if cached_attestations is not None else [])
    return await asyncio.to_thread(
        _participation_record_from, instance, context_id, subject_did, cached_json
    )


async def aggregate_trust_input(
    scp: SCP,
    context_id: str,
    subject_did: str,
    events: list[EventLogEntry] | list[dict[str, Any]],
    merkle_root: list[int],
    consequence_rules: list[dict[str, Any]] | None = None,
    threshold_requirements: dict[str, ThresholdRequirement] | dict[str, Any] | None = None,
    attestor_sets: dict[str, list[AttestorInfo]] | dict[str, Any] | None = None,
    cached_attestations: list[CachedAttestation] | list[dict[str, Any]] | None = None,
    challenge_results: list[ChallengeVerification] | list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Aggregate all trust engine layers into a single TrustInput.

    Every structured input is typed (ADR-058): the wire DTOs
    (:class:`EventLogEntry`, :class:`ThresholdRequirement`,
    :class:`AttestorInfo`, :class:`CachedAttestation`) are ``TypedDict``
    pass-throughs of the serde snake_case shapes, and ``challenge_results``
    accepts the :class:`ChallengeVerification` dataclass (serialized via its
    bridge projection). Raw equivalently-shaped dicts remain accepted (a
    ``TypedDict`` is a ``dict`` at runtime). Serialization lives in the shared
    :func:`_encode_aggregate_trust_wire`, so this helper and
    :meth:`scp_sdk.SCP.aggregate_trust_input` emit byte-identical wire JSON.
    Using ``is not None`` (never a falsy check) keeps the distinction between
    an explicit empty collection and an absent parameter — empty means
    "no rules apply", absent means "use protocol defaults".

    Args:
        scp: The :class:`~scp_sdk.SCP` instance to dispatch on.
        context_id: The context to aggregate trust inputs for.
        subject_did: The DID of the subject to evaluate.
        events: Full signed event-log entries (:class:`EventLogEntry`).
        merkle_root: 32-byte Merkle root as a list of integers.
        consequence_rules: Optional list of consequence rule dicts.
        threshold_requirements: Optional mapping of
            :data:`ATTESTATION_TYPES` names to
            :class:`ThresholdRequirement` values.
        attestor_sets: Optional mapping of :data:`ATTESTATION_TYPES` names to
            lists of :class:`AttestorInfo` values.
        cached_attestations: Optional list of :class:`CachedAttestation`
            (typed) or raw equivalently-shaped dicts to pre-populate the
            trust store.
        challenge_results: Optional list of :class:`ChallengeVerification`
            (typed) or raw equivalently-shaped dicts to pre-populate the
            trust store.

    Returns:
        A dict containing the aggregated ``TrustInput`` fields:
        ``verified_attestations``, ``participation_record``,
        ``challenge_results``, ``consequence_structure``, and
        ``threshold_counts``.

    Raises:
        ValueError: If ``merkle_root`` is not exactly 32 elements or a
            ``threshold_requirements`` / ``attestor_sets`` key is not a
            valid :data:`ATTESTATION_TYPES` name.
    """
    # Same `_bridge()` test seam as :func:`evaluate_trust` — tests patch
    # ``scp_sdk.trust._bridge`` with a MagicMock whose
    # ``aggregate_trust_input`` attribute stands in for the bridge call.
    # Production falls through to the real SCP instance.
    bridge = _bridge()
    if hasattr(bridge, "_mock_name"):
        instance: Any = bridge
    else:
        instance = scp._native

    wire = _encode_aggregate_trust_wire(
        events,
        merkle_root,
        consequence_rules,
        threshold_requirements,
        attestor_sets,
        cached_attestations,
        challenge_results,
    )

    try:
        result = await asyncio.to_thread(
            instance.aggregate_trust_input, context_id, subject_did, *wire
        )
    except Exception as exc:  # PyO3 raises native Scp*Error
        raise _coded_bridge_error(exc) from exc
    if isinstance(result, str):
        return json.loads(result)
    return result


def verify_participation_requirements(
    expected_subject: str,
    requirements: list[RequireParticipation],
    profiles: list[ParticipationProfile],
) -> None:
    """Verify participation profiles against admission requirements.

    Delegates to the Rust ``scp-core`` implementation via the PyO3
    bridge, which performs the full verification including:

    1. Subject binding: only profiles whose signed ``subject_did`` equals
       ``expected_subject`` contribute to any threshold, freshness, or
       distinct-signer accounting. Participation profiles are public and
       signed by the *context*, not the subject, so without this binding a
       victim's genuine high-standing profiles could be replayed to admit a
       different agent (cross-subject participation-profile replay).
    2. Signature verification on subject-matching participation profiles.
    3. Freshness/staleness checking (``max_age_secs``).
    4. Distinct signer counting (``min_contexts``).
    5. Threshold operator semantics (``ParticipationThreshold``).
    6. Diagnostic error reporting (``ParticipationAdmissionError``).
    7. Typed field extraction (``ParticipationFact.extract_value``).

    Security caveat — authenticity is not authorization: this verifies that
    each profile is genuinely signed over its subject binding, NOT that the
    signer is trusted. ``signer_public_key`` is self-certifying, so a subject
    can present genuinely-signed profiles from signers it controls, inflating
    ``min_contexts``. Consumers MUST establish signer legitimacy separately
    (a trusted-signer set, a context-membership proof, or the §7.3.5
    threshold/independence path) and MUST NOT treat a passing check as an
    authorization decision.

    Success is indicated by returning without exception. Failures raise the
    bridge's native coded ``ValidationError`` (rooted at ``ScpError``); the
    structured per-case ``SCP-VALID-*`` code is recoverable from the
    exception's string form (the ``[CODE]``-prefixed message), so callers
    branch on the code — never on error prose.

    Args:
        expected_subject: The DID of the agent being admitted. Profiles for
            any other subject are ignored (fail-closed).
        requirements: The participation requirements to verify against.
        profiles: The participation profiles to evaluate.

    Raises:
        ScpError: If the bridge module is not available.
        ValidationError: Native bridge exception whose ``[SCP-VALID-NNNN]``-
            prefixed message carries the per-case structured code:
            ``SCP-VALID-7000`` for a malformed ``expected_subject`` DID;
            ``SCP-VALID-7031`` / ``SCP-VALID-7030`` for malformed
            requirements / profiles JSON (unreachable through this typed
            wrapper, which always serializes valid JSON); and
            ``SCP-VALID-7032`` for a failed admission check, with the
            specific failure reason from ``ParticipationAdmissionError``.
    """
    bridge = _bridge()

    profile_json = json.dumps([p._to_bridge_dict() for p in profiles])
    requirements_json = json.dumps([r._to_bridge_dict() for r in requirements])

    bridge.verify_participation_requirements(expected_subject, requirements_json, profile_json)


# ---------------------------------------------------------------------------
# Challenge trust-input wire DTOs + typed verification wrappers (§7.3.4,
# ADR-058)
# ---------------------------------------------------------------------------


# Codes the bridge raises for a challenge or an admission check. Each name is
# the Rust ``TrustError`` or ``AdmissionError`` variant the code maps from in
# ``scp-ffi-common``'s ``trust_error_code`` and ``admission_error_code``.

#: A signer's key could not be resolved: the instance has no DID resolver, or a
#: supplied ``ChallengeVerification`` could not be checked (DID resolution
#: failed, spec 03). Maps from ``AdmissionError::VerificationUnavailable`` and
#: a missing instance resolver.
DID_RESOLUTION_FAILED_CODE = "SCP-IDENT-1033"
#: The registry's JSON schema validation error, which the bridges also raise
#: for every trust error without a code of its own: a challenge, response or
#: verification whose signature does not verify, a record bound to another
#: verifier, subject, context or window, a caller who is not a member or has
#: not opted in, or a failed ledger write. Maps from each ``TrustError``
#: variant ``trust_error_code`` does not name.
JSON_SCHEMA_VALIDATION_FAILED_CODE = "SCP-VALID-7003"
#: A protocol capability URI's request has fewer test cases than the URI's
#: standard requires (spec 07 §7.3.4.3; for ``scp:capability:multilingual/v1``,
#: fewer than five cases in some ``category``).
CHALLENGE_SUITE_BELOW_MINIMUM_CODE = "SCP-VALID-7039"
#: The agent capabilities JSON of a capability admission check does not decode
#: as a list of capability URIs.
MALFORMED_AGENT_CAPABILITIES_CODE = "SCP-VALID-7074"
#: The challenge verifications JSON of a capability admission check does not
#: decode as a list of ``ChallengeVerification`` records.
MALFORMED_CHALLENGE_VERIFICATIONS_CODE = "SCP-VALID-7075"
#: A capability requirement is unmet: the subject lacks a required capability,
#: or a ``ChallengeVerified`` requirement has no record that admits the
#: subject. Maps from ``AdmissionError::MissingCapability`` and
#: ``AdmissionError::VerificationRequired``.
ADMISSION_REQUIREMENT_UNMET_CODE = "SCP-VALID-7076"
#: A capability admission check names an empty subject DID. Maps from
#: ``AdmissionError::EmptySubjectDid``.
EMPTY_SUBJECT_DID_CODE = "SCP-VALID-7077"
#: The challenger's ledger already holds its maximum of open challenges.
CHALLENGE_NOT_OPEN_CODE = "SCP-VALID-7099"
#: The time is outside the challenge window, or grading ran at or after
#: ``expires_at``.
CHALLENGE_EXPIRED_CODE = "SCP-VALID-7102"
#: The attempt is not the last graded attempt plus one.
ATTEMPT_OUT_OF_ORDER_CODE = "SCP-VALID-7103"
#: The attempt exceeds ``1 + max_retries``.
RETRIES_EXHAUSTED_CODE = "SCP-VALID-7104"
#: The cooldown since the last graded attempt has not passed; the message
#: names the second the next attempt is accepted (:func:`retry_after`).
COOLDOWN_ACTIVE_CODE = "SCP-VALID-7105"
#: The challenge closed after a pass or after its last allowed attempt.
CHALLENGE_CLOSED_CODE = "SCP-VALID-7106"
#: The challenger's ledger holds no live challenge with this id, request
#: digest and subject.
UNKNOWN_CHALLENGE_CODE = "SCP-VALID-7107"
#: The response answers another challenge, or its outputs do not match the
#: request's cases one for one and in order.
OUTPUTS_MISMATCH_CODE = "SCP-VALID-7108"
#: A ``CustomEval`` evaluator outlet is unregistered, has no handler, or the
#: challenger may not call it; the subject is charged no attempt.
EVALUATOR_UNAVAILABLE_CODE = "SCP-VALID-7109"
#: A required capability has no passing record from a trusted challenger: the
#: only passing record comes from a verifier the requirement does not trust.
#: Maps from ``AdmissionError::UntrustedVerifier``.
UNTRUSTED_VERIFIER_CODE = "SCP-VALID-7121"
#: The verifier and the subject are the same identity.
SELF_CHALLENGE_CODE = "SCP-VALID-7127"
#: The capability URI names a standard whose pass condition cannot be
#: computed from the subject's outputs, or a system capability.
STANDARD_NOT_GRADABLE_CODE = "SCP-VALID-7128"
#: No capability definition can be obtained for the URI.
CAPABILITY_DEFINITION_UNAVAILABLE_CODE = "SCP-VALID-7129"
#: A policy value lies outside the capability definition's limits, or a
#: record exceeds a requirement's retry cap.
POLICY_OUTSIDE_DEFINITION_CODE = "SCP-VALID-7137"
#: A ``SchemaMatch`` schema breaks a schema limit.
SCHEMA_REJECTED_CODE = "SCP-VALID-7138"
#: Another grading of the same challenge holds a live lease.
GRADING_IN_PROGRESS_CODE = "SCP-VALID-7139"
#: A response exceeds the protocol's size or JSON depth limit.
RESPONSE_TOO_LARGE_CODE = "SCP-VALID-7143"
#: Two validly signed capability definitions for one URI differ.
DEFINITION_EQUIVOCATION_CODE = "SCP-VALID-7144"
#: The challenger has no grading capacity left; the subject is charged no
#: attempt.
GRADING_CAPACITY_EXHAUSTED_CODE = "SCP-VALID-7146"
#: A DID, capability URI or context id is not in canonical form.
NON_CANONICAL_IDENTIFIER_CODE = "SCP-VALID-7147"
#: A context declares more capability requirements than the protocol allows.
TOO_MANY_CAPABILITY_REQUIREMENTS_CODE = "SCP-VALID-7148"
#: Another grading of the same challenge took the grading lease first; the
#: subject is charged no attempt.
GRADING_LEASE_LOST_CODE = "SCP-VALID-7149"
#: The challenger's last challenge to this subject for this capability is
#: still inside its window; the message names the second a new one may be
#: created (:func:`retry_after`).
CHALLENGE_WINDOW_OPEN_CODE = "SCP-VALID-7151"
#: Grading ran at or before the request's ``created_at``; the message names
#: the second the same attempt may be resubmitted (:func:`retry_after`).
CHALLENGE_NOT_YET_GRADABLE_CODE = "SCP-VALID-7153"

#: The codes a later call with the same arguments can succeed after: the
#: refusal reports a busy challenger, a running grading, or a time that has
#: not yet come.
_RETRYABLE_CODES = frozenset(
    {
        CHALLENGE_NOT_OPEN_CODE,
        COOLDOWN_ACTIVE_CODE,
        GRADING_IN_PROGRESS_CODE,
        GRADING_CAPACITY_EXHAUSTED_CODE,
        GRADING_LEASE_LOST_CODE,
        CHALLENGE_WINDOW_OPEN_CODE,
        CHALLENGE_NOT_YET_GRADABLE_CODE,
    }
)

#: The ``(retry_after=N)`` suffix ``scp-ffi-common`` appends to the message
#: of a 7105, 7151 or 7153 refusal; ``N`` is a Unix second.
_RETRY_AFTER_RE = re.compile(r"\(retry_after=([0-9]+)\)\s*\Z")


def is_retryable(code: str) -> bool:
    """Return whether a challenge refusal with ``code`` can succeed when the
    caller repeats the call later.

    ``True`` exactly for :data:`CHALLENGE_NOT_OPEN_CODE`,
    :data:`COOLDOWN_ACTIVE_CODE`, :data:`GRADING_IN_PROGRESS_CODE`,
    :data:`GRADING_CAPACITY_EXHAUSTED_CODE`, :data:`GRADING_LEASE_LOST_CODE`,
    :data:`CHALLENGE_WINDOW_OPEN_CODE` and
    :data:`CHALLENGE_NOT_YET_GRADABLE_CODE`. Every other code is final for the
    same arguments.
    """
    return code in _RETRYABLE_CODES


def retry_after(error: BaseException | str) -> int | None:
    """Return the Unix second from which a refused call may succeed, or
    ``None`` when the refusal names none.

    The bridge appends ``(retry_after=N)`` to the message of a
    :data:`COOLDOWN_ACTIVE_CODE`, :data:`CHALLENGE_WINDOW_OPEN_CODE` or
    :data:`CHALLENGE_NOT_YET_GRADABLE_CODE` refusal. ``error`` is the raised
    exception or its message.
    """
    message = error.message if isinstance(error, ScpError) else str(error)
    match = _RETRY_AFTER_RE.search(message)
    return None if match is None else int(match.group(1))


@dataclass(frozen=True)
class ExactMatch:
    """A test case passes when the output equals ``value`` (spec 07 §7.3.4)."""

    #: The required output.
    value: Any

    def _to_wire(self) -> dict[str, Any]:
        return {"ExactMatch": {"value": self.value}}


@dataclass(frozen=True)
class SchemaMatch:
    """A test case passes when the output validates against ``schema`` (JSON
    Schema draft 2020-12)."""

    #: The JSON Schema the output must satisfy.
    schema: Any

    def _to_wire(self) -> dict[str, Any]:
        return {"SchemaMatch": {"schema": self.schema}}


@dataclass(frozen=True)
class ContainsAll:
    """A test case passes when every string in ``required`` appears in the
    output's string form."""

    #: Strings that must all appear.
    required: list[str]

    def _to_wire(self) -> dict[str, Any]:
        return {"ContainsAll": {"required": list(self.required)}}


@dataclass(frozen=True)
class ContainsNone:
    """A test case passes when no string in ``forbidden`` appears in the
    output's string form."""

    #: Strings that must not appear.
    forbidden: list[str]

    def _to_wire(self) -> dict[str, Any]:
        return {"ContainsNone": {"forbidden": list(self.forbidden)}}


@dataclass(frozen=True)
class CustomEval:
    """An evaluator outlet the challenger chooses scores the output; the SDK
    ships none.

    :meth:`scp_sdk.SCP.trust_create_challenge` passes
    ``evaluator_context_id`` to the bridge as the context whose outlets grade
    the request's ``CustomEval`` cases. Every ``CustomEval`` case of one
    request names the same context. The wire form carries only
    ``evaluator_outlet_id``.
    """

    #: The evaluator outlet's identifier.
    evaluator_outlet_id: str
    #: The context where the evaluator outlet is registered; the verifier must
    #: be able to call the outlet there.
    evaluator_context_id: str

    def __post_init__(self) -> None:
        _require_str("CustomEval.evaluator_outlet_id", self.evaluator_outlet_id)
        _require_str("CustomEval.evaluator_context_id", self.evaluator_context_id)

    def _to_wire(self) -> dict[str, Any]:
        return {"CustomEval": {"evaluator_outlet_id": self.evaluator_outlet_id}}


#: What a test case's output must satisfy. Serialized externally tagged,
#: ``{"<Variant>": {<fields>}}``, the Rust ``ExpectedOutput`` wire form.
ExpectedOutput = ExactMatch | SchemaMatch | ContainsAll | ContainsNone | CustomEval


@dataclass(frozen=True)
class TestCase:
    """One test case of a challenge, written by the verifier (spec 07 §7.3.4).

    A request's weights sum to 10000. Numbers in ``input`` and in the expected
    output must lie within ±(2**53 - 1) (I-JSON); the bridge refuses others.
    For ``scp:capability:multilingual/v1``, ``category`` is a BCP 47 language
    tag and each distinct category needs at least five cases.
    """

    __test__ = False  # not a pytest class

    #: Identifier, unique within the request.
    test_id: str
    #: JSON input given to the subject.
    input: Any
    #: What constitutes passing this case.
    expected: ExpectedOutput
    #: Test category.
    category: str
    #: Importance weight in basis points.
    weight: int

    def __post_init__(self) -> None:
        _require_uint("TestCase.weight", self.weight, 32)

    def _to_wire(self) -> dict[str, Any]:
        """Convert to the Rust ``TestCase`` serde JSON shape."""
        return {
            "test_id": self.test_id,
            "input": self.input,
            "expected": self.expected._to_wire(),
            "category": self.category,
            "weight": self.weight,
        }


@dataclass(frozen=True)
class ChallengePolicy:
    """A stricter retry policy than the capability definition's (spec 07
    §7.3.4).

    A policy may only tighten the definition, on any URI: at most the
    definition's retries, and at least its cooldown. A field left ``None``
    takes the definition's value. Omit the policy to take the definition's
    values for both.
    """

    #: Retries after the first attempt; at most the definition's. ``None``
    #: takes the definition's value.
    max_retries: int | None = None
    #: Seconds between graded attempts; at least the definition's. ``None``
    #: takes the definition's value.
    cooldown_secs: int | None = None

    def __post_init__(self) -> None:
        if self.max_retries is not None:
            _require_uint("ChallengePolicy.max_retries", self.max_retries, 32)
        if self.cooldown_secs is not None:
            _require_uint("ChallengePolicy.cooldown_secs", self.cooldown_secs, 32)

    def _to_bridge_dict(self) -> dict[str, int]:
        """The bridge's ``policy`` dict: only the fields this policy sets."""
        picked = {"max_retries": self.max_retries, "cooldown_secs": self.cooldown_secs}
        return {key: value for key, value in picked.items() if value is not None}


@dataclass(frozen=True)
class CreateChallengeConfig:
    """The arguments of :meth:`scp_sdk.SCP.trust_create_challenge` (spec 07
    §7.3.4 step 1)."""

    #: The challenger, an identity of this instance; its custody signs.
    verifier: Identity
    #: DID of the identity being challenged.
    subject: str
    #: The capability URI under test, in canonical form.
    capability_uri: str
    #: The challenger-written cases; their weights sum to 10000.
    test_cases: list[TestCase]
    #: The context where the challenge is administered.
    context_id: str
    #: Seconds from creation during which attempts are graded.
    window_secs: int
    #: A stricter policy than the capability definition's; ``None`` takes the
    #: definition's values.
    policy: ChallengePolicy | None = None


@dataclass(frozen=True)
class ChallengeCase:
    """One test case as the request carries it: the input, never the expected
    output, which the challenger's ledger keeps."""

    __test__ = False  # not a pytest class

    #: Identifier, unique within the request.
    test_id: str
    #: JSON input given to the subject.
    input: Any
    #: Test category.
    category: str
    #: Importance weight in basis points.
    weight: int

    def __post_init__(self) -> None:
        _require_str("ChallengeCase.test_id", self.test_id)
        _require_str("ChallengeCase.category", self.category)
        _require_uint("ChallengeCase.weight", self.weight, 32)

    @classmethod
    def from_dict(cls, data: Any) -> ChallengeCase:
        """Build a case from the Rust ``ChallengeCase`` serde JSON shape."""
        return cls(**_exact_fields(cls, data))


@dataclass(frozen=True)
class ChallengeRequest:
    """A signed challenge request (spec 07 §7.3.4, ADR-017).

    :meth:`scp_sdk.SCP.trust_create_challenge` returns one. The verifier's
    signature covers every other field.
    """

    #: The 32-byte random id as 64 lowercase hex characters.
    challenge_id: str
    #: The capability URI under test.
    capability_uri: str
    #: Digest of the capability definition, as 64 lowercase hex characters.
    definition_digest: str
    #: The test cases, without their expected outputs.
    test_cases: list[ChallengeCase]
    #: Unix timestamp (seconds) when the request was created.
    created_at: int
    #: Unix timestamp (seconds) after which no response is graded.
    expires_at: int
    #: Retries the standard allows.
    max_retries: int
    #: Cooldown in seconds between attempts.
    cooldown_secs: int
    #: Score in basis points needed to pass.
    pass_threshold_bps: int
    #: The context the challenge is administered for.
    context_id: str
    #: DID of the challenger.
    verifier: str
    #: DID of the subject.
    subject: str
    #: The verifier's 64-byte signature as a list of integers.
    verifier_signature: list[int]

    def __post_init__(self) -> None:
        _require_lower_hex_32("ChallengeRequest.challenge_id", self.challenge_id)
        _require_lower_hex_32("ChallengeRequest.definition_digest", self.definition_digest)
        for name in ("created_at", "expires_at"):
            _require_uint(f"ChallengeRequest.{name}", getattr(self, name), 64)
        for name in ("max_retries", "cooldown_secs", "pass_threshold_bps"):
            _require_uint(f"ChallengeRequest.{name}", getattr(self, name), 32)
        for name in ("capability_uri", "context_id", "verifier", "subject"):
            _require_str(f"ChallengeRequest.{name}", getattr(self, name))
        if not isinstance(self.test_cases, list) or not all(
            isinstance(c, ChallengeCase) for c in self.test_cases
        ):
            msg = "ChallengeRequest.test_cases must be a list of ChallengeCase"
            raise ValueError(msg)
        _require_signature("ChallengeRequest.verifier_signature", self.verifier_signature)

    def _to_wire(self) -> dict[str, Any]:
        """Convert to the Rust ``ChallengeRequest`` serde JSON shape."""
        wire = {f.name: getattr(self, f.name) for f in fields(self)}
        wire["test_cases"] = [asdict(c) for c in self.test_cases]
        return wire

    @classmethod
    def from_dict(cls, data: Any) -> ChallengeRequest:
        """Build a request from the Rust ``ChallengeRequest`` serde JSON shape.

        Raises:
            ValueError: If a field is absent, unknown, or malformed.
        """
        wire = dict(_exact_fields(cls, data))
        cases = wire["test_cases"]
        if not isinstance(cases, list):
            msg = f"ChallengeRequest.test_cases must be a list, got {cases!r}"
            raise ValueError(msg)
        wire["test_cases"] = [ChallengeCase.from_dict(c) for c in cases]
        return cls(**wire)


@dataclass(frozen=True)
class TestOutput:
    """The subject's output for one test case."""

    __test__ = False  # not a pytest class

    #: The answered case's ``test_id``.
    test_id: str
    #: The subject's JSON output.
    output: Any

    def __post_init__(self) -> None:
        _require_str("TestOutput.test_id", self.test_id)


@dataclass(frozen=True)
class ChallengeResponse:
    """A subject's signed response to a challenge request (spec 07 §7.3.4).

    :meth:`scp_sdk.SCP.trust_respond_to_challenge` returns one. The subject's
    signature covers every other field.
    """

    #: The answered request's ``challenge_id``.
    challenge_id: str
    #: Digest of the answered request, as 64 lowercase hex characters.
    request_digest: str
    #: DID of the subject.
    subject: str
    #: The attempt this response makes, starting at 1.
    attempt: int
    #: One output per test case.
    outputs: list[TestOutput]
    #: The subject's 64-byte signature as a list of integers.
    subject_signature: list[int]

    def __post_init__(self) -> None:
        _require_lower_hex_32("ChallengeResponse.challenge_id", self.challenge_id)
        _require_lower_hex_32("ChallengeResponse.request_digest", self.request_digest)
        _require_str("ChallengeResponse.subject", self.subject)
        _require_uint("ChallengeResponse.attempt", self.attempt, 32)
        if not isinstance(self.outputs, list) or not all(
            isinstance(o, TestOutput) for o in self.outputs
        ):
            msg = "ChallengeResponse.outputs must be a list of TestOutput"
            raise ValueError(msg)
        _require_signature("ChallengeResponse.subject_signature", self.subject_signature)

    def _to_wire(self) -> dict[str, Any]:
        """Convert to the Rust ``ChallengeResponse`` serde JSON shape."""
        wire = {f.name: getattr(self, f.name) for f in fields(self)}
        wire["outputs"] = [asdict(o) for o in self.outputs]
        return wire

    @classmethod
    def from_dict(cls, data: Any) -> ChallengeResponse:
        """Build a response from the Rust ``ChallengeResponse`` serde JSON shape.

        Raises:
            ValueError: If a field is absent, unknown, or malformed.
        """
        wire = dict(_exact_fields(cls, data))
        outputs = wire["outputs"]
        if not isinstance(outputs, list):
            msg = f"ChallengeResponse.outputs must be a list, got {outputs!r}"
            raise ValueError(msg)
        wire["outputs"] = [TestOutput(**_exact_fields(TestOutput, o)) for o in outputs]
        return cls(**wire)


@dataclass(frozen=True)
class CaseResult:
    """How one test case graded."""

    #: Whether the output met the case's expected output.
    passed: bool
    #: Why the case failed, or the evaluator's reason; ``None`` when there is
    #: none.
    reason: str | None

    @classmethod
    def from_dict(cls, data: Any) -> CaseResult:
        """Build a result from the bridge's case-result JSON shape."""
        wire = _exact_fields(cls, data)
        if not isinstance(wire["passed"], bool):
            msg = f"CaseResult.passed must be a bool, got {wire['passed']!r}"
            raise ValueError(msg)
        if wire["reason"] is not None:
            _require_str("CaseResult.reason", wire["reason"])
        return cls(passed=wire["passed"], reason=wire["reason"])


@dataclass(frozen=True)
class GradedChallenge:
    """What :meth:`scp_sdk.SCP.trust_grade_response` returns."""

    #: The signed record of the grading.
    record: ChallengeVerification
    #: One result per test case, in request order.
    case_results: list[CaseResult]
    #: Why the record could not be stored in this instance's trust store, as a
    #: ``{"code", "message"}`` dict, or ``None`` when it was stored. The record
    #: is signed and valid either way.
    trust_store_error: dict[str, str] | None


async def trust_verify_attestation(
    scp: SCP,
    context_id: str,
    attestation: CachedAttestationEnvelope | dict[str, Any],
) -> dict[str, Any]:
    """Verify an attestation's signature, evidence, expiry, its own revocation
    status, and the instance's revocation list for ``context_id``
    (ADR-017, §7.4.4).

    Takes the typed attestation envelope
    (:class:`CachedAttestationEnvelope` — the same wire DTO the
    cached-attestation inputs use) and serializes it to the serde wire shape
    internally (ADR-058) before calling the instance's
    ``trust_verify_attestation`` bridge method. The revocation list lives in
    the instance's storage, so the call needs the instance and the context.

    Args:
        scp: The :class:`~scp_sdk.SCP` instance whose revocation list is read.
        context_id: The context whose revocation list is checked.
        attestation: The typed attestation envelope (or a raw
            equivalently-shaped dict).

    Returns:
        A dict with ``valid`` (bool), ``chain_depth`` (int), and ``error``
        (str | None — the verification failure reason when ``valid`` is
        ``False``).

    Raises:
        ScpError: On a malformed context id or attestation, a missing storage
            provider, or a revocation list that cannot be read. A list that
            cannot be read raises; it never reads as ``valid: False``.
    """
    try:
        return await asyncio.to_thread(
            scp._native.trust_verify_attestation, context_id, json.dumps(attestation)
        )
    except Exception as exc:  # PyO3 raises native Scp*Error
        raise _coded_bridge_error(exc) from exc


__all__ = [
    "ADMISSION_REQUIREMENT_UNMET_CODE",
    "ATTEMPT_OUT_OF_ORDER_CODE",
    "ATTESTATION_TYPES",
    "CAPABILITY_DEFINITION_UNAVAILABLE_CODE",
    "CHALLENGE_CLOSED_CODE",
    "CHALLENGE_EXPIRED_CODE",
    "CHALLENGE_NOT_OPEN_CODE",
    "CHALLENGE_NOT_YET_GRADABLE_CODE",
    "CHALLENGE_SUITE_BELOW_MINIMUM_CODE",
    "CHALLENGE_WINDOW_OPEN_CODE",
    "COOLDOWN_ACTIVE_CODE",
    "DEFINITION_EQUIVOCATION_CODE",
    "DID_RESOLUTION_FAILED_CODE",
    "EMPTY_SUBJECT_DID_CODE",
    "EVALUATOR_UNAVAILABLE_CODE",
    "GRADING_CAPACITY_EXHAUSTED_CODE",
    "GRADING_IN_PROGRESS_CODE",
    "GRADING_LEASE_LOST_CODE",
    "INVALID_REQUIREMENT_CODE",
    "JSON_SCHEMA_VALIDATION_FAILED_CODE",
    "MALFORMED_AGENT_CAPABILITIES_CODE",
    "MALFORMED_CHALLENGE_VERIFICATIONS_CODE",
    "NON_CANONICAL_IDENTIFIER_CODE",
    "OUTPUTS_MISMATCH_CODE",
    "PARTICIPATION_FACT_VARIANTS",
    "PARTICIPATION_THRESHOLD_OPERATORS",
    "POLICY_OUTSIDE_DEFINITION_CODE",
    "RESPONSE_TOO_LARGE_CODE",
    "RETRIES_EXHAUSTED_CODE",
    "SCHEMA_REJECTED_CODE",
    "SELF_CHALLENGE_CODE",
    "STANDARD_NOT_GRADABLE_CODE",
    "TOO_MANY_CAPABILITY_REQUIREMENTS_CODE",
    "UNKNOWN_CHALLENGE_CODE",
    "UNTRUSTED_VERIFIER_CODE",
    "AttestationSummary",
    "AttestorInfo",
    "BehavioralRecord",
    "CachedAttestation",
    "CachedAttestationEnvelope",
    "CapabilityRequirement",
    "CapabilityValidation",
    "CaseResult",
    "ChallengeCase",
    "ChallengePolicy",
    "ChallengeRequest",
    "ChallengeResponse",
    "ChallengeVerification",
    "ChallengeVerified",
    "ContainsAll",
    "ContainsNone",
    "CreateChallengeConfig",
    "CustomEval",
    "EventLogEntry",
    "EventLogEntryPayload",
    "ExactMatch",
    "ExpectedOutput",
    "GradedChallenge",
    "ParticipationFact",
    "ParticipationProfile",
    "ParticipationThreshold",
    "RequireParticipation",
    "RetryCap",
    "SchemaMatch",
    "SelfAttested",
    "TestCase",
    "TestOutput",
    "ThresholdRequirement",
    "TrustEvaluation",
    "aggregate_trust_input",
    "evaluate_trust",
    "is_retryable",
    "participation_record",
    "retry_after",
    "trust_verify_attestation",
    "verify_participation_requirements",
]
