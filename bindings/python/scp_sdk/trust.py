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
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, TypedDict

from scp_sdk.errors import ContextError, ScpError, _coded_bridge_error

if TYPE_CHECKING:
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
    try:
        import _scp_core  # type: ignore[import-not-found]

        return _scp_core
    except ImportError as exc:
        raise ScpError(
            "The _scp_core extension module is not installed. "
            "Install scp-python with: pip install scp-python",
            code="SCP-UNKNOWN-0001",
        ) from exc


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

#: Valid capability verification-level names, matching the Rust
#: ``VerificationLevel`` enum variants in ``scp-core``.
VERIFICATION_LEVELS: frozenset[str] = frozenset({"SelfAttested", "ChallengeVerified"})


@dataclass
class VerificationLevel:
    """How a capability must be verified for admission.

    Mirrors the Rust ``VerificationLevel`` enum (``scp-core``). Serializes as
    the bare variant name string (``"SelfAttested"`` / ``"ChallengeVerified"``).

    - ``"SelfAttested"`` -- the agent claims the capability (present in their
      capability list); no challenge proof required.
    - ``"ChallengeVerified"`` -- the capability was verified through the
      challenge-response protocol. Also satisfies ``SelfAttested``.
    """

    #: The verification-level variant name.
    name: str

    def __post_init__(self) -> None:
        if self.name not in VERIFICATION_LEVELS:
            msg = (
                f"Invalid VerificationLevel name {self.name!r}. "
                f"Valid: {sorted(VERIFICATION_LEVELS)}"
            )
            raise ValueError(msg)


@dataclass
class CapabilityRequirement:
    """A single admission requirement: a capability URI and the minimum
    verification level needed.

    Mirrors the Rust ``CapabilityRequirement`` struct (``scp-core``). See
    §7.3.4.4.
    """

    #: The capability URI that must be present.
    capability: str

    #: The minimum verification level required.
    verification_level: VerificationLevel

    def _to_bridge_dict(self) -> dict[str, Any]:
        """Convert to a dict matching the Rust ``CapabilityRequirement``
        serde JSON representation."""
        return {
            "capability": self.capability,
            "verification_level": self.verification_level.name,
        }


@dataclass
class ChallengeVerificationMethod:
    """How a capability was verified, as recorded in a
    :class:`ChallengeVerification`.

    Mirrors the Rust ``VerificationMethod`` enum (``scp-core``). Named
    ``ChallengeVerificationMethod`` in the SDK to avoid colliding with the
    DID-document ``VerificationMethod`` type in the other bindings; the wire
    shape is unchanged.

    - ``name == "SelfAttested"`` serializes as the bare string
      ``"SelfAttested"``.
    - ``name == "ChallengeVerified"`` serializes as
      ``{"ChallengeVerified": {"challenge_type": <uri>}}`` and requires
      ``challenge_type``.

    SECURITY: ``verification_method`` is NOT covered by the verifier signature
    (ADR-017 caveat) — consumers MUST NOT key trust decisions on it.
    """

    #: The verification-method variant name.
    name: str

    #: The challenge-type capability URI. Required iff ``name`` is
    #: ``"ChallengeVerified"``; must be ``None`` otherwise.
    challenge_type: str | None = None

    def __post_init__(self) -> None:
        if self.name not in VERIFICATION_LEVELS:
            msg = (
                f"Invalid ChallengeVerificationMethod name {self.name!r}. "
                f"Valid: {sorted(VERIFICATION_LEVELS)}"
            )
            raise ValueError(msg)
        if self.name == "ChallengeVerified" and self.challenge_type is None:
            msg = "ChallengeVerificationMethod 'ChallengeVerified' requires challenge_type"
            raise ValueError(msg)
        if self.name == "SelfAttested" and self.challenge_type is not None:
            msg = "ChallengeVerificationMethod 'SelfAttested' must not carry challenge_type"
            raise ValueError(msg)

    def _to_bridge_value(self) -> Any:
        """Convert to the serde-tagged value the Rust ``VerificationMethod``
        deserializes."""
        if self.name == "SelfAttested":
            return "SelfAttested"
        return {"ChallengeVerified": {"challenge_type": self.challenge_type}}


@dataclass
class ChallengeVerification:
    """A signed record that a specific verifier tested a capability and the
    agent passed (spec §7.3.4.2, ADR-017).

    Mirrors the Rust ``ChallengeVerification`` struct (``scp-core``). Pass a
    list of these to :func:`check_capability_requirements` to satisfy
    ``ChallengeVerified`` requirements.

    SECURITY (ADR-017 caveat): only the *signed* fields bind trust —
    ``verification_id``, ``verifier_did``, ``subject_did``, ``capability_uri``,
    ``challenge_type``, ``passed``, ``score``, ``test_count``, ``pass_count``,
    ``verified_at``, ``expires_at``, ``context_id``. The ``result``,
    ``completed_at``, and ``verification_method`` fields are NOT signed and can
    be altered after minting without invalidating the signature. Consumers MUST
    NOT key trust decisions on those unsigned fields.
    """

    #: Unique verification identifier (derived from the challenge ID).
    verification_id: str

    #: DID of the verifier who issued and verified the challenge.
    verifier_did: str

    #: DID of the subject who answered the challenge.
    subject_did: str

    #: The capability URI that was verified.
    capability_uri: str

    #: The type of challenge that was verified (a capability URI string).
    challenge_type: str

    #: How the capability was verified (unsigned metadata).
    verification_method: ChallengeVerificationMethod

    #: Whether the subject passed the challenge overall.
    passed: bool

    #: Total number of test cases in the challenge.
    test_count: int

    #: Number of test cases the subject passed.
    pass_count: int

    #: The challenge-specific result from the response (arbitrary JSON, unsigned).
    result: Any

    #: Unix timestamp (seconds) when the response was completed (unsigned).
    completed_at: int

    #: Unix timestamp (seconds) when the verification was performed.
    verified_at: int

    #: Unix timestamp (seconds) when this verification expires.
    expires_at: int

    #: Ed25519 signature by the verifier over the verification record.
    #: 64-byte array as a list of integers.
    verifier_signature: list[int]

    #: Optional numeric score (0-100) for graded challenges.
    score: int | None = None

    #: Context in which the challenge was issued, if any.
    context_id: str | None = None

    def __post_init__(self) -> None:
        _u64_fields = (
            "completed_at",
            "verified_at",
            "expires_at",
        )
        for name in _u64_fields:
            val = getattr(self, name)
            if val < 0:
                msg = (
                    f"ChallengeVerification.{name} must be non-negative "
                    f"(Rust type is u64), got {val}"
                )
                raise ValueError(msg)
            if val > 0xFFFF_FFFF_FFFF_FFFF:
                msg = (
                    f"ChallengeVerification.{name} must be <= 18446744073709551615 "
                    f"(Rust type is u64), got {val}"
                )
                raise ValueError(msg)

        # test_count / pass_count are u32.
        for name in ("test_count", "pass_count"):
            val = getattr(self, name)
            if val < 0:
                msg = (
                    f"ChallengeVerification.{name} must be non-negative "
                    f"(Rust type is u32), got {val}"
                )
                raise ValueError(msg)
            if val > 0xFFFF_FFFF:
                msg = (
                    f"ChallengeVerification.{name} must be <= 4294967295 "
                    f"(Rust type is u32), got {val}"
                )
                raise ValueError(msg)

        if self.score is not None and not (0 <= self.score <= 0xFFFF_FFFF):
            msg = (
                f"ChallengeVerification.score must be a u32 in [0, 4294967295] "
                f"or None, got {self.score}"
            )
            raise ValueError(msg)

        if len(self.verifier_signature) != 64:
            msg = (
                f"ChallengeVerification.verifier_signature must be exactly 64 "
                f"elements, got {len(self.verifier_signature)}"
            )
            raise ValueError(msg)
        for i, elem in enumerate(self.verifier_signature):
            if not (0 <= elem <= 255):
                msg = f"ChallengeVerification.verifier_signature[{i}] must be 0-255, got {elem}"
                raise ValueError(msg)

    def _to_bridge_dict(self) -> dict[str, Any]:
        """Convert to a dict matching the Rust ``ChallengeVerification`` serde
        JSON representation."""
        return {
            "verification_id": self.verification_id,
            "verifier_did": self.verifier_did,
            "subject_did": self.subject_did,
            "capability_uri": self.capability_uri,
            "challenge_type": self.challenge_type,
            "verification_method": self.verification_method._to_bridge_value(),
            "passed": self.passed,
            "score": self.score,
            "test_count": self.test_count,
            "pass_count": self.pass_count,
            "result": self.result,
            "completed_at": self.completed_at,
            "verified_at": self.verified_at,
            "expires_at": self.expires_at,
            "context_id": self.context_id,
            "verifier_signature": self.verifier_signature,
        }


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
    The diagnostic is non-throwing for capability outcomes; it raises only
    for malformed FFI inputs (e.g. a ``context_id`` with control
    characters), which propagate to the caller.

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
            # token) still raises and propagates.
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
            result = await asyncio.to_thread(
                instance.ucan_evaluate, context_id, token, None, subject_did
            )
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
        behavioral = _participation_record_from(instance, context_id, subject_did, "[]")
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


def participation_record(
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
    return _participation_record_from(instance, context_id, subject_did, cached_json)


def aggregate_trust_input(
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

    result = instance.aggregate_trust_input(context_id, subject_did, *wire)
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


def check_capability_requirements(
    context_id: str,
    subject_did: str,
    requirements: list[CapabilityRequirement],
    agent_capabilities: list[str],
    challenge_verifications: list[ChallengeVerification],
) -> None:
    """Verify an agent's capabilities against a context's admission requirements.

    Delegates to the Rust ``scp-core`` implementation via the PyO3 bridge
    (spec §7.3.4.4, SCP-ACR-008). For each requirement the agent must either
    self-attest the capability (``SelfAttested``) or present a valid
    ``ChallengeVerification`` record (``ChallengeVerified``). Each supplied
    verification is signature-verified against the production DID resolver and
    only counts if it is authentic and its signed ``subject_did``/``context_id``
    equal ``subject_did``/``context_id`` — a genuine result minted for another
    subject or context cannot admit this agent.

    Security caveat — authenticity is not authorization: a passing
    ``ChallengeVerified`` check proves the verifier's signature is authentic and
    bound to this subject/context, NOT that the verifier is trusted. A
    ``verifier_did`` is self-certifying, so a subject can present a genuinely
    signed result from a verifier it controls. Establish verifier legitimacy
    separately (a trusted-verifier set, a context-membership proof, or the
    §7.3.5 threshold/independence path) and do NOT treat success as an
    authorization decision.

    Success is indicated by returning without exception. Failures raise the
    bridge's native coded ``ValidationError`` (rooted at ``ScpError``); the
    structured per-case ``SCP-VALID-*`` code is recoverable from the
    exception's string form (the ``[CODE]``-prefixed message), so callers
    branch on the code — never on error prose.

    Args:
        context_id: The context the agent is being admitted to.
        subject_did: The DID of the agent being admitted. Must be a valid DID.
        requirements: Typed :class:`CapabilityRequirement` values. Serialized
            internally to the serde wire shape (ADR-058).
        agent_capabilities: The agent's self-attested capability URIs.
        challenge_verifications: The agent's typed :class:`ChallengeVerification`
            records. Serialized internally to the serde wire shape (ADR-058).

    Raises:
        ScpError: If the bridge module is not available.
        ValidationError: Native bridge exception whose ``[SCP-VALID-NNNN]``-
            prefixed message carries the per-case structured code:
            ``SCP-VALID-7000`` for a malformed ``subject_did``;
            ``SCP-VALID-7073`` / ``SCP-VALID-7074`` / ``SCP-VALID-7075`` for
            malformed requirements / agent-capabilities /
            challenge-verifications JSON (unreachable through this typed
            wrapper, which always serializes valid JSON); ``SCP-VALID-7076``
            for an unmet admission requirement, with the specific failure
            reason from ``AdmissionError``; and ``SCP-VALID-7077`` for its
            empty-subject variant.
    """
    bridge = _bridge()

    requirements_json = json.dumps([r._to_bridge_dict() for r in requirements])
    agent_capabilities_json = json.dumps(agent_capabilities)
    challenge_verifications_json = json.dumps(
        [c._to_bridge_dict() for c in challenge_verifications]
    )

    bridge.check_capability_requirements(
        context_id,
        subject_did,
        requirements_json,
        agent_capabilities_json,
        challenge_verifications_json,
    )


# ---------------------------------------------------------------------------
# Challenge trust-input wire DTOs + typed verification wrappers (§7.3.4,
# ADR-058)
# ---------------------------------------------------------------------------


class ChallengeRequest(TypedDict):
    """A challenge request for capability verification (ADR-017, §7.3.4).

    The serde wire shape of the Rust ``ChallengeRequest`` (``scp-core``) the
    bridge deserializes for :func:`trust_verify_response`. ``challenge_type``
    is a bare capability URI string (the Rust ``ChallengeType`` serializes as
    its URI string); ``timeout`` is the ``std::time::Duration`` serde shape
    (``{"secs": int, "nanos": int}``). In the same pass-through TypedDict
    family as :class:`CachedAttestationEnvelope`; a raw equivalently-shaped
    ``dict`` is also accepted.
    """

    #: Unique challenge identifier (UUID v4).
    challenge_id: str
    #: The type of challenge being issued (a capability URI string).
    challenge_type: str
    #: DID of the entity issuing the challenge.
    challenger_did: str
    #: DID of the entity being challenged.
    subject_did: str
    #: The capability URI being tested (§7.3.4.1).
    capability_uri: str
    #: Challenge-specific parameters (schema, test vectors, limits, etc.).
    parameters: Any
    #: Maximum time allowed to respond (``{"secs": int, "nanos": int}``).
    timeout: dict[str, int]
    #: Ed25519 signature over the canonical challenge bytes (64 bytes as ints).
    signature: list[int]


class ChallengeResponse(TypedDict):
    """A response to a challenge request (ADR-017, §7.3.4).

    The serde wire shape of the Rust ``ChallengeResponse`` (``scp-core``) the
    bridge deserializes for :func:`trust_verify_response`.
    """

    #: The challenge ID this response corresponds to.
    challenge_id: str
    #: DID of the entity responding to the challenge.
    responder_did: str
    #: Challenge-specific result data (pass/fail, metrics, evidence, etc.).
    result: Any
    #: Unix timestamp (seconds) when the response was completed.
    completed_at: int
    #: Ed25519 signature over the canonical response bytes (64 bytes as ints).
    signature: list[int]


def trust_verify_attestation(
    attestation: CachedAttestationEnvelope | dict[str, Any],
) -> dict[str, Any]:
    """Verify an attestation's signature, evidence, expiry, and revocation
    status (ADR-017, §7.4).

    Takes the typed attestation envelope
    (:class:`CachedAttestationEnvelope` — the same wire DTO the
    cached-attestation inputs use) and serializes it to the serde wire shape
    internally (ADR-058) before calling the bridge
    ``trust_verify_attestation`` free function.

    Args:
        attestation: The typed attestation envelope (or a raw
            equivalently-shaped dict).

    Returns:
        A dict with ``valid`` (bool), ``chain_depth`` (int), and ``error``
        (str | None — the verification failure reason when ``valid`` is
        ``False``).

    Raises:
        ScpError: If the bridge module is not available.
        ValueError: If the serialized envelope fails bridge deserialization.
    """
    bridge = _bridge()
    return bridge.trust_verify_attestation(json.dumps(attestation))


def trust_verify_response(
    challenge: ChallengeRequest | dict[str, Any],
    response: ChallengeResponse | dict[str, Any],
) -> bool:
    """Verify a challenge response against its original challenge request
    (ADR-017, §7.3.4).

    Takes the typed :class:`ChallengeRequest` / :class:`ChallengeResponse`
    wire DTOs and serializes them to the serde wire shapes internally
    (ADR-058) before calling the bridge ``trust_verify_response`` free
    function.

    Args:
        challenge: The typed challenge request (or a raw equivalently-shaped
            dict).
        response: The typed challenge response (or a raw equivalently-shaped
            dict).

    Returns:
        ``True`` if the response is valid (correct responder, within timeout,
        valid signature), ``False`` otherwise.

    Raises:
        ScpError: If the bridge module is not available.
        ValueError: If a serialized record fails bridge deserialization.
    """
    bridge = _bridge()
    return bridge.trust_verify_response(json.dumps(challenge), json.dumps(response))


def trust_create_challenge(target_did: str) -> dict[str, Any]:
    """Create a challenge request for capability verification (ADR-017,
    §7.3.4).

    Calls the bridge ``trust_create_challenge`` free function, which builds a
    schema-validation challenge request for ``target_did`` signed with an
    ephemeral Ed25519 key. Pass the returned ``challenge_json`` to
    :func:`trust_verify_response` alongside the responder's serialized
    :class:`ChallengeResponse`.

    Args:
        target_did: DID of the entity being challenged.

    Returns:
        A dict with ``challenge_id`` (str — the unique challenge ID, UUID v4)
        and ``challenge_json`` (str — the full serialized
        :class:`ChallengeRequest` JSON).

    Raises:
        ScpError: If the bridge module is not available, ``target_did`` fails
            DID validation, or challenge signing fails.
    """
    bridge = _bridge()
    return bridge.trust_create_challenge(target_did)


__all__ = [
    "ATTESTATION_TYPES",
    "PARTICIPATION_FACT_VARIANTS",
    "PARTICIPATION_THRESHOLD_OPERATORS",
    "VERIFICATION_LEVELS",
    "AttestationSummary",
    "AttestorInfo",
    "BehavioralRecord",
    "CachedAttestation",
    "CachedAttestationEnvelope",
    "CapabilityRequirement",
    "CapabilityValidation",
    "ChallengeRequest",
    "ChallengeResponse",
    "ChallengeVerification",
    "ChallengeVerificationMethod",
    "EventLogEntry",
    "EventLogEntryPayload",
    "ParticipationFact",
    "ParticipationProfile",
    "ParticipationThreshold",
    "RequireParticipation",
    "ThresholdRequirement",
    "TrustEvaluation",
    "VerificationLevel",
    "aggregate_trust_input",
    "check_capability_requirements",
    "evaluate_trust",
    "participation_record",
    "trust_create_challenge",
    "trust_verify_attestation",
    "trust_verify_response",
    "verify_participation_requirements",
]
