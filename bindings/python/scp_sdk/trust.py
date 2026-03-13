"""Trust evaluation for the SCP Python SDK.

Provides :func:`evaluate_trust` and the :class:`TrustEvaluation`
dataclass for assessing the trustworthiness of a participant within
an SCP context.  Trust evaluation is a four-layer model:

1. **Protocol Enforcement** -- mechanical pass/fail (UCAN validity,
   signatures, capability ceiling, revocation).
2. **Behavioral Validation** -- verified facts from the event log
   (participation history, governance actions, tool usage).
3. **Attestation Authenticity** -- verified signatures and evidence
   freshness from attestations.
4. **Trust Evaluation Inputs** -- endorsements, challenge results,
   and consequence structures for agent judgment.

See ``.docs/sketch.md`` section ``SCP.Trust.evaluate`` and
``.docs/adrs/phase-3.md`` ADR-014 for the SDK design.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from scp_sdk.errors import ContextError, ScpError

logger = logging.getLogger("scp_sdk")

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
# UCAN error classification for Layer 1 independent checks
# ---------------------------------------------------------------------------

# Error message prefixes that indicate an early token structure failure.
# Maps to CapabilityValidation.tokens_valid.
# Pipeline step 1 (parse/header validation) — fails before any other
# check has run.
_TOKEN_PARSE_PREFIXES: tuple[str, ...] = (
    "malformed token:",
    "deserialization failed:",
    "unsupported algorithm:",
    "unsupported UCAN version:",
)

# Error message prefixes that indicate a signature/chain integrity failure.
# Maps to CapabilityValidation.signatures_valid.
# Pipeline steps: 2 (signature), 3 (chain), 4 (root issuer),
#   5 (audience), 5a/5b (key scope), 6b (category A), 7 (attenuation).
_SIGNATURE_CHAIN_PREFIXES: tuple[str, ...] = (
    "signature verification failed",
    "invalid issuer:",
    "audience mismatch:",
    "delegation chain broken:",
    "circular delegation detected:",
    "attenuation violation:",
    "key scope mismatch:",
    "self-delegation",
    "Category A violation:",
)

# Error message prefixes that indicate a capability ceiling/scope failure.
# Maps to CapabilityValidation.within_ceiling.
# Pipeline steps: 6 (capability match), 8 (ceiling compliance).
_CAPABILITY_CEILING_PREFIXES: tuple[str, ...] = (
    "capability outside ceiling:",
    "capability not granted:",
)

# Error message prefixes for nonce failures (step 9).
# Maps to CapabilityValidation.tokens_valid.
# By step 9, signature and ceiling checks have already passed.
_NONCE_PREFIXES: tuple[str, ...] = (
    "nonce reused:",
    "nonce too old:",
    "nonce from the future:",
    "invalid nonce format:",
    "nonce tracker full:",
    "system clock error:",
)

# Error message prefixes that indicate a revocation failure.
# Maps to CapabilityValidation.not_revoked.
# Pipeline step: 10 (revocation check).
_REVOCATION_PREFIXES: tuple[str, ...] = ("token revoked:",)

# Error message prefixes for expiry/time-bounds failures (step 11).
# Maps to CapabilityValidation.tokens_valid.
# By step 11, all other checks have passed.
_EXPIRY_PREFIXES: tuple[str, ...] = (
    "token expired",
    "token not yet valid",
    "invalid time range:",
    "expiry too far in the future:",
)


def _extract_core_error(error_message: str) -> str:
    """Extract the core UcanError Display text from a bridge error message.

    The Rust bridge formats UCAN errors as::

        [SCP-PERM-3001] permission error: <UcanError Display> \u2014 <advice>

    This strips the code prefix and trailing advice to yield the raw
    ``UcanError`` Display text for prefix matching.
    """
    core = error_message
    if "] permission error: " in core:
        core = core.split("] permission error: ", 1)[1]
    # Strip the trailing advice suffix added by the Rust From<UcanError> impl.
    if " \u2014 " in core:
        core = core.split(" \u2014 ", 1)[0]
    return core


def _classify_ucan_error(error_message: str) -> str:
    """Classify a UCAN validation error into a fine-grained pipeline stage.

    Returns one of:
    - ``"token_parse"`` — step 1 (parse/header) failed
    - ``"signatures"`` — steps 2-7 (signature, chain, issuer, audience,
      key scope, attenuation) failed
    - ``"ceiling"`` — steps 6/8 (capability match, ceiling) failed
    - ``"nonce"`` — step 9 (nonce validation) failed
    - ``"revoked"`` — step 10 (revocation check) failed
    - ``"expiry"`` — step 11 (time bounds) failed
    - ``"unknown"`` — unrecognized error
    """
    core = _extract_core_error(error_message)

    for prefix in _TOKEN_PARSE_PREFIXES:
        if core.startswith(prefix):
            return "token_parse"

    for prefix in _SIGNATURE_CHAIN_PREFIXES:
        if core.startswith(prefix):
            return "signatures"

    for prefix in _CAPABILITY_CEILING_PREFIXES:
        if core.startswith(prefix):
            return "ceiling"

    for prefix in _NONCE_PREFIXES:
        if core.startswith(prefix):
            return "nonce"

    for prefix in _REVOCATION_PREFIXES:
        if core.startswith(prefix):
            return "revoked"

    for prefix in _EXPIRY_PREFIXES:
        if core.startswith(prefix):
            return "expiry"

    return "unknown"


# Maps pipeline stages to which CapabilityValidation fields are known
# to have passed when that stage fails, based on the 11-step sequential
# pipeline in validate.rs:
#
#   parse(1) → sig(2) → chain(3-5) → key_scope(5a/b) → cap_match(6)
#   → cat_A(6b) → attenuation(7) → ceiling(8) → nonce(9)
#   → revocation(10) → expiry(11)
#
# Each value lists the fields that PASSED before the failure point.
# The failing field is NOT in the set — it will be set to False.
# Fields after the failure are also not in the set (never ran).
_PASSED_BEFORE: dict[str, set[str]] = {
    # Step 1: parse fails — nothing passed.
    "token_parse": set(),
    # Steps 2-7: signature/chain fails — parse passed.
    "signatures": {"tokens_valid"},
    # Steps 6/8: capability/ceiling fails — parse + sig passed.
    "ceiling": {"tokens_valid", "signatures_valid"},
    # Step 9: nonce fails — parse + sig + ceiling all passed.
    "nonce": {"signatures_valid", "within_ceiling"},
    # Step 10: revocation fails — parse + sig + ceiling + nonce passed.
    "revoked": {"tokens_valid", "signatures_valid", "within_ceiling"},
    # Step 11: expiry fails — parse + sig + ceiling + nonce + revocation passed.
    "expiry": {"signatures_valid", "within_ceiling", "not_revoked"},
    # Unknown: conservatively nothing passed.
    "unknown": set(),
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class CapabilityValidation:
    """Layer 1: Protocol enforcement results (mechanical, pass/fail).

    All fields must be ``True`` for the subject to be considered
    protocol-compliant.
    """

    #: UCAN tokens parse and have valid structure.
    tokens_valid: bool = False

    #: All signatures verify against the claimed DIDs.
    signatures_valid: bool = False

    #: Requested capabilities are within the context's ceiling.
    within_ceiling: bool = False

    #: No tokens have been revoked.
    not_revoked: bool = False


@dataclass
class BehavioralRecord:
    """Layer 2: Behavioral validation (verified facts from event log)."""

    #: Number of contexts the subject has participated in.
    contexts_participated: int = 0

    #: Total participation duration in seconds.
    total_duration: float = 0.0

    #: Number of governance actions taken against the subject.
    governance_actions_against: int = 0

    #: Tool invocation history as list of ``{"type": str, "count": int}``.
    tool_invocations: list[dict[str, Any]] = field(default_factory=list)

    #: Role change history.
    role_history: list[dict[str, Any]] = field(default_factory=list)

    #: Endorsement accuracy score (0.0--1.0), if available.
    endorsement_accuracy: float | None = None


@dataclass
class Attestation:
    """Layer 3: A single verified attestation."""

    #: Attestation type identifier.
    type: str

    #: Whether the attestation signature is valid.
    signature_valid: bool

    #: Whether the evidence is valid (if applicable).
    evidence_valid: bool | None = None

    #: Whether the attestation is within its renewal interval.
    fresh: bool = False

    #: DID of the attestation issuer.
    issuer: str = ""

    #: The claim content.
    claim: dict[str, Any] = field(default_factory=dict)


@dataclass
class Endorsement:
    """Layer 4: An endorsement from another participant."""

    #: DID of the endorser.
    from_did: str

    #: The capability being endorsed.
    capability: str

    #: Behavioral summary of the endorser.
    endorser_behavioral_record: dict[str, Any] = field(default_factory=dict)


@dataclass
class ChallengeResult:
    """Layer 4: Result of a capability challenge."""

    #: The capability that was challenged.
    capability: str

    #: Whether the challenge was passed.
    passed: bool

    #: ISO 8601 timestamp when the challenge was verified.
    verified_at: str = ""


@dataclass
class TrustEvaluation:
    """Complete trust evaluation result for a subject in a context.

    Contains the four-layer trust model: protocol enforcement,
    behavioral validation, attestation authenticity, and trust
    evaluation inputs.  The agent/client decides what to do with this
    information -- the protocol provides the data, not the verdict.

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

    #: Layer 2: Behavioral validation (verified facts).
    behavioral_record: BehavioralRecord | None = None

    #: Layer 3: Attestation authenticity (verified signatures).
    attestations: list[Attestation] = field(default_factory=list)

    #: Layer 4: Endorsements from other participants.
    endorsements: list[Endorsement] = field(default_factory=list)

    #: Layer 4: Challenge results.
    challenge_results: list[ChallengeResult] = field(default_factory=list)

    #: Layer 4: Consequence rules defined by the context.
    consequence_structure: list[dict[str, Any]] | None = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def evaluate_trust(
    subject_did: str,
    context_id: str,
    capability_tokens: list[str] | None = None,
) -> TrustEvaluation:
    """Evaluate the trustworthiness of a participant in a context.

    Performs the four-layer trust evaluation model:

    1. **Protocol enforcement** -- validates UCAN tokens, signatures,
       capability ceiling compliance, and revocation status.
    2. **Behavioral validation** -- queries the event log for the
       subject's participation history.
    3. **Attestation authenticity** -- verifies signatures and evidence
       freshness for any attestations the subject presents.
    4. **Trust evaluation inputs** -- gathers endorsements, challenge
       results, and consequence structures.

    The result is an informational :class:`TrustEvaluation` -- the
    protocol provides structured data, but the agent/client decides
    what trust threshold to apply.

    Args:
        subject_did: The DID of the participant to evaluate.
        context_id: The ID of the context to evaluate trust within.
        capability_tokens: Optional list of UCAN token strings to
            validate as part of the evaluation.

    Returns:
        A :class:`TrustEvaluation` with all four layers populated.

    Raises:
        ScpError: If the evaluation cannot be performed (e.g., context
            not found, bridge unavailable).

    Example::

        evaluation = await evaluate_trust(
            subject_did="did:dht:z6MkBob...",
            context_id="ctx_abc123",
            capability_tokens=["eyJhbGciOiJFZERTQSIs..."],
        )
        if evaluation.capability_validation.tokens_valid:
            print("UCAN tokens are valid")
    """
    logger.debug(
        "Evaluating trust for %s in context %s",
        subject_did,
        context_id,
    )

    bridge = _bridge()

    # Layer 1: Validate capability tokens if provided.
    # Each of the four CapabilityValidation fields is set independently
    # based on which specific check failed (ADR-017, spec section 9.3).
    # The bridge's ucan_validate runs an 11-step pipeline that returns
    # on the first failure. We classify the error to determine which
    # check failed, and infer which earlier checks passed based on
    # the pipeline execution order.
    cap_validation = CapabilityValidation()
    if capability_tokens:
        # Start optimistic: assume all pass until a failure proves otherwise.
        cap_validation.tokens_valid = True
        cap_validation.signatures_valid = True
        cap_validation.within_ceiling = True
        cap_validation.not_revoked = True

        for token in capability_tokens:
            try:
                bridge.ucan_validate(context_id, token, "*")
            except Exception as exc:
                error_msg = str(exc)
                failed_category = _classify_ucan_error(error_msg)
                passed = _PASSED_BEFORE.get(failed_category, set())

                # The failing category is definitely False.
                # Categories before it in the pipeline passed.
                # Categories after it are unknown (never ran) — set False.
                cap_validation.tokens_valid = "tokens_valid" in passed
                cap_validation.signatures_valid = "signatures_valid" in passed
                cap_validation.within_ceiling = "within_ceiling" in passed
                cap_validation.not_revoked = "not_revoked" in passed
                break

    # Layer 2: Query behavioral record from event log.
    behavioral: BehavioralRecord | None = None
    try:
        events = bridge.event_log_query(
            context_id,
            {"actor_did": subject_did},
        )
        behavioral = BehavioralRecord(
            contexts_participated=1,
            tool_invocations=[
                {"type": e.event_type, "count": 1} for e in events if e.event_type == "ToolInvoked"
            ],
        )
    except ContextError:
        logger.debug(
            "Could not retrieve behavioral record for %s",
            subject_did,
        )

    return TrustEvaluation(
        subject_did=subject_did,
        context_id=context_id,
        capability_validation=cap_validation,
        behavioral_record=behavioral,
    )


# ---------------------------------------------------------------------------
# Participation types (spec section 9.3, SCP-BA-004)
# ---------------------------------------------------------------------------


@dataclass
class ParticipationFact:
    """A verified participation fact used in admission evaluation.

    See spec section 9.3 (Sybil Resistance and Identity Uniqueness).
    """

    #: Type of participation fact (e.g., ``"context_membership"``).
    fact_type: str

    #: DID of the participant this fact pertains to.
    participant_did: str

    #: Context ID where the fact was observed.
    context_id: str

    #: Numeric value of the fact (e.g., participation count).
    value: float = 0.0


@dataclass
class ParticipationThreshold:
    """A threshold requirement for context admission.

    See spec section 9.3 (Sybil Resistance and Identity Uniqueness).
    """

    #: The fact type this threshold applies to.
    fact_type: str

    #: Minimum value required to satisfy the threshold.
    minimum: float

    #: Optional maximum value constraint.
    maximum: float | None = None


@dataclass
class ParticipationProfile:
    """A participant's aggregated participation profile.

    See spec section 9.3 (Sybil Resistance and Identity Uniqueness).
    """

    #: DID of the participant.
    participant_did: str

    #: Verified participation facts.
    facts: list[ParticipationFact] = field(default_factory=list)


@dataclass
class RequireParticipation:
    """Participation-based admission requirement for a context.

    See spec section 9.3 (Sybil Resistance and Identity Uniqueness).
    """

    #: Thresholds that must be met for admission.
    thresholds: list[ParticipationThreshold] = field(default_factory=list)

    #: Whether ALL thresholds must be met (True) or ANY (False).
    require_all: bool = True


def verify_participation_requirements(
    requirement: RequireParticipation,
    profile: ParticipationProfile,
) -> bool:
    """Verify whether a participant meets participation requirements.

    Evaluates the participant's profile against the requirement's
    thresholds. Returns ``True`` if the participant meets the
    criteria, ``False`` otherwise.

    Args:
        requirement: The participation requirement to verify against.
        profile: The participant's participation profile.

    Returns:
        ``True`` if requirements are met, ``False`` otherwise.
    """
    if not requirement.thresholds:
        return True

    results: list[bool] = []
    for threshold in requirement.thresholds:
        matching_facts = [f for f in profile.facts if f.fact_type == threshold.fact_type]
        if not matching_facts:
            results.append(False)
            continue

        total_value = sum(f.value for f in matching_facts)
        meets_min = total_value >= threshold.minimum
        meets_max = threshold.maximum is None or total_value <= threshold.maximum
        results.append(meets_min and meets_max)

    if requirement.require_all:
        return all(results)
    return any(results)


__all__ = [
    "Attestation",
    "BehavioralRecord",
    "CapabilityValidation",
    "ChallengeResult",
    "Endorsement",
    "ParticipationFact",
    "ParticipationProfile",
    "ParticipationThreshold",
    "RequireParticipation",
    "TrustEvaluation",
    "evaluate_trust",
    "verify_participation_requirements",
]
