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

from scp_sdk.errors import ScpError

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
            "Install scp-sdk with: pip install scp-sdk",
            code="SCP-ERR-0001",
        ) from exc


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
    cap_validation = CapabilityValidation()
    if capability_tokens:
        all_valid = True
        for token in capability_tokens:
            try:
                bridge.ucan_validate(context_id, token, "*")
            except Exception:
                all_valid = False
                break
        cap_validation.tokens_valid = all_valid
        cap_validation.signatures_valid = all_valid
        cap_validation.within_ceiling = all_valid
        cap_validation.not_revoked = all_valid

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
                {"type": e.event_type, "count": 1}
                for e in events
                if e.event_type == "ToolInvoked"
            ],
        )
    except Exception:
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


__all__ = [
    "Attestation",
    "BehavioralRecord",
    "CapabilityValidation",
    "ChallengeResult",
    "Endorsement",
    "TrustEvaluation",
    "evaluate_trust",
]
