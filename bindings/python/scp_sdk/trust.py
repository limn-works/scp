"""Trust evaluation for the SCP Python SDK.

Provides :func:`evaluate_trust` and the :class:`TrustEvaluation`
dataclass for assessing the trustworthiness of a participant within
an SCP context.  Trust evaluation is a four-layer model:

1. **Protocol Enforcement** -- mechanical pass/fail (UCAN validity,
   signatures, capability ceiling, nonce, revocation, and expiry).
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

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from scp_sdk.errors import ContextError, ScpError

if TYPE_CHECKING:
    from scp_sdk.scp import SCP

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
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class CapabilityValidation:
    """Layer 1: Protocol enforcement results (mechanical, pass/fail).

    All fields must be ``True`` for the subject to be considered
    protocol-compliant.

    These six per-stage booleans are the canonical structured result of
    the read-only ``ucan_evaluate`` diagnostic (spec §7.2.4, ADR-055):
    one boolean per pipeline-stage group of the 11-step ADR-016 pipeline.
    They are populated directly from the bridge's structured result --
    never reverse-engineered by parsing error prose. The result is
    strictly ordered and short-circuiting: a field is ``True`` only if its
    stage ran *and* passed, so the first failing stage and every later
    stage are ``False``.
    """

    #: UCAN tokens parse and have valid structure (step 1).
    tokens_valid: bool = False

    #: All signatures verify against the claimed DIDs across the whole
    #: delegation chain (steps 2-7).
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
        "ToolInvocationCount",
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
    - ``"ToolInvocationCount"`` -- total tool invocations.
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

    #: Total tool invocations across all tool types.
    tool_invocation_count: int = 0

    #: Whether ``tool_invocation_count`` is anchored in the canonical Merkle
    #: log. ``False`` until ADR-051 makes ``ToolInvoked`` a convergent leaf:
    #: the count is computed from per-author local events, not the Merkle log
    #: (§7.3.2; ADR-011 amendment exclusion taxonomy §2). Consumers MUST NOT
    #: treat the count as Merkle-proven while this is ``False``.
    tool_invocation_count_anchored: bool = False

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
            "tool_invocation_count",
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
            "tool_invocation_count": self.tool_invocation_count,
            "tool_invocation_count_anchored": self.tool_invocation_count_anchored,
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


def _structured_to_capability_validation(result: Any) -> CapabilityValidation:
    """Map a bridge ``CapabilityValidation`` record onto the SDK dataclass.

    The bridge's structured ``ucan_evaluate`` result (PyO3
    ``PyCapabilityValidation``) exposes the same six snake_case booleans as
    the SDK :class:`CapabilityValidation`. This reads them directly -- the
    per-check breakdown comes from the structured record, never from parsing
    error prose (spec §7.2.4, ADR-055 Decision 3).
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
    subject_did: str,
    context_id: str,
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
    4. **Trust evaluation inputs** — gathers endorsements, challenge
       results, and consequence structures.

    Layer 1 consumes the structured bridge result directly (ADR-055): it
    does not reverse-engineer *which* check failed by parsing error prose.
    The diagnostic is non-throwing for capability outcomes; it raises only
    for malformed FFI inputs (e.g. a ``context_id`` with control
    characters), which propagate to the caller.

    This module-level function consumes the :class:`SCP` instance to
    dispatch ``ucan_evaluate`` and ``event_log_query`` bridge calls. The
    callers already receive the :class:`SCP` instance by value (matching
    the ADR-048 explicit-instance pattern).

    Args:
        scp: The :class:`~scp_sdk.SCP` instance to dispatch bridge calls on.
        subject_did: The DID of the participant to evaluate.
        context_id: The ID of the context to evaluate trust within.
        capability_tokens: Optional list of UCAN token strings to
            evaluate as part of the evaluation.

    Returns:
        A :class:`TrustEvaluation` with all four layers populated.
    """
    logger.debug(
        "Evaluating trust for %s in context %s",
        subject_did,
        context_id,
    )

    bridge = _bridge()
    # `_bridge()` is the seam tests use to inject a mock — patching
    # `scp_sdk.trust._bridge` returns a mock whose `ucan_evaluate` /
    # `event_log_query` attributes stand in for the live bridge. In
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
            # for. See ADR-055 / spec §7.2.4: the diagnostic's challenge
            # capability is optional, and ``None`` means intrinsic-validity.
            result = await asyncio.to_thread(instance.ucan_evaluate, context_id, token)
            per_token = _structured_to_capability_validation(result)
            cap_validation.tokens_valid &= per_token.tokens_valid
            cap_validation.signatures_valid &= per_token.signatures_valid
            cap_validation.within_ceiling &= per_token.within_ceiling
            cap_validation.nonce_valid &= per_token.nonce_valid
            cap_validation.not_revoked &= per_token.not_revoked
            cap_validation.time_bounds_valid &= per_token.time_bounds_valid

    # Layer 2: query behavioral record from the event log.
    behavioral: BehavioralRecord | None = None
    try:
        events = await asyncio.to_thread(
            instance.event_log_query,
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


def aggregate_trust_input(
    scp: SCP,
    context_id: str,
    subject_did: str,
    events: list[dict[str, Any]],
    merkle_root: list[int],
    consequence_rules: list[dict[str, Any]] | None = None,
    threshold_requirements: dict[str, Any] | None = None,
    attestor_sets: dict[str, Any] | None = None,
    cached_attestations: list[dict[str, Any]] | None = None,
    challenge_results: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Aggregate all trust engine layers into a single TrustInput.

    Phase 4 PR 5 Agent B+C retained this module-level helper because it is
    a pure serialization layer over :meth:`scp_sdk.SCP.aggregate_trust_input`
    -- it takes the caller-friendly Python types (lists/dicts of ``Any``)
    and produces the ``json.dumps``-serialized strings the bridge expects.
    Using ``is not None`` (never a falsy check) keeps the distinction between
    an explicit empty collection and an absent parameter — empty means
    "no rules apply", absent means "use protocol defaults".

    Args:
        scp: The :class:`~scp_sdk.SCP` instance to dispatch on.
        context_id: The context to aggregate trust inputs for.
        subject_did: The DID of the subject to evaluate.
        events: List of event log entry dicts.
        merkle_root: 32-byte Merkle root as a list of integers.
        consequence_rules: Optional list of consequence rule dicts.
        threshold_requirements: Optional mapping of attestation type
            names to threshold requirement dicts.
        attestor_sets: Optional mapping of attestation type names to
            lists of attestor info dicts.
        cached_attestations: Optional list of cached attestation dicts
            to pre-populate the in-memory trust store.
        challenge_results: Optional list of challenge verification
            dicts to pre-populate the in-memory trust store.

    Returns:
        A dict containing the aggregated ``TrustInput`` fields:
        ``verified_attestations``, ``participation_record``,
        ``challenge_results``, ``consequence_structure``, and
        ``threshold_counts``.
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

    events_json = json.dumps(events)
    merkle_root_json = json.dumps(merkle_root)
    # Distinguish "explicit empty collection" from "absent". Each Optional
    # parameter must round-trip an empty list/dict as `"[]"` / `"{}"` so the
    # bridge sees the caller's intent. Never use the falsy form — it collapses
    # `[]` (no rules to evaluate) to the same value as `None` (use defaults).
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
        json.dumps(challenge_results) if challenge_results is not None else "[]"
    )

    result = instance.aggregate_trust_input(
        context_id,
        subject_did,
        events_json,
        merkle_root_json,
        consequence_rules_json,
        threshold_requirements_json,
        attestor_sets_json,
        cached_attestations_json,
        challenge_results_json,
    )
    if isinstance(result, str):
        return json.loads(result)
    return result


def verify_participation_requirements(
    requirements: list[RequireParticipation],
    profiles: list[ParticipationProfile],
) -> None:
    """Verify participation profiles against admission requirements.

    Delegates to the Rust ``scp-core`` implementation via the PyO3
    bridge, which performs the full verification including:

    1. Signature verification on all participation profiles.
    2. Freshness/staleness checking (``max_age_secs``).
    3. Distinct signer counting (``min_contexts``).
    4. Threshold operator semantics (``ParticipationThreshold``).
    5. Diagnostic error reporting (``ParticipationAdmissionError``).
    6. Typed field extraction (``ParticipationFact.extract_value``).

    Success is indicated by returning without exception. Verification
    failures raise ``RuntimeError`` with diagnostic details from the
    Rust bridge.

    Args:
        requirements: The participation requirements to verify against.
        profiles: The participation profiles to evaluate.

    Raises:
        ScpError: If the bridge module is not available.
        RuntimeError: If verification fails (with diagnostic details
            from ``ParticipationAdmissionError``).
        ValueError: If JSON serialization or parsing fails.
    """
    bridge = _bridge()

    profile_json = json.dumps([p._to_bridge_dict() for p in profiles])
    requirements_json = json.dumps([r._to_bridge_dict() for r in requirements])

    bridge.verify_participation_requirements(profile_json, requirements_json)


__all__ = [
    "PARTICIPATION_FACT_VARIANTS",
    "PARTICIPATION_THRESHOLD_OPERATORS",
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
    "aggregate_trust_input",
    "evaluate_trust",
    "verify_participation_requirements",
]
