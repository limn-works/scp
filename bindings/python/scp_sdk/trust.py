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

import json
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
#
# NOTE: More specific "malformed token:" sub-patterns (e.g. DID errors,
# capability URI errors) are matched BEFORE this list in _classify_ucan_error
# so they route to the correct pipeline stage.
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
# Also includes DID resolution failures (step 2) that the Rust bridge
# wraps as MalformedToken.
#
# Parent-token expiry/revocation in the delegation chain is also wrapped
# as DelegationChainBroken by the Rust bridge (issue #1026), so those
# errors match "delegation chain broken:" and classify conservatively
# as "signatures" → _PASSED_BEFORE = {tokens_valid} only.  This avoids
# optimistically reporting True for checks that never ran on the leaf.
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
    # DID resolution failures (step 2) — all ResolutionError variants become
    # MalformedToken("...") via From<ResolutionError> for UcanError.
    # See crates/scp-ffi/common/src/resolvers.rs.
    "malformed token: DID not found",
    "malformed token: invalid DID document",
    "malformed token: network unavailable",
    "malformed token: DID revoked/downgraded",
    # Runtime MalformedToken(format!(...)) constructions from validate.rs
    # that represent signature/DID resolution failures (step 2).
    "malformed token: verification method",
    "malformed token: unrecognized signing key ID",
    # Runtime MalformedToken(format!(...)) constructions from resolvers.rs
    # BridgeDidResolver — DID decode/resolution failures (step 2).
    "malformed token: z-base-32 decode failed",
    "malformed token: DID public key must be 32 bytes",
    "malformed token: hex decode failed",
    "malformed token: unsupported DID method",
)

# Error message prefixes that indicate a capability ceiling/scope failure.
# Maps to CapabilityValidation.within_ceiling.
# Pipeline steps: 6 (capability match), 8 (ceiling compliance).
# Also includes capability URI parse failures (step 6) that the Rust bridge
# wraps as MalformedToken.
_CAPABILITY_CEILING_PREFIXES: tuple[str, ...] = (
    "capability outside ceiling:",
    "capability not granted:",
    "malformed token: unparseable capability",
)

# Error message prefixes for nonce failures (step 9).
# By step 9, parse, signature, and ceiling checks have already passed.
_NONCE_PREFIXES: tuple[str, ...] = (
    "nonce reused:",
    "nonce too old:",
    "nonce from the future:",
    "invalid nonce format:",
    "nonce tracker full:",
)

# Error message prefixes that indicate a revocation failure.
# Maps to CapabilityValidation.not_revoked.
# Pipeline step: 10 (revocation check).
_REVOCATION_PREFIXES: tuple[str, ...] = ("token revoked:",)

# Error message prefixes for expiry/time-bounds failures (step 11).
# By step 11, all other checks (parse, sig, ceiling, nonce, revocation) passed.
_EXPIRY_PREFIXES: tuple[str, ...] = (
    "token expired",
    "token not yet valid",
    "invalid time range:",
    "expiry too far in the future:",
    "system clock error:",
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

    # Check more-specific "malformed token:" sub-patterns BEFORE the
    # generic _TOKEN_PARSE_PREFIXES catch-all, so that e.g.
    # "malformed token: DID not found" → "signatures" (step 2) and
    # "malformed token: unparseable capability" → "ceiling" (step 6)
    # instead of falling through to "token_parse" (step 1).
    for prefix in _SIGNATURE_CHAIN_PREFIXES:
        if core.startswith(prefix):
            return "signatures"

    for prefix in _CAPABILITY_CEILING_PREFIXES:
        if core.startswith(prefix):
            return "ceiling"

    for prefix in _TOKEN_PARSE_PREFIXES:
        if core.startswith(prefix):
            return "token_parse"

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
    "nonce": {"tokens_valid", "signatures_valid", "within_ceiling"},
    # Step 10: revocation fails — parse + sig + ceiling + nonce passed.
    "revoked": {"tokens_valid", "signatures_valid", "within_ceiling", "nonce_valid"},
    # Step 11: expiry fails — parse + sig + ceiling + nonce + revocation passed.
    "expiry": {
        "tokens_valid",
        "signatures_valid",
        "within_ceiling",
        "nonce_valid",
        "not_revoked",
    },
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

    #: Nonce validation passed (step 9: no reuse, not stale, valid format).
    nonce_valid: bool = False

    #: No tokens have been revoked.
    not_revoked: bool = False

    #: Token time bounds are valid (not expired, not pre-dated, valid range).
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


async def evaluate_trust(
    subject_did: str,
    context_id: str,
    capability_tokens: list[str] | None = None,
) -> TrustEvaluation:
    """Evaluate the trustworthiness of a participant in a context.

    Performs the four-layer trust evaluation model:

    1. **Protocol enforcement** -- validates UCAN tokens, signatures,
       capability ceiling compliance, nonce, revocation, and expiry.
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
    # Each of the six CapabilityValidation fields is set independently
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
        cap_validation.nonce_valid = True
        cap_validation.not_revoked = True
        cap_validation.time_bounds_valid = True

        # Multi-token evaluation uses fail-fast semantics: we stop at the
        # first token that fails validation and report that failure.
        # Remaining tokens are not evaluated.  This is intentional —
        # the Rust bridge itself validates one token at a time, and a
        # single invalid token is sufficient to fail the capability check.
        for token in capability_tokens:
            try:
                bridge.ucan_validate(context_id, token, "*")
            except bridge.UcanError as exc:
                error_msg = str(exc)
                failed_category = _classify_ucan_error(error_msg)
                passed = _PASSED_BEFORE.get(failed_category, set())

                # The failing category is definitely False.
                # Categories before it in the pipeline passed.
                # Categories after it are unknown (never ran) — set False.
                cap_validation.tokens_valid = "tokens_valid" in passed
                cap_validation.signatures_valid = "signatures_valid" in passed
                cap_validation.within_ceiling = "within_ceiling" in passed
                cap_validation.nonce_valid = "nonce_valid" in passed
                cap_validation.not_revoked = "not_revoked" in passed
                cap_validation.time_bounds_valid = "time_bounds_valid" in passed
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


def aggregate_trust_input(
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

    Combines participation records, attestation verification, challenge
    results, consequence structure, and threshold counts into a single
    aggregated result for agent-level evaluation.

    Delegates to the Rust ``scp-core`` implementation via the PyO3
    bridge, which uses concrete implementations for the generic trait
    bounds: ``InMemoryTrustStore`` for ``TrustProtocolRepository``,
    ``IdentityDidPublicKeyResolver`` for ``DidPublicKeyResolver``, and
    ``SystemClock`` for ``Clock``.

    Args:
        context_id: The context to aggregate trust inputs for.
        subject_did: The DID of the subject to evaluate.
        events: List of event log entry dicts.
        merkle_root: 32-byte Merkle root as a list of integers.
        consequence_rules: Optional list of consequence rule dicts.
        threshold_requirements: Optional dict mapping attestation type
            names to threshold requirement dicts.
        attestor_sets: Optional dict mapping attestation type names to
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

    Raises:
        ScpError: If the bridge module is not available.
        ValueError: If any input is malformed or aggregation fails.

    Example::

        result = aggregate_trust_input(
            context_id="ctx_abc123",
            subject_did="did:dht:z6MkBob...",
            events=[{
                "event_type": "MessageSent",
                "actor_did": "did:dht:z6MkBob...",
                "timestamp": 1700000000,
                "sequence": 1,
                "payload": {"data": ""},
            }],
            merkle_root=[0] * 32,
        )
        print(result["participation_record"]["participation_count"])
    """
    bridge = _bridge()

    events_json = json.dumps(events)
    merkle_root_json = json.dumps(merkle_root)
    consequence_rules_json = json.dumps(consequence_rules or [])
    threshold_requirements_json = json.dumps(threshold_requirements or {})
    attestor_sets_json = json.dumps(attestor_sets or {})
    cached_attestations_json = json.dumps(cached_attestations or [])
    challenge_results_json = json.dumps(challenge_results or [])

    result_json = bridge.aggregate_trust_input(
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

    return json.loads(result_json)


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
