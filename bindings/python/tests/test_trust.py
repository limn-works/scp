"""Tests for SCP Python SDK trust evaluation.

Covers:
- evaluate_trust Layer 1 consumption of the structured ucan_evaluate result
- CapabilityValidation field independence and multi-token AND aggregation
- Read-only diagnostic semantics: ucan_evaluate records NO nonce state
- Dataclass construction for all trust types
- Participation requirement verification

See ``.docs/adrs/phase-2.md`` ADR-059 and ``.docs/specs/07-trust-validation-and-capabilities.md``
§7.2.4 (structured capability evaluation: gate vs. diagnostic), and ADR-017 /
spec section 9.3 for the four-layer trust model.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from scp_sdk._extension import native_module
from scp_sdk.errors import ContextError, ScpError, ValidationError
from scp_sdk.trust import (
    ANSWER_KEY_MISMATCH_CODE,
    CHALLENGE_SUITE_BELOW_MINIMUM_CODE,
    GRADING_CAPACITY_EXHAUSTED_CODE,
    GRADING_LEASE_LOST_CODE,
    NON_CANONICAL_IDENTIFIER_CODE,
    TOO_MANY_CAPABILITY_REQUIREMENTS_CODE,
    AttestationSummary,
    AttestorInfo,
    BehavioralRecord,
    CachedAttestation,
    CachedAttestationEnvelope,
    CapabilityRequirement,
    CapabilityValidation,
    CaseResult,
    ChallengePolicy,
    ChallengeRequest,
    ChallengeResponse,
    ChallengeVerification,
    ContainsAll,
    ContainsNone,
    CustomEval,
    EventLogEntry,
    ExactMatch,
    GradedChallenge,
    ParticipationFact,
    ParticipationProfile,
    ParticipationThreshold,
    RequireParticipation,
    RetryCap,
    SchemaMatch,
    TestCase,
    TestOutput,
    TrustEvaluation,
    VerificationLevel,
    encode_capability_requirements,
    evaluate_trust,
    participation_record,
    verify_participation_requirements,
)
from tests.conftest import skip_reason_if_extension_absent
from tests.harness_custody import create_in_memory_identity


def _require_native_extension() -> None:
    """Skip the calling test only when no native extension is installed.

    The loader decides, through ``skip_reason_if_extension_absent``: an
    installed extension that fails to load, or lacks a function the test calls,
    fails the test instead of skipping it. ``pytest.importorskip("_scp_core")``,
    which this guard replaces, skips on any ``ImportError`` before pytest 9.1,
    and an installed extension that fails to ``dlopen`` raises ``ImportError``
    just as an absent one does, so a broken build skipped these tests instead
    of failing them.
    """
    try:
        native_module()
    except Exception as exc:
        pytest.skip(skip_reason_if_extension_absent(exc))


# -----------------------------------------------------------------------
# Structured-result test fake
# -----------------------------------------------------------------------


@dataclass
class _FakeStructuredResult:
    """Stand-in for the bridge's PyCapabilityValidation (six snake_case bools).

    The structured diagnostic returns this; evaluate_trust reads the six
    attributes directly. Tests construct it to model per-stage outcomes
    instead of emitting error prose (ADR-059).
    """

    tokens_valid: bool = True
    signatures_valid: bool = True
    within_ceiling: bool = True
    nonce_valid: bool = True
    not_revoked: bool = True
    time_bounds_valid: bool = True


# -----------------------------------------------------------------------
# CapabilityValidation field independence integration tests
# -----------------------------------------------------------------------


class TestCapabilityValidationFieldIndependence:
    """Verify evaluate_trust maps the structured ucan_evaluate result.

    These mock the bridge's ``ucan_evaluate`` to return a structured
    per-stage result (NOT raising prose) and exercise the field-mapping
    and AND-aggregation logic in evaluate_trust.
    """

    def _run(self, result: _FakeStructuredResult) -> CapabilityValidation:
        """Helper: mock bridge.ucan_evaluate to return the given result."""
        mock_bridge = MagicMock()
        mock_bridge.ucan_evaluate.return_value = result

        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            evaluation = asyncio.run(
                evaluate_trust(
                    scp=MagicMock(),
                    subject_did="did:dht:z6MkBob",
                    context_id="ctx-test",
                    capability_tokens=["fake-token"],
                )
            )
        return evaluation.capability_validation

    def test_all_pass_when_evaluation_succeeds(self) -> None:
        cv = self._run(_FakeStructuredResult())
        assert cv.tokens_valid is True
        assert cv.signatures_valid is True
        assert cv.within_ceiling is True
        assert cv.nonce_valid is True
        assert cv.not_revoked is True
        assert cv.time_bounds_valid is True

    def test_revoked_token_keeps_other_fields(self) -> None:
        """A revoked token: structured result reports not_revoked=False directly."""
        cv = self._run(_FakeStructuredResult(not_revoked=False, time_bounds_valid=False))
        assert cv.tokens_valid is True
        assert cv.signatures_valid is True
        assert cv.within_ceiling is True
        assert cv.nonce_valid is True
        assert cv.not_revoked is False
        assert cv.time_bounds_valid is False

    def test_invalid_signature_reported_directly(self) -> None:
        """Bad signature: signatures_valid=False, later stages False (short-circuit)."""
        cv = self._run(
            _FakeStructuredResult(
                tokens_valid=True,
                signatures_valid=False,
                within_ceiling=False,
                nonce_valid=False,
                not_revoked=False,
                time_bounds_valid=False,
            )
        )
        assert cv.tokens_valid is True
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.time_bounds_valid is False

    def test_expired_token_only_time_bounds_false(self) -> None:
        cv = self._run(_FakeStructuredResult(time_bounds_valid=False))
        assert cv.tokens_valid is True
        assert cv.signatures_valid is True
        assert cv.within_ceiling is True
        assert cv.nonce_valid is True
        assert cv.not_revoked is True
        assert cv.time_bounds_valid is False

    def test_capability_outside_ceiling(self) -> None:
        cv = self._run(
            _FakeStructuredResult(
                within_ceiling=False,
                nonce_valid=False,
                not_revoked=False,
                time_bounds_valid=False,
            )
        )
        assert cv.tokens_valid is True
        assert cv.signatures_valid is True
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.time_bounds_valid is False

    def test_malformed_token_all_false(self) -> None:
        """An unparseable token: structured result is all-False."""
        cv = self._run(
            _FakeStructuredResult(
                tokens_valid=False,
                signatures_valid=False,
                within_ceiling=False,
                nonce_valid=False,
                not_revoked=False,
                time_bounds_valid=False,
            )
        )
        assert cv.tokens_valid is False
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.time_bounds_valid is False

    def test_no_tokens_all_default_false(self) -> None:
        """When no tokens are provided, all fields stay at default (False)."""
        mock_bridge = MagicMock()
        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            evaluation = asyncio.run(
                evaluate_trust(
                    scp=MagicMock(),
                    subject_did="did:dht:z6MkBob",
                    context_id="ctx-test",
                    capability_tokens=None,
                )
            )
        cv = evaluation.capability_validation
        assert cv.tokens_valid is False
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.time_bounds_valid is False
        # The diagnostic must not even be called when there are no tokens.
        mock_bridge.ucan_evaluate.assert_not_called()

    def test_malformed_ffi_input_propagates(self) -> None:
        """Malformed FFI input still raises and is NOT swallowed.

        Per §7.2.4 the diagnostic is non-throwing for capability OUTCOMES,
        but malformed FFI input (e.g. a control char in context_id) still
        raises, as the coded SDK :class:`ValidationError`.
        """
        mock_bridge = MagicMock()
        mock_bridge.ucan_evaluate.side_effect = RuntimeError(
            "[SCP-VALID-7001] validation error: context_id contains control characters"
        )

        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            with pytest.raises(ValidationError, match="control characters") as excinfo:
                asyncio.run(
                    evaluate_trust(
                        scp=MagicMock(),
                        subject_did="did:dht:z6MkBob",
                        context_id="ctx\x00bad",
                        capability_tokens=["fake-token"],
                    )
                )
        assert excinfo.value.code == "SCP-VALID-7001"

    def test_inactive_context_raises_sdk_context_error_with_code(self) -> None:
        """A native ``ContextError`` from ``ucan_evaluate`` reaches the caller as
        the SDK :class:`ContextError` with ``.code == "SCP-CTX-2023"``.

        The PyO3 ``ContextError`` is a separate class from
        ``scp_sdk.errors.ContextError``, so an untranslated native error would
        miss an ``except scp_sdk.ContextError`` handler.
        """

        class _NativeContextError(Exception):
            pass

        _NativeContextError.__name__ = "ContextError"  # mimic the PyO3 class name
        mock_bridge = MagicMock()
        mock_bridge.ucan_evaluate.side_effect = _NativeContextError(
            "[SCP-CTX-2023] context error: cannot evaluate a UCAN in context: context is not active"
        )

        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            with pytest.raises(ContextError) as excinfo:
                asyncio.run(
                    evaluate_trust(
                        scp=MagicMock(),
                        subject_did="did:dht:z6MkBob",
                        context_id="ctx-closing",
                        capability_tokens=["fake-token"],
                    )
                )
        assert not isinstance(excinfo.value, _NativeContextError)
        assert excinfo.value.code == "SCP-CTX-2023"


# -----------------------------------------------------------------------
# SCP UCAN wrappers translate the native lifecycle refusal
# -----------------------------------------------------------------------


class _NativeContextError(Exception):
    """Stands in for the PyO3 ``_scp_core.ContextError`` class."""


_NativeContextError.__name__ = "ContextError"

#: Each SCP wrapper of the five gated PyO3 UCAN entry points, with arguments.
_UCAN_WRAPPER_CALLS: list[tuple[str, tuple[Any, ...]]] = [
    ("ucan_validate", ("ctx-closing", "a.b.c", "messages:write", "did:dht:z6MkBob")),
    ("ucan_evaluate", ("ctx-closing", "a.b.c", "did:dht:z6MkBob")),
    ("ucan_mint", ("ctx-closing", "did:dht:z6MkBob", ["messages:write"])),
    (
        "ucan_delegate",
        ("ctx-closing", "did:dht:z6MkAlice", "did:dht:z6MkBob", "a.b.c", ["messages:write"]),
    ),
    ("ucan_revoke", ("ctx-closing", "a.b.c", "did:dht:z6MkAlice")),
]


def _scp_with_native(native: MagicMock) -> Any:
    from scp_sdk.scp import SCP

    scp = SCP.__new__(SCP)
    scp._native = native
    return scp


class TestScpUcanWrappersTranslateContextRefusal:
    """Every SCP wrapper of the five gated UCAN entry points re-raises the
    native ``SCP-CTX-2023`` refusal as the SDK :class:`ContextError`, so an
    ``except scp_sdk.ContextError`` handler catches it and reads ``.code``."""

    @pytest.mark.parametrize(("method", "args"), _UCAN_WRAPPER_CALLS)
    def test_inactive_context_raises_sdk_context_error(
        self, method: str, args: tuple[Any, ...]
    ) -> None:
        native = MagicMock()
        getattr(native, method).side_effect = _NativeContextError(
            "[SCP-CTX-2023] context error: cannot use a UCAN in context: context is not active"
        )
        scp = _scp_with_native(native)

        with pytest.raises(ContextError) as excinfo:
            asyncio.run(getattr(scp, method)(*args))
        assert not isinstance(excinfo.value, _NativeContextError)
        assert excinfo.value.code == "SCP-CTX-2023"
        assert isinstance(excinfo.value.__cause__, _NativeContextError)

    def test_revoke_returns_the_native_result_when_the_bridge_admits_it(self) -> None:
        native = MagicMock()
        native.ucan_revoke.return_value = None
        scp = _scp_with_native(native)

        assert asyncio.run(scp.ucan_revoke("ctx-active", "a.b.c", "did:dht:z6MkAlice")) is None
        native.ucan_revoke.assert_called_once_with("ctx-active", "a.b.c", "did:dht:z6MkAlice")


# -----------------------------------------------------------------------
# Multi-token AND aggregation
# -----------------------------------------------------------------------


class TestMultiTokenAndAggregation:
    """evaluate_trust AND-combines the six booleans across the token set."""

    def test_any_token_failing_a_stage_fails_the_aggregate(self) -> None:
        """Token A all-true, token B within_ceiling=False -> aggregate within_ceiling=False."""
        token_a = _FakeStructuredResult()  # all true
        token_b = _FakeStructuredResult(within_ceiling=False)  # one stage false

        mock_bridge = MagicMock()
        mock_bridge.ucan_evaluate.side_effect = [token_a, token_b]

        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            evaluation = asyncio.run(
                evaluate_trust(
                    scp=MagicMock(),
                    subject_did="did:dht:z6MkBob",
                    context_id="ctx-test",
                    capability_tokens=["token-a", "token-b"],
                )
            )
        cv = evaluation.capability_validation
        # The single false field on token B makes only that aggregate field False.
        assert cv.within_ceiling is False
        # Every other field stays True (both tokens passed those stages).
        assert cv.tokens_valid is True
        assert cv.signatures_valid is True
        assert cv.nonce_valid is True
        assert cv.not_revoked is True
        assert cv.time_bounds_valid is True
        # Both tokens were evaluated.
        assert mock_bridge.ucan_evaluate.call_count == 2

    def test_evaluate_trust_supplies_no_challenge_capability(self) -> None:
        """evaluate_trust must call ucan_evaluate WITHOUT a challenge capability.

        Trust evaluation assesses each token's GENERAL (intrinsic) validity, so
        it must NOT impose an invoked-capability grant-match. The historical
        bug passed a ``"*"`` sentinel the real bridge rejects; the fix is to
        pass no capability at all (intrinsic-validity mode, ADR-059 / §7.2.4).
        This pins the call shape so the mock cannot diverge from the real
        None-accepting contract.
        """
        mock_bridge = MagicMock()
        mock_bridge.ucan_evaluate.return_value = _FakeStructuredResult()

        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            asyncio.run(
                evaluate_trust(
                    scp=MagicMock(),
                    subject_did="did:dht:z6MkBob",
                    context_id="ctx-test",
                    capability_tokens=["only-token"],
                )
            )

        assert mock_bridge.ucan_evaluate.call_count == 1
        call = mock_bridge.ucan_evaluate.call_args
        # No challenge capability in either positional or keyword form, and
        # never the rejected "*" sentinel.
        positional = call.args
        assert "*" not in positional
        assert "*" not in call.kwargs.values()
        # The diagnostic is called for general validity with the challenge
        # capability None and the subject DID passed as the presenting agent
        # (so the audience check evaluates against the DID under assessment; the
        # bridge requires it fail-closed and rejects an absent/empty value
        # rather than falling back to a tautological token-own-aud check).
        # Signature is
        # ucan_evaluate(context_id, token, capability, presenting_agent_did).
        assert positional == ("ctx-test", "only-token", None, "did:dht:z6MkBob")
        assert "capability" not in call.kwargs

    def test_all_tokens_passing_yields_all_true(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.ucan_evaluate.side_effect = [
            _FakeStructuredResult(),
            _FakeStructuredResult(),
            _FakeStructuredResult(),
        ]
        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            evaluation = asyncio.run(
                evaluate_trust(
                    scp=MagicMock(),
                    subject_did="did:dht:z6MkBob",
                    context_id="ctx-test",
                    capability_tokens=["a", "b", "c"],
                )
            )
        cv = evaluation.capability_validation
        assert cv.all_valid


# -----------------------------------------------------------------------
# Read-only diagnostic: nonce is NOT recorded
# -----------------------------------------------------------------------


class TestDiagnosticDoesNotRecordNonce:
    """The structured diagnostic probes the nonce read-only and records nothing.

    This is the class of bug ADR-059 surfaces: the OLD prose mocks emitted
    a nonce string unconditionally and never modeled nonce *state*, so a
    repeated-evaluation nonce defect could hide. Here the fakes model state:

    - ``ucan_evaluate`` (the diagnostic) returns ``nonce_valid=True`` even
      when called twice on the same token -- proving it records nothing.
    - ``ucan_validate`` (the gate) flips to a NonceReused error on the 2nd
      call -- proving the gate DOES record, so the mock genuinely models the
      real recording semantics rather than ignoring state.

    evaluate_trust (which uses the diagnostic) must therefore be idempotent
    across repeated calls on the same token.
    """

    class _NonceReused(Exception):
        pass

    def test_repeated_evaluation_is_idempotent_diagnostic_records_nothing(self) -> None:
        # Stateful gate: records the nonce; 2nd call on same token is a replay.
        recorded: set[str] = set()

        def gate(context_id: str, token: str, capability: str | None = None, *args: Any) -> None:
            if token in recorded:
                raise self._NonceReused(f"nonce reused: {token}")
            recorded.add(token)

        # Stateful diagnostic: NEVER records -- always reports nonce_valid=True,
        # regardless of how many times it is called on the same token. Capability
        # is optional (evaluate_trust runs the intrinsic-validity diagnostic, so it
        # calls ucan_evaluate(context_id, token) with no challenge capability).
        def diagnostic(
            context_id: str, token: str, capability: str | None = None, *args: Any
        ) -> _FakeStructuredResult:
            return _FakeStructuredResult(nonce_valid=True)

        mock_bridge = MagicMock()
        mock_bridge.UcanError = self._NonceReused
        mock_bridge.ucan_validate.side_effect = gate
        mock_bridge.ucan_evaluate.side_effect = diagnostic

        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            first = asyncio.run(
                evaluate_trust(
                    scp=MagicMock(),
                    subject_did="did:dht:z6MkBob",
                    context_id="ctx-test",
                    capability_tokens=["same-token"],
                )
            )
            second = asyncio.run(
                evaluate_trust(
                    scp=MagicMock(),
                    subject_did="did:dht:z6MkBob",
                    context_id="ctx-test",
                    capability_tokens=["same-token"],
                )
            )

        # Idempotent: both evaluations see nonce_valid=True. The diagnostic
        # recorded nothing, so the second call is not a replay.
        assert first.capability_validation.nonce_valid is True
        assert second.capability_validation.nonce_valid is True
        # evaluate_trust must use the read-only diagnostic, never the gate.
        mock_bridge.ucan_validate.assert_not_called()

    def test_mock_gate_actually_models_recording(self) -> None:
        """Sanity check that the gate fake DOES record (else the test above is vacuous).

        Calling the gate twice on the same token must raise NonceReused --
        proving the mock models real nonce-recording state, so the
        diagnostic's idempotence is a meaningful contrast, not an artifact
        of a stateless mock.
        """
        recorded: set[str] = set()

        def gate(token: str) -> None:
            if token in recorded:
                raise self._NonceReused(f"nonce reused: {token}")
            recorded.add(token)

        gate("t")  # first call records
        with pytest.raises(self._NonceReused, match="nonce reused"):
            gate("t")  # replay


# -----------------------------------------------------------------------
# Dataclass construction tests
# -----------------------------------------------------------------------


class TestCapabilityValidation:
    """Tests for the CapabilityValidation dataclass."""

    def test_default_all_false(self) -> None:
        cv = CapabilityValidation()
        assert cv.tokens_valid is False
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.time_bounds_valid is False

    def test_individual_fields_settable(self) -> None:
        cv = CapabilityValidation(
            tokens_valid=True,
            signatures_valid=False,
            within_ceiling=True,
            nonce_valid=True,
            not_revoked=False,
            time_bounds_valid=True,
        )
        assert cv.tokens_valid is True
        assert cv.signatures_valid is False
        assert cv.within_ceiling is True
        assert cv.nonce_valid is True
        assert cv.not_revoked is False
        assert cv.time_bounds_valid is True


class TestBehavioralRecord:
    """Tests for the BehavioralRecord dataclass (the typed §7.3.2 facts)."""

    def test_default_construction(self) -> None:
        br = BehavioralRecord()
        # The twelve typed participation facts, all defaulted.
        assert br.subject_did == ""
        assert br.participation_duration_secs == 0
        assert br.governance_actions_against == 0
        assert br.governance_actions_by == 0
        assert br.outlet_invocation_count == 0
        assert br.outlet_invocation_count_anchored is False
        assert br.context_creation_count == 0
        assert br.role_progression_count == 0
        assert br.attestation_count == 0
        assert br.attestation_count_anchored is False
        assert br.computed_at == 0
        assert br.event_log_root == ""

    def test_obsolete_fields_removed(self) -> None:
        # The client-side-computation fields are gone from the typed shape.
        br = BehavioralRecord()
        for obsolete in (
            "contexts_participated",
            "total_duration",
            "outlet_invocations",
            "role_history",
            "endorsement_accuracy",
        ):
            assert not hasattr(br, obsolete), f"obsolete field {obsolete} must be removed"


class _FakeParticipationRecord:
    """A fake PyParticipationRecord with the twelve typed fields."""

    def __init__(self, **overrides: object) -> None:
        self.subject_did = "did:dht:zsubject"
        self.participation_duration_secs = 0
        self.governance_actions_against = 0
        self.governance_actions_by = 0
        self.outlet_invocation_count = 0
        self.outlet_invocation_count_anchored = False
        self.context_creation_count = 0
        self.role_progression_count = 0
        self.attestation_count = 0
        self.attestation_count_anchored = False
        self.computed_at = 1
        self.event_log_root = "00"
        for key, value in overrides.items():
            setattr(self, key, value)


class TestParticipationRecordWrapper:
    """The participation_record SDK wrapper projects the typed bridge record."""

    async def test_projects_all_twelve_fields(self) -> None:
        mock_scp = MagicMock()
        mock_bridge = MagicMock()
        mock_bridge.participation_record.return_value = _FakeParticipationRecord(
            subject_did="did:dht:zalice",
            participation_duration_secs=300,
            governance_actions_against=2,
            governance_actions_by=3,
            outlet_invocation_count=4,
            outlet_invocation_count_anchored=False,
            context_creation_count=1,
            role_progression_count=5,
            attestation_count=0,
            computed_at=42,
            event_log_root="deadbeef",
        )
        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            record = await participation_record(mock_scp, "ctx-1", "did:dht:zalice")

        assert isinstance(record, BehavioralRecord)
        assert record.subject_did == "did:dht:zalice"
        assert record.participation_duration_secs == 300
        assert record.governance_actions_against == 2
        assert record.governance_actions_by == 3
        assert record.outlet_invocation_count == 4
        assert record.outlet_invocation_count_anchored is False
        assert record.context_creation_count == 1
        assert record.role_progression_count == 5
        assert record.attestation_count == 0
        # attestation_count is credential-layer, never Merkle-anchored.
        assert record.attestation_count_anchored is False
        assert record.computed_at == 42
        assert record.event_log_root == "deadbeef"

    async def test_defaults_to_empty_cached_attestations(self) -> None:
        mock_scp = MagicMock()
        mock_bridge = MagicMock()
        mock_bridge.participation_record.return_value = _FakeParticipationRecord()
        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            await participation_record(mock_scp, "ctx-1", "did:dht:zsubject")

        # No cached attestations supplied → the bridge receives an empty JSON
        # array (honest, verifier-relative; the SDK fabricates none).
        call = mock_bridge.participation_record.call_args
        assert call.args == ("ctx-1", "did:dht:zsubject", "[]")

    async def test_typed_cached_attestation_serializes_to_snake_case_wire(self) -> None:
        """A typed CachedAttestation is json.dumps'd onto the wire verbatim.

        The TypedDict is a dict at runtime, so its serde-canonical snake_case
        keys cross the FFI exactly as the Python SDK's raw dicts (and the TS
        SDK's typed input) do — parity across bindings.
        """
        mock_scp = MagicMock()
        mock_bridge = MagicMock()
        mock_bridge.participation_record.return_value = _FakeParticipationRecord()
        envelope: CachedAttestationEnvelope = {
            "id": "att-1",
            "attestation_type": "IdentityLink",
            "issuer": "did:dht:zissuer",
            "subject": "did:dht:zsubject",
            "claim": {"linked_did": "did:dht:zsubject"},
            "issued_at": 1000,
            "revocation_status": "NotRevoked",
            "signature": list(range(64)),
        }
        cached: CachedAttestation = {
            "attestation": envelope,
            "verified_at": 1234,
            "ttl_secs": 3600,
        }
        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            await participation_record(mock_scp, "ctx-1", "did:dht:zsubject", [cached])

        call = mock_bridge.participation_record.call_args
        assert call.args == ("ctx-1", "did:dht:zsubject", json.dumps([cached]))
        # The signature is a list of 64 byte ints (serde_bytes deserializes a
        # sequence of u8); confirm it survives serialization intact.
        wire = json.loads(call.args[2])
        assert wire[0]["attestation"]["signature"] == list(range(64))
        assert wire[0]["attestation"]["attestation_type"] == "IdentityLink"

    def test_evaluate_trust_layer2_consumes_participation_record(self) -> None:
        mock_scp = MagicMock()
        mock_bridge = MagicMock()
        mock_bridge.participation_record.return_value = _FakeParticipationRecord(
            subject_did="did:dht:zbob",
            governance_actions_by=7,
        )
        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            evaluation = asyncio.run(
                evaluate_trust(
                    scp=mock_scp,
                    subject_did="did:dht:zbob",
                    context_id="ctx-1",
                )
            )

        # Layer 2 is the typed record received from the bridge op — NOT a
        # client-side event-log classification. evaluate_trust never queries the
        # event log itself.
        mock_bridge.event_log_query.assert_not_called()
        assert evaluation.behavioral_record is not None
        assert evaluation.behavioral_record.governance_actions_by == 7
        assert evaluation.behavioral_record.attestation_count_anchored is False
        # evaluate_trust supplies no cached attestations.
        call = mock_bridge.participation_record.call_args
        assert call.args == ("ctx-1", "did:dht:zbob", "[]")

    def test_evaluate_trust_empty_log_folds_into_zeroed_record(self) -> None:
        """An empty event log (SCP-CTX-2076) folds into a ZEROED record.

        The branch keys on the STRUCTURED code, not error prose, and the record
        is non-null (all counts 0) — identical in shape to the populated case.
        """
        mock_scp = MagicMock()
        mock_bridge = MagicMock()
        mock_bridge.participation_record.side_effect = ContextError(
            "no recorded participation facts for did:dht:zsubject",
            code="SCP-CTX-2076",
        )
        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            evaluation = asyncio.run(
                evaluate_trust(
                    scp=mock_scp,
                    subject_did="did:dht:zsubject",
                    context_id="ctx-1",
                )
            )

        record = evaluation.behavioral_record
        assert isinstance(record, BehavioralRecord)
        assert record.subject_did == "did:dht:zsubject"
        assert record.participation_duration_secs == 0
        assert record.outlet_invocation_count == 0
        assert record.outlet_invocation_count_anchored is False
        assert record.attestation_count == 0
        assert record.attestation_count_anchored is False
        assert record.event_log_root == ""

    def test_evaluate_trust_propagates_non_empty_log_context_error(self) -> None:
        """A genuine ContextError (NOT SCP-CTX-2076) propagates, never swallowed.

        The prior blanket ``except ContextError`` masked real failures such as
        NotInitialized; only the dedicated empty-log code is folded gracefully.
        """
        mock_scp = MagicMock()
        mock_bridge = MagicMock()
        mock_bridge.participation_record.side_effect = ContextError(
            "context not initialized",
            code="SCP-CTX-2000",
        )
        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            with pytest.raises(ContextError, match="not initialized"):
                asyncio.run(
                    evaluate_trust(
                        scp=mock_scp,
                        subject_did="did:dht:zsubject",
                        context_id="ctx-1",
                    )
                )

    async def test_participation_record_translates_native_error_with_code(self) -> None:
        """The public wrapper re-raises native bridge errors as coded SDK errors.

        A native exception whose string carries ``[SCP-CTX-2076]`` becomes a
        typed :class:`ContextError` exposing ``.code`` so callers branch on the
        structured code, not prose.
        """
        mock_scp = MagicMock()
        mock_bridge = MagicMock()

        class _NativeContextError(Exception):
            pass

        _NativeContextError.__name__ = "ContextError"  # mimic the PyO3 class name
        mock_bridge.participation_record.side_effect = _NativeContextError(
            "[SCP-CTX-2076] context error: no recorded participation facts"
        )
        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            with pytest.raises(ContextError) as excinfo:
                await participation_record(mock_scp, "ctx-1", "did:dht:zsubject")
        assert excinfo.value.code == "SCP-CTX-2076"


class TestAttestationSummary:
    """Tests for the AttestationSummary dataclass (canonical 4-field shape)."""

    def test_construction(self) -> None:
        att = AttestationSummary(
            type="identity", issuer="did:dht:zIssuer", valid=True, revoked=False
        )
        assert att.type == "identity"
        assert att.issuer == "did:dht:zIssuer"
        assert att.valid is True
        assert att.revoked is False


class TestTrustEvaluation:
    """Tests for the TrustEvaluation dataclass."""

    def test_minimal_construction(self) -> None:
        te = TrustEvaluation(
            subject_did="did:dht:zBob",
            context_id="ctx-123",
        )
        assert te.subject_did == "did:dht:zBob"
        assert te.context_id == "ctx-123"
        assert te.capability_validation.tokens_valid is False
        # behavioral_record is non-null (a zeroed default), identical in shape to
        # the TypeScript SDK — never `None`.
        assert isinstance(te.behavioral_record, BehavioralRecord)
        assert te.behavioral_record.subject_did == ""
        assert te.behavioral_record.participation_duration_secs == 0
        assert te.behavioral_record.attestation_count_anchored is False
        # Canonical shape across all four SDKs: Layers 1-3 only. The Layer-4
        # fields (endorsements, challenge_results, consequence_structure) are
        # NOT part of this op's result.
        assert te.attestations == []
        assert not hasattr(te, "endorsements")
        assert not hasattr(te, "challenge_results")
        assert not hasattr(te, "consequence_structure")


# -----------------------------------------------------------------------
# Participation requirement tests
# -----------------------------------------------------------------------


class TestVerifyParticipationRequirements:
    """Tests for verify_participation_requirements.

    The SDK function serializes RequireParticipation and
    ParticipationProfile lists to JSON and delegates to the Rust
    bridge. These tests verify correct construction, serialization,
    and bridge delegation.
    """

    def test_single_requirement_passes(self) -> None:
        """Bridge returns without exception when a single requirement is satisfied."""
        req = RequireParticipation(
            fact=ParticipationFact(name="ParticipationDuration"),
            threshold=ParticipationThreshold(operator="AtLeast", value=100),
        )
        profile = ParticipationProfile(
            subject_did="did:dht:zAlice",
            participation_duration_secs=200,
        )
        mock_bridge = MagicMock()
        mock_bridge.verify_participation_requirements.return_value = True
        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            result = verify_participation_requirements("did:dht:zAlice", [req], [profile])
        assert result is None
        mock_bridge.verify_participation_requirements.assert_called_once()

    def test_single_requirement_fails(self) -> None:
        """Bridge raises RuntimeError when requirement is not met."""
        req = RequireParticipation(
            fact=ParticipationFact(name="ParticipationDuration"),
            threshold=ParticipationThreshold(operator="AtLeast", value=500),
        )
        profile = ParticipationProfile(
            subject_did="did:dht:zAlice",
            participation_duration_secs=200,
        )
        mock_bridge = MagicMock()
        mock_bridge.verify_participation_requirements.side_effect = RuntimeError(
            "threshold not met: ParticipationDuration AtLeast 500, got 200"
        )
        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            with pytest.raises(RuntimeError, match="threshold not met"):
                verify_participation_requirements("did:dht:zAlice", [req], [profile])

    def test_multiple_requirements_all_pass(self) -> None:
        """Bridge returns without exception when multiple requirements are all satisfied."""
        reqs = [
            RequireParticipation(
                fact=ParticipationFact(name="ParticipationDuration"),
                threshold=ParticipationThreshold(operator="AtLeast", value=100),
            ),
            RequireParticipation(
                fact=ParticipationFact(name="ContextCreationCount"),
                threshold=ParticipationThreshold(operator="GreaterThan", value=0),
            ),
        ]
        profile = ParticipationProfile(
            subject_did="did:dht:zAlice",
            participation_duration_secs=200,
            context_creation_count=3,
        )
        mock_bridge = MagicMock()
        mock_bridge.verify_participation_requirements.return_value = True
        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            result = verify_participation_requirements("did:dht:zAlice", reqs, [profile])
        assert result is None

    def test_multiple_profiles(self) -> None:
        """Bridge receives multiple profiles for min_contexts checking."""
        req = RequireParticipation(
            fact=ParticipationFact(name="AttestationCount"),
            threshold=ParticipationThreshold(operator="AtLeast", value=1),
            min_contexts=2,
        )
        profiles = [
            ParticipationProfile(
                subject_did="did:dht:zAlice",
                attestation_count=3,
            ),
            ParticipationProfile(
                subject_did="did:dht:zAlice",
                attestation_count=2,
            ),
        ]
        mock_bridge = MagicMock()
        mock_bridge.verify_participation_requirements.return_value = True
        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            result = verify_participation_requirements("did:dht:zAlice", [req], profiles)
        assert result is None

    def test_serialization_format(self) -> None:
        """Verify JSON serialization matches Rust serde expectations."""
        req = RequireParticipation(
            fact=ParticipationFact(name="GovernanceActionsAgainst"),
            threshold=ParticipationThreshold(operator="LessThan", value=3),
            max_age_secs=7200,
            min_contexts=1,
        )
        profile = ParticipationProfile(
            subject_did="did:dht:zAlice",
            governance_actions_against=1,
        )
        mock_bridge = MagicMock()
        mock_bridge.verify_participation_requirements.return_value = True
        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            verify_participation_requirements("did:dht:zAlice", [req], [profile])

        call_args = mock_bridge.verify_participation_requirements.call_args
        import json

        assert call_args[0][0] == "did:dht:zAlice"
        # Bridge arg order is (expected_subject, requirements_json, profile_json).
        reqs_json = json.loads(call_args[0][1])
        profiles_json = json.loads(call_args[0][2])

        assert profiles_json[0]["subject_did"] == "did:dht:zAlice"
        assert profiles_json[0]["governance_actions_against"] == 1
        assert reqs_json[0]["fact"] == "GovernanceActionsAgainst"
        assert reqs_json[0]["threshold"] == {"LessThan": 3}
        assert reqs_json[0]["max_age_secs"] == 7200
        assert reqs_json[0]["min_contexts"] == 1

    def test_max_age_secs_default(self) -> None:
        """RequireParticipation defaults max_age_secs to 3600."""
        req = RequireParticipation(
            fact=ParticipationFact(name="OutletInvocationCount"),
            threshold=ParticipationThreshold(operator="Equals", value=10),
        )
        assert req.max_age_secs == 3600
        assert req.min_contexts == 1


# -----------------------------------------------------------------------
# u64 upper-bound validation tests
# -----------------------------------------------------------------------

_U64_MAX = 0xFFFF_FFFF_FFFF_FFFF
_U64_OVERFLOW = _U64_MAX + 1


class TestU64UpperBoundValidation:
    """Tests that u64 fields reject values exceeding 2^64 - 1."""

    def test_participation_threshold_value_at_max(self) -> None:
        """ParticipationThreshold.value accepts u64 max."""
        pt = ParticipationThreshold(operator="AtLeast", value=_U64_MAX)
        assert pt.value == _U64_MAX

    def test_participation_threshold_value_overflow(self) -> None:
        """ParticipationThreshold.value rejects u64 overflow."""
        with pytest.raises(ValueError, match="must be <= 18446744073709551615"):
            ParticipationThreshold(operator="AtLeast", value=_U64_OVERFLOW)

    def test_require_participation_max_age_secs_at_max(self) -> None:
        """RequireParticipation.max_age_secs accepts u64 max."""
        req = RequireParticipation(
            fact=ParticipationFact(name="ParticipationDuration"),
            threshold=ParticipationThreshold(operator="AtLeast", value=0),
            max_age_secs=_U64_MAX,
        )
        assert req.max_age_secs == _U64_MAX

    def test_require_participation_max_age_secs_overflow(self) -> None:
        """RequireParticipation.max_age_secs rejects u64 overflow."""
        with pytest.raises(ValueError, match="must be <= 18446744073709551615"):
            RequireParticipation(
                fact=ParticipationFact(name="ParticipationDuration"),
                threshold=ParticipationThreshold(operator="AtLeast", value=0),
                max_age_secs=_U64_OVERFLOW,
            )

    @pytest.mark.parametrize(
        "field_name",
        [
            "participation_duration_secs",
            "governance_actions_against",
            "governance_actions_by",
            "outlet_invocation_count",
            "context_creation_count",
            "role_progression_count",
            "attestation_count",
            "updated_at",
        ],
    )
    def test_participation_profile_u64_field_at_max(self, field_name: str) -> None:
        """ParticipationProfile u64 fields accept u64 max."""
        kwargs: dict[str, Any] = {"subject_did": "did:dht:zAlice", field_name: _U64_MAX}
        profile = ParticipationProfile(**kwargs)
        assert getattr(profile, field_name) == _U64_MAX

    @pytest.mark.parametrize(
        "field_name",
        [
            "participation_duration_secs",
            "governance_actions_against",
            "governance_actions_by",
            "outlet_invocation_count",
            "context_creation_count",
            "role_progression_count",
            "attestation_count",
            "updated_at",
        ],
    )
    def test_participation_profile_u64_field_overflow(self, field_name: str) -> None:
        """ParticipationProfile u64 fields reject u64 overflow."""
        kwargs: dict[str, Any] = {"subject_did": "did:dht:zAlice", field_name: _U64_OVERFLOW}
        with pytest.raises(ValueError, match="must be <= 18446744073709551615"):
            ParticipationProfile(**kwargs)


class TestAggregateTrustInputFalsy:
    """H14 / M16 regression: aggregate_trust_input must distinguish
    explicit empty collections from `None` for every Optional parameter.
    Empty collections must serialize as `[]` / `{}`, never collapse to
    the default branch.
    """

    @staticmethod
    def _mock_bridge() -> MagicMock:
        bridge = MagicMock()
        bridge.aggregate_trust_input.return_value = "{}"
        return bridge

    async def test_empty_consequence_rules_serializes_as_empty_array(self) -> None:
        from scp_sdk.trust import aggregate_trust_input

        bridge = self._mock_bridge()
        with patch("scp_sdk.trust._bridge", return_value=bridge):
            await aggregate_trust_input(
                scp=MagicMock(),
                context_id="ctx-1",
                subject_did="did:dht:zAlice",
                events=[],
                merkle_root=[0] * 32,
                consequence_rules=[],
            )
        # Positional args: context_id, subject_did, events_json,
        # merkle_root_json, consequence_rules_json, threshold_json,
        # attestor_sets_json, cached_attestations_json,
        # challenge_results_json
        call_args = bridge.aggregate_trust_input.call_args[0]
        assert call_args[4] == "[]"

    async def test_none_consequence_rules_still_serializes_as_empty_array(self) -> None:
        # `None` and absent both fall back to `[]` here -- the bridge
        # needs SOMETHING to deserialize. The point of `is not None` is
        # that an *explicit empty* list is not silently lost; this test
        # documents that the None branch still produces a valid value.
        from scp_sdk.trust import aggregate_trust_input

        bridge = self._mock_bridge()
        with patch("scp_sdk.trust._bridge", return_value=bridge):
            await aggregate_trust_input(
                scp=MagicMock(),
                context_id="ctx-1",
                subject_did="did:dht:zAlice",
                events=[],
                merkle_root=[0] * 32,
                consequence_rules=None,
            )
        call_args = bridge.aggregate_trust_input.call_args[0]
        assert call_args[4] == "[]"

    async def test_empty_threshold_requirements_serializes_as_empty_object(self) -> None:
        from scp_sdk.trust import aggregate_trust_input

        bridge = self._mock_bridge()
        with patch("scp_sdk.trust._bridge", return_value=bridge):
            await aggregate_trust_input(
                scp=MagicMock(),
                context_id="ctx-1",
                subject_did="did:dht:zAlice",
                events=[],
                merkle_root=[0] * 32,
                threshold_requirements={},
            )
        call_args = bridge.aggregate_trust_input.call_args[0]
        assert call_args[5] == "{}"

    async def test_empty_attestor_sets_serializes_as_empty_object(self) -> None:
        from scp_sdk.trust import aggregate_trust_input

        bridge = self._mock_bridge()
        with patch("scp_sdk.trust._bridge", return_value=bridge):
            await aggregate_trust_input(
                scp=MagicMock(),
                context_id="ctx-1",
                subject_did="did:dht:zAlice",
                events=[],
                merkle_root=[0] * 32,
                attestor_sets={},
            )
        call_args = bridge.aggregate_trust_input.call_args[0]
        assert call_args[6] == "{}"

    async def test_empty_cached_attestations_serializes_as_empty_array(self) -> None:
        from scp_sdk.trust import aggregate_trust_input

        bridge = self._mock_bridge()
        with patch("scp_sdk.trust._bridge", return_value=bridge):
            await aggregate_trust_input(
                scp=MagicMock(),
                context_id="ctx-1",
                subject_did="did:dht:zAlice",
                events=[],
                merkle_root=[0] * 32,
                cached_attestations=[],
            )
        call_args = bridge.aggregate_trust_input.call_args[0]
        assert call_args[7] == "[]"

    async def test_empty_challenge_results_serializes_as_empty_array(self) -> None:
        from scp_sdk.trust import aggregate_trust_input

        bridge = self._mock_bridge()
        with patch("scp_sdk.trust._bridge", return_value=bridge):
            await aggregate_trust_input(
                scp=MagicMock(),
                context_id="ctx-1",
                subject_did="did:dht:zAlice",
                events=[],
                merkle_root=[0] * 32,
                challenge_results=[],
            )
        call_args = bridge.aggregate_trust_input.call_args[0]
        assert call_args[8] == "[]"

    async def test_populated_inputs_round_trip(self) -> None:
        import json as _json

        from scp_sdk.trust import aggregate_trust_input

        bridge = self._mock_bridge()
        rules = [{"name": "rate-limit", "trigger": "velocity"}]
        thresholds = {
            "Endorsement": {
                "required_count": 2,
                "total_attestors": 3,
                "independence_threshold": 0.5,
            }
        }
        with patch("scp_sdk.trust._bridge", return_value=bridge):
            await aggregate_trust_input(
                scp=MagicMock(),
                context_id="ctx-1",
                subject_did="did:dht:zAlice",
                events=[],
                merkle_root=[0] * 32,
                consequence_rules=rules,
                threshold_requirements=thresholds,
            )
        call_args = bridge.aggregate_trust_input.call_args[0]
        assert _json.loads(call_args[4]) == rules
        assert _json.loads(call_args[5]) == thresholds


class TestAggregateTrustInputTyped:
    """ADR-058: aggregate_trust_input takes typed inputs and serializes to the
    exact serde wire JSON the bridge deserializes — no hand-authored JSON."""

    @staticmethod
    def _mock_bridge() -> MagicMock:
        bridge = MagicMock()
        bridge.aggregate_trust_input.return_value = "{}"
        return bridge

    @staticmethod
    def _event() -> EventLogEntry:
        return {
            "event_type": "MessageSent",
            "actor_did": "did:dht:zActor",
            "timestamp": 1_700_000_000,
            "sequence": 0,
            "payload": {"data": [1, 2, 3]},
            "prev_hash": [0] * 32,
            "signature": [5] * 64,
        }

    async def test_typed_events_serialize_verbatim(self) -> None:
        from scp_sdk.trust import aggregate_trust_input

        bridge = self._mock_bridge()
        event = self._event()
        with patch("scp_sdk.trust._bridge", return_value=bridge):
            await aggregate_trust_input(
                scp=MagicMock(),
                context_id="ctx-1",
                subject_did="did:dht:zAlice",
                events=[event],
                merkle_root=[7] * 32,
            )
        call_args = bridge.aggregate_trust_input.call_args[0]
        assert json.loads(call_args[2]) == [event]
        assert json.loads(call_args[3]) == [7] * 32

    async def test_typed_attestor_sets_serialize_verbatim(self) -> None:
        from scp_sdk.trust import aggregate_trust_input

        bridge = self._mock_bridge()
        attestor: AttestorInfo = {
            "did": "did:dht:zAttestor",
            "context_memberships": ["ctx-1"],
            "endorsements": ["did:dht:zOther"],
            "attestation": None,
        }
        with patch("scp_sdk.trust._bridge", return_value=bridge):
            await aggregate_trust_input(
                scp=MagicMock(),
                context_id="ctx-1",
                subject_did="did:dht:zAlice",
                events=[],
                merkle_root=[0] * 32,
                attestor_sets={"Endorsement": [attestor]},
            )
        call_args = bridge.aggregate_trust_input.call_args[0]
        assert json.loads(call_args[6]) == {"Endorsement": [attestor]}

    async def test_challenge_results_accept_the_dataclass(self) -> None:
        """``challenge_results`` accepts the merged ChallengeVerification
        dataclass and serializes it via its bridge projection."""
        from scp_sdk.trust import aggregate_trust_input

        bridge = self._mock_bridge()
        verification = ChallengeVerification.from_dict(_record_dict())
        with patch("scp_sdk.trust._bridge", return_value=bridge):
            await aggregate_trust_input(
                scp=MagicMock(),
                context_id="ctx-1",
                subject_did="did:dht:zAlice",
                events=[],
                merkle_root=[0] * 32,
                challenge_results=[verification],
            )
        call_args = bridge.aggregate_trust_input.call_args[0]
        assert json.loads(call_args[8]) == [verification._to_bridge_dict()]

    async def test_rejects_wrong_length_merkle_root(self) -> None:
        from scp_sdk.trust import aggregate_trust_input

        bridge = self._mock_bridge()
        with (
            patch("scp_sdk.trust._bridge", return_value=bridge),
            pytest.raises(ValueError, match="merkle_root must be exactly 32 elements, got 3"),
        ):
            await aggregate_trust_input(
                scp=MagicMock(),
                context_id="ctx-1",
                subject_did="did:dht:zAlice",
                events=[],
                merkle_root=[1, 2, 3],
            )
        bridge.aggregate_trust_input.assert_not_called()

    @pytest.mark.parametrize("param", ["threshold_requirements", "attestor_sets"])
    async def test_rejects_invalid_attestation_type_key(self, param: str) -> None:
        from scp_sdk.trust import aggregate_trust_input

        bridge = self._mock_bridge()
        with (
            patch("scp_sdk.trust._bridge", return_value=bridge),
            pytest.raises(ValueError, match="not an AttestationType"),
        ):
            await aggregate_trust_input(
                scp=MagicMock(),
                context_id="ctx-1",
                subject_did="did:dht:zAlice",
                events=[],
                merkle_root=[0] * 32,
                **{param: {"WebAuthn": {}}},
            )
        bridge.aggregate_trust_input.assert_not_called()

    def test_scp_method_serializes_through_the_shared_encoder(self) -> None:
        """SCP.aggregate_trust_input (the class surface) takes the same typed
        inputs and emits byte-identical wire JSON via the shared encoder."""
        from scp_sdk.scp import SCP

        scp = MagicMock()
        scp._native.aggregate_trust_input.return_value = "{}"
        event = self._event()
        result = asyncio.run(
            SCP.aggregate_trust_input(
                scp,
                "ctx-1",
                "did:dht:zAlice",
                events=[event],
                merkle_root=[7] * 32,
                threshold_requirements={
                    "Endorsement": {
                        "required_count": 1,
                        "total_attestors": 1,
                        "independence_threshold": 0.0,
                    }
                },
            )
        )
        assert result == "{}"
        call_args = scp._native.aggregate_trust_input.call_args[0]
        assert call_args[0] == "ctx-1"
        assert call_args[1] == "did:dht:zAlice"
        assert json.loads(call_args[2]) == [event]
        assert json.loads(call_args[3]) == [7] * 32
        assert call_args[4] == "[]"
        assert json.loads(call_args[5]) == {
            "Endorsement": {
                "required_count": 1,
                "total_attestors": 1,
                "independence_threshold": 0.0,
            }
        }
        assert call_args[6] == "{}"
        assert call_args[7] == "[]"
        assert call_args[8] == "[]"

    def test_scp_method_rejects_wrong_length_merkle_root(self) -> None:
        from scp_sdk.scp import SCP

        scp = MagicMock()
        with pytest.raises(ValueError, match="merkle_root must be exactly 32 elements"):
            asyncio.run(
                SCP.aggregate_trust_input(scp, "ctx-1", "did:dht:zAlice", [], [1, 2]),
            )
        scp._native.aggregate_trust_input.assert_not_called()


class TestTrustVerifyTyped:
    """ADR-058 Op D: trust_verify_attestation takes the typed wire DTO and
    serializes it to the exact serde JSON the bridge parses."""

    @staticmethod
    def _envelope() -> CachedAttestationEnvelope:
        return {
            "id": "att-1",
            "attestation_type": "AgentCapability",
            "issuer": "did:dht:zIssuer",
            "subject": "did:dht:zSubject",
            "claim": {"capability": "scp:capability:schema-validation/v1"},
            "issued_at": 1_700_000_000,
            "revocation_status": "Active",
            "signature": [3] * 64,
        }

    async def test_verify_attestation_serializes_the_typed_envelope(self) -> None:
        from scp_sdk.trust import trust_verify_attestation

        scp = MagicMock()
        scp._native.trust_verify_attestation.return_value = {
            "valid": False,
            "chain_depth": 0,
            "error": "unresolvable issuer",
        }
        result = await trust_verify_attestation(scp, "ctx-1", self._envelope())
        assert result["valid"] is False
        context_id, wire_json = scp._native.trust_verify_attestation.call_args[0]
        assert context_id == "ctx-1"
        assert json.loads(wire_json) == self._envelope()

    async def test_verify_attestation_without_a_resolver_fails_closed(self, scp: Any) -> None:
        """An instance with no identity has no DID resolver, so the issuer's
        `#active` key cannot be resolved: a coded SCP-VALID-7052 error, never a
        verdict. The issuer DID in the message proves the typed envelope
        parsed on the real Rust deserializer (a parse failure is 7012)."""
        from scp_sdk.trust import trust_verify_attestation

        _require_native_extension()
        with pytest.raises(ValidationError) as info:
            await trust_verify_attestation(scp, "ctx-1", self._envelope())
        assert info.value.code == "SCP-VALID-7052"
        assert "did:dht:zIssuer" in str(info.value)

    async def test_verify_attestation_resolvable_issuer_bad_signature(self, scp: Any) -> None:
        """An issuer that resolves on this instance reaches the real verifier:
        a dummy signature yields a structured `valid: False` verdict."""
        from scp_sdk.trust import trust_verify_attestation

        _require_native_extension()
        issuer = await create_in_memory_identity(scp)
        envelope = {**self._envelope(), "issuer": issuer.did}
        result = await trust_verify_attestation(scp, "ctx-1", envelope)
        assert result["valid"] is False
        assert "signature" in result["error"]

    async def test_aggregate_trust_input_raises_the_coded_sdk_error(self, scp: Any) -> None:
        """A bridge refusal from aggregate_trust_input reaches the caller as the
        coded SDK exception, not the native ``_scp_core`` one."""
        from scp_sdk.trust import aggregate_trust_input

        _require_native_extension()
        with pytest.raises(ValidationError) as info:
            await aggregate_trust_input(scp, "bad\x00ctx", "did:dht:zSubject", [], [0] * 32)
        assert info.value.code.startswith("SCP-VALID-")


_SCHEMA_URI = "scp:capability:schema-validation/v1"


def _schema_cases(n: int) -> list[TestCase]:
    """``n`` exact-match cases whose weights sum to 10000."""
    weight = 10_000 // n
    return [
        TestCase(
            test_id=f"t{i}",
            input={"i": i},
            expected=ExactMatch(value={"ok": True}),
            category="basic",
            weight=10_000 - weight * (n - 1) if i == 0 else weight,
        )
        for i in range(n)
    ]


def _record_dict(**overrides: Any) -> dict[str, Any]:
    """The 23-field bridge form of a graded record."""
    record: dict[str, Any] = {
        "verification_id": "ab" * 32,
        "verifier": "did:dht:zVerifier",
        "subject": "did:dht:zSubject",
        "capability_uri": _SCHEMA_URI,
        "definition_digest": "c8" * 32,
        "suite_digest": "cd" * 32,
        "challenge_id": "01" * 32,
        "attempt": 2,
        "response_digest": "02" * 32,
        "max_retries": 2,
        "cooldown_secs": 300,
        "pass_threshold_bps": 9_000,
        "min_category_cases": 0,
        "passed": True,
        "score": 9_500,
        "test_count": 20,
        "pass_count": 19,
        "challenge_created_at": 1_699_999_000,
        "challenge_expires_at": 1_700_003_600,
        "timestamp": 1_700_000_000,
        "expires_at": 1_700_086_400,
        "context_id": "ctx-1",
        "verifier_signature": [7] * 64,
    }
    record.update(overrides)
    return record


def _request_dict(**overrides: Any) -> dict[str, Any]:
    """The bridge form of a signed challenge request."""
    request: dict[str, Any] = {
        "challenge_id": "ab" * 32,
        "capability_uri": _SCHEMA_URI,
        "definition_digest": "c8" * 32,
        "test_cases": [
            {
                "test_id": c.test_id,
                "input": c.input,
                "category": c.category,
                "weight": c.weight,
                "answer_commitment": "3f" * 32,
            }
            for c in _schema_cases(20)
        ],
        "created_at": 1_700_000_000,
        "expires_at": 1_700_003_600,
        "max_retries": 2,
        "cooldown_secs": 300,
        "pass_threshold_bps": 9_000,
        "context_id": "ctx-1",
        "verifier": "did:dht:zVerifier",
        "subject": "did:dht:zSubject",
        "verifier_signature": [8] * 64,
    }
    request.update(overrides)
    return request


def _response_dict(**overrides: Any) -> dict[str, Any]:
    """The bridge form of a signed challenge response."""
    response: dict[str, Any] = {
        "challenge_id": "ab" * 32,
        "request_digest": "5e" * 32,
        "subject": "did:dht:zSubject",
        "attempt": 1,
        "outputs": [{"test_id": "t0", "output": {"ok": True}}],
        "subject_signature": [4] * 64,
    }
    response.update(overrides)
    return response


class TestChallengeWireTypes:
    """The challenge types encode and decode the Rust serde shapes."""

    def test_test_case_encodes_every_expected_output_externally_tagged(self) -> None:
        variants = [
            (ExactMatch(value=[1, "a"]), {"ExactMatch": {"value": [1, "a"]}}),
            (
                SchemaMatch(schema={"type": "object"}),
                {"SchemaMatch": {"schema": {"type": "object"}}},
            ),
            (ContainsAll(required=["a", "b"]), {"ContainsAll": {"required": ["a", "b"]}}),
            (ContainsNone(forbidden=["x"]), {"ContainsNone": {"forbidden": ["x"]}}),
            (CustomEval(evaluator_outlet_id="o-1"), {"CustomEval": {"evaluator_outlet_id": "o-1"}}),
        ]
        for expected, wire in variants:
            case = TestCase(test_id="t", input=None, expected=expected, category="c", weight=1)
            encoded = case._to_wire()
            assert encoded["expected"] == wire
            assert TestCase.from_dict(encoded) == case

    def test_test_case_from_dict_rejects_unknown_variant(self) -> None:
        with pytest.raises(ValueError, match="unknown ExpectedOutput variant"):
            TestCase.from_dict(
                {"test_id": "t", "input": 1, "expected": {"Nope": {}}, "category": "c", "weight": 1}
            )

    def test_record_round_trips_through_the_bridge_shape(self) -> None:
        record = ChallengeVerification.from_dict(_record_dict())
        assert record.verifier == "did:dht:zVerifier"
        assert record.definition_digest == "c8" * 32
        assert record.attempt == 2
        assert record._to_bridge_dict() == _record_dict()

    def test_record_rejects_uppercase_hex_ids_and_short_digests(self) -> None:
        with pytest.raises(ValueError, match="verification_id must be 64 lowercase hex"):
            ChallengeVerification.from_dict(_record_dict(verification_id="AB" * 32))
        with pytest.raises(ValueError, match="response_digest must be 64 lowercase hex"):
            ChallengeVerification.from_dict(_record_dict(response_digest="02" * 31))

    def test_record_rejects_score_above_basis_point_range(self) -> None:
        with pytest.raises(ValueError, match="basis points"):
            ChallengeVerification.from_dict(_record_dict(score=10_001))
        assert ChallengeVerification.from_dict(_record_dict(score=10_000)).score == 10_000

    def test_record_rejects_a_missing_or_unknown_field(self) -> None:
        record = _record_dict()
        del record["attempt"]
        with pytest.raises(ValueError, match=r"missing \['attempt'\]"):
            ChallengeVerification.from_dict(record)
        with pytest.raises(ValueError, match=r"unknown \['result'\]"):
            ChallengeVerification.from_dict(_record_dict(result=True))

    def test_request_and_response_round_trip(self) -> None:
        request = ChallengeRequest.from_dict(_request_dict())
        assert request.test_cases[0].answer_commitment == "3f" * 32
        assert request._to_wire() == _request_dict()
        response = ChallengeResponse.from_dict(_response_dict())
        assert response.outputs == [TestOutput(test_id="t0", output={"ok": True})]
        assert response._to_wire() == _response_dict()

    def test_request_refuses_an_expected_output_and_a_short_signature(self) -> None:
        leaked = _request_dict()
        leaked["test_cases"][0]["expected"] = {"ExactMatch": {"value": 1}}
        with pytest.raises(ValueError, match=r"unknown \['expected'\]"):
            ChallengeRequest.from_dict(leaked)
        with pytest.raises(ValueError, match="verifier_signature must be exactly 64"):
            ChallengeRequest.from_dict(_request_dict(verifier_signature=[1, 2]))
        with pytest.raises(ValueError, match="request_digest must be 64 lowercase hex"):
            ChallengeResponse.from_dict(_response_dict(request_digest="5E" * 32))

    def test_capability_requirements_encode_verifiers_and_retry_cap(self) -> None:
        encoded = encode_capability_requirements(
            [
                CapabilityRequirement(
                    capability=_SCHEMA_URI,
                    verification_level=VerificationLevel(name="ChallengeVerified"),
                    trusted_verifiers=["did:dht:zVerifier"],
                    retry_cap=RetryCap(max_retries=3, min_cooldown_secs=60),
                ),
                CapabilityRequirement(
                    capability="scp:capability:summarization/v1",
                    verification_level=VerificationLevel(name="SelfAttested"),
                ),
            ]
        )
        assert json.loads(encoded) == [
            {
                "capability": _SCHEMA_URI,
                "verification_level": "ChallengeVerified",
                "trusted_verifiers": ["did:dht:zVerifier"],
                "retry_cap": {"max_retries": 3, "min_cooldown_secs": 60},
            },
            {
                "capability": "scp:capability:summarization/v1",
                "verification_level": "SelfAttested",
                "trusted_verifiers": [],
                "retry_cap": None,
            },
        ]
        with pytest.raises(ValueError, match=r"RetryCap\.max_retries"):
            RetryCap(max_retries=-1, min_cooldown_secs=0)

    def test_error_codes_match_the_bridge(self) -> None:
        assert ANSWER_KEY_MISMATCH_CODE == "SCP-VALID-7145"
        assert GRADING_CAPACITY_EXHAUSTED_CODE == "SCP-VALID-7146"
        assert NON_CANONICAL_IDENTIFIER_CODE == "SCP-VALID-7147"
        assert TOO_MANY_CAPABILITY_REQUIREMENTS_CODE == "SCP-VALID-7148"
        assert GRADING_LEASE_LOST_CODE == "SCP-VALID-7149"

    def test_module_functions_are_gone(self) -> None:
        import scp_sdk
        import scp_sdk.trust
        from scp_sdk.scp import SCP

        for name in (
            "trust_create_challenge",
            "trust_verify_response",
            "check_capability_requirements",
        ):
            assert not hasattr(scp_sdk.trust, name)
            assert not hasattr(scp_sdk, name)
        assert not hasattr(SCP, "trust_verify_response")


class TestTrustChallengeMethods:
    """The challenge methods encode their typed arguments for the bridge and
    decode its answer."""

    def test_create_serializes_the_typed_cases_and_policy(self) -> None:
        from scp_sdk.scp import SCP

        scp = MagicMock()
        scp._native.trust_create_challenge.return_value = {
            "challenge_id": "ab" * 32,
            "request_json": json.dumps(_request_dict()),
        }
        cases = _schema_cases(20)
        request = asyncio.run(
            SCP.trust_create_challenge(
                scp,
                "did:dht:zV",
                "did:dht:zS",
                "example:capability/v1",
                cases,
                "ctx-1",
                60,
                evaluator_context_id="ctx-eval",
                policy=ChallengePolicy(max_retries=1, cooldown_secs=30),
            )
        )
        assert request == ChallengeRequest.from_dict(_request_dict())
        args = scp._native.trust_create_challenge.call_args[0]
        assert args[:3] == ("did:dht:zV", "did:dht:zS", "example:capability/v1")
        assert json.loads(args[3]) == [case._to_wire() for case in cases]
        assert args[4:] == (60, "ctx-1", "ctx-eval", {"max_retries": 1, "cooldown_secs": 30})

    def test_respond_and_grade_round_trip_the_wire_forms(self) -> None:
        from scp_sdk.scp import SCP

        scp = MagicMock()
        scp._native.trust_respond_to_challenge.return_value = json.dumps(_response_dict())
        scp._native.trust_grade_response.return_value = {
            "record_json": json.dumps(_record_dict()),
            "reasons_json": json.dumps([{"passed": True, "reason": None}]),
            "trust_store_error": None,
        }
        request = ChallengeRequest.from_dict(_request_dict())
        outputs = [TestOutput(test_id="t0", output={"ok": True})]
        response = asyncio.run(
            SCP.trust_respond_to_challenge(scp, "did:dht:zSubject", request, outputs, 1)
        )
        assert response == ChallengeResponse.from_dict(_response_dict())
        subject, request_json, outputs_json, attempt = (
            scp._native.trust_respond_to_challenge.call_args[0]
        )
        assert (subject, attempt) == ("did:dht:zSubject", 1)
        assert json.loads(request_json) == _request_dict()
        assert json.loads(outputs_json) == [{"test_id": "t0", "output": {"ok": True}}]

        graded = asyncio.run(SCP.trust_grade_response(scp, "did:dht:zVerifier", request, response))
        assert graded == GradedChallenge(
            record=ChallengeVerification.from_dict(_record_dict()),
            case_results=[CaseResult(passed=True, reason=None)],
            trust_store_error=None,
        )
        verifier, request_json, response_json = scp._native.trust_grade_response.call_args[0]
        assert verifier == "did:dht:zVerifier"
        assert json.loads(request_json) == _request_dict()
        assert json.loads(response_json) == _response_dict()

    def test_grade_refuses_a_malformed_case_result(self) -> None:
        from scp_sdk.scp import SCP

        scp = MagicMock()
        scp._native.trust_grade_response.return_value = {
            "record_json": json.dumps(_record_dict()),
            "reasons_json": json.dumps([{"passed": "yes", "reason": None}]),
            "trust_store_error": None,
        }
        with pytest.raises(ValueError, match=r"CaseResult\.passed must be a bool"):
            asyncio.run(
                SCP.trust_grade_response(
                    scp,
                    "did:dht:zVerifier",
                    ChallengeRequest.from_dict(_request_dict()),
                    ChallengeResponse.from_dict(_response_dict()),
                )
            )

    @pytest.mark.parametrize(
        "code",
        [
            CHALLENGE_SUITE_BELOW_MINIMUM_CODE,
            ANSWER_KEY_MISMATCH_CODE,
            GRADING_CAPACITY_EXHAUSTED_CODE,
            NON_CANONICAL_IDENTIFIER_CODE,
            TOO_MANY_CAPABILITY_REQUIREMENTS_CODE,
            GRADING_LEASE_LOST_CODE,
        ],
    )
    def test_bridge_error_surfaces_as_coded_sdk_error(self, code: str) -> None:
        from scp_sdk.scp import SCP

        scp = MagicMock()
        scp._native.trust_grade_response.side_effect = RuntimeError(f"[{code}] refused")
        with pytest.raises(ValidationError) as info:
            asyncio.run(
                SCP.trust_grade_response(
                    scp,
                    "did:dht:zVerifier",
                    ChallengeRequest.from_dict(_request_dict()),
                    ChallengeResponse.from_dict(_response_dict()),
                )
            )
        assert info.value.code == code


class TestTrustChallengeRealBridge:
    """The SDK methods against the native bridge."""

    @staticmethod
    async def _requiring_context(scp: Any, verifier_did: str) -> str:
        """A context whose governance requires ``_SCHEMA_URI`` graded by
        ``verifier_did``."""
        creator = await create_in_memory_identity(scp)
        ctx = await scp.context_create(
            creator.did,
            {
                "ceiling": ["messages:read", "messages:write"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
                "capability_requirements": encode_capability_requirements(
                    [
                        CapabilityRequirement(
                            capability=_SCHEMA_URI,
                            verification_level=VerificationLevel(name="ChallengeVerified"),
                            trusted_verifiers=[verifier_did],
                        )
                    ]
                ),
            },
        )
        context_id: str = ctx.context_id
        return context_id

    @pytest.mark.asyncio
    async def test_below_minimum_is_valid_7039(self, scp) -> None:  # type: ignore[no-untyped-def]
        _require_native_extension()

        verifier = await create_in_memory_identity(scp)
        subject = await create_in_memory_identity(scp)
        context_id = await self._requiring_context(scp, verifier.did)
        with pytest.raises(ValidationError) as info:
            await scp.trust_create_challenge(
                verifier.did, subject.did, _SCHEMA_URI, _schema_cases(19), context_id, 3_600
            )
        assert info.value.code == CHALLENGE_SUITE_BELOW_MINIMUM_CODE

    @pytest.mark.asyncio
    async def test_challenge_round_trip(self, scp) -> None:  # type: ignore[no-untyped-def]
        """Test 38: one challenge from creation to admission through the real
        bridge. The context's governance requires the capability, so the
        subject is refused before it holds a record and admitted after."""
        _require_native_extension()

        verifier = await create_in_memory_identity(scp)
        subject = await create_in_memory_identity(scp)
        context_id = await self._requiring_context(scp, verifier.did)
        cases = _schema_cases(20)

        request = await scp.trust_create_challenge(
            verifier.did, subject.did, _SCHEMA_URI, cases, context_id, 3_600
        )
        assert request.verifier == verifier.did
        assert request.subject == subject.did
        assert request.context_id == context_id
        assert [c.test_id for c in request.test_cases] == [c.test_id for c in cases]
        assert request.expires_at - request.created_at == 3_600
        # The request commits to each answer and never carries it.
        assert "ExactMatch" not in json.dumps(request._to_wire())

        with pytest.raises(ValidationError) as unmet:
            await scp.check_capability_requirements(context_id, subject.did, [], [])
        assert unmet.value.code == "SCP-VALID-7076"

        response = await scp.trust_respond_to_challenge(
            subject.did,
            request,
            [TestOutput(test_id=c.test_id, output={"ok": True}) for c in cases],
            1,
        )
        assert response.challenge_id == request.challenge_id
        assert response.subject == subject.did
        assert response.attempt == 1

        graded = await scp.trust_grade_response(verifier.did, request, response)
        assert graded.trust_store_error is None
        assert len(graded.case_results) == 20
        assert all(c.passed for c in graded.case_results)
        record = graded.record
        assert record.passed
        assert record.attempt == 1
        assert (record.pass_count, record.test_count) == (20, 20)
        assert record.challenge_id == request.challenge_id
        assert (record.verifier, record.subject) == (verifier.did, subject.did)
        assert record.context_id == context_id

        await scp.check_capability_requirements(context_id, subject.did, [], [record])
        # Every field is signed: a record whose attempt was altered is dropped.
        with pytest.raises(ValidationError) as altered:
            await scp.check_capability_requirements(
                context_id, subject.did, [], [dataclasses.replace(record, attempt=2)]
            )
        assert altered.value.code == "SCP-VALID-7076"

    @pytest.mark.asyncio
    async def test_forged_response_is_refused_and_grades_nothing(self, scp) -> None:  # type: ignore[no-untyped-def]
        _require_native_extension()

        verifier = await create_in_memory_identity(scp)
        subject = await create_in_memory_identity(scp)
        context_id = await self._requiring_context(scp, verifier.did)
        cases = _schema_cases(20)
        request = await scp.trust_create_challenge(
            verifier.did, subject.did, _SCHEMA_URI, cases, context_id, 3_600
        )
        response = await scp.trust_respond_to_challenge(
            subject.did,
            request,
            [TestOutput(test_id=c.test_id, output={"ok": True}) for c in cases],
            1,
        )
        forged = dataclasses.replace(response, subject_signature=[0] * 64)
        with pytest.raises(ScpError):
            await scp.trust_grade_response(verifier.did, request, forged)
        # The forgery took no attempt: the real response still grades as attempt 1.
        graded = await scp.trust_grade_response(verifier.did, request, response)
        assert graded.record.attempt == 1
        assert graded.record.passed
