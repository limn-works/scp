"""Tests for SCP Python SDK trust evaluation.

Covers:
- evaluate_trust Layer 1 consumption of the structured ucan_evaluate result
- CapabilityValidation field independence and multi-token AND aggregation
- Read-only diagnostic semantics: ucan_evaluate records NO nonce state
- Dataclass construction for all trust types
- Participation requirement verification

See ``.docs/adrs/phase-2.md`` ADR-057 and ``.docs/specs/07-trust-validation-and-capabilities.md``
§7.2.4 (structured capability evaluation: gate vs. diagnostic), and ADR-017 /
spec section 9.3 for the four-layer trust model.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from scp_sdk.errors import ContextError
from scp_sdk.trust import (
    AttestationSummary,
    AttestorInfo,
    BehavioralRecord,
    CachedAttestation,
    CachedAttestationEnvelope,
    CapabilityValidation,
    ChallengeRequest,
    ChallengeResponse,
    EventLogEntry,
    ParticipationFact,
    ParticipationProfile,
    ParticipationThreshold,
    RequireParticipation,
    TrustEvaluation,
    evaluate_trust,
    participation_record,
    verify_participation_requirements,
)

# -----------------------------------------------------------------------
# Structured-result test fake
# -----------------------------------------------------------------------


@dataclass
class _FakeStructuredResult:
    """Stand-in for the bridge's PyCapabilityValidation (six snake_case bools).

    The structured diagnostic returns this; evaluate_trust reads the six
    attributes directly. Tests construct it to model per-stage outcomes
    instead of emitting error prose (ADR-057).
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
        raises a ValidationError-shaped exception that must propagate.
        """
        mock_bridge = MagicMock()
        mock_bridge.ucan_evaluate.side_effect = RuntimeError(
            "[SCP-VALID-7001] validation error: context_id contains control characters"
        )

        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            with pytest.raises(RuntimeError, match="control characters"):
                asyncio.run(
                    evaluate_trust(
                        scp=MagicMock(),
                        subject_did="did:dht:z6MkBob",
                        context_id="ctx\x00bad",
                        capability_tokens=["fake-token"],
                    )
                )


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
        pass no capability at all (intrinsic-validity mode, ADR-057 / §7.2.4).
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

    This is the class of bug ADR-057 surfaces: the OLD prose mocks emitted
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
        assert br.tool_invocation_count == 0
        assert br.tool_invocation_count_anchored is False
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
            "tool_invocations",
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
        self.tool_invocation_count = 0
        self.tool_invocation_count_anchored = False
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

    def test_projects_all_twelve_fields(self) -> None:
        mock_scp = MagicMock()
        mock_bridge = MagicMock()
        mock_bridge.participation_record.return_value = _FakeParticipationRecord(
            subject_did="did:dht:zalice",
            participation_duration_secs=300,
            governance_actions_against=2,
            governance_actions_by=3,
            tool_invocation_count=4,
            tool_invocation_count_anchored=False,
            context_creation_count=1,
            role_progression_count=5,
            attestation_count=0,
            computed_at=42,
            event_log_root="deadbeef",
        )
        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            record = participation_record(mock_scp, "ctx-1", "did:dht:zalice")

        assert isinstance(record, BehavioralRecord)
        assert record.subject_did == "did:dht:zalice"
        assert record.participation_duration_secs == 300
        assert record.governance_actions_against == 2
        assert record.governance_actions_by == 3
        assert record.tool_invocation_count == 4
        assert record.tool_invocation_count_anchored is False
        assert record.context_creation_count == 1
        assert record.role_progression_count == 5
        assert record.attestation_count == 0
        # attestation_count is credential-layer, never Merkle-anchored.
        assert record.attestation_count_anchored is False
        assert record.computed_at == 42
        assert record.event_log_root == "deadbeef"

    def test_defaults_to_empty_cached_attestations(self) -> None:
        mock_scp = MagicMock()
        mock_bridge = MagicMock()
        mock_bridge.participation_record.return_value = _FakeParticipationRecord()
        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            participation_record(mock_scp, "ctx-1", "did:dht:zsubject")

        # No cached attestations supplied → the bridge receives an empty JSON
        # array (honest, verifier-relative; the SDK fabricates none).
        call = mock_bridge.participation_record.call_args
        assert call.args == ("ctx-1", "did:dht:zsubject", "[]")

    def test_typed_cached_attestation_serializes_to_snake_case_wire(self) -> None:
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
            participation_record(mock_scp, "ctx-1", "did:dht:zsubject", [cached])

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
        assert record.tool_invocation_count == 0
        assert record.tool_invocation_count_anchored is False
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

    def test_participation_record_translates_native_error_with_code(self) -> None:
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
                participation_record(mock_scp, "ctx-1", "did:dht:zsubject")
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
            fact=ParticipationFact(name="ToolInvocationCount"),
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
            "tool_invocation_count",
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
            "tool_invocation_count",
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

    def test_empty_consequence_rules_serializes_as_empty_array(self) -> None:
        from scp_sdk.trust import aggregate_trust_input

        bridge = self._mock_bridge()
        with patch("scp_sdk.trust._bridge", return_value=bridge):
            aggregate_trust_input(
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

    def test_none_consequence_rules_still_serializes_as_empty_array(self) -> None:
        # `None` and absent both fall back to `[]` here -- the bridge
        # needs SOMETHING to deserialize. The point of `is not None` is
        # that an *explicit empty* list is not silently lost; this test
        # documents that the None branch still produces a valid value.
        from scp_sdk.trust import aggregate_trust_input

        bridge = self._mock_bridge()
        with patch("scp_sdk.trust._bridge", return_value=bridge):
            aggregate_trust_input(
                scp=MagicMock(),
                context_id="ctx-1",
                subject_did="did:dht:zAlice",
                events=[],
                merkle_root=[0] * 32,
                consequence_rules=None,
            )
        call_args = bridge.aggregate_trust_input.call_args[0]
        assert call_args[4] == "[]"

    def test_empty_threshold_requirements_serializes_as_empty_object(self) -> None:
        from scp_sdk.trust import aggregate_trust_input

        bridge = self._mock_bridge()
        with patch("scp_sdk.trust._bridge", return_value=bridge):
            aggregate_trust_input(
                scp=MagicMock(),
                context_id="ctx-1",
                subject_did="did:dht:zAlice",
                events=[],
                merkle_root=[0] * 32,
                threshold_requirements={},
            )
        call_args = bridge.aggregate_trust_input.call_args[0]
        assert call_args[5] == "{}"

    def test_empty_attestor_sets_serializes_as_empty_object(self) -> None:
        from scp_sdk.trust import aggregate_trust_input

        bridge = self._mock_bridge()
        with patch("scp_sdk.trust._bridge", return_value=bridge):
            aggregate_trust_input(
                scp=MagicMock(),
                context_id="ctx-1",
                subject_did="did:dht:zAlice",
                events=[],
                merkle_root=[0] * 32,
                attestor_sets={},
            )
        call_args = bridge.aggregate_trust_input.call_args[0]
        assert call_args[6] == "{}"

    def test_empty_cached_attestations_serializes_as_empty_array(self) -> None:
        from scp_sdk.trust import aggregate_trust_input

        bridge = self._mock_bridge()
        with patch("scp_sdk.trust._bridge", return_value=bridge):
            aggregate_trust_input(
                scp=MagicMock(),
                context_id="ctx-1",
                subject_did="did:dht:zAlice",
                events=[],
                merkle_root=[0] * 32,
                cached_attestations=[],
            )
        call_args = bridge.aggregate_trust_input.call_args[0]
        assert call_args[7] == "[]"

    def test_empty_challenge_results_serializes_as_empty_array(self) -> None:
        from scp_sdk.trust import aggregate_trust_input

        bridge = self._mock_bridge()
        with patch("scp_sdk.trust._bridge", return_value=bridge):
            aggregate_trust_input(
                scp=MagicMock(),
                context_id="ctx-1",
                subject_did="did:dht:zAlice",
                events=[],
                merkle_root=[0] * 32,
                challenge_results=[],
            )
        call_args = bridge.aggregate_trust_input.call_args[0]
        assert call_args[8] == "[]"

    def test_populated_inputs_round_trip(self) -> None:
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
            aggregate_trust_input(
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

    def test_typed_events_serialize_verbatim(self) -> None:
        from scp_sdk.trust import aggregate_trust_input

        bridge = self._mock_bridge()
        event = self._event()
        with patch("scp_sdk.trust._bridge", return_value=bridge):
            aggregate_trust_input(
                scp=MagicMock(),
                context_id="ctx-1",
                subject_did="did:dht:zAlice",
                events=[event],
                merkle_root=[7] * 32,
            )
        call_args = bridge.aggregate_trust_input.call_args[0]
        assert json.loads(call_args[2]) == [event]
        assert json.loads(call_args[3]) == [7] * 32

    def test_typed_attestor_sets_serialize_verbatim(self) -> None:
        from scp_sdk.trust import aggregate_trust_input

        bridge = self._mock_bridge()
        attestor: AttestorInfo = {
            "did": "did:dht:zAttestor",
            "context_memberships": ["ctx-1"],
            "endorsements": ["did:dht:zOther"],
            "attestation": None,
        }
        with patch("scp_sdk.trust._bridge", return_value=bridge):
            aggregate_trust_input(
                scp=MagicMock(),
                context_id="ctx-1",
                subject_did="did:dht:zAlice",
                events=[],
                merkle_root=[0] * 32,
                attestor_sets={"Endorsement": [attestor]},
            )
        call_args = bridge.aggregate_trust_input.call_args[0]
        assert json.loads(call_args[6]) == {"Endorsement": [attestor]}

    def test_challenge_results_accept_the_dataclass(self) -> None:
        """``challenge_results`` accepts the merged ChallengeVerification
        dataclass and serializes it via its bridge projection."""
        from scp_sdk.trust import (
            ChallengeVerification,
            ChallengeVerificationMethod,
            aggregate_trust_input,
        )

        bridge = self._mock_bridge()
        verification = ChallengeVerification(
            verification_id="v-1",
            verifier_did="did:dht:zVerifier",
            subject_did="did:dht:zAlice",
            capability_uri="scp:capability:schema-validation/v1",
            challenge_type="scp:capability:schema-validation/v1",
            verification_method=ChallengeVerificationMethod(name="SelfAttested"),
            passed=True,
            test_count=1,
            pass_count=1,
            result=True,
            completed_at=1_700_000_000,
            verified_at=1_700_000_000,
            expires_at=4_000_000_000,
            verifier_signature=[9] * 64,
        )
        with patch("scp_sdk.trust._bridge", return_value=bridge):
            aggregate_trust_input(
                scp=MagicMock(),
                context_id="ctx-1",
                subject_did="did:dht:zAlice",
                events=[],
                merkle_root=[0] * 32,
                challenge_results=[verification],
            )
        call_args = bridge.aggregate_trust_input.call_args[0]
        assert json.loads(call_args[8]) == [verification._to_bridge_dict()]

    def test_rejects_wrong_length_merkle_root(self) -> None:
        from scp_sdk.trust import aggregate_trust_input

        bridge = self._mock_bridge()
        with (
            patch("scp_sdk.trust._bridge", return_value=bridge),
            pytest.raises(ValueError, match="merkle_root must be exactly 32 elements, got 3"),
        ):
            aggregate_trust_input(
                scp=MagicMock(),
                context_id="ctx-1",
                subject_did="did:dht:zAlice",
                events=[],
                merkle_root=[1, 2, 3],
            )
        bridge.aggregate_trust_input.assert_not_called()

    @pytest.mark.parametrize("param", ["threshold_requirements", "attestor_sets"])
    def test_rejects_invalid_attestation_type_key(self, param: str) -> None:
        from scp_sdk.trust import aggregate_trust_input

        bridge = self._mock_bridge()
        with (
            patch("scp_sdk.trust._bridge", return_value=bridge),
            pytest.raises(ValueError, match="not an AttestationType"),
        ):
            aggregate_trust_input(
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
    """ADR-058 Op D: trust_verify_attestation / trust_verify_response take
    typed wire DTOs and serialize to the exact serde JSON the bridge parses."""

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

    @staticmethod
    def _challenge() -> ChallengeRequest:
        return {
            "challenge_id": "chal-1",
            "challenge_type": "scp:capability:schema-validation/v1",
            "challenger_did": "did:dht:zChallenger",
            "subject_did": "did:dht:zSubject",
            "capability_uri": "scp:capability:schema-validation/v1",
            "parameters": {"schema": "object"},
            "timeout": {"secs": 300, "nanos": 0},
            "signature": [8] * 64,
        }

    @staticmethod
    def _response() -> ChallengeResponse:
        return {
            "challenge_id": "chal-1",
            "responder_did": "did:dht:zSubject",
            "result": {"passed": True},
            "completed_at": 1_700_000_100,
            "signature": [4] * 64,
        }

    def test_verify_attestation_serializes_the_typed_envelope(self) -> None:
        from scp_sdk.trust import trust_verify_attestation

        bridge = MagicMock()
        bridge.trust_verify_attestation.return_value = {
            "valid": False,
            "chain_depth": 0,
            "error": "unresolvable issuer",
        }
        with patch("scp_sdk.trust._bridge", return_value=bridge):
            result = trust_verify_attestation(self._envelope())
        assert result["valid"] is False
        (wire_json,) = bridge.trust_verify_attestation.call_args[0]
        assert json.loads(wire_json) == self._envelope()

    def test_verify_response_serializes_both_typed_records(self) -> None:
        from scp_sdk.trust import trust_verify_response

        bridge = MagicMock()
        bridge.trust_verify_response.return_value = False
        with patch("scp_sdk.trust._bridge", return_value=bridge):
            result = trust_verify_response(self._challenge(), self._response())
        assert result is False
        challenge_json, response_json = bridge.trust_verify_response.call_args[0]
        assert json.loads(challenge_json) == self._challenge()
        assert json.loads(response_json) == self._response()

    def test_verify_attestation_real_bridge_call_through(self) -> None:
        """The typed envelope's serialized JSON parses on the REAL Rust
        `Attestation` deserializer: a dummy signature yields a structured
        `valid: False` (verification ran), never a parse error."""
        pytest.importorskip("_scp_core")
        from scp_sdk.trust import trust_verify_attestation

        result = trust_verify_attestation(self._envelope())
        assert result["valid"] is False
        assert result["error"]

    def test_verify_response_real_bridge_call_through(self) -> None:
        """The typed challenge pair's serialized JSON parses on the REAL Rust
        `ChallengeRequest` / `ChallengeResponse` deserializers: dummy
        signatures yield a structured `False`, never a parse error."""
        pytest.importorskip("_scp_core")
        from scp_sdk.trust import trust_verify_response

        assert trust_verify_response(self._challenge(), self._response()) is False


class TestTrustCreateChallenge:
    """trust_create_challenge wraps the bridge free function unchanged and
    returns its `challenge_id` / `challenge_json` dict."""

    def test_passes_target_did_through_to_the_bridge(self) -> None:
        from scp_sdk.trust import trust_create_challenge

        bridge = MagicMock()
        bridge.trust_create_challenge.return_value = {
            "challenge_id": "chal-1",
            "challenge_json": "{}",
        }
        with patch("scp_sdk.trust._bridge", return_value=bridge):
            result = trust_create_challenge("did:dht:zSubject")
        assert result == {"challenge_id": "chal-1", "challenge_json": "{}"}
        bridge.trust_create_challenge.assert_called_once_with("did:dht:zSubject")

    def test_real_bridge_call_through(self) -> None:
        """The REAL bridge issues a signed schema-validation challenge: the
        returned `challenge_json` parses and targets the subject DID."""
        pytest.importorskip("_scp_core")
        from scp_sdk.trust import trust_create_challenge

        result = trust_create_challenge("did:dht:zSubject")
        assert result["challenge_id"]
        challenge = json.loads(result["challenge_json"])
        assert challenge["challenge_id"] == result["challenge_id"]
        assert challenge["subject_did"] == "did:dht:zSubject"
        assert len(challenge["signature"]) == 64

    def test_exported_from_the_package_root(self) -> None:
        import scp_sdk
        from scp_sdk.trust import trust_create_challenge

        assert scp_sdk.trust_create_challenge is trust_create_challenge
