"""Tests for SCP Python SDK trust evaluation.

Covers:
- UCAN error classification into the 4 independent Layer 1 checks
- CapabilityValidation field independence
- evaluate_trust Layer 1 integration (mocked bridge)
- Dataclass construction for all trust types
- Participation requirement verification

See ``.docs/adrs/phase-3.md`` ADR-017 and spec section 9.3 for the
four-layer trust model.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

from scp_sdk.trust import (
    _PASSED_BEFORE,
    Attestation,
    BehavioralRecord,
    CapabilityValidation,
    ChallengeResult,
    Endorsement,
    ParticipationFact,
    ParticipationProfile,
    ParticipationThreshold,
    RequireParticipation,
    TrustEvaluation,
    _classify_ucan_error,
    _extract_core_error,
    evaluate_trust,
    verify_participation_requirements,
)

# -----------------------------------------------------------------------
# Error extraction helper tests
# -----------------------------------------------------------------------


class TestExtractCoreError:
    """Tests for _extract_core_error which strips bridge formatting."""

    def test_full_bridge_format(self) -> None:
        msg = (
            "[SCP-PERM-3001] permission error: token expired"
            " \u2014 check token format, signatures, time bounds, and capability chain"
        )
        assert _extract_core_error(msg) == "token expired"

    def test_no_prefix(self) -> None:
        msg = "token expired \u2014 advice text"
        assert _extract_core_error(msg) == "token expired"

    def test_no_suffix(self) -> None:
        msg = "[SCP-PERM-3001] permission error: token expired"
        assert _extract_core_error(msg) == "token expired"

    def test_bare_message(self) -> None:
        msg = "token expired"
        assert _extract_core_error(msg) == "token expired"


# -----------------------------------------------------------------------
# Error classification tests
# -----------------------------------------------------------------------


class TestClassifyUcanError:
    """Tests that _classify_ucan_error maps errors to correct pipeline stages."""

    # -- Token parse errors (step 1) --

    def test_malformed_token(self) -> None:
        assert _classify_ucan_error("malformed token: bad base64") == "token_parse"

    def test_deserialization_failed(self) -> None:
        assert _classify_ucan_error("deserialization failed: invalid JSON") == "token_parse"

    def test_unsupported_algorithm(self) -> None:
        msg = "unsupported algorithm: expected EdDSA, got RS256"
        assert _classify_ucan_error(msg) == "token_parse"

    def test_unsupported_version(self) -> None:
        msg = "unsupported UCAN version: expected 0.10.0, got 0.9.0"
        assert _classify_ucan_error(msg) == "token_parse"

    # -- Signature/chain errors (steps 2-7) --

    def test_signature_invalid(self) -> None:
        assert _classify_ucan_error("signature verification failed") == "signatures"

    def test_invalid_issuer(self) -> None:
        msg = "invalid issuer: expected did:dht:zCreator, got did:dht:zImposter"
        assert _classify_ucan_error(msg) == "signatures"

    def test_audience_mismatch(self) -> None:
        msg = "audience mismatch: expected did:dht:zMember, got did:dht:zOther"
        assert _classify_ucan_error(msg) == "signatures"

    def test_delegation_chain_broken(self) -> None:
        assert _classify_ucan_error("delegation chain broken: aud/iss mismatch") == "signatures"

    def test_circular_delegation(self) -> None:
        assert _classify_ucan_error("circular delegation detected: A->B->A") == "signatures"

    def test_attenuation_violation(self) -> None:
        assert _classify_ucan_error("attenuation violation: widened scope") == "signatures"

    def test_key_scope_mismatch(self) -> None:
        msg = "key scope mismatch: token scoped to #agent but signed by #active"
        assert _classify_ucan_error(msg) == "signatures"

    def test_self_delegation(self) -> None:
        msg = "self-delegation (iss == aud) requires scp_key_scope in facts"
        assert _classify_ucan_error(msg) == "signatures"

    def test_category_a_violation(self) -> None:
        msg = "Category A violation: did_document:update signed by agent key (kid=#agent)"
        assert _classify_ucan_error(msg) == "signatures"

    def test_did_not_found(self) -> None:
        """MalformedToken from DID resolver (step 2) → signatures, not token_parse."""
        msg = "malformed token: DID not found: did:dht:z6MkMissing"
        assert _classify_ucan_error(msg) == "signatures"

    def test_invalid_did_document(self) -> None:
        """MalformedToken from invalid DID document (step 2) → signatures."""
        msg = "malformed token: invalid DID document: BEP44 signature invalid"
        assert _classify_ucan_error(msg) == "signatures"

    def test_network_unavailable(self) -> None:
        """MalformedToken from network unavailable (step 2) → signatures."""
        msg = "malformed token: network unavailable: all resolvers timed out"
        assert _classify_ucan_error(msg) == "signatures"

    def test_did_revoked_downgraded(self) -> None:
        """MalformedToken from DID revoked/downgraded (step 2) → signatures."""
        msg = "malformed token: DID revoked/downgraded: stale sequence for did:dht:zTest"
        assert _classify_ucan_error(msg) == "signatures"

    # -- Capability/ceiling errors (steps 6, 8) --

    def test_capability_outside_ceiling(self) -> None:
        assert _classify_ucan_error("capability outside ceiling: messages:admin") == "ceiling"

    def test_capability_not_granted(self) -> None:
        assert _classify_ucan_error("capability not granted: messages:write") == "ceiling"

    def test_unparseable_capability_uri(self) -> None:
        """MalformedToken from capability URI parse (step 6) → ceiling, not token_parse."""
        msg = "malformed token: unparseable capability URI in attestation: bad://uri"
        assert _classify_ucan_error(msg) == "ceiling"

    # -- Nonce errors (step 9) --

    def test_nonce_reused(self) -> None:
        assert _classify_ucan_error("nonce reused: abc-123") == "nonce"

    def test_nonce_too_old(self) -> None:
        assert _classify_ucan_error("nonce too old: 1000-aabb") == "nonce"

    def test_nonce_from_future(self) -> None:
        assert _classify_ucan_error("nonce from the future: 9999999-aabb") == "nonce"

    def test_nonce_format_invalid(self) -> None:
        assert _classify_ucan_error("invalid nonce format: bad") == "nonce"

    def test_nonce_tracker_full(self) -> None:
        msg = "nonce tracker full: capacity 100000 reached with no expired entries to prune"
        assert _classify_ucan_error(msg) == "nonce"

    def test_clock_error(self) -> None:
        assert _classify_ucan_error("system clock error: time went backwards") == "nonce"

    # -- Revocation errors (step 10) --

    def test_token_revoked(self) -> None:
        assert _classify_ucan_error("token revoked: bafyabc123") == "revoked"

    # -- Expiry errors (step 11) --

    def test_token_expired(self) -> None:
        assert _classify_ucan_error("token expired") == "expiry"

    def test_token_not_yet_valid(self) -> None:
        assert _classify_ucan_error("token not yet valid") == "expiry"

    def test_invalid_time_range(self) -> None:
        msg = "invalid time range: nbf (1000) must be less than exp (999)"
        assert _classify_ucan_error(msg) == "expiry"

    def test_expiry_too_far(self) -> None:
        msg = "expiry too far in the future: 100000s exceeds 24h maximum"
        assert _classify_ucan_error(msg) == "expiry"

    # -- Unknown --

    def test_unknown_error(self) -> None:
        assert _classify_ucan_error("something completely unexpected") == "unknown"

    # -- With full bridge formatting --

    def test_with_bridge_prefix_and_suffix(self) -> None:
        msg = (
            "[SCP-PERM-3001] permission error: token revoked: bafyabc123"
            " \u2014 check token format, signatures, time bounds, and capability chain"
        )
        assert _classify_ucan_error(msg) == "revoked"

    def test_signature_with_bridge_format(self) -> None:
        msg = (
            "[SCP-PERM-3001] permission error: signature verification failed"
            " \u2014 check token format, signatures, time bounds, and capability chain"
        )
        assert _classify_ucan_error(msg) == "signatures"


# -----------------------------------------------------------------------
# Passed-before mapping tests
# -----------------------------------------------------------------------


class TestPassedBeforeMapping:
    """Tests that _PASSED_BEFORE correctly reflects the pipeline order."""

    def test_token_parse_nothing_passed(self) -> None:
        assert _PASSED_BEFORE["token_parse"] == set()

    def test_signatures_tokens_passed(self) -> None:
        assert _PASSED_BEFORE["signatures"] == {"tokens_valid"}

    def test_ceiling_tokens_and_sigs_passed(self) -> None:
        assert _PASSED_BEFORE["ceiling"] == {"tokens_valid", "signatures_valid"}

    def test_nonce_tokens_sigs_and_ceiling_passed(self) -> None:
        assert _PASSED_BEFORE["nonce"] == {"tokens_valid", "signatures_valid", "within_ceiling"}

    def test_revoked_all_except_revoked_passed(self) -> None:
        assert _PASSED_BEFORE["revoked"] == {
            "tokens_valid",
            "signatures_valid",
            "within_ceiling",
            "nonce_valid",
        }

    def test_expiry_all_except_expiry_passed(self) -> None:
        assert _PASSED_BEFORE["expiry"] == {
            "tokens_valid",
            "signatures_valid",
            "within_ceiling",
            "nonce_valid",
            "not_revoked",
        }

    def test_unknown_nothing_passed(self) -> None:
        assert _PASSED_BEFORE["unknown"] == set()


# -----------------------------------------------------------------------
# CapabilityValidation field independence integration tests
# -----------------------------------------------------------------------


class TestCapabilityValidationFieldIndependence:
    """Verify that each CapabilityValidation field is set independently.

    These tests mock the bridge and exercise the full classification +
    field-setting logic in evaluate_trust.
    """

    # Sentinel exception class that simulates _scp_core.UcanError for
    # tests.  The production code catches ``bridge.UcanError``; the mock
    # bridge exposes this class so the except clause can match it.
    class _MockUcanError(Exception):
        pass

    def _run(self, error_msg: str) -> CapabilityValidation:
        """Helper: mock bridge.ucan_validate to raise with given message."""
        mock_bridge = MagicMock()
        mock_bridge.UcanError = self._MockUcanError
        mock_bridge.ucan_validate.side_effect = self._MockUcanError(error_msg)

        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            result = asyncio.run(
                evaluate_trust(
                    subject_did="did:dht:z6MkBob",
                    context_id="ctx-test",
                    capability_tokens=["fake-token"],
                )
            )
        return result.capability_validation

    def test_all_pass_when_validation_succeeds(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.UcanError = self._MockUcanError
        mock_bridge.ucan_validate.return_value = None

        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            result = asyncio.run(
                evaluate_trust(
                    subject_did="did:dht:z6MkBob",
                    context_id="ctx-test",
                    capability_tokens=["good-token"],
                )
            )
        cv = result.capability_validation
        assert cv.tokens_valid is True
        assert cv.signatures_valid is True
        assert cv.within_ceiling is True
        assert cv.nonce_valid is True
        assert cv.not_revoked is True
        assert cv.not_expired is True

    def test_revoked_token_has_valid_signature(self) -> None:
        """A revoked token should show signatures_valid=True, not_revoked=False."""
        cv = self._run("token revoked: bafyabc123")
        assert cv.tokens_valid is True
        assert cv.signatures_valid is True
        assert cv.within_ceiling is True
        assert cv.nonce_valid is True
        assert cv.not_revoked is False
        assert cv.not_expired is False

    def test_invalid_signature_does_not_affect_tokens_valid(self) -> None:
        """A bad signature should show tokens_valid=True (parse worked)."""
        cv = self._run("signature verification failed")
        assert cv.tokens_valid is True
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.not_expired is False

    def test_expired_token_has_valid_everything_else(self) -> None:
        """An expired token shows all other checks passed but not_expired=False."""
        cv = self._run("token expired")
        assert cv.tokens_valid is True
        assert cv.signatures_valid is True
        assert cv.within_ceiling is True
        assert cv.nonce_valid is True
        assert cv.not_revoked is True
        assert cv.not_expired is False

    def test_token_not_yet_valid_marks_not_expired_false(self) -> None:
        """A not-yet-valid token shows all checks passed but not_expired=False."""
        cv = self._run("token not yet valid")
        assert cv.tokens_valid is True
        assert cv.signatures_valid is True
        assert cv.within_ceiling is True
        assert cv.nonce_valid is True
        assert cv.not_revoked is True
        assert cv.not_expired is False

    def test_capability_outside_ceiling(self) -> None:
        cv = self._run("capability outside ceiling: messages:admin")
        assert cv.tokens_valid is True
        assert cv.signatures_valid is True
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.not_expired is False

    def test_malformed_token_all_false(self) -> None:
        """A malformed token means nothing could be checked."""
        cv = self._run("malformed token: bad base64")
        assert cv.tokens_valid is False
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.not_expired is False

    def test_nonce_reused(self) -> None:
        """Nonce reuse: parse, sig, and ceiling passed; nonce_valid=False."""
        cv = self._run("nonce reused: abc-123")
        assert cv.tokens_valid is True
        assert cv.signatures_valid is True
        assert cv.within_ceiling is True
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.not_expired is False

    def test_audience_mismatch(self) -> None:
        msg = "audience mismatch: expected did:dht:zMember, got did:dht:zOther"
        cv = self._run(msg)
        assert cv.tokens_valid is True
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.not_expired is False

    def test_no_tokens_all_default_false(self) -> None:
        """When no tokens are provided, all fields stay at default (False)."""
        mock_bridge = MagicMock()
        mock_bridge.UcanError = self._MockUcanError

        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            result = asyncio.run(
                evaluate_trust(
                    subject_did="did:dht:z6MkBob",
                    context_id="ctx-test",
                    capability_tokens=None,
                )
            )
        cv = result.capability_validation
        assert cv.tokens_valid is False
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.not_expired is False

    def test_with_bridge_formatted_error(self) -> None:
        """Full bridge error format is parsed correctly."""
        msg = (
            "[SCP-PERM-3001] permission error: token revoked: bafyabc123"
            " \u2014 check token format, signatures, time bounds, and capability chain"
        )
        cv = self._run(msg)
        assert cv.tokens_valid is True
        assert cv.signatures_valid is True
        assert cv.within_ceiling is True
        assert cv.nonce_valid is True
        assert cv.not_revoked is False
        assert cv.not_expired is False

    def test_did_not_found_classified_as_signature(self) -> None:
        """DID resolution failure (step 2) → tokens_valid=True, signatures_valid=False."""
        cv = self._run("malformed token: DID not found: did:dht:z6MkMissing")
        assert cv.tokens_valid is True
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.not_expired is False

    def test_invalid_did_document_classified_as_signature(self) -> None:
        """Invalid DID document (step 2) → tokens_valid=True, signatures_valid=False."""
        cv = self._run("malformed token: invalid DID document: BEP44 signature invalid")
        assert cv.tokens_valid is True
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.not_expired is False

    def test_network_unavailable_classified_as_signature(self) -> None:
        """Network unavailable (step 2) → tokens_valid=True, signatures_valid=False."""
        cv = self._run("malformed token: network unavailable: all resolvers timed out")
        assert cv.tokens_valid is True
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.not_expired is False

    def test_did_revoked_downgraded_classified_as_signature(self) -> None:
        """DID revoked/downgraded (step 2) → tokens_valid=True, signatures_valid=False."""
        cv = self._run("malformed token: DID revoked/downgraded: stale sequence")
        assert cv.tokens_valid is True
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.not_expired is False

    def test_unparseable_capability_classified_as_ceiling(self) -> None:
        """Capability URI parse failure (step 6) → tokens+sigs valid, ceiling=False."""
        cv = self._run("malformed token: unparseable capability URI in attestation: bad://uri")
        assert cv.tokens_valid is True
        assert cv.signatures_valid is True
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.not_expired is False

    def test_unknown_error_conservatively_all_false(self) -> None:
        """Unrecognized errors set all fields to False (fail-closed)."""
        cv = self._run("something completely unexpected happened")
        assert cv.tokens_valid is False
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.not_expired is False

    def test_non_ucan_exception_propagates(self) -> None:
        """Non-UcanError exceptions (e.g. ValidationError) are NOT silently caught."""
        mock_bridge = MagicMock()
        mock_bridge.UcanError = self._MockUcanError
        # Raise a plain Exception — this should NOT be caught by
        # ``except bridge.UcanError``, and must propagate to the caller.
        mock_bridge.ucan_validate.side_effect = RuntimeError(
            "[SCP-VALID-7001] validation error: context_id contains control characters"
        )

        import pytest

        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            with pytest.raises(RuntimeError, match="control characters"):
                asyncio.run(
                    evaluate_trust(
                        subject_did="did:dht:z6MkBob",
                        context_id="ctx\x00bad",
                        capability_tokens=["fake-token"],
                    )
                )


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
        assert cv.not_expired is False

    def test_individual_fields_settable(self) -> None:
        cv = CapabilityValidation(
            tokens_valid=True,
            signatures_valid=False,
            within_ceiling=True,
            nonce_valid=True,
            not_revoked=False,
            not_expired=True,
        )
        assert cv.tokens_valid is True
        assert cv.signatures_valid is False
        assert cv.within_ceiling is True
        assert cv.nonce_valid is True
        assert cv.not_revoked is False
        assert cv.not_expired is True


class TestBehavioralRecord:
    """Tests for the BehavioralRecord dataclass."""

    def test_default_construction(self) -> None:
        br = BehavioralRecord()
        assert br.contexts_participated == 0
        assert br.total_duration == 0.0
        assert br.governance_actions_against == 0
        assert br.tool_invocations == []
        assert br.role_history == []
        assert br.endorsement_accuracy is None


class TestAttestation:
    """Tests for the Attestation dataclass."""

    def test_construction(self) -> None:
        att = Attestation(type="identity", signature_valid=True)
        assert att.type == "identity"
        assert att.signature_valid is True
        assert att.evidence_valid is None
        assert att.fresh is False
        assert att.issuer == ""
        assert att.claim == {}


class TestEndorsement:
    """Tests for the Endorsement dataclass."""

    def test_construction(self) -> None:
        end = Endorsement(from_did="did:dht:zAlice", capability="messages:write")
        assert end.from_did == "did:dht:zAlice"
        assert end.capability == "messages:write"
        assert end.endorser_behavioral_record == {}


class TestChallengeResult:
    """Tests for the ChallengeResult dataclass."""

    def test_construction(self) -> None:
        cr = ChallengeResult(capability="tool_invoke:assistant", passed=True)
        assert cr.capability == "tool_invoke:assistant"
        assert cr.passed is True
        assert cr.verified_at == ""


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
        assert te.behavioral_record is None
        assert te.attestations == []
        assert te.endorsements == []
        assert te.challenge_results == []
        assert te.consequence_structure is None


# -----------------------------------------------------------------------
# Participation requirement tests
# -----------------------------------------------------------------------


class TestVerifyParticipationRequirements:
    """Tests for verify_participation_requirements."""

    def test_empty_thresholds_passes(self) -> None:
        req = RequireParticipation(thresholds=[])
        profile = ParticipationProfile(participant_did="did:dht:zAlice")
        assert verify_participation_requirements(req, profile) is True

    def test_single_threshold_met(self) -> None:
        req = RequireParticipation(
            thresholds=[ParticipationThreshold(fact_type="context_membership", minimum=1.0)],
        )
        profile = ParticipationProfile(
            participant_did="did:dht:zAlice",
            facts=[
                ParticipationFact(
                    fact_type="context_membership",
                    participant_did="did:dht:zAlice",
                    context_id="ctx-1",
                    value=2.0,
                ),
            ],
        )
        assert verify_participation_requirements(req, profile) is True

    def test_single_threshold_not_met(self) -> None:
        req = RequireParticipation(
            thresholds=[ParticipationThreshold(fact_type="context_membership", minimum=5.0)],
        )
        profile = ParticipationProfile(
            participant_did="did:dht:zAlice",
            facts=[
                ParticipationFact(
                    fact_type="context_membership",
                    participant_did="did:dht:zAlice",
                    context_id="ctx-1",
                    value=2.0,
                ),
            ],
        )
        assert verify_participation_requirements(req, profile) is False

    def test_require_all_true(self) -> None:
        req = RequireParticipation(
            thresholds=[
                ParticipationThreshold(fact_type="a", minimum=1.0),
                ParticipationThreshold(fact_type="b", minimum=1.0),
            ],
            require_all=True,
        )
        profile = ParticipationProfile(
            participant_did="did:dht:zAlice",
            facts=[
                ParticipationFact(
                    fact_type="a",
                    participant_did="did:dht:zAlice",
                    context_id="ctx-1",
                    value=2.0,
                ),
            ],
        )
        # Only 'a' met, 'b' not met — require_all=True → False
        assert verify_participation_requirements(req, profile) is False

    def test_require_any(self) -> None:
        req = RequireParticipation(
            thresholds=[
                ParticipationThreshold(fact_type="a", minimum=1.0),
                ParticipationThreshold(fact_type="b", minimum=1.0),
            ],
            require_all=False,
        )
        profile = ParticipationProfile(
            participant_did="did:dht:zAlice",
            facts=[
                ParticipationFact(
                    fact_type="a",
                    participant_did="did:dht:zAlice",
                    context_id="ctx-1",
                    value=2.0,
                ),
            ],
        )
        # Only 'a' met — require_all=False → True
        assert verify_participation_requirements(req, profile) is True

    def test_maximum_constraint(self) -> None:
        req = RequireParticipation(
            thresholds=[
                ParticipationThreshold(fact_type="a", minimum=1.0, maximum=3.0),
            ],
        )
        profile = ParticipationProfile(
            participant_did="did:dht:zAlice",
            facts=[
                ParticipationFact(
                    fact_type="a",
                    participant_did="did:dht:zAlice",
                    context_id="ctx-1",
                    value=5.0,
                ),
            ],
        )
        # value 5.0 > maximum 3.0 → False
        assert verify_participation_requirements(req, profile) is False
