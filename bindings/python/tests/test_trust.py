"""Tests for SCP Python SDK trust evaluation.

Covers:
- UCAN error classification into the 6 independent Layer 1 checks
- CapabilityValidation field independence
- evaluate_trust Layer 1 integration (mocked bridge)
- Dataclass construction for all trust types
- Participation requirement verification

See ``.docs/adrs/phase-3.md`` ADR-017 and spec section 9.3 for the
four-layer trust model.
"""

from __future__ import annotations

import asyncio
import base64 as _base64
import json as _json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

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
    _extract_all_capability_uris,
    _extract_core_error,
    _intersect_capability_validation,
    evaluate_trust,
    verify_participation_requirements,
)

#: Capability URI declared by :func:`_make_mock_token`. ``evaluate_trust``
#: extracts ``att[0]["with"]`` from the (unverified) JWT payload and passes it
#: to ``ucan_validate``, so a mock token must carry a real ``att`` entry.
_MOCK_CAP_URI = "scp:ctx:test-context/messages:write"


def _b64url(obj: dict[str, Any]) -> str:
    raw = _json.dumps(obj).encode("utf-8")
    return _base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _make_mock_token(cap_uri: str = _MOCK_CAP_URI) -> str:
    """Build a minimally-valid UCAN JWT (``header.payload.signature``) whose
    base64url payload declares one capability in ``att[0]["with"]``.

    The signature segment is a placeholder -- the mocked ``ucan_validate``
    never verifies it; ``evaluate_trust`` only reads the payload to pick the
    capability URI to validate against.
    """
    header = _b64url({"alg": "EdDSA", "typ": "JWT", "ucv": "0.10.0"})
    payload = _b64url({"att": [{"with": cap_uri, "can": "messages/write"}]})
    return f"{header}.{payload}.sig"


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
# _extract_all_capability_uris tests
# -----------------------------------------------------------------------


class TestExtractAllCapabilityUris:
    """Tests for _extract_all_capability_uris which returns all att[i].with values."""

    def test_multi_att_returns_all_uris(self) -> None:
        """Multi-att token returns all non-empty with values."""
        att = [
            {"with": "scp:ctx:c/a:read"},
            {"with": "scp:ctx:c/b:write"},
            {"with": "scp:ctx:c/c:admin"},
        ]
        token = f"{_b64url({'alg': 'EdDSA'})}.{_b64url({'att': att})}.sig"
        result = _extract_all_capability_uris(token)
        assert result == ["scp:ctx:c/a:read", "scp:ctx:c/b:write", "scp:ctx:c/c:admin"]

    def test_single_att_returns_list_with_one_uri(self) -> None:
        """Single-att token returns a one-element list."""
        token = (
            f"{_b64url({'alg': 'EdDSA'})}."
            f"{_b64url({'att': [{'with': 'scp:ctx:c/messages:write'}]})}."
            f"sig"
        )
        result = _extract_all_capability_uris(token)
        assert result == ["scp:ctx:c/messages:write"]

    def test_skips_entries_with_missing_or_empty_with(self) -> None:
        """Entries without a valid 'with' key are skipped."""
        token = (
            f"{_b64url({'alg': 'EdDSA'})}."
            f"{_b64url({'att': [{'can': 'x'}, {'with': 'scp:ctx:c/a:read'}, {'with': ''}]})}."
            f"sig"
        )
        result = _extract_all_capability_uris(token)
        assert result == ["scp:ctx:c/a:read"]

    def test_not_a_jwt_triple_returns_none(self) -> None:
        """A non-JWT string returns None."""
        assert _extract_all_capability_uris("not-a-jwt") is None

    def test_invalid_base64url_returns_none(self) -> None:
        """Non-base64url payload returns None."""
        assert _extract_all_capability_uris("header.@@@notbase64@@@.sig") is None

    def test_empty_att_returns_none(self) -> None:
        """A token with empty att returns None (not [])."""
        token = f"{_b64url({'alg': 'EdDSA'})}.{_b64url({'att': []})}.sig"
        assert _extract_all_capability_uris(token) is None

    def test_all_entries_missing_with_returns_none(self) -> None:
        """All entries without 'with' → None (no valid capabilities)."""
        token = f"{_b64url({'alg': 'EdDSA'})}.{_b64url({'att': [{'can': 'x'}, {'with': ''}]})}.sig"
        assert _extract_all_capability_uris(token) is None


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

    # -- Delegation chain parent-token failures (issue #1026) --
    # These errors are now wrapped as DelegationChainBroken by Rust, so
    # they classify as "signatures" (conservative) instead of the
    # optimistic leaf-token stages they would have matched before.

    def test_parent_token_expired_classifies_as_signatures(self) -> None:
        """Parent expiry wrapped by Rust → 'signatures', not 'expiry'."""
        msg = "delegation chain broken: parent token failed: token expired"
        assert _classify_ucan_error(msg) == "signatures"

    def test_parent_token_not_yet_valid_classifies_as_signatures(self) -> None:
        msg = "delegation chain broken: parent token failed: token not yet valid"
        assert _classify_ucan_error(msg) == "signatures"

    def test_parent_token_invalid_time_range_classifies_as_signatures(self) -> None:
        msg = (
            "delegation chain broken: parent token failed: "
            "invalid time range: nbf (1000) must be less than exp (999)"
        )
        assert _classify_ucan_error(msg) == "signatures"

    def test_parent_token_expiry_too_far_classifies_as_signatures(self) -> None:
        msg = (
            "delegation chain broken: parent token failed: "
            "expiry too far in the future: 100000s exceeds 24h maximum"
        )
        assert _classify_ucan_error(msg) == "signatures"

    def test_parent_token_revoked_classifies_as_signatures(self) -> None:
        msg = "delegation chain broken: parent token failed: token revoked: bafyabc123"
        assert _classify_ucan_error(msg) == "signatures"

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
                    scp=MagicMock(),
                    subject_did="did:dht:z6MkBob",
                    context_id="ctx-test",
                    capability_tokens=[_make_mock_token()],
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
                    scp=MagicMock(),
                    subject_did="did:dht:z6MkBob",
                    context_id="ctx-test",
                    capability_tokens=[_make_mock_token()],
                )
            )
        cv = result.capability_validation
        assert cv.tokens_valid is True
        assert cv.signatures_valid is True
        assert cv.within_ceiling is True
        assert cv.nonce_valid is True
        assert cv.not_revoked is True
        assert cv.time_bounds_valid is True

    def test_revoked_token_has_valid_signature(self) -> None:
        """A revoked token should show signatures_valid=True, not_revoked=False."""
        cv = self._run("token revoked: bafyabc123")
        assert cv.tokens_valid is True
        assert cv.signatures_valid is True
        assert cv.within_ceiling is True
        assert cv.nonce_valid is True
        assert cv.not_revoked is False
        assert cv.time_bounds_valid is False

    def test_invalid_signature_does_not_affect_tokens_valid(self) -> None:
        """A bad signature should show tokens_valid=True (parse worked)."""
        cv = self._run("signature verification failed")
        assert cv.tokens_valid is True
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.time_bounds_valid is False

    def test_expired_token_has_valid_everything_else(self) -> None:
        """An expired token shows all other checks passed but time_bounds_valid=False."""
        cv = self._run("token expired")
        assert cv.tokens_valid is True
        assert cv.signatures_valid is True
        assert cv.within_ceiling is True
        assert cv.nonce_valid is True
        assert cv.not_revoked is True
        assert cv.time_bounds_valid is False

    def test_token_not_yet_valid_marks_time_bounds_valid_false(self) -> None:
        """A not-yet-valid token shows all checks passed but time_bounds_valid=False."""
        cv = self._run("token not yet valid")
        assert cv.tokens_valid is True
        assert cv.signatures_valid is True
        assert cv.within_ceiling is True
        assert cv.nonce_valid is True
        assert cv.not_revoked is True
        assert cv.time_bounds_valid is False

    def test_capability_outside_ceiling(self) -> None:
        cv = self._run("capability outside ceiling: messages:admin")
        assert cv.tokens_valid is True
        assert cv.signatures_valid is True
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.time_bounds_valid is False

    def test_malformed_token_all_false(self) -> None:
        """A malformed token means nothing could be checked."""
        cv = self._run("malformed token: bad base64")
        assert cv.tokens_valid is False
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.time_bounds_valid is False

    def test_nonce_reused(self) -> None:
        """Nonce reuse: parse, sig, and ceiling passed; nonce_valid=False."""
        cv = self._run("nonce reused: abc-123")
        assert cv.tokens_valid is True
        assert cv.signatures_valid is True
        assert cv.within_ceiling is True
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.time_bounds_valid is False

    def test_audience_mismatch(self) -> None:
        msg = "audience mismatch: expected did:dht:zMember, got did:dht:zOther"
        cv = self._run(msg)
        assert cv.tokens_valid is True
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.time_bounds_valid is False

    def test_no_tokens_all_default_false(self) -> None:
        """When no tokens are provided, all fields stay at default (False)."""
        mock_bridge = MagicMock()
        mock_bridge.UcanError = self._MockUcanError

        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            result = asyncio.run(
                evaluate_trust(
                    scp=MagicMock(),
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
        assert cv.time_bounds_valid is False

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
        assert cv.time_bounds_valid is False

    def test_did_not_found_classified_as_signature(self) -> None:
        """DID resolution failure (step 2) → tokens_valid=True, signatures_valid=False."""
        cv = self._run("malformed token: DID not found: did:dht:z6MkMissing")
        assert cv.tokens_valid is True
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.time_bounds_valid is False

    def test_invalid_did_document_classified_as_signature(self) -> None:
        """Invalid DID document (step 2) → tokens_valid=True, signatures_valid=False."""
        cv = self._run("malformed token: invalid DID document: BEP44 signature invalid")
        assert cv.tokens_valid is True
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.time_bounds_valid is False

    def test_network_unavailable_classified_as_signature(self) -> None:
        """Network unavailable (step 2) → tokens_valid=True, signatures_valid=False."""
        cv = self._run("malformed token: network unavailable: all resolvers timed out")
        assert cv.tokens_valid is True
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.time_bounds_valid is False

    def test_did_revoked_downgraded_classified_as_signature(self) -> None:
        """DID revoked/downgraded (step 2) → tokens_valid=True, signatures_valid=False."""
        cv = self._run("malformed token: DID revoked/downgraded: stale sequence")
        assert cv.tokens_valid is True
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.time_bounds_valid is False

    def test_unparseable_capability_classified_as_ceiling(self) -> None:
        """Capability URI parse failure (step 6) → tokens+sigs valid, ceiling=False."""
        cv = self._run("malformed token: unparseable capability URI in attestation: bad://uri")
        assert cv.tokens_valid is True
        assert cv.signatures_valid is True
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.time_bounds_valid is False

    def test_unknown_error_conservatively_all_false(self) -> None:
        """Unrecognized errors set all fields to False (fail-closed)."""
        cv = self._run("something completely unexpected happened")
        assert cv.tokens_valid is False
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.time_bounds_valid is False

    # -- Delegation chain parent-token failures (issue #1026) --
    # Parent-token expiry/revocation now classifies conservatively: only
    # tokens_valid is True (parse passed for the leaf), all other fields
    # are False because steps 6-11 never ran on the leaf token.

    def test_parent_expired_does_not_report_ceiling_true(self) -> None:
        """AC: parent expired + leaf invalid ceiling → within_ceiling is not True."""
        cv = self._run("delegation chain broken: parent token failed: token expired")
        assert cv.tokens_valid is True
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.time_bounds_valid is False

    def test_parent_revoked_does_not_report_nonce_or_revoked_true(self) -> None:
        """AC: parent revoked + leaf valid → not_revoked and nonce_valid are not True."""
        cv = self._run("delegation chain broken: parent token failed: token revoked: bafyabc123")
        assert cv.tokens_valid is True
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.time_bounds_valid is False

    def test_parent_not_yet_valid_conservative(self) -> None:
        """Parent not-yet-valid → conservative (only tokens_valid)."""
        cv = self._run("delegation chain broken: parent token failed: token not yet valid")
        assert cv.tokens_valid is True
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.time_bounds_valid is False

    def test_parent_expiry_too_far_conservative(self) -> None:
        """Parent expiry-too-far → conservative (only tokens_valid)."""
        cv = self._run(
            "delegation chain broken: parent token failed: "
            "expiry too far in the future: 100000s exceeds 24h maximum"
        )
        assert cv.tokens_valid is True
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.time_bounds_valid is False

    def test_parent_invalid_time_range_conservative(self) -> None:
        """Parent invalid-time-range → conservative (only tokens_valid)."""
        cv = self._run(
            "delegation chain broken: parent token failed: "
            "invalid time range: nbf (1000) must be less than exp (999)"
        )
        assert cv.tokens_valid is True
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.time_bounds_valid is False

    def test_multi_att_token_evaluates_all_uris(self) -> None:
        """evaluate_trust validates ALL att[i] URIs and AND-intersects verdicts.

        When every URI in a multi-att token passes, all fields are true.
        Both att[0]["with"] and att[1]["with"] are sent to ucan_validate.
        """
        multi_att = [
            {"with": "scp:ctx:c/messages:read", "can": "messages/read"},
            {"with": "scp:ctx:c/messages:admin", "can": "messages/admin"},
        ]
        multi_att_token = (
            f"{_b64url({'alg': 'EdDSA', 'typ': 'JWT', 'ucv': '0.10.0'})}."
            f"{_b64url({'att': multi_att})}."
            f"sig"
        )

        uris_seen: list[str] = []

        def side_effect(context_id: str, token: str, cap_uri: str) -> None:
            uris_seen.append(cap_uri)
            # all URIs pass — return None

        mock_bridge = MagicMock()
        mock_bridge.UcanError = self._MockUcanError
        mock_bridge.ucan_validate.side_effect = side_effect

        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            result = asyncio.run(
                evaluate_trust(
                    scp=MagicMock(),
                    subject_did="did:dht:z6MkBob",
                    context_id="ctx-test",
                    capability_tokens=[multi_att_token],
                )
            )
        cv = result.capability_validation
        # Both URIs passed — all fields true.
        assert cv.tokens_valid is True
        assert cv.signatures_valid is True
        assert cv.within_ceiling is True
        assert cv.nonce_valid is True
        assert cv.not_revoked is True
        assert cv.time_bounds_valid is True
        # Both att URIs were sent to ucan_validate.
        assert "scp:ctx:c/messages:read" in uris_seen
        assert "scp:ctx:c/messages:admin" in uris_seen
        assert len(uris_seen) == 2

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
                        scp=MagicMock(),
                        subject_did="did:dht:z6MkBob",
                        context_id="ctx\x00bad",
                        capability_tokens=[_make_mock_token()],
                    )
                )

    def test_malformed_jwt_token_all_false_bridge_not_called(self) -> None:
        """A token that is not a header.payload.signature triple cannot have
        its capability extracted, so it is treated as invalid and never reaches
        the bridge. This is the fail-closed path for "*" no longer being passed.
        """
        mock_bridge = MagicMock()
        mock_bridge.UcanError = self._MockUcanError

        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            result = asyncio.run(
                evaluate_trust(
                    scp=MagicMock(),
                    subject_did="did:dht:z6MkBob",
                    context_id="ctx-test",
                    capability_tokens=["not-a-jwt"],
                )
            )
        cv = result.capability_validation
        assert cv.tokens_valid is False
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.time_bounds_valid is False
        mock_bridge.ucan_validate.assert_not_called()

    def test_empty_att_token_all_false_bridge_not_called(self) -> None:
        """A structurally-valid JWT that declares no capabilities grants
        nothing, so there is no capability URI to validate against and the
        bridge is never called.
        """
        mock_bridge = MagicMock()
        mock_bridge.UcanError = self._MockUcanError

        empty_att_token = f"{_b64url({'alg': 'EdDSA'})}.{_b64url({'att': []})}.sig"
        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            result = asyncio.run(
                evaluate_trust(
                    scp=MagicMock(),
                    subject_did="did:dht:z6MkBob",
                    context_id="ctx-test",
                    capability_tokens=[empty_att_token],
                )
            )
        cv = result.capability_validation
        assert cv.tokens_valid is False
        assert cv.signatures_valid is False
        assert cv.within_ceiling is False
        assert cv.nonce_valid is False
        assert cv.not_revoked is False
        assert cv.time_bounds_valid is False
        mock_bridge.ucan_validate.assert_not_called()

    def test_declared_capability_uri_passed_to_bridge(self) -> None:
        """evaluate_trust must validate the token against its own declared
        capability (att[0]["with"]), never the bogus "*" literal that the
        bridge rejects with InvalidCapabilityUri.
        """
        mock_bridge = MagicMock()
        mock_bridge.UcanError = self._MockUcanError
        mock_bridge.ucan_validate.return_value = None

        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            asyncio.run(
                evaluate_trust(
                    scp=MagicMock(),
                    subject_did="did:dht:z6MkBob",
                    context_id="ctx-test",
                    capability_tokens=[_make_mock_token()],
                )
            )
        # Positional args: (context_id, token, capability_uri)
        call_args = mock_bridge.ucan_validate.call_args[0]
        assert call_args[2] == _MOCK_CAP_URI

    def test_multi_att_att0_expiry_att1_also_validated_intersected(self) -> None:
        """Multi-att token: att[0] expiry + att[1] same expiry → both validated, intersected.

        evaluate_trust validates ALL att URIs. att[0] fails at step 11 (expiry)
        so time_bounds_valid=False for att[0]. att[1] is also sent to the bridge.
        When both fail with the same stage, the AND-intersected verdict is returned
        and fail-fast stops processing further tokens.
        """
        multi_att = [
            {"with": "scp:ctx:c/messages:read", "can": "messages/read"},
            {"with": "scp:ctx:c/messages:write", "can": "messages/write"},
        ]
        multi_att_token = (
            f"{_b64url({'alg': 'EdDSA', 'typ': 'JWT', 'ucv': '0.10.0'})}."
            f"{_b64url({'att': multi_att})}."
            f"sig"
        )

        uris_seen: list[str] = []

        def side_effect(context_id: str, token: str, cap_uri: str) -> None:
            uris_seen.append(cap_uri)
            # Both att entries fail with expiry (step 11).
            raise TestCapabilityValidationFieldIndependence._MockUcanError("token expired")

        mock_bridge = MagicMock()
        mock_bridge.UcanError = self._MockUcanError
        mock_bridge.ucan_validate.side_effect = side_effect

        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            result = asyncio.run(
                evaluate_trust(
                    scp=MagicMock(),
                    subject_did="did:dht:z6MkBob",
                    context_id="ctx-test",
                    capability_tokens=[multi_att_token],
                )
            )
        cv = result.capability_validation
        # Both att entries fail expiry: sigs/ceiling/nonce/revoked=True, time_bounds=False.
        assert cv.tokens_valid is True
        assert cv.signatures_valid is True
        assert cv.within_ceiling is True
        assert cv.nonce_valid is True
        assert cv.not_revoked is True
        assert cv.time_bounds_valid is False
        # Both att URIs were presented to ucan_validate (AND-intersection over all URIs).
        assert "scp:ctx:c/messages:read" in uris_seen
        assert "scp:ctx:c/messages:write" in uris_seen
        assert len(uris_seen) == 2

    def test_cross_att_and_intersection_att0_expiry_att1_ceiling(self) -> None:
        """Cross-att AND-intersection: att[0] expiry + att[1] ceiling → both fields false.

        att[0] fails at step 11 (expiry): time_bounds_valid=False.
        att[1] fails at step 8 (ceiling): within_ceiling=False.
        The AND-intersected verdict must have BOTH time_bounds_valid=False AND
        within_ceiling=False. Fields that passed in both (tokens_valid,
        signatures_valid) stay True.
        """
        multi_att = [
            {"with": "scp:ctx:c/messages:read", "can": "messages/read"},
            {"with": "scp:ctx:c/messages:write", "can": "messages/write"},
        ]
        multi_att_token = (
            f"{_b64url({'alg': 'EdDSA', 'typ': 'JWT', 'ucv': '0.10.0'})}."
            f"{_b64url({'att': multi_att})}."
            f"sig"
        )

        uris_seen: list[str] = []

        def side_effect(context_id: str, token: str, cap_uri: str) -> None:
            uris_seen.append(cap_uri)
            if cap_uri.endswith(":read"):
                # att[0] fails at step 11 (expiry): tokens+sigs+ceiling+nonce+notRevoked=True,
                # time_bounds=False.
                raise TestCapabilityValidationFieldIndependence._MockUcanError("token expired")
            # att[1] fails at step 8 (ceiling): tokens+sigs=True, ceiling=False, rest=False.
            raise TestCapabilityValidationFieldIndependence._MockUcanError(
                "capability outside ceiling: write not granted"
            )

        mock_bridge = MagicMock()
        mock_bridge.UcanError = self._MockUcanError
        mock_bridge.ucan_validate.side_effect = side_effect

        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            result = asyncio.run(
                evaluate_trust(
                    scp=MagicMock(),
                    subject_did="did:dht:z6MkBob",
                    context_id="ctx-test",
                    capability_tokens=[multi_att_token],
                )
            )
        cv = result.capability_validation
        # tokens_valid: True (passed in both att[0] expiry verdict AND att[1] ceiling verdict)
        assert cv.tokens_valid is True
        # signatures_valid: True (passed in both)
        assert cv.signatures_valid is True
        # within_ceiling: False (att[1] failed ceiling; AND → False)
        assert cv.within_ceiling is False
        # nonce_valid: False (att[1] ceiling verdict has nonce=False; AND → False)
        assert cv.nonce_valid is False
        # not_revoked: False (att[1] ceiling verdict has not_revoked=False; AND → False)
        assert cv.not_revoked is False
        # time_bounds_valid: False (att[0] expiry verdict has time_bounds=False; AND → False)
        assert cv.time_bounds_valid is False
        # Both att URIs were sent to ucan_validate.
        assert "scp:ctx:c/messages:read" in uris_seen
        assert "scp:ctx:c/messages:write" in uris_seen
        assert len(uris_seen) == 2


# -----------------------------------------------------------------------
# _intersect_capability_validation unit tests
# -----------------------------------------------------------------------


class TestIntersectCapabilityValidation:
    """Unit tests for the _intersect_capability_validation helper."""

    def _all_true(self) -> CapabilityValidation:
        return CapabilityValidation(
            tokens_valid=True,
            signatures_valid=True,
            within_ceiling=True,
            nonce_valid=True,
            not_revoked=True,
            time_bounds_valid=True,
        )

    def test_true_and_true_is_true(self) -> None:
        result = _intersect_capability_validation(self._all_true(), self._all_true())
        assert result.tokens_valid is True
        assert result.signatures_valid is True
        assert result.within_ceiling is True
        assert result.nonce_valid is True
        assert result.not_revoked is True
        assert result.time_bounds_valid is True

    def test_false_wins_in_first_operand(self) -> None:
        expiry_fail = CapabilityValidation(
            tokens_valid=True,
            signatures_valid=True,
            within_ceiling=True,
            nonce_valid=True,
            not_revoked=True,
            time_bounds_valid=False,
        )
        result = _intersect_capability_validation(expiry_fail, self._all_true())
        assert result.tokens_valid is True
        assert result.signatures_valid is True
        assert result.within_ceiling is True
        assert result.nonce_valid is True
        assert result.not_revoked is True
        assert result.time_bounds_valid is False

    def test_false_wins_in_second_operand(self) -> None:
        ceiling_fail = CapabilityValidation(
            tokens_valid=True,
            signatures_valid=True,
            within_ceiling=False,
            nonce_valid=False,
            not_revoked=False,
            time_bounds_valid=False,
        )
        result = _intersect_capability_validation(self._all_true(), ceiling_fail)
        assert result.tokens_valid is True
        assert result.signatures_valid is True
        assert result.within_ceiling is False
        assert result.nonce_valid is False
        assert result.not_revoked is False
        assert result.time_bounds_valid is False

    def test_cross_field_intersection(self) -> None:
        """Two operands that fail at different pipeline stages."""
        expiry_fail = CapabilityValidation(
            tokens_valid=True,
            signatures_valid=True,
            within_ceiling=True,
            nonce_valid=True,
            not_revoked=True,
            time_bounds_valid=False,
        )
        ceiling_fail = CapabilityValidation(
            tokens_valid=True,
            signatures_valid=True,
            within_ceiling=False,
            nonce_valid=False,
            not_revoked=False,
            time_bounds_valid=False,
        )
        result = _intersect_capability_validation(expiry_fail, ceiling_fail)
        # tokens + sigs passed in both
        assert result.tokens_valid is True
        assert result.signatures_valid is True
        # ceiling failed in ceiling_fail
        assert result.within_ceiling is False
        # nonce/revoked/timebounds all false
        assert result.nonce_valid is False
        assert result.not_revoked is False
        assert result.time_bounds_valid is False


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
            result = verify_participation_requirements([req], [profile])
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
                verify_participation_requirements([req], [profile])

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
            result = verify_participation_requirements(reqs, [profile])
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
            result = verify_participation_requirements([req], profiles)
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
            verify_participation_requirements([req], [profile])

        call_args = mock_bridge.verify_participation_requirements.call_args
        import json

        profiles_json = json.loads(call_args[0][0])
        reqs_json = json.loads(call_args[0][1])

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
        thresholds = {"WebAuthn": {"min_attestors": 2}}
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
