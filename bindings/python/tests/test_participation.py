"""Tests for SCP Python SDK participation types and verification.

Covers:
- ParticipationFact rejects invalid names
- ParticipationThreshold rejects invalid operators and negative values
- ParticipationProfile validates byte array lengths and non-negative numerics
- RequireParticipation validates non-negative fields and min_contexts u32 range
- ``_to_bridge_dict`` produces correct JSON structure
- ``verify_participation_requirements`` delegates to bridge (mocked)

See spec section 7.3.2.1 and SCP-BA-004.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from scp_sdk.trust import (
    PARTICIPATION_FACT_VARIANTS,
    PARTICIPATION_THRESHOLD_OPERATORS,
    ParticipationFact,
    ParticipationProfile,
    ParticipationThreshold,
    RequireParticipation,
    verify_participation_requirements,
)

# -----------------------------------------------------------------------
# ParticipationFact tests
# -----------------------------------------------------------------------


class TestParticipationFact:
    """Tests for ParticipationFact validation."""

    def test_valid_fact_names_accepted(self) -> None:
        for name in PARTICIPATION_FACT_VARIANTS:
            fact = ParticipationFact(name=name)
            assert fact.name == name

    def test_invalid_fact_name_rejected(self) -> None:
        with pytest.raises(ValueError, match="Invalid ParticipationFact name"):
            ParticipationFact(name="NonexistentFact")

    def test_empty_fact_name_rejected(self) -> None:
        with pytest.raises(ValueError, match="Invalid ParticipationFact name"):
            ParticipationFact(name="")

    def test_case_sensitive_fact_name(self) -> None:
        with pytest.raises(ValueError, match="Invalid ParticipationFact name"):
            ParticipationFact(name="participationduration")


# -----------------------------------------------------------------------
# ParticipationThreshold tests
# -----------------------------------------------------------------------


class TestParticipationThreshold:
    """Tests for ParticipationThreshold validation."""

    def test_valid_operators_accepted(self) -> None:
        for op in PARTICIPATION_THRESHOLD_OPERATORS:
            threshold = ParticipationThreshold(operator=op, value=10)
            assert threshold.operator == op
            assert threshold.value == 10

    def test_invalid_operator_rejected(self) -> None:
        with pytest.raises(ValueError, match="Invalid ParticipationThreshold operator"):
            ParticipationThreshold(operator="NotAnOperator", value=5)

    def test_empty_operator_rejected(self) -> None:
        with pytest.raises(ValueError, match="Invalid ParticipationThreshold operator"):
            ParticipationThreshold(operator="", value=5)

    def test_negative_value_rejected(self) -> None:
        with pytest.raises(ValueError, match="must be non-negative"):
            ParticipationThreshold(operator="AtLeast", value=-1)

    def test_zero_value_accepted(self) -> None:
        threshold = ParticipationThreshold(operator="Equals", value=0)
        assert threshold.value == 0

    def test_large_positive_value_accepted(self) -> None:
        threshold = ParticipationThreshold(operator="GreaterThan", value=2**63)
        assert threshold.value == 2**63


# -----------------------------------------------------------------------
# ParticipationProfile tests
# -----------------------------------------------------------------------


class TestParticipationProfile:
    """Tests for ParticipationProfile validation."""

    def test_default_construction(self) -> None:
        profile = ParticipationProfile(subject_did="did:dht:z6MkTest")
        assert profile.subject_did == "did:dht:z6MkTest"
        assert profile.participation_duration_secs == 0
        assert profile.governance_actions_against == 0
        assert profile.governance_actions_by == 0
        assert profile.tool_invocation_count == 0
        assert profile.context_creation_count == 0
        assert profile.role_progression_count == 0
        assert profile.attestation_count == 0
        assert profile.updated_at == 0
        assert len(profile.event_log_root) == 32
        assert len(profile.signer_public_key) == 32
        assert len(profile.signature) == 64

    def test_negative_participation_duration_rejected(self) -> None:
        with pytest.raises(ValueError, match="participation_duration_secs must be non-negative"):
            ParticipationProfile(
                subject_did="did:dht:z6MkTest",
                participation_duration_secs=-1,
            )

    def test_negative_governance_actions_against_rejected(self) -> None:
        with pytest.raises(ValueError, match="governance_actions_against must be non-negative"):
            ParticipationProfile(
                subject_did="did:dht:z6MkTest",
                governance_actions_against=-1,
            )

    def test_negative_governance_actions_by_rejected(self) -> None:
        with pytest.raises(ValueError, match="governance_actions_by must be non-negative"):
            ParticipationProfile(
                subject_did="did:dht:z6MkTest",
                governance_actions_by=-1,
            )

    def test_negative_tool_invocation_count_rejected(self) -> None:
        with pytest.raises(ValueError, match="tool_invocation_count must be non-negative"):
            ParticipationProfile(
                subject_did="did:dht:z6MkTest",
                tool_invocation_count=-1,
            )

    def test_negative_context_creation_count_rejected(self) -> None:
        with pytest.raises(ValueError, match="context_creation_count must be non-negative"):
            ParticipationProfile(
                subject_did="did:dht:z6MkTest",
                context_creation_count=-1,
            )

    def test_negative_role_progression_count_rejected(self) -> None:
        with pytest.raises(ValueError, match="role_progression_count must be non-negative"):
            ParticipationProfile(
                subject_did="did:dht:z6MkTest",
                role_progression_count=-1,
            )

    def test_negative_attestation_count_rejected(self) -> None:
        with pytest.raises(ValueError, match="attestation_count must be non-negative"):
            ParticipationProfile(
                subject_did="did:dht:z6MkTest",
                attestation_count=-1,
            )

    def test_negative_updated_at_rejected(self) -> None:
        with pytest.raises(ValueError, match="updated_at must be non-negative"):
            ParticipationProfile(
                subject_did="did:dht:z6MkTest",
                updated_at=-1,
            )

    def test_event_log_root_wrong_length_rejected(self) -> None:
        with pytest.raises(ValueError, match="event_log_root must be exactly 32 elements"):
            ParticipationProfile(
                subject_did="did:dht:z6MkTest",
                event_log_root=[0] * 31,
            )

    def test_event_log_root_too_long_rejected(self) -> None:
        with pytest.raises(ValueError, match="event_log_root must be exactly 32 elements"):
            ParticipationProfile(
                subject_did="did:dht:z6MkTest",
                event_log_root=[0] * 33,
            )

    def test_signer_public_key_wrong_length_rejected(self) -> None:
        with pytest.raises(ValueError, match="signer_public_key must be exactly 32 elements"):
            ParticipationProfile(
                subject_did="did:dht:z6MkTest",
                signer_public_key=[0] * 16,
            )

    def test_signature_wrong_length_rejected(self) -> None:
        with pytest.raises(ValueError, match="signature must be exactly 64 elements"):
            ParticipationProfile(
                subject_did="did:dht:z6MkTest",
                signature=[0] * 63,
            )

    def test_byte_array_element_out_of_range_rejected(self) -> None:
        bad_root = [0] * 32
        bad_root[5] = 256
        with pytest.raises(ValueError, match=r"event_log_root\[5\] must be 0-255"):
            ParticipationProfile(
                subject_did="did:dht:z6MkTest",
                event_log_root=bad_root,
            )

    def test_byte_array_negative_element_rejected(self) -> None:
        bad_key = [0] * 32
        bad_key[0] = -1
        with pytest.raises(ValueError, match=r"signer_public_key\[0\] must be 0-255"):
            ParticipationProfile(
                subject_did="did:dht:z6MkTest",
                signer_public_key=bad_key,
            )


# -----------------------------------------------------------------------
# RequireParticipation tests
# -----------------------------------------------------------------------


class TestRequireParticipation:
    """Tests for RequireParticipation validation."""

    def _make_requirement(self, **kwargs: object) -> RequireParticipation:
        defaults: dict[str, object] = {
            "fact": ParticipationFact(name="ParticipationDuration"),
            "threshold": ParticipationThreshold(operator="AtLeast", value=100),
        }
        defaults.update(kwargs)
        return RequireParticipation(**defaults)  # type: ignore[arg-type]

    def test_default_values(self) -> None:
        req = self._make_requirement()
        assert req.max_age_secs == 3600
        assert req.min_contexts == 1

    def test_negative_max_age_secs_rejected(self) -> None:
        with pytest.raises(ValueError, match="max_age_secs must be non-negative"):
            self._make_requirement(max_age_secs=-1)

    def test_zero_max_age_secs_accepted(self) -> None:
        req = self._make_requirement(max_age_secs=0)
        assert req.max_age_secs == 0

    def test_negative_min_contexts_rejected(self) -> None:
        with pytest.raises(ValueError, match="min_contexts must be non-negative"):
            self._make_requirement(min_contexts=-1)

    def test_zero_min_contexts_accepted(self) -> None:
        req = self._make_requirement(min_contexts=0)
        assert req.min_contexts == 0

    def test_min_contexts_exceeds_u32_max_rejected(self) -> None:
        with pytest.raises(ValueError, match="must be <= 4294967295"):
            self._make_requirement(min_contexts=0xFFFF_FFFF + 1)

    def test_min_contexts_at_u32_max_accepted(self) -> None:
        req = self._make_requirement(min_contexts=0xFFFF_FFFF)
        assert req.min_contexts == 0xFFFF_FFFF


# -----------------------------------------------------------------------
# _to_bridge_dict tests
# -----------------------------------------------------------------------


class TestToBridgeDict:
    """Tests that _to_bridge_dict produces correct JSON-compatible structures."""

    def test_participation_profile_bridge_dict(self) -> None:
        profile = ParticipationProfile(
            subject_did="did:dht:z6MkAlice",
            participation_duration_secs=3600,
            governance_actions_against=2,
            governance_actions_by=5,
            tool_invocation_count=10,
            context_creation_count=3,
            role_progression_count=1,
            attestation_count=7,
            updated_at=1700000000,
            event_log_root=[1] * 32,
            signer_public_key=[2] * 32,
            signature=[3] * 64,
        )
        d = profile._to_bridge_dict()

        assert d["subject_did"] == "did:dht:z6MkAlice"
        assert d["participation_duration_secs"] == 3600
        assert d["governance_actions_against"] == 2
        assert d["governance_actions_by"] == 5
        assert d["tool_invocation_count"] == 10
        assert d["context_creation_count"] == 3
        assert d["role_progression_count"] == 1
        assert d["attestation_count"] == 7
        assert d["updated_at"] == 1700000000
        assert d["event_log_root"] == [1] * 32
        assert d["signer_public_key"] == [2] * 32
        assert d["signature"] == [3] * 64

    def test_require_participation_bridge_dict(self) -> None:
        req = RequireParticipation(
            fact=ParticipationFact(name="ToolInvocationCount"),
            threshold=ParticipationThreshold(operator="GreaterThan", value=50),
            max_age_secs=7200,
            min_contexts=3,
        )
        d = req._to_bridge_dict()

        assert d["fact"] == "ToolInvocationCount"
        assert d["threshold"] == {"GreaterThan": 50}
        assert d["max_age_secs"] == 7200
        assert d["min_contexts"] == 3

    def test_require_participation_bridge_dict_defaults(self) -> None:
        req = RequireParticipation(
            fact=ParticipationFact(name="AttestationCount"),
            threshold=ParticipationThreshold(operator="Equals", value=0),
        )
        d = req._to_bridge_dict()

        assert d["fact"] == "AttestationCount"
        assert d["threshold"] == {"Equals": 0}
        assert d["max_age_secs"] == 3600
        assert d["min_contexts"] == 1


# -----------------------------------------------------------------------
# verify_participation_requirements bridge delegation tests
# -----------------------------------------------------------------------


class TestVerifyParticipationRequirements:
    """Tests that verify_participation_requirements delegates to the Rust bridge."""

    def test_delegates_to_bridge(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.verify_participation_requirements.return_value = True

        profiles = [ParticipationProfile(subject_did="did:dht:z6MkAlice")]
        requirements = [
            RequireParticipation(
                fact=ParticipationFact(name="ParticipationDuration"),
                threshold=ParticipationThreshold(operator="AtLeast", value=0),
            ),
        ]

        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            result = verify_participation_requirements(requirements, profiles)

        assert result is True
        mock_bridge.verify_participation_requirements.assert_called_once()

        # Verify the JSON args are well-formed strings.
        call_args = mock_bridge.verify_participation_requirements.call_args
        import json

        profiles_json = json.loads(call_args[0][0])
        requirements_json = json.loads(call_args[0][1])

        assert len(profiles_json) == 1
        assert profiles_json[0]["subject_did"] == "did:dht:z6MkAlice"
        assert len(requirements_json) == 1
        assert requirements_json[0]["fact"] == "ParticipationDuration"
        assert requirements_json[0]["threshold"] == {"AtLeast": 0}

    def test_raises_on_bridge_failure(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.verify_participation_requirements.side_effect = RuntimeError(
            "Threshold not met"
        )

        profiles = [ParticipationProfile(subject_did="did:dht:z6MkBob")]
        requirements = [
            RequireParticipation(
                fact=ParticipationFact(name="ToolInvocationCount"),
                threshold=ParticipationThreshold(operator="AtLeast", value=100),
            ),
        ]

        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            with pytest.raises(RuntimeError, match="Threshold not met"):
                verify_participation_requirements(requirements, profiles)

    def test_empty_requirements_and_profiles(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.verify_participation_requirements.return_value = True

        with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
            result = verify_participation_requirements([], [])

        assert result is True
        call_args = mock_bridge.verify_participation_requirements.call_args
        import json

        assert json.loads(call_args[0][0]) == []
        assert json.loads(call_args[0][1]) == []
