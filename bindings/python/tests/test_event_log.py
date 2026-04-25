"""Tests for the SCP Python SDK event log module.

Covers:
- Event, Proof, Checkpoint, SignedCheckpoint dataclasses
- :meth:`SCP.event_log_query` / :meth:`SCP.event_log_verify` /
  :meth:`SCP.event_log_checkpoint` dispatch
- ``_extract_root_hash`` and ``_extract_event_count`` helpers

Phase 4 PR 5 Agent B+C (#1549) deleted the :class:`EventLog` namespace
class. Every operation lives on :class:`scp_sdk.SCP` — see
:meth:`SCP.event_log_query`, :meth:`SCP.event_log_verify`,
:meth:`SCP.event_log_checkpoint`.

Tests mock the ``_native`` bridge; no Rust extension required.

See ``.docs/standards/python.md`` and ``.docs/adrs/phase-3.md`` ADR-014.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from scp_sdk.event_log import (
    _EMPTY_ROOT_HASH,
    Checkpoint,
    Event,
    Proof,
    SignedCheckpoint,
    _extract_event_count,
    _extract_root_hash,
)

# -----------------------------------------------------------------------
# Test fixtures: mock bridge objects
# -----------------------------------------------------------------------

SAMPLE_ROOT_HASH = "a1b2c3d4e5f6" + "0" * 52


def _make_mock_event(
    event_type: str = "LogSummary",
    actor_did: str = "",
    timestamp: float = 1_700_000_000.0,
    payload: Any = None,
    sequence: int = 0,
) -> SimpleNamespace:
    """Create a mock bridge event (SimpleNamespace mimics PyEvent)."""
    return SimpleNamespace(
        event_type=event_type,
        actor_did=actor_did,
        timestamp=timestamp,
        payload=payload,
        sequence=sequence,
    )


def _make_log_summary_event(
    event_count: int = 10,
    merkle_root: str = SAMPLE_ROOT_HASH,
    sequence: int = 9,
) -> SimpleNamespace:
    """Create a mock LogSummary event matching the bridge's format."""
    return _make_mock_event(
        event_type="LogSummary",
        payload={"event_count": event_count, "merkle_root": merkle_root},
        sequence=sequence,
    )


def _make_scp(native: MagicMock | None = None) -> MagicMock:
    scp = MagicMock()
    scp._native = native if native is not None else MagicMock()
    return scp


# -----------------------------------------------------------------------
# Dataclass tests
# -----------------------------------------------------------------------


class TestEventDataclass:
    """Tests for the Event dataclass."""

    def test_event_construction(self) -> None:
        event = Event(
            event_type="MessageSent",
            actor_did="did:dht:z6MkAlice",
            timestamp=1_700_000_000.0,
            payload={"text": "hello"},
            sequence=42,
        )
        assert event.event_type == "MessageSent"
        assert event.actor_did == "did:dht:z6MkAlice"
        assert event.timestamp == 1_700_000_000.0
        assert event.payload == {"text": "hello"}
        assert event.sequence == 42

    def test_event_equality(self) -> None:
        kwargs: dict[str, Any] = {
            "event_type": "ContextCreated",
            "actor_did": "did:dht:z6MkBob",
            "timestamp": 1.0,
            "payload": None,
            "sequence": 0,
        }
        assert Event(**kwargs) == Event(**kwargs)

    def test_event_with_none_payload(self) -> None:
        event = Event(
            event_type="ContextClosed",
            actor_did="did:dht:z6MkAlice",
            timestamp=1.0,
            payload=None,
            sequence=0,
        )
        assert event.payload is None


class TestProofDataclass:
    """Tests for the Proof dataclass."""

    def test_proof_construction(self) -> None:
        proof = Proof(
            verified=True,
            proof_type="inclusion",
            details={"leaf_index": 5, "path": []},
        )
        assert proof.verified is True
        assert proof.proof_type == "inclusion"
        assert proof.details == {"leaf_index": 5, "path": []}

    def test_proof_absence_type(self) -> None:
        proof = Proof(verified=False, proof_type="absence", details=None)
        assert proof.proof_type == "absence"
        assert proof.verified is False


class TestCheckpointDataclass:
    """Tests for the Checkpoint dataclass."""

    def test_checkpoint_construction(self) -> None:
        cp = Checkpoint(
            context_id="ctx-abc",
            sequence=9,
            timestamp=1_700_000_000.0,
            root_hash="ab" * 32,
            event_count=10,
        )
        assert cp.context_id == "ctx-abc"
        assert cp.sequence == 9
        assert cp.timestamp == 1_700_000_000.0
        assert cp.root_hash == "ab" * 32
        assert cp.event_count == 10

    def test_checkpoint_default_event_count(self) -> None:
        cp = Checkpoint(
            context_id="ctx-x",
            sequence=0,
            timestamp=1.0,
            root_hash="00" * 32,
        )
        assert cp.event_count == 0

    def test_checkpoint_root_hash_is_string(self) -> None:
        cp = Checkpoint(
            context_id="ctx-y",
            sequence=5,
            timestamp=2.0,
            root_hash=SAMPLE_ROOT_HASH,
            event_count=6,
        )
        assert isinstance(cp.root_hash, str)
        assert len(cp.root_hash) == 64


class TestSignedCheckpointDataclass:
    """Tests for the SignedCheckpoint dataclass."""

    def test_construction(self) -> None:
        sc = SignedCheckpoint(
            context_id="ctx-signed",
            sender_did="did:dht:z6MkAlice",
            event_count=42,
            merkle_root="ab" * 32,
            epoch=3,
            timestamp=1_700_000_000,
            signature="cd" * 64,
        )
        assert sc.context_id == "ctx-signed"
        assert sc.sender_did == "did:dht:z6MkAlice"
        assert sc.event_count == 42
        assert sc.merkle_root == "ab" * 32
        assert sc.epoch == 3
        assert sc.timestamp == 1_700_000_000
        assert sc.signature == "cd" * 64

    def test_epoch_can_be_none(self) -> None:
        sc = SignedCheckpoint(
            context_id="ctx-broadcast",
            sender_did="did:dht:z6MkBob",
            event_count=0,
            merkle_root="00" * 32,
            epoch=None,
            timestamp=1_700_000_000,
            signature="ff" * 64,
        )
        assert sc.epoch is None


# -----------------------------------------------------------------------
# _extract_root_hash helper tests
# -----------------------------------------------------------------------


class TestExtractRootHash:
    """Tests for the _extract_root_hash helper function."""

    def test_extracts_root_from_log_summary(self) -> None:
        events = [_make_log_summary_event(merkle_root="ab" * 32)]
        assert _extract_root_hash(events) == "ab" * 32

    def test_returns_empty_sentinel_for_empty_events(self) -> None:
        assert _extract_root_hash([]) == _EMPTY_ROOT_HASH

    def test_returns_empty_sentinel_for_none_payload(self) -> None:
        events = [_make_mock_event(payload=None)]
        assert _extract_root_hash(events) == _EMPTY_ROOT_HASH

    def test_returns_empty_sentinel_for_non_dict_payload(self) -> None:
        events = [_make_mock_event(payload="not a dict")]
        assert _extract_root_hash(events) == _EMPTY_ROOT_HASH

    def test_returns_empty_sentinel_for_missing_merkle_root_key(self) -> None:
        events = [_make_mock_event(payload={"event_count": 5})]
        assert _extract_root_hash(events) == _EMPTY_ROOT_HASH

    def test_returns_empty_sentinel_for_wrong_length_root(self) -> None:
        events = [_make_mock_event(payload={"merkle_root": "tooshort"})]
        assert _extract_root_hash(events) == _EMPTY_ROOT_HASH

    def test_returns_empty_sentinel_for_non_string_root(self) -> None:
        events = [_make_mock_event(payload={"merkle_root": 12345})]
        assert _extract_root_hash(events) == _EMPTY_ROOT_HASH

    def test_picks_first_valid_root_from_multiple_events(self) -> None:
        first_root = "11" * 32
        second_root = "22" * 32
        events = [
            _make_log_summary_event(merkle_root=first_root),
            _make_log_summary_event(merkle_root=second_root),
        ]
        assert _extract_root_hash(events) == first_root

    def test_skips_events_without_payload_attr(self) -> None:
        no_payload = object()
        valid = _make_log_summary_event(merkle_root="cc" * 32)
        assert _extract_root_hash([no_payload, valid]) == "cc" * 32

    def test_empty_root_hash_is_64_zeros(self) -> None:
        assert _EMPTY_ROOT_HASH == "0" * 64
        assert len(_EMPTY_ROOT_HASH) == 64


# -----------------------------------------------------------------------
# _extract_event_count helper tests
# -----------------------------------------------------------------------


class TestExtractEventCount:
    """Tests for the _extract_event_count helper function."""

    def test_extracts_count_from_log_summary(self) -> None:
        events = [_make_log_summary_event(event_count=42)]
        assert _extract_event_count(events) == 42

    def test_returns_len_for_empty_events(self) -> None:
        assert _extract_event_count([]) == 0

    def test_returns_len_for_non_dict_payload(self) -> None:
        events = [_make_mock_event(payload="string")]
        assert _extract_event_count(events) == 1

    def test_returns_len_for_missing_event_count_key(self) -> None:
        events = [_make_mock_event(payload={"merkle_root": "ab" * 32})]
        assert _extract_event_count(events) == 1

    def test_returns_len_for_non_int_count(self) -> None:
        events = [_make_mock_event(payload={"event_count": "not_int"})]
        assert _extract_event_count(events) == 1

    def test_handles_zero_event_count(self) -> None:
        events = [_make_log_summary_event(event_count=0)]
        assert _extract_event_count(events) == 0

    def test_handles_large_event_count(self) -> None:
        events = [_make_log_summary_event(event_count=1_000_000)]
        assert _extract_event_count(events) == 1_000_000


# -----------------------------------------------------------------------
# SCP.event_log_* dispatch tests
# -----------------------------------------------------------------------


class TestScpEventLogQuery:
    """Tests for :meth:`SCP.event_log_query` — bridge dispatch + wrapping."""

    @pytest.mark.asyncio
    async def test_query_returns_event_list(self) -> None:
        from scp_sdk.scp import SCP

        raw_events = [
            _make_mock_event(
                event_type="MessageSent",
                actor_did="did:dht:z6MkAlice",
                timestamp=1_700_000_000.0,
                payload={"text": "hello"},
                sequence=0,
            ),
        ]
        native = MagicMock()
        native.event_log_query.return_value = raw_events
        scp = _make_scp(native)

        events = await SCP.event_log_query(scp, "ctx-query")
        assert len(events) == 1
        assert isinstance(events[0], Event)
        assert events[0].event_type == "MessageSent"
        assert events[0].actor_did == "did:dht:z6MkAlice"

    @pytest.mark.asyncio
    async def test_query_passes_filter_dict_through(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.event_log_query.return_value = []
        scp = _make_scp(native)

        filter_dict = {
            "event_type": "ToolInvoked",
            "actor_did": "did:dht:z6MkBob",
            "after_timestamp": 1_700_000_000.0,
        }
        await SCP.event_log_query(scp, "ctx-filter", filter_dict)

        native.event_log_query.assert_called_once_with("ctx-filter", filter_dict)

    @pytest.mark.asyncio
    async def test_query_no_filters_passes_none(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.event_log_query.return_value = []
        scp = _make_scp(native)

        await SCP.event_log_query(scp, "ctx-no-filter")
        native.event_log_query.assert_called_once_with("ctx-no-filter", None)

    @pytest.mark.asyncio
    async def test_query_empty_result(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.event_log_query.return_value = []
        scp = _make_scp(native)

        events = await SCP.event_log_query(scp, "ctx-empty-q")
        assert events == []


class TestScpEventLogVerify:
    """Tests for :meth:`SCP.event_log_verify`."""

    @pytest.mark.asyncio
    async def test_verify_returns_proof(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.event_log_verify.return_value = SimpleNamespace(
            verified=True,
            proof_type="inclusion",
            details={"leaf_index": 0},
        )
        scp = _make_scp(native)

        proof = await SCP.event_log_verify(
            scp, "ctx-verify", {"type": "inclusion", "leaf_index": 0}
        )
        assert isinstance(proof, Proof)
        assert proof.verified is True
        assert proof.proof_type == "inclusion"

    @pytest.mark.asyncio
    async def test_verify_passes_claim_to_bridge(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.event_log_verify.return_value = SimpleNamespace(
            verified=True,
            proof_type="absence",
            details={},
        )
        scp = _make_scp(native)

        claim = {"type": "absence", "event_hash": "ff" * 32}
        await SCP.event_log_verify(scp, "ctx-claim", claim)
        native.event_log_verify.assert_called_once_with("ctx-claim", claim)


class TestScpEventLogCheckpoint:
    """Tests for :meth:`SCP.event_log_checkpoint`."""

    @pytest.mark.asyncio
    async def test_returns_signed_checkpoint(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.event_log_checkpoint.return_value = SimpleNamespace(
            context_id="ctx-signed",
            sender_did="did:dht:z6MkAlice",
            event_count=42,
            merkle_root="ab" * 32,
            epoch=3,
            timestamp=1_700_000_000,
            signature="cd" * 64,
        )
        scp = _make_scp(native)

        sc = await SCP.event_log_checkpoint(scp, "ctx-signed", "did:dht:z6MkAlice", 3)
        assert isinstance(sc, SignedCheckpoint)
        assert sc.context_id == "ctx-signed"
        assert sc.sender_did == "did:dht:z6MkAlice"
        assert sc.event_count == 42
        assert sc.merkle_root == "ab" * 32
        assert sc.epoch == 3
        assert sc.signature == "cd" * 64


# -----------------------------------------------------------------------
# Module __all__ exports
# -----------------------------------------------------------------------


class TestModuleExports:
    """Tests that the module exports the expected names."""

    def test_all_contains_expected_names(self) -> None:
        from scp_sdk.event_log import __all__

        assert "Event" in __all__
        assert "Proof" in __all__
        assert "Checkpoint" in __all__
        assert "SignedCheckpoint" in __all__

    def test_event_log_class_is_removed(self) -> None:
        """Phase 4 PR 5 (#1549) deleted :class:`EventLog`."""
        from scp_sdk import event_log

        assert not hasattr(event_log, "EventLog"), (
            "EventLog class was deleted in #1549 — use SCP.event_log_* methods instead"
        )
