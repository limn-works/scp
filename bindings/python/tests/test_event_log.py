"""Tests for the SCP Python SDK event log module.

Covers:
- Event, Proof, and Checkpoint dataclasses
- EventLog class (query, verify, checkpoint)
- _extract_root_hash and _extract_event_count helpers
- root_hash computation in checkpoint() (SCP-045 fix)
- Empty log, single event, and multi-event scenarios

The bridge (_scp_core) is mocked since these are unit tests that
run without the compiled Rust extension.

See ``.docs/standards/python.md`` for test naming conventions.
See ``.docs/adrs/phase-3.md`` ADR-014 for event log SDK design.
"""

from __future__ import annotations

import sys
import time
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from scp_sdk.event_log import (
    _EMPTY_ROOT_HASH,
    Checkpoint,
    Event,
    EventLog,
    Proof,
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


def _make_bridge_module(events: list[Any] | None = None) -> ModuleType:
    """Create a mock _scp_core bridge module."""
    mock_bridge = MagicMock(spec=ModuleType)
    if events is not None:
        mock_bridge.event_log_query = MagicMock(return_value=events)
    else:
        mock_bridge.event_log_query = MagicMock(return_value=[])
    mock_bridge.event_log_verify = MagicMock(
        return_value=SimpleNamespace(
            verified=True,
            proof_type="inclusion",
            details={"leaf_index": 0},
        ),
    )
    return mock_bridge


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
# EventLog class tests
# -----------------------------------------------------------------------


class TestEventLogInit:
    """Tests for EventLog construction."""

    def test_stores_context_id(self) -> None:
        log = EventLog(context_id="ctx-test-123")
        assert log.context_id == "ctx-test-123"

    def test_context_id_property_is_readonly(self) -> None:
        log = EventLog(context_id="ctx-ro")
        with pytest.raises(AttributeError):
            log.context_id = "ctx-new"  # type: ignore[misc]


class TestEventLogCheckpoint:
    """Tests for EventLog.checkpoint() -- the SCP-045 root_hash fix."""

    async def test_checkpoint_empty_log_returns_zero_root(self) -> None:
        mock_bridge = _make_bridge_module(events=[])
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}):
            log = EventLog(context_id="ctx-empty")
            cp = await log.checkpoint()

        assert cp.context_id == "ctx-empty"
        assert cp.sequence == 0
        assert cp.root_hash == _EMPTY_ROOT_HASH
        assert cp.event_count == 0
        assert isinstance(cp.timestamp, float)

    async def test_checkpoint_extracts_root_hash_from_bridge(self) -> None:
        expected_root = "deadbeef" + "0" * 56
        events = [_make_log_summary_event(event_count=5, merkle_root=expected_root, sequence=4)]
        mock_bridge = _make_bridge_module(events=events)
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}):
            log = EventLog(context_id="ctx-with-events")
            cp = await log.checkpoint()

        assert cp.root_hash == expected_root
        assert cp.event_count == 5
        assert cp.sequence == 4
        assert cp.context_id == "ctx-with-events"

    async def test_checkpoint_root_hash_is_valid_hex_string(self) -> None:
        root = "abcdef01" * 8
        events = [_make_log_summary_event(event_count=3, merkle_root=root, sequence=2)]
        mock_bridge = _make_bridge_module(events=events)
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}):
            log = EventLog(context_id="ctx-hex")
            cp = await log.checkpoint()

        assert len(cp.root_hash) == 64
        int(cp.root_hash, 16)

    async def test_checkpoint_timestamp_is_recent(self) -> None:
        events = [_make_log_summary_event()]
        mock_bridge = _make_bridge_module(events=events)
        before = time.time()
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}):
            log = EventLog(context_id="ctx-ts")
            cp = await log.checkpoint()
        after = time.time()

        assert before <= cp.timestamp <= after

    async def test_checkpoint_calls_bridge_with_correct_context(self) -> None:
        events = [_make_log_summary_event()]
        mock_bridge = _make_bridge_module(events=events)
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}):
            log = EventLog(context_id="ctx-call-check")
            await log.checkpoint()

        mock_bridge.event_log_query.assert_called_once_with("ctx-call-check", None)

    async def test_checkpoint_with_fallback_when_no_merkle_root_in_payload(self) -> None:
        events = [_make_mock_event(payload={"event_count": 3}, sequence=2)]
        mock_bridge = _make_bridge_module(events=events)
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}):
            log = EventLog(context_id="ctx-no-root")
            cp = await log.checkpoint()

        assert cp.root_hash == _EMPTY_ROOT_HASH
        assert cp.event_count == 3

    async def test_checkpoint_with_fallback_when_no_event_count_in_payload(self) -> None:
        root = "ff" * 32
        events = [_make_mock_event(payload={"merkle_root": root}, sequence=0)]
        mock_bridge = _make_bridge_module(events=events)
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}):
            log = EventLog(context_id="ctx-no-count")
            cp = await log.checkpoint()

        assert cp.root_hash == root
        assert cp.event_count == 1

    async def test_checkpoint_root_hash_not_empty_string(self) -> None:
        """Regression: SCP-045 stub returned root_hash='' -- must never happen."""
        events = [_make_log_summary_event()]
        mock_bridge = _make_bridge_module(events=events)
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}):
            log = EventLog(context_id="ctx-regression")
            cp = await log.checkpoint()

        assert cp.root_hash != ""
        assert len(cp.root_hash) == 64

    async def test_checkpoint_empty_log_root_hash_not_empty_string(self) -> None:
        """Regression: even empty logs must return the sentinel, not ''."""
        mock_bridge = _make_bridge_module(events=[])
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}):
            log = EventLog(context_id="ctx-empty-regression")
            cp = await log.checkpoint()

        assert cp.root_hash != ""
        assert cp.root_hash == "0" * 64

    async def test_checkpoint_matches_rfc6962_sentinel_for_empty_log(self) -> None:
        """The empty-tree root is [0u8; 32] hex-encoded = 64 zero chars.

        This matches the Rust scp-core tree::root() for an empty EventLog.
        """
        mock_bridge = _make_bridge_module(events=[])
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}):
            log = EventLog(context_id="ctx-rfc")
            cp = await log.checkpoint()

        expected_empty_root_hex = "00" * 32
        assert cp.root_hash == expected_empty_root_hex


class TestEventLogQuery:
    """Tests for EventLog.query()."""

    async def test_query_returns_event_list(self) -> None:
        raw_events = [
            _make_mock_event(
                event_type="MessageSent",
                actor_did="did:dht:z6MkAlice",
                timestamp=1_700_000_000.0,
                payload={"text": "hello"},
                sequence=0,
            ),
        ]
        mock_bridge = _make_bridge_module()
        mock_bridge.event_log_query.return_value = raw_events
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}):
            log = EventLog(context_id="ctx-query")
            events = await log.query()

        assert len(events) == 1
        assert isinstance(events[0], Event)
        assert events[0].event_type == "MessageSent"
        assert events[0].actor_did == "did:dht:z6MkAlice"

    async def test_query_passes_filters(self) -> None:
        mock_bridge = _make_bridge_module()
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}):
            log = EventLog(context_id="ctx-filter")
            await log.query(
                event_type="ToolInvoked",
                actor="did:dht:z6MkBob",
                since=1_700_000_000.0,
            )

        call_args = mock_bridge.event_log_query.call_args
        filter_dict = call_args[0][1]
        assert filter_dict["event_type"] == "ToolInvoked"
        assert filter_dict["actor_did"] == "did:dht:z6MkBob"
        assert filter_dict["after_timestamp"] == 1_700_000_000.0

    async def test_query_no_filters_passes_none(self) -> None:
        mock_bridge = _make_bridge_module()
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}):
            log = EventLog(context_id="ctx-no-filter")
            await log.query()

        mock_bridge.event_log_query.assert_called_once_with("ctx-no-filter", None)

    async def test_query_empty_result(self) -> None:
        mock_bridge = _make_bridge_module(events=[])
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}):
            log = EventLog(context_id="ctx-empty-q")
            events = await log.query()

        assert events == []


class TestEventLogVerify:
    """Tests for EventLog.verify()."""

    async def test_verify_returns_proof(self) -> None:
        mock_bridge = _make_bridge_module()
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}):
            log = EventLog(context_id="ctx-verify")
            proof = await log.verify({"type": "inclusion", "leaf_index": 0})

        assert isinstance(proof, Proof)
        assert proof.verified is True
        assert proof.proof_type == "inclusion"

    async def test_verify_passes_claim_to_bridge(self) -> None:
        mock_bridge = _make_bridge_module()
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}):
            log = EventLog(context_id="ctx-claim")
            claim = {"type": "absence", "event_hash": "ff" * 32}
            await log.verify(claim)

        mock_bridge.event_log_verify.assert_called_once_with("ctx-claim", claim)


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
        assert "EventLog" in __all__
