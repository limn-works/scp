"""Media operations for the SCP Python SDK.

Provides functions for media session lifecycle management and WebRTC
signaling message construction and verification.

All operations delegate to the ``_scp_core`` PyO3 bridge layer.

See ADR-024 in ``.docs/adrs/phase-5.md``.
"""

from __future__ import annotations

from typing import Any

from scp_sdk.errors import ScpError


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
# Session lifecycle
# ---------------------------------------------------------------------------


def check_media_capability(
    ceiling: list[str],
    capability: str,
) -> bool:
    """Check that a media capability is present in the context ceiling.

    Args:
        ceiling: List of capability name strings from the context ceiling.
        capability: Media capability: ``"voice"``, ``"video"``, or
            ``"screen_share"``.

    Returns:
        ``True`` if the capability is in the ceiling.

    Raises:
        ValidationError: If *capability* is not a recognized value.
        ContextError: If the capability is not in the ceiling.
    """
    bridge = _bridge()
    return bridge.media_check_capability(ceiling, capability)


def initiate_session(
    context_id: str,
    ceiling: list[str],
    capabilities: list[str],
    participants: list[str],
    timestamp: int,
) -> dict[str, Any]:
    """Initiate a media session after validating capabilities against the ceiling.

    Args:
        context_id: The context hosting this media session.
        ceiling: The context's capability ceiling as a list of capability
            name strings (e.g., ``["media:voice", "messages:read"]``).
        capabilities: Media capabilities to activate (e.g.,
            ``["voice", "video"]``).
        participants: Initial participant DIDs.
        timestamp: Unix timestamp (seconds) for session creation.

    Returns:
        A dict with session fields: ``session_id``, ``context_id``,
        ``participants``, ``capabilities``, ``state``, ``started_at``.

    Raises:
        ValidationError: If any capability string is invalid.
        ContextError: If capabilities or participants are empty, or any
            capability is not in the ceiling.
    """
    bridge = _bridge()
    return dict(
        bridge.media_initiate_session(context_id, ceiling, capabilities, participants, timestamp)
    )


def activate_session(session_json: str) -> dict[str, Any]:
    """Activate a media session (transition from Initiating to Active).

    Args:
        session_json: JSON string representing the session (as returned
            by :func:`initiate_session` after ``json.dumps``).

    Returns:
        A dict with the updated session fields.

    Raises:
        ContextError: If the session is not in the ``Initiating`` state.
    """
    bridge = _bridge()
    return dict(bridge.media_activate_session(session_json))


def join_session(session_json: str, participant_did: str) -> dict[str, Any]:
    """Add a participant to a media session.

    Args:
        session_json: JSON string representing the session.
        participant_did: DID of the participant to add.

    Returns:
        A dict with the updated session fields.

    Raises:
        ContextError: If the session has ended.
    """
    bridge = _bridge()
    return dict(bridge.media_join_session(session_json, participant_did))


def end_session(
    session_json: str,
    timestamp: int,
) -> dict[str, Any]:
    """End a media session and return metadata for event log recording.

    Args:
        session_json: JSON string representing the session.
        timestamp: Unix timestamp (seconds) when the session ended.

    Returns:
        A dict with two keys: ``session`` (updated session) and
        ``metadata`` (session metadata for event log recording).

    Raises:
        ContextError: If the session has already ended or the timestamp
            is before the session start time.
    """
    bridge = _bridge()
    result = bridge.media_end_session(session_json, timestamp)
    return {
        "session": dict(result["session"]),
        "metadata": dict(result["metadata"]),
    }


# ---------------------------------------------------------------------------
# Signaling
# ---------------------------------------------------------------------------


def create_offer(
    session_id: str,
    sdp: str,
    sender_did: str,
) -> dict[str, str]:
    """Create an SDP offer signaling message.

    Args:
        session_id: The media session ID.
        sdp: Raw SDP payload string.
        sender_did: DID of the participant creating the offer.

    Returns:
        A dict with ``session_id`` and ``message`` (JSON-serialized
        signaling message).
    """
    bridge = _bridge()
    return dict(bridge.media_create_offer(session_id, sdp, sender_did))


def create_answer(
    session_id: str,
    sdp: str,
    sender_did: str,
) -> dict[str, str]:
    """Create an SDP answer signaling message.

    Args:
        session_id: The media session ID.
        sdp: Raw SDP payload string.
        sender_did: DID of the participant creating the answer.

    Returns:
        A dict with ``session_id`` and ``message`` (JSON-serialized
        signaling message).
    """
    bridge = _bridge()
    return dict(bridge.media_create_answer(session_id, sdp, sender_did))


def create_ice_candidate(
    session_id: str,
    candidate: str,
    sender_did: str,
    *,
    sdp_mid: str | None = None,
    sdp_mline_index: int | None = None,
) -> dict[str, str]:
    """Create an ICE candidate signaling message.

    Args:
        session_id: The media session ID.
        candidate: ICE candidate attribute string.
        sender_did: DID of the participant who gathered the candidate.
        sdp_mid: Optional SDP media stream identification tag.
        sdp_mline_index: Optional zero-based index of the media
            description in the SDP.

    Returns:
        A dict with ``session_id`` and ``message`` (JSON-serialized
        signaling message).
    """
    bridge = _bridge()
    return dict(
        bridge.media_create_ice_candidate(
            session_id, candidate, sender_did, sdp_mid, sdp_mline_index
        )
    )


def create_session_end(
    session_id: str,
    sender_did: str,
) -> dict[str, str]:
    """Create a session-end signaling message.

    Args:
        session_id: The media session ID.
        sender_did: DID of the participant ending the session.

    Returns:
        A dict with ``session_id`` and ``message`` (JSON-serialized
        signaling message).
    """
    bridge = _bridge()
    return dict(bridge.media_create_session_end(session_id, sender_did))


def send_signaling(signaling_json: str) -> dict[str, str]:
    """Serialize a signaling message for transport.

    Args:
        signaling_json: JSON string representing a signaling message.

    Returns:
        A dict with ``payload`` (base64-encoded bytes) and
        ``message_type`` (``"Signaling"``).

    Raises:
        ValidationError: If the JSON is not a valid signaling message.
    """
    bridge = _bridge()
    return dict(bridge.media_send_signaling(signaling_json))


def verify_sender_attribution(
    signaling_json: str,
    envelope_sender_did: str,
) -> bool:
    """Verify that the sender DID in a signaling message matches the envelope.

    Args:
        signaling_json: JSON string representing a signaling message.
        envelope_sender_did: The DID from the authenticated SCP envelope.

    Returns:
        ``True`` if the sender attribution is valid.

    Raises:
        ValidationError: If the JSON is invalid.
        ContextError: If the sender DID does not match.
    """
    bridge = _bridge()
    return bridge.media_verify_sender_attribution(signaling_json, envelope_sender_did)


__all__ = [
    "activate_session",
    "check_media_capability",
    "create_answer",
    "create_ice_candidate",
    "create_offer",
    "create_session_end",
    "end_session",
    "initiate_session",
    "join_session",
    "send_signaling",
    "verify_sender_attribution",
]
