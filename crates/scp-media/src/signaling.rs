//! WebRTC signaling types transported over SCP.
//!
//! Signaling messages (SDP offers/answers, ICE candidates) flow as standard
//! SCP encrypted governed messages. They are subject to the same capability
//! checks, authentication, and event-log recording as any other context
//! action. Actual media frames never touch SCP relays.
//!
//! See ADR-024 in `.docs/adrs/phase-5.md`.

use serde::{Deserialize, Serialize};

use scp_core::identity::DID;

/// Errors from signaling operations.
#[derive(Debug, thiserror::Error)]
pub enum SignalingError {
    /// The sender DID in the signaling message does not match the envelope
    /// sender DID. This indicates either a bug or a spoofing attempt.
    #[error("sender mismatch: message claims sender {claimed} but envelope sender is {envelope}")]
    SenderMismatch {
        /// The sender DID claimed in the signaling message body.
        claimed: String,
        /// The sender DID from the authenticated SCP envelope.
        envelope: String,
    },
}

/// A WebRTC signaling message exchanged through SCP.
///
/// These messages are encrypted and governed by the context. They enable
/// WebRTC session negotiation without requiring a separate signaling
/// channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignalingMessage {
    /// SDP offer initiating or updating a media session.
    Offer(SessionDescription),

    /// SDP answer accepting a media session offer.
    Answer(SessionDescription),

    /// ICE candidate for connectivity establishment.
    IceCandidate(Candidate),

    /// Graceful session teardown request.
    SessionEnd,
}

/// An SDP session description with sender attribution.
///
/// Wraps a raw SDP string together with the DID of the participant who
/// generated it. This attribution is verifiable through SCP message
/// authentication.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionDescription {
    /// Raw SDP (Session Description Protocol) payload.
    pub sdp: String,

    /// DID of the participant who generated this description.
    pub sender_did: DID,
}

/// An ICE candidate for WebRTC connectivity checks.
///
/// Carries the candidate string, optional SDP association fields, and
/// the DID of the participant who gathered the candidate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Candidate {
    /// ICE candidate attribute string.
    pub candidate: String,

    /// SDP media stream identification tag, if applicable.
    pub sdp_mid: Option<String>,

    /// Zero-based index of the media description in the SDP, if applicable.
    pub sdp_mline_index: Option<u16>,

    /// DID of the participant who gathered this candidate.
    pub sender_did: DID,
}

/// A session identifier for correlating signaling messages.
pub type SessionId = String;

/// Creates an SDP offer signaling message.
#[must_use]
pub fn create_offer(
    session_id: &str,
    sdp: String,
    sender_did: DID,
) -> (SessionId, SignalingMessage) {
    (
        session_id.to_owned(),
        SignalingMessage::Offer(SessionDescription { sdp, sender_did }),
    )
}

/// Creates an SDP answer signaling message.
#[must_use]
pub fn create_answer(
    session_id: &str,
    sdp: String,
    sender_did: DID,
) -> (SessionId, SignalingMessage) {
    (
        session_id.to_owned(),
        SignalingMessage::Answer(SessionDescription { sdp, sender_did }),
    )
}

/// Creates an ICE candidate signaling message.
#[must_use]
pub fn create_ice_candidate(
    session_id: &str,
    candidate: String,
    sdp_mid: Option<String>,
    sdp_mline_index: Option<u16>,
    sender_did: DID,
) -> (SessionId, SignalingMessage) {
    (
        session_id.to_owned(),
        SignalingMessage::IceCandidate(Candidate {
            candidate,
            sdp_mid,
            sdp_mline_index,
            sender_did,
        }),
    )
}

/// Serializes a signaling message to JSON bytes for transport.
///
/// # Errors
///
/// Returns an error if JSON serialization fails.
pub fn serialize_signaling(msg: &SignalingMessage) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(msg)
}

/// Deserializes a signaling message from JSON bytes.
///
/// # Errors
///
/// Returns an error if JSON deserialization fails.
pub fn deserialize_signaling(bytes: &[u8]) -> Result<SignalingMessage, serde_json::Error> {
    serde_json::from_slice(bytes)
}

/// Verifies that the sender DID claimed in a signaling message matches the
/// authenticated envelope sender.
///
/// Signaling messages contain a self-asserted `sender_did` field. This
/// function checks that the claimed sender matches the DID from the
/// authenticated SCP envelope (which is cryptographically verified via MLS
/// group membership). Any mismatch indicates either a bug or a spoofing
/// attempt and must be rejected.
///
/// `SessionEnd` messages carry no sender DID and always pass verification.
///
/// # Arguments
///
/// * `msg` - The deserialized signaling message to verify.
/// * `envelope_sender_did` - The DID from the authenticated SCP envelope.
///
/// # Errors
///
/// Returns [`SignalingError::SenderMismatch`] if the claimed sender DID
/// does not match the envelope sender.
pub fn verify_sender_attribution(
    msg: &SignalingMessage,
    envelope_sender_did: &str,
) -> Result<(), SignalingError> {
    let claimed = match msg {
        SignalingMessage::Offer(desc) => &desc.sender_did,
        SignalingMessage::Answer(desc) => &desc.sender_did,
        SignalingMessage::IceCandidate(c) => &c.sender_did,
        // SessionEnd carries no sender DID -- nothing to verify.
        SignalingMessage::SessionEnd => return Ok(()),
    };

    if claimed != envelope_sender_did {
        return Err(SignalingError::SenderMismatch {
            claimed: claimed.to_string(),
            envelope: envelope_sender_did.to_owned(),
        });
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn create_offer_returns_session_id_and_message() {
        let (sid, msg) = create_offer("sess-1", "v=0\r\n".into(), "did:dht:zAlice".into());
        assert_eq!(sid, "sess-1");
        match msg {
            SignalingMessage::Offer(desc) => {
                assert_eq!(desc.sdp, "v=0\r\n");
                assert_eq!(desc.sender_did, "did:dht:zAlice");
            }
            _ => panic!("expected Offer"),
        }
    }

    #[test]
    fn create_answer_returns_session_id_and_message() {
        let (sid, msg) = create_answer("sess-2", "v=0\r\n".into(), "did:dht:zBob".into());
        assert_eq!(sid, "sess-2");
        match msg {
            SignalingMessage::Answer(desc) => {
                assert_eq!(desc.sdp, "v=0\r\n");
                assert_eq!(desc.sender_did, "did:dht:zBob");
            }
            _ => panic!("expected Answer"),
        }
    }

    #[test]
    fn create_ice_candidate_with_all_fields() {
        let (sid, msg) = create_ice_candidate(
            "sess-3",
            "candidate:1 1 UDP 2130706431 10.0.0.1 5000 typ host".to_owned(),
            Some("audio".to_owned()),
            Some(0),
            "did:dht:zAlice".into(),
        );
        assert_eq!(sid, "sess-3");
        match msg {
            SignalingMessage::IceCandidate(c) => {
                assert!(c.candidate.contains("candidate:1"));
                assert_eq!(c.sdp_mid, Some("audio".to_owned()));
                assert_eq!(c.sdp_mline_index, Some(0));
                assert_eq!(c.sender_did, "did:dht:zAlice");
            }
            _ => panic!("expected IceCandidate"),
        }
    }

    #[test]
    fn create_ice_candidate_without_optional_fields() {
        let (_, msg) = create_ice_candidate(
            "sess-4",
            "candidate:2 1 UDP 1694498815 192.168.1.1 6000 typ srflx".to_owned(),
            None,
            None,
            "did:dht:zBob".into(),
        );
        match msg {
            SignalingMessage::IceCandidate(c) => {
                assert!(c.sdp_mid.is_none());
                assert!(c.sdp_mline_index.is_none());
            }
            _ => panic!("expected IceCandidate"),
        }
    }

    #[test]
    fn serialize_deserialize_offer_roundtrip() {
        let (_, msg) = create_offer(
            "s1",
            "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\n".to_owned(),
            "did:dht:z1".into(),
        );
        let bytes = serialize_signaling(&msg).unwrap();
        let restored = deserialize_signaling(&bytes).unwrap();
        match (&msg, &restored) {
            (SignalingMessage::Offer(a), SignalingMessage::Offer(b)) => {
                assert_eq!(a.sdp, b.sdp);
                assert_eq!(a.sender_did, b.sender_did);
            }
            _ => panic!("roundtrip mismatch"),
        }
    }

    #[test]
    fn serialize_deserialize_ice_roundtrip() {
        let (_, msg) = create_ice_candidate(
            "s2",
            "candidate:1".to_owned(),
            Some("video".to_owned()),
            Some(1),
            "did:dht:z2".into(),
        );
        let bytes = serialize_signaling(&msg).unwrap();
        let restored = deserialize_signaling(&bytes).unwrap();
        match (&msg, &restored) {
            (SignalingMessage::IceCandidate(a), SignalingMessage::IceCandidate(b)) => {
                assert_eq!(a, b);
            }
            _ => panic!("roundtrip mismatch"),
        }
    }

    #[test]
    fn serialize_session_end() {
        let msg = SignalingMessage::SessionEnd;
        let bytes = serialize_signaling(&msg).unwrap();
        let restored = deserialize_signaling(&bytes).unwrap();
        assert!(matches!(restored, SignalingMessage::SessionEnd));
    }

    #[test]
    fn deserialize_invalid_json_fails() {
        let result = deserialize_signaling(b"not json");
        assert!(result.is_err());
    }

    // -- verify_sender_attribution ------------------------------------------

    #[test]
    fn verify_sender_attribution_passes_for_matching_offer() {
        let (_, msg) = create_offer("s1", "v=0\r\n".into(), "did:dht:zAlice".into());
        let result = verify_sender_attribution(&msg, "did:dht:zAlice");
        assert!(result.is_ok());
    }

    #[test]
    fn verify_sender_attribution_passes_for_matching_answer() {
        let (_, msg) = create_answer("s1", "v=0\r\n".into(), "did:dht:zBob".into());
        let result = verify_sender_attribution(&msg, "did:dht:zBob");
        assert!(result.is_ok());
    }

    #[test]
    fn verify_sender_attribution_passes_for_matching_ice_candidate() {
        let (_, msg) = create_ice_candidate(
            "s1",
            "candidate:1".to_owned(),
            None,
            None,
            "did:dht:zAlice".into(),
        );
        let result = verify_sender_attribution(&msg, "did:dht:zAlice");
        assert!(result.is_ok());
    }

    #[test]
    fn verify_sender_attribution_passes_for_session_end() {
        let msg = SignalingMessage::SessionEnd;
        // SessionEnd has no sender_did -- should always pass.
        let result = verify_sender_attribution(&msg, "did:dht:zAnyone");
        assert!(result.is_ok());
    }

    #[test]
    fn verify_sender_attribution_fails_for_mismatched_offer() {
        let (_, msg) = create_offer("s1", "v=0\r\n".into(), "did:dht:zAlice".into());
        let result = verify_sender_attribution(&msg, "did:dht:zEve");
        assert!(result.is_err());

        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("did:dht:zAlice"),
            "error should contain claimed DID"
        );
        assert!(
            msg.contains("did:dht:zEve"),
            "error should contain envelope DID"
        );
    }

    #[test]
    fn verify_sender_attribution_fails_for_mismatched_answer() {
        let (_, msg) = create_answer("s1", "v=0\r\n".into(), "did:dht:zBob".into());
        let result = verify_sender_attribution(&msg, "did:dht:zMallory");
        assert!(result.is_err());
    }

    #[test]
    fn verify_sender_attribution_fails_for_mismatched_ice_candidate() {
        let (_, msg) = create_ice_candidate(
            "s1",
            "candidate:1".to_owned(),
            None,
            None,
            "did:dht:zAlice".into(),
        );
        let result = verify_sender_attribution(&msg, "did:dht:zEve");
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(err, SignalingError::SenderMismatch { .. }));
    }
}
