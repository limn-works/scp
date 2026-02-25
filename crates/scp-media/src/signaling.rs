//! WebRTC signaling types transported over SCP.
//!
//! Signaling messages (SDP offers/answers, ICE candidates) flow as standard
//! SCP encrypted governed messages. They are subject to the same capability
//! checks, authentication, and event-log recording as any other context
//! action. Actual media frames never touch SCP relays.
//!
//! See ADR-024 in `.docs/adrs/phase-5.md`.

use serde::{Deserialize, Serialize};

/// A DID string (e.g., `"did:dht:z6Mk..."`).
///
/// Represented as a plain `String`. Matches the type alias pattern used
/// across `scp-core` modules.
pub type DID = String;

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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
