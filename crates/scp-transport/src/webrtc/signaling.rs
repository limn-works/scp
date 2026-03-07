//! WebRTC signaling types for SCP.
//!
//! WebRTC requires a signaling channel to exchange SDP offers/answers and
//! ICE candidates before a peer connection can be established. In SCP, the
//! signaling channel is the native relay transport -- SDP messages flow as
//! standard SCP messages through an existing context.
//!
//! This module defines the signaling message types. The actual signaling
//! transport is pluggable via the [`SignalingChannel`] trait.

use serde::{Deserialize, Serialize};

/// A WebRTC signaling message exchanged during connection setup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignalingMessage {
    /// SDP offer from the initiating peer.
    Offer {
        /// The SDP offer string.
        sdp: String,
    },
    /// SDP answer from the receiving peer.
    Answer {
        /// The SDP answer string.
        sdp: String,
    },
    /// ICE candidate discovered during connectivity checks.
    IceCandidate {
        /// The ICE candidate string.
        candidate: String,
        /// The SDP media description index.
        sdp_m_line_index: u32,
        /// The SDP mid attribute.
        sdp_mid: Option<String>,
    },
}

/// Trait for WebRTC signaling channel implementations.
///
/// The signaling channel exchanges SDP offers/answers and ICE candidates
/// between peers. In SCP, this is typically the native relay transport
/// carrying signaling messages through an existing context.
pub trait SignalingChannel: Send + Sync {
    /// Send a signaling message to the remote peer.
    fn send_signal(
        &self,
        message: SignalingMessage,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), crate::error::TransportError>> + Send + '_>,
    >;

    /// Receive the next signaling message from the remote peer.
    fn recv_signal(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<SignalingMessage, crate::error::TransportError>>
                + Send
                + '_,
        >,
    >;
}

/// Configuration for ICE servers (STUN/TURN).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceServerConfig {
    /// ICE server URLs (e.g., `stun:stun.l.google.com:19302`,
    /// `turn:turn.example.com:3478`).
    pub urls: Vec<String>,
    /// Username for TURN authentication (not needed for STUN).
    pub username: Option<String>,
    /// Credential for TURN authentication.
    pub credential: Option<String>,
}

impl IceServerConfig {
    /// Create a STUN-only ICE server configuration.
    #[must_use]
    pub fn stun(url: String) -> Self {
        Self {
            urls: vec![url],
            username: None,
            credential: None,
        }
    }

    /// Create a TURN ICE server configuration with credentials.
    #[must_use]
    pub fn turn(url: String, username: String, credential: String) -> Self {
        Self {
            urls: vec![url],
            username: Some(username),
            credential: Some(credential),
        }
    }
}

/// State of an ICE connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceConnectionState {
    /// Initial state, no connectivity checks started.
    New,
    /// ICE agent is checking candidate pairs.
    Checking,
    /// At least one candidate pair has succeeded.
    Connected,
    /// ICE checks have completed and a final pair selected.
    Completed,
    /// All candidate pairs have failed.
    Failed,
    /// The connection was closed.
    Closed,
    /// The connection was lost and is being re-established.
    Disconnected,
}

/// State of a WebRTC data channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataChannelState {
    /// Channel is being set up.
    Connecting,
    /// Channel is open and ready for data transfer.
    Open,
    /// Channel is shutting down.
    Closing,
    /// Channel is fully closed.
    Closed,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn stun_config_has_no_credentials() {
        let config = IceServerConfig::stun("stun:stun.l.google.com:19302".to_owned());
        assert_eq!(config.urls.len(), 1);
        assert!(config.username.is_none());
        assert!(config.credential.is_none());
    }

    #[test]
    fn turn_config_has_credentials() {
        let config = IceServerConfig::turn(
            "turn:turn.example.com:3478".to_owned(),
            "user".to_owned(),
            "pass".to_owned(),
        );
        assert_eq!(config.urls.len(), 1);
        assert_eq!(config.username.as_deref(), Some("user"));
        assert_eq!(config.credential.as_deref(), Some("pass"));
    }

    #[test]
    fn signaling_message_serialization_roundtrip() {
        let offer = SignalingMessage::Offer {
            sdp: "v=0\r\n...".to_owned(),
        };
        let json = serde_json::to_string(&offer).unwrap();
        let parsed: SignalingMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            SignalingMessage::Offer { sdp } => assert_eq!(sdp, "v=0\r\n..."),
            other => panic!("expected Offer, got {other:?}"),
        }
    }

    #[test]
    fn ice_candidate_serialization() {
        let candidate = SignalingMessage::IceCandidate {
            candidate: "candidate:1 1 udp 2122260223 10.0.0.1 12345 typ host".to_owned(),
            sdp_m_line_index: 0,
            sdp_mid: Some("0".to_owned()),
        };
        let json = serde_json::to_string(&candidate).unwrap();
        assert!(json.contains("candidate:"));
        let parsed: SignalingMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            SignalingMessage::IceCandidate {
                sdp_m_line_index,
                sdp_mid,
                ..
            } => {
                assert_eq!(sdp_m_line_index, 0);
                assert_eq!(sdp_mid.as_deref(), Some("0"));
            }
            other => panic!("expected IceCandidate, got {other:?}"),
        }
    }
}
