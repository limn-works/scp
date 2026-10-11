//! WebRTC signaling and data channel abstraction types for SCP.
//!
//! WebRTC requires a signaling channel to exchange SDP offers/answers and
//! ICE candidates before a peer connection can be established. In SCP, the
//! signaling channel is the native relay transport -- SDP messages flow as
//! standard SCP messages through an existing context.
//!
//! The [`DataChannelProvider`] trait abstracts the platform-specific WebRTC
//! data channel implementation. Platform code (webrtc-rs, `web_sys`, etc.)
//! implements this trait; the adapter orchestrates SCP message framing over
//! whatever data channel implementation is provided.

use std::pin::Pin;

use serde::{Deserialize, Serialize};

use crate::error::TransportError;

/// A heap-allocated future that borrows its receiver for `'a` and resolves to `T`.
///
/// Both traits in this module return this shape because platform code stores
/// them behind `dyn`, and a trait that declares `async fn` is not
/// dyn-compatible.
type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

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
    fn send_signal(&self, message: SignalingMessage) -> BoxFuture<'_, Result<(), TransportError>>;

    /// Receive the next signaling message from the remote peer.
    fn recv_signal(&self) -> BoxFuture<'_, Result<SignalingMessage, TransportError>>;
}

/// Trait for WebRTC data channel implementations.
///
/// Platform code implements this trait to provide the actual data channel
/// transport. The adapter uses this trait to send and receive binary
/// messages over WebRTC data channels. Each instance represents a single
/// data channel identified by a label (the routing ID hex).
///
/// # Implementors
///
/// - Native platforms: `webrtc-rs` crate wrapping `RTCDataChannel`
/// - WASM: `web_sys::RtcDataChannel`
/// - Testing: in-memory mock (see tests)
pub trait DataChannelProvider: Send + Sync {
    /// Open or create a data channel with the given label.
    ///
    /// If the channel already exists, this should return successfully.
    /// The label is the hex-encoded routing ID.
    fn open_channel(&self, label: &str) -> BoxFuture<'_, Result<(), TransportError>>;

    /// Send binary data on the channel with the given label.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::SendFailed`] if the channel does not exist
    /// or the send operation fails.
    /// Returns [`TransportError::PayloadTooLarge`] if the data exceeds the
    /// maximum message size.
    fn send_data(&self, label: &str, data: Vec<u8>) -> BoxFuture<'_, Result<(), TransportError>>;

    /// Receive the next binary message from the channel with the given label.
    ///
    /// Returns `None` if the channel is closed.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if the channel does not exist.
    fn recv_data(&self, label: &str) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>>;

    /// Close the data channel with the given label.
    ///
    /// If the channel does not exist, this should return successfully.
    fn close_channel(&self, label: &str) -> BoxFuture<'_, Result<(), TransportError>>;

    /// Check whether a channel with the given label is open.
    fn is_channel_open(&self, label: &str) -> BoxFuture<'_, bool>;
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
