//! [`WebRtcAdapter`] -- implements [`TransportAdapter`] for peer-to-peer
//! communication via WebRTC data channels per spec section 10.5.2.
//!
//! SCP operations map to WebRTC primitives:
//!
//! | Transport method | WebRTC primitive | Details |
//! |------------------|------------------|---------|
//! | `send` | `DataChannel` send | Binary on channel labeled `hex(routing_id)` |
//! | `subscribe` | `DataChannel` open | Open/accept with label `hex(routing_id)` |
//! | `unsubscribe` | `DataChannel` close | Close the data channel |
//! | `query` | Request/response | Application-level over `DataChannel` |
//! | `delete` | Not applicable | P2P, no central store |
//!
//! # Architecture
//!
//! The adapter orchestrates SCP message framing over a pluggable
//! [`DataChannelProvider`]. Platform code implements the provider trait
//! with the actual WebRTC stack (webrtc-rs, web_sys, etc.). The adapter
//! handles serialization, routing, and the `TransportAdapter` contract.
//!
//! # Connection Model
//!
//! Peer-to-peer via ICE (STUN/TURN). Signaling uses an external channel
//! (typically the SCP native relay) to exchange SDP offers/answers and ICE
//! candidates. DTLS encryption over SCTP for data channels.
//!
//! See `.docs/specs/10-infrastructure-and-self-hosting.md` section 10.5.2.

use std::pin::Pin;
use std::sync::Arc;

use scp_core::envelope::OuterEnvelope;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use super::signaling::{
    DataChannelProvider, IceConnectionState, IceServerConfig, SignalingChannel, SignalingMessage,
};
use crate::error::TransportError;
use crate::traits::{BlobId, RoutingId, SubscriptionStream, TransportAdapter, TransportEvent};

/// A boxed, pinned, `Send`-safe future -- the return type for all
/// [`TransportAdapter`] methods to ensure the trait is dyn-compatible.
type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Configuration for the WebRTC transport adapter.
#[derive(Debug, Clone)]
pub struct WebRtcConfig {
    /// ICE server configurations for STUN/TURN.
    pub ice_servers: Vec<IceServerConfig>,
    /// Maximum message size for data channels (bytes).
    /// WebRTC data channels have a default max of 256 KiB for SCTP messages.
    pub max_message_size: usize,
    /// ICE connection timeout in seconds.
    pub ice_timeout_secs: u64,
}

impl Default for WebRtcConfig {
    fn default() -> Self {
        Self {
            ice_servers: vec![IceServerConfig::stun(
                "stun:stun.l.google.com:19302".to_owned(),
            )],
            max_message_size: 262_144, // 256 KiB
            ice_timeout_secs: 30,
        }
    }
}

/// Peer connection state tracked by the adapter.
struct PeerConnectionState {
    /// ICE connection state.
    ice_state: IceConnectionState,
}

/// Transport adapter for WebRTC data channels.
///
/// Implements [`TransportAdapter`] by mapping SCP operations to WebRTC data
/// channel operations via an injected [`DataChannelProvider`]. The adapter
/// handles SCP message framing (MessagePack serialization) and delegates
/// actual data transport to the provider.
///
/// # Lifecycle
///
/// 1. Create adapter with [`WebRtcConfig`], a [`SignalingChannel`], and a
///    [`DataChannelProvider`].
/// 2. The first `send` or `subscribe` triggers ICE connectivity checks
///    via the signaling channel.
/// 3. Data channels are created per routing ID via the provider.
/// 4. `delete` returns [`TransportError::NotSupported`] -- P2P has no central store.
///
/// # Thread Safety
///
/// The adapter is `Send + Sync` and can be shared across tasks. Internal
/// state is protected by async mutexes.
pub struct WebRtcAdapter {
    config: WebRtcConfig,
    signaling: Arc<dyn SignalingChannel>,
    provider: Arc<dyn DataChannelProvider>,
    peer: Arc<Mutex<Option<PeerConnectionState>>>,
}

impl WebRtcAdapter {
    /// Create a new WebRTC adapter with the given configuration, signaling
    /// channel, and data channel provider.
    ///
    /// The adapter does not initiate a connection immediately -- the first
    /// transport operation triggers ICE connectivity checks.
    pub fn new(
        config: WebRtcConfig,
        signaling: Arc<dyn SignalingChannel>,
        provider: Arc<dyn DataChannelProvider>,
    ) -> Self {
        Self {
            config,
            signaling,
            provider,
            peer: Arc::new(Mutex::new(None)),
        }
    }

    /// Ensure a peer connection is established.
    ///
    /// Actual SDP negotiation and ICE connectivity are delegated to the
    /// [`DataChannelProvider`] implementation, which owns the platform WebRTC
    /// stack. This method uses [`DataChannelProvider::open_channel`] with a
    /// control label as a connectivity probe, then records peer state.
    ///
    /// On the first call the adapter also exchanges signaling messages with
    /// the remote peer via the [`SignalingChannel`] so that both sides are
    /// aware of the connection intent.
    async fn ensure_connected(&self) -> Result<(), TransportError> {
        let mut peer_guard = self.peer.lock().await;
        if peer_guard.is_some() {
            return Ok(());
        }

        debug!("initiating WebRTC peer connection");

        let timeout = std::time::Duration::from_secs(self.config.ice_timeout_secs);

        // Notify the remote peer via signaling that we want to connect.
        let offer_sdp = create_sdp_offer(&self.config);
        self.signaling
            .send_signal(SignalingMessage::Offer {
                sdp: offer_sdp.clone(),
            })
            .await
            .map_err(|e| {
                TransportError::ConnectionFailed(format!("failed to send SDP offer: {e}"))
            })?;

        // Wait for SDP answer.
        let answer_result = tokio::time::timeout(timeout, self.signaling.recv_signal()).await;
        let answer_sdp = match answer_result {
            Ok(Ok(SignalingMessage::Answer { sdp })) => sdp,
            Ok(Ok(other)) => {
                return Err(TransportError::ProtocolError(format!(
                    "expected SDP answer, got {other:?}"
                )));
            }
            Ok(Err(e)) => {
                return Err(TransportError::ConnectionFailed(format!(
                    "signaling error waiting for answer: {e}"
                )));
            }
            Err(_) => {
                return Err(TransportError::Timeout);
            }
        };

        debug!(
            offer_len = offer_sdp.len(),
            answer_len = answer_sdp.len(),
            "signaling exchange complete"
        );

        // Use the provider's open_channel as a connectivity probe.
        self.provider
            .open_channel("__scp_control")
            .await
            .map_err(|e| {
                TransportError::ConnectionFailed(format!(
                    "data channel provider connectivity check failed: {e}"
                ))
            })?;

        *peer_guard = Some(PeerConnectionState {
            ice_state: IceConnectionState::Connected,
        });

        Ok(())
    }

    /// Check that the peer connection is in a usable ICE state.
    async fn check_ice_state(&self) -> Result<(), TransportError> {
        let peer_guard = self.peer.lock().await;
        let peer = peer_guard.as_ref().ok_or(TransportError::NotConnected)?;

        match peer.ice_state {
            IceConnectionState::Connected | IceConnectionState::Completed => Ok(()),
            _ => Err(TransportError::NotConnected),
        }
    }
}

impl TransportAdapter for WebRtcAdapter {
    fn send(&self, envelope: &OuterEnvelope) -> BoxFuture<'_, Result<BlobId, TransportError>> {
        let wire_result = rmp_serde::to_vec_named(envelope)
            .map_err(|e| TransportError::SendFailed(format!("envelope serialization failed: {e}")));
        let routing_id_hex = hex::encode(&envelope.routing_id);

        Box::pin(async move {
            let wire_bytes = wire_result?;
            let blob_id = BlobId::from_sha256(&wire_bytes);

            self.ensure_connected().await?;
            self.check_ice_state().await?;

            // Check message size.
            if wire_bytes.len() > self.config.max_message_size {
                return Err(TransportError::PayloadTooLarge(format!(
                    "envelope size {} exceeds WebRTC max message size {}",
                    wire_bytes.len(),
                    self.config.max_message_size
                )));
            }

            // Ensure the data channel is open.
            self.provider.open_channel(&routing_id_hex).await?;

            // Send via the data channel provider.
            self.provider.send_data(&routing_id_hex, wire_bytes).await?;

            debug!(
                routing_id = %routing_id_hex,
                blob_id = %hex::encode(blob_id.as_bytes()),
                "sent envelope via WebRTC data channel"
            );

            Ok(blob_id)
        })
    }

    fn subscribe(
        &self,
        routing_id: &RoutingId,
        _since: Option<u64>,
    ) -> BoxFuture<'_, Result<SubscriptionStream, TransportError>> {
        let routing_id_hex = hex::encode(routing_id.as_bytes());

        // Note: `since` is ignored for WebRTC -- P2P has no durable storage.
        // Only live messages are delivered.

        Box::pin(async move {
            self.ensure_connected().await?;
            self.check_ice_state().await?;

            // Ensure the data channel is open.
            self.provider.open_channel(&routing_id_hex).await?;

            let provider = Arc::clone(&self.provider);
            let label = routing_id_hex.clone();

            // Convert the data channel into a TransportEvent stream.
            let stream = futures::stream::unfold(
                (provider, label, false),
                |(provider, label, terminated)| async move {
                    if terminated {
                        return None;
                    }

                    match provider.recv_data(&label).await {
                        Ok(Some(raw_bytes)) => {
                            let event = match rmp_serde::from_slice::<OuterEnvelope>(&raw_bytes) {
                                Ok(envelope) => TransportEvent::Envelope(envelope),
                                Err(e) => {
                                    warn!(error = %e, "failed to deserialize envelope from WebRTC data channel");
                                    TransportEvent::Error(TransportError::ProtocolError(format!(
                                        "invalid MessagePack in data channel message: {e}"
                                    )))
                                }
                            };
                            Some((event, (provider, label, false)))
                        }
                        Ok(None) => {
                            // Channel closed.
                            Some((
                                TransportEvent::Terminated {
                                    reason: "WebRTC data channel closed".to_owned(),
                                },
                                (provider, label, true),
                            ))
                        }
                        Err(e) => {
                            warn!(error = %e, "WebRTC data channel recv error");
                            Some((TransportEvent::Error(e), (provider, label, false)))
                        }
                    }
                },
            );

            debug!(
                routing_id = %routing_id_hex,
                "subscribed to WebRTC data channel"
            );

            Ok(Box::pin(stream) as SubscriptionStream)
        })
    }

    fn unsubscribe(&self, routing_id: &RoutingId) -> BoxFuture<'_, Result<(), TransportError>> {
        let routing_id_hex = hex::encode(routing_id.as_bytes());

        Box::pin(async move {
            self.provider.close_channel(&routing_id_hex).await?;

            debug!(
                routing_id = %routing_id_hex,
                "closed WebRTC data channel"
            );

            Ok(())
        })
    }

    fn query(
        &self,
        _routing_id: &RoutingId,
        _since: Option<u64>,
    ) -> BoxFuture<'_, Result<Vec<OuterEnvelope>, TransportError>> {
        // WebRTC is P2P with no durable storage. Query returns empty results.
        // Per spec section 10.5.2: "Request/response over DataChannel
        // (application-level, no native query)."
        // The caller should use subscribe() for live message delivery.

        Box::pin(async move {
            self.ensure_connected().await?;

            debug!("WebRTC query returns empty -- P2P has no durable storage");
            Ok(Vec::new())
        })
    }

    fn delete(&self, _blob_id: &BlobId) -> BoxFuture<'_, Result<(), TransportError>> {
        // Per spec section 10.5.2: "Not applicable (P2P, no central store)."
        Box::pin(async move {
            Err(TransportError::NotSupported(
                "WebRTC is P2P with no central store -- delete is not applicable".to_owned(),
            ))
        })
    }
}

/// Create a signaling SDP offer template.
///
/// This is **not** a real SDP offer for WebRTC media negotiation -- actual SDP
/// generation and ICE processing are handled by the platform's
/// [`DataChannelProvider`]. This template communicates SCP transport parameters
/// (ICE servers, max message size) to the remote peer during signaling setup.
fn create_sdp_offer(config: &WebRtcConfig) -> String {
    let ice_servers: Vec<String> = config
        .ice_servers
        .iter()
        .flat_map(|s| s.urls.iter().cloned())
        .collect();

    format!(
        "v=0\r\n\
         o=scp 0 0 IN IP4 0.0.0.0\r\n\
         s=SCP WebRTC Transport\r\n\
         t=0 0\r\n\
         a=ice-servers:{}\r\n\
         a=max-message-size:{}\r\n\
         m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
         c=IN IP4 0.0.0.0\r\n\
         a=sctp-port:5000\r\n",
        ice_servers.join(","),
        config.max_message_size
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::HashMap;

    use tokio::sync::Mutex as TokioMutex;

    use super::*;

    /// A mock signaling channel for testing.
    struct MockSignalingChannel {
        outbound: TokioMutex<Vec<SignalingMessage>>,
        inbound: TokioMutex<Vec<SignalingMessage>>,
    }

    impl MockSignalingChannel {
        fn new() -> Self {
            Self {
                outbound: TokioMutex::new(Vec::new()),
                inbound: TokioMutex::new(vec![
                    // Pre-load an SDP answer for connection setup.
                    SignalingMessage::Answer {
                        sdp: "v=0\r\no=remote 0 0 IN IP4 0.0.0.0\r\n".to_owned(),
                    },
                ]),
            }
        }
    }

    impl SignalingChannel for MockSignalingChannel {
        fn send_signal(
            &self,
            message: SignalingMessage,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<(), TransportError>> + Send + '_>>
        {
            Box::pin(async move {
                self.outbound.lock().await.push(message);
                Ok(())
            })
        }

        fn recv_signal(
            &self,
        ) -> Pin<
            Box<
                dyn std::future::Future<Output = Result<SignalingMessage, TransportError>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async move {
                let mut inbound = self.inbound.lock().await;
                if inbound.is_empty() {
                    Err(TransportError::NotConnected)
                } else {
                    Ok(inbound.remove(0))
                }
            })
        }
    }

    /// A mock data channel provider for testing.
    /// Channels are in-memory mpsc queues keyed by label.
    pub(crate) struct MockDataChannelProvider {
        channels: TokioMutex<HashMap<String, MockChannel>>,
    }

    struct MockChannel {
        buffer: std::collections::VecDeque<Vec<u8>>,
        open: bool,
    }

    impl MockDataChannelProvider {
        pub(crate) fn new() -> Self {
            Self {
                channels: TokioMutex::new(HashMap::new()),
            }
        }

        /// Inject data into a channel (simulates remote peer sending).
        pub(crate) async fn inject_data(&self, label: &str, data: Vec<u8>) {
            let mut channels = self.channels.lock().await;
            if let Some(ch) = channels.get_mut(label) {
                ch.buffer.push_back(data);
            }
        }
    }

    impl DataChannelProvider for MockDataChannelProvider {
        fn open_channel(
            &self,
            label: &str,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<(), TransportError>> + Send + '_>>
        {
            let label = label.to_owned();
            Box::pin(async move {
                let mut channels = self.channels.lock().await;
                channels.entry(label).or_insert_with(|| MockChannel {
                    buffer: std::collections::VecDeque::new(),
                    open: true,
                });
                Ok(())
            })
        }

        fn send_data(
            &self,
            label: &str,
            data: Vec<u8>,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<(), TransportError>> + Send + '_>>
        {
            let label = label.to_owned();
            Box::pin(async move {
                let mut channels = self.channels.lock().await;
                let ch = channels.get_mut(&label).ok_or_else(|| {
                    TransportError::SendFailed(format!("no channel for label {label}"))
                })?;
                if !ch.open {
                    return Err(TransportError::NotConnected);
                }
                ch.buffer.push_back(data);
                Ok(())
            })
        }

        fn recv_data(
            &self,
            label: &str,
        ) -> Pin<
            Box<
                dyn std::future::Future<Output = Result<Option<Vec<u8>>, TransportError>>
                    + Send
                    + '_,
            >,
        > {
            let label = label.to_owned();
            Box::pin(async move {
                let mut channels = self.channels.lock().await;
                let ch = channels
                    .get_mut(&label)
                    .ok_or(TransportError::NotConnected)?;
                if !ch.open && ch.buffer.is_empty() {
                    return Ok(None);
                }
                Ok(ch.buffer.pop_front())
            })
        }

        fn close_channel(
            &self,
            label: &str,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<(), TransportError>> + Send + '_>>
        {
            let label = label.to_owned();
            Box::pin(async move {
                let mut channels = self.channels.lock().await;
                if let Some(ch) = channels.get_mut(&label) {
                    ch.open = false;
                }
                Ok(())
            })
        }

        fn is_channel_open(
            &self,
            label: &str,
        ) -> Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
            let label = label.to_owned();
            Box::pin(async move {
                let channels = self.channels.lock().await;
                channels.get(&label).is_some_and(|ch| ch.open)
            })
        }
    }

    fn make_adapter() -> (
        WebRtcAdapter,
        Arc<MockSignalingChannel>,
        Arc<MockDataChannelProvider>,
    ) {
        let signaling = Arc::new(MockSignalingChannel::new());
        let provider = Arc::new(MockDataChannelProvider::new());
        let adapter =
            WebRtcAdapter::new(WebRtcConfig::default(), signaling.clone(), provider.clone());
        (adapter, signaling, provider)
    }

    #[tokio::test]
    async fn webrtc_adapter_creation() {
        let (adapter, _, _) = make_adapter();
        // Adapter created without connecting.
        let peer = adapter.peer.lock().await;
        assert!(peer.is_none());
    }

    #[tokio::test]
    async fn webrtc_ensure_connected_exchanges_sdp() {
        let (adapter, signaling, _) = make_adapter();

        adapter.ensure_connected().await.unwrap();

        // Verify SDP offer was sent.
        let outbound = signaling.outbound.lock().await;
        assert_eq!(outbound.len(), 1);
        match &outbound[0] {
            SignalingMessage::Offer { sdp } => {
                assert!(sdp.contains("SCP WebRTC Transport"));
            }
            other => panic!("expected Offer, got {other:?}"),
        }

        // Verify peer connection is established.
        let peer = adapter.peer.lock().await;
        assert!(peer.is_some());
        assert_eq!(
            peer.as_ref().unwrap().ice_state,
            IceConnectionState::Connected
        );
    }

    #[tokio::test]
    async fn webrtc_delete_returns_not_supported() {
        let (adapter, _, _) = make_adapter();

        let blob_id = BlobId::new([0xAA; 32]);
        let result = adapter.delete(&blob_id).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            TransportError::NotSupported(msg) => {
                assert!(msg.contains("P2P"));
            }
            other => panic!("expected NotSupported, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn webrtc_query_returns_empty() {
        let (adapter, _, _) = make_adapter();

        let routing_id = RoutingId::new([0xBB; 32]);
        let result = adapter.query(&routing_id, None).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn webrtc_config_defaults() {
        let config = WebRtcConfig::default();
        assert_eq!(config.max_message_size, 262_144);
        assert_eq!(config.ice_timeout_secs, 30);
        assert_eq!(config.ice_servers.len(), 1);
    }

    #[test]
    fn sdp_offer_contains_ice_servers() {
        let config = WebRtcConfig::default();
        let sdp = create_sdp_offer(&config);
        assert!(sdp.contains("stun:stun.l.google.com:19302"));
        assert!(sdp.contains("max-message-size:262144"));
        assert!(sdp.contains("webrtc-datachannel"));
    }

    #[tokio::test]
    async fn webrtc_send_transports_data_through_provider() {
        let (adapter, _, provider) = make_adapter();

        adapter.ensure_connected().await.unwrap();

        // Create a minimal outer envelope.
        let envelope = OuterEnvelope {
            routing_id: vec![0xAA; 32],
            recipient_hint: None,
            blob_ttl: 3600,
            encrypted_blob: vec![0x01, 0x02, 0x03],
        };

        let blob_id = adapter.send(&envelope).await.unwrap();

        // Verify data was sent through the provider.
        let routing_id_hex = hex::encode(&envelope.routing_id);
        assert!(provider.is_channel_open(&routing_id_hex).await);

        // The provider should have the serialized envelope in its buffer.
        let channels = provider.channels.lock().await;
        let ch = channels.get(&routing_id_hex).unwrap();
        assert_eq!(ch.buffer.len(), 1);

        // Verify the blob ID is correct.
        let wire_bytes = rmp_serde::to_vec_named(&envelope).unwrap();
        assert_eq!(blob_id, BlobId::from_sha256(&wire_bytes));
    }

    #[tokio::test]
    async fn webrtc_unsubscribe_closes_channel() {
        let (adapter, _, provider) = make_adapter();

        adapter.ensure_connected().await.unwrap();

        let routing_id = RoutingId::new([0xCC; 32]);
        let routing_id_hex = hex::encode(routing_id.as_bytes());

        // Open the channel first.
        provider.open_channel(&routing_id_hex).await.unwrap();
        assert!(provider.is_channel_open(&routing_id_hex).await);

        // Unsubscribe should close it.
        adapter.unsubscribe(&routing_id).await.unwrap();
        assert!(!provider.is_channel_open(&routing_id_hex).await);
    }
}
