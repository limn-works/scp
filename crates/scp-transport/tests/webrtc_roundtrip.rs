//! Roundtrip integration test for the WebRTC transport adapter.
//!
//! Tests the full cycle: construct adapter with mock DataChannelProvider,
//! send envelope, subscribe, verify envelope received through the provider.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use futures::StreamExt;
use scp_core::envelope::OuterEnvelope;
use scp_transport::TransportAdapter;
use scp_transport::error::TransportError;
use scp_transport::traits::{BlobId, RoutingId, TransportEvent};
use scp_transport::webrtc::adapter::{WebRtcAdapter, WebRtcConfig};
use scp_transport::webrtc::signaling::{DataChannelProvider, SignalingChannel, SignalingMessage};
use tokio::sync::Mutex;

/// Mock signaling channel for testing.
struct MockSignalingChannel {
    outbound: Mutex<Vec<SignalingMessage>>,
    inbound: Mutex<Vec<SignalingMessage>>,
}

impl MockSignalingChannel {
    fn new() -> Self {
        Self {
            outbound: Mutex::new(Vec::new()),
            inbound: Mutex::new(vec![SignalingMessage::Answer {
                sdp: "v=0\r\no=remote 0 0 IN IP4 0.0.0.0\r\n".to_owned(),
            }]),
        }
    }
}

impl SignalingChannel for MockSignalingChannel {
    fn send_signal(
        &self,
        message: SignalingMessage,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), TransportError>> + Send + '_>> {
        Box::pin(async move {
            self.outbound.lock().await.push(message);
            Ok(())
        })
    }

    fn recv_signal(
        &self,
    ) -> Pin<
        Box<dyn std::future::Future<Output = Result<SignalingMessage, TransportError>> + Send + '_>,
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

/// Mock data channel provider for testing.
struct MockDataChannelProvider {
    channels: Mutex<HashMap<String, MockChannel>>,
}

struct MockChannel {
    buffer: std::collections::VecDeque<Vec<u8>>,
    open: bool,
}

impl MockDataChannelProvider {
    fn new() -> Self {
        Self {
            channels: Mutex::new(HashMap::new()),
        }
    }

    /// Inject data into a channel (simulates remote peer sending).
    async fn inject_data(&self, label: &str, data: Vec<u8>) {
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
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), TransportError>> + Send + '_>> {
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
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), TransportError>> + Send + '_>> {
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
        Box<dyn std::future::Future<Output = Result<Option<Vec<u8>>, TransportError>> + Send + '_>,
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
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), TransportError>> + Send + '_>> {
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

fn test_envelope() -> OuterEnvelope {
    OuterEnvelope {
        routing_id: vec![0xBB; 32],
        recipient_hint: None,
        blob_ttl: 7200,
        encrypted_blob: vec![0x10, 0x20, 0x30],
    }
}

fn make_adapter() -> (WebRtcAdapter, Arc<MockDataChannelProvider>) {
    let signaling = Arc::new(MockSignalingChannel::new());
    let provider = Arc::new(MockDataChannelProvider::new());
    let adapter = WebRtcAdapter::new(WebRtcConfig::default(), signaling, provider.clone());
    (adapter, provider)
}

#[tokio::test]
async fn webrtc_send_and_receive_roundtrip() {
    let (adapter, provider) = make_adapter();
    let envelope = test_envelope();

    // Send the envelope through the adapter.
    let blob_id = adapter.send(&envelope).await.unwrap();

    // Verify the blob ID matches.
    let wire_bytes = rmp_serde::to_vec_named(&envelope).unwrap();
    assert_eq!(blob_id, BlobId::from_sha256(&wire_bytes));

    // The provider should have the data in the channel buffer.
    let routing_id_hex = hex::encode(&envelope.routing_id);
    let channels = provider.channels.lock().await;
    let ch = channels.get(&routing_id_hex).unwrap();
    assert_eq!(ch.buffer.len(), 1);

    // Deserialize and verify the envelope matches.
    let received: OuterEnvelope = rmp_serde::from_slice(&ch.buffer[0]).unwrap();
    assert_eq!(received.routing_id, envelope.routing_id);
    assert_eq!(received.blob_ttl, envelope.blob_ttl);
    assert_eq!(received.encrypted_blob, envelope.encrypted_blob);
}

#[tokio::test]
async fn webrtc_subscribe_receives_injected_data() {
    let (adapter, provider) = make_adapter();
    let envelope = test_envelope();
    let routing_id = RoutingId::new([0xBB; 32]);
    let routing_id_hex = hex::encode(routing_id.as_bytes());

    // Subscribe first (this opens the channel).
    let mut stream = adapter.subscribe(&routing_id, None).await.unwrap();

    // Inject serialized envelope data (simulates remote peer sending).
    let wire_bytes = rmp_serde::to_vec_named(&envelope).unwrap();
    provider.inject_data(&routing_id_hex, wire_bytes).await;

    // Read from the subscription stream.
    let event = stream.next().await.unwrap();
    match event {
        TransportEvent::Envelope(received) => {
            assert_eq!(received.routing_id, envelope.routing_id);
            assert_eq!(received.blob_ttl, envelope.blob_ttl);
            assert_eq!(received.encrypted_blob, envelope.encrypted_blob);
        }
        other => panic!("expected Envelope, got {other:?}"),
    }
}

#[tokio::test]
async fn webrtc_subscribe_handles_channel_close() {
    let (adapter, provider) = make_adapter();
    let routing_id = RoutingId::new([0xCC; 32]);
    let routing_id_hex = hex::encode(routing_id.as_bytes());

    let mut stream = adapter.subscribe(&routing_id, None).await.unwrap();

    // Close the channel (simulates peer disconnection).
    provider.close_channel(&routing_id_hex).await.unwrap();

    // The stream should yield a Terminated event.
    let event = stream.next().await.unwrap();
    match event {
        TransportEvent::Terminated { reason } => {
            assert!(reason.contains("closed"));
        }
        other => panic!("expected Terminated, got {other:?}"),
    }
}

#[tokio::test]
async fn webrtc_payload_too_large_rejected() {
    let (adapter, _) = make_adapter();

    let large_envelope = OuterEnvelope {
        routing_id: vec![0xDD; 32],
        recipient_hint: None,
        blob_ttl: 3600,
        encrypted_blob: vec![0xFF; 300_000], // > 256 KiB default max
    };

    let result = adapter.send(&large_envelope).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        TransportError::PayloadTooLarge(msg) => {
            assert!(msg.contains("exceeds"));
        }
        other => panic!("expected PayloadTooLarge, got {other:?}"),
    }
}

#[tokio::test]
async fn webrtc_delete_returns_not_supported() {
    let (adapter, _) = make_adapter();

    let blob_id = BlobId::new([0xEE; 32]);
    let result = adapter.delete(&blob_id).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        TransportError::NotSupported(_) => {}
        other => panic!("expected NotSupported, got {other:?}"),
    }
}

#[tokio::test]
async fn webrtc_unsubscribe_closes_provider_channel() {
    let (adapter, provider) = make_adapter();
    let routing_id = RoutingId::new([0xFF; 32]);
    let routing_id_hex = hex::encode(routing_id.as_bytes());

    // Subscribe to open the channel.
    let _stream = adapter.subscribe(&routing_id, None).await.unwrap();
    assert!(provider.is_channel_open(&routing_id_hex).await);

    // Unsubscribe.
    adapter.unsubscribe(&routing_id).await.unwrap();
    assert!(!provider.is_channel_open(&routing_id_hex).await);
}
