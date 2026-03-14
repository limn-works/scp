//! Roundtrip integration test for the Nostr transport adapter.
//!
//! Tests the full cycle: construct adapter, create events with real
//! Schnorr signatures, verify signature validity, and test envelope
//! encoding/decoding roundtrip.
//!
//! Does NOT require a real Nostr relay -- tests the event construction,
//! signing, and parsing pipeline.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use k256::schnorr::signature::Verifier;
use scp_core::envelope::OuterEnvelope;
use scp_transport::nostr::adapter::{NostrAdapter, NostrConfig};
use scp_transport::nostr::protocol::{NostrEvent, SCP_EVENT_KIND};

/// Generate a valid test signing key.
fn test_signing_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    key[31] = 42;
    key
}

/// Create a minimal outer envelope for testing.
fn test_envelope() -> OuterEnvelope {
    OuterEnvelope {
        version: scp_core::envelope::outer::SCP_OUTER_ENVELOPE_VERSION,
        routing_id: vec![0xAA; 32],
        recipient_hint: None,
        blob_ttl: 3600,
        encrypted_blob: vec![0x01, 0x02, 0x03, 0x04],
        extensions: std::collections::HashMap::new(),
        version_compatibility: None,
    }
}

#[test]
fn nostr_event_creation_and_signing_roundtrip() {
    let config = NostrConfig::new("wss://relay.example.com".to_owned(), test_signing_key());
    let adapter = NostrAdapter::new(config).unwrap();

    // Create a signed event by constructing it the same way the adapter does
    // internally, but without needing a WebSocket connection.
    let content = "test-content";
    let tags = vec![vec!["r".to_owned(), "deadbeef".to_owned()]];
    let id = NostrEvent::compute_id(&adapter.pubkey_hex(), 1000, SCP_EVENT_KIND, &tags, content)
        .unwrap();

    let mut event = NostrEvent {
        id,
        pubkey: adapter.pubkey_hex().to_owned(),
        created_at: 1000,
        kind: SCP_EVENT_KIND,
        tags,
        content: content.to_owned(),
        sig: String::new(),
    };

    // Sign the event.
    event.sig = adapter.sign_event(&event).unwrap();

    // Verify the signature.
    assert_eq!(event.sig.len(), 128, "signature should be 128 hex chars");
    assert_ne!(
        event.sig,
        "0".repeat(128),
        "signature should not be placeholder"
    );

    let sig_bytes = hex::decode(&event.sig).unwrap();
    let signature = k256::schnorr::Signature::try_from(sig_bytes.as_slice()).unwrap();
    let id_bytes = event.id_bytes().unwrap();
    let verifying_key = adapter.verifying_key();
    verifying_key.verify(&id_bytes, &signature).unwrap();
}

#[test]
fn nostr_envelope_base64_roundtrip() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let envelope = test_envelope();

    // Serialize to MessagePack with named fields (what the adapter does).
    let wire_bytes = rmp_serde::to_vec_named(&envelope).unwrap();

    // Base64 encode (what Nostr events use for content).
    let encoded = STANDARD.encode(&wire_bytes);

    // Decode and deserialize (what the adapter does on receive).
    let decoded_bytes = STANDARD.decode(&encoded).unwrap();
    let decoded: OuterEnvelope = rmp_serde::from_slice(&decoded_bytes).unwrap();

    assert_eq!(decoded.routing_id, envelope.routing_id);
    assert_eq!(decoded.blob_ttl, envelope.blob_ttl);
    assert_eq!(decoded.encrypted_blob, envelope.encrypted_blob);
    assert_eq!(decoded.recipient_hint, envelope.recipient_hint);
}

#[test]
fn nostr_deletion_event_is_properly_signed() {
    let config = NostrConfig::new("wss://relay.example.com".to_owned(), test_signing_key());
    let adapter = NostrAdapter::new(config).unwrap();

    // The deletion event ID needs to be 64 hex chars (32 bytes).
    let event_id = hex::encode([0xDEu8; 32]);
    let deletion_event = adapter.create_deletion_event(&event_id).unwrap();

    assert_eq!(deletion_event.kind, 5);
    assert_eq!(deletion_event.tags[0][0], "e");
    assert_eq!(deletion_event.tags[0][1], event_id);

    // Verify signature.
    let sig_bytes = hex::decode(&deletion_event.sig).unwrap();
    let signature = k256::schnorr::Signature::try_from(sig_bytes.as_slice()).unwrap();
    let id_bytes = deletion_event.id_bytes().unwrap();
    let verifying_key = adapter.verifying_key();
    verifying_key.verify(&id_bytes, &signature).unwrap();
}

#[test]
fn nostr_different_keys_produce_different_pubkeys() {
    let mut key1 = [0u8; 32];
    key1[31] = 1;
    let mut key2 = [0u8; 32];
    key2[31] = 2;

    let config1 = NostrConfig::new("wss://relay.example.com".to_owned(), key1);
    let config2 = NostrConfig::new("wss://relay.example.com".to_owned(), key2);

    let adapter1 = NostrAdapter::new(config1).unwrap();
    let adapter2 = NostrAdapter::new(config2).unwrap();

    assert_ne!(adapter1.pubkey_hex(), adapter2.pubkey_hex());
}
