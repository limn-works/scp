//! Sender-key-encrypted envelopes for shadow identity messages.
//!
//! Shadow messages use the sender key layer (§9.16) rather than MLS
//! encryption. Each shadow has its own AES-256-GCM sender key (generated
//! in SCP-BCH-010). The [`SenderKeyEnvelope`] is structurally
//! distinguishable from MLS-encrypted envelopes: it contains a
//! `sender_did` field with the shadow's DID and `encryption_type` set
//! to `"sender_key"`, while MLS envelopes have `encryption_type`
//! `"mls"`.
//!
//! Receivers select the correct decryption path (sender key vs MLS)
//! based on the `encryption_type` discriminator.
//!
//! See §12.6.1 and SCP-BCH-012.

use serde::{Deserialize, Serialize};

use super::provenance::{BridgeProvenance, mark_bridge_provenance};
use super::{BridgeConnector, ShadowIdentity};
use crate::crypto::sender_keys::{SenderKey, SenderKeyError, encrypt_sender_layer};
use crate::provenance::DataProvenance;

// ---------------------------------------------------------------------------
// SenderKeyEnvelope
// ---------------------------------------------------------------------------

/// A sender-key-encrypted envelope for shadow identity messages.
///
/// Structurally distinguishable from MLS-encrypted envelopes by the
/// `encryption_type` field (`"sender_key"` vs `"mls"`). The receiver
/// uses this discriminator to select the correct decryption path.
///
/// See §12.6.1 and SCP-BCH-012.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderKeyEnvelope {
    /// The shadow DID that sent this message.
    pub sender_did: String,

    /// Encryption type discriminator: always `"sender_key"` for shadow
    /// messages, distinguishing from `"mls"` for native MLS envelopes.
    pub encryption_type: String,

    /// AES-256-GCM ciphertext: `nonce (12 bytes) || ciphertext || tag`.
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,

    /// Bridge provenance metadata for this message.
    pub bridge_provenance: BridgeProvenance,

    /// Optional platform-specific message ID for correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_message_id: Option<String>,

    /// Optional platform-reported timestamp (Unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_timestamp: Option<u64>,
}

/// The encryption type discriminator for sender-key-encrypted envelopes.
pub const SENDER_KEY_ENCRYPTION_TYPE: &str = "sender_key";

/// The encryption type discriminator for MLS-encrypted envelopes.
pub const MLS_ENCRYPTION_TYPE: &str = "mls";

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

/// Parameters for constructing a sender-key-encrypted envelope.
pub struct SealShadowEnvelopeParams<'a> {
    /// The shadow identity emitting the message.
    pub shadow: &'a ShadowIdentity,
    /// The bridge connector operating this shadow.
    pub connector: &'a BridgeConnector,
    /// The shadow's AES-256-GCM sender key.
    pub sender_key: &'a SenderKey,
    /// Message plaintext to encrypt.
    pub plaintext: &'a [u8],
    /// Base provenance record for this message.
    pub base_provenance: DataProvenance,
    /// Optional platform message ID for correlation.
    pub platform_message_id: Option<String>,
    /// Optional platform-reported timestamp.
    pub platform_timestamp: Option<u64>,
}

/// Constructs a sender-key-encrypted envelope for a shadow message.
///
/// Encrypts the plaintext with AES-256-GCM using the shadow's sender
/// key (random 12-byte nonce per message), attaches bridge provenance
/// via [`mark_bridge_provenance`], and returns the complete envelope.
///
/// # Errors
///
/// Returns [`SenderKeyError`] if encryption fails.
pub fn seal_shadow_envelope(
    params: &SealShadowEnvelopeParams<'_>,
) -> Result<SenderKeyEnvelope, SenderKeyError> {
    let ciphertext = encrypt_sender_layer(params.sender_key, params.plaintext)?;

    let bridge_provenance = mark_bridge_provenance(
        params.base_provenance.clone(),
        params.connector,
        params.shadow,
    );

    Ok(SenderKeyEnvelope {
        sender_did: params.shadow.shadow_id.clone(),
        encryption_type: SENDER_KEY_ENCRYPTION_TYPE.to_owned(),
        ciphertext,
        bridge_provenance,
        platform_message_id: params.platform_message_id.clone(),
        platform_timestamp: params.platform_timestamp,
    })
}

/// Returns `true` if the envelope is a sender-key-encrypted envelope
/// (shadow message), `false` if it is an MLS-encrypted envelope.
#[must_use]
pub fn is_sender_key_envelope(envelope: &SenderKeyEnvelope) -> bool {
    envelope.encryption_type == SENDER_KEY_ENCRYPTION_TYPE
}

// ---------------------------------------------------------------------------
// Decryption
// ---------------------------------------------------------------------------

/// Opens a sender-key-encrypted envelope using the shadow's sender key.
///
/// # Errors
///
/// Returns [`SenderKeyError`] if decryption fails (wrong key, tampered
/// ciphertext, etc.).
pub fn open_shadow_envelope(
    envelope: &SenderKeyEnvelope,
    sender_key: &SenderKey,
) -> Result<Vec<u8>, SenderKeyError> {
    crate::crypto::sender_keys::decrypt_sender_layer(sender_key, &envelope.ciphertext)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::bridge::{BridgeMode, BridgeStatus, ShadowProvenanceStatus};
    use crate::context::MemoryScope;
    use crate::crypto::sender_keys::generate_sender_key;
    use crate::provenance::{DiscoveryMethod, SourceType};

    fn make_base_provenance() -> DataProvenance {
        DataProvenance {
            source_context: "ctx-bridge-test".to_string(),
            source_type: SourceType::Persistent,
            counterparties: vec!["did:dht:z6MkAlice".into()],
            purpose: Some("bridged message".to_string()),
            discovery_method: DiscoveryMethod::SharedContext("ctx-shared".to_string()),
            age: Duration::from_secs(30),
            memory_scope: MemoryScope::Full,
            chain_depth: 0,
            chain_path: None,
            payment_amount: None,
            payment_adapter: None,
            payment_receipt_id: None,
        }
    }

    fn make_connector() -> BridgeConnector {
        BridgeConnector {
            bridge_id: "bridge-test-001".to_string(),
            operator_did: "did:dht:z6MkOperator".into(),
            platform: "discord".to_string(),
            mode: BridgeMode::Relay,
            status: BridgeStatus::Active,
            registration_context: "ctx-reg".to_string(),
            registered_at: 1_700_000_000,
        }
    }

    fn make_shadow() -> ShadowIdentity {
        ShadowIdentity {
            shadow_id: "shadow:bridge-test-001:alice".to_string(),
            platform_handle: "@alice#1234".to_string(),
            bridge_id: "bridge-test-001".to_string(),
            attributed_role: "observer".to_string(),
            provenance_status: ShadowProvenanceStatus::Shadow,
            created_at: 1_700_000_100,
        }
    }

    #[test]
    fn seal_and_open_roundtrip() {
        let key = generate_sender_key();
        let plaintext = b"Hello from shadow!";

        let params = SealShadowEnvelopeParams {
            shadow: &make_shadow(),
            connector: &make_connector(),
            sender_key: &key,
            plaintext,
            base_provenance: make_base_provenance(),
            platform_message_id: Some("msg-ext-001".to_owned()),
            platform_timestamp: Some(1_700_000_200),
        };

        let envelope = seal_shadow_envelope(&params).unwrap();

        // Verify envelope structure.
        assert_eq!(envelope.encryption_type, SENDER_KEY_ENCRYPTION_TYPE);
        assert_eq!(envelope.sender_did, "shadow:bridge-test-001:alice");
        assert!(is_sender_key_envelope(&envelope));
        assert_eq!(envelope.platform_message_id, Some("msg-ext-001".to_owned()));
        assert_eq!(envelope.platform_timestamp, Some(1_700_000_200));

        // Verify provenance.
        assert_eq!(envelope.bridge_provenance.originating_platform, "discord");
        assert_eq!(envelope.bridge_provenance.bridge_mode, BridgeMode::Relay);
        assert_eq!(
            envelope.bridge_provenance.shadow_status,
            ShadowProvenanceStatus::Shadow
        );
        assert_eq!(
            envelope.bridge_provenance.operator_did,
            "did:dht:z6MkOperator"
        );

        // Decrypt.
        let decrypted = open_shadow_envelope(&envelope, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let key = generate_sender_key();
        let wrong_key = generate_sender_key();

        let params = SealShadowEnvelopeParams {
            shadow: &make_shadow(),
            connector: &make_connector(),
            sender_key: &key,
            plaintext: b"secret",
            base_provenance: make_base_provenance(),
            platform_message_id: None,
            platform_timestamp: None,
        };

        let envelope = seal_shadow_envelope(&params).unwrap();
        let result = open_shadow_envelope(&envelope, &wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn each_envelope_has_unique_nonce() {
        let key = generate_sender_key();
        let shadow = make_shadow();
        let connector = make_connector();

        let env1 = seal_shadow_envelope(&SealShadowEnvelopeParams {
            shadow: &shadow,
            connector: &connector,
            sender_key: &key,
            plaintext: b"message 1",
            base_provenance: make_base_provenance(),
            platform_message_id: None,
            platform_timestamp: None,
        })
        .unwrap();

        let env2 = seal_shadow_envelope(&SealShadowEnvelopeParams {
            shadow: &shadow,
            connector: &connector,
            sender_key: &key,
            plaintext: b"message 1",
            base_provenance: make_base_provenance(),
            platform_message_id: None,
            platform_timestamp: None,
        })
        .unwrap();

        // Same plaintext but different nonces → different ciphertexts.
        assert_ne!(env1.ciphertext, env2.ciphertext);
    }

    #[test]
    fn sender_key_envelope_is_distinguishable_from_mls() {
        let key = generate_sender_key();
        let params = SealShadowEnvelopeParams {
            shadow: &make_shadow(),
            connector: &make_connector(),
            sender_key: &key,
            plaintext: b"test",
            base_provenance: make_base_provenance(),
            platform_message_id: None,
            platform_timestamp: None,
        };

        let envelope = seal_shadow_envelope(&params).unwrap();
        assert_eq!(envelope.encryption_type, "sender_key");
        assert_ne!(envelope.encryption_type, MLS_ENCRYPTION_TYPE);
    }

    #[test]
    fn claimed_shadow_produces_claimed_provenance() {
        let key = generate_sender_key();
        let mut shadow = make_shadow();
        shadow.provenance_status = ShadowProvenanceStatus::Claimed;

        let params = SealShadowEnvelopeParams {
            shadow: &shadow,
            connector: &make_connector(),
            sender_key: &key,
            plaintext: b"claimed message",
            base_provenance: make_base_provenance(),
            platform_message_id: None,
            platform_timestamp: None,
        };

        let envelope = seal_shadow_envelope(&params).unwrap();
        assert_eq!(
            envelope.bridge_provenance.shadow_status,
            ShadowProvenanceStatus::Claimed
        );
    }

    #[test]
    fn serialization_roundtrip() {
        let key = generate_sender_key();
        let params = SealShadowEnvelopeParams {
            shadow: &make_shadow(),
            connector: &make_connector(),
            sender_key: &key,
            plaintext: b"roundtrip test",
            base_provenance: make_base_provenance(),
            platform_message_id: Some("ext-123".to_owned()),
            platform_timestamp: Some(1_700_000_300),
        };

        let envelope = seal_shadow_envelope(&params).unwrap();
        let json = serde_json::to_string(&envelope).unwrap();
        let restored: SenderKeyEnvelope = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.sender_did, envelope.sender_did);
        assert_eq!(restored.encryption_type, envelope.encryption_type);
        assert_eq!(restored.ciphertext, envelope.ciphertext);
        assert_eq!(restored.platform_message_id, envelope.platform_message_id);
        assert_eq!(restored.platform_timestamp, envelope.platform_timestamp);

        // Can still decrypt after deserialization.
        let decrypted = open_shadow_envelope(&restored, &key).unwrap();
        assert_eq!(decrypted, b"roundtrip test");
    }
}
