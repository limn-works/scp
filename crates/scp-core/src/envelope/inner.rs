//! Inner envelope — the decrypted payload visible only to MLS group members.
//!
//! Contains sender identity, sequence metadata, payload with integrity hash,
//! optional provenance, and an Ed25519 signature. See ADR-002.

use serde::{Deserialize, Serialize};

/// Serde helper for `[u8; 64]` — serde's derive only handles arrays up to 32
/// elements. Serializes as a `MessagePack` `bin` blob, deserializes back.
mod signature_serde {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(val: &[u8; 64], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_bytes(val)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 64], D::Error> {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = [u8; 64];

            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("64 bytes")
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                <[u8; 64]>::try_from(v).map_err(|_| E::invalid_length(v.len(), &self))
            }

            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                self.visit_bytes(&v)
            }
        }

        de.deserialize_bytes(Visitor)
    }
}

/// Provenance metadata indicating the origin of a message.
///
/// Attached to messages that carry tool outputs, cross-context transfers,
/// or other content requiring verifiable origin. See spec section 7.7.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// DID of the original source that produced this content.
    pub source_did: String,
    /// Identifier of the tool or service that generated the content, if applicable.
    pub tool_id: Option<String>,
    /// Unix timestamp (milliseconds) when the content was originally produced.
    pub generated_at: u64,
    /// Optional content hash from the originating context for cross-context transfers.
    pub source_content_hash: Option<[u8; 32]>,
}

/// The inner envelope, visible only to MLS group members after decryption.
///
/// Contains the full message with sender identity, sequence numbers,
/// timestamps, payload, provenance, and a signature covering all fields.
/// The signature is computed over `SHA256(context_id || sender_did || epoch
/// || generation || sequence || timestamp || payload_hash || provenance_hash)`.
/// See ADR-002 for the complete signing specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InnerEnvelope {
    /// The SCP context identifier this message belongs to.
    pub context_id: String,
    /// The sender's full DID (e.g. `did:dht:z6Mk...`).
    pub sender_did: String,
    /// MLS epoch number at time of encryption.
    pub epoch: u64,
    /// MLS generation number assigned automatically by the MLS layer.
    pub generation: u64,
    /// SCP per-sender monotonic sequence number (spec section 9.8.5).
    pub sequence: u64,
    /// Creation timestamp (Unix milliseconds).
    pub timestamp: u64,
    /// SHA-256 hash of the original plaintext payload (before padding).
    ///
    /// Enables content-addressing, deduplication, and integrity verification
    /// after decryption. This hash is inside the encrypted blob and invisible
    /// to relays.
    pub payload_hash: [u8; 32],
    /// The message payload (after bucket padding per Decision 3).
    pub payload: Vec<u8>,
    /// Optional provenance metadata (spec section 7.7).
    pub provenance: Option<Provenance>,
    /// Ed25519 signature over the canonical signing input.
    #[serde(with = "signature_serde")]
    pub signature: [u8; 64],
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn inner_envelope_serializes_to_and_from_msgpack() {
        let envelope = InnerEnvelope {
            context_id: "ctx-abc-123".to_string(),
            sender_did: "did:dht:z6MkTest".to_string(),
            epoch: 1,
            generation: 0,
            sequence: 42,
            timestamp: 1_700_000_000_000,
            payload_hash: [0xab; 32],
            payload: vec![1, 2, 3, 4],
            provenance: None,
            signature: [0xcd; 64],
        };

        let packed = rmp_serde::to_vec(&envelope).expect("serialization should succeed in test");
        let unpacked: InnerEnvelope =
            rmp_serde::from_slice(&packed).expect("deserialization should succeed in test");

        assert_eq!(envelope, unpacked);
    }

    #[test]
    fn inner_envelope_with_provenance_roundtrips() {
        let envelope = InnerEnvelope {
            context_id: "ctx-xyz".to_string(),
            sender_did: "did:dht:z6MkSender".to_string(),
            epoch: 5,
            generation: 3,
            sequence: 100,
            timestamp: 1_700_000_001_000,
            payload_hash: [0x11; 32],
            payload: vec![10, 20, 30],
            provenance: Some(Provenance {
                source_did: "did:dht:z6MkSource".to_string(),
                tool_id: Some("tool-gpt".to_string()),
                generated_at: 1_699_999_999_000,
                source_content_hash: Some([0xff; 32]),
            }),
            signature: [0xee; 64],
        };

        let packed = rmp_serde::to_vec(&envelope).expect("serialization should succeed in test");
        let unpacked: InnerEnvelope =
            rmp_serde::from_slice(&packed).expect("deserialization should succeed in test");

        assert_eq!(envelope, unpacked);
    }

    #[test]
    fn provenance_serializes_independently() {
        let prov = Provenance {
            source_did: "did:dht:z6MkOrig".to_string(),
            tool_id: None,
            generated_at: 1_600_000_000_000,
            source_content_hash: None,
        };

        let packed = rmp_serde::to_vec(&prov).expect("serialization should succeed in test");
        let unpacked: Provenance =
            rmp_serde::from_slice(&packed).expect("deserialization should succeed in test");

        assert_eq!(prov, unpacked);
    }
}
