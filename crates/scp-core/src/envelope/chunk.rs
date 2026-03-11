//! Large-message chunking for SCP envelopes.
//!
//! Messages larger than the largest bucket size (256 KB) cannot be padded to a
//! single bucket. Per §9.10.3, such messages are split into 256 KB blocks,
//! each of which is independently padded, encrypted, and transmitted as its
//! own outer envelope. The receiver reassembles chunks by `message_id` before
//! passing the complete payload up to the application.
//!
//! The SDK handles chunking transparently: application developers never see
//! individual chunks. Relay operators see uniform bucket-sized blobs
//! indistinguishable from single-message envelopes.
//!
//! # Wire format
//!
//! Each chunk is carried as the payload of a normal [`InnerEnvelope`] with
//! [`MessageType::Content`]. The chunk metadata is serialized as the inner
//! envelope's payload. The receiver deserializes the `ChunkEnvelope`, buffers
//! it, and reassembles when all chunks have arrived.
//!
//! [`InnerEnvelope`]: super::inner::InnerEnvelope
//! [`MessageType::Content`]: super::inner::MessageType::Content

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::EnvelopeError;
use super::padding::BUCKET_SIZES;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum chunk payload size in bytes (256 KB minus 4-byte length suffix used
/// by bucket padding). This ensures each chunk fits in the largest bucket after
/// padding.
pub const MAX_CHUNK_PAYLOAD_SIZE: usize = BUCKET_SIZES[BUCKET_SIZES.len() - 1] - 4;

/// Maximum number of chunks per message. Limits total reassembled message size
/// to approximately 64 GB (`MAX_CHUNK_PAYLOAD_SIZE` * 262,144), which is far
/// beyond any realistic protocol message.
pub const MAX_TOTAL_CHUNKS: u32 = 262_144;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A chunk of a large message that exceeded the maximum bucket size (256 KB).
///
/// When a message payload exceeds 256 KB, the SDK splits it into chunks of at
/// most [`MAX_CHUNK_PAYLOAD_SIZE`] bytes. Each chunk is serialized as the
/// payload of an independent [`InnerEnvelope`], padded, encrypted, and sent as
/// a separate [`OuterEnvelope`]. The receiver collects chunks by `message_id`
/// and reassembles the original payload when all chunks have arrived.
///
/// # Fields
///
/// - `message_id` — A unique identifier for the complete message, shared by
///   all chunks. Derived as `SHA-256("SCP-CHUNK-MSG-ID-V1:" || BE32(len(payload)) || payload || BE32(len(sender_did)) || sender_did || BE64(timestamp))`
///   to ensure uniqueness without requiring coordination.
/// - `chunk_index` — Zero-based position of this chunk in the sequence.
/// - `total_chunks` — Total number of chunks in the complete message.
/// - `payload_hash` — SHA-256 hash of the complete (pre-chunked) payload,
///   enabling integrity verification after reassembly.
/// - `data` — The chunk's payload bytes (at most [`MAX_CHUNK_PAYLOAD_SIZE`]).
///
/// [`InnerEnvelope`]: super::inner::InnerEnvelope
/// [`OuterEnvelope`]: super::outer::OuterEnvelope
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkEnvelope {
    /// Unique identifier for the complete message. All chunks of the same
    /// message share this value. 32 bytes, derived via SHA-256.
    #[serde(with = "crate::serde_util::serde_hash_32")]
    pub message_id: [u8; 32],

    /// Zero-based index of this chunk within the complete message.
    pub chunk_index: u32,

    /// Total number of chunks that compose the complete message.
    /// Must be >= 1 and <= [`MAX_TOTAL_CHUNKS`].
    pub total_chunks: u32,

    /// SHA-256 hash of the complete (pre-chunked) payload. Used by the
    /// receiver to verify integrity after reassembly.
    #[serde(with = "crate::serde_util::serde_hash_32")]
    pub payload_hash: [u8; 32],

    /// The chunk's payload bytes. At most [`MAX_CHUNK_PAYLOAD_SIZE`] bytes.
    /// Uses `serde_bytes` for efficient `MessagePack` binary encoding.
    #[serde(with = "crate::serde_util::serde_bounded_bytes")]
    pub data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Chunking (split)
// ---------------------------------------------------------------------------

/// Splits a large payload into [`ChunkEnvelope`]s.
///
/// Each chunk carries at most [`MAX_CHUNK_PAYLOAD_SIZE`] bytes of payload data.
/// The `message_id` is derived as
/// `SHA-256("SCP-CHUNK-MSG-ID-V1:" || BE32(payload.len) || payload || BE32(did.len) || sender_did || BE64(timestamp))`
/// using length-prefixed, domain-separated hashing to provide a unique,
/// deterministic identifier without coordination or field-collision ambiguity.
///
/// # Arguments
///
/// - `payload` — The full message payload to chunk.
/// - `sender_did` — The sender's DID, mixed into the message ID derivation.
/// - `timestamp` — Creation timestamp (Unix ms), mixed into the message ID.
///
/// # Errors
///
/// Returns [`EnvelopeError::SerializationFailed`] if the payload is empty.
pub fn split_into_chunks(
    payload: &[u8],
    sender_did: &str,
    timestamp: u64,
) -> Result<Vec<ChunkEnvelope>, EnvelopeError> {
    if payload.is_empty() {
        return Err(EnvelopeError::SerializationFailed(
            "cannot chunk an empty payload".into(),
        ));
    }

    // Derive message_id with length-prefixed fields for unambiguous domain
    // separation. Without length prefixes, payload="ab" + did="cd" collides
    // with payload="abc" + did="d".
    // Format: SHA-256("SCP-CHUNK-MSG-ID-V1:" || BE32(payload.len) || payload
    //                  || BE32(did.len) || sender_did || BE64(timestamp))
    let message_id: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(b"SCP-CHUNK-MSG-ID-V1:");
        #[allow(clippy::cast_possible_truncation)]
        hasher.update((payload.len() as u32).to_be_bytes());
        hasher.update(payload);
        #[allow(clippy::cast_possible_truncation)]
        hasher.update((sender_did.len() as u32).to_be_bytes());
        hasher.update(sender_did.as_bytes());
        hasher.update(timestamp.to_be_bytes());
        hasher.finalize().into()
    };

    // SHA-256 of the complete payload for integrity verification.
    let payload_hash: [u8; 32] = Sha256::digest(payload).into();

    // Split into chunks.
    let chunks_iter = payload.chunks(MAX_CHUNK_PAYLOAD_SIZE);
    let total_chunks_usize = chunks_iter.len();
    let total_chunks = u32::try_from(total_chunks_usize).map_err(|_| {
        EnvelopeError::SerializationFailed(format!(
            "payload requires {total_chunks_usize} chunks, exceeding u32::MAX"
        ))
    })?;

    if total_chunks > MAX_TOTAL_CHUNKS {
        return Err(EnvelopeError::SerializationFailed(format!(
            "payload requires {total_chunks} chunks, exceeding MAX_TOTAL_CHUNKS ({MAX_TOTAL_CHUNKS})"
        )));
    }

    let envelopes: Vec<ChunkEnvelope> = payload
        .chunks(MAX_CHUNK_PAYLOAD_SIZE)
        .enumerate()
        .map(|(i, chunk_data)| {
            // Safety: total_chunks <= MAX_TOTAL_CHUNKS (262,144) < u32::MAX
            #[allow(clippy::cast_possible_truncation)]
            let chunk_index = i as u32;
            ChunkEnvelope {
                message_id,
                chunk_index,
                total_chunks,
                payload_hash,
                data: chunk_data.to_vec(),
            }
        })
        .collect();

    Ok(envelopes)
}

// ---------------------------------------------------------------------------
// Reassembly
// ---------------------------------------------------------------------------

/// Reassembles a complete payload from a set of [`ChunkEnvelope`]s.
///
/// # Requirements
///
/// - All chunks must share the same `message_id`.
/// - All chunks must agree on `total_chunks` and `payload_hash`.
/// - Exactly `total_chunks` distinct `chunk_index` values must be present
///   `(0..total_chunks)`.
/// - No duplicate `chunk_index` values.
///
/// After concatenation the reassembled payload's SHA-256 hash is verified
/// against the `payload_hash` carried in the chunks.
///
/// # Errors
///
/// Returns [`EnvelopeError::DeserializationFailed`] if:
/// - The chunk set is empty.
/// - Chunks have mismatched `message_id`, `total_chunks`, or `payload_hash`.
/// - Duplicate or out-of-range `chunk_index` values are present.
/// - Not all chunks are present (missing indices).
/// - The reassembled payload's hash does not match `payload_hash`.
pub fn reassemble_chunks(chunks: &[ChunkEnvelope]) -> Result<Vec<u8>, EnvelopeError> {
    if chunks.is_empty() {
        return Err(EnvelopeError::DeserializationFailed(
            "no chunks to reassemble".into(),
        ));
    }

    let first = &chunks[0];
    let message_id = first.message_id;
    let total_chunks = first.total_chunks;
    let payload_hash = first.payload_hash;

    if total_chunks == 0 {
        return Err(EnvelopeError::DeserializationFailed(
            "total_chunks must be >= 1".into(),
        ));
    }

    if total_chunks > MAX_TOTAL_CHUNKS {
        return Err(EnvelopeError::DeserializationFailed(format!(
            "total_chunks {total_chunks} exceeds MAX_TOTAL_CHUNKS ({MAX_TOTAL_CHUNKS})"
        )));
    }

    if chunks.len() != total_chunks as usize {
        return Err(EnvelopeError::DeserializationFailed(format!(
            "expected {total_chunks} chunks, got {}",
            chunks.len()
        )));
    }

    // Validate consistency and collect into index-ordered slots.
    let mut slots: Vec<Option<&[u8]>> = vec![None; total_chunks as usize];

    for chunk in chunks {
        if chunk.message_id != message_id {
            return Err(EnvelopeError::DeserializationFailed(
                "mismatched message_id across chunks".into(),
            ));
        }
        if chunk.total_chunks != total_chunks {
            return Err(EnvelopeError::DeserializationFailed(format!(
                "mismatched total_chunks: expected {total_chunks}, got {}",
                chunk.total_chunks
            )));
        }
        if chunk.payload_hash != payload_hash {
            return Err(EnvelopeError::DeserializationFailed(
                "mismatched payload_hash across chunks".into(),
            ));
        }
        if chunk.chunk_index >= total_chunks {
            return Err(EnvelopeError::DeserializationFailed(format!(
                "chunk_index {} out of range [0, {total_chunks})",
                chunk.chunk_index
            )));
        }
        let idx = chunk.chunk_index as usize;
        if slots[idx].is_some() {
            return Err(EnvelopeError::DeserializationFailed(format!(
                "duplicate chunk_index {idx}"
            )));
        }
        slots[idx] = Some(&chunk.data);
    }

    // Concatenate in order. Pre-allocate based on total data size.
    let total_size: usize = slots.iter().filter_map(|s| s.map(<[u8]>::len)).sum();
    let mut reassembled = Vec::with_capacity(total_size);
    for (i, slot) in slots.iter().enumerate() {
        match slot {
            Some(data) => reassembled.extend_from_slice(data),
            None => {
                return Err(EnvelopeError::DeserializationFailed(format!(
                    "missing chunk at index {i}"
                )));
            }
        }
    }

    // Verify integrity.
    let actual_hash: [u8; 32] = Sha256::digest(&reassembled).into();
    if actual_hash != payload_hash {
        return Err(EnvelopeError::DeserializationFailed(
            "reassembled payload hash does not match payload_hash".into(),
        ));
    }

    Ok(reassembled)
}

/// Returns `true` if `payload` is too large for a single bucket and must be
/// chunked before transmission.
#[must_use]
pub const fn needs_chunking(payload: &[u8]) -> bool {
    // pad_to_bucket requires payload + 4-byte length suffix to fit in the
    // largest bucket (256 KB). If it doesn't fit, chunking is needed.
    payload.len() + 4 > BUCKET_SIZES[BUCKET_SIZES.len() - 1]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const TEST_DID: &str = "did:dht:test123";
    const TEST_TIMESTAMP: u64 = 1_700_000_000_000;

    #[test]
    fn small_payload_does_not_need_chunking() {
        let payload = vec![0xAB; 1024]; // 1 KB
        assert!(!needs_chunking(&payload));
    }

    #[test]
    fn payload_at_max_bucket_does_not_need_chunking() {
        // 256 KB minus 4-byte length suffix = max payload that fits.
        let payload = vec![0xAB; MAX_CHUNK_PAYLOAD_SIZE];
        assert!(!needs_chunking(&payload));
    }

    #[test]
    fn payload_over_max_bucket_needs_chunking() {
        let payload = vec![0xAB; MAX_CHUNK_PAYLOAD_SIZE + 1];
        assert!(needs_chunking(&payload));
    }

    #[test]
    fn split_empty_payload_fails() {
        let result = split_into_chunks(&[], TEST_DID, TEST_TIMESTAMP);
        assert!(result.is_err());
    }

    #[test]
    fn split_small_payload_produces_one_chunk() {
        let payload = vec![0xAB; 1024];
        let chunks = split_into_chunks(&payload, TEST_DID, TEST_TIMESTAMP).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].chunk_index, 0);
        assert_eq!(chunks[0].total_chunks, 1);
        assert_eq!(chunks[0].data, payload);
    }

    #[test]
    fn split_large_payload_produces_correct_chunks() {
        // 2.5 * MAX_CHUNK_PAYLOAD_SIZE => 3 chunks.
        let payload_size = MAX_CHUNK_PAYLOAD_SIZE * 2 + MAX_CHUNK_PAYLOAD_SIZE / 2;
        #[allow(clippy::cast_possible_truncation)]
        let payload: Vec<u8> = (0..payload_size).map(|i| (i % 256) as u8).collect();
        let chunks = split_into_chunks(&payload, TEST_DID, TEST_TIMESTAMP).unwrap();

        assert_eq!(chunks.len(), 3);
        #[allow(clippy::cast_possible_truncation)]
        for (i, chunk) in chunks.iter().enumerate() {
            assert_eq!(chunk.chunk_index, i as u32);
            assert_eq!(chunk.total_chunks, 3);
            assert_eq!(chunk.message_id, chunks[0].message_id);
            assert_eq!(chunk.payload_hash, chunks[0].payload_hash);
        }

        // First two chunks are full-size, last is partial.
        assert_eq!(chunks[0].data.len(), MAX_CHUNK_PAYLOAD_SIZE);
        assert_eq!(chunks[1].data.len(), MAX_CHUNK_PAYLOAD_SIZE);
        assert_eq!(chunks[2].data.len(), MAX_CHUNK_PAYLOAD_SIZE / 2);
    }

    #[test]
    fn split_exactly_at_boundary_produces_correct_chunks() {
        // Exactly 2 * MAX_CHUNK_PAYLOAD_SIZE => 2 chunks.
        let payload = vec![0xCD; MAX_CHUNK_PAYLOAD_SIZE * 2];
        let chunks = split_into_chunks(&payload, TEST_DID, TEST_TIMESTAMP).unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].data.len(), MAX_CHUNK_PAYLOAD_SIZE);
        assert_eq!(chunks[1].data.len(), MAX_CHUNK_PAYLOAD_SIZE);
    }

    #[test]
    fn roundtrip_split_reassemble() {
        let payload: Vec<u8> = (0..500_000_u32).flat_map(u32::to_le_bytes).collect();
        let chunks = split_into_chunks(&payload, TEST_DID, TEST_TIMESTAMP).unwrap();
        let reassembled = reassemble_chunks(&chunks).unwrap();
        assert_eq!(reassembled, payload);
    }

    #[test]
    fn reassemble_empty_fails() {
        let result = reassemble_chunks(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn reassemble_mismatched_message_id_fails() {
        let payload = vec![0xAB; MAX_CHUNK_PAYLOAD_SIZE * 2];
        let mut chunks = split_into_chunks(&payload, TEST_DID, TEST_TIMESTAMP).unwrap();
        chunks[1].message_id = [0xFF; 32]; // Tamper with message_id.
        let result = reassemble_chunks(&chunks);
        assert!(result.is_err());
    }

    #[test]
    fn reassemble_mismatched_total_chunks_fails() {
        let payload = vec![0xAB; MAX_CHUNK_PAYLOAD_SIZE * 2];
        let mut chunks = split_into_chunks(&payload, TEST_DID, TEST_TIMESTAMP).unwrap();
        chunks[1].total_chunks = 5; // Tamper with total_chunks.
        let result = reassemble_chunks(&chunks);
        assert!(result.is_err());
    }

    #[test]
    fn reassemble_duplicate_index_fails() {
        let payload = vec![0xAB; MAX_CHUNK_PAYLOAD_SIZE * 2];
        let mut chunks = split_into_chunks(&payload, TEST_DID, TEST_TIMESTAMP).unwrap();
        chunks[1].chunk_index = 0; // Duplicate.
        let result = reassemble_chunks(&chunks);
        assert!(result.is_err());
    }

    #[test]
    fn reassemble_corrupted_data_fails_integrity_check() {
        let payload = vec![0xAB; MAX_CHUNK_PAYLOAD_SIZE * 2];
        let mut chunks = split_into_chunks(&payload, TEST_DID, TEST_TIMESTAMP).unwrap();
        chunks[0].data[0] = 0xFF; // Corrupt data.
        let result = reassemble_chunks(&chunks);
        assert!(result.is_err());
    }

    #[test]
    fn reassemble_missing_chunk_fails() {
        let payload = vec![0xAB; MAX_CHUNK_PAYLOAD_SIZE * 3];
        let mut chunks = split_into_chunks(&payload, TEST_DID, TEST_TIMESTAMP).unwrap();
        chunks.remove(1); // Remove middle chunk.
        let result = reassemble_chunks(&chunks);
        assert!(result.is_err());
    }

    #[test]
    fn reassemble_out_of_order_succeeds() {
        let payload: Vec<u8> = (0..500_000_u32).flat_map(u32::to_le_bytes).collect();
        let mut chunks = split_into_chunks(&payload, TEST_DID, TEST_TIMESTAMP).unwrap();
        chunks.reverse(); // Deliver in reverse order.
        let reassembled = reassemble_chunks(&chunks).unwrap();
        assert_eq!(reassembled, payload);
    }

    #[test]
    fn message_id_is_deterministic() {
        let payload = vec![0xAB; 1024];
        let chunks_a = split_into_chunks(&payload, TEST_DID, TEST_TIMESTAMP).unwrap();
        let chunks_b = split_into_chunks(&payload, TEST_DID, TEST_TIMESTAMP).unwrap();
        assert_eq!(chunks_a[0].message_id, chunks_b[0].message_id);
    }

    #[test]
    fn message_id_differs_for_different_senders() {
        let payload = vec![0xAB; 1024];
        let chunks_a = split_into_chunks(&payload, "did:dht:alice", TEST_TIMESTAMP).unwrap();
        let chunks_b = split_into_chunks(&payload, "did:dht:bob", TEST_TIMESTAMP).unwrap();
        assert_ne!(chunks_a[0].message_id, chunks_b[0].message_id);
    }

    #[test]
    fn message_id_differs_for_different_timestamps() {
        let payload = vec![0xAB; 1024];
        let chunks_a = split_into_chunks(&payload, TEST_DID, 1_000).unwrap();
        let chunks_b = split_into_chunks(&payload, TEST_DID, 2_000).unwrap();
        assert_ne!(chunks_a[0].message_id, chunks_b[0].message_id);
    }

    #[test]
    fn chunk_envelope_serialization_roundtrip() {
        let payload = vec![0xAB; MAX_CHUNK_PAYLOAD_SIZE + 100];
        let chunks = split_into_chunks(&payload, TEST_DID, TEST_TIMESTAMP).unwrap();

        for chunk in &chunks {
            let serialized = rmp_serde::to_vec(chunk).unwrap();
            let deserialized: ChunkEnvelope = rmp_serde::from_slice(&serialized).unwrap();
            assert_eq!(&deserialized, chunk);
        }
    }

    #[test]
    fn single_chunk_roundtrip() {
        // A payload that fits in one chunk should still work through the
        // split/reassemble pipeline.
        let payload = vec![0x42; 100];
        let chunks = split_into_chunks(&payload, TEST_DID, TEST_TIMESTAMP).unwrap();
        assert_eq!(chunks.len(), 1);
        let reassembled = reassemble_chunks(&chunks).unwrap();
        assert_eq!(reassembled, payload);
    }
}
