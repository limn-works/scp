//! AES-256-GCM encryption and decryption for the sender-side key layer.
//!
//! Each sender in an SCP context maintains a symmetric AES-256 key. Messages
//! are encrypted with this key before MLS group encryption (double encryption).
//! This enables per-relationship blocking: rotating the sender key and
//! redistributing it to everyone except the blocked party makes the blocker's
//! future messages unreadable to the blocked party without removing them from
//! the MLS group. See ADR-007 in `.docs/adrs/phase-1.md`.
//!
//! # Wire Format
//!
//! The ciphertext produced by [`encrypt_sender_layer`] is:
//!
//! ```text
//! nonce (12 bytes) || ciphertext || auth_tag (16 bytes)
//! ```
//!
//! `aes-gcm` appends the 16-byte authentication tag to the ciphertext
//! automatically, so the output is `nonce || encrypted_data_with_tag`.

use aes_gcm::aead::Payload;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use rand::RngCore;
use rand::rngs::OsRng;

use super::{SenderKey, SenderKeyError};

/// Size of the AES-256-GCM nonce in bytes.
const NONCE_SIZE: usize = 12;

/// Encrypts `plaintext` with AES-256-GCM using the given sender key,
/// binding cleartext metadata as Additional Authenticated Data (AAD).
///
/// The AAD is a length-prefixed binary encoding of `context_id`,
/// `sender_did`, `epoch`, and `sequence` — the same format used by
/// [`build_broadcast_aad`](super::broadcast) — which prevents
/// ciphertext relocation across contexts, attribution forgery, and
/// epoch/sequence manipulation.
///
/// Generates a random 12-byte nonce per invocation. Returns
/// `nonce (12 bytes) || ciphertext || auth_tag (16 bytes)`.
///
/// # Errors
///
/// Returns [`SenderKeyError::EncryptionFailed`] if the underlying AEAD
/// operation fails (should not happen with valid key material).
pub fn encrypt_sender_layer(
    sender_key: &SenderKey,
    plaintext: &[u8],
    context_id: &str,
    sender_did: &str,
    epoch: u64,
    sequence: u64,
) -> Result<Vec<u8>, SenderKeyError> {
    let cipher = Aes256Gcm::new_from_slice(sender_key.as_bytes())
        .map_err(|e| SenderKeyError::EncryptionFailed(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = build_sender_aad(context_id, sender_did, epoch, sequence);
    let encrypted = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| SenderKeyError::EncryptionFailed(e.to_string()))?;

    let mut output = Vec::with_capacity(NONCE_SIZE + encrypted.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&encrypted);
    Ok(output)
}

/// Decrypts a sender-layer ciphertext previously produced by
/// [`encrypt_sender_layer`].
///
/// The caller must supply the same `context_id`, `sender_did`, `epoch`,
/// and `sequence` that were used at encryption time — they are bound into
/// the AAD and any mismatch will fail AEAD verification.
///
/// # Errors
///
/// Returns [`SenderKeyError::AuthenticationFailed`] if the ciphertext is
/// too short, the nonce is invalid, or AEAD verification fails.
pub fn decrypt_sender_layer(
    sender_key: &SenderKey,
    ciphertext: &[u8],
    context_id: &str,
    sender_did: &str,
    epoch: u64,
    sequence: u64,
) -> Result<Vec<u8>, SenderKeyError> {
    if ciphertext.len() < NONCE_SIZE {
        return Err(SenderKeyError::AuthenticationFailed);
    }

    let cipher = Aes256Gcm::new_from_slice(sender_key.as_bytes())
        .map_err(|_| SenderKeyError::AuthenticationFailed)?;

    let nonce = Nonce::from_slice(&ciphertext[..NONCE_SIZE]);
    let aad = build_sender_aad(context_id, sender_did, epoch, sequence);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ciphertext[NONCE_SIZE..],
                aad: &aad,
            },
        )
        .map_err(|_| SenderKeyError::AuthenticationFailed)
}

/// Builds the Additional Authenticated Data (AAD) for sender-layer
/// AES-256-GCM operations.
///
/// Format: length-prefixed binary —
/// `[4-byte context_id len (BE)][context_id bytes][4-byte DID len (BE)][DID bytes][8-byte epoch (BE)][8-byte sequence (BE)]`.
///
/// This is the same binary format used by [`build_broadcast_aad`](super::broadcast)
/// for broadcast keys, ensuring consistent AAD construction across sender
/// key variants.
#[allow(clippy::cast_possible_truncation)] // String lengths are always < 4 GiB
fn build_sender_aad(context_id: &str, sender_did: &str, epoch: u64, sequence: u64) -> Vec<u8> {
    let ctx_bytes = context_id.as_bytes();
    let did_bytes = sender_did.as_bytes();
    let mut aad = Vec::with_capacity(4 + ctx_bytes.len() + 4 + did_bytes.len() + 8 + 8);
    aad.extend_from_slice(&(ctx_bytes.len() as u32).to_be_bytes());
    aad.extend_from_slice(ctx_bytes);
    aad.extend_from_slice(&(did_bytes.len() as u32).to_be_bytes());
    aad.extend_from_slice(did_bytes);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad
}

/// Size of the epoch + sequence header in bytes.
pub const SENDER_HEADER_SIZE: usize = 16;

/// Prepends epoch + sequence header to sender-key ciphertext.
///
/// Wire format: `epoch (8 bytes BE) || sequence (8 bytes BE) || ciphertext`.
/// Used by [`ContextCryptoProvider::seal`] to construct the MLS plaintext.
#[must_use]
pub fn build_sender_header(epoch: u64, sequence: u64, ciphertext: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(SENDER_HEADER_SIZE + ciphertext.len());
    buf.extend_from_slice(&epoch.to_be_bytes());
    buf.extend_from_slice(&sequence.to_be_bytes());
    buf.extend_from_slice(ciphertext);
    buf
}

/// Parses epoch + sequence header from the front of `data`.
///
/// Returns `(epoch, sequence, ciphertext_slice)`.
///
/// # Errors
///
/// Returns an error string if `data` is shorter than [`SENDER_HEADER_SIZE`].
pub fn parse_sender_header(data: &[u8]) -> Result<(u64, u64, &[u8]), &'static str> {
    if data.len() < SENDER_HEADER_SIZE {
        return Err("sender key header too short");
    }
    // SAFETY: length validated above; slice sizes are exact.
    let epoch_bytes: [u8; 8] = match data[..8].try_into() {
        Ok(b) => b,
        Err(_) => return Err("sender key header too short"),
    };
    let seq_bytes: [u8; 8] = match data[8..16].try_into() {
        Ok(b) => b,
        Err(_) => return Err("sender key header too short"),
    };
    let epoch = u64::from_be_bytes(epoch_bytes);
    let sequence = u64::from_be_bytes(seq_bytes);
    Ok((epoch, sequence, &data[16..]))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::crypto::sender_keys::generate_sender_key;
    use proptest::prelude::*;

    const TEST_CTX: &str = "ctx-test-123";
    const TEST_DID: &str = "did:dht:z6MkTestSender";
    const TEST_EPOCH: u64 = 1;
    const TEST_SEQ: u64 = 42;

    proptest! {
        #[test]
        fn roundtrip_any_plaintext(plaintext in proptest::collection::vec(any::<u8>(), 0..512)) {
            let key = generate_sender_key();
            let ct = encrypt_sender_layer(&key, &plaintext, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ).unwrap();
            let pt = decrypt_sender_layer(&key, &ct, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ).unwrap();
            prop_assert_eq!(pt, plaintext);
        }
    }

    #[test]
    fn wrong_context_id_fails_aead() {
        let key = generate_sender_key();
        let plaintext = b"hello";
        let ct = encrypt_sender_layer(&key, plaintext, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ)
            .unwrap();
        let result = decrypt_sender_layer(&key, &ct, "wrong-ctx", TEST_DID, TEST_EPOCH, TEST_SEQ);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_sender_did_fails_aead() {
        let key = generate_sender_key();
        let plaintext = b"hello";
        let ct = encrypt_sender_layer(&key, plaintext, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ)
            .unwrap();
        let result =
            decrypt_sender_layer(&key, &ct, TEST_CTX, "did:dht:wrong", TEST_EPOCH, TEST_SEQ);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_epoch_fails_aead() {
        let key = generate_sender_key();
        let plaintext = b"hello";
        let ct = encrypt_sender_layer(&key, plaintext, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ)
            .unwrap();
        let result = decrypt_sender_layer(&key, &ct, TEST_CTX, TEST_DID, 999, TEST_SEQ);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_sequence_fails_aead() {
        let key = generate_sender_key();
        let plaintext = b"hello";
        let ct = encrypt_sender_layer(&key, plaintext, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ)
            .unwrap();
        let result = decrypt_sender_layer(&key, &ct, TEST_CTX, TEST_DID, TEST_EPOCH, 0);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_key_fails_aead() {
        let key = generate_sender_key();
        let wrong_key = generate_sender_key();
        let plaintext = b"hello";
        let ct = encrypt_sender_layer(&key, plaintext, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ)
            .unwrap();
        let result =
            decrypt_sender_layer(&wrong_key, &ct, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ);
        assert!(result.is_err());
    }

    #[test]
    fn truncated_ciphertext_fails() {
        let key = generate_sender_key();
        let result =
            decrypt_sender_layer(&key, &[0u8; 5], TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ);
        assert!(result.is_err());
    }

    #[test]
    fn header_roundtrip() {
        let epoch = 42u64;
        let seq = 99u64;
        let ct = b"ciphertext-payload";
        let header = build_sender_header(epoch, seq, ct);
        assert_eq!(header.len(), SENDER_HEADER_SIZE + ct.len());
        let (e, s, data) = parse_sender_header(&header).unwrap();
        assert_eq!(e, epoch);
        assert_eq!(s, seq);
        assert_eq!(data, ct);
    }

    #[test]
    fn parse_header_too_short() {
        assert!(parse_sender_header(&[0u8; 15]).is_err());
        assert!(parse_sender_header(&[]).is_err());
    }
}
