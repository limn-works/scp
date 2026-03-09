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
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| SenderKeyError::EncryptionFailed(e.to_string()))?;

    // Wire format: nonce || ciphertext_with_tag
    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypts AES-256-GCM ciphertext produced by [`encrypt_sender_layer`].
///
/// Extracts the 12-byte nonce from the beginning of `ciphertext`, then
/// decrypts the remainder using the same AAD binding as the encrypt path.
/// Verifies the authentication tag (including AAD) and rejects tampered
/// or relocated ciphertext.
///
/// # Errors
///
/// - [`SenderKeyError::CiphertextTooShort`] if `ciphertext` is shorter than
///   the nonce size (12 bytes).
/// - [`SenderKeyError::AuthenticationFailed`] if the authentication tag
///   verification fails (tampered or corrupted ciphertext, or AAD mismatch).
pub fn decrypt_sender_layer(
    sender_key: &SenderKey,
    ciphertext: &[u8],
    context_id: &str,
    sender_did: &str,
    epoch: u64,
    sequence: u64,
) -> Result<Vec<u8>, SenderKeyError> {
    if ciphertext.len() < NONCE_SIZE {
        return Err(SenderKeyError::CiphertextTooShort {
            actual: ciphertext.len(),
            minimum: NONCE_SIZE,
        });
    }

    let (nonce_bytes, encrypted) = ciphertext.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(sender_key.as_bytes())
        .map_err(|e| SenderKeyError::EncryptionFailed(e.to_string()))?;

    let aad = build_sender_aad(context_id, sender_did, epoch, sequence);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: encrypted,
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

#[cfg(test)]
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
        #[allow(clippy::unwrap_used)]
        fn encrypt_decrypt_roundtrip(plaintext in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let key = generate_sender_key();
            let ciphertext = encrypt_sender_layer(&key, &plaintext, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ).unwrap();
            let decrypted = decrypt_sender_layer(&key, &ciphertext, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ).unwrap();
            prop_assert_eq!(plaintext, decrypted);
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn decrypt_rejects_tampered_ciphertext() {
        let key = generate_sender_key();
        let plaintext = b"hello world";
        let mut ciphertext =
            encrypt_sender_layer(&key, plaintext, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ)
                .unwrap();

        // Flip a byte in the encrypted portion (after the 12-byte nonce).
        let tamper_index = NONCE_SIZE + 1;
        ciphertext[tamper_index] ^= 0xFF;

        let result =
            decrypt_sender_layer(&key, &ciphertext, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(SenderKeyError::AuthenticationFailed)),
            "expected AuthenticationFailed, got {result:?}"
        );
    }

    #[test]
    fn decrypt_rejects_too_short_ciphertext() {
        let key = generate_sender_key();
        let short = vec![0u8; 5];
        let result = decrypt_sender_layer(&key, &short, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ);
        assert!(matches!(
            result,
            Err(SenderKeyError::CiphertextTooShort {
                actual: 5,
                minimum: 12
            })
        ));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn decrypt_with_wrong_key_fails() {
        let key1 = generate_sender_key();
        let key2 = generate_sender_key();
        let plaintext = b"secret message";
        let ciphertext =
            encrypt_sender_layer(&key1, plaintext, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ)
                .unwrap();

        let result =
            decrypt_sender_layer(&key2, &ciphertext, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ);
        assert!(matches!(result, Err(SenderKeyError::AuthenticationFailed)));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn ciphertext_starts_with_12_byte_nonce() {
        let key = generate_sender_key();
        let plaintext = b"test";
        let ciphertext =
            encrypt_sender_layer(&key, plaintext, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ)
                .unwrap();

        // Ciphertext should be: 12 (nonce) + plaintext.len() + 16 (tag)
        assert_eq!(ciphertext.len(), NONCE_SIZE + plaintext.len() + 16);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn decrypt_rejects_wrong_context_id() {
        let key = generate_sender_key();
        let plaintext = b"context-bound message";
        let ciphertext =
            encrypt_sender_layer(&key, plaintext, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ)
                .unwrap();

        let result = decrypt_sender_layer(
            &key,
            &ciphertext,
            "wrong-ctx",
            TEST_DID,
            TEST_EPOCH,
            TEST_SEQ,
        );
        assert!(
            matches!(result, Err(SenderKeyError::AuthenticationFailed)),
            "decryption with wrong context_id must fail"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn decrypt_rejects_wrong_sender_did() {
        let key = generate_sender_key();
        let plaintext = b"sender-bound message";
        let ciphertext =
            encrypt_sender_layer(&key, plaintext, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ)
                .unwrap();

        let result = decrypt_sender_layer(
            &key,
            &ciphertext,
            TEST_CTX,
            "did:dht:z6MkWrong",
            TEST_EPOCH,
            TEST_SEQ,
        );
        assert!(
            matches!(result, Err(SenderKeyError::AuthenticationFailed)),
            "decryption with wrong sender_did must fail"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn decrypt_rejects_wrong_epoch() {
        let key = generate_sender_key();
        let plaintext = b"epoch-bound message";
        let ciphertext =
            encrypt_sender_layer(&key, plaintext, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ)
                .unwrap();

        let result = decrypt_sender_layer(
            &key,
            &ciphertext,
            TEST_CTX,
            TEST_DID,
            TEST_EPOCH + 1,
            TEST_SEQ,
        );
        assert!(
            matches!(result, Err(SenderKeyError::AuthenticationFailed)),
            "decryption with wrong epoch must fail"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn decrypt_rejects_wrong_sequence() {
        let key = generate_sender_key();
        let plaintext = b"sequence-bound message";
        let ciphertext =
            encrypt_sender_layer(&key, plaintext, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ)
                .unwrap();

        let result = decrypt_sender_layer(
            &key,
            &ciphertext,
            TEST_CTX,
            TEST_DID,
            TEST_EPOCH,
            TEST_SEQ + 1,
        );
        assert!(
            matches!(result, Err(SenderKeyError::AuthenticationFailed)),
            "decryption with wrong sequence must fail"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn build_sender_aad_is_deterministic() {
        let aad1 = build_sender_aad("ctx-1", "did:dht:z6MkA", 5, 10);
        let aad2 = build_sender_aad("ctx-1", "did:dht:z6MkA", 5, 10);
        assert_eq!(aad1, aad2);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn build_sender_aad_differs_by_field() {
        let base = build_sender_aad("ctx-1", "did:dht:z6MkA", 5, 10);
        assert_ne!(base, build_sender_aad("ctx-2", "did:dht:z6MkA", 5, 10));
        assert_ne!(base, build_sender_aad("ctx-1", "did:dht:z6MkB", 5, 10));
        assert_ne!(base, build_sender_aad("ctx-1", "did:dht:z6MkA", 6, 10));
        assert_ne!(base, build_sender_aad("ctx-1", "did:dht:z6MkA", 5, 11));
    }
}
