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

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use rand::RngCore;
use rand::rngs::OsRng;

use super::{SenderKey, SenderKeyError};

/// Size of the AES-256-GCM nonce in bytes.
const NONCE_SIZE: usize = 12;

/// Encrypts `plaintext` with AES-256-GCM using the given sender key.
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
) -> Result<Vec<u8>, SenderKeyError> {
    let cipher = Aes256Gcm::new_from_slice(sender_key.as_bytes())
        .map_err(|e| SenderKeyError::EncryptionFailed(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
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
/// decrypts the remainder. Verifies the authentication tag and rejects
/// tampered ciphertext.
///
/// # Errors
///
/// - [`SenderKeyError::CiphertextTooShort`] if `ciphertext` is shorter than
///   the nonce size (12 bytes).
/// - [`SenderKeyError::AuthenticationFailed`] if the authentication tag
///   verification fails (tampered or corrupted ciphertext).
pub fn decrypt_sender_layer(
    sender_key: &SenderKey,
    ciphertext: &[u8],
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

    cipher
        .decrypt(nonce, encrypted)
        .map_err(|_| SenderKeyError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sender_keys::generate_sender_key;
    use proptest::prelude::*;

    proptest! {
        #[test]
        #[allow(clippy::unwrap_used)]
        fn encrypt_decrypt_roundtrip(plaintext in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let key = generate_sender_key();
            let ciphertext = encrypt_sender_layer(&key, &plaintext).unwrap();
            let decrypted = decrypt_sender_layer(&key, &ciphertext).unwrap();
            prop_assert_eq!(plaintext, decrypted);
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn decrypt_rejects_tampered_ciphertext() {
        let key = generate_sender_key();
        let plaintext = b"hello world";
        let mut ciphertext = encrypt_sender_layer(&key, plaintext).unwrap();

        // Flip a byte in the encrypted portion (after the 12-byte nonce).
        let tamper_index = NONCE_SIZE + 1;
        ciphertext[tamper_index] ^= 0xFF;

        let result = decrypt_sender_layer(&key, &ciphertext);
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
        let result = decrypt_sender_layer(&key, &short);
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
        let ciphertext = encrypt_sender_layer(&key1, plaintext).unwrap();

        let result = decrypt_sender_layer(&key2, &ciphertext);
        assert!(matches!(result, Err(SenderKeyError::AuthenticationFailed)));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn ciphertext_starts_with_12_byte_nonce() {
        let key = generate_sender_key();
        let plaintext = b"test";
        let ciphertext = encrypt_sender_layer(&key, plaintext).unwrap();

        // Ciphertext should be: 12 (nonce) + plaintext.len() + 16 (tag)
        assert_eq!(ciphertext.len(), NONCE_SIZE + plaintext.len() + 16);
    }
}
