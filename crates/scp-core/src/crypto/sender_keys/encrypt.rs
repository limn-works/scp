//! AES-256-GCM encryption and decryption for the sender-side key layer.
//!
//! Implements ADR-007 criteria 2 and 3: `encrypt_sender_layer` and
//! `decrypt_sender_layer`. The wire format is `nonce (12 bytes) || ciphertext || auth_tag (16 bytes)`.

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use rand::RngCore;

use super::{SenderKey, SenderKeyError};

/// Minimum ciphertext length: 12-byte nonce + 16-byte auth tag.
const MIN_CIPHERTEXT_LEN: usize = 12 + 16;

/// Encrypts plaintext with AES-256-GCM using the given sender key.
///
/// Generates a random 12-byte nonce per invocation. Returns
/// `nonce (12 bytes) || ciphertext || auth_tag (16 bytes)`.
///
/// See ADR-007 criterion 2.
///
/// # Errors
///
/// Returns [`SenderKeyError::EncryptionFailed`] if AES-256-GCM encryption fails.
pub fn encrypt_sender_layer(
    sender_key: &SenderKey,
    plaintext: &[u8],
) -> Result<Vec<u8>, SenderKeyError> {
    let cipher = Aes256Gcm::new((&sender_key.0).into());

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // aes-gcm encrypt returns ciphertext || auth_tag
    let ciphertext_with_tag = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| SenderKeyError::EncryptionFailed)?;

    // Wire format: nonce || ciphertext || auth_tag
    let mut output = Vec::with_capacity(12 + ciphertext_with_tag.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext_with_tag);
    Ok(output)
}

/// Decrypts AES-256-GCM ciphertext produced by [`encrypt_sender_layer`].
///
/// Expects the wire format `nonce (12 bytes) || ciphertext || auth_tag (16 bytes)`.
/// Rejects tampered ciphertext (authentication tag mismatch) and wrong keys.
///
/// See ADR-007 criterion 3.
///
/// # Errors
///
/// Returns [`SenderKeyError::CiphertextTooShort`] if the input is shorter than
/// 28 bytes (12-byte nonce + 16-byte auth tag).
///
/// Returns [`SenderKeyError::DecryptionFailed`] if the authentication tag does
/// not verify (wrong key or tampered ciphertext).
pub fn decrypt_sender_layer(
    sender_key: &SenderKey,
    ciphertext: &[u8],
) -> Result<Vec<u8>, SenderKeyError> {
    if ciphertext.len() < MIN_CIPHERTEXT_LEN {
        return Err(SenderKeyError::CiphertextTooShort {
            len: ciphertext.len(),
            min: MIN_CIPHERTEXT_LEN,
        });
    }

    let (nonce_bytes, ciphertext_with_tag) = ciphertext.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new((&sender_key.0).into());

    cipher
        .decrypt(nonce, ciphertext_with_tag)
        .map_err(|_| SenderKeyError::DecryptionFailed)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::sender_keys::generate_sender_key;
    use proptest::prelude::*;

    #[test]
    fn encrypt_then_decrypt_returns_original_plaintext() {
        let key = generate_sender_key();
        let plaintext = b"hello, SCP";
        let ciphertext = encrypt_sender_layer(&key, plaintext).expect("encryption should succeed");
        let decrypted = decrypt_sender_layer(&key, &ciphertext).expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_empty_plaintext_roundtrips() {
        let key = generate_sender_key();
        let ciphertext = encrypt_sender_layer(&key, b"").expect("encryption should succeed");
        let decrypted = decrypt_sender_layer(&key, &ciphertext).expect("decryption should succeed");
        assert!(decrypted.is_empty());
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let key = generate_sender_key();
        let plaintext = b"tamper test";
        let mut ciphertext =
            encrypt_sender_layer(&key, plaintext).expect("encryption should succeed");

        // Flip a byte in the ciphertext portion (after the 12-byte nonce)
        let idx = 12 + (ciphertext.len() - 12) / 2;
        ciphertext[idx] ^= 0xff;

        let result = decrypt_sender_layer(&key, &ciphertext);
        assert!(
            matches!(result, Err(SenderKeyError::DecryptionFailed)),
            "tampered ciphertext should be rejected"
        );
    }

    #[test]
    fn decrypt_rejects_wrong_key() {
        let key1 = generate_sender_key();
        let key2 = generate_sender_key();
        let plaintext = b"wrong key test";
        let ciphertext = encrypt_sender_layer(&key1, plaintext).expect("encryption should succeed");

        let result = decrypt_sender_layer(&key2, &ciphertext);
        assert!(
            matches!(result, Err(SenderKeyError::DecryptionFailed)),
            "wrong key should be rejected"
        );
    }

    #[test]
    fn decrypt_rejects_too_short_ciphertext() {
        let key = generate_sender_key();
        let short = vec![0u8; 10];
        let result = decrypt_sender_layer(&key, &short);
        assert!(
            matches!(
                result,
                Err(SenderKeyError::CiphertextTooShort { len: 10, min: 28 })
            ),
            "too-short ciphertext should be rejected"
        );
    }

    #[test]
    fn ciphertext_has_correct_structure() {
        let key = generate_sender_key();
        let plaintext = b"structure test";
        let ciphertext = encrypt_sender_layer(&key, plaintext).expect("encryption should succeed");

        // nonce (12) + plaintext len + auth tag (16)
        assert_eq!(ciphertext.len(), 12 + plaintext.len() + 16);
    }

    #[test]
    fn two_encryptions_produce_different_ciphertext() {
        let key = generate_sender_key();
        let plaintext = b"nonce uniqueness";
        let ct1 = encrypt_sender_layer(&key, plaintext).expect("encryption should succeed");
        let ct2 = encrypt_sender_layer(&key, plaintext).expect("encryption should succeed");

        // Different random nonces produce different ciphertext
        assert_ne!(ct1, ct2);
    }

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
}
