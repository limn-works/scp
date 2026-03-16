//! WASM-local sender-side AES-256-GCM key layer.
//!
//! Ports `scp_core::crypto::sender_keys` into a WASM-compatible form.
//! Each sender in an SCP context maintains an AES-256 symmetric key.
//! Messages are encrypted with this key before MLS group encryption
//! (double encryption), enabling per-relationship blocking.
//!
//! # Wire Format
//!
//! The ciphertext produced by [`encrypt_sender_layer`] is:
//!
//! ```text
//! nonce (12 bytes) || ciphertext || auth_tag (16 bytes)
//! ```
//!
//! # AAD Format
//!
//! The AAD format MUST match `scp_core::crypto::sender_keys::encrypt::build_sender_aad`
//! exactly for cross-bridge conformance:
//!
//! ```text
//! [4-byte context_id len (BE)][context_id bytes][4-byte DID len (BE)][DID bytes][8-byte epoch (BE)][8-byte sequence (BE)]
//! ```
//!
//! See ADR-007 in `.docs/adrs/phase-1.md`.

use aes_gcm::aead::Payload;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::error::WasmCryptoError;

/// Size of the AES-256-GCM nonce in bytes.
const NONCE_SIZE: usize = 12;

/// Opaque handle for a 32-byte AES-256 sender key.
///
/// Key material is zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SenderKey([u8; 32]);

impl SenderKey {
    /// Creates a sender key from raw 32-byte key material.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns a reference to the raw 32-byte key material.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SenderKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SenderKey").field(&"[REDACTED]").finish()
    }
}

/// Generates a random 32-byte AES-256 sender key.
///
/// Uses the platform's cryptographically secure random number generator
/// (`WebCrypto`'s `getRandomValues` in WASM).
#[must_use]
pub fn generate_sender_key() -> SenderKey {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    SenderKey(bytes)
}

/// Encrypts `plaintext` with AES-256-GCM using the given sender key,
/// binding cleartext metadata as Additional Authenticated Data (AAD).
///
/// Returns `nonce (12 bytes) || ciphertext || auth_tag (16 bytes)`.
///
/// # Errors
///
/// Returns [`WasmCryptoError::SenderKeyError`] if encryption fails.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_sender_layer(
    sender_key: &SenderKey,
    plaintext: &[u8],
    context_id: &str,
    sender_did: &str,
    epoch: u64,
    sequence: u64,
) -> Result<Vec<u8>, WasmCryptoError> {
    let cipher = Aes256Gcm::new_from_slice(sender_key.as_bytes())
        .map_err(|e| WasmCryptoError::SenderKeyError(format!("key init: {e}")))?;

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
        .map_err(|e| WasmCryptoError::SenderKeyError(format!("encryption: {e}")))?;

    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypts AES-256-GCM ciphertext produced by [`encrypt_sender_layer`].
///
/// # Errors
///
/// - [`WasmCryptoError::CiphertextTooShort`] if `ciphertext` is shorter
///   than the nonce size.
/// - [`WasmCryptoError::AuthenticationFailed`] if the authentication tag
///   verification fails.
#[allow(clippy::too_many_arguments)]
pub fn decrypt_sender_layer(
    sender_key: &SenderKey,
    ciphertext: &[u8],
    context_id: &str,
    sender_did: &str,
    epoch: u64,
    sequence: u64,
) -> Result<Vec<u8>, WasmCryptoError> {
    if ciphertext.len() < NONCE_SIZE {
        return Err(WasmCryptoError::CiphertextTooShort {
            actual: ciphertext.len(),
            minimum: NONCE_SIZE,
        });
    }

    let (nonce_bytes, encrypted) = ciphertext.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(sender_key.as_bytes())
        .map_err(|e| WasmCryptoError::SenderKeyError(format!("key init: {e}")))?;

    let aad = build_sender_aad(context_id, sender_did, epoch, sequence);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: encrypted,
                aad: &aad,
            },
        )
        .map_err(|_| WasmCryptoError::AuthenticationFailed)
}

/// Builds the Additional Authenticated Data (AAD) for sender-layer
/// AES-256-GCM operations.
///
/// Format: `[4-byte context_id len (BE)][context_id bytes][4-byte DID len (BE)][DID bytes][8-byte epoch (BE)][8-byte sequence (BE)]`
///
/// This format MUST match `scp_core::crypto::sender_keys::encrypt::build_sender_aad`
/// exactly for cross-bridge conformance.
#[must_use]
#[allow(clippy::cast_possible_truncation)] // String lengths are always < 4 GiB
pub fn build_sender_aad(context_id: &str, sender_did: &str, epoch: u64, sequence: u64) -> Vec<u8> {
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

    const TEST_CTX: &str = "ctx-test-123";
    const TEST_DID: &str = "did:dht:z6MkTestSender";
    const TEST_EPOCH: u64 = 1;
    const TEST_SEQ: u64 = 42;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn encrypt_decrypt_roundtrip() {
        let key = generate_sender_key();
        let plaintext = b"hello world sender key";
        let ciphertext =
            encrypt_sender_layer(&key, plaintext, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ)
                .unwrap();
        let decrypted =
            decrypt_sender_layer(&key, &ciphertext, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ)
                .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn generate_sender_key_produces_32_bytes() {
        let key = generate_sender_key();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn generate_sender_key_produces_distinct_keys() {
        let key1 = generate_sender_key();
        let key2 = generate_sender_key();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn decrypt_rejects_tampered_ciphertext() {
        let key = generate_sender_key();
        let plaintext = b"tamper test";
        let mut ciphertext =
            encrypt_sender_layer(&key, plaintext, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ)
                .unwrap();

        // Flip a byte after the nonce.
        let tamper_index = NONCE_SIZE + 1;
        ciphertext[tamper_index] ^= 0xFF;

        let result =
            decrypt_sender_layer(&key, &ciphertext, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ);
        assert!(matches!(result, Err(WasmCryptoError::AuthenticationFailed)));
    }

    #[test]
    fn decrypt_rejects_too_short_ciphertext() {
        let key = generate_sender_key();
        let short = vec![0u8; 5];
        let result = decrypt_sender_layer(&key, &short, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ);
        assert!(matches!(
            result,
            Err(WasmCryptoError::CiphertextTooShort {
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
        let plaintext = b"wrong key test";
        let ciphertext =
            encrypt_sender_layer(&key1, plaintext, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ)
                .unwrap();

        let result =
            decrypt_sender_layer(&key2, &ciphertext, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ);
        assert!(matches!(result, Err(WasmCryptoError::AuthenticationFailed)));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn ciphertext_is_nonce_plus_payload_plus_tag() {
        let key = generate_sender_key();
        let plaintext = b"size test";
        let ciphertext =
            encrypt_sender_layer(&key, plaintext, TEST_CTX, TEST_DID, TEST_EPOCH, TEST_SEQ)
                .unwrap();

        // nonce(12) + plaintext(9) + tag(16) = 37
        assert_eq!(ciphertext.len(), NONCE_SIZE + plaintext.len() + 16);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn decrypt_rejects_wrong_context_id() {
        let key = generate_sender_key();
        let plaintext = b"context-bound";
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
        assert!(matches!(result, Err(WasmCryptoError::AuthenticationFailed)));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn decrypt_rejects_wrong_sender_did() {
        let key = generate_sender_key();
        let plaintext = b"sender-bound";
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
        assert!(matches!(result, Err(WasmCryptoError::AuthenticationFailed)));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn decrypt_rejects_wrong_epoch() {
        let key = generate_sender_key();
        let plaintext = b"epoch-bound";
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
        assert!(matches!(result, Err(WasmCryptoError::AuthenticationFailed)));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn decrypt_rejects_wrong_sequence() {
        let key = generate_sender_key();
        let plaintext = b"sequence-bound";
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
        assert!(matches!(result, Err(WasmCryptoError::AuthenticationFailed)));
    }

    #[test]
    fn build_sender_aad_is_deterministic() {
        let aad1 = build_sender_aad("ctx-1", "did:dht:z6MkA", 5, 10);
        let aad2 = build_sender_aad("ctx-1", "did:dht:z6MkA", 5, 10);
        assert_eq!(aad1, aad2);
    }

    #[test]
    fn build_sender_aad_differs_by_field() {
        let base = build_sender_aad("ctx-1", "did:dht:z6MkA", 5, 10);
        assert_ne!(base, build_sender_aad("ctx-2", "did:dht:z6MkA", 5, 10));
        assert_ne!(base, build_sender_aad("ctx-1", "did:dht:z6MkB", 5, 10));
        assert_ne!(base, build_sender_aad("ctx-1", "did:dht:z6MkA", 6, 10));
        assert_ne!(base, build_sender_aad("ctx-1", "did:dht:z6MkA", 5, 11));
    }

    #[test]
    fn sender_key_debug_redacts_material() {
        let key = generate_sender_key();
        let debug = format!("{key:?}");
        assert!(debug.contains("REDACTED"));
        assert!(
            !debug.contains(", "),
            "debug output should not contain raw byte values"
        );
    }
}
