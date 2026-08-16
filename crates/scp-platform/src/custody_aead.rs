//! Shared AES-256-GCM sealing for one 32-byte private key entry.
//!
//! [`FileKeyCustody`] and [`SqliteKeyCustody`] both persist a 32-byte private
//! key beside a `key_type` discriminant that says whether those bytes are an
//! Ed25519 seed or an X25519 static secret. This module is the single place
//! that binds the two together: the caller passes the discriminant (and, where
//! the storage layer gives entries stable names, the entry's name) as
//! Additional Authenticated Data, so an altered discriminant makes the AEAD tag
//! fail rather than yielding the same 32 bytes under a different algorithm.
//!
//! # Why the binding matters
//!
//! `SigningKey::from_bytes` and `StaticSecret::from` both accept any 32 bytes,
//! so a discriminant stored outside the AEAD lets whoever can rewrite it decide
//! which algorithm consumes the key material. Reusing one seed as both an
//! Ed25519 signing key and an X25519 Diffie-Hellman secret breaks the domain
//! separation each algorithm's security argument assumes. GitHub issue #2299,
//! the unauthenticated `key_type` byte, records the two custody backends that
//! stored the discriminant unbound.
//!
//! # Sealed entry layout
//!
//! ```text
//! nonce (12 bytes) || ciphertext (32 bytes) || tag (16 bytes)   = 60 bytes
//! ```
//!
//! The nonce is drawn from `OsRng` for every seal. The AAD is not stored here —
//! each caller reconstructs it from data it already holds and passes it back to
//! [`open`].
//!
//! [`FileKeyCustody`]: crate::file::FileKeyCustody
//! [`SqliteKeyCustody`]: crate::sqlite::SqliteKeyCustody

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::error::PlatformError;

/// AES-256-GCM nonce length in bytes.
pub const NONCE_LEN: usize = 12;

/// Private key length in bytes (Ed25519 seed or X25519 static secret).
pub const KEY_LEN: usize = 32;

/// AES-256-GCM authentication tag length in bytes.
pub const TAG_LEN: usize = 16;

/// Length in bytes of one sealed entry: nonce, ciphertext, and tag.
pub const SEALED_LEN: usize = NONCE_LEN + KEY_LEN + TAG_LEN;

/// Seals one 32-byte private key under `wrapping_key`, binding `aad`.
///
/// Returns `nonce || ciphertext || tag`. Every call draws a fresh nonce from
/// `OsRng`, so sealing the same key twice produces different bytes.
///
/// # Errors
///
/// Returns [`PlatformError::CustodyError`] if the cipher rejects the wrapping
/// key or the AEAD encryption fails.
pub fn seal(
    wrapping_key: &[u8; KEY_LEN],
    private_key: &[u8; KEY_LEN],
    aad: &[u8],
) -> Result<[u8; SEALED_LEN], PlatformError> {
    let cipher = Aes256Gcm::new_from_slice(wrapping_key)
        .map_err(|e| PlatformError::CustodyError(format!("cipher init failed: {e}")))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: private_key.as_slice(),
                aad,
            },
        )
        .map_err(|e| PlatformError::CustodyError(format!("encryption failed: {e}")))?;

    if ciphertext.len() != KEY_LEN + TAG_LEN {
        return Err(PlatformError::CustodyError(format!(
            "sealed key has wrong length: expected {}, got {}",
            KEY_LEN + TAG_LEN,
            ciphertext.len()
        )));
    }

    let mut sealed = [0u8; SEALED_LEN];
    sealed[..NONCE_LEN].copy_from_slice(&nonce_bytes);
    sealed[NONCE_LEN..].copy_from_slice(&ciphertext);
    Ok(sealed)
}

/// Opens a sealed entry under `wrapping_key`, requiring `aad` to match the
/// value [`seal`] bound.
///
/// A caller that passes a different `key_type` discriminant than the one the
/// entry was sealed with gets a decryption failure here, never 32 bytes.
///
/// # Errors
///
/// Returns [`PlatformError::CustodyError`] if `sealed` is not
/// [`SEALED_LEN`] bytes, if the cipher rejects the wrapping key, or if the
/// AEAD tag does not verify — which covers a wrong wrapping key, altered
/// ciphertext, and an AAD that does not match the sealed one.
pub fn open(
    wrapping_key: &[u8; KEY_LEN],
    sealed: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, PlatformError> {
    if sealed.len() != SEALED_LEN {
        return Err(PlatformError::CustodyError(format!(
            "sealed key entry has wrong length: expected {SEALED_LEN}, got {}",
            sealed.len()
        )));
    }

    let cipher = Aes256Gcm::new_from_slice(wrapping_key)
        .map_err(|e| PlatformError::CustodyError(format!("cipher init failed: {e}")))?;
    let nonce = Nonce::from_slice(&sealed[..NONCE_LEN]);

    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &sealed[NONCE_LEN..],
                    aad,
                },
            )
            .map_err(|_| {
                PlatformError::CustodyError(
                    "decryption failed (wrong passphrase, altered key type, \
                     or tampered entry?)"
                        .to_owned(),
                )
            })?,
    );

    let mut key_bytes = Zeroizing::new([0u8; KEY_LEN]);
    if plaintext.len() != KEY_LEN {
        return Err(PlatformError::CustodyError(format!(
            "decrypted key has wrong length: expected {KEY_LEN}, got {}",
            plaintext.len()
        )));
    }
    key_bytes.copy_from_slice(&plaintext);
    Ok(key_bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const WRAPPING_KEY: [u8; KEY_LEN] = [0x5Au8; KEY_LEN];
    const PRIVATE_KEY: [u8; KEY_LEN] = [0x11u8; KEY_LEN];

    #[test]
    fn round_trips_under_matching_aad() {
        let sealed = seal(&WRAPPING_KEY, &PRIVATE_KEY, b"ed25519").unwrap();
        let opened = open(&WRAPPING_KEY, &sealed, b"ed25519").unwrap();
        assert_eq!(*opened, PRIVATE_KEY);
    }

    #[test]
    fn sealed_entry_is_sixty_bytes() {
        let sealed = seal(&WRAPPING_KEY, &PRIVATE_KEY, b"ed25519").unwrap();
        assert_eq!(sealed.len(), 60, "12-byte nonce + 32-byte ct + 16-byte tag");
    }

    #[test]
    fn mismatched_aad_fails_to_open() {
        let sealed = seal(&WRAPPING_KEY, &PRIVATE_KEY, b"ed25519").unwrap();
        let result = open(&WRAPPING_KEY, &sealed, b"x25519");
        assert!(
            result.is_err(),
            "a different AAD must fail the tag check, not return key bytes"
        );
    }

    #[test]
    fn wrong_wrapping_key_fails_to_open() {
        let sealed = seal(&WRAPPING_KEY, &PRIVATE_KEY, b"ed25519").unwrap();
        let result = open(&[0x00u8; KEY_LEN], &sealed, b"ed25519");
        assert!(
            result.is_err(),
            "a wrong wrapping key must fail the tag check"
        );
    }

    #[test]
    fn tampered_ciphertext_fails_to_open() {
        let mut sealed = seal(&WRAPPING_KEY, &PRIVATE_KEY, b"ed25519").unwrap();
        sealed[NONCE_LEN] ^= 0xFF;
        let result = open(&WRAPPING_KEY, &sealed, b"ed25519");
        assert!(
            result.is_err(),
            "a flipped ciphertext bit must fail the tag check"
        );
    }

    #[test]
    fn short_entry_is_rejected() {
        let result = open(&WRAPPING_KEY, &[0u8; SEALED_LEN - 1], b"ed25519");
        match result {
            Err(PlatformError::CustodyError(msg)) => {
                assert!(msg.contains("wrong length"), "got: {msg}");
            }
            other => panic!("expected a length error, got {other:?}"),
        }
    }

    #[test]
    fn two_seals_of_one_key_differ() {
        let first = seal(&WRAPPING_KEY, &PRIVATE_KEY, b"ed25519").unwrap();
        let second = seal(&WRAPPING_KEY, &PRIVATE_KEY, b"ed25519").unwrap();
        assert_ne!(first, second, "each seal must draw a fresh nonce");
    }
}
