//! CEK wrapping and unwrapping for the content access key layer (ADR-038, §9.17).
//!
//! Implements:
//! - AES-256-KW (RFC 3394) key wrapping and unwrapping.
//! - AES-256-GCM content encryption with AAD binding.
//! - `wrap_content` / `unwrap_content` combining both into the `WrappedContent` wire format.
//!
//! # Layer Ordering
//!
//! Access key wrapping occurs BEFORE sender key encryption (encrypted contexts)
//! or broadcast key encryption (broadcast contexts):
//!
//! ```text
//! Send:    plaintext → AES-GCM(CEK) → {ciphertext, wrapped_ceks} → sender/broadcast encrypt
//! Receive: sender/broadcast decrypt → unwrap_cek → AES-GCM_decrypt(CEK) → plaintext
//! ```
//!
//! # AES-256-GCM AAD
//!
//! Content encryption MUST bind `context_id || sender_did || sequence_number` as
//! additional authenticated data (AAD). This prevents cross-context ciphertext
//! relocation and message reordering attacks.
//!
//! # Integrity
//!
//! Integrity is verified by AES-256-GCM's authentication tag — no separate
//! content hash is stored. Storing SHA-256(plaintext) alongside ciphertext would
//! create a plaintext confirmation oracle (ADR-038 §4).

use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes_gcm::Aes256Gcm;
use aes_gcm::Nonce;
use aes_gcm::aead::{Aead, Payload};
use rand::RngCore;
use rand::rngs::OsRng;
use subtle::ConstantTimeEq;

use super::{
    AccessKey, AccessKeyError, ContentEncryptionKey, WrappedCek, WrappedContent, compute_member_id,
};

// ---------------------------------------------------------------------------
// AES-256-KW (RFC 3394) constants
// ---------------------------------------------------------------------------

/// RFC 3394 default Initial Value (IV).
const AES_KW_IV: [u8; 8] = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];

/// Number of 64-bit (8-byte) semiblocks in a 256-bit key.
const N_SEMIBLOCKS: usize = 4;

/// AES-256-GCM nonce size in bytes.
const NONCE_SIZE: usize = 12;

// ---------------------------------------------------------------------------
// AES-256-KW wrap / unwrap (RFC 3394)
// ---------------------------------------------------------------------------

/// Wraps a 32-byte CEK with a 32-byte access key using AES-256-KW (RFC 3394).
///
/// Produces a 40-byte output: 32-byte wrapped key + 8-byte integrity check value.
///
/// # Errors
///
/// Returns [`AccessKeyError::EncryptionFailed`] if AES cipher initialization fails
/// (should not occur with valid 32-byte key material).
pub fn wrap_cek(
    cek: &ContentEncryptionKey,
    access_key: &AccessKey,
) -> Result<[u8; 40], AccessKeyError> {
    let cipher = Aes256::new(GenericArray::from_slice(access_key.as_bytes()));

    // RFC 3394 §2.2.1 — Key Wrap
    // Input: plaintext key data as n 64-bit blocks R[1..n]
    // Output: (n+1) 64-bit blocks C[0..n] where C[0] is the integrity check

    let key_data = cek.as_bytes();
    let mut a = AES_KW_IV;
    let mut r = [[0u8; 8]; N_SEMIBLOCKS];
    for (idx, semiblock) in r.iter_mut().enumerate() {
        semiblock.copy_from_slice(&key_data[idx * 8..(idx + 1) * 8]);
    }

    // RFC 3394 §2.2.1: 6 rounds, n semiblocks per round
    for j in 0..6u64 {
        for (idx, semiblock) in r.iter_mut().enumerate() {
            // B = AES(A || R[i])
            let mut block = [0u8; 16];
            block[..8].copy_from_slice(&a);
            block[8..].copy_from_slice(semiblock);
            let block_ga = GenericArray::from_mut_slice(&mut block);
            cipher.encrypt_block(block_ga);

            // A = MSB(64, B) XOR t where t = (n*j)+i+1
            let t = (N_SEMIBLOCKS as u64) * j + (idx as u64) + 1;
            a.copy_from_slice(&block[..8]);
            let t_bytes = t.to_be_bytes();
            for (byte, xor_byte) in a.iter_mut().zip(t_bytes.iter()) {
                *byte ^= xor_byte;
            }

            // R[i] = LSB(64, B)
            semiblock.copy_from_slice(&block[8..]);
        }
    }

    // Output: A || R[1] || ... || R[n]
    let mut output = [0u8; 40];
    output[..8].copy_from_slice(&a);
    for (idx, semiblock) in r.iter().enumerate() {
        output[8 + idx * 8..8 + (idx + 1) * 8].copy_from_slice(semiblock);
    }

    Ok(output)
}

/// Unwraps a 40-byte wrapped CEK using a 32-byte access key via AES-256-KW (RFC 3394).
///
/// Verifies the integrity check value. Returns the unwrapped 32-byte CEK.
///
/// # Errors
///
/// - [`AccessKeyError::InvalidWrappedKeyLength`] if the input is not 40 bytes.
/// - [`AccessKeyError::KeyUnwrapFailed`] if the integrity check fails (wrong
///   access key or tampered data).
pub fn unwrap_cek(
    wrapped: &[u8; 40],
    access_key: &AccessKey,
) -> Result<ContentEncryptionKey, AccessKeyError> {
    let cipher = Aes256::new(GenericArray::from_slice(access_key.as_bytes()));

    // RFC 3394 §2.2.2 — Key Unwrap
    let mut a = [0u8; 8];
    a.copy_from_slice(&wrapped[..8]);
    let mut r = [[0u8; 8]; N_SEMIBLOCKS];
    for (idx, semiblock) in r.iter_mut().enumerate() {
        semiblock.copy_from_slice(&wrapped[8 + idx * 8..8 + (idx + 1) * 8]);
    }

    // 6 rounds in reverse
    for j in (0..6u64).rev() {
        for idx in (0..N_SEMIBLOCKS).rev() {
            // t = (n*j)+i+1
            let t = (N_SEMIBLOCKS as u64) * j + (idx as u64) + 1;

            // A = A XOR t
            let t_bytes = t.to_be_bytes();
            for (byte, xor_byte) in a.iter_mut().zip(t_bytes.iter()) {
                *byte ^= xor_byte;
            }

            // B = AES^-1(A || R[i])
            let mut block = [0u8; 16];
            block[..8].copy_from_slice(&a);
            block[8..].copy_from_slice(&r[idx]);
            let block_ga = GenericArray::from_mut_slice(&mut block);
            cipher.decrypt_block(block_ga);

            // A = MSB(64, B)
            a.copy_from_slice(&block[..8]);
            // R[i] = LSB(64, B)
            r[idx].copy_from_slice(&block[8..]);
        }
    }

    // Verify integrity check value (constant-time to prevent timing oracle)
    if !bool::from(a.ct_eq(&AES_KW_IV)) {
        return Err(AccessKeyError::KeyUnwrapFailed);
    }

    // Reconstruct the CEK
    let mut key_data = [0u8; 32];
    for (idx, semiblock) in r.iter().enumerate() {
        key_data[idx * 8..(idx + 1) * 8].copy_from_slice(semiblock);
    }

    Ok(ContentEncryptionKey::from_bytes(key_data))
}

// ---------------------------------------------------------------------------
// AAD construction
// ---------------------------------------------------------------------------

/// Constructs the AES-256-GCM additional authenticated data (AAD).
///
/// Per spec section 05-contexts.md line 979:
/// ```text
/// aad = context_id || sender_did || key_epoch_bytes || sequence_bytes
/// ```
/// Where `context_id` and `sender_did` are UTF-8 bytes with 4-byte BE length
/// prefixes, `key_epoch_bytes` is 8-byte big-endian, and `sequence_bytes` is
/// 8-byte big-endian.
///
/// Length prefixes prevent field-boundary ambiguity (e.g., a `context_id`
/// "ab" + `sender_did` "cd" would otherwise collide with "abc" + "d").
///
/// This prevents cross-context ciphertext relocation, epoch substitution,
/// and message reordering. See ADR-038 and spec section 9.17.1.
fn build_aad(context_id: &str, sender_did: &str, key_epoch: u64, sequence_number: u64) -> Vec<u8> {
    let ctx_bytes = context_id.as_bytes();
    let did_bytes = sender_did.as_bytes();
    let mut aad = Vec::with_capacity(4 + ctx_bytes.len() + 4 + did_bytes.len() + 8 + 8);
    // context_id with u32 BE length prefix
    #[allow(clippy::cast_possible_truncation)] // DID/context strings are well under u32::MAX bytes
    aad.extend_from_slice(&(ctx_bytes.len() as u32).to_be_bytes());
    aad.extend_from_slice(ctx_bytes);
    // sender_did with u32 BE length prefix
    #[allow(clippy::cast_possible_truncation)] // DID/context strings are well under u32::MAX bytes
    aad.extend_from_slice(&(did_bytes.len() as u32).to_be_bytes());
    aad.extend_from_slice(did_bytes);
    // key_epoch as 8-byte big-endian
    aad.extend_from_slice(&key_epoch.to_be_bytes());
    // sequence_number as 8-byte big-endian
    aad.extend_from_slice(&sequence_number.to_be_bytes());
    aad
}

// ---------------------------------------------------------------------------
// Recipient type for wrap_content
// ---------------------------------------------------------------------------

/// A recipient for content wrapping: DID string + access key.
pub struct Recipient<'a> {
    /// The member's DID string (e.g., "did:dht:z6Mk...").
    pub did: &'a str,
    /// The member's access key for this context.
    pub access_key: &'a AccessKey,
}

// ---------------------------------------------------------------------------
// wrap_content / unwrap_content
// ---------------------------------------------------------------------------

/// Encrypts plaintext and wraps the CEK for each recipient.
///
/// 1. Generates a fresh random CEK (32 bytes).
/// 2. Encrypts the plaintext with AES-256-GCM using the CEK.
///    AAD per spec section 05-contexts.md line 979 (length-prefixed fields + `key_epoch`).
/// 3. Wraps the CEK with each recipient's access key using AES-256-KW.
/// 4. Returns a `WrappedContent` containing ciphertext, nonce, and wrapped CEKs.
///
/// The `wrapped_ceks` list is sorted by `member_id` for deterministic
/// serialization (ADR-038 §4).
///
/// # Errors
///
/// Returns [`AccessKeyError::EncryptionFailed`] if AES-GCM encryption fails.
pub fn wrap_content(
    plaintext: &[u8],
    recipients: &[Recipient<'_>],
    context_id: &str,
    sender_did: &str,
    key_epoch: u64,
    sequence_number: u64,
) -> Result<WrappedContent, AccessKeyError> {
    // 1. Generate fresh CEK
    let cek = ContentEncryptionKey::generate();

    // 2. Encrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(cek.as_bytes())
        .map_err(|e| AccessKeyError::EncryptionFailed(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = build_aad(context_id, sender_did, key_epoch, sequence_number);
    let payload = Payload {
        msg: plaintext,
        aad: &aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| AccessKeyError::EncryptionFailed(e.to_string()))?;

    // 3. Wrap CEK for each recipient
    let mut wrapped_ceks = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let member_id = compute_member_id(recipient.did);
        let wrapped_key = wrap_cek(&cek, recipient.access_key)?;
        wrapped_ceks.push(WrappedCek {
            member_id,
            wrapped_key,
        });
    }

    // Sort by member_id for deterministic serialization
    wrapped_ceks.sort_by_key(|wk| wk.member_id);

    Ok(WrappedContent {
        ciphertext,
        nonce: nonce_bytes,
        wrapped_ceks,
    })
}

/// Unwraps and decrypts content for a specific member.
///
/// 1. Computes the member's `member_id` from their DID.
/// 2. Finds the corresponding `WrappedCek` in the `wrapped_ceks` list.
/// 3. Unwraps the CEK using the member's access key (AES-256-KW).
/// 4. Decrypts the ciphertext with AES-256-GCM using the unwrapped CEK.
///    AAD per spec section 05-contexts.md line 979 (length-prefixed fields + `key_epoch`).
///
/// # Errors
///
/// - [`AccessKeyError::NotRecipient`] if the member's `member_id` is not in `wrapped_ceks`.
/// - [`AccessKeyError::KeyUnwrapFailed`] if the access key is wrong (AES-256-KW integrity check fails).
/// - [`AccessKeyError::IntegrityFailure`] if the AEAD tag verification fails (content tampered or
///   AAD mismatch — e.g., wrong `context_id` for cross-context relocation detection).
pub fn unwrap_content(
    wrapped: &WrappedContent,
    member_did: &str,
    access_key: &AccessKey,
    context_id: &str,
    sender_did: &str,
    key_epoch: u64,
    sequence_number: u64,
) -> Result<Vec<u8>, AccessKeyError> {
    // 1. Compute truncated DID hash for recipient lookup
    let lookup_id = compute_member_id(member_did);

    // 2. Find the wrapped CEK for this member
    let wrapped_cek = wrapped
        .wrapped_ceks
        .iter()
        .find(|wc| wc.member_id == lookup_id)
        .ok_or(AccessKeyError::NotRecipient)?;

    // 3. Unwrap the CEK
    let cek = unwrap_cek(&wrapped_cek.wrapped_key, access_key)?;

    // 4. Decrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(cek.as_bytes())
        .map_err(|e| AccessKeyError::EncryptionFailed(e.to_string()))?;

    let nonce = Nonce::from_slice(&wrapped.nonce);
    let aad = build_aad(context_id, sender_did, key_epoch, sequence_number);
    let payload = Payload {
        msg: &wrapped.ciphertext,
        aad: &aad,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|_| AccessKeyError::IntegrityFailure)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::access_keys::generate_access_key;

    // -- AES-256-KW wrap/unwrap tests --

    #[test]
    fn wrap_unwrap_cek_roundtrip() {
        let access_key = generate_access_key("ctx-test", "did:dht:test");
        let cek = ContentEncryptionKey::generate();
        let original_bytes = *cek.as_bytes();

        let wrapped = wrap_cek(&cek, &access_key).unwrap();
        assert_eq!(wrapped.len(), 40, "wrapped CEK must be 40 bytes");

        let unwrapped = unwrap_cek(&wrapped, &access_key).unwrap();
        assert_eq!(unwrapped.as_bytes(), &original_bytes);
    }

    #[test]
    fn unwrap_cek_wrong_key_fails() {
        let key1 = generate_access_key("ctx-test", "did:dht:test");
        let key2 = generate_access_key("ctx-test", "did:dht:test");
        let cek = ContentEncryptionKey::generate();

        let wrapped = wrap_cek(&cek, &key1).unwrap();
        let result = unwrap_cek(&wrapped, &key2);
        assert!(
            matches!(result, Err(AccessKeyError::KeyUnwrapFailed)),
            "unwrap with wrong key should fail, got {result:?}"
        );
    }

    #[test]
    fn unwrap_cek_tampered_data_fails() {
        let access_key = generate_access_key("ctx-test", "did:dht:test");
        let cek = ContentEncryptionKey::generate();

        let mut wrapped = wrap_cek(&cek, &access_key).unwrap();
        // Tamper with a byte in the wrapped key
        wrapped[20] ^= 0xFF;

        let result = unwrap_cek(&wrapped, &access_key);
        assert!(
            matches!(result, Err(AccessKeyError::KeyUnwrapFailed)),
            "unwrap with tampered data should fail, got {result:?}"
        );
    }

    // -- wrap_content / unwrap_content tests --

    #[test]
    fn wrap_unwrap_content_single_recipient() {
        let access_key = generate_access_key("ctx-test", "did:dht:test");
        let did = "did:dht:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
        let context_id = "ctx-test-123";
        let sender_did = "did:dht:z6MkSender";
        let seq = 42u64;
        let plaintext = b"Hello, SCP!";

        let recipients = vec![Recipient {
            did,
            access_key: &access_key,
        }];

        let wrapped = wrap_content(plaintext, &recipients, context_id, sender_did, 0, seq).unwrap();

        assert_eq!(wrapped.wrapped_ceks.len(), 1);
        assert_eq!(wrapped.nonce.len(), 12);

        let decrypted =
            unwrap_content(&wrapped, did, &access_key, context_id, sender_did, 0, seq).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrap_unwrap_content_multiple_recipients() {
        let key_alice = generate_access_key("ctx-test", "did:dht:test");
        let key_bob = generate_access_key("ctx-test", "did:dht:test");
        let key_charlie = generate_access_key("ctx-test", "did:dht:test");
        let did_alice = "did:dht:z6MkAlice";
        let did_bob = "did:dht:z6MkBob";
        let did_charlie = "did:dht:z6MkCharlie";
        let context_id = "ctx-multi";
        let sender_did = "did:dht:z6MkSender";
        let seq = 1u64;
        let plaintext = b"Message for everyone";

        let recipients = vec![
            Recipient {
                did: did_alice,
                access_key: &key_alice,
            },
            Recipient {
                did: did_bob,
                access_key: &key_bob,
            },
            Recipient {
                did: did_charlie,
                access_key: &key_charlie,
            },
        ];

        let wrapped = wrap_content(plaintext, &recipients, context_id, sender_did, 0, seq).unwrap();
        assert_eq!(wrapped.wrapped_ceks.len(), 3);

        // Each recipient can decrypt
        let dec_alice = unwrap_content(
            &wrapped, did_alice, &key_alice, context_id, sender_did, 0, seq,
        )
        .unwrap();
        assert_eq!(dec_alice, plaintext);

        let dec_bob =
            unwrap_content(&wrapped, did_bob, &key_bob, context_id, sender_did, 0, seq).unwrap();
        assert_eq!(dec_bob, plaintext);

        let dec_charlie = unwrap_content(
            &wrapped,
            did_charlie,
            &key_charlie,
            context_id,
            sender_did,
            0,
            seq,
        )
        .unwrap();
        assert_eq!(dec_charlie, plaintext);
    }

    #[test]
    fn unwrap_content_not_recipient() {
        let key_alice = generate_access_key("ctx-test", "did:dht:test");
        let key_eve = generate_access_key("ctx-test", "did:dht:test");
        let did_alice = "did:dht:z6MkAlice";
        let did_eve = "did:dht:z6MkEve";
        let context_id = "ctx-test";
        let sender_did = "did:dht:z6MkSender";
        let seq = 1u64;
        let plaintext = b"Secret";

        let recipients = vec![Recipient {
            did: did_alice,
            access_key: &key_alice,
        }];

        let wrapped = wrap_content(plaintext, &recipients, context_id, sender_did, 0, seq).unwrap();

        // Eve is not a recipient
        let result = unwrap_content(&wrapped, did_eve, &key_eve, context_id, sender_did, 0, seq);
        assert!(
            matches!(result, Err(AccessKeyError::NotRecipient)),
            "non-recipient should get NotRecipient error, got {result:?}"
        );
    }

    #[test]
    fn unwrap_content_wrong_access_key() {
        let key_alice = generate_access_key("ctx-test", "did:dht:test");
        let key_wrong = generate_access_key("ctx-test", "did:dht:test");
        let did_alice = "did:dht:z6MkAlice";
        let context_id = "ctx-test";
        let sender_did = "did:dht:z6MkSender";
        let seq = 1u64;
        let plaintext = b"Secret";

        let recipients = vec![Recipient {
            did: did_alice,
            access_key: &key_alice,
        }];

        let wrapped = wrap_content(plaintext, &recipients, context_id, sender_did, 0, seq).unwrap();

        // Alice tries with wrong key
        let result = unwrap_content(
            &wrapped, did_alice, &key_wrong, context_id, sender_did, 0, seq,
        );
        assert!(
            matches!(result, Err(AccessKeyError::KeyUnwrapFailed)),
            "wrong access key should fail at key unwrap, got {result:?}"
        );
    }

    #[test]
    fn unwrap_content_tampered_ciphertext() {
        let access_key = generate_access_key("ctx-test", "did:dht:test");
        let did = "did:dht:z6MkAlice";
        let context_id = "ctx-test";
        let sender_did = "did:dht:z6MkSender";
        let seq = 1u64;
        let plaintext = b"Integrity test";

        let recipients = vec![Recipient {
            did,
            access_key: &access_key,
        }];

        let mut wrapped =
            wrap_content(plaintext, &recipients, context_id, sender_did, 0, seq).unwrap();

        // Tamper with the ciphertext
        if let Some(byte) = wrapped.ciphertext.get_mut(5) {
            *byte ^= 0xFF;
        }

        let result = unwrap_content(&wrapped, did, &access_key, context_id, sender_did, 0, seq);
        assert!(
            matches!(result, Err(AccessKeyError::IntegrityFailure)),
            "tampered ciphertext should fail with IntegrityFailure, got {result:?}"
        );
    }

    #[test]
    fn unwrap_content_wrong_context_id_fails() {
        let access_key = generate_access_key("ctx-test", "did:dht:test");
        let did = "did:dht:z6MkAlice";
        let context_id = "ctx-original";
        let wrong_context_id = "ctx-relocated";
        let sender_did = "did:dht:z6MkSender";
        let seq = 1u64;
        let plaintext = b"Cross-context relocation test";

        let recipients = vec![Recipient {
            did,
            access_key: &access_key,
        }];

        let wrapped = wrap_content(plaintext, &recipients, context_id, sender_did, 0, seq).unwrap();

        // Attempt to decrypt with wrong context_id (simulating cross-context relocation)
        let result = unwrap_content(
            &wrapped,
            did,
            &access_key,
            wrong_context_id,
            sender_did,
            0,
            seq,
        );
        assert!(
            matches!(result, Err(AccessKeyError::IntegrityFailure)),
            "wrong context_id should fail with IntegrityFailure (AAD mismatch), got {result:?}"
        );
    }

    #[test]
    fn unwrap_content_wrong_sender_did_fails() {
        let access_key = generate_access_key("ctx-test", "did:dht:test");
        let did = "did:dht:z6MkAlice";
        let context_id = "ctx-test";
        let sender_did = "did:dht:z6MkSender";
        let wrong_sender = "did:dht:z6MkImpersonator";
        let seq = 1u64;
        let plaintext = b"Sender binding test";

        let recipients = vec![Recipient {
            did,
            access_key: &access_key,
        }];

        let wrapped = wrap_content(plaintext, &recipients, context_id, sender_did, 0, seq).unwrap();

        let result = unwrap_content(&wrapped, did, &access_key, context_id, wrong_sender, 0, seq);
        assert!(
            matches!(result, Err(AccessKeyError::IntegrityFailure)),
            "wrong sender_did should fail with IntegrityFailure (AAD mismatch), got {result:?}"
        );
    }

    #[test]
    fn unwrap_content_wrong_sequence_number_fails() {
        let access_key = generate_access_key("ctx-test", "did:dht:test");
        let did = "did:dht:z6MkAlice";
        let context_id = "ctx-test";
        let sender_did = "did:dht:z6MkSender";
        let seq = 1u64;
        let wrong_seq = 2u64;
        let plaintext = b"Sequence binding test";

        let recipients = vec![Recipient {
            did,
            access_key: &access_key,
        }];

        let wrapped = wrap_content(plaintext, &recipients, context_id, sender_did, 0, seq).unwrap();

        let result = unwrap_content(
            &wrapped,
            did,
            &access_key,
            context_id,
            sender_did,
            0,
            wrong_seq,
        );
        assert!(
            matches!(result, Err(AccessKeyError::IntegrityFailure)),
            "wrong sequence_number should fail with IntegrityFailure (AAD mismatch), got {result:?}"
        );
    }

    #[test]
    fn wrapped_ceks_sorted_by_member_id() {
        let key_a = generate_access_key("ctx-test", "did:dht:test");
        let key_b = generate_access_key("ctx-test", "did:dht:test");
        let key_c = generate_access_key("ctx-test", "did:dht:test");
        let context_id = "ctx-sort";
        let sender_did = "did:dht:z6MkSender";
        let seq = 1u64;

        let recipients = vec![
            Recipient {
                did: "did:dht:z6MkZzz",
                access_key: &key_a,
            },
            Recipient {
                did: "did:dht:z6MkAaa",
                access_key: &key_b,
            },
            Recipient {
                did: "did:dht:z6MkMmm",
                access_key: &key_c,
            },
        ];

        let wrapped = wrap_content(b"test", &recipients, context_id, sender_did, 0, seq).unwrap();

        // Verify sorted order
        for i in 1..wrapped.wrapped_ceks.len() {
            assert!(
                wrapped.wrapped_ceks[i - 1].member_id <= wrapped.wrapped_ceks[i].member_id,
                "wrapped_ceks must be sorted by member_id"
            );
        }
    }

    #[test]
    fn wrapped_content_msgpack_roundtrip() {
        let access_key = generate_access_key("ctx-test", "did:dht:test");
        let did = "did:dht:z6MkAlice";
        let context_id = "ctx-msgpack";
        let sender_did = "did:dht:z6MkSender";
        let seq = 1u64;
        let plaintext = b"MessagePack roundtrip test";

        let recipients = vec![Recipient {
            did,
            access_key: &access_key,
        }];

        let wrapped = wrap_content(plaintext, &recipients, context_id, sender_did, 0, seq).unwrap();

        // Serialize to MessagePack
        let encoded =
            rmp_serde::to_vec(&wrapped).expect("MessagePack serialization should succeed");

        // Deserialize from MessagePack
        let decoded: WrappedContent =
            rmp_serde::from_slice(&encoded).expect("MessagePack deserialization should succeed");

        // Verify fields match
        assert_eq!(decoded.ciphertext, wrapped.ciphertext);
        assert_eq!(decoded.nonce, wrapped.nonce);
        assert_eq!(decoded.wrapped_ceks.len(), wrapped.wrapped_ceks.len());
        for (orig, dec) in wrapped.wrapped_ceks.iter().zip(decoded.wrapped_ceks.iter()) {
            assert_eq!(orig.member_id, dec.member_id);
            assert_eq!(orig.wrapped_key, dec.wrapped_key);
        }

        // Verify that deserialized content can still be decrypted
        let decrypted =
            unwrap_content(&decoded, did, &access_key, context_id, sender_did, 0, seq).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrap_content_empty_plaintext() {
        let access_key = generate_access_key("ctx-test", "did:dht:test");
        let did = "did:dht:z6MkAlice";
        let context_id = "ctx-empty";
        let sender_did = "did:dht:z6MkSender";
        let seq = 0u64;

        let recipients = vec![Recipient {
            did,
            access_key: &access_key,
        }];

        let wrapped = wrap_content(b"", &recipients, context_id, sender_did, 0, seq).unwrap();

        let decrypted =
            unwrap_content(&wrapped, did, &access_key, context_id, sender_did, 0, seq).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn wrap_content_large_plaintext() {
        let access_key = generate_access_key("ctx-test", "did:dht:test");
        let did = "did:dht:z6MkAlice";
        let context_id = "ctx-large";
        let sender_did = "did:dht:z6MkSender";
        let seq = 999u64;

        let plaintext = vec![0xAB_u8; 64 * 1024]; // 64 KiB

        let recipients = vec![Recipient {
            did,
            access_key: &access_key,
        }];

        let wrapped =
            wrap_content(&plaintext, &recipients, context_id, sender_did, 0, seq).unwrap();

        let decrypted =
            unwrap_content(&wrapped, did, &access_key, context_id, sender_did, 0, seq).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// RFC 3394 test vector: 256-bit KEK, 256-bit key data.
    /// From RFC 3394 §4.6.
    #[test]
    fn rfc3394_test_vector_256bit_kek_256bit_data() {
        let kek_bytes: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let key_data: [u8; 32] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F,
        ];
        let expected_wrapped: [u8; 40] = [
            0x28, 0xC9, 0xF4, 0x04, 0xC4, 0xB8, 0x10, 0xF4, 0xCB, 0xCC, 0xB3, 0x5C, 0xFB, 0x87,
            0xF8, 0x26, 0x3F, 0x57, 0x86, 0xE2, 0xD8, 0x0E, 0xD3, 0x26, 0xCB, 0xC7, 0xF0, 0xE7,
            0x1A, 0x99, 0xF4, 0x3B, 0xFB, 0x98, 0x8B, 0x9B, 0x7A, 0x02, 0xDD, 0x21,
        ];

        let kek = AccessKey::from_parts(
            kek_bytes,
            "ctx-test".to_owned(),
            "did:dht:test".to_owned(),
            0,
        );
        let cek = ContentEncryptionKey::from_bytes(key_data);

        let wrapped = wrap_cek(&cek, &kek).unwrap();
        assert_eq!(
            wrapped, expected_wrapped,
            "wrapped output must match RFC 3394 §4.6 test vector"
        );

        let unwrapped = unwrap_cek(&wrapped, &kek).unwrap();
        assert_eq!(
            unwrapped.as_bytes(),
            &key_data,
            "unwrapped must match original key data"
        );
    }
}
