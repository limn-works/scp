//! Generalized ECIES envelope seal/open for arbitrary-length payloads.
//!
//! Reuses the HKDF-SHA256 + AES-128-GCM construction from `sender_keys/key_protocol.rs`
//! but with variable-length plaintext and invitation-specific domain separators.
//! Used for invitation bundle and join response encryption (spec §5.12.3).

use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Pub};
use zeroize::Zeroizing;

use super::sender_keys::key_protocol::{aes128gcm_decrypt, aes128gcm_encrypt, hkdf_derive_key};

/// Errors from envelope seal/open operations.
#[derive(Debug, thiserror::Error)]
pub enum EnvelopeSealError {
    /// ECIES encryption failed.
    #[error("ECIES encryption failed: {0}")]
    SealFailed(String),
    /// ECIES decryption failed.
    #[error("ECIES decryption failed: {0}")]
    OpenFailed(String),
}

/// Appends `data` to `buf` with a 4-byte big-endian length prefix.
///
/// Used by `build_invitation_info`, `build_invitation_aad`, and
/// `derive_routing_id` to enforce unambiguous field boundaries and prevent
/// boundary-shift attacks.
#[allow(clippy::cast_possible_truncation)]
fn append_length_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Derives a routing ID by hashing a DID with a domain separator.
/// Format: `SHA-256(len(did) || did || domain)` where `len` is a 4-byte
/// big-endian length prefix, preventing boundary-shift attacks where a DID
/// suffix could be confused with the domain prefix.
fn derive_routing_id(did: &str, domain: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let did_bytes = did.as_bytes();
    #[allow(clippy::cast_possible_truncation)]
    let did_len = did_bytes.len() as u32;
    hasher.update(did_len.to_be_bytes());
    hasher.update(did_bytes);
    hasher.update(domain);
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    bytes
}

/// Derives a personal invitation routing ID for a DID.
/// `SHA-256(len(did) || did || b"scp-invitations")` per spec §5.12.3.
#[must_use]
pub fn derive_invitation_routing_id(did: &str) -> [u8; 32] {
    derive_routing_id(did, b"scp-invitations")
}

/// Derives a key package routing ID for a DID.
/// `SHA-256(len(did) || did || b"scp-key-packages")`.
#[must_use]
pub fn derive_key_package_routing_id(did: &str) -> [u8; 32] {
    derive_routing_id(did, b"scp-key-packages")
}

/// Converts an Ed25519 public key to X25519 via birational mapping (RFC 7748).
/// `u = (1+y)/(1-y)` in the Edwards form, computed by `ed25519_dalek::VerifyingKey::to_montgomery`.
///
/// # Errors
///
/// Returns [`EnvelopeSealError::SealFailed`] if the 32-byte input is not a valid
/// Ed25519 public key.
pub fn ed25519_pubkey_to_x25519(ed25519_pub: &[u8; 32]) -> Result<[u8; 32], EnvelopeSealError> {
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(ed25519_pub)
        .map_err(|e| EnvelopeSealError::SealFailed(format!("invalid Ed25519 public key: {e}")))?;
    Ok(verifying_key.to_montgomery().to_bytes())
}

/// Builds the HKDF info string for invitation ECIES.
/// Format: `"scp-invitation-v1" || len(context_id) || context_id || len(creator_did) || creator_did`
fn build_invitation_info(context_id: &str, creator_did: &str) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(b"scp-invitation-v1");
    append_length_prefixed(&mut info, context_id.as_bytes());
    append_length_prefixed(&mut info, creator_did.as_bytes());
    info
}

/// Builds the AES-GCM AAD for invitation ECIES (distinct from HKDF info).
/// Format: `"scp-invitation-aad-v1" || len(context_id) || context_id || len(creator_did) || creator_did || ephemeral_pubkey[32]`
///
/// Including the ephemeral public key in the AAD binds the ciphertext to
/// the specific DH exchange, preventing ephemeral key substitution attacks.
fn build_invitation_aad(context_id: &str, creator_did: &str, ephemeral_pub: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(b"scp-invitation-aad-v1");
    append_length_prefixed(&mut aad, context_id.as_bytes());
    append_length_prefixed(&mut aad, creator_did.as_bytes());
    aad.extend_from_slice(ephemeral_pub);
    aad
}

/// ECIES-seals an arbitrary-length payload to a recipient's X25519 public key.
///
/// Returns `(sealed_bytes, ephemeral_pubkey)` where `sealed_bytes` = `nonce || ciphertext || tag`.
/// Uses HKDF-SHA256 + AES-128-GCM, matching the sender key ECIES construction.
///
/// # Errors
///
/// Returns [`EnvelopeSealError::SealFailed`] if encryption fails.
pub fn ecies_seal(
    plaintext: &[u8],
    recipient_x25519_pub: &[u8; 32],
    context_id: &str,
    creator_did: &str,
) -> Result<(Vec<u8>, [u8; 32]), EnvelopeSealError> {
    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let ephemeral_public = X25519Pub::from(&ephemeral_secret);
    let ephemeral_pub_bytes = ephemeral_public.to_bytes();

    let recipient_key = X25519Pub::from(*recipient_x25519_pub);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_key);

    let info = build_invitation_info(context_id, creator_did);
    let aad = build_invitation_aad(context_id, creator_did, &ephemeral_pub_bytes);

    // x25519-dalek v2 SharedSecret implements Zeroize + zeroize(drop) when the
    // zeroize feature is enabled (which it is). Wrapping in Zeroizing is
    // defense-in-depth — ensures zeroing even if the feature is ever removed.
    let shared_bytes = Zeroizing::new(*shared_secret.as_bytes());
    let aes_key = hkdf_derive_key(shared_bytes.as_ref(), &info)
        .map_err(|e| EnvelopeSealError::SealFailed(e.to_string()))?;

    let sealed = aes128gcm_encrypt(&aes_key, plaintext, &aad)
        .map_err(|e| EnvelopeSealError::SealFailed(e.to_string()))?;

    Ok((sealed, ephemeral_pub_bytes))
}

/// ECIES-opens a sealed payload using a local X25519 secret key.
///
/// The `ephemeral_pub` is the sender's ephemeral X25519 public key from the seal operation.
///
/// # Errors
///
/// Returns [`EnvelopeSealError::OpenFailed`] if decryption fails (wrong key, tampered
/// ciphertext, wrong context/DID binding).
pub fn ecies_open(
    sealed: &[u8],
    ephemeral_pub: &[u8; 32],
    local_x25519_secret: &[u8; 32],
    context_id: &str,
    creator_did: &str,
) -> Result<Vec<u8>, EnvelopeSealError> {
    let ephemeral_key = X25519Pub::from(*ephemeral_pub);
    // Wrap the dereferenced secret in Zeroizing so the stack copy is zeroed
    // on drop (StaticSecret::from consumes by value, creating a second copy).
    let secret_copy = Zeroizing::new(*local_x25519_secret);
    let local_secret = x25519_dalek::StaticSecret::from(*secret_copy);
    let shared_secret = local_secret.diffie_hellman(&ephemeral_key);

    let info = build_invitation_info(context_id, creator_did);
    let aad = build_invitation_aad(context_id, creator_did, ephemeral_pub);

    // x25519-dalek v2 SharedSecret implements Zeroize + zeroize(drop) when the
    // zeroize feature is enabled (which it is). Wrapping in Zeroizing is
    // defense-in-depth — ensures zeroing even if the feature is ever removed.
    let shared_bytes = Zeroizing::new(*shared_secret.as_bytes());
    let aes_key = hkdf_derive_key(shared_bytes.as_ref(), &info)
        .map_err(|e| EnvelopeSealError::OpenFailed(e.to_string()))?;

    aes128gcm_decrypt(&aes_key, sealed, &aad)
        .map_err(|e| EnvelopeSealError::OpenFailed(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn ecies_seal_open_roundtrip() {
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = X25519Pub::from(&secret);

        let plaintext = b"hello world, this is an invitation bundle";
        let (sealed, eph_pub) =
            ecies_seal(plaintext, public.as_bytes(), "ctx-123", "did:dht:z6MkAlice").unwrap();

        let recovered = ecies_open(
            &sealed,
            &eph_pub,
            &secret.to_bytes(),
            "ctx-123",
            "did:dht:z6MkAlice",
        )
        .unwrap();

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn ecies_wrong_context_fails() {
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = X25519Pub::from(&secret);

        let (sealed, eph_pub) = ecies_seal(
            b"payload",
            public.as_bytes(),
            "ctx-123",
            "did:dht:z6MkAlice",
        )
        .unwrap();

        let result = ecies_open(
            &sealed,
            &eph_pub,
            &secret.to_bytes(),
            "ctx-WRONG", // Different context
            "did:dht:z6MkAlice",
        );
        assert!(result.is_err());
    }

    #[test]
    fn ecies_wrong_did_fails() {
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = X25519Pub::from(&secret);

        let (sealed, eph_pub) = ecies_seal(
            b"payload",
            public.as_bytes(),
            "ctx-123",
            "did:dht:z6MkAlice",
        )
        .unwrap();

        let result = ecies_open(
            &sealed,
            &eph_pub,
            &secret.to_bytes(),
            "ctx-123",
            "did:dht:z6MkBob", // Different DID
        );
        assert!(result.is_err());
    }

    #[test]
    fn ed25519_to_x25519_roundtrip() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();

        let x25519_pub = ed25519_pubkey_to_x25519(&verifying_key.to_bytes()).unwrap();

        // The X25519 public key should be 32 bytes and non-zero
        assert_ne!(x25519_pub, [0u8; 32]);
    }

    #[test]
    fn ed25519_birational_ecies_roundtrip() {
        // Simulate: Alice seals to Bob's Ed25519 key via birational conversion
        let bob_signing = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let bob_verifying = bob_signing.verifying_key();

        // Alice converts Bob's Ed25519 pub to X25519 pub
        let bob_x25519_pub = ed25519_pubkey_to_x25519(&bob_verifying.to_bytes()).unwrap();

        // Alice seals
        let (sealed, eph_pub) = ecies_seal(
            b"welcome message",
            &bob_x25519_pub,
            "ctx-abc",
            "did:dht:z6MkAlice",
        )
        .unwrap();

        // Bob converts his Ed25519 secret to X25519 secret
        let bob_scalar_bytes = bob_signing.to_scalar_bytes();
        let bob_x25519_secret = x25519_dalek::StaticSecret::from(bob_scalar_bytes);

        // Bob opens
        let recovered = ecies_open(
            &sealed,
            &eph_pub,
            &bob_x25519_secret.to_bytes(),
            "ctx-abc",
            "did:dht:z6MkAlice",
        )
        .unwrap();

        assert_eq!(recovered, b"welcome message");
    }

    #[test]
    fn routing_id_derivation() {
        let id1 = derive_invitation_routing_id("did:dht:z6MkAlice");
        let id2 = derive_invitation_routing_id("did:dht:z6MkAlice");
        let id3 = derive_invitation_routing_id("did:dht:z6MkBob");

        assert_eq!(id1, id2); // Deterministic
        assert_ne!(id1, id3); // Different for different DIDs
    }

    #[test]
    fn large_payload_ecies() {
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = X25519Pub::from(&secret);

        // 10KB payload (larger than Welcome messages typically)
        let plaintext = vec![0x42u8; 10_000];
        let (sealed, eph_pub) = ecies_seal(
            &plaintext,
            public.as_bytes(),
            "ctx-large",
            "did:dht:z6MkAlice",
        )
        .unwrap();

        let recovered = ecies_open(
            &sealed,
            &eph_pub,
            &secret.to_bytes(),
            "ctx-large",
            "did:dht:z6MkAlice",
        )
        .unwrap();

        assert_eq!(recovered, plaintext);
    }
}
