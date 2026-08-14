//! RFC 9180 HPKE envelope seal/open for arbitrary-length payloads.
//!
//! Used for invitation bundle and join response encryption (spec §5.12.3.1),
//! over the shared [`crate::crypto::hpke`] core (RFC 9180 Base mode, §9.5).
//! The invitation-specific `info`/`aad` domain separators distinguish these
//! ciphertexts from sender-key, access-key, broadcast-key, and private-state
//! HPKE.

use sha2::{Digest, Sha256};

use crate::crypto::hpke;

/// Errors from envelope seal/open operations.
#[derive(Debug, thiserror::Error)]
pub enum EnvelopeSealError {
    /// HPKE encryption failed.
    #[error("HPKE encryption failed: {0}")]
    SealFailed(String),
    /// HPKE decryption failed.
    #[error("HPKE decryption failed: {0}")]
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

/// Builds the HPKE `info` string for invitation HPKE (§5.12.3.1).
/// Format: `"scp-invitation-v1" || len(context_id) || context_id || len(creator_did) || creator_did`
fn build_invitation_info(context_id: &str, creator_did: &str) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(b"scp-invitation-v1");
    append_length_prefixed(&mut info, context_id.as_bytes());
    append_length_prefixed(&mut info, creator_did.as_bytes());
    info
}

/// Builds the AEAD AAD for invitation HPKE (distinct from the HPKE `info`).
/// Format: `"scp-invitation-aad-v1" || len(context_id) || context_id || len(creator_did) || creator_did`
///
/// The ephemeral public key (`enc`) is NOT carried in the AAD: RFC 9180 binds
/// `enc` into the key schedule via `kem_context = enc || pkRm` (§4.1), so an
/// ephemeral-key substitution already produces a different derived key and
/// fails AEAD verification. Including `enc` in the AAD would be redundant (and
/// caused a build-AAD-before-enc-exists ordering wart). See spec §5.12.3.1.
fn build_invitation_aad(context_id: &str, creator_did: &str) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(b"scp-invitation-aad-v1");
    append_length_prefixed(&mut aad, context_id.as_bytes());
    append_length_prefixed(&mut aad, creator_did.as_bytes());
    aad
}

/// HPKE-seals an arbitrary-length payload to a recipient's X25519 public key
/// (RFC 9180 Base mode, §5.12.3.1).
///
/// Returns `(sealed, enc)` where `sealed` is the HPKE ciphertext
/// (`ciphertext || tag`) and `enc` is the 32-byte HPKE encapsulated key. There
/// is no external nonce — the AEAD nonce is derived internally by RFC 9180.
///
/// # Errors
///
/// Returns [`EnvelopeSealError::SealFailed`] if HPKE sealing fails.
pub fn hpke_seal_invitation(
    plaintext: &[u8],
    recipient_x25519_pub: &[u8; 32],
    context_id: &str,
    creator_did: &str,
) -> Result<(Vec<u8>, [u8; 32]), EnvelopeSealError> {
    let info = build_invitation_info(context_id, creator_did);
    let aad = build_invitation_aad(context_id, creator_did);

    let (enc, ct) = hpke::seal(recipient_x25519_pub, &info, &aad, plaintext)
        .map_err(|e| EnvelopeSealError::SealFailed(e.to_string()))?;

    Ok((ct, enc))
}

/// HPKE-opens a sealed payload using a local (software-held) X25519 secret key.
///
/// The `ephemeral_pub` is the HPKE encapsulated key (`enc`) from the seal
/// operation.
///
/// # Errors
///
/// Returns [`EnvelopeSealError::OpenFailed`] if HPKE open fails (wrong key,
/// tampered ciphertext/enc, wrong context/DID binding).
pub fn hpke_open_invitation(
    sealed: &[u8],
    ephemeral_pub: &[u8; 32],
    local_x25519_secret: &[u8; 32],
    context_id: &str,
    creator_did: &str,
) -> Result<Vec<u8>, EnvelopeSealError> {
    let info = build_invitation_info(context_id, creator_did);
    let aad = build_invitation_aad(context_id, creator_did);

    hpke::open(local_x25519_secret, ephemeral_pub, &info, &aad, sealed)
        .map_err(|e| EnvelopeSealError::OpenFailed(e.to_string()))
}

/// HPKE-opens a sealed invitation whose KEM Diffie-Hellman output was computed
/// **inside a `KeyCustody` boundary** — the split-custody counterpart of
/// [`hpke_open_invitation`] (spec §5.12.3.1, ADR-006).
///
/// This is the joiner path: the recipient key is the invitee's Ed25519
/// `#active` identity key, held in custody. The one step that must touch the
/// non-extractable private key — `dh = DH(sk_active_x25519, enc)` — is performed
/// in custody via `KeyCustody::ed25519_to_x25519_agree(handle, enc)`; the
/// private key never leaves the boundary. This function takes that
/// custody-computed `dh` plus `recipient_pk` (`pkRm`, the invitee's own `#active`
/// public key mapped to X25519 via [`ed25519_pubkey_to_x25519`]) and completes
/// the RFC 9180 Decap + AEAD open in software. The `info`/`aad` are built with
/// the SAME [`build_invitation_info`]/[`build_invitation_aad`] as the seal side,
/// so the two never diverge.
///
/// # Caller contract (load-bearing)
///
/// For one and the same custody `#active` handle and one and the same `enc`:
/// `dh = KeyCustody::ed25519_to_x25519_agree(handle, enc)` and
/// `recipient_pk = ed25519_pubkey_to_x25519(KeyCustody::public_key(handle))`.
/// A mismatched `dh`/`recipient_pk`/`enc`/`info`/`aad` fails closed (AEAD tag
/// mismatch), indistinguishable from a wrong-key error. Binding `enc || pkRm`
/// into the shared secret closes the unknown-key-share gap.
///
/// `context_id` / `creator_did` are the **binding hints** used to build
/// `info`/`aad`; a successful open proves the sealer used the identical values
/// (they are AEAD-authenticated). The caller MUST still cross-check them against
/// the decrypted, signature-verified bundle before deriving any authority.
///
/// # Errors
///
/// Returns [`EnvelopeSealError::OpenFailed`] if HPKE open fails (wrong
/// `dh`/`recipient_pk`/`enc`, wrong context/DID binding, or tampered `sealed`).
pub fn hpke_open_invitation_with_external_dh(
    sealed: &[u8],
    dh: &[u8; 32],
    recipient_pk: &[u8; 32],
    enc: &[u8; 32],
    context_id: &str,
    creator_did: &str,
) -> Result<Vec<u8>, EnvelopeSealError> {
    let info = build_invitation_info(context_id, creator_did);
    let aad = build_invitation_aad(context_id, creator_did);

    hpke::custody::open_with_external_dh(dh, recipient_pk, enc, &info, &aad, sealed)
        .map_err(|e| EnvelopeSealError::OpenFailed(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use x25519_dalek::PublicKey as X25519Pub;

    use super::*;

    #[test]
    fn ecies_seal_open_roundtrip() {
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = X25519Pub::from(&secret);

        let plaintext = b"hello world, this is an invitation bundle";
        let (sealed, eph_pub) =
            hpke_seal_invitation(plaintext, public.as_bytes(), "ctx-123", "did:dht:z6MkAlice")
                .unwrap();

        let recovered = hpke_open_invitation(
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

        let (sealed, eph_pub) = hpke_seal_invitation(
            b"payload",
            public.as_bytes(),
            "ctx-123",
            "did:dht:z6MkAlice",
        )
        .unwrap();

        let result = hpke_open_invitation(
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

        let (sealed, eph_pub) = hpke_seal_invitation(
            b"payload",
            public.as_bytes(),
            "ctx-123",
            "did:dht:z6MkAlice",
        )
        .unwrap();

        let result = hpke_open_invitation(
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
        let (sealed, eph_pub) = hpke_seal_invitation(
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
        let recovered = hpke_open_invitation(
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
    fn external_dh_open_matches_seal() {
        // Seal to Bob's Ed25519 #active key via birational conversion, then open
        // via the split-custody external-DH path (dh computed "outside" the HPKE
        // core, as `KeyCustody::ed25519_to_x25519_agree` would).
        let bob_signing = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let bob_verifying = bob_signing.verifying_key();
        let bob_x25519_pub = ed25519_pubkey_to_x25519(&bob_verifying.to_bytes()).unwrap();

        let (sealed, enc) = hpke_seal_invitation(
            b"bundle-wire-bytes",
            &bob_x25519_pub,
            "ctx-xdh",
            "did:dht:z6MkAlice",
        )
        .unwrap();

        // Recompute dh = DH(sk_active_x25519, enc) exactly as custody would.
        let bob_x25519_secret = x25519_dalek::StaticSecret::from(bob_signing.to_scalar_bytes());
        let enc_pub = X25519Pub::from(enc);
        let dh = bob_x25519_secret.diffie_hellman(&enc_pub);

        let recovered = hpke_open_invitation_with_external_dh(
            &sealed,
            dh.as_bytes(),
            &bob_x25519_pub,
            &enc,
            "ctx-xdh",
            "did:dht:z6MkAlice",
        )
        .unwrap();
        assert_eq!(recovered, b"bundle-wire-bytes");
    }

    #[test]
    fn external_dh_open_wrong_binding_fails() {
        let bob_signing = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let bob_x25519_pub =
            ed25519_pubkey_to_x25519(&bob_signing.verifying_key().to_bytes()).unwrap();
        let (sealed, enc) =
            hpke_seal_invitation(b"payload", &bob_x25519_pub, "ctx-xdh", "did:dht:z6MkAlice")
                .unwrap();
        let bob_x25519_secret = x25519_dalek::StaticSecret::from(bob_signing.to_scalar_bytes());
        let dh = bob_x25519_secret.diffie_hellman(&X25519Pub::from(enc));

        // Wrong creator_did in the binding hint → AEAD open fails closed.
        let result = hpke_open_invitation_with_external_dh(
            &sealed,
            dh.as_bytes(),
            &bob_x25519_pub,
            &enc,
            "ctx-xdh",
            "did:dht:z6MkMallory",
        );
        assert!(result.is_err());
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
        let (sealed, eph_pub) = hpke_seal_invitation(
            &plaintext,
            public.as_bytes(),
            "ctx-large",
            "did:dht:z6MkAlice",
        )
        .unwrap();

        let recovered = hpke_open_invitation(
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
