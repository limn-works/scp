//! Wire types and HPKE distribution protocol for access keys.
//!
//! Access keys are distributed via the same pull-based HPKE protocol as
//! sender keys (§9.16.2), but with a distinct domain separator
//! (`"scp-access-key-v1"`) to prevent cross-protocol key confusion.
//!
//! Protocol flow:
//! 1. New member sends [`AccessKeyRequest`] with ephemeral X25519 wrapping
//!    pubkey, signature, nonce, and timestamp for replay protection.
//! 2. Key holder verifies the request and HPKE-encrypts the access key.
//! 3. Key holder responds with [`AccessKeyResponse`] containing the sealed
//!    key and ephemeral pubkey.
//! 4. Requester decrypts via [`open_access_key_response`].
//!
//! See ADR-038 §2 and spec §9.17.1.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Pub};
use zeroize::Zeroizing;

use scp_platform::traits::{KeyCustody, KeyHandle, KeyType};
use scp_primitives::Clock;

use scp_protocol::crypto::access_keys::{AccessKey, AccessKeyError};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// AES-128-GCM nonce size in bytes.
const HPKE_NONCE_SIZE: usize = 12;

/// Size of the cryptographic nonce in access key requests (bytes).
const ACCESS_KEY_NONCE_SIZE: usize = 16;

/// HKDF info prefix for access key HPKE encryption.
///
/// The full info string is:
/// `"scp-access-key-v1" || BE32(len(context_id)) || context_id || BE32(len(member_did)) || member_did || epoch_bytes`
///
/// Variable-length fields (`context_id`, `member_did`) are preceded by 4-byte
/// big-endian length prefixes to prevent concatenation ambiguity. The epoch
/// is fixed-width (8 bytes BE) and needs no prefix.
///
/// This MUST be distinct from the sender key HPKE info (`"scp-sender-key-v1"`)
/// to prevent cross-protocol key confusion per spec §9.17.1.
const HPKE_INFO_PREFIX: &[u8] = b"scp-access-key-v1";

/// Maximum age in seconds for an access key request to be considered fresh.
///
/// Requests older than this are rejected to prevent replay attacks.
/// See spec §9.17.1.
const REQUEST_FRESHNESS_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Request for a member's access key.
///
/// Sent to the key holder (context creator or `AddMember` executor).
/// The requester includes a fresh X25519 wrapping public key so the
/// responder can HPKE-encrypt the access key material.
///
/// Contains a timestamp and cryptographic nonce for replay protection.
/// The responder rejects requests older than 30 seconds and deduplicates
/// by nonce within the freshness window.
///
/// Signature payload: `SHA-256("SCP-ACCESS-KEY-REQUEST-V1:" || context_id || requester_did || nonce || timestamp_BE || wrapping_pubkey)`.
///
/// See spec §9.17.1 and §9.5.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessKeyRequest {
    /// The DID of the member requesting the access key.
    pub requester_did: String,
    /// The context the access key belongs to.
    pub context_id: String,
    /// Fresh X25519 public key for HPKE wrapping (32 bytes).
    #[serde(with = "serde_bytes")]
    pub wrapping_pubkey: Vec<u8>,
    /// Cryptographic nonce for replay protection (16 bytes, CSPRNG).
    #[serde(with = "serde_bytes")]
    pub nonce: [u8; ACCESS_KEY_NONCE_SIZE],
    /// Unix timestamp in seconds when the request was created.
    pub timestamp: u64,
    /// Ed25519 signature over the request payload.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// Response containing HPKE-encrypted access key material.
///
/// Sent back to the requester. The access key is encrypted using HPKE:
/// ephemeral X25519 ECDH + HKDF-SHA256 + AES-128-GCM, with the
/// `"scp-access-key-v1"` domain separator.
///
/// See spec §9.17.1 and ADR-038 §2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessKeyResponse {
    /// The context the access key belongs to.
    pub context_id: String,
    /// The DID of the member who owns this access key.
    pub member_did: String,
    /// The epoch of the distributed access key.
    pub epoch: u64,
    /// HPKE-sealed access key bytes (AES-128-GCM nonce || ciphertext || tag).
    #[serde(with = "serde_bytes")]
    pub hpke_sealed_key: Vec<u8>,
    /// The ephemeral X25519 public key used in the HPKE encapsulation.
    #[serde(with = "serde_bytes")]
    pub ephemeral_pubkey: Vec<u8>,
}

/// Result of [`request_access_key`], containing the serialized request
/// message and the X25519 wrapping key handle for later HPKE decryption.
#[derive(Debug)]
pub struct AccessKeyRequestResult {
    /// The serialized [`AccessKeyRequest`] message to send.
    pub request_message: Vec<u8>,
    /// The X25519 private key handle used for HPKE wrapping. The caller
    /// retains this to decrypt the eventual [`AccessKeyResponse`].
    pub wrapping_key_handle: KeyHandle,
}

// ---------------------------------------------------------------------------
// Request construction (requester side)
// ---------------------------------------------------------------------------

/// Constructs a signed [`AccessKeyRequest`] with a fresh ephemeral X25519
/// wrapping keypair and serializes it for transmission.
///
/// The requester signs the request with their signing key (Active or Agent).
/// The wrapping key handle is returned so the caller can later decrypt
/// the [`AccessKeyResponse`] via [`open_access_key_response`].
///
/// # Errors
///
/// Returns [`AccessKeyError::SigningFailed`] if signing fails.
/// Returns [`AccessKeyError::SerializationFailed`] if serialization fails.
/// Returns [`AccessKeyError::KeyCustodyError`] if key generation fails.
pub async fn request_access_key(
    key_custody: &impl KeyCustody,
    signing_key: &KeyHandle,
    requester_did: &str,
    context_id: &str,
    clock: &dyn Clock,
) -> Result<AccessKeyRequestResult, AccessKeyError> {
    // Generate fresh X25519 wrapping keypair.
    let wrapping_key_handle = key_custody
        .generate_keypair(KeyType::X25519)
        .await
        .map_err(|e| AccessKeyError::KeyCustodyError(e.to_string()))?;

    let wrapping_pubkey = key_custody
        .public_key(&wrapping_key_handle)
        .await
        .map_err(|e| AccessKeyError::KeyCustodyError(e.to_string()))?;

    let timestamp = clock.now_secs();

    // Generate cryptographic nonce for replay protection.
    let mut nonce = [0u8; ACCESS_KEY_NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);

    // Sign the request payload.
    let hash = compute_request_hash(
        context_id,
        requester_did,
        &nonce,
        timestamp,
        wrapping_pubkey.as_bytes(),
    );

    let signature = key_custody
        .sign(signing_key, &hash)
        .await
        .map_err(|e| AccessKeyError::SigningFailed(e.to_string()))?;

    let request = AccessKeyRequest {
        requester_did: requester_did.to_owned(),
        context_id: context_id.to_owned(),
        wrapping_pubkey: wrapping_pubkey.into_bytes(),
        nonce,
        timestamp,
        signature: signature.into_bytes(),
    };

    let message = serde_json::to_vec(&request)
        .map_err(|e| AccessKeyError::SerializationFailed(e.to_string()))?;

    Ok(AccessKeyRequestResult {
        request_message: message,
        wrapping_key_handle,
    })
}

// ---------------------------------------------------------------------------
// Request verification and handling (responder side)
// ---------------------------------------------------------------------------

/// Verifies the Ed25519 signature on an [`AccessKeyRequest`].
///
/// # Errors
///
/// Returns [`AccessKeyError::VerificationFailed`] if the public key or
/// signature bytes are malformed. Returns `Ok(false)` if the signature is
/// well-formed but invalid.
pub fn verify_access_key_request(
    request: &AccessKeyRequest,
    requester_public_key: &[u8],
) -> Result<bool, AccessKeyError> {
    let hash = compute_request_hash(
        &request.context_id,
        &request.requester_did,
        &request.nonce,
        request.timestamp,
        &request.wrapping_pubkey,
    );
    verify_ed25519_signature(requester_public_key, &hash, &request.signature)
}

/// Validates that an [`AccessKeyRequest`] timestamp is within the
/// freshness window.
///
/// Requests older than `REQUEST_FRESHNESS_SECS` or more than
/// `REQUEST_FRESHNESS_SECS` in the future are rejected to prevent
/// replay attacks and clock manipulation per spec §9.17.1.
///
/// # Errors
///
/// Returns [`AccessKeyError::StaleRequest`] if the request timestamp
/// is outside the freshness window.
pub const fn validate_request_freshness(
    request: &AccessKeyRequest,
    now_secs: u64,
) -> Result<(), AccessKeyError> {
    // Reject far-future timestamps (clock skew / manipulation).
    if request.timestamp > now_secs.saturating_add(REQUEST_FRESHNESS_SECS) {
        return Err(AccessKeyError::StaleRequest);
    }
    let age = now_secs.saturating_sub(request.timestamp);
    if age > REQUEST_FRESHNESS_SECS {
        return Err(AccessKeyError::StaleRequest);
    }
    Ok(())
}

/// Handles an incoming [`AccessKeyRequest`]: verifies the signature,
/// checks freshness, checks nonce replay, and HPKE-encrypts the access
/// key to the requester's wrapping public key.
///
/// Returns the serialized [`AccessKeyResponse`] on success.
///
/// # HPKE Assembly
///
/// 1. Generate ephemeral X25519 keypair.
/// 2. ECDH between ephemeral secret and requester's wrapping pubkey.
/// 3. HKDF-SHA256 with info = `"scp-access-key-v1" || BE32(len(context_id)) || context_id || BE32(len(member_did)) || member_did || epoch_bytes`
///    to derive a 16-byte AES-128-GCM encryption key.
/// 4. AES-128-GCM encrypt the access key bytes.
/// 5. Include the ephemeral public key in the response.
///
/// # Errors
///
/// Returns [`AccessKeyError::VerificationFailed`] if the request signature
/// is invalid or malformed.
/// Returns [`AccessKeyError::StaleRequest`] if the request is too old or
/// too far in the future.
/// Returns [`AccessKeyError::ReplayedNonce`] if the request nonce has been
/// seen before within the expiry window.
/// Returns other variants for HPKE failures.
pub fn handle_access_key_request(
    request: &AccessKeyRequest,
    requester_public_key: &[u8],
    access_key: &AccessKey,
    now_secs: u64,
    nonce_dedup: &mut scp_protocol::crypto::sender_keys::NonceDedup,
) -> Result<Vec<u8>, AccessKeyError> {
    // Verify the request signature.
    let valid = verify_access_key_request(request, requester_public_key)?;
    if !valid {
        return Err(AccessKeyError::VerificationFailed(
            "access key request signature verification failed".to_owned(),
        ));
    }

    // Check freshness (replay protection).
    validate_request_freshness(request, now_secs)?;

    // Nonce replay protection: reject requests with previously-seen nonces.
    if nonce_dedup.is_replayed(&request.nonce, now_secs) {
        return Err(AccessKeyError::ReplayedNonce);
    }

    // Parse the requester's wrapping public key.
    let wrapping_bytes: [u8; 32] = request.wrapping_pubkey.as_slice().try_into().map_err(|_| {
        AccessKeyError::VerificationFailed(format!(
            "wrapping pubkey must be 32 bytes, got {}",
            request.wrapping_pubkey.len()
        ))
    })?;

    // HPKE seal with access-key-specific info string and AAD binding.
    let info = build_hpke_info(
        access_key.context_id(),
        access_key.member_did(),
        access_key.epoch(),
    );
    let aad = build_hpke_aad(
        access_key.context_id(),
        access_key.member_did(),
        access_key.epoch(),
    );
    let (sealed, ephemeral_pub) = hpke_seal(access_key.as_bytes(), &wrapping_bytes, &info, &aad)?;

    let response = AccessKeyResponse {
        context_id: access_key.context_id().to_owned(),
        member_did: access_key.member_did().to_owned(),
        epoch: access_key.epoch(),
        hpke_sealed_key: sealed,
        ephemeral_pubkey: ephemeral_pub.to_vec(),
    };

    // Record the nonce only after the request has been fully validated and
    // the response constructed. This prevents the nonce dedup cache from
    // being poisoned by requests that fail for other reasons.
    nonce_dedup.record(request.nonce, now_secs);

    serde_json::to_vec(&response).map_err(|e| AccessKeyError::SerializationFailed(e.to_string()))
}

// ---------------------------------------------------------------------------
// Response handling (requester side)
// ---------------------------------------------------------------------------

/// Decrypts an [`AccessKeyResponse`] using the requester's wrapping key
/// handle inside the [`KeyCustody`] boundary.
///
/// The shared secret is computed via `key_custody.dh_agree(wrapping_key_handle,
/// ephemeral_pk)` so the wrapping private key never leaves custody. KDF +
/// AEAD decryption then recovers the access key in software.
///
/// # Errors
///
/// Returns [`AccessKeyError::KeyCustodyError`] if the DH agreement fails.
/// Returns [`AccessKeyError::HpkeDecryptionFailed`] if AEAD decryption fails.
pub async fn open_access_key_response(
    key_custody: &impl KeyCustody,
    wrapping_key_handle: &KeyHandle,
    response: &AccessKeyResponse,
) -> Result<AccessKey, AccessKeyError> {
    let ephemeral_bytes: [u8; 32] =
        response
            .ephemeral_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| {
                AccessKeyError::HpkeDecryptionFailed(format!(
                    "ephemeral pubkey must be 32 bytes, got {}",
                    response.ephemeral_pubkey.len()
                ))
            })?;

    // Compute shared secret inside custody boundary.
    let shared_secret = key_custody
        .dh_agree(wrapping_key_handle, &ephemeral_bytes)
        .await
        .map_err(|e| AccessKeyError::KeyCustodyError(e.to_string()))?;

    // Build info string with access-key-specific domain separator.
    let info = build_hpke_info(&response.context_id, &response.member_did, response.epoch);

    // Derive AES-128-GCM key from shared secret (zeroized on drop).
    let aes_key = hkdf_derive_key(shared_secret.as_bytes(), &info)?;

    // Build AAD to verify context binding during decryption.
    let aad = build_hpke_aad(&response.context_id, &response.member_did, response.epoch);

    // Decrypt the sealed access key.
    let plaintext = aes128gcm_decrypt(&aes_key, &response.hpke_sealed_key, &aad)?;

    let key_bytes: [u8; 32] = plaintext.as_slice().try_into().map_err(|_| {
        AccessKeyError::HpkeDecryptionFailed(format!(
            "decrypted key must be 32 bytes, got {}",
            plaintext.len()
        ))
    })?;

    Ok(AccessKey::from_parts(
        key_bytes,
        response.context_id.clone(),
        response.member_did.clone(),
        response.epoch,
    ))
}

// ---------------------------------------------------------------------------
// HPKE helpers (access-key-specific domain separator)
// ---------------------------------------------------------------------------

/// Builds the HPKE info string for access key distribution.
///
/// Format: `"scp-access-key-v1" || BE32(len(context_id)) || context_id || BE32(len(member_did)) || member_did || epoch_bytes`
///
/// Variable-length fields are preceded by 4-byte big-endian length prefixes
/// to prevent concatenation ambiguity. The epoch is fixed-width (8 bytes BE)
/// and needs no prefix.
///
/// This MUST be distinct from sender key HPKE info to prevent
/// cross-protocol key confusion per spec §9.17.1.
fn build_hpke_info(context_id: &str, member_did: &str, epoch: u64) -> Vec<u8> {
    let mut info = Vec::with_capacity(
        HPKE_INFO_PREFIX.len() + 4 + context_id.len() + 4 + member_did.len() + 8,
    );
    info.extend_from_slice(HPKE_INFO_PREFIX);
    #[allow(clippy::cast_possible_truncation)] // context_id/DID lengths << u32::MAX
    let ctx_len = context_id.len() as u32;
    info.extend_from_slice(&ctx_len.to_be_bytes());
    info.extend_from_slice(context_id.as_bytes());
    #[allow(clippy::cast_possible_truncation)]
    let did_len = member_did.len() as u32;
    info.extend_from_slice(&did_len.to_be_bytes());
    info.extend_from_slice(member_did.as_bytes());
    info.extend_from_slice(&epoch.to_be_bytes());
    info
}

/// HPKE seal: encrypts `plaintext` to `recipient_pub` using ephemeral X25519
/// ECDH + HKDF-SHA256 + AES-128-GCM with access-key-specific info string.
///
/// `aad` is bound to the AEAD tag as Additional Authenticated Data,
/// preventing ciphertext relocation across contexts or members.
///
/// Returns `(sealed_bytes, ephemeral_public_key)`.
fn hpke_seal(
    plaintext: &[u8; 32],
    recipient_pub: &[u8; 32],
    info: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; 32]), AccessKeyError> {
    // 1. Generate ephemeral X25519 keypair.
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519Pub::from(&ephemeral_secret);

    // 2. ECDH between ephemeral secret and recipient's wrapping pubkey.
    let recipient_key = X25519Pub::from(*recipient_pub);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_key);

    // 3. HKDF to derive 16-byte AES-128-GCM key (zeroized on drop).
    let aes_key = hkdf_derive_key(shared_secret.as_bytes(), info)?;

    // 4. AES-128-GCM encrypt with AAD binding.
    let sealed = aes128gcm_encrypt(&aes_key, plaintext, aad)?;

    Ok((sealed, ephemeral_public.to_bytes()))
}

/// Derives a 16-byte AES-128-GCM key from a 32-byte shared secret using
/// HKDF-SHA256 with the access-key-specific info string.
///
/// The returned key is wrapped in [`Zeroizing`] so the derived key material
/// is zeroed on drop (defense-in-depth).
fn hkdf_derive_key(
    shared_secret: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; 16]>, AccessKeyError> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = Zeroizing::new([0u8; 16]);
    hk.expand(info, okm.as_mut())
        .map_err(|e| AccessKeyError::HpkeEncryptionFailed(e.to_string()))?;
    Ok(okm)
}

/// Encrypts `plaintext` with AES-128-GCM using `aad` as Additional
/// Authenticated Data. Returns `nonce || ciphertext || tag`.
fn aes128gcm_encrypt(
    key: &[u8; 16],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AccessKeyError> {
    let cipher = Aes128Gcm::new_from_slice(key)
        .map_err(|e| AccessKeyError::HpkeEncryptionFailed(e.to_string()))?;

    let mut nonce_bytes = [0u8; HPKE_NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| AccessKeyError::HpkeEncryptionFailed(e.to_string()))?;

    let mut output = Vec::with_capacity(HPKE_NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypts AES-128-GCM ciphertext of the form `nonce || ciphertext || tag`,
/// verifying `aad` as Additional Authenticated Data.
fn aes128gcm_decrypt(key: &[u8; 16], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, AccessKeyError> {
    if sealed.len() < HPKE_NONCE_SIZE {
        return Err(AccessKeyError::HpkeDecryptionFailed(format!(
            "sealed data too short: {} bytes, minimum {HPKE_NONCE_SIZE}",
            sealed.len(),
        )));
    }

    let (nonce_bytes, encrypted) = sealed.split_at(HPKE_NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes128Gcm::new_from_slice(key)
        .map_err(|e| AccessKeyError::HpkeDecryptionFailed(e.to_string()))?;

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: encrypted,
                aad,
            },
        )
        .map_err(|e| AccessKeyError::HpkeDecryptionFailed(e.to_string()))
}

/// Builds Additional Authenticated Data (AAD) for access key HPKE
/// AES-128-GCM operations.
///
/// Format: length-prefixed binary —
/// `[4-byte context_id len (BE)][context_id bytes][4-byte member_did len (BE)][member_did bytes][8-byte epoch (BE)]`.
///
/// This matches the sender key HPKE AAD pattern in `key_protocol.rs`
/// for consistent AAD construction across key distribution protocols.
#[allow(clippy::cast_possible_truncation)] // String lengths are always < 4 GiB
fn build_hpke_aad(context_id: &str, member_did: &str, epoch: u64) -> Vec<u8> {
    let ctx_bytes = context_id.as_bytes();
    let did_bytes = member_did.as_bytes();
    let mut aad = Vec::with_capacity(4 + ctx_bytes.len() + 4 + did_bytes.len() + 8);
    aad.extend_from_slice(&(ctx_bytes.len() as u32).to_be_bytes());
    aad.extend_from_slice(ctx_bytes);
    aad.extend_from_slice(&(did_bytes.len() as u32).to_be_bytes());
    aad.extend_from_slice(did_bytes);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

// ---------------------------------------------------------------------------
// Hash / signature helpers
// ---------------------------------------------------------------------------

/// Computes the canonical hash for an `AccessKeyRequest`.
///
/// Uses the canonical hash construction from §9.5.2:
/// `SHA-256("SCP-ACCESS-KEY-REQUEST-V1:" || context_id || requester_did || nonce || timestamp_BE || wrapping_pubkey)`
///
/// The nonce is fixed-size (`ACCESS_KEY_NONCE_SIZE` = 16 bytes) and
/// needs no length prefix.
fn compute_request_hash(
    context_id: &str,
    requester_did: &str,
    nonce: &[u8; ACCESS_KEY_NONCE_SIZE],
    timestamp: u64,
    wrapping_pubkey: &[u8],
) -> Vec<u8> {
    use scp_protocol::crypto::canonical::{CanonicalField, canonical_hash};

    canonical_hash(
        "SCP-ACCESS-KEY-REQUEST-V1:",
        &[
            CanonicalField::VarBytes(context_id.as_bytes()),
            CanonicalField::VarBytes(requester_did.as_bytes()),
            CanonicalField::RawBytes(nonce),
            CanonicalField::U64(timestamp),
            CanonicalField::RawBytes(wrapping_pubkey),
        ],
    )
    .to_vec()
}

/// Verifies an Ed25519 signature, delegating to the canonical
/// [`scp_primitives::crypto::verify_ed25519_signature`].
///
/// Returns `Ok(true)` if the signature is valid, `Ok(false)` if it is
/// well-formed but invalid, or `Err` if the inputs are malformed.
fn verify_ed25519_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, AccessKeyError> {
    match scp_protocol::crypto::ed25519::verify_ed25519_signature(public_key, message, signature) {
        Ok(()) => Ok(true),
        Err(reason) => {
            if reason.starts_with("signature verification failed") {
                Ok(false)
            } else {
                Err(AccessKeyError::VerificationFailed(reason))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use scp_protocol::crypto::access_keys::generate_access_key;
    use scp_protocol::crypto::sender_keys::NonceDedup;

    // -----------------------------------------------------------------------
    // Wire type serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn access_key_request_serialization_roundtrip() {
        let request = AccessKeyRequest {
            requester_did: "did:dht:alice".to_owned(),
            context_id: "ctx-1".to_owned(),
            wrapping_pubkey: vec![0u8; 32],
            nonce: [0u8; ACCESS_KEY_NONCE_SIZE],
            timestamp: 1_700_000_000,
            signature: vec![0u8; 64],
        };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: AccessKeyRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.requester_did, request.requester_did);
        assert_eq!(deserialized.context_id, request.context_id);
        assert_eq!(deserialized.timestamp, request.timestamp);
        assert_eq!(deserialized.nonce, request.nonce);
    }

    #[test]
    fn access_key_response_serialization_roundtrip() {
        let response = AccessKeyResponse {
            context_id: "ctx-1".to_owned(),
            member_did: "did:dht:alice".to_owned(),
            epoch: 5,
            hpke_sealed_key: vec![1, 2, 3, 4],
            ephemeral_pubkey: vec![0u8; 32],
        };
        let json = serde_json::to_string(&response).unwrap();
        let deserialized: AccessKeyResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.context_id, response.context_id);
        assert_eq!(deserialized.member_did, response.member_did);
        assert_eq!(deserialized.epoch, response.epoch);
    }

    #[test]
    fn access_key_request_msgpack_roundtrip() {
        let request = AccessKeyRequest {
            requester_did: "did:dht:bob".to_owned(),
            context_id: "ctx-2".to_owned(),
            wrapping_pubkey: vec![42u8; 32],
            nonce: [0xAA; ACCESS_KEY_NONCE_SIZE],
            timestamp: 1_700_000_000,
            signature: vec![7u8; 64],
        };
        let bytes = rmp_serde::to_vec(&request).unwrap();
        let deserialized: AccessKeyRequest = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(deserialized.requester_did, request.requester_did);
        assert_eq!(deserialized.wrapping_pubkey, request.wrapping_pubkey);
        assert_eq!(deserialized.nonce, request.nonce);
    }

    #[test]
    fn access_key_response_msgpack_roundtrip() {
        let response = AccessKeyResponse {
            context_id: "ctx-2".to_owned(),
            member_did: "did:dht:bob".to_owned(),
            epoch: 10,
            hpke_sealed_key: vec![5, 6, 7, 8],
            ephemeral_pubkey: vec![99u8; 32],
        };
        let bytes = rmp_serde::to_vec(&response).unwrap();
        let deserialized: AccessKeyResponse = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(deserialized.epoch, 10);
        assert_eq!(deserialized.hpke_sealed_key, response.hpke_sealed_key);
    }

    // -----------------------------------------------------------------------
    // HPKE info string tests
    // -----------------------------------------------------------------------

    #[test]
    fn build_hpke_info_uses_correct_domain_separator() {
        let info = build_hpke_info("ctx-1", "did:dht:alice", 0);
        assert!(info.starts_with(b"scp-access-key-v1"));
    }

    #[test]
    fn build_hpke_info_is_deterministic() {
        let info1 = build_hpke_info("ctx-1", "did:dht:alice", 5);
        let info2 = build_hpke_info("ctx-1", "did:dht:alice", 5);
        assert_eq!(info1, info2);
    }

    #[test]
    fn build_hpke_info_differs_by_epoch() {
        let info0 = build_hpke_info("ctx-1", "did:dht:alice", 0);
        let info1 = build_hpke_info("ctx-1", "did:dht:alice", 1);
        assert_ne!(info0, info1);
    }

    #[test]
    fn build_hpke_info_differs_by_context() {
        let info_a = build_hpke_info("ctx-a", "did:dht:alice", 0);
        let info_b = build_hpke_info("ctx-b", "did:dht:alice", 0);
        assert_ne!(info_a, info_b);
    }

    #[test]
    fn build_hpke_info_differs_by_member() {
        let info_alice = build_hpke_info("ctx-1", "did:dht:alice", 0);
        let info_bob = build_hpke_info("ctx-1", "did:dht:bob", 0);
        assert_ne!(info_alice, info_bob);
    }

    #[test]
    fn build_hpke_info_distinct_from_sender_key_info() {
        let access_info = build_hpke_info("ctx-1", "did:dht:alice", 0);
        // Sender key HPKE uses "scp-sender-key-v1" as a flat info string.
        assert!(!access_info.starts_with(b"scp-sender-key"));
    }

    #[test]
    fn build_hpke_info_has_length_prefixes() {
        let info = build_hpke_info("ctx-1", "did:dht:alice", 42);
        let prefix_len = HPKE_INFO_PREFIX.len();

        // After the domain separator, the next 4 bytes should be the
        // big-endian length of "ctx-1" (5).
        let ctx_len_bytes = &info[prefix_len..prefix_len + 4];
        assert_eq!(ctx_len_bytes, &5u32.to_be_bytes());

        // After context_id, the next 4 bytes should be the big-endian
        // length of "did:dht:alice" (13).
        let member_offset = prefix_len + 4 + 5;
        let member_len_bytes = &info[member_offset..member_offset + 4];
        assert_eq!(member_len_bytes, &13u32.to_be_bytes());

        // After member_did, the last 8 bytes should be the epoch (42).
        let epoch_offset = member_offset + 4 + 13;
        let epoch_bytes = &info[epoch_offset..epoch_offset + 8];
        assert_eq!(epoch_bytes, &42u64.to_be_bytes());
    }

    #[test]
    fn build_hpke_info_length_prefixes_prevent_boundary_shift() {
        // Without length prefixes, ("ab", "cd") and ("a", "bcd") would
        // produce the same concatenation. With length prefixes they differ.
        let info_a = build_hpke_info("ab", "cd", 0);
        let info_b = build_hpke_info("a", "bcd", 0);
        assert_ne!(info_a, info_b);
    }

    // -----------------------------------------------------------------------
    // HPKE seal/open roundtrip tests (without KeyCustody)
    // -----------------------------------------------------------------------

    #[test]
    fn hpke_seal_open_roundtrip() {
        // Generate a simulated wrapping keypair.
        let wrapping_secret = EphemeralSecret::random_from_rng(OsRng);
        let wrapping_public = X25519Pub::from(&wrapping_secret);

        let access_key = generate_access_key("ctx-1", "did:dht:alice");
        let info = build_hpke_info("ctx-1", "did:dht:alice", 0);
        let aad = build_hpke_aad("ctx-1", "did:dht:alice", 0);

        // Seal.
        let (sealed, ephemeral_pub) = hpke_seal(
            access_key.as_bytes(),
            &wrapping_public.to_bytes(),
            &info,
            &aad,
        )
        .unwrap();

        // Derive shared secret on the requester side.
        let ephemeral_key = X25519Pub::from(ephemeral_pub);
        let shared_secret = wrapping_secret.diffie_hellman(&ephemeral_key);

        // Derive AES key and decrypt.
        let aes_key = hkdf_derive_key(shared_secret.as_bytes(), &info).unwrap();
        let plaintext = aes128gcm_decrypt(&aes_key, &sealed, &aad).unwrap();

        assert_eq!(plaintext.len(), 32);
        assert_eq!(plaintext.as_slice(), access_key.as_bytes());
    }

    #[test]
    fn hpke_seal_produces_nonce_plus_ciphertext_plus_tag() {
        let wrapping_secret = EphemeralSecret::random_from_rng(OsRng);
        let wrapping_public = X25519Pub::from(&wrapping_secret);
        let info = build_hpke_info("ctx-1", "did:dht:alice", 0);
        let aad = build_hpke_aad("ctx-1", "did:dht:alice", 0);

        let key_bytes = [42u8; 32];
        let (sealed, _) = hpke_seal(&key_bytes, &wrapping_public.to_bytes(), &info, &aad).unwrap();

        // nonce (12) + plaintext (32) + tag (16) = 60
        assert_eq!(sealed.len(), HPKE_NONCE_SIZE + 32 + 16);
    }

    #[test]
    fn hpke_different_info_produces_different_keys() {
        // Same shared secret but different info strings should produce
        // different derived keys.
        let shared_secret = [42u8; 32];
        let info_a = build_hpke_info("ctx-a", "did:dht:alice", 0);
        let info_b = build_hpke_info("ctx-b", "did:dht:alice", 0);

        let key_a = hkdf_derive_key(&shared_secret, &info_a).unwrap();
        let key_b = hkdf_derive_key(&shared_secret, &info_b).unwrap();

        assert_ne!(*key_a, *key_b);
    }

    // -----------------------------------------------------------------------
    // Request freshness tests
    // -----------------------------------------------------------------------

    #[test]
    fn validate_request_freshness_accepts_recent() {
        let request = AccessKeyRequest {
            requester_did: "did:dht:alice".to_owned(),
            context_id: "ctx-1".to_owned(),
            wrapping_pubkey: vec![0u8; 32],
            nonce: [0u8; ACCESS_KEY_NONCE_SIZE],
            timestamp: 1_000_000,
            signature: vec![0u8; 64],
        };
        assert!(validate_request_freshness(&request, 1_000_010).is_ok());
    }

    #[test]
    fn validate_request_freshness_accepts_at_boundary() {
        let request = AccessKeyRequest {
            requester_did: "did:dht:alice".to_owned(),
            context_id: "ctx-1".to_owned(),
            wrapping_pubkey: vec![0u8; 32],
            nonce: [0u8; ACCESS_KEY_NONCE_SIZE],
            timestamp: 1_000_000,
            signature: vec![0u8; 64],
        };
        assert!(validate_request_freshness(&request, 1_000_030).is_ok());
    }

    #[test]
    fn validate_request_freshness_rejects_stale() {
        let request = AccessKeyRequest {
            requester_did: "did:dht:alice".to_owned(),
            context_id: "ctx-1".to_owned(),
            wrapping_pubkey: vec![0u8; 32],
            nonce: [0u8; ACCESS_KEY_NONCE_SIZE],
            timestamp: 1_000_000,
            signature: vec![0u8; 64],
        };
        let result = validate_request_freshness(&request, 1_000_031);
        assert!(matches!(result, Err(AccessKeyError::StaleRequest)));
    }

    #[test]
    fn validate_request_freshness_rejects_far_future() {
        let request = AccessKeyRequest {
            requester_did: "did:dht:alice".to_owned(),
            context_id: "ctx-1".to_owned(),
            wrapping_pubkey: vec![0u8; 32],
            nonce: [0u8; ACCESS_KEY_NONCE_SIZE],
            // Timestamp far ahead of "now".
            timestamp: 1_000_100,
            signature: vec![0u8; 64],
        };
        let result = validate_request_freshness(&request, 1_000_000);
        assert!(matches!(result, Err(AccessKeyError::StaleRequest)));
    }

    #[test]
    fn validate_request_freshness_accepts_slight_future() {
        // A timestamp up to REQUEST_FRESHNESS_SECS ahead should be accepted
        // (covers minor clock skew).
        let request = AccessKeyRequest {
            requester_did: "did:dht:alice".to_owned(),
            context_id: "ctx-1".to_owned(),
            wrapping_pubkey: vec![0u8; 32],
            nonce: [0u8; ACCESS_KEY_NONCE_SIZE],
            timestamp: 1_000_030,
            signature: vec![0u8; 64],
        };
        assert!(validate_request_freshness(&request, 1_000_000).is_ok());
    }

    // -----------------------------------------------------------------------
    // Signature verification tests
    // -----------------------------------------------------------------------

    #[test]
    fn verify_ed25519_signature_rejects_wrong_length_pubkey() {
        let result = verify_ed25519_signature(&[0u8; 16], b"msg", &[0u8; 64]);
        assert!(matches!(result, Err(AccessKeyError::VerificationFailed(_))));
    }

    #[test]
    fn verify_ed25519_signature_rejects_wrong_length_signature() {
        let result = verify_ed25519_signature(&[0u8; 32], b"msg", &[0u8; 32]);
        assert!(matches!(result, Err(AccessKeyError::VerificationFailed(_))));
    }

    // -----------------------------------------------------------------------
    // HPKE distribution E2E test (with real Ed25519 signing)
    // -----------------------------------------------------------------------

    #[test]
    fn handle_access_key_request_rejects_invalid_signature() {
        let access_key = generate_access_key("ctx-1", "did:dht:alice");
        let mut nonce_dedup = NonceDedup::new();

        // Create a request with a bogus signature.
        let request = AccessKeyRequest {
            requester_did: "did:dht:bob".to_owned(),
            context_id: "ctx-1".to_owned(),
            wrapping_pubkey: vec![0u8; 32],
            nonce: [0u8; ACCESS_KEY_NONCE_SIZE],
            timestamp: 1_000_000,
            signature: vec![0u8; 64],
        };

        // Use a random public key that won't match the signature.
        let result = handle_access_key_request(
            &request,
            &[1u8; 32], // bogus pubkey
            &access_key,
            1_000_000,
            &mut nonce_dedup,
        );
        // Should fail at signature verification or produce false.
        assert!(result.is_err());
    }

    #[test]
    fn handle_access_key_request_rejects_stale_request() {
        let access_key = generate_access_key("ctx-1", "did:dht:alice");
        let mut nonce_dedup = NonceDedup::new();

        // Even with a valid-looking request, staleness should be caught.
        // (The signature check happens first, but let's test that stale
        // requests are rejected in principle.)
        let request = AccessKeyRequest {
            requester_did: "did:dht:bob".to_owned(),
            context_id: "ctx-1".to_owned(),
            wrapping_pubkey: vec![0u8; 32],
            nonce: [0u8; ACCESS_KEY_NONCE_SIZE],
            timestamp: 1_000_000,
            signature: vec![0u8; 64],
        };

        // Will fail on signature first, but validate_request_freshness
        // independently rejects stale:
        let freshness = validate_request_freshness(&request, 1_000_100);
        assert!(matches!(freshness, Err(AccessKeyError::StaleRequest)));

        // And the full handler also rejects (due to sig failure):
        let result = handle_access_key_request(
            &request,
            &[1u8; 32],
            &access_key,
            1_000_100,
            &mut nonce_dedup,
        );
        assert!(result.is_err());
    }

    #[test]
    fn handle_access_key_request_rejects_wrong_wrapping_key_length() {
        let access_key = generate_access_key("ctx-1", "did:dht:alice");
        let mut nonce_dedup = NonceDedup::new();

        let request = AccessKeyRequest {
            requester_did: "did:dht:bob".to_owned(),
            context_id: "ctx-1".to_owned(),
            wrapping_pubkey: vec![0u8; 16], // wrong length
            nonce: [0u8; ACCESS_KEY_NONCE_SIZE],
            timestamp: 1_000_000,
            signature: vec![0u8; 64],
        };

        // Will fail on signature first, but wrapping key validation
        // would also catch this.
        let result = handle_access_key_request(
            &request,
            &[1u8; 32],
            &access_key,
            1_000_000,
            &mut nonce_dedup,
        );
        assert!(result.is_err());
    }

    /// Full HPKE distribution E2E test using real Ed25519 keys and signatures.
    #[test]
    fn hpke_distribution_e2e_with_real_signing() {
        use ed25519_dalek::{Signer, SigningKey};

        let mut nonce_dedup = NonceDedup::new();

        // 1. Generate requester's Ed25519 keypair.
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // 2. Generate X25519 wrapping keypair for the requester.
        let wrapping_secret = EphemeralSecret::random_from_rng(OsRng);
        let wrapping_public = X25519Pub::from(&wrapping_secret);

        let timestamp = 1_700_000_000_u64;
        let mut nonce = [0u8; ACCESS_KEY_NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);

        // 3. Build and sign the request.
        let hash = compute_request_hash(
            "ctx-1",
            "did:dht:bob",
            &nonce,
            timestamp,
            &wrapping_public.to_bytes(),
        );
        let sig = signing_key.sign(&hash);

        let request = AccessKeyRequest {
            requester_did: "did:dht:bob".to_owned(),
            context_id: "ctx-1".to_owned(),
            wrapping_pubkey: wrapping_public.to_bytes().to_vec(),
            nonce,
            timestamp,
            signature: sig.to_bytes().to_vec(),
        };

        // 4. Generate the access key to distribute.
        let access_key = generate_access_key("ctx-1", "did:dht:alice");
        let original_key_bytes = *access_key.as_bytes();

        // 5. Handle the request (responder side).
        let response_bytes = handle_access_key_request(
            &request,
            verifying_key.as_bytes(),
            &access_key,
            timestamp,
            &mut nonce_dedup,
        )
        .unwrap();

        // 6. Parse the response.
        let response: AccessKeyResponse = serde_json::from_slice(&response_bytes).unwrap();

        assert_eq!(response.context_id, "ctx-1");
        assert_eq!(response.member_did, "did:dht:alice");
        assert_eq!(response.epoch, 0);

        // 7. Decrypt the response (requester side) -- manual HPKE open.
        let ephemeral_bytes: [u8; 32] = response.ephemeral_pubkey.as_slice().try_into().unwrap();
        let ephemeral_key = X25519Pub::from(ephemeral_bytes);
        let shared_secret = wrapping_secret.diffie_hellman(&ephemeral_key);

        let info = build_hpke_info("ctx-1", "did:dht:alice", 0);
        let aes_key = hkdf_derive_key(shared_secret.as_bytes(), &info).unwrap();
        let aad = build_hpke_aad("ctx-1", "did:dht:alice", 0);
        let plaintext = aes128gcm_decrypt(&aes_key, &response.hpke_sealed_key, &aad).unwrap();

        let recovered_bytes: [u8; 32] = plaintext.as_slice().try_into().unwrap();
        assert_eq!(recovered_bytes, original_key_bytes);

        // 8. Replaying the same request should be rejected.
        let replay_result = handle_access_key_request(
            &request,
            verifying_key.as_bytes(),
            &access_key,
            timestamp,
            &mut nonce_dedup,
        );
        assert!(matches!(replay_result, Err(AccessKeyError::ReplayedNonce)));
    }

    // -----------------------------------------------------------------------
    // Nonce replay protection tests
    // -----------------------------------------------------------------------

    #[test]
    fn handle_access_key_request_rejects_replayed_nonce() {
        use ed25519_dalek::{Signer, SigningKey};

        let mut nonce_dedup = NonceDedup::new();
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let wrapping_secret = EphemeralSecret::random_from_rng(OsRng);
        let wrapping_public = X25519Pub::from(&wrapping_secret);

        let timestamp = 1_700_000_000_u64;
        let mut nonce = [0u8; ACCESS_KEY_NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);

        let hash = compute_request_hash(
            "ctx-1",
            "did:dht:bob",
            &nonce,
            timestamp,
            &wrapping_public.to_bytes(),
        );
        let sig = signing_key.sign(&hash);

        let request = AccessKeyRequest {
            requester_did: "did:dht:bob".to_owned(),
            context_id: "ctx-1".to_owned(),
            wrapping_pubkey: wrapping_public.to_bytes().to_vec(),
            nonce,
            timestamp,
            signature: sig.to_bytes().to_vec(),
        };

        let access_key = generate_access_key("ctx-1", "did:dht:alice");

        // First request should succeed.
        let result = handle_access_key_request(
            &request,
            verifying_key.as_bytes(),
            &access_key,
            timestamp,
            &mut nonce_dedup,
        );
        assert!(result.is_ok());

        // Replay with same nonce should fail.
        let result = handle_access_key_request(
            &request,
            verifying_key.as_bytes(),
            &access_key,
            timestamp,
            &mut nonce_dedup,
        );
        assert!(matches!(result, Err(AccessKeyError::ReplayedNonce)));
    }

    #[test]
    fn nonce_included_in_request_hash() {
        // Different nonces should produce different hashes.
        let nonce_a = [0xAAu8; ACCESS_KEY_NONCE_SIZE];
        let nonce_b = [0xBBu8; ACCESS_KEY_NONCE_SIZE];

        let hash_a = compute_request_hash("ctx-1", "did:dht:bob", &nonce_a, 100, &[0u8; 32]);
        let hash_b = compute_request_hash("ctx-1", "did:dht:bob", &nonce_b, 100, &[0u8; 32]);

        assert_ne!(hash_a, hash_b);
    }
}
