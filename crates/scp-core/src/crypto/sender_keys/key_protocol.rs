//! Async signing operations for the sender key distribution protocol.
//!
//! This module contains the **async** operations that depend on
//! [`KeyCustody`] for signing and key agreement. Pure synchronous
//! verification, wire types, HPKE helpers, and constants live in
//! [`super::key_protocol_verify`] and are re-exported here for backward
//! compatibility.
//!
//! See ADR-007 in `.docs/adrs/phase-1.md` for the full protocol design
//! and §5.14.8 for broadcast-mode blocking specifics.

pub use super::key_protocol_verify::*;

use std::collections::HashSet;
use std::hash::BuildHasher;

use rand::RngCore;
use rand::rngs::OsRng;

use scp_platform::traits::{KeyCustody, KeyHandle, KeyType};

use super::{SenderKey, SenderKeyError, generate_sender_key};
use crate::identity::SigningKeyId;

// ---------------------------------------------------------------------------
// SenderKeyRequestResult — holds KeyHandle from scp-platform
// ---------------------------------------------------------------------------

/// Result of [`request_sender_key`], containing the serialized request
/// message and the X25519 wrapping key handle for later HPKE decryption.
#[derive(Debug)]
pub struct SenderKeyRequestResult {
    /// The serialized [`SenderKeyRequest`] message to send.
    pub request_message: Vec<u8>,
    /// The X25519 private key handle used for HPKE wrapping. The caller
    /// retains this to decrypt the eventual [`SenderKeyResponse`].
    pub wrapping_key_handle: KeyHandle,
}

// ---------------------------------------------------------------------------
// Epoch advance — signing
// ---------------------------------------------------------------------------

/// Constructs a signed [`SenderKeyEpochAdvance`] and serializes it for
/// transmission as an MLS application message.
///
/// The sender signs `SHA-256(context_id || sender_did || "key_epoch" || epoch_BE || signer_key_ref)`
/// with their signing key (Active or Agent, as specified by `signer_key_ref`).
///
/// # Errors
///
/// Returns [`SenderKeyError::SigningFailed`] if the signing operation fails.
/// Returns [`SenderKeyError::SerializationFailed`] if serialization fails.
pub async fn publish_sender_key_epoch_advance(
    key_custody: &impl KeyCustody,
    signing_key: &KeyHandle,
    context_id: &str,
    sender_did: &str,
    epoch: u64,
    signer_key_ref: SigningKeyId,
) -> Result<Vec<u8>, SenderKeyError> {
    let hash = compute_epoch_advance_hash(context_id, sender_did, epoch, signer_key_ref);

    let signature = key_custody
        .sign(signing_key, &hash)
        .await
        .map_err(|e| SenderKeyError::SigningFailed(e.to_string()))?;

    let sig_bytes: [u8; 64] = signature
        .into_bytes()
        .try_into()
        .map_err(|_| SenderKeyError::SigningFailed("Ed25519 signature must be 64 bytes".into()))?;

    let advance = SenderKeyEpochAdvance {
        sender_did: sender_did.to_owned(),
        epoch,
        signer_key_ref,
        signature: sig_bytes,
    };

    rmp_serde::to_vec_named(&advance)
        .map_err(|e| SenderKeyError::SerializationFailed(e.to_string()))
}

// ---------------------------------------------------------------------------
// Sender key request — signing
// ---------------------------------------------------------------------------

/// Constructs a signed [`SenderKeyRequest`] with a fresh ephemeral X25519
/// wrapping keypair and serializes it for transmission.
///
/// The requester signs the request with their Active Signing Key. The
/// wrapping key handle is returned so the caller can later decrypt the
/// [`SenderKeyResponse`] via [`open_sender_key_response`].
///
/// # Errors
///
/// Returns [`SenderKeyError::SigningFailed`] if signing fails.
/// Returns [`SenderKeyError::SerializationFailed`] if serialization fails.
/// Returns [`SenderKeyError::KeyCustodyError`] if key generation fails.
pub async fn request_sender_key(
    key_custody: &impl KeyCustody,
    signing_key: &KeyHandle,
    requester_did: &str,
    sender_did: &str,
    epoch: u64,
) -> Result<SenderKeyRequestResult, SenderKeyError> {
    // Generate fresh X25519 wrapping keypair.
    let wrapping_key_handle = key_custody
        .generate_keypair(KeyType::X25519)
        .await
        .map_err(|e| SenderKeyError::KeyCustodyError(e.to_string()))?;

    let wrapping_pubkey = key_custody
        .public_key(&wrapping_key_handle)
        .await
        .map_err(|e| SenderKeyError::KeyCustodyError(e.to_string()))?;

    // Generate cryptographic nonce and timestamp for replay protection.
    let mut nonce = [0u8; REQUEST_NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    let timestamp = crate::time::now_secs()?;

    // Sign the request (including nonce and timestamp).
    let hash = compute_request_hash(
        requester_did,
        sender_did,
        epoch,
        wrapping_pubkey.as_bytes(),
        &nonce,
        timestamp,
    );

    let signature = key_custody
        .sign(signing_key, &hash)
        .await
        .map_err(|e| SenderKeyError::SigningFailed(e.to_string()))?;

    let wrap_bytes: [u8; 32] = wrapping_pubkey.into_bytes().try_into().map_err(|_| {
        SenderKeyError::KeyCustodyError("X25519 public key must be 32 bytes".into())
    })?;
    let sig_bytes: [u8; 64] = signature
        .into_bytes()
        .try_into()
        .map_err(|_| SenderKeyError::SigningFailed("Ed25519 signature must be 64 bytes".into()))?;

    let request = SenderKeyRequest {
        requester_did: requester_did.to_owned(),
        sender_did: sender_did.to_owned(),
        epoch,
        wrapping_pubkey: wrap_bytes,
        nonce,
        timestamp,
        signature: sig_bytes,
    };

    let message = rmp_serde::to_vec_named(&request)
        .map_err(|e| SenderKeyError::SerializationFailed(e.to_string()))?;

    Ok(SenderKeyRequestResult {
        request_message: message,
        wrapping_key_handle,
    })
}

// ---------------------------------------------------------------------------
// Handle sender key request (responder side) — async
// ---------------------------------------------------------------------------

/// Handles an incoming [`SenderKeyRequest`].
///
/// Verifies the signature, validates timestamp freshness, checks nonce
/// replay, verifies membership and the block list, and HPKE-encrypts
/// the sender key to the requester's wrapping public key.
///
/// Returns `None` if the requester is blocked (no response, the requester
/// cannot obtain the key). Returns `Some(serialized_response)` otherwise.
///
/// # Replay Protection
///
/// Two layers of replay defense:
///
/// 1. **Timestamp freshness** — rejects requests with timestamps outside
///    `REQUEST_FRESHNESS_SECS` (past or future), preventing replay of old
///    requests and guarding against clock-skew manipulation.
/// 2. **Nonce dedup** — rejects requests whose nonce has been seen within
///    `NONCE_EXPIRY_SECS`, preventing replay of recently-valid requests.
///    After processing, the nonce is recorded in the dedup cache.
///
/// # Sybil Resistance (BLACK-006, §9.16.6)
///
/// When `context_members` is `Some`, the requester's DID must be in the
/// membership set or the request is rejected with
/// [`SenderKeyError::NotContextMember`]. This is the primary mechanical
/// defense against Sybil block bypass: a Sybil DID that has not been
/// admitted to the context through normal admission controls cannot obtain
/// sender keys, even though it is not on the block list.
///
/// In **Encrypted** contexts, MLS group membership already gates who can
/// see application messages, so `context_members` is a defense-in-depth
/// redundancy. In **Broadcast** contexts, where key requests travel as
/// relay messages outside MLS, `context_members` is the primary gate.
///
/// Callers SHOULD always provide `context_members`. Passing `None` is
/// permitted for backward compatibility but disables the membership check.
///
/// # HPKE Assembly
///
/// 1. Generate ephemeral X25519 keypair (software-generated).
/// 2. ECDH between ephemeral secret and requester's wrapping pubkey.
/// 3. HKDF-SHA256 to derive a 16-byte AES-128-GCM encryption key.
/// 4. AES-128-GCM encrypt the sender key bytes.
/// 5. Include the ephemeral public key in the response.
///
/// # Errors
///
/// Returns [`SenderKeyError::StaleSenderKeyRequest`] if the request
/// timestamp is outside the freshness window.
/// Returns [`SenderKeyError::ReplayedRequest`] if the request nonce has
/// already been seen within the dedup window.
/// Returns [`SenderKeyError::NotContextMember`] if `context_members` is
/// provided and the requester is not a member.
/// Returns [`SenderKeyError::VerificationFailed`] if the request signature
/// is invalid or malformed. Returns other variants for HPKE failures.
pub async fn handle_sender_key_request<S: BuildHasher + Sync>(
    request: &SenderKeyRequest,
    requester_public_key: &[u8],
    params: &HandleRequestParams<'_, S>,
    nonce_dedup: &mut NonceDedup,
) -> Result<Option<Vec<u8>>, SenderKeyError> {
    // Verify the request signature.
    let valid = verify_sender_key_request(request, requester_public_key)?;
    if !valid {
        return Err(SenderKeyError::VerificationFailed(
            "sender key request signature verification failed".to_owned(),
        ));
    }

    // Timestamp freshness: reject requests outside the freshness window.
    validate_sender_key_request_freshness(request, params.now_secs)?;

    // Nonce replay protection: reject requests with previously-seen nonces.
    if nonce_dedup.is_replayed(&request.nonce, params.now_secs) {
        return Err(SenderKeyError::ReplayedRequest);
    }

    // Membership gate (BLACK-006, §9.16.6): reject requests from DIDs
    // that are not context members. This prevents Sybil identities —
    // which bypass per-DID block lists by definition — from obtaining
    // sender keys. The Sybil DID must first pass the context's admission
    // controls (MLS membership, UCAN gating, earned capacity thresholds)
    // before it can even request a key.
    if let Some(members) = params.context_members
        && !members.contains(&request.requester_did)
    {
        return Err(SenderKeyError::NotContextMember {
            did: request.requester_did.clone(),
        });
    }

    // Check block list: if requester is blocked, return None (no response).
    if params.block_list.contains(&request.requester_did) {
        return Ok(None);
    }

    // The wrapping public key is already validated as [u8; 32] by serde.
    let wrapping_bytes: [u8; 32] = request.wrapping_pubkey;

    // HPKE seal: encrypt the sender key to the requester's wrapping key.
    // Context binding (§9.16.2): info and AAD include context_id, sender_did, epoch.
    let (sealed_vec, ephemeral_pub) = hpke_seal_sender_key(
        params.sender_key.as_bytes(),
        &wrapping_bytes,
        params.context_id,
        params.sender_did,
        params.epoch,
    )?;

    // Convert to fixed-size array. hpke_seal always returns exactly 60 bytes
    // (nonce 12 + ciphertext 32 + tag 16) for a 32-byte plaintext input.
    let sealed: [u8; 60] = sealed_vec.try_into().map_err(|v: Vec<u8>| {
        SenderKeyError::HpkeEncryptionFailed(format!(
            "HPKE seal produced {} bytes, expected 60",
            v.len()
        ))
    })?;

    let response = SenderKeyResponse {
        sender_did: params.sender_did.to_owned(),
        epoch: params.epoch,
        hpke_sealed_key: sealed,
        ephemeral_pubkey: ephemeral_pub,
        request_nonce: request.nonce,
    };

    let message = rmp_serde::to_vec_named(&response)
        .map_err(|e| SenderKeyError::SerializationFailed(e.to_string()))?;

    // Record nonce only after successful processing to prevent the dedup
    // cache from being poisoned by requests that fail for other reasons
    // (e.g., the requester is blocked or not a member).
    nonce_dedup.record(request.nonce, params.now_secs);

    Ok(Some(message))
}

// ---------------------------------------------------------------------------
// Open sender key response (requester side) — async custody variant
// ---------------------------------------------------------------------------

/// Decrypts a [`SenderKeyResponse`] using the requester's wrapping key handle
/// inside the [`KeyCustody`] boundary.
///
/// The shared secret is computed via `key_custody.dh_agree(wrapping_key_handle,
/// ephemeral_pk)` so the wrapping private key never leaves custody. KDF + AEAD
/// decryption then recovers the sender key in software.
///
/// # Errors
///
/// Returns [`SenderKeyError::KeyCustodyError`] if the DH agreement fails.
/// Returns [`SenderKeyError::HpkeDecryptionFailed`] if AEAD decryption fails.
pub async fn open_sender_key_response(
    key_custody: &impl KeyCustody,
    wrapping_key_handle: &KeyHandle,
    context_id: &str,
    response: &SenderKeyResponse,
) -> Result<SenderKey, SenderKeyError> {
    // hpke_sealed_key is [u8; 60] — length is enforced at the type level
    // (nonce 12 + ciphertext 32 + AES-128-GCM tag 16 = 60 bytes).
    // The ephemeral public key is already validated as [u8; 32] by serde.
    let ephemeral_bytes: [u8; 32] = response.ephemeral_pubkey;

    // Compute shared secret inside custody boundary.
    let shared_secret = key_custody
        .dh_agree(wrapping_key_handle, &ephemeral_bytes)
        .await
        .map_err(|e| SenderKeyError::KeyCustodyError(e.to_string()))?;

    // Build context-bound info and AAD (§9.16.2) using response fields.
    let info = build_hpke_info(context_id, &response.sender_did, response.epoch);
    let aad = build_hpke_aad(context_id, &response.sender_did, response.epoch);

    // Derive AES-128-GCM key from shared secret (zeroized on drop).
    let aes_key = hkdf_derive_key(shared_secret.as_bytes(), &info)?;

    // Decrypt the sealed sender key with AAD verification.
    let plaintext = aes128gcm_decrypt(&aes_key, &response.hpke_sealed_key, &aad)?;

    let key_bytes: [u8; 32] = plaintext.as_slice().try_into().map_err(|_| {
        SenderKeyError::HpkeDecryptionFailed(format!(
            "decrypted key must be 32 bytes, got {}",
            plaintext.len()
        ))
    })?;

    Ok(SenderKey::from_bytes(key_bytes))
}

// ---------------------------------------------------------------------------
// Block notification — signing
// ---------------------------------------------------------------------------

/// Constructs a signed [`BlockNotification`] and serializes it for
/// transmission as an MLS application message.
///
/// Signature payload:
/// `SHA-256(context_id || "block" || blocker_did || blocked_did || signing_key_id || timestamp_BE)`.
///
/// # Errors
///
/// Returns [`SenderKeyError::SigningFailed`] if the signing operation fails.
/// Returns [`SenderKeyError::SerializationFailed`] if serialization fails.
#[allow(clippy::similar_names)] // blocker_did/blocked_did are domain terms
pub async fn send_block_notification(
    key_custody: &impl KeyCustody,
    signing_key: &KeyHandle,
    context_id: &str,
    blocker_did: &str,
    blocked_did: &str,
    signing_key_id: SigningKeyId,
) -> Result<Vec<u8>, SenderKeyError> {
    let timestamp = current_timestamp_ms()?;

    let hash = compute_block_notification_hash(
        context_id,
        blocker_did,
        blocked_did,
        signing_key_id,
        timestamp,
    );

    let signature = key_custody
        .sign(signing_key, &hash)
        .await
        .map_err(|e| SenderKeyError::SigningFailed(e.to_string()))?;

    let sig_bytes: [u8; 64] = signature
        .into_bytes()
        .try_into()
        .map_err(|_| SenderKeyError::SigningFailed("Ed25519 signature must be 64 bytes".into()))?;

    let notification = BlockNotification {
        notification_type: "block".to_owned(),
        blocker: blocker_did.to_owned(),
        blocked: blocked_did.to_owned(),
        signing_key_id,
        timestamp,
        signature: sig_bytes,
    };

    rmp_serde::to_vec_named(&notification)
        .map_err(|e| SenderKeyError::SerializationFailed(e.to_string()))
}

// ---------------------------------------------------------------------------
// Rotate sender key for block — async
// ---------------------------------------------------------------------------

/// Generates a new sender key, increments the epoch, publishes a
/// [`SenderKeyEpochAdvance`], and adds the blocked DID to the block list.
///
/// Non-blocked members observe the epoch advance, send a
/// [`SenderKeyRequest`], and receive the new key via
/// [`handle_sender_key_request`] which checks the block list. The blocked
/// party can send a request but receives no response.
///
/// # Errors
///
/// Returns [`SenderKeyError::EpochOverflow`] if the epoch counter is at
/// `u64::MAX` and cannot be incremented.
/// Returns [`SenderKeyError::SigningFailed`] if signing the epoch advance fails.
/// Returns [`SenderKeyError::SerializationFailed`] if serialization fails.
pub async fn rotate_sender_key_for_block<S: BuildHasher + Send + Sync>(
    key_custody: &impl KeyCustody,
    signing_key: &KeyHandle,
    params: &RotateForBlockParams<'_>,
    block_list: &mut HashSet<String, S>,
) -> Result<RotateForBlockResult, SenderKeyError> {
    // Generate new sender key.
    let new_key = generate_sender_key();
    let new_epoch = params
        .current_epoch
        .checked_add(1)
        .ok_or(SenderKeyError::EpochOverflow)?;

    // Add blocked DID to block list.
    block_list.insert(params.blocked_did.to_owned());

    // Publish epoch advance notification.
    let epoch_advance_message = publish_sender_key_epoch_advance(
        key_custody,
        signing_key,
        params.context_id,
        params.sender_did,
        new_epoch,
        params.signer_key_ref,
    )
    .await?;

    Ok(RotateForBlockResult {
        new_key,
        new_epoch,
        epoch_advance_message,
    })
}

// ---------------------------------------------------------------------------
// Async Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::items_after_statements
)]
mod tests {
    use std::collections::HashSet;

    use scp_platform::testing::InMemoryKeyCustody;
    use scp_platform::traits::{KeyCustody, KeyType};

    use super::super::key_protocol_verify::{
        BLOCK_NOTIFICATION_FRESHNESS_MS, REQUEST_FRESHNESS_SECS,
    };
    use super::*;

    /// Creates a test custody and an Ed25519 signing key.
    async fn setup() -> (InMemoryKeyCustody, KeyHandle) {
        let custody = InMemoryKeyCustody::new();
        let key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        (custody, key)
    }

    /// Creates test fixtures for sender key request handling tests.
    ///
    /// Returns `(bob_custody, bob_signing_key, bob_public_key, sender_key)`.
    async fn setup_request_test_fixtures() -> (
        InMemoryKeyCustody,
        KeyHandle,
        scp_platform::traits::PublicKey,
        SenderKey,
    ) {
        let bob_custody = InMemoryKeyCustody::new();
        let bob_signing_key = bob_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .unwrap();
        let bob_pubkey = bob_custody.public_key(&bob_signing_key).await.unwrap();
        let sender_key = generate_sender_key();
        (bob_custody, bob_signing_key, bob_pubkey, sender_key)
    }

    // -------------------------------------------------------------------
    // SenderKeyEpochAdvance tests
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn epoch_advance_creation_and_signature_verification() {
        let (custody, signing_key) = setup().await;
        let pubkey = custody.public_key(&signing_key).await.unwrap();

        let message = publish_sender_key_epoch_advance(
            &custody,
            &signing_key,
            "ctx-1",
            "did:dht:alice",
            5,
            SigningKeyId::Active,
        )
        .await
        .unwrap();

        let advance: SenderKeyEpochAdvance = rmp_serde::from_slice(&message).unwrap();
        assert_eq!(advance.sender_did, "did:dht:alice");
        assert_eq!(advance.epoch, 5);
        assert_eq!(advance.signer_key_ref, SigningKeyId::Active);

        let valid = verify_epoch_advance(&advance, "ctx-1", pubkey.as_bytes()).unwrap();
        assert!(valid, "epoch advance signature should be valid");
    }

    #[tokio::test]
    async fn epoch_advance_rejects_wrong_context() {
        let (custody, signing_key) = setup().await;
        let pubkey = custody.public_key(&signing_key).await.unwrap();

        let message = publish_sender_key_epoch_advance(
            &custody,
            &signing_key,
            "ctx-1",
            "did:dht:alice",
            5,
            SigningKeyId::Active,
        )
        .await
        .unwrap();

        let advance: SenderKeyEpochAdvance = rmp_serde::from_slice(&message).unwrap();

        // Verify with wrong context_id should fail.
        let valid = verify_epoch_advance(&advance, "ctx-WRONG", pubkey.as_bytes()).unwrap();
        assert!(!valid, "wrong context should invalidate signature");
    }

    #[tokio::test]
    async fn epoch_advance_rejects_wrong_key() {
        let (custody, signing_key) = setup().await;
        let other_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let wrong_pubkey = custody.public_key(&other_key).await.unwrap();

        let message = publish_sender_key_epoch_advance(
            &custody,
            &signing_key,
            "ctx-1",
            "did:dht:alice",
            5,
            SigningKeyId::Active,
        )
        .await
        .unwrap();

        let advance: SenderKeyEpochAdvance = rmp_serde::from_slice(&message).unwrap();
        let valid = verify_epoch_advance(&advance, "ctx-1", wrong_pubkey.as_bytes()).unwrap();
        assert!(!valid, "wrong public key should invalidate signature");
    }

    #[tokio::test]
    async fn epoch_advance_with_agent_signing_key() {
        let (custody, signing_key) = setup().await;
        let pubkey = custody.public_key(&signing_key).await.unwrap();

        let message = publish_sender_key_epoch_advance(
            &custody,
            &signing_key,
            "ctx-1",
            "did:dht:alice",
            3,
            SigningKeyId::Agent,
        )
        .await
        .unwrap();

        let advance: SenderKeyEpochAdvance = rmp_serde::from_slice(&message).unwrap();
        assert_eq!(advance.signer_key_ref, SigningKeyId::Agent);

        let valid = verify_epoch_advance(&advance, "ctx-1", pubkey.as_bytes()).unwrap();
        assert!(valid, "Agent signing key epoch advance should verify");
    }

    #[tokio::test]
    async fn epoch_advance_rejects_tampered_signer_key_ref() {
        let (custody, signing_key) = setup().await;
        let pubkey = custody.public_key(&signing_key).await.unwrap();

        let message = publish_sender_key_epoch_advance(
            &custody,
            &signing_key,
            "ctx-1",
            "did:dht:alice",
            3,
            SigningKeyId::Active,
        )
        .await
        .unwrap();

        let mut advance: SenderKeyEpochAdvance = rmp_serde::from_slice(&message).unwrap();
        // Tamper: flip signer_key_ref from Active to Agent.
        advance.signer_key_ref = SigningKeyId::Agent;

        let valid = verify_epoch_advance(&advance, "ctx-1", pubkey.as_bytes()).unwrap();
        assert!(
            !valid,
            "tampering with signer_key_ref must invalidate signature"
        );
    }

    #[tokio::test]
    async fn epoch_advance_serde_defaults_signer_key_ref_to_active() {
        // Simulate an old-format message without signer_key_ref by
        // constructing a minimal struct that omits the field.
        #[derive(serde::Serialize)]
        struct LegacyAdvance {
            sender_did: String,
            epoch: u64,
            #[serde(with = "serde_bytes")]
            signature: Vec<u8>,
        }

        let (custody, signing_key) = setup().await;

        let message = publish_sender_key_epoch_advance(
            &custody,
            &signing_key,
            "ctx-1",
            "did:dht:alice",
            5,
            SigningKeyId::Active,
        )
        .await
        .unwrap();

        let advance: SenderKeyEpochAdvance = rmp_serde::from_slice(&message).unwrap();
        let legacy = LegacyAdvance {
            sender_did: advance.sender_did.clone(),
            epoch: advance.epoch,
            signature: advance.signature.to_vec(),
        };
        let legacy_bytes = rmp_serde::to_vec_named(&legacy).unwrap();
        let deserialized: SenderKeyEpochAdvance = rmp_serde::from_slice(&legacy_bytes).unwrap();

        assert_eq!(
            deserialized.signer_key_ref,
            SigningKeyId::Active,
            "missing signer_key_ref should default to Active"
        );
    }

    // -------------------------------------------------------------------
    // SenderKeyRequest/Response roundtrip with HPKE
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn request_response_roundtrip_with_hpke() {
        // Setup: Alice (sender/responder) and Bob (requester).
        let alice_custody = InMemoryKeyCustody::new();
        let _alice_signing_key = alice_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .unwrap();

        let bob_custody = InMemoryKeyCustody::new();
        let bob_signing_key = bob_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .unwrap();
        let bob_pubkey = bob_custody.public_key(&bob_signing_key).await.unwrap();

        let sender_key = generate_sender_key();
        let sender_key_bytes = *sender_key.as_bytes();

        // Bob creates a request for Alice's key.
        let request_result = request_sender_key(
            &bob_custody,
            &bob_signing_key,
            "did:dht:bob",
            "did:dht:alice",
            1,
        )
        .await
        .unwrap();

        let request: SenderKeyRequest =
            rmp_serde::from_slice(&request_result.request_message).unwrap();

        // Alice handles the request (no membership gate — backward compat).
        let block_list = HashSet::new();
        let mut nonce_dedup = NonceDedup::new();
        let response_bytes = handle_sender_key_request(
            &request,
            bob_pubkey.as_bytes(),
            &HandleRequestParams {
                sender_key: &sender_key,
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                block_list: &block_list,
                context_members: None,
                now_secs: request.timestamp,
            },
            &mut nonce_dedup,
        )
        .await
        .unwrap();

        assert!(
            response_bytes.is_some(),
            "non-blocked requester should get a response"
        );
        let response: SenderKeyResponse = rmp_serde::from_slice(&response_bytes.unwrap()).unwrap();

        assert_eq!(response.sender_did, "did:dht:alice");
        assert_eq!(response.epoch, 1);

        // Bob opens the response using his wrapping key.
        let recovered_key = open_sender_key_response(
            &bob_custody,
            &request_result.wrapping_key_handle,
            "ctx-1",
            &response,
        )
        .await
        .unwrap();

        assert_eq!(
            recovered_key.as_bytes(),
            &sender_key_bytes,
            "recovered sender key should match original"
        );
    }

    #[tokio::test]
    async fn request_signature_verification() {
        let (custody, signing_key) = setup().await;
        let pubkey = custody.public_key(&signing_key).await.unwrap();

        let result = request_sender_key(&custody, &signing_key, "did:dht:bob", "did:dht:alice", 3)
            .await
            .unwrap();

        let request: SenderKeyRequest = rmp_serde::from_slice(&result.request_message).unwrap();

        let valid = verify_sender_key_request(&request, pubkey.as_bytes()).unwrap();
        assert!(valid, "request signature should be valid");
    }

    #[tokio::test]
    async fn request_rejects_wrong_signer() {
        let custody = InMemoryKeyCustody::new();
        let signing_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let other_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let wrong_pubkey = custody.public_key(&other_key).await.unwrap();

        let result = request_sender_key(&custody, &signing_key, "did:dht:bob", "did:dht:alice", 3)
            .await
            .unwrap();

        let request: SenderKeyRequest = rmp_serde::from_slice(&result.request_message).unwrap();

        let valid = verify_sender_key_request(&request, wrong_pubkey.as_bytes()).unwrap();
        assert!(!valid, "wrong signer should invalidate request signature");
    }

    // -------------------------------------------------------------------
    // Block list enforcement
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn blocked_requester_gets_no_response() {
        let bob_custody = InMemoryKeyCustody::new();
        let bob_signing_key = bob_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .unwrap();
        let bob_pubkey = bob_custody.public_key(&bob_signing_key).await.unwrap();

        let sender_key = generate_sender_key();

        // Bob creates a request.
        let request_result = request_sender_key(
            &bob_custody,
            &bob_signing_key,
            "did:dht:bob",
            "did:dht:alice",
            1,
        )
        .await
        .unwrap();

        let request: SenderKeyRequest =
            rmp_serde::from_slice(&request_result.request_message).unwrap();

        // Alice has Bob on her block list.
        let mut block_list = HashSet::new();
        block_list.insert("did:dht:bob".into());

        let mut nonce_dedup = NonceDedup::new();
        let response = handle_sender_key_request(
            &request,
            bob_pubkey.as_bytes(),
            &HandleRequestParams {
                sender_key: &sender_key,
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                block_list: &block_list,
                context_members: None,
                now_secs: request.timestamp,
            },
            &mut nonce_dedup,
        )
        .await
        .unwrap();

        assert!(
            response.is_none(),
            "blocked requester should receive no response"
        );
    }

    #[tokio::test]
    async fn unblocked_requester_gets_response() {
        let bob_custody = InMemoryKeyCustody::new();
        let bob_signing_key = bob_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .unwrap();
        let bob_pubkey = bob_custody.public_key(&bob_signing_key).await.unwrap();

        let sender_key = generate_sender_key();

        let request_result = request_sender_key(
            &bob_custody,
            &bob_signing_key,
            "did:dht:bob",
            "did:dht:alice",
            1,
        )
        .await
        .unwrap();

        let request: SenderKeyRequest =
            rmp_serde::from_slice(&request_result.request_message).unwrap();

        // Block list has someone else, not Bob.
        let mut block_list = HashSet::new();
        block_list.insert("did:dht:dave".into());

        let mut nonce_dedup = NonceDedup::new();
        let response = handle_sender_key_request(
            &request,
            bob_pubkey.as_bytes(),
            &HandleRequestParams {
                sender_key: &sender_key,
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                block_list: &block_list,
                context_members: None,
                now_secs: request.timestamp,
            },
            &mut nonce_dedup,
        )
        .await
        .unwrap();

        assert!(
            response.is_some(),
            "unblocked requester should receive a response"
        );
    }

    // -------------------------------------------------------------------
    // Membership gate — Sybil defense (BLACK-006)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn non_member_rejected_when_context_members_provided() {
        let sybil_custody = InMemoryKeyCustody::new();
        let sybil_signing_key = sybil_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .unwrap();
        let sybil_pubkey = sybil_custody.public_key(&sybil_signing_key).await.unwrap();

        let sender_key = generate_sender_key();

        // Sybil identity creates a request.
        let request_result = request_sender_key(
            &sybil_custody,
            &sybil_signing_key,
            "did:dht:sybil",
            "did:dht:alice",
            1,
        )
        .await
        .unwrap();

        let request: SenderKeyRequest =
            rmp_serde::from_slice(&request_result.request_message).unwrap();

        let block_list: HashSet<String> = HashSet::new();

        // Context members do NOT include the Sybil identity.
        let mut members = HashSet::new();
        members.insert("did:dht:alice".to_owned());
        members.insert("did:dht:bob".to_owned());

        let mut nonce_dedup = NonceDedup::new();
        let result = handle_sender_key_request(
            &request,
            sybil_pubkey.as_bytes(),
            &HandleRequestParams {
                sender_key: &sender_key,
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                block_list: &block_list,
                context_members: Some(&members),
                now_secs: request.timestamp,
            },
            &mut nonce_dedup,
        )
        .await;

        assert!(
            matches!(result, Err(SenderKeyError::NotContextMember { .. })),
            "non-member Sybil DID should be rejected, got {result:?}"
        );
    }

    #[tokio::test]
    async fn member_allowed_when_context_members_provided() {
        let bob_custody = InMemoryKeyCustody::new();
        let bob_signing_key = bob_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .unwrap();
        let bob_pubkey = bob_custody.public_key(&bob_signing_key).await.unwrap();

        let sender_key = generate_sender_key();

        let request_result = request_sender_key(
            &bob_custody,
            &bob_signing_key,
            "did:dht:bob",
            "did:dht:alice",
            1,
        )
        .await
        .unwrap();

        let request: SenderKeyRequest =
            rmp_serde::from_slice(&request_result.request_message).unwrap();

        let block_list: HashSet<String> = HashSet::new();

        // Context members include Bob.
        let mut members = HashSet::new();
        members.insert("did:dht:alice".to_owned());
        members.insert("did:dht:bob".to_owned());

        let mut nonce_dedup = NonceDedup::new();
        let response = handle_sender_key_request(
            &request,
            bob_pubkey.as_bytes(),
            &HandleRequestParams {
                sender_key: &sender_key,
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                block_list: &block_list,
                context_members: Some(&members),
                now_secs: request.timestamp,
            },
            &mut nonce_dedup,
        )
        .await
        .unwrap();

        assert!(
            response.is_some(),
            "member should receive a response when context_members is provided"
        );
    }

    // -------------------------------------------------------------------
    // expand_block_list + Sybil (async E2E test)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn expanded_block_list_blocks_sybil_identity() {
        // End-to-end: Dave is blocked. Dave's Sybil alias is linked.
        // The expanded block list should block the Sybil alias too.
        let sybil_custody = InMemoryKeyCustody::new();
        let sybil_signing_key = sybil_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .unwrap();
        let sybil_pubkey = sybil_custody.public_key(&sybil_signing_key).await.unwrap();

        let sender_key = generate_sender_key();

        // Sybil identity requests the key.
        let request_result = request_sender_key(
            &sybil_custody,
            &sybil_signing_key,
            "did:dht:dave-alt",
            "did:dht:alice",
            1,
        )
        .await
        .unwrap();

        let request: SenderKeyRequest =
            rmp_serde::from_slice(&request_result.request_message).unwrap();

        // Original block list only has Dave.
        let mut block_list = HashSet::new();
        block_list.insert("did:dht:dave".to_owned());

        // Expand with identity links.
        let expanded = expand_block_list(&block_list, |did| {
            if did == "did:dht:dave" {
                vec!["did:dht:dave-alt".to_owned()]
            } else {
                vec![]
            }
        });

        let mut nonce_dedup = NonceDedup::new();
        let response = handle_sender_key_request(
            &request,
            sybil_pubkey.as_bytes(),
            &HandleRequestParams {
                sender_key: &sender_key,
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                block_list: &expanded,
                context_members: None,
                now_secs: request.timestamp,
            },
            &mut nonce_dedup,
        )
        .await
        .unwrap();

        assert!(
            response.is_none(),
            "Sybil alias should be blocked via expanded block list"
        );
    }

    // -------------------------------------------------------------------
    // Block notification tests
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn block_notification_creation_and_verification() {
        let (custody, signing_key) = setup().await;
        let pubkey = custody.public_key(&signing_key).await.unwrap();

        let message = send_block_notification(
            &custody,
            &signing_key,
            "ctx-1",
            "did:dht:alice",
            "did:dht:dave",
            SigningKeyId::Active,
        )
        .await
        .unwrap();

        let notification: BlockNotification = rmp_serde::from_slice(&message).unwrap();
        assert_eq!(notification.notification_type, "block");
        assert_eq!(notification.blocker, "did:dht:alice");
        assert_eq!(notification.blocked, "did:dht:dave");
        assert_eq!(notification.signing_key_id, SigningKeyId::Active);
        assert!(notification.timestamp > 0);

        let valid = verify_block_notification(&notification, "ctx-1", pubkey.as_bytes()).unwrap();
        assert!(valid, "block notification signature should be valid");
    }

    #[tokio::test]
    async fn block_notification_rejects_wrong_context() {
        let (custody, signing_key) = setup().await;
        let pubkey = custody.public_key(&signing_key).await.unwrap();

        let message = send_block_notification(
            &custody,
            &signing_key,
            "ctx-1",
            "did:dht:alice",
            "did:dht:dave",
            SigningKeyId::Active,
        )
        .await
        .unwrap();

        let notification: BlockNotification = rmp_serde::from_slice(&message).unwrap();
        let valid =
            verify_block_notification(&notification, "ctx-WRONG", pubkey.as_bytes()).unwrap();
        assert!(!valid, "wrong context should invalidate block notification");
    }

    #[tokio::test]
    async fn block_notification_rejects_wrong_key() {
        let (custody, signing_key) = setup().await;
        let other_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let wrong_pubkey = custody.public_key(&other_key).await.unwrap();

        let message = send_block_notification(
            &custody,
            &signing_key,
            "ctx-1",
            "did:dht:alice",
            "did:dht:dave",
            SigningKeyId::Active,
        )
        .await
        .unwrap();

        let notification: BlockNotification = rmp_serde::from_slice(&message).unwrap();
        let valid =
            verify_block_notification(&notification, "ctx-1", wrong_pubkey.as_bytes()).unwrap();
        assert!(!valid, "wrong key should invalidate block notification");
    }

    // -------------------------------------------------------------------
    // rotate_sender_key_for_block flow
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn rotate_sender_key_for_block_increments_epoch_and_blocks() {
        let (custody, signing_key) = setup().await;
        let pubkey = custody.public_key(&signing_key).await.unwrap();

        let mut block_list = HashSet::new();
        let current_epoch = 3;

        let result = rotate_sender_key_for_block(
            &custody,
            &signing_key,
            &RotateForBlockParams {
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                current_epoch,
                blocked_did: "did:dht:dave",
                signer_key_ref: SigningKeyId::Active,
            },
            &mut block_list,
        )
        .await
        .unwrap();

        // Epoch should be incremented.
        assert_eq!(result.new_epoch, 4);

        // Block list should contain the blocked DID.
        assert!(block_list.contains("did:dht:dave"));

        // The epoch advance message should be valid.
        let advance: SenderKeyEpochAdvance =
            rmp_serde::from_slice(&result.epoch_advance_message).unwrap();
        assert_eq!(advance.epoch, 4);
        assert_eq!(advance.sender_did, "did:dht:alice");

        let valid = verify_epoch_advance(&advance, "ctx-1", pubkey.as_bytes()).unwrap();
        assert!(valid, "epoch advance from rotate should be valid");

        // New key should be 32 bytes.
        assert_eq!(result.new_key.as_bytes().len(), 32);
    }

    #[tokio::test]
    async fn rotate_sender_key_for_block_multiple_blocks_accumulate() {
        let (custody, signing_key) = setup().await;

        let mut block_list = HashSet::new();

        let result1 = rotate_sender_key_for_block(
            &custody,
            &signing_key,
            &RotateForBlockParams {
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                current_epoch: 0,
                blocked_did: "did:dht:dave",
                signer_key_ref: SigningKeyId::Active,
            },
            &mut block_list,
        )
        .await
        .unwrap();

        let result2 = rotate_sender_key_for_block(
            &custody,
            &signing_key,
            &RotateForBlockParams {
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                current_epoch: result1.new_epoch,
                blocked_did: "did:dht:eve",
                signer_key_ref: SigningKeyId::Active,
            },
            &mut block_list,
        )
        .await
        .unwrap();

        assert_eq!(result2.new_epoch, 2);
        assert!(block_list.contains("did:dht:dave"));
        assert!(block_list.contains("did:dht:eve"));
        assert_eq!(block_list.len(), 2);
    }

    // -------------------------------------------------------------------
    // End-to-end: block then request (blocked party gets nothing)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn blocked_party_cannot_obtain_key_after_rotation() {
        let alice_custody = InMemoryKeyCustody::new();
        let alice_signing_key = alice_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .unwrap();

        let dave_custody = InMemoryKeyCustody::new();
        let dave_signing_key = dave_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .unwrap();
        let dave_pubkey = dave_custody.public_key(&dave_signing_key).await.unwrap();

        let mut block_list = HashSet::new();

        // Alice rotates her key, blocking Dave.
        let rotate_result = rotate_sender_key_for_block(
            &alice_custody,
            &alice_signing_key,
            &RotateForBlockParams {
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                current_epoch: 0,
                blocked_did: "did:dht:dave",
                signer_key_ref: SigningKeyId::Active,
            },
            &mut block_list,
        )
        .await
        .unwrap();

        // Dave tries to request the new key.
        let request_result = request_sender_key(
            &dave_custody,
            &dave_signing_key,
            "did:dht:dave",
            "did:dht:alice",
            rotate_result.new_epoch,
        )
        .await
        .unwrap();

        let request: SenderKeyRequest =
            rmp_serde::from_slice(&request_result.request_message).unwrap();

        // Alice handles Dave's request with the updated block list.
        let mut nonce_dedup = NonceDedup::new();
        let response = handle_sender_key_request(
            &request,
            dave_pubkey.as_bytes(),
            &HandleRequestParams {
                sender_key: &rotate_result.new_key,
                sender_did: "did:dht:alice",
                epoch: rotate_result.new_epoch,
                block_list: &block_list,
                context_members: None,
                now_secs: request.timestamp,
                context_id: "ctx-1",
            },
            &mut nonce_dedup,
        )
        .await
        .unwrap();

        assert!(
            response.is_none(),
            "blocked Dave should not receive Alice's new key"
        );
    }

    // -------------------------------------------------------------------
    // Epoch overflow
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn rotate_sender_key_for_block_epoch_overflow_returns_error() {
        let (custody, signing_key) = setup().await;
        let mut block_list = HashSet::new();

        let result = rotate_sender_key_for_block(
            &custody,
            &signing_key,
            &RotateForBlockParams {
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                current_epoch: u64::MAX,
                blocked_did: "did:dht:dave",
                signer_key_ref: SigningKeyId::Active,
            },
            &mut block_list,
        )
        .await;

        assert!(
            matches!(result, Err(SenderKeyError::EpochOverflow)),
            "epoch at u64::MAX should return EpochOverflow, got {result:?}"
        );
    }

    // -------------------------------------------------------------------
    // validate_block_notification_freshness (SCP-179) — async variants
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn fresh_block_notification_passes_freshness_check() {
        let (custody, signing_key) = setup().await;
        let msg = send_block_notification(
            &custody,
            &signing_key,
            "ctx-1",
            "did:dht:alice",
            "did:dht:dave",
            SigningKeyId::Active,
        )
        .await
        .unwrap();

        let notification: BlockNotification = rmp_serde::from_slice(&msg).unwrap();
        let now_ms = current_timestamp_ms().unwrap();
        let result = validate_block_notification_freshness(&notification, now_ms);
        assert!(
            result.is_ok(),
            "fresh notification should pass freshness check"
        );
    }

    #[tokio::test]
    async fn stale_block_notification_rejected() {
        let (custody, signing_key) = setup().await;
        let msg = send_block_notification(
            &custody,
            &signing_key,
            "ctx-1",
            "did:dht:alice",
            "did:dht:dave",
            SigningKeyId::Active,
        )
        .await
        .unwrap();

        let notification: BlockNotification = rmp_serde::from_slice(&msg).unwrap();
        // Simulate the notification being received far in the future.
        let far_future_ms = notification.timestamp + BLOCK_NOTIFICATION_FRESHNESS_MS + 1_000;
        let result = validate_block_notification_freshness(&notification, far_future_ms);
        assert!(
            matches!(result, Err(SenderKeyError::StaleBlockNotification)),
            "stale notification should be rejected with StaleBlockNotification"
        );
    }

    #[tokio::test]
    async fn future_timestamp_block_notification_rejected() {
        let (custody, signing_key) = setup().await;
        let msg = send_block_notification(
            &custody,
            &signing_key,
            "ctx-1",
            "did:dht:alice",
            "did:dht:dave",
            SigningKeyId::Active,
        )
        .await
        .unwrap();

        let mut notification: BlockNotification = rmp_serde::from_slice(&msg).unwrap();
        // Set the notification timestamp far ahead of "now" so it exceeds the
        // freshness window into the future.
        let now_ms = notification.timestamp;
        notification.timestamp = now_ms + BLOCK_NOTIFICATION_FRESHNESS_MS + 10_000;
        let result = validate_block_notification_freshness(&notification, now_ms);
        assert!(
            matches!(result, Err(SenderKeyError::StaleBlockNotification)),
            "future-timestamped notification should be rejected with StaleBlockNotification"
        );
    }

    #[tokio::test]
    async fn sender_key_response_echoes_request_nonce() {
        let alice_custody = InMemoryKeyCustody::new();
        let _alice_signing_key = alice_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .unwrap();

        let requester_custody = InMemoryKeyCustody::new();
        let requester_signing_key = requester_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .unwrap();
        // The requester's *public* key is used by the responder to verify the request signature.
        let requester_pubkey = requester_custody
            .public_key(&requester_signing_key)
            .await
            .unwrap();

        let sender_key = generate_sender_key();
        let block_list: HashSet<String> = HashSet::new();

        let result = request_sender_key(
            &requester_custody,
            &requester_signing_key,
            "did:dht:requester",
            "did:dht:alice",
            1,
        )
        .await
        .unwrap();

        let request: SenderKeyRequest = rmp_serde::from_slice(&result.request_message).unwrap();
        let original_nonce = request.nonce;

        let mut nonce_dedup = NonceDedup::new();
        let response_bytes = handle_sender_key_request(
            &request,
            requester_pubkey.as_bytes(), // verify requester's signature
            &HandleRequestParams {
                sender_key: &sender_key,
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                block_list: &block_list,
                context_members: None,
                now_secs: request.timestamp,
            },
            &mut nonce_dedup,
        )
        .await
        .unwrap()
        .unwrap();

        let response: SenderKeyResponse = rmp_serde::from_slice(&response_bytes).unwrap();
        assert_eq!(
            response.request_nonce, original_nonce,
            "response must echo the request nonce"
        );
    }

    // -------------------------------------------------------------------
    // handle_request_rejects_stale_timestamp / replayed nonce
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn handle_request_rejects_stale_timestamp() {
        let (bob_custody, bob_signing_key, bob_pubkey, sender_key) =
            setup_request_test_fixtures().await;

        let request_result = request_sender_key(
            &bob_custody,
            &bob_signing_key,
            "did:dht:bob",
            "did:dht:alice",
            1,
        )
        .await
        .unwrap();

        let request: SenderKeyRequest =
            rmp_serde::from_slice(&request_result.request_message).unwrap();

        let block_list: HashSet<String> = HashSet::new();
        let mut nonce_dedup = NonceDedup::new();
        // Simulate receiving the request far in the future.
        let stale_now = request.timestamp + REQUEST_FRESHNESS_SECS + 100;
        let result = handle_sender_key_request(
            &request,
            bob_pubkey.as_bytes(),
            &HandleRequestParams {
                sender_key: &sender_key,
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                block_list: &block_list,
                context_members: None,
                now_secs: stale_now,
            },
            &mut nonce_dedup,
        )
        .await;

        assert!(
            matches!(result, Err(SenderKeyError::StaleSenderKeyRequest)),
            "stale request should be rejected, got {result:?}"
        );
    }

    #[tokio::test]
    async fn handle_request_rejects_replayed_nonce() {
        let (bob_custody, bob_signing_key, bob_pubkey, sender_key) =
            setup_request_test_fixtures().await;

        let request_result = request_sender_key(
            &bob_custody,
            &bob_signing_key,
            "did:dht:bob",
            "did:dht:alice",
            1,
        )
        .await
        .unwrap();

        let request: SenderKeyRequest =
            rmp_serde::from_slice(&request_result.request_message).unwrap();

        let block_list: HashSet<String> = HashSet::new();
        let mut nonce_dedup = NonceDedup::new();

        let params = HandleRequestParams {
            sender_key: &sender_key,
            context_id: "ctx-1",
            sender_did: "did:dht:alice",
            epoch: 1,
            block_list: &block_list,
            context_members: None,
            now_secs: request.timestamp,
        };

        // First call succeeds.
        let first =
            handle_sender_key_request(&request, bob_pubkey.as_bytes(), &params, &mut nonce_dedup)
                .await;
        assert!(first.is_ok(), "first request should succeed");

        // Second call with same nonce should be rejected as replay.
        let second =
            handle_sender_key_request(&request, bob_pubkey.as_bytes(), &params, &mut nonce_dedup)
                .await;
        assert!(
            matches!(second, Err(SenderKeyError::ReplayedRequest)),
            "replayed request should be rejected, got {second:?}"
        );
    }
}
