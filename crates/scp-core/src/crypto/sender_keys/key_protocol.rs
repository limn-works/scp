//! Pull-based sender key distribution protocol and block notifications.
//!
//! This module is **transport-agnostic** — the same types and protocol apply to
//! both Encrypted contexts (where epoch advances travel as MLS application
//! messages) and Broadcast contexts (where they travel as relay messages).
//! The context/transport layer above determines delivery; this layer handles
//! key generation, rotation, request/response, and blocking.
//!
//! When a sender generates or rotates a key, they publish a lightweight
//! [`SenderKeyEpochAdvance`] notification. Members request the actual key
//! material on demand via HPKE-encrypted [`SenderKeyRequest`] /
//! [`SenderKeyResponse`] exchange.
//!
//! Block notifications ([`BlockNotification`]) enable mutual key rotation:
//! when Alice blocks Dave, a signed notification triggers Dave's client to
//! rotate his sender key excluding Alice.
//!
//! See ADR-007 in `.docs/adrs/phase-1.md` for the full protocol design
//! and §5.14.8 for broadcast-mode blocking specifics.

use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Pub};
use zeroize::Zeroizing;

use scp_platform::traits::{KeyCustody, KeyHandle, KeyType};

use super::{SenderKey, SenderKeyError, generate_sender_key};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// AES-128-GCM nonce size in bytes.
const HPKE_NONCE_SIZE: usize = 12;

/// HKDF info string for sender key HPKE encryption.
const HPKE_INFO: &[u8] = b"scp-sender-key-hpke-v1";

/// Grace period in seconds during which the old key should still be accepted
/// for decryption of in-flight messages after an epoch advance.
pub const GRACE_PERIOD_SECS: u64 = 30;

/// Size of the cryptographic nonce embedded in sender key requests (bytes).
const REQUEST_NONCE_SIZE: usize = 16;

/// Duration in seconds for which a seen nonce is remembered to prevent replay.
const NONCE_EXPIRY_SECS: u64 = 300; // 5 minutes

/// Maximum age in milliseconds for a block notification to be considered fresh.
const BLOCK_NOTIFICATION_FRESHNESS_MS: u64 = 30_000; // 30 seconds

/// Maximum number of nonces tracked by [`NonceDedup`] to prevent memory exhaustion.
const NONCE_DEDUP_CAPACITY: usize = 10_000;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Lightweight notification that a sender rotated their key to a new epoch.
///
/// Published as an MLS application message (broadcast to all group members).
/// Recipients verify the signature and record the new epoch, then request
/// the actual key material via [`SenderKeyRequest`]. **O(1) cost** regardless
/// of group size.
///
/// Signature payload: `SHA-256(context_id || sender_did || "key_epoch" || epoch_BE)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderKeyEpochAdvance {
    /// The DID of the sender who rotated their key.
    pub sender_did: String,
    /// The new epoch number for this sender's key.
    pub epoch: u64,
    /// Ed25519 signature over the epoch advance payload.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// Request for a sender's current key at a specific epoch.
///
/// Sent as an MLS application message to the key holder. The requester
/// includes a fresh X25519 wrapping public key so the responder can
/// HPKE-encrypt the sender key material.
///
/// Contains a cryptographic nonce and timestamp for replay protection.
/// The responder rejects requests with duplicate nonces within a 5-minute
/// window and echoes the nonce in the response for binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderKeyRequest {
    /// The DID of the member requesting the key.
    pub requester_did: String,
    /// The DID of the sender whose key is being requested.
    pub sender_did: String,
    /// The epoch number being requested.
    pub epoch: u64,
    /// Fresh X25519 public key for HPKE wrapping.
    #[serde(with = "serde_bytes")]
    pub wrapping_pubkey: Vec<u8>,
    /// Cryptographic nonce for replay protection (16 bytes, generated with
    /// `OsRng`). The responder echoes this in [`SenderKeyResponse::request_nonce`]
    /// and rejects duplicate nonces within [`NONCE_EXPIRY_SECS`].
    pub nonce: [u8; REQUEST_NONCE_SIZE],
    /// Unix timestamp in seconds when the request was created.
    pub timestamp: u64,
    /// Ed25519 signature over the request payload.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// Response containing HPKE-encrypted sender key material.
///
/// Sent as an MLS application message back to the requester. The sender
/// key is encrypted using HPKE: ephemeral X25519 ECDH + HKDF + AES-128-GCM.
///
/// The [`request_nonce`][SenderKeyResponse::request_nonce] field echoes the
/// nonce from the corresponding [`SenderKeyRequest`] to bind the response to
/// the originating request and prevent response substitution attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderKeyResponse {
    /// The DID of the sender whose key is being distributed.
    pub sender_did: String,
    /// The epoch of the distributed key.
    pub epoch: u64,
    /// HPKE-sealed sender key bytes (AES-128-GCM nonce || ciphertext || tag).
    #[serde(with = "serde_bytes")]
    pub hpke_sealed_key: Vec<u8>,
    /// The ephemeral X25519 public key used in the HPKE encapsulation.
    #[serde(with = "serde_bytes")]
    pub ephemeral_pubkey: Vec<u8>,
    /// Echo of the request nonce from [`SenderKeyRequest::nonce`], binding
    /// this response to the originating request.
    pub request_nonce: [u8; REQUEST_NONCE_SIZE],
}

/// A signed block notification sent as an MLS application message.
///
/// When Alice blocks Dave, Alice sends this notification so Dave's client
/// can automatically rotate Dave's sender key excluding Alice. The signature
/// prevents forgery by other group members.
///
/// Signature payload: `SHA-256(context_id || "block" || blocker_did || blocked_did || timestamp_BE)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockNotification {
    /// The type discriminator for deserialization.
    #[serde(rename = "type")]
    pub notification_type: String,
    /// The DID of the member who initiated the block.
    pub blocker: String,
    /// The DID of the member being blocked.
    pub blocked: String,
    /// Unix timestamp in milliseconds when the block was issued.
    pub timestamp: u64,
    /// Ed25519 signature from the blocker's Active Signing Key.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// Result of [`rotate_sender_key_for_block`], containing the new key,
/// updated epoch, and the serialized epoch advance notification.
#[derive(Debug)]
pub struct RotateForBlockResult {
    /// The newly generated sender key.
    pub new_key: SenderKey,
    /// The new epoch number after rotation.
    pub new_epoch: u64,
    /// The serialized [`SenderKeyEpochAdvance`] message to broadcast.
    pub epoch_advance_message: Vec<u8>,
}

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
// Epoch advance
// ---------------------------------------------------------------------------

/// Constructs a signed [`SenderKeyEpochAdvance`] and serializes it for
/// transmission as an MLS application message.
///
/// The sender signs `SHA-256(context_id || sender_did || "key_epoch" || epoch_BE)`
/// with their Active Signing Key.
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
) -> Result<Vec<u8>, SenderKeyError> {
    let hash = compute_epoch_advance_hash(context_id, sender_did, epoch);

    let signature = key_custody
        .sign(signing_key, &hash)
        .await
        .map_err(|e| SenderKeyError::SigningFailed(e.to_string()))?;

    let advance = SenderKeyEpochAdvance {
        sender_did: sender_did.to_owned(),
        epoch,
        signature: signature.into_bytes(),
    };

    serde_json::to_vec(&advance).map_err(|e| SenderKeyError::SerializationFailed(e.to_string()))
}

/// Verifies the Ed25519 signature on a [`SenderKeyEpochAdvance`].
///
/// The caller must provide the `context_id` since it is not embedded in the
/// advance message (it is known from the MLS group context).
///
/// # Errors
///
/// Returns [`SenderKeyError::VerificationFailed`] if the public key or
/// signature bytes are malformed. Returns `Ok(false)` if the signature is
/// well-formed but invalid.
pub fn verify_epoch_advance(
    advance: &SenderKeyEpochAdvance,
    context_id: &str,
    sender_public_key: &[u8],
) -> Result<bool, SenderKeyError> {
    let hash = compute_epoch_advance_hash(context_id, &advance.sender_did, advance.epoch);
    verify_ed25519_signature(sender_public_key, &hash, &advance.signature)
}

// ---------------------------------------------------------------------------
// Sender key request
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

    let request = SenderKeyRequest {
        requester_did: requester_did.to_owned(),
        sender_did: sender_did.to_owned(),
        epoch,
        wrapping_pubkey: wrapping_pubkey.into_bytes(),
        nonce,
        timestamp,
        signature: signature.into_bytes(),
    };

    let message = serde_json::to_vec(&request)
        .map_err(|e| SenderKeyError::SerializationFailed(e.to_string()))?;

    Ok(SenderKeyRequestResult {
        request_message: message,
        wrapping_key_handle,
    })
}

/// Verifies the Ed25519 signature on a [`SenderKeyRequest`].
///
/// # Errors
///
/// Returns [`SenderKeyError::VerificationFailed`] if the public key or
/// signature bytes are malformed. Returns `Ok(false)` if the signature is
/// well-formed but invalid.
pub fn verify_sender_key_request(
    request: &SenderKeyRequest,
    requester_public_key: &[u8],
) -> Result<bool, SenderKeyError> {
    let hash = compute_request_hash(
        &request.requester_did,
        &request.sender_did,
        request.epoch,
        &request.wrapping_pubkey,
        &request.nonce,
        request.timestamp,
    );
    verify_ed25519_signature(requester_public_key, &hash, &request.signature)
}

// ---------------------------------------------------------------------------
// Handle sender key request (responder side)
// ---------------------------------------------------------------------------

/// Handles an incoming [`SenderKeyRequest`]: verifies the signature, checks
/// membership and the block list, and HPKE-encrypts the sender key to the
/// requester's wrapping public key.
///
/// Returns `None` if the requester is blocked (no response, the requester
/// cannot obtain the key). Returns `Some(serialized_response)` otherwise.
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
/// Returns [`SenderKeyError::NotContextMember`] if `context_members` is
/// provided and the requester is not a member.
/// Returns [`SenderKeyError::VerificationFailed`] if the request signature
/// is invalid or malformed. Returns other variants for HPKE failures.
#[allow(clippy::implicit_hasher)] // context_members uses default hasher for ergonomic None inference
pub async fn handle_sender_key_request<S: BuildHasher + Sync>(
    request: &SenderKeyRequest,
    requester_public_key: &[u8],
    sender_key: &SenderKey,
    sender_did: &str,
    epoch: u64,
    block_list: &HashSet<String, S>,
    context_members: Option<&HashSet<String>>,
) -> Result<Option<Vec<u8>>, SenderKeyError> {
    // Verify the request signature.
    let valid = verify_sender_key_request(request, requester_public_key)?;
    if !valid {
        return Err(SenderKeyError::VerificationFailed(
            "sender key request signature verification failed".to_owned(),
        ));
    }

    // Membership gate (BLACK-006, §9.16.6): reject requests from DIDs
    // that are not context members. This prevents Sybil identities —
    // which bypass per-DID block lists by definition — from obtaining
    // sender keys. The Sybil DID must first pass the context's admission
    // controls (MLS membership, UCAN gating, earned capacity thresholds)
    // before it can even request a key.
    if let Some(members) = context_members
        && !members.contains(&request.requester_did)
    {
        return Err(SenderKeyError::NotContextMember {
            did: request.requester_did.clone(),
        });
    }

    // Check block list: if requester is blocked, return None (no response).
    if block_list.contains(&request.requester_did) {
        return Ok(None);
    }

    // Parse the requester's wrapping public key.
    let wrapping_bytes: [u8; 32] = request.wrapping_pubkey.as_slice().try_into().map_err(|_| {
        SenderKeyError::VerificationFailed(format!(
            "wrapping pubkey must be 32 bytes, got {}",
            request.wrapping_pubkey.len()
        ))
    })?;

    // HPKE seal: encrypt the sender key to the requester's wrapping key.
    let (sealed, ephemeral_pub) = hpke_seal(sender_key.as_bytes(), &wrapping_bytes)?;

    let response = SenderKeyResponse {
        sender_did: sender_did.to_owned(),
        epoch,
        hpke_sealed_key: sealed,
        ephemeral_pubkey: ephemeral_pub.to_vec(),
        request_nonce: request.nonce,
    };

    let message = serde_json::to_vec(&response)
        .map_err(|e| SenderKeyError::SerializationFailed(e.to_string()))?;

    Ok(Some(message))
}

// ---------------------------------------------------------------------------
// Expand block list with identity-linked DIDs (BLACK-006, §9.16.6)
// ---------------------------------------------------------------------------

/// Expands a block list to include identity-linked DIDs (Sybil defense).
///
/// Given a block list and a resolver that maps each blocked DID to its
/// identity-linked DIDs (e.g., other DIDs attested to the same human via
/// attestation chains, or DIDs flagged by context governance as Sybil
/// aliases), returns a new `HashSet` containing the union of the original
/// block list and all linked DIDs.
///
/// This function is the caller's integration point for identity-group
/// blocking (§9.16.6). The `identity_links` callback is deliberately
/// abstract: it may consult attestation chains (§3.5, §7.4), governance
/// records, or any context-specific Sybil detection mechanism. The sender
/// key layer does not prescribe the linking strategy — it provides the
/// expansion mechanism.
///
/// # Example
///
/// ```
/// use std::collections::{HashMap, HashSet};
/// use scp_core::crypto::sender_keys::key_protocol::expand_block_list;
///
/// let mut block_list = HashSet::new();
/// block_list.insert("did:dht:dave".to_owned());
///
/// // Identity resolver: dave has a known Sybil alias
/// let mut links: HashMap<String, Vec<String>> = HashMap::new();
/// links.insert(
///     "did:dht:dave".to_owned(),
///     vec!["did:dht:dave-alt".to_owned()],
/// );
///
/// let expanded = expand_block_list(&block_list, |did| {
///     links.get(did).cloned().unwrap_or_default()
/// });
///
/// assert!(expanded.contains("did:dht:dave"));
/// assert!(expanded.contains("did:dht:dave-alt"));
/// ```
#[must_use]
pub fn expand_block_list<F, S: BuildHasher>(
    block_list: &HashSet<String, S>,
    identity_links: F,
) -> HashSet<String>
where
    F: Fn(&str) -> Vec<String>,
{
    let mut expanded: HashSet<String> = block_list.iter().cloned().collect();
    for did in block_list {
        for linked in identity_links(did) {
            expanded.insert(linked);
        }
    }
    expanded
}

// ---------------------------------------------------------------------------
// Open sender key response (requester side)
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
    response: &SenderKeyResponse,
) -> Result<SenderKey, SenderKeyError> {
    let ephemeral_bytes: [u8; 32] =
        response
            .ephemeral_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| {
                SenderKeyError::HpkeDecryptionFailed(format!(
                    "ephemeral pubkey must be 32 bytes, got {}",
                    response.ephemeral_pubkey.len()
                ))
            })?;

    // Compute shared secret inside custody boundary.
    let shared_secret = key_custody
        .dh_agree(wrapping_key_handle, &ephemeral_bytes)
        .await
        .map_err(|e| SenderKeyError::KeyCustodyError(e.to_string()))?;

    // Derive AES-128-GCM key from shared secret (zeroized on drop).
    let aes_key = hkdf_derive_key(shared_secret.as_bytes())?;

    // Decrypt the sealed sender key.
    let plaintext = aes128gcm_decrypt(&aes_key, &response.hpke_sealed_key)?;

    let key_bytes: [u8; 32] = plaintext.as_slice().try_into().map_err(|_| {
        SenderKeyError::HpkeDecryptionFailed(format!(
            "decrypted key must be 32 bytes, got {}",
            plaintext.len()
        ))
    })?;

    Ok(SenderKey::from_bytes(key_bytes))
}

// ---------------------------------------------------------------------------
// Block notification
// ---------------------------------------------------------------------------

/// Constructs a signed [`BlockNotification`] and serializes it for
/// transmission as an MLS application message.
///
/// Signature payload:
/// `SHA-256(context_id || "block" || blocker_did || blocked_did || timestamp_BE)`.
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
) -> Result<Vec<u8>, SenderKeyError> {
    let timestamp = current_timestamp_ms()?;

    let hash = compute_block_notification_hash(context_id, blocker_did, blocked_did, timestamp);

    let signature = key_custody
        .sign(signing_key, &hash)
        .await
        .map_err(|e| SenderKeyError::SigningFailed(e.to_string()))?;

    let notification = BlockNotification {
        notification_type: "block_notification".to_owned(),
        blocker: blocker_did.to_owned(),
        blocked: blocked_did.to_owned(),
        timestamp,
        signature: signature.into_bytes(),
    };

    serde_json::to_vec(&notification)
        .map_err(|e| SenderKeyError::SerializationFailed(e.to_string()))
}

/// Validates that a [`BlockNotification`] timestamp is within the freshness
/// window.
///
/// Block notifications older than [`BLOCK_NOTIFICATION_FRESHNESS_MS`]
/// milliseconds are rejected to prevent replay of old block events.
///
/// # Parameters
///
/// - `notification` -- The notification to validate.
/// - `now_ms` -- The current Unix timestamp in milliseconds.
///
/// # Errors
///
/// Returns [`SenderKeyError::StaleBlockNotification`] if the notification
/// timestamp is outside the freshness window.
pub const fn validate_block_notification_freshness(
    notification: &BlockNotification,
    now_ms: u64,
) -> Result<(), SenderKeyError> {
    let age_ms = now_ms.saturating_sub(notification.timestamp);
    if age_ms > BLOCK_NOTIFICATION_FRESHNESS_MS {
        return Err(SenderKeyError::StaleBlockNotification);
    }
    Ok(())
}

/// Verifies the Ed25519 signature on a [`BlockNotification`].
///
/// The caller must provide the `context_id` since it is not embedded in the
/// notification (it is known from the MLS group context).
///
/// # Errors
///
/// Returns [`SenderKeyError::VerificationFailed`] if the public key or
/// signature bytes are malformed. Returns `Ok(false)` if the signature is
/// well-formed but invalid.
pub fn verify_block_notification(
    notification: &BlockNotification,
    context_id: &str,
    blocker_public_key: &[u8],
) -> Result<bool, SenderKeyError> {
    let hash = compute_block_notification_hash(
        context_id,
        &notification.blocker,
        &notification.blocked,
        notification.timestamp,
    );
    verify_ed25519_signature(blocker_public_key, &hash, &notification.signature)
}

// ---------------------------------------------------------------------------
// Rotate sender key for block
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
    context_id: &str,
    sender_did: &str,
    current_epoch: u64,
    blocked_did: &str,
    block_list: &mut HashSet<String, S>,
) -> Result<RotateForBlockResult, SenderKeyError> {
    // Generate new sender key.
    let new_key = generate_sender_key();
    let new_epoch = current_epoch
        .checked_add(1)
        .ok_or(SenderKeyError::EpochOverflow)?;

    // Add blocked DID to block list.
    block_list.insert(blocked_did.to_owned());

    // Publish epoch advance notification.
    let epoch_advance_message = publish_sender_key_epoch_advance(
        key_custody,
        signing_key,
        context_id,
        sender_did,
        new_epoch,
    )
    .await?;

    Ok(RotateForBlockResult {
        new_key,
        new_epoch,
        epoch_advance_message,
    })
}

// ---------------------------------------------------------------------------
// Nonce deduplication
// ---------------------------------------------------------------------------

/// Bounded nonce deduplication cache for sender key request replay protection.
///
/// Tracks seen request nonces for up to [`NONCE_EXPIRY_SECS`] seconds and
/// caps the stored count at [`NONCE_DEDUP_CAPACITY`] entries to prevent
/// memory exhaustion from `DoS` attacks.
///
/// Callers should call [`NonceDedup::is_replayed`] before processing a
/// request, then [`NonceDedup::record`] once the request is accepted.
#[derive(Debug, Default)]
pub struct NonceDedup {
    /// Nonce bytes → Unix timestamp (seconds) when first seen.
    seen: HashMap<[u8; REQUEST_NONCE_SIZE], u64>,
}

impl NonceDedup {
    /// Creates a new, empty dedup cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }

    /// Returns `true` if `nonce` has been seen within [`NONCE_EXPIRY_SECS`]
    /// of `now_secs`, indicating a replay attempt.
    ///
    /// Also evicts entries older than [`NONCE_EXPIRY_SECS`].
    pub fn is_replayed(&mut self, nonce: &[u8; REQUEST_NONCE_SIZE], now_secs: u64) -> bool {
        self.seen
            .retain(|_, seen_at| now_secs.saturating_sub(*seen_at) < NONCE_EXPIRY_SECS);
        self.seen.contains_key(nonce)
    }

    /// Records `nonce` as seen at `now_secs`.
    ///
    /// If at capacity ([`NONCE_DEDUP_CAPACITY`]), the oldest entry is evicted
    /// to make room.
    pub fn record(&mut self, nonce: [u8; REQUEST_NONCE_SIZE], now_secs: u64) {
        if self.seen.len() >= NONCE_DEDUP_CAPACITY
            && let Some(oldest_key) = self.seen.iter().min_by_key(|(_, ts)| *ts).map(|(k, _)| *k)
        {
            self.seen.remove(&oldest_key);
        }
        self.seen.insert(nonce, now_secs);
    }
}

// ---------------------------------------------------------------------------
// HPKE helpers
// ---------------------------------------------------------------------------

/// HPKE seal: encrypts `plaintext` to `recipient_pub` using ephemeral X25519
/// ECDH + HKDF-SHA256 + AES-128-GCM.
///
/// Returns `(sealed_bytes, ephemeral_public_key)`.
fn hpke_seal(
    plaintext: &[u8; 32],
    recipient_pub: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 32]), SenderKeyError> {
    // 1. Generate ephemeral X25519 keypair.
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519Pub::from(&ephemeral_secret);

    // 2. ECDH between ephemeral secret and recipient's wrapping pubkey.
    let recipient_key = X25519Pub::from(*recipient_pub);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_key);

    // 3. HKDF to derive 16-byte AES-128-GCM key (zeroized on drop).
    let aes_key = hkdf_derive_key(shared_secret.as_bytes())?;

    // 4. AES-128-GCM encrypt.
    let sealed = aes128gcm_encrypt(&aes_key, plaintext)?;

    Ok((sealed, ephemeral_public.to_bytes()))
}

/// Derives a 16-byte AES-128-GCM key from a 32-byte shared secret using
/// HKDF-SHA256.
///
/// The returned key is wrapped in [`Zeroizing`] so the derived key material
/// is zeroed on drop (defense-in-depth, see issue #82).
fn hkdf_derive_key(shared_secret: &[u8]) -> Result<Zeroizing<[u8; 16]>, SenderKeyError> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = Zeroizing::new([0u8; 16]);
    hk.expand(HPKE_INFO, okm.as_mut())
        .map_err(|e| SenderKeyError::HpkeEncryptionFailed(e.to_string()))?;
    Ok(okm)
}

/// Encrypts `plaintext` with AES-128-GCM. Returns `nonce || ciphertext || tag`.
fn aes128gcm_encrypt(key: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>, SenderKeyError> {
    let cipher = Aes128Gcm::new_from_slice(key)
        .map_err(|e| SenderKeyError::HpkeEncryptionFailed(e.to_string()))?;

    let mut nonce_bytes = [0u8; HPKE_NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| SenderKeyError::HpkeEncryptionFailed(e.to_string()))?;

    let mut output = Vec::with_capacity(HPKE_NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypts AES-128-GCM ciphertext of the form `nonce || ciphertext || tag`.
fn aes128gcm_decrypt(key: &[u8; 16], sealed: &[u8]) -> Result<Vec<u8>, SenderKeyError> {
    if sealed.len() < HPKE_NONCE_SIZE {
        return Err(SenderKeyError::HpkeDecryptionFailed(format!(
            "sealed data too short: {} bytes, minimum {}",
            sealed.len(),
            HPKE_NONCE_SIZE
        )));
    }

    let (nonce_bytes, encrypted) = sealed.split_at(HPKE_NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes128Gcm::new_from_slice(key)
        .map_err(|e| SenderKeyError::HpkeDecryptionFailed(e.to_string()))?;

    cipher
        .decrypt(nonce, encrypted)
        .map_err(|e| SenderKeyError::HpkeDecryptionFailed(e.to_string()))
}

// ---------------------------------------------------------------------------
// Hash helpers
// ---------------------------------------------------------------------------

/// Computes `SHA-256("SCP-EPOCH-ADVANCE-V1:" || len(context_id) || context_id
///   || len(sender_did) || sender_did || "key_epoch" || epoch_BE)`.
///
/// Variable-length fields are prefixed with their length as a 4-byte
/// big-endian u32 to prevent field-boundary ambiguity. The domain separator
/// prevents cross-protocol hash confusion.
fn compute_epoch_advance_hash(context_id: &str, sender_did: &str, epoch: u64) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"SCP-EPOCH-ADVANCE-V1:");
    #[allow(clippy::cast_possible_truncation)]
    let length_prefix = |hasher: &mut Sha256, bytes: &[u8]| {
        hasher.update((bytes.len() as u32).to_be_bytes());
        hasher.update(bytes);
    };
    length_prefix(&mut hasher, context_id.as_bytes());
    length_prefix(&mut hasher, sender_did.as_bytes());
    hasher.update(b"key_epoch");
    hasher.update(epoch.to_be_bytes());
    hasher.finalize().to_vec()
}

/// Computes `SHA-256("SCP-KEY-REQUEST-V1:" || len(requester_did) || requester_did
///   || len(sender_did) || sender_did || epoch_BE || len(wrapping_pubkey)
///   || wrapping_pubkey || nonce || timestamp_BE)`.
///
/// Variable-length fields are prefixed with their length as a 4-byte
/// big-endian u32 to prevent field-boundary ambiguity. The domain separator
/// prevents cross-protocol hash confusion. `nonce` is fixed-size
/// (`REQUEST_NONCE_SIZE`) and needs no prefix.
fn compute_request_hash(
    requester_did: &str,
    sender_did: &str,
    epoch: u64,
    wrapping_pubkey: &[u8],
    nonce: &[u8; REQUEST_NONCE_SIZE],
    timestamp: u64,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"SCP-KEY-REQUEST-V1:");
    #[allow(clippy::cast_possible_truncation)]
    let length_prefix = |hasher: &mut Sha256, bytes: &[u8]| {
        hasher.update((bytes.len() as u32).to_be_bytes());
        hasher.update(bytes);
    };
    length_prefix(&mut hasher, requester_did.as_bytes());
    length_prefix(&mut hasher, sender_did.as_bytes());
    hasher.update(epoch.to_be_bytes());
    length_prefix(&mut hasher, wrapping_pubkey);
    hasher.update(nonce);
    hasher.update(timestamp.to_be_bytes());
    hasher.finalize().to_vec()
}

/// Computes `SHA-256("SCP-BLOCK-NOTIFICATION-V1:" || len(context_id) || context_id
///   || len(blocker_did) || blocker_did || len(blocked_did) || blocked_did
///   || timestamp_BE)`.
///
/// Variable-length fields are prefixed with their length as a 4-byte
/// big-endian u32 to prevent field-boundary ambiguity. The domain separator
/// prevents cross-protocol hash confusion.
#[allow(clippy::similar_names)] // blocker_did/blocked_did are domain terms
fn compute_block_notification_hash(
    context_id: &str,
    blocker_did: &str,
    blocked_did: &str,
    timestamp: u64,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"SCP-BLOCK-NOTIFICATION-V1:");
    #[allow(clippy::cast_possible_truncation)]
    let length_prefix = |hasher: &mut Sha256, bytes: &[u8]| {
        hasher.update((bytes.len() as u32).to_be_bytes());
        hasher.update(bytes);
    };
    length_prefix(&mut hasher, context_id.as_bytes());
    length_prefix(&mut hasher, blocker_did.as_bytes());
    length_prefix(&mut hasher, blocked_did.as_bytes());
    hasher.update(timestamp.to_be_bytes());
    hasher.finalize().to_vec()
}

/// Verifies an Ed25519 signature against a public key and message.
///
/// Returns `Ok(true)` if valid, `Ok(false)` if well-formed but invalid.
///
/// # Errors
///
/// Returns [`SenderKeyError::VerificationFailed`] if the public key or
/// signature bytes are malformed.
fn verify_ed25519_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, SenderKeyError> {
    match crate::crypto::ed25519::verify_ed25519_signature(public_key, message, signature) {
        Ok(()) => Ok(true),
        Err(reason) => {
            // Distinguish malformed inputs (public key / signature byte length
            // errors) from valid-but-non-matching signatures.
            if reason.contains("must be 32 bytes")
                || reason.contains("must be 64 bytes")
                || reason.contains("invalid public key")
            {
                Err(SenderKeyError::VerificationFailed(reason))
            } else {
                Ok(false)
            }
        }
    }
}

/// Returns the current Unix timestamp in milliseconds.
///
/// # Errors
///
/// Returns [`SenderKeyError::ClockError`] (via [`crate::time::ClockError`])
/// if the system clock is before the Unix epoch.
fn current_timestamp_ms() -> Result<u64, crate::time::ClockError> {
    crate::time::now_millis()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::HashSet;

    use scp_platform::testing::InMemoryKeyCustody;
    use scp_platform::traits::{KeyCustody, KeyType};

    use super::*;

    /// Creates a test custody and an Ed25519 signing key.
    async fn setup() -> (InMemoryKeyCustody, KeyHandle) {
        let custody = InMemoryKeyCustody::new();
        let key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        (custody, key)
    }

    // -------------------------------------------------------------------
    // SenderKeyEpochAdvance tests
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn epoch_advance_creation_and_signature_verification() {
        let (custody, signing_key) = setup().await;
        let pubkey = custody.public_key(&signing_key).await.unwrap();

        let message =
            publish_sender_key_epoch_advance(&custody, &signing_key, "ctx-1", "did:dht:alice", 5)
                .await
                .unwrap();

        let advance: SenderKeyEpochAdvance = serde_json::from_slice(&message).unwrap();
        assert_eq!(advance.sender_did, "did:dht:alice");
        assert_eq!(advance.epoch, 5);

        let valid = verify_epoch_advance(&advance, "ctx-1", pubkey.as_bytes()).unwrap();
        assert!(valid, "epoch advance signature should be valid");
    }

    #[tokio::test]
    async fn epoch_advance_rejects_wrong_context() {
        let (custody, signing_key) = setup().await;
        let pubkey = custody.public_key(&signing_key).await.unwrap();

        let message =
            publish_sender_key_epoch_advance(&custody, &signing_key, "ctx-1", "did:dht:alice", 5)
                .await
                .unwrap();

        let advance: SenderKeyEpochAdvance = serde_json::from_slice(&message).unwrap();

        // Verify with wrong context_id should fail.
        let valid = verify_epoch_advance(&advance, "ctx-WRONG", pubkey.as_bytes()).unwrap();
        assert!(!valid, "wrong context should invalidate signature");
    }

    #[tokio::test]
    async fn epoch_advance_rejects_wrong_key() {
        let (custody, signing_key) = setup().await;
        let other_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let wrong_pubkey = custody.public_key(&other_key).await.unwrap();

        let message =
            publish_sender_key_epoch_advance(&custody, &signing_key, "ctx-1", "did:dht:alice", 5)
                .await
                .unwrap();

        let advance: SenderKeyEpochAdvance = serde_json::from_slice(&message).unwrap();
        let valid = verify_epoch_advance(&advance, "ctx-1", wrong_pubkey.as_bytes()).unwrap();
        assert!(!valid, "wrong public key should invalidate signature");
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
            serde_json::from_slice(&request_result.request_message).unwrap();

        // Alice handles the request (no membership gate — backward compat).
        let block_list = HashSet::new();
        let response_bytes = handle_sender_key_request(
            &request,
            bob_pubkey.as_bytes(),
            &sender_key,
            "did:dht:alice",
            1,
            &block_list,
            None,
        )
        .await
        .unwrap();

        assert!(
            response_bytes.is_some(),
            "non-blocked requester should get a response"
        );
        let response: SenderKeyResponse = serde_json::from_slice(&response_bytes.unwrap()).unwrap();

        assert_eq!(response.sender_did, "did:dht:alice");
        assert_eq!(response.epoch, 1);

        // Bob opens the response using his wrapping key.
        let recovered_key =
            open_sender_key_response(&bob_custody, &request_result.wrapping_key_handle, &response)
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

        let request: SenderKeyRequest = serde_json::from_slice(&result.request_message).unwrap();

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

        let request: SenderKeyRequest = serde_json::from_slice(&result.request_message).unwrap();

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
            serde_json::from_slice(&request_result.request_message).unwrap();

        // Alice has Bob on her block list.
        let mut block_list = HashSet::new();
        block_list.insert("did:dht:bob".into());

        let response = handle_sender_key_request(
            &request,
            bob_pubkey.as_bytes(),
            &sender_key,
            "did:dht:alice",
            1,
            &block_list,
            None,
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
            serde_json::from_slice(&request_result.request_message).unwrap();

        // Block list has someone else, not Bob.
        let mut block_list = HashSet::new();
        block_list.insert("did:dht:dave".into());

        let response = handle_sender_key_request(
            &request,
            bob_pubkey.as_bytes(),
            &sender_key,
            "did:dht:alice",
            1,
            &block_list,
            None,
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
            serde_json::from_slice(&request_result.request_message).unwrap();

        let block_list: HashSet<String> = HashSet::new();

        // Context members do NOT include the Sybil identity.
        let mut members = HashSet::new();
        members.insert("did:dht:alice".to_owned());
        members.insert("did:dht:bob".to_owned());

        let result = handle_sender_key_request(
            &request,
            sybil_pubkey.as_bytes(),
            &sender_key,
            "did:dht:alice",
            1,
            &block_list,
            Some(&members),
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
            serde_json::from_slice(&request_result.request_message).unwrap();

        let block_list: HashSet<String> = HashSet::new();

        // Context members include Bob.
        let mut members = HashSet::new();
        members.insert("did:dht:alice".to_owned());
        members.insert("did:dht:bob".to_owned());

        let response = handle_sender_key_request(
            &request,
            bob_pubkey.as_bytes(),
            &sender_key,
            "did:dht:alice",
            1,
            &block_list,
            Some(&members),
        )
        .await
        .unwrap();

        assert!(
            response.is_some(),
            "member should receive a response when context_members is provided"
        );
    }

    // -------------------------------------------------------------------
    // expand_block_list — identity-linked blocking (BLACK-006)
    // -------------------------------------------------------------------

    #[test]
    fn expand_block_list_adds_linked_dids() {
        let mut block_list = HashSet::new();
        block_list.insert("did:dht:dave".to_owned());

        let expanded = expand_block_list(&block_list, |did| {
            if did == "did:dht:dave" {
                vec!["did:dht:dave-alt".to_owned(), "did:dht:dave-bot".to_owned()]
            } else {
                vec![]
            }
        });

        assert!(expanded.contains("did:dht:dave"));
        assert!(expanded.contains("did:dht:dave-alt"));
        assert!(expanded.contains("did:dht:dave-bot"));
        assert_eq!(expanded.len(), 3);
    }

    #[test]
    fn expand_block_list_no_links_returns_original() {
        let mut block_list = HashSet::new();
        block_list.insert("did:dht:dave".to_owned());

        let expanded = expand_block_list(&block_list, |_| vec![]);

        assert_eq!(expanded, block_list);
    }

    #[test]
    fn expand_block_list_deduplicates() {
        let mut block_list = HashSet::new();
        block_list.insert("did:dht:dave".to_owned());
        block_list.insert("did:dht:eve".to_owned());

        // Both dave and eve link to the same alias.
        let expanded = expand_block_list(&block_list, |did| {
            if did == "did:dht:dave" || did == "did:dht:eve" {
                vec!["did:dht:shared-alias".to_owned()]
            } else {
                vec![]
            }
        });

        assert!(expanded.contains("did:dht:dave"));
        assert!(expanded.contains("did:dht:eve"));
        assert!(expanded.contains("did:dht:shared-alias"));
        assert_eq!(expanded.len(), 3);
    }

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
            serde_json::from_slice(&request_result.request_message).unwrap();

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

        let response = handle_sender_key_request(
            &request,
            sybil_pubkey.as_bytes(),
            &sender_key,
            "did:dht:alice",
            1,
            &expanded,
            None,
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
        )
        .await
        .unwrap();

        let notification: BlockNotification = serde_json::from_slice(&message).unwrap();
        assert_eq!(notification.notification_type, "block_notification");
        assert_eq!(notification.blocker, "did:dht:alice");
        assert_eq!(notification.blocked, "did:dht:dave");
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
        )
        .await
        .unwrap();

        let notification: BlockNotification = serde_json::from_slice(&message).unwrap();
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
        )
        .await
        .unwrap();

        let notification: BlockNotification = serde_json::from_slice(&message).unwrap();
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
            "ctx-1",
            "did:dht:alice",
            current_epoch,
            "did:dht:dave",
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
            serde_json::from_slice(&result.epoch_advance_message).unwrap();
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
            "ctx-1",
            "did:dht:alice",
            0,
            "did:dht:dave",
            &mut block_list,
        )
        .await
        .unwrap();

        let result2 = rotate_sender_key_for_block(
            &custody,
            &signing_key,
            "ctx-1",
            "did:dht:alice",
            result1.new_epoch,
            "did:dht:eve",
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
            "ctx-1",
            "did:dht:alice",
            0,
            "did:dht:dave",
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
            serde_json::from_slice(&request_result.request_message).unwrap();

        // Alice handles Dave's request with the updated block list.
        let response = handle_sender_key_request(
            &request,
            dave_pubkey.as_bytes(),
            &rotate_result.new_key,
            "did:dht:alice",
            rotate_result.new_epoch,
            &block_list,
            None,
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
            "ctx-1",
            "did:dht:alice",
            u64::MAX,
            "did:dht:dave",
            &mut block_list,
        )
        .await;

        assert!(
            matches!(result, Err(SenderKeyError::EpochOverflow)),
            "epoch at u64::MAX should return EpochOverflow, got {result:?}"
        );
    }

    // -------------------------------------------------------------------
    // HPKE helpers
    // -------------------------------------------------------------------

    #[test]
    fn hpke_seal_and_open_roundtrip() {
        let plaintext = [0xABu8; 32];

        // Generate a recipient X25519 keypair in software for this test.
        let recipient_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let recipient_public = X25519Pub::from(&recipient_secret);

        let (sealed, ephemeral_pub) = hpke_seal(&plaintext, &recipient_public.to_bytes()).unwrap();

        // Manually do the recipient-side ECDH + KDF + decrypt.
        let ephemeral_key = X25519Pub::from(ephemeral_pub);
        let shared = recipient_secret.diffie_hellman(&ephemeral_key);
        let aes_key = hkdf_derive_key(shared.as_bytes()).unwrap();
        let recovered = aes128gcm_decrypt(&aes_key, &sealed).unwrap();

        assert_eq!(recovered.as_slice(), &plaintext);
    }

    #[test]
    fn hpke_rejects_wrong_recipient() {
        let plaintext = [0xCDu8; 32];

        let recipient_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let recipient_public = X25519Pub::from(&recipient_secret);

        let wrong_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);

        let (sealed, ephemeral_pub) = hpke_seal(&plaintext, &recipient_public.to_bytes()).unwrap();

        // Wrong recipient tries to decrypt.
        let ephemeral_key = X25519Pub::from(ephemeral_pub);
        let shared = wrong_secret.diffie_hellman(&ephemeral_key);
        let aes_key = hkdf_derive_key(shared.as_bytes()).unwrap();
        let result = aes128gcm_decrypt(&aes_key, &sealed);

        assert!(
            result.is_err(),
            "wrong recipient should fail AEAD decryption"
        );
    }

    #[test]
    fn verify_ed25519_rejects_invalid_pubkey_length() {
        let result = verify_ed25519_signature(&[0u8; 16], &[0u8; 32], &[0u8; 64]);
        assert!(result.is_err());
    }

    #[test]
    fn verify_ed25519_rejects_invalid_signature_length() {
        let result = verify_ed25519_signature(&[0u8; 32], &[0u8; 32], &[0u8; 32]);
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------
    // NonceDedup — replay protection (SCP-179)
    // -------------------------------------------------------------------

    #[test]
    fn nonce_dedup_accepts_fresh_nonce() {
        let mut dedup = NonceDedup::new();
        let nonce = [1u8; REQUEST_NONCE_SIZE];
        let now = 1_700_000_000u64;
        assert!(
            !dedup.is_replayed(&nonce, now),
            "fresh nonce should not be replayed"
        );
    }

    #[test]
    fn nonce_dedup_rejects_recorded_nonce_within_window() {
        let mut dedup = NonceDedup::new();
        let nonce = [2u8; REQUEST_NONCE_SIZE];
        let now = 1_700_000_000u64;
        dedup.record(nonce, now);
        assert!(
            dedup.is_replayed(&nonce, now + 60),
            "nonce recorded 60s ago should still be replayed within 5-min window"
        );
    }

    #[test]
    fn nonce_dedup_evicts_expired_nonce() {
        let mut dedup = NonceDedup::new();
        let nonce = [3u8; REQUEST_NONCE_SIZE];
        let now = 1_700_000_000u64;
        dedup.record(nonce, now);
        // Advance time past the expiry window.
        let future = now + NONCE_EXPIRY_SECS + 1;
        assert!(
            !dedup.is_replayed(&nonce, future),
            "expired nonce should be evicted and not considered replayed"
        );
    }

    #[test]
    fn nonce_dedup_distinct_nonces_not_replayed() {
        let mut dedup = NonceDedup::new();
        let nonce_a = [10u8; REQUEST_NONCE_SIZE];
        let nonce_b = [20u8; REQUEST_NONCE_SIZE];
        let now = 1_700_000_000u64;
        dedup.record(nonce_a, now);
        assert!(
            !dedup.is_replayed(&nonce_b, now),
            "different nonce should not be replayed"
        );
    }

    #[test]
    fn nonce_dedup_evicts_oldest_at_capacity() {
        let mut dedup = NonceDedup::new();
        let now = 1_700_000_000u64;

        // Fill to capacity using distinct nonces.
        for i in 0..NONCE_DEDUP_CAPACITY {
            let mut nonce = [0u8; REQUEST_NONCE_SIZE];
            let i_bytes = (i as u64).to_be_bytes();
            nonce[..8].copy_from_slice(&i_bytes);
            dedup.record(nonce, now + i as u64);
        }

        // Adding one more should evict the oldest without panicking.
        let mut new_nonce = [0xFFu8; REQUEST_NONCE_SIZE];
        new_nonce[0] = 0xAA;
        let check_time = now + NONCE_DEDUP_CAPACITY as u64 + 1;
        // Before recording: the new nonce is not a replay.
        assert!(!dedup.is_replayed(&new_nonce, check_time));
        // Recording it makes subsequent uses a replay.
        dedup.record(new_nonce, check_time);
        assert!(dedup.is_replayed(&new_nonce, check_time));
    }

    // -------------------------------------------------------------------
    // validate_block_notification_freshness (SCP-179)
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
        )
        .await
        .unwrap();

        let notification: BlockNotification = serde_json::from_slice(&msg).unwrap();
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
        )
        .await
        .unwrap();

        let notification: BlockNotification = serde_json::from_slice(&msg).unwrap();
        // Simulate the notification being received far in the future.
        let far_future_ms = notification.timestamp + BLOCK_NOTIFICATION_FRESHNESS_MS + 1_000;
        let result = validate_block_notification_freshness(&notification, far_future_ms);
        assert!(
            matches!(result, Err(SenderKeyError::StaleBlockNotification)),
            "stale notification should be rejected with StaleBlockNotification"
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

        let request: SenderKeyRequest = serde_json::from_slice(&result.request_message).unwrap();
        let original_nonce = request.nonce;

        let response_bytes = handle_sender_key_request(
            &request,
            requester_pubkey.as_bytes(), // verify requester's signature
            &sender_key,
            "did:dht:alice",
            1,
            &block_list,
            None,
        )
        .await
        .unwrap()
        .unwrap();

        let response: SenderKeyResponse = serde_json::from_slice(&response_bytes).unwrap();
        assert_eq!(
            response.request_nonce, original_nonce,
            "response must echo the request nonce"
        );
    }

    // -------------------------------------------------------------------
    // length prefix prevents field boundary ambiguity
    // -------------------------------------------------------------------

    #[test]
    fn epoch_advance_hash_boundary_shift_produces_different_hash() {
        let hash_a = compute_epoch_advance_hash("ctx-AB", "did:key:CD", 1);
        let hash_b = compute_epoch_advance_hash("ctx-ABC", "did:key:D", 1);
        assert_ne!(
            hash_a, hash_b,
            "shifting bytes between context_id and sender_did must produce different hashes"
        );
    }

    #[test]
    fn request_hash_boundary_shift_produces_different_hash() {
        let nonce = [0u8; REQUEST_NONCE_SIZE];
        let hash_a = compute_request_hash("did:key:AB", "did:key:CD", 1, &[0xAA], &nonce, 100);
        let hash_b = compute_request_hash("did:key:ABC", "did:key:D", 1, &[0xAA], &nonce, 100);
        assert_ne!(
            hash_a, hash_b,
            "shifting bytes between requester_did and sender_did must produce different hashes"
        );
    }

    #[test]
    fn block_notification_hash_boundary_shift_produces_different_hash() {
        let hash_a = compute_block_notification_hash("ctx-1", "did:key:AB", "did:key:CD", 100);
        let hash_b = compute_block_notification_hash("ctx-1", "did:key:ABC", "did:key:D", 100);
        assert_ne!(
            hash_a, hash_b,
            "shifting bytes between blocker_did and blocked_did must produce different hashes"
        );
    }
}
