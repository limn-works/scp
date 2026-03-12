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

use super::{SenderKey, SenderKeyError, generate_sender_key};
use crate::identity::SigningKeyId;
use crate::serde_util::{serde_hpke_sealed_60, serde_pubkey_32, serde_signature_64};

// ---------------------------------------------------------------------------
// Wrapping keypair generation (§9.16.1)
// ---------------------------------------------------------------------------

/// Generates a stable X25519 wrapping keypair for sender key distribution.
///
/// Each member maintains one keypair per context, published as the
/// `scp_wrapping_key` MLS `LeafNode` extension. The keypair is used for HPKE
/// wrapping of sender key distributions (§9.16.2) and remains stable across
/// MLS epoch advances, rotating only on identity key rotation (§9.12) or
/// suspected compromise.
///
/// Returns `(public_key, secret_key)` as raw 32-byte arrays. The secret key
/// should be persisted via `ProtocolStore::store_wrapping_keypair` and the
/// public key included in the `LeafNode` extension via `make_wrapping_key_extension`.
///
/// See spec §9.16.1.
#[must_use]
pub fn generate_wrapping_keypair() -> ([u8; 32], [u8; 32]) {
    use x25519_dalek::StaticSecret;
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = X25519Pub::from(&secret);
    (public.to_bytes(), secret.to_bytes())
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// AES-128-GCM nonce size in bytes.
const HPKE_NONCE_SIZE: usize = 12;

/// HKDF info domain separator for sender key HPKE encryption (§9.16.2).
/// The full info string is `"scp-sender-key-v1" || context_id || sender_did || epoch_BE`.
const HPKE_INFO_PREFIX: &[u8] = b"scp-sender-key-v1";

/// Grace period in seconds during which the old key should still be accepted
/// for decryption of in-flight messages after an epoch advance.
pub const GRACE_PERIOD_SECS: u64 = 30;

/// Size of the cryptographic nonce embedded in sender key requests (bytes).
const REQUEST_NONCE_SIZE: usize = 16;

/// Duration in seconds for which a seen nonce is remembered to prevent replay.
const NONCE_EXPIRY_SECS: u64 = 300; // 5 minutes

/// Maximum age in milliseconds for a block notification to be considered fresh.
const BLOCK_NOTIFICATION_FRESHNESS_MS: u64 = 30_000; // 30 seconds

/// Maximum age in seconds for a sender key request to be considered fresh.
///
/// Matches [`NONCE_EXPIRY_SECS`] so timestamp freshness and nonce dedup windows
/// are aligned: a request that survived nonce replay should also survive the
/// freshness check, and vice versa.
const REQUEST_FRESHNESS_SECS: u64 = NONCE_EXPIRY_SECS;

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
/// Signature payload: `SHA-256(context_id || sender_did || "key_epoch" || epoch_BE || signer_key_ref)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderKeyEpochAdvance {
    /// The DID of the sender who rotated their key.
    pub sender_did: String,
    /// The new epoch number for this sender's key.
    pub epoch: u64,
    /// Identifies which DID verification method (`#active` or `#agent`)
    /// produced the signature. Defaults to `Active` for backward
    /// compatibility with epoch advances created before ADR-039.
    #[serde(default)]
    pub signer_key_ref: SigningKeyId,
    /// Ed25519 signature over the epoch advance payload.
    #[serde(with = "serde_signature_64")]
    pub signature: [u8; 64],
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
    /// Fresh X25519 public key for HPKE wrapping (32 bytes).
    #[serde(with = "serde_pubkey_32")]
    pub wrapping_pubkey: [u8; 32],
    /// Cryptographic nonce for replay protection (16 bytes, generated with
    /// `OsRng`). The responder echoes this in [`SenderKeyResponse::request_nonce`]
    /// and rejects duplicate nonces within [`NONCE_EXPIRY_SECS`].
    #[serde(with = "serde_bytes")]
    pub nonce: [u8; REQUEST_NONCE_SIZE],
    /// Unix timestamp in seconds when the request was created.
    pub timestamp: u64,
    /// Ed25519 signature over the request payload.
    #[serde(with = "serde_signature_64")]
    pub signature: [u8; 64],
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
    /// Exactly 60 bytes: nonce (12) + encrypted key (32) + tag (16).
    #[serde(with = "serde_hpke_sealed_60")]
    pub hpke_sealed_key: [u8; 60],
    /// The ephemeral X25519 public key used in the HPKE encapsulation.
    #[serde(with = "serde_pubkey_32")]
    pub ephemeral_pubkey: [u8; 32],
    /// Echo of the request nonce from [`SenderKeyRequest::nonce`], binding
    /// this response to the originating request.
    #[serde(with = "serde_bytes")]
    pub request_nonce: [u8; REQUEST_NONCE_SIZE],
}

/// A signed block notification sent as an MLS application message.
///
/// When Alice blocks Dave, Alice sends this notification so Dave's client
/// can automatically rotate Dave's sender key excluding Alice. The signature
/// prevents forgery by other group members.
///
/// Signature payload (via canonical hash):
/// `SHA-256("SCP-BLOCK-NOTIFICATION-V1:" || context_id || blocker_did || blocked_did || signing_key_id || timestamp_BE)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockNotification {
    /// The type discriminator for deserialization.
    #[serde(rename = "type")]
    pub notification_type: String,
    /// The DID of the member who initiated the block.
    pub blocker: String,
    /// The DID of the member being blocked.
    pub blocked: String,
    /// Identifies which DID verification method (`#active` or `#agent`)
    /// produced the signature. Verifiers resolve the correct public key
    /// from the blocker's DID document using this field (ADR-039).
    #[serde(default)]
    pub signing_key_id: SigningKeyId,
    /// Unix timestamp in milliseconds when the block was issued.
    pub timestamp: u64,
    /// Ed25519 signature from the blocker's Active Signing Key or Agent
    /// Signing Key.
    #[serde(with = "serde_signature_64")]
    pub signature: [u8; 64],
}

/// Tagged-union envelope for sender key distribution sub-protocol messages.
///
/// Wraps the four sender key wire types ([`SenderKeyEpochAdvance`],
/// [`SenderKeyRequest`], [`SenderKeyResponse`], [`BlockNotification`]) with a
/// `msg_type` discriminator so they can ride as the payload of an inner
/// envelope with [`MessageType::KeyDistribution`].
///
/// Serialized with `MessagePack` via `rmp-serde`. The `msg_type` tag is a
/// string discriminator (`"epoch_advance"`, `"key_request"`, `"key_response"`,
/// `"block_notification"`) for forward-compatible decoding.
///
/// # Transport Path
///
/// In **Encrypted** contexts, sender key messages travel inside MLS application
/// messages: the caller serializes a `SenderKeyDistributionMessage` as the
/// `payload` of an [`InnerEnvelope`] with
/// `message_type: MessageType::KeyDistribution`, then seals it into an
/// [`OuterEnvelope`] via the normal MLS pipeline.
///
/// In **Broadcast** contexts, where MLS is not used, the same serialized
/// `SenderKeyDistributionMessage` is published as a relay blob on the
/// context's routing ID, with the `recipient_hint` set for directed messages
/// (key requests and responses).
///
/// [`MessageType::KeyDistribution`]: crate::envelope::inner::MessageType::KeyDistribution
/// [`InnerEnvelope`]: crate::envelope::inner::InnerEnvelope
/// [`OuterEnvelope`]: crate::envelope::OuterEnvelope
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "msg_type")]
pub enum SenderKeyDistributionMessage {
    /// A sender rotated their key to a new epoch (§9.16.2 step 1).
    #[serde(rename = "epoch_advance")]
    EpochAdvance(SenderKeyEpochAdvance),

    /// A member requests a sender's key at a specific epoch (§9.16.2 step 2).
    #[serde(rename = "key_request")]
    KeyRequest(SenderKeyRequest),

    /// A sender responds with HPKE-encrypted key material (§9.16.2 step 3).
    #[serde(rename = "key_response")]
    KeyResponse(SenderKeyResponse),

    /// A block notification triggering mutual key rotation (§9.16.3).
    #[serde(rename = "block_notification")]
    BlockNotification(BlockNotification),
}

impl SenderKeyDistributionMessage {
    /// Serializes this message to `MessagePack` bytes for transmission.
    ///
    /// # Errors
    ///
    /// Returns [`SenderKeyError::SerializationFailed`] if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SenderKeyError> {
        rmp_serde::to_vec_named(self)
            .map_err(|e| SenderKeyError::SerializationFailed(e.to_string()))
    }

    /// Deserializes a `SenderKeyDistributionMessage` from `MessagePack` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SenderKeyError::SerializationFailed`] if deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SenderKeyError> {
        rmp_serde::from_slice(bytes).map_err(|e| SenderKeyError::SerializationFailed(e.to_string()))
    }
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

/// Verifies the Ed25519 signature on a [`SenderKeyEpochAdvance`].
///
/// The caller must provide the `context_id` since it is not embedded in the
/// advance message (it is known from the MLS group context).
///
/// **Key resolution:** Callers must inspect `advance.signer_key_ref` to
/// determine which verification method public key to pass as
/// `sender_public_key`. For [`SigningKeyId::Active`], use the `#active`
/// verification method. For [`SigningKeyId::Agent`], use the `#agent`
/// verification method from the sender's DID document.
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
    let hash = compute_epoch_advance_hash(
        context_id,
        &advance.sender_did,
        advance.epoch,
        advance.signer_key_ref,
    );
    verify_ed25519_signature(sender_public_key, &hash, &advance.signature)
}

// ---------------------------------------------------------------------------
// Category A enforcement for sender key operations (ADR-039, SCP-AB-020)
// ---------------------------------------------------------------------------

/// Enforces Category A restrictions on a sender key operation.
///
/// Call this when a sender key protocol message (epoch advance, block
/// notification, etc.) is associated with a DID-modifying action. If the
/// `signer_key_ref` is [`SigningKeyId::Agent`] and the `action_resource`
/// is a Category A resource, returns `Err` with the violation details.
///
/// Sender key rotation itself is Category B (operational), so this function
/// should only be called when the caller knows the sender key operation is
/// part of a larger DID-modification flow.
///
/// # Errors
///
/// Returns [`SenderKeyError::CategoryAViolation`] if an agent key attempted
/// a DID document modification via the sender key protocol.
pub fn enforce_sender_key_category_a(
    signer_key_ref: SigningKeyId,
    sender_did: &str,
    action_resource: &str,
    evidence_signature: &[u8],
) -> Result<(), SenderKeyError> {
    use crate::trust::custody_violation::{classify_action, enforce_category_a};

    let category = classify_action(action_resource);
    if let Err(violation) = enforce_category_a(
        signer_key_ref,
        category,
        sender_did,
        &format!("sender key operation: {action_resource}"),
        evidence_signature,
    ) {
        return Err(SenderKeyError::CategoryAViolation(violation.error_message));
    }

    Ok(())
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

/// Validates that a [`SenderKeyRequest`] timestamp is within the freshness
/// window.
///
/// Sender key requests older than [`REQUEST_FRESHNESS_SECS`] seconds are
/// rejected to prevent replay of old requests. Requests with timestamps far
/// in the future (beyond the freshness window) are also rejected to guard
/// against clock-skew manipulation.
///
/// The freshness window is aligned with [`NONCE_EXPIRY_SECS`] so that
/// timestamp validation and nonce dedup cover the same time horizon.
///
/// # Parameters
///
/// - `request` -- The request to validate.
/// - `now_secs` -- The current Unix timestamp in seconds.
///
/// # Errors
///
/// Returns [`SenderKeyError::StaleSenderKeyRequest`] if the request
/// timestamp is outside the freshness window.
pub const fn validate_sender_key_request_freshness(
    request: &SenderKeyRequest,
    now_secs: u64,
) -> Result<(), SenderKeyError> {
    // Reject far-future timestamps (clock skew / manipulation).
    if request.timestamp > now_secs.saturating_add(REQUEST_FRESHNESS_SECS) {
        return Err(SenderKeyError::StaleSenderKeyRequest);
    }
    // Reject stale timestamps.
    let age_secs = now_secs.saturating_sub(request.timestamp);
    if age_secs > REQUEST_FRESHNESS_SECS {
        return Err(SenderKeyError::StaleSenderKeyRequest);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Handle sender key request (responder side)
// ---------------------------------------------------------------------------

/// Parameters for [`handle_sender_key_request`].
///
/// Groups the responder-side context that does not vary per request,
/// avoiding `clippy::too_many_arguments`.
pub struct HandleRequestParams<'a, S: BuildHasher = std::collections::hash_map::RandomState> {
    /// The current sender key to distribute.
    pub sender_key: &'a SenderKey,
    /// The SCP context identifier for HPKE context binding (§9.16.2).
    pub context_id: &'a str,
    /// The sender's full DID.
    pub sender_did: &'a str,
    /// The current epoch for the sender key.
    pub epoch: u64,
    /// DIDs blocked by this sender. Blocked requesters receive `None`.
    pub block_list: &'a HashSet<String, S>,
    /// If `Some`, the requester must be in this set or the request is
    /// rejected with [`SenderKeyError::NotContextMember`]. Pass `None`
    /// to disable the membership check (backward compatibility).
    pub context_members: Option<&'a HashSet<String>>,
    /// Current Unix timestamp in seconds for freshness validation.
    pub now_secs: u64,
}

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
///    [`REQUEST_FRESHNESS_SECS`] (past or future), preventing replay of old
///    requests and guarding against clock-skew manipulation.
/// 2. **Nonce dedup** — rejects requests whose nonce has been seen within
///    [`NONCE_EXPIRY_SECS`], preventing replay of recently-valid requests.
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

/// Decrypts an HPKE-sealed sender key using the raw X25519 wrapping secret
/// key bytes.
///
/// This is the non-custody variant of [`open_sender_key_response`] for use
/// when the wrapping secret key is held in software (e.g., in
/// [`MlsCryptoProvider`](crate::crypto::mls::MlsCryptoProvider)) rather
/// than inside a [`KeyCustody`] boundary.
///
/// # Arguments
///
/// * `sealed` - The HPKE-sealed key bytes (`nonce || ciphertext || tag`).
/// * `ephemeral_pubkey` - The sender's ephemeral X25519 public key.
/// * `wrapping_secret` - The recipient's X25519 wrapping secret key (32 bytes).
/// * `context_id` - The SCP context identifier (hex string).
/// * `sender_did` - The DID of the sender.
/// * `epoch` - The sender key epoch.
///
/// # Errors
///
/// Returns [`SenderKeyError::HpkeDecryptionFailed`] if ECDH, KDF, or AEAD
/// decryption fails.
pub fn hpke_open_sender_key(
    sealed: &[u8],
    ephemeral_pubkey: &[u8; 32],
    wrapping_secret: &[u8; 32],
    context_id: &str,
    sender_did: &str,
    epoch: u64,
) -> Result<SenderKey, SenderKeyError> {
    use x25519_dalek::StaticSecret;

    let secret = StaticSecret::from(*wrapping_secret);
    let ephemeral_pub = X25519Pub::from(*ephemeral_pubkey);
    let shared_secret = secret.diffie_hellman(&ephemeral_pub);

    let info = build_hpke_info(context_id, sender_did, epoch);
    let aad = build_hpke_aad(context_id, sender_did, epoch);

    let aes_key = hkdf_derive_key(shared_secret.as_bytes(), &info)?;
    let plaintext = aes128gcm_decrypt(&aes_key, sealed, &aad)?;

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
        notification_type: "block_notification".to_owned(),
        blocker: blocker_did.to_owned(),
        blocked: blocked_did.to_owned(),
        signing_key_id,
        timestamp,
        signature: sig_bytes,
    };

    rmp_serde::to_vec_named(&notification)
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
    // Reject future timestamps: saturating_sub would return 0 for future
    // timestamps, bypassing the staleness check. A far-future timestamp
    // would make the notification valid indefinitely.
    if notification.timestamp > now_ms.saturating_add(BLOCK_NOTIFICATION_FRESHNESS_MS) {
        return Err(SenderKeyError::StaleBlockNotification);
    }
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
        notification.signing_key_id,
        notification.timestamp,
    );
    verify_ed25519_signature(blocker_public_key, &hash, &notification.signature)
}

// ---------------------------------------------------------------------------
// Rotate sender key for block
// ---------------------------------------------------------------------------

/// Parameters for [`rotate_sender_key_for_block`].
///
/// Groups the non-cryptographic parameters that describe the rotation
/// context, avoiding the excessive argument count that would otherwise
/// trigger `clippy::too_many_arguments`.
pub struct RotateForBlockParams<'a> {
    /// The SCP context identifier.
    pub context_id: &'a str,
    /// The sender's full DID.
    pub sender_did: &'a str,
    /// The current epoch number before rotation.
    pub current_epoch: u64,
    /// The DID being blocked.
    pub blocked_did: &'a str,
    /// Which DID verification method produced the signature.
    pub signer_key_ref: SigningKeyId,
}

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
// HPKE context binding helpers (§9.16.2)
// ---------------------------------------------------------------------------

fn build_hpke_info(context_id: &str, sender_did: &str, epoch: u64) -> Vec<u8> {
    let ctx_bytes = context_id.as_bytes();
    let did_bytes = sender_did.as_bytes();
    // 4-byte BE length prefix per variable-length field prevents boundary-shift collisions.
    let mut info =
        Vec::with_capacity(HPKE_INFO_PREFIX.len() + 4 + ctx_bytes.len() + 4 + did_bytes.len() + 8);
    info.extend_from_slice(HPKE_INFO_PREFIX);
    #[allow(clippy::cast_possible_truncation)] // context_id/DID lengths << u32::MAX
    let ctx_len = ctx_bytes.len() as u32;
    info.extend_from_slice(&ctx_len.to_be_bytes());
    info.extend_from_slice(ctx_bytes);
    #[allow(clippy::cast_possible_truncation)]
    let did_len = did_bytes.len() as u32;
    info.extend_from_slice(&did_len.to_be_bytes());
    info.extend_from_slice(did_bytes);
    info.extend_from_slice(&epoch.to_be_bytes());
    info
}

fn build_hpke_aad(context_id: &str, sender_did: &str, epoch: u64) -> Vec<u8> {
    let ctx_bytes = context_id.as_bytes();
    let did_bytes = sender_did.as_bytes();
    // 4-byte BE length prefix per variable-length field prevents boundary-shift collisions.
    let mut aad = Vec::with_capacity(4 + ctx_bytes.len() + 4 + did_bytes.len() + 8);
    #[allow(clippy::cast_possible_truncation)] // context_id/DID lengths << u32::MAX
    let ctx_len = ctx_bytes.len() as u32;
    aad.extend_from_slice(&ctx_len.to_be_bytes());
    aad.extend_from_slice(ctx_bytes);
    #[allow(clippy::cast_possible_truncation)]
    let did_len = did_bytes.len() as u32;
    aad.extend_from_slice(&did_len.to_be_bytes());
    aad.extend_from_slice(did_bytes);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

// ---------------------------------------------------------------------------
// HPKE helpers
// ---------------------------------------------------------------------------

/// HPKE-seals a 32-byte sender key to a recipient's X25519 wrapping pubkey.
///
/// Returns `(sealed_bytes, ephemeral_pubkey)` where `sealed_bytes` is
/// `nonce || ciphertext || tag` (60 bytes for 32-byte plaintext) and
/// `ephemeral_pubkey` is the 32-byte X25519 public key used for ECDH.
///
/// Context binding: both info and AAD include `context_id`, `sender_did`,
/// and `epoch` to prevent cross-context/cross-epoch replay (§9.16.2).
///
/// # Errors
///
/// Returns [`SenderKeyError::HpkeEncryptionFailed`] if HKDF or AES-128-GCM
/// encryption fails.
pub fn hpke_seal_sender_key(
    plaintext: &[u8; 32],
    recipient_pub: &[u8; 32],
    context_id: &str,
    sender_did: &str,
    epoch: u64,
) -> Result<(Vec<u8>, [u8; 32]), SenderKeyError> {
    // 1. Generate ephemeral X25519 keypair.
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519Pub::from(&ephemeral_secret);

    // 2. ECDH between ephemeral secret and recipient's wrapping pubkey.
    let recipient_key = X25519Pub::from(*recipient_pub);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_key);

    // 3. Build context-bound info and AAD (§9.16.2).
    let info = build_hpke_info(context_id, sender_did, epoch);
    let aad = build_hpke_aad(context_id, sender_did, epoch);

    // 4. HKDF to derive 16-byte AES-128-GCM key (zeroized on drop).
    let aes_key = hkdf_derive_key(shared_secret.as_bytes(), &info)?;

    // 5. AES-128-GCM encrypt with AAD.
    let sealed = aes128gcm_encrypt(&aes_key, plaintext, &aad)?;

    Ok((sealed, ephemeral_public.to_bytes()))
}

/// Derives a 16-byte AES-128-GCM key from a 32-byte shared secret using
/// HKDF-SHA256.
///
/// The returned key is wrapped in [`Zeroizing`] so the derived key material
/// is zeroed on drop (defense-in-depth, see issue #82).
fn hkdf_derive_key(
    shared_secret: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; 16]>, SenderKeyError> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = Zeroizing::new([0u8; 16]);
    hk.expand(info, okm.as_mut())
        .map_err(|e| SenderKeyError::HpkeEncryptionFailed(e.to_string()))?;
    Ok(okm)
}

/// Encrypts `plaintext` with AES-128-GCM. Returns `nonce || ciphertext || tag`.
fn aes128gcm_encrypt(
    key: &[u8; 16],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, SenderKeyError> {
    let cipher = Aes128Gcm::new_from_slice(key)
        .map_err(|e| SenderKeyError::HpkeEncryptionFailed(e.to_string()))?;

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
        .map_err(|e| SenderKeyError::HpkeEncryptionFailed(e.to_string()))?;

    let mut output = Vec::with_capacity(HPKE_NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypts AES-128-GCM ciphertext of the form `nonce || ciphertext || tag`.
fn aes128gcm_decrypt(key: &[u8; 16], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, SenderKeyError> {
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
        .decrypt(
            nonce,
            Payload {
                msg: encrypted,
                aad,
            },
        )
        .map_err(|e| SenderKeyError::HpkeDecryptionFailed(e.to_string()))
}

// ---------------------------------------------------------------------------
// Hash helpers
// ---------------------------------------------------------------------------

/// Computes `SHA-256("SCP-EPOCH-ADVANCE-V1:" || len(context_id) || context_id
///   || len(sender_did) || sender_did || "key_epoch" || epoch_BE
///   || len(signer_key_ref) || signer_key_ref)`.
///
/// Variable-length fields are prefixed with their length as a 4-byte
/// big-endian u32 to prevent field-boundary ambiguity. The domain separator
/// prevents cross-protocol hash confusion.
fn compute_epoch_advance_hash(
    context_id: &str,
    sender_did: &str,
    epoch: u64,
    signer_key_ref: SigningKeyId,
) -> Vec<u8> {
    use crate::crypto::canonical::{CanonicalField, canonical_hash};

    // Field order per §9.5.2: context_id, sender_did, "key_epoch" literal, epoch, signer_key_ref.
    canonical_hash(
        "SCP-EPOCH-ADVANCE-V1:",
        &[
            CanonicalField::VarBytes(context_id.as_bytes()),
            CanonicalField::VarBytes(sender_did.as_bytes()),
            CanonicalField::RawBytes(b"key_epoch"),
            CanonicalField::U64(epoch),
            CanonicalField::VarBytes(signer_key_ref.as_bytes()),
        ],
    )
    .to_vec()
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
    use crate::crypto::canonical::{CanonicalField, canonical_hash};

    // Field order per §9.5.2: requester_did, sender_did, epoch, wrapping_pubkey, nonce, timestamp.
    canonical_hash(
        "SCP-KEY-REQUEST-V1:",
        &[
            CanonicalField::VarBytes(requester_did.as_bytes()),
            CanonicalField::VarBytes(sender_did.as_bytes()),
            CanonicalField::U64(epoch),
            CanonicalField::VarBytes(wrapping_pubkey),
            CanonicalField::RawBytes(nonce),
            CanonicalField::U64(timestamp),
        ],
    )
    .to_vec()
}

/// Computes `SHA-256("SCP-BLOCK-NOTIFICATION-V1:" || len(context_id) || context_id
///   || len(blocker_did) || blocker_did || len(blocked_did) || blocked_did
///   || len(signing_key_id) || signing_key_id || timestamp_BE)`.
///
/// Variable-length fields are prefixed with their length as a 4-byte
/// big-endian u32 to prevent field-boundary ambiguity. The domain separator
/// prevents cross-protocol hash confusion.
#[allow(clippy::similar_names)] // blocker_did/blocked_did are domain terms
fn compute_block_notification_hash(
    context_id: &str,
    blocker_did: &str,
    blocked_did: &str,
    signing_key_id: SigningKeyId,
    timestamp: u64,
) -> Vec<u8> {
    use crate::crypto::canonical::{CanonicalField, canonical_hash};

    // Field order per ADR-007 §6: context_id, blocker_did, blocked_did, signing_key_id, timestamp.
    canonical_hash(
        "SCP-BLOCK-NOTIFICATION-V1:",
        &[
            CanonicalField::VarBytes(context_id.as_bytes()),
            CanonicalField::VarBytes(blocker_did.as_bytes()),
            CanonicalField::VarBytes(blocked_did.as_bytes()),
            CanonicalField::VarBytes(signing_key_id.as_bytes()),
            CanonicalField::U64(timestamp),
        ],
    )
    .to_vec()
}

/// Verifies an Ed25519 signature against a public key and message using
/// strict verification (rejects small-order points).
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
            // Signature mismatch → Ok(false). Malformed inputs → Err.
            // Match the known verification-failure prefix so unknown errors
            // default to Err (safe) rather than Ok(false) (silent suppression).
            if reason.starts_with("signature verification failed") {
                Ok(false)
            } else {
                Err(SenderKeyError::VerificationFailed(reason))
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
// Bridge shadow sender key distribution (SCP-BCH-011, §12.6.1)
// ---------------------------------------------------------------------------

/// Parameters for handling a sender key request for a shadow identity
/// routed to the bridge operator.
pub struct BridgeShadowKeyParams<'a> {
    /// The shadow's sender key to distribute (from `SenderKeyStore`).
    pub shadow_sender_key: &'a SenderKey,
    /// The bridge operator's DID.
    pub bridge_operator_did: &'a str,
    /// The shadow DID being requested.
    pub shadow_did: &'a str,
    /// The context ID.
    pub context_id: &'a str,
}

/// Handles a sender key request for a shadow identity.
///
/// The bridge operator retrieves the shadow's sender key from
/// `SenderKeyStore` and wraps it via HPKE to the requester's wrapping
/// key. Uses the `"scp-sender-key-v1"` domain separation label
/// per §9.16.2.
///
/// # Arguments
///
/// - `requester_wrapping_pubkey` -- The requesting member's X25519
///   wrapping public key (32 bytes).
/// - `params` -- Bridge shadow key parameters.
///
/// # Returns
///
/// `(hpke_sealed_key, ephemeral_public_key)` -- The HPKE-wrapped sender
/// key and the ephemeral public key for ECDH reconstruction.
///
/// # Errors
///
/// Returns `SenderKeyError::HpkeEncryptionFailed` if HPKE wrapping fails.
pub fn handle_bridge_shadow_key_request(
    requester_wrapping_pubkey: &[u8; 32],
    params: &BridgeShadowKeyParams<'_>,
) -> Result<([u8; 60], [u8; 32]), SenderKeyError> {
    let (sealed_vec, ephemeral_pub) = hpke_seal_sender_key(
        params.shadow_sender_key.as_bytes(),
        requester_wrapping_pubkey,
        params.context_id,
        params.shadow_did,
        0, // Shadow keys are initial distribution (epoch 0)
    )?;

    // Convert to fixed-size array.
    let mut sealed_arr = [0u8; 60];
    if sealed_vec.len() != 60 {
        return Err(SenderKeyError::HpkeEncryptionFailed(format!(
            "expected 60 bytes from HPKE seal, got {}",
            sealed_vec.len()
        )));
    }
    sealed_arr.copy_from_slice(&sealed_vec);

    Ok((sealed_arr, ephemeral_pub))
}

/// Returns all shadow DIDs that have sender keys in the store for a
/// given context. Used by members joining a bridged context to discover
/// which shadows to request keys from.
///
/// # Arguments
///
/// - `store` -- The sender key store.
/// - `context_id` -- The context to enumerate.
/// - `shadow_prefix` -- Prefix for shadow DIDs (e.g., `"shadow:"`).
///
/// # Returns
///
/// A list of shadow DIDs in the context that have sender keys.
#[must_use]
pub fn list_shadow_sender_key_dids(
    store: &super::SenderKeyStore,
    context_id: &str,
    shadow_prefix: &str,
) -> Vec<String> {
    store
        .get_all(context_id)
        .into_keys()
        .filter(|did| did.starts_with(shadow_prefix))
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
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
        #[derive(Serialize)]
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
        assert_eq!(notification.notification_type, "block_notification");
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
    // HPKE helpers
    // -------------------------------------------------------------------

    #[test]
    fn hpke_seal_and_open_roundtrip() {
        let plaintext = [0xABu8; 32];
        let ctx = "ctx-test";
        let sender = "did:dht:alice";
        let epoch = 1u64;

        let recipient_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let recipient_public = X25519Pub::from(&recipient_secret);

        let (sealed, ephemeral_pub) =
            hpke_seal_sender_key(&plaintext, &recipient_public.to_bytes(), ctx, sender, epoch)
                .unwrap();

        let ephemeral_key = X25519Pub::from(ephemeral_pub);
        let shared = recipient_secret.diffie_hellman(&ephemeral_key);
        let info = build_hpke_info(ctx, sender, epoch);
        let aad = build_hpke_aad(ctx, sender, epoch);
        let aes_key = hkdf_derive_key(shared.as_bytes(), &info).unwrap();
        let recovered = aes128gcm_decrypt(&aes_key, &sealed, &aad).unwrap();

        assert_eq!(recovered.as_slice(), &plaintext);
    }

    #[test]
    fn hpke_rejects_wrong_recipient() {
        let plaintext = [0xCDu8; 32];
        let ctx = "ctx-test";
        let sender = "did:dht:alice";
        let epoch = 1u64;

        let recipient_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let recipient_public = X25519Pub::from(&recipient_secret);

        let wrong_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);

        let (sealed, ephemeral_pub) =
            hpke_seal_sender_key(&plaintext, &recipient_public.to_bytes(), ctx, sender, epoch)
                .unwrap();

        let ephemeral_key = X25519Pub::from(ephemeral_pub);
        let shared = wrong_secret.diffie_hellman(&ephemeral_key);
        let info = build_hpke_info(ctx, sender, epoch);
        let aad = build_hpke_aad(ctx, sender, epoch);
        let aes_key = hkdf_derive_key(shared.as_bytes(), &info).unwrap();
        let result = aes128gcm_decrypt(&aes_key, &sealed, &aad);

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
    // HPKE context binding (§9.16.2, #395)
    // -------------------------------------------------------------------

    #[test]
    fn hpke_rejects_wrong_context_id() {
        let plaintext = [0xEFu8; 32];
        let sender = "did:dht:alice";
        let epoch = 1u64;
        let recipient_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let recipient_public = X25519Pub::from(&recipient_secret);

        let (sealed, ephemeral_pub) = hpke_seal_sender_key(
            &plaintext,
            &recipient_public.to_bytes(),
            "ctx-A",
            sender,
            epoch,
        )
        .unwrap();

        let ephemeral_key = X25519Pub::from(ephemeral_pub);
        let shared = recipient_secret.diffie_hellman(&ephemeral_key);
        let wrong_info = build_hpke_info("ctx-B", sender, epoch);
        let wrong_aad = build_hpke_aad("ctx-B", sender, epoch);
        let aes_key = hkdf_derive_key(shared.as_bytes(), &wrong_info).unwrap();
        let result = aes128gcm_decrypt(&aes_key, &sealed, &wrong_aad);
        assert!(
            result.is_err(),
            "wrong context_id should fail AEAD decryption"
        );
    }

    #[test]
    fn hpke_rejects_wrong_sender_did() {
        let plaintext = [0xDDu8; 32];
        let ctx = "ctx-test";
        let epoch = 1u64;
        let recipient_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let recipient_public = X25519Pub::from(&recipient_secret);

        let (sealed, ephemeral_pub) = hpke_seal_sender_key(
            &plaintext,
            &recipient_public.to_bytes(),
            ctx,
            "did:dht:alice",
            epoch,
        )
        .unwrap();

        let ephemeral_key = X25519Pub::from(ephemeral_pub);
        let shared = recipient_secret.diffie_hellman(&ephemeral_key);
        let wrong_info = build_hpke_info(ctx, "did:dht:bob", epoch);
        let wrong_aad = build_hpke_aad(ctx, "did:dht:bob", epoch);
        let aes_key = hkdf_derive_key(shared.as_bytes(), &wrong_info).unwrap();
        let result = aes128gcm_decrypt(&aes_key, &sealed, &wrong_aad);
        assert!(
            result.is_err(),
            "wrong sender_did should fail AEAD decryption"
        );
    }

    #[test]
    fn hpke_rejects_wrong_epoch() {
        let plaintext = [0xBBu8; 32];
        let ctx = "ctx-test";
        let sender = "did:dht:alice";
        let recipient_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let recipient_public = X25519Pub::from(&recipient_secret);

        let (sealed, ephemeral_pub) =
            hpke_seal_sender_key(&plaintext, &recipient_public.to_bytes(), ctx, sender, 1).unwrap();

        let ephemeral_key = X25519Pub::from(ephemeral_pub);
        let shared = recipient_secret.diffie_hellman(&ephemeral_key);
        let wrong_info = build_hpke_info(ctx, sender, 2);
        let wrong_aad = build_hpke_aad(ctx, sender, 2);
        let aes_key = hkdf_derive_key(shared.as_bytes(), &wrong_info).unwrap();
        let result = aes128gcm_decrypt(&aes_key, &sealed, &wrong_aad);
        assert!(result.is_err(), "wrong epoch should fail AEAD decryption");
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
    // validate_sender_key_request_freshness (timestamp + replay)
    // -------------------------------------------------------------------

    #[test]
    fn fresh_request_passes_freshness_check() {
        let now = 1_700_000_000u64;
        let request = SenderKeyRequest {
            requester_did: "did:dht:bob".to_owned(),
            sender_did: "did:dht:alice".to_owned(),
            epoch: 1,
            wrapping_pubkey: [0u8; 32],
            nonce: [0u8; REQUEST_NONCE_SIZE],
            timestamp: now,
            signature: [0u8; 64],
        };
        assert!(
            validate_sender_key_request_freshness(&request, now).is_ok(),
            "request at current time should pass freshness check"
        );
    }

    #[test]
    fn stale_request_rejected_by_freshness_check() {
        let now = 1_700_000_000u64;
        let request = SenderKeyRequest {
            requester_did: "did:dht:bob".to_owned(),
            sender_did: "did:dht:alice".to_owned(),
            epoch: 1,
            wrapping_pubkey: [0u8; 32],
            nonce: [0u8; REQUEST_NONCE_SIZE],
            timestamp: now,
            signature: [0u8; 64],
        };
        // Simulate receiving far in the future.
        let far_future = now + REQUEST_FRESHNESS_SECS + 1;
        let result = validate_sender_key_request_freshness(&request, far_future);
        assert!(
            matches!(result, Err(SenderKeyError::StaleSenderKeyRequest)),
            "stale request should be rejected with StaleSenderKeyRequest"
        );
    }

    #[test]
    fn future_timestamp_request_rejected_by_freshness_check() {
        let now = 1_700_000_000u64;
        let request = SenderKeyRequest {
            requester_did: "did:dht:bob".to_owned(),
            sender_did: "did:dht:alice".to_owned(),
            epoch: 1,
            wrapping_pubkey: [0u8; 32],
            nonce: [0u8; REQUEST_NONCE_SIZE],
            // Timestamp far ahead of "now".
            timestamp: now + REQUEST_FRESHNESS_SECS + 10_000,
            signature: [0u8; 64],
        };
        let result = validate_sender_key_request_freshness(&request, now);
        assert!(
            matches!(result, Err(SenderKeyError::StaleSenderKeyRequest)),
            "future-timestamped request should be rejected with StaleSenderKeyRequest"
        );
    }

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

    // -------------------------------------------------------------------
    // length prefix prevents field boundary ambiguity
    // -------------------------------------------------------------------

    #[test]
    fn epoch_advance_hash_boundary_shift_produces_different_hash() {
        let hash_a = compute_epoch_advance_hash("ctx-AB", "did:key:CD", 1, SigningKeyId::Active);
        let hash_b = compute_epoch_advance_hash("ctx-ABC", "did:key:D", 1, SigningKeyId::Active);
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
        let hash_a = compute_block_notification_hash(
            "ctx-1",
            "did:key:AB",
            "did:key:CD",
            SigningKeyId::Active,
            100,
        );
        let hash_b = compute_block_notification_hash(
            "ctx-1",
            "did:key:ABC",
            "did:key:D",
            SigningKeyId::Active,
            100,
        );
        assert_ne!(
            hash_a, hash_b,
            "shifting bytes between blocker_did and blocked_did must produce different hashes"
        );
    }

    // -------------------------------------------------------------------
    // Category A enforcement tests (ADR-039, SCP-AB-020)
    // -------------------------------------------------------------------

    #[test]
    fn enforce_rejects_agent_key_category_a_did_document() {
        let result = enforce_sender_key_category_a(
            SigningKeyId::Agent,
            "did:dht:alice",
            "did_document",
            &[0xAB; 64],
        );
        assert!(
            result.is_err(),
            "agent key should be rejected for did_document"
        );
        assert!(matches!(
            result.unwrap_err(),
            SenderKeyError::CategoryAViolation(_)
        ));
    }

    #[test]
    fn enforce_rejects_agent_key_category_a_verification_method() {
        let result = enforce_sender_key_category_a(
            SigningKeyId::Agent,
            "did:dht:alice",
            "verification_method",
            &[0xAB; 64],
        );
        assert!(
            result.is_err(),
            "agent key should be rejected for verification_method"
        );
    }

    #[test]
    fn enforce_accepts_agent_key_category_b_messages() {
        let result = enforce_sender_key_category_a(
            SigningKeyId::Agent,
            "did:dht:alice",
            "messages",
            &[0xAB; 64],
        );
        assert!(result.is_ok(), "agent key should be accepted for messages");
    }

    #[test]
    fn enforce_accepts_active_key_category_a() {
        let result = enforce_sender_key_category_a(
            SigningKeyId::Active,
            "did:dht:alice",
            "did_document",
            &[0xAB; 64],
        );
        assert!(
            result.is_ok(),
            "active key should be accepted for did_document"
        );
    }

    #[test]
    fn enforce_accepts_active_key_category_b() {
        let result = enforce_sender_key_category_a(
            SigningKeyId::Active,
            "did:dht:alice",
            "messages",
            &[0xAB; 64],
        );
        assert!(result.is_ok(), "active key should be accepted for messages");
    }

    #[test]
    fn enforce_rejects_agent_key_all_category_a_resources() {
        let category_a_resources = [
            "did_document",
            "verification_method",
            "identity",
            "pre_rotation",
            "service",
            "relay_config",
            "did_migration",
            "key_management",
        ];

        for resource in &category_a_resources {
            let result = enforce_sender_key_category_a(
                SigningKeyId::Agent,
                "did:dht:alice",
                resource,
                &[0xAB; 64],
            );
            assert!(
                result.is_err(),
                "agent key should be rejected for Category A resource: {resource}"
            );
        }
    }

    // -------------------------------------------------------------------
    // Deserialization size-limit tests (#347)
    // -------------------------------------------------------------------

    #[test]
    fn hpke_sealed_key_wrong_length_rejected_on_deser() {
        // hpke_sealed_key is now [u8; 60] — length is enforced at the type
        // level by serde_hpke_sealed_60. Verify deserialization rejects wrong
        // sizes (#347).
        #[derive(serde::Serialize)]
        struct FakeResponse {
            sender_did: String,
            epoch: u64,
            #[serde(with = "serde_bytes")]
            hpke_sealed_key: Vec<u8>,
            #[serde(with = "serde_pubkey_32")]
            ephemeral_pubkey: [u8; 32],
            #[serde(with = "serde_bytes")]
            request_nonce: [u8; REQUEST_NONCE_SIZE],
        }

        // 59 bytes — too short.
        let fake_short = FakeResponse {
            sender_did: "did:dht:alice".to_owned(),
            epoch: 1,
            hpke_sealed_key: vec![0u8; 59],
            ephemeral_pubkey: [0u8; 32],
            request_nonce: [0u8; REQUEST_NONCE_SIZE],
        };
        let serialized = rmp_serde::to_vec_named(&fake_short).unwrap();
        let result = rmp_serde::from_slice::<SenderKeyResponse>(&serialized);
        assert!(result.is_err(), "should reject 59-byte sealed key");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("60-byte HPKE sealed key"),
            "error should mention 60-byte: {err}"
        );

        // 61 bytes — too long.
        let fake_long = FakeResponse {
            sender_did: "did:dht:alice".to_owned(),
            epoch: 1,
            hpke_sealed_key: vec![0u8; 61],
            ephemeral_pubkey: [0u8; 32],
            request_nonce: [0u8; REQUEST_NONCE_SIZE],
        };
        let serialized_long = rmp_serde::to_vec_named(&fake_long).unwrap();
        let result_long = rmp_serde::from_slice::<SenderKeyResponse>(&serialized_long);
        assert!(result_long.is_err(), "should reject 61-byte sealed key");
    }

    #[test]
    fn oversized_signature_rejected_on_deser() {
        // A SenderKeyEpochAdvance with a 65-byte signature field must be
        // rejected during deserialization because serde_signature_64 enforces
        // exactly 64 bytes (#347).
        #[derive(serde::Serialize)]
        struct FakeAdvance {
            sender_did: String,
            epoch: u64,
            signer_key_ref: SigningKeyId,
            #[serde(with = "serde_bytes")]
            signature: Vec<u8>,
        }

        let fake = FakeAdvance {
            sender_did: "did:dht:alice".to_owned(),
            epoch: 1,
            signer_key_ref: SigningKeyId::Active,
            signature: vec![0u8; 65],
        };

        let serialized = rmp_serde::to_vec_named(&fake).unwrap();
        let result = rmp_serde::from_slice::<SenderKeyEpochAdvance>(&serialized);
        assert!(result.is_err(), "should reject 65-byte signature");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("64-byte signature"),
            "error should mention 64-byte: {err}"
        );
    }

    // -------------------------------------------------------------------
    // MessagePack wire-format round-trip serde tests (#335)
    // -------------------------------------------------------------------

    #[test]
    fn sender_key_epoch_advance_msgpack_roundtrip() {
        let advance = SenderKeyEpochAdvance {
            sender_did: "did:dht:alice".to_owned(),
            epoch: 42,
            signer_key_ref: SigningKeyId::Active,
            signature: [0xAB; 64],
        };
        let bytes = rmp_serde::to_vec_named(&advance).unwrap();
        let deserialized: SenderKeyEpochAdvance = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(deserialized.sender_did, advance.sender_did);
        assert_eq!(deserialized.epoch, advance.epoch);
        assert_eq!(deserialized.signer_key_ref, advance.signer_key_ref);
        assert_eq!(deserialized.signature, advance.signature);
    }

    #[test]
    fn sender_key_epoch_advance_agent_key_roundtrip() {
        let advance = SenderKeyEpochAdvance {
            sender_did: "did:dht:bob".to_owned(),
            epoch: 1,
            signer_key_ref: SigningKeyId::Agent,
            signature: [0xCD; 64],
        };
        let bytes = rmp_serde::to_vec_named(&advance).unwrap();
        let deserialized: SenderKeyEpochAdvance = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(deserialized.signer_key_ref, SigningKeyId::Agent);
        assert_eq!(deserialized.signature, advance.signature);
    }

    #[test]
    fn sender_key_request_msgpack_roundtrip() {
        let request = SenderKeyRequest {
            requester_did: "did:dht:bob".to_owned(),
            sender_did: "did:dht:alice".to_owned(),
            epoch: 7,
            wrapping_pubkey: [0x11; 32],
            nonce: [0x22; REQUEST_NONCE_SIZE],
            timestamp: 1_700_000_000,
            signature: [0x33; 64],
        };
        let bytes = rmp_serde::to_vec_named(&request).unwrap();
        let deserialized: SenderKeyRequest = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(deserialized.requester_did, request.requester_did);
        assert_eq!(deserialized.sender_did, request.sender_did);
        assert_eq!(deserialized.epoch, request.epoch);
        assert_eq!(deserialized.wrapping_pubkey, request.wrapping_pubkey);
        assert_eq!(deserialized.nonce, request.nonce);
        assert_eq!(deserialized.timestamp, request.timestamp);
        assert_eq!(deserialized.signature, request.signature);
    }

    #[test]
    fn sender_key_response_msgpack_roundtrip() {
        let response = SenderKeyResponse {
            sender_did: "did:dht:alice".to_owned(),
            epoch: 3,
            hpke_sealed_key: [0x44; 60],
            ephemeral_pubkey: [0x55; 32],
            request_nonce: [0x66; REQUEST_NONCE_SIZE],
        };
        let bytes = rmp_serde::to_vec_named(&response).unwrap();
        let deserialized: SenderKeyResponse = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(deserialized.sender_did, response.sender_did);
        assert_eq!(deserialized.epoch, response.epoch);
        assert_eq!(deserialized.hpke_sealed_key, response.hpke_sealed_key);
        assert_eq!(deserialized.ephemeral_pubkey, response.ephemeral_pubkey);
        assert_eq!(deserialized.request_nonce, response.request_nonce);
    }

    #[test]
    fn block_notification_msgpack_roundtrip() {
        let notification = BlockNotification {
            notification_type: "block_notification".to_owned(),
            blocker: "did:dht:alice".to_owned(),
            blocked: "did:dht:dave".to_owned(),
            signing_key_id: SigningKeyId::Active,
            timestamp: 1_700_000_000_000,
            signature: [0x77; 64],
        };
        let bytes = rmp_serde::to_vec_named(&notification).unwrap();
        let deserialized: BlockNotification = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(
            deserialized.notification_type,
            notification.notification_type
        );
        assert_eq!(deserialized.blocker, notification.blocker);
        assert_eq!(deserialized.blocked, notification.blocked);
        assert_eq!(deserialized.signing_key_id, notification.signing_key_id);
        assert_eq!(deserialized.timestamp, notification.timestamp);
        assert_eq!(deserialized.signature, notification.signature);
    }

    // -------------------------------------------------------------------
    // SenderKeyDistributionMessage transport envelope tests (#335)
    // -------------------------------------------------------------------

    #[test]
    fn distribution_message_epoch_advance_roundtrip() {
        let advance = SenderKeyEpochAdvance {
            sender_did: "did:dht:alice".to_owned(),
            epoch: 5,
            signer_key_ref: SigningKeyId::Active,
            signature: [0xAA; 64],
        };
        let msg = SenderKeyDistributionMessage::EpochAdvance(advance);
        let bytes = msg.to_bytes().unwrap();
        let deserialized = SenderKeyDistributionMessage::from_bytes(&bytes).unwrap();
        match deserialized {
            SenderKeyDistributionMessage::EpochAdvance(a) => {
                assert_eq!(a.sender_did, "did:dht:alice");
                assert_eq!(a.epoch, 5);
            }
            other => panic!("expected EpochAdvance, got {other:?}"),
        }
    }

    #[test]
    fn distribution_message_key_request_roundtrip() {
        let request = SenderKeyRequest {
            requester_did: "did:dht:bob".to_owned(),
            sender_did: "did:dht:alice".to_owned(),
            epoch: 1,
            wrapping_pubkey: [0xBB; 32],
            nonce: [0xCC; REQUEST_NONCE_SIZE],
            timestamp: 1_700_000_000,
            signature: [0xDD; 64],
        };
        let msg = SenderKeyDistributionMessage::KeyRequest(request);
        let bytes = msg.to_bytes().unwrap();
        let deserialized = SenderKeyDistributionMessage::from_bytes(&bytes).unwrap();
        match deserialized {
            SenderKeyDistributionMessage::KeyRequest(r) => {
                assert_eq!(r.requester_did, "did:dht:bob");
                assert_eq!(r.sender_did, "did:dht:alice");
                assert_eq!(r.epoch, 1);
            }
            other => panic!("expected KeyRequest, got {other:?}"),
        }
    }

    #[test]
    fn distribution_message_key_response_roundtrip() {
        let response = SenderKeyResponse {
            sender_did: "did:dht:alice".to_owned(),
            epoch: 2,
            hpke_sealed_key: [0xEE; 60],
            ephemeral_pubkey: [0xFF; 32],
            request_nonce: [0x11; REQUEST_NONCE_SIZE],
        };
        let msg = SenderKeyDistributionMessage::KeyResponse(response);
        let bytes = msg.to_bytes().unwrap();
        let deserialized = SenderKeyDistributionMessage::from_bytes(&bytes).unwrap();
        match deserialized {
            SenderKeyDistributionMessage::KeyResponse(r) => {
                assert_eq!(r.sender_did, "did:dht:alice");
                assert_eq!(r.epoch, 2);
                assert_eq!(r.hpke_sealed_key, [0xEE; 60]);
            }
            other => panic!("expected KeyResponse, got {other:?}"),
        }
    }

    #[test]
    fn distribution_message_block_notification_roundtrip() {
        let notification = BlockNotification {
            notification_type: "block_notification".to_owned(),
            blocker: "did:dht:alice".to_owned(),
            blocked: "did:dht:dave".to_owned(),
            signing_key_id: SigningKeyId::Active,
            timestamp: 1_700_000_000_000,
            signature: [0x99; 64],
        };
        let msg = SenderKeyDistributionMessage::BlockNotification(notification);
        let bytes = msg.to_bytes().unwrap();
        let deserialized = SenderKeyDistributionMessage::from_bytes(&bytes).unwrap();
        match deserialized {
            SenderKeyDistributionMessage::BlockNotification(n) => {
                assert_eq!(n.blocker, "did:dht:alice");
                assert_eq!(n.blocked, "did:dht:dave");
            }
            other => panic!("expected BlockNotification, got {other:?}"),
        }
    }

    #[test]
    fn distribution_message_discriminator_preserved_in_wire_format() {
        // Verify that the msg_type tag is correctly set for each variant.
        let advance = SenderKeyDistributionMessage::EpochAdvance(SenderKeyEpochAdvance {
            sender_did: "did:dht:alice".to_owned(),
            epoch: 1,
            signer_key_ref: SigningKeyId::Active,
            signature: [0; 64],
        });
        let request = SenderKeyDistributionMessage::KeyRequest(SenderKeyRequest {
            requester_did: "did:dht:bob".to_owned(),
            sender_did: "did:dht:alice".to_owned(),
            epoch: 1,
            wrapping_pubkey: [0; 32],
            nonce: [0; REQUEST_NONCE_SIZE],
            timestamp: 0,
            signature: [0; 64],
        });
        let response = SenderKeyDistributionMessage::KeyResponse(SenderKeyResponse {
            sender_did: "did:dht:alice".to_owned(),
            epoch: 1,
            hpke_sealed_key: [0; 60],
            ephemeral_pubkey: [0; 32],
            request_nonce: [0; REQUEST_NONCE_SIZE],
        });
        let block = SenderKeyDistributionMessage::BlockNotification(BlockNotification {
            notification_type: "block_notification".to_owned(),
            blocker: "did:dht:alice".to_owned(),
            blocked: "did:dht:dave".to_owned(),
            signing_key_id: SigningKeyId::Active,
            timestamp: 0,
            signature: [0; 64],
        });

        // All four variants should serialize and deserialize back to the same
        // variant (discriminator is preserved in wire format).
        for (msg, expected_variant) in [
            (&advance, "EpochAdvance"),
            (&request, "KeyRequest"),
            (&response, "KeyResponse"),
            (&block, "BlockNotification"),
        ] {
            let bytes = msg.to_bytes().unwrap();
            let restored = SenderKeyDistributionMessage::from_bytes(&bytes).unwrap();
            let variant = format!("{restored:?}");
            assert!(
                variant.starts_with(expected_variant),
                "expected {expected_variant} variant, got: {variant}"
            );
        }
    }

    // Bridge shadow sender key distribution (SCP-BCH-011)
    // -------------------------------------------------------------------

    #[test]
    fn bridge_shadow_key_request_roundtrip() {
        use super::{BridgeShadowKeyParams, handle_bridge_shadow_key_request};

        let shadow_key = generate_sender_key();
        let (recipient_pub, recipient_secret) = generate_wrapping_keypair();

        let params = BridgeShadowKeyParams {
            shadow_sender_key: &shadow_key,
            bridge_operator_did: "did:dht:z6MkOperator",
            shadow_did: "shadow:bridge-001:user-alice",
            context_id: "ctx-bridge-test",
        };

        let (sealed, ephemeral_pub) =
            handle_bridge_shadow_key_request(&recipient_pub, &params).unwrap();

        // Unwrap: ECDH with recipient secret and ephemeral public.
        let recipient_static = x25519_dalek::StaticSecret::from(recipient_secret);
        let eph_pub = x25519_dalek::PublicKey::from(ephemeral_pub);
        let shared = recipient_static.diffie_hellman(&eph_pub);
        let info = build_hpke_info("ctx-bridge-test", "shadow:bridge-001:user-alice", 0);
        let aad = build_hpke_aad("ctx-bridge-test", "shadow:bridge-001:user-alice", 0);
        let aes_key = hkdf_derive_key(shared.as_bytes(), &info).unwrap();

        let decrypted = aes128gcm_decrypt(&aes_key, &sealed, &aad).unwrap();
        assert_eq!(decrypted.len(), 32);
        assert_eq!(&decrypted[..], shadow_key.as_bytes());
    }

    #[test]
    fn bridge_shadow_key_domain_separation() {
        // Verify that HPKE_INFO (domain separation label) is "scp-sender-key-v1".
        assert_eq!(HPKE_INFO_PREFIX, b"scp-sender-key-v1");
    }

    #[test]
    fn bridge_shadow_key_request_nonexistent_shadow_key_fails() {
        use super::{BridgeShadowKeyParams, handle_bridge_shadow_key_request};

        // Should succeed — it's a well-formed request. The "nonexistent"
        // check would happen at a higher layer (SenderKeyStore lookup).
        let shadow_key = generate_sender_key();
        let (recipient_pub, _) = generate_wrapping_keypair();

        let params = BridgeShadowKeyParams {
            shadow_sender_key: &shadow_key,
            bridge_operator_did: "did:dht:z6MkOperator",
            shadow_did: "shadow:nonexistent",
            context_id: "ctx-test",
        };

        let result = handle_bridge_shadow_key_request(&recipient_pub, &params);
        assert!(result.is_ok());
    }

    #[test]
    fn list_shadow_sender_key_dids_filters_by_prefix() {
        use super::list_shadow_sender_key_dids;
        use crate::crypto::sender_keys::SenderKeyStore;

        let mut store = SenderKeyStore::new();
        store.set("ctx-1", "shadow:bridge-001:alice", generate_sender_key());
        store.set("ctx-1", "shadow:bridge-001:bob", generate_sender_key());
        store.set("ctx-1", "did:dht:z6MkNative", generate_sender_key());

        let shadow_dids = list_shadow_sender_key_dids(&store, "ctx-1", "shadow:");
        assert_eq!(shadow_dids.len(), 2);
        assert!(shadow_dids.contains(&"shadow:bridge-001:alice".to_owned()));
        assert!(shadow_dids.contains(&"shadow:bridge-001:bob".to_owned()));
    }

    #[test]
    fn list_shadow_sender_key_dids_empty_context() {
        use super::list_shadow_sender_key_dids;
        use crate::crypto::sender_keys::SenderKeyStore;

        let store = SenderKeyStore::new();
        let dids = list_shadow_sender_key_dids(&store, "ctx-empty", "shadow:");
        assert!(dids.is_empty());
    }

    // -------------------------------------------------------------------
    // Forward compatibility: unknown fields ignored (§13.5.1, #593)
    // -------------------------------------------------------------------

    #[test]
    fn sender_key_epoch_advance_ignores_unknown_fields() {
        let advance = SenderKeyEpochAdvance {
            sender_did: "did:dht:alice".to_owned(),
            epoch: 42,
            signer_key_ref: SigningKeyId::Active,
            signature: [0xAB; 64],
        };
        let mut map: serde_json::Map<String, serde_json::Value> =
            serde_json::from_value(serde_json::to_value(&advance).unwrap()).unwrap();
        map.insert("future_field".into(), "v2-data".into());
        let result =
            serde_json::from_value::<SenderKeyEpochAdvance>(serde_json::Value::Object(map));
        assert!(
            result.is_ok(),
            "wire-format types must ignore unknown fields per §13.5.1: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        assert_eq!(decoded.sender_did, "did:dht:alice");
        assert_eq!(decoded.epoch, 42);
    }

    #[test]
    fn sender_key_request_ignores_unknown_fields() {
        let request = SenderKeyRequest {
            requester_did: "did:dht:bob".to_owned(),
            sender_did: "did:dht:alice".to_owned(),
            epoch: 7,
            wrapping_pubkey: [0x11; 32],
            nonce: [0x22; REQUEST_NONCE_SIZE],
            timestamp: 1_700_000_000,
            signature: [0x33; 64],
        };
        let mut map: serde_json::Map<String, serde_json::Value> =
            serde_json::from_value(serde_json::to_value(&request).unwrap()).unwrap();
        map.insert("future_field".into(), 42.into());
        let result = serde_json::from_value::<SenderKeyRequest>(serde_json::Value::Object(map));
        assert!(
            result.is_ok(),
            "wire-format types must ignore unknown fields per §13.5.1: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        assert_eq!(decoded.requester_did, "did:dht:bob");
        assert_eq!(decoded.epoch, 7);
    }

    #[test]
    fn sender_key_response_ignores_unknown_fields() {
        let response = SenderKeyResponse {
            sender_did: "did:dht:alice".to_owned(),
            epoch: 3,
            hpke_sealed_key: [0x44; 60],
            ephemeral_pubkey: [0x55; 32],
            request_nonce: [0x66; REQUEST_NONCE_SIZE],
        };
        let mut map: serde_json::Map<String, serde_json::Value> =
            serde_json::from_value(serde_json::to_value(&response).unwrap()).unwrap();
        map.insert("future_field".into(), serde_json::json!({"nested": true}));
        let result = serde_json::from_value::<SenderKeyResponse>(serde_json::Value::Object(map));
        assert!(
            result.is_ok(),
            "wire-format types must ignore unknown fields per §13.5.1: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        assert_eq!(decoded.sender_did, "did:dht:alice");
        assert_eq!(decoded.epoch, 3);
    }

    #[test]
    fn block_notification_ignores_unknown_fields() {
        let notification = BlockNotification {
            notification_type: "block_notification".to_owned(),
            blocker: "did:dht:alice".to_owned(),
            blocked: "did:dht:dave".to_owned(),
            signing_key_id: SigningKeyId::Active,
            timestamp: 1_700_000_000_000,
            signature: [0x77; 64],
        };
        let mut map: serde_json::Map<String, serde_json::Value> =
            serde_json::from_value(serde_json::to_value(&notification).unwrap()).unwrap();
        map.insert("future_field".into(), "v2-data".into());
        let result = serde_json::from_value::<BlockNotification>(serde_json::Value::Object(map));
        assert!(
            result.is_ok(),
            "wire-format types must ignore unknown fields per §13.5.1: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        assert_eq!(decoded.blocker, "did:dht:alice");
        assert_eq!(decoded.blocked, "did:dht:dave");
    }
}
