//! Wire types and HPKE distribution protocol for access keys.
//!
//! Access keys are distributed via the same pull-based RFC 9180 HPKE protocol
//! as sender keys (§9.16.2), but with a distinct domain separator
//! (`"scp-access-key-v1"`) to prevent cross-protocol key confusion. Sealing and
//! opening go through the shared [`scp_protocol::crypto::hpke`] core.
//!
//! Protocol flow:
//! 1. New member sends [`AccessKeyRequest`] with an ephemeral DHKEM(P-256)
//!    wrapping pubkey (65-byte uncompressed point), signature, nonce, and
//!    timestamp for replay protection.
//! 2. Key holder verifies the request and HPKE-seals the access key.
//! 3. Key holder responds with [`AccessKeyResponse`] containing the sealed
//!    ciphertext (`ct`) and the HPKE encapsulated key (`enc`).
//! 4. Requester opens via [`open_access_key_response`].
//!
//! See ADR-038 §2 and spec §9.17.1.

use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use scp_clock::Clock;
use scp_platform::traits::{KeyCustody, KeyHandle, KeyType};

use scp_did::{DID, SigningKeyId};
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::crypto::access_keys::{AccessKey, AccessKeyError};
use scp_protocol::crypto::hpke::p256::{self as hpke, P256Point};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

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

/// Maximum age (seconds) for an access key request. Requests older than
/// this are rejected. Set to 300s (5 minutes) to accommodate network
/// latency and clock skew for past timestamps.
const REQUEST_MAX_AGE_SECS: u64 = 300;

/// Maximum future tolerance (seconds) for access key request timestamps.
/// Requests timestamped further in the future than this are rejected.
/// Tighter than the past window because future timestamps indicate clock
/// manipulation rather than legitimate network delay.
const REQUEST_MAX_FUTURE_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Request for a member's access key.
///
/// Sent to the key holder (context creator or `AddMember` executor).
/// The requester includes a fresh DHKEM(P-256) wrapping public key so the
/// responder can HPKE-encrypt the access key material.
///
/// Contains a timestamp and cryptographic nonce for replay protection.
/// The responder rejects requests older than 300 seconds or more than 30
/// seconds in the future, and deduplicates by nonce within the window.
///
/// Signature payload: `SHA-256("SCP-ACCESS-KEY-REQUEST-V1:" || BE32(len(context_id)) || context_id || BE32(len(requester_did)) || requester_did || timestamp_BE || wrapping_pubkey || nonce)`,
/// the §9.5.2 `AccessKeyRequest` field table.
///
/// See spec §9.17.1 and §9.5.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessKeyRequest {
    /// The DID of the member requesting the access key.
    pub requester_did: String,
    /// The context the access key belongs to.
    pub context_id: String,
    /// Fresh DHKEM(P-256) public key for HPKE wrapping: the 65-byte
    /// uncompressed SEC1 point (RFC 9180 §7.1.1), validated (§9.5) when the
    /// request is decoded, so no hash or seal reads an unvalidated key.
    pub wrapping_pubkey: P256Point,
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
/// Sent back to the requester. The access key is sealed with RFC 9180 HPKE
/// Base mode (DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM) under
/// the `"scp-access-key-v1"` domain separator. The AEAD nonce is internal per
/// RFC 9180 — there is no external nonce on the wire.
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
    /// HPKE ciphertext (`ct = ciphertext || tag`, exactly 48 bytes: a 32-byte
    /// access key plus the 16-byte AES-128-GCM tag). Fixed-size so deserialize
    /// cannot allocate an arbitrarily large buffer from malicious input.
    #[serde(with = "scp_protocol::serde_util::serde_hpke_sealed_48")]
    pub hpke_sealed_key: [u8; 48],
    /// HPKE encapsulated key (`enc`, the 65-byte uncompressed ephemeral P-256
    /// public key), validated (§9.5) when the response is decoded, before any
    /// key agreement on open.
    pub ephemeral_pubkey: P256Point,
}

/// Result of [`request_access_key`], containing the serialized request
/// message and the DHKEM(P-256) wrapping key handle for later HPKE decryption.
#[derive(Debug)]
pub struct AccessKeyRequestResult {
    /// The serialized [`AccessKeyRequest`] message to send.
    pub request_message: Vec<u8>,
    /// The [`KeyType::HpkeP256`] key handle used for HPKE wrapping. The caller
    /// retains this to decrypt the eventual [`AccessKeyResponse`].
    pub wrapping_key_handle: KeyHandle,
}

// ---------------------------------------------------------------------------
// Request construction (requester side)
// ---------------------------------------------------------------------------

/// Constructs a signed [`AccessKeyRequest`] with a fresh ephemeral
/// DHKEM(P-256) wrapping keypair and serializes it for transmission.
///
/// The requester signs the request with their signing key (Active or Agent).
/// The wrapping key handle is returned so the caller can later decrypt
/// the [`AccessKeyResponse`] via [`open_access_key_response`].
///
/// # Errors
///
/// Returns [`AccessKeyError::Custody`] if key generation, the public-key
/// lookup or signing fails in custody.
/// Returns [`AccessKeyError::MalformedWrappingPublicKey`] if custody returns a
/// wrapping public key that is not a valid 65-byte uncompressed P-256 point.
/// Returns [`AccessKeyError::SerializationFailed`] if serialization fails.
pub async fn request_access_key(
    key_custody: &impl KeyCustody,
    signing_key: &KeyHandle,
    requester_did: &str,
    context_id: &str,
    clock: &dyn Clock,
) -> Result<AccessKeyRequestResult, AccessKeyError> {
    // Generate a fresh DHKEM(P-256) wrapping keypair inside custody.
    let wrapping_key_handle = key_custody
        .generate_keypair(KeyType::HpkeP256)
        .await
        .map_err(|e| AccessKeyError::Custody(e.into()))?;

    let wrapping_pubkey = key_custody
        .public_key(&wrapping_key_handle)
        .await
        .map_err(|e| AccessKeyError::Custody(e.into()))?;
    let wrapping_pubkey = P256Point::try_from(wrapping_pubkey.as_bytes())
        .map_err(|e| AccessKeyError::MalformedWrappingPublicKey(e.to_string()))?;

    let timestamp = clock.now_secs();

    // Generate cryptographic nonce for replay protection.
    let mut nonce = [0u8; ACCESS_KEY_NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);

    // Sign the request payload.
    let hash = compute_request_hash(
        context_id,
        requester_did,
        timestamp,
        &wrapping_pubkey,
        &nonce,
    )?;

    let signature = key_custody
        .sign(signing_key, &hash)
        .await
        .map_err(|e| AccessKeyError::Custody(e.into()))?;

    let request = AccessKeyRequest {
        requester_did: requester_did.to_owned(),
        context_id: context_id.to_owned(),
        wrapping_pubkey,
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
/// Returns [`AccessKeyError::VerificationFailed`] if the signing public key or
/// signature bytes are malformed. Returns `Ok(false)` if the signature is
/// well-formed but invalid.
pub fn verify_access_key_request(
    request: &AccessKeyRequest,
    requester_public_key: &[u8],
) -> Result<bool, AccessKeyError> {
    let hash = compute_request_hash(
        &request.context_id,
        &request.requester_did,
        request.timestamp,
        &request.wrapping_pubkey,
        &request.nonce,
    )?;
    verify_ed25519_signature(requester_public_key, &hash, &request.signature)
}

/// Validates that an [`AccessKeyRequest`] timestamp is within the
/// freshness window.
///
/// Requests older than `REQUEST_MAX_AGE_SECS` (300s) or more than
/// `REQUEST_MAX_FUTURE_SECS` (30s) in the future are rejected to prevent
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
    if request.timestamp > now_secs.saturating_add(REQUEST_MAX_FUTURE_SECS) {
        return Err(AccessKeyError::StaleRequest);
    }
    let age = now_secs.saturating_sub(request.timestamp);
    if age > REQUEST_MAX_AGE_SECS {
        return Err(AccessKeyError::StaleRequest);
    }
    Ok(())
}

/// Handles an incoming [`AccessKeyRequest`] and seals the access key to it.
///
/// It binds the request to the context this holder serves, verifies the
/// signature against the requester's `#active` key as `key_resolver` resolves
/// it, checks freshness, checks nonce replay, and HPKE-encrypts the access key
/// to the requester's wrapping public key.
///
/// The holder resolves the verification key itself, so a request is accepted
/// only when its signature verifies under the key bound to the DID it claims
/// (spec 09 §9.17.1).
///
/// Returns the serialized [`AccessKeyResponse`] on success.
///
/// # HPKE Assembly
///
/// 1. Generate an ephemeral P-256 keypair (DHKEM(P-256) Encap).
/// 2. ECDH between ephemeral secret and requester's wrapping pubkey.
/// 3. HKDF-SHA256 with info = `"scp-access-key-v1" || BE32(len(context_id)) || context_id || BE32(len(member_did)) || member_did || epoch_bytes`
///    to derive a 16-byte AES-128-GCM encryption key.
/// 4. AES-128-GCM encrypt the access key bytes.
/// 5. Include the ephemeral public key in the response.
///
/// # Errors
///
/// Returns [`AccessKeyError::ContextMismatch`] if the request names a context
/// other than `expected_context_id`.
/// Returns [`AccessKeyError::VerificationFailed`] if the requester DID does
/// not resolve to an `#active` key, or the request signature is invalid or
/// malformed.
/// Returns [`AccessKeyError::StaleRequest`] if the request is too old or
/// too far in the future.
/// Returns [`AccessKeyError::ReplayedNonce`] if the request nonce has been
/// seen before within the expiry window.
/// Returns other variants for HPKE failures.
pub fn handle_access_key_request(
    request: &AccessKeyRequest,
    expected_context_id: &str,
    key_resolver: &KeyResolver,
    access_key: &AccessKey,
    now_secs: u64,
    nonce_dedup: &mut scp_protocol::crypto::sender_keys::NonceDedup,
) -> Result<Vec<u8>, AccessKeyError> {
    // Bind the request to the context this holder serves before any other
    // check, so a request for another context never reaches the seal.
    if request.context_id != expected_context_id {
        return Err(AccessKeyError::ContextMismatch {
            expected: expected_context_id.to_owned(),
            actual: request.context_id.clone(),
        });
    }

    // Resolve the claimed requester's `#active` key; an unresolvable DID
    // fails closed.
    let requester_did = DID(request.requester_did.clone());
    let requester_key = key_resolver(&requester_did, SigningKeyId::Active).ok_or_else(|| {
        AccessKeyError::VerificationFailed(format!(
            "no #active key resolves for requester {}",
            request.requester_did
        ))
    })?;

    // Verify the request signature.
    let valid = verify_access_key_request(request, requester_key.as_bytes())?;
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

    // HPKE seal with access-key-specific info string and AAD binding
    // (RFC 9180 Base mode via the shared hpke core).
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
    let (enc, sealed_vec) =
        hpke::seal(&request.wrapping_pubkey, &info, &aad, access_key.as_bytes())
            .map_err(|e| AccessKeyError::HpkeEncryptionFailed(e.to_string()))?;

    // Convert to fixed-size array. The HPKE seal always returns exactly 48
    // bytes (ciphertext 32 + AES-128-GCM tag 16) for a 32-byte access key;
    // the AEAD nonce is internal per RFC 9180.
    let sealed: [u8; 48] = sealed_vec.try_into().map_err(|v: Vec<u8>| {
        AccessKeyError::HpkeEncryptionFailed(format!(
            "HPKE seal produced {} bytes, expected 48",
            v.len()
        ))
    })?;

    let response = AccessKeyResponse {
        context_id: access_key.context_id().to_owned(),
        member_did: access_key.member_did().to_owned(),
        epoch: access_key.epoch(),
        hpke_sealed_key: sealed,
        ephemeral_pubkey: enc,
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

/// Opens an [`AccessKeyResponse`] using the requester's wrapping key handle
/// inside the [`KeyCustody`] boundary (RFC 9180 HPKE Base mode, §9.17.1).
///
/// The KEM Diffie-Hellman output is computed inside custody via
/// `key_custody.dh_agree(wrapping_key_handle, enc)` so the wrapping private key
/// never leaves the boundary; `pkRm` is fetched via
/// `key_custody.public_key(wrapping_key_handle)`. DHKEM Decap
/// (`ExtractAndExpand(dh, enc || pkRm)`), `KeySchedule_base`, and the AEAD open
/// then complete in software via
/// [`scp_protocol::crypto::hpke::custody::open_with_external_dh`].
///
/// # Errors
///
/// Returns [`AccessKeyError::HpkeDecryptionFailed`] if HPKE open fails
/// (wrong key/`info`/`aad`, tampered `enc`/`ct`) or the recovered plaintext
/// is not exactly 32 bytes. The response's `enc` was validated (§9.5) when it
/// was decoded.
/// Returns [`AccessKeyError::Custody`] if the DH agreement or public-key
/// lookup fails in custody, and [`AccessKeyError::MalformedWrappingPublicKey`]
/// if custody returns a wrapping public key that is not 65 bytes.
pub async fn open_access_key_response(
    key_custody: &impl KeyCustody,
    wrapping_key_handle: &KeyHandle,
    response: &AccessKeyResponse,
) -> Result<AccessKey, AccessKeyError> {
    // Spec 09 §9.16.2 order: `enc` is validated (§9.5) before any key
    // agreement (decoding the `P256Point` validated it), agree on the
    // validated bytes, fetch pkRm for the same handle, then open.
    let enc = hpke::ValidatedEnc::from(response.ephemeral_pubkey);

    // Compute the KEM DH output inside the custody boundary (same handle,
    // same enc — the only sound inputs to open_with_external_dh).
    let dh = key_custody
        .dh_agree(wrapping_key_handle, enc.as_bytes())
        .await
        .map_err(|e| AccessKeyError::Custody(e.into()))?;
    let dh_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(*dh.as_bytes());

    // Fetch pkRm for the same handle (kem_context = enc || pkRm).
    let pk_rm = key_custody
        .public_key(wrapping_key_handle)
        .await
        .map_err(|e| AccessKeyError::Custody(e.into()))?;
    let pk_rm_bytes: [u8; hpke::PUBLIC_KEY_LEN] = pk_rm.as_bytes().try_into().map_err(|_| {
        AccessKeyError::MalformedWrappingPublicKey(format!(
            "wrapping public key must be {} bytes, got {}",
            hpke::PUBLIC_KEY_LEN,
            pk_rm.as_bytes().len()
        ))
    })?;

    // Build context-bound info and AAD (§9.17.1).
    let info = build_hpke_info(&response.context_id, &response.member_did, response.epoch);
    let aad = build_hpke_aad(&response.context_id, &response.member_did, response.epoch);

    let plaintext = Zeroizing::new(
        hpke::custody::open_with_external_dh(
            &dh_bytes,
            &pk_rm_bytes,
            &enc,
            &info,
            &aad,
            &response.hpke_sealed_key,
        )
        .map_err(|e| AccessKeyError::HpkeDecryptionFailed(e.to_string()))?,
    );

    let key_bytes: Zeroizing<[u8; 32]> =
        Zeroizing::new(plaintext.as_slice().try_into().map_err(|_| {
            AccessKeyError::HpkeDecryptionFailed(format!(
                "decrypted key must be 32 bytes, got {}",
                plaintext.len()
            ))
        })?);

    Ok(AccessKey::from_parts(
        *key_bytes,
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
/// Uses the canonical hash construction and the `AccessKeyRequest` field
/// table of §9.5.2, in its order:
/// `SHA-256("SCP-ACCESS-KEY-REQUEST-V1:" || BE32(len(context_id)) || context_id || BE32(len(requester_did)) || requester_did || timestamp_BE || wrapping_pubkey || nonce)`
///
/// `wrapping_pubkey` (65 bytes, a validated DHKEM(P-256) point) and the nonce
/// (`ACCESS_KEY_NONCE_SIZE` = 16 bytes) are fixed-width and carry no length
/// prefix; their types make that width a compile-time fact.
fn compute_request_hash(
    context_id: &str,
    requester_did: &str,
    timestamp: u64,
    wrapping_pubkey: &P256Point,
    nonce: &[u8; ACCESS_KEY_NONCE_SIZE],
) -> Result<Vec<u8>, AccessKeyError> {
    use scp_protocol::crypto::canonical::{CanonicalField, canonical_hash};

    canonical_hash(
        "SCP-ACCESS-KEY-REQUEST-V1:",
        &[
            CanonicalField::VarBytes(context_id.as_bytes()),
            CanonicalField::VarBytes(requester_did.as_bytes()),
            CanonicalField::U64(timestamp),
            CanonicalField::RawBytes(wrapping_pubkey.as_bytes()),
            CanonicalField::RawBytes(nonce),
        ],
    )
    .map(|h| h.to_vec())
    .map_err(|e| AccessKeyError::VerificationFailed(format!("canonical hash failed: {e}")))
}

/// Verifies an Ed25519 signature, delegating to the canonical
/// [`scp_crypto::verify_ed25519_signature`].
///
/// Returns `Ok(true)` if the signature is valid, `Ok(false)` if it is
/// well-formed but invalid, or `Err` if the inputs are malformed.
fn verify_ed25519_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, AccessKeyError> {
    match scp_crypto::verify_ed25519_signature(public_key, message, signature) {
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
    use crate::crypto::key_loss_custody::{KeyLoss, KeyLossCustody};
    use scp_protocol::crypto::access_keys::generate_access_key;
    use scp_protocol::crypto::sender_keys::NonceDedup;

    /// A valid wire point, distinct per `seed`.
    fn pt(seed: u8) -> P256Point {
        P256Point::try_from(scp_crypto::p256::testing::valid_uncompressed_point(seed)).unwrap()
    }

    /// A resolver that knows exactly `entries` (DID, `#active` key) and
    /// resolves nothing else.
    fn resolver(entries: &[(&str, ed25519_dalek::VerifyingKey)]) -> KeyResolver {
        let entries: Vec<(String, ed25519_dalek::VerifyingKey)> = entries
            .iter()
            .map(|(did, key)| ((*did).to_owned(), *key))
            .collect();
        std::sync::Arc::new(move |did: &DID, kid: SigningKeyId| {
            if kid != SigningKeyId::Active {
                return None;
            }
            entries
                .iter()
                .find(|(d, _)| d == did.as_ref())
                .map(|(_, key)| *key)
        })
    }

    /// Builds an `AccessKeyRequest` from `requester_did` for `context_id`,
    /// signed by `signer`.
    fn signed_request(
        signer: &ed25519_dalek::SigningKey,
        requester_did: &str,
        context_id: &str,
        wrapping_pubkey: P256Point,
        timestamp: u64,
    ) -> AccessKeyRequest {
        use ed25519_dalek::Signer;
        let mut nonce = [0u8; ACCESS_KEY_NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);
        let hash = compute_request_hash(
            context_id,
            requester_did,
            timestamp,
            &wrapping_pubkey,
            &nonce,
        )
        .unwrap();
        AccessKeyRequest {
            requester_did: requester_did.to_owned(),
            context_id: context_id.to_owned(),
            wrapping_pubkey,
            nonce,
            timestamp,
            signature: signer.sign(&hash).to_bytes().to_vec(),
        }
    }

    /// A requester whose custody no longer holds the signing key fails the
    /// access-key request with the typed custody failure, so a caller sees
    /// key-not-found as `SCP-CRYPTO-4006`.
    #[tokio::test]
    async fn request_access_key_carries_a_destroyed_signing_key_as_key_not_found() {
        use scp_platform::testing::InMemoryKeyCustody;
        let custody = InMemoryKeyCustody::new();
        let signing_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        custody.destroy_key(&signing_key).await.unwrap();
        let err = request_access_key(
            &custody,
            &signing_key,
            "did:dht:alice",
            "ctx-1",
            &scp_clock::SystemClock,
        )
        .await
        .expect_err("signing under a destroyed key must fail");
        assert!(
            matches!(&err, AccessKeyError::Custody(failure) if failure.is_key_not_found()),
            "a destroyed signing key is a key-not-found custody failure, got {err:?}"
        );
    }

    fn assert_key_not_found<T: std::fmt::Debug>(result: Result<T, AccessKeyError>, step: &str) {
        let err = result.expect_err(step);
        assert!(
            matches!(&err, AccessKeyError::Custody(failure) if failure.is_key_not_found()),
            "{step}: expected AccessKeyError::Custody key-not-found, got {err:?}"
        );
    }

    async fn request_with(
        custody: &impl KeyCustody,
        signing_key: &KeyHandle,
    ) -> Result<AccessKeyRequestResult, AccessKeyError> {
        request_access_key(
            custody,
            signing_key,
            "did:dht:alice",
            "ctx-1",
            &scp_clock::SystemClock,
        )
        .await
    }

    /// A response whose `enc` is a valid P-256 point, so `open` reaches
    /// both custody calls. The sealed key is never opened by these tests.
    fn response_with_valid_enc() -> AccessKeyResponse {
        let secret = scp_crypto::p256::P256SigningKey::random(&mut OsRng);
        AccessKeyResponse {
            context_id: "ctx-1".to_owned(),
            member_did: "did:dht:alice".to_owned(),
            epoch: 1,
            hpke_sealed_key: [0u8; 48],
            ephemeral_pubkey: P256Point::from(&secret.public_key()),
        }
    }

    #[tokio::test]
    async fn request_access_key_wrapping_key_generation_is_custody_key_not_found() {
        let custody = KeyLossCustody::new(KeyLoss::OnGenerate);
        let signing_key = custody
            .inner
            .generate_keypair(KeyType::Ed25519)
            .await
            .unwrap();
        assert_key_not_found(
            request_with(&custody, &signing_key).await,
            "wrapping key generation",
        );
    }

    #[tokio::test]
    async fn request_access_key_wrapping_public_key_is_custody_key_not_found() {
        let custody = KeyLossCustody::new(KeyLoss::AfterGenerate);
        let signing_key = custody
            .inner
            .generate_keypair(KeyType::Ed25519)
            .await
            .unwrap();
        assert_key_not_found(
            request_with(&custody, &signing_key).await,
            "wrapping public key read",
        );
    }

    #[tokio::test]
    async fn open_access_key_response_with_a_destroyed_wrapping_key_is_custody_key_not_found() {
        let custody = scp_platform::testing::InMemoryKeyCustody::new();
        let wrapping_key = custody.generate_keypair(KeyType::HpkeP256).await.unwrap();
        custody.destroy_key(&wrapping_key).await.unwrap();
        assert_key_not_found(
            open_access_key_response(&custody, &wrapping_key, &response_with_valid_enc()).await,
            "DH agreement",
        );
    }

    #[tokio::test]
    async fn open_access_key_response_wrapping_public_key_is_custody_key_not_found() {
        let custody = KeyLossCustody::new(KeyLoss::AfterDhAgree);
        let wrapping_key = custody.generate_keypair(KeyType::HpkeP256).await.unwrap();
        assert_key_not_found(
            open_access_key_response(&custody, &wrapping_key, &response_with_valid_enc()).await,
            "wrapping public key read after DH agreement",
        );
    }

    // -----------------------------------------------------------------------
    // Wire type serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn access_key_request_serialization_roundtrip() {
        let request = AccessKeyRequest {
            requester_did: "did:dht:alice".to_owned(),
            context_id: "ctx-1".to_owned(),
            wrapping_pubkey: pt(0),
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
            hpke_sealed_key: [0x11; 48],
            ephemeral_pubkey: pt(0),
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
            wrapping_pubkey: pt(42),
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
            hpke_sealed_key: [0x55; 48],
            ephemeral_pubkey: pt(99),
        };
        let bytes = rmp_serde::to_vec(&response).unwrap();
        let deserialized: AccessKeyResponse = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(deserialized.epoch, 10);
        assert_eq!(deserialized.hpke_sealed_key, response.hpke_sealed_key);
    }

    // -----------------------------------------------------------------------
    // HPKE info string tests
    // -----------------------------------------------------------------------

    /// §25.12 Vector 25: the access-key HPKE info string the production
    /// `build_hpke_info` builds from the spec inputs. The member is the
    /// §25.1 fixture identifier hpke member.
    #[test]
    fn spec_25_vector_25_access_key_hpke_info() {
        let info = build_hpke_info(
            "hpke-test-context",
            "scp:4ggxxxop37nk6djtrfoclzjx6s7bi44zcsf6v4qit2zpoctr5tea",
            42,
        );
        assert_eq!(info.len(), 106, "§25.12 Vector 25 length drift");
        assert_eq!(
            hex::encode(&info),
            "7363702d6163636573732d6b65792d76310000001168706b652d746573742d636f6e74657874\
             000000387363703a3467677878786f7033376e6b36646a7472666f636c7a6a78367337626934\
             347a637366367634716974327a706f63747235746561000000000000002a",
            "§25.12 Vector 25 info drift"
        );
    }

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
        // Generate a simulated wrapping keypair (software-held).
        let wrapping_secret = scp_crypto::p256::P256SigningKey::random(&mut OsRng);
        let wrapping_public = wrapping_secret.public_key();

        let access_key = generate_access_key("ctx-1", "did:dht:alice");
        let info = build_hpke_info("ctx-1", "did:dht:alice", 0);
        let aad = build_hpke_aad("ctx-1", "did:dht:alice", 0);

        // Seal via the shared RFC 9180 HPKE core.
        let (enc, sealed) = hpke::seal(
            &P256Point::from(&wrapping_public),
            &info,
            &aad,
            access_key.as_bytes(),
        )
        .unwrap();

        // ct is exactly 48 bytes: 32-byte key + 16-byte AEAD tag.
        assert_eq!(sealed.len(), 48);

        // Open with the software-held secret.
        let plaintext = hpke::open(
            &wrapping_secret.to_scalar_bytes(),
            enc.as_bytes(),
            &info,
            &aad,
            &sealed,
        )
        .unwrap();

        assert_eq!(plaintext.len(), 32);
        assert_eq!(plaintext.as_slice(), access_key.as_bytes());
    }

    #[test]
    fn hpke_seal_produces_ciphertext_plus_tag() {
        let wrapping_secret = scp_crypto::p256::P256SigningKey::random(&mut OsRng);
        let wrapping_public = wrapping_secret.public_key();
        let info = build_hpke_info("ctx-1", "did:dht:alice", 0);
        let aad = build_hpke_aad("ctx-1", "did:dht:alice", 0);

        let key_bytes = [42u8; 32];
        let (_enc, sealed) =
            hpke::seal(&P256Point::from(&wrapping_public), &info, &aad, &key_bytes).unwrap();

        // RFC 9180: ct = plaintext (32) + AEAD tag (16) = 48. No external nonce.
        assert_eq!(sealed.len(), 32 + 16);
    }

    #[test]
    fn hpke_different_info_produces_different_ciphertext() {
        // Sealing the same key under different info strings (different context)
        // must not cross-open: a ciphertext sealed with info_a fails to open
        // with info_b.
        let wrapping_secret = scp_crypto::p256::P256SigningKey::random(&mut OsRng);
        let wrapping_public = wrapping_secret.public_key();
        let info_a = build_hpke_info("ctx-a", "did:dht:alice", 0);
        let aad_a = build_hpke_aad("ctx-a", "did:dht:alice", 0);
        let info_b = build_hpke_info("ctx-b", "did:dht:alice", 0);
        let aad_b = build_hpke_aad("ctx-b", "did:dht:alice", 0);

        let (enc, sealed) = hpke::seal(
            &P256Point::from(&wrapping_public),
            &info_a,
            &aad_a,
            &[42u8; 32],
        )
        .unwrap();

        assert!(
            hpke::open(
                &wrapping_secret.to_scalar_bytes(),
                enc.as_bytes(),
                &info_b,
                &aad_b,
                &sealed
            )
            .is_err(),
            "different info/aad must fail to open"
        );
    }

    // -----------------------------------------------------------------------
    // Request freshness tests
    // -----------------------------------------------------------------------

    #[test]
    fn validate_request_freshness_accepts_recent() {
        let request = AccessKeyRequest {
            requester_did: "did:dht:alice".to_owned(),
            context_id: "ctx-1".to_owned(),
            wrapping_pubkey: pt(0),
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
            wrapping_pubkey: pt(0),
            nonce: [0u8; ACCESS_KEY_NONCE_SIZE],
            timestamp: 1_000_000,
            signature: vec![0u8; 64],
        };
        // At exactly REQUEST_MAX_AGE_SECS (300s) age — still within window.
        assert!(validate_request_freshness(&request, 1_000_300).is_ok());
    }

    #[test]
    fn validate_request_freshness_rejects_stale() {
        let request = AccessKeyRequest {
            requester_did: "did:dht:alice".to_owned(),
            context_id: "ctx-1".to_owned(),
            wrapping_pubkey: pt(0),
            nonce: [0u8; ACCESS_KEY_NONCE_SIZE],
            timestamp: 1_000_000,
            signature: vec![0u8; 64],
        };
        // One second past the 300s window.
        let result = validate_request_freshness(&request, 1_000_301);
        assert!(matches!(result, Err(AccessKeyError::StaleRequest)));
    }

    #[test]
    fn validate_request_freshness_rejects_far_future() {
        let request = AccessKeyRequest {
            requester_did: "did:dht:alice".to_owned(),
            context_id: "ctx-1".to_owned(),
            wrapping_pubkey: pt(0),
            nonce: [0u8; ACCESS_KEY_NONCE_SIZE],
            // Timestamp more than 30s ahead of "now".
            timestamp: 1_000_031,
            signature: vec![0u8; 64],
        };
        let result = validate_request_freshness(&request, 1_000_000);
        assert!(matches!(result, Err(AccessKeyError::StaleRequest)));
    }

    #[test]
    fn validate_request_freshness_accepts_slight_future() {
        // A timestamp within REQUEST_MAX_FUTURE_SECS ahead should be accepted
        // (covers clock skew per §9.14).
        let request = AccessKeyRequest {
            requester_did: "did:dht:alice".to_owned(),
            context_id: "ctx-1".to_owned(),
            wrapping_pubkey: pt(0),
            nonce: [0u8; ACCESS_KEY_NONCE_SIZE],
            timestamp: 1_000_025,
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
            wrapping_pubkey: pt(0),
            nonce: [0u8; ACCESS_KEY_NONCE_SIZE],
            timestamp: 1_000_000,
            signature: vec![0u8; 64],
        };

        // Bob resolves to a key the all-zero signature does not verify under.
        let bob_key = ed25519_dalek::SigningKey::generate(&mut OsRng).verifying_key();
        let result = handle_access_key_request(
            &request,
            "ctx-1",
            &resolver(&[("did:dht:bob", bob_key)]),
            &access_key,
            1_000_000,
            &mut nonce_dedup,
        );
        assert!(
            matches!(&result, Err(AccessKeyError::VerificationFailed(m)) if m.contains("signature")),
            "expected a signature failure, got {result:?}"
        );
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
            wrapping_pubkey: pt(0),
            nonce: [0u8; ACCESS_KEY_NONCE_SIZE],
            timestamp: 1_000_000,
            signature: vec![0u8; 64],
        };

        // Will fail on signature first, but validate_request_freshness
        // independently rejects stale (more than REQUEST_MAX_AGE_SECS old):
        let freshness = validate_request_freshness(&request, 1_000_400);
        assert!(matches!(freshness, Err(AccessKeyError::StaleRequest)));

        // And the full handler also rejects (due to sig failure):
        let bob_key = ed25519_dalek::SigningKey::generate(&mut OsRng).verifying_key();
        let result = handle_access_key_request(
            &request,
            "ctx-1",
            &resolver(&[("did:dht:bob", bob_key)]),
            &access_key,
            1_000_100,
            &mut nonce_dedup,
        );
        assert!(result.is_err());
    }

    /// The JSON encoding of an `AccessKeyRequest`, captured before the wrapping
    /// key moved from `Vec<u8>` to a validating point type. The type change
    /// must not change a byte on the wire.
    #[test]
    fn access_key_request_json_encoding_is_unchanged() {
        let request = AccessKeyRequest {
            requester_did: "did:dht:bob".to_owned(),
            context_id: "ctx-golden".to_owned(),
            wrapping_pubkey: pt(9),
            nonce: [0x11; ACCESS_KEY_NONCE_SIZE],
            timestamp: 1_700_000_000,
            signature: vec![0x22; 64],
        };
        let encoded = serde_json::to_vec(&request).expect("encode");
        assert_eq!(hex::encode(&encoded), GOLDEN_ACCESS_KEY_REQUEST_JSON_HEX);
        let decoded: AccessKeyRequest = serde_json::from_slice(&encoded).expect("decode");
        assert_eq!(serde_json::to_vec(&decoded).expect("re-encode"), encoded);
    }

    const GOLDEN_ACCESS_KEY_REQUEST_JSON_HEX: &str = "7b227265717565737465725f646964223a226469643a6468743a626f62222c22636f6e746578745f6964223a226374782d676f6c64656e222c227772617070696e675f7075626b6579223a5b342c36392c37362c37302c3231372c3233392c31392c3134352c3135352c3234322c3136312c3232312c3232342c32302c3135332c3133372c34372c39302c38312c3138392c35362c3230362c36362c3138382c34332c35332c31342c35322c3136342c39352c3131372c37302c3233312c35382c33372c32372c3134332c352c33342c3134362c3136372c34372c3231362c3132332c36352c3136312c35392c34382c3232392c332c38342c3134382c3231332c3138362c3137382c37362c3233362c3230382c37302c3232362c38332c3132312c3133362c3131372c36325d2c226e6f6e6365223a5b31372c31372c31372c31372c31372c31372c31372c31372c31372c31372c31372c31372c31372c31372c31372c31375d2c2274696d657374616d70223a313730303030303030302c227369676e6174757265223a5b33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33345d7d";

    /// §9.5: a wire key that is not a 65-byte uncompressed P-256 point fails
    /// at decode, in the request's `wrapping_pubkey` and the response's
    /// `ephemeral_pubkey` (`enc`), so neither the signature hash, the seal nor
    /// any key agreement reads it. The unmodified encoding is the positive
    /// control.
    #[test]
    fn access_key_wire_points_reject_invalid_encodings_at_decode() {
        let request = serde_json::to_value(AccessKeyRequest {
            requester_did: "did:dht:bob".to_owned(),
            context_id: "ctx-1".to_owned(),
            wrapping_pubkey: pt(3),
            nonce: [0u8; ACCESS_KEY_NONCE_SIZE],
            timestamp: 1_000_000,
            signature: vec![0u8; 64],
        })
        .unwrap();
        let response = serde_json::to_value(AccessKeyResponse {
            context_id: "ctx-1".to_owned(),
            member_did: "did:dht:alice".to_owned(),
            epoch: 1,
            hpke_sealed_key: [0u8; 48],
            ephemeral_pubkey: pt(3),
        })
        .unwrap();
        serde_json::from_value::<AccessKeyRequest>(request.clone()).unwrap();
        serde_json::from_value::<AccessKeyResponse>(response.clone()).unwrap();

        for (case, bad) in scp_crypto::p256::testing::invalid_point_encodings(3) {
            let mut json = request.clone();
            json["wrapping_pubkey"] = serde_json::json!(bad);
            let err = serde_json::from_value::<AccessKeyRequest>(json)
                .unwrap_err()
                .to_string();
            assert!(err.contains("P-256 point"), "request, {case}: {err}");

            let mut json = response.clone();
            json["ephemeral_pubkey"] = serde_json::json!(bad);
            let err = serde_json::from_value::<AccessKeyResponse>(json)
                .unwrap_err()
                .to_string();
            assert!(err.contains("P-256 point"), "response, {case}: {err}");
        }
    }

    /// Spec 09 §9.17.1: a holder answers only requests for the context it
    /// serves. A correctly signed request naming another context is rejected
    /// before any seal; the same request against its own context is the
    /// positive control.
    #[test]
    fn handle_access_key_request_rejects_another_context() {
        let bob = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let resolver = resolver(&[("did:dht:bob", bob.verifying_key())]);
        let access_key = generate_access_key("ctx-1", "did:dht:alice");
        let request = signed_request(&bob, "did:dht:bob", "ctx-other", pt(4), 1_700_000_000);

        let result = handle_access_key_request(
            &request,
            "ctx-1",
            &resolver,
            &access_key,
            1_700_000_000,
            &mut NonceDedup::new(),
        );
        assert!(
            matches!(
                &result,
                Err(AccessKeyError::ContextMismatch { expected, actual })
                    if expected == "ctx-1" && actual == "ctx-other"
            ),
            "expected ContextMismatch, got {result:?}"
        );

        handle_access_key_request(
            &request,
            "ctx-other",
            &resolver,
            &generate_access_key("ctx-other", "did:dht:alice"),
            1_700_000_000,
            &mut NonceDedup::new(),
        )
        .expect("the same request is answered by the context it names");
    }

    /// The holder resolves the verification key from the DID the request
    /// claims. Mallory signing with her own key while claiming to be Bob is
    /// rejected, whatever key she presents; Bob's own request is the positive
    /// control, and a DID that resolves to no key fails closed.
    #[test]
    fn handle_access_key_request_verifies_against_the_claimed_did() {
        let bob = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let mallory = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let resolver = resolver(&[
            ("did:dht:bob", bob.verifying_key()),
            ("did:dht:mallory", mallory.verifying_key()),
        ]);
        let access_key = generate_access_key("ctx-1", "did:dht:alice");

        let forged = signed_request(&mallory, "did:dht:bob", "ctx-1", pt(5), 1_700_000_000);
        let result = handle_access_key_request(
            &forged,
            "ctx-1",
            &resolver,
            &access_key,
            1_700_000_000,
            &mut NonceDedup::new(),
        );
        assert!(
            matches!(&result, Err(AccessKeyError::VerificationFailed(_))),
            "a request Mallory signed claiming Bob must fail, got {result:?}"
        );

        let unknown = signed_request(&bob, "did:dht:carol", "ctx-1", pt(5), 1_700_000_000);
        let result = handle_access_key_request(
            &unknown,
            "ctx-1",
            &resolver,
            &access_key,
            1_700_000_000,
            &mut NonceDedup::new(),
        );
        assert!(
            matches!(&result, Err(AccessKeyError::VerificationFailed(m)) if m.contains("no #active key")),
            "an unresolvable requester must fail closed, got {result:?}"
        );

        let genuine = signed_request(&bob, "did:dht:bob", "ctx-1", pt(5), 1_700_000_000);
        handle_access_key_request(
            &genuine,
            "ctx-1",
            &resolver,
            &access_key,
            1_700_000_000,
            &mut NonceDedup::new(),
        )
        .expect("Bob's own request is answered");
    }

    /// Full HPKE distribution E2E test using real Ed25519 keys and signatures.
    #[test]
    fn hpke_distribution_e2e_with_real_signing() {
        use ed25519_dalek::{Signer, SigningKey};

        let mut nonce_dedup = NonceDedup::new();

        // 1. Generate requester's Ed25519 keypair.
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // 2. Generate a DHKEM(P-256) wrapping keypair for the requester
        //    (software-held so the test can run the software `hpke::open` path).
        let wrapping_secret = scp_crypto::p256::P256SigningKey::random(&mut OsRng);
        let wrapping_public = wrapping_secret.public_key();

        let timestamp = 1_700_000_000_u64;
        let mut nonce = [0u8; ACCESS_KEY_NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);

        // 3. Build and sign the request.
        let hash = compute_request_hash(
            "ctx-1",
            "did:dht:bob",
            timestamp,
            &P256Point::from(&wrapping_public),
            &nonce,
        )
        .unwrap();
        let sig = signing_key.sign(&hash);

        let request = AccessKeyRequest {
            requester_did: "did:dht:bob".to_owned(),
            context_id: "ctx-1".to_owned(),
            wrapping_pubkey: P256Point::from(&wrapping_public),
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
            "ctx-1",
            &resolver(&[("did:dht:bob", verifying_key)]),
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

        // 7. Open the response (requester side) via the software HPKE path.
        // `enc` is the 65-byte DHKEM(P-256) point; the sealed key is 48 bytes.
        assert_eq!(response.ephemeral_pubkey.as_bytes().len(), hpke::ENC_LEN);
        assert_eq!(response.hpke_sealed_key.len(), 48);
        let info = build_hpke_info("ctx-1", "did:dht:alice", 0);
        let aad = build_hpke_aad("ctx-1", "did:dht:alice", 0);
        let plaintext = hpke::open(
            &wrapping_secret.to_scalar_bytes(),
            response.ephemeral_pubkey.as_bytes(),
            &info,
            &aad,
            &response.hpke_sealed_key,
        )
        .unwrap();

        let recovered_bytes: [u8; 32] = plaintext.as_slice().try_into().unwrap();
        assert_eq!(recovered_bytes, original_key_bytes);

        // 8. Replaying the same request should be rejected.
        let replay_result = handle_access_key_request(
            &request,
            "ctx-1",
            &resolver(&[("did:dht:bob", verifying_key)]),
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

        let wrapping_secret = scp_crypto::p256::P256SigningKey::random(&mut OsRng);
        let wrapping_public = wrapping_secret.public_key();

        let timestamp = 1_700_000_000_u64;
        let mut nonce = [0u8; ACCESS_KEY_NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);

        let hash = compute_request_hash(
            "ctx-1",
            "did:dht:bob",
            timestamp,
            &P256Point::from(&wrapping_public),
            &nonce,
        )
        .unwrap();
        let sig = signing_key.sign(&hash);

        let request = AccessKeyRequest {
            requester_did: "did:dht:bob".to_owned(),
            context_id: "ctx-1".to_owned(),
            wrapping_pubkey: P256Point::from(&wrapping_public),
            nonce,
            timestamp,
            signature: sig.to_bytes().to_vec(),
        };

        let access_key = generate_access_key("ctx-1", "did:dht:alice");

        // First request should succeed.
        let result = handle_access_key_request(
            &request,
            "ctx-1",
            &resolver(&[("did:dht:bob", verifying_key)]),
            &access_key,
            timestamp,
            &mut nonce_dedup,
        );
        assert!(result.is_ok());

        // Replay with same nonce should fail.
        let result = handle_access_key_request(
            &request,
            "ctx-1",
            &resolver(&[("did:dht:bob", verifying_key)]),
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

        let hash_a = compute_request_hash("ctx-1", "did:dht:bob", 100, &pt(0), &nonce_a).unwrap();
        let hash_b = compute_request_hash("ctx-1", "did:dht:bob", 100, &pt(0), &nonce_b).unwrap();

        assert_ne!(hash_a, hash_b);
    }

    /// §9.5.2 `AccessKeyRequest` table: the signed preimage is the domain
    /// separator, then `context_id` and `requester_did` (4-byte BE length +
    /// UTF-8), `timestamp` (8-byte BE), the 65-byte wrapping key and the
    /// 16-byte nonce, in that order. Rebuilt here byte by byte from the table,
    /// not through the canonical encoder.
    #[test]
    fn request_hash_matches_spec_field_order() {
        use sha2::{Digest, Sha256};

        let context_id = "ctx-spec";
        let requester_did = "did:dht:requester";
        let timestamp = 1_700_000_000_u64;
        let wrapping_pubkey = pt(5);
        let nonce = [0x5Au8; ACCESS_KEY_NONCE_SIZE];

        let mut preimage = Vec::new();
        preimage.extend_from_slice(b"SCP-ACCESS-KEY-REQUEST-V1:");
        preimage.extend_from_slice(&u32::try_from(context_id.len()).unwrap().to_be_bytes());
        preimage.extend_from_slice(context_id.as_bytes());
        preimage.extend_from_slice(&u32::try_from(requester_did.len()).unwrap().to_be_bytes());
        preimage.extend_from_slice(requester_did.as_bytes());
        preimage.extend_from_slice(&timestamp.to_be_bytes());
        preimage.extend_from_slice(wrapping_pubkey.as_bytes());
        preimage.extend_from_slice(&nonce);
        assert_eq!(preimage.len(), 26 + 4 + 8 + 4 + 17 + 8 + 65 + 16);

        let expected = Sha256::digest(&preimage).to_vec();
        let actual = compute_request_hash(
            context_id,
            requester_did,
            timestamp,
            &wrapping_pubkey,
            &nonce,
        )
        .unwrap();
        assert_eq!(actual, expected, "§9.5.2 AccessKeyRequest preimage drift");
    }

    /// A request built by `request_access_key` (custody-held `HpkeP256`
    /// wrapping key, custody signature) verifies against the signer's public
    /// key, and its wrapping key is a 65-byte uncompressed point.
    #[tokio::test]
    async fn request_access_key_signs_and_verifies() {
        let custody = scp_platform::testing::InMemoryKeyCustody::new();
        let signing_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let signing_pub = custody.public_key(&signing_key).await.unwrap();
        let result = request_with(&custody, &signing_key).await.unwrap();
        let request: AccessKeyRequest = serde_json::from_slice(&result.request_message).unwrap();
        assert_eq!(request.wrapping_pubkey.as_bytes()[0], 0x04);
        assert!(verify_access_key_request(&request, signing_pub.as_bytes()).unwrap());

        let mut tampered = request;
        tampered.timestamp += 1;
        assert!(!verify_access_key_request(&tampered, signing_pub.as_bytes()).unwrap());
    }

    /// Custody round trip: the requester's custody-held `HpkeP256` key opens
    /// what the responder sealed, through the spec 09 §9.16.2 sequence
    /// (validate `enc`, `dh_agree`, `public_key`, open).
    #[tokio::test]
    async fn custody_request_handle_open_round_trip() {
        let custody = crate::crypto::dh_counting_custody::DhCountingCustody::new();
        let signing_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let signing_pub = custody.public_key(&signing_key).await.unwrap();
        let result = request_with(&custody, &signing_key).await.unwrap();
        let request: AccessKeyRequest = serde_json::from_slice(&result.request_message).unwrap();

        let access_key = generate_access_key("ctx-1", "did:dht:alice");
        let mut nonce_dedup = NonceDedup::new();
        let signing_pub =
            ed25519_dalek::VerifyingKey::from_bytes(signing_pub.as_bytes().try_into().unwrap())
                .unwrap();
        let response_bytes = handle_access_key_request(
            &request,
            "ctx-1",
            &resolver(&[("did:dht:alice", signing_pub)]),
            &access_key,
            request.timestamp,
            &mut nonce_dedup,
        )
        .unwrap();
        let response: AccessKeyResponse = serde_json::from_slice(&response_bytes).unwrap();
        assert_eq!(response.hpke_sealed_key.len(), 48);

        let opened = open_access_key_response(&custody, &result.wrapping_key_handle, &response)
            .await
            .unwrap();
        assert_eq!(opened.as_bytes(), access_key.as_bytes());
        assert_eq!(custody.dh_calls(), 1);
    }
}
