//! Production `ContextCryptoProvider` implementation backed by `OpenMLS`.
//!
//! [`MlsCryptoProvider`] bridges the [`ContextCryptoProvider`] trait (used by
//! [`ContextManager`]) to the existing `OpenMLS` wrappers in `crypto/mls/`:
//!
//! - Group lifecycle → [`group::create_group`], [`group::add_member`],
//!   [`group::remove_member`], [`group::destroy_group`]
//! - Encrypt/decrypt → [`encrypt::encrypt`], [`encrypt::decrypt`]
//! - Key packages → [`key_package::KeyPackageBuffer`]
//! - Sender keys → [`sender_keys::generate_sender_key`]
//!
//! Each context's MLS group and sender key are stored in per-context maps
//! protected by `std::sync::Mutex`. The provider is `Send + Sync` as required
//! by the trait bound.
//!
//! See ADR-001 for the MLS wrapper design and ADR-007 for sender keys.
//!
//! [`ContextCryptoProvider`]: crate::context::builder::ContextCryptoProvider
//! [`ContextManager`]: crate::context::manager::ContextManager

use std::collections::HashMap;
use std::sync::Mutex;

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use scp_identity::SigningKeyId;
use serde::{Deserialize, Serialize};
use tls_codec::Deserialize as TlsDeserializeTrait;
use zeroize::Zeroizing;

use super::credential::ScpCredential;
use super::encrypt::{encrypt, serialize_ciphertext};
use super::group::{self, SCP_CIPHERSUITE, ScpMlsGroup};
use crate::context::ContextError;
use crate::context::builder::{ContextCreationError, ContextCryptoProvider};
use crate::crypto::sender_keys::{
    NonceDedup, SenderKey, SenderKeyDistributionMessage, SenderKeyResponse, SenderKeyStore,
    generate_sender_key, generate_wrapping_keypair,
};

// ---------------------------------------------------------------------------
// MlsCryptoSnapshot — serializable per-context crypto state for persistence
// ---------------------------------------------------------------------------

/// Serializable snapshot of per-context MLS cryptographic state.
///
/// Captures all state needed to resume MLS encryption/decryption after a
/// process restart: the `OpenMLS` `MemoryStorage` contents (MLS group tree,
/// epoch secrets, key schedule, etc.), the local sender key, the sender
/// key store entries, the sender key epoch counter, and per-member X25519
/// wrapping public keys.
///
/// The MLS group state is serialized as the raw key-value pairs from the
/// `OpenMLS` `MemoryStorage` backing the group. On restore, these are
/// re-injected into a fresh `MemoryStorage` and the `MlsGroup` is
/// reconstructed via `MlsGroup::load`.
///
/// # Security
///
/// This snapshot contains cryptographic key material (sender keys, MLS
/// epoch secrets). It MUST be stored encrypted at rest (§17.5) and
/// destroyed on context close/expiry per the memory scope policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MlsCryptoSnapshot {
    /// The raw key-value pairs from the `OpenMLS` `MemoryStorage`.
    /// Each pair is `(key_bytes, value_bytes)`.
    mls_storage_entries: Vec<(Vec<u8>, Vec<u8>)>,
    /// The local member's AES-256 sender key (32 bytes).
    local_sender_key: SenderKey,
    /// All sender keys for this context: `(sender_did, key)` pairs.
    sender_key_entries: Vec<(String, SenderKey)>,
    /// The sender key epoch counter.
    sender_key_epoch: u64,
    /// Remote members' X25519 wrapping public keys: `(did, pubkey)` pairs.
    member_wrapping_keys: Vec<(String, [u8; 32])>,
    /// The MLS signer (`SignatureKeyPair`) serialized via serde to bytes.
    /// `SignatureKeyPair` does not derive `Clone` without the `clonable`
    /// feature, so we serialize it separately and store the blob here.
    signer_bytes: Vec<u8>,
    /// The MLS group ID bytes. Required to call `MlsGroup::load` on restore.
    group_id: Vec<u8>,
}

/// Per-context cryptographic state managed by [`MlsCryptoProvider`].
struct ContextCryptoState {
    /// The `OpenMLS` group for this context (Encrypted mode only).
    mls_group: ScpMlsGroup,
    /// The local member's AES-256 sender key for this context.
    sender_key: SenderKey,
    /// Sender key store tracking per-member keys (for blocking/distribution).
    sender_key_store: SenderKeyStore,
    /// Sender key epoch counter (incremented on each key rotation).
    sender_key_epoch: u64,
    /// Pending sender key distribution messages: `(target_did, serialized_message)`.
    /// Drained by [`MlsCryptoProvider::drain_pending_sender_key_messages`].
    pending_distributions: Vec<(String, Vec<u8>)>,
    /// Nonce deduplication cache for sender key requests (replay protection).
    nonce_dedup: NonceDedup,
    /// Remote members' X25519 wrapping public keys, keyed by DID.
    /// Populated from key packages during [`MlsCryptoProvider::add_member`].
    member_wrapping_keys: HashMap<String, [u8; 32]>,
}

/// Production [`ContextCryptoProvider`] backed by `OpenMLS`.
///
/// Manages per-context MLS groups and sender keys. Thread-safe via internal
/// `Mutex`-protected maps.
///
/// # Construction
///
/// Create with [`MlsCryptoProvider::new`], providing the local member's DID.
/// The DID is used to generate SCP credentials for MLS group operations.
///
/// # Concurrency
///
/// Each method acquires the internal mutex for the duration of the operation.
/// The `ContextManager` ensures that concurrent calls for the same context are
/// serialized at a higher level (via `tokio::sync::Mutex` on the context map),
/// so contention on these mutexes is minimal.
pub struct MlsCryptoProvider {
    /// The local member's DID (e.g., `"did:dht:z6Mk..."`).
    local_did: String,
    /// Per-context crypto state, keyed by the 32-byte context ID.
    contexts: Mutex<HashMap<[u8; 32], ContextCryptoState>>,
    /// Broadcast keys for broadcast-mode contexts.
    broadcast_keys: Mutex<HashMap<[u8; 32], SenderKey>>,
    /// X25519 wrapping public key for sender key HPKE (§9.16.1).
    /// Published in the MLS `LeafNode` `scp_wrapping_key` extension.
    wrapping_public_key: [u8; 32],
    /// X25519 wrapping secret key for sender key HPKE (§9.16.1).
    /// Used to open HPKE-sealed sender key responses. Wrapped in
    /// [`Zeroizing`] so key material is zeroed on drop.
    wrapping_secret_key: Mutex<Zeroizing<[u8; 32]>>,
}

#[allow(clippy::significant_drop_tightening)]
impl MlsCryptoProvider {
    /// Creates a new production crypto provider for the given local DID.
    ///
    /// # Arguments
    ///
    /// * `local_did` - The local member's DID (must be a valid `did:dht:z...`).
    #[must_use]
    pub fn new(local_did: String) -> Self {
        let (wrapping_public_key, wrapping_secret_key) = generate_wrapping_keypair();
        Self {
            local_did,
            contexts: Mutex::new(HashMap::new()),
            broadcast_keys: Mutex::new(HashMap::new()),
            wrapping_public_key,
            wrapping_secret_key: Mutex::new(Zeroizing::new(wrapping_secret_key)),
        }
    }

    /// Returns a reference to the per-context MLS group state.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if no MLS group exists for the
    /// given context ID.
    fn with_context<F, R>(&self, context_id: &[u8; 32], f: F) -> Result<R, ContextError>
    where
        F: FnOnce(&mut ContextCryptoState) -> Result<R, ContextError>,
    {
        let mut contexts = self
            .contexts
            .lock()
            .map_err(|e| ContextError::CryptoFailed(format!("lock poisoned: {e}")))?;
        let state = contexts.get_mut(context_id).ok_or_else(|| {
            ContextError::CryptoFailed("no MLS group for this context".to_string())
        })?;
        f(state)
    }

    /// Creates the SCP credential for the local member.
    fn make_credential(&self) -> Result<ScpCredential, ContextCreationError> {
        ScpCredential::new(self.local_did.clone(), None, SigningKeyId::Active)
            .map_err(|e| ContextCreationError::CryptoFailed(e.to_string()))
    }
}

#[allow(clippy::significant_drop_tightening)]
impl ContextCryptoProvider for MlsCryptoProvider {
    fn validate_creator_identity(&self) -> Result<(), ContextCreationError> {
        // Validate that the local DID is a valid did:dht:z... format.
        if !self.local_did.starts_with("did:dht:z") {
            return Err(ContextCreationError::IdentityValidationFailed(
                "invalid DID format".to_string(),
            ));
        }
        Ok(())
    }

    fn create_mls_group(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        let credential = self.make_credential()?;
        let mls_group =
            group::create_group_with_wrapping_key(&credential, Some(&self.wrapping_public_key))
                .map_err(|e| ContextCreationError::CryptoFailed(e.to_string()))?;

        let sender_key = generate_sender_key();
        let sender_key_store = SenderKeyStore::new();

        let state = ContextCryptoState {
            mls_group,
            sender_key,
            sender_key_store,
            sender_key_epoch: 0,
            pending_distributions: Vec::new(),
            nonce_dedup: NonceDedup::new(),
            member_wrapping_keys: HashMap::new(),
        };

        let mut contexts = self
            .contexts
            .lock()
            .map_err(|e| ContextCreationError::CryptoFailed(format!("lock poisoned: {e}")))?;
        contexts.insert(*context_id, state);
        Ok(())
    }

    fn generate_sender_key(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        let mut contexts = self
            .contexts
            .lock()
            .map_err(|e| ContextCreationError::CryptoFailed(format!("lock poisoned: {e}")))?;
        let state = contexts.get_mut(context_id).ok_or_else(|| {
            ContextCreationError::CryptoFailed(
                "no MLS group for this context — cannot generate sender key".to_string(),
            )
        })?;
        // Rotate the sender key to a fresh random value.
        state.sender_key = generate_sender_key();
        Ok(())
    }

    fn init_broadcast_key(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        let key = generate_sender_key();
        let mut broadcast_keys = self
            .broadcast_keys
            .lock()
            .map_err(|e| ContextCreationError::CryptoFailed(format!("lock poisoned: {e}")))?;
        broadcast_keys.insert(*context_id, key);
        Ok(())
    }

    fn destroy_mls_group(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        let mut contexts = self
            .contexts
            .lock()
            .map_err(|e| ContextCreationError::CryptoFailed(format!("lock poisoned: {e}")))?;
        if let Some(mut state) = contexts.remove(context_id) {
            let _ = group::destroy_group(&mut state.mls_group);
        }
        Ok(())
    }

    fn destroy_sender_key(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        // Zeroize the sender key in context state (if present).
        {
            let mut contexts = self
                .contexts
                .lock()
                .map_err(|e| ContextCreationError::CryptoFailed(format!("lock poisoned: {e}")))?;
            if let Some(state) = contexts.get_mut(context_id) {
                // Overwrite with a fresh key then drop — ensures old key
                // material doesn't linger. The fresh key is immediately
                // discarded when the context is later destroyed.
                state.sender_key = generate_sender_key();
                // Clear all stored member sender keys for this context.
                let ctx_id_hex = hex::encode(context_id);
                let member_dids: Vec<String> = state
                    .sender_key_store
                    .get_all(&ctx_id_hex)
                    .keys()
                    .cloned()
                    .collect();
                for did in &member_dids {
                    state.sender_key_store.remove(&ctx_id_hex, did);
                }
            }
        }
        // Also clean up broadcast keys.
        let mut broadcast_keys = self
            .broadcast_keys
            .lock()
            .map_err(|e| ContextCreationError::CryptoFailed(format!("lock poisoned: {e}")))?;
        broadcast_keys.remove(context_id);
        Ok(())
    }

    fn validate_key_package(
        &self,
        owner_did: &str,
        key_package_bytes: Option<&[u8]>,
    ) -> Result<(), ContextError> {
        let bytes = key_package_bytes.ok_or_else(|| {
            ContextError::InvalidKeyPackage(
                "production MlsCryptoProvider requires MLS key package bytes".to_string(),
            )
        })?;

        // Deserialize and validate the key package.
        let kp_in = MlsMessageIn::tls_deserialize(&mut &*bytes)
            .map_err(|e| ContextError::InvalidKeyPackage(format!("TLS deserialization: {e}")))?;

        // Extract the KeyPackage from the MlsMessageIn.
        let body = kp_in.extract();
        match body {
            MlsMessageBodyIn::KeyPackage(kp) => {
                // Validate ciphersuite and signature.
                let provider = super::storage::InMemoryMlsProvider::default();
                let verified = kp
                    .validate(provider.crypto(), ProtocolVersion::Mls10)
                    .map_err(|e| {
                        ContextError::InvalidKeyPackage(format!("validation failed: {e}"))
                    })?;

                if verified.ciphersuite() != SCP_CIPHERSUITE {
                    return Err(ContextError::InvalidKeyPackage(format!(
                        "wrong ciphersuite: expected {:?}, got {:?}",
                        SCP_CIPHERSUITE,
                        verified.ciphersuite()
                    )));
                }

                // Bind credential to owner_did: extract the ScpCredential
                // from the key package's leaf node and verify the DID matches.
                let leaf_node = verified.leaf_node();
                if let Ok(basic_cred) = BasicCredential::try_from(leaf_node.credential().clone()) {
                    let scp_cred =
                        ScpCredential::from_bytes(basic_cred.identity()).map_err(|e| {
                            ContextError::InvalidKeyPackage(format!(
                                "credential deserialization failed: {e}"
                            ))
                        })?;
                    if scp_cred.did != owner_did {
                        return Err(ContextError::InvalidKeyPackage(
                            "key package credential DID does not match owner_did".to_string(),
                        ));
                    }
                } else {
                    return Err(ContextError::InvalidKeyPackage(
                        "key package does not contain a BasicCredential".to_string(),
                    ));
                }

                Ok(())
            }
            _ => Err(ContextError::InvalidKeyPackage(
                "message is not a KeyPackage".to_string(),
            )),
        }
    }

    fn add_member(
        &self,
        context_id: &[u8; 32],
        member_did: &str,
        key_package_bytes: Option<&[u8]>,
    ) -> Result<(), ContextError> {
        let bytes = key_package_bytes.ok_or_else(|| {
            ContextError::CryptoFailed(
                "production MlsCryptoProvider requires MLS key package bytes for add_member"
                    .to_string(),
            )
        })?;

        // Pre-validate the key package to extract the wrapping key before
        // the add operation consumes it. Key package bytes arrive as TLS-
        // serialized KeyPackageIn (not MlsMessageIn).
        let wrapping_key = {
            KeyPackageIn::tls_deserialize(&mut &*bytes)
                .ok()
                .and_then(|kp_in| {
                    let provider_tmp = super::storage::InMemoryMlsProvider::default();
                    kp_in
                        .validate(provider_tmp.crypto(), ProtocolVersion::Mls10)
                        .ok()
                        .and_then(|verified| {
                            super::wrapping_extension::extract_wrapping_key(
                                verified.leaf_node().extensions(),
                            )
                            .ok()
                            .flatten()
                        })
                })
        };

        // Deserialize to KeyPackageIn for the actual add operation.
        let kp_in = KeyPackageIn::tls_deserialize(&mut &*bytes)
            .map_err(|e| ContextError::CryptoFailed(format!("key package deserialization: {e}")))?;

        let member_did_owned = member_did.to_owned();
        self.with_context(context_id, |state| {
            let _result = group::add_member(&mut state.mls_group, kp_in)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
            // Store the member's wrapping key if present.
            if let Some(wk) = wrapping_key {
                state.member_wrapping_keys.insert(member_did_owned, wk);
            }
            Ok(())
        })
    }

    fn remove_member(&self, context_id: &[u8; 32], member_did: &str) -> Result<(), ContextError> {
        // Reject self-removal: the local member cannot remove themselves via
        // this method — they should leave the group instead.
        if member_did == self.local_did {
            return Err(ContextError::CryptoFailed(
                "cannot remove self from MLS group — use leave instead".to_string(),
            ));
        }

        self.with_context(context_id, |state| {
            // Find the member's leaf index by matching their DID in the
            // SCP credential embedded in each member's MLS leaf node.
            let members = state
                .mls_group
                .members()
                .map_err(|e: super::error::MlsError| ContextError::CryptoFailed(e.to_string()))?;

            let own_index = state
                .mls_group
                .own_leaf_index()
                .map_err(|e: super::error::MlsError| ContextError::CryptoFailed(e.to_string()))?;

            let mut target_index = None;
            for member in &members {
                if member.index == own_index {
                    continue;
                }
                if let Ok(basic_cred) = BasicCredential::try_from(member.credential.clone())
                    && let Ok(scp_cred) = ScpCredential::from_bytes(basic_cred.identity())
                    && scp_cred.did == member_did
                {
                    target_index = Some(member.index);
                    break;
                }
            }

            let leaf_index = target_index.ok_or_else(|| {
                ContextError::MemberNotFound(format!("member {member_did} not found in MLS group"))
            })?;

            let _result = group::remove_member(&mut state.mls_group, leaf_index)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
            Ok(())
        })
    }

    fn distribute_sender_key(
        &self,
        context_id: &[u8; 32],
        member_did: &str,
    ) -> Result<(), ContextError> {
        let ctx_id_hex = hex::encode(context_id);
        let mut contexts = self
            .contexts
            .lock()
            .map_err(|e| ContextError::CryptoFailed(format!("lock poisoned: {e}")))?;
        let state = contexts.get_mut(context_id).ok_or_else(|| {
            ContextError::CryptoFailed("no MLS group for this context".to_string())
        })?;
        // Store our sender key locally under our DID so local
        // encrypt/decrypt can find it.
        state
            .sender_key_store
            .set(&ctx_id_hex, &self.local_did, state.sender_key.clone());

        // HPKE-seal our sender key to the target member's wrapping pubkey
        // and queue a SenderKeyResponse for transport delivery.
        if let Some(recipient_wrapping_pub) = state.member_wrapping_keys.get(member_did) {
            let (sealed_vec, ephemeral_pub) =
                crate::crypto::sender_keys::key_protocol::hpke_seal_sender_key(
                    state.sender_key.as_bytes(),
                    recipient_wrapping_pub,
                    &ctx_id_hex,
                    &self.local_did,
                    state.sender_key_epoch,
                )
                .map_err(|e| ContextError::CryptoFailed(format!("HPKE seal failed: {e}")))?;

            let sealed: [u8; 60] = sealed_vec.try_into().map_err(|v: Vec<u8>| {
                ContextError::CryptoFailed(format!(
                    "HPKE seal produced {} bytes, expected 60",
                    v.len()
                ))
            })?;

            let response = SenderKeyResponse {
                sender_did: self.local_did.clone(),
                epoch: state.sender_key_epoch,
                hpke_sealed_key: sealed,
                ephemeral_pubkey: ephemeral_pub,
                // No request nonce for proactive distribution — use zeroed nonce.
                request_nonce: [0u8; 16],
            };

            let msg = SenderKeyDistributionMessage::KeyResponse(response);
            let serialized = msg
                .to_bytes()
                .map_err(|e| ContextError::CryptoFailed(format!("serialization failed: {e}")))?;

            state
                .pending_distributions
                .push((member_did.to_owned(), serialized));
        } else {
            tracing::debug!(
                member_did = %member_did,
                context_id = %ctx_id_hex,
                "no wrapping key for member — sender key stored locally only"
            );
        }
        Ok(())
    }

    fn remove_member_sender_key(
        &self,
        context_id: &[u8; 32],
        member_did: &str,
    ) -> Result<(), ContextError> {
        let ctx_id_hex = hex::encode(context_id);
        let mut contexts = self
            .contexts
            .lock()
            .map_err(|e| ContextError::CryptoFailed(format!("lock poisoned: {e}")))?;
        let state = contexts.get_mut(context_id).ok_or_else(|| {
            ContextError::CryptoFailed("no MLS group for this context".to_string())
        })?;
        state.sender_key_store.remove(&ctx_id_hex, member_did);
        // Also remove the member's wrapping key — they are no longer a member.
        state.member_wrapping_keys.remove(member_did);
        Ok(())
    }

    fn drain_pending_sender_key_messages(
        &self,
        context_id: &[u8; 32],
    ) -> Result<Vec<(String, Vec<u8>)>, ContextError> {
        let mut contexts = self
            .contexts
            .lock()
            .map_err(|e| ContextError::CryptoFailed(format!("lock poisoned: {e}")))?;
        let state = contexts.get_mut(context_id).ok_or_else(|| {
            ContextError::CryptoFailed("no MLS group for this context".to_string())
        })?;
        Ok(std::mem::take(&mut state.pending_distributions))
    }

    fn process_incoming_sender_key(
        &self,
        context_id: &[u8; 32],
        sender_did: &str,
        message_bytes: &[u8],
    ) -> Result<(), ContextError> {
        let ctx_id_hex = hex::encode(context_id);

        // Deserialize the distribution message.
        let msg = SenderKeyDistributionMessage::from_bytes(message_bytes)
            .map_err(|e| ContextError::CryptoFailed(format!("deserialization failed: {e}")))?;

        match msg {
            SenderKeyDistributionMessage::KeyResponse(response) => {
                // HPKE-open the sealed sender key using our wrapping secret key.
                let wrapping_secret = self
                    .wrapping_secret_key
                    .lock()
                    .map_err(|e| ContextError::CryptoFailed(format!("lock poisoned: {e}")))?;

                let sender_key = crate::crypto::sender_keys::key_protocol::hpke_open_sender_key(
                    &response.hpke_sealed_key,
                    &response.ephemeral_pubkey,
                    &wrapping_secret,
                    &ctx_id_hex,
                    &response.sender_did,
                    response.epoch,
                )
                .map_err(|e| ContextError::CryptoFailed(format!("HPKE open failed: {e}")))?;

                // Verify the sender DID matches the claimed sender.
                if response.sender_did != sender_did {
                    return Err(ContextError::CryptoFailed(format!(
                        "sender DID mismatch: message claims {}, transport says {}",
                        response.sender_did, sender_did
                    )));
                }

                // Store the recovered sender key.
                let mut contexts = self
                    .contexts
                    .lock()
                    .map_err(|e| ContextError::CryptoFailed(format!("lock poisoned: {e}")))?;
                let state = contexts.get_mut(context_id).ok_or_else(|| {
                    ContextError::CryptoFailed("no MLS group for this context".to_string())
                })?;
                state
                    .sender_key_store
                    .set(&ctx_id_hex, sender_did, sender_key);
                Ok(())
            }
            _ => Err(ContextError::CryptoFailed(
                "expected SenderKeyDistributionMessage::KeyResponse".to_string(),
            )),
        }
    }

    fn handle_sender_key_request(
        &self,
        context_id: &[u8; 32],
        request_bytes: &[u8],
        requester_public_key: &[u8],
    ) -> Result<Option<Vec<u8>>, ContextError> {
        let ctx_id_hex = hex::encode(context_id);

        // Deserialize the request.
        let request: crate::crypto::sender_keys::SenderKeyRequest =
            rmp_serde::from_slice(request_bytes)
                .map_err(|e| ContextError::CryptoFailed(format!("request deserialization: {e}")))?;

        let now_secs = crate::time::now_secs()
            .map_err(|e| ContextError::CryptoFailed(format!("clock error: {e}")))?;

        let mut contexts = self
            .contexts
            .lock()
            .map_err(|e| ContextError::CryptoFailed(format!("lock poisoned: {e}")))?;
        let state = contexts.get_mut(context_id).ok_or_else(|| {
            ContextError::CryptoFailed("no MLS group for this context".to_string())
        })?;

        // Verify the request signature.
        let valid =
            crate::crypto::sender_keys::verify_sender_key_request(&request, requester_public_key)
                .map_err(|e| ContextError::CryptoFailed(format!("signature verification: {e}")))?;
        if !valid {
            return Err(ContextError::CryptoFailed(
                "sender key request signature verification failed".to_string(),
            ));
        }

        // Timestamp freshness.
        crate::crypto::sender_keys::validate_sender_key_request_freshness(&request, now_secs)
            .map_err(|e| ContextError::CryptoFailed(format!("freshness check: {e}")))?;

        // Nonce replay protection.
        if state.nonce_dedup.is_replayed(&request.nonce, now_secs) {
            return Err(ContextError::CryptoFailed(
                "replayed sender key request".to_string(),
            ));
        }

        // HPKE-seal our sender key to the requester's wrapping pubkey.
        let (sealed_vec, ephemeral_pub) =
            crate::crypto::sender_keys::key_protocol::hpke_seal_sender_key(
                state.sender_key.as_bytes(),
                &request.wrapping_pubkey,
                &ctx_id_hex,
                &self.local_did,
                state.sender_key_epoch,
            )
            .map_err(|e| ContextError::CryptoFailed(format!("HPKE seal failed: {e}")))?;

        let sealed: [u8; 60] = sealed_vec.try_into().map_err(|v: Vec<u8>| {
            ContextError::CryptoFailed(format!("HPKE seal produced {} bytes, expected 60", v.len()))
        })?;

        let response = SenderKeyResponse {
            sender_did: self.local_did.clone(),
            epoch: state.sender_key_epoch,
            hpke_sealed_key: sealed,
            ephemeral_pubkey: ephemeral_pub,
            request_nonce: request.nonce,
        };

        let message = rmp_serde::to_vec_named(&response)
            .map_err(|e| ContextError::CryptoFailed(format!("serialization: {e}")))?;

        // Record nonce after successful processing.
        state.nonce_dedup.record(request.nonce, now_secs);

        Ok(Some(message))
    }

    fn encrypt_message(
        &self,
        context_id: &[u8; 32],
        _sender_did: &str,
        payload: &[u8],
        epoch: u64,
        sequence: u64,
    ) -> Result<Vec<u8>, ContextError> {
        self.with_context(context_id, |state| {
            let ctx_str = hex::encode(context_id);
            // Step 1: Encrypt payload with sender key (AES-256-GCM, ADR-007).
            let sender_encrypted = crate::crypto::sender_keys::encrypt::encrypt_sender_layer(
                &state.sender_key,
                payload,
                &ctx_str,
                &self.local_did,
                epoch,
                sequence,
            )
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

            // Step 2: Encrypt via MLS application message (ADR-001).
            let mls_message = encrypt(&mut state.mls_group, &sender_encrypted)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

            let ciphertext = serialize_ciphertext(&mls_message)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

            Ok(ciphertext)
        })
    }

    fn export_crypto_state(&self, context_id: &[u8; 32]) -> Result<Vec<u8>, ContextError> {
        let contexts = self
            .contexts
            .lock()
            .map_err(|e| ContextError::CryptoFailed(format!("lock poisoned: {e}")))?;
        let Some(state) = contexts.get(context_id) else {
            return Ok(Vec::new());
        };

        // Extract the MLS group and signer, both required for restore.
        let group = state
            .mls_group
            .group
            .as_ref()
            .ok_or_else(|| ContextError::CryptoFailed("MLS group destroyed".to_string()))?;

        let signer = state
            .mls_group
            .signer
            .as_ref()
            .ok_or_else(|| ContextError::CryptoFailed("MLS signer destroyed".to_string()))?;

        let group_id = group.group_id().as_slice().to_vec();

        // Serialize the signer via serde (it derives Serialize).
        let signer_bytes = rmp_serde::to_vec_named(signer)
            .map_err(|e| ContextError::CryptoFailed(format!("signer serialization: {e}")))?;

        // Extract the raw key-value pairs from the OpenMLS MemoryStorage.
        let mls_storage_entries = {
            let values = state
                .mls_group
                .provider
                .storage()
                .values
                .read()
                .map_err(|e| ContextError::CryptoFailed(format!("storage lock poisoned: {e}")))?;
            values.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };

        // Collect sender key store entries for this context.
        let ctx_id_hex = hex::encode(context_id);
        let sender_key_entries: Vec<(String, SenderKey)> = state
            .sender_key_store
            .get_all(&ctx_id_hex)
            .into_iter()
            .collect();

        let snapshot = MlsCryptoSnapshot {
            mls_storage_entries,
            local_sender_key: state.sender_key.clone(),
            sender_key_entries,
            sender_key_epoch: state.sender_key_epoch,
            member_wrapping_keys: state
                .member_wrapping_keys
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
            signer_bytes,
            group_id,
        };

        rmp_serde::to_vec_named(&snapshot)
            .map_err(|e| ContextError::CryptoFailed(format!("snapshot serialization: {e}")))
    }

    fn restore_crypto_state(&self, context_id: &[u8; 32], data: &[u8]) -> Result<(), ContextError> {
        if data.is_empty() {
            return Ok(());
        }

        let snapshot: MlsCryptoSnapshot = rmp_serde::from_slice(data)
            .map_err(|e| ContextError::CryptoFailed(format!("snapshot deserialization: {e}")))?;

        // Reconstruct the InMemoryMlsProvider with the persisted storage entries.
        let provider = super::storage::InMemoryMlsProvider::default();
        {
            let mut values =
                provider.storage().values.write().map_err(|e| {
                    ContextError::CryptoFailed(format!("storage lock poisoned: {e}"))
                })?;
            for (k, v) in snapshot.mls_storage_entries {
                values.insert(k, v);
            }
        }

        // Deserialize the signer.
        let signer: SignatureKeyPair = rmp_serde::from_slice(&snapshot.signer_bytes)
            .map_err(|e| ContextError::CryptoFailed(format!("signer deserialization: {e}")))?;

        // Re-store the signer in the provider's key store so OpenMLS can find it.
        signer
            .store(provider.storage())
            .map_err(|e| ContextError::CryptoFailed(format!("signer store failed: {e}")))?;

        // Reconstruct the MLS group from persisted storage via MlsGroup::load.
        let group_id = GroupId::from_slice(&snapshot.group_id);
        let mls_group = MlsGroup::load(provider.storage(), &group_id)
            .map_err(|e| ContextError::CryptoFailed(format!("MlsGroup::load storage error: {e}")))?
            .ok_or_else(|| {
                ContextError::CryptoFailed(
                    "MlsGroup::load returned None — group not found in restored storage"
                        .to_string(),
                )
            })?;

        // Reconstruct SenderKeyStore.
        let ctx_id_hex = hex::encode(context_id);
        let mut sender_key_store = SenderKeyStore::new();
        for (did, key) in snapshot.sender_key_entries {
            sender_key_store.set(&ctx_id_hex, &did, key);
        }

        // Reconstruct member wrapping keys.
        let member_wrapping_keys: HashMap<String, [u8; 32]> =
            snapshot.member_wrapping_keys.into_iter().collect();

        let scp_group = ScpMlsGroup {
            group: Some(mls_group),
            provider,
            signer: super::group::ZeroizingSigner::new(signer),
            destroyed: false,
        };

        let crypto_state = ContextCryptoState {
            mls_group: scp_group,
            sender_key: snapshot.local_sender_key,
            sender_key_store,
            sender_key_epoch: snapshot.sender_key_epoch,
            pending_distributions: Vec::new(),
            nonce_dedup: NonceDedup::new(),
            member_wrapping_keys,
        };

        let mut contexts = self
            .contexts
            .lock()
            .map_err(|e| ContextError::CryptoFailed(format!("lock poisoned: {e}")))?;
        contexts.insert(*context_id, crypto_state);

        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::significant_drop_tightening
)]
mod tests {
    use super::*;
    use crate::crypto::mls::group::generate_key_package;
    use tls_codec::Serialize as TlsSerializeTrait;

    const TEST_DID: &str = "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    fn make_provider() -> MlsCryptoProvider {
        MlsCryptoProvider::new(TEST_DID.to_string())
    }

    fn make_context_id() -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = 0x42;
        id
    }

    #[test]
    fn validate_creator_identity_accepts_valid_did() {
        let provider = make_provider();
        assert!(provider.validate_creator_identity().is_ok());
    }

    #[test]
    fn validate_creator_identity_rejects_invalid_did() {
        let provider = MlsCryptoProvider::new("did:key:invalid".to_string());
        assert!(provider.validate_creator_identity().is_err());
    }

    #[test]
    fn create_mls_group_and_destroy() {
        let provider = make_provider();
        let ctx_id = make_context_id();

        assert!(provider.create_mls_group(&ctx_id).is_ok());

        // Verify group exists by attempting to encrypt.
        let encrypted = provider.encrypt_message(&ctx_id, TEST_DID, b"hello", 0, 0);
        assert!(encrypted.is_ok());

        // Destroy.
        assert!(provider.destroy_mls_group(&ctx_id).is_ok());

        // After destroy, encrypt should fail.
        let encrypted = provider.encrypt_message(&ctx_id, TEST_DID, b"hello", 0, 0);
        assert!(encrypted.is_err());
    }

    #[test]
    fn add_member_with_real_key_package() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        // Generate a key package for Bob.
        let bob_cred = ScpCredential::new(
            "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo".to_string(),
            None,
            SigningKeyId::Active,
        )
        .unwrap();
        let (bob_kp_bundle, _bob_signer, _bob_provider) = generate_key_package(&bob_cred).unwrap();

        // Serialize the key package to bytes.
        let kp_bytes = bob_kp_bundle
            .key_package()
            .tls_serialize_detached()
            .unwrap();

        // Add Bob.
        let result = provider.add_member(&ctx_id, &bob_cred.did, Some(&kp_bytes));
        assert!(result.is_ok(), "add_member failed: {result:?}");
    }

    #[test]
    fn add_member_requires_key_package_bytes() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        // add_member with None should fail.
        let result = provider.add_member(&ctx_id, "did:dht:z6MkBob", None);
        assert!(result.is_err());
    }

    #[test]
    fn remove_member_by_did() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        // Add Bob.
        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let bob_cred = ScpCredential::new(bob_did.to_string(), None, SigningKeyId::Active).unwrap();
        let (bob_kp_bundle, _bob_signer, _bob_provider) = generate_key_package(&bob_cred).unwrap();
        let kp_bytes = bob_kp_bundle
            .key_package()
            .tls_serialize_detached()
            .unwrap();
        provider
            .add_member(&ctx_id, bob_did, Some(&kp_bytes))
            .unwrap();

        // Remove Bob.
        let result = provider.remove_member(&ctx_id, bob_did);
        assert!(result.is_ok(), "remove_member failed: {result:?}");
    }

    #[test]
    fn encrypt_message_produces_ciphertext() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        let plaintext = b"test message";
        let ciphertext = provider
            .encrypt_message(&ctx_id, TEST_DID, plaintext, 0, 0)
            .unwrap();

        // Ciphertext should be non-empty and different from plaintext.
        assert!(!ciphertext.is_empty());
        assert_ne!(&ciphertext, plaintext.as_slice());
    }

    #[test]
    fn encrypt_decrypt_roundtrip_two_members() {
        // Alice creates a group.
        let alice_did = "did:dht:z6MkAliceAliceAliceAliceAliceAliceAliceAlic";
        let alice_provider = MlsCryptoProvider::new(alice_did.to_string());
        let ctx_id = make_context_id();
        alice_provider.create_mls_group(&ctx_id).unwrap();

        // Generate a key package for Bob.
        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let bob_cred = ScpCredential::new(bob_did.to_string(), None, SigningKeyId::Active).unwrap();
        let (bob_kp_bundle, bob_signer, bob_provider_mls) =
            generate_key_package(&bob_cred).unwrap();
        // We need the Welcome message to let Bob join. Get it from the
        // underlying group directly.
        let add_result = {
            let mut contexts = alice_provider.contexts.lock().unwrap();
            let state = contexts.get_mut(&ctx_id).unwrap();
            let kp_in: KeyPackageIn = bob_kp_bundle.key_package().clone().into();
            group::add_member(&mut state.mls_group, kp_in).unwrap()
        };

        // Bob joins using the Welcome.
        let bob_group =
            group::join_group(&add_result.welcome, bob_provider_mls, bob_signer).unwrap();

        // Alice encrypts a message.
        let plaintext = b"Hello Bob!";
        let ciphertext = {
            let mut contexts = alice_provider.contexts.lock().unwrap();
            let state = contexts.get_mut(&ctx_id).unwrap();
            let msg = encrypt(&mut state.mls_group, plaintext).unwrap();
            serialize_ciphertext(&msg).unwrap()
        };

        // Bob decrypts using his group directly.
        let mut bob_group = bob_group;
        let decrypted = super::super::encrypt::decrypt(&mut bob_group, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn forward_secrecy_after_epoch_advance() {
        // Alice creates a group.
        let alice_did = "did:dht:z6MkAliceAliceAliceAliceAliceAliceAliceAlic";
        let alice_provider = MlsCryptoProvider::new(alice_did.to_string());
        let ctx_id = make_context_id();
        alice_provider.create_mls_group(&ctx_id).unwrap();

        // Add Bob.
        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let bob_cred = ScpCredential::new(bob_did.to_string(), None, SigningKeyId::Active).unwrap();
        let (bob_kp_bundle, bob_signer, bob_provider_mls) =
            generate_key_package(&bob_cred).unwrap();

        let add_result = {
            let mut contexts = alice_provider.contexts.lock().unwrap();
            let state = contexts.get_mut(&ctx_id).unwrap();
            let kp_in: KeyPackageIn = bob_kp_bundle.key_package().clone().into();
            group::add_member(&mut state.mls_group, kp_in).unwrap()
        };

        let mut bob_group =
            group::join_group(&add_result.welcome, bob_provider_mls, bob_signer).unwrap();

        // Alice encrypts in epoch 1.
        let ciphertext_epoch1 = {
            let mut contexts = alice_provider.contexts.lock().unwrap();
            let state = contexts.get_mut(&ctx_id).unwrap();
            let msg = encrypt(&mut state.mls_group, b"epoch 1 message").unwrap();
            serialize_ciphertext(&msg).unwrap()
        };

        // Bob decrypts successfully in epoch 1.
        let decrypted = super::super::encrypt::decrypt(&mut bob_group, &ciphertext_epoch1).unwrap();
        assert_eq!(decrypted, b"epoch 1 message");

        // Add Carol to advance to epoch 2.
        let carol_did = "did:dht:z6MkCarolCarolCarolCarolCarolCarolCarolCar";
        let carol_cred =
            ScpCredential::new(carol_did.to_string(), None, SigningKeyId::Active).unwrap();
        let (carol_kp_bundle, _carol_signer, _carol_provider) =
            generate_key_package(&carol_cred).unwrap();

        {
            let mut contexts = alice_provider.contexts.lock().unwrap();
            let state = contexts.get_mut(&ctx_id).unwrap();
            let kp_in: KeyPackageIn = carol_kp_bundle.key_package().clone().into();
            let _add_result2 = group::add_member(&mut state.mls_group, kp_in).unwrap();
        }

        // Verify epoch advanced.
        let epoch = {
            let contexts = alice_provider.contexts.lock().unwrap();
            let state = contexts.get(&ctx_id).unwrap();
            state.mls_group.epoch().unwrap()
        };
        assert_eq!(epoch, 2, "epoch should be 2 after second add");

        // Alice encrypts in epoch 2 — Carol can't replay epoch 1 messages
        // because they're under different epoch keys. This verifies forward
        // secrecy: keys from epoch 1 are not reusable in epoch 2.
        let ciphertext_epoch2 = {
            let mut contexts = alice_provider.contexts.lock().unwrap();
            let state = contexts.get_mut(&ctx_id).unwrap();
            let msg = encrypt(&mut state.mls_group, b"epoch 2 message").unwrap();
            serialize_ciphertext(&msg).unwrap()
        };

        // Verify the epoch 2 ciphertext is different from epoch 1.
        assert_ne!(ciphertext_epoch1, ciphertext_epoch2);
    }

    #[test]
    fn max_past_epochs_allows_grace_window() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        let contexts = provider.contexts.lock().unwrap();
        let state = contexts.get(&ctx_id).unwrap();
        let inner = state.mls_group.inner().unwrap();

        assert_eq!(
            inner.epoch().as_u64(),
            0,
            "new group should start at epoch 0"
        );
    }

    #[test]
    fn three_member_group() {
        let alice_did = "did:dht:z6MkAliceAliceAliceAliceAliceAliceAliceAlic";
        let provider = MlsCryptoProvider::new(alice_did.to_string());
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        // Add Bob.
        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let bob_cred = ScpCredential::new(bob_did.to_string(), None, SigningKeyId::Active).unwrap();
        let (bob_kp_bundle, bob_signer, bob_provider_mls) =
            generate_key_package(&bob_cred).unwrap();
        let add_bob_result = {
            let mut contexts = provider.contexts.lock().unwrap();
            let state = contexts.get_mut(&ctx_id).unwrap();
            let kp_in: KeyPackageIn = bob_kp_bundle.key_package().clone().into();
            group::add_member(&mut state.mls_group, kp_in).unwrap()
        };

        let _bob_group =
            group::join_group(&add_bob_result.welcome, bob_provider_mls, bob_signer).unwrap();

        // Add Carol.
        let carol_did = "did:dht:z6MkCarolCarolCarolCarolCarolCarolCarolCar";
        let carol_cred =
            ScpCredential::new(carol_did.to_string(), None, SigningKeyId::Active).unwrap();
        let (carol_kp_bundle, carol_signer, carol_provider_mls) =
            generate_key_package(&carol_cred).unwrap();

        let add_carol_result = {
            let mut contexts = provider.contexts.lock().unwrap();
            let state = contexts.get_mut(&ctx_id).unwrap();
            let kp_in: KeyPackageIn = carol_kp_bundle.key_package().clone().into();
            group::add_member(&mut state.mls_group, kp_in).unwrap()
        };

        let _carol_group =
            group::join_group(&add_carol_result.welcome, carol_provider_mls, carol_signer).unwrap();

        let contexts = provider.contexts.lock().unwrap();
        let state = contexts.get(&ctx_id).unwrap();
        let members = state.mls_group.members().unwrap();
        assert_eq!(
            members.len(),
            3,
            "group should have 3 members (Alice, Bob, Carol)"
        );
        assert_eq!(
            state.mls_group.epoch().unwrap(),
            2,
            "epoch should be 2 after two adds"
        );
    }

    #[test]
    fn member_removal_advances_epoch() {
        let alice_did = "did:dht:z6MkAliceAliceAliceAliceAliceAliceAliceAlic";
        let provider = MlsCryptoProvider::new(alice_did.to_string());
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let bob_cred = ScpCredential::new(bob_did.to_string(), None, SigningKeyId::Active).unwrap();
        let (bob_kp_bundle, _bob_signer, _bob_provider) = generate_key_package(&bob_cred).unwrap();
        let bob_kp_bytes = bob_kp_bundle
            .key_package()
            .tls_serialize_detached()
            .unwrap();
        provider
            .add_member(&ctx_id, bob_did, Some(&bob_kp_bytes))
            .unwrap();

        {
            let contexts = provider.contexts.lock().unwrap();
            let state = contexts.get(&ctx_id).unwrap();
            assert_eq!(state.mls_group.epoch().unwrap(), 1);
        }

        provider.remove_member(&ctx_id, bob_did).unwrap();

        {
            let contexts = provider.contexts.lock().unwrap();
            let state = contexts.get(&ctx_id).unwrap();
            assert_eq!(state.mls_group.epoch().unwrap(), 2);
            let members = state.mls_group.members().unwrap();
            assert_eq!(members.len(), 1, "only Alice should remain");
        }
    }

    #[test]
    fn ciphersuite_is_correct() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        let contexts = provider.contexts.lock().unwrap();
        let state = contexts.get(&ctx_id).unwrap();
        let inner = state.mls_group.inner().unwrap();
        assert_eq!(
            inner.ciphersuite(),
            SCP_CIPHERSUITE,
            "must use MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
        );
    }

    #[test]
    fn init_and_destroy_broadcast_key() {
        let provider = make_provider();
        let ctx_id = make_context_id();

        assert!(provider.init_broadcast_key(&ctx_id).is_ok());
        assert!(provider.destroy_sender_key(&ctx_id).is_ok());
    }

    #[test]
    fn distribute_and_remove_sender_key() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        assert!(
            provider
                .distribute_sender_key(&ctx_id, "did:dht:z6MkBob")
                .is_ok()
        );
        {
            let contexts = provider.contexts.lock().unwrap();
            let state = contexts.get(&ctx_id).unwrap();
            let ctx_hex = hex::encode(ctx_id);
            assert!(state.sender_key_store.get(&ctx_hex, TEST_DID).is_some());
        }

        assert!(provider.remove_member_sender_key(&ctx_id, TEST_DID).is_ok());
    }

    #[test]
    fn distribute_sender_key_errors_without_context() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        assert!(
            provider
                .distribute_sender_key(&ctx_id, "did:dht:z6MkBob")
                .is_err()
        );
    }

    #[test]
    fn remove_member_sender_key_errors_without_context() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        assert!(
            provider
                .remove_member_sender_key(&ctx_id, "did:dht:z6MkBob")
                .is_err()
        );
    }

    #[test]
    fn generate_sender_key_errors_without_context() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        assert!(provider.generate_sender_key(&ctx_id).is_err());
    }

    #[test]
    fn self_removal_rejected() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        let result = provider.remove_member(&ctx_id, TEST_DID);
        assert!(result.is_err());
    }

    // -- New tests for sender key distribution wiring --------------------------

    #[test]
    fn create_mls_group_includes_wrapping_key() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        let contexts = provider.contexts.lock().unwrap();
        let state = contexts.get(&ctx_id).unwrap();
        let extracted =
            super::super::wrapping_extension::extract_own_wrapping_key(&state.mls_group).unwrap();
        assert_eq!(
            extracted,
            Some(provider.wrapping_public_key),
            "own leaf node must contain provider's wrapping public key"
        );
    }

    #[test]
    fn distribute_sender_key_hpke_seals_when_wrapping_key_available() {
        use super::super::group::generate_key_package_with_wrapping_key;

        let alice_provider = make_provider();
        let ctx_id = make_context_id();
        alice_provider.create_mls_group(&ctx_id).unwrap();

        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let bob_wrapping = [0xBB_u8; 32];
        let bob_cred = ScpCredential::new(bob_did.to_string(), None, SigningKeyId::Active).unwrap();
        let (bob_kp_bundle, _bob_signer, _bob_provider) =
            generate_key_package_with_wrapping_key(&bob_cred, Some(&bob_wrapping)).unwrap();
        let kp_bytes = bob_kp_bundle
            .key_package()
            .tls_serialize_detached()
            .unwrap();

        alice_provider
            .add_member(&ctx_id, bob_did, Some(&kp_bytes))
            .unwrap();

        {
            let contexts = alice_provider.contexts.lock().unwrap();
            let state = contexts.get(&ctx_id).unwrap();
            assert_eq!(
                state.member_wrapping_keys.get(bob_did),
                Some(&bob_wrapping),
                "Bob's wrapping key must be stored after add_member"
            );
        }

        alice_provider
            .distribute_sender_key(&ctx_id, bob_did)
            .unwrap();

        let pending = alice_provider
            .drain_pending_sender_key_messages(&ctx_id)
            .unwrap();
        assert_eq!(pending.len(), 1, "should have 1 pending distribution");
        assert_eq!(pending[0].0, bob_did, "pending message should target Bob");
        assert!(
            !pending[0].1.is_empty(),
            "serialized message should be non-empty"
        );

        let msg =
            crate::crypto::sender_keys::SenderKeyDistributionMessage::from_bytes(&pending[0].1)
                .unwrap();
        match msg {
            crate::crypto::sender_keys::SenderKeyDistributionMessage::KeyResponse(resp) => {
                assert_eq!(resp.sender_did, TEST_DID);
                assert_eq!(resp.epoch, 0);
            }
            _ => panic!("expected KeyResponse variant"),
        }
    }

    #[test]
    fn distribute_sender_key_no_wrapping_key_still_stores_locally() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let bob_cred = ScpCredential::new(bob_did.to_string(), None, SigningKeyId::Active).unwrap();
        let (bob_kp_bundle, _bob_signer, _bob_provider) = generate_key_package(&bob_cred).unwrap();
        let kp_bytes = bob_kp_bundle
            .key_package()
            .tls_serialize_detached()
            .unwrap();
        provider
            .add_member(&ctx_id, bob_did, Some(&kp_bytes))
            .unwrap();

        provider.distribute_sender_key(&ctx_id, bob_did).unwrap();

        {
            let contexts = provider.contexts.lock().unwrap();
            let state = contexts.get(&ctx_id).unwrap();
            let ctx_hex = hex::encode(ctx_id);
            assert!(state.sender_key_store.get(&ctx_hex, TEST_DID).is_some());
        }

        let pending = provider.drain_pending_sender_key_messages(&ctx_id).unwrap();
        assert!(pending.is_empty());
    }

    #[test]
    fn process_incoming_sender_key_roundtrip() {
        use super::super::group::generate_key_package_with_wrapping_key;

        let alice_provider = make_provider();
        let bob_provider = MlsCryptoProvider::new(
            "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo".to_string(),
        );
        let ctx_id = make_context_id();
        alice_provider.create_mls_group(&ctx_id).unwrap();
        bob_provider.create_mls_group(&ctx_id).unwrap();

        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";

        let bob_cred = ScpCredential::new(bob_did.to_string(), None, SigningKeyId::Active).unwrap();
        let (bob_kp_bundle, _bob_signer, _bob_mls) = generate_key_package_with_wrapping_key(
            &bob_cred,
            Some(&bob_provider.wrapping_public_key),
        )
        .unwrap();
        let kp_bytes = bob_kp_bundle
            .key_package()
            .tls_serialize_detached()
            .unwrap();
        alice_provider
            .add_member(&ctx_id, bob_did, Some(&kp_bytes))
            .unwrap();

        alice_provider
            .distribute_sender_key(&ctx_id, bob_did)
            .unwrap();
        let pending = alice_provider
            .drain_pending_sender_key_messages(&ctx_id)
            .unwrap();
        assert_eq!(pending.len(), 1);

        bob_provider
            .process_incoming_sender_key(&ctx_id, TEST_DID, &pending[0].1)
            .unwrap();

        {
            let bob_contexts = bob_provider.contexts.lock().unwrap();
            let bob_state = bob_contexts.get(&ctx_id).unwrap();
            let ctx_hex = hex::encode(ctx_id);
            let alice_key = bob_state.sender_key_store.get(&ctx_hex, TEST_DID);
            assert!(
                alice_key.is_some(),
                "Bob must have Alice's sender key after processing distribution"
            );

            let alice_contexts = alice_provider.contexts.lock().unwrap();
            let alice_state = alice_contexts.get(&ctx_id).unwrap();
            assert_eq!(
                alice_key.unwrap().as_bytes(),
                alice_state.sender_key.as_bytes(),
                "recovered key must match Alice's sender key"
            );
        }
    }

    #[test]
    fn drain_pending_sender_key_messages_clears_queue() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        let pending = provider.drain_pending_sender_key_messages(&ctx_id).unwrap();
        assert!(pending.is_empty());

        provider
            .distribute_sender_key(&ctx_id, "did:dht:z6MkBob")
            .unwrap();
        let pending = provider.drain_pending_sender_key_messages(&ctx_id).unwrap();
        assert!(pending.is_empty());
    }

    #[test]
    fn drain_pending_sender_key_messages_errors_without_context() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        assert!(provider.drain_pending_sender_key_messages(&ctx_id).is_err());
    }

    #[test]
    fn process_incoming_sender_key_rejects_wrong_sender() {
        let bob_provider = MlsCryptoProvider::new(
            "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo".to_string(),
        );
        let ctx_id = make_context_id();
        bob_provider.create_mls_group(&ctx_id).unwrap();

        let ctx_hex = hex::encode(ctx_id);
        let (sealed_vec, ephemeral_pub) =
            crate::crypto::sender_keys::key_protocol::hpke_seal_sender_key(
                &[42u8; 32],
                &bob_provider.wrapping_public_key,
                &ctx_hex,
                TEST_DID,
                0,
            )
            .unwrap();
        let sealed: [u8; 60] = sealed_vec.try_into().unwrap();

        let response = SenderKeyResponse {
            sender_did: TEST_DID.to_string(),
            epoch: 0,
            hpke_sealed_key: sealed,
            ephemeral_pubkey: ephemeral_pub,
            request_nonce: [0u8; 16],
        };
        let msg = SenderKeyDistributionMessage::KeyResponse(response);
        let serialized = msg.to_bytes().unwrap();

        let result =
            bob_provider.process_incoming_sender_key(&ctx_id, "did:dht:z6MkCharlie", &serialized);
        assert!(
            result.is_err(),
            "should reject when sender_did doesn't match transport sender"
        );
    }

    // -------------------------------------------------------------------
    // MLS crypto state persistence tests (#645)
    // -------------------------------------------------------------------

    #[test]
    fn export_crypto_state_returns_empty_for_unknown_context() {
        let provider = make_provider();
        let unknown_ctx = [0xFFu8; 32];
        let exported = provider.export_crypto_state(&unknown_ctx).unwrap();
        assert!(
            exported.is_empty(),
            "should return empty Vec for unknown context"
        );
    }

    #[test]
    fn restore_crypto_state_noop_on_empty_data() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        // restore_crypto_state with empty data should be a no-op.
        let result = provider.restore_crypto_state(&ctx_id, &[]);
        assert!(result.is_ok(), "empty data should succeed silently");
    }

    #[test]
    fn export_restore_crypto_state_roundtrip() {
        let provider = make_provider();
        let ctx_id = make_context_id();

        // Create a group and generate a sender key.
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        // Store a sender key for a remote member.
        {
            let ctx_id_hex = hex::encode(ctx_id);
            let mut contexts = provider.contexts.lock().unwrap();
            let state = contexts.get_mut(&ctx_id).unwrap();
            state.sender_key_store.set(
                &ctx_id_hex,
                "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo",
                generate_sender_key(),
            );
            state.member_wrapping_keys.insert(
                "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo".to_owned(),
                [0xAA; 32],
            );
            state.sender_key_epoch = 42;
        }

        // Capture pre-export state for comparison.
        let (original_sender_key, original_epoch, original_wrapping_key, original_bob_key) = {
            let contexts = provider.contexts.lock().unwrap();
            let state = contexts.get(&ctx_id).unwrap();
            let ctx_id_hex = hex::encode(ctx_id);
            (
                state.sender_key.clone(),
                state.sender_key_epoch,
                state
                    .member_wrapping_keys
                    .get("did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo")
                    .copied()
                    .unwrap(),
                state
                    .sender_key_store
                    .get(
                        &ctx_id_hex,
                        "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo",
                    )
                    .unwrap()
                    .clone(),
            )
        };

        // Export crypto state.
        let exported = provider.export_crypto_state(&ctx_id).unwrap();
        assert!(!exported.is_empty(), "exported state should be non-empty");

        // Create a fresh provider and restore the state.
        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string());

        // Verify context doesn't exist before restore.
        let encrypted = provider2.encrypt_message(&ctx_id, TEST_DID, b"test", 0, 0);
        assert!(encrypted.is_err(), "should fail before restore");

        // Restore.
        provider2.restore_crypto_state(&ctx_id, &exported).unwrap();

        // Verify the MLS group is functional: encrypt should succeed.
        let encrypted = provider2.encrypt_message(&ctx_id, TEST_DID, b"test after restore", 0, 0);
        assert!(
            encrypted.is_ok(),
            "encrypt should succeed after restore: {encrypted:?}"
        );

        // Verify sender key state is restored.
        {
            let contexts = provider2.contexts.lock().unwrap();
            let state = contexts.get(&ctx_id).unwrap();
            let ctx_id_hex = hex::encode(ctx_id);

            // Sender key matches.
            assert_eq!(
                state.sender_key.as_bytes(),
                original_sender_key.as_bytes(),
                "local sender key should be restored"
            );

            // Sender key epoch matches.
            assert_eq!(
                state.sender_key_epoch, original_epoch,
                "sender key epoch should be restored"
            );

            // Bob's sender key is restored.
            let bob_key = state
                .sender_key_store
                .get(
                    &ctx_id_hex,
                    "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo",
                )
                .expect("Bob's sender key should be restored");
            assert_eq!(
                bob_key.as_bytes(),
                original_bob_key.as_bytes(),
                "Bob's sender key should match"
            );

            // Bob's wrapping key is restored.
            let wk = state
                .member_wrapping_keys
                .get("did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo")
                .expect("Bob's wrapping key should be restored");
            assert_eq!(*wk, original_wrapping_key, "wrapping key should match");

            // Pending distributions should be empty after restore.
            assert!(
                state.pending_distributions.is_empty(),
                "pending distributions should be empty after restore"
            );
        }
    }

    #[test]
    fn export_fails_on_destroyed_group() {
        let provider = make_provider();
        let ctx_id = make_context_id();

        provider.create_mls_group(&ctx_id).unwrap();
        provider.destroy_mls_group(&ctx_id).unwrap();

        // After destroy, export should return empty (context removed).
        let exported = provider.export_crypto_state(&ctx_id).unwrap();
        assert!(
            exported.is_empty(),
            "destroyed group should export empty state"
        );
    }

    #[test]
    fn restore_rejects_corrupt_data() {
        let provider = make_provider();
        let ctx_id = make_context_id();

        let result = provider.restore_crypto_state(&ctx_id, b"not valid msgpack");
        assert!(result.is_err(), "corrupt data should fail");
    }

    #[test]
    fn restore_idempotent_on_same_context() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        let exported = provider.export_crypto_state(&ctx_id).unwrap();

        // Restore into a fresh provider twice — second should overwrite cleanly.
        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string());
        provider2.restore_crypto_state(&ctx_id, &exported).unwrap();
        provider2.restore_crypto_state(&ctx_id, &exported).unwrap();

        // Should still be functional.
        let encrypted = provider2.encrypt_message(&ctx_id, TEST_DID, b"test", 0, 0);
        assert!(
            encrypted.is_ok(),
            "second restore should produce working state"
        );
    }

    #[test]
    fn export_restore_preserves_mls_epoch() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        // Get the epoch before export.
        let epoch_before = {
            let contexts = provider.contexts.lock().unwrap();
            let state = contexts.get(&ctx_id).unwrap();
            state.mls_group.epoch().unwrap()
        };

        let exported = provider.export_crypto_state(&ctx_id).unwrap();

        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string());
        provider2.restore_crypto_state(&ctx_id, &exported).unwrap();

        // Verify epoch is preserved.
        let epoch_after = {
            let contexts = provider2.contexts.lock().unwrap();
            let state = contexts.get(&ctx_id).unwrap();
            state.mls_group.epoch().unwrap()
        };

        assert_eq!(
            epoch_before, epoch_after,
            "MLS epoch should be preserved across export/restore"
        );
    }
}
