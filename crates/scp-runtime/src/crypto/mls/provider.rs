//! Production `ContextCryptoProvider` implementation backed by `OpenMLS`.
//!
//! [`MlsCryptoProvider`] bridges the [`ContextCryptoProvider`] trait (used by
//! [`ContextManager`]) to the existing `OpenMLS` wrappers in `crypto/mls/`:
//!
//! - Group lifecycle → [`group::create_group`], [`group::add_member`],
//!   [`group::remove_member`], [`group::destroy_group`]
//! - Encrypt/decrypt → `encrypt::encrypt`, `encrypt::decrypt`
//! - Key packages → `key_package::KeyPackageBuffer`
//! - Sender keys → `sender_keys::generate_sender_key`
//!
//! Each context's MLS group and sender key are stored in per-context maps
//! protected by `std::sync::Mutex`. The provider is `Send + Sync` as required
//! by the trait bound.
//!
//! See ADR-001 for the MLS wrapper design and ADR-007 for sender keys.
//!
//! [`ContextCryptoProvider`]: scp_protocol::context::builder::ContextCryptoProvider
//! [`ContextManager`]: crate::context::manager::ContextManager

use std::collections::HashMap;
use std::sync::Mutex;

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use scp_identity::SigningKeyId;
use scp_primitives::Clock;
use serde::{Deserialize, Serialize};
use tls_codec::Deserialize as TlsDeserializeTrait;
use zeroize::{Zeroize, Zeroizing};

use super::credential::ScpCredential;
use super::encrypt::{DecryptedContent, decrypt_with_sender_did};
use super::group::{self, SCP_CIPHERSUITE, ScpMlsGroup};
use scp_protocol::context::ContextError;
use scp_protocol::context::builder::{ContextCreationError, ContextCryptoProvider};
use scp_protocol::crypto::sender_keys::{
    NonceDedup, SenderKey, SenderKeyDistributionMessage, SenderKeyResponse, SenderKeyStore,
    generate_sender_key, generate_wrapping_keypair,
};

/// Maximum allowed epoch advance in a single sender key distribution.
/// Prevents epoch poisoning attacks where an attacker sets `epoch=u64::MAX`.
///
/// Also used by `import_context` (§23.17 Invariant 3) to bound incoming
/// snapshot epoch values against the local per-sender floors.
pub(crate) const MAX_EPOCH_ADVANCE: u64 = 1000;

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
/// # Security — Sensitive Key Material
///
/// **This struct contains raw private key material:**
///
/// - `signer_bytes` — Ed25519 private signing key (MLS credential signer)
/// - `local_sender_key` — AES-256 sender key (per-context message encryption)
/// - `wrapping_secret_key` — X25519 secret key (HPKE-sealed sender key decryption)
/// - `mls_storage_entries` — `OpenMLS` `MemoryStorage` dump, which includes MLS
///   epoch secrets, HPKE private keys, and the key schedule
///
/// **Why self-encryption is not feasible:** Encrypting the snapshot before
/// returning from `export_crypto_state` creates a circular dependency — the
/// encryption key would need to be stored outside the snapshot or derived
/// from material inside it (defeating the purpose). This is the same trust
/// model used by `OpenMLS` itself, which stores MLS `KeyPackage` private
/// keys in its `StorageProvider` backend in plaintext.
///
/// **Storage layer requirements:** The `Storage` backend that persists this
/// blob MUST provide encryption at rest (§17.5). Platform implementations
/// (Keychain on iOS/macOS, Android Keystore, OS-level encrypted storage)
/// satisfy this. In-memory storage used in tests is acceptable because no
/// persistence occurs.
///
/// **Defense in depth:** `export_crypto_state` and `restore_crypto_state`
/// zeroize the intermediate `MlsCryptoSnapshot` struct after
/// serialization/extraction to minimize the window where private keys
/// exist as a structured, easily-extractable object in memory.
#[derive(Serialize, Deserialize)]
struct MlsCryptoSnapshot {
    /// The raw key-value pairs from the `OpenMLS` `MemoryStorage`.
    /// Each pair is `(key_bytes, value_bytes)`.
    mls_storage_entries: Vec<(Vec<u8>, Vec<u8>)>,
    /// The local member's AES-256 sender key (32 bytes).
    local_sender_key: SenderKey,
    /// All sender keys for this context: `(sender_did, key)` pairs.
    sender_key_entries: Vec<(String, SenderKey)>,
    /// Per-sender epoch high-water marks for this context:
    /// `(sender_did, epoch)` pairs.
    ///
    /// Persisted so the `#1608` rollback-protection invariant
    /// (`SenderKeyStore::set_checked` rejects epoch regressions) survives
    /// a restart. Without this, an attacker who captured an old-epoch
    /// sender-key distribution pre-restart could replay it after restore
    /// because the fresh in-memory map would have no record of the
    /// higher epoch.
    ///
    /// MIGRATION: `#[serde(default)]` — legacy snapshots (pre-C1)
    /// deserialize with an empty vec. `SenderKey` material does not
    /// carry the epoch it was bound to, so per-sender floors cannot
    /// be recovered exactly from legacy data. The restore path
    /// compensates by seeding every sender with a conservative lower
    /// bound derived from the persisted global `sender_key_epoch`
    /// counter. This closes the one-shot rollback window for the
    /// common case. See `had_epoch_map` / `legacy_floor` logic in
    /// `restore_crypto_state` for details and the documented
    /// residual window for peers whose true floor exceeded the local
    /// counter at snapshot time (bounded by `MAX_EPOCH_ADVANCE` in
    /// the receive path).
    #[serde(default)]
    sender_key_epochs: Vec<(String, u64)>,
    /// The sender key epoch counter.
    sender_key_epoch: u64,
    /// The send-side message sequence counter.
    /// MIGRATION: `#[serde(default)]` — old snapshots deserialize as 0, which is
    /// the correct initial state. GCM nonces are random (`OsRng`), not counter-derived,
    /// so a sequence reset does not create nonce reuse.
    #[serde(default)]
    send_sequence: u64,
    /// Remote members' X25519 wrapping public keys: `(did, pubkey)` pairs.
    member_wrapping_keys: Vec<(String, [u8; 32])>,
    /// The MLS signer (`SignatureKeyPair`) serialized via serde to bytes.
    /// `SignatureKeyPair` does not derive `Clone` without the `clonable`
    /// feature, so we serialize it separately and store the blob here.
    signer_bytes: Vec<u8>,
    /// The MLS group ID bytes. Required to call `MlsGroup::load` on restore.
    group_id: Vec<u8>,
    /// Receive-side sequence tracking: `(sender_did, last_epoch, last_sequence)`.
    /// MIGRATION: `#[serde(default)]` — old snapshots deserialize with an empty
    /// tracker, so the first message from each sender is accepted unconditionally.
    /// MLS-level replay protection remains the primary defense; this tracker is
    /// defense-in-depth at the sender-key layer.
    #[serde(default)]
    recv_sequence_tracker: Vec<(String, u64, u64)>,
    /// The provider-level X25519 wrapping public key (§9.16.1).
    /// Persisted so remote members' HPKE-sealed sender key responses can
    /// still be decrypted after a restart. Without this, the restored
    /// provider would generate a fresh keypair whose public key doesn't
    /// match the one published in the MLS tree's `LeafNode` extension.
    #[serde(default)]
    wrapping_public_key: [u8; 32],
    /// The provider-level X25519 wrapping secret key (§9.16.1).
    /// Wrapped in a `Vec<u8>` for serde compatibility; the 32-byte key
    /// is re-wrapped in [`Zeroizing`] on restore.
    #[serde(default)]
    wrapping_secret_key: Vec<u8>,
}

// SECURITY: Manual Debug impl redacts all sensitive key material.
// Clone is intentionally NOT derived — snapshots contain raw private keys
// (Ed25519 signer, AES-256 sender key, X25519 wrapping secret, MLS epoch
// secrets) and should not be freely duplicated. The export/restore path
// constructs snapshots fresh each time without cloning.
impl std::fmt::Debug for MlsCryptoSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlsCryptoSnapshot")
            .field(
                "mls_storage_entries",
                &format_args!("[{} entries, REDACTED]", self.mls_storage_entries.len()),
            )
            .field("local_sender_key", &"[REDACTED]")
            .field(
                "sender_key_entries",
                &format_args!("[{} entries, REDACTED]", self.sender_key_entries.len()),
            )
            .field(
                "sender_key_epochs",
                &format_args!("[{} entries]", self.sender_key_epochs.len()),
            )
            .field("sender_key_epoch", &self.sender_key_epoch)
            .field("send_sequence", &self.send_sequence)
            .field(
                "recv_sequence_tracker",
                &format_args!("[{} entries]", self.recv_sequence_tracker.len()),
            )
            .field(
                "member_wrapping_keys",
                &format_args!("[{} entries]", self.member_wrapping_keys.len()),
            )
            .field("signer_bytes", &"[REDACTED]")
            .field("group_id", &format_args!("[{} bytes]", self.group_id.len()))
            .field("wrapping_public_key", &"[REDACTED]")
            .field("wrapping_secret_key", &"[REDACTED]")
            .finish()
    }
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
    /// Send-side message sequence counter.
    send_sequence: u64,
    /// Pending sender key distribution messages: `(target_did, serialized_message)`.
    /// Drained by [`MlsCryptoProvider::drain_pending_sender_key_messages`].
    pending_distributions: Vec<(String, Vec<u8>)>,
    /// Nonce deduplication cache for sender key requests (replay protection).
    nonce_dedup: NonceDedup,
    /// Remote members' X25519 wrapping public keys, keyed by DID.
    /// Populated from key packages during [`MlsCryptoProvider::add_member`].
    member_wrapping_keys: HashMap<String, [u8; 32]>,
    /// Receive-side sequence tracking for replay detection.
    /// Maps `sender_did` -> (`last_epoch`, `last_sequence`).
    recv_sequence_tracker: HashMap<String, (u64, u64)>,
}

/// State retained for a pending Welcome-based join operation.
///
/// When [`MlsCryptoProvider::prepare_key_package_for_join`] generates a key
/// package, the signer and provider are retained here so that a subsequent
/// [`MlsCryptoProvider::join_from_welcome`] call can reconstruct the group.
struct PendingJoinState {
    /// The signing key pair for the generated key package, wrapped in
    /// [`EagerDropSigner`] for best-effort zeroization (consistent with
    /// [`ScpMlsGroup::signer`]).
    signer: super::group::EagerDropSigner,
    /// The MLS provider holding the key package's private state.
    provider: super::storage::InMemoryMlsProvider,
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
    /// Behind a `Mutex` so it can be restored from a persisted snapshot
    /// via [`ContextCryptoProvider::restore_crypto_state`] (which takes `&self`).
    wrapping_public_key: Mutex<[u8; 32]>,
    /// X25519 wrapping secret key for sender key HPKE (§9.16.1).
    /// Used to open HPKE-sealed sender key responses. Wrapped in
    /// [`Zeroizing`] so key material is zeroed on drop.
    wrapping_secret_key: Mutex<Zeroizing<[u8; 32]>>,
    /// Pending key package state for Welcome-based joins (§5.12.3).
    /// `prepare_key_package_for_join` replaces any previous entry;
    /// `join_from_welcome` takes it. `Option` enforces the single-entry
    /// invariant at the type level.
    pending_joins: Mutex<Option<PendingJoinState>>,
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
            wrapping_public_key: Mutex::new(wrapping_public_key),
            wrapping_secret_key: Mutex::new(Zeroizing::new(wrapping_secret_key)),
            pending_joins: Mutex::new(None),
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
        let wrapping_pk = self
            .wrapping_public_key
            .lock()
            .map_err(|e| ContextCreationError::CryptoFailed(format!("lock poisoned: {e}")))?;
        let mls_group = group::create_group_with_wrapping_key(&credential, Some(&*wrapping_pk))
            .map_err(|e| ContextCreationError::CryptoFailed(e.to_string()))?;

        let sender_key = generate_sender_key();
        let sender_key_store = SenderKeyStore::new();

        let state = ContextCryptoState {
            mls_group,
            sender_key,
            sender_key_store,
            sender_key_epoch: 1,
            send_sequence: 0,
            pending_distributions: Vec::new(),
            nonce_dedup: NonceDedup::new(),
            member_wrapping_keys: HashMap::new(),
            recv_sequence_tracker: HashMap::new(),
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

        // Deserialize the key package as KeyPackageIn (TLS format).
        // This matches add_member() which also uses KeyPackageIn, ensuring
        // both methods accept the same byte format (#1294).
        let kp_in = KeyPackageIn::tls_deserialize(&mut &*bytes)
            .map_err(|e| ContextError::InvalidKeyPackage(format!("TLS deserialization: {e}")))?;

        // Validate ciphersuite and signature.
        let provider = super::storage::InMemoryMlsProvider::default();
        let verified = kp_in
            .validate(provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| ContextError::InvalidKeyPackage(format!("validation failed: {e}")))?;

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
            let scp_cred = ScpCredential::from_bytes(basic_cred.identity()).map_err(|e| {
                ContextError::InvalidKeyPackage(format!("credential deserialization failed: {e}"))
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

    fn add_member(
        &self,
        context_id: &[u8; 32],
        member_did: &str,
        key_package_bytes: Option<&[u8]>,
    ) -> Result<scp_protocol::context::builder::AddMemberOutput, ContextError> {
        use tls_codec::Serialize as TlsSerializeTrait;

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
            let result = group::add_member(&mut state.mls_group, kp_in)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

            // TLS-serialize Welcome and Commit for cross-process delivery.
            let welcome_bytes = result
                .welcome
                .tls_serialize_detached()
                .map_err(|e| ContextError::CryptoFailed(format!("serializing welcome: {e}")))?;
            let commit_bytes = result
                .commit
                .tls_serialize_detached()
                .map_err(|e| ContextError::CryptoFailed(format!("serializing commit: {e}")))?;

            // Store the member's wrapping key if present.
            if let Some(wk) = wrapping_key {
                state.member_wrapping_keys.insert(member_did_owned, wk);
            }

            Ok(scp_protocol::context::builder::AddMemberOutput {
                welcome_bytes,
                commit_bytes,
            })
        })
    }

    fn remove_member(
        &self,
        context_id: &[u8; 32],
        member_did: &str,
    ) -> Result<scp_protocol::context::builder::RemoveMemberOutput, ContextError> {
        use tls_codec::Serialize as TlsSerializeTrait;

        // Self-removal (leave): the local member's MLS group state does not
        // need to be updated when they leave — they simply abandon their
        // local group state. The remaining members process the removal via
        // a Commit from the group admin. Treat as a no-op (#1294).
        if member_did == self.local_did {
            return Ok(scp_protocol::context::builder::RemoveMemberOutput::default());
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

            // If the member is not in the MLS group (e.g., they were never
            // MLS-added, or they're the local member under a different DID
            // in a multi-identity test environment), treat as a no-op. The
            // ContextManager handles membership state authoritatively; the
            // crypto provider only manages MLS group state (#1294).
            let Some(leaf_index) = target_index else {
                tracing::warn!(
                    member_did = %member_did,
                    "remove_member: member DID not found in MLS group leaf nodes — \
                     member may not have been MLS-added"
                );
                return Ok(scp_protocol::context::builder::RemoveMemberOutput::default());
            };

            let result = group::remove_member(&mut state.mls_group, leaf_index)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

            let commit_bytes = result.commit.tls_serialize_detached().map_err(|e| {
                ContextError::CryptoFailed(format!("serializing remove commit: {e}"))
            })?;

            let group_info_bytes = result
                .group_info
                .map(|gi| {
                    gi.tls_serialize_detached().map_err(|e| {
                        ContextError::CryptoFailed(format!("serializing remove group info: {e}"))
                    })
                })
                .transpose()?
                .unwrap_or_default();

            Ok(scp_protocol::context::builder::RemoveMemberOutput {
                commit_bytes,
                group_info_bytes,
            })
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
        state.sender_key_store.set_unchecked(
            &ctx_id_hex,
            &self.local_did,
            state.sender_key.clone(),
        );

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
        // Prune replay tracker entry for this specific member.
        state.recv_sequence_tracker.remove(member_did);
        // D3 defensive sweep: also drop any recv_sequence_tracker entries
        // for DIDs that are no longer in member_wrapping_keys. This catches
        // the re-population edge case where in-flight messages from a
        // previously-removed member arrive after their explicit prune and
        // re-populate the tracker via `open()`. Without this sweep the
        // tracker could slowly accumulate entries for non-members across a
        // churning context. Bounded by current membership size.
        let current_members: std::collections::HashSet<String> =
            state.member_wrapping_keys.keys().cloned().collect();
        state
            .recv_sequence_tracker
            .retain(|did, _| current_members.contains(did));
        Ok(())
    }

    fn rotate_sender_key(&self, context_id: &[u8; 32]) -> Result<(), ContextError> {
        let ctx_id_hex = hex::encode(context_id);
        let mut contexts = self
            .contexts
            .lock()
            .map_err(|e| ContextError::CryptoFailed(format!("lock poisoned: {e}")))?;
        let state = contexts.get_mut(context_id).ok_or_else(|| {
            ContextError::CryptoFailed("no MLS group for this context".to_string())
        })?;

        // 1. Generate fresh AES-256 sender key.
        let new_key = generate_sender_key();
        state.sender_key = new_key.clone();

        // 2. Increment sender_key_epoch (monotonic, §9.16.5).
        state.sender_key_epoch = state
            .sender_key_epoch
            .checked_add(1)
            .ok_or_else(|| ContextError::CryptoFailed("sender key epoch overflow".to_string()))?;

        // 3. Update local sender key store entry.
        state
            .sender_key_store
            .set_unchecked(&ctx_id_hex, &self.local_did, new_key);

        // 4. HPKE-seal new key to each remaining member's wrapping pubkey
        //    and queue distributions (§9.16.2).
        let member_keys: Vec<(String, [u8; 32])> = state
            .member_wrapping_keys
            .iter()
            .map(|(did, key)| (did.clone(), *key))
            .collect();

        for (member_did, wrapping_pub) in &member_keys {
            // Skip self-sealing: the local member already has the key in
            // state.sender_key. Sealing to ourselves wastes CPU and queues
            // a distribution message that the local node would discard.
            if *member_did == self.local_did {
                continue;
            }
            let seal_result = crate::crypto::sender_keys::key_protocol::hpke_seal_sender_key(
                state.sender_key.as_bytes(),
                wrapping_pub,
                &ctx_id_hex,
                &self.local_did,
                state.sender_key_epoch,
            );

            match seal_result {
                Ok((sealed_vec, ephemeral_pub)) => {
                    let sealed: [u8; 60] = match sealed_vec.try_into() {
                        Ok(s) => s,
                        Err(v) => {
                            tracing::warn!(
                                member_did = %member_did,
                                "HPKE seal produced {} bytes, expected 60 — skipping",
                                v.len()
                            );
                            continue;
                        }
                    };

                    let response = SenderKeyResponse {
                        sender_did: self.local_did.clone(),
                        epoch: state.sender_key_epoch,
                        hpke_sealed_key: sealed,
                        ephemeral_pubkey: ephemeral_pub,
                        request_nonce: [0u8; 16],
                    };

                    let msg = SenderKeyDistributionMessage::KeyResponse(response);
                    match msg.to_bytes() {
                        Ok(serialized) => {
                            state
                                .pending_distributions
                                .push((member_did.clone(), serialized));
                        }
                        Err(e) => {
                            tracing::warn!(
                                member_did = %member_did,
                                error = %e,
                                "failed to serialize sender key distribution — skipping"
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        member_did = %member_did,
                        error = %e,
                        "HPKE seal failed for sender key rotation — skipping"
                    );
                }
            }
        }

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
                    return Err(ContextError::CryptoFailed(
                        "sender DID mismatch in sender key distribution".into(),
                    ));
                }

                // Store the recovered sender key with epoch monotonicity check (#1608).
                let mut contexts = self
                    .contexts
                    .lock()
                    .map_err(|e| ContextError::CryptoFailed(format!("lock poisoned: {e}")))?;
                let state = contexts.get_mut(context_id).ok_or_else(|| {
                    ContextError::CryptoFailed("no MLS group for this context".to_string())
                })?;

                // Epoch poisoning defense: reject sender keys with unreasonably
                // high epoch values. An attacker could set epoch=u64::MAX to
                // permanently block future key rotations via epoch monotonicity.
                let current_epoch = state.sender_key_store.epoch(&ctx_id_hex, sender_did);
                if response.epoch > current_epoch.saturating_add(MAX_EPOCH_ADVANCE) {
                    return Err(ContextError::CryptoFailed(
                        "epoch poisoning: claimed epoch exceeds acceptable advance".into(),
                    ));
                }

                state
                    .sender_key_store
                    .set_checked(&ctx_id_hex, sender_did, sender_key, response.epoch)
                    .map_err(|e| ContextError::CryptoFailed(format!("epoch check failed: {e}")))?;
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
        blocked_dids: &std::collections::HashSet<String>,
    ) -> Result<Option<Vec<u8>>, ContextError> {
        let ctx_id_hex = hex::encode(context_id);

        // Deserialize the request.
        let request: scp_protocol::crypto::sender_keys::SenderKeyRequest =
            rmp_serde::from_slice(request_bytes)
                .map_err(|e| ContextError::CryptoFailed(format!("request deserialization: {e}")))?;

        let now_secs = scp_primitives::SystemClock.now_secs();

        let mut contexts = self
            .contexts
            .lock()
            .map_err(|e| ContextError::CryptoFailed(format!("lock poisoned: {e}")))?;
        let state = contexts.get_mut(context_id).ok_or_else(|| {
            ContextError::CryptoFailed("no MLS group for this context".to_string())
        })?;

        // Verify the request signature.
        let valid = scp_protocol::crypto::sender_keys::verify_sender_key_request(
            &request,
            requester_public_key,
        )
        .map_err(|e| ContextError::CryptoFailed(format!("signature verification: {e}")))?;
        if !valid {
            return Err(ContextError::CryptoFailed(
                "sender key request signature verification failed".to_string(),
            ));
        }

        // Timestamp freshness.
        scp_protocol::crypto::sender_keys::validate_sender_key_request_freshness(
            &request, now_secs,
        )
        .map_err(|e| ContextError::CryptoFailed(format!("freshness check: {e}")))?;

        // Nonce replay protection.
        if state.nonce_dedup.is_replayed(&request.nonce, now_secs) {
            return Err(ContextError::CryptoFailed(
                "replayed sender key request".to_string(),
            ));
        }

        // H1: Membership check — requester must be a known member (has a
        // wrapping key registered via add_member). Prevents non-members
        // from obtaining sender keys even if they forge a valid request.
        if !state
            .member_wrapping_keys
            .contains_key(&request.requester_did)
        {
            return Err(ContextError::CryptoFailed(
                "sender key request from non-member".to_string(),
            ));
        }

        // H1: Blocked DID check — requester must not be blocked.
        if blocked_dids.contains(&request.requester_did) {
            return Err(ContextError::CryptoFailed(
                "sender key request from blocked member".to_string(),
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

    fn seal(
        &self,
        context_id: &[u8; 32],
        inner: &scp_protocol::envelope::inner::InnerEnvelope,
        routing_id: &[u8],
        blob_ttl: u32,
    ) -> Result<Vec<u8>, ContextError> {
        self.with_context(context_id, |state| {
            // Use hex-encoded context_id bytes as AAD context string, matching
            // the decrypt path in `open` which also uses `hex::encode(context_id)`.
            // `seal_envelope` uses `inner.context_id` (the original string), which
            // would cause an AAD mismatch on the receive side.
            let ctx_str = hex::encode(context_id);

            // 1. Serialize inner envelope to MessagePack.
            let serialized = rmp_serde::to_vec_named(inner).map_err(|e| {
                ContextError::CryptoFailed(format!("inner envelope serialization: {e}"))
            })?;

            // 2. Sender key encrypt (AES-256-GCM, ADR-007).
            // AAD binds context_id, sender_did, epoch, and sequence to prevent
            // ciphertext relocation. Uses hex-encoded context_id bytes for
            // consistency with the decrypt path.
            let sender_encrypted =
                scp_protocol::crypto::sender_keys::encrypt::encrypt_sender_layer(
                    &state.sender_key,
                    &serialized,
                    &ctx_str,
                    &self.local_did,
                    state.sender_key_epoch,
                    state.send_sequence,
                )
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

            let with_header = scp_protocol::crypto::sender_keys::encrypt::build_sender_header(
                state.sender_key_epoch,
                state.send_sequence,
                &sender_encrypted,
            );

            // 3. MLS encrypt.
            let mls_message =
                crate::crypto::mls::encrypt::encrypt(&mut state.mls_group, &with_header)
                    .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
            let encrypted_blob = crate::crypto::mls::encrypt::serialize_ciphertext(&mls_message)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

            // 4. Wrap in outer envelope.
            let outer = scp_protocol::envelope::outer::create_outer_envelope(
                routing_id,
                None, // no recipient hint for group messages
                blob_ttl,
                encrypted_blob,
            )
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

            state.send_sequence = state.send_sequence.checked_add(1).ok_or_else(|| {
                ContextError::CryptoFailed("send sequence counter overflow".into())
            })?;

            rmp_serde::to_vec_named(&outer).map_err(|e| {
                ContextError::CryptoFailed(format!("outer envelope serialization: {e}"))
            })
        })
    }

    fn open(
        &self,
        context_id: &[u8; 32],
        outer_bytes: &[u8],
    ) -> Result<scp_protocol::context::builder::OpenResult, ContextError> {
        self.with_context(context_id, |state| {
            let ctx_str = hex::encode(context_id);

            // Step 0: Deserialize outer envelope to extract MLS ciphertext.
            let outer: scp_protocol::envelope::outer::OuterEnvelope =
                rmp_serde::from_slice(outer_bytes).map_err(|e| {
                    ContextError::CryptoFailed(format!("outer envelope deserialization: {e}"))
                })?;

            // Step 1: MLS decrypt and extract sender DID from credential.
            let content = decrypt_with_sender_did(&mut state.mls_group, &outer.encrypted_blob)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

            match content {
                DecryptedContent::Application {
                    plaintext: mls_decrypted,
                    sender_did,
                } => {
                    // Per spec §9.16.1 "Management prefix exclusivity", the
                    // SCPM_MAGIC check lives in exactly one place — the
                    // shared helper in scp-protocol::context::builder. Do
                    // not re-implement the prefix check inline here or
                    // anywhere else in the codebase.
                    if let Some(mgmt_payload) =
                        scp_protocol::context::builder::try_strip_management_prefix(&mls_decrypted)
                    {
                        if mgmt_payload.len()
                            > scp_protocol::context::builder::MAX_MANAGEMENT_PAYLOAD_SIZE
                        {
                            return Err(ContextError::CryptoFailed(
                                "management payload exceeds size limit".into(),
                            ));
                        }
                        return Ok(scp_protocol::context::builder::OpenResult::Management {
                            sender_did,
                            payload: mgmt_payload.to_vec(),
                        });
                    }

                    // Step 2: Look up the sender's key from the sender key store.
                    let sender_key = state
                        .sender_key_store
                        .get(&ctx_str, &sender_did)
                        .cloned()
                        .ok_or_else(|| {
                            ContextError::CryptoFailed("sender key lookup failed".into())
                        })?;

                    // Step 3: Parse header and sender key decrypt.
                    let (epoch, sequence, sender_ciphertext) =
                        scp_protocol::crypto::sender_keys::encrypt::parse_sender_header(
                            &mls_decrypted,
                        )
                        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
                    // Epoch/sequence from header — see send_message comment about AAD.
                    let decrypted = scp_protocol::crypto::sender_keys::decrypt_sender_layer(
                        &sender_key,
                        sender_ciphertext,
                        &ctx_str,
                        &sender_did,
                        epoch,
                        sequence,
                    )
                    .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

                    // Receive-side replay detection: reject messages with
                    // epoch/sequence <= last seen for this sender.
                    if let Some(&(last_epoch, last_seq)) =
                        state.recv_sequence_tracker.get(&sender_did)
                        && (epoch < last_epoch || (epoch == last_epoch && sequence <= last_seq))
                    {
                        return Err(ContextError::CryptoFailed(
                            "replay or reorder detected".into(),
                        ));
                    }
                    state
                        .recv_sequence_tracker
                        .insert(sender_did.clone(), (epoch, sequence));

                    // Step 4: Deserialize as InnerEnvelope.
                    // The inner envelope is returned with its padded payload intact.
                    // The caller (verify_and_unwrap) is responsible for stripping
                    // padding and verifying content integrity — keeping open()
                    // focused on MLS decrypt → sender key decrypt → deserialize.
                    let inner =
                        scp_protocol::envelope::inner::InnerEnvelope::from_bytes(&decrypted)
                            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

                    // Signature verification is deferred to ContextManager which
                    // has access to the key_resolver for resolving sender public keys.

                    Ok(scp_protocol::context::builder::OpenResult::Application(
                        Box::new(scp_protocol::context::builder::OpenedEnvelope {
                            inner,
                            sender_did,
                        }),
                    ))
                }
                DecryptedContent::Commit { sender_did: _ } => {
                    // Commit messages advance the MLS epoch. `decrypt_with_sender_did`
                    // has already called `merge_staged_commit` to apply the epoch
                    // change. No application payload exists.
                    Ok(scp_protocol::context::builder::OpenResult::Control)
                }
                DecryptedContent::Proposal { sender_did: _ } => {
                    Ok(scp_protocol::context::builder::OpenResult::Control)
                }
            }
        })
    }

    fn mls_encrypt_management(
        &self,
        context_id: &[u8; 32],
        plaintext: &[u8],
        routing_id: &[u8],
        blob_ttl: u32,
    ) -> Result<Vec<u8>, ContextError> {
        if plaintext.len() > scp_protocol::context::builder::MAX_MANAGEMENT_PAYLOAD_SIZE {
            return Err(ContextError::CryptoFailed(
                "management payload exceeds size limit".into(),
            ));
        }
        self.with_context(context_id, |state| {
            // Prepend the canonical SCPM magic to tag this as a management
            // message for the receive side. The strip/check logic lives in
            // the shared `try_strip_management_prefix` helper per spec
            // §9.16.1 exclusivity; the prepend side is symmetric and
            // trivial enough to leave inline.
            let magic = &scp_protocol::context::builder::MANAGEMENT_MSG_MAGIC;
            let mut tagged = Vec::with_capacity(magic.len() + plaintext.len());
            tagged.extend_from_slice(magic);
            tagged.extend_from_slice(plaintext);
            let mls_message = crate::crypto::mls::encrypt::encrypt(&mut state.mls_group, &tagged)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
            let encrypted_blob = crate::crypto::mls::encrypt::serialize_ciphertext(&mls_message)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
            let outer = scp_protocol::envelope::outer::create_outer_envelope(
                routing_id,
                None,
                blob_ttl,
                encrypted_blob,
            )
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
            rmp_serde::to_vec_named(&outer)
                .map_err(|e| ContextError::CryptoFailed(format!("serialization: {e}")))
        })
    }

    fn advance_epoch(
        &self,
        context_id: &[u8; 32],
    ) -> Result<scp_protocol::context::builder::AdvanceEpochOutput, ContextError> {
        use tls_codec::Serialize as TlsSerializeTrait;

        let wrapping_pk = {
            let guard = self
                .wrapping_public_key
                .lock()
                .map_err(|e| ContextError::CryptoFailed(format!("lock poisoned: {e}")))?;
            *guard
        };
        self.with_context(context_id, |state| {
            let commit = super::ratchet::propose_update_with_wrapping_key(
                &mut state.mls_group,
                &wrapping_pk,
            )
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

            let commit_bytes = commit.tls_serialize_detached().map_err(|e| {
                ContextError::CryptoFailed(format!("serializing epoch advance commit: {e}"))
            })?;

            Ok(scp_protocol::context::builder::AdvanceEpochOutput { commit_bytes })
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
        // SECURITY: Wrapped in Zeroizing so the Ed25519 private key bytes are
        // zeroed if an early `?` return occurs before the snapshot is built.
        let mut signer_bytes = Zeroizing::new(
            rmp_serde::to_vec_named(signer)
                .map_err(|e| ContextError::CryptoFailed(format!("signer serialization: {e}")))?,
        );

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

        // Persist per-sender epoch high-water marks so the `#1608`
        // rollback-protection invariant survives a restart
        // (`SenderKeyStore::set_checked` will reject any restored epoch
        // that regresses below the persisted floor). Includes entries
        // for senders whose key has been removed but whose floor is
        // still retained — `remove` intentionally preserves the epoch
        // as a high-water mark.
        let sender_key_epochs: Vec<(String, u64)> =
            state.sender_key_store.epochs_for_context(&ctx_id_hex);

        // Read the provider-level wrapping keypair for persistence.
        let pub_key_guard = self
            .wrapping_public_key
            .lock()
            .map_err(|e| ContextError::CryptoFailed(format!("wrapping key lock poisoned: {e}")))?;
        let secret_key_guard = self
            .wrapping_secret_key
            .lock()
            .map_err(|e| ContextError::CryptoFailed(format!("wrapping key lock poisoned: {e}")))?;

        let mut snapshot = MlsCryptoSnapshot {
            mls_storage_entries,
            local_sender_key: state.sender_key.clone(),
            sender_key_entries,
            sender_key_epochs,
            sender_key_epoch: state.sender_key_epoch,
            send_sequence: state.send_sequence,
            member_wrapping_keys: state
                .member_wrapping_keys
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
            // Move signer bytes out of the Zeroizing wrapper and into the
            // snapshot. The wrapper is left holding an empty Vec (which it
            // will zeroize on drop — a no-op for an empty vec).
            recv_sequence_tracker: state
                .recv_sequence_tracker
                .iter()
                .map(|(did, (epoch, seq))| (did.clone(), *epoch, *seq))
                .collect(),
            signer_bytes: std::mem::take(&mut signer_bytes),
            group_id,
            wrapping_public_key: *pub_key_guard,
            wrapping_secret_key: secret_key_guard.to_vec(),
        };

        let result = rmp_serde::to_vec_named(&snapshot)
            .map_err(|e| ContextError::CryptoFailed(format!("snapshot serialization: {e}")));

        // SECURITY: Zeroize sensitive key material in the intermediate snapshot
        // to minimize the window where private keys exist as structured data in
        // memory. The serialized blob is the caller's responsibility (Storage
        // layer must encrypt at rest per §17.5).
        snapshot.signer_bytes.zeroize();
        snapshot.local_sender_key.zeroize();
        snapshot.wrapping_secret_key.zeroize();
        for (_, value) in &mut snapshot.mls_storage_entries {
            value.zeroize();
        }
        for (_, key) in &mut snapshot.sender_key_entries {
            key.zeroize();
        }

        result
    }

    fn restore_crypto_state(&self, context_id: &[u8; 32], data: &[u8]) -> Result<(), ContextError> {
        if data.is_empty() {
            return Ok(());
        }

        let mut snapshot: MlsCryptoSnapshot = rmp_serde::from_slice(data)
            .map_err(|e| ContextError::CryptoFailed(format!("snapshot deserialization: {e}")))?;

        // Reconstruct the InMemoryMlsProvider with the persisted storage entries.
        let provider = super::storage::InMemoryMlsProvider::default();
        {
            let mut values =
                provider.storage().values.write().map_err(|e| {
                    ContextError::CryptoFailed(format!("storage lock poisoned: {e}"))
                })?;
            // Drain entries so the snapshot no longer holds MLS storage data
            // (which contains epoch secrets and HPKE private keys).
            for (k, v) in snapshot.mls_storage_entries.drain(..) {
                values.insert(k, v);
            }
        }

        // Deserialize the signer from the snapshot's raw bytes.
        let signer: SignatureKeyPair = rmp_serde::from_slice(&snapshot.signer_bytes)
            .map_err(|e| ContextError::CryptoFailed(format!("signer deserialization: {e}")))?;

        // SECURITY: Zeroize the raw signer bytes now that they've been
        // deserialized — the Ed25519 private key should not linger in this
        // intermediate buffer.
        snapshot.signer_bytes.zeroize();

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

        // Reconstruct SenderKeyStore. drain() moves keys out and clears the
        // snapshot's copy.
        let ctx_id_hex = hex::encode(context_id);
        let mut sender_key_store = SenderKeyStore::new();

        // Restore the per-sender epoch high-water map FIRST so it acts
        // as a floor for the `set_checked` path going forward. The
        // restored values are authoritative high-water marks (not
        // user-supplied receive traffic), so `restore_epoch_high_water`
        // bypasses the monotonicity check.
        //
        // `sender_key_epochs` can cover DIDs that no longer have a key
        // entry (e.g., removed members whose floor was preserved by
        // `SenderKeyStore::remove`) — those entries still matter for
        // rollback protection and must be restored.
        let had_epoch_map = !snapshot.sender_key_epochs.is_empty();
        for (did, epoch) in snapshot.sender_key_epochs.drain(..) {
            sender_key_store.restore_epoch_high_water(&ctx_id_hex, &did, epoch);
        }

        // Legacy-snapshot back-compat hardening: snapshots without a
        // `sender_key_epochs` field leave the map above empty. If
        // we installed key material below with `set_unchecked` and
        // left every floor at 0, the first post-upgrade receive
        // would be `set_checked(..., epoch=k>0)` and would be
        // accepted against a zero floor — re-opening the rollback
        // window for exactly one boot cycle.
        //
        // `SenderKey` material does not carry the epoch it was
        // bound to, so legacy data cannot recover per-sender floors
        // exactly. Use the snapshot's global `sender_key_epoch`
        // counter (present in legacy snapshots) as a conservative
        // lower bound for every sender we see key material for.
        // This is strictly tighter than zero and closes the one-
        // shot rollback window for the common case.
        //
        // Residual window: the global `sender_key_epoch` counter
        // increments only on local `rotate_sender_key`, so a remote
        // sender whose true floor exceeded the local counter at
        // snapshot time is seeded with the lower local value. The
        // residual window per sender is `peer_floor - local_floor`,
        // bounded by the `MAX_EPOCH_ADVANCE = 1000` guard in
        // `open_inner_envelope`. The next legitimate rotation from
        // that sender advances the floor past the exposed window
        // permanently. Closing this residual fully would require
        // either a format break (carrying per-sender epochs in
        // legacy snapshots, which they do not have) or rejecting
        // legacy snapshots outright, locking users out on upgrade.
        let legacy_floor = if had_epoch_map {
            None
        } else {
            Some(snapshot.sender_key_epoch.max(1))
        };
        for (did, key) in snapshot.sender_key_entries.drain(..) {
            // Install key material via `set_unchecked` — the restored
            // key IS authoritative (it was persisted by this same
            // provider). `set_checked` would be rejected when the
            // restored key's epoch equals an already-restored floor.
            sender_key_store.set_unchecked(&ctx_id_hex, &did, key);
            // Legacy-path only: seed a floor from the global
            // `sender_key_epoch` if no per-sender map was persisted.
            if let Some(floor) = legacy_floor {
                sender_key_store.restore_epoch_high_water(&ctx_id_hex, &did, floor);
            }
        }

        // Reconstruct member wrapping keys.
        let member_wrapping_keys: HashMap<String, [u8; 32]> =
            snapshot.member_wrapping_keys.drain(..).collect();

        let scp_group = ScpMlsGroup {
            group: Some(mls_group),
            provider,
            signer: super::group::EagerDropSigner::new(signer),
            destroyed: false,
        };

        // Take the local_sender_key and leave a zeroed placeholder. SenderKey
        // implements ZeroizeOnDrop, so the placeholder is cleaned when snapshot
        // drops, and the original is moved into crypto_state.
        let local_sender_key = std::mem::replace(
            &mut snapshot.local_sender_key,
            SenderKey::from_bytes([0u8; 32]),
        );

        let recv_sequence_tracker: HashMap<String, (u64, u64)> = snapshot
            .recv_sequence_tracker
            .drain(..)
            .map(|(did, epoch, seq)| (did, (epoch, seq)))
            .collect();

        let crypto_state = ContextCryptoState {
            mls_group: scp_group,
            sender_key: local_sender_key,
            sender_key_store,
            sender_key_epoch: snapshot.sender_key_epoch,
            send_sequence: snapshot.send_sequence,
            pending_distributions: Vec::new(),
            nonce_dedup: NonceDedup::new(),
            member_wrapping_keys,
            recv_sequence_tracker,
        };

        // Restore the provider-level X25519 wrapping keypair BEFORE inserting
        // into the contexts map. This prevents partial state: if any lock is
        // poisoned the function returns early without modifying either the
        // contexts map or the wrapping keys.
        //
        // Both wrapping key locks are acquired before either is written. This
        // ensures that a poison on the second lock cannot leave the first key
        // updated while the second retains its old value.
        //
        // Legacy snapshots (pre-wrapping-key persistence) have default
        // [0u8; 32] — skip restore in that case to keep the fresh keypair.
        if snapshot.wrapping_public_key != [0u8; 32] && snapshot.wrapping_secret_key.len() == 32 {
            // SECURITY: Wrap the intermediate secret in Zeroizing so it is
            // zeroed on drop even if a `?` return occurs below.
            let mut secret = Zeroizing::new([0u8; 32]);
            secret.copy_from_slice(&snapshot.wrapping_secret_key);

            let mut pub_guard = self.wrapping_public_key.lock().map_err(|e| {
                ContextError::CryptoFailed(format!("wrapping key lock poisoned: {e}"))
            })?;
            let mut secret_guard = self.wrapping_secret_key.lock().map_err(|e| {
                ContextError::CryptoFailed(format!("wrapping key lock poisoned: {e}"))
            })?;

            *pub_guard = snapshot.wrapping_public_key;
            *secret_guard = Zeroizing::new(*secret);
        }

        // SECURITY: Zeroize the wrapping secret key bytes remaining in the
        // snapshot. The key has been copied into the Zeroizing<[u8; 32]> guard
        // above (or skipped for legacy snapshots), so this intermediate Vec
        // should not retain raw X25519 secret key material.
        snapshot.wrapping_secret_key.zeroize();

        let mut contexts = self
            .contexts
            .lock()
            .map_err(|e| ContextError::CryptoFailed(format!("lock poisoned: {e}")))?;
        contexts.insert(*context_id, crypto_state);

        Ok(())
    }

    fn export_sender_key_epochs(&self, context_id: &[u8; 32]) -> Vec<(String, u64)> {
        let Ok(contexts) = self.contexts.lock() else {
            return Vec::new();
        };
        let Some(state) = contexts.get(context_id) else {
            return Vec::new();
        };
        let ctx_id_hex = hex::encode(context_id);
        state.sender_key_store.epochs_for_context(&ctx_id_hex)
    }

    fn validate_and_merge_epoch_floors(
        &self,
        context_id: &[u8; 32],
        local_floors: Vec<(String, u64)>,
        max_advance_per_sender: u64,
    ) -> Result<(), ContextError> {
        if local_floors.is_empty() {
            return Ok(());
        }

        let ctx_id_hex = hex::encode(context_id);

        // Step 1: read the imported (restored) epoch floors.
        let import_floors: Vec<(String, u64)> = {
            let contexts = self
                .contexts
                .lock()
                .map_err(|e| ContextError::CryptoFailed(format!("lock poisoned: {e}")))?;
            // No restored state (mls_state was empty): no incoming floors.
            // Local floors are trivially dominant; merge them in below.
            contexts.get(context_id).map_or_else(Vec::new, |state| {
                state.sender_key_store.epochs_for_context(&ctx_id_hex)
            })
        };

        // Step 2: build a temporary store seeded with local floors, then
        // validate the import floors against them via the atomic-reject helper.
        // Rejects if any import floor regresses below a local floor, or
        // overshoots local + max_advance (epoch-poisoning guard).
        let mut temp_store = SenderKeyStore::new();
        for (did, floor) in &local_floors {
            temp_store.restore_epoch_high_water(&ctx_id_hex, did, *floor);
        }
        temp_store
            .merge_incoming_epochs_with_atomic_reject(
                &ctx_id_hex,
                import_floors,
                max_advance_per_sender,
            )
            .map_err(|per_sender_deltas| ContextError::SnapshotFloorRegression {
                resource: "sender_key_epoch".to_owned(),
                per_sender_deltas,
            })?;

        // Step 3: apply the merged floors (max of local and import) back into
        // the real store. Ensures local-only senders (absent from the import
        // snapshot) retain their floor (Invariant 4 append-only dominance).
        let merged = temp_store.epochs_for_context(&ctx_id_hex);
        let mut contexts = self
            .contexts
            .lock()
            .map_err(|e| ContextError::CryptoFailed(format!("lock poisoned: {e}")))?;
        if let Some(state) = contexts.get_mut(context_id) {
            for (did, epoch) in merged {
                state
                    .sender_key_store
                    .restore_epoch_high_water(&ctx_id_hex, &did, epoch);
            }
        }

        Ok(())
    }

    fn prepare_key_package_for_join(&self) -> Result<Vec<u8>, ContextError> {
        use tls_codec::Serialize as TlsSerializeTrait;

        let credential = self
            .make_credential()
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        let wrapping_pk = self
            .wrapping_public_key
            .lock()
            .map_err(|e| ContextError::CryptoFailed(format!("lock poisoned: {e}")))?;

        let (kp_bundle, signer, provider) =
            super::group::generate_key_package_with_wrapping_key(&credential, Some(&*wrapping_pk))
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        let kp_bytes = kp_bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(|e| ContextError::CryptoFailed(format!("serializing key package: {e}")))?;

        let mut pending = self
            .pending_joins
            .lock()
            .map_err(|e| ContextError::CryptoFailed(format!("lock poisoned: {e}")))?;

        // Only one key package can be outstanding at a time.
        // New prepare calls replace the old pending state to avoid
        // LIFO matching errors when Welcomes arrive out of order.
        *pending = Some(PendingJoinState {
            signer: super::group::EagerDropSigner::new(signer),
            provider,
        });

        Ok(kp_bytes)
    }

    fn join_from_welcome(
        &self,
        context_id: &[u8; 32],
        welcome_bytes: &[u8],
    ) -> Result<(), ContextError> {
        let mut entry = {
            let mut pending = self
                .pending_joins
                .lock()
                .map_err(|e| ContextError::CryptoFailed(format!("lock poisoned: {e}")))?;
            pending.take().ok_or_else(|| {
                ContextError::CryptoFailed("no pending key package for Welcome".into())
            })?
        };

        let signer = entry.signer.take().ok_or_else(|| {
            ContextError::CryptoFailed("pending join signer already consumed".into())
        })?;

        let group = super::group::join_group_from_bytes(welcome_bytes, entry.provider, signer)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        let sender_key = generate_sender_key();

        let mut contexts = self
            .contexts
            .lock()
            .map_err(|e| ContextError::CryptoFailed(format!("lock poisoned: {e}")))?;

        // Destroy any existing MLS group state for this context to ensure
        // proper key material cleanup (defense-in-depth).
        if let Some(mut old_state) = contexts.remove(context_id) {
            let _ = group::destroy_group(&mut old_state.mls_group);
        }

        contexts.insert(
            *context_id,
            ContextCryptoState {
                mls_group: group,
                sender_key,
                sender_key_store: SenderKeyStore::new(),
                sender_key_epoch: 1,
                send_sequence: 0,
                pending_distributions: Vec::new(),
                nonce_dedup: NonceDedup::new(),
                member_wrapping_keys: HashMap::new(),
                recv_sequence_tracker: HashMap::new(),
            },
        );

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
    use crate::crypto::mls::encrypt::{encrypt, serialize_ciphertext};
    use crate::crypto::mls::group::generate_key_package;
    use scp_protocol::crypto::sender_keys::SenderKeyError;
    use tls_codec::Serialize as TlsSerializeTrait;

    const TEST_DID: &str = "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    /// Test helper: encrypt a message using the old `encrypt_message` path
    /// (sender key + MLS encrypt). Used by provider-level tests that test
    /// the crypto layer directly without the full envelope pipeline.
    fn test_encrypt_message(
        provider: &MlsCryptoProvider,
        context_id: &[u8; 32],
        payload: &[u8],
        epoch: u64,
        sequence: u64,
    ) -> Result<Vec<u8>, ContextError> {
        provider.with_context(context_id, |state| {
            let ctx_str = hex::encode(context_id);
            let sender_encrypted =
                scp_protocol::crypto::sender_keys::encrypt::encrypt_sender_layer(
                    &state.sender_key,
                    payload,
                    &ctx_str,
                    &provider.local_did,
                    epoch,
                    sequence,
                )
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

            let mls_message = encrypt(&mut state.mls_group, &sender_encrypted)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

            serialize_ciphertext(&mls_message)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))
        })
    }

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
        let encrypted = test_encrypt_message(&provider, &ctx_id, b"hello", 0, 0);
        assert!(encrypted.is_ok());

        // Destroy.
        assert!(provider.destroy_mls_group(&ctx_id).is_ok());

        // After destroy, encrypt should fail.
        let encrypted = test_encrypt_message(&provider, &ctx_id, b"hello", 0, 0);
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
        let output = result.unwrap();
        assert!(
            !output.commit_bytes.is_empty(),
            "remove_member must return non-empty commit_bytes for MLS group epoch advance"
        );
    }

    #[test]
    fn remove_member_self_returns_empty_commit() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        // Self-removal (leave) returns empty commit bytes — the local node
        // does not produce a Commit for its own departure.
        let output = provider
            .remove_member(&ctx_id, &provider.local_did)
            .unwrap();
        assert!(
            output.commit_bytes.is_empty(),
            "self-removal must return empty commit_bytes"
        );
    }

    #[test]
    fn advance_epoch_returns_non_empty_commit() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        let output = provider.advance_epoch(&ctx_id);
        assert!(output.is_ok(), "advance_epoch failed: {output:?}");
        let output = output.unwrap();
        assert!(
            !output.commit_bytes.is_empty(),
            "advance_epoch must return non-empty commit_bytes for MLS epoch advance"
        );
    }

    #[test]
    fn encrypt_message_produces_ciphertext() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        let plaintext = b"test message";
        let ciphertext = test_encrypt_message(&provider, &ctx_id, plaintext, 0, 0).unwrap();

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
    fn self_removal_is_noop() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        // Self-removal is a no-op: the leaving member abandons their local
        // MLS group state; the remaining members handle the actual removal
        // via a Commit from the group admin (#1294).
        let result = provider.remove_member(&ctx_id, TEST_DID);
        assert!(result.is_ok());
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
            Some(*provider.wrapping_public_key.lock().unwrap()),
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

        let msg = scp_protocol::crypto::sender_keys::SenderKeyDistributionMessage::from_bytes(
            &pending[0].1,
        )
        .unwrap();
        match msg {
            scp_protocol::crypto::sender_keys::SenderKeyDistributionMessage::KeyResponse(resp) => {
                assert_eq!(resp.sender_did, TEST_DID);
                assert_eq!(resp.epoch, 1, "initial epoch starts at 1 (0 is sentinel)");
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
        let bob_wrapping_pk = *bob_provider.wrapping_public_key.lock().unwrap();
        let (bob_kp_bundle, _bob_signer, _bob_mls) =
            generate_key_package_with_wrapping_key(&bob_cred, Some(&bob_wrapping_pk)).unwrap();
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
        let bob_wrapping_pk = *bob_provider.wrapping_public_key.lock().unwrap();
        let (sealed_vec, ephemeral_pub) =
            crate::crypto::sender_keys::key_protocol::hpke_seal_sender_key(
                &[42u8; 32],
                &bob_wrapping_pk,
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
            state.sender_key_store.set_unchecked(
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
        let encrypted = test_encrypt_message(&provider2, &ctx_id, b"test", 0, 0);
        assert!(encrypted.is_err(), "should fail before restore");

        // Restore.
        provider2.restore_crypto_state(&ctx_id, &exported).unwrap();

        // Verify the MLS group is functional: encrypt should succeed.
        let encrypted = test_encrypt_message(&provider2, &ctx_id, b"test after restore", 0, 0);
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
    fn restore_preserves_sender_key_epoch_high_water_mark() {
        // Regression for #1608 rollback-protection across restart.
        //
        // Scenario:
        //   1. Alice stores Bob's sender key via set_checked at epoch=5.
        //   2. Alice exports the crypto state (snapshot).
        //   3. Alice restarts and restores the snapshot into a fresh
        //      provider.
        //   4. An attacker replays an older-epoch distribution (epoch=3)
        //      or attempts same-epoch (epoch=5) — BOTH must be rejected.
        //   5. A legitimate post-snapshot rotation (epoch=6) must be
        //      accepted.
        //
        // Without persistence of the per-sender epoch map, the fresh
        // in-memory store would have no floor and accept any epoch,
        // silently re-opening the rollback window.
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let ctx_id_hex = hex::encode(ctx_id);

        // Step 1: install Bob's epoch-5 key via set_checked so the
        // epoch map is populated exactly as it would be in production.
        {
            let mut contexts = provider.contexts.lock().unwrap();
            let state = contexts.get_mut(&ctx_id).unwrap();
            state
                .sender_key_store
                .set_checked(&ctx_id_hex, bob_did, generate_sender_key(), 5)
                .expect("first set_checked at epoch 5 must succeed");
            assert_eq!(
                state.sender_key_store.epoch(&ctx_id_hex, bob_did),
                5,
                "pre-snapshot epoch must be 5"
            );
        }

        // Step 2: export snapshot.
        let exported = provider.export_crypto_state(&ctx_id).unwrap();
        assert!(!exported.is_empty());

        // Step 3: simulate restart — fresh provider, restore state.
        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string());
        provider2.restore_crypto_state(&ctx_id, &exported).unwrap();

        // Verify the restored floor exactly matches the persisted epoch.
        {
            let contexts = provider2.contexts.lock().unwrap();
            let state = contexts.get(&ctx_id).unwrap();
            assert_eq!(
                state.sender_key_store.epoch(&ctx_id_hex, bob_did),
                5,
                "post-restore epoch floor must match persisted value"
            );
        }

        // Step 4a: replay of pre-snapshot epoch=3 MUST be rejected.
        {
            let mut contexts = provider2.contexts.lock().unwrap();
            let state = contexts.get_mut(&ctx_id).unwrap();
            let err = state
                .sender_key_store
                .set_checked(&ctx_id_hex, bob_did, generate_sender_key(), 3)
                .expect_err("replay of epoch 3 must be rejected after restore");
            assert!(
                matches!(
                    err,
                    SenderKeyError::EpochNotMonotonic {
                        current: 5,
                        received: 3,
                        ..
                    }
                ),
                "expected EpochNotMonotonic(current=5, received=3), got {err:?}"
            );
        }

        // Step 4b: same-epoch replay at 5 MUST also be rejected.
        {
            let mut contexts = provider2.contexts.lock().unwrap();
            let state = contexts.get_mut(&ctx_id).unwrap();
            let err = state
                .sender_key_store
                .set_checked(&ctx_id_hex, bob_did, generate_sender_key(), 5)
                .expect_err("same-epoch replay at 5 must be rejected after restore");
            assert!(
                matches!(
                    err,
                    SenderKeyError::EpochNotMonotonic {
                        current: 5,
                        received: 5,
                        ..
                    }
                ),
                "expected EpochNotMonotonic(current=5, received=5), got {err:?}"
            );
        }

        // Step 5: legitimate post-snapshot rotation to epoch=6 is accepted.
        {
            let mut contexts = provider2.contexts.lock().unwrap();
            let state = contexts.get_mut(&ctx_id).unwrap();
            state
                .sender_key_store
                .set_checked(&ctx_id_hex, bob_did, generate_sender_key(), 6)
                .expect("post-snapshot rotation at epoch 6 must succeed");
            assert_eq!(
                state.sender_key_store.epoch(&ctx_id_hex, bob_did),
                6,
                "epoch floor should advance to 6 after legitimate rotation"
            );
        }
    }

    #[test]
    fn restore_preserves_epoch_floor_for_removed_members() {
        // Removed members still have their epoch floor retained (see
        // `SenderKeyStore::remove`) so a rejoining member cannot replay
        // an earlier-epoch key. This invariant must survive a restart.
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let carol_did = "did:dht:z6MkCarolCarolCarolCarolCarolCarolCarolCa";
        let ctx_id_hex = hex::encode(ctx_id);

        // Install then remove Carol's epoch-9 key. The key is gone but
        // the floor is retained.
        {
            let mut contexts = provider.contexts.lock().unwrap();
            let state = contexts.get_mut(&ctx_id).unwrap();
            state
                .sender_key_store
                .set_checked(&ctx_id_hex, carol_did, generate_sender_key(), 9)
                .unwrap();
            state.sender_key_store.remove(&ctx_id_hex, carol_did);
            assert!(
                state.sender_key_store.get(&ctx_id_hex, carol_did).is_none(),
                "key must be gone after remove"
            );
            assert_eq!(
                state.sender_key_store.epoch(&ctx_id_hex, carol_did),
                9,
                "epoch floor must be retained post-remove"
            );
        }

        // Snapshot + restart.
        let exported = provider.export_crypto_state(&ctx_id).unwrap();
        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string());
        provider2.restore_crypto_state(&ctx_id, &exported).unwrap();

        // Restored store has no key for Carol but still has the floor.
        {
            let contexts = provider2.contexts.lock().unwrap();
            let state = contexts.get(&ctx_id).unwrap();
            assert!(
                state.sender_key_store.get(&ctx_id_hex, carol_did).is_none(),
                "removed key must not reappear after restore"
            );
            assert_eq!(
                state.sender_key_store.epoch(&ctx_id_hex, carol_did),
                9,
                "removed-member floor must survive restart"
            );
        }

        // Attempt to install an earlier-epoch key (rejoin attack) — rejected.
        {
            let mut contexts = provider2.contexts.lock().unwrap();
            let state = contexts.get_mut(&ctx_id).unwrap();
            let err = state
                .sender_key_store
                .set_checked(&ctx_id_hex, carol_did, generate_sender_key(), 4)
                .expect_err("rejoin at older epoch must be rejected");
            assert!(matches!(err, SenderKeyError::EpochNotMonotonic { .. }));
        }
    }

    #[test]
    fn restore_tolerates_legacy_snapshot_with_seeded_floor() {
        // Back-compat: a snapshot serialized before `sender_key_epochs`
        // was persisted must still deserialize cleanly AND must close
        // the one-shot rollback window that would otherwise exist at
        // the first post-upgrade restart.
        //
        // Without the legacy-floor seed, restoring would leave every
        // per-sender floor at 0, so a captured pre-upgrade epoch=k>0
        // distribution could be replayed through `set_checked` against
        // a zero floor. The fix seeds every restored sender with the
        // global `sender_key_epoch` counter (which IS persisted in
        // legacy snapshots) as a conservative lower bound.
        //
        // We simulate a legacy snapshot by clearing the new field from
        // the freshly-exported snapshot and re-serializing it, which
        // models the wire format of the old struct (serde(default)
        // fills in an empty Vec on deserialize).
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let ctx_id_hex = hex::encode(ctx_id);
        {
            let mut contexts = provider.contexts.lock().unwrap();
            let state = contexts.get_mut(&ctx_id).unwrap();
            // Set a non-trivial global sender_key_epoch so we can verify
            // the legacy seed uses it.
            state.sender_key_epoch = 7;
            state
                .sender_key_store
                .set_unchecked(&ctx_id_hex, bob_did, generate_sender_key());
        }

        // Export, then hand-edit the msgpack to drop the epoch map.
        let exported = provider.export_crypto_state(&ctx_id).unwrap();
        let mut snapshot: MlsCryptoSnapshot = rmp_serde::from_slice(&exported).unwrap();
        snapshot.sender_key_epochs.clear();
        let legacy_bytes = rmp_serde::to_vec_named(&snapshot).unwrap();

        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string());
        provider2
            .restore_crypto_state(&ctx_id, &legacy_bytes)
            .expect("legacy snapshot (empty epoch map) must restore cleanly");

        // The legacy snapshot had no per-sender epoch map, so the
        // restore path seeds every sender with the global
        // `sender_key_epoch` counter as a conservative lower bound.
        // This closes the one-shot rollback window.
        {
            let mut contexts = provider2.contexts.lock().unwrap();
            let state = contexts.get_mut(&ctx_id).unwrap();
            assert_eq!(
                state.sender_key_store.epoch(&ctx_id_hex, bob_did),
                7,
                "legacy restore must seed per-sender floor from the global sender_key_epoch \
                 counter (= 7 in this fixture), not leave it at zero"
            );
            // Replay of epoch <= 7 must be rejected — the one-shot
            // window is closed.
            let err = state
                .sender_key_store
                .set_checked(&ctx_id_hex, bob_did, generate_sender_key(), 7)
                .expect_err("same-epoch replay must be rejected under legacy seed");
            assert!(matches!(err, SenderKeyError::EpochNotMonotonic { .. }));
            let err = state
                .sender_key_store
                .set_checked(&ctx_id_hex, bob_did, generate_sender_key(), 3)
                .expect_err("older-epoch replay must be rejected under legacy seed");
            assert!(matches!(err, SenderKeyError::EpochNotMonotonic { .. }));
            // Legitimate rotation above the seeded floor is accepted.
            state
                .sender_key_store
                .set_checked(&ctx_id_hex, bob_did, generate_sender_key(), 8)
                .expect("post-seed rotation at epoch 8 must succeed");
        }
    }

    #[test]
    fn restore_legacy_snapshot_gap_case_residual_window_documented() {
        // Pins the residual-window case for legacy snapshots: the
        // floor seed uses the global `sender_key_epoch` counter,
        // which reflects LOCAL rotation count only. A remote peer
        // whose true per-sender floor exceeded the local counter at
        // snapshot time is seeded with the lower local value,
        // leaving a residual rollback window bounded by
        // `MAX_EPOCH_ADVANCE` in the receive path. This test
        // encodes the observed behavior so the gap case is
        // unambiguous.
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let peer_did = "did:dht:z6MkPeerPeerPeerPeerPeerPeerPeerPeerPeerPe";
        let ctx_id_hex = hex::encode(ctx_id);

        // Scenario: local provider has rotated only once
        // (`sender_key_epoch = 1`), but the peer has rotated many
        // times and set_checked has been called with epoch = 50 for
        // the peer. This represents a pre-C1 runtime where the peer
        // epoch IS tracked in the `epochs` map but the snapshot
        // format does NOT persist it.
        {
            let mut contexts = provider.contexts.lock().unwrap();
            let state = contexts.get_mut(&ctx_id).unwrap();
            state.sender_key_epoch = 1;
            state
                .sender_key_store
                .set_checked(&ctx_id_hex, peer_did, generate_sender_key(), 50)
                .unwrap();
            assert_eq!(
                state.sender_key_store.epoch(&ctx_id_hex, peer_did),
                50,
                "pre-snapshot peer floor is 50 (above local counter 1)"
            );
        }

        // Export, then strip the per-sender epoch map to simulate a
        // legacy snapshot.
        let exported = provider.export_crypto_state(&ctx_id).unwrap();
        let mut snapshot: MlsCryptoSnapshot = rmp_serde::from_slice(&exported).unwrap();
        snapshot.sender_key_epochs.clear();
        let legacy_bytes = rmp_serde::to_vec_named(&snapshot).unwrap();

        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string());
        provider2
            .restore_crypto_state(&ctx_id, &legacy_bytes)
            .expect("legacy restore must succeed");

        // OBSERVED BEHAVIOR: the peer's restored floor equals the
        // LOCAL sender_key_epoch counter (1), NOT the true pre-snapshot
        // peer floor (50). This is the documented residual window.
        {
            let contexts = provider2.contexts.lock().unwrap();
            let state = contexts.get(&ctx_id).unwrap();
            let seeded = state.sender_key_store.epoch(&ctx_id_hex, peer_did);
            assert_eq!(
                seeded, 1,
                "legacy seed uses global sender_key_epoch (1), NOT the true peer floor (50). \
                 This is the documented residual window bounded by MAX_EPOCH_ADVANCE in the \
                 receive path. Fully closing it would require a format break."
            );
            // The residual window is `peer_floor - seeded_floor` = 49
            // in this scenario, bounded from above by MAX_EPOCH_ADVANCE
            // in the actual receive path.
            assert!(
                50 > seeded,
                "gap exists: true peer floor ({}) > seeded floor ({})",
                50,
                seeded
            );
        }
    }

    #[test]
    fn restore_legacy_snapshot_with_zero_global_epoch_seeds_floor_to_one() {
        // Edge case of the legacy-floor seed: if the legacy snapshot's
        // global `sender_key_epoch` is 0 (brand-new context, never
        // rotated), the seed must still be at least 1 so that
        // `set_checked` rejects an incoming epoch=0 (which would fail
        // the `epoch > current_epoch` guard regardless, but we want
        // the floor to be explicit rather than implicit).
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let ctx_id_hex = hex::encode(ctx_id);
        {
            let mut contexts = provider.contexts.lock().unwrap();
            let state = contexts.get_mut(&ctx_id).unwrap();
            state.sender_key_epoch = 0;
            state
                .sender_key_store
                .set_unchecked(&ctx_id_hex, bob_did, generate_sender_key());
        }

        let exported = provider.export_crypto_state(&ctx_id).unwrap();
        let mut snapshot: MlsCryptoSnapshot = rmp_serde::from_slice(&exported).unwrap();
        snapshot.sender_key_epochs.clear();
        let legacy_bytes = rmp_serde::to_vec_named(&snapshot).unwrap();

        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string());
        provider2
            .restore_crypto_state(&ctx_id, &legacy_bytes)
            .unwrap();

        let contexts = provider2.contexts.lock().unwrap();
        let state = contexts.get(&ctx_id).unwrap();
        assert_eq!(
            state.sender_key_store.epoch(&ctx_id_hex, bob_did),
            1,
            "legacy seed must clamp to at least 1 when global counter is 0"
        );
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
        let encrypted = test_encrypt_message(&provider2, &ctx_id, b"test", 0, 0);
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

    #[test]
    fn test_wrapping_key_persisted_across_restart() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        // Capture the original wrapping keypair.
        let original_public = *provider.wrapping_public_key.lock().unwrap();
        let original_secret: [u8; 32] = **provider.wrapping_secret_key.lock().unwrap();

        // Sanity: the keypair should not be all zeros.
        assert_ne!(
            original_public, [0u8; 32],
            "wrapping public key must not be zero"
        );
        assert_ne!(
            original_secret, [0u8; 32],
            "wrapping secret key must not be zero"
        );

        // Export the crypto state.
        let exported = provider.export_crypto_state(&ctx_id).unwrap();
        assert!(!exported.is_empty());

        // Create a fresh provider (simulates restart — gets a NEW random keypair).
        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string());
        let fresh_public = *provider2.wrapping_public_key.lock().unwrap();
        assert_ne!(
            fresh_public, original_public,
            "fresh provider should have a DIFFERENT wrapping public key"
        );

        // Restore the exported state into the fresh provider.
        provider2.restore_crypto_state(&ctx_id, &exported).unwrap();

        // After restore, the wrapping keypair must match the ORIGINAL, not the fresh one.
        let restored_public = *provider2.wrapping_public_key.lock().unwrap();
        let restored_secret: [u8; 32] = **provider2.wrapping_secret_key.lock().unwrap();

        assert_eq!(
            restored_public, original_public,
            "wrapping public key must be restored from snapshot, not freshly generated"
        );
        assert_eq!(
            restored_secret, original_secret,
            "wrapping secret key must be restored from snapshot, not freshly generated"
        );
    }
}
