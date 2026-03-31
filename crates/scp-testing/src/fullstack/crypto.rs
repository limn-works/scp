//! End-to-end [`ContextCryptoProvider`] with real MLS and sender keys.
//!
//! Unlike `MlsCryptoProvider`, this provider captures Welcome messages and
//! sender keys in a shared [`KeyExchange`] so a second node's provider can
//! pick them up — enabling true two-party (or multi-party) E2E tests through
//! `ContextManager`.
//!
//! # What's real
//!
//! - `OpenMLS` groups (create, add, remove, encrypt, decrypt)
//! - AES-256-GCM sender key encryption with AAD binding
//! - Key package generation, Welcome processing
//!
//! # What's test infrastructure
//!
//! - `KeyExchange` side channel (bridges Welcome + sender key material)
//! - `join_from_welcome()` extra method (not part of trait)
//! - `decrypt_message()` extra method (not part of trait)

use std::collections::HashMap;
use std::sync::Mutex;

use scp_core::context::ContextError;
use scp_core::context::builder::{ContextCreationError, ContextCryptoProvider};
use scp_core::crypto::access_keys::{AccessKey, AccessKeyStore};
use scp_core::crypto::mls::credential::ScpCredential;
use sha2::Digest;
use subtle::ConstantTimeEq;

use scp_core::crypto::mls::encrypt::encrypt as mls_encrypt;
use scp_core::crypto::mls::encrypt::{
    DecryptedContent, decrypt, decrypt_with_sender_did, serialize_ciphertext,
};
use scp_core::crypto::mls::epoch_grace::EpochGraceStore;
use scp_core::crypto::mls::group::{
    ScpMlsGroup, add_member, create_group, destroy_group, generate_key_package, join_group,
};
use scp_core::crypto::mls::ratchet::{process_commit, propose_update, serialize_mls_message};
use scp_core::crypto::sender_keys::encrypt::{
    build_sender_header, decrypt_sender_layer, encrypt_sender_layer, parse_sender_header,
};
use scp_core::crypto::sender_keys::{SenderKey, SenderKeyStore, generate_sender_key};
use scp_identity::SigningKeyId;

use super::exchange::{KeyExchange, PendingWelcome};

/// End-to-end crypto provider backed by real MLS groups and sender keys.
///
/// Each node (Alice, Bob, etc.) gets its own `E2eCryptoProvider` instance.
/// They share a `KeyExchange` (via `Arc<Mutex<>>`) to coordinate Welcome
/// messages and sender keys.
///
/// # Thread safety
///
/// Uses `std::sync::Mutex` (not `tokio::sync::Mutex`) because
/// `ContextCryptoProvider` trait methods are synchronous.
pub struct E2eCryptoProvider {
    /// This node's DID.
    local_did: String,
    /// Per-context MLS groups, keyed by context ID bytes.
    groups: Mutex<HashMap<[u8; 32], ScpMlsGroup>>,
    /// Sender key store (`context_id_hex` + `sender_did` -> sender key).
    sender_keys: Mutex<SenderKeyStore>,
    /// Broadcast keys (not used in E2E tests, but required by trait).
    broadcast_keys: Mutex<HashMap<[u8; 32], SenderKey>>,
    /// Shared key exchange for Welcome messages and sender keys.
    exchange: std::sync::Arc<Mutex<KeyExchange>>,
    /// Tracks which members have been added to each context (for sender key
    /// distribution targeting).
    members: Mutex<HashMap<[u8; 32], Vec<String>>>,
    /// Per-member access keys for content-access-key wrapping/unwrapping.
    /// Keyed by `(context_id_str, member_did)`. Populated via
    /// `pickup_access_keys` (joiner picks up all keys from `KeyExchange`)
    /// and `set_access_key` (creator copies key from `ContextManager`).
    access_keys: Mutex<AccessKeyStore>,
    /// Per-context sender key epoch counter: `context_id` -> epoch.
    sender_key_epochs: Mutex<HashMap<[u8; 32], u64>>,
    /// Per-context send-side message sequence counter: `context_id` -> sequence.
    send_sequences: Mutex<HashMap<[u8; 32], u64>>,
}

#[allow(clippy::significant_drop_tightening)]
impl E2eCryptoProvider {
    /// Creates a new E2E crypto provider for the given DID.
    ///
    /// The `exchange` is shared between all providers in a `FullStackNetwork`.
    #[must_use]
    pub fn new(local_did: String, exchange: std::sync::Arc<Mutex<KeyExchange>>) -> Self {
        Self {
            local_did,
            groups: Mutex::new(HashMap::new()),
            sender_keys: Mutex::new(SenderKeyStore::new()),
            broadcast_keys: Mutex::new(HashMap::new()),
            exchange,
            members: Mutex::new(HashMap::new()),
            access_keys: Mutex::new(AccessKeyStore::new()),
            sender_key_epochs: Mutex::new(HashMap::new()),
            send_sequences: Mutex::new(HashMap::new()),
        }
    }

    /// Returns the local DID.
    #[must_use]
    pub fn local_did(&self) -> &str {
        &self.local_did
    }

    /// Converts a context ID to the hex string used as sender key store key.
    fn context_id_hex(context_id: &[u8; 32]) -> String {
        hex::encode(context_id)
    }

    /// Helper: build an `ScpCredential` for the local DID.
    fn credential(&self) -> Result<ScpCredential, ContextCreationError> {
        ScpCredential::new(self.local_did.clone(), None, SigningKeyId::Active)
            .map_err(|e| ContextCreationError::CryptoFailed(e.to_string()))
    }

    // -- Extra methods (not part of ContextCryptoProvider trait) ---------------

    /// Returns the list of member DIDs for a context, as known from the MLS
    /// group roster. Populated during `join_from_welcome`.
    #[must_use]
    pub fn context_members(&self, context_id: &[u8; 32]) -> Vec<String> {
        let members = self
            .members
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        members.get(context_id).cloned().unwrap_or_default()
    }

    /// Joins a context by retrieving the Welcome message from the shared
    /// `KeyExchange` and forming the local MLS group state.
    ///
    /// Also picks up any sender keys deposited for this node.
    ///
    /// # Errors
    ///
    /// Returns `ContextError` if no Welcome is available or MLS join fails.
    pub fn join_from_welcome(&self, context_id: &[u8; 32]) -> Result<(), ContextError> {
        let pending = {
            let mut exchange = self
                .exchange
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            exchange
                .take_welcome(context_id, &self.local_did)
                .ok_or_else(|| {
                    ContextError::CryptoFailed(format!(
                        "no Welcome available for {} in context {}",
                        self.local_did,
                        hex::encode(context_id)
                    ))
                })?
        };

        let group = join_group(&pending.welcome, pending.provider, pending.signer)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        // Extract member DIDs from the MLS group so regenerate_and_distribute_sender_key
        // knows who to distribute to (the joiner's members map is otherwise empty).
        let member_dids: Vec<String> = group
            .members()
            .unwrap_or_default()
            .iter()
            .filter_map(|m| {
                ScpCredential::from_bytes(m.credential.serialized_content())
                    .ok()
                    .map(|c| c.did)
            })
            .collect();

        {
            let mut groups = self
                .groups
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            groups.insert(*context_id, group);
        }

        // Populate the members map from the MLS group roster so that
        // regenerate_and_distribute_sender_key can find existing members.
        {
            let mut members_guard = self
                .members
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            members_guard.insert(*context_id, member_dids);
        }

        // Pick up any sender keys deposited for us.
        let ctx_hex = Self::context_id_hex(context_id);
        let sender_keys = {
            let mut exchange = self
                .exchange
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            exchange.take_sender_keys(&ctx_hex, &self.local_did)
        };
        if !sender_keys.is_empty() {
            let mut store = self
                .sender_keys
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for (sender_did, key) in sender_keys {
                store.set(&ctx_hex, &sender_did, key);
            }
        }

        // Access key pickup is handled by FullStackNode::join_from_welcome
        // which has access to the original string context_id needed for
        // the KeyExchange lookup.

        Ok(())
    }

    /// Processes any pending MLS commits for this node in the given context.
    ///
    /// When another member adds a third party, the MLS group epoch advances.
    /// Existing members must process the Commit to stay in sync. This method
    /// retrieves and processes all pending commits from the `KeyExchange`.
    ///
    /// # Errors
    ///
    /// Returns `ContextError` if commit processing fails.
    pub fn process_pending_commits(&self, context_id: &[u8; 32]) -> Result<(), ContextError> {
        let commits = {
            let mut exchange = self
                .exchange
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            exchange.take_commits(context_id, &self.local_did)
        };

        if commits.is_empty() {
            return Ok(());
        }

        let mut groups = self
            .groups
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let group = groups
            .get_mut(context_id)
            .ok_or_else(|| ContextError::CryptoFailed("no MLS group for context".into()))?;

        // Use a temporary grace store — we don't need epoch grace tracking
        // in tests, only the commit processing side effect (epoch advance).
        let mut grace_store = EpochGraceStore::new();

        for commit_bytes in &commits {
            process_commit(group, commit_bytes, &mut grace_store)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
        }

        Ok(())
    }

    /// Regenerates and distributes the local sender key to all known members.
    ///
    /// After `join_from_welcome`, the joiner's sender key (generated during
    /// the throwaway `create_context`) is stale — it was created for a
    /// different MLS group. This method regenerates it and deposits it in
    /// the `KeyExchange` for all existing members to pick up.
    ///
    /// # Errors
    ///
    /// Returns `ContextError` if the sender key cannot be generated or
    /// distributed.
    pub fn regenerate_and_distribute_sender_key(
        &self,
        context_id: &[u8; 32],
    ) -> Result<(), ContextError> {
        // Regenerate sender key.
        let key = generate_sender_key();
        let ctx_hex = Self::context_id_hex(context_id);

        {
            let mut store = self
                .sender_keys
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            store.set(&ctx_hex, &self.local_did, key);
        }

        // Distribute to all known members in the exchange.
        // Read existing members from the exchange's deposited sender keys
        // by reading the members list.
        let members: Vec<String> = {
            let members_guard = self
                .members
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            members_guard.get(context_id).cloned().unwrap_or_default()
        };

        for member_did in &members {
            if member_did != &self.local_did {
                self.distribute_sender_key(context_id, member_did)?;
            }
        }

        Ok(())
    }

    /// Picks up any pending sender keys from the shared `KeyExchange`.
    ///
    /// This is the complement of `distribute_sender_key`: when another node
    /// deposits its sender key for this node, calling `pickup_sender_keys`
    /// retrieves and stores them locally so `decrypt_message` can find them.
    ///
    /// # Errors
    ///
    /// Returns `ContextError` if the lock is poisoned (shouldn't happen in
    /// well-behaved tests).
    pub fn pickup_sender_keys(&self, context_id: &[u8; 32]) -> Result<(), ContextError> {
        let ctx_hex = Self::context_id_hex(context_id);
        let sender_keys = {
            let mut exchange = self
                .exchange
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            exchange.take_sender_keys(&ctx_hex, &self.local_did)
        };
        if !sender_keys.is_empty() {
            let mut store = self
                .sender_keys
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for (sender_did, key) in sender_keys {
                store.set(&ctx_hex, &sender_did, key);
            }
        }
        Ok(())
    }

    /// Deposits an access key in the shared `KeyExchange` for a joiner to
    /// pick up during `join_from_welcome`.
    ///
    /// `target_joiner_did` is the DID of the member who will retrieve this
    /// key. `member_did` identifies whose access key this is.
    pub fn deposit_access_key(
        &self,
        context_id: &str,
        target_joiner_did: &str,
        member_did: &str,
        key: AccessKey,
    ) {
        let mut exchange = self
            .exchange
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        exchange.deposit_access_key(context_id, target_joiner_did, member_did, key);
    }

    /// Picks up ALL access keys from the shared `KeyExchange` deposited for
    /// this node and stores them locally in the access key store.
    pub fn pickup_access_keys(&self, context_id: &str) {
        let keys = {
            let mut exchange = self
                .exchange
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            exchange.take_access_keys(context_id, &self.local_did)
        };
        let mut store = self
            .access_keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (member_did, key) in keys {
            store.set(context_id, &member_did, key);
        }
    }

    /// Returns a reference to the local access key store (for the decrypt
    /// path in `FullStackNode`).
    pub fn get_access_key(&self, context_id: &str, member_did: &str) -> Option<AccessKey> {
        let store = self
            .access_keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        store.get(context_id, member_did).cloned()
    }

    /// Stores an access key directly in the local access key store.
    ///
    /// Unlike [`pickup_access_keys`](Self::pickup_access_keys), this bypasses
    /// the `KeyExchange` and writes directly to the provider's store.
    /// Used to copy the context creator's access key from the
    /// `ContextManager`'s `PerContextState` into the crypto provider.
    pub fn set_access_key(&self, context_id: &str, member_did: &str, key: AccessKey) {
        let mut store = self
            .access_keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        store.set(context_id, member_did, key);
    }

    /// Decrypts a message produced by the full envelope pipeline (`seal`).
    ///
    /// Performs the reverse of the send path:
    /// `OuterEnvelope` → MLS decrypt → sender key decrypt → `InnerEnvelope` →
    /// strip padding → access key unwrap → plaintext.
    ///
    /// # Arguments
    ///
    /// * `context_id` - The 32-byte context identifier.
    /// * `ciphertext` - The serialized `OuterEnvelope` (output of `seal`).
    /// * `sender_did` - The DID of the sender (for sender key lookup).
    /// * `epoch` - The sender key epoch (AAD).
    /// * `sequence` - The sequence number (AAD).
    ///
    /// # Errors
    ///
    /// Returns `ContextError` if any decryption or deserialization step fails.
    pub fn decrypt_message(
        &self,
        context_id: &[u8; 32],
        ciphertext: &[u8],
        sender_did: &str,
        epoch: u64,
        sequence: u64,
    ) -> Result<Vec<u8>, ContextError> {
        let ctx_hex = Self::context_id_hex(context_id);

        // Step 0: Deserialize outer envelope to extract MLS ciphertext.
        let outer: scp_core::envelope::outer::OuterEnvelope = rmp_serde::from_slice(ciphertext)
            .map_err(|e| {
                ContextError::CryptoFailed(format!("outer envelope deserialization: {e}"))
            })?;

        // Step 1: MLS decrypt.
        let mls_decrypted = {
            let mut groups = self
                .groups
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let group = groups
                .get_mut(context_id)
                .ok_or_else(|| ContextError::CryptoFailed("no MLS group for context".into()))?;
            decrypt(group, &outer.encrypted_blob)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?
        };

        // Step 2: Sender key decrypt.
        let sender_key = {
            let store = self
                .sender_keys
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            store.get(&ctx_hex, sender_did).cloned().ok_or_else(|| {
                ContextError::CryptoFailed(format!(
                    "no sender key for {sender_did} in context {ctx_hex}"
                ))
            })?
        };

        let sender_decrypted = decrypt_sender_layer(
            &sender_key,
            &mls_decrypted,
            &ctx_hex,
            sender_did,
            epoch,
            sequence,
        )
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        // Step 3: Deserialize InnerEnvelope.
        let inner = scp_core::envelope::inner::InnerEnvelope::from_bytes(&sender_decrypted)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        // Step 4: Strip padding to recover wrapped content bytes.
        let stripped = scp_core::envelope::strip_padding(&inner.payload)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        // Step 5: Verify content integrity (constant-time).
        let computed_hash: [u8; 32] = sha2::Sha256::digest(&stripped).into();
        if !bool::from(computed_hash[..].ct_eq(&inner.payload_hash[..])) {
            return Err(ContextError::CryptoFailed(
                "content integrity check failed".into(),
            ));
        }

        // Step 6: Deserialize WrappedContent and unwrap access key layer.
        let wrapped: scp_core::crypto::access_keys::WrappedContent =
            rmp_serde::from_slice(&stripped).map_err(|e| {
                ContextError::CryptoFailed(format!("wrapped content deserialization: {e}"))
            })?;

        let access_key = {
            let store = self
                .access_keys
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            store
                .get(&inner.context_id, &self.local_did)
                .cloned()
                .ok_or_else(|| {
                    ContextError::CryptoFailed(format!(
                        "no access key for {} in context {}",
                        self.local_did, inner.context_id
                    ))
                })?
        };

        scp_core::crypto::access_keys::wrapping::unwrap_content(
            &wrapped,
            &self.local_did,
            &access_key,
            &inner.context_id,
            sender_did,
            0,
            0,
        )
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))
    }
}

// Nursery lint — false-positives on lock guards across block boundaries.
#[allow(clippy::significant_drop_tightening)]
impl ContextCryptoProvider for E2eCryptoProvider {
    fn validate_creator_identity(&self) -> Result<(), ContextCreationError> {
        let _ = self.credential()?;
        Ok(())
    }

    fn create_mls_group(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        let credential = self.credential()?;
        let group = create_group(&credential)
            .map_err(|e| ContextCreationError::CryptoFailed(e.to_string()))?;

        let mut groups = self
            .groups
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        groups.insert(*context_id, group);

        // Track the creator as a member so commits from add_member are
        // deposited for them in the exchange.
        let mut members = self
            .members
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        members
            .entry(*context_id)
            .or_default()
            .push(self.local_did.clone());

        Ok(())
    }

    fn generate_sender_key(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        let key = generate_sender_key();
        let ctx_hex = Self::context_id_hex(context_id);

        let mut store = self
            .sender_keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        store.set(&ctx_hex, &self.local_did, key);

        // Initialize epoch and sequence counters for this context.
        self.sender_key_epochs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(*context_id)
            .or_insert(1);
        self.send_sequences
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(*context_id)
            .or_insert(0);

        Ok(())
    }

    fn init_broadcast_key(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        let key = generate_sender_key();
        let mut broadcast_keys = self
            .broadcast_keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        broadcast_keys.insert(*context_id, key);
        Ok(())
    }

    fn destroy_mls_group(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        let mut groups = self
            .groups
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(mut group) = groups.remove(context_id) {
            let _ = destroy_group(&mut group);
        }
        Ok(())
    }

    fn destroy_sender_key(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        let ctx_hex = Self::context_id_hex(context_id);
        let mut store = self
            .sender_keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = store.remove(&ctx_hex, &self.local_did);

        let mut broadcast_keys = self
            .broadcast_keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        broadcast_keys.remove(context_id);
        Ok(())
    }

    fn validate_key_package(
        &self,
        owner_did: &str,
        _key_package_bytes: Option<&[u8]>,
    ) -> Result<(), ContextError> {
        if owner_did.is_empty() {
            return Err(ContextError::InvalidKeyPackage("owner DID is empty".into()));
        }
        if !owner_did.starts_with("did:") {
            return Err(ContextError::InvalidKeyPackage(
                "owner DID does not start with did:".into(),
            ));
        }
        Ok(())
    }

    fn add_member(
        &self,
        context_id: &[u8; 32],
        member_did: &str,
        _key_package_bytes: Option<&[u8]>,
    ) -> Result<scp_core::context::AddMemberOutput, ContextError> {
        // Generate a key package for the new member.
        let member_credential =
            ScpCredential::new(member_did.to_owned(), None, SigningKeyId::Active)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        let (kp_bundle, signer, provider) = generate_key_package(&member_credential)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        let kp_in: openmls::prelude::KeyPackageIn = kp_bundle.key_package().clone().into();

        // Add to MLS group.
        let result = {
            let mut groups = self
                .groups
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let group = groups
                .get_mut(context_id)
                .ok_or_else(|| ContextError::CryptoFailed("no MLS group for context".into()))?;
            add_member(group, kp_in).map_err(|e| ContextError::CryptoFailed(e.to_string()))?
        };

        // Serialize the Welcome for cross-process delivery via AddMemberOutput.
        let welcome_bytes = scp_core::crypto::mls::ratchet::serialize_mls_message(&result.welcome)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
        let commit_bytes = serialize_mls_message(&result.commit)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        // Read existing members before locking exchange (avoid nested locks).
        let existing_members: Vec<String> = {
            let members = self
                .members
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            members.get(context_id).cloned().unwrap_or_default()
        };

        // CAPTURE: Deposit Welcome + signer + provider in the exchange
        // so the joiner can retrieve them via join_from_welcome().
        // Also deposit the Commit for existing members so their MLS groups
        // advance to the new epoch.
        {
            let mut exchange = self
                .exchange
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            exchange.deposit_welcome(
                *context_id,
                member_did,
                PendingWelcome {
                    welcome: result.welcome,
                    signer,
                    provider,
                },
            );

            // Deposit the commit for all existing members except the local
            // node (the adder already merged the commit) and the new joiner
            // (who receives the Welcome instead).
            for did in &existing_members {
                if did != &self.local_did {
                    exchange.deposit_commit(*context_id, did, commit_bytes.clone());
                }
            }
        }

        // Track the member for sender key distribution.
        {
            let mut members = self
                .members
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            members
                .entry(*context_id)
                .or_default()
                .push(member_did.to_owned());
        }

        Ok(scp_core::context::AddMemberOutput {
            welcome_bytes,
            commit_bytes,
        })
    }

    fn remove_member(
        &self,
        context_id: &[u8; 32],
        member_did: &str,
    ) -> Result<scp_core::context::RemoveMemberOutput, ContextError> {
        use scp_core::crypto::mls::group::remove_member as mls_remove_member;
        use tls_codec::Serialize as TlsSerializeTrait;

        if member_did == self.local_did {
            return Err(ContextError::CryptoFailed(
                "cannot remove self from MLS group".to_string(),
            ));
        }

        let mut groups = self
            .groups
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let group = groups
            .get_mut(context_id)
            .ok_or_else(|| ContextError::CryptoFailed("no MLS group for context".into()))?;

        let members = group
            .members()
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        let mut target_index = None;
        for member in &members {
            let credential_bytes = member.credential.serialized_content();
            if let Ok(cred) = ScpCredential::from_bytes(credential_bytes)
                && cred.did == member_did
            {
                target_index = Some(member.index);
                break;
            }
        }

        let leaf_index = target_index.ok_or_else(|| {
            ContextError::MemberNotFound(format!("member {member_did} not in MLS group"))
        })?;

        let result = mls_remove_member(group, leaf_index)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        let commit_bytes = result
            .commit
            .tls_serialize_detached()
            .map_err(|e| ContextError::CryptoFailed(format!("serializing remove commit: {e}")))?;

        let group_info_bytes = result
            .group_info
            .map(|gi| {
                gi.tls_serialize_detached().map_err(|e| {
                    ContextError::CryptoFailed(format!("serializing remove group info: {e}"))
                })
            })
            .transpose()?
            .unwrap_or_default();

        Ok(scp_core::context::RemoveMemberOutput {
            commit_bytes,
            group_info_bytes,
        })
    }

    fn distribute_sender_key(
        &self,
        context_id: &[u8; 32],
        member_did: &str,
    ) -> Result<(), ContextError> {
        let ctx_hex = Self::context_id_hex(context_id);

        // Get the local sender key.
        let key = {
            let store = self
                .sender_keys
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            store
                .get(&ctx_hex, &self.local_did)
                .cloned()
                .ok_or_else(|| {
                    ContextError::CryptoFailed(
                        "no sender key for local DID in this context".to_string(),
                    )
                })?
        };

        // CAPTURE: Deposit the sender key in the exchange for the target member.
        {
            let mut exchange = self
                .exchange
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            exchange.deposit_sender_key(&ctx_hex, &self.local_did, member_did, key);
        }

        Ok(())
    }

    fn remove_member_sender_key(
        &self,
        context_id: &[u8; 32],
        member_did: &str,
    ) -> Result<(), ContextError> {
        let ctx_hex = Self::context_id_hex(context_id);
        let mut store = self
            .sender_keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = store.remove(&ctx_hex, member_did);
        Ok(())
    }
    fn advance_epoch(
        &self,
        context_id: &[u8; 32],
    ) -> Result<scp_core::context::AdvanceEpochOutput, ContextError> {
        use tls_codec::Serialize as TlsSerializeTrait;

        let mut groups = self
            .groups
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let group = groups
            .get_mut(context_id)
            .ok_or_else(|| ContextError::CryptoFailed("no MLS group for context".into()))?;
        let commit =
            propose_update(group).map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
        let commit_bytes = commit.tls_serialize_detached().map_err(|e| {
            ContextError::CryptoFailed(format!("serializing epoch advance commit: {e}"))
        })?;
        Ok(scp_core::context::AdvanceEpochOutput { commit_bytes })
    }

    fn seal(
        &self,
        context_id: &[u8; 32],
        inner: &scp_core::envelope::inner::InnerEnvelope,
        routing_id: &[u8],
        blob_ttl: u32,
    ) -> Result<Vec<u8>, ContextError> {
        let ctx_str = Self::context_id_hex(context_id);

        // 1. Serialize inner envelope to MessagePack.
        let serialized = rmp_serde::to_vec_named(inner).map_err(|e| {
            ContextError::CryptoFailed(format!("inner envelope serialization: {e}"))
        })?;

        // 2. Sender key encrypt (AES-256-GCM, ADR-007).
        let sender_key = {
            let store = self
                .sender_keys
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            store
                .get(&ctx_str, &self.local_did)
                .cloned()
                .ok_or_else(|| {
                    ContextError::CryptoFailed(
                        "no sender key for local DID in this context".to_string(),
                    )
                })?
        };
        let epoch = {
            let epochs = self
                .sender_key_epochs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            epochs.get(context_id).copied().unwrap_or(1)
        };
        let sequence = {
            let seqs = self
                .send_sequences
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            seqs.get(context_id).copied().unwrap_or(0)
        };

        let sender_encrypted = encrypt_sender_layer(
            &sender_key,
            &serialized,
            &ctx_str,
            &self.local_did,
            epoch,
            sequence,
        )
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        let with_header = build_sender_header(epoch, sequence, &sender_encrypted);

        // 3. MLS encrypt.
        let mls_message = {
            let mut groups = self
                .groups
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let group = groups
                .get_mut(context_id)
                .ok_or_else(|| ContextError::CryptoFailed("no MLS group for context".into()))?;
            mls_encrypt(group, &with_header)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?
        };
        let encrypted_blob = serialize_ciphertext(&mls_message)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        // 4. Wrap in outer envelope.
        let outer = scp_core::envelope::outer::create_outer_envelope(
            routing_id,
            None,
            blob_ttl,
            encrypted_blob,
        )
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        // Increment send sequence after successful encryption.
        {
            let mut seqs = self
                .send_sequences
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let seq = seqs.entry(*context_id).or_insert(0);
            *seq = seq.wrapping_add(1);
        }

        rmp_serde::to_vec_named(&outer)
            .map_err(|e| ContextError::CryptoFailed(format!("outer envelope serialization: {e}")))
    }

    fn open(
        &self,
        context_id: &[u8; 32],
        outer_bytes: &[u8],
    ) -> Result<scp_core::context::builder::OpenResult, ContextError> {
        let ctx_str = Self::context_id_hex(context_id);

        // Step 0: Deserialize outer envelope to extract MLS ciphertext.
        let outer: scp_core::envelope::outer::OuterEnvelope = rmp_serde::from_slice(outer_bytes)
            .map_err(|e| {
                ContextError::CryptoFailed(format!("outer envelope deserialization: {e}"))
            })?;

        // Step 1: MLS decrypt and extract sender DID from credential.
        let content = {
            let mut groups = self
                .groups
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let group = groups
                .get_mut(context_id)
                .ok_or_else(|| ContextError::CryptoFailed("no MLS group for context".into()))?;
            decrypt_with_sender_did(group, &outer.encrypted_blob)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?
        };

        match content {
            DecryptedContent::Application {
                plaintext: mls_decrypted,
                sender_did,
            } => {
                let magic = &scp_core::context::builder::MANAGEMENT_MSG_MAGIC;
                if mls_decrypted.len() >= magic.len() && mls_decrypted[..magic.len()] == *magic {
                    return Ok(scp_core::context::builder::OpenResult::Management {
                        sender_did,
                        payload: mls_decrypted[magic.len()..].to_vec(),
                    });
                }

                // Step 2: Look up the sender's key from the sender key store.
                let sender_key = {
                    let store = self
                        .sender_keys
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    store.get(&ctx_str, &sender_did).cloned().ok_or_else(|| {
                        ContextError::CryptoFailed(format!(
                            "no sender key for {sender_did} in context {ctx_str}"
                        ))
                    })?
                };

                // Step 3: Parse header and sender key decrypt.
                let (epoch, sequence, sender_ciphertext) = parse_sender_header(&mls_decrypted)
                    .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

                let decrypted = decrypt_sender_layer(
                    &sender_key,
                    sender_ciphertext,
                    &ctx_str,
                    &sender_did,
                    epoch,
                    sequence,
                )
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

                // Step 4: Deserialize as InnerEnvelope.
                let inner = scp_core::envelope::inner::InnerEnvelope::from_bytes(&decrypted)
                    .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

                // Step 5: Strip padding to recover original payload.
                let stripped = scp_core::envelope::strip_padding(&inner.payload)
                    .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

                // Step 6: Verify content integrity (constant-time).
                let computed_hash: [u8; 32] = sha2::Sha256::digest(&stripped).into();
                if !bool::from(computed_hash[..].ct_eq(&inner.payload_hash[..])) {
                    return Err(ContextError::CryptoFailed(
                        "content integrity check failed".into(),
                    ));
                }

                Ok(scp_core::context::builder::OpenResult::Application(
                    Box::new(scp_core::context::builder::OpenedEnvelope { inner, sender_did }),
                ))
            }
            DecryptedContent::Commit { sender_did: _ }
            | DecryptedContent::Proposal { sender_did: _ } => {
                Ok(scp_core::context::builder::OpenResult::Control)
            }
        }
    }

    fn mls_encrypt_management(
        &self,
        context_id: &[u8; 32],
        plaintext: &[u8],
        routing_id: &[u8],
        blob_ttl: u32,
    ) -> Result<Vec<u8>, ContextError> {
        let magic = &scp_core::context::builder::MANAGEMENT_MSG_MAGIC;
        let mut tagged = Vec::with_capacity(magic.len() + plaintext.len());
        tagged.extend_from_slice(magic);
        tagged.extend_from_slice(plaintext);

        let mls_message = {
            let mut groups = self
                .groups
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let group = groups
                .get_mut(context_id)
                .ok_or_else(|| ContextError::CryptoFailed("no MLS group for context".into()))?;
            mls_encrypt(group, &tagged).map_err(|e| ContextError::CryptoFailed(e.to_string()))?
        };
        let encrypted_blob = serialize_ciphertext(&mls_message)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        let outer = scp_core::envelope::outer::create_outer_envelope(
            routing_id,
            None,
            blob_ttl,
            encrypted_blob,
        )
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        rmp_serde::to_vec_named(&outer)
            .map_err(|e| ContextError::CryptoFailed(format!("serialization: {e}")))
    }
}
