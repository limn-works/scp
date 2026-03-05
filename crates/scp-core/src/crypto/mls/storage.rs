//! `StorageProvider` bridge to scp-platform storage adapters.
//!
//! `OpenMLS` requires a `StorageProvider` trait implementation for persisting
//! group state, key packages, and other MLS artifacts. This module bridges
//! between the `OpenMLS` storage requirements and the scp-platform `Storage`
//! trait.
//!
//! # Architecture
//!
//! [`MlsStorageBridge`] wraps an `Arc<ProtocolStore<S>>` and a context ID.
//! All keys are prefixed with `mls/{context_id}/...` per spec section 17.9.
//! `OpenMLS` key types are serialized via `MessagePack` for sub-key construction;
//! entity values are serialized via `MessagePack` and stored as raw bytes through
//! the `ProtocolStore`'s underlying `Storage` backend.
//!
//! [`ScpMlsProvider`] combines `RustCrypto` (crypto + randomness) with
//! `MlsStorageBridge<S>` for a complete `OpenMlsProvider` implementation.
//!
//! # Why this bypasses `ProtocolStore` domain methods
//!
//! Every other domain area (contexts, identity, TLS, UCANs, etc.) stores
//! data through typed `ProtocolStore` methods that apply `StoredValue`
//! version envelopes and follow SCP key conventions. This module is the
//! sole exception: it accesses `ProtocolStore::storage()` to call raw
//! `Storage` trait methods directly. This is intentional because:
//!
//! 1. **`OpenMLS` owns the storage contract.** The `StorageProvider` trait
//!    dictates what gets stored, the key structure, and the serialization
//!    format. Wrapping values in `StoredValue` envelopes would break
//!    `OpenMLS` deserialization on read-back.
//!
//! 2. **The bridge *is* the domain layer for MLS.** It constructs
//!    namespaced keys (`mls/{context_id}/{label}/{hex_key}`), validates
//!    context IDs via `sanitize_key_component`, and handles serialization.
//!    Adding `ProtocolStore` wrapper methods would be indirection with no
//!    added value — they would just call `self.storage.store(key, value)`.
//!
//! 3. **Migration is `OpenMLS`'s concern.** `ProtocolStore`'s version
//!    envelopes and `Migratable` trait enable lazy on-read migration for
//!    SCP-owned data. MLS state serialization is governed by the `OpenMLS`
//!    version. If the format changes across `OpenMLS` upgrades, migration
//!    must follow `OpenMLS`'s own compatibility guarantees, not SCP's
//!    `StoredValue` versioning.
//!
//! # Sync-to-Async Bridge
//!
//! `OpenMLS` `StorageProvider` is a synchronous trait, but `Storage` is async.
//! The bridge uses `tokio::runtime::Handle::current().block_on()` to call
//! async storage methods from synchronous trait implementations. This
//! requires a running tokio runtime in the current thread.
//!
//! See spec section 17.9 and ADR-006. See SCP-PERSIST-050.

use std::sync::Arc;

use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;
use openmls_traits::storage::{CURRENT_VERSION, StorageProvider, traits};
use serde::Serialize;

use scp_platform::traits::Storage;

use crate::store::ProtocolStore;

/// Context identifier type alias for consistency with the rest of scp-core.
type ContextId = String;

// ---------------------------------------------------------------------------
// Storage key labels
// ---------------------------------------------------------------------------

const KEY_PACKAGE_LABEL: &str = "key_package";
const PSK_LABEL: &str = "psk";
const ENCRYPTION_KEY_PAIR_LABEL: &str = "encryption_key_pair";
const SIGNATURE_KEY_PAIR_LABEL: &str = "signature_key_pair";
const EPOCH_KEY_PAIRS_LABEL: &str = "epoch_key_pairs";
const TREE_LABEL: &str = "tree";
const GROUP_CONTEXT_LABEL: &str = "group_context";
const INTERIM_TRANSCRIPT_HASH_LABEL: &str = "interim_transcript_hash";
const CONFIRMATION_TAG_LABEL: &str = "confirmation_tag";
const JOIN_CONFIG_LABEL: &str = "join_config";
const OWN_LEAF_NODES_LABEL: &str = "own_leaf_nodes";
const GROUP_STATE_LABEL: &str = "group_state";
const QUEUED_PROPOSAL_LABEL: &str = "queued_proposal";
const PROPOSAL_QUEUE_REFS_LABEL: &str = "proposal_queue_refs";
const OWN_LEAF_NODE_INDEX_LABEL: &str = "own_leaf_node_index";
const EPOCH_SECRETS_LABEL: &str = "epoch_secrets";
const RESUMPTION_PSK_STORE_LABEL: &str = "resumption_psk";
const MESSAGE_SECRETS_LABEL: &str = "message_secrets";

// ---------------------------------------------------------------------------
// MlsStorageBridgeError
// ---------------------------------------------------------------------------

/// Errors produced by [`MlsStorageBridge`] storage operations.
#[derive(Debug, thiserror::Error)]
pub enum MlsStorageBridgeError {
    /// The underlying storage backend returned an error.
    #[error("storage error: {0}")]
    Storage(#[from] scp_platform::PlatformError),

    /// Serialization of an `OpenMLS` key or value failed.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Deserialization of a stored `OpenMLS` value failed.
    #[error("deserialization error: {0}")]
    Deserialization(String),

    /// No tokio runtime available on the current thread.
    ///
    /// The MLS storage bridge requires a tokio runtime to bridge async
    /// `Storage` operations into sync `StorageProvider` methods. This error
    /// occurs when `StorageProvider` methods are called outside a tokio context.
    #[error("no tokio runtime available: {0}")]
    NoRuntime(String),
}

// ---------------------------------------------------------------------------
// MlsStorageBridge
// ---------------------------------------------------------------------------

/// Bridges `OpenMLS` `StorageProvider` to scp-platform `Storage` via `ProtocolStore`.
///
/// All keys are prefixed with `mls/{context_id}/` per spec section 17.9.
/// `OpenMLS` key types are serialized to hex-encoded `MessagePack` bytes for sub-key
/// construction. Entity values are serialized via `MessagePack`.
///
/// The bridge is generic over `S: Storage`, enabling use with any storage
/// backend (in-memory, `SQLite`, etc.).
///
/// See spec section 17.9. See SCP-PERSIST-050.
pub struct MlsStorageBridge<S: Storage> {
    store: Arc<ProtocolStore<S>>,
    context_id: ContextId,
}

impl<S: Storage> MlsStorageBridge<S> {
    /// Creates a new `MlsStorageBridge` for the given context.
    ///
    /// Validates the `context_id` via [`sanitize_key_component`] to prevent
    /// namespace escape in storage keys. All storage keys will be prefixed
    /// with `mls/{context_id}/`.
    ///
    /// # Errors
    ///
    /// Returns [`MlsStorageBridgeError::Serialization`] if the context ID
    /// contains forbidden characters (`/`, `\`, `..`, or null bytes).
    pub fn new(
        store: Arc<ProtocolStore<S>>,
        context_id: ContextId,
    ) -> Result<Self, MlsStorageBridgeError> {
        crate::store::sanitize_key_component(&context_id).map_err(|e| {
            MlsStorageBridgeError::Serialization(format!("invalid context_id for MLS storage: {e}"))
        })?;
        Ok(Self { store, context_id })
    }

    /// Returns the context ID this bridge is scoped to.
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Builds a storage key with the MLS prefix, label, and hex-encoded sub-key.
    ///
    /// Format: `mls/{context_id}/{label}/{hex(sub_key_bytes)}`
    fn build_key(&self, label: &str, sub_key_bytes: &[u8]) -> String {
        format!(
            "mls/{}/{}/{}",
            self.context_id,
            label,
            hex::encode(sub_key_bytes)
        )
    }

    /// Serializes an `OpenMLS` key type to `MessagePack` bytes for use in storage key construction.
    fn serialize_key<K: Serialize>(key: &K) -> Result<Vec<u8>, MlsStorageBridgeError> {
        rmp_serde::to_vec(key).map_err(|e| MlsStorageBridgeError::Serialization(e.to_string()))
    }

    /// Serializes an `OpenMLS` entity value to `MessagePack` bytes for storage.
    fn serialize_value<V: Serialize>(value: &V) -> Result<Vec<u8>, MlsStorageBridgeError> {
        rmp_serde::to_vec(value).map_err(|e| MlsStorageBridgeError::Serialization(e.to_string()))
    }

    /// Deserializes an `OpenMLS` entity value from stored `MessagePack` bytes.
    fn deserialize_value<V: serde::de::DeserializeOwned>(
        bytes: &[u8],
    ) -> Result<V, MlsStorageBridgeError> {
        rmp_serde::from_slice(bytes)
            .map_err(|e| MlsStorageBridgeError::Deserialization(e.to_string()))
    }

    /// Synchronously stores a value by blocking on the async storage operation.
    ///
    /// Uses `block_in_place` to avoid panicking when called from within a
    /// tokio multi-thread runtime (which is the common case in tests and
    /// when `OpenMLS` calls `StorageProvider` methods during group operations).
    fn sync_store(&self, key: &str, value: &[u8]) -> Result<(), MlsStorageBridgeError> {
        tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::try_current()
                .map_err(|e| MlsStorageBridgeError::NoRuntime(e.to_string()))?;
            handle
                .block_on(self.store.storage().store(key, value))
                .map_err(MlsStorageBridgeError::from)
        })
    }

    /// Synchronously retrieves a value by blocking on the async storage operation.
    fn sync_retrieve(&self, key: &str) -> Result<Option<Vec<u8>>, MlsStorageBridgeError> {
        tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::try_current()
                .map_err(|e| MlsStorageBridgeError::NoRuntime(e.to_string()))?;
            handle
                .block_on(self.store.storage().retrieve(key))
                .map_err(MlsStorageBridgeError::from)
        })
    }

    /// Synchronously deletes a value by blocking on the async storage operation.
    fn sync_delete(&self, key: &str) -> Result<(), MlsStorageBridgeError> {
        tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::try_current()
                .map_err(|e| MlsStorageBridgeError::NoRuntime(e.to_string()))?;
            handle
                .block_on(self.store.storage().delete(key))
                .map_err(MlsStorageBridgeError::from)
        })
    }

    /// Writes a single-valued entity keyed by group ID + label.
    fn write_group_value<GroupId: Serialize, V: Serialize>(
        &self,
        label: &str,
        group_id: &GroupId,
        value: &V,
    ) -> Result<(), MlsStorageBridgeError> {
        let gid_bytes = Self::serialize_key(group_id)?;
        let key = self.build_key(label, &gid_bytes);
        let val_bytes = Self::serialize_value(value)?;
        self.sync_store(&key, &val_bytes)
    }

    /// Reads a single-valued entity keyed by group ID + label.
    fn read_group_value<GroupId: Serialize, V: serde::de::DeserializeOwned>(
        &self,
        label: &str,
        group_id: &GroupId,
    ) -> Result<Option<V>, MlsStorageBridgeError> {
        let gid_bytes = Self::serialize_key(group_id)?;
        let key = self.build_key(label, &gid_bytes);
        match self.sync_retrieve(&key)? {
            Some(bytes) => Ok(Some(Self::deserialize_value(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Deletes a single-valued entity keyed by group ID + label.
    fn delete_group_value<GroupId: Serialize>(
        &self,
        label: &str,
        group_id: &GroupId,
    ) -> Result<(), MlsStorageBridgeError> {
        let gid_bytes = Self::serialize_key(group_id)?;
        let key = self.build_key(label, &gid_bytes);
        self.sync_delete(&key)
    }

    /// Appends a value to a `MessagePack`-encoded list stored under a single key.
    fn append_to_list<GroupId: Serialize, V: Serialize>(
        &self,
        label: &str,
        group_id: &GroupId,
        value: &V,
    ) -> Result<(), MlsStorageBridgeError> {
        let gid_bytes = Self::serialize_key(group_id)?;
        let key = self.build_key(label, &gid_bytes);
        let val_bytes = Self::serialize_value(value)?;

        let mut list: Vec<Vec<u8>> = match self.sync_retrieve(&key)? {
            Some(bytes) => rmp_serde::from_slice(&bytes)
                .map_err(|e| MlsStorageBridgeError::Deserialization(e.to_string()))?,
            None => Vec::new(),
        };
        list.push(val_bytes);

        let list_bytes = rmp_serde::to_vec(&list)
            .map_err(|e| MlsStorageBridgeError::Serialization(e.to_string()))?;
        self.sync_store(&key, &list_bytes)
    }

    /// Reads a `MessagePack`-encoded list stored under a single key.
    fn read_list<GroupId: Serialize, V: serde::de::DeserializeOwned>(
        &self,
        label: &str,
        group_id: &GroupId,
    ) -> Result<Vec<V>, MlsStorageBridgeError> {
        let gid_bytes = Self::serialize_key(group_id)?;
        let key = self.build_key(label, &gid_bytes);
        match self.sync_retrieve(&key)? {
            Some(bytes) => {
                let items: Vec<Vec<u8>> = rmp_serde::from_slice(&bytes)
                    .map_err(|e| MlsStorageBridgeError::Deserialization(e.to_string()))?;
                items
                    .iter()
                    .map(|item_bytes| Self::deserialize_value(item_bytes))
                    .collect()
            }
            None => Ok(Vec::new()),
        }
    }

    /// Removes a specific value from a `MessagePack`-encoded list stored under a single key.
    fn remove_from_list<GroupId: Serialize, V: Serialize>(
        &self,
        label: &str,
        group_id: &GroupId,
        value: &V,
    ) -> Result<(), MlsStorageBridgeError> {
        let gid_bytes = Self::serialize_key(group_id)?;
        let key = self.build_key(label, &gid_bytes);
        let val_bytes = Self::serialize_value(value)?;

        let mut list: Vec<Vec<u8>> = match self.sync_retrieve(&key)? {
            Some(bytes) => rmp_serde::from_slice(&bytes)
                .map_err(|e| MlsStorageBridgeError::Deserialization(e.to_string()))?,
            None => Vec::new(),
        };

        if let Some(pos) = list.iter().position(|stored| stored == &val_bytes) {
            list.remove(pos);
        }

        let list_bytes = rmp_serde::to_vec(&list)
            .map_err(|e| MlsStorageBridgeError::Serialization(e.to_string()))?;
        self.sync_store(&key, &list_bytes)
    }
}

// ---------------------------------------------------------------------------
// StorageProvider implementation
// ---------------------------------------------------------------------------

impl<S: Storage> StorageProvider<CURRENT_VERSION> for MlsStorageBridge<S> {
    type Error = MlsStorageBridgeError;

    // --- writers for group state ---

    fn write_mls_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        self.write_group_value(JOIN_CONFIG_LABEL, group_id, config)
    }

    fn append_own_leaf_node<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        self.append_to_list(OWN_LEAF_NODES_LABEL, group_id, leaf_node)
    }

    fn queue_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error> {
        // Store the proposal keyed by (group_id, proposal_ref)
        let composite_key = Self::serialize_key(&(group_id, proposal_ref))?;
        let key = self.build_key(QUEUED_PROPOSAL_LABEL, &composite_key);
        let val_bytes = Self::serialize_value(proposal)?;
        self.sync_store(&key, &val_bytes)?;

        // Append proposal_ref to the per-group queue list
        self.append_to_list(PROPOSAL_QUEUE_REFS_LABEL, group_id, proposal_ref)
    }

    fn write_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        self.write_group_value(TREE_LABEL, group_id, tree)
    }

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        self.write_group_value(
            INTERIM_TRANSCRIPT_HASH_LABEL,
            group_id,
            interim_transcript_hash,
        )
    }

    fn write_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        self.write_group_value(GROUP_CONTEXT_LABEL, group_id, group_context)
    }

    fn write_confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        self.write_group_value(CONFIRMATION_TAG_LABEL, group_id, confirmation_tag)
    }

    fn write_group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        self.write_group_value(GROUP_STATE_LABEL, group_id, group_state)
    }

    fn write_message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        self.write_group_value(MESSAGE_SECRETS_LABEL, group_id, message_secrets)
    }

    fn write_resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        self.write_group_value(RESUMPTION_PSK_STORE_LABEL, group_id, resumption_psk_store)
    }

    fn write_own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        self.write_group_value(OWN_LEAF_NODE_INDEX_LABEL, group_id, own_leaf_index)
    }

    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        self.write_group_value(EPOCH_SECRETS_LABEL, group_id, group_epoch_secrets)
    }

    // --- writers for crypto objects ---

    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        let pk_bytes = Self::serialize_key(public_key)?;
        let key = self.build_key(SIGNATURE_KEY_PAIR_LABEL, &pk_bytes);
        let val_bytes = Self::serialize_value(signature_key_pair)?;
        self.sync_store(&key, &val_bytes)
    }

    fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        let pk_bytes = Self::serialize_key(public_key)?;
        let key = self.build_key(ENCRYPTION_KEY_PAIR_LABEL, &pk_bytes);
        let val_bytes = Self::serialize_value(key_pair)?;
        self.sync_store(&key, &val_bytes)
    }

    fn write_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error> {
        let composite = Self::serialize_key(&(group_id, epoch, leaf_index))?;
        let key = self.build_key(EPOCH_KEY_PAIRS_LABEL, &composite);
        let val_bytes = Self::serialize_value(&key_pairs)?;
        self.sync_store(&key, &val_bytes)
    }

    fn write_key_package<
        HashReference: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error> {
        let hr_bytes = Self::serialize_key(hash_ref)?;
        let key = self.build_key(KEY_PACKAGE_LABEL, &hr_bytes);
        let val_bytes = Self::serialize_value(key_package)?;
        self.sync_store(&key, &val_bytes)
    }

    fn write_psk<
        PskId: traits::PskId<CURRENT_VERSION>,
        PskBundle: traits::PskBundle<CURRENT_VERSION>,
    >(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        let id_bytes = Self::serialize_key(psk_id)?;
        let key = self.build_key(PSK_LABEL, &id_bytes);
        let val_bytes = Self::serialize_value(psk)?;
        self.sync_store(&key, &val_bytes)
    }

    // --- getters for group state ---

    fn mls_group_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        self.read_group_value(JOIN_CONFIG_LABEL, group_id)
    }

    fn own_leaf_nodes<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        self.read_list(OWN_LEAF_NODES_LABEL, group_id)
    }

    fn queued_proposal_refs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        self.read_list(PROPOSAL_QUEUE_REFS_LABEL, group_id)
    }

    fn queued_proposals<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        let refs: Vec<ProposalRef> = self.read_list(PROPOSAL_QUEUE_REFS_LABEL, group_id)?;

        refs.into_iter()
            .map(|proposal_ref| {
                let composite_key = Self::serialize_key(&(group_id, &proposal_ref))?;
                let key = self.build_key(QUEUED_PROPOSAL_LABEL, &composite_key);
                let bytes = self.sync_retrieve(&key)?;
                let proposal: QueuedProposal = match bytes {
                    Some(b) => Self::deserialize_value(&b)?,
                    None => {
                        return Err(MlsStorageBridgeError::Deserialization(
                            "queued proposal not found".to_owned(),
                        ));
                    }
                };
                Ok((proposal_ref, proposal))
            })
            .collect()
    }

    fn tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        self.read_group_value(TREE_LABEL, group_id)
    }

    fn group_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        self.read_group_value(GROUP_CONTEXT_LABEL, group_id)
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        self.read_group_value(INTERIM_TRANSCRIPT_HASH_LABEL, group_id)
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        self.read_group_value(CONFIRMATION_TAG_LABEL, group_id)
    }

    fn group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        self.read_group_value(GROUP_STATE_LABEL, group_id)
    }

    fn message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        self.read_group_value(MESSAGE_SECRETS_LABEL, group_id)
    }

    fn resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        self.read_group_value(RESUMPTION_PSK_STORE_LABEL, group_id)
    }

    fn own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        self.read_group_value(OWN_LEAF_NODE_INDEX_LABEL, group_id)
    }

    fn group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        self.read_group_value(EPOCH_SECRETS_LABEL, group_id)
    }

    // --- getters for crypto objects ---

    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        let pk_bytes = Self::serialize_key(public_key)?;
        let key = self.build_key(SIGNATURE_KEY_PAIR_LABEL, &pk_bytes);
        match self.sync_retrieve(&key)? {
            Some(bytes) => Ok(Some(Self::deserialize_value(&bytes)?)),
            None => Ok(None),
        }
    }

    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        let pk_bytes = Self::serialize_key(public_key)?;
        let key = self.build_key(ENCRYPTION_KEY_PAIR_LABEL, &pk_bytes);
        match self.sync_retrieve(&key)? {
            Some(bytes) => Ok(Some(Self::deserialize_value(&bytes)?)),
            None => Ok(None),
        }
    }

    fn encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
        let composite = Self::serialize_key(&(group_id, epoch, leaf_index))?;
        let key = self.build_key(EPOCH_KEY_PAIRS_LABEL, &composite);
        self.sync_retrieve(&key)?
            .map_or_else(|| Ok(Vec::new()), |bytes| Self::deserialize_value(&bytes))
    }

    fn key_package<
        KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        let hr_bytes = Self::serialize_key(hash_ref)?;
        let key = self.build_key(KEY_PACKAGE_LABEL, &hr_bytes);
        match self.sync_retrieve(&key)? {
            Some(bytes) => Ok(Some(Self::deserialize_value(&bytes)?)),
            None => Ok(None),
        }
    }

    fn psk<PskBundle: traits::PskBundle<CURRENT_VERSION>, PskId: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        let id_bytes = Self::serialize_key(psk_id)?;
        let key = self.build_key(PSK_LABEL, &id_bytes);
        match self.sync_retrieve(&key)? {
            Some(bytes) => Ok(Some(Self::deserialize_value(&bytes)?)),
            None => Ok(None),
        }
    }

    // --- deleters for group state ---

    fn remove_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        // Remove from the per-group proposal queue refs list
        self.remove_from_list(PROPOSAL_QUEUE_REFS_LABEL, group_id, proposal_ref)?;

        // Delete the proposal data itself
        let composite_key = Self::serialize_key(&(group_id, proposal_ref))?;
        let key = self.build_key(QUEUED_PROPOSAL_LABEL, &composite_key);
        self.sync_delete(&key)
    }

    fn delete_own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_group_value(OWN_LEAF_NODES_LABEL, group_id)
    }

    fn delete_group_config<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_group_value(JOIN_CONFIG_LABEL, group_id)
    }

    fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_group_value(TREE_LABEL, group_id)
    }

    fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_group_value(CONFIRMATION_TAG_LABEL, group_id)
    }

    fn delete_group_state<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_group_value(GROUP_STATE_LABEL, group_id)
    }

    fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_group_value(GROUP_CONTEXT_LABEL, group_id)
    }

    fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_group_value(INTERIM_TRANSCRIPT_HASH_LABEL, group_id)
    }

    fn delete_message_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_group_value(MESSAGE_SECRETS_LABEL, group_id)
    }

    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_group_value(RESUMPTION_PSK_STORE_LABEL, group_id)
    }

    fn delete_own_leaf_index<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_group_value(OWN_LEAF_NODE_INDEX_LABEL, group_id)
    }

    fn delete_group_epoch_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_group_value(EPOCH_SECRETS_LABEL, group_id)
    }

    fn clear_proposal_queue<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        // Read all proposal refs, delete each proposal, then delete the refs list
        let refs: Vec<ProposalRef> = self.read_list(PROPOSAL_QUEUE_REFS_LABEL, group_id)?;

        for proposal_ref in &refs {
            let composite_key = Self::serialize_key(&(group_id, proposal_ref))?;
            let key = self.build_key(QUEUED_PROPOSAL_LABEL, &composite_key);
            self.sync_delete(&key)?;
        }

        // Delete the refs list itself
        self.delete_group_value(PROPOSAL_QUEUE_REFS_LABEL, group_id)
    }

    // --- deleters for crypto objects ---

    fn delete_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<(), Self::Error> {
        let pk_bytes = Self::serialize_key(public_key)?;
        let key = self.build_key(SIGNATURE_KEY_PAIR_LABEL, &pk_bytes);
        self.sync_delete(&key)
    }

    fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        let pk_bytes = Self::serialize_key(public_key)?;
        let key = self.build_key(ENCRYPTION_KEY_PAIR_LABEL, &pk_bytes);
        self.sync_delete(&key)
    }

    fn delete_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error> {
        let composite = Self::serialize_key(&(group_id, epoch, leaf_index))?;
        let key = self.build_key(EPOCH_KEY_PAIRS_LABEL, &composite);
        self.sync_delete(&key)
    }

    fn delete_key_package<KeyPackageRef: traits::HashReference<CURRENT_VERSION>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        let hr_bytes = Self::serialize_key(hash_ref)?;
        let key = self.build_key(KEY_PACKAGE_LABEL, &hr_bytes);
        self.sync_delete(&key)
    }

    fn delete_psk<PskKey: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        let id_bytes = Self::serialize_key(psk_id)?;
        let key = self.build_key(PSK_LABEL, &id_bytes);
        self.sync_delete(&key)
    }
}

// ---------------------------------------------------------------------------
// ScpMlsProvider — combined crypto + persistent storage
// ---------------------------------------------------------------------------

/// Complete `OpenMLS` provider combining `RustCrypto` with persistent storage.
///
/// `ScpMlsProvider<S>` replaces the in-memory `OpenMlsRustCrypto` provider
/// with one that persists MLS state through [`MlsStorageBridge<S>`]. Crypto
/// operations and randomness use `RustCrypto` (same as `OpenMlsRustCrypto`).
///
/// See spec section 17.9. See SCP-PERSIST-050.
pub struct ScpMlsProvider<S: Storage> {
    crypto: RustCrypto,
    storage: MlsStorageBridge<S>,
}

impl<S: Storage> ScpMlsProvider<S> {
    /// Creates a new `ScpMlsProvider` with the given store and context ID.
    ///
    /// # Errors
    ///
    /// Returns [`MlsStorageBridgeError`] if the context ID contains
    /// forbidden characters.
    pub fn new(
        store: Arc<ProtocolStore<S>>,
        context_id: ContextId,
    ) -> Result<Self, MlsStorageBridgeError> {
        Ok(Self {
            crypto: RustCrypto::default(),
            storage: MlsStorageBridge::new(store, context_id)?,
        })
    }

    /// Returns a reference to the underlying [`MlsStorageBridge`].
    #[must_use]
    pub const fn mls_storage(&self) -> &MlsStorageBridge<S> {
        &self.storage
    }
}

impl<S: Storage> OpenMlsProvider for ScpMlsProvider<S> {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MlsStorageBridge<S>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

// ---------------------------------------------------------------------------
// Legacy in-memory provider support
// ---------------------------------------------------------------------------

/// The in-memory MLS provider type for backward compatibility.
///
/// Phase 1 code uses this type alias. New code should prefer
/// [`ScpMlsProvider<S>`] for persistent storage.
///
/// See ADR-001 and ADR-006 for the storage provider strategy.
pub type InMemoryMlsProvider = openmls_rust_crypto::OpenMlsRustCrypto;

/// Creates a new in-memory MLS provider instance.
///
/// Each provider instance has independent storage. This is retained for
/// backward compatibility with existing tests and Phase 1 code.
///
/// # Example
///
/// ```rust,ignore
/// let provider = scp_core::crypto::mls::storage::new_provider();
/// ```
#[must_use]
pub fn new_provider() -> InMemoryMlsProvider {
    openmls_rust_crypto::OpenMlsRustCrypto::default()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use openmls::group::GroupId as MlsGroupId;
    use openmls::group::MlsGroupState;
    use openmls_traits::storage::StorageProvider;

    /// Helper to create a test `ProtocolStore` with `InMemoryStorage`.
    fn test_store() -> Arc<ProtocolStore<scp_platform::testing::InMemoryStorage>> {
        Arc::new(ProtocolStore::new(
            scp_platform::testing::InMemoryStorage::new(),
        ))
    }

    /// Creates an `OpenMLS` `GroupId` for testing.
    fn test_group_id(name: &[u8]) -> MlsGroupId {
        MlsGroupId::from_slice(name)
    }

    /// Serializes a value to JSON bytes for comparison when `PartialEq`
    /// is not available on the type.
    fn to_json_bytes<T: serde::Serialize>(value: &T) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }

    // -- AC4: group state store/load roundtrip --

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn group_state_roundtrip_via_bridge() {
        let store = test_store();
        let bridge = MlsStorageBridge::new(store, "ctx-roundtrip".to_owned()).unwrap();

        let group_id = test_group_id(b"test-group-1");
        let state_value = MlsGroupState::Operational;

        StorageProvider::write_group_state(&bridge, &group_id, &state_value).unwrap();

        let loaded: Option<MlsGroupState> =
            StorageProvider::group_state(&bridge, &group_id).unwrap();
        assert!(loaded.is_some());
        assert_eq!(
            to_json_bytes(&loaded.unwrap()),
            to_json_bytes(&MlsGroupState::Operational)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn group_state_returns_none_for_missing() {
        let store = test_store();
        let bridge = MlsStorageBridge::new(store, "ctx-empty".to_owned()).unwrap();

        let group_id = test_group_id(b"nonexistent");
        let loaded: Option<MlsGroupState> =
            StorageProvider::group_state(&bridge, &group_id).unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn group_state_overwrite() {
        let store = test_store();
        let bridge = MlsStorageBridge::new(store, "ctx-overwrite".to_owned()).unwrap();

        let group_id = test_group_id(b"group-ow");

        StorageProvider::write_group_state(&bridge, &group_id, &MlsGroupState::Operational)
            .unwrap();
        StorageProvider::write_group_state(&bridge, &group_id, &MlsGroupState::Inactive).unwrap();

        let loaded: Option<MlsGroupState> =
            StorageProvider::group_state(&bridge, &group_id).unwrap();
        assert!(loaded.is_some());
        assert_eq!(
            to_json_bytes(&loaded.unwrap()),
            to_json_bytes(&MlsGroupState::Inactive)
        );
    }

    // -- AC4: internal helpers roundtrip (type-agnostic) --

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn write_and_read_group_value_roundtrip() {
        let store = test_store();
        let bridge = MlsStorageBridge::new(store, "ctx-internal".to_owned()).unwrap();

        let key_data = "some-group-id";
        let value_data = vec![1u8, 2, 3, 4, 5];

        bridge
            .write_group_value("test_label", &key_data, &value_data)
            .unwrap();
        let loaded: Option<Vec<u8>> = bridge.read_group_value("test_label", &key_data).unwrap();
        assert_eq!(loaded, Some(value_data));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn read_group_value_returns_none_for_missing() {
        let store = test_store();
        let bridge = MlsStorageBridge::new(store, "ctx-miss".to_owned()).unwrap();

        let loaded: Option<Vec<u8>> = bridge
            .read_group_value::<&str, Vec<u8>>("missing_label", &"no-key")
            .unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn list_append_and_read() {
        let store = test_store();
        let bridge = MlsStorageBridge::new(store, "ctx-list".to_owned()).unwrap();

        let group_key = "list-group";
        bridge
            .append_to_list("items", &group_key, &vec![1u8, 2])
            .unwrap();
        bridge
            .append_to_list("items", &group_key, &vec![3u8, 4])
            .unwrap();

        let loaded: Vec<Vec<u8>> = bridge.read_list("items", &group_key).unwrap();
        assert_eq!(loaded, vec![vec![1, 2], vec![3, 4]]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn list_remove_item() {
        let store = test_store();
        let bridge = MlsStorageBridge::new(store, "ctx-rm".to_owned()).unwrap();

        let group_key = "rm-group";
        bridge
            .append_to_list("items", &group_key, &vec![10u8])
            .unwrap();
        bridge
            .append_to_list("items", &group_key, &vec![20u8])
            .unwrap();
        bridge
            .append_to_list("items", &group_key, &vec![30u8])
            .unwrap();

        bridge
            .remove_from_list("items", &group_key, &vec![20u8])
            .unwrap();

        let loaded: Vec<Vec<u8>> = bridge.read_list("items", &group_key).unwrap();
        assert_eq!(loaded, vec![vec![10], vec![30]]);
    }

    // -- AC5: context isolation --

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn context_isolation_between_bridges() {
        let store = test_store();

        let bridge_a = MlsStorageBridge::new(Arc::clone(&store), "ctx-alpha".to_owned()).unwrap();
        let bridge_b = MlsStorageBridge::new(Arc::clone(&store), "ctx-beta".to_owned()).unwrap();

        let group_id = test_group_id(b"shared-group-id");

        // Store different values in each context
        StorageProvider::write_group_state(&bridge_a, &group_id, &MlsGroupState::Operational)
            .unwrap();
        StorageProvider::write_group_state(&bridge_b, &group_id, &MlsGroupState::Inactive).unwrap();

        // Verify isolation — each bridge reads its own value
        let from_a: Option<MlsGroupState> =
            StorageProvider::group_state(&bridge_a, &group_id).unwrap();
        let from_b: Option<MlsGroupState> =
            StorageProvider::group_state(&bridge_b, &group_id).unwrap();
        assert!(from_a.is_some());
        assert!(from_b.is_some());
        assert_eq!(
            to_json_bytes(&from_a.unwrap()),
            to_json_bytes(&MlsGroupState::Operational)
        );
        assert_eq!(
            to_json_bytes(&from_b.unwrap()),
            to_json_bytes(&MlsGroupState::Inactive)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn context_isolation_internal_values() {
        let store = test_store();

        let bridge_a = MlsStorageBridge::new(Arc::clone(&store), "ctx-iso-1".to_owned()).unwrap();
        let bridge_b = MlsStorageBridge::new(Arc::clone(&store), "ctx-iso-2".to_owned()).unwrap();

        let key = "same-key";

        bridge_a
            .write_group_value("data", &key, &vec![10u8, 20, 30])
            .unwrap();
        bridge_b
            .write_group_value("data", &key, &vec![40u8, 50, 60])
            .unwrap();

        let loaded_a: Option<Vec<u8>> = bridge_a.read_group_value("data", &key).unwrap();
        let loaded_b: Option<Vec<u8>> = bridge_b.read_group_value("data", &key).unwrap();
        assert_eq!(loaded_a, Some(vec![10, 20, 30]));
        assert_eq!(loaded_b, Some(vec![40, 50, 60]));

        // A third context sees no data
        let bridge_c = MlsStorageBridge::new(Arc::clone(&store), "ctx-iso-3".to_owned()).unwrap();
        let loaded_c: Option<Vec<u8>> = bridge_c.read_group_value("data", &key).unwrap();
        assert!(loaded_c.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn context_isolation_delete_does_not_affect_other() {
        let store = test_store();

        let bridge_a = MlsStorageBridge::new(Arc::clone(&store), "ctx-del-1".to_owned()).unwrap();
        let bridge_b = MlsStorageBridge::new(Arc::clone(&store), "ctx-del-2".to_owned()).unwrap();

        let group_id = test_group_id(b"gid-del");

        StorageProvider::write_group_state(&bridge_a, &group_id, &MlsGroupState::Operational)
            .unwrap();
        StorageProvider::write_group_state(&bridge_b, &group_id, &MlsGroupState::Operational)
            .unwrap();

        // Delete from A only
        StorageProvider::delete_group_state(&bridge_a, &group_id).unwrap();

        // A should be gone, B should remain
        let from_a: Option<MlsGroupState> =
            StorageProvider::group_state(&bridge_a, &group_id).unwrap();
        let from_b: Option<MlsGroupState> =
            StorageProvider::group_state(&bridge_b, &group_id).unwrap();
        assert!(from_a.is_none());
        assert!(from_b.is_some());
    }

    // -- AC6: state survives simulated restart --

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn state_survives_simulated_restart() {
        let store = test_store();
        let group_id = test_group_id(b"persist-group");

        // Phase 1: Write state and drop the bridge
        {
            let bridge =
                MlsStorageBridge::new(Arc::clone(&store), "ctx-restart".to_owned()).unwrap();
            StorageProvider::write_group_state(&bridge, &group_id, &MlsGroupState::Operational)
                .unwrap();
            // bridge is dropped here
        }

        // Phase 2: Recreate bridge with same store + context_id
        {
            let bridge =
                MlsStorageBridge::new(Arc::clone(&store), "ctx-restart".to_owned()).unwrap();
            let loaded: Option<MlsGroupState> =
                StorageProvider::group_state(&bridge, &group_id).unwrap();
            assert!(loaded.is_some());
            assert_eq!(
                to_json_bytes(&loaded.unwrap()),
                to_json_bytes(&MlsGroupState::Operational)
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn restart_with_multiple_value_types() {
        let store = test_store();
        let context_id = "ctx-multi-restart".to_owned();

        // Phase 1: Write multiple value types via internal helpers
        {
            let bridge = MlsStorageBridge::new(Arc::clone(&store), context_id.clone()).unwrap();
            bridge
                .write_group_value("state", &"key1", &vec![1u8, 2, 3])
                .unwrap();
            bridge
                .write_group_value("config", &"key1", &vec![10u8, 20])
                .unwrap();
            bridge
                .append_to_list("nodes", &"key1", &vec![99u8])
                .unwrap();
        }

        // Phase 2: Recreate and verify all state types
        {
            let bridge = MlsStorageBridge::new(Arc::clone(&store), context_id).unwrap();
            let state: Option<Vec<u8>> = bridge.read_group_value("state", &"key1").unwrap();
            let config: Option<Vec<u8>> = bridge.read_group_value("config", &"key1").unwrap();
            let nodes: Vec<Vec<u8>> = bridge.read_list("nodes", &"key1").unwrap();

            assert_eq!(state, Some(vec![1, 2, 3]));
            assert_eq!(config, Some(vec![10, 20]));
            assert_eq!(nodes, vec![vec![99]]);
        }
    }

    // -- Key prefix verification --

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn keys_use_correct_mls_prefix() {
        let store = test_store();
        let bridge = MlsStorageBridge::new(Arc::clone(&store), "ctx-prefix".to_owned()).unwrap();

        bridge
            .write_group_value("group_state", &"gid", &vec![1u8])
            .unwrap();

        // Verify the key in the underlying storage uses the mls/ prefix
        let keys = store.storage().list_keys("mls/ctx-prefix/").await.unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys[0].starts_with("mls/ctx-prefix/group_state/"));
    }

    // -- ScpMlsProvider tests --

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn provider_exposes_storage_and_crypto() {
        let store = test_store();
        let provider = ScpMlsProvider::new(store, "ctx-provider".to_owned()).unwrap();

        // Verify the provider implements the required traits
        let _storage = provider.storage();
        let _crypto = provider.crypto();
        let _rand = provider.rand();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn provider_group_state_roundtrip() {
        let store = test_store();
        let provider = ScpMlsProvider::new(store, "ctx-prov-rt".to_owned()).unwrap();

        let group_id = test_group_id(b"prov-group");
        StorageProvider::write_group_state(
            provider.storage(),
            &group_id,
            &MlsGroupState::Operational,
        )
        .unwrap();

        let loaded: Option<MlsGroupState> =
            StorageProvider::group_state(provider.storage(), &group_id).unwrap();
        assert!(loaded.is_some());
        assert_eq!(
            to_json_bytes(&loaded.unwrap()),
            to_json_bytes(&MlsGroupState::Operational)
        );
    }

    // -- Legacy in-memory provider backward compatibility --

    #[test]
    fn legacy_provider_exposes_storage_and_crypto() {
        let provider = new_provider();
        let _storage = openmls_traits::OpenMlsProvider::storage(&provider);
        let _crypto = openmls_traits::OpenMlsProvider::crypto(&provider);
    }
}
