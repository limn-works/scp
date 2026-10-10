//! The in-memory MLS provider: storage wiped on release, a stored signer
//! refused, and randomness drawn from the operating system on every request.
//!
//! openmls keeps a group's HPKE private keys, epoch secrets, and message secrets
//! as serialized bytes in `openmls_memory_storage::MemoryStorage::values`, a
//! plain `HashMap<Vec<u8>, Vec<u8>>` that frees those bytes without zeroizing
//! them. [`InMemoryMlsStorage`] wraps that storage and zeroizes every value when
//! it drops, so every owner of one (an [`InMemoryMlsProvider`] held by an
//! [`crate::ScpMlsGroup`], a `KeyPackage` bundle's provider, a provider rebuilt
//! from a snapshot, a provider dropped on an error path, or a bare
//! `InMemoryMlsStorage`) releases the storage wiped (security model spec §9.15
//! step 2).
//!
//! [`InMemoryMlsStorage`] wraps that `MemoryStorage` and refuses
//! `write_signature_key_pair`: it stores nothing and returns
//! [`InMemoryMlsStorageError::SignerStorageForbidden`], because every openmls
//! operation SCP calls takes the signer as an argument (persistence spec
//! §17.9). [`InMemoryMlsProvider::from_storage_entries`] refuses a
//! signer-labelled entry on restore, as
//! [`crate::snapshot::capture_signer_and_storage`] does on capture (§17.9.1).
//!
//! openmls draws path secrets, leaf HPKE key pairs, init secrets, and commit
//! randomness from `provider.rand()`. `openmls_rust_crypto`'s `RustCrypto`
//! answers that from one `ChaCha20Rng` seeded once per provider and never
//! reseeded or zeroized, so its seed would regenerate every one of those secrets.
//! [`OsRand`] replaces it as the `RandProvider`: each request reads the
//! operating system's generator and keeps nothing, so no seed exists to recover.
//!
//! What this provider's wipe does not reach, and what reaches it instead.
//! Every shipped SCP artifact installs the wiping global allocator, which
//! zeroes each heap block before freeing it, the old block of a reallocation
//! included (security model spec §9.15, freed heap memory). In those artifacts
//! the allocator wipes each of these copies when it is freed:
//! - values openmls replaces or deletes during normal group operation, which
//!   `MemoryStorage` frees before the provider is released;
//! - the copies `openmls_memory_storage` 0.6.0's `MemoryStorage` makes while
//!   it encodes and decodes: the smaller buffers `serde_json::to_vec` outgrows,
//!   the original it drops after storing `value.to_vec()`, the buffers each
//!   list append and removal outgrows when it re-encodes the stored list, and
//!   the buffers every `serde_json` read decodes through;
//! - hpke-rs 0.7.0's encapsulation intermediates (the input key material
//!   `hpke.random()` returns, from which the ephemeral private key derives,
//!   the Diffie-Hellman output, the `eae_prk`, and the KEM shared secret `zz`),
//!   the `labeled_ikm` and `dkp_prk` that `derive_key_pair` builds for every
//!   leaf and path-node encryption key openmls derives through
//!   `derive_hpke_keypair`, and the Diffie-Hellman output, `eae_prk`, and `zz`
//!   of decapsulation (`hpke_open`, `hpke_setup_receiver_and_export`), all
//!   plain `Vec<u8>` values.
//!
//! The allocator does not reach these, which §9.15 states as limits:
//! - each copy while it is live, before it is freed;
//! - the `ChaCha20Rng` inside the wrapped `RustCrypto`. It stays in memory for
//!   the provider's life, and two kinds of draw reach its seed.
//!   `OpenMlsCrypto::signature_key_gen` is one: the `disallowed-methods` ban
//!   in `.clippy.toml` and `crates/scp-runtime/clippy.toml` forbids it, and
//!   SCP creates signers through `SignatureKeyPair::new`, which draws from
//!   `OsRng`. `OpenMlsRand::random_array` and `random_vec` are the other:
//!   `RustCrypto` implements `OpenMlsRand` too, so `crypto()` exposes them.
//!   No SCP code calls them through `crypto()` today, but nothing enforces
//!   that yet;
//! - HPKE encapsulation randomness. openmls draws it through `crypto()`, not
//!   `rand()`: each `hpke_seal` builds an hpke-rs context whose
//!   `HpkeRustCryptoPrng` seeds a `ChaCha20Rng` from the operating system for
//!   that call. That type's `Zeroize` is a no-op, and the generator state it
//!   holds on the stack is outside any allocator. [`OsRand`] therefore covers
//!   `rand()` draws only;
//! - every copy above in a Rust application that links this crate without
//!   linking `scp-alloc`, because that application chooses its own global
//!   allocator.

use std::collections::HashMap;
use std::sync::RwLock;

use openmls_memory_storage::{MemoryStorage, MemoryStorageError};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::storage::{CURRENT_VERSION, StorageProvider, traits};
use zeroize::Zeroize;

use crate::error::MlsError;
use crate::snapshot::ProviderStorageEntries;

/// The label `openmls_memory_storage` 0.6.0 puts at the start of the storage
/// key of a stored signer: `SIGNATURE_KEY_PAIR_LABEL` in its `src/lib.rs`, which
/// `build_key` prefixes to the JSON encoding of the public key and the
/// big-endian storage version. No other label of that crate starts with these
/// bytes.
pub(crate) const SIGNER_STORAGE_LABEL: &[u8] = b"SignatureKeyPair";

/// True when `key` is a storage key under which `MemoryStorage` would hold an
/// MLS signer, so the entry it names holds the signer's private key.
pub(crate) fn is_signer_storage_key(key: &[u8]) -> bool {
    key.starts_with(SIGNER_STORAGE_LABEL)
}

/// openmls's randomness source for [`InMemoryMlsProvider`]: every request reads
/// the operating system's generator (`getrandom`) and the type holds no state,
/// so no seed outlives a single call.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRand;

/// The operating system's random source failed to fill a request.
#[derive(Debug, thiserror::Error)]
#[error("operating-system random source failed: {0}")]
pub struct OsRandError(getrandom::Error);

impl OpenMlsRand for OsRand {
    type Error = OsRandError;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        let mut out = [0u8; N];
        getrandom::getrandom(&mut out).map_err(OsRandError)?;
        Ok(out)
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut out = vec![0u8; len];
        getrandom::getrandom(&mut out).map_err(OsRandError)?;
        Ok(out)
    }
}

/// An error from [`InMemoryMlsStorage`].
#[derive(Debug, thiserror::Error)]
pub enum InMemoryMlsStorageError {
    /// The wrapped `openmls_memory_storage::MemoryStorage` failed.
    #[error("in-memory MLS storage failed: {0}")]
    Memory(#[source] MemoryStorageError),

    /// A caller asked the storage to store an MLS signer. The storage wrote
    /// nothing: every openmls operation SCP calls takes the signer as an
    /// argument, so the signer never enters provider storage (persistence
    /// spec §17.9).
    #[error("MLS signer must not be stored in provider storage (spec §17.9)")]
    SignerStorageForbidden,
}

/// The `StorageProvider` of [`InMemoryMlsProvider`].
///
/// It is openmls's `MemoryStorage`, except that `write_signature_key_pair`
/// stores nothing and returns
/// [`InMemoryMlsStorageError::SignerStorageForbidden`] (persistence spec
/// §17.9), and that its `Drop` zeroizes every stored value. Every other method
/// delegates to `MemoryStorage`.
#[derive(Default)]
pub struct InMemoryMlsStorage {
    memory: MemoryStorage,
}

impl InMemoryMlsStorage {
    /// The raw `(storage key, value)` map of the wrapped `MemoryStorage`.
    ///
    /// Snapshot capture reads it, and tests insert into it directly. A direct
    /// insert bypasses the signer refusal of `write_signature_key_pair`;
    /// capture and [`InMemoryMlsProvider::from_storage_entries`] check every
    /// key for a signer entry (§17.9.1).
    #[must_use]
    pub const fn values(&self) -> &RwLock<HashMap<Vec<u8>, Vec<u8>>> {
        &self.memory.values
    }
}

impl Drop for InMemoryMlsStorage {
    /// Zeroizes every stored value in place before `MemoryStorage` frees the
    /// map, so each value's allocation is freed holding only zeroes
    /// (`Vec::zeroize` wipes the whole capacity and keeps the allocation).
    /// [`InMemoryMlsProvider`] has no `Drop` of its own: dropping its `storage`
    /// field runs this one.
    ///
    /// A poisoned lock does not stop the wipe: the map is taken from the poison
    /// error and wiped anyway, because a panic elsewhere does not make the key
    /// material less sensitive.
    fn drop(&mut self) {
        let mut values = self
            .memory
            .values
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for value in values.values_mut() {
            value.zeroize();
        }
    }
}

// SECURITY: the derived `Debug` of `MemoryStorage` prints every value, which
// holds private key material, so this `Debug` prints only the entry count.
impl std::fmt::Debug for InMemoryMlsStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let entries = self.memory.values.read().map_or(0, |v| v.len());
        f.debug_struct("InMemoryMlsStorage")
            .field("values", &format_args!("[{entries} entries, REDACTED]"))
            .finish()
    }
}

impl StorageProvider<CURRENT_VERSION> for InMemoryMlsStorage {
    type Error = InMemoryMlsStorageError;

    /// Stores nothing and returns
    /// [`InMemoryMlsStorageError::SignerStorageForbidden`]: the signer never
    /// enters provider storage (persistence spec §17.9).
    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        _public_key: &SignaturePublicKey,
        _signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        Err(InMemoryMlsStorageError::SignerStorageForbidden)
    }

    fn write_mls_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        self.memory
            .write_mls_join_config(group_id, config)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn append_own_leaf_node<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        self.memory
            .append_own_leaf_node(group_id, leaf_node)
            .map_err(InMemoryMlsStorageError::Memory)
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
        self.memory
            .queue_proposal(group_id, proposal_ref, proposal)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn write_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        self.memory
            .write_tree(group_id, tree)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        self.memory
            .write_interim_transcript_hash(group_id, interim_transcript_hash)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn write_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        self.memory
            .write_context(group_id, group_context)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn write_confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        self.memory
            .write_confirmation_tag(group_id, confirmation_tag)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn write_group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        self.memory
            .write_group_state(group_id, group_state)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn write_message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        self.memory
            .write_message_secrets(group_id, message_secrets)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn write_resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        self.memory
            .write_resumption_psk_store(group_id, resumption_psk_store)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn write_own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        self.memory
            .write_own_leaf_index(group_id, own_leaf_index)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        self.memory
            .write_group_epoch_secrets(group_id, group_epoch_secrets)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        self.memory
            .write_encryption_key_pair(public_key, key_pair)
            .map_err(InMemoryMlsStorageError::Memory)
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
        self.memory
            .write_encryption_epoch_key_pairs(group_id, epoch, leaf_index, key_pairs)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn write_key_package<
        HashReference: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error> {
        self.memory
            .write_key_package(hash_ref, key_package)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn write_psk<
        PskId: traits::PskId<CURRENT_VERSION>,
        PskBundle: traits::PskBundle<CURRENT_VERSION>,
    >(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        self.memory
            .write_psk(psk_id, psk)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn mls_group_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        self.memory
            .mls_group_join_config(group_id)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn own_leaf_nodes<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        self.memory
            .own_leaf_nodes(group_id)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn queued_proposal_refs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        self.memory
            .queued_proposal_refs(group_id)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn queued_proposals<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        self.memory
            .queued_proposals(group_id)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        self.memory
            .tree(group_id)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn group_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        self.memory
            .group_context(group_id)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        self.memory
            .interim_transcript_hash(group_id)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        self.memory
            .confirmation_tag(group_id)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        self.memory
            .group_state(group_id)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        self.memory
            .message_secrets(group_id)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        self.memory
            .resumption_psk_store(group_id)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        self.memory
            .own_leaf_index(group_id)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        self.memory
            .group_epoch_secrets(group_id)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        self.memory
            .signature_key_pair(public_key)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        self.memory
            .encryption_key_pair(public_key)
            .map_err(InMemoryMlsStorageError::Memory)
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
        self.memory
            .encryption_epoch_key_pairs(group_id, epoch, leaf_index)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn key_package<
        KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        self.memory
            .key_package(hash_ref)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn psk<PskBundle: traits::PskBundle<CURRENT_VERSION>, PskId: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        self.memory
            .psk(psk_id)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn remove_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        self.memory
            .remove_proposal(group_id, proposal_ref)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn delete_own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.memory
            .delete_own_leaf_nodes(group_id)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn delete_group_config<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.memory
            .delete_group_config(group_id)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.memory
            .delete_tree(group_id)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.memory
            .delete_confirmation_tag(group_id)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn delete_group_state<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.memory
            .delete_group_state(group_id)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.memory
            .delete_context(group_id)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.memory
            .delete_interim_transcript_hash(group_id)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn delete_message_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.memory
            .delete_message_secrets(group_id)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.memory
            .delete_all_resumption_psk_secrets(group_id)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn delete_own_leaf_index<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.memory
            .delete_own_leaf_index(group_id)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn delete_group_epoch_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.memory
            .delete_group_epoch_secrets(group_id)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn clear_proposal_queue<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.memory
            .clear_proposal_queue::<GroupId, ProposalRef>(group_id)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn delete_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<(), Self::Error> {
        self.memory
            .delete_signature_key_pair(public_key)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        self.memory
            .delete_encryption_key_pair(public_key)
            .map_err(InMemoryMlsStorageError::Memory)
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
        self.memory
            .delete_encryption_epoch_key_pairs(group_id, epoch, leaf_index)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn delete_key_package<KeyPackageRef: traits::HashReference<CURRENT_VERSION>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        self.memory
            .delete_key_package(hash_ref)
            .map_err(InMemoryMlsStorageError::Memory)
    }

    fn delete_psk<PskKey: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        self.memory
            .delete_psk(psk_id)
            .map_err(InMemoryMlsStorageError::Memory)
    }
}

/// The in-memory MLS provider: `openmls_rust_crypto`'s crypto, with
/// [`InMemoryMlsStorage`] as storage (every value zeroized on drop, a stored
/// signer refused), and [`OsRand`] as the random source.
///
/// See ADR-001 and ADR-006 for the storage provider strategy, and ADR-057 for
/// why it lives in `scp-mls`.
#[derive(Default)]
pub struct InMemoryMlsProvider {
    crypto: RustCrypto,
    storage: InMemoryMlsStorage,
}

impl InMemoryMlsProvider {
    /// Builds a provider whose storage holds `entries`, the `(storage key,
    /// value)` pairs a snapshot captured.
    ///
    /// Checks every key before it inserts any: when one is a signer storage
    /// key, it returns [`MlsError::SignerStorageForbidden`] and leaves
    /// `entries` untouched, so the caller's wiping buffer still holds and
    /// later zeroizes every entry (persistence spec §17.9.1). Otherwise it
    /// drains `entries` into the new provider, whose storage's `Drop` wipes
    /// them.
    ///
    /// # Errors
    ///
    /// [`MlsError::SignerStorageForbidden`] when a key carries openmls's
    /// signature-key-pair label, and [`MlsError::Snapshot`] when the new
    /// provider's storage lock is poisoned.
    pub fn from_storage_entries(entries: &mut ProviderStorageEntries) -> Result<Self, MlsError> {
        if entries.iter().any(|(k, _)| is_signer_storage_key(k)) {
            return Err(MlsError::SignerStorageForbidden);
        }
        let provider = Self::default();
        {
            let mut values =
                provider.storage.values().write().map_err(|e| {
                    MlsError::Snapshot(format!("provider storage lock poisoned: {e}"))
                })?;
            for (k, v) in entries.drain(..) {
                values.insert(k, v);
            }
        }
        Ok(provider)
    }
}

// SECURITY: `MemoryStorage`'s derived `Debug` prints every storage value, which
// holds private key material, so this `Debug` prints only the entry count. It
// leaves out `crypto`, whose derived `Debug` would print its generator state.
impl std::fmt::Debug for InMemoryMlsProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let entries = self.storage.values().read().map_or(0, |v| v.len());
        f.debug_struct("InMemoryMlsProvider")
            .field("storage", &format_args!("[{entries} entries, REDACTED]"))
            .finish_non_exhaustive()
    }
}

impl OpenMlsProvider for InMemoryMlsProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = OsRand;
    type StorageProvider = InMemoryMlsStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        // `OsRand` is a stateless unit value, so every provider shares the one
        // promoted constant; there is no per-provider generator to hold.
        &OsRand
    }
}

// openmls draws path secrets, leaf HPKE keys, and init secrets from
// `provider.rand()`, so the provider's `RandProvider` must be the stateless OS
// source: `RustCrypto` there again would put one long-lived seed behind every
// one of those secrets (security model spec §9.15 step 2). Both assertions fail
// the build: the first if `rand()` returns any other type, the second if
// `OsRand` gains a field, since a zero-sized source has nowhere to keep a seed
// or a stream position.
const _: fn(&InMemoryMlsProvider) -> &OsRand = <InMemoryMlsProvider as OpenMlsProvider>::rand;
const _: () = assert!(std::mem::size_of::<OsRand>() == 0);

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Two arrays from `OsRand` differ, and neither an array nor a vector
    /// comes back all zeroes.
    #[test]
    fn os_rand_returns_nonconstant_bytes() {
        let provider = InMemoryMlsProvider::default();
        let a: [u8; 32] = provider.rand().random_array().unwrap();
        let b: [u8; 32] = provider.rand().random_array().unwrap();
        let v = provider.rand().random_vec(48).unwrap();
        assert_eq!(v.len(), 48);
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
        assert_ne!(v, vec![0u8; 48]);
    }

    /// `RustCrypto::signature_key_gen` draws from the provider's long-lived
    /// `ChaCha20Rng`, which `OsRand` does not replace.
    ///
    /// The `expect` is the control for the `signature_key_gen` entry in the
    /// workspace `.clippy.toml`: it is unfulfilled, and the CI clippy run
    /// (`-D warnings`) fails, when that entry stops disallowing the call.
    #[test]
    fn signature_key_gen_is_disallowed() {
        use openmls_traits::crypto::OpenMlsCrypto;
        use openmls_traits::types::SignatureScheme;

        let provider = InMemoryMlsProvider::default();
        #[expect(
            clippy::disallowed_methods,
            reason = "control for the lint: generates a signer from the long-lived seed on purpose"
        )]
        let (private, public) = provider
            .crypto()
            .signature_key_gen(SignatureScheme::ED25519)
            .unwrap();
        assert_eq!(public.len(), 32);
        assert!(!private.is_empty());
    }

    fn signer() -> openmls_basic_credential::SignatureKeyPair {
        openmls_basic_credential::SignatureKeyPair::new(
            openmls_traits::types::SignatureScheme::ED25519,
        )
        .unwrap()
    }

    /// `SignatureKeyPair::store` and a direct `write_signature_key_pair` both
    /// return `SignerStorageForbidden` and leave the storage empty
    /// (persistence spec §17.9). The `expect`s are the controls for the two
    /// `.clippy.toml` entries.
    #[test]
    fn storage_refuses_signer_write_and_stores_nothing() {
        let provider = InMemoryMlsProvider::default();
        let signer = signer();

        #[expect(
            clippy::disallowed_methods,
            reason = "control for the lint and the refusal: stores the signer on purpose"
        )]
        let stored = signer.store(provider.storage());
        assert!(matches!(
            stored,
            Err(InMemoryMlsStorageError::SignerStorageForbidden)
        ));

        #[expect(
            clippy::disallowed_methods,
            reason = "control for the lint and the refusal: stores the signer through the trait on purpose"
        )]
        let written = provider
            .storage()
            .write_signature_key_pair(&signer.id(), &signer);
        assert!(matches!(
            written,
            Err(InMemoryMlsStorageError::SignerStorageForbidden)
        ));

        assert!(provider.storage().values().read().unwrap().is_empty());
    }

    /// The predicate matches the key openmls's own `MemoryStorage` files a
    /// signer under, and matches neither the key it files an HPKE encryption
    /// key pair under nor any key a live group stores.
    #[test]
    fn signer_storage_key_matches_memory_storage_label() {
        /// Stand-ins for openmls's encryption key and HPKE key pair, so the
        /// raw `MemoryStorage` builds an `EncryptionKeyPair` key itself.
        #[derive(serde::Serialize, serde::Deserialize)]
        struct TestEncryptionKey(Vec<u8>);
        impl openmls_traits::storage::Key<CURRENT_VERSION> for TestEncryptionKey {}
        impl traits::EncryptionKey<CURRENT_VERSION> for TestEncryptionKey {}
        #[derive(serde::Serialize, serde::Deserialize)]
        struct TestHpkeKeyPair(Vec<u8>);
        impl openmls_traits::storage::Entity<CURRENT_VERSION> for TestHpkeKeyPair {}
        impl traits::HpkeKeyPair<CURRENT_VERSION> for TestHpkeKeyPair {}

        let raw_keys = |raw: &MemoryStorage| -> Vec<Vec<u8>> {
            raw.values.read().unwrap().keys().cloned().collect()
        };

        let signer = signer();
        let raw = MemoryStorage::default();
        #[expect(
            clippy::disallowed_methods,
            reason = "writes a signer into openmls's raw MemoryStorage to read the key it builds"
        )]
        raw.write_signature_key_pair(&signer.id(), &signer).unwrap();
        let signer_keys = raw_keys(&raw);
        assert_eq!(signer_keys.len(), 1);
        assert!(is_signer_storage_key(&signer_keys[0]));

        let raw = MemoryStorage::default();
        raw.write_encryption_key_pair(
            &TestEncryptionKey(vec![1, 2, 3]),
            &TestHpkeKeyPair(vec![4, 5, 6]),
        )
        .unwrap();
        let encryption_keys = raw_keys(&raw);
        assert_eq!(encryption_keys.len(), 1);
        assert!(encryption_keys[0].starts_with(b"EncryptionKeyPair"));
        assert!(!is_signer_storage_key(&encryption_keys[0]));

        // No key a live group stores is a signer key.
        let credential = crate::ScpCredential::new(
            "did:dht:z6Mkalice".to_owned(),
            None,
            scp_did::SigningKeyId::Active,
        )
        .unwrap();
        let group = crate::group::create_group(&credential, &scp_clock::SystemClock).unwrap();
        let group_keys: Vec<Vec<u8>> = group
            .provider()
            .storage()
            .values()
            .read()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert!(!group_keys.is_empty());
        assert!(!group_keys.iter().any(|k| is_signer_storage_key(k)));
    }

    /// A signer-labelled entry makes `from_storage_entries` fail before it
    /// drains anything: the buffer still holds both entries (§17.9.1).
    #[test]
    fn from_storage_entries_refuses_signer_entry_and_inserts_nothing() {
        let mut signer_key = SIGNER_STORAGE_LABEL.to_vec();
        signer_key.extend_from_slice(b"[1,2,3]");
        let plain = (b"EpochSecrets-a".to_vec(), vec![0xAB; 8]);
        let signer_entry = (signer_key, vec![0xCD; 8]);
        let mut entries: ProviderStorageEntries =
            zeroize::Zeroizing::new(vec![plain.clone(), signer_entry.clone()]);

        let result = InMemoryMlsProvider::from_storage_entries(&mut entries);
        assert!(matches!(result, Err(MlsError::SignerStorageForbidden)));
        assert_eq!(*entries, vec![plain.clone(), signer_entry]);

        // Control: without the signer entry the entries are drained in.
        let mut accepted: ProviderStorageEntries = zeroize::Zeroizing::new(vec![plain.clone()]);
        let provider = InMemoryMlsProvider::from_storage_entries(&mut accepted).unwrap();
        assert!(accepted.is_empty());
        assert_eq!(
            provider.storage().values().read().unwrap().get(&plain.0),
            Some(&plain.1)
        );
    }
}
