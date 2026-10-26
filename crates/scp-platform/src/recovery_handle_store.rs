//! The SDK's own store-set member and the one-writer lease
//! (`09-security-model.md` §9.7.4.2 R10, `17-persistence-and-storage.md`
//! §17.3 and §17.8; SCP-311).
//!
//! The store set itself — the value types, the codecs, the member traits and
//! [`StoreSet`](scp_kel::recovery_store::StoreSet) — lives in
//! `scp_kel::recovery_store`, which builds for `wasm32`, so a browser member
//! implements the same traits. This module holds the two pieces that need
//! the platform: [`SdkLocalMember`], the member over the SDK's encrypted
//! storage, and [`RecoveryLeases`], the registry that makes one writer per
//! `(credential, identity)` on a device.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};

use scp_did::Identifier;
use scp_kel::recovery_store::{
    CredentialId, EntrySource, MemberRead, NotReachedCause, RecordDecodeError, RecoveryEventStore,
    RecoveryHandleStore, RecoveryStoreError, SetLease, StoreEntry, StoreWriteFailure,
    check_event_length, decode_entry, encode_entry,
};

use crate::EncryptedStorage;

#[cfg(test)]
mod tests;

// ---------------------------------------------------------------------------
// The SDK's local store
// ---------------------------------------------------------------------------

/// The SDK's own local store as a store-set member, over injected encrypted
/// storage.
///
/// It holds the credential's entry and the signed events under
/// `recovery/{sha256_hex(credential_id)}/` (`17-persistence-and-storage.md`
/// §17.3), and no store-set record: the record lives only in the
/// platform-account member (§17.8). It is the one member whose entry may
/// carry the `largeBlob` skip bit.
#[derive(Debug)]
pub struct SdkLocalMember<S: EncryptedStorage> {
    storage: S,
    entry_key: String,
    credential_id: CredentialId,
}

impl<S: EncryptedStorage> SdkLocalMember<S> {
    /// Binds `storage` to `credential_id`'s entry and events.
    #[must_use]
    pub fn new(storage: S, credential_id: &CredentialId) -> Self {
        Self {
            storage,
            entry_key: credential_id.entry_key(),
            credential_id: credential_id.clone(),
        }
    }

    async fn read_decoded<T>(
        &self,
        key: &str,
        decode: impl FnOnce(&[u8]) -> Result<Option<T>, RecordDecodeError> + Send,
    ) -> MemberRead<T> {
        match self.storage.retrieve(key).await {
            Ok(None) => MemberRead::ReachedEmpty,
            Ok(Some(bytes)) => match decode(&bytes) {
                Ok(Some(value)) => MemberRead::Reached(value),
                Ok(None) => MemberRead::ReachedEmpty,
                Err(error) => MemberRead::NotReached(NotReachedCause::Undecodable(error)),
            },
            Err(error) => MemberRead::NotReached(NotReachedCause::Unreachable {
                cause: error.to_string(),
            }),
        }
    }

    async fn store(&self, key: &str, bytes: &[u8]) -> Result<(), StoreWriteFailure> {
        self.storage
            .store(key, bytes)
            .await
            .map_err(|error| StoreWriteFailure {
                cause: error.to_string(),
            })
    }
}

impl<S: EncryptedStorage> RecoveryHandleStore for SdkLocalMember<S> {
    type WriteFailure = StoreWriteFailure;

    async fn read_entry(&self) -> MemberRead<StoreEntry> {
        self.read_decoded(&self.entry_key, |bytes| {
            decode_entry(bytes, EntrySource::SdkLocal)
        })
        .await
    }

    async fn write_entry(&self, entry: &StoreEntry) -> Result<(), StoreWriteFailure> {
        self.store(&self.entry_key, &encode_entry(entry)).await
    }
}

impl<S: EncryptedStorage> RecoveryEventStore for SdkLocalMember<S> {
    async fn read_event(&self, event_digest: &[u8; 32]) -> MemberRead<Vec<u8>> {
        self.read_decoded(&self.credential_id.event_key(event_digest), |bytes| {
            check_event_length(bytes).map(|()| Some(bytes.to_vec()))
        })
        .await
    }

    async fn write_event(
        &self,
        event_digest: &[u8; 32],
        event: &[u8],
    ) -> Result<(), StoreWriteFailure> {
        self.store(&self.credential_id.event_key(event_digest), event)
            .await
    }
}

// ---------------------------------------------------------------------------
// The one-writer lease
// ---------------------------------------------------------------------------

/// A held lease's key: the credential identifier's bytes and the identity.
type LeaseKey = (Vec<u8>, [u8; 32]);

/// The registry of store-set leases over one local database.
///
/// A device runs one writer per `(credential_id, identifier)`: R10's
/// one-reveal-at-a-time rule reads every store and then writes, so two
/// writers on one device would each merge against a read the other's write
/// makes stale. The registry is keyed on the pair, not on a storage
/// instance, so two storage instances over one database share it when the
/// caller injects the registry for that database path into both. Clones
/// share the registry.
#[derive(Clone, Debug)]
pub struct RecoveryLeases {
    held: Arc<Mutex<HashSet<LeaseKey>>>,
}

impl RecoveryLeases {
    /// An empty registry, for one local database path.
    #[must_use]
    pub fn new() -> Self {
        Self {
            held: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Takes the lease on `credential_id`'s store set for `identifier`.
    /// Dropping the returned lease releases it.
    ///
    /// # Errors
    ///
    /// [`RecoveryStoreError::SetInUse`] while another lease on the pair is
    /// held.
    pub fn acquire(
        &self,
        credential_id: CredentialId,
        identifier: Identifier,
    ) -> Result<RecoveryLease, RecoveryStoreError> {
        let key = (credential_id.as_bytes().to_vec(), *identifier.as_bytes());
        // A poisoned lock means a holder panicked while inserting or
        // removing one key; the set is still a valid set of keys.
        let inserted = self
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key);
        if !inserted {
            return Err(RecoveryStoreError::SetInUse);
        }
        Ok(RecoveryLease {
            leases: self.clone(),
            credential_id,
            identifier,
        })
    }
}

impl Default for RecoveryLeases {
    fn default() -> Self {
        Self::new()
    }
}

/// A held lease on one credential's store set for one identity. A
/// [`StoreSet`](scp_kel::recovery_store::StoreSet) takes it and holds it for
/// its life; dropping it releases the pair.
#[derive(Debug)]
pub struct RecoveryLease {
    leases: RecoveryLeases,
    credential_id: CredentialId,
    identifier: Identifier,
}

impl SetLease for RecoveryLease {
    fn credential_id(&self) -> &CredentialId {
        &self.credential_id
    }

    fn identifier(&self) -> Identifier {
        self.identifier
    }
}

impl Drop for RecoveryLease {
    fn drop(&mut self) {
        let key = (
            self.credential_id.as_bytes().to_vec(),
            *self.identifier.as_bytes(),
        );
        self.leases
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&key);
    }
}
