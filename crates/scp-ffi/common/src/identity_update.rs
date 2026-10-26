//! One update at a time per identity on a bridge instance, which keeps the
//! callback custody identity entry (spec §17.3) in step with the registry.
//!
//! An operation that changes an identity's key handles or document (key
//! rotation, an agent key's addition, rotation or removal, a device
//! attestation, a migration) reads the identity's current state, publishes
//! the changed document, rewrites the callback custody entry and installs
//! the change in the bridge's registries. Two such operations running at
//! once on one identity would each start from the same state, publish
//! different documents, and leave the registry on one and the stored entry
//! on the other, so a restart would restore a retired key.
//!
//! [`IdentityUpdates::lock`] serializes them: each operation holds an
//! [`IdentityUpdateGuard`] for its DID from its read through its install,
//! and [`IdentityUpdateGuard::commit`] records the state the operation installed
//! in the guard's slot, so the next operation on that DID starts from it,
//! even when its caller passes a handle taken before the change. A
//! migration marks the retired DID's slot, and a later lock of that DID
//! fails with [`IdentityUpdateError::Migrated`].
//!
//! The guard is the only way to rewrite a callback custody entry after a
//! change ([`crate::callback_identity::rewrite_entry`] takes it), so an
//! operation cannot rewrite the entry without holding the lock.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use scp_did::DidDocument;
use scp_identity::dht::ScpIdentity;
use tokio::sync::OwnedMutexGuard;

use crate::error_codes;

/// The identity state the last update of a DID installed.
#[derive(Debug, Clone)]
pub struct CommittedIdentity {
    /// The identity's key handles after the update.
    pub identity: ScpIdentity,
    /// The document the update published.
    pub document: DidDocument,
}

/// What one DID's slot records.
#[derive(Debug, Default)]
enum Slot {
    /// No update has installed a change since the slot was created; the
    /// bridge's own state for the DID is current.
    #[default]
    Unchanged,
    /// The state the last update installed.
    Current(Box<CommittedIdentity>),
    /// A migration moved the identity to this DID.
    Migrated(String),
}

/// Why an update could not start.
#[derive(Debug, thiserror::Error)]
pub enum IdentityUpdateError {
    /// The DID was retired by a migration that installed while this update
    /// waited; the identity now lives under `to`.
    #[error("identity '{did}' was migrated to '{to}'; update the migrated identity")]
    Migrated {
        /// The retired DID the update named.
        did: String,
        /// The DID the migration moved the identity to.
        to: String,
    },
}

impl IdentityUpdateError {
    /// The SDK error code: the retired DID no longer names a live identity,
    /// `SCP-IDENT-1002`.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Migrated { .. } => error_codes::IDENT_1002,
        }
    }
}

type Slots = Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<Slot>>>>>;

/// Proof that the holder is the one update running on [`did`](Self::did).
#[derive(Debug)]
pub struct IdentityUpdateGuard {
    did: String,
    slot: OwnedMutexGuard<Slot>,
    slots: Slots,
}

impl IdentityUpdateGuard {
    /// The DID this guard serializes.
    #[must_use]
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The state the last update of this DID installed, or `None` when no
    /// update installed one since the slot was created, so the caller's own
    /// view of the identity is current.
    #[must_use]
    pub fn committed(&self) -> Option<&CommittedIdentity> {
        match &*self.slot {
            Slot::Current(committed) => Some(committed),
            Slot::Unchanged | Slot::Migrated(_) => None,
        }
    }

    /// Records `identity` and `document` as the state this update installed.
    /// When `identity` names another DID (a migration), the guard's DID is
    /// marked retired and the new DID's slot starts from the migrated state.
    pub fn commit(&mut self, identity: ScpIdentity, document: DidDocument) {
        if identity.did == self.did {
            *self.slot = Slot::Current(Box::new(CommittedIdentity { identity, document }));
            return;
        }
        let to = identity.did.clone();
        *self.slot = Slot::Migrated(to.clone());
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        slots.insert(
            to,
            Arc::new(tokio::sync::Mutex::new(Slot::Current(Box::new(
                CommittedIdentity { identity, document },
            )))),
        );
    }
}

/// The per-DID update slots of one bridge instance.
#[derive(Debug, Default)]
pub struct IdentityUpdates {
    slots: Slots,
}

impl IdentityUpdates {
    /// An empty set of slots.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn slot(&self, did: &str) -> Arc<tokio::sync::Mutex<Slot>> {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(slots.entry(did.to_owned()).or_default())
    }

    /// Waits until no other update of `did` runs on this instance and
    /// returns the guard that holds it.
    ///
    /// # Errors
    ///
    /// [`IdentityUpdateError::Migrated`] when a migration retired `did`.
    pub async fn lock(&self, did: &str) -> Result<IdentityUpdateGuard, IdentityUpdateError> {
        let slot = self.slot(did).lock_owned().await;
        if let Slot::Migrated(to) = &*slot {
            return Err(IdentityUpdateError::Migrated {
                did: did.to_owned(),
                to: to.clone(),
            });
        }
        Ok(IdentityUpdateGuard {
            did: did.to_owned(),
            slot,
            slots: Arc::clone(&self.slots),
        })
    }
}

impl Drop for IdentityUpdateGuard {
    /// Removes the slot when this update installed nothing and no other
    /// update holds or waits on it, so a DID that names no identity (a
    /// refused or failed update) leaves no slot behind. Every holder and
    /// waiter clones the slot under the table lock, so the count read under
    /// it is exact.
    fn drop(&mut self) {
        if !matches!(*self.slot, Slot::Unchanged) {
            return;
        }
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        let ours = OwnedMutexGuard::mutex(&self.slot);
        if slots
            .get(&self.did)
            .is_some_and(|slot| Arc::ptr_eq(slot, ours) && Arc::strong_count(ours) == 2)
        {
            slots.remove(&self.did);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(did: &str, seed: u64) -> ScpIdentity {
        ScpIdentity {
            identity_key: scp_platform::KeyHandle::new(seed),
            active_signing_key: scp_platform::KeyHandle::new(seed + 1),
            agent_signing_key: None,
            pre_rotation_commitment: [0; 32],
            did: did.to_owned(),
        }
    }

    fn document(did: &str) -> DidDocument {
        DidDocument {
            context: vec![],
            id: did.to_owned(),
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            also_known_as: vec![],
            service: vec![],
        }
    }

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn slot_count(updates: &IdentityUpdates) -> usize {
        updates
            .slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// A second update of one DID waits for the first, then starts from the
    /// state the first installed rather than from its caller's stale view.
    #[tokio::test]
    async fn a_second_update_starts_from_the_first_ones_result() -> TestResult {
        let updates = Arc::new(IdentityUpdates::new());
        let did = "did:dht:a";
        let mut first = updates.lock(did).await?;
        let waiter = {
            let updates = Arc::clone(&updates);
            tokio::spawn(async move {
                let second = updates.lock(did).await?;
                Ok::<_, IdentityUpdateError>(second.committed().map(|c| c.identity.clone()))
            })
        };
        tokio::task::yield_now().await;
        assert!(
            !waiter.is_finished(),
            "the second update waits for the first"
        );
        first.commit(identity(did, 10), document(did));
        drop(first);
        let seen = waiter.await??;
        assert_eq!(
            seen.map(|s| s.active_signing_key),
            Some(scp_platform::KeyHandle::new(11))
        );
        Ok(())
    }

    /// An update that installs nothing leaves no slot; one that waits keeps
    /// the slot alive until it runs.
    #[tokio::test]
    async fn an_update_that_installs_nothing_leaves_no_slot() -> TestResult {
        let updates = Arc::new(IdentityUpdates::new());
        drop(updates.lock("did:dht:none").await?);
        assert_eq!(slot_count(&updates), 0);

        let first = updates.lock("did:dht:a").await?;
        let waiter = {
            let updates = Arc::clone(&updates);
            tokio::spawn(async move { updates.lock("did:dht:a").await.map(drop) })
        };
        tokio::task::yield_now().await;
        drop(first);
        assert_eq!(slot_count(&updates), 1);
        waiter.await??;
        assert_eq!(slot_count(&updates), 0);
        Ok(())
    }

    /// A migration retires the old DID: a later update of it is refused, and
    /// the new DID starts from the migrated state.
    #[tokio::test]
    async fn a_migration_retires_the_old_did() -> TestResult {
        let updates = IdentityUpdates::new();
        let mut guard = updates.lock("did:dht:old").await?;
        guard.commit(identity("did:dht:new", 20), document("did:dht:new"));
        drop(guard);
        let refused = updates.lock("did:dht:old").await.err();
        assert_eq!(
            refused.as_ref().map(IdentityUpdateError::code),
            Some(error_codes::IDENT_1002)
        );
        let moved = updates.lock("did:dht:new").await?;
        let migrated = moved.committed().map(|c| c.identity.identity_key);
        drop(moved);
        assert_eq!(migrated, Some(scp_platform::KeyHandle::new(20)));
        Ok(())
    }
}
