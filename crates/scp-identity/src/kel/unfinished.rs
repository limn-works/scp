//! `Identity::unfinished` and `Identity::abandon_unfinished`
//! (`03-identity.md` §3.10.10; `17-persistence-and-storage.md` §17.3): the
//! listing that reaches every key a creation or a composition left, and the
//! call that abandons one.

use std::future::Future;

use scp_did::Identifier;
use scp_platform::EncryptedStorage;

use super::abandon::{abandon_composition, all_destroyed, destroy_keys};
use super::creation_record::{
    CreationId, delete_creation_record, list_creations, read_creation_record,
};
use super::device_record::{DEVICE_RECORD_PREFIX, DEVICE_RECORD_SUFFIX, read_device_record};
use super::{Identity, IdentityConfig, IdentityError, parse_identifier};

/// An event that is not reveal-authorized, which this device composed and
/// returned as awaiting signatures and has not published
/// (`09-security-model.md` §9.7.4.2 R10, §9.18.17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeptComposition {
    /// The identity the event creates or extends.
    pub identifier: Identifier,
    /// The event's sequence.
    pub sequence: u64,
    /// SHA-256 of the event's signed preimage.
    pub event_digest: [u8; 32],
}

/// One item [`Identity::unfinished`] lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unfinished {
    /// A creation record a crash, a runtime shutdown or a failed cleanup
    /// left behind (§17.3).
    Creation(CreationId),
    /// A composition this device kept and has neither published nor
    /// abandoned.
    Composition(KeptComposition),
}

impl<S: EncryptedStorage + Clone + 'static> Identity<S> {
    /// Lists every creation record and every `KeptComposition` the config's
    /// store holds (§17.3): creations first, in key order, then each
    /// identity's compositions.
    ///
    /// # Errors
    ///
    /// [`IdentityError::PersistFailed`] where the store cannot be listed or
    /// read, or a key under a record prefix is not one `create` writes.
    pub fn unfinished(
        config: &IdentityConfig<S>,
    ) -> impl Future<Output = Result<Vec<Unfinished>, IdentityError>> + Send + 'static {
        let store = config.persistence.clone();
        async move {
            let mut items: Vec<Unfinished> = list_creations(&store)
                .await?
                .into_iter()
                .map(Unfinished::Creation)
                .collect();
            let keys = store
                .list_keys(DEVICE_RECORD_PREFIX)
                .await
                .map_err(|error| {
                    tracing::error!(%error, "listing device records failed");
                    IdentityError::PersistFailed
                })?;
            for key in &keys {
                let Some(component) = key
                    .strip_prefix(DEVICE_RECORD_PREFIX)
                    .and_then(|rest| rest.strip_suffix(DEVICE_RECORD_SUFFIX))
                    .filter(|component| !component.contains('/'))
                else {
                    // Another record under `identity/`, such as a creation
                    // record or a DID document (§17.3).
                    continue;
                };
                let identifier = parse_identifier(component).map_err(|error| {
                    tracing::error!(key, %error, "a device-record key names no identifier");
                    IdentityError::PersistFailed
                })?;
                let Some(record) = read_device_record(&store, &identifier).await? else {
                    continue;
                };
                items.extend(record.kept.iter().map(|entry| {
                    Unfinished::Composition(KeptComposition {
                        identifier: entry.identifier,
                        sequence: entry.sequence,
                        event_digest: entry.event_digest,
                    })
                }));
            }
            Ok(items)
        }
    }

    /// Abandons one listed item. For a creation it destroys every key the
    /// record names, treating a handle its custody no longer holds as
    /// destroyed, then deletes the record; for a composition it runs
    /// [`abandon_pending`](Self::abandon_pending)'s body.
    ///
    /// Must be awaited inside a Tokio runtime: the work runs in a spawned
    /// task, so dropping the returned future leaves the record naming every
    /// key it did not destroy.
    ///
    /// # Errors
    ///
    /// - [`IdentityError::NoUnfinishedCreation`] where the store holds no
    ///   record for the creation, so nothing was destroyed.
    /// - [`IdentityError::NoPendingSignature`] where the device record holds
    ///   no entry for the composition.
    /// - [`IdentityError::CustodySigningFailed`] where a custody fails to
    ///   destroy a key; the record then stays, naming every key.
    /// - [`IdentityError::PersistFailed`] where a record cannot be read,
    ///   written or removed, or the runtime cancelled the task.
    pub fn abandon_unfinished(
        config: &IdentityConfig<S>,
        item: &Unfinished,
    ) -> impl Future<Output = Result<(), IdentityError>> + Send + 'static {
        let config = config.clone();
        let item = *item;
        async move {
            let task = tokio::spawn(async move {
                match item {
                    Unfinished::Creation(creation) => abandon_creation(&config, creation).await,
                    Unfinished::Composition(kept) => all_destroyed(
                        abandon_composition(&config, &kept.identifier, &kept.event_digest).await,
                    ),
                }
            });
            match task.await {
                Ok(result) => result,
                Err(join) if join.is_panic() => std::panic::resume_unwind(join.into_panic()),
                Err(join) => {
                    tracing::error!(%join, "the runtime cancelled abandon_unfinished");
                    Err(IdentityError::PersistFailed)
                }
            }
        }
    }
}

/// Destroys every key `creation`'s record names, then deletes the record,
/// all under the record lock, so a `create` still running finds the record
/// gone at its next rewrite and cleans up after itself (§17.3).
async fn abandon_creation<S: EncryptedStorage + Clone>(
    config: &IdentityConfig<S>,
    creation: CreationId,
) -> Result<(), IdentityError> {
    let _held = config.record_lock.hold().await;
    let Some(record) = read_creation_record(&config.persistence, creation).await? else {
        return Err(IdentityError::NoUnfinishedCreation);
    };
    let next: Vec<_> = record.next.into_iter().collect();
    let undestroyed = destroy_keys(config, &next, &record.keys).await;
    if !undestroyed.is_empty() {
        return Err(IdentityError::CustodySigningFailed);
    }
    delete_creation_record(&config.persistence, creation).await
}
