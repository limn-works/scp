//! `Identity::abandon_pending` (`03-identity.md` §3.10.10;
//! `09-security-model.md` §9.7.4.2 R10): a device discards its own
//! `PendingSignatureRecord` and, on the composing device, its
//! `KeptComposition` for one event.

use std::future::Future;

use scp_did::Identifier;
use scp_platform::{
    EncryptedStorage, KeyHandle, NextSetCustodyError, NextSetKeyHandle, PlatformError,
};

use super::create::PendingEvent;
use super::device_record::{
    EventRef, delete_device_record, read_device_record, write_device_record,
};
use super::error::UndestroyedKey;
use super::{Identity, IdentityConfig, IdentityError};

impl<S: EncryptedStorage + Clone + 'static> Identity<S> {
    /// Discards this device's `PendingSignatureRecord` for `pending` and, on
    /// the composing device, its `KeptComposition`. No other device's state
    /// changes.
    ///
    /// On the composing device of an inception, where the record then holds
    /// no other entry, it first destroys the keys that composition minted,
    /// the next-set member, `#0` and `#active`, then removes the device
    /// record, because an inception never published installs those keys on
    /// no chain. Where another entry remains it removes only this event's
    /// entries and destroys no key, because that entry may record a released
    /// signature (§9.7.4.1 item 8; `17-persistence-and-storage.md` §17.3).
    ///
    /// Must be awaited inside a Tokio runtime: the work runs in a spawned
    /// task, so dropping the returned future leaves no key destroyed and the
    /// record still naming it.
    ///
    /// # Errors
    ///
    /// - [`IdentityError::NoPendingSignature`] where this device holds
    ///   neither a `PendingSignatureRecord` nor a `KeptComposition` for the
    ///   event.
    /// - [`IdentityError::CustodySigningFailed`] where a custody fails to
    ///   destroy a key; the record then stays as it was, naming every key.
    /// - [`IdentityError::PersistFailed`] where the device record cannot be
    ///   read or written, or the runtime cancelled the task.
    pub fn abandon_pending(
        config: &IdentityConfig<S>,
        pending: &PendingEvent,
    ) -> impl Future<Output = Result<(), IdentityError>> + Send + 'static {
        let config = config.clone();
        let identifier = pending.identifier;
        let event_digest = pending.event_digest;
        async move {
            let task = tokio::spawn(async move {
                all_destroyed(abandon_composition(&config, &identifier, &event_digest).await)
            });
            match task.await {
                Ok(result) => result,
                Err(join) if join.is_panic() => std::panic::resume_unwind(join.into_panic()),
                Err(join) => {
                    tracing::error!(%join, "the runtime cancelled abandon_pending");
                    Err(IdentityError::PersistFailed)
                }
            }
        }
    }
}

/// Maps a destroy pass that left keys live to SCP-IDENT-1111.
pub(super) fn all_destroyed(
    result: Result<Vec<UndestroyedKey>, IdentityError>,
) -> Result<(), IdentityError> {
    let undestroyed = result?;
    if undestroyed.is_empty() {
        Ok(())
    } else {
        Err(IdentityError::CustodySigningFailed)
    }
}

/// The body of `abandon_pending`, which the `create` guard, `create`'s
/// cleanup and `abandon_unfinished` also run. Returns every key it failed
/// to destroy; where that list is not empty the record stays as it was,
/// naming every key.
///
/// Holds the config's record lock across the read, the destroys and the
/// write, so two abandons in one process lose no update (§17.3). Destroys
/// before it writes.
///
/// # Errors
///
/// - [`IdentityError::NoPendingSignature`] where the record holds no entry
///   for `event_digest`.
/// - [`IdentityError::PersistFailed`] where the record cannot be read,
///   written or removed.
pub(super) async fn abandon_composition<S: EncryptedStorage + Clone>(
    config: &IdentityConfig<S>,
    identifier: &Identifier,
    event_digest: &[u8; 32],
) -> Result<Vec<UndestroyedKey>, IdentityError> {
    let not_held = IdentityError::NoPendingSignature {
        event_digest: *event_digest,
    };
    let _held = config.record_lock.hold().await;
    let Some(mut record) = read_device_record(&config.persistence, identifier).await? else {
        return Err(not_held);
    };
    let names = |entry: &EventRef| entry.event_digest == *event_digest;
    let kept = record.kept.iter().position(names);
    let signed = record.pending.iter().position(names);
    if kept.is_none() && signed.is_none() {
        return Err(not_held);
    }
    if let Some(index) = signed {
        record.pending.remove(index);
    }
    let composition = kept.map(|index| record.kept.remove(index));
    // An unpublished inception installs its keys on no chain: destroy them,
    // then remove the record that names them. Another entry may record a
    // released signature, which forbids destroying a standing next-set key
    // (§9.7.4.1 item 8), so then only this event's entries go.
    let sole = record.kept.is_empty() && record.pending.is_empty();
    if sole && composition.is_some_and(|entry| entry.sequence == 0) {
        let keys: Vec<KeyHandle> = record
            .root
            .iter()
            .map(|(_, handle)| *handle)
            .chain(record.active)
            .collect();
        let undestroyed = destroy_keys(config, &record.next, &keys).await;
        if !undestroyed.is_empty() {
            return Ok(undestroyed);
        }
        delete_device_record(&config.persistence, identifier).await?;
        return Ok(vec![]);
    }
    write_device_record(&config.persistence, identifier, &record).await?;
    Ok(vec![])
}

/// Destroys each next-set member and each key, attempting every handle, and
/// returns every one it failed to destroy. A handle the custody no longer
/// holds counts as destroyed, which a custody that never reissues an id
/// makes safe (`16-test-infrastructure.md` §16.12.3, §16.12.3a).
pub(super) async fn destroy_keys<S: EncryptedStorage + Clone>(
    config: &IdentityConfig<S>,
    next: &[NextSetKeyHandle],
    keys: &[KeyHandle],
) -> Vec<UndestroyedKey> {
    let mut undestroyed = Vec::new();
    for handle in next {
        match config.next_set_custody.destroy(handle).await {
            Ok(()) | Err(NextSetCustodyError::HandleNotFound) => {}
            Err(error) => {
                tracing::error!(%error, handle = handle.id(), "destroying a next-set member failed");
                undestroyed.push(UndestroyedKey::NextSetMember(*handle));
            }
        }
    }
    for key in keys {
        match config.custody.destroy_key(key).await {
            Ok(()) | Err(PlatformError::KeyNotFound) => {}
            Err(error) => {
                tracing::error!(%error, handle = key.id(), "destroying a root or #active key failed");
                undestroyed.push(UndestroyedKey::Key(*key));
            }
        }
    }
    undestroyed
}
