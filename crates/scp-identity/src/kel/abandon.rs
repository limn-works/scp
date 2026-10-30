//! `Identity::abandon_pending` (`03-identity.md` §3.10.10;
//! `09-security-model.md` §9.7.4.2 R10): a device discards its own
//! `PendingSignatureRecord` and, on the composing device, its
//! `KeptComposition` for one event.

use std::future::Future;

use scp_platform::{
    EncryptedStorage, KeyHandle, NextSetCustodyError, NextSetKeyHandle, PlatformError,
};

use super::create::PendingEvent;
use super::device_record::{delete_device_record, read_device_record, write_device_record};
use super::{Identity, IdentityConfig, IdentityError};

impl<S: EncryptedStorage + Clone + 'static> Identity<S> {
    /// Discards this device's `PendingSignatureRecord` for `pending` and, on
    /// the composing device, its `KeptComposition`. No other device's state
    /// changes.
    ///
    /// On the composing device of an inception it first destroys the keys
    /// that composition minted, the next-set member, `#0` and `#active`,
    /// then removes the device record, because an inception never published
    /// installs those keys on no chain. Call it only while no signature over
    /// the event has been released (§9.7.4.1 item 8).
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
        let pending = pending.clone();
        async move {
            let task = tokio::spawn(async move { abandon_composition(&config, &pending).await });
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

/// The body of `abandon_pending`, which the `create` guard also runs.
///
/// Destroys before it writes, so a failure leaves a record that still names
/// every key it held.
pub(super) async fn abandon_composition<S: EncryptedStorage + Clone>(
    config: &IdentityConfig<S>,
    pending: &PendingEvent,
) -> Result<(), IdentityError> {
    let not_held = IdentityError::NoPendingSignature {
        event_digest: pending.event_digest,
    };
    let Some(mut record) = read_device_record(&config.persistence, &pending.identifier).await?
    else {
        return Err(not_held);
    };
    let names = |entry: &super::device_record::EventRef| entry.event_digest == pending.event_digest;
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
    // then remove the record that names them.
    if composition.is_some_and(|entry| entry.sequence == 0) {
        let keys: Vec<KeyHandle> = record
            .root
            .iter()
            .map(|(_, handle)| *handle)
            .chain(record.active)
            .collect();
        destroy_keys(config, &record.next, &keys).await?;
        return delete_device_record(&config.persistence, &pending.identifier).await;
    }
    write_device_record(&config.persistence, &pending.identifier, &record).await
}

/// Destroys each next-set member and each key. A handle the custody no
/// longer holds counts as destroyed. Every handle is attempted before a
/// failure is reported.
///
/// # Errors
///
/// [`IdentityError::CustodySigningFailed`] where any destruction failed
/// for a reason other than an absent handle.
pub(super) async fn destroy_keys<S: EncryptedStorage + Clone>(
    config: &IdentityConfig<S>,
    next: &[NextSetKeyHandle],
    keys: &[KeyHandle],
) -> Result<(), IdentityError> {
    let mut failed = false;
    for handle in next {
        match config.next_set_custody.destroy(handle).await {
            Ok(()) | Err(NextSetCustodyError::HandleNotFound) => {}
            Err(error) => {
                tracing::error!(%error, "destroying a next-set member failed");
                failed = true;
            }
        }
    }
    for key in keys {
        match config.custody.destroy_key(key).await {
            Ok(()) | Err(PlatformError::KeyNotFound) => {}
            Err(error) => {
                tracing::error!(%error, "destroying a root or #active key failed");
                failed = true;
            }
        }
    }
    if failed {
        Err(IdentityError::CustodySigningFailed)
    } else {
        Ok(())
    }
}
