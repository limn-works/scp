//! The callback custody identity entry (spec §17.3, SCP-345 decision D1).
//!
//! An identity created with a host custody provider keeps, at
//! `identity/{did}/callback_custody`, a `StoredValue` of its custody
//! namespace, its [`ScpIdentity`] (key handles and pre-rotation commitment)
//! and its DID document. The create path draws the namespace
//! ([`create_records`]) and writes the entry ([`write_entry`]) before it
//! returns. The load path reads the entry and reopens the records over the
//! stored namespace ([`open_entry`]), never a new one, then checks that the
//! provider it was given holds the identity key the DID derives from
//! ([`check_provider`]). Both refuse storage that does not persist.
//!
//! Every bridge maps a [`CallbackIdentityError`] to the code
//! [`CallbackIdentityError::code`] names, so the three bridges refuse alike.

use std::fmt;

use scp_did::DidDocument;
use scp_identity::ScpIdentity;
use scp_platform::store_value::{
    from_stored_value_bytes, sanitize_key_component, to_stored_value_bytes,
};
use scp_platform::{KeyCustody, KeyHandle, PlatformError, Storage};

use crate::callback_custody::{CustodyLoadError, CustodyRecords};
use crate::custody_namespace::{CustodyNamespace, CustodyNamespaces};
use crate::error_codes;
use crate::identity_update::IdentityUpdateGuard;

/// Why a callback custody identity could not be created or loaded.
#[derive(Debug)]
pub enum CallbackIdentityError {
    /// The instance storage does not persist (the `in_memory` selection,
    /// spec §17.6): the entry and the custody records would end with the
    /// instance while the host keys remain.
    NotPersistent,
    /// `identity_load` was called for an identity that has a callback
    /// custody entry; only `identity_load_with_custody`, which takes the
    /// provider, loads it.
    ProviderRequired,
    /// The storage holds no callback custody entry for the DID.
    EntryAbsent,
    /// The entry does not decode; it is never replaced by a default.
    EntryUndecodable(String),
    /// The entry names another DID than the one requested.
    EntryDidMismatch {
        /// The DID the entry names.
        stored: String,
    },
    /// The DID cannot form a storage key (spec §17.3 key components).
    InvalidDid(String),
    /// The instance storage failed.
    Storage(PlatformError),
    /// The custody namespace could not be drawn or opened.
    Records(CustodyLoadError),
    /// The provider could not report the identity key.
    Provider(PlatformError),
    /// The provider's identity key does not derive the stored DID.
    ProviderMismatch,
    /// The create failed with `cause`, and destroying the keys it minted
    /// failed too, so the host still holds the keys `orphaned` names.
    KeysOrphaned {
        /// Why the create failed.
        cause: Box<Self>,
        /// Each minted key the destroy left, with the destroy's error.
        orphaned: Vec<(KeyHandle, PlatformError)>,
    },
}

impl CallbackIdentityError {
    /// The error code every bridge reports for this refusal.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NotPersistent => error_codes::STORAGE_8000,
            Self::ProviderRequired => error_codes::IDENT_1003,
            Self::EntryAbsent => error_codes::IDENT_1002,
            Self::EntryUndecodable(_)
            | Self::EntryDidMismatch { .. }
            | Self::InvalidDid(_)
            | Self::Storage(_) => error_codes::IDENT_1009,
            Self::Records(_) | Self::Provider(_) | Self::ProviderMismatch => {
                error_codes::IDENT_1008
            }
            Self::KeysOrphaned { cause, .. } => cause.code(),
        }
    }

    /// Whether the refusal is about the instance storage selection, which
    /// each bridge reports in its storage error class, not its identity one.
    #[must_use]
    pub fn is_storage_selection(&self) -> bool {
        match self {
            Self::NotPersistent => true,
            Self::KeysOrphaned { cause, .. } => cause.is_storage_selection(),
            _ => false,
        }
    }
}

impl fmt::Display for CallbackIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPersistent => f.write_str(
                "callback custody needs storage that persists: its identity entry and key \
                 records would end with this in-memory instance while the host keys remain; \
                 select {\"type\": \"sqlite\", ...} storage (spec section 17.6)",
            ),
            Self::ProviderRequired => f.write_str(
                "this identity keeps its keys in a host custody provider; load it with \
                 identity_load_with_custody and the provider (spec 03 section 3.2.2)",
            ),
            Self::EntryAbsent => f.write_str(
                "no callback custody identity entry is stored for this DID; was it created \
                 with identity_create_with_custody on this storage?",
            ),
            Self::EntryUndecodable(detail) => {
                write!(
                    f,
                    "the callback custody identity entry does not decode: {detail}"
                )
            }
            Self::EntryDidMismatch { stored } => write!(
                f,
                "the callback custody identity entry names another DID: {stored}"
            ),
            Self::InvalidDid(did) => write!(f, "the DID cannot form a storage key: {did}"),
            Self::Storage(e) => write!(f, "callback custody identity entry storage failed: {e}"),
            Self::Records(e) => write!(f, "{e}"),
            Self::Provider(e) => write!(
                f,
                "the custody provider could not report the identity key: {e}"
            ),
            Self::ProviderMismatch => f.write_str(
                "the custody provider's identity key does not derive this DID; pass the \
                 provider that created the identity",
            ),
            Self::KeysOrphaned { cause, orphaned } => {
                write!(
                    f,
                    "{cause}; destroying the keys the create minted then failed, and the host \
                     still holds"
                )?;
                for (key, e) in orphaned {
                    write!(f, " key_id {} ({e})", key.id())?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for CallbackIdentityError {}

impl From<CustodyLoadError> for CallbackIdentityError {
    fn from(e: CustodyLoadError) -> Self {
        Self::Records(e)
    }
}

/// The storage key of `did`'s callback custody identity entry:
/// `identity/{did}/callback_custody` (spec §17.3).
///
/// # Errors
///
/// [`CallbackIdentityError::InvalidDid`] when `did` is not a valid key
/// component.
pub fn entry_key(did: &str) -> Result<String, CallbackIdentityError> {
    let did = sanitize_key_component(did)
        .map_err(|_| CallbackIdentityError::InvalidDid(did.to_owned()))?;
    Ok(format!("identity/{did}/callback_custody"))
}

/// The custody records of a new callback identity, under a namespace drawn
/// from the operating system's random source and opened through the
/// instance's `table`. The only path that draws a namespace.
///
/// `storage` is `None` when the instance storage does not persist.
///
/// # Errors
///
/// [`CallbackIdentityError::NotPersistent`] for `None`, and
/// [`CallbackIdentityError::Records`] when no namespace can be drawn.
pub fn create_records<S>(
    table: &CustodyNamespaces,
    storage: Option<S>,
) -> Result<CustodyRecords, CallbackIdentityError>
where
    S: Storage + Send + Sync + 'static,
{
    let storage = storage.ok_or(CallbackIdentityError::NotPersistent)?;
    Ok(CustodyRecords::create(table, storage)?)
}

/// Writes the callback custody identity entry of `identity` under its DID.
///
/// # Errors
///
/// [`CallbackIdentityError::InvalidDid`], [`CallbackIdentityError::Storage`],
/// or [`CallbackIdentityError::EntryUndecodable`] when the entry does not
/// encode.
async fn write_entry<S: Storage + ?Sized>(
    storage: &S,
    namespace: [u8; 16],
    identity: &ScpIdentity,
    document: &DidDocument,
) -> Result<(), CallbackIdentityError> {
    let key = entry_key(&identity.did)?;
    let bytes = to_stored_value_bytes(&(namespace, identity, document))
        .map_err(|e| CallbackIdentityError::EntryUndecodable(e.to_string()))?;
    storage
        .store(&key, &bytes)
        .await
        .map_err(CallbackIdentityError::Storage)
}

/// Writes the callback custody identity entry of an identity just created
/// over `custody`, whose records live under `namespace` (spec §17.3).
///
/// A failed write fails the create, and no later load could reach the keys
/// the create minted, so they are destroyed through `custody` (host key and
/// custody record) before the error returns. A key the host already lacks
/// counts as destroyed.
///
/// `storage` is `None` when the instance storage stopped persisting.
///
/// # Errors
///
/// The write's [`CallbackIdentityError`], or
/// [`CallbackIdentityError::KeysOrphaned`] carrying it when a destroy failed
/// too.
pub async fn write_created_entry<S, C>(
    storage: Option<&S>,
    custody: &C,
    namespace: [u8; 16],
    identity: &ScpIdentity,
    document: &DidDocument,
) -> Result<(), CallbackIdentityError>
where
    S: Storage + ?Sized,
    C: KeyCustody,
{
    let written = match storage {
        Some(storage) => write_entry(storage, namespace, identity, document).await,
        None => Err(CallbackIdentityError::NotPersistent),
    };
    let Err(cause) = written else {
        return Ok(());
    };
    let minted = [
        identity.agent_signing_key,
        Some(identity.active_signing_key),
        Some(identity.identity_key),
    ];
    let mut orphaned = Vec::new();
    for key in minted.into_iter().flatten() {
        match custody.destroy_key(&key).await {
            Ok(()) | Err(PlatformError::KeyNotFound) => {}
            Err(e) => orphaned.push((key, e)),
        }
    }
    if orphaned.is_empty() {
        Err(cause)
    } else {
        Err(CallbackIdentityError::KeysOrphaned {
            cause: Box::new(cause),
            orphaned,
        })
    }
}

/// Rewrites the callback custody identity entry after an operation changed
/// the identity's key handles or document (spec §17.3).
///
/// The operations are rotation of the active or agent key, an agent key's
/// addition or removal, a device attestation, and a migration. The entry keeps `namespace` and takes `identity`
/// and `document`, under `identity`'s DID; when the operation moved the
/// identity to a new DID, the entry under the DID `update` holds is removed
/// after the new one is written, so a load of the retired DID finds no entry.
///
/// Every bridge runs this before it installs the change in its registry, so
/// a restart loads the identity as it was after the change. `update` is the
/// operation's hold on its DID ([`crate::identity_update`]), so no other
/// update of the identity reads, publishes or rewrites until this one
/// installs.
///
/// `storage` is `None` when the instance storage stopped persisting.
///
/// # Errors
///
/// [`CallbackIdentityError::NotPersistent`] for `None`;
/// [`CallbackIdentityError::InvalidDid`], [`CallbackIdentityError::Storage`]
/// or [`CallbackIdentityError::EntryUndecodable`] when the write or the
/// removal fails.
pub async fn rewrite_entry<S: Storage + ?Sized>(
    storage: Option<&S>,
    namespace: [u8; 16],
    update: &IdentityUpdateGuard,
    identity: &ScpIdentity,
    document: &DidDocument,
) -> Result<(), CallbackIdentityError> {
    let storage = storage.ok_or(CallbackIdentityError::NotPersistent)?;
    let previous_did = update.did();
    let retired = if previous_did == identity.did {
        None
    } else {
        Some(entry_key(previous_did)?)
    };
    write_entry(storage, namespace, identity, document).await?;
    if let Some(key) = retired {
        storage
            .delete(&key)
            .await
            .map_err(CallbackIdentityError::Storage)?;
    }
    Ok(())
}

/// Refuses a provider-less `identity_load` of a DID that has a callback
/// custody entry in `storage`.
///
/// # Errors
///
/// [`CallbackIdentityError::ProviderRequired`] when the entry exists;
/// [`CallbackIdentityError::InvalidDid`] or [`CallbackIdentityError::Storage`]
/// when the check cannot run.
pub async fn refuse_plain_load<S: Storage + ?Sized>(
    storage: &S,
    did: &str,
) -> Result<(), CallbackIdentityError> {
    let key = entry_key(did)?;
    if storage
        .exists(&key)
        .await
        .map_err(CallbackIdentityError::Storage)?
    {
        return Err(CallbackIdentityError::ProviderRequired);
    }
    Ok(())
}

/// A callback custody identity read from its entry, with its records open
/// over the stored namespace.
#[derive(Debug)]
pub struct LoadedCallbackIdentity {
    /// The identity's custody records, live in the instance's table until
    /// they drop.
    pub records: CustodyRecords,
    /// The identity's key handles, pre-rotation commitment and DID.
    pub identity: ScpIdentity,
    /// The identity's DID document.
    pub document: DidDocument,
}

/// Reads `did`'s callback custody identity entry and opens its records over
/// the stored namespace through the instance's `table`.
///
/// `storage` is `None` when the instance storage does not persist.
///
/// # Errors
///
/// [`CallbackIdentityError::NotPersistent`] for `None`;
/// [`CallbackIdentityError::EntryAbsent`] with no entry;
/// [`CallbackIdentityError::EntryUndecodable`] or
/// [`CallbackIdentityError::EntryDidMismatch`] for a bad entry;
/// [`CallbackIdentityError::Records`] with
/// [`CustodyLoadError::NamespaceLive`] while another adapter of the instance
/// holds the namespace.
pub async fn open_entry<S>(
    table: &CustodyNamespaces,
    storage: Option<S>,
    did: &str,
) -> Result<LoadedCallbackIdentity, CallbackIdentityError>
where
    S: Storage + Send + Sync + 'static,
{
    let storage = storage.ok_or(CallbackIdentityError::NotPersistent)?;
    let key = entry_key(did)?;
    let bytes = storage
        .retrieve(&key)
        .await
        .map_err(CallbackIdentityError::Storage)?
        .ok_or(CallbackIdentityError::EntryAbsent)?;
    let (namespace, identity, document): ([u8; 16], ScpIdentity, DidDocument) =
        from_stored_value_bytes(&bytes)
            .map_err(|e| CallbackIdentityError::EntryUndecodable(e.to_string()))?;
    if identity.did != did {
        return Err(CallbackIdentityError::EntryDidMismatch {
            stored: identity.did,
        });
    }
    let records = CustodyRecords::open(table, storage, CustodyNamespace::from_bytes(namespace))?;
    Ok(LoadedCallbackIdentity {
        records,
        identity,
        document,
    })
}

/// Checks that `custody`, the adapter over the provider a load was given,
/// holds the identity key `identity.did` derives from, and returns that
/// key's public key as lowercase hex for the handle.
///
/// # Errors
///
/// [`CallbackIdentityError::Provider`] when the adapter cannot report the
/// key; [`CallbackIdentityError::ProviderMismatch`] when the key does not
/// derive the DID.
pub async fn check_provider<C: KeyCustody + ?Sized>(
    custody: &C,
    identity: &ScpIdentity,
) -> Result<String, CallbackIdentityError> {
    let public = custody
        .public_key(&identity.identity_key)
        .await
        .map_err(CallbackIdentityError::Provider)?;
    let derived = scp_identity::extract_public_key(&identity.did)
        .map_err(|_| CallbackIdentityError::ProviderMismatch)?;
    if public.as_bytes() == derived.as_slice() {
        Ok(hex::encode(public.as_bytes()))
    } else {
        Err(CallbackIdentityError::ProviderMismatch)
    }
}

#[cfg(all(test, feature = "testing"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;

    use scp_identity::DidMethod;
    use scp_platform::in_memory::InMemoryStorage;
    use scp_platform::testing::{InMemoryKeyCustody, InMemoryPreRotationCustody};

    use super::*;
    use crate::identity_update::IdentityUpdates;

    async fn minted(custody: &InMemoryKeyCustody) -> (ScpIdentity, DidDocument) {
        let (identity, document, _) =
            scp_identity::DidDht::with_client(Arc::new(scp_dht::InMemoryDhtClient::new()))
                .create(custody, &InMemoryPreRotationCustody::new())
                .await
                .unwrap();
        (identity, document)
    }

    /// The entry written at create reopens the records under the same
    /// namespace, with the same handles and document; a second open while
    /// the first records live is refused, and opens again once they drop.
    #[tokio::test]
    async fn the_entry_reopens_the_created_namespace_once_at_a_time() {
        let storage = Arc::new(InMemoryStorage::new());
        let table = CustodyNamespaces::new();
        let created = create_records(&table, Some(Arc::clone(&storage))).unwrap();
        let namespace = created.namespace();
        let custody = InMemoryKeyCustody::new();
        let (identity, document) = minted(&custody).await;
        write_entry(storage.as_ref(), namespace, &identity, &document)
            .await
            .unwrap();

        // The create's adapter still holds the namespace.
        assert!(matches!(
            open_entry(&table, Some(Arc::clone(&storage)), &identity.did).await,
            Err(CallbackIdentityError::Records(
                CustodyLoadError::NamespaceLive
            ))
        ));
        drop(created);

        let loaded = open_entry(&table, Some(Arc::clone(&storage)), &identity.did)
            .await
            .unwrap();
        assert_eq!(loaded.records.namespace(), namespace);
        assert_eq!(loaded.identity.did, identity.did);
        assert_eq!(loaded.identity.identity_key, identity.identity_key);
        assert_eq!(loaded.document, document);
        let second = open_entry(&table, Some(Arc::clone(&storage)), &identity.did)
            .await
            .unwrap_err();
        assert_eq!(second.code(), error_codes::IDENT_1008);
        drop(loaded);
        open_entry(&table, Some(storage), &identity.did)
            .await
            .unwrap();
    }

    /// Storage that does not persist is refused on create and load with
    /// `SCP-STORAGE-8000`, in the storage class.
    #[tokio::test]
    async fn storage_that_does_not_persist_is_refused() {
        let table = CustodyNamespaces::new();
        let create = create_records::<Arc<InMemoryStorage>>(&table, None).unwrap_err();
        let load = open_entry::<Arc<InMemoryStorage>>(&table, None, "did:dht:x")
            .await
            .unwrap_err();
        for e in [create, load] {
            assert_eq!(e.code(), error_codes::STORAGE_8000);
            assert!(e.is_storage_selection());
        }
    }

    /// No entry is `SCP-IDENT-1002`; an undecodable entry and an entry
    /// naming another DID are `SCP-IDENT-1009`, never a default.
    #[tokio::test]
    async fn absent_and_bad_entries_are_refused() {
        let storage = Arc::new(InMemoryStorage::new());
        let table = CustodyNamespaces::new();
        let custody = InMemoryKeyCustody::new();
        let (identity, document) = minted(&custody).await;
        let absent = open_entry(&table, Some(Arc::clone(&storage)), &identity.did)
            .await
            .unwrap_err();
        assert_eq!(absent.code(), error_codes::IDENT_1002);

        storage
            .store(&entry_key(&identity.did).unwrap(), b"junk")
            .await
            .unwrap();
        let junk = open_entry(&table, Some(Arc::clone(&storage)), &identity.did)
            .await
            .unwrap_err();
        assert!(matches!(junk, CallbackIdentityError::EntryUndecodable(_)));
        assert_eq!(junk.code(), error_codes::IDENT_1009);

        // The entry of `identity` stored under another DID's key.
        let (other, _) = minted(&InMemoryKeyCustody::new()).await;
        let bytes = to_stored_value_bytes(&([7u8; 16], &identity, &document)).unwrap();
        storage
            .store(&entry_key(&other.did).unwrap(), &bytes)
            .await
            .unwrap();
        let moved = open_entry(&table, Some(storage), &other.did)
            .await
            .unwrap_err();
        assert!(matches!(
            moved,
            CallbackIdentityError::EntryDidMismatch { .. }
        ));
        assert_eq!(moved.code(), error_codes::IDENT_1009);
    }

    /// A rewrite replaces the entry under the same DID, so the load returns
    /// the changed handles and document; a rewrite to a new DID moves the
    /// entry, so the retired DID has none; no storage is `SCP-STORAGE-8000`.
    #[tokio::test]
    async fn a_rewrite_replaces_the_entry_and_a_migration_moves_it() {
        let storage = Arc::new(InMemoryStorage::new());
        let table = CustodyNamespaces::new();
        let custody = InMemoryKeyCustody::new();
        let (identity, document) = minted(&custody).await;
        write_entry(storage.as_ref(), [3; 16], &identity, &document)
            .await
            .unwrap();

        let mut changed = identity.clone();
        changed.active_signing_key = custody
            .generate_keypair(scp_platform::KeyType::Ed25519)
            .await
            .unwrap();
        let mut changed_document = document.clone();
        changed_document
            .also_known_as
            .push("did:dht:changed".to_owned());
        let updates = IdentityUpdates::new();
        let update = updates.lock(&identity.did).await.unwrap();
        rewrite_entry(
            Some(storage.as_ref()),
            [3; 16],
            &update,
            &changed,
            &changed_document,
        )
        .await
        .unwrap();
        let loaded = open_entry(&table, Some(Arc::clone(&storage)), &identity.did)
            .await
            .unwrap();
        assert_eq!(loaded.records.namespace(), [3; 16]);
        assert_eq!(
            loaded.identity.active_signing_key,
            changed.active_signing_key
        );
        assert_eq!(loaded.document, changed_document);
        drop(loaded);

        let (moved, moved_document) = minted(&InMemoryKeyCustody::new()).await;
        rewrite_entry(
            Some(storage.as_ref()),
            [3; 16],
            &update,
            &moved,
            &moved_document,
        )
        .await
        .unwrap();
        let retired = open_entry(&table, Some(Arc::clone(&storage)), &identity.did)
            .await
            .unwrap_err();
        assert_eq!(retired.code(), error_codes::IDENT_1002);
        let loaded = open_entry(&table, Some(Arc::clone(&storage)), &moved.did)
            .await
            .unwrap();
        assert_eq!(loaded.document, moved_document);

        drop(update);
        let update = updates.lock(&moved.did).await.unwrap();
        let absent =
            rewrite_entry::<InMemoryStorage>(None, [3; 16], &update, &moved, &moved_document)
                .await
                .unwrap_err();
        drop(update);
        assert!(absent.is_storage_selection());
    }

    /// A provider-less load of a DID with an entry is `SCP-IDENT-1003`; a
    /// DID without one passes.
    #[tokio::test]
    async fn a_plain_load_of_a_callback_identity_is_refused() {
        let storage = InMemoryStorage::new();
        let custody = InMemoryKeyCustody::new();
        let (identity, document) = minted(&custody).await;
        refuse_plain_load(&storage, &identity.did).await.unwrap();
        write_entry(&storage, [1; 16], &identity, &document)
            .await
            .unwrap();
        let e = refuse_plain_load(&storage, &identity.did)
            .await
            .unwrap_err();
        assert!(matches!(e, CallbackIdentityError::ProviderRequired));
        assert_eq!(e.code(), error_codes::IDENT_1003);
    }

    /// The provider that minted the identity passes; one holding another
    /// identity key at the same handle is `ProviderMismatch`; one without
    /// the key is `Provider`.
    #[tokio::test]
    async fn the_provider_must_hold_the_did_key() {
        let custody = InMemoryKeyCustody::new();
        let (identity, _) = minted(&custody).await;
        assert_eq!(
            check_provider(&custody, &identity).await.unwrap(),
            hex::encode(scp_identity::extract_public_key(&identity.did).unwrap())
        );

        let other = InMemoryKeyCustody::new();
        let (other_identity, _) = minted(&other).await;
        assert_eq!(other_identity.identity_key, identity.identity_key);
        assert!(matches!(
            check_provider(&other, &identity).await,
            Err(CallbackIdentityError::ProviderMismatch)
        ));
        assert!(matches!(
            check_provider(&InMemoryKeyCustody::new(), &identity).await,
            Err(CallbackIdentityError::Provider(_))
        ));
    }
}
