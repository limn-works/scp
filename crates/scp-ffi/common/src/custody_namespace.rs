//! The custody record store over the instance storage, and the table of
//! custody namespaces that admits one live store per namespace (spec §17.3
//! `custody/record/{namespace}/{key_id}`; SCP-345).
//!
//! Each record store is scoped to one [`CustodyNamespace`], drawn when its
//! identity is created and stored with the identity. Two identities whose
//! hosts reuse a key id therefore never read, overwrite or delete each
//! other's record. [`CustodyNamespaces::open`] is the only way to build a
//! store, and it refuses a namespace a live store of the same storage holds.
//!
//! The table's constructor is private to this crate, and the bridge
//! instance ([`crate::bridge_instance::CoreFields::custody_namespaces`]) holds
//! the one table of its storage, so code outside the bridge crates cannot
//! build a second table and through it a second live store:
//!
//! ```compile_fail,E0624
//! let table = scp_ffi_common::custody_namespace::CustodyNamespaces::new();
//! ```
//!
//! The bridge instance's table is the one way in:
//!
//! ```
//! let core = scp_ffi_common::bridge_instance::CoreFields::new();
//! let _table: &scp_ffi_common::custody_namespace::CustodyNamespaces = core.custody_namespaces();
//! ```

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use scp_platform::custody_record::BoxFuture;
use scp_platform::{
    CustodyRecord, CustodyRecordStore, KeyHandle, KeyRole, KeyType, PlatformError, Storage,
};
use tokio::sync::Mutex;

/// Prefix of every custody record key (spec §17.3).
const RECORD_PREFIX: &str = "custody/record/";

/// The one record format version: `[version, type code, role byte]`.
const RECORD_VERSION: u8 = 0x01;

/// Length of a stored record value.
const RECORD_LEN: usize = 3;

/// The 16-byte namespace that scopes one callback adapter's records
/// (spec §17.3). The adapter's builder draws it from a CSPRNG; this crate
/// takes it as bytes and draws nothing.
///
/// A store's `put` checks for a record and then writes under a lock only
/// that store holds, and [`Storage`] has no insert-if-absent, so two live
/// stores over one namespace could each pass the check and write different
/// records. [`CustodyNamespaces::open`] therefore refuses a namespace that a
/// live store of the same storage holds, whatever value carries its bytes.
/// The namespace is neither `Copy` nor `Clone`, and `open` takes it by move.
#[derive(PartialEq, Eq)]
pub(crate) struct CustodyNamespace([u8; 16]);

impl CustodyNamespace {
    /// The namespace `bytes`.
    #[must_use]
    pub(crate) const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The namespace's 16 bytes.
    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// The 32 lowercase hex characters a record key carries.
    fn to_hex(&self) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(32);
        for b in self.0 {
            out.push(char::from(DIGITS[usize::from(b >> 4)]));
            out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
        }
        out
    }
}

impl fmt::Debug for CustodyNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CustodyNamespace({})", self.to_hex())
    }
}

/// A [`CustodyRecordStore`] over the instance [`Storage`] the operator
/// selected (spec §17.6), scoped to one [`CustodyNamespace`].
///
/// The key is `custody/record/{namespace as 32 lowercase hex}/{decimal key
/// id}`, and the value is `[0x01, type code, role byte]` (spec §17.3).
///
/// One store object serializes its own `put`s and `remove`s, so the check
/// that refuses a different record and the write that follows it are not
/// interleaved by another call on the same object. Only
/// [`CustodyNamespaces::open`] builds one, so one namespace has at most one
/// live store per storage.
struct StorageCustodyRecordStore<S: Storage> {
    storage: S,
    namespace: CustodyNamespace,
    write_gate: Mutex<()>,
}

impl<S: Storage> fmt::Debug for StorageCustodyRecordStore<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StorageCustodyRecordStore")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl<S: Storage> StorageCustodyRecordStore<S> {
    /// A store over `storage` that reads and writes only `namespace`'s
    /// records.
    #[must_use]
    const fn new(storage: S, namespace: CustodyNamespace) -> Self {
        Self {
            storage,
            namespace,
            write_gate: Mutex::const_new(()),
        }
    }

    /// The storage key of `handle`'s record in this namespace.
    fn key(&self, handle: KeyHandle) -> String {
        format!("{RECORD_PREFIX}{}/{}", self.namespace.to_hex(), handle.id())
    }

    async fn read(&self, handle: KeyHandle) -> Result<Option<CustodyRecord>, PlatformError> {
        self.storage
            .retrieve(&self.key(handle))
            .await?
            .map(|value| decode(handle, &value))
            .transpose()
    }
}

/// The stored value of `record`.
const fn encode(record: CustodyRecord) -> [u8; RECORD_LEN] {
    [
        RECORD_VERSION,
        record.key_type.storage_code(),
        record.role.to_byte(),
    ]
}

/// Decodes a stored record, refusing an unknown version, type code or role
/// byte and any length but [`RECORD_LEN`]. It never falls back to a default.
fn decode(handle: KeyHandle, value: &[u8]) -> Result<CustodyRecord, PlatformError> {
    let id = handle.id();
    let [version, code, role] = <[u8; RECORD_LEN]>::try_from(value).map_err(|_| {
        PlatformError::CustodyError(format!(
            "custody record {id} has length {}, expected {RECORD_LEN}",
            value.len()
        ))
    })?;
    if version != RECORD_VERSION {
        return Err(PlatformError::CustodyError(format!(
            "custody record {id} has unknown version {version}"
        )));
    }
    let key_type = KeyType::from_storage_code(code).ok_or_else(|| {
        PlatformError::CustodyError(format!("custody record {id} has unknown type code {code}"))
    })?;
    let role = KeyRole::from_byte(role).ok_or_else(|| {
        PlatformError::CustodyError(format!("custody record {id} has unknown role {role}"))
    })?;
    Ok(CustodyRecord { key_type, role })
}

impl<S: Storage> CustodyRecordStore for StorageCustodyRecordStore<S> {
    fn put(
        &self,
        handle: KeyHandle,
        key_type: KeyType,
        role: KeyRole,
    ) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            let record = CustodyRecord { key_type, role };
            let _gate = self.write_gate.lock().await;
            match self.read(handle).await? {
                Some(existing) if existing == record => Ok(()),
                Some(existing) => Err(PlatformError::CustodyError(format!(
                    "custody record {} is {existing:?}; refusing to overwrite it with {record:?}",
                    handle.id()
                ))),
                None => self.storage.store(&self.key(handle), &encode(record)).await,
            }
        })
    }

    fn get(
        &self,
        handle: KeyHandle,
    ) -> BoxFuture<'_, Result<Option<CustodyRecord>, PlatformError>> {
        Box::pin(self.read(handle))
    }

    fn remove(&self, handle: KeyHandle) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            let _gate = self.write_gate.lock().await;
            self.storage.delete(&self.key(handle)).await
        })
    }
}

/// [`CustodyNamespaces::open`] refused a namespace because a live store of
/// the same storage holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NamespaceLive;

impl fmt::Display for NamespaceLive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a live custody record store already holds this custody namespace")
    }
}

impl std::error::Error for NamespaceLive {}

/// The custody namespaces the live record stores of one storage hold
/// (spec §17.3).
///
/// The owner of a storage, a bridge instance, keeps one table for it, and
/// every record store over that storage comes from [`open`](Self::open). A
/// store's `put` checks for a record and then writes under a lock only that
/// store holds, so two live stores over one namespace could each pass the
/// check and write different records; the table refuses the second. Clones
/// share one table.
#[derive(Debug, Clone)]
pub struct CustodyNamespaces {
    live: Arc<std::sync::Mutex<HashSet<[u8; 16]>>>,
}

impl CustodyNamespaces {
    /// A table with no live namespace.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            live: Arc::new(std::sync::Mutex::new(HashSet::new())),
        }
    }

    fn live(&self) -> std::sync::MutexGuard<'_, HashSet<[u8; 16]>> {
        // A poisoned table is still consistent: the lock guards a plain set
        // that no panic leaves half-written.
        self.live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Opens the record store of `namespace` over `storage`. The namespace is
    /// live until the store drops.
    ///
    /// # Errors
    ///
    /// [`NamespaceLive`] while another store from this table holds
    /// `namespace`.
    pub(crate) fn open<S: Storage>(
        &self,
        storage: S,
        namespace: CustodyNamespace,
    ) -> Result<LiveCustodyRecordStore<S>, NamespaceLive> {
        let bytes = *namespace.as_bytes();
        if !self.live().insert(bytes) {
            return Err(NamespaceLive);
        }
        Ok(LiveCustodyRecordStore {
            store: StorageCustodyRecordStore::new(storage, namespace),
            _lease: NamespaceLease {
                table: self.clone(),
                bytes,
            },
        })
    }

    /// A new table and the store of `namespace` over `storage` it holds,
    /// for a test adapter that needs records but no instance: a new table
    /// holds no namespace, so the open cannot be refused.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub(crate) fn open_alone<S: Storage>(
        storage: S,
        namespace: CustodyNamespace,
    ) -> (Self, LiveCustodyRecordStore<S>) {
        let table = Self::new();
        let bytes = *namespace.as_bytes();
        table.live().insert(bytes);
        let store = LiveCustodyRecordStore {
            store: StorageCustodyRecordStore::new(storage, namespace),
            _lease: NamespaceLease {
                table: table.clone(),
                bytes,
            },
        };
        (table, store)
    }
}

/// Releases a namespace from its table when the store holding it drops.
struct NamespaceLease {
    table: CustodyNamespaces,
    bytes: [u8; 16],
}

impl Drop for NamespaceLease {
    fn drop(&mut self) {
        self.table.live().remove(&self.bytes);
    }
}

/// A [`CustodyRecordStore`] over the instance [`Storage`] (spec §17.6),
/// scoped to one [`CustodyNamespace`].
///
/// It holds its namespace in its [`CustodyNamespaces`] table until it
/// drops. The key is `custody/record/{namespace as 32 lowercase hex}/{decimal key
/// id}`, and the value is `[0x01, type code, role byte]` (spec §17.3).
pub(crate) struct LiveCustodyRecordStore<S: Storage> {
    // Declared before `_lease`, so the store drops before its namespace is
    // released and a later `open` builds the only live store.
    store: StorageCustodyRecordStore<S>,
    _lease: NamespaceLease,
}

impl<S: Storage> fmt::Debug for LiveCustodyRecordStore<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveCustodyRecordStore")
            .field("namespace", &self.store.namespace)
            .finish_non_exhaustive()
    }
}

impl<S: Storage> LiveCustodyRecordStore<S> {
    /// The namespace this store reads and writes.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn namespace(&self) -> &CustodyNamespace {
        &self.store.namespace
    }
}

impl<S: Storage> CustodyRecordStore for LiveCustodyRecordStore<S> {
    fn put(
        &self,
        handle: KeyHandle,
        key_type: KeyType,
        role: KeyRole,
    ) -> BoxFuture<'_, Result<(), PlatformError>> {
        self.store.put(handle, key_type, role)
    }

    fn get(
        &self,
        handle: KeyHandle,
    ) -> BoxFuture<'_, Result<Option<CustodyRecord>, PlatformError>> {
        self.store.get(handle)
    }

    fn remove(&self, handle: KeyHandle) -> BoxFuture<'_, Result<(), PlatformError>> {
        self.store.remove(handle)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{
        CustodyNamespace, CustodyNamespaces, CustodyRecord, CustodyRecordStore, NamespaceLive,
        RECORD_LEN, StorageCustodyRecordStore,
    };
    use scp_platform::in_memory::InMemoryStorage;
    use scp_platform::{KeyHandle, KeyRole, KeyType, PlatformError, Storage};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const NS_A: CustodyNamespace = CustodyNamespace::from_bytes([0xa1; 16]);
    const NS_B: CustodyNamespace = CustodyNamespace::from_bytes([0xb2; 16]);

    fn store(
        storage: &Arc<InMemoryStorage>,
        ns: CustodyNamespace,
    ) -> StorageCustodyRecordStore<Arc<InMemoryStorage>> {
        StorageCustodyRecordStore::new(Arc::clone(storage), ns)
    }

    const fn record(key_type: KeyType, role: KeyRole) -> CustodyRecord {
        CustodyRecord { key_type, role }
    }

    #[tokio::test]
    async fn put_then_get_round_trips_every_type_and_role() -> TestResult {
        let storage = Arc::new(InMemoryStorage::new());
        let records = store(&storage, NS_A);
        let mut id = 0;
        for key_type in [
            KeyType::Ed25519,
            KeyType::P256Signing,
            KeyType::HpkeP256,
            KeyType::P256KeyEvent,
        ] {
            for role in [KeyRole::Operational, KeyRole::Identity] {
                id += 1;
                records.put(KeyHandle::new(id), key_type, role).await?;
                assert_eq!(
                    records.get(KeyHandle::new(id)).await?,
                    Some(record(key_type, role))
                );
            }
        }
        assert_eq!(records.get(KeyHandle::new(99)).await?, None);
        Ok(())
    }

    #[tokio::test]
    async fn stored_key_and_value_follow_the_spec_layout() -> TestResult {
        let storage = Arc::new(InMemoryStorage::new());
        let mut ns = [0u8; 16];
        ns[0] = 0x0f;
        ns[15] = 0xab;
        let records = store(&storage, CustodyNamespace::from_bytes(ns));
        records
            .put(KeyHandle::new(42), KeyType::HpkeP256, KeyRole::Identity)
            .await?;
        let key = "custody/record/0f0000000000000000000000000000ab/42";
        assert_eq!(storage.retrieve(key).await?, Some(vec![0x01, 3, 0x01]));
        assert_eq!(
            storage.list_keys("custody/record/").await?,
            vec![key.to_owned()]
        );
        assert_eq!(
            format!("{:?}", CustodyNamespace::from_bytes(ns)),
            "CustodyNamespace(0f0000000000000000000000000000ab)"
        );
        Ok(())
    }

    #[tokio::test]
    async fn put_refuses_a_different_record_and_accepts_the_same_one() -> TestResult {
        let storage = Arc::new(InMemoryStorage::new());
        let records = store(&storage, NS_A);
        let handle = KeyHandle::new(7);
        records
            .put(handle, KeyType::P256Signing, KeyRole::Operational)
            .await?;
        records
            .put(handle, KeyType::P256Signing, KeyRole::Operational)
            .await?;
        for (key_type, role) in [
            (KeyType::HpkeP256, KeyRole::Operational),
            (KeyType::P256Signing, KeyRole::Identity),
        ] {
            assert!(matches!(
                records.put(handle, key_type, role).await,
                Err(PlatformError::CustodyError(_))
            ));
        }
        assert_eq!(
            records.get(handle).await?,
            Some(record(KeyType::P256Signing, KeyRole::Operational))
        );
        Ok(())
    }

    #[tokio::test]
    async fn remove_then_put_records_afresh() -> TestResult {
        let storage = Arc::new(InMemoryStorage::new());
        let records = store(&storage, NS_A);
        let handle = KeyHandle::new(3);
        records
            .put(handle, KeyType::Ed25519, KeyRole::Identity)
            .await?;
        records.remove(handle).await?;
        assert_eq!(records.get(handle).await?, None);
        records.remove(handle).await?;
        records
            .put(handle, KeyType::HpkeP256, KeyRole::Operational)
            .await?;
        assert_eq!(
            records.get(handle).await?,
            Some(record(KeyType::HpkeP256, KeyRole::Operational))
        );
        Ok(())
    }

    #[tokio::test]
    async fn two_namespaces_share_storage_without_crosstalk() -> TestResult {
        let storage = Arc::new(InMemoryStorage::new());
        let a = store(&storage, NS_A);
        let b = store(&storage, NS_B);
        let handle = KeyHandle::new(1);
        a.put(handle, KeyType::P256Signing, KeyRole::Operational)
            .await?;
        // The same id in another namespace takes a different record.
        b.put(handle, KeyType::HpkeP256, KeyRole::Identity).await?;
        assert_eq!(
            a.get(handle).await?,
            Some(record(KeyType::P256Signing, KeyRole::Operational))
        );
        assert_eq!(
            b.get(handle).await?,
            Some(record(KeyType::HpkeP256, KeyRole::Identity))
        );
        a.remove(handle).await?;
        assert_eq!(a.get(handle).await?, None);
        assert_eq!(
            b.get(handle).await?,
            Some(record(KeyType::HpkeP256, KeyRole::Identity))
        );
        assert_ne!(a.key(handle), b.key(handle));
        Ok(())
    }

    #[tokio::test]
    async fn get_refuses_a_malformed_record() -> TestResult {
        let storage = Arc::new(InMemoryStorage::new());
        let records = store(&storage, NS_A);
        let handle = KeyHandle::new(5);
        let cases: [(&str, Vec<u8>); 7] = [
            ("unknown version 0", vec![0x00, 2, 0x00]),
            ("unknown version 2", vec![0x02, 2, 0x00]),
            ("retired type code 1", vec![0x01, 1, 0x00]),
            ("unknown type code 5", vec![0x01, 5, 0x00]),
            ("unknown role", vec![0x01, 2, 0x02]),
            ("short", vec![0x01, 2]),
            ("long", vec![0x01, 2, 0x00, 0x00]),
        ];
        for (name, value) in cases {
            storage.store(&records.key(handle), &value).await?;
            assert!(
                matches!(
                    records.get(handle).await,
                    Err(PlatformError::CustodyError(_))
                ),
                "{name}"
            );
            // A put over a malformed record is refused too, never treated as
            // absent.
            assert!(
                matches!(
                    records
                        .put(handle, KeyType::P256Signing, KeyRole::Operational)
                        .await,
                    Err(PlatformError::CustodyError(_))
                ),
                "{name}"
            );
            assert_eq!(storage.retrieve(&records.key(handle)).await?, Some(value));
        }
        assert_eq!(RECORD_LEN, 3);
        Ok(())
    }

    /// One store's gate holds the check and the write together: of two
    /// concurrent puts of different records under one id, one lands and the
    /// other is refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_different_puts_on_one_store_admit_one() -> TestResult {
        for id in 0..64 {
            let storage = Arc::new(InMemoryStorage::new());
            let records = Arc::new(store(&storage, NS_A));
            let handle = KeyHandle::new(id);
            let (first, second) = (Arc::clone(&records), Arc::clone(&records));
            let a = tokio::spawn(async move {
                first
                    .put(handle, KeyType::P256Signing, KeyRole::Operational)
                    .await
            });
            let b = tokio::spawn(async move {
                second
                    .put(handle, KeyType::HpkeP256, KeyRole::Identity)
                    .await
            });
            let (a, b) = (a.await?, b.await?);
            assert_eq!(
                usize::from(a.is_ok()) + usize::from(b.is_ok()),
                1,
                "{a:?} {b:?}"
            );
            let stored = records.get(handle).await?;
            let winner = if a.is_ok() {
                record(KeyType::P256Signing, KeyRole::Operational)
            } else {
                record(KeyType::HpkeP256, KeyRole::Identity)
            };
            assert_eq!(stored, Some(winner));
        }
        Ok(())
    }

    /// Storage whose every operation fails.
    struct FailingStorage;

    impl Storage for FailingStorage {
        async fn store(&self, _key: &str, _data: &[u8]) -> Result<(), PlatformError> {
            Err(PlatformError::StorageError("write failed".into()))
        }

        async fn retrieve(&self, _key: &str) -> Result<Option<Vec<u8>>, PlatformError> {
            Err(PlatformError::StorageError("read failed".into()))
        }

        async fn delete(&self, _key: &str) -> Result<(), PlatformError> {
            Err(PlatformError::StorageError("delete failed".into()))
        }

        async fn list_keys(&self, _prefix: &str) -> Result<Vec<String>, PlatformError> {
            Err(PlatformError::StorageError("list failed".into()))
        }

        async fn delete_prefix(&self, _prefix: &str) -> Result<u64, PlatformError> {
            Err(PlatformError::StorageError("delete failed".into()))
        }

        async fn exists(&self, _key: &str) -> Result<bool, PlatformError> {
            Err(PlatformError::StorageError("read failed".into()))
        }
    }

    #[tokio::test]
    async fn storage_failures_reach_the_caller() {
        let records: Arc<dyn CustodyRecordStore> =
            Arc::new(StorageCustodyRecordStore::new(FailingStorage, NS_A));
        let handle = KeyHandle::new(1);
        assert!(matches!(
            records
                .put(handle, KeyType::Ed25519, KeyRole::Identity)
                .await,
            Err(PlatformError::StorageError(_))
        ));
        assert!(matches!(
            records.get(handle).await,
            Err(PlatformError::StorageError(_))
        ));
        assert!(matches!(
            records.remove(handle).await,
            Err(PlatformError::StorageError(_))
        ));
    }

    /// Two namespaces open side by side and keep apart the records they put
    /// concurrently under one key id.
    #[tokio::test]
    async fn two_stores_over_one_storage_keep_their_records_apart() -> TestResult {
        let storage = Arc::new(InMemoryStorage::new());
        let table = CustodyNamespaces::new();
        let a = table.open(
            Arc::clone(&storage),
            CustodyNamespace::from_bytes([0x11; 16]),
        )?;
        let b = table.open(
            Arc::clone(&storage),
            CustodyNamespace::from_bytes([0x22; 16]),
        )?;
        let handle = KeyHandle::new(9);
        let (put_a, put_b) = tokio::join!(
            a.put(handle, KeyType::P256Signing, KeyRole::Operational),
            b.put(handle, KeyType::HpkeP256, KeyRole::Identity),
        );
        put_a?;
        put_b?;
        assert_eq!(
            a.get(handle).await?,
            Some(record(KeyType::P256Signing, KeyRole::Operational))
        );
        assert_eq!(
            b.get(handle).await?,
            Some(record(KeyType::HpkeP256, KeyRole::Identity))
        );
        assert_eq!(storage.list_keys("custody/record/").await?.len(), 2);
        Ok(())
    }

    /// A second open of a live namespace is refused, through the table or a
    /// clone of it, until the first store drops; the reopened store reads
    /// the records the first wrote.
    #[tokio::test]
    async fn a_live_namespace_opens_once_until_its_store_drops() -> TestResult {
        let storage = Arc::new(InMemoryStorage::new());
        let table = CustodyNamespaces::new();
        let first = table.open(
            Arc::clone(&storage),
            CustodyNamespace::from_bytes([0x33; 16]),
        )?;
        first
            .put(
                KeyHandle::new(1),
                KeyType::P256KeyEvent,
                KeyRole::Operational,
            )
            .await?;
        // Equal bytes in a new value are the same namespace.
        let second = table.open(
            Arc::clone(&storage),
            CustodyNamespace::from_bytes([0x33; 16]),
        );
        assert_eq!(second.err(), Some(NamespaceLive));
        // A clone of the table is the same table.
        let again = table.clone().open(
            Arc::clone(&storage),
            CustodyNamespace::from_bytes([0x33; 16]),
        );
        assert_eq!(again.err(), Some(NamespaceLive));
        drop(first);
        let reopened = table.open(
            Arc::clone(&storage),
            CustodyNamespace::from_bytes([0x33; 16]),
        )?;
        assert_eq!(
            reopened.namespace(),
            &CustodyNamespace::from_bytes([0x33; 16])
        );
        assert_eq!(
            reopened.get(KeyHandle::new(1)).await?,
            Some(record(KeyType::P256KeyEvent, KeyRole::Operational)),
            "a reopened namespace reads the records its earlier store wrote"
        );
        Ok(())
    }
}
