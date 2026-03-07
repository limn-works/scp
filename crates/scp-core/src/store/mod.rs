//! Protocol store for SCP client-side persistence.
//!
//! `ProtocolStore<S>` wraps a `Storage` implementation and provides typed
//! domain methods for all protocol state. Storage adapters implement the
//! thin `Storage` trait (six methods); `ProtocolStore` handles all structured
//! domain logic and key conventions.
//!
//! # Key Convention
//!
//! All keys follow `{namespace}/{entity_id}/{sub_key}` with `/` as the
//! hierarchy separator. See spec section 17.3 for the full key convention.
//!
//! # Module Structure
//!
//! Each domain area has its own submodule with the `ProtocolStore` impl
//! methods for that area. This keeps the impl blocks organized and
//! focused.
//!
//! See spec section 17.4 and ADR-006.

pub mod access_keys;
pub mod context;
pub mod economy;
pub mod event_log;
pub mod identity;
pub mod nonce;
pub mod tls;
pub mod tools;
pub mod transport;
pub mod ucan;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zeroize::Zeroize;

use scp_platform::traits::Storage;

// ---------------------------------------------------------------------------
// Key sanitization
// ---------------------------------------------------------------------------

/// Validates a storage key component, rejecting path traversal characters.
///
/// Rejects strings containing `/`, `\`, `..`, or null bytes to prevent
/// storage path traversal attacks.
///
/// # Errors
///
/// Returns [`StoreError::SerializationFailed`] if the input contains
/// forbidden characters (`/`, `\`, `..`, or null bytes).
pub fn sanitize_key_component(s: &str) -> Result<&str, StoreError> {
    if s.contains('/') || s.contains('\\') || s.contains("..") || s.contains('\0') {
        return Err(StoreError::SerializationFailed(format!(
            "invalid key component: contains forbidden characters: {s:?}"
        )));
    }
    Ok(s)
}

// ---------------------------------------------------------------------------
// StoreError
// ---------------------------------------------------------------------------

/// Errors produced by `ProtocolStore` operations.
///
/// Wraps platform storage errors and adds protocol-level error variants
/// for serialization/deserialization failures and missing data.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The underlying storage backend returned an error.
    #[error("storage error: {0}")]
    Storage(#[from] scp_platform::PlatformError),

    /// Serialization of a protocol value failed.
    #[error("serialization failed: {0}")]
    SerializationFailed(String),

    /// Deserialization of a stored value failed.
    #[error("deserialization failed: {0}")]
    DeserializationFailed(String),

    /// The stored value was written by a newer SCP version and cannot be read.
    #[error("incompatible version: stored={stored}, current={current}")]
    IncompatibleVersion {
        /// The version found in the stored data.
        stored: u16,
        /// The maximum version this build can read.
        current: u16,
    },
}

// ---------------------------------------------------------------------------
// StoredValue
// ---------------------------------------------------------------------------

/// Version envelope for all values persisted by `ProtocolStore`.
///
/// Every value written by `ProtocolStore` is wrapped in `StoredValue`.
/// On read, `version` is checked before deserializing `data`. This enables
/// lazy on-read migration (spec section 17.10) without requiring
/// schema-level versioning in the storage backend.
///
/// See spec section 17.5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredValue<T> {
    /// Schema version for the contained data type.
    pub version: u16,
    /// The serialized domain value.
    pub data: T,
}

/// Current schema version for all `StoredValue` envelopes.
///
/// Incremented when the serialized format of any domain type changes.
/// Migration logic (spec section 17.10) uses this to detect stale data.
pub const CURRENT_STORE_VERSION: u16 = 1;

/// Current key-space schema version.
///
/// Used by `ProtocolStore::initialize()` to detect whether key-space
/// migrations need to run on startup. Incremented when the key
/// convention changes (e.g., key format changes, key renames).
///
/// See spec section 17.10.
pub const CURRENT_SCHEMA_VERSION: u16 = 1;

// ---------------------------------------------------------------------------
// Migratable trait (SCP-PERSIST-018)
// ---------------------------------------------------------------------------

/// Trait for types that support lazy on-read migration.
///
/// Each `Migratable` type declares its `CURRENT_VERSION` and provides a
/// `migrate` function that transforms raw `StoredValue` bytes from an
/// older version to the current version. Migration functions are pure --
/// no I/O, no side effects, independently testable.
///
/// On read, `ProtocolStore` checks the stored `StoredValue.version`. If it
/// is behind `CURRENT_VERSION`, the migration chain is applied iteratively
/// and the upgraded value is written back to storage. If the version is
/// ahead, `StoreError::IncompatibleVersion` is returned.
///
/// The `data` parameter to `migrate` contains the raw `MessagePack` bytes
/// of the full `StoredValue` envelope as originally stored. The migration
/// function must deserialize the old format and produce the current type.
///
/// See spec section 17.10. See SCP-PERSIST-018.
pub trait Migratable: Sized + Serialize + DeserializeOwned {
    /// Current version number for this type.
    const CURRENT_VERSION: u16;

    /// Migrate from `old_version` raw stored bytes to the current version.
    ///
    /// `data` is the full raw bytes of the `StoredValue` envelope as stored.
    /// Returns `None` if migration from this version is not supported.
    fn migrate(old_version: u16, data: &[u8]) -> Option<Self>;
}

// ---------------------------------------------------------------------------
// ProtocolStore
// ---------------------------------------------------------------------------

/// Concrete protocol store wrapping a platform `Storage` implementation.
///
/// Provides typed domain methods for all protocol state. Storage adapters
/// implement the thin `Storage` trait; `ProtocolStore` handles all structured
/// domain logic, key conventions, and serialization.
///
/// The type parameter `S` is the concrete storage backend (e.g.,
/// `InMemoryStorage`, `SqliteStorage`). The `Storage` trait uses RPITIT
/// (return-position `impl Trait` in traits) and is not dyn-compatible,
/// so `ProtocolStore` is generic rather than using `Arc<dyn Storage>`.
///
/// See spec section 17.4.
pub struct ProtocolStore<S: Storage> {
    storage: S,
}

impl<S: Storage> ProtocolStore<S> {
    /// Creates a new `ProtocolStore` wrapping the given storage backend.
    #[must_use]
    pub const fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Returns a reference to the underlying storage backend.
    ///
    /// Used by [`MlsStorageBridge`](crate::crypto::mls::storage::MlsStorageBridge)
    /// to perform raw storage operations for `OpenMLS` state persistence.
    ///
    /// See spec section 17.9. See SCP-PERSIST-050.
    #[must_use]
    pub const fn storage(&self) -> &S {
        &self.storage
    }

    /// Serializes a value into a `StoredValue` envelope using `MessagePack`.
    ///
    /// Wraps the data in a version envelope (spec section 17.5) and
    /// serializes the entire envelope with `rmp-serde`.
    fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, StoreError> {
        let envelope = StoredValue {
            version: CURRENT_STORE_VERSION,
            data: value,
        };
        rmp_serde::to_vec(&envelope).map_err(|e| StoreError::SerializationFailed(e.to_string()))
    }

    /// Deserializes a `StoredValue` envelope from `MessagePack` bytes.
    ///
    /// Checks the version field: if the stored version exceeds the current
    /// version, returns `StoreError::IncompatibleVersion`. Otherwise
    /// deserializes and returns the inner data.
    fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, StoreError> {
        let envelope: StoredValue<T> = rmp_serde::from_slice(bytes)
            .map_err(|e| StoreError::DeserializationFailed(e.to_string()))?;
        if envelope.version > CURRENT_STORE_VERSION {
            return Err(StoreError::IncompatibleVersion {
                stored: envelope.version,
                current: CURRENT_STORE_VERSION,
            });
        }
        Ok(envelope.data)
    }

    /// Stores a serialized value under the given key.
    ///
    /// Wraps the value in a `StoredValue` envelope and writes it to
    /// the underlying storage backend.
    async fn store_value<T: Serialize + Sync>(
        &self,
        key: &str,
        value: &T,
    ) -> Result<(), StoreError> {
        let bytes = Self::serialize(value)?;
        self.storage.store(key, &bytes).await?;
        Ok(())
    }

    /// Stores a serialized value under the given key, then zeroizes the
    /// serialized buffer.
    ///
    /// Defense-in-depth: prevents sensitive key material from lingering
    /// in memory after the storage write completes. Use this instead of
    /// `store_value` when the serialized data contains cryptographic keys.
    async fn store_value_zeroize<T: Serialize + Sync>(
        &self,
        key: &str,
        value: &T,
    ) -> Result<(), StoreError> {
        let mut bytes = Self::serialize(value)?;
        let result = self
            .storage
            .store(key, &bytes)
            .await
            .map_err(StoreError::Storage);
        bytes.zeroize();
        result
    }

    /// Loads and deserializes a value from the given key.
    ///
    /// Returns `None` if the key does not exist. Checks the version
    /// envelope before deserializing the inner data.
    async fn load_value<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, StoreError> {
        match self.storage.retrieve(key).await? {
            Some(bytes) => Ok(Some(Self::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    // -----------------------------------------------------------------------
    // Version-aware read/write for Migratable types (SCP-PERSIST-018)
    // -----------------------------------------------------------------------

    /// Stores a `Migratable` value with its type-specific version.
    ///
    /// Wraps the value in a `StoredValue` envelope using the type's
    /// `CURRENT_VERSION` rather than the global `CURRENT_STORE_VERSION`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_migratable<T: Migratable + Sync>(
        &self,
        key: &str,
        value: &T,
    ) -> Result<(), StoreError> {
        let envelope = StoredValue {
            version: T::CURRENT_VERSION,
            data: value,
        };
        let bytes = rmp_serde::to_vec(&envelope)
            .map_err(|e| StoreError::SerializationFailed(e.to_string()))?;
        self.storage.store(key, &bytes).await?;
        Ok(())
    }

    /// Loads a `Migratable` value, applying migration if needed.
    ///
    /// If the stored version is behind `T::CURRENT_VERSION`, calls
    /// `T::migrate()` to upgrade the data, then writes the upgraded
    /// value back to storage so future reads do not re-migrate.
    ///
    /// If the stored version is ahead, returns
    /// `StoreError::IncompatibleVersion`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::IncompatibleVersion`] if the stored version
    /// is ahead of `T::CURRENT_VERSION`.
    /// Returns [`StoreError::DeserializationFailed`] if deserialization
    /// or migration fails.
    /// Returns [`StoreError::Storage`] if the underlying storage fails.
    pub async fn load_migratable<T: Migratable + Sync>(
        &self,
        key: &str,
    ) -> Result<Option<T>, StoreError> {
        let Some(raw) = self.storage.retrieve(key).await? else {
            return Ok(None);
        };

        // Peek at the version field without fully deserializing the data.
        // We use `IgnoredAny` to skip the data field efficiently.
        let peek: StoredValue<serde::de::IgnoredAny> = rmp_serde::from_slice(&raw)
            .map_err(|e| StoreError::DeserializationFailed(e.to_string()))?;

        if peek.version == T::CURRENT_VERSION {
            // No migration needed — deserialize the data directly.
            let full: StoredValue<T> = rmp_serde::from_slice(&raw)
                .map_err(|e| StoreError::DeserializationFailed(e.to_string()))?;
            return Ok(Some(full.data));
        }

        if peek.version > T::CURRENT_VERSION {
            return Err(StoreError::IncompatibleVersion {
                stored: peek.version,
                current: T::CURRENT_VERSION,
            });
        }

        // Version is behind — apply migration chain iteratively.
        // Each call to T::migrate(v, raw) transforms version v to v+1.
        // The chain repeats until we reach CURRENT_VERSION.
        let mut current_raw = raw;
        let mut current_version = peek.version;

        while current_version < T::CURRENT_VERSION {
            match T::migrate(current_version, &current_raw) {
                Some(migrated) => {
                    current_version += 1;
                    if current_version < T::CURRENT_VERSION {
                        // Re-serialize at the intermediate version for the next step.
                        let envelope = StoredValue {
                            version: current_version,
                            data: &migrated,
                        };
                        current_raw = rmp_serde::to_vec(&envelope)
                            .map_err(|e| StoreError::SerializationFailed(e.to_string()))?;
                    } else {
                        // Reached CURRENT_VERSION — write back and return.
                        self.store_migratable(key, &migrated).await?;
                        return Ok(Some(migrated));
                    }
                }
                None => {
                    return Err(StoreError::DeserializationFailed(format!(
                        "migration from version {current_version} not supported for this type",
                    )));
                }
            }
        }

        // Should not reach here — the while loop exits via return.
        Err(StoreError::DeserializationFailed(
            "migration chain did not reach current version".to_owned(),
        ))
    }

    // -----------------------------------------------------------------------
    // Schema version startup check (SCP-PERSIST-019)
    // -----------------------------------------------------------------------

    /// Initializes the `ProtocolStore`, checking and setting the schema version.
    ///
    /// On startup:
    /// - If `_meta/schema_version` is missing, writes the current version.
    /// - If it matches the current version, proceeds normally.
    /// - If it is behind, executes registered key-space migrations in order.
    /// - If it is ahead, returns `StoreError::IncompatibleVersion`.
    ///
    /// Key-space migrations are the only blocking startup operation.
    ///
    /// See spec section 17.10. See SCP-PERSIST-019.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::IncompatibleVersion`] if the stored schema
    /// version is ahead of the current version.
    /// Returns [`StoreError::Storage`] if the underlying storage fails.
    pub async fn initialize(&self) -> Result<(), StoreError> {
        let key = "_meta/schema_version";
        let stored_version: Option<u16> = self.load_value(key).await?;

        match stored_version {
            None => {
                // Fresh store — write current version.
                self.store_value(key, &CURRENT_SCHEMA_VERSION).await?;
                Ok(())
            }
            Some(v) if v == CURRENT_SCHEMA_VERSION => {
                // Up to date.
                Ok(())
            }
            Some(v) if v > CURRENT_SCHEMA_VERSION => Err(StoreError::IncompatibleVersion {
                stored: v,
                current: CURRENT_SCHEMA_VERSION,
            }),
            Some(v) => {
                // Behind current — run key-space migrations.
                self.run_schema_migrations(v).await?;
                // Update to current version after successful migration.
                self.store_value(key, &CURRENT_SCHEMA_VERSION).await?;
                Ok(())
            }
        }
    }

    /// Runs key-space migrations from `from_version` to `CURRENT_SCHEMA_VERSION`.
    ///
    /// Currently no key-space migrations are registered (schema version
    /// has never changed). This hook is functional and ready for future
    /// versions to register migration steps.
    #[allow(clippy::unused_async)]
    async fn run_schema_migrations(&self, _from_version: u16) -> Result<(), StoreError> {
        // Migration steps would be registered here as the schema evolves.
        // Example:
        // if from_version < 2 { self.migrate_v1_to_v2().await?; }
        // if from_version < 3 { self.migrate_v2_to_v3().await?; }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn stored_value_roundtrip_via_msgpack() {
        let original = StoredValue {
            version: 1,
            data: "hello".to_owned(),
        };
        let bytes = rmp_serde::to_vec(&original).unwrap();
        let decoded: StoredValue<String> = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let value = vec![1u32, 2, 3, 4, 5];
        let bytes =
            ProtocolStore::<scp_platform::testing::InMemoryStorage>::serialize(&value).unwrap();
        let decoded: Vec<u32> =
            ProtocolStore::<scp_platform::testing::InMemoryStorage>::deserialize(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn deserialize_rejects_future_version() {
        let envelope = StoredValue {
            version: CURRENT_STORE_VERSION + 1,
            data: "future",
        };
        let bytes = rmp_serde::to_vec(&envelope).unwrap();
        let result =
            ProtocolStore::<scp_platform::testing::InMemoryStorage>::deserialize::<String>(&bytes);
        assert!(matches!(
            result,
            Err(StoreError::IncompatibleVersion { .. })
        ));
    }

    #[tokio::test]
    async fn store_value_and_load_value_roundtrip() {
        let store = ProtocolStore::new(scp_platform::testing::InMemoryStorage::new());
        let value = vec![42u64, 100, 999];
        store.store_value("test/key", &value).await.unwrap();
        let loaded: Option<Vec<u64>> = store.load_value("test/key").await.unwrap();
        assert_eq!(loaded, Some(value));
    }

    #[tokio::test]
    async fn load_value_returns_none_for_missing_key() {
        let store = ProtocolStore::new(scp_platform::testing::InMemoryStorage::new());
        let loaded: Option<String> = store.load_value("nonexistent").await.unwrap();
        assert!(loaded.is_none());
    }

    // -------------------------------------------------------------------
    // Migratable trait tests (SCP-PERSIST-018)
    // -------------------------------------------------------------------

    /// Test type at version 3, with migration from v1 and v2.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct TestMigratable {
        value: String,
        extra: u32,
    }

    impl Migratable for TestMigratable {
        const CURRENT_VERSION: u16 = 3;

        fn migrate(old_version: u16, data: &[u8]) -> Option<Self> {
            match old_version {
                1 => {
                    // v1 stored data as a plain String in the envelope.
                    let envelope: StoredValue<String> = rmp_serde::from_slice(data).ok()?;
                    Some(Self {
                        value: envelope.data,
                        extra: 0, // default for v1 data
                    })
                }
                2 => {
                    // v2 stored data as (String, u32) tuple in the envelope.
                    let envelope: StoredValue<(String, u32)> = rmp_serde::from_slice(data).ok()?;
                    Some(Self {
                        value: envelope.data.0,
                        extra: envelope.data.1,
                    })
                }
                _ => None,
            }
        }
    }

    #[tokio::test]
    async fn migratable_current_version_roundtrip() {
        let store = ProtocolStore::new(scp_platform::testing::InMemoryStorage::new());
        let original = TestMigratable {
            value: "hello".to_owned(),
            extra: 42,
        };

        store
            .store_migratable("test/migratable", &original)
            .await
            .unwrap();
        let loaded: Option<TestMigratable> =
            store.load_migratable("test/migratable").await.unwrap();
        assert_eq!(loaded, Some(original));
    }

    #[tokio::test]
    async fn migratable_migration_from_v1() {
        let store = ProtocolStore::new(scp_platform::testing::InMemoryStorage::new());

        // Manually store a v1 value (just a String).
        let v1_data = "migrated-value".to_owned();
        let envelope = StoredValue {
            version: 1u16,
            data: &v1_data,
        };
        let bytes = rmp_serde::to_vec(&envelope).unwrap();
        store.storage.store("test/migrate", &bytes).await.unwrap();

        // Load should trigger migration.
        let loaded: Option<TestMigratable> = store.load_migratable("test/migrate").await.unwrap();
        let loaded = loaded.unwrap();
        assert_eq!(loaded.value, "migrated-value");
        assert_eq!(loaded.extra, 0); // default from migration

        // Verify the migrated value was written back at v3.
        let raw = store
            .storage
            .retrieve("test/migrate")
            .await
            .unwrap()
            .unwrap();
        let check: StoredValue<TestMigratable> = rmp_serde::from_slice(&raw).unwrap();
        assert_eq!(check.version, 3);
    }

    #[tokio::test]
    async fn migratable_rejects_future_version() {
        let store = ProtocolStore::new(scp_platform::testing::InMemoryStorage::new());

        // Manually store a future version.
        let envelope = StoredValue {
            version: 99u16,
            data: "future",
        };
        let bytes = rmp_serde::to_vec(&envelope).unwrap();
        store.storage.store("test/future", &bytes).await.unwrap();

        let result: Result<Option<TestMigratable>, _> = store.load_migratable("test/future").await;
        assert!(matches!(
            result,
            Err(StoreError::IncompatibleVersion {
                stored: 99,
                current: 3
            })
        ));
    }

    #[tokio::test]
    async fn migratable_returns_none_for_missing() {
        let store = ProtocolStore::new(scp_platform::testing::InMemoryStorage::new());
        let loaded: Option<TestMigratable> = store.load_migratable("nonexistent").await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn migratable_migration_from_v2() {
        let store = ProtocolStore::new(scp_platform::testing::InMemoryStorage::new());

        // Manually store a v2 value: (String, u32) tuple.
        let v2_data = ("from-v2".to_owned(), 77u32);
        let envelope = StoredValue {
            version: 2u16,
            data: &v2_data,
        };
        let bytes = rmp_serde::to_vec(&envelope).unwrap();
        store
            .storage
            .store("test/migrate-v2", &bytes)
            .await
            .unwrap();

        // Load should trigger migration from v2 to v3.
        let loaded: Option<TestMigratable> =
            store.load_migratable("test/migrate-v2").await.unwrap();
        let loaded = loaded.unwrap();
        assert_eq!(loaded.value, "from-v2");
        assert_eq!(loaded.extra, 77);

        // Verify the migrated value was written back at v3.
        let raw = store
            .storage
            .retrieve("test/migrate-v2")
            .await
            .unwrap()
            .unwrap();
        let check: StoredValue<TestMigratable> = rmp_serde::from_slice(&raw).unwrap();
        assert_eq!(check.version, 3);
    }

    #[tokio::test]
    async fn migratable_chain_migration_v1_to_v3_via_v2() {
        // Verifies that iterative chain migration works: v1 -> v2 -> v3.
        // The v1 migrate step produces a TestMigratable (at v2 semantics),
        // which is then re-serialized at v2 and fed into the v2 migrate step.
        let store = ProtocolStore::new(scp_platform::testing::InMemoryStorage::new());

        // Store a v1 value.
        let v1_data = "chain-test".to_owned();
        let envelope = StoredValue {
            version: 1u16,
            data: &v1_data,
        };
        let bytes = rmp_serde::to_vec(&envelope).unwrap();
        store.storage.store("test/chain", &bytes).await.unwrap();

        // Load triggers v1 -> v2 -> v3 chain.
        let loaded: Option<TestMigratable> = store.load_migratable("test/chain").await.unwrap();
        let loaded = loaded.unwrap();
        assert_eq!(loaded.value, "chain-test");
        // v1 migration sets extra=0; if the chain goes v1->v3 directly
        // instead of v1->v2->v3, the v2 step would overwrite extra.
        // Both paths produce extra=0 for this data, but the version
        // written back must be 3.
        assert_eq!(loaded.extra, 0);

        let raw = store.storage.retrieve("test/chain").await.unwrap().unwrap();
        let check: StoredValue<TestMigratable> = rmp_serde::from_slice(&raw).unwrap();
        assert_eq!(check.version, 3);
    }

    // -------------------------------------------------------------------
    // Schema version startup check tests (SCP-PERSIST-019)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn initialize_writes_version_on_fresh_store() {
        let store = ProtocolStore::new(scp_platform::testing::InMemoryStorage::new());
        store.initialize().await.unwrap();

        let version: Option<u16> = store.load_value("_meta/schema_version").await.unwrap();
        assert_eq!(version, Some(CURRENT_SCHEMA_VERSION));
    }

    #[tokio::test]
    async fn initialize_proceeds_on_matching_version() {
        let store = ProtocolStore::new(scp_platform::testing::InMemoryStorage::new());

        // Pre-set the version.
        store
            .store_value("_meta/schema_version", &CURRENT_SCHEMA_VERSION)
            .await
            .unwrap();

        // Should succeed without error.
        store.initialize().await.unwrap();
    }

    #[tokio::test]
    async fn initialize_errors_on_future_version() {
        let store = ProtocolStore::new(scp_platform::testing::InMemoryStorage::new());

        let future_version: u16 = CURRENT_SCHEMA_VERSION + 5;
        store
            .store_value("_meta/schema_version", &future_version)
            .await
            .unwrap();

        let result = store.initialize().await;
        assert!(matches!(
            result,
            Err(StoreError::IncompatibleVersion { .. })
        ));
    }

    #[tokio::test]
    async fn initialize_triggers_migration_for_old_version() {
        let store = ProtocolStore::new(scp_platform::testing::InMemoryStorage::new());

        // Set a behind version. Currently no migrations exist, but the
        // hook should still execute and update to current.
        let old_version: u16 = 0;
        store
            .store_value("_meta/schema_version", &old_version)
            .await
            .unwrap();

        store.initialize().await.unwrap();

        // Version should be updated to current.
        let version: Option<u16> = store.load_value("_meta/schema_version").await.unwrap();
        assert_eq!(version, Some(CURRENT_SCHEMA_VERSION));
    }

    // -------------------------------------------------------------------
    // sanitize_key_component unit tests
    // -------------------------------------------------------------------

    #[test]
    fn sanitize_rejects_forward_slash() {
        let result = sanitize_key_component("../identity/victim");
        assert!(result.is_err());
    }

    #[test]
    fn sanitize_rejects_backslash() {
        let result = sanitize_key_component("evil\\path");
        assert!(result.is_err());
    }

    #[test]
    fn sanitize_rejects_dot_dot() {
        let result = sanitize_key_component("foo..bar");
        assert!(result.is_err());
    }

    #[test]
    fn sanitize_rejects_null_byte() {
        let result = sanitize_key_component("evil\0id");
        assert!(result.is_err());
    }

    #[test]
    fn sanitize_accepts_well_formed_identifiers() {
        assert!(sanitize_key_component("ctx-123").is_ok());
        assert!(sanitize_key_component("did:dht:z6MkTest").is_ok());
        assert!(sanitize_key_component("tok-abc-def").is_ok());
        assert!(sanitize_key_component("x402").is_ok());
    }

    // -------------------------------------------------------------------
    // Cross-domain key traversal rejection tests
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn context_store_rejects_traversal_context_id() {
        let store = ProtocolStore::new(scp_platform::testing::InMemoryStorage::new());
        let result = store
            .store_context_state("../identity/victim", b"bad")
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn context_store_rejects_null_byte_context_id() {
        let store = ProtocolStore::new(scp_platform::testing::InMemoryStorage::new());
        let result = store.store_context_state("evil\0ctx", b"bad").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn identity_store_rejects_traversal_did() {
        let store = ProtocolStore::new(scp_platform::testing::InMemoryStorage::new());
        let malicious_did = scp_identity::DID::from("../context/victim");
        let result = store.store_identity_document(&malicious_did, b"bad").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn identity_store_rejects_backslash_did() {
        let store = ProtocolStore::new(scp_platform::testing::InMemoryStorage::new());
        let malicious_did = scp_identity::DID::from("evil\\did");
        let result = store.store_identity_document(&malicious_did, b"bad").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn tool_store_rejects_traversal_tool_id() {
        let store = ProtocolStore::new(scp_platform::testing::InMemoryStorage::new());
        let result = store
            .store_tool("ctx-1", "../ucan_token/steal", b"bad")
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn tool_store_rejects_null_byte_session_id() {
        let store = ProtocolStore::new(scp_platform::testing::InMemoryStorage::new());
        let result = store.store_tool_session("ctx-1", "sess\0ion", b"bad").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn economy_store_rejects_traversal_adapter_id() {
        let store = ProtocolStore::new(scp_platform::testing::InMemoryStorage::new());
        let did = scp_identity::DID::from("did:dht:z6MkTest");
        let result = store
            .store_adapter_credentials(&did, "../document", b"bad")
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn ucan_store_rejects_traversal_context_id() {
        let store = ProtocolStore::new(scp_platform::testing::InMemoryStorage::new());
        let result = store
            .store_ucan_token("../identity/victim", "tok-1", b"bad")
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn well_formed_identifiers_succeed_across_all_domains() {
        let store = ProtocolStore::new(scp_platform::testing::InMemoryStorage::new());
        let did = scp_identity::DID::from("did:dht:z6MkTest");

        // Context domain
        store
            .store_context_state("ctx-valid", b"state")
            .await
            .unwrap();

        // Identity domain
        store.store_identity_document(&did, b"doc").await.unwrap();

        // Tools domain
        store
            .store_tool("ctx-valid", "tool-ok", b"reg")
            .await
            .unwrap();

        // Economy domain
        store
            .store_adapter_credentials(&did, "x402", b"cred")
            .await
            .unwrap();

        // UCAN domain
        store
            .store_ucan_token("ctx-valid", "tok-ok", b"token")
            .await
            .unwrap();
    }
}
