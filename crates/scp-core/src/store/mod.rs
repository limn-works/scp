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

pub mod context;
pub mod economy;
pub mod event_log;
pub mod identity;
pub mod nonce;
pub mod tools;
pub mod ucan;

use serde::{Deserialize, Serialize, de::DeserializeOwned};

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
