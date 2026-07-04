//! Storage abstraction for the participant driver.
//!
//! The [`Storage`] trait is a minimal synchronous key/value interface the
//! driver uses to persist per-context participant snapshots (the in-memory MLS
//! provider snapshot plus the sender-key / event-log / membership state, per
//! ADR-057 component 3 and §17.9.1, which a browser backs with `IndexedDB`/OPFS).
//! It is deliberately tiny and synchronous so it compiles to wasm32 and a
//! browser backend can wrap an `IndexedDB`/OPFS shim.
//!
//! The driver writes a snapshot here after every state-mutating op and reads it
//! back through [`crate::ScpClient::restore_context`] /
//! [`crate::ScpClient::restore_all_contexts`] (ADR-057 T2). [`MemoryStorage`] is
//! the development/test backend; a browser supplies an `IndexedDB`/OPFS-backed
//! implementation of the same four methods.

use std::collections::HashMap;
use std::sync::Mutex;

/// A minimal synchronous key/value store.
///
/// Keys and values are opaque byte strings. Implementations must be
/// thread-safe (`Send + Sync`) so the driver can hold one behind an `Arc`.
///
/// Every method is **fallible** — a browser `IndexedDB`/OPFS backend can fail on
/// any access (quota, transaction abort, corruption), and the driver must be
/// able to surface that as a `SCP-STORAGE-8001` rather than mistaking a backend
/// fault for "absent" (which would silently drop durable state). `get` returns
/// `Ok(None)` only for a genuinely-missing key; a backend error is `Err`.
pub trait Storage: Send + Sync {
    /// Returns the value stored under `key`, `Ok(None)` if the key is genuinely
    /// absent, or `Err` if the backend read itself failed.
    ///
    /// # Errors
    ///
    /// Returns a backend-specific error string if the read fails (distinct from
    /// a missing key, which is `Ok(None)`).
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, String>;

    /// Stores `value` under `key`, overwriting any prior value.
    ///
    /// # Errors
    ///
    /// Returns a backend-specific error string if the write fails.
    fn put(&self, key: &str, value: Vec<u8>) -> Result<(), String>;

    /// Deletes the value stored under `key`. A no-op if the key is absent.
    ///
    /// # Errors
    ///
    /// Returns a backend-specific error string if the delete fails.
    fn delete(&self, key: &str) -> Result<(), String>;

    /// Returns every key that starts with `prefix`, in unspecified order.
    ///
    /// The driver uses this to enumerate its persisted contexts on reopen
    /// (there is no separate index to keep consistent). A browser backend maps
    /// this to an `IndexedDB` key-range / cursor scan.
    ///
    /// # Errors
    ///
    /// Returns a backend-specific error string if the enumeration fails.
    fn list_keys(&self, prefix: &str) -> Result<Vec<String>, String>;
}

/// In-memory [`Storage`] for the MVP driver.
///
/// Backs the key/value store with a `HashMap` behind a `Mutex`. This is the
/// development/test storage backend; a browser client supplies an
/// `IndexedDB`-backed backend in a later slice (ADR-057 component 3).
#[derive(Debug, Default)]
pub struct MemoryStorage {
    map: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryStorage {
    /// Creates a new, empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Storage for MemoryStorage {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        // A poisoned lock cannot corrupt a plain byte map; recover the guard.
        let map = self
            .map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(map.get(key).cloned())
    }

    fn put(&self, key: &str, value: Vec<u8>) -> Result<(), String> {
        self.map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key.to_owned(), value);
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<(), String> {
        self.map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(key);
        Ok(())
    }

    fn list_keys(&self, prefix: &str) -> Result<Vec<String>, String> {
        let map = self
            .map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(map
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }
}
