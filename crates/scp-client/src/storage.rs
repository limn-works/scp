//! Storage abstraction for the participant driver.
//!
//! The [`Storage`] trait is a minimal synchronous key/value interface the
//! driver uses to persist out-of-band snapshots (e.g. the in-memory MLS
//! provider snapshot, per ADR-057 component 3, which a browser would back with
//! `IndexedDB`). It is deliberately tiny and synchronous so it compiles to
//! wasm32 and a browser backend can wrap an `IndexedDB` shim in a later slice.
//!
//! For the Slice-2 MVP the concrete impl is [`MemoryStorage`], a `HashMap`. The
//! MVP message path does not yet snapshot through this — it is wired so the
//! driver carries a storage handle from construction, keeping the dependency
//! explicit and ready for Slice 3 (`IndexedDB`) without an API change.

use std::collections::HashMap;
use std::sync::Mutex;

/// A minimal synchronous key/value store.
///
/// Keys and values are opaque byte strings. Implementations must be
/// thread-safe (`Send + Sync`) so the driver can hold one behind an `Arc`.
///
/// The trait is intentionally infallible-by-value for `get` (returns
/// `Option`) and fallible for the mutating operations, mirroring the shape a
/// browser `IndexedDB`-backed implementation needs (writes can fail; a missing
/// key is not an error).
pub trait Storage: Send + Sync {
    /// Returns the value stored under `key`, or `None` if absent.
    fn get(&self, key: &str) -> Option<Vec<u8>>;

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
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        // A poisoned lock cannot corrupt a plain byte map; recover the guard.
        let map = self
            .map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.get(key).cloned()
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
}
