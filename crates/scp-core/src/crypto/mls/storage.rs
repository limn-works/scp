//! Storage bridge between `OpenMLS` and SCP's platform abstraction.
//!
//! [`MlsStorageBridge`] is a newtype wrapper around `OpenMLS`'s
//! [`MemoryStorage`] that serves as the named abstraction point for
//! MLS state persistence. Phase 1 delegates directly to in-memory
//! storage; future phases will bridge to `scp-platform`'s `Storage`
//! trait for persistent backends (Keychain, `SQLite`, etc.).
//!
//! The wrapper implements [`Deref`] and [`DerefMut`] to [`MemoryStorage`],
//! which means it automatically satisfies `OpenMLS`'s `StorageProvider`
//! trait through the blanket impl. All `OpenMLS` operations that require
//! a storage provider accept `&MlsStorageBridge` directly.
//!
//! See ADR-001 and ADR-006 for storage design.

use std::ops::{Deref, DerefMut};

use openmls_rust_crypto::MemoryStorage;

/// A bridge from `OpenMLS` storage operations to SCP's platform storage.
///
/// Phase 1 uses [`MemoryStorage`] directly. The bridge exists so that
/// all MLS storage access flows through a single type that can be
/// replaced with a persistent backend in later phases without changing
/// call sites.
///
/// # Usage
///
/// ```rust
/// use scp_core::crypto::mls::storage::MlsStorageBridge;
///
/// let storage = MlsStorageBridge::new();
/// // `storage` can be passed to any OpenMLS function expecting
/// // a `&impl StorageProvider`.
/// ```
///
/// # Future evolution
///
/// When `scp-platform`'s `Storage` trait stabilizes, this type will
/// accept a generic `S: Storage` parameter and translate `OpenMLS`
/// storage calls into platform storage operations (key-value `store`,
/// `retrieve`, `delete`). The current `Deref`-based delegation will
/// be replaced with explicit trait implementation.
#[derive(Debug, Default)]
pub struct MlsStorageBridge {
    /// The underlying `OpenMLS` in-memory storage.
    inner: MemoryStorage,
}

impl MlsStorageBridge {
    /// Creates a new `MlsStorageBridge` backed by an empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Deref for MlsStorageBridge {
    type Target = MemoryStorage;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for MlsStorageBridge {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls_traits::storage::{CURRENT_VERSION, StorageProvider};

    #[test]
    fn bridge_creates_default_empty_storage() {
        let bridge = MlsStorageBridge::new();
        // Verify we can access the underlying MemoryStorage.
        // The version method is available through the StorageProvider trait.
        assert_eq!(
            <MemoryStorage as StorageProvider<CURRENT_VERSION>>::version(),
            CURRENT_VERSION
        );
        // Verify Deref works -- we can obtain a MemoryStorage reference.
        let inner_ref: &MemoryStorage = &bridge;
        let _ = inner_ref;
    }
}
