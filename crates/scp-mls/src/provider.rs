//! The in-memory MLS provider, which wipes its storage when released.
//!
//! openmls keeps a group's HPKE private keys, epoch secrets, and message secrets
//! as serialized bytes in `openmls_memory_storage::MemoryStorage::values`, a
//! plain `HashMap<Vec<u8>, Vec<u8>>` that frees those bytes without zeroizing
//! them. [`InMemoryMlsProvider`] owns that storage and zeroizes every value when
//! it drops, so every owner (an [`crate::ScpMlsGroup`], a `KeyPackage` bundle's
//! provider, a provider rebuilt from a snapshot, or one dropped on an error path)
//! releases the storage wiped (security model spec §9.15).
//!
//! openmls itself replaces and deletes values during normal group operation, and
//! those superseded buffers are freed unzeroized inside `MemoryStorage`; this
//! type covers only the values present when the provider is released.

use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::{OpenMlsRustCrypto, RustCrypto};
use openmls_traits::OpenMlsProvider;
use zeroize::Zeroize;

/// The in-memory MLS provider: `openmls_rust_crypto`'s crypto and storage, with
/// every storage value zeroized on drop.
///
/// See ADR-001 and ADR-006 for the storage provider strategy, and ADR-057 for
/// why it lives in `scp-mls`.
#[derive(Default)]
pub struct InMemoryMlsProvider {
    inner: OpenMlsRustCrypto,
}

// SECURITY: the derived `Debug` of `OpenMlsRustCrypto` prints every storage value,
// which holds private key material, so this `Debug` prints only the entry count.
impl std::fmt::Debug for InMemoryMlsProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let entries = self.inner.storage().values.read().map_or(0, |v| v.len());
        f.debug_struct("InMemoryMlsProvider")
            .field("storage", &format_args!("[{entries} entries, REDACTED]"))
            .finish()
    }
}

impl OpenMlsProvider for InMemoryMlsProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        self.inner.storage()
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        self.inner.crypto()
    }

    fn rand(&self) -> &Self::RandProvider {
        self.inner.rand()
    }
}

impl Drop for InMemoryMlsProvider {
    /// Zeroizes every storage value in place before `MemoryStorage` frees the
    /// map, so each value's allocation is freed holding only zeroes
    /// (`Vec::zeroize` wipes the whole capacity and keeps the allocation).
    ///
    /// A poisoned lock does not stop the wipe: the map is taken from the poison
    /// error and wiped anyway, because a panic elsewhere does not make the key
    /// material less sensitive.
    fn drop(&mut self) {
        let mut values = self
            .inner
            .storage()
            .values
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for value in values.values_mut() {
            value.zeroize();
        }
    }
}
