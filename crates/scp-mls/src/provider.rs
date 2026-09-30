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

use std::collections::HashMap;

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
    /// Zeroizes every storage value before `MemoryStorage` frees the map.
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
        zeroize_values(&mut values);
    }
}

/// Zeroizes every value in `values` in place, leaving each an empty vector with
/// its allocation still held, so the caller frees only zeroed memory.
fn zeroize_values(values: &mut HashMap<Vec<u8>, Vec<u8>>) {
    for value in values.values_mut() {
        value.zeroize();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn zeroize_values_empties_every_value_in_its_own_allocation() {
        let mut values: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        values.insert(b"EpochSecrets-a".to_vec(), vec![0xAB; 64]);
        values.insert(b"EncryptionKeyPair-b".to_vec(), vec![0xCD; 32]);
        let capacities: HashMap<Vec<u8>, usize> = values
            .iter()
            .map(|(k, v)| (k.clone(), v.capacity()))
            .collect();

        zeroize_values(&mut values);

        // Both entries are still in the map, so the vectors inspected here are the
        // original allocations: each is emptied (zeroize clears after wiping) and
        // keeps its capacity, so nothing was freed or reallocated before the wipe.
        assert_eq!(values.len(), 2);
        for (key, value) in &values {
            assert!(value.is_empty(), "value under {key:?} was not zeroized");
            assert_eq!(value.capacity(), capacities[key]);
        }
    }

    /// `Drop` recovers a poisoned storage lock and wipes anyway instead of
    /// panicking (a panic inside `drop` during unwinding aborts the process).
    #[test]
    #[allow(clippy::panic)]
    fn drop_wipes_through_a_poisoned_storage_lock() {
        let provider = InMemoryMlsProvider::default();
        provider
            .storage()
            .values
            .write()
            .unwrap()
            .insert(b"EpochSecrets-a".to_vec(), vec![0xAB; 64]);
        std::thread::scope(|s| {
            let poisoner = s.spawn(|| {
                let _guard = provider.storage().values.write().unwrap();
                panic!("poison the storage lock");
            });
            assert!(poisoner.join().is_err());
        });
        assert!(provider.storage().values.is_poisoned());

        drop(provider);
    }
}
