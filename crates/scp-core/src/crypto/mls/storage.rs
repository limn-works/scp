//! `StorageProvider` bridge to scp-platform storage adapters.
//!
//! `OpenMLS` requires a `StorageProvider` trait implementation for persisting
//! group state, key packages, and other MLS artifacts. This module bridges
//! between the `OpenMLS` storage requirements and the scp-platform `Storage`
//! trait.
//!
//! # Phase 1
//!
//! Phase 1 uses the in-memory provider from ADR-006. The
//! [`ScpMlsProvider`] wraps `OpenMlsRustCrypto` which includes
//! `openmls_memory_storage::MemoryStorage` as its storage backend. This
//! provides a complete `OpenMlsProvider` implementation with no external
//! dependencies.
//!
//! # Future Phases
//!
//! Production storage providers (Keychain, `SQLite`) will implement the
//! `StorageProvider` trait by delegating to the scp-platform `Storage`
//! adapter, with `MessagePack` serialization for values.

use openmls_rust_crypto::OpenMlsRustCrypto;

/// The MLS provider type used by SCP for cryptographic operations and storage.
///
/// In Phase 1, this is `OpenMlsRustCrypto`, which bundles:
/// - `RustCrypto`-based cryptographic primitives (X25519, AES-128-GCM, SHA-256, Ed25519)
/// - In-memory `MemoryStorage` for MLS state persistence
/// - A cryptographically secure random number generator
///
/// This type satisfies the `OpenMlsProvider` trait required by all `OpenMLS`
/// group operations. Future phases will replace the storage backend with
/// scp-platform `Storage` adapters while keeping the same crypto primitives.
///
/// See ADR-001 and ADR-006 for the storage provider strategy.
pub type ScpMlsProvider = OpenMlsRustCrypto;

/// Creates a new [`ScpMlsProvider`] instance with in-memory storage.
///
/// Each provider instance has independent storage. In Phase 1, this means
/// each participant in a test scenario needs their own provider instance.
///
/// # Example
///
/// ```rust,ignore
/// let provider = scp_core::crypto::mls::storage::new_provider();
/// ```
#[must_use]
pub fn new_provider() -> ScpMlsProvider {
    OpenMlsRustCrypto::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls_traits::OpenMlsProvider;

    #[test]
    fn provider_exposes_storage_and_crypto() {
        let provider = new_provider();
        // Verify the provider implements the required traits by accessing
        // its storage and crypto components.
        let _storage = provider.storage();
        let _crypto = provider.crypto();
    }
}
