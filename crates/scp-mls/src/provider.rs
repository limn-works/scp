//! The in-memory MLS provider: storage wiped on release, and randomness drawn
//! from the operating system on every request.
//!
//! openmls keeps a group's HPKE private keys, epoch secrets, and message secrets
//! as serialized bytes in `openmls_memory_storage::MemoryStorage::values`, a
//! plain `HashMap<Vec<u8>, Vec<u8>>` that frees those bytes without zeroizing
//! them. [`InMemoryMlsProvider`] owns that storage and zeroizes every value when
//! it drops, so every owner (an [`crate::ScpMlsGroup`], a `KeyPackage` bundle's
//! provider, a provider rebuilt from a snapshot, or one dropped on an error path)
//! releases the storage wiped (security model spec §9.15 step 2).
//!
//! openmls draws path secrets, leaf HPKE key pairs, init secrets, and commit
//! randomness from `provider.rand()`. `openmls_rust_crypto`'s `RustCrypto`
//! answers that from one `ChaCha20Rng` seeded once per provider and never
//! reseeded or zeroized, so its seed would regenerate every one of those secrets.
//! [`OsRand`] replaces it as the `RandProvider`: each request reads the
//! operating system's generator and keeps nothing, so no seed exists to recover.
//!
//! What the wipe does not cover:
//! - values openmls replaces or deletes during normal group operation, which
//!   `MemoryStorage` frees unzeroized before the provider is released;
//! - the copies `openmls_memory_storage` 0.6.0's `MemoryStorage` makes while
//!   it encodes and decodes. It encodes each secret through
//!   `serde_json::to_vec`, whose growing buffer frees its smaller copies
//!   unwiped; it stores `value.to_vec()` and drops the original unwiped; on
//!   each list append and removal it decodes the stored list and re-encodes
//!   it into the stored `Vec`, which grows and frees what it outgrew
//!   unwiped; and it decodes every read through `serde_json`. SCP's own
//!   encoders do not reach inside this store;
//! - the `ChaCha20Rng` inside the wrapped `RustCrypto`. It stays in memory for
//!   the provider's life, and two kinds of draw reach its seed.
//!   `OpenMlsCrypto::signature_key_gen` is one: the `disallowed-methods` ban
//!   in `.clippy.toml` and `crates/scp-runtime/clippy.toml` forbids it, and
//!   SCP creates signers through `SignatureKeyPair::new`, which draws from
//!   `OsRng`. `OpenMlsRand::random_array` and `random_vec` are the other:
//!   `RustCrypto` implements `OpenMlsRand` too, so `crypto()` exposes them.
//!   No SCP code calls them through `crypto()` today, but nothing enforces
//!   that yet;
//! - HPKE encapsulation randomness. openmls draws it through `crypto()`, not
//!   `rand()`: each `hpke_seal` builds an hpke-rs context whose
//!   `HpkeRustCryptoPrng` seeds a `ChaCha20Rng` from the operating system for
//!   that call, and that type's `Zeroize` is a no-op, so the generator state
//!   is freed unwiped. [`OsRand`] therefore covers `rand()` draws only;
//! - hpke-rs 0.7.0's encapsulation intermediates. The input key material
//!   `hpke.random()` returns is a plain `Vec<u8>`, and the ephemeral private
//!   key is derived from it, so that key's own zeroize on drop does not cover
//!   the ephemeral secret. The Diffie-Hellman output, the `eae_prk`, and the
//!   KEM shared secret `zz` are plain `Vec<u8>` too;
//! - hpke-rs's `derive_key_pair`, which openmls reaches through
//!   `derive_hpke_keypair` for every leaf and path-node encryption key. It
//!   leaves the `labeled_ikm` it builds from the node secret and the
//!   `dkp_prk` it extracts in plain `Vec<u8>`;
//! - decapsulation (`hpke_open`, `hpke_setup_receiver_and_export`), which
//!   leaves the Diffie-Hellman output, the `eae_prk`, and `zz` in plain
//!   `Vec<u8>`.

use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::{OpenMlsRustCrypto, RustCrypto};
use openmls_traits::OpenMlsProvider;
use openmls_traits::random::OpenMlsRand;
use zeroize::Zeroize;

/// openmls's randomness source for [`InMemoryMlsProvider`]: every request reads
/// the operating system's generator (`getrandom`) and the type holds no state,
/// so no seed outlives a single call.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRand;

/// The operating system's random source failed to fill a request.
#[derive(Debug, thiserror::Error)]
#[error("operating-system random source failed: {0}")]
pub struct OsRandError(getrandom::Error);

impl OpenMlsRand for OsRand {
    type Error = OsRandError;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        let mut out = [0u8; N];
        getrandom::getrandom(&mut out).map_err(OsRandError)?;
        Ok(out)
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut out = vec![0u8; len];
        getrandom::getrandom(&mut out).map_err(OsRandError)?;
        Ok(out)
    }
}

/// The in-memory MLS provider: `openmls_rust_crypto`'s crypto and storage, with
/// every storage value zeroized on drop, and [`OsRand`] as the random source.
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
    type RandProvider = OsRand;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        self.inner.storage()
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        self.inner.crypto()
    }

    fn rand(&self) -> &Self::RandProvider {
        // `OsRand` is a stateless unit value, so every provider shares the one
        // promoted constant; there is no per-provider generator to hold.
        &OsRand
    }
}

// openmls draws path secrets, leaf HPKE keys, and init secrets from
// `provider.rand()`, so the provider's `RandProvider` must be the stateless OS
// source: `RustCrypto` there again would put one long-lived seed behind every
// one of those secrets (security model spec §9.15 step 2). Both assertions fail
// the build: the first if `rand()` returns any other type, the second if
// `OsRand` gains a field, since a zero-sized source has nowhere to keep a seed
// or a stream position.
const _: fn(&InMemoryMlsProvider) -> &OsRand = <InMemoryMlsProvider as OpenMlsProvider>::rand;
const _: () = assert!(std::mem::size_of::<OsRand>() == 0);

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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Two arrays from `OsRand` differ, and neither an array nor a vector
    /// comes back all zeroes.
    #[test]
    fn os_rand_returns_nonconstant_bytes() {
        let provider = InMemoryMlsProvider::default();
        let a: [u8; 32] = provider.rand().random_array().unwrap();
        let b: [u8; 32] = provider.rand().random_array().unwrap();
        let v = provider.rand().random_vec(48).unwrap();
        assert_eq!(v.len(), 48);
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
        assert_ne!(v, vec![0u8; 48]);
    }

    /// `RustCrypto::signature_key_gen` draws from the provider's long-lived
    /// `ChaCha20Rng`, which `OsRand` does not replace.
    ///
    /// The `expect` is the control for the `signature_key_gen` entry in the
    /// workspace `.clippy.toml`: it is unfulfilled, and the CI clippy run
    /// (`-D warnings`) fails, when that entry stops disallowing the call.
    #[test]
    fn signature_key_gen_is_disallowed() {
        use openmls_traits::crypto::OpenMlsCrypto;
        use openmls_traits::types::SignatureScheme;

        let provider = InMemoryMlsProvider::default();
        #[expect(
            clippy::disallowed_methods,
            reason = "control for the lint: generates a signer from the long-lived seed on purpose"
        )]
        let (private, public) = provider
            .crypto()
            .signature_key_gen(SignatureScheme::ED25519)
            .unwrap();
        assert_eq!(public.len(), 32);
        assert!(!private.is_empty());
    }
}
