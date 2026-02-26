//! In-memory [`KeyCustody`] implementation for testing.
//!
//! Stores Ed25519 and X25519 keypairs in `HashMap`s indexed by opaque integer
//! handles. Supports optional seeded RNG for deterministic key generation.
//! See ADR-006 in `.docs/adrs/phase-1.md`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore, SeedableRng};
use sha2::Sha256;
use tokio::sync::Mutex;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::error::PlatformError;
use crate::traits::{
    CustodyType, KeyCustody, KeyHandle, KeyType, PseudonymKeypair, PublicKey, SharedSecret,
    Signature,
};

/// Tracks what type of key material is stored for a given handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredKeyType {
    Ed25519,
    X25519,
}

/// Internal key storage that holds both Ed25519 and X25519 private keys.
struct KeyStore {
    ed25519_keys: HashMap<u64, SigningKey>,
    x25519_keys: HashMap<u64, StaticSecret>,
    key_types: HashMap<u64, StoredKeyType>,
}

impl KeyStore {
    fn new() -> Self {
        Self {
            ed25519_keys: HashMap::new(),
            x25519_keys: HashMap::new(),
            key_types: HashMap::new(),
        }
    }

    /// Returns the stored key type for a handle, or an error if not found.
    fn lookup_type(&self, handle: KeyHandle) -> Result<StoredKeyType, PlatformError> {
        self.key_types
            .get(&handle.id())
            .copied()
            .ok_or(PlatformError::KeyNotFound)
    }
}

/// In-memory implementation of [`KeyCustody`] for testing and development.
///
/// Stores cryptographic key material in memory using `HashMap`s. Keys are
/// identified by opaque integer handles allocated by an atomic counter. This
/// implementation provides the same API surface as production hardware-backed
/// adapters (Secure Enclave, Android Keystore) but requires no platform
/// dependencies.
///
/// # Deterministic Testing
///
/// Use [`InMemoryKeyCustody::from_seed`] to create an instance with a seedable
/// RNG for reproducible test scenarios.
///
/// # Thread Safety
///
/// All mutable state is protected by a `tokio::sync::Mutex`, making this type
/// safe to share across async tasks.
///
/// See ADR-006 in `.docs/adrs/phase-1.md`.
pub struct InMemoryKeyCustody {
    store: Mutex<KeyStore>,
    rng: Mutex<Box<dyn RngCore + Send>>,
    next_id: AtomicU64,
}

/// A type-erased RNG that is both `RngCore` and `CryptoRng`.
///
/// Needed because `rand::rngs::StdRng` implements `CryptoRng` but we store
/// a `Box<dyn RngCore + Send>` for flexibility. This wrapper preserves the
/// `CryptoRng` marker for the seedable path while the non-seeded path uses
/// `rand::rngs::OsRng` (which is also `CryptoRng`).
struct CryptoRngWrapper<R: RngCore + CryptoRng + Send>(R);

impl<R: RngCore + CryptoRng + Send> RngCore for CryptoRngWrapper<R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl InMemoryKeyCustody {
    /// Creates a new in-memory key custody with a cryptographically secure RNG.
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: Mutex::new(KeyStore::new()),
            rng: Mutex::new(Box::new(CryptoRngWrapper(rand::rngs::OsRng))),
            next_id: AtomicU64::new(1),
        }
    }

    /// Creates a new in-memory key custody with a deterministic RNG seeded by
    /// `seed`.
    ///
    /// Useful for reproducible test scenarios: the same seed always produces
    /// the same sequence of keys.
    #[must_use]
    pub fn from_seed(seed: u64) -> Self {
        let mut seed_bytes = [0u8; 32];
        seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());
        let rng = rand::rngs::StdRng::from_seed(seed_bytes);
        Self {
            store: Mutex::new(KeyStore::new()),
            rng: Mutex::new(Box::new(CryptoRngWrapper(rng))),
            next_id: AtomicU64::new(1),
        }
    }

    /// Allocates the next key handle ID.
    fn next_handle(&self) -> KeyHandle {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        KeyHandle::new(id)
    }

    /// Imports an existing Ed25519 private key and returns a handle to it.
    ///
    /// This is used in tests where the signing key must match an externally
    /// provided key (e.g., the MLS group member's signing key for inner
    /// envelope signing in `open_envelope` tests).
    pub async fn import_ed25519_key(&self, private_key_bytes: &[u8; 32]) -> KeyHandle {
        let handle = self.next_handle();
        let signing_key = SigningKey::from_bytes(private_key_bytes);
        let mut store = self.store.lock().await;
        store.ed25519_keys.insert(handle.id(), signing_key);
        store.key_types.insert(handle.id(), StoredKeyType::Ed25519);
        handle
    }
}

impl Default for InMemoryKeyCustody {
    fn default() -> Self {
        Self::new()
    }
}

// The trait uses RPITIT (`-> impl Future<...> + Send`), so each impl method
// must return a future rather than use `async fn` directly.
#[allow(clippy::manual_async_fn)]
impl KeyCustody for InMemoryKeyCustody {
    fn generate_keypair(
        &self,
        key_type: KeyType,
    ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send {
        async move {
            let handle = self.next_handle();
            let mut key_bytes = [0u8; 32];
            self.rng.lock().await.fill_bytes(&mut key_bytes);

            let mut store = self.store.lock().await;
            match key_type {
                KeyType::Ed25519 => {
                    let signing_key = SigningKey::from_bytes(&key_bytes);
                    store.ed25519_keys.insert(handle.id(), signing_key);
                    store.key_types.insert(handle.id(), StoredKeyType::Ed25519);
                }
                KeyType::X25519 => {
                    let secret = StaticSecret::from(key_bytes);
                    store.x25519_keys.insert(handle.id(), secret);
                    store.key_types.insert(handle.id(), StoredKeyType::X25519);
                }
            }
            drop(store);

            Ok(handle)
        }
    }

    fn sign(
        &self,
        key: &KeyHandle,
        data: &[u8],
    ) -> impl Future<Output = Result<Signature, PlatformError>> + Send {
        let key_id = key.id();
        async move {
            let store = self.store.lock().await;
            let key_type = store.lookup_type(KeyHandle::new(key_id))?;

            if key_type != StoredKeyType::Ed25519 {
                return Err(PlatformError::WrongKeyType {
                    expected: KeyType::Ed25519,
                    actual: KeyType::X25519,
                });
            }

            let signing_key = store
                .ed25519_keys
                .get(&key_id)
                .ok_or(PlatformError::KeyNotFound)?;

            let signature = signing_key.sign(data);
            drop(store);
            Ok(Signature::new(signature.to_bytes().to_vec()))
        }
    }

    fn public_key(
        &self,
        key: &KeyHandle,
    ) -> impl Future<Output = Result<PublicKey, PlatformError>> + Send {
        let key_id = key.id();
        async move {
            let store = self.store.lock().await;
            let key_type = store.lookup_type(KeyHandle::new(key_id))?;

            let result = match key_type {
                StoredKeyType::Ed25519 => {
                    let signing_key = store
                        .ed25519_keys
                        .get(&key_id)
                        .ok_or(PlatformError::KeyNotFound)?;
                    let verifying_key: VerifyingKey = signing_key.verifying_key();
                    Ok(PublicKey::new(verifying_key.to_bytes().to_vec()))
                }
                StoredKeyType::X25519 => {
                    let secret = store
                        .x25519_keys
                        .get(&key_id)
                        .ok_or(PlatformError::KeyNotFound)?;
                    let public = X25519PublicKey::from(secret);
                    Ok(PublicKey::new(public.to_bytes().to_vec()))
                }
            };
            drop(store);
            result
        }
    }

    fn destroy_key(
        &self,
        key: &KeyHandle,
    ) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let key_id = key.id();
        async move {
            let mut store = self.store.lock().await;
            let key_type = store.lookup_type(KeyHandle::new(key_id))?;

            match key_type {
                StoredKeyType::Ed25519 => {
                    store.ed25519_keys.remove(&key_id);
                }
                StoredKeyType::X25519 => {
                    store.x25519_keys.remove(&key_id);
                }
            }
            store.key_types.remove(&key_id);
            drop(store);

            Ok(())
        }
    }

    fn dh_agree(
        &self,
        key: &KeyHandle,
        peer_public: &[u8; 32],
    ) -> impl Future<Output = Result<SharedSecret, PlatformError>> + Send {
        let key_id = key.id();
        let peer = *peer_public;
        async move {
            let store = self.store.lock().await;
            let key_type = store.lookup_type(KeyHandle::new(key_id))?;

            if key_type != StoredKeyType::X25519 {
                return Err(PlatformError::WrongKeyType {
                    expected: KeyType::X25519,
                    actual: KeyType::Ed25519,
                });
            }

            let secret = store
                .x25519_keys
                .get(&key_id)
                .ok_or(PlatformError::KeyNotFound)?;

            let peer_key = X25519PublicKey::from(peer);
            let shared = secret.diffie_hellman(&peer_key);
            drop(store);
            Ok(SharedSecret::new(shared.to_bytes()))
        }
    }

    fn derive_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
    ) -> impl Future<Output = Result<PseudonymKeypair, PlatformError>> + Send {
        let key_id = key.id();
        let context_id = context_id.to_vec();
        async move {
            let mut store = self.store.lock().await;
            let key_type = store.lookup_type(KeyHandle::new(key_id))?;

            if key_type != StoredKeyType::Ed25519 {
                return Err(PlatformError::WrongKeyType {
                    expected: KeyType::Ed25519,
                    actual: KeyType::X25519,
                });
            }

            let signing_key = store
                .ed25519_keys
                .get(&key_id)
                .ok_or(PlatformError::KeyNotFound)?;

            // HMAC-SHA256(ed25519_private_key_bytes, context_id || "scp-pseudonym")
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(signing_key.to_bytes().as_slice())
                .map_err(|e| PlatformError::CustodyError(e.to_string()))?;
            mac.update(&context_id);
            mac.update(b"scp-pseudonym");
            let hmac_output = mac.finalize().into_bytes();

            // Derive Ed25519 keypair from first 32 bytes of HMAC output.
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&hmac_output[..32]);
            let pseudonym_signing_key = SigningKey::from_bytes(&seed);
            let pseudonym_verifying_key = pseudonym_signing_key.verifying_key();

            // Store the derived signing key and return a handle.
            let handle = self.next_handle();
            store
                .ed25519_keys
                .insert(handle.id(), pseudonym_signing_key);
            store.key_types.insert(handle.id(), StoredKeyType::Ed25519);
            drop(store);

            Ok(PseudonymKeypair {
                public_key: PublicKey::new(pseudonym_verifying_key.to_bytes().to_vec()),
                key_handle: handle,
            })
        }
    }

    fn custody_type(&self, _key: &KeyHandle) -> CustodyType {
        CustodyType::InMemory
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generate_ed25519_keypair_returns_handle() {
        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        assert!(handle.id() > 0);
    }

    #[tokio::test]
    async fn generate_x25519_keypair_returns_handle() {
        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::X25519).await.unwrap();
        assert!(handle.id() > 0);
    }

    #[tokio::test]
    async fn sign_with_ed25519_key_succeeds() {
        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let data = b"hello world";
        let sig = custody.sign(&handle, data).await.unwrap();
        assert_eq!(sig.as_bytes().len(), 64);
    }

    #[tokio::test]
    async fn sign_with_x25519_key_fails() {
        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::X25519).await.unwrap();
        let result = custody.sign(&handle, b"data").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            PlatformError::WrongKeyType { expected, actual } => {
                assert_eq!(expected, KeyType::Ed25519);
                assert_eq!(actual, KeyType::X25519);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn public_key_ed25519_returns_32_bytes() {
        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let pubkey = custody.public_key(&handle).await.unwrap();
        assert_eq!(pubkey.as_bytes().len(), 32);
    }

    #[tokio::test]
    async fn public_key_x25519_returns_32_bytes() {
        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::X25519).await.unwrap();
        let pubkey = custody.public_key(&handle).await.unwrap();
        assert_eq!(pubkey.as_bytes().len(), 32);
    }

    #[tokio::test]
    async fn destroy_key_makes_subsequent_operations_fail() {
        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        // Key works before destruction.
        custody.sign(&handle, b"test").await.unwrap();

        // Destroy the key.
        custody.destroy_key(&handle).await.unwrap();

        // All operations should now fail.
        assert!(custody.sign(&handle, b"test").await.is_err());
        assert!(custody.public_key(&handle).await.is_err());
        assert!(custody.destroy_key(&handle).await.is_err());
    }

    #[tokio::test]
    async fn dh_agree_with_x25519_keys_produces_shared_secret() {
        let custody = InMemoryKeyCustody::new();

        let alice_handle = custody.generate_keypair(KeyType::X25519).await.unwrap();
        let bob_handle = custody.generate_keypair(KeyType::X25519).await.unwrap();

        let alice_pub = custody.public_key(&alice_handle).await.unwrap();
        let bob_pub = custody.public_key(&bob_handle).await.unwrap();

        let alice_bytes: [u8; 32] = alice_pub.as_bytes().try_into().unwrap();
        let bob_bytes: [u8; 32] = bob_pub.as_bytes().try_into().unwrap();

        let secret_ab = custody.dh_agree(&alice_handle, &bob_bytes).await.unwrap();
        let secret_ba = custody.dh_agree(&bob_handle, &alice_bytes).await.unwrap();

        // Both sides compute the same shared secret.
        assert_eq!(secret_ab.as_bytes(), secret_ba.as_bytes());
    }

    #[tokio::test]
    async fn dh_agree_with_ed25519_key_fails() {
        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let peer = [0u8; 32];
        let result = custody.dh_agree(&handle, &peer).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            PlatformError::WrongKeyType { expected, actual } => {
                assert_eq!(expected, KeyType::X25519);
                assert_eq!(actual, KeyType::Ed25519);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn derive_pseudonym_is_deterministic() {
        let custody = InMemoryKeyCustody::from_seed(42);
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let context_id = b"test-context";

        let first = custody.derive_pseudonym(&handle, context_id).await.unwrap();
        let second = custody.derive_pseudonym(&handle, context_id).await.unwrap();

        // Same identity key + same context_id = same pseudonym public key.
        assert_eq!(first.public_key.as_bytes(), second.public_key.as_bytes());
    }

    #[tokio::test]
    async fn derive_pseudonym_different_contexts_produce_different_keys() {
        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        let first = custody
            .derive_pseudonym(&handle, b"context-a")
            .await
            .unwrap();
        let second = custody
            .derive_pseudonym(&handle, b"context-b")
            .await
            .unwrap();

        // Different contexts produce different pseudonyms.
        assert_ne!(first.public_key.as_bytes(), second.public_key.as_bytes());
    }

    #[tokio::test]
    async fn derive_pseudonym_with_x25519_key_fails() {
        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::X25519).await.unwrap();
        let result = custody.derive_pseudonym(&handle, b"ctx").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            PlatformError::WrongKeyType { expected, actual } => {
                assert_eq!(expected, KeyType::Ed25519);
                assert_eq!(actual, KeyType::X25519);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn custody_type_always_returns_in_memory() {
        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        assert_eq!(custody.custody_type(&handle), CustodyType::InMemory);
    }

    #[tokio::test]
    async fn sign_with_destroyed_key_returns_key_not_found() {
        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        custody.destroy_key(&handle).await.unwrap();
        match custody.sign(&handle, b"data").await.unwrap_err() {
            PlatformError::KeyNotFound => {}
            other => panic!("expected KeyNotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sign_with_invalid_handle_returns_key_not_found() {
        let custody = InMemoryKeyCustody::new();
        let bogus = KeyHandle::new(9999);
        match custody.sign(&bogus, b"data").await.unwrap_err() {
            PlatformError::KeyNotFound => {}
            other => panic!("expected KeyNotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn seeded_custody_produces_deterministic_keys() {
        let first = InMemoryKeyCustody::from_seed(12345);
        let second = InMemoryKeyCustody::from_seed(12345);

        let handle_first = first.generate_keypair(KeyType::Ed25519).await.unwrap();
        let handle_second = second.generate_keypair(KeyType::Ed25519).await.unwrap();

        let pk_first = first.public_key(&handle_first).await.unwrap();
        let pk_second = second.public_key(&handle_second).await.unwrap();

        assert_eq!(pk_first.as_bytes(), pk_second.as_bytes());
    }

    #[tokio::test]
    async fn ed25519_signature_verifies_correctly() {
        use ed25519_dalek::Verifier;

        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let data = b"important message";

        let sig = custody.sign(&handle, data).await.unwrap();
        let pubkey = custody.public_key(&handle).await.unwrap();

        let pk_bytes: [u8; 32] = pubkey.as_bytes().try_into().unwrap();
        let verifying_key = VerifyingKey::from_bytes(&pk_bytes).unwrap();
        let sig_bytes: [u8; 64] = sig.as_bytes().try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        assert!(verifying_key.verify(data, &signature).is_ok());
    }

    #[tokio::test]
    async fn derive_pseudonym_key_handle_can_sign() {
        use ed25519_dalek::Verifier;

        let custody = InMemoryKeyCustody::new();
        let identity_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let pseudonym = custody
            .derive_pseudonym(&identity_handle, b"context-1")
            .await
            .unwrap();

        let data = b"pseudonym signed message";
        let sig = custody.sign(&pseudonym.key_handle, data).await.unwrap();

        let pk_bytes: [u8; 32] = pseudonym.public_key.as_bytes().try_into().unwrap();
        let verifying_key = VerifyingKey::from_bytes(&pk_bytes).unwrap();
        let sig_bytes: [u8; 64] = sig.as_bytes().try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        assert!(verifying_key.verify(data, &signature).is_ok());
    }

    #[tokio::test]
    async fn handles_are_unique_across_key_types() {
        let custody = InMemoryKeyCustody::new();
        let h1 = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let h2 = custody.generate_keypair(KeyType::X25519).await.unwrap();
        let h3 = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        assert_ne!(h1.id(), h2.id());
        assert_ne!(h2.id(), h3.id());
        assert_ne!(h1.id(), h3.id());
    }
}
