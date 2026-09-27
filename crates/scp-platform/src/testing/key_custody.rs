//! In-memory [`KeyCustody`] implementation for testing.
//!
//! Stores Ed25519, X25519 and P-256 keypairs in `HashMap`s indexed by opaque
//! integer handles. Supports optional seeded RNG for deterministic key generation.
//! See ADR-006 in `.docs/adrs/phase-1.md`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::{CryptoRng, RngCore, SeedableRng};
use tokio::sync::Mutex;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::PlatformError;
use crate::traits::{
    CustodyType, KeyCustody, KeyHandle, KeyType, PseudonymKeypair, PublicKey, SharedSecret,
    Signature,
};

/// The error for using a key of type `actual` where `expected` is required.
const fn wrong_type(actual: KeyType, expected: KeyType) -> PlatformError {
    PlatformError::WrongKeyType { expected, actual }
}

/// Internal key storage. P-256 signing and HPKE keys share `p256_keys`; the
/// handle's entry in `key_types` says which operations it permits.
struct KeyStore {
    ed25519_keys: HashMap<u64, SigningKey>,
    x25519_keys: HashMap<u64, StaticSecret>,
    p256_keys: HashMap<u64, P256SigningKey>,
    key_types: HashMap<u64, KeyType>,
}

impl KeyStore {
    fn new() -> Self {
        Self {
            ed25519_keys: HashMap::new(),
            x25519_keys: HashMap::new(),
            p256_keys: HashMap::new(),
            key_types: HashMap::new(),
        }
    }

    /// Returns the stored key type for a handle, or an error if not found.
    fn lookup_type(&self, handle: KeyHandle) -> Result<KeyType, PlatformError> {
        self.key_types
            .get(&handle.id())
            .copied()
            .ok_or(PlatformError::KeyNotFound)
    }

    fn p256_key(&self, key_id: u64) -> Result<&P256SigningKey, PlatformError> {
        self.p256_keys
            .get(&key_id)
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
/// Use [`InMemoryKeyCustody::from_seed_bytes`] to create an instance with a
/// seedable RNG for reproducible test scenarios.
///
/// # Thread Safety
///
/// All mutable state is protected by a `tokio::sync::Mutex`, making this type
/// safe to share across async tasks.
///
/// See ADR-006 in `.docs/adrs/phase-1.md`.
pub struct InMemoryKeyCustody {
    store: Mutex<KeyStore>,
    // Trait-object RNG that preserves the `CryptoRng` marker across the
    // `Box<dyn ...>` boundary. Both constructors (`new` from `OsRng`,
    // `from_seed_bytes` from `StdRng::from_seed`) only accept RNGs that
    // are `CryptoRng + RngCore + Send`, so the marker is upheld at
    // every call site.
    rng: Mutex<Box<dyn SecureRng>>,
    next_id: AtomicU64,
}

/// Composite trait combining [`RngCore`], [`CryptoRng`], and [`Send`].
///
/// The `Box<dyn SecureRng>` held by [`InMemoryKeyCustody`] is a
/// trait-object RNG. A bare `Box<dyn RngCore + Send>` would lose the
/// [`CryptoRng`] marker at the trait-object boundary — consumers of
/// the boxed RNG would see only [`RngCore`]. This composite trait
/// keeps both markers observable through erasure, and the blanket
/// impl covers every concrete RNG that already satisfies the bound.
trait SecureRng: RngCore + CryptoRng + Send {}

impl<R: RngCore + CryptoRng + Send + ?Sized> SecureRng for R {}

impl InMemoryKeyCustody {
    /// Creates a new in-memory key custody with a cryptographically secure RNG.
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: Mutex::new(KeyStore::new()),
            rng: Mutex::new(Box::new(rand::rngs::OsRng)),
            next_id: AtomicU64::new(1),
        }
    }

    /// Creates a new in-memory key custody with a deterministic RNG seeded by
    /// the full 32-byte `seed`.
    ///
    /// This is the byte-level seed API used by cross-bridge parity testing
    /// (ADR-046): bridges that accept a 32-byte seed from the harness feed it
    /// directly into this constructor so that every bridge's
    /// `generate_keypair` call sequence yields byte-identical Ed25519 signing
    /// keys. Callers with a narrower source of entropy (e.g. a u64
    /// determinism fixture) must zero-pad into a full `[u8; 32]` at the
    /// call site — the library no longer does this implicitly.
    ///
    /// # Determinism contract
    ///
    /// Given a fixed `seed`, `rand::rngs::StdRng::from_seed(seed)` produces a
    /// deterministic byte stream. `KeyCustody::generate_keypair` consumes
    /// exactly 32 bytes from the RNG per call (via `fill_bytes`), whatever the
    /// key type, and feeds them into `ed25519_dalek::SigningKey::from_bytes`
    /// (Ed25519), `StaticSecret::from` (X25519) or
    /// `P256SigningKey::from_scalar_bytes` (both P-256 types). The first
    /// handle therefore has private key `seed_stream[0..32]`, the second has
    /// `seed_stream[32..64]`, and so on. This contract is the basis of the
    /// cross-bridge byte-exact identity parity test.
    ///
    /// A P-256 draw that is not a valid scalar (zero or `>= n`, probability
    /// about 2^-32) fails the call with [`PlatformError::CustodyError`]
    /// rather than drawing again, so the stream position never depends on
    /// the key material.
    #[must_use]
    pub fn from_seed_bytes(seed: [u8; 32]) -> Self {
        let rng = rand::rngs::StdRng::from_seed(seed);
        Self {
            store: Mutex::new(KeyStore::new()),
            rng: Mutex::new(Box::new(rng)),
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
        store.key_types.insert(handle.id(), KeyType::Ed25519);
        handle
    }

    /// Exports a clone of the Ed25519 signing key for the given handle.
    ///
    /// Required by FFI bridges that need the raw `ed25519_dalek::SigningKey`
    /// for core governance functions (`propose_governance_action`,
    /// `approve_governance_proposal`, etc.) which take `&SigningKey` directly.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::KeyNotFound`] if the handle is invalid.
    /// Returns [`PlatformError::WrongKeyType`] if the handle refers to an
    /// X25519 key.
    pub async fn export_ed25519_signing_key(
        &self,
        handle: &KeyHandle,
    ) -> Result<SigningKey, PlatformError> {
        let store = self.store.lock().await;
        let key_type = store.lookup_type(*handle)?;
        if key_type != KeyType::Ed25519 {
            return Err(wrong_type(key_type, KeyType::Ed25519));
        }
        store
            .ed25519_keys
            .get(&handle.id())
            .cloned()
            .ok_or(PlatformError::KeyNotFound)
    }
}

impl Default for InMemoryKeyCustody {
    fn default() -> Self {
        Self::new()
    }
}

use scp_crypto::p256::P256SigningKey;
use scp_crypto::pseudonym::derive_pseudonym_keypair;

// Trait uses RPITIT with explicit `+ Send` bound; async fn in trait
// does not guarantee Send futures, so manual impl Future is required.
#[allow(clippy::manual_async_fn)]
impl KeyCustody for InMemoryKeyCustody {
    fn generate_keypair(
        &self,
        key_type: KeyType,
    ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send {
        async move {
            let handle = self.next_handle();
            let mut key_bytes = Zeroizing::new([0u8; 32]);
            self.rng.lock().await.fill_bytes(key_bytes.as_mut());

            let mut store = self.store.lock().await;
            match key_type {
                KeyType::Ed25519 => {
                    let signing_key = SigningKey::from_bytes(&key_bytes);
                    store.ed25519_keys.insert(handle.id(), signing_key);
                    store.key_types.insert(handle.id(), KeyType::Ed25519);
                }
                KeyType::X25519 => {
                    let secret = StaticSecret::from(*key_bytes);
                    store.x25519_keys.insert(handle.id(), secret);
                    store.key_types.insert(handle.id(), KeyType::X25519);
                }
                KeyType::P256Signing | KeyType::HpkeP256 => {
                    let key = P256SigningKey::from_scalar_bytes(&key_bytes).map_err(|e| {
                        PlatformError::CustodyError(format!(
                            "RNG draw is not a valid P-256 scalar: {e}"
                        ))
                    })?;
                    store.p256_keys.insert(handle.id(), key);
                    store.key_types.insert(handle.id(), key_type);
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

            match key_type {
                KeyType::Ed25519 => {}
                KeyType::P256Signing => {
                    return crate::traits::sign_p256_digest(store.p256_key(key_id)?, data);
                }
                KeyType::X25519 => return Err(wrong_type(key_type, KeyType::Ed25519)),
                KeyType::HpkeP256 => return Err(wrong_type(key_type, KeyType::P256Signing)),
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
                KeyType::Ed25519 => {
                    let signing_key = store
                        .ed25519_keys
                        .get(&key_id)
                        .ok_or(PlatformError::KeyNotFound)?;
                    let verifying_key: VerifyingKey = signing_key.verifying_key();
                    Ok(PublicKey::new(verifying_key.to_bytes().to_vec()))
                }
                KeyType::X25519 => {
                    let secret = store
                        .x25519_keys
                        .get(&key_id)
                        .ok_or(PlatformError::KeyNotFound)?;
                    let public = X25519PublicKey::from(secret);
                    Ok(PublicKey::new(public.to_bytes().to_vec()))
                }
                KeyType::P256Signing => Ok(PublicKey::new(
                    store
                        .p256_key(key_id)?
                        .public_key()
                        .to_compressed()
                        .to_vec(),
                )),
                KeyType::HpkeP256 => Ok(PublicKey::new(
                    store
                        .p256_key(key_id)?
                        .public_key()
                        .to_uncompressed()
                        .to_vec(),
                )),
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
                KeyType::Ed25519 => {
                    store.ed25519_keys.remove(&key_id);
                }
                KeyType::X25519 => {
                    store.x25519_keys.remove(&key_id);
                }
                KeyType::P256Signing | KeyType::HpkeP256 => {
                    store.p256_keys.remove(&key_id);
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
        peer_public: &[u8],
    ) -> impl Future<Output = Result<SharedSecret, PlatformError>> + Send {
        let key_id = key.id();
        let peer_public = peer_public.to_vec();
        async move {
            let store = self.store.lock().await;
            let key_type = store.lookup_type(KeyHandle::new(key_id))?;

            match key_type {
                KeyType::X25519 => {}
                KeyType::HpkeP256 => {
                    return crate::traits::p256_dh_agree(store.p256_key(key_id)?, &peer_public);
                }
                KeyType::Ed25519 => return Err(wrong_type(key_type, KeyType::X25519)),
                KeyType::P256Signing => return Err(wrong_type(key_type, KeyType::HpkeP256)),
            }
            let peer = crate::traits::x25519_peer(&peer_public)?;

            let secret = store
                .x25519_keys
                .get(&key_id)
                .ok_or(PlatformError::KeyNotFound)?;

            let peer_key = X25519PublicKey::from(peer);
            let shared = secret.diffie_hellman(&peer_key);
            drop(store);
            let shared_bytes = Zeroizing::new(shared.to_bytes());
            Ok(SharedSecret::new(*shared_bytes))
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

            if key_type != KeyType::Ed25519 {
                return Err(wrong_type(key_type, KeyType::Ed25519));
            }

            let signing_key = store
                .ed25519_keys
                .get(&key_id)
                .ok_or(PlatformError::KeyNotFound)?;

            // Software custody (§9.10.4.A): the ikm is the identity private
            // seed, never the public key. Until S12 the identity key is
            // Ed25519, so its 32-byte seed is the ikm.
            let ikm = Zeroizing::new(signing_key.to_bytes());
            let pseudonym_key = derive_pseudonym_keypair(&ikm, &context_id, None)
                .map_err(|e| PlatformError::CustodyError(format!("pseudonym derivation: {e}")))?;
            let public_key = pseudonym_key.public_key().to_compressed();

            let handle = self.next_handle();
            store.p256_keys.insert(handle.id(), pseudonym_key);
            store.key_types.insert(handle.id(), KeyType::P256Signing);
            drop(store);

            PseudonymKeypair::new(&public_key, handle)
        }
    }

    fn derive_rotatable_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
        pseudonym_epoch: u64,
    ) -> impl Future<Output = Result<PseudonymKeypair, PlatformError>> + Send {
        let key_id = key.id();
        let context_id = context_id.to_vec();
        async move {
            let mut store = self.store.lock().await;
            let key_type = store.lookup_type(KeyHandle::new(key_id))?;

            if key_type != KeyType::Ed25519 {
                return Err(wrong_type(key_type, KeyType::Ed25519));
            }

            let signing_key = store
                .ed25519_keys
                .get(&key_id)
                .ok_or(PlatformError::KeyNotFound)?;

            // Software custody (§9.10.4.A): the ikm is the identity private
            // seed, never the public key. Until S12 the identity key is
            // Ed25519, so its 32-byte seed is the ikm.
            let ikm = Zeroizing::new(signing_key.to_bytes());
            let pseudonym_key = derive_pseudonym_keypair(&ikm, &context_id, Some(pseudonym_epoch))
                .map_err(|e| PlatformError::CustodyError(format!("pseudonym derivation: {e}")))?;
            let public_key = pseudonym_key.public_key().to_compressed();

            let handle = self.next_handle();
            store.p256_keys.insert(handle.id(), pseudonym_key);
            store.key_types.insert(handle.id(), KeyType::P256Signing);
            drop(store);

            PseudonymKeypair::new(&public_key, handle)
        }
    }

    fn ed25519_to_x25519_agree(
        &self,
        ed25519_handle: &KeyHandle,
        peer_x25519_public: &[u8; 32],
    ) -> impl Future<Output = Result<SharedSecret, PlatformError>> + Send {
        let key_id = ed25519_handle.id();
        let peer = *peer_x25519_public;
        async move {
            let store = self.store.lock().await;
            let key_type = store.lookup_type(KeyHandle::new(key_id))?;

            if key_type != KeyType::Ed25519 {
                return Err(wrong_type(key_type, KeyType::Ed25519));
            }

            let signing_key = store
                .ed25519_keys
                .get(&key_id)
                .ok_or(PlatformError::KeyNotFound)?;

            // Convert Ed25519 → X25519 via birational conversion and perform DH.
            let result = crate::traits::x25519_agree_from_ed25519(signing_key, &peer);
            drop(store);
            Ok(result)
        }
    }

    fn custody_type(&self, _key: &KeyHandle) -> CustodyType {
        CustodyType::InMemory
    }

    fn import_ed25519_signing_key(
        &self,
        seed: &Zeroizing<[u8; 32]>,
    ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send {
        // Wrap the local copy in `Zeroizing` immediately so the bytes
        // are wiped when this function returns. `[u8; 32]` is `Copy`,
        // so dereferencing the borrow performs a stack copy; capturing
        // it directly into a `Zeroizing` ensures the wrapper owns the
        // only stack residue (the original `seed` is owned by the
        // caller and stays in their `Zeroizing`).
        let seed_copy: Zeroizing<[u8; 32]> = Zeroizing::new(**seed);
        async move {
            let handle = self.next_handle();
            let signing_key = SigningKey::from_bytes(&seed_copy);

            let mut store = self.store.lock().await;
            store.ed25519_keys.insert(handle.id(), signing_key);
            store.key_types.insert(handle.id(), KeyType::Ed25519);
            drop(store);

            // `seed_copy: Zeroizing<[u8; 32]>` drops here → bytes wiped.
            Ok(handle)
        }
    }

    fn generate_ephemeral_ed25519_seed(
        &self,
    ) -> impl Future<Output = Result<Zeroizing<[u8; 32]>, PlatformError>> + Send {
        async move {
            // Draw 32 bytes from the SAME RNG used by `generate_keypair`. This
            // preserves the ADR-046 byte-parity invariant: the seeded
            // bridge-parity tests expect `seed[0..32]` → identity_key,
            // `seed[32..64]` → active_signing_key, `seed[64..96]` →
            // pre-rotation key. Calling this method between identity and
            // active generations would break parity; the dht::create flow
            // is responsible for the correct ordering.
            let mut seed = Zeroizing::new([0u8; 32]);
            self.rng.lock().await.fill_bytes(seed.as_mut());
            Ok(seed)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    /// Converts a `u64` into a 32-byte seed (low 8 bytes little-endian,
    /// remaining 24 bytes zero) for determinism tests that only need a
    /// small-integer handle. Callers that actually want full 32-byte
    /// entropy should pass a `[u8; 32]` to `from_seed_bytes` directly.
    #[must_use]
    fn seed_from_u64(v: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..8].copy_from_slice(&v.to_le_bytes());
        out
    }

    use super::*;
    use hmac::{Hmac, Mac};
    use scp_crypto::p256::{P256PublicKey, verify_prehash_strict};
    use scp_crypto::pseudonym::{PSEUDONYM_SCALAR_LABEL, derive_pseudonym_secret};
    use sha2::Sha256;

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
        let custody = InMemoryKeyCustody::from_seed_bytes(seed_from_u64(42));
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let context_id = b"test-context";

        let first = custody.derive_pseudonym(&handle, context_id).await.unwrap();
        let second = custody.derive_pseudonym(&handle, context_id).await.unwrap();

        // Same identity key + same context_id = same pseudonym public key.
        assert_eq!(
            first.public_key().as_bytes(),
            second.public_key().as_bytes()
        );
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
        assert_ne!(
            first.public_key().as_bytes(),
            second.public_key().as_bytes()
        );
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
    async fn from_seed_bytes_is_deterministic_across_instances() {
        // Two custodies created with the same 32-byte seed must produce
        // byte-identical Ed25519 key sequences. This is the invariant the
        // cross-bridge parity harness relies on (ADR-046).
        let seed = [0xA5u8; 32];
        let c1 = InMemoryKeyCustody::from_seed_bytes(seed);
        let c2 = InMemoryKeyCustody::from_seed_bytes(seed);

        for _ in 0..3 {
            let h1 = c1.generate_keypair(KeyType::Ed25519).await.unwrap();
            let h2 = c2.generate_keypair(KeyType::Ed25519).await.unwrap();
            let p1 = c1.public_key(&h1).await.unwrap();
            let p2 = c2.public_key(&h2).await.unwrap();
            assert_eq!(p1.as_bytes(), p2.as_bytes());
        }
    }

    #[tokio::test]
    async fn from_seed_bytes_different_seeds_diverge() {
        let c1 = InMemoryKeyCustody::from_seed_bytes([0u8; 32]);
        let c2 = InMemoryKeyCustody::from_seed_bytes([1u8; 32]);
        let h1 = c1.generate_keypair(KeyType::Ed25519).await.unwrap();
        let h2 = c2.generate_keypair(KeyType::Ed25519).await.unwrap();
        let p1 = c1.public_key(&h1).await.unwrap();
        let p2 = c2.public_key(&h2).await.unwrap();
        assert_ne!(p1.as_bytes(), p2.as_bytes());
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
        let first = InMemoryKeyCustody::from_seed_bytes(seed_from_u64(12345));
        let second = InMemoryKeyCustody::from_seed_bytes(seed_from_u64(12345));

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
        let custody = InMemoryKeyCustody::new();
        let identity_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let pseudonym = custody
            .derive_pseudonym(&identity_handle, b"context-1")
            .await
            .unwrap();

        // The pseudonym is a 33-byte compressed P-256 point, and the handle's
        // public key is that same point.
        let pk_bytes = pseudonym.public_key().as_bytes();
        assert_eq!(pk_bytes.len(), 33);
        assert_eq!(
            custody
                .public_key(pseudonym.key_handle())
                .await
                .unwrap()
                .as_bytes(),
            pk_bytes
        );
        let pk = P256PublicKey::from_sec1(pk_bytes).unwrap();
        let point: [u8; 33] = pk_bytes.try_into().unwrap();
        assert_eq!(
            pseudonym.routing_id(),
            &scp_crypto::pseudonym::pseudonym_routing_id(&point)
        );

        // It signs a 32-byte digest, low-s, verifiable under §9.5.1.
        let digest = [0x5au8; 32];
        let sig = custody.sign(pseudonym.key_handle(), &digest).await.unwrap();
        verify_prehash_strict(&pk, &digest, sig.as_bytes()).unwrap();

        // Any other length is refused, never hashed or truncated.
        assert!(matches!(
            custody
                .sign(pseudonym.key_handle(), b"pseudonym signed message")
                .await,
            Err(PlatformError::CustodyError(_))
        ));
        // The pseudonym handle is a P256Signing key: Ed25519-only and
        // key-agreement operations on it fail closed with WrongKeyType.
        assert!(matches!(
            custody.derive_pseudonym(pseudonym.key_handle(), b"x").await,
            Err(PlatformError::WrongKeyType {
                expected: KeyType::Ed25519,
                actual: KeyType::P256Signing
            })
        ));
        assert!(matches!(
            custody.dh_agree(pseudonym.key_handle(), &[9u8; 32]).await,
            Err(PlatformError::WrongKeyType {
                expected: KeyType::HpkeP256,
                actual: KeyType::P256Signing
            })
        ));

        custody.destroy_key(pseudonym.key_handle()).await.unwrap();
        assert!(matches!(
            custody.public_key(pseudonym.key_handle()).await,
            Err(PlatformError::KeyNotFound)
        ));
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

    // -----------------------------------------------------------------------
    // derive_rotatable_pseudonym tests — BLACK-001 mitigation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn derive_rotatable_pseudonym_is_deterministic() {
        let custody = InMemoryKeyCustody::from_seed_bytes(seed_from_u64(42));
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let context_id = b"test-context";

        let first = custody
            .derive_rotatable_pseudonym(&handle, context_id, 5)
            .await
            .unwrap();
        let second = custody
            .derive_rotatable_pseudonym(&handle, context_id, 5)
            .await
            .unwrap();

        assert_eq!(
            first.public_key().as_bytes(),
            second.public_key().as_bytes(),
            "same identity + context + epoch = same pseudonym"
        );
    }

    #[tokio::test]
    async fn derive_rotatable_pseudonym_different_epochs_produce_different_keys() {
        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let context_id = b"test-context";

        let epoch0 = custody
            .derive_rotatable_pseudonym(&handle, context_id, 0)
            .await
            .unwrap();
        let epoch1 = custody
            .derive_rotatable_pseudonym(&handle, context_id, 1)
            .await
            .unwrap();

        assert_ne!(
            epoch0.public_key().as_bytes(),
            epoch1.public_key().as_bytes(),
            "different epochs must produce different pseudonyms (BLACK-001)"
        );
    }

    #[tokio::test]
    async fn derive_rotatable_pseudonym_differs_from_v1() {
        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let context_id = b"test-context";

        let v1 = custody.derive_pseudonym(&handle, context_id).await.unwrap();
        let v2_epoch0 = custody
            .derive_rotatable_pseudonym(&handle, context_id, 0)
            .await
            .unwrap();

        assert_ne!(
            v1.public_key().as_bytes(),
            v2_epoch0.public_key().as_bytes(),
            "v2 epoch 0 must differ from v1 (different domain separator)"
        );
    }

    #[tokio::test]
    async fn derive_rotatable_pseudonym_with_x25519_key_fails() {
        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::X25519).await.unwrap();
        let result = custody.derive_rotatable_pseudonym(&handle, b"ctx", 0).await;
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
    async fn derive_rotatable_pseudonym_golden_vector() {
        // Known identity key seed: 0x00...01 (31 zeros, then 0x01).
        let seed_bytes: [u8; 32] = {
            let mut s = [0u8; 32];
            s[31] = 1;
            s
        };
        let context_id = b"test";
        let epoch: u64 = 7;

        // Compute expected pseudonym seed using the v2 reference algorithm:
        // seed = HMAC-SHA256(pseudonym_secret, context_id || epoch_BE || "scp-pseudonym-v2")
        // Native software custody: the ikm is the Ed25519 identity seed (S0).
        let pseudonym_secret = derive_pseudonym_secret(&Zeroizing::new(seed_bytes));
        let mut mac = Hmac::<Sha256>::new_from_slice(pseudonym_secret.as_slice()).unwrap();
        mac.update(context_id);
        mac.update(&epoch.to_be_bytes());
        mac.update(b"scp-pseudonym-v2");
        let expected_seed: [u8; 32] = mac.finalize().into_bytes().into();

        let expected_pubkey = P256SigningKey::from_seed(PSEUDONYM_SCALAR_LABEL, &expected_seed)
            .unwrap()
            .public_key()
            .to_compressed();

        let custody = InMemoryKeyCustody::new();
        let handle = custody.import_ed25519_key(&seed_bytes).await;

        let pseudo = custody
            .derive_rotatable_pseudonym(&handle, context_id, epoch)
            .await
            .unwrap();

        assert_eq!(
            pseudo.public_key().as_bytes(),
            expected_pubkey.as_slice(),
            "v2 pseudonym must match reference HMAC-SHA256 algorithm output"
        );
    }

    /// Cross-platform golden-value test for pseudonym derivation.
    ///
    /// Verifies that `derive_pseudonym` is deterministic and that different
    /// context IDs produce different pseudonyms. The `expected_seed` value is
    /// computed from the reference HMAC-SHA256 algorithm using an HKDF-derived
    /// pseudonym secret from the private key (§9.10.4.A). This golden vector is
    /// authoritative for cross-language (Swift, Kotlin, TypeScript) verification.
    #[tokio::test]
    async fn derive_pseudonym_cross_platform_golden_vector() {
        // Known identity key seed: 0x00...01 (31 zeros, then 0x01).
        // This is a deterministic test key; never use in production.
        let seed_bytes: [u8; 32] = {
            let mut s = [0u8; 32];
            s[31] = 1;
            s
        };
        let context_id = b"test";

        // Compute expected pseudonym seed using the reference algorithm directly:
        // seed = HMAC-SHA256(pseudonym_secret, context_id || "scp-pseudonym")
        // §9.10.4.A: HMAC key is a secret derived from the private key via HKDF,
        // NOT the public key, to prevent membership enumeration attacks.
        // Native software custody: the ikm is the Ed25519 identity seed (S0).
        let pseudonym_secret = derive_pseudonym_secret(&Zeroizing::new(seed_bytes));
        let mut mac = Hmac::<Sha256>::new_from_slice(pseudonym_secret.as_slice()).unwrap();
        mac.update(context_id);
        mac.update(b"scp-pseudonym");
        let expected_seed: [u8; 32] = mac.finalize().into_bytes().into();

        // Import the known seed as an Ed25519 signing key so derivation is
        // deterministic regardless of the RNG state.
        let custody = InMemoryKeyCustody::new();
        let handle = custody.import_ed25519_key(&seed_bytes).await;

        // Verify determinism across two calls with same inputs.
        let pseudo1 = custody.derive_pseudonym(&handle, context_id).await.unwrap();
        let pseudo2 = custody.derive_pseudonym(&handle, context_id).await.unwrap();
        assert_eq!(
            pseudo1.public_key().as_bytes(),
            pseudo2.public_key().as_bytes(),
            "pseudonym derivation must be deterministic for identical inputs"
        );

        let pseudo_other = custody
            .derive_pseudonym(&handle, b"other_context")
            .await
            .unwrap();
        assert_ne!(
            pseudo1.public_key().as_bytes(),
            pseudo_other.public_key().as_bytes(),
            "different context_id must produce different pseudonym"
        );

        // Assert that the implementation matches the reference algorithm.
        // expected_seed is HMAC-SHA256(pseudonym_secret, context_id || "scp-pseudonym"),
        // so the expected public key is the P-256 key from that seed by the
        // FIPS 186-5 A.2.1 step under "SCP-PSEUDONYM-P256-V1" (§9.10.4).
        let expected_pubkey = P256SigningKey::from_seed(PSEUDONYM_SCALAR_LABEL, &expected_seed)
            .unwrap()
            .public_key()
            .to_compressed();
        assert_eq!(
            pseudo1.public_key().as_bytes(),
            expected_pubkey.as_slice(),
            "pseudonym public key must match reference HMAC-SHA256 algorithm output"
        );
    }

    /// ADR-046: every `generate_keypair` consumes exactly 32 RNG bytes,
    /// whatever the key type, so P-256 keys take `seed_stream[32k..32k+32]`
    /// as their scalar and never shift the handles generated after them.
    #[tokio::test]
    async fn p256_generation_consumes_exactly_32_rng_bytes() {
        let seed = [7u8; 32];
        let mut stream = rand::rngs::StdRng::from_seed(seed);
        let mut draws = [[0u8; 32]; 4];
        for draw in &mut draws {
            stream.fill_bytes(draw);
        }

        let custody = InMemoryKeyCustody::from_seed_bytes(seed);
        let p256 = custody
            .generate_keypair(KeyType::P256Signing)
            .await
            .unwrap();
        let ed = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let hpke = custody.generate_keypair(KeyType::HpkeP256).await.unwrap();
        let x = custody.generate_keypair(KeyType::X25519).await.unwrap();

        let expect_p256 = P256SigningKey::from_scalar_bytes(&draws[0]).unwrap();
        assert_eq!(
            custody.public_key(&p256).await.unwrap().as_bytes(),
            expect_p256.public_key().to_compressed().as_slice()
        );
        assert_eq!(
            custody.public_key(&ed).await.unwrap().as_bytes(),
            SigningKey::from_bytes(&draws[1]).verifying_key().as_bytes()
        );
        let expect_hpke = P256SigningKey::from_scalar_bytes(&draws[2]).unwrap();
        assert_eq!(
            custody.public_key(&hpke).await.unwrap().as_bytes(),
            expect_hpke.public_key().to_uncompressed().as_slice()
        );
        assert_eq!(
            custody.public_key(&x).await.unwrap().as_bytes(),
            X25519PublicKey::from(&StaticSecret::from(draws[3])).as_bytes()
        );
    }

    /// A9: a pinned key and digest whose raw RFC 6979 signature has a high
    /// `s`. The custody must return the low-s form, which differs from the
    /// raw signature and verifies strictly.
    #[tokio::test]
    async fn p256_sign_normalises_a_pinned_high_s_signature() {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let seed = [7u8; 32];
        let mut scalar = [0u8; 32];
        rand::rngs::StdRng::from_seed(seed).fill_bytes(&mut scalar);
        let raw_signer = p256::ecdsa::SigningKey::from_slice(&scalar).unwrap();

        let digest = [HIGH_S_DIGEST_BYTE; 32];
        let raw: p256::ecdsa::Signature = raw_signer.sign_prehash(&digest).unwrap();
        assert!(
            raw.normalize_s().is_some(),
            "the pinned digest's raw RFC 6979 s must be high"
        );

        let custody = InMemoryKeyCustody::from_seed_bytes(seed);
        let handle = custody
            .generate_keypair(KeyType::P256Signing)
            .await
            .unwrap();
        let pk = P256PublicKey::from_sec1(custody.public_key(&handle).await.unwrap().as_bytes())
            .unwrap();
        let sig = custody.sign(&handle, &digest).await.unwrap();
        assert_ne!(sig.as_bytes(), raw.to_bytes().as_slice());
        assert_eq!(
            sig.as_bytes(),
            raw.normalize_s().unwrap().to_bytes().as_slice()
        );
        verify_prehash_strict(&pk, &digest, sig.as_bytes()).unwrap();
    }

    /// First byte `b` such that the digest `[b; 32]` gives a high raw `s`
    /// under the key `StdRng::from_seed([7; 32])` draws first.
    const HIGH_S_DIGEST_BYTE: u8 = 0;

    #[tokio::test]
    async fn p256_signing_key_signs_digests_only() {
        let custody = InMemoryKeyCustody::new();
        let handle = custody
            .generate_keypair(KeyType::P256Signing)
            .await
            .unwrap();
        let pk_bytes = custody.public_key(&handle).await.unwrap();
        assert_eq!(pk_bytes.as_bytes().len(), 33);
        let pk = P256PublicKey::from_sec1(pk_bytes.as_bytes()).unwrap();

        // 64 distinct digests: RFC 6979 yields a high raw s for about half,
        // so every one verifying strictly shows the low-s normalisation.
        for i in 0..64u8 {
            let digest = [i; 32];
            let sig = custody.sign(&handle, &digest).await.unwrap();
            verify_prehash_strict(&pk, &digest, sig.as_bytes()).unwrap();
        }

        assert!(matches!(
            custody.sign(&handle, &[0u8; 33]).await,
            Err(PlatformError::CustodyError(_))
        ));
        assert!(matches!(
            custody.ed25519_to_x25519_agree(&handle, &[1u8; 32]).await,
            Err(PlatformError::WrongKeyType {
                expected: KeyType::Ed25519,
                actual: KeyType::P256Signing
            })
        ));
    }

    #[tokio::test]
    async fn hpke_p256_dh_agree_matches_ecdh_and_rejects_bad_peers() {
        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::HpkeP256).await.unwrap();
        let pk_bytes = custody.public_key(&handle).await.unwrap();
        assert_eq!(pk_bytes.as_bytes().len(), 65);
        let own_pk = P256PublicKey::from_sec1(pk_bytes.as_bytes()).unwrap();

        let peer = P256SigningKey::from_scalar_bytes(&[3u8; 32]).unwrap();
        let expected = scp_crypto::p256::ecdh_p256(&peer, &own_pk);
        let shared = custody
            .dh_agree(&handle, &peer.public_key().to_uncompressed())
            .await
            .unwrap();
        assert_eq!(shared.as_bytes(), &*expected);

        // A compressed point (RFC 9180 §7.1.1 takes only the uncompressed
        // form), an off-curve 65-byte point, a 32-byte X25519-style key, and
        // the empty slice are all refused.
        let compressed = peer.public_key().to_compressed();
        let mut off_curve = peer.public_key().to_uncompressed();
        off_curve[64] ^= 1;
        for bad in [&compressed[..], off_curve.as_slice(), &[9u8; 32], &[]] {
            assert!(matches!(
                custody.dh_agree(&handle, bad).await,
                Err(PlatformError::CustodyError(_))
            ));
        }

        assert!(matches!(
            custody.sign(&handle, &[0u8; 32]).await,
            Err(PlatformError::WrongKeyType {
                expected: KeyType::P256Signing,
                actual: KeyType::HpkeP256
            })
        ));
    }

    #[tokio::test]
    async fn x25519_dh_agree_rejects_wrong_peer_length() {
        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::X25519).await.unwrap();
        for bad in [&[1u8; 31][..], &[1u8; 33][..], &[][..]] {
            assert!(matches!(
                custody.dh_agree(&handle, bad).await,
                Err(PlatformError::CustodyError(_))
            ));
        }
    }
}
