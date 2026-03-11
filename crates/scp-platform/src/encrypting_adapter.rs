//! AES-256-GCM encrypting wrapper for arbitrary [`Storage`] backends.
//!
//! [`EncryptingAdapter`] wraps any `Storage` implementation with per-value
//! AES-256-GCM encryption, making it satisfy the sealed
//! [`EncryptedStorage`](crate::encrypted::EncryptedStorage) bound without
//! requiring the inner backend to encrypt natively.
//!
//! # Wire format
//!
//! Each stored value is `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
//! The storage key string is used as Additional Authenticated Data (AAD),
//! preventing relocation attacks (moving a ciphertext from one key to
//! another).
//!
//! # Usage
//!
//! ```rust,ignore
//! use scp_platform::encrypting_adapter::EncryptingAdapter;
//! use scp_platform::testing::InMemoryStorage;
//! use zeroize::Zeroizing;
//!
//! let key = Zeroizing::new([0x42u8; 32]);
//! let inner = InMemoryStorage::new();
//! let encrypted = EncryptingAdapter::new(inner, key);
//! // `encrypted` implements EncryptedStorage and can be passed to ProtocolStore::new().
//! ```
//!
//! See issue #695.

use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit, Nonce, aead::OsRng};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::encrypted::EncryptedStorage;
use crate::error::PlatformError;
use crate::traits::Storage;

/// Nonce length for AES-256-GCM (96 bits).
const NONCE_LEN: usize = 12;

/// AES-256-GCM tag length (128 bits).
const TAG_LEN: usize = 16;

/// A [`Storage`] wrapper that encrypts values with AES-256-GCM before
/// delegating to the inner backend.
///
/// Key names are passed through unencrypted (they are not secret — the
/// `ProtocolStore` key convention is deterministic). Only values are
/// encrypted.
///
/// Implements [`EncryptedStorage`] so it can be used with
/// `ProtocolStore::new()`.
pub struct EncryptingAdapter<S: Storage> {
    inner: S,
    key: Zeroizing<[u8; 32]>,
}

impl<S: Storage> EncryptingAdapter<S> {
    /// Creates a new encrypting adapter wrapping `inner` with the given
    /// 32-byte AES-256 key.
    ///
    /// The key is stored in a [`Zeroizing`] wrapper and cleared on drop.
    /// Callers should zeroize their copy of the key after passing it here.
    #[must_use]
    pub const fn new(inner: S, key: Zeroizing<[u8; 32]>) -> Self {
        Self { inner, key }
    }

    /// Encrypts `plaintext` with AES-256-GCM using the storage `key_str`
    /// as AAD.
    ///
    /// Returns `nonce || ciphertext || tag`.
    fn seal(&self, plaintext: &[u8], key_str: &str) -> Result<Vec<u8>, PlatformError> {
        let cipher = Aes256Gcm::new(self.key.as_ref().into());
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        // Allocate output: nonce + plaintext (which will be encrypted in-place) + tag
        let mut buffer = Vec::with_capacity(NONCE_LEN + plaintext.len() + TAG_LEN);
        buffer.extend_from_slice(&nonce_bytes);
        buffer.extend_from_slice(plaintext);

        // Encrypt in-place on the plaintext portion (after the nonce prefix).
        let tag = cipher
            .encrypt_in_place_detached(&nonce, key_str.as_bytes(), &mut buffer[NONCE_LEN..])
            .map_err(|e| PlatformError::StorageError(format!("encryption failed: {e}")))?;
        buffer.extend_from_slice(tag.as_slice());

        Ok(buffer)
    }

    /// Decrypts `nonce || ciphertext || tag` using the storage `key_str`
    /// as AAD.
    fn open(&self, data: &[u8], key_str: &str) -> Result<Vec<u8>, PlatformError> {
        if data.len() < NONCE_LEN + TAG_LEN {
            return Err(PlatformError::StorageError(
                "encrypted data too short".to_owned(),
            ));
        }

        let cipher = Aes256Gcm::new(self.key.as_ref().into());
        let nonce = Nonce::from_slice(&data[..NONCE_LEN]);
        let ciphertext_end = data.len() - TAG_LEN;
        let ciphertext = &data[NONCE_LEN..ciphertext_end];
        let tag = &data[ciphertext_end..];

        let mut plaintext = ciphertext.to_vec();
        cipher
            .decrypt_in_place_detached(nonce, key_str.as_bytes(), &mut plaintext, tag.into())
            .map_err(|e| PlatformError::StorageError(format!("decryption failed: {e}")))?;

        Ok(plaintext)
    }
}

// ---------------------------------------------------------------------------
// Sealed + EncryptedStorage impls
// ---------------------------------------------------------------------------

// The `Sealed` trait is in `encrypted::private`, which is `pub(crate)` — we
// can impl it here because we're in the same crate.
impl<S: Storage> crate::encrypted::private::Sealed for EncryptingAdapter<S> {}
impl<S: Storage> EncryptedStorage for EncryptingAdapter<S> {}

// ---------------------------------------------------------------------------
// Storage delegation with encryption
// ---------------------------------------------------------------------------

impl<S: Storage> Storage for EncryptingAdapter<S> {
    async fn store(&self, key: &str, data: &[u8]) -> Result<(), PlatformError> {
        let sealed = self.seal(data, key)?;
        self.inner.store(key, &sealed).await
    }

    async fn retrieve(&self, key: &str) -> Result<Option<Vec<u8>>, PlatformError> {
        match self.inner.retrieve(key).await? {
            Some(ct) => Ok(Some(self.open(&ct, key)?)),
            None => Ok(None),
        }
    }

    fn delete(&self, key: &str) -> impl Future<Output = Result<(), PlatformError>> + Send {
        self.inner.delete(key)
    }

    fn list_keys(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<Vec<String>, PlatformError>> + Send {
        self.inner.list_keys(prefix)
    }

    fn delete_prefix(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<u64, PlatformError>> + Send {
        self.inner.delete_prefix(prefix)
    }

    fn exists(&self, key: &str) -> impl Future<Output = Result<bool, PlatformError>> + Send {
        self.inner.exists(key)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::testing::InMemoryStorage;

    fn make_adapter() -> EncryptingAdapter<InMemoryStorage> {
        let key = Zeroizing::new([0x42u8; 32]);
        EncryptingAdapter::new(InMemoryStorage::new(), key)
    }

    #[tokio::test]
    async fn roundtrip_store_retrieve() {
        let adapter = make_adapter();
        adapter.store("test/key", b"hello world").await.unwrap();
        let loaded = adapter.retrieve("test/key").await.unwrap();
        assert_eq!(loaded.as_deref(), Some(b"hello world".as_slice()));
    }

    #[tokio::test]
    async fn retrieve_missing_returns_none() {
        let adapter = make_adapter();
        let loaded = adapter.retrieve("nonexistent").await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn different_keys_different_ciphertext() {
        let adapter = make_adapter();
        let data = b"same data";
        adapter.store("key/a", data).await.unwrap();
        adapter.store("key/b", data).await.unwrap();

        // Raw ciphertexts should differ (different nonces + different AAD).
        let raw_a = adapter.inner.retrieve("key/a").await.unwrap().unwrap();
        let raw_b = adapter.inner.retrieve("key/b").await.unwrap().unwrap();
        assert_ne!(raw_a, raw_b);
    }

    #[tokio::test]
    async fn tampered_ciphertext_fails() {
        let adapter = make_adapter();
        adapter.store("test/tamper", b"secret").await.unwrap();

        // Tamper with the stored ciphertext.
        let mut raw = adapter
            .inner
            .retrieve("test/tamper")
            .await
            .unwrap()
            .unwrap();
        raw[NONCE_LEN] ^= 0xFF; // flip a byte in the ciphertext
        adapter.inner.store("test/tamper", &raw).await.unwrap();

        let result = adapter.retrieve("test/tamper").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn relocation_attack_fails() {
        let adapter = make_adapter();
        adapter.store("key/original", b"value").await.unwrap();

        // Copy the ciphertext to a different key (different AAD).
        let raw = adapter
            .inner
            .retrieve("key/original")
            .await
            .unwrap()
            .unwrap();
        adapter.inner.store("key/relocated", &raw).await.unwrap();

        // Decryption under the wrong key should fail (AAD mismatch).
        let result = adapter.retrieve("key/relocated").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn delete_removes_key() {
        let adapter = make_adapter();
        adapter.store("test/del", b"data").await.unwrap();
        adapter.delete("test/del").await.unwrap();
        let loaded = adapter.retrieve("test/del").await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn list_keys_passthrough() {
        let adapter = make_adapter();
        adapter.store("prefix/a", b"1").await.unwrap();
        adapter.store("prefix/b", b"2").await.unwrap();
        adapter.store("other/c", b"3").await.unwrap();

        let keys = adapter.list_keys("prefix/").await.unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"prefix/a".to_owned()));
        assert!(keys.contains(&"prefix/b".to_owned()));
    }

    #[tokio::test]
    async fn exists_passthrough() {
        let adapter = make_adapter();
        adapter.store("test/exists", b"x").await.unwrap();
        assert!(adapter.exists("test/exists").await.unwrap());
        assert!(!adapter.exists("test/nope").await.unwrap());
    }

    #[tokio::test]
    async fn delete_prefix_passthrough() {
        let adapter = make_adapter();
        adapter.store("pfx/a", b"1").await.unwrap();
        adapter.store("pfx/b", b"2").await.unwrap();
        adapter.store("other/c", b"3").await.unwrap();

        let deleted = adapter.delete_prefix("pfx/").await.unwrap();
        assert_eq!(deleted, 2);
        assert!(adapter.retrieve("pfx/a").await.unwrap().is_none());
        assert!(adapter.retrieve("pfx/b").await.unwrap().is_none());
        assert!(adapter.retrieve("other/c").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn empty_value_roundtrip() {
        let adapter = make_adapter();
        adapter.store("test/empty", b"").await.unwrap();
        let loaded = adapter.retrieve("test/empty").await.unwrap();
        assert_eq!(loaded.as_deref(), Some(b"".as_slice()));
    }

    #[tokio::test]
    async fn short_ciphertext_rejected() {
        // Manually store a too-short value to test the length check.
        let adapter = make_adapter();
        adapter.inner.store("test/short", &[0u8; 10]).await.unwrap();
        let result = adapter.retrieve("test/short").await;
        assert!(result.is_err());
    }
}
