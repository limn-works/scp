//! Enum dispatch for [`KeyCustody`] in the `PyO3` FFI bridge.
//!
//! The [`KeyCustody`] trait uses RPITIT (return-position `impl Trait` in trait),
//! which makes it NOT object-safe. This module provides [`FfiKeyCustody`], an
//! enum that wraps the concrete custody implementations used by the FFI bridge
//! and manually delegates each trait method to the active variant.
//!
//! # Variants
//!
//! - [`InMemoryKeyCustody`] — Test/development only. Keys exist only in memory
//!   and are lost when the process exits. Available because `scp-ffi` enables
//!   `scp-platform/testing`.
//! - [`FileKeyCustody`] — Encrypted-at-rest key storage using Argon2id +
//!   AES-256-GCM. The default production custody for desktop/server platforms.
//!
//! See issue #323 and ADR-006.

use scp_platform::error::PlatformError;
use scp_platform::file::FileKeyCustody;
#[cfg(feature = "allow_in_memory_custody")]
use scp_platform::testing::InMemoryKeyCustody;
use scp_platform::traits::{
    CustodyType, KeyCustody, KeyHandle, KeyType, PseudonymKeypair, PublicKey, SharedSecret,
    Signature,
};

/// Enum dispatch wrapper for [`KeyCustody`] implementations used by the
/// `PyO3` FFI bridge.
///
/// Since [`KeyCustody`] uses RPITIT and is not object-safe, we cannot use
/// `Arc<dyn KeyCustody>`. Instead, this enum wraps the concrete types and
/// delegates each method to the active variant.
pub enum FfiKeyCustody {
    /// Test/development in-memory custody. Keys are lost on process exit.
    /// Available because `scp-ffi` enables `scp-platform/testing`.
    #[cfg(feature = "allow_in_memory_custody")]
    InMemory(InMemoryKeyCustody),
    /// Encrypted file-backed custody (Argon2id + AES-256-GCM).
    /// Production default for desktop/server platforms.
    File(FileKeyCustody),
}

impl KeyCustody for FfiKeyCustody {
    async fn generate_keypair(&self, key_type: KeyType) -> Result<KeyHandle, PlatformError> {
        match self {
            #[cfg(feature = "allow_in_memory_custody")]
            Self::InMemory(kc) => kc.generate_keypair(key_type).await,
            Self::File(kc) => kc.generate_keypair(key_type).await,
        }
    }

    async fn sign(&self, key: &KeyHandle, data: &[u8]) -> Result<Signature, PlatformError> {
        match self {
            #[cfg(feature = "allow_in_memory_custody")]
            Self::InMemory(kc) => kc.sign(key, data).await,
            Self::File(kc) => kc.sign(key, data).await,
        }
    }

    async fn public_key(&self, key: &KeyHandle) -> Result<PublicKey, PlatformError> {
        match self {
            #[cfg(feature = "allow_in_memory_custody")]
            Self::InMemory(kc) => kc.public_key(key).await,
            Self::File(kc) => kc.public_key(key).await,
        }
    }

    async fn destroy_key(&self, key: &KeyHandle) -> Result<(), PlatformError> {
        match self {
            #[cfg(feature = "allow_in_memory_custody")]
            Self::InMemory(kc) => kc.destroy_key(key).await,
            Self::File(kc) => kc.destroy_key(key).await,
        }
    }

    async fn dh_agree(
        &self,
        key: &KeyHandle,
        peer_public: &[u8; 32],
    ) -> Result<SharedSecret, PlatformError> {
        match self {
            #[cfg(feature = "allow_in_memory_custody")]
            Self::InMemory(kc) => kc.dh_agree(key, peer_public).await,
            Self::File(kc) => kc.dh_agree(key, peer_public).await,
        }
    }

    async fn derive_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
    ) -> Result<PseudonymKeypair, PlatformError> {
        match self {
            #[cfg(feature = "allow_in_memory_custody")]
            Self::InMemory(kc) => kc.derive_pseudonym(key, context_id).await,
            Self::File(kc) => kc.derive_pseudonym(key, context_id).await,
        }
    }

    async fn derive_rotatable_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
        pseudonym_epoch: u64,
    ) -> Result<PseudonymKeypair, PlatformError> {
        match self {
            #[cfg(feature = "allow_in_memory_custody")]
            Self::InMemory(kc) => {
                kc.derive_rotatable_pseudonym(key, context_id, pseudonym_epoch)
                    .await
            }
            Self::File(kc) => {
                kc.derive_rotatable_pseudonym(key, context_id, pseudonym_epoch)
                    .await
            }
        }
    }

    fn custody_type(&self, key: &KeyHandle) -> CustodyType {
        match self {
            #[cfg(feature = "allow_in_memory_custody")]
            Self::InMemory(kc) => kc.custody_type(key),
            Self::File(kc) => kc.custody_type(key),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ffi_custody_in_memory_generates_and_signs() {
        let custody = FfiKeyCustody::InMemory(InMemoryKeyCustody::new());
        let handle = custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .expect("generate keypair");
        let sig = custody.sign(&handle, b"test data").await.expect("sign");
        assert_eq!(sig.as_bytes().len(), 64, "Ed25519 signature is 64 bytes");
    }

    #[tokio::test]
    async fn ffi_custody_file_generates_and_signs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test_keys.bin");
        let file_kc = FileKeyCustody::new(&path, "test-passphrase").expect("FileKeyCustody::new");
        let custody = FfiKeyCustody::File(file_kc);
        let handle = custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .expect("generate keypair");
        let sig = custody.sign(&handle, b"test data").await.expect("sign");
        assert_eq!(sig.as_bytes().len(), 64, "Ed25519 signature is 64 bytes");
    }

    #[tokio::test]
    async fn ffi_custody_file_custody_type_is_software() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test_keys_type.bin");
        let file_kc = FileKeyCustody::new(&path, "test-passphrase").expect("FileKeyCustody::new");
        let custody = FfiKeyCustody::File(file_kc);
        let handle = custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .expect("generate keypair");
        assert_eq!(custody.custody_type(&handle), CustodyType::Software);
    }

    #[tokio::test]
    async fn ffi_custody_in_memory_custody_type_is_in_memory() {
        let custody = FfiKeyCustody::InMemory(InMemoryKeyCustody::new());
        let handle = custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .expect("generate keypair");
        assert_eq!(custody.custody_type(&handle), CustodyType::InMemory);
    }

    #[tokio::test]
    async fn ffi_custody_file_dh_agree_succeeds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test_keys_dh.bin");
        let file_kc = FileKeyCustody::new(&path, "passphrase").expect("FileKeyCustody::new");
        let custody = FfiKeyCustody::File(file_kc);

        let handle_a = custody
            .generate_keypair(KeyType::X25519)
            .await
            .expect("generate X25519 keypair A");
        let handle_b = custody
            .generate_keypair(KeyType::X25519)
            .await
            .expect("generate X25519 keypair B");

        let pub_b = custody.public_key(&handle_b).await.expect("public key B");
        let pub_b_bytes: [u8; 32] = pub_b.as_bytes().try_into().expect("32 bytes");

        let shared = custody
            .dh_agree(&handle_a, &pub_b_bytes)
            .await
            .expect("dh_agree");
        assert_eq!(shared.as_bytes().len(), 32, "shared secret is 32 bytes");
    }

    #[tokio::test]
    async fn ffi_custody_file_destroy_key_prevents_sign() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test_keys_destroy.bin");
        let file_kc = FileKeyCustody::new(&path, "passphrase").expect("FileKeyCustody::new");
        let custody = FfiKeyCustody::File(file_kc);

        let handle = custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .expect("generate keypair");
        custody.destroy_key(&handle).await.expect("destroy key");
        let result = custody.sign(&handle, b"test").await;
        assert!(result.is_err(), "signing with destroyed key should fail");
    }
}
