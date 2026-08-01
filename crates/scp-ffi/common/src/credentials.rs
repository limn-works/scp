//! Bridge credential-store selection seam shared by all three FFI bridges.
//!
//! `BridgeCredentialStore` uses RPITIT (return-position `impl Trait`), so it is
//! **not** dyn-compatible — a bridge cannot hold an
//! `Arc<dyn BridgeCredentialStore>`. Following the same enum-dispatch shape the
//! codebase already uses for the other non-object-safe provider capabilities
//! (`StorageProvider`, `ProtocolRepository`), [`FfiCredentialStore`] is a
//! concrete enum that itself implements `BridgeCredentialStore`, dispatching per
//! arm:
//!
//! - [`FfiCredentialStore::Durable`] — the **real** production backend
//!   ([`ProtocolRepositoryCredentialStore`], erased as
//!   `Arc<dyn DurableCredentialBackend>`), persisting bridge tokens through the
//!   same `EncryptedStorage` backend the bridge already selected for
//!   `mls_storage` and the saga journal.
//! - `FfiCredentialStore::InMemory` — a **test-harness-only** double
//!   (`#[cfg(feature = "testing")]`), gated so it is provably absent from every
//!   shipped artifact (ADR-062 §Decision 5 / §Decision 6 G1, SCP-CAPINJECT-009).
//!
//! There is deliberately **no `Default`** and no zero-argument constructor: a
//! bridge MUST select the arm explicitly at its construction boundary
//! (SCP-CAPSEL-8000). The deleted `impl Default for InMemoryCredentialStore` was
//! the live SCP-CAPSEL-8000/8011 violation this seam replaces.
//!
//! Credentials are classified **durability-only** (spec §17.17.2): RAM-only
//! tokens are re-obtainable by re-auth, so the security-relevant fix is the
//! selection boundary, not the persistence itself. Durability nonetheless
//! tracks the storage selection by construction — a Sqlite selection persists
//! tokens across restart; an encrypted-in-memory selection keeps them encrypted
//! at rest.

use std::sync::Arc;

use scp_core::bridge::credentials::{
    BridgeCredential, BridgeCredentialStore, CredentialError, CredentialType,
    DurableCredentialBackend, ProtocolRepositoryCredentialStore,
};
use scp_platform::EncryptedStorage;
use zeroize::Zeroizing;

/// The bridge credential-store selection seam. See the module docs.
///
/// `Clone` is cheap — every arm is an `Arc`.
#[derive(Clone)]
pub enum FfiCredentialStore {
    /// The real durable backend, selected at the bridge construction boundary
    /// from the same storage handle used for `mls_storage` / the saga journal.
    Durable(Arc<dyn DurableCredentialBackend>),

    /// Test-harness-only in-memory double. Gated behind `testing` so it is
    /// provably absent from shipped artifacts (ADR-062 §Decision 6 G1).
    #[cfg(feature = "testing")]
    InMemory(Arc<scp_core::bridge::credentials::InMemoryCredentialStore>),
}

impl std::fmt::Debug for FfiCredentialStore {
    /// Redacted `Debug` — never surfaces credential state, only the selected
    /// arm.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Durable(_) => f.write_str("FfiCredentialStore::Durable"),
            #[cfg(feature = "testing")]
            Self::InMemory(_) => f.write_str("FfiCredentialStore::InMemory"),
        }
    }
}

impl FfiCredentialStore {
    /// Selects the **real durable backend** over the given `EncryptedStorage`
    /// handle.
    ///
    /// The handle is the SAME `Arc<S>` the bridge already threads into
    /// [`DurableProviders::from_handle`](scp_core::context::supervisor::DurableProviders::from_handle),
    /// so credentials share the one chosen backend by construction (spec §17.6):
    /// a Sqlite handle persists tokens across restart; an
    /// `EncryptingAdapter<InMemoryStorage>` handle keeps them encrypted at rest.
    #[must_use]
    pub fn durable_from_handle<S>(handle: Arc<S>) -> Self
    where
        S: EncryptedStorage + 'static,
    {
        let backend: Arc<dyn DurableCredentialBackend> =
            Arc::new(ProtocolRepositoryCredentialStore::new(handle));
        Self::Durable(backend)
    }

    /// Selects the **test-harness-only** in-memory double.
    ///
    /// Gated behind `testing`; never reachable from a shipped artifact
    /// (ADR-062 §Decision 6 G1).
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn in_memory() -> Self {
        Self::InMemory(Arc::new(
            scp_core::bridge::credentials::InMemoryCredentialStore::new(),
        ))
    }
}

impl BridgeCredentialStore for FfiCredentialStore {
    async fn provision(
        &self,
        bridge_id: &str,
        credential_type: CredentialType,
        plaintext: &[u8],
        bridge_credential_key: &[u8; 32],
    ) -> Result<BridgeCredential, CredentialError> {
        match self {
            Self::Durable(backend) => {
                backend
                    .provision(bridge_id, credential_type, plaintext, bridge_credential_key)
                    .await
            }
            #[cfg(feature = "testing")]
            Self::InMemory(store) => {
                store
                    .provision(bridge_id, credential_type, plaintext, bridge_credential_key)
                    .await
            }
        }
    }

    async fn retrieve(
        &self,
        bridge_id: &str,
        credential_type: &CredentialType,
        bridge_credential_key: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, CredentialError> {
        match self {
            Self::Durable(backend) => {
                backend
                    .retrieve(bridge_id, credential_type, bridge_credential_key)
                    .await
            }
            #[cfg(feature = "testing")]
            Self::InMemory(store) => {
                store
                    .retrieve(bridge_id, credential_type, bridge_credential_key)
                    .await
            }
        }
    }

    async fn rotate(
        &self,
        bridge_id: &str,
        credential_type: &CredentialType,
        new_plaintext: &[u8],
        bridge_credential_key: &[u8; 32],
    ) -> Result<BridgeCredential, CredentialError> {
        match self {
            Self::Durable(backend) => {
                backend
                    .rotate(
                        bridge_id,
                        credential_type,
                        new_plaintext,
                        bridge_credential_key,
                    )
                    .await
            }
            #[cfg(feature = "testing")]
            Self::InMemory(store) => {
                store
                    .rotate(
                        bridge_id,
                        credential_type,
                        new_plaintext,
                        bridge_credential_key,
                    )
                    .await
            }
        }
    }

    async fn revoke(&self, bridge_id: &str) -> Result<(), CredentialError> {
        match self {
            Self::Durable(backend) => backend.revoke(bridge_id).await,
            #[cfg(feature = "testing")]
            Self::InMemory(store) => store.revoke(bridge_id).await,
        }
    }

    async fn list(&self, bridge_id: &str) -> Result<Vec<CredentialType>, CredentialError> {
        match self {
            Self::Durable(backend) => backend.list(bridge_id).await,
            #[cfg(feature = "testing")]
            Self::InMemory(store) => store.list(bridge_id).await,
        }
    }

    async fn store_bridge_credential_key(
        &self,
        bridge_id: &str,
        key: Zeroizing<[u8; 32]>,
    ) -> Result<(), CredentialError> {
        match self {
            Self::Durable(backend) => backend.store_bridge_credential_key(bridge_id, key).await,
            #[cfg(feature = "testing")]
            Self::InMemory(store) => store.store_bridge_credential_key(bridge_id, key).await,
        }
    }

    async fn get_bridge_credential_key(
        &self,
        bridge_id: &str,
    ) -> Result<Zeroizing<[u8; 32]>, CredentialError> {
        match self {
            Self::Durable(backend) => backend.get_bridge_credential_key(bridge_id).await,
            #[cfg(feature = "testing")]
            Self::InMemory(store) => store.get_bridge_credential_key(bridge_id).await,
        }
    }

    async fn delete_bridge_credential_key(&self, bridge_id: &str) -> Result<(), CredentialError> {
        match self {
            Self::Durable(backend) => backend.delete_bridge_credential_key(bridge_id).await,
            #[cfg(feature = "testing")]
            Self::InMemory(store) => store.delete_bridge_credential_key(bridge_id).await,
        }
    }
}

#[cfg(all(test, feature = "testing"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The in-memory harness arm dispatches through the enum end-to-end.
    #[tokio::test]
    async fn in_memory_arm_provision_retrieve_roundtrip() {
        let store = FfiCredentialStore::in_memory();
        let key = *scp_core::bridge::credentials::generate_bridge_credential_key();

        store
            .provision("bridge-x", CredentialType::ApiKey, b"secret-token", &key)
            .await
            .unwrap();

        let out = store
            .retrieve("bridge-x", &CredentialType::ApiKey, &key)
            .await
            .unwrap();
        assert_eq!(out.as_slice(), b"secret-token");
    }
}
