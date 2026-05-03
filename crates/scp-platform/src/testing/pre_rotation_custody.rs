//! In-memory [`PreRotationCustody`] for testing.
//!
//! Stores pre-rotation keypairs in a `HashMap` keyed by an opaque
//! [`PreRotationKeyHandle`]. Distinct from [`InMemoryKeyCustody`]: there is
//! NO shared state, NO shared lock, NO shared handle namespace. This
//! satisfies spec §9.7.4.1 §3 ("storage isolation") at the type level —
//! callers cannot pass an operational [`KeyHandle`] to this custody.
//!
//! **Not suitable for production.** This implementation co-resides in
//! process memory with operational keys; the §9.7.4.1 §3 substrate-isolation
//! requirement is not satisfied. Tests only.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::Mutex;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::traits::{
    PreRotationCustody, PreRotationCustodyError, PreRotationCustodyKind, PreRotationKeyHandle,
};

/// In-memory [`PreRotationCustody`] for tests.
///
/// Stores `(public_key, private_key)` per handle. Handles are allocated
/// from an internal `AtomicU64`; they do not collide with operational
/// [`KeyHandle`] IDs because the type system prevents conversion in either
/// direction.
#[derive(Debug, Default)]
pub struct InMemoryPreRotationCustody {
    store: Mutex<HashMap<u64, PreRotationKeyEntry>>,
    next_id: AtomicU64,
}

/// Defense in depth: derive `Zeroize` + `ZeroizeOnDrop` so the
/// `private_key` field is wiped if the entry is moved/dropped via any
/// path the `Zeroizing` wrapper alone wouldn't catch (e.g., enum
/// repacking, struct-level drop). The `public_key` is non-secret but
/// included for the derive's structural correctness.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
struct PreRotationKeyEntry {
    public_key: [u8; 32],
    private_key: Zeroizing<[u8; 32]>,
}

impl InMemoryPreRotationCustody {
    /// Creates a fresh, empty in-memory pre-rotation custody.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of stored pre-rotation keys (testing helper).
    #[cfg(test)]
    pub async fn len(&self) -> usize {
        self.store.lock().await.len()
    }

    /// Returns whether the store has no pre-rotation keys (testing helper).
    #[cfg(test)]
    pub async fn is_empty(&self) -> bool {
        self.store.lock().await.is_empty()
    }
}

#[allow(clippy::manual_async_fn)]
impl PreRotationCustody for InMemoryPreRotationCustody {
    fn store_committed_pre_rotation_key(
        &self,
        public_key: &[u8; 32],
        private_key: Zeroizing<[u8; 32]>,
    ) -> impl std::future::Future<Output = Result<PreRotationKeyHandle, PreRotationCustodyError>> + Send
    {
        let public_key = *public_key;
        async move {
            let id = self.next_id.fetch_add(1, Ordering::SeqCst);
            self.store.lock().await.insert(
                id,
                PreRotationKeyEntry {
                    public_key,
                    private_key,
                },
            );
            Ok(PreRotationKeyHandle::new(id))
        }
    }

    fn reveal_public_key(
        &self,
        handle: &PreRotationKeyHandle,
    ) -> impl std::future::Future<Output = Result<[u8; 32], PreRotationCustodyError>> + Send {
        let id = handle.id();
        async move {
            self.store
                .lock()
                .await
                .get(&id)
                .map(|entry| entry.public_key)
                .ok_or(PreRotationCustodyError::HandleNotFound)
        }
    }

    fn destroy_after_migration(
        &self,
        handle: PreRotationKeyHandle,
    ) -> impl std::future::Future<Output = Result<Zeroizing<[u8; 32]>, PreRotationCustodyError>> + Send
    {
        let id = handle.id();
        async move {
            // `PreRotationKeyEntry` derives `ZeroizeOnDrop`, so partial
            // moves out of fields are forbidden. Copy the private key
            // bytes into a fresh `Zeroizing` and let the entry's
            // `Drop` zeroize the source on the next line.
            self.store
                .lock()
                .await
                .remove(&id)
                .map(|entry| {
                    let bytes: [u8; 32] = *entry.private_key;
                    Zeroizing::new(bytes)
                    // `entry` drops here → ZeroizeOnDrop wipes both
                    // public_key and private_key fields.
                })
                .ok_or(PreRotationCustodyError::HandleNotFound)
        }
    }

    fn custody_kind(&self) -> PreRotationCustodyKind {
        PreRotationCustodyKind::InMemory
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn store_reveal_destroy_round_trip() {
        let custody = InMemoryPreRotationCustody::new();
        let public = [0xAAu8; 32];
        let private = Zeroizing::new([0xBBu8; 32]);

        let handle = custody
            .store_committed_pre_rotation_key(&public, private)
            .await
            .unwrap();

        let revealed = custody.reveal_public_key(&handle).await.unwrap();
        assert_eq!(revealed, public);

        let destroyed = custody.destroy_after_migration(handle).await.unwrap();
        assert_eq!(*destroyed, [0xBBu8; 32]);

        // After destroy, the handle MUST not resolve.
        let err = custody
            .reveal_public_key(&handle)
            .await
            .expect_err("destroyed handle MUST be unreachable");
        assert!(matches!(err, PreRotationCustodyError::HandleNotFound));
    }

    #[tokio::test]
    async fn distinct_handles_per_store() {
        let custody = InMemoryPreRotationCustody::new();
        let h1 = custody
            .store_committed_pre_rotation_key(&[0u8; 32], Zeroizing::new([1u8; 32]))
            .await
            .unwrap();
        let h2 = custody
            .store_committed_pre_rotation_key(&[2u8; 32], Zeroizing::new([3u8; 32]))
            .await
            .unwrap();
        assert_ne!(h1, h2, "each store call MUST mint a fresh handle");
        assert_eq!(custody.len().await, 2);
    }

    #[tokio::test]
    async fn destroy_returns_handle_not_found_for_unknown_handle() {
        let custody = InMemoryPreRotationCustody::new();
        let err = custody
            .destroy_after_migration(PreRotationKeyHandle::new(999))
            .await
            .expect_err("unknown handle MUST fail");
        assert!(matches!(err, PreRotationCustodyError::HandleNotFound));
    }

    #[tokio::test]
    async fn custody_kind_reports_in_memory() {
        let custody = InMemoryPreRotationCustody::new();
        assert_eq!(custody.custody_kind(), PreRotationCustodyKind::InMemory);
    }
}
