//! In-memory [`NextSetCustody`] for tests (SCP-345).
//!
//! Holds P-256 next-set keys in a `HashMap` keyed by an opaque
//! [`NextSetKeyHandle`], with no state shared with
//! [`InMemoryKeyCustody`](crate::testing::InMemoryKeyCustody) or
//! [`InMemoryPreRotationCustody`](crate::testing::InMemoryPreRotationCustody).
//!
//! **Not suitable for production.** The keys sit in process memory beside the
//! operational keys, so the §9.7.4.1 §3 substrate isolation does not hold. A
//! shipped build compiles no `NextSetCustody` implementor from this crate;
//! SCP-311 owns the production implementors.

// The module declaration in `testing/mod.rs` carries the same gate; this
// file repeats it because scp-testing's `test_double_gating` test parses each
// file alone.
#![cfg(feature = "testing")]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use scp_crypto::p256::P256SecretKey;
use scp_kel::{
    CustodyProbe, IndexedSignature, KeyEventSignError, KeyEventSigner, ProbeSignature,
    SigningChange,
};
use tokio::sync::Mutex;

use crate::traits::{
    BackupArtifact, BackupRequest, NextSetCustody, NextSetCustodyError, NextSetKeyHandle,
    PreRotationCustodyKind, RestoreMaterial, generate_p256_os_rng, sign_key_event_digest,
};

/// In-memory [`NextSetCustody`] for tests: software P-256 keys, raw-arm
/// signatures, [`PreRotationCustodyKind::InMemory`].
#[derive(Default)]
pub struct InMemoryNextSetCustody {
    keys: Mutex<HashMap<u64, P256SecretKey>>,
    next_id: AtomicU64,
}

impl std::fmt::Debug for InMemoryNextSetCustody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryNextSetCustody")
            .field("next_id", &self.next_id)
            .finish_non_exhaustive()
    }
}

impl InMemoryNextSetCustody {
    /// An empty custody.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Signs `digest` with the key under `member`, giving the raw form.
    async fn sign_digest(
        &self,
        member: &NextSetKeyHandle,
        digest: &[u8; 32],
    ) -> Result<[u8; 64], KeyEventSignError> {
        // One statement, so the guard drops as soon as the signature exists.
        let signed = self
            .keys
            .lock()
            .await
            .get(&member.id())
            .map(|key| sign_key_event_digest(key, digest));
        Ok(signed.ok_or(KeyEventSignError::MemberNotFound)??)
    }
}

impl KeyEventSigner for InMemoryNextSetCustody {
    type Member = NextSetKeyHandle;

    /// Signs the change's digest `D` (the raw arm).
    async fn sign_change(
        &self,
        member: &NextSetKeyHandle,
        change: &SigningChange,
    ) -> Result<IndexedSignature, KeyEventSignError> {
        let signature = self.sign_digest(member, &change.digest()).await?;
        Ok(IndexedSignature::Raw { signature })
    }

    /// Signs the probe's raw digest (§9.7.4.1 item 5, step d).
    async fn sign_probe(
        &self,
        member: &NextSetKeyHandle,
        probe: &CustodyProbe,
    ) -> Result<ProbeSignature, KeyEventSignError> {
        let signature = self.sign_digest(member, &probe.raw_digest()).await?;
        Ok(ProbeSignature::raw(signature))
    }
}

impl NextSetCustody for InMemoryNextSetCustody {
    async fn generate(&self) -> Result<NextSetKeyHandle, NextSetCustodyError> {
        let key =
            generate_p256_os_rng().map_err(|e| NextSetCustodyError::Unavailable(e.to_string()))?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.keys.lock().await.insert(id, key);
        Ok(NextSetKeyHandle::new(id))
    }

    async fn reveal_public_key(
        &self,
        handle: &NextSetKeyHandle,
    ) -> Result<[u8; 33], NextSetCustodyError> {
        self.keys
            .lock()
            .await
            .get(&handle.id())
            .map(|key| key.public_key().to_compressed())
            .ok_or(NextSetCustodyError::HandleNotFound)
    }

    async fn destroy(&self, handle: &NextSetKeyHandle) -> Result<(), NextSetCustodyError> {
        self.keys
            .lock()
            .await
            .remove(&handle.id())
            .map(drop)
            .ok_or(NextSetCustodyError::HandleNotFound)
    }

    /// Refused: an in-memory custody is not the headless custody §9.7.4.1
    /// item 4 lets seal a copyable artifact.
    async fn seal_backup(
        &self,
        _handle: &NextSetKeyHandle,
        _request: BackupRequest,
    ) -> Result<BackupArtifact, NextSetCustodyError> {
        Err(NextSetCustodyError::MethodNotOffered)
    }

    /// Refused for the reason [`seal_backup`](Self::seal_backup) is.
    async fn restore(
        &self,
        _material: RestoreMaterial,
        _expected_commitment: [u8; 32],
    ) -> Result<NextSetKeyHandle, NextSetCustodyError> {
        Err(NextSetCustodyError::MethodNotOffered)
    }

    fn custody_kind(&self) -> PreRotationCustodyKind {
        PreRotationCustodyKind::InMemory
    }
}

// `scp_testing::next_set_custody_conformance!` runs the spec 16 §16.12.3a
// suite against this custody (`crates/scp-testing/src/conformance/next_set_custody.rs`).

#[cfg(test)]
mod tests {
    use super::InMemoryNextSetCustody;
    use crate::traits::{NextSetCustody, PreRotationCustodyKind};

    #[test]
    fn declares_the_in_memory_kind() {
        assert_eq!(
            InMemoryNextSetCustody::new().custody_kind(),
            PreRotationCustodyKind::InMemory
        );
    }
}
