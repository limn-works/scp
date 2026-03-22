//! Trust engine storage operations for `ProtocolRepository`.
//!
//! Implements persistent storage for trust engine data: cached attestations,
//! revocation state, and challenge results. These methods back the
//! [`TrustProtocolRepository`]
//! trait via the synchronous [`ProtocolRepositoryTrustBridge`] adapter.
//!
//! # Key convention
//!
//! ```text
//! trust/{context_id}/attestation/{subject_did}/{attestation_id}
//! trust/{context_id}/revocation_state
//! trust/{context_id}/challenge/{subject_did}/{verification_id}
//! ```
//!
//! See spec section 17.3.

use std::collections::HashMap;
use std::sync::Arc;

use scp_platform::traits::Storage;

use super::{ProtocolRepository, StoreError, sanitize_key_component};
use crate::trust::TrustError;
use crate::trust::aggregate::{CachedAttestation, TrustProtocolRepository};
use crate::trust::challenge::ChallengeVerification;

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

/// Builds the storage key for a cached attestation.
///
/// Format: `trust/{context_id}/attestation/{subject_did}/{attestation_id}`
fn attestation_key(
    context_id: &str,
    subject_did: &str,
    attestation_id: &str,
) -> Result<String, StoreError> {
    let ctx = sanitize_key_component(context_id)?;
    let subject = sanitize_key_component(subject_did)?;
    let att = sanitize_key_component(attestation_id)?;
    Ok(format!("trust/{ctx}/attestation/{subject}/{att}"))
}

/// Builds the prefix for listing all cached attestations for a subject DID
/// within a context.
///
/// Format: `trust/{context_id}/attestation/{subject_did}/`
fn attestation_prefix(context_id: &str, subject_did: &str) -> Result<String, StoreError> {
    let ctx = sanitize_key_component(context_id)?;
    let subject = sanitize_key_component(subject_did)?;
    Ok(format!("trust/{ctx}/attestation/{subject}/"))
}

/// Builds the storage key for per-context revocation state.
///
/// Format: `trust/{context_id}/revocation_state`
fn revocation_state_key(context_id: &str) -> Result<String, StoreError> {
    let ctx = sanitize_key_component(context_id)?;
    Ok(format!("trust/{ctx}/revocation_state"))
}

/// Builds the storage key for a challenge verification result.
///
/// Format: `trust/{context_id}/challenge/{subject_did}/{verification_id}`
fn challenge_key(
    context_id: &str,
    subject_did: &str,
    verification_id: &str,
) -> Result<String, StoreError> {
    let ctx = sanitize_key_component(context_id)?;
    let subject = sanitize_key_component(subject_did)?;
    let ver = sanitize_key_component(verification_id)?;
    Ok(format!("trust/{ctx}/challenge/{subject}/{ver}"))
}

/// Builds the prefix for listing all challenge results for a subject DID
/// within a context.
///
/// Format: `trust/{context_id}/challenge/{subject_did}/`
fn challenge_prefix(context_id: &str, subject_did: &str) -> Result<String, StoreError> {
    let ctx = sanitize_key_component(context_id)?;
    let subject = sanitize_key_component(subject_did)?;
    Ok(format!("trust/{ctx}/challenge/{subject}/"))
}

// ---------------------------------------------------------------------------
// ProtocolRepository — trust methods
// ---------------------------------------------------------------------------

impl<S: Storage> ProtocolRepository<S> {
    /// Stores a cached attestation entry.
    ///
    /// The key includes the attestation's subject DID and unique ID, so
    /// storing the same attestation ID again replaces the previous entry
    /// (replace-by-ID semantics).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if key sanitization, serialization, or storage
    /// fails.
    pub async fn store_trust_cached_attestation(
        &self,
        context_id: &str,
        entry: &CachedAttestation,
    ) -> Result<(), StoreError> {
        let key = attestation_key(
            context_id,
            entry.attestation.subject.as_ref(),
            &entry.attestation.id,
        )?;
        self.store_value(&key, entry).await
    }

    /// Loads all cached attestation entries for a subject DID within a context.
    ///
    /// Returns ALL entries regardless of TTL expiry — the caller (bridge layer)
    /// is responsible for filtering expired entries using its own clock.
    ///
    /// Returns an empty `Vec` if no entries exist.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if key sanitization, storage enumeration, or
    /// deserialization fails.
    pub async fn load_trust_cached_attestations(
        &self,
        context_id: &str,
        subject_did: &str,
    ) -> Result<Vec<CachedAttestation>, StoreError> {
        let prefix = attestation_prefix(context_id, subject_did)?;
        let keys = self.storage().list_keys(&prefix).await?;
        let mut entries = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(entry) = self.load_value::<CachedAttestation>(&key).await? {
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    /// Stores revocation state for a context.
    ///
    /// Replaces any existing revocation state. The map keys are attestation
    /// IDs and values indicate revocation status (`true` = revoked).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if key sanitization, serialization, or storage
    /// fails.
    pub async fn store_trust_revocation_state(
        &self,
        context_id: &str,
        state: &HashMap<String, bool>,
    ) -> Result<(), StoreError> {
        let key = revocation_state_key(context_id)?;
        self.store_value(&key, state).await
    }

    /// Loads revocation state for a context.
    ///
    /// Returns an empty `HashMap` if no state has been stored.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if key sanitization or deserialization fails.
    pub async fn load_trust_revocation_state(
        &self,
        context_id: &str,
    ) -> Result<HashMap<String, bool>, StoreError> {
        let key = revocation_state_key(context_id)?;
        Ok(self.load_value(&key).await?.unwrap_or_default())
    }

    /// Stores a challenge verification result.
    ///
    /// The key includes the subject DID and verification ID, so storing the
    /// same verification ID again replaces the previous entry (idempotent).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if key sanitization, serialization, or storage
    /// fails.
    pub async fn store_trust_challenge_result(
        &self,
        context_id: &str,
        result: &ChallengeVerification,
    ) -> Result<(), StoreError> {
        let key = challenge_key(
            context_id,
            result.subject_did.as_ref(),
            &result.verification_id,
        )?;
        self.store_value(&key, result).await
    }

    /// Loads all challenge verification results for a subject DID within a
    /// context.
    ///
    /// Returns an empty `Vec` if no results exist.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if key sanitization, storage enumeration, or
    /// deserialization fails.
    pub async fn load_trust_challenge_results(
        &self,
        context_id: &str,
        subject_did: &str,
    ) -> Result<Vec<ChallengeVerification>, StoreError> {
        let prefix = challenge_prefix(context_id, subject_did)?;
        let keys = self.storage().list_keys(&prefix).await?;
        let mut results = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(result) = self.load_value::<ChallengeVerification>(&key).await? {
                results.push(result);
            }
        }
        Ok(results)
    }
}

// ---------------------------------------------------------------------------
// ProtocolRepositoryTrustBridge — sync adapter for TrustProtocolRepository
// ---------------------------------------------------------------------------

/// Synchronous bridge from [`TrustProtocolRepository`] to the async
/// `ProtocolRepository` trust methods.
///
/// Wraps `Arc<ProtocolRepository<S>>` and a tokio `Handle`, and implements the
/// synchronous [`TrustProtocolRepository`] trait by blocking on async methods
/// via `Handle::block_on`.
///
/// The `Handle` is stored on construction rather than obtained via
/// `Handle::current()`, because FFI callers run on non-tokio threads (Python,
/// Node.js libuv, Swift/Kotlin main threads).
///
/// `get_cached_attestations` returns ALL entries including expired ones —
/// `AttestationCache` handles TTL expiry and re-verification upstream.
///
/// See issue #502.
pub struct ProtocolRepositoryTrustBridge<S: Storage> {
    store: Arc<ProtocolRepository<S>>,
    handle: tokio::runtime::Handle,
}

impl<S: Storage> ProtocolRepositoryTrustBridge<S> {
    /// Creates a new bridge wrapping the given `ProtocolRepository` and
    /// tokio runtime handle.
    pub const fn new(store: Arc<ProtocolRepository<S>>, handle: tokio::runtime::Handle) -> Self {
        Self { store, handle }
    }
}

/// Maps a `StoreError` to a `TrustError::StoreError`.
#[allow(clippy::needless_pass_by_value)] // used as fn pointer in map_err
fn map_store_error(e: StoreError) -> TrustError {
    TrustError::StoreError {
        reason: e.to_string(),
    }
}

impl<S: Storage + 'static> TrustProtocolRepository for ProtocolRepositoryTrustBridge<S> {
    fn get_cached_attestations(
        &self,
        context_id: &str,
        subject_did: &str,
    ) -> Result<Vec<CachedAttestation>, TrustError> {
        let store = self.store.clone();
        let ctx_id = context_id.to_owned();
        let subject = subject_did.to_owned();
        self.handle
            .block_on(async {
                store
                    .load_trust_cached_attestations(&ctx_id, &subject)
                    .await
            })
            .map_err(map_store_error)
    }

    fn store_cached_attestation(
        &self,
        context_id: &str,
        entry: CachedAttestation,
    ) -> Result<(), TrustError> {
        let store = self.store.clone();
        let ctx_id = context_id.to_owned();
        self.handle
            .block_on(async { store.store_trust_cached_attestation(&ctx_id, &entry).await })
            .map_err(map_store_error)
    }

    fn get_revocation_state(&self, context_id: &str) -> Result<HashMap<String, bool>, TrustError> {
        let store = self.store.clone();
        let ctx_id = context_id.to_owned();
        self.handle
            .block_on(async { store.load_trust_revocation_state(&ctx_id).await })
            .map_err(map_store_error)
    }

    fn store_revocation_state(
        &self,
        context_id: &str,
        state: &HashMap<String, bool>,
    ) -> Result<(), TrustError> {
        let store = self.store.clone();
        let ctx_id = context_id.to_owned();
        let state = state.clone();
        self.handle
            .block_on(async { store.store_trust_revocation_state(&ctx_id, &state).await })
            .map_err(map_store_error)
    }

    fn get_challenge_results(
        &self,
        context_id: &str,
        subject_did: &str,
    ) -> Result<Vec<ChallengeVerification>, TrustError> {
        let store = self.store.clone();
        let ctx_id = context_id.to_owned();
        let subject = subject_did.to_owned();
        self.handle
            .block_on(async { store.load_trust_challenge_results(&ctx_id, &subject).await })
            .map_err(map_store_error)
    }

    fn store_challenge_result(
        &self,
        context_id: &str,
        result: &ChallengeVerification,
    ) -> Result<(), TrustError> {
        let store = self.store.clone();
        let ctx_id = context_id.to_owned();
        let result = result.clone();
        self.handle
            .block_on(async { store.store_trust_challenge_result(&ctx_id, &result).await })
            .map_err(map_store_error)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::trust::attestation::RevocationStatus;
    use crate::trust::challenge::{ChallengeType, VerificationMethod};
    use crate::trust::{Attestation, AttestationType};

    fn make_attestation(id: &str, subject: &str) -> Attestation {
        Attestation {
            id: id.to_owned(),
            attestation_type: AttestationType::Endorsement,
            issuer: "did:key:bob".into(),
            subject: subject.into(),
            claim: serde_json::json!({"skill": "rust"}),
            evidence: None,
            issued_at: 1000,
            expires_at: Some(10_000),
            renewal_interval: None,
            revocation_status: RevocationStatus::Active,
            signature: vec![0u8; 64],
            renewed_at: None,
        }
    }

    fn make_cached(id: &str, subject: &str, verified_at: u64, ttl: u64) -> CachedAttestation {
        CachedAttestation {
            attestation: make_attestation(id, subject),
            verified_at,
            ttl_secs: ttl,
        }
    }

    fn make_challenge_result(id: &str, subject: &str) -> ChallengeVerification {
        ChallengeVerification {
            verification_id: id.to_owned(),
            verifier_did: "did:key:verifier".into(),
            subject_did: subject.into(),
            capability_uri: "scp:capability:schema-validation/v1".to_owned(),
            challenge_type: ChallengeType::schema_validation(),
            verification_method: VerificationMethod::ChallengeVerified {
                challenge_type: ChallengeType::schema_validation(),
            },
            passed: true,
            score: Some(95),
            test_count: 10,
            pass_count: 9,
            result: serde_json::json!({"passed": true}),
            completed_at: 1800,
            verified_at: 1801,
            expires_at: 88_200,
            context_id: Some("ctx-test".to_owned()),
            verifier_signature: vec![0u8; 64],
        }
    }

    fn new_store() -> ProtocolRepository<scp_platform::testing::InMemoryStorage> {
        ProtocolRepository::new_for_testing(scp_platform::testing::InMemoryStorage::new())
    }

    // -------------------------------------------------------------------
    // Attestation cache roundtrip
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn attestation_roundtrip() {
        let store = new_store();
        let entry = make_cached("att-1", "did:key:alice", 1000, 300);

        store
            .store_trust_cached_attestation("ctx-1", &entry)
            .await
            .unwrap();

        let loaded = store
            .load_trust_cached_attestations("ctx-1", "did:key:alice")
            .await
            .unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].attestation.id, "att-1");
        assert_eq!(loaded[0].verified_at, 1000);
    }

    #[tokio::test]
    async fn attestation_replace_by_id() {
        let store = new_store();
        let entry1 = make_cached("att-1", "did:key:alice", 1000, 300);
        store
            .store_trust_cached_attestation("ctx-1", &entry1)
            .await
            .unwrap();

        // Replace with updated verified_at.
        let entry2 = make_cached("att-1", "did:key:alice", 2000, 300);
        store
            .store_trust_cached_attestation("ctx-1", &entry2)
            .await
            .unwrap();

        let loaded = store
            .load_trust_cached_attestations("ctx-1", "did:key:alice")
            .await
            .unwrap();
        assert_eq!(loaded.len(), 1, "should have 1 entry after replace-by-ID");
        assert_eq!(loaded[0].verified_at, 2000);
    }

    #[tokio::test]
    async fn attestation_empty_context() {
        let store = new_store();
        let loaded = store
            .load_trust_cached_attestations("ctx-empty", "did:key:nobody")
            .await
            .unwrap();
        assert!(loaded.is_empty());
    }

    // -------------------------------------------------------------------
    // Revocation state roundtrip
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn revocation_state_roundtrip() {
        let store = new_store();
        let mut state = HashMap::new();
        state.insert("att-1".to_owned(), true);
        state.insert("att-2".to_owned(), false);

        store
            .store_trust_revocation_state("ctx-1", &state)
            .await
            .unwrap();

        let loaded = store.load_trust_revocation_state("ctx-1").await.unwrap();
        assert_eq!(loaded, state);
    }

    #[tokio::test]
    async fn revocation_state_empty_returns_default() {
        let store = new_store();
        let loaded = store
            .load_trust_revocation_state("ctx-empty")
            .await
            .unwrap();
        assert!(loaded.is_empty());
    }

    // -------------------------------------------------------------------
    // Challenge result roundtrip
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn challenge_result_roundtrip() {
        let store = new_store();
        let result = make_challenge_result("cv-1", "did:key:alice");

        store
            .store_trust_challenge_result("ctx-1", &result)
            .await
            .unwrap();

        let loaded = store
            .load_trust_challenge_results("ctx-1", "did:key:alice")
            .await
            .unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].verification_id, "cv-1");
        assert!(loaded[0].passed);
    }

    #[tokio::test]
    async fn challenge_result_accumulation() {
        let store = new_store();

        let r1 = make_challenge_result("cv-1", "did:key:alice");
        let r2 = {
            let mut r = make_challenge_result("cv-2", "did:key:alice");
            r.passed = false;
            r.score = Some(40);
            r
        };

        store
            .store_trust_challenge_result("ctx-1", &r1)
            .await
            .unwrap();
        store
            .store_trust_challenge_result("ctx-1", &r2)
            .await
            .unwrap();

        let loaded = store
            .load_trust_challenge_results("ctx-1", "did:key:alice")
            .await
            .unwrap();
        assert_eq!(loaded.len(), 2);
    }

    #[tokio::test]
    async fn challenge_result_empty() {
        let store = new_store();
        let loaded = store
            .load_trust_challenge_results("ctx-empty", "did:key:nobody")
            .await
            .unwrap();
        assert!(loaded.is_empty());
    }

    // -------------------------------------------------------------------
    // Key traversal rejection
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn rejects_traversal_in_context_id() {
        let store = new_store();
        let entry = make_cached("att-1", "did:key:alice", 1000, 300);
        let result = store
            .store_trust_cached_attestation("../identity/victim", &entry)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rejects_traversal_in_subject_did() {
        let store = new_store();
        let loaded = store
            .load_trust_cached_attestations("ctx-1", "../context/victim")
            .await;
        assert!(loaded.is_err());
    }

    #[tokio::test]
    async fn rejects_null_byte_in_attestation_id() {
        let store = new_store();
        let mut entry = make_cached("att\0evil", "did:key:alice", 1000, 300);
        entry.attestation.id = "att\0evil".to_owned();
        let result = store.store_trust_cached_attestation("ctx-1", &entry).await;
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------
    // Bridge TTL filtering
    // -------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn bridge_returns_all_entries_including_expired() {
        let store = Arc::new(new_store());
        let handle = tokio::runtime::Handle::current();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let fresh = make_cached("att-fresh", "did:key:alice", now, 86400);
        let expired = make_cached("att-expired", "did:key:alice", 1000, 1);

        store
            .store_trust_cached_attestation("ctx-1", &fresh)
            .await
            .unwrap();
        store
            .store_trust_cached_attestation("ctx-1", &expired)
            .await
            .unwrap();

        // Call bridge from a blocking thread (simulates FFI caller context).
        let bridge = ProtocolRepositoryTrustBridge::new(store, handle);
        let cached = tokio::task::spawn_blocking(move || {
            bridge
                .get_cached_attestations("ctx-1", "did:key:alice")
                .unwrap()
        })
        .await
        .unwrap();
        assert_eq!(cached.len(), 2, "both fresh and expired should be returned");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bridge_revocation_state_roundtrip() {
        let store = Arc::new(new_store());
        let handle = tokio::runtime::Handle::current();
        let bridge = ProtocolRepositoryTrustBridge::new(store, handle);

        let mut state = HashMap::new();
        state.insert("att-1".to_owned(), true);

        // Call from blocking thread (simulates FFI caller context).
        tokio::task::spawn_blocking(move || {
            bridge.store_revocation_state("ctx-1", &state).unwrap();
            let loaded = bridge.get_revocation_state("ctx-1").unwrap();
            assert_eq!(loaded, state);
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bridge_challenge_result_roundtrip() {
        let store = Arc::new(new_store());
        let handle = tokio::runtime::Handle::current();
        let bridge = ProtocolRepositoryTrustBridge::new(store, handle);

        let result = make_challenge_result("cv-1", "did:key:alice");

        // Call from blocking thread (simulates FFI caller context).
        tokio::task::spawn_blocking(move || {
            bridge.store_challenge_result("ctx-1", &result).unwrap();
            let loaded = bridge
                .get_challenge_results("ctx-1", "did:key:alice")
                .unwrap();
            assert_eq!(loaded.len(), 1);
            assert_eq!(loaded[0].verification_id, "cv-1");
        })
        .await
        .unwrap();
    }

    // -------------------------------------------------------------------
    // Namespace isolation — trust keys never collide with other domains
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn all_trust_keys_use_trust_prefix() {
        let store = new_store();

        // Store data across all three trust sub-domains.
        let att = make_cached("att-ns", "did:key:alice", 1000, 300);
        store
            .store_trust_cached_attestation("ctx-ns", &att)
            .await
            .unwrap();

        let mut revocation = HashMap::new();
        revocation.insert("att-ns".to_owned(), false);
        store
            .store_trust_revocation_state("ctx-ns", &revocation)
            .await
            .unwrap();

        let cr = make_challenge_result("cv-ns", "did:key:alice");
        store
            .store_trust_challenge_result("ctx-ns", &cr)
            .await
            .unwrap();

        // Enumerate ALL keys in storage and verify every one starts with "trust/".
        let all_keys = store.storage().list_keys("").await.unwrap();
        for key in &all_keys {
            assert!(
                key.starts_with("trust/"),
                "trust store wrote key outside trust/ namespace: {key}"
            );
        }
        // Ensure we actually wrote something (guard against vacuous pass).
        assert!(
            all_keys.len() >= 3,
            "expected at least 3 keys, got {}",
            all_keys.len()
        );
    }

    // -------------------------------------------------------------------
    // delete_context cleans up trust keys
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn delete_context_removes_trust_keys() {
        let store = new_store();

        // Store trust data across all three sub-domains.
        let att = make_cached("att-del", "did:key:alice", 1000, 300);
        store
            .store_trust_cached_attestation("ctx-del", &att)
            .await
            .unwrap();

        let mut revocation = HashMap::new();
        revocation.insert("att-del".to_owned(), true);
        store
            .store_trust_revocation_state("ctx-del", &revocation)
            .await
            .unwrap();

        let cr = make_challenge_result("cv-del", "did:key:alice");
        store
            .store_trust_challenge_result("ctx-del", &cr)
            .await
            .unwrap();

        // Verify data exists.
        let keys_before = store.storage().list_keys("trust/ctx-del/").await.unwrap();
        assert!(
            keys_before.len() >= 3,
            "trust data should exist before delete"
        );

        // delete_context should remove trust/ keys for this context.
        store.delete_context("ctx-del").await.unwrap();

        let keys_after = store.storage().list_keys("trust/ctx-del/").await.unwrap();
        assert!(
            keys_after.is_empty(),
            "trust keys should be gone after delete_context, found: {keys_after:?}"
        );
    }
}
