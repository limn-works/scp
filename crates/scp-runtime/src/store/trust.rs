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
//! trust/{context_id}/attestation/{subject_did}/{sha256_hex(revocation_list_key(issuer, attestation_id))}
//! trust/{context_id}/revocation/{sha256_hex(revocation_list_key)}
//! trust/{context_id}/challenge/{subject_did}/{verification_id}
//! ```
//!
//! See spec section 17.3.

use std::collections::HashMap;
use std::sync::Arc;

use scp_platform::traits::Storage;

use super::{ProtocolRepository, StoreError, sanitize_key_component};
use scp_protocol::trust::TrustError;
use scp_protocol::trust::aggregate::{
    CachedAttestation, RevocationEntry, TrustProtocolRepository, plan_revocation_write,
    revocation_list_key,
};
use scp_protocol::trust::challenge::ChallengeVerification;

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

/// Builds the storage key for a cached attestation.
///
/// Format: `trust/{context_id}/attestation/{subject_did}/{sha256_hex(list_key)}`,
/// where `list_key` is `revocation_list_key(issuer, attestation_id)`.
///
/// The key names the issuer as well as the id, because §7.4.1 of
/// `.docs/specs/07-trust-validation-and-capabilities.md` binds
/// `Attestation.id` to no issuer: a key built from the id alone would let any
/// DID overwrite another issuer's cached attestation by signing one that
/// carries its id. Both fields are caller-chosen bytes, so they reach the path
/// only as a fixed-width hash that `sanitize_key_component` always accepts.
fn attestation_key(
    context_id: &str,
    subject_did: &str,
    attestation: &scp_protocol::trust::Attestation,
) -> Result<String, StoreError> {
    use sha2::{Digest, Sha256};
    let ctx = sanitize_key_component(context_id)?;
    let subject = sanitize_key_component(subject_did)?;
    let list_key = revocation_list_key(&attestation.issuer, &attestation.id);
    let digest = Sha256::digest(list_key.as_bytes());
    Ok(format!(
        "trust/{ctx}/attestation/{subject}/{}",
        hex::encode(digest)
    ))
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

/// Builds the storage key for ONE entry of a context's revocation list.
///
/// Format: `trust/{context_id}/revocation/{sha256_hex(list_key)}`
///
/// One entry per storage key, rather than one blob holding a whole map, is what
/// lets [`ProtocolRepository::add_trust_revocations`] add keys without reading
/// and rewriting a map that a concurrent caller may have grown meanwhile. The
/// list key itself travels inside [`RevocationRecord`], because a caller chooses
/// both the issuer DID and the attestation id that
/// `scp_protocol::trust::aggregate::revocation_list_key` joins, so those bytes
/// must never reach a storage path; hashing them yields a fixed-width hex
/// component that `sanitize_key_component` always accepts.
fn revocation_entry_key(context_id: &str, list_key: &str) -> Result<String, StoreError> {
    use sha2::{Digest, Sha256};
    let ctx = sanitize_key_component(context_id)?;
    let digest = Sha256::digest(list_key.as_bytes());
    Ok(format!("trust/{ctx}/revocation/{}", hex::encode(digest)))
}

/// Builds the prefix that lists every revocation entry for a context.
///
/// Format: `trust/{context_id}/revocation/`
fn revocation_prefix(context_id: &str) -> Result<String, StoreError> {
    let ctx = sanitize_key_component(context_id)?;
    Ok(format!("trust/{ctx}/revocation/"))
}

/// One entry of a context's revocation list, as persisted.
///
/// `list_key` carries the key that
/// `scp_protocol::trust::aggregate::revocation_list_key` built from an issuer
/// DID plus an attestation id. A storage key holds a hash of that value, so the
/// value itself rides in the record and
/// [`ProtocolRepository::load_trust_revocation_state`] rebuilds the map from it.
/// A record exists only for a revocation; its presence is the revocation.
#[derive(serde::Serialize, serde::Deserialize)]
struct RevocationRecord {
    /// The revocation-list key this record stands for.
    list_key: String,
    /// The revoked attestation's own `expires_at`, which decides when the
    /// record is pruned (see `RevocationEntry::expires_at`).
    expires_at: Option<u64>,
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
    /// The key includes the attestation's subject DID, issuer DID, and ID, so
    /// storing an attestation replaces only an entry that carries the same
    /// issuer and the same ID.
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
            &entry.attestation,
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

    /// Records each entry in `entries` as a revocation for a context, after
    /// pruning the records that are moot at `now`, by the plan
    /// `scp_protocol::trust::aggregate::plan_revocation_write` returns.
    ///
    /// SECURITY (lost update). Each record is written under its own storage
    /// key, so no write carries a stale copy of another key, and two concurrent
    /// callers that record different revocations both keep their record. A
    /// prune deletes only a record whose
    /// attestation has expired, which a concurrent caller can at most rewrite
    /// with the same content, and which no verification can need.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::StoreError`] if key sanitization, serialization,
    /// or storage fails.
    async fn add_trust_revocations(
        &self,
        context_id: &str,
        entries: &[RevocationEntry],
        now: u64,
    ) -> Result<(), TrustError> {
        if entries.is_empty() {
            return Ok(());
        }
        let existing = self
            .load_trust_revocation_records(context_id)
            .await
            .map_err(map_store_error)?;
        let plan = plan_revocation_write(&existing, entries, now);
        for list_key in &plan.prune {
            let key = revocation_entry_key(context_id, list_key).map_err(map_store_error)?;
            self.storage()
                .delete(&key)
                .await
                .map_err(|e| map_store_error(StoreError::from(e)))?;
        }
        for entry in plan.write {
            let key = revocation_entry_key(context_id, &entry.list_key).map_err(map_store_error)?;
            let record = RevocationRecord {
                list_key: entry.list_key,
                expires_at: entry.expires_at,
            };
            self.store_value(&key, &record)
                .await
                .map_err(map_store_error)?;
        }
        Ok(())
    }

    /// Loads every revocation record a context holds, with each record's
    /// expiry.
    async fn load_trust_revocation_records(
        &self,
        context_id: &str,
    ) -> Result<Vec<RevocationEntry>, StoreError> {
        let prefix = revocation_prefix(context_id)?;
        let keys = self.storage().list_keys(&prefix).await?;
        let mut records = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(record) = self.load_value::<RevocationRecord>(&key).await? {
                records.push(RevocationEntry {
                    list_key: record.list_key,
                    expires_at: record.expires_at,
                });
            }
        }
        Ok(records)
    }

    /// Loads revocation state for a context.
    ///
    /// Returns an empty `HashMap` if no state has been stored.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if key sanitization, storage enumeration, or
    /// deserialization fails.
    pub async fn load_trust_revocation_state(
        &self,
        context_id: &str,
    ) -> Result<HashMap<String, bool>, StoreError> {
        Ok(self
            .load_trust_revocation_records(context_id)
            .await?
            .into_iter()
            .map(|record| (record.list_key, true))
            .collect())
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

    fn add_revocations(
        &self,
        context_id: &str,
        entries: &[RevocationEntry],
        now: u64,
    ) -> Result<(), TrustError> {
        let store = self.store.clone();
        let ctx_id = context_id.to_owned();
        let entries = entries.to_vec();
        // `TrustProtocolRepository` is a sync trait over an async repository, and every
        // sibling method in this impl bridges that gap exactly this way. A caller reaches
        // this method from an FFI bridge thread, never from a tokio worker. Deleting this
        // call would delete the per-key merge `verify_and_cache_attestations` needs to add
        // revocations; a read-then-whole-map-write alternative loses a concurrent caller's
        // additions, which is a defect this method exists to close.
        self.handle
            .block_on(async { store.add_trust_revocations(&ctx_id, &entries, now).await }) // ci-allow: block-on: sync TrustProtocolRepository over an async repository, mirroring five sibling methods
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
    use scp_protocol::trust::attestation::RevocationStatus;
    use scp_protocol::trust::challenge::{ChallengeType, VerificationMethod};
    use scp_protocol::trust::{Attestation, AttestationType};

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

    /// A revocation entry that never expires.
    fn rev(list_key: &str) -> RevocationEntry {
        RevocationEntry {
            list_key: list_key.to_owned(),
            expires_at: None,
        }
    }

    fn new_store() -> ProtocolRepository<scp_platform::in_memory::InMemoryStorage> {
        ProtocolRepository::new_for_testing(scp_platform::in_memory::InMemoryStorage::new())
    }

    /// A [`Storage`] that injects faults on every read AND write operation, used
    /// to prove that backend faults surface as [`TrustError::StoreError`] (an
    /// INFRA fault that the verify-on-ingest layer MUST propagate, never classify
    /// as a per-entry verification rejection).
    struct AllFaultyStorage;

    #[allow(clippy::manual_async_fn)]
    impl Storage for AllFaultyStorage {
        fn store(
            &self,
            _key: &str,
            _data: &[u8],
        ) -> impl std::future::Future<Output = Result<(), scp_platform::PlatformError>> + Send
        {
            async move {
                Err(scp_platform::PlatformError::StorageError(
                    "injected store fault".to_owned(),
                ))
            }
        }
        fn retrieve(
            &self,
            _key: &str,
        ) -> impl std::future::Future<Output = Result<Option<Vec<u8>>, scp_platform::PlatformError>> + Send
        {
            async move {
                Err(scp_platform::PlatformError::StorageError(
                    "injected retrieve fault".to_owned(),
                ))
            }
        }
        fn delete(
            &self,
            _key: &str,
        ) -> impl std::future::Future<Output = Result<(), scp_platform::PlatformError>> + Send
        {
            async move {
                Err(scp_platform::PlatformError::StorageError(
                    "injected delete fault".to_owned(),
                ))
            }
        }
        fn list_keys(
            &self,
            _prefix: &str,
        ) -> impl std::future::Future<Output = Result<Vec<String>, scp_platform::PlatformError>> + Send
        {
            async move {
                Err(scp_platform::PlatformError::StorageError(
                    "injected list_keys fault".to_owned(),
                ))
            }
        }
        fn delete_prefix(
            &self,
            _prefix: &str,
        ) -> impl std::future::Future<Output = Result<u64, scp_platform::PlatformError>> + Send
        {
            async move {
                Err(scp_platform::PlatformError::StorageError(
                    "injected delete_prefix fault".to_owned(),
                ))
            }
        }
        fn exists(
            &self,
            _key: &str,
        ) -> impl std::future::Future<Output = Result<bool, scp_platform::PlatformError>> + Send
        {
            async move {
                Err(scp_platform::PlatformError::StorageError(
                    "injected exists fault".to_owned(),
                ))
            }
        }
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
        store
            .add_trust_revocations("ctx-1", &[rev("att-1"), rev("att-2")], 1000)
            .await
            .unwrap();

        let loaded = store.load_trust_revocation_state("ctx-1").await.unwrap();
        let expected: HashMap<String, bool> =
            [("att-1".to_owned(), true), ("att-2".to_owned(), true)]
                .into_iter()
                .collect();
        assert_eq!(loaded, expected);
    }

    /// Two issuers' attestations that carry one id and one subject are two
    /// cache entries, and storing the second leaves the first in place.
    #[tokio::test]
    async fn attestations_from_two_issuers_with_one_id_both_survive() {
        let store = new_store();
        let honest = make_cached("att-shared", "did:key:alice", 1000, 300);
        let mut forged = make_cached("att-shared", "did:key:alice", 1001, 300);
        forged.attestation.issuer = "did:key:mallory".into();

        store
            .store_trust_cached_attestation("ctx-1", &honest)
            .await
            .unwrap();
        store
            .store_trust_cached_attestation("ctx-1", &forged)
            .await
            .unwrap();

        let loaded = store
            .load_trust_cached_attestations("ctx-1", "did:key:alice")
            .await
            .unwrap();
        assert_eq!(loaded.len(), 2, "one id from two issuers is two entries");
        assert!(
            loaded
                .iter()
                .any(|e| e.attestation.issuer.as_ref() == "did:key:bob" && e.verified_at == 1000),
            "the honest issuer's entry must survive, cache reads {loaded:?}"
        );
    }

    /// A record whose attestation has expired is pruned by the next write, and
    /// a record that never expires is kept.
    #[tokio::test]
    async fn add_trust_revocations_prunes_records_whose_attestation_expired() {
        let store = new_store();
        let expiring = RevocationEntry {
            list_key: "9:did:key:a:att-old".to_owned(),
            expires_at: Some(1500),
        };
        store
            .add_trust_revocations(
                "ctx-prune",
                &[expiring, rev("9:did:key:a:att-forever")],
                1000,
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .load_trust_revocation_state("ctx-prune")
                .await
                .unwrap()
                .len(),
            2
        );

        store
            .add_trust_revocations("ctx-prune", &[rev("9:did:key:a:att-new")], 2000)
            .await
            .unwrap();

        let loaded = store
            .load_trust_revocation_state("ctx-prune")
            .await
            .unwrap();
        assert!(
            !loaded.contains_key("9:did:key:a:att-old"),
            "a record past its attestation's expiry must be pruned, list reads {loaded:?}"
        );
        assert!(loaded.contains_key("9:did:key:a:att-forever"));
        assert!(loaded.contains_key("9:did:key:a:att-new"));
    }

    /// SECURITY (lost update, issue #2335 bug-catcher item 8). Two callers on
    /// one context each read that context's revocation list, then each record a
    /// revocation through `add_trust_revocations`. Both revocations survive,
    /// because each key is written under its own storage key and no write
    /// carries a stale copy of another key. Both reads happen BEFORE either
    /// write, which is the interleaving that loses an update when a caller
    /// rebuilds a whole map from its own earlier read.
    #[tokio::test]
    async fn interleaved_revocation_additions_both_survive() {
        let store = new_store();

        let first_read = store.load_trust_revocation_state("ctx-race").await.unwrap();
        let second_read = store.load_trust_revocation_state("ctx-race").await.unwrap();
        assert!(first_read.is_empty());
        assert!(second_read.is_empty());

        store
            .add_trust_revocations("ctx-race", &[rev("9:did:key:a:att-a")], 1000)
            .await
            .unwrap();
        store
            .add_trust_revocations("ctx-race", &[rev("9:did:key:b:att-b")], 1000)
            .await
            .unwrap();

        let loaded = store.load_trust_revocation_state("ctx-race").await.unwrap();
        assert_eq!(
            loaded.get("9:did:key:a:att-a"),
            Some(&true),
            "the first caller's revocation must survive, list reads {loaded:?}"
        );
        assert_eq!(
            loaded.get("9:did:key:b:att-b"),
            Some(&true),
            "the second caller's revocation must be recorded, list reads {loaded:?}"
        );
    }

    /// A revocation-list key carries a caller-chosen issuer DID and a
    /// caller-chosen attestation id, so those bytes must not reach a storage
    /// path. `revocation_entry_key` hashes the key, so a key holding `..` and
    /// `/` still round-trips and still writes inside this context's namespace.
    #[tokio::test]
    async fn revocation_key_with_path_characters_round_trips() {
        let store = new_store();
        let hostile = "13:did:key:../..:att/../../escape".to_owned();

        store
            .add_trust_revocations("ctx-hostile", &[rev(&hostile)], 1000)
            .await
            .unwrap();

        let loaded = store
            .load_trust_revocation_state("ctx-hostile")
            .await
            .unwrap();
        assert_eq!(loaded.get(&hostile), Some(&true));

        for key in store.storage().list_keys("").await.unwrap() {
            assert!(
                key.starts_with("trust/ctx-hostile/revocation/"),
                "a revocation entry must stay inside its context namespace: {key}"
            );
        }
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

    /// An attestation id and issuer reach the storage path only as a hash, so
    /// path-hostile bytes in either stay inside the subject's namespace.
    #[tokio::test]
    async fn hostile_attestation_id_stays_inside_its_namespace() {
        let store = new_store();
        let mut entry = make_cached("att\0evil/../../escape", "did:key:alice", 1000, 300);
        entry.attestation.issuer = "did:key:../..".into();
        store
            .store_trust_cached_attestation("ctx-1", &entry)
            .await
            .unwrap();
        for key in store.storage().list_keys("").await.unwrap() {
            assert!(
                key.starts_with("trust/ctx-1/attestation/did:key:alice/"),
                "a cached attestation must stay inside its subject namespace: {key}"
            );
        }
        let loaded = store
            .load_trust_cached_attestations("ctx-1", "did:key:alice")
            .await
            .unwrap();
        assert_eq!(loaded.len(), 1);
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
            bridge
                .add_revocations("ctx-1", &[rev("att-1")], 1000)
                .unwrap();
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
    // Infra-fault propagation — backend faults surface as StoreError
    // -------------------------------------------------------------------

    /// A backend read fault must surface as [`TrustError::StoreError`] (an INFRA
    /// fault), NEVER as a canonicalization/verification rejection. This is what
    /// keeps the verify-on-ingest layer from silently dropping every credential
    /// on a transient store error.
    #[tokio::test(flavor = "multi_thread")]
    async fn bridge_read_fault_surfaces_as_store_error() {
        let store = Arc::new(ProtocolRepository::new_for_testing(AllFaultyStorage));
        let handle = tokio::runtime::Handle::current();
        let bridge = ProtocolRepositoryTrustBridge::new(store, handle);

        let err = tokio::task::spawn_blocking(move || {
            bridge
                .get_cached_attestations("ctx-1", "did:key:alice")
                .expect_err("a backend read fault must error")
        })
        .await
        .unwrap();

        assert!(
            matches!(err, TrustError::StoreError { .. }),
            "backend read fault must map to StoreError (infra → propagate), got {err:?}"
        );
    }

    /// A backend write fault must likewise surface as [`TrustError::StoreError`].
    #[tokio::test(flavor = "multi_thread")]
    async fn bridge_write_fault_surfaces_as_store_error() {
        let store = Arc::new(ProtocolRepository::new_for_testing(AllFaultyStorage));
        let handle = tokio::runtime::Handle::current();
        let bridge = ProtocolRepositoryTrustBridge::new(store, handle);
        let entry = make_cached("att-1", "did:key:alice", 1000, 300);

        let err = tokio::task::spawn_blocking(move || {
            bridge
                .store_cached_attestation("ctx-1", entry)
                .expect_err("a backend write fault must error")
        })
        .await
        .unwrap();

        assert!(
            matches!(err, TrustError::StoreError { .. }),
            "backend write fault must map to StoreError (infra → propagate), got {err:?}"
        );
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

        store
            .add_trust_revocations("ctx-ns", &[rev("att-ns")], 1000)
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

        store
            .add_trust_revocations("ctx-del", &[rev("att-del")], 1000)
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
