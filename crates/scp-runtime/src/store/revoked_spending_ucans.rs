//! Durable, DID-scoped store for revoked **global-scope** spending UCANs
//! (spec §19.5 "Revocation").
//!
//! # Why this store exists
//!
//! A spending UCAN's scope is either a single context (`scp:spending:{ctx}`) or
//! global (`scp:spending:*`). Context-scoped revocations live in that context's
//! Class-S `revoked_spending_ucan_cids` set (per-context governance state).
//! A **global** spending UCAN, however, authorizes spends in *any* context, so
//! its revocation cannot be keyed by a context — it is keyed by the issuer/payer
//! DID (spending UCANs are self-delegations, `iss == aud == did`, §19.5).
//!
//! This store is the durable home for those global-scope revocations. It mirrors
//! the existing DID-scoped [`identity/{did}/adapter_credentials/`] store
//! (`store::economy`, §19.2.4): same `ProtocolRepository<S: Storage>` backing,
//! same `identity/{did}/...` key namespace. Enforcement is **local,
//! per-instance** self-governance (§19.5 "Enforcement location") — there is no
//! cross-instance propagation and none is claimed; blast radius across a payer's
//! other instances is bounded by the 24-hour spending-UCAN expiry (§9.5).
//!
//! # Key format
//!
//! ```text
//! identity/{did}/revoked_spending_ucans/{cid}
//! ```
//!
//! `cid` is the SHA-256 revocation CID (`compute_revocation_cid`) — the exact
//! identifier the paid-action gate computes over the encoded token. Both `did`
//! and `cid` are stored raw in the value so hydration recovers them losslessly
//! (the key components are sanitized and therefore not reversible).

use std::collections::{HashMap, HashSet};

use scp_did::DID;
use scp_platform::traits::Storage;
use serde::{Deserialize, Serialize};

use super::{ProtocolRepository, StoreError, sanitize_key_component};

/// Durable record of one revoked global-scope spending UCAN.
///
/// Both fields are stored **raw** (unsanitized) so [`RevokedSpendingUcanStore::load_all`]
/// reconstructs the exact `(DID, cid)` pairs — the storage key sanitizes its
/// components and is therefore not reversible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RevokedSpendingUcanRecord {
    /// The issuer/payer DID whose global spending UCAN was revoked.
    did: String,
    /// The SHA-256 revocation CID of the revoked token.
    cid: String,
}

/// Key prefix under which every identity's data (including revoked global
/// spending UCANs) is namespaced. Hydration scans this prefix and filters for
/// the `revoked_spending_ucans` segment because the DID sits *between* the
/// prefix and the segment, so no single narrower prefix covers all DIDs.
const IDENTITY_PREFIX: &str = "identity/";

/// The per-DID key segment identifying a revoked global spending-UCAN entry.
const REVOKED_SEGMENT: &str = "/revoked_spending_ucans/";

/// Builds the storage key for a revoked global spending UCAN.
///
/// Format: `identity/{did}/revoked_spending_ucans/{cid}`.
fn revoked_spending_ucan_key(did: &DID, cid: &str) -> Result<String, StoreError> {
    let did_str = sanitize_key_component(did.as_ref())?;
    let cid_str = sanitize_key_component(cid)?;
    Ok(format!(
        "{IDENTITY_PREFIX}{did_str}/revoked_spending_ucans/{cid_str}"
    ))
}

impl<S: Storage> ProtocolRepository<S> {
    /// Durably records that a global-scope spending UCAN (identified by its
    /// revocation `cid`) is revoked for `did`.
    ///
    /// Idempotent: re-recording the same `(did, cid)` overwrites the identical
    /// value. The value carries the raw `did`/`cid` so
    /// [`Self::load_all_revoked_spending_ucans`] recovers them losslessly.
    ///
    /// # Errors
    ///
    /// [`StoreError::SerializationFailed`] if the record cannot be serialized;
    /// [`StoreError::Storage`] if the underlying write fails.
    pub async fn record_revoked_spending_ucan(
        &self,
        did: &DID,
        cid: &str,
    ) -> Result<(), StoreError> {
        let key = revoked_spending_ucan_key(did, cid)?;
        let record = RevokedSpendingUcanRecord {
            did: did.as_ref().to_owned(),
            cid: cid.to_owned(),
        };
        self.store_value(&key, &record).await
    }

    /// Returns `true` iff `cid` is durably recorded as a revoked global spending
    /// UCAN for `did`.
    ///
    /// # Errors
    ///
    /// [`StoreError::Storage`] if the underlying read fails.
    pub async fn is_revoked_spending_ucan(&self, did: &DID, cid: &str) -> Result<bool, StoreError> {
        let key = revoked_spending_ucan_key(did, cid)?;
        Ok(self
            .load_value::<RevokedSpendingUcanRecord>(&key)
            .await?
            .is_some())
    }

    /// Loads every revoked global spending-UCAN CID, grouped by issuer DID.
    ///
    /// Used to hydrate the in-memory gate cache at supervisor construction so a
    /// revocation persisted before a restart still rejects afterward. Scans the
    /// `identity/` prefix and keeps only `.../revoked_spending_ucans/...` keys,
    /// reconstructing `(DID, cid)` from each record's raw fields (the key's
    /// components are sanitized and not reversible).
    ///
    /// # Errors
    ///
    /// [`StoreError::Storage`] if the underlying list/read fails.
    pub async fn load_all_revoked_spending_ucans(
        &self,
    ) -> Result<HashMap<DID, HashSet<String>>, StoreError> {
        let keys = self.storage.list_keys(IDENTITY_PREFIX).await?;
        let mut out: HashMap<DID, HashSet<String>> = HashMap::new();
        for key in keys {
            if !key.contains(REVOKED_SEGMENT) {
                continue;
            }
            if let Some(record) = self.load_value::<RevokedSpendingUcanRecord>(&key).await? {
                out.entry(DID::from(record.did))
                    .or_default()
                    .insert(record.cid);
            }
        }
        Ok(out)
    }
}

/// Narrow, object-safe durable store for revoked **global-scope** spending
/// UCANs (spec §19.5).
///
/// Injected into the [`Supervisor`](crate::context::supervisor::Supervisor) as a
/// provider `OnceLock` (like `event_log` / `crypto` / …), constructed by each
/// FFI bridge over the bridge's OWN `ProtocolRepository` — so the raw `Storage`
/// handle is never re-exposed (ADR-049 durable-providers rule). The paid-action
/// gate never touches this trait: it reads a lock-free in-memory `ArcSwap`
/// snapshot the supervisor hydrates from [`Self::load_all`] at construction and
/// updates on each global revocation, keeping the ADR-049 §5 gate capability
/// boundary unchanged.
///
/// `async_trait` (not RPITIT) so the trait is object-safe — the supervisor holds
/// it as `Arc<dyn RevokedSpendingUcanStore>`, matching the other provider traits
/// (`ContextEventLogProvider`, `ContextPersistence`).
#[async_trait::async_trait]
pub trait RevokedSpendingUcanStore: Send + Sync {
    /// Durably records `cid` as a revoked global spending UCAN for `did`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the durable write fails.
    async fn record(&self, did: &DID, cid: &str) -> Result<(), StoreError>;

    /// Loads every revoked global spending-UCAN CID grouped by issuer DID
    /// (hydration).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the durable read fails.
    async fn load_all(&self) -> Result<HashMap<DID, HashSet<String>>, StoreError>;
}

#[async_trait::async_trait]
impl<S: Storage> RevokedSpendingUcanStore for ProtocolRepository<S> {
    async fn record(&self, did: &DID, cid: &str) -> Result<(), StoreError> {
        self.record_revoked_spending_ucan(did, cid).await
    }

    async fn load_all(&self) -> Result<HashMap<DID, HashSet<String>>, StoreError> {
        self.load_all_revoked_spending_ucans().await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use scp_platform::testing::InMemoryStorage;

    fn repo() -> ProtocolRepository<InMemoryStorage> {
        ProtocolRepository::new_for_testing(InMemoryStorage::new())
    }

    fn did(s: &str) -> DID {
        DID::from(s.to_owned())
    }

    #[tokio::test]
    async fn record_then_is_revoked_true() {
        let repo = repo();
        let d = did("did:dht:z6MkPayer");
        assert!(!repo.is_revoked_spending_ucan(&d, "cidA").await.unwrap());
        repo.record_revoked_spending_ucan(&d, "cidA").await.unwrap();
        assert!(repo.is_revoked_spending_ucan(&d, "cidA").await.unwrap());
        // A different CID for the same DID is independent.
        assert!(!repo.is_revoked_spending_ucan(&d, "cidB").await.unwrap());
    }

    #[tokio::test]
    async fn record_is_idempotent() {
        let repo = repo();
        let d = did("did:dht:z6MkPayer");
        repo.record_revoked_spending_ucan(&d, "cidA").await.unwrap();
        repo.record_revoked_spending_ucan(&d, "cidA").await.unwrap();
        let all = repo.load_all_revoked_spending_ucans().await.unwrap();
        assert_eq!(all.get(&d).map(HashSet::len), Some(1));
    }

    #[tokio::test]
    async fn load_all_groups_by_did_and_recovers_raw_values() {
        let repo = repo();
        let d1 = did("did:dht:z6MkAlice");
        let d2 = did("did:dht:z6MkBob");
        repo.record_revoked_spending_ucan(&d1, "cid1")
            .await
            .unwrap();
        repo.record_revoked_spending_ucan(&d1, "cid2")
            .await
            .unwrap();
        repo.record_revoked_spending_ucan(&d2, "cid3")
            .await
            .unwrap();

        let all = repo.load_all_revoked_spending_ucans().await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(
            all.get(&d1).unwrap(),
            &HashSet::from(["cid1".to_owned(), "cid2".to_owned()])
        );
        assert_eq!(all.get(&d2).unwrap(), &HashSet::from(["cid3".to_owned()]));
    }

    #[tokio::test]
    async fn load_all_ignores_other_identity_keys() {
        let repo = repo();
        let d = did("did:dht:z6MkPayer");
        // A sibling identity-scoped store (adapter credentials) must NOT leak
        // into the revoked-spending-UCAN hydration.
        repo.store_adapter_credentials(&d, "x402", b"cred")
            .await
            .unwrap();
        repo.record_revoked_spending_ucan(&d, "cidA").await.unwrap();

        let all = repo.load_all_revoked_spending_ucans().await.unwrap();
        assert_eq!(all.get(&d).unwrap(), &HashSet::from(["cidA".to_owned()]));
    }

    #[tokio::test]
    async fn trait_object_roundtrip() {
        let repo = repo();
        let store: &dyn RevokedSpendingUcanStore = &repo;
        let d = did("did:dht:z6MkPayer");
        store.record(&d, "cidA").await.unwrap();
        let all = store.load_all().await.unwrap();
        assert_eq!(all.get(&d).unwrap(), &HashSet::from(["cidA".to_owned()]));
    }
}
