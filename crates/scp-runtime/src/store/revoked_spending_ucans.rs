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
//! This store is the durable home for those global-scope revocations. It shares
//! the `identity/{did}/` key namespace and the same `ProtocolRepository<S: Storage>`
//! backing used by the DID-scoped `identity/{did}/adapter_credentials/` store
//! (`store::economy`, §19.2.4) — a namespace/backing relationship only; the
//! record shape and access pattern are this store's own. Enforcement is **local,
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
//! (the `did`/`cid` values carry the raw identifiers; the storage *key*
//! components are sanitized — the sanitizer REJECTS rather than transforms, so
//! it never silently mangles a value).
//!
//! # Bounding (expiry GC)
//!
//! A spending UCAN is self-issued (`iss == aud == did`), so a payer can mint
//! and then revoke an unbounded number of *distinct* tokens against their own
//! DID — the revocation stores are NOT "self-limiting by construction". They
//! are instead bounded by **expiry-based garbage collection**: a spending UCAN
//! carries a ≤24-hour expiry (§9.5), and a revoked CID for an ALREADY-EXPIRED
//! token is moot (the token is expiry-rejected by the paid-action gate
//! regardless of whether its CID is in the set). Each record therefore carries
//! the time after which its revocation is provably moot
//! ([`RevokedSpendingUcanRecord::revocation_moot_after_secs`]), and expired
//! records are pruned on every [`record`](RevokedSpendingUcanStore::record)
//! (insert) and on every [`load_all`](RevokedSpendingUcanStore::load_all)
//! (hydration). Steady-state size is thus bounded by the number of a DID's
//! spending UCANs revoked within the last ~24 hours, together with the
//! trusted-local-caller self-governance model (only the payer, or a
//! context creator for a context-scoped token, can revoke — §19.5).

use std::collections::{HashMap, HashSet};

use scp_did::DID;
use scp_platform::traits::Storage;
use serde::{Deserialize, Serialize};

use super::{ProtocolRepository, StoreError, sanitize_key_component};

/// Durable record of one revoked global-scope spending UCAN.
///
/// `did`/`cid` are stored **raw** (unsanitized) so [`RevokedSpendingUcanStore::load_all`]
/// reconstructs the exact `(DID, cid)` pairs — the storage key sanitizes its
/// components (rejecting, not transforming) so it is not a reversible carrier of
/// the raw values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RevokedSpendingUcanRecord {
    /// The issuer/payer DID whose global spending UCAN was revoked.
    did: String,
    /// The SHA-256 revocation CID of the revoked token.
    cid: String,
    /// Unix seconds after which this revocation is provably moot and may be
    /// garbage-collected: the revoked token's `exp` plus the clock-skew
    /// tolerance the paid-action gate applies to expiry. Once `now` exceeds
    /// this, the token is expiry-rejected by the gate regardless of whether its
    /// CID remains in the revoked set, so retaining the CID only wastes space.
    /// Defaults to `0` (immediately GC-eligible) for records written by an
    /// older build without this field.
    #[serde(default)]
    revocation_moot_after_secs: u64,
}

/// Key prefix under which every identity's data (including revoked global
/// spending UCANs) is namespaced. Hydration scans this prefix and filters for
/// the `revoked_spending_ucans` segment because the DID sits *between* the
/// prefix and the segment, so no single narrower prefix covers all DIDs.
const IDENTITY_PREFIX: &str = "identity/";

/// The per-DID key segment identifying a revoked global spending-UCAN entry.
const REVOKED_SEGMENT: &str = "/revoked_spending_ucans/";

/// Builds the `identity/{sanitized_did}` prefix component for `did`.
///
/// Used both to construct a per-entry key and to scope the per-DID expiry-GC
/// prune to a single issuer's revocations.
fn did_prefix_component(did: &DID) -> Result<String, StoreError> {
    let did_str = sanitize_key_component(did.as_ref())?;
    Ok(format!("{IDENTITY_PREFIX}{did_str}"))
}

/// Builds the storage key for a revoked global spending UCAN.
///
/// Format: `identity/{did}/revoked_spending_ucans/{cid}`.
fn revoked_spending_ucan_key(did: &DID, cid: &str) -> Result<String, StoreError> {
    let cid_str = sanitize_key_component(cid)?;
    Ok(format!(
        "{}/revoked_spending_ucans/{cid_str}",
        did_prefix_component(did)?
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
    /// `revocation_moot_after_secs` is the Unix time after which this revocation
    /// is provably moot (the revoked token's `exp` plus the gate's clock-skew
    /// tolerance); `now_secs` is the current time. After writing the record this
    /// method prunes every already-moot revoked entry for the SAME `did`
    /// (expiry GC on insert, spec §19.5) so the per-DID set stays bounded by the
    /// number of still-relevant (unexpired) revocations.
    ///
    /// # Errors
    ///
    /// [`StoreError::SerializationFailed`] if the record cannot be serialized;
    /// [`StoreError::Storage`] if the underlying write/prune fails.
    pub async fn record_revoked_spending_ucan(
        &self,
        did: &DID,
        cid: &str,
        revocation_moot_after_secs: u64,
        now_secs: u64,
    ) -> Result<(), StoreError> {
        let key = revoked_spending_ucan_key(did, cid)?;
        let record = RevokedSpendingUcanRecord {
            did: did.as_ref().to_owned(),
            cid: cid.to_owned(),
            revocation_moot_after_secs,
        };
        self.store_value(&key, &record).await?;
        // Expiry GC on insert: drop this DID's already-moot revocations so a
        // mint+revoke flood of self-issued spending UCANs cannot grow the set
        // without bound (the revoked stores are NOT self-limiting — a payer can
        // mint unlimited distinct tokens against their own DID).
        let did_prefix = format!("{}/revoked_spending_ucans/", did_prefix_component(did)?);
        self.prune_moot_revoked_spending_ucans(&did_prefix, now_secs)
            .await?;
        Ok(())
    }

    /// Deletes every revoked-spending-UCAN record under `prefix` whose
    /// [`RevokedSpendingUcanRecord::revocation_moot_after_secs`] is at or before
    /// `now_secs` (i.e. the underlying token is already expiry-rejected by the
    /// gate). Shared by the insert (per-DID prefix) and hydration (all-DID
    /// `identity/` prefix) GC paths.
    async fn prune_moot_revoked_spending_ucans(
        &self,
        prefix: &str,
        now_secs: u64,
    ) -> Result<(), StoreError> {
        let keys = self.storage.list_keys(prefix).await?;
        for key in keys {
            if !key.contains(REVOKED_SEGMENT) {
                continue;
            }
            if let Some(record) = self.load_value::<RevokedSpendingUcanRecord>(&key).await?
                && record.revocation_moot_after_secs <= now_secs
            {
                self.storage.delete(&key).await?;
            }
        }
        Ok(())
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

    /// Loads every *still-relevant* revoked global spending-UCAN CID, grouped by
    /// issuer DID, garbage-collecting already-moot entries as it goes.
    ///
    /// Used to hydrate the in-memory gate cache at supervisor startup so a
    /// revocation persisted before a restart still rejects afterward. Scans the
    /// `identity/` prefix and keeps only `.../revoked_spending_ucans/...` keys,
    /// reconstructing `(DID, cid)` from each record's raw `did`/`cid` fields
    /// (the value carries them; the key's `sanitize_key_component` REJECTS
    /// disallowed input rather than transforming it, so it is not relied on as a
    /// reversible carrier).
    ///
    /// Expiry GC on hydration (spec §19.5): a record whose
    /// `revocation_moot_after_secs <= now_secs` is for an already-expiry-rejected
    /// token, so it is DELETED from durable storage and omitted from the result —
    /// bounding both the durable store and the hydrated in-memory cache.
    ///
    /// # Errors
    ///
    /// [`StoreError::Storage`] if the underlying list/read/delete fails.
    pub async fn load_all_revoked_spending_ucans(
        &self,
        now_secs: u64,
    ) -> Result<HashMap<DID, HashSet<String>>, StoreError> {
        let keys = self.storage.list_keys(IDENTITY_PREFIX).await?;
        let mut out: HashMap<DID, HashSet<String>> = HashMap::new();
        for key in keys {
            if !key.contains(REVOKED_SEGMENT) {
                continue;
            }
            if let Some(record) = self.load_value::<RevokedSpendingUcanRecord>(&key).await? {
                if record.revocation_moot_after_secs <= now_secs {
                    // GC: the revoked token is already expiry-rejected by the
                    // gate, so its CID is dead weight — drop it durably.
                    self.storage.delete(&key).await?;
                    continue;
                }
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
    /// Durably records `cid` as a revoked global spending UCAN for `did`, and
    /// prunes this DID's already-moot revocations (expiry GC on insert).
    ///
    /// `revocation_moot_after_secs` is the Unix time after which the revocation
    /// is provably moot (the token's `exp` plus the gate's clock-skew
    /// tolerance); `now_secs` is the current time used for the GC comparison.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the durable write/prune fails.
    async fn record(
        &self,
        did: &DID,
        cid: &str,
        revocation_moot_after_secs: u64,
        now_secs: u64,
    ) -> Result<(), StoreError>;

    /// Loads every still-relevant revoked global spending-UCAN CID grouped by
    /// issuer DID (hydration), garbage-collecting already-moot entries (those
    /// with `revocation_moot_after_secs <= now_secs`) as it goes.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the durable read/delete fails.
    async fn load_all(&self, now_secs: u64) -> Result<HashMap<DID, HashSet<String>>, StoreError>;
}

#[async_trait::async_trait]
impl<S: Storage> RevokedSpendingUcanStore for ProtocolRepository<S> {
    async fn record(
        &self,
        did: &DID,
        cid: &str,
        revocation_moot_after_secs: u64,
        now_secs: u64,
    ) -> Result<(), StoreError> {
        self.record_revoked_spending_ucan(did, cid, revocation_moot_after_secs, now_secs)
            .await
    }

    async fn load_all(&self, now_secs: u64) -> Result<HashMap<DID, HashSet<String>>, StoreError> {
        self.load_all_revoked_spending_ucans(now_secs).await
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

    /// A moot-after time far in the future — these tokens never GC in tests
    /// that pass a small `now`.
    const FAR_FUTURE: u64 = u64::MAX;
    /// A representative "now" used by non-GC tests.
    const NOW: u64 = 1_700_000_000;

    #[tokio::test]
    async fn record_then_is_revoked_true() {
        let repo = repo();
        let d = did("did:dht:z6MkPayer");
        assert!(!repo.is_revoked_spending_ucan(&d, "cidA").await.unwrap());
        repo.record_revoked_spending_ucan(&d, "cidA", FAR_FUTURE, NOW)
            .await
            .unwrap();
        assert!(repo.is_revoked_spending_ucan(&d, "cidA").await.unwrap());
        // A different CID for the same DID is independent.
        assert!(!repo.is_revoked_spending_ucan(&d, "cidB").await.unwrap());
    }

    #[tokio::test]
    async fn record_is_idempotent() {
        let repo = repo();
        let d = did("did:dht:z6MkPayer");
        repo.record_revoked_spending_ucan(&d, "cidA", FAR_FUTURE, NOW)
            .await
            .unwrap();
        repo.record_revoked_spending_ucan(&d, "cidA", FAR_FUTURE, NOW)
            .await
            .unwrap();
        let all = repo.load_all_revoked_spending_ucans(NOW).await.unwrap();
        assert_eq!(all.get(&d).map(HashSet::len), Some(1));
    }

    #[tokio::test]
    async fn load_all_groups_by_did_and_recovers_raw_values() {
        let repo = repo();
        let d1 = did("did:dht:z6MkAlice");
        let d2 = did("did:dht:z6MkBob");
        repo.record_revoked_spending_ucan(&d1, "cid1", FAR_FUTURE, NOW)
            .await
            .unwrap();
        repo.record_revoked_spending_ucan(&d1, "cid2", FAR_FUTURE, NOW)
            .await
            .unwrap();
        repo.record_revoked_spending_ucan(&d2, "cid3", FAR_FUTURE, NOW)
            .await
            .unwrap();

        let all = repo.load_all_revoked_spending_ucans(NOW).await.unwrap();
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
        repo.record_revoked_spending_ucan(&d, "cidA", FAR_FUTURE, NOW)
            .await
            .unwrap();

        let all = repo.load_all_revoked_spending_ucans(NOW).await.unwrap();
        assert_eq!(all.get(&d).unwrap(), &HashSet::from(["cidA".to_owned()]));
    }

    #[tokio::test]
    async fn trait_object_roundtrip() {
        let repo = repo();
        let store: &dyn RevokedSpendingUcanStore = &repo;
        let d = did("did:dht:z6MkPayer");
        store.record(&d, "cidA", FAR_FUTURE, NOW).await.unwrap();
        let all = store.load_all(NOW).await.unwrap();
        assert_eq!(all.get(&d).unwrap(), &HashSet::from(["cidA".to_owned()]));
    }

    /// Expiry GC (spec §19.5): a revoked entry whose token is already
    /// expiry-moot is pruned — on hydration (`load_all`) it is dropped from the
    /// durable store AND omitted from the result — while a still-relevant entry
    /// is retained and keeps rejecting.
    #[tokio::test]
    async fn load_all_prunes_moot_and_retains_relevant() {
        let repo = repo();
        let d = did("did:dht:z6MkPayer");
        // `expired` is moot at/after t=1000; `live` stays relevant until t=5000.
        repo.record_revoked_spending_ucan(&d, "expired-cid", 1_000, 500)
            .await
            .unwrap();
        repo.record_revoked_spending_ucan(&d, "live-cid", 5_000, 500)
            .await
            .unwrap();

        // Hydrate at t=2000: the expired entry is GC'd, the live one survives.
        let all = repo.load_all_revoked_spending_ucans(2_000).await.unwrap();
        assert_eq!(
            all.get(&d).unwrap(),
            &HashSet::from(["live-cid".to_owned()]),
            "hydration must drop the moot entry and keep the still-relevant one"
        );
        // The moot entry is durably gone; the live one still rejects.
        assert!(
            !repo
                .is_revoked_spending_ucan(&d, "expired-cid")
                .await
                .unwrap(),
            "the moot revocation must be pruned from durable storage"
        );
        assert!(
            repo.is_revoked_spending_ucan(&d, "live-cid").await.unwrap(),
            "the still-relevant revocation must be retained and keep rejecting"
        );
    }

    /// Expiry GC on insert: recording a fresh revocation prunes this DID's
    /// already-moot entries in the same call, so a mint+revoke flood cannot
    /// grow the durable set without bound.
    #[tokio::test]
    async fn record_prunes_moot_entries_for_same_did_on_insert() {
        let repo = repo();
        let d = did("did:dht:z6MkPayer");
        // Seed a moot entry (moot at/after t=1000).
        repo.record_revoked_spending_ucan(&d, "old-cid", 1_000, 500)
            .await
            .unwrap();
        // Insert a new one at t=2000 — the seeded moot entry is GC'd on insert.
        repo.record_revoked_spending_ucan(&d, "new-cid", 9_000, 2_000)
            .await
            .unwrap();
        assert!(
            !repo.is_revoked_spending_ucan(&d, "old-cid").await.unwrap(),
            "insert-time GC must drop the moot entry"
        );
        assert!(
            repo.is_revoked_spending_ucan(&d, "new-cid").await.unwrap(),
            "the freshly-recorded revocation must be retained"
        );
    }
}
