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
//! # Bounding (expiry GC — this global store only)
//!
//! A spending UCAN is self-issued (`iss == aud == did`), so a payer can mint
//! and then revoke an unbounded number of *distinct* tokens against their own
//! DID — this store is NOT "self-limiting by construction". Because it is
//! node-local and **non-convergent** (see the module intro), it is safe to
//! bound by **expiry-based garbage collection**: a spending UCAN carries a
//! ≤24-hour expiry (§9.5), and a revoked CID for an ALREADY-EXPIRED token is
//! moot (the token is expiry-rejected by the paid-action gate regardless of
//! whether its CID is in the set). Each record therefore carries the time after
//! which its revocation is provably moot
//! ([`RevokedSpendingUcanRecord::revocation_moot_after_secs`]), and expired
//! records are pruned on every [`record`](RevokedSpendingUcanStore::record)
//! (insert) and on every [`load_all`](RevokedSpendingUcanStore::load_all)
//! (hydration). Steady-state size is thus bounded by the number of a DID's
//! global spending UCANs revoked within the last ~24 hours, together with the
//! trusted-local-caller self-governance model (only the payer can revoke a
//! global-scope token — §19.5).
//!
//! **What is bounded (durable store AND in-memory cache).** The expiry-GC above
//! bounds the DURABLE store. The paid-action gate, however, reads an in-memory
//! `ArcSwap` cache, not the durable store. That cache is kept bounded too: it is
//! wholesale re-loaded (already-moot entries dropped) on hydration, and on the
//! INCREMENTAL path a global revocation RE-DERIVES the affected DID's cache entry
//! from the freshly-pruned durable store via
//! [`load_for_did`](RevokedSpendingUcanStore::load_for_did) rather than
//! blind-inserting — so the cache entry equals the DID's bounded durable set
//! after every revocation, instead of growing monotonically until restart
//! (invariant 2a). A DID that stops revoking retains its last-derived (already
//! bounded) entry until the next hydration; the number of *distinct* payer DIDs
//! is the trusted-local self-governance model's own bound.
//!
//! This expiry-GC bound applies to **this global store only**. The per-context
//! Class-S `revoked_spending_ucan_cids` set (context-scoped revocations) is
//! **convergent governance state** — it converges to context members via the
//! append-only `SpendingUcanRevoked` leaf and is covered by the signed export
//! digest (§23.16.8) — so it is deliberately NOT time-GC'd: lazy per-instance
//! expiry pruning would diverge members' sets and break export-digest
//! convergence, and could not shrink the set below the immutable convergent
//! log. Its growth is bounded by the scope-matched authorization model
//! (issuer or scope-context creator only — SCP-ECON-12067) instead (spec §19.5).

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
    ///
    /// **Upgrade default = RETAIN (`u64::MAX`), not GC.** A record written by an
    /// older build (or a partially-written/legacy record) that LACKS this field
    /// deserializes to `u64::MAX` — "never moot" — via
    /// [`retain_forever_moot_after`], so it SURVIVES rather than being dropped on
    /// sight. Fail-closed (spec §19.5): forgetting a revocation (fail-OPEN) is the
    /// dangerous direction; retaining one longer than strictly necessary is
    /// harmless — the revoked token's own ≤24h expiry (§9.5) still bounds the
    /// blast radius, and the next `record`/`load_all` that carries a real moot
    /// time prunes it. Defaulting to `0` would have made such a legacy record
    /// GC-eligible immediately, silently forgetting a still-live revocation.
    #[serde(default = "retain_forever_moot_after")]
    revocation_moot_after_secs: u64,
}

/// `#[serde(default)]` provider for
/// [`RevokedSpendingUcanRecord::revocation_moot_after_secs`]: a record missing
/// the field is treated as "never moot" (`u64::MAX`) so it is RETAINED, never
/// GC'd on sight (spec §19.5 fail-closed — see the field doc).
const fn retain_forever_moot_after() -> u64 {
    u64::MAX
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

    /// Loads a SINGLE DID's still-relevant revoked global spending-UCAN CIDs (the
    /// bounded, expiry-GC'd durable set), pruning that DID's already-moot entries
    /// as it goes.
    ///
    /// Used to RE-DERIVE that DID's in-memory cache entry after a global
    /// revocation (invariant 2a, spec §19.5): the incremental cache update must
    /// mirror the freshly-pruned durable store rather than blind-insert, so the
    /// cache stays bounded (== the durable set) instead of growing monotonically
    /// until the next restart's full hydration. Scoped to the DID's own
    /// `identity/{did}/revoked_spending_ucans/` prefix — cheaper than a full
    /// `identity/`-wide [`Self::load_all_revoked_spending_ucans`] scan on every
    /// revocation.
    ///
    /// # Errors
    ///
    /// [`StoreError::Storage`] if the underlying list/read/delete fails.
    pub async fn load_revoked_spending_ucans_for_did(
        &self,
        did: &DID,
        now_secs: u64,
    ) -> Result<HashSet<String>, StoreError> {
        let did_prefix = format!("{}/revoked_spending_ucans/", did_prefix_component(did)?);
        // Prune this DID's already-moot entries first, then read what remains — so
        // the returned set is exactly the bounded durable set.
        self.prune_moot_revoked_spending_ucans(&did_prefix, now_secs)
            .await?;
        let keys = self.storage.list_keys(&did_prefix).await?;
        let mut out = HashSet::new();
        for key in keys {
            if !key.contains(REVOKED_SEGMENT) {
                continue;
            }
            if let Some(record) = self.load_value::<RevokedSpendingUcanRecord>(&key).await?
                && record.revocation_moot_after_secs > now_secs
            {
                out.insert(record.cid);
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

    /// Loads a SINGLE DID's still-relevant revoked global spending-UCAN CIDs
    /// (bounded, expiry-GC'd) — used to RE-DERIVE that DID's in-memory cache entry
    /// after a revocation so the cache mirrors the durable store and stays bounded
    /// (invariant 2a, spec §19.5). Prunes that DID's already-moot entries.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the durable list/read/delete fails.
    async fn load_for_did(&self, did: &DID, now_secs: u64) -> Result<HashSet<String>, StoreError>;
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

    async fn load_for_did(&self, did: &DID, now_secs: u64) -> Result<HashSet<String>, StoreError> {
        self.load_revoked_spending_ucans_for_did(did, now_secs)
            .await
    }
}

// ---------------------------------------------------------------------------
// Fail-closed hydration state (spec §19.5)
// ---------------------------------------------------------------------------

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

/// Shared hydration state of the in-memory GLOBAL-scope spending-UCAN
/// revocation cache (spec §19.5, fail-closed).
///
/// The paid-action gate authorizes a GLOBAL-scope (`scp:spending:*`) spend by
/// consulting the in-memory `global_revoked_spending_cids` cache. That cache is
/// only trustworthy once it has been hydrated from the durable
/// [`RevokedSpendingUcanStore`] at startup. If a configured store is NOT (yet)
/// hydrated — because startup has not run, or its hydration READ failed — the
/// cache may be an empty snapshot that would silently RE-AUTHORIZE a globally
/// revoked token (fail-OPEN). This flag lets the gate distinguish "the empty set
/// is authoritative" from "we do not yet know the revoked set" and fail closed
/// in the latter case.
///
/// Cheaply cloneable (`Arc<AtomicU8>`): the supervisor holds the writer and
/// clones a reader into every actor's [`ActorDeps`](crate::context::actor::deps::ActorDeps),
/// so a flip to `Hydrated` (or `Failed`) after an actor has already spawned is
/// observed by that actor's gate — the state is shared, not snapshotted.
///
/// **Context-scoped spends are UNAFFECTED** by this flag: their revocations live
/// in the per-context Class-S `revoked_spending_ucan_cids` set restored with the
/// context snapshot, not this global-store hydration.
#[derive(Clone)]
pub struct GlobalRevocationHydration {
    state: Arc<AtomicU8>,
}

impl GlobalRevocationHydration {
    /// No durable global-scope revocation store is configured on this instance —
    /// the global revoked set is empty BY CONSTRUCTION and there is nothing to
    /// hydrate, so GLOBAL-scope spends are NOT gated on hydration.
    const NOT_CONFIGURED: u8 = 0;
    /// A store IS configured but hydration has not completed successfully yet
    /// (startup not run, or a create/join happened before `restore_on_startup`).
    /// GLOBAL-scope spends fail closed — the revoked set is unknown.
    const NEEDS_HYDRATION: u8 = 1;
    /// Hydration completed successfully — the cache reflects the durable store.
    const HYDRATED: u8 = 2;
    /// Hydration was attempted and FAILED (store read error). GLOBAL-scope spends
    /// fail closed until a successful re-hydration.
    const FAILED: u8 = 3;

    fn with_state(state: u8) -> Self {
        Self {
            state: Arc::new(AtomicU8::new(state)),
        }
    }

    /// Construct in the [`Self::NOT_CONFIGURED`] state — no durable store wired.
    #[must_use]
    pub fn not_configured() -> Self {
        Self::with_state(Self::NOT_CONFIGURED)
    }

    /// Construct in the [`Self::NEEDS_HYDRATION`] state — a durable store IS wired
    /// but has not been hydrated yet, so GLOBAL-scope spends fail closed until
    /// [`Self::mark_hydrated`].
    #[must_use]
    pub fn needs_hydration() -> Self {
        Self::with_state(Self::NEEDS_HYDRATION)
    }

    /// Transition to [`Self::NEEDS_HYDRATION`] — a durable store was wired after
    /// construction (the supervisor is already behind an `Arc`, so this interior
    /// mutation flips the shared default `NotConfigured` without reassigning the
    /// field). Idempotent store.
    pub fn mark_needs_hydration(&self) {
        self.state.store(Self::NEEDS_HYDRATION, Ordering::SeqCst);
    }

    /// Record a successful hydration — the cache now reflects the durable store.
    pub fn mark_hydrated(&self) {
        self.state.store(Self::HYDRATED, Ordering::SeqCst);
    }

    /// Record a FAILED hydration — the cache is untrustworthy; GLOBAL-scope
    /// spends fail closed until a subsequent successful hydration.
    pub fn mark_failed(&self) {
        self.state.store(Self::FAILED, Ordering::SeqCst);
    }

    /// `true` iff the global revoked-CID cache may be trusted for a fail-OPEN
    /// (permit) decision on a GLOBAL-scope spend: either no durable store is
    /// configured (empty set is authoritative by construction) or a configured
    /// store hydrated successfully. `false` while a configured store is
    /// un-hydrated or its hydration failed — the gate MUST fail closed for
    /// GLOBAL-scope spending UCANs in that case (spec §19.5).
    #[must_use]
    pub fn status_known(&self) -> bool {
        let s = self.state.load(Ordering::SeqCst);
        s == Self::NOT_CONFIGURED || s == Self::HYDRATED
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

    /// `load_for_did` (invariant 2a) returns ONLY the DID's still-relevant CIDs,
    /// pruning already-moot entries — the bounded set used to RE-DERIVE the
    /// in-memory cache so it mirrors the durable store rather than growing.
    #[tokio::test]
    async fn load_for_did_returns_bounded_set_and_prunes_moot() {
        let repo = repo();
        let d1 = did("did:dht:z6MkAlice");
        let d2 = did("did:dht:z6MkBob");
        // d1: one moot (≤1000), one live (≤9000). d2: one live — must NOT leak.
        repo.record_revoked_spending_ucan(&d1, "d1-moot", 1_000, 500)
            .await
            .unwrap();
        repo.record_revoked_spending_ucan(&d1, "d1-live", 9_000, 500)
            .await
            .unwrap();
        repo.record_revoked_spending_ucan(&d2, "d2-live", 9_000, 500)
            .await
            .unwrap();

        // Re-derive d1 at t=2000: the moot entry is dropped, the live one kept,
        // and d2's CID never appears.
        let d1_set = repo
            .load_revoked_spending_ucans_for_did(&d1, 2_000)
            .await
            .unwrap();
        assert_eq!(
            d1_set,
            HashSet::from(["d1-live".to_owned()]),
            "load_for_did must return only the DID's still-relevant CIDs (bounded), pruning moot"
        );
        // The moot entry is durably pruned; the live one survives.
        assert!(!repo.is_revoked_spending_ucan(&d1, "d1-moot").await.unwrap());
        assert!(repo.is_revoked_spending_ucan(&d1, "d1-live").await.unwrap());
        assert!(repo.is_revoked_spending_ucan(&d2, "d2-live").await.unwrap());
    }

    /// A record written WITHOUT `revocation_moot_after_secs` (an older-build /
    /// legacy record) must deserialize with the RETAIN default (`u64::MAX`) so it
    /// is NOT GC'd on sight — fail-closed upgrade (spec §19.5, invariant 1b).
    #[tokio::test]
    async fn legacy_record_without_moot_field_is_retained_not_dropped() {
        // Simulate a record written by an older build: the on-disk value has NO
        // `revocation_moot_after_secs` field. `store_value` over serde_json must
        // round-trip through the `#[serde(default = ...)]` retain default.
        #[derive(serde::Serialize)]
        struct LegacyRecord<'a> {
            did: &'a str,
            cid: &'a str,
        }
        let repo = repo();
        let d = did("did:dht:z6MkPayer");
        let key = revoked_spending_ucan_key(&d, "legacy-cid").unwrap();
        repo.store_value(
            &key,
            &LegacyRecord {
                did: d.as_ref(),
                cid: "legacy-cid",
            },
        )
        .await
        .unwrap();

        // Hydrate FAR in the future: a `0` default would GC this immediately; the
        // `u64::MAX` retain default keeps it.
        let all = repo
            .load_all_revoked_spending_ucans(u64::MAX - 1)
            .await
            .unwrap();
        assert_eq!(
            all.get(&d).map(|s| s.contains("legacy-cid")),
            Some(true),
            "a legacy record lacking the moot field must be RETAINED (retain-on-upgrade default), not GC'd on sight"
        );
    }

    /// The fail-closed hydration flag (spec §19.5, invariant 1a): only
    /// `NotConfigured` and `Hydrated` are "status known" (gate may fail open);
    /// `NeedsHydration` and `Failed` are unknown (gate must fail closed).
    #[test]
    fn hydration_flag_status_known_transitions() {
        let not_configured = GlobalRevocationHydration::not_configured();
        assert!(
            not_configured.status_known(),
            "no store configured ⇒ empty set is authoritative ⇒ status known"
        );

        let flag = GlobalRevocationHydration::needs_hydration();
        assert!(
            !flag.status_known(),
            "a configured-but-un-hydrated store ⇒ status UNKNOWN ⇒ fail closed"
        );
        flag.mark_hydrated();
        assert!(flag.status_known(), "successful hydration ⇒ status known");
        flag.mark_failed();
        assert!(
            !flag.status_known(),
            "a FAILED hydration ⇒ status UNKNOWN ⇒ fail closed"
        );

        // The reader shares state with the writer (Arc), so a clone observes a
        // later transition — the property the actor-gate wiring relies on.
        let reader = flag.clone();
        flag.mark_hydrated();
        assert!(
            reader.status_known(),
            "a cloned reader must observe the writer's later mark_hydrated"
        );
    }
}
