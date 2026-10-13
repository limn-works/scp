//! Trust input aggregation and `TrustProtocolRepository` integration.
//!
//! [`aggregate_trust_input`] combines all trust engine layers into a single
//! [`TrustInput`] struct for agent-level evaluation. The trust engine does not
//! produce trust "scores" -- each agent applies its own criteria to the
//! aggregated inputs.
//!
//! # `TrustProtocolRepository` integration
//!
//! [`TrustProtocolRepository`] caches verified attestations with TTL-based refresh,
//! stores revocation list state per context, and persists challenge results
//! with timestamps. This avoids redundant verification work across trust
//! evaluations.
//!
//! # Attestation cache
//!
//! [`AttestationCache`] provides TTL-based caching for verified attestations.
//! Entries are refreshed when their TTL expires, avoiding repeated signature
//! verification and DID resolution for recently-verified attestations.
//!
//! See ADR-017 acceptance criteria 9-10 in `.docs/adrs/phase-4.md`.

use std::collections::{HashMap, HashSet};

use scp_clock::Clock;
use scp_did::DID;
use scp_event_log::Event;

use super::attestation::{
    Attestation, AttestationRevocationChecker, AttestorInfo, DidPublicKeyResolver, FreshnessStatus,
    ThresholdCheckInput, ThresholdRequirement, check_attestation_freshness,
    check_threshold_attestation, verify_attestation,
};
use super::challenge::{ChallengeVerification, verify_challenge_verification};
use super::consequence::ConsequenceRule;
use super::participation::compute_participation_record;
use super::{AttestationType, TrustError, TrustInput};

// ---------------------------------------------------------------------------
// TrustProtocolRepository
// ---------------------------------------------------------------------------

/// Persistent store for trust engine data.
///
/// Caches verified attestations with TTL-based refresh, stores revocation list
/// state per context, and persists challenge results with timestamps. All
/// methods take `&self` for interior mutability (implementations use interior
/// locking or cell types as appropriate).
///
/// See ADR-017 acceptance criterion 10.
pub trait TrustProtocolRepository: Send + Sync {
    /// Retrieves cached verified attestations for a subject DID within a
    /// context. Returns all cached entries including expired ones —
    /// callers (e.g., `AttestationCache`) handle expiry and re-verification.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError`] if the store is unavailable or corrupt.
    fn get_cached_attestations(
        &self,
        context_id: &str,
        subject_did: &str,
    ) -> Result<Vec<CachedAttestation>, TrustError>;

    /// Stores an ALREADY-VERIFIED attestation in the cache with a TTL.
    ///
    /// An entry replaces only an entry that carries the same issuer AND the same
    /// attestation id, the pair [`revocation_list_key`] joins. §7.4.1 of
    /// `.docs/specs/07-trust-validation-and-capabilities.md` binds
    /// `Attestation.id` to no issuer, so two issuers can carry one id, and an
    /// implementation that replaced on id alone would let an attacker who mints
    /// a DID at no cost overwrite an honest issuer's cached attestation by
    /// signing one that carries its id.
    ///
    /// SECURITY: this is a raw write that performs NO verification — the caller
    /// is asserting the attestation was verified at `entry.verified_at`. It is
    /// therefore NOT a safe ingest boundary for caller-controlled data: feeding
    /// it an attestation whose `verified_at`/`ttl_secs` came from an untrusted
    /// caller lets a forged attestation masquerade as "freshly verified" and be
    /// returned unverified by [`AttestationCache::get_verified_attestations`].
    /// Untrusted attestations MUST instead go through
    /// [`AttestationCache::verify_and_cache`], which verifies the signature,
    /// expiry, and revocation against the resolver-resolved issuer key and stamps
    /// a trusted `verified_at` before calling this method.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError`] if the store write fails.
    fn store_cached_attestation(
        &self,
        context_id: &str,
        entry: CachedAttestation,
    ) -> Result<(), TrustError>;

    /// Retrieves the revocation list state for a context.
    ///
    /// Returns a map whose key [`revocation_list_key`] builds from an issuer DID
    /// plus an attestation id, and whose value reports whether that issuer
    /// revoked that attestation (true = revoked). Every record
    /// [`add_revocations`](Self::add_revocations) writes, the only writer this
    /// trait offers, reads back as true. A caller MUST build every key
    /// it reads or writes with [`revocation_list_key`]; a bare attestation id is
    /// not a key, because §7.4.1 of
    /// `.docs/specs/07-trust-validation-and-capabilities.md` binds
    /// `Attestation.id` to no issuer.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError`] if the store is unavailable.
    fn get_revocation_state(&self, context_id: &str) -> Result<HashMap<String, bool>, TrustError>;

    /// Records each entry in `entries` as a revocation for a context, leaving
    /// every record this call does not name as it was, after pruning the
    /// records that can no longer change a verification.
    ///
    /// Each `list_key` comes from [`revocation_list_key`]. Passing an empty
    /// slice writes nothing and prunes nothing.
    ///
    /// An implementation applies [`plan_revocation_write`] to its current
    /// records and `entries` and carries out the plan that function returns:
    /// it deletes each pruned record and writes each new record. Spec 07
    /// §7.4.4 states no size bound for the list, so neither the plan nor the
    /// store refuses a write by count.
    ///
    /// SECURITY (lost update). An implementation MUST NOT lose a revocation that
    /// a concurrent caller on the same context recorded. Reading a whole map,
    /// inserting into a local copy, and writing that copy back does lose one:
    /// two callers that both read `{}` and then write `{p}` and `{q}` leave one
    /// of `p` and `q` durable and drop the other, and a dropped revocation means
    /// a revoked attestation counts again. An implementation therefore either
    /// holds one lock across its own read and write (which serializes callers
    /// inside one process only), or writes each key independently so no write
    /// carries a stale copy of another key (which holds across processes too).
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::StoreError`] if a store read or write fails.
    fn add_revocations(
        &self,
        context_id: &str,
        entries: &[RevocationEntry],
        now: u64,
    ) -> Result<(), TrustError>;

    /// Retrieves persisted challenge results for a subject DID within a
    /// context.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError`] if the store is unavailable.
    fn get_challenge_results(
        &self,
        context_id: &str,
        subject_did: &str,
    ) -> Result<Vec<ChallengeVerification>, TrustError>;

    /// Persists a challenge result with its timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError`] if the store write fails.
    fn store_challenge_result(
        &self,
        context_id: &str,
        result: &ChallengeVerification,
    ) -> Result<(), TrustError>;
}

// ---------------------------------------------------------------------------
// Revocation list key
// ---------------------------------------------------------------------------

/// Builds the key under which a context's persisted revocation list records one
/// issuer's revocation of one attestation id.
///
/// SECURITY (cross-issuer suppression, issue #2335 finding 13). §7.4.1 of
/// `.docs/specs/07-trust-validation-and-capabilities.md` describes
/// `Attestation.id` as a UUID v4 that an issuer chooses, and states no rule
/// deriving that id from its issuer, so two issuers can carry one id. A
/// revocation list keyed on an id alone therefore lets an attacker suppress an
/// honest issuer's attestation: the attacker mints a fresh DID at no cost
/// (`IdentityDidPublicKeyResolver` reads a public key out of a DID string, so no
/// publication gates it), signs an attestation that carries the honest issuer's
/// id and revokes itself, and a consumer that ingests that record drops every
/// later copy of the honest issuer's attestation. Keying on issuer DID plus id
/// confines a revocation to the issuer who signed it.
///
/// The issuer's byte length precedes the issuer, so two distinct
/// `(issuer, attestation_id)` pairs never produce one key: a reader recovers the
/// issuer boundary from that leading length, and no character a caller embeds in
/// either field moves that boundary. A separator alone would not hold, because a
/// caller chooses both an issuer DID and an attestation id and could embed the
/// separator in either one.
#[must_use]
pub fn revocation_list_key(issuer: &DID, attestation_id: &str) -> String {
    let issuer: &str = issuer.as_ref();
    format!("{}:{issuer}:{attestation_id}", issuer.len())
}

// ---------------------------------------------------------------------------
// Revocation records
// ---------------------------------------------------------------------------

/// One revocation a caller asks [`TrustProtocolRepository::add_revocations`]
/// to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationEntry {
    /// The key [`revocation_list_key`] built from the revoking issuer and the
    /// revoked attestation's id.
    pub list_key: String,
    /// The revoked attestation's own `expires_at`. Once it passes, step 3 of
    /// [`verify_attestation`] rejects every copy of that attestation, so the
    /// record can no longer change a verification and is pruned. `None` means
    /// the attestation never expires, and its record is never pruned.
    pub expires_at: Option<u64>,
}

impl RevocationEntry {
    /// Builds the entry that records `attestation`'s issuer revoking it.
    #[must_use]
    pub fn for_attestation(attestation: &Attestation) -> Self {
        Self {
            list_key: revocation_list_key(&attestation.issuer, &attestation.id),
            expires_at: attestation.expires_at,
        }
    }

    /// Reports whether this record can no longer change a verification at
    /// `now`. Matches step 3 of [`verify_attestation`], which rejects when
    /// `expires_at < now`.
    #[must_use]
    pub fn is_moot(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|expires_at| expires_at < now)
    }
}

/// What [`plan_revocation_write`] tells a store to do.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RevocationWritePlan {
    /// The list keys of existing records to delete, each moot at `now`.
    pub prune: Vec<String>,
    /// The new records to write, each absent from the kept records and listed
    /// once.
    pub write: Vec<RevocationEntry>,
}

/// Decides how one [`TrustProtocolRepository::add_revocations`] call changes a
/// context's revocation records, so every store applies one rule.
///
/// `existing` lists every record the context holds. The plan prunes each
/// existing record that [`RevocationEntry::is_moot`] reports moot at `now`,
/// and skips each new entry that is moot, that the kept records already hold,
/// or that this call already listed. Pruning a moot record loses nothing,
/// because step 3 of [`verify_attestation`] rejects an expired attestation
/// before step 5 reads the list. The plan refuses no write by count: spec 07
/// §7.4.4 states no size bound for the list.
#[must_use]
pub fn plan_revocation_write(
    existing: &[RevocationEntry],
    entries: &[RevocationEntry],
    now: u64,
) -> RevocationWritePlan {
    let mut plan = RevocationWritePlan::default();
    if entries.is_empty() {
        return plan;
    }
    let mut held: HashSet<&str> = HashSet::with_capacity(existing.len());
    for record in existing {
        if record.is_moot(now) {
            plan.prune.push(record.list_key.clone());
        } else {
            held.insert(record.list_key.as_str());
        }
    }
    for entry in entries {
        if entry.is_moot(now) || !held.insert(entry.list_key.as_str()) {
            continue;
        }
        plan.write.push(entry.clone());
    }
    plan
}

// ---------------------------------------------------------------------------
// RevocationMapChecker
// ---------------------------------------------------------------------------

/// [`AttestationRevocationChecker`] backed by a context's persisted revocation
/// list.
///
/// The list is an `issuer + attestation_id -> revoked` map from
/// [`TrustProtocolRepository::get_revocation_state`], whose keys
/// [`revocation_list_key`] builds. Every reader of that list builds this one
/// checker: the READ path in [`AttestationCache::get_verified_attestations`],
/// the threshold counts in [`aggregate_trust_input`], and the FFI ingest and
/// verify helpers. A cached
/// attestation that is later context-revoked is therefore dropped on read (even
/// while still inside its cache TTL) rather than continuing to inflate trust
/// until TTL expiry.
pub struct RevocationMapChecker<'a, H = std::collections::hash_map::RandomState> {
    /// `revocation_list_key(issuer, attestation_id) -> revoked` for the context.
    revoked: &'a HashMap<String, bool, H>,
}

impl<'a, H: std::hash::BuildHasher> RevocationMapChecker<'a, H> {
    /// Wraps a map that [`TrustProtocolRepository::get_revocation_state`]
    /// returned.
    #[must_use]
    pub const fn new(revoked: &'a HashMap<String, bool, H>) -> Self {
        Self { revoked }
    }
}

impl<H: std::hash::BuildHasher> AttestationRevocationChecker for RevocationMapChecker<'_, H> {
    fn check_revocation(&self, attestation_id: &str, issuer: &DID) -> Option<u64> {
        // The list stores only a boolean per key (no timestamp); report `0` as
        // the revocation time when listed. That value only populates a
        // dropped-entry log line, not a user-facing field. The key carries the
        // issuer, so one issuer's revocation never reaches another issuer's
        // attestation that carries the same id.
        if self
            .revoked
            .get(&revocation_list_key(issuer, attestation_id))
            .copied()
            .unwrap_or(false)
        {
            Some(0)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// CachedAttestation
// ---------------------------------------------------------------------------

/// A verified attestation stored in the cache with TTL metadata.
///
/// The `verified_at` timestamp records when the attestation was last verified.
/// The `ttl_secs` field determines when the cache entry should be refreshed.
/// An entry is considered expired when `verified_at + ttl_secs < now`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CachedAttestation {
    /// The verified attestation.
    pub attestation: Attestation,

    /// Unix timestamp (seconds) when the attestation was last verified.
    pub verified_at: u64,

    /// Time-to-live in seconds. The cache entry should be refreshed when
    /// `verified_at + ttl_secs < now`.
    pub ttl_secs: u64,
}

impl CachedAttestation {
    /// Returns `true` if this cache entry has expired (needs refresh).
    #[must_use]
    pub const fn is_expired(&self, now: u64) -> bool {
        now > self.verified_at.saturating_add(self.ttl_secs)
    }
}

// ---------------------------------------------------------------------------
// AttestationCache
// ---------------------------------------------------------------------------

/// Default TTL for cached attestations: 5 minutes.
const DEFAULT_ATTESTATION_TTL_SECS: u64 = 5 * 60;

/// In-memory attestation cache with TTL-based refresh.
///
/// Wraps a [`TrustProtocolRepository`] and provides TTL-aware attestation retrieval.
/// When cached entries are fresh, they are returned directly. When expired,
/// attestations are re-verified and the cache is updated.
///
/// See ADR-017 acceptance criterion 10.
pub struct AttestationCache<S> {
    /// The backing store for persisted cache entries.
    store: S,

    /// TTL in seconds for new cache entries.
    ttl_secs: u64,
}

impl<S: TrustProtocolRepository> AttestationCache<S> {
    /// Creates a new attestation cache with the default TTL.
    #[must_use]
    pub const fn new(store: S) -> Self {
        Self {
            store,
            ttl_secs: DEFAULT_ATTESTATION_TTL_SECS,
        }
    }

    /// Creates a new attestation cache with a custom TTL.
    #[must_use]
    pub const fn with_ttl(store: S, ttl_secs: u64) -> Self {
        Self { store, ttl_secs }
    }

    /// Retrieves verified attestations for a subject, refreshing expired entries.
    ///
    /// For each cached attestation:
    /// - If the cache entry is fresh, the attestation is returned as-is.
    /// - If the cache entry is expired, the attestation is re-verified. If
    ///   verification succeeds, the cache entry is updated. If verification
    ///   fails (expired, revoked, bad signature), the entry is discarded.
    ///
    /// SECURITY: returning fresh entries WITHOUT re-verification is sound only
    /// because `verified_at` is a TRUSTED stamp — it is set exclusively by
    /// [`Self::verify_and_cache`] AFTER a successful signature/expiry/revocation
    /// check (and re-stamped here after a successful re-verification). The cache
    /// invariant is therefore "fresh ⟹ verified within TTL". Callers MUST NOT
    /// populate the backing store with caller-controlled `verified_at` via the
    /// raw [`TrustProtocolRepository::store_cached_attestation`]; untrusted
    /// attestations are ingested through [`Self::verify_and_cache`] (see the FFI
    /// `verified_attestations` / `populate_and_aggregate` helpers), which is what
    /// keeps a forged, freshly-marked entry from ever being returned here.
    ///
    /// SECURITY (read-path revocation): the cached-but-fresh invariant says
    /// nothing about revocations that happen AFTER an entry is cached. The
    /// signature/expiry stamp does not capture a later context revocation. This
    /// method therefore consults the context revocation list
    /// ([`TrustProtocolRepository::get_revocation_state`]) on EVERY read and
    /// drops any revoked entry on BOTH the fresh-return path and the stale
    /// re-verification path. Without this, a cached attestation that is later
    /// context-revoked would keep inflating `attestation_count` / trust until its
    /// cache TTL expired (fail-open). The lookup is O(1) per entry.
    ///
    /// SECURITY (read-path attestation expiry): the cache TTL is independent of
    /// the attestation's own `expires_at`. A cache TTL longer than the
    /// attestation's remaining lifetime would otherwise return a still-fresh
    /// cache entry whose underlying attestation has already expired. The
    /// fresh-return path therefore ALSO drops any entry whose
    /// `attestation.expires_at` is `Some(t)` with `t < now`, matching the stale
    /// path (where re-verification rejects expired attestations).
    ///
    /// # Errors
    ///
    /// Returns [`TrustError`] if the store is unavailable or a verification
    /// step fails in an unexpected way.
    pub fn get_verified_attestations(
        &self,
        context_id: &str,
        subject_did: &str,
        resolver: &impl DidPublicKeyResolver,
        clock: &impl Clock,
    ) -> Result<Vec<Attestation>, TrustError> {
        let cached = self
            .store
            .get_cached_attestations(context_id, subject_did)?;
        let now = clock.now_secs();

        // Build the context revocation checker once; applied to every entry on
        // both the fresh and stale paths so a post-cache revocation is honored.
        let revoked = self.store.get_revocation_state(context_id)?;
        let revocation_checker = RevocationMapChecker::new(&revoked);

        let mut result = Vec::new();

        for entry in cached {
            if entry.is_expired(now) {
                // Re-verify the attestation, consulting the context revocation
                // list. `.is_ok()` keeps the entry only on success; a non-Ok
                // result — a verification rejection (bad signature / expired /
                // context-revoked) OR a resolver infra fault — drops this one
                // entry. This is conservative (it can only drop, never inflate)
                // and is sound here because the injected `resolver` is total and
                // pure (`IdentityDidPublicKeyResolver`: a deterministic DID-string
                // parse, no network), so no transient fault can spuriously drop a
                // valid entry. A future networked/fallible resolver swap MUST
                // revisit this to separate rejections from infra faults.
                if verify_attestation(&entry.attestation, resolver, clock, &revocation_checker)
                    .is_ok()
                {
                    // Update cache with new verified_at.
                    let refreshed = CachedAttestation {
                        attestation: entry.attestation.clone(),
                        verified_at: now,
                        ttl_secs: self.ttl_secs,
                    };
                    self.store.store_cached_attestation(context_id, refreshed)?;
                    result.push(entry.attestation);
                }
                // On any non-Ok result the entry is dropped (see note above).
            } else if revocation_checker
                .check_revocation(&entry.attestation.id, &entry.attestation.issuer)
                .is_none()
                && entry.attestation.expires_at.is_none_or(|exp| exp >= now)
            {
                // Fresh entry: still within cache TTL, but drop it if it has
                // since been context-revoked OR if the attestation's own
                // `expires_at` has passed. A cache TTL longer than the
                // attestation's lifetime would otherwise keep returning an
                // expired credential until the cache entry itself expired
                // (read-path fail-open).
                result.push(entry.attestation);
            }
        }

        Ok(result)
    }

    /// Verifies a new attestation against `revocation_checker` and, if valid,
    /// stores it in the cache with the current timestamp and configured TTL.
    ///
    /// An attestation that is validly signed but that `revocation_checker`
    /// reports revoked is rejected, so it is neither cached nor counted.
    /// `revocation_checker` is required for the reason [`verify_attestation`]
    /// requires it.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError`] if verification or caching fails.
    pub fn verify_and_cache(
        &self,
        context_id: &str,
        attestation: &Attestation,
        resolver: &impl DidPublicKeyResolver,
        clock: &impl Clock,
        revocation_checker: &dyn AttestationRevocationChecker,
    ) -> Result<(), TrustError> {
        verify_attestation(attestation, resolver, clock, revocation_checker)?;

        let entry = CachedAttestation {
            attestation: attestation.clone(),
            verified_at: clock.now_secs(),
            ttl_secs: self.ttl_secs,
        };
        self.store.store_cached_attestation(context_id, entry)?;

        Ok(())
    }

    /// Returns a reference to the backing store.
    #[must_use]
    pub const fn store(&self) -> &S {
        &self.store
    }
}

// ---------------------------------------------------------------------------
// AggregationContext
// ---------------------------------------------------------------------------

/// Input parameters for trust input aggregation.
///
/// Collects all the references needed by [`aggregate_trust_input`] into a
/// single struct to avoid a large parameter list.
pub struct AggregationContext<'a, S, R, C> {
    /// The context ID to aggregate trust inputs for.
    pub context_id: &'a str,

    /// The subject DID to evaluate.
    pub subject_did: &'a str,

    /// Event log entries for the context. Used for participation record
    /// computation and consequence evaluation.
    pub events: &'a [Event],

    /// Merkle root of the event log at computation time.
    pub merkle_root: [u8; 32],

    /// Consequence rules declared at context creation.
    pub consequence_rules: &'a [ConsequenceRule],

    /// Threshold requirements per attestation type. If a type is present,
    /// the threshold check is performed and included in `threshold_counts`.
    pub threshold_requirements: &'a HashMap<AttestationType, ThresholdRequirement>,

    /// Attestor information for threshold checks. Keyed by attestation type.
    pub attestor_sets: &'a HashMap<AttestationType, Vec<AttestorInfo>>,

    /// The attestation cache (with backing store).
    pub cache: &'a AttestationCache<S>,

    /// DID public key resolver for attestation verification.
    pub resolver: &'a R,

    /// DID public key resolver for re-verifying stored challenge results.
    /// It resolves the verifier's `#active` key, which an attestation
    /// resolver need not cover.
    pub challenge_resolver: &'a dyn DidPublicKeyResolver,

    /// Clock for timestamp operations.
    pub clock: &'a C,
}

// ---------------------------------------------------------------------------
// aggregate_trust_input
// ---------------------------------------------------------------------------

/// Aggregates all trust engine layers into a single [`TrustInput`] for
/// agent-level evaluation.
///
/// This function:
/// 1. Computes the participation record from the event log.
/// 2. Collects and verifies attestations from the cache (with TTL-based
///    refresh).
/// 3. Collects challenge results with timestamps from the store.
/// 4. Collects consequence structure from context parameters.
/// 5. Computes threshold counts per attestation type.
///
/// # Errors
///
/// Returns [`TrustError`] if participation record computation fails or if the
/// backing store is unavailable.
///
/// See ADR-017 acceptance criterion 9.
pub fn aggregate_trust_input<S, R, C>(
    ctx: &AggregationContext<'_, S, R, C>,
) -> Result<TrustInput, TrustError>
where
    S: TrustProtocolRepository,
    R: DidPublicKeyResolver,
    C: Clock,
{
    // 1. Collect and verify attestations from cache. Computed BEFORE the
    //    participation record because `attestation_count` is a credential-layer
    //    fact (§7.4) sourced from these — the record needs the subject's
    //    accessible, currently-valid attestations as input.
    let verified_attestations = ctx.cache.get_verified_attestations(
        ctx.context_id,
        ctx.subject_did,
        ctx.resolver,
        ctx.clock,
    )?;

    // 2. Compute participation record from the event log, threading the
    //    verified attestations in for the credential-layer `attestation_count`.
    let participation_record = compute_participation_record(
        ctx.events,
        ctx.subject_did,
        ctx.context_id,
        ctx.merkle_root,
        ctx.clock.now_secs(),
        &verified_attestations,
    )?;

    // 3. Collect challenge results with timestamps from the store, RE-VALIDATING
    //    each on read. The store is persistent (SQLCipher), so a challenge result
    //    that was valid at ingest is otherwise served as a CURRENT trust signal
    //    forever — even after its `expires_at` passes (read-path fail-open). Re-
    //    run the same verify-on-ingest gate (`verify_challenge_verification`:
    //    verifier signature + context binding + subject binding + expiry) against
    //    the target context, subject, and current clock, dropping any result that
    //    no longer verifies. Mirrors the attestation read path
    //    ([`AttestationCache::get_verified_attestations`]), which likewise re-
    //    validates persisted entries on every read.
    //
    //    Only a rejection of the record itself
    //    ([`TrustError::is_record_rejection`]) drops it. Any other failure, such
    //    as a resolver outage, propagates: dropping a valid record on a
    //    transient fault would silently zero the subject's challenge signal.
    let stored = ctx
        .cache
        .store()
        .get_challenge_results(ctx.context_id, ctx.subject_did)?;
    let mut challenge_results: Vec<ChallengeVerification> = Vec::with_capacity(stored.len());
    for cv in stored {
        match verify_challenge_verification(
            &cv,
            ctx.challenge_resolver,
            ctx.context_id,
            ctx.subject_did,
            ctx.clock,
        ) {
            Ok(()) => challenge_results.push(cv),
            Err(e) if e.is_record_rejection() => {}
            Err(e) => return Err(e),
        }
    }

    // 4. Consequence structure comes directly from context params.
    let consequence_structure: Vec<ConsequenceRule> = ctx.consequence_rules.to_vec();

    // 5. Compute threshold counts per attestation type. The context revocation
    //    list reaches the threshold check for the same reason it reaches
    //    `get_verified_attestations`: an endorsement revoked after its issuer
    //    signed it must stop counting toward a threshold on the next read.
    let revoked = ctx.cache.store().get_revocation_state(ctx.context_id)?;
    let revocation_checker = RevocationMapChecker::new(&revoked);
    let threshold_counts = compute_threshold_counts(ctx, &revocation_checker);

    Ok(TrustInput {
        verified_attestations,
        participation_record,
        challenge_results,
        consequence_structure,
        threshold_counts,
    })
}

// ---------------------------------------------------------------------------
// Threshold count computation
// ---------------------------------------------------------------------------

/// Computes threshold counts `(met, required)` per attestation type.
///
/// For each attestation type with a threshold requirement, runs
/// [`check_threshold_attestation`] against the caller-supplied attestor set and
/// records `(valid_count, required_count)`. `check_threshold_attestation`
/// applies its own admission rules — subject binding, issuer binding,
/// signature verification, and DID deduplication — so `attestor_sets` reaches
/// the count as raw candidates and never as a pre-approved tally.
fn compute_threshold_counts<S, R, C>(
    ctx: &AggregationContext<'_, S, R, C>,
    revocation_checker: &dyn AttestationRevocationChecker,
) -> HashMap<AttestationType, (u32, u32)>
where
    S: TrustProtocolRepository,
    R: DidPublicKeyResolver,
    C: Clock,
{
    let mut counts = HashMap::new();
    let subject_did = DID::from(ctx.subject_did);

    for (att_type, requirement) in ctx.threshold_requirements {
        let attestors = ctx
            .attestor_sets
            .get(att_type)
            .map_or(&[] as &[AttestorInfo], |v| v.as_slice());

        let result = check_threshold_attestation(&ThresholdCheckInput {
            attestation_type: att_type,
            subject_did: &subject_did,
            attestors,
            requirement,
            resolver: ctx.resolver,
            clock: ctx.clock,
            revocation_checker,
        });
        counts.insert(
            att_type.clone(),
            (result.valid_count, result.required_count),
        );
    }

    counts
}

// ---------------------------------------------------------------------------
// Freshness-aware filtering helper
// ---------------------------------------------------------------------------

/// Filters attestations by freshness, returning only fresh or stale
/// attestations (excluding expired ones).
///
/// This is a convenience function for agents that want to exclude expired
/// attestations from their evaluation. Stale attestations are included but
/// can be distinguished by callers using [`check_attestation_freshness`].
#[must_use]
pub fn filter_by_freshness(
    attestations: &[Attestation],
    clock: &impl Clock,
) -> Vec<(Attestation, FreshnessStatus)> {
    attestations
        .iter()
        .filter_map(|att| {
            let freshness = check_attestation_freshness(att, clock);
            match freshness {
                FreshnessStatus::Expired => None,
                status => Some((att.clone(), status)),
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::significant_drop_tightening
)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Duration;

    use super::*;
    use crate::trust::attestation::RevocationStatus;
    use scp_clock::TestClock;
    use scp_event_log::{EventPayload, EventType};

    // -----------------------------------------------------------------------
    // Test helpers: InMemoryTrustStore
    // -----------------------------------------------------------------------

    /// An in-memory implementation of [`TrustProtocolRepository`] for testing.
    struct InMemoryTrustStore {
        attestations: Mutex<HashMap<(String, String), Vec<CachedAttestation>>>,
        /// `list_key -> expires_at` per context.
        revocations: Mutex<HashMap<String, HashMap<String, Option<u64>>>>,
        challenges: Mutex<HashMap<(String, String), Vec<ChallengeVerification>>>,
    }

    impl InMemoryTrustStore {
        fn new() -> Self {
            Self {
                attestations: Mutex::new(HashMap::new()),
                revocations: Mutex::new(HashMap::new()),
                challenges: Mutex::new(HashMap::new()),
            }
        }
    }

    impl TrustProtocolRepository for InMemoryTrustStore {
        fn get_cached_attestations(
            &self,
            context_id: &str,
            subject_did: &str,
        ) -> Result<Vec<CachedAttestation>, TrustError> {
            let store = self
                .attestations
                .lock()
                .map_err(|_| TrustError::InvalidEventData {
                    sequence: 0,
                    reason: "lock poisoned".to_owned(),
                })?;
            let key = (context_id.to_owned(), subject_did.to_owned());
            Ok(store.get(&key).cloned().unwrap_or_default())
        }

        fn store_cached_attestation(
            &self,
            context_id: &str,
            entry: CachedAttestation,
        ) -> Result<(), TrustError> {
            let mut store = self
                .attestations
                .lock()
                .map_err(|_| TrustError::InvalidEventData {
                    sequence: 0,
                    reason: "lock poisoned".to_owned(),
                })?;
            let key = (context_id.to_owned(), entry.attestation.subject.to_string());
            let entries = store.entry(key).or_default();

            // Replace the entry carrying the same issuer AND id, or append.
            if let Some(pos) = entries.iter().position(|e| {
                e.attestation.id == entry.attestation.id
                    && e.attestation.issuer == entry.attestation.issuer
            }) {
                entries[pos] = entry;
            } else {
                entries.push(entry);
            }

            Ok(())
        }

        fn get_revocation_state(
            &self,
            context_id: &str,
        ) -> Result<HashMap<String, bool>, TrustError> {
            let store = self
                .revocations
                .lock()
                .map_err(|_| TrustError::InvalidEventData {
                    sequence: 0,
                    reason: "lock poisoned".to_owned(),
                })?;
            Ok(store
                .get(context_id)
                .map(|records| records.keys().map(|k| (k.clone(), true)).collect())
                .unwrap_or_default())
        }

        fn add_revocations(
            &self,
            context_id: &str,
            entries: &[RevocationEntry],
            now: u64,
        ) -> Result<(), TrustError> {
            // One guard covers the read, the plan, and the writes, so a
            // concurrent caller on this context cannot drop what this call adds.
            let mut store = self
                .revocations
                .lock()
                .map_err(|_| TrustError::InvalidEventData {
                    sequence: 0,
                    reason: "lock poisoned".to_owned(),
                })?;
            let records = store.entry(context_id.to_owned()).or_default();
            let existing: Vec<RevocationEntry> = records
                .iter()
                .map(|(list_key, expires_at)| RevocationEntry {
                    list_key: list_key.clone(),
                    expires_at: *expires_at,
                })
                .collect();
            let plan = plan_revocation_write(&existing, entries, now);
            for list_key in &plan.prune {
                records.remove(list_key);
            }
            for entry in plan.write {
                records.insert(entry.list_key, entry.expires_at);
            }
            Ok(())
        }

        fn get_challenge_results(
            &self,
            context_id: &str,
            subject_did: &str,
        ) -> Result<Vec<ChallengeVerification>, TrustError> {
            let store = self
                .challenges
                .lock()
                .map_err(|_| TrustError::InvalidEventData {
                    sequence: 0,
                    reason: "lock poisoned".to_owned(),
                })?;
            let key = (context_id.to_owned(), subject_did.to_owned());
            Ok(store.get(&key).cloned().unwrap_or_default())
        }

        fn store_challenge_result(
            &self,
            context_id: &str,
            result: &ChallengeVerification,
        ) -> Result<(), TrustError> {
            let mut store = self
                .challenges
                .lock()
                .map_err(|_| TrustError::InvalidEventData {
                    sequence: 0,
                    reason: "lock poisoned".to_owned(),
                })?;
            let key = (context_id.to_owned(), result.subject.to_string());
            store.entry(key).or_default().push(result.clone());
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // Test helpers: TestResolver
    // -----------------------------------------------------------------------

    struct TestResolver {
        keys: HashMap<String, Vec<u8>>,
    }

    impl TestResolver {
        fn new() -> Self {
            Self {
                keys: HashMap::new(),
            }
        }
    }

    impl DidPublicKeyResolver for TestResolver {
        fn resolve_public_key(&self, did: &str) -> Result<Vec<u8>, TrustError> {
            self.keys
                .get(did)
                .cloned()
                .ok_or_else(|| TrustError::AttestationSignatureInvalid {
                    attestation_id: String::new(),
                    reason: format!("DID not found: {did}"),
                })
        }
    }

    // -----------------------------------------------------------------------
    // Test helpers: event and attestation construction
    // -----------------------------------------------------------------------

    fn make_event(
        event_type: EventType,
        actor_did: &str,
        timestamp: u64,
        sequence: u64,
        payload: Vec<u8>,
    ) -> Event {
        Event {
            event_type,
            actor_did: actor_did.into(),
            timestamp,
            sequence,
            payload: EventPayload { data: payload },
            prev_hash: [0u8; 32],
            signature: vec![0u8; 64],
        }
    }

    fn make_attestation(id: &str, subject: &str, att_type: AttestationType) -> Attestation {
        Attestation {
            id: id.to_owned(),
            attestation_type: att_type,
            issuer: "did:key:issuer".into(),
            subject: subject.into(),
            claim: serde_json::json!({"test": true}),
            evidence: None,
            issued_at: 1000,
            expires_at: Some(5000),
            renewal_interval: None,
            revocation_status: RevocationStatus::Active,
            signature: vec![0u8; 64],
            renewed_at: None,
        }
    }

    /// Builds an [`AttestorInfo`] whose attestation `issuer` genuinely signed
    /// about `subject`, and seeds `resolver` with the issuer's public key so
    /// [`check_threshold_attestation`] verifies that signature.
    fn signed_attestor(
        resolver: &mut TestResolver,
        issuer: &str,
        subject: &str,
        attestation_type: AttestationType,
        id: &str,
    ) -> AttestorInfo {
        use ed25519_dalek::Signer;

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        resolver.keys.insert(
            issuer.to_owned(),
            signing_key.verifying_key().to_bytes().to_vec(),
        );

        let mut attestation = Attestation {
            id: id.to_owned(),
            attestation_type,
            issuer: issuer.into(),
            subject: subject.into(),
            claim: serde_json::json!({"test": true}),
            evidence: None,
            issued_at: 1000,
            expires_at: Some(5000),
            renewal_interval: None,
            revocation_status: RevocationStatus::Active,
            signature: vec![],
            renewed_at: None,
        };
        let canonical =
            crate::trust::attestation::canonical_attestation_bytes(&attestation).unwrap();
        attestation.signature = signing_key.sign(&canonical).to_bytes().to_vec();

        AttestorInfo {
            did: issuer.into(),
            context_memberships: std::collections::HashSet::new(),
            endorsements: std::collections::HashSet::new(),
            attestation: Some(attestation),
        }
    }

    /// Runs `aggregate_trust_input` for subject `did:key:alice` over a
    /// single-event log and returns the threshold counts it produced, so each
    /// threshold assertion exercises the shipped caller path. Each entry of
    /// `revoked` names one revocation as `(issuer DID, attestation id)`, which
    /// is what [`revocation_list_key`] turns into a revocation-list key.
    fn threshold_counts_via_aggregate(
        resolver: &TestResolver,
        requirements: &HashMap<AttestationType, ThresholdRequirement>,
        attestor_sets: &HashMap<AttestationType, Vec<AttestorInfo>>,
        revoked: &[(&str, &str)],
    ) -> HashMap<AttestationType, (u32, u32)> {
        let store = InMemoryTrustStore::new();
        let entries: Vec<RevocationEntry> = revoked
            .iter()
            .map(|(issuer, id)| RevocationEntry {
                list_key: revocation_list_key(&DID::from(*issuer), id),
                expires_at: None,
            })
            .collect();
        store.add_revocations("ctx-1", &entries, 2000).unwrap();
        let cache = AttestationCache::new(store);
        let clock = TestClock::new(2000);
        let events = vec![make_event(
            EventType::MessageSent,
            "did:key:alice",
            1000,
            0,
            vec![],
        )];
        let consequence_rules = vec![];

        let ctx = AggregationContext {
            context_id: "ctx-1",
            subject_did: "did:key:alice",
            events: &events,
            merkle_root: [0u8; 32],
            consequence_rules: &consequence_rules,
            threshold_requirements: requirements,
            attestor_sets,
            cache: &cache,
            resolver,
            challenge_resolver: resolver,
            clock: &clock,
        };

        aggregate_trust_input(&ctx).unwrap().threshold_counts
    }

    /// Deterministic verifier signing key used by `make_challenge_verification`,
    /// so a test resolver can be seeded with the matching public key.
    fn challenge_verifier_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    /// Builds a GENUINELY verifier-signed [`ChallengeVerification`] bound to
    /// `context_id`. The `verifier_signature` is a real Ed25519 signature over
    /// the canonical bytes, so it passes `verify_challenge_verification` when the
    /// resolver is seeded via [`seed_challenge_verifier`].
    fn make_challenge_verification(
        capability_uri: &str,
        responder: &str,
        completed_at: u64,
        context_id: Option<&str>,
    ) -> ChallengeVerification {
        use crate::trust::challenge::{
            ChallengeType, VerificationMethod, challenge_verification_id,
            challenge_verification_signing_digest,
        };
        use ed25519_dalek::Signer;

        let verifier_pub = challenge_verifier_key().verifying_key().to_bytes();
        let verifier = scp_did::did_dht_from_public_key(&verifier_pub);
        let subject = DID::from(responder);
        let timestamp = completed_at + 1;
        let mut cv = ChallengeVerification {
            verification_id: challenge_verification_id(
                &verifier,
                &subject,
                capability_uri,
                timestamp,
            )
            .unwrap(),
            verifier,
            subject,
            capability_uri: capability_uri.to_owned(),
            suite_digest: [3u8; 32],
            passed: true,
            score: None,
            test_count: 1,
            pass_count: 1,
            timestamp,
            expires_at: completed_at + 86400,
            context_id: context_id.map(ToOwned::to_owned),
            verifier_signature: vec![],
            verification_method: VerificationMethod::ChallengeVerified {
                challenge_type: ChallengeType::schema_validation(),
            },
            result: serde_json::json!({"passed": true}),
            completed_at,
        };
        let digest = challenge_verification_signing_digest(&cv).unwrap();
        cv.verifier_signature = challenge_verifier_key().sign(&digest).to_bytes().to_vec();
        cv
    }

    /// Capability URIs the challenge-result tests record.
    const SCHEMA_URI: &str = "scp:capability:schema-validation/v1";
    const RATE_URI: &str = "scp:capability:rate-limit-compliance/v1";

    /// Seeds `resolver` with the public key for the verifier DID used by
    /// [`make_challenge_verification`], so the genuine signature resolves and
    /// verifies on the challenge read path.
    fn seed_challenge_verifier(resolver: &mut TestResolver) {
        let verifier_pub = challenge_verifier_key().verifying_key().to_bytes();
        let verifier_did = scp_did::did_dht_from_public_key(&verifier_pub).to_string();
        resolver.keys.insert(verifier_did, verifier_pub.to_vec());
    }

    // -----------------------------------------------------------------------
    // CachedAttestation tests
    // -----------------------------------------------------------------------

    #[test]
    fn cached_attestation_is_expired_when_past_ttl() {
        let entry = CachedAttestation {
            attestation: make_attestation("att-1", "did:key:alice", AttestationType::Endorsement),
            verified_at: 1000,
            ttl_secs: 300,
        };

        assert!(!entry.is_expired(1000));
        assert!(!entry.is_expired(1300));
        assert!(entry.is_expired(1301));
    }

    #[test]
    fn cached_attestation_is_not_expired_within_ttl() {
        let entry = CachedAttestation {
            attestation: make_attestation("att-1", "did:key:alice", AttestationType::Endorsement),
            verified_at: 1000,
            ttl_secs: 600,
        };

        assert!(!entry.is_expired(1000));
        assert!(!entry.is_expired(1300));
        assert!(!entry.is_expired(1600));
        assert!(entry.is_expired(1601));
    }

    #[test]
    fn cached_attestation_handles_zero_ttl() {
        let entry = CachedAttestation {
            attestation: make_attestation("att-1", "did:key:alice", AttestationType::Endorsement),
            verified_at: 1000,
            ttl_secs: 0,
        };

        // At the exact verified_at time, not expired (now == verified_at + 0).
        assert!(!entry.is_expired(1000));
        // Any time after is expired.
        assert!(entry.is_expired(1001));
    }

    // -----------------------------------------------------------------------
    // InMemoryTrustStore tests
    // -----------------------------------------------------------------------

    #[test]
    fn store_caches_and_retrieves_attestations() {
        let store = InMemoryTrustStore::new();

        let att = make_attestation("att-1", "did:key:alice", AttestationType::Endorsement);
        let entry = CachedAttestation {
            attestation: att,
            verified_at: 1000,
            ttl_secs: 300,
        };

        store.store_cached_attestation("ctx-1", entry).unwrap();

        let cached = store
            .get_cached_attestations("ctx-1", "did:key:alice")
            .unwrap();
        assert_eq!(cached.len(), 1);
        assert_eq!(cached[0].attestation.id, "att-1");
    }

    #[test]
    fn store_replaces_attestation_with_same_id() {
        let store = InMemoryTrustStore::new();

        let att = make_attestation("att-1", "did:key:alice", AttestationType::Endorsement);
        let entry1 = CachedAttestation {
            attestation: att.clone(),
            verified_at: 1000,
            ttl_secs: 300,
        };
        let entry2 = CachedAttestation {
            attestation: att,
            verified_at: 2000,
            ttl_secs: 300,
        };

        store.store_cached_attestation("ctx-1", entry1).unwrap();
        store.store_cached_attestation("ctx-1", entry2).unwrap();

        let cached = store
            .get_cached_attestations("ctx-1", "did:key:alice")
            .unwrap();
        assert_eq!(cached.len(), 1);
        assert_eq!(cached[0].verified_at, 2000);
    }

    #[test]
    fn store_returns_empty_for_unknown_context() {
        let store = InMemoryTrustStore::new();

        let cached = store
            .get_cached_attestations("ctx-unknown", "did:key:alice")
            .unwrap();
        assert!(cached.is_empty());
    }

    fn entry(list_key: &str, expires_at: Option<u64>) -> RevocationEntry {
        RevocationEntry {
            list_key: list_key.to_owned(),
            expires_at,
        }
    }

    /// The plan prunes each record moot at `now` (step 3 rejects its
    /// attestation first), keeps the rest, and skips a new entry the kept
    /// records already hold, one listed twice, or one already moot.
    #[test]
    fn plan_revocation_write_prunes_moot_records_and_skips_duplicates() {
        let existing = [
            entry("old", Some(999)),
            entry("kept", None),
            entry("edge", Some(1000)),
        ];
        let entries = [
            entry("kept", None),
            entry("new", Some(5000)),
            entry("new", Some(5000)),
            entry("already-expired", Some(10)),
        ];
        let plan = plan_revocation_write(&existing, &entries, 1000);
        assert_eq!(plan.prune, vec!["old".to_owned()]);
        assert_eq!(plan.write, vec![entry("new", Some(5000))]);
    }

    /// The plan refuses no write by count (spec 07 §7.4.4 states no size
    /// bound): a large list still takes a new record, and a moot record in it
    /// is still pruned.
    #[test]
    fn plan_revocation_write_refuses_no_write_by_count() {
        let mut large: Vec<RevocationEntry> =
            (0..4096).map(|i| entry(&format!("k{i}"), None)).collect();
        large[0].expires_at = Some(5);
        let fresh: Vec<RevocationEntry> =
            (0..2048).map(|i| entry(&format!("n{i}"), None)).collect();
        let plan = plan_revocation_write(&large, &fresh, 1000);
        assert_eq!(plan.prune, vec!["k0".to_owned()]);
        assert_eq!(plan.write, fresh);

        // An empty call neither prunes nor writes.
        let empty = plan_revocation_write(&large, &[], 1000);
        assert_eq!(empty, RevocationWritePlan::default());
    }

    /// The test store replaces a cached attestation only on the same issuer
    /// AND id, the rule `store_cached_attestation` states.
    #[test]
    fn two_issuers_with_one_attestation_id_are_two_cache_entries() {
        let store = InMemoryTrustStore::new();
        let mut honest =
            make_attestation("att-shared", "did:key:alice", AttestationType::Endorsement);
        honest.issuer = "did:key:honest".into();
        let mut other = honest.clone();
        other.issuer = "did:key:other".into();
        for attestation in [honest, other] {
            store
                .store_cached_attestation(
                    "ctx-1",
                    CachedAttestation {
                        attestation,
                        verified_at: 1000,
                        ttl_secs: 300,
                    },
                )
                .unwrap();
        }
        assert_eq!(
            store
                .get_cached_attestations("ctx-1", "did:key:alice")
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn store_persists_and_retrieves_revocation_state() {
        let store = InMemoryTrustStore::new();

        let issuer = DID::from("did:key:issuer");
        let revoked_key = revocation_list_key(&issuer, "att-1");
        let active_key = revocation_list_key(&issuer, "att-2");

        store
            .add_revocations(
                "ctx-1",
                &[RevocationEntry {
                    list_key: revoked_key.clone(),
                    expires_at: None,
                }],
                1000,
            )
            .unwrap();

        let retrieved = store.get_revocation_state("ctx-1").unwrap();
        assert_eq!(retrieved.len(), 1);
        assert_eq!(retrieved.get(&revoked_key), Some(&true));
        assert_eq!(retrieved.get(&active_key), None);
    }

    /// SECURITY (key injectivity, issue #2335 finding 13). A caller chooses both
    /// an issuer DID and an attestation id, so a key built from those two fields
    /// must map distinct pairs to distinct keys. The leading issuer length is
    /// what delivers that: a caller who embeds the `:` separator in either field
    /// cannot move the issuer boundary, so it cannot make its own pair collide
    /// with another issuer's pair and reach that issuer's attestations.
    #[test]
    fn revocation_list_keys_separate_issuer_from_attestation_id() {
        // Embedding the separator inside an id must not reproduce another
        // issuer's key.
        let forged = revocation_list_key(&DID::from("did:key:m"), "did:key:h:att-1");
        let honest = revocation_list_key(&DID::from("did:key:m:did:key:h"), "att-1");
        assert_ne!(
            forged, honest,
            "a separator a caller embeds must not collide two distinct issuer/id pairs"
        );

        // Same issuer and same id yield one key, so a lookup finds what a write
        // recorded.
        assert_eq!(
            revocation_list_key(&DID::from("did:key:h"), "att-1"),
            revocation_list_key(&DID::from("did:key:h"), "att-1"),
        );

        // One id under two issuers yields two keys.
        assert_ne!(
            revocation_list_key(&DID::from("did:key:h"), "att-1"),
            revocation_list_key(&DID::from("did:key:m"), "att-1"),
        );
    }

    #[test]
    fn store_returns_empty_revocations_for_unknown_context() {
        let store = InMemoryTrustStore::new();

        let state = store.get_revocation_state("ctx-unknown").unwrap();
        assert!(state.is_empty());
    }

    #[test]
    fn store_persists_and_retrieves_challenge_results() {
        let store = InMemoryTrustStore::new();

        let cv = make_challenge_verification(SCHEMA_URI, "did:key:alice", 1000, Some("ctx-1"));
        store.store_challenge_result("ctx-1", &cv).unwrap();

        let results = store
            .get_challenge_results("ctx-1", "did:key:alice")
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].capability_uri, SCHEMA_URI);
        assert_eq!(results[0].completed_at, 1000);
    }

    #[test]
    fn store_accumulates_multiple_challenge_results() {
        let store = InMemoryTrustStore::new();

        let cv1 = make_challenge_verification(SCHEMA_URI, "did:key:alice", 1000, Some("ctx-1"));
        let cv2 = make_challenge_verification(RATE_URI, "did:key:alice", 2000, Some("ctx-1"));

        store.store_challenge_result("ctx-1", &cv1).unwrap();
        store.store_challenge_result("ctx-1", &cv2).unwrap();

        let results = store
            .get_challenge_results("ctx-1", "did:key:alice")
            .unwrap();
        assert_eq!(results.len(), 2);
    }

    // -----------------------------------------------------------------------
    // AttestationCache tests
    // -----------------------------------------------------------------------

    #[test]
    fn cache_returns_fresh_attestations_without_reverification() {
        let store = InMemoryTrustStore::new();
        let clock = TestClock::new(1000);

        let att = make_attestation("att-1", "did:key:alice", AttestationType::Endorsement);
        let entry = CachedAttestation {
            attestation: att,
            verified_at: 900,
            ttl_secs: 300,
        };

        store.store_cached_attestation("ctx-1", entry).unwrap();

        let cache = AttestationCache::new(store);
        let resolver = TestResolver::new();

        // Entry is fresh (900 + 300 = 1200 > 1000), so no reverification
        // needed. The resolver has no keys but that's OK because we don't
        // need to verify.
        let result = cache
            .get_verified_attestations("ctx-1", "did:key:alice", &resolver, &clock)
            .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "att-1");
    }

    #[test]
    fn cache_drops_fresh_entry_whose_attestation_has_expired() {
        // The cache entry is fresh (within TTL) but the attestation's own
        // `expires_at` has passed relative to `now`. The fresh-return path must
        // drop it rather than return an expired credential.
        let store = InMemoryTrustStore::new();
        // make_attestation sets expires_at = Some(5000); clock past that.
        let clock = TestClock::new(6000);

        let att = make_attestation("att-1", "did:key:alice", AttestationType::Endorsement);
        let entry = CachedAttestation {
            attestation: att,
            verified_at: 5900, // fresh: 5900 + 600 = 6500 > 6000
            ttl_secs: 600,
        };
        store.store_cached_attestation("ctx-1", entry).unwrap();

        let cache = AttestationCache::new(store);
        let resolver = TestResolver::new();

        let result = cache
            .get_verified_attestations("ctx-1", "did:key:alice", &resolver, &clock)
            .unwrap();

        assert!(
            result.is_empty(),
            "a fresh cache entry whose attestation expires_at < now must be excluded on read"
        );
    }

    #[test]
    fn cache_discards_expired_entries_that_fail_reverification() {
        let store = InMemoryTrustStore::new();
        let clock = TestClock::new(2000);

        let att = make_attestation("att-1", "did:key:alice", AttestationType::Endorsement);
        let entry = CachedAttestation {
            attestation: att,
            verified_at: 500,
            ttl_secs: 300,
        };

        store.store_cached_attestation("ctx-1", entry).unwrap();

        let cache = AttestationCache::new(store);
        // No keys in resolver -> verification will fail.
        let resolver = TestResolver::new();

        let result = cache
            .get_verified_attestations("ctx-1", "did:key:alice", &resolver, &clock)
            .unwrap();

        // The expired entry should be discarded because reverification fails.
        assert!(result.is_empty());
    }

    #[test]
    fn cache_custom_ttl_is_respected() {
        let store = InMemoryTrustStore::new();
        let cache = AttestationCache::with_ttl(store, 60);

        assert_eq!(cache.ttl_secs, 60);
    }

    // -----------------------------------------------------------------------
    // aggregate_trust_input tests
    // -----------------------------------------------------------------------

    #[test]
    fn aggregate_returns_complete_trust_input() {
        let store = InMemoryTrustStore::new();
        let clock = TestClock::new(2000);
        // Seed the resolver with the verifier key so the genuinely-signed
        // challenge result re-validates on the read path (Fix 1).
        let mut resolver = TestResolver::new();
        seed_challenge_verifier(&mut resolver);

        // Seed the store with cached attestations.
        let att = make_attestation("att-1", "did:key:alice", AttestationType::Endorsement);
        let entry = CachedAttestation {
            attestation: att,
            verified_at: 1900,
            ttl_secs: 300,
        };
        store.store_cached_attestation("ctx-1", entry).unwrap();

        // Seed the store with a genuinely-signed, in-context challenge result.
        let cv = make_challenge_verification(SCHEMA_URI, "did:key:alice", 1500, Some("ctx-1"));
        store.store_challenge_result("ctx-1", &cv).unwrap();

        let cache = AttestationCache::new(store);

        // Create events for participation record computation.
        let events = vec![
            make_event(EventType::MessageSent, "did:key:alice", 1000, 0, vec![]),
            make_event(EventType::MessageSent, "did:key:alice", 1500, 1, vec![]),
            make_event(
                EventType::OutletInvoked,
                "did:key:alice",
                1600,
                2,
                b"my-outlet".to_vec(),
            ),
        ];

        // Define consequence rules.
        let consequence_rules = vec![ConsequenceRule {
            trigger: super::super::consequence::ConsequenceTrigger::MessageVelocity,
            action: super::super::consequence::ConsequenceAction::Enforcement(
                super::super::consequence::EnforcementSeverity::SuspendCapability {
                    capabilities: vec![crate::context::roles::Capability::MessagesWrite],
                },
            ),
            threshold: 10,
            window: Duration::from_hours(1),
        }];

        let threshold_requirements = HashMap::new();
        let attestor_sets = HashMap::new();

        let ctx = AggregationContext {
            context_id: "ctx-1",
            subject_did: "did:key:alice",
            events: &events,
            merkle_root: [0u8; 32],
            consequence_rules: &consequence_rules,
            threshold_requirements: &threshold_requirements,
            attestor_sets: &attestor_sets,
            cache: &cache,
            resolver: &resolver,
            challenge_resolver: &resolver,
            clock: &clock,
        };

        let input = aggregate_trust_input(&ctx).unwrap();

        // Participation profile.
        assert_eq!(input.participation_record.subject_did, "did:key:alice");
        assert_eq!(input.participation_record.context_id, "ctx-1");
        assert_eq!(input.participation_record.participation_count, 3);
        assert_eq!(
            input
                .participation_record
                .outlet_invocations
                .get("my-outlet"),
            Some(&1)
        );

        // Verified attestations.
        assert_eq!(input.verified_attestations.len(), 1);
        assert_eq!(input.verified_attestations[0].id, "att-1");

        // Challenge results.
        assert_eq!(input.challenge_results.len(), 1);
        assert_eq!(input.challenge_results[0].capability_uri, SCHEMA_URI);

        // Consequence structure.
        assert_eq!(input.consequence_structure.len(), 1);

        // Threshold counts (empty -- no requirements defined).
        assert!(input.threshold_counts.is_empty());
    }

    #[test]
    fn aggregate_excludes_persisted_challenge_result_after_expiry() {
        // Fix 1 (read-path re-validation). A genuine, in-context, properly-signed
        // challenge result is persisted; after the clock advances past its
        // `expires_at`, re-running aggregation must EXCLUDE it (the persistent
        // store would otherwise serve it as a current trust signal forever).
        let store = InMemoryTrustStore::new();
        let mut resolver = TestResolver::new();
        seed_challenge_verifier(&mut resolver);

        // completed_at = 1500 → expires_at = 1500 + 86400 = 87_900.
        let cv = make_challenge_verification(SCHEMA_URI, "did:key:alice", 1500, Some("ctx-1"));
        store.store_challenge_result("ctx-1", &cv).unwrap();

        let events = vec![make_event(
            EventType::MessageSent,
            "did:key:alice",
            1000,
            0,
            vec![],
        )];
        let consequence_rules = vec![];
        let threshold_requirements = HashMap::new();
        let attestor_sets = HashMap::new();
        let cache = AttestationCache::new(store);

        // Sanity: before expiry the result IS included.
        let before_clock = TestClock::new(2000);
        let ctx_before = AggregationContext {
            context_id: "ctx-1",
            subject_did: "did:key:alice",
            events: &events,
            merkle_root: [0u8; 32],
            consequence_rules: &consequence_rules,
            threshold_requirements: &threshold_requirements,
            attestor_sets: &attestor_sets,
            cache: &cache,
            resolver: &resolver,
            challenge_resolver: &resolver,
            clock: &before_clock,
        };
        let input_before = aggregate_trust_input(&ctx_before).unwrap();
        assert_eq!(
            input_before.challenge_results.len(),
            1,
            "a valid, unexpired challenge result must be included"
        );

        // After expiry the result is EXCLUDED on read.
        let after_clock = TestClock::new(90_000);
        let ctx_after = AggregationContext {
            context_id: "ctx-1",
            subject_did: "did:key:alice",
            events: &events,
            merkle_root: [0u8; 32],
            consequence_rules: &consequence_rules,
            threshold_requirements: &threshold_requirements,
            attestor_sets: &attestor_sets,
            cache: &cache,
            resolver: &resolver,
            challenge_resolver: &resolver,
            clock: &after_clock,
        };
        let input_after = aggregate_trust_input(&ctx_after).unwrap();
        assert!(
            input_after.challenge_results.is_empty(),
            "an expired persisted challenge result must be excluded on the read path"
        );
    }

    /// Runs `aggregate_trust_input` over one stored, genuinely signed,
    /// in-context challenge result for `did:key:alice`, with the attestation
    /// and challenge resolvers given separately.
    fn aggregate_one_challenge(
        resolver: &TestResolver,
        challenge_resolver: &dyn DidPublicKeyResolver,
    ) -> Result<TrustInput, TrustError> {
        let store = InMemoryTrustStore::new();
        let cv = make_challenge_verification(SCHEMA_URI, "did:key:alice", 1500, Some("ctx-1"));
        store.store_challenge_result("ctx-1", &cv).unwrap();
        let events = vec![make_event(
            EventType::MessageSent,
            "did:key:alice",
            1000,
            0,
            vec![],
        )];
        let threshold_requirements = HashMap::new();
        let attestor_sets = HashMap::new();
        let cache = AttestationCache::new(store);
        let clock = TestClock::new(2000);
        let ctx = AggregationContext {
            context_id: "ctx-1",
            subject_did: "did:key:alice",
            events: &events,
            merkle_root: [0u8; 32],
            consequence_rules: &[],
            threshold_requirements: &threshold_requirements,
            attestor_sets: &attestor_sets,
            cache: &cache,
            resolver,
            challenge_resolver,
            clock: &clock,
        };
        aggregate_trust_input(&ctx)
    }

    #[test]
    fn aggregate_reverifies_challenges_with_challenge_resolver() {
        // The attestation resolver knows no key; the challenge resolver knows
        // the verifier's. The stored challenge result must be re-verified with
        // the challenge resolver and kept.
        let rejects_everything = TestResolver::new();
        let mut challenge_resolver = TestResolver::new();
        seed_challenge_verifier(&mut challenge_resolver);

        let input = aggregate_one_challenge(&rejects_everything, &challenge_resolver).unwrap();
        assert_eq!(input.challenge_results.len(), 1);
        assert_eq!(input.challenge_results[0].capability_uri, SCHEMA_URI);

        // Control: with the challenge resolver also empty, the record's
        // signature cannot be authenticated, so it is dropped.
        let input = aggregate_one_challenge(&rejects_everything, &rejects_everything).unwrap();
        assert!(input.challenge_results.is_empty());
    }

    /// A challenge resolver whose backend is down.
    struct UnavailableResolver;

    impl DidPublicKeyResolver for UnavailableResolver {
        fn resolve_public_key(&self, did: &str) -> Result<Vec<u8>, TrustError> {
            Err(TrustError::KeyResolutionUnavailable {
                did: did.to_owned(),
                reason: "resolver offline".to_owned(),
            })
        }
    }

    #[test]
    fn aggregate_propagates_challenge_resolver_outage() {
        // A resolver outage is not a judgment on the record: aggregation fails
        // instead of silently dropping a possibly valid challenge result.
        let resolver = TestResolver::new();
        let result = aggregate_one_challenge(&resolver, &UnavailableResolver);
        assert!(
            matches!(&result, Err(TrustError::KeyResolutionUnavailable { did, .. }) if did.starts_with("did:dht:")),
            "got {result:?}"
        );
    }

    #[test]
    fn aggregate_computes_threshold_counts() {
        let mut resolver = TestResolver::new();

        // Set up threshold requirements.
        let mut threshold_requirements = HashMap::new();
        threshold_requirements.insert(
            AttestationType::Endorsement,
            ThresholdRequirement::new(3, 5, 0.5),
        );

        // Set up attestor sets with 2 matching attestors (below threshold).
        let mut attestor_sets = HashMap::new();
        attestor_sets.insert(
            AttestationType::Endorsement,
            vec![
                signed_attestor(
                    &mut resolver,
                    "did:key:attestor1",
                    "did:key:alice",
                    AttestationType::Endorsement,
                    "att-a1",
                ),
                signed_attestor(
                    &mut resolver,
                    "did:key:attestor2",
                    "did:key:alice",
                    AttestationType::Endorsement,
                    "att-a2",
                ),
            ],
        );

        let counts =
            threshold_counts_via_aggregate(&resolver, &threshold_requirements, &attestor_sets, &[]);

        // Threshold counts should show (2, 3) for Endorsement type.
        let counts = counts.get(&AttestationType::Endorsement);
        assert!(counts.is_some(), "expected Endorsement in threshold_counts");
        let (met, required) = counts.unwrap();
        assert_eq!(*met, 2);
        assert_eq!(*required, 3);
    }

    #[test]
    fn aggregate_returns_error_for_empty_event_log() {
        let store = InMemoryTrustStore::new();
        let clock = TestClock::new(2000);
        let resolver = TestResolver::new();

        let cache = AttestationCache::new(store);

        let consequence_rules = vec![];
        let threshold_requirements = HashMap::new();
        let attestor_sets = HashMap::new();

        let ctx = AggregationContext {
            context_id: "ctx-1",
            subject_did: "did:key:alice",
            events: &[],
            merkle_root: [0u8; 32],
            consequence_rules: &consequence_rules,
            threshold_requirements: &threshold_requirements,
            attestor_sets: &attestor_sets,
            cache: &cache,
            resolver: &resolver,
            challenge_resolver: &resolver,
            clock: &clock,
        };

        let result = aggregate_trust_input(&ctx);
        assert!(result.is_err());
        match result {
            Err(TrustError::EmptyEventLog) => {}
            other => panic!("expected EmptyEventLog, got {other:?}"),
        }
    }

    #[test]
    fn aggregate_with_no_attestations_or_challenges() {
        let store = InMemoryTrustStore::new();
        let clock = TestClock::new(2000);
        let resolver = TestResolver::new();

        let cache = AttestationCache::new(store);

        let events = vec![make_event(
            EventType::MessageSent,
            "did:key:alice",
            1000,
            0,
            vec![],
        )];

        let consequence_rules = vec![];
        let threshold_requirements = HashMap::new();
        let attestor_sets = HashMap::new();

        let ctx = AggregationContext {
            context_id: "ctx-1",
            subject_did: "did:key:alice",
            events: &events,
            merkle_root: [0u8; 32],
            consequence_rules: &consequence_rules,
            threshold_requirements: &threshold_requirements,
            attestor_sets: &attestor_sets,
            cache: &cache,
            resolver: &resolver,
            challenge_resolver: &resolver,
            clock: &clock,
        };

        let input = aggregate_trust_input(&ctx).unwrap();

        assert!(input.verified_attestations.is_empty());
        assert!(input.challenge_results.is_empty());
        assert!(input.consequence_structure.is_empty());
        assert!(input.threshold_counts.is_empty());
        assert_eq!(input.participation_record.participation_count, 1);
    }

    #[test]
    fn aggregate_includes_multiple_consequence_rules() {
        let store = InMemoryTrustStore::new();
        let clock = TestClock::new(2000);
        let resolver = TestResolver::new();

        let cache = AttestationCache::new(store);

        let events = vec![make_event(
            EventType::MessageSent,
            "did:key:alice",
            1000,
            0,
            vec![],
        )];

        let consequence_rules = vec![
            ConsequenceRule {
                trigger: super::super::consequence::ConsequenceTrigger::MessageVelocity,
                action: super::super::consequence::ConsequenceAction::Enforcement(
                    super::super::consequence::EnforcementSeverity::SuspendAccess,
                ),
                threshold: 10,
                window: Duration::from_mins(1),
            },
            ConsequenceRule {
                trigger: super::super::consequence::ConsequenceTrigger::OutletRateExceeded,
                action: super::super::consequence::ConsequenceAction::AssignRole {
                    to_role: "observer".to_owned(),
                },
                threshold: 5,
                window: Duration::from_mins(2),
            },
        ];

        let threshold_requirements = HashMap::new();
        let attestor_sets = HashMap::new();

        let ctx = AggregationContext {
            context_id: "ctx-1",
            subject_did: "did:key:alice",
            events: &events,
            merkle_root: [0u8; 32],
            consequence_rules: &consequence_rules,
            threshold_requirements: &threshold_requirements,
            attestor_sets: &attestor_sets,
            cache: &cache,
            resolver: &resolver,
            challenge_resolver: &resolver,
            clock: &clock,
        };

        let input = aggregate_trust_input(&ctx).unwrap();

        assert_eq!(input.consequence_structure.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Threshold count tests, driven through aggregate_trust_input
    //
    // Every assertion here runs the caller path that ships in TrustInput, so a
    // rule that `check_threshold_attestation` stops applying fails a test here
    // rather than only inside the attestation module.
    // -----------------------------------------------------------------------

    #[test]
    fn aggregate_threshold_counts_empty_without_requirements() {
        let resolver = TestResolver::new();
        let counts =
            threshold_counts_via_aggregate(&resolver, &HashMap::new(), &HashMap::new(), &[]);
        assert!(counts.is_empty());
    }

    #[test]
    fn aggregate_threshold_counts_with_empty_attestor_set() {
        let resolver = TestResolver::new();
        let mut requirements = HashMap::new();
        requirements.insert(
            AttestationType::OutletIntegrity,
            ThresholdRequirement::new(2, 3, 0.5),
        );

        let counts = threshold_counts_via_aggregate(&resolver, &requirements, &HashMap::new(), &[]);
        let (met, required) = counts.get(&AttestationType::OutletIntegrity).unwrap();
        assert_eq!(*met, 0);
        assert_eq!(*required, 2);
    }

    #[test]
    fn aggregate_threshold_counts_multiple_types() {
        let mut resolver = TestResolver::new();
        let mut requirements = HashMap::new();
        requirements.insert(
            AttestationType::Endorsement,
            ThresholdRequirement::new(2, 3, 0.0),
        );
        requirements.insert(
            AttestationType::OutletIntegrity,
            ThresholdRequirement::new(1, 2, 0.0),
        );

        let mut attestor_sets = HashMap::new();
        attestor_sets.insert(
            AttestationType::Endorsement,
            vec![signed_attestor(
                &mut resolver,
                "did:key:a",
                "did:key:alice",
                AttestationType::Endorsement,
                "att-1",
            )],
        );

        let counts = threshold_counts_via_aggregate(&resolver, &requirements, &attestor_sets, &[]);

        // Endorsement: 1 met, 2 required.
        let (met, required) = counts.get(&AttestationType::Endorsement).unwrap();
        assert_eq!(*met, 1);
        assert_eq!(*required, 2);

        // OutletIntegrity: 0 met (no attestors), 1 required.
        let (met, required) = counts.get(&AttestationType::OutletIntegrity).unwrap();
        assert_eq!(*met, 0);
        assert_eq!(*required, 1);
    }

    #[test]
    fn aggregate_counts_repeated_attestor_did_once() {
        // Spec §7.3.5 rule 1: multiple attestations from one DID count as one.
        // Five copies of one endorser reaching `aggregate_trust_input` must
        // report valid_count 1, not 5.
        let mut resolver = TestResolver::new();
        let attestor = signed_attestor(
            &mut resolver,
            "did:key:a",
            "did:key:alice",
            AttestationType::Endorsement,
            "att-dup",
        );

        let mut requirements = HashMap::new();
        requirements.insert(
            AttestationType::Endorsement,
            ThresholdRequirement::new(3, 5, 0.5),
        );

        let mut attestor_sets = HashMap::new();
        attestor_sets.insert(
            AttestationType::Endorsement,
            vec![
                attestor.clone(),
                attestor.clone(),
                attestor.clone(),
                attestor.clone(),
                attestor,
            ],
        );

        let counts = threshold_counts_via_aggregate(&resolver, &requirements, &attestor_sets, &[]);
        let (met, required) = counts.get(&AttestationType::Endorsement).unwrap();
        assert_eq!(*met, 1, "five copies of one DID count once");
        assert_eq!(*required, 3);
    }

    #[test]
    fn aggregate_drops_attestation_naming_another_subject() {
        let mut resolver = TestResolver::new();
        let attestor = signed_attestor(
            &mut resolver,
            "did:key:a",
            "did:key:mallory",
            AttestationType::Endorsement,
            "att-other-subject",
        );

        let mut requirements = HashMap::new();
        requirements.insert(
            AttestationType::Endorsement,
            ThresholdRequirement::new(1, 1, 0.5),
        );
        let mut attestor_sets = HashMap::new();
        attestor_sets.insert(AttestationType::Endorsement, vec![attestor]);

        let counts = threshold_counts_via_aggregate(&resolver, &requirements, &attestor_sets, &[]);
        let (met, _) = counts.get(&AttestationType::Endorsement).unwrap();
        assert_eq!(
            *met, 0,
            "an endorsement written about did:key:mallory must not count for did:key:alice"
        );
    }

    #[test]
    fn aggregate_drops_attestation_issued_by_another_did() {
        let mut resolver = TestResolver::new();
        let mut attestor = signed_attestor(
            &mut resolver,
            "did:key:real-issuer",
            "did:key:alice",
            AttestationType::Endorsement,
            "att-borrowed",
        );
        // The claimant carries an attestation that another DID issued.
        attestor.did = "did:key:claimant".into();

        let mut requirements = HashMap::new();
        requirements.insert(
            AttestationType::Endorsement,
            ThresholdRequirement::new(1, 1, 0.5),
        );
        let mut attestor_sets = HashMap::new();
        attestor_sets.insert(AttestationType::Endorsement, vec![attestor]);

        let counts = threshold_counts_via_aggregate(&resolver, &requirements, &attestor_sets, &[]);
        let (met, _) = counts.get(&AttestationType::Endorsement).unwrap();
        assert_eq!(
            *met, 0,
            "an attestor may only claim an attestation that it issued itself"
        );
    }

    #[test]
    fn aggregate_drops_attestation_with_forged_signature() {
        let mut resolver = TestResolver::new();
        let mut attestor = signed_attestor(
            &mut resolver,
            "did:key:a",
            "did:key:alice",
            AttestationType::Endorsement,
            "att-forged",
        );
        if let Some(attestation) = attestor.attestation.as_mut() {
            attestation.signature = vec![0u8; 64];
        }

        let mut requirements = HashMap::new();
        requirements.insert(
            AttestationType::Endorsement,
            ThresholdRequirement::new(1, 1, 0.5),
        );
        let mut attestor_sets = HashMap::new();
        attestor_sets.insert(AttestationType::Endorsement, vec![attestor]);

        let counts = threshold_counts_via_aggregate(&resolver, &requirements, &attestor_sets, &[]);
        let (met, _) = counts.get(&AttestationType::Endorsement).unwrap();
        assert_eq!(*met, 0, "a forged signature must not count");
    }

    #[test]
    fn aggregate_drops_context_revoked_attestation_from_threshold_count() {
        let mut resolver = TestResolver::new();
        let attestor = signed_attestor(
            &mut resolver,
            "did:key:a",
            "did:key:alice",
            AttestationType::Endorsement,
            "att-revoked",
        );

        let mut requirements = HashMap::new();
        requirements.insert(
            AttestationType::Endorsement,
            ThresholdRequirement::new(1, 1, 0.5),
        );
        let mut attestor_sets = HashMap::new();
        attestor_sets.insert(AttestationType::Endorsement, vec![attestor]);

        // Sanity: the same endorsement counts while the context has not
        // revoked it.
        let counts = threshold_counts_via_aggregate(&resolver, &requirements, &attestor_sets, &[]);
        let (met, _) = counts.get(&AttestationType::Endorsement).unwrap();
        assert_eq!(*met, 1, "an unrevoked endorsement counts");

        let counts = threshold_counts_via_aggregate(
            &resolver,
            &requirements,
            &attestor_sets,
            &[("did:key:a", "att-revoked")],
        );
        let (met, _) = counts.get(&AttestationType::Endorsement).unwrap();
        assert_eq!(*met, 0, "a context-revoked endorsement must stop counting");
    }

    /// SECURITY (issuer-scoped revocation, issue #2335 finding 13, threshold
    /// path). A revocation that a DIFFERENT issuer signed leaves an endorsement
    /// counting toward its threshold. §7.4.1 of
    /// `.docs/specs/07-trust-validation-and-capabilities.md` binds
    /// `Attestation.id` to no issuer, so a revocation list keyed on an id alone
    /// would let anyone who learns an id drive an endorsement's threshold count
    /// to zero by signing a self-revoking attestation carrying that id. The test
    /// above pins the same-issuer case, so the two together separate scoping
    /// from a checker that reports nothing.
    #[test]
    fn a_foreign_issuers_revocation_leaves_a_threshold_count_intact() {
        let mut resolver = TestResolver::new();
        let attestor = signed_attestor(
            &mut resolver,
            "did:key:a",
            "did:key:alice",
            AttestationType::Endorsement,
            "att-shared-id",
        );

        let mut requirements = HashMap::new();
        requirements.insert(
            AttestationType::Endorsement,
            ThresholdRequirement::new(1, 1, 0.5),
        );
        let mut attestor_sets = HashMap::new();
        attestor_sets.insert(AttestationType::Endorsement, vec![attestor]);

        let counts = threshold_counts_via_aggregate(
            &resolver,
            &requirements,
            &attestor_sets,
            &[("did:key:attacker", "att-shared-id")],
        );
        let (met, _) = counts.get(&AttestationType::Endorsement).unwrap();
        assert_eq!(
            *met, 1,
            "a revocation another issuer signed must not stop this endorsement counting"
        );
    }

    // -----------------------------------------------------------------------
    // filter_by_freshness tests
    // -----------------------------------------------------------------------

    #[test]
    fn filter_excludes_expired_attestations() {
        let clock = TestClock::new(6000);

        let fresh_att = Attestation {
            expires_at: Some(7000),
            ..make_attestation("att-fresh", "did:key:alice", AttestationType::Endorsement)
        };

        let expired_att = Attestation {
            expires_at: Some(5000),
            ..make_attestation("att-expired", "did:key:alice", AttestationType::Endorsement)
        };

        let attestations = vec![fresh_att, expired_att];
        let filtered = filter_by_freshness(&attestations, &clock);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].0.id, "att-fresh");
        assert_eq!(filtered[0].1, FreshnessStatus::Fresh);
    }

    #[test]
    fn filter_includes_stale_attestations_with_status() {
        let clock = TestClock::new(2000);

        let stale_att = Attestation {
            issued_at: 500,
            expires_at: Some(5000),
            renewal_interval: Some(Duration::from_mins(10)),
            ..make_attestation("att-stale", "did:key:alice", AttestationType::Endorsement)
        };

        let attestations = vec![stale_att];
        let filtered = filter_by_freshness(&attestations, &clock);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].0.id, "att-stale");
        match &filtered[0].1 {
            FreshnessStatus::Stale { since } => {
                assert_eq!(*since, 1100); // 500 + 600
            }
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    #[test]
    fn filter_returns_empty_for_all_expired() {
        let clock = TestClock::new(10_000);

        let attestations = vec![
            Attestation {
                expires_at: Some(5000),
                ..make_attestation("att-1", "did:key:alice", AttestationType::Endorsement)
            },
            Attestation {
                expires_at: Some(8000),
                ..make_attestation("att-2", "did:key:alice", AttestationType::Endorsement)
            },
        ];

        let filtered = filter_by_freshness(&attestations, &clock);
        assert!(filtered.is_empty());
    }
}
