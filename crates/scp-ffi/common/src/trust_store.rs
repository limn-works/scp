//! Trust-aggregation storage helpers shared by the `PyO3`, napi-rs, and
//! `UniFFI` bridges.
//!
//! [`populate_and_aggregate`] runs the aggregation pipeline over whichever
//! [`TrustProtocolRepository`] a bridge hands it. Every shipped bridge hands it
//! a `ProtocolRepositoryTrustBridge` over the storage its caller configured.
//! `InMemoryFfiTrustStore` compiles only under
//! `#[cfg(any(test, feature = "testing"))]`, so no shipped artifact contains
//! it (root `AGENTS.md`, "No dev/test-only stand-ins in production").
//!
//! See ADR-017 acceptance criterion 10 in `.docs/adrs/phase-4.md`.

use std::collections::HashMap;
#[cfg(any(test, feature = "testing"))]
use std::sync::Mutex;

use scp_clock::Clock;
#[cfg(any(test, feature = "testing"))]
use scp_core::trust::aggregate::plan_revocation_write;
use scp_core::trust::aggregate::{
    CachedAttestation, RevocationEntry, RevocationMapChecker, TrustProtocolRepository,
    revocation_list_key,
};
use scp_core::trust::attestation::{Attestation, DidPublicKeyResolver, RevocationStatus};
use scp_core::trust::{
    ChallengeVerification, TrustError, verify_attestation, verify_challenge_verification,
};
use scp_event_log::Event;

/// In-memory implementation of `TrustProtocolRepository`, for tests only.
///
/// Uses `std::sync::Mutex` for interior mutability. It forgets every entry
/// when dropped, so a shipped path that aggregated through it would read an
/// empty store in place of the caller's configured one. The
/// `#[cfg(any(test, feature = "testing"))]` gate keeps it out of every shipped
/// artifact, the same gate `InMemoryNonceTracker` in `scp-protocol` carries.
#[cfg(any(test, feature = "testing"))]
pub struct InMemoryFfiTrustStore {
    attestations: Mutex<HashMap<(String, String), Vec<CachedAttestation>>>,
    /// `list_key -> expires_at` per context.
    revocations: Mutex<HashMap<String, HashMap<String, Option<u64>>>>,
    challenges: Mutex<HashMap<(String, String), Vec<ChallengeVerification>>>,
}

#[cfg(any(test, feature = "testing"))]
impl InMemoryFfiTrustStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            attestations: Mutex::new(HashMap::new()),
            revocations: Mutex::new(HashMap::new()),
            challenges: Mutex::new(HashMap::new()),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl Default for InMemoryFfiTrustStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "testing"))]
fn lock_error() -> TrustError {
    // A poisoned lock is an INFRA fault, not a credential rejection. It must map
    // to a variant OUTSIDE the verify-on-ingest rejection allowlist
    // (`TrustError::is_record_rejection`) so it propagates rather than being silently
    // swallowed as a dropped entry. `StoreError` is that variant; the dedicated
    // `CanonicalizationFailed` variant is the only canonicalization-rejection
    // signal, so an infra fault can never collide with a rejection here.
    TrustError::StoreError {
        reason: "lock poisoned".to_owned(),
    }
}

#[cfg(any(test, feature = "testing"))]
#[allow(clippy::significant_drop_tightening)]
impl TrustProtocolRepository for InMemoryFfiTrustStore {
    fn get_cached_attestations(
        &self,
        context_id: &str,
        subject_did: &str,
    ) -> Result<Vec<CachedAttestation>, TrustError> {
        let store = self.attestations.lock().map_err(|_| lock_error())?;
        let key = (context_id.to_owned(), subject_did.to_owned());
        Ok(store.get(&key).cloned().unwrap_or_default())
    }

    fn store_cached_attestation(
        &self,
        context_id: &str,
        entry: CachedAttestation,
    ) -> Result<(), TrustError> {
        let mut store = self.attestations.lock().map_err(|_| lock_error())?;
        let key = (context_id.to_owned(), entry.attestation.subject.to_string());
        let entries = store.entry(key).or_default();
        // Replace only the entry carrying the same issuer AND id (see
        // `TrustProtocolRepository::store_cached_attestation`).
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

    fn get_revocation_state(&self, context_id: &str) -> Result<HashMap<String, bool>, TrustError> {
        let store = self.revocations.lock().map_err(|_| lock_error())?;
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
        // ONE guard spans the read, the plan, and the writes, so a concurrent
        // caller on this context cannot overwrite what this call adds (see the
        // lost-update requirement on `TrustProtocolRepository::add_revocations`).
        let mut store = self.revocations.lock().map_err(|_| lock_error())?;
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
        let store = self.challenges.lock().map_err(|_| lock_error())?;
        let key = (context_id.to_owned(), subject_did.to_owned());
        Ok(store.get(&key).cloned().unwrap_or_default())
    }

    fn store_challenge_result(
        &self,
        context_id: &str,
        result: &ChallengeVerification,
    ) -> Result<(), TrustError> {
        let mut store = self.challenges.lock().map_err(|_| lock_error())?;
        let key = (context_id.to_owned(), result.subject.to_string());
        store.entry(key).or_default().push(result.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Verify-on-ingest support
// ---------------------------------------------------------------------------

/// Reports whether a verify-on-ingest rejection proves that `attestation`
/// carries an issuer-signed revocation of itself.
///
/// Both conditions below must hold, and together they decide whether
/// [`verify_and_cache_attestations`] may record
/// `revocation_list_key(attestation.issuer, attestation.id)` in a context's
/// revocation list:
///
/// 1. `verify_attestation` returned
///    [`TrustError::AttestationRevoked`]. That function checks an Ed25519
///    signature against a resolver-resolved issuer key as step 1 and reads
///    `revocation_status` only at step 4, so an `AttestationRevoked` it returns
///    already proves a signature verified. Step 4 also compares `revoked_by`
///    against `issuer` and raises a DIFFERENT variant,
///    [`TrustError::AttestationRevocationInvalid`], when those two DIDs differ,
///    which is what §7.4.4 of
///    `.docs/specs/07-trust-validation-and-capabilities.md` demands ("Only the
///    issuer (`revoked_by == issuer`) can revoke"). Condition 1 therefore
///    carries both proofs, and this module adds no second `revoked_by`
///    comparison. Source: `crates/scp-protocol/src/trust/attestation.rs`,
///    `verify_attestation`.
/// 2. `attestation.revocation_status` itself reads `Revoked`. Step 4 returns
///    before step 5 consults an external checker, so a step-5 hit — a hit
///    against a revocation list that [`verify_and_cache_attestations`] itself
///    wrote on an earlier call — leaves `revocation_status` reading `Active` and
///    fails condition 2. One write can therefore never justify another.
///
/// A bad signature, a malformed record, and an expired credential each produce a
/// different `TrustError` variant, so each fails condition 1.
///
/// SECURITY (what these two conditions do NOT decide — issue #2335 finding 13).
/// Neither condition constrains WHICH attestation id an attacker names. §7.4.1 of
/// `.docs/specs/07-trust-validation-and-capabilities.md` describes
/// `Attestation.id` as a UUID v4 that an issuer chooses, and states no rule
/// deriving that id from its issuer, so an attacker who mints a fresh DID at no
/// cost can sign a self-revoking attestation carrying an honest issuer's id and
/// satisfy both conditions above. Issuer scoping, not these conditions, is what
/// keeps that record away from the honest issuer's attestation:
/// [`verify_and_cache_attestations`] writes
/// `revocation_list_key(attestation.issuer, attestation.id)`, so an attacker's
/// record lands under the attacker's own DID and every reader that looks up the
/// honest issuer's attestation misses it.
const fn is_issuer_signed_revocation(err: &TrustError, attestation: &Attestation) -> bool {
    matches!(err, TrustError::AttestationRevoked { .. })
        && matches!(
            attestation.revocation_status,
            RevocationStatus::Revoked { .. }
        )
}

/// Verify-on-ingest for caller-supplied attestations.
///
/// Shared by [`populate_and_aggregate`] and [`verified_attestations`] so the
/// SECURITY rationale lives in exactly one place.
///
/// SECURITY (verify-on-ingest). Caller-supplied attestations carry caller-
/// controlled `verified_at`/`ttl_secs`. Persisting them raw via
/// `store_cached_attestation` would let a caller mark a forged attestation
/// "fresh" so it is counted AND durably persisted UNVERIFIED — a forged
/// `attestation_count` plus persistent poisoning of every later
/// `evaluate_trust`. Each caller entry is routed through
/// `AttestationCache::verify_and_cache`, which verifies the Ed25519 signature
/// against the RESOLVER-resolved issuer key, checks expiry, the issuer-bound
/// `revocation_status` field, AND the context's external revocation list BEFORE
/// caching, and stamps a trusted `verified_at` from the injected clock (the
/// caller's is ignored). A verification REJECTION drops the one entry; an INFRA
/// fault propagates so a backend error never silently zeroes trust.
///
/// SECURITY (revocation write-back, §7.4.4). This helper both READS a context's
/// revocation list and WRITES to it. Section 7.4.4 of
/// `.docs/specs/07-trust-validation-and-capabilities.md` defines how an issuer
/// revokes: an issuer flips `revocation_status` from `Active` to
/// `Revoked { reason, revoked_at, revoked_by }` and republishes that attestation
/// where an original was published, so a consumer learns about a revocation by
/// encountering a republished, genuinely-signed, revoked copy. Dropping such a
/// copy and remembering nothing would let a holder who still owns a
/// pre-revocation copy of that same attestation id present it on a later call
/// and have it counted. Each entry that satisfies
/// [`is_issuer_signed_revocation`] therefore contributes a [`RevocationEntry`]
/// for `revocation_list_key(issuer, id)` to
/// [`add_revocations`](TrustProtocolRepository::add_revocations), and every
/// reader of that list builds a [`RevocationMapChecker`] over it on every later
/// call. A failed write is an INFRA fault and propagates, matching how this
/// helper treats a failed `get_revocation_state`.
///
/// Every entry this helper records came from a caller; `add_revocations`
/// prunes the records whose attestation has expired and refuses no write by
/// count, because spec 07 §7.4.4 states no size bound for the list.
///
/// SECURITY (concurrent ingest). Keys reach a store only through
/// `add_revocations`, which adds the keys it names and leaves every unexpired
/// key alone. Two callers that both read one context's map and then write a
/// whole copy back would lose one caller's addition: each copy is stale about
/// the other's key. `add_revocations` carries that lost-update requirement in
/// its own contract, so this helper never reconstructs a whole map from a read
/// it performed earlier.
///
/// SECURITY (ordering of a revocation write against a cache write). This helper
/// runs TWO passes over `entries`. Pass 1 verifies every entry and caches
/// nothing, so it can discover every revocation this batch carries. The
/// revocation write then happens BEFORE any cache write, and a failed write
/// aborts the call with nothing cached. Caching first would leave the opposite
/// state on that failure — accepted attestations durable, a discovered
/// revocation absent — and a later call that omits the revoked copy would count
/// every cached entry. Pass 2 caches each entry pass 1 accepted, re-checked
/// against the keys pass 1 recorded, so a batch that carries both an issuer's
/// revoked copy and that issuer's earlier `Active` copy caches neither, whatever
/// order those two copies arrive in.
///
/// SECURITY (issuer scoping, issue #2335 finding 13). A key carries the DID that
/// signed a revocation alongside the revoked attestation's id, because §7.4.4
/// grants a revocation to the issuer alone ("Only the issuer
/// (`revoked_by == issuer`) can revoke an attestation") while §7.4.1 binds
/// `Attestation.id` to no issuer. Keying on an id alone would break that grant:
/// an attacker who derives a DID from a fresh keypair — which costs nothing,
/// because `IdentityDidPublicKeyResolver` reads a public key out of a DID string
/// and no publication gates it — signs an attestation carrying an honest
/// issuer's id and revoking itself, both conditions of
/// [`is_issuer_signed_revocation`] hold, and every later read of the honest
/// issuer's attestation then finds that id listed. [`revocation_list_key`]
/// places the attacker's record under the attacker's DID, so the honest issuer's
/// attestation keeps being counted.
fn verify_and_cache_attestations<S: TrustProtocolRepository>(
    cache: &scp_core::trust::aggregate::AttestationCache<S>,
    context_id: &str,
    resolver: &impl DidPublicKeyResolver,
    clock: &impl Clock,
    entries: Vec<CachedAttestation>,
) -> Result<(), TrustError> {
    let mut revoked = cache.store().get_revocation_state(context_id)?;

    // Keys this batch learned about. Each key binds a revoked attestation's id
    // to the issuer that signed that revocation (see the SECURITY note on issuer
    // scoping above).
    let mut newly_revoked: Vec<RevocationEntry> = Vec::new();
    let mut accepted: Vec<CachedAttestation> = Vec::new();

    // PASS 1 — verify every entry, cache none of them.
    {
        let revocation_checker = RevocationMapChecker::new(&revoked);
        for ca in entries {
            match verify_attestation(&ca.attestation, resolver, clock, &revocation_checker) {
                Ok(()) => accepted.push(ca),
                Err(reason) if reason.is_record_rejection() => {
                    let key = revocation_list_key(&ca.attestation.issuer, &ca.attestation.id);
                    if is_issuer_signed_revocation(&reason, &ca.attestation)
                        && !revoked.get(&key).copied().unwrap_or(false)
                        && !newly_revoked.iter().any(|e| e.list_key == key)
                    {
                        newly_revoked.push(RevocationEntry::for_attestation(&ca.attestation));
                    }
                    tracing::debug!(
                        attestation_id = %ca.attestation.id,
                        issuer = %ca.attestation.issuer,
                        %reason,
                        "dropping caller-supplied attestation that failed verify-on-ingest",
                    );
                }
                Err(infra) => return Err(infra),
            }
        }
    }

    // Revocation write BEFORE any cache write, so a failure here leaves nothing
    // cached rather than leaving a discovered revocation unrecorded.
    if !newly_revoked.is_empty() {
        cache
            .store()
            .add_revocations(context_id, &newly_revoked, clock.now_secs())?;
        for entry in newly_revoked {
            revoked.insert(entry.list_key, true);
        }
    }

    // PASS 2 — cache each accepted entry. `verify_and_cache` re-runs
    // verification against the keys pass 1 recorded, so a copy this batch
    // revoked never reaches the cache, whatever order the two copies arrived in.
    let revocation_checker = RevocationMapChecker::new(&revoked);
    for ca in accepted {
        match cache.verify_and_cache(
            context_id,
            &ca.attestation,
            resolver,
            clock,
            &revocation_checker,
        ) {
            Ok(()) => {}
            Err(reason) if reason.is_record_rejection() => {
                tracing::debug!(
                    attestation_id = %ca.attestation.id,
                    issuer = %ca.attestation.issuer,
                    %reason,
                    "dropping caller-supplied attestation revoked by this same batch",
                );
            }
            Err(infra) => return Err(infra),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Single-attestation verification against a context's revocation list
// ---------------------------------------------------------------------------

/// What [`verify_attestation_in_context`] concluded about one attestation.
#[derive(Debug)]
pub enum AttestationVerdict {
    /// Every step of `verify_attestation` passed, including the context's
    /// revocation list.
    Valid,
    /// The attestation itself failed a step: a bad signature, an expired
    /// credential, malformed evidence, or a revocation (its own field or the
    /// context's list). Carries the rejection.
    Rejected(TrustError),
}

/// Verifies one caller-supplied attestation against the revocation list of
/// `context_id`, writing nothing.
///
/// Step 5 of `verify_attestation` reads the list
/// [`TrustProtocolRepository::get_revocation_state`] returns for
/// `context_id`, so an attestation its issuer revoked through a republished
/// copy that an earlier ingest recorded fails here even when the copy the
/// caller presents still reads `Active`. `resolver` and `clock` are the
/// caller's: this helper resolves no key and reads no time of its own.
///
/// # Errors
///
/// Returns the store's [`TrustError`] when the revocation list cannot be read.
/// A store fault is never reported as a rejection, so a backend outage never
/// reads as an invalid credential, and never as a valid one.
pub fn verify_attestation_in_context<S, R, C>(
    store: &S,
    context_id: &str,
    attestation: &Attestation,
    resolver: &R,
    clock: &C,
) -> Result<AttestationVerdict, TrustError>
where
    S: TrustProtocolRepository + ?Sized,
    R: DidPublicKeyResolver + ?Sized,
    C: Clock + ?Sized,
{
    let revoked = store.get_revocation_state(context_id)?;
    match verify_attestation(
        attestation,
        resolver,
        clock,
        &RevocationMapChecker::new(&revoked),
    ) {
        Ok(()) => Ok(AttestationVerdict::Valid),
        Err(reason) if reason.is_record_rejection() => Ok(AttestationVerdict::Rejected(reason)),
        Err(infra) => Err(infra),
    }
}

// ---------------------------------------------------------------------------
// Shared aggregation helper — used by all FFI bridges
// ---------------------------------------------------------------------------

/// Populates a trust store and runs the aggregation pipeline.
///
/// Generic over the store implementation: shipped bridges pass a
/// `ProtocolRepositoryTrustBridge` over their configured storage, and tests
/// pass the test-only `InMemoryFfiTrustStore`. Returns the aggregated
/// `TrustInput` as a JSON string.
///
/// # Errors
///
/// Returns [`TrustError`] if store population, aggregation, or serialization
/// fails, or if `challenge_resolver` cannot reach its backend
/// ([`TrustError::KeyResolutionUnavailable`]).
///
/// `challenge_resolver` resolves each challenge verifier's `#active` key, for
/// verify-on-ingest and for the aggregation read path. The bridges pass their
/// instance's resolver through
/// [`instance_challenge_resolver`](crate::resolvers::instance_challenge_resolver).
#[allow(clippy::too_many_arguments, clippy::implicit_hasher)]
pub fn populate_and_aggregate<S: TrustProtocolRepository>(
    store: S,
    challenge_resolver: &dyn DidPublicKeyResolver,
    context_id: &str,
    subject_did: &str,
    cached_attestations: Vec<CachedAttestation>,
    challenge_results: &[ChallengeVerification],
    events: &[Event],
    merkle_root: [u8; 32],
    consequence_rules: &[scp_core::trust::ConsequenceRule],
    threshold_requirements: &HashMap<
        scp_core::trust::AttestationType,
        scp_core::trust::ThresholdRequirement,
    >,
    attestor_sets: &HashMap<scp_core::trust::AttestationType, Vec<scp_core::trust::AttestorInfo>>,
) -> Result<String, TrustError> {
    let cache = scp_core::trust::aggregate::AttestationCache::new(store);
    let resolver = scp_core::trust::IdentityDidPublicKeyResolver;
    let clock = scp_clock::SystemClock;

    // Verify-on-ingest for caller-supplied attestations (see helper for the
    // SECURITY rationale).
    verify_and_cache_attestations(&cache, context_id, &resolver, &clock, cached_attestations)?;

    // SECURITY (verify-on-ingest). Caller-supplied challenge verifications carry
    // a caller-controlled `passed`/`score` trust signal that is only meaningful
    // because the verifier signs it (§7.3.4.2). Persisting them raw would let a
    // caller forge a `passed=true` record and have it counted as an
    // admission/trust signal — the same forgery class as the attestation path.
    // `verify_challenge_verification` checks the verifier's Ed25519 signature
    // (resolver-resolved verifier key, binding `passed`/`score`/`expires_at`/
    // `subject_did`/`context_id`), binds the record to THIS `context_id` (no
    // cross-context replay; a `None` context-agnostic record is rejected) and to
    // THIS `subject_did` (no cross-subject attribution), and rejects an expired
    // record (clock-relative) BEFORE storing. Drop records
    // that fail verification, and propagate infra faults so a backend error does
    // not silently discard a legitimate verifier's signal.
    for cr in challenge_results {
        match verify_challenge_verification(cr, challenge_resolver, context_id, subject_did, &clock)
        {
            Ok(()) => cache.store().store_challenge_result(context_id, cr)?,
            Err(reason) if reason.is_record_rejection() => {
                tracing::debug!(
                    verification_id = %hex::encode(cr.verification_id),
                    %reason,
                    "dropping caller-supplied challenge result that failed verify-on-ingest",
                );
            }
            Err(infra) => return Err(infra),
        }
    }

    let ctx = scp_core::trust::aggregate::AggregationContext {
        context_id,
        subject_did,
        events,
        merkle_root,
        consequence_rules,
        threshold_requirements,
        attestor_sets,
        cache: &cache,
        resolver: &resolver,
        challenge_resolver,
        clock: &clock,
    };

    let trust_input = scp_core::trust::aggregate::aggregate_trust_input(&ctx)?;
    serde_json::to_string(&trust_input).map_err(|e| TrustError::StoreError {
        reason: format!("failed to serialize TrustInput: {e}"),
    })
}

/// Populates a trust store with caller-supplied attestations and returns the
/// subject's accessible, currently-valid (non-expired, non-revoked, signature-
/// verified) attestations.
///
/// This is the attestation-sourcing half of [`populate_and_aggregate`], factored
/// out so the participation-record bridge path can obtain the credential-layer
/// `attestation_count` input (§7.4) WITHOUT running the full trust aggregation.
/// It uses the SAME `AttestationCache` /
/// [`IdentityDidPublicKeyResolver`](scp_core::trust::IdentityDidPublicKeyResolver) /
/// [`SystemClock`](scp_clock::SystemClock) wiring as
/// `aggregate_trust_input`, so the participation `attestation_count` and the
/// aggregation's `verified_attestations` agree by construction.
///
/// The returned attestations are threaded into
/// [`Supervisor::participation_record`](scp_core) /
/// [`compute_participation_record`](scp_core::trust::compute_participation_record):
/// the caller passes them, this helper sources them — neither fabricates an
/// empty set. A subject with no cached/persisted attestations yields an empty
/// `Vec` (count 0, verifier-relative per §7.3.2).
///
/// # Errors
///
/// Returns [`TrustError`] if store population or attestation verification fails.
pub fn verified_attestations<S: TrustProtocolRepository>(
    store: S,
    context_id: &str,
    subject_did: &str,
    cached_attestations: Vec<CachedAttestation>,
) -> Result<Vec<scp_core::trust::attestation::Attestation>, TrustError> {
    let cache = scp_core::trust::aggregate::AttestationCache::new(store);
    let resolver = scp_core::trust::IdentityDidPublicKeyResolver;
    let clock = scp_clock::SystemClock;

    // Verify-on-ingest for caller-supplied attestations (see helper for the
    // SECURITY rationale). A REJECTION drops the entry so a caller can never
    // inflate `attestation_count` with an unverified, freshly-marked, or
    // context-revoked entry.
    verify_and_cache_attestations(&cache, context_id, &resolver, &clock, cached_attestations)?;

    cache.get_verified_attestations(context_id, subject_did, &resolver, &clock)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use scp_core::trust::AttestationType;
    use scp_core::trust::challenge::{ChallengeType, VerificationMethod};
    use scp_event_log::{Event, EventPayload, EventType};

    /// A revocation entry that never expires.
    fn rev(list_key: &str) -> RevocationEntry {
        RevocationEntry {
            list_key: list_key.to_owned(),
            expires_at: None,
        }
    }

    #[test]
    fn new_store_returns_empty_collections() {
        let store = InMemoryFfiTrustStore::new();
        assert!(
            store
                .get_cached_attestations("ctx-1", "did:key:test")
                .unwrap()
                .is_empty()
        );
        assert!(store.get_revocation_state("ctx-1").unwrap().is_empty());
        assert!(
            store
                .get_challenge_results("ctx-1", "did:key:test")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn revocation_state_roundtrip() {
        let store = InMemoryFfiTrustStore::new();
        store
            .add_revocations("ctx-1", &[rev("att-1"), rev("att-2")], 1000)
            .unwrap();
        let retrieved = store.get_revocation_state("ctx-1").unwrap();
        let expected: HashMap<String, bool> =
            [("att-1".to_owned(), true), ("att-2".to_owned(), true)]
                .into_iter()
                .collect();
        assert_eq!(retrieved, expected);
    }

    /// SECURITY (lost update, issue #2335 bug-catcher item 8). Two callers on
    /// one context each read that context's revocation list, then each record a
    /// revocation. Both revocations must survive. `add_revocations` delivers
    /// that because it adds the keys it names; rebuilding a whole map from an
    /// earlier read and writing that map back does not, because each caller's
    /// copy is stale about the other caller's key, and a dropped revocation lets
    /// a revoked attestation count again. Both reads happen BEFORE either write,
    /// which is the interleaving that loses an update.
    #[test]
    fn two_interleaved_callers_both_keep_their_revocation() {
        let store = InMemoryFfiTrustStore::new();
        let context_id = "ctx-interleaved";
        let first_key = revocation_list_key(&scp_did::DID::from("did:key:first"), "att-first");
        let second_key = revocation_list_key(&scp_did::DID::from("did:key:second"), "att-second");

        // Both callers read the same empty list.
        let first_read = store.get_revocation_state(context_id).unwrap();
        let second_read = store.get_revocation_state(context_id).unwrap();
        assert!(first_read.is_empty());
        assert!(second_read.is_empty());

        // Then both write.
        store
            .add_revocations(context_id, &[rev(&first_key)], 1000)
            .unwrap();
        store
            .add_revocations(context_id, &[rev(&second_key)], 1000)
            .unwrap();

        let state = store.get_revocation_state(context_id).unwrap();
        assert_eq!(
            state.get(&first_key),
            Some(&true),
            "the first caller's revocation must survive the second caller's write, list reads {state:?}"
        );
        assert_eq!(
            state.get(&second_key),
            Some(&true),
            "the second caller's revocation must be recorded, list reads {state:?}"
        );
    }

    #[test]
    fn attestation_cache_deduplicates_by_id() {
        let store = InMemoryFfiTrustStore::new();
        let att = make_attestation("att-1", "did:key:alice");

        let entry1 = CachedAttestation {
            attestation: att.clone(),
            verified_at: 1000,
            ttl_secs: 300,
        };
        store.store_cached_attestation("ctx-1", entry1).unwrap();

        // Cache the same attestation ID again with updated verified_at.
        let entry2 = CachedAttestation {
            attestation: att,
            verified_at: 2000,
            ttl_secs: 300,
        };
        store.store_cached_attestation("ctx-1", entry2).unwrap();

        // Should have exactly 1 entry (deduplicated by ID), with updated timestamp.
        let cached = store
            .get_cached_attestations("ctx-1", "did:key:alice")
            .unwrap();
        assert_eq!(cached.len(), 1);
        assert_eq!(cached[0].verified_at, 2000);
    }

    // -----------------------------------------------------------------------
    // Integration test helpers
    // -----------------------------------------------------------------------

    fn make_attestation(id: &str, subject: &str) -> scp_core::trust::Attestation {
        scp_core::trust::Attestation {
            id: id.to_owned(),
            attestation_type: AttestationType::Endorsement,
            issuer: "did:key:bob".into(),
            subject: subject.into(),
            claim: serde_json::json!({"skill": "rust", "level": "expert"}),
            evidence: None,
            issued_at: 1000,
            expires_at: Some(10_000),
            renewal_interval: None,
            revocation_status: RevocationStatus::Active,
            signature: vec![0u8; 64],
            renewed_at: None,
        }
    }

    /// The capability every challenge-result test record names.
    const CHALLENGE_URI: &str = "scp:capability:schema-validation/v1";

    /// An `expires_at` 30 days past the real clock, within the 90-day
    /// validity bound, for records that must stay live at ingest (which reads
    /// the system clock).
    fn live_expiry() -> u64 {
        scp_clock::SystemClock.now_secs() + 30 * 86_400
    }

    /// Builds a challenge record with a derived `verification_id`, its
    /// `timestamp` one day before `expires_at`, and an empty signature.
    fn unsigned_challenge(
        verifier_key: &ed25519_dalek::SigningKey,
        subject: &str,
        record_context: Option<&str>,
        expires_at: u64,
    ) -> ChallengeVerification {
        let verifier = scp_did::did_dht_from_public_key(&verifier_key.verifying_key().to_bytes());
        let subject = scp_did::DID::from(subject);
        let timestamp = expires_at.saturating_sub(86_400);
        ChallengeVerification {
            verification_id: scp_core::trust::challenge_verification_id(
                &verifier,
                &subject,
                CHALLENGE_URI,
                timestamp,
            )
            .unwrap(),
            verifier,
            subject,
            capability_uri: CHALLENGE_URI.to_owned(),
            suite_digest: [0x5d; 32],
            passed: true,
            score: Some(95),
            test_count: 1,
            pass_count: 1,
            timestamp,
            expires_at,
            context_id: record_context.map(ToOwned::to_owned),
            verifier_signature: Vec::new(),
            verification_method: VerificationMethod::ChallengeVerified {
                challenge_type: ChallengeType::schema_validation(),
            },
            result: serde_json::json!({"passed": true}),
            completed_at: timestamp,
        }
    }

    /// Signs `cv` over its `D_v` with the [`make_genuinely_signed_challenge_with`]
    /// verifier key.
    fn sign_challenge(mut cv: ChallengeVerification) -> ChallengeVerification {
        use ed25519_dalek::Signer;
        let digest = scp_core::trust::challenge_verification_signing_digest(&cv).unwrap();
        cv.verifier_signature = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32])
            .sign(&digest)
            .to_bytes()
            .to_vec();
        cv
    }

    /// A `ChallengeVerification` that is FORGED only in its signature: its
    /// verifier DID resolves, its id is derived, its `context_id` matches the
    /// ingest context and it is live, but the `verifier_signature` is all
    /// zeros, so a correct gate drops it solely because the signature does not
    /// verify.
    fn make_challenge_result(subject: &str, context_id: &str) -> ChallengeVerification {
        let mut cv = unsigned_challenge(
            &ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]),
            subject,
            Some(context_id),
            live_expiry(),
        );
        cv.verifier_signature = vec![0u8; 64];
        cv
    }

    /// Produces a GENUINELY verifier-signed [`ChallengeVerification`] with the
    /// record's signed `context_id` set to `record_context` and the signed
    /// `expires_at` set to `expires_at`. The verifier DID is a `did:dht:z`
    /// whose identity key is the signing key, so
    /// `IdentityDidPublicKeyResolver` resolves it. By varying
    /// `record_context`/`expires_at` the caller exercises the context-binding
    /// and expiry gates with an otherwise-valid record.
    fn make_genuinely_signed_challenge_with(
        subject: &str,
        record_context: Option<&str>,
        expires_at: u64,
    ) -> ChallengeVerification {
        sign_challenge(unsigned_challenge(
            &ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]),
            subject,
            record_context,
            expires_at,
        ))
    }

    /// Convenience: a genuinely-signed, in-context, live challenge.
    fn make_genuinely_signed_challenge(subject: &str, context_id: &str) -> ChallengeVerification {
        make_genuinely_signed_challenge_with(subject, Some(context_id), live_expiry())
    }

    fn make_event(event_type: EventType, actor: &str, ts: u64, seq: u64, data: Vec<u8>) -> Event {
        Event {
            event_type,
            actor_did: actor.into(),
            timestamp: ts,
            sequence: seq,
            payload: EventPayload { data },
            prev_hash: [0u8; 32],
            signature: vec![0u8; 64],
        }
    }

    /// Resolver that returns a dummy key — attestation cache holds already-verified
    /// (non-expired) entries, so the resolver is not called for fresh entries.
    struct NoOpResolver;
    impl scp_core::trust::attestation::DidPublicKeyResolver for NoOpResolver {
        fn resolve_public_key(&self, _did: &str) -> Result<Vec<u8>, TrustError> {
            Ok(vec![0u8; 32])
        }
    }

    /// Resolver that returns the public key for the verifier DID used by
    /// [`make_genuinely_signed_challenge_with`] (signing key `[3u8; 32]`), so a
    /// genuinely-signed challenge result re-validates on the aggregation read
    /// path (Fix 1). Fresh cached attestations are not re-verified, so the
    /// resolver is only consulted for the challenge result here.
    struct GenuineVerifierResolver;
    impl scp_core::trust::attestation::DidPublicKeyResolver for GenuineVerifierResolver {
        fn resolve_public_key(&self, _did: &str) -> Result<Vec<u8>, TrustError> {
            Ok(ed25519_dalek::SigningKey::from_bytes(&[3u8; 32])
                .verifying_key()
                .to_bytes()
                .to_vec())
        }
    }

    // -----------------------------------------------------------------------
    // Integration test: full aggregation pipeline
    // -----------------------------------------------------------------------

    /// Exercises the full aggregation pipeline through `InMemoryFfiTrustStore`
    /// with real data — events, cached attestations, challenge results, and
    /// consequence rules — verifying the aggregated `TrustInput` output.
    #[test]
    fn aggregate_pipeline_with_populated_store() {
        use scp_clock::TestClock;
        use scp_core::context::roles::Capability;
        use scp_core::trust::ConsequenceRule;
        use scp_core::trust::aggregate::{AggregationContext, AttestationCache};
        use scp_core::trust::consequence::{
            ConsequenceAction, ConsequenceTrigger, EnforcementSeverity,
        };

        let context_id = "ctx-integration";
        let subject_did = "did:key:alice";
        let clock = TestClock::new(2000);
        // Resolves the genuine challenge verifier key so the read-path
        // re-validation (Fix 1) keeps the genuinely-signed challenge result.
        let resolver = GenuineVerifierResolver;

        // --- Populate the store ---
        let store = InMemoryFfiTrustStore::new();

        let cached_att = CachedAttestation {
            attestation: make_attestation("att-integration-1", subject_did),
            verified_at: 1900, // fresh: 1900 + 600 = 2500 > 2000
            ttl_secs: 600,
        };
        store
            .store_cached_attestation(context_id, cached_att)
            .unwrap();

        // A genuinely verifier-signed, in-context challenge result so it survives
        // the aggregation read-path re-validation.
        let cr = make_genuinely_signed_challenge(subject_did, context_id);
        store.store_challenge_result(context_id, &cr).unwrap();

        // --- Build events ---
        let events = vec![
            make_event(EventType::MessageSent, subject_did, 1000, 0, vec![]),
            make_event(EventType::MessageSent, subject_did, 1200, 1, vec![]),
            make_event(EventType::GovernanceAction, subject_did, 1400, 2, vec![]),
            make_event(
                EventType::OutletInvoked,
                subject_did,
                1600,
                3,
                b"review-outlet".to_vec(),
            ),
        ];

        let consequence_rules = vec![ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendCapability {
                capabilities: vec![Capability::MessagesWrite],
            }),
            threshold: 100,
            window: std::time::Duration::from_hours(1),
        }];

        let threshold_requirements = HashMap::new();
        let attestor_sets = HashMap::new();
        let cache = AttestationCache::new(store);

        // --- Run aggregation ---
        let ctx = AggregationContext {
            context_id,
            subject_did,
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

        let input = scp_core::trust::aggregate::aggregate_trust_input(&ctx).unwrap();

        // --- Verify aggregated output ---
        assert_eq!(input.participation_record.subject_did, subject_did);
        assert_eq!(input.participation_record.context_id, context_id);
        assert_eq!(input.participation_record.participation_count, 4);
        assert_eq!(
            input
                .participation_record
                .outlet_invocations
                .get("review-outlet"),
            Some(&1)
        );

        assert_eq!(input.verified_attestations.len(), 1);
        assert_eq!(input.verified_attestations[0].id, "att-integration-1");
        assert_eq!(
            input.verified_attestations[0].attestation_type,
            AttestationType::Endorsement
        );

        assert_eq!(input.challenge_results.len(), 1);
        assert_eq!(
            input.challenge_results[0].verification_id,
            cr.verification_id
        );
        assert_eq!(input.challenge_results[0].capability_uri, CHALLENGE_URI);
        assert!(input.challenge_results[0].passed);
        assert_eq!(input.challenge_results[0].score, Some(95));

        assert_eq!(input.consequence_structure.len(), 1);
        assert!(input.threshold_counts.is_empty());

        // Verify JSON serialization (as the FFI bridges do).
        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("att-integration-1"));
        assert!(json.contains(&hex::encode(cr.verification_id)));
    }

    /// Builds a caller-supplied attestation that an attacker has marked "fresh"
    /// (`verified_at`/`ttl_secs` maxed out) but whose signature is forged and
    /// whose issuer is attacker-chosen.
    fn make_forged_fresh_cached(subject: &str) -> CachedAttestation {
        CachedAttestation {
            attestation: scp_core::trust::Attestation {
                id: "forged-fresh-1".to_owned(),
                attestation_type: AttestationType::Endorsement,
                // Attacker-chosen issuer; the signature below does not authenticate
                // the attestation under this issuer's key.
                issuer: "did:key:00000000000000000000000000000000000000000000000000000000000000ff"
                    .into(),
                subject: subject.into(),
                claim: serde_json::json!({"skill": "rust", "level": "expert"}),
                evidence: None,
                issued_at: 1,
                expires_at: Some(u64::MAX),
                renewal_interval: None,
                revocation_status: RevocationStatus::Active,
                signature: vec![0u8; 64],
                renewed_at: None,
            },
            // The attacker asserts "verified just now, valid forever" — exactly the
            // metadata the old raw-store path trusted on the caller's say-so.
            verified_at: u64::MAX,
            ttl_secs: u64::MAX,
        }
    }

    /// SECURITY (verify-on-ingest, Finding 1). A caller-supplied attestation
    /// marked fresh with a FORGED signature MUST NOT be returned by
    /// `verified_attestations`: every caller entry is re-verified against the
    /// resolver-resolved issuer key before it can be counted, so the forgery is
    /// dropped (`attestation_count == 0`) rather than trusted on the caller's
    /// metadata. Pre-fix, the raw-store path returned the fresh-marked entry
    /// unverified (count 1).
    #[test]
    fn forged_fresh_attestation_excluded_by_verified_attestations() {
        let context_id = "ctx-forgery";
        let subject_did =
            "did:key:11111111111111111111111111111111111111111111111111111111111111aa";

        let store = InMemoryFfiTrustStore::new();
        let verified = verified_attestations(
            store,
            context_id,
            subject_did,
            vec![make_forged_fresh_cached(subject_did)],
        )
        .unwrap();

        assert!(
            verified.is_empty(),
            "forged fresh attestation must be excluded on ingest, got {} entry/entries",
            verified.len()
        );
    }

    /// SECURITY (verify-on-ingest, Finding 1). The same exclusion holds through
    /// the full `populate_and_aggregate` path: the serialized `TrustInput` carries
    /// no verified attestations for a forged fresh entry, so `attestation_count`
    /// cannot be inflated and the durable store is not poisoned.
    #[test]
    fn forged_fresh_attestation_excluded_by_populate_and_aggregate() {
        let context_id = "ctx-forgery-agg";
        let subject_did =
            "did:key:22222222222222222222222222222222222222222222222222222222222222bb";

        // One real event so the participation record computes (an empty log would
        // short-circuit with EmptyEventLog before attestation aggregation).
        let events = vec![make_event(
            EventType::MessageSent,
            subject_did,
            1000,
            0,
            vec![],
        )];

        let store = InMemoryFfiTrustStore::new();
        let json = populate_and_aggregate(
            store,
            &scp_core::trust::IdentityDidPublicKeyResolver,
            context_id,
            subject_did,
            vec![make_forged_fresh_cached(subject_did)],
            &[],
            &events,
            [0u8; 32],
            &[],
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let attestations = parsed["verified_attestations"].as_array().unwrap();
        assert!(
            attestations.is_empty(),
            "forged fresh attestation must not survive aggregation, got {} entry/entries",
            attestations.len()
        );
    }

    /// Builds a genuinely Ed25519-signed `Endorsement` attestation whose issuer
    /// DID resolves (a production `did:dht:z` DID derived from the signing key),
    /// signed over the real `canonical_attestation_bytes`.
    fn make_genuinely_signed(
        id: &str,
        subject: &str,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> scp_core::trust::Attestation {
        use ed25519_dalek::Signer;
        let pubkey: [u8; 32] = signing_key.verifying_key().to_bytes();
        let issuer = scp_did::did_dht_from_public_key(&pubkey);
        let mut att = scp_core::trust::Attestation {
            id: id.to_owned(),
            attestation_type: AttestationType::Endorsement,
            issuer,
            subject: subject.into(),
            claim: serde_json::json!({"skill": "rust", "level": "expert"}),
            evidence: None,
            issued_at: 1000,
            expires_at: Some(u64::MAX),
            renewal_interval: None,
            revocation_status: RevocationStatus::Active,
            signature: Vec::new(),
            renewed_at: None,
        };
        let canonical = scp_core::trust::canonical_attestation_bytes(&att).unwrap();
        att.signature = signing_key.sign(&canonical).to_bytes().to_vec();
        att
    }

    /// POSITIVE verify-on-ingest (Finding 9). A genuinely-signed attestation with
    /// a resolvable issuer DID MUST survive ingest and be counted — guarding
    /// against an over-strict regression in `verify_and_cache`
    /// that the forgery-only tests above could not catch (they pass whether the
    /// verifier accepts valid signatures or rejects everything).
    #[test]
    fn genuinely_signed_attestation_counted_by_verified_attestations() {
        let context_id = "ctx-genuine";
        let subject_did =
            "did:key:33333333333333333333333333333333333333333333333333333333333333cc";
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let att = make_genuinely_signed("genuine-1", subject_did, &signing_key);

        let store = InMemoryFfiTrustStore::new();
        let verified = verified_attestations(
            store,
            context_id,
            subject_did,
            vec![CachedAttestation {
                attestation: att,
                verified_at: 0,
                ttl_secs: u64::MAX,
            }],
        )
        .unwrap();

        assert_eq!(
            verified.len(),
            1,
            "genuinely-signed attestation must survive verify-on-ingest"
        );
        assert_eq!(verified[0].id, "genuine-1");
    }

    /// POSITIVE verify-on-ingest through the full `populate_and_aggregate` path:
    /// a genuinely-signed attestation IS present in the serialized `TrustInput`.
    #[test]
    fn genuinely_signed_attestation_counted_by_populate_and_aggregate() {
        let context_id = "ctx-genuine-agg";
        let subject_did =
            "did:key:44444444444444444444444444444444444444444444444444444444444444dd";
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let att = make_genuinely_signed("genuine-agg-1", subject_did, &signing_key);

        let events = vec![make_event(
            EventType::MessageSent,
            subject_did,
            1000,
            0,
            vec![],
        )];

        let store = InMemoryFfiTrustStore::new();
        let json = populate_and_aggregate(
            store,
            &scp_core::trust::IdentityDidPublicKeyResolver,
            context_id,
            subject_did,
            vec![CachedAttestation {
                attestation: att,
                verified_at: 0,
                ttl_secs: u64::MAX,
            }],
            &[],
            &events,
            [0u8; 32],
            &[],
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let attestations = parsed["verified_attestations"].as_array().unwrap();
        assert_eq!(
            attestations.len(),
            1,
            "genuinely-signed attestation must survive aggregation"
        );
        assert_eq!(attestations[0]["id"], "genuine-agg-1");
    }

    /// SECURITY verify-on-ingest for challenge results (Finding 2). A
    /// caller-supplied `ChallengeVerification` with `passed = true` but a forged
    /// (here, all-zero) verifier signature MUST be dropped — its verifier
    /// signature does not verify against the resolved verifier key — so it never
    /// reaches `TrustInput.challenge_results` to be consumed as an admission/
    /// trust signal. Pre-fix, challenge results were stored raw and counted.
    #[test]
    fn forged_challenge_result_excluded_by_populate_and_aggregate() {
        let context_id = "ctx-challenge-forgery";
        let subject_did =
            "did:key:55555555555555555555555555555555555555555555555555555555555555ee";

        // `passed = true`, but the verifier signature is forged (zeros) and the
        // verifier DID is attacker-chosen — the signature cannot authenticate.
        let forged = make_challenge_result(subject_did, context_id);

        let events = vec![make_event(
            EventType::MessageSent,
            subject_did,
            1000,
            0,
            vec![],
        )];

        let store = InMemoryFfiTrustStore::new();
        let json = populate_and_aggregate(
            store,
            &scp_core::trust::IdentityDidPublicKeyResolver,
            context_id,
            subject_did,
            vec![],
            &[forged],
            &events,
            [0u8; 32],
            &[],
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let challenge_results = parsed["challenge_results"].as_array().unwrap();
        assert!(
            challenge_results.is_empty(),
            "forged challenge result must not survive verify-on-ingest, got {} entry/entries",
            challenge_results.len()
        );
    }

    /// POSITIVE verify-on-ingest for challenge results: a GENUINELY
    /// verifier-signed, in-context, unexpired `ChallengeVerification` MUST
    /// survive ingest and reach `TrustInput.challenge_results`. Without this, the
    /// forgery-only test above would also pass against a gate that rejects
    /// everything; this pins that the gate accepts valid records.
    #[test]
    fn genuinely_signed_challenge_survives_populate_and_aggregate() {
        let context_id = "ctx-challenge-genuine";
        let subject_did =
            "did:key:66666666666666666666666666666666666666666666666666666666666666ff";

        let genuine = make_genuinely_signed_challenge(subject_did, context_id);

        let events = vec![make_event(
            EventType::MessageSent,
            subject_did,
            1000,
            0,
            vec![],
        )];

        let store = InMemoryFfiTrustStore::new();
        let json = populate_and_aggregate(
            store,
            &scp_core::trust::IdentityDidPublicKeyResolver,
            context_id,
            subject_did,
            vec![],
            std::slice::from_ref(&genuine),
            &events,
            [0u8; 32],
            &[],
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let challenge_results = parsed["challenge_results"].as_array().unwrap();
        assert_eq!(
            challenge_results.len(),
            1,
            "genuinely-signed, in-context, unexpired challenge must survive ingest"
        );
        assert_eq!(
            challenge_results[0]["verification_id"],
            hex::encode(genuine.verification_id)
        );
        assert_eq!(challenge_results[0]["capability_uri"], CHALLENGE_URI);
    }

    /// SECURITY (verify-on-ingest, expiry binding). A genuinely verifier-signed
    /// challenge result whose `expires_at` is in the PAST (relative to the real
    /// ingest clock) MUST be dropped — an expired verification is not a current
    /// trust signal (spec §7.3.4). The signature is valid, so this isolates the
    /// expiry gate.
    #[test]
    fn expired_challenge_result_dropped_at_ingest() {
        let context_id = "ctx-challenge-expired";
        let subject_did =
            "did:key:77777777777777777777777777777777777777777777777777777777777777ff";

        // expires_at = 1000 is far below the real system clock used at ingest.
        let expired = make_genuinely_signed_challenge_with(subject_did, Some(context_id), 1000);

        let events = vec![make_event(
            EventType::MessageSent,
            subject_did,
            1000,
            0,
            vec![],
        )];

        let store = InMemoryFfiTrustStore::new();
        let json = populate_and_aggregate(
            store,
            &scp_core::trust::IdentityDidPublicKeyResolver,
            context_id,
            subject_did,
            vec![],
            &[expired],
            &events,
            [0u8; 32],
            &[],
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let challenge_results = parsed["challenge_results"].as_array().unwrap();
        assert!(
            challenge_results.is_empty(),
            "expired challenge result must be dropped at ingest, got {} entry/entries",
            challenge_results.len()
        );
    }

    /// SECURITY (verify-on-ingest, context binding). A genuinely verifier-signed
    /// challenge result minted for a DIFFERENT context MUST NOT be replayed into
    /// this context's aggregation. The signature is valid (and binds the signed
    /// `context_id`), so this isolates the cross-context replay gate.
    #[test]
    fn cross_context_challenge_result_dropped_at_ingest() {
        let ingest_context = "ctx-challenge-target";
        let other_context = "ctx-challenge-origin";
        let subject_did =
            "did:key:88888888888888888888888888888888888888888888888888888888888888ff";

        // Genuinely signed, unexpired — but bound to `other_context`.
        let foreign =
            make_genuinely_signed_challenge_with(subject_did, Some(other_context), live_expiry());

        let events = vec![make_event(
            EventType::MessageSent,
            subject_did,
            1000,
            0,
            vec![],
        )];

        let store = InMemoryFfiTrustStore::new();
        let json = populate_and_aggregate(
            store,
            &scp_core::trust::IdentityDidPublicKeyResolver,
            ingest_context,
            subject_did,
            vec![],
            &[foreign],
            &events,
            [0u8; 32],
            &[],
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let challenge_results = parsed["challenge_results"].as_array().unwrap();
        assert!(
            challenge_results.is_empty(),
            "cross-context challenge result must be dropped at ingest, got {} entry/entries",
            challenge_results.len()
        );
    }

    /// SECURITY (read-path revocation, white-hat P1). A cached attestation that
    /// is FRESH (within cache TTL) but has since been CONTEXT-revoked MUST be
    /// excluded from `get_verified_attestations` on the read path — not only at
    /// ingest. Without the read-path revocation check, a later-revoked entry
    /// keeps inflating trust until its cache TTL expires (fail-open). The control
    /// assertion (present before revocation) proves the entry is otherwise fresh
    /// and returned, so the exclusion is attributable to revocation alone.
    #[test]
    fn context_revoked_fresh_attestation_excluded_from_read_path() {
        use scp_clock::TestClock;

        let context_id = "ctx-revoke-read";
        let subject_did = "did:key:alice-revoke";

        let store = InMemoryFfiTrustStore::new();
        // Cache a fresh attestation directly (raw store). `ttl_secs = u64::MAX`
        // keeps it fresh forever, so any exclusion is due to revocation, not TTL.
        store
            .store_cached_attestation(
                context_id,
                CachedAttestation {
                    attestation: make_attestation("att-revoked", subject_did),
                    verified_at: 1000,
                    ttl_secs: u64::MAX,
                },
            )
            .unwrap();

        let cache = scp_core::trust::aggregate::AttestationCache::new(store);
        let resolver = NoOpResolver; // fresh entries are not re-verified
        let clock = TestClock::new(2000);

        // Control: present while not revoked.
        let before = cache
            .get_verified_attestations(context_id, subject_did, &resolver, &clock)
            .unwrap();
        assert_eq!(before.len(), 1, "fresh attestation should be returned");

        // Context-revoke the entry, then read again. The key binds the revoked
        // id to the issuer that `make_attestation` names.
        let key = revocation_list_key(&scp_did::DID::from("did:key:bob"), "att-revoked");
        cache
            .store()
            .add_revocations(context_id, &[rev(&key)], 2000)
            .unwrap();

        let after = cache
            .get_verified_attestations(context_id, subject_did, &resolver, &clock)
            .unwrap();
        assert!(
            after.is_empty(),
            "context-revoked fresh attestation must be excluded on the read path, got {}",
            after.len()
        );
    }

    // -----------------------------------------------------------------------
    // Revocation write-back (§7.4.4)
    // -----------------------------------------------------------------------

    /// Builds a genuinely Ed25519-signed attestation that carries an
    /// issuer-signed revocation of itself: `revocation_status` reads
    /// `Revoked { .. }`, `revoked_by` equals `issuer`, and `signature` covers
    /// those bytes. This is what §7.4.4 of
    /// `.docs/specs/07-trust-validation-and-capabilities.md` tells an issuer to
    /// republish when that issuer revokes.
    fn make_genuinely_signed_revoked(
        id: &str,
        subject: &str,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> scp_core::trust::Attestation {
        use ed25519_dalek::Signer;
        let pubkey: [u8; 32] = signing_key.verifying_key().to_bytes();
        let issuer = scp_did::did_dht_from_public_key(&pubkey);
        let mut att = scp_core::trust::Attestation {
            id: id.to_owned(),
            attestation_type: AttestationType::Endorsement,
            issuer: issuer.clone(),
            subject: subject.into(),
            claim: serde_json::json!({"skill": "rust", "level": "expert"}),
            evidence: None,
            issued_at: 1000,
            expires_at: Some(u64::MAX),
            renewal_interval: None,
            revocation_status: RevocationStatus::Revoked {
                revoked_at: 2000,
                reason: "issuer withdrew this endorsement".to_owned(),
                revoked_by: issuer,
            },
            signature: Vec::new(),
            renewed_at: None,
        };
        let canonical = scp_core::trust::canonical_attestation_bytes(&att).unwrap();
        att.signature = signing_key.sign(&canonical).to_bytes().to_vec();
        att
    }

    /// Test-only handle that lets two `verified_attestations` calls share ONE
    /// underlying store. `verified_attestations` takes its store by value, and
    /// `TrustProtocolRepository` carries no blanket implementation for a
    /// reference, so each call receives a clone of this `Arc` handle over one
    /// [`InMemoryFfiTrustStore`]. Cloning a handle keeps every entry that an
    /// earlier call wrote.
    #[derive(Clone)]
    struct SharedFfiStore(std::sync::Arc<InMemoryFfiTrustStore>);

    impl SharedFfiStore {
        fn new() -> Self {
            Self(std::sync::Arc::new(InMemoryFfiTrustStore::new()))
        }
    }

    impl TrustProtocolRepository for SharedFfiStore {
        fn get_cached_attestations(
            &self,
            context_id: &str,
            subject_did: &str,
        ) -> Result<Vec<CachedAttestation>, TrustError> {
            self.0.get_cached_attestations(context_id, subject_did)
        }

        fn store_cached_attestation(
            &self,
            context_id: &str,
            entry: CachedAttestation,
        ) -> Result<(), TrustError> {
            self.0.store_cached_attestation(context_id, entry)
        }

        fn get_revocation_state(
            &self,
            context_id: &str,
        ) -> Result<HashMap<String, bool>, TrustError> {
            self.0.get_revocation_state(context_id)
        }

        fn add_revocations(
            &self,
            context_id: &str,
            entries: &[RevocationEntry],
            now: u64,
        ) -> Result<(), TrustError> {
            self.0.add_revocations(context_id, entries, now)
        }

        fn get_challenge_results(
            &self,
            context_id: &str,
            subject_did: &str,
        ) -> Result<Vec<ChallengeVerification>, TrustError> {
            self.0.get_challenge_results(context_id, subject_did)
        }

        fn store_challenge_result(
            &self,
            context_id: &str,
            result: &ChallengeVerification,
        ) -> Result<(), TrustError> {
            self.0.store_challenge_result(context_id, result)
        }
    }

    /// The ingest path records an issuer-signed revocation through
    /// `add_revocations`, the only revocation writer `TrustProtocolRepository`
    /// offers, with the revoked attestation's own expiry, so the record is
    /// pruned once that attestation can no longer verify.
    #[test]
    fn ingest_records_a_revocation_with_its_attestations_expiry() {
        let context_id = "ctx-merge-only";
        let subject_did =
            "did:key:3333333333333333333333333333333333333333333333333333333333333399";
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[71u8; 32]);
        let revoked_copy = make_genuinely_signed_revoked("att-merge-1", subject_did, &signing_key);

        let inner = SharedFfiStore::new();
        let verified = verified_attestations(
            inner.clone(),
            context_id,
            subject_did,
            vec![fresh_entry(revoked_copy)],
        )
        .expect("ingest must record a revocation");
        assert!(verified.is_empty(), "a revoked attestation is not counted");

        let issuer = scp_did::did_dht_from_public_key(&signing_key.verifying_key().to_bytes());
        let state = inner.get_revocation_state(context_id).unwrap();
        assert_eq!(
            state.get(&revocation_list_key(&issuer, "att-merge-1")),
            Some(&true),
            "the merge write must have recorded the revocation, list reads {state:?}"
        );
        let records = inner.0.revocations.lock().unwrap();
        assert_eq!(
            records[context_id].get(&revocation_list_key(&issuer, "att-merge-1")),
            Some(&Some(u64::MAX)),
            "the record must carry the revoked attestation's own expires_at"
        );
    }

    /// Test-only store whose revocation write, `add_revocations`, fails with
    /// an INFRA fault (`StoreError`, a variant
    /// outside `TrustError::is_record_rejection`). Every other method delegates to a
    /// working [`SharedFfiStore`], so a test that feeds it an issuer-signed
    /// revoked attestation isolates a revocation-list write failure.
    struct RevocationWriteFailsStore(SharedFfiStore);

    impl TrustProtocolRepository for RevocationWriteFailsStore {
        fn get_cached_attestations(
            &self,
            context_id: &str,
            subject_did: &str,
        ) -> Result<Vec<CachedAttestation>, TrustError> {
            self.0.get_cached_attestations(context_id, subject_did)
        }

        fn store_cached_attestation(
            &self,
            context_id: &str,
            entry: CachedAttestation,
        ) -> Result<(), TrustError> {
            self.0.store_cached_attestation(context_id, entry)
        }

        fn get_revocation_state(
            &self,
            context_id: &str,
        ) -> Result<HashMap<String, bool>, TrustError> {
            self.0.get_revocation_state(context_id)
        }

        fn add_revocations(
            &self,
            _context_id: &str,
            _entries: &[RevocationEntry],
            _now: u64,
        ) -> Result<(), TrustError> {
            Err(TrustError::StoreError {
                reason: "revocation-state write failed".to_owned(),
            })
        }

        fn get_challenge_results(
            &self,
            context_id: &str,
            subject_did: &str,
        ) -> Result<Vec<ChallengeVerification>, TrustError> {
            self.0.get_challenge_results(context_id, subject_did)
        }

        fn store_challenge_result(
            &self,
            context_id: &str,
            result: &ChallengeVerification,
        ) -> Result<(), TrustError> {
            self.0.store_challenge_result(context_id, result)
        }
    }

    /// Wraps an attestation as a caller-supplied cache entry marked fresh
    /// forever, so no TTL or freshness effect can explain a later exclusion.
    fn fresh_entry(attestation: scp_core::trust::Attestation) -> CachedAttestation {
        CachedAttestation {
            attestation,
            verified_at: 0,
            ttl_secs: u64::MAX,
        }
    }

    /// SECURITY (revocation write-back, §7.4.4, issue #2335 finding 13).
    /// Ingesting an issuer-signed revoked attestation records that attestation's
    /// id, so a LATER ingest of a pre-revocation `Active`-status copy carrying
    /// that same id yields nothing. Without a writer on the ingest path, a holder
    /// who kept a pre-revocation copy gets it counted again: that second copy
    /// verifies (genuine signature, unexpired, own status `Active`) and no
    /// shipped reader knows an issuer revoked it.
    #[test]
    fn issuer_signed_revocation_bars_a_later_pre_revocation_copy() {
        let context_id = "ctx-revocation-writeback";
        let subject_did =
            "did:key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa11";
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]);

        // One issuer, one attestation id, two signed copies: a republished
        // revoked copy, and a pre-revocation copy that still reads `Active`.
        let revoked_copy =
            make_genuinely_signed_revoked("att-writeback-1", subject_did, &signing_key);
        let active_copy = make_genuinely_signed("att-writeback-1", subject_did, &signing_key);

        let store = SharedFfiStore::new();

        let first = verified_attestations(
            store.clone(),
            context_id,
            subject_did,
            vec![fresh_entry(revoked_copy)],
        )
        .unwrap();
        assert!(
            first.is_empty(),
            "a revoked attestation must not be counted, got {} entry/entries",
            first.len()
        );

        let second = verified_attestations(
            store,
            context_id,
            subject_did,
            vec![fresh_entry(active_copy)],
        )
        .unwrap();
        assert!(
            second.is_empty(),
            "a pre-revocation copy of a revoked attestation id must stay uncounted, got {} entry/entries",
            second.len()
        );
    }

    /// SECURITY (issuer-scoped revocation, issue #2335 finding 13, ingest path).
    /// Two issuers can carry one attestation id, because §7.4.1 of
    /// `.docs/specs/07-trust-validation-and-capabilities.md` binds
    /// `Attestation.id` to no issuer. An attacker derives a DID from a fresh
    /// keypair at no cost and signs a self-revoking attestation that carries an
    /// honest issuer's id; that record verifies and satisfies both conditions of
    /// `is_issuer_signed_revocation`, so it reaches a context's revocation list.
    /// The honest issuer's attestation MUST still be counted afterwards. Keying
    /// that list on an id alone drops it instead, which hands any caller a
    /// suppression primitive against any attestation whose id it learns.
    #[test]
    fn one_issuers_revocation_leaves_another_issuers_attestation_counted() {
        let context_id = "ctx-cross-issuer-revocation";
        let subject_did =
            "did:key:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee55";
        let honest_key = ed25519_dalek::SigningKey::from_bytes(&[41u8; 32]);
        let attacker_key = ed25519_dalek::SigningKey::from_bytes(&[43u8; 32]);

        // One id, two issuers: an honest endorsement, and an attacker record
        // that revokes itself while carrying that same id.
        let shared_id = "endorsement-alice-2026";
        let attacker_revoked = make_genuinely_signed_revoked(shared_id, subject_did, &attacker_key);
        let honest_active = make_genuinely_signed(shared_id, subject_did, &honest_key);
        let honest_issuer = honest_active.issuer.clone();
        assert_ne!(
            attacker_revoked.issuer, honest_issuer,
            "the two issuers must differ for this test to exercise issuer scoping"
        );

        let store = SharedFfiStore::new();

        let attacker_pass = verified_attestations(
            store.clone(),
            context_id,
            subject_did,
            vec![fresh_entry(attacker_revoked)],
        )
        .unwrap();
        assert!(
            attacker_pass.is_empty(),
            "a revoked attestation must not be counted, got {} entry/entries",
            attacker_pass.len()
        );

        let honest_pass = verified_attestations(
            store,
            context_id,
            subject_did,
            vec![fresh_entry(honest_active)],
        )
        .unwrap();
        assert_eq!(
            honest_pass.len(),
            1,
            "an attacker's revocation must not suppress another issuer's attestation carrying that id, got {honest_pass:?}"
        );
        assert_eq!(
            honest_pass[0].issuer, honest_issuer,
            "the surviving attestation must be the honest issuer's"
        );
    }

    /// SECURITY (issuer-scoped revocation, issue #2335 finding 13, read path).
    /// `AttestationCache::get_verified_attestations` applies the same issuer
    /// scoping as the ingest path: a revocation that one issuer signed leaves a
    /// CACHED attestation from a different issuer carrying that same id in the
    /// returned set. The control assertion (the attacker's own entry, dropped)
    /// proves the read path does consult the revocation list, so the survival of
    /// the honest entry is attributable to issuer scoping rather than to a
    /// checker that reports nothing.
    #[test]
    fn read_path_scopes_a_revocation_to_the_issuer_that_signed_it() {
        use scp_clock::TestClock;

        let context_id = "ctx-cross-issuer-read";
        let subject_did =
            "did:key:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff66";
        let shared_id = "endorsement-bob-2026";
        let honest_key = ed25519_dalek::SigningKey::from_bytes(&[47u8; 32]);
        let attacker_key = ed25519_dalek::SigningKey::from_bytes(&[53u8; 32]);

        let honest = make_genuinely_signed(shared_id, subject_did, &honest_key);
        // The attacker's copy carries the same id under a different issuer. Both
        // copies are cached in ONE store, because the cache keys an entry on its
        // issuer as well as its id, so neither replaces the other.
        let attacker = make_genuinely_signed(shared_id, subject_did, &attacker_key);
        let honest_issuer = honest.issuer.clone();
        let attacker_issuer = attacker.issuer.clone();

        let store = InMemoryFfiTrustStore::new();
        store
            .store_cached_attestation(context_id, fresh_entry(honest))
            .unwrap();
        store
            .store_cached_attestation(context_id, fresh_entry(attacker))
            .unwrap();
        assert_eq!(
            store
                .get_cached_attestations(context_id, subject_did)
                .unwrap()
                .len(),
            2,
            "one id from two issuers must be two cache entries"
        );
        // The attacker's revocation, recorded under the attacker's own DID.
        let attacker_list_key = revocation_list_key(&attacker_issuer, shared_id);
        store
            .add_revocations(context_id, &[rev(&attacker_list_key)], 2000)
            .unwrap();

        let cache = scp_core::trust::aggregate::AttestationCache::new(store);
        let resolver = scp_core::trust::IdentityDidPublicKeyResolver;
        let clock = TestClock::new(2000);

        let read = cache
            .get_verified_attestations(context_id, subject_did, &resolver, &clock)
            .unwrap();
        // The attacker's own entry is excluded by its revocation (the control
        // that proves the read path consults the list), and the honest entry
        // carrying the same id survives.
        assert_eq!(
            read.len(),
            1,
            "only the honest issuer's attestation may survive, got {read:?}"
        );
        assert_eq!(
            read[0].issuer, honest_issuer,
            "the surviving attestation must be the honest issuer's"
        );
    }

    /// SECURITY (issuer-scoped revocation, issue #2335 finding 13, own-issuer
    /// case). Issuer scoping must not cost an issuer the ability to revoke its
    /// own attestation: ingesting an issuer-signed revoked copy suppresses that
    /// SAME issuer's earlier `Active` copy carrying that id, on the next read.
    /// This is what commit cd24d8b98 closed, and issuer scoping keeps it closed.
    #[test]
    fn an_issuers_revocation_suppresses_that_issuers_own_earlier_active_copy() {
        let context_id = "ctx-own-issuer-revocation";
        let subject_did =
            "did:key:1111111111111111111111111111111111111111111111111111111111111177";
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[59u8; 32]);
        let shared_id = "endorsement-carol-2026";

        let active_copy = make_genuinely_signed(shared_id, subject_did, &signing_key);
        let revoked_copy = make_genuinely_signed_revoked(shared_id, subject_did, &signing_key);

        let store = SharedFfiStore::new();

        let before = verified_attestations(
            store.clone(),
            context_id,
            subject_did,
            vec![fresh_entry(active_copy)],
        )
        .unwrap();
        assert_eq!(
            before.len(),
            1,
            "the active copy must be counted before its issuer revokes it, got {before:?}"
        );

        let during = verified_attestations(
            store.clone(),
            context_id,
            subject_did,
            vec![fresh_entry(revoked_copy)],
        )
        .unwrap();
        assert!(
            during.is_empty(),
            "the revoked copy must not be counted, and the cached active copy must drop with it, got {during:?}"
        );

        // A later call that supplies nothing reads the cache alone, so the
        // revocation this ingest recorded is what excludes the cached copy.
        let after = verified_attestations(store, context_id, subject_did, vec![]).unwrap();
        assert!(
            after.is_empty(),
            "an issuer's own revocation must keep suppressing that issuer's cached copy, got {after:?}"
        );
    }

    /// SECURITY (revocation write-back, §7.4.4). Ingesting an issuer-signed
    /// revoked attestation writes that attestation's id into a context's
    /// revocation list, which is what both readers consult:
    /// a `RevocationMapChecker` on this ingest path and another inside
    /// `AttestationCache::get_verified_attestations`, a read path.
    #[test]
    fn issuer_signed_revocation_lands_in_the_context_revocation_list() {
        let context_id = "ctx-revocation-list";
        let subject_did =
            "did:key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb22";
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]);
        let revoked_copy = make_genuinely_signed_revoked("att-listed-1", subject_did, &signing_key);

        let store = SharedFfiStore::new();
        verified_attestations(
            store.clone(),
            context_id,
            subject_did,
            vec![fresh_entry(revoked_copy)],
        )
        .unwrap();

        let issuer = scp_did::did_dht_from_public_key(&signing_key.verifying_key().to_bytes());
        let state = store.get_revocation_state(context_id).unwrap();
        assert_eq!(
            state.get(&revocation_list_key(&issuer, "att-listed-1")),
            Some(&true),
            "an issuer-signed revocation must persist under its issuer plus its attestation id, list reads {state:?}"
        );
    }

    /// SECURITY (revocation write-back, forgery gate). A revoked-status
    /// attestation whose signature does not verify proves nothing, so it leaves a
    /// context's revocation list untouched. Otherwise any caller could suppress
    /// an honest subject's attestation by naming that attestation's id inside a
    /// forged revoked record.
    #[test]
    fn forged_revocation_leaves_the_context_revocation_list_unchanged() {
        let context_id = "ctx-revocation-forgery";
        let subject_did =
            "did:key:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc33";
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[29u8; 32]);

        // Issuer DID resolves and `revoked_by` equals `issuer`, so an all-zero
        // signature is what fails — no earlier gate masks a signature check.
        let mut forged = make_genuinely_signed_revoked("att-forged-1", subject_did, &signing_key);
        forged.signature = vec![0u8; 64];

        let store = SharedFfiStore::new();
        let verified = verified_attestations(
            store.clone(),
            context_id,
            subject_did,
            vec![fresh_entry(forged)],
        )
        .unwrap();
        assert!(verified.is_empty(), "a forged record must not be counted");

        let state = store.get_revocation_state(context_id).unwrap();
        assert!(
            state.is_empty(),
            "a forged revocation must not enter a context revocation list, list reads {state:?}"
        );
    }

    /// A failed `add_revocations` is an INFRA fault: `verified_attestations`
    /// propagates it instead of returning `Ok`. Swallowing it would drop a
    /// revocation this ingest just learned about, and a later ingest of a
    /// pre-revocation copy would then count that copy.
    #[test]
    fn revocation_list_write_failure_propagates() {
        let context_id = "ctx-revocation-write-fault";
        let subject_did =
            "did:key:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd44";
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[31u8; 32]);
        let revoked_copy = make_genuinely_signed_revoked("att-fault-1", subject_did, &signing_key);

        let store = RevocationWriteFailsStore(SharedFfiStore::new());
        let err = verified_attestations(
            store,
            context_id,
            subject_did,
            vec![fresh_entry(revoked_copy)],
        )
        .unwrap_err();

        assert!(
            matches!(&err, TrustError::StoreError { reason } if reason == "revocation-state write failed"),
            "expected a propagated StoreError raised by a revocation write, got {err:?}"
        );
    }

    /// SECURITY (write ordering, issue #2335 bug-catcher item 9). A failed
    /// revocation write leaves NOTHING cached. Caching accepted entries first
    /// would leave the opposite state — attestations durable, a discovered
    /// revocation absent — and a later call that omits the revoked copy would
    /// count every cached entry. The genuinely-signed second entry is what makes
    /// this assertion meaningful: it would be cached on a successful call, so an
    /// empty cache here reports ordering rather than a batch that cached nothing
    /// anyway.
    #[test]
    fn a_failed_revocation_write_leaves_nothing_cached() {
        let context_id = "ctx-revocation-write-order";
        let subject_did =
            "did:key:2222222222222222222222222222222222222222222222222222222222222288";
        let revoking_key = ed25519_dalek::SigningKey::from_bytes(&[61u8; 32]);
        let other_key = ed25519_dalek::SigningKey::from_bytes(&[67u8; 32]);

        let revoked_copy = make_genuinely_signed_revoked("att-order-1", subject_did, &revoking_key);
        let cacheable = make_genuinely_signed("att-order-2", subject_did, &other_key);

        let inner = SharedFfiStore::new();
        let store = RevocationWriteFailsStore(inner.clone());
        let err = verified_attestations(
            store,
            context_id,
            subject_did,
            vec![fresh_entry(revoked_copy), fresh_entry(cacheable)],
        )
        .unwrap_err();
        assert!(
            matches!(&err, TrustError::StoreError { reason } if reason == "revocation-state write failed"),
            "expected a propagated StoreError raised by a revocation write, got {err:?}"
        );

        let cached = inner
            .get_cached_attestations(context_id, subject_did)
            .unwrap();
        assert!(
            cached.is_empty(),
            "a failed revocation write must leave no cached attestation behind, cache holds {} entry/entries",
            cached.len()
        );
    }

    /// Fix C (classifier). The dedicated `CanonicalizationFailed` variant is
    /// classified as a verify-on-ingest REJECTION (drop the one entry), while
    /// infra faults are NOT (they propagate). `InvalidEventData`,
    /// `ChallengeSigningFailed` and `KeyResolutionUnavailable` are not
    /// rejections. Pins the classifier the ingest loops call.
    #[test]
    fn canonicalization_failures_are_rejections_infra_is_not() {
        assert!(
            TrustError::CanonicalizationFailed {
                reason: "claim serialization failed".to_owned(),
            }
            .is_record_rejection()
        );
        for infra in [
            TrustError::StoreError {
                reason: "lock poisoned".to_owned(),
            },
            TrustError::InvalidEventData {
                sequence: 0,
                reason: "unrelated".to_owned(),
            },
            TrustError::ChallengeSigningFailed {
                reason: "unrelated".to_owned(),
            },
            TrustError::KeyResolutionUnavailable {
                did: "did:dht:zX".to_owned(),
                reason: "offline".to_owned(),
            },
        ] {
            assert!(!infra.is_record_rejection(), "{infra:?}");
        }
    }

    /// Runs `populate_and_aggregate` over one caller-supplied challenge record
    /// and returns how many challenge results reached the output.
    fn populate_challenge_count(record: ChallengeVerification, context_id: &str) -> usize {
        let subject_did = record.subject.to_string();
        let events = vec![make_event(
            EventType::MessageSent,
            &subject_did,
            1000,
            0,
            vec![],
        )];
        let json = populate_and_aggregate(
            InMemoryFfiTrustStore::new(),
            &scp_core::trust::IdentityDidPublicKeyResolver,
            context_id,
            &subject_did,
            vec![],
            &[record],
            &events,
            [0u8; 32],
            &[],
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        parsed["challenge_results"].as_array().unwrap().len()
    }

    const POPULATE_SUBJECT: &str =
        "did:key:99999999999999999999999999999999999999999999999999999999999999ff";

    #[test]
    fn populate_drops_record_with_underived_verification_id() {
        // A genuinely signed record whose id is not derived from its fields is
        // dropped, not an aggregation failure.
        let ctx = "ctx-underived-id";
        let mut cv = unsigned_challenge(
            &ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]),
            POPULATE_SUBJECT,
            Some(ctx),
            live_expiry(),
        );
        cv.verification_id = [0x11; 32];
        assert_eq!(populate_challenge_count(sign_challenge(cv), ctx), 0);
        // Control: the same record with its derived id survives.
        assert_eq!(
            populate_challenge_count(
                make_genuinely_signed_challenge_with(POPULATE_SUBJECT, Some(ctx), live_expiry()),
                ctx
            ),
            1
        );
    }

    #[test]
    fn populate_drops_record_with_validity_over_90_days() {
        let ctx = "ctx-validity";
        let mut cv = unsigned_challenge(
            &ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]),
            POPULATE_SUBJECT,
            Some(ctx),
            live_expiry(),
        );
        cv.expires_at = cv.timestamp + 90 * 86_400 + 1;
        assert_eq!(populate_challenge_count(sign_challenge(cv), ctx), 0);
        // Control: exactly 90 days is accepted.
        let mut cv = unsigned_challenge(
            &ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]),
            POPULATE_SUBJECT,
            Some(ctx),
            live_expiry(),
        );
        cv.expires_at = cv.timestamp + 90 * 86_400;
        assert_eq!(populate_challenge_count(sign_challenge(cv), ctx), 1);
    }

    /// A challenge resolver whose backend is down.
    struct UnavailableResolver;
    impl DidPublicKeyResolver for UnavailableResolver {
        fn resolve_public_key(&self, did: &str) -> Result<Vec<u8>, TrustError> {
            Err(TrustError::KeyResolutionUnavailable {
                did: did.to_owned(),
                reason: "offline".to_owned(),
            })
        }
    }

    #[test]
    fn populate_propagates_challenge_resolver_outage() {
        // A resolver outage must not silently drop a record: it fails the call.
        let ctx = "ctx-outage";
        let record = make_genuinely_signed_challenge(POPULATE_SUBJECT, ctx);
        let err = populate_and_aggregate(
            InMemoryFfiTrustStore::new(),
            &UnavailableResolver,
            ctx,
            POPULATE_SUBJECT,
            vec![],
            &[record],
            &[],
            [0u8; 32],
            &[],
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap_err();
        assert!(
            matches!(err, TrustError::KeyResolutionUnavailable { .. }),
            "{err:?}"
        );
    }

    fn populate_without_resolver(
        records: &[ChallengeVerification],
        ctx: &str,
    ) -> Result<String, TrustError> {
        populate_and_aggregate(
            InMemoryFfiTrustStore::new(),
            crate::resolvers::instance_challenge_resolver(None),
            ctx,
            POPULATE_SUBJECT,
            vec![],
            records,
            // One event, so the control below reaches aggregation instead of
            // stopping at EmptyEventLog.
            &[make_event(
                EventType::MessageSent,
                POPULATE_SUBJECT,
                1000,
                0,
                vec![],
            )],
            [0u8; 32],
            &[],
            &HashMap::new(),
            &HashMap::new(),
        )
    }

    #[test]
    fn populate_without_resolver_fails_closed_on_challenge_record() {
        // An instance with no DID resolver can neither admit nor drop a record.
        let ctx = "ctx-no-resolver";
        let record = make_genuinely_signed_challenge(POPULATE_SUBJECT, ctx);
        let err = populate_without_resolver(&[record], ctx).unwrap_err();
        assert!(
            matches!(err, TrustError::KeyResolutionUnavailable { .. }),
            "{err:?}"
        );
        // Control: with no record to verify, the call needs no resolver.
        populate_without_resolver(&[], ctx).unwrap();
    }

    /// Fix C (behavioral). An invalid caller credential drops ONLY itself and
    /// does not abort the batch: a forged attestation alongside a genuinely
    /// signed one yields exactly the genuine one in the aggregated output.
    #[test]
    fn invalid_attestation_drops_only_itself_not_the_batch() {
        let context_id = "ctx-batch-continue";
        let subject_did =
            "did:key:99999999999999999999999999999999999999999999999999999999999999ff";

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[13u8; 32]);
        let genuine = make_genuinely_signed("genuine-batch-1", subject_did, &signing_key);

        let events = vec![make_event(
            EventType::MessageSent,
            subject_did,
            1000,
            0,
            vec![],
        )];

        let store = InMemoryFfiTrustStore::new();
        // Forged first, genuine second — the forged rejection must not abort the
        // loop before the genuine entry is verified and cached.
        let json = populate_and_aggregate(
            store,
            &scp_core::trust::IdentityDidPublicKeyResolver,
            context_id,
            subject_did,
            vec![
                make_forged_fresh_cached(subject_did),
                CachedAttestation {
                    attestation: genuine,
                    verified_at: 0,
                    ttl_secs: u64::MAX,
                },
            ],
            &[],
            &events,
            [0u8; 32],
            &[],
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let attestations = parsed["verified_attestations"].as_array().unwrap();
        assert_eq!(
            attestations.len(),
            1,
            "exactly the genuine attestation should survive; the forged one drops without aborting the batch"
        );
        assert_eq!(attestations[0]["id"], "genuine-batch-1");
    }

    // -----------------------------------------------------------------------
    // verify_attestation_in_context
    // -----------------------------------------------------------------------

    /// The single-attestation verifier reads the context's revocation list: an
    /// issuer's `Active` copy verifies before that issuer's revoked copy is
    /// ingested, and is rejected after, although the copy itself still reads
    /// `Active`. Another issuer's attestation carrying the same id stays valid.
    #[test]
    fn verify_attestation_in_context_rejects_a_copy_the_context_list_revoked() {
        let context_id = "ctx-verify-in-context";
        let subject_did =
            "did:key:4444444444444444444444444444444444444444444444444444444444444411";
        let issuer_key = ed25519_dalek::SigningKey::from_bytes(&[83u8; 32]);
        let other_key = ed25519_dalek::SigningKey::from_bytes(&[89u8; 32]);
        let shared_id = "endorsement-verify-2026";
        let active_copy = make_genuinely_signed(shared_id, subject_did, &issuer_key);
        let revoked_copy = make_genuinely_signed_revoked(shared_id, subject_did, &issuer_key);
        let other_issuer = make_genuinely_signed(shared_id, subject_did, &other_key);
        let resolver = scp_core::trust::IdentityDidPublicKeyResolver;
        let clock = scp_clock::SystemClock;

        let store = SharedFfiStore::new();
        let before =
            verify_attestation_in_context(&store, context_id, &active_copy, &resolver, &clock)
                .unwrap();
        assert!(
            matches!(before, AttestationVerdict::Valid),
            "the active copy must verify before its issuer revokes it, got {before:?}"
        );

        verified_attestations(
            store.clone(),
            context_id,
            subject_did,
            vec![fresh_entry(revoked_copy)],
        )
        .unwrap();

        let after =
            verify_attestation_in_context(&store, context_id, &active_copy, &resolver, &clock)
                .unwrap();
        assert!(
            matches!(
                after,
                AttestationVerdict::Rejected(TrustError::AttestationRevoked { .. })
            ),
            "the context's revocation list must reject the pre-revocation copy, got {after:?}"
        );
        let other =
            verify_attestation_in_context(&store, context_id, &other_issuer, &resolver, &clock)
                .unwrap();
        assert!(
            matches!(other, AttestationVerdict::Valid),
            "one issuer's revocation must not reject another issuer's attestation, got {other:?}"
        );
    }

    /// Test-only store whose revocation-list read fails with an INFRA fault.
    struct RevocationReadFailsStore(SharedFfiStore);

    impl TrustProtocolRepository for RevocationReadFailsStore {
        fn get_cached_attestations(
            &self,
            context_id: &str,
            subject_did: &str,
        ) -> Result<Vec<CachedAttestation>, TrustError> {
            self.0.get_cached_attestations(context_id, subject_did)
        }

        fn store_cached_attestation(
            &self,
            context_id: &str,
            entry: CachedAttestation,
        ) -> Result<(), TrustError> {
            self.0.store_cached_attestation(context_id, entry)
        }

        fn get_revocation_state(
            &self,
            _context_id: &str,
        ) -> Result<HashMap<String, bool>, TrustError> {
            Err(TrustError::StoreError {
                reason: "revocation-state read failed".to_owned(),
            })
        }

        fn add_revocations(
            &self,
            context_id: &str,
            entries: &[RevocationEntry],
            now: u64,
        ) -> Result<(), TrustError> {
            self.0.add_revocations(context_id, entries, now)
        }

        fn get_challenge_results(
            &self,
            context_id: &str,
            subject_did: &str,
        ) -> Result<Vec<ChallengeVerification>, TrustError> {
            self.0.get_challenge_results(context_id, subject_did)
        }

        fn store_challenge_result(
            &self,
            context_id: &str,
            result: &ChallengeVerification,
        ) -> Result<(), TrustError> {
            self.0.store_challenge_result(context_id, result)
        }
    }

    /// A revocation list that cannot be read is an error, never a verdict: a
    /// valid attestation does not read as valid, and does not read as
    /// rejected, while the list is unreadable.
    #[test]
    fn verify_attestation_in_context_propagates_an_unreadable_revocation_list() {
        let subject_did =
            "did:key:5555555555555555555555555555555555555555555555555555555555555511";
        let issuer_key = ed25519_dalek::SigningKey::from_bytes(&[97u8; 32]);
        let attestation = make_genuinely_signed("att-read-fault", subject_did, &issuer_key);
        let store = RevocationReadFailsStore(SharedFfiStore::new());

        let err = verify_attestation_in_context(
            &store,
            "ctx-read-fault",
            &attestation,
            &scp_core::trust::IdentityDidPublicKeyResolver,
            &scp_clock::SystemClock,
        )
        .unwrap_err();
        assert!(
            matches!(&err, TrustError::StoreError { reason } if reason == "revocation-state read failed"),
            "expected the store's read fault, got {err:?}"
        );
    }
}
