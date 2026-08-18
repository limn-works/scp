//! In-memory implementation of [`TrustProtocolRepository`] for FFI bridges.
//!
//! Shared across the `PyO3`, napi-rs, and `UniFFI` bridges. Each
//! `aggregate_trust_input` call creates a fresh store, populates it with
//! caller-provided data, runs the aggregation, and drops it. Thread safety
//! is provided by `std::sync::Mutex` — adequate for this ephemeral use case.
//!
//! See ADR-017 acceptance criterion 10 in `.docs/adrs/phase-4.md`.

use std::collections::HashMap;
use std::sync::Mutex;

use scp_core::trust::aggregate::{CachedAttestation, TrustProtocolRepository, revocation_list_key};
use scp_core::trust::attestation::{Attestation, RevocationStatus};
use scp_core::trust::{ChallengeVerification, TrustError, verify_challenge_verification};
use scp_event_log::Event;

/// In-memory implementation of `TrustProtocolRepository` for the FFI bridge.
///
/// Uses `std::sync::Mutex` for interior mutability. This is fine for the FFI
/// use case: each `aggregate_trust_input` call creates a fresh store, populates
/// it, runs the aggregation, and drops it.
pub struct InMemoryFfiTrustStore {
    attestations: Mutex<HashMap<(String, String), Vec<CachedAttestation>>>,
    revocations: Mutex<HashMap<String, HashMap<String, bool>>>,
    challenges: Mutex<HashMap<(String, String), Vec<ChallengeVerification>>>,
}

impl InMemoryFfiTrustStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            attestations: Mutex::new(HashMap::new()),
            revocations: Mutex::new(HashMap::new()),
            challenges: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryFfiTrustStore {
    fn default() -> Self {
        Self::new()
    }
}

fn lock_error() -> TrustError {
    // A poisoned lock is an INFRA fault, not a credential rejection. It must map
    // to a variant OUTSIDE the verify-on-ingest rejection allowlist
    // (`is_verification_rejection`) so it propagates rather than being silently
    // swallowed as a dropped entry. `StoreError` is that variant; the dedicated
    // `CanonicalizationFailed` variant is the only canonicalization-rejection
    // signal, so an infra fault can never collide with a rejection here.
    TrustError::StoreError {
        reason: "lock poisoned".to_owned(),
    }
}

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
        // SECURITY (cross-issuer cache overwrite, issue #2335 finding 13).
        // Replace-by-id alone lets an attacker's attestation carrying an honest
        // issuer's id take that issuer's slot, because §7.4.1 binds
        // `Attestation.id` to no issuer. Matching on issuer AND id gives each
        // issuer its own entry, matching the storage key
        // `ProtocolRepository::store_trust_cached_attestation` builds.
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
        Ok(store.get(context_id).cloned().unwrap_or_default())
    }

    fn store_revocation_state(
        &self,
        context_id: &str,
        state: &HashMap<String, bool>,
    ) -> Result<(), TrustError> {
        let mut store = self.revocations.lock().map_err(|_| lock_error())?;
        store.insert(context_id.to_owned(), state.clone());
        Ok(())
    }

    fn add_revocations(&self, context_id: &str, keys: &[String]) -> Result<(), TrustError> {
        // ONE guard spans the lookup and the inserts, so a concurrent caller on
        // this context cannot overwrite what this call adds (see the lost-update
        // requirement on `TrustProtocolRepository::add_revocations`).
        let mut store = self.revocations.lock().map_err(|_| lock_error())?;
        let entry = store.entry(context_id.to_owned()).or_default();
        for key in keys {
            entry.insert(key.clone(), true);
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
        let key = (context_id.to_owned(), result.subject_did.to_string());
        store.entry(key).or_default().push(result.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Verify-on-ingest support
// ---------------------------------------------------------------------------

// One `AttestationRevocationChecker` implementation serves every path that
// answers step 5 of `verify_attestation` from a persisted revocation list, and
// it lives in `scp_protocol::trust::aggregate` beside `revocation_list_key`,
// the function that builds every key it reads. A second copy here would let a
// reader's rule drift from a writer's while both compiled.
//
// `verify_attestation` given `None` checks only the issuer-bound
// `revocation_status` field an attestation carries. A validly-signed attestation
// that its issuer separately revoked through a context's revocation list would
// still pass that field check, so `verify_and_cache_attestations` (ingest) and
// `verify_attestation_in_context` (each bridge's `trust_verify_attestation` op)
// both hand a real checker to step 5.
//
// `verify_and_cache_attestations` writes each key both readers consult: an entry
// whose own issuer-signed `revocation_status` reads `Revoked` adds
// `revocation_list_key(issuer, id)` to a context's revocation list, so a later
// ingest of a pre-revocation copy from THAT issuer hits the checker instead of
// being counted, and so does a later `trust_verify_attestation` call naming that
// same context. A copy that a different issuer signed carries a different key,
// so it stays unaffected.
use scp_core::trust::aggregate::RevocationMapChecker;

/// Classifies a verify-on-ingest error.
///
/// Returns `true` for a verification REJECTION — the caller-supplied credential
/// is itself invalid (bad signature, expired, revoked, malformed
/// evidence/revocation, context-mismatched, subject-mismatched, or
/// non-canonicalizable), so dropping that one entry and continuing is correct.
/// Returns `false` for an INFRA fault
/// (store read/write failure, poisoned lock), which MUST propagate: silently
/// dropping every credential on a transient backend error would zero a subject's
/// trust without signal. Closed allowlist of rejection variants (white-hat P2-d).
///
/// `CanonicalizationFailed` is the dedicated canonicalization-failure variant
/// raised by `canonical_attestation_bytes` / `canonical_challenge_verification_bytes`:
/// a credential whose own bytes cannot be canonicalized cannot be authenticated,
/// so it is a REJECTION of that one entry (drop it), not an infra fault. It is
/// purpose-built so the allowlist is closed by construction — no infrastructure
/// path produces it, and it is NOT overloaded onto a general-purpose variant.
/// `InvalidEventData` / `ChallengeSigningFailed` are deliberately EXCLUDED: they
/// are no longer used by the ingest canonicalization paths, so treating them as
/// rejections would risk silently swallowing an unrelated fault.
const fn is_verification_rejection(err: &TrustError) -> bool {
    matches!(
        err,
        TrustError::AttestationSignatureInvalid { .. }
            | TrustError::AttestationExpired { .. }
            | TrustError::AttestationRevoked { .. }
            | TrustError::AttestationRevocationInvalid { .. }
            | TrustError::AttestationEvidenceInvalid { .. }
            | TrustError::ChallengeVerificationSignatureInvalid { .. }
            | TrustError::ChallengeVerificationExpired { .. }
            | TrustError::ChallengeContextMismatch { .. }
            | TrustError::ChallengeSubjectMismatch { .. }
            | TrustError::CanonicalizationFailed { .. }
    )
}

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

/// Adds each key in `keys` to a context's revocation list, writing nothing when
/// `keys` is empty.
///
/// [`verify_and_cache_attestations`] calls this on its ordinary path AND on its
/// abort path, so a revocation pass 1 discovered reaches a context's list
/// whichever way that pass ends.
///
/// # Errors
///
/// Propagates whatever [`add_revocations`](TrustProtocolRepository::add_revocations)
/// returns, so a failed revocation write never reads as a completed ingest.
fn write_revocations<S: TrustProtocolRepository>(
    store: &S,
    context_id: &str,
    keys: &std::collections::HashSet<String>,
) -> Result<(), TrustError> {
    if keys.is_empty() {
        return Ok(());
    }
    let keys: Vec<String> = keys.iter().cloned().collect();
    store.add_revocations(context_id, &keys)
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
/// `evaluate_trust`. Each caller entry is routed through `verify_and_cache`,
/// which verifies the Ed25519 signature against the RESOLVER-resolved issuer
/// key, checks expiry, the issuer-bound
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
/// [`is_issuer_signed_revocation`] therefore contributes
/// `revocation_list_key(issuer, id)` to
/// [`add_revocations`](TrustProtocolRepository::add_revocations), which both
/// readers of that list — [`RevocationMapChecker`] on this ingest path and
/// `RevocationMapChecker` on `AttestationCache::get_verified_attestations`, a
/// read path — consult on every later call. A failed write is an INFRA fault and
/// propagates, matching how this helper treats a failed `get_revocation_state`.
///
/// SECURITY (concurrent ingest). Keys reach a store through `add_revocations`,
/// which adds the keys it names and leaves every other key alone, rather than
/// through `store_revocation_state`, which replaces a whole map. Two callers
/// that both read one context's map and then write a whole copy back lose one
/// caller's addition: each copy is stale about the other's key. `add_revocations`
/// carries that lost-update requirement in its own contract, so this helper
/// never reconstructs a whole map from a read it performed earlier.
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
    subject_did: &str,
    resolver: &scp_core::trust::IdentityDidPublicKeyResolver,
    clock: &scp_clock::SystemClock,
    entries: Vec<CachedAttestation>,
) -> Result<(), TrustError> {
    let mut revoked = cache.store().get_revocation_state(context_id)?;

    // Keys this batch learned about. Each key binds a revoked attestation's id
    // to the issuer that signed that revocation (see the SECURITY note on issuer
    // scoping above). A set rather than a list, because a batch a caller
    // controls decides how many keys this holds.
    let mut newly_revoked: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut accepted: Vec<CachedAttestation> = Vec::new();

    // PASS 1 — verify every entry, cache none of them.
    {
        let revocation_checker = RevocationMapChecker { revoked: &revoked };
        for ca in entries {
            // SECURITY (subject scoping). A caller asks about ONE subject, and
            // `store_cached_attestation` keys an entry on the subject the entry
            // itself names. Caching an entry that names another subject would
            // let one call write into a subject nobody asked about, so an entry
            // whose subject differs from `subject_did` is dropped here.
            if ca.attestation.subject.as_ref() != subject_did {
                tracing::debug!(
                    attestation_id = %ca.attestation.id,
                    issuer = %ca.attestation.issuer,
                    entry_subject = %ca.attestation.subject,
                    requested_subject = %subject_did,
                    "dropping caller-supplied attestation naming another subject",
                );
                continue;
            }
            match scp_core::trust::verify_attestation(
                &ca.attestation,
                resolver,
                clock,
                Some(&revocation_checker),
            ) {
                Ok(()) => accepted.push(ca),
                Err(reason) if is_verification_rejection(&reason) => {
                    let key = revocation_list_key(&ca.attestation.issuer, &ca.attestation.id);
                    if is_issuer_signed_revocation(&reason, &ca.attestation)
                        && !revoked.get(&key).copied().unwrap_or(false)
                    {
                        newly_revoked.insert(key);
                    }
                    tracing::debug!(
                        attestation_id = %ca.attestation.id,
                        issuer = %ca.attestation.issuer,
                        %reason,
                        "dropping caller-supplied attestation that failed verify-on-ingest",
                    );
                }
                // An INFRA fault aborts this batch, and the revocations pass 1
                // already found are written before that abort. Returning here
                // with them unwritten would let a caller who appends a poison
                // entry after an issuer-signed revoked copy keep that
                // revocation out of a context's list, which is a suppression
                // primitive built out of caller data.
                Err(infra) => {
                    write_revocations(cache.store(), context_id, &newly_revoked)?;
                    return Err(infra);
                }
            }
        }
    }

    // Revocation write BEFORE any cache write, so a failure here leaves nothing
    // cached rather than leaving a discovered revocation unrecorded.
    write_revocations(cache.store(), context_id, &newly_revoked)?;
    for key in newly_revoked {
        revoked.insert(key, true);
    }

    // PASS 2 — cache each accepted entry. `verify_and_cache`
    // re-runs verification against the keys pass 1 recorded, so a copy this
    // batch revoked never reaches the cache, whatever order the two copies
    // arrived in.
    let revocation_checker = RevocationMapChecker { revoked: &revoked };
    for ca in accepted {
        match cache.verify_and_cache(
            context_id,
            &ca.attestation,
            resolver,
            clock,
            Some(&revocation_checker),
        ) {
            Ok(()) => {}
            Err(reason) if is_verification_rejection(&reason) => {
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
// Shared aggregation helper — used by all FFI bridges
// ---------------------------------------------------------------------------

/// Populates a trust store and runs the aggregation pipeline.
///
/// Generic over the store implementation to support both persistent
/// (`ProtocolRepositoryTrustBridge`) and ephemeral (`InMemoryFfiTrustStore`)
/// stores. Returns the aggregated `TrustInput` as a JSON string. See #502.
///
/// # Errors
///
/// Returns [`TrustError`] if store population, aggregation, or serialization
/// fails.
#[allow(clippy::too_many_arguments, clippy::implicit_hasher)]
pub fn populate_and_aggregate<S: TrustProtocolRepository>(
    store: S,
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
    verify_and_cache_attestations(
        &cache,
        context_id,
        subject_did,
        &resolver,
        &clock,
        cached_attestations,
    )?;

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
        match verify_challenge_verification(cr, &resolver, context_id, subject_did, &clock) {
            Ok(()) => cache.store().store_challenge_result(context_id, cr)?,
            Err(reason) if is_verification_rejection(&reason) => {
                tracing::debug!(
                    verification_id = %cr.verification_id,
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
    verify_and_cache_attestations(
        &cache,
        context_id,
        subject_did,
        &resolver,
        &clock,
        cached_attestations,
    )?;

    cache.get_verified_attestations(context_id, subject_did, &resolver, &clock)
}

// ---------------------------------------------------------------------------
// Context-scoped attestation verification — shared by all three FFI bridges
// ---------------------------------------------------------------------------

/// Verifies one attestation against a context, consulting that context's
/// persisted revocation list.
///
/// Every native bridge's `trust_verify_attestation` op routes here, so a caller
/// on Python, on TypeScript, on Swift, and on Kotlin receives the identical
/// verdict for identical inputs.
///
/// # What this reads
///
/// `store.get_revocation_state(context_id)` returns an
/// `issuer + attestation_id -> revoked` map whose keys
/// [`revocation_list_key`] builds.
/// [`RevocationMapChecker`] wraps that map and answers step 5 of
/// [`verify_attestation`](scp_core::trust::verify_attestation). An empty map
/// answers "no issuer revoked this id", which is the honest reading of a
/// context whose revocation list holds no entry — it is a real read of a real
/// list, not a stand-in that reports "not revoked" without consulting anything.
///
/// Two paths write that map, and both build every key with
/// [`revocation_list_key`]: [`verify_and_cache_attestations`] adds a key through
/// [`add_revocations`](TrustProtocolRepository::add_revocations) when it meets
/// an issuer-signed revoked attestation, and a caller that owns a whole map
/// replaces it through
/// [`store_revocation_state`](TrustProtocolRepository::store_revocation_state).
/// One key space spans that writer and this reader, so a revocation an ingest
/// recorded rejects a later verification of a pre-revocation copy from that same
/// issuer, and leaves another issuer's attestation carrying that same id
/// verifiable.
///
/// # Why a context is required
///
/// Section 7.4.4 of `.docs/specs/07-trust-validation-and-capabilities.md` states
/// that revocation is immediate for a new verification. Step 4 of
/// `verify_attestation` reads the `revocation_status` field the attestation
/// itself carries, which a holder of a pre-revocation copy still reads as
/// `Active`. Only step 5 catches that holder, and this codebase
/// persists revocation state per context, so a verification that names no
/// context can consult no list. Naming a context is therefore what lets this
/// function keep §7.4.4.
///
/// # What this writes
///
/// Nothing. This function reads a revocation list and reports a verdict, and an
/// application that hands it an attestation decides nothing about what a
/// context's revocation list holds. A caller controls both the context id and
/// the attestation bytes this op receives, so writing an entry per call would
/// let that caller grow a context's revocation list without bound, and
/// [`get_revocation_state`](TrustProtocolRepository::get_revocation_state)
/// loads that whole list on every later verification in that context.
/// [`verify_and_cache_attestations`] is the path that records a revocation,
/// because a caller reaches it by asking to ingest and count an attestation
/// rather than by asking a question about one.
///
/// # Errors
///
/// Returns [`TrustError::StoreError`] when the revocation-list read fails, and
/// the [`TrustError`] variant that `verify_attestation` raises when the
/// attestation fails verification — including
/// [`TrustError::AttestationRevoked`] when this context's revocation list names
/// this attestation's issuer together with its id.
pub fn verify_attestation_in_context<S: TrustProtocolRepository>(
    store: &S,
    context_id: &str,
    attestation: &scp_core::trust::attestation::Attestation,
    resolver: &scp_core::trust::IdentityDidPublicKeyResolver,
    clock: &scp_clock::SystemClock,
) -> Result<(), TrustError> {
    let revoked = store.get_revocation_state(context_id)?;
    let revocation_checker = RevocationMapChecker { revoked: &revoked };
    scp_core::trust::verify_attestation(attestation, resolver, clock, Some(&revocation_checker))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use scp_core::trust::AttestationType;
    use scp_core::trust::challenge::{ChallengeType, VerificationMethod};
    use scp_event_log::{Event, EventPayload, EventType};

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
        let mut state = HashMap::new();
        state.insert("att-1".to_owned(), true);
        state.insert("att-2".to_owned(), false);

        store.store_revocation_state("ctx-1", &state).unwrap();
        let retrieved = store.get_revocation_state("ctx-1").unwrap();
        assert_eq!(retrieved, state);
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
            .add_revocations(context_id, std::slice::from_ref(&first_key))
            .unwrap();
        store
            .add_revocations(context_id, std::slice::from_ref(&second_key))
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

    /// SECURITY (cross-issuer cache overwrite, issue #2335 finding 13). This
    /// store stands in for `ProtocolRepository`, so it partitions cached
    /// entries the same way: an attestation another issuer signed under one id
    /// occupies its own slot rather than replacing an honest issuer's entry.
    #[test]
    fn one_issuers_attestation_does_not_replace_anothers_under_a_shared_id() {
        let store = InMemoryFfiTrustStore::new();
        let subject = "did:key:alice";
        let mut honest = fresh_entry(make_attestation("shared-id", subject));
        honest.attestation.issuer = scp_did::DID::from("did:key:honest");
        let mut attacker = fresh_entry(make_attestation("shared-id", subject));
        attacker.attestation.issuer = scp_did::DID::from("did:key:attacker");

        store.store_cached_attestation("ctx-1", honest).unwrap();
        store.store_cached_attestation("ctx-1", attacker).unwrap();

        let loaded = store.get_cached_attestations("ctx-1", subject).unwrap();
        assert_eq!(
            loaded.len(),
            2,
            "each issuer keeps its own slot under a shared id, store holds {loaded:?}"
        );
        assert!(
            loaded
                .iter()
                .any(|e| e.attestation.issuer.as_ref() == "did:key:honest"),
            "the honest issuer's attestation must survive, store holds {loaded:?}"
        );
    }

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

    /// A `ChallengeVerification` that is FORGED only in its signature: its
    /// `verifier_did` is a RESOLVABLE `did:key:{hex}` (so verify-on-ingest gets
    /// past DID resolution and actually reaches the signature branch — the
    /// previous `did:key:verifier` was non-hex and failed resolution first,
    /// masking the signature check), its `context_id` matches the ingest context,
    /// and its `expires_at` is far in the future. Everything is otherwise valid
    /// EXCEPT the all-zero `verifier_signature`, so a correct gate drops it solely
    /// because the signature does not verify (which is what the mutation check on
    /// the signature branch exercises).
    ///
    /// The verifier DID is a `did:dht:z` (resolvable in production without the
    /// testing-only `did:key:{hex}` path), so resolution genuinely succeeds and
    /// the all-zero signature is what fails — not a masked resolution error.
    fn make_challenge_result(id: &str, subject: &str, context_id: &str) -> ChallengeVerification {
        // A resolvable verifier DID whose key the all-zero signature does NOT
        // authenticate.
        let verifier_pub = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32])
            .verifying_key()
            .to_bytes();
        let verifier_did = scp_did::did_dht_from_public_key(&verifier_pub);
        ChallengeVerification {
            verification_id: id.to_owned(),
            verifier_did,
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
            expires_at: u64::MAX,
            context_id: Some(context_id.to_owned()),
            verifier_signature: vec![0u8; 64],
        }
    }

    /// Produces a GENUINELY verifier-signed [`ChallengeVerification`] with the
    /// record's signed `context_id` set to `record_context` and the signed
    /// `expires_at` set to `expires_at`. The verifier DID is a `did:dht:z` that
    /// resolves in production (no testing-only `did:key` path), and the
    /// `verifier_signature` is a real Ed25519 signature over the public
    /// [`canonical_challenge_verification_bytes`], mirroring the attestation
    /// path's `make_genuinely_signed`. By varying `record_context`/`expires_at`
    /// the caller exercises the context-binding and expiry gates with an
    /// otherwise-valid (genuinely-signed) record.
    fn make_genuinely_signed_challenge_with(
        subject: &str,
        record_context: Option<&str>,
        expires_at: u64,
    ) -> ChallengeVerification {
        use ed25519_dalek::Signer;

        let verifier_key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let verifier_pub: [u8; 32] = verifier_key.verifying_key().to_bytes();
        let verifier_did = scp_did::did_dht_from_public_key(&verifier_pub);

        let mut cv = ChallengeVerification {
            verification_id: "genuine-cv-1".to_owned(),
            verifier_did,
            subject_did: subject.into(),
            capability_uri: "scp:capability:schema-validation/v1".to_owned(),
            challenge_type: ChallengeType::schema_validation(),
            verification_method: VerificationMethod::ChallengeVerified {
                challenge_type: ChallengeType::schema_validation(),
            },
            passed: true,
            score: Some(95),
            test_count: 1,
            pass_count: 1,
            result: serde_json::json!({"passed": true}),
            completed_at: 1000,
            verified_at: 1001,
            expires_at,
            context_id: record_context.map(ToOwned::to_owned),
            verifier_signature: Vec::new(),
        };
        let canonical = scp_core::trust::canonical_challenge_verification_bytes(&cv).unwrap();
        cv.verifier_signature = verifier_key.sign(&canonical).to_bytes().to_vec();
        cv
    }

    /// Convenience: a genuinely-signed, in-context, non-expiring challenge.
    fn make_genuinely_signed_challenge(subject: &str, context_id: &str) -> ChallengeVerification {
        make_genuinely_signed_challenge_with(subject, Some(context_id), u64::MAX)
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
        assert_eq!(input.challenge_results[0].verification_id, "genuine-cv-1");
        assert!(input.challenge_results[0].passed);
        assert_eq!(input.challenge_results[0].score, Some(95));

        assert_eq!(input.consequence_structure.len(), 1);
        assert!(input.threshold_counts.is_empty());

        // Verify JSON serialization (as the FFI bridges do).
        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("att-integration-1"));
        assert!(json.contains("genuine-cv-1"));
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
    /// against an over-strict regression in `verify_and_cache` that the
    /// forgery-only tests above could not catch (they pass whether the verifier
    /// accepts valid signatures or rejects everything).
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
        let forged = make_challenge_result("forged-cv-1", subject_did, context_id);

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
            context_id,
            subject_did,
            vec![],
            &[genuine],
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
        assert_eq!(challenge_results[0]["verification_id"], "genuine-cv-1");
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
            make_genuinely_signed_challenge_with(subject_did, Some(other_context), u64::MAX);

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
        let mut revoked = HashMap::new();
        revoked.insert(
            revocation_list_key(&scp_did::DID::from("did:key:bob"), "att-revoked"),
            true,
        );
        cache
            .store()
            .store_revocation_state(context_id, &revoked)
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

        fn store_revocation_state(
            &self,
            context_id: &str,
            state: &HashMap<String, bool>,
        ) -> Result<(), TrustError> {
            self.0.store_revocation_state(context_id, state)
        }

        fn add_revocations(&self, context_id: &str, keys: &[String]) -> Result<(), TrustError> {
            self.0.add_revocations(context_id, keys)
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

    /// Test-only store that REJECTS a whole-map revocation replace and accepts a
    /// merge. Every other method delegates to a working [`SharedFfiStore`], so a
    /// test that feeds it an issuer-signed revoked attestation observes which of
    /// the two write shapes the ingest path used.
    struct WholeMapReplaceRejectingStore(SharedFfiStore);

    impl TrustProtocolRepository for WholeMapReplaceRejectingStore {
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

        fn store_revocation_state(
            &self,
            _context_id: &str,
            _state: &HashMap<String, bool>,
        ) -> Result<(), TrustError> {
            Err(TrustError::StoreError {
                reason: "whole-map revocation replace reached the ingest path".to_owned(),
            })
        }

        fn add_revocations(&self, context_id: &str, keys: &[String]) -> Result<(), TrustError> {
            self.0.add_revocations(context_id, keys)
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

    /// SECURITY (lost update, issue #2335 bug-catcher item 8, caller half).
    /// The ingest path records a revocation through `add_revocations`, which adds
    /// the keys it names, and never through `store_revocation_state`, which
    /// replaces a whole map with a copy read before other callers wrote. This
    /// store fails a whole-map replace, so an ingest that reaches for one fails
    /// here rather than silently dropping a concurrent caller's revocation in
    /// production.
    #[test]
    fn ingest_records_a_revocation_without_replacing_a_whole_map() {
        let context_id = "ctx-merge-only";
        let subject_did =
            "did:key:3333333333333333333333333333333333333333333333333333333333333399";
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[71u8; 32]);
        let revoked_copy = make_genuinely_signed_revoked("att-merge-1", subject_did, &signing_key);

        let inner = SharedFfiStore::new();
        let store = WholeMapReplaceRejectingStore(inner.clone());
        let verified = verified_attestations(
            store,
            context_id,
            subject_did,
            vec![fresh_entry(revoked_copy)],
        )
        .expect("ingest must record a revocation without replacing a whole map");
        assert!(verified.is_empty(), "a revoked attestation is not counted");

        let issuer = scp_did::did_dht_from_public_key(&signing_key.verifying_key().to_bytes());
        let state = inner.get_revocation_state(context_id).unwrap();
        assert_eq!(
            state.get(&revocation_list_key(&issuer, "att-merge-1")),
            Some(&true),
            "the merge write must have recorded the revocation, list reads {state:?}"
        );
    }

    /// Test-only store whose revocation writes — both `store_revocation_state`
    /// and `add_revocations` — fail with an INFRA fault (`StoreError`, a variant
    /// outside `is_verification_rejection`). Every other method delegates to a
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

        fn store_revocation_state(
            &self,
            _context_id: &str,
            _state: &HashMap<String, bool>,
        ) -> Result<(), TrustError> {
            Err(TrustError::StoreError {
                reason: "revocation-state write failed".to_owned(),
            })
        }

        fn add_revocations(&self, _context_id: &str, _keys: &[String]) -> Result<(), TrustError> {
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
        // The attacker's copy carries the same id under a different issuer. Each
        // copy is cached in its own store below, because
        // `InMemoryFfiTrustStore::store_cached_attestation` replaces an entry
        // whose id matches (replace-by-id semantics).
        let attacker = make_genuinely_signed(shared_id, subject_did, &attacker_key);
        let honest_issuer = honest.issuer.clone();
        let attacker_issuer = attacker.issuer.clone();

        let store = InMemoryFfiTrustStore::new();
        store
            .store_cached_attestation(context_id, fresh_entry(honest))
            .unwrap();
        // The attacker's revocation, recorded under the attacker's own DID.
        let mut revoked = HashMap::new();
        revoked.insert(revocation_list_key(&attacker_issuer, shared_id), true);
        store.store_revocation_state(context_id, &revoked).unwrap();

        let cache = scp_core::trust::aggregate::AttestationCache::new(store);
        let resolver = scp_core::trust::IdentityDidPublicKeyResolver;
        let clock = TestClock::new(2000);

        let read = cache
            .get_verified_attestations(context_id, subject_did, &resolver, &clock)
            .unwrap();
        assert_eq!(
            read.len(),
            1,
            "a revocation the attacker signed must not exclude the honest issuer's cached attestation, got {read:?}"
        );
        assert_eq!(
            read[0].issuer, honest_issuer,
            "the surviving attestation must be the honest issuer's"
        );

        // Control: the attacker's OWN entry, cached under the same id, is
        // excluded by that same revocation list.
        let attacker_store = InMemoryFfiTrustStore::new();
        attacker_store
            .store_cached_attestation(context_id, fresh_entry(attacker))
            .unwrap();
        attacker_store
            .store_revocation_state(context_id, &revoked)
            .unwrap();
        let attacker_cache = scp_core::trust::aggregate::AttestationCache::new(attacker_store);
        let attacker_read = attacker_cache
            .get_verified_attestations(context_id, subject_did, &resolver, &clock)
            .unwrap();
        assert!(
            attacker_read.is_empty(),
            "the attacker's own revoked attestation must be excluded on the read path, got {attacker_read:?}"
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
    /// one `RevocationMapChecker` on this ingest path and another
    /// inside `AttestationCache::get_verified_attestations`, a read path.
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

    /// A failed `store_revocation_state` is an INFRA fault: `verified_attestations`
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
    /// infra store faults are NOT (they propagate). The previously-overloaded
    /// `InvalidEventData` / `ChallengeSigningFailed` variants are EXCLUDED so the
    /// rejection set is closed by construction. Pins the closed allowlist's
    /// membership.
    #[test]
    fn canonicalization_failures_are_rejections_infra_is_not() {
        assert!(is_verification_rejection(
            &TrustError::CanonicalizationFailed {
                reason: "claim serialization failed".to_owned(),
            }
        ));
        // Infra store fault (e.g. poisoned lock) must remain non-rejection so it
        // propagates rather than silently dropping an entry.
        assert!(!is_verification_rejection(&TrustError::StoreError {
            reason: "lock poisoned".to_owned(),
        }));
        // The previously-overloaded variants are no longer rejections: they are
        // not produced by the ingest canonicalization paths, so they must
        // propagate rather than silently drop an entry.
        assert!(!is_verification_rejection(&TrustError::InvalidEventData {
            sequence: 0,
            reason: "unrelated".to_owned(),
        }));
        assert!(!is_verification_rejection(
            &TrustError::ChallengeSigningFailed {
                reason: "unrelated".to_owned(),
            }
        ));
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
    // verify_attestation_in_context (§7.4.4) — bridge verification honors a
    // context's revocation list
    // -----------------------------------------------------------------------

    /// Section 7.4.4 of `.docs/specs/07-trust-validation-and-capabilities.md`
    /// states that revocation is immediate for a new verification. A holder of
    /// a pre-revocation copy still carries `revocation_status: Active`, so step
    /// 4 of `verify_attestation` accepts that copy, and only a revocation-list
    /// read rejects it.
    ///
    /// This test FAILS the moment [`verify_attestation_in_context`] stops
    /// handing a checker to `verify_attestation` — passing `None` there turns
    /// this assertion's expected `AttestationRevoked` into `Ok(())`.
    #[test]
    fn verify_attestation_in_context_rejects_an_id_the_revocation_list_names() {
        let context_id = "ctx-revoked-read";
        let subject_did =
            "did:key:55555555555555555555555555555555555555555555555555555555555555ee";
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        // `revocation_status` reads `Active`: this is the stale copy a holder
        // keeps after an issuer publishes a revoked replacement.
        let att = make_genuinely_signed("revoked-by-list", subject_did, &signing_key);

        let store = InMemoryFfiTrustStore::new();
        let mut revoked = HashMap::new();
        // A revocation list key binds an issuer to an attestation id, so this
        // entry names the issuer that signed `att` (§7.4.4 grants a revocation
        // to that issuer alone).
        revoked.insert(revocation_list_key(&att.issuer, "revoked-by-list"), true);
        store.store_revocation_state(context_id, &revoked).unwrap();

        let result = verify_attestation_in_context(
            &store,
            context_id,
            &att,
            &scp_core::trust::IdentityDidPublicKeyResolver,
            &scp_clock::SystemClock,
        );

        assert!(
            matches!(
                &result,
                Err(TrustError::AttestationRevoked { attestation_id, .. })
                    if attestation_id == "revoked-by-list"
            ),
            "expected AttestationRevoked for revoked-by-list, got {result:?}"
        );
    }

    /// A context whose revocation list names a DIFFERENT id must not reject
    /// this attestation. Without this assertion a checker that rejects every id
    /// would satisfy the test above.
    #[test]
    fn verify_attestation_in_context_accepts_an_id_the_revocation_list_omits() {
        let context_id = "ctx-revoked-other";
        let subject_did =
            "did:key:66666666666666666666666666666666666666666666666666666666666666ff";
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[12u8; 32]);
        let att = make_genuinely_signed("not-revoked", subject_did, &signing_key);

        let store = InMemoryFfiTrustStore::new();
        let mut revoked = HashMap::new();
        revoked.insert(
            revocation_list_key(&att.issuer, "some-other-attestation"),
            true,
        );
        store.store_revocation_state(context_id, &revoked).unwrap();

        verify_attestation_in_context(
            &store,
            context_id,
            &att,
            &scp_core::trust::IdentityDidPublicKeyResolver,
            &scp_clock::SystemClock,
        )
        .unwrap();
    }

    /// A revocation list is per context. An id revoked in one context must not
    /// reject a verification that names a different context.
    #[test]
    fn verify_attestation_in_context_scopes_a_revocation_list_to_its_own_context() {
        let subject_did =
            "did:key:77777777777777777777777777777777777777777777777777777777777777aa";
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[14u8; 32]);
        let att = make_genuinely_signed("scoped-id", subject_did, &signing_key);

        let store = InMemoryFfiTrustStore::new();
        let mut revoked = HashMap::new();
        revoked.insert(revocation_list_key(&att.issuer, "scoped-id"), true);
        store.store_revocation_state("ctx-a", &revoked).unwrap();

        let resolver = scp_core::trust::IdentityDidPublicKeyResolver;
        let clock = scp_clock::SystemClock;

        assert!(
            verify_attestation_in_context(&store, "ctx-a", &att, &resolver, &clock).is_err(),
            "ctx-a revoked this id"
        );
        verify_attestation_in_context(&store, "ctx-b", &att, &resolver, &clock).unwrap();
    }

    /// A forged signature fails before any revocation read matters, so the
    /// helper reports the signature failure rather than an acceptance.
    #[test]
    fn verify_attestation_in_context_rejects_a_forged_signature() {
        let context_id = "ctx-forged";
        let subject_did =
            "did:key:88888888888888888888888888888888888888888888888888888888888888bb";
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[15u8; 32]);
        let mut att = make_genuinely_signed("forged-sig", subject_did, &signing_key);
        att.signature = vec![0u8; 64];

        let store = InMemoryFfiTrustStore::new();

        let result = verify_attestation_in_context(
            &store,
            context_id,
            &att,
            &scp_core::trust::IdentityDidPublicKeyResolver,
            &scp_clock::SystemClock,
        );

        assert!(
            matches!(result, Err(TrustError::AttestationSignatureInvalid { .. })),
            "expected AttestationSignatureInvalid, got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // One key space spans the ingest writer and the bridge reader
    // -----------------------------------------------------------------------

    /// SECURITY (one key space across a writer and a reader, issue #2335
    /// finding 13). Two paths touch a context's revocation list:
    /// [`verify_and_cache_attestations`] writes a key through `add_revocations`
    /// when it meets an issuer-signed revoked attestation, and
    /// [`verify_attestation_in_context`] reads that list on every bridge's
    /// `trust_verify_attestation` op. Both build every key with
    /// `revocation_list_key(issuer, attestation_id)`.
    ///
    /// This test drives a write through one path and a read through the other,
    /// so a key space that differs between them fails it: a writer keyed on an
    /// issuer plus an id against a reader keyed on a bare id finds nothing and
    /// returns `Ok(())`, and so does that pairing reversed.
    #[test]
    fn a_revocation_the_ingest_path_wrote_rejects_a_later_context_verification() {
        let context_id = "ctx-writer-reader-one-key-space";
        let subject_did =
            "did:key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa77";
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[57u8; 32]);

        // One issuer, one id: an issuer-signed revoked copy that an ingest
        // records, and a pre-revocation copy a holder still carries.
        let revoked_copy =
            make_genuinely_signed_revoked("att-one-key-space", subject_did, &signing_key);
        let active_copy = make_genuinely_signed("att-one-key-space", subject_did, &signing_key);

        let store = SharedFfiStore::new();

        // WRITER — an ingest records that revocation.
        let counted = verified_attestations(
            store.clone(),
            context_id,
            subject_did,
            vec![fresh_entry(revoked_copy)],
        )
        .unwrap();
        assert!(
            counted.is_empty(),
            "a revoked attestation must not be counted, got {} entry/entries",
            counted.len()
        );

        // READER — a bridge verification of that pre-revocation copy.
        let result = verify_attestation_in_context(
            &store,
            context_id,
            &active_copy,
            &scp_core::trust::IdentityDidPublicKeyResolver,
            &scp_clock::SystemClock,
        );
        assert!(
            matches!(
                &result,
                Err(TrustError::AttestationRevoked { attestation_id, .. })
                    if attestation_id == "att-one-key-space"
            ),
            "a bridge verification must read the key an ingest wrote, got {result:?}"
        );
    }

    /// SECURITY (subject scoping on ingest). A caller asks about one subject,
    /// and `store_cached_attestation` keys an entry on the subject that entry
    /// names. Caching an entry naming another subject would let one aggregate
    /// call write into a subject nobody asked about, so ingest drops such an
    /// entry rather than caching it.
    #[test]
    fn an_entry_naming_another_subject_never_reaches_that_subjects_cache() {
        let context_id = "ctx-subject-scoping";
        let asked_about =
            "did:key:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd11";
        let other_subject =
            "did:key:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee22";
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[73u8; 32]);

        let for_other = make_genuinely_signed("att-other-subject", other_subject, &signing_key);
        let store = SharedFfiStore::new();

        // One aggregate call naming `asked_about`, carrying an entry that names
        // `other_subject`.
        let counted = verified_attestations(
            store.clone(),
            context_id,
            asked_about,
            vec![fresh_entry(for_other)],
        )
        .unwrap();
        assert!(
            counted.is_empty(),
            "an entry naming another subject is not counted for this subject, got {counted:?}"
        );

        // That other subject's cache stays empty, so no later read of it
        // returns an entry this call wrote.
        let other_cached = store
            .get_cached_attestations(context_id, other_subject)
            .unwrap();
        assert!(
            other_cached.is_empty(),
            "one subject's aggregate call must not write another subject's cache, cache holds {other_cached:?}"
        );
    }

    /// SECURITY (the verify op writes nothing, §7.4.4).
    /// [`verify_attestation_in_context`] answers a question about one
    /// attestation, and a caller controls both the context id and the
    /// attestation bytes it hands that op. Recording a revocation there would
    /// let that caller add one entry per call to a context's revocation list —
    /// an attacker derives a DID from a fresh keypair at no cost and signs a
    /// self-revoking attestation, so each call costs it one Ed25519 signature —
    /// and `get_revocation_state` loads that whole list on every later
    /// verification in that context. [`verify_and_cache_attestations`] is the
    /// path that records a revocation, because a caller reaches it by asking to
    /// ingest and count an attestation.
    ///
    /// This test pins that absence: restoring an `add_revocations` call inside
    /// [`verify_attestation_in_context`] turns the last two assertions below
    /// from an empty list plus `Ok(())` into a one-entry list plus
    /// `Err(AttestationRevoked)`.
    #[test]
    fn verifying_a_republished_revoked_copy_records_nothing() {
        let context_id = "ctx-verify-op-writes-nothing";
        let subject_did =
            "did:key:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc99";
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[67u8; 32]);

        let revoked_copy =
            make_genuinely_signed_revoked("att-verify-writeback", subject_did, &signing_key);
        let active_copy = make_genuinely_signed("att-verify-writeback", subject_did, &signing_key);

        let store = SharedFfiStore::new();
        let resolver = scp_core::trust::IdentityDidPublicKeyResolver;
        let clock = scp_clock::SystemClock;

        // An application verifies the republished revoked copy. Step 4 of
        // `verify_attestation` reads the signed `Revoked` field that copy
        // carries, so the verdict rejects it.
        let revoked_read =
            verify_attestation_in_context(&store, context_id, &revoked_copy, &resolver, &clock);
        assert!(
            matches!(&revoked_read, Err(TrustError::AttestationRevoked { .. })),
            "a revoked copy must not verify, got {revoked_read:?}"
        );

        // That verification recorded nothing, so this context's revocation list
        // still holds no entry.
        let listed = store.get_revocation_state(context_id).unwrap();
        assert!(
            listed.is_empty(),
            "the verify op must not write a revocation list entry, list holds {listed:?}"
        );

        // A pre-revocation copy of that same id therefore still verifies: an
        // ingest through `verified_attestations`, not a verification, is what
        // records a revocation.
        verify_attestation_in_context(&store, context_id, &active_copy, &resolver, &clock)
            .expect("no revocation was recorded, so this copy still verifies");
    }

    /// SECURITY (issuer-scoped revocation across a writer and a reader). One
    /// key space is necessary but not sufficient: that key space also carries
    /// an issuer. An attacker mints a DID at no cost, signs an attestation that
    /// carries an honest issuer's id and revokes itself, and lets a consumer
    /// ingest it. A later bridge verification of the honest issuer's
    /// attestation must still succeed.
    #[test]
    fn an_attackers_ingested_revocation_leaves_another_issuers_attestation_verifiable() {
        let context_id = "ctx-writer-reader-issuer-scope";
        let subject_did =
            "did:key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb88";
        let honest_key = ed25519_dalek::SigningKey::from_bytes(&[61u8; 32]);
        let attacker_key = ed25519_dalek::SigningKey::from_bytes(&[63u8; 32]);

        let shared_id = "endorsement-shared-id-2026";
        let attacker_revoked = make_genuinely_signed_revoked(shared_id, subject_did, &attacker_key);
        let honest_active = make_genuinely_signed(shared_id, subject_did, &honest_key);
        assert_ne!(
            attacker_revoked.issuer, honest_active.issuer,
            "the two issuers must differ for this test to exercise issuer scoping"
        );

        let store = SharedFfiStore::new();

        // WRITER — an attacker's self-revocation reaches this context's list.
        verified_attestations(
            store.clone(),
            context_id,
            subject_did,
            vec![fresh_entry(attacker_revoked)],
        )
        .unwrap();

        // READER — an honest issuer's attestation carrying that same id.
        verify_attestation_in_context(
            &store,
            context_id,
            &honest_active,
            &scp_core::trust::IdentityDidPublicKeyResolver,
            &scp_clock::SystemClock,
        )
        .expect("an attacker's revocation must not reject another issuer's attestation");

        // Control — that attacker's own id stays rejected, which proves the
        // write landed and this reader consults it.
        let attacker_active = make_genuinely_signed(shared_id, subject_did, &attacker_key);
        let attacker_read = verify_attestation_in_context(
            &store,
            context_id,
            &attacker_active,
            &scp_core::trust::IdentityDidPublicKeyResolver,
            &scp_clock::SystemClock,
        );
        assert!(
            matches!(&attacker_read, Err(TrustError::AttestationRevoked { .. })),
            "an attacker's own revoked id must stay rejected, got {attacker_read:?}"
        );
    }
}
