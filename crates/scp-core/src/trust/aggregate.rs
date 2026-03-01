//! Trust input aggregation and `TrustProtocolStore` integration.
//!
//! [`aggregate_trust_input`] combines all trust engine layers into a single
//! [`TrustInput`] struct for agent-level evaluation. The trust engine does not
//! produce trust "scores" -- each agent applies its own criteria to the
//! aggregated inputs.
//!
//! # `TrustProtocolStore` integration
//!
//! [`TrustProtocolStore`] caches verified attestations with TTL-based refresh,
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

use std::collections::HashMap;

use crate::event_log::Event;
use crate::identity::cache::Clock;

use super::attestation::{
    Attestation, AttestorInfo, DidPublicKeyResolver, FreshnessStatus, ThresholdRequirement,
    check_attestation_freshness, check_threshold_attestation, verify_attestation,
};
use super::behavioral::compute_behavioral_record;
use super::challenge::ChallengeVerification;
use super::consequence::ConsequenceRule;
use super::{AttestationType, TrustError, TrustInput};

// ---------------------------------------------------------------------------
// TrustProtocolStore
// ---------------------------------------------------------------------------

/// Persistent store for trust engine data.
///
/// Caches verified attestations with TTL-based refresh, stores revocation list
/// state per context, and persists challenge results with timestamps. All
/// methods take `&self` for interior mutability (implementations use interior
/// locking or cell types as appropriate).
///
/// See ADR-017 acceptance criterion 10.
pub trait TrustProtocolStore {
    /// Retrieves cached verified attestations for a subject DID within a
    /// context. Returns only attestations whose cache entry has not expired.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError`] if the store is unavailable or corrupt.
    fn get_cached_attestations(
        &self,
        context_id: &str,
        subject_did: &str,
    ) -> Result<Vec<CachedAttestation>, TrustError>;

    /// Stores a verified attestation in the cache with a TTL.
    ///
    /// If an attestation with the same ID already exists, it is replaced.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError`] if the store write fails.
    fn cache_attestation(
        &self,
        context_id: &str,
        entry: CachedAttestation,
    ) -> Result<(), TrustError>;

    /// Retrieves the revocation list state for a context.
    ///
    /// Returns a map of attestation ID to revocation status (true = revoked).
    ///
    /// # Errors
    ///
    /// Returns [`TrustError`] if the store is unavailable.
    fn get_revocation_state(&self, context_id: &str) -> Result<HashMap<String, bool>, TrustError>;

    /// Stores revocation list state for a context.
    ///
    /// Replaces the existing revocation state for the context.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError`] if the store write fails.
    fn set_revocation_state(
        &self,
        context_id: &str,
        state: &HashMap<String, bool>,
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
// CachedAttestation
// ---------------------------------------------------------------------------

/// A verified attestation stored in the cache with TTL metadata.
///
/// The `verified_at` timestamp records when the attestation was last verified.
/// The `ttl_secs` field determines when the cache entry should be refreshed.
/// An entry is considered expired when `verified_at + ttl_secs < now`.
#[derive(Debug, Clone)]
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
/// Wraps a [`TrustProtocolStore`] and provides TTL-aware attestation retrieval.
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

impl<S: TrustProtocolStore> AttestationCache<S> {
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
        let now = clock.now();
        let mut result = Vec::new();

        for entry in cached {
            if entry.is_expired(now) {
                // Re-verify the attestation.
                if verify_attestation(&entry.attestation, resolver, clock).is_ok() {
                    // Update cache with new verified_at.
                    let refreshed = CachedAttestation {
                        attestation: entry.attestation.clone(),
                        verified_at: now,
                        ttl_secs: self.ttl_secs,
                    };
                    self.store.cache_attestation(context_id, refreshed)?;
                    result.push(entry.attestation);
                }
                // If verification fails, the entry is silently discarded.
            } else {
                result.push(entry.attestation);
            }
        }

        Ok(result)
    }

    /// Verifies and caches a new attestation.
    ///
    /// Verifies the attestation, and if valid, stores it in the cache with
    /// the current timestamp and configured TTL.
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
    ) -> Result<(), TrustError> {
        verify_attestation(attestation, resolver, clock)?;

        let entry = CachedAttestation {
            attestation: attestation.clone(),
            verified_at: clock.now(),
            ttl_secs: self.ttl_secs,
        };
        self.store.cache_attestation(context_id, entry)?;

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

    /// Event log entries for the context. Used for behavioral record
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
/// 1. Computes the behavioral record from the event log.
/// 2. Collects and verifies attestations from the cache (with TTL-based
///    refresh).
/// 3. Collects challenge results with timestamps from the store.
/// 4. Collects consequence structure from context parameters.
/// 5. Computes threshold counts per attestation type.
///
/// # Errors
///
/// Returns [`TrustError`] if behavioral record computation fails or if the
/// backing store is unavailable.
///
/// See ADR-017 acceptance criterion 9.
pub fn aggregate_trust_input<S, R, C>(
    ctx: &AggregationContext<'_, S, R, C>,
) -> Result<TrustInput, TrustError>
where
    S: TrustProtocolStore,
    R: DidPublicKeyResolver,
    C: Clock,
{
    // 1. Compute behavioral record from event log.
    let behavioral_record = compute_behavioral_record(
        ctx.events,
        ctx.subject_did,
        ctx.context_id,
        ctx.merkle_root,
        ctx.clock.now(),
    )?;

    // 2. Collect and verify attestations from cache.
    let verified_attestations = ctx.cache.get_verified_attestations(
        ctx.context_id,
        ctx.subject_did,
        ctx.resolver,
        ctx.clock,
    )?;

    // 3. Collect challenge results with timestamps from the store.
    let challenge_results = ctx
        .cache
        .store()
        .get_challenge_results(ctx.context_id, ctx.subject_did)?;

    // 4. Consequence structure comes directly from context params.
    let consequence_structure: Vec<ConsequenceRule> = ctx.consequence_rules.to_vec();

    // 5. Compute threshold counts per attestation type.
    let threshold_counts = compute_threshold_counts(ctx.threshold_requirements, ctx.attestor_sets);

    Ok(TrustInput {
        verified_attestations,
        behavioral_record,
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
/// [`check_threshold_attestation`] against the provided attestor set and
/// records `(valid_count, required_count)`.
fn compute_threshold_counts(
    requirements: &HashMap<AttestationType, ThresholdRequirement>,
    attestor_sets: &HashMap<AttestationType, Vec<AttestorInfo>>,
) -> HashMap<AttestationType, (u32, u32)> {
    let mut counts = HashMap::new();

    for (att_type, requirement) in requirements {
        let attestors = attestor_sets
            .get(att_type)
            .map_or(&[] as &[AttestorInfo], |v| v.as_slice());

        let result = check_threshold_attestation(att_type, attestors, requirement);
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
    use crate::event_log::{EventPayload, EventType};
    use crate::identity::cache::TestClock;
    use crate::trust::attestation::RevocationStatus;

    // -----------------------------------------------------------------------
    // Test helpers: InMemoryTrustStore
    // -----------------------------------------------------------------------

    /// An in-memory implementation of [`TrustProtocolStore`] for testing.
    struct InMemoryTrustStore {
        attestations: Mutex<HashMap<(String, String), Vec<CachedAttestation>>>,
        revocations: Mutex<HashMap<String, HashMap<String, bool>>>,
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

    impl TrustProtocolStore for InMemoryTrustStore {
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

        fn cache_attestation(
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

            // Replace existing entry with same ID, or append.
            if let Some(pos) = entries
                .iter()
                .position(|e| e.attestation.id == entry.attestation.id)
            {
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
            Ok(store.get(context_id).cloned().unwrap_or_default())
        }

        fn set_revocation_state(
            &self,
            context_id: &str,
            state: &HashMap<String, bool>,
        ) -> Result<(), TrustError> {
            let mut store = self
                .revocations
                .lock()
                .map_err(|_| TrustError::InvalidEventData {
                    sequence: 0,
                    reason: "lock poisoned".to_owned(),
                })?;
            store.insert(context_id.to_owned(), state.clone());
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
            let key = (context_id.to_owned(), result.responder_did.to_string());
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

    fn make_challenge_verification(
        challenge_id: &str,
        responder: &str,
        completed_at: u64,
    ) -> ChallengeVerification {
        use crate::trust::challenge::{ChallengeType, VerificationMethod};
        ChallengeVerification {
            challenge_id: challenge_id.to_owned(),
            challenger_did: "did:key:challenger".into(),
            responder_did: responder.into(),
            challenge_type: ChallengeType::SchemaValidation,
            verification_method: VerificationMethod::ChallengeVerified {
                challenge_type: ChallengeType::SchemaValidation,
            },
            result: serde_json::json!({"passed": true}),
            completed_at,
            verified_at: completed_at + 1,
        }
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

        store.cache_attestation("ctx-1", entry).unwrap();

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

        store.cache_attestation("ctx-1", entry1).unwrap();
        store.cache_attestation("ctx-1", entry2).unwrap();

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

    #[test]
    fn store_persists_and_retrieves_revocation_state() {
        let store = InMemoryTrustStore::new();

        let mut state = HashMap::new();
        state.insert("att-1".to_owned(), true);
        state.insert("att-2".to_owned(), false);

        store.set_revocation_state("ctx-1", &state).unwrap();

        let retrieved = store.get_revocation_state("ctx-1").unwrap();
        assert_eq!(retrieved.len(), 2);
        assert_eq!(retrieved.get("att-1"), Some(&true));
        assert_eq!(retrieved.get("att-2"), Some(&false));
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

        let cv = make_challenge_verification("ch-1", "did:key:alice", 1000);
        store.store_challenge_result("ctx-1", &cv).unwrap();

        let results = store
            .get_challenge_results("ctx-1", "did:key:alice")
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].challenge_id, "ch-1");
        assert_eq!(results[0].completed_at, 1000);
    }

    #[test]
    fn store_accumulates_multiple_challenge_results() {
        let store = InMemoryTrustStore::new();

        let cv1 = make_challenge_verification("ch-1", "did:key:alice", 1000);
        let cv2 = make_challenge_verification("ch-2", "did:key:alice", 2000);

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

        store.cache_attestation("ctx-1", entry).unwrap();

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
    fn cache_discards_expired_entries_that_fail_reverification() {
        let store = InMemoryTrustStore::new();
        let clock = TestClock::new(2000);

        let att = make_attestation("att-1", "did:key:alice", AttestationType::Endorsement);
        let entry = CachedAttestation {
            attestation: att,
            verified_at: 500,
            ttl_secs: 300,
        };

        store.cache_attestation("ctx-1", entry).unwrap();

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
        let resolver = TestResolver::new();

        // Seed the store with cached attestations.
        let att = make_attestation("att-1", "did:key:alice", AttestationType::Endorsement);
        let entry = CachedAttestation {
            attestation: att,
            verified_at: 1900,
            ttl_secs: 300,
        };
        store.cache_attestation("ctx-1", entry).unwrap();

        // Seed the store with challenge results.
        let cv = make_challenge_verification("ch-1", "did:key:alice", 1500);
        store.store_challenge_result("ctx-1", &cv).unwrap();

        let cache = AttestationCache::new(store);

        // Create events for behavioral record computation.
        let events = vec![
            make_event(EventType::MessageSent, "did:key:alice", 1000, 0, vec![]),
            make_event(EventType::MessageSent, "did:key:alice", 1500, 1, vec![]),
            make_event(
                EventType::ToolInvoked,
                "did:key:alice",
                1600,
                2,
                b"my-tool".to_vec(),
            ),
        ];

        // Define consequence rules.
        let consequence_rules = vec![ConsequenceRule {
            trigger: super::super::consequence::ConsequenceTrigger::MessageVelocity,
            action: super::super::consequence::ConsequenceAction::CapabilitySuspension(vec![
                "messages:write".to_owned(),
            ]),
            threshold: 10,
            window: Duration::from_secs(3600),
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
            clock: &clock,
        };

        let input = aggregate_trust_input(&ctx).unwrap();

        // Behavioral record.
        assert_eq!(input.behavioral_record.subject_did, "did:key:alice");
        assert_eq!(input.behavioral_record.context_id, "ctx-1");
        assert_eq!(input.behavioral_record.participation_count, 3);
        assert_eq!(
            input.behavioral_record.tool_invocations.get("my-tool"),
            Some(&1)
        );

        // Verified attestations.
        assert_eq!(input.verified_attestations.len(), 1);
        assert_eq!(input.verified_attestations[0].id, "att-1");

        // Challenge results.
        assert_eq!(input.challenge_results.len(), 1);
        assert_eq!(input.challenge_results[0].challenge_id, "ch-1");

        // Consequence structure.
        assert_eq!(input.consequence_structure.len(), 1);

        // Threshold counts (empty -- no requirements defined).
        assert!(input.threshold_counts.is_empty());
    }

    #[test]
    fn aggregate_computes_threshold_counts() {
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

        // Set up threshold requirements.
        let mut threshold_requirements = HashMap::new();
        threshold_requirements.insert(
            AttestationType::Endorsement,
            ThresholdRequirement {
                required_count: 3,
                total_attestors: 5,
                independence_threshold: 0.5,
            },
        );

        // Set up attestor sets with 2 matching attestors (below threshold).
        let mut attestor_sets = HashMap::new();
        attestor_sets.insert(
            AttestationType::Endorsement,
            vec![
                AttestorInfo {
                    did: "did:key:attestor1".into(),
                    context_memberships: std::collections::HashSet::new(),
                    endorsements: std::collections::HashSet::new(),
                    attestation: Some(make_attestation(
                        "att-a1",
                        "did:key:alice",
                        AttestationType::Endorsement,
                    )),
                },
                AttestorInfo {
                    did: "did:key:attestor2".into(),
                    context_memberships: std::collections::HashSet::new(),
                    endorsements: std::collections::HashSet::new(),
                    attestation: Some(make_attestation(
                        "att-a2",
                        "did:key:alice",
                        AttestationType::Endorsement,
                    )),
                },
            ],
        );

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
            clock: &clock,
        };

        let input = aggregate_trust_input(&ctx).unwrap();

        // Threshold counts should show (2, 3) for Endorsement type.
        let counts = input.threshold_counts.get(&AttestationType::Endorsement);
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
            clock: &clock,
        };

        let input = aggregate_trust_input(&ctx).unwrap();

        assert!(input.verified_attestations.is_empty());
        assert!(input.challenge_results.is_empty());
        assert!(input.consequence_structure.is_empty());
        assert!(input.threshold_counts.is_empty());
        assert_eq!(input.behavioral_record.participation_count, 1);
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
                action: super::super::consequence::ConsequenceAction::AccessRevocation,
                threshold: 10,
                window: Duration::from_secs(60),
            },
            ConsequenceRule {
                trigger: super::super::consequence::ConsequenceTrigger::ToolRateExceeded,
                action: super::super::consequence::ConsequenceAction::RoleDemotion {
                    to_role: "observer".to_owned(),
                },
                threshold: 5,
                window: Duration::from_secs(120),
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
            clock: &clock,
        };

        let input = aggregate_trust_input(&ctx).unwrap();

        assert_eq!(input.consequence_structure.len(), 2);
    }

    // -----------------------------------------------------------------------
    // compute_threshold_counts tests
    // -----------------------------------------------------------------------

    #[test]
    fn threshold_counts_with_no_requirements_returns_empty() {
        let requirements = HashMap::new();
        let attestor_sets = HashMap::new();

        let counts = compute_threshold_counts(&requirements, &attestor_sets);
        assert!(counts.is_empty());
    }

    #[test]
    fn threshold_counts_with_empty_attestor_set() {
        let mut requirements = HashMap::new();
        requirements.insert(
            AttestationType::ToolIntegrity,
            ThresholdRequirement {
                required_count: 2,
                total_attestors: 3,
                independence_threshold: 0.5,
            },
        );

        let attestor_sets = HashMap::new();

        let counts = compute_threshold_counts(&requirements, &attestor_sets);
        let (met, required) = counts.get(&AttestationType::ToolIntegrity).unwrap();
        assert_eq!(*met, 0);
        assert_eq!(*required, 2);
    }

    #[test]
    fn threshold_counts_multiple_types() {
        let mut requirements = HashMap::new();
        requirements.insert(
            AttestationType::Endorsement,
            ThresholdRequirement {
                required_count: 2,
                total_attestors: 3,
                independence_threshold: 0.0,
            },
        );
        requirements.insert(
            AttestationType::ToolIntegrity,
            ThresholdRequirement {
                required_count: 1,
                total_attestors: 2,
                independence_threshold: 0.0,
            },
        );

        let mut attestor_sets = HashMap::new();
        attestor_sets.insert(
            AttestationType::Endorsement,
            vec![AttestorInfo {
                did: "did:key:a".into(),
                context_memberships: std::collections::HashSet::new(),
                endorsements: std::collections::HashSet::new(),
                attestation: Some(make_attestation(
                    "att-1",
                    "did:key:alice",
                    AttestationType::Endorsement,
                )),
            }],
        );

        let counts = compute_threshold_counts(&requirements, &attestor_sets);

        // Endorsement: 1 met, 2 required.
        let (met, required) = counts.get(&AttestationType::Endorsement).unwrap();
        assert_eq!(*met, 1);
        assert_eq!(*required, 2);

        // ToolIntegrity: 0 met (no attestors), 1 required.
        let (met, required) = counts.get(&AttestationType::ToolIntegrity).unwrap();
        assert_eq!(*met, 0);
        assert_eq!(*required, 1);
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
            renewal_interval: Some(Duration::from_secs(600)),
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
