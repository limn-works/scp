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

use scp_core::trust::aggregate::{CachedAttestation, TrustProtocolRepository};
use scp_core::trust::{ChallengeVerification, TrustError};
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
    TrustError::InvalidEventData {
        sequence: 0,
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
    let clock = scp_identity::cache::SystemClock;

    // SECURITY (verify-on-ingest). Caller-supplied attestations carry caller-
    // controlled `verified_at`/`ttl_secs`. Persisting them raw via
    // `store_cached_attestation` would let a caller mark a forged attestation
    // "fresh" so it is counted AND durably persisted UNVERIFIED — a forged
    // `attestation_count` plus persistent poisoning of every later
    // `evaluate_trust`. Route each caller entry through `verify_and_cache`, which
    // verifies the Ed25519 signature against the RESOLVER-resolved issuer key and
    // checks expiry/revocation BEFORE caching, and stamps a trusted `verified_at`
    // from the injected clock (the caller's is ignored). Entries that fail
    // verification are dropped — never counted, never persisted.
    for ca in cached_attestations {
        if let Err(reason) = cache.verify_and_cache(context_id, &ca.attestation, &resolver, &clock)
        {
            tracing::debug!(
                attestation_id = %ca.attestation.id,
                %reason,
                "dropping caller-supplied attestation that failed verify-on-ingest",
            );
        }
    }
    for cr in challenge_results {
        cache.store().store_challenge_result(context_id, cr)?;
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
/// [`SystemClock`](scp_identity::cache::SystemClock) wiring as
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
    let clock = scp_identity::cache::SystemClock;

    // SECURITY (verify-on-ingest). See `populate_and_aggregate`: caller-supplied
    // `verified_at`/`ttl_secs` are NOT trusted as proof of prior verification.
    // Every caller entry is verified (signature/expiry/revocation) against the
    // resolver-resolved issuer key via `verify_and_cache` BEFORE it can be
    // counted; forged/expired/revoked entries are dropped, so a caller can never
    // inflate `attestation_count` with an unverified, freshly-marked entry.
    for ca in cached_attestations {
        if let Err(reason) = cache.verify_and_cache(context_id, &ca.attestation, &resolver, &clock)
        {
            tracing::debug!(
                attestation_id = %ca.attestation.id,
                %reason,
                "dropping caller-supplied attestation that failed verify-on-ingest",
            );
        }
    }

    cache.get_verified_attestations(context_id, subject_did, &resolver, &clock)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use scp_core::trust::AttestationType;
    use scp_core::trust::attestation::RevocationStatus;
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

    fn make_challenge_result(id: &str, subject: &str, context_id: &str) -> ChallengeVerification {
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
            context_id: Some(context_id.to_owned()),
            verifier_signature: vec![0u8; 64],
        }
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

    // -----------------------------------------------------------------------
    // Integration test: full aggregation pipeline
    // -----------------------------------------------------------------------

    /// Exercises the full aggregation pipeline through `InMemoryFfiTrustStore`
    /// with real data — events, cached attestations, challenge results, and
    /// consequence rules — verifying the aggregated `TrustInput` output.
    #[test]
    fn aggregate_pipeline_with_populated_store() {
        use scp_core::context::roles::Capability;
        use scp_core::trust::ConsequenceRule;
        use scp_core::trust::aggregate::{AggregationContext, AttestationCache};
        use scp_core::trust::consequence::{
            ConsequenceAction, ConsequenceTrigger, EnforcementSeverity,
        };
        use scp_identity::cache::TestClock;

        let context_id = "ctx-integration";
        let subject_did = "did:key:alice";
        let clock = TestClock::new(2000);
        let resolver = NoOpResolver;

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

        let cr = make_challenge_result("cv-1", subject_did, context_id);
        store.store_challenge_result(context_id, &cr).unwrap();

        // --- Build events ---
        let events = vec![
            make_event(EventType::MessageSent, subject_did, 1000, 0, vec![]),
            make_event(EventType::MessageSent, subject_did, 1200, 1, vec![]),
            make_event(EventType::GovernanceAction, subject_did, 1400, 2, vec![]),
            make_event(
                EventType::ToolInvoked,
                subject_did,
                1600,
                3,
                b"review-tool".to_vec(),
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
                .tool_invocations
                .get("review-tool"),
            Some(&1)
        );

        assert_eq!(input.verified_attestations.len(), 1);
        assert_eq!(input.verified_attestations[0].id, "att-integration-1");
        assert_eq!(
            input.verified_attestations[0].attestation_type,
            AttestationType::Endorsement
        );

        assert_eq!(input.challenge_results.len(), 1);
        assert_eq!(input.challenge_results[0].verification_id, "cv-1");
        assert!(input.challenge_results[0].passed);
        assert_eq!(input.challenge_results[0].score, Some(95));

        assert_eq!(input.consequence_structure.len(), 1);
        assert!(input.threshold_counts.is_empty());

        // Verify JSON serialization (as the FFI bridges do).
        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("att-integration-1"));
        assert!(json.contains("cv-1"));
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
}
