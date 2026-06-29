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
use scp_core::trust::{
    AttestationRevocationChecker, ChallengeVerification, TrustError, verify_challenge_verification,
};
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
// Verify-on-ingest support
// ---------------------------------------------------------------------------

/// External attestation revocation checker backed by a context's persisted
/// revocation list (an `attestation_id -> revoked` map from
/// [`get_revocation_state`](TrustProtocolRepository::get_revocation_state)).
///
/// [`verify_attestation`](scp_core::trust::verify_attestation) alone only checks
/// the issuer-bound `revocation_status` field carried on the attestation itself.
/// A validly-signed attestation that the issuer has separately revoked via the
/// context revocation list would still pass that field check. Wiring this
/// checker into ingest (mirroring the UCAN validation path) means a
/// context-revoked attestation is rejected before it can be cached or counted.
struct RevocationStateChecker<'a> {
    /// `attestation_id -> revoked` for the context.
    revoked: &'a HashMap<String, bool>,
}

impl AttestationRevocationChecker for RevocationStateChecker<'_> {
    fn check_revocation(&self, attestation_id: &str, _issuer: &scp_primitives::DID) -> Option<u64> {
        // The context revocation list stores only a boolean per attestation id
        // (no timestamp); report `0` as the revocation time when an id is
        // listed. That value only ever populates the dropped-entry log line, not
        // a user-facing field.
        if self.revoked.get(attestation_id).copied().unwrap_or(false) {
            Some(0)
        } else {
            None
        }
    }
}

/// Classifies a verify-on-ingest error.
///
/// Returns `true` for a verification REJECTION — the caller-supplied credential
/// is itself invalid (bad signature, expired, revoked, malformed
/// evidence/revocation), so dropping it and continuing is correct. Returns
/// `false` for an INFRA fault (store read/write failure, poisoned lock), which
/// MUST propagate: silently dropping every credential on a transient backend
/// error would zero a subject's trust without signal. Closed allowlist of
/// rejection variants (white-hat P2-d).
const fn is_verification_rejection(err: &TrustError) -> bool {
    matches!(
        err,
        TrustError::AttestationSignatureInvalid { .. }
            | TrustError::AttestationExpired { .. }
            | TrustError::AttestationRevoked { .. }
            | TrustError::AttestationRevocationInvalid { .. }
            | TrustError::AttestationEvidenceInvalid { .. }
            | TrustError::ChallengeVerificationSignatureInvalid { .. }
    )
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
    // `evaluate_trust`. Route each caller entry through
    // `verify_and_cache_with_revocation`, which verifies the Ed25519 signature
    // against the RESOLVER-resolved issuer key, checks expiry, the issuer-bound
    // `revocation_status` field, AND the context's external revocation list
    // BEFORE caching, and stamps a trusted `verified_at` from the injected clock
    // (the caller's is ignored). A verification REJECTION drops the entry; an
    // INFRA fault propagates so a backend error never silently zeroes trust.
    let revoked = cache.store().get_revocation_state(context_id)?;
    let revocation_checker = RevocationStateChecker { revoked: &revoked };
    for ca in cached_attestations {
        match cache.verify_and_cache_with_revocation(
            context_id,
            &ca.attestation,
            &resolver,
            &clock,
            Some(&revocation_checker),
        ) {
            Ok(()) => {}
            Err(reason) if is_verification_rejection(&reason) => {
                tracing::debug!(
                    attestation_id = %ca.attestation.id,
                    %reason,
                    "dropping caller-supplied attestation that failed verify-on-ingest",
                );
            }
            Err(infra) => return Err(infra),
        }
    }

    // SECURITY (verify-on-ingest). Caller-supplied challenge verifications carry
    // a caller-controlled `passed`/`score` trust signal that is only meaningful
    // because the verifier signs it (§7.3.4.2). Persisting them raw would let a
    // caller forge a `passed=true` record and have it counted as an
    // admission/trust signal — the same forgery class as the attestation path.
    // Verify the verifier's Ed25519 signature (resolver-resolved verifier key,
    // binding `passed`/`score`/`expires_at`/`subject_did`) BEFORE storing; drop
    // records that fail verification, and propagate infra faults so a backend
    // error does not silently discard a legitimate verifier's signal.
    for cr in challenge_results {
        match verify_challenge_verification(cr, &resolver) {
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
    // Every caller entry is verified (signature/expiry/issuer-field revocation
    // AND the context's external revocation list) against the resolver-resolved
    // issuer key via `verify_and_cache_with_revocation` BEFORE it can be counted.
    // A verification REJECTION drops the entry so a caller can never inflate
    // `attestation_count` with an unverified, freshly-marked, or context-revoked
    // entry; an INFRA fault propagates so a backend error never silently zeroes
    // the count.
    let revoked = cache.store().get_revocation_state(context_id)?;
    let revocation_checker = RevocationStateChecker { revoked: &revoked };
    for ca in cached_attestations {
        match cache.verify_and_cache_with_revocation(
            context_id,
            &ca.attestation,
            &resolver,
            &clock,
            Some(&revocation_checker),
        ) {
            Ok(()) => {}
            Err(reason) if is_verification_rejection(&reason) => {
                tracing::debug!(
                    attestation_id = %ca.attestation.id,
                    %reason,
                    "dropping caller-supplied attestation that failed verify-on-ingest",
                );
            }
            Err(infra) => return Err(infra),
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
        let issuer = scp_primitives::did_dht_from_public_key(&pubkey);
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
    /// against an over-strict regression in `verify_and_cache_with_revocation`
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
}
