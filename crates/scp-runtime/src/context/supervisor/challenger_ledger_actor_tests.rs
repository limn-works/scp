//! Tests of the challenger attempt ledger (spec 07 §7.3.4 steps 1, 3, 4).
//! Every request, response and record is built through the production
//! issue, respond, authenticate and grade steps.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};

use async_trait::async_trait;
use dashmap::DashMap;
use ed25519_dalek::{Signer, SigningKey, Verifier};
use serde_json::json;

use scp_clock::{Clock, TestClock};
use scp_did::DID;
use scp_protocol::trust::capability_definition::ProtocolOnlyDefinitions;
use scp_protocol::trust::{
    ActiveKeyResolver, AnswerKey, CanonicalIdentifier, ChallengeClosure, ChallengePolicy,
    ChallengeRequest, ChallengeResponse, ExpectedOutput, GradeError, GradeOutcome,
    MAX_GRADING_FAULTS, NewChallenge, OwnedAuthenticatedResponse, SchemaVerdict, TestCase,
    TestOutput, TrustError, authenticate_challenge_response, challenge_request_unsigned,
    challenge_response_signing_digest, challenge_response_unsigned,
    challenge_verification_signing_digest, grade,
};

use super::*;
use crate::crypto::mls::storage_adapter::OpenMlsStorageError;

/// A protocol row: `Total(20)`, 9500, 2 retries, cooldown 300.
const URI: &str = "scp:capability:schema-validation/v1";
const START: u64 = 1_700_000_000;
const WINDOW: u64 = 3600;
const COOLDOWN: u64 = 300;

// ---------------------------------------------------------------------------
// Storage with a write log and injected failures
// ---------------------------------------------------------------------------

#[derive(Default)]
struct TestStorage {
    kv: DashMap<String, Vec<u8>>,
    log: DashMap<usize, (String, Vec<u8>)>,
    writes: AtomicUsize,
    /// Stores still allowed before every store fails; negative is unlimited.
    stores_left: AtomicI64,
    fail_reads: AtomicBool,
}

impl TestStorage {
    fn new() -> Arc<Self> {
        let storage = Self::default();
        storage.stores_left.store(-1, Ordering::SeqCst);
        Arc::new(storage)
    }

    fn allow_stores(&self, n: i64) {
        self.stores_left.store(n, Ordering::SeqCst);
    }

    fn writes(&self) -> usize {
        self.writes.load(Ordering::SeqCst)
    }

    fn entry_versions(&self) -> Vec<LedgerEntry> {
        let mut log: Vec<(usize, (String, Vec<u8>))> = self
            .log
            .iter()
            .map(|e| (*e.key(), e.value().clone()))
            .collect();
        log.sort_by_key(|(n, _)| *n);
        log.into_iter()
            .filter(|(_, (key, _))| key.starts_with("scp-challenger/"))
            .map(|(_, (_, bytes))| rmp_serde::from_slice(&bytes).unwrap())
            .collect()
    }
}

fn injected() -> OpenMlsStorageError {
    OpenMlsStorageError::JoinFailure("injected failure".to_owned())
}

#[async_trait]
impl OpenMlsStorageAdapter for TestStorage {
    async fn store(&self, key: &str, value: &[u8]) -> Result<(), OpenMlsStorageError> {
        let left = self.stores_left.load(Ordering::SeqCst);
        if left == 0 {
            return Err(injected());
        }
        if left > 0 {
            self.stores_left.fetch_sub(1, Ordering::SeqCst);
        }
        let n = self.writes.fetch_add(1, Ordering::SeqCst);
        self.log.insert(n, (key.to_owned(), value.to_vec()));
        self.kv.insert(key.to_owned(), value.to_vec());
        Ok(())
    }

    async fn retrieve(&self, key: &str) -> Result<Option<Vec<u8>>, OpenMlsStorageError> {
        if self.fail_reads.load(Ordering::SeqCst) {
            return Err(injected());
        }
        Ok(self.kv.get(key).map(|v| v.value().clone()))
    }

    async fn delete(&self, key: &str) -> Result<(), OpenMlsStorageError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.kv.remove(key);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Parties
// ---------------------------------------------------------------------------

struct Keys(HashMap<String, Vec<u8>>);

impl ActiveKeyResolver for Keys {
    fn resolve_active_key(&self, did: &str) -> Result<Vec<u8>, TrustError> {
        self.0
            .get(did)
            .cloned()
            .ok_or_else(|| TrustError::KeyResolutionUnavailable {
                did: did.to_owned(),
                reason: "not in the test resolver".to_owned(),
            })
    }
}

struct Harness {
    verifier_key: SigningKey,
    verifier: DID,
    subject_key: SigningKey,
    subject: DID,
    resolver: Keys,
    clock: Arc<TestClock>,
    storage: Arc<TestStorage>,
    handle: ChallengerLedgerHandle,
}

fn party(seed: u8) -> (SigningKey, DID) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let did = scp_did::did_dht_from_public_key(&key.verifying_key().to_bytes());
    (key, did)
}

fn spawn(
    identity: &DID,
    storage: &Arc<TestStorage>,
    clock: &Arc<TestClock>,
) -> ChallengerLedgerHandle {
    let deps = ChallengerLedgerDeps {
        mls_storage: Arc::clone(storage) as Arc<dyn OpenMlsStorageAdapter>,
        clock: Arc::clone(clock) as Arc<dyn Clock>,
    };
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_GRADINGS_PER_CHALLENGER));
    ChallengerLedgerActor::spawn(
        CanonicalIdentifier::parse(identity).unwrap(),
        deps,
        semaphore,
    )
    .0
}

fn harness() -> Harness {
    let (verifier_key, verifier) = party(1);
    let (subject_key, subject) = party(2);
    let mut keys = HashMap::new();
    keys.insert(
        verifier.0.clone(),
        verifier_key.verifying_key().to_bytes().to_vec(),
    );
    keys.insert(
        subject.0.clone(),
        subject_key.verifying_key().to_bytes().to_vec(),
    );
    let clock = Arc::new(TestClock::new(START));
    let storage = TestStorage::new();
    let handle = spawn(&verifier, &storage, &clock);
    Harness {
        verifier_key,
        verifier,
        subject_key,
        subject,
        resolver: Keys(keys),
        clock,
        storage,
        handle,
    }
}

fn cases() -> Vec<TestCase> {
    (0..20)
        .map(|i| TestCase {
            test_id: format!("t{i}"),
            input: json!({"prompt": i}),
            expected: ExpectedOutput::ExactMatch { value: json!("ok") },
            category: "general".to_owned(),
            weight: 500,
        })
        .collect()
}

/// A Create command's outcome, with the answer key kept for grading.
#[derive(Debug)]
struct Issued {
    request: ChallengeRequest,
    key: AnswerKey,
}

impl Harness {
    fn signer(&self) -> CommandSigner {
        CommandSigner::local_ed25519(self.verifier_key.clone())
    }

    fn now(&self) -> u64 {
        self.clock.now_secs()
    }

    async fn create(&self) -> Result<Issued, ChallengeLedgerError> {
        self.create_with(&self.handle, self.signer()).await
    }

    async fn create_with(
        &self,
        handle: &ChallengerLedgerHandle,
        signer: CommandSigner,
    ) -> Result<Issued, ChallengeLedgerError> {
        let policy = ChallengePolicy::resolve(&ProtocolOnlyDefinitions, URI, None).unwrap();
        let definition = policy.definition().clone();
        let (unsigned, key) = challenge_request_unsigned(NewChallenge {
            verifier: self.verifier.clone(),
            subject: self.subject.clone(),
            test_cases: cases(),
            created_at: self.now(),
            window_secs: WINDOW,
            context_id: "ctx-1".to_owned(),
            policy,
        })
        .unwrap();
        let answer_key = key.clone();
        let request = handle
            .send(|reply| ChallengerLedgerCommand::Create {
                unsigned: Box::new(unsigned),
                answer_key,
                definition: Box::new(definition),
                evaluator_context_id: None,
                signer,
                reply,
            })
            .await?;
        Ok(Issued { request, key })
    }

    /// The subject's signed response, every answer `answer`.
    fn respond_response(
        &self,
        request: &ChallengeRequest,
        attempt: u32,
        answer: &str,
    ) -> ChallengeResponse {
        let outputs = request
            .test_cases
            .iter()
            .map(|c| TestOutput {
                test_id: c.test_id.clone(),
                output: json!(answer),
            })
            .collect();
        let unsigned = challenge_response_unsigned(
            request,
            &self.subject,
            attempt,
            outputs,
            &self.resolver,
            self.clock.as_ref(),
        )
        .unwrap();
        let signature = self.subject_key.sign(&unsigned.signing_digest());
        unsigned.with_subject_signature(signature.to_bytes().to_vec())
    }

    /// The subject's authenticated response, every answer `answer`.
    fn respond(
        &self,
        request: &ChallengeRequest,
        attempt: u32,
        answer: &str,
    ) -> Arc<OwnedAuthenticatedResponse> {
        let response = self.respond_response(request, attempt, answer);
        Arc::new(
            authenticate_challenge_response(request, &response, &self.verifier, &self.resolver)
                .unwrap()
                .to_owned_response(),
        )
    }

    /// A subject-signed response at `attempt`, built without the subject-side
    /// builder's attempt range check, as a dishonest subject would send it.
    /// Authentication does not bound the attempt, so only the ledger refuses it.
    fn respond_unbounded(
        &self,
        request: &ChallengeRequest,
        attempt: u32,
    ) -> Arc<OwnedAuthenticatedResponse> {
        let honest = self.respond_response(request, 1, "ok");
        let mut response = ChallengeResponse {
            attempt,
            subject_signature: Vec::new(),
            ..honest
        };
        let digest = challenge_response_signing_digest(&response).unwrap();
        response.subject_signature = self.subject_key.sign(&digest).to_bytes().to_vec();
        Arc::new(
            authenticate_challenge_response(request, &response, &self.verifier, &self.resolver)
                .unwrap()
                .to_owned_response(),
        )
    }

    async fn begin(
        &self,
        auth: &Arc<OwnedAuthenticatedResponse>,
    ) -> Result<BeginOutcome, ChallengeLedgerError> {
        self.handle
            .send(|reply| ChallengerLedgerCommand::BeginGrade {
                auth: Arc::clone(auth),
                signer: self.signer(),
                reply,
            })
            .await
    }

    async fn lease(&self, auth: &Arc<OwnedAuthenticatedResponse>) -> GradingLease {
        match self.begin(auth).await.unwrap() {
            BeginOutcome::Lease(lease) => lease,
            BeginOutcome::Stored(_) => panic!("expected a lease, got a stored record"),
        }
    }

    async fn commit_with(
        &self,
        auth: &Arc<OwnedAuthenticatedResponse>,
        lease_id: u64,
        key: &AnswerKey,
        signer: CommandSigner,
    ) -> Result<GradedAttempt, ChallengeLedgerError> {
        let outcome = outcome(auth, key);
        self.handle
            .send(|reply| ChallengerLedgerCommand::Commit {
                auth: Arc::clone(auth),
                lease_id,
                outcome,
                signer,
                reply,
            })
            .await
    }

    async fn commit(
        &self,
        auth: &Arc<OwnedAuthenticatedResponse>,
        lease_id: u64,
        key: &AnswerKey,
    ) -> Result<GradedAttempt, ChallengeLedgerError> {
        self.commit_with(auth, lease_id, key, self.signer()).await
    }

    /// Begin and Commit one attempt.
    async fn graded(&self, issued: &Issued, attempt: u32, answer: &str) -> GradedAttempt {
        let auth = self.respond(&issued.request, attempt, answer);
        let lease = self.lease(&auth).await;
        self.commit(&auth, lease.lease_id, &issued.key)
            .await
            .unwrap()
    }

    async fn fault(
        &self,
        challenge_id: [u8; 32],
        lease_id: u64,
    ) -> Result<FaultRecorded, ChallengeLedgerError> {
        self.handle
            .send(|reply| ChallengerLedgerCommand::RecordFault {
                challenge_id,
                lease_id,
                fault: GradingFault::AnswerKeyMismatch(GradeError::AnswerKeyMismatch {
                    test_id: "t0".to_owned(),
                }),
                reply,
            })
            .await
    }

    async fn lookup(
        &self,
        request: &ChallengeRequest,
        subject: &DID,
    ) -> Result<(), ChallengeLedgerError> {
        let request_digest =
            scp_protocol::trust::challenge_request_signing_digest(request).unwrap();
        let subject = CanonicalIdentifier::parse(subject).unwrap();
        self.handle
            .send(|reply| ChallengerLedgerCommand::Lookup {
                challenge_id: request.challenge_id,
                request_digest,
                subject,
                reply,
            })
            .await
    }

    fn assert_verifier_signed(&self, record: &scp_protocol::trust::ChallengeVerification) {
        let digest = challenge_verification_signing_digest(record).unwrap();
        let signature = ed25519_dalek::Signature::from_slice(&record.verifier_signature).unwrap();
        self.verifier_key
            .verifying_key()
            .verify(&digest, &signature)
            .unwrap();
    }
}

fn outcome(auth: &OwnedAuthenticatedResponse, key: &AnswerKey) -> GradeOutcome {
    let none_evals = BTreeMap::new();
    let none_schemas: BTreeMap<usize, SchemaVerdict> = BTreeMap::new();
    grade(&auth.as_authenticated(), key, &none_evals, &none_schemas).unwrap()
}

fn trust_err<T: std::fmt::Debug>(result: Result<T, ChallengeLedgerError>) -> TrustError {
    match result {
        Err(ChallengeLedgerError::Trust(e)) => e,
        other => panic!("expected a TrustError, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// An opening mismatch is a fault and uses no
/// attempt; attempt 1 is still the next attempt.
#[tokio::test]
async fn grade_opening_mismatch_is_fault_not_attempt() {
    let h = harness();
    let issued = h.create().await.unwrap();
    let auth = h.respond(&issued.request, 1, "ok");
    let lease = h.lease(&auth).await;
    let recorded = h
        .fault(issued.request.challenge_id, lease.lease_id)
        .await
        .unwrap();
    assert_eq!(
        recorded,
        FaultRecorded {
            faults: 1,
            closed: None
        }
    );
    // The fault released the lease and consumed nothing: attempt 1 grades.
    let lease = h.lease(&auth).await;
    let graded = h.commit(&auth, lease.lease_id, &issued.key).await.unwrap();
    assert_eq!(graded.record.attempt, 1);
    assert!(graded.record.passed);
}

/// `MAX_GRADING_FAULTS` faults close the challenge as
/// `Faulted`, and a later Begin is refused with `ChallengeFaulted`.
#[tokio::test]
async fn faults_close_at_max_grading_faults() {
    let h = harness();
    let issued = h.create().await.unwrap();
    let auth = h.respond(&issued.request, 1, "ok");
    for n in 1..=MAX_GRADING_FAULTS {
        let lease = h.lease(&auth).await;
        let recorded = h
            .fault(issued.request.challenge_id, lease.lease_id)
            .await
            .unwrap();
        assert_eq!(recorded.faults, n);
        let expected = (n == MAX_GRADING_FAULTS).then_some(ChallengeClosure::Faulted);
        assert_eq!(recorded.closed, expected);
    }
    assert!(matches!(
        trust_err(h.begin(&auth).await),
        TrustError::ChallengeFaulted {
            faults: MAX_GRADING_FAULTS,
            ..
        }
    ));
}

/// A live lease refuses a second Begin up to its deadline
/// (`now + budget + margin`); after it, a second Begin takes the lease and
/// the first Commit gets `GradingLeaseLost` and writes nothing.
#[tokio::test]
async fn grading_past_lease_deadline_loses_lease() {
    let h = harness();
    let issued = h.create().await.unwrap();
    let auth = h.respond(&issued.request, 1, "ok");
    let first = h.lease(&auth).await;
    assert!(matches!(
        trust_err(h.begin(&auth).await),
        TrustError::GradingInProgress { .. }
    ));
    h.clock
        .advance(CHALLENGE_GRADING_BUDGET_SECS + CHALLENGE_LEASE_MARGIN_SECS);
    assert!(matches!(
        trust_err(h.begin(&auth).await),
        TrustError::GradingInProgress { .. }
    ));
    h.clock.advance(1);
    let second = h.lease(&auth).await;
    assert_ne!(first.lease_id, second.lease_id);
    let writes = h.storage.writes();
    assert!(matches!(
        trust_err(h.commit(&auth, first.lease_id, &issued.key).await),
        TrustError::GradingLeaseLost { .. }
    ));
    assert_eq!(h.storage.writes(), writes, "a lost lease writes nothing");
    let graded = h.commit(&auth, second.lease_id, &issued.key).await.unwrap();
    assert_eq!(graded.record.attempt, 1);
}

/// Begin runs `check_attempt`, so inside the
/// cooldown or outside the window it takes no lease.
#[tokio::test]
async fn begin_refuses_inside_cooldown_and_outside_window_without_grading() {
    let h = harness();
    let issued = h.create().await.unwrap();
    h.graded(&issued, 1, "no").await;
    let auth = h.respond(&issued.request, 2, "no");
    h.clock.advance(COOLDOWN - 1);
    assert!(matches!(
        trust_err(h.begin(&auth).await),
        TrustError::CooldownActive { .. }
    ));
    // The refusal took no lease: once the cooldown ends, Begin succeeds.
    h.clock.advance(1);
    let lease = h.lease(&auth).await;
    h.fault(issued.request.challenge_id, lease.lease_id)
        .await
        .unwrap();
    h.clock.set(issued.request.expires_at + 1);
    assert!(matches!(
        trust_err(h.begin(&auth).await),
        TrustError::ChallengeExpired { .. }
    ));
}

/// With two retries, attempt 3 is graded and closes the
/// challenge as `Exhausted`; attempt 4 is refused.
#[tokio::test]
async fn ledger_refuses_beyond_max_retries() {
    let h = harness();
    let issued = h.create().await.unwrap();
    assert_eq!(issued.request.max_retries, 2);
    for attempt in 1..=3 {
        let graded = h.graded(&issued, attempt, "no").await;
        assert_eq!(graded.record.attempt, attempt);
        h.clock.advance(COOLDOWN);
    }
    // The builder refuses attempt 4 on the subject's side.
    assert!(matches!(
        challenge_response_unsigned(
            &issued.request,
            &h.subject,
            4,
            Vec::new(),
            &h.resolver,
            h.clock.as_ref(),
        ),
        Err(TrustError::RetriesExhausted {
            attempt: 4,
            allowed: 3,
            ..
        })
    ));
    // A dishonest subject signs attempt 4 anyway; the ledger is closed.
    let auth = h.respond_unbounded(&issued.request, 4);
    assert!(matches!(
        trust_err(h.begin(&auth).await),
        TrustError::ChallengeClosed { .. }
    ));
}

/// The cooldown runs from the last graded attempt, not from
/// `created_at`.
#[tokio::test]
async fn ledger_cooldown_boundary() {
    let h = harness();
    let issued = h.create().await.unwrap();
    h.clock.advance(100);
    h.graded(&issued, 1, "no").await;
    let auth = h.respond(&issued.request, 2, "ok");
    h.clock.advance(COOLDOWN - 1);
    match trust_err(h.begin(&auth).await) {
        TrustError::CooldownActive { retry_after, .. } => {
            assert_eq!(retry_after, issued.request.created_at + 100 + COOLDOWN);
        }
        other => panic!("expected CooldownActive, got {other:?}"),
    }
    h.clock.advance(1);
    let lease = h.lease(&auth).await;
    let graded = h.commit(&auth, lease.lease_id, &issued.key).await.unwrap();
    assert_eq!(graded.record.attempt, 2);
}

/// A passed challenge refuses the next attempt.
#[tokio::test]
async fn ledger_refuses_after_pass() {
    let h = harness();
    let issued = h.create().await.unwrap();
    assert!(h.graded(&issued, 1, "ok").await.record.passed);
    h.clock.advance(COOLDOWN);
    let auth = h.respond(&issued.request, 2, "ok");
    assert!(matches!(
        trust_err(h.begin(&auth).await),
        TrustError::ChallengeClosed { .. }
    ));
}

/// Attempt 1 again with a different `D_r` is out of order.
#[tokio::test]
async fn ledger_refuses_replayed_attempt_with_new_digest() {
    let h = harness();
    let issued = h.create().await.unwrap();
    h.graded(&issued, 1, "no").await;
    h.clock.advance(COOLDOWN);
    let replay = h.respond(&issued.request, 1, "ok");
    assert!(matches!(
        trust_err(h.begin(&replay).await),
        TrustError::AttemptOutOfOrder {
            attempt: 1,
            expected: 2,
            ..
        }
    ));
}

/// A resubmitted `(attempt, D_r)` returns the stored record
/// even after the challenge closed, and grades nothing.
#[tokio::test]
async fn ledger_resubmit_checked_first_returns_stored() {
    let h = harness();
    let issued = h.create().await.unwrap();
    let auth = h.respond(&issued.request, 1, "ok");
    let lease = h.lease(&auth).await;
    let graded = h.commit(&auth, lease.lease_id, &issued.key).await.unwrap();
    h.clock.advance(10);
    let writes = h.storage.writes();
    match h.begin(&auth).await.unwrap() {
        BeginOutcome::Stored(stored) => assert_eq!(*stored, graded),
        BeginOutcome::Lease(_) => panic!("a resubmit must not take a lease"),
    }
    assert_eq!(
        h.storage.writes(),
        writes,
        "a signed resubmit writes nothing"
    );
}

/// The first write holding an attempt also holds the
/// closure it causes.
#[tokio::test]
async fn ledger_pending_and_closure_one_write() {
    let h = harness();
    let issued = h.create().await.unwrap();
    h.graded(&issued, 1, "ok").await;
    let versions = h.storage.entry_versions();
    let first_with_attempt = versions
        .iter()
        .find(|v| !v.attempts.is_empty())
        .expect("an entry version holds the attempt");
    assert!(matches!(
        first_with_attempt.attempts[0].state,
        AttemptState::Pending(_)
    ));
    assert_eq!(first_with_attempt.closed, Some(ChallengeClosure::Passed));
}

/// A signer that reports Ed25519 and always fails.
struct RefusingSigner;

impl scp_crypto::DynScpSigner for RefusingSigner {
    fn algorithm(&self) -> scp_crypto::SigAlg {
        scp_crypto::SigAlg::Ed25519
    }

    fn public_key(&self) -> Vec<u8> {
        vec![0; 32]
    }

    fn sign_boxed<'a>(&'a self, _digest: &'a [u8; 32]) -> scp_crypto::SignFuture<'a> {
        Box::pin(async { Err(scp_crypto::SignError::Backend("refused".to_owned())) })
    }
}

/// The record is persisted before it is signed. A sign that
/// fails leaves a Pending attempt; after a restart, the resubmit re-signs it
/// with the persisted `timestamp`, so `D_v` is the one first computed.
#[tokio::test]
async fn ledger_restart_resigns_pending_same_digest() {
    let h = harness();
    let issued = h.create().await.unwrap();
    let auth = h.respond(&issued.request, 1, "no");
    let lease = h.lease(&auth).await;
    let graded_at = h.now();
    let refused = h
        .commit_with(
            &auth,
            lease.lease_id,
            &issued.key,
            CommandSigner::new(Arc::new(RefusingSigner)),
        )
        .await;
    assert!(matches!(refused, Err(ChallengeLedgerError::Context(_))));
    h.handle.send_shutdown().await.unwrap();

    h.clock.advance(COOLDOWN + 7);
    let restarted = spawn(&h.verifier, &h.storage, &h.clock);
    let stored = restarted
        .send(|reply| ChallengerLedgerCommand::BeginGrade {
            auth: Arc::clone(&auth),
            signer: h.signer(),
            reply,
        })
        .await
        .unwrap();
    let BeginOutcome::Stored(stored) = stored else {
        panic!("the Pending attempt must be returned, not graded again");
    };
    assert_eq!(stored.record.timestamp, graded_at);
    h.assert_verifier_signed(&stored.record);
}

/// An entry past `expires_at + CHALLENGE_CLOCK_SKEW_SECS` is
/// pruned from memory and storage, and grading it is `UnknownChallenge`.
#[tokio::test]
async fn ledger_prunes_and_refuses_unknown() {
    let h = harness();
    let issued = h.create().await.unwrap();
    let auth = h.respond(&issued.request, 1, "ok");
    h.lookup(&issued.request, &h.subject).await.unwrap();
    h.clock
        .set(issued.request.expires_at + CHALLENGE_CLOCK_SKEW_SECS + 1);
    assert!(matches!(
        trust_err(h.lookup(&issued.request, &h.subject).await),
        TrustError::UnknownChallenge { .. }
    ));
    assert!(matches!(
        trust_err(h.begin(&auth).await),
        TrustError::UnknownChallenge { .. }
    ));
    let entry_key = format!(
        "scp-challenger/{}/{}",
        h.verifier.0,
        hex::encode(issued.request.challenge_id)
    );
    assert!(
        !h.storage.kv.contains_key(&entry_key),
        "the entry is deleted"
    );
}

/// The ledger holds at most
/// `MAX_OPEN_CHALLENGES_PER_CHALLENGER` challenges.
#[tokio::test]
async fn ledger_index_bound() {
    let h = harness();
    for _ in 0..MAX_OPEN_CHALLENGES_PER_CHALLENGER {
        h.create().await.unwrap();
    }
    assert!(matches!(
        trust_err(h.create().await),
        TrustError::ChallengeNotOpen {
            open: MAX_OPEN_CHALLENGES_PER_CHALLENGER,
            ..
        }
    ));
}

/// Lookup is read-only and needs the id, the request digest and the
/// subject's key to match.
#[tokio::test]
async fn lookup_refuses_other_digest_or_subject_and_writes_nothing() {
    let h = harness();
    let issued = h.create().await.unwrap();
    let writes = h.storage.writes();
    h.lookup(&issued.request, &h.subject).await.unwrap();
    let mut altered = issued.request.clone();
    altered.context_id = "ctx-2".to_owned();
    assert!(matches!(
        trust_err(h.lookup(&altered, &h.subject).await),
        TrustError::UnknownChallenge { .. }
    ));
    let (_, other) = party(3);
    assert!(matches!(
        trust_err(h.lookup(&issued.request, &other).await),
        TrustError::UnknownChallenge { .. }
    ));
    assert_eq!(h.storage.writes(), writes);
}

/// A ledger that cannot load refuses every command instead of serving from
/// an empty ledger, and serves once a load succeeds.
#[tokio::test]
async fn unloadable_ledger_refuses_until_it_loads() {
    let h = harness();
    let issued = h.create().await.unwrap();
    h.handle.send_shutdown().await.unwrap();
    h.storage.fail_reads.store(true, Ordering::SeqCst);
    let restarted = spawn(&h.verifier, &h.storage, &h.clock);
    let auth = h.respond(&issued.request, 1, "ok");
    let refused = restarted
        .send(|reply| ChallengerLedgerCommand::BeginGrade {
            auth: Arc::clone(&auth),
            signer: h.signer(),
            reply,
        })
        .await;
    assert!(matches!(
        refused,
        Err(ChallengeLedgerError::Context(
            ContextError::PersistenceFailed(_)
        ))
    ));
    h.storage.fail_reads.store(false, Ordering::SeqCst);
    let begun = restarted
        .send(|reply| ChallengerLedgerCommand::BeginGrade {
            auth: Arc::clone(&auth),
            signer: h.signer(),
            reply,
        })
        .await
        .unwrap();
    assert!(matches!(begun, BeginOutcome::Lease(_)));
}

/// A failed write leaves the turn's state unchanged: Create persists before
/// it signs, so a refused index write leaves no challenge behind.
#[tokio::test]
async fn create_write_failure_creates_nothing() {
    let h = harness();
    h.storage.allow_stores(0);
    assert!(matches!(
        h.create().await,
        Err(ChallengeLedgerError::Context(
            ContextError::PersistenceFailed(_)
        ))
    ));
    h.storage.allow_stores(-1);
    let issued = h.create().await.unwrap();
    h.lookup(&issued.request, &h.subject).await.unwrap();
}

/// Create refuses a request whose verifier is not this ledger's identity.
#[tokio::test]
async fn create_refuses_foreign_verifier() {
    let h = harness();
    let (_, other) = party(4);
    let foreign = spawn(&other, &h.storage, &h.clock);
    assert!(matches!(
        trust_err(h.create_with(&foreign, h.signer()).await),
        TrustError::ChallengeVerifierMismatch { .. }
    ));
}
