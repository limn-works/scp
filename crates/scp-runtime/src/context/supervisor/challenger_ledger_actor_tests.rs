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
    ActiveKeyResolver, AnswerKey, AuthenticatedResponse, CanonicalIdentifier, ChallengeClosure,
    ChallengePolicy, ChallengeRequest, ChallengeResponse, ExpectedOutput, GradeOutcome,
    NewChallenge, PolicyPick, SchemaVerdict, TestCase, TestOutput, TrustError,
    authenticate_challenge_response, challenge_request_signing_digest, challenge_request_unsigned,
    challenge_response_signing_digest, challenge_response_unsigned,
    challenge_verification_signing_digest, grade,
};

use super::*;
use crate::crypto::mls::storage_adapter::OpenMlsStorageError;

/// A protocol row: `Total(20)`, 9500, 2 retries, cooldown 300.
const URI: &str = "scp:capability:schema-validation/v1";
/// Another protocol row: `Total(15)`, 9500, 2 retries, cooldown 300.
const OTHER_URI: &str = "scp:capability:outlet-schema-compliance/v1";
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
    fail_deletes: AtomicBool,
    /// Fails every write of the challenger index, and no other write.
    fail_index_stores: AtomicBool,
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
        if key.starts_with("scp-challenger-ids/") && self.fail_index_stores.load(Ordering::SeqCst) {
            return Err(injected());
        }
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
        if self.fail_deletes.load(Ordering::SeqCst) {
            return Err(injected());
        }
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
    keyed(SigningKey::from_bytes(&[seed; 32]))
}

/// The `n`th of many distinct subjects; never equal to a [`party`].
fn numbered_party(n: u16) -> (SigningKey, DID) {
    let mut seed = [0x5a_u8; 32];
    seed[..2].copy_from_slice(&n.to_le_bytes());
    keyed(SigningKey::from_bytes(&seed))
}

fn keyed(key: SigningKey) -> (SigningKey, DID) {
    let did = scp_did::did_dht_from_public_key(&key.verifying_key().to_bytes());
    (key, did)
}

/// Spawns a ledger actor. `shared` is the state a respawn keeps; a fresh
/// ledger takes `ChallengerLedgerShared::new()`.
fn spawn(
    identity: &DID,
    storage: &Arc<TestStorage>,
    clock: &Arc<TestClock>,
    shared: ChallengerLedgerShared,
) -> ChallengerLedgerHandle {
    let deps = ChallengerLedgerDeps {
        mls_storage: Arc::clone(storage) as Arc<dyn OpenMlsStorageAdapter>,
        clock: Arc::clone(clock) as Arc<dyn Clock>,
    };
    ChallengerLedgerActor::spawn(CanonicalIdentifier::parse(identity).unwrap(), deps, shared).0
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
    let handle = spawn(&verifier, &storage, &clock, ChallengerLedgerShared::new());
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

    /// Creates a challenge to the harness subject for `URI`, then advances the
    /// clock one second, to the first instant strictly inside the window
    /// (RULING 5), so the challenge is gradable at once.
    async fn create(&self) -> Result<Issued, ChallengeLedgerError> {
        let issued = self
            .create_as(&self.handle, self.signer(), &self.subject, URI)
            .await?;
        self.clock.advance(1);
        Ok(issued)
    }

    /// The unsigned request to `subject` for `uri`, created now, and its
    /// answer key.
    fn unsigned_for(&self, subject: &DID, uri: &str) -> (UnsignedChallengeRequest, AnswerKey) {
        let policy =
            ChallengePolicy::resolve(&ProtocolOnlyDefinitions, uri, PolicyPick::default()).unwrap();
        challenge_request_unsigned(NewChallenge {
            verifier: self.verifier.clone(),
            subject: subject.clone(),
            test_cases: cases(),
            created_at: self.now(),
            window_secs: WINDOW,
            context_id: "ctx-1".to_owned(),
            policy,
        })
        .unwrap()
    }

    async fn send_create(
        handle: &ChallengerLedgerHandle,
        unsigned: UnsignedChallengeRequest,
        answer_key: AnswerKey,
        signer: CommandSigner,
    ) -> Result<ChallengeRequest, ChallengeLedgerError> {
        handle
            .send(|reply| ChallengerLedgerCommand::Create {
                unsigned: Box::new(unsigned),
                answer_key,
                evaluator_context_id: None,
                signer,
                reply,
            })
            .await
    }

    /// Creates a challenge to `subject` for `uri` at the clock's time,
    /// without advancing it.
    async fn create_as(
        &self,
        handle: &ChallengerLedgerHandle,
        signer: CommandSigner,
        subject: &DID,
        uri: &str,
    ) -> Result<Issued, ChallengeLedgerError> {
        let (unsigned, key) = self.unsigned_for(subject, uri);
        let request = Self::send_create(handle, unsigned, key.clone(), signer).await?;
        Ok(Issued { request, key })
    }

    /// `subject`'s signed response, every answer `answer`.
    fn response_as(
        &self,
        (subject_key, subject): &(SigningKey, DID),
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
            subject,
            attempt,
            outputs,
            &self.resolver_with(subject_key, subject),
            self.clock.as_ref(),
        )
        .unwrap();
        let signature = subject_key.sign(&unsigned.signing_digest());
        unsigned.with_subject_signature(signature.to_bytes().to_vec())
    }

    /// The verifier's key and `subject`'s.
    fn resolver_with(&self, subject_key: &SigningKey, subject: &DID) -> Keys {
        let mut keys = self.resolver.0.clone();
        keys.insert(
            subject.0.clone(),
            subject_key.verifying_key().to_bytes().to_vec(),
        );
        Keys(keys)
    }

    /// `subject`'s authenticated response, every answer `answer`.
    fn respond_as(
        &self,
        subject: &(SigningKey, DID),
        request: &ChallengeRequest,
        attempt: u32,
        answer: &str,
    ) -> Arc<AuthenticatedResponse> {
        let response = self.response_as(subject, request, attempt, answer);
        Arc::new(
            authenticate_challenge_response(
                request.clone(),
                response,
                &self.verifier,
                &self.resolver_with(&subject.0, &subject.1),
            )
            .unwrap(),
        )
    }

    fn me(&self) -> (SigningKey, DID) {
        (self.subject_key.clone(), self.subject.clone())
    }

    /// The harness subject's signed response, every answer `answer`.
    fn respond_response(
        &self,
        request: &ChallengeRequest,
        attempt: u32,
        answer: &str,
    ) -> ChallengeResponse {
        self.response_as(&self.me(), request, attempt, answer)
    }

    /// The harness subject's authenticated response, every answer `answer`.
    fn respond(
        &self,
        request: &ChallengeRequest,
        attempt: u32,
        answer: &str,
    ) -> Arc<AuthenticatedResponse> {
        self.respond_as(&self.me(), request, attempt, answer)
    }

    /// A subject-signed response at `attempt`, built without the subject-side
    /// builder's attempt range check, as a dishonest subject would send it.
    /// Authentication does not bound the attempt, so only the ledger refuses it.
    fn respond_unbounded(
        &self,
        request: &ChallengeRequest,
        attempt: u32,
    ) -> Arc<AuthenticatedResponse> {
        let honest = self.respond_response(request, 1, "ok");
        let mut response = ChallengeResponse {
            attempt,
            subject_signature: Vec::new(),
            ..honest
        };
        let digest = challenge_response_signing_digest(&response).unwrap();
        response.subject_signature = self.subject_key.sign(&digest).to_bytes().to_vec();
        Arc::new(
            authenticate_challenge_response(
                request.clone(),
                response,
                &self.verifier,
                &self.resolver,
            )
            .unwrap(),
        )
    }

    async fn begin(
        &self,
        auth: &Arc<AuthenticatedResponse>,
    ) -> Result<BeginOutcome, ChallengeLedgerError> {
        begin_on(&self.handle, auth).await
    }

    async fn lease(&self, auth: &Arc<AuthenticatedResponse>) -> GradingLease {
        lease_on(&self.handle, auth).await
    }

    async fn commit_with(
        &self,
        auth: &Arc<AuthenticatedResponse>,
        lease_id: u64,
        key: &AnswerKey,
        signer: CommandSigner,
    ) -> Result<GradedAttempt, ChallengeLedgerError> {
        commit_on(&self.handle, auth, lease_id, key, signer).await
    }

    async fn commit(
        &self,
        auth: &Arc<AuthenticatedResponse>,
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
        auth: &Arc<AuthenticatedResponse>,
        lease_id: u64,
    ) -> Result<(), ChallengeLedgerError> {
        fault_on(&self.handle, auth, lease_id).await
    }

    async fn lookup(
        &self,
        request: &ChallengeRequest,
        subject: &DID,
        response: &ChallengeResponse,
    ) -> Result<(), ChallengeLedgerError> {
        let request_digest = challenge_request_signing_digest(request).unwrap();
        let response_digest = challenge_response_signing_digest(response).unwrap();
        let subject = CanonicalIdentifier::parse(subject).unwrap();
        self.handle
            .send(|reply| ChallengerLedgerCommand::Lookup {
                challenge_id: request.challenge_id,
                request_digest,
                subject,
                response_digest,
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

    /// The storage key of `challenge_id`'s entry.
    fn entry_key(&self, challenge_id: &[u8; 32]) -> String {
        format!(
            "scp-challenger/{}/{}",
            self.verifier.0,
            hex::encode(challenge_id)
        )
    }

    /// The challenge ids the durable index names.
    fn index_ids(&self) -> Vec<String> {
        let bytes = self
            .storage
            .kv
            .get(&format!("scp-challenger-ids/{}", self.verifier.0))
            .map(|v| v.value().clone())
            .unwrap_or_default();
        if bytes.is_empty() {
            return Vec::new();
        }
        rmp_serde::from_slice(&bytes).unwrap()
    }

    /// Stops the actor and spawns its replacement with the same shared state,
    /// as the supervisor does.
    async fn respawn(&self) -> ChallengerLedgerHandle {
        self.handle.send_shutdown().await.unwrap();
        spawn(
            &self.verifier,
            &self.storage,
            &self.clock,
            self.handle.shared(),
        )
    }
}

async fn begin_on(
    handle: &ChallengerLedgerHandle,
    auth: &Arc<AuthenticatedResponse>,
) -> Result<BeginOutcome, ChallengeLedgerError> {
    handle
        .send(|reply| ChallengerLedgerCommand::BeginGrade {
            auth: Arc::clone(auth),
            reply,
        })
        .await
}

async fn lease_on(
    handle: &ChallengerLedgerHandle,
    auth: &Arc<AuthenticatedResponse>,
) -> GradingLease {
    match begin_on(handle, auth).await.unwrap() {
        BeginOutcome::Lease(lease) => Ok(lease),
        BeginOutcome::Stored(stored) => Err(stored),
    }
    .expect("expected a lease, got a stored record")
}

async fn commit_on(
    handle: &ChallengerLedgerHandle,
    auth: &Arc<AuthenticatedResponse>,
    lease_id: u64,
    key: &AnswerKey,
    signer: CommandSigner,
) -> Result<GradedAttempt, ChallengeLedgerError> {
    let outcome = outcome(auth, key);
    handle
        .send(|reply| ChallengerLedgerCommand::Commit {
            auth: Arc::clone(auth),
            lease_id,
            outcome,
            signer,
            reply,
        })
        .await
}

async fn fault_on(
    handle: &ChallengerLedgerHandle,
    auth: &Arc<AuthenticatedResponse>,
    lease_id: u64,
) -> Result<(), ChallengeLedgerError> {
    handle
        .send(|reply| ChallengerLedgerCommand::RecordFault {
            auth: Arc::clone(auth),
            lease_id,
            fault: TrustError::SchemaRejected {
                test_id: "t0".to_owned(),
                reason: "schema gate".to_owned(),
            },
            reply,
        })
        .await
}

fn outcome(auth: &AuthenticatedResponse, key: &AnswerKey) -> GradeOutcome {
    let none_evals = BTreeMap::new();
    let none_schemas: BTreeMap<usize, SchemaVerdict> = BTreeMap::new();
    grade(auth, key, &none_evals, &none_schemas)
}

fn trust_err<T: std::fmt::Debug>(result: Result<T, ChallengeLedgerError>) -> TrustError {
    match result {
        Err(ChallengeLedgerError::Trust(e)) => Ok(e),
        other => Err(other),
    }
    .expect("expected a TrustError")
}

fn is_persistence_failure<T: std::fmt::Debug>(result: &Result<T, ChallengeLedgerError>) -> bool {
    matches!(
        result,
        Err(ChallengeLedgerError::Context(
            ContextError::PersistenceFailed(_)
        ))
    )
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

fn refusing() -> CommandSigner {
    CommandSigner::new(Arc::new(RefusingSigner))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// T8: a fault uses no attempt and closes nothing, but restarts the
/// cooldown: Begin is refused until `fault + cooldown`, then attempt 1
/// grades.
#[tokio::test]
async fn fault_uses_no_attempt_and_starts_the_cooldown() {
    let h = harness();
    let issued = h.create().await.unwrap();
    let auth = h.respond(&issued.request, 1, "ok");
    let lease = h.lease(&auth).await;
    let fault_at = h.now();
    h.fault(&auth, lease.lease_id).await.unwrap();
    h.clock.advance(COOLDOWN - 1);
    let refusal = trust_err(h.begin(&auth).await);
    assert!(
        matches!(refusal, TrustError::CooldownActive { retry_after, .. } if retry_after == fault_at + COOLDOWN),
        "expected CooldownActive until {}, got {refusal:?}",
        fault_at + COOLDOWN
    );
    h.clock.advance(1);
    let lease = h.lease(&auth).await;
    let graded = h.commit(&auth, lease.lease_id, &issued.key).await.unwrap();
    assert_eq!(graded.record.attempt, 1);
    assert!(graded.record.passed);
}

/// T8: four faults leave the challenge open, each restarting the cooldown;
/// after them attempt 1 still grades, and the cooldown before attempt 2
/// runs from that attempt, the later event.
#[tokio::test]
async fn four_faults_leave_the_challenge_open() {
    let h = harness();
    let issued = h.create().await.unwrap();
    let auth = h.respond(&issued.request, 1, "no");
    for _ in 0..4 {
        let lease = h.lease(&auth).await;
        h.fault(&auth, lease.lease_id).await.unwrap();
        assert!(matches!(
            trust_err(h.begin(&auth).await),
            TrustError::CooldownActive { .. }
        ));
        h.clock.advance(COOLDOWN);
    }
    let lease = h.lease(&auth).await;
    let graded = h.commit(&auth, lease.lease_id, &issued.key).await.unwrap();
    assert_eq!(graded.record.attempt, 1);
    let second = h.respond(&issued.request, 2, "ok");
    h.clock.advance(COOLDOWN - 1);
    let refusal = trust_err(h.begin(&second).await);
    assert!(
        matches!(refusal, TrustError::CooldownActive { retry_after, .. } if retry_after == graded.record.timestamp + COOLDOWN),
        "expected CooldownActive until {}, got {refusal:?}",
        graded.record.timestamp + COOLDOWN
    );
    h.clock.advance(1);
    h.lease(&second).await;
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

/// Begin runs `check_attempt`, so inside the cooldown or at the window's
/// end (RULING 5: strictly inside) it takes no lease.
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
    h.fault(&auth, lease.lease_id).await.unwrap();
    h.clock.set(issued.request.expires_at);
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
    let first = h.graded(&issued, 1, "no").await;
    let auth = h.respond(&issued.request, 2, "ok");
    h.clock.advance(COOLDOWN - 1);
    let refusal = trust_err(h.begin(&auth).await);
    assert!(
        matches!(refusal, TrustError::CooldownActive { retry_after, .. } if retry_after == first.record.timestamp + COOLDOWN),
        "expected CooldownActive until {}, got {refusal:?}",
        first.record.timestamp + COOLDOWN
    );
    assert!(first.record.timestamp > issued.request.created_at + 100);
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

/// Commit runs the attempt check again at its own `t` (spec 07 §7.3.4 step
/// 4): an attempt that began at the last second inside the window and
/// commits at `expires_at` is refused with `ChallengeExpired` while its lease
/// is still live, and writes no record. The attempt stays unused, so a
/// resubmit is refused by Begin for the same reason, not served as stored.
#[tokio::test]
async fn commit_reruns_the_attempt_check_and_writes_nothing_when_it_fails() {
    let h = harness();
    let issued = h.create().await.unwrap();
    h.clock.set(issued.request.expires_at - 1);
    let auth = h.respond(&issued.request, 1, "ok");
    let lease = h.lease(&auth).await;
    h.clock.advance(1);
    let writes = h.storage.writes();
    let refusal = trust_err(h.commit(&auth, lease.lease_id, &issued.key).await);
    assert!(
        matches!(refusal, TrustError::ChallengeExpired { .. }),
        "commit at expires_at must re-run the attempt check, got {refusal:?}"
    );
    assert_eq!(
        h.storage.writes(),
        writes,
        "a refused commit writes nothing"
    );
    assert!(
        h.storage
            .entry_versions()
            .iter()
            .all(|v| v.attempts.is_empty()),
        "no stored entry holds an attempt"
    );
    assert!(matches!(
        trust_err(h.begin(&auth).await),
        TrustError::ChallengeExpired { .. }
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
/// even after the challenge closed, and grades and writes nothing.
#[tokio::test]
async fn ledger_resubmit_checked_first_returns_stored() {
    let h = harness();
    let issued = h.create().await.unwrap();
    let auth = h.respond(&issued.request, 1, "ok");
    let lease = h.lease(&auth).await;
    let graded = h.commit(&auth, lease.lease_id, &issued.key).await.unwrap();
    h.clock.advance(10);
    let writes = h.storage.writes();
    let resubmit = h.begin(&auth).await.unwrap();
    assert!(
        matches!(&resubmit, BeginOutcome::Stored(stored) if **stored == graded),
        "a resubmit must return the stored record and take no lease, got {resubmit:?}"
    );
    assert_eq!(h.storage.writes(), writes, "a resubmit writes nothing");
}

/// The one write that holds an attempt holds its signed record and the
/// closure it causes.
#[tokio::test]
async fn ledger_signed_attempt_and_closure_one_write() {
    let h = harness();
    let issued = h.create().await.unwrap();
    h.graded(&issued, 1, "ok").await;
    let versions = h.storage.entry_versions();
    let with_attempt: Vec<&LedgerEntry> =
        versions.iter().filter(|v| !v.attempts.is_empty()).collect();
    assert_eq!(with_attempt.len(), 1, "one write records the attempt");
    h.assert_verifier_signed(&with_attempt[0].attempts[0].record);
    assert_eq!(with_attempt[0].closed, Some(ChallengeClosure::Passed));
    // The entry stores the signed request.
    assert_eq!(versions[0].request, issued.request);
    assert!(!versions[0].request.verifier_signature.is_empty());
}

/// T9: Create signs before it writes, so a sign failure writes nothing, and
/// the subject is not blocked by a challenge that does not exist.
#[tokio::test]
async fn create_sign_failure_persists_nothing() {
    let h = harness();
    let writes = h.storage.writes();
    let refused = h.create_as(&h.handle, refusing(), &h.subject, URI).await;
    assert!(
        matches!(refused, Err(ChallengeLedgerError::Context(_))),
        "{refused:?}"
    );
    assert_eq!(h.storage.writes(), writes, "a sign failure writes nothing");
    assert!(h.index_ids().is_empty());
    h.create_as(&h.handle, h.signer(), &h.subject, URI)
        .await
        .unwrap();
}

/// T9 and TQ5 (index and entry sites): a failed index write or entry write
/// refuses Create and leaves no challenge, in memory or after a respawn, so
/// Lookup refuses it and the subject can be challenged again. The next index
/// write drops the id an entry write failure left behind.
#[tokio::test]
async fn create_write_failure_creates_nothing() {
    let h = harness();
    h.storage.allow_stores(0);
    assert!(is_persistence_failure(&h.create().await));
    h.storage.allow_stores(1);
    let (unsigned, key) = h.unsigned_for(&h.subject, URI);
    // Sign a copy as Create would, so the subject can respond to the
    // request the refused Create would have issued.
    let signature = h.verifier_key.sign(&unsigned.signing_digest());
    let request = unsigned
        .clone()
        .with_verifier_signature(signature.to_bytes().to_vec());
    h.clock.advance(1);
    let response = h.respond_response(&request, 1, "ok");
    let refused = Harness::send_create(&h.handle, unsigned, key, h.signer()).await;
    assert!(is_persistence_failure(&refused), "{refused:?}");
    h.storage.allow_stores(-1);
    let orphan = hex::encode(request.challenge_id);
    assert_eq!(h.index_ids(), vec![orphan.clone()], "the index write held");
    assert!(
        !h.storage
            .kv
            .contains_key(&h.entry_key(&request.challenge_id))
    );
    assert!(matches!(
        trust_err(h.lookup(&request, &h.subject, &response).await),
        TrustError::UnknownChallenge { .. }
    ));
    let restarted = h.respawn().await;
    let request_digest = challenge_request_signing_digest(&request).unwrap();
    let response_digest = challenge_response_signing_digest(&response).unwrap();
    let after_respawn = restarted
        .send(|reply| ChallengerLedgerCommand::Lookup {
            challenge_id: request.challenge_id,
            request_digest,
            subject: CanonicalIdentifier::parse(&h.subject).unwrap(),
            response_digest,
            reply,
        })
        .await;
    assert!(matches!(
        trust_err(after_respawn),
        TrustError::UnknownChallenge { .. }
    ));
    let issued = h
        .create_as(&restarted, h.signer(), &h.subject, URI)
        .await
        .unwrap();
    assert_eq!(
        h.index_ids(),
        vec![hex::encode(issued.request.challenge_id)]
    );
}

/// TQ5 (index site alone): when only the index write fails, Create refuses
/// before the entry write, so no entry is stored and the subject is not
/// blocked.
#[tokio::test]
async fn create_index_write_failure_alone_creates_nothing() {
    let h = harness();
    h.storage.fail_index_stores.store(true, Ordering::SeqCst);
    let (unsigned, key) = h.unsigned_for(&h.subject, URI);
    let challenge_id = unsigned.request().challenge_id;
    let refused = Harness::send_create(&h.handle, unsigned, key, h.signer()).await;
    assert!(is_persistence_failure(&refused), "{refused:?}");
    h.storage.fail_index_stores.store(false, Ordering::SeqCst);
    assert!(!h.storage.kv.contains_key(&h.entry_key(&challenge_id)));
    h.create_as(&h.handle, h.signer(), &h.subject, URI)
        .await
        .unwrap();
}

/// T9: Commit signs before it writes, so a sign failure writes nothing,
/// releases the lease and uses no attempt; attempt 1 then grades. After a
/// respawn the ledger holds no attempt.
#[tokio::test]
async fn commit_sign_failure_records_nothing() {
    let h = harness();
    let issued = h.create().await.unwrap();
    let auth = h.respond(&issued.request, 1, "no");
    let lease = h.lease(&auth).await;
    let writes = h.storage.writes();
    let refused = h
        .commit_with(&auth, lease.lease_id, &issued.key, refusing())
        .await;
    assert!(matches!(refused, Err(ChallengeLedgerError::Context(_))));
    assert_eq!(h.storage.writes(), writes, "a sign failure writes nothing");
    let restarted = h.respawn().await;
    let lease = lease_on(&restarted, &auth).await;
    let graded = commit_on(&restarted, &auth, lease.lease_id, &issued.key, h.signer())
        .await
        .unwrap();
    assert_eq!(graded.record.attempt, 1);
    h.assert_verifier_signed(&graded.record);
}

/// TQ5 (attempt site): a failed attempt write refuses Commit, releases the
/// lease and uses no attempt.
#[tokio::test]
async fn commit_write_failure_records_nothing() {
    let h = harness();
    let issued = h.create().await.unwrap();
    let auth = h.respond(&issued.request, 1, "ok");
    let lease = h.lease(&auth).await;
    h.storage.allow_stores(0);
    assert!(is_persistence_failure(
        &h.commit(&auth, lease.lease_id, &issued.key).await
    ));
    h.storage.allow_stores(-1);
    let lease = h.lease(&auth).await;
    let graded = h.commit(&auth, lease.lease_id, &issued.key).await.unwrap();
    assert_eq!(graded.record.attempt, 1);
}

/// TQ5 (fault site): a failed fault write refuses `RecordFault` and records
/// no fault, so a respawned ledger starts no cooldown.
#[tokio::test]
async fn fault_write_failure_records_nothing() {
    let h = harness();
    let issued = h.create().await.unwrap();
    let auth = h.respond(&issued.request, 1, "ok");
    let lease = h.lease(&auth).await;
    h.storage.allow_stores(0);
    assert!(is_persistence_failure(
        &h.fault(&auth, lease.lease_id).await
    ));
    h.storage.allow_stores(-1);
    let restarted = h.respawn().await;
    lease_on(&restarted, &auth).await;
}

/// A failed fault write releases the lease, as a failed Commit does: the
/// same actor, without a respawn, grants the next Begin a new lease, and no
/// cooldown runs because no fault was recorded.
#[tokio::test]
async fn fault_write_failure_releases_the_lease() {
    let h = harness();
    let issued = h.create().await.unwrap();
    let auth = h.respond(&issued.request, 1, "ok");
    let lease = h.lease(&auth).await;
    h.storage.allow_stores(0);
    assert!(is_persistence_failure(
        &h.fault(&auth, lease.lease_id).await
    ));
    h.storage.allow_stores(-1);
    let next = h.lease(&auth).await;
    assert_ne!(next.lease_id, lease.lease_id);
    let graded = h.commit(&auth, next.lease_id, &issued.key).await.unwrap();
    assert_eq!(graded.record.attempt, 1);
}

/// Two challenges such that, at the returned time, the first is past its
/// prune point and the second is strictly inside its window.
async fn prunable_and_live(h: &Harness) -> (Issued, Issued, u64) {
    let stale = h.create().await.unwrap();
    h.clock.advance(CHALLENGE_CLOCK_SKEW_SECS + 2);
    let (other_key, other) = party(3);
    let live = h
        .create_as(&h.handle, h.signer(), &other, URI)
        .await
        .unwrap();
    let at = stale.request.expires_at + CHALLENGE_CLOCK_SKEW_SECS + 1;
    assert!(live.request.created_at < at && at < live.request.expires_at);
    let _ = other_key;
    (stale, live, at)
}

/// T10: prune is best-effort. A failing delete refuses no turn: a Commit on
/// another challenge succeeds, and the expired entry stays until a later
/// turn deletes it.
#[tokio::test]
async fn prune_delete_failure_refuses_no_turn() {
    let h = harness();
    let (stale, live, at) = prunable_and_live(&h).await;
    h.clock.set(at);
    h.storage.fail_deletes.store(true, Ordering::SeqCst);
    let other = party(3);
    let auth = h.respond_as(&other, &live.request, 1, "ok");
    let lease = h.lease(&auth).await;
    let graded = h.commit(&auth, lease.lease_id, &live.key).await.unwrap();
    assert!(graded.record.passed);
    let stale_key = h.entry_key(&stale.request.challenge_id);
    assert!(h.storage.kv.contains_key(&stale_key), "the delete failed");
    h.storage.fail_deletes.store(false, Ordering::SeqCst);
    h.begin(&auth).await.unwrap();
    assert!(
        !h.storage.kv.contains_key(&stale_key),
        "the next turn prunes"
    );
    assert!(
        !h.index_ids()
            .contains(&hex::encode(stale.request.challenge_id))
    );
}

/// TQ5 (prune site): a failing index rewrite after prune refuses no turn.
#[tokio::test]
async fn prune_index_write_failure_refuses_no_turn() {
    let h = harness();
    let (stale, live, at) = prunable_and_live(&h).await;
    h.clock.set(at);
    h.storage.allow_stores(0);
    let auth = h.respond_as(&party(3), &live.request, 1, "ok");
    h.lease(&auth).await;
    h.storage.allow_stores(-1);
    assert!(
        !h.storage
            .kv
            .contains_key(&h.entry_key(&stale.request.challenge_id))
    );
    assert!(
        h.index_ids()
            .contains(&hex::encode(stale.request.challenge_id)),
        "the index rewrite failed"
    );
}

/// T11: lease ids survive a respawn. A stale fault or commit naming a lease
/// taken before the respawn is refused, even though the new actor issued a
/// lease for the same response; so is a fault naming another response.
#[tokio::test]
async fn stale_lease_from_before_a_respawn_is_lost() {
    let h = harness();
    let issued = h.create().await.unwrap();
    let auth = h.respond(&issued.request, 1, "ok");
    let stale = h.lease(&auth).await;
    let restarted = h.respawn().await;
    let fresh = lease_on(&restarted, &auth).await;
    assert_ne!(stale.lease_id, fresh.lease_id);
    let writes = h.storage.writes();
    assert!(matches!(
        trust_err(fault_on(&restarted, &auth, stale.lease_id).await),
        TrustError::GradingLeaseLost { .. }
    ));
    assert!(matches!(
        trust_err(commit_on(&restarted, &auth, stale.lease_id, &issued.key, h.signer()).await),
        TrustError::GradingLeaseLost { .. }
    ));
    let other_response = h.respond(&issued.request, 1, "no");
    assert!(matches!(
        trust_err(fault_on(&restarted, &other_response, fresh.lease_id).await),
        TrustError::GradingLeaseLost { .. }
    ));
    assert_eq!(h.storage.writes(), writes, "a lost lease writes nothing");
    commit_on(&restarted, &auth, fresh.lease_id, &issued.key, h.signer())
        .await
        .unwrap();
}

/// An entry past `expires_at + CHALLENGE_CLOCK_SKEW_SECS` is
/// pruned from memory and storage, and grading it is `UnknownChallenge`.
#[tokio::test]
async fn ledger_prunes_and_refuses_unknown() {
    let h = harness();
    let issued = h.create().await.unwrap();
    let response = h.respond_response(&issued.request, 1, "ok");
    let auth = h.respond(&issued.request, 1, "ok");
    h.lookup(&issued.request, &h.subject, &response)
        .await
        .unwrap();
    h.clock
        .set(issued.request.expires_at + CHALLENGE_CLOCK_SKEW_SECS + 1);
    assert!(matches!(
        trust_err(h.lookup(&issued.request, &h.subject, &response).await),
        TrustError::UnknownChallenge { .. }
    ));
    assert!(matches!(
        trust_err(h.begin(&auth).await),
        TrustError::UnknownChallenge { .. }
    ));
    assert!(
        !h.storage
            .kv
            .contains_key(&h.entry_key(&issued.request.challenge_id)),
        "the entry is deleted"
    );
}

/// T12 (RED-001): the bound counts open challenges only. 1024 open
/// challenges refuse the next Create; once one of them is closed, Create
/// succeeds.
///
/// One challenge is created through the actor. 1022 copies of the entry the
/// actor stored for it, each under its own challenge id and subject, are
/// written to the store, and a respawned actor loads all 1023. The 1024th
/// open challenge is then created, and the first one graded closed, through
/// that live actor, and every count after them is read without another
/// respawn. So the refusal depends on Create inserting its entry into the
/// actor's memory, and the final Create depends on Commit storing the closure
/// there; a load from the store supplies neither.
///
/// Creating every challenge through the actor would cost O(n²), because each
/// Create rewrites the whole index and scans every entry; the bound depends on
/// neither.
#[tokio::test]
async fn ledger_bound_counts_open_challenges_only() {
    let h = harness();
    let subjects: Vec<(SigningKey, DID)> = (0..=MAX_OPEN_CHALLENGES_PER_CHALLENGER)
        .map(|n| numbered_party(u16::try_from(n).unwrap()))
        .collect();
    let (last, open) = subjects.split_last().unwrap();
    let (boundary_subject, open) = open.split_last().unwrap();
    let (graded_subject, copied) = open.split_first().unwrap();
    assert_eq!(copied.len() + 2, MAX_OPEN_CHALLENGES_PER_CHALLENGER);

    let issued = h
        .create_as(&h.handle, h.signer(), &graded_subject.1, URI)
        .await
        .unwrap();
    let open_template = h.stored_entry(&issued.request.challenge_id);
    assert_eq!(open_template.closed, None);
    let handle = h.respawn_seeded(&h.handle, &open_template, copied).await;

    // The 1024th open challenge, created by the live actor.
    h.create_as(&handle, h.signer(), &boundary_subject.1, URI)
        .await
        .unwrap();
    assert!(matches!(
        trust_err(h.create_as(&handle, h.signer(), &last.1, URI).await),
        TrustError::ChallengeNotOpen {
            open: MAX_OPEN_CHALLENGES_PER_CHALLENGER,
            ..
        }
    ));

    h.clock.advance(1);
    let auth = h.respond_as(graded_subject, &issued.request, 1, "ok");
    let lease = lease_on(&handle, &auth).await;
    let graded = commit_on(&handle, &auth, lease.lease_id, &issued.key, h.signer())
        .await
        .unwrap();
    assert!(graded.record.passed);
    assert_eq!(
        h.stored_entry(&issued.request.challenge_id).closed,
        Some(ChallengeClosure::Passed)
    );
    // 1024 entries, one of them closed: the same actor admits the Create.
    h.create_as(&handle, h.signer(), &last.1, URI)
        .await
        .unwrap();
}

impl Harness {
    /// The entry the store holds for `challenge_id`.
    fn stored_entry(&self, challenge_id: &[u8; 32]) -> LedgerEntry {
        let bytes = self
            .storage
            .kv
            .get(&self.entry_key(challenge_id))
            .map(|v| v.value().clone())
            .expect("the entry is stored");
        rmp_serde::from_slice(&bytes).unwrap()
    }

    /// Stops `handle`'s actor, stores one copy of `template` per subject in
    /// `subjects`, each under its own challenge id, adds them to the index,
    /// and spawns the replacement, which loads them.
    async fn respawn_seeded(
        &self,
        handle: &ChallengerLedgerHandle,
        template: &LedgerEntry,
        subjects: &[(SigningKey, DID)],
    ) -> ChallengerLedgerHandle {
        handle.send_shutdown().await.unwrap();
        let mut ids = self.index_ids();
        for (n, (_, subject)) in subjects.iter().enumerate() {
            let mut challenge_id = [0xc5_u8; 32];
            challenge_id[..8].copy_from_slice(&u64::try_from(n).unwrap().to_be_bytes());
            assert_ne!(challenge_id, template.request.challenge_id);
            let mut entry = template.clone();
            entry.request.challenge_id = challenge_id;
            entry.request.subject = subject.clone();
            entry.subject_key = *CanonicalIdentifier::parse(subject).unwrap().key();
            let id = hex::encode(challenge_id);
            if !ids.contains(&id) {
                ids.push(id);
            }
            self.storage.kv.insert(
                self.entry_key(&challenge_id),
                rmp_serde::to_vec_named(&entry).unwrap(),
            );
        }
        self.storage.kv.insert(
            format!("scp-challenger-ids/{}", self.verifier.0),
            rmp_serde::to_vec_named(&ids).unwrap(),
        );
        spawn(&self.verifier, &self.storage, &self.clock, handle.shared())
    }
}

/// T6 (RULING 14): Create refuses while the latest challenge to the same
/// subject (by canonical key, whatever the spelling) for the same capability
/// is inside its window, across a respawn; another capability or another
/// subject is not blocked; at `expires_at` the block ends.
#[tokio::test]
async fn create_refuses_while_the_latest_window_is_open() {
    let h = harness();
    let first = h
        .create_as(&h.handle, h.signer(), &h.subject, URI)
        .await
        .unwrap();
    let expires_at = first.request.expires_at;
    h.clock.set(expires_at - 1);
    let open_id = hex::encode(first.request.challenge_id);
    let window_open = |e: TrustError| {
        assert!(
            matches!(&e, TrustError::ChallengeWindowOpen { challenge_id, expires_at: until }
                if *challenge_id == open_id && *until == expires_at),
            "expected ChallengeWindowOpen for {open_id} until {expires_at}, got {e:?}"
        );
    };
    window_open(trust_err(
        h.create_as(&h.handle, h.signer(), &h.subject, URI).await,
    ));
    h.create_as(&h.handle, h.signer(), &h.subject, OTHER_URI)
        .await
        .unwrap();
    h.create_as(&h.handle, h.signer(), &party(3).1, URI)
        .await
        .unwrap();
    let restarted = h.respawn().await;
    window_open(trust_err(
        h.create_as(&restarted, h.signer(), &h.subject, URI).await,
    ));
    // The same key spelled as did:key.
    let did_key = DID::from(format!(
        "did:key:{}",
        hex::encode(h.subject_key.verifying_key().to_bytes())
    ));
    assert_ne!(did_key, h.subject);
    window_open(trust_err(
        h.create_as(&restarted, h.signer(), &did_key, URI).await,
    ));
    h.clock.set(expires_at);
    h.create_as(&restarted, h.signer(), &h.subject, URI)
        .await
        .unwrap();
}

/// T6 (RULING 14): a closed challenge still blocks until its window ends.
#[tokio::test]
async fn create_refuses_inside_the_window_after_a_pass() {
    let h = harness();
    let issued = h.create().await.unwrap();
    assert!(h.graded(&issued, 1, "ok").await.record.passed);
    h.clock.set(issued.request.expires_at - 1);
    assert!(matches!(
        trust_err(h.create_as(&h.handle, h.signer(), &h.subject, URI).await),
        TrustError::ChallengeWindowOpen { .. }
    ));
    h.clock.set(issued.request.expires_at);
    h.create_as(&h.handle, h.signer(), &h.subject, URI)
        .await
        .unwrap();
}

/// Lookup is read-only and needs the id, the request digest and the
/// subject's key to match.
#[tokio::test]
async fn lookup_refuses_other_digest_or_subject_and_writes_nothing() {
    let h = harness();
    let issued = h.create().await.unwrap();
    let response = h.respond_response(&issued.request, 1, "ok");
    let writes = h.storage.writes();
    h.lookup(&issued.request, &h.subject, &response)
        .await
        .unwrap();
    let mut altered = issued.request.clone();
    altered.context_id = "ctx-2".to_owned();
    assert!(matches!(
        trust_err(h.lookup(&altered, &h.subject, &response).await),
        TrustError::UnknownChallenge { .. }
    ));
    let (_, other) = party(3);
    assert!(matches!(
        trust_err(h.lookup(&issued.request, &other, &response).await),
        TrustError::UnknownChallenge { .. }
    ));
    assert_eq!(h.storage.writes(), writes);
}

/// T13 (U-1): Lookup on a closed challenge admits only a resubmit of a
/// response it graded, so a fresh response costs no resolution. A closed
/// challenge with no stored attempt for the response's `D_r` is a lookup
/// miss, refused with `UnknownChallenge` (spec 07 §7.3.4 step 3.2).
#[tokio::test]
async fn lookup_on_a_closed_challenge_admits_only_a_resubmit() {
    let h = harness();
    let issued = h.create().await.unwrap();
    let graded_response = h.respond_response(&issued.request, 1, "ok");
    assert!(h.graded(&issued, 1, "ok").await.record.passed);
    h.lookup(&issued.request, &h.subject, &graded_response)
        .await
        .unwrap();
    let fresh = h.respond_response(&issued.request, 2, "ok");
    assert!(matches!(
        trust_err(h.lookup(&issued.request, &h.subject, &fresh).await),
        TrustError::UnknownChallenge { .. }
    ));
}

/// A ledger that cannot load refuses every command instead of serving from
/// an empty ledger, and serves once a load succeeds.
#[tokio::test]
async fn unloadable_ledger_refuses_until_it_loads() {
    let h = harness();
    let issued = h.create().await.unwrap();
    h.handle.send_shutdown().await.unwrap();
    h.storage.fail_reads.store(true, Ordering::SeqCst);
    let restarted = spawn(
        &h.verifier,
        &h.storage,
        &h.clock,
        ChallengerLedgerShared::new(),
    );
    let auth = h.respond(&issued.request, 1, "ok");
    assert!(is_persistence_failure(&begin_on(&restarted, &auth).await));
    h.storage.fail_reads.store(false, Ordering::SeqCst);
    assert!(matches!(
        begin_on(&restarted, &auth).await.unwrap(),
        BeginOutcome::Lease(_)
    ));
}

/// Create refuses a request whose verifier is not this ledger's identity.
#[tokio::test]
async fn create_refuses_foreign_verifier() {
    let h = harness();
    let (_, other) = party(4);
    let foreign = spawn(&other, &h.storage, &h.clock, ChallengerLedgerShared::new());
    assert!(matches!(
        trust_err(h.create_as(&foreign, h.signer(), &h.subject, URI).await),
        TrustError::ChallengeVerifierMismatch { .. }
    ));
}
