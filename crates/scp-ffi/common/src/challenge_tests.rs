//! Tests of the shared challenge operations over a real supervisor, its
//! challenger ledger and its outlet economy path. Keys: 1 is the
//! challenger, 2 the subject, 3 a forger and a non-member challenger.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::AtomicUsize;

use ed25519_dalek::{SigningKey, Verifier};
use scp_clock::TestClock;
use scp_core::context::builder::{ContextCreationError, ContextEventLogProvider};
use scp_core::context::governance::KeyResolver;
use scp_core::context::supervisor::MAX_CONCURRENT_GRADINGS_PER_CHALLENGER;
use scp_core::context::{Capability, ContextParams, LocalTransportProvider};
use scp_core::crypto::mls::provider::NodeMlsFactory;
use scp_core::crypto::mls::storage_adapter::{OpenMlsStorageAdapter, SpawnBlockingStorageAdapter};
use scp_core::economy::{Amount, CostSchedule, CurrencyCode, EconomicPolicy};
use scp_crypto::{DynScpSigner, SigAlg, SignFuture};
use scp_platform::in_memory::InMemoryStorage;
use scp_protocol::context::outlets::registry::{
    OutletRegistration, OutletSchema, OutletTestVector,
};
use scp_protocol::trust::{
    CapabilityRequirements, challenge_request_signing_digest, challenge_response_signing_digest,
};
use serde_json::json;

use super::*;

const URI: &str = "scp:capability:schema-validation/v1";
const EVAL_CTX: &str = "ctx-evaluator";
const JUDGE: &str = "judge";
/// Seeds of further subjects, for tests that challenge more than one:
/// RULING 14 refuses a second challenge to one subject inside the first's
/// window.
const SUBJECT_SEEDS: std::ops::RangeInclusive<u8> = 10..=18;

// ---------------------------------------------------------------------------
// Parties
// ---------------------------------------------------------------------------

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn did(seed: u8) -> DID {
    scp_did::did_dht_from_public_key(&key(seed).verifying_key().to_bytes())
}

fn signer(seed: u8) -> CommandSigner {
    CommandSigner::local_ed25519(key(seed))
}

/// Resolves the did:dht of keys 1-3 to the key it was made from, and counts
/// every call.
#[derive(Default)]
struct SeedResolver {
    calls: AtomicUsize,
}

impl SeedResolver {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ActiveKeyResolver for SeedResolver {
    fn resolve_active_key(&self, did_str: &str) -> Result<Vec<u8>, TrustError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        (1u8..=3)
            .chain(SUBJECT_SEEDS)
            .find(|seed| did(*seed).0 == did_str)
            .map(|seed| key(seed).verifying_key().to_bytes().to_vec())
            .ok_or_else(|| TrustError::KeyResolutionUnavailable {
                did: did_str.to_owned(),
                reason: "not in the test resolver".to_owned(),
            })
    }
}

/// Reports P-256 and counts every sign it is asked for.
struct P256Counting(Arc<AtomicUsize>);

impl DynScpSigner for P256Counting {
    fn algorithm(&self) -> SigAlg {
        SigAlg::EcdsaP256Sha256
    }

    fn public_key(&self) -> Vec<u8> {
        vec![0x04; 65]
    }

    fn sign_boxed<'a>(&'a self, _digest: &'a [u8; 32]) -> SignFuture<'a> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok([0; 64]) })
    }
}

// ---------------------------------------------------------------------------
// Supervisor and evaluator context
// ---------------------------------------------------------------------------

struct NoOpEventLog;

#[async_trait::async_trait]
#[allow(clippy::unused_async)]
impl ContextEventLogProvider for NoOpEventLog {
    async fn init_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn append_event(
        &self,
        _: &[u8; 32],
        _: scp_event_log::EventType,
        _: &str,
        _: scp_event_log::EventPayload,
        _timestamp_secs: u64,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn destroy_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
}

fn supervisor(clock: &Arc<TestClock>) -> Arc<Supervisor> {
    let key_resolver: KeyResolver = Arc::new(|_: &DID, _: scp_did::SigningKeyId| None);
    let mls_storage: Arc<dyn OpenMlsStorageAdapter> = Arc::new(SpawnBlockingStorageAdapter::new(
        Arc::new(InMemoryStorage::new()),
    ));
    Supervisor::with_providers(
        Arc::new(NodeMlsFactory::new(did(1).0, Arc::new(SystemClock))),
        Box::new(LocalTransportProvider),
        Box::new(NoOpEventLog),
        key_resolver,
        None,
        None,
        None,
        Some(Arc::clone(clock) as Arc<dyn scp_clock::Clock>),
        mls_storage,
    )
}

/// The challenger (key 1) creates the evaluator context, so its role holds
/// the whole ceiling, `OutletCallAll` included.
fn evaluator_params() -> ContextParams {
    ContextParams {
        ceiling: vec![
            Capability::new("messages:read").unwrap(),
            Capability::new("messages:write").unwrap(),
            Capability::new("role:assign").unwrap(),
            Capability::new("governance:propose").unwrap(),
            Capability::new("governance:vote").unwrap(),
            Capability::OutletRegister,
            Capability::OutletCallAll,
        ],
        ..ContextParams::default()
    }
}

fn priced_params() -> ContextParams {
    ContextParams {
        economic_policy: Some(EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: CurrencyCode::from("USD"),
                per_message: None,
                per_outlet_call: Some(Amount::new(5)),
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec![],
            pricing_formula: None,
            payee: DID::from("did:key:test-payee"),
        }),
        ..evaluator_params()
    }
}

fn judge() -> OutletRegistration {
    OutletRegistration {
        outlet_id: JUDGE.to_owned(),
        kind: scp_protocol::context::outlets::OutletKind::default(),
        name: JUDGE.to_owned(),
        description: "challenge evaluator".to_owned(),
        schema: OutletSchema {
            input_schema: json!({"type": "object"}),
            output_schema: json!({"type": "object"}),
            aggregate_schema: None,
        },
        implementation_hash: [0u8; 32],
        test_vectors: vec![OutletTestVector {
            input: json!({}),
            expected_output: json!({}),
            description: "noop".to_owned(),
        }],
        operator_did: did(1),
        cost: None,
        message_catalog: Vec::new(),
        registered_at: 0,
        signature: Vec::new(),
    }
}

fn registry() -> OutletRegistry {
    let mut registry = OutletRegistry::new();
    registry.insert(judge());
    registry
}

fn verdict(passed: bool) -> Value {
    json!({"passed": passed, "reason": "judged"})
}

/// A handler that returns `verdict(true)` and counts its calls.
fn passing_handler(calls: &Arc<AtomicUsize>) -> EvaluatorHandler {
    let calls = Arc::clone(calls);
    Arc::new(move |_input| {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(verdict(true))
    })
}

/// A bridge's evaluator state: a registry and one handler, served for
/// every evaluator context.
struct TestHost {
    registry: Option<OutletRegistry>,
    handler: Option<EvaluatorHandler>,
}

impl EvaluatorHost for TestHost {
    fn registry(&self, _evaluator_context_id: &str) -> Option<OutletRegistry> {
        self.registry.clone()
    }

    fn handler(
        &self,
        _evaluator_context_id: &str,
        _outlet_id: &OutletId,
    ) -> Option<EvaluatorHandler> {
        self.handler.clone()
    }
}

/// A [`TestHost`] with the supervisor the shared invoker checks and runs
/// evaluators through, as each bridge builds it.
struct TestInvoker {
    sup: Arc<Supervisor>,
    host: TestHost,
}

impl TestInvoker {
    fn shared(&self) -> SharedEvaluatorInvoker<'_> {
        SharedEvaluatorInvoker::new(&self.sup, &self.host)
    }
}

/// 20 cases of weight 500; the last `custom` are `CustomEval` on the judge,
/// the rest `ExactMatch` on `"ok"`.
fn cases_json(custom: usize) -> String {
    cases_json_with(
        (0..custom)
            .map(|_| ExpectedOutput::CustomEval {
                evaluator_outlet_id: OutletId::from(JUDGE),
            })
            .collect(),
    )
}

/// 20 cases of weight 500; the last `tail.len()` expect `tail`, in order,
/// the rest `ExactMatch` on `"ok"`.
fn cases_json_with(tail: Vec<ExpectedOutput>) -> String {
    let head = 20 - tail.len();
    let mut tail = tail.into_iter();
    let cases: Vec<TestCase> = (0..20)
        .map(|i| TestCase {
            test_id: format!("t{i}"),
            input: json!({"prompt": i}),
            expected: if i >= head {
                tail.next().unwrap()
            } else {
                ExpectedOutput::ExactMatch { value: json!("ok") }
            },
            category: "general".to_owned(),
            weight: 500,
        })
        .collect();
    serde_json::to_string(&cases).unwrap()
}

struct Harness {
    sup: Arc<Supervisor>,
    /// The supervisor's clock, started at the wall clock's time.
    clock: Arc<TestClock>,
    resolver: Arc<SeedResolver>,
    repo: Arc<ProtocolRepository<InMemoryStorage>>,
}

impl Harness {
    async fn new(params: ContextParams) -> Self {
        let clock = Arc::new(TestClock::new(scp_clock::Clock::now_secs(&SystemClock)));
        let sup = supervisor(&clock);
        sup.register_local_did(did(1)).await.unwrap();
        sup.create_context(EVAL_CTX.to_owned(), params, did(1), None)
            .await
            .unwrap();
        Self {
            sup,
            clock,
            resolver: Arc::new(SeedResolver::default()),
            repo: Arc::new(ProtocolRepository::new_for_testing(InMemoryStorage::new())),
        }
    }

    fn invoker(
        &self,
        registry: Option<OutletRegistry>,
        handler: Option<EvaluatorHandler>,
    ) -> TestInvoker {
        TestInvoker {
            sup: Arc::clone(&self.sup),
            host: TestHost { registry, handler },
        }
    }

    fn args(challenger: u8, custom: usize, evaluator: Option<&str>) -> CreateChallenge {
        Self::args_for(challenger, 2, custom, evaluator)
    }

    fn args_for(
        challenger: u8,
        subject: u8,
        custom: usize,
        evaluator: Option<&str>,
    ) -> CreateChallenge {
        CreateChallenge {
            verifier: did(challenger),
            subject: did(subject),
            capability_uri: URI.to_owned(),
            test_cases_json: cases_json(custom),
            window_secs: 3600,
            context_id: EVAL_CTX.to_owned(),
            policy: PolicyPick::default(),
            evaluator_context_id: evaluator.map(str::to_owned),
        }
    }

    async fn try_create(
        &self,
        challenger: u8,
        evaluator: Option<&str>,
        invoker: &TestInvoker,
    ) -> Result<ChallengeRequest, ChallengeOpError> {
        let created = create_challenge(
            &self.sup,
            &signer(challenger),
            Self::args(challenger, 1, evaluator),
            &invoker.shared(),
            &ProtocolOnlyDefinitions,
        )
        .await;
        self.clock.advance(1);
        created
    }

    /// Creates a challenge to subject 2, then advances the clock one second,
    /// to the first instant strictly inside the window (spec 07 §7.3.4,
    /// RULING 5), so the challenge is gradable at once.
    async fn create(&self, custom: usize, invoker: &TestInvoker) -> ChallengeRequest {
        self.create_for(2, custom, invoker).await
    }

    async fn create_for(
        &self,
        subject: u8,
        custom: usize,
        invoker: &TestInvoker,
    ) -> ChallengeRequest {
        let request = create_challenge(
            &self.sup,
            &signer(1),
            Self::args_for(1, subject, custom, Some(EVAL_CTX)),
            &invoker.shared(),
            &ProtocolOnlyDefinitions,
        )
        .await
        .unwrap();
        self.clock.advance(1);
        request
    }

    /// Creates a challenge to `subject` whose last cases expect `tail`, then
    /// advances the clock one second, as [`Self::create`] does.
    async fn create_with(
        &self,
        subject: u8,
        tail: Vec<ExpectedOutput>,
        invoker: &TestInvoker,
    ) -> ChallengeRequest {
        let mut args = Self::args_for(1, subject, 0, Some(EVAL_CTX));
        args.test_cases_json = cases_json_with(tail);
        let request = create_challenge(
            &self.sup,
            &signer(1),
            args,
            &invoker.shared(),
            &ProtocolOnlyDefinitions,
        )
        .await
        .unwrap();
        self.clock.advance(1);
        request
    }

    async fn respond(&self, request: &ChallengeRequest, attempt: u32) -> ChallengeResponse {
        self.respond_as(2, request, attempt).await
    }

    async fn respond_as(
        &self,
        subject: u8,
        request: &ChallengeRequest,
        attempt: u32,
    ) -> ChallengeResponse {
        let outputs: Vec<TestOutput> = request
            .test_cases
            .iter()
            .map(|c| TestOutput {
                test_id: c.test_id.clone(),
                output: json!("ok"),
            })
            .collect();
        respond_to_challenge(
            &signer(subject),
            Arc::clone(&self.resolver),
            did(subject).0,
            &serde_json::to_string(request).unwrap(),
            &serde_json::to_string(&outputs).unwrap(),
            attempt,
        )
        .await
        .unwrap()
    }

    async fn grade_within(
        &self,
        request: &ChallengeRequest,
        response: &ChallengeResponse,
        invoker: &TestInvoker,
        budget: Duration,
    ) -> Result<GradeResult, ChallengeOpError> {
        grade_response_within(
            &Grader {
                sup: &self.sup,
                signer: &signer(1),
                resolver: Arc::clone(&self.resolver),
                invoker: &invoker.shared(),
            },
            &self.repo,
            &did(1),
            (
                &serde_json::to_string(request).unwrap(),
                &serde_json::to_string(response).unwrap(),
            ),
            budget,
        )
        .await
    }

    async fn grade(
        &self,
        request: &ChallengeRequest,
        response: &ChallengeResponse,
        invoker: &TestInvoker,
    ) -> Result<GradeResult, ChallengeOpError> {
        grade_response(
            &Grader {
                sup: &self.sup,
                signer: &signer(1),
                resolver: Arc::clone(&self.resolver),
                invoker: &invoker.shared(),
            },
            &self.repo,
            &did(1),
            &serde_json::to_string(request).unwrap(),
            &serde_json::to_string(response).unwrap(),
        )
        .await
    }
}

fn is_unavailable(error: &ChallengeOpError) -> bool {
    matches!(
        error,
        ChallengeOpError::Trust(TrustError::EvaluatorUnavailable { .. })
    )
}

// ---------------------------------------------------------------------------
// Create and respond
// ---------------------------------------------------------------------------

/// A P-256 signer is refused before any custody call, by every operation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p256_signer_refused_before_custody() {
    let h = Harness::new(evaluator_params()).await;
    let invoker = h.invoker(None, None);
    let signs = Arc::new(AtomicUsize::new(0));
    let p256 = CommandSigner::new(Arc::new(P256Counting(Arc::clone(&signs))));

    let err = create_challenge(
        &h.sup,
        &p256,
        Harness::args(1, 0, None),
        &invoker.shared(),
        &ProtocolOnlyDefinitions,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, ChallengeOpError::Context(_)), "{err:?}");

    let request = h.create(0, &invoker).await;
    let request_json = serde_json::to_string(&request).unwrap();
    let err = respond_to_challenge(
        &p256,
        Arc::clone(&h.resolver),
        did(2).0,
        &request_json,
        "[]",
        1,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, ChallengeOpError::Context(_)), "{err:?}");

    let response = h.respond(&request, 1).await;
    let resolutions = h.resolver.calls();
    let err = grade_response(
        &Grader {
            sup: &h.sup,
            signer: &p256,
            resolver: Arc::clone(&h.resolver),
            invoker: &invoker.shared(),
        },
        &h.repo,
        &did(1),
        &request_json,
        &serde_json::to_string(&response).unwrap(),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, ChallengeOpError::Context(_)), "{err:?}");
    assert_eq!(signs.load(Ordering::SeqCst), 0);
    assert_eq!(h.resolver.calls(), resolutions);
}

/// Each malformed argument is named, with its own code.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_argument_is_named() {
    let h = Harness::new(evaluator_params()).await;
    let invoker = h.invoker(None, None);
    let named = |err: ChallengeOpError, expected: JsonInput| match err {
        ChallengeOpError::MalformedJson { input, .. } => assert_eq!(input, expected),
        other => panic!("expected {expected} to be named, got {other:?}"),
    };

    let mut args = Harness::args(1, 0, None);
    args.test_cases_json = "{".to_owned();
    named(
        create_challenge(
            &h.sup,
            &signer(1),
            args,
            &invoker.shared(),
            &ProtocolOnlyDefinitions,
        )
        .await
        .unwrap_err(),
        JsonInput::TestCases,
    );

    let request = h.create(0, &invoker).await;
    let request_json = serde_json::to_string(&request).unwrap();
    named(
        respond_to_challenge(&signer(2), Arc::clone(&h.resolver), did(2).0, "{", "[]", 1)
            .await
            .unwrap_err(),
        JsonInput::Challenge,
    );
    named(
        respond_to_challenge(
            &signer(2),
            Arc::clone(&h.resolver),
            did(2).0,
            &request_json,
            "{",
            1,
        )
        .await
        .unwrap_err(),
        JsonInput::Outputs,
    );
    named(
        grade_response(
            &Grader {
                sup: &h.sup,
                signer: &signer(1),
                resolver: Arc::clone(&h.resolver),
                invoker: &invoker.shared(),
            },
            &h.repo,
            &did(1),
            &request_json,
            "{\"x\":1}",
        )
        .await
        .unwrap_err(),
        JsonInput::Response,
    );
    named(
        check_capability_requirements(&h.sup, None, EVAL_CTX.to_owned(), did(2).0, "{", "[]")
            .await
            .unwrap_err(),
        JsonInput::AgentCapabilities,
    );
    named(
        check_capability_requirements(&h.sup, None, EVAL_CTX.to_owned(), did(2).0, "[]", "{")
            .await
            .unwrap_err(),
        JsonInput::ChallengeVerifications,
    );
    assert_eq!(JsonInput::Response.code(), crate::error_codes::VALID_7002);
    assert_eq!(
        JsonInput::AgentCapabilities.code(),
        crate::error_codes::VALID_7074
    );
    assert_eq!(
        JsonInput::ChallengeVerifications.code(),
        crate::error_codes::VALID_7075
    );
}

/// The request is signed by the challenger's key over its digest, and the
/// response by the subject's key over its digest.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_and_respond_sign_their_digests() {
    let h = Harness::new(evaluator_params()).await;
    let invoker = h.invoker(None, None);
    let request = h.create(0, &invoker).await;
    let digest = challenge_request_signing_digest(&request).unwrap();
    let signature = ed25519_dalek::Signature::from_slice(&request.verifier_signature).unwrap();
    key(1).verifying_key().verify(&digest, &signature).unwrap();
    assert_eq!(request.verifier, did(1));
    assert_eq!(request.subject, did(2));

    let response = h.respond(&request, 1).await;
    let digest = challenge_response_signing_digest(&response).unwrap();
    let signature = ed25519_dalek::Signature::from_slice(&response.subject_signature).unwrap();
    key(2).verifying_key().verify(&digest, &signature).unwrap();
    assert_eq!(response.attempt, 1);
}

/// Fewer cases than the definition's minimum are refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_refuses_suite_below_minimum() {
    let h = Harness::new(evaluator_params()).await;
    let invoker = h.invoker(None, None);
    let cases: Vec<TestCase> = (0..5)
        .map(|i| TestCase {
            test_id: format!("t{i}"),
            input: json!({"prompt": i}),
            expected: ExpectedOutput::ExactMatch { value: json!("ok") },
            category: "general".to_owned(),
            weight: 2000,
        })
        .collect();
    let mut args = Harness::args(1, 0, None);
    args.test_cases_json = serde_json::to_string(&cases).unwrap();
    let err = create_challenge(
        &h.sup,
        &signer(1),
        args,
        &invoker.shared(),
        &ProtocolOnlyDefinitions,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            err,
            ChallengeOpError::Trust(TrustError::ChallengeSuiteBelowMinimum { supplied: 5, .. })
        ),
        "{err:?}"
    );
}

/// A `CustomEval` case is refused at create without an evaluator context,
/// with its outlet unregistered or its handler missing, and when the
/// challenger holds no invocation permission there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn custom_eval_unavailable_at_create() {
    let h = Harness::new(evaluator_params()).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let ready = h.invoker(Some(registry()), Some(passing_handler(&calls)));
    let err = h.try_create(1, None, &ready).await.unwrap_err();
    assert!(is_unavailable(&err), "no evaluator context: {err:?}");
    let err = h
        .try_create(
            1,
            Some(EVAL_CTX),
            &h.invoker(Some(OutletRegistry::new()), Some(passing_handler(&calls))),
        )
        .await
        .unwrap_err();
    assert!(is_unavailable(&err), "unregistered outlet: {err:?}");
    let err = h
        .try_create(1, Some(EVAL_CTX), &h.invoker(Some(registry()), None))
        .await
        .unwrap_err();
    assert!(is_unavailable(&err), "no handler: {err:?}");
    let err = h
        .try_create(1, Some("ctx-unknown"), &ready)
        .await
        .unwrap_err();
    assert!(is_unavailable(&err), "unknown context: {err:?}");
    let err = h.try_create(3, Some(EVAL_CTX), &ready).await.unwrap_err();
    assert!(is_unavailable(&err), "non-member challenger: {err:?}");

    h.try_create(1, Some(EVAL_CTX), &ready).await.unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "create never runs the evaluator"
    );
}

// ---------------------------------------------------------------------------
// Grade
// ---------------------------------------------------------------------------

/// An all-correct response passes, the record is signed by the challenger
/// and written to the trust store, and a resubmit returns it again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grade_signs_and_stores_the_record() {
    let h = Harness::new(evaluator_params()).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let invoker = h.invoker(Some(registry()), Some(passing_handler(&calls)));
    let request = h.create(1, &invoker).await;
    let response = h.respond(&request, 1).await;
    let graded = h.grade(&request, &response, &invoker).await.unwrap();
    assert!(graded.record.passed);
    assert_eq!(graded.record.verifier, did(1));
    assert!(graded.trust_store_error.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let digest =
        scp_protocol::trust::challenge_verification_signing_digest(&graded.record).unwrap();
    let signature =
        ed25519_dalek::Signature::from_slice(&graded.record.verifier_signature).unwrap();
    key(1).verifying_key().verify(&digest, &signature).unwrap();
    let stored = h
        .repo
        .load_trust_challenge_results(EVAL_CTX, did(2).as_ref())
        .await
        .unwrap();
    assert_eq!(stored, vec![graded.record.clone()]);

    let again = h.grade(&request, &response, &invoker).await.unwrap();
    assert_eq!(again.record, graded.record);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a resubmit runs no evaluator"
    );
}

/// A [`Storage`] that refuses every write, so a graded record cannot reach
/// the trust store.
struct RefusingStorage;

impl Storage for RefusingStorage {
    fn store(
        &self,
        _key: &str,
        _data: &[u8],
    ) -> impl std::future::Future<Output = Result<(), scp_platform::PlatformError>> + Send {
        std::future::ready(Err(scp_platform::PlatformError::StorageError(
            "disk full".to_owned(),
        )))
    }
    fn retrieve(
        &self,
        _key: &str,
    ) -> impl std::future::Future<Output = Result<Option<Vec<u8>>, scp_platform::PlatformError>> + Send
    {
        std::future::ready(Ok(None))
    }
    fn delete(
        &self,
        _key: &str,
    ) -> impl std::future::Future<Output = Result<(), scp_platform::PlatformError>> + Send {
        std::future::ready(Ok(()))
    }
    fn list_keys(
        &self,
        _prefix: &str,
    ) -> impl std::future::Future<Output = Result<Vec<String>, scp_platform::PlatformError>> + Send
    {
        std::future::ready(Ok(Vec::new()))
    }
    fn delete_prefix(
        &self,
        _prefix: &str,
    ) -> impl std::future::Future<Output = Result<u64, scp_platform::PlatformError>> + Send {
        std::future::ready(Ok(0))
    }
    fn exists(
        &self,
        _key: &str,
    ) -> impl std::future::Future<Output = Result<bool, scp_platform::PlatformError>> + Send {
        std::future::ready(Ok(false))
    }
}

/// A graded record the trust store refuses comes back with the code every
/// trust-store write failure reports, and the record and reasons intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_trust_store_write_is_a_coded_error() {
    let h = Harness::new(evaluator_params()).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let invoker = h.invoker(Some(registry()), Some(passing_handler(&calls)));
    let request = h.create(1, &invoker).await;
    let response = h.respond(&request, 1).await;
    let graded = h.grade(&request, &response, &invoker).await.unwrap();

    let refusing = Arc::new(ProtocolRepository::new_for_testing(RefusingStorage));
    let stored = store_graded(
        &refusing,
        GradedAttempt {
            record: graded.record.clone(),
            reasons: graded.reasons.clone(),
        },
    )
    .await;
    assert_eq!(stored.record, graded.record);
    assert_eq!(stored.reasons, graded.reasons);
    let error = stored
        .trust_store_error
        .expect("the refused write is reported");
    let expected = TrustError::StoreError {
        reason: String::new(),
    };
    assert_eq!(error.code, crate::error_codes::trust_error_code(&expected));
    assert_eq!(error.code, crate::error_codes::VALID_7003);
    assert!(error.message.contains("disk full"), "{error:?}");
}

/// 13: an evaluator outlet missing at grade time is a challenger fault: the
/// attempt is not used and the challenge stays open, but the fault starts
/// the cooldown (spec 07 §7.3.4 step 3), so a grade inside it is refused.
/// Once the cooldown ends and the outlet is back, the same attempt grades.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn custom_eval_missing_outlet_is_fault() {
    let h = Harness::new(evaluator_params()).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let ready = h.invoker(Some(registry()), Some(passing_handler(&calls)));
    // Every response is signed before the test clock runs ahead: the subject
    // side reads the wall clock.
    let mut challenges = Vec::new();
    for subject in SUBJECT_SEEDS.take(2) {
        let request = h.create_for(subject, 1, &ready).await;
        let response = h.respond_as(subject, &request, 1).await;
        challenges.push((request, response));
    }
    for ((request, response), missing) in challenges.into_iter().zip([
        vec![
            h.invoker(Some(OutletRegistry::new()), Some(passing_handler(&calls))),
            h.invoker(Some(registry()), None),
        ],
        vec![h.invoker(None, Some(passing_handler(&calls)))],
    ]) {
        let cooldown = u64::from(request.cooldown_secs);
        for invoker in &missing {
            let err = h.grade(&request, &response, invoker).await.unwrap_err();
            assert!(is_unavailable(&err), "{err:?}");
            h.clock.advance(cooldown - 1);
            let refused = h.grade(&request, &response, &ready).await.unwrap_err();
            assert!(
                matches!(
                    refused,
                    ChallengeOpError::Trust(TrustError::CooldownActive { .. })
                ),
                "{refused:?}"
            );
            h.clock.advance(1);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let graded = h.grade(&request, &response, &ready).await.unwrap();
        assert_eq!(graded.record.attempt, 1);
        assert!(graded.record.passed);
        calls.store(0, Ordering::SeqCst);
    }
}

/// A handler that sleeps `millis`, then returns `verdict(true)`.
fn sleeping_handler(millis: u64) -> EvaluatorHandler {
    Arc::new(move |_input| {
        std::thread::sleep(Duration::from_millis(millis));
        Ok(verdict(true))
    })
}

/// 13b: the budget is total per attempt: two 500 ms evaluators under a
/// 750 ms budget, so the first passes with 250 ms to spare and the second
/// would end 250 ms past the budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grading_budget_is_total_per_attempt() {
    let h = Harness::new(evaluator_params()).await;
    let invoker = h.invoker(Some(registry()), Some(sleeping_handler(500)));
    let request = h.create(2, &invoker).await;
    let response = h.respond(&request, 1).await;
    let graded = h
        .grade_within(&request, &response, &invoker, Duration::from_millis(750))
        .await
        .unwrap();
    assert!(graded.reasons[18].passed, "{:?}", graded.reasons[18]);
    assert_eq!(
        graded.reasons[19].reason.as_deref(),
        Some("budget_exceeded"),
        "{:?}",
        graded.reasons[19]
    );
}

/// TQ7: a slow evaluator that started uses the budget up, so its case and
/// the `SchemaMatch` case after it both fail with `budget_exceeded`, and the
/// attempt is graded: neither is a fault.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_evaluator_cuts_off_the_schema_case_after_it() {
    let h = Harness::new(evaluator_params()).await;
    let invoker = h.invoker(Some(registry()), Some(sleeping_handler(1000)));
    let request = h
        .create_with(
            2,
            vec![
                ExpectedOutput::CustomEval {
                    evaluator_outlet_id: OutletId::from(JUDGE),
                },
                ExpectedOutput::SchemaMatch {
                    schema: json!({"type": "string"}),
                },
            ],
            &invoker,
        )
        .await;
    let response = h.respond(&request, 1).await;
    let graded = h
        .grade_within(&request, &response, &invoker, Duration::from_millis(300))
        .await
        .unwrap();
    assert_eq!(graded.record.attempt, 1);
    for i in [18, 19] {
        assert_eq!(
            graded.reasons[i].reason.as_deref(),
            Some("budget_exceeded"),
            "case {i}: {:?}",
            graded.reasons[i]
        );
    }
}

/// 13e: a handler error and a budget overrun fail the case, and the record
/// is still signed: neither is a fault.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evaluator_error_and_budget_overrun_fail_the_case() {
    let h = Harness::new(evaluator_params()).await;
    let failing: EvaluatorHandler = Arc::new(|_input| Err("evaluator crashed".to_owned()));
    let invoker = h.invoker(Some(registry()), Some(failing));
    let request = h.create(1, &invoker).await;
    let response = h.respond(&request, 1).await;
    let graded = h.grade(&request, &response, &invoker).await.unwrap();
    assert_eq!(
        graded.reasons[19],
        CaseResult {
            passed: false,
            reason: Some(EVALUATOR_FAILED_REASON.to_owned()),
        }
    );
    assert_eq!(graded.record.attempt, 1);

    let slow = h.invoker(Some(registry()), Some(sleeping_handler(500)));
    let subject = *SUBJECT_SEEDS.start();
    let request = h.create_for(subject, 1, &slow).await;
    let response = h.respond_as(subject, &request, 1).await;
    let graded = h
        .grade_within(&request, &response, &slow, Duration::from_millis(100))
        .await
        .unwrap();
    assert!(!graded.reasons[19].passed, "{:?}", graded.reasons[19]);
    assert_eq!(graded.record.attempt, 1);
}

/// T13 (U-1): a fresh response to a passed challenge is refused by the
/// ledger lookup before any DID resolution.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fresh_response_to_a_closed_challenge_resolves_nothing() {
    let h = Harness::new(evaluator_params()).await;
    let invoker = h.invoker(None, None);
    let request = h.create(0, &invoker).await;
    let first = h.respond(&request, 1).await;
    assert!(
        h.grade(&request, &first, &invoker)
            .await
            .unwrap()
            .record
            .passed
    );
    let fresh = h.respond(&request, 2).await;
    let calls = h.resolver.calls();
    let err = h.grade(&request, &fresh, &invoker).await.unwrap_err();
    assert!(
        matches!(
            err,
            ChallengeOpError::Trust(TrustError::ChallengeClosed { .. })
        ),
        "{err:?}"
    );
    assert_eq!(h.resolver.calls(), calls, "the refusal resolved a DID");
}

/// 13f: a response signed by anyone but the subject is refused before any
/// lease, so three forgeries record no fault and the subject still grades.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forged_response_takes_no_lease_and_records_no_fault() {
    let h = Harness::new(evaluator_params()).await;
    let invoker = h.invoker(None, None);
    let request = h.create(0, &invoker).await;
    let genuine = h.respond(&request, 1).await;
    let mut forged = genuine.clone();
    forged.subject_signature = {
        use ed25519_dalek::Signer as _;
        let digest = challenge_response_signing_digest(&forged).unwrap();
        key(3).sign(&digest).to_bytes().to_vec()
    };
    for _ in 0..3 {
        let err = h.grade(&request, &forged, &invoker).await.unwrap_err();
        assert!(matches!(err, ChallengeOpError::Trust(_)), "{err:?}");
        assert!(!is_unavailable(&err));
    }
    let graded = h.grade(&request, &genuine, &invoker).await.unwrap();
    assert!(graded.record.passed);
}

/// 13j: an unknown challenge, or a request whose digest or subject differs
/// from the ledger's, is refused before any key resolution.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_or_mismatched_challenge_refused_before_resolution() {
    let h = Harness::new(evaluator_params()).await;
    let invoker = h.invoker(None, None);
    let request = h.create(0, &invoker).await;
    let response = h.respond(&request, 1).await;

    let other = Harness::new(evaluator_params()).await;
    let unknown = other.create(0, &other.invoker(None, None)).await;
    let mut altered = request.clone();
    altered.expires_at -= 1;
    let mut other_subject = request.clone();
    other_subject.subject = did(3);

    let before = h.resolver.calls();
    for candidate in [&unknown, &altered, &other_subject] {
        let err = h.grade(candidate, &response, &invoker).await.unwrap_err();
        assert!(
            matches!(
                err,
                ChallengeOpError::Trust(TrustError::UnknownChallenge { .. })
            ),
            "{err:?}"
        );
    }
    assert_eq!(
        h.resolver.calls(),
        before,
        "no resolution before the lookup"
    );
}

struct ReleaseOnDrop(Arc<AtomicBool>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// 13h: a challenger grades at most eight attempts at once; a ninth is
/// refused, and a grading that is dropped keeps its permit until its
/// blocking handler returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grading_permits_bound_leaked_threads() {
    let h = Arc::new(Harness::new(evaluator_params()).await);
    let release = Arc::new(AtomicBool::new(false));
    // Releases the handlers however the test ends, so a failure does not
    // hang the runtime's shutdown on spinning blocking threads.
    let _release_on_exit = ReleaseOnDrop(Arc::clone(&release));
    let entered = Arc::new(AtomicUsize::new(0));
    let blocking: EvaluatorHandler = {
        let release = Arc::clone(&release);
        let entered = Arc::clone(&entered);
        Arc::new(move |_input| {
            entered.fetch_add(1, Ordering::SeqCst);
            while !release.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(verdict(true))
        })
    };
    let invoker = Arc::new(h.invoker(Some(registry()), Some(blocking)));
    let mut pending = Vec::new();
    for subject in SUBJECT_SEEDS.take(MAX_CONCURRENT_GRADINGS_PER_CHALLENGER + 1) {
        let request = h.create_for(subject, 1, &invoker).await;
        let response = h.respond_as(subject, &request, 1).await;
        pending.push((request, response));
    }
    let (ninth_request, ninth_response) = pending.pop().unwrap();
    let mut tasks: Vec<_> = pending
        .into_iter()
        .map(|(request, response)| {
            let h = Arc::clone(&h);
            let invoker = Arc::clone(&invoker);
            tokio::spawn(async move {
                h.grade_within(&request, &response, &invoker, Duration::from_secs(30))
                    .await
            })
        })
        .collect();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while entered.load(Ordering::SeqCst) < MAX_CONCURRENT_GRADINGS_PER_CHALLENGER {
        assert!(
            tokio::time::Instant::now() < deadline,
            "handlers never started"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let err = h
        .grade(&ninth_request, &ninth_response, &invoker)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            ChallengeOpError::Trust(TrustError::GradingCapacityExhausted { .. })
        ),
        "{err:?}"
    );

    let dropped = tasks.remove(0);
    dropped.abort();
    assert!(dropped.await.unwrap_err().is_cancelled());
    assert!(
        h.sup
            .challenge_grading_permit(did(1).as_ref())
            .await
            .is_err(),
        "the dropped grading's handler still holds its permit"
    );

    release.store(true, Ordering::SeqCst);
    for task in tasks {
        assert!(task.await.unwrap().unwrap().record.passed);
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while h
        .sup
        .challenge_grading_permit(did(1).as_ref())
        .await
        .is_err()
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the permit never returned"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

// ---------------------------------------------------------------------------
// The evaluator helper
// ---------------------------------------------------------------------------

async fn invoke(h: &Harness, handler: EvaluatorHandler) -> EvaluatorOutcome {
    let permit = Arc::new(
        h.sup
            .challenge_grading_permit(did(1).as_ref())
            .await
            .unwrap(),
    );
    let registry = registry();
    invoke_evaluator_outlet(
        &h.sup,
        Some(&registry),
        Some(handler),
        EvaluatorCall {
            evaluator_context_id: EVAL_CTX,
            outlet_id: &OutletId::from(JUDGE),
            challenger: &did(1),
            input: json!({"case": {}, "output": "ok"}),
            remaining: Duration::from_secs(5),
            permit,
            started: Arc::new(AtomicBool::new(false)),
        },
    )
    .await
}

/// 13i: an error before the handler runs (a payment refusal) or after it
/// returned a verdict (the settlement) is unavailable, a fault; a rate-limit
/// refusal by the reserve is a capacity refusal; an error of the handler
/// itself fails the case.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evaluator_reserve_error_is_fault_execute_error_is_case_fail() {
    // A priced context refuses at reserve: the evaluator holds no spending
    // capability. The handler never runs.
    let priced = Harness::new(priced_params()).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let outcome = invoke(&priced, passing_handler(&calls)).await;
    assert!(
        matches!(outcome, EvaluatorOutcome::Unavailable(_)),
        "{outcome:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    // The rate limit refuses the eleventh call at reserve, for capacity.
    let h = Harness::new(evaluator_params()).await;
    for _ in 0..10 {
        let outcome = invoke(&h, passing_handler(&calls)).await;
        assert_eq!(
            outcome,
            EvaluatorOutcome::Verdict {
                passed: true,
                reason: "judged".to_owned()
            }
        );
    }
    let outcome = invoke(&h, passing_handler(&calls)).await;
    assert!(
        matches!(
            outcome,
            EvaluatorOutcome::CapacityRefused {
                cause: GradingCapacityCause::EvaluatorRateLimit,
                ..
            }
        ),
        "{outcome:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 10);

    // A handler error, and an output that is no verdict, fail the case.
    let h = Harness::new(evaluator_params()).await;
    let outcome = invoke(&h, Arc::new(|_| Err("boom".to_owned()))).await;
    assert_eq!(
        outcome,
        EvaluatorOutcome::CaseFailed(EVALUATOR_FAILED_REASON.to_owned())
    );
    let outcome = invoke(&h, Arc::new(|_| Ok(json!({"passed": true})))).await;
    assert_eq!(
        outcome,
        EvaluatorOutcome::CaseFailed(EVALUATOR_FAILED_REASON.to_owned())
    );

    // The settlement fails after a verdict: the context dies while the
    // handler runs, so the capture cannot settle.
    let h = Harness::new(evaluator_params()).await;
    let sup = Arc::clone(&h.sup);
    let poisoning: EvaluatorHandler = Arc::new(move |_| {
        tokio::runtime::Handle::current().block_on(sup.test_poison_context(EVAL_CTX));
        Ok(verdict(true))
    });
    let outcome = invoke(&h, poisoning).await;
    assert!(
        matches!(outcome, EvaluatorOutcome::Unavailable(_)),
        "{outcome:?}"
    );
}

/// An input the evaluator's input schema refuses fails the case without a
/// reserve: it carries the subject's output.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evaluator_input_refused_by_schema_fails_the_case() {
    let h = Harness::new(evaluator_params()).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let mut registration = judge();
    registration.schema.input_schema = json!({"type": "object", "required": ["missing"]});
    let mut registry = OutletRegistry::new();
    registry.insert(registration);
    let permit = Arc::new(
        h.sup
            .challenge_grading_permit(did(1).as_ref())
            .await
            .unwrap(),
    );
    let outcome = invoke_evaluator_outlet(
        &h.sup,
        Some(&registry),
        Some(passing_handler(&calls)),
        EvaluatorCall {
            evaluator_context_id: EVAL_CTX,
            outlet_id: &OutletId::from(JUDGE),
            challenger: &did(1),
            input: json!({"case": {}, "output": "ok"}),
            remaining: Duration::from_secs(5),
            permit,
            started: Arc::new(AtomicBool::new(false)),
        },
    )
    .await;
    assert_eq!(
        outcome,
        EvaluatorOutcome::CaseFailed(EVALUATOR_FAILED_REASON.to_owned())
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

// ---------------------------------------------------------------------------
// Capacity refusals, budget expiry, shutdown, permits and bounds
// ---------------------------------------------------------------------------

/// Waits up to 10 s for `done`, failing the test with `what` after that.
async fn wait_until(what: &str, done: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(tokio::time::Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// A handler that counts its entries and spins until `release` is set.
fn held_handler(entered: &Arc<AtomicUsize>, release: &Arc<AtomicBool>) -> EvaluatorHandler {
    let (entered, release) = (Arc::clone(entered), Arc::clone(release));
    Arc::new(move |_input| {
        entered.fetch_add(1, Ordering::SeqCst);
        while !release.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(verdict(true))
    })
}

/// Takes every free grading permit of the challenger.
async fn take_free_permits(h: &Harness) -> Vec<OwnedSemaphorePermit> {
    let mut held = Vec::new();
    while let Ok(permit) = h.sup.challenge_grading_permit(did(1).as_ref()).await {
        held.push(permit);
    }
    held
}

/// T14: the evaluator context's rate limit refuses the reserve, so the
/// grading is a capacity refusal (7146): the lease is released, and neither
/// an attempt nor a fault is recorded. An immediate re-grade passes Begin
/// (no `GradingInProgress`, no `CooldownActive`) and is refused for capacity
/// again; once one token refills, still inside the cooldown a fault would
/// start, the same attempt grades.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evaluator_rate_limit_refusal_releases_the_lease_and_records_nothing() {
    let h = Harness::new(evaluator_params()).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let invoker = h.invoker(Some(registry()), Some(passing_handler(&calls)));
    let request = h.create(1, &invoker).await;
    let response = h.respond(&request, 1).await;
    // The hard rate limit's burst is 10 calls; the clock does not move, so
    // no token refills.
    for _ in 0..10 {
        let outcome = invoke(&h, passing_handler(&calls)).await;
        assert!(
            matches!(outcome, EvaluatorOutcome::Verdict { .. }),
            "{outcome:?}"
        );
    }
    for _ in 0..2 {
        let err = h.grade(&request, &response, &invoker).await.unwrap_err();
        let ChallengeOpError::Trust(trust) = &err else {
            panic!("{err:?}");
        };
        assert!(
            matches!(
                trust,
                TrustError::GradingCapacityExhausted {
                    cause: GradingCapacityCause::EvaluatorRateLimit,
                    ..
                }
            ),
            "{trust:?}"
        );
        assert_eq!(
            crate::error_codes::trust_error_code(trust),
            crate::error_codes::VALID_7146
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 10);
    // One token refills every 5 s (200 per 1000 s).
    assert!(u64::from(request.cooldown_secs) > 5);
    h.clock.advance(5);
    let graded = h.grade(&request, &response, &invoker).await.unwrap();
    assert_eq!(graded.record.attempt, 1);
    assert!(graded.record.passed);
    assert_eq!(calls.load(Ordering::SeqCst), 11);
}

/// T14 (budget): a reserve that cannot price the call refuses it with the
/// budget error, and the evaluator outcome is a capacity refusal naming the
/// budget; the handler never runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evaluator_budget_refusal_is_a_capacity_refusal() {
    use scp_core::economy::{Coefficient, PricingFormula, PricingMetric, PricingVariable};
    let mut params = priced_params();
    if let Some(policy) = params.economic_policy.as_mut() {
        policy.cost_schedule.per_outlet_call = None;
        // `i64::MAX` times any time of day above 1 overflows, so the cost
        // cannot be computed.
        policy.pricing_formula = Some(PricingFormula {
            base_cost: Amount::new(0),
            variables: vec![PricingVariable::Linear {
                metric: PricingMetric::TimeOfDay,
                coefficient: Coefficient::new(i64::MAX),
            }],
            cap: None,
            floor: None,
        });
    }
    let h = Harness::new(params).await;
    if scp_clock::Clock::now_secs(&*h.clock) % 86_400 < 2 {
        h.clock.advance(2);
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let outcome = invoke(&h, passing_handler(&calls)).await;
    assert!(
        matches!(
            outcome,
            EvaluatorOutcome::CapacityRefused {
                cause: GradingCapacityCause::EvaluatorBudget,
                ..
            }
        ),
        "{outcome:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

/// T15: the grading budget expires while the evaluator's reserve is still
/// waiting on the evaluator context, before the evaluator started: a fault,
/// not a charged attempt. The same attempt is then refused by the fault's
/// cooldown, where a charged attempt would return its stored record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn budget_expiry_before_the_evaluator_started_is_a_fault() {
    let h = Harness::new(evaluator_params()).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let invoker = h.invoker(Some(registry()), Some(passing_handler(&calls)));
    let request = h.create(1, &invoker).await;
    let response = h.respond(&request, 1).await;
    let stall = h.sup.test_stall_actor(EVAL_CTX);
    let err = h
        .grade_within(&request, &response, &invoker, Duration::from_millis(300))
        .await
        .unwrap_err();
    assert!(is_unavailable(&err), "{err:?}");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let again = h
        .grade_within(&request, &response, &invoker, Duration::from_millis(300))
        .await
        .unwrap_err();
    assert!(
        matches!(
            again,
            ChallengeOpError::Trust(TrustError::CooldownActive { .. })
        ),
        "{again:?}"
    );
    drop(stall);
}

/// T16: a supervisor shutdown waits for an evaluator pipeline that has not
/// settled, so storage never closes under an unsettled reserve.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_waits_for_the_evaluator_settle() {
    let h = Arc::new(Harness::new(evaluator_params()).await);
    let release = Arc::new(AtomicBool::new(false));
    let _release_on_exit = ReleaseOnDrop(Arc::clone(&release));
    let entered = Arc::new(AtomicUsize::new(0));
    let invoker = Arc::new(h.invoker(Some(registry()), Some(held_handler(&entered, &release))));
    let request = h.create(1, &invoker).await;
    let response = h.respond(&request, 1).await;
    let grading = {
        let (h, invoker) = (Arc::clone(&h), Arc::clone(&invoker));
        tokio::spawn(async move {
            h.grade_within(&request, &response, &invoker, Duration::from_secs(30))
                .await
        })
    };
    wait_until("the handler never started", || {
        entered.load(Ordering::SeqCst) == 1
    })
    .await;
    let shutdown = {
        let sup = Arc::clone(&h.sup);
        tokio::spawn(async move { sup.shutdown_all_contexts().await })
    };
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !shutdown.is_finished(),
        "shutdown finished while an evaluator pipeline had not settled"
    );
    release.store(true, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(10), shutdown)
        .await
        .expect("shutdown never finished")
        .unwrap();
    // The settle ran against a stopped context; the outcome is not under test.
    let _ = grading.await.unwrap();
}

/// T17: an evaluator call cut off after 1 ms keeps its permit on the
/// handler's thread, so 7 of the 8 permits are free until the handler
/// returns, and all 8 after.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cut_off_evaluator_holds_one_permit_until_it_returns() {
    let h = Harness::new(evaluator_params()).await;
    let release = Arc::new(AtomicBool::new(false));
    let _release_on_exit = ReleaseOnDrop(Arc::clone(&release));
    let entered = Arc::new(AtomicUsize::new(0));
    let permit = Arc::new(
        h.sup
            .challenge_grading_permit(did(1).as_ref())
            .await
            .unwrap(),
    );
    let registry = registry();
    let started = Arc::new(AtomicBool::new(false));
    let outcome = invoke_evaluator_outlet(
        &h.sup,
        Some(&registry),
        Some(held_handler(&entered, &release)),
        EvaluatorCall {
            evaluator_context_id: EVAL_CTX,
            outlet_id: &OutletId::from(JUDGE),
            challenger: &did(1),
            input: json!({"case": {}, "output": "ok"}),
            remaining: Duration::from_millis(1),
            permit,
            started: Arc::clone(&started),
        },
    )
    .await;
    assert_eq!(
        outcome,
        EvaluatorOutcome::CaseFailed(EVALUATOR_FAILED_REASON.to_owned())
    );
    assert!(started.load(Ordering::SeqCst));
    wait_until("the handler never started", || {
        entered.load(Ordering::SeqCst) == 1
    })
    .await;
    let held = take_free_permits(&h).await;
    assert_eq!(held.len(), MAX_CONCURRENT_GRADINGS_PER_CHALLENGER - 1);
    drop(held);
    release.store(true, Ordering::SeqCst);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let held = take_free_permits(&h).await;
        if held.len() == MAX_CONCURRENT_GRADINGS_PER_CHALLENGER {
            break;
        }
        drop(held);
        assert!(
            tokio::time::Instant::now() < deadline,
            "the permit never returned"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// T17: an evaluator input larger than `MAX_CHALLENGE_RESPONSE_BYTES`
/// fails its case without a call; the reserve and the handler never run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversize_evaluator_input_fails_the_case_without_a_call() {
    let h = Harness::new(evaluator_params()).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let permit = Arc::new(
        h.sup
            .challenge_grading_permit(did(1).as_ref())
            .await
            .unwrap(),
    );
    let registry = registry();
    let started = Arc::new(AtomicBool::new(false));
    let outcome = invoke_evaluator_outlet(
        &h.sup,
        Some(&registry),
        Some(passing_handler(&calls)),
        EvaluatorCall {
            evaluator_context_id: EVAL_CTX,
            outlet_id: &OutletId::from(JUDGE),
            challenger: &did(1),
            input: json!({"case": {}, "output": "x".repeat(MAX_CHALLENGE_RESPONSE_BYTES)}),
            remaining: Duration::from_secs(30),
            permit,
            started: Arc::clone(&started),
        },
    )
    .await;
    assert!(
        matches!(outcome, EvaluatorOutcome::CaseFailed(_)),
        "{outcome:?}"
    );
    assert!(!started.load(Ordering::SeqCst));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

/// T17: a resubmit of a graded attempt returns its stored record without a
/// grading permit, so it succeeds while every permit is held.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stored_resubmit_takes_no_permit() {
    let h = Harness::new(evaluator_params()).await;
    let invoker = h.invoker(None, None);
    let request = h.create(0, &invoker).await;
    let response = h.respond(&request, 1).await;
    let graded = h.grade(&request, &response, &invoker).await.unwrap();
    let held = take_free_permits(&h).await;
    assert_eq!(held.len(), MAX_CONCURRENT_GRADINGS_PER_CHALLENGER);
    let again = h.grade(&request, &response, &invoker).await.unwrap();
    assert_eq!(again.record, graded.record);
    drop(held);
}

/// T18: a request larger than `MAX_CHALLENGE_RESPONSE_BYTES` is refused
/// with `ResponseTooLarge` (7143) by grade and by respond, before any
/// resolution.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversize_request_refused_before_resolution() {
    let h = Harness::new(evaluator_params()).await;
    let invoker = h.invoker(None, None);
    let request = h.create(0, &invoker).await;
    let response = h.respond(&request, 1).await;
    let mut oversize = serde_json::to_string(&request).unwrap();
    oversize.push_str(&" ".repeat(MAX_CHALLENGE_RESPONSE_BYTES));
    let before = h.resolver.calls();
    let graded = grade_response(
        &Grader {
            sup: &h.sup,
            signer: &signer(1),
            resolver: Arc::clone(&h.resolver),
            invoker: &invoker.shared(),
        },
        &h.repo,
        &did(1),
        &oversize,
        &serde_json::to_string(&response).unwrap(),
    )
    .await;
    let responded = respond_to_challenge(
        &signer(2),
        Arc::clone(&h.resolver),
        did(2).0,
        &oversize,
        "[]",
        1,
    )
    .await;
    for result in [graded.map(|_| ()), responded.map(|_| ())] {
        let err = result.unwrap_err();
        let ChallengeOpError::Trust(trust) = &err else {
            panic!("{err:?}");
        };
        assert!(
            matches!(trust, TrustError::ResponseTooLarge { .. }),
            "{trust:?}"
        );
        assert_eq!(
            crate::error_codes::trust_error_code(trust),
            crate::error_codes::VALID_7143
        );
    }
    assert_eq!(h.resolver.calls(), before, "the refusal resolved a DID");
}

/// A grade at `created_at` is refused as not yet gradable (7153), naming
/// `created_at + 1`, and the same attempt grades one second later.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grade_at_created_at_is_not_yet_gradable() {
    let h = Harness::new(evaluator_params()).await;
    let invoker = h.invoker(None, None);
    let request = create_challenge(
        &h.sup,
        &signer(1),
        Harness::args(1, 0, None),
        &invoker.shared(),
        &ProtocolOnlyDefinitions,
    )
    .await
    .unwrap();
    let response = h.respond(&request, 1).await;
    let err = h.grade(&request, &response, &invoker).await.unwrap_err();
    let ChallengeOpError::Trust(trust) = &err else {
        panic!("{err:?}");
    };
    assert!(
        matches!(
            trust,
            TrustError::ChallengeNotYetGradable { retry_at, .. }
                if *retry_at == request.created_at + 1
        ),
        "{trust:?}"
    );
    assert_eq!(
        crate::error_codes::trust_error_code(trust),
        crate::error_codes::VALID_7153
    );
    h.clock.advance(1);
    let graded = h.grade(&request, &response, &invoker).await.unwrap();
    assert_eq!(graded.record.attempt, 1);
}

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------

fn requiring_params() -> ContextParams {
    let requirements: CapabilityRequirements = serde_json::from_value(json!([{
        "capability": URI,
        "verification_level": "ChallengeVerified",
        "trusted_verifiers": [did(1).0],
    }]))
    .unwrap();
    ContextParams {
        capability_requirements: requirements,
        ..evaluator_params()
    }
}

/// The check reads the context's governed requirements, fails closed on a
/// record it cannot verify, and errors on an unknown context.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn check_capability_requirements_reads_governance() {
    let h = Harness::new(requiring_params()).await;
    let caps = serde_json::to_string(&[URI]).unwrap();
    let err =
        check_capability_requirements(&h.sup, None, EVAL_CTX.to_owned(), did(2).0, &caps, "[]")
            .await
            .unwrap_err();
    assert!(
        matches!(
            err,
            ChallengeOpError::Admission(AdmissionError::VerificationRequired { .. })
        ),
        "{err:?}"
    );

    let invoker = h.invoker(None, None);
    let request = h.create(0, &invoker).await;
    let response = h.respond(&request, 1).await;
    let graded = h.grade(&request, &response, &invoker).await.unwrap();
    // More than MAX_ADMISSION_RECORDS records are refused at decode.
    let flood = serde_json::to_string(&vec![
        graded.record.clone();
        scp_protocol::trust::MAX_ADMISSION_RECORDS + 1
    ])
    .unwrap();
    let err =
        check_capability_requirements(&h.sup, None, EVAL_CTX.to_owned(), did(2).0, &caps, &flood)
            .await
            .unwrap_err();
    assert!(
        matches!(
            &err,
            ChallengeOpError::MalformedJson {
                input: JsonInput::ChallengeVerifications,
                reason,
            } if reason.contains("invalid length")
        ),
        "{err:?}"
    );

    let records = serde_json::to_string(&[graded.record]).unwrap();
    let err =
        check_capability_requirements(&h.sup, None, EVAL_CTX.to_owned(), did(2).0, &caps, &records)
            .await
            .unwrap_err();
    assert!(
        matches!(
            err,
            ChallengeOpError::Admission(AdmissionError::VerificationUnavailable { .. })
        ),
        "{err:?}"
    );

    let open = Harness::new(evaluator_params()).await;
    check_capability_requirements(&open.sup, None, EVAL_CTX.to_owned(), did(2).0, "[]", "[]")
        .await
        .unwrap();

    let err =
        check_capability_requirements(&h.sup, None, "ctx-unknown".to_owned(), did(2).0, "[]", "[]")
            .await
            .unwrap_err();
    assert!(matches!(err, ChallengeOpError::Context(_)), "{err:?}");
}

/// A refusal with a retry time ends its message with
/// `(retry_after=<unix seconds>)`, the suffix every SDK's `retryAfter`
/// reads; a refusal without one carries no suffix.
#[test]
fn retry_time_reaches_the_bridge_message() {
    let message = |e: TrustError| match ChallengeOpError::Trust(e).code_and_class() {
        ChallengeFailure::Coded { code, message, .. } => (code, message),
        ChallengeFailure::Context(e) => panic!("{e}"),
    };
    let id = || "ab".repeat(32);
    for (error, code, at) in [
        (
            TrustError::CooldownActive {
                challenge_id: id(),
                retry_after: 1_700_000_100,
            },
            crate::error_codes::VALID_7105,
            1_700_000_100,
        ),
        (
            TrustError::ChallengeWindowOpen {
                challenge_id: id(),
                expires_at: 1_700_003_600,
            },
            crate::error_codes::VALID_7151,
            1_700_003_600,
        ),
        (
            TrustError::ChallengeNotYetGradable {
                challenge_id: id(),
                now: 1_700_000_000,
                created_at: 1_700_000_000,
                retry_at: 1_700_000_001,
            },
            crate::error_codes::VALID_7153,
            1_700_000_001,
        ),
    ] {
        let (got, text) = message(error);
        assert_eq!(got, code);
        assert!(text.ends_with(&format!("(retry_after={at})")), "{text}");
    }
    let (code, text) = message(TrustError::GradingCapacityExhausted {
        challenger: "did:dht:x".to_owned(),
        cause: GradingCapacityCause::GradingPermits,
    });
    assert_eq!(code, crate::error_codes::VALID_7146);
    assert!(!text.contains("retry_after="), "{text}");
}
