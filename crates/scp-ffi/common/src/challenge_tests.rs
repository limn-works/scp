//! Tests of the shared challenge operations over a real supervisor, its
//! challenger ledger and its outlet economy path. Keys: 1 is the
//! challenger, 2 the subject, 3 a forger and a non-member challenger.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::AtomicUsize;

use ed25519_dalek::{SigningKey, Verifier};
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

fn supervisor() -> Arc<Supervisor> {
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
        Some(Arc::new(SystemClock)),
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

/// A bridge invoker over a registry and one handler, through the shared
/// helpers, as each bridge implements it.
struct TestInvoker {
    sup: Arc<Supervisor>,
    registry: Option<OutletRegistry>,
    handler: Option<EvaluatorHandler>,
}

#[async_trait::async_trait]
impl EvaluatorInvoker for TestInvoker {
    async fn check_registered(
        &self,
        evaluator_context_id: &str,
        outlet_id: &OutletId,
        challenger: &DID,
    ) -> Result<(), TrustError> {
        check_evaluator_registered(
            &self.sup,
            evaluator_context_id,
            self.registry.as_ref(),
            self.handler.is_some(),
            challenger,
            outlet_id,
        )
        .await
    }

    async fn invoke(&self, call: EvaluatorCall<'_>) -> EvaluatorOutcome {
        invoke_evaluator_outlet(
            &self.sup,
            self.registry.as_ref(),
            self.handler.clone(),
            call,
        )
        .await
    }
}

/// 20 cases of weight 500; the last `custom` are `CustomEval` on the judge,
/// the rest `ExactMatch` on `"ok"`.
fn cases_json(custom: usize) -> String {
    let cases: Vec<TestCase> = (0..20)
        .map(|i| TestCase {
            test_id: format!("t{i}"),
            input: json!({"prompt": i}),
            expected: if i >= 20 - custom {
                ExpectedOutput::CustomEval {
                    evaluator_outlet_id: OutletId::from(JUDGE),
                }
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
    resolver: Arc<SeedResolver>,
    repo: Arc<ProtocolRepository<InMemoryStorage>>,
}

impl Harness {
    async fn new(params: ContextParams) -> Self {
        let sup = supervisor();
        sup.register_local_did(did(1)).await.unwrap();
        sup.create_context(EVAL_CTX.to_owned(), params, did(1), None)
            .await
            .unwrap();
        Self {
            sup,
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
            registry,
            handler,
        }
    }

    fn args(challenger: u8, custom: usize, evaluator: Option<&str>) -> CreateChallenge {
        CreateChallenge {
            verifier: did(challenger),
            subject: did(2),
            capability_uri: URI.to_owned(),
            test_cases_json: cases_json(custom),
            window_secs: 3600,
            context_id: EVAL_CTX.to_owned(),
            policy: None,
            evaluator_context_id: evaluator.map(str::to_owned),
        }
    }

    async fn try_create(
        &self,
        challenger: u8,
        evaluator: Option<&str>,
        invoker: &TestInvoker,
    ) -> Result<ChallengeRequest, ChallengeOpError> {
        create_challenge(
            &self.sup,
            &signer(challenger),
            Self::args(challenger, 1, evaluator),
            invoker,
            &ProtocolOnlyDefinitions,
        )
        .await
    }

    async fn create(&self, custom: usize, invoker: &TestInvoker) -> ChallengeRequest {
        create_challenge(
            &self.sup,
            &signer(1),
            Self::args(1, custom, Some(EVAL_CTX)),
            invoker,
            &ProtocolOnlyDefinitions,
        )
        .await
        .unwrap()
    }

    async fn respond(&self, request: &ChallengeRequest, attempt: u32) -> ChallengeResponse {
        let outputs: Vec<TestOutput> = request
            .test_cases
            .iter()
            .map(|c| TestOutput {
                test_id: c.test_id.clone(),
                output: json!("ok"),
            })
            .collect();
        respond_to_challenge(
            &signer(2),
            Arc::clone(&self.resolver),
            did(2).0,
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
                invoker,
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
                invoker,
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
        &invoker,
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
            invoker: &invoker,
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
        create_challenge(&h.sup, &signer(1), args, &invoker, &ProtocolOnlyDefinitions)
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
                invoker: &invoker,
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
    let err = create_challenge(&h.sup, &signer(1), args, &invoker, &ProtocolOnlyDefinitions)
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

/// 13: an evaluator outlet missing at grade time is a challenger fault; the
/// attempt is not used, and the same attempt grades once it is back. Two
/// faults per challenge, because the third closes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn custom_eval_missing_outlet_is_fault() {
    let h = Harness::new(evaluator_params()).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let ready = h.invoker(Some(registry()), Some(passing_handler(&calls)));
    for missing in [
        vec![
            h.invoker(Some(OutletRegistry::new()), Some(passing_handler(&calls))),
            h.invoker(Some(registry()), None),
        ],
        vec![h.invoker(None, Some(passing_handler(&calls)))],
    ] {
        let request = h.create(1, &ready).await;
        let response = h.respond(&request, 1).await;
        for invoker in &missing {
            let err = h.grade(&request, &response, invoker).await.unwrap_err();
            assert!(is_unavailable(&err), "{err:?}");
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

/// 13b: the budget is total per attempt: two 200 ms evaluators under a
/// 300 ms budget, so the first passes and the second runs out of time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grading_budget_is_total_per_attempt() {
    let h = Harness::new(evaluator_params()).await;
    let invoker = h.invoker(Some(registry()), Some(sleeping_handler(200)));
    let request = h.create(2, &invoker).await;
    let response = h.respond(&request, 1).await;
    let graded = h
        .grade_within(&request, &response, &invoker, Duration::from_millis(300))
        .await
        .unwrap();
    assert!(graded.reasons[18].passed, "{:?}", graded.reasons[18]);
    assert!(!graded.reasons[19].passed, "{:?}", graded.reasons[19]);
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
    let request = h.create(1, &slow).await;
    let response = h.respond(&request, 1).await;
    let graded = h
        .grade_within(&request, &response, &slow, Duration::from_millis(100))
        .await
        .unwrap();
    assert!(!graded.reasons[19].passed, "{:?}", graded.reasons[19]);
    assert_eq!(graded.record.attempt, 1);
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
    for _ in 0..=MAX_CONCURRENT_GRADINGS_PER_CHALLENGER {
        let request = h.create(1, &invoker).await;
        let response = h.respond(&request, 1).await;
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
        },
    )
    .await
}

/// 13i: an error before the handler runs (the economy reserve, the rate
/// limit) or after it returned a verdict (the settlement) is unavailable, a
/// fault; an error of the handler itself fails the case.
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

    // The rate limit refuses the eleventh call at reserve.
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
        matches!(outcome, EvaluatorOutcome::Unavailable(_)),
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
