//! The challenge operations the three bridges share (spec 07 §7.3.4,
//! ADR-017).
//!
//! The challenger's attempt ledger lives in the supervisor
//! ([`Supervisor::dispatch_challenge_create`] and its siblings): every
//! request and record is signed inside a ledger turn, through the
//! challenger's custody signer, so the ledger state and the signature never
//! diverge. These operations parse the caller's JSON, run the checks that
//! need no ledger state, authenticate a response before any lease, run the
//! evaluators, and hand each step to the ledger.
//!
//! Evaluator outlets are bridge state (the registry and the host
//! handlers), so each bridge implements [`EvaluatorInvoker`] once over its
//! state and calls [`check_evaluator_registered`] and
//! [`invoke_evaluator_outlet`], which hold the shared rules.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use scp_clock::SystemClock;
use scp_core::context::ContextError;
use scp_core::context::actor::signer::CommandSigner;
use scp_core::context::supervisor::{
    BeginOutcome, ChallengeLedgerError, GradedAttempt, GradingFault, Supervisor,
};
use scp_core::store::ProtocolRepository;
use scp_did::DID;
use scp_platform::traits::Storage;
use scp_protocol::context::outlets::registry::OutletRegistry;
use scp_protocol::context::outlets::{
    OutletId, has_outlet_invocation_capability, sha256_json, validate_value_against_schema,
};
use scp_protocol::trust::attestation::ActiveKeyResolver;
use scp_protocol::trust::schema_gate::schema_verdict;
use scp_protocol::trust::{
    AdmissionCheck, AdmissionError, CHALLENGE_GRADING_BUDGET_SECS, CapabilityDefinitionSource,
    CapabilityUri, CaseResult, ChallengePolicy, ChallengeRequest, ChallengeResponse,
    ChallengeVerification, ExpectedOutput, NewChallenge, OwnedAuthenticatedResponse, PolicyPick,
    ProtocolOnlyDefinitions, SchemaGate, SchemaVerdict, TestCase, TestOutput, TrustError,
    authenticate_challenge_response, challenge_request_unsigned, challenge_response_unsigned,
    check_response_bounds, grade,
};
use serde_json::Value;
use tokio::sync::OwnedSemaphorePermit;

use crate::resolvers::{
    BlockingResolutionFailed, IdentityBackedDidResolver, instance_active_key_resolver,
    run_blocking_resolution,
};

/// The per-case reason of a `CustomEval` case whose evaluator ran and
/// returned no verdict, or whose input the evaluator refuses.
pub const EVALUATOR_FAILED_REASON: &str = "evaluator_failed";

/// The caller-supplied JSON argument of a challenge operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonInput {
    /// `test_cases_json`: a JSON array of `TestCase`.
    TestCases,
    /// `challenge_json`: a signed `ChallengeRequest`.
    Challenge,
    /// `response_json`: a signed `ChallengeResponse`.
    Response,
    /// `outputs_json`: a JSON array of `TestOutput`.
    Outputs,
    /// `agent_capabilities_json`: a JSON array of capability URIs.
    AgentCapabilities,
    /// `challenge_verifications_json`: a JSON array of
    /// `ChallengeVerification`.
    ChallengeVerifications,
}

impl JsonInput {
    /// The bridge error code a malformed argument of this kind reports:
    /// `SCP-VALID-7002` for the challenge arguments, and the admission
    /// check's own `SCP-VALID-7074` and `SCP-VALID-7075`.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TestCases | Self::Challenge | Self::Response | Self::Outputs => {
                crate::error_codes::VALID_7002
            }
            Self::AgentCapabilities => crate::error_codes::VALID_7074,
            Self::ChallengeVerifications => crate::error_codes::VALID_7075,
        }
    }
}

impl std::fmt::Display for JsonInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TestCases => "test_cases_json",
            Self::Challenge => "challenge_json",
            Self::Response => "response_json",
            Self::Outputs => "outputs_json",
            Self::AgentCapabilities => "agent_capabilities_json",
            Self::ChallengeVerifications => "challenge_verifications_json",
        })
    }
}

/// Why a challenge operation failed.
#[derive(Debug, thiserror::Error)]
pub enum ChallengeOpError {
    /// A caller-supplied JSON argument does not decode to its type. The
    /// bridge reports [`JsonInput::code`].
    #[error("failed to parse {input}: {reason}")]
    MalformedJson {
        /// Which argument failed to decode.
        input: JsonInput,
        /// The decoder's message.
        reason: String,
    },
    /// The protocol or the challenger's ledger refused the operation.
    #[error(transparent)]
    Trust(#[from] TrustError),
    /// The runtime could not complete it: a signer that refused, timed out
    /// or is not Ed25519, a persistence failure, an unknown or busy context.
    #[error(transparent)]
    Context(#[from] ContextError),
    /// The admission check refused the agent.
    #[error(transparent)]
    Admission(#[from] AdmissionError),
    /// The blocking resolution task panicked or was cancelled.
    #[error(transparent)]
    Blocking(#[from] BlockingResolutionFailed),
}

impl From<ChallengeLedgerError> for ChallengeOpError {
    fn from(error: ChallengeLedgerError) -> Self {
        match error {
            ChallengeLedgerError::Trust(e) => Self::Trust(e),
            ChallengeLedgerError::Context(e) => Self::Context(e),
        }
    }
}

/// Decodes `$json` as the argument `$input`, naming it on failure.
macro_rules! decode {
    ($input:expr, $json:expr) => {
        serde_json::from_str($json).map_err(|e| ChallengeOpError::MalformedJson {
            input: $input,
            reason: e.to_string(),
        })
    };
}

// ---------------------------------------------------------------------------
// Evaluators
// ---------------------------------------------------------------------------

/// A host evaluator handler: the same shape as every bridge's outlet
/// handler.
pub type EvaluatorHandler = Arc<dyn Fn(Value) -> Result<Value, String> + Send + Sync>;

/// What one `CustomEval` case's evaluator produced (spec 07 §7.3.4 step 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluatorOutcome {
    /// The evaluator ran and returned a well-formed verdict.
    Verdict {
        /// Whether the case passed.
        passed: bool,
        /// The evaluator's reason.
        reason: String,
    },
    /// The evaluator ran and returned no verdict, or refused the subject's
    /// output as input: the case fails with this reason.
    CaseFailed(String),
    /// The evaluator could not run, or its settlement failed after a
    /// verdict: a challenger fault, which uses no attempt.
    Unavailable(String),
}

/// The bridge side of a `CustomEval` evaluator.
///
/// It owns the outlet registry and the host handlers of the evaluator
/// context. Each bridge implements it once,
/// over its own state, by calling [`check_evaluator_registered`] and
/// [`invoke_evaluator_outlet`].
#[async_trait::async_trait]
pub trait EvaluatorInvoker: Send + Sync {
    /// Create-time check: the outlet is registered in the evaluator
    /// context, a host handler is present, and `challenger` is a member
    /// whose role grants the outlet invocation permission.
    ///
    /// # Errors
    ///
    /// [`TrustError::EvaluatorUnavailable`] naming the first check that
    /// fails.
    async fn check_registered(
        &self,
        evaluator_context_id: &str,
        outlet_id: &OutletId,
        challenger: &DID,
    ) -> Result<(), TrustError>;

    /// Runs the evaluator on `call.input` within `call.remaining`, holding
    /// `call.permit` until the handler returns.
    async fn invoke(&self, call: EvaluatorCall<'_>) -> EvaluatorOutcome;
}

/// One evaluator invocation.
///
/// It names the outlet in its evaluator context, the challenger invoking
/// it, the case input, the time left in the grading budget, and the grading
/// permit the handler holds until it returns.
pub struct EvaluatorCall<'a> {
    /// The context the evaluator outlet is registered in.
    pub evaluator_context_id: &'a str,
    /// The evaluator outlet.
    pub outlet_id: &'a OutletId,
    /// The challenger, invoking the outlet as a member of the context.
    pub challenger: &'a DID,
    /// The case and the subject's output.
    pub input: Value,
    /// The time left in the attempt's grading budget.
    pub remaining: Duration,
    /// The challenger's grading permit.
    pub permit: Arc<OwnedSemaphorePermit>,
}

/// The shared body of [`EvaluatorInvoker::check_registered`].
///
/// `registry` is the bridge's outlet registry of the evaluator context
/// (`None` when the bridge serves no such context) and `has_handler`
/// whether a host handler is registered for `outlet_id`. Membership and the
/// permission are read from the supervisor's live role state.
///
/// # Errors
///
/// [`TrustError::EvaluatorUnavailable`] naming the first check that fails.
pub async fn check_evaluator_registered(
    sup: &Supervisor,
    evaluator_context_id: &str,
    registry: Option<&OutletRegistry>,
    has_handler: bool,
    challenger: &DID,
    outlet_id: &OutletId,
) -> Result<(), TrustError> {
    let unavailable = |reason: String| TrustError::EvaluatorUnavailable {
        context_id: evaluator_context_id.to_owned(),
        outlet_id: outlet_id.clone(),
        reason,
    };
    let registry =
        registry.ok_or_else(|| unavailable("the evaluator context is not open".to_owned()))?;
    let registration = registry
        .get(outlet_id)
        .ok_or_else(|| unavailable("the outlet is not registered".to_owned()))?;
    if !has_handler {
        return Err(unavailable("no host handler is registered".to_owned()));
    }
    let role_state = sup
        .get_role_state_checked(evaluator_context_id)
        .await
        .map_err(|e| unavailable(format!("the role state cannot be read: {e}")))?
        .ok_or_else(|| unavailable("the evaluator context is not registered".to_owned()))?;
    if !has_outlet_invocation_capability(
        &role_state,
        challenger.as_ref(),
        outlet_id,
        registration.kind,
    ) {
        return Err(unavailable(format!(
            "{challenger} holds no permission to invoke the outlet"
        )));
    }
    Ok(())
}

/// A verdict an evaluator returns: an object of exactly `passed` (a
/// boolean) and `reason` (a string).
struct EvaluatorVerdict {
    passed: bool,
    reason: String,
}

/// Reads `output` as a verdict; any other key, or a missing one, is no
/// verdict.
fn parse_verdict(output: &Value) -> Option<EvaluatorVerdict> {
    let object = output.as_object()?;
    if object.len() != 2 {
        return None;
    }
    Some(EvaluatorVerdict {
        passed: object.get("passed")?.as_bool()?,
        reason: object.get("reason")?.as_str()?.to_owned(),
    })
}

/// The shared body of [`EvaluatorInvoker::invoke`].
///
/// It runs `handler` as the executor of
/// [`Supervisor::invoke_outlet_with_economy`] on a blocking thread that
/// holds `call.permit`, with `call.challenger` as the invoker.
///
/// The phase of a failure decides its class, never the error's variant:
/// - no handler, no registration, or any error before the executor
///   started (the context state, the permission, the economy reserve, the
///   rate limit) is [`EvaluatorOutcome::Unavailable`];
/// - an input the evaluator's input schema refuses is
///   [`EvaluatorOutcome::CaseFailed`], checked before the reserve because
///   the input carries the subject's output;
/// - an error after the executor started with no well-formed verdict (a
///   handler error, a panic, a timeout, an output the output schema
///   refuses) is [`EvaluatorOutcome::CaseFailed`];
/// - an error after the handler returned a well-formed verdict (the
///   settlement) is [`EvaluatorOutcome::Unavailable`], and the verdict is
///   discarded: the challenger's own settlement never decides a subject's
///   case.
///
/// The economy pipeline runs on its own task. A reserve holds budget, a
/// rate-limit slot, and any escrow until its settle runs, so dropping the
/// pipeline between the two would leak them; the task carries it to its
/// settle when the grading budget expires or the caller is dropped.
pub async fn invoke_evaluator_outlet(
    sup: &Arc<Supervisor>,
    registry: Option<&OutletRegistry>,
    handler: Option<EvaluatorHandler>,
    call: EvaluatorCall<'_>,
) -> EvaluatorOutcome {
    let EvaluatorCall {
        evaluator_context_id,
        outlet_id,
        challenger,
        input,
        remaining,
        permit,
    } = call;
    let Some(registry) = registry else {
        return EvaluatorOutcome::Unavailable("the evaluator context is not open".to_owned());
    };
    let Some(registration) = registry.get(outlet_id) else {
        return EvaluatorOutcome::Unavailable("the outlet is not registered".to_owned());
    };
    let Some(handler) = handler else {
        return EvaluatorOutcome::Unavailable("no host handler is registered".to_owned());
    };
    if validate_value_against_schema(&input, &registration.schema.input_schema).is_err()
        || sha256_json(&input).is_err()
    {
        return EvaluatorOutcome::CaseFailed(EVALUATOR_FAILED_REASON.to_owned());
    }
    let output_schema = registration.schema.output_schema.clone();
    let started = Arc::new(AtomicBool::new(false));
    let captured: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));
    let executor = {
        let started = Arc::clone(&started);
        let captured = Arc::clone(&captured);
        move |input: Value| {
            started.store(true, Ordering::SeqCst);
            async move {
                let output = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    handler(input)
                })
                .await
                .map_err(|e| format!("evaluator handler task failed: {e}"))??;
                if let Ok(mut slot) = captured.lock() {
                    *slot = Some(output.clone());
                }
                Ok(output)
            }
        }
    };
    let timeout_ms = u32::try_from(remaining.as_millis())
        .unwrap_or(u32::MAX)
        .max(1);
    let pipeline = {
        let sup = Arc::clone(sup);
        let evaluator_context_id = evaluator_context_id.to_owned();
        let registry = registry.clone();
        let outlet_id = outlet_id.clone();
        let challenger = challenger.clone();
        tokio::spawn(async move {
            sup.invoke_outlet_with_economy(
                &evaluator_context_id,
                &registry,
                &outlet_id,
                input,
                &challenger,
                None,
                None,
                Some(timeout_ms),
                executor,
            )
            .await
        })
    };
    let joined = pipeline
        .await
        .map(|result| result.map(|invocation| invocation.output));
    classify_evaluator_result(joined, &started, &captured, &output_schema)
}

/// Classifies an evaluator pipeline's result by the phase it failed in: see
/// [`invoke_evaluator_outlet`].
fn classify_evaluator_result(
    joined: Result<Result<Value, ContextError>, tokio::task::JoinError>,
    started: &AtomicBool,
    captured: &Mutex<Option<Value>>,
    output_schema: &Value,
) -> EvaluatorOutcome {
    let result = match joined {
        Ok(result) => result,
        // A pipeline that panicked before the handler started never ran the
        // evaluator; one that panicked after it reached no settled verdict.
        Err(e) if !started.load(Ordering::SeqCst) => {
            return EvaluatorOutcome::Unavailable(format!("the evaluator task failed: {e}"));
        }
        Err(_) => return EvaluatorOutcome::CaseFailed(EVALUATOR_FAILED_REASON.to_owned()),
    };
    match result {
        Ok(output) => parse_verdict(&output).map_or_else(
            || EvaluatorOutcome::CaseFailed(EVALUATOR_FAILED_REASON.to_owned()),
            |v| EvaluatorOutcome::Verdict {
                passed: v.passed,
                reason: v.reason,
            },
        ),
        Err(e) if !started.load(Ordering::SeqCst) => EvaluatorOutcome::Unavailable(e.to_string()),
        Err(e) => {
            let verdict_returned = captured
                .lock()
                .ok()
                .and_then(|slot| slot.clone())
                .is_some_and(|output| {
                    parse_verdict(&output).is_some()
                        && validate_value_against_schema(&output, output_schema).is_ok()
                        && sha256_json(&output).is_ok()
                });
            if verdict_returned {
                EvaluatorOutcome::Unavailable(format!(
                    "the evaluator returned a verdict and its settlement failed: {e}"
                ))
            } else {
                EvaluatorOutcome::CaseFailed(EVALUATOR_FAILED_REASON.to_owned())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

/// The arguments of [`create_challenge`] a caller chooses.
#[derive(Debug, Clone)]
pub struct CreateChallenge {
    /// The challenger, an identity this instance hosts.
    pub verifier: DID,
    /// The subject.
    pub subject: DID,
    /// The capability URI under test, in canonical form.
    pub capability_uri: String,
    /// A JSON array of `TestCase`, with their answers.
    pub test_cases_json: String,
    /// `expires_at - created_at`, in `1..=MAX_CHALLENGE_WINDOW_SECS`.
    pub window_secs: u64,
    /// The context the challenge is administered in.
    pub context_id: String,
    /// Fewer retries or a longer cooldown than the definition's; `None`
    /// takes the definition's values.
    pub policy: Option<PolicyPick>,
    /// The context of the `CustomEval` evaluator outlets; required when a
    /// case is `CustomEval`.
    pub evaluator_context_id: Option<String>,
}

/// Builds a challenge and records it in the challenger's ledger (spec 07
/// §7.3.4 step 1).
///
/// The cases are the challenger-written test cases, and the returned request
/// is the one the ledger signed with the challenger's `#active` key through
/// `signer`.
///
/// Checks, in order: the signer is Ed25519 (before any custody call); the
/// cases parse; [`ChallengePolicy::resolve`] (the definition, the
/// ungradable standards, the policy limits); [`challenge_request_unsigned`]
/// (the parties, the suite rules, the minimum, the schema gate, the
/// window); every `CustomEval` outlet is registered in
/// `evaluator_context_id` and invocable by the challenger; then the ledger.
///
/// # Errors
///
/// - [`ChallengeOpError::Context`] when the signer is not Ed25519, the
///   supervisor has no clock, or the ledger cannot persist or sign.
/// - [`ChallengeOpError::MalformedJson`] when the cases do not parse.
/// - [`ChallengeOpError::Trust`] for every protocol and ledger refusal,
///   including [`TrustError::EvaluatorUnavailable`].
pub async fn create_challenge(
    sup: &Supervisor,
    signer: &CommandSigner,
    args: CreateChallenge,
    invoker: &dyn EvaluatorInvoker,
    defs: &dyn CapabilityDefinitionSource,
) -> Result<ChallengeRequest, ChallengeOpError> {
    signer.require_ed25519()?;
    let test_cases: Vec<TestCase> = decode!(JsonInput::TestCases, &args.test_cases_json)?;
    let policy = ChallengePolicy::resolve(defs, &args.capability_uri, args.policy)?;
    let evaluator_outlets: Vec<OutletId> = test_cases
        .iter()
        .filter_map(|case| match &case.expected {
            ExpectedOutput::CustomEval {
                evaluator_outlet_id,
            } => Some(evaluator_outlet_id.clone()),
            _ => None,
        })
        .collect();
    let definition = policy.definition().clone();
    let verifier = args.verifier.clone();
    let (unsigned, answer_key) = challenge_request_unsigned(NewChallenge {
        verifier: args.verifier,
        subject: args.subject,
        test_cases,
        created_at: sup.now_secs()?,
        window_secs: args.window_secs,
        context_id: args.context_id,
        policy,
    })?;
    for outlet_id in &evaluator_outlets {
        let Some(evaluator_context_id) = args.evaluator_context_id.as_deref() else {
            return Err(TrustError::EvaluatorUnavailable {
                context_id: String::new(),
                outlet_id: outlet_id.clone(),
                reason: "a CustomEval case needs an evaluator context".to_owned(),
            }
            .into());
        };
        invoker
            .check_registered(evaluator_context_id, outlet_id, &verifier)
            .await?;
    }
    Ok(sup
        .dispatch_challenge_create(
            verifier.as_ref(),
            unsigned,
            answer_key,
            definition,
            args.evaluator_context_id,
            signer.clone(),
        )
        .await?)
}

// ---------------------------------------------------------------------------
// Respond
// ---------------------------------------------------------------------------

/// Builds the subject's response to the signed request in `request_json`
/// from the outputs in `outputs_json`, and signs it with the subject's
/// `#active` key through `signer` (spec 07 §7.3.4 step 2).
///
/// `resolver` resolves the challenger's key to check the request
/// signature; its lookups block, so the check runs on a blocking thread.
///
/// # Errors
///
/// - [`ChallengeOpError::Context`] when the signer is not Ed25519 (before
///   any resolution or custody call), or the custody failure from signing.
/// - [`ChallengeOpError::MalformedJson`] naming the first argument that
///   does not decode.
/// - [`ChallengeOpError::Trust`] for every refusal of
///   [`challenge_response_unsigned`].
/// - [`ChallengeOpError::Blocking`] when the resolution task fails.
pub async fn respond_to_challenge<R>(
    signer: &CommandSigner,
    resolver: Arc<R>,
    subject: String,
    request_json: &str,
    outputs_json: &str,
    attempt: u32,
) -> Result<ChallengeResponse, ChallengeOpError>
where
    R: ActiveKeyResolver + Send + Sync + 'static,
{
    signer.require_ed25519()?;
    let request: ChallengeRequest = decode!(JsonInput::Challenge, request_json)?;
    let outputs: Vec<TestOutput> = decode!(JsonInput::Outputs, outputs_json)?;
    let unsigned = run_blocking_resolution(move |_scope| {
        challenge_response_unsigned(
            &request,
            &subject,
            attempt,
            outputs,
            resolver.as_ref(),
            &SystemClock,
        )
    })
    .await??;
    let signature = signer
        .sign_bounded_ed25519(&unsigned.signing_digest())
        .await?;
    Ok(unsigned.with_subject_signature(signature.to_vec()))
}

// ---------------------------------------------------------------------------
// Grade
// ---------------------------------------------------------------------------

/// A graded attempt, as [`grade_response`] returns it.
#[derive(Debug, Clone)]
pub struct GradeResult {
    /// The signed record.
    pub record: ChallengeVerification,
    /// The per-case results, never signed.
    pub reasons: Vec<CaseResult>,
    /// Why the record could not be written to the bridge's trust store,
    /// when it could not. The record is signed and the attempt is used
    /// either way.
    pub trust_store_error: Option<String>,
}

/// Grades the subject's response in `response_json` to the request in
/// `request_json` and returns the record the challenger's ledger signed
/// (spec 07 §7.3.4 steps 3 and 4). `verifier` is the challenger.
///
/// Steps, in order:
/// 1. the signer is Ed25519, and the raw response fits
///    [`check_response_bounds`];
/// 2. the request and response decode;
/// 3. the ledger holds the challenge with this request digest and subject
///    (read only, before any resolution);
/// 4. [`authenticate_challenge_response`] on a blocking thread, so a forged
///    response takes no lease and records no fault;
/// 5. one of the challenger's grading permits;
/// 6. Begin: a resubmitted attempt returns its stored record, otherwise the
///    caller holds the grading lease;
/// 7. the cases run one at a time within `CHALLENGE_GRADING_BUDGET_SECS`
///    for the whole attempt; a case the budget cuts off fails with
///    `budget_exceeded`;
/// 8. an answer key that does not open, a stored schema the gate refuses,
///    or an unavailable evaluator is a fault, which uses no attempt;
///    otherwise the ledger commits and signs the record;
/// 9. the record is written to `repo`, whose failure is returned as
///    [`GradeResult::trust_store_error`].
///
/// # Errors
///
/// - [`ChallengeOpError::Context`] when the signer is not Ed25519, or the
///   ledger cannot persist or sign.
/// - [`ChallengeOpError::MalformedJson`] naming the argument that does not
///   decode.
/// - [`ChallengeOpError::Trust`] for every protocol refusal, every ledger
///   refusal, and every recorded fault.
/// - [`ChallengeOpError::Blocking`] when the resolution task fails.
pub async fn grade_response<R, S>(
    grader: &Grader<'_, R>,
    repo: &Arc<ProtocolRepository<S>>,
    verifier: &DID,
    request_json: &str,
    response_json: &str,
) -> Result<GradeResult, ChallengeOpError>
where
    R: ActiveKeyResolver + Send + Sync + 'static,
    S: Storage + 'static,
{
    grade_response_within(
        grader,
        repo,
        verifier,
        (request_json, response_json),
        Duration::from_secs(CHALLENGE_GRADING_BUDGET_SECS),
    )
    .await
}

/// What a bridge grades with: the supervisor that holds the challenger's
/// ledger, the challenger's signer, the instance's DID resolver, and the
/// bridge's evaluator invoker.
pub struct Grader<'a, R> {
    /// The supervisor that holds the challenger's ledger.
    pub sup: &'a Supervisor,
    /// The challenger's `#active` key, which signs the record.
    pub signer: &'a CommandSigner,
    /// The instance's DID resolver, which authenticates the response.
    pub resolver: Arc<R>,
    /// The bridge's evaluator invoker, which runs `CustomEval` cases.
    pub invoker: &'a dyn EvaluatorInvoker,
}

/// [`grade_response`] with the grading budget as a parameter, so a test
/// can prove the budget is total per attempt without waiting a minute.
async fn grade_response_within<R, S>(
    grader: &Grader<'_, R>,
    repo: &Arc<ProtocolRepository<S>>,
    verifier: &DID,
    (request_json, response_json): (&str, &str),
    budget: Duration,
) -> Result<GradeResult, ChallengeOpError>
where
    R: ActiveKeyResolver + Send + Sync + 'static,
    S: Storage + 'static,
{
    let Grader {
        sup,
        signer,
        resolver,
        invoker,
    } = grader;
    let (sup, signer, invoker) = (*sup, *signer, *invoker);
    let resolver = Arc::clone(resolver);
    signer.require_ed25519()?;
    check_response_bounds(response_json.as_bytes())?;
    let request: ChallengeRequest = decode!(JsonInput::Challenge, request_json)?;
    let response: ChallengeResponse = decode!(JsonInput::Response, response_json)?;
    let challenger = verifier.as_ref();
    sup.dispatch_challenge_lookup(challenger, &request).await?;
    let auth = {
        let challenger = challenger.to_owned();
        run_blocking_resolution(move |_scope| {
            authenticate_challenge_response(&request, &response, &challenger, resolver.as_ref())
                .map(|auth| auth.to_owned_response())
        })
        .await??
    };
    let auth = Arc::new(auth);
    let permit = Arc::new(sup.challenge_grading_permit(challenger).await?);
    let lease = match sup
        .dispatch_challenge_begin_grade(challenger, Arc::clone(&auth), signer.clone())
        .await?
    {
        BeginOutcome::Stored(stored) => return Ok(store_graded(repo, *stored).await),
        BeginOutcome::Lease(lease) => lease,
    };
    let challenge_id = auth.as_authenticated().request().challenge_id;
    let fault = |fault: GradingFault| async {
        let error = TrustError::from(fault.clone());
        sup.dispatch_challenge_fault(challenger, challenge_id, lease.lease_id, fault)
            .await?;
        Err::<GradeResult, ChallengeOpError>(error.into())
    };
    // An answer key that does not open is a fault before any evaluator runs.
    let empty = BTreeMap::new();
    if let Err(e) = grade(
        &auth.as_authenticated(),
        &lease.answer_key,
        &empty,
        &BTreeMap::new(),
    ) {
        return fault(GradingFault::AnswerKeyMismatch(e)).await;
    }
    let mut evaluated = CaseVerdicts::default();
    let run = async {
        let case_run = CaseRun {
            evaluator_context_id: lease.evaluator_context_id.as_deref(),
            challenger: verifier,
            invoker,
            permit: &permit,
            deadline: tokio::time::Instant::now() + budget,
        };
        evaluate_cases(&auth, &lease.answer_key, &case_run, &mut evaluated).await;
    };
    // On expiry the in-flight case and every later one have no verdict, so
    // `grade` fails them with `budget_exceeded`.
    let _ = tokio::time::timeout(budget, run).await;
    if let Some(f) = evaluated.fault.take() {
        return fault(f).await;
    }
    let outcome = match grade(
        &auth.as_authenticated(),
        &lease.answer_key,
        &evaluated.evals,
        &evaluated.schemas,
    ) {
        Ok(outcome) => outcome,
        Err(e) => return fault(GradingFault::AnswerKeyMismatch(e)).await,
    };
    let committed = sup
        .dispatch_challenge_commit(challenger, auth, lease.lease_id, outcome, signer.clone())
        .await?;
    Ok(store_graded(repo, committed).await)
}

/// The verdicts gathered for one attempt, and the fault that stopped it.
#[derive(Default)]
struct CaseVerdicts {
    evals: BTreeMap<usize, CaseResult>,
    schemas: BTreeMap<usize, SchemaVerdict>,
    fault: Option<GradingFault>,
}

/// How one attempt runs its evaluated cases: the evaluator context, the
/// challenger, the bridge's invoker, the grading permit, and the budget's
/// deadline.
struct CaseRun<'a> {
    evaluator_context_id: Option<&'a str>,
    challenger: &'a DID,
    invoker: &'a dyn EvaluatorInvoker,
    permit: &'a Arc<OwnedSemaphorePermit>,
    deadline: tokio::time::Instant,
}

/// Validates `output` against a `SchemaMatch` case's schema on the blocking
/// pool, holding `permit`.
///
/// A schema the gate refuses is a challenger fault; a validation that
/// panicked did not accept the output.
async fn schema_case(
    permit: Arc<OwnedSemaphorePermit>,
    test_id: &str,
    schema: &Value,
    output: &Value,
) -> Result<SchemaVerdict, GradingFault> {
    let (id, schema, output) = (test_id.to_owned(), schema.clone(), output.clone());
    let verdict = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        SchemaGate::admit(&id, &schema).map(|validator| schema_verdict(&validator, &output))
    })
    .await;
    match verdict {
        Ok(Ok(verdict)) => Ok(verdict),
        Ok(Err(e)) => Err(GradingFault::SchemaRejected {
            test_id: test_id.to_owned(),
            reason: e.to_string(),
        }),
        Err(_) => Ok(SchemaVerdict::Fail),
    }
}

/// Runs every `SchemaMatch` and `CustomEval` case of the attempt, one at a
/// time, filling `out`. It stops at the first fault.
async fn evaluate_cases(
    auth: &OwnedAuthenticatedResponse,
    answer_key: &scp_protocol::trust::AnswerKey,
    run: &CaseRun<'_>,
    out: &mut CaseVerdicts,
) {
    let CaseRun {
        evaluator_context_id,
        challenger,
        invoker,
        permit,
        deadline,
    } = *run;
    let auth = auth.as_authenticated();
    let cases = &auth.request().test_cases;
    let outputs = &auth.response().outputs;
    for (i, ((opening, case), output)) in answer_key
        .openings()
        .iter()
        .zip(cases)
        .zip(outputs)
        .enumerate()
    {
        match &opening.expected {
            ExpectedOutput::SchemaMatch { schema } => {
                match schema_case(Arc::clone(permit), &case.test_id, schema, &output.output).await {
                    Ok(verdict) => {
                        out.schemas.insert(i, verdict);
                    }
                    Err(fault) => {
                        out.fault = Some(fault);
                        return;
                    }
                }
            }
            ExpectedOutput::CustomEval {
                evaluator_outlet_id,
            } => {
                let Some(context_id) = evaluator_context_id else {
                    out.fault = Some(GradingFault::EvaluatorUnavailable {
                        context_id: String::new(),
                        outlet_id: evaluator_outlet_id.clone(),
                        reason: "the challenge names no evaluator context".to_owned(),
                    });
                    return;
                };
                let input = serde_json::json!({
                    "case": {
                        "test_id": case.test_id,
                        "input": case.input,
                        "category": case.category,
                        "weight": case.weight,
                    },
                    "output": output.output,
                });
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                match invoker
                    .invoke(EvaluatorCall {
                        evaluator_context_id: context_id,
                        outlet_id: evaluator_outlet_id,
                        challenger,
                        input,
                        remaining,
                        permit: Arc::clone(permit),
                    })
                    .await
                {
                    EvaluatorOutcome::Verdict { passed, reason } => {
                        out.evals.insert(
                            i,
                            CaseResult {
                                passed,
                                reason: Some(reason),
                            },
                        );
                    }
                    EvaluatorOutcome::CaseFailed(reason) => {
                        out.evals.insert(
                            i,
                            CaseResult {
                                passed: false,
                                reason: Some(reason),
                            },
                        );
                    }
                    EvaluatorOutcome::Unavailable(reason) => {
                        out.fault = Some(GradingFault::EvaluatorUnavailable {
                            context_id: context_id.to_owned(),
                            outlet_id: evaluator_outlet_id.clone(),
                            reason,
                        });
                        return;
                    }
                }
            }
            ExpectedOutput::ExactMatch { .. }
            | ExpectedOutput::ContainsAll { .. }
            | ExpectedOutput::ContainsNone { .. } => {}
        }
    }
}

/// Writes a graded attempt's record to the bridge's trust store. A write
/// failure is logged and returned, never raised: the record is signed and
/// the attempt used either way, and a resubmit writes it again.
async fn store_graded<S: Storage + 'static>(
    repo: &Arc<ProtocolRepository<S>>,
    graded: GradedAttempt,
) -> GradeResult {
    let GradedAttempt { record, reasons } = graded;
    let trust_store_error = repo
        .store_trust_challenge_result(&record.context_id, &record)
        .await
        .err()
        .map(|e| {
            tracing::warn!(
                verification_id = %hex::encode(record.verification_id),
                error = %e,
                "graded challenge record not written to the trust store"
            );
            e.to_string()
        });
    GradeResult {
        record,
        reasons,
        trust_store_error,
    }
}

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------

/// Checks the agent `subject_did` against the live capability requirements
/// of `context_id` (spec 07 §7.3.4.4), as context governance set them.
///
/// Each record is verified against its challenger's `#active` key through
/// `resolver`; with none, a supplied record fails closed with
/// [`AdmissionError::VerificationUnavailable`].
///
/// # Errors
///
/// - [`ChallengeOpError::MalformedJson`] naming the argument that does not
///   decode.
/// - [`ChallengeOpError::Context`] when the context's requirements cannot
///   be read: an unknown, crashed, poisoned or busy context never reads as
///   an empty list.
/// - [`ChallengeOpError::Admission`] when the agent does not meet them.
/// - [`ChallengeOpError::Blocking`] when the resolution task fails.
pub async fn check_capability_requirements(
    sup: &Supervisor,
    resolver: Option<Arc<IdentityBackedDidResolver>>,
    context_id: String,
    subject_did: String,
    agent_capabilities_json: &str,
    challenge_verifications_json: &str,
) -> Result<(), ChallengeOpError> {
    let capabilities: Vec<CapabilityUri> =
        decode!(JsonInput::AgentCapabilities, agent_capabilities_json)?;
    let records: Vec<ChallengeVerification> = decode!(
        JsonInput::ChallengeVerifications,
        challenge_verifications_json
    )?;
    let requirements = sup.capability_requirements_checked(&context_id).await?;
    run_blocking_resolution(move |scope| {
        scp_protocol::trust::check_capability_requirements(
            &requirements,
            &capabilities,
            &records,
            &AdmissionCheck {
                context_id: &context_id,
                subject_did: &subject_did,
                resolver: instance_active_key_resolver(scope, resolver.as_ref()),
                definitions: &ProtocolOnlyDefinitions,
                clock: &SystemClock,
            },
        )
    })
    .await??;
    Ok(())
}

#[cfg(test)]
#[path = "challenge_tests.rs"]
mod tests;
