//! napi-rs bridge for trust engine operations.
//!
//! Per-bridge-instance (`_on`) implementations consumed by the corresponding
//! methods on [`crate::scp::Scp`]. The free-function wrappers that routed
//! through the process-global default bridge instance were deleted.
//!
//! See ADR-017 in `.docs/adrs/phase-4.md`.

use scp_ffi_common::error_codes as codes;
use std::sync::Arc;

use napi_derive::napi;

use crate::error::ScpNapiError;
use crate::runtime::NapiBridgeInstance;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Trust score query result.
#[napi(object)]
#[derive(Debug)]
pub struct NapiTrustScoreResult {
    /// Number of message events attributed to the DID.
    pub message_count: i64,
    /// Number of governance action events attributed to the DID.
    pub governance_count: i64,
    /// Normalized composite score (0.0–1.0).
    pub composite_score: f64,
}

/// Attestation verification result.
#[napi(object)]
#[derive(Debug)]
pub struct NapiAttestationVerificationResult {
    /// Whether the attestation is valid.
    pub valid: bool,
    /// Chain depth (1 for single attestation).
    pub chain_depth: i32,
    /// Error message if verification failed, empty string if valid.
    pub error_message: String,
}

/// A signed challenge request, as `trustCreateChallenge` returns it.
#[napi(object)]
#[derive(Debug)]
pub struct NapiChallengeRequest {
    /// The challenge id: lowercase hex of its 32 random bytes.
    pub challenge_id: String,
    /// The signed `ChallengeRequest` (JSON), which carries no answers.
    pub request_json: String,
}

/// A challenger's choice of fewer retries or a longer cooldown than the
/// capability definition's. An absent field takes the definition's value.
#[napi(object)]
#[derive(Debug, Clone, Copy)]
pub struct NapiPolicyPick {
    /// Retries after the first attempt; at most the definition's.
    pub max_retries: Option<u32>,
    /// Seconds between graded attempts; at least the definition's.
    pub cooldown_secs: Option<u32>,
}

/// A graded attempt, as `trustGradeResponse` returns it.
#[napi(object)]
#[derive(Debug)]
pub struct NapiGradeResult {
    /// The signed `ChallengeVerification` (JSON).
    pub record_json: String,
    /// The per-case results (JSON array of `CaseResult`), never signed.
    pub reasons_json: String,
    /// Why the record could not be written to this instance's trust store,
    /// when it could not; the record is signed and the attempt used either
    /// way.
    pub trust_store_error: Option<NapiTrustStoreWriteError>,
}

/// A failed write of a graded record to this instance's trust store.
#[napi(object)]
#[derive(Debug, PartialEq, Eq)]
pub struct NapiTrustStoreWriteError {
    /// The error code, the one every trust-store write failure reports.
    pub code: String,
    /// The message.
    pub message: String,
}

/// Structured participation facts (§7.3.2) for a subject DID in a context.
///
/// The scalar projection of scp-core's `ParticipationRecord`, produced by
/// `Scp.participationRecord`. Counts are flattened ONCE in the shared Rust core
/// (`ParticipationFacts`) so TypeScript RECEIVES the facts rather than
/// re-aggregating event-log collections — eliminating cross-binding divergence
/// by construction. `u64` counts/timestamps are surfaced as napi `i64` (JS
/// number; lossless for these ranges, matching `NapiTrustScoreResult`);
/// booleans/strings map directly. See ADR-017.
#[napi(object)]
#[derive(Debug)]
pub struct NapiParticipationRecord {
    /// The DID whose participation is summarized.
    pub subject_did: String,
    /// Total seconds of context participation (§7.3.2).
    pub participation_duration_secs: i64,
    /// Count of governance actions taken against this identity.
    pub governance_actions_against: i64,
    /// Count of governance actions initiated by this identity.
    pub governance_actions_by: i64,
    /// Total outlet invocations across all outlet types.
    pub outlet_invocation_count: i64,
    /// Whether `outlet_invocation_count` is anchored in the canonical Merkle log
    /// (`false` until ADR-051; consumers MUST NOT treat it as Merkle-proven).
    pub outlet_invocation_count_anchored: bool,
    /// Number of contexts created by the subject.
    pub context_creation_count: i64,
    /// Number of role transitions for the subject.
    pub role_progression_count: i64,
    /// Number of accessible, currently-valid credential-layer attestations
    /// (§7.4) for the subject. Verifier-relative.
    pub attestation_count: i64,
    /// Whether `attestation_count` is anchored in / verifiable against a context
    /// Merkle root. Always `false` — credential-layer, verifier-relative (§7.4),
    /// never a context-event-log count (§7.3.2). Parallel of
    /// `outlet_invocation_count_anchored`.
    pub attestation_count_anchored: bool,
    /// Unix timestamp (seconds) when the record was computed.
    pub computed_at: i64,
    /// Merkle root (hex) of the event log at computation time.
    pub event_log_root: String,
}

impl From<&scp_core::trust::ParticipationFacts> for NapiParticipationRecord {
    #[allow(clippy::cast_possible_wrap)] // counts/timestamps are well within i64::MAX; documented
    fn from(f: &scp_core::trust::ParticipationFacts) -> Self {
        Self {
            subject_did: f.subject_did.to_string(),
            participation_duration_secs: f.participation_duration_secs as i64,
            governance_actions_against: f.governance_actions_against as i64,
            governance_actions_by: f.governance_actions_by as i64,
            outlet_invocation_count: f.outlet_invocation_count as i64,
            outlet_invocation_count_anchored: f.outlet_invocation_count_anchored,
            context_creation_count: f.context_creation_count as i64,
            role_progression_count: f.role_progression_count as i64,
            attestation_count: f.attestation_count as i64,
            attestation_count_anchored: f.attestation_count_anchored,
            computed_at: f.computed_at as i64,
            event_log_root: hex::encode(f.event_log_root),
        }
    }
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

/// Builds a bridge validation error carrying the explicit `SCP-VALID-*` code
/// the UniFFI/PyO3 bridges emit for the same logical failure case (e.g. the
/// per-case `check_capability_requirements` codes `VALID_7073`..=`VALID_7077`,
/// or the `verify_participation_requirements` codes `VALID_7030`/`VALID_7031`/
/// `VALID_7032`), so a TypeScript caller can branch on the same code a
/// Python/Swift/Kotlin caller sees.
fn coded_validation_error(msg: &str, code: &str) -> napi::Error {
    napi::Error::from(ScpNapiError::Validation {
        message: msg.to_owned(),
        code: code.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of [`Scp::trust_query_score`](crate::scp::Scp::trust_query_score).
/// Runs a trust operation that resolves signers' `#active` keys on tokio's
/// blocking pool, so a DID lookup never blocks the JavaScript thread.
///
/// # Errors
///
/// `work`'s own error, or `CTX_2000` when the blocking task panics or is
/// cancelled.
pub(crate) async fn on_resolution_pool<T, F>(work: F) -> napi::Result<T>
where
    F: FnOnce(&scp_ffi_common::BlockingResolutionScope) -> napi::Result<T> + Send + 'static,
    T: Send + 'static,
{
    scp_ffi_common::run_blocking_resolution(work)
        .await
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Context {
                message: e.to_string(),
                code: codes::CTX_2000.to_owned(),
            })
        })?
}

pub(crate) fn trust_query_score_on(
    bi: &NapiBridgeInstance,
    did: String,
    context_id: String,
) -> napi::Result<NapiTrustScoreResult> {
    // Per-argument codes match the UniFFI bridge (invalid DID → VALID_7010,
    // invalid context id → VALID_7011) so the same logical failure carries
    // the same code on every native bridge.
    if did.is_empty() {
        return Err(coded_validation_error(
            "DID must not be empty",
            codes::VALID_7010,
        ));
    }
    if context_id.is_empty() {
        return Err(coded_validation_error(
            "context_id must not be empty",
            codes::VALID_7011,
        ));
    }

    let (message_count, governance_count) =
        crate::runtime::query_trust_event_counts(bi, &context_id, &did);

    let total = message_count + governance_count;
    #[allow(clippy::cast_precision_loss)]
    let composite_score = (1.0 + total as f64).log10().min(1.0);

    #[allow(clippy::cast_possible_wrap)]
    Ok(NapiTrustScoreResult {
        message_count: message_count as i64,
        governance_count: governance_count as i64,
        composite_score,
    })
}

/// Per-bridge-instance implementation of `trust_verify_attestation`.
///
/// Verifies one attestation's signature, evidence, expiry, and its own
/// revocation status, and checks this instance's revocation list for
/// `context_id`. A rejection returns `valid: false` with the reason; a
/// revocation list that cannot be read is an error (`VALID_7052`), never a
/// verdict.
pub(crate) fn trust_verify_attestation_on(
    scope: &scp_ffi_common::BlockingResolutionScope,
    bi: &NapiBridgeInstance,
    context_id: String,
    attestation_json: String,
) -> napi::Result<NapiAttestationVerificationResult> {
    use scp_ffi_common::trust_store::AttestationVerdict;

    scp_ffi_common::validate::validate_context_id(&context_id)
        .map_err(|e| coded_validation_error(&e.message, codes::VALID_7011))?;
    // VALID_7012 matches the UniFFI bridge's code for malformed attestation
    // JSON so the same logical failure carries the same code on every bridge.
    let attestation: scp_core::trust::Attestation = serde_json::from_str(&attestation_json)
        .map_err(|e| {
            coded_validation_error(
                &format!("failed to parse attestation JSON: {e}"),
                codes::VALID_7012,
            )
        })?;

    // The issuer's current `#active` key (spec 09 §9.7.1), resolved through
    // this instance's DID resolver; an instance without one fails closed.
    let resolver =
        scp_ffi_common::instance_active_key_resolver(scope, crate::runtime::did_resolver(bi));
    let verdict = match crate::runtime::protocol_repository(bi) {
        crate::runtime::ProtocolRepoVariant::InMemory(repo) => {
            run_verify_attestation(repo, resolver, &context_id, &attestation)
        }
        crate::runtime::ProtocolRepoVariant::Sqlite(repo) => {
            run_verify_attestation(repo, resolver, &context_id, &attestation)
        }
    }
    .map_err(|e| coded_validation_error(&e.to_string(), codes::VALID_7052))?;

    Ok(match verdict {
        AttestationVerdict::Valid => NapiAttestationVerificationResult {
            valid: true,
            chain_depth: 1,
            error_message: String::new(),
        },
        AttestationVerdict::Rejected(reason) => NapiAttestationVerificationResult {
            valid: false,
            chain_depth: 0,
            error_message: reason.to_string(),
        },
    })
}

/// Verifies one attestation against the revocation list in the concrete
/// backend behind a `ProtocolRepoVariant` arm, with the instance's `#active`
/// key resolver and the system clock.
fn run_verify_attestation<S: scp_platform::traits::Storage + 'static>(
    repo: &Arc<scp_core::store::ProtocolRepository<S>>,
    resolver: &dyn scp_core::trust::attestation::ActiveKeyResolver,
    context_id: &str,
    attestation: &scp_core::trust::Attestation,
) -> Result<scp_ffi_common::trust_store::AttestationVerdict, scp_core::trust::TrustError> {
    let handle = crate::runtime().handle().clone();
    let bridge = scp_core::trust::ProtocolRepositoryTrustBridge::new(Arc::clone(repo), handle);
    scp_ffi_common::trust_store::verify_attestation_in_context(
        &bridge,
        context_id,
        attestation,
        resolver,
        &scp_clock::SystemClock,
    )
}

/// Maps a shared challenge-operation failure to its bridge error through
/// [`ChallengeOpError::code_and_class`](scp_ffi_common::challenge::ChallengeOpError::code_and_class),
/// so the code and class are the same on every bridge; a runtime failure
/// takes this bridge's `ContextError` conversion.
fn challenge_op_error(e: scp_ffi_common::challenge::ChallengeOpError) -> napi::Error {
    use scp_ffi_common::challenge::ChallengeFailure;
    use scp_ffi_common::error_codes::TrustFailureClass;
    napi::Error::from(match e.code_and_class() {
        ChallengeFailure::Coded {
            code,
            class,
            message,
        } => {
            let code = code.to_owned();
            match class {
                TrustFailureClass::Validation => ScpNapiError::Validation { message, code },
                TrustFailureClass::Identity => ScpNapiError::Identity { message, code },
                TrustFailureClass::Context => ScpNapiError::Context { message, code },
            }
        }
        ChallengeFailure::Context(e) => ScpNapiError::from(e),
    })
}

/// Resolves `did` to the custody signer over its `#active` key. An
/// identity this instance does not host fails with `SCP-IDENT-1001`.
async fn identity_signer(
    bi: &NapiBridgeInstance,
    did: &str,
) -> napi::Result<scp_core::context::actor::signer::CommandSigner> {
    let (custody, active_handle) = crate::runtime::with_identity(bi, did, |entry| {
        Ok((entry.custody.clone(), entry.identity.active_signing_key))
    })
    .map_err(napi::Error::from)?;
    scp_ffi_common::signer::identity_command_signer(custody, active_handle)
        .await
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))
}

/// The evaluator side of `CustomEval` grading on this bridge: the outlet
/// registry and host handlers of the evaluator context's UCAN state.
struct NapiEvaluatorInvoker<'a> {
    bi: &'a NapiBridgeInstance,
    sup: &'a Arc<scp_core::context::supervisor::Supervisor>,
}

impl NapiEvaluatorInvoker<'_> {
    /// A snapshot of the evaluator context's registry and the outlet's
    /// handler; `None` when the context is not open on this bridge, the
    /// only failure of `with_context`.
    fn snapshot(
        &self,
        evaluator_context_id: &str,
        outlet_id: &scp_core::context::outlets::OutletId,
    ) -> Option<(
        scp_core::context::outlets::OutletRegistry,
        Option<crate::runtime::OutletHandler>,
    )> {
        crate::runtime::with_context(self.bi, evaluator_context_id, |rt| {
            Ok((
                rt.outlet_registry.clone(),
                rt.outlet_handlers.get(outlet_id.as_str()).cloned(),
            ))
        })
        .ok()
    }
}

#[async_trait::async_trait]
impl scp_ffi_common::challenge::EvaluatorInvoker for NapiEvaluatorInvoker<'_> {
    async fn check_registered(
        &self,
        evaluator_context_id: &str,
        outlet_id: &scp_core::context::outlets::OutletId,
        challenger: &scp_did::DID,
    ) -> Result<(), scp_core::trust::TrustError> {
        let snapshot = self.snapshot(evaluator_context_id, outlet_id);
        scp_ffi_common::challenge::check_evaluator_registered(
            self.sup,
            evaluator_context_id,
            snapshot.as_ref().map(|(registry, _)| registry),
            snapshot
                .as_ref()
                .is_some_and(|(_, handler)| handler.is_some()),
            challenger,
            outlet_id,
        )
        .await
    }

    async fn invoke(
        &self,
        call: scp_ffi_common::challenge::EvaluatorCall<'_>,
    ) -> scp_ffi_common::challenge::EvaluatorOutcome {
        let (registry, handler) = self
            .snapshot(call.evaluator_context_id, call.outlet_id)
            .map_or((None, None), |(registry, handler)| {
                (Some(registry), handler)
            });
        scp_ffi_common::challenge::invoke_evaluator_outlet(
            self.sup,
            registry.as_ref(),
            handler,
            call,
        )
        .await
    }
}

/// Per-bridge-instance implementation of `trust_create_challenge`
/// (spec 07 §7.3.4 step 1, ADR-017).
///
/// Builds a challenge from the challenger-written `test_cases_json` (a JSON
/// array of `TestCase`, with their answers), records it in `verifier`'s
/// ledger, and returns the request the ledger signed with `verifier`'s
/// `#active` key. `policy` picks fewer retries or a longer cooldown than the
/// capability definition's; `evaluator_context_id` names the context of the
/// `CustomEval` evaluator outlets.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn trust_create_challenge_on(
    bi: &NapiBridgeInstance,
    verifier: String,
    subject: String,
    capability_uri: String,
    test_cases_json: String,
    context_id: String,
    window_secs: u32,
    evaluator_context_id: Option<String>,
    policy: Option<NapiPolicyPick>,
) -> napi::Result<NapiChallengeRequest> {
    scp_ffi_common::challenge::validate_challenge_did(&verifier).map_err(challenge_op_error)?;
    scp_ffi_common::challenge::validate_challenge_did(&subject).map_err(challenge_op_error)?;
    scp_ffi_common::challenge::validate_challenge_context_id(&context_id)
        .map_err(challenge_op_error)?;
    if let Some(id) = &evaluator_context_id {
        scp_ffi_common::challenge::validate_challenge_context_id(id).map_err(challenge_op_error)?;
    }
    let sup = crate::runtime::supervisor(bi)?;
    let signer = identity_signer(bi, &verifier).await?;
    let request = scp_ffi_common::challenge::create_challenge(
        sup,
        &signer,
        scp_ffi_common::challenge::CreateChallenge {
            verifier: verifier.into(),
            subject: subject.into(),
            capability_uri,
            test_cases_json,
            window_secs: u64::from(window_secs),
            context_id,
            policy: policy
                .map(|p| scp_core::trust::PolicyPick {
                    max_retries: p.max_retries,
                    cooldown_secs: p.cooldown_secs,
                })
                .unwrap_or_default(),
            evaluator_context_id,
        },
        &NapiEvaluatorInvoker { bi, sup },
        &scp_core::trust::ProtocolOnlyDefinitions,
    )
    .await
    .map_err(challenge_op_error)?;
    let request_json =
        scp_ffi_common::challenge::challenge_json("challenge", serde_json::to_string(&request))
            .map_err(challenge_op_error)?;
    Ok(NapiChallengeRequest {
        challenge_id: hex::encode(request.challenge_id),
        request_json,
    })
}

/// Per-bridge-instance implementation of `trust_respond_to_challenge`
/// (spec 07 §7.3.4 step 2, ADR-017).
///
/// Checks the challenger's signature on `request_json` through this
/// instance's DID resolver, and returns the `ChallengeResponse` JSON of
/// `outputs_json` for `attempt`, signed with `subject`'s `#active` key.
pub(crate) async fn trust_respond_to_challenge_on(
    bi: &NapiBridgeInstance,
    subject: String,
    request_json: String,
    outputs_json: String,
    attempt: u32,
) -> napi::Result<String> {
    scp_ffi_common::challenge::validate_challenge_did(&subject).map_err(challenge_op_error)?;
    let resolver = scp_ffi_common::challenge::required_did_resolver(
        crate::runtime::did_resolver(bi).cloned(),
        "trustRespondToChallenge",
    )
    .map_err(challenge_op_error)?;
    let signer = identity_signer(bi, &subject).await?;
    let response = scp_ffi_common::challenge::respond_to_challenge(
        &signer,
        resolver,
        subject,
        &request_json,
        &outputs_json,
        attempt,
    )
    .await
    .map_err(challenge_op_error)?;
    scp_ffi_common::challenge::challenge_json(
        "challenge response",
        serde_json::to_string(&response),
    )
    .map_err(challenge_op_error)
}

/// Per-bridge-instance implementation of `trust_grade_response`
/// (spec 07 §7.3.4 steps 3 and 4, ADR-017).
///
/// Grades the subject's `response_json` to `request_json` in `verifier`'s
/// ledger, runs `CustomEval` cases on this bridge's evaluator outlets, and
/// writes the signed record to this instance's protocol repository.
pub(crate) async fn trust_grade_response_on(
    bi: &NapiBridgeInstance,
    verifier: String,
    request_json: String,
    response_json: String,
) -> napi::Result<NapiGradeResult> {
    scp_ffi_common::challenge::validate_challenge_did(&verifier).map_err(challenge_op_error)?;
    let resolver = scp_ffi_common::challenge::required_did_resolver(
        crate::runtime::did_resolver(bi).cloned(),
        "trustGradeResponse",
    )
    .map_err(challenge_op_error)?;
    let sup = crate::runtime::supervisor(bi)?;
    let signer = identity_signer(bi, &verifier).await?;
    let verifier: scp_did::DID = verifier.into();
    let invoker = NapiEvaluatorInvoker { bi, sup };
    let grading = scp_ffi_common::challenge::Grader {
        sup,
        signer: &signer,
        resolver,
        invoker: &invoker,
    };
    let graded = match crate::runtime::protocol_repository(bi) {
        crate::runtime::ProtocolRepoVariant::InMemory(repo) => {
            scp_ffi_common::challenge::grade_response(
                &grading,
                repo,
                &verifier,
                &request_json,
                &response_json,
            )
            .await
        }
        crate::runtime::ProtocolRepoVariant::Sqlite(repo) => {
            scp_ffi_common::challenge::grade_response(
                &grading,
                repo,
                &verifier,
                &request_json,
                &response_json,
            )
            .await
        }
    }
    .map_err(challenge_op_error)?;
    let json = |what: &str, serialized| {
        scp_ffi_common::challenge::challenge_json(what, serialized).map_err(challenge_op_error)
    };
    Ok(NapiGradeResult {
        record_json: json(
            "challenge verification",
            serde_json::to_string(&graded.record),
        )?,
        reasons_json: json("case results", serde_json::to_string(&graded.reasons))?,
        trust_store_error: graded.trust_store_error.map(|e| NapiTrustStoreWriteError {
            code: e.code.to_owned(),
            message: e.message,
        }),
    })
}

// ---------------------------------------------------------------------------
// verify_participation_requirements (SCP-BA-004)
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of `verify_participation_requirements`.
///
/// Pure verification — the bridge instance is unused but accepted for API
/// symmetry with the other `_on` helpers in this module.
///
/// `expected_subject` is the DID of the agent being admitted: only profiles
/// whose signed `subject_did` equals it contribute to any accounting, closing
/// cross-subject participation-profile replay.
pub(crate) fn verify_participation_requirements_on(
    _bi: &NapiBridgeInstance,
    expected_subject: String,
    requirements_json: String,
    profile_json: String,
) -> napi::Result<()> {
    // Full DID-format validation (matching the PyO3 reference bridge), not just a
    // non-empty check, so all native bridges reject malformed ids identically.
    scp_ffi_common::validate::validate_did(&expected_subject)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    // Per-case codes match the UniFFI bridge: malformed requirements JSON →
    // VALID_7031, malformed profiles JSON → VALID_7030, failed admission
    // check → VALID_7032 (below).
    let requirements: Vec<scp_core::trust::RequireParticipation> =
        serde_json::from_str(&requirements_json).map_err(|e| {
            coded_validation_error(
                &format!("failed to parse participation requirements JSON: {e}"),
                codes::VALID_7031,
            )
        })?;

    let profiles: Vec<scp_core::trust::ParticipationProfile> = serde_json::from_str(&profile_json)
        .map_err(|e| {
            coded_validation_error(
                &format!("failed to parse participation profiles JSON: {e}"),
                codes::VALID_7030,
            )
        })?;

    // Fail-closed clock: a pre-epoch host clock is an unrecoverable environment
    // failure and must not silently read as time 0, which would make every
    // participation statement appear maximally fresh and bypass `max_age_secs`.
    // Matches the SystemClock invariant used on the verify-on-ingest path.
    let current_time = scp_clock::Clock::now_secs(&scp_clock::SystemClock);

    scp_core::trust::verify_participation_requirements(
        current_time,
        &expected_subject,
        &requirements,
        &profiles,
    )
    .map_err(|e| {
        coded_validation_error(
            &format!("participation admission verification failed: {e}"),
            codes::VALID_7032,
        )
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// check_capability_requirements (§7.3.4.4, SCP-ACR-008)
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of `check_capability_requirements`
/// (spec 07 §7.3.4.4).
///
/// Checks the agent against the capability requirements in `context_id`'s
/// governance state, read at call time. Each record's signature is checked
/// against the verifier's `#active` key through `bi`'s DID resolver on the
/// blocking pool; with none, a supplied record fails closed with
/// `SCP-IDENT-1033`. A record counts only for `subject_did` in `context_id`,
/// from a verifier the requirement trusts.
pub(crate) async fn check_capability_requirements_on(
    bi: &NapiBridgeInstance,
    context_id: String,
    subject_did: String,
    agent_capabilities_json: String,
    challenge_verifications_json: String,
) -> napi::Result<()> {
    // Full DID-format validation (matching the PyO3 reference bridge), not just a
    // non-empty check, so all native bridges reject malformed ids identically.
    scp_ffi_common::validate::validate_did(&subject_did)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    scp_ffi_common::challenge::validate_challenge_context_id(&context_id)
        .map_err(challenge_op_error)?;
    let sup = crate::runtime::supervisor(bi)?;
    scp_ffi_common::challenge::check_capability_requirements(
        sup,
        crate::runtime::did_resolver(bi).cloned(),
        context_id,
        subject_did,
        &agent_capabilities_json,
        &challenge_verifications_json,
    )
    .await
    .map_err(challenge_op_error)
}

// ---------------------------------------------------------------------------
// aggregate_trust_input (§7.3)
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of [`Scp::aggregate_trust_input`](crate::scp::Scp::aggregate_trust_input).
#[allow(clippy::too_many_arguments)]
pub(crate) fn aggregate_trust_input_on(
    scope: &scp_ffi_common::BlockingResolutionScope,
    bi: &NapiBridgeInstance,
    context_id: String,
    subject_did: String,
    events_json: String,
    merkle_root_json: String,
    consequence_rules_json: String,
    threshold_requirements_json: String,
    attestor_sets_json: String,
    cached_attestations_json: String,
    challenge_results_json: String,
) -> napi::Result<String> {
    // Per-argument codes match the UniFFI bridge's `aggregate_trust_input`
    // (context id → VALID_7040, subject DID → VALID_7041, then one code per
    // JSON input, VALID_7042..=VALID_7049) so the same logical failure
    // carries the same code on every native bridge.
    if context_id.is_empty() {
        return Err(coded_validation_error(
            "context_id must not be empty",
            codes::VALID_7040,
        ));
    }
    if subject_did.is_empty() {
        return Err(coded_validation_error(
            "subject DID must not be empty",
            codes::VALID_7041,
        ));
    }

    let events: Vec<scp_event_log::Event> = serde_json::from_str(&events_json).map_err(|e| {
        coded_validation_error(
            &format!("failed to parse events JSON: {e}"),
            codes::VALID_7042,
        )
    })?;

    let merkle_root_vec: Vec<u8> = serde_json::from_str(&merkle_root_json).map_err(|e| {
        coded_validation_error(
            &format!("failed to parse merkle_root JSON: {e}"),
            codes::VALID_7043,
        )
    })?;
    let merkle_root: [u8; 32] = merkle_root_vec.try_into().map_err(|v: Vec<u8>| {
        coded_validation_error(
            &format!("merkle_root must be exactly 32 bytes, got {}", v.len()),
            codes::VALID_7044,
        )
    })?;

    let consequence_rules: Vec<scp_core::trust::ConsequenceRule> =
        serde_json::from_str(&consequence_rules_json).map_err(|e| {
            coded_validation_error(
                &format!("failed to parse consequence_rules JSON: {e}"),
                codes::VALID_7045,
            )
        })?;

    let threshold_requirements: std::collections::HashMap<
        scp_core::trust::AttestationType,
        scp_core::trust::ThresholdRequirement,
    > = serde_json::from_str(&threshold_requirements_json).map_err(|e| {
        coded_validation_error(
            &format!("failed to parse threshold_requirements JSON: {e}"),
            codes::VALID_7046,
        )
    })?;

    let attestor_sets: std::collections::HashMap<
        scp_core::trust::AttestationType,
        Vec<scp_core::trust::AttestorInfo>,
    > = serde_json::from_str(&attestor_sets_json).map_err(|e| {
        coded_validation_error(
            &format!("failed to parse attestor_sets JSON: {e}"),
            codes::VALID_7047,
        )
    })?;

    let cached_attestations: Vec<scp_core::trust::aggregate::CachedAttestation> =
        serde_json::from_str(&cached_attestations_json).map_err(|e| {
            coded_validation_error(
                &format!("failed to parse cached_attestations JSON: {e}"),
                codes::VALID_7048,
            )
        })?;

    let challenge_results: Vec<scp_core::trust::ChallengeVerification> =
        serde_json::from_str(&challenge_results_json).map_err(|e| {
            coded_validation_error(
                &format!("failed to parse challenge_results JSON: {e}"),
                codes::VALID_7049,
            )
        })?;

    // Route trust aggregation through this bridge instance's
    // `ProtocolRepoVariant` so SQLite-backed bridges store trust
    // attestations in the same SQLCipher database as context snapshots and
    // event log entries. Per-bridge dispatch cannot be `None` — each
    // `NapiBridgeInstance` owns a concrete variant from construction, so
    // the split-brain failure mode main's `Option` guarded against
    // (trust writes silently landing in an ephemeral store while
    // context/event-log writes landed in SQLCipher) is structurally
    // unreachable.
    match crate::runtime::protocol_repository(bi) {
        crate::runtime::ProtocolRepoVariant::InMemory(repo) => {
            let handle = crate::runtime().handle().clone();
            let bridge =
                scp_core::trust::ProtocolRepositoryTrustBridge::new(Arc::clone(repo), handle);
            scp_ffi_common::trust_store::populate_and_aggregate(
                bridge,
                scp_ffi_common::instance_active_key_resolver(
                    scope,
                    crate::runtime::did_resolver(bi),
                ),
                &scp_core::trust::ProtocolOnlyDefinitions,
                &context_id,
                &subject_did,
                cached_attestations,
                &challenge_results,
                &events,
                merkle_root,
                &consequence_rules,
                &threshold_requirements,
                &attestor_sets,
            )
            .map_err(|e| {
                // VALID_7052 mirrors the UniFFI bridge's code for a failed
                // trust aggregation.
                coded_validation_error(&e.to_string(), codes::VALID_7052)
            })
        }
        crate::runtime::ProtocolRepoVariant::Sqlite(repo) => {
            let handle = crate::runtime().handle().clone();
            let bridge =
                scp_core::trust::ProtocolRepositoryTrustBridge::new(Arc::clone(repo), handle);
            scp_ffi_common::trust_store::populate_and_aggregate(
                bridge,
                scp_ffi_common::instance_active_key_resolver(
                    scope,
                    crate::runtime::did_resolver(bi),
                ),
                &scp_core::trust::ProtocolOnlyDefinitions,
                &context_id,
                &subject_did,
                cached_attestations,
                &challenge_results,
                &events,
                merkle_root,
                &consequence_rules,
                &threshold_requirements,
                &attestor_sets,
            )
            .map_err(|e| {
                // VALID_7052 mirrors the UniFFI bridge's code for a failed
                // trust aggregation.
                coded_validation_error(&e.to_string(), codes::VALID_7052)
            })
        }
    }
}

/// Per-instance participation-record computation (§7.3.2) for `subject_did` in
/// `context_id`.
///
/// Sources the subject's accessible, currently-valid attestations from THIS
/// instance's `ProtocolRepository` variant (populating any caller-supplied
/// `cached_attestations_json` first, exactly as `aggregate_trust_input_on`
/// does) — the REAL credential-layer source, not `&[]`. The shared Supervisor
/// gathers the FULL event log + Merkle root for every other fact. Returns the
/// flattened typed record so the SDK never re-aggregates.
/// Builds a `ProtocolRepositoryTrustBridge` over the concrete backend behind a
/// [`ProtocolRepoVariant`](scp_ffi_common::bridge_runtime::ProtocolRepoVariant) arm and reads back the subject's verified
/// attestations. Single source of truth for the per-backend
/// attestation-sourcing path: both `ProtocolRepoVariant` arms route through this
/// one generic body (mirroring the `PyO3` bridge's `run_verified_attestations`).
/// The match remains pure type dispatch because each variant holds a distinct
/// concrete `ProtocolRepository<S>`.
fn run_verified_attestations<S: scp_platform::traits::Storage + 'static>(
    repo: &Arc<scp_core::store::ProtocolRepository<S>>,
    resolver: &dyn scp_core::trust::attestation::ActiveKeyResolver,
    context_id: &str,
    subject_did: &str,
    cached_attestations: Vec<scp_core::trust::aggregate::CachedAttestation>,
) -> Result<Vec<scp_core::trust::attestation::Attestation>, scp_core::trust::TrustError> {
    let handle = crate::runtime().handle().clone();
    let bridge = scp_core::trust::ProtocolRepositoryTrustBridge::new(Arc::clone(repo), handle);
    scp_ffi_common::trust_store::verified_attestations(
        bridge,
        resolver,
        context_id,
        subject_did,
        cached_attestations,
    )
}

pub(crate) fn participation_record_on(
    scope: &scp_ffi_common::BlockingResolutionScope,
    bi: &NapiBridgeInstance,
    context_id: String,
    subject_did: String,
    cached_attestations_json: String,
) -> napi::Result<NapiParticipationRecord> {
    // Full format validation (matching the PyO3 reference bridge), not just a
    // non-empty check, so all native bridges reject malformed ids identically.
    scp_ffi_common::validate::validate_context_id(&context_id)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    scp_ffi_common::validate::validate_did(&subject_did)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    let cached_attestations: Vec<scp_core::trust::aggregate::CachedAttestation> =
        serde_json::from_str(&cached_attestations_json).map_err(|e| {
            napi::Error::from(ScpNapiError::Validation {
                message: format!("failed to parse cached_attestations JSON: {e}"),
                code: codes::VALID_7059.to_owned(),
            })
        })?;

    // Source verified attestations from this instance's `ProtocolRepository`
    // (same backend as context/event-log writes). Both variants route through
    // the single generic `run_verified_attestations` helper.
    let resolver =
        scp_ffi_common::instance_active_key_resolver(scope, crate::runtime::did_resolver(bi));
    let verified = match crate::runtime::protocol_repository(bi) {
        crate::runtime::ProtocolRepoVariant::InMemory(repo) => {
            run_verified_attestations(repo, resolver, &context_id, &subject_did, cached_attestations)
        }
        crate::runtime::ProtocolRepoVariant::Sqlite(repo) => {
            run_verified_attestations(repo, resolver, &context_id, &subject_did, cached_attestations)
        }
    }
    // An error from `verified_attestations` is an INFRA fault (trust-store read,
    // signature-verification infrastructure) — NOT caller-input validation. Code
    // it as a context-layer fault (CTX_2000), consistent with the generic-failure
    // arm of `participation_record` below, and keep it propagating (fail-closed):
    // it must never be folded into the empty-log CTX_2076 path.
    .map_err(|e| {
        napi::Error::from(ScpNapiError::Context {
            message: e.to_string(),
            code: codes::CTX_2000.to_owned(),
        })
    })?;

    let record = crate::runtime::supervisor(bi)?
        .participation_record(&context_id, &subject_did, &verified)
        .map_err(|e| {
            // Empty-log → dedicated CTX_2076 so SDKs branch on the code, not the
            // message; genuine failures stay on the generic CTX_2000.
            let code = match e {
                scp_core::context::ContextError::NoParticipationFacts { .. } => codes::CTX_2076,
                _ => codes::CTX_2000,
            };
            napi::Error::from(ScpNapiError::Context {
                message: e.to_string(),
                code: code.to_owned(),
            })
        })?;

    let facts = scp_core::trust::ParticipationFacts::from(&record);
    Ok(NapiParticipationRecord::from(&facts))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::runtime::NapiBridgeInstance;

    fn test_bi() -> NapiBridgeInstance {
        NapiBridgeInstance::new_napi()
    }

    #[test]
    fn trust_query_score_validates_empty_did() {
        let bi = test_bi();
        let result = trust_query_score_on(&bi, String::new(), "ctx".to_owned());
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7010),
            "expected {}, got: {msg}",
            codes::VALID_7010
        );
    }

    #[test]
    fn trust_query_score_validates_empty_context() {
        let bi = test_bi();
        let result = trust_query_score_on(&bi, "did:key:test".to_owned(), String::new());
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7011),
            "expected {}, got: {msg}",
            codes::VALID_7011
        );
    }

    #[test]
    fn trust_query_score_returns_zeros_for_unknown_context() {
        let bi = test_bi();
        let result =
            trust_query_score_on(&bi, "did:key:test".to_owned(), "nonexistent-ctx".to_owned());
        assert!(result.is_ok());
        let score = result.unwrap();
        assert_eq!(score.message_count, 0);
        assert_eq!(score.governance_count, 0);
    }

    // -----------------------------------------------------------------
    // Challenges (spec 07 §7.3.4)
    // -----------------------------------------------------------------

    const SCHEMA_URI: &str = "scp:capability:schema-validation/v1";

    /// `n` exact-match cases whose weights sum to 10000, each expecting
    /// `{"ok": true}`, as JSON.
    fn test_cases_json(n: usize) -> String {
        let weight = 10_000 / n;
        let cases: Vec<scp_core::trust::TestCase> = (0..n)
            .map(|i| scp_core::trust::TestCase {
                test_id: format!("t{i}"),
                input: serde_json::json!({ "i": i }),
                expected: scp_core::trust::ExpectedOutput::ExactMatch {
                    value: serde_json::json!({ "ok": true }),
                },
                category: "basic".to_owned(),
                weight: u32::try_from(if i == 0 {
                    10_000 - weight * (n - 1)
                } else {
                    weight
                })
                .unwrap(),
            })
            .collect();
        serde_json::to_string(&cases).unwrap()
    }

    fn assert_code<T: std::fmt::Debug>(result: napi::Result<T>, code: &str) {
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains(code), "expected {code}, got: {msg}");
    }

    const VALID_DID: &str = "did:dht:zjerxoow7gsm8suaqfsc86txbreganh7chorzwwh4crbh7imbdhgy";

    #[tokio::test]
    async fn trust_create_challenge_rejects_invalid_arguments() {
        let bi = test_bi();
        let create = |subject: &str, context_id: &str| {
            trust_create_challenge_on(
                &bi,
                VALID_DID.to_owned(),
                subject.to_owned(),
                SCHEMA_URI.to_owned(),
                test_cases_json(20),
                context_id.to_owned(),
                300,
                None,
                None,
            )
        };
        assert_code(create("", "ctx").await, codes::VALID_7013);
        assert_code(create(VALID_DID, "").await, codes::VALID_7011);
    }

    #[tokio::test]
    async fn trust_respond_and_grade_without_resolver_are_ident_1033() {
        let bi = test_bi();
        assert!(crate::runtime::did_resolver(&bi).is_none());
        assert_code(
            trust_respond_to_challenge_on(
                &bi,
                VALID_DID.to_owned(),
                "{}".to_owned(),
                "[]".to_owned(),
                1,
            )
            .await,
            codes::IDENT_1033,
        );
        assert_code(
            trust_grade_response_on(&bi, VALID_DID.to_owned(), "{}".to_owned(), "{}".to_owned())
                .await,
            codes::IDENT_1033,
        );
    }

    #[cfg(feature = "testing")]
    mod challenge_live {
        use super::*;
        use scp_platform::traits::KeyCustody as _;

        /// Installs a resolver over a caller-retained in-memory DHT on `bi`.
        fn install_resolver(bi: &NapiBridgeInstance) -> Arc<scp_dht::InMemoryDhtClient> {
            let dht_client = Arc::new(scp_dht::InMemoryDhtClient::new());
            let resolver = Arc::new(scp_identity::DualLayerResolver::new(
                Arc::new(scp_identity::NoOpRelayQuerier),
                Arc::clone(&dht_client),
                Arc::new(scp_identity::DidCache::new()),
                Vec::new(),
            ));
            crate::runtime::init_did_resolver(bi, resolver, tokio::runtime::Handle::current());
            dht_client
        }

        /// A DID resolver whose every lookup announces itself on `entered`
        /// and then waits for a permit on `release`.
        struct GatedResolver {
            entered: Arc<tokio::sync::Notify>,
            release: Arc<tokio::sync::Semaphore>,
        }

        impl scp_identity::resolver::DidResolver for GatedResolver {
            fn resolve(
                &self,
                _did: &str,
            ) -> impl std::future::Future<
                Output = Result<
                    Option<scp_identity::resolver::ResolvedDidDocument>,
                    scp_identity::IdentityError,
                >,
            > + Send {
                let entered = Arc::clone(&self.entered);
                let release = Arc::clone(&self.release);
                async move {
                    entered.notify_one();
                    release.acquire().await.unwrap().forget();
                    Ok(None)
                }
            }
        }

        /// `trustVerifyAttestation` resolves the issuer's key on the blocking
        /// pool: while one call waits on a DID lookup, the single runtime
        /// thread that awaits it still completes a second call. An export
        /// that resolved on the calling thread would block that thread inside
        /// the lookup and never reach the second call.
        #[test]
        fn a_pending_key_resolution_leaves_the_calling_thread_free() {
            let release = Arc::new(tokio::sync::Semaphore::new(0));
            let gate = Arc::clone(&release);
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            let caller = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async move {
                    let scp = crate::scp::Scp::new_in_memory_for_test();
                    // An issuer this instance does not host, so its key comes
                    // only from the resolver.
                    let issuer = scp_did::did_dht_from_public_key(
                        &ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
                            .verifying_key()
                            .to_bytes(),
                    );
                    let entered = Arc::new(tokio::sync::Notify::new());
                    crate::runtime::init_did_resolver(
                        &scp.inner,
                        Arc::new(GatedResolver {
                            entered: Arc::clone(&entered),
                            release: Arc::clone(&gate),
                        }),
                        tokio::runtime::Handle::current(),
                    );
                    let attestation = scp_core::trust::Attestation {
                        id: "att-pool".to_owned(),
                        attestation_type: scp_core::trust::AttestationType::Endorsement,
                        issuer: issuer.clone(),
                        subject: "did:dht:zsubject".into(),
                        claim: serde_json::json!({"skill": "rust"}),
                        evidence: None,
                        issued_at: 1000,
                        expires_at: Some(u64::MAX),
                        renewal_interval: None,
                        revocation_status: scp_core::trust::RevocationStatus::Active,
                        signature: vec![0u8; 64],
                        renewed_at: None,
                    };
                    let first = scp.trust_verify_attestation(
                        "ctx-pool".to_owned(),
                        serde_json::to_string(&attestation).unwrap(),
                    );
                    tokio::pin!(first);
                    tokio::select! {
                        biased;
                        early = &mut first => unreachable!("the lookup is gated: {early:?}"),
                        () = entered.notified() => {}
                    }
                    // The first call is parked in the lookup; a second call on
                    // this same thread still runs to completion.
                    let second = scp
                        .trust_verify_attestation("ctx-pool".to_owned(), "not json".to_owned())
                        .await;
                    assert!(second.is_err(), "malformed JSON is refused");
                    done_tx.send(()).unwrap();
                    gate.add_permits(1);
                    // The issuer is not found: the attestation is rejected,
                    // not verified.
                    let verdict = first.await.unwrap();
                    assert!(!verdict.valid, "{verdict:?}");
                });
            });
            let freed = done_rx.recv_timeout(std::time::Duration::from_secs(30));
            release.add_permits(1);
            assert!(
                freed.is_ok(),
                "the second call never ran: the first blocked the calling thread"
            );
            caller.join().unwrap();
        }

        /// Publishes `who`'s DID document into `dht_client`, signed by its
        /// identity key.
        async fn publish(
            who: &crate::identity::NapiIdentity,
            dht_client: &Arc<scp_dht::InMemoryDhtClient>,
        ) {
            use scp_dht::DhtClient as _;
            let inner = &who.inner;
            let identity = inner.scp_identity.as_ref().unwrap();
            let doc_json = inner.document.as_ref().unwrap().to_json().unwrap();
            let custody = inner.custody.as_ref().unwrap();
            let public_key = scp_identity::extract_public_key(&identity.did).unwrap();
            let signable = scp_dht::bep44_signable(doc_json.as_bytes(), 1);
            let signature: [u8; 64] = custody
                .sign(&identity.identity_key, &signable)
                .await
                .unwrap()
                .into_bytes()
                .try_into()
                .unwrap();
            dht_client
                .publish(&public_key, &signature, doc_json.as_bytes(), 1)
                .await
                .unwrap();
        }

        async fn identity(scp: &crate::scp::Scp) -> crate::identity::NapiIdentity {
            scp.identity_create("in_memory".to_owned(), None)
                .await
                .unwrap()
        }

        /// Creates a challenge for `SCHEMA_URI` from `verifier` to `subject`
        /// in `context_id`, with `n` cases.
        async fn create(
            scp: &crate::scp::Scp,
            verifier: &str,
            subject: &str,
            context_id: &str,
            n: usize,
        ) -> napi::Result<NapiChallengeRequest> {
            trust_create_challenge_on(
                &scp.inner,
                verifier.to_owned(),
                subject.to_owned(),
                SCHEMA_URI.to_owned(),
                test_cases_json(n),
                context_id.to_owned(),
                300,
                None,
                None,
            )
            .await
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn trust_create_challenge_below_minimum_is_valid_7039() {
            let scp = crate::scp::Scp::new_in_memory_for_test();
            let v = identity(&scp).await;
            // The challenger ledger lives on the supervisor a context attaches.
            context_with(&scp, &v, serde_json::json!([])).await.unwrap();
            assert_code(
                create(&scp, &v.inner.did, VALID_DID, "ctx", 19).await,
                codes::VALID_7039,
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn trust_create_challenge_rejects_malformed_test_cases_json() {
            let scp = crate::scp::Scp::new_in_memory_for_test();
            let v = identity(&scp).await;
            // The challenger ledger lives on the supervisor a context attaches.
            context_with(&scp, &v, serde_json::json!([])).await.unwrap();
            let result = trust_create_challenge_on(
                &scp.inner,
                v.inner.did.clone(),
                VALID_DID.to_owned(),
                SCHEMA_URI.to_owned(),
                r#"{"not":"an array"}"#.to_owned(),
                "ctx".to_owned(),
                300,
                None,
                None,
            )
            .await;
            assert_code(result, codes::VALID_7002);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn trust_create_challenge_destroyed_key_is_crypto_4006() {
            let scp = crate::scp::Scp::new_in_memory_for_test();
            let v = identity(&scp).await;
            // The challenger ledger lives on the supervisor a context attaches.
            context_with(&scp, &v, serde_json::json!([])).await.unwrap();
            let identity = v.inner.scp_identity.as_ref().unwrap();
            v.inner
                .custody
                .as_ref()
                .unwrap()
                .destroy_key(&identity.active_signing_key)
                .await
                .unwrap();
            assert_code(
                create(&scp, &v.inner.did, VALID_DID, "ctx", 20).await,
                codes::CRYPTO_4006,
            );
        }

        /// A verifier, a subject, both published to the instance resolver,
        /// and a context created by the verifier that requires `SCHEMA_URI`
        /// verified by it.
        struct Graded {
            scp: crate::scp::Scp,
            dht: Arc<scp_dht::InMemoryDhtClient>,
            verifier: crate::identity::NapiIdentity,
            subject: crate::identity::NapiIdentity,
            context_id: String,
        }

        /// Creates a context through the bridge that requires `SCHEMA_URI`
        /// verified by `verifier`.
        async fn requiring_context(
            scp: &crate::scp::Scp,
            verifier: &crate::identity::NapiIdentity,
        ) -> String {
            context_with(
                scp,
                verifier,
                serde_json::json!([{
                    "capability": SCHEMA_URI,
                    "verification_level": "ChallengeVerified",
                    "trusted_verifiers": [verifier.inner.did],
                }]),
            )
            .await
            .unwrap()
        }

        async fn graded_setup() -> Graded {
            let scp = crate::scp::Scp::new_in_memory_for_test();
            let dht = install_resolver(&scp.inner);
            let verifier = identity(&scp).await;
            let subject = identity(&scp).await;
            publish(&verifier, &dht).await;
            publish(&subject, &dht).await;
            let context_id = requiring_context(&scp, &verifier).await;
            Graded {
                scp,
                dht,
                verifier,
                subject,
                context_id,
            }
        }

        impl Graded {
            /// Runs create, respond and grade through the bridge with every
            /// answer correct, and returns the grade result.
            async fn grade(&self) -> NapiGradeResult {
                let created = create(
                    &self.scp,
                    &self.verifier.inner.did,
                    &self.subject.inner.did,
                    &self.context_id,
                    20,
                )
                .await
                .unwrap();
                assert_eq!(created.challenge_id.len(), 64);
                assert_eq!(created.challenge_id, created.challenge_id.to_lowercase());
                // The window is open strictly after `created_at` (spec 07
                // §7.3.4), and the bridge reads the wall clock.
                let created_at = serde_json::from_str::<serde_json::Value>(&created.request_json)
                    .unwrap()["created_at"]
                    .as_u64()
                    .unwrap();
                while std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    <= created_at
                {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                let outputs: Vec<scp_core::trust::TestOutput> = (0..20)
                    .map(|i| scp_core::trust::TestOutput {
                        test_id: format!("t{i}"),
                        output: serde_json::json!({ "ok": true }),
                    })
                    .collect();
                let response_json = trust_respond_to_challenge_on(
                    &self.scp.inner,
                    self.subject.inner.did.clone(),
                    created.request_json.clone(),
                    serde_json::to_string(&outputs).unwrap(),
                    1,
                )
                .await
                .unwrap();
                trust_grade_response_on(
                    &self.scp.inner,
                    self.verifier.inner.did.clone(),
                    created.request_json,
                    response_json,
                )
                .await
                .unwrap()
            }

            /// The admission check of `subject` in `context_id` with
            /// `records_json` and no self-attested capabilities.
            async fn admit(
                &self,
                subject: &str,
                context_id: &str,
                records_json: String,
            ) -> napi::Result<()> {
                check_capability_requirements_on(
                    &self.scp.inner,
                    context_id.to_owned(),
                    subject.to_owned(),
                    "[]".to_owned(),
                    records_json,
                )
                .await
            }
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn trust_grade_response_rejects_malformed_json() {
            let g = graded_setup().await;
            let created = create(
                &g.scp,
                &g.verifier.inner.did,
                &g.subject.inner.did,
                &g.context_id,
                20,
            )
            .await
            .unwrap();
            for (request, response) in [
                ("bad".to_owned(), "bad".to_owned()),
                (created.request_json, "bad".to_owned()),
            ] {
                assert_code(
                    trust_grade_response_on(
                        &g.scp.inner,
                        g.verifier.inner.did.clone(),
                        request,
                        response,
                    )
                    .await,
                    codes::VALID_7002,
                );
            }
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn trust_create_respond_grade_round_trip_with_production_resolver() {
            let g = graded_setup().await;
            let v_id = g.verifier.inner.scp_identity.as_ref().unwrap();
            let s_id = g.subject.inner.scp_identity.as_ref().unwrap();
            // `#0` and `#active` differ, so only an `#active` lookup verifies.
            assert_ne!(v_id.identity_key, v_id.active_signing_key);
            assert_ne!(s_id.identity_key, s_id.active_signing_key);

            let graded = g.grade().await;
            assert_eq!(graded.trust_store_error, None);
            let reasons: Vec<scp_core::trust::CaseResult> =
                serde_json::from_str(&graded.reasons_json).unwrap();
            assert_eq!(reasons.len(), 20);
            let record: scp_core::trust::ChallengeVerification =
                serde_json::from_str(&graded.record_json).unwrap();
            assert!(record.passed, "{record:?}");
            assert_eq!((record.attempt, record.pass_count), (1, 20));
            assert_eq!(record.context_id, g.context_id);

            let resolver = Arc::clone(crate::runtime::did_resolver(&g.scp.inner).unwrap());
            let (subject, context_id) = (g.subject.inner.did.clone(), g.context_id.clone());
            let verified = tokio::task::spawn_blocking(move || {
                let check = |resolver: &dyn scp_core::trust::attestation::ActiveKeyResolver| {
                    scp_core::trust::verify_challenge_verification(
                        &record,
                        resolver,
                        &scp_core::trust::ProtocolOnlyDefinitions,
                        &context_id,
                        &subject,
                        &scp_clock::SystemClock,
                    )
                };
                // Negative: the `#0` key does not verify the record.
                (
                    check(resolver.as_ref()),
                    check(&scp_core::trust::IdentityDidPublicKeyResolver),
                )
            })
            .await
            .unwrap();
            verified.0.unwrap();
            assert!(
                matches!(
                    verified.1,
                    Err(scp_core::trust::TrustError::ChallengeVerificationSignatureInvalid { .. })
                ),
                "{:?}",
                verified.1
            );

            // The context's governed requirement admits the subject with the
            // record, and refuses it without one.
            g.admit(
                &g.subject.inner.did,
                &g.context_id,
                format!("[{}]", graded.record_json),
            )
            .await
            .unwrap();
            assert_code(
                g.admit(&g.subject.inner.did, &g.context_id, "[]".to_owned())
                    .await,
                codes::VALID_7076,
            );
        }

        /// Which key re-signs a graded record.
        enum CvSigner {
            /// The verifier's self-certifying identity key `#0`, through its
            /// custody.
            IdentityKey,
            /// A key unrelated to the verifier's DID.
            Unrelated,
        }

        /// A record signed by the verifier's `#active` key, which differs from
        /// `#0`, is admitted through the instance resolver; the same record
        /// re-signed by an unrelated key or by `#0` is dropped.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn check_capability_requirements_admits_only_active_key_records() {
            let g = graded_setup().await;
            let graded = g.grade().await;
            g.admit(
                &g.subject.inner.did,
                &g.context_id,
                format!("[{}]", graded.record_json),
            )
            .await
            .unwrap();
            let v_id = g.verifier.inner.scp_identity.as_ref().unwrap();
            let custody = g.verifier.inner.custody.as_ref().unwrap();
            for signer in [CvSigner::IdentityKey, CvSigner::Unrelated] {
                let mut record: scp_core::trust::ChallengeVerification =
                    serde_json::from_str(&graded.record_json).unwrap();
                let digest =
                    scp_core::trust::challenge_verification_signing_digest(&record).unwrap();
                record.verifier_signature = match signer {
                    CvSigner::IdentityKey => custody
                        .sign(&v_id.identity_key, &digest)
                        .await
                        .unwrap()
                        .into_bytes(),
                    CvSigner::Unrelated => {
                        use ed25519_dalek::Signer;
                        ed25519_dalek::SigningKey::from_bytes(&[42; 32])
                            .sign(&digest)
                            .to_bytes()
                            .to_vec()
                    }
                };
                assert_code(
                    g.admit(
                        &g.subject.inner.did,
                        &g.context_id,
                        serde_json::to_string(&[record]).unwrap(),
                    )
                    .await,
                    codes::VALID_7076,
                );
            }
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn check_capability_requirements_binds_subject_and_context() {
            let g = graded_setup().await;
            let records = format!("[{}]", g.grade().await.record_json);
            // Control: the record admits its own subject in its own context.
            g.admit(&g.subject.inner.did, &g.context_id, records.clone())
                .await
                .unwrap();
            // Cross-subject replay.
            assert_code(
                g.admit(VALID_DID, &g.context_id, records.clone()).await,
                codes::VALID_7076,
            );
            // Cross-context replay, into a context with the same requirement.
            let other = requiring_context(&g.scp, &g.verifier).await;
            assert_ne!(other, g.context_id);
            assert_code(
                g.admit(&g.subject.inner.did, &other, records).await,
                codes::VALID_7076,
            );
            drop(g.dht);
        }

        /// Creates a context through the bridge, created by `creator`, whose
        /// governance holds `requirements`.
        async fn context_with(
            scp: &crate::scp::Scp,
            creator: &crate::identity::NapiIdentity,
            requirements: serde_json::Value,
        ) -> napi::Result<String> {
            let params = serde_json::json!({
                "ceiling": ["messages:read", "messages:write"],
                "memoryScope": "ephemeral",
                "governance": "single_admin",
                "capabilityRequirements": requirements.to_string(),
            })
            .to_string();
            crate::context::context_create_on(&scp.inner, creator, params)
                .await
                .map(|handle| handle.context_id())
        }

        fn self_attested() -> serde_json::Value {
            serde_json::json!([{
                "capability": SCHEMA_URI,
                "verification_level": "SelfAttested",
            }])
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn context_create_refuses_malformed_capability_requirements() {
            let scp = crate::scp::Scp::new_in_memory_for_test();
            let creator = identity(&scp).await;
            for bad in [
                serde_json::json!("not an array"),
                serde_json::json!([{ "capability": SCHEMA_URI }]),
            ] {
                assert!(context_with(&scp, &creator, bad).await.is_err());
            }
            // The bridge takes the requirements only as the JSON string the
            // SDK encodes; a raw array is refused, not normalized.
            let params = serde_json::json!({
                "ceiling": ["messages:read", "messages:write"],
                "memoryScope": "ephemeral",
                "governance": "single_admin",
                "capabilityRequirements": self_attested(),
            })
            .to_string();
            let msg = crate::context::context_create_on(&scp.inner, &creator, params)
                .await
                .map(|handle| handle.context_id())
                .unwrap_err()
                .to_string();
            assert!(
                msg.contains(&format!("[{}]", codes::VALID_7000)),
                "expected {}, got: {msg}",
                codes::VALID_7000
            );
        }

        /// A requirement list that breaks a spec 07 §7.3.4.4 rule refuses
        /// context creation and a `ModifyCapabilityRequirements` proposal
        /// with the rule's own code; a valid proposal sets the list
        /// admission reads.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn capability_requirement_refusals_keep_their_codes() {
            use scp_core::trust::challenge::MAX_CAPABILITY_REQUIREMENTS_PER_CONTEXT;
            fn assert_validation<T: std::fmt::Debug>(result: napi::Result<T>, code: &str) {
                let msg = result.unwrap_err().to_string();
                assert!(
                    msg.contains(&format!("[{code}] validation error")),
                    "expected a {code} validation error, got: {msg}"
                );
            }
            let scp = crate::scp::Scp::new_in_memory_for_test();
            let creator = identity(&scp).await;
            let requirement = |verifiers: &[&str]| {
                serde_json::json!({
                    "capability": SCHEMA_URI,
                    "verification_level": "ChallengeVerified",
                    "trusted_verifiers": verifiers,
                })
            };
            let no_verifier = serde_json::json!([requirement(&[])]);
            let too_many = serde_json::Value::from(vec![
                requirement(&[creator.inner.did.as_str()]);
                MAX_CAPABILITY_REQUIREMENTS_PER_CONTEXT + 1
            ]);
            assert_validation(
                context_with(&scp, &creator, no_verifier.clone()).await,
                codes::VALID_7150,
            );
            assert_validation(
                context_with(&scp, &creator, too_many.clone()).await,
                codes::VALID_7148,
            );

            let params = serde_json::json!({
                "ceiling": ["messages:read", "messages:write", "governance:propose"],
                "memoryScope": "ephemeral",
                "governance": "single_admin",
            })
            .to_string();
            let handle = crate::context::context_create_on(&scp.inner, &creator, params)
                .await
                .unwrap();
            let modify = |requirements: serde_json::Value| {
                scp.context_governance_modify_capability_requirements(
                    &handle,
                    requirements.to_string(),
                    creator.inner.did.clone(),
                )
            };
            assert_validation(modify(no_verifier).await, codes::VALID_7150);
            assert_validation(modify(too_many).await, codes::VALID_7148);
            let admit = || {
                check_capability_requirements_on(
                    &scp.inner,
                    handle.context_id(),
                    creator.inner.did.clone(),
                    "[]".to_owned(),
                    "[]".to_owned(),
                )
            };
            admit().await.unwrap();
            modify(serde_json::json!([requirement(&[creator
                .inner
                .did
                .as_str()])]))
            .await
            .unwrap();
            assert_code(admit().await, codes::VALID_7076);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn check_capability_requirements_rejects_malformed_inputs_and_unknown_context() {
            let scp = crate::scp::Scp::new_in_memory_for_test();
            let creator = identity(&scp).await;
            let ctx = context_with(&scp, &creator, self_attested()).await.unwrap();
            let check = |ctx: &str, caps: &str, records: &str| {
                check_capability_requirements_on(
                    &scp.inner,
                    ctx.to_owned(),
                    VALID_DID.to_owned(),
                    caps.to_owned(),
                    records.to_owned(),
                )
            };
            assert_code(check(&ctx, "not json", "[]").await, codes::VALID_7074);
            assert_code(check(&ctx, "[]", "not json").await, codes::VALID_7075);
            assert_code(
                check("ctx-never-created", "[]", "[]").await,
                codes::CTX_2001,
            );
        }

        /// The requirement comes from the context's governance: with none,
        /// empty inputs pass; with a `SelfAttested` one, the declared
        /// capability decides.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn check_capability_requirements_reads_the_context_requirement() {
            let scp = crate::scp::Scp::new_in_memory_for_test();
            let creator = identity(&scp).await;
            let open = context_with(&scp, &creator, serde_json::json!([]))
                .await
                .unwrap();
            let gated = context_with(&scp, &creator, self_attested()).await.unwrap();
            let check = |ctx: &str, caps: String| {
                check_capability_requirements_on(
                    &scp.inner,
                    ctx.to_owned(),
                    VALID_DID.to_owned(),
                    caps,
                    "[]".to_owned(),
                )
            };
            check(&open, "[]".to_owned()).await.unwrap();
            check(&gated, format!(r#"["{SCHEMA_URI}"]"#)).await.unwrap();
            assert_code(check(&gated, "[]".to_owned()).await, codes::VALID_7076);
        }
    }

    #[test]
    fn trust_verify_attestation_rejects_invalid_json() {
        let bi = test_bi();
        let result = trust_verify_attestation_on(
            &scp_ffi_common::BlockingResolutionScope::for_tests(),
            &bi,
            "ctx-1".to_owned(),
            "not json".to_owned(),
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7012),
            "expected {}, got: {msg}",
            codes::VALID_7012
        );
    }

    #[test]
    fn verify_participation_requirements_rejects_invalid_profile_json() {
        // Malformed JSON in the PROFILE position (now the 3rd arg).
        let bi = test_bi();
        let result = verify_participation_requirements_on(
            &bi,
            "did:key:alice".to_owned(),
            "[]".to_owned(),
            "not json".to_owned(),
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7030),
            "expected {}, got: {msg}",
            codes::VALID_7030
        );
    }

    #[test]
    fn verify_participation_requirements_rejects_invalid_requirements_json() {
        // Malformed JSON in the REQUIREMENTS position (now the 2nd arg).
        let bi = test_bi();
        let result = verify_participation_requirements_on(
            &bi,
            "did:key:alice".to_owned(),
            "not json".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7031),
            "expected {}, got: {msg}",
            codes::VALID_7031
        );
    }

    #[test]
    fn verify_participation_requirements_unmet_requirement_fails_with_admission_code() {
        // A requirement with no satisfying profiles fails the admission check
        // itself (not JSON parsing), which carries its own per-case code.
        let bi = test_bi();
        let requirements = r#"[{"fact":"ParticipationDuration","threshold":{"AtLeast":1},"max_age_secs":3600,"min_contexts":0}]"#;
        let result = verify_participation_requirements_on(
            &bi,
            "did:key:alice".to_owned(),
            requirements.to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7032),
            "expected {}, got: {msg}",
            codes::VALID_7032
        );
    }

    #[test]
    fn verify_participation_requirements_empty_inputs_succeeds() {
        let bi = test_bi();
        let result = verify_participation_requirements_on(
            &bi,
            "did:key:alice".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn verify_participation_requirements_rejects_empty_subject() {
        let bi = test_bi();
        let result = verify_participation_requirements_on(
            &bi,
            String::new(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7000),
            "expected {}, got: {msg}",
            codes::VALID_7000
        );
    }

    #[test]
    fn verify_participation_requirements_rejects_malformed_subject() {
        // Parity with the PyO3 reference bridge: `expected_subject` gets full
        // DID-format validation, not just a non-empty check.
        let bi = test_bi();
        let result = verify_participation_requirements_on(
            &bi,
            "not-a-did".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
    }

    // -- check_capability_requirements (§7.3.4.4, SCP-ACR-008) --

    #[tokio::test]
    async fn check_capability_requirements_rejects_empty_and_malformed_subject() {
        let bi = test_bi();
        for subject in ["", "not-a-did"] {
            assert_code(
                check_capability_requirements_on(
                    &bi,
                    "ctx-1".to_owned(),
                    subject.to_owned(),
                    "[]".to_owned(),
                    "[]".to_owned(),
                )
                .await,
                codes::VALID_7000,
            );
        }
    }

    #[tokio::test]
    async fn check_capability_requirements_rejects_empty_context_id() {
        let bi = test_bi();
        assert_code(
            check_capability_requirements_on(
                &bi,
                String::new(),
                VALID_DID.to_owned(),
                "[]".to_owned(),
                "[]".to_owned(),
            )
            .await,
            codes::VALID_7011,
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_empty_context() {
        let bi = test_bi();
        let result = aggregate_trust_input_on(
            &scp_ffi_common::BlockingResolutionScope::for_tests(),
            &bi,
            String::new(),
            "did:key:test".to_owned(),
            "[]".to_owned(),
            "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]".to_owned(),
            "[]".to_owned(),
            "{}".to_owned(),
            "{}".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7040),
            "expected {}, got: {msg}",
            codes::VALID_7040
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_events_json() {
        let bi = test_bi();
        let result = aggregate_trust_input_on(
            &scp_ffi_common::BlockingResolutionScope::for_tests(),
            &bi,
            "ctx-1".to_owned(),
            "did:key:test".to_owned(),
            "not json".to_owned(),
            "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]".to_owned(),
            "[]".to_owned(),
            "{}".to_owned(),
            "{}".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7042),
            "expected {}, got: {msg}",
            codes::VALID_7042
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_empty_did() {
        let bi = test_bi();
        let result = aggregate_trust_input_on(
            &scp_ffi_common::BlockingResolutionScope::for_tests(),
            &bi,
            "ctx-1".to_owned(),
            String::new(),
            "[]".to_owned(),
            "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]".to_owned(),
            "[]".to_owned(),
            "{}".to_owned(),
            "{}".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7041),
            "expected {}, got: {msg}",
            codes::VALID_7041
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_merkle_root_json() {
        let bi = test_bi();
        let result = aggregate_trust_input_on(
            &scp_ffi_common::BlockingResolutionScope::for_tests(),
            &bi,
            "ctx-1".to_owned(),
            "did:key:test".to_owned(),
            "[]".to_owned(),
            "not json".to_owned(),
            "[]".to_owned(),
            "{}".to_owned(),
            "{}".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7043),
            "expected {}, got: {msg}",
            codes::VALID_7043
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_wrong_length_merkle_root() {
        let bi = test_bi();
        let result = aggregate_trust_input_on(
            &scp_ffi_common::BlockingResolutionScope::for_tests(),
            &bi,
            "ctx-1".to_owned(),
            "did:key:test".to_owned(),
            "[]".to_owned(),
            "[0,0,0]".to_owned(),
            "[]".to_owned(),
            "{}".to_owned(),
            "{}".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7044),
            "expected {}, got: {msg}",
            codes::VALID_7044
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_consequence_rules_json() {
        let bi = test_bi();
        let result = aggregate_trust_input_on(
            &scp_ffi_common::BlockingResolutionScope::for_tests(),
            &bi,
            "ctx-1".to_owned(),
            "did:key:test".to_owned(),
            "[]".to_owned(),
            "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]".to_owned(),
            "not json".to_owned(),
            "{}".to_owned(),
            "{}".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7045),
            "expected {}, got: {msg}",
            codes::VALID_7045
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_threshold_requirements_json() {
        let bi = test_bi();
        let result = aggregate_trust_input_on(
            &scp_ffi_common::BlockingResolutionScope::for_tests(),
            &bi,
            "ctx-1".to_owned(),
            "did:key:test".to_owned(),
            "[]".to_owned(),
            "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]".to_owned(),
            "[]".to_owned(),
            "not json".to_owned(),
            "{}".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7046),
            "expected {}, got: {msg}",
            codes::VALID_7046
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_attestor_sets_json() {
        let bi = test_bi();
        let result = aggregate_trust_input_on(
            &scp_ffi_common::BlockingResolutionScope::for_tests(),
            &bi,
            "ctx-1".to_owned(),
            "did:key:test".to_owned(),
            "[]".to_owned(),
            "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]".to_owned(),
            "[]".to_owned(),
            "{}".to_owned(),
            "not json".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7047),
            "expected {}, got: {msg}",
            codes::VALID_7047
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_cached_attestations_json() {
        let bi = test_bi();
        let result = aggregate_trust_input_on(
            &scp_ffi_common::BlockingResolutionScope::for_tests(),
            &bi,
            "ctx-1".to_owned(),
            "did:key:test".to_owned(),
            "[]".to_owned(),
            "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]".to_owned(),
            "[]".to_owned(),
            "{}".to_owned(),
            "{}".to_owned(),
            "not json".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7048),
            "expected {}, got: {msg}",
            codes::VALID_7048
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_challenge_results_json() {
        let bi = test_bi();
        let result = aggregate_trust_input_on(
            &scp_ffi_common::BlockingResolutionScope::for_tests(),
            &bi,
            "ctx-1".to_owned(),
            "did:key:test".to_owned(),
            "[]".to_owned(),
            "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]".to_owned(),
            "[]".to_owned(),
            "{}".to_owned(),
            "{}".to_owned(),
            "[]".to_owned(),
            "not json".to_owned(),
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7049),
            "expected {}, got: {msg}",
            codes::VALID_7049
        );
    }

    #[test]
    fn participation_record_rejects_empty_context() {
        let bi = test_bi();
        let result = participation_record_on(
            &scp_ffi_common::BlockingResolutionScope::for_tests(),
            &bi,
            String::new(),
            "did:key:test".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn participation_record_rejects_empty_did() {
        let bi = test_bi();
        let result = participation_record_on(
            &scp_ffi_common::BlockingResolutionScope::for_tests(),
            &bi,
            "ctx-1".to_owned(),
            String::new(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn participation_record_rejects_invalid_attestations_json() {
        let bi = test_bi();
        let result = participation_record_on(
            &scp_ffi_common::BlockingResolutionScope::for_tests(),
            &bi,
            "ctx-1".to_owned(),
            "did:key:test".to_owned(),
            "not json".to_owned(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn participation_record_rejects_malformed_did() {
        // Format validation (not just non-empty) matches the PyO3 reference
        // bridge: a non-empty but malformed DID is rejected.
        let bi = test_bi();
        let result = participation_record_on(
            &scp_ffi_common::BlockingResolutionScope::for_tests(),
            &bi,
            "ctx-1".to_owned(),
            "not-a-did".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
    }

    /// The typed `NapiParticipationRecord` surfaces every flattened fact from
    /// the shared `ParticipationFacts` projection (i64-widened) with identical
    /// values.
    #[test]
    fn participation_record_view_exposes_all_facts() {
        let facts = scp_core::trust::ParticipationFacts {
            subject_did: "did:key:bob".into(),
            participation_duration_secs: 300,
            governance_actions_against: 1,
            governance_actions_by: 2,
            outlet_invocation_count: 5,
            outlet_invocation_count_anchored: false,
            context_creation_count: 1,
            role_progression_count: 3,
            attestation_count: 2,
            attestation_count_anchored: false,
            computed_at: 42,
            event_log_root: [7u8; 32],
        };
        let view = NapiParticipationRecord::from(&facts);
        assert_eq!(view.subject_did, "did:key:bob");
        assert_eq!(view.participation_duration_secs, 300);
        assert_eq!(view.governance_actions_against, 1);
        assert_eq!(view.governance_actions_by, 2);
        assert_eq!(view.outlet_invocation_count, 5);
        assert!(!view.outlet_invocation_count_anchored);
        assert_eq!(view.context_creation_count, 1);
        assert_eq!(view.role_progression_count, 3);
        assert_eq!(view.attestation_count, 2);
        assert!(!view.attestation_count_anchored);
        assert_eq!(view.computed_at, 42);
        assert_eq!(view.event_log_root, hex::encode([7u8; 32]));
    }
}
