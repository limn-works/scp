//! `PyO3` bridge functions for the SCP trust engine.
//!
//! Exposes trust engine operations to Python. Stateful operations are methods
//! on the `SCP` class; pure helpers remain as free `#[pyfunction]` exports.
//!
//! Pure helpers (no bridge state):
//!
//! - [`py_verify_participation_requirements`] — Verify participation profiles
//!   against admission requirements.
//!
//! `SCP` methods (bridge-state accessors):
//!
//! - `PyScp::trust_verify_attestation` — Verify an attestation, including
//!   this instance's revocation list for the context.
//! - `PyScp::trust_query_score` — Query participation-based trust data for a DID.
//! - `PyScp::trust_create_challenge` — Create a challenge in the verifier
//!   identity's ledger, which signs the request with its `#active` key.
//! - `PyScp::trust_respond_to_challenge` — Answer a challenge, signed by the
//!   subject identity's `#active` key.
//! - `PyScp::trust_grade_response` — Grade a response in the verifier
//!   identity's ledger and return the record it signed.
//! - `PyScp::aggregate_trust_input` — Aggregate all trust engine layers into
//!   a single [`TrustInput`](scp_core::trust::TrustInput) for agent-level
//!   evaluation.
//!
//! Migrated from flat `#[pyfunction]` exports to `#[pymethods] impl PyScp`
//! methods in Phase 4 PR 4 sub-slice E.
//!
//! The trust engine does not produce trust "scores" — it provides verifiable
//! facts (participation records, attestation verification results, challenge
//! verification results) that agents consume for their own trust evaluation
//! logic. The `composite_score` field in the query result is a normalized
//! summary for convenience, not an authoritative trust judgment.
//!
//! See ADR-017 in `.docs/adrs/phase-4.md`.

use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyDict;
use scp_ffi_common::error_codes as codes;

use crate::runtime::PyBridgeInstance;
use crate::types::encode_hex;

// ---------------------------------------------------------------------------
// Coded-error helper — cross-bridge error-code parity
// ---------------------------------------------------------------------------

/// Builds a bridge validation error carrying the specific `SCP-VALID-*` code
/// the UniFFI/NAPI bridges emit for the same logical failure case, so a
/// Python caller can branch on the same `.code` a Swift/Kotlin/TypeScript
/// caller sees (e.g. the per-case `verify_participation_requirements` codes
/// `VALID_7030`/`VALID_7031`/`VALID_7032`, or the trust-helper codes
/// `VALID_7012..=VALID_7017`).
fn coded_validation_error(message: String, code: &str) -> crate::error::ScpPyError {
    crate::error::ScpPyError::ValidationError {
        message,
        code: code.to_owned(),
    }
}

/// Runs `work` on tokio's blocking pool with the GIL released. The trust
/// operations that verify attestations or challenge records resolve each
/// signer's `#active` key (spec 09 §9.7.1), and a DID lookup blocks; it must
/// hold neither the GIL nor the calling thread.
///
/// # Errors
///
/// `work`'s own error; `CTX_2000` when the blocking task panics or is
/// cancelled; the runtime error when no runtime can drive the task.
fn on_resolution_pool<T, F>(py: Python<'_>, work: F) -> PyResult<T>
where
    F: FnOnce(&scp_ffi_common::BlockingResolutionScope) -> PyResult<T> + Send + 'static,
    T: Send + 'static,
{
    crate::actor_wait::block_on_released(py, scp_ffi_common::run_blocking_resolution(work))?
        .map_err(|e| crate::error::ScpPyError::ContextError {
            message: e.to_string(),
            code: codes::CTX_2000.to_owned(),
        })?
}

// ---------------------------------------------------------------------------
// trust_query_score — per-bridge helper used by PyScp method
// ---------------------------------------------------------------------------

/// Queries participation-based trust data for a DID within a context on the
/// given bridge instance.
fn trust_query_score_impl(
    bi: &PyBridgeInstance,
    py: Python<'_>,
    did: &str,
    context_id: &str,
) -> PyResult<Py<PyDict>> {
    // Per-argument codes match the UniFFI bridge (invalid DID → VALID_7010,
    // invalid context id → VALID_7011) so the same logical failure carries
    // the same code on every native bridge. The PyO3 boundary additionally
    // rejects malformed (non-empty) values under the same per-argument code.
    scp_ffi_common::validate::validate_did(did)
        .map_err(|e| coded_validation_error(e.message, codes::VALID_7010))?;
    scp_ffi_common::validate::validate_context_id(context_id)
        .map_err(|e| coded_validation_error(e.message, codes::VALID_7011))?;

    // Query the runtime registry for event counts. The event log stores leaf
    // hashes (Merkle tree), not full events. The runtime registry tracks
    // per-context event metadata sufficient for participation summaries.
    let (message_count, governance_count) =
        crate::runtime::query_trust_event_counts(bi, context_id, did);

    // Compute a normalized composite score. This is a convenience metric:
    // log2(1 + total_events) / 10, capped at 1.0.
    let total = message_count + governance_count;
    #[allow(clippy::cast_precision_loss)]
    let composite = (1.0 + total as f64).log10().min(1.0);

    let dict = PyDict::new(py);
    dict.set_item("message_count", message_count)?;
    dict.set_item("governance_count", governance_count)?;
    dict.set_item("composite_score", composite)?;

    Ok(dict.into())
}

// ---------------------------------------------------------------------------
// trust_verify_attestation
// ---------------------------------------------------------------------------

/// Verifies one attestation against this instance's revocation list for
/// `context_id`, on the instance's configured storage.
///
/// Returns a dict with `valid` (bool), `chain_depth` (int, 1 when valid and 0
/// otherwise), and `error` (the rejection's message, or `None` when valid). A
/// rejection is a property of the attestation; a storage fault is not, and
/// raises instead of reading as `valid: False`.
///
/// # Errors
///
/// `VALID_7011` for a malformed `context_id`, `VALID_7012` for malformed JSON,
/// `VALID_7005` when this instance has no storage provider (the verification
/// cannot read a revocation list, so it fails closed), and `VALID_7052` when
/// the revocation list cannot be read.
fn trust_verify_attestation_impl(
    bi: &Arc<PyBridgeInstance>,
    py: Python<'_>,
    context_id: &str,
    attestation_json: &str,
) -> PyResult<Py<PyDict>> {
    use crate::runtime::StorageProvider;
    use scp_ffi_common::trust_store::AttestationVerdict;

    scp_ffi_common::validate::validate_context_id(context_id)
        .map_err(|e| coded_validation_error(e.message, codes::VALID_7011))?;
    let attestation: scp_core::trust::Attestation = serde_json::from_str(attestation_json)
        .map_err(|e| {
            coded_validation_error(
                format!("failed to parse attestation JSON: {e}"),
                codes::VALID_7012,
            )
        })?;
    let handle = crate::runtime()?.handle().clone();
    let bi = Arc::clone(bi);
    let context_id = context_id.to_owned();
    // The store read and the key resolution block, so they run on the
    // blocking pool without the GIL.
    let verdict = on_resolution_pool(py, move |scope| {
        let provider = crate::runtime::get_storage(&bi).map_err(|_| {
            coded_validation_error(
                "bridge storage not initialized — attestation verification cannot read \
                 this instance's revocation list (bridge init bug)"
                    .to_owned(),
                codes::VALID_7005,
            )
        })?;
        // The issuer's current `#active` key (spec 09 §9.7.1), resolved
        // through this instance's DID resolver; an instance without one fails
        // closed.
        let resolver =
            scp_ffi_common::instance_active_key_resolver(scope, crate::runtime::did_resolver(&bi));
        match provider {
            StorageProvider::InMemoryEncrypted(storage) => run_verify_attestation(
                Arc::clone(storage),
                handle,
                resolver,
                &context_id,
                &attestation,
            ),
            StorageProvider::Sqlite(storage) => run_verify_attestation(
                Arc::clone(storage),
                handle,
                resolver,
                &context_id,
                &attestation,
            ),
        }
        .map_err(|e| coded_validation_error(e.to_string(), codes::VALID_7052).into())
    })?;

    let dict = PyDict::new(py);
    match verdict {
        AttestationVerdict::Valid => {
            dict.set_item("valid", true)?;
            dict.set_item("chain_depth", 1)?;
            dict.set_item("error", py.None())?;
        }
        AttestationVerdict::Rejected(reason) => {
            dict.set_item("valid", false)?;
            dict.set_item("chain_depth", 0)?;
            dict.set_item("error", reason.to_string())?;
        }
    }
    Ok(dict.into())
}

/// Builds a `ProtocolRepositoryTrustBridge` over the concrete encrypted backend
/// and verifies one attestation against its revocation list, with the
/// instance's `#active` key resolver and the system clock.
fn run_verify_attestation<S: scp_platform::EncryptedStorage + 'static>(
    storage: Arc<S>,
    handle: tokio::runtime::Handle,
    resolver: &dyn scp_core::trust::attestation::ActiveKeyResolver,
    context_id: &str,
    attestation: &scp_core::trust::Attestation,
) -> Result<scp_ffi_common::trust_store::AttestationVerdict, scp_core::trust::TrustError> {
    let repo = Arc::new(scp_core::store::ProtocolRepository::new(storage));
    let bridge = scp_core::trust::ProtocolRepositoryTrustBridge::new(repo, handle);
    scp_ffi_common::trust_store::verify_attestation_in_context(
        &bridge,
        context_id,
        attestation,
        resolver,
        &scp_clock::SystemClock,
    )
}

// ---------------------------------------------------------------------------
// Challenges (spec 07 §7.3.4, ADR-017)
// ---------------------------------------------------------------------------

/// Maps a shared challenge-operation failure to its bridge error: a JSON
/// argument that does not parse takes its argument's code, a protocol or
/// ledger refusal the `TrustError` mapping, a runtime failure the
/// `ContextError` mapping, an admission refusal the shared admission table,
/// and a failed blocking task `SCP-CTX-2000`.
fn challenge_op_error(e: scp_ffi_common::challenge::ChallengeOpError) -> PyErr {
    use scp_ffi_common::challenge::ChallengeOpError;
    use scp_ffi_common::error_codes::{TrustFailureClass, admission_error_code};
    match e {
        ChallengeOpError::MalformedJson { input, .. } => {
            coded_validation_error(e.to_string(), input.code()).into()
        }
        ChallengeOpError::Trust(e) => crate::error::ScpPyError::from(e).into(),
        ChallengeOpError::Context(e) => crate::error::ScpPyError::from(e).into(),
        ChallengeOpError::Admission(e) => {
            let message = format!("capability admission verification failed: {e}");
            match admission_error_code(&e) {
                (code, TrustFailureClass::Validation) => coded_validation_error(message, code),
                (code, TrustFailureClass::Identity) => crate::error::ScpPyError::IdentityError {
                    message,
                    code: code.to_owned(),
                },
            }
            .into()
        }
        ChallengeOpError::Blocking(e) => crate::error::ScpPyError::ContextError {
            message: e.to_string(),
            code: codes::CTX_2000.to_owned(),
        }
        .into(),
    }
}

/// `SCP-VALID-7013` for an invalid DID argument of a challenge operation,
/// the same code on every bridge.
fn validate_challenge_did(did: &str) -> PyResult<()> {
    scp_ffi_common::validate::validate_did(did)
        .map_err(|e| coded_validation_error(e.message, codes::VALID_7013).into())
}

/// `SCP-VALID-7011` for an invalid context id argument of a challenge
/// operation, the same code on every bridge.
fn validate_challenge_context_id(context_id: &str) -> PyResult<()> {
    scp_ffi_common::validate::validate_context_id(context_id)
        .map_err(|e| coded_validation_error(e.message, codes::VALID_7011).into())
}

/// This instance's DID resolver; with none, `operation` fails with
/// `SCP-IDENT-1033`.
fn required_did_resolver(
    bi: &PyBridgeInstance,
    operation: &str,
) -> PyResult<Arc<scp_ffi_common::IdentityBackedDidResolver>> {
    crate::runtime::did_resolver(bi).cloned().ok_or_else(|| {
        crate::error::ScpPyError::IdentityError {
            message: format!(
                "DID resolver not initialized — create an identity with identity_create \
                 before calling {operation}"
            ),
            code: codes::IDENT_1033.to_owned(),
        }
        .into()
    })
}

/// A serialized challenge-operation result, `SCP-VALID-7015` when it did not
/// serialize.
fn challenge_json(what: &str, serialized: serde_json::Result<String>) -> PyResult<String> {
    serialized.map_err(|e| {
        coded_validation_error(
            format!("failed to serialize {what}: {e}"),
            codes::VALID_7015,
        )
        .into()
    })
}

/// Reads the optional `policy` dict of `trust_create_challenge`: both
/// `max_retries` and `cooldown_secs`, as non-negative integers, and no other
/// key. Anything else is `SCP-VALID-7002`, the code of a malformed challenge
/// argument.
fn policy_pick(
    policy: Option<&Bound<'_, PyDict>>,
) -> PyResult<Option<scp_core::trust::PolicyPick>> {
    let Some(policy) = policy else {
        return Ok(None);
    };
    let malformed =
        |what: String| -> PyErr { coded_validation_error(what, codes::VALID_7002).into() };
    if policy.len() != 2 {
        return Err(malformed(
            "policy must hold exactly max_retries and cooldown_secs".to_owned(),
        ));
    }
    let field = |key: &str| -> PyResult<u32> {
        policy
            .get_item(key)?
            .ok_or_else(|| malformed(format!("policy is missing {key}")))?
            .extract::<u32>()
            .map_err(|e| {
                malformed(format!(
                    "policy {key} must be an integer in 0..=2^32-1: {e}"
                ))
            })
    };
    Ok(Some(scp_core::trust::PolicyPick {
        max_retries: field("max_retries")?,
        cooldown_secs: field("cooldown_secs")?,
    }))
}

/// The evaluator side of `CustomEval` grading on this bridge: the outlet
/// registry and host handlers of the evaluator context's bridge state.
struct PyEvaluatorInvoker<'a> {
    bi: &'a PyBridgeInstance,
    sup: &'a Arc<scp_core::context::supervisor::Supervisor>,
}

impl PyEvaluatorInvoker<'_> {
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
impl scp_ffi_common::challenge::EvaluatorInvoker for PyEvaluatorInvoker<'_> {
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

/// Implementation of `PyScp::trust_create_challenge` (spec 07 §7.3.4 step 1).
#[allow(clippy::too_many_arguments)]
fn trust_create_challenge_impl(
    bi: &PyBridgeInstance,
    py: Python<'_>,
    verifier: &str,
    subject: &str,
    capability_uri: &str,
    test_cases_json: &str,
    window_secs: u64,
    context_id: &str,
    evaluator_context_id: Option<&str>,
    policy: Option<&Bound<'_, PyDict>>,
) -> PyResult<Py<PyDict>> {
    validate_challenge_did(verifier)?;
    validate_challenge_did(subject)?;
    validate_challenge_context_id(context_id)?;
    if let Some(id) = evaluator_context_id {
        validate_challenge_context_id(id)?;
    }
    let policy = policy_pick(policy)?;
    let sup = crate::runtime::supervisor(bi)?;
    let signer = crate::context::resolve_signer(py, bi, verifier)?;
    let invoker = PyEvaluatorInvoker { bi, sup };
    let request = crate::actor_wait::block_on_released(
        py,
        scp_ffi_common::challenge::create_challenge(
            sup,
            &signer,
            scp_ffi_common::challenge::CreateChallenge {
                verifier: verifier.into(),
                subject: subject.into(),
                capability_uri: capability_uri.to_owned(),
                test_cases_json: test_cases_json.to_owned(),
                window_secs,
                context_id: context_id.to_owned(),
                policy,
                evaluator_context_id: evaluator_context_id.map(str::to_owned),
            },
            &invoker,
            &scp_core::trust::ProtocolOnlyDefinitions,
        ),
    )?
    .map_err(challenge_op_error)?;

    let dict = PyDict::new(py);
    dict.set_item("challenge_id", hex::encode(request.challenge_id))?;
    dict.set_item(
        "request_json",
        challenge_json("challenge", serde_json::to_string(&request))?,
    )?;
    Ok(dict.into())
}

/// Implementation of `PyScp::trust_respond_to_challenge` (spec 07 §7.3.4
/// step 2).
fn trust_respond_to_challenge_impl(
    bi: &PyBridgeInstance,
    py: Python<'_>,
    subject: &str,
    request_json: &str,
    outputs_json: &str,
    attempt: u32,
) -> PyResult<String> {
    validate_challenge_did(subject)?;
    let resolver = required_did_resolver(bi, "trust_respond_to_challenge")?;
    let signer = crate::context::resolve_signer(py, bi, subject)?;
    let response = crate::actor_wait::block_on_released(
        py,
        scp_ffi_common::challenge::respond_to_challenge(
            &signer,
            resolver,
            subject.to_owned(),
            request_json,
            outputs_json,
            attempt,
        ),
    )?
    .map_err(challenge_op_error)?;
    challenge_json("challenge response", serde_json::to_string(&response))
}

/// Grades one response against the protocol repository over the concrete
/// encrypted backend behind a `StorageProvider` arm.
async fn grade_with_storage<S: scp_platform::EncryptedStorage + 'static>(
    storage: Arc<S>,
    grader: &scp_ffi_common::challenge::Grader<'_, scp_ffi_common::IdentityBackedDidResolver>,
    verifier: &scp_did::DID,
    request_json: &str,
    response_json: &str,
) -> Result<scp_ffi_common::challenge::GradeResult, scp_ffi_common::challenge::ChallengeOpError> {
    let repo = Arc::new(scp_core::store::ProtocolRepository::new(storage));
    scp_ffi_common::challenge::grade_response(grader, &repo, verifier, request_json, response_json)
        .await
}

/// Implementation of `PyScp::trust_grade_response` (spec 07 §7.3.4 steps 3
/// and 4).
fn trust_grade_response_impl(
    bi: &PyBridgeInstance,
    py: Python<'_>,
    verifier: &str,
    request_json: &str,
    response_json: &str,
) -> PyResult<Py<PyDict>> {
    use crate::runtime::StorageProvider;
    validate_challenge_did(verifier)?;
    let resolver = required_did_resolver(bi, "trust_grade_response")?;
    let provider = crate::runtime::get_storage(bi).map_err(|_| {
        coded_validation_error(
            "bridge storage not initialized — a graded record cannot be stored until this \
             PyBridgeInstance has allocated its storage provider (bridge init bug)"
                .to_owned(),
            codes::VALID_7005,
        )
    })?;
    let sup = crate::runtime::supervisor(bi)?;
    let signer = crate::context::resolve_signer(py, bi, verifier)?;
    let verifier_did: scp_did::DID = verifier.into();
    let invoker = PyEvaluatorInvoker { bi, sup };
    let grading = scp_ffi_common::challenge::Grader {
        sup,
        signer: &signer,
        resolver,
        invoker: &invoker,
    };
    let graded = crate::actor_wait::block_on_released(py, async {
        match provider {
            StorageProvider::InMemoryEncrypted(storage) => {
                grade_with_storage(
                    Arc::clone(storage),
                    &grading,
                    &verifier_did,
                    request_json,
                    response_json,
                )
                .await
            }
            StorageProvider::Sqlite(storage) => {
                grade_with_storage(
                    Arc::clone(storage),
                    &grading,
                    &verifier_did,
                    request_json,
                    response_json,
                )
                .await
            }
        }
    })?
    .map_err(challenge_op_error)?;

    let dict = PyDict::new(py);
    dict.set_item(
        "record_json",
        challenge_json(
            "challenge verification",
            serde_json::to_string(&graded.record),
        )?,
    )?;
    dict.set_item(
        "reasons_json",
        challenge_json("case results", serde_json::to_string(&graded.reasons))?,
    )?;
    dict.set_item("trust_store_error", graded.trust_store_error)?;
    Ok(dict.into())
}

// ---------------------------------------------------------------------------
// verify_participation_requirements (SCP-BA-004)
// ---------------------------------------------------------------------------

/// Verifies participation profiles against admission requirements, bound to the
/// agent being admitted.
///
/// Inputs:
/// - `expected_subject`: the DID of the agent being admitted. Only profiles
///   whose signed `subject_did` equals this value contribute to any threshold,
///   freshness, or distinct-signer accounting — a victim's genuine profiles
///   cannot be replayed to admit a different agent (cross-subject replay).
/// - `requirements_json`: JSON array of `RequireParticipation` objects.
/// - `profile_json`: JSON array of `ParticipationProfile` objects.
///
/// Uses the current system time for freshness checks. Returns `Ok(())` on
/// success — success is indicated by returning without exception. Raises
/// `ScpError` with a diagnostic message if any requirement fails or if the JSON
/// is malformed.
///
/// See §7.3.2.1.
///
/// # Errors
///
/// Returns `ValidationError` with a per-case code matching the UniFFI/NAPI
/// bridges: `VALID_7000` for an invalid `expected_subject` DID, `VALID_7031`
/// for malformed requirements JSON, `VALID_7030` for malformed profiles JSON,
/// and `VALID_7032` if participation admission verification fails (with the
/// specific failure reason from `ParticipationAdmissionError`).
#[pyfunction]
#[pyo3(name = "verify_participation_requirements")]
pub fn py_verify_participation_requirements(
    expected_subject: &str,
    requirements_json: &str,
    profile_json: &str,
) -> PyResult<()> {
    // VALID_7000 matches the UniFFI/NAPI bridges, which route this same
    // check through the shared `scp_ffi_common::validate::ValidationError`
    // conversion (generic validation code).
    scp_ffi_common::validate::validate_did(expected_subject)
        .map_err(|e| coded_validation_error(e.message, codes::VALID_7000))?;

    let requirements: Vec<scp_core::trust::RequireParticipation> =
        serde_json::from_str(requirements_json).map_err(|e| {
            coded_validation_error(
                format!("failed to parse participation requirements JSON: {e}"),
                codes::VALID_7031,
            )
        })?;

    let profiles: Vec<scp_core::trust::ParticipationProfile> = serde_json::from_str(profile_json)
        .map_err(|e| {
        coded_validation_error(
            format!("failed to parse participation profiles JSON: {e}"),
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
        expected_subject,
        &requirements,
        &profiles,
    )
    .map_err(|e| {
        // VALID_7032 mirrors the UniFFI bridge's code for a failed
        // participation admission check, so every native bridge surfaces the
        // identical code for the same logical failure.
        coded_validation_error(
            format!("participation admission verification failed: {e}"),
            codes::VALID_7032,
        )
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// aggregate_trust_input (§7.3)
// ---------------------------------------------------------------------------

/// Aggregates all trust engine layers into a single `TrustInput` for
/// agent-level evaluation.
///
/// Accepts all inputs as JSON strings and returns the aggregated `TrustInput`
/// as a JSON string. Uses the `BridgeInstance` storage provider for persistent
/// trust data when initialized (trust data survives across calls and restarts);
/// falls back to an ephemeral in-memory store otherwise.
///
/// # Errors
///
/// Returns `ScpError` if any JSON input is malformed or if aggregation fails.
///
/// See ADR-017 acceptance criterion 9, spec §7.3.
#[allow(clippy::too_many_arguments)]
fn aggregate_trust_input_impl(
    bi: &Arc<PyBridgeInstance>,
    py: Python<'_>,
    context_id: &str,
    subject_did: &str,
    events_json: &str,
    merkle_root_json: &str,
    consequence_rules_json: &str,
    threshold_requirements_json: &str,
    attestor_sets_json: &str,
    cached_attestations_json: &str,
    challenge_results_json: &str,
) -> PyResult<String> {
    // Per-argument codes match the UniFFI bridge's `aggregate_trust_input`
    // (context id → VALID_7040, subject DID → VALID_7041, then one code per
    // JSON input, VALID_7042..=VALID_7049) so the same logical failure
    // carries the same code on every native bridge. The PyO3 boundary
    // additionally rejects malformed (non-empty) ids under the same
    // per-argument code.
    scp_ffi_common::validate::validate_context_id(context_id)
        .map_err(|e| coded_validation_error(e.message, codes::VALID_7040))?;
    scp_ffi_common::validate::validate_did(subject_did)
        .map_err(|e| coded_validation_error(e.message, codes::VALID_7041))?;

    // Parse all JSON inputs.
    let events: Vec<scp_event_log::Event> = serde_json::from_str(events_json).map_err(|e| {
        coded_validation_error(
            format!("failed to parse events JSON: {e}"),
            codes::VALID_7042,
        )
    })?;

    let merkle_root_vec: Vec<u8> = serde_json::from_str(merkle_root_json).map_err(|e| {
        coded_validation_error(
            format!("failed to parse merkle_root JSON: {e}"),
            codes::VALID_7043,
        )
    })?;
    let merkle_root: [u8; 32] = merkle_root_vec.try_into().map_err(|v: Vec<u8>| {
        coded_validation_error(
            format!("merkle_root must be exactly 32 bytes, got {}", v.len()),
            codes::VALID_7044,
        )
    })?;

    let consequence_rules: Vec<scp_core::trust::ConsequenceRule> =
        serde_json::from_str(consequence_rules_json).map_err(|e| {
            coded_validation_error(
                format!("failed to parse consequence_rules JSON: {e}"),
                codes::VALID_7045,
            )
        })?;

    let threshold_requirements: std::collections::HashMap<
        scp_core::trust::AttestationType,
        scp_core::trust::ThresholdRequirement,
    > = serde_json::from_str(threshold_requirements_json).map_err(|e| {
        coded_validation_error(
            format!("failed to parse threshold_requirements JSON: {e}"),
            codes::VALID_7046,
        )
    })?;

    let attestor_sets: std::collections::HashMap<
        scp_core::trust::AttestationType,
        Vec<scp_core::trust::AttestorInfo>,
    > = serde_json::from_str(attestor_sets_json).map_err(|e| {
        coded_validation_error(
            format!("failed to parse attestor_sets JSON: {e}"),
            codes::VALID_7047,
        )
    })?;

    let cached_attestations: Vec<scp_core::trust::aggregate::CachedAttestation> =
        serde_json::from_str(cached_attestations_json).map_err(|e| {
            coded_validation_error(
                format!("failed to parse cached_attestations JSON: {e}"),
                codes::VALID_7048,
            )
        })?;

    let challenge_results: Vec<scp_core::trust::ChallengeVerification> =
        serde_json::from_str(challenge_results_json).map_err(|e| {
            coded_validation_error(
                format!("failed to parse challenge_results JSON: {e}"),
                codes::VALID_7049,
            )
        })?;

    let bi = Arc::clone(bi);
    let (context_id, subject_did) = (context_id.to_owned(), subject_did.to_owned());
    // Each attestation and challenge record resolves its signer's key, so the
    // aggregation runs on the blocking pool without the GIL.
    on_resolution_pool(py, move |scope| {
        aggregate_with_storage(
            scope,
            &bi,
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
    })
}

/// Dispatches `populate_and_aggregate` to the active storage backend.
///
/// If the `BridgeInstance` storage provider is initialized, builds a
/// `ProtocolRepositoryTrustBridge` over the concrete storage backend
/// (`InMemoryEncrypted` or `Sqlite`) so cached attestations, revocation
/// states, and challenge results survive process restarts.
/// Otherwise falls back to an ephemeral in-memory store.
#[allow(clippy::too_many_arguments)]
fn aggregate_with_storage(
    scope: &scp_ffi_common::BlockingResolutionScope,
    bi: &PyBridgeInstance,
    context_id: &str,
    subject_did: &str,
    cached_attestations: Vec<scp_core::trust::aggregate::CachedAttestation>,
    challenge_results: &[scp_core::trust::ChallengeVerification],
    events: &[scp_event_log::Event],
    merkle_root: [u8; 32],
    consequence_rules: &[scp_core::trust::ConsequenceRule],
    threshold_requirements: &std::collections::HashMap<
        scp_core::trust::AttestationType,
        scp_core::trust::ThresholdRequirement,
    >,
    attestor_sets: &std::collections::HashMap<
        scp_core::trust::AttestationType,
        Vec<scp_core::trust::AttestorInfo>,
    >,
) -> PyResult<String> {
    use crate::runtime::StorageProvider;
    // Surface storage-not-initialized as an init bug, not a silent fallback.
    // The former path swapped in an ephemeral `InMemoryFfiTrustStore` so
    // aggregations against a `SCP({storage: sqlite})` caller's configured
    // SQLCipher store invisibly landed in an empty ephemeral store. See
    // `with_storage_py`.
    let provider = crate::runtime::get_storage(bi).map_err(|_| {
        coded_validation_error(
            "bridge storage not initialized — trust aggregation is \
             unreachable until this PyBridgeInstance has allocated its \
             storage provider (bridge init bug)"
                .to_owned(),
            codes::VALID_7005,
        )
    })?;
    let handle = crate::runtime()?.handle().clone();
    // The aggregation logic lives ONCE in `run_aggregation` (generic over the
    // concrete `EncryptedStorage` backend). The match is pure type dispatch: the
    // sealed `EncryptedStorage` bound on `ProtocolRepository::new` cannot be
    // satisfied by the `StorageProvider` enum itself (the marker trait lives in
    // `scp-platform`), so the concrete `Arc<S>` must be recovered per variant.
    // Both arms route through the single generic body — no duplicated logic.
    let inputs = AggregationInputs {
        // The instance resolver verifies each attestation's and challenge
        // record's `#active` signature; without one, a supplied record fails
        // closed.
        resolver: scp_ffi_common::instance_active_key_resolver(
            scope,
            crate::runtime::did_resolver(bi),
        ),
        context_id,
        subject_did,
        cached_attestations,
        challenge_results,
        events,
        merkle_root,
        consequence_rules,
        threshold_requirements,
        attestor_sets,
    };
    let result = match provider {
        StorageProvider::InMemoryEncrypted(storage) => {
            run_aggregation(Arc::clone(storage), handle, inputs)
        }
        StorageProvider::Sqlite(storage) => run_aggregation(Arc::clone(storage), handle, inputs),
    };
    // VALID_7052 mirrors the UniFFI bridge's code for a failed trust
    // aggregation, so every native bridge surfaces the identical code for
    // the same logical failure.
    result.map_err(|e| coded_validation_error(e.to_string(), codes::VALID_7052).into())
}

/// Owned + borrowed inputs for [`run_aggregation`], grouped to keep the generic
/// helper's signature manageable.
struct AggregationInputs<'a> {
    resolver: &'a dyn scp_core::trust::attestation::ActiveKeyResolver,
    context_id: &'a str,
    subject_did: &'a str,
    cached_attestations: Vec<scp_core::trust::aggregate::CachedAttestation>,
    challenge_results: &'a [scp_core::trust::ChallengeVerification],
    events: &'a [scp_event_log::Event],
    merkle_root: [u8; 32],
    consequence_rules: &'a [scp_core::trust::ConsequenceRule],
    threshold_requirements: &'a std::collections::HashMap<
        scp_core::trust::AttestationType,
        scp_core::trust::ThresholdRequirement,
    >,
    attestor_sets: &'a std::collections::HashMap<
        scp_core::trust::AttestationType,
        Vec<scp_core::trust::AttestorInfo>,
    >,
}

/// Builds a `ProtocolRepositoryTrustBridge` over the concrete encrypted backend
/// and runs `populate_and_aggregate`. Single source of truth for the per-backend
/// aggregation path (both `StorageProvider` variants route through this).
fn run_aggregation<S: scp_platform::EncryptedStorage + 'static>(
    storage: Arc<S>,
    handle: tokio::runtime::Handle,
    inputs: AggregationInputs<'_>,
) -> Result<String, scp_core::trust::TrustError> {
    let repo = Arc::new(scp_core::store::ProtocolRepository::new(storage));
    let bridge = scp_core::trust::ProtocolRepositoryTrustBridge::new(repo, handle);
    scp_ffi_common::trust_store::populate_and_aggregate(
        bridge,
        inputs.resolver,
        &scp_core::trust::ProtocolOnlyDefinitions,
        inputs.context_id,
        inputs.subject_did,
        inputs.cached_attestations,
        inputs.challenge_results,
        inputs.events,
        inputs.merkle_root,
        inputs.consequence_rules,
        inputs.threshold_requirements,
        inputs.attestor_sets,
    )
}

// ---------------------------------------------------------------------------
// PyParticipationRecord
// ---------------------------------------------------------------------------

/// Structured participation facts (§7.3.2) for a subject DID in a context.
///
/// The scalar projection of scp-core's
/// [`ParticipationRecord`](scp_core::trust::ParticipationRecord), produced by
/// [`PyScp::participation_record`](crate::scp::PyScp::participation_record). Counts are flattened ONCE in the shared Rust
/// core (`ParticipationFacts`) so Python RECEIVES the facts rather than
/// re-aggregating event-log collections — eliminating cross-binding divergence
/// by construction.
///
/// See `scp_core::trust::ParticipationFacts` and ADR-017.
#[pyclass(name = "ParticipationRecord")]
#[derive(Debug, Clone)]
pub struct PyParticipationRecord {
    /// The DID whose participation is summarized.
    #[pyo3(get)]
    pub subject_did: String,
    /// Total seconds of context participation (§7.3.2).
    #[pyo3(get)]
    pub participation_duration_secs: u64,
    /// Count of governance actions taken against this identity (projected
    /// `target_did` is the subject).
    #[pyo3(get)]
    pub governance_actions_against: u64,
    /// Count of governance actions initiated by this identity.
    #[pyo3(get)]
    pub governance_actions_by: u64,
    /// Total outlet invocations across all outlet types.
    #[pyo3(get)]
    pub outlet_invocation_count: u64,
    /// Whether `outlet_invocation_count` is anchored in the canonical Merkle log.
    /// `false` until ADR-051 makes `OutletInvoked` a convergent leaf (§7.3.2) —
    /// consumers MUST NOT treat the count as Merkle-proven while this is `false`.
    #[pyo3(get)]
    pub outlet_invocation_count_anchored: bool,
    /// Number of contexts created by the subject (`ChildContextCreated`).
    #[pyo3(get)]
    pub context_creation_count: u64,
    /// Number of role transitions for the subject.
    #[pyo3(get)]
    pub role_progression_count: u64,
    /// Number of accessible, currently-valid credential-layer attestations
    /// (§7.4) for the subject. Verifier-relative.
    #[pyo3(get)]
    pub attestation_count: u64,
    /// Whether `attestation_count` is anchored in / verifiable against a context
    /// Merkle root. Always `false` — it is a credential-layer, verifier-relative
    /// fact (§7.4), never a context-event-log count (§7.3.2). The parallel of
    /// `outlet_invocation_count_anchored`, surfaced so the non-anchored nature is
    /// mechanically visible.
    #[pyo3(get)]
    pub attestation_count_anchored: bool,
    /// Unix timestamp (seconds) when the record was computed.
    #[pyo3(get)]
    pub computed_at: u64,
    /// Merkle root (hex) of the event log at computation time.
    #[pyo3(get)]
    pub event_log_root: String,
}

impl From<&scp_core::trust::ParticipationFacts> for PyParticipationRecord {
    fn from(f: &scp_core::trust::ParticipationFacts) -> Self {
        Self {
            subject_did: f.subject_did.to_string(),
            participation_duration_secs: f.participation_duration_secs,
            governance_actions_against: f.governance_actions_against,
            governance_actions_by: f.governance_actions_by,
            outlet_invocation_count: f.outlet_invocation_count,
            outlet_invocation_count_anchored: f.outlet_invocation_count_anchored,
            context_creation_count: f.context_creation_count,
            role_progression_count: f.role_progression_count,
            attestation_count: f.attestation_count,
            attestation_count_anchored: f.attestation_count_anchored,
            computed_at: f.computed_at,
            event_log_root: encode_hex(&f.event_log_root),
        }
    }
}

#[pymethods]
impl PyParticipationRecord {
    fn __repr__(&self) -> String {
        format!(
            "ParticipationRecord(subject_did={}, participation_duration_secs={}, \
             governance_actions_against={}, governance_actions_by={}, \
             outlet_invocation_count={}, outlet_invocation_count_anchored={}, \
             context_creation_count={}, role_progression_count={}, \
             attestation_count={}, attestation_count_anchored={})",
            self.subject_did,
            self.participation_duration_secs,
            self.governance_actions_against,
            self.governance_actions_by,
            self.outlet_invocation_count,
            self.outlet_invocation_count_anchored,
            self.context_creation_count,
            self.role_progression_count,
            self.attestation_count,
            self.attestation_count_anchored,
        )
    }
}

/// Sources the subject's verified attestations from this bridge instance's
/// persistent trust store, then computes the participation record via the
/// shared Supervisor.
///
/// Mirrors `aggregate_with_storage`'s attestation handling: caller-supplied
/// `cached_attestations` are populated into the bridge's
/// `ProtocolRepositoryTrustBridge` over the concrete storage backend, and the
/// subject's accessible, currently-valid attestations are read back via
/// `get_verified_attestations` — the REAL credential-layer source, not `&[]`.
/// Those attestations feed `attestation_count` (§7.4); the Supervisor gathers
/// the full event log + Merkle root for every other fact.
fn participation_record_impl(
    bi: &Arc<PyBridgeInstance>,
    py: Python<'_>,
    context_id: &str,
    subject_did: &str,
    cached_attestations_json: &str,
) -> PyResult<PyParticipationRecord> {
    // VALID_7000 matches the UniFFI/NAPI bridges, which route these same
    // checks through the shared `scp_ffi_common::validate::ValidationError`
    // conversion (generic validation code).
    scp_ffi_common::validate::validate_context_id(context_id)
        .map_err(|e| coded_validation_error(e.message, codes::VALID_7000))?;
    scp_ffi_common::validate::validate_did(subject_did)
        .map_err(|e| coded_validation_error(e.message, codes::VALID_7000))?;

    let cached_attestations: Vec<scp_core::trust::aggregate::CachedAttestation> =
        serde_json::from_str(cached_attestations_json).map_err(|e| {
            coded_validation_error(
                format!("failed to parse cached_attestations JSON: {e}"),
                codes::VALID_7059,
            )
        })?;

    // Source verified attestations from this instance's persistent trust store
    // (same backend as context/event-log writes). The sourcing
    // logic lives ONCE in `run_verified_attestations` (generic over the concrete
    // `EncryptedStorage` backend); the match is pure type dispatch because the
    // sealed `EncryptedStorage` bound cannot be satisfied by the `StorageProvider`
    // enum itself. Both arms route through the single generic body.
    let handle = crate::runtime()?.handle().clone();
    let bi = Arc::clone(bi);
    let (context_id, subject_did) = (context_id.to_owned(), subject_did.to_owned());
    // Each cached attestation resolves its issuer's key, so the record is
    // computed on the blocking pool without the GIL.
    on_resolution_pool(py, move |scope| {
        participation_record_on_pool(
            scope,
            &bi,
            handle,
            &context_id,
            &subject_did,
            cached_attestations,
        )
    })
}

/// The part of [`participation_record_impl`] that resolves keys: sources the
/// verified attestations, then computes the record through the Supervisor.
fn participation_record_on_pool(
    scope: &scp_ffi_common::BlockingResolutionScope,
    bi: &PyBridgeInstance,
    handle: tokio::runtime::Handle,
    context_id: &str,
    subject_did: &str,
    cached_attestations: Vec<scp_core::trust::aggregate::CachedAttestation>,
) -> PyResult<PyParticipationRecord> {
    use crate::runtime::StorageProvider;

    let provider = crate::runtime::get_storage(bi)?;
    let resolver =
        scp_ffi_common::instance_active_key_resolver(scope, crate::runtime::did_resolver(bi));
    let verified = match provider {
        StorageProvider::InMemoryEncrypted(storage) => run_verified_attestations(
            Arc::clone(storage),
            handle,
            resolver,
            context_id,
            subject_did,
            cached_attestations,
        ),
        StorageProvider::Sqlite(storage) => run_verified_attestations(
            Arc::clone(storage),
            handle,
            resolver,
            context_id,
            subject_did,
            cached_attestations,
        ),
    }
    // An error from `verified_attestations` is an INFRA fault (trust-store read,
    // signature-verification infrastructure) — NOT a caller-input validation
    // error. Code it as a context-layer fault (CTX_2000), consistent with the
    // generic-failure arm of `participation_record` below, and keep it propagating
    // (fail-closed): it must never be folded into the empty-log CTX_2076 path.
    .map_err(|e| crate::error::ScpPyError::ContextError {
        message: e.to_string(),
        code: scp_ffi_common::error_codes::CTX_2000.to_owned(),
    })?;

    let record = crate::runtime::supervisor(bi)?
        .participation_record(context_id, subject_did, &verified)
        // Map the empty-log condition to its dedicated, stable code (CTX_2076) so
        // SDKs can branch on "no recorded participation facts" without string-
        // matching; genuine failures stay on the generic context code (CTX_2000),
        // matching NAPI/UniFFI. `ScpPyError::context` would emit CTX_2001,
        // diverging from the other bridges for the same condition.
        .map_err(|e| {
            let code = match e {
                scp_core::context::ContextError::NoParticipationFacts { .. } => {
                    scp_ffi_common::error_codes::CTX_2076
                }
                _ => scp_ffi_common::error_codes::CTX_2000,
            };
            crate::error::ScpPyError::ContextError {
                message: e.to_string(),
                code: code.to_owned(),
            }
        })?;

    let facts = scp_core::trust::ParticipationFacts::from(&record);
    Ok(PyParticipationRecord::from(&facts))
}

/// Builds a `ProtocolRepositoryTrustBridge` over the concrete encrypted backend
/// and reads back the subject's verified attestations. Single source of truth for
/// the per-backend attestation-sourcing path (both `StorageProvider` variants
/// route through this).
fn run_verified_attestations<S: scp_platform::EncryptedStorage + 'static>(
    storage: Arc<S>,
    handle: tokio::runtime::Handle,
    resolver: &dyn scp_core::trust::attestation::ActiveKeyResolver,
    context_id: &str,
    subject_did: &str,
    cached_attestations: Vec<scp_core::trust::aggregate::CachedAttestation>,
) -> Result<Vec<scp_core::trust::attestation::Attestation>, scp_core::trust::TrustError> {
    let repo = Arc::new(scp_core::store::ProtocolRepository::new(storage));
    let bridge = scp_core::trust::ProtocolRepositoryTrustBridge::new(repo, handle);
    scp_ffi_common::trust_store::verified_attestations(
        bridge,
        resolver,
        context_id,
        subject_did,
        cached_attestations,
    )
}

// ---------------------------------------------------------------------------
// PyScp methods — migrated from #[pyfunction] exports (Phase 4 PR 4).
// ---------------------------------------------------------------------------

#[pymethods]
impl crate::scp::PyScp {
    /// Queries participation-based trust data for a DID within a context.
    ///
    /// Returns a dict with:
    /// - `message_count` (int): Number of `MessageSent` events by this DID.
    /// - `governance_count` (int): Number of `GovernanceAction` events by this DID.
    /// - `composite_score` (float): Normalized summary (0.0–1.0) based on
    ///   participation count. This is a convenience metric, not an authoritative
    ///   trust judgment — agents should evaluate the raw counts per their own
    ///   criteria.
    ///
    /// The data is derived from the event log via the participation record
    /// computation (Layer 2 of the four-layer trust model).
    ///
    /// # Errors
    ///
    /// Returns `ScpError` if input validation fails.
    /// Verifies an attestation's signature, evidence, expiry, its own
    /// revocation status, and this instance's revocation list for
    /// `context_id`.
    ///
    /// See `trust_verify_attestation_impl` for the result and error codes.
    ///
    /// # Errors
    ///
    /// Returns `ScpError` for malformed input, a missing storage provider, or
    /// an unreadable revocation list.
    #[pyo3(name = "trust_verify_attestation")]
    pub fn trust_verify_attestation(
        &self,
        py: Python<'_>,
        context_id: &str,
        attestation_json: &str,
    ) -> PyResult<Py<PyDict>> {
        trust_verify_attestation_impl(&self.inner, py, context_id, attestation_json)
    }

    #[pyo3(name = "trust_query_score")]
    pub fn trust_query_score(
        &self,
        py: Python<'_>,
        did: &str,
        context_id: &str,
    ) -> PyResult<Py<PyDict>> {
        let bi = &*self.inner;
        trust_query_score_impl(bi, py, did, context_id)
    }

    /// Creates a challenge in `verifier`'s ledger and returns the request the
    /// ledger signed with `verifier`'s `#active` key (spec 07 §7.3.4 step 1,
    /// ADR-017).
    ///
    /// `verifier` is the DID of an identity hosted on this instance.
    /// `test_cases_json` is the challenger-written JSON array of `TestCase`,
    /// with their answers; the request carries only their commitments. The
    /// subject answers within `window_secs`. `context_id` is the context the
    /// record will be bound to. `evaluator_context_id` names the context whose
    /// outlets grade `CustomEval` cases. `policy`, a dict of `max_retries` and
    /// `cooldown_secs`, picks fewer retries or a longer cooldown than the
    /// capability definition's.
    ///
    /// Returns a dict with `challenge_id` (lowercase hex of its 32 random
    /// bytes) and `request_json` (the signed `ChallengeRequest`).
    ///
    /// # Errors
    ///
    /// - `SCP-VALID-7013` for an invalid verifier or subject DID,
    ///   `SCP-VALID-7011` for an invalid context id.
    /// - `SCP-VALID-7002` for malformed `test_cases_json` or `policy`.
    /// - The `TrustError` code of the refusal: a suite below the definition's
    ///   minimum, a policy looser than the definition's, a self-challenge, or
    ///   a `CustomEval` evaluator that is not registered.
    /// - The identity registry's error when `verifier` is not hosted here, and
    ///   the custody error when signing fails (`SCP-CRYPTO-4006` for a
    ///   destroyed key).
    #[pyo3(
        name = "trust_create_challenge",
        signature = (
            verifier,
            subject,
            capability_uri,
            test_cases_json,
            window_secs,
            context_id,
            evaluator_context_id = None,
            policy = None
        )
    )]
    #[allow(clippy::too_many_arguments)]
    pub fn trust_create_challenge(
        &self,
        py: Python<'_>,
        verifier: &str,
        subject: &str,
        capability_uri: &str,
        test_cases_json: &str,
        window_secs: u64,
        context_id: &str,
        evaluator_context_id: Option<&str>,
        policy: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Py<PyDict>> {
        trust_create_challenge_impl(
            &self.inner,
            py,
            verifier,
            subject,
            capability_uri,
            test_cases_json,
            window_secs,
            context_id,
            evaluator_context_id,
            policy,
        )
    }

    /// Answers a challenge: checks the challenger's signature on
    /// `request_json` through this instance's DID resolver, and returns the
    /// `ChallengeResponse` JSON of `outputs_json` for `attempt`, signed with
    /// `subject`'s `#active` key (spec 07 §7.3.4 step 2, ADR-017).
    ///
    /// # Errors
    ///
    /// - `SCP-VALID-7013` for an invalid subject DID.
    /// - `SCP-VALID-7002` for a malformed request or outputs JSON.
    /// - `SCP-IDENT-1033` when this instance has no DID resolver.
    /// - The `TrustError` code when the request is refused.
    /// - The identity registry's error when `subject` is not hosted here, and
    ///   the custody error when signing fails.
    #[pyo3(name = "trust_respond_to_challenge")]
    pub fn trust_respond_to_challenge(
        &self,
        py: Python<'_>,
        subject: &str,
        request_json: &str,
        outputs_json: &str,
        attempt: u32,
    ) -> PyResult<String> {
        trust_respond_to_challenge_impl(
            &self.inner,
            py,
            subject,
            request_json,
            outputs_json,
            attempt,
        )
    }

    /// Grades the subject's `response_json` to `request_json` in `verifier`'s
    /// ledger and returns the record it signed with `verifier`'s `#active`
    /// key (spec 07 §7.3.4 steps 3 and 4, ADR-017).
    ///
    /// `CustomEval` cases run on this bridge's outlets in the evaluator
    /// context. The record is written to this instance's protocol repository.
    /// Returns a dict with `record_json`, `reasons_json` (the per-case
    /// results, never signed) and `trust_store_error` (why the record could
    /// not be stored, or `None`; the attempt is used either way). The GIL is
    /// released while grading runs.
    ///
    /// # Errors
    ///
    /// - `SCP-VALID-7013` for an invalid verifier DID.
    /// - `SCP-VALID-7002` for a malformed request or response JSON.
    /// - `SCP-IDENT-1033` when this instance has no DID resolver.
    /// - `SCP-VALID-7005` when this instance has no storage.
    /// - The `TrustError` code when the response is refused.
    /// - The identity registry's error when `verifier` is not hosted here, and
    ///   the custody error when signing fails.
    #[pyo3(name = "trust_grade_response")]
    pub fn trust_grade_response(
        &self,
        py: Python<'_>,
        verifier: &str,
        request_json: &str,
        response_json: &str,
    ) -> PyResult<Py<PyDict>> {
        trust_grade_response_impl(&self.inner, py, verifier, request_json, response_json)
    }

    /// Checks an agent against the capability requirements in `context_id`'s
    /// governance state, read at call time (spec 07 §7.3.4.4).
    ///
    /// Inputs:
    /// - `context_id`: the context the agent is being admitted to. A record
    ///   only counts when its signed `context_id` equals this value.
    /// - `subject_did`: the DID of the agent being admitted. Only records whose
    ///   signed `subject` equals this value count.
    /// - `agent_capabilities_json`: JSON array of capability-URI strings the
    ///   agent self-attests.
    /// - `challenge_verifications_json`: JSON array of `ChallengeVerification`
    ///   records. Each counts only if its signature verifies against the
    ///   verifier's `#active` key, resolved through this instance's DID
    ///   resolver, and it comes from a verifier the requirement trusts, within
    ///   the requirement's retry cap.
    ///
    /// Returns `None` on success. The GIL is released while the check runs.
    ///
    /// # Errors
    ///
    /// - `SCP-VALID-7000` for an invalid `subject_did`, `SCP-VALID-7011` for
    ///   an invalid `context_id`.
    /// - `SCP-VALID-7074` / `7075` for malformed agent-capabilities or
    ///   challenge-verifications JSON.
    /// - The admission code of the refusal: `SCP-VALID-7076` for an unmet
    ///   requirement, `SCP-VALID-7121` for an untrusted verifier,
    ///   `SCP-VALID-7137` past the retry cap.
    /// - `SCP-IDENT-1033` when a record must be verified and this instance has
    ///   no DID resolver, or its backend is unreachable.
    /// - The `ContextError` code when the context's governance cannot be read.
    #[pyo3(name = "check_capability_requirements")]
    pub fn check_capability_requirements(
        &self,
        py: Python<'_>,
        context_id: &str,
        subject_did: &str,
        agent_capabilities_json: &str,
        challenge_verifications_json: &str,
    ) -> PyResult<()> {
        // VALID_7000 matches the UniFFI/NAPI bridges, which route this same
        // check through the shared `ValidationError` conversion.
        scp_ffi_common::validate::validate_did(subject_did)
            .map_err(|e| coded_validation_error(e.message, codes::VALID_7000))?;
        validate_challenge_context_id(context_id)?;
        let bi = &*self.inner;
        let sup = crate::runtime::supervisor(bi)?;
        crate::actor_wait::block_on_released(
            py,
            scp_ffi_common::challenge::check_capability_requirements(
                sup,
                crate::runtime::did_resolver(bi).cloned(),
                context_id.to_owned(),
                subject_did.to_owned(),
                agent_capabilities_json,
                challenge_verifications_json,
            ),
        )?
        .map_err(challenge_op_error)
    }

    /// Aggregates all trust engine layers into a single `TrustInput` for
    /// agent-level evaluation.
    ///
    /// Accepts all inputs as JSON strings and returns the aggregated `TrustInput`
    /// as a JSON string. Uses the `BridgeInstance` storage provider for persistent
    /// trust data when initialized (trust data survives across calls and restarts);
    /// falls back to an ephemeral in-memory store otherwise.
    ///
    /// # Errors
    ///
    /// Returns `ScpError` if any JSON input is malformed or if aggregation fails.
    ///
    /// See ADR-017 acceptance criterion 9, spec §7.3.
    #[pyo3(name = "aggregate_trust_input")]
    #[allow(clippy::too_many_arguments)]
    pub fn aggregate_trust_input(
        &self,
        py: Python<'_>,
        context_id: &str,
        subject_did: &str,
        events_json: &str,
        merkle_root_json: &str,
        consequence_rules_json: &str,
        threshold_requirements_json: &str,
        attestor_sets_json: &str,
        cached_attestations_json: &str,
        challenge_results_json: &str,
    ) -> PyResult<String> {
        aggregate_trust_input_impl(
            &self.inner,
            py,
            context_id,
            subject_did,
            events_json,
            merkle_root_json,
            consequence_rules_json,
            threshold_requirements_json,
            attestor_sets_json,
            cached_attestations_json,
            challenge_results_json,
        )
    }

    /// Computes the structured participation record (§7.3.2) for `subject_did`
    /// in `context_id`.
    ///
    /// The bridge sources the subject's accessible, currently-valid attestations
    /// from this instance's persistent trust store (populating any
    /// caller-supplied `cached_attestations_json` first, exactly as
    /// `aggregate_trust_input` does), and the shared Supervisor gathers the FULL
    /// event log to derive every other fact. Returns a typed
    /// [`PyParticipationRecord`] — the SDK receives the flattened facts and never
    /// re-aggregates event-log collections.
    ///
    /// # Errors
    ///
    /// Returns `ScpError` if validation fails, `cached_attestations_json` is
    /// malformed, storage is uninitialized, or the record computation fails
    /// (e.g. an empty event log).
    ///
    /// See ADR-017 and spec §7.3.2.
    #[pyo3(name = "participation_record", signature = (context_id, subject_did, cached_attestations_json="[]"))]
    pub fn participation_record(
        &self,
        py: Python<'_>,
        context_id: &str,
        subject_did: &str,
        cached_attestations_json: &str,
    ) -> PyResult<PyParticipationRecord> {
        participation_record_impl(
            &self.inner,
            py,
            context_id,
            subject_did,
            cached_attestations_json,
        )
    }
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Registers trust engine bridge free functions with the Python module.
///
/// Post-migration (Phase 4 PR 4 sub-slice E), stateful trust operations
/// (`trust_query_score`, `aggregate_trust_input`) are exposed as methods on
/// `SCP`, as are the challenge operations, which sign through an identity
/// hosted on the instance, capability requirement verification, which
/// resolves verifier keys through the instance's DID resolver, and
/// `trust_verify_attestation`, which reads the instance's revocation list.
/// Only the pure participation requirement verification helper remains as a
/// free `#[pyfunction]` export.
pub fn register_trust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyParticipationRecord>()?;
    m.add_function(wrap_pyfunction!(py_verify_participation_requirements, m)?)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn default_scp() -> crate::scp::PyScp {
        crate::scp::PyScp::new_in_memory_for_test()
    }

    /// A DID resolver that announces each lookup on `entered`, then waits up
    /// to ten seconds for a permit on `release`, recording whether one came.
    struct GatedResolver {
        entered: std::sync::Mutex<std::sync::mpsc::Sender<()>>,
        release: Arc<tokio::sync::Semaphore>,
        released: Arc<std::sync::atomic::AtomicBool>,
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
            if let Ok(entered) = self.entered.lock() {
                entered.send(()).ok();
            }
            let release = Arc::clone(&self.release);
            let released = Arc::clone(&self.released);
            async move {
                let permit =
                    tokio::time::timeout(std::time::Duration::from_secs(10), release.acquire())
                        .await;
                released.store(
                    matches!(permit, Ok(Ok(_))),
                    std::sync::atomic::Ordering::SeqCst,
                );
                Ok(None)
            }
        }
    }

    /// `trust_verify_attestation` resolves the issuer's key without the GIL:
    /// while the lookup is pending, another Python thread takes the GIL and
    /// then lets the lookup finish. Holding the GIL across the lookup would
    /// keep that thread out until the lookup gave up.
    #[test]
    fn a_pending_key_resolution_lets_another_thread_take_the_gil() {
        pyo3::prepare_freethreaded_python();
        crate::init_runtime().unwrap();
        let scp = default_scp();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
        crate::runtime::init_did_resolver(
            &scp.inner,
            Arc::new(GatedResolver {
                entered: std::sync::Mutex::new(entered_tx),
                release: Arc::clone(&release),
                released: Arc::clone(&released),
            }),
            crate::runtime().unwrap().handle().clone(),
        );
        let helper = std::thread::spawn(move || {
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
            Python::with_gil(|_py| release.add_permits(1));
        });
        // An issuer this instance does not host, so its key comes only from
        // the resolver.
        let issuer = scp_did::did_dht_from_public_key(
            &ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        let attestation = scp_core::trust::Attestation {
            id: "att-gil".to_owned(),
            attestation_type: scp_core::trust::AttestationType::Endorsement,
            issuer,
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
        let outcome = Python::with_gil(|py| {
            scp.trust_verify_attestation(
                py,
                "ctx-gil",
                &serde_json::to_string(&attestation).unwrap(),
            )
        });
        helper.join().unwrap();
        assert!(
            released.load(std::sync::atomic::Ordering::SeqCst),
            "the helper thread could not take the GIL while the lookup was pending"
        );
        // The issuer is not found: the attestation is rejected, not verified.
        let valid = Python::with_gil(|py| {
            outcome
                .unwrap()
                .bind(py)
                .get_item("valid")
                .unwrap()
                .unwrap()
                .extract::<bool>()
                .unwrap()
        });
        assert!(!valid);
    }

    #[test]
    fn trust_query_score_validates_did() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            // Empty DID should fail validation.
            let result = default_scp().trust_query_score(py, "", "ctx-1");
            assert!(result.is_err());
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(scp_ffi_common::error_codes::VALID_7010),
                "expected {}, got: {err_str}",
                scp_ffi_common::error_codes::VALID_7010
            );
        });
    }

    #[test]
    fn trust_query_score_validates_context_id() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            // Empty context ID should fail validation.
            let result = default_scp().trust_query_score(py, "did:key:test", "");
            assert!(result.is_err());
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(scp_ffi_common::error_codes::VALID_7011),
                "expected {}, got: {err_str}",
                scp_ffi_common::error_codes::VALID_7011
            );
        });
    }

    #[test]
    fn trust_query_score_returns_valid_dict() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let result = default_scp().trust_query_score(py, "did:key:test", "ctx-valid");
            assert!(result.is_ok());
            let dict = result.unwrap();
            let dict_ref = dict.bind(py);
            assert!(dict_ref.get_item("message_count").unwrap().is_some());
            assert!(dict_ref.get_item("governance_count").unwrap().is_some());
            assert!(dict_ref.get_item("composite_score").unwrap().is_some());
        });
    }

    #[test]
    fn trust_verify_attestation_rejects_invalid_json() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let result = default_scp().trust_verify_attestation(py, "ctx-valid", "not valid json");
            assert!(result.is_err());
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(scp_ffi_common::error_codes::VALID_7012),
                "expected {}, got: {err_str}",
                scp_ffi_common::error_codes::VALID_7012
            );
        });
    }

    const SCHEMA_URI: &str = "scp:capability:schema-validation/v1";
    const VALID_DID: &str = "did:dht:zjerxoow7gsm8suaqfsc86txbreganh7chorzwwh4crbh7imbdhgy";

    /// `n` exact-match test cases whose weights sum to 10000.
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

    fn assert_code<T: std::fmt::Debug>(result: PyResult<T>, code: &str) {
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains(code), "expected {code}, got: {msg}");
    }

    #[test]
    fn trust_create_challenge_rejects_invalid_arguments() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let create = |subject: &str, context_id: &str| {
                default_scp().trust_create_challenge(
                    py, VALID_DID, subject, SCHEMA_URI, "[]", 300, context_id, None, None,
                )
            };
            assert_code(create("", "ctx"), codes::VALID_7013);
            assert_code(create(VALID_DID, ""), codes::VALID_7011);
        });
    }

    #[test]
    fn trust_create_challenge_rejects_malformed_policy() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            for keys in [
                vec![("max_retries", 1_u32)],
                vec![("max_retries", 1), ("cooldown_secs", 1), ("extra", 1)],
            ] {
                let policy = PyDict::new(py);
                for (k, v) in keys {
                    policy.set_item(k, v).unwrap();
                }
                let result = default_scp().trust_create_challenge(
                    py,
                    VALID_DID,
                    VALID_DID,
                    SCHEMA_URI,
                    "[]",
                    300,
                    "ctx",
                    None,
                    Some(&policy),
                );
                assert_code(result, codes::VALID_7002);
            }
        });
    }

    #[test]
    fn trust_respond_and_grade_without_resolver_are_ident_1033() {
        // A fresh instance has no DID resolver until an identity is created.
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let scp = default_scp();
            assert!(crate::runtime::did_resolver(&scp.inner).is_none());
            assert_code(
                scp.trust_respond_to_challenge(py, VALID_DID, "{}", "[]", 1),
                codes::IDENT_1033,
            );
            assert_code(
                scp.trust_grade_response(py, VALID_DID, "{}", "{}"),
                codes::IDENT_1033,
            );
        });
    }

    #[test]
    fn verify_participation_requirements_rejects_invalid_profile_json() {
        // Malformed JSON in the PROFILE position (now the 3rd arg).
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|_py| {
            let result = py_verify_participation_requirements("did:key:alice", "[]", "not json");
            assert!(result.is_err());
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(scp_ffi_common::error_codes::VALID_7030),
                "expected {}, got: {err_str}",
                scp_ffi_common::error_codes::VALID_7030
            );
        });
    }

    #[test]
    fn verify_participation_requirements_rejects_invalid_requirements_json() {
        // Malformed JSON in the REQUIREMENTS position (now the 2nd arg).
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|_py| {
            let result = py_verify_participation_requirements("did:key:alice", "not json", "[]");
            assert!(result.is_err());
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(scp_ffi_common::error_codes::VALID_7031),
                "expected {}, got: {err_str}",
                scp_ffi_common::error_codes::VALID_7031
            );
        });
    }

    #[test]
    fn verify_participation_requirements_empty_inputs_succeeds() {
        // Empty requirements = no constraints = always passes.
        let result = py_verify_participation_requirements("did:key:alice", "[]", "[]");
        assert!(result.is_ok());
    }

    #[test]
    fn verify_participation_requirements_rejects_invalid_subject() {
        // A malformed subject DID is rejected at the FFI boundary.
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|_py| {
            let result = py_verify_participation_requirements("not-a-did", "[]", "[]");
            assert!(result.is_err());
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(scp_ffi_common::error_codes::VALID_7000),
                "expected {}, got: {err_str}",
                scp_ffi_common::error_codes::VALID_7000
            );
        });
    }

    #[test]
    fn verify_participation_requirements_unmet_requirement_fails_with_admission_code() {
        // A requirement with no satisfying profiles fails the admission check
        // itself (not JSON parsing), which carries its own per-case code.
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|_py| {
            let requirements = r#"[{"fact":"ParticipationDuration","threshold":{"AtLeast":1},"max_age_secs":3600,"min_contexts":0}]"#;
            let result = py_verify_participation_requirements("did:key:alice", requirements, "[]");
            assert!(result.is_err());
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(scp_ffi_common::error_codes::VALID_7032),
                "expected {}, got: {err_str}",
                scp_ffi_common::error_codes::VALID_7032
            );
        });
    }

    // -- check_capability_requirements (§7.3.4.4, SCP-ACR-008) --

    #[test]
    fn check_capability_requirements_rejects_empty_and_malformed_subject() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            for subject in ["", "not-a-did"] {
                let result =
                    default_scp().check_capability_requirements(py, "ctx-1", subject, "[]", "[]");
                assert_code(result, codes::VALID_7000);
            }
            let result = default_scp().check_capability_requirements(py, "", VALID_DID, "[]", "[]");
            assert_code(result, codes::VALID_7011);
        });
    }

    /// Challenges and capability admission through identities hosted on the
    /// instance, so the instance DID resolver reads each `#active` key.
    #[cfg(feature = "testing")]
    mod challenge_live {
        use scp_platform::KeyCustody as _;

        use super::*;

        /// The custody and `(identity, #active)` key handles of `did`.
        fn keys(
            scp: &crate::scp::PyScp,
            did: &str,
        ) -> (
            Arc<crate::custody::FfiKeyCustody>,
            scp_platform::KeyHandle,
            scp_platform::KeyHandle,
        ) {
            crate::runtime::with_identity(&scp.inner, did, |entry| {
                Ok((
                    Arc::clone(&entry.custody),
                    entry.identity.identity_key,
                    entry.identity.active_signing_key,
                ))
            })
            .unwrap()
        }

        fn identity(py: Python<'_>, scp: &crate::scp::PyScp) -> String {
            scp.identity_create(py, "in_memory", None)
                .unwrap()
                .did()
                .to_owned()
        }

        fn setup() {
            pyo3::prepare_freethreaded_python();
            crate::init_runtime().ok();
        }

        /// Creates a context through the bridge, created by `creator`, whose
        /// governance holds `requirements`, and returns its id.
        fn context_with(
            py: Python<'_>,
            scp: &crate::scp::PyScp,
            creator: &str,
            requirements: &serde_json::Value,
        ) -> PyResult<String> {
            let params = PyDict::new(py);
            params.set_item("ceiling", vec!["messages:read"]).unwrap();
            params
                .set_item("capability_requirements", requirements.to_string())
                .unwrap();
            let handle = scp.context_create(py, creator, &params)?;
            Py::new(py, handle)?
                .bind(py)
                .getattr("context_id")?
                .extract()
        }

        fn challenge_requirement(verifier: &str) -> serde_json::Value {
            serde_json::json!([{
                "capability": SCHEMA_URI,
                "verification_level": "ChallengeVerified",
                "trusted_verifiers": [verifier],
            }])
        }

        fn self_attested() -> serde_json::Value {
            serde_json::json!([{
                "capability": SCHEMA_URI,
                "verification_level": "SelfAttested",
            }])
        }

        /// Creates a `SCHEMA_URI` challenge from `verifier` to `subject` in
        /// `context_id` with `cases_json`.
        fn create(
            py: Python<'_>,
            scp: &crate::scp::PyScp,
            verifier: &str,
            subject: &str,
            context_id: &str,
            cases_json: &str,
        ) -> PyResult<(String, String)> {
            let created = scp.trust_create_challenge(
                py, verifier, subject, SCHEMA_URI, cases_json, 300, context_id, None, None,
            )?;
            let created = created.bind(py);
            let field = |name: &str| -> String {
                created.get_item(name).unwrap().unwrap().extract().unwrap()
            };
            Ok((field("challenge_id"), field("request_json")))
        }

        /// A verifier, a subject, and a context created by the verifier that
        /// requires `SCHEMA_URI` verified by it, on one instance.
        struct Graded {
            scp: crate::scp::PyScp,
            verifier: String,
            subject: String,
            context_id: String,
        }

        impl Graded {
            fn new(py: Python<'_>) -> Self {
                let scp = default_scp();
                let verifier = identity(py, &scp);
                let subject = identity(py, &scp);
                let context_id =
                    context_with(py, &scp, &verifier, &challenge_requirement(&verifier)).unwrap();
                Self {
                    scp,
                    verifier,
                    subject,
                    context_id,
                }
            }

            /// Runs create, respond and grade through the bridge with every
            /// answer correct, and returns `(record_json, reasons_json,
            /// trust_store_error)`.
            fn grade(&self, py: Python<'_>) -> (String, String, Option<String>) {
                let (challenge_id, request_json) = create(
                    py,
                    &self.scp,
                    &self.verifier,
                    &self.subject,
                    &self.context_id,
                    &test_cases_json(20),
                )
                .unwrap();
                assert_eq!(challenge_id.len(), 64);
                assert_eq!(challenge_id, challenge_id.to_lowercase());
                let outputs: Vec<scp_core::trust::TestOutput> = (0..20)
                    .map(|i| scp_core::trust::TestOutput {
                        test_id: format!("t{i}"),
                        output: serde_json::json!({ "ok": true }),
                    })
                    .collect();
                let response_json = self
                    .scp
                    .trust_respond_to_challenge(
                        py,
                        &self.subject,
                        &request_json,
                        &serde_json::to_string(&outputs).unwrap(),
                        1,
                    )
                    .unwrap();
                let graded = self
                    .scp
                    .trust_grade_response(py, &self.verifier, &request_json, &response_json)
                    .unwrap();
                let graded = graded.bind(py);
                let item = |name: &str| graded.get_item(name).unwrap().unwrap();
                (
                    item("record_json").extract().unwrap(),
                    item("reasons_json").extract().unwrap(),
                    item("trust_store_error").extract().unwrap(),
                )
            }

            fn admit(
                &self,
                py: Python<'_>,
                subject: &str,
                context_id: &str,
                records_json: &str,
            ) -> PyResult<()> {
                self.scp
                    .check_capability_requirements(py, context_id, subject, "[]", records_json)
            }
        }

        #[test]
        fn trust_create_challenge_below_minimum_and_malformed_cases() {
            setup();
            Python::with_gil(|py| {
                let scp = default_scp();
                let v = identity(py, &scp);
                // The challenger ledger lives on the supervisor a context attaches.
                context_with(py, &scp, &v, &serde_json::json!([])).unwrap();
                assert_code(
                    create(py, &scp, &v, VALID_DID, "ctx", &test_cases_json(19)),
                    codes::VALID_7039,
                );
                assert_code(
                    create(py, &scp, &v, VALID_DID, "ctx", r#"{"not":"an array"}"#),
                    codes::VALID_7002,
                );
                assert_code(
                    create(py, &scp, &v, &v, "ctx", &test_cases_json(20)),
                    codes::VALID_7127,
                );
            });
        }

        #[test]
        fn trust_create_challenge_destroyed_key_is_crypto_4006() {
            setup();
            Python::with_gil(|py| {
                let scp = default_scp();
                let v = identity(py, &scp);
                // The challenger ledger lives on the supervisor a context attaches.
                context_with(py, &scp, &v, &serde_json::json!([])).unwrap();
                let (custody, _, active) = keys(&scp, &v);
                crate::runtime()
                    .unwrap()
                    .block_on(custody.destroy_key(&active))
                    .unwrap();
                assert_code(
                    create(py, &scp, &v, VALID_DID, "ctx", &test_cases_json(20)),
                    codes::CRYPTO_4006,
                );
            });
        }

        #[test]
        fn trust_grade_response_rejects_malformed_json() {
            setup();
            Python::with_gil(|py| {
                let g = Graded::new(py);
                let (_, request_json) = create(
                    py,
                    &g.scp,
                    &g.verifier,
                    &g.subject,
                    &g.context_id,
                    &test_cases_json(20),
                )
                .unwrap();
                for request in ["bad", request_json.as_str()] {
                    assert_code(
                        g.scp.trust_grade_response(py, &g.verifier, request, "bad"),
                        codes::VALID_7002,
                    );
                }
            });
        }

        #[test]
        fn trust_create_respond_grade_round_trip_with_production_resolver() {
            setup();
            Python::with_gil(|py| {
                let g = Graded::new(py);
                let (_, v_identity, v_active) = keys(&g.scp, &g.verifier);
                let (_, s_identity, s_active) = keys(&g.scp, &g.subject);
                // `#0` and `#active` differ, so only an `#active` lookup verifies.
                assert_ne!(v_identity, v_active);
                assert_ne!(s_identity, s_active);

                let (record_json, reasons_json, trust_store_error) = g.grade(py);
                assert_eq!(trust_store_error, None);
                let reasons: Vec<scp_core::trust::CaseResult> =
                    serde_json::from_str(&reasons_json).unwrap();
                assert_eq!(reasons.len(), 20);
                let record: scp_core::trust::ChallengeVerification =
                    serde_json::from_str(&record_json).unwrap();
                assert!(record.passed, "{record:?}");
                assert_eq!((record.attempt, record.pass_count), (1, 20));
                assert_eq!(record.subject, g.subject);
                assert_eq!(record.context_id, g.context_id);

                let resolver = crate::runtime::did_resolver(&g.scp.inner).unwrap();
                let check = |resolver: &dyn scp_core::trust::attestation::ActiveKeyResolver| {
                    scp_core::trust::verify_challenge_verification(
                        &record,
                        resolver,
                        &scp_core::trust::ProtocolOnlyDefinitions,
                        &g.context_id,
                        &g.subject,
                        &scp_clock::SystemClock,
                    )
                };
                check(resolver.as_ref()).unwrap();
                // Negative: the `#0` key does not verify the record.
                let identity_key = check(&scp_core::trust::IdentityDidPublicKeyResolver);
                assert!(
                    matches!(
                        identity_key,
                        Err(
                            scp_core::trust::TrustError::ChallengeVerificationSignatureInvalid { .. }
                        )
                    ),
                    "{identity_key:?}"
                );

                // The context's governed requirement admits the subject with
                // the record, and refuses it without one.
                g.admit(py, &g.subject, &g.context_id, &format!("[{record_json}]"))
                    .unwrap();
                assert_code(
                    g.admit(py, &g.subject, &g.context_id, "[]"),
                    codes::VALID_7076,
                );
            });
        }

        #[test]
        fn context_create_refuses_malformed_capability_requirements() {
            setup();
            Python::with_gil(|py| {
                let scp = default_scp();
                let creator = identity(py, &scp);
                for bad in [
                    serde_json::json!("not an array"),
                    serde_json::json!([{ "capability": SCHEMA_URI }]),
                ] {
                    assert!(context_with(py, &scp, &creator, &bad).is_err());
                }
            });
        }

        #[test]
        fn check_capability_requirements_rejects_malformed_inputs_and_unknown_context() {
            setup();
            Python::with_gil(|py| {
                let scp = default_scp();
                let creator = identity(py, &scp);
                let ctx = context_with(py, &scp, &creator, &self_attested()).unwrap();
                let check = |ctx: &str, caps: &str, records: &str| {
                    scp.check_capability_requirements(py, ctx, VALID_DID, caps, records)
                };
                assert_code(check(&ctx, "not json", "[]"), codes::VALID_7074);
                assert_code(check(&ctx, "[]", "not json"), codes::VALID_7075);
                assert_code(check("ctx-never-created", "[]", "[]"), codes::CTX_2001);
            });
        }

        /// The requirement comes from the context's governance: with none,
        /// empty inputs pass; with a `SelfAttested` one, the declared
        /// capability decides.
        #[test]
        fn check_capability_requirements_reads_the_context_requirement() {
            setup();
            Python::with_gil(|py| {
                let scp = default_scp();
                let creator = identity(py, &scp);
                let open = context_with(py, &scp, &creator, &serde_json::json!([])).unwrap();
                let gated = context_with(py, &scp, &creator, &self_attested()).unwrap();
                let check = |ctx: &str, caps: &str| {
                    scp.check_capability_requirements(py, ctx, VALID_DID, caps, "[]")
                };
                check(&open, "[]").unwrap();
                check(&gated, &format!(r#"["{SCHEMA_URI}"]"#)).unwrap();
                assert_code(check(&gated, "[]"), codes::VALID_7076);
            });
        }

        /// Which key re-signs a graded record.
        enum CvSigner {
            /// The verifier's self-certifying identity key `#0`, through its
            /// custody.
            IdentityKey,
            /// A key unrelated to the verifier's DID.
            Unrelated,
        }

        /// A record signed by the verifier's `#active` key, which differs
        /// from `#0`, is admitted; the same record re-signed by `#0` or by an
        /// unrelated key is dropped, so the requirement is unmet.
        #[test]
        fn check_capability_requirements_admits_only_active_key_records() {
            setup();
            Python::with_gil(|py| {
                let g = Graded::new(py);
                let (record_json, _, _) = g.grade(py);
                g.admit(py, &g.subject, &g.context_id, &format!("[{record_json}]"))
                    .unwrap();
                let (custody, v_identity, _) = keys(&g.scp, &g.verifier);
                for signer in [CvSigner::IdentityKey, CvSigner::Unrelated] {
                    let mut record: scp_core::trust::ChallengeVerification =
                        serde_json::from_str(&record_json).unwrap();
                    let digest =
                        scp_core::trust::challenge_verification_signing_digest(&record).unwrap();
                    record.verifier_signature = match signer {
                        CvSigner::IdentityKey => crate::runtime()
                            .unwrap()
                            .block_on(custody.sign(&v_identity, &digest))
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
                            py,
                            &g.subject,
                            &g.context_id,
                            &serde_json::to_string(&[record]).unwrap(),
                        ),
                        codes::VALID_7076,
                    );
                }
            });
        }

        #[test]
        fn check_capability_requirements_binds_subject_and_context() {
            setup();
            Python::with_gil(|py| {
                let g = Graded::new(py);
                let records = format!("[{}]", g.grade(py).0);
                // Control: the record admits its own subject in its own context.
                g.admit(py, &g.subject, &g.context_id, &records).unwrap();
                // Cross-subject replay.
                assert_code(
                    g.admit(py, VALID_DID, &g.context_id, &records),
                    codes::VALID_7076,
                );
                // Cross-context replay, into a context with the same requirement.
                let other =
                    context_with(py, &g.scp, &g.verifier, &challenge_requirement(&g.verifier))
                        .unwrap();
                assert_ne!(other, g.context_id);
                assert_code(g.admit(py, &g.subject, &other, &records), codes::VALID_7076);
            });
        }
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_events_json() {
        pyo3::prepare_freethreaded_python();
        let result = Python::with_gil(|py| {
            default_scp().aggregate_trust_input(
                py,
                "ctx-1",
                "did:key:test",
                "not json",
                "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
                "[]",
                "{}",
                "{}",
                "[]",
                "[]",
            )
        });
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains(scp_ffi_common::error_codes::VALID_7042),
            "expected {}, got: {err_str}",
            scp_ffi_common::error_codes::VALID_7042
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_wrong_merkle_root_length() {
        pyo3::prepare_freethreaded_python();
        let result = Python::with_gil(|py| {
            default_scp().aggregate_trust_input(
                py,
                "ctx-1",
                "did:key:test",
                "[]",
                "[0,0,0]",
                "[]",
                "{}",
                "{}",
                "[]",
                "[]",
            )
        });
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains(scp_ffi_common::error_codes::VALID_7044),
            "expected {}, got: {err_str}",
            scp_ffi_common::error_codes::VALID_7044
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_empty_did() {
        pyo3::prepare_freethreaded_python();
        let result = Python::with_gil(|py| {
            default_scp().aggregate_trust_input(
                py,
                "ctx-1",
                "",
                "[]",
                "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
                "[]",
                "{}",
                "{}",
                "[]",
                "[]",
            )
        });
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains(scp_ffi_common::error_codes::VALID_7041),
            "expected {}, got: {err_str}",
            scp_ffi_common::error_codes::VALID_7041
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_empty_context() {
        pyo3::prepare_freethreaded_python();
        pyo3::prepare_freethreaded_python();
        let result = Python::with_gil(|py| {
            default_scp().aggregate_trust_input(
                py,
                "",
                "did:key:test",
                "[]",
                "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
                "[]",
                "{}",
                "{}",
                "[]",
                "[]",
            )
        });
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains(scp_ffi_common::error_codes::VALID_7040),
            "expected {}, got: {err_str}",
            scp_ffi_common::error_codes::VALID_7040
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_merkle_root_json() {
        pyo3::prepare_freethreaded_python();
        pyo3::prepare_freethreaded_python();
        let result = Python::with_gil(|py| {
            default_scp().aggregate_trust_input(
                py,
                "ctx-1",
                "did:key:test",
                "[]",
                "not json",
                "[]",
                "{}",
                "{}",
                "[]",
                "[]",
            )
        });
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains(scp_ffi_common::error_codes::VALID_7043),
            "expected {}, got: {err_str}",
            scp_ffi_common::error_codes::VALID_7043
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_consequence_rules_json() {
        pyo3::prepare_freethreaded_python();
        pyo3::prepare_freethreaded_python();
        let result = Python::with_gil(|py| {
            default_scp().aggregate_trust_input(
                py,
                "ctx-1",
                "did:key:test",
                "[]",
                "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
                "not json",
                "{}",
                "{}",
                "[]",
                "[]",
            )
        });
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains(scp_ffi_common::error_codes::VALID_7045),
            "expected {}, got: {err_str}",
            scp_ffi_common::error_codes::VALID_7045
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_threshold_requirements_json() {
        pyo3::prepare_freethreaded_python();
        pyo3::prepare_freethreaded_python();
        let result = Python::with_gil(|py| {
            default_scp().aggregate_trust_input(
                py,
                "ctx-1",
                "did:key:test",
                "[]",
                "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
                "[]",
                "not json",
                "{}",
                "[]",
                "[]",
            )
        });
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains(scp_ffi_common::error_codes::VALID_7046),
            "expected {}, got: {err_str}",
            scp_ffi_common::error_codes::VALID_7046
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_attestor_sets_json() {
        pyo3::prepare_freethreaded_python();
        pyo3::prepare_freethreaded_python();
        let result = Python::with_gil(|py| {
            default_scp().aggregate_trust_input(
                py,
                "ctx-1",
                "did:key:test",
                "[]",
                "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
                "[]",
                "{}",
                "not json",
                "[]",
                "[]",
            )
        });
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains(scp_ffi_common::error_codes::VALID_7047),
            "expected {}, got: {err_str}",
            scp_ffi_common::error_codes::VALID_7047
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_cached_attestations_json() {
        pyo3::prepare_freethreaded_python();
        pyo3::prepare_freethreaded_python();
        let result = Python::with_gil(|py| {
            default_scp().aggregate_trust_input(
                py,
                "ctx-1",
                "did:key:test",
                "[]",
                "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
                "[]",
                "{}",
                "{}",
                "not json",
                "[]",
            )
        });
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains(scp_ffi_common::error_codes::VALID_7048),
            "expected {}, got: {err_str}",
            scp_ffi_common::error_codes::VALID_7048
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_challenge_results_json() {
        pyo3::prepare_freethreaded_python();
        pyo3::prepare_freethreaded_python();
        let result = Python::with_gil(|py| {
            default_scp().aggregate_trust_input(
                py,
                "ctx-1",
                "did:key:test",
                "[]",
                "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
                "[]",
                "{}",
                "{}",
                "[]",
                "not json",
            )
        });
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains(scp_ffi_common::error_codes::VALID_7049),
            "expected {}, got: {err_str}",
            scp_ffi_common::error_codes::VALID_7049
        );
    }

    #[test]
    fn participation_record_validates_context_id() {
        pyo3::prepare_freethreaded_python();
        let result =
            Python::with_gil(|py| default_scp().participation_record(py, "", "did:key:test", "[]"));
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains(scp_ffi_common::error_codes::VALID_7000),
            "expected {}, got: {err_str}",
            scp_ffi_common::error_codes::VALID_7000
        );
    }

    #[test]
    fn participation_record_validates_did() {
        pyo3::prepare_freethreaded_python();
        let result = Python::with_gil(|py| {
            default_scp().participation_record(py, "ctx-1", "not-a-did", "[]")
        });
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains(scp_ffi_common::error_codes::VALID_7000),
            "expected {}, got: {err_str}",
            scp_ffi_common::error_codes::VALID_7000
        );
    }

    #[test]
    fn participation_record_rejects_invalid_attestations_json() {
        pyo3::prepare_freethreaded_python();
        let result = Python::with_gil(|py| {
            default_scp().participation_record(py, "ctx-1", "did:key:test", "not json")
        });
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains(scp_ffi_common::error_codes::VALID_7059),
            "expected {}, got: {err_str}",
            scp_ffi_common::error_codes::VALID_7059
        );
    }

    /// The typed `PyParticipationRecord` surfaces every flattened fact from the
    /// shared `ParticipationFacts` projection with byte-identical values.
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
        let view = PyParticipationRecord::from(&facts);
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
        assert_eq!(view.event_log_root, encode_hex(&[7u8; 32]));
    }
}
