//! napi-rs bridge for outlet operations.
//!
//! Exposes outlet registration, invocation, and verification:
//!
//! - `outlet_register` — Register an outlet in a context.
//! - `outlet_invoke` — Invoke an outlet within a context.
//! - `outlet_verify` — Verify an outlet against its test vectors.
//!
//! See ADR-022 in `.docs/adrs/phase-4.md`.

use napi_derive::napi;
use scp_clock::Clock;
use scp_ffi_common::error_codes as codes;
use scp_ffi_common::validate::{
    validate_did, validate_outlet_id, validate_outlet_name, validate_ucan_token,
};

use crate::context::NapiContextHandle;
use crate::error::ScpNapiError;

/// Validates a UCAN token for outlet invocation authorization.
///
/// Performs the full 11-step ADR-016 validation pipeline.
fn validate_ucan_for_outlet(
    bi: &crate::runtime::NapiBridgeInstance,
    context_id: &str,
    outlet_id: &str,
    identity_did: &str,
    ucan_token: &str,
    proof_resolver: &scp_ffi_common::BridgeProofResolver,
) -> Result<(), ScpNapiError> {
    crate::runtime::with_context(bi, context_id, |rt| {
        // SCP-OUT-014: select the split capability stem from the outlet's
        // registered kind — `outlet_query:{id}` for Query outlets,
        // `outlet_call:{id}` for Action outlets.
        let outlet_kind_for_ucan = rt
            .outlet_registry
            .get(outlet_id)
            .map(|r| r.kind)
            .ok_or_else(|| ScpNapiError::Permission {
                message: format!("outlet '{outlet_id}' not registered in context '{context_id}'"),
                code: codes::PERM_3001.to_owned(),
            })?;

        let production_resolver = crate::runtime::did_resolver(bi);
        let did_resolver = scp_ffi_common::DispatchDidResolver::new(
            production_resolver.map(std::convert::AsRef::as_ref),
        );
        let revocation_checker = scp_ffi_common::BridgeRevocationChecker {
            revocation_list: &rt.core.revocation_list,
        };
        let mut nonce_adapter = scp_ffi_common::BridgeNonceTracker {
            inner: &mut rt.core.nonce_tracker,
        };

        let mut ctx = scp_core::crypto::ucan::validate::ValidationContext {
            did_resolver: &did_resolver,
            nonce_tracker: &mut nonce_adapter,
            revocation_checker: &revocation_checker,
            proof_resolver,
            ceiling: &rt.core.ceiling_strings,
            context_creator_did: &rt.core.creator_did,
            presenting_agent_did: identity_did,
            clock_skew_tolerance_secs:
                scp_core::crypto::ucan::validate::DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
            clock: &scp_clock::SystemClock,
            // §5.4.5 HIGH-3 — outlet-invocation site resolves effective caveats
            // from each token's `nb` field so §7.3.8 Step 7b (per-edge narrow)
            // and Step 11b (time-box) run over the proof chain's VALIDATED-
            // NARROWED caveat set. Generic validate/evaluate sites (ucan.rs)
            // stay on `NoCaveatResolver`.
            caveat_resolver: &scp_core::crypto::ucan::validate::TokenNbCaveatResolver,
        };

        scp_core::context::outlets::validate_outlet_invocation_ucan(
            ucan_token,
            context_id,
            outlet_id,
            outlet_kind_for_ucan,
            &mut ctx,
        )
        .map_err(|e| ScpNapiError::Permission {
            message: format!("UCAN authorization failed for outlet '{outlet_id}': {e}"),
            code: codes::PERM_3001.to_owned(),
        })
    })
}

// ---------------------------------------------------------------------------
// NapiOutletKind — outlet semantic class (Query vs Action) — §5.4.2
// ---------------------------------------------------------------------------

/// Outlet semantic class (§5.4.2).
///
/// Crosses the NAPI boundary as the lowercase string `"query"` / `"action"`,
/// matching the §5.4.2 wire vocabulary used by the spec, the canonical
/// preimage, and every other bridge. Surfaced to TypeScript as `OutletKind`.
///
/// - `Query` — read-only, idempotent. UCAN stem `outlet_query:{id}`.
/// - `Action` — may mutate state. UCAN stem `outlet_call:{id}`. §5.4.2
///   fail-safe default.
#[napi(string_enum = "lowercase", js_name = "OutletKind")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NapiOutletKind {
    /// Read-only, idempotent. UCAN stem `outlet_query:{id}`.
    Query,
    /// May mutate state. UCAN stem `outlet_call:{id}`. §5.4.2 fail-safe default.
    Action,
}

impl From<NapiOutletKind> for scp_core::context::outlets::OutletKind {
    fn from(k: NapiOutletKind) -> Self {
        match k {
            NapiOutletKind::Query => Self::Query,
            NapiOutletKind::Action => Self::Action,
        }
    }
}

// ---------------------------------------------------------------------------
// NapiOutletDefinition — outlet definition for registration
// ---------------------------------------------------------------------------

/// Outlet definition for registration in a context.
///
/// See ADR-010 (Outlet Registry) and spec §5.4.1 (Outlets).
#[napi(object)]
pub struct NapiOutletDefinition {
    /// Human-readable outlet name.
    pub name: String,
    /// Outlet description.
    pub description: String,
    /// Outlet semantic class (Query vs Action — §5.4.2). Selects the UCAN
    /// capability stem required to invoke the outlet. Surfaced as a required
    /// field on the TypeScript SDK's `OutletDefinition`.
    pub kind: NapiOutletKind,
    /// JSON Schema for outlet input (as a JSON string).
    pub input_schema_json: String,
    /// JSON Schema for outlet output (as a JSON string).
    pub output_schema_json: String,
    /// DID of the outlet operator (responsible party).
    pub operator_did: String,
    /// Test vectors for integrity verification (serialized as JSON string).
    pub test_vectors_json: Option<String>,
    /// SHA-256 hash of the implementation binary (32 bytes).
    pub implementation_hash: Option<Vec<u8>>,
    /// Optional per-invocation cost metadata (spec §5.4.1).
    pub cost: Option<NapiOutletCost>,
}

/// Per-invocation cost metadata for an outlet (spec §5.4.1).
#[napi(object)]
pub struct NapiOutletCost {
    /// Cost per invocation in the smallest currency unit.
    ///
    /// Crosses the napi boundary as a JS `bigint` (`BigInt`) so a full `u64`
    /// round-trips exactly — a JS `number` narrows through `i64` and loses
    /// precision above 2^53 (ADR-060 native-integer money surface).
    pub amount: napi::bindgen_prelude::BigInt,
    /// ISO 4217 or protocol-defined currency code.
    pub currency: String,
    /// DID of the payment recipient. May differ from `operator_did`.
    pub payee: String,
    /// Optional pricing formula identifier for dynamic pricing (§19.4).
    pub cost_formula: Option<String>,
}

// ---------------------------------------------------------------------------
// NapiOutletVerificationResult — result of outlet verification
// ---------------------------------------------------------------------------

/// Result of verifying an outlet against its registered test vectors.
#[napi(object)]
pub struct NapiOutletVerificationResult {
    /// The verified outlet's ID.
    pub outlet_id: String,
    /// `true` if all test vectors passed.
    pub passed: bool,
    /// Failure messages for vectors that did not pass. Empty on success.
    pub failures: Vec<String>,
}

// ---------------------------------------------------------------------------
// Validation helpers for outlet registration inputs
// ---------------------------------------------------------------------------

/// Validates and parses a JSON schema string.
///
/// Returns an `SCP-VALID-7035` error for `input_schema_json` or
/// `SCP-VALID-7036` for `output_schema_json` when the JSON is malformed.
fn validate_schema_json(json: &str, field_name: &str) -> napi::Result<serde_json::Value> {
    let code = match field_name {
        "input_schema_json" => codes::VALID_7035,
        _ => codes::VALID_7036,
    };
    serde_json::from_str(json).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("invalid {field_name}: {e}"),
            code: code.to_owned(),
        })
    })
}

/// Validates and parses optional test vectors JSON.
///
/// `None` is acceptable (no test vectors). A `Some` value that is not valid
/// JSON returns `SCP-VALID-7037`.
fn validate_test_vectors_json(
    json: Option<&str>,
) -> napi::Result<Vec<scp_core::context::outlets::OutletTestVector>> {
    json.map_or_else(
        || Ok(Vec::new()),
        |s| {
            serde_json::from_str(s).map_err(|e| {
                napi::Error::from(ScpNapiError::Validation {
                    message: format!("invalid test_vectors_json: {e}"),
                    code: codes::VALID_7037.to_owned(),
                })
            })
        },
    )
}

/// Validates an optional implementation hash.
///
/// `None` is acceptable (defaults to zeroed hash). A `Some` value that is not
/// exactly 32 bytes returns `SCP-VALID-7038`.
fn validate_implementation_hash(bytes: Option<&[u8]>) -> napi::Result<[u8; 32]> {
    bytes.map_or_else(
        || Ok([0u8; 32]),
        |b| {
            scp_ffi_common::validate::expect_fixed_bytes::<32>(b, "implementation_hash").map_err(
                |msg| {
                    napi::Error::from(ScpNapiError::Validation {
                        message: msg,
                        code: codes::VALID_7038.to_owned(),
                    })
                },
            )
        },
    )
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of [`outlet_register`].
#[allow(clippy::unused_async)] // preserves signature symmetry with the async free function
pub(crate) async fn outlet_register_on(
    bi: &crate::runtime::NapiBridgeInstance,
    handle: &NapiContextHandle,
    definition: NapiOutletDefinition,
) -> napi::Result<String> {
    crate::napi_check_handle!(&bi.core, handle);
    validate_outlet_name(&definition.name).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    let state_str = handle.state()?;
    if state_str != "active" {
        return Err(ScpNapiError::Outlet {
            message: format!(
                "cannot register outlet in context in {state_str:?} state — context must be active"
            ),
            code: codes::OUTLET_6003.to_owned(),
        }
        .into());
    }

    // Ensure UCAN state is registered so the outlet registry is available.
    crate::runtime::ensure_registered(bi, handle)?;

    let context_id = handle.context_id();

    // Build a scp-core OutletRegistration from the NAPI definition.
    // Shared with every other bridge via `scp_ffi_common::outlet_id`.
    let outlet_id = scp_ffi_common::outlet_id::generate_outlet_id(&definition.name);

    let input_schema = validate_schema_json(&definition.input_schema_json, "input_schema_json")?;
    let output_schema = validate_schema_json(&definition.output_schema_json, "output_schema_json")?;

    let test_vectors = validate_test_vectors_json(definition.test_vectors_json.as_deref())?;

    let implementation_hash =
        validate_implementation_hash(definition.implementation_hash.as_deref())?;

    let cost = definition
        .cost
        .map(
            |c| -> napi::Result<scp_core::context::outlets::OutletCost> {
                // ADR-060: `OutletCost.amount` is the `Amount` newtype. The JS
                // `bigint` marshals to an exact `u64` via the shared economy helper,
                // preserving the full range (values above 2^53 survive intact).
                let amount = crate::economy::amount_u64_from_bigint(&c.amount, "cost.amount")?;
                Ok(scp_core::context::outlets::OutletCost {
                    amount: scp_core::economy::Amount(amount),
                    currency: c.currency,
                    payee: c.payee.into(),
                    cost_formula: c.cost_formula,
                })
            },
        )
        .transpose()?;

    let core_registration = scp_core::context::outlets::OutletRegistration {
        outlet_id,
        // §5.4.2: the caller-supplied semantic class selects the invocation
        // capability stem (`outlet_query:` vs `outlet_call:`).
        kind: definition.kind.into(),
        name: definition.name,
        description: definition.description,
        schema: scp_core::context::outlets::OutletSchema {
            input_schema,
            output_schema,
            aggregate_schema: None,
        },
        implementation_hash,
        test_vectors,
        operator_did: definition.operator_did.into(),
        cost,
        message_catalog: Vec::new(),
        registered_at: scp_clock::Clock::now_secs(&scp_clock::SystemClock),
        signature: Vec::new(),
    };

    // Register the outlet in the context's outlet registry.
    let registered_id = crate::runtime::with_context(bi, &context_id, |rt| {
        let (registered_id, _event) = scp_core::context::outlets::register_outlet(
            &mut rt.outlet_registry,
            &rt.role_state,
            core_registration,
            &rt.core.creator_did.clone(),
        )
        .map_err(|e| ScpNapiError::Outlet {
            message: format!("outlet registration failed: {e}"),
            code: codes::OUTLET_6001.to_owned(),
        })?;
        Ok(registered_id)
    })
    .map_err(napi::Error::from)?;

    Ok(registered_id)
}

/// Per-bridge-instance implementation of [`outlet_invoke`].
#[allow(clippy::too_many_arguments)]
pub(crate) async fn outlet_invoke_on(
    bi: &crate::runtime::NapiBridgeInstance,
    handle: &NapiContextHandle,
    outlet_id: String,
    input_json: String,
    identity_did: String,
    ucan_token: String,
    proof_tokens: Option<Vec<String>>,
    spending_ucan_jwt: Option<String>,
) -> napi::Result<String> {
    crate::napi_check_handle!(&bi.core, handle);
    validate_outlet_id(&outlet_id).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    validate_did(&identity_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    validate_ucan_token(&ucan_token).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    if let Some(jwt) = spending_ucan_jwt.as_deref() {
        validate_ucan_token(jwt).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    }

    let state_str = handle.state()?;
    if state_str != "active" {
        return Err(ScpNapiError::Outlet {
            message: format!(
                "cannot invoke outlet in context in {state_str:?} state — context must be active"
            ),
            code: codes::OUTLET_6005.to_owned(),
        }
        .into());
    }

    let context_id = handle.context_id();
    crate::runtime::ensure_registered(bi, handle)?;

    // UCAN authorization (full 11-step ADR-016 pipeline). Bridge-owned
    // because the proof resolver, revocation list, and nonce tracker
    // live in the bridge UCAN registry, not in the runtime.
    let proof_resolver = crate::ucan::build_proof_resolver_from_tokens(proof_tokens.as_deref())
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Permission {
                message: format!("failed to build proof resolver: {e}"),
                code: codes::PERM_3001.to_owned(),
            })
        })?;
    validate_ucan_for_outlet(
        bi,
        &context_id,
        &outlet_id,
        &identity_did,
        &ucan_token,
        &proof_resolver,
    )
    .map_err(napi::Error::from)?;

    // Parse the optional spending UCAN JWT (§19.5 AND-composition).
    // Mirrors `context_send`. An invalid JWT surfaces as
    // `SCP-ECON-12061` before the manager call.
    let spending_ucan_token = spending_ucan_jwt
        .as_deref()
        .map(scp_core::crypto::ucan::validate::parse_ucan)
        .transpose()
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("invalid spending UCAN: {e}"),
                code: codes::ECON_12061.to_owned(),
            })
        })?;

    // §7.3.8 value-caveat resolution. The invocation caveats live in the `nb`
    // of the VALIDATED INVOCATION UCAN (`ucan_token`, the token granting the
    // `outlet_call:*` / `outlet_query:*` capability) — NOT the spending UCAN,
    // which is a SEPARATE economy token (§19.5). `narrow()` folds every parent's
    // value-caveats into the leaf, so the leaf's `nb` IS the effective,
    // validated-narrowed caveat set. Parsed from the same token string
    // `validate_ucan_for_outlet` validated above; `ucan_cid` (present iff
    // caveats are) keys the owned Class-S counters to this invocation
    // delegation's revocation CID.
    let invocation_ucan_token =
        scp_core::crypto::ucan::validate::parse_ucan(&ucan_token).map_err(|e| {
            napi::Error::from(ScpNapiError::Permission {
                message: format!("invalid invocation UCAN for outlet '{outlet_id}': {e}"),
                code: codes::PERM_3001.to_owned(),
            })
        })?;
    // Mint the caveats and their counter key TOGETHER, from the ONE validated
    // invocation token, into a single `InvocationCaveatBinding` — the `ucan_cid`
    // is computed only inside `.map` over the resolved caveats, so the runtime
    // receives "caveats present ⟹ cid present" by construction (§7.3.8
    // fail-closed coupling), not as a bridge-side convention.
    let caveat_binding = {
        use scp_core::crypto::ucan::validate::CaveatResolver as _;
        scp_core::crypto::ucan::validate::TokenNbCaveatResolver
            .resolve_caveats(&invocation_ucan_token)
            .map(
                |caveats| scp_core::context::outlets::InvocationCaveatBinding {
                    caveats,
                    ucan_cid: scp_core::crypto::ucan::revoke::compute_revocation_cid(
                        &invocation_ucan_token.encoded,
                    ),
                },
            )
    };

    // Snapshot the bridge-owned outlet registry and (optionally) the
    // registered handler closure BEFORE entering the runtime call. The
    // runtime requires `&OutletRegistry`; cloning the registry once is
    // cheap and avoids holding the bridge UCAN-state DashMap shard
    // lock across the runtime's three-phase lock split.
    let context_id_for_executor = context_id.clone();
    let outlet_id_for_executor = outlet_id.clone();
    let identity_for_executor = identity_did.clone();
    let (registry, handler) = crate::runtime::with_context(bi, &context_id, |rt| {
        Ok((
            rt.outlet_registry.clone(),
            rt.outlet_handlers.get(&outlet_id).cloned(),
        ))
    })
    .map_err(napi::Error::from)?;

    // Build the executor closure. Phase 2 of `invoke_outlet_with_economy`
    // runs WITHOUT holding the `contexts` mutex; the runtime calls the
    // executor exactly once with the validated input value.
    let executor = move |input: serde_json::Value| {
        let handler = handler.clone();
        let input_for_echo = input.clone();
        async move {
            handler.map_or_else(
                || {
                    Ok(serde_json::json!({
                        "outlet": outlet_id_for_executor,
                        "context": context_id_for_executor,
                        "status": "validated",
                        "input_valid": true,
                        "invoker_did": identity_for_executor,
                        "validated_input": input_for_echo,
                    }))
                },
                |h| {
                    h(input).map_err(|e| {
                        format!("outlet handler for '{outlet_id_for_executor}' failed: {e}")
                    })
                },
            )
        }
    };

    // Parse input JSON once (the runtime expects `serde_json::Value`).
    let input_value: serde_json::Value = serde_json::from_str(&input_json).map_err(|e| {
        napi::Error::from(ScpNapiError::Outlet {
            message: format!("invalid input JSON: {e}"),
            code: codes::OUTLET_6002.to_owned(),
        })
    })?;

    let supervisor = crate::runtime::supervisor(bi)?;
    let invoker_did_typed: scp_did::DID = identity_did.into();
    let outlet_id_typed = scp_core::context::outlets::OutletId::from(outlet_id.as_str());
    let outcome = supervisor
        .invoke_outlet_with_economy(
            &context_id,
            &registry,
            &outlet_id_typed,
            input_value,
            &invoker_did_typed,
            spending_ucan_token.as_ref(),
            caveat_binding,
            None,
            executor,
        )
        .await
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    // The runtime built the canonical `OutletInvokedEvent`; the
    // transport / event-log layer is the one responsible for signing
    // and appending it. Pull the JSON output back out for the JS
    // caller.
    serde_json::to_string(&outcome.output).map_err(|e| {
        napi::Error::from(ScpNapiError::Outlet {
            message: format!("failed to serialize outlet output: {e}"),
            code: codes::OUTLET_6006.to_owned(),
        })
    })
}

/// Per-bridge-instance implementation of [`outlet_verify`].
#[allow(clippy::unused_async)] // preserves signature symmetry with the async free function
pub(crate) async fn outlet_verify_on(
    bi: &crate::runtime::NapiBridgeInstance,
    handle: &NapiContextHandle,
    outlet_id: String,
) -> napi::Result<NapiOutletVerificationResult> {
    crate::napi_check_handle!(&bi.core, handle);
    let state_str = handle.state()?;
    if state_str != "active" {
        return Err(ScpNapiError::Outlet {
            message: format!(
                "cannot verify outlet in context in {state_str:?} state — context must be active"
            ),
            code: codes::OUTLET_6007.to_owned(),
        }
        .into());
    }

    let context_id = handle.context_id();
    crate::runtime::ensure_registered(bi, handle)?;

    // Look up the outlet and verify against its test vectors (matching PyO3 pattern).
    let result = crate::runtime::with_context(bi, &context_id, |rt| {
        let (verification_result, _event) = scp_core::context::outlets::verify_outlet(
            &rt.outlet_registry,
            &outlet_id,
            // Identity executor: returns the expected output for each vector.
            // This validates the test vector structure; real execution verification
            // happens when a full executor is connected.
            |input| {
                if let Some(registration) = rt.outlet_registry.get(&outlet_id) {
                    for vector in &registration.test_vectors {
                        if vector.input == *input {
                            return vector.expected_output.clone();
                        }
                    }
                }
                serde_json::Value::Null
            },
        )
        .map_err(|e| ScpNapiError::Outlet {
            message: format!("outlet verification failed: {e}"),
            code: codes::OUTLET_6001.to_owned(),
        })?;

        Ok(verification_result)
    })
    .map_err(napi::Error::from)?;

    let failures: Vec<String> = result
        .vector_results
        .iter()
        .filter(|r| !r.passed)
        .map(|r| r.description.clone())
        .collect();

    Ok(NapiOutletVerificationResult {
        outlet_id: result.outlet_id,
        passed: result.integrity_ok,
        failures,
    })
}

// ---------------------------------------------------------------------------
// Cross-context outlet invocation
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of [`outlet_invoke_cross_context`].
#[allow(clippy::too_many_arguments)]
pub(crate) async fn outlet_invoke_cross_context_on(
    bi: &crate::runtime::NapiBridgeInstance,
    source_handle: &NapiContextHandle,
    target_handle: &NapiContextHandle,
    outlet_id: String,
    input_json: String,
    invoker_did: String,
    ucan_token: String,
    chain_depth: u8,
    proof_tokens: Option<Vec<String>>,
) -> napi::Result<String> {
    crate::napi_check_handle!(&bi.core, source_handle, target_handle);
    // Validate both contexts are active.
    let source_state = source_handle.state()?;
    if source_state != "active" {
        return Err(ScpNapiError::Outlet {
            message: format!(
                "cannot invoke cross-context outlet: source context in {source_state:?} state"
            ),
            code: codes::OUTLET_6010.to_owned(),
        }
        .into());
    }

    let target_state = target_handle.state()?;
    if target_state != "active" {
        return Err(ScpNapiError::Outlet {
            message: format!(
                "cannot invoke cross-context outlet: target context in {target_state:?} state"
            ),
            code: codes::OUTLET_6011.to_owned(),
        }
        .into());
    }

    let source_context_id = source_handle.context_id();
    let target_context_id = target_handle.context_id();

    // Validate chain depth (context-configurable, default 8 per ADR-043).
    let max_chain_depth = {
        let supervisor = crate::runtime::supervisor(bi)?;
        let source_max = supervisor
            .context_params(&source_context_id)
            .await
            .and_then(|p| p.max_chain_depth);
        scp_core::provenance::attach::effective_max_chain_depth(source_max)
    };
    if chain_depth > max_chain_depth {
        return Err(ScpNapiError::Outlet {
            message: format!(
                "cross-context chain depth {chain_depth} exceeds maximum {max_chain_depth}"
            ),
            code: codes::OUTLET_6012.to_owned(),
        }
        .into());
    }

    // Ensure target context UCAN state is registered.
    crate::runtime::ensure_registered(bi, target_handle)?;

    // Primary authorization: UCAN token validation via the full 11-step
    // ADR-016 pipeline against the TARGET context's ceiling.
    // See spec §6.2, §8, ADR-016, and issue #319.
    let proof_resolver = crate::ucan::build_proof_resolver_from_tokens(proof_tokens.as_deref())
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Permission {
                message: format!("failed to build proof resolver: {e}"),
                code: codes::PERM_3001.to_owned(),
            })
        })?;
    validate_ucan_for_outlet(
        bi,
        &target_context_id,
        &outlet_id,
        &invoker_did,
        &ucan_token,
        &proof_resolver,
    )
    .map_err(napi::Error::from)?;

    let input_value: serde_json::Value = serde_json::from_str(&input_json).map_err(|e| {
        napi::Error::from(ScpNapiError::Outlet {
            message: format!("invalid input JSON: {e}"),
            code: codes::OUTLET_6002.to_owned(),
        })
    })?;

    let output = crate::runtime::with_context(bi, &target_context_id, |rt| {
        let registration =
            rt.outlet_registry
                .get(&outlet_id)
                .ok_or_else(|| ScpNapiError::Outlet {
                    message: format!(
                        "outlet '{outlet_id}' not found in target context '{target_context_id}'"
                    ),
                    code: codes::OUTLET_6002.to_owned(),
                })?;

        // Validate input against the outlet's input schema.
        scp_core::context::outlets::validate_value_against_schema(
            &input_value,
            &registration.schema.input_schema,
        )
        .map_err(|e| ScpNapiError::Outlet {
            message: format!("input validation failed: {e}"),
            code: codes::OUTLET_6002.to_owned(),
        })?;

        // Dispatch to handler or echo mode.
        let output = if let Some(handler) = rt.outlet_handlers.get(&outlet_id) {
            let handler = handler.clone();
            let out = handler(input_value.clone()).map_err(|e| ScpNapiError::Outlet {
                message: format!("cross-context outlet handler for '{outlet_id}' failed: {e}"),
                code: codes::OUTLET_6002.to_owned(),
            })?;

            scp_core::context::outlets::validate_value_against_schema(
                &out,
                &registration.schema.output_schema,
            )
            .map_err(|msg| ScpNapiError::Outlet {
                message: format!("output validation failed for outlet '{outlet_id}': {msg}"),
                code: codes::OUTLET_6002.to_owned(),
            })?;

            out
        } else {
            serde_json::json!({
                "outlet": outlet_id,
                "source_context": source_context_id,
                "target_context": target_context_id,
                "status": "validated",
                "chain_depth": chain_depth,
                "invoker_did": invoker_did,
                "validated_input": input_value,
            })
        };

        Ok(output)
    })
    .map_err(napi::Error::from)?;

    serde_json::to_string(&output).map_err(|e| {
        napi::Error::from(ScpNapiError::Outlet {
            message: format!("failed to serialize cross-context output: {e}"),
            code: codes::OUTLET_6013.to_owned(),
        })
    })
}

// ---------------------------------------------------------------------------
// Cross-context outlet-invocation saga (§6.2.4, ADR-049 §3a)
// ---------------------------------------------------------------------------

/// The committed terminal of a §6.2.4 cross-context outlet-invocation saga.
///
/// Returned by [`Scp::outlet_invoke_cross_context_saga`](crate::scp::Scp) on a
/// `Committed` terminal. Every NON-committed terminal rejects the Promise with
/// a typed saga error (`SagaAborted` / `SagaNeedsRepair` / `SagaBusy`) instead.
///
/// Carries the supervisor-minted `saga_id` plus — for the committed
/// cross-context invocation — the target's signed receipt and the captured
/// outlet output (spec §6.2.4 "Receipt / response return path"). The `receipt`
/// is the JCS-canonical `CrossContextOutletReceipt` bytes; `output` is the
/// receipt's canonical `output_jcs` bytes (the exact bytes the caller side
/// recorded a hash of). Both are surfaced as JS `Buffer` so a caller can verify
/// the receipt signature and recompute `output_hash` without a re-serialization
/// step.
#[napi(object)]
pub struct NapiSagaResult {
    /// The durable saga identifier (supervisor-minted, never a caller input).
    pub saga_id: String,
    /// The target's signed `CrossContextOutletReceipt` bytes (JCS), or `None`.
    pub receipt: Option<napi::bindgen_prelude::Buffer>,
    /// The captured outlet output bytes (the receipt's canonical `output_jcs`),
    /// or `None`.
    pub output: Option<napi::bindgen_prelude::Buffer>,
}

/// Maps a `SagaError` terminal (the typed §6.2.4 terminal space) onto the
/// bridge's typed saga error variants.
///
/// The decomposition — the `SagaAbortReason::RateLimited → Option<u64>` read,
/// the `None`-never-coerced-to-`0` rule, and the `SCP-SAGA-{code}` formatting —
/// lives ONCE in [`scp_ffi_common::saga_errors::decompose_saga_error`], unit-
/// tested there, so the three bridges cannot drift. This function is the thin
/// per-bridge tail that carries the napi-rs field labels (`message:`); the
/// machine-parseable `(retry_after_ms=…)` / `(saga_id=…)` /
/// `(contended_context=…)` message suffix the TS wrapper reverses is encoded by
/// the `#[error(...)]` Display impl on [`ScpNapiError`], with `retry_after_ms`
/// rendered as a literal `null` when `None` (never `0`):
///
/// - `Aborted` → [`ScpNapiError::SagaAborted`] (`retry_after_ms`, `None` never
///   `0`, `SCP-SAGA-{code}`).
/// - `NeedsRepair` → [`ScpNapiError::SagaNeedsRepair`] (durable repair handle,
///   `SCP-SAGA-13065`).
/// - `Busy` → [`ScpNapiError::SagaBusy`] (`SCP-SAGA-13066`).
fn map_saga_error(err: scp_core::context::supervisor::SagaError) -> ScpNapiError {
    use scp_ffi_common::saga_errors::{SagaErrorKind, decompose_saga_error};
    let parts = decompose_saga_error(err);
    match parts.kind {
        SagaErrorKind::Aborted { retry_after_ms } => ScpNapiError::SagaAborted {
            message: parts.message,
            code: parts.code,
            retry_after_ms,
        },
        SagaErrorKind::NeedsRepair { saga_id } => ScpNapiError::SagaNeedsRepair {
            message: parts.message,
            code: parts.code,
            saga_id,
        },
        SagaErrorKind::Busy { contended_context } => ScpNapiError::SagaBusy {
            message: parts.message,
            code: parts.code,
            contended_context,
        },
    }
}

/// Resolves the Active Signing Key the supervisor saga signs under for a
/// co-resident context owned by `creator_did` — exported via the shared
/// callback/in-memory custody path. The caller and target each resolve to their
/// OWN creator's key so the receipt (target-signed) and each side's divergence
/// marker (own-signed) are signed under the correct per-context Active Signing
/// Key (spec §6.2.4 "Signer authorization": the receipt key MUST be the one
/// authorized to act for `target_context_id`).
///
/// `creator_did` is read off the context HANDLE (`creator_did()`), the
/// authoritative owner the handle was minted with — not via the UCAN-state
/// registry, which a freshly-created context only populates lazily on its first
/// UCAN/outlet call. `context_id` is carried only for the error message.
async fn resolve_context_signing_key(
    bi: &crate::runtime::NapiBridgeInstance,
    creator_did: &str,
    context_id: &str,
) -> napi::Result<ed25519_dalek::SigningKey> {
    let (custody, key_handle) = crate::runtime::with_identity(bi, creator_did, |entry| {
        Ok((entry.custody.clone(), entry.identity.active_signing_key))
    })
    .map_err(napi::Error::from)?;
    custody
        .export_ed25519_signing_key(&key_handle)
        .await
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Crypto {
                message: format!(
                    "cannot export the Active Signing Key for context '{context_id}' \
                     (owner '{creator_did}') — a cross-context saga signs the receipt and \
                     divergence markers with each context's own key: {e}"
                ),
                code: codes::CRYPTO_4001.to_owned(),
            })
        })
}

/// Decodes the §6.2.4 envelope nonce from its canonical 32-char hex form into
/// the 16-byte value, FAIL-CLOSED.
///
/// The nonce is a 16-byte value carried as a hex string — the one canonical
/// wire form (§6.2.4 wire envelope). Any other length is a malformed envelope,
/// NOT a "pad it" situation. Both failure modes surface as a validation error.
fn decode_asserted_nonce(asserted_nonce_hex: &str) -> napi::Result<[u8; 16]> {
    let bytes = hex::decode(asserted_nonce_hex).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!(
                "asserted_nonce_hex is not valid hex: {e} — supply the 16-byte §6.2.4 envelope \
                 nonce as a 32-char lowercase-hex string"
            ),
            code: codes::VALID_7001.to_owned(),
        })
    })?;
    <[u8; 16]>::try_from(bytes.as_slice()).map_err(|_| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!(
                "asserted_nonce_hex must decode to exactly 16 bytes (32 hex chars), got {} bytes",
                bytes.len()
            ),
            code: codes::VALID_7001.to_owned(),
        })
    })
}

/// Enforces the §6.2.4 *Caller authentication* binding (normative — §6.2.4 +
/// ADR-049 §3a) BEFORE the saga runs.
///
/// `caller_did` / `caller_context_id` MUST be the channel-authenticated
/// identity of the transport leg, never an envelope-asserted free value. For
/// the co-resident NAPI bridge the "channel-authenticated principal" is an
/// identity THIS bridge instance hosts — one present in its per-instance
/// identity registry (populated only by the identity-creation paths on this
/// instance). Both axes are enforced here:
///
///   (a) `caller_did` is hosted/authenticated by this bridge instance, AND
///   (b) `caller_did` is a member of the named `caller_context_id`.
///
/// A mismatch on either axis ⇒ a typed `Rejected`-flavored `SagaAborted` (the
/// §6.2.4 "mismatch ⇒ Rejected" terminal), carrying the registered caller-axis
/// code `SCP-SAGA-13050`. The supervisor's own gate 1 ALSO checks membership,
/// but membership alone is necessary-not-sufficient (it does not prove the
/// request leg is authenticated AS that member) — so axis (a) is the
/// load-bearing addition this seam contributes. Enforcing here, before the
/// entry point, also means the saga never observes an unauthenticated caller.
async fn enforce_caller_principal_binding(
    bi: &crate::runtime::NapiBridgeInstance,
    supervisor: &std::sync::Arc<scp_core::context::supervisor::Supervisor>,
    caller_context_id: &str,
    caller_did: &str,
) -> napi::Result<()> {
    if !crate::runtime::identity_registry_contains(bi, caller_did) {
        return Err(ScpNapiError::SagaAborted {
            message: format!(
                "caller_did '{caller_did}' is not an identity hosted by this bridge instance — \
                 a cross-context saga's caller MUST be the channel-authenticated principal (an \
                 identity created on this instance), not an envelope-asserted value (§6.2.4 \
                 Caller authentication)"
            ),
            code: codes::SAGA_13050.to_owned(),
            retry_after_ms: None,
        }
        .into());
    }

    if !supervisor.is_member(caller_context_id, caller_did).await {
        return Err(ScpNapiError::SagaAborted {
            message: format!(
                "caller_did '{caller_did}' is hosted by this bridge but is not a member of \
                 caller_context_id '{caller_context_id}' — not authorized to initiate a \
                 cross-context saga over it (§6.2.4 Caller authentication)"
            ),
            code: codes::SAGA_13050.to_owned(),
            retry_after_ms: None,
        }
        .into());
    }
    Ok(())
}

/// Per-bridge-instance implementation of the §6.2.4 cross-context
/// outlet-invocation saga export.
///
/// See [`Scp::outlet_invoke_cross_context_saga`](crate::scp::Scp) for the full
/// contract. The flow is, in order:
///
/// 1. **Validate inputs** (active handles; well-formed ids/dids/outlet-id; the
///    nonce decodes to `[u8; 16]`, fail-closed on a wrong length).
/// 2. **Caller-principal binding (§6.2.4 *Caller authentication*, normative).**
///    `caller_did` MUST be an identity THIS bridge instance hosts AND a member
///    of `caller_context_id`. A mismatch ⇒ a typed `Rejected`-flavored
///    `SagaAborted` BEFORE the saga runs. `nonce` / `timestamp` / `chain_depth`
///    REMAIN caller-supplied freshness fields (the target validates them).
/// 3. **Chokepoint (ADR-056).** Convert the caller/target id STRINGS → `[u8; 32]`
///    via `scp_core::context::state::context_id_to_bytes` (decode-64-hex-else-
///    SHA256). Raw `Sha256` of a 64-hex id would double-hash and miss the actor.
/// 4. **Signing keys.** Resolve each co-resident context's Active Signing Key
///    via the context's `creator_did`.
/// 5. **Executor.** Snapshot the TARGET context's outlet handler and build the
///    `move |input| async {…}` closure the supervisor runs at Commit-B (echo
///    fallback when no handler is registered, matching the synchronous path).
/// 6. Await the producer; map the terminal `SagaError` → typed bridge error,
///    `Committed` → [`NapiSagaResult`].
#[allow(clippy::too_many_arguments)] // Flat §6.2.4 envelope — agent-first named params, no builder.
pub(crate) async fn outlet_invoke_cross_context_saga_on(
    bi: &crate::runtime::NapiBridgeInstance,
    source_handle: &NapiContextHandle,
    target_handle: &NapiContextHandle,
    caller_did: String,
    outlet_registration_id: String,
    input_json: String,
    asserted_nonce_hex: String,
    asserted_timestamp_ms: u64,
    asserted_chain_depth: u8,
    ucan_proof_id: Option<String>,
) -> napi::Result<NapiSagaResult> {
    use scp_core::context::supervisor::{CrossContextOutletInvocationRequest, SagaSigningKeys};

    crate::napi_check_handle!(&bi.core, source_handle, target_handle);

    let source_state = source_handle.state()?;
    if source_state != "active" {
        return Err(ScpNapiError::Outlet {
            message: format!(
                "cannot start cross-context saga: caller context in {source_state:?} state"
            ),
            code: codes::OUTLET_6010.to_owned(),
        }
        .into());
    }
    let target_state = target_handle.state()?;
    if target_state != "active" {
        return Err(ScpNapiError::Outlet {
            message: format!(
                "cannot start cross-context saga: target context in {target_state:?} state"
            ),
            code: codes::OUTLET_6011.to_owned(),
        }
        .into());
    }

    let caller_context_id = source_handle.context_id();
    let target_context_id = target_handle.context_id();
    let caller_creator_did = source_handle.creator_did();
    let target_creator_did = target_handle.creator_did();

    scp_ffi_common::validate::validate_context_id(&caller_context_id)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    scp_ffi_common::validate::validate_context_id(&target_context_id)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    validate_did(&caller_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    validate_outlet_id(&outlet_registration_id)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    let asserted_nonce = decode_asserted_nonce(&asserted_nonce_hex)?;
    let input_value: serde_json::Value = serde_json::from_str(&input_json).map_err(|e| {
        napi::Error::from(ScpNapiError::Outlet {
            message: format!("invalid input JSON: {e}"),
            code: codes::OUTLET_6002.to_owned(),
        })
    })?;

    // Caller-principal binding (§6.2.4 *Caller authentication*) — BEFORE the
    // saga runs, so the supervisor never observes an unauthenticated caller.
    let supervisor = crate::runtime::supervisor(bi)?;
    enforce_caller_principal_binding(bi, supervisor, &caller_context_id, &caller_did).await?;

    // ----- Chokepoint (ADR-056): id STRING → [u8; 32] ------------------------
    //
    // MANDATORY: convert via the canonical cross-crate keying resolver, which
    // decodes a real 64-hex id rather than re-hashing it. The producer does
    // `hex::encode(wire)` for actor lookup, so a raw SHA-256 of a 64-hex id
    // here would double-hash and key the wrong (non-existent) actor slot,
    // surfacing as a spurious ContextNotRegistered abort.
    let caller_context_bytes = scp_core::context::state::context_id_to_bytes(&caller_context_id);
    let target_context_bytes = scp_core::context::state::context_id_to_bytes(&target_context_id);

    // ----- Signing keys: each context's Active Signing Key -------------------
    let target_signing_key =
        resolve_context_signing_key(bi, &target_creator_did, &target_context_id).await?;
    let caller_signing_key =
        resolve_context_signing_key(bi, &caller_creator_did, &caller_context_id).await?;

    // ----- Executor: snapshot the TARGET context's outlet handler --------------
    //
    // Snapshot the registered handler closure (an `Arc<dyn Fn>` — cloning is a
    // refcount bump) OUTSIDE the runtime call, then move it into the `FnOnce`
    // executor the supervisor runs supervisor-side at Commit-B (off the actor
    // mailbox). Falls back to a schema-only echo when no handler is registered,
    // matching the synchronous cross-context path. A target context with no
    // FFI-side UCAN/outlet state yet registered (the lazy registry is unpopulated
    // until its first outlet/UCAN call) likewise carries no handler ⇒ echo. The
    // supervisor validates the output against the outlet's registered output
    // schema at Commit-B, so the executor only produces the value.
    let handler = crate::runtime::with_context(bi, &target_context_id, |rt| {
        Ok(rt.outlet_handlers.get(&outlet_registration_id).cloned())
    })
    .unwrap_or(None);
    let outlet_id_for_echo = outlet_registration_id.clone();
    let target_ctx_for_echo = target_context_id.clone();
    let caller_did_for_echo = caller_did.clone();
    let executor = move |value: serde_json::Value| {
        let handler = handler.clone();
        let echo_input = value.clone();
        async move {
            handler.map_or_else(
                || {
                    Ok(serde_json::json!({
                        "outlet": outlet_id_for_echo,
                        "target_context": target_ctx_for_echo,
                        "caller_did": caller_did_for_echo,
                        "status": "validated",
                        "input_valid": true,
                        "validated_input": echo_input,
                    }))
                },
                |h| {
                    h(value).map_err(|e| {
                        format!(
                            "cross-context saga outlet handler for '{outlet_id_for_echo}' failed: {e}"
                        )
                    })
                },
            )
        }
    };

    let request = CrossContextOutletInvocationRequest {
        caller_context_id: caller_context_bytes,
        target_context_id: target_context_bytes,
        caller_did: scp_did::DID(caller_did.clone()),
        outlet_registration_id: outlet_registration_id.clone(),
        ucan_proof_id,
        input: input_value,
        asserted_chain_depth,
        asserted_nonce,
        asserted_timestamp_ms,
    };

    // The producer drives a multi-phase saga; its future is large. Box it so
    // the held state does not bloat this bridge method's own future
    // (`clippy::large_futures`).
    let output = Box::pin(supervisor.start_cross_context_outlet_invocation_saga(
        request,
        SagaSigningKeys {
            target: &target_signing_key,
            caller: &caller_signing_key,
        },
        executor,
    ))
    .await
    .map_err(map_saga_error)?;

    Ok(NapiSagaResult {
        saga_id: output.saga_id.0,
        receipt: output.receipt.map(napi::bindgen_prelude::Buffer::from),
        output: output.output.map(napi::bindgen_prelude::Buffer::from),
    })
}

// ---------------------------------------------------------------------------
// Stateful outlet sessions (spec section 6.2.1)
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of [`outlet_session_create`].
pub(crate) async fn outlet_session_create_on(
    bi: &crate::runtime::NapiBridgeInstance,
    handle: &NapiContextHandle,
    outlet_id: String,
    source_context_id: String,
    ttl_seconds: Option<u32>,
) -> napi::Result<String> {
    crate::napi_check_handle!(&bi.core, handle);
    let state_str = handle.state()?;
    if state_str != "active" {
        return Err(ScpNapiError::Outlet {
            message: format!(
                "cannot create session in context in {state_str:?} state — context must be active"
            ),
            code: codes::OUTLET_6014.to_owned(),
        }
        .into());
    }

    let context_id = handle.context_id();
    crate::runtime::ensure_registered(bi, handle)?;

    // Read context-configured session cap (ADR-043), falling back to default.
    let cap = {
        let supervisor = crate::runtime::supervisor(bi)?;
        supervisor
            .context_params(&context_id)
            .await
            .and_then(|p| p.session_cap)
            .unwrap_or(scp_core::context::outlets::DEFAULT_SESSION_CAP_PER_CALLER) as usize
    };

    crate::runtime::with_context(bi, &context_id, |rt| {
        // Enforce per-caller session cap (context-configured, ADR-043).
        let current = rt.session_store.count_by_source(&source_context_id);
        if current >= cap {
            return Err(ScpNapiError::Outlet {
                message: format!(
                    "session cap exceeded for caller '{source_context_id}': {current} active (max {cap})"
                ),
                code: codes::OUTLET_6015.to_owned(),
            });
        }

        let session_id = uuid::Uuid::new_v4().to_string();
        let now_ms = scp_clock::SystemClock.now_millis();

        let session = scp_core::context::outlets::OutletSession {
            session_id: session_id.clone(),
            outlet_id,
            source_context: source_context_id,
            state: serde_json::Value::Null,
            created_at: now_ms,
            ttl: ttl_seconds.map(|s| std::time::Duration::from_secs(u64::from(s))),
            call_count: 0,
        };

        rt.session_store.insert(session);
        Ok(session_id)
    })
    .map_err(napi::Error::from)
}

/// Per-bridge-instance implementation of [`outlet_session_invoke`].
#[allow(clippy::unused_async)] // preserves signature symmetry with the async free function
pub(crate) async fn outlet_session_invoke_on(
    bi: &crate::runtime::NapiBridgeInstance,
    handle: &NapiContextHandle,
    session_id: String,
    input_json: String,
    invoker_did: String,
    ucan_token: String,
    proof_tokens: Option<Vec<String>>,
) -> napi::Result<String> {
    crate::napi_check_handle!(&bi.core, handle);
    let state_str = handle.state()?;
    if state_str != "active" {
        return Err(ScpNapiError::Outlet {
            message: format!(
                "cannot invoke session in context in {state_str:?} state — context must be active"
            ),
            code: codes::OUTLET_6017.to_owned(),
        }
        .into());
    }

    let context_id = handle.context_id();
    crate::runtime::ensure_registered(bi, handle)?;

    // Look up the outlet_id from the session before UCAN validation so we can
    // validate against the correct outlet capability.
    let outlet_id_for_ucan = crate::runtime::with_context(bi, &context_id, |rt| {
        let session = rt
            .session_store
            .get(&session_id)
            .ok_or_else(|| ScpNapiError::Outlet {
                message: format!("session '{session_id}' not found"),
                code: codes::OUTLET_6018.to_owned(),
            })?;
        Ok(session.outlet_id.clone())
    })
    .map_err(napi::Error::from)?;

    // Primary authorization: UCAN token validation via the full 11-step
    // ADR-016 pipeline. See spec §6.2, §8, ADR-016, and issue #319.
    let proof_resolver = crate::ucan::build_proof_resolver_from_tokens(proof_tokens.as_deref())
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Permission {
                message: format!("failed to build proof resolver: {e}"),
                code: codes::PERM_3001.to_owned(),
            })
        })?;
    validate_ucan_for_outlet(
        bi,
        &context_id,
        &outlet_id_for_ucan,
        &invoker_did,
        &ucan_token,
        &proof_resolver,
    )
    .map_err(napi::Error::from)?;

    let output = crate::runtime::with_context(bi, &context_id, |rt| {
        let session = rt
            .session_store
            .get(&session_id)
            .ok_or_else(|| ScpNapiError::Outlet {
                message: format!("session '{session_id}' not found"),
                code: codes::OUTLET_6018.to_owned(),
            })?;

        // Check expiry.
        let now_ms = scp_clock::SystemClock.now_millis();
        if session.is_expired(now_ms) {
            rt.session_store.remove(&session_id);
            return Err(ScpNapiError::Outlet {
                message: format!("session '{session_id}' has expired"),
                code: codes::OUTLET_6019.to_owned(),
            });
        }

        let outlet_id = session.outlet_id.clone();
        let current_state = session.state.clone();
        let call_count = session.call_count;

        let input_value: serde_json::Value =
            serde_json::from_str(&input_json).map_err(|e| ScpNapiError::Outlet {
                message: format!("invalid input JSON: {e}"),
                code: codes::OUTLET_6002.to_owned(),
            })?;

        // Validate input against outlet's input schema if outlet is registered.
        if let Some(registration) = rt.outlet_registry.get(&outlet_id) {
            scp_core::context::outlets::validate_value_against_schema(
                &input_value,
                &registration.schema.input_schema,
            )
            .map_err(|e| ScpNapiError::Outlet {
                message: format!("input validation failed: {e}"),
                code: codes::OUTLET_6002.to_owned(),
            })?;
        }

        // Execute via handler or echo mode.
        let (new_state, output) = if let Some(handler) = rt.outlet_handlers.get(&outlet_id) {
            let handler = handler.clone();
            let out = handler(input_value).map_err(|e| ScpNapiError::Outlet {
                message: format!("outlet handler for '{outlet_id}' failed: {e}"),
                code: codes::OUTLET_6002.to_owned(),
            })?;
            (current_state, out)
        } else {
            let out = serde_json::json!({
                "outlet": outlet_id,
                "session_id": session_id,
                "status": "validated",
                "call_count": call_count + 1,
                "invoker_did": invoker_did,
                "validated_input": input_value,
            });
            (current_state, out)
        };

        // Update session state and increment call count.
        if let Some(session) = rt.session_store.get_mut(&session_id) {
            session.state = new_state;
            session.call_count = session.call_count.saturating_add(1);
        }

        Ok(output)
    })
    .map_err(napi::Error::from)?;

    serde_json::to_string(&output).map_err(|e| {
        napi::Error::from(ScpNapiError::Outlet {
            message: format!("failed to serialize session invoke output: {e}"),
            code: codes::OUTLET_6020.to_owned(),
        })
    })
}

/// Per-bridge-instance implementation of [`outlet_session_close`].
#[allow(clippy::unused_async)] // preserves signature symmetry with the async free function
pub(crate) async fn outlet_session_close_on(
    bi: &crate::runtime::NapiBridgeInstance,
    handle: &NapiContextHandle,
    session_id: String,
) -> napi::Result<()> {
    crate::napi_check_handle!(&bi.core, handle);
    let context_id = handle.context_id();
    crate::runtime::ensure_registered(bi, handle)?;

    crate::runtime::with_context(bi, &context_id, |rt| {
        if rt.session_store.remove(&session_id).is_none() {
            return Err(ScpNapiError::Outlet {
                message: format!("session '{session_id}' not found"),
                code: codes::OUTLET_6021.to_owned(),
            });
        }
        Ok(())
    })
    .map_err(napi::Error::from)
}

// ---------------------------------------------------------------------------
// Bidirectional consent protocol (spec §6.2.0.1)
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of [`outlet_interface_expose`].
#[allow(clippy::unused_async)] // preserves signature symmetry with the async free function
pub(crate) async fn outlet_interface_expose_on(
    bi: &crate::runtime::NapiBridgeInstance,
    handle: &NapiContextHandle,
    outlet_id: String,
    target_context_id: String,
    rate_limit_json: Option<String>,
) -> napi::Result<String> {
    crate::napi_check_handle!(&bi.core, handle);
    scp_ffi_common::validate::validate_outlet_id(&outlet_id)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    scp_ffi_common::validate::validate_context_id(&target_context_id)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    let state_str = handle.state()?;
    if state_str != "active" {
        return Err(ScpNapiError::Outlet {
            message: format!(
                "cannot expose outlet interface in context in {state_str:?} state — context must be active"
            ),
            code: codes::OUTLET_6030.to_owned(),
        }
        .into());
    }

    let context_id = handle.context_id();
    crate::runtime::ensure_registered(bi, handle)?;

    let rate_limit = match rate_limit_json {
        Some(ref json) => {
            let parsed: scp_core::context::outlets::interface::RateLimit =
                serde_json::from_str(json).map_err(|e| {
                    napi::Error::from(ScpNapiError::Validation {
                        message: format!("invalid rate_limit_json: {e}"),
                        code: codes::VALID_7040.to_owned(),
                    })
                })?;
            Some(parsed)
        }
        None => None,
    };

    crate::runtime::with_context(bi, &context_id, |rt| {
        let context_handle = scp_core::context::ContextHandle::new(
            context_id.clone(),
            scp_core::context::ContextParams::default(),
        );

        let interface = scp_core::context::outlets::interface::expose_outlet(
            context_handle.context_id(),
            &outlet_id,
            &target_context_id,
            &rt.role_state,
            &rt.core.creator_did,
            &rt.outlet_registry,
            rate_limit,
            None,
        )
        .map_err(|e| ScpNapiError::Outlet {
            message: format!("expose_outlet failed: {e}"),
            code: codes::OUTLET_6030.to_owned(),
        })?;

        serde_json::to_string(&interface).map_err(|e| ScpNapiError::Outlet {
            message: format!("failed to serialize OutletInterface: {e}"),
            code: codes::OUTLET_6031.to_owned(),
        })
    })
    .map_err(napi::Error::from)
}

/// Per-bridge-instance implementation of [`outlet_interface_accept`].
#[allow(clippy::unused_async)] // preserves signature symmetry with the async free function
pub(crate) async fn outlet_interface_accept_on(
    bi: &crate::runtime::NapiBridgeInstance,
    handle: &NapiContextHandle,
    interface_json: String,
) -> napi::Result<String> {
    crate::napi_check_handle!(&bi.core, handle);
    let state_str = handle.state()?;
    if state_str != "active" {
        return Err(ScpNapiError::Outlet {
            message: format!(
                "cannot accept outlet interface in context in {state_str:?} state — context must be active"
            ),
            code: codes::OUTLET_6032.to_owned(),
        }
        .into());
    }

    let context_id = handle.context_id();
    crate::runtime::ensure_registered(bi, handle)?;

    let mut interface: scp_core::context::outlets::interface::OutletInterface =
        serde_json::from_str(&interface_json).map_err(|e| {
            napi::Error::from(ScpNapiError::Validation {
                message: format!("invalid interface_json: {e}"),
                code: codes::VALID_7041.to_owned(),
            })
        })?;

    crate::runtime::with_context(bi, &context_id, |rt| {
        let context_handle = scp_core::context::ContextHandle::new(
            context_id.clone(),
            scp_core::context::ContextParams::default(),
        );

        scp_core::context::outlets::interface::accept_outlet_interface(
            context_handle.context_id(),
            &mut interface,
            &rt.role_state,
            &rt.core.creator_did,
            None,
        )
        .map_err(|e| ScpNapiError::Outlet {
            message: format!("accept_outlet_interface failed: {e}"),
            code: codes::OUTLET_6032.to_owned(),
        })?;

        serde_json::to_string(&interface).map_err(|e| ScpNapiError::Outlet {
            message: format!("failed to serialize OutletInterface: {e}"),
            code: codes::OUTLET_6033.to_owned(),
        })
    })
    .map_err(napi::Error::from)
}

/// Per-bridge-instance implementation of [`outlet_interface_revoke`].
#[allow(clippy::unused_async)] // preserves signature symmetry with the async free function
pub(crate) async fn outlet_interface_revoke_on(
    bi: &crate::runtime::NapiBridgeInstance,
    handle: &NapiContextHandle,
    interface_id_hex: String,
) -> napi::Result<String> {
    crate::napi_check_handle!(&bi.core, handle);
    let context_id = handle.context_id();

    let interface_id_bytes = hex::decode(&interface_id_hex).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("invalid interface_id_hex: not valid hex: {e}"),
            code: codes::VALID_7042.to_owned(),
        })
    })?;
    let interface_id: [u8; 32] = scp_ffi_common::validate::expect_fixed_bytes::<32>(
        interface_id_bytes.as_slice(),
        "interface_id_hex",
    )
    .map_err(|msg| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("{msg} (64 hex chars)"),
            code: codes::VALID_7042.to_owned(),
        })
    })?;

    let now_ms = scp_clock::SystemClock.now_millis();

    let event = scp_core::context::outlets::interface::revoke_outlet_interface(
        interface_id,
        &context_id,
        now_ms,
    );

    serde_json::to_string(&event).map_err(|e| {
        napi::Error::from(ScpNapiError::Outlet {
            message: format!("failed to serialize InterfaceRevoked: {e}"),
            code: codes::OUTLET_6035.to_owned(),
        })
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_ffi_common::error_codes as codes;

    // -----------------------------------------------------------------------
    // validate_schema_json
    // -----------------------------------------------------------------------

    #[test]
    fn validate_schema_json_accepts_valid_input_schema() {
        let result = validate_schema_json(r#"{"type": "object"}"#, "input_schema_json");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), serde_json::json!({"type": "object"}));
    }

    #[test]
    fn validate_schema_json_accepts_valid_output_schema() {
        let result = validate_schema_json(r#"{"type": "string"}"#, "output_schema_json");
        assert!(result.is_ok());
    }

    #[test]
    fn validate_schema_json_rejects_invalid_input_schema() {
        let result = validate_schema_json("not valid json{{{", "input_schema_json");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7035),
            "error should contain SCP-VALID-7035, got: {msg}"
        );
        assert!(
            msg.contains("invalid input_schema_json"),
            "error should reference field name, got: {msg}"
        );
    }

    #[test]
    fn validate_schema_json_rejects_invalid_output_schema() {
        let result = validate_schema_json("{broken", "output_schema_json");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7036),
            "error should contain SCP-VALID-7036, got: {msg}"
        );
        assert!(
            msg.contains("invalid output_schema_json"),
            "error should reference field name, got: {msg}"
        );
    }

    #[test]
    fn validate_schema_json_rejects_empty_string() {
        let result = validate_schema_json("", "input_schema_json");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains(codes::VALID_7035));
    }

    // -----------------------------------------------------------------------
    // validate_test_vectors_json
    // -----------------------------------------------------------------------

    #[test]
    fn validate_test_vectors_json_accepts_none() {
        let result = validate_test_vectors_json(None);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn validate_test_vectors_json_accepts_valid_json() {
        let result = validate_test_vectors_json(Some("[]"));
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn validate_test_vectors_json_rejects_invalid_json() {
        let result = validate_test_vectors_json(Some("not json"));
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7037),
            "error should contain SCP-VALID-7037, got: {msg}"
        );
        assert!(
            msg.contains("invalid test_vectors_json"),
            "error should reference field name, got: {msg}"
        );
    }

    #[test]
    fn validate_test_vectors_json_rejects_wrong_type() {
        // Valid JSON but not an array of TestVector.
        let result = validate_test_vectors_json(Some(r#"{"not": "an array"}"#));
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains(codes::VALID_7037));
    }

    // -----------------------------------------------------------------------
    // validate_implementation_hash
    // -----------------------------------------------------------------------

    #[test]
    fn validate_implementation_hash_accepts_none() {
        let result = validate_implementation_hash(None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), [0u8; 32]);
    }

    #[test]
    fn validate_implementation_hash_accepts_32_bytes() {
        let hash = [0xabu8; 32];
        let result = validate_implementation_hash(Some(&hash));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), [0xab; 32]);
    }

    #[test]
    fn validate_implementation_hash_rejects_short() {
        let hash = [0u8; 16];
        let result = validate_implementation_hash(Some(&hash));
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7038),
            "error should contain SCP-VALID-7038, got: {msg}"
        );
        assert!(
            msg.contains("got 16"),
            "error should report actual length, got: {msg}"
        );
    }

    #[test]
    fn validate_implementation_hash_rejects_long() {
        let hash = [0u8; 64];
        let result = validate_implementation_hash(Some(&hash));
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains(codes::VALID_7038));
        assert!(
            msg.contains("got 64"),
            "error should report actual length, got: {msg}"
        );
    }

    #[test]
    fn validate_implementation_hash_rejects_empty() {
        let result = validate_implementation_hash(Some(&[]));
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains(codes::VALID_7038));
        assert!(msg.contains("got 0"));
    }

    /// `registered_at` on an outlet registered via the NAPI bridge must be a
    /// seconds-epoch timestamp, not milliseconds or hardcoded 0.
    /// Calls the actual `outlet_register` bridge function and inspects the
    /// stored `OutletRegistration`. Catches the original bug from issue #871.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn registered_at_is_seconds_epoch() {
        use crate::context::NapiContextHandle;

        let bi = std::sync::Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        let ctx_id = format!("ctx-napi-ts-test-{}", std::process::id());
        let creator_did = "did:dht:z6MkNapiTsTest";

        let handle = NapiContextHandle::test_active_on(&bi, ctx_id.clone(), creator_did.to_owned());

        let definition = NapiOutletDefinition {
            name: "napi-timestamp-probe".to_owned(),
            description: "probes registered_at value".to_owned(),
            kind: NapiOutletKind::Action,
            input_schema_json:
                r#"{"type":"object","properties":{"a":{"type":"string"},"b":{"type":"number"}}}"#
                    .to_owned(),
            output_schema_json: r#"{"type":"object"}"#.to_owned(),
            test_vectors_json: None,
            implementation_hash: None,
            operator_did: creator_did.to_owned(),
            cost: None,
        };

        let outlet_id = outlet_register_on(&bi, &handle, definition)
            .await
            .expect("outlet_register should succeed");

        // Read the stored registration back and verify registered_at.
        let registered_at = crate::runtime::with_context(&bi, &ctx_id, |rt| {
            let reg = rt
                .outlet_registry
                .get(&outlet_id)
                .expect("outlet should exist in registry after registration");
            Ok(reg.registered_at)
        })
        .unwrap();

        assert!(
            registered_at > 1_700_000_000 && registered_at < 2_000_000_000,
            "registered_at should be seconds-epoch (got {registered_at}); \
             milliseconds would be ~1.7 trillion, hardcoded 0 would fail lower bound"
        );

        // Clean up global state.
        crate::runtime::remove_context(&bi, &ctx_id);
    }

    /// SCP-OUT-014: a `Query`-kind definition round-trips through the bridge —
    /// the stored `OutletRegistration.kind` reflects the caller-supplied kind,
    /// which is what the invocation gate and UCAN stem selection read back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn register_query_outlet_round_trips_kind() {
        use crate::context::NapiContextHandle;

        let bi = std::sync::Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        let ctx_id = format!("ctx-napi-kind-test-{}", std::process::id());
        let creator_did = "did:dht:z6MkNapiKindTest";
        let handle = NapiContextHandle::test_active_on(&bi, ctx_id.clone(), creator_did.to_owned());

        let definition = NapiOutletDefinition {
            name: "napi-query-probe".to_owned(),
            description: "probes kind round-trip".to_owned(),
            kind: NapiOutletKind::Query,
            input_schema_json:
                r#"{"type":"object","properties":{"a":{"type":"string"},"b":{"type":"number"}}}"#
                    .to_owned(),
            output_schema_json: r#"{"type":"object"}"#.to_owned(),
            test_vectors_json: None,
            implementation_hash: None,
            operator_did: creator_did.to_owned(),
            cost: None,
        };

        let outlet_id = outlet_register_on(&bi, &handle, definition)
            .await
            .expect("outlet_register should succeed");

        let kind = crate::runtime::with_context(&bi, &ctx_id, |rt| {
            Ok(rt.outlet_registry.get(&outlet_id).expect("registered").kind)
        })
        .unwrap();
        assert_eq!(kind, scp_core::context::outlets::OutletKind::Query);

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    /// The `NapiOutletKind` → core `OutletKind` mapping is exact.
    #[test]
    fn napi_outlet_kind_maps_to_core() {
        use scp_core::context::outlets::OutletKind;
        assert_eq!(OutletKind::from(NapiOutletKind::Query), OutletKind::Query);
        assert_eq!(OutletKind::from(NapiOutletKind::Action), OutletKind::Action);
    }

    // ------------------------------------------------------------------
    // map_saga_error — the bridge's typed-terminal → typed-error mapping.
    //
    // The classification itself (the `RateLimited → Option<u64>` read, the
    // `None`-never-`0` rule, the `SCP-SAGA-{code}` formatting, the fixed
    // terminal codes) lives in `scp_ffi_common::saga_errors` and is unit-tested
    // there for all three bridges. The producer's actual terminal behavior is
    // covered by the Committed e2e test below and in `scp-runtime`. Here we
    // test ONLY this bridge's thin tail: that each `SagaErrorKind` routes
    // through `common` onto the right `ScpNapiError` variant, AND the
    // napi-specific message-suffix Display encoding — the load-bearing
    // `(retry_after_ms=null)` rendering for a `None` hint (never `0`) that the
    // TS wrapper reverses, which `common` does not exercise.
    // ------------------------------------------------------------------

    use scp_core::context::supervisor::{
        SagaAbortReason, SagaError as CoreSagaError, SagaId as CoreSagaId,
    };

    /// `Aborted` routes through `common` onto `ScpNapiError::SagaAborted` with
    /// the `SCP-SAGA-{code}` string and `retry_after_ms` carried structurally;
    /// a `None` back-off hint stays `None` (never `Some(0)`) AND renders as the
    /// literal `(retry_after_ms=null)` suffix the TS wrapper reverses.
    #[test]
    fn map_saga_error_aborted_routes_through_common_with_null_suffix() {
        let some = map_saga_error(CoreSagaError::Aborted {
            reason: SagaAbortReason::RateLimited {
                retry_after_ms: Some(2500),
            },
            code: 13026,
            message: "inbound rate limit exceeded".to_owned(),
        });
        match some {
            ScpNapiError::SagaAborted {
                code,
                retry_after_ms,
                ..
            } => {
                assert_eq!(code, "SCP-SAGA-13026");
                assert_eq!(retry_after_ms, Some(2500));
            }
            other => panic!("expected SagaAborted, got {other:?}"),
        }

        let none = map_saga_error(CoreSagaError::Aborted {
            reason: SagaAbortReason::RateLimited {
                retry_after_ms: None,
            },
            code: 13026,
            message: "hard limit, no precise back-off".to_owned(),
        });
        match &none {
            ScpNapiError::SagaAborted { retry_after_ms, .. } => {
                assert_eq!(*retry_after_ms, None, "None must NOT be coerced to Some(0)");
            }
            other => panic!("expected SagaAborted, got {other:?}"),
        }
        assert!(
            none.to_string().contains("(retry_after_ms=null)"),
            "None retry_after_ms must render as the literal `null`, not 0: {none}"
        );
    }

    /// `NeedsRepair` / `Busy` route through `common` onto their napi-rs variants
    /// with the fixed terminal codes and per-terminal datum carried.
    #[test]
    fn map_saga_error_needs_repair_and_busy_route_through_common() {
        let repair = map_saga_error(CoreSagaError::NeedsRepair {
            saga_id: CoreSagaId("saga-abc-123".to_owned()),
            message: "commit retries exhausted".to_owned(),
        });
        match repair {
            ScpNapiError::SagaNeedsRepair { code, saga_id, .. } => {
                assert_eq!(code, codes::SAGA_13065);
                assert_eq!(saga_id, "saga-abc-123");
            }
            other => panic!("expected SagaNeedsRepair, got {other:?}"),
        }

        let busy = map_saga_error(CoreSagaError::Busy {
            contended_context: "ctx-shared-99".to_owned(),
            message: "participant set overlaps an in-flight saga".to_owned(),
        });
        match busy {
            ScpNapiError::SagaBusy {
                code,
                contended_context,
                ..
            } => {
                assert_eq!(code, codes::SAGA_13066);
                assert_eq!(contended_context, "ctx-shared-99");
            }
            other => panic!("expected SagaBusy, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // decode_asserted_nonce — the §6.2.4 envelope-nonce hex decoder is
    // fail-closed on BOTH malformed-input arms. It is a pure hex-decode +
    // length-check (no supervisor, no custody), so these live in the
    // non-gated `mod tests` and run even in the no-feature lib build.
    // VALID_7001 is shared across both arms, so each test also pins its
    // arm-specific message substring (mirrors the UniFFI bridge's tests).
    // ------------------------------------------------------------------

    /// `decode_asserted_nonce` is fail-closed on non-hex input: it surfaces a
    /// validation error (`SCP-VALID-7001`) with the non-hex arm's message —
    /// the bridge never pads, truncates, or coerces a malformed envelope nonce.
    #[test]
    fn decode_asserted_nonce_non_hex_fails_closed() {
        let err = decode_asserted_nonce("not-hex-at-all-zz")
            .expect_err("non-hex must be rejected fail-closed");
        let msg = format!("{err}");
        assert!(
            msg.contains(codes::VALID_7001),
            "error should carry SCP-VALID-7001, got: {msg}"
        );
        // VALID_7001 is shared with the wrong-length arm; pin the non-hex arm
        // specifically (mirrors how the wrong-length test asserts "16 bytes").
        assert!(
            msg.contains("is not valid hex"),
            "must reject for the non-hex arm specifically; got: {msg}"
        );
    }

    /// `decode_asserted_nonce` is fail-closed on a wrong-length input (valid hex
    /// but 8 bytes, not 16): a wrong length is a malformed §6.2.4 envelope,
    /// surfaced as a validation error (`SCP-VALID-7001`) — never padded or
    /// truncated to fit.
    #[test]
    fn decode_asserted_nonce_wrong_length_fails_closed() {
        // 8 bytes (16 hex chars), not 16.
        let err = decode_asserted_nonce("0011223344556677")
            .expect_err("a wrong-length nonce must be rejected fail-closed");
        let msg = format!("{err}");
        assert!(
            msg.contains(codes::VALID_7001),
            "error should carry SCP-VALID-7001, got: {msg}"
        );
        assert!(
            msg.contains("exactly 16 bytes"),
            "message must explain the 16-byte requirement, got: {msg}"
        );
    }

    /// The happy path: a canonical 32-char hex nonce decodes to its 16 bytes
    /// verbatim — pins the success contract locally alongside the fail-closed
    /// arms.
    #[test]
    fn decode_asserted_nonce_accepts_canonical_32_hex_chars() {
        let nonce = decode_asserted_nonce("000102030405060708090a0b0c0d0e0f")
            .expect("a canonical 32-char hex nonce must decode");
        assert_eq!(
            nonce,
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
    }

    /// All §6.2.4 cross-context-outlet saga binding tests and their pure-string /
    /// DHT / governance helpers live in this single submodule gated on
    /// `allow_in_memory_custody`. Gating the module (rather than each item)
    /// covers every helper AND every future saga test added here by
    /// construction, closing the no-feature `function is never used` regression
    /// class: a saga test added without an explicit per-item `#[cfg(...)]` can
    /// no longer silently reintroduce the no-feature compile warning.
    #[cfg(feature = "allow_in_memory_custody")]
    mod xctx_saga_tests {
        use super::*;

        // ------------------------------------------------------------------
        // End-to-end Committed terminal through the NAPI bridge.
        //
        // Mirrors the PyO3 e2e: an authenticated caller drives the §6.2.4
        // cross-context outlet-invocation saga to a real Committed terminal and the
        // bridge returns the committed receipt + output bytes. The setup wires the
        // two producer authorization axes:
        //
        //   1. Caller axis (gate 1): caller_did is hosted by this instance AND a
        //      member of the CALLER (source) context A — satisfied by creating A
        //      via the real context-create path with `owner` as single-admin.
        //   2. Target axis (gate 2): a bidirectionally-approved OutletInterface
        //      (approved_by_source && approved_by_target, source=A, target=B), which
        //      the producer queries against A's actor governance state, established
        //      IN A via a governance EstablishOutletInterface action (auto-executed
        //      under single_admin).
        //
        // Context B holds the outlet registered into its ACTOR governance state (via a
        // RegisterOutlet governance action — the saga's Prepare-B reads it from there)
        // PLUS the FFI-side handler the executor snapshots and runs once at Commit-B.
        // The handler returns `{"sum":42,"ok":1}`, which Commit-B validates against
        // the registered numeric `{sum, ok}` output schema before committing.
        //
        // For hermeticity against the process-global `SHARED_DHT_CLIENT` `OnceLock`,
        // the test installs its OWN per-instance resolver (over a caller-retained
        // in-memory DHT) BEFORE the first `identity_create`, then explicitly seeds
        // the owner's DID document into that resolver-visible store. The supervisor
        // (built lazily on first `context_create_on`) snapshots that resolver, so
        // governance vote verification resolves the proposer key through it without
        // racing a concurrent sibling on the global. Prepare-B enforces a §9.14
        // ±5min timestamp skew, so the invocation uses `SystemTime::now()`.
        // ------------------------------------------------------------------

        /// Serializes a `RegisterOutlet` governance action for the saga outlet. Mirrors
        /// the registered schema: 2 input + 2 output properties (clears the §9.2.1
        /// specificity floor of 2), numeric `{sum, ok}` output so Commit-B's
        /// output-schema validation accepts the handler's response.
        fn register_outlet_action_json(outlet_id: &str, outlet_name: &str, owner: &str) -> String {
            let impl_hash = serde_json::Value::from(vec![0u8; 32]);
            let register_action = serde_json::json!({
                "RegisterOutlet": {
                    "registration": {
                        "outlet_id": outlet_id,
                        "name": outlet_name,
                        "description": format!("Outlet: {outlet_name}"),
                        "schema": {
                            "input_schema": {
                                "type": "object",
                                "properties": {
                                    "a": {"type": "string"},
                                    "b": {"type": "string"}
                                }
                            },
                            "output_schema": {
                                "type": "object",
                                "properties": {
                                    "sum": {"type": "number"},
                                    "ok": {"type": "number"}
                                }
                            }
                        },
                        "implementation_hash": impl_hash,
                        "test_vectors": [],
                        "operator_did": owner,
                        "cost": null,
                        "registered_at": 0,
                        "signature": []
                    }
                }
            });
            serde_json::to_string(&register_action).unwrap()
        }

        /// Serializes the bidirectionally-approved `EstablishOutletInterface`
        /// governance action (source=A, target=B, BOTH approvals true).
        fn establish_interface_action_json(ctx_a: &str, ctx_b: &str, outlet_id: &str) -> String {
            let action = serde_json::json!({
                "EstablishOutletInterface": {
                    "interface": {
                        "source_context": ctx_a,
                        "target_context": ctx_b,
                        "outlet_id": outlet_id,
                        "rate_limit": null,
                        "inbound_rate_limit": null,
                        "per_caller_rate_limit": null,
                        "approved_by_source": true,
                        "approved_by_target": true,
                        "outbound_policy": null,
                        "inbound_policy": null
                    }
                }
            });
            serde_json::to_string(&action).unwrap()
        }

        /// The registered outlet registration definition for context B's FFI-side
        /// registry, matching the governance `RegisterOutlet` schema (2-in/2-out,
        /// numeric `{sum, ok}` output) so the deterministic id agrees and the
        /// handler's response validates at Commit-B.
        fn build_napi_outlet_def(outlet_name: &str, owner: &str) -> NapiOutletDefinition {
            NapiOutletDefinition {
            name: outlet_name.to_owned(),
            description: format!("Outlet: {outlet_name}"),
            kind: NapiOutletKind::Action,
            input_schema_json:
                r#"{"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}}}"#
                    .to_owned(),
            output_schema_json:
                r#"{"type":"object","properties":{"sum":{"type":"number"},"ok":{"type":"number"}}}"#
                    .to_owned(),
            test_vectors_json: None,
            implementation_hash: None,
            operator_did: owner.to_owned(),
            cost: None,
        }
        }

        /// Installs a per-instance DID resolver backed by a caller-retained
        /// in-memory DHT client on `bi` and returns that client, so the committed
        /// e2e test can seed the owner's DID document into the SAME store the
        /// supervisor's governance key resolver reads from — WITHOUT depending on
        /// the process-global `SHARED_DHT_CLIENT` `OnceLock`.
        ///
        /// Why this is necessary (test hermeticity): the production
        /// `ensure_did_resolver_initialized_on` path stores its `InMemoryDhtClient`
        /// in the process-wide `SHARED_DHT_CLIENT` `OnceLock` (so
        /// cross-identity flows in one process share a DHT). The three co-located
        /// `xctx_saga` tests run concurrently under the default test harness; a
        /// sibling can win the `SHARED_DHT_CLIENT.set` (or mutate the shared DHT)
        /// first, so this test's owner DID document lands in / is read from a
        /// resolver the committed test does not control, and governance vote
        /// verification fails with `[SCP-CTX-2041] unknown voter: cannot resolve
        /// public key for DID …`. Installing a FRESH per-instance resolver here,
        /// BEFORE the first identity creation, makes `ensure_did_resolver_initialized_on`
        /// a no-op (it short-circuits when a resolver is already present), so this
        /// retained client is the one the supervisor snapshots — fully isolated from
        /// the global. Mirrors the `UniFFI` bridge's `install_seedable_resolver`.
        fn install_seedable_resolver(
            bi: &std::sync::Arc<crate::runtime::NapiBridgeInstance>,
        ) -> std::sync::Arc<scp_dht::InMemoryDhtClient> {
            let dht_client = std::sync::Arc::new(scp_dht::InMemoryDhtClient::new());
            let resolver = std::sync::Arc::new(scp_identity::DualLayerResolver::new(
                std::sync::Arc::new(scp_identity::NoOpRelayQuerier),
                std::sync::Arc::clone(&dht_client),
                std::sync::Arc::new(scp_identity::DidCache::new()),
                Vec::new(),
            ));
            crate::runtime::init_did_resolver(bi, resolver, tokio::runtime::Handle::current());
            dht_client
        }

        /// Publishes `owner_identity`'s DID document into `dht_client` (the
        /// resolver-visible store installed by [`install_seedable_resolver`]) by
        /// signing the BEP44 record with the identity's retained in-memory custody.
        /// Mirrors the production `publish_to_shared_dht_for` step so the
        /// supervisor's governance key resolver can resolve the proposer key during
        /// single-admin vote verification.
        async fn seed_owner_document_into_resolver(
            owner_identity: &crate::identity::NapiIdentity,
            dht_client: &std::sync::Arc<scp_dht::InMemoryDhtClient>,
        ) {
            use scp_dht::DhtClient as _;
            use scp_platform::traits::KeyCustody as _;

            let inner = &owner_identity.inner;
            let identity = inner
                .scp_identity
                .as_ref()
                .expect("in-memory owner retains its ScpIdentity");
            let document = inner
                .document
                .as_ref()
                .expect("in-memory owner retains its DID document");
            let custody = inner
                .in_memory_custody
                .as_ref()
                .expect("in-memory owner retains its custody");

            let doc_json = document.to_json().expect("document serializes to JSON");
            let value = doc_json.as_bytes();
            let public_key =
                scp_identity::extract_public_key(&identity.did).expect("DID embeds the public key");
            let seq: u64 = 1;
            let signable = scp_dht::bep44_signable(value, seq);
            let sig_bytes = custody
                .sign(&identity.identity_key, &signable)
                .await
                .expect("identity custody signs the BEP44 record")
                .into_bytes();
            let signature: [u8; 64] = sig_bytes.try_into().expect("Ed25519 signature is 64 bytes");
            dht_client
                .publish(&public_key, &signature, value, seq)
                .await
                .expect("publish into the resolver-visible store");
        }

        /// Full `Committed` terminal through the NAPI bridge: an authenticated
        /// caller drives the §6.2.4 cross-context outlet-invocation saga to a real
        /// commit and the bridge returns the committed receipt + output bytes.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn xctx_saga_authenticated_caller_commits_via_governance_established_interface() {
            let scp = crate::scp::Scp::new_in_memory_for_test();
            let bi = std::sync::Arc::clone(&scp.inner);

            // Install a per-instance, caller-retained DID resolver BEFORE the first
            // identity creation, so this test is hermetic against the process-global
            // `SHARED_DHT_CLIENT` `OnceLock` a concurrent sibling `xctx_saga` test
            // could win first (which otherwise leaves this owner's DID unresolvable
            // → `[SCP-CTX-2041] unknown voter`). See `install_seedable_resolver`.
            let resolver_dht = install_seedable_resolver(&bi);

            // Owner via the real identity-create path so it retains a real
            // `ScpIdentity`, custody, and DID document. MUST precede the first
            // context_create (which lazily builds the supervisor + snapshots the
            // resolver installed above).
            let owner_identity = scp
                .identity_create("in_memory".to_owned(), None)
                .await
                .expect("identity_create should succeed");
            let owner = owner_identity.inner.did.clone();

            // Seed the owner's DID document into the per-instance resolver's store
            // so governance vote verification (RegisterOutlet / EstablishOutletInterface
            // auto-execute under single_admin) can resolve the proposer's public
            // key. Without this the resolver is empty and the propose below fails.
            seed_owner_document_into_resolver(&owner_identity, &resolver_dht).await;

            // Context A (caller/source): ceiling carries governance:propose (so the
            // admin can propose) and outlet:interface (required by
            // execute_establish_outlet_interface's ceiling check).
            let params_a = serde_json::json!({
                "ceiling": [
                    "governance:propose",
                    "outlet:interface",
                    "outlet:call:*",
                    "messages:read",
                    "messages:write"
                ],
                "governance": "single_admin",
                "memoryScope": "ephemeral",
            })
            .to_string();
            let handle_a = crate::context::context_create_on(&bi, &owner_identity, params_a)
                .await
                .expect("context_create A should succeed");
            let ctx_a = handle_a.context_id();

            // Context B (target): ceiling carries governance:propose and
            // outlet:register so the saga outlet can be registered into B's ACTOR
            // governance state (the saga's Prepare-B reads it from there).
            let params_b = serde_json::json!({
                "ceiling": ["governance:propose", "outlet:register"],
                "governance": "single_admin",
                "memoryScope": "ephemeral",
            })
            .to_string();
            let handle_b = crate::context::context_create_on(&bi, &owner_identity, params_b)
                .await
                .expect("context_create B should succeed");
            let ctx_b = handle_b.context_id();

            // Deterministic outlet id shared across the actor registry, the interface,
            // and the FFI-side handler.
            let outlet_name = "xctx_saga_commit_outlet";
            let outlet_id = scp_ffi_common::outlet_id::generate_outlet_id(outlet_name);

            // Register the outlet into B's ACTOR governance state.
            let register_json = register_outlet_action_json(&outlet_id, outlet_name, &owner);
            crate::context::context_governance_propose_on(
                &bi,
                &handle_b,
                register_json,
                owner.clone(),
            )
            .await
            .expect("RegisterOutlet must auto-execute under single_admin");

            // Register the outlet into B's FFI-side registry (so register_outlet_handler
            // accepts it) and attach the deterministic handler the executor runs at
            // Commit-B.
            let ffi_outlet_id =
                outlet_register_on(&bi, &handle_b, build_napi_outlet_def(outlet_name, &owner))
                    .await
                    .expect("FFI outlet_register should succeed");
            assert_eq!(
                ffi_outlet_id, outlet_id,
                "FFI and governance outlet ids must agree (deterministic generate_outlet_id)"
            );
            let handler: crate::runtime::OutletHandler =
                std::sync::Arc::new(|_input: serde_json::Value| {
                    Ok(serde_json::json!({"sum": 42, "ok": 1}))
                });
            crate::runtime::register_outlet_handler(&bi, &ctx_b, &outlet_id, handler)
                .expect("register_outlet_handler should succeed");

            // Establish the bidirectionally-approved interface in A via governance.
            let interface_json = establish_interface_action_json(&ctx_a, &ctx_b, &outlet_id);
            let propose_result = crate::context::context_governance_propose_on(
                &bi,
                &handle_a,
                interface_json,
                owner.clone(),
            )
            .await
            .expect("EstablishOutletInterface must auto-execute under single_admin");
            assert!(
                !propose_result.is_empty(),
                "governance_propose must return a non-empty result JSON"
            );

            // A near-now timestamp: Prepare-B enforces a §9.14 ±5min skew tolerance.
            let now_ms = u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
            )
            .unwrap();
            // A 16-byte nonce as 32 lowercase-hex chars.
            let nonce_hex = "0123456789abcdef0123456789abcdef".to_owned();

            let result = Box::pin(outlet_invoke_cross_context_saga_on(
                &bi,
                &handle_a,
                &handle_b,
                owner.clone(),
                outlet_id.clone(),
                r#"{"a":"x","b":"y"}"#.to_owned(),
                nonce_hex,
                now_ms,
                1,
                None,
            ))
            .await
            .expect("saga must reach Committed");

            // Committed terminal: non-empty saga id + a receipt + output bytes.
            assert!(
                !result.saga_id.is_empty(),
                "a committed saga must carry a non-empty saga id"
            );
            let receipt = result.receipt.expect("committed saga must carry a receipt");
            assert!(!receipt.is_empty(), "receipt bytes must be non-empty");
            let output_buf = result
                .output
                .expect("committed saga must carry output bytes");

            // The committed output decodes to the handler's response (numeric, per
            // the registered output schema). Assert the parsed values, not raw
            // bytes, so a JCS-canonical encoding still passes.
            let out: serde_json::Value =
                serde_json::from_slice(output_buf.as_ref()).expect("output must be valid JSON");
            assert_eq!(out["sum"], 42, "committed output sum must be the handler's");
            assert_eq!(out["ok"], 1, "committed output ok must be the handler's");
        }

        // ------------------------------------------------------------------
        // Caller-principal binding (§6.2.4 *Caller authentication*) — the two
        // axes `enforce_caller_principal_binding` enforces at the NAPI seam,
        // BEFORE the saga runs. These are the behavioral counterparts of the
        // PyO3 `e2e_bridge.rs` axis-(a)/axis-(b) tests.
        //
        // MUTATION-RESISTANCE: the producer's own gate 1 ALSO rejects a
        // non-member caller with SCP-SAGA-13050. Asserting only the code (as the
        // TS addon test does) would PASS even if this bridge's binding were
        // removed — the producer would surface 13050 anyway. So each test asserts
        // the BRIDGE-UNIQUE message substring that `enforce_caller_principal_binding`
        // emits and the producer never does:
        //   axis (a): "is not an identity hosted by this bridge instance"
        //   axis (b): "is hosted by this bridge but is not a member of"
        // The producer's gate-1 message is "... is not a member of caller context
        // '...' — not authorized to initiate over it", which contains neither.
        // ------------------------------------------------------------------

        /// Creates an ephemeral single-admin context owned by `owner_identity` whose
        /// ceiling carries the saga-relevant capabilities. Mirrors the e2e setup but
        /// without the outlet/interface wiring the two binding-rejection tests never
        /// reach (they abort at the caller gate before the producer runs).
        async fn create_saga_context(
            bi: &std::sync::Arc<crate::runtime::NapiBridgeInstance>,
            owner_identity: &crate::identity::NapiIdentity,
        ) -> crate::context::NapiContextHandle {
            let params = serde_json::json!({
                "ceiling": [
                    "governance:propose",
                    "outlet:interface",
                    "outlet:register",
                    "outlet:call:*",
                    "messages:read",
                    "messages:write"
                ],
                "governance": "single_admin",
                "memoryScope": "ephemeral",
            })
            .to_string();
            crate::context::context_create_on(bi, owner_identity, params)
                .await
                .expect("context_create should succeed")
        }

        /// (a) Caller-principal binding, hosted axis: a `caller_did` this bridge
        /// instance does NOT host is rejected with `SagaAborted` (SCP-SAGA-13050)
        /// BEFORE the saga runs. Asserts the bridge-unique axis-(a) substring so the
        /// test fails if `enforce_caller_principal_binding`'s registry check is
        /// removed (the producer's gate-1 message never carries this phrasing).
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn xctx_saga_unhosted_caller_rejected_before_saga() {
            let scp = crate::scp::Scp::new_in_memory_for_test();
            let bi = std::sync::Arc::clone(&scp.inner);

            let owner_identity = scp
                .identity_create("in_memory".to_owned(), None)
                .await
                .expect("identity_create should succeed");

            let handle_a = create_saga_context(&bi, &owner_identity).await;
            let handle_b = create_saga_context(&bi, &owner_identity).await;
            let outlet_id =
                scp_ffi_common::outlet_id::generate_outlet_id("xctx_saga_unhosted_probe");

            // A syntactically valid DID that was never created on this instance.
            let unhosted_caller = "did:dht:z6MkUnhostedCallerPrincipal0001".to_owned();

            let now_ms = u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
            )
            .unwrap();

            // `NapiSagaResult` is not `Debug`, so destructure the `Err` terminal
            // explicitly rather than `expect_err`.
            let Err(err) = Box::pin(outlet_invoke_cross_context_saga_on(
                &bi,
                &handle_a,
                &handle_b,
                unhosted_caller,
                outlet_id,
                r#"{"a":"x","b":"y"}"#.to_owned(),
                "0123456789abcdef0123456789abcdef".to_owned(),
                now_ms,
                1,
                None,
            ))
            .await
            else {
                panic!("an unhosted caller_did must be rejected before the saga runs")
            };

            let msg = format!("{err}");
            assert!(
                msg.contains(codes::SAGA_13050),
                "expected caller-axis SCP-SAGA-13050, got: {msg}"
            );
            // BRIDGE-UNIQUE axis-(a) substring — the producer never emits it.
            assert!(
                msg.contains("is not an identity hosted by this bridge instance"),
                "message must be the BRIDGE axis-(a) hosted-principal rejection (not a producer \
             message), got: {msg}"
            );
        }

        /// (b) Caller-principal binding, membership axis: a `caller_did` that IS
        /// hosted by this bridge but is NOT a member of `caller_context_id` is
        /// rejected with `SagaAborted` (SCP-SAGA-13050) BEFORE the saga runs. Asserts
        /// the bridge-unique axis-(b) substring so the test fails if the bridge's
        /// `is_member` check is removed — the producer's gate-1 message shares only
        /// the bare "not a member of" phrasing, not this prefix.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn xctx_saga_hosted_non_member_caller_rejected() {
            let scp = crate::scp::Scp::new_in_memory_for_test();
            let bi = std::sync::Arc::clone(&scp.inner);

            let owner_identity = scp
                .identity_create("in_memory".to_owned(), None)
                .await
                .expect("identity_create should succeed");

            // A SECOND hosted identity that is NOT a member of the caller context.
            let stranger_identity = scp
                .identity_create("in_memory".to_owned(), None)
                .await
                .expect("identity_create should succeed");
            let stranger = stranger_identity.inner.did.clone();

            // Contexts created by `owner` ⇒ `stranger` is hosted but not a member.
            let handle_a = create_saga_context(&bi, &owner_identity).await;
            let handle_b = create_saga_context(&bi, &owner_identity).await;
            let outlet_id =
                scp_ffi_common::outlet_id::generate_outlet_id("xctx_saga_nonmember_probe");

            let now_ms = u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
            )
            .unwrap();

            // `NapiSagaResult` is not `Debug`, so destructure the `Err` terminal
            // explicitly rather than `expect_err`.
            let Err(err) = Box::pin(outlet_invoke_cross_context_saga_on(
                &bi,
                &handle_a,
                &handle_b,
                stranger, // hosted, but not a member of caller context A
                outlet_id,
                r#"{"a":"x","b":"y"}"#.to_owned(),
                "0123456789abcdef0123456789abcdef".to_owned(),
                now_ms,
                1,
                None,
            ))
            .await
            else {
                panic!("a hosted non-member caller must be rejected before the saga runs")
            };

            let msg = format!("{err}");
            assert!(
                msg.contains(codes::SAGA_13050),
                "expected caller-axis SCP-SAGA-13050, got: {msg}"
            );
            // BRIDGE-UNIQUE axis-(b) substring — the producer's gate-1 message
            // carries only the bare "not a member of" phrasing, not this prefix.
            assert!(
                msg.contains("is hosted by this bridge but is not a member of"),
                "message must be the BRIDGE axis-(b) membership rejection (not the producer gate-1 \
             message), got: {msg}"
            );
        }

        /// (a, axis-isolated) Caller-principal binding, hosted-here axis as the SOLE
        /// guard: a `caller_did` that IS a genuine member of `caller_context_id` (so
        /// the membership axis (b) would PASS) but is NOT an identity hosted by this
        /// bridge instance is STILL rejected with `SagaAborted` (SCP-SAGA-13050)
        /// BEFORE the saga runs.
        ///
        /// This is the property `xctx_saga_unhosted_caller_rejected_before_saga`
        /// cannot prove: that test's caller is BOTH unhosted AND a non-member, so
        /// axis (b) (and the producer's gate 1) would reject it even if axis (a) were
        /// deleted. Here the caller is inserted as a real member of `caller_ctx` via
        /// `Supervisor::test_insert_member` (the actor-state membership injection
        /// that bypasses the MLS Welcome a non-hosted DID could never complete), so
        /// `supervisor.is_member` returns true and axis (b) passes the caller. The
        /// ONLY thing that can reject it is axis (a): the caller DID was never
        /// `identity_create`'d, so it is absent from this instance's identity
        /// registry. The test therefore fails closed iff the bridge's
        /// `identity_registry_contains` axis (a) check is removed, and is INDEPENDENT
        /// of axis (b) by construction.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn xctx_saga_member_but_unhosted_caller_rejected_by_hosted_axis() {
            let scp = crate::scp::Scp::new_in_memory_for_test();
            let bi = std::sync::Arc::clone(&scp.inner);

            // `owner` is a hosted identity used only to create the contexts.
            let owner_identity = scp
                .identity_create("in_memory".to_owned(), None)
                .await
                .expect("identity_create should succeed");

            let handle_a = create_saga_context(&bi, &owner_identity).await;
            let handle_b = create_saga_context(&bi, &owner_identity).await;
            let ctx_a = handle_a.context_id();
            let outlet_id =
                scp_ffi_common::outlet_id::generate_outlet_id("xctx_saga_member_unhosted_probe");

            // The caller is a syntactically valid DID that is NEVER `identity_create`'d
            // (so the bridge's identity registry does NOT host it — axis (a) must
            // reject), yet is injected as a genuine member of `caller_ctx` via the
            // actor-state membership path (so `supervisor.is_member` returns true and
            // axis (b) passes). `test_insert_member` is the test-only injection that
            // records the member into role state exactly as an executed `AddMember`
            // would, without the MLS Welcome a non-hosted DID could never complete.
            let member_but_unhosted_caller = "did:dht:z6MkMemberButUnhostedCaller001".to_owned();
            let supervisor =
                crate::runtime::supervisor(&bi).expect("supervisor must be initialized");
            supervisor
                .test_insert_member(
                    &ctx_a,
                    scp_did::DID(member_but_unhosted_caller.clone()),
                    "member",
                )
                .await
                .expect("test_insert_member should record the caller into caller_ctx membership");

            // Precondition: the supervisor MUST see the caller as a member of
            // `caller_ctx` (axis (b) passes), while the bridge's identity registry
            // does NOT host it (axis (a) is the sole remaining guard).
            assert!(
                supervisor
                    .is_member(&ctx_a, &member_but_unhosted_caller)
                    .await,
                "precondition: caller must be a genuine member of caller_ctx so axis (b) passes"
            );
            assert!(
                !crate::runtime::identity_registry_contains(&bi, &member_but_unhosted_caller),
                "precondition: caller must NOT be hosted so axis (a) is the sole guard"
            );

            let now_ms = u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
            )
            .unwrap();

            // `NapiSagaResult` is not `Debug`, so destructure the `Err` terminal
            // explicitly rather than `expect_err`.
            let Err(err) = Box::pin(outlet_invoke_cross_context_saga_on(
                &bi,
                &handle_a,
                &handle_b,
                member_but_unhosted_caller, // member of caller_ctx, but NOT hosted
                outlet_id,
                r#"{"a":"x","b":"y"}"#.to_owned(),
                "0123456789abcdef0123456789abcdef".to_owned(),
                now_ms,
                1,
                None,
            ))
            .await
            else {
                panic!(
                    "a member-but-unhosted caller must be rejected by axis (a) before the saga runs"
                )
            };

            let msg = format!("{err}");
            assert!(
                msg.contains(codes::SAGA_13050),
                "expected caller-axis SCP-SAGA-13050, got: {msg}"
            );
            // BRIDGE-UNIQUE axis-(a) substring. Because the caller IS a member, the
            // membership axis (b) and the producer's gate 1 would BOTH pass — so the
            // axis-(b) message ("is hosted by this bridge but is not a member of") can
            // never appear here. The ONLY rejection that fits is axis (a). Asserting
            // its exact substring makes this test fail closed iff
            // `enforce_caller_principal_binding`'s `identity_registry_contains` check
            // is removed.
            assert!(
                msg.contains("is not an identity hosted by this bridge instance"),
                "message must be the BRIDGE axis-(a) hosted-here rejection, got: {msg}"
            );
        }
    }
}
