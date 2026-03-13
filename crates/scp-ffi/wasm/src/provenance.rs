//! `wasm-bindgen` bridge for provenance operations.
//!
//! Exposes provenance evaluation and attachment to JavaScript (browser target):
//!
//! - `provenance_check_chain_depth` — Check if chain depth is within limits.
//! - `evaluate_provenance_quality` — Evaluate provenance quality tier.
//! - `provenance_attach` — Attach provenance metadata for cross-context data flow.
//!
//! # WASM constraints
//!
//! This bridge does NOT depend on `scp-core` (tokio multi-thread incompatible
//! with `wasm32-unknown-unknown`). Provenance operations are pure computation
//! (chain depth arithmetic, quality tier evaluation, JSON construction)
//! re-implemented locally with algorithm-identical logic.
//!
//! See ADR-019 in `.docs/adrs/phase-4.md`.

use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// Constants (mirror scp-core::provenance::attach)
// ---------------------------------------------------------------------------

/// Protocol default maximum chain depth (3 hops).
const DEFAULT_MAX_CHAIN_DEPTH: u32 = 3;

/// Protocol hard maximum chain depth (5 hops).
const PROTOCOL_HARD_MAX_CHAIN_DEPTH: u32 = 5;

// ---------------------------------------------------------------------------
// Local enums (mirror scp-core::provenance)
// ---------------------------------------------------------------------------

/// Source type for provenance quality evaluation.
enum SourceType {
    Persistent,
    Ephemeral,
    Summary,
}

impl SourceType {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "Persistent" | "persistent" => Some(Self::Persistent),
            "Ephemeral" | "ephemeral" => Some(Self::Ephemeral),
            "Summary" | "summary" => Some(Self::Summary),
            _ => None,
        }
    }
}

impl std::fmt::Display for SourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Persistent => write!(f, "Persistent"),
            Self::Ephemeral => write!(f, "Ephemeral"),
            Self::Summary => write!(f, "Summary"),
        }
    }
}

/// Context state for provenance quality evaluation.
#[derive(Clone, Copy)]
enum ContextState {
    Active,
    ClosedWithSummaryVerified,
    ClosedWithSummaryUnverified,
    ClosedEphemeral,
    Unknown,
}

impl ContextState {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "Active" | "active" => Some(Self::Active),
            "ClosedWithSummaryVerified" | "closed_with_summary_verified" => {
                Some(Self::ClosedWithSummaryVerified)
            }
            "ClosedWithSummaryUnverified" | "closed_with_summary_unverified" => {
                Some(Self::ClosedWithSummaryUnverified)
            }
            "ClosedEphemeral" | "closed_ephemeral" => Some(Self::ClosedEphemeral),
            "Unknown" | "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

impl std::fmt::Display for ContextState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "Active"),
            Self::ClosedWithSummaryVerified => write!(f, "ClosedWithSummaryVerified"),
            Self::ClosedWithSummaryUnverified => write!(f, "ClosedWithSummaryUnverified"),
            Self::ClosedEphemeral => write!(f, "ClosedEphemeral"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Memory scope for provenance attachment.
enum MemoryScope {
    Full,
    Summary,
    Ephemeral,
}

impl MemoryScope {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "Full" | "full" => Some(Self::Full),
            "Summary" | "summary" => Some(Self::Summary),
            "Ephemeral" | "ephemeral" => Some(Self::Ephemeral),
            _ => None,
        }
    }
}

impl std::fmt::Display for MemoryScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full => write!(f, "Full"),
            Self::Summary => write!(f, "Summary"),
            Self::Ephemeral => write!(f, "Ephemeral"),
        }
    }
}

// ---------------------------------------------------------------------------
// Quality evaluation (mirrors scp-core::provenance::evaluate)
// ---------------------------------------------------------------------------

/// Evaluates provenance quality tier.
///
/// Quality tiers (highest to lowest):
/// - 3 = `PersistentVerifiable` — active + persistent source
/// - 2 = `SummaryVerified` — closed with verified summary
/// - 1 = `EphemeralKnownParties` — ephemeral but counterparties known
/// - 0 = `NoProvenance` — no protocol-level origin tracking
fn compute_quality(
    has_provenance: bool,
    source_type: &SourceType,
    context_state: ContextState,
    has_counterparties: bool,
) -> u32 {
    if !has_provenance {
        return 0;
    }
    match context_state {
        ContextState::Active => {
            if matches!(source_type, SourceType::Persistent) {
                3
            } else {
                // Active context but source type isn't Persistent — inconsistent
                // state; degrade gracefully (matches scp-core evaluate_quality)
                1
            }
        }
        ContextState::ClosedWithSummaryVerified => 2,
        ContextState::ClosedWithSummaryUnverified | ContextState::ClosedEphemeral => {
            u32::from(has_counterparties)
        }
        ContextState::Unknown => 0,
    }
}

// ---------------------------------------------------------------------------
// provenance_check_chain_depth
// ---------------------------------------------------------------------------

/// Checks whether a given chain depth is within the allowed limit.
///
/// Returns `true` if `depth <= max_depth_override` (or `depth <= DEFAULT_MAX_CHAIN_DEPTH`
/// when no override is provided). The effective max is clamped to
/// `PROTOCOL_HARD_MAX_CHAIN_DEPTH` (5).
///
/// # JS usage
///
/// ```js
/// const ok = provenance_check_chain_depth(2, null); // true (default max = 3)
/// const bad = provenance_check_chain_depth(4, null); // false
/// const custom = provenance_check_chain_depth(4, 5); // true
/// ```
#[must_use]
#[wasm_bindgen]
pub fn provenance_check_chain_depth(depth: u32, max_depth_override: Option<u32>) -> bool {
    let context_or_default = max_depth_override.unwrap_or(DEFAULT_MAX_CHAIN_DEPTH);
    let effective_max = context_or_default.min(PROTOCOL_HARD_MAX_CHAIN_DEPTH);
    depth <= effective_max
}

// ---------------------------------------------------------------------------
// evaluate_provenance_quality
// ---------------------------------------------------------------------------

/// Evaluates the quality tier for a provenance record.
///
/// Returns a numeric tier: 3 (highest, `PersistentVerifiable`) down to
/// 0 (lowest, `NoProvenance`).
///
/// # Arguments
///
/// - `source_context` — Source context ID, or `None` (no provenance).
/// - `source_type` — One of `"Persistent"` / `"persistent"`, `"Ephemeral"` / `"ephemeral"`,
///   `"Summary"` / `"summary"`.
/// - `context_state` — One of `"Active"` / `"active"`,
///   `"ClosedWithSummaryVerified"` / `"closed_with_summary_verified"`,
///   `"ClosedWithSummaryUnverified"` / `"closed_with_summary_unverified"`,
///   `"ClosedEphemeral"` / `"closed_ephemeral"`, `"Unknown"` / `"unknown"`.
/// - `counterparties_json` — Optional JSON array of counterparty DID strings.
///   Non-empty array → counterparties known. `None` or `"[]"` → unknown.
///
/// # Errors
///
/// Returns `JsError` if `context_state` or `source_type` are invalid values,
/// or if `counterparties_json` is not valid JSON.
///
/// # JS usage
///
/// ```js
/// const tier = evaluate_provenance_quality("ctx-1", "persistent", "active", '["did:key:z6Mk..."]');
/// console.log(tier); // 3
/// ```
#[wasm_bindgen]
pub fn evaluate_provenance_quality(
    source_context: Option<String>,
    source_type: String,
    context_state: String,
    counterparties_json: Option<String>,
) -> Result<u32, JsError> {
    let cs = ContextState::from_str(&context_state).ok_or_else(|| {
        JsError::new(&format!(
            "[SCP-VALID-7200] invalid context_state: '{context_state}'"
        ))
    })?;

    let has_counterparties = if let Some(ref json) = counterparties_json {
        let arr: Vec<String> = serde_json::from_str(json).map_err(|e| {
            JsError::new(&format!(
                "[SCP-VALID-7202] invalid counterparties_json: {e}"
            ))
        })?;
        !arr.is_empty()
    } else {
        false
    };

    let has_provenance = source_context.is_some();

    let st = SourceType::from_str(&source_type).ok_or_else(|| {
        JsError::new(&format!(
            "[SCP-VALID-7201] invalid source_type: '{source_type}'"
        ))
    })?;

    Ok(compute_quality(has_provenance, &st, cs, has_counterparties))
}

// ---------------------------------------------------------------------------
// provenance_attach
// ---------------------------------------------------------------------------

/// Attaches provenance metadata for a cross-context data flow.
///
/// Returns a JSON string representing the provenance record.
///
/// # Arguments
///
/// - `source_context_id` — ID of the source context.
/// - `source_type` — One of `"Persistent"` / `"persistent"`, `"Ephemeral"` / `"ephemeral"`,
///   `"Summary"` / `"summary"`.
/// - `memory_scope` — One of `"Full"` / `"full"`, `"Summary"` / `"summary"`,
///   `"Ephemeral"` / `"ephemeral"`.
/// - `counterparties_json` — JSON array of DID strings.
/// - `target_context_id` — ID of the target context.
/// - `existing_chain_depth` — Chain depth from existing provenance, or -1 for first hop.
/// - `existing_chain_path_json` — JSON array of context IDs from existing provenance, or empty.
/// - `discovery_method` — Optional: `"OutOfBand"`, `"out_of_band"`, `"shared_context:<id>"`, or `"registry:<id>"`. `"none"`/`"None"` accepted for backward compat.
/// - `purpose` — Optional human-readable purpose description.
///
/// # WASM limitation: no `counterparty_policy`
///
/// The native (napi-rs) bridge accepts a `counterparty_policy` parameter
/// (`"full"` / `"pseudonymized"` / `"redacted"`) that controls how
/// counterparty DIDs are represented in the output record. This WASM bridge
/// does not support `counterparty_policy` because the policy application
/// logic lives in `scp-core::provenance::attach`, which cannot be compiled
/// to `wasm32-unknown-unknown` (tokio multi-thread dependency; see ADR-034).
/// Counterparty DIDs are always included verbatim ("full" behavior).
/// The TypeScript WASM adapter (`wasm.ts`) silently drops the parameter.
///
/// # Errors
///
/// Returns `JsError` if parameters are invalid or JSON parsing fails.
///
/// # JS usage
///
/// ```js
/// const prov = provenance_attach(
///   "ctx-source", "Persistent", "Full",
///   '["did:key:alice"]', "ctx-target", -1, "[]",
///   "OutOfBand", null
/// );
/// ```
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)] // wasm_bindgen requires explicit params
pub fn provenance_attach(
    source_context_id: String,
    source_type: String,
    memory_scope: String,
    counterparties_json: String,
    target_context_id: String,
    existing_chain_depth: f64,
    existing_chain_path_json: String,
    discovery_method: Option<String>,
    purpose: Option<String>,
) -> Result<String, JsError> {
    if source_context_id.is_empty() {
        return Err(JsError::new(
            "[SCP-VALID-7210] source_context_id must not be empty",
        ));
    }
    if target_context_id.is_empty() {
        return Err(JsError::new(
            "[SCP-VALID-7211] target_context_id must not be empty",
        ));
    }

    let st = SourceType::from_str(&source_type).ok_or_else(|| {
        JsError::new(&format!(
            "[SCP-VALID-7212] invalid source_type: '{source_type}'"
        ))
    })?;

    let ms = MemoryScope::from_str(&memory_scope).ok_or_else(|| {
        JsError::new(&format!(
            "[SCP-VALID-7213] invalid memory_scope: '{memory_scope}'"
        ))
    })?;

    let counterparties: Vec<String> = serde_json::from_str(&counterparties_json).map_err(|e| {
        JsError::new(&format!(
            "[SCP-VALID-7214] invalid counterparties JSON: {e}"
        ))
    })?;

    let dm = parse_wasm_discovery_method(discovery_method.as_deref())?;

    // Compute chain depth and path
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let (chain_depth, chain_path) = if existing_chain_depth < 0.0 {
        // First hop
        (0_u32, serde_json::Value::Null)
    } else {
        let prev_depth = existing_chain_depth.max(0.0) as u32;
        let new_depth = prev_depth.saturating_add(1);

        let mut path: Vec<String> =
            serde_json::from_str(&existing_chain_path_json).map_err(|e| {
                JsError::new(&format!(
                    "[SCP-VALID-7215] existing_chain_path_json is not valid JSON: {e}"
                ))
            })?;
        path.push(source_context_id.clone());

        (new_depth, serde_json::json!(path))
    };

    // WASM has no real timer — age is always 0 at attachment time.
    // The field must be present for structural parity with the NAPI bridge.
    let result = serde_json::json!({
        "source_context": source_context_id,
        "source_type": st.to_string(),
        "counterparties": counterparties,
        "memory_scope": ms.to_string(),
        "chain_depth": chain_depth,
        "chain_path": chain_path,
        "age_secs": 0,
        "discovery_method": dm,
        "purpose": purpose,
        "payment_amount": serde_json::Value::Null,
        "payment_adapter": serde_json::Value::Null,
        "payment_receipt_id": serde_json::Value::Null,
    });

    Ok(result.to_string())
}

/// Parses a discovery method string into a JSON value (§24.2.3).
///
/// Accepted formats:
/// - `OutOfBand`, `out_of_band`, `None`, `none`, or absent → `"OutOfBand"`
/// - `shared_context:<context_id>` → `{"SharedContext": "<context_id>"}`
/// - `registry:<context_id>` → `{"Registry": "<context_id>"}`
///
/// `"None"` / `"none"` are accepted for backward compatibility (renamed to
/// `OutOfBand` in issue #772).
fn parse_wasm_discovery_method(s: Option<&str>) -> Result<serde_json::Value, JsError> {
    let Some(s) = s else {
        return Ok(serde_json::json!("OutOfBand"));
    };
    match s {
        "none" | "None" | "OutOfBand" | "out_of_band" => Ok(serde_json::json!("OutOfBand")),
        _ if s.starts_with("shared_context:") => {
            let ctx_id = &s["shared_context:".len()..];
            if ctx_id.is_empty() {
                return Err(JsError::new(
                    "[SCP-VALID-7216] invalid discovery_method 'shared_context:': context ID must not be empty",
                ));
            }
            Ok(serde_json::json!({"SharedContext": ctx_id}))
        }
        _ if s.starts_with("registry:") => {
            let ctx_id = &s["registry:".len()..];
            if ctx_id.is_empty() {
                return Err(JsError::new(
                    "[SCP-VALID-7216] invalid discovery_method 'registry:': context ID must not be empty",
                ));
            }
            Ok(serde_json::json!({"Registry": ctx_id}))
        }
        other => Err(JsError::new(&format!(
            "[SCP-VALID-7216] invalid discovery_method '{other}': expected 'OutOfBand', \
             'out_of_band', 'shared_context:<context_id>', or 'registry:<context_id>'"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, target_arch = "wasm32"))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn check_chain_depth_within_default() {
        assert!(provenance_check_chain_depth(0, None));
        assert!(provenance_check_chain_depth(3, None));
    }

    #[test]
    fn check_chain_depth_exceeds_default() {
        assert!(!provenance_check_chain_depth(4, None));
    }

    #[test]
    fn check_chain_depth_custom_max() {
        assert!(provenance_check_chain_depth(4, Some(5)));
        assert!(!provenance_check_chain_depth(6, Some(5)));
    }

    #[test]
    fn check_chain_depth_clamps_to_hard_max() {
        // Even with override of 10, hard max is 5
        assert!(!provenance_check_chain_depth(6, Some(10)));
        assert!(provenance_check_chain_depth(5, Some(10)));
    }

    #[test]
    fn evaluate_quality_persistent_active() {
        let tier = evaluate_provenance_quality(
            Some("ctx-1".to_owned()),
            "Persistent".to_owned(),
            "Active".to_owned(),
            Some("[\"did:key:alice\"]".to_owned()),
        )
        .unwrap();
        assert_eq!(tier, 3);
    }

    #[test]
    fn evaluate_quality_no_provenance() {
        let tier =
            evaluate_provenance_quality(None, "Persistent".to_owned(), "Active".to_owned(), None)
                .unwrap();
        assert_eq!(tier, 0);
    }

    #[test]
    fn evaluate_quality_summary_verified() {
        let tier = evaluate_provenance_quality(
            Some("ctx-1".to_owned()),
            "Summary".to_owned(),
            "ClosedWithSummaryVerified".to_owned(),
            Some("[\"did:key:alice\"]".to_owned()),
        )
        .unwrap();
        assert_eq!(tier, 2);
    }

    #[test]
    fn evaluate_quality_active_ephemeral_always_returns_1() {
        // Active + non-Persistent always degrades to EphemeralKnownParties (1),
        // regardless of counterparties — matches scp-core evaluate_quality.
        let with_parties = evaluate_provenance_quality(
            Some("ctx-1".to_owned()),
            "Ephemeral".to_owned(),
            "Active".to_owned(),
            Some("[\"did:key:alice\"]".to_owned()),
        )
        .unwrap();
        assert_eq!(with_parties, 1);

        let without_parties = evaluate_provenance_quality(
            Some("ctx-1".to_owned()),
            "Ephemeral".to_owned(),
            "Active".to_owned(),
            None,
        )
        .unwrap();
        assert_eq!(without_parties, 1);
    }

    #[test]
    fn evaluate_quality_active_summary_always_returns_1() {
        // Active + Summary also degrades to EphemeralKnownParties (1).
        let tier = evaluate_provenance_quality(
            Some("ctx-1".to_owned()),
            "Summary".to_owned(),
            "Active".to_owned(),
            None,
        )
        .unwrap();
        assert_eq!(tier, 1);
    }

    #[test]
    fn evaluate_quality_ephemeral_with_parties() {
        let tier = evaluate_provenance_quality(
            Some("ctx-1".to_owned()),
            "Ephemeral".to_owned(),
            "ClosedEphemeral".to_owned(),
            Some("[\"did:key:alice\"]".to_owned()),
        )
        .unwrap();
        assert_eq!(tier, 1);
    }

    #[test]
    fn evaluate_quality_ephemeral_no_parties() {
        let tier = evaluate_provenance_quality(
            Some("ctx-1".to_owned()),
            "Ephemeral".to_owned(),
            "ClosedEphemeral".to_owned(),
            None,
        )
        .unwrap();
        assert_eq!(tier, 0);
    }

    #[test]
    fn evaluate_quality_ephemeral_empty_parties() {
        // Empty counterparties array should be treated as no counterparties
        let tier = evaluate_provenance_quality(
            Some("ctx-1".to_owned()),
            "Ephemeral".to_owned(),
            "ClosedEphemeral".to_owned(),
            Some("[]".to_owned()),
        )
        .unwrap();
        assert_eq!(tier, 0);
    }

    #[test]
    fn evaluate_quality_unknown_state() {
        let tier = evaluate_provenance_quality(
            Some("ctx-1".to_owned()),
            "Persistent".to_owned(),
            "Unknown".to_owned(),
            Some("[\"did:key:alice\"]".to_owned()),
        )
        .unwrap();
        assert_eq!(tier, 0);
    }

    #[test]
    fn evaluate_quality_invalid_state_fails() {
        assert!(
            evaluate_provenance_quality(
                Some("ctx-1".to_owned()),
                "Persistent".to_owned(),
                "InvalidState".to_owned(),
                Some("[\"did:key:alice\"]".to_owned()),
            )
            .is_err()
        );
    }

    #[test]
    fn evaluate_quality_invalid_counterparties_json_fails() {
        assert!(
            evaluate_provenance_quality(
                Some("ctx-1".to_owned()),
                "Persistent".to_owned(),
                "Active".to_owned(),
                Some("not valid json".to_owned()),
            )
            .is_err()
        );
    }

    #[test]
    fn attach_first_hop() {
        let result = provenance_attach(
            "ctx-source".to_owned(),
            "Persistent".to_owned(),
            "Full".to_owned(),
            "[\"did:key:alice\"]".to_owned(),
            "ctx-target".to_owned(),
            -1.0,
            "[]".to_owned(),
            None,
            None,
        )
        .unwrap();

        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["chain_depth"], 0);
        assert!(json["chain_path"].is_null());
        assert_eq!(json["source_context"], "ctx-source");
        assert_eq!(json["discovery_method"], "OutOfBand");
        assert!(json["purpose"].is_null());
        assert!(json["payment_amount"].is_null());
        assert!(json["payment_adapter"].is_null());
        assert!(json["payment_receipt_id"].is_null());
    }

    #[test]
    fn attach_second_hop() {
        let result = provenance_attach(
            "ctx-hop2".to_owned(),
            "Persistent".to_owned(),
            "Full".to_owned(),
            "[\"did:key:bob\"]".to_owned(),
            "ctx-target".to_owned(),
            0.0,
            "[]".to_owned(),
            None,
            None,
        )
        .unwrap();

        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["chain_depth"], 1);
        let path = json["chain_path"].as_array().unwrap();
        assert_eq!(path.len(), 1);
        assert_eq!(path[0], "ctx-hop2");
    }

    #[test]
    fn attach_with_discovery_method() {
        let result = provenance_attach(
            "ctx-source".to_owned(),
            "Persistent".to_owned(),
            "Full".to_owned(),
            "[]".to_owned(),
            "ctx-target".to_owned(),
            -1.0,
            "[]".to_owned(),
            Some("shared_context:ctx-shared".to_owned()),
            Some("data sharing".to_owned()),
        )
        .unwrap();

        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["discovery_method"]["SharedContext"], "ctx-shared");
        assert_eq!(json["purpose"], "data sharing");
    }

    #[test]
    fn attach_with_registry_discovery() {
        let result = provenance_attach(
            "ctx-source".to_owned(),
            "Persistent".to_owned(),
            "Full".to_owned(),
            "[]".to_owned(),
            "ctx-target".to_owned(),
            -1.0,
            "[]".to_owned(),
            Some("registry:ctx-registry".to_owned()),
            None,
        )
        .unwrap();

        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["discovery_method"]["Registry"], "ctx-registry");
    }

    #[test]
    fn attach_empty_source_fails() {
        assert!(
            provenance_attach(
                String::new(),
                "Persistent".to_owned(),
                "Full".to_owned(),
                "[]".to_owned(),
                "ctx-target".to_owned(),
                -1.0,
                "[]".to_owned(),
                None,
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn attach_invalid_source_type_fails() {
        assert!(
            provenance_attach(
                "ctx-source".to_owned(),
                "InvalidType".to_owned(),
                "Full".to_owned(),
                "[]".to_owned(),
                "ctx-target".to_owned(),
                -1.0,
                "[]".to_owned(),
                None,
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn attach_invalid_discovery_method_fails() {
        assert!(
            provenance_attach(
                "ctx-source".to_owned(),
                "Persistent".to_owned(),
                "Full".to_owned(),
                "[]".to_owned(),
                "ctx-target".to_owned(),
                -1.0,
                "[]".to_owned(),
                Some("invalid_method".to_owned()),
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn parse_discovery_method_rejects_empty_shared_context_id() {
        let result = parse_wasm_discovery_method(Some("shared_context:"));
        assert!(result.is_err());
    }

    #[test]
    fn parse_discovery_method_rejects_empty_registry_id() {
        let result = parse_wasm_discovery_method(Some("registry:"));
        assert!(result.is_err());
    }

    #[test]
    fn parse_discovery_method_accepts_valid_ids() {
        let shared = parse_wasm_discovery_method(Some("shared_context:ctx-123")).unwrap();
        assert_eq!(shared, serde_json::json!({"SharedContext": "ctx-123"}));

        let registry = parse_wasm_discovery_method(Some("registry:reg-456")).unwrap();
        assert_eq!(registry, serde_json::json!({"Registry": "reg-456"}));

        let none = parse_wasm_discovery_method(None).unwrap();
        assert_eq!(none, serde_json::json!("OutOfBand"));
    }

    // -----------------------------------------------------------------------
    // Lowercase / snake_case enum value tests (NAPI parity)
    // -----------------------------------------------------------------------

    #[test]
    fn evaluate_quality_lowercase_source_type_and_context_state() {
        // lowercase "persistent" + "active" must work (matches NAPI bridge)
        let tier = evaluate_provenance_quality(
            Some("ctx-1".to_owned()),
            "persistent".to_owned(),
            "active".to_owned(),
            Some("[\"did:key:alice\"]".to_owned()),
        )
        .unwrap();
        assert_eq!(tier, 3);
    }

    #[test]
    fn evaluate_quality_lowercase_ephemeral() {
        let tier = evaluate_provenance_quality(
            Some("ctx-1".to_owned()),
            "ephemeral".to_owned(),
            "closed_ephemeral".to_owned(),
            Some("[\"did:key:alice\"]".to_owned()),
        )
        .unwrap();
        assert_eq!(tier, 1);
    }

    #[test]
    fn evaluate_quality_lowercase_summary_verified() {
        let tier = evaluate_provenance_quality(
            Some("ctx-1".to_owned()),
            "summary".to_owned(),
            "closed_with_summary_verified".to_owned(),
            Some("[\"did:key:alice\"]".to_owned()),
        )
        .unwrap();
        assert_eq!(tier, 2);
    }

    #[test]
    fn evaluate_quality_lowercase_summary_unverified() {
        let tier = evaluate_provenance_quality(
            Some("ctx-1".to_owned()),
            "summary".to_owned(),
            "closed_with_summary_unverified".to_owned(),
            None,
        )
        .unwrap();
        assert_eq!(tier, 0);
    }

    #[test]
    fn evaluate_quality_lowercase_unknown() {
        let tier = evaluate_provenance_quality(
            Some("ctx-1".to_owned()),
            "persistent".to_owned(),
            "unknown".to_owned(),
            None,
        )
        .unwrap();
        assert_eq!(tier, 0);
    }

    #[test]
    fn attach_lowercase_source_type_and_memory_scope() {
        let result = provenance_attach(
            "ctx-source".to_owned(),
            "persistent".to_owned(),
            "full".to_owned(),
            "[\"did:key:alice\"]".to_owned(),
            "ctx-target".to_owned(),
            -1.0,
            "[]".to_owned(),
            None,
            None,
        )
        .unwrap();

        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["source_context"], "ctx-source");
        assert_eq!(json["source_type"], "Persistent");
        assert_eq!(json["memory_scope"], "Full");
    }

    #[test]
    fn attach_lowercase_ephemeral_summary() {
        let result = provenance_attach(
            "ctx-source".to_owned(),
            "ephemeral".to_owned(),
            "summary".to_owned(),
            "[]".to_owned(),
            "ctx-target".to_owned(),
            -1.0,
            "[]".to_owned(),
            None,
            None,
        )
        .unwrap();

        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["source_type"], "Ephemeral");
        assert_eq!(json["memory_scope"], "Summary");
    }

    #[test]
    fn attach_lowercase_summary_ephemeral_scope() {
        let result = provenance_attach(
            "ctx-source".to_owned(),
            "summary".to_owned(),
            "ephemeral".to_owned(),
            "[]".to_owned(),
            "ctx-target".to_owned(),
            -1.0,
            "[]".to_owned(),
            None,
            None,
        )
        .unwrap();

        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["source_type"], "Summary");
        assert_eq!(json["memory_scope"], "Ephemeral");
    }
}

/// Tests that run on all targets (including native) to verify lowercase/snake_case
/// enum parsing without requiring wasm-bindgen types.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests_native {
    use super::*;

    // -- SourceType --

    #[test]
    fn source_type_from_str_pascal_case() {
        assert!(matches!(SourceType::from_str("Persistent"), Some(SourceType::Persistent)));
        assert!(matches!(SourceType::from_str("Ephemeral"), Some(SourceType::Ephemeral)));
        assert!(matches!(SourceType::from_str("Summary"), Some(SourceType::Summary)));
    }

    #[test]
    fn source_type_from_str_lowercase() {
        assert!(matches!(SourceType::from_str("persistent"), Some(SourceType::Persistent)));
        assert!(matches!(SourceType::from_str("ephemeral"), Some(SourceType::Ephemeral)));
        assert!(matches!(SourceType::from_str("summary"), Some(SourceType::Summary)));
    }

    #[test]
    fn source_type_from_str_invalid() {
        assert!(SourceType::from_str("PERSISTENT").is_none());
        assert!(SourceType::from_str("invalid").is_none());
        assert!(SourceType::from_str("").is_none());
    }

    // -- ContextState --

    #[test]
    fn context_state_from_str_pascal_case() {
        assert!(matches!(ContextState::from_str("Active"), Some(ContextState::Active)));
        assert!(matches!(
            ContextState::from_str("ClosedWithSummaryVerified"),
            Some(ContextState::ClosedWithSummaryVerified)
        ));
        assert!(matches!(
            ContextState::from_str("ClosedWithSummaryUnverified"),
            Some(ContextState::ClosedWithSummaryUnverified)
        ));
        assert!(matches!(
            ContextState::from_str("ClosedEphemeral"),
            Some(ContextState::ClosedEphemeral)
        ));
        assert!(matches!(ContextState::from_str("Unknown"), Some(ContextState::Unknown)));
    }

    #[test]
    fn context_state_from_str_snake_case() {
        assert!(matches!(ContextState::from_str("active"), Some(ContextState::Active)));
        assert!(matches!(
            ContextState::from_str("closed_with_summary_verified"),
            Some(ContextState::ClosedWithSummaryVerified)
        ));
        assert!(matches!(
            ContextState::from_str("closed_with_summary_unverified"),
            Some(ContextState::ClosedWithSummaryUnverified)
        ));
        assert!(matches!(
            ContextState::from_str("closed_ephemeral"),
            Some(ContextState::ClosedEphemeral)
        ));
        assert!(matches!(ContextState::from_str("unknown"), Some(ContextState::Unknown)));
    }

    #[test]
    fn context_state_from_str_invalid() {
        assert!(ContextState::from_str("ACTIVE").is_none());
        assert!(ContextState::from_str("closedEphemeral").is_none());
        assert!(ContextState::from_str("").is_none());
    }

    // -- MemoryScope --

    #[test]
    fn memory_scope_from_str_pascal_case() {
        assert!(matches!(MemoryScope::from_str("Full"), Some(MemoryScope::Full)));
        assert!(matches!(MemoryScope::from_str("Summary"), Some(MemoryScope::Summary)));
        assert!(matches!(MemoryScope::from_str("Ephemeral"), Some(MemoryScope::Ephemeral)));
    }

    #[test]
    fn memory_scope_from_str_lowercase() {
        assert!(matches!(MemoryScope::from_str("full"), Some(MemoryScope::Full)));
        assert!(matches!(MemoryScope::from_str("summary"), Some(MemoryScope::Summary)));
        assert!(matches!(MemoryScope::from_str("ephemeral"), Some(MemoryScope::Ephemeral)));
    }

    #[test]
    fn memory_scope_from_str_invalid() {
        assert!(MemoryScope::from_str("FULL").is_none());
        assert!(MemoryScope::from_str("invalid").is_none());
        assert!(MemoryScope::from_str("").is_none());
    }

    // -- compute_quality with lowercase-parsed enums --

    #[test]
    fn compute_quality_with_lowercase_parsed_enums() {
        let st = SourceType::from_str("persistent").unwrap();
        let cs = ContextState::from_str("active").unwrap();
        assert_eq!(compute_quality(true, &st, cs, true), 3);

        let st2 = SourceType::from_str("summary").unwrap();
        let cs2 = ContextState::from_str("closed_with_summary_verified").unwrap();
        assert_eq!(compute_quality(true, &st2, cs2, true), 2);

        let st3 = SourceType::from_str("ephemeral").unwrap();
        let cs3 = ContextState::from_str("closed_ephemeral").unwrap();
        assert_eq!(compute_quality(true, &st3, cs3, true), 1);
        assert_eq!(compute_quality(true, &st3, cs3, false), 0);

        let cs4 = ContextState::from_str("unknown").unwrap();
        assert_eq!(compute_quality(true, &st, cs4, true), 0);
    }
}
