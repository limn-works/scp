//! `wasm-bindgen` bridge for provenance operations.
//!
//! Exposes provenance evaluation and attachment to JavaScript (browser target):
//!
//! - [`provenance_check_chain_depth`] — Check if chain depth is within limits.
//! - [`evaluate_provenance_quality`] — Evaluate provenance quality tier.
//! - [`provenance_attach`] — Attach provenance metadata for cross-context data flow.
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
            "Persistent" => Some(Self::Persistent),
            "Ephemeral" => Some(Self::Ephemeral),
            "Summary" => Some(Self::Summary),
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
            "Active" => Some(Self::Active),
            "ClosedWithSummaryVerified" => Some(Self::ClosedWithSummaryVerified),
            "ClosedWithSummaryUnverified" => Some(Self::ClosedWithSummaryUnverified),
            "ClosedEphemeral" => Some(Self::ClosedEphemeral),
            "Unknown" => Some(Self::Unknown),
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
            "Full" => Some(Self::Full),
            "Summary" => Some(Self::Summary),
            "Ephemeral" => Some(Self::Ephemeral),
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
/// - `source_type` — One of `"Persistent"`, `"Ephemeral"`, `"Summary"`, or `None`
///   (no provenance).
/// - `context_state` — One of `"Active"`, `"ClosedWithSummaryVerified"`,
///   `"ClosedWithSummaryUnverified"`, `"ClosedEphemeral"`, `"Unknown"`.
/// - `has_counterparties` — `"true"` or `"false"` string indicating whether
///   counterparties are known.
///
/// # Errors
///
/// Returns `JsError` if `context_state` or `source_type` are invalid values.
///
/// # JS usage
///
/// ```js
/// const tier = evaluate_provenance_quality("Persistent", "Active", true);
/// console.log(tier); // 3
/// ```
#[wasm_bindgen]
pub fn evaluate_provenance_quality(
    source_type: Option<String>,
    context_state: String,
    has_counterparties: bool,
) -> Result<u32, JsError> {
    let cs = ContextState::from_str(&context_state).ok_or_else(|| {
        JsError::new(&format!(
            "[SCP-VALID-7200] invalid context_state: '{context_state}'"
        ))
    })?;

    let Some(st_str) = source_type else {
        return Ok(compute_quality(
            false,
            &SourceType::Persistent,
            cs,
            has_counterparties,
        ));
    };

    let st = SourceType::from_str(&st_str).ok_or_else(|| {
        JsError::new(&format!("[SCP-VALID-7201] invalid source_type: '{st_str}'"))
    })?;

    Ok(compute_quality(true, &st, cs, has_counterparties))
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
/// - `source_type` — One of `"Persistent"`, `"Ephemeral"`, `"Summary"`.
/// - `memory_scope` — One of `"Full"`, `"Summary"`, `"Ephemeral"`.
/// - `counterparties_json` — JSON array of DID strings.
/// - `target_context_id` — ID of the target context.
/// - `existing_chain_depth` — Chain depth from existing provenance, or -1 for first hop.
/// - `existing_chain_path_json` — JSON array of context IDs from existing provenance, or empty.
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
///   '["did:key:alice"]', "ctx-target", -1, "[]"
/// );
/// ```
#[wasm_bindgen]
pub fn provenance_attach(
    source_context_id: String,
    source_type: String,
    memory_scope: String,
    counterparties_json: String,
    target_context_id: String,
    existing_chain_depth: f64,
    existing_chain_path_json: String,
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

    // Compute chain depth and path
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let (chain_depth, chain_path) = if existing_chain_depth < 0.0 {
        // First hop
        (0_u32, serde_json::Value::Null)
    } else {
        let prev_depth = existing_chain_depth.max(0.0) as u32;
        let new_depth = prev_depth.saturating_add(1);

        let mut path: Vec<String> =
            serde_json::from_str(&existing_chain_path_json).unwrap_or_default();
        path.push(source_context_id.clone());

        (new_depth, serde_json::json!(path))
    };

    let result = serde_json::json!({
        "source_context": source_context_id,
        "source_type": st.to_string(),
        "counterparties": counterparties,
        "memory_scope": ms.to_string(),
        "chain_depth": chain_depth,
        "chain_path": chain_path,
        "target_context": target_context_id,
    });

    Ok(result.to_string())
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
        let tier =
            evaluate_provenance_quality(Some("Persistent".to_owned()), "Active".to_owned(), true)
                .unwrap();
        assert_eq!(tier, 3);
    }

    #[test]
    fn evaluate_quality_no_provenance() {
        let tier = evaluate_provenance_quality(None, "Active".to_owned(), false).unwrap();
        assert_eq!(tier, 0);
    }

    #[test]
    fn evaluate_quality_summary_verified() {
        let tier = evaluate_provenance_quality(
            Some("Summary".to_owned()),
            "ClosedWithSummaryVerified".to_owned(),
            true,
        )
        .unwrap();
        assert_eq!(tier, 2);
    }

    #[test]
    fn evaluate_quality_active_ephemeral_always_returns_1() {
        // Active + non-Persistent always degrades to EphemeralKnownParties (1),
        // regardless of counterparties — matches scp-core evaluate_quality.
        let with_parties =
            evaluate_provenance_quality(Some("Ephemeral".to_owned()), "Active".to_owned(), true)
                .unwrap();
        assert_eq!(with_parties, 1);

        let without_parties =
            evaluate_provenance_quality(Some("Ephemeral".to_owned()), "Active".to_owned(), false)
                .unwrap();
        assert_eq!(without_parties, 1);
    }

    #[test]
    fn evaluate_quality_active_summary_always_returns_1() {
        // Active + Summary also degrades to EphemeralKnownParties (1).
        let tier =
            evaluate_provenance_quality(Some("Summary".to_owned()), "Active".to_owned(), false)
                .unwrap();
        assert_eq!(tier, 1);
    }

    #[test]
    fn evaluate_quality_ephemeral_with_parties() {
        let tier = evaluate_provenance_quality(
            Some("Ephemeral".to_owned()),
            "ClosedEphemeral".to_owned(),
            true,
        )
        .unwrap();
        assert_eq!(tier, 1);
    }

    #[test]
    fn evaluate_quality_ephemeral_no_parties() {
        let tier = evaluate_provenance_quality(
            Some("Ephemeral".to_owned()),
            "ClosedEphemeral".to_owned(),
            false,
        )
        .unwrap();
        assert_eq!(tier, 0);
    }

    #[test]
    fn evaluate_quality_unknown_state() {
        let tier =
            evaluate_provenance_quality(Some("Persistent".to_owned()), "Unknown".to_owned(), true)
                .unwrap();
        assert_eq!(tier, 0);
    }

    #[test]
    fn evaluate_quality_invalid_state_fails() {
        assert!(
            evaluate_provenance_quality(
                Some("Persistent".to_owned()),
                "InvalidState".to_owned(),
                true,
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
        )
        .unwrap();

        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["chain_depth"], 0);
        assert!(json["chain_path"].is_null());
        assert_eq!(json["source_context"], "ctx-source");
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
        )
        .unwrap();

        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["chain_depth"], 1);
        let path = json["chain_path"].as_array().unwrap();
        assert_eq!(path.len(), 1);
        assert_eq!(path[0], "ctx-hop2");
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
            )
            .is_err()
        );
    }
}
