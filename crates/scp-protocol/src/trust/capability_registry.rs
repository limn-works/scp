//! Protocol capability registry (ADR-041, §7.3.4.3).
//!
//! Compile-time constant maps from [`CapabilityUri`] string representations to
//! [`RegistryEntry`] metadata. The registry contains 28 protocol-defined
//! challenge capabilities across 10 categories and 5 system capabilities.
//!
//! Note: `scp:capability:tool-integrity/v1` is NOT included — it is an
//! attestation type (§7.4.2), not a challenge-testable capability. See #407.
//!
//! # SDK Enforcement (§7.3.4.2)
//!
//! [`validate_capability_uri`] is the SDK enforcement point: it accepts known
//! protocol capabilities, known system capabilities, and all valid DID-scoped
//! URIs (no registry lookup). It rejects unknown `scp:capability:*` and unknown
//! `scp:system:*` URIs with [`CapabilityRegistryError::UnknownProtocolCapability`].
//!
//! # Examples
//!
//! ```
//! use scp_core::trust::capability_registry::{
//!     lookup_protocol_capability, is_known_protocol_capability, validate_capability_uri,
//! };
//! use scp_core::trust::CapabilityUri;
//!
//! // Lookup a known protocol capability
//! let entry = lookup_protocol_capability("scp:capability:prompt-injection-resistance/v1");
//! assert!(entry.is_some());
//! assert_eq!(entry.unwrap().category, "safety-security");
//!
//! // Check if a URI is a known protocol capability
//! assert!(is_known_protocol_capability("scp:capability:schema-validation/v1"));
//! assert!(!is_known_protocol_capability("scp:capability:nonexistent/v1"));
//!
//! // Validate a capability URI (SDK enforcement point)
//! let uri = validate_capability_uri("scp:capability:prompt-injection-resistance/v1").unwrap();
//! assert!(matches!(uri, CapabilityUri::Protocol { .. }));
//!
//! // DID-scoped URIs are always accepted
//! let uri = validate_capability_uri("did:dht:z6Mk123:capability:custom/v1").unwrap();
//! assert!(matches!(uri, CapabilityUri::DidScoped { .. }));
//!
//! // Unknown protocol URIs are rejected
//! let err = validate_capability_uri("scp:capability:nonexistent/v1");
//! assert!(err.is_err());
//! ```

use std::collections::HashMap;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

use super::capability_uri::{CapabilityUri, CapabilityUriError};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by capability registry validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CapabilityRegistryError {
    /// The URI is not a known protocol or system capability.
    #[error("unknown protocol capability: {0}")]
    UnknownProtocolCapability(String),

    /// The URI failed to parse.
    #[error("invalid capability URI: {0}")]
    InvalidUri(#[from] CapabilityUriError),
}

// ---------------------------------------------------------------------------
// RegistryEntry
// ---------------------------------------------------------------------------

/// Metadata for a registered protocol or system capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryEntry {
    /// Category grouping (e.g., `"safety-security"`, `"code"`, `"system"`).
    pub category: String,
    /// Human-readable description of what the capability tests or provides.
    pub description: String,
    /// Optional JSON Schema for capability parameters (e.g., `max_ms` for
    /// latency-compliance). `None` for capabilities with no parameters.
    pub parameter_schema: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Helper to build registry entries
// ---------------------------------------------------------------------------

fn entry(
    category: &str,
    description: &str,
    parameter_schema: Option<serde_json::Value>,
) -> RegistryEntry {
    RegistryEntry {
        category: category.to_owned(),
        description: description.to_owned(),
        parameter_schema,
    }
}

// ---------------------------------------------------------------------------
// Protocol registry (28 challenge capabilities)
// ---------------------------------------------------------------------------

/// The protocol capability registry: 28 challenge capabilities across 10
/// categories, keyed by their full URI string.
///
/// Per ADR-041 and §7.3.4.3.
static PROTOCOL_REGISTRY: LazyLock<HashMap<String, RegistryEntry>> = LazyLock::new(|| {
    // 28 challenge capabilities across 10 categories.
    // tool-integrity/v1 is NOT included: it is an attestation type (§7.4.2),
    // not a challenge-testable capability. See #407.
    let mut m = HashMap::with_capacity(28);

    // -- Safety & Security (4) --
    m.insert(
        "scp:capability:prompt-injection-resistance/v1".into(),
        entry(
            "safety-security",
            "Test prompts with injection vectors. Pass = follows system instructions despite adversarial input.",
            None,
        ),
    );
    m.insert(
        "scp:capability:content-safety/v1".into(),
        entry(
            "safety-security",
            "Harmful/illegal content requests. Pass = refusal on all vectors.",
            None,
        ),
    );
    m.insert(
        "scp:capability:privacy-compliance/v1".into(),
        entry(
            "safety-security",
            "Cross-context data leakage test. Pass = no leakage.",
            None,
        ),
    );
    m.insert(
        "scp:capability:credential-handling/v1".into(),
        entry(
            "safety-security",
            "Secrets provided in context. Pass = no credential exposure in outputs or tool calls.",
            None,
        ),
    );

    // -- Schema & Protocol Compliance (3) --
    m.insert(
        "scp:capability:schema-validation/v1".into(),
        entry(
            "schema-compliance",
            "Valid/invalid payloads against JSON Schema. Pass = correct classification.",
            None,
        ),
    );
    m.insert(
        "scp:capability:tool-schema-compliance/v1".into(),
        entry(
            "schema-compliance",
            "Tool calls must match declared schemas. Pass = no extra/missing fields.",
            None,
        ),
    );
    m.insert(
        "scp:capability:output-format-compliance/v1".into(),
        entry(
            "schema-compliance",
            "Produce output in requested formats. Pass = valid format.",
            None,
        ),
    );

    // -- Behavioral Compliance (4) --
    m.insert(
        "scp:capability:rate-limit-compliance/v1".into(),
        entry(
            "behavioral-compliance",
            "Stay within declared limits. Pass = no violations over window.",
            None,
        ),
    );
    m.insert(
        "scp:capability:instruction-adherence/v1".into(),
        entry(
            "behavioral-compliance",
            "Follow system instructions despite conflicting user input.",
            None,
        ),
    );
    m.insert(
        "scp:capability:context-policy-adherence/v1".into(),
        entry(
            "behavioral-compliance",
            "Follow context governance rules.",
            None,
        ),
    );
    m.insert(
        "scp:capability:graceful-degradation/v1".into(),
        entry(
            "behavioral-compliance",
            "Acknowledge limitations rather than hallucinate.",
            None,
        ),
    );

    // -- Operational (3) --
    m.insert(
        "scp:capability:latency-compliance/v1".into(),
        entry(
            "operational",
            "Respond within time bounds.",
            Some(serde_json::json!({
                "type": "object",
                "properties": {
                    "max_ms": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Maximum response time in milliseconds"
                    }
                },
                "required": ["max_ms"]
            })),
        ),
    );
    m.insert(
        "scp:capability:idempotency/v1".into(),
        entry(
            "operational",
            "Same request = consistent side effects. No double-execution.",
            None,
        ),
    );
    m.insert(
        "scp:capability:multilingual/v1".into(),
        entry(
            "operational",
            "Respond in specified languages.",
            Some(serde_json::json!({
                "type": "object",
                "properties": {
                    "languages": {
                        "type": "array",
                        "items": { "type": "string" },
                        "minItems": 1,
                        "description": "ISO 639-1 language codes the agent must support"
                    }
                },
                "required": ["languages"]
            })),
        ),
    );

    // -- Spending / Commerce (2) --
    m.insert(
        "scp:capability:spending-compliance/v1".into(),
        entry(
            "spending-commerce",
            "Request approval before spending, stay within budget.",
            None,
        ),
    );
    m.insert(
        "scp:capability:cost-awareness/v1".into(),
        entry(
            "spending-commerce",
            "Select cost-efficient tools, explain tradeoffs.",
            None,
        ),
    );

    // -- Reasoning / Logic (3) --
    m.insert(
        "scp:capability:logical-reasoning/v1".into(),
        entry(
            "reasoning-logic",
            "Logic problems. Pass = correct with valid reasoning.",
            None,
        ),
    );
    m.insert(
        "scp:capability:mathematical-reasoning/v1".into(),
        entry(
            "reasoning-logic",
            "Math problems.",
            Some(serde_json::json!({
                "type": "object",
                "properties": {
                    "difficulty": {
                        "type": "string",
                        "enum": ["basic", "intermediate", "advanced"],
                        "description": "Difficulty level of mathematical problems"
                    }
                },
                "required": ["difficulty"]
            })),
        ),
    );
    m.insert(
        "scp:capability:causal-reasoning/v1".into(),
        entry(
            "reasoning-logic",
            "Distinguish cause from correlation.",
            None,
        ),
    );

    // -- Code (2) --
    m.insert(
        "scp:capability:code-generation/v1".into(),
        entry(
            "code",
            "Produce working code from spec.",
            Some(serde_json::json!({
                "type": "object",
                "properties": {
                    "languages": {
                        "type": "array",
                        "items": { "type": "string" },
                        "minItems": 1,
                        "description": "Programming languages the agent must support"
                    }
                },
                "required": ["languages"]
            })),
        ),
    );
    m.insert(
        "scp:capability:code-review/v1".into(),
        entry("code", "Identify planted bugs with explanations.", None),
    );

    // -- Recall / Fidelity (2) --
    m.insert(
        "scp:capability:context-recall/v1".into(),
        entry(
            "recall-fidelity",
            "Accurate recall of earlier conversation.",
            None,
        ),
    );
    m.insert(
        "scp:capability:instruction-retention/v1".into(),
        entry(
            "recall-fidelity",
            "Follow instructions after long intervening context.",
            None,
        ),
    );

    // -- Bias / Fairness (2) --
    m.insert(
        "scp:capability:bias-resistance/v1".into(),
        entry(
            "bias-fairness",
            "Equivalent responses regardless of demographics.",
            None,
        ),
    );
    m.insert(
        "scp:capability:viewpoint-diversity/v1".into(),
        entry(
            "bias-fairness",
            "Multiple perspectives on contentious topics.",
            None,
        ),
    );

    // -- Factual / Hallucination (3) --
    m.insert(
        "scp:capability:factual-accuracy/v1".into(),
        entry(
            "factual-hallucination",
            "Correct on verifiable questions.",
            None,
        ),
    );
    m.insert(
        "scp:capability:hallucination-resistance/v1".into(),
        entry(
            "factual-hallucination",
            "\"I don't know\" for nonexistent things.",
            None,
        ),
    );
    m.insert(
        "scp:capability:source-attribution/v1".into(),
        entry("factual-hallucination", "Real, verifiable citations.", None),
    );

    // The spec §7.3.4.3 and ADR-041 list 28 challenge capabilities across
    // 10 categories. tool-integrity/v1 is an attestation type (§7.4.2),
    // not a challenge-testable capability — excluded per #407.
    debug_assert_eq!(
        m.len(),
        28,
        "PROTOCOL_REGISTRY must contain exactly 28 entries"
    );
    m
});

// ---------------------------------------------------------------------------
// System registry (5 system capabilities)
// ---------------------------------------------------------------------------

/// The system capability registry: 5 protocol-level feature flags for node
/// roles, keyed by their full URI string.
///
/// Per ADR-041 and §7.3.4.3.
static SYSTEM_REGISTRY: LazyLock<HashMap<String, RegistryEntry>> = LazyLock::new(|| {
    let mut m = HashMap::with_capacity(5);

    m.insert(
        "scp:system:mls-group-management".into(),
        entry("system", "MLS epoch transitions.", None),
    );
    m.insert(
        "scp:system:key-rotation".into(),
        entry("system", "Key rotation operations.", None),
    );
    m.insert(
        "scp:system:governance-participation".into(),
        entry("system", "Governance proposal/vote.", None),
    );
    m.insert(
        "scp:system:relay-operation".into(),
        entry("system", "Relay node.", None),
    );
    m.insert(
        "scp:system:bridge-operation".into(),
        entry("system", "Platform bridge.", None),
    );

    debug_assert_eq!(m.len(), 5, "SYSTEM_REGISTRY must contain exactly 5 entries");
    m
});

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Looks up a protocol challenge capability by its full URI string.
///
/// Returns `Some(&RegistryEntry)` if the URI matches a known protocol
/// capability, `None` otherwise.
///
/// # Examples
///
/// ```
/// use scp_core::trust::capability_registry::lookup_protocol_capability;
///
/// let entry = lookup_protocol_capability("scp:capability:prompt-injection-resistance/v1");
/// assert!(entry.is_some());
/// assert_eq!(entry.unwrap().category, "safety-security");
///
/// assert!(lookup_protocol_capability("scp:capability:nonexistent/v1").is_none());
/// ```
#[must_use]
pub fn lookup_protocol_capability(uri: &str) -> Option<&'static RegistryEntry> {
    PROTOCOL_REGISTRY.get(uri)
}

/// Looks up a system capability by its full URI string.
///
/// Returns `Some(&RegistryEntry)` if the URI matches a known system
/// capability, `None` otherwise.
#[must_use]
pub fn lookup_system_capability(uri: &str) -> Option<&'static RegistryEntry> {
    SYSTEM_REGISTRY.get(uri)
}

/// Returns `true` if the given URI string is a known protocol challenge
/// capability.
///
/// # Examples
///
/// ```
/// use scp_core::trust::capability_registry::is_known_protocol_capability;
///
/// assert!(is_known_protocol_capability("scp:capability:schema-validation/v1"));
/// assert!(!is_known_protocol_capability("scp:capability:nonexistent/v1"));
/// ```
#[must_use]
pub fn is_known_protocol_capability(uri: &str) -> bool {
    PROTOCOL_REGISTRY.contains_key(uri)
}

/// Returns `true` if the given URI string is a known system capability.
#[must_use]
pub fn is_known_system_capability(uri: &str) -> bool {
    SYSTEM_REGISTRY.contains_key(uri)
}

/// Validates a capability URI string, enforcing SDK-level restrictions
/// (§7.3.4.2).
///
/// - **Protocol capabilities** (`scp:capability:*`): accepted only if present
///   in the protocol registry. Unknown `scp:capability:*` URIs are rejected
///   with [`CapabilityRegistryError::UnknownProtocolCapability`].
/// - **System capabilities** (`scp:system:*`): accepted only if present in
///   the system registry. Unknown `scp:system:*` URIs are rejected with
///   [`CapabilityRegistryError::UnknownProtocolCapability`].
/// - **DID-scoped capabilities** (`did:*`): always accepted without registry
///   lookup (authority is the definer's DID).
///
/// # Errors
///
/// - [`CapabilityRegistryError::InvalidUri`] if the URI fails structural
///   parsing.
/// - [`CapabilityRegistryError::UnknownProtocolCapability`] if the URI has
///   a reserved prefix (`scp:capability:*` or `scp:system:*`) but is not in
///   the registry.
///
/// # Examples
///
/// ```
/// use scp_core::trust::capability_registry::validate_capability_uri;
///
/// // Known protocol capability — accepted
/// assert!(validate_capability_uri("scp:capability:prompt-injection-resistance/v1").is_ok());
///
/// // Unknown protocol capability — rejected
/// assert!(validate_capability_uri("scp:capability:nonexistent/v1").is_err());
///
/// // DID-scoped — always accepted
/// assert!(validate_capability_uri("did:dht:z6Mk123:capability:anything/v1").is_ok());
///
/// // Known system capability — accepted
/// assert!(validate_capability_uri("scp:system:relay-operation").is_ok());
///
/// // Unknown system capability — rejected
/// assert!(validate_capability_uri("scp:system:nonexistent").is_err());
/// ```
pub fn validate_capability_uri(uri: &str) -> Result<CapabilityUri, CapabilityRegistryError> {
    let parsed: CapabilityUri = uri.parse()?;

    match &parsed {
        CapabilityUri::Protocol { .. } => {
            if !PROTOCOL_REGISTRY.contains_key(uri) {
                return Err(CapabilityRegistryError::UnknownProtocolCapability(
                    uri.to_owned(),
                ));
            }
        }
        CapabilityUri::System { .. } => {
            if !SYSTEM_REGISTRY.contains_key(uri) {
                return Err(CapabilityRegistryError::UnknownProtocolCapability(
                    uri.to_owned(),
                ));
            }
        }
        CapabilityUri::DidScoped { .. } => {
            // DID-scoped URIs are always accepted — authority is the
            // definer's identity, not the protocol registry.
        }
    }

    Ok(parsed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Registry size invariants
    // -----------------------------------------------------------------------

    #[test]
    fn protocol_registry_contains_exactly_28_entries() {
        assert_eq!(PROTOCOL_REGISTRY.len(), 28);
    }

    #[test]
    fn system_registry_contains_exactly_5_entries() {
        assert_eq!(SYSTEM_REGISTRY.len(), 5);
    }

    // -----------------------------------------------------------------------
    // All 28 protocol capability URIs (from §7.3.4.3)
    // -----------------------------------------------------------------------

    const ALL_PROTOCOL_URIS: [&str; 28] = [
        // Safety & Security (4)
        "scp:capability:prompt-injection-resistance/v1",
        "scp:capability:content-safety/v1",
        "scp:capability:privacy-compliance/v1",
        "scp:capability:credential-handling/v1",
        // Schema & Protocol Compliance (3)
        "scp:capability:schema-validation/v1",
        "scp:capability:tool-schema-compliance/v1",
        "scp:capability:output-format-compliance/v1",
        // Behavioral Compliance (4)
        "scp:capability:rate-limit-compliance/v1",
        "scp:capability:instruction-adherence/v1",
        "scp:capability:context-policy-adherence/v1",
        "scp:capability:graceful-degradation/v1",
        // Operational (3)
        "scp:capability:latency-compliance/v1",
        "scp:capability:idempotency/v1",
        "scp:capability:multilingual/v1",
        // Spending / Commerce (2)
        "scp:capability:spending-compliance/v1",
        "scp:capability:cost-awareness/v1",
        // Reasoning / Logic (3)
        "scp:capability:logical-reasoning/v1",
        "scp:capability:mathematical-reasoning/v1",
        "scp:capability:causal-reasoning/v1",
        // Code (2)
        "scp:capability:code-generation/v1",
        "scp:capability:code-review/v1",
        // Recall / Fidelity (2)
        "scp:capability:context-recall/v1",
        "scp:capability:instruction-retention/v1",
        // Bias / Fairness (2)
        "scp:capability:bias-resistance/v1",
        "scp:capability:viewpoint-diversity/v1",
        // Factual / Hallucination (3)
        "scp:capability:factual-accuracy/v1",
        "scp:capability:hallucination-resistance/v1",
        "scp:capability:source-attribution/v1",
    ];

    const ALL_SYSTEM_URIS: [&str; 5] = [
        "scp:system:mls-group-management",
        "scp:system:key-rotation",
        "scp:system:governance-participation",
        "scp:system:relay-operation",
        "scp:system:bridge-operation",
    ];

    // -----------------------------------------------------------------------
    // lookup_protocol_capability
    // -----------------------------------------------------------------------

    #[test]
    fn lookup_protocol_capability_returns_some_for_known() {
        let entry = lookup_protocol_capability("scp:capability:prompt-injection-resistance/v1");
        assert!(entry.is_some());
        let e = entry.unwrap();
        assert_eq!(e.category, "safety-security");
        assert!(!e.description.is_empty());
    }

    #[test]
    fn lookup_protocol_capability_returns_none_for_unknown() {
        assert!(lookup_protocol_capability("scp:capability:nonexistent/v1").is_none());
    }

    #[test]
    fn lookup_protocol_capability_returns_none_for_system() {
        assert!(lookup_protocol_capability("scp:system:relay-operation").is_none());
    }

    // -----------------------------------------------------------------------
    // is_known_protocol_capability
    // -----------------------------------------------------------------------

    #[test]
    fn is_known_protocol_capability_true_for_all_28() {
        for uri in ALL_PROTOCOL_URIS {
            assert!(
                is_known_protocol_capability(uri),
                "expected is_known_protocol_capability to return true for {uri}"
            );
        }
    }

    #[test]
    fn is_known_protocol_capability_false_for_unknown() {
        assert!(!is_known_protocol_capability(
            "scp:capability:nonexistent/v1"
        ));
    }

    #[test]
    fn is_known_protocol_capability_false_for_system() {
        assert!(!is_known_protocol_capability("scp:system:relay-operation"));
    }

    // -----------------------------------------------------------------------
    // System capability lookup
    // -----------------------------------------------------------------------

    #[test]
    fn lookup_system_capability_returns_some_for_known() {
        for uri in ALL_SYSTEM_URIS {
            let entry = lookup_system_capability(uri);
            assert!(
                entry.is_some(),
                "expected lookup_system_capability to return Some for {uri}"
            );
            assert_eq!(entry.unwrap().category, "system");
        }
    }

    #[test]
    fn lookup_system_capability_returns_none_for_unknown() {
        assert!(lookup_system_capability("scp:system:nonexistent").is_none());
    }

    #[test]
    fn is_known_system_capability_true_for_all_5() {
        for uri in ALL_SYSTEM_URIS {
            assert!(
                is_known_system_capability(uri),
                "expected is_known_system_capability to return true for {uri}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // validate_capability_uri — protocol capabilities
    // -----------------------------------------------------------------------

    #[test]
    fn validate_accepts_all_28_protocol_capabilities() {
        for uri in ALL_PROTOCOL_URIS {
            let result = validate_capability_uri(uri);
            assert!(
                result.is_ok(),
                "validate_capability_uri should accept known protocol URI {uri}, got {result:?}"
            );
            assert!(matches!(result.unwrap(), CapabilityUri::Protocol { .. }));
        }
    }

    #[test]
    fn validate_rejects_unknown_protocol_capability() {
        let result = validate_capability_uri("scp:capability:nonexistent/v1");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CapabilityRegistryError::UnknownProtocolCapability(_)
        ));
    }

    // -----------------------------------------------------------------------
    // validate_capability_uri — system capabilities
    // -----------------------------------------------------------------------

    #[test]
    fn validate_accepts_all_5_system_capabilities() {
        for uri in ALL_SYSTEM_URIS {
            let result = validate_capability_uri(uri);
            assert!(
                result.is_ok(),
                "validate_capability_uri should accept known system URI {uri}, got {result:?}"
            );
            assert!(matches!(result.unwrap(), CapabilityUri::System { .. }));
        }
    }

    #[test]
    fn validate_rejects_unknown_system_capability() {
        let result = validate_capability_uri("scp:system:nonexistent");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CapabilityRegistryError::UnknownProtocolCapability(_)
        ));
    }

    // -----------------------------------------------------------------------
    // validate_capability_uri — DID-scoped capabilities
    // -----------------------------------------------------------------------

    #[test]
    fn validate_accepts_arbitrary_did_scoped_capabilities() {
        // DID-scoped URIs are always accepted without registry lookup
        let uris = [
            "did:dht:z6Mk123:capability:anything/v1",
            "did:web:example.com:capability:custom-skill/v42",
            "did:key:z6Mktest:capability:domain-expertise/v3",
        ];
        for uri in uris {
            let result = validate_capability_uri(uri);
            assert!(
                result.is_ok(),
                "validate_capability_uri should accept DID-scoped URI {uri}, got {result:?}"
            );
            assert!(matches!(result.unwrap(), CapabilityUri::DidScoped { .. }));
        }
    }

    // -----------------------------------------------------------------------
    // validate_capability_uri — invalid URIs
    // -----------------------------------------------------------------------

    #[test]
    fn validate_rejects_malformed_uri() {
        let result = validate_capability_uri("not-a-uri");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CapabilityRegistryError::InvalidUri(_)
        ));
    }

    // -----------------------------------------------------------------------
    // Parameterized capabilities have non-None parameter_schema
    // -----------------------------------------------------------------------

    #[test]
    fn parameterized_capabilities_have_schemas() {
        let parameterized = [
            "scp:capability:latency-compliance/v1",
            "scp:capability:multilingual/v1",
            "scp:capability:mathematical-reasoning/v1",
            "scp:capability:code-generation/v1",
        ];
        for uri in parameterized {
            let entry = lookup_protocol_capability(uri).unwrap();
            assert!(
                entry.parameter_schema.is_some(),
                "expected parameter_schema to be Some for {uri}"
            );
        }
    }

    #[test]
    fn code_review_has_no_parameter_schema() {
        // code-review is NOT parameterized per the spec (no param listed in ADR-041)
        let entry = lookup_protocol_capability("scp:capability:code-review/v1").unwrap();
        assert!(entry.parameter_schema.is_none());
    }

    #[test]
    fn non_parameterized_capabilities_have_none_schema() {
        let non_parameterized = [
            "scp:capability:prompt-injection-resistance/v1",
            "scp:capability:content-safety/v1",
            "scp:capability:schema-validation/v1",
            "scp:capability:rate-limit-compliance/v1",
            "scp:capability:spending-compliance/v1",
            "scp:capability:logical-reasoning/v1",
            "scp:capability:context-recall/v1",
            "scp:capability:bias-resistance/v1",
            "scp:capability:factual-accuracy/v1",
        ];
        for uri in non_parameterized {
            let entry = lookup_protocol_capability(uri).unwrap();
            assert!(
                entry.parameter_schema.is_none(),
                "expected parameter_schema to be None for {uri}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Category grouping
    // -----------------------------------------------------------------------

    #[test]
    fn category_grouping_safety_security() {
        let uris = [
            "scp:capability:prompt-injection-resistance/v1",
            "scp:capability:content-safety/v1",
            "scp:capability:privacy-compliance/v1",
            "scp:capability:credential-handling/v1",
        ];
        for uri in uris {
            assert_eq!(
                lookup_protocol_capability(uri).unwrap().category,
                "safety-security",
                "wrong category for {uri}"
            );
        }
        assert_eq!(uris.len(), 4);
    }

    #[test]
    fn category_grouping_schema_compliance() {
        let uris = [
            "scp:capability:schema-validation/v1",
            "scp:capability:tool-schema-compliance/v1",
            "scp:capability:output-format-compliance/v1",
        ];
        for uri in uris {
            assert_eq!(
                lookup_protocol_capability(uri).unwrap().category,
                "schema-compliance",
                "wrong category for {uri}"
            );
        }
        assert_eq!(uris.len(), 3);
    }

    #[test]
    fn category_grouping_behavioral_compliance() {
        let uris = [
            "scp:capability:rate-limit-compliance/v1",
            "scp:capability:instruction-adherence/v1",
            "scp:capability:context-policy-adherence/v1",
            "scp:capability:graceful-degradation/v1",
        ];
        for uri in uris {
            assert_eq!(
                lookup_protocol_capability(uri).unwrap().category,
                "behavioral-compliance",
                "wrong category for {uri}"
            );
        }
        assert_eq!(uris.len(), 4);
    }

    #[test]
    fn category_grouping_operational() {
        let uris = [
            "scp:capability:latency-compliance/v1",
            "scp:capability:idempotency/v1",
            "scp:capability:multilingual/v1",
        ];
        for uri in uris {
            assert_eq!(
                lookup_protocol_capability(uri).unwrap().category,
                "operational",
                "wrong category for {uri}"
            );
        }
        assert_eq!(uris.len(), 3);
    }

    #[test]
    fn category_grouping_spending_commerce() {
        let uris = [
            "scp:capability:spending-compliance/v1",
            "scp:capability:cost-awareness/v1",
        ];
        for uri in uris {
            assert_eq!(
                lookup_protocol_capability(uri).unwrap().category,
                "spending-commerce",
                "wrong category for {uri}"
            );
        }
        assert_eq!(uris.len(), 2);
    }

    #[test]
    fn category_grouping_reasoning_logic() {
        let uris = [
            "scp:capability:logical-reasoning/v1",
            "scp:capability:mathematical-reasoning/v1",
            "scp:capability:causal-reasoning/v1",
        ];
        for uri in uris {
            assert_eq!(
                lookup_protocol_capability(uri).unwrap().category,
                "reasoning-logic",
                "wrong category for {uri}"
            );
        }
        assert_eq!(uris.len(), 3);
    }

    #[test]
    fn category_grouping_code() {
        let uris = [
            "scp:capability:code-generation/v1",
            "scp:capability:code-review/v1",
        ];
        for uri in uris {
            assert_eq!(
                lookup_protocol_capability(uri).unwrap().category,
                "code",
                "wrong category for {uri}"
            );
        }
        assert_eq!(uris.len(), 2);
    }

    #[test]
    fn category_grouping_recall_fidelity() {
        let uris = [
            "scp:capability:context-recall/v1",
            "scp:capability:instruction-retention/v1",
        ];
        for uri in uris {
            assert_eq!(
                lookup_protocol_capability(uri).unwrap().category,
                "recall-fidelity",
                "wrong category for {uri}"
            );
        }
        assert_eq!(uris.len(), 2);
    }

    #[test]
    fn category_grouping_bias_fairness() {
        let uris = [
            "scp:capability:bias-resistance/v1",
            "scp:capability:viewpoint-diversity/v1",
        ];
        for uri in uris {
            assert_eq!(
                lookup_protocol_capability(uri).unwrap().category,
                "bias-fairness",
                "wrong category for {uri}"
            );
        }
        assert_eq!(uris.len(), 2);
    }

    #[test]
    fn category_grouping_factual_hallucination() {
        let uris = [
            "scp:capability:factual-accuracy/v1",
            "scp:capability:hallucination-resistance/v1",
            "scp:capability:source-attribution/v1",
        ];
        for uri in uris {
            assert_eq!(
                lookup_protocol_capability(uri).unwrap().category,
                "factual-hallucination",
                "wrong category for {uri}"
            );
        }
        assert_eq!(uris.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Round-trip: every registry entry's URI parses back to the same CapabilityUri
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_all_protocol_registry_entries() {
        for uri_str in ALL_PROTOCOL_URIS {
            let parsed: CapabilityUri = uri_str.parse().unwrap();
            let displayed = parsed.to_string();
            assert_eq!(
                displayed, uri_str,
                "round-trip failed for protocol capability {uri_str}"
            );
            // Parse again to verify the displayed form is equivalent
            let reparsed: CapabilityUri = displayed.parse().unwrap();
            assert_eq!(parsed, reparsed, "re-parse failed for {uri_str}");
        }
    }

    #[test]
    fn roundtrip_all_system_registry_entries() {
        for uri_str in ALL_SYSTEM_URIS {
            let parsed: CapabilityUri = uri_str.parse().unwrap();
            let displayed = parsed.to_string();
            assert_eq!(
                displayed, uri_str,
                "round-trip failed for system capability {uri_str}"
            );
            let reparsed: CapabilityUri = displayed.parse().unwrap();
            assert_eq!(parsed, reparsed, "re-parse failed for {uri_str}");
        }
    }

    // -----------------------------------------------------------------------
    // All protocol entries have Protocol variant
    // -----------------------------------------------------------------------

    #[test]
    fn all_protocol_entries_parse_to_protocol_variant() {
        for uri_str in ALL_PROTOCOL_URIS {
            let parsed: CapabilityUri = uri_str.parse().unwrap();
            assert!(
                matches!(parsed, CapabilityUri::Protocol { .. }),
                "expected Protocol variant for {uri_str}, got {parsed:?}"
            );
        }
    }

    #[test]
    fn all_system_entries_parse_to_system_variant() {
        for uri_str in ALL_SYSTEM_URIS {
            let parsed: CapabilityUri = uri_str.parse().unwrap();
            assert!(
                matches!(parsed, CapabilityUri::System { .. }),
                "expected System variant for {uri_str}, got {parsed:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // RegistryEntry struct fields
    // -----------------------------------------------------------------------

    /// tool-integrity/v1 is an attestation type (§7.4.2), NOT a challenge-
    /// testable capability. It must not appear in the protocol registry.
    /// Guard against accidental re-addition (#407).
    #[test]
    fn tool_integrity_is_not_a_protocol_capability() {
        assert!(
            !is_known_protocol_capability("scp:capability:tool-integrity/v1"),
            "tool-integrity/v1 is an attestation type, not a challenge capability"
        );
        assert!(
            validate_capability_uri("scp:capability:tool-integrity/v1").is_err(),
            "tool-integrity/v1 must be rejected by SDK validation"
        );
    }

    #[test]
    fn registry_entry_has_required_fields() {
        let entry =
            lookup_protocol_capability("scp:capability:prompt-injection-resistance/v1").unwrap();
        // category is a String
        assert!(!entry.category.is_empty());
        // description is a String
        assert!(!entry.description.is_empty());
        // parameter_schema is Option<serde_json::Value>
        // For this capability, it should be None
        assert!(entry.parameter_schema.is_none());
    }

    #[test]
    fn registry_entry_with_parameter_schema() {
        let entry = lookup_protocol_capability("scp:capability:latency-compliance/v1").unwrap();
        assert!(entry.parameter_schema.is_some());
        let schema = entry.parameter_schema.as_ref().unwrap();
        // Verify it has the expected structure
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"]["max_ms"].is_object());
    }

    // -----------------------------------------------------------------------
    // Serde round-trip for RegistryEntry
    // -----------------------------------------------------------------------

    #[test]
    fn registry_entry_serde_roundtrip() {
        let entry = lookup_protocol_capability("scp:capability:latency-compliance/v1").unwrap();
        let json = serde_json::to_string(entry).unwrap();
        let deserialized: RegistryEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(*entry, deserialized);
    }
}
