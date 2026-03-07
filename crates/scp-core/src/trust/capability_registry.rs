//! Protocol capability registry (ADR-041, §7.3.4.3).
//!
//! Contains all protocol-defined challenge capabilities and system capabilities.
//! SDKs MUST reject any `scp:capability:*` URI not present in this registry.
//!
//! See ADR-041 in `.docs/adrs/phase-4.md`.

use std::collections::HashMap;
use std::sync::LazyLock;

use super::capability_uri::{AgentCapabilityUri, CapabilityUriError};

// ---------------------------------------------------------------------------
// RegistryEntry
// ---------------------------------------------------------------------------

/// Metadata for a registered protocol capability.
#[derive(Debug, Clone)]
pub struct RegistryEntry {
    /// Category grouping (e.g., `"safety-security"`, `"operational"`).
    pub category: String,
    /// Human-readable description of the capability.
    pub description: String,
    /// Optional JSON schema for challenge parameters.
    pub parameter_schema: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Protocol registry (27 challenge capabilities)
// ---------------------------------------------------------------------------

/// The protocol capability registry: all 27 challenge capabilities.
///
/// Keyed by the canonical URI string for fast lookup.
pub static PROTOCOL_REGISTRY: LazyLock<HashMap<String, RegistryEntry>> =
    LazyLock::new(|| {
        let mut m = HashMap::new();

        // Safety & Security (4)
        m.insert(
            "scp:capability:prompt-injection-resistance/v1".to_owned(),
            RegistryEntry {
                category: "safety-security".to_owned(),
                description: "Tests whether the subject resists prompt injection attacks."
                    .to_owned(),
                parameter_schema: None,
            },
        );
        m.insert(
            "scp:capability:content-safety/v1".to_owned(),
            RegistryEntry {
                category: "safety-security".to_owned(),
                description: "Tests whether the subject filters unsafe content.".to_owned(),
                parameter_schema: None,
            },
        );
        m.insert(
            "scp:capability:privacy-compliance/v1".to_owned(),
            RegistryEntry {
                category: "safety-security".to_owned(),
                description: "Tests whether the subject handles private data correctly.".to_owned(),
                parameter_schema: None,
            },
        );
        m.insert(
            "scp:capability:credential-handling/v1".to_owned(),
            RegistryEntry {
                category: "safety-security".to_owned(),
                description: "Tests whether the subject handles credentials securely.".to_owned(),
                parameter_schema: None,
            },
        );

        // Schema & Protocol Compliance (3)
        m.insert(
            "scp:capability:schema-validation/v1".to_owned(),
            RegistryEntry {
                category: "schema-compliance".to_owned(),
                description: "Tests whether the subject correctly validates schemas.".to_owned(),
                parameter_schema: None,
            },
        );
        m.insert(
            "scp:capability:tool-schema-compliance/v1".to_owned(),
            RegistryEntry {
                category: "schema-compliance".to_owned(),
                description: "Tests whether the subject complies with tool schemas.".to_owned(),
                parameter_schema: None,
            },
        );
        m.insert(
            "scp:capability:output-format-compliance/v1".to_owned(),
            RegistryEntry {
                category: "schema-compliance".to_owned(),
                description: "Tests whether the subject produces correctly formatted output."
                    .to_owned(),
                parameter_schema: None,
            },
        );

        // Behavioral Compliance (4)
        m.insert(
            "scp:capability:rate-limit-compliance/v1".to_owned(),
            RegistryEntry {
                category: "behavioral-compliance".to_owned(),
                description: "Tests whether the subject complies with rate limits.".to_owned(),
                parameter_schema: None,
            },
        );
        m.insert(
            "scp:capability:instruction-adherence/v1".to_owned(),
            RegistryEntry {
                category: "behavioral-compliance".to_owned(),
                description: "Tests whether the subject adheres to instructions.".to_owned(),
                parameter_schema: None,
            },
        );
        m.insert(
            "scp:capability:context-policy-adherence/v1".to_owned(),
            RegistryEntry {
                category: "behavioral-compliance".to_owned(),
                description: "Tests whether the subject adheres to context policies.".to_owned(),
                parameter_schema: None,
            },
        );
        m.insert(
            "scp:capability:graceful-degradation/v1".to_owned(),
            RegistryEntry {
                category: "behavioral-compliance".to_owned(),
                description: "Tests whether the subject degrades gracefully under load.".to_owned(),
                parameter_schema: None,
            },
        );

        // Operational (3)
        m.insert(
            "scp:capability:latency-compliance/v1".to_owned(),
            RegistryEntry {
                category: "operational".to_owned(),
                description: "Tests whether the subject responds within latency bounds.".to_owned(),
                parameter_schema: Some(serde_json::json!({
                    "type": "object",
                    "properties": {
                        "max_ms": { "type": "integer", "minimum": 1 }
                    },
                    "required": ["max_ms"]
                })),
            },
        );
        m.insert(
            "scp:capability:idempotency/v1".to_owned(),
            RegistryEntry {
                category: "operational".to_owned(),
                description: "Tests whether the subject's operations are idempotent.".to_owned(),
                parameter_schema: None,
            },
        );
        m.insert("scp:capability:multilingual/v1".to_owned(), RegistryEntry {
        category: "operational".to_owned(),
        description: "Tests whether the subject supports multiple languages.".to_owned(),
        parameter_schema: Some(serde_json::json!({
            "type": "object",
            "properties": {
                "languages": { "type": "array", "items": { "type": "string" }, "minItems": 1 }
            },
            "required": ["languages"]
        })),
    });

        // Spending / Commerce (2)
        m.insert(
            "scp:capability:spending-compliance/v1".to_owned(),
            RegistryEntry {
                category: "spending-commerce".to_owned(),
                description: "Tests whether the subject complies with spending limits.".to_owned(),
                parameter_schema: None,
            },
        );
        m.insert(
            "scp:capability:cost-awareness/v1".to_owned(),
            RegistryEntry {
                category: "spending-commerce".to_owned(),
                description: "Tests whether the subject is aware of operational costs.".to_owned(),
                parameter_schema: None,
            },
        );

        // Reasoning / Logic (3)
        m.insert(
            "scp:capability:logical-reasoning/v1".to_owned(),
            RegistryEntry {
                category: "reasoning-logic".to_owned(),
                description: "Tests logical reasoning capability.".to_owned(),
                parameter_schema: None,
            },
        );
        m.insert("scp:capability:mathematical-reasoning/v1".to_owned(), RegistryEntry {
        category: "reasoning-logic".to_owned(),
        description: "Tests mathematical reasoning capability.".to_owned(),
        parameter_schema: Some(serde_json::json!({
            "type": "object",
            "properties": {
                "difficulty": { "type": "string", "enum": ["basic", "intermediate", "advanced"] }
            },
            "required": ["difficulty"]
        })),
    });
        m.insert(
            "scp:capability:causal-reasoning/v1".to_owned(),
            RegistryEntry {
                category: "reasoning-logic".to_owned(),
                description: "Tests causal reasoning capability.".to_owned(),
                parameter_schema: None,
            },
        );

        // Code (2)
        m.insert("scp:capability:code-generation/v1".to_owned(), RegistryEntry {
        category: "code".to_owned(),
        description: "Tests code generation capability.".to_owned(),
        parameter_schema: Some(serde_json::json!({
            "type": "object",
            "properties": {
                "languages": { "type": "array", "items": { "type": "string" }, "minItems": 1 }
            },
            "required": ["languages"]
        })),
    });
        m.insert("scp:capability:code-review/v1".to_owned(), RegistryEntry {
        category: "code".to_owned(),
        description: "Tests code review capability.".to_owned(),
        parameter_schema: Some(serde_json::json!({
            "type": "object",
            "properties": {
                "languages": { "type": "array", "items": { "type": "string" }, "minItems": 1 }
            }
        })),
    });

        // Recall / Fidelity (2)
        m.insert(
            "scp:capability:context-recall/v1".to_owned(),
            RegistryEntry {
                category: "recall-fidelity".to_owned(),
                description: "Tests context recall capability.".to_owned(),
                parameter_schema: None,
            },
        );
        m.insert(
            "scp:capability:instruction-retention/v1".to_owned(),
            RegistryEntry {
                category: "recall-fidelity".to_owned(),
                description: "Tests instruction retention capability.".to_owned(),
                parameter_schema: None,
            },
        );

        // Bias / Fairness (2)
        m.insert(
            "scp:capability:bias-resistance/v1".to_owned(),
            RegistryEntry {
                category: "bias-fairness".to_owned(),
                description: "Tests bias resistance capability.".to_owned(),
                parameter_schema: None,
            },
        );
        m.insert(
            "scp:capability:viewpoint-diversity/v1".to_owned(),
            RegistryEntry {
                category: "bias-fairness".to_owned(),
                description: "Tests viewpoint diversity capability.".to_owned(),
                parameter_schema: None,
            },
        );

        // Factual / Hallucination (3)
        m.insert(
            "scp:capability:factual-accuracy/v1".to_owned(),
            RegistryEntry {
                category: "factual-hallucination".to_owned(),
                description: "Tests factual accuracy capability.".to_owned(),
                parameter_schema: None,
            },
        );
        m.insert(
            "scp:capability:hallucination-resistance/v1".to_owned(),
            RegistryEntry {
                category: "factual-hallucination".to_owned(),
                description: "Tests hallucination resistance capability.".to_owned(),
                parameter_schema: None,
            },
        );
        m.insert(
            "scp:capability:source-attribution/v1".to_owned(),
            RegistryEntry {
                category: "factual-hallucination".to_owned(),
                description: "Tests source attribution capability.".to_owned(),
                parameter_schema: None,
            },
        );

        m
    });

// ---------------------------------------------------------------------------
// System registry (5 system capabilities)
// ---------------------------------------------------------------------------

/// The system capability registry: all 5 system capabilities.
pub static SYSTEM_REGISTRY: LazyLock<HashMap<String, RegistryEntry>> = LazyLock::new(|| {
    let mut m = HashMap::new();

    m.insert(
        "scp:system:mls-group-management".to_owned(),
        RegistryEntry {
            category: "system".to_owned(),
            description: "Node manages MLS group state.".to_owned(),
            parameter_schema: None,
        },
    );
    m.insert(
        "scp:system:key-rotation".to_owned(),
        RegistryEntry {
            category: "system".to_owned(),
            description: "Node supports key rotation.".to_owned(),
            parameter_schema: None,
        },
    );
    m.insert(
        "scp:system:governance-participation".to_owned(),
        RegistryEntry {
            category: "system".to_owned(),
            description: "Node participates in governance.".to_owned(),
            parameter_schema: None,
        },
    );
    m.insert(
        "scp:system:relay-operation".to_owned(),
        RegistryEntry {
            category: "system".to_owned(),
            description: "Node operates as a relay.".to_owned(),
            parameter_schema: None,
        },
    );
    m.insert(
        "scp:system:bridge-operation".to_owned(),
        RegistryEntry {
            category: "system".to_owned(),
            description: "Node operates as a bridge.".to_owned(),
            parameter_schema: None,
        },
    );

    m
});

// ---------------------------------------------------------------------------
// Lookup functions
// ---------------------------------------------------------------------------

/// Looks up a protocol capability in the registry.
///
/// Returns `Some(&RegistryEntry)` if the URI is a known protocol capability,
/// `None` otherwise.
#[must_use]
pub fn lookup_protocol_capability(uri: &AgentCapabilityUri) -> Option<&'static RegistryEntry> {
    PROTOCOL_REGISTRY.get(&uri.to_string())
}

/// Returns `true` if the URI is a known protocol capability.
#[must_use]
pub fn is_known_protocol_capability(uri: &AgentCapabilityUri) -> bool {
    PROTOCOL_REGISTRY.contains_key(&uri.to_string())
}

/// Looks up a system capability in the registry.
///
/// Returns `Some(&RegistryEntry)` if the URI is a known system capability,
/// `None` otherwise.
#[must_use]
pub fn lookup_system_capability(uri: &AgentCapabilityUri) -> Option<&'static RegistryEntry> {
    SYSTEM_REGISTRY.get(&uri.to_string())
}

/// Validates an agent capability URI against the protocol registry.
///
/// - Protocol capabilities (`scp:capability:*`): must be present in
///   [`PROTOCOL_REGISTRY`]. Unknown protocol URIs are rejected.
/// - DID-scoped capabilities: always accepted (no registry lookup).
/// - System capabilities (`scp:system:*`): must be present in
///   [`SYSTEM_REGISTRY`]. Unknown system URIs are rejected.
///
/// # Errors
///
/// Returns [`CapabilityUriError::UnknownProtocolCapability`] if the URI uses
/// the `scp:capability:*` prefix but is not in the protocol registry, or if
/// it uses `scp:system:*` but is not in the system registry.
pub fn validate_capability_uri(uri: &AgentCapabilityUri) -> Result<(), CapabilityUriError> {
    match uri {
        AgentCapabilityUri::Protocol { .. } => {
            if is_known_protocol_capability(uri) {
                Ok(())
            } else {
                Err(CapabilityUriError::UnknownProtocolCapability(
                    uri.to_string(),
                ))
            }
        }
        AgentCapabilityUri::DidScoped { .. } => {
            // DID-scoped capabilities are always valid (authority is the DID).
            Ok(())
        }
        AgentCapabilityUri::System { .. } => {
            if SYSTEM_REGISTRY.contains_key(&uri.to_string()) {
                Ok(())
            } else {
                Err(CapabilityUriError::UnknownProtocolCapability(
                    uri.to_string(),
                ))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn protocol_registry_has_28_entries() {
        // ADR-041 lists 28 capabilities across 10 categories (the ADR text
        // says "27" but the actual enumerated list contains 28:
        // 4+3+4+3+2+3+2+2+2+3 = 28). The code matches the enumerated list.
        assert_eq!(PROTOCOL_REGISTRY.len(), 28);
    }

    #[test]
    fn system_registry_has_5_entries() {
        assert_eq!(SYSTEM_REGISTRY.len(), 5);
    }

    #[test]
    fn lookup_known_protocol_capability() {
        let uri: AgentCapabilityUri = "scp:capability:prompt-injection-resistance/v1"
            .parse()
            .unwrap();
        let entry = lookup_protocol_capability(&uri);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().category, "safety-security");
    }

    #[test]
    fn lookup_unknown_protocol_capability() {
        let uri: AgentCapabilityUri = "scp:capability:nonexistent/v1".parse().unwrap();
        assert!(lookup_protocol_capability(&uri).is_none());
    }

    #[test]
    fn is_known_returns_true_for_all_28() {
        for key in PROTOCOL_REGISTRY.keys() {
            let uri: AgentCapabilityUri = key.parse().unwrap();
            assert!(is_known_protocol_capability(&uri), "expected known: {key}");
        }
    }

    #[test]
    fn validate_accepts_all_protocol_capabilities() {
        for key in PROTOCOL_REGISTRY.keys() {
            let uri: AgentCapabilityUri = key.parse().unwrap();
            assert!(
                validate_capability_uri(&uri).is_ok(),
                "expected valid: {key}"
            );
        }
    }

    #[test]
    fn validate_accepts_did_scoped() {
        let uri: AgentCapabilityUri = "did:dht:z6Mk123:capability:custom/v1".parse().unwrap();
        assert!(validate_capability_uri(&uri).is_ok());
    }

    #[test]
    fn validate_rejects_unknown_protocol() {
        let uri: AgentCapabilityUri = "scp:capability:nonexistent/v1".parse().unwrap();
        let err = validate_capability_uri(&uri).unwrap_err();
        assert!(matches!(
            err,
            CapabilityUriError::UnknownProtocolCapability(_)
        ));
    }

    #[test]
    fn validate_accepts_system_capabilities() {
        for key in SYSTEM_REGISTRY.keys() {
            let uri: AgentCapabilityUri = key.parse().unwrap();
            assert!(
                validate_capability_uri(&uri).is_ok(),
                "expected valid system: {key}"
            );
        }
    }

    #[test]
    fn validate_rejects_unknown_system() {
        let uri: AgentCapabilityUri = "scp:system:nonexistent".parse().unwrap();
        let err = validate_capability_uri(&uri).unwrap_err();
        assert!(matches!(
            err,
            CapabilityUriError::UnknownProtocolCapability(_)
        ));
    }

    #[test]
    fn parameterized_capabilities_have_schemas() {
        let parameterized = [
            "scp:capability:latency-compliance/v1",
            "scp:capability:multilingual/v1",
            "scp:capability:mathematical-reasoning/v1",
            "scp:capability:code-generation/v1",
            "scp:capability:code-review/v1",
        ];
        for uri_str in &parameterized {
            let entry = PROTOCOL_REGISTRY.get(*uri_str);
            assert!(entry.is_some(), "expected registry entry for {uri_str}");
            assert!(
                entry.unwrap().parameter_schema.is_some(),
                "expected parameter_schema for {uri_str}"
            );
        }
    }

    #[test]
    fn category_counts() {
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for entry in PROTOCOL_REGISTRY.values() {
            *counts.entry(entry.category.as_str()).or_default() += 1;
        }
        assert_eq!(counts["safety-security"], 4);
        assert_eq!(counts["schema-compliance"], 3);
        assert_eq!(counts["behavioral-compliance"], 4);
        assert_eq!(counts["operational"], 3);
        assert_eq!(counts["spending-commerce"], 2);
        assert_eq!(counts["reasoning-logic"], 3);
        assert_eq!(counts["code"], 2);
        assert_eq!(counts["recall-fidelity"], 2);
        assert_eq!(counts["bias-fairness"], 2);
        assert_eq!(counts["factual-hallucination"], 3);
    }

    #[test]
    fn all_registry_uris_parse_roundtrip() {
        for key in PROTOCOL_REGISTRY.keys() {
            let uri: AgentCapabilityUri = key.parse().unwrap();
            assert_eq!(uri.to_string(), *key, "roundtrip failed for {key}");
        }
        for key in SYSTEM_REGISTRY.keys() {
            let uri: AgentCapabilityUri = key.parse().unwrap();
            assert_eq!(uri.to_string(), *key, "roundtrip failed for {key}");
        }
    }
}
