//! Standard tool schemas for contexts with discovery tools.
//!
//! Contexts with discovery tools are standard SCP contexts with standardized
//! tool schemas for search, registration, and deregistration. Two-tier
//! membership separates writers (MLS members, bounded at 500) from readers
//! (DID-authenticated, unbounded).
//!
//! Standard tool schemas (conventions per ADR-020):
//! - `agent_search(query) -> { results }` -- search the registry.
//! - `agent_register(did, capabilities, metadata) -> { registered, entry_id }` -- register an agent.
//! - `agent_deregister(did) -> { removed }` -- deregister an agent.
//!
//! Custom tools (reputation scoring, category browsing, geographic filtering)
//! are allowed beyond the standard set.
//!
//! See ADR-020 in `.docs/adrs/phase-4.md`, acceptance criteria 3-10.

use serde::{Deserialize, Serialize};

use super::{DID, RegistrationEntry};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Standard tool name for agent search.
pub const TOOL_AGENT_SEARCH: &str = "agent_search";

/// Standard tool name for agent registration.
pub const TOOL_AGENT_REGISTER: &str = "agent_register";

/// Standard tool name for agent deregistration.
pub const TOOL_AGENT_DEREGISTER: &str = "agent_deregister";

// ---------------------------------------------------------------------------
// AgentSearchParams
// ---------------------------------------------------------------------------

/// Parameters for the `agent_search` standard tool.
///
/// All fields are optional filters. An empty query matches all entries.
///
/// See ADR-020 acceptance criterion 3.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentSearchParams {
    /// Filter by capability strings. Only agents advertising all listed
    /// capabilities are returned.
    pub capability_filter: Option<Vec<String>>,
    /// Free-text keyword filter applied to metadata.
    pub keywords: Option<Vec<String>>,
    /// Maximum number of results to return.
    pub limit: Option<usize>,
}

// ---------------------------------------------------------------------------
// AgentSearchResult
// ---------------------------------------------------------------------------

/// Result of an `agent_search` tool invocation.
///
/// See ADR-020 acceptance criterion 3.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentSearchResult {
    /// Matching registration entries.
    pub entries: Vec<RegistrationEntry>,
    /// Total number of matches (may exceed `entries.len()` if limited).
    pub total_matches: usize,
}

// ---------------------------------------------------------------------------
// AgentRegisterParams
// ---------------------------------------------------------------------------

/// Parameters for the `agent_register` standard tool.
///
/// Sent as a DID-signed request by a reader. A writer verifies the signature
/// and records the registration in the event log as an application message.
/// The registrant does NOT become an MLS member.
///
/// See ADR-020 acceptance criterion 5.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentRegisterParams {
    /// The DID of the agent to register.
    pub did: DID,
    /// Capabilities to advertise in this registry.
    pub capabilities: Vec<String>,
    /// Arbitrary metadata for the registration.
    pub metadata: serde_json::Value,
}

// ---------------------------------------------------------------------------
// AgentRegisterResult
// ---------------------------------------------------------------------------

/// Result of an `agent_register` tool invocation.
///
/// See ADR-020 acceptance criterion 5.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentRegisterResult {
    /// Whether the registration was successful.
    pub registered: bool,
    /// The unique entry ID assigned to the registration.
    pub entry_id: String,
}

// ---------------------------------------------------------------------------
// AgentDeregisterParams
// ---------------------------------------------------------------------------

/// Parameters for the `agent_deregister` standard tool.
///
/// Privacy: registration is withdrawable via this tool. The agent must
/// authenticate as the entry owner.
///
/// See ADR-020 acceptance criterion 9.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentDeregisterParams {
    /// The DID of the agent to deregister.
    pub did: DID,
}

// ---------------------------------------------------------------------------
// AgentDeregisterResult
// ---------------------------------------------------------------------------

/// Result of an `agent_deregister` tool invocation.
///
/// See ADR-020 acceptance criterion 9.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentDeregisterResult {
    /// Whether the entry was removed.
    pub removed: bool,
}

// ---------------------------------------------------------------------------
// RegistrationEvent
// ---------------------------------------------------------------------------

/// Event payload for registration operations recorded in the Merkle event log.
///
/// All writes to the discovery context are recorded in the context's Merkle
/// event log (ADR-011). Readers can request inclusion proofs to verify
/// registration and audit registry integrity.
///
/// See ADR-020 acceptance criterion 10.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RegistrationEvent {
    /// An agent was registered.
    Registered {
        /// The registration entry.
        entry: RegistrationEntry,
        /// The DID of the writer that processed the registration.
        processed_by: DID,
    },
    /// An agent's registration was updated.
    Updated {
        /// The updated registration entry.
        entry: RegistrationEntry,
        /// The DID of the writer that processed the update.
        processed_by: DID,
    },
    /// An agent was deregistered.
    Deregistered {
        /// The DID of the deregistered agent.
        did: DID,
        /// The entry ID that was removed.
        entry_id: String,
        /// The DID of the writer that processed the deregistration.
        processed_by: DID,
    },
}

// ---------------------------------------------------------------------------
// Standard tool schemas (JSON)
// ---------------------------------------------------------------------------

/// Returns the JSON Schema for the `agent_search` tool.
#[must_use]
pub fn agent_search_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "capability_filter": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Filter by capability strings"
            },
            "keywords": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Free-text keyword filter"
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of results"
            }
        }
    })
}

/// Returns the JSON Schema for the `agent_register` tool.
#[must_use]
pub fn agent_register_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "required": ["did", "capabilities"],
        "properties": {
            "did": {
                "type": "string",
                "description": "The DID of the agent to register"
            },
            "capabilities": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Capabilities to advertise"
            },
            "metadata": {
                "type": "object",
                "description": "Arbitrary metadata"
            }
        }
    })
}

/// Returns the JSON Schema for the `agent_deregister` tool.
#[must_use]
pub fn agent_deregister_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "required": ["did"],
        "properties": {
            "did": {
                "type": "string",
                "description": "The DID of the agent to deregister"
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Returns whether a tool name matches one of the standard discovery tool
/// names.
#[must_use]
pub fn is_standard_tool(name: &str) -> bool {
    matches!(
        name,
        TOOL_AGENT_SEARCH | TOOL_AGENT_REGISTER | TOOL_AGENT_DEREGISTER
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const AGENT_A_DID: &str = "did:dht:z6MkAgentA";
    const WRITER_DID: &str = "did:dht:z6MkWriter";

    // -- Standard tool schemas --------------------------------------------

    #[test]
    fn agent_search_schema_is_valid_json_object() {
        let schema = agent_search_schema();
        assert!(schema.is_object());
        assert_eq!(schema["type"], "object");
    }

    #[test]
    fn agent_register_schema_is_valid_json_object() {
        let schema = agent_register_schema();
        assert!(schema.is_object());
        assert_eq!(schema["type"], "object");
        assert!(
            schema["required"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("did"))
        );
    }

    #[test]
    fn agent_deregister_schema_is_valid_json_object() {
        let schema = agent_deregister_schema();
        assert!(schema.is_object());
        assert_eq!(schema["type"], "object");
        assert!(
            schema["required"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("did"))
        );
    }

    // -- Serialization roundtrips -----------------------------------------

    #[test]
    fn agent_search_params_serialization_roundtrip() {
        let params = AgentSearchParams {
            capability_filter: Some(vec!["code_review".to_owned()]),
            keywords: Some(vec!["rust".to_owned()]),
            limit: Some(10),
        };
        let json = serde_json::to_string(&params).unwrap();
        let deserialized: AgentSearchParams = serde_json::from_str(&json).unwrap();
        assert_eq!(params, deserialized);
    }

    #[test]
    fn agent_register_params_serialization_roundtrip() {
        let params = AgentRegisterParams {
            did: AGENT_A_DID.into(),
            capabilities: vec!["testing".to_owned()],
            metadata: serde_json::json!({"key": "value"}),
        };
        let json = serde_json::to_string(&params).unwrap();
        let deserialized: AgentRegisterParams = serde_json::from_str(&json).unwrap();
        assert_eq!(params, deserialized);
    }

    #[test]
    fn agent_deregister_params_serialization_roundtrip() {
        let params = AgentDeregisterParams {
            did: AGENT_A_DID.into(),
        };
        let json = serde_json::to_string(&params).unwrap();
        let deserialized: AgentDeregisterParams = serde_json::from_str(&json).unwrap();
        assert_eq!(params, deserialized);
    }

    #[test]
    fn agent_register_result_serialization_roundtrip() {
        let result = AgentRegisterResult {
            registered: true,
            entry_id: "reg-1".to_owned(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: AgentRegisterResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }

    #[test]
    fn agent_deregister_result_serialization_roundtrip() {
        let result = AgentDeregisterResult { removed: true };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: AgentDeregisterResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }

    #[test]
    fn registration_event_serialization_roundtrip() {
        let entry = RegistrationEntry {
            did: AGENT_A_DID.into(),
            capabilities: vec!["testing".to_owned()],
            metadata: serde_json::json!({}),
            entry_id: "reg-1".to_owned(),
            registered_at: 1_700_000_000,
        };

        let event = RegistrationEvent::Registered {
            entry,
            processed_by: WRITER_DID.into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: RegistrationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, deserialized);
    }

    // -- is_standard_tool -------------------------------------------------

    #[test]
    fn is_standard_tool_detects_standard_names() {
        assert!(is_standard_tool(TOOL_AGENT_SEARCH));
        assert!(is_standard_tool(TOOL_AGENT_REGISTER));
        assert!(is_standard_tool(TOOL_AGENT_DEREGISTER));
        assert!(!is_standard_tool("custom_tool"));
        assert!(!is_standard_tool(""));
    }

    // -- AgentSearchResult serialization ----------------------------------

    #[test]
    fn agent_search_result_serialization_roundtrip() {
        let result = AgentSearchResult {
            entries: vec![RegistrationEntry {
                did: AGENT_A_DID.into(),
                capabilities: vec!["testing".to_owned()],
                metadata: serde_json::json!({}),
                entry_id: "reg-1".to_owned(),
                registered_at: 1_700_000_000,
            }],
            total_matches: 1,
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: AgentSearchResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }
}
