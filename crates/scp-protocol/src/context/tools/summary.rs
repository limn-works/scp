//! Default summary tool for generating structured context summaries.
//!
//! Produces a structured JSON summary from a context's event log, including
//! participant DIDs, message counts, time range, tool invocations, and
//! governance actions. Registered by default in the `summary` context template.
//!
//! See issue #365 and spec §5.11.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::json;

use scp_primitives::DID;

// ---------------------------------------------------------------------------
// ContextSummary
// ---------------------------------------------------------------------------

/// Structured output from the default summary tool.
///
/// All fields are deterministically derived from the event log. The output
/// schema is a `serde_json::Value` with a well-defined structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextSummary {
    /// DIDs of all participants who appear in the event log.
    pub participant_dids: Vec<DID>,
    /// Number of messages sent per participant.
    pub message_count_per_participant: HashMap<String, u64>,
    /// Unix timestamp (seconds) of the first event.
    pub first_event_at: Option<u64>,
    /// Unix timestamp (seconds) of the last event.
    pub last_event_at: Option<u64>,
    /// Tool invocation counts: tool name -> invocation count.
    pub tool_invocations: HashMap<String, u64>,
    /// Governance actions taken, with counts.
    pub governance_actions: HashMap<String, u64>,
    /// Total number of events in the log.
    pub total_event_count: usize,
}

/// Generates a structured summary from a list of event names and timestamps.
///
/// Events are expected as `(event_name, timestamp, optional_did)` tuples
/// extracted from the event log. The function parses event names to extract
/// participant, tool, and governance metadata.
///
/// # Arguments
///
/// * `events` - Slice of event entries with (`event_name`, timestamp).
///
/// # Returns
///
/// A [`ContextSummary`] containing the structured summary data.
#[must_use]
pub fn generate_summary(events: &[(String, u64)]) -> ContextSummary {
    let mut participants: HashMap<String, u64> = HashMap::new();
    let mut tool_invocations: HashMap<String, u64> = HashMap::new();
    let mut governance_actions: HashMap<String, u64> = HashMap::new();
    let mut first_event_at: Option<u64> = None;
    let mut last_event_at: Option<u64> = None;

    for (event_name, timestamp) in events {
        // Track time range.
        match first_event_at {
            None => first_event_at = Some(*timestamp),
            Some(first) if *timestamp < first => first_event_at = Some(*timestamp),
            _ => {}
        }
        match last_event_at {
            None => last_event_at = Some(*timestamp),
            Some(last) if *timestamp > last => last_event_at = Some(*timestamp),
            _ => {}
        }

        // Categorize events by name prefix.
        if event_name.starts_with("MessageSent") {
            // Extract DID from "MessageSent:did:..." pattern if present.
            if let Some(did) = event_name.strip_prefix("MessageSent:") {
                *participants.entry(did.to_owned()).or_insert(0) += 1;
            } else {
                *participants.entry("unknown".to_owned()).or_insert(0) += 1;
            }
        } else if event_name.starts_with("MemberJoined") {
            if let Some(did) = event_name.strip_prefix("MemberJoined:") {
                participants.entry(did.to_owned()).or_insert(0);
            }
        } else if event_name.starts_with("ToolInvoked") {
            if let Some(tool_name) = event_name.strip_prefix("ToolInvoked:") {
                *tool_invocations.entry(tool_name.to_owned()).or_insert(0) += 1;
            } else {
                *tool_invocations.entry("unknown".to_owned()).or_insert(0) += 1;
            }
        } else if event_name.starts_with("GovernanceAction") {
            if let Some(action_name) = event_name.strip_prefix("GovernanceAction:") {
                *governance_actions
                    .entry(action_name.to_owned())
                    .or_insert(0) += 1;
            } else {
                *governance_actions.entry("unknown".to_owned()).or_insert(0) += 1;
            }
        }
    }

    let participant_dids: Vec<DID> = participants.keys().map(|d| DID::from(d.as_str())).collect();

    ContextSummary {
        participant_dids,
        message_count_per_participant: participants,
        first_event_at,
        last_event_at,
        tool_invocations,
        governance_actions,
        total_event_count: events.len(),
    }
}

/// Converts a [`ContextSummary`] to a `serde_json::Value` with a defined schema.
///
/// The output is a JSON object matching the MCP-compatible tool output schema.
#[must_use]
pub fn summary_to_json(summary: &ContextSummary) -> serde_json::Value {
    json!({
        "participant_dids": summary.participant_dids,
        "message_count_per_participant": summary.message_count_per_participant,
        "first_event_at": summary.first_event_at,
        "last_event_at": summary.last_event_at,
        "tool_invocations": summary.tool_invocations,
        "governance_actions": summary.governance_actions,
        "total_event_count": summary.total_event_count,
    })
}

/// Returns the MCP-compatible JSON Schema for the default summary tool output.
#[must_use]
pub fn summary_output_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {
            "participant_dids": {
                "type": "array",
                "items": { "type": "string" }
            },
            "message_count_per_participant": {
                "type": "object",
                "additionalProperties": { "type": "integer" }
            },
            "first_event_at": {
                "type": ["integer", "null"]
            },
            "last_event_at": {
                "type": ["integer", "null"]
            },
            "tool_invocations": {
                "type": "object",
                "additionalProperties": { "type": "integer" }
            },
            "governance_actions": {
                "type": "object",
                "additionalProperties": { "type": "integer" }
            },
            "total_event_count": {
                "type": "integer"
            }
        },
        "required": [
            "participant_dids",
            "message_count_per_participant",
            "first_event_at",
            "last_event_at",
            "tool_invocations",
            "governance_actions",
            "total_event_count"
        ]
    })
}

/// Returns the MCP-compatible JSON Schema for the default summary tool input.
///
/// The tool accepts no input (the event log is implicit). The input schema is
/// an empty object for MCP compatibility.
#[must_use]
pub fn summary_input_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {},
        "required": []
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn generate_summary_empty_events() {
        let summary = generate_summary(&[]);
        assert!(summary.participant_dids.is_empty());
        assert!(summary.message_count_per_participant.is_empty());
        assert!(summary.first_event_at.is_none());
        assert!(summary.last_event_at.is_none());
        assert!(summary.tool_invocations.is_empty());
        assert!(summary.governance_actions.is_empty());
        assert_eq!(summary.total_event_count, 0);
    }

    #[test]
    fn generate_summary_with_messages() {
        let events = vec![
            ("MemberJoined:did:dht:alice".to_owned(), 100),
            ("MemberJoined:did:dht:bob".to_owned(), 101),
            ("MessageSent:did:dht:alice".to_owned(), 102),
            ("MessageSent:did:dht:alice".to_owned(), 103),
            ("MessageSent:did:dht:bob".to_owned(), 104),
        ];
        let summary = generate_summary(&events);
        assert_eq!(summary.total_event_count, 5);
        assert_eq!(
            summary.message_count_per_participant.get("did:dht:alice"),
            Some(&2)
        );
        assert_eq!(
            summary.message_count_per_participant.get("did:dht:bob"),
            Some(&1)
        );
        assert_eq!(summary.first_event_at, Some(100));
        assert_eq!(summary.last_event_at, Some(104));
    }

    #[test]
    fn generate_summary_with_tools_and_governance() {
        let events = vec![
            ("ToolInvoked:search".to_owned(), 100),
            ("ToolInvoked:search".to_owned(), 101),
            ("ToolInvoked:generate".to_owned(), 102),
            ("GovernanceAction:RoleAssign".to_owned(), 103),
            ("GovernanceAction:RoleAssign".to_owned(), 104),
            ("GovernanceAction:MemberBan".to_owned(), 105),
        ];
        let summary = generate_summary(&events);
        assert_eq!(summary.tool_invocations.get("search"), Some(&2));
        assert_eq!(summary.tool_invocations.get("generate"), Some(&1));
        assert_eq!(summary.governance_actions.get("RoleAssign"), Some(&2));
        assert_eq!(summary.governance_actions.get("MemberBan"), Some(&1));
    }

    #[test]
    fn generate_summary_ten_events_produces_valid_json() {
        let events: Vec<(String, u64)> = (0..10)
            .map(|i| {
                let name = match i % 4 {
                    0 => format!("MemberJoined:did:dht:user{i}"),
                    1 => format!("MessageSent:did:dht:user{i}"),
                    2 => format!("ToolInvoked:tool{i}"),
                    _ => format!("GovernanceAction:action{i}"),
                };
                (name, 1000 + i)
            })
            .collect();
        let summary = generate_summary(&events);
        let json = summary_to_json(&summary);
        assert!(json.is_object());
        assert_eq!(
            json.get("total_event_count")
                .and_then(serde_json::Value::as_u64),
            Some(10)
        );
        assert!(json.get("participant_dids").unwrap().is_array());
        assert!(json.get("tool_invocations").unwrap().is_object());
        assert!(json.get("governance_actions").unwrap().is_object());
    }

    #[test]
    fn summary_output_schema_is_valid_json_object() {
        let schema = summary_output_schema();
        assert_eq!(schema.get("type").and_then(|v| v.as_str()), Some("object"));
        assert!(schema.get("properties").unwrap().is_object());
    }

    #[test]
    fn summary_input_schema_is_valid_json_object() {
        let schema = summary_input_schema();
        assert_eq!(schema.get("type").and_then(|v| v.as_str()), Some("object"));
    }
}
