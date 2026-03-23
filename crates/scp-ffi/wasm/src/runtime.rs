//! WASM-local algorithm implementations for tool registration and schema validation.
//!
//! This module contains the WASM-local implementations that the manager depends on:
//! - `ToolRegistry` and `ToolRegistration` — tool registration storage
//! - JSON Schema validation
//!
//! Event log, Merkle proofs, and event type tags are provided by `scp-event-log`.
//!
//! Context state management has been moved to
//! [`WasmContextManager`](crate::manager::WasmContextManager) per issue #389.
//!
//! See SCP-218 and ADR-022/ADR-034 in `.docs/adrs/phase-4.md`.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// ToolRegistry — tool registration storage (mirrors scp-core)
// ---------------------------------------------------------------------------

/// In-memory tool storage per context.
///
/// Mirrors `scp_core::context::tools::ToolRegistry`. Stores tool registrations
/// keyed by tool ID.
pub struct ToolRegistry {
    tools: HashMap<String, ToolRegistration>,
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolRegistry {
    /// Creates a new empty tool registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    /// Returns the registration for `tool_id`, or `None` if not found.
    #[must_use]
    pub fn get(&self, tool_id: &str) -> Option<&ToolRegistration> {
        self.tools.get(tool_id)
    }

    /// Returns the number of registered tools.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// Returns `true` if the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// Inserts a tool registration.
    ///
    /// # Errors
    ///
    /// Returns an error if the tool ID is already registered.
    pub fn insert(&mut self, registration: ToolRegistration) -> Result<(), String> {
        if self.tools.contains_key(&registration.tool_id) {
            return Err(format!(
                "tool already registered: \"{}\"",
                registration.tool_id
            ));
        }
        self.tools
            .insert(registration.tool_id.clone(), registration);
        Ok(())
    }
}

/// Per-invocation cost metadata for a tool (spec §5.4.1, §19.3).
///
/// Mirrors `scp_core::context::tools::ToolCost`. Tool-level costs
/// are additive with context costs.
pub struct ToolCost {
    /// Cost per invocation in the smallest currency unit.
    pub amount: u64,
    /// ISO 4217 or protocol-defined currency code.
    pub currency: String,
    /// The DID that receives tool invocation payments. May differ from the
    /// context payee.
    pub payee: String,
    /// Optional pricing formula identifier for dynamic pricing (§19.4).
    pub cost_formula: Option<String>,
}

/// A tool registration entry.
///
/// Mirrors `scp_core::context::tools::ToolRegistration`.
pub struct ToolRegistration {
    /// Unique tool identifier.
    pub tool_id: String,
    /// Human-readable tool name.
    pub name: String,
    /// Tool description.
    pub description: String,
    /// JSON Schema for input/output.
    pub input_schema: serde_json::Value,
    /// JSON Schema for output.
    pub output_schema: serde_json::Value,
    /// SHA-256 hash of the tool implementation. Used for integrity verification.
    pub implementation_hash: [u8; 32],
    /// Test vectors for verification.
    pub test_vectors: Vec<TestVector>,
    /// DID of the tool operator.
    pub operator_did: String,
    /// Optional per-invocation cost metadata (spec §5.4.1, §19.3).
    pub cost: Option<ToolCost>,
    /// Unix timestamp (seconds) when the tool was registered.
    pub registered_at: u64,
    /// Ed25519 signature over the canonical registration bytes.
    pub signature: Vec<u8>,
}

/// A known input-output pair for tool verification.
///
/// Mirrors `scp_core::context::tools::TestVector`.
#[derive(Debug)]
pub struct TestVector {
    /// Input value.
    pub input: serde_json::Value,
    /// Expected output value.
    pub expected_output: serde_json::Value,
    /// Human-readable description.
    pub description: String,
}

// ---------------------------------------------------------------------------
// EventLog + Merkle proof types are now provided by `scp-event-log`.
// See `scp_event_log::{EventLog, Event, EventType, EventPayload}`,
// `scp_event_log::tree::{append_unsigned_event, event_type_tag, root, event_count}`,
// and `scp_event_log::proof::{prove_inclusion, prove_absence, verify_inclusion}`.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Schema validation (mirrors scp-core schema module)
// ---------------------------------------------------------------------------

/// Validates that a JSON value is a structurally valid JSON Schema.
///
/// # Errors
///
/// Returns an error if the schema is not a JSON object, is missing the
/// `"type"` field, or has an unrecognized type value.
#[allow(clippy::items_after_statements)]
pub fn validate_schema(schema: &serde_json::Value) -> Result<(), String> {
    let obj = schema
        .as_object()
        .ok_or_else(|| "schema must be a JSON object".to_owned())?;

    let type_field = obj
        .get("type")
        .ok_or_else(|| "schema is missing the required \"type\" field".to_owned())?;

    let type_str = type_field
        .as_str()
        .ok_or_else(|| "schema \"type\" field must be a string".to_owned())?;

    const VALID_TYPES: &[&str] = &[
        "object", "array", "string", "number", "integer", "boolean", "null",
    ];

    if !VALID_TYPES.contains(&type_str) {
        return Err(format!("unrecognized JSON Schema type: \"{type_str}\""));
    }

    Ok(())
}

/// Validates a JSON value against a JSON Schema using the `jsonschema` crate.
///
/// # Errors
///
/// Returns an error if the schema is invalid or the value does not conform.
pub fn validate_value_against_schema(
    value: &serde_json::Value,
    schema: &serde_json::Value,
) -> Result<(), String> {
    if !schema.is_object() {
        return Err("schema is not a JSON object".to_owned());
    }

    let validator =
        jsonschema::validator_for(schema).map_err(|e| format!("invalid schema: {e}"))?;

    validator
        .validate(value)
        .map_err(|e| format!("schema validation failed: {e}"))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Encodes bytes as lowercase hexadecimal.
#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Decodes a hex string to a 32-byte hash.
///
/// # Errors
///
/// Returns an error if the hex string is not exactly 64 characters or
/// contains invalid hex digits.
pub fn decode_hex_hash(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("hex decode error: {e}"))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("expected 32 bytes (64 hex chars), got {}", v.len()))
}

/// Queries event counts for trust scoring within a context.
///
/// Returns `(message_count, governance_count)` derived from the context's
/// event log via [`crate::manager::WasmContextManager`]. Returns `(0, 0)` if context not found.
///
/// WASM bridge limitation: the event log is a Merkle tree of hashes only
/// (no per-DID event attribution). Returns total leaf count as
/// `message_count`; `governance_count` is always 0. Full per-DID scoring
/// requires event payload storage (not available in the WASM bridge due
/// to scp-core dependency constraint per ADR-034).
#[must_use]
pub fn query_trust_event_counts(context_id: &str, _did: &str) -> (u64, u64) {
    crate::manager::with_manager(|mgr| {
        let total = mgr
            .event_log_leaf_count(context_id)
            .map_or(0, |n| u64::try_from(n).unwrap_or(u64::MAX));
        Ok((total, 0))
    })
    .unwrap_or((0, 0))
}
