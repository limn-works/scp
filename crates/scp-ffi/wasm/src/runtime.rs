//! WASM-local tool registry and re-exports from `scp-protocol`.
//!
//! Tool registration types (`ToolRegistration`, `TestVector`, `ToolCost`,
//! `ToolSchema`) and schema validation functions (`validate_schema`,
//! `validate_value_against_schema`) are imported from `scp-protocol`.
//!
//! A thin `ToolRegistry` wrapper is kept locally because the `scp-protocol`
//! version's `insert` method is `pub(crate)` and cannot be called from
//! external crates.
//!
//! Event log, Merkle proofs, and event type tags are provided by `scp-event-log`.
//!
//! Context state management lives in
//! [`WasmContextManager`](crate::manager::WasmContextManager) per issue #389.
//!
//! See SCP-218 and ADR-022/ADR-034 in `.docs/adrs/phase-4.md`.

use std::collections::HashMap;

// Re-export tool types from scp-protocol for use by manager.rs, tools.rs, etc.
pub use scp_protocol::context::tools::schema::{
    SchemaValidationError, validate_schema, validate_value_against_schema,
};
pub use scp_protocol::context::tools::{TestVector, ToolCost, ToolRegistration, ToolSchema};

// ---------------------------------------------------------------------------
// ToolRegistry — thin wrapper (scp-protocol's insert is pub(crate))
// ---------------------------------------------------------------------------

/// In-memory tool storage per context.
///
/// Wraps `HashMap<String, ToolRegistration>` with duplicate-checking insert.
/// Uses `ToolRegistration` from `scp-protocol`; only the registry wrapper is
/// local because `scp_protocol::context::tools::ToolRegistry::insert` is
/// `pub(crate)`.
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
