//! WASM-local runtime helpers and re-exports from `scp-protocol`.
//!
//! Tool registration types (`ToolRegistration`, `TestVector`, `ToolCost`,
//! `ToolSchema`), `ToolRegistry`, and schema validation functions
//! (`validate_schema`, `validate_value_against_schema`) are imported from
//! `scp-protocol`.
//!
//! Event log, Merkle proofs, and event type tags are provided by `scp-event-log`.
//!
//! Context state management lives in
//! [`WasmContextManager`](crate::manager::WasmContextManager) per issue #389.
//!
//! See SCP-218 and ADR-022/ADR-034 in `.docs/adrs/phase-4.md`.

// Re-export tool types from scp-protocol for use by manager.rs, tools.rs, etc.
pub use scp_protocol::context::tools::schema::{
    SchemaValidationError, validate_schema, validate_value_against_schema,
};
pub use scp_protocol::context::tools::{
    TestVector, ToolCost, ToolRegistration, ToolRegistry, ToolSchema,
};

/// Inserts a tool registration with duplicate checking.
///
/// Unlike `ToolRegistry::insert` (which returns the previous registration),
/// this returns an error if the tool ID is already registered — preserving
/// the WASM bridge's "register once" semantics.
///
/// # Errors
///
/// Returns an error string if the tool ID is already registered.
pub fn tool_registry_insert_unique(
    registry: &mut ToolRegistry,
    registration: ToolRegistration,
) -> Result<(), String> {
    if registry.contains(&registration.tool_id) {
        return Err(format!(
            "tool already registered: \"{}\"",
            registration.tool_id
        ));
    }
    registry.insert(registration);
    Ok(())
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
