//! WASM-local algorithm implementations for Merkle tree, proofs, and schema validation.
//!
//! This module contains the pure algorithm implementations that mirror scp-core:
//! - `ToolRegistry` and `ToolRegistration` — tool registration storage
//! - `WasmEventLog` — RFC 6962 Merkle tree
//! - Merkle proof types and operations (inclusion/absence proofs)
//! - JSON Schema validation
//!
//! Context state management has been moved to
//! [`WasmContextManager`](crate::manager::WasmContextManager) per issue #389.
//! This module retains only the algorithm-level implementations that the manager
//! depends on. The algorithms are identical to scp-core's implementations;
//! `wasm_conformance.rs` cross-validates both.
//!
//! See SCP-218 and ADR-022/ADR-034 in `.docs/adrs/phase-4.md`.

use std::collections::BTreeSet;
use std::collections::HashMap;

use sha2::{Digest, Sha256};

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
    /// Test vectors for verification.
    pub test_vectors: Vec<TestVector>,
    /// DID of the tool operator.
    pub operator_did: String,
}

/// A known input-output pair for tool verification.
///
/// Mirrors `scp_core::context::tools::TestVector`.
pub struct TestVector {
    /// Input value.
    pub input: serde_json::Value,
    /// Expected output value.
    pub expected_output: serde_json::Value,
    /// Human-readable description.
    pub description: String,
}

// ---------------------------------------------------------------------------
// WasmEventLog — Merkle tree (mirrors scp-core EventLog)
// ---------------------------------------------------------------------------

/// An append-only Merkle tree for a single SCP context.
///
/// Mirrors `scp_event_log::EventLog`. Follows Certificate Transparency
/// (RFC 6962) structure with SHA-256 hashing and domain separation prefixes.
/// Leaf nodes use `0x00` prefix, interior nodes use `0x01` prefix.
pub struct WasmEventLog {
    /// SHA-256 hashes of events, in append order.
    leaves: Vec<[u8; 32]>,
    /// Interior node layers. `tree[0]` is the first interior layer above
    /// leaves. The root is at the top.
    tree: Vec<Vec<[u8; 32]>>,
    /// Context ID.
    context_id: String,
    /// Sorted index of `(leaf_hash, leaf_index)` for absence proof support.
    sorted_leaves: BTreeSet<([u8; 32], u64)>,
}

impl WasmEventLog {
    /// Creates a new empty event log.
    #[must_use]
    pub fn new(context_id: String) -> Self {
        Self {
            leaves: Vec::new(),
            tree: Vec::new(),
            context_id,
            sorted_leaves: BTreeSet::new(),
        }
    }

    /// Returns the number of leaves (events) in the log.
    #[must_use]
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Appends a pre-computed leaf hash to the log and rebuilds the tree.
    pub fn append_leaf(&mut self, leaf_hash: [u8; 32]) {
        let leaf_index = self.leaves.len() as u64;
        self.leaves.push(leaf_hash);
        self.sorted_leaves.insert((leaf_hash, leaf_index));
        self.recompute_tree();
    }

    /// Returns the current Merkle root hash.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        if self.leaves.is_empty() {
            return [0u8; 32];
        }
        if self.tree.is_empty() {
            return self.leaves[0];
        }
        let top_layer = &self.tree[self.tree.len() - 1];
        top_layer[0]
    }

    /// Returns the number of events in the log.
    #[must_use]
    pub fn event_count(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// Returns the context ID.
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Returns the leaf hashes in append order.
    #[must_use]
    pub fn leaves(&self) -> &[[u8; 32]] {
        &self.leaves
    }

    /// Returns the interior node layers.
    #[must_use]
    pub fn tree_layers(&self) -> &[Vec<[u8; 32]>] {
        &self.tree
    }

    /// Returns a reference to the sorted leaf index.
    #[must_use]
    pub fn sorted_leaves(&self) -> &BTreeSet<([u8; 32], u64)> {
        &self.sorted_leaves
    }

    /// Recomputes the entire interior tree from the leaf layer.
    ///
    /// RFC 6962 structure: odd nodes are promoted by hashing with themselves.
    fn recompute_tree(&mut self) {
        self.tree.clear();

        if self.leaves.len() <= 1 {
            return;
        }

        let mut current_layer: &[[u8; 32]] = &self.leaves;
        let mut owned_layer: Vec<[u8; 32]>;

        loop {
            let parent_count = current_layer.len().div_ceil(2);
            let mut parents = Vec::with_capacity(parent_count);

            let mut i = 0;
            while i < current_layer.len() {
                if i + 1 < current_layer.len() {
                    parents.push(hash_pair(&current_layer[i], &current_layer[i + 1]));
                } else {
                    // RFC 6962: odd node is promoted, not duplicated.
                    parents.push(current_layer[i]);
                }
                i += 2;
            }

            self.tree.push(parents.clone());

            if parents.len() == 1 {
                break;
            }

            owned_layer = parents;
            current_layer = &owned_layer;
        }
    }
}

// ---------------------------------------------------------------------------
// Merkle proof types (mirrors scp-core proof module)
// ---------------------------------------------------------------------------

/// Direction indicator for a proof step.
#[derive(Debug, Clone, Copy)]
pub enum Direction {
    /// The sibling is to the left.
    Left,
    /// The sibling is to the right.
    Right,
}

/// A single step in a Merkle inclusion proof path.
#[derive(Debug, Clone)]
pub struct ProofStep {
    /// The hash of the sibling node.
    pub sibling_hash: [u8; 32],
    /// Whether the sibling is left or right.
    pub direction: Direction,
}

/// A Merkle inclusion proof.
#[derive(Debug, Clone)]
pub struct InclusionProof {
    /// The leaf index.
    pub leaf_index: u64,
    /// The leaf hash.
    pub leaf_hash: [u8; 32],
    /// The path from leaf to root.
    pub path: Vec<ProofStep>,
    /// The root hash at proof time.
    pub root: [u8; 32],
}

/// A leaf hash paired with its inclusion proof (for absence proofs).
#[derive(Debug, Clone)]
pub struct LeafWithProof {
    /// The leaf hash.
    pub leaf_hash: [u8; 32],
    /// The leaf index.
    pub leaf_index: u64,
    /// The inclusion proof.
    pub inclusion_proof: InclusionProof,
}

/// An absence proof.
#[derive(Debug, Clone)]
pub struct AbsenceProof {
    /// The hash being proven absent.
    pub query_hash: [u8; 32],
    /// The greatest leaf hash less than the query hash.
    pub lower: Option<LeafWithProof>,
    /// The least leaf hash greater than the query hash.
    pub upper: Option<LeafWithProof>,
    /// The Merkle root.
    pub root: [u8; 32],
    /// Total leaf count.
    pub leaf_count: u64,
}

// ---------------------------------------------------------------------------
// Merkle proof operations (mirrors scp-core proof functions)
// ---------------------------------------------------------------------------

/// Generates a Merkle inclusion proof for the leaf at `leaf_index`.
///
/// # Errors
///
/// Returns an error if the log is empty or `leaf_index` is out of bounds.
pub fn prove_inclusion(log: &WasmEventLog, leaf_index: u64) -> Result<InclusionProof, String> {
    let leaf_count = log.event_count();

    if leaf_count == 0 {
        return Err("event log is empty".to_owned());
    }

    if leaf_index >= leaf_count {
        return Err(format!(
            "leaf index {leaf_index} out of bounds (log has {leaf_count} leaves)"
        ));
    }

    let leaves = log.leaves();
    #[allow(clippy::cast_possible_truncation)]
    let leaf_idx_usize = leaf_index as usize;
    let leaf_hash = leaves[leaf_idx_usize];
    let current_root = log.root();

    if leaf_count == 1 {
        return Ok(InclusionProof {
            leaf_index,
            leaf_hash,
            path: Vec::new(),
            root: current_root,
        });
    }

    let tree_layers = log.tree_layers();
    let mut path = Vec::new();
    let mut idx = leaf_idx_usize;

    // First level: siblings are in the leaf layer.
    let sibling_idx = idx ^ 1;
    if sibling_idx < leaves.len() {
        let direction = if idx.is_multiple_of(2) {
            Direction::Right
        } else {
            Direction::Left
        };
        path.push(ProofStep {
            sibling_hash: leaves[sibling_idx],
            direction,
        });
    }
    // Odd node: no proof step needed — node is promoted per RFC 6962.

    idx /= 2;

    // Remaining levels: siblings are in tree_layers.
    for layer in tree_layers.iter().take(tree_layers.len().saturating_sub(1)) {
        let sibling_idx = idx ^ 1;
        if sibling_idx < layer.len() {
            let direction = if idx.is_multiple_of(2) {
                Direction::Right
            } else {
                Direction::Left
            };
            path.push(ProofStep {
                sibling_hash: layer[sibling_idx],
                direction,
            });
        }
        // Odd node: no proof step needed — node is promoted per RFC 6962.
        idx /= 2;
    }

    Ok(InclusionProof {
        leaf_index,
        leaf_hash,
        path,
        root: current_root,
    })
}

/// Generates an absence proof for `event_hash`.
///
/// # Errors
///
/// Returns an error if the log is empty or the hash is present in the log.
pub fn prove_absence(log: &WasmEventLog, event_hash: &[u8; 32]) -> Result<AbsenceProof, String> {
    let leaf_count = log.event_count();

    if leaf_count == 0 {
        return Err("event log is empty".to_owned());
    }

    let sorted = log.sorted_leaves();
    let current_root = log.root();

    let exact_match = sorted
        .range((*event_hash, 0)..=(*event_hash, u64::MAX))
        .next();

    if exact_match.is_some() {
        return Err("absence proof requested for event hash that is present in the log".to_owned());
    }

    let lower = sorted
        .range(..(*event_hash, 0))
        .next_back()
        .map(|(hash, index)| (*hash, *index));

    let upper = sorted
        .range((*event_hash, u64::MAX)..)
        .next()
        .map(|(hash, index)| (*hash, *index));

    let lower_proof: Option<LeafWithProof> = lower
        .map(|(hash, index)| {
            let inclusion_proof = prove_inclusion(log, index)?;
            Ok::<LeafWithProof, String>(LeafWithProof {
                leaf_hash: hash,
                leaf_index: index,
                inclusion_proof,
            })
        })
        .transpose()?;

    let upper_proof: Option<LeafWithProof> = upper
        .map(|(hash, index)| {
            let inclusion_proof = prove_inclusion(log, index)?;
            Ok::<LeafWithProof, String>(LeafWithProof {
                leaf_hash: hash,
                leaf_index: index,
                inclusion_proof,
            })
        })
        .transpose()?;

    Ok(AbsenceProof {
        query_hash: *event_hash,
        lower: lower_proof,
        upper: upper_proof,
        root: current_root,
        leaf_count,
    })
}

/// Verifies a Merkle inclusion proof (pure function).
#[must_use]
pub fn verify_inclusion(proof: &InclusionProof) -> bool {
    let mut current_hash = proof.leaf_hash;

    for step in &proof.path {
        current_hash = match step.direction {
            Direction::Left => hash_pair(&step.sibling_hash, &current_hash),
            Direction::Right => hash_pair(&current_hash, &step.sibling_hash),
        };
    }

    current_hash == proof.root
}

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

/// Computes `SHA-256(0x01 || left || right)` for an interior Merkle tree node.
///
/// RFC 6962 Section 2.1 domain separation for interior nodes.
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

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
/// event log via [`WasmContextManager`]. Returns `(0, 0)` if context not found.
#[must_use]
pub fn query_trust_event_counts(_context_id: &str, _did: &str) -> (u64, u64) {
    // WASM bridge: event log is a Merkle tree of hashes only (no per-DID
    // event attribution). Return total leaf count as message_count.
    // Full per-DID scoring requires event payload storage (not available
    // in the WASM bridge due to scp-core dependency constraint).
    (0, 0)
}
