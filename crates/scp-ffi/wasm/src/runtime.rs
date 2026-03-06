//! WASM-local runtime registry mapping context IDs to live runtime state.
//!
//! Mirrors the `PyO3` bridge's `runtime.rs` (see `crates/scp-ffi/src/runtime.rs`)
//! but uses only WASM-compatible types — no scp-core dependency (which requires
//! tokio multi-thread runtime, incompatible with wasm32-unknown-unknown).
//!
//! The runtime re-implements the relevant scp-core logic (tool registry, event
//! log Merkle tree, UCAN revocation, schema validation) in pure Rust that
//! compiles to wasm32. The algorithms are identical to scp-core's implementations.
//!
//! # Architecture
//!
//! A global `RefCell<HashMap<String, WasmContextRuntime>>` maps context IDs to
//! their runtime state. WASM is single-threaded, so `RefCell` provides interior
//! mutability without the overhead of `Mutex` or `DashMap`.
//!
//! See SCP-218 and ADR-022 in `.docs/adrs/phase-4.md`.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};

use sha2::{Digest, Sha256};

use crate::error::ScpWasmError;

// ---------------------------------------------------------------------------
// Thread-local context registry (WASM is single-threaded)
// ---------------------------------------------------------------------------

thread_local! {
    static CONTEXT_REGISTRY: RefCell<HashMap<String, WasmContextRuntime>> =
        RefCell::new(HashMap::new());
}

// ---------------------------------------------------------------------------
// WasmContextRuntime — per-context runtime state
// ---------------------------------------------------------------------------

/// Per-context runtime state for the WASM bridge.
///
/// Mirrors `ContextRuntime` in the `PyO3` bridge's `runtime.rs`. Each context
/// gets its own tool registry, event log, revocation list, and capability
/// ceiling. Created by `context_create`, destroyed by `context_close`.
pub struct WasmContextRuntime {
    /// Tool registry for this context.
    pub tool_registry: ToolRegistry,
    /// Event log (Merkle tree) for this context.
    pub event_log: WasmEventLog,
    /// Capability ceiling as `{resource}:{action}` strings for UCAN validation.
    pub ceiling_strings: HashSet<String>,
    /// The DID of the context creator.
    pub creator_did: String,
}

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
                    parents.push(hash_pair(&current_layer[i], &current_layer[i]));
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
    // leaf_index validated against leaves.len(); fits in usize.
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
    } else {
        path.push(ProofStep {
            sibling_hash: leaves[idx],
            direction: Direction::Right,
        });
    }

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
        } else {
            path.push(ProofStep {
                sibling_hash: layer[idx],
                direction: Direction::Right,
            });
        }
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
/// Mirrors `scp_core::context::tools::schema::validate_schema`.
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
/// Mirrors `scp_core::context::tools::schema::validate_value_against_schema`.
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

// ---------------------------------------------------------------------------
// Registry operations
// ---------------------------------------------------------------------------

/// Registers a new context in the global runtime registry.
///
/// Creates a `WasmContextRuntime` with empty tool registry, event log,
/// revocation set, and default capability ceiling. The creator DID is stored.
///
/// # Errors
///
/// Returns an error if the context ID is already registered.
pub fn register_context(context_id: &str, creator_did: &str) -> Result<(), ScpWasmError> {
    CONTEXT_REGISTRY.with(|reg| {
        let mut map = reg.borrow_mut();
        if map.contains_key(context_id) {
            return Err(ScpWasmError::Context {
                message: format!("context '{context_id}' is already registered"),
                code: "SCP-CTX-2000".to_owned(),
            });
        }

        let ceiling_strings: HashSet<String> = [
            "messages:read",
            "messages:write",
            "tool_register:*",
            "tool_invoke:*",
            "role_assign:*",
            "member_invite:*",
            "member_remove:*",
            "governance_propose:*",
            "governance_vote:*",
            "context_close:*",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();

        let runtime = WasmContextRuntime {
            tool_registry: ToolRegistry::new(),
            event_log: WasmEventLog::new(context_id.to_owned()),
            ceiling_strings,
            creator_did: creator_did.to_owned(),
        };

        map.insert(context_id.to_owned(), runtime);
        Ok(())
    })
}

/// Removes a context from the global runtime registry.
pub fn remove_context(context_id: &str) {
    CONTEXT_REGISTRY.with(|reg| {
        reg.borrow_mut().remove(context_id);
    });
}

/// Executes a closure with mutable access to a context's runtime state.
///
/// Mirrors the `PyO3` bridge's `with_context` function.
///
/// # Errors
///
/// Returns an error if the context ID is not found in the registry,
/// or if the closure itself returns an error.
pub fn with_context<T, F>(context_id: &str, f: F) -> Result<T, ScpWasmError>
where
    F: FnOnce(&mut WasmContextRuntime) -> Result<T, ScpWasmError>,
{
    CONTEXT_REGISTRY.with(|reg| {
        let mut map = reg.borrow_mut();
        let rt = map
            .get_mut(context_id)
            .ok_or_else(|| ScpWasmError::Context {
                message: format!(
                    "context '{context_id}' not found in runtime registry \
                     — was it created with context_create?"
                ),
                code: "SCP-CTX-2001".to_owned(),
            })?;
        f(rt)
    })
}

// ---------------------------------------------------------------------------
// WASM-local UCAN validation for tool invocation (#319)
// ---------------------------------------------------------------------------

/// Validates a UCAN token for tool invocation authorization in the WASM bridge.
///
/// WASM cannot depend on scp-core (tokio incompatible), so this implements a
/// local validation subset: JWT format, base64url decode, payload parse, expiry,
/// revocation, audience match, capability match (specific + wildcard), and
/// ceiling compliance.
///
/// **Not yet implemented** (deferred to SCP-218 `WebCrypto` wiring):
/// - Ed25519 signature verification
/// - Delegation chain traversal
/// - Root issuer verification
/// - Nonce replay detection
///
/// # Errors
///
/// Returns [`ScpWasmError::Permission`] if the token is malformed, expired,
/// revoked, has an audience mismatch, or lacks the required
/// `tool_invoke:{tool_name}` capability for the given context.
///
/// See CLAUDE.md §UCAN Validation — Known Gaps.
/// See spec §6.2, §8, ADR-016, and issue #319.
pub fn validate_tool_ucan_wasm(
    token: &str,
    context_id: &str,
    tool_name: &str,
    identity_did: &str,
    rt: &mut WasmContextRuntime,
) -> Result<(), ScpWasmError> {
    let (payload, payload_bytes) = parse_and_decode_ucan_payload(token)?;
    check_ucan_expiry(&payload)?;
    check_ucan_revocation(context_id, &payload_bytes)?;
    check_ucan_audience(&payload, identity_did)?;
    check_ucan_tool_capability(&payload, context_id, tool_name)?;
    check_ucan_ceiling(rt, tool_name)?;
    Ok(())
}

/// Parses a JWT token string and decodes the payload (steps 1-2).
fn parse_and_decode_ucan_payload(
    token: &str,
) -> Result<(serde_json::Value, Vec<u8>), ScpWasmError> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(ScpWasmError::Permission {
            message: format!(
                "UCAN token is not valid JWT format — expected 3 parts, got {}",
                parts.len()
            ),
            code: "SCP-PERM-3001".to_owned(),
        });
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| ScpWasmError::Permission {
            message: format!("UCAN payload base64url decode failed: {e}"),
            code: "SCP-PERM-3001".to_owned(),
        })?;

    let payload: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|e| ScpWasmError::Permission {
            message: format!("UCAN payload is not valid JSON: {e}"),
            code: "SCP-PERM-3001".to_owned(),
        })?;

    Ok((payload, payload_bytes))
}

/// Checks that the UCAN token has not expired (step 3).
fn check_ucan_expiry(payload: &serde_json::Value) -> Result<(), ScpWasmError> {
    let exp = payload
        .get("exp")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| ScpWasmError::Permission {
            message: "UCAN token missing required 'exp' field".to_owned(),
            code: "SCP-PERM-3001".to_owned(),
        })?;

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let now_secs = (js_sys::Date::now() / 1000.0) as u64;
    if exp <= now_secs {
        return Err(ScpWasmError::Permission {
            message: format!("UCAN token has expired (exp={exp}, now={now_secs})"),
            code: "SCP-PERM-3001".to_owned(),
        });
    }
    Ok(())
}

/// Checks the UCAN token against the revocation list (step 4).
///
/// Uses `compute_revocation_cid` (JSON payload hash) matching scp-core's format.
fn check_ucan_revocation(context_id: &str, payload_bytes: &[u8]) -> Result<(), ScpWasmError> {
    let ucan_payload: crate::ucan::UcanPayloadForRevocation =
        serde_json::from_slice(payload_bytes).map_err(|e| ScpWasmError::Permission {
            message: format!("UCAN payload deserialization failed for revocation check: {e}"),
            code: "SCP-PERM-3001".to_owned(),
        })?;
    let revocation_cid =
        crate::ucan::compute_revocation_cid_from_payload(&ucan_payload).map_err(|e| {
            ScpWasmError::Permission {
                message: format!("failed to compute revocation CID: {e}"),
                code: "SCP-PERM-3001".to_owned(),
            }
        })?;
    let is_revoked =
        crate::ucan::is_token_revoked(context_id, &revocation_cid).unwrap_or(false);
    if is_revoked {
        return Err(ScpWasmError::Permission {
            message: "UCAN token has been revoked".to_owned(),
            code: "SCP-PERM-3001".to_owned(),
        });
    }
    Ok(())
}

/// Checks the UCAN audience matches the expected identity DID (step 5).
fn check_ucan_audience(
    payload: &serde_json::Value,
    identity_did: &str,
) -> Result<(), ScpWasmError> {
    let aud = payload
        .get("aud")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ScpWasmError::Permission {
            message: "UCAN token missing required 'aud' field".to_owned(),
            code: "SCP-PERM-3001".to_owned(),
        })?;
    if aud != identity_did {
        return Err(ScpWasmError::Permission {
            message: format!("UCAN audience mismatch: expected '{identity_did}', got '{aud}'"),
            code: "SCP-PERM-3001".to_owned(),
        });
    }
    Ok(())
}

/// Checks the UCAN att array for `tool_invoke:{tool_name}` or wildcard (step 6).
fn check_ucan_tool_capability(
    payload: &serde_json::Value,
    context_id: &str,
    tool_name: &str,
) -> Result<(), ScpWasmError> {
    let required_resource = format!("scp:ctx:{context_id}/tool_invoke:{tool_name}");
    let wildcard_resource = format!("scp:ctx:{context_id}/tool_invoke:*");
    let mut has_capability = false;

    if let Some(att) = payload.get("att").and_then(serde_json::Value::as_array) {
        for attenuation in att {
            let with_str = attenuation
                .get("with")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");

            if with_str == required_resource || with_str == wildcard_resource {
                has_capability = true;
                break;
            }

            // Check for wildcard action via the `can` field being "*".
            let can_str = attenuation
                .get("can")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");

            let expected_prefix = format!("scp:ctx:{context_id}/tool_invoke:");
            if with_str.starts_with(&expected_prefix) && can_str == "*" {
                has_capability = true;
                break;
            }
        }
    }

    if !has_capability {
        return Err(ScpWasmError::Permission {
            message: format!(
                "UCAN token does not grant tool_invoke:{tool_name} capability for context '{context_id}'"
            ),
            code: "SCP-PERM-3001".to_owned(),
        });
    }
    Ok(())
}

/// Checks the tool invocation is within the context's capability ceiling (step 7).
fn check_ucan_ceiling(
    rt: &WasmContextRuntime,
    tool_name: &str,
) -> Result<(), ScpWasmError> {
    if !rt.ceiling_strings.is_empty() {
        let capability_name = format!("tool_invoke:{tool_name}");
        let wildcard = "tool_invoke:*".to_owned();
        if !rt.ceiling_strings.contains(&capability_name) && !rt.ceiling_strings.contains(&wildcard)
        {
            return Err(ScpWasmError::Permission {
                message: format!("tool_invoke:{tool_name} outside context ceiling"),
                code: "SCP-PERM-3001".to_owned(),
            });
        }
    }
    Ok(())
}

