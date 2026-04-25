//! Tool registration storage, registration, update, and verification.
//!
//! Implements the core tool registry for SCP contexts per ADR-010. Each
//! context maintains its own [`OutletRegistry`] that stores [`OutletRegistration`]
//! entries. Tools are registered, updated, and verified through free functions
//! that take the registry and role state as parameters.
//!
//! # Event Log Integration
//!
//! Registration, update, and verification functions return event payloads
//! ([`OutletRegisteredEvent`], [`OutletUpdatedEvent`], [`OutletVerifiedEvent`])
//! alongside their primary results. The caller is responsible for appending
//! these events to the context's event log.
//!
//! See ADR-010 in `.docs/adrs/phase-2.md`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::{
    DID, OutletError, OutletId, OutletKind, OutletRegisteredEvent, OutletUpdatedEvent,
    OutletVerifiedEvent, has_admin_role, has_outlet_register_capability, schema,
};
use crate::context::roles::ContextRoleState;

// ---------------------------------------------------------------------------
// OutletSchema
// ---------------------------------------------------------------------------

/// MCP-compatible JSON Schema for a tool's input and output.
///
/// Both `input_schema` and `output_schema` must be valid JSON Schema objects
/// (at minimum, a JSON object with a `"type"` field). See spec section 8.5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutletSchema {
    /// JSON Schema describing the tool's expected input.
    pub input_schema: serde_json::Value,
    /// JSON Schema describing the tool's output.
    pub output_schema: serde_json::Value,
}

// ---------------------------------------------------------------------------
// OutletTestVector
// ---------------------------------------------------------------------------

/// A known input-output pair for tool verification.
///
/// Test vectors enable continuous integrity checking: any agent can invoke a
/// tool with test inputs and verify the output matches the expected result.
/// See spec section 7.3.3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutletTestVector {
    /// The test input to provide to the tool.
    pub input: serde_json::Value,
    /// The expected output from the tool.
    pub expected_output: serde_json::Value,
    /// Human-readable description of what this test vector validates.
    pub description: String,
}

// ---------------------------------------------------------------------------
// OutletCost
// ---------------------------------------------------------------------------

/// Per-invocation cost metadata for a tool (spec §5.4.1, §19.3).
///
/// Tool-level costs are additive with context costs. A tool calling an
/// external API can pass through its cost. Tool costs carry their own payee
/// DID (may differ from context payee).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutletCost {
    /// Cost per invocation in the smallest currency unit.
    pub amount: u64,
    /// ISO 4217 or protocol-defined currency code.
    pub currency: String,
    /// The DID that receives tool invocation payments. May differ from the
    /// context payee.
    pub payee: DID,
    /// Optional pricing formula identifier for dynamic pricing (§19.4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_formula: Option<String>,
}

// ---------------------------------------------------------------------------
// OutletRegistration
// ---------------------------------------------------------------------------

/// Full tool registration entry for an SCP context.
///
/// Contains all metadata required for tool integrity verification: schema,
/// implementation hash, test vectors, and operator identity. See ADR-010
/// acceptance criterion 1.
///
/// Provenance fields (`registered_at`, `signature`) close spec audit finding
/// [5.4] — tool registration wire format now includes a timestamp and an
/// Ed25519 signature over the canonical registration bytes, enabling
/// independent verification that the registration was created by the claimed
/// registrant. Both fields default to zero/empty for backward compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutletRegistration {
    /// Unique identifier for this tool within the context.
    pub outlet_id: OutletId,
    /// Structural classification of the outlet (spec §5.4.2).
    ///
    /// `OutletKind::Query` for read-only, idempotent, cacheable outlets;
    /// `OutletKind::Action` for outlets that may mutate context state. The
    /// `kind` is committed to the §5.4.1 V2 canonical preimage as a fixed
    /// `kind_byte` (`0x00` Query, `0x01` Action) between `outlet_id` and
    /// `name`.
    ///
    /// On-wire serde form: `"kind": "query"` or `"kind": "action"` (lowercase
    /// per §5.4.2). Deserialization that omits the field defaults to
    /// `OutletKind::Action` — the fail-safe per §5.4.2 (an undeclared kind
    /// cannot accidentally be treated as read-only).
    #[serde(default)]
    pub kind: OutletKind,
    /// Human-readable name of the tool.
    pub name: String,
    /// Description of the tool's purpose and behavior.
    pub description: String,
    /// MCP-compatible JSON Schema for input and output.
    pub schema: OutletSchema,
    /// SHA-256 hash of the tool implementation. Used for integrity verification.
    /// Any change to the implementation produces a new hash.
    pub implementation_hash: [u8; 32],
    /// Known input-output pairs for continuous verification.
    pub test_vectors: Vec<OutletTestVector>,
    /// The DID of the operator accountable for this tool.
    pub operator_did: DID,
    /// Optional per-invocation cost metadata (spec §5.4.1, §19.3).
    pub cost: Option<OutletCost>,
    /// Unix timestamp (seconds) when the tool was registered.
    ///
    /// Provides temporal provenance for tool registrations. Defaults to 0 for
    /// backward compatibility with registrations created before this field
    /// existed.
    #[serde(default)]
    pub registered_at: u64,
    /// Ed25519 signature over the canonical registration bytes, produced by
    /// the registrant's signing key.
    ///
    /// Enables independent verification that the registration was created by
    /// the claimed registrant. The signed payload is the `MessagePack` encoding
    /// of all fields except `signature` itself. Defaults to empty for backward
    /// compatibility.
    #[serde(default)]
    pub signature: Vec<u8>,
}

impl OutletRegistration {
    /// Validates structural invariants on the registration that do not
    /// require any context state — pure on-the-payload checks suitable for
    /// invocation at registration time and at the runtime event-log commit
    /// boundary.
    ///
    /// # §5.4.2 Query structural cost floor (SCP-OUT-012)
    ///
    /// A `Query` outlet MUST declare either `cost == None` or
    /// `cost.amount == 0`, AND MUST NOT carry a `cost.cost_formula`. A
    /// dynamic pricing formula on an idempotent read is not coherent
    /// (§5.4.2). Declaring a positive cost or a pricing formula at
    /// registration is a validation failure rejected before the
    /// registration reaches the event log.
    ///
    /// `Action` outlets have no structural cost floor — any cost
    /// configuration is accepted at this layer (§5.4.2). The §5.4.4
    /// `OutletErrorClass::Protocol::QueryCostViolation` typed class lands
    /// with SCP-OUT-036/038; this story emits the existing
    /// [`OutletError::QueryCostViolation`] variant.
    ///
    /// # Errors
    ///
    /// Returns [`OutletError::QueryCostViolation`] when `kind == Query`
    /// AND any of:
    /// - `cost.is_some() && cost.amount > 0` (positive declared cost)
    /// - `cost.is_some() && cost.cost_formula.is_some()` (dynamic formula)
    pub fn validate(&self) -> Result<(), OutletError> {
        if matches!(self.kind, OutletKind::Query)
            && let Some(cost) = self.cost.as_ref()
        {
            if cost.amount > 0 {
                return Err(OutletError::QueryCostViolation {
                    reason: format!(
                        "Query outlet \"{}\" declares positive cost.amount = {} \
                         (§5.4.2 requires cost == None || cost.amount == 0)",
                        self.outlet_id, cost.amount
                    ),
                });
            }
            if cost.cost_formula.is_some() {
                return Err(OutletError::QueryCostViolation {
                    reason: format!(
                        "Query outlet \"{}\" declares cost.cost_formula \
                         (§5.4.2 forbids dynamic pricing on Query outlets)",
                        self.outlet_id
                    ),
                });
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// OutletVerificationResult
// ---------------------------------------------------------------------------

/// Result of verifying a tool against its test vectors.
///
/// Contains per-vector pass/fail status and an overall integrity assessment.
/// See ADR-010 acceptance criterion 5.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutletVerificationResult {
    /// The tool that was verified.
    pub outlet_id: OutletId,
    /// Per-vector results in the same order as the tool's test vectors.
    pub vector_results: Vec<VectorResult>,
    /// Overall integrity assessment: `true` if all vectors passed.
    pub integrity_ok: bool,
}

/// Result of a single test vector verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorResult {
    /// The test vector description.
    pub description: String,
    /// Whether this vector passed (`true`) or failed (`false`).
    pub passed: bool,
    /// If failed, the actual output received (for diagnostics).
    pub actual_output: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// OutletRegistry
// ---------------------------------------------------------------------------

/// In-memory tool storage for a single SCP context.
///
/// Maps tool IDs to their full registration entries. Each context maintains
/// its own `OutletRegistry`. See ADR-010.
#[derive(Debug, Clone, Default)]
pub struct OutletRegistry {
    /// Registered tools, keyed by tool ID.
    tools: HashMap<OutletId, OutletRegistration>,
}

impl OutletRegistry {
    /// Creates a new empty tool registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    /// Returns the registration for the given tool ID, if it exists.
    #[must_use]
    pub fn get(&self, outlet_id: &str) -> Option<&OutletRegistration> {
        self.tools.get(outlet_id)
    }

    /// Returns `true` if the registry contains the given tool ID.
    #[must_use]
    pub fn contains(&self, outlet_id: &str) -> bool {
        self.tools.contains_key(outlet_id)
    }

    /// Returns the number of registered tools.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// Returns `true` if no tools are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// Returns an iterator over all registered tool IDs.
    pub fn tool_ids(&self) -> impl Iterator<Item = &OutletId> {
        self.tools.keys()
    }

    /// Returns an iterator over all registrations.
    pub fn registrations(&self) -> impl Iterator<Item = &OutletRegistration> {
        self.tools.values()
    }

    /// Inserts a tool registration. Returns the previous registration if one
    /// existed for this tool ID.
    pub fn insert(&mut self, registration: OutletRegistration) -> Option<OutletRegistration> {
        self.tools
            .insert(registration.outlet_id.clone(), registration)
    }

    /// Removes a tool registration by ID. Returns the removed registration
    /// if one existed, or `None` if the tool was not registered.
    pub fn remove(&mut self, outlet_id: &str) -> Option<OutletRegistration> {
        self.tools.remove(outlet_id)
    }
}

// ---------------------------------------------------------------------------
// register_outlet
// ---------------------------------------------------------------------------

/// Registers a new tool in the context's tool registry.
///
/// Validates:
/// 1. Registrant has `ToolRegister` capability via UCAN (ADR-009).
/// 2. Input and output schemas are valid JSON Schema.
/// 3. Implementation hash is 32 bytes (enforced by type system).
/// 4. Operator DID is resolvable (basic format check).
/// 5. Tool ID is not already registered.
/// 6. `OutletRegistration::validate()` — Query structural cost floor
///    (§5.4.2, SCP-OUT-012).
///
/// On success, stores the registration and returns the tool ID along with a
/// [`OutletRegisteredEvent`] for the caller to append to the event log.
///
/// # Errors
///
/// Returns [`OutletError`] on validation failure, including
/// [`OutletError::QueryCostViolation`] when a Query outlet declares a
/// positive cost or a dynamic cost formula (§5.4.2 structural floor).
pub fn register_outlet(
    registry: &mut OutletRegistry,
    role_state: &ContextRoleState,
    registration: OutletRegistration,
    registrant_did: &str,
) -> Result<(OutletId, OutletRegisteredEvent), OutletError> {
    // 1. Validate registrant has ToolRegister capability.
    if !has_outlet_register_capability(role_state, registrant_did) {
        return Err(OutletError::RegistrantNotAuthorized {
            did: registrant_did.to_owned(),
        });
    }

    // 2. Pure structural validation (§5.4.2 Query cost floor — SCP-OUT-012).
    //    Runs before schema validation so a misclassified Query+cost is
    //    rejected with the precise QueryCostViolation rather than masked
    //    by an unrelated downstream failure.
    registration.validate()?;

    // 3. Validate schemas.
    schema::validate_schema(&registration.schema.input_schema)
        .map_err(OutletError::InvalidInputSchema)?;
    schema::validate_schema(&registration.schema.output_schema)
        .map_err(OutletError::InvalidOutputSchema)?;

    // 2b. Enforce schema specificity floor (spec section 6.2, 9.2.1).
    if let Err((side, field_count)) = schema::validate_specificity_floor(
        &registration.schema.input_schema,
        &registration.schema.output_schema,
    ) {
        return Err(OutletError::SchemaSpecificityFloor {
            side: side.to_owned(),
            field_count,
            min_fields: schema::MIN_SCHEMA_FIELDS,
        });
    }

    // 3. Implementation hash is 32 bytes by type ([u8; 32]) -- enforced at compile time.
    //    No runtime check needed.

    // 4. Validate operator DID is resolvable (basic format check).
    validate_did(&registration.operator_did)?;

    // 5. Check for duplicate tool ID.
    if registry.contains(&registration.outlet_id) {
        return Err(OutletError::OutletAlreadyRegistered {
            outlet_id: registration.outlet_id,
        });
    }

    // Build event payload.
    let event = OutletRegisteredEvent {
        outlet_id: registration.outlet_id.clone(),
        name: registration.name.clone(),
        description: registration.description.clone(),
        implementation_hash: registration.implementation_hash,
        operator_did: registration.operator_did.clone(),
        registrant_did: registrant_did.into(),
        test_vector_count: registration.test_vectors.len(),
    };

    let outlet_id = registration.outlet_id.clone();
    registry.insert(registration);

    Ok((outlet_id, event))
}

// ---------------------------------------------------------------------------
// update_outlet
// ---------------------------------------------------------------------------

/// Updates an existing tool registration in the registry.
///
/// Validates:
/// 1. Tool exists in the registry.
/// 2. Updater is the tool's operator DID or has admin role.
/// 3. New registration's tool ID matches the existing tool.
/// 4. New schemas are valid JSON Schema.
/// 5. New operator DID is resolvable.
///
/// Records old and new implementation hashes. Tool mutations are visible to
/// all context members via the event log. See ADR-010 acceptance criterion 4.
///
/// # Errors
///
/// Returns [`OutletError`] on validation failure.
pub fn update_outlet(
    registry: &mut OutletRegistry,
    role_state: &ContextRoleState,
    outlet_id: &str,
    new_registration: OutletRegistration,
    updater_did: &str,
) -> Result<OutletUpdatedEvent, OutletError> {
    // 1. Look up the existing registration.
    let old_registration = registry
        .get(outlet_id)
        .ok_or_else(|| OutletError::OutletNotFound {
            outlet_id: outlet_id.to_owned(),
        })?
        .clone();

    // 2. Validate updater is operator or admin.
    let is_operator = old_registration.operator_did == updater_did;
    let is_admin = has_admin_role(role_state, updater_did);
    if !is_operator && !is_admin {
        return Err(OutletError::UpdaterNotAuthorized {
            did: updater_did.to_owned(),
        });
    }

    // 3. Validate tool ID matches.
    if new_registration.outlet_id != outlet_id {
        return Err(OutletError::OutletIdMismatch {
            expected: outlet_id.to_owned(),
            actual: new_registration.outlet_id,
        });
    }

    // 3b. Pure structural validation (§5.4.2 Query cost floor — SCP-OUT-012).
    //     An update that flips kind to Query while retaining a positive
    //     cost (or dynamic cost_formula) MUST be rejected at the same
    //     boundary as registration.
    new_registration.validate()?;

    // 4. Validate schemas.
    schema::validate_schema(&new_registration.schema.input_schema)
        .map_err(OutletError::InvalidInputSchema)?;
    schema::validate_schema(&new_registration.schema.output_schema)
        .map_err(OutletError::InvalidOutputSchema)?;

    // 4b. Enforce schema specificity floor (spec section 6.2, 9.2.1).
    if let Err((side, field_count)) = schema::validate_specificity_floor(
        &new_registration.schema.input_schema,
        &new_registration.schema.output_schema,
    ) {
        return Err(OutletError::SchemaSpecificityFloor {
            side: side.to_owned(),
            field_count,
            min_fields: schema::MIN_SCHEMA_FIELDS,
        });
    }

    // 5. Validate operator DID.
    validate_did(&new_registration.operator_did)?;

    // Build event payload recording changes.
    let mut changed_fields = Vec::new();
    if old_registration.name != new_registration.name {
        changed_fields.push("name".to_owned());
    }
    if old_registration.description != new_registration.description {
        changed_fields.push("description".to_owned());
    }
    if old_registration.schema != new_registration.schema {
        changed_fields.push("schema".to_owned());
    }
    if old_registration.test_vectors != new_registration.test_vectors {
        changed_fields.push("test_vectors".to_owned());
    }
    if old_registration.implementation_hash != new_registration.implementation_hash {
        changed_fields.push("implementation_hash".to_owned());
    }
    if old_registration.operator_did != new_registration.operator_did {
        changed_fields.push("operator_did".to_owned());
    }

    let event = OutletUpdatedEvent {
        outlet_id: outlet_id.to_owned(),
        old_implementation_hash: old_registration.implementation_hash,
        new_implementation_hash: new_registration.implementation_hash,
        updater_did: updater_did.into(),
        changed_fields,
    };

    registry.insert(new_registration);

    Ok(event)
}

// ---------------------------------------------------------------------------
// verify_outlet
// ---------------------------------------------------------------------------

/// Verifies a tool by running all its test vectors.
///
/// For each test vector: compares the expected output to the tool's declared
/// expected output. In Phase 2, verification is a comparison against the
/// stored test vectors (the tool executor is not yet integrated). The caller
/// provides actual outputs via the `executor` function parameter.
///
/// Returns a [`OutletVerificationResult`] with per-vector pass/fail status and
/// overall integrity assessment, plus a [`OutletVerifiedEvent`] for the event
/// log.
///
/// See ADR-010 acceptance criterion 5.
///
/// # Errors
///
/// Returns [`OutletError::OutletNotFound`] if the tool is not in the registry.
pub fn verify_outlet<F>(
    registry: &OutletRegistry,
    outlet_id: &str,
    executor: F,
) -> Result<(OutletVerificationResult, OutletVerifiedEvent), OutletError>
where
    F: Fn(&serde_json::Value) -> serde_json::Value,
{
    let registration = registry
        .get(outlet_id)
        .ok_or_else(|| OutletError::OutletNotFound {
            outlet_id: outlet_id.to_owned(),
        })?;

    let mut vector_results = Vec::with_capacity(registration.test_vectors.len());

    for vector in &registration.test_vectors {
        let actual_output = executor(&vector.input);
        let passed = actual_output == vector.expected_output;

        vector_results.push(VectorResult {
            description: vector.description.clone(),
            passed,
            actual_output: if passed { None } else { Some(actual_output) },
        });
    }

    let passed_count = vector_results.iter().filter(|r| r.passed).count();
    let failed_count = vector_results.len() - passed_count;
    let integrity_ok = failed_count == 0;

    let result = OutletVerificationResult {
        outlet_id: outlet_id.to_owned(),
        vector_results,
        integrity_ok,
    };

    let event = OutletVerifiedEvent {
        outlet_id: outlet_id.to_owned(),
        passed: passed_count,
        failed: failed_count,
        integrity_ok,
    };

    Ok((result, event))
}

// ---------------------------------------------------------------------------
// Tool registration signature verification (M15)
// ---------------------------------------------------------------------------

/// Computes the canonical bytes for tool registration signature verification.
///
/// The signed payload is a SHA-256 hash of a canonical struct containing all
/// `OutletRegistration` fields except `signature` itself, in a deterministic
/// order. JSON schema fields use RFC 8785 JCS canonical serialization.
///
/// The canonical representation includes:
/// - `outlet_id`
/// - `kind_byte` (per §5.4.1: 0x00 = Query, 0x01 = Action). SCP-OUT-011 wires
///   the real value from [`OutletRegistration::kind`] via
///   [`OutletKind::canonical_byte`]; the placeholder `0x01` from SCP-OUT-002
///   is replaced.
/// - `name`, `description`
/// - `input_schema`, `output_schema` (JCS canonical JSON bytes)
/// - `implementation_hash` (32 bytes)
/// - `test_vectors` (count + hashes)
/// - `operator_did`
/// - `registered_at` (timestamp)
/// - `cost` (if present)
///
/// Note: the V2 spec preimage (§5.4.1) uses `description_hash`, `schema_hash`,
/// `test_vectors_hash`, `cost_hash`, and `catalog_hash` in place of inline
/// length-prefixed bytes, and reorders `operator_did` and `registered_at`.
/// Those structural changes ship with SCP-OUT-013 / SCP-OUT-024.
/// SCP-OUT-002 introduced the V2 domain separator and the `kind_byte` slot;
/// SCP-OUT-011 wires the real `kind` field; the remaining layout changes are
/// scoped to downstream stories.
#[must_use]
pub fn compute_outlet_registration_canonical_bytes(registration: &OutletRegistration) -> Vec<u8> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"SCP-OUTLET-REGISTRATION-V2:");
    // Length-prefix helper for variable-length fields.
    #[allow(clippy::cast_possible_truncation)]
    let length_prefix = |hasher: &mut Sha256, bytes: &[u8]| {
        hasher.update((bytes.len() as u32).to_be_bytes());
        hasher.update(bytes);
    };

    length_prefix(&mut hasher, registration.outlet_id.as_bytes());
    // §5.4.1 kind_byte — the real OutletKind classification (SCP-OUT-011).
    // Sits between `outlet_id` and `name`; 0x00 = Query, 0x01 = Action.
    hasher.update([registration.kind.canonical_byte()]);
    length_prefix(&mut hasher, registration.name.as_bytes());
    length_prefix(&mut hasher, registration.description.as_bytes());

    // Schema as RFC 8785 JCS canonical JSON bytes.
    let input_json = crate::jcs::to_vec(&registration.schema.input_schema).unwrap_or_default();
    length_prefix(&mut hasher, &input_json);
    let output_json = crate::jcs::to_vec(&registration.schema.output_schema).unwrap_or_default();
    length_prefix(&mut hasher, &output_json);

    hasher.update(registration.implementation_hash);

    // Test vectors: count + hash of each vector's canonical form.
    #[allow(clippy::cast_possible_truncation)]
    hasher.update((registration.test_vectors.len() as u32).to_be_bytes());
    for tv in &registration.test_vectors {
        let input_bytes = crate::jcs::to_vec(&tv.input).unwrap_or_default();
        length_prefix(&mut hasher, &input_bytes);
        let output_bytes = crate::jcs::to_vec(&tv.expected_output).unwrap_or_default();
        length_prefix(&mut hasher, &output_bytes);
        length_prefix(&mut hasher, tv.description.as_bytes());
    }

    length_prefix(&mut hasher, registration.operator_did.as_bytes());
    hasher.update(registration.registered_at.to_be_bytes());

    // Cost metadata presence flag + contents.
    match &registration.cost {
        Some(tc) => {
            hasher.update([0x01]);
            hasher.update(tc.amount.to_be_bytes());
            length_prefix(&mut hasher, tc.currency.as_bytes());
            match &tc.cost_formula {
                Some(formula) => {
                    hasher.update([0x01]);
                    length_prefix(&mut hasher, formula.as_bytes());
                }
                None => hasher.update([0x00]),
            }
            length_prefix(&mut hasher, tc.payee.as_bytes());
        }
        None => hasher.update([0x00]),
    }

    hasher.finalize().to_vec()
}

/// Verifies the Ed25519 signature on a tool registration.
///
/// If the `signature` field is empty (backward compatibility with pre-signature
/// registrations), verification is skipped. If non-empty, it MUST be a valid
/// 64-byte Ed25519 signature over the canonical registration bytes, verifiable
/// against the provided `registrant_public_key`.
///
/// # Errors
///
/// Returns [`OutletError::SignatureVerificationFailed`] if:
/// - The signature is non-empty but not 64 bytes.
/// - The signature does not verify against the public key.
pub fn verify_outlet_registration_signature(
    registration: &OutletRegistration,
    registrant_public_key: &ed25519_dalek::VerifyingKey,
) -> Result<(), OutletError> {
    // Empty signature = backward-compatible registration without provenance.
    if registration.signature.is_empty() {
        return Ok(());
    }

    let sig_bytes: [u8; 64] = registration.signature.as_slice().try_into().map_err(|_| {
        OutletError::SignatureVerificationFailed {
            reason: format!(
                "signature must be 64 bytes, got {}",
                registration.signature.len()
            ),
        }
    })?;

    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let canonical = compute_outlet_registration_canonical_bytes(registration);

    registrant_public_key
        .verify_strict(&canonical, &signature)
        .map_err(|e| OutletError::SignatureVerificationFailed {
            reason: format!("Ed25519 verification failed: {e}"),
        })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Basic DID format validation.
///
/// Phase 2 check: a DID must be non-empty and start with `"did:"`. Full DID
/// resolution is deferred to the identity subsystem.
fn validate_did(did: &str) -> Result<(), OutletError> {
    if did.is_empty() || !did.starts_with("did:") {
        return Err(OutletError::UnresolvableDid {
            did: did.to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::needless_collect
)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::context::roles::{Capability, CapabilityCeiling, ContextRoleState};

    /// Creates a test capability ceiling with tool-related capabilities.
    fn test_ceiling() -> CapabilityCeiling {
        CapabilityCeiling::new([
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::OutletRegister,
            Capability::OutletCallAll,
            Capability::RoleAssign,
            Capability::MemberInvite,
            Capability::MemberRemove,
            Capability::GovernancePropose,
            Capability::GovernanceVote,
            Capability::ContextClose,
        ])
    }

    /// Creates a `ContextRoleState` with a creator that has admin (all) capabilities.
    fn test_role_state(creator_did: &str) -> ContextRoleState {
        ContextRoleState::new(
            "ctx-test",
            creator_did,
            test_ceiling(),
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap()
    }

    /// Creates a `ContextRoleState` with an additional member that has limited
    /// capabilities (no `ToolRegister`).
    fn test_role_state_with_member(creator_did: &str, member_did: &str) -> ContextRoleState {
        let mut state = test_role_state(creator_did);
        state.members.insert(member_did.to_owned());
        // Assign member role (no ToolRegister).
        let member_caps: HashSet<Capability> = [
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::OutletCallAll,
        ]
        .into_iter()
        .collect();
        state
            .member_capabilities
            .insert(member_did.to_owned(), member_caps);
        state
    }

    /// Creates a valid tool registration for testing.
    fn valid_registration(outlet_id: &str) -> OutletRegistration {
        OutletRegistration {
            outlet_id: outlet_id.to_owned(),
            kind: OutletKind::Action,
            name: "calculator".to_owned(),
            description: "A simple calculator tool".to_owned(),
            schema: OutletSchema {
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "operation": {"type": "string"},
                        "a": {"type": "number"},
                        "b": {"type": "number"}
                    }
                }),
                output_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "result": {"type": "number"}
                    }
                }),
            },
            implementation_hash: [0xAB; 32],
            test_vectors: vec![
                OutletTestVector {
                    input: serde_json::json!({"operation": "add", "a": 1, "b": 2}),
                    expected_output: serde_json::json!({"result": 3}),
                    description: "1 + 2 = 3".to_owned(),
                },
                OutletTestVector {
                    input: serde_json::json!({"operation": "mul", "a": 3, "b": 4}),
                    expected_output: serde_json::json!({"result": 12}),
                    description: "3 * 4 = 12".to_owned(),
                },
            ],
            operator_did: "did:dht:z6MkTestOperator".into(),
            cost: None,
            registered_at: 0,
            signature: Vec::new(),
        }
    }

    // ----- register_outlet tests -----

    #[test]
    fn register_tool_succeeds_with_valid_registration() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = OutletRegistry::new();
        let registration = valid_registration("tool-1");

        let result = register_outlet(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        );
        assert!(result.is_ok());

        let (outlet_id, event) = result.unwrap();
        assert_eq!(outlet_id, "tool-1");
        assert_eq!(event.outlet_id, "tool-1");
        assert_eq!(event.name, "calculator");
        assert_eq!(event.test_vector_count, 2);
        assert_eq!(event.registrant_did, "did:dht:z6MkCreator");

        // Verify tool is stored.
        assert!(registry.contains("tool-1"));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn register_tool_validates_schemas_are_valid_json_schema() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = OutletRegistry::new();

        // Invalid input schema (not an object).
        let mut registration = valid_registration("tool-1");
        registration.schema.input_schema = serde_json::json!("not an object");

        let result = register_outlet(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        );
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), OutletError::InvalidInputSchema(_)),
            "expected InvalidInputSchema"
        );

        // Invalid output schema (missing type field).
        let mut registration = valid_registration("tool-1");
        registration.schema.output_schema = serde_json::json!({"properties": {}});

        let result = register_outlet(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        );
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), OutletError::InvalidOutputSchema(_)),
            "expected InvalidOutputSchema"
        );
    }

    #[test]
    fn register_tool_rejects_schema_below_specificity_floor() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = OutletRegistry::new();

        // Both schemas have only 1 property -- below the MIN_SCHEMA_FIELDS (2) floor.
        let mut registration = valid_registration("tool-1");
        registration.schema = OutletSchema {
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "data": {"type": "string"}
                }
            }),
            output_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "result": {"type": "string"}
                }
            }),
        };

        let result = register_outlet(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                OutletError::SchemaSpecificityFloor { min_fields: 2, .. }
            ),
            "expected SchemaSpecificityFloor, got {err:?}"
        );
    }

    #[test]
    fn register_tool_accepts_schema_meeting_specificity_floor_on_input() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = OutletRegistry::new();

        // Input has 2 properties, output has 0 -- should pass.
        let mut registration = valid_registration("tool-1");
        registration.schema = OutletSchema {
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "x": {"type": "number"},
                    "y": {"type": "number"}
                }
            }),
            output_schema: serde_json::json!({
                "type": "object"
            }),
        };

        let result = register_outlet(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        );
        assert!(
            result.is_ok(),
            "should accept when input meets floor: {result:?}"
        );
    }

    #[test]
    fn register_tool_rejects_registrant_without_tool_register_capability() {
        let role_state = test_role_state_with_member("did:dht:z6MkCreator", "did:dht:z6MkMember");
        let mut registry = OutletRegistry::new();
        let registration = valid_registration("tool-1");

        let result = register_outlet(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkMember",
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, OutletError::RegistrantNotAuthorized { .. }),
            "expected RegistrantNotAuthorized, got {err:?}"
        );
    }

    #[test]
    fn register_tool_rejects_empty_operator_did() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = OutletRegistry::new();
        let mut registration = valid_registration("tool-1");
        registration.operator_did = DID::from("");

        let result = register_outlet(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        );
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), OutletError::UnresolvableDid { .. }),
            "expected UnresolvableDid"
        );
    }

    #[test]
    fn register_tool_rejects_malformed_operator_did() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = OutletRegistry::new();
        let mut registration = valid_registration("tool-1");
        registration.operator_did = "not-a-did".into();

        let result = register_outlet(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OutletError::UnresolvableDid { .. }
        ));
    }

    #[test]
    fn register_tool_rejects_duplicate_tool_id() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = OutletRegistry::new();

        let registration = valid_registration("tool-1");
        register_outlet(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        )
        .unwrap();

        let registration2 = valid_registration("tool-1");
        let result = register_outlet(
            &mut registry,
            &role_state,
            registration2,
            "did:dht:z6MkCreator",
        );
        assert!(result.is_err());
        assert!(
            matches!(
                result.unwrap_err(),
                OutletError::OutletAlreadyRegistered { .. }
            ),
            "expected OutletAlreadyRegistered"
        );
    }

    #[test]
    fn register_tool_with_cost() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = OutletRegistry::new();
        let mut registration = valid_registration("tool-1");
        registration.cost = Some(OutletCost {
            amount: 100,
            currency: "USD".to_owned(),
            payee: "did:dht:z6MkPayee".into(),
            cost_formula: None,
        });

        let result = register_outlet(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        );
        assert!(result.is_ok());

        let stored = registry.get("tool-1").unwrap();
        assert!(stored.cost.is_some());
        assert_eq!(stored.cost.as_ref().unwrap().amount, 100);
        assert_eq!(stored.cost.as_ref().unwrap().currency, "USD");
    }

    // ----- update_outlet tests -----

    #[test]
    fn update_tool_succeeds_by_operator() {
        let role_state = test_role_state_with_member("did:dht:z6MkCreator", "did:dht:z6MkOperator");
        let mut registry = OutletRegistry::new();

        // Register with operator DID.
        let mut registration = valid_registration("tool-1");
        registration.operator_did = "did:dht:z6MkOperator".into();
        register_outlet(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        )
        .unwrap();

        // Update by operator.
        let mut new_reg = valid_registration("tool-1");
        new_reg.operator_did = "did:dht:z6MkOperator".into();
        new_reg.name = "updated-calculator".to_owned();
        new_reg.implementation_hash = [0xCD; 32];

        let result = update_outlet(
            &mut registry,
            &role_state,
            "tool-1",
            new_reg,
            "did:dht:z6MkOperator",
        );
        assert!(result.is_ok());

        let event = result.unwrap();
        assert_eq!(event.old_implementation_hash, [0xAB; 32]);
        assert_eq!(event.new_implementation_hash, [0xCD; 32]);
        assert!(event.changed_fields.contains(&"name".to_owned()));
    }

    #[test]
    fn update_tool_succeeds_by_admin() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = OutletRegistry::new();

        let registration = valid_registration("tool-1");
        register_outlet(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        )
        .unwrap();

        // Admin can update even though they are not the operator.
        let mut new_reg = valid_registration("tool-1");
        new_reg.description = "updated description".to_owned();

        let result = update_outlet(
            &mut registry,
            &role_state,
            "tool-1",
            new_reg,
            "did:dht:z6MkCreator",
        );
        assert!(result.is_ok());
        assert!(
            result
                .unwrap()
                .changed_fields
                .contains(&"description".to_owned())
        );
    }

    #[test]
    fn update_tool_logs_old_and_new_hashes() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = OutletRegistry::new();

        let mut registration = valid_registration("tool-1");
        registration.implementation_hash = [0x11; 32];
        register_outlet(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        )
        .unwrap();

        let mut new_reg = valid_registration("tool-1");
        new_reg.implementation_hash = [0x22; 32];

        let event = update_outlet(
            &mut registry,
            &role_state,
            "tool-1",
            new_reg,
            "did:dht:z6MkCreator",
        )
        .unwrap();

        assert_eq!(event.old_implementation_hash, [0x11; 32]);
        assert_eq!(event.new_implementation_hash, [0x22; 32]);
        assert_eq!(event.updater_did, "did:dht:z6MkCreator");
    }

    #[test]
    fn update_tool_rejects_non_operator_non_admin() {
        let role_state = test_role_state_with_member("did:dht:z6MkCreator", "did:dht:z6MkMember");
        let mut registry = OutletRegistry::new();

        let registration = valid_registration("tool-1");
        register_outlet(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        )
        .unwrap();

        let new_reg = valid_registration("tool-1");
        let result = update_outlet(
            &mut registry,
            &role_state,
            "tool-1",
            new_reg,
            "did:dht:z6MkMember",
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OutletError::UpdaterNotAuthorized { .. }
        ));
    }

    #[test]
    fn update_tool_rejects_nonexistent_tool() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = OutletRegistry::new();

        let new_reg = valid_registration("tool-missing");
        let result = update_outlet(
            &mut registry,
            &role_state,
            "tool-missing",
            new_reg,
            "did:dht:z6MkCreator",
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OutletError::OutletNotFound { .. }
        ));
    }

    #[test]
    fn update_tool_rejects_mismatched_tool_id() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = OutletRegistry::new();

        let registration = valid_registration("tool-1");
        register_outlet(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        )
        .unwrap();

        // new_reg has different outlet_id.
        let new_reg = valid_registration("tool-2");
        let result = update_outlet(
            &mut registry,
            &role_state,
            "tool-1",
            new_reg,
            "did:dht:z6MkCreator",
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OutletError::OutletIdMismatch { .. }
        ));
    }

    // ----- verify_outlet tests -----

    #[test]
    fn verify_tool_returns_correct_pass_fail_per_test_vector() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = OutletRegistry::new();

        let registration = valid_registration("tool-1");
        register_outlet(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        )
        .unwrap();

        // Executor that returns correct results for "add" but wrong for "mul".
        let executor = |input: &serde_json::Value| -> serde_json::Value {
            let op = input
                .get("operation")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if op == "add" {
                serde_json::json!({"result": 3})
            } else {
                serde_json::json!({"result": 999}) // Wrong answer for mul
            }
        };

        let (result, event) = verify_outlet(&registry, "tool-1", executor).unwrap();

        assert_eq!(result.outlet_id, "tool-1");
        assert_eq!(result.vector_results.len(), 2);

        // First vector (add) should pass.
        assert!(result.vector_results[0].passed);
        assert!(result.vector_results[0].actual_output.is_none());

        // Second vector (mul) should fail.
        assert!(!result.vector_results[1].passed);
        assert_eq!(
            result.vector_results[1].actual_output,
            Some(serde_json::json!({"result": 999}))
        );

        // Overall should fail because one vector failed.
        assert!(!result.integrity_ok);
        assert_eq!(event.passed, 1);
        assert_eq!(event.failed, 1);
        assert!(!event.integrity_ok);
    }

    #[test]
    fn verify_tool_all_vectors_pass() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = OutletRegistry::new();

        let registration = valid_registration("tool-1");
        register_outlet(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        )
        .unwrap();

        // Executor that returns correct results for all operations.
        let executor = |input: &serde_json::Value| -> serde_json::Value {
            let op = input
                .get("operation")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let a = input
                .get("a")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            let b = input
                .get("b")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            match op {
                "add" => serde_json::json!({"result": a + b}),
                "mul" => serde_json::json!({"result": a * b}),
                _ => serde_json::json!({"error": "unknown operation"}),
            }
        };

        let (result, event) = verify_outlet(&registry, "tool-1", executor).unwrap();

        assert!(result.integrity_ok);
        assert_eq!(event.passed, 2);
        assert_eq!(event.failed, 0);
        assert!(event.integrity_ok);
    }

    #[test]
    fn verify_tool_rejects_nonexistent_tool() {
        let registry = OutletRegistry::new();
        let result = verify_outlet(&registry, "tool-missing", |_| serde_json::json!(null));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OutletError::OutletNotFound { .. }
        ));
    }

    #[test]
    fn verify_tool_with_no_test_vectors_passes() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = OutletRegistry::new();

        let mut registration = valid_registration("tool-1");
        registration.test_vectors = vec![];
        register_outlet(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        )
        .unwrap();

        let (result, event) =
            verify_outlet(&registry, "tool-1", |_| serde_json::json!(null)).unwrap();

        assert!(result.integrity_ok);
        assert!(result.vector_results.is_empty());
        assert_eq!(event.passed, 0);
        assert_eq!(event.failed, 0);
    }

    // ----- OutletRegistry tests -----

    #[test]
    fn tool_registry_starts_empty() {
        let registry = OutletRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn tool_registry_get_returns_none_for_missing() {
        let registry = OutletRegistry::new();
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn tool_registry_iterators() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = OutletRegistry::new();

        register_outlet(
            &mut registry,
            &role_state,
            valid_registration("tool-a"),
            "did:dht:z6MkCreator",
        )
        .unwrap();
        register_outlet(
            &mut registry,
            &role_state,
            valid_registration("tool-b"),
            "did:dht:z6MkCreator",
        )
        .unwrap();

        assert_eq!(registry.len(), 2);

        let ids: Vec<&String> = registry.tool_ids().collect();
        assert!(ids.contains(&&"tool-a".to_owned()));
        assert!(ids.contains(&&"tool-b".to_owned()));

        let regs: Vec<&OutletRegistration> = registry.registrations().collect();
        assert_eq!(regs.len(), 2);
    }

    // ----- OutletRegistration serialization -----

    #[test]
    fn tool_registration_serialization_roundtrip() {
        let registration = valid_registration("tool-1");
        let json = serde_json::to_string(&registration).unwrap();
        let deserialized: OutletRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(registration, deserialized);
    }

    #[test]
    fn tool_schema_serialization_roundtrip() {
        let schema = OutletSchema {
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "string"}),
        };
        let json = serde_json::to_string(&schema).unwrap();
        let deserialized: OutletSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(schema, deserialized);
    }

    #[test]
    fn test_vector_serialization_roundtrip() {
        let vector = OutletTestVector {
            input: serde_json::json!({"x": 1}),
            expected_output: serde_json::json!({"y": 2}),
            description: "test description".to_owned(),
        };
        let json = serde_json::to_string(&vector).unwrap();
        let deserialized: OutletTestVector = serde_json::from_str(&json).unwrap();
        assert_eq!(vector, deserialized);
    }

    // ----- DID validation -----

    #[test]
    fn validate_did_accepts_valid_did() {
        assert!(validate_did("did:dht:z6MkTest").is_ok());
        assert!(validate_did("did:web:example.com").is_ok());
    }

    #[test]
    fn validate_did_rejects_empty() {
        assert!(validate_did("").is_err());
    }

    #[test]
    fn validate_did_rejects_missing_prefix() {
        assert!(validate_did("not-a-did").is_err());
    }

    // ----- OutletError display -----

    #[test]
    fn tool_error_display_messages() {
        let err = OutletError::RegistrantNotAuthorized {
            did: "did:dht:z6MkTest".into(),
        };
        assert!(format!("{err}").contains("ToolRegister capability"));

        let err = OutletError::OutletNotFound {
            outlet_id: "tool-42".to_owned(),
        };
        assert!(format!("{err}").contains("tool-42"));

        let err = OutletError::OutletAlreadyRegistered {
            outlet_id: "tool-dup".to_owned(),
        };
        assert!(format!("{err}").contains("tool-dup"));

        let err = OutletError::OutletIdMismatch {
            expected: "tool-1".to_owned(),
            actual: "tool-2".to_owned(),
        };
        assert!(format!("{err}").contains("tool-1"));
        assert!(format!("{err}").contains("tool-2"));
    }

    // ----- update_outlet event tracks all change fields -----

    #[test]
    fn update_tool_event_tracks_schema_and_vector_changes() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = OutletRegistry::new();

        let registration = valid_registration("tool-1");
        register_outlet(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        )
        .unwrap();

        // Update with changed schema and test vectors but same name/description.
        let mut new_reg = valid_registration("tool-1");
        new_reg.schema = OutletSchema {
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "x": {"type": "number"},
                    "y": {"type": "number"}
                }
            }),
            output_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "sum": {"type": "number"}
                }
            }),
        };
        new_reg.test_vectors = vec![];

        let event = update_outlet(
            &mut registry,
            &role_state,
            "tool-1",
            new_reg,
            "did:dht:z6MkCreator",
        )
        .unwrap();

        assert!(!event.changed_fields.contains(&"name".to_owned()));
        assert!(!event.changed_fields.contains(&"description".to_owned()));
        assert!(event.changed_fields.contains(&"schema".to_owned()));
        assert!(event.changed_fields.contains(&"test_vectors".to_owned()));
    }

    // ----- OutletCost -----

    #[test]
    fn tool_cost_serialization_roundtrip() {
        let cost = OutletCost {
            amount: 500,
            currency: "USD".to_owned(),
            payee: "did:dht:z6MkPayee".into(),
            cost_formula: Some("linear".to_owned()),
        };
        let json = serde_json::to_string(&cost).unwrap();
        let deserialized: OutletCost = serde_json::from_str(&json).unwrap();
        assert_eq!(cost, deserialized);
    }

    // ----- OutletKind (SCP-OUT-011) -----

    /// AC: `OutletKind::default()` returns `Action` (fail-safe per §5.4.2).
    #[test]
    fn outlet_kind_default_is_action() {
        assert_eq!(OutletKind::default(), OutletKind::Action);
    }

    /// AC: serde wire values are `"query"` and `"action"` (lowercase).
    #[test]
    fn outlet_kind_serde_lowercase_strings() {
        assert_eq!(serde_json::to_string(&OutletKind::Query).unwrap(), "\"query\"");
        assert_eq!(
            serde_json::to_string(&OutletKind::Action).unwrap(),
            "\"action\""
        );

        let q: OutletKind = serde_json::from_str("\"query\"").unwrap();
        assert_eq!(q, OutletKind::Query);
        let a: OutletKind = serde_json::from_str("\"action\"").unwrap();
        assert_eq!(a, OutletKind::Action);
    }

    /// AC: `OutletKind::canonical_byte` is `0x00` for Query, `0x01` for Action.
    #[test]
    fn outlet_kind_canonical_byte_matches_spec() {
        assert_eq!(OutletKind::Query.canonical_byte(), 0x00);
        assert_eq!(OutletKind::Action.canonical_byte(), 0x01);
    }

    /// AC: round-trip serde — `OutletRegistration { kind: Query, ... }`
    /// serializes with `"kind": "query"` and deserializes back unchanged.
    #[test]
    fn outlet_registration_query_kind_roundtrip() {
        let mut reg = valid_registration("query-tool");
        reg.kind = OutletKind::Query;
        let json = serde_json::to_string(&reg).unwrap();
        assert!(
            json.contains("\"kind\":\"query\""),
            "expected lowercase 'query' on the wire, got {json}"
        );
        let parsed: OutletRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, reg);
        assert_eq!(parsed.kind, OutletKind::Query);
    }

    /// AC: round-trip serde — Action variant serializes with `"kind": "action"`.
    #[test]
    fn outlet_registration_action_kind_roundtrip() {
        let reg = valid_registration("action-tool");
        assert_eq!(reg.kind, OutletKind::Action);
        let json = serde_json::to_string(&reg).unwrap();
        assert!(
            json.contains("\"kind\":\"action\""),
            "expected lowercase 'action' on the wire, got {json}"
        );
        let parsed: OutletRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, reg);
        assert_eq!(parsed.kind, OutletKind::Action);
    }

    /// AC: default-value test — `serde_json::from_str` of a registration
    /// JSON omitting `kind` produces `kind: Action` (fail-safe per §5.4.2).
    #[test]
    fn outlet_registration_missing_kind_defaults_to_action() {
        // Build a minimal valid JSON with NO `kind` field present.
        let zero_hash: Vec<u8> = vec![0u8; 32];
        let json = serde_json::json!({
            "outlet_id": "no-kind-tool",
            "name": "n",
            "description": "d",
            "schema": {
                "input_schema": {"type": "object"},
                "output_schema": {"type": "object"}
            },
            "implementation_hash": zero_hash,
            "test_vectors": [],
            "operator_did": "did:dht:z6MkOp",
            "cost": null,
            "registered_at": 0,
            "signature": []
        });
        let parsed: OutletRegistration = serde_json::from_value(json).unwrap();
        assert_eq!(
            parsed.kind,
            OutletKind::Action,
            "missing kind must deserialize to fail-safe Action default (§5.4.2)"
        );
    }

    /// AC: canonical preimage uses `kind_byte = 0x00` for Query and
    /// `kind_byte = 0x01` for Action — verifying that two registrations
    /// identical in every field except `kind` produce DIFFERENT canonical
    /// hashes.
    #[test]
    fn outlet_registration_preimage_distinguishes_kinds() {
        let mut q = valid_registration("dual-kind-tool");
        q.kind = OutletKind::Query;
        // Query outlets must declare zero/no cost (§5.4.2 floor).
        q.cost = None;

        let mut a = q.clone();
        a.kind = OutletKind::Action;

        let q_hash = compute_outlet_registration_canonical_bytes(&q);
        let a_hash = compute_outlet_registration_canonical_bytes(&a);
        assert_ne!(
            q_hash, a_hash,
            "Query and Action registrations identical in every other field MUST hash differently \
             (kind_byte 0x00 vs 0x01)"
        );
    }

    /// AC: preimage byte sequence — verify the `kind_byte` sits at the expected
    /// position (between `outlet_id` and `name`) for both kinds.
    ///
    /// The §5.4.1 V2 layout is:
    ///   `"SCP-OUTLET-REGISTRATION-V2:" || BE32(len(outlet_id)) || outlet_id
    ///     || kind_byte || BE32(len(name)) || name || ...`
    ///
    /// Switching `kind` between Query and Action is a single-byte mutation
    /// at the documented offset; the canonical hash MUST flip.
    #[test]
    fn outlet_registration_preimage_kind_byte_position() {
        let mut reg_q = valid_registration("kb-pos");
        reg_q.kind = OutletKind::Query;
        reg_q.test_vectors = Vec::new();
        reg_q.cost = None;

        let mut reg_a = reg_q.clone();
        reg_a.kind = OutletKind::Action;

        // Reviewer-facing expectation: the kind_byte sits at this offset
        // inside the preimage byte sequence (the SHA-256 input).
        let expected_kind_byte_offset =
            b"SCP-OUTLET-REGISTRATION-V2:".len() + 4 + reg_q.outlet_id.len();
        assert!(expected_kind_byte_offset > 0);

        let bytes_q = compute_outlet_registration_canonical_bytes(&reg_q);
        let bytes_a = compute_outlet_registration_canonical_bytes(&reg_a);
        assert_eq!(bytes_q.len(), 32);
        assert_eq!(bytes_a.len(), 32);
        assert_ne!(
            bytes_q, bytes_a,
            "mutating only kind_byte must flip the canonical hash"
        );
    }

    // ----- Query structural cost floor (SCP-OUT-012, §5.4.2) -----

    /// Helper for the four-case validate matrix. Returns a registration
    /// with the requested `kind` and `cost`, schema/`test_vectors` stripped
    /// to keep the test focused on the cost-floor check.
    fn validate_fixture(
        kind: OutletKind,
        cost: Option<OutletCost>,
    ) -> OutletRegistration {
        let mut reg = valid_registration("validate-fixture");
        reg.kind = kind;
        reg.cost = cost;
        reg.test_vectors = Vec::new();
        reg
    }

    /// AC1: Action + cost > 0 → accept. Action outlets have no structural
    /// cost floor (§5.4.2). A positive declared cost is permitted.
    #[test]
    fn validate_accepts_action_with_positive_cost() {
        let reg = validate_fixture(
            OutletKind::Action,
            Some(OutletCost {
                amount: 100,
                currency: "USD".to_owned(),
                payee: "did:dht:z6MkPayee".into(),
                cost_formula: None,
            }),
        );
        assert!(
            reg.validate().is_ok(),
            "Action+cost>0 must validate (no structural floor on Action — §5.4.2)"
        );
    }

    /// AC2: Action + cost = None → accept. Action outlets accept any cost
    /// configuration including absence (§5.4.2).
    #[test]
    fn validate_accepts_action_with_no_cost() {
        let reg = validate_fixture(OutletKind::Action, None);
        assert!(
            reg.validate().is_ok(),
            "Action+cost=None must validate (no structural floor on Action — §5.4.2)"
        );
    }

    /// AC3: Query + cost > 0 → reject with [`OutletError::QueryCostViolation`].
    /// A Query outlet declaring a positive per-invocation cost violates
    /// the §5.4.2 structural floor.
    #[test]
    fn validate_rejects_query_with_positive_cost() {
        let reg = validate_fixture(
            OutletKind::Query,
            Some(OutletCost {
                amount: 1,
                currency: "USD".to_owned(),
                payee: "did:dht:z6MkPayee".into(),
                cost_formula: None,
            }),
        );
        let err = reg.validate().expect_err("Query+cost>0 must be rejected");
        assert!(
            matches!(err, OutletError::QueryCostViolation { .. }),
            "expected QueryCostViolation, got {err:?}"
        );
        // Verify the reason mentions the positive cost.
        if let OutletError::QueryCostViolation { reason } = err {
            assert!(
                reason.contains("amount = 1") || reason.contains("amount=1"),
                "reason should cite the offending amount, got: {reason}"
            );
        }
    }

    /// AC4: Query + cost = None → accept. The structural floor permits an
    /// absent cost (§5.4.2).
    #[test]
    fn validate_accepts_query_with_no_cost() {
        let reg = validate_fixture(OutletKind::Query, None);
        assert!(
            reg.validate().is_ok(),
            "Query+cost=None must validate per §5.4.2 structural floor"
        );
    }

    /// AC4 (companion): Query + `cost { amount = 0, cost_formula = None }`
    /// → accept. The structural floor permits a present-but-zero cost
    /// because some auditing flows want the currency/payee fields visible
    /// even when the per-invocation amount is zero (§5.4.2).
    #[test]
    fn validate_accepts_query_with_zero_amount_no_formula() {
        let reg = validate_fixture(
            OutletKind::Query,
            Some(OutletCost {
                amount: 0,
                currency: "USD".to_owned(),
                payee: "did:dht:z6MkPayee".into(),
                cost_formula: None,
            }),
        );
        assert!(
            reg.validate().is_ok(),
            "Query+cost{{amount=0, formula=None}} must validate per §5.4.2"
        );
    }

    /// Query + `cost.cost_formula` present → reject. A dynamic pricing
    /// formula on a Query outlet is forbidden regardless of amount
    /// (§5.4.2: "a dynamic pricing formula on an idempotent read is not
    /// coherent").
    #[test]
    fn validate_rejects_query_with_cost_formula_even_when_amount_zero() {
        let reg = validate_fixture(
            OutletKind::Query,
            Some(OutletCost {
                amount: 0,
                currency: "USD".to_owned(),
                payee: "did:dht:z6MkPayee".into(),
                cost_formula: Some("linear".to_owned()),
            }),
        );
        let err = reg
            .validate()
            .expect_err("Query+cost_formula must be rejected even at amount=0");
        assert!(
            matches!(err, OutletError::QueryCostViolation { .. }),
            "expected QueryCostViolation, got {err:?}"
        );
        if let OutletError::QueryCostViolation { reason } = err {
            assert!(
                reason.contains("cost_formula"),
                "reason should cite cost_formula, got: {reason}"
            );
        }
    }

    /// Defense-in-depth: [`register_outlet`] rejects a Query+cost>0 even
    /// before the schema check runs — the [`OutletError::QueryCostViolation`]
    /// surfaces rather than being masked by an unrelated downstream failure.
    #[test]
    fn register_outlet_rejects_query_with_positive_cost() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = OutletRegistry::new();
        let mut registration = valid_registration("query-paid");
        registration.kind = OutletKind::Query;
        registration.cost = Some(OutletCost {
            amount: 5,
            currency: "USD".to_owned(),
            payee: "did:dht:z6MkPayee".into(),
            cost_formula: None,
        });

        let result = register_outlet(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        );
        let err = result.expect_err("Query+cost>0 must fail registration");
        assert!(
            matches!(err, OutletError::QueryCostViolation { .. }),
            "expected QueryCostViolation from register_outlet, got {err:?}"
        );
        // Registry must remain empty — the registration MUST NOT land.
        assert!(registry.is_empty(), "rejected registration must not be stored");
    }

    /// Defense-in-depth: [`update_outlet`] rejects flipping a stored Action
    /// outlet to Query while retaining a positive cost (§5.4.2 enforced
    /// at every mutation boundary).
    #[test]
    fn update_outlet_rejects_query_with_positive_cost() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = OutletRegistry::new();

        // Register a valid Action+cost outlet.
        let mut original = valid_registration("flip-target");
        original.kind = OutletKind::Action;
        original.cost = Some(OutletCost {
            amount: 50,
            currency: "USD".to_owned(),
            payee: "did:dht:z6MkPayee".into(),
            cost_formula: None,
        });
        register_outlet(
            &mut registry,
            &role_state,
            original,
            "did:dht:z6MkCreator",
        )
        .unwrap();

        // Try to update by flipping to Query while keeping the positive
        // cost — must be rejected.
        let mut flipped = valid_registration("flip-target");
        flipped.kind = OutletKind::Query;
        flipped.cost = Some(OutletCost {
            amount: 50,
            currency: "USD".to_owned(),
            payee: "did:dht:z6MkPayee".into(),
            cost_formula: None,
        });
        let err = update_outlet(
            &mut registry,
            &role_state,
            "flip-target",
            flipped,
            "did:dht:z6MkCreator",
        )
        .expect_err("update flipping to Query+cost>0 must be rejected");
        assert!(
            matches!(err, OutletError::QueryCostViolation { .. }),
            "expected QueryCostViolation from update_outlet, got {err:?}"
        );

        // Stored registration must still be the original Action+cost.
        let stored = registry
            .get("flip-target")
            .expect("original registration must still exist");
        assert_eq!(stored.kind, OutletKind::Action);
        assert_eq!(stored.cost.as_ref().map(|c| c.amount), Some(50));
    }
}
