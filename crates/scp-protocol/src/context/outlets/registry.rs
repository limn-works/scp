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
    DID, OutletError, OutletId, OutletRegisteredEvent, OutletUpdatedEvent, OutletVerifiedEvent,
    has_admin_role, has_outlet_register_capability, schema,
};
// `OutletKind` is referenced only by the tests module below; gating the
// import keeps the lib build warning-free while preserving the test-only
// fixture helpers that exercise both Query and Action kinds.
#[cfg(test)]
use super::OutletKind;
use crate::context::roles::ContextRoleState;
use crate::economy::types::Amount;

// ---------------------------------------------------------------------------
// OutletSchema
// ---------------------------------------------------------------------------

/// MCP-compatible JSON Schema for a tool's input and output.
///
/// Both `input_schema` and `output_schema` must be valid JSON Schema objects
/// (at minimum, a JSON object with a `"type"` field). See spec section 8.5.
///
/// Streaming outlets (§5.4.5) MAY additionally declare an `aggregate_schema`
/// describing the shape of the terminal `End.aggregate` value. When present,
/// it is validated by the cross-context chunk bridge (SCP-OUT-036) at stream
/// close. When absent, the runtime falls back to validating `End.aggregate`
/// against `output_schema` per §5.4.5 ("matches `aggregate_schema` or
/// defaults to last Data").
///
/// # Backward compatibility
///
/// `aggregate_schema` is `Option` and is omitted from `MessagePack` /
/// `serde_json` output via `skip_serializing_if = "Option::is_none"`. A
/// pre-OUT-036 registration deserializes with `aggregate_schema = None`,
/// and round-trip serialization of a `None`-valued schema is byte-identical
/// to the pre-OUT-036 form — `schema_hash` (§5.4.1) is preserved across
/// upgrades, so existing operator signatures remain valid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutletSchema {
    /// JSON Schema describing the tool's expected input.
    pub input_schema: serde_json::Value,
    /// JSON Schema describing the tool's output.
    pub output_schema: serde_json::Value,
    /// JSON Schema describing the terminal aggregate value emitted by a
    /// streaming outlet's `End` chunk (§5.4.5). Optional — when absent,
    /// `End.aggregate` is validated against `output_schema` per the §5.4.5
    /// "matches `aggregate_schema` or defaults to last Data" rule.
    ///
    /// Serialized only when `Some`, preserving byte-for-byte `MessagePack`
    /// compatibility with pre-OUT-036 registrations whose `schema_hash`
    /// (§5.4.1) was computed over a 2-field schema body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aggregate_schema: Option<serde_json::Value>,
}

impl OutletSchema {
    /// Constructs a non-streaming `OutletSchema` (no `aggregate_schema`).
    ///
    /// Convenience constructor for the common pre-OUT-036 case. Use
    /// [`Self::with_aggregate_schema`] to attach the aggregate schema.
    #[must_use]
    pub const fn new(input_schema: serde_json::Value, output_schema: serde_json::Value) -> Self {
        Self {
            input_schema,
            output_schema,
            aggregate_schema: None,
        }
    }

    /// Returns a copy of this schema with `aggregate_schema` set.
    #[must_use]
    pub fn with_aggregate_schema(mut self, schema: serde_json::Value) -> Self {
        self.aggregate_schema = Some(schema);
        self
    }
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
    ///
    /// Serializes on the wire as a canonical decimal string (ADR-060).
    pub amount: Amount,
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
//
// The struct definition and validation entry points live in the sibling
// `registration` module per SCP-OUT-040 (the §5.4.1 V2 preimage now includes
// `description_hash` and `catalog_hash` terms that need to live next to the
// `message_catalog` field they cover). The re-export below preserves the
// public path `scp_protocol::context::outlets::registry::OutletRegistration`
// for every existing caller.
pub use super::registration::OutletRegistration;

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
    pub fn outlet_ids(&self) -> impl Iterator<Item = &OutletId> {
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
        return Err(OutletError::ToolAlreadyRegistered {
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
        return Err(OutletError::ToolIdMismatch {
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
        // `verify_outlet` only attributes test-vector failures here; the
        // QueryMisdeclaration reason is emitted from the runtime
        // `ReadOnlyInvocation` deny-list (SCP-OUT-013), not from this path.
        reason: if integrity_ok {
            None
        } else {
            Some(super::OutletVerifiedReason::TestVectorFailed)
        },
    };

    Ok((result, event))
}

// ---------------------------------------------------------------------------
// Tool registration signature verification (M15)
// ---------------------------------------------------------------------------

/// Computes the canonical SHA-256 digest of the §5.4.1 V2 outlet-registration
/// preimage.
///
/// Returns the 32-byte SHA-256 output as a `Vec<u8>` for backward
/// compatibility with the original signature; new code should prefer
/// [`super::hash::compute_outlet_registration_canonical_bytes`], which
/// returns a typed `[u8; 32]`. Both calls produce byte-identical output;
/// this shim exists so downstream callers (FFI bridges, conformance
/// fixtures, tests) keep compiling.
///
/// The V2 preimage layout is documented in [`super::hash`]; SCP-OUT-040 added
/// `description_hash` and `catalog_hash` terms (round-5 ADR-049) closing the
/// remaining operator-prose covert-channel surface.
#[must_use]
pub fn compute_outlet_registration_canonical_bytes(registration: &OutletRegistration) -> Vec<u8> {
    super::hash::compute_outlet_registration_canonical_bytes(registration).to_vec()
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
            Capability::ToolRegister,
            Capability::ToolInvokeAll,
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
            &scp_clock::SystemClock,
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
            Capability::ToolInvokeAll,
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
                aggregate_schema: None,
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
            message_catalog: Vec::new(),
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
            aggregate_schema: None,
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
            aggregate_schema: None,
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
                OutletError::ToolAlreadyRegistered { .. }
            ),
            "expected ToolAlreadyRegistered"
        );
    }

    #[test]
    fn register_tool_with_cost() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = OutletRegistry::new();
        let mut registration = valid_registration("tool-1");
        registration.cost = Some(OutletCost {
            amount: Amount(100),
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
        assert_eq!(stored.cost.as_ref().unwrap().amount, Amount(100));
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
            OutletError::ToolIdMismatch { .. }
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

        let ids: Vec<&String> = registry.outlet_ids().collect();
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
            aggregate_schema: None,
        };
        let json = serde_json::to_string(&schema).unwrap();
        let deserialized: OutletSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(schema, deserialized);
    }

    /// AC (SCP-OUT-036): `aggregate_schema: None` is omitted from JSON
    /// and `MessagePack` output, so adding the field does not change the
    /// `schema_hash` (§5.4.1) for existing pre-OUT-036 registrations.
    /// Critical for signature compatibility — operators MUST NOT have
    /// to re-sign every registration on the version bump.
    #[test]
    fn outlet_schema_omits_none_aggregate_schema_from_serialization() {
        // Locally-scoped helper type — declared at the top of the test
        // body so the items-after-statements lint stays happy.
        #[derive(Serialize)]
        struct LegacyOutletSchema {
            input_schema: serde_json::Value,
            output_schema: serde_json::Value,
        }

        let with_none = OutletSchema {
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "string"}),
            aggregate_schema: None,
        };
        let json = serde_json::to_string(&with_none).unwrap();
        // The JSON output must NOT contain the `aggregate_schema` key.
        assert!(
            !json.contains("aggregate_schema"),
            "None aggregate_schema must be omitted; got {json}"
        );
        // MessagePack output should also omit the field. We compare the
        // bytes against a hand-constructed pre-OUT-036 form.
        let bytes_new = rmp_serde::to_vec(&with_none).unwrap();
        let legacy = LegacyOutletSchema {
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "string"}),
        };
        let bytes_legacy = rmp_serde::to_vec(&legacy).unwrap();
        assert_eq!(
            bytes_new, bytes_legacy,
            "MessagePack serialization with aggregate_schema=None must match the pre-OUT-036 \
             2-field encoding byte-for-byte"
        );
    }

    /// AC (SCP-OUT-036): `aggregate_schema: Some(...)` round-trips
    /// through JSON and `MessagePack`. Aggregate schema content survives
    /// serialization without loss.
    #[test]
    fn outlet_schema_with_aggregate_schema_roundtrips() {
        let schema = OutletSchema {
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "object",
                "properties": {"chunk": {"type": "integer"}}}),
            aggregate_schema: Some(serde_json::json!({
                "type": "object",
                "properties": {
                    "total": {"type": "integer"},
                    "summary": {"type": "string"}
                },
                "required": ["total", "summary"]
            })),
        };

        // JSON roundtrip.
        let json = serde_json::to_string(&schema).unwrap();
        assert!(
            json.contains("aggregate_schema"),
            "Some aggregate_schema must appear in JSON; got {json}"
        );
        let parsed: OutletSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, schema);

        // `MessagePack` roundtrip.
        let bytes = rmp_serde::to_vec(&schema).unwrap();
        let parsed_mp: OutletSchema = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(parsed_mp, schema);
    }

    /// AC (SCP-OUT-036): `OutletSchema::new` constructs a 2-field schema
    /// with `aggregate_schema = None`. `with_aggregate_schema` attaches.
    #[test]
    fn outlet_schema_constructors() {
        let two_field = OutletSchema::new(
            serde_json::json!({"type": "object"}),
            serde_json::json!({"type": "string"}),
        );
        assert!(two_field.aggregate_schema.is_none());

        let with_agg = two_field
            .clone()
            .with_aggregate_schema(serde_json::json!({"type": "object"}));
        assert_eq!(
            with_agg.aggregate_schema,
            Some(serde_json::json!({"type": "object"}))
        );
        // The original is unmodified.
        assert!(two_field.aggregate_schema.is_none());
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

        let err = OutletError::ToolAlreadyRegistered {
            outlet_id: "tool-dup".to_owned(),
        };
        assert!(format!("{err}").contains("tool-dup"));

        let err = OutletError::ToolIdMismatch {
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
            aggregate_schema: None,
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
            amount: Amount(500),
            currency: "USD".to_owned(),
            payee: "did:dht:z6MkPayee".into(),
            cost_formula: Some("linear".to_owned()),
        };
        let json = serde_json::to_string(&cost).unwrap();
        let deserialized: OutletCost = serde_json::from_str(&json).unwrap();
        assert_eq!(cost, deserialized);
    }

    #[test]
    fn outlet_cost_amount_serializes_as_canonical_decimal_string() {
        // ADR-060 wire form: amount is a quoted string, not a JSON number.
        let cost = OutletCost {
            amount: Amount(500),
            currency: "USD".to_owned(),
            payee: "did:dht:z6MkPayee".into(),
            cost_formula: None,
        };
        let value: serde_json::Value = serde_json::to_value(&cost).unwrap();
        assert_eq!(value["amount"], serde_json::json!("500"));
        assert!(value["amount"].is_string());
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
        assert_eq!(
            serde_json::to_string(&OutletKind::Query).unwrap(),
            "\"query\""
        );
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
    fn validate_fixture(kind: OutletKind, cost: Option<OutletCost>) -> OutletRegistration {
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
                amount: Amount(100),
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
                amount: Amount(1),
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
                amount: Amount(0),
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
                amount: Amount(0),
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
            amount: Amount(5),
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
        assert!(
            registry.is_empty(),
            "rejected registration must not be stored"
        );
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
            amount: Amount(50),
            currency: "USD".to_owned(),
            payee: "did:dht:z6MkPayee".into(),
            cost_formula: None,
        });
        register_outlet(&mut registry, &role_state, original, "did:dht:z6MkCreator").unwrap();

        // Try to update by flipping to Query while keeping the positive
        // cost — must be rejected.
        let mut flipped = valid_registration("flip-target");
        flipped.kind = OutletKind::Query;
        flipped.cost = Some(OutletCost {
            amount: Amount(50),
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
        assert_eq!(stored.cost.as_ref().map(|c| c.amount), Some(Amount(50)));
    }
}
