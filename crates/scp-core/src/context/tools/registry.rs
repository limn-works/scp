//! Tool registration storage, registration, update, and verification.
//!
//! Implements the core tool registry for SCP contexts per ADR-010. Each
//! context maintains its own [`ToolRegistry`] that stores [`ToolRegistration`]
//! entries. Tools are registered, updated, and verified through free functions
//! that take the registry and role state as parameters.
//!
//! # Event Log Integration
//!
//! Registration, update, and verification functions return event payloads
//! ([`ToolRegisteredEvent`], [`ToolUpdatedEvent`], [`ToolVerifiedEvent`])
//! alongside their primary results. The caller is responsible for appending
//! these events to the context's event log.
//!
//! See ADR-010 in `.docs/adrs/phase-2.md`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::{
    DID, ToolError, ToolId, ToolRegisteredEvent, ToolUpdatedEvent, ToolVerifiedEvent,
    has_admin_role, has_tool_register_capability, schema,
};
use crate::context::roles::ContextRoleState;

// ---------------------------------------------------------------------------
// ToolSchema
// ---------------------------------------------------------------------------

/// MCP-compatible JSON Schema for a tool's input and output.
///
/// Both `input_schema` and `output_schema` must be valid JSON Schema objects
/// (at minimum, a JSON object with a `"type"` field). See spec section 8.5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolSchema {
    /// JSON Schema describing the tool's expected input.
    pub input_schema: serde_json::Value,
    /// JSON Schema describing the tool's output.
    pub output_schema: serde_json::Value,
}

// ---------------------------------------------------------------------------
// TestVector
// ---------------------------------------------------------------------------

/// A known input-output pair for tool verification.
///
/// Test vectors enable continuous integrity checking: any agent can invoke a
/// tool with test inputs and verify the output matches the expected result.
/// See spec section 7.3.3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestVector {
    /// The test input to provide to the tool.
    pub input: serde_json::Value,
    /// The expected output from the tool.
    pub expected_output: serde_json::Value,
    /// Human-readable description of what this test vector validates.
    pub description: String,
}

// ---------------------------------------------------------------------------
// ToolEconomicMetadata
// ---------------------------------------------------------------------------

/// Optional economic metadata for a tool (spec section 19.3).
///
/// Tool-level costs are additive with context costs. A tool calling an
/// external API can pass through its cost. Tool costs carry their own payee
/// DID (may differ from context payee).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolEconomicMetadata {
    /// Cost per invocation in the smallest currency unit.
    pub cost_per_invoke: u64,
    /// Optional pricing formula identifier for dynamic pricing.
    pub cost_formula: Option<String>,
    /// The DID that receives tool invocation payments. May differ from the
    /// context payee.
    pub payee: DID,
}

// ---------------------------------------------------------------------------
// ToolRegistration
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
pub struct ToolRegistration {
    /// Unique identifier for this tool within the context.
    pub tool_id: ToolId,
    /// Human-readable name of the tool.
    pub name: String,
    /// Description of the tool's purpose and behavior.
    pub description: String,
    /// MCP-compatible JSON Schema for input and output.
    pub schema: ToolSchema,
    /// SHA-256 hash of the tool implementation. Used for integrity verification.
    /// Any change to the implementation produces a new hash.
    pub implementation_hash: [u8; 32],
    /// Known input-output pairs for continuous verification.
    pub test_vectors: Vec<TestVector>,
    /// The DID of the operator accountable for this tool.
    pub operator_did: DID,
    /// Optional economic metadata for per-invocation costs (spec section 19.3).
    pub economic_metadata: Option<ToolEconomicMetadata>,
    /// Unix timestamp (milliseconds) when the tool was registered.
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
    /// the claimed registrant. The signed payload is the MessagePack encoding
    /// of all fields except `signature` itself. Defaults to empty for backward
    /// compatibility.
    #[serde(default)]
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// ToolVerificationResult
// ---------------------------------------------------------------------------

/// Result of verifying a tool against its test vectors.
///
/// Contains per-vector pass/fail status and an overall integrity assessment.
/// See ADR-010 acceptance criterion 5.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolVerificationResult {
    /// The tool that was verified.
    pub tool_id: ToolId,
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
// ToolRegistry
// ---------------------------------------------------------------------------

/// In-memory tool storage for a single SCP context.
///
/// Maps tool IDs to their full registration entries. Each context maintains
/// its own `ToolRegistry`. See ADR-010.
#[derive(Debug, Clone, Default)]
pub struct ToolRegistry {
    /// Registered tools, keyed by tool ID.
    tools: HashMap<ToolId, ToolRegistration>,
}

impl ToolRegistry {
    /// Creates a new empty tool registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    /// Returns the registration for the given tool ID, if it exists.
    #[must_use]
    pub fn get(&self, tool_id: &str) -> Option<&ToolRegistration> {
        self.tools.get(tool_id)
    }

    /// Returns `true` if the registry contains the given tool ID.
    #[must_use]
    pub fn contains(&self, tool_id: &str) -> bool {
        self.tools.contains_key(tool_id)
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
    pub fn tool_ids(&self) -> impl Iterator<Item = &ToolId> {
        self.tools.keys()
    }

    /// Returns an iterator over all registrations.
    pub fn registrations(&self) -> impl Iterator<Item = &ToolRegistration> {
        self.tools.values()
    }

    /// Inserts a tool registration. Returns the previous registration if one
    /// existed for this tool ID.
    fn insert(&mut self, registration: ToolRegistration) -> Option<ToolRegistration> {
        self.tools
            .insert(registration.tool_id.clone(), registration)
    }
}

// ---------------------------------------------------------------------------
// register_tool
// ---------------------------------------------------------------------------

/// Registers a new tool in the context's tool registry.
///
/// Validates:
/// 1. Registrant has `ToolRegister` capability via UCAN (ADR-009).
/// 2. Input and output schemas are valid JSON Schema.
/// 3. Implementation hash is 32 bytes (enforced by type system).
/// 4. Operator DID is resolvable (basic format check).
/// 5. Tool ID is not already registered.
///
/// On success, stores the registration and returns the tool ID along with a
/// [`ToolRegisteredEvent`] for the caller to append to the event log.
///
/// # Errors
///
/// Returns [`ToolError`] on validation failure.
pub fn register_tool(
    registry: &mut ToolRegistry,
    role_state: &ContextRoleState,
    registration: ToolRegistration,
    registrant_did: &str,
) -> Result<(ToolId, ToolRegisteredEvent), ToolError> {
    // 1. Validate registrant has ToolRegister capability.
    if !has_tool_register_capability(role_state, registrant_did) {
        return Err(ToolError::RegistrantNotAuthorized {
            did: registrant_did.to_owned(),
        });
    }

    // 2. Validate schemas.
    schema::validate_schema(&registration.schema.input_schema)
        .map_err(ToolError::InvalidInputSchema)?;
    schema::validate_schema(&registration.schema.output_schema)
        .map_err(ToolError::InvalidOutputSchema)?;

    // 2b. Enforce schema specificity floor (spec section 6.2, 9.2.1).
    if let Err((side, field_count)) = schema::validate_specificity_floor(
        &registration.schema.input_schema,
        &registration.schema.output_schema,
    ) {
        return Err(ToolError::SchemaSpecificityFloor {
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
    if registry.contains(&registration.tool_id) {
        return Err(ToolError::ToolAlreadyRegistered {
            tool_id: registration.tool_id,
        });
    }

    // Build event payload.
    let event = ToolRegisteredEvent {
        tool_id: registration.tool_id.clone(),
        name: registration.name.clone(),
        description: registration.description.clone(),
        implementation_hash: registration.implementation_hash,
        operator_did: registration.operator_did.clone(),
        registrant_did: registrant_did.into(),
        test_vector_count: registration.test_vectors.len(),
    };

    let tool_id = registration.tool_id.clone();
    registry.insert(registration);

    Ok((tool_id, event))
}

// ---------------------------------------------------------------------------
// update_tool
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
/// Returns [`ToolError`] on validation failure.
pub fn update_tool(
    registry: &mut ToolRegistry,
    role_state: &ContextRoleState,
    tool_id: &str,
    new_registration: ToolRegistration,
    updater_did: &str,
) -> Result<ToolUpdatedEvent, ToolError> {
    // 1. Look up the existing registration.
    let old_registration = registry
        .get(tool_id)
        .ok_or_else(|| ToolError::ToolNotFound {
            tool_id: tool_id.to_owned(),
        })?
        .clone();

    // 2. Validate updater is operator or admin.
    let is_operator = old_registration.operator_did == updater_did;
    let is_admin = has_admin_role(role_state, updater_did);
    if !is_operator && !is_admin {
        return Err(ToolError::UpdaterNotAuthorized {
            did: updater_did.to_owned(),
        });
    }

    // 3. Validate tool ID matches.
    if new_registration.tool_id != tool_id {
        return Err(ToolError::ToolIdMismatch {
            expected: tool_id.to_owned(),
            actual: new_registration.tool_id,
        });
    }

    // 4. Validate schemas.
    schema::validate_schema(&new_registration.schema.input_schema)
        .map_err(ToolError::InvalidInputSchema)?;
    schema::validate_schema(&new_registration.schema.output_schema)
        .map_err(ToolError::InvalidOutputSchema)?;

    // 4b. Enforce schema specificity floor (spec section 6.2, 9.2.1).
    if let Err((side, field_count)) = schema::validate_specificity_floor(
        &new_registration.schema.input_schema,
        &new_registration.schema.output_schema,
    ) {
        return Err(ToolError::SchemaSpecificityFloor {
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

    let event = ToolUpdatedEvent {
        tool_id: tool_id.to_owned(),
        old_implementation_hash: old_registration.implementation_hash,
        new_implementation_hash: new_registration.implementation_hash,
        updater_did: updater_did.into(),
        changed_fields,
    };

    registry.insert(new_registration);

    Ok(event)
}

// ---------------------------------------------------------------------------
// verify_tool
// ---------------------------------------------------------------------------

/// Verifies a tool by running all its test vectors.
///
/// For each test vector: compares the expected output to the tool's declared
/// expected output. In Phase 2, verification is a comparison against the
/// stored test vectors (the tool executor is not yet integrated). The caller
/// provides actual outputs via the `executor` function parameter.
///
/// Returns a [`ToolVerificationResult`] with per-vector pass/fail status and
/// overall integrity assessment, plus a [`ToolVerifiedEvent`] for the event
/// log.
///
/// See ADR-010 acceptance criterion 5.
///
/// # Errors
///
/// Returns [`ToolError::ToolNotFound`] if the tool is not in the registry.
pub fn verify_tool<F>(
    registry: &ToolRegistry,
    tool_id: &str,
    executor: F,
) -> Result<(ToolVerificationResult, ToolVerifiedEvent), ToolError>
where
    F: Fn(&serde_json::Value) -> serde_json::Value,
{
    let registration = registry
        .get(tool_id)
        .ok_or_else(|| ToolError::ToolNotFound {
            tool_id: tool_id.to_owned(),
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

    let result = ToolVerificationResult {
        tool_id: tool_id.to_owned(),
        vector_results,
        integrity_ok,
    };

    let event = ToolVerifiedEvent {
        tool_id: tool_id.to_owned(),
        passed: passed_count,
        failed: failed_count,
        integrity_ok,
    };

    Ok((result, event))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Basic DID format validation.
///
/// Phase 2 check: a DID must be non-empty and start with `"did:"`. Full DID
/// resolution is deferred to the identity subsystem.
fn validate_did(did: &str) -> Result<(), ToolError> {
    if did.is_empty() || !did.starts_with("did:") {
        return Err(ToolError::UnresolvableDid {
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
        ContextRoleState::new("ctx-test", creator_did, test_ceiling(), vec![]).unwrap()
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
    fn valid_registration(tool_id: &str) -> ToolRegistration {
        ToolRegistration {
            tool_id: tool_id.to_owned(),
            name: "calculator".to_owned(),
            description: "A simple calculator tool".to_owned(),
            schema: ToolSchema {
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
                TestVector {
                    input: serde_json::json!({"operation": "add", "a": 1, "b": 2}),
                    expected_output: serde_json::json!({"result": 3}),
                    description: "1 + 2 = 3".to_owned(),
                },
                TestVector {
                    input: serde_json::json!({"operation": "mul", "a": 3, "b": 4}),
                    expected_output: serde_json::json!({"result": 12}),
                    description: "3 * 4 = 12".to_owned(),
                },
            ],
            operator_did: "did:dht:z6MkTestOperator".into(),
            economic_metadata: None,
            registered_at: 0,
            signature: Vec::new(),
        }
    }

    // ----- register_tool tests -----

    #[test]
    fn register_tool_succeeds_with_valid_registration() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = ToolRegistry::new();
        let registration = valid_registration("tool-1");

        let result = register_tool(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        );
        assert!(result.is_ok());

        let (tool_id, event) = result.unwrap();
        assert_eq!(tool_id, "tool-1");
        assert_eq!(event.tool_id, "tool-1");
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
        let mut registry = ToolRegistry::new();

        // Invalid input schema (not an object).
        let mut registration = valid_registration("tool-1");
        registration.schema.input_schema = serde_json::json!("not an object");

        let result = register_tool(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        );
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ToolError::InvalidInputSchema(_)),
            "expected InvalidInputSchema"
        );

        // Invalid output schema (missing type field).
        let mut registration = valid_registration("tool-1");
        registration.schema.output_schema = serde_json::json!({"properties": {}});

        let result = register_tool(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        );
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ToolError::InvalidOutputSchema(_)),
            "expected InvalidOutputSchema"
        );
    }

    #[test]
    fn register_tool_rejects_schema_below_specificity_floor() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = ToolRegistry::new();

        // Both schemas have only 1 property -- below the MIN_SCHEMA_FIELDS (2) floor.
        let mut registration = valid_registration("tool-1");
        registration.schema = ToolSchema {
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

        let result = register_tool(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ToolError::SchemaSpecificityFloor { min_fields: 2, .. }),
            "expected SchemaSpecificityFloor, got {err:?}"
        );
    }

    #[test]
    fn register_tool_accepts_schema_meeting_specificity_floor_on_input() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = ToolRegistry::new();

        // Input has 2 properties, output has 0 -- should pass.
        let mut registration = valid_registration("tool-1");
        registration.schema = ToolSchema {
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

        let result = register_tool(
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
        let mut registry = ToolRegistry::new();
        let registration = valid_registration("tool-1");

        let result = register_tool(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkMember",
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ToolError::RegistrantNotAuthorized { .. }),
            "expected RegistrantNotAuthorized, got {err:?}"
        );
    }

    #[test]
    fn register_tool_rejects_empty_operator_did() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = ToolRegistry::new();
        let mut registration = valid_registration("tool-1");
        registration.operator_did = DID::from("");

        let result = register_tool(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        );
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ToolError::UnresolvableDid { .. }),
            "expected UnresolvableDid"
        );
    }

    #[test]
    fn register_tool_rejects_malformed_operator_did() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = ToolRegistry::new();
        let mut registration = valid_registration("tool-1");
        registration.operator_did = "not-a-did".into();

        let result = register_tool(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ToolError::UnresolvableDid { .. }
        ));
    }

    #[test]
    fn register_tool_rejects_duplicate_tool_id() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = ToolRegistry::new();

        let registration = valid_registration("tool-1");
        register_tool(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        )
        .unwrap();

        let registration2 = valid_registration("tool-1");
        let result = register_tool(
            &mut registry,
            &role_state,
            registration2,
            "did:dht:z6MkCreator",
        );
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ToolError::ToolAlreadyRegistered { .. }),
            "expected ToolAlreadyRegistered"
        );
    }

    #[test]
    fn register_tool_with_economic_metadata() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = ToolRegistry::new();
        let mut registration = valid_registration("tool-1");
        registration.economic_metadata = Some(ToolEconomicMetadata {
            cost_per_invoke: 100,
            cost_formula: None,
            payee: "did:dht:z6MkPayee".into(),
        });

        let result = register_tool(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        );
        assert!(result.is_ok());

        let stored = registry.get("tool-1").unwrap();
        assert!(stored.economic_metadata.is_some());
        assert_eq!(
            stored.economic_metadata.as_ref().unwrap().cost_per_invoke,
            100
        );
    }

    // ----- update_tool tests -----

    #[test]
    fn update_tool_succeeds_by_operator() {
        let role_state = test_role_state_with_member("did:dht:z6MkCreator", "did:dht:z6MkOperator");
        let mut registry = ToolRegistry::new();

        // Register with operator DID.
        let mut registration = valid_registration("tool-1");
        registration.operator_did = "did:dht:z6MkOperator".into();
        register_tool(
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

        let result = update_tool(
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
        let mut registry = ToolRegistry::new();

        let registration = valid_registration("tool-1");
        register_tool(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        )
        .unwrap();

        // Admin can update even though they are not the operator.
        let mut new_reg = valid_registration("tool-1");
        new_reg.description = "updated description".to_owned();

        let result = update_tool(
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
        let mut registry = ToolRegistry::new();

        let mut registration = valid_registration("tool-1");
        registration.implementation_hash = [0x11; 32];
        register_tool(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        )
        .unwrap();

        let mut new_reg = valid_registration("tool-1");
        new_reg.implementation_hash = [0x22; 32];

        let event = update_tool(
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
        let mut registry = ToolRegistry::new();

        let registration = valid_registration("tool-1");
        register_tool(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        )
        .unwrap();

        let new_reg = valid_registration("tool-1");
        let result = update_tool(
            &mut registry,
            &role_state,
            "tool-1",
            new_reg,
            "did:dht:z6MkMember",
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ToolError::UpdaterNotAuthorized { .. }
        ));
    }

    #[test]
    fn update_tool_rejects_nonexistent_tool() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = ToolRegistry::new();

        let new_reg = valid_registration("tool-missing");
        let result = update_tool(
            &mut registry,
            &role_state,
            "tool-missing",
            new_reg,
            "did:dht:z6MkCreator",
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ToolError::ToolNotFound { .. }
        ));
    }

    #[test]
    fn update_tool_rejects_mismatched_tool_id() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = ToolRegistry::new();

        let registration = valid_registration("tool-1");
        register_tool(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        )
        .unwrap();

        // new_reg has different tool_id.
        let new_reg = valid_registration("tool-2");
        let result = update_tool(
            &mut registry,
            &role_state,
            "tool-1",
            new_reg,
            "did:dht:z6MkCreator",
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ToolError::ToolIdMismatch { .. }
        ));
    }

    // ----- verify_tool tests -----

    #[test]
    fn verify_tool_returns_correct_pass_fail_per_test_vector() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = ToolRegistry::new();

        let registration = valid_registration("tool-1");
        register_tool(
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

        let (result, event) = verify_tool(&registry, "tool-1", executor).unwrap();

        assert_eq!(result.tool_id, "tool-1");
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
        let mut registry = ToolRegistry::new();

        let registration = valid_registration("tool-1");
        register_tool(
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

        let (result, event) = verify_tool(&registry, "tool-1", executor).unwrap();

        assert!(result.integrity_ok);
        assert_eq!(event.passed, 2);
        assert_eq!(event.failed, 0);
        assert!(event.integrity_ok);
    }

    #[test]
    fn verify_tool_rejects_nonexistent_tool() {
        let registry = ToolRegistry::new();
        let result = verify_tool(&registry, "tool-missing", |_| serde_json::json!(null));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ToolError::ToolNotFound { .. }
        ));
    }

    #[test]
    fn verify_tool_with_no_test_vectors_passes() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = ToolRegistry::new();

        let mut registration = valid_registration("tool-1");
        registration.test_vectors = vec![];
        register_tool(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        )
        .unwrap();

        let (result, event) =
            verify_tool(&registry, "tool-1", |_| serde_json::json!(null)).unwrap();

        assert!(result.integrity_ok);
        assert!(result.vector_results.is_empty());
        assert_eq!(event.passed, 0);
        assert_eq!(event.failed, 0);
    }

    // ----- ToolRegistry tests -----

    #[test]
    fn tool_registry_starts_empty() {
        let registry = ToolRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn tool_registry_get_returns_none_for_missing() {
        let registry = ToolRegistry::new();
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn tool_registry_iterators() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = ToolRegistry::new();

        register_tool(
            &mut registry,
            &role_state,
            valid_registration("tool-a"),
            "did:dht:z6MkCreator",
        )
        .unwrap();
        register_tool(
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

        let regs: Vec<&ToolRegistration> = registry.registrations().collect();
        assert_eq!(regs.len(), 2);
    }

    // ----- ToolRegistration serialization -----

    #[test]
    fn tool_registration_serialization_roundtrip() {
        let registration = valid_registration("tool-1");
        let json = serde_json::to_string(&registration).unwrap();
        let deserialized: ToolRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(registration, deserialized);
    }

    #[test]
    fn tool_schema_serialization_roundtrip() {
        let schema = ToolSchema {
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "string"}),
        };
        let json = serde_json::to_string(&schema).unwrap();
        let deserialized: ToolSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(schema, deserialized);
    }

    #[test]
    fn test_vector_serialization_roundtrip() {
        let vector = TestVector {
            input: serde_json::json!({"x": 1}),
            expected_output: serde_json::json!({"y": 2}),
            description: "test description".to_owned(),
        };
        let json = serde_json::to_string(&vector).unwrap();
        let deserialized: TestVector = serde_json::from_str(&json).unwrap();
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

    // ----- ToolError display -----

    #[test]
    fn tool_error_display_messages() {
        let err = ToolError::RegistrantNotAuthorized {
            did: "did:dht:z6MkTest".into(),
        };
        assert!(format!("{err}").contains("ToolRegister capability"));

        let err = ToolError::ToolNotFound {
            tool_id: "tool-42".to_owned(),
        };
        assert!(format!("{err}").contains("tool-42"));

        let err = ToolError::ToolAlreadyRegistered {
            tool_id: "tool-dup".to_owned(),
        };
        assert!(format!("{err}").contains("tool-dup"));

        let err = ToolError::ToolIdMismatch {
            expected: "tool-1".to_owned(),
            actual: "tool-2".to_owned(),
        };
        assert!(format!("{err}").contains("tool-1"));
        assert!(format!("{err}").contains("tool-2"));
    }

    // ----- update_tool event tracks all change fields -----

    #[test]
    fn update_tool_event_tracks_schema_and_vector_changes() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        let mut registry = ToolRegistry::new();

        let registration = valid_registration("tool-1");
        register_tool(
            &mut registry,
            &role_state,
            registration,
            "did:dht:z6MkCreator",
        )
        .unwrap();

        // Update with changed schema and test vectors but same name/description.
        let mut new_reg = valid_registration("tool-1");
        new_reg.schema = ToolSchema {
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

        let event = update_tool(
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

    // ----- Economic metadata -----

    #[test]
    fn tool_economic_metadata_serialization_roundtrip() {
        let meta = ToolEconomicMetadata {
            cost_per_invoke: 500,
            cost_formula: Some("linear".to_owned()),
            payee: "did:dht:z6MkPayee".into(),
        };
        let json = serde_json::to_string(&meta).unwrap();
        let deserialized: ToolEconomicMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(meta, deserialized);
    }
}
