//! Cross-context tool bridge between two SCP contexts (spec section 6.2).
//!
//! Demonstrates the full bidirectional consent protocol for cross-context
//! tool interfaces:
//!
//!   1. Create two contexts with separate identities and role states.
//!   2. Register a tool in Context A (the provider).
//!   3. Context A exposes the tool to Context B via `expose_tool`.
//!   4. Publish an `InterfaceOffer` (governance approval step).
//!   5. Context B accepts the offer via `accept_tool_interface`.
//!   6. A participant in Context B invokes the tool across contexts via
//!      `invoke_cross_context` — the bridge routes the call to Context A,
//!      executes, and returns the result with provenance events for both
//!      event logs.
//!
//! Usage:
//!   `cargo run`

use scp_core::context::outlets::interface::{
    accept_tool_interface, create_interface_offer, expose_tool, invoke_cross_context,
    InboundPolicy, OutboundPolicy, RateLimit,
};
use scp_core::context::outlets::{
    register_outlet, OutletKind, OutletRegistration, OutletRegistry, OutletSchema,
};
use scp_core::context::roles::{Capability, CapabilityCeiling, ContextRoleState};
use scp_core::context::{ContextHandle, ContextParams, ContextState, MemoryScope};
use scp_core::provenance::attach::SourceContextInfo;
use scp_core::provenance::{CounterpartyPolicy, DiscoveryMethod, SourceType};
use scp_did::DID;

use std::time::Duration;

/// Builds a capability ceiling with admin and tool capabilities.
fn admin_ceiling() -> CapabilityCeiling {
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
        Capability::OutletInterface,
    ])
}

/// Sets up a context handle in the Active state.
fn create_active_context(context_id: &str) -> Result<ContextHandle, Box<dyn std::error::Error>> {
    let handle = ContextHandle::new(context_id.to_owned(), ContextParams::default());
    // `transition_to` is a synchronous lock-free ArcSwap CAS (ADR-049 §10).
    handle.transition_to(&ContextState::Active)?;
    Ok(handle)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== SCP Cross-Context Tool Bridge ===\n");

    // -----------------------------------------------------------------------
    // 1. Create identities
    // -----------------------------------------------------------------------

    let operator_did: DID = "did:dht:z6MkBridgeOperator".into();
    // The bridge operator participates in both contexts. In a real deployment
    // this is a human whose SDK bridges tool requests locally (spec section 6.2.0).
    println!("Bridge operator: {operator_did}");

    // -----------------------------------------------------------------------
    // 2. Create two separate contexts
    // -----------------------------------------------------------------------

    let ctx_a = create_active_context("context-a-provider")?;
    let ctx_b = create_active_context("context-b-consumer")?;
    println!("Context A (provider): {}", ctx_a.context_id());
    println!("Context B (consumer): {}", ctx_b.context_id());

    // Role states: the operator is admin in both contexts.
    let role_state_a = ContextRoleState::new(
        ctx_a.context_id(),
        &*operator_did,
        admin_ceiling(),
        vec![],
        &scp_clock::SystemClock,
    )
    .map_err(|e| e.to_string())?;
    let role_state_b = ContextRoleState::new(
        ctx_b.context_id(),
        &*operator_did,
        admin_ceiling(),
        vec![],
        &scp_clock::SystemClock,
    )
    .map_err(|e| e.to_string())?;

    // -----------------------------------------------------------------------
    // 3. Register a tool in Context A
    // -----------------------------------------------------------------------

    let mut registry_a = OutletRegistry::new();
    let registration = OutletRegistration {
        outlet_id: "translator".to_owned(),
        kind: OutletKind::Action,
        name: "Translator".to_owned(),
        description: "Translates text between languages".to_owned(),
        schema: OutletSchema::new(
            serde_json::json!({
                "type": "object",
                "properties": {
                    "text": { "type": "string" },
                    "target_language": { "type": "string" }
                },
                "required": ["text", "target_language"]
            }),
            serde_json::json!({
                "type": "object",
                "properties": {
                    "translated": { "type": "string" },
                    "source_language": { "type": "string" }
                },
                "required": ["translated", "source_language"]
            }),
        ),
        implementation_hash: [0xBB; 32],
        test_vectors: vec![],
        operator_did: operator_did.clone(),
        cost: None,
        message_catalog: vec![],
        registered_at: 0,
        signature: Vec::new(),
    };

    let (outlet_id, _event) =
        register_outlet(&mut registry_a, &role_state_a, registration, &operator_did)
            .map_err(|e| e.to_string())?;
    println!("\nRegistered outlet in Context A: {outlet_id}");

    // -----------------------------------------------------------------------
    // 4. Context A exposes the tool to Context B (section 6.2.0.1 step 1-2)
    // -----------------------------------------------------------------------

    let outbound_policy = OutboundPolicy {
        allowed_callers: vec![], // any member with OutletInterface capability
        max_calls_per_minute: 60,
        max_payload_bytes: 65_536,
        require_provenance: true,
    };

    let rate_limit = RateLimit::new(60, Duration::from_secs(60), &scp_clock::SystemClock);

    let mut interface = expose_tool(
        ctx_a.context_id(),
        &outlet_id,
        &ctx_b.context_id().to_owned(),
        &role_state_a,
        &operator_did,
        &registry_a,
        Some(rate_limit),
        Some(outbound_policy),
    )
    .map_err(|e| e.to_string())?;

    println!(
        "Context A exposed '{}' to Context B (approved_by_source: {})",
        interface.outlet_id, interface.approved_by_source,
    );

    // -----------------------------------------------------------------------
    // 5. Create and publish the InterfaceOffer (section 6.2.0.1 step 3)
    // -----------------------------------------------------------------------

    let outlet_reg = registry_a
        .get(&outlet_id)
        .ok_or("outlet not found in registry")?;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_millis() as u64;
    let offer = create_interface_offer(&interface, outlet_reg, now_ms);
    println!(
        "Published InterfaceOffer (expires in 7 days, offer_id: {:02x}{:02x}...)",
        offer.offer_id[0], offer.offer_id[1],
    );

    // -----------------------------------------------------------------------
    // 6. Context B accepts the interface (section 6.2.0.1 step 4)
    // -----------------------------------------------------------------------

    let inbound_policy = InboundPolicy {
        allowed_source_roles: vec![], // any role
        max_calls_per_minute: 60,
        max_response_bytes: 65_536,
        require_spending_ucan: false,
    };

    accept_tool_interface(
        ctx_b.context_id(),
        &mut interface,
        &role_state_b,
        &operator_did,
        Some(inbound_policy),
    )
    .map_err(|e| e.to_string())?;

    println!(
        "Context B accepted interface (approved_by_target: {})",
        interface.approved_by_target,
    );

    // -----------------------------------------------------------------------
    // 7. The target context also needs the tool in its registry for
    //    invoke_cross_context to verify the tool exists on the target side.
    //    In a real deployment the offer carries the tool schema, which the
    //    target context registers locally on acceptance.
    // -----------------------------------------------------------------------

    let mut registry_b = OutletRegistry::new();
    let target_registration = OutletRegistration {
        outlet_id: "translator".to_owned(),
        kind: OutletKind::Action,
        name: "Translator".to_owned(),
        description: "Translates text between languages".to_owned(),
        schema: OutletSchema::new(
            serde_json::json!({
                "type": "object",
                "properties": {
                    "text": { "type": "string" },
                    "target_language": { "type": "string" }
                },
                "required": ["text", "target_language"]
            }),
            serde_json::json!({
                "type": "object",
                "properties": {
                    "translated": { "type": "string" },
                    "source_language": { "type": "string" }
                },
                "required": ["translated", "source_language"]
            }),
        ),
        implementation_hash: [0xBB; 32],
        test_vectors: vec![],
        operator_did: operator_did.clone(),
        cost: None,
        message_catalog: vec![],
        registered_at: 0,
        signature: Vec::new(),
    };
    register_outlet(
        &mut registry_b,
        &role_state_b,
        target_registration,
        &operator_did,
    )
    .map_err(|e| e.to_string())?;

    // -----------------------------------------------------------------------
    // 8. Invoke the tool across contexts (section 6.2)
    // -----------------------------------------------------------------------

    let input = serde_json::json!({
        "text": "Hello, world!",
        "target_language": "es"
    });
    println!("\nInvoking cross-context tool with: {input}");

    // The executor simulates the tool's implementation in Context A.
    // In production the bridge operator's SDK routes this through their
    // local membership in Context A (shared-member bridging, section 6.2.0).
    let executor = |input: &serde_json::Value| -> Result<serde_json::Value, String> {
        let text = input["text"]
            .as_str()
            .ok_or_else(|| "missing 'text'".to_owned())?;
        let target = input["target_language"]
            .as_str()
            .ok_or_else(|| "missing 'target_language'".to_owned())?;
        // Simulated translation.
        let translated = match target {
            "es" => format!("Hola, mundo! (translated from: {text})"),
            "fr" => format!("Bonjour le monde! (translated from: {text})"),
            _ => format!("[{target}] {text}"),
        };
        Ok(serde_json::json!({
            "translated": translated,
            "source_language": "en"
        }))
    };

    // Provenance metadata for the source context (section 24). Attached to
    // every cross-context invocation so the target can evaluate source quality.
    let source_context_info = SourceContextInfo {
        context_id: ctx_a.context_id().to_owned(),
        source_type: SourceType::Persistent,
        memory_scope: MemoryScope::Full,
        members: vec![operator_did.clone()],
        discovery_method: DiscoveryMethod::OutOfBand,
        data_age: Duration::from_secs(0),
        purpose: Some("cross-context translation".to_owned()),
        counterparty_policy: CounterpartyPolicy::Full,
    };

    let (output, source_event, target_event) = invoke_cross_context(
        ctx_a.context_id(),
        None, // source_max_chain_depth: use protocol default (ADR-043)
        &mut interface,
        &input,
        &operator_did,
        &role_state_a,
        &registry_b,
        0, // chain_depth: first hop
        executor,
        &scp_clock::SystemClock,
        &source_context_info,
    )
    .map_err(|e| e.to_string())?;

    println!("  Result: {output}");
    println!("\n--- Event log entries ---");
    println!(
        "  Source event (Context A): request_id={}, status={:?}",
        source_event.request_id, source_event.status,
    );
    println!(
        "  Target event (Context B): request_id={}, status={:?}",
        target_event.request_id, target_event.status,
    );
    println!(
        "  Both events share the same request_id: {}",
        source_event.request_id == target_event.request_id,
    );

    // -----------------------------------------------------------------------
    // 9. Demonstrate chain depth enforcement (section 6.2, section 24.4)
    // -----------------------------------------------------------------------

    println!("\n--- Chain depth enforcement ---");
    // Default max chain depth is 8 (ADR-043). Context-configurable, no protocol ceiling.
    // Attempting chain_depth=9 should fail with the default configuration.
    let deep_result = invoke_cross_context(
        ctx_a.context_id(),
        None, // source_max_chain_depth: use protocol default (ADR-043)
        &mut interface,
        &input,
        &operator_did,
        &role_state_a,
        &registry_b,
        9, // chain_depth: exceeds default max of 8 (ADR-043)
        |_| Ok(serde_json::json!({})),
        &scp_clock::SystemClock,
        &source_context_info,
    );
    match deep_result {
        Err(e) => println!("  Chain depth 9 rejected: {e}"),
        Ok(_) => println!("  Chain depth 9 accepted (max_chain_depth may be configured higher)"),
    }

    println!("\nCross-context bridge complete.");
    Ok(())
}
