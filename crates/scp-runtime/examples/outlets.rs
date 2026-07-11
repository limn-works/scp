//! Outlet registration and invocation within a context.
//!
//! Demonstrates registering a outlet with a JSON schema, checking
//! capabilities, and invoking the outlet with input validation.
//!
//! Usage:
//!   `cargo run -p scp-runtime --features testing --example outlets`

use scp_did::DID;
use scp_protocol::context::outlets::lifecycle::OutletStatus;
use scp_protocol::context::outlets::registry::{
    OutletRegistration, OutletRegistry, OutletSchema, register_outlet,
};
use scp_protocol::context::roles::{Capability, CapabilityCeiling, ContextRoleState};
use scp_protocol::context::{ContextParams, ContextState};
use scp_runtime::context::ContextHandle;
use scp_runtime::context::outlets::invoke::invoke_outlet;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let creator: DID = "did:dht:z6MkCreator".into();

    // 1. Set up a context handle in Active state.
    let handle = ContextHandle::new("outlet-demo".to_owned(), ContextParams::default());
    handle.transition_to(&ContextState::Active)?;

    // 2. Build role state with outlet capabilities in the ceiling.
    let ceiling = CapabilityCeiling::new([
        Capability::OutletRegister,
        Capability::OutletCallAll,
        Capability::MessagesRead,
        Capability::MessagesWrite,
    ]);
    let role_state = ContextRoleState::new(
        "outlet-demo",
        &*creator,
        ceiling,
        vec![],
        &scp_clock::SystemClock,
    )
    .map_err(|e| e.to_string())?;

    // 3. Create a outlet registry and register a calculator outlet.
    let mut registry = OutletRegistry::new();
    let registration = OutletRegistration {
        outlet_id: "calculator".to_owned(),
        kind: scp_protocol::context::outlets::OutletKind::default(),
        name: "Calculator".to_owned(),
        description: "A simple arithmetic calculator".to_owned(),
        schema: OutletSchema {
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "a": {"type": "number"},
                    "b": {"type": "number"},
                    "op": {"type": "string", "enum": ["add", "sub", "mul"]}
                },
                "required": ["a", "b", "op"]
            }),
            output_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "result": {"type": "number"}
                },
                "required": ["result"]
            }),
            aggregate_schema: None,
        },
        implementation_hash: [0xAA; 32],
        test_vectors: vec![],
        operator_did: creator.clone(),
        cost: None,
        message_catalog: Vec::new(),
        registered_at: 0,
        signature: Vec::new(),
    };

    let (outlet_id, event) = register_outlet(&mut registry, &role_state, registration, &creator)
        .map_err(|e| e.to_string())?;
    println!("Registered outlet: {outlet_id}");
    println!("  Event: {}", event.outlet_id);

    // 4. List registered outlets.
    let outlets: Vec<_> = registry.registrations().collect();
    println!("  Outlets in registry: {}", outlets.len());
    for outlet in &outlets {
        println!("    - {} ({})", outlet.name, outlet.outlet_id);
    }

    // 5. Define an executor function.
    let executor = |input: serde_json::Value| async move {
        let a = input["a"]
            .as_f64()
            .ok_or_else(|| "missing 'a'".to_owned())?;
        let b = input["b"]
            .as_f64()
            .ok_or_else(|| "missing 'b'".to_owned())?;
        let op = input["op"]
            .as_str()
            .ok_or_else(|| "missing 'op'".to_owned())?;
        let result = match op {
            "add" => a + b,
            "sub" => a - b,
            "mul" => a * b,
            _ => return Err(format!("unknown op: {op}")),
        };
        Ok(serde_json::json!({"result": result}))
    };

    // 6. Invoke the outlet.
    let input = serde_json::json!({"a": 7, "b": 3, "op": "mul"});
    println!("\nInvoking calculator with: {input}");

    let (output, invoke_event, _consequences, _receipt) = invoke_outlet(
        &handle,
        &registry,
        &role_state,
        &"calculator".to_owned(),
        input,
        &creator,
        None, // default timeout
        executor,
        None::<&mut scp_runtime::context::outlets::invoke::OutletEconomyContext<'_>>,
    )
    .await
    .map_err(|e| e.to_string())?;

    println!("  Result: {output}");
    println!("  Status: {:?}", invoke_event.status);
    assert_eq!(invoke_event.status, OutletStatus::Success);
    assert_eq!(output["result"], 21.0);
    println!("\nOutlet invocation complete.");

    Ok(())
}
