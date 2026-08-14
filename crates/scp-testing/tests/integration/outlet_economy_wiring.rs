#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::too_many_lines
)]

//! C4 (#1606) — outlet-invoke economy wiring integration test.
//!
//! Verifies that `Supervisor::invoke_outlet_with_economy` — the SINGLE
//! non-streaming managed outlet-invoke entry all 3 FFI bridges route through —
//! actually deducts per-invocation cost from the per-DID budget tracker,
//! increments the per-DID velocity counter, returns the executor output, and
//! produces an `OutletInvokedEvent` carrying the deducted cost.
//!
//! Before C4 the bridges bypassed this method entirely and outlets cost ZERO
//! from a Python/Node/Swift/Kotlin client's perspective regardless of
//! `EconomicPolicy`. The `pipeline_wiring` assertions cover the structural fact
//! that the bridge outlet-invoke functions now CALL this method; this test
//! covers the runtime semantics that their delegations inherit.
//!
//! ## ADR-049 note — post-actor-per-context rewiring
//!
//! The old `ContextManager` type + its `ContextCryptoProvider` mock and the
//! `grant_budget_for_test` / `remaining_budget_for_test` / `velocity_for_test`
//! manager hooks were deleted in ADR-049. This test now drives the actor-model
//! `Supervisor` directly:
//! * The context host is a real `Supervisor` built from a concrete
//!   `NodeMlsFactory` (no mock crypto) via `Supervisor::with_providers`, with a
//!   clock (required by `invoke_outlet_with_economy`) and NO payment adapter
//!   (so a funded invocation produces no `PaymentReceipt`).
//! * Budget is granted the real way — a governance `ApproveSpend` action, which
//!   auto-executes for the SingleAdmin creator — because no out-of-crate budget
//!   test hook exists.
//! * Budget / velocity are read back through the public `dispatch_query`
//!   mailbox commands `RemainingBudgetForTest` / `VelocityForTest`.
//! * The budget-rejection test passes a VALIDLY-SIGNED spending UCAN: signature
//!   validation now runs BEFORE the budget gate, so an empty-signature token
//!   would fail with a different (signature) error rather than reaching the
//!   budget gate — which surfaces as `SCP-OUTLET-6150 economic.budget-exceeded`
//!   (the canonical economic-class outlet code the caller observes).

use std::sync::Arc;

use scp_core::context::builder::{
    ContextCreationError, ContextEventLogProvider, ContextTransportProvider,
};
use scp_core::context::governance::{GovernanceAction, KeyResolver};
use scp_core::context::outlets::OutletId;
use scp_core::context::outlets::registry::{
    OutletRegistration, OutletRegistry, OutletSchema, OutletTestVector,
};
use scp_core::context::supervisor::Supervisor;
use scp_core::context::{Capability, ContextParams, LocalTransportProvider};
use scp_core::crypto::mls::provider::NodeMlsFactory;
use scp_core::crypto::mls::storage_adapter::{OpenMlsStorageAdapter, SpawnBlockingStorageAdapter};
use scp_core::economy::{Amount, CostSchedule, CurrencyCode, EconomicPolicy};
use scp_did::DID;
use scp_platform::in_memory::InMemoryStorage;
use scp_runtime::context::actor::commands::QueriesCommand;

// ---------------------------------------------------------------------------
// Host construction — a real `Supervisor` over a concrete `NodeMlsFactory`.
// ---------------------------------------------------------------------------

/// No-op event-log provider (mirrors `saga_bridge_bootstrap.rs`).
struct NoOpEventLog;
// `unused_async`: these no-op test-double methods have no await, but the
// ADR-049 Decision-7 async `ContextEventLogProvider` trait requires the
// `async fn` signature.
#[async_trait::async_trait]
#[allow(clippy::unused_async)]
impl ContextEventLogProvider for NoOpEventLog {
    async fn init_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn append_event(
        &self,
        _: &[u8; 32],
        _: scp_event_log::EventType,
        _: &str,
        _: scp_event_log::EventPayload,
        _timestamp_secs: u64,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn destroy_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
}

fn test_mls_storage() -> Arc<dyn OpenMlsStorageAdapter> {
    Arc::new(SpawnBlockingStorageAdapter::new(Arc::new(
        InMemoryStorage::new(),
    )))
}

/// Builds a real `Supervisor` with a concrete `NodeMlsFactory`, a clock (the
/// `invoke_outlet_with_economy` path requires one), and NO payment adapter so a
/// funded invocation yields no `PaymentReceipt`.
fn build_supervisor(creator_did: &str, key_resolver: KeyResolver) -> Arc<Supervisor> {
    Supervisor::with_providers(
        Arc::new(NodeMlsFactory::new(
            creator_did.to_owned(),
            Arc::new(scp_clock::SystemClock),
        )),
        Box::new(LocalTransportProvider) as Box<dyn ContextTransportProvider>,
        Box::new(NoOpEventLog) as Box<dyn ContextEventLogProvider>,
        key_resolver,
        None,                                   // persistence
        None,                                   // payment_adapter -> no PaymentReceipt
        None,                                   // event_tx
        Some(Arc::new(scp_clock::SystemClock)), // clock (required by invoke_outlet_with_economy)
        test_mls_storage(),
    )
}

// ---------------------------------------------------------------------------
// Budget / velocity accessors — the public `dispatch_query` mailbox commands.
// ---------------------------------------------------------------------------

async fn remaining_budget(sup: &Arc<Supervisor>, context_id: &str, did: &DID) -> Amount {
    let (tx, rx) = tokio::sync::oneshot::channel();
    sup.dispatch_query(QueriesCommand::RemainingBudgetForTest {
        context_id: context_id.to_owned(),
        member_did: did.clone(),
        reply: tx,
    })
    .await
    .expect("dispatch RemainingBudgetForTest");
    rx.await.expect("budget reply").expect("budget ok")
}

async fn velocity(sup: &Arc<Supervisor>, context_id: &str, did: &DID, now_secs: u64) -> u64 {
    let (tx, rx) = tokio::sync::oneshot::channel();
    sup.dispatch_query(QueriesCommand::VelocityForTest {
        context_id: context_id.to_owned(),
        member_did: did.clone(),
        now_secs,
        reply: tx,
    })
    .await
    .expect("dispatch VelocityForTest");
    rx.await.expect("velocity reply").expect("velocity ok")
}

/// Grants `amount` of per-DID budget to `spender` through a governance
/// `ApproveSpend` action, signed by the admin. Under the default SingleAdmin
/// governance the creator/admin's proposal auto-approves and EXECUTES, so the
/// grant lands in the actor's budget tracker — the real path a client uses
/// (there is no out-of-crate budget test hook).
async fn grant_budget(
    sup: &Arc<Supervisor>,
    context_id: &str,
    admin: &DID,
    admin_key: &ed25519_dalek::SigningKey,
    spender: &DID,
    amount: Amount,
) {
    let (_proposal, _events, execution) = sup
        .propose_governance_action(
            context_id,
            admin,
            GovernanceAction::ApproveSpend {
                spender: spender.clone(),
                amount,
                purpose: "outlet-economy wiring test budget".to_owned(),
            },
            admin_key,
        )
        .await
        .expect("ApproveSpend proposal");
    assert!(
        execution.is_some(),
        "SingleAdmin ApproveSpend by the admin must auto-execute"
    );
}

// ---------------------------------------------------------------------------
// Deterministic key material — one Ed25519 key per DID so `mock_key_resolver`
// resolves the same verifying key a governance proposal / spending UCAN is
// signed under.
// ---------------------------------------------------------------------------

/// Derives a deterministic Ed25519 seed from a DID string by XOR-folding the
/// DID bytes into a 32-byte array.
fn did_to_seed(did: &DID) -> [u8; 32] {
    let mut s = [0u8; 32];
    let bytes = did.as_ref().as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        s[i % 32] ^= *b;
    }
    s
}

/// Key resolver that returns the deterministic verifying key derived from the
/// DID string — used for both governance-proposal signature validation and
/// spending-UCAN signature validation.
fn mock_key_resolver() -> KeyResolver {
    Arc::new(|did: &DID, _kid: scp_did::SigningKeyId| {
        Some(ed25519_dalek::SigningKey::from_bytes(&did_to_seed(did)).verifying_key())
    })
}

/// The signing key `mock_key_resolver` resolves for `did`.
fn signing_key_for_did(did: &DID) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&did_to_seed(did))
}

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

fn governance_params_with_outlets() -> ContextParams {
    ContextParams {
        ceiling: vec![
            Capability::new("messages:read").expect("known capability"),
            Capability::new("messages:write").expect("known capability"),
            Capability::new("role:assign").expect("known capability"),
            Capability::new("governance:propose").expect("known capability"),
            Capability::new("governance:vote").expect("known capability"),
            Capability::new("member:ban").expect("known capability"),
            Capability::new("context:close").expect("known capability"),
            Capability::OutletRegister,
            Capability::OutletCallAll,
        ],
        ..ContextParams::default()
    }
}

fn priced_policy(per_outlet_call: u64) -> EconomicPolicy {
    EconomicPolicy {
        locked: false,
        cost_schedule: CostSchedule {
            currency: CurrencyCode::from("USD"),
            per_message: Some(Amount::new(1)),
            per_outlet_call: Some(Amount::new(per_outlet_call)),
            per_join: Some(Amount::new(1)),
            per_period: None,
            per_byte_stored: None,
        },
        payment_adapters: vec![],
        pricing_formula: None,
        payee: DID::from("did:key:test-payee"),
    }
}

fn echo_outlet() -> OutletRegistration {
    OutletRegistration {
        outlet_id: "echo".to_owned(),
        kind: scp_core::context::outlets::OutletKind::default(),
        name: "echo".to_owned(),
        description: "echo outlet for C4 wiring test".to_owned(),
        schema: OutletSchema {
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "object"}),
            aggregate_schema: None,
        },
        implementation_hash: [0u8; 32],
        test_vectors: vec![OutletTestVector {
            input: serde_json::json!({}),
            expected_output: serde_json::json!({}),
            description: "noop".to_owned(),
        }],
        operator_did: DID::from("did:key:test-operator"),
        cost: None,
        message_catalog: Vec::new(),
        registered_at: 0,
        signature: Vec::new(),
    }
}

/// Builds a fully-signed `UcanToken` bound to `actor_did` that exercises the
/// complete C1b validation pipeline (signature, iss/aud binding, expiry,
/// nonce). Signed with the deterministic Ed25519 key `mock_key_resolver`
/// resolves for the same DID.
fn signed_spending_ucan_for(actor_did: &DID) -> scp_core::crypto::ucan::UcanToken {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use scp_core::crypto::ucan::spending::{
        Amount as SpendAmount, CurrencyCode as SpendCurrency, SpendingCapability,
    };
    use scp_core::crypto::ucan::{
        Attenuation, UcanHeader, UcanPayload, UcanToken, nonce::generate_nonce,
    };

    let cap = SpendingCapability {
        max_per_action: SpendAmount(u64::MAX),
        max_total: SpendAmount(u64::MAX),
        currency: SpendCurrency::from_code("USD").unwrap_or(SpendCurrency(*b"USD\0")),
        time_window: std::time::Duration::from_hours(1),
        allowed_adapters: vec![],
    };
    let mut fct = serde_json::Map::new();
    fct.insert(
        "spending_capability".to_owned(),
        cap.to_fact_value().unwrap_or(serde_json::Value::Null),
    );
    fct.insert(
        "scp_key_scope".to_owned(),
        serde_json::Value::String("#agent".to_owned()),
    );

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let header = UcanHeader::with_kid("#agent".to_owned());
    let payload = UcanPayload {
        iss: actor_did.as_ref().to_owned(),
        aud: actor_did.as_ref().to_owned(),
        exp: now + 3600,
        nbf: Some(now.saturating_sub(60)),
        nnc: generate_nonce(&scp_clock::SystemClock),
        att: vec![Attenuation {
            with: "scp:spending:*".to_owned(),
            can: "spend".to_owned(),
        }],
        prf: vec![],
        fct: Some(serde_json::Value::Object(fct)),
        nb: None,
    };

    let header_json = serde_json::to_vec(&header).expect("header serializes");
    let payload_json = serde_json::to_vec(&payload).expect("payload serializes");
    let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
    let signing_input = format!("{header_b64}.{payload_b64}");

    let signing_key = signing_key_for_did(actor_did);
    let signature = ed25519_dalek::Signer::sign(&signing_key, signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    let encoded = format!("{signing_input}.{sig_b64}");

    UcanToken {
        header,
        payload,
        signature: signature.to_bytes().to_vec(),
        encoded,
    }
}

// ---------------------------------------------------------------------------
// Test 1: invoke_outlet_with_economy deducts budget and records velocity.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invoke_outlet_with_economy_deducts_budget_and_records_velocity() {
    // The invoker is also the context creator/admin, so it inherits the full
    // ceiling (including OutletCallAll) — the reserve-phase authorization gate
    // clears — and can grant itself budget via SingleAdmin ApproveSpend.
    let invoker = DID::from("did:dht:z6MkOutletEconomyInvoker");
    let sup = build_supervisor(invoker.as_ref(), mock_key_resolver());
    sup.register_local_did(invoker.clone()).await.unwrap();

    let context_id = "ctx-c4-outlet-economy";
    let mut params = governance_params_with_outlets();
    params.economic_policy = Some(priced_policy(7));
    sup.create_context(context_id.to_owned(), params, invoker.clone(), None)
        .await
        .expect("create_context");

    // Grant the invoker a 1000 USD budget via governance ApproveSpend.
    let admin_key = signing_key_for_did(&invoker);
    grant_budget(
        &sup,
        context_id,
        &invoker,
        &admin_key,
        &invoker,
        Amount::new(1_000),
    )
    .await;

    let mut registry = OutletRegistry::new();
    registry.insert(echo_outlet());

    // Fully signed UCAN bound to the invoker, matching mock_key_resolver.
    let spending_ucan = signed_spending_ucan_for(&invoker);

    // Snapshot pre-call state. The baseline velocity is read with a pre-call
    // anchor; the "after" read (below) re-anchors AFTER the invocation so the
    // 60s sliding window is guaranteed to cover the entry the call records even
    // if the invocation crossed a wall-clock second boundary — otherwise a stale
    // pre-call anchor could flake the comparison.
    let budget_before = remaining_budget(&sup, context_id, &invoker).await;
    let now_secs_before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let velocity_before = velocity(&sup, context_id, &invoker, now_secs_before).await;

    // THE CRITICAL CALL — exactly the path the 3 FFI bridges route through.
    let outcome = sup
        .invoke_outlet_with_economy(
            context_id,
            &registry,
            &OutletId::from("echo"),
            serde_json::json!({"hello": "world"}),
            &invoker,
            Some(&spending_ucan),
            None,
            None,
            |input: serde_json::Value| async move {
                Ok::<serde_json::Value, String>(serde_json::json!({"echoed": input}))
            },
        )
        .await
        .expect("invoke_outlet_with_economy must succeed for a funded paid outlet");

    // The executor ran and produced the expected output.
    assert_eq!(
        outcome.output,
        serde_json::json!({"echoed": {"hello": "world"}}),
        "executor output must round-trip through the managed invoke"
    );

    // The budget was deducted by EXACTLY the policy cost.
    let budget_after = remaining_budget(&sup, context_id, &invoker).await;
    assert_eq!(
        budget_before.value() - budget_after.value(),
        7,
        "invoke_outlet_with_economy must deduct the per_outlet_call cost (7) from the per-DID budget — \
         got {} -> {}",
        budget_before.value(),
        budget_after.value()
    );

    // Velocity was recorded. Re-anchor AFTER the call so the sliding window
    // covers the just-recorded entry regardless of second-boundary timing.
    let now_secs_after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let velocity_after = velocity(&sup, context_id, &invoker, now_secs_after).await;
    // `velocity_before` is provably 0: the only prior action was the governance
    // `grant_budget` (ApproveSpend), which records no velocity entry. Assert the
    // EXACT +1 so a "2 entries per call" regression is caught, not just >.
    assert_eq!(
        velocity_after,
        velocity_before + 1,
        "invoke_outlet_with_economy must record EXACTLY one velocity entry per call \
         (before={velocity_before}, after={velocity_after})"
    );

    // The OutletInvokedEvent carries the deducted cost, outlet, and invoker.
    assert_eq!(
        outcome.event.cost.map(Amount::value),
        Some(7),
        "OutletInvokedEvent.cost must reflect the deducted per-invocation cost"
    );
    assert_eq!(
        outcome.event.outlet_id, "echo",
        "OutletInvokedEvent.outlet_id must match the invoked outlet"
    );
    assert_eq!(
        outcome.event.invoker_did, invoker,
        "OutletInvokedEvent.invoker_did must match the invoker"
    );

    // No payment adapter configured -> escrow capture is skipped.
    assert!(
        outcome.payment_receipt.is_none(),
        "no PaymentAdapter configured -> no PaymentReceipt expected"
    );
}

// ---------------------------------------------------------------------------
// Test 2: invoke_outlet_with_economy rejects insufficient budget.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invoke_outlet_with_economy_rejects_insufficient_budget() {
    let invoker = DID::from("did:dht:z6MkOutletEconomyBroke");
    let sup = build_supervisor(invoker.as_ref(), mock_key_resolver());
    sup.register_local_did(invoker.clone()).await.unwrap();

    let context_id = "ctx-c4-budget-rejected";
    let mut params = governance_params_with_outlets();
    // Price the outlet above any granted budget.
    params.economic_policy = Some(priced_policy(100));
    sup.create_context(context_id.to_owned(), params, invoker.clone(), None)
        .await
        .expect("create_context");

    // Grant ZERO budget — the per-DID budget tracker has no entry for the
    // invoker, so `has_budget` returns false and the pre-check must reject.
    let mut registry = OutletRegistry::new();
    registry.insert(echo_outlet());

    // A validly-signed UCAN: signature validation now runs BEFORE the budget
    // gate, so the rejection we assert is genuinely the budget gate, not a
    // signature failure.
    let spending_ucan = signed_spending_ucan_for(&invoker);

    let result = sup
        .invoke_outlet_with_economy(
            context_id,
            &registry,
            &OutletId::from("echo"),
            serde_json::json!({}),
            &invoker,
            Some(&spending_ucan),
            None,
            None,
            |_input: serde_json::Value| async move {
                panic!("executor must NOT run when the pre-check rejects on budget")
            },
        )
        .await;

    let err = result.expect_err("expected budget-exceeded rejection");
    let msg = format!("{err}");
    // `invoke_outlet_with_economy` surfaces `InvocationError::BudgetExceeded`,
    // which maps to the canonical economic-class outlet code `SCP-OUTLET-6150`
    // with the discriminating slug `economic.budget-exceeded`. Assert BOTH: the
    // code pins the error class and the slug pins the specific economic fault,
    // so a regression to a non-economic error OR to a different economic
    // sub-fault (e.g. insufficient-funds) is caught. (The inner `SCP-ECON-12010`
    // "no budget" string is remapped and never surfaces here.)
    assert!(
        msg.contains("SCP-OUTLET-6150") && msg.contains("economic.budget-exceeded"),
        "expected SCP-OUTLET-6150 economic.budget-exceeded error, got: {msg}"
    );

    // The velocity entry recorded during Phase-1 reserve must have been rolled
    // back by the budget rejection.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let v = velocity(&sup, context_id, &invoker, now_secs).await;
    assert_eq!(
        v, 0,
        "Phase-1 budget rejection must roll back the velocity entry — got {v}"
    );
}
