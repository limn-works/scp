// ADR-049 commit 12c.9e: ContextCryptoProvider trait deleted. MockCrypto
// here reimplements that trait for unit-test coverage of outlet economy
// wiring. Rewiring to real `MlsCryptoProvider` requires backend injection
// (12c.9f). File gated until then.
#![cfg(any())]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::too_many_lines
)]

//! C4 (#1606) — Bridge outlet-invoke economy wiring integration test.
//!
//! Verifies that `ContextManager::invoke_outlet_with_economy` — the SINGLE
//! entry point all 3 FFI bridges (PyO3, NAPI, UniFFI) now route
//! through after the C4 fix — actually deducts per-invocation cost from
//! the per-DID budget tracker, increments the per-DID velocity counter,
//! returns the executor output, and produces a `OutletInvokedEvent` with
//! the correct cost.
//!
//! Before C4 the bridges bypassed this method entirely and outlets cost
//! ZERO from a Python/Node/Swift/Kotlin client's perspective regardless
//! of `EconomicPolicy`. The pipeline_wiring assertions cover the
//! structural fact that the bridge outlet-invoke functions now CALL
//! `invoke_outlet_with_economy`; this test covers the runtime semantics
//! that the bridges' delegations now inherit.
//!
//! The mock providers below mirror the pattern used in
//! `e2e_context_manager.rs` and `messaging.rs`'s in-crate tests. Each
//! integration test file is a separate compile unit so the mocks have
//! to live here rather than in a shared module.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use scp_core::context::builder::{
    ContextCreationError, ContextCryptoProvider, ContextEventLogProvider, ContextTransportProvider,
};
use scp_core::context::governance::KeyResolver;
use scp_core::context::manager::ContextManager;
use scp_core::context::outlets::OutletId;
use scp_core::context::outlets::registry::{
    OutletRegistration, OutletRegistry, OutletSchema, OutletTestVector,
};
use scp_core::context::{
    AddMemberOutput, Capability, ContextError, ContextParams, RemoveMemberOutput,
};
use scp_core::economy::{Amount, CostSchedule, CurrencyCode, EconomicPolicy};
use scp_did::DID;

// ---------------------------------------------------------------------------
// Mock providers — minimal implementations for ContextManager construction.
// Mirror `crates/scp-testing/tests/integration/e2e_context_manager.rs`.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockCrypto;

impl ContextCryptoProvider for MockCrypto {
    fn validate_creator_identity(&self) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn create_mls_group(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn generate_sender_key(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn init_broadcast_key(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn destroy_mls_group(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn destroy_sender_key(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn validate_key_package(
        &self,
        _owner_did: &str,
        _key_package_bytes: Option<&[u8]>,
    ) -> Result<(), ContextError> {
        Ok(())
    }
    fn add_member(
        &self,
        _ctx_id: &[u8; 32],
        _member_did: &str,
        _key_package_bytes: Option<&[u8]>,
    ) -> Result<AddMemberOutput, ContextError> {
        Ok(AddMemberOutput::default())
    }
    fn remove_member(
        &self,
        _ctx_id: &[u8; 32],
        _member_did: &str,
    ) -> Result<RemoveMemberOutput, ContextError> {
        Ok(RemoveMemberOutput::default())
    }
    fn distribute_sender_key(
        &self,
        _ctx_id: &[u8; 32],
        _member_did: &str,
    ) -> Result<(), ContextError> {
        Ok(())
    }
    fn remove_member_sender_key(
        &self,
        _ctx_id: &[u8; 32],
        _member_did: &str,
    ) -> Result<(), ContextError> {
        Ok(())
    }
    fn seal(
        &self,
        _context_id: &[u8; 32],
        inner: &scp_core::envelope::inner::InnerEnvelope,
        _routing_id: &[u8],
        _blob_ttl: u32,
    ) -> Result<Vec<u8>, ContextError> {
        rmp_serde::to_vec_named(inner)
            .map_err(|e| ContextError::CryptoFailed(format!("mock seal: {e}")))
    }
    fn open(
        &self,
        _context_id: &[u8; 32],
        outer_bytes: &[u8],
    ) -> Result<scp_core::context::builder::OpenResult, ContextError> {
        let inner: scp_core::envelope::inner::InnerEnvelope = rmp_serde::from_slice(outer_bytes)
            .map_err(|e| ContextError::CryptoFailed(format!("mock open: {e}")))?;
        let sender_did = inner.sender_did.clone();
        Ok(scp_core::context::builder::OpenResult::Application(
            Box::new(scp_core::context::builder::OpenedEnvelope { inner, sender_did }),
        ))
    }
}

#[derive(Default)]
struct MockTransport {
    connected: AtomicBool,
}

impl MockTransport {
    fn connected() -> Self {
        let t = Self::default();
        t.connected.store(true, Ordering::Relaxed);
        t
    }
}

#[async_trait::async_trait]
impl ContextTransportProvider for MockTransport {
    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }
    async fn publish_context(
        &self,
        _id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn delete_published(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn send_message(
        &self,
        _ctx_id: &[u8; 32],
        _encrypted_payload: &[u8],
    ) -> Result<(), ContextError> {
        Ok(())
    }
}

#[derive(Default)]
struct MockEventLog {
    events: Mutex<Vec<([u8; 32], String)>>,
}

// `unused_async`: `init_event_log` / `destroy_event_log` have no await because
// they are no-op test doubles, but the ADR-049 Decision-7 async
// `ContextEventLogProvider` trait requires the `async fn` signature.
#[async_trait::async_trait]
#[allow(clippy::unused_async)]
impl ContextEventLogProvider for MockEventLog {
    async fn init_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn append_event(
        &self,
        id: &[u8; 32],
        event_type: scp_event_log::EventType,
        _actor_did: &str,
        _payload: scp_event_log::EventPayload,
        _timestamp_secs: u64,
    ) -> Result<(), ContextCreationError> {
        self.events
            .lock()
            .unwrap()
            .push((*id, format!("{event_type:?}")));
        Ok(())
    }
    async fn destroy_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
}

fn noop_key_resolver() -> KeyResolver {
    std::sync::Arc::new(|_did: &DID, _kid: scp_did::SigningKeyId| None)
}

/// Derives a deterministic Ed25519 seed from a DID string by XOR-folding
/// the DID bytes into a 32-byte array. Matches the algorithm used by
/// the in-crate `mock_key_resolver` so signing and verification are consistent.
fn did_to_seed(did: &DID) -> [u8; 32] {
    let mut s = [0u8; 32];
    let bytes = did.as_ref().as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        s[i % 32] ^= *b;
    }
    s
}

/// Mock key resolver that returns a deterministic verifying key derived from
/// the DID string. Used by happy-path tests that need real signature verification.
fn mock_key_resolver() -> KeyResolver {
    std::sync::Arc::new(|did, _kid: scp_did::SigningKeyId| {
        let seed = did_to_seed(did);
        Some(ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key())
    })
}

/// Returns the signing key corresponding to what `mock_key_resolver` resolves
/// for the given DID. Used to produce tokens that pass end-to-end validation.
fn signing_key_for_did(did: &DID) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&did_to_seed(did))
}

// ---------------------------------------------------------------------------
// Helpers — fixture builders.
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

/// Build a `UcanToken` carrying a `SpendingCapability` that comfortably
/// covers any per-action cost the test will exercise. The signature
/// field is empty because `economy_pre_check` only consults
/// `payload.fct.spending_capability` for the AND-composition check.
///
/// Suitable ONLY for tests that assert rejection (budget exceeded, etc.)
/// where the rejection happens before C1b signature validation. For happy-path
/// invocations that must pass the full C1b pipeline, use `signed_spending_ucan_for`.
fn dummy_spending_ucan() -> scp_core::crypto::ucan::UcanToken {
    use scp_core::crypto::ucan::spending::{
        Amount as SpendAmount, CurrencyCode as SpendCurrency, SpendingCapability,
    };
    use scp_core::crypto::ucan::{
        Attenuation, UcanHeader, UcanPayload, UcanToken, nonce::generate_nonce,
    };

    let cap = SpendingCapability {
        max_per_action: SpendAmount(1_000),
        max_total: SpendAmount(10_000),
        currency: SpendCurrency::from_code("USD").unwrap_or(SpendCurrency(*b"USD\0")),
        time_window: std::time::Duration::from_hours(1),
        allowed_adapters: vec![],
    };
    let mut fct = serde_json::Map::new();
    fct.insert(
        "spending_capability".to_owned(),
        cap.to_fact_value().unwrap_or(serde_json::Value::Null),
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    UcanToken {
        header: UcanHeader::new(),
        payload: UcanPayload {
            iss: "did:key:invoker".to_owned(),
            aud: "did:key:test-context".to_owned(),
            exp: now + 3600,
            nbf: Some(now),
            nnc: generate_nonce(&scp_clock::SystemClock),
            att: vec![Attenuation {
                with: "scp:spending:*".to_owned(),
                can: "spend".to_owned(),
            }],
            prf: vec![],
            fct: Some(serde_json::Value::Object(fct)),
            nb: None,
        },
        signature: vec![],
        encoded: "test.spending.ucan".to_owned(),
    }
}

/// Build a fully-signed `UcanToken` bound to `actor_did` for happy-path tests
/// that exercise the complete C1b validation pipeline (signature, iss/aud
/// binding, expiry, nonce). The token is signed with the deterministic Ed25519
/// key produced by `signing_key_for_did`, which `mock_key_resolver` resolves for
/// the same DID.
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
// Test 1: invoke_outlet_with_economy deducts budget and records velocity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invoke_outlet_with_economy_deducts_budget_and_records_velocity() {
    // C1b: happy-path invocations now require a fully signed spending UCAN
    // bound to the invoker DID. Use mock_key_resolver so validate_spending_ucan_signed
    // can resolve the verifying key, and signed_spending_ucan_for to produce a
    // token signed by the matching private key.
    // ADR-049 commit 12c.9c — wrap with `attach_test_supervisor`.
    let manager = scp_core::context::attach_test_supervisor(ContextManager::new(
        Box::new(MockCrypto),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    ));

    let invoker = DID::from("did:key:invoker");
    let context_id = "ctx-c4-outlet-economy".to_owned();
    let mut params = governance_params_with_outlets();
    params.economic_policy = Some(priced_policy(7));

    let _handle = manager
        .create_context(context_id.clone(), params, invoker.clone(), None)
        .await
        .expect("create_context");

    // Mirror an `ApproveSpend` governance proposal: grant the invoker
    // a 1000 USD budget via the test-only hook added in PR #1606.
    manager
        .grant_budget_for_test(&context_id, &invoker, Amount::new(1_000))
        .await;

    let mut registry = OutletRegistry::new();
    registry.insert(echo_outlet());

    // Fully signed UCAN bound to the invoker, matching mock_key_resolver.
    let spending_ucan = signed_spending_ucan_for(&invoker);

    // Snapshot pre-call state.
    let budget_before = manager
        .remaining_budget_for_test(&context_id, &invoker)
        .await;
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let velocity_before = manager
        .velocity_for_test(&context_id, &invoker, now_secs)
        .await;

    // THE CRITICAL CALL — exactly the path the 3 FFI bridges
    // now route through after C4. The closure echoes the input back
    // so we can also verify the executor is invoked.
    let outcome = manager
        .invoke_outlet_with_economy(
            &context_id,
            &registry,
            &OutletId::from("echo"),
            serde_json::json!({"hello": "world"}),
            &invoker,
            Some(&spending_ucan),
            None,
            |input: serde_json::Value| async move { Ok(serde_json::json!({"echoed": input})) },
        )
        .await
        .expect("invoke_outlet_with_economy must succeed for free-budget paid outlet");

    // Verify the executor ran and produced the expected output.
    assert_eq!(
        outcome.output,
        serde_json::json!({"echoed": {"hello": "world"}}),
        "executor output must round-trip through the manager"
    );

    // Verify the budget was deducted by EXACTLY the policy cost.
    // Before C4 the bridges bypassed this entirely; the budget would
    // be unchanged from `budget_before`.
    let budget_after = manager
        .remaining_budget_for_test(&context_id, &invoker)
        .await;
    assert_eq!(
        budget_before.value() - budget_after.value(),
        7,
        "invoke_outlet_with_economy must deduct the per_outlet_call cost (7) from the per-DID budget — \
         got {} -> {}",
        budget_before.value(),
        budget_after.value()
    );

    // Verify velocity was recorded. Before C4 the bridges did not
    // record velocity at all, so escalation never engaged.
    let velocity_after = manager
        .velocity_for_test(&context_id, &invoker, now_secs)
        .await;
    assert!(
        velocity_after > velocity_before,
        "invoke_outlet_with_economy must record one velocity entry per call \
         (before={velocity_before}, after={velocity_after})"
    );

    // Verify the OutletInvokedEvent carries the deducted cost.
    assert_eq!(
        outcome.event.cost.map(scp_core::economy::Amount::value),
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

    // Sanity-check: no payment receipt was produced (no payment
    // adapter configured → escrow capture is skipped).
    assert!(
        outcome.payment_receipt.is_none(),
        "no PaymentAdapter configured → no PaymentReceipt expected"
    );
}

// ---------------------------------------------------------------------------
// Test 2: invoke_outlet_with_economy rejects insufficient budget
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invoke_outlet_with_economy_rejects_insufficient_budget() {
    // ADR-049 commit 12c.9c — wrap with `attach_test_supervisor`.
    let manager = scp_core::context::attach_test_supervisor(ContextManager::new(
        Box::new(MockCrypto),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    ));

    let invoker = DID::from("did:key:invoker");
    let context_id = "ctx-c4-budget-rejected".to_owned();
    let mut params = governance_params_with_outlets();
    // Price the outlet above any granted budget.
    params.economic_policy = Some(priced_policy(100));

    let _handle = manager
        .create_context(context_id.clone(), params, invoker.clone(), None)
        .await
        .expect("create_context");

    // Grant ZERO budget — the per-DID budget tracker has no entry for
    // the invoker, so `has_budget` returns false and the pre-check
    // must reject the invocation.
    let mut registry = OutletRegistry::new();
    registry.insert(echo_outlet());
    let spending_ucan = dummy_spending_ucan();

    let result = manager
        .invoke_outlet_with_economy(
            &context_id,
            &registry,
            &OutletId::from("echo"),
            serde_json::json!({}),
            &invoker,
            Some(&spending_ucan),
            None,
            |_input: serde_json::Value| async move {
                panic!("executor must NOT run when the pre-check rejects on budget")
            },
        )
        .await;

    let err = result.expect_err("expected budget-exceeded rejection");
    let msg = format!("{err}");
    assert!(
        msg.contains("SCP-ECON-12010") || msg.contains("budget exceeded"),
        "expected SCP-ECON-12010 budget-exceeded error, got: {msg}"
    );

    // Velocity tracker must have been rolled back. The new test-only
    // accessor reads `get_velocity` directly so we can prove the
    // rollback happened.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let velocity = manager
        .velocity_for_test(&context_id, &invoker, now_secs)
        .await;
    assert_eq!(
        velocity, 0,
        "Phase 1 budget rejection must roll back the velocity entry — got {velocity}"
    );
}
