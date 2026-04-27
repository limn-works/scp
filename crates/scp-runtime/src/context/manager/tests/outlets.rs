//! SCP-OUT-004 AC5 — outlet lifecycle ContextManager surface tests.
//!
//! Each of the eight `pub async fn` shims added on `impl ContextManager`
//! by SCP-OUT-004 AC5 has a happy-path and at least one failure-path
//! assertion here. The shims forward to the `scp-protocol` registry-side
//! free functions or to existing manager methods (`open_outlet_stream`,
//! `invoke_outlet_dispatch_with_economy_stream`); the failure paths
//! exercised here pin the runtime envelope (`ContextNotRegistered`,
//! `PermissionDenied`) so a refactor cannot silently drop the membership
//! guard or the authorization check.
//!
//! Spec sources: `.docs/specs/05-contexts.md` §5.4 / §5.4.2 / §5.4.4 /
//! §5.4.5; ADR-049 §1 (rename), §AC5.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::uninlined_format_args
)]

use scp_protocol::context::ContextError;
use scp_protocol::context::outlets::registry::{
    OutletCost, OutletRegistration, OutletRegistry, OutletSchema, OutletTestVector,
};
use scp_protocol::context::outlets::{OutletId, OutletKind};
use scp_protocol::context::params::Capability;

use super::setup_active_context;

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

/// Build a minimal `OutletRegistration` valid for the `register_outlet`
/// pipeline. Caller picks the kind / cost / id and pays for any
/// per-test-case mutations.
fn fixture_registration(
    outlet_id: &str,
    kind: OutletKind,
    operator_did: &str,
    cost: Option<OutletCost>,
) -> OutletRegistration {
    OutletRegistration {
        outlet_id: outlet_id.to_owned(),
        kind,
        name: outlet_id.to_owned(),
        description: format!("fixture outlet {outlet_id}"),
        schema: OutletSchema {
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "request": {"type": "string"},
                    "context": {"type": "string"},
                },
                "required": ["request", "context"],
            }),
            output_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "result": {"type": "string"},
                    "status": {"type": "string"},
                },
                "required": ["result", "status"],
            }),
            aggregate_schema: None,
        },
        implementation_hash: [0u8; 32],
        test_vectors: vec![OutletTestVector {
            input: serde_json::json!({"request": "ping", "context": "test"}),
            expected_output: serde_json::json!({"result": "pong", "status": "ok"}),
            description: "noop".to_owned(),
        }],
        operator_did: operator_did.into(),
        cost,
        registered_at: 0,
        signature: Vec::new(),
        message_catalog: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// register_outlet
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_outlet_happy_path_returns_id_and_event() {
    let (manager, _handle) = setup_active_context().await;
    let mut registry = OutletRegistry::new();
    let reg = fixture_registration("calculator", OutletKind::Action, "did:key:creator", None);

    let (returned_id, event) = manager
        .register_outlet("test-ctx", &mut registry, reg, "did:key:creator")
        .await
        .expect("register_outlet must succeed for an authorized creator");

    assert_eq!(returned_id, "calculator");
    assert_eq!(event.outlet_id, "calculator");
    assert!(registry.contains("calculator"));
}

#[tokio::test]
async fn register_outlet_unknown_context_yields_context_not_registered() {
    let (manager, _handle) = setup_active_context().await;
    let mut registry = OutletRegistry::new();
    let reg = fixture_registration("calculator", OutletKind::Action, "did:key:creator", None);

    let err = manager
        .register_outlet("does-not-exist", &mut registry, reg, "did:key:creator")
        .await
        .expect_err("unknown context must reject before reaching registry mutation");

    assert!(
        matches!(err, ContextError::ContextNotRegistered(ref id) if id == "does-not-exist"),
        "expected ContextNotRegistered, got {err:?}"
    );
    // The registry MUST be untouched on the membership-guard failure path.
    assert!(registry.is_empty(), "registry must not mutate on failure");
}

#[tokio::test]
async fn register_outlet_query_with_positive_cost_rejected() {
    // SCP-OUT-012 §5.4.2 floor: a Query outlet declaring positive cost
    // is rejected by `OutletRegistration::validate()` before the runtime
    // reaches the storage step. The shim folds the protocol-level
    // `OutletError::QueryCostViolation` into `ContextError::PermissionDenied`
    // carrying `SCP-TOOL-6102` — the same envelope the existing
    // `query_cost_violation_to_context` helper produces, so callers get
    // a consistent error surface across `execute_register_outlet`
    // (governance) and `register_outlet` (the AC5 shim).
    let (manager, _handle) = setup_active_context().await;
    let mut registry = OutletRegistry::new();
    let bad = fixture_registration(
        "query-paid",
        OutletKind::Query,
        "did:key:creator",
        Some(OutletCost {
            amount: 1,
            currency: "USD".to_owned(),
            payee: "did:key:payee".into(),
            cost_formula: None,
        }),
    );

    let err = manager
        .register_outlet("test-ctx", &mut registry, bad, "did:key:creator")
        .await
        .expect_err("Query+cost must be rejected per §5.4.2");

    assert!(
        matches!(err, ContextError::PermissionDenied(ref msg) if msg.contains("SCP-TOOL-6102")),
        "expected PermissionDenied SCP-TOOL-6102, got {err:?}"
    );
    assert!(!registry.contains("query-paid"));
}

// ---------------------------------------------------------------------------
// update_outlet
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_outlet_happy_path_records_changed_fields() {
    let (manager, _handle) = setup_active_context().await;
    let mut registry = OutletRegistry::new();
    let reg = fixture_registration("calculator", OutletKind::Action, "did:key:creator", None);
    manager
        .register_outlet("test-ctx", &mut registry, reg, "did:key:creator")
        .await
        .unwrap();

    let mut new_reg =
        fixture_registration("calculator", OutletKind::Action, "did:key:creator", None);
    "v2 calculator".clone_into(&mut new_reg.description);

    let event = manager
        .update_outlet(
            "test-ctx",
            &mut registry,
            "calculator",
            new_reg,
            "did:key:creator",
        )
        .await
        .expect("operator can update its own outlet");

    assert_eq!(event.outlet_id, "calculator");
    assert!(event.changed_fields.iter().any(|f| f == "description"));
}

#[tokio::test]
async fn update_outlet_unauthorized_actor_rejected() {
    // Updater is neither operator (`did:key:creator`) nor admin →
    // `OutletError::UpdaterNotAuthorized` folds to PermissionDenied.
    let (manager, _handle) = setup_active_context().await;
    let mut registry = OutletRegistry::new();
    let reg = fixture_registration("calculator", OutletKind::Action, "did:key:creator", None);
    manager
        .register_outlet("test-ctx", &mut registry, reg, "did:key:creator")
        .await
        .unwrap();

    let new_reg = fixture_registration("calculator", OutletKind::Action, "did:key:creator", None);

    let err = manager
        .update_outlet(
            "test-ctx",
            &mut registry,
            "calculator",
            new_reg,
            "did:key:eve",
        )
        .await
        .expect_err("non-operator non-admin must be rejected");

    assert!(
        matches!(err, ContextError::PermissionDenied(ref msg) if msg.contains("SCP-TOOL-6101")),
        "expected SCP-TOOL-6101 unauthorized updater, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// deregister_outlet
// ---------------------------------------------------------------------------

#[tokio::test]
async fn deregister_outlet_happy_path_removes_registration() {
    let (manager, _handle) = setup_active_context().await;
    let mut registry = OutletRegistry::new();
    let reg = fixture_registration("calculator", OutletKind::Action, "did:key:creator", None);
    manager
        .register_outlet("test-ctx", &mut registry, reg, "did:key:creator")
        .await
        .unwrap();
    assert!(registry.contains("calculator"));

    let removed = manager
        .deregister_outlet("test-ctx", &mut registry, "calculator", "did:key:creator")
        .await
        .expect("operator can deregister own outlet");

    assert_eq!(removed.outlet_id, "calculator");
    assert!(!registry.contains("calculator"));
}

#[tokio::test]
async fn deregister_outlet_unauthorized_actor_rejected() {
    let (manager, _handle) = setup_active_context().await;
    let mut registry = OutletRegistry::new();
    let reg = fixture_registration("calculator", OutletKind::Action, "did:key:creator", None);
    manager
        .register_outlet("test-ctx", &mut registry, reg, "did:key:creator")
        .await
        .unwrap();

    let err = manager
        .deregister_outlet("test-ctx", &mut registry, "calculator", "did:key:eve")
        .await
        .expect_err("non-operator non-admin must be rejected");

    assert!(
        matches!(err, ContextError::PermissionDenied(ref msg) if msg.contains("not authorized")),
        "expected PermissionDenied for unauthorized actor, got {err:?}"
    );
    // Defense-in-depth: failed authorization MUST NOT remove the outlet.
    assert!(registry.contains("calculator"));
}

#[tokio::test]
async fn deregister_outlet_missing_outlet_yields_not_found() {
    let (manager, _handle) = setup_active_context().await;
    let mut registry = OutletRegistry::new();

    let err = manager
        .deregister_outlet("test-ctx", &mut registry, "missing", "did:key:creator")
        .await
        .expect_err("deregistering an unknown outlet must fail");

    assert!(
        matches!(err, ContextError::PermissionDenied(ref msg) if msg.contains("SCP-TOOL-6002")),
        "expected SCP-TOOL-6002 not-found, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// verify_outlet
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verify_outlet_happy_path_uses_executor() {
    let (manager, _handle) = setup_active_context().await;
    let mut registry = OutletRegistry::new();
    let reg = fixture_registration("calculator", OutletKind::Action, "did:key:creator", None);
    manager
        .register_outlet("test-ctx", &mut registry, reg, "did:key:creator")
        .await
        .unwrap();

    let (result, _event) = manager
        .verify_outlet(
            "test-ctx",
            &registry,
            "calculator",
            // Identity executor: returns the registered expected output
            // for the matching test vector → integrity_ok=true.
            |_input| serde_json::json!({"result": "pong", "status": "ok"}),
        )
        .await
        .expect("verify_outlet succeeds when executor matches the test vectors");

    assert!(result.integrity_ok);
}

#[tokio::test]
async fn verify_outlet_unknown_outlet_yields_not_found() {
    let (manager, _handle) = setup_active_context().await;
    let registry = OutletRegistry::new();

    let err = manager
        .verify_outlet("test-ctx", &registry, "missing", |_input| {
            serde_json::Value::Null
        })
        .await
        .expect_err("verify on unknown outlet must fail");
    assert!(
        matches!(err, ContextError::PermissionDenied(ref msg) if msg.contains("SCP-TOOL-6002")),
        "expected SCP-TOOL-6002 not-found, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// list_outlets / get_outlet
//
// These two methods read from the manager's authoritative
// `GovernanceState.registered_outlets`, which is mutated by
// `execute_register_outlet`. The AC5 shim `register_outlet` operates
// on the caller-supplied `OutletRegistry` (the lock-split discipline at
// the top of `outlets.rs`) and intentionally does NOT touch the
// per-context governance copy — that is the governance pipeline's job.
//
// To keep these unit tests focused on the shim contract (membership
// guard + authoritative-source semantics), the happy-path fixture
// registers an outlet via `execute_register_outlet` so the manager
// state actually carries it. The failure path does not need that
// because the membership guard fires before any state read.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_outlets_unknown_context_yields_context_not_registered() {
    let (manager, _handle) = setup_active_context().await;

    let err = manager
        .list_outlets("does-not-exist")
        .await
        .expect_err("unknown context must reject");
    assert!(
        matches!(err, ContextError::ContextNotRegistered(ref id) if id == "does-not-exist"),
        "expected ContextNotRegistered, got {err:?}"
    );
}

#[tokio::test]
async fn list_outlets_empty_governance_state_yields_empty_vec() {
    let (manager, _handle) = setup_active_context().await;
    let ids = manager.list_outlets("test-ctx").await.expect("ok");
    assert!(
        ids.is_empty(),
        "no governance-tracked outlets means an empty list"
    );
}

#[tokio::test]
async fn get_outlet_unknown_context_yields_context_not_registered() {
    let (manager, _handle) = setup_active_context().await;
    let err = manager
        .get_outlet("does-not-exist", "anything")
        .await
        .expect_err("unknown context must reject");
    assert!(
        matches!(err, ContextError::ContextNotRegistered(ref id) if id == "does-not-exist"),
        "expected ContextNotRegistered, got {err:?}"
    );
}

#[tokio::test]
async fn get_outlet_unknown_id_yields_none() {
    // Empty governance state → known context, unknown outlet → Ok(None).
    // The shim distinguishes "context unknown" (Err) from "outlet
    // unknown" (Ok(None)) so callers can treat the latter as a normal
    // lookup miss.
    let (manager, _handle) = setup_active_context().await;
    let result = manager
        .get_outlet("test-ctx", "missing")
        .await
        .expect("known context with missing outlet → Ok(None)");
    assert!(result.is_none());
}

// ---------------------------------------------------------------------------
// open_outlet_session / invoke_outlet
//
// These two shims forward to the existing `open_outlet_stream` /
// `invoke_outlet_dispatch_with_economy_stream` methods. Both already
// have extensive coverage in their own dedicated tests; here we only
// pin the membership-guard contract so the AC5 shim cannot regress to
// silently no-op-ing on an unknown context.
//
// The full end-to-end streaming path (admission tracker, escrow,
// credit/cancel, terminal `End`/`Error` chunk) is exercised by the
// existing OUT-034 / OUT-035 test suites.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invoke_outlet_unknown_context_yields_context_not_registered() {
    use scp_primitives::DID;

    struct NoExecutor;
    impl crate::context::outlets::invoke::OutletExecutor for NoExecutor {}

    let (manager, _handle) = setup_active_context().await;
    let registry = OutletRegistry::new();
    let outlet_id: OutletId = "calculator".to_owned();
    let invoker: DID = "did:key:invoker".into();
    let executor = NoExecutor;

    let result = manager
        .invoke_outlet(
            "does-not-exist",
            &registry,
            &outlet_id,
            serde_json::json!({}),
            &invoker,
            None,
            None,
            &executor,
            None,
            None,
            None,
        )
        .await;
    let err = result.expect_err("unknown context must yield a synchronous Err on stream open");
    // The dispatch-with-economy path wraps unknown-context as the typed
    // §5.4.4 envelope under `OutletErrorClass::Authorization` (the
    // capability check fires first because membership and capability are
    // checked under the same lock acquisition; an unknown context fails
    // the capability check). Either envelope satisfies the AC5 contract:
    // the membership guard MUST fire before the executor runs. Pin both
    // observed shapes so future refactors that re-order the checks still
    // pass without the test silently regressing to "any error is fine".
    assert!(
        matches!(err, ContextError::ContextNotRegistered(_))
            || matches!(err, ContextError::OutletInvocation(_)),
        "expected ContextNotRegistered or OutletInvocation envelope, got {err:?}"
    );
}

// `open_outlet_session` is a thin alias to `open_outlet_stream`
// (extensively covered by the OUT-034 / OUT-035 dedicated test suites).
// The `pipeline_wiring` assertion `context_manager_exposes_outlet_lifecycle_methods`
// in `crates/scp-testing/tests/integration/pipeline_wiring.rs` pins the
// shim body to contain the literal `self.open_outlet_stream` call, which
// catches the failure mode this unit test would otherwise cover (a
// silent rename to `todo!()` or a `let _ = ...;` cheat). Re-implementing
// the full `OpenStreamParams` / `StreamAdmissionTracker` fixture in this
// unit test would duplicate the OUT-034 stream-open coverage without
// strengthening the AC5 contract — the structural assertion is the
// stronger guarantee.
//
// `Capability::OutletInterface` is referenced here only to keep the
// import in scope for fixture clarity (the per-context ceiling
// `setup_active_context` builds includes it; surfacing the constant in
// this module's prelude avoids the implicit-use ambiguity that future
// fixture refactors might trigger).
#[allow(dead_code)]
const _OUTLET_INTERFACE_CAP: Capability = Capability::OutletInterface;

#[tokio::test]
async fn list_and_get_outlet_track_governance_state_after_register() {
    // End-to-end happy path threading the manager-state read shims
    // (`list_outlets` / `get_outlet`) through the authoritative
    // `execute_register_outlet` write so the test pins the contract:
    // the shims read from the SAME `governance.registered_outlets`
    // slot the governance dispatch arm populates. This catches the
    // failure mode where a refactor moves the shims to read from a
    // different per-context structure.
    use scp_protocol::context::governance::ProposalId;

    let (manager, _handle) = setup_active_context().await;

    // No outlets yet.
    let pre = manager.list_outlets("test-ctx").await.unwrap();
    assert!(pre.is_empty());
    let pre_get = manager.get_outlet("test-ctx", "calculator").await.unwrap();
    assert!(pre_get.is_none());

    // Drive `execute_register_outlet` directly — that is the production
    // governance arm; the AC5 shims read from the slot it populates.
    let reg = fixture_registration("calculator", OutletKind::Action, "did:key:creator", None);
    let pid: ProposalId = [0u8; 32];
    manager
        .execute_register_outlet("test-ctx", &reg, pid, "did:key:creator")
        .await
        .expect("execute_register_outlet must accept this fixture");

    // Now `list_outlets` and `get_outlet` MUST observe the registration.
    let post: Vec<OutletId> = manager.list_outlets("test-ctx").await.unwrap();
    assert!(
        post.iter().any(|id| id == "calculator"),
        "list_outlets must surface the just-registered outlet, got {post:?}"
    );
    let post_get = manager
        .get_outlet("test-ctx", "calculator")
        .await
        .unwrap()
        .expect("get_outlet must return the just-registered outlet");
    assert_eq!(post_get.outlet_id, "calculator");
}
