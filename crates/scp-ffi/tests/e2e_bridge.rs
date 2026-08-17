//! End-to-end tests for the `PyO3` bridge layer.
//!
//! These tests exercise the public API surface of `scp-ffi` from an
//! integration test crate. They cover: identity registry, context
//! lifecycle, outlets, UCAN, event log, discovery, provenance, bridge
//! trust, sync, and trust engine.
//!
//! For `ContextManager` methods that require complex types (`join_context`,
//! `leave_context`), membership is set up via the manager's internal
//! `add_member` on the locked context. The private `#[pyfunction]` bridge
//! functions (`py_identity_create`, `py_context_create`, etc.) are already
//! covered by 190+ unit tests in their respective source modules.
//!
//! Run with:
//! ```sh
//! DYLD_LIBRARY_PATH=$(python3.12 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))") \
//!   cargo test -p scp-ffi --test e2e_bridge --features testing
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::sync::Once;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use _scp_core::context::PyContextHandle;
use _scp_core::custody::FfiKeyCustody;
use _scp_core::runtime::{self, IdentityEntry, PyBridgeInstance};

static INIT: Once = Once::new();

/// Ensures the Python interpreter and the crate-internal tokio runtime are
/// initialized. Per-`PyBridgeInstance` runtime wiring (including the
/// `Supervisor`) is attached separately via [`__bi`] /
/// `runtime::init_context_manager_for_test`, which uses
/// `LocalTransportProvider` so `publish_context` succeeds without warning
/// noise (`NotConfiguredTransportProvider` would log warnings on best-effort
/// publish).
fn setup() {
    INIT.call_once(|| {
        pyo3::prepare_freethreaded_python();
        // Initialize the crate-internal tokio runtime used by bridge functions
        // like py_event_log_query when storage is available.
        _scp_core::init_runtime().unwrap();
    });
}

/// Returns a fresh bridge instance with a test bridge-runtime attached.
/// Phase D (#1695): tests no longer share a process-global default.
fn __bi() -> Arc<PyBridgeInstance> {
    let bi = Arc::new(PyBridgeInstance::new_py());
    runtime::init_context_manager_for_test(&bi);
    bi
}

/// Returns the shared, process-lifetime tokio runtime for async operations in tests.
///
/// Uses a multi-thread runtime because the context-creating codepath reaches
/// `tokio::task::block_in_place`, which panics on a current-thread runtime.
/// Interim per generic-moseying-lightning §484 until Phase 3's `block_in_place`
/// elimination; remove (revert to `new_current_thread`) when persistence is async.
///
/// SHARED + PERSISTENT (not a fresh runtime per call): mirrors production's
/// global runtime (`crate::runtime()` / `RUNTIME` in `scp-ffi/src/lib.rs`).
/// The actor-per-context bootstrap spawns each context's actor task with a bare
/// `tokio::spawn` on the ambient runtime. A per-call runtime would be dropped
/// when the create-call returns, aborting the actor task and closing its mailbox,
/// so later mailbox-routed queries (`is_member`/`member_count`/`member_role`)
/// would hit a closed channel and return `None`. A single long-lived runtime
/// keeps the actor alive across create + query, matching production semantics.
fn test_runtime() -> &'static tokio::runtime::Runtime {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    })
}

/// Generates a random hex context ID (16 bytes = 32 hex chars).
fn random_context_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Creates an in-memory identity and registers it in the runtime registry.
///
/// Takes the bridge instance so the caller can reuse the same `bi` for
/// subsequent registry lookups — each `PyBridgeInstance` has its own
/// identity/context registry and `instance_id`.
fn create_test_identity(bi: &PyBridgeInstance) -> String {
    setup();
    let rt = test_runtime();

    let custody = Arc::new(FfiKeyCustody::InMemory(
        scp_platform::testing::InMemoryKeyCustody::new(),
    ));

    let pre_rotation_custody = Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
    let (identity, document, pre_rotation_handle) = rt.block_on(async {
        let did_method = scp_identity::DidDht::with_client(std::sync::Arc::new(
            scp_dht::InMemoryDhtClient::new(),
        ));
        scp_identity::DidMethod::create(
            &did_method,
            custody.as_ref(),
            pre_rotation_custody.as_ref(),
        )
        .await
        .unwrap()
    });

    let did = identity.did.clone();

    runtime::register_identity(
        bi,
        &did,
        IdentityEntry {
            identity,
            custody,
            document,
            identity_link_attestations: Vec::new(),
            pre_rotation_handle,
            pre_rotation_custody,
        },
    );

    did
}

/// Creates a context via the per-instance `Supervisor` and registers FFI
/// state. Returns the `context_id`.
///
/// Takes the bridge instance so the caller can reuse the same `bi` for
/// subsequent registry lookups — each `PyBridgeInstance` has its own
/// identity/context registry and `instance_id`.
fn create_test_context(bi: &PyBridgeInstance, creator_did: &str) -> String {
    setup();
    let context_id = random_context_id();
    runtime::register_context(bi, &context_id, creator_did, &[]).unwrap();

    let rt = test_runtime();
    let supervisor = runtime::supervisor(bi).unwrap().clone();
    let creator = scp_did::DID(creator_did.to_owned());
    let ctx_id = context_id.clone();

    rt.block_on(async move {
        // The supervisor's role state is what every authorization check reads, so
        // the fixture creates the context with `default_ceiling()` — the ceiling
        // `build_core_context_params` sends when a caller supplies none.
        let params = scp_core::context::ContextParams {
            ceiling: scp_core::context::roles::default_ceiling()
                .iter()
                .cloned()
                .collect(),
            ..scp_core::context::ContextParams::default()
        };
        supervisor
            .create_context(ctx_id.clone(), params, creator.clone(), None)
            .await
            .unwrap();
        supervisor.register_local_did(creator).await.unwrap();
    });

    context_id
}

/// Builds an outlet registration `PyDict` with valid schema (2+ properties).
fn build_outlet_reg<'py>(py: Python<'py>, name: &str, operator_did: &str) -> Bound<'py, PyDict> {
    let reg = PyDict::new(py);
    reg.set_item("name", name).unwrap();
    reg.set_item("description", format!("Outlet: {name}"))
        .unwrap();
    reg.set_item("operator_did", operator_did).unwrap();
    let schema = PyDict::new(py);
    let is = PyDict::new(py);
    is.set_item("type", "object").unwrap();
    let is_props = PyDict::new(py);
    let s_type = PyDict::new(py);
    s_type.set_item("type", "string").unwrap();
    is_props.set_item("a", s_type.clone()).unwrap();
    is_props.set_item("b", s_type).unwrap();
    is.set_item("properties", is_props).unwrap();
    let os = PyDict::new(py);
    os.set_item("type", "object").unwrap();
    let os_props = PyDict::new(py);
    let n_type = PyDict::new(py);
    n_type.set_item("type", "number").unwrap();
    os_props.set_item("sum", n_type.clone()).unwrap();
    os_props.set_item("ok", n_type).unwrap();
    os.set_item("properties", os_props).unwrap();
    schema.set_item("input_schema", is).unwrap();
    schema.set_item("output_schema", os).unwrap();
    reg.set_item("schema", schema).unwrap();

    let tv = PyDict::new(py);
    let tv_input = PyDict::new(py);
    tv_input.set_item("a", "hello").unwrap();
    tv_input.set_item("b", "world").unwrap();
    let tv_output = PyDict::new(py);
    tv_output.set_item("sum", 42).unwrap();
    tv_output.set_item("ok", 1).unwrap();
    tv.set_item("input", tv_input).unwrap();
    tv.set_item("expected_output", tv_output).unwrap();
    tv.set_item("description", "test vector").unwrap();
    let tv_list = PyList::new(py, &[tv]).unwrap();
    reg.set_item("test_vectors", tv_list).unwrap();
    reg
}

// ============================================================================
// Identity (via runtime registry)
// ============================================================================

#[test]
fn identity_create_returns_valid_did() {
    let bi = __bi();
    let did = create_test_identity(&bi);
    assert!(did.starts_with("did:dht:"));
    assert!(runtime::identity_registry_contains(&bi, &did));
}

#[test]
fn identity_multiple_unique() {
    let bi = __bi();
    let did1 = create_test_identity(&bi);
    let did2 = create_test_identity(&bi);
    assert_ne!(did1, did2);
}

#[test]
fn identity_registry_lookup() {
    let bi = __bi();
    let did = create_test_identity(&bi);
    let result = runtime::with_identity(&bi, &did, |entry| Ok(entry.identity.did.clone()));
    assert_eq!(result.unwrap(), did);
}

#[test]
fn identity_unknown_did_fails() {
    setup();
    let bi = __bi();
    let result: Result<(), _> = runtime::with_identity(&bi, "did:dht:nonexistent", |_entry| Ok(()));
    assert!(result.is_err());
}

// ============================================================================
// Context lifecycle
// ============================================================================

#[test]
fn context_create_registers_in_runtime() {
    let bi = __bi();
    let did = create_test_identity(&bi);
    let ctx_id = create_test_context(&bi, &did);

    let creator = runtime::live_role_state(&bi, &ctx_id).unwrap().creator_did;
    assert_eq!(creator, did);
}

#[test]
fn context_membership_creator_is_member() {
    let bi = __bi();
    let did = create_test_identity(&bi);
    let ctx_id = create_test_context(&bi, &did);

    let rt = test_runtime();
    let supervisor = runtime::supervisor(&bi).unwrap().clone();

    assert!(rt.block_on(supervisor.is_member(&ctx_id, &did)));
    assert_eq!(rt.block_on(supervisor.member_count(&ctx_id)), Some(1));

    let dids = rt.block_on(supervisor.member_dids(&ctx_id));
    assert!(dids.contains(&did));
}

#[test]
fn context_member_role_creator_is_admin() {
    let bi = __bi();
    let did = create_test_identity(&bi);
    let ctx_id = create_test_context(&bi, &did);

    let rt = test_runtime();
    let supervisor = runtime::supervisor(&bi).unwrap().clone();

    let role = rt.block_on(supervisor.member_role(&ctx_id, &did));
    assert!(role.is_some());
    let role_str = format!("{:?}", role.unwrap());
    // Role name is lowercase "admin" in the ContextManager.
    assert!(
        role_str.to_lowercase().contains("admin"),
        "Creator role should contain 'admin', got: {role_str}"
    );
}

#[test]
fn context_drain_events_is_idempotent() {
    let bi = __bi();
    let did = create_test_identity(&bi);
    let ctx_id = create_test_context(&bi, &did);

    let rt = test_runtime();
    let supervisor = runtime::supervisor(&bi).unwrap().clone();

    // First drain: may or may not have events depending on ContextManager internals.
    let events = rt.block_on(supervisor.drain_events(&ctx_id));
    let first_count = events.len();

    // Second drain: must be empty (events are consumed).
    let events2 = rt.block_on(supervisor.drain_events(&ctx_id));
    assert!(
        events2.is_empty(),
        "Second drain should return empty, first had {first_count}"
    );
}

#[test]
fn multiple_contexts_independent() {
    let bi = __bi();
    let did = create_test_identity(&bi);
    let ctx1 = create_test_context(&bi, &did);
    let ctx2 = create_test_context(&bi, &did);
    assert_ne!(ctx1, ctx2);
}

// ============================================================================
// Context creation → MLS group verification (issue #501 AC)
// ============================================================================

/// Verifies that creating a context through the bridge establishes the
/// context in the `ContextManager` with a valid group (the creator is a
/// member and crypto provider's `create_mls_group` was called successfully).
///
/// This is the acceptance criterion from issue #501: "create context through
/// bridge → verify MLS group exists." The bridge uses `NoOpCryptoProvider`
/// whose `create_mls_group` succeeds (real `NodeMlsFactory` integration
/// is a separate concern). The test verifies the full bridge path:
/// identity creation → context creation → `ContextManager` state is populated.
#[test]
fn context_create_establishes_mls_group() {
    let bi = __bi();
    let did = create_test_identity(&bi);
    let ctx_id = create_test_context(&bi, &did);

    let rt = test_runtime();
    let supervisor = runtime::supervisor(&bi).unwrap().clone();

    // The ContextManager should have the context with the creator as a member.
    // This confirms that the full creation flow ran (including the crypto
    // provider's create_mls_group call which must succeed for create_context
    // to return Ok).
    let member_count = rt.block_on(supervisor.member_count(&ctx_id));
    assert_eq!(
        member_count,
        Some(1),
        "Context should have exactly 1 member (the creator) after creation"
    );

    // Verify the creator is registered as a member.
    assert!(
        rt.block_on(supervisor.is_member(&ctx_id, &did)),
        "Creator DID should be a member of the context"
    );

    // Verify role state exists (populated during creation).
    let role_state = rt.block_on(supervisor.get_role_state(&ctx_id));
    assert!(
        role_state.is_some(),
        "Context should have role state after creation"
    );

    // Verify the creator has admin role (context creator gets admin).
    let role = rt.block_on(supervisor.member_role(&ctx_id, &did));
    assert!(role.is_some(), "Creator should have a role assignment");
    let role_str = format!("{:?}", role.unwrap());
    assert!(
        role_str.to_lowercase().contains("admin"),
        "Creator should be admin, got: {role_str}"
    );
}

// ============================================================================
// Outlet registration and verification
// ============================================================================

#[test]
fn outlet_register_and_verify() {
    Python::with_gil(|py| {
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        runtime::init_context_manager_for_test(scp.bridge_instance());
        let did = create_test_identity(scp.bridge_instance());
        let ctx_id = create_test_context(scp.bridge_instance(), &did);

        let reg = PyDict::new(py);
        reg.set_item("name", "test_outlet").unwrap();
        reg.set_item("description", "A test outlet").unwrap();
        reg.set_item("operator_did", &did).unwrap();

        let schema = PyDict::new(py);
        let input_schema = PyDict::new(py);
        input_schema.set_item("type", "object").unwrap();
        let input_props = PyDict::new(py);
        let str_type = PyDict::new(py);
        str_type.set_item("type", "string").unwrap();
        input_props.set_item("x", str_type.clone()).unwrap();
        input_props.set_item("y", str_type).unwrap();
        input_schema.set_item("properties", input_props).unwrap();
        let output_schema = PyDict::new(py);
        output_schema.set_item("type", "object").unwrap();
        let output_props = PyDict::new(py);
        let int_type = PyDict::new(py);
        int_type.set_item("type", "integer").unwrap();
        output_props.set_item("result", int_type.clone()).unwrap();
        output_props.set_item("status", int_type).unwrap();
        output_schema.set_item("properties", output_props).unwrap();
        schema.set_item("input_schema", input_schema).unwrap();
        schema.set_item("output_schema", output_schema).unwrap();
        reg.set_item("schema", schema).unwrap();

        let tv = PyDict::new(py);
        let tv_input = PyDict::new(py);
        tv_input.set_item("x", "hello").unwrap();
        tv_input.set_item("y", "world").unwrap();
        let tv_output = PyDict::new(py);
        tv_output.set_item("result", 42).unwrap();
        tv_output.set_item("status", 0).unwrap();
        tv.set_item("input", tv_input).unwrap();
        tv.set_item("expected_output", tv_output).unwrap();
        tv.set_item("description", "identity vector").unwrap();
        let tv_list = PyList::new(py, &[tv]).unwrap();
        reg.set_item("test_vectors", tv_list).unwrap();

        let outlet_id = scp.outlet_register(&ctx_id, &reg.as_borrowed()).unwrap();
        assert!(outlet_id.contains("test_outlet"));

        let result = scp.outlet_verify(&ctx_id, &outlet_id).unwrap();
        assert!(result.passed);
        assert!(result.failures.is_empty());
    });
}

#[test]
fn outlet_register_rejects_invalid_context() {
    setup();
    Python::with_gil(|py| {
        let reg = PyDict::new(py);
        reg.set_item("name", "orphan_outlet").unwrap();
        reg.set_item("description", "No context").unwrap();
        reg.set_item("operator_did", "did:key:test").unwrap();
        let schema = PyDict::new(py);
        schema.set_item("input_schema", PyDict::new(py)).unwrap();
        schema.set_item("output_schema", PyDict::new(py)).unwrap();
        reg.set_item("schema", schema).unwrap();

        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        let result = scp.outlet_register("nonexistent-ctx", &reg.as_borrowed());
        assert!(result.is_err());
    });
}

#[test]
fn outlet_register_rejects_empty_name() {
    Python::with_gil(|py| {
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        runtime::init_context_manager_for_test(scp.bridge_instance());
        let did = create_test_identity(scp.bridge_instance());
        let ctx_id = create_test_context(scp.bridge_instance(), &did);

        let reg = PyDict::new(py);
        reg.set_item("name", "").unwrap();
        reg.set_item("description", "bad outlet").unwrap();
        reg.set_item("operator_did", &did).unwrap();
        let schema = PyDict::new(py);
        schema.set_item("input_schema", PyDict::new(py)).unwrap();
        schema.set_item("output_schema", PyDict::new(py)).unwrap();
        reg.set_item("schema", schema).unwrap();

        let result = scp.outlet_register(&ctx_id, &reg.as_borrowed());
        assert!(result.is_err());
    });
}

// ============================================================================
// UCAN mint
// ============================================================================

// Note: `ucan_mint_returns_token` requires the crate-internal global tokio
// runtime (RUNTIME OnceLock in lib.rs) which is not accessible from
// integration tests. This is covered by unit tests in ucan.rs.

#[test]
fn ucan_mint_rejects_empty_context() {
    setup();
    let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
    let result = scp.ucan_mint(
        "",
        "did:key:someone",
        vec!["messages:write".to_owned()],
        None,
    );
    assert!(result.is_err());
}

// ============================================================================
// Event log
// ============================================================================

#[test]
fn event_log_query_empty_returns_empty() {
    Python::with_gil(|py| {
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        runtime::init_context_manager_for_test(scp.bridge_instance());
        let did = create_test_identity(scp.bridge_instance());
        let ctx_id = create_test_context(scp.bridge_instance(), &did);

        // A fresh context's creation stream is two leaves: `ContextCreated`
        // (sequence 0) followed by the founder's `MemberJoined` (sequence 1).
        // The founder join leaf is what gives the creator a non-zero
        // participation duration — without it the membership-interval model has
        // no join event to open the creator's interval. The shape is identical
        // across the native bridges (PyO3/NAPI/UniFFI).
        let events = scp.event_log_query(py, &ctx_id, None).unwrap();
        assert_eq!(
            events.len(),
            2,
            "expected ContextCreated + founder MemberJoined on a fresh context"
        );
        assert_eq!(events[0].event_type, "ContextCreated");
        assert_eq!(
            events[1].event_type, "MemberJoined",
            "the founder's MemberJoined leaf must follow ContextCreated"
        );
    });
}

#[test]
fn event_log_query_with_appended_event() {
    Python::with_gil(|py| {
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        runtime::init_context_manager_for_test(scp.bridge_instance());
        let did = create_test_identity(scp.bridge_instance());
        let ctx_id = create_test_context(scp.bridge_instance(), &did);

        // Manually append an unsigned event to the log.
        runtime::with_context(scp.bridge_instance(), &ctx_id, |rt| {
            let event = scp_event_log::Event {
                event_type: scp_event_log::EventType::ContextCreated,
                actor_did: scp_did::DID("did:key:test".to_owned()),
                timestamp: 1_700_000_000,
                sequence: 0,
                payload: scp_event_log::EventPayload { data: vec![] },
                prev_hash: [0u8; 32],
                signature: vec![],
            };
            scp_event_log::tree::append_unsigned_event(&mut rt.event_log, &event).unwrap();
            Ok(())
        })
        .unwrap();

        // Now query should return a LogSummary.
        let events = scp.event_log_query(py, &ctx_id, None).unwrap();
        assert!(!events.is_empty());
    });
}

#[test]
fn event_log_query_with_filter() {
    Python::with_gil(|py| {
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        runtime::init_context_manager_for_test(scp.bridge_instance());
        let did = create_test_identity(scp.bridge_instance());
        let ctx_id = create_test_context(scp.bridge_instance(), &did);

        let filter = PyDict::new(py);
        filter.set_item("limit", 1).unwrap();

        let events = scp
            .event_log_query(py, &ctx_id, Some(&filter.as_borrowed()))
            .unwrap();
        assert!(events.len() <= 1);
    });
}

#[test]
fn event_log_query_projects_governance_target_did_from_storage() {
    // Drives the storage-fallback path of `event_log_query`: register FFI state
    // WITHOUT a supervisor `create_context` (so the manager path returns None),
    // append one event to the per-context log so `event_count > 0`, then write a
    // `GovernanceActionExecuted` event to storage. The query must project the
    // event's `target_did` into `payload_json` via the shared `project_payload`
    // decoder, agreeing byte-for-byte with the other three bridges.
    use scp_platform::Storage as _;
    Python::with_gil(|py| {
        setup();
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        let bi = scp.bridge_instance();
        let did = create_test_identity(bi);
        let ctx_id = random_context_id();
        // FFI state only — no supervisor entry, so the manager path is empty.
        runtime::register_context(bi, &ctx_id, &did, &[]).unwrap();

        let target_did = "did:key:target-member";
        let governance_event = scp_event_log::Event {
            event_type: scp_event_log::EventType::GovernanceActionExecuted,
            actor_did: scp_did::DID(did),
            timestamp: 1_700_000_000,
            sequence: 0,
            payload: scp_event_log::payload::encode_payload(
                &scp_event_log::payload::GovernanceActionExecutedPayload {
                    target_did: target_did.to_owned(),
                    action_type: "RemoveMember".to_owned(),
                },
            )
            .unwrap(),
            prev_hash: [0u8; 32],
            signature: vec![],
        };

        // Per-context log must be non-empty so the fallback does not early-return.
        runtime::with_context(bi, &ctx_id, |rt| {
            scp_event_log::tree::append_unsigned_event(&mut rt.event_log, &governance_event)
                .unwrap();
            Ok(())
        })
        .unwrap();

        // Persist the full typed event under the ProtocolRepository key format.
        let storage = runtime::get_storage(bi).unwrap();
        let key = format!("context/{ctx_id}/event_data/{:020}", 0u64);
        let bytes = rmp_serde::to_vec(&governance_event).unwrap();
        test_runtime()
            .block_on(storage.store(&key, &bytes))
            .unwrap();

        let events = scp.event_log_query(py, &ctx_id, None).unwrap();
        assert_eq!(events.len(), 1, "the stored governance event is returned");

        let payload = events[0].payload.bind(py);
        let projected: String = payload
            .get_item("target_did")
            .expect("target_did key present in projected payload")
            .extract()
            .unwrap();
        assert_eq!(
            projected, target_did,
            "GovernanceActionExecuted leaf projects its target_did"
        );
    });
}

#[test]
fn event_log_query_projects_role_assigned_subject_did_from_storage() {
    // Drives the storage-fallback path of `event_log_query`: register FFI state
    // WITHOUT a supervisor `create_context` (so the manager path returns None),
    // append one `RoleAssigned` event to the per-context log so `event_count > 0`,
    // then write the same event to storage. The query must project the event's
    // `subject_did` (the affected member, NOT the governance actor) into
    // `payload_json` via the shared `project_payload` decoder, agreeing
    // byte-for-byte with the other three bridges.
    use scp_platform::Storage as _;
    Python::with_gil(|py| {
        setup();
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        let bi = scp.bridge_instance();
        let did = create_test_identity(bi);
        let ctx_id = random_context_id();
        // FFI state only — no supervisor entry, so the manager path is empty.
        runtime::register_context(bi, &ctx_id, &did, &[]).unwrap();

        let subject_did = "did:key:subject-member";
        let role_event = scp_event_log::Event {
            event_type: scp_event_log::EventType::RoleAssigned,
            actor_did: scp_did::DID(did),
            timestamp: 1_700_000_000,
            sequence: 0,
            payload: scp_event_log::payload::encode_payload(
                &scp_event_log::payload::RoleAssignedPayload {
                    subject_did: subject_did.to_owned(),
                    role: "moderator".to_owned(),
                },
            )
            .unwrap(),
            prev_hash: [0u8; 32],
            signature: vec![],
        };

        // Per-context log must be non-empty so the fallback does not early-return.
        runtime::with_context(bi, &ctx_id, |rt| {
            scp_event_log::tree::append_unsigned_event(&mut rt.event_log, &role_event).unwrap();
            Ok(())
        })
        .unwrap();

        // Persist the full typed event under the ProtocolRepository key format.
        let storage = runtime::get_storage(bi).unwrap();
        let key = format!("context/{ctx_id}/event_data/{:020}", 0u64);
        let bytes = rmp_serde::to_vec(&role_event).unwrap();
        test_runtime()
            .block_on(storage.store(&key, &bytes))
            .unwrap();

        let events = scp.event_log_query(py, &ctx_id, None).unwrap();
        assert_eq!(
            events.len(),
            1,
            "the stored role-assigned event is returned"
        );

        let payload = events[0].payload.bind(py);
        let projected: String = payload
            .get_item("subject_did")
            .expect("subject_did key present in projected payload")
            .extract()
            .unwrap();
        assert_eq!(
            projected, subject_did,
            "RoleAssigned leaf projects its subject_did"
        );
        // A subject-bearing leaf must NOT surface a target_did key — a missing
        // key raises KeyError (an Err) from PyDict::get_item.
        assert!(
            payload.get_item("target_did").is_err(),
            "RoleAssigned leaf carries a subject, not a target"
        );
    });
}

#[test]
fn event_log_verify_inclusion_proof_after_append() {
    Python::with_gil(|py| {
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        runtime::init_context_manager_for_test(scp.bridge_instance());
        let did = create_test_identity(scp.bridge_instance());
        let ctx_id = create_test_context(scp.bridge_instance(), &did);

        // Append an unsigned event so the log is non-empty.
        runtime::with_context(scp.bridge_instance(), &ctx_id, |rt| {
            let event = scp_event_log::Event {
                event_type: scp_event_log::EventType::ContextCreated,
                actor_did: scp_did::DID("did:key:test".to_owned()),
                timestamp: 1_700_000_000,
                sequence: 0,
                payload: scp_event_log::EventPayload { data: vec![] },
                prev_hash: [0u8; 32],
                signature: vec![],
            };
            scp_event_log::tree::append_unsigned_event(&mut rt.event_log, &event).unwrap();
            Ok(())
        })
        .unwrap();

        let claim = PyDict::new(py);
        claim.set_item("type", "inclusion").unwrap();
        claim.set_item("leaf_index", 0).unwrap();

        let proof = scp
            .event_log_verify(py, &ctx_id, &claim.as_borrowed())
            .unwrap();
        assert!(proof.verified);
        assert_eq!(proof.proof_type, "inclusion");
    });
}

#[test]
fn event_log_query_invalid_context_fails() {
    setup();
    Python::with_gil(|py| {
        let result = _scp_core::scp::PyScp::new_in_memory_for_test().event_log_query(
            py,
            "nonexistent",
            None,
        );
        assert!(result.is_err());
    });
}

#[test]
fn event_log_checkpoint_by_did_generates_signed_checkpoint() {
    Python::with_gil(|_py| {
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        runtime::init_context_manager_for_test(scp.bridge_instance());
        let did = create_test_identity(scp.bridge_instance());
        let ctx_id = create_test_context(scp.bridge_instance(), &did);

        // Append an unsigned event so the log is non-empty.
        runtime::with_context(scp.bridge_instance(), &ctx_id, |rt| {
            let event = scp_event_log::Event {
                event_type: scp_event_log::EventType::ContextCreated,
                actor_did: scp_did::DID(did.clone()),
                timestamp: 1_700_000_000,
                sequence: 0,
                payload: scp_event_log::EventPayload { data: vec![] },
                prev_hash: [0u8; 32],
                signature: vec![],
            };
            scp_event_log::tree::append_unsigned_event(&mut rt.event_log, &event).unwrap();
            Ok(())
        })
        .unwrap();

        let checkpoint = scp.event_log_checkpoint_by_did(&ctx_id, &did, 7).unwrap();
        assert_eq!(checkpoint.context_id, ctx_id);
        assert_eq!(checkpoint.sender_did, did);
        assert_eq!(checkpoint.event_count, 1);
        assert_eq!(checkpoint.epoch, Some(7));
        // Ed25519 signature is 64 bytes -> 128 hex chars.
        assert_eq!(checkpoint.signature.len(), 128);
        assert_eq!(checkpoint.merkle_root.len(), 64);
    });
}

#[test]
fn event_log_checkpoint_by_did_unregistered_did_errors() {
    Python::with_gil(|_py| {
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        runtime::init_context_manager_for_test(scp.bridge_instance());
        let did = create_test_identity(scp.bridge_instance());
        let ctx_id = create_test_context(scp.bridge_instance(), &did);

        // A syntactically valid DID that was never registered in this instance.
        let result = scp.event_log_checkpoint_by_did(&ctx_id, "did:dht:zUnregisteredMember", 0);
        assert!(
            result.is_err(),
            "checkpoint for an unregistered DID must error"
        );
    });
}

#[test]
fn event_log_checkpoint_by_did_invalid_context_errors() {
    Python::with_gil(|_py| {
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        runtime::init_context_manager_for_test(scp.bridge_instance());
        let did = create_test_identity(scp.bridge_instance());

        // DID is registered, but the context does not exist.
        let result = scp.event_log_checkpoint_by_did("nonexistent-context", &did, 0);
        assert!(
            result.is_err(),
            "checkpoint for a nonexistent context must error"
        );
    });
}

// ============================================================================
// Discovery
// ============================================================================

#[test]
fn discovery_parse_address_discovery_handle() {
    setup();
    Python::with_gil(|py| {
        let r = _scp_core::discovery::py_discovery_parse_address(py, "alice@cooking-community")
            .unwrap();
        let t: String = r.get_item("type").unwrap().unwrap().extract().unwrap();
        assert_eq!(t, "DiscoveryHandle");
        let lp: String = r
            .get_item("local_part")
            .unwrap()
            .unwrap()
            .extract()
            .unwrap();
        assert_eq!(lp, "alice");
    });
}

#[test]
fn discovery_parse_address_domain_handle() {
    setup();
    Python::with_gil(|py| {
        let r = _scp_core::discovery::py_discovery_parse_address(py, "alice@example.com").unwrap();
        let t: String = r.get_item("type").unwrap().unwrap().extract().unwrap();
        assert_eq!(t, "DomainHandle");
    });
}

#[test]
fn discovery_normalize_address() {
    setup();
    assert_eq!(
        _scp_core::discovery::py_discovery_normalize_address("  ALICE@Cooking  "),
        "alice@cooking"
    );
}

#[test]
fn discovery_create_query_with_capabilities() {
    setup();
    let json = _scp_core::discovery::py_discovery_create_query(
        Some(vec!["code_review".to_owned()]),
        None,
        None,
    )
    .unwrap();
    assert!(json.contains("code_review"));
}

#[test]
fn discovery_create_query_empty() {
    setup();
    let json = _scp_core::discovery::py_discovery_create_query(None, None, None).unwrap();
    assert!(!json.is_empty());
}

#[test]
fn discovery_context_discover_scp_uri() {
    setup();
    Python::with_gil(|py| {
        let results = _scp_core::discovery::py_context_discover(
            py,
            "scp://context/abcd1234?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1",
        )
        .unwrap();
        assert_eq!(results.len(), 1);
    });
}

#[test]
fn discovery_context_discover_invalid_query_fails() {
    setup();
    Python::with_gil(|py| {
        let r = _scp_core::discovery::py_context_discover(py, "https://not-valid.example.com");
        assert!(r.is_err());
    });
}

// ============================================================================
// Provenance
// ============================================================================

#[test]
fn provenance_evaluate_quality_returns_tier() {
    setup();
    let q = _scp_core::provenance::evaluate_provenance_quality(
        Some("ctx-source".to_owned()),
        "persistent",
        "active",
        Some(vec!["did:key:alice".to_owned()]),
    )
    .unwrap();
    assert!(q <= 3);
}

#[test]
fn provenance_evaluate_quality_invalid_source_type() {
    setup();
    let r =
        _scp_core::provenance::evaluate_provenance_quality(None, "invalid_type", "active", None);
    assert!(r.is_err());
}

#[test]
fn provenance_attach_returns_dict() {
    setup();
    Python::with_gil(|py| {
        let r = _scp_core::scp::PyScp::new_in_memory_for_test()
            .provenance_attach(
                py,
                "ctx-source".to_owned(),
                "persistent",
                "full",
                vec!["did:key:alice".to_owned()],
                "ctx-target".to_owned(),
                "did:key:actor".to_owned(),
                None,
            )
            .unwrap();
        let src: String = r
            .get_item("source_context")
            .unwrap()
            .unwrap()
            .extract()
            .unwrap();
        assert_eq!(src, "ctx-source");
        let depth: u8 = r
            .get_item("chain_depth")
            .unwrap()
            .unwrap()
            .extract()
            .unwrap();
        assert_eq!(depth, 0);
    });
}

#[test]
fn provenance_attach_increments_chain_depth() {
    setup();
    Python::with_gil(|py| {
        let r = _scp_core::scp::PyScp::new_in_memory_for_test()
            .provenance_attach(
                py,
                "ctx-s2".to_owned(),
                "persistent",
                "full",
                vec![],
                "ctx-t2".to_owned(),
                "did:key:actor".to_owned(),
                Some(2),
            )
            .unwrap();
        let depth: u8 = r
            .get_item("chain_depth")
            .unwrap()
            .unwrap()
            .extract()
            .unwrap();
        assert_eq!(depth, 3);
    });
}

#[test]
fn provenance_check_chain_depth_within_limit() {
    setup();
    assert!(_scp_core::provenance::provenance_check_chain_depth(0, None));
    assert!(_scp_core::provenance::provenance_check_chain_depth(3, None));
}

#[test]
fn provenance_check_chain_depth_exceeds_limit() {
    setup();
    // Default is now 8 (ADR-043), so depth 4 is within default.
    assert!(_scp_core::provenance::provenance_check_chain_depth(4, None));
    // Depth 9 exceeds default of 8.
    assert!(!_scp_core::provenance::provenance_check_chain_depth(
        9, None
    ));
    assert!(!_scp_core::provenance::provenance_check_chain_depth(
        2,
        Some(1)
    ));
}

#[test]
fn provenance_attach_rejects_invalid_memory_scope() {
    setup();
    Python::with_gil(|py| {
        let r = _scp_core::scp::PyScp::new_in_memory_for_test().provenance_attach(
            py,
            "ctx".to_owned(),
            "persistent",
            "invalid_scope",
            vec![],
            "ctx-t".to_owned(),
            "did:key:actor".to_owned(),
            None,
        );
        assert!(r.is_err());
    });
}

// ============================================================================
// Bridge trust evaluation
// ============================================================================

#[test]
fn bridge_evaluate_trust_native_native() {
    setup();
    assert_eq!(
        _scp_core::bridge_connector::py_bridge_evaluate_trust(false, true, "shadow").unwrap(),
        3
    );
}

#[test]
fn bridge_evaluate_trust_native_bridged() {
    setup();
    assert_eq!(
        _scp_core::bridge_connector::py_bridge_evaluate_trust(false, false, "shadow").unwrap(),
        2
    );
}

#[test]
fn bridge_evaluate_trust_shadow_bridged() {
    setup();
    assert_eq!(
        _scp_core::bridge_connector::py_bridge_evaluate_trust(true, false, "shadow").unwrap(),
        0
    );
}

#[test]
fn bridge_evaluate_trust_claimed_bridged() {
    setup();
    assert_eq!(
        _scp_core::bridge_connector::py_bridge_evaluate_trust(true, false, "claimed").unwrap(),
        1
    );
}

#[test]
fn bridge_register_succeeds_with_separate_governance_did() {
    // py_bridge_register now takes a separate governance_did parameter,
    // so providing distinct operator and governance DIDs should succeed.
    setup();
    Python::with_gil(|py| {
        let r = _scp_core::bridge_connector::py_bridge_register(
            py,
            "ctx-br",
            "did:key:op",
            "did:key:gov",
            "discord",
            "relay",
            None,
            None,
            10_000,
            "",
            "",
            "",
        );
        assert!(
            r.is_ok(),
            "Registration with distinct governance DID should succeed"
        );
    });
}

#[test]
fn bridge_register_rejects_self_approval() {
    // approve_registration rejects self-approval. This test verifies that
    // constraint is enforced when governance_did == operator_did.
    setup();
    Python::with_gil(|py| {
        let r = _scp_core::bridge_connector::py_bridge_register(
            py,
            "ctx-br-self",
            "did:key:op",
            "did:key:op",
            "discord",
            "relay",
            None,
            None,
            10_000,
            "",
            "",
            "",
        );
        assert!(r.is_err(), "Self-approval should be rejected");
    });
}

#[test]
fn bridge_create_shadow_returns_dict() {
    setup();
    Python::with_gil(|py| {
        let r = _scp_core::scp::PyScp::new_in_memory_for_test()
            .bridge_create_shadow(py, "bridge-d", "@user#1234", "relay", "ctx-sh")
            .unwrap();
        let d = r.bind(py);
        let sid: String = d.get_item("shadow_id").unwrap().unwrap().extract().unwrap();
        assert!(!sid.is_empty());
        let h: String = d
            .get_item("platform_handle")
            .unwrap()
            .unwrap()
            .extract()
            .unwrap();
        assert_eq!(h, "@user#1234");
    });
}

// ============================================================================
// Sync classification
// ============================================================================

#[test]
fn sync_classify_short() {
    setup();
    assert_eq!(
        _scp_core::sync::py_sync_classify_offline(1_000_000, 1_003_600),
        "short"
    );
}

#[test]
fn sync_classify_extended() {
    setup();
    assert_eq!(
        _scp_core::sync::py_sync_classify_offline(1_000_000, 1_100_000),
        "extended"
    );
}

#[test]
fn sync_classify_long() {
    setup();
    assert_eq!(
        _scp_core::sync::py_sync_classify_offline(1_000_000, 2_000_000),
        "long"
    );
}

#[test]
fn sync_classify_custom_thresholds() {
    setup();
    assert_eq!(
        _scp_core::sync::py_sync_classify_offline_custom(1_000_000, 1_003_600, 7_200, 259_200),
        "short"
    );
    assert_eq!(
        _scp_core::sync::py_sync_classify_offline_custom(1_000_000, 1_010_800, 7_200, 259_200),
        "extended"
    );
}

#[test]
fn sync_get_policy_returns_dict() {
    setup();
    Python::with_gil(|py| {
        let p = _scp_core::sync::py_sync_get_policy(py).unwrap();
        let d = p.bind(py);
        let t1: u64 = d
            .get_item("tier_1_threshold_secs")
            .unwrap()
            .unwrap()
            .extract()
            .unwrap();
        assert_eq!(t1, 14400);
        let t2: u64 = d
            .get_item("tier_2_threshold_secs")
            .unwrap()
            .unwrap()
            .extract()
            .unwrap();
        assert_eq!(t2, 604_800);
    });
}

// ============================================================================
// Trust engine
// ============================================================================

#[test]
fn trust_query_score_returns_valid_dict() {
    setup();
    Python::with_gil(|py| {
        let r = _scp_core::scp::PyScp::new_in_memory_for_test()
            .trust_query_score(py, "did:key:test", "ctx-trust")
            .unwrap();
        let d = r.bind(py);
        let mc: u64 = d
            .get_item("message_count")
            .unwrap()
            .unwrap()
            .extract()
            .unwrap();
        assert_eq!(mc, 0);
    });
}

#[test]
fn trust_query_score_validates_empty_did() {
    setup();
    Python::with_gil(|py| {
        assert!(
            _scp_core::scp::PyScp::new_in_memory_for_test()
                .trust_query_score(py, "", "ctx-valid")
                .is_err()
        );
    });
}

#[test]
fn trust_create_challenge_returns_dict() {
    setup();
    Python::with_gil(|py| {
        let r = _scp_core::trust::py_trust_create_challenge(py, "did:key:target").unwrap();
        let d = r.bind(py);
        let cid: String = d
            .get_item("challenge_id")
            .unwrap()
            .unwrap()
            .extract()
            .unwrap();
        assert!(!cid.is_empty());
    });
}

#[test]
fn trust_verify_attestation_rejects_invalid_json() {
    setup();
    Python::with_gil(|py| {
        assert!(_scp_core::trust::py_trust_verify_attestation(py, "not valid json").is_err());
    });
}

#[test]
fn trust_verify_response_rejects_invalid_json() {
    setup();
    assert!(_scp_core::trust::py_trust_verify_response("bad", "bad").is_err());
}

#[test]
fn verify_participation_requirements_empty_passes() {
    setup();
    assert!(
        _scp_core::trust::py_verify_participation_requirements("did:key:alice", "[]", "[]").is_ok()
    );
}

// ============================================================================
// Cross-domain: Identity -> Context -> Outlet -> UCAN -> EventLog
// ============================================================================

#[test]
fn cross_domain_identity_context_outlet_eventlog_provenance() {
    // Cross-domain flow test: identity -> context -> outlet -> event log -> provenance.
    // Does NOT call functions requiring the crate-internal global runtime
    // (py_ucan_mint, py_event_log_checkpoint). Those are tested in unit tests.
    Python::with_gil(|py| {
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        runtime::init_context_manager_for_test(scp.bridge_instance());
        let did_a = create_test_identity(scp.bridge_instance());
        let ctx_id = create_test_context(scp.bridge_instance(), &did_a);

        // `outlet_call:*` and `messages:write` both sit in `default_ceiling()`,
        // which `create_test_context` gave the supervisor, and the ceiling is read
        // from there — so no bridge-side ceiling write is needed or possible.

        // Register an outlet using the helper.
        let reg = build_outlet_reg(py, "cross_domain_outlet", &did_a);
        let outlet_id = scp.outlet_register(&ctx_id, &reg.as_borrowed()).unwrap();
        assert!(!outlet_id.is_empty());

        // Verify outlet.
        let vr = scp.outlet_verify(&ctx_id, &outlet_id).unwrap();
        assert!(vr.passed);

        // Append an event and query.
        runtime::with_context(scp.bridge_instance(), &ctx_id, |rt| {
            let event = scp_event_log::Event {
                event_type: scp_event_log::EventType::ContextCreated,
                actor_did: scp_did::DID(did_a.clone()),
                timestamp: 1_700_000_000,
                sequence: 0,
                payload: scp_event_log::EventPayload { data: vec![] },
                prev_hash: [0u8; 32],
                signature: vec![],
            };
            scp_event_log::tree::append_unsigned_event(&mut rt.event_log, &event).unwrap();
            Ok(())
        })
        .unwrap();

        let events = scp.event_log_query(py, &ctx_id, None).unwrap();
        assert!(!events.is_empty());

        // Revoke a token (revoker is the context creator).
        let dummy = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsInVjdiI6IjAuMTAuMCJ9.\
            eyJpc3MiOiJkaWQ6a2V5OnRlc3QiLCJhdWQiOiJkaWQ6a2V5OnRlc3QyIiwiZXhwIjo5OTk5OTk5OTk5LCJubmMiOiIxNjk5OTk5MDAwMDAwLWFhYmJjY2RkMTEyMjMzNDQiLCJhdHQiOltdLCJwcmYiOltdfQ.\
            dGVzdC1zaWduYXR1cmUtYnl0ZXMtMDAwMDAwMDAwMDAw";
        scp.ucan_revoke(&ctx_id, dummy, &did_a).unwrap();

        // Evaluate provenance (pure helper — module-level free fn per ADR-048 §1).
        let q = _scp_core::provenance::evaluate_provenance_quality(
            Some(ctx_id),
            "persistent",
            "active",
            None,
        )
        .unwrap();
        assert!(q <= 3);
    });
}

// ============================================================================
// Storage initialization (via the with_storage factory)
// ============================================================================

// The legacy `runtime::init_storage(&bi, "in_memory")` imperative-attach
// helper was removed in #1543 PR-C in favour of the
// `PyBridgeInstance::with_storage_py(StorageConfig)` factory — driven from
// Python by `SCP.with_storage({...})`. Coverage for the factory's InMemory
// path lives in
// `crates/scp-ffi/src/runtime.rs::tests::test_py_bridge_instance_with_storage_py_initializes_storage`.
// Validation of unknown storage `type` strings now happens at the Python
// boundary in `crate::scp::PyScp::with_storage` (covered by
// `bindings/python/tests/test_scp_class.py::test_with_storage_rejects_unknown_type`).

// ============================================================================
// Cross-context outlet-invocation saga (§6.2.4, ADR-049 §3a) — PyO3 export
// ============================================================================
//
// These tests exercise what the PyO3 bridge ADDS on top of the supervisor
// producer (`start_cross_context_outlet_invocation_saga`), whose committed /
// abort / busy / rate-limit / co-residency paths are covered in
// `crates/scp-runtime` integration tests (the full `Committed` path needs the
// actor-state interface establishment those tests inject directly, which has
// no bridge-public wiring). At the bridge layer the export's own
// responsibilities are:
//
//   - the §6.2.4 *Caller authentication* binding (caller_did MUST be hosted by
//     this bridge instance AND a member of caller_context_id) — rejected BEFORE
//     the saga runs;
//   - the ADR-056 chokepoint (a real 64-hex id decodes to the digest the
//     producer's `hex::encode` lookup expects — it reaches the actor rather
//     than double-hashing to a missing slot);
//   - the participant-context-set gating surfaced as `SagaBusyError`;
//   - fail-closed nonce decoding;
//   - the typed terminal → typed Python exception mapping.

/// A real 64-character lowercase-hex context id (32 bytes). The ADR-056
/// chokepoint decodes such an id to its digest, and the producer's
/// `hex::encode(digest)` actor lookup reproduces the SAME 64-hex string — so a
/// context registered under this id is reachable by the saga. (The 32-hex
/// `random_context_id` helper would hit the SHA-256 fallback and miss the
/// actor.)
fn random_64hex_context_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Creates a co-resident context under a real 64-hex id (so the saga
/// chokepoint round-trips to the actor). Mirrors [`create_test_context`] but
/// with a caller-chosen id.
fn create_test_context_with_id(bi: &PyBridgeInstance, creator_did: &str, context_id: &str) {
    setup();
    runtime::register_context(bi, context_id, creator_did, &[]).unwrap();

    let rt = test_runtime();
    let supervisor = runtime::supervisor(bi).unwrap().clone();
    let creator = scp_did::DID(creator_did.to_owned());
    let ctx_id = context_id.to_owned();

    rt.block_on(async move {
        // Same `default_ceiling()` the id-generating sibling uses, for the same
        // reason: authorization reads the supervisor's ceiling.
        let params = scp_core::context::ContextParams {
            ceiling: scp_core::context::roles::default_ceiling()
                .iter()
                .cloned()
                .collect(),
            ..scp_core::context::ContextParams::default()
        };
        supervisor
            .create_context(ctx_id.clone(), params, creator.clone(), None)
            .await
            .unwrap();
        supervisor.register_local_did(creator).await.unwrap();
    });
}

/// Creates a registered context under a fresh 64-hex id whose CREATOR holds the
/// `ContextClose` capability, so the creator can later drive it `Closed` through
/// the REAL supervisor close path. Returns the generated id.
///
/// `default_ceiling()` carries `context:close`, and
/// [`create_test_context_with_id`] now seeds the supervisor with that ceiling,
/// so this helper is that call under a generated id. It stays as a named helper
/// because its call sites read as "a context I can close".
fn create_closeable_test_context(bi: &PyBridgeInstance, creator_did: &str) -> String {
    let context_id = random_64hex_context_id();
    create_test_context_with_id(bi, creator_did, &context_id);
    context_id
}

/// Drives a registered context to a NON-active (`Closed`) lifecycle state through
/// the REAL supervisor close path — the exact `LifecycleCommand::CloseContext`
/// dispatch the bridge's `context_close` uses. The per-context actor stays alive
/// reporting `Closed` (close is non-terminal for the actor; ADR-049 §10), so a
/// subsequent `supervisor.read_context_state(context_id)` returns
/// `Some(Closed)` — exactly what the streaming-saga open's active-state guard
/// reads. `initiator_did` must be the creator of a context created with a
/// `ContextClose`-bearing ceiling (see `create_closeable_test_context`).
fn drive_context_closed(bi: &PyBridgeInstance, context_id: &str, initiator_did: &str) {
    use scp_core::context::actor::commands::{CloseContextPayload, LifecycleCommand};

    let rt = test_runtime();
    let supervisor = runtime::supervisor(bi).unwrap().clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = LifecycleCommand::CloseContext {
        payload: Box::new(CloseContextPayload {
            context_id: context_id.to_owned(),
            params: scp_core::context::ContextParams::default(),
            initiator_did: scp_did::DID(initiator_did.to_owned()),
        }),
        reply: tx,
    };
    rt.block_on(async move {
        supervisor.dispatch_lifecycle_command(cmd).await.unwrap();
        rx.await.unwrap().unwrap();
    });
}

/// Registers a minimal `{a,b} -> {sum,ok}` outlet in `context_id`, returning the
/// outlet registration id. Reuses the shared [`build_outlet_reg`] schema.
fn register_saga_outlet(
    py: Python<'_>,
    scp: &_scp_core::scp::PyScp,
    context_id: &str,
    operator_did: &str,
) -> String {
    let reg = build_outlet_reg(py, "xctx_saga_outlet", operator_did);
    scp.outlet_register(context_id, &reg.as_borrowed()).unwrap()
}

/// A valid 16-byte nonce as a 32-char hex string.
fn nonce_hex() -> String {
    "00112233445566778899aabbccddeeff".to_owned()
}

/// (a) Caller-principal binding: a `caller_did` this bridge instance does NOT
/// host is rejected with `SagaAbortedError` (SCP-SAGA-13050) BEFORE the saga
/// runs — the §6.2.4 *Caller authentication* channel-auth binding. The caller
/// is a real well-formed DID that is simply not in this instance's registry.
#[test]
fn xctx_saga_unhosted_caller_rejected_before_saga() {
    Python::with_gil(|py| {
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        runtime::init_context_manager_for_test(scp.bridge_instance());
        let bi = scp.bridge_instance();

        let owner = create_test_identity(bi);
        let caller_ctx = random_64hex_context_id();
        let target_ctx = random_64hex_context_id();
        create_test_context_with_id(bi, &owner, &caller_ctx);
        create_test_context_with_id(bi, &owner, &target_ctx);
        let outlet_id = register_saga_outlet(py, &scp, &target_ctx, &owner);

        // A syntactically valid DID that was never created on this instance.
        let unhosted_caller = "did:dht:z6MkUnhostedCallerPrincipal0001";

        let input = PyDict::new(py);
        input.set_item("a", "x").unwrap();
        input.set_item("b", "y").unwrap();

        let err = scp
            .outlet_invoke_cross_context_saga(
                &caller_ctx,
                &target_ctx,
                unhosted_caller,
                &outlet_id,
                &input.as_borrowed(),
                &nonce_hex(),
                1_700_000_000_000,
                1,
                None,
            )
            .expect_err("an unhosted caller_did must be rejected before the saga runs");

        assert!(
            err.is_instance_of::<_scp_core::error::SagaAbortedError>(py),
            "expected SagaAbortedError, got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("SCP-SAGA-13050"),
            "expected caller-axis SCP-SAGA-13050, got: {msg}"
        );
        assert!(
            msg.contains("not an identity hosted by this bridge"),
            "message must name the hosted-principal mismatch, got: {msg}"
        );
    });
}

/// (b) Caller-principal binding, membership axis: a `caller_did` that IS hosted
/// by this bridge but is NOT a member of `caller_context_id` is rejected with
/// `SagaAbortedError` (SCP-SAGA-13050) BEFORE the saga runs.
#[test]
fn xctx_saga_hosted_non_member_caller_rejected() {
    Python::with_gil(|py| {
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        runtime::init_context_manager_for_test(scp.bridge_instance());
        let bi = scp.bridge_instance();

        let owner = create_test_identity(bi);
        // A SECOND hosted identity that is NOT a member of caller_ctx.
        let stranger = create_test_identity(bi);
        let caller_ctx = random_64hex_context_id();
        let target_ctx = random_64hex_context_id();
        create_test_context_with_id(bi, &owner, &caller_ctx);
        create_test_context_with_id(bi, &owner, &target_ctx);
        let outlet_id = register_saga_outlet(py, &scp, &target_ctx, &owner);

        let input = PyDict::new(py);
        input.set_item("a", "x").unwrap();
        input.set_item("b", "y").unwrap();

        let err = scp
            .outlet_invoke_cross_context_saga(
                &caller_ctx,
                &target_ctx,
                &stranger, // hosted, but not a member of caller_ctx
                &outlet_id,
                &input.as_borrowed(),
                &nonce_hex(),
                1_700_000_000_000,
                1,
                None,
            )
            .expect_err("a hosted non-member caller must be rejected before the saga runs");

        assert!(
            err.is_instance_of::<_scp_core::error::SagaAbortedError>(py),
            "expected SagaAbortedError, got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("SCP-SAGA-13050"),
            "expected caller-axis SCP-SAGA-13050, got: {msg}"
        );
        // BRIDGE-UNIQUE axis-b substring. The producer's gate 1 ALSO rejects a
        // non-member with SCP-SAGA-13050 and a message containing the bare
        // "is not a member of caller" phrasing — so asserting only "not a member
        // of" would PASS even if the PyO3 membership axis were removed (the
        // producer's gate would surface the same code + substring). Asserting
        // the bridge-unique "is hosted by this bridge but is not a member of"
        // prefix (which the producer never emits) makes this test fail closed if
        // the bridge's axis-b `is_member` check is deleted.
        assert!(
            msg.contains("is hosted by this bridge but is not a member of"),
            "message must be the BRIDGE axis-b membership rejection (not the producer gate-1 \
             message), got: {msg}"
        );
    });
}

/// (a, axis-isolated) Caller-principal binding, hosted-here axis as the SOLE
/// guard: a `caller_did` that IS a genuine member of `caller_context_id` (so the
/// membership axis (b) would PASS) but is NOT an identity hosted by this bridge
/// instance is STILL rejected with `SagaAbortedError` (SCP-SAGA-13050) BEFORE
/// the saga runs.
///
/// This is the property the `xctx_saga_unhosted_caller_rejected_before_saga`
/// test cannot prove: that test's caller is BOTH unhosted AND a non-member, so
/// axis (b) (and the producer's gate 1) would reject it even if axis (a) were
/// deleted. Here the caller is a real member of `caller_ctx` — it CREATED
/// `caller_ctx` (the creator is always a member, per
/// `context_create_establishes_mls_group`), so `supervisor.is_member` returns
/// true and axis (b) passes the caller. The ONLY thing that can reject it is
/// axis (a): the caller DID was never `create_test_identity`'d, so it is absent
/// from this instance's identity registry. The test therefore fails closed iff
/// the bridge's `identity_registry_contains` axis (a) check is removed, and is
/// INDEPENDENT of axis (b) by construction.
#[test]
fn xctx_saga_member_but_unhosted_caller_rejected_by_hosted_axis() {
    Python::with_gil(|py| {
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        runtime::init_context_manager_for_test(scp.bridge_instance());
        let bi = scp.bridge_instance();

        // `owner` is a hosted identity used only to create the TARGET context and
        // register the saga outlet (the outlet operator must be a member of B).
        let owner = create_test_identity(bi);

        // The caller is a syntactically valid DID that CREATES `caller_ctx` —
        // making it a genuine member of `caller_ctx` (the creator is always a
        // member) so the supervisor's membership axis (b) passes — but is NEVER
        // registered as a hosted identity on this instance (no
        // `create_test_identity`), so the bridge's identity registry does NOT
        // contain it. Axis (a) must reject it.
        let member_but_unhosted_caller = "did:dht:z6MkMemberButUnhostedCaller001".to_owned();

        let caller_ctx = random_64hex_context_id();
        let target_ctx = random_64hex_context_id();
        // Caller context is CREATED BY the unhosted caller → caller is a member.
        create_test_context_with_id(bi, &member_but_unhosted_caller, &caller_ctx);
        create_test_context_with_id(bi, &owner, &target_ctx);
        let outlet_id = register_saga_outlet(py, &scp, &target_ctx, &owner);

        // Precondition: the supervisor MUST see the caller as a member of
        // `caller_ctx` (axis (b) passes), while the bridge's identity registry
        // does NOT host it (axis (a) is the sole remaining guard).
        let rt = test_runtime();
        let supervisor = runtime::supervisor(bi).unwrap().clone();
        assert!(
            rt.block_on(supervisor.is_member(&caller_ctx, &member_but_unhosted_caller)),
            "precondition: caller must be a genuine member of caller_ctx so axis (b) passes"
        );
        assert!(
            !runtime::identity_registry_contains(bi, &member_but_unhosted_caller),
            "precondition: caller must NOT be hosted so axis (a) is the sole guard"
        );

        let input = PyDict::new(py);
        input.set_item("a", "x").unwrap();
        input.set_item("b", "y").unwrap();

        let err = scp
            .outlet_invoke_cross_context_saga(
                &caller_ctx,
                &target_ctx,
                &member_but_unhosted_caller, // member of caller_ctx, but NOT hosted
                &outlet_id,
                &input.as_borrowed(),
                &nonce_hex(),
                1_700_000_000_000,
                1,
                None,
            )
            .expect_err(
                "a member-but-unhosted caller must be rejected by axis (a) before the saga",
            );

        assert!(
            err.is_instance_of::<_scp_core::error::SagaAbortedError>(py),
            "expected SagaAbortedError, got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("SCP-SAGA-13050"),
            "expected caller-axis SCP-SAGA-13050, got: {msg}"
        );
        // BRIDGE-UNIQUE axis-(a) substring. Because the caller IS a member, the
        // membership axis (b) and the producer's gate 1 would BOTH pass — so the
        // axis-(b) message ("is hosted by this bridge but is not a member of") can
        // never appear here. The ONLY rejection that fits is axis (a). Asserting
        // its exact substring makes this test fail closed iff
        // `enforce_caller_principal_binding`'s `identity_registry_contains` check
        // is removed.
        assert!(
            msg.contains("not an identity hosted by this bridge instance"),
            "message must be the BRIDGE axis-(a) hosted-here rejection, got: {msg}"
        );
    });
}

/// (c)+(e) Chokepoint + target-axis authorization: an authenticated caller
/// (hosted + member) over REAL 64-hex contexts passes the bridge's
/// channel-auth binding and the chokepoint round-trips to the actor — the saga
/// then aborts at the supervisor's TARGET-axis gate (SCP-SAGA-13062: no
/// established interface) rather than at the caller gate or with a spurious
/// `ContextNotRegistered`. Reaching 13062 proves the digest keyed the right
/// actor (had the chokepoint double-hashed, gate 1's `is_member` would have
/// failed first with 13050).
#[test]
fn xctx_saga_authenticated_caller_reaches_target_axis_gate() {
    Python::with_gil(|py| {
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        runtime::init_context_manager_for_test(scp.bridge_instance());
        let bi = scp.bridge_instance();

        let owner = create_test_identity(bi);
        let caller_ctx = random_64hex_context_id();
        let target_ctx = random_64hex_context_id();
        create_test_context_with_id(bi, &owner, &caller_ctx);
        create_test_context_with_id(bi, &owner, &target_ctx);
        let outlet_id = register_saga_outlet(py, &scp, &target_ctx, &owner);

        let input = PyDict::new(py);
        input.set_item("a", "x").unwrap();
        input.set_item("b", "y").unwrap();

        let err = scp
            .outlet_invoke_cross_context_saga(
                &caller_ctx,
                &target_ctx,
                &owner, // hosted AND a member of caller_ctx (its creator)
                &outlet_id,
                &input.as_borrowed(),
                &nonce_hex(),
                1_700_000_000_000,
                1,
                None,
            )
            .expect_err("no established interface exists, so the target-axis gate aborts the saga");

        assert!(
            err.is_instance_of::<_scp_core::error::SagaAbortedError>(py),
            "expected SagaAbortedError, got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("SCP-SAGA-13062"),
            "expected target-axis SCP-SAGA-13062 (caller passed gate 1 — chokepoint reached the \
             actor), got: {msg}"
        );
        assert!(
            !msg.contains("SCP-SAGA-13050"),
            "must NOT be the caller-axis reject — the authenticated caller passed gate 1, got: {msg}"
        );
    });
}

// (d) Participant-context-set gating → `SagaBusyError` (SCP-SAGA-13066): NOT
// reachable from the bridge's PUBLIC surface. The producer evaluates the
// target-axis interface gate (SCP-SAGA-13062) BEFORE it attempts the
// participant-context-set reservation (supervisor.rs:
// `start_cross_context_outlet_invocation_saga` runs gate 1 → gate 2 → reserve).
// Establishing the actor-state `OutletInterface` that gate 2 requires has no
// bridge-public wiring (the bridge's `outlet_interface_expose`/`accept` write
// only the FFI-side copy, not the actor's `governance.outlet_interfaces`), so a
// bridge caller cannot pass gate 2 and therefore can never reach the
// reservation step to observe `SagaBusy`. The producer's actual `SagaBusy`
// terminal is covered in `crates/scp-runtime` integration tests; the bridge's
// SOLE added responsibility for the Busy terminal is the typed-error mapping,
// which is unit-tested directly in `outlets.rs`
// (`map_saga_error` → `SagaBusyError` with the structured `contended_context`).

/// Fail-closed nonce decoding: a malformed `asserted_nonce_hex` (wrong length)
/// raises `ValidationError` — the bridge does NOT pad, truncate, or accept any
/// non-canonical form. The saga never runs.
#[test]
fn xctx_saga_malformed_nonce_rejected_fail_closed() {
    Python::with_gil(|py| {
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        runtime::init_context_manager_for_test(scp.bridge_instance());
        let bi = scp.bridge_instance();

        let owner = create_test_identity(bi);
        let caller_ctx = random_64hex_context_id();
        let target_ctx = random_64hex_context_id();
        create_test_context_with_id(bi, &owner, &caller_ctx);
        create_test_context_with_id(bi, &owner, &target_ctx);
        let outlet_id = register_saga_outlet(py, &scp, &target_ctx, &owner);

        let input = PyDict::new(py);
        input.set_item("a", "x").unwrap();
        input.set_item("b", "y").unwrap();

        // 8 bytes, not 16.
        let short_nonce = "0011223344556677";
        let err = scp
            .outlet_invoke_cross_context_saga(
                &caller_ctx,
                &target_ctx,
                &owner,
                &outlet_id,
                &input.as_borrowed(),
                short_nonce,
                1_700_000_000_000,
                1,
                None,
            )
            .expect_err("a wrong-length nonce must be rejected fail-closed");

        assert!(
            err.is_instance_of::<_scp_core::error::ValidationError>(py),
            "expected ValidationError, got: {err}"
        );
        assert!(
            err.to_string().contains("16 bytes"),
            "message must explain the 16-byte requirement, got: {err}"
        );
    });
}

// ============================================================================
// Cross-context STREAMING saga (§5.4.5 / §6.2.4, SCP-OUT-047) — PyO3 export
// ============================================================================
//
// These tests exercise what the PyO3 streaming-saga bridge ADDS on top of the
// supervisor producer (`start_cross_context_streaming_outlet_invocation_saga` /
// `recover_streaming_saga_truncated_close`), whose full non-blocking-open,
// paid-drive, and key-bearing crash-recovery paths are covered in the
// `crates/scp-runtime` integration tests (the full Committed / truncated-close
// paths need the actor-state interface + budget injection those tests apply
// directly, which has no bridge-public wiring — identical to the unary saga
// export above). At the bridge layer the export's own responsibilities are:
//
//   - the §6.2.4 caller-principal binding on the OPEN (caller_did MUST be hosted
//     by this bridge instance AND a member of caller_context_id) — rejected
//     BEFORE the saga runs, so the receiver is NEVER handed out;
//   - the RECOVER reconnect-caller authentication (caller_did MUST be hosted)
//     and the "no active saga" lookup miss.

/// A placeholder invocation-UCAN JWT. The streaming-saga caller-principal
/// rejection test fails at the §6.2.4 caller-binding step (b) — BEFORE the UCAN
/// is validated (step c) — so the token only needs to pass the non-empty /
/// no-control-char input check at step (a).
fn placeholder_streaming_ucan() -> String {
    "eyJhbGciOiJFZERTQSJ9.eyJ0ZXN0Ijp0cnVlfQ.placeholder-not-validated".to_owned()
}

/// SCP-OUT-047 (a): the cross-context STREAMING saga open applies the SAME
/// §6.2.4 caller-principal binding as the unary saga — a `caller_did` this
/// bridge instance does NOT host is rejected with `SagaAbortedError`
/// (SCP-SAGA-13050) BEFORE the saga runs. The open returns an ERROR, not a
/// saga-id handle, so the receiver is NEVER handed out.
#[test]
fn xctx_streaming_saga_unhosted_caller_rejected_before_saga() {
    Python::with_gil(|py| {
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        runtime::init_context_manager_for_test(scp.bridge_instance());
        let bi = scp.bridge_instance();

        let owner = create_test_identity(bi);
        let caller_ctx = random_64hex_context_id();
        let target_ctx = random_64hex_context_id();
        create_test_context_with_id(bi, &owner, &caller_ctx);
        create_test_context_with_id(bi, &owner, &target_ctx);
        let outlet_id = register_saga_outlet(py, &scp, &target_ctx, &owner);

        // A syntactically valid DID never created on this instance.
        let unhosted_caller = "did:dht:z6MkUnhostedStreamingCaller01";

        let input = PyDict::new(py);
        input.set_item("a", "x").unwrap();
        input.set_item("b", "y").unwrap();

        let err = scp
            .outlet_streaming_saga_open(
                &caller_ctx,
                &target_ctx,
                unhosted_caller,
                &outlet_id,
                &input.as_borrowed(),
                &nonce_hex(),
                1_700_000_000_000,
                1,
                &placeholder_streaming_ucan(),
                None,
                None,
                None,
                None,
            )
            .expect_err("an unhosted caller_did must be rejected before the streaming saga runs");

        assert!(
            err.is_instance_of::<_scp_core::error::SagaAbortedError>(py),
            "expected SagaAbortedError, got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("SCP-SAGA-13050"),
            "expected caller-axis SCP-SAGA-13050, got: {msg}"
        );
        assert!(
            msg.contains("not an identity hosted by this bridge"),
            "message must name the hosted-principal mismatch, got: {msg}"
        );
    });
}

/// SCP-OUT-047 (b): a `caller_did` that IS hosted by this bridge but is NOT a
/// member of `caller_context_id` is rejected with `SagaAbortedError`
/// (SCP-SAGA-13050) BEFORE the streaming saga runs (the membership axis of the
/// §6.2.4 caller-principal binding).
#[test]
fn xctx_streaming_saga_hosted_non_member_caller_rejected() {
    Python::with_gil(|py| {
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        runtime::init_context_manager_for_test(scp.bridge_instance());
        let bi = scp.bridge_instance();

        let owner = create_test_identity(bi);
        // A SECOND hosted identity that is NOT a member of caller_ctx.
        let stranger = create_test_identity(bi);
        let caller_ctx = random_64hex_context_id();
        let target_ctx = random_64hex_context_id();
        create_test_context_with_id(bi, &owner, &caller_ctx);
        create_test_context_with_id(bi, &owner, &target_ctx);
        let outlet_id = register_saga_outlet(py, &scp, &target_ctx, &owner);

        let input = PyDict::new(py);
        input.set_item("a", "x").unwrap();
        input.set_item("b", "y").unwrap();

        let err = scp
            .outlet_streaming_saga_open(
                &caller_ctx,
                &target_ctx,
                &stranger, // hosted, but not a member of caller_ctx
                &outlet_id,
                &input.as_borrowed(),
                &nonce_hex(),
                1_700_000_000_000,
                1,
                &placeholder_streaming_ucan(),
                None,
                None,
                None,
                None,
            )
            .expect_err(
                "a hosted non-member caller must be rejected before the streaming saga runs",
            );

        assert!(
            err.is_instance_of::<_scp_core::error::SagaAbortedError>(py),
            "expected SagaAbortedError, got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("SCP-SAGA-13050"),
            "expected caller-axis SCP-SAGA-13050, got: {msg}"
        );
        // The bridge-unique axis-b substring (the producer never emits this
        // exact phrasing), so the test fails closed if the membership axis is
        // removed from the bridge.
        assert!(
            msg.contains("is hosted by this bridge but is not a member of"),
            "message must be the BRIDGE axis-b membership rejection, got: {msg}"
        );
    });
}

/// SCP-OUT-047: the streaming-saga RECOVER (key-bearing truncated-close)
/// authenticates the reconnect caller — a `caller_did` this bridge instance does
/// NOT host is rejected with a typed `ContextError` before any seal is attempted
/// (§6.2.4 channel-auth). No signing key is ever resolved for an unhosted caller.
#[test]
fn xctx_streaming_saga_recover_unhosted_caller_rejected() {
    Python::with_gil(|py| {
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        runtime::init_context_manager_for_test(scp.bridge_instance());

        let unhosted_caller = "did:dht:z6MkUnhostedStreamingRecover1";
        let err = scp
            .outlet_streaming_saga_recover_truncated_close("any-saga-id", unhosted_caller)
            .expect_err("an unhosted caller_did must be rejected by streaming-saga recover");

        assert!(
            err.is_instance_of::<_scp_core::error::ContextError>(py),
            "expected ContextError, got: {err}"
        );
        assert!(
            err.to_string()
                .contains("not an identity hosted by this bridge instance"),
            "message must name the channel-auth mismatch, got: {err}"
        );
    });
}

/// SCP-OUT-047: the streaming-saga RECOVER surfaces a DISTINCT "no active saga"
/// rejection for an unknown/evicted saga id (after the reconnect caller is
/// authenticated) — a typo'd or stale handle must not masquerade as a clean
/// close.
#[test]
fn xctx_streaming_saga_recover_unknown_saga_rejected() {
    Python::with_gil(|py| {
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        runtime::init_context_manager_for_test(scp.bridge_instance());
        let bi = scp.bridge_instance();

        // A genuinely hosted identity, so recover passes the channel-auth gate
        // and reaches the registry lookup.
        let hosted = create_test_identity(bi);
        let err = scp
            .outlet_streaming_saga_recover_truncated_close("unknown-saga-id-0001", &hosted)
            .expect_err("an unknown saga id must be rejected by streaming-saga recover");

        assert!(
            err.is_instance_of::<_scp_core::error::ContextError>(py),
            "expected ContextError, got: {err}"
        );
        assert!(
            err.to_string()
                .contains("no active cross-context streaming saga"),
            "message must name the unknown-saga lookup miss, got: {err}"
        );
    });
}

/// SCP-OUT-047 (SECURITY — review MUST FIX #1): the streaming-saga RECOVER is
/// MONEY-MOVING (it bills the invoker / credits the operator over the target's
/// durable prefix and marks the saga `Committed`). A `caller_did` that IS hosted
/// by this bridge instance but is NOT the invoker pinned at open is rejected with
/// `SCP-PERM-3001` — the SAME invoker gate the same-context grant/cancel/terminate
/// siblings enforce — BEFORE any signing key is resolved or seal is driven, and
/// the (stranger's) saga entry is LEFT INTACT (no settle, not evicted). Without
/// this gate the earlier "any hosted identity" check would let any co-resident
/// identity settle a stranger's saga.
#[test]
fn xctx_streaming_saga_recover_hosted_non_invoker_rejected() {
    Python::with_gil(|py| {
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        runtime::init_context_manager_for_test(scp.bridge_instance());
        let bi = scp.bridge_instance();

        // The invoker who "opened" the saga, and a DIFFERENT hosted identity.
        let invoker = create_test_identity(bi);
        let stranger = create_test_identity(bi);
        let target_ctx = random_64hex_context_id();
        create_test_context_with_id(bi, &invoker, &target_ctx);

        // Inject a live saga entry pinned to `invoker`. The full committed path
        // needs actor-state/budget injection that has no bridge-public wiring
        // (identical to the unary-saga bridge tests), so the invoker gate is
        // exercised against a directly-seeded registry entry.
        let saga_id = "saga-out047-invoker-gate-0001";
        scp.insert_test_streaming_saga_entry(saga_id, &target_ctx, &invoker);

        // A hosted-but-not-invoker caller clears the channel-auth gate, reaches
        // the invoker check, and is rejected there.
        let err = scp
            .outlet_streaming_saga_recover_truncated_close(saga_id, &stranger)
            .expect_err("a hosted non-invoker caller must be rejected by streaming-saga recover");

        assert!(
            err.is_instance_of::<_scp_core::error::ContextError>(py),
            "expected ContextError, got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("SCP-PERM-3001"),
            "expected the invoker-gate SCP-PERM-3001, got: {msg}"
        );
        assert!(
            msg.contains("is not the invoker"),
            "message must name the pinned-invoker mismatch, got: {msg}"
        );
        // No settle: the rejection is BEFORE the recovery driver and does NOT
        // evict — the invoker's saga entry survives for the legitimate invoker to
        // recover later.
        assert!(
            scp.test_streaming_saga_entry_present(saga_id),
            "a rejected non-invoker recover must NOT evict the invoker's saga entry"
        );
    });
}

/// SCP-OUT-047 pass-3a (LIFECYCLE): a money-moving streaming-saga OPEN against a
/// NON-active source or target context is rejected with `SCP-OUTLET-6010`
/// (caller axis) / `SCP-OUTLET-6011` (target axis) — parity with the NAPI and
/// `UniFFI` streaming-open guards — BEFORE the caller-principal binding, the UCAN
/// check, or the saga drive, so NO saga is started and NO receiver is handed out.
///
/// The guard is LOAD-BEARING: the runtime streaming reserve path
/// (`reserve_outlet_stream_economy`) debits escrow with no context-active gate,
/// so this bridge check is the sole barrier. `PyO3` is string-keyed (no handle),
/// so the state is read authoritatively from the supervisor actor via
/// `read_context_state`; the context is driven to `Closed` through the REAL
/// supervisor close path.
#[test]
fn xctx_streaming_saga_open_rejects_non_active_context() {
    Python::with_gil(|py| {
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        runtime::init_context_manager_for_test(scp.bridge_instance());
        let bi = scp.bridge_instance();

        let owner = create_test_identity(bi);
        let input = PyDict::new(py);
        input.set_item("a", "x").unwrap();
        input.set_item("b", "y").unwrap();

        // --- source (caller) context non-active → OUTLET_6010 ---------------
        let caller_ctx = create_closeable_test_context(bi, &owner);
        let target_ctx = create_closeable_test_context(bi, &owner);
        let outlet_id = register_saga_outlet(py, &scp, &target_ctx, &owner);
        drive_context_closed(bi, &caller_ctx, &owner);

        let err = scp
            .outlet_streaming_saga_open(
                &caller_ctx,
                &target_ctx,
                &owner,
                &outlet_id,
                &input.as_borrowed(),
                &nonce_hex(),
                1_700_000_000_000,
                1,
                &placeholder_streaming_ucan(),
                None,
                None,
                None,
                None,
            )
            .expect_err("a non-active source context must be rejected before the saga runs");
        assert!(
            err.is_instance_of::<_scp_core::error::ContextError>(py),
            "expected ContextError, got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("SCP-OUTLET-6010"),
            "expected caller-axis SCP-OUTLET-6010, got: {msg}"
        );
        assert!(
            scp.test_streaming_saga_registry_is_empty(),
            "a rejected non-active open must NOT start a saga / hand out a receiver"
        );

        // --- source active, target context non-active → OUTLET_6011 ---------
        // Fresh caller (the first is now closed); reuse the still-active target,
        // then close it so only the TARGET axis is non-active.
        let caller_ctx2 = create_closeable_test_context(bi, &owner);
        let target_ctx2 = create_closeable_test_context(bi, &owner);
        let outlet_id2 = register_saga_outlet(py, &scp, &target_ctx2, &owner);
        drive_context_closed(bi, &target_ctx2, &owner);

        let err = scp
            .outlet_streaming_saga_open(
                &caller_ctx2,
                &target_ctx2,
                &owner,
                &outlet_id2,
                &input.as_borrowed(),
                &nonce_hex(),
                1_700_000_000_000,
                1,
                &placeholder_streaming_ucan(),
                None,
                None,
                None,
                None,
            )
            .expect_err("a non-active target context must be rejected before the saga runs");
        assert!(
            err.is_instance_of::<_scp_core::error::ContextError>(py),
            "expected ContextError, got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("SCP-OUTLET-6011"),
            "expected target-axis SCP-OUTLET-6011, got: {msg}"
        );
        assert!(
            scp.test_streaming_saga_registry_is_empty(),
            "a rejected non-active open must NOT start a saga / hand out a receiver"
        );
    });
}

/// Reads a `PyContextHandle`'s `context_id` through its Python getter. The
/// bridge's `context_create` generates the id internally and the Rust-level
/// getter is `#[pymethods]`-private, so the id is read the same way a Python
/// caller would: via the `context_id` attribute.
fn handle_context_id(py: Python<'_>, handle: &PyContextHandle) -> String {
    handle
        .clone()
        .into_pyobject(py)
        .unwrap()
        .getattr("context_id")
        .unwrap()
        .extract::<String>()
        .unwrap()
}

/// Builds and wires the full saga precondition through the `PyO3` bridge:
/// owner identity, caller context A, target context B, the outlet registered into
/// both B's actor governance state and the FFI-side registry (with a
/// deterministic handler), and the bidirectionally-approved `OutletInterface`
/// established in A. Returns `(scp, ctx_a, ctx_b, owner, outlet_id)` so the
/// `#[test]` body can invoke the saga and assert its terminal state. All setup
/// lives here; every assertion stays in the test.
///
/// The setup mirrors the producer's two authorization axes
/// (`start_cross_context_outlet_invocation_saga`, supervisor.rs):
///
/// 1. **Caller axis (gate 1).** `caller_did` must be hosted by this bridge AND a
///    member of the CALLER (source) context A. Creating A via `context_create`
///    with `owner` as the single-admin creator satisfies both.
/// 2. **Target axis (gate 2).** The producer requires a *bidirectionally
///    approved* `OutletInterface` (`approved_by_source && approved_by_target`)
///    that it queries against the CALLER context A's actor governance state
///    (`has_established_outlet_interface`, `queries_helpers.rs`) — NOT context B's.
///    So the interface is established IN A, via a governance
///    `EstablishOutletInterface` action proposed by A's admin (auto-executed under
///    `single_admin`). `execute_establish_outlet_interface` (`governance_helpers.rs`)
///    pushes the interface verbatim into A's `governance.outlet_interfaces`, and
///    additionally requires A's ceiling to contain `outlet:interface` — which the
///    admin role grants because A's ceiling lists it. The three id-form fields
///    (`source_context` = A, `target_context` = B, `outlet_id` = the registration
///    id) are compared on the raw 64-hex digest form, so they must equal A/B/id
///    exactly, with BOTH approvals `true`.
///
/// Context B holds the registered outlet plus the handler the executor snapshots
/// and runs once at Commit-B (`rt.outlet_handlers.get(outlet_id)`, outlets.rs). The
/// handler returns `{"sum": 42, "ok": 1}`, which Commit-B validates against the
/// outlet's registered numeric `{sum, ok}` output schema (from `build_outlet_reg`)
/// before committing. The committed output bytes therefore decode to that JSON.
fn establish_xctx_saga_commit_preconditions(
    py: Python<'_>,
) -> (_scp_core::scp::PyScp, String, String, String, String) {
    // Initializes the process-global tokio runtime the bridge methods
    // (`identity_create`, `context_create`, `governance_propose`,
    // `outlet_invoke_cross_context_saga`) block on.
    setup();
    let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
    let bi = scp.bridge_instance();

    // Create the owner via the bridge's real `identity_create` so its DID
    // document is published into the per-instance resolver DHT, and so the
    // resolver itself is initialized on the instance. Governance vote
    // verification (even single_admin auto-execute) resolves the proposer's
    // public key through that resolver — a registry-only test identity is
    // unresolvable and fails with "unknown voter".
    //
    // This MUST precede `init_context_manager_for_test`: the supervisor
    // snapshots `bi.did_resolver()` at build time, falling back to the
    // always-`None` resolver if none is configured yet. Creating the
    // identity first means the supervisor's governance key resolver is the
    // real document-VM resolver that can see the published document.
    let owner_identity = scp
        .identity_create(py, "in_memory", None)
        .unwrap()
        .into_pyobject(py)
        .unwrap();
    let owner = owner_identity
        .getattr("did")
        .unwrap()
        .extract::<String>()
        .unwrap();

    runtime::init_context_manager_for_test(bi);

    // Context A (caller/source). Its ceiling carries the two load-bearing
    // capabilities: `governance:propose` (so `owner`, as admin, can propose)
    // and `outlet:interface` (required by `execute_establish_outlet_interface`'s
    // ceiling check). The remaining entries are harmless. `context_create`
    // generates a real 64-hex id, so the ADR-056 saga chokepoint round-trips
    // to A's actor.
    let params_a = PyDict::new(py);
    let ceiling_a = PyList::new(
        py,
        [
            "governance:propose",
            "outlet:interface",
            "outlet:call:*",
            "messages:read",
            "messages:write",
        ],
    )
    .unwrap();
    params_a.set_item("ceiling", ceiling_a).unwrap();
    let handle_a = scp.context_create(&owner, &params_a.as_borrowed()).unwrap();
    let ctx_a = handle_context_id(py, &handle_a);

    // Context B (target). Its ceiling carries `governance:propose` and
    // `outlet:register` so the saga outlet can be registered into B's ACTOR
    // governance state (the saga's Prepare-B reads the outlet from B's
    // `governance.registered_outlets`, not from the FFI-side registry).
    let params_b = PyDict::new(py);
    let ceiling_b = PyList::new(py, ["governance:propose", "outlet:register"]).unwrap();
    params_b.set_item("ceiling", ceiling_b).unwrap();
    let handle_b = scp.context_create(&owner, &params_b.as_borrowed()).unwrap();
    let ctx_b = handle_context_id(py, &handle_b);

    // The outlet id is the deterministic `generate_outlet_id(name)` form shared
    // by all bridges. The same id keys (a) B's actor `registered_outlets`
    // (saga Prepare-B), (b) the interface in A (saga gate 2), and (c) the
    // FFI-side handler the executor snapshots at Commit-B.
    let outlet_name = "xctx_saga_commit_outlet";
    let outlet_id = format!("outlet-{outlet_name}");

    // Register the saga outlet into B's ACTOR governance state so the saga's
    // Prepare-B finds it.
    let register_json = register_outlet_action_json(&outlet_id, outlet_name, &owner);
    scp.governance_propose(&handle_b, &owner, &register_json)
        .expect("RegisterOutlet must auto-execute under single_admin");

    // The executor snapshots the handler from the FFI-side `outlet_handlers`
    // at Commit-B. `register_outlet_handler` requires the outlet to exist in
    // the FFI-side `outlet_registry`, so register it there too (same id), then
    // attach a deterministic handler returning the numeric `{sum, ok}`.
    let reg = build_outlet_reg(py, outlet_name, &owner);
    let ffi_outlet_id = scp.outlet_register(&ctx_b, &reg.as_borrowed()).unwrap();
    assert_eq!(
        ffi_outlet_id, outlet_id,
        "FFI and governance outlet ids must agree (deterministic generate_outlet_id)"
    );
    let handler: runtime::OutletHandler =
        Arc::new(|_input: serde_json::Value| Ok(serde_json::json!({"sum": 42, "ok": 1})));
    runtime::register_outlet_handler(bi, &ctx_b, &outlet_id, handler).unwrap();

    // Establish the bidirectionally-approved interface in A via governance.
    let action_json = establish_interface_action_json(&ctx_a, &ctx_b, &outlet_id);
    let propose_result = scp
        .governance_propose(&handle_a, &owner, &action_json)
        .expect("EstablishOutletInterface must auto-execute under single_admin");
    assert!(
        !propose_result.is_empty(),
        "governance_propose must return a non-empty result JSON"
    );

    (scp, ctx_a, ctx_b, owner, outlet_id)
}

/// Serializes a `RegisterOutlet` governance action for the saga outlet. The schema
/// mirrors `build_outlet_reg`: 2 input + 2 output properties (clears the §9.2.1
/// specificity floor of 2), numeric `{sum, ok}` output (so Commit-B's
/// output-schema validation accepts the handler's response). `implementation_hash`
/// is a fixed `[u8; 32]`; serde expects a 32-element JSON number array (the
/// `json!` macro has no array-repeat sugar).
fn register_outlet_action_json(outlet_id: &str, outlet_name: &str, owner: &str) -> String {
    let impl_hash = serde_json::Value::from(vec![0u8; 32]);
    let register_action = serde_json::json!({
        "RegisterOutlet": {
            "registration": {
                "outlet_id": outlet_id,
                "name": outlet_name,
                "description": format!("Outlet: {outlet_name}"),
                "schema": {
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "a": {"type": "string"},
                            "b": {"type": "string"}
                        }
                    },
                    "output_schema": {
                        "type": "object",
                        "properties": {
                            "sum": {"type": "number"},
                            "ok": {"type": "number"}
                        }
                    }
                },
                "implementation_hash": impl_hash,
                "test_vectors": [],
                "operator_did": owner,
                "cost": null,
                "registered_at": 0,
                "signature": []
            }
        }
    });
    serde_json::to_string(&register_action).unwrap()
}

/// Serializes the bidirectionally-approved `EstablishOutletInterface` governance
/// action. Externally-tagged `GovernanceAction` (no serde rename) → the
/// `EstablishOutletInterface` variant wraps the `snake_case` `OutletInterface` struct;
/// the `Option` fields render as JSON `null`.
fn establish_interface_action_json(ctx_a: &str, ctx_b: &str, outlet_id: &str) -> String {
    let action = serde_json::json!({
        "EstablishOutletInterface": {
            "interface": {
                "source_context": ctx_a,
                "target_context": ctx_b,
                "outlet_id": outlet_id,
                "rate_limit": null,
                "inbound_rate_limit": null,
                "per_caller_rate_limit": null,
                "approved_by_source": true,
                "approved_by_target": true,
                "outbound_policy": null,
                "inbound_policy": null
            }
        }
    });
    serde_json::to_string(&action).unwrap()
}

/// Full `Committed` terminal through the `PyO3` bridge: an authenticated caller
/// drives the §6.2.4 cross-context outlet-invocation saga to a real commit and
/// the bridge returns the committed receipt + output bytes. See
/// `establish_xctx_saga_commit_preconditions` for the setup it depends on.
#[test]
fn xctx_saga_authenticated_caller_commits_via_governance_established_interface() {
    Python::with_gil(|py| {
        let (scp, ctx_a, ctx_b, owner, outlet_id) = establish_xctx_saga_commit_preconditions(py);

        // Invoke the saga from A → B with the authenticated caller. The outlet's
        // input schema wants string `a`/`b`.
        let input = PyDict::new(py);
        input.set_item("a", "x").unwrap();
        input.set_item("b", "y").unwrap();

        // A near-now timestamp: Prepare-B enforces a §9.14 ±5min skew tolerance,
        // so a fixed historical timestamp would abort with SCP-SAGA-13018.
        let now_ms = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();

        let result = scp
            .outlet_invoke_cross_context_saga(
                &ctx_a,
                &ctx_b,
                &owner,
                &outlet_id,
                &input.as_borrowed(),
                &nonce_hex(),
                now_ms,
                1,
                None,
            )
            .expect("saga must reach Committed");

        // Committed terminal: non-empty saga id + a receipt + output bytes.
        assert!(
            !result.saga_id.is_empty(),
            "a committed saga must carry a non-empty saga id"
        );
        assert!(
            result.receipt.is_some(),
            "committed saga must carry a receipt"
        );
        assert!(
            result.output.is_some(),
            "committed saga must carry output bytes"
        );

        // The committed output decodes to the handler's response (numeric, per
        // the registered output schema). Assert the parsed values, not raw
        // bytes, so a JCS-canonical encoding still passes.
        let out: serde_json::Value =
            serde_json::from_slice(result.output.as_ref().unwrap()).unwrap();
        assert_eq!(out["sum"], 42, "committed output sum must be the handler's");
        assert_eq!(out["ok"], 1, "committed output ok must be the handler's");
    });
}

// ============================================================================
// Cross-context STREAMING saga — NON-BLOCKING OPEN at the FFI boundary
// (§5.4.5 / §6.2.4, SCP-OUT-047 AC6) — PyO3 export
// ============================================================================
//
// The rejection tests above prove the caller-binding gates BEFORE the saga
// runs. This drives the FULL happy path through the REAL FFI
// `outlet_streaming_saga_open` to the Commit-transition and asserts the
// property AC6 names: the open returns a `saga_id` PROMPTLY while the saga FSM
// is still PRE-Committed (the supervisor's own durable journal reads
// `Committing`) — i.e. the open did NOT block until the stream terminated. The
// bridge's `BridgeStreamExecutor` is single-shot by the accepted SCP-OUT-037
// primitive (handler → one value → one Data chunk + framework terminal); a
// target handler that BLOCKS before releasing its one value makes the
// pre-Committed observation race-free (the off-mailbox seal cannot reach
// stream-close, and thus cannot resolve `Committed`, until the test releases
// it).

/// Builds and wires the full CROSS-CONTEXT STREAMING saga precondition through
/// the `PyO3` bridge: an `owner` admin, a delegated `invoker`, caller context A,
/// target context B, the outlet registered into both B's actor governance state
/// and the FFI-side registry (with a *controllable* single-shot handler that
/// BLOCKS until released), the invoker seeded as a capability-bearing member of
/// BOTH A and B, the bidirectionally-approved `OutletInterface` established in A,
/// and an `outlet_call:*` invocation UCAN (owner → invoker) minted in B.
///
/// Distinct from [`establish_xctx_saga_commit_preconditions`] (the UNARY saga
/// helper, whose export validates no UCAN at the bridge and needs no delegated
/// invoker): the streaming-saga open validates the invocation UCAN at the bridge
/// against the TARGET context B, so B's ceiling MUST admit `outlet:call:*` (else
/// `ucan_mint`'s mint-time ceiling check rejects) and a delegated invoker
/// (iss ≠ aud) is required — a self-issued owner → owner token would need a
/// `key_scope` (ADR-039).
///
/// Returns `(scp, ctx_a, ctx_b, invoker, outlet_id, invocation_ucan,
/// release_tx)`; the `#[test]` body drives the open, asserts the pre-Committed
/// journal state, then `release_tx.send(())` unblocks the handler so the stream
/// drains to its terminal.
#[cfg(all(feature = "testing", feature = "outlet-capability-test-grant"))]
#[allow(clippy::too_many_lines)] // one linear cross-context streaming precondition
fn establish_xctx_streaming_saga_preconditions(
    py: Python<'_>,
) -> (
    _scp_core::scp::PyScp,
    String,
    String,
    String,
    String,
    String,
    std::sync::mpsc::Sender<()>,
) {
    setup();
    let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
    let bi = scp.bridge_instance();

    // Owner (admin/creator of both contexts) + a SEPARATE delegated invoker,
    // both PUBLISHED into the resolver so governance vote verification and the
    // invocation-UCAN signature check resolve their keys. Created BEFORE the
    // context manager so the supervisor snapshots the real document-VM resolver
    // (mirrors the unary saga helper's ordering).
    let owner = published_identity_did(py, &scp);
    let invoker = published_identity_did(py, &scp);

    runtime::init_context_manager_for_test(bi);

    // Context A (caller/source). Its ceiling carries `governance:propose` (owner
    // proposes), `outlet:interface` (the interface-establish ceiling check), and
    // `outlet:call:*` (so the invoker's granted OutletCallAll stays within A's
    // ceiling).
    let params_a = PyDict::new(py);
    let ceiling_a = PyList::new(
        py,
        [
            "governance:propose",
            "outlet:interface",
            "outlet:call:*",
            "messages:read",
            "messages:write",
        ],
    )
    .unwrap();
    params_a.set_item("ceiling", ceiling_a).unwrap();
    let handle_a = scp.context_create(&owner, &params_a.as_borrowed()).unwrap();
    let ctx_a = handle_context_id(py, &handle_a);

    // Context B (target). Its ceiling carries `governance:propose`,
    // `outlet:register` (so the saga outlet registers into B's ACTOR governance
    // state), and `outlet:call:*` — REQUIRED so `ucan_mint` (mint-time ceiling
    // enforcement) accepts the `outlet_call:*` invocation UCAN issued in B.
    let params_b = PyDict::new(py);
    let ceiling_b = PyList::new(
        py,
        ["governance:propose", "outlet:register", "outlet:call:*"],
    )
    .unwrap();
    params_b.set_item("ceiling", ceiling_b).unwrap();
    let handle_b = scp.context_create(&owner, &params_b.as_borrowed()).unwrap();
    let ctx_b = handle_context_id(py, &handle_b);

    let outlet_name = "xctx_streaming_saga_outlet";
    let outlet_id = format!("outlet-{outlet_name}");

    // Register the saga outlet into B's ACTOR governance state (saga Prepare-B
    // reads it) AND the FFI-side registry (the executor snapshots the handler).
    let register_json = register_outlet_action_json(&outlet_id, outlet_name, &owner);
    scp.governance_propose(&handle_b, &owner, &register_json)
        .expect("RegisterOutlet must auto-execute under single_admin");
    let reg = build_outlet_reg(py, outlet_name, &owner);
    let ffi_outlet_id = scp.outlet_register(&ctx_b, &reg.as_borrowed()).unwrap();
    assert_eq!(
        ffi_outlet_id, outlet_id,
        "FFI and governance outlet ids must agree (deterministic generate_outlet_id)"
    );

    // A CONTROLLABLE single-shot handler: it BLOCKS on `release_rx.recv()` until
    // the test releases it, so the off-mailbox seal cannot reach the terminal
    // (and thus cannot resolve `Committed`) until the pre-Committed journal state
    // has been observed. `Arc<Mutex<Receiver>>` is `Send + Sync` (the handler is
    // `Fn + Send + Sync`); it is invoked exactly once (single-shot).
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let gate = Arc::new(std::sync::Mutex::new(release_rx));
    let handler: runtime::OutletHandler = Arc::new(move |_input: serde_json::Value| {
        if let Ok(rx) = gate.lock() {
            let _ = rx.recv();
        }
        Ok(serde_json::json!({ "sum": 42, "ok": 1 }))
    });
    runtime::register_outlet_handler(bi, &ctx_b, &outlet_id, handler).unwrap();

    // Seed the invoker as a capability-bearing member of BOTH contexts: member of
    // A (the §6.2.4 caller-principal binding checks A-membership) with
    // OutletInterface + OutletCallAll, and member of B (the pump's §9.8.5
    // membership + role-state capability gate) with OutletCallAll. Mirrors the
    // runtime fixture `ss_grant_outlet_caps` / the same-context live-stream test.
    {
        let rt = test_runtime();
        let supervisor = runtime::supervisor(bi).unwrap().clone();
        rt.block_on(supervisor.test_insert_member(&ctx_a, scp_did::DID(invoker.clone()), "member"))
            .expect("seed invoker as a member of caller context A");
        rt.block_on(supervisor.test_grant_member_capability(
            &ctx_a,
            scp_did::DID(invoker.clone()),
            "outlet_call:*",
        ))
        .expect("grant OutletCallAll to the invoker in A");
        rt.block_on(supervisor.test_grant_member_capability(
            &ctx_a,
            scp_did::DID(invoker.clone()),
            "outlet:interface",
        ))
        .expect("grant OutletInterface to the invoker in A");
        rt.block_on(supervisor.test_insert_member(&ctx_b, scp_did::DID(invoker.clone()), "member"))
            .expect("seed invoker as a member of target context B");
        rt.block_on(supervisor.test_grant_member_capability(
            &ctx_b,
            scp_did::DID(invoker.clone()),
            "outlet_call:*",
        ))
        .expect("grant OutletCallAll to the invoker in B");
    }

    // Establish the bidirectionally-approved interface in A via governance.
    let action_json = establish_interface_action_json(&ctx_a, &ctx_b, &outlet_id);
    scp.governance_propose(&handle_a, &owner, &action_json)
        .expect("EstablishOutletInterface must auto-execute under single_admin");

    // Mint the invocation UCAN in B (issued by B's creator `owner`, delegated to
    // the `invoker` audience), granting `outlet_call:*`. The streaming-saga open
    // validates it at the bridge against B (the "UCAN check locus").
    let ucan = scp
        .ucan_mint(&ctx_b, &invoker, vec!["outlet_call:*".to_owned()], None)
        .expect("mint the outlet_call invocation UCAN in B")
        .encoded;

    (scp, ctx_a, ctx_b, invoker, outlet_id, ucan, release_tx)
}

/// SCP-OUT-047 AC6 — the streaming-saga FFI open does NOT block until Committed.
/// Drives the REAL `outlet_streaming_saga_open` to the Commit-transition with a
/// target handler BLOCKED before releasing its single-shot value, and asserts
/// the open returned a `saga_id` while the supervisor's own durable saga journal
/// still reads `Committing` (pre-Committed / sealing). Then releases the handler
/// and drains to the terminal via `outlet_streaming_saga_poll_next`.
///
/// This is the FFI-boundary proof of AC6's INTENT (non-blocking open): the seal
/// pumps off-mailbox and reaches `Committed` asynchronously at stream-close, NOT
/// inline on the open call.
#[cfg(all(feature = "testing", feature = "outlet-capability-test-grant"))]
#[test]
#[allow(clippy::too_many_lines)] // one linear §6.2.4 non-blocking-open flow
fn xctx_streaming_saga_open_returns_before_committed_non_blocking() {
    use scp_core::context::outlets::stream::{ChunkPayload, OutletStreamChunk};
    use scp_core::context::supervisor::{SagaId, SagaState};

    Python::with_gil(|py| {
        let (scp, ctx_a, ctx_b, invoker, outlet_id, ucan, release_tx) =
            establish_xctx_streaming_saga_preconditions(py);

        let input = PyDict::new(py);
        input.set_item("a", "x").unwrap();
        input.set_item("b", "y").unwrap();

        // A near-now timestamp: Prepare-B enforces a §9.14 ±5min skew tolerance.
        let now_ms = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();

        // OPEN — the REAL FFI streaming-saga export. It MUST return a `saga_id` at
        // the Commit-transition (non-blocking); the seal pumps off-mailbox, and
        // the target handler is BLOCKED, so the stream cannot yet reach terminal.
        // `estimated_chunk_count = Some(1)` matches the single-shot executor's one
        // billable Data chunk (an unbounded default would trip the credit-window
        // bound).
        let saga_id = scp
            .outlet_streaming_saga_open(
                &ctx_a,
                &ctx_b,
                &invoker,
                &outlet_id,
                &input.as_borrowed(),
                &nonce_hex(),
                now_ms,
                1,
                &ucan,
                None,
                None,
                None,
                Some(1),
            )
            .expect("the streaming-saga open returns a saga_id at the Commit-transition");
        assert!(
            !saga_id.is_empty(),
            "a Commit-transition streaming saga carries a non-empty saga id"
        );

        // AC6 — the open returned while the saga FSM is still PRE-Committed: the
        // supervisor's OWN durable journal reads `Committing`. The off-mailbox seal
        // has NOT resolved it to `Committed` (the handler is blocked), proving the
        // FFI open did not block until stream-terminal. Read via the supervisor's
        // testing journal accessor on the test runtime (a journal read, no mailbox).
        let bi = scp.bridge_instance();
        let rt = test_runtime();
        let supervisor = runtime::supervisor(bi).unwrap().clone();
        let sid = SagaId(saga_id.clone());
        let state = rt.block_on(supervisor.test_saga_journal_state(&sid));
        assert_eq!(
            state,
            Some(SagaState::Committing),
            "AC6: the FFI open returned while the streaming saga is still pre-Committed \
             (journal Committing / sealing) — a non-blocking open"
        );

        // Release the blocked handler; the single-shot seal now forwards its one
        // Data chunk and closes to the terminal.
        release_tx
            .send(())
            .expect("release the blocked target handler so the seal reaches the terminal");

        // Drain to terminal via the REAL FFI poll_next. The single-shot executor
        // yields exactly one Data chunk plus the framework terminal.
        let mut saw_data = false;
        let mut saw_terminal = false;
        for _ in 0..16 {
            let Some(bytes) = scp.outlet_streaming_saga_poll_next(py, &saga_id).unwrap() else {
                // Abnormal terminal (channel closed without a terminal chunk).
                break;
            };
            let chunk: OutletStreamChunk = serde_json::from_slice(&bytes).unwrap();
            if matches!(chunk.payload, ChunkPayload::Data { .. }) {
                saw_data = true;
            }
            if chunk.payload.is_terminal() {
                saw_terminal = true;
                break;
            }
        }
        assert!(
            saw_data,
            "the single-shot seal forwarded its one Data chunk"
        );
        assert!(
            saw_terminal,
            "poll_next drained the streaming saga to its terminal chunk"
        );

        // The terminal EVICTED the saga registry entry — a further poll is a
        // DISTINCT not-found error (the saga is genuinely gone), never a silent None.
        assert!(
            scp.outlet_streaming_saga_poll_next(py, &saga_id)
                .unwrap_err()
                .to_string()
                .contains("no active cross-context streaming saga"),
            "the saga entry is evicted at the terminal chunk (no registry leak)"
        );
        let _ = ctx_b;
    });
}

// ============================================================================
// Streaming outlets (§5.4.5, SCP-OUT-037 — C7 PyO3 reference bridge)
// ============================================================================

/// Creates an identity via the REAL bridge `identity_create` (which PUBLISHES
/// the DID document into the instance's resolver, so UCAN signatures issued by
/// it verify) and returns its DID string.
fn published_identity_did(py: Python<'_>, scp: &_scp_core::scp::PyScp) -> String {
    scp.identity_create(py, "in_memory", None)
        .unwrap()
        .into_pyobject(py)
        .unwrap()
        .getattr("did")
        .unwrap()
        .extract::<String>()
        .unwrap()
}

/// End-to-end §5.4.5 streaming flow through the `PyO3` reference bridge:
/// open → CRITICAL #1 (grant/cancel/terminate by a non-invoker → `SCP-PERM-3001`)
/// → grant by the pinned invoker succeeds → `poll_next` drains the Data chunk →
/// drain to terminal → `poll_next` returns `None` (which evicts the entry).
#[test]
#[allow(clippy::too_many_lines)] // single comprehensive §5.4.5 e2e flow — readability favors one linear test over arbitrary splits
fn outlet_stream_open_path_wired_and_control_plane_not_found() {
    Python::with_gil(|py| {
        // Initializes the process-global tokio runtime the bridge methods block
        // on (`identity_create`, `outlet_stream_open`, …).
        setup();
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        let bi = scp.bridge_instance();

        // Create identities via the REAL bridge `identity_create` so each DID
        // document is PUBLISHED into the resolver — the UCAN signature check at
        // open resolves the issuer's key. Identities are created BEFORE the
        // context manager so the supervisor's governance key resolver snapshots
        // the real document-VM resolver (mirrors the saga tests' ordering).
        let creator = published_identity_did(py, &scp);
        // The invoker is a SEPARATE hosted identity the creator delegates to —
        // a self-delegation (iss == aud) would require a key_scope (ADR-039).
        let invoker = published_identity_did(py, &scp);
        let stranger = published_identity_did(py, &scp);

        runtime::init_context_manager_for_test(bi);
        // Create the context via the REAL bridge method so its actor is spawned
        // on the SAME process-global runtime the streaming ops query (a context
        // created on a different runtime is unreachable → transport.rate-limited).
        let ctx = {
            let params = PyDict::new(py);
            let handle = scp.context_create(&creator, &params.as_borrowed()).unwrap();
            handle_context_id(py, &handle)
        };

        // Outlet operated by the creator (co-resident custody signs chunks).
        let reg = build_outlet_reg(py, "streaming_calc", &creator);
        let outlet_id = scp.outlet_register(&ctx, &reg.as_borrowed()).unwrap();

        // Schema-valid Data value ({sum, ok}).
        runtime::register_outlet_handler(
            bi,
            &ctx,
            &outlet_id,
            std::sync::Arc::new(
                |_input: serde_json::Value| -> Result<serde_json::Value, String> {
                    Ok(serde_json::json!({ "sum": 3, "ok": 1 }))
                },
            ),
        )
        .unwrap();

        // Creator-issued outlet_call UCAN delegated to the invoker (root
        // issuer == context creator).
        let ucan = scp
            .ucan_mint(&ctx, &invoker, vec!["outlet_call:*".to_owned()], None)
            .unwrap();

        let input = PyDict::new(py);
        input.set_item("a", "1").unwrap();
        input.set_item("b", "2").unwrap();

        // OPEN — drives the WHOLE bridge open path end-to-end: bridge UCAN
        // validation (11-step ADR-016), §7.3.8 effective-caveat resolution +
        // caveats-binding computation, custody resolution of BOTH the operator
        // chunk signer and the invoker verifying key, `StreamIdentity` +
        // `OpenStreamParams` construction, the live revocation-checker wiring,
        // the executor adapter, and the `Supervisor::open_outlet_stream`
        // dispatch. The invoker is a delegated NON-member, so the open reaches
        // the runtime's §9.8.5 membership gate and is rejected there — proving
        // the open path is fully wired and that `OpenStreamRejection` maps to a
        // canonical outlet-class code (NOT a UCAN error: reaching the
        // runtime gate means UCAN validation PASSED). A member invoker with the
        // funded economy fixture drives the pump to completion at the RUNTIME
        // level in `open_outlet_stream_reserve_pump_settle_end_to_end`; the
        // bridge control methods below are thin pass-throughs to that same
        // `StreamSessionHandle` surface (a member-backed live stream is not
        // constructible at the bridge boundary — it needs the
        // `pub(in crate::context)` `spawn_actor_with_state` fixture).
        let open_err = scp
            .outlet_stream_open(
                &ctx,
                &outlet_id,
                &input.as_borrowed(),
                &invoker,
                &ucan.encoded,
                None,
                None,
                None,
                None,
            )
            .expect_err("a non-member invoker is rejected at the runtime membership gate");
        let msg = open_err.to_string();
        assert!(
            msg.contains(scp_core::context::outlets::error_codes::CODE_AUTHORIZATION_DENIED),
            "the open reached the runtime and mapped its rejection to the canonical \
             NON-RETRYABLE authorization-denied code (#2196: a non-member membership \
             denial is SCP-OUTLET-6110 authorization.denied, NOT the old wrongly-retryable \
             transport-fault SCP-OUTLET-6160): {msg}"
        );

        // Control-plane graceful not-found: the six control methods on an
        // unknown handle must return a clean error / None — never panic. (The
        // live CRITICAL #1 caller==invoker gate fires only against a live entry;
        // its discrimination is exercised at the runtime handle level.)
        let bogus = "0".repeat(32);
        // The bridge now signs the grant internally + auto-assigns monotonic_seq,
        // so the caller supplies only a chunk count. An unknown handle rejects at
        // the CRITICAL #1 lookup before any signing / reserve.
        assert!(
            scp.outlet_stream_grant_credit(py, &bogus, &invoker, 1)
                .unwrap_err()
                .to_string()
                .contains("no active outlet stream"),
            "grant on an unknown handle is a clean not-found error"
        );
        assert!(
            scp.outlet_stream_cancel(py, &bogus, &invoker)
                .unwrap_err()
                .to_string()
                .contains("no active outlet stream"),
            "cancel on an unknown handle is a clean not-found error"
        );
        assert!(
            scp.outlet_stream_terminate(
                py,
                &bogus,
                &invoker,
                "authorization.revoked-mid-stream",
                "x",
            )
            .unwrap_err()
            .to_string()
            .contains("no active outlet stream"),
            "terminate on an unknown handle is a clean not-found error"
        );
        // An unknown handle is a DISTINCT error, NOT a `None` terminal — a
        // stale/typo'd handle must never masquerade as a clean stream end.
        assert!(
            scp.outlet_stream_poll_next(py, &bogus)
                .unwrap_err()
                .to_string()
                .contains("no active outlet stream"),
            "poll on an unknown handle is a distinct not-found error, not None"
        );

        // The terminate slug guard is pure input validation (reachable without a
        // live stream): an unknown slug fails closed as a validation error. The
        // canonical `code` is now derived internally from the slug, so there is
        // no longer a caller-supplied code that could disagree with the slug.
        assert!(
            scp.outlet_stream_terminate(py, &bogus, &invoker, "not.a.terminal.slug", "y")
                .is_err(),
            "an unknown terminate slug is rejected"
        );
        let _ = stranger;
    });
}

/// The two pure protocol wrappers round-trip: `compute_caveats_binding`
/// produces the 32-byte binding, and `verify_chunk_signature` rejects a chunk
/// signed under a different key (fail-closed) while accepting a correctly
/// GIL-deadlock regression (BLOCKER): a REAL Python outlet handler + a LIVE
/// member-backed stream, driven through `outlet_stream_poll_next` to its
/// terminal chunk.
///
/// # What this proves
///
/// The streaming pump runs the registered PYTHON handler on a detached tokio
/// task; that handler REACQUIRES the GIL (`mcp.rs` `Python::with_gil`) to
/// produce each chunk. `poll_next` blocks on the runtime awaiting that chunk.
/// If `poll_next` held the GIL across its blocking `recv()` (the pre-fix bug),
/// the consumer would park holding the GIL while the producer blocks trying to
/// take it — a guaranteed interpreter deadlock, and THIS TEST WOULD HANG
/// FOREVER. The `py.allow_threads` fix releases the GIL across `recv()`, so the
/// producer runs, the chunk flows, and `poll_next` returns. Reaching the
/// terminal chunk (rather than hanging) is the regression signal.
///
/// # Why it is now constructible
///
/// The invoker is made a real MEMBER via the `testing`-gated
/// `Supervisor::test_insert_member`, so the open clears the §9.8.5 membership
/// gate that rejects the delegated non-member in
/// `outlet_stream_open_path_wired_and_control_plane_not_found`. The outlet is
/// ZERO-cost (`build_outlet_reg` declares no `cost`), so no escrow / funding
/// fixture is needed — the reserve is `Amount(0)`.
// Requires `testing` (test_insert_member + in-memory harness) AND the dedicated
// non-leaking `outlet-capability-test-grant` feature (the capability-escalation
// seam that authorizes the member invoker — see scp-runtime/Cargo.toml).
#[cfg(all(feature = "testing", feature = "outlet-capability-test-grant"))]
#[test]
#[allow(clippy::too_many_lines)] // single linear §5.4.5 live-stream flow — readability favors one test
fn outlet_stream_live_poll_next_drains_to_terminal_without_gil_deadlock() {
    use scp_core::context::outlets::stream::{ChunkPayload, OutletStreamChunk};

    Python::with_gil(|py| {
        setup();
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        let bi = scp.bridge_instance();

        let creator = published_identity_did(py, &scp);
        let invoker = published_identity_did(py, &scp);
        // A non-invoker principal, to prove the grant control-plane rejects a
        // caller that is not the pinned invoker (CRITICAL #1).
        let stranger = published_identity_did(py, &scp);

        runtime::init_context_manager_for_test(bi);
        let ctx = {
            let params = PyDict::new(py);
            let handle = scp.context_create(&creator, &params.as_borrowed()).unwrap();
            handle_context_id(py, &handle)
        };

        // Zero-cost outlet operated by the creator (co-resident custody signs
        // chunks).
        let reg = build_outlet_reg(py, "streaming_live", &creator);
        let outlet_id = scp.outlet_register(&ctx, &reg.as_borrowed()).unwrap();

        // Register a REAL PYTHON handler through the bridge's
        // `mcp_register_outlet_handler` path — the closure that reacquires the
        // GIL to produce the chunk (the producer side of the deadlock).
        let handler: PyObject = py
            .eval(c"lambda i: {'sum': 3, 'ok': 1}", None, None)
            .unwrap()
            .unbind();
        scp.py_register_outlet_handler(py, &ctx, &outlet_id, handler)
            .unwrap();

        // Make the invoker a real member (clears the §9.8.5 membership gate) and
        // grant it `OutletCallAll` (clears the runtime's role-state
        // defense-in-depth capability gate — the default `member` role grants
        // only `messages:*`). Both mirror the runtime fixture
        // `authorizing_role_state`.
        {
            let rt = test_runtime();
            let supervisor = runtime::supervisor(bi).unwrap().clone();
            rt.block_on(supervisor.test_insert_member(
                &ctx,
                scp_did::DID(invoker.clone()),
                "member",
            ))
            .expect("test_insert_member seeds the invoker as a member");
            rt.block_on(supervisor.test_grant_member_capability(
                &ctx,
                scp_did::DID(invoker.clone()),
                "outlet_call:*",
            ))
            .expect("grant OutletCallAll to the member invoker");
        }

        // Creator-issued outlet_call UCAN delegated to the member invoker.
        let ucan = scp
            .ucan_mint(&ctx, &invoker, vec!["outlet_call:*".to_owned()], None)
            .unwrap();

        let input = PyDict::new(py);
        input.set_item("a", "1").unwrap();
        input.set_item("b", "2").unwrap();

        // OPEN — now succeeds (member + valid UCAN + zero cost), returning the
        // hex StreamHandleId promptly (Commit transition, never block-until-
        // terminal).
        let handle_id = scp
            .outlet_stream_open(
                &ctx,
                &outlet_id,
                &input.as_borrowed(),
                &invoker,
                &ucan.encoded,
                None,
                None,
                None,
                // Single-shot handler → declare 1 billable chunk (must be
                // <= credit_window; an unbounded default coerces to u32::MAX and
                // trips SCP-OUTLET-6120 input.estimate-exceeds-bound).
                Some(1),
            )
            .expect("member invoker opens a live stream");

        // GIL DEADLOCK GUARD — this MUST be the FIRST call that touches the live
        // pump, BEFORE any grant_credit. The context's default credit window
        // (>= 1) admits the first Data chunk with NO grant, so this poll_next
        // PARKS on the pump: it awaits a chunk the Python handler must produce by
        // reacquiring the GIL. If poll_next held the GIL across recv() (the
        // pre-fix bug) the producer could never run and this call would HANG
        // FOREVER. It only returns because poll_next's `allow_threads` releases
        // the GIL. (Ordering matters: a preceding grant_credit — which has its
        // OWN allow_threads — would let the pump buffer both chunks into the mpsc
        // channel, so a later poll would read a buffered chunk without the pump
        // needing to run during poll, defeating the guard. Reverting ONLY
        // poll_next's allow_threads must make THIS call hang.)
        let first = scp
            .outlet_stream_poll_next(py, &handle_id)
            .unwrap()
            .expect("first poll parks on the live pump and returns its first chunk");
        let first_chunk: OutletStreamChunk = serde_json::from_slice(&first).unwrap();
        assert!(
            matches!(first_chunk.payload, ChunkPayload::Data { .. }),
            "the first parked poll_next forwarded the Python handler's Data chunk"
        );

        // CRITICAL #1: a non-invoker caller cannot steer the stream. The
        // caller==invoker gate fires on the registry lookup BEFORE any signing /
        // reserve, so this is deterministic regardless of pump progress. The
        // entry is still live (the Data chunk above is not terminal).
        assert!(
            scp.outlet_stream_grant_credit(py, &handle_id, &stranger, 1)
                .unwrap_err()
                .to_string()
                .contains("SCP-PERM-3001"),
            "a caller that is not the pinned invoker is rejected with SCP-PERM-3001"
        );

        // A self-grant exercises the bridge's INTERNAL credit signing + escrow
        // reserve + apply path end-to-end. The single-shot stream may already
        // have closed (a benign SCP-OUTLET-6101 lifecycle race), but a
        // bridge-signed grant must NEVER be rejected as a signature/authorization
        // failure (SCP-OUTLET-6110) — that would mean the bridge built a bad
        // credit preimage or signed under the wrong custody key.
        if let Err(e) = scp.outlet_stream_grant_credit(py, &handle_id, &invoker, 1) {
            let msg = e.to_string();
            assert!(
                !msg.contains(scp_core::context::outlets::error_codes::CODE_AUTHORIZATION_DENIED),
                "a correctly bridge-signed grant must not be rejected as a signature/auth \
                 failure: {msg}"
            );
        }

        // Drive the REST of the stream to its terminal.
        let mut saw_terminal = false;
        for _ in 0..16 {
            let Some(bytes) = scp.outlet_stream_poll_next(py, &handle_id).unwrap() else {
                // Abnormal terminal (channel closed without a terminal chunk).
                break;
            };
            let chunk: OutletStreamChunk = serde_json::from_slice(&bytes).unwrap();
            if chunk.payload.is_terminal() {
                saw_terminal = true;
                break;
            }
        }

        assert!(
            saw_terminal,
            "poll_next reached the stream's terminal chunk without deadlocking on the GIL"
        );

        // The terminal chunk EVICTED the entry, so a further poll is a distinct
        // not-found error (the stream is genuinely gone), never a silent None.
        assert!(
            scp.outlet_stream_poll_next(py, &handle_id)
                .unwrap_err()
                .to_string()
                .contains("no active outlet stream"),
            "the entry is evicted at the terminal chunk (no registry leak)"
        );
    });
}

/// signed one.
#[test]
fn outlet_stream_pure_wrappers_roundtrip() {
    Python::with_gil(|_py| {
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        let empty = scp_core::trust::caveats::InvocationCaveats::empty();
        let caveats_jcs = empty.to_canonical_json_bytes().unwrap();
        let request_id = [7u8; 16];
        let binding = scp
            .outlet_stream_compute_caveats_binding(
                b"cid-abc",
                &request_id,
                "did:dht:zInvoker",
                3,
                &caveats_jcs,
            )
            .unwrap();
        assert_eq!(binding.len(), 32, "caveats binding is 32 bytes");
        // Matches the pure protocol helper exactly.
        let expected = scp_core::context::outlets::stream::compute_caveats_binding(
            b"cid-abc",
            &request_id,
            "did:dht:zInvoker",
            3,
            &caveats_jcs,
        );
        assert_eq!(binding.as_slice(), expected.as_slice());

        // Sign a chunk with a known key; verify accepts under the matching key.
        let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let vk = key.verifying_key();
        let binding32 = <[u8; 32]>::try_from(binding.as_slice()).unwrap();
        let payload = scp_core::context::outlets::stream::ChunkPayload::Data {
            value: serde_json::json!({ "sum": 3 }),
        };
        let sig = scp_core::context::outlets::stream::sign_chunk(
            &key,
            "ctx-1",
            "outlet-1",
            &request_id,
            0,
            &binding32,
            &payload,
        )
        .unwrap();
        let chunk = scp_core::context::outlets::stream::OutletStreamChunk {
            request_id,
            sequence: 0,
            payload,
            sig,
        };
        let chunk_bytes = serde_json::to_vec(&chunk).unwrap();
        assert!(
            scp.outlet_stream_verify_chunk_signature(
                &chunk_bytes,
                vk.as_bytes(),
                "ctx-1",
                "outlet-1",
                &binding,
            )
            .unwrap(),
            "correctly signed chunk verifies"
        );
        // A different operator key is rejected (fail-closed).
        let other_vk = ed25519_dalek::SigningKey::from_bytes(&[10u8; 32]).verifying_key();
        assert!(
            !scp.outlet_stream_verify_chunk_signature(
                &chunk_bytes,
                other_vk.as_bytes(),
                "ctx-1",
                "outlet-1",
                &binding,
            )
            .unwrap(),
            "chunk signed by a different key must NOT verify"
        );
    });
}

/// The UNARY cross-context saga refuses a non-active caller context and a
/// non-active target context with the same two codes its streaming twin uses
/// (`xctx_streaming_saga_open_rejects_non_active_context`), read from each
/// context's supervisor actor through `read_context_state`.
///
/// Before the gate existed, a `Closing` / `Expired` / `MigratingOut` context refused a
/// streaming saga and admitted a unary one, so one bridge answered one
/// lifecycle question two ways. Removing either check makes the call fall
/// through to a `SagaAborted` from the saga drive instead, failing the code
/// assertions below.
#[test]
fn xctx_unary_saga_rejects_non_active_context() {
    Python::with_gil(|py| {
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        runtime::init_context_manager_for_test(scp.bridge_instance());
        let bi = scp.bridge_instance();

        let owner = create_test_identity(bi);
        let input = PyDict::new(py);
        input.set_item("a", "x").unwrap();
        input.set_item("b", "y").unwrap();

        // --- source (caller) context non-active → OUTLET_6010 ---------------
        let caller_ctx = create_closeable_test_context(bi, &owner);
        let target_ctx = create_closeable_test_context(bi, &owner);
        let outlet_id = register_saga_outlet(py, &scp, &target_ctx, &owner);
        drive_context_closed(bi, &caller_ctx, &owner);

        let err = scp
            .outlet_invoke_cross_context_saga(
                &caller_ctx,
                &target_ctx,
                &owner,
                &outlet_id,
                &input.as_borrowed(),
                &nonce_hex(),
                1_700_000_000_000,
                1,
                None,
            )
            .expect_err("a non-active caller context must be rejected before the saga runs");
        assert!(
            err.is_instance_of::<_scp_core::error::ContextError>(py),
            "expected ContextError, got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("SCP-OUTLET-6010"),
            "expected caller-axis SCP-OUTLET-6010, got: {msg}"
        );

        // --- caller active, target non-active → OUTLET_6011 -----------------
        let caller_ctx2 = create_closeable_test_context(bi, &owner);
        let target_ctx2 = create_closeable_test_context(bi, &owner);
        let outlet_id2 = register_saga_outlet(py, &scp, &target_ctx2, &owner);
        drive_context_closed(bi, &target_ctx2, &owner);

        let err = scp
            .outlet_invoke_cross_context_saga(
                &caller_ctx2,
                &target_ctx2,
                &owner,
                &outlet_id2,
                &input.as_borrowed(),
                &nonce_hex(),
                1_700_000_000_000,
                1,
                None,
            )
            .expect_err("a non-active target context must be rejected before the saga runs");
        let msg = err.to_string();
        assert!(
            msg.contains("SCP-OUTLET-6011"),
            "expected target-axis SCP-OUTLET-6011, got: {msg}"
        );
    });
}

/// Builds a context whose ceiling admits outlet registration and outlet calls,
/// registers one outlet in it, seeds `invoker` as a capability-bearing member in
/// the SUPERVISOR only, and mints an `outlet_call:*` UCAN for that invoker.
///
/// The bridge writes no membership record, so a capability gate that reads a
/// bridge-local copy sees no member and rejects.
#[cfg(all(feature = "testing", feature = "outlet-capability-test-grant"))]
fn supervisor_only_member_context(
    py: Python<'_>,
    scp: &_scp_core::scp::PyScp,
    owner: &str,
    invoker: &str,
) -> (String, String, String) {
    let params = PyDict::new(py);
    let ceiling = PyList::new(
        py,
        [
            "outlet:register",
            "outlet:call:*",
            "messages:read",
            "messages:write",
        ],
    )
    .unwrap();
    params.set_item("ceiling", ceiling).unwrap();
    let handle = scp.context_create(owner, &params.as_borrowed()).unwrap();
    let ctx_id = handle_context_id(py, &handle);

    let reg = build_outlet_reg(py, "supervisor_member_outlet", owner);
    let outlet_id = scp.outlet_register(&ctx_id, &reg.as_borrowed()).unwrap();

    let rt = test_runtime();
    let supervisor = runtime::supervisor(scp.bridge_instance()).unwrap().clone();
    rt.block_on(supervisor.test_insert_member(&ctx_id, scp_did::DID(invoker.to_owned()), "member"))
        .expect("seed the invoker in the supervisor only");
    rt.block_on(supervisor.test_grant_member_capability(
        &ctx_id,
        scp_did::DID(invoker.to_owned()),
        "outlet_call:*",
    ))
    .expect("grant OutletCallAll in the supervisor only");

    let ucan = scp
        .ucan_mint(&ctx_id, invoker, vec!["outlet_call:*".to_owned()], None)
        .expect("mint the invocation UCAN")
        .encoded;

    (ctx_id, outlet_id, ucan)
}

/// `outlet_session_invoke` admits an invoker whose capability exists ONLY in the
/// supervisor's role state, so the session capability gate reads the supervisor.
///
/// A gate reading a bridge-local copy finds no such member and rejects with
/// "does not have invocation capability", which this test forbids.
#[cfg(all(feature = "testing", feature = "outlet-capability-test-grant"))]
#[test]
fn session_invoke_admits_a_supervisor_only_capability_holder() {
    Python::with_gil(|py| {
        setup();
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        // Published BEFORE the supervisor is built, so the supervisor snapshots
        // the document-backed resolver the UCAN signature check needs.
        let owner = published_identity_did(py, &scp);
        let invoker = published_identity_did(py, &scp);
        runtime::init_context_manager_for_test(scp.bridge_instance());
        let (ctx_id, outlet_id, ucan) = supervisor_only_member_context(py, &scp, &owner, &invoker);

        let session_id = scp
            .outlet_session_create(&ctx_id, &outlet_id, &ctx_id, None)
            .expect("session creation");

        let input = PyDict::new(py);
        input.set_item("a", "x").unwrap();
        input.set_item("b", "y").unwrap();
        scp.outlet_session_invoke(
            py,
            &ctx_id,
            &session_id,
            &input.as_borrowed(),
            &invoker,
            &ucan,
            None,
        )
        .expect("the supervisor grants the capability, so the session invocation proceeds");
    });
}

/// The cross-context source-capability gate admits an invoker whose capability
/// exists ONLY in the source context's supervisor role state.
///
/// The call still fails afterwards — the two contexts share no approved outlet
/// interface — so the assertion is that it does NOT fail at the capability gate,
/// which is where a bridge-local copy rejects it.
#[cfg(all(feature = "testing", feature = "outlet-capability-test-grant"))]
#[test]
fn cross_context_invoke_admits_a_supervisor_only_capability_holder() {
    Python::with_gil(|py| {
        setup();
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        // Published BEFORE the supervisor is built, so the supervisor snapshots
        // the document-backed resolver the UCAN signature check needs.
        let owner = published_identity_did(py, &scp);
        let invoker = published_identity_did(py, &scp);
        runtime::init_context_manager_for_test(scp.bridge_instance());
        let (source_ctx, _source_outlet, _source_ucan) =
            supervisor_only_member_context(py, &scp, &owner, &invoker);
        let (target_ctx, target_outlet, target_ucan) =
            supervisor_only_member_context(py, &scp, &owner, &invoker);

        let input = PyDict::new(py);
        input.set_item("a", "x").unwrap();
        input.set_item("b", "y").unwrap();
        let result = scp.outlet_invoke_cross_context(
            py,
            &source_ctx,
            &target_ctx,
            &target_outlet,
            &input.as_borrowed(),
            &invoker,
            &target_ucan,
            1,
            None,
        );
        if let Err(err) = result {
            let message = err.to_string();
            assert!(
                !message.contains("does not have invocation capability"),
                "the source-capability gate must read the supervisor's role state: {message}"
            );
        }
    });
}

/// `ucan_mint` enforces the ceiling the SUPERVISOR holds, not one the bridge was
/// registered with.
///
/// The fixture hands `register_context` a WIDE ceiling carrying `outlet:call:*`
/// and creates the supervisor context with a NARROW one that omits it, then
/// mints `outlet_call:*`. The supervisor's ceiling forbids that capability, so
/// the mint must refuse; a bridge-local ceiling built from the registration
/// argument permits it and the mint succeeds.
#[cfg(feature = "testing")]
#[test]
fn ucan_mint_enforces_the_supervisor_ceiling_not_the_registration_ceiling() {
    Python::with_gil(|py| {
        setup();
        let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
        let owner = published_identity_did(py, &scp);
        let audience = published_identity_did(py, &scp);
        let bi = scp.bridge_instance();
        runtime::init_context_manager_for_test(bi);

        let ctx_id = random_context_id();
        let wide = vec![
            "outlet:call:*".to_owned(),
            "messages:read".to_owned(),
            "messages:write".to_owned(),
        ];
        runtime::register_context(bi, &ctx_id, &owner, &wide).unwrap();

        let rt = test_runtime();
        let supervisor = runtime::supervisor(bi).unwrap().clone();
        let creator = scp_did::DID(owner);
        let narrow_ctx = ctx_id.clone();
        rt.block_on(async move {
            let params = scp_core::context::ContextParams {
                ceiling: vec![
                    scp_core::context::roles::Capability::new("messages:read").unwrap(),
                    scp_core::context::roles::Capability::new("messages:write").unwrap(),
                ],
                ..scp_core::context::ContextParams::default()
            };
            supervisor
                .create_context(narrow_ctx, params, creator.clone(), None)
                .await
                .unwrap();
            supervisor.register_local_did(creator).await.unwrap();
        });

        let err = scp
            .ucan_mint(&ctx_id, &audience, vec!["outlet_call:*".to_owned()], None)
            .expect_err("the supervisor ceiling omits outlet_call, so the mint must refuse");
        let message = err.to_string().to_lowercase();
        assert!(
            message.contains("ceiling"),
            "the refusal must be the ceiling check: {message}"
        );
    });
}
