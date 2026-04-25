//! End-to-end tests for the `PyO3` bridge layer.
//!
//! These tests exercise the public API surface of `scp-ffi` from an
//! integration test crate. They cover: identity registry, context
//! lifecycle, tools, UCAN, event log, discovery, provenance, bridge
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
//!   cargo test -p scp-ffi --test e2e_bridge --features allow_in_memory_custody
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::sync::Once;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use _scp_core::custody::FfiKeyCustody;
use _scp_core::runtime::{self, IdentityEntry};

static INIT: Once = Once::new();

/// Ensures the Python interpreter, tokio runtime, and `Supervisor` are initialized.
///
/// Uses `init_supervisor_for_test()` which wires `LocalTransportProvider`
/// so that `publish_context` succeeds without warning noise
/// (`NotConfiguredTransportProvider` would log warnings on best-effort publish).
fn setup() {
    INIT.call_once(|| {
        pyo3::prepare_freethreaded_python();
        // Initialize the crate-internal tokio runtime used by bridge functions
        // like py_event_log_query when storage is available.
        _scp_core::init_runtime().unwrap();
    });
    // Uses LocalTransportProvider so publish_context succeeds without warning
    // noise (NotConfiguredTransportProvider logs warnings on best-effort publish).
    runtime::init_supervisor_for_test();
}

/// Creates a tokio runtime for async operations in tests.
fn test_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Generates a random hex context ID (16 bytes = 32 hex chars).
fn random_context_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Creates an in-memory identity and registers it in the runtime registry.
fn create_test_identity() -> String {
    setup();
    let rt = test_runtime();

    let custody = Arc::new(FfiKeyCustody::InMemory(
        scp_platform::testing::InMemoryKeyCustody::new(),
    ));

    let (identity, document) = rt.block_on(async {
        let did_method = scp_identity::DidDht::new();
        scp_identity::DidMethod::create(&did_method, custody.as_ref())
            .await
            .unwrap()
    });

    let did = identity.did.clone();

    runtime::register_identity(
        &did,
        IdentityEntry {
            identity,
            custody,
            document,
            identity_link_attestations: Vec::new(),
        },
    );

    did
}

/// Creates a context via the per-instance `Supervisor` and registers FFI
/// state. Returns the `context_id`.
fn create_test_context(creator_did: &str) -> String {
    setup();
    let context_id = random_context_id();
    runtime::register_context(&context_id, creator_did, &[]).unwrap();

    let rt = test_runtime();
    let supervisor = runtime::supervisor().unwrap().clone();
    let creator = scp_identity::DID(creator_did.to_owned());
    let ctx_id = context_id.clone();

    rt.block_on(async move {
        let params = scp_core::context::ContextParams::default();
        supervisor
            .create_context(ctx_id.clone(), params, creator.clone(), None)
            .await
            .unwrap();
        supervisor.register_local_did(creator).await.unwrap();
    });

    context_id
}

/// Builds a tool registration `PyDict` with valid schema (2+ properties).
fn build_tool_reg<'py>(py: Python<'py>, name: &str, operator_did: &str) -> Bound<'py, PyDict> {
    let reg = PyDict::new(py);
    reg.set_item("name", name).unwrap();
    reg.set_item("description", format!("Tool: {name}"))
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
    let did = create_test_identity();
    assert!(did.starts_with("did:dht:"));
    assert!(runtime::identity_registry_contains(&did));
}

#[test]
fn identity_multiple_unique() {
    let did1 = create_test_identity();
    let did2 = create_test_identity();
    assert_ne!(did1, did2);
}

#[test]
fn identity_registry_lookup() {
    let did = create_test_identity();
    let result = runtime::with_identity(&did, |entry| Ok(entry.identity.did.clone()));
    assert_eq!(result.unwrap(), did);
}

#[test]
fn identity_unknown_did_fails() {
    setup();
    let result = runtime::with_identity("did:dht:nonexistent", |_| Ok(()));
    assert!(result.is_err());
}

// ============================================================================
// Context lifecycle
// ============================================================================

#[test]
fn context_create_registers_in_runtime() {
    let did = create_test_identity();
    let ctx_id = create_test_context(&did);

    let creator = runtime::with_context(&ctx_id, |rt| Ok(rt.creator_did.clone())).unwrap();
    assert_eq!(creator, did);
}

#[test]
fn context_membership_creator_is_member() {
    let did = create_test_identity();
    let ctx_id = create_test_context(&did);

    let rt = test_runtime();
    let supervisor = runtime::supervisor().unwrap().clone();

    assert!(rt.block_on(supervisor.is_member(&ctx_id, &did)));
    assert_eq!(rt.block_on(supervisor.member_count(&ctx_id)), Some(1));

    let dids = rt.block_on(supervisor.member_dids(&ctx_id));
    assert!(dids.contains(&did));
}

#[test]
fn context_member_role_creator_is_admin() {
    let did = create_test_identity();
    let ctx_id = create_test_context(&did);

    let rt = test_runtime();
    let supervisor = runtime::supervisor().unwrap().clone();

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
    let did = create_test_identity();
    let ctx_id = create_test_context(&did);

    let rt = test_runtime();
    let supervisor = runtime::supervisor().unwrap().clone();

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
    let did = create_test_identity();
    let ctx1 = create_test_context(&did);
    let ctx2 = create_test_context(&did);
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
/// whose `create_mls_group` succeeds (real `MlsCryptoProvider` integration
/// is a separate concern). The test verifies the full bridge path:
/// identity creation → context creation → `ContextManager` state is populated.
#[test]
fn context_create_establishes_mls_group() {
    let did = create_test_identity();
    let ctx_id = create_test_context(&did);

    let rt = test_runtime();
    let supervisor = runtime::supervisor().unwrap().clone();

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
// Tool registration and verification
// ============================================================================

#[test]
fn tool_register_and_verify() {
    Python::with_gil(|py| {
        let did = create_test_identity();
        let ctx_id = create_test_context(&did);

        let reg = PyDict::new(py);
        reg.set_item("name", "test_tool").unwrap();
        reg.set_item("description", "A test tool").unwrap();
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

        let tool_id = _scp_core::tools::py_tool_register(&ctx_id, &reg.as_borrowed()).unwrap();
        assert!(tool_id.contains("test_tool"));

        let result = _scp_core::tools::py_tool_verify(&ctx_id, &tool_id).unwrap();
        assert!(result.passed);
        assert!(result.failures.is_empty());
    });
}

#[test]
fn tool_register_rejects_invalid_context() {
    setup();
    Python::with_gil(|py| {
        let reg = PyDict::new(py);
        reg.set_item("name", "orphan_tool").unwrap();
        reg.set_item("description", "No context").unwrap();
        reg.set_item("operator_did", "did:key:test").unwrap();
        let schema = PyDict::new(py);
        schema.set_item("input_schema", PyDict::new(py)).unwrap();
        schema.set_item("output_schema", PyDict::new(py)).unwrap();
        reg.set_item("schema", schema).unwrap();

        let result = _scp_core::tools::py_tool_register("nonexistent-ctx", &reg.as_borrowed());
        assert!(result.is_err());
    });
}

#[test]
fn tool_register_rejects_empty_name() {
    Python::with_gil(|py| {
        let did = create_test_identity();
        let ctx_id = create_test_context(&did);

        let reg = PyDict::new(py);
        reg.set_item("name", "").unwrap();
        reg.set_item("description", "bad tool").unwrap();
        reg.set_item("operator_did", &did).unwrap();
        let schema = PyDict::new(py);
        schema.set_item("input_schema", PyDict::new(py)).unwrap();
        schema.set_item("output_schema", PyDict::new(py)).unwrap();
        reg.set_item("schema", schema).unwrap();

        let result = _scp_core::tools::py_tool_register(&ctx_id, &reg.as_borrowed());
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
    let result = _scp_core::ucan::py_ucan_mint(
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
        let did = create_test_identity();
        let ctx_id = create_test_context(&did);

        // Event log starts empty when context is created via ContextManager
        // (not via py_context_create which appends events). Query should
        // succeed and return an empty list.
        let events = _scp_core::event_log::py_event_log_query(py, &ctx_id, None).unwrap();
        assert!(events.is_empty());
    });
}

#[test]
fn event_log_query_with_appended_event() {
    Python::with_gil(|py| {
        let did = create_test_identity();
        let ctx_id = create_test_context(&did);

        // Manually append an unsigned event to the log.
        runtime::with_context(&ctx_id, |rt| {
            let event = scp_event_log::Event {
                event_type: scp_event_log::EventType::ContextCreated,
                actor_did: scp_identity::DID("did:key:test".to_owned()),
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
        let events = _scp_core::event_log::py_event_log_query(py, &ctx_id, None).unwrap();
        assert!(!events.is_empty());
    });
}

#[test]
fn event_log_query_with_filter() {
    Python::with_gil(|py| {
        let did = create_test_identity();
        let ctx_id = create_test_context(&did);

        let filter = PyDict::new(py);
        filter.set_item("limit", 1).unwrap();

        let events =
            _scp_core::event_log::py_event_log_query(py, &ctx_id, Some(&filter.as_borrowed()))
                .unwrap();
        assert!(events.len() <= 1);
    });
}

#[test]
fn event_log_verify_inclusion_proof_after_append() {
    Python::with_gil(|py| {
        let did = create_test_identity();
        let ctx_id = create_test_context(&did);

        // Append an unsigned event so the log is non-empty.
        runtime::with_context(&ctx_id, |rt| {
            let event = scp_event_log::Event {
                event_type: scp_event_log::EventType::ContextCreated,
                actor_did: scp_identity::DID("did:key:test".to_owned()),
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

        let proof =
            _scp_core::event_log::py_event_log_verify(py, &ctx_id, &claim.as_borrowed()).unwrap();
        assert!(proof.verified);
        assert_eq!(proof.proof_type, "inclusion");
    });
}

#[test]
fn event_log_query_invalid_context_fails() {
    setup();
    Python::with_gil(|py| {
        let result = _scp_core::event_log::py_event_log_query(py, "nonexistent", None);
        assert!(result.is_err());
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
    let q = _scp_core::provenance::py_evaluate_provenance_quality(
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
        _scp_core::provenance::py_evaluate_provenance_quality(None, "invalid_type", "active", None);
    assert!(r.is_err());
}

#[test]
fn provenance_attach_returns_dict() {
    setup();
    Python::with_gil(|py| {
        let r = _scp_core::provenance::py_provenance_attach(
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
        let r = _scp_core::provenance::py_provenance_attach(
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
    assert!(_scp_core::provenance::py_provenance_check_chain_depth(
        0, None
    ));
    assert!(_scp_core::provenance::py_provenance_check_chain_depth(
        3, None
    ));
}

#[test]
fn provenance_check_chain_depth_exceeds_limit() {
    setup();
    // Default is now 8 (ADR-043), so depth 4 is within default.
    assert!(_scp_core::provenance::py_provenance_check_chain_depth(
        4, None
    ));
    // Depth 9 exceeds default of 8.
    assert!(!_scp_core::provenance::py_provenance_check_chain_depth(
        9, None
    ));
    assert!(!_scp_core::provenance::py_provenance_check_chain_depth(
        2,
        Some(1)
    ));
}

#[test]
fn provenance_attach_rejects_invalid_memory_scope() {
    setup();
    Python::with_gil(|py| {
        let r = _scp_core::provenance::py_provenance_attach(
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
        let r = _scp_core::bridge_connector::py_bridge_create_shadow(
            py,
            "bridge-d",
            "@user#1234",
            "relay",
            "ctx-sh",
        )
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
        let r = _scp_core::trust::py_trust_query_score(py, "did:key:test", "ctx-trust").unwrap();
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
        assert!(_scp_core::trust::py_trust_query_score(py, "", "ctx-valid").is_err());
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
    assert!(_scp_core::trust::py_verify_participation_requirements("[]", "[]").unwrap());
}

// ============================================================================
// Cross-domain: Identity -> Context -> Tool -> UCAN -> EventLog
// ============================================================================

#[test]
fn cross_domain_identity_context_tool_eventlog_provenance() {
    // Cross-domain flow test: identity -> context -> tool -> event log -> provenance.
    // Does NOT call functions requiring the crate-internal global runtime
    // (py_ucan_mint, py_event_log_checkpoint). Those are tested in unit tests.
    Python::with_gil(|py| {
        let did_a = create_test_identity();
        let ctx_id = create_test_context(&did_a);

        runtime::with_context(&ctx_id, |rt| {
            rt.ceiling_strings.insert("tool_invoke:*".to_owned());
            rt.ceiling_strings.insert("messages:write".to_owned());
            Ok(())
        })
        .unwrap();

        // Register a tool using the helper.
        let reg = build_tool_reg(py, "cross_domain_tool", &did_a);
        let tool_id = _scp_core::tools::py_tool_register(&ctx_id, &reg.as_borrowed()).unwrap();
        assert!(!tool_id.is_empty());

        // Verify tool.
        let vr = _scp_core::tools::py_tool_verify(&ctx_id, &tool_id).unwrap();
        assert!(vr.passed);

        // Append an event and query.
        runtime::with_context(&ctx_id, |rt| {
            let event = scp_event_log::Event {
                event_type: scp_event_log::EventType::ContextCreated,
                actor_did: scp_identity::DID(did_a.clone()),
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

        let events = _scp_core::event_log::py_event_log_query(py, &ctx_id, None).unwrap();
        assert!(!events.is_empty());

        // Revoke a token (revoker is the context creator).
        let dummy = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsInVjdiI6IjAuMTAuMCJ9.\
            eyJpc3MiOiJkaWQ6a2V5OnRlc3QiLCJhdWQiOiJkaWQ6a2V5OnRlc3QyIiwiZXhwIjo5OTk5OTk5OTk5LCJubmMiOiIxNjk5OTk5MDAwMDAwLWFhYmJjY2RkMTEyMjMzNDQiLCJhdHQiOltdLCJwcmYiOltdfQ.\
            dGVzdC1zaWduYXR1cmUtYnl0ZXMtMDAwMDAwMDAwMDAw";
        _scp_core::ucan::py_ucan_revoke(&ctx_id, dummy, &did_a).unwrap();

        // Evaluate provenance.
        let q = _scp_core::provenance::py_evaluate_provenance_quality(
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
// Storage initialization
// ============================================================================

#[test]
fn init_storage_in_memory() {
    setup();
    assert!(runtime::init_storage("in_memory").is_ok());
}

#[test]
fn init_storage_unknown_type_fails() {
    setup();
    assert!(runtime::init_storage("nonexistent").is_err());
}
