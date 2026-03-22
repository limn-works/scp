#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::single_match,
    clippy::cast_precision_loss
)]

//! B15: FFI Bridge API Surface Conformance
//!
//! Verifies that the 4 FFI bridges (PyO3, UniFFI, NAPI, WASM) export
//! consistent operation sets. PyO3 is the reference bridge (100% coverage
//! target). Other bridges should match except where architecture constraints
//! apply (e.g. WASM cannot depend on scp-core per ADR-034).
//!
//! Implementation: reads bridge source files at compile time via `include_str!`
//! and searches for exported function name patterns. Each bridge has naming
//! conventions (e.g. PyO3 prefixes with `py_`, WASM uses alternate names for
//! some operations) that are handled by per-bridge alias tables.

// ---------------------------------------------------------------------------
// Source files embedded at compile time
// ---------------------------------------------------------------------------

// PyO3 bridge sources
const PYO3_IDENTITY: &str = include_str!("../../../../crates/scp-ffi/src/identity.rs");
const PYO3_CONTEXT: &str = include_str!("../../../../crates/scp-ffi/src/context.rs");
const PYO3_TOOLS: &str = include_str!("../../../../crates/scp-ffi/src/tools.rs");
const PYO3_UCAN: &str = include_str!("../../../../crates/scp-ffi/src/ucan.rs");
const PYO3_EVENT_LOG: &str = include_str!("../../../../crates/scp-ffi/src/event_log.rs");
const PYO3_TRANSPORT: &str = include_str!("../../../../crates/scp-ffi/src/transport.rs");
const PYO3_BRIDGE_CONNECTOR: &str =
    include_str!("../../../../crates/scp-ffi/src/bridge_connector.rs");
const PYO3_SYNC: &str = include_str!("../../../../crates/scp-ffi/src/sync.rs");
const PYO3_PROVENANCE: &str = include_str!("../../../../crates/scp-ffi/src/provenance.rs");
const PYO3_DISCOVERY: &str = include_str!("../../../../crates/scp-ffi/src/discovery.rs");
const PYO3_TRUST: &str = include_str!("../../../../crates/scp-ffi/src/trust.rs");
const PYO3_MCP: &str = include_str!("../../../../crates/scp-ffi/src/mcp.rs");
const PYO3_ECONOMY: &str = include_str!("../../../../crates/scp-ffi/src/economy.rs");
const PYO3_MEDIA: &str = include_str!("../../../../crates/scp-ffi/src/media.rs");

// UniFFI bridge (single file)
const UNIFFI_BRIDGE: &str = include_str!("../../../../crates/scp-ffi/uniffi/src/bridge.rs");

// NAPI bridge sources
const NAPI_IDENTITY: &str = include_str!("../../../../crates/scp-ffi/napi/src/identity.rs");
const NAPI_CONTEXT: &str = include_str!("../../../../crates/scp-ffi/napi/src/context.rs");
const NAPI_TOOLS: &str = include_str!("../../../../crates/scp-ffi/napi/src/tools.rs");
const NAPI_UCAN: &str = include_str!("../../../../crates/scp-ffi/napi/src/ucan.rs");
const NAPI_EVENT_LOG: &str = include_str!("../../../../crates/scp-ffi/napi/src/event_log.rs");
const NAPI_TRANSPORT: &str = include_str!("../../../../crates/scp-ffi/napi/src/transport.rs");
const NAPI_BRIDGE_CONNECTOR: &str =
    include_str!("../../../../crates/scp-ffi/napi/src/bridge_connector.rs");
const NAPI_SYNC: &str = include_str!("../../../../crates/scp-ffi/napi/src/sync.rs");
const NAPI_PROVENANCE: &str = include_str!("../../../../crates/scp-ffi/napi/src/provenance.rs");
const NAPI_DISCOVERY: &str = include_str!("../../../../crates/scp-ffi/napi/src/discovery.rs");
const NAPI_TRUST: &str = include_str!("../../../../crates/scp-ffi/napi/src/trust.rs");
const NAPI_MCP: &str = include_str!("../../../../crates/scp-ffi/napi/src/mcp.rs");
const NAPI_ECONOMY: &str = include_str!("../../../../crates/scp-ffi/napi/src/economy.rs");
const NAPI_MEDIA: &str = include_str!("../../../../crates/scp-ffi/napi/src/media.rs");

// WASM bridge sources
const WASM_IDENTITY: &str = include_str!("../../../../crates/scp-ffi/wasm/src/identity.rs");
const WASM_CONTEXT: &str = include_str!("../../../../crates/scp-ffi/wasm/src/context.rs");
const WASM_TOOLS: &str = include_str!("../../../../crates/scp-ffi/wasm/src/tools.rs");
const WASM_UCAN: &str = include_str!("../../../../crates/scp-ffi/wasm/src/ucan.rs");
const WASM_EVENT_LOG: &str = include_str!("../../../../crates/scp-ffi/wasm/src/event_log.rs");
const WASM_TRANSPORT: &str = include_str!("../../../../crates/scp-ffi/wasm/src/transport.rs");
const WASM_SYNC: &str = include_str!("../../../../crates/scp-ffi/wasm/src/sync.rs");
const WASM_PROVENANCE: &str = include_str!("../../../../crates/scp-ffi/wasm/src/provenance.rs");
const WASM_DISCOVERY: &str = include_str!("../../../../crates/scp-ffi/wasm/src/discovery.rs");
const WASM_TRUST: &str = include_str!("../../../../crates/scp-ffi/wasm/src/trust.rs");
const WASM_ECONOMY: &str = include_str!("../../../../crates/scp-ffi/wasm/src/economy.rs");

// ---------------------------------------------------------------------------
// Reference operation set
//
// Each tuple: (category, canonical_name, wasm_required)
// `wasm_required=false` means WASM is allowed to omit it per ADR-034.
//
// The canonical name is the "ideal" shared name. Each bridge detection
// function uses an alias table to map canonical names to the actual function
// names in that bridge (e.g. PyO3 prefixes with `py_`, NAPI uses
// `context_execute_governance_action` for `governance_execute`, etc.).
// ---------------------------------------------------------------------------

const PARITY_OPERATIONS: &[(&str, &str, bool)] = &[
    // Identity
    ("identity", "identity_create", true),
    ("identity", "identity_load", true),
    ("identity", "identity_resolve", true),
    ("identity", "identity_migrate", true),
    ("identity", "identity_attest_device", true),
    ("identity", "identity_verify_device_attestation", true),
    // Context lifecycle
    ("context", "context_create", true),
    ("context", "context_join", true),
    ("context", "context_leave", true),
    ("context", "context_close", true),
    ("context", "context_send", true),
    ("context", "context_subscribe", true),
    ("context", "context_export", true),
    ("context", "context_import", true),
    // Membership queries
    ("membership", "context_member_count", true),
    ("membership", "context_is_member", true),
    ("membership", "context_member_dids", true),
    ("membership", "context_member_role", true),
    // Events
    ("events", "context_drain_events", true),
    // Governance
    ("governance", "governance_execute", true),
    // Tools
    ("tools", "tool_register", true),
    ("tools", "tool_invoke", true),
    ("tools", "tool_verify", true),
    ("tools", "tool_invoke_cross_context", false),
    ("tools", "tool_session_create", false),
    ("tools", "tool_session_invoke", false),
    ("tools", "tool_session_close", false),
    // UCAN
    ("ucan", "ucan_validate", true),
    ("ucan", "ucan_mint", true),
    ("ucan", "ucan_revoke", true),
    ("ucan", "ucan_delegate", true),
    // Event Log
    ("event_log", "event_log_query", true),
    ("event_log", "event_log_verify", true),
    ("event_log", "event_log_checkpoint", true),
    // Transport -- WASM has these but they are optional per ADR-034
    ("transport", "transport_connect", false),
    ("transport", "transport_status", false),
    // Broadcast
    ("broadcast", "broadcast_subscribe", true),
    ("broadcast", "broadcast_unsubscribe", true),
    ("broadcast", "broadcast_publish", true),
    ("broadcast", "broadcast_block", true),
    // Trust
    ("trust", "trust_query_score", true),
    ("trust", "trust_verify_attestation", true),
    ("trust", "trust_create_challenge", true),
    ("trust", "trust_verify_response", true),
    ("trust", "verify_participation_requirements", true),
    // Sync
    ("sync", "sync_classify_offline", true),
    ("sync", "sync_classify_offline_custom", true),
    ("sync", "sync_get_policy", true),
    // Discovery
    ("discovery", "discovery_parse_address", true),
    ("discovery", "discovery_normalize_address", true),
    // Provenance
    ("provenance", "provenance_check_chain_depth", true),
    ("provenance", "evaluate_provenance_quality", true),
    ("provenance", "provenance_attach", true),
    // Bridge connector -- WASM does not have these (no cross-bridge in browser)
    ("bridge", "bridge_evaluate_trust", false),
    ("bridge", "bridge_register", false),
    ("bridge", "bridge_create_shadow", false),
    // MCP -- PyO3 and NAPI only (WASM/UniFFI do not expose MCP server/client)
    ("mcp", "mcp_server", false),
    ("mcp", "mcp_client", false),
    // Economy -- WASM has a subset; not required per ADR-034
    ("economy", "economy_estimate_cost", false),
    ("economy", "economy_policy_requires_payment", false),
    ("economy", "economy_auto_accept_blocked", false),
    ("economy", "economy_check_policy_lock", false),
    ("economy", "economy_validate_policy_change", false),
    ("economy", "economy_evaluate_formula", false),
    ("economy", "economy_adjust_relay_price", false),
    ("economy", "economy_budget_remaining", false),
    ("economy", "economy_budget_grant", false),
    ("economy", "economy_budget_record_spend", false),
    ("economy", "economy_antispam_record", false),
    ("economy", "economy_antispam_velocity", false),
    ("economy", "economy_antispam_escalated_cost", false),
    // Media -- WASM has no media bridge; not required per ADR-034
    ("media", "media_initiate_session", false),
    ("media", "media_activate_session", false),
    ("media", "media_join_session", false),
    ("media", "media_end_session", false),
    ("media", "media_create_offer", false),
    ("media", "media_create_answer", false),
    ("media", "media_create_ice_candidate", false),
    ("media", "media_create_session_end", false),
    ("media", "media_send_signaling", false),
    ("media", "media_verify_sender_attribution", false),
    ("media", "media_check_capability", false),
    // Petname -- all bridges including WASM
    ("petname", "petname_set", true),
    ("petname", "petname_remove", true),
    ("petname", "petname_set_context", true),
    ("petname", "petname_remove_context", true),
    ("petname", "petname_resolve_did", true),
    ("petname", "petname_resolve_context", true),
    ("petname", "petname_get_for_did", true),
    ("petname", "petname_get_for_context", true),
    // Handle/Scope -- all bridges including WASM
    ("handle", "handle_register", true),
    ("handle", "handle_lookup", true),
    ("handle", "handle_deregister", true),
    ("scope", "scope_register", true),
    ("scope", "scope_lookup", true),
    ("scope", "scope_deregister", true),
    // Governance checkpoints -- all bridges including WASM
    ("governance", "context_create_governance_checkpoint", true),
    ("governance", "context_add_checkpoint_cosignature", true),
];

// ---------------------------------------------------------------------------
// Detection: source contains `fn <name>(` or `fn <name> (`
// ---------------------------------------------------------------------------

fn source_has_fn(source: &str, name: &str) -> bool {
    // Match `fn name(`, `fn name (`, or `fn name<` (generic lifetime params)
    source.contains(&format!("fn {name}("))
        || source.contains(&format!("fn {name} ("))
        || source.contains(&format!("fn {name}<"))
}

fn any_source_has_fn(sources: &[&str], name: &str) -> bool {
    sources.iter().any(|s| source_has_fn(s, name))
}

// ---------------------------------------------------------------------------
// Per-bridge alias tables
//
// Maps canonical operation name -> actual function names to search for.
// Bridges with no alias entry use the canonical name directly, plus
// any bridge-specific prefix (py_ for PyO3).
// ---------------------------------------------------------------------------

/// Returns the function names to search for in PyO3 sources.
/// PyO3 prefixes all functions with `py_`, plus some operations use
/// different names (e.g. `context_receive` instead of `context_subscribe`).
fn pyo3_names(canonical: &str) -> Vec<String> {
    let mut names = vec![format!("py_{canonical}")];
    match canonical {
        // PyO3 uses "context_receive" for the subscribe/receive pattern
        "context_subscribe" => {
            names.push("py_context_receive".to_string());
        }
        // PyO3 uses "broadcast_block_subscriber" not "broadcast_block"
        "broadcast_block" => {
            names.push("py_broadcast_block_subscriber".to_string());
        }
        // PyO3 governance is named py_governance_execute
        "governance_execute" => {
            names.push("py_governance_execute".to_string());
        }
        // MCP: check for specific sub-functions
        "mcp_server" => {
            names.push("py_mcp_serve".to_string());
        }
        "mcp_client" => {
            names.push("py_mcp_client_connect_stdio".to_string());
        }
        // Governance checkpoints: PyO3 uses py_create_governance_checkpoint
        "context_create_governance_checkpoint" => {
            names.push("py_create_governance_checkpoint".to_string());
        }
        "context_add_checkpoint_cosignature" => {
            names.push("py_add_checkpoint_cosignature".to_string());
        }
        _ => {}
    }
    names
}

/// Returns the function names to search for in UniFFI source.
fn uniffi_names(canonical: &str) -> Vec<String> {
    let mut names = vec![canonical.to_string()];
    match canonical {
        "broadcast_block" => {
            names.push("broadcast_block_subscriber".to_string());
        }
        // UniFFI uses create_governance_checkpoint (no context_ prefix)
        "context_create_governance_checkpoint" => {
            names.push("create_governance_checkpoint".to_string());
        }
        "context_add_checkpoint_cosignature" => {
            names.push("add_checkpoint_cosignature".to_string());
        }
        _ => {}
    }
    names
}

/// Returns the function names to search for in NAPI sources.
fn napi_names(canonical: &str) -> Vec<String> {
    let mut names = vec![canonical.to_string()];
    match canonical {
        "governance_execute" => {
            names.push("context_execute_governance_action".to_string());
        }
        "broadcast_block" => {
            names.push("broadcast_block_subscriber".to_string());
        }
        "mcp_server" => {
            names.push("mcp_server_create".to_string());
        }
        "mcp_client" => {
            names.push("mcp_client_connect_stdio".to_string());
        }
        _ => {}
    }
    names
}

/// Returns the function names to search for in WASM sources.
fn wasm_names(canonical: &str) -> Vec<String> {
    let mut names = vec![canonical.to_string()];
    match canonical {
        "governance_execute" => {
            names.push("context_execute_governance".to_string());
        }
        "broadcast_block_subscriber" => {
            names.push("broadcast_block".to_string());
        }
        _ => {}
    }
    names
}

// ---------------------------------------------------------------------------
// Per-bridge detection
// ---------------------------------------------------------------------------

fn pyo3_has_operation(sources: &[&str], canonical: &str) -> bool {
    pyo3_names(canonical)
        .iter()
        .any(|name| any_source_has_fn(sources, name))
}

fn uniffi_has_operation(canonical: &str) -> bool {
    uniffi_names(canonical)
        .iter()
        .any(|name| source_has_fn(UNIFFI_BRIDGE, name))
}

fn napi_has_operation(sources: &[&str], canonical: &str) -> bool {
    napi_names(canonical)
        .iter()
        .any(|name| any_source_has_fn(sources, name))
}

fn wasm_has_operation(sources: &[&str], canonical: &str) -> bool {
    wasm_names(canonical)
        .iter()
        .any(|name| any_source_has_fn(sources, name))
}

// ---------------------------------------------------------------------------
// Collected sources per bridge
// ---------------------------------------------------------------------------

fn pyo3_sources() -> Vec<&'static str> {
    vec![
        PYO3_IDENTITY,
        PYO3_CONTEXT,
        PYO3_TOOLS,
        PYO3_UCAN,
        PYO3_EVENT_LOG,
        PYO3_TRANSPORT,
        PYO3_BRIDGE_CONNECTOR,
        PYO3_SYNC,
        PYO3_PROVENANCE,
        PYO3_DISCOVERY,
        PYO3_TRUST,
        PYO3_MCP,
        PYO3_ECONOMY,
        PYO3_MEDIA,
    ]
}

fn napi_sources() -> Vec<&'static str> {
    vec![
        NAPI_IDENTITY,
        NAPI_CONTEXT,
        NAPI_TOOLS,
        NAPI_UCAN,
        NAPI_EVENT_LOG,
        NAPI_TRANSPORT,
        NAPI_BRIDGE_CONNECTOR,
        NAPI_SYNC,
        NAPI_PROVENANCE,
        NAPI_DISCOVERY,
        NAPI_TRUST,
        NAPI_MCP,
        NAPI_ECONOMY,
        NAPI_MEDIA,
    ]
}

fn wasm_sources() -> Vec<&'static str> {
    vec![
        WASM_IDENTITY,
        WASM_CONTEXT,
        WASM_TOOLS,
        WASM_UCAN,
        WASM_EVENT_LOG,
        WASM_TRANSPORT,
        WASM_SYNC,
        WASM_PROVENANCE,
        WASM_DISCOVERY,
        WASM_TRUST,
        WASM_ECONOMY,
    ]
}

// ---------------------------------------------------------------------------
// Coverage result
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct BridgeCoverage {
    name: &'static str,
    present: Vec<(&'static str, &'static str)>,
    missing: Vec<(&'static str, &'static str)>,
    total: usize,
}

impl BridgeCoverage {
    fn coverage_pct(&self) -> f64 {
        if self.total == 0 {
            return 100.0;
        }
        (self.present.len() as f64 / self.total as f64) * 100.0
    }
}

fn compute_coverage<F>(name: &'static str, detect: F) -> BridgeCoverage
where
    F: Fn(&str) -> bool,
{
    let mut present = Vec::new();
    let mut missing = Vec::new();

    for &(category, op, _) in PARITY_OPERATIONS {
        if detect(op) {
            present.push((category, op));
        } else {
            missing.push((category, op));
        }
    }

    let total = PARITY_OPERATIONS.len();
    BridgeCoverage {
        name,
        present,
        missing,
        total,
    }
}

fn compute_pyo3_coverage() -> BridgeCoverage {
    let sources = pyo3_sources();
    compute_coverage("PyO3", |op| pyo3_has_operation(&sources, op))
}

fn compute_uniffi_coverage() -> BridgeCoverage {
    compute_coverage("UniFFI", uniffi_has_operation)
}

fn compute_napi_coverage() -> BridgeCoverage {
    let sources = napi_sources();
    compute_coverage("NAPI", |op| napi_has_operation(&sources, op))
}

fn compute_wasm_coverage() -> BridgeCoverage {
    let sources = wasm_sources();
    compute_coverage("WASM", |op| wasm_has_operation(&sources, op))
}

// ---------------------------------------------------------------------------
// Helper: print missing operations
// ---------------------------------------------------------------------------

fn print_coverage(cov: &BridgeCoverage) {
    eprintln!(
        "{} coverage: {:.1}% ({}/{})",
        cov.name,
        cov.coverage_pct(),
        cov.present.len(),
        cov.total
    );
    if !cov.missing.is_empty() {
        eprintln!("{} missing operations:", cov.name);
        for (cat, op) in &cov.missing {
            eprintln!("  {cat}/{op}");
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// PyO3 is the reference bridge -- it must cover ALL operations.
#[test]
fn pyo3_bridge_covers_all_operations() {
    let coverage = compute_pyo3_coverage();
    print_coverage(&coverage);

    if !coverage.missing.is_empty() {
        let missing_list: Vec<String> = coverage
            .missing
            .iter()
            .map(|(cat, op)| format!("  {cat}/{op}"))
            .collect();
        panic!(
            "PyO3 (reference bridge) is missing {} operations:\n{}",
            coverage.missing.len(),
            missing_list.join("\n")
        );
    }
}

/// UniFFI bridge should cover all core operations except MCP (which UniFFI
/// does not expose) and bridge_register/bridge_create_shadow (not yet
/// implemented). Fails on any gap outside the documented exclusion set.
#[test]
fn uniffi_bridge_covers_core_operations() {
    let coverage = compute_uniffi_coverage();
    print_coverage(&coverage);

    // Known intentional exclusions for UniFFI:
    // - mcp_server / mcp_client: UniFFI targets mobile; MCP is PyO3/NAPI only
    let known_exclusions: &[&str] = &["mcp_server", "mcp_client"];

    let unexpected_missing: Vec<_> = coverage
        .missing
        .iter()
        .filter(|(_, op)| !known_exclusions.contains(op))
        .collect();

    assert!(
        unexpected_missing.is_empty(),
        "UniFFI has {} unexpected missing operations: {:?}",
        unexpected_missing.len(),
        unexpected_missing
    );

    // Also assert the known exclusion count hasn't grown
    let known_missing_count = coverage
        .missing
        .iter()
        .filter(|(_, op)| known_exclusions.contains(op))
        .count();
    assert_eq!(
        known_missing_count,
        known_exclusions.len(),
        "Known exclusion count mismatch -- an excluded operation may have been added"
    );
}

/// NAPI bridge should cover all operations except identity_migrate
/// (not yet implemented in NAPI).
#[test]
fn napi_bridge_covers_core_operations() {
    let coverage = compute_napi_coverage();
    print_coverage(&coverage);

    // Known intentional exclusions for NAPI:
    // - identity_migrate: not yet in NAPI bridge
    let known_exclusions: &[&str] = &["identity_migrate"];

    let unexpected_missing: Vec<_> = coverage
        .missing
        .iter()
        .filter(|(_, op)| !known_exclusions.contains(op))
        .collect();

    assert!(
        unexpected_missing.is_empty(),
        "NAPI has {} unexpected missing operations: {:?}",
        unexpected_missing.len(),
        unexpected_missing
    );
}

/// WASM bridge has intentionally fewer operations per ADR-034.
/// This test verifies all wasm_required operations are present and reports
/// optional gaps without failing.
#[test]
fn wasm_bridge_covers_core_operations() {
    let coverage = compute_wasm_coverage();
    print_coverage(&coverage);

    // Separate required vs optional gaps
    let required_missing: Vec<_> = coverage
        .missing
        .iter()
        .filter(|(cat, op)| {
            PARITY_OPERATIONS
                .iter()
                .any(|(c, o, req)| c == cat && o == op && *req)
        })
        .collect();

    let optional_missing: Vec<_> = coverage
        .missing
        .iter()
        .filter(|(cat, op)| {
            PARITY_OPERATIONS
                .iter()
                .any(|(c, o, req)| c == cat && o == op && !*req)
        })
        .collect();

    if !optional_missing.is_empty() {
        eprintln!("WASM intentionally omitted operations (ADR-034, not failures):");
        for (cat, op) in &optional_missing {
            eprintln!("  {cat}/{op}");
        }
    }

    assert!(
        required_missing.is_empty(),
        "WASM is missing {} required operations: {:?}",
        required_missing.len(),
        required_missing
    );
}

/// Cross-bridge parity matrix: builds and prints a matrix of all operations
/// across all 4 bridges. Documents the current state of parity.
///
/// Assertions:
/// 1. PyO3 (reference) must be 100%.
/// 2. Every bridge must cover all operations marked wasm_required=true
///    (with documented exclusions per bridge).
#[test]
fn cross_bridge_parity_matrix() {
    let pyo3 = compute_pyo3_coverage();
    let uniffi = compute_uniffi_coverage();
    let napi = compute_napi_coverage();
    let wasm = compute_wasm_coverage();

    // Print matrix header
    eprintln!();
    eprintln!(
        "{:<15} {:<40} {:>5} {:>6} {:>5} {:>5}",
        "Category", "Operation", "PyO3", "UniFFI", "NAPI", "WASM"
    );
    eprintln!("{}", "-".repeat(82));

    for &(category, op, _wasm_required) in PARITY_OPERATIONS {
        let p = pyo3.present.iter().any(|(_, o)| *o == op);
        let u = uniffi.present.iter().any(|(_, o)| *o == op);
        let n = napi.present.iter().any(|(_, o)| *o == op);
        let w = wasm.present.iter().any(|(_, o)| *o == op);

        let mark = |present: bool| if present { "Y" } else { "-" };

        eprintln!(
            "{:<15} {:<40} {:>5} {:>6} {:>5} {:>5}",
            category,
            op,
            mark(p),
            mark(u),
            mark(n),
            mark(w)
        );
    }

    // Summary
    eprintln!("{}", "-".repeat(82));
    eprintln!(
        "{:<15} {:<40} {:>5} {:>6} {:>5} {:>5}",
        "TOTAL",
        "",
        pyo3.present.len(),
        uniffi.present.len(),
        napi.present.len(),
        wasm.present.len()
    );
    eprintln!(
        "{:<15} {:<40} {:>4.1}% {:>5.1}% {:>4.1}% {:>4.1}%",
        "COVERAGE",
        "",
        pyo3.coverage_pct(),
        uniffi.coverage_pct(),
        napi.coverage_pct(),
        wasm.coverage_pct()
    );
    eprintln!();

    // PyO3 is the reference -- must be 100%
    assert_eq!(
        pyo3.present.len(),
        pyo3.total,
        "PyO3 (reference bridge) must have 100% coverage"
    );

    // Count total unique operations across all non-reference bridges
    let all_gaps: usize = uniffi.missing.len() + napi.missing.len() + wasm.missing.len();
    eprintln!("Total parity gaps across non-reference bridges: {all_gaps}");

    // Verify minimum coverage thresholds
    assert!(
        uniffi.coverage_pct() >= 85.0,
        "UniFFI coverage {:.1}% below 85% threshold",
        uniffi.coverage_pct()
    );
    assert!(
        napi.coverage_pct() >= 95.0,
        "NAPI coverage {:.1}% below 95% threshold",
        napi.coverage_pct()
    );
    assert!(
        wasm.coverage_pct() >= 70.0,
        "WASM coverage {:.1}% below 70% threshold",
        wasm.coverage_pct()
    );
}

// ---------------------------------------------------------------------------
// Marker attribute presence tests
// ---------------------------------------------------------------------------

/// Verifies PyO3 source files actually contain `#[pyfunction]` markers.
#[test]
fn pyo3_sources_contain_pyfunction_markers() {
    let sources = pyo3_sources();
    let marker_count: usize = sources
        .iter()
        .map(|s| s.matches("#[pyfunction]").count())
        .sum();

    eprintln!("PyO3 #[pyfunction] count: {marker_count}");
    assert!(
        marker_count >= 30,
        "Expected at least 30 #[pyfunction] markers, found {marker_count}"
    );
}

/// Verifies UniFFI bridge source contains `#[uniffi::export]` markers.
#[test]
fn uniffi_source_contains_export_markers() {
    let marker_count = UNIFFI_BRIDGE.matches("#[uniffi::export]").count();

    eprintln!("UniFFI #[uniffi::export] count: {marker_count}");
    assert!(
        marker_count >= 30,
        "Expected at least 30 #[uniffi::export] markers, found {marker_count}"
    );
}

/// Verifies NAPI source files actually contain `#[napi]` markers.
#[test]
fn napi_sources_contain_napi_markers() {
    let sources = napi_sources();
    let marker_count: usize = sources.iter().map(|s| s.matches("#[napi]").count()).sum();

    eprintln!("NAPI #[napi] count: {marker_count}");
    assert!(
        marker_count >= 30,
        "Expected at least 30 #[napi] markers, found {marker_count}"
    );
}

/// Verifies WASM source files actually contain `#[wasm_bindgen]` markers.
#[test]
fn wasm_sources_contain_wasm_bindgen_markers() {
    let sources = wasm_sources();
    let marker_count: usize = sources
        .iter()
        .map(|s| s.matches("#[wasm_bindgen]").count())
        .sum();

    eprintln!("WASM #[wasm_bindgen] count: {marker_count}");
    assert!(
        marker_count >= 30,
        "Expected at least 30 #[wasm_bindgen] markers, found {marker_count}"
    );
}

// ---------------------------------------------------------------------------
// Per-category coverage depth tests
// ---------------------------------------------------------------------------

/// Verifies identity operations are present across all bridges.
/// identity_migrate is excluded from UniFFI/NAPI (known gap).
#[test]
fn identity_category_coverage() {
    let identity_ops: Vec<_> = PARITY_OPERATIONS
        .iter()
        .filter(|(cat, _, _)| *cat == "identity")
        .collect();

    let pyo3_srcs = pyo3_sources();
    let napi_srcs = napi_sources();
    let wasm_srcs = wasm_sources();

    for &(_, op, _) in &identity_ops {
        assert!(
            pyo3_has_operation(&pyo3_srcs, op),
            "PyO3 missing identity op: {op}"
        );
        assert!(
            wasm_has_operation(&wasm_srcs, op),
            "WASM missing identity op: {op}"
        );

        // identity_migrate is a known gap in UniFFI and NAPI
        if *op != "identity_migrate" {
            assert!(uniffi_has_operation(op), "UniFFI missing identity op: {op}");
            assert!(
                napi_has_operation(&napi_srcs, op),
                "NAPI missing identity op: {op}"
            );
        }
    }
}

/// Verifies context lifecycle operations are present across all bridges.
/// Handles naming variance: PyO3 uses `context_receive` for `context_subscribe`.
#[test]
fn context_category_coverage() {
    let context_ops: Vec<_> = PARITY_OPERATIONS
        .iter()
        .filter(|(cat, _, _)| *cat == "context")
        .collect();

    let pyo3_srcs = pyo3_sources();
    let napi_srcs = napi_sources();
    let wasm_srcs = wasm_sources();

    for &(_, op, _) in &context_ops {
        assert!(
            pyo3_has_operation(&pyo3_srcs, op),
            "PyO3 missing context op: {op}"
        );
        assert!(uniffi_has_operation(op), "UniFFI missing context op: {op}");
        assert!(
            napi_has_operation(&napi_srcs, op),
            "NAPI missing context op: {op}"
        );
        assert!(
            wasm_has_operation(&wasm_srcs, op),
            "WASM missing context op: {op}"
        );
    }
}

/// Verifies UCAN operations are present across all bridges.
#[test]
fn ucan_category_coverage() {
    let ucan_ops: Vec<_> = PARITY_OPERATIONS
        .iter()
        .filter(|(cat, _, _)| *cat == "ucan")
        .collect();

    let pyo3_srcs = pyo3_sources();
    let napi_srcs = napi_sources();
    let wasm_srcs = wasm_sources();

    for &(_, op, _) in &ucan_ops {
        assert!(
            pyo3_has_operation(&pyo3_srcs, op),
            "PyO3 missing UCAN op: {op}"
        );
        assert!(uniffi_has_operation(op), "UniFFI missing UCAN op: {op}");
        assert!(
            napi_has_operation(&napi_srcs, op),
            "NAPI missing UCAN op: {op}"
        );
        assert!(
            wasm_has_operation(&wasm_srcs, op),
            "WASM missing UCAN op: {op}"
        );
    }
}

/// Verifies tool operations are present across all bridges.
#[test]
fn tools_category_coverage() {
    let tool_ops: Vec<_> = PARITY_OPERATIONS
        .iter()
        .filter(|(cat, _, _)| *cat == "tools")
        .collect();

    let pyo3_srcs = pyo3_sources();
    let napi_srcs = napi_sources();
    let wasm_srcs = wasm_sources();

    for &(_, op, _) in &tool_ops {
        assert!(
            pyo3_has_operation(&pyo3_srcs, op),
            "PyO3 missing tool op: {op}"
        );
        assert!(uniffi_has_operation(op), "UniFFI missing tool op: {op}");
        assert!(
            napi_has_operation(&napi_srcs, op),
            "NAPI missing tool op: {op}"
        );
        assert!(
            wasm_has_operation(&wasm_srcs, op),
            "WASM missing tool op: {op}"
        );
    }
}

/// Verifies broadcast operations are present across all bridges.
/// Accounts for naming variance: `broadcast_block` vs `broadcast_block_subscriber`.
#[test]
fn broadcast_category_coverage() {
    let broadcast_ops: Vec<_> = PARITY_OPERATIONS
        .iter()
        .filter(|(cat, _, _)| *cat == "broadcast")
        .collect();

    let pyo3_srcs = pyo3_sources();
    let napi_srcs = napi_sources();
    let wasm_srcs = wasm_sources();

    for &(_, op, _) in &broadcast_ops {
        assert!(
            pyo3_has_operation(&pyo3_srcs, op),
            "PyO3 missing broadcast op: {op}"
        );
        assert!(
            uniffi_has_operation(op),
            "UniFFI missing broadcast op: {op}"
        );
        assert!(
            napi_has_operation(&napi_srcs, op),
            "NAPI missing broadcast op: {op}"
        );
        assert!(
            wasm_has_operation(&wasm_srcs, op),
            "WASM missing broadcast op: {op}"
        );
    }
}

/// Verifies trust operations are present across all bridges.
#[test]
fn trust_category_coverage() {
    let trust_ops: Vec<_> = PARITY_OPERATIONS
        .iter()
        .filter(|(cat, _, _)| *cat == "trust")
        .collect();

    let pyo3_srcs = pyo3_sources();
    let napi_srcs = napi_sources();
    let wasm_srcs = wasm_sources();

    for &(_, op, _) in &trust_ops {
        assert!(
            pyo3_has_operation(&pyo3_srcs, op),
            "PyO3 missing trust op: {op}"
        );
        assert!(uniffi_has_operation(op), "UniFFI missing trust op: {op}");
        assert!(
            napi_has_operation(&napi_srcs, op),
            "NAPI missing trust op: {op}"
        );
        assert!(
            wasm_has_operation(&wasm_srcs, op),
            "WASM missing trust op: {op}"
        );
    }
}

/// Verifies event_log operations are present across all bridges.
#[test]
fn event_log_category_coverage() {
    let event_log_ops: Vec<_> = PARITY_OPERATIONS
        .iter()
        .filter(|(cat, _, _)| *cat == "event_log")
        .collect();

    let pyo3_srcs = pyo3_sources();
    let napi_srcs = napi_sources();
    let wasm_srcs = wasm_sources();

    for &(_, op, _) in &event_log_ops {
        assert!(
            pyo3_has_operation(&pyo3_srcs, op),
            "PyO3 missing event_log op: {op}"
        );
        assert!(
            uniffi_has_operation(op),
            "UniFFI missing event_log op: {op}"
        );
        assert!(
            napi_has_operation(&napi_srcs, op),
            "NAPI missing event_log op: {op}"
        );
        assert!(
            wasm_has_operation(&wasm_srcs, op),
            "WASM missing event_log op: {op}"
        );
    }
}

/// Verifies discovery and provenance operations are present across all bridges.
#[test]
fn discovery_and_provenance_coverage() {
    let ops: Vec<_> = PARITY_OPERATIONS
        .iter()
        .filter(|(cat, _, _)| *cat == "discovery" || *cat == "provenance")
        .collect();

    let pyo3_srcs = pyo3_sources();
    let napi_srcs = napi_sources();
    let wasm_srcs = wasm_sources();

    for &(cat, op, _) in &ops {
        assert!(
            pyo3_has_operation(&pyo3_srcs, op),
            "PyO3 missing {cat} op: {op}"
        );
        assert!(uniffi_has_operation(op), "UniFFI missing {cat} op: {op}");
        assert!(
            napi_has_operation(&napi_srcs, op),
            "NAPI missing {cat} op: {op}"
        );
        assert!(
            wasm_has_operation(&wasm_srcs, op),
            "WASM missing {cat} op: {op}"
        );
    }
}

// =========================================================================
// RATCHET CONSTANTS — may only increase
// Any decrease requires human approval
// =========================================================================

const MIN_PARITY_OPERATIONS: usize = 98;

/// Named set of operations that must have `wasm_required=true`.
/// This is a named set, not a count — swapping one operation for another is
/// caught. Operations can be added but never removed or weakened.
const WASM_REQUIRED_OPERATIONS: &[&str] = &[
    // Identity
    "identity_create",
    "identity_load",
    "identity_resolve",
    "identity_migrate",
    "identity_attest_device",
    "identity_verify_device_attestation",
    // Context lifecycle
    "context_create",
    "context_join",
    "context_leave",
    "context_close",
    "context_send",
    "context_subscribe",
    "context_export",
    "context_import",
    // Membership
    "context_member_count",
    "context_is_member",
    "context_member_dids",
    "context_member_role",
    // Events
    "context_drain_events",
    // Governance
    "governance_execute",
    // Tools (core only — sessions and cross-context are optional)
    "tool_register",
    "tool_invoke",
    "tool_verify",
    // UCAN
    "ucan_validate",
    "ucan_mint",
    "ucan_revoke",
    "ucan_delegate",
    // Event Log
    "event_log_query",
    "event_log_verify",
    "event_log_checkpoint",
    // Broadcast
    "broadcast_subscribe",
    "broadcast_unsubscribe",
    "broadcast_publish",
    "broadcast_block",
    // Trust
    "trust_query_score",
    "trust_verify_attestation",
    "trust_create_challenge",
    "trust_verify_response",
    "verify_participation_requirements",
    // Sync
    "sync_classify_offline",
    "sync_classify_offline_custom",
    "sync_get_policy",
    // Discovery
    "discovery_parse_address",
    "discovery_normalize_address",
    // Provenance
    "provenance_check_chain_depth",
    "evaluate_provenance_quality",
    "provenance_attach",
    // Petname
    "petname_set",
    "petname_remove",
    "petname_set_context",
    "petname_remove_context",
    "petname_resolve_did",
    "petname_resolve_context",
    "petname_get_for_did",
    "petname_get_for_context",
    // Handle/Scope
    "handle_register",
    "handle_lookup",
    "handle_deregister",
    "scope_register",
    "scope_lookup",
    "scope_deregister",
    // Governance checkpoints
    "context_create_governance_checkpoint",
    "context_add_checkpoint_cosignature",
];

// ---------------------------------------------------------------------------
// Ratchet meta-tests — detect weakening of enforcement
// ---------------------------------------------------------------------------

/// The total operation count must never decrease. New operations may be
/// added; existing operations must not be removed without human approval.
#[test]
fn parity_operation_count_never_decreases() {
    assert!(
        PARITY_OPERATIONS.len() >= MIN_PARITY_OPERATIONS,
        "PARITY_OPERATIONS has {} entries, minimum is {}. \
         Operations were removed without updating the ratchet.",
        PARITY_OPERATIONS.len(),
        MIN_PARITY_OPERATIONS
    );
}

/// Every operation in `WASM_REQUIRED_OPERATIONS` must remain in
/// `PARITY_OPERATIONS` with `wasm_required=true`. Changing an operation
/// from required to optional (or removing it) is caught.
#[test]
fn wasm_required_set_not_weakened() {
    for op_name in WASM_REQUIRED_OPERATIONS {
        let entry = PARITY_OPERATIONS
            .iter()
            .find(|(_, name, _)| name == op_name);
        assert!(entry.is_some(), "{op_name} removed from PARITY_OPERATIONS");
        assert!(
            entry.unwrap().2,
            "{op_name} changed from wasm_required=true to false"
        );
    }
}

/// Verify that WASM_REQUIRED_OPERATIONS is consistent with PARITY_OPERATIONS.
/// Every operation marked `wasm_required=true` in PARITY_OPERATIONS must
/// appear in the named set.
#[test]
fn wasm_required_set_is_complete() {
    for &(_, op, required) in PARITY_OPERATIONS {
        if required {
            assert!(
                WASM_REQUIRED_OPERATIONS.contains(&op),
                "Operation {op} has wasm_required=true but is not in WASM_REQUIRED_OPERATIONS. \
                 Add it to the named set."
            );
        }
    }
}
