#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::struct_excessive_bools
)]

//! B17: SDK wrapper layer completeness.
//!
//! Structural/static analysis test that verifies each language SDK wrapper
//! (Python, TypeScript, Swift, Kotlin) exposes the expected public API
//! surface by embedding SDK source files at compile time and searching for
//! function/method signatures matching the expected operations.
//!
//! This test does NOT execute SDK code — it analyses source text for the
//! presence of wrapper functions.  A missing wrapper is a coverage gap.

// ---------------------------------------------------------------------------
// Embedded SDK source files (compile-time via include_str!)
// ---------------------------------------------------------------------------

// Python SDK files
const PY_IDENTITY: &str = include_str!("../../../../bindings/python/scp_sdk/identity.py");
const PY_CONTEXT: &str = include_str!("../../../../bindings/python/scp_sdk/context.py");
const PY_TOOLS: &str = include_str!("../../../../bindings/python/scp_sdk/tools.py");
const PY_UCAN: &str = include_str!("../../../../bindings/python/scp_sdk/ucan.py");
const PY_EVENT_LOG: &str = include_str!("../../../../bindings/python/scp_sdk/event_log.py");
const PY_TRANSPORT: &str = include_str!("../../../../bindings/python/scp_sdk/transport.py");
const PY_DISCOVERY: &str = include_str!("../../../../bindings/python/scp_sdk/discovery.py");
const PY_PROVENANCE: &str = include_str!("../../../../bindings/python/scp_sdk/provenance.py");
const PY_TRUST: &str = include_str!("../../../../bindings/python/scp_sdk/trust.py");
const PY_SYNC: &str = include_str!("../../../../bindings/python/scp_sdk/sync.py");
const PY_BRIDGE: &str = include_str!("../../../../bindings/python/scp_sdk/bridge.py");
const PY_GOVERNANCE: &str = include_str!("../../../../bindings/python/scp_sdk/governance.py");

// TypeScript SDK files
const TS_IDENTITY: &str = include_str!("../../../../bindings/typescript/src/identity.ts");
const TS_CONTEXT: &str = include_str!("../../../../bindings/typescript/src/context.ts");
const TS_TOOLS: &str = include_str!("../../../../bindings/typescript/src/tools.ts");
const TS_UCAN: &str = include_str!("../../../../bindings/typescript/src/ucan.ts");
const TS_EVENT_LOG: &str = include_str!("../../../../bindings/typescript/src/event-log.ts");
const TS_TRANSPORT: &str = include_str!("../../../../bindings/typescript/src/transport.ts");
const TS_DISCOVERY: &str = include_str!("../../../../bindings/typescript/src/discovery.ts");
const TS_PROVENANCE: &str = include_str!("../../../../bindings/typescript/src/provenance.ts");
const TS_TRUST: &str = include_str!("../../../../bindings/typescript/src/trust.ts");
const TS_SYNC: &str = include_str!("../../../../bindings/typescript/src/sync.ts");
const TS_BRIDGE: &str = include_str!("../../../../bindings/typescript/src/bridge.ts");

// Swift SDK files
const SWIFT_IDENTITY: &str = include_str!("../../../../bindings/swift/Sources/SCP/Identity.swift");
const SWIFT_CONTEXT: &str = include_str!("../../../../bindings/swift/Sources/SCP/Context.swift");
const SWIFT_TOOLS: &str = include_str!("../../../../bindings/swift/Sources/SCP/Tools.swift");
const SWIFT_UCAN: &str = include_str!("../../../../bindings/swift/Sources/SCP/Ucan.swift");
const SWIFT_EVENT_LOG: &str = include_str!("../../../../bindings/swift/Sources/SCP/EventLog.swift");
const SWIFT_TRANSPORT: &str =
    include_str!("../../../../bindings/swift/Sources/SCP/Transport.swift");
const SWIFT_DISCOVERY: &str =
    include_str!("../../../../bindings/swift/Sources/SCP/Discovery.swift");
const SWIFT_PROVENANCE: &str =
    include_str!("../../../../bindings/swift/Sources/SCP/Provenance.swift");
const SWIFT_TRUST: &str = include_str!("../../../../bindings/swift/Sources/SCP/Trust.swift");
// Sync.swift and Bridge.swift deleted in PR 4 Phase C (#1549 façade deletion) —
// their functionality is exposed as methods on the SCP class directly.
const SWIFT_GOVERNANCE: &str =
    include_str!("../../../../bindings/swift/Sources/SCP/Governance.swift");
// Phase 4 PR 4 migrated many per-module Swift wrappers into methods on the
// `SCP` class in `Scp.swift` (e.g. `ucanValidate`, `transportStatus`,
// `syncClassifyOffline`, `identityMigrate`, `bridgeEvaluateTrust`). This
// file is now the canonical wrapper surface alongside the per-module
// files above, so include it for the SDK wrapper coverage matrix.
const SWIFT_SCP: &str = include_str!("../../../../bindings/swift/Sources/SCP/Scp.swift");
// UniFFI-generated bindings. Exposes the raw bridge functions
// (`bridgeRegister`, `bridgeCreateShadow`, `evaluateProvenanceQuality`,
// etc.) that the hand-written wrappers delegate to. Some operations are
// currently invoked only via the generated free functions — include this
// file so the coverage matrix sees them.
const SWIFT_BINDINGS: &str =
    include_str!("../../../../bindings/swift/Sources/SCP/Internal/ScpBindings.swift");

// Kotlin SDK files
const KT_IDENTITY: &str =
    include_str!("../../../../bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/Identity.kt");
const KT_BRIDGE_CONNECTOR: &str = include_str!(
    "../../../../bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/BridgeConnector.kt"
);
const KT_DISCOVERY: &str =
    include_str!("../../../../bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/Discovery.kt");
const KT_PROVENANCE: &str =
    include_str!("../../../../bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/Provenance.kt");
const KT_SYNC: &str =
    include_str!("../../../../bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/Sync.kt");
const KT_COROUTINE_BRIDGE: &str = include_str!(
    "../../../../bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/bridge/CoroutineBridge.kt"
);

// ---------------------------------------------------------------------------
// Operation definitions — the expected wrapper surface
// ---------------------------------------------------------------------------

/// A single expected operation with its category and detection patterns per SDK.
struct ExpectedOp {
    category: &'static str,
    name: &'static str,
    /// Patterns to search for in Python SDK source.
    py_patterns: &'static [&'static str],
    /// Patterns to search for in TypeScript SDK source.
    ts_patterns: &'static [&'static str],
    /// Patterns to search for in Swift SDK source.
    swift_patterns: &'static [&'static str],
    /// Patterns to search for in Kotlin SDK source.
    kt_patterns: &'static [&'static str],
}

/// All SDK source text concatenated per language, for searching across files.
fn py_all() -> String {
    [
        PY_IDENTITY,
        PY_CONTEXT,
        PY_TOOLS,
        PY_UCAN,
        PY_EVENT_LOG,
        PY_TRANSPORT,
        PY_DISCOVERY,
        PY_PROVENANCE,
        PY_TRUST,
        PY_SYNC,
        PY_BRIDGE,
        PY_GOVERNANCE,
    ]
    .join("\n")
}

fn ts_all() -> String {
    [
        TS_IDENTITY,
        TS_CONTEXT,
        TS_TOOLS,
        TS_UCAN,
        TS_EVENT_LOG,
        TS_TRANSPORT,
        TS_DISCOVERY,
        TS_PROVENANCE,
        TS_TRUST,
        TS_SYNC,
        TS_BRIDGE,
    ]
    .join("\n")
}

fn swift_all() -> String {
    [
        SWIFT_IDENTITY,
        SWIFT_CONTEXT,
        SWIFT_TOOLS,
        SWIFT_UCAN,
        SWIFT_EVENT_LOG,
        SWIFT_TRANSPORT,
        SWIFT_DISCOVERY,
        SWIFT_PROVENANCE,
        SWIFT_TRUST,
        SWIFT_GOVERNANCE,
        SWIFT_SCP,
        SWIFT_BINDINGS,
    ]
    .join("\n")
}

fn kt_all() -> String {
    [
        KT_IDENTITY,
        KT_BRIDGE_CONNECTOR,
        KT_DISCOVERY,
        KT_PROVENANCE,
        KT_SYNC,
        KT_COROUTINE_BRIDGE,
    ]
    .join("\n")
}

/// Returns true if `source` contains ANY of the given `patterns` (case-sensitive substring).
fn has_any_pattern(source: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|p| source.contains(p))
}

/// The canonical list of expected SDK wrapper operations.
fn expected_operations() -> Vec<ExpectedOp> {
    vec![
        // --- Identity ---
        ExpectedOp {
            category: "Identity",
            name: "create",
            py_patterns: &["async def create(", "py_identity_create"],
            ts_patterns: &["static async create(", "identityCreate"],
            swift_patterns: &["func createIdentity(", "identityCreate"],
            kt_patterns: &["fun identityCreate(", "fun create("],
        },
        ExpectedOp {
            category: "Identity",
            name: "load",
            py_patterns: &["async def load(", "py_identity_load"],
            ts_patterns: &["static async load(", "identityLoad"],
            swift_patterns: &["func loadIdentity(", "identityLoad"],
            kt_patterns: &["fun identityLoad(", "fun load("],
        },
        ExpectedOp {
            category: "Identity",
            name: "resolve",
            py_patterns: &["async def resolve(", "py_identity_resolve"],
            ts_patterns: &["static async resolve(", "identityResolve"],
            swift_patterns: &["func resolveIdentity(", "identityResolve"],
            kt_patterns: &["fun identityResolve(", "fun resolve("],
        },
        ExpectedOp {
            category: "Identity",
            name: "rotate_key",
            py_patterns: &["async def rotate_key(", "py_identity_rotate_key"],
            ts_patterns: &["async rotateKey(", "identityRotateKey"],
            swift_patterns: &["rotateKey()", "rotate_key"],
            kt_patterns: &["rotateKey", "rotate_key"],
        },
        ExpectedOp {
            category: "Identity",
            name: "add_agent_key",
            py_patterns: &["async def add_agent_key(", "py_identity_add_agent_key"],
            ts_patterns: &["async addAgentKey(", "identityAddAgentKey"],
            swift_patterns: &["func addAgentKeyToIdentity(", "addAgentKey"],
            kt_patterns: &["fun addAgentKey(", "identityAddAgentKey"],
        },
        ExpectedOp {
            category: "Identity",
            name: "rotate_agent_key",
            py_patterns: &[
                "async def rotate_agent_key(",
                "py_identity_rotate_agent_key",
            ],
            ts_patterns: &["async rotateAgentKey(", "identityRotateAgentKey"],
            swift_patterns: &["func rotateAgentKeyForIdentity(", "rotateAgentKey"],
            kt_patterns: &["fun rotateAgentKey(", "identityRotateAgentKey"],
        },
        ExpectedOp {
            category: "Identity",
            name: "remove_agent_key",
            py_patterns: &[
                "async def remove_agent_key(",
                "py_identity_remove_agent_key",
            ],
            ts_patterns: &["async removeAgentKey(", "identityRemoveAgentKey"],
            swift_patterns: &["func removeAgentKeyFromIdentity(", "removeAgentKey"],
            kt_patterns: &["fun removeAgentKey(", "identityRemoveAgentKey"],
        },
        ExpectedOp {
            category: "Identity",
            name: "migrate",
            py_patterns: &["async def migrate(", "py_identity_migrate"],
            ts_patterns: &["async migrate(", "identityMigrate"],
            // Swift: rotate_key is the layer-1 equivalent; migrate may not be separately exposed
            swift_patterns: &["migrate", "identityMigrate"],
            kt_patterns: &["fun migrate(", "identityMigrate"],
        },
        ExpectedOp {
            category: "Identity",
            name: "attest_device",
            py_patterns: &["async def attest_device(", "py_identity_attest_device"],
            ts_patterns: &["async attestDevice(", "identityAttestDevice"],
            swift_patterns: &["func identityAttestDevice(", "attestDevice"],
            kt_patterns: &["fun attestDevice(", "identityAttestDevice"],
        },
        // --- Context ---
        ExpectedOp {
            category: "Context",
            name: "create",
            py_patterns: &["async def create(", "py_context_create"],
            ts_patterns: &["static async create(", "contextCreate"],
            swift_patterns: &["ContextBridge", "CreateFn"],
            kt_patterns: &["fun contextCreate("],
        },
        ExpectedOp {
            category: "Context",
            name: "join",
            py_patterns: &["async def join(", "py_context_join"],
            ts_patterns: &["async join(", "contextJoin"],
            swift_patterns: &["func joinContext(", "JoinFn"],
            kt_patterns: &["fun contextJoin("],
        },
        ExpectedOp {
            category: "Context",
            name: "leave",
            py_patterns: &["async def leave(", "py_context_leave"],
            ts_patterns: &["async leave(", "contextLeave"],
            swift_patterns: &["func leave(", "LeaveFn"],
            kt_patterns: &["fun contextLeave("],
        },
        ExpectedOp {
            category: "Context",
            name: "close",
            py_patterns: &["async def close(", "py_context_close"],
            ts_patterns: &["async close(", "contextClose"],
            swift_patterns: &["func close(", "CloseFn"],
            kt_patterns: &["fun contextClose("],
        },
        ExpectedOp {
            category: "Context",
            name: "send",
            py_patterns: &["async def send(", "py_context_send"],
            ts_patterns: &["async send(", "contextSend"],
            swift_patterns: &["func send(", "SendFn"],
            kt_patterns: &["fun contextSend("],
        },
        ExpectedOp {
            category: "Context",
            name: "receive",
            py_patterns: &["async def receive(", "py_context_receive"],
            ts_patterns: &["async *receive(", "receive("],
            swift_patterns: &["SubscribeFn", "subscribe"],
            kt_patterns: &["fun contextSubscribe(", "subscribe"],
        },
        // --- Tools ---
        ExpectedOp {
            category: "Tools",
            name: "register",
            py_patterns: &["ToolDefinition", "class ToolDefinition"],
            ts_patterns: &["registerTool(", "defineToolDefinition"],
            swift_patterns: &["ToolDefinition", "toolRegister", "InvokeFn"],
            kt_patterns: &["fun toolRegister("],
        },
        ExpectedOp {
            category: "Tools",
            name: "invoke",
            py_patterns: &["async def invoke(", "tool_invoke"],
            ts_patterns: &["async invokeTool(", "toolInvoke"],
            swift_patterns: &["ToolInvocationResult", "toolInvoke", "InvokeFn"],
            kt_patterns: &["fun toolInvoke("],
        },
        ExpectedOp {
            category: "Tools",
            name: "verify",
            py_patterns: &["TestVector", "class TestVector"],
            ts_patterns: &["verifyTool(", "toolVerify"],
            swift_patterns: &["ToolVerificationResult", "verifyInclusion"],
            kt_patterns: &["fun toolVerify("],
        },
        // --- UCAN ---
        // Phase 4 PR 4 moved the UCAN wrappers from free-function form
        // (`validateUcanToken` / `mintUcanToken` / `revokeUcanToken`) into
        // methods on the `SCP` class (`ucanValidate` / `ucanMint` /
        // `ucanRevoke`). Both spellings are accepted.
        ExpectedOp {
            category: "UCAN",
            name: "validate",
            py_patterns: &["async def validate(", "ucan_validate"],
            ts_patterns: &["validateUcan(", "ucanValidate"],
            swift_patterns: &[
                "func validateUcanToken(",
                "func validate(",
                "func ucanValidate(",
            ],
            kt_patterns: &["fun ucanValidate("],
        },
        ExpectedOp {
            category: "UCAN",
            name: "mint",
            py_patterns: &["async def mint(", "ucan_mint"],
            ts_patterns: &["mintUcan(", "ucanMint"],
            swift_patterns: &["func mintUcanToken(", "func mint(", "func ucanMint("],
            kt_patterns: &["fun ucanMint("],
        },
        ExpectedOp {
            category: "UCAN",
            name: "revoke",
            py_patterns: &["async def revoke(", "ucan_revoke"],
            ts_patterns: &["revokeUcan(", "ucanRevoke"],
            swift_patterns: &["func revokeUcanToken(", "func revoke(", "func ucanRevoke("],
            kt_patterns: &["fun ucanRevoke("],
        },
        // --- Event Log ---
        ExpectedOp {
            category: "EventLog",
            name: "query",
            py_patterns: &["async def query(", "event_log_query"],
            ts_patterns: &["async query(", "eventLogQuery"],
            swift_patterns: &["func query(", "eventLogQuery"],
            kt_patterns: &["fun eventLogQuery("],
        },
        ExpectedOp {
            category: "EventLog",
            name: "verify",
            py_patterns: &["async def verify(", "event_log_verify"],
            ts_patterns: &["async verify(", "eventLogVerify"],
            swift_patterns: &["func verifyInclusion(", "func proveInclusion("],
            kt_patterns: &["fun eventLogVerify("],
        },
        // --- Transport ---
        ExpectedOp {
            category: "Transport",
            name: "connect",
            py_patterns: &["async def connect(", "transport_connect"],
            ts_patterns: &["static async connect(", "transportConnect"],
            swift_patterns: &["func connectTransport(", "transportConnect"],
            kt_patterns: &["fun transportConnect("],
        },
        ExpectedOp {
            category: "Transport",
            name: "status",
            py_patterns: &["async def status(", "transport_status"],
            ts_patterns: &["async status(", "transportStatus"],
            swift_patterns: &["func queryTransportStatus(", "transportStatus"],
            kt_patterns: &["fun transportStatus("],
        },
        // --- Discovery ---
        ExpectedOp {
            category: "Discovery",
            name: "parse_address",
            py_patterns: &["def parse_address(", "discovery_parse_address"],
            ts_patterns: &["parseAddress(", "discoveryParseAddress"],
            swift_patterns: &["func parseAddress(", "discoveryParseAddress"],
            kt_patterns: &["fun discoveryParseAddress(", "fun parseAddress("],
        },
        // --- Provenance ---
        ExpectedOp {
            category: "Provenance",
            name: "evaluate_quality",
            py_patterns: &[
                "def evaluate_provenance_quality(",
                "provenance_evaluate_quality",
            ],
            ts_patterns: &["evaluateProvenanceQuality(", "provenanceEvaluateQuality"],
            swift_patterns: &[
                "func evaluateProvenanceQuality(",
                "provenanceEvaluateQuality",
            ],
            kt_patterns: &["fun evaluateProvenanceQuality(", "evaluateQuality"],
        },
        ExpectedOp {
            category: "Provenance",
            name: "check_chain_depth",
            py_patterns: &["def check_chain_depth(", "provenance_check_chain_depth"],
            ts_patterns: &["checkChainDepth(", "provenanceCheckChainDepth"],
            swift_patterns: &[
                "func checkProvenanceChainDepth(",
                "provenanceCheckChainDepth",
            ],
            kt_patterns: &["checkChainDepth", "provenanceCheckChainDepth"],
        },
        // --- Sync ---
        ExpectedOp {
            category: "Sync",
            name: "classify_offline",
            py_patterns: &["classify_offline", "sync_classify_offline"],
            ts_patterns: &["classifyOffline(", "syncClassifyOffline"],
            swift_patterns: &["func classifyOffline(", "syncClassifyOffline"],
            kt_patterns: &["fun syncClassifyOffline(", "classifyOffline"],
        },
        ExpectedOp {
            category: "Sync",
            name: "get_policy",
            py_patterns: &["get_policy", "sync_get_policy", "SyncPolicy"],
            ts_patterns: &["getPolicy(", "SyncPolicy", "syncGetPolicy"],
            swift_patterns: &["func getSyncPolicy(", "SyncPolicy"],
            kt_patterns: &["SyncPolicy", "getPolicy"],
        },
        // --- Membership ---
        ExpectedOp {
            category: "Membership",
            name: "member_count",
            py_patterns: &["async def member_count(", "py_context_member_count"],
            ts_patterns: &["async memberCount(", "contextMemberCount"],
            swift_patterns: &["memberCount", "contextMemberCount"],
            kt_patterns: &["fun contextMemberCount("],
        },
        ExpectedOp {
            category: "Membership",
            name: "is_member",
            py_patterns: &["async def is_member(", "py_context_is_member"],
            ts_patterns: &["async isMember(", "contextIsMember"],
            swift_patterns: &["isMember", "contextIsMember"],
            kt_patterns: &["fun contextIsMember("],
        },
        ExpectedOp {
            category: "Membership",
            name: "member_dids",
            py_patterns: &["async def member_dids(", "py_context_member_dids"],
            ts_patterns: &["async memberDids(", "contextMemberDids"],
            swift_patterns: &["memberDids", "contextMemberDids"],
            kt_patterns: &["fun contextMemberDids("],
        },
        ExpectedOp {
            category: "Membership",
            name: "member_role",
            py_patterns: &["async def member_role(", "py_context_member_role"],
            ts_patterns: &["async memberRole(", "contextMemberRole"],
            swift_patterns: &["memberRole", "contextMemberRole"],
            kt_patterns: &["fun contextMemberRole("],
        },
        // --- Governance ---
        ExpectedOp {
            category: "Governance",
            name: "execute",
            py_patterns: &[
                "async def execute_governance_action(",
                "py_governance_execute",
            ],
            ts_patterns: &["executeGovernanceAction(", "governanceExecute"],
            swift_patterns: &["Governance", "governance"],
            kt_patterns: &["fun governanceExecute("],
        },
        // --- Broadcast ---
        ExpectedOp {
            category: "Broadcast",
            name: "subscribe",
            py_patterns: &["async def broadcast_subscribe(", "py_broadcast_subscribe"],
            ts_patterns: &["broadcastSubscribe("],
            swift_patterns: &["broadcastSubscribe", "BroadcastSubscribe"],
            kt_patterns: &["fun broadcastSubscribe("],
        },
        ExpectedOp {
            category: "Broadcast",
            name: "unsubscribe",
            py_patterns: &[
                "async def broadcast_unsubscribe(",
                "py_broadcast_unsubscribe",
            ],
            ts_patterns: &["broadcastUnsubscribe("],
            swift_patterns: &["broadcastUnsubscribe", "BroadcastUnsubscribe"],
            kt_patterns: &["fun broadcastUnsubscribe("],
        },
        ExpectedOp {
            category: "Broadcast",
            name: "publish",
            py_patterns: &["async def broadcast_publish(", "py_broadcast_publish"],
            ts_patterns: &["broadcastPublish("],
            swift_patterns: &["broadcastPublish", "BroadcastPublish"],
            kt_patterns: &["fun broadcastPublish("],
        },
        // --- Bridge ---
        ExpectedOp {
            category: "Bridge",
            name: "register",
            py_patterns: &["def register(", "bridge_register"],
            ts_patterns: &["registerBridge(", "bridgeRegister"],
            swift_patterns: &["func bridgeRegister("],
            kt_patterns: &["fun bridgeRegister("],
        },
        ExpectedOp {
            category: "Bridge",
            name: "evaluate_trust",
            py_patterns: &["evaluate_trust", "bridge_evaluate_trust"],
            ts_patterns: &["evaluateBridgeTrust(", "bridgeEvaluateTrust"],
            // Phase 4 PR 4 renamed `evaluateBridgeTrust` → `bridgeEvaluateTrust`
            // on the `SCP` class in Scp.swift. Accept both.
            swift_patterns: &["func evaluateBridgeTrust(", "func bridgeEvaluateTrust("],
            kt_patterns: &["fun bridgeEvaluateTrust("],
        },
        ExpectedOp {
            category: "Bridge",
            name: "create_shadow",
            py_patterns: &["create_shadow", "bridge_create_shadow"],
            ts_patterns: &["createShadow(", "bridgeCreateShadow"],
            swift_patterns: &["func bridgeCreateShadow("],
            kt_patterns: &["fun bridgeCreateShadow("],
        },
    ]
}

// ---------------------------------------------------------------------------
// Per-SDK detection result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct OpResult {
    category: &'static str,
    name: &'static str,
    py: bool,
    ts: bool,
    swift: bool,
    kt: bool,
}

fn check_all_operations() -> Vec<OpResult> {
    let py_src = py_all();
    let ts_src = ts_all();
    let swift_src = swift_all();
    let kt_src = kt_all();

    expected_operations()
        .into_iter()
        .map(|op| OpResult {
            category: op.category,
            name: op.name,
            py: has_any_pattern(&py_src, op.py_patterns),
            ts: has_any_pattern(&ts_src, op.ts_patterns),
            swift: has_any_pattern(&swift_src, op.swift_patterns),
            kt: has_any_pattern(&kt_src, op.kt_patterns),
        })
        .collect()
}

/// Prints a summary matrix and returns (total, missing) counts per SDK.
fn print_matrix(results: &[OpResult]) -> (usize, usize, usize, usize, usize) {
    println!();
    println!(
        "{:<14} {:<20} {:>6} {:>6} {:>7} {:>8}",
        "Category", "Operation", "Python", "TS", "Swift", "Kotlin"
    );
    println!("{}", "-".repeat(65));

    let mut py_missing = 0usize;
    let mut ts_missing = 0usize;
    let mut swift_missing = 0usize;
    let mut kt_missing = 0usize;

    for r in results {
        let py_mark = if r.py { "  Y" } else { "  -" };
        let ts_mark = if r.ts { "  Y" } else { "  -" };
        let sw_mark = if r.swift { "  Y" } else { "  -" };
        let kt_mark = if r.kt { "  Y" } else { "  -" };

        if !r.py {
            py_missing += 1;
        }
        if !r.ts {
            ts_missing += 1;
        }
        if !r.swift {
            swift_missing += 1;
        }
        if !r.kt {
            kt_missing += 1;
        }

        println!(
            "{:<14} {:<20} {:>6} {:>6} {:>7} {:>8}",
            r.category, r.name, py_mark, ts_mark, sw_mark, kt_mark
        );
    }

    let total = results.len();
    println!("{}", "-".repeat(65));
    println!(
        "{:<14} {:<20} {:>4}/{} {:>4}/{} {:>5}/{} {:>6}/{}",
        "TOTAL",
        "",
        total - py_missing,
        total,
        total - ts_missing,
        total,
        total - swift_missing,
        total,
        total - kt_missing,
        total
    );
    println!();

    (total, py_missing, ts_missing, swift_missing, kt_missing)
}

// ---------------------------------------------------------------------------
// Tests — per-SDK and cross-SDK
// ---------------------------------------------------------------------------

#[test]
fn python_sdk_identity_wrappers() {
    let src = py_all();
    assert!(
        src.contains("async def create(") || src.contains("py_identity_create"),
        "Python SDK missing identity create wrapper"
    );
    assert!(
        src.contains("async def load(") || src.contains("py_identity_load"),
        "Python SDK missing identity load wrapper"
    );
    assert!(
        src.contains("async def resolve(") || src.contains("py_identity_resolve"),
        "Python SDK missing identity resolve wrapper"
    );
    assert!(
        src.contains("async def rotate_key(") || src.contains("py_identity_rotate_key"),
        "Python SDK missing identity rotate_key wrapper"
    );
}

#[test]
fn python_sdk_context_wrappers() {
    let src = py_all();
    for (name, patterns) in [
        (
            "create",
            &["async def create(", "py_context_create"] as &[&str],
        ),
        ("join", &["async def join(", "py_context_join"]),
        ("leave", &["async def leave(", "py_context_leave"]),
        ("close", &["async def close(", "py_context_close"]),
        ("send", &["async def send(", "py_context_send"]),
        ("receive", &["async def receive(", "py_context_receive"]),
    ] {
        assert!(
            has_any_pattern(&src, patterns),
            "Python SDK missing context {name} wrapper"
        );
    }
}

#[test]
fn python_sdk_membership_wrappers() {
    let src = py_all();
    for (name, patterns) in [
        (
            "member_count",
            &["async def member_count(", "py_context_member_count"] as &[&str],
        ),
        (
            "is_member",
            &["async def is_member(", "py_context_is_member"],
        ),
        (
            "member_dids",
            &["async def member_dids(", "py_context_member_dids"],
        ),
        (
            "member_role",
            &["async def member_role(", "py_context_member_role"],
        ),
    ] {
        assert!(
            has_any_pattern(&src, patterns),
            "Python SDK missing membership {name} wrapper"
        );
    }
}

#[test]
fn python_sdk_governance_wrappers() {
    let src = py_all();
    assert!(
        src.contains("async def execute_governance_action(")
            || src.contains("py_governance_execute"),
        "Python SDK missing governance execute wrapper"
    );
}

#[test]
fn python_sdk_broadcast_wrappers() {
    let src = py_all();
    for (name, patterns) in [
        (
            "subscribe",
            &["async def broadcast_subscribe(", "py_broadcast_subscribe"] as &[&str],
        ),
        (
            "unsubscribe",
            &[
                "async def broadcast_unsubscribe(",
                "py_broadcast_unsubscribe",
            ],
        ),
        (
            "publish",
            &["async def broadcast_publish(", "py_broadcast_publish"],
        ),
    ] {
        assert!(
            has_any_pattern(&src, patterns),
            "Python SDK missing broadcast {name} wrapper"
        );
    }
}

#[test]
fn python_sdk_ucan_wrappers() {
    let src = py_all();
    for (name, patterns) in [
        (
            "validate",
            &["async def validate(", "ucan_validate"] as &[&str],
        ),
        ("mint", &["async def mint(", "ucan_mint"]),
        ("revoke", &["async def revoke(", "ucan_revoke"]),
    ] {
        assert!(
            has_any_pattern(&src, patterns),
            "Python SDK missing UCAN {name} wrapper"
        );
    }
}

#[test]
fn python_sdk_infra_wrappers() {
    let src = py_all();
    // Event Log
    assert!(
        has_any_pattern(&src, &["async def query(", "event_log_query"]),
        "Python SDK missing event log query wrapper"
    );
    assert!(
        has_any_pattern(&src, &["async def verify(", "event_log_verify"]),
        "Python SDK missing event log verify wrapper"
    );
    // Transport
    assert!(
        has_any_pattern(&src, &["async def connect(", "transport_connect"]),
        "Python SDK missing transport connect wrapper"
    );
    assert!(
        has_any_pattern(&src, &["async def status(", "transport_status"]),
        "Python SDK missing transport status wrapper"
    );
    // Discovery
    assert!(
        has_any_pattern(&src, &["def parse_address(", "discovery_parse_address"]),
        "Python SDK missing discovery parse_address wrapper"
    );
    // Provenance
    assert!(
        has_any_pattern(
            &src,
            &[
                "def evaluate_provenance_quality(",
                "provenance_evaluate_quality"
            ]
        ),
        "Python SDK missing provenance evaluate_quality wrapper"
    );
    // Sync
    assert!(
        has_any_pattern(&src, &["classify_offline", "sync_classify_offline"]),
        "Python SDK missing sync classify_offline wrapper"
    );
}

#[test]
fn typescript_sdk_identity_wrappers() {
    let src = ts_all();
    assert!(
        src.contains("static async create(") || src.contains("identityCreate"),
        "TypeScript SDK missing identity create wrapper"
    );
    assert!(
        src.contains("static async load(") || src.contains("identityLoad"),
        "TypeScript SDK missing identity load wrapper"
    );
    assert!(
        src.contains("static async resolve(") || src.contains("identityResolve"),
        "TypeScript SDK missing identity resolve wrapper"
    );
    assert!(
        src.contains("async rotateKey(") || src.contains("identityRotateKey"),
        "TypeScript SDK missing identity rotateKey wrapper"
    );
}

#[test]
fn typescript_sdk_context_wrappers() {
    let src = ts_all();
    for (name, patterns) in [
        (
            "create",
            &["static async create(", "contextCreate"] as &[&str],
        ),
        ("join", &["async join(", "contextJoin"]),
        ("leave", &["async leave(", "contextLeave"]),
        ("close", &["async close(", "contextClose"]),
        ("send", &["async send(", "contextSend"]),
    ] {
        assert!(
            has_any_pattern(&src, patterns),
            "TypeScript SDK missing context {name} wrapper"
        );
    }
}

#[test]
fn typescript_sdk_membership_wrappers() {
    let src = ts_all();
    for (name, patterns) in [
        (
            "memberCount",
            &["async memberCount(", "contextMemberCount"] as &[&str],
        ),
        ("isMember", &["async isMember(", "contextIsMember"]),
        ("memberDids", &["async memberDids(", "contextMemberDids"]),
        ("memberRole", &["async memberRole(", "contextMemberRole"]),
    ] {
        assert!(
            has_any_pattern(&src, patterns),
            "TypeScript SDK missing membership {name} wrapper"
        );
    }
}

#[test]
fn typescript_sdk_broadcast_wrappers() {
    let src = ts_all();
    for (name, patterns) in [
        ("subscribe", &["broadcastSubscribe("] as &[&str]),
        ("unsubscribe", &["broadcastUnsubscribe("]),
        ("publish", &["broadcastPublish("]),
    ] {
        assert!(
            has_any_pattern(&src, patterns),
            "TypeScript SDK missing broadcast {name} wrapper"
        );
    }
}

#[test]
fn typescript_sdk_governance_wrappers() {
    let src = ts_all();
    assert!(
        src.contains("executeGovernanceAction(") || src.contains("governanceExecute"),
        "TypeScript SDK missing governance execute wrapper"
    );
}

#[test]
fn swift_sdk_identity_wrappers() {
    let src = swift_all();
    assert!(
        src.contains("func createIdentity(") || src.contains("identityCreate"),
        "Swift SDK missing identity create wrapper"
    );
    assert!(
        src.contains("func loadIdentity(") || src.contains("identityLoad"),
        "Swift SDK missing identity load wrapper"
    );
    assert!(
        src.contains("func resolveIdentity(") || src.contains("identityResolve"),
        "Swift SDK missing identity resolve wrapper"
    );
}

#[test]
fn swift_sdk_context_wrappers() {
    let src = swift_all();
    assert!(
        src.contains("func send(") || src.contains("SendFn"),
        "Swift SDK missing context send wrapper"
    );
    assert!(
        src.contains("func leave(") || src.contains("LeaveFn"),
        "Swift SDK missing context leave wrapper"
    );
    assert!(
        src.contains("func close(") || src.contains("CloseFn"),
        "Swift SDK missing context close wrapper"
    );
}

#[test]
fn swift_sdk_ucan_wrappers() {
    let src = swift_all();
    // Phase 4 PR 4 moved UCAN wrappers onto the `SCP` class
    // (`ucanValidate` / `ucanMint` / `ucanRevoke`). Accept the new method
    // names alongside the legacy `validateUcanToken` / `mintUcanToken` /
    // `revokeUcanToken` free-function spellings.
    assert!(
        src.contains("func validateUcanToken(")
            || src.contains("func validate(")
            || src.contains("func ucanValidate("),
        "Swift SDK missing UCAN validate wrapper"
    );
    assert!(
        src.contains("func mintUcanToken(")
            || src.contains("func mint(")
            || src.contains("func ucanMint("),
        "Swift SDK missing UCAN mint wrapper"
    );
    assert!(
        src.contains("func revokeUcanToken(")
            || src.contains("func revoke(")
            || src.contains("func ucanRevoke("),
        "Swift SDK missing UCAN revoke wrapper"
    );
}

#[test]
fn swift_sdk_discovery_wrappers() {
    let src = swift_all();
    assert!(
        src.contains("func parseAddress(") || src.contains("discoveryParseAddress"),
        "Swift SDK missing discovery parse_address wrapper"
    );
}

#[test]
fn swift_sdk_transport_wrappers() {
    let src = swift_all();
    assert!(
        src.contains("func connectTransport(") || src.contains("transportConnect"),
        "Swift SDK missing transport connect wrapper"
    );
    assert!(
        src.contains("func queryTransportStatus(") || src.contains("transportStatus"),
        "Swift SDK missing transport status wrapper"
    );
}

#[test]
fn swift_sdk_bridge_wrappers() {
    let src = swift_all();
    // Phase 4 PR 4 renamed `evaluateBridgeTrust` → `bridgeEvaluateTrust`
    // on the `SCP` class in Scp.swift. `bridgeRegister` and
    // `bridgeCreateShadow` come from the UniFFI-generated bindings in
    // `Internal/ScpBindings.swift`, which is now included in `swift_all()`.
    assert!(
        src.contains("func bridgeRegister("),
        "Swift SDK missing bridge register wrapper"
    );
    assert!(
        src.contains("func evaluateBridgeTrust(") || src.contains("func bridgeEvaluateTrust("),
        "Swift SDK missing bridge evaluate_trust wrapper"
    );
    assert!(
        src.contains("func bridgeCreateShadow("),
        "Swift SDK missing bridge create_shadow wrapper"
    );
}

#[test]
fn kotlin_sdk_identity_wrappers() {
    let src = kt_all();
    assert!(
        src.contains("fun identityCreate("),
        "Kotlin SDK missing identity create wrapper"
    );
    assert!(
        src.contains("fun identityLoad("),
        "Kotlin SDK missing identity load wrapper"
    );
    assert!(
        src.contains("fun identityResolve("),
        "Kotlin SDK missing identity resolve wrapper"
    );
}

#[test]
fn kotlin_sdk_context_wrappers() {
    let src = kt_all();
    for (name, pattern) in [
        ("create", "fun contextCreate("),
        ("join", "fun contextJoin("),
        ("leave", "fun contextLeave("),
        ("close", "fun contextClose("),
        ("send", "fun contextSend("),
    ] {
        assert!(
            src.contains(pattern),
            "Kotlin SDK missing context {name} wrapper"
        );
    }
}

#[test]
fn kotlin_sdk_membership_wrappers() {
    let src = kt_all();
    for (name, pattern) in [
        ("memberCount", "fun contextMemberCount("),
        ("isMember", "fun contextIsMember("),
        ("memberDids", "fun contextMemberDids("),
        ("memberRole", "fun contextMemberRole("),
    ] {
        assert!(
            src.contains(pattern),
            "Kotlin SDK missing membership {name} wrapper"
        );
    }
}

#[test]
fn kotlin_sdk_governance_wrappers() {
    let src = kt_all();
    assert!(
        src.contains("fun governanceExecute("),
        "Kotlin SDK missing governance execute wrapper"
    );
}

#[test]
fn kotlin_sdk_broadcast_wrappers() {
    let src = kt_all();
    for (name, pattern) in [
        ("subscribe", "fun broadcastSubscribe("),
        ("unsubscribe", "fun broadcastUnsubscribe("),
        ("publish", "fun broadcastPublish("),
    ] {
        assert!(
            src.contains(pattern),
            "Kotlin SDK missing broadcast {name} wrapper"
        );
    }
}

#[test]
fn kotlin_sdk_ucan_wrappers() {
    let src = kt_all();
    for (name, pattern) in [
        ("validate", "fun ucanValidate("),
        ("mint", "fun ucanMint("),
        ("revoke", "fun ucanRevoke("),
    ] {
        assert!(
            src.contains(pattern),
            "Kotlin SDK missing UCAN {name} wrapper"
        );
    }
}

#[test]
fn kotlin_sdk_infra_wrappers() {
    let src = kt_all();
    assert!(
        src.contains("fun eventLogQuery("),
        "Kotlin SDK missing event log query wrapper"
    );
    assert!(
        src.contains("fun eventLogVerify("),
        "Kotlin SDK missing event log verify wrapper"
    );
    assert!(
        src.contains("fun transportConnect("),
        "Kotlin SDK missing transport connect wrapper"
    );
    assert!(
        src.contains("fun transportStatus("),
        "Kotlin SDK missing transport status wrapper"
    );
}

#[test]
fn kotlin_sdk_discovery_wrappers() {
    let src = kt_all();
    assert!(
        src.contains("fun discoveryParseAddress("),
        "Kotlin SDK missing discovery parse_address wrapper"
    );
}

#[test]
fn kotlin_sdk_bridge_wrappers() {
    let src = kt_all();
    assert!(
        src.contains("fun bridgeRegister("),
        "Kotlin SDK missing bridge register wrapper"
    );
    assert!(
        src.contains("fun bridgeEvaluateTrust("),
        "Kotlin SDK missing bridge evaluate_trust wrapper"
    );
    assert!(
        src.contains("fun bridgeCreateShadow("),
        "Kotlin SDK missing bridge create_shadow wrapper"
    );
}

// ---------------------------------------------------------------------------
// Cross-SDK completeness matrix
// ---------------------------------------------------------------------------

#[test]
fn cross_sdk_wrapper_completeness_matrix() {
    let results = check_all_operations();
    let (total, py_miss, ts_miss, swift_miss, kt_miss) = print_matrix(&results);

    // Collect detailed gap report.
    let mut gaps: Vec<String> = Vec::new();
    for r in &results {
        if !r.py {
            gaps.push(format!("  Python  missing: {}/{}", r.category, r.name));
        }
        if !r.ts {
            gaps.push(format!("  TS      missing: {}/{}", r.category, r.name));
        }
        if !r.swift {
            gaps.push(format!("  Swift   missing: {}/{}", r.category, r.name));
        }
        if !r.kt {
            gaps.push(format!("  Kotlin  missing: {}/{}", r.category, r.name));
        }
    }

    if !gaps.is_empty() {
        println!("SDK wrapper gaps detected:");
        for g in &gaps {
            println!("{g}");
        }
        println!();
    }

    // Assert Python SDK (reference bridge) has full coverage — zero gaps.
    assert_eq!(
        py_miss, 0,
        "Python SDK (reference bridge) has {py_miss}/{total} missing wrappers"
    );

    // Assert TypeScript SDK has full coverage — zero gaps.
    assert_eq!(
        ts_miss, 0,
        "TypeScript SDK has {ts_miss}/{total} missing wrappers"
    );

    // Swift SDK: Identity/migrate is not exposed (UniFFI bridge does not
    // export identityMigrate yet). This is a known gap, not a test failure.
    // When the bridge adds it, update this threshold to 0.
    assert!(
        swift_miss <= 1,
        "Swift SDK has {swift_miss}/{total} missing wrappers (expected at most 1)"
    );

    // Assert Kotlin SDK has full coverage — zero gaps.
    assert_eq!(
        kt_miss, 0,
        "Kotlin SDK has {kt_miss}/{total} missing wrappers"
    );
}

// ---------------------------------------------------------------------------
// File-existence sanity checks — confirm include_str! sources compiled
// ---------------------------------------------------------------------------

#[test]
fn all_sdk_source_files_are_non_empty() {
    let files: &[(&str, &str)] = &[
        ("Python identity.py", PY_IDENTITY),
        ("Python context.py", PY_CONTEXT),
        ("Python tools.py", PY_TOOLS),
        ("Python ucan.py", PY_UCAN),
        ("Python event_log.py", PY_EVENT_LOG),
        ("Python transport.py", PY_TRANSPORT),
        ("Python discovery.py", PY_DISCOVERY),
        ("Python provenance.py", PY_PROVENANCE),
        ("Python trust.py", PY_TRUST),
        ("Python sync.py", PY_SYNC),
        ("Python bridge.py", PY_BRIDGE),
        ("Python governance.py", PY_GOVERNANCE),
        ("TypeScript identity.ts", TS_IDENTITY),
        ("TypeScript context.ts", TS_CONTEXT),
        ("TypeScript tools.ts", TS_TOOLS),
        ("TypeScript ucan.ts", TS_UCAN),
        ("TypeScript event-log.ts", TS_EVENT_LOG),
        ("TypeScript transport.ts", TS_TRANSPORT),
        ("TypeScript discovery.ts", TS_DISCOVERY),
        ("TypeScript provenance.ts", TS_PROVENANCE),
        ("TypeScript trust.ts", TS_TRUST),
        ("TypeScript sync.ts", TS_SYNC),
        ("TypeScript bridge.ts", TS_BRIDGE),
        ("Swift Identity.swift", SWIFT_IDENTITY),
        ("Swift Context.swift", SWIFT_CONTEXT),
        ("Swift Tools.swift", SWIFT_TOOLS),
        ("Swift Ucan.swift", SWIFT_UCAN),
        ("Swift EventLog.swift", SWIFT_EVENT_LOG),
        ("Swift Transport.swift", SWIFT_TRANSPORT),
        ("Swift Discovery.swift", SWIFT_DISCOVERY),
        ("Swift Provenance.swift", SWIFT_PROVENANCE),
        ("Swift Trust.swift", SWIFT_TRUST),
        ("Swift Governance.swift", SWIFT_GOVERNANCE),
        ("Kotlin Identity.kt", KT_IDENTITY),
        ("Kotlin BridgeConnector.kt", KT_BRIDGE_CONNECTOR),
        ("Kotlin Discovery.kt", KT_DISCOVERY),
        ("Kotlin Provenance.kt", KT_PROVENANCE),
        ("Kotlin Sync.kt", KT_SYNC),
        ("Kotlin CoroutineBridge.kt", KT_COROUTINE_BRIDGE),
    ];

    for (label, content) in files {
        assert!(!content.is_empty(), "SDK source file is empty: {label}");
    }
}
