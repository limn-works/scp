# Enforcement rows that restored bridge-connector code needs

> **ARCHIVED — NOT LIVE ENFORCEMENT.** This file records, verbatim, the rows of enforcement and test files that the Track BR code slices, S3a to S9, delete. The Track BR slice S2 pull request copied each row from main on 2026-10-09, while the rows were still live and still passing. Nothing below is enforced.

Restored bridge-connector code fails CI until these rows return, because the gates check every FFI export, every SDK wrapper and every mutable global against them. Restore the code first (`HISTORY.md` lists the paths), then put each block below back at the line its heading names, then run the gate that reads the file. When the surrounding file has changed since 2026-10-09, put the block next to the neighbouring lines it sat between on main, which the tag `archive/bridge-connectors-pre-cut` holds: `git show archive/bridge-connectors-pre-cut:<path>`.

Each section names the file and the line range on main when archived. A four-backtick `text` fence holds the lines byte for byte. Where pull request #2483, "chore: cut platform bridge connectors from every layer (Track BR)", rewrote lines instead of deleting them, a second fence after "Text after the cut:" holds its rewrite.

## `.docs/standards/sdk-capability-matrix.json`

The "Bridge" domain of the SDK capability matrix. `scripts/check-sdk-coverage.py` checks every operation in it against the four SDKs.

### `.docs/standards/sdk-capability-matrix.json`, lines 1861–1952 on main when archived

````text
    {
      "domain": "Bridge",
      "operations": [
        {
          "name": "register",
          "python": true,
          "typescript": false,
          "kotlin": true,
          "swift": true,
          "exemptions": {
            "typescript": "bridge_register is an internal Bridge interface method (bridgeRegister on the internal Bridge interface in bindings/typescript/src/internal/bridge.ts); it is not exposed as a named public SDK function — registration is handled at the FFI layer directly via the NAPI addon"
          }
        },
        {
          "name": "evaluate_trust",
          "python": true,
          "typescript": true,
          "kotlin": true,
          "swift": true
        },
        {
          "name": "create_shadow",
          "python": true,
          "typescript": true,
          "kotlin": true,
          "swift": true
        },
        {
          "name": "credential_provision",
          "python": true,
          "typescript": true,
          "kotlin": true,
          "swift": true
        },
        {
          "name": "credential_retrieve",
          "python": true,
          "typescript": true,
          "kotlin": true,
          "swift": true
        },
        {
          "name": "credential_rotate",
          "python": true,
          "typescript": true,
          "kotlin": true,
          "swift": true
        },
        {
          "name": "credential_revoke",
          "python": true,
          "typescript": true,
          "kotlin": true,
          "swift": true
        },
        {
          "name": "credential_list",
          "python": true,
          "typescript": true,
          "kotlin": true,
          "swift": true
        },
        {
          "name": "credential_store_key",
          "python": true,
          "typescript": true,
          "kotlin": true,
          "swift": true
        },
        {
          "name": "credential_get_key",
          "python": true,
          "typescript": true,
          "kotlin": true,
          "swift": true
        },
        {
          "name": "credential_delete_key",
          "python": true,
          "typescript": true,
          "kotlin": true,
          "swift": true
        },
        {
          "name": "credential_backend_durable",
          "python": true,
          "typescript": true,
          "kotlin": true,
          "swift": true
        }
      ]
    },
````

## `scripts/check-sdk-coverage.py`

Two blocks of the `ALIASES` table, which map Bridge matrix operations to the SDK symbol names that the coverage check accepts.

### `scripts/check-sdk-coverage.py`, lines 938–945 on main when archived

````text
    # Bridge -- Python uses bare 'register' and 'evaluate_trust'.
    # TypeScript's bridgeRegister is matched by the domain_camel auto-candidate.
    ("Bridge", "register"): {
        "python": ["register"],
    },
    ("Bridge", "evaluate_trust"): {
        "python": ["evaluate_trust"],
    },
````

### `scripts/check-sdk-coverage.py`, lines 1081–1092 on main when archived

````text
    # Bridge credential storage backend is bridge-INTERNAL: the durable
    # `FfiCredentialStore` is selected from the SAME storage config the SDK
    # already chooses (ADR-062 §Decision 5, SCP-CAPINJECT-009). There is no
    # dedicated SDK wrapper method — selecting storage (SCP / withStorage /
    # withSqlite) selects the durable credential backend by construction, so the
    # matrix cell aliases to the existing storage-selection symbols.
    ("Bridge", "credential_backend_durable"): {
        "python": ["SCP"],
        "typescript": ["SCP"],
        "swift": ["withStorage", "SCP"],
        "kotlin": ["withStorage", "withSqlite", "SCP"],
    },
````

## `crates/scp-testing/tests/integration/sdk_wrapper.rs`

The bridge-connector wrapper sources the SDK wrapper test reads, the Bridge `ExpectedOp` entries, and the Swift and Kotlin bridge wrapper tests.

### `crates/scp-testing/tests/integration/sdk_wrapper.rs`, line 34 on main when archived

````text
const PY_BRIDGE: &str = include_str!("../../../../bindings/python/scp_sdk/bridge.py");
````

### `crates/scp-testing/tests/integration/sdk_wrapper.rs`, line 54 on main when archived

````text
const TS_BRIDGE: &str = include_str!("../../../../bindings/typescript/src/bridge.ts");
````

### `crates/scp-testing/tests/integration/sdk_wrapper.rs`, lines 85–87 on main when archived

````text
// `syncClassifyOffline`, `identityMigrate`, `bridgeEvaluateTrust`). This
// file is now the canonical wrapper surface alongside the per-module
// files above, so include it for the SDK wrapper coverage matrix.
````

Text after the cut:

````text
// `syncClassifyOffline`, `identityMigrate`). This file is now the
// canonical wrapper surface alongside the per-module files above, so
// include it for the SDK wrapper coverage matrix.
````

### `crates/scp-testing/tests/integration/sdk_wrapper.rs`, lines 90–93 on main when archived

````text
// (`bridgeRegister`, `bridgeCreateShadow`, `evaluateProvenanceQuality`,
// etc.) that the hand-written wrappers delegate to. Some operations are
// currently invoked only via the generated free functions — include this
// file so the coverage matrix sees them.
````

Text after the cut:

````text
// (`evaluateProvenanceQuality`, etc.) that the hand-written wrappers
// delegate to. Some operations are currently invoked only via the
// generated free functions — include this file so the coverage matrix
// sees them.
````

### `crates/scp-testing/tests/integration/sdk_wrapper.rs`, lines 100–102 on main when archived

````text
const KT_BRIDGE_CONNECTOR: &str = include_str!(
    "../../../../bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/BridgeConnector.kt"
);
````

### `crates/scp-testing/tests/integration/sdk_wrapper.rs`, line 144 on main when archived

````text
        PY_BRIDGE,
````

### `crates/scp-testing/tests/integration/sdk_wrapper.rs`, line 161 on main when archived

````text
        TS_BRIDGE,
````

### `crates/scp-testing/tests/integration/sdk_wrapper.rs`, line 188 on main when archived

````text
        KT_BRIDGE_CONNECTOR,
````

### `crates/scp-testing/tests/integration/sdk_wrapper.rs`, lines 648–674 on main when archived

````text
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
````

### `crates/scp-testing/tests/integration/sdk_wrapper.rs`, lines 1193–1213 on main when archived

````text
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

````

### `crates/scp-testing/tests/integration/sdk_wrapper.rs`, lines 1333–1349 on main when archived

````text
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

````

### `crates/scp-testing/tests/integration/sdk_wrapper.rs`, line 1428 on main when archived

````text
        ("Python bridge.py", PY_BRIDGE),
````

### `crates/scp-testing/tests/integration/sdk_wrapper.rs`, line 1438 on main when archived

````text
        ("TypeScript bridge.ts", TS_BRIDGE),
````

### `crates/scp-testing/tests/integration/sdk_wrapper.rs`, line 1450 on main when archived

````text
        ("Kotlin BridgeConnector.kt", KT_BRIDGE_CONNECTOR),
````

## `scripts/bridge-aliases.json`

The 11 bridge-connector operations in the cross-bridge alias table: `bridge_create_shadow`, eight `bridge_credential_*` operations, `bridge_evaluate_trust` and `bridge_register`.

### `scripts/bridge-aliases.json`, lines 889–1034 on main when archived

````text
    {
      "canonical": "bridge_evaluate_trust",
      "category": "bridge",
      "pyo3": [
        "py_bridge_evaluate_trust",
        "bridge_evaluate_trust"
      ],
      "uniffi": [
        "bridge_evaluate_trust"
      ],
      "napi": [
        "bridge_evaluate_trust"
      ]
    },
    {
      "canonical": "bridge_register",
      "category": "bridge",
      "pyo3": [
        "py_bridge_register",
        "bridge_register"
      ],
      "uniffi": [
        "bridge_register"
      ],
      "napi": [
        "bridge_register"
      ]
    },
    {
      "canonical": "bridge_create_shadow",
      "category": "bridge",
      "pyo3": [
        "py_bridge_create_shadow",
        "bridge_create_shadow"
      ],
      "uniffi": [
        "bridge_create_shadow"
      ],
      "napi": [
        "bridge_create_shadow"
      ]
    },
    {
      "canonical": "bridge_credential_provision",
      "category": "bridge",
      "pyo3": [
        "bridge_credential_provision"
      ],
      "uniffi": [
        "bridge_credential_provision"
      ],
      "napi": [
        "bridge_credential_provision"
      ]
    },
    {
      "canonical": "bridge_credential_retrieve",
      "category": "bridge",
      "pyo3": [
        "bridge_credential_retrieve"
      ],
      "uniffi": [
        "bridge_credential_retrieve"
      ],
      "napi": [
        "bridge_credential_retrieve"
      ]
    },
    {
      "canonical": "bridge_credential_rotate",
      "category": "bridge",
      "pyo3": [
        "bridge_credential_rotate"
      ],
      "uniffi": [
        "bridge_credential_rotate"
      ],
      "napi": [
        "bridge_credential_rotate"
      ]
    },
    {
      "canonical": "bridge_credential_revoke",
      "category": "bridge",
      "pyo3": [
        "bridge_credential_revoke"
      ],
      "uniffi": [
        "bridge_credential_revoke"
      ],
      "napi": [
        "bridge_credential_revoke"
      ]
    },
    {
      "canonical": "bridge_credential_list",
      "category": "bridge",
      "pyo3": [
        "bridge_credential_list"
      ],
      "uniffi": [
        "bridge_credential_list"
      ],
      "napi": [
        "bridge_credential_list"
      ]
    },
    {
      "canonical": "bridge_credential_store_key",
      "category": "bridge",
      "pyo3": [
        "bridge_credential_store_key"
      ],
      "uniffi": [
        "bridge_credential_store_key"
      ],
      "napi": [
        "bridge_credential_store_key"
      ]
    },
    {
      "canonical": "bridge_credential_get_key",
      "category": "bridge",
      "pyo3": [
        "bridge_credential_get_key"
      ],
      "uniffi": [
        "bridge_credential_get_key"
      ],
      "napi": [
        "bridge_credential_get_key"
      ]
    },
    {
      "canonical": "bridge_credential_delete_key",
      "category": "bridge",
      "pyo3": [
        "bridge_credential_delete_key"
      ],
      "uniffi": [
        "bridge_credential_delete_key"
      ],
      "napi": [
        "bridge_credential_delete_key"
      ]
    },
````

## `scripts/ffi-export-allowlist.json`

Eight allowlist entries for bridge-connector FFI exports that exist on fewer than three bridges.

### `scripts/ffi-export-allowlist.json`, lines 42–89 on main when archived

````text
    {
      "name": "py_bridge_claim_shadow",
      "path": "crates/scp-ffi/src/bridge_connector.rs",
      "kind": "bridge-specific",
      "reason": "Claims a bridge shadow identity via identity attestation (spec \u00a712.2.1). PyO3-only helper in bridge_connector.rs; the registered cross-bridge op is bridge_create_shadow, not claim. Not a parity gap."
    },
    {
      "name": "py_bridge_derive_credential_key",
      "path": "crates/scp-ffi/src/bridge_connector.rs",
      "kind": "bridge-specific",
      "reason": "Derives a per-bridge credential encryption key (spec \u00a712.11.2). PyO3-only crypto helper in bridge_connector.rs; the cross-bridge credential ops (bridge_credential_provision, bridge_credential_retrieve, bridge_credential_rotate, bridge_credential_revoke, bridge_credential_list, bridge_credential_store_key, bridge_credential_get_key, bridge_credential_delete_key) are registered separately. Not a parity gap."
    },
    {
      "name": "py_bridge_generate_credential_key",
      "path": "crates/scp-ffi/src/bridge_connector.rs",
      "kind": "bridge-specific",
      "reason": "Generates a random bridge credential key (spec \u00a712.11.2). PyO3-only crypto helper in bridge_connector.rs; the cross-bridge credential ops are registered separately. Not a parity gap."
    },
    {
      "name": "py_bridge_oauth_build_auth_url",
      "path": "crates/scp-ffi/src/bridge_connector.rs",
      "kind": "bridge-specific",
      "reason": "Builds an OAuth 2.0 authorization URL for a bridge connector (spec \u00a712.2.1). PyO3-only convenience helper in bridge_connector.rs; not among the 11 cross-bridge Bridge ops in .docs/standards/sdk-capability-matrix.json. Not a parity gap."
    },
    {
      "name": "py_bridge_oauth_generate_pkce",
      "path": "crates/scp-ffi/src/bridge_connector.rs",
      "kind": "bridge-specific",
      "reason": "PKCE S256 challenge generation for bridge-connector OAuth (spec \u00a712.2.1). PyO3-only convenience helper in bridge_connector.rs; not among the 11 cross-bridge Bridge ops in .docs/standards/sdk-capability-matrix.json. Not a parity gap."
    },
    {
      "name": "py_bridge_oauth_scopes_for_mode",
      "path": "crates/scp-ffi/src/bridge_connector.rs",
      "kind": "bridge-specific",
      "reason": "Returns recommended OAuth scopes for a bridge mode (spec \u00a712.2.1). PyO3-only convenience helper in bridge_connector.rs; not among the 11 cross-bridge Bridge ops in .docs/standards/sdk-capability-matrix.json. Not a parity gap."
    },
    {
      "name": "py_bridge_open_shadow_envelope",
      "path": "crates/scp-ffi/src/bridge_connector.rs",
      "kind": "bridge-specific",
      "reason": "Opens a sender-key-encrypted bridge shadow envelope (spec \u00a712.10.2). PyO3-only crypto helper in bridge_connector.rs; not among the 11 cross-bridge Bridge ops in .docs/standards/sdk-capability-matrix.json. Not a parity gap."
    },
    {
      "name": "py_bridge_seal_shadow_envelope",
      "path": "crates/scp-ffi/src/bridge_connector.rs",
      "kind": "bridge-specific",
      "reason": "Seals a sender-key-encrypted bridge shadow envelope (spec \u00a712.10.2). PyO3-only crypto helper in bridge_connector.rs; not among the 11 cross-bridge Bridge ops in .docs/standards/sdk-capability-matrix.json. Not a parity gap."
    },
````

## `scripts/check-no-mutable-globals.sh`

Two allowlist rows: `CREDENTIAL_HKDF_SALT`, the bridge credential salt, and `EVENT_COUNTER`, the webhook event-ID counter.

### `scripts/check-no-mutable-globals.sh`, line 117 on main when archived

````text
    CREDENTIAL_HKDF_SALT            # why: domain-separation salt for bridge credential HKDF — pure constant derived from a fixed seed at import.
````

### `scripts/check-no-mutable-globals.sh`, line 125 on main when archived

````text
    EVENT_COUNTER                   # why: monotonic `AtomicU64` for webhook event IDs; no shared state, safe across instances.
````

## `crates/scp-testing/tests/integration/pipeline_wiring.rs`

The test `b3_webhook_dispatch_wired`, which asserts that the node webhook dispatcher exists and that every FFI bridge wires Supervisor events into it.

### `crates/scp-testing/tests/integration/pipeline_wiring.rs`, lines 2815–2952 on main when archived

````text
/// Webhook dispatch must exist and be wired into bridge event handling.
/// ApplicationNode must dispatch webhooks when context events occur for
/// registered bridges with webhook_url.
#[test]
fn b3_webhook_dispatch_wired() {
    let node_src = include_str!("../../../../crates/scp-node/src/lib.rs");
    assert!(
        node_src.contains("mod webhook"),
        "ApplicationNode must have webhook module registered"
    );

    let webhook_src = include_str!("../../../../crates/scp-node/src/webhook.rs");
    assert!(
        webhook_src.contains("dispatch_webhook"),
        "webhook module must export dispatch_webhook function"
    );
    assert!(
        webhook_src.contains("WebhookEvent"),
        "webhook module must define WebhookEvent type"
    );
    assert!(
        webhook_src.contains("X-SCP-Signature"),
        "webhook dispatch must set X-SCP-Signature header"
    );
    assert!(
        webhook_src.contains("X-SCP-Timestamp"),
        "webhook dispatch must set X-SCP-Timestamp header"
    );
    assert!(
        webhook_src.contains("validate_webhook_url"),
        "webhook module must include SSRF validation"
    );

    // The consumer that bridges Supervisor events to the dispatcher must
    // exist (§12.10.5). Without it, local context events can never reach
    // registered webhooks — the dispatcher would only ever be fed by the
    // inbound HTTP relay endpoint.
    assert!(
        webhook_src.contains("fn spawn_event_consumer"),
        "webhook module must export spawn_event_consumer (local-event → dispatcher bridge)"
    );
    assert!(
        webhook_src.contains("fn map_context_event"),
        "webhook module must map ContextEvent variants to webhook event types"
    );

    // The consumer must be wired in production: the node exposes the wire, and
    // the FFI node-startup path enables the Supervisor event channel and spawns
    // the consumer. A string match here guards against the regression where the
    // plumbing existed but was never connected.
    assert!(
        node_src.contains("fn wire_context_events"),
        "ApplicationNode must expose wire_context_events to connect events to the dispatcher"
    );

    // The producer seam: the supervisor exposes the public subscribe surface
    // that FFI node startup drives. After ADR-049 the event channel moved off
    // the deleted ContextManager onto the Supervisor, so the live symbol is
    // `Supervisor::subscribe_events` (the former `ContextManager::with_event_channel`
    // accessor is gone).
    let supervisor_src =
        include_str!("../../../../crates/scp-runtime/src/context/supervisor/supervisor.rs");
    assert!(
        supervisor_src.contains("fn subscribe_events"),
        "Supervisor must expose subscribe_events so the node webhook dispatcher \
         consumer can subscribe (otherwise no events are dispatched)"
    );

    // Every bridge (PyO3 reference, NAPI, UniFFI) must independently
    // (a) enable the Supervisor event channel at supervisor construction and
    // (b) wire the consumer into the dispatcher at node startup. The original
    // wiring was first fixed only on PyO3; NAPI/UniFFI had structurally
    // identical startup paths that were never wired, so local events never
    // reached the dispatcher on Node/Bun/Swift/Kotlin. These per-bridge string
    // matches guard against that drift recurring.
    //
    // The shared supervision seam (`spawn_supervised_event_consumer`) lives in
    // `scp-ffi-common`; assert it exists so the consolidated wire cannot be
    // silently inlined-and-diverged again.
    let common_server_src = include_str!("../../../../crates/scp-ffi/common/src/server.rs");
    assert!(
        common_server_src.contains("fn spawn_supervised_event_consumer"),
        "scp-ffi-common must expose the shared spawn_supervised_event_consumer \
         supervision seam used by all bridges"
    );
    assert!(
        common_server_src.contains("fn wire_and_supervise_context_events"),
        "RunningNode must expose wire_and_supervise_context_events (shared \
         subscribe → wire → supervise seam for all bridges)"
    );

    // PyO3 reference bridge.
    let ffi_server_src = include_str!("../../../../crates/scp-ffi/src/server.rs");
    assert!(
        ffi_server_src.contains("wire_node_webhook_events")
            && ffi_server_src.contains("wire_and_supervise_context_events"),
        "PyO3 node startup must call wire_node_webhook_events into the shared \
         wire_and_supervise_context_events seam so local events reach the \
         webhook dispatcher"
    );
    let ffi_runtime_src = include_str!("../../../../crates/scp-ffi/src/runtime.rs");
    assert!(
        ffi_runtime_src.contains("EVENT_CHANNEL_CAPACITY")
            && ffi_runtime_src.contains("Some(event_tx)"),
        "PyO3 production Supervisor construction must enable the event channel \
         (otherwise subscribe_events yields None and no events are dispatched)"
    );

    // NAPI bridge (Node.js/Bun).
    let napi_server_src = include_str!("../../../../crates/scp-ffi/napi/src/server.rs");
    assert!(
        napi_server_src.contains("wire_and_supervise_context_events"),
        "NAPI node startup must wire Supervisor events into the webhook \
         dispatcher (regression guard on Node/Bun)"
    );
    let napi_runtime_src = include_str!("../../../../crates/scp-ffi/napi/src/runtime.rs");
    assert!(
        napi_runtime_src.contains("EVENT_CHANNEL_CAPACITY")
            && napi_runtime_src.contains("Some(event_tx)"),
        "NAPI production Supervisor construction must enable the event channel \
         (otherwise subscribe_events yields None and no events are dispatched)"
    );

    // UniFFI bridge (Swift/Kotlin).
    let uniffi_server_src = include_str!("../../../../crates/scp-ffi/uniffi/src/server.rs");
    assert!(
        uniffi_server_src.contains("wire_and_supervise_context_events"),
        "UniFFI node startup must wire Supervisor events into the webhook \
         dispatcher (regression guard on Swift/Kotlin)"
    );
    let uniffi_runtime_src = include_str!("../../../../crates/scp-ffi/uniffi/src/runtime.rs");
    assert!(
        uniffi_runtime_src.contains("EVENT_CHANNEL_CAPACITY")
            && uniffi_runtime_src.contains("Some(event_tx)"),
        "UniFFI production Supervisor construction must enable the event channel \
         (otherwise subscribe_events yields None and no events are dispatched)"
    );
}
````

Text after the cut (pull request #2483 replaces the test with one that keeps only the Supervisor event-channel assertions):

````text
/// The `Supervisor` `ContextEvent` channel (ADR-049 §12a) must be exposed and
/// enabled on every production bridge. The supervisor exposes the public
/// subscribe surface, and each bridge's production `Supervisor` construction
/// enables the channel, so `subscribe_events()` yields a receiver on every
/// bridge.
#[test]
fn context_event_channel_enabled_on_every_bridge() {
    // The producer seam: after ADR-049 the event channel moved off the deleted
    // ContextManager onto the Supervisor, so the live symbol is
    // `Supervisor::subscribe_events` (the former
    // `ContextManager::with_event_channel` accessor is gone).
    let supervisor_src =
        include_str!("../../../../crates/scp-runtime/src/context/supervisor/supervisor.rs");
    assert!(
        supervisor_src.contains("fn subscribe_events"),
        "Supervisor must expose subscribe_events (otherwise no Rust caller can subscribe)"
    );

    // PyO3 reference bridge.
    let ffi_runtime_src = include_str!("../../../../crates/scp-ffi/src/runtime.rs");
    assert!(
        ffi_runtime_src.contains("EVENT_CHANNEL_CAPACITY")
            && ffi_runtime_src.contains("Some(event_tx)"),
        "PyO3 production Supervisor construction must enable the event channel \
         (otherwise subscribe_events yields None)"
    );

    // NAPI bridge (Node.js/Bun).
    let napi_runtime_src = include_str!("../../../../crates/scp-ffi/napi/src/runtime.rs");
    assert!(
        napi_runtime_src.contains("EVENT_CHANNEL_CAPACITY")
            && napi_runtime_src.contains("Some(event_tx)"),
        "NAPI production Supervisor construction must enable the event channel \
         (otherwise subscribe_events yields None)"
    );

    // UniFFI bridge (Swift/Kotlin).
    let uniffi_runtime_src = include_str!("../../../../crates/scp-ffi/uniffi/src/runtime.rs");
    assert!(
        uniffi_runtime_src.contains("EVENT_CHANNEL_CAPACITY")
            && uniffi_runtime_src.contains("Some(event_tx)"),
        "UniFFI production Supervisor construction must enable the event channel \
         (otherwise subscribe_events yields None)"
    );
}
````

## `crates/scp-testing/tests/integration/ffi_conformance.rs`

The two `include_str!` constants that feed the PyO3 and NAPI `bridge_connector.rs` sources to the FFI conformance checks, and their two entries in the source lists.

### `crates/scp-testing/tests/integration/ffi_conformance.rs`, lines 41–42 on main when archived

````text
const PYO3_BRIDGE_CONNECTOR: &str =
    include_str!("../../../../crates/scp-ffi/src/bridge_connector.rs");
````

### `crates/scp-testing/tests/integration/ffi_conformance.rs`, lines 91–92 on main when archived

````text
const NAPI_BRIDGE_CONNECTOR: &str =
    include_str!("../../../../crates/scp-ffi/napi/src/bridge_connector.rs");
````

### `crates/scp-testing/tests/integration/ffi_conformance.rs`, line 679 on main when archived

````text
        PYO3_BRIDGE_CONNECTOR,
````

### `crates/scp-testing/tests/integration/ffi_conformance.rs`, line 702 on main when archived

````text
        NAPI_BRIDGE_CONNECTOR,
````
