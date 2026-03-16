# Cross-Layer Coverage Matrix

## FFI Bridge Coverage (Operations × Targets)

Legend: ✅ = Implemented | ⚠️ = Partial/Stub | ❌ = Missing | N/A = Not applicable per ADR-034

### Identity Operations

| Operation | PyO3 | NAPI | UniFFI | WASM |
|-----------|------|------|--------|------|
| identity_create | ✅ | ✅ | ✅ | ✅ |
| identity_create_with_agent_key | ✅ | ✅ | ✅ | ❌ |
| identity_load | ✅ | ✅ | ✅ | ✅ |
| identity_resolve | ✅ | ✅ | ✅ | ✅ |
| identity_rotate_key | ✅ | ✅ | ✅ | ✅ |
| identity_migrate | ✅ | ✅ | ✅ | ✅ |
| custody_migration | ✅ | ✅ | ✅ | ✅ |
| export_signing_key_bytes | ✅ | ✅ | ⚠️ (returns error) | N/A |

### Context Operations

| Operation | PyO3 | NAPI | UniFFI | WASM |
|-----------|------|------|--------|------|
| context_create | ✅ | ✅ | ✅ | ✅ |
| context_join | ✅ | ✅ | ✅ | ✅ |
| context_leave | ✅ | ✅ | ✅ | ✅ |
| context_close | ✅ | ✅ | ✅ | ✅ |
| context_send | ✅ | ✅ | ✅ | ✅ |
| context_subscribe | ✅ | ✅ | ✅ | ✅ |
| context_export | ✅ | ✅ | ✅ | ✅ |
| context_import | ✅ | ✅ | ✅ | ✅ |
| context_member_count | ✅ | ✅ | ✅ | ✅ |
| context_is_member | ✅ | ✅ | ✅ | ✅ |
| context_member_dids | ✅ | ✅ | ✅ | ✅ |
| context_member_role | ✅ | ✅ | ✅ | ✅ |
| context_drain_events | ✅ | ✅ | ✅ | ✅ |
| governance_execute | ✅ | ✅ | ✅ | ✅ |

### Broadcast Operations

| Operation | PyO3 | NAPI | UniFFI | WASM |
|-----------|------|------|--------|------|
| broadcast_subscribe | ✅ | ✅ | ✅ | ✅ |
| broadcast_unsubscribe | ✅ | ✅ | ✅ | ✅ |
| broadcast_publish | ✅ | ✅ | ✅ | ✅ |
| broadcast_block_subscriber | ✅ | ✅ | ✅ | ✅ |
| broadcast_handle_key_request | ✅ | ✅ | ✅ | ✅ |
| UCAN validation on subscribe | ⚠️ NoOp | ⚠️ NoOp | ⚠️ NoOp | ✅ |

### Tool Operations

| Operation | PyO3 | NAPI | UniFFI | WASM |
|-----------|------|------|--------|------|
| tool_register | ✅ | ✅ | ✅ | ✅ |
| tool_invoke | ✅ | ✅ | ✅ | ✅ |
| tool_verify | ✅ | ✅ | ✅ | ✅ |
| Role-based capability check | ✅ | ✅ | ✅ | ⚠️ (missing) |

### UCAN Operations

| Operation | PyO3 | NAPI | UniFFI | WASM |
|-----------|------|------|--------|------|
| ucan_validate | ✅ | ✅ | ✅ | ✅ |
| ucan_mint | ✅ | ✅ | ✅ | ✅ |
| ucan_revoke | ✅ | ✅ | ✅ | ✅ |

### Event Log Operations

| Operation | PyO3 | NAPI | UniFFI | WASM |
|-----------|------|------|--------|------|
| event_log_query | ✅ | ✅ | ✅ | ✅ |
| event_log_verify | ✅ | ✅ | ✅ | ✅ |

### Transport Operations

| Operation | PyO3 | NAPI | UniFFI | WASM |
|-----------|------|------|--------|------|
| transport_connect | ✅ | ✅ | ✅ | ✅ |
| transport_disconnect | ✅ | ✅ | ✅ | ✅ |
| transport_status | ✅ | ✅ | ✅ | ✅ |

### MCP Operations

| Operation | PyO3 | NAPI | UniFFI | WASM |
|-----------|------|------|--------|------|
| mcp_serve (stdio) | ✅ | ✅ | ✅ | N/A |
| mcp_serve (sse) | ✅ | ❌ (returns error) | ❌ (returns error) | N/A |
| mcp_client_connect | ✅ | ✅ | ✅ | N/A |
| agent_role | ✅ | ❌ (returns None) | ✅ | N/A |
| context_tools | ✅ | ❌ (returns empty) | ✅ | N/A |
| validate_capability | ✅ | ❌ (returns error) | ✅ | N/A |
| invoke_tool (via MCP) | ✅ | ❌ (returns error) | ✅ | N/A |
| context_members | ✅ | ❌ (returns empty) | ✅ | N/A |
| context_events | ✅ | ❌ (returns empty) | ✅ | N/A |
| subscribe_resource | ⚠️ (no-op) | ❌ (returns error) | ⚠️ (no-op) | N/A |

### Trust Operations

| Operation | PyO3 | NAPI | UniFFI | WASM |
|-----------|------|------|--------|------|
| trust scoring | ✅ | ✅ | ⚠️ (event counts return 0,0) | ✅ |

### Discovery Operations

| Operation | PyO3 | NAPI | UniFFI | WASM |
|-----------|------|------|--------|------|
| discovery (context) | ✅ | ✅ | ✅ | ✅ |
| petnames | ✅ | ✅ | ✅ | ✅ |
| handles | ✅ | ✅ | ✅ | ✅ |
| push registration | ✅ | ✅ | ✅ | ✅ |

### SCPID Operations

| Operation | PyO3 | NAPI | UniFFI | WASM |
|-----------|------|------|--------|------|
| scpid_challenge | ✅ | ✅ | ✅ | ✅ |
| scpid_sign | ✅ | ✅ | ✅ | ✅ |
| scpid_verify | ✅ | ✅ | ✅ | N/A (per ADR-034) |

### Sync Operations

| Operation | PyO3 | NAPI | UniFFI | WASM |
|-----------|------|------|--------|------|
| sync status | ✅ | ✅ | ✅ | ✅ |
| conflict resolution | ✅ | ✅ | ✅ | ✅ |

### Media Operations

| Operation | PyO3 | NAPI | UniFFI | WASM |
|-----------|------|------|--------|------|
| media session | ✅ | ✅ | ✅ | N/A |
| media keys | ✅ | ✅ | ✅ | N/A |

### Economy Operations

| Operation | PyO3 | NAPI | UniFFI | WASM |
|-----------|------|------|--------|------|
| economy policy | ✅ | ✅ | ✅ | ✅ |
| budget tracking | ✅ | ✅ | ✅ | ✅ |
| receipts | ✅ | ✅ | ✅ | ✅ |

### Provenance Operations

| Operation | PyO3 | NAPI | UniFFI | WASM |
|-----------|------|------|--------|------|
| provenance attach | ✅ | ✅ | ✅ | ✅ |
| provenance evaluate | ✅ | ✅ | ✅ | ✅ |

### Bridge Connector Operations

| Operation | PyO3 | NAPI | UniFFI | WASM |
|-----------|------|------|--------|------|
| bridge registration | ✅ | ✅ | ✅ | ✅ |
| bridge claiming | ✅ | ✅ | ✅ | ✅ |
