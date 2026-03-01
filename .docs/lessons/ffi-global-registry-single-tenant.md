# FFI Global Registry: Single-Tenant Limitation (RED-017)

## Problem

The PyO3 FFI bridge (`crates/scp-ffi/src/runtime.rs`) uses process-global static registries (`OnceLock<DashMap<...>>`) for context state, known-context discovery metadata, relay connections, and identity routing secrets. In multi-tenant deployments (e.g., a Django or FastAPI server serving multiple SCP users in the same process), all tenants share these registries. Tenant A's context IDs, identity DIDs, and routing secrets are accessible to Tenant B.

## Affected Statics

- `CONTEXT_REGISTRY` — maps context IDs to `ContextRuntime` (tool registries, event logs, role state, UCAN state)
- `KNOWN_CONTEXTS` — maps context IDs to `KnownContext` (routing IDs, relay URLs, member DIDs)
- `RELAY_CONNECTION` — single shared relay adapter
- `IDENTITY_ROUTING_SECRETS` (inside `get_or_create_routing_secret`) — maps identity DIDs to 32-byte secrets

## Why Only PyO3

The NAPI (Node.js), UniFFI (Swift/Kotlin), and WASM bridges use per-instance opaque handle objects (`NapiContextHandle`, `ContextHandle`, `WasmContextHandle`) instead of global registries. Each handle carries its own state. The PyO3 bridge predates this pattern and uses a flat function surface with string-keyed global lookups.

## Impact

- **Cross-tenant context leakage**: Tenant A can access Tenant B's contexts by guessing or enumerating context IDs.
- **Cross-tenant identity leakage**: Routing secrets derived for one tenant's DID are shared with all tenants.
- **Single relay connection**: Only one relay connection exists process-wide. The last tenant to connect wins.
- **No isolation guarantees**: The protocol's context isolation principle (tenet #3) is violated at the FFI boundary.

## Mitigation (Current)

Doc comments on all four statics warn about the single-tenant limitation. The PyO3 bridge is safe for single-tenant use (CLI tools, single-user desktop apps, single-tenant servers).

## Resolution (SCP-228)

Replace global registries with per-instance `ScpRuntime` objects. Each tenant creates its own runtime instance with isolated context, identity, and relay state. The Python SDK wraps the runtime in a class that serves as the entry point for all operations. This matches the pattern used by the NAPI, UniFFI, and WASM bridges.

## Lesson

Process-global statics in FFI bridges create implicit coupling between all callers in the same process. For protocol libraries that may be embedded in multi-tenant servers, prefer per-instance state from the start. The other three bridges (NAPI, UniFFI, WASM) got this right by using opaque handle objects.
