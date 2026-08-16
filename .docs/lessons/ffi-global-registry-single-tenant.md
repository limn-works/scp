# FFI global registries made PyO3 single-tenant (RED-017)

**Status: resolved.** PyO3 now holds per-instance bridge-instance state instead of process-global registries. Three bridges remain — PyO3, NAPI, UniFFI — after removal of a fourth wasm-bindgen bridge, which ADR-057, in-browser client over shared MLS, records at its line 9 as correct and standing. That same ADR revised one further conclusion: a browser no longer runs as a remote thin client, and instead executes protocol code through `scp-client-wasm` over shared `scp-mls`. Everything under "What went wrong" describes an implementation that no longer ships.

## Rule

A process-global static inside an FFI bridge couples every caller that shares one process. A protocol library can end up embedded in a multi-tenant server, so give it per-instance state from its first commit.

## What went wrong

PyO3 (`crates/scp-ffi/src/runtime.rs`) held process-global static registries (`OnceLock<DashMap<...>>`) for context state, known-context discovery metadata, relay connections, and identity routing secrets. Every tenant inside one process shared those registries, so tenant A reached tenant B's context IDs, identity DIDs, and routing secrets.

Four statics carried that shared state:

- `CONTEXT_REGISTRY` — mapped a context ID to `ContextRuntime` (outlet registries, event logs, role state, UCAN state)
- `KNOWN_CONTEXTS` — mapped a context ID to `KnownContext` (routing IDs, relay URLs, member DIDs)
- `RELAY_CONNECTION` — one shared relay adapter, so whichever tenant connected last displaced every earlier connection
- `IDENTITY_ROUTING_SECRETS` (inside `get_or_create_routing_secret`) — mapped an identity DID to 32 secret bytes

Three consequences followed. A tenant enumerated another tenant's contexts by guessing a context ID. Routing secrets derived for one DID reached every tenant. Context isolation, which this protocol names its security boundary, broke at an FFI boundary rather than at a protocol layer.

NAPI and UniFFI never carried that defect, because each hands a caller a per-instance opaque handle (`NapiContextHandle`, `ContextHandle`) that owns its own state. PyO3 predated that pattern and exposed a flat function surface keyed by string lookups into globals. Doc comments on all four statics warned about single-tenant use, which made that limitation legible without removing it.

## What holds now

Per-instance state replaced those globals. `crates/scp-ffi/src/runtime.rs:404` declares `pub struct PyBridgeInstance`, and none of `CONTEXT_REGISTRY`, `KNOWN_CONTEXTS`, `RELAY_CONNECTION`, or `IDENTITY_ROUTING_SECRETS` appears anywhere in that file. Each tenant constructs its own instance, which owns its context, identity, and relay state, so PyO3 now matches NAPI and UniFFI. Lifecycle documentation for all three lives at `crates/scp-ffi/common/src/bridge_instance.rs`.
