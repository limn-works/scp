# FFI global registries made PyO3 single-tenant (RED-017)

**Status: resolved.** PyO3 now holds per-instance `BridgeInstance` state instead of process-global registries. ADR-055 removed a fourth wasm-bindgen bridge on 2026-06-29, so PyO3, NAPI and UniFFI remain, and a browser runs as a remote thin client. Everything under "What went wrong" describes an implementation that no longer ships.

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

SCP-228 replaced those globals with per-instance runtime objects. Each tenant constructs its own instance, which owns its context, identity, and relay state, and a Python SDK class wraps that instance as one entry point. PyO3 now matches NAPI and UniFFI.
