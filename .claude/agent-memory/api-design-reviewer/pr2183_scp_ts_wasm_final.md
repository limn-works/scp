---
name: pr2183-scp-ts-wasm-final
description: PR #2183 (@limn-works/scp-ts-wasm browser SDK, ADR-057) final Round-F API confirmation — APPROVED; two-constructor create/connect split + SCP-VALID-7026 guard, symmetric undefined observers
metadata:
  type: project
---

# PR #2183 `@limn-works/scp-ts-wasm` — final public-API confirmation (Round F)

APPROVED (confirmation of earlier APPROVED state; nothing regressed). Branch `feat/scp-ts-wasm-packaging`.

**Why it's sound:**
- **Two-constructor split** `ScpBrowserClient.create()` (sync, BYO `JsSocket`) vs `connect()` (async, managed WebSocket). Happy path = `connect({custody, storage, url})`, shown in the barrel quickstart. `connect()` takes `url` not a socket (extends `WebSocketRelaySocketOptions`), so a foreign socket CANNOT be injected into the managed path — the two paths are structurally disjoint.
- **SCP-VALID-7026 guard** = good, not a trap. `create()` with a `WebSocketRelaySocket` throws with a pointer to `connect()`. Converts the silent footgun (managed socket handed to BYO path → unattached → `send()` throws forever, no inbound pump) into a loud actionable error. Fails safe.
- **Observers symmetric**: `mlsEpoch/memberDids/eventLogRoot/eventLogLeafCount/eventLogLeafHashes` all return `undefined` for not-held/poisoned; `contextStatus()` is the explicit throwing-distinction predicate (`live|poisoned|absent` enum). `mlsEpoch` gates on `contextStatus!=="live"` to match siblings (single-threaded driver, no race). u64s are `bigint` (not lossy Number, #1229).
- **Adapters** flat named-field, no typestate: `WebCryptoCustody.create({did, crypto?})`, `IndexedDbStorage.open({databaseName?, storeName?, indexedDB?})`, `new InMemoryStorage()`. Custody #1980 seams fail closed (throw) not fabricate.

**Two prior-pass MINORs now RESOLVED in this final state:**
- `mlsEpoch` was throw-on-absent; NOW returns `undefined` symmetric with the 4 peer observers (gates on `contextStatus!=="live"`). ✓
- duplicate `mapWasmError`==`mapBridgeError` export collapsed to just `mapBridgeError`. ✓

**Observations (non-blocking, inherent to design):**
- Naming (`createContext`/`sendMessage`/`closeContext`) CONFORMS to the sdk-common verb-noun standard (`.docs/standards/sdk-common.md:317,324` = `createContext`). The NAPI sibling's `contextCreate`/`contextSend` is the KNOWN OUTLIER, not the wasm tier. Do NOT flag wasm as the divergence — it's the standard-conformant one.
- Three construction verbs (`new` / `.create` / `.open`) across the three injected adapters. Each justified (`open`=async I/O preload, `create`=validating factory + private ctor, `new`=trivial in-memory).
- `WebSocketRelaySocket` is exported + constructable but has no standalone happy path — hand-building one only leads to the 7026 guard (create) or is redundant with connect (which builds its own). Fails safe; exported mainly for its option types.
- `InitInput` (type of `ScpBrowserConnectOptions.wasmModule` / `initScp` param) not re-exported from barrel. Structurally typed so callers pass a value without naming it; minor.
