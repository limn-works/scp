---
name: scp-ts-wasm-browser-tier
description: API review of @limn-works/scp-ts-wasm (ADR-057 in-browser SCP client) — PR #2183, ScpBrowserClient create/connect, embedder ports
metadata:
  type: project
---

# @limn-works/scp-ts-wasm browser tier (PR #2183, ADR-057)

Reviewed the in-browser SCP participant SDK: `ScpBrowserClient` + 3 embedder
ports (`JsSocket`/`JsKeyCustody`/`JsStorage`) + adapters (WebSocketRelaySocket,
IndexedDbStorage, InMemoryStorage, WebCryptoCustody). Verdict: APPROVED, minor
observations only.

**Construction model (well-designed):** two static factories, private ctor.
`create(options)` sync = bring-your-own `JsSocket` (embedder pumps inbound);
`connect(options)` async = managed WebSocket + wasm load + two-phase attach pump.
`custody`+`storage` are REQUIRED fields (no silent default). `InMemoryStorage` is
explicitly framed (its own JSDoc) as a legitimate ephemeral choice, NOT a
stand-in. Errors single-sourced from `@scp-core/errors` via `mapWasmError` →
`mapBridgeError` (prefix dispatch). u64 observers return `bigint` (#1229).

**Minor findings (none blocking):**
- `mlsEpoch(id): bigint` is `call()`-wrapped (THROWS on absent) while its 4 peer
  observers (`memberDids`/`eventLogRoot`/`eventLogLeafCount`/`eventLogLeafHashes`)
  return `| undefined` on absent. Accidental null-vs-throw asymmetry on peer
  observers (client.ts ~375 vs 385).
- `mapWasmError` AND `mapBridgeError` both exported with identical behavior
  (mapWasmError just delegates) — two public names for one fn.
- `create` pump obligation (onmessage→handleRelayFrame, onopen→resubscribeAll) is
  documentation-only (JSDoc + README prose), no code example, no type enforcement.
  Inherent to bring-your-own-socket. Exporting `WebSocketRelaySocket` class invites
  `create({socket: new WebSocketRelaySocket()})` which silently never connects
  unless you also call `.attach()` (only `connect` does).
- `JsKeyCustody` exposes 5 throwing #1980 seam methods (sign/getPublicKey/
  generateKeypair/destroyKey/dhAgree) on the public embedder interface; only
  `did()` has a driver call site. Mechanically justified (mirrors wasm-bindgen
  extern shape verbatim) but is unused public surface today.

**Naming note:** WASM uses verb-noun (`createContext`,`sendMessage`,`closeContext`)
which MATCHES sdk-common.md §naming standard; NAPI `@limn-works/scp-ts` uses
`contextCreate`/`contextSend` (its flat 180-method SCP class needs domain prefixes).
The two packages' surfaces genuinely differ (WASM = low-level MLS primitives:
addMember(keyPackageBytes), joinContextEncrypted(welcome,eventlog,wrappingkeys);
NAPI = high-level managed inviteMember/contextJoinFromWelcome). index.ts claim
"the two tiers share one developer API shape" is true at the IDIOM level (flat
frozen results, shared ScpError, bigint u64, injected ports), NOT method-name/
signature level — a capability SUBSET, documented as such.
