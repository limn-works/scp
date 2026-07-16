# SCP Planning Session 09 — ADR-057 Slice 3: TS SDK Browser Backend Packaging & Transport Shape

**Date:** July 15, 2026
**Scope:** Lock the permanent public-API shape for how the ADR-057 in-browser client is delivered through `@limn-works/scp-ts`, plus the transport and sequencing decisions that gate Slice 3 execution. Six decisions locked (D1–D6). This is a DOA-grade (permanent public API) set of rulings, recorded here because "artifacts are the system of record."
**Status:** Decided — awaiting execution. #2145 (the ADR-057 test stack) merged to `main` (`bc4464566`), so Slice-3 coding can branch from a clean `main`.
**Provenance:**
- ADR-057 (`.docs/adrs/ADR-057-in-browser-client-over-shared-mls.md`): Implementation Slices 3–4 (lines 84–85, "wire the browser backend behind the existing `@limn-works/scp-ts` API"; "Re-add browser examples … as in-browser-client demos … closes the intent behind #1951"); the **Amends ADR-055** note (line 5, ADR-057 revises ADR-055's remote-thin-client browser conclusion); the mechanical scope fence (lines 51–52, `scp-client`/`scp-client-wasm` MUST NOT reach `scp-runtime`/`scp-identity`/tokio); the as-built custody caveat (line 72); T3 (line 94, the resolved untrusted-relay timestamp blocker).
- Ground-truth investigations (July 15, 2026): current `bindings/typescript` packaging; `scp-client-wasm` portability audit; external SDK convention survey.
- External primary sources: esbuild docs (native `esbuild` vs `esbuild-wasm`); `@duckdb/duckdb-wasm` package.json; napi-rs v3 WebAssembly docs (`-wasm32-wasi` separate package); Firebase JS SDK v9 `exports` + `@firebase/app` peerDependency model; Node.js "Dual package hazard" docs (v15.2.0 archive).
- Issue #1951 (reframed this session to in-browser-client demos); #1444 (panic=unwind, re-scoped LIVE); #1229 (u64/BigInt, re-scoped LIVE); #2143/#2144 (filed).

## Context / how this was re-scoped

The task label "TS SDK browser backend" inherited an ADR-055 premise (browser = remote thin client). **ADR-057 amends ADR-055 on exactly this point** (line 5): the browser runs the full protocol in-tab over `scp-client-wasm`. #1951 was written under the stale model and was reframed this session. The shipped TS source still carries ADR-055 remote-thin-client comments — a stale-comment cleanup folded into Slice 3.

Three ground-truth findings drove the decisions:

1. **The `scp-client-wasm` client is portable-non-native, not browser-locked.** Custody and storage are injected extern ports (`JsKeyCustody`/`JsStorage` — "opaque JS object with these methods," zero DOM calls); clock is `Date.now()`; `web-sys` features = only `console`; a grep across `scp-client-wasm`/`scp-client`/`scp-mls` for `window`/`document`/`navigator`/`indexedDB`/`WebSocket` returns zero browser globals. It compiles to `wasm32-unknown-unknown` with no DOM assumption. `getrandom` uses the Web-standard `crypto.getRandomValues`. → The tier is honestly named by **mechanism (wasm)**, not environment (browser); it can run in Deno/Bun/Workers/edge with swapped adapters.

2. **The current package is single-entry and the NAPI binary is already out of the bundle graph.** `@limn-works/scp-ts` ships one `.` export, ESM+CJS, `getBridge()` dynamically imports `native.ts`, which loads the per-platform `@limn-works/scp-ts-napi-*` optional-dep binary via `createRequire`/`node:module`. The only browser-bundle poison is `native.ts`'s `node:module` import. The dual-package (`instanceof`) hazard **already exists today** (ESM+CJS with an `instanceof ScpError` fast-path in `mapBridgeError`). The `Bridge` interface has **160 methods**; error mapping is by category **prefix**, not number (so browser `SCP-CTX-2005` → `ContextError` cleanly).

3. **External convention for native+wasm-of-the-same-code is separate packages named by the wasm mechanism, native as the unqualified base.** `esbuild`/`esbuild-wasm`, `duckdb`/`@duckdb/duckdb-wasm`, napi-rs `-wasm32-wasi`. Environment names (`browser`/`node`) are used only as bundler-selection *conditions*, not as the capability-tier handle. Firebase avoids the dual-package hazard via a shared-core **peer dependency**.

## Decisions

**D1 — Two self-contained packages; no core package, no subpaths.** Ship exactly two npm packages a consumer ever sees:
- `@limn-works/scp-ts` = shared core (error hierarchy, types, wire marshalling) **+** the NAPI-backed `ScpClient` (full capability). The base package; keeps its current name and its `@limn-works/scp-ts-napi-*` optional-dep binaries.
- `@limn-works/scp-ts-wasm` = shared core **+** the WASM-backed `ScpClient` (participant subset) + browser-default adapters (`WebCryptoCustody`, `IndexedDbStorage`).

Each package **bundles its own copy of the shared core** (which lives as one module in the monorepo, bundled into both at build — single source, no drift, no third published package). A consumer installs exactly one package for their tier and imports everything (client, adapters, errors) from it. Node: `npm i @limn-works/scp-ts`. Browser/edge: `npm i @limn-works/scp-ts-wasm`.

*Rationale:* This is the esbuild/duckdb/napi-rs convention. The `instanceof`/dual-package hazard that would justify a shared-singleton core **does not exist across tiers** — native and wasm never co-load in one JS realm (you are in Node *or* browser/edge; even an isomorphic app splits them across the server process and the client bundle). So core duplication is harmless, and the wire byte-format that must agree across tiers lives in **Rust** (`scp-protocol` + relay-client crate, pinned by the cross-target KAT), not in the duplicated TS — TS only marshals `Uint8Array`s.

*Rejected alternatives:*
- **Separate `-core` package (3 packages).** Only existed to make error classes a cross-tier singleton — a hazard that does not occur (tiers never co-load). Net effect was a confusing third package a browser user must install alongside `-wasm`. Rejected as unnecessary complexity.
- **One package with `/napi` + `/wasm` subpaths, root = core.** Viable, and keeps one install — but bundle isolation becomes a *manual* invariant (a CI guard forbidding `node:` in the `/wasm` build) and it runs against the dominant convention. Two self-contained packages get physical isolation by construction. (If single-install ergonomics ever outweigh, this remains the fallback.)

**D2 — Keep the `-ts` family suffix; native is the unqualified base, wasm is the mechanism-suffixed tier.** Package names are `@limn-works/scp-ts` and `@limn-works/scp-ts-wasm` — NOT bare `@limn-works/scp`.

*Rationale:* `-ts` is part of the deliberate cross-language `scp-{lang}` naming family (`scp-kt`, etc.), adopted partly because bare `scp` was unavailable across registries. The SDK's core principle is *identical shape across all language bindings*; predictable naming is part of that shape. Dropping `-ts` only in npm makes TS the inconsistent outlier to save three characters in one registry. The mechanism suffix stacks cleanly: `scp-ts` (the TS SDK) + `scp-ts-wasm` (its wasm variant).

*Rejected:* bare `@limn-works/scp` + `@limn-works/scp-wasm` — cleaner in isolation, but breaks the cross-language family consistency; not worth it.

**D3 — Explicit tier opt-in; no transparent native→wasm fallback.** A consumer installs `@limn-works/scp-ts` *or* `@limn-works/scp-ts-wasm` deliberately. The base package is **not** a client the browser silently falls back from.

*Rationale:* esbuild/napi-rs do transparent fallback because their wasm build is functionally identical (just slower). Ours is a **capability subset** — the wasm tier has no governance/economy/saga/media/DHT/broadcast-hosting (all behind the `scp-runtime` scope fence). A silent fallback would give a browser dev a subset under the same import as the full node surface — a misuse magnet and a "same import, different capability by environment" trap. The reduced tier must be a knowing choice, which is why it has its own legible package. *Caveat (accepted):* `@limn-works/scp-ts` being the canonical name means a browser dev's naive `npm i @limn-works/scp-ts` lands on native (won't load in a browser) — the same situation esbuild has; managed by leading browser users to `-wasm` prominently in the quickstart/README.

**D4 — Transport is an injected `JsSocket` port, not a `web_sys::WebSocket` call; WebSocket first.** The relay transport the browser client speaks is delivered as a JS-injected socket-like extern object (constructor-injected exactly like `JsKeyCustody`/`JsStorage`), NOT a direct `web_sys::WebSocket` binding inside the Rust crate.

*Rationale:* Keeps `scp-client-wasm` honestly portable (D1/mechanism-naming) — the embedder supplies a browser `WebSocket`, a Deno socket, a Workers `WebSocketPair`, or Node `ws`. Also gives a mockable socket for host tests, and keeps the wasm fence trivially clean (no `web-sys` transport features). WebSocket is the universal relay baseline (spec §10.15.3); WebTransport is a strict follow-on behind the same injected-port interface. This is a simplification over the earlier "port the `web_sys` WebTransport pump from `scp-transport`" assumption.

**D5 — Move the relay wire types to a wasm-safe home as a behavior-preserving prequel slice.** `ClientMessage`/`RelayMessage` (currently in native-only `scp-transport/src/native/protocol.rs`) move into a wasm-safe home; their sole non-wasm coupling (`serde_bounded_bytes` attribute pointing at `scp_core::serde_util`) re-points to the wasm-safe `scp_protocol::serde_util` re-export it already aliases. Native relay/adapters import the types back (one definition, both targets — the `scp-mls` discipline). A forked wasm-local copy is **rejected** (reintroduces the byte-parity tax ADR-055/057 exist to kill). Sequenced as its own small, revertable corrective slice (T1c-a/b precedent) before the wasm transport code, so the native-import retarget's blast radius is isolated from new-code review.

**D6 — `#1444` (panic=unwind) is a hard prerequisite for the untrusted-relay transport.** The wasm build must be `panic=unwind` and the `scp-mls` `catch_unwind` sites (encrypt.rs, currently inert under wasm `panic=abort`) must become effective before an untrusted relay can feed tampered ciphertext safely — otherwise a tampered blob aborts the tab instead of surfacing a typed `DecryptionFailed`. #1444 lands with or before the transport slice.

## Mechanical guards & cleanups (fold into execution)

- **Bundle-isolation CI check:** build the `@limn-works/scp-ts-wasm` bundle and assert **zero `node:` references** (same category as the wasm-fence / no-shim checks). Physical proof the browser build carries no node code.
- **Per-package dual-package hazard:** each package ships ESM+CJS (already true today); bound the existing `instanceof` hazard *within* each package via an ES-module-wrapper over CJS (Node docs Approach #1) or a single shared-core chunk, plus `"sideEffects": false`. No **cross-tier** guard is needed (D1 rationale).
- **Identity test:** an error thrown by the `scp-ts-wasm` client is `instanceof ContextError` from the same package's core.
- **Stale-comment cleanup:** the shipped TS source/comments describe the ADR-055 remote-thin-client model; update to the ADR-057 in-browser story as part of Slice 3.
- **`#1229` (u64/BigInt):** `scp-client-wasm` returns `u64` (`eventLogLeafCount`, `mlsEpoch`) → JS `BigInt`; reconcile against the TS type declarations in the browser backend.

## Execution notes

- **Sequencing:** (1) D5 wire-types move (prequel corrective slice); (2) D6 panic=unwind + effective `catch_unwind`; (3) `scp-client-wasm` transport as an injected `JsSocket` port + envelope/pseudonym wrapping (pure `scp-protocol`); (4) the `@limn-works/scp-ts-wasm` package (wasm `ScpClient` wrapper + `WebCryptoCustody`/`IndexedDbStorage` + core bundling + bundle-isolation CI); (5) Slice 4 — re-add the two TS browser examples as in-browser-client demos (#1951), restoring the `.docs/specs/21-documentation.md` matrices.
- **Fence:** everything in the wasm tier stays inside the ADR-057 mechanical scope fence (no `scp-runtime`/`scp-identity`/tokio); the 160-method `Bridge` surface is NOT reimplemented — the wasm `ScpClient` exposes only the participant subset (create/join/send/receive/close/queries + the two pure outlet predicates).
- **Issue triage (done this session):** closed 12 ADR-055-era wasm issues (10 moot deleted-bridge, 2 verified-fixed on main); re-scoped #1444 and #1229 as LIVE against the new stack.
