---
name: scp-ts-wasm-pr2183-audit
description: Round-F double-zero audit of PR #2183 (@limn-works/scp-ts-wasm browser SDK, ADR-057 Slice 3) — verdict SHIP, verified evergreen facts
metadata:
  type: project
---

# PR #2183 scp-ts-wasm — Round-F verdict: SHIP (2026-08-01)

Held to double-zero because reviewers previously missed a non-uniform crash-consistency data-loss bug. That bug class is now EXPLICITLY and faithfully covered.

**Why:** confirmation pass on the browser wasm TS SDK. **How to apply:** future SCP wasm-tier reviews can trust these verified boundaries; re-verify only if the cited code changes.

## Verified load-bearing facts (evergreen)
- **Write-behind prefix is airtight.** `indexeddb-storage.ts` prefix = FIFO chain + sticky poison. Every op routes through `.then(() => { if #chainPoisoned return; #runOp })`; the poison flag is set in the faulting op's `.catch`, and the next op's `.then` is chained AFTER that catch, so poison is always observed before any later op runs. No other path reaches `#runOp`. Non-uniform fault (put faults, later delete would succeed) cannot create a gap.
- **The non-uniform test is faithful** (`indexeddb-storage.test.ts` "strict PREFIX" test). It seeds key K, faults ONLY the first readwrite tx, issues put(new)+delete(K), then reopens and asserts K SURVIVED. If the poison gate broke, delete(K) would run (arm already reset) and remove K → test FAILS. This is a real regression guard for the missed bug class, not a uniform-fault convenience.
- **wasm storage boundary is UAF-safe.** `scp-client-wasm/src/storage.rs` extern `set(value: Vec<u8>)` BY VALUE → wasm-bindgen marshals an owned Uint8Array copy detached from wasm linear memory, NOT a `&[u8]` subarray view. This is what makes both IndexedDbStorage mirror and InMemoryStorage safe to RETAIN bytes across later wasm calls (memory growth would detach a view). Deliberate, documented (lines 130-132).
- **`testing` feature gates ONLY DID-format acceptance** — scp-mls/credential.rs:97-99 accepts did:key/did:test prefixes; scp-did/lib.rs:154 decodes did:key hex. Crypto/MLS/storage/transport bodies byte-identical test-vs-prod. So the real-wasm e2e (built --features testing) faithfully exercises shipped method bodies.
- **CI path filter EXACTLY matches** `cargo tree -p scp-client-wasm -e no-dev` closure (client, client-wasm, clock, crypto, did, event-log, mls, protocol, relay-client). No masked-break gap.
- **Guards sound/bounded:** check-release-only asserts the SAME argv `buildArgs` runs (single-sourced, --release unconditional). check-node-free = one bounded `node:` scan. coverage: typescript-wasm is iterate-only OPTIONAL tier, NOT in expected_sdks — additive, can't hide core-tier gaps.
- **Relay mock faithful** (test-relay.ts) — dumb pipe, self-echo included, subscribed-at-publish-time, drives REAL WasmScpClient. Manual pump models eventual delivery.
- **Custody honest:** WebCryptoCustody #1980 seams (sign/dhAgree/etc.) FAIL CLOSED loudly, not fabricated. e2e passes with stubCustody whose sign() throws → proves driver only calls did().

## Non-blocking notes carried forward
- WebCryptoCustody NAME implies WebCrypto key storage but MLS signing key still lives in scp-mls (wasm linear memory, extractable) until #1980. Release notes MUST state on-device non-extractable custody is not yet in effect. MEDIUM doc-honesty, not a false code guarantee.
- Marshalling (client.ts) leaks a wasm wrapper if a getter throws mid-construction (bounded linear-mem leak, not UAF). LOW.
- Pump catches wasm TRAP same as Rust panic and continues; theoretically continues on a poisoned instance. Driver returns Results, so defense-in-depth. LOW.
