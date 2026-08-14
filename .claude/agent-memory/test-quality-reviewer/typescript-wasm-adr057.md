---
name: typescript-wasm-adr057
description: Test patterns and coverage notes for bindings/typescript-wasm (ADR-057 browser SCP client, PR #2183)
metadata:
  type: project
---

# bindings/typescript-wasm test suite (ADR-057, PR #2183)

Bun test runner. 20 tests / 5 files. Runs against REAL compiled `scp-client-wasm`
(built `--features testing` into `tests/.wasm-test/`), never a hand-mock of WasmScpClient.

## Genuinely strong patterns (replicate)
- **e2e-exchange.test.ts**: real two-party (alice+bob distinct wasm clients) over a
  shared faithful MessagePack `TestRelay` (mirrors Rust `scp-relay-mock`). Payload
  equality after cross-client MLS decrypt proves it is NOT a loopback. Self-echo drop
  is load-bearing-asserted (aliceEvents length == 1). Relay subscription routing is
  load-bearing (unsubscribed → empty → fail). §9.16 sender-key dists delivered
  out-of-band via receiveMessage (disclosed simplification; ciphertext still real-wasm
  produced+consumed). Error path (SCP-CTX-2001) originates in real wasm — wrapper
  sendMessage just delegates through `call()`, no pre-check.
- **indexeddb-storage.test.ts**: both regression tests DISCRIMINATE against pre-fix prod.
  Uniform fault → flushed() rejects (needs sticky #pendingFault capture). Non-uniform
  (put faults, later delete would free space) → poison gate skips delete → durable store
  stays strict PREFIX; without `#chainPoisoned` gate the delete lands → gap → reopen sees
  keep deleted → test fails. faultingFactory Proxy over IDBFactory is a clean fault-injection seam.

## Coverage gap (Low)
- websocket-relay-socket.ts:188-198 — the `WebAssembly.RuntimeError` fatal-trap branch
  (route to onError + close() + disable reconnect) has ZERO tests. All 6 socket tests use
  regular Errors. Correct by inspection, no false-green, but the Round-F-added fatal path
  is untested. A test delivering a frame whose onFrame throws WebAssembly.RuntimeError,
  asserting close() fired + no reconnect, would close it.

## Disclosed residual (observation)
- websocket "onopen re-sends tracked subscriptions" test uses a stand-in onOpen
  (`() => socket.send(subscribe)`), NOT client.resubscribeAll. Proves transport re-fires
  onOpen on reconnect + send targets the new socket; does NOT prove client tracks+replays
  real subscriptions over a live relay reconnect. Explicitly disclosed as e2e gap.
- Reconnect tests use real setTimeout (sleep(30) vs 5ms delay) — 6x margin, Low flake risk.
