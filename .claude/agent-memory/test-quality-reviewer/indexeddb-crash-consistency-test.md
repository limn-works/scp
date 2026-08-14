# TS-wasm IndexedDbStorage crash-consistency regression test (PR #2183)

File: `bindings/typescript-wasm/tests/indexeddb-storage.test.ts`
Adapter: `src/adapters/indexeddb-storage.ts` (ADR-057 T2 sync-facade-over-async-mirror).

## Good pattern: non-uniform fault + reopen-reads-durable-truth
The "NON-UNIFORM fault keeps the durable store a strict PREFIX" test is a model regression test:
- `firstWriteFaultingFactory` Proxies IDBFactory so ONLY the first `readwrite` tx throws (self-disarms `arm.failFirstWrite=false`). Models quota-put aborts / later delete would succeed. Deterministic (FIFO microtask chain, no timers/randomness).
- Fault scoped to `readwrite` so the readonly `#preload` during `open()` is immune; arm is flipped true AFTER open, and seed/reopen use the RAW factory. No risk of faulting the wrong tx.
- The load-bearing assertion reads durable truth via a FRESH `open()` (reopened.get), NOT the poisoned instance's diverged mirror. Correct recovery modeling.
- Self-checking against false-green: assertion (a) requires the fault to have surfaced (`toThrow(/non-uniform/)`), so a silently-broken injection fails rather than green-passes.

## Two distinct discriminators (verified against old code b9c5e0a29^)
Old code: `#throwIfFaulted` surfaced-once-then-CLEARED, and `#enqueue` had no poison gate.
- Assertion (c) set-still-throws → guards STICKINESS (old code cleared fault on first read → (c) fails).
- Assertion (b) reopened keep survives → guards the POISON GATE (old code ran the delete → keep deleted → (b) fails).
Each of the three assertions targets a separate part of the fix; none vacuous.

## Minor finding — RESOLVED @0c8545e13
The DRY dup is now collapsed to ONE `faultingFactory(real, shouldFault: (txArgs)=>string|undefined)`. Re-verified at final HEAD: consolidation preserved discriminating power — uniform test passes `()=>arm.fail?msg:undefined`; non-uniform passes an arg-inspecting `args[1]==="readwrite"` self-disarming predicate. No assertion weakened.

## Round F — WHOLE-SUITE final confirmation (PR #2183, HEAD 0c8545e13): CLEAN
Reviewed all 7 test files + adapters + storage.rs/client.rs/error.rs diff + CI.
- `e2e-exchange.test.ts`: REAL two-party over REAL `--features testing` wasm (load-wasm.ts feeds test-build BYTES to PROD glue via initScp; NO WasmScpClient mock). `support/test-relay.ts` FAITHFUL: real MessagePack ClientMessage/RelayMessage, routing_id-hex subscription table, deliver-to-all-incl-publisher self-echo (exercised: alice's own echo dropped), pump() iterative cascade w/ loud non-convergence bound. Convergence proven at crypto level (byte-identical leaf hashes, equal roots, leafHashes.length===2*32, epoch>=1). Cannot green-pass bypassing relay (bobEvents.length===1 fails if relay inert). Not a loopback — prior transport-slice failure mode ABSENT.
- websocket + web-crypto-custody unit tests: meaningful. websocket reconnect uses real setTimeout (sleep 30 vs delay 5 → LOW flakiness); close()-disables-reconnect is proper wait-to-confirm-absence. web-crypto #1980 seams fail CLOSED (throw, not fake-success) — matters under no-nullifier tenet. `crypto` injection seam real (adapter opt line 52).
- No false green in CI. LOCAL-ONLY foot-gun: load-wasm.ts:47 rebuilds test wasm only if ABSENT (existsSync) → stale cached wasm masks local Rust edits. CI immune (fresh checkout@v5, tests/.wasm-test/ gitignored, path-dep filter covers full scp-client-wasm closure).
- Low observations: (1) smoke.test.ts:9-21 inline stubCustody duplicates support/stubs.ts (import instead); (2) reconnect-resume + IndexedDbStorage-through-real-driver not covered e2e (unit-covered; acceptable).
