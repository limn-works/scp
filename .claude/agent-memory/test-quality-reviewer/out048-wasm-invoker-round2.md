---
name: out048-wasm-invoker-round2
description: SCP-OUT-048 TS-wasm browser-invoker streaming session — round-2 + round-3 verification, SHIP @755ee122c
metadata:
  type: project
---

# ROUND-3 (@755ee122c) — all 3 round-2 gaps CLOSED genuinely. SHIP. 31 pass/0 fail (10 in this file).

All 3 weak/untested items from round-2 (below) are now closed with discriminating, non-tautological tests:
- **R3-4 multi-chunk-single-frame 6110 (:550)** — KEYSTONE fix for the #pending.length=0 clear. Pre-decrypts a VALID seq-0 frame via `invoker.handleRelayFrame(validFrame)` so its MessageReceived event is BUFFERED (handleRelayFrame buffers; only drainEvents clears — confirmed by buildPair:291 clearing setup events post-settle). Then session's first next()→#ingestFrame(wrongKeyFrame) does one drainEvents() returning BOTH events FIFO: valid pushed to #pending, wrong-key fails verify in SAME loop → clears #pending, markClosed, throws 6110. Batching is STRUCTURALLY guaranteed (session's first ingest is first drainEvents; nothing drains between :577 and it). MUTATION (static): remove `#pending.length=0` (session:561) → final `next()` line 604 sees #closed && #pending.length==1 → shifts+returns {done:false,value:validChunk} instead of {done:true} → FAILS. Genuinely load-bearing, NOT tautological. The single-chunk 6110 (:519) remains non-discriminating for the clear (round-2 finding confirmed correct).
- **R3-6 7028/7029 code pins (:610,:640)** — 7028 test now catches + asserts `.code==="SCP-VALID-7028"` (was only .toThrow class). NEW 7029 re-entrant-drain test: `first=session.next()` sets #draining=true synchronously before its first await (session:432 before :434), then `reentrant=session.next()` synchronously hits the #draining guard (:421)→rejects 7029. MUTATION: remove #draining guard → reentrant pollNext→null→resolves {done:true} not reject → FAILS. Load-bearing.
- **R3-7 terminal-Error aggregate + no-End 6100 (:669,:721)** — Error test builds a REAL terminal Error chunk via new signOperatorChunkWire helper (WebCrypto Ed25519 sign under RFC8032-TV1 operator seed 9d61b19d…, mirroring Rust sign_chunk preimage SCP-OUTLET-CHUNK-SIG-V1). SELF-VALIDATING KAT: on-device wasm verify accepts it ONLY if TS preimage == Rust byte-for-byte; a mismatch → 6110 thrown, failing the `code:6130` assert. So it CANNOT vacuously pass. aggregate() rethrows typed OutletError w/ chunk's code+message; idempotent 2nd call re-throws cached #error. errorPayload key order (@type,code,message,terminal) already == JCS sorted order so JSON.stringify==JCS. no-End test: pollNext→null immediately → aggregate hits session:509 → throws 6100 asserted DIRECTLY (not .catch-swallowed). Both genuine.

signOperatorChunkWire helper is a legit test-double (operator's role), doubles as cross-target KAT. No new tautologies. VERDICT: SHIP.

---

# SCP-OUT-048 browser-invoker streaming — round-2 verification (@8ac118069, branch feat/outlet-xctx-048-wasm-session)

# SCP-OUT-048 browser-invoker streaming — round-2 verification (@8ac118069, branch feat/outlet-xctx-048-wasm-session)

VERDICT: SHIP. All round-1 test asks met with genuine (non-tautological) tests.

Files: bindings/typescript-wasm/tests/outlets-streaming-invoker.test.ts (6 tests),
tests/fixtures/outlet-stream-invoker-kat.json, crates/scp-client-wasm/tests/out048_ts_invoker_fixture_kat.rs.

**Why:** AC3 was UPDATED (story, one-way flow) so browser-initiated cancel is now OUT OF SCOPE — no cancel signing predicate in wasm, NodeStreamCoordinator has no cancel port (only open/grantCredit/pollNext). So "no cancel routed on gap" is a STRUCTURAL guarantee (type has nothing to call), not an assertion. Cancel signing exports fully removed; grep for outletStreamSignCancel/computeCancelPreimage = empty; removed test "a signed OutletStreamCancel verifies…" gone cleanly.

**Credit golden-pin (round-1 FIX-med) — GENUINELY closes the blind spot.** creditPreimageHex is a COMMITTED constant. Rust KAT out048_...rs:135-144 RE-COMPUTES compute_credit_sig_preimage from scp-protocol and assert_eq!s the committed hex (re-derive, not re-read). TS test:264-279 computes via wasm compute wrapper → asserts ==golden(276), then WebCrypto (INDEPENDENT ed25519) verifies the real outletStreamSignCredit sig over that golden preimage(278). Transitive chain: wasm-sign-preimage ==(via WebCrypto verify) wasm-compute-preimage ==(276) golden ==(Rust KAT) scp-protocol. Same-builder drift now forces a visible committed-hex change + fails one of the two asserts unless fixture regenerated in lockstep. Maximal closure a golden can give.

**Load-bearing confirmations (would FAIL on regression):**
- 6131 gap test (:378): [0,1,3], asserts throws 6131 + seen==[0,1] (chunk 3 NOT yielded). Strong. If gap check deleted → seen==[0,1,3], no throw → fails.
- in-session 6110 (:426): wrong-key chunk through REAL MLS decrypt + real wasm verify → next() rejects 6110. If verify bypassed → resolves value → fails. Passing control = round-trip test(:204) + predicate test part-c(:344).
- Credit validation(:304): new Credit(0/-1/3.5/2**32) throw InvalidGrant, Credit(4).value==4. Real boundary test.
- 7028 dedup(:457): 2nd session on same (client,ctx) throws; after drain-to-terminal releases WeakMap claim, 3rd constructs. markClosed release IS discriminated.

**NON-discriminating / weak asserts (note, NOT blocking):**
- Both 6131 and 6110 tests assert `next()==done` as "#pending cleared" proof, but in BOTH the offending chunk was already shift()'d and each frame delivers exactly ONE event, so #pending is EMPTY when the throw fires. The #pending.length=0 fix lines (425/521) are present but NOT discriminated by these tests — even without them next() returns done (frame queue exhausted → pollNext null → done). The actual round-1 bug-catcher MED (multi-chunk-in-one-frame: chunk N pushed, N+1 fails, N left buffered) is UNTESTED — no test delivers 2+ events in one ingestFrame where first verifies + second fails.
- 7028 test asserts .toThrow(ValidationError) not the 7028 code specifically — but 7028 is the only ValidationError possible at construction, so effectively discriminating. Could pin code.

**Remaining untested (coder skipped as transitive):**
- aggregate() on a terminal ERROR chunk (session.ts:438-443 + 465 #error rethrow): GENUINE gap — fixture has no Error chunk. Low ROI (path simple).
- no-End 6100 + pollNext-null: EXECUTED in 7028 test's `first.aggregate().catch(()=>{})` (pollNext null → markClosed → done → aggregate throws 6100) but the .catch swallows without asserting the code. Path runs, code unasserted. Acceptable.

Positives: real 2-party MLS (operator+invoker ScpBrowserClient over TestRelay), chunks are §25.2 RFC8032-TV1 KAT re-derived byte-for-byte in Rust, deterministic settle() (no sleep), no shared mutable state.
