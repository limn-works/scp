---
name: out048-wasm-invoker-cancel-nextseq-defect
description: SCP-OUT-048 browser-invoker streaming session — SHIP WITH CONDITIONS; the OutletStreamCancel next_seq is bound to the receiver cursor, violating §5.4.5:203 (must be runtime emission cursor, never caller-supplied). Everything else sound.
metadata:
  type: project
---

# SCP-OUT-048 WASM browser-invoker streaming session — audit

## DEFINITIVE FINAL (HEAD 4d54f107c, post-rebase onto main 3c1631316): SHIP, 0 blockers.
Rebase content-inert: all 16 slice files BYTE-IDENTICAL between reviewed 951d7cba4 and rebased 4d54f107c (`git diff 951d7cba4 4d54f107c -- <files>` empty); merge-base == current main HEAD (clean linear rebase). Round-4 delta sound line-by-line: R4-1 asyncDispose→`async Promise<void>` + sync `[Symbol.dispose]` (fixes TS2851 for `await using`; both defer to idempotent #markClosed). R4-2 REMOVED caller-owned seed `.fill(0)` from #markClosed — CORRECT: seed is invoker's long-lived identity key, mutating breaks reuse for a 2nd session; wasm-side transient zeroize (signing_key_from_seed lib.rs:1060-1067, both paths) is the load-bearing scrub, intact. R4-3 4 non-vacuous release-path/guard tests (return/close/`await using` each prove claim-release by reconstructing on same pair w/o 7028; grantCredit non-Credit → InvalidGrant before lazy open). R4-4 `assertGrantU32` on both raw predicates ([1,2^32) non-zero int, before wasm call) = native Credit parity. Cancel removal still complete (grep: only prose). grantCredit: instanceof guard + double #throwIfClosed TOCTOU + validated .value. Re-ran on rebased tree: bun 15/15 pass 0 skip (3 exercise real wasm), error-codes gate PASS (4251, 7029/7010 registered), Rust KAT re-derives byte-exact. Non-blocking residuals unchanged (spec :515 text #2204).

## FINAL VERDICT (HEAD 755ee122c, slice-3 completion): SHIP.
Round-1 DOA blocker RESOLVED via Option A — browser OutletCancel signing surface REMOVED entirely (no session.cancel(), no coordinator cancel port, no sign_cancel predicate, no dangling export; PRD AC now enforces removal via negative grep `outlet_stream_sign_cancel`→nothing). Gap path surfaces StreamGap(6131) with NO cancel routed; node-side credit-stall/timeout reclaims. Browser cancel deferred #2203; §5.4.5:515 spec clarification #2204.
Verified this pass: Rust KAT re-derives every fixture byte & PASSES; 10/10 TS tests PASS (43 expects); wasm32 build succeeds (fence mechanical — only `zeroize` added, all scp_runtime refs are comments). Credit signing reuses KAT-pinned scp-protocol sign_credit_grant (all 7 fields bound); Credit newtype validates [1,2^32); monotonic_seq atomic strictly-increasing; credit preimage cross-target golden-pinned (closes sign/compute drift blind spot). WeakMap guard airtight (claim added after throw-check, released in #markClosed from all terminal paths + close/return/asyncDispose; test 7028 verifies release-then-reconstruct). Multi-chunk-single-frame 6110 test genuinely exercises #pending clear. Seed zeroize real (wasm Vec per-call both paths; JS seed at close). error-code delta clean (7028/7029 avoid 7027 governance collision).
Non-blocking residuals: (1) LOW raw outletStreamSignCredit({grant:number}) unguarded — wasm-bindgen coerces OOR to u32; session grantCredit(Credit) is the guarded surface + node bounds via checked_mul/InsufficientFunds. (2) LOW session throws 6110 (authorization.denied family) for operator chunk-SIG-verify fail (a msg-auth failure, not invoker-authz denial); retry=Never correct, msg clear; taxonomy underspecs it. (3) MEDIUM process: spec :515 text still literally says drain "cancels via the signed OutletCancel path" — browser can't/doesn't; tracked #2204 but spec text not yet amended.

# (round-1, HEAD 4cdc78a89 — historical)

Verdict: **SHIP WITH CONDITIONS**. One HIGH cross-layer/DOA blocker on the cancel surface; open/credit/chunk-verify/decrypt are all sound.

## The blocker (HIGH, DOA-class): cancel `next_seq` = receiver cursor
- `outlet-stream-session.ts:306` `cancel()` binds `BigInt(this.#expectedSequence)` (the RECEIVER-side consumed cursor) into the `SCP-OUTLET-CANCEL-V1` preimage.
- `types.ts` documents it explicitly: `OutletStreamCancel.nextSeq` = "The receiver-side cursor at which the invoker cancelled the stream." So it is a *deliberate documented* semantic, not a typo.
- §5.4.5:203 (specs/05-contexts.md) is unambiguous: next_seq MUST be the **runtime's next-to-emit (emission) cursor**, read from live runtime state, **"never a value supplied by the caller."** Caller-forged next_seq = billing forge (0 nullifies billing of delivered chunks; u64::MAX over-bills).
- The node's only apply path, `dispatch.rs:1179 apply_outlet_cancel_verbatim`, cross-checks `cancel.next_seq != guard.next_emission_seq` → `CancelError::CursorAdvanced` (NO mutation). It is currently **dead_code** (cross-context forwarding caller lands "a later chunk").
- Browser architecturally **cannot** know the node's emission cursor (executor pump is node-side; NodeStreamCoordinator has no cursor-fetch). Receiver cursor == emission cursor only with zero in-flight chunks; a realistic mid-stream cancel (credit_window default 32 ahead) mismatches → when wired, the cancel is REJECTED = "a cancel that doesn't actually cancel." If instead the node is made to accept the caller value, it reopens the exact forge §5.4.5:203 + round-7 closed.
- The PRD's own CRITICAL #3 said cancel is "N/A for WASM (no session/cancel per ADR-057)" — OUT-048 adds the session+cancel anyway, breaking that assumption without a spec carve-out (no "browser" cancel provision exists in §5.4.5).
- Tests HIDE it: the cancel test (`outlets-streaming-invoker.test.ts:292`) uses a fresh session (0 consumed → next_seq=0) and a mock `cancel: async () => {}` that swallows the wire — it asserts only that the SIGNATURE verifies, never that the cancel achieves cancellation against a node with an advanced cursor.
- Fix options: (a) drop the browser cancel surface from this slice (defer with node-side cross-context cancel wiring that has correct cursor provenance), or (b) add an authoritative cursor-fetch to NodeStreamCoordinator + spec the cross-context cancel cursor provenance (mind the TOCTOU that motivated runtime-local derivation).

## Secondary
- MEDIUM: `grantCredit(grant: number)` has NO range/integer validation; wasm-bindgen silently ToInt32-coerces negative/fractional/overflow u32 (grant=-1 → 4.29e9). OUT-038 mandates InvalidGrant throw for 0/negative/>=2^32; browser session ignores it. Bounded by node escrow (checked_mul/InsufficientFunds) but a footgun + cross-SDK inconsistency.
- LOW: session holds `invokerSigningSeed` for its whole lifetime, never zeroized on close (consistent with sanctioned key-on-device posture, but no dispose).
- LOW: test file named `outlets-streaming-invoker.test.ts`; ACs name `outlet-streaming.test.ts` (intent met, literal mismatch).
- LOW: session-layer sequence-gap detection (`next()` 6131) implemented but untested in this file.

## What is genuinely sound (verified, do not re-litigate)
- Fence holds MECHANICALLY: no scp-runtime/scp-identity/tokio dep (Cargo.toml adds only ed25519-dalek [already transitive] + zeroize); all 5 "scp_runtime" hits in lib.rs are comments. AC#5 grep clean (no saga/pump/seal/escrow/receipt symbols).
- Crypto REUSED from KAT-pinned scp-protocol (sign_credit_grant/sign_cancel/compute_*_preimage/verify_* pre-exist on base 8658f1afe; stream.rs untouched this branch).
- Cross-target KAT guard `out048_ts_invoker_fixture_kat.rs` re-derives EVERY fixture byte from scp-protocol + §25.2 ref keys, fails loudly on drift — genuine, passes.
- Data-plane round-trip test is REAL: operator→relay→invoker over real MLS + real wasm, on-device decrypt+verify of 10 Data + End; credit sig verified via WebCrypto over recomputed preimage. 3/3 pass, not vacuous.
- Credit preimage binds (context,outlet,request,grant,monotonic_seq,stream_epoch,caveats_binding) → sound anti-replay/anti-cross-stream/anti-cross-epoch. Wrong-epoch + wrong-key negatives are real.
- Zeroize is HONEST: labeled non-load-bearing best-effort; matches ADR-057 §Consequences "As-built caveat (Slice 3)" sanction; seed zeroized both paths; ed25519-dalek SigningKey is ZeroizeOnDrop. NOT a rug.
- monotonic_seq auto-assigned strictly-increasing per session (#creditSeq, JS run-to-completion makes sign+increment atomic; gaps OK, node rejects dup/regress). No over-credit from browser side.
- Matrix rows real (typescript-wasm:true, others false+exemptions); coverage aliases resolve to real exported symbols.
