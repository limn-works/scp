---
name: scpout048-wasm-invoker-session
description: SCP-OUT-048 browser-invoker wasm streaming session review — enforcement convergent (NOT blocker); real findings are a zero-value alias + speculative preimage seam
metadata:
  type: project
---

SCP-OUT-048 (branch feat/outlet-xctx-048-wasm-session) review verdict.

**No BLOCKER. Enforcement is convergent/bounded:**
- `out048_ts_invoker_fixture_kat.rs` (196 lines) is a positive byte-identity KAT: re-derives every fixture byte from scp-protocol §5.4.5 primitives + §25.2 RFC-8032 reference key, asserts committed JSON matches. Bounded enumeration (11 chunks 0..10, scalars, keys, one wrong-key chunk). NOT a denylist. Genuine value: cross-language fixture-drift pin — the type system does NOT guarantee a hand-committed JSON fixture still matches current serialization. Operator-signed chunks MUST be produced in Rust (wasm invoker surface is verify-only), so fixture+pin is the right shape.
- KAT guard vs the TS test are NOT redundant: guard pins fixture↔reference-impl byte-identity; TS test exercises the session consumer (decrypt/verify/sequence/terminal/gap/cancel round-trip through a real MLS group). Without the guard a stale-but-self-consistent fixture would still pass the TS test (false confidence).
- check-sdk-coverage.py delta = 4 explicit positive alias entries (BrowserParticipant op → typescript-wasm wrapper). Bounded whitelist.

**4 wasm predicates already well-factored:** sign_credit vs sign_cancel are near-identical in shape but operate on distinct wire types (OutletStreamCredit vs OutletStreamCancel), distinct field sets, distinct domain separators (SCP-OUTLET-CREDIT-V1 / -CANCEL-V1), distinct scp-protocol primitives — NOT collapsible. Shared parsing already extracted into `signing_key_from_seed` / `request_id_16` / `caveats_binding_32`. De-dup done.

**Real findings (both non-blocking):**
1. `caveatsBindingFor` (outlet-stream-session.ts:165) is a zero-value pass-through synonym of `outletStreamComputeCaveatsBinding` — identical arity/order/types/return, both public exports. Delete; callers use the existing export.
2. The two preimage predicates `outlet_stream_compute_credit_preimage` / `_cancel_preimage` (+ TS wrappers + matrix rows + coverage aliases) are NOT in OUT-048 AC (AC-2 requires the *sign* predicates only) and have NO production consumer — only tests. Documented as a "#1980-forward WebCrypto seam" (future browser-custody-signing slice). YAGNI/speculative public surface — orchestrator should confirm #1980 is a committed near-term slice or defer.

Minor: SCP-OUTLET-6100 overloaded across 4 semantically distinct conditions (grant-after-close, cancel-after-close, concurrent-drain, closed-without-End); duplicated closed-guard in grantCredit/cancel.

**ROUND-2 (HEAD 8ac118069, fix delta 4cdc78a89..8ac118069) — SHIP, all resolved, no new bloat:**
- caveatsBindingFor DELETED (grep-clean, re-export gone, session caveatsBinding doc repointed to outletStreamComputeCaveatsBinding). RESOLVED.
- Cancel path removed ENTIRELY via Option-A (not implemented): cancel() method, sign_cancel + compute_cancel_preimage Rust predicates, TS wrappers, and the 2 BrowserParticipant cancel alias rows all deleted. Net simplification, no orphaned helpers/dead branches. Only credit-side kept (in-scope). This SUPERSEDES the round-1 "keep cancel preimage as #1980 seam" — cancel is node-delegated (§5.4.5 next_seq = runtime cursor); gap surfaces StreamGap 6131 + node credit-stall reclaims.
- credit-preimage seam KEPT (only credit is in scope) + now golden-pinned: KAT re-derives via compute_credit_sig_preimage, asserts creditPreimageHex. Bounded compute+compare pinning a cross-SDK byte contract (closes "sign & compute share a builder → both drift together" blind spot) — NOT a re-check of a compile-time guarantee. Convergent.
- Credit newtype (credit.ts, 62 lines): minimal mirror of native Credit; reimplemented-not-imported to keep node: out of browser bundle (node-free guard), rationale documented. Proportionate.
- named-options wrappers (OutletStreamSignCreditParams / CreditPreimageParams): TS interfaces destructured to internal positional wasm calls — eliminates the adjacent-same-typed swap footgun. Clean.
- WeakMap live-consumer guard (SCP-VALID-7028): const module-level WeakMap<client, Set<contextId>>, auto-GC, claim released in #markClosed. Positive registry (not a denylist), simplest correct idiom for tagging a foreign object; mutable-globals concern preempted (const binding, browser tier). NOT over-engineered.
- #throwIfClosed(action): used 2× in grantCredit (TOCTOU before+after await open). Genuine minor dedup.
- SCP-VALID-7027 for concurrent re-entrant drain (was overloaded into 6100): IMPROVES taxonomy — separates caller-misuse from lifecycle-closed. 6100 now only 2 related lifecycle uses. Good call.

**ROUND-3/4 FINAL (HEAD 4d54f107c, rebased) — SHIP, definitive merge gate. No BLOCKER, no new bloat:**
- Disposal surface = 4 entry points (close(), return() [AsyncIterator hook], [Symbol.asyncDispose] [`await using`], [Symbol.dispose] [`using`]) all 1-2 lines deferring to idempotent #markClosed. TEXTBOOK single-source-of-truth + thin protocol adapters; each covers a DISTINCT ECMAScript lifecycle mechanism, minimal complete set (class MUST release to avoid the 7028 live-consumer lockout leak). NOT bloat. 7027→7029 renumber (7027 was already Governance in error_codes.rs).
- assertGrantU32 (client.ts:607) = proportionate 4-line positive range check [1,2**32); guards the 2 RAW predicate entries (outletStreamSignCredit / computeCreditPreimage take `grant: number`). NOT a redundant type re-check: wasm-bindgen SILENTLY coerces/truncates/wraps an out-of-range JS number to u32 — this fills the exact residual the Rust u32 type cannot reach across the FFI boundary (signing a wrong grant = economic bug). Distinct surface from the branded Credit (session path). Same [1,2**32) rule in credit.ts:52 is intentional cross-tier parity, guards a different surface — do NOT consolidate (would couple predicate module to Credit class).
- Caller-seed zeroize REMOVED (R4-2 64f9330d8): net simplification; correct per caller-owned long-lived-identity-key model; #markClosed no longer touches the seed, doc note at lines 137-147/279-281. Supersedes the R3-1 "best-effort zeroize" which was added then removed.
- error_codes.rs +VALID_7025/7026/7028/7029 = bounded closed central registry (positive prose entries), NOT a growing denylist.
- Residual (pre-adjudicated, non-blocking): outletStreamComputeCreditPreimage persists as #1980-forward WebCrypto seam, still no prod consumer (tests only) — accepted round-2 as KEPT + golden-pinned.
