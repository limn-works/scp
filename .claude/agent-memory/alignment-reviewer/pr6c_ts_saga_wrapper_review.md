---
name: pr6c-ts-saga-wrapper-review
description: Alignment review of PR-6c TS SDK slice (#1939) wrapping NAPI toolInvokeCrossContextSaga (§6.2.4) @ a44084299 — ALIGNED, 1 OBSERVATION
metadata:
  type: project
---

# PR-6c TS slice (#1939) — SCP.toolInvokeCrossContextSaga @ `a44084299` (worktree pr6c-ts) — ALIGNED, 1 OBSERVATION

TS slice (2/4) of #1939 / PR-6c wrapping NAPI op `toolInvokeCrossContextSaga` (native = PR-6b #116). Sibling of merged Python slice [[pr6c_py_saga_wrapper_review.md]].

**Why:** verify TS wrapper aligns with §6.2.4 + ADR-049 §3a + NAPI bridge contract + Python-slice parity.
**How to apply:** if this slice resurfaces or Kotlin/Swift slices (3/4, 4/4) land, reuse these verified facts; the OBSERVATION below is the only open hardening note.

## Verified (all PASS)
- **Param order/types** EXACT vs NAPI export scp.rs:2935 (source,target handles / callerDid / toolRegistrationId / inputJson / assertedNonceHex / timestampMs:bigint(BigInt) / chainDepth:number(u8) / ucanProofId?:string(Option)). bridge.ts + native.ts + scp.ts all identical shape.
- **Display formats** match error.rs:127-170 VERBATIM: `[{code}] saga aborted: {message} (retry_after_ms={null|u64})` / `...saga needs repair: {message} (saga_id=…)` / `...saga busy: {message} (contended_context=…)`. retry_after_ms rendered literal `null` when None (never 0) by Display map_or_else.
- **Codes** correct: Aborted code from supervisor SagaError (`format!("SCP-SAGA-{code}")`; generic abort=13067 NOT 13050 specific-membership-reject; 13050 synthesized directly at caller-membership gate), NeedsRepair=13065, Busy=13066 (saga_errors.rs:118/124/132). TS subclass DEFAULT codes (13067/13065/13066) only defensive — mapSagaError ALWAYS passes the parsed code; specific 13050 preserved through SagaAbortedError.
- **mapSagaError datum parse** faithful + decoy-resistant: code regex `/^\s*\[(SCP-SAGA-\d+)\]/` START-anchored; datum regexes `\s*$` END-anchored = last-anchored (decoy `(retry_after_ms=…)` in {message} can't match). Tests prove decoy resistance for all 3 data.
- **retryAfterMs** never null→0: `datum===undefined||datum==="null" ? null : Number(datum)`. ✓
- **Validation** SCP-VALID-7002 BEFORE dispatch (fail-fast): timestampMs non-negative bigint, chainDepth integer 0..255 (u8). PARITY with Python (same code 7002, same bounds). TS needs no bool-guard (bigint type-checked, Number.isInteger) — language-appropriate vs Python's isinstance bool reject. NAPI bridge itself re-validates BigInt get_u64 signed/lossless → VALID_7001 (boundary, different layer — fine).
- **SagaResult** faithful nullable pass-through: receipt/output `?? null` (Buffer=Uint8Array subtype), never synthesized; normalized identically in native.ts bridge AND scp.ts (two consumers of raw native method, consistent — no double-norm bug).
- **block-until-terminal** = native async awaited (TS equiv of Python to_thread-over-block). **SagaId supervisor-minted**: NO saga_id input param; read out-only `output.saga_id.0` (tools.rs:998).
- **Matrix flip** ts-only: typescript false→true + typescript exemption REMOVED; kotlin/swift stay false WITH exemptions intact; alias (bridge-aliases.json category tools) unchanged. No spec drift.
- **No #NNNN in TS source/tests** (matrix JSON #1939 = legit tracking data, prior precedent).

## OBSERVATION (defense-in-depth, non-blocking)
`mapSagaError` PHRASE dispatch uses UNANCHORED `message.includes("] saga aborted:")` etc., checked in order aborted→needs-repair→busy. The DATUM regexes are last-anchored (decoy-hardened + tested), but the phrase substring search is NOT. A {message} body containing literal `"] saga aborted:"` inside a Busy/NeedsRepair terminal would misclassify the CLASS (e.g. SagaBusy → SagaAbortedError) though `.code` is preserved (start-anchored). Inherent to napi-rs collapsing typed SagaError to ONE Display string — Python is structurally immune (dispatches on PyO3 exception `type().__name__`). Low likelihood ({message} internally generated). HARDENING: anchor phrase to immediately follow code prefix, e.g. `/^\s*\[SCP-SAGA-\d+\] saga (aborted|needs repair|busy):/`. Asymmetry worth noting given the project hardened+tested the datum path against decoys but left the phrase path loose.

## LESSON
napi-rs SDK-wrapper-over-typed-error → unlike PyO3 (typed exception classes → structural type+args-tuple dispatch), napi collapses to ONE Display string so the SDK MUST string-parse. Verify: code START-anchored, datum END/last-anchored + decoy-tested, retryAfterMs null-never-0, nullable pass-through `?? null` never synthesized, pre-dispatch validation mirrors sibling Python code+bounds (SCP-VALID-7002), matrix single-lang flip + exemption removed only for that lang, no saga_id input + read out-only. Watch the PHRASE-dispatch-unanchored asymmetry as the napi-specific weak point.
