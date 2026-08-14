# PR-6c TS SDK saga wrapper + mapSagaError tests

Files: bindings/typescript/tests/{tools.test.ts (saga describe), errors.test.ts (mapSagaError)},
src/{errors.ts mapSagaError, scp.ts toolInvokeCrossContextSaga, types.ts SagaResult}.

## Harness (reusable)
- `mountMockScp()` + `native.__stub(name, fn)` from tests/mock-bridge.ts mounts a Proxy mock
  at SCP construction; the public SCP method calls `this.#native.<name>` DIRECTLY (bypasses the
  Bridge interface / native.ts createNativeBridge). So mock-based tests exercise scp.ts's REAL
  logic (validation guards, try/catch→mapSagaError, `?? null`). Not mock-echo.
- Strict-by-default mock: unstubbed inspectable method THROWS (cryptographer M-1). So a
  validation-reject test that doesn't stub the saga proves validation fired BEFORE native dispatch
  (else it'd throw the distinct "unstubbed" error, not ValidationError).
- native.ts createNativeBridge.<op> is DEAD duplicate for mock tests (only e2e-relay/real-napi
  real-addon tests hit it). Duplicated `?? null` normalization lives in BOTH scp.ts and native.ts.

## Mutation results (10/12 killed) — exemplary anchors
- KILLED: end-anchor `\s*$` on each datum regex (decoy-last-anchor tests), null→0, phrase
  dispatch corruption, u8 bound 255→254, timestamp 0n→-1n, DROP `typeof!=="bigint"` guard
  (non-bigint 123 test), receipt `?? null` removed, chainDepth `<0`→`<-1`.
- The decoy tests (`(retry_after_ms=999) … =2500` → 2500) are the gold-standard end-anchor proof.

## TWO SURVIVING MUTATIONS (the recurring gap shape: asymmetric/parity coverage)
- M9 SURVIVED: `output: raw.output ?? null` — receipt-omit IS tested, output-omit is NOT.
  Asymmetric null-normalization coverage. Fix = one test omitting output.
- M12 SURVIVED: saga guard `Number.isInteger(chainDepth)` — saga describe tests 256 & -1 but
  never a fractional 1.5; the NON-saga toolInvokeCrossContext describe DOES test 1.5. Parity gap.
- LESSON: when a wrapper normalizes/validates two symmetric fields (receipt+output) or shares a
  guard with a sibling method, grep that BOTH halves / the fractional case are pinned. Mutation-
  survives-on-the-very-invariant-the-doc-calls-load-bearing = Revise even when code is correct.

## No flakiness; brittleness intentional
- Display-string format asserts pin the Rust ScpNapiError wire contract (like PreRotation code
  tests) — should break on Display drift. Minor: no co-location comment to Rust source (PreRotation
  block has one). Pure/deterministic; afterEach shutdown(1)=safe mock no-op.
