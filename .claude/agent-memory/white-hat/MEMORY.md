# White Hat Agent Memory

## Recurring weaknesses in this codebase
- A check-then-act sequence split across a lock release (nonce replay, standing channels, budgets) is a TOCTOU race; the check and the mutation belong under one lock or one actor turn.
- Key material left un-zeroized, or zeroized in one module and not its sibling (a TLS key PEM was zeroized while a bearer secret was not).
- `unwrap_or_default` on serialization or on the system clock turns a failure into a plausible value; return an error.
- Manual string parsing or building where a URL parser belongs (a context name placed in a URI without percent-encoding).
- UCAN validation that parses a token (`parse_ucan`) where it should validate it (`validate_ucan`) checks structure only and admits forged bearer tokens.
- Input validation deleted on the grounds that output is escaped. That is a defense-in-depth regression.
- A global capacity cap with no per-DID sub-cap (a 10,000-entry handle registry) lets one member exhaust the namespace.
- Maps keyed by attacker-chosen identifiers (sender DIDs, per-context economy state) with no capacity bound.

## Invariants to preserve when reviewing a change
- `RevocationPending` counts as revoked (fail-closed).
- A sender-key epoch may advance by at most `MAX_EPOCH_ADVANCE` per step, and the key store enforces monotonicity.
- Access-key request freshness is asymmetric: 300 seconds into the past, 30 seconds into the future (`crates/scp-runtime/src/crypto/access_keys/wire.rs`).
- A key request answers every deny path with one uniform reason, so the response does not reveal the block list.
- A capability check precedes any budget deduction, so a permission failure cannot leak budget.

## TypeScript test-seam defense
`__setBridgeForTests` (`bindings/typescript/src/internal/bridge.ts`) swaps the native bridge. Three layers keep it out of production:
1. `bindings/typescript/package.json` `exports` names only `"."`, so a deep import of `internal/` fails to resolve.
2. `tsup` bundles with `splitting: false` from `src/index.ts`, so anything outside the index export graph is eliminated from `dist/`. After a build, `node -e 'import("./dist/index.js").then(m=>console.log("__setBridgeForTests" in m))'` must print `false`. Adding `splitting: true` or an `./internal` subpath export removes this layer.
3. `assertTestEnvironment` reads `_IS_TEST_ENVIRONMENT` (`internal/test-guard.ts`), which is frozen at import time and reads env keys with `Object.hasOwn`, so neither a later `process.env` write nor prototype pollution flips it. A `NODE_ENV=test` leaked into a production image does open it.
