# @limn-works/scp-ts-wasm — vetted browser SDK package (ADR-057, PR #2183)

Browser wasm-tier TS SDK. APPROVED at Round F double-zero 2026-08-01.
Round H (2026-08-01, HEAD d8023440b) re-confirmed at 0c8545e13→d8023440b: post-approval
batch was docs (Rust core error.rs/client.rs/storage.rs = comment-only, no behavior change;
TS doc reframes ADR-055→057), marshalling/pump/test polish, LICENSE files added to BOTH
typescript + typescript-wasm, `"license":"Apache-2.0"` added to typescript/package.json.
ZERO new dependencies. `dependencies:{}` still empty. Pre-release (v0.1.0) → no migration.

## Vetted deps (all devDependencies; `dependencies:{}` is correct)
- Runtime deps: NONE. Only external src/ import is `@scp-core/errors` (tsconfig path
  alias → `../typescript/src/errors`, BUNDLED by tsup, not a node_modules pkg).
  So the self-contained/bundled-core design (ADR-057 Amendment D1) holds.
- `@msgpack/msgpack` ^3.0.0 — TEST-ONLY (tests/support/test-relay.ts). Not bundled,
  not shipped. Correct placement.
- Pinned exact (good): @biomejs/biome 2.5.5, tsup 8.5.1.
- Caret dev-only (fine): @types/bun, @types/node, fake-indexeddb, typescript.
- wasm-pack pinned 0.14.0 in BOTH .mise.toml and CI (reproducible release-only build).

## Publish hygiene (all correct)
- `files:["dist/","README.md","LICENSE"]` — whitelist; no src/tests/scripts/secrets ship.
- ESM+CJS dual (main=.cjs, module=.js, types=.d.ts, exports map). tsup `shims:true`
  polyfills import.meta.url for the CJS wasm `new URL()` load.
- .wasm NOT bundled by esbuild — copied into dist/ by scripts/copy-wasm-asset.ts
  (runs after tsup). guard:node-free excludes .wasm from its text scan.
- LICENSE present (Apache-2.0). No .npmrc/.env. No hardcoded secrets.

## CI gate (genuinely gates)
- Job `typescript-wasm-check` in ci.yml: in BOTH `needs:` of the `ci` roll-up AND
  the `results` array. Roll-up fails only on failure/cancelled; skipped passes.
- Path filter = exact `cargo tree -p scp-client-wasm -e no-dev` closure (9 scp crates:
  client-wasm, client, mls, crypto, did, clock, protocol, event-log, relay-client)
  + bindings/typescript-wasm/** + bindings/typescript/src/errors.ts (the bundled core).
  Verified `--features testing` adds NO extra scp crate, so filter covers test build too.
