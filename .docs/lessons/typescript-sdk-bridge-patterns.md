# TypeScript SDK Bridge Patterns

> **ADR-055 (2026-06-29):** the WASM bridge was removed and the TypeScript SDK is now NAPI-only — the browser is served by a remote thin client, not an in-process WASM backend. The "WASM ambient module declarations" section and the WASM-deferral/`@limn-works/scp-ts-wasm` references below are historical (they describe the prior dual NAPI+WASM-fallback backend). The non-WASM TypeScript patterns in this lesson remain evergreen.

Lessons from implementing `bindings/typescript/` (SCP-081).

## exactOptionalPropertyTypes requires conditional assignment

With `exactOptionalPropertyTypes: true` in tsconfig, you cannot write:

```ts
const result = { ...base, optionalField: maybeUndefined };
```

Because `undefined` is not assignable to an optional property. Instead:

```ts
const result: MyType = { ...base };
if (value !== undefined) {
  (result as { optionalField: T }).optionalField = value;
}
```

## AsyncDisposable in object literals needs captured references

`this` inside an object literal method does not reference the object itself.
For `[Symbol.asyncDispose]()` in object literals, capture the object in a
named variable:

```ts
const server: McpServer = {
  async stop() { /* ... */ },
  async [Symbol.asyncDispose]() {
    await server.stop();  // NOT this.stop()
  },
};
```

## WASM ambient module declarations

The `@limn-works/scp-ts-wasm` package (produced by `wasm-pack --target bundler`) does
not ship TypeScript declarations. An ambient module declaration at
`src/internal/wasm-types.d.ts` provides the type surface. The file must be
covered by the tsconfig `include` glob (`src/**/*.ts` matches `.d.ts`).

## Biome node: protocol rule

Biome's `useNodejsImportProtocol` rule requires `"node:module"` not
`"module"` for Node.js built-in imports. This is classified as an "unsafe"
fix, so it requires `biome check --write --unsafe` to auto-apply.

## Bridge runtime detection must be synchronous

The bridge detection function (`detectBridge()`) must be synchronous to
avoid top-level await, which breaks CJS compatibility. Detection checks
`process.versions.bun` and `process.versions.node` — these are available
synchronously in their respective runtimes. WASM initialization is deferred
to the first `getBridge()` call.
