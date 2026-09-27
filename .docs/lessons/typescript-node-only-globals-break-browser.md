# Node-Only Globals Silently Break Code That Also Runs in a Browser

`Buffer`, `process`, and `setImmediate` do not exist in browsers or edge runtimes, and
referencing one throws `ReferenceError`. `tsc` reports nothing, because `@types/node` declares
them, and every test under Node or Bun passes. `__extractFirstCapabilityUri` in
`bindings/typescript/src/trust.ts` once decoded a JWT with `Buffer.from(…, "base64url")`
inside a `try`/`catch` that returned `null`, so in a browser every token decoded to `null` and
`evaluateLayer1` reported all-false: a verdict that looks legitimate.

## Rules

- On any path more than one runtime runs, treat Node globals as absent. Feature-detect with
  `typeof X !== "undefined"` and fall back to Web APIs: `atob`/`btoa`,
  `TextEncoder`/`TextDecoder`, `crypto.subtle`, `queueMicrotask`.
- Never let a `try`/`catch` turn a `ReferenceError` into a fail-closed value. A missing global
  is a packaging defect, not a data outcome.
- Test the fallback by deleting the global: `bindings/typescript/tests/browser-fallback.test.ts`
  deletes `globalThis.Buffer`, runs the decoder, and restores it in a `finally`. Without such a
  test the fallback is dead code.
- Browser `atob` accepts standard base64, not base64url: map `-`→`+` and `_`→`/` and re-pad
  first.

## Which files the rules bind

Every file that more than one runtime compiles. Today that includes
`bindings/typescript/src/trust.ts`, whose `__decodeBase64UrlToUtf8` has a `globalThis.atob`
branch, and `bindings/typescript/src/errors.ts`, which the browser package
`bindings/typescript-wasm/` bundles through the `@scp-core/errors` path alias in its
`tsconfig.json`, so a Node global there breaks `mapBridgeError` for every browser error.
