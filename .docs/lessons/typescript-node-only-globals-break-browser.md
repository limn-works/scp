# Node-Only Globals Silently Break Cross-Environment Code Paths

**Problem**: TypeScript utility code compiled for cross-environment use references Node
globals — `Buffer`, `process`, `setImmediate` — that the browser and edge runtimes do not
provide, and referencing one throws `ReferenceError`. The compiler does not catch it:
`Buffer` is a valid ambient type in any project carrying `@types/node`, so browser-only
breakage passes `tsc` and every test that runs under Node or Bun.

`__extractFirstCapabilityUri` in `bindings/typescript/src/trust.ts` decoded a JWT payload
with `Buffer.from(segment, "base64url").toString("utf8")` inside its own `try`/`catch`,
which returned `null` on any error. In the browser every capability token therefore decoded
to `null`, and `evaluateLayer1` reported all-false for every valid token — a verdict that
reads as a legitimate result rather than a defect. Two amplifiers made it near-undetectable
together: a Node-only global on a path that also runs in the browser, and a swallowing
`try`/`catch` that converted the `ReferenceError` into a benign-looking return value.

## Rules

- **Treat `Buffer`, `process`, `setImmediate`, and every other Node global as absent on any
  path intended to run cross-environment.** Feature-detect with
  `typeof X !== "undefined"` and supply a Web-standard fallback: `atob`/`btoa`,
  `TextEncoder`/`TextDecoder`, `crypto.subtle`, `queueMicrotask`.
- **Grep every cross-environment file for `Buffer` and `process` before you ship it.** A
  project carrying `@types/node` compiles both, so `tsc` reports nothing about the
  `ReferenceError` the browser throws at runtime.
- **Never let a `try`/`catch` swallow a `ReferenceError` into a fail-closed value.** A
  missing global is a build or packaging defect, not a data-validity outcome, and folding it
  into `null` or an all-false verdict hides the defect behind a plausible result.
- **A Node-only test suite never exercises the browser branch, so make the test remove the
  global.** Delete `globalThis.Buffer`, run the code, and restore it in a `finally`. Without
  that test the fallback is dead code, and it regresses the moment someone rewrites it back
  to `Buffer`. `bindings/typescript/tests/browser-fallback.test.ts` calls
  `__extractFirstCapabilityUri` with `globalThis.Buffer` deleted, which is the only
  execution the `atob` branch of `trust.ts` gets.
- **Browser `atob` accepts standard base64 and not base64url**, so normalize `-` and `_` to
  `+` and `/` and re-pad before decoding.

```ts
function decodeBase64UrlToUtf8(segment: string): string {
  const b64 = segment.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  const normalized = b64 + pad;
  if (typeof Buffer !== "undefined") {
    return Buffer.from(normalized, "base64").toString("utf8"); // Node/Bun
  }
  const binary = globalThis.atob(normalized);                  // browser/edge
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}
```

**Scope**: these rules bind every file that more than one runtime compiles, and two files
under `bindings/typescript/` are such files today. ADR-055, which removed the WASM bridge
(`.docs/adrs/phase-4.md`), left the napi-rs bridge as the only in-process backend that
package ships, but ADR-057, the in-browser client over shared MLS, then added the browser
package `@limn-works/scp-ts-wasm` under `bindings/typescript-wasm/`, and that package
bundles `bindings/typescript/src/errors.ts` at build time through the `@scp-core/errors`
path alias `bindings/typescript-wasm/tsconfig.json` declares. A Node global added to
`errors.ts` therefore throws inside `mapBridgeError`, which classifies every wasm-tier
throw. `bindings/typescript/src/trust.ts` is the second file: its
`__decodeBase64UrlToUtf8` declares a `globalThis.atob` branch for browsers, so the rules
above govern it whether or not a consumer bundles that package for a browser today.
