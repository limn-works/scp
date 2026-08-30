# Node-Only Globals Silently Break Cross-Environment Code Paths

**Problem**: TypeScript utility code compiled for cross-environment use references Node
globals — `Buffer`, `process`, `setImmediate` — that the browser and edge runtimes do not
provide, and referencing one throws `ReferenceError`. The compiler does not catch it:
`Buffer` is a valid ambient type in any project carrying `@types/node`, so browser-only
breakage passes `tsc` and every test that runs under Node or Bun.

A JWT-decoding helper called `Buffer.from(segment, "base64url").toString("utf8")` inside its
own `try`/`catch`, which returned `null` on any error. In the browser every capability token
therefore decoded to `null`, and the trust layer reported all-false for every valid token —
a verdict that reads as a legitimate result rather than a defect. Two amplifiers made it
near-undetectable together: a Node-only global on a path that also runs in the browser, and
a swallowing `try`/`catch` that converted the `ReferenceError` into a benign-looking return
value.

## Rules

- **Treat `Buffer`, `process`, `setImmediate`, and every other Node global as absent on any
  path intended to run cross-environment.** Feature-detect with
  `typeof X !== "undefined"` and supply a Web-standard fallback: `atob`/`btoa`,
  `TextEncoder`/`TextDecoder`, `crypto.subtle`, `queueMicrotask`.
- **Never let a `try`/`catch` swallow a `ReferenceError` into a fail-closed value.** A
  missing global is a build or packaging defect, not a data-validity outcome, and folding it
  into `null` or an all-false verdict hides the defect behind a plausible result.
- **A Node-only test suite never exercises the browser branch, so make the test remove the
  global.** Delete `globalThis.Buffer`, run the code, and restore it in a `finally`. Without
  that test the fallback is dead code, and it regresses the moment someone rewrites it back
  to `Buffer`.
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

**Scope**: ADR-055, which removed the WASM bridge (`.docs/adrs/phase-4.md`), left
`bindings/typescript/` running on the napi-rs bridge alone, so no file there runs in a
browser today. These rules bind any shared helper written for more than one runtime,
including the browser SDK ADR-057, the in-browser client over shared MLS, describes.
