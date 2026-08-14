# Node-Only Globals Silently Break Cross-Environment Code Paths

**Date:** 2026-07-15
**Source:** branch `fix/sdk-coverage-fail-closed-and-parity` — `bindings/typescript/src/trust.ts`

**Note:** As of ADR-055 (PR #1934), the `scp-ffi/wasm` bridge is removed and
`bindings/typescript/` is NAPI-only (Node/Bun). The pattern documented here
was a real bug found during development. The principle remains relevant for any
TypeScript utility code intended to run cross-environment (e.g. shared helpers
used in future browser-facing SDKs under ADR-057's shared-wasm model).

## The trap

TypeScript utility code compiled for cross-environment use may reference Node globals —
`Buffer`, `process`, `setImmediate` — that do **not** exist in the browser or edge
runtimes. Referencing one throws `ReferenceError`. The compiler will not catch it:
`Buffer` is a valid ambient type in a TypeScript project with `@types/node`, so
browser-only breakage sails through `tsc` and through every test that happens to run
under Node/Bun.

## What happened

`__extractFirstCapabilityUri` in `trust.ts` decoded the JWT payload with
`Buffer.from(segment, "base64url").toString("utf8")`. In the browser, `Buffer` is
undefined, so the call threw. The throw landed inside the function's own `try/catch`,
which returned `null` on any error. So instead of crashing loudly, **every** capability
token decoded to `null`, `evaluateLayer1` reported `ALL_LAYER1_FIELDS_FALSE` for every
valid token, and Layer 1 was invisibly broken for all browser consumers — a false
"all-invalid" trust verdict that looks like a legitimate result, not a bug.

The two failure amplifiers, together, made this near-undetectable:
1. **A Node-only global** referenced on a code path that also runs in the browser.
2. **A swallowing `try/catch`** that converted the `ReferenceError` into a benign-looking
   `null` return instead of surfacing it.

## The fix pattern

Feature-detect the global and fall back to Web-standard APIs:

```ts
function __decodeBase64UrlToUtf8(segment: string): string {
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

Note also that browser `atob` only accepts standard base64, not base64url — normalize
`-`/`_` → `+`/`/` and re-pad before decoding.

## Locking it in

A Node-only test suite can never exercise the browser branch. Add a test that
**temporarily removes `globalThis.Buffer`** (delete it, run the code, restore it in a
`finally`) so the fallback path is actually executed under CI. Without this, the browser
branch is dead code that regresses the moment someone "simplifies" it back to `Buffer`.

## The rule

- Treat `Buffer`, `process`, `setImmediate`, and any other Node global as **absent**
  on any code path intended to run cross-environment. Feature-detect
  (`typeof X !== "undefined"`) and provide a Web-standard fallback (`atob`/`btoa`,
  `TextEncoder`/`TextDecoder`, `crypto.subtle`, `queueMicrotask`).
- `@types/node` in the project makes these compile — the type checker is **not** a guard
  against runtime `ReferenceError` in the browser. Grep for `Buffer`/`process` in any file
  that runs cross-environment before shipping.
- Never let a `try/catch` swallow a `ReferenceError` into a fail-closed value. A missing
  global is a build/packaging defect, not a data-validity outcome — folding it into
  `null`/all-false hides the defect behind a plausible verdict.
