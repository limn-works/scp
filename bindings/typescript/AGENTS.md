# TypeScript SDK (`bindings/typescript/`)

Use bun, never npm or npx. Follow `.docs/standards/typescript.md`. Biome handles lint and format; `bun run check` runs `tsc --noEmit`.

## Values crossing the napi-rs bridge

- A napi-rs callback whose argument is a tuple, such as `ThreadsafeFunction<(String, Vec<u8>), …>`, receives one argument: a two-element array. Write the JavaScript side as `sign: ([keyId, message]) => …`. A single-value callback receives one positional argument. The `#[napi(ts_type = "(keyId, message) => ...")]` annotation implies positional arguments and is wrong; trust the runtime.
- A napi `Vec<u8>` parameter or return value is a JavaScript `Array<number>`, not a `Uint8Array`; passing a `Uint8Array` throws "Given napi value is not an array". Accept `Uint8Array | readonly number[]`, convert inputs with `ArrayBuffer.isView(x) ? Array.from(x) : x`, and wrap byte returns in `Uint8Array.from(raw)`, as `broadcastPublish` does.

## Testing against the real addon

`bun run check`, `bun run lint`, and a single-file `bun test` are not enough. The real-napi tests skip themselves when no built `.node` exists, and some failures appear only when every test file runs in one process. Before you push a bridge-facing change, build the addon (`cargo build -p scp-ffi-napi --release --features scp-ffi-napi/testing`, then copy the library to `node_modules/@limn-works/scp-ts-napi-<platform>/index.node` with a one-line `package.json`), and run the whole `bun test` suite. The release build takes minutes, so run it from the main session rather than a worktree subagent.

## Code that also runs in a browser

`Buffer`, `process`, and `setImmediate` do not exist in browsers or edge runtimes, and referencing one throws `ReferenceError`. `tsc` stays silent because `@types/node` declares them, and every test under Node or Bun passes. Once, a JWT decoder in `src/trust.ts` called `Buffer.from(…, "base64url")` inside a `try`/`catch` that returned `null`, so in a browser every token decoded to `null` and `evaluateLayer1` reported all-false: a verdict that looks legitimate.

- On any path more than one runtime runs, treat Node globals as absent. Feature-detect with `typeof X !== "undefined"` and fall back to Web APIs: `atob`/`btoa`, `TextEncoder`/`TextDecoder`, `crypto.subtle`, `queueMicrotask`.
- Never let a `try`/`catch` turn a `ReferenceError` into a fail-closed value. A missing global is a packaging defect, not a data outcome.
- Test each fallback by deleting the global, as `tests/browser-fallback.test.ts` does with `globalThis.Buffer`; without such a test the fallback is dead code.
- Browser `atob` accepts standard base64, not base64url: map `-`→`+` and `_`→`/` and re-pad first.
- The rules bind every file more than one runtime compiles. That includes `src/trust.ts` (its `__decodeBase64UrlToUtf8` has a `globalThis.atob` branch) and `src/errors.ts`, which the browser package `bindings/typescript-wasm/` bundles through the `@scp-core/errors` path alias, so a Node global there breaks `mapBridgeError` for every browser error.
