import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  target: "esnext",
  splitting: false,
  // Inject the `import.meta.url` shim into the CJS output so the wasm-bindgen
  // glue's `new URL('./..._bg.wasm', import.meta.url)` resolves to the dist
  // sibling under `require()` too (ESM has `import.meta.url` natively). Without
  // this the CJS bundle's default wasm load would break.
  shims: true,
  // The shared core (`@scp-core/errors`) and the wasm-bindgen glue are bundled
  // in so the PUBLISHED package is self-contained (ADR-057 Amendment 2026-07-15
  // D1 — each package bundles its own copy of the one in-repo core module).
  // `sideEffects:false` (package.json) + a single bundled core chunk bounds the
  // per-package dual-package `instanceof` hazard.
  //
  // NOTE: the `.wasm` binary is NOT bundled or copied by esbuild. The `--target
  // web` glue references it as `new URL('./scp_client_wasm_bg.wasm',
  // import.meta.url)`, which esbuild leaves as a *runtime* reference (verified
  // empirically: `tsup` alone emits no `dist/*.wasm`). The sibling `.wasm` is
  // placed into `dist/` by `scripts/copy-wasm-asset.ts` (run after `tsup` in the
  // `build` script), so the `new URL(...)` resolves to it at runtime.
});
