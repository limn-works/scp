import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  target: "esnext",
  splitting: false,
  // The shared core (`@scp-core/errors`) and the wasm-bindgen glue are bundled
  // in so the PUBLISHED package is self-contained (ADR-057 Amendment 2026-07-15
  // D1 — each package bundles its own copy of the one in-repo core module).
  // `sideEffects:false` (package.json) + a single bundled core chunk bounds the
  // per-package dual-package `instanceof` hazard.
  loader: {
    // The `--target web` glue references its sibling wasm as
    // `new URL('scp_client_wasm_bg.wasm', import.meta.url)`. The `file` loader
    // copies that binary into dist/ and rewrites the URL to point at it, so the
    // emitted bundle resolves the wasm relative to itself at runtime.
    ".wasm": "file",
  },
  esbuildOptions(options) {
    // Keep the copied wasm's basename stable (no content hash) so it lands as
    // dist/scp_client_wasm_bg.wasm — a 1:1 sibling the `files:["dist/"]`
    // allowlist ships and the `new URL(...)` reference resolves to.
    options.assetNames = "[name]";
  },
});
