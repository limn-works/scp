#!/usr/bin/env bun
/**
 * Copies the built `.wasm` binary next to the emitted bundle in `dist/`.
 *
 * The bundle references its wasm sibling as
 * `new URL('./scp_client_wasm_bg.wasm', import.meta.url)`, which resolves
 * relative to `dist/index.js` (or `dist/index.cjs` via the tsup `shims`
 * import.meta.url polyfill) at runtime. tsup/esbuild bundles the glue JS but
 * does not copy the binary asset itself, so this step places it. The
 * `files:["dist/"]` allowlist then ships it in the published package.
 *
 * Run after `tsup` (see the package `build` script). Fails loudly if the wasm
 * source is missing (i.e. `build:wasm` did not run first).
 */

import { copyFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { OUT_NAME, PROD_OUT_DIR, packageRootFromScript } from "./wasm-build";

const packageRoot = packageRootFromScript(import.meta.url);
const wasmName = `${OUT_NAME}_bg.wasm`;
const source = join(packageRoot, PROD_OUT_DIR, wasmName);
const distDir = join(packageRoot, "dist");
const dest = join(distDir, wasmName);

if (!existsSync(source)) {
  console.error(
    `FATAL: wasm artifact not found at ${source}. Run \`bun run build:wasm\` before this step.`,
  );
  process.exit(1);
}

if (!existsSync(distDir)) {
  mkdirSync(distDir, { recursive: true });
}

copyFileSync(source, dest);
console.log(`copied ${wasmName} -> dist/${wasmName}`);
process.exit(0);
