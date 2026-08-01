#!/usr/bin/env bun
/**
 * Builds the `@limn-works/scp-ts-wasm` wasm artifact via wasm-pack.
 *
 * Usage:
 *   bun scripts/build-wasm.ts          # production build -> src/wasm/
 *   bun scripts/build-wasm.ts --test   # test build (--features testing) -> tests/.wasm-test/
 *
 * The build is ALWAYS `--release` (ADR-057 Prereq-4); there is no `--dev`
 * path. See scripts/wasm-build.ts for the profile invariant the
 * check-release-only guard enforces.
 */

import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  assertReleaseOnly,
  buildArgs,
  OUT_NAME,
  PROD_OUT_DIR,
  packageRootFromScript,
  repoRootFromPackageRoot,
  TEST_OUT_DIR,
} from "./wasm-build";

const test = process.argv.includes("--test");
const packageRoot = packageRootFromScript(import.meta.url);
const repoRoot = repoRootFromPackageRoot(packageRoot);

const args = buildArgs({ test, repoRoot, packageRoot });

// Defense-in-depth: the argv this process is about to run must itself satisfy
// the release-only invariant (the same shared check the standalone guard runs).
// A drift here (someone editing buildArgs to inject a dev profile) fails the
// build loudly rather than shipping a debug-assert wasm.
try {
  assertReleaseOnly(args);
} catch (error) {
  console.error(`FATAL: ${(error as Error).message}.`);
  process.exit(1);
}

console.log(`wasm-pack ${args.join(" ")}`);
const result = spawnSync("wasm-pack", args, { stdio: "inherit", cwd: repoRoot });

if (result.error) {
  console.error(`FATAL: could not launch wasm-pack: ${result.error.message}`);
  process.exit(1);
}
if ((result.status ?? 1) !== 0) {
  process.exit(result.status ?? 1);
}

// Normalize the generated glue's wasm reference to a `./`-relative specifier so
// the bundler (tsup/esbuild) recognizes it as a sibling asset, copies the
// `.wasm` into dist/, and rewrites the URL to resolve relative to the emitted
// bundle (ADR-057 Slice-3: ship the `.wasm` as a sibling via
// `new URL('./..._bg.wasm', import.meta.url)`). wasm-pack emits it without the
// `./`, which esbuild treats as a bare specifier and would NOT copy.
const outDir = test ? TEST_OUT_DIR : PROD_OUT_DIR;
const gluePath = join(packageRoot, outDir, `${OUT_NAME}.js`);
const glue = readFileSync(gluePath, "utf8");
const bareRef = `new URL('${OUT_NAME}_bg.wasm', import.meta.url)`;
const relativeRef = `new URL('./${OUT_NAME}_bg.wasm', import.meta.url)`;
if (glue.includes(bareRef)) {
  writeFileSync(gluePath, glue.replace(bareRef, relativeRef));
  console.log(`patched ${gluePath}: wasm reference is now './'-relative for bundler asset copy`);
} else if (!glue.includes(relativeRef)) {
  console.error(
    `FATAL: expected the wasm-bindgen glue to reference the wasm via \`${bareRef}\` (or the './'-relative form); found neither. wasm-pack output shape changed — the sibling-asset copy would silently break.`,
  );
  process.exit(1);
}
process.exit(0);
