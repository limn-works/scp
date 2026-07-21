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
import {
  buildArgs,
  FORBIDDEN_PROFILE_FLAGS,
  packageRootFromScript,
  repoRootFromPackageRoot,
  WASM_PACK_PROFILE_FLAG,
} from "./wasm-build.ts";

const test = process.argv.includes("--test");
const packageRoot = packageRootFromScript(import.meta.url);
const repoRoot = repoRootFromPackageRoot(packageRoot);

const args = buildArgs({ test, repoRoot, packageRoot });

// Defense-in-depth: the argv this process is about to run must itself satisfy
// the release-only invariant. A drift here (someone editing buildArgs to inject
// a dev profile) fails the build loudly rather than shipping a debug-assert
// wasm. This is the same positive invariant the standalone guard asserts.
if (!args.includes(WASM_PACK_PROFILE_FLAG)) {
  console.error(
    `FATAL: wasm-pack argv is missing the required ${WASM_PACK_PROFILE_FLAG} profile flag (ADR-057 Prereq-4).`,
  );
  process.exit(1);
}
for (const forbidden of FORBIDDEN_PROFILE_FLAGS) {
  if (args.includes(forbidden)) {
    console.error(
      `FATAL: wasm-pack argv contains the forbidden profile flag ${forbidden} — the shipped wasm must be --release (ADR-057 Prereq-4).`,
    );
    process.exit(1);
  }
}

console.log(`wasm-pack ${args.join(" ")}`);
const result = spawnSync("wasm-pack", args, { stdio: "inherit", cwd: repoRoot });

if (result.error) {
  console.error(`FATAL: could not launch wasm-pack: ${result.error.message}`);
  process.exit(1);
}
process.exit(result.status ?? 1);
