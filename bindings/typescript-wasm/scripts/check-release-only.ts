#!/usr/bin/env bun
/**
 * Guard: the `@limn-works/scp-ts-wasm` wasm build is `--release`-only.
 *
 * ADR-057 Prerequisite 4 (reframed): the fail-closed-on-tampered-ciphertext
 * guarantee rests on the shipped wasm being a `--release` build (openmls's
 * decrypt `debug_assert!` compiled out → typed `Err`, not a tab-abort). A
 * `wasm-pack build --dev` re-arms that assert.
 *
 * This is a POSITIVE, BOUNDED invariant, asserted against the SAME argv the
 * build actually runs (imported from wasm-build.ts, not a text regex that could
 * drift): for every build variant (production AND test), the wasm-pack argv
 * (a) contains exactly the `--release` profile flag and (b) contains no
 * dev/debug/profiling profile flag. It is closed by construction — the only
 * permitted profile is the whitelisted `--release`; it is not a denylist chase.
 *
 * Exit 0 on pass, 1 on violation.
 */

import {
  assertReleaseOnly,
  buildArgs,
  packageRootFromScript,
  repoRootFromPackageRoot,
  WASM_PACK_PROFILE_FLAG,
} from "./wasm-build";

const packageRoot = packageRootFromScript(import.meta.url);
const repoRoot = repoRootFromPackageRoot(packageRoot);

const errors: string[] = [];

// Assert BOTH build variants through the one shared check (assertReleaseOnly),
// accumulating any violation across variants so all are reported at once.
for (const test of [false, true]) {
  const label = test ? "test" : "production";
  const args = buildArgs({ test, repoRoot, packageRoot });
  try {
    assertReleaseOnly(args);
  } catch (error) {
    errors.push(`${label} build: ${(error as Error).message}`);
  }
}

if (errors.length > 0) {
  console.error("FAIL: --release-only wasm-build guard (ADR-057 Prereq-4):");
  for (const e of errors) {
    console.error(`  - ${e}`);
  }
  process.exit(1);
}

console.log(
  `PASS: every scp-ts-wasm build variant uses the ${WASM_PACK_PROFILE_FLAG} profile and no dev/debug profile flag (ADR-057 Prereq-4).`,
);
process.exit(0);
