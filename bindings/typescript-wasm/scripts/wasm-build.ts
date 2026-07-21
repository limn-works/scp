/**
 * Shared wasm-pack build configuration for `@limn-works/scp-ts-wasm`.
 *
 * The build profile is a single load-bearing invariant (ADR-057 Prerequisite 4,
 * reframed): the shipped wasm MUST be a `--release` build. openmls's decrypt
 * path carries a `debug_assert!` that a `--dev` (debug-assertions-on) build
 * re-arms — a tampered ciphertext would then abort the tab instead of surfacing
 * a typed `[SCP-CRYPTO-4010]` `DecryptionFailed`. `--release` compiles that
 * assert out, so `process_message` returns a typed `Err` on tampered ciphertext.
 *
 * The profile flag is a constant here so the `check-release-only` guard asserts
 * against the SAME argv the build actually runs — a positive, bounded invariant
 * (the profile flag is `--release`, and no debug/dev profile flag appears),
 * never a text regex over a script that could drift from what executes.
 */

import { resolve } from "node:path";

/**
 * The ONLY permitted wasm-pack build profile flag. Hard-coded to `--release`;
 * there is no `--dev` / `--debug` / `--profiling` path (ADR-057 Prereq-4).
 */
export const WASM_PACK_PROFILE_FLAG = "--release" as const;

/**
 * Debug/dev profile flags that MUST NEVER appear in a shipped-artifact build
 * (they re-arm the openmls decrypt `debug_assert!`). The guard rejects any of
 * these; the whitelist above is the only allowed profile.
 */
export const FORBIDDEN_PROFILE_FLAGS: readonly string[] = ["--dev", "--debug", "--profiling"];

/** The crate wasm-pack compiles (repo-relative). */
export const CRATE_PATH = "crates/scp-client-wasm";

/** The wasm-bindgen output basename (imported by the TS glue + `.wasm` sibling). */
export const OUT_NAME = "scp_client_wasm";

/**
 * The production wasm output directory, relative to this package root — a
 * `src/` sibling so tsup bundles the emitted glue and copies the `.wasm`.
 */
export const PROD_OUT_DIR = "src/wasm";

/**
 * The test wasm output directory, relative to this package root. Built with the
 * `testing` feature (did:key/did:test fixtures) and loaded by the real-wasm e2e
 * suite. Never shipped — the published `files` allowlist is `dist/` only.
 */
export const TEST_OUT_DIR = "tests/.wasm-test";

export interface WasmBuildOptions {
  /**
   * When true, build the test variant: the `testing` feature (non-production
   * did:key/did:test formats) enabled and emitted to {@link TEST_OUT_DIR}. The
   * production build never enables `testing`.
   */
  readonly test: boolean;
  /** Absolute path to the repo root (two levels above this package). */
  readonly repoRoot: string;
  /** Absolute path to this package root. */
  readonly packageRoot: string;
}

/**
 * Builds the exact `wasm-pack` argv for a build variant.
 *
 * `--release` is unconditional. The `testing` feature is added ONLY for the
 * test variant, and never for the production (shipped) variant.
 */
export function buildArgs(opts: WasmBuildOptions): string[] {
  const outDir = opts.test ? TEST_OUT_DIR : PROD_OUT_DIR;
  const args = [
    "build",
    resolve(opts.repoRoot, CRATE_PATH),
    WASM_PACK_PROFILE_FLAG,
    "--target",
    "web",
    "--out-dir",
    resolve(opts.packageRoot, outDir),
    "--out-name",
    OUT_NAME,
  ];
  if (opts.test) {
    // did:key / did:test fixtures for the offline two-party e2e exchange. The
    // production build omits this so no non-production DID format ships.
    args.push("--features", "testing");
  }
  return args;
}

/** Absolute path to this package root, resolved from this module's location. */
export function packageRootFromScript(scriptUrl: string): string {
  return resolve(new URL(".", scriptUrl).pathname, "..");
}

/** Absolute path to the repo root, resolved from this package root. */
export function repoRootFromPackageRoot(packageRoot: string): string {
  return resolve(packageRoot, "..", "..");
}
