/**
 * Loads the REAL, built wasm into the SDK under bun for the test suite.
 *
 * The suite exercises `ScpBrowserClient` against the actual compiled
 * `scp-client-wasm` surface — never a hand-written mock of `WasmScpClient` (a
 * drifting mock is exactly the "test stand-in masks reality" failure that hid the
 * transport blockers). The `--features testing` build enables the offline
 * did:key/did:test fixtures the two-party exchange uses; the shipped production
 * build never enables it.
 *
 * The façade's glue is the production glue (`src/wasm`); feeding it the test
 * build's wasm BYTES exercises the identical method bodies with the testing
 * feature's DID parsing — the JS import ABI is unchanged by the feature (it only
 * flips Rust-internal DID-format acceptance).
 */

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { initScp } from "../../src/index";

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = join(here, "..", "..");
const testWasmPath = join(packageRoot, "tests", ".wasm-test", "scp_client_wasm_bg.wasm");

/** Ensures the test wasm build exists (builds it with `--features testing` if not). */
function ensureTestWasm(): void {
  if (existsSync(testWasmPath)) {
    return;
  }
  const result = spawnSync("bun", ["scripts/build-wasm.ts", "--test"], {
    cwd: packageRoot,
    stdio: "inherit",
  });
  if ((result.status ?? 1) !== 0) {
    throw new Error(
      "failed to build the test wasm (`bun scripts/build-wasm.ts --test`) — cannot run the real-wasm suite.",
    );
  }
}

let initPromise: Promise<void> | undefined;

/** Initializes the SDK with the real test wasm exactly once for the suite. */
export function loadRealWasm(): Promise<void> {
  if (!initPromise) {
    ensureTestWasm();
    const bytes = readFileSync(testWasmPath);
    // A fresh Uint8Array over the file bytes; the wasm-bindgen `init` accepts a
    // BufferSource and instantiates it against the (production) glue's imports.
    initPromise = initScp(new Uint8Array(bytes));
  }
  return initPromise;
}
