/**
 * `SCP.identityCreateWithCustody` on a shipped addon refuses with
 * `SCP-IDENT-1100` before it calls the provider (spec `03-identity.md`
 * §3.10.10): no substrate satisfies the independent-residence requirement of
 * `09-security-model.md` §9.7.4.1 item 3a, so a shipped addon creates no key.
 *
 * The Rust shipped-build tests of `scp-ffi-napi` cannot reach this entry
 * point, because it takes JS callbacks. This file drives it through the SDK.
 *
 * The file runs against either build and asserts each build's outcome, since
 * the test-skip invariant (`dispatcher-invariant.test.ts`) permits no
 * build-conditional skip:
 * - a shipped addon (no testing-only `fullstackCreateNode` method) rejects
 *   with `SCP-IDENT-1100`, never `SCP-IDENT-1059`, and the provider records
 *   no call;
 * - a `testing` addon reaches the provider, so the provider records a call.
 *
 * Job `rust-test-napi-production` in `.github/workflows/ci.yml` builds the
 * shipped addon and runs this file with `SCP_EXPECT_SHIPPED_ADDON=1`, which
 * fails the file when the addon carries the testing-only method, so that run
 * cannot pass through the `testing` branch.
 */

import { expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { ScpError } from "../src/errors";
import type { KeyCustodyProvider } from "../src/scp";
import { __getNativeScp, SCP } from "../src/scp";
import { napiSuite } from "./napi-guard";

/** The code a shipped addon returns for every identity creation. */
const IDENT_1100 = "SCP-IDENT-1100";
/** The superseded pre-rotation code, which creation no longer returns. */
const IDENT_1059 = "SCP-IDENT-1059";

const suite = await napiSuite(() => {
  const probe = new SCP({ storage: { type: "in_memory" } });
  const native = __getNativeScp(probe) as unknown as Record<string, unknown>;
  const shipped = typeof native.fullstackCreateNode !== "function";
  probe.shutdown(1).catch(() => {});
  if (process.env.SCP_EXPECT_SHIPPED_ADDON === "1" && !shipped) {
    throw new Error(
      "SCP_EXPECT_SHIPPED_ADDON=1, but the addon carries the testing-only " +
        "fullstackCreateNode method, so it is not a shipped build",
    );
  }
  return { shipped };
});

/** A provider whose every method records its name and throws. */
function recordingProvider(calls: string[]): KeyCustodyProvider {
  const refuse = (name: string) => (): never => {
    calls.push(name);
    throw new Error(`provider method ${name} called`);
  };
  return {
    generateKeypair: refuse("generateKeypair"),
    sign: refuse("sign"),
    getPublicKey: refuse("getPublicKey"),
    destroyKey: refuse("destroyKey"),
    dhAgree: refuse("dhAgree"),
    derivePseudonym: refuse("derivePseudonym"),
    deriveRotatablePseudonym: refuse("deriveRotatablePseudonym"),
    custodyType: refuse("custodyType"),
  };
}

suite.describe("identityCreateWithCustody on a shipped addon", ({ shipped }) => {
  test("identityCreateWithCustody refuses with SCP-IDENT-1100 before any provider call", async () => {
    // Callback custody refuses storage that does not persist (spec §17.3)
    // before the creation refusal, so the instance is SQLite.
    const dir = await mkdtemp(join(tmpdir(), "scp-shipped-addon-"));
    const scp = new SCP({
      storage: { type: "sqlite", path: dir, key: new Uint8Array(32).fill(0x5c) },
    });
    const calls: string[] = [];
    try {
      let code: string | undefined;
      try {
        await scp.identityCreateWithCustody(recordingProvider(calls));
        code = undefined;
      } catch (err) {
        code = (err as ScpError).code;
      }
      if (shipped) {
        expect(code).toBe(IDENT_1100);
        expect(code).not.toBe(IDENT_1059);
        expect(calls).toEqual([]);
      } else {
        expect(code).not.toBe(IDENT_1100);
        expect(calls.length).toBeGreaterThan(0);
      }
    } finally {
      await scp.shutdown(1).catch(() => {});
      await rm(dir, { recursive: true, force: true });
    }
  });
});
