/**
 * Runs the quick start from `bindings/typescript/README.md` end to end, so a
 * reader who copies that block runs code this suite proved.
 *
 * `fixtures/readme-quickstart.ts` holds the README block verbatim. This test
 * spawns it as its own process with `SCP_KEY_PASSPHRASE` and a scratch `HOME`
 * set: the Rust side reads the NATIVE process environment, and a
 * `process.env` write inside a running Bun process does not reach it. Spawning
 * also matches what a reader does — the quick start is a script, not a
 * library call.
 *
 * Skipped when the native NAPI addon is unavailable (browser runtime, missing
 * platform binary), matching `persistence.test.ts`.
 */

import { describe, expect, it } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { SCP } from "../src/scp";

function napiAvailable(): boolean {
  try {
    const probe = new SCP({ storage: { type: "in_memory" } });
    probe.shutdown(1).catch(() => {});
    return true;
  } catch {
    return false;
  }
}

const describeNapi = napiAvailable() ? describe : describe.skip;

describeNapi("README quick start", () => {
  it("runs end to end and prints a DID", async () => {
    const keyHome = await mkdtemp(join(tmpdir(), "scp-ts-quickstart-home-"));
    try {
      const child = Bun.spawn(
        ["bun", "run", join(import.meta.dir, "fixtures", "readme-quickstart.ts")],
        {
          cwd: join(import.meta.dir, ".."),
          env: {
            ...process.env,
            HOME: keyHome,
            SCP_KEY_PASSPHRASE: "quickstart-passphrase",
          },
          stdout: "pipe",
          stderr: "pipe",
        },
      );

      const [stdout, stderr, exitCode] = await Promise.all([
        new Response(child.stdout).text(),
        new Response(child.stderr).text(),
        child.exited,
      ]);

      expect(exitCode, `quick start failed:\n${stderr}`).toBe(0);
      expect(stdout).toMatch(/^DID: did:/m);
    } finally {
      await rm(keyHome, { recursive: true, force: true });
    }
  }, 60_000);
});
