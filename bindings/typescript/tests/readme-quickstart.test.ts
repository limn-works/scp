/**
 * Runs the quick start in `bindings/typescript/README.md`.
 *
 * `quickStartScript` reads the first `typescript` code block under the README's
 * `## Quick Start` heading, replaces its one package specifier
 * `"@limn-works/scp-ts"` with the absolute path of `src/index.ts`, and writes
 * the result to a scratch file. The test runs that file in a child `bun`
 * process, so an edit that leaves the README block unable to run fails here.
 * The specifier swap is needed because this package has no `node_modules`
 * entry for itself and no built `dist/` during `bun test`.
 *
 * The block uses `"in_memory"` custody, which only a `testing` addon accepts;
 * every SDK test run builds the addon with that feature.
 */

import { describe, expect, it } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadNativeAddon } from "../src/internal/native";
import { skipReasonIfAddonAbsent } from "./napi-guard";

const PACKAGE_ROOT = join(import.meta.dir, "..");
const README = join(PACKAGE_ROOT, "README.md");
const HEADING = "\n## Quick Start\n";
const FENCE_OPEN = "```typescript\n";
const FENCE_CLOSE = "\n```\n";
const SPECIFIER = '"@limn-works/scp-ts"';

/**
 * Returns the first `typescript` block after the Quick Start heading, and
 * throws when the README has no such heading or block, so a README that drops
 * the quick start fails the test instead of running nothing.
 */
function extractQuickStart(readmeText: string): string {
  const [, afterHeading] = readmeText.split(HEADING, 2);
  if (afterHeading === undefined) throw new Error("the README has no '## Quick Start' heading");
  const [, body] = afterHeading.split(FENCE_OPEN, 2);
  if (body === undefined) throw new Error("the Quick Start section has no typescript block");
  const end = body.indexOf(FENCE_CLOSE);
  if (end < 0) throw new Error("the Quick Start typescript block has no closing fence");
  return `${body.slice(0, end)}\n`;
}

/** Returns the block with its package specifier pointed at this package's source. */
function pointAtSource(block: string): string {
  if (!block.includes(SPECIFIER)) {
    throw new Error(`the Quick Start block does not import ${SPECIFIER}`);
  }
  return block.replaceAll(SPECIFIER, JSON.stringify(join(PACKAGE_ROOT, "src", "index.ts")));
}

function addonInstalled(): boolean {
  try {
    loadNativeAddon();
    return true;
  } catch (e: unknown) {
    skipReasonIfAddonAbsent(e);
    return false;
  }
}

describe("README quick start extraction", () => {
  it("reads the typescript block under the heading, not an earlier one", () => {
    const text =
      "# T\n\n```typescript\nbefore();\n```\n\n" +
      "## Quick Start\n\nProse.\n\n```typescript\nquick();\n```\n\n" +
      "```typescript\nafter();\n```\n";
    expect(extractQuickStart(text)).toBe("quick();\n");
  });

  it("throws when the block imports no package specifier", () => {
    expect(() => pointAtSource('import { SCP } from "./elsewhere";\n')).toThrow(SPECIFIER);
  });
});

const describeNapi = addonInstalled() ? describe : describe.skip;

describeNapi("README quick start", () => {
  it("runs and prints the DID and context it created", async () => {
    const dir = await mkdtemp(join(tmpdir(), "scp-ts-readme-quickstart-"));
    try {
      const script = join(dir, "readme-quickstart.ts");
      await writeFile(script, pointAtSource(extractQuickStart(await readFile(README, "utf8"))));
      const child = Bun.spawn([process.execPath, "run", script], {
        cwd: dir,
        env: process.env,
        stdout: "pipe",
        stderr: "pipe",
      });
      const [stdout, stderr, exitCode] = await Promise.all([
        new Response(child.stdout).text(),
        new Response(child.stderr).text(),
        child.exited,
      ]);
      expect(exitCode, `the README quick start failed:\n${stderr}`).toBe(0);
      expect(stdout).toMatch(/^DID: did:/m);
      expect(stdout).toMatch(/^Context: \S+/m);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }, 60_000);
});
