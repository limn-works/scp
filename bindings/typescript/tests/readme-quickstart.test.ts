/**
 * Runs the code examples in `bindings/typescript/README.md`.
 *
 * `extractBlock` reads the first `typescript` code block under a README
 * heading. Each test replaces that block's one package specifier
 * `"@limn-works/scp-ts"` with the absolute path of `src/index.ts`, writes the
 * result to a scratch file, and runs it in a child `bun` process, so an edit
 * that leaves a README block unable to run fails here. The specifier swap is
 * needed because this package has no `node_modules` entry for itself and no
 * built `dist/` during `bun test`.
 *
 * Both blocks use in-memory storage and `"encrypted_file"` custody (spec
 * `03-identity.md` §3.2.2). The child runs with `HOME` set to its scratch
 * directory and a fixed `SCP_KEY_PASSPHRASE`, so the key file it writes,
 * `$HOME/.scp/keys.bin`, never touches the real home directory. Only a
 * `testing` addon creates the identity (a shipped one answers
 * `SCP-IDENT-1059`); every SDK test run builds the addon with that feature.
 */

import { describe, expect, it } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadNativeAddon } from "../src/internal/native";
import { skipReasonIfAddonAbsent } from "./napi-guard";

const PACKAGE_ROOT = join(import.meta.dir, "..");
const README = join(PACKAGE_ROOT, "README.md");
const QUICK_START = "Quick Start";
const ERROR_HANDLING = "Error Handling";
const FENCE_OPEN = "```typescript\n";
const FENCE_CLOSE = "\n```\n";
const SPECIFIER = '"@limn-works/scp-ts"';
/** The key-file passphrase the README blocks run under; a test value, not a secret. */
const README_KEY_PASSPHRASE = "readme-quickstart-test-passphrase";

/**
 * Returns the first `typescript` block after the `## {heading}` line, and
 * throws when the README has no such heading or block, so a README that drops
 * the example fails the test instead of running nothing.
 */
function extractBlock(readmeText: string, heading: string): string {
  const [, afterHeading] = readmeText.split(`\n## ${heading}\n`, 2);
  if (afterHeading === undefined) throw new Error(`the README has no '## ${heading}' heading`);
  const [, body] = afterHeading.split(FENCE_OPEN, 2);
  if (body === undefined) throw new Error(`the ${heading} section has no typescript block`);
  const end = body.indexOf(FENCE_CLOSE);
  if (end < 0) throw new Error(`the ${heading} typescript block has no closing fence`);
  return `${body.slice(0, end)}\n`;
}

/** Returns the block with its package specifier pointed at this package's source. */
function pointAtSource(block: string): string {
  if (!block.includes(SPECIFIER)) {
    throw new Error(`the README block does not import ${SPECIFIER}`);
  }
  return block.replaceAll(SPECIFIER, JSON.stringify(join(PACKAGE_ROOT, "src", "index.ts")));
}

/** Runs the README block under `heading` in a child `bun` process. */
async function runReadmeBlock(
  heading: string,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const dir = await mkdtemp(join(tmpdir(), "scp-ts-readme-"));
  try {
    const script = join(dir, "readme-block.ts");
    await writeFile(script, pointAtSource(extractBlock(await readFile(README, "utf8"), heading)));
    const child = Bun.spawn([process.execPath, "run", script], {
      cwd: dir,
      env: { ...process.env, HOME: dir, SCP_KEY_PASSPHRASE: README_KEY_PASSPHRASE },
      stdout: "pipe",
      stderr: "pipe",
    });
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
      child.exited,
    ]);
    return { stdout, stderr, exitCode };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
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

describe("README block extraction", () => {
  it("reads the typescript block under the heading, not an earlier one", () => {
    const text =
      "# T\n\n```typescript\nbefore();\n```\n\n" +
      "### Quick Start\n\n```typescript\nh3();\n```\n\n" +
      "## Quick Start\n\nProse.\n\n```typescript\nquick();\n```\n\n" +
      "```typescript\nafter();\n```\n";
    expect(extractBlock(text, QUICK_START)).toBe("quick();\n");
  });

  it("throws when the block imports no package specifier", () => {
    expect(() => pointAtSource('import { SCP } from "./elsewhere";\n')).toThrow(SPECIFIER);
  });
});

const describeNapi = addonInstalled() ? describe : describe.skip;

describeNapi("README examples", () => {
  it("the quick start runs and prints the DID and context it created", async () => {
    const { stdout, stderr, exitCode } = await runReadmeBlock(QUICK_START);
    expect(exitCode, `the README quick start failed:\n${stderr}`).toBe(0);
    expect(stdout).toMatch(/^DID: did:/m);
    expect(stdout).toMatch(/^Context: \S+/m);
  }, 60_000);

  // The block rethrows anything that is not a ValidationError, so exit 0 plus
  // the printed code proves its catch clause handled the typed error.
  it("the error handling block catches the typed ValidationError", async () => {
    const { stderr, exitCode } = await runReadmeBlock(ERROR_HANDLING);
    expect(exitCode, `the README error example failed:\n${stderr}`).toBe(0);
    expect(stderr).toMatch(/^contextCreate rejected the params: SCP-VALID-7000$/m);
  }, 60_000);
});
