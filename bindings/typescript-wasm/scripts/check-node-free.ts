#!/usr/bin/env bun
/**
 * Guard: the built `@limn-works/scp-ts-wasm` bundle carries no `node:` code.
 *
 * ADR-057 / planning-session-09 bundle-isolation check. The wasm tier ships to
 * browsers/edge; a `node:`-prefixed import specifier in the emitted bundle is
 * physical proof it dragged in node-only code. This is a SINGLE, BOUNDED absence
 * assertion — one scan for the `node:` import prefix over the built output — NOT
 * an open-ended denylist of built-in module names. It stays one positive
 * invariant ("the wasm bundle contains no `node:` specifier") so it cannot grow
 * into a "one more spelling" chase.
 *
 * Requires `dist/` to exist (run `bun run build` first). Exit 0 on pass, 1 on a
 * `node:` specifier or a missing/empty `dist/`.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { packageRootFromScript } from "./wasm-build";

const packageRoot = packageRootFromScript(import.meta.url);
const distDir = join(packageRoot, "dist");

function listFiles(dir: string): string[] {
  const out: string[] = [];
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return out;
  }
  for (const entry of entries) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      out.push(...listFiles(full));
    } else {
      out.push(full);
    }
  }
  return out;
}

const files = listFiles(distDir);

if (files.length === 0) {
  console.error(`FAIL: bundle-isolation guard: dist/ is missing or empty at ${distDir}.`);
  console.error("      Run `bun run build` before this guard.");
  process.exit(1);
}

// Scan every emitted JavaScript/TypeScript-declaration artifact for a `node:`
// import specifier. The single regex is the whole invariant: any `node:`
// prefix (as an import/require target, i.e. quoted) is a violation. `.wasm` and
// source maps are binary/opaque and excluded from the text scan.
const NODE_SPECIFIER = /["'`]node:[a-z/_-]+["'`]/g;
const scannable = files.filter((f) => /\.(cjs|js|mjs|d\.ts|d\.cts|d\.mts)$/.test(f));

const violations: string[] = [];
for (const file of scannable) {
  const text = readFileSync(file, "utf8");
  const matches = text.match(NODE_SPECIFIER);
  if (matches) {
    const unique = [...new Set(matches)].join(", ");
    violations.push(`${file}: ${unique}`);
  }
}

if (violations.length > 0) {
  console.error(
    "FAIL: bundle-isolation guard — the browser wasm bundle contains node: specifiers:",
  );
  for (const v of violations) {
    console.error(`  - ${v}`);
  }
  console.error(
    "\nThe wasm tier must carry no node-only code. Remove the import that pulls a node: builtin.",
  );
  process.exit(1);
}

console.log(
  `PASS: bundle-isolation guard — no node: specifier in ${scannable.length} emitted dist artifact(s).`,
);
process.exit(0);
