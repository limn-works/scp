/**
 * Dispatcher invariant test (#1543 batch 3a follow-up).
 *
 * `internal/native.ts` routes calls through one of two handles:
 *   • `native.X` — method on the per-instance `Scp` class (Rust source:
 *                  `impl Scp { #[napi] fn X(&self) }` in `crates/scp-ffi/napi/src/scp.rs`).
 *   • `addon.X` — module-level NAPI free function (Rust source:
 *                 `#[napi] pub fn X()` in any other `crates/scp-ffi/napi/src/*.rs`).
 *
 * Routing through the wrong handle silently becomes `(undefined)(args)` at
 * runtime — a regression caught and fixed across two follow-up PRs (97051e32e,
 * 176763958), which corrected 13 mis-routed sites. This test guards against
 * the same bug class returning.
 *
 * Approach (static): parse the Rust sources and the dispatcher TS file
 * directly. The runtime introspection alternative (loading the actual NAPI
 * addon and reading `Object.getOwnPropertyNames(addon.SCP.prototype)`) is
 * infeasible in the default test environment because `@limn-works/scp-ts-napi-*`
 * is not always built before `bun test` runs. Static analysis catches the
 * same invariant from the Rust source of truth — `#[napi]` placement
 * (inside `impl Scp` vs at module scope) determines the JS-side handle, and
 * napi-rs's snake_case → camelCase default conversion is well-defined.
 */

import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "../../..");

const NAPI_SRC_DIR = join(REPO_ROOT, "crates", "scp-ffi", "napi", "src");
const SCP_RS = join(NAPI_SRC_DIR, "scp.rs");
const DISPATCHER_TS = join(REPO_ROOT, "bindings", "typescript", "src", "internal", "native.ts");

// ---------------------------------------------------------------------------
// Naming conversion (Rust snake_case → napi-rs default camelCase)
// ---------------------------------------------------------------------------

/**
 * napi-rs default conversion: `snake_case` → `camelCase`. Used when no
 * explicit `js_name = "..."` is provided on `#[napi]`. Non-leading
 * underscores boundary into uppercase; leading underscores are kept (private).
 */
function toCamelCase(snake: string): string {
  return snake.replace(/_([a-z0-9])/g, (_, c: string) => c.toUpperCase());
}

// ---------------------------------------------------------------------------
// Parse Rust sources
// ---------------------------------------------------------------------------

interface NapiDecl {
  name: string;
  rangeStart: number;
}

/** Skips over whitespace, doc comments, block comments, and intervening attrs. */
function skipNonCodePrefix(after: string): number {
  let cursor = 0;
  while (cursor < after.length) {
    // Whitespace
    if (/\s/.test(after.charAt(cursor))) {
      cursor++;
      continue;
    }
    // Line comments (including doc comments)
    if (after.startsWith("//", cursor)) {
      const eol = after.indexOf("\n", cursor);
      if (eol === -1) return cursor;
      cursor = eol + 1;
      continue;
    }
    // Block comments
    if (after.startsWith("/*", cursor)) {
      const end = after.indexOf("*/", cursor + 2);
      if (end === -1) return cursor;
      cursor = end + 2;
      continue;
    }
    // Another attribute (#[allow(...)] etc.)
    if (after.startsWith("#[", cursor)) {
      const end = after.indexOf("]", cursor + 2);
      if (end === -1) return cursor;
      cursor = end + 1;
      continue;
    }
    break;
  }
  return cursor;
}

const FN_RE = /^(?:pub(?:\s*\(\s*[a-z]+\s*\))?\s+)?(?:async\s+)?fn\s+([a-z_][a-z0-9_]*)/i;
const JS_NAME_RE = /js_name\s*=\s*"([^"]+)"/;

/**
 * Extracts `#[napi]`-annotated function declarations from Rust source. For
 * each match returns the declared JS name (either the `js_name` override
 * or the snake_case→camelCase default).
 */
function extractNapiDecls(rustSrc: string): NapiDecl[] {
  const out: NapiDecl[] = [];

  const napiRe = /#\[napi(?:\(([^)]*)\))?\]/g;
  let m: RegExpExecArray | null = napiRe.exec(rustSrc);
  while (m !== null) {
    const args = m[1] ?? "";
    const attrEnd = m.index + m[0].length;
    const matchIndex = m.index;

    const after = rustSrc.slice(attrEnd, attrEnd + 1500);
    const cursor = skipNonCodePrefix(after);

    const next = after.slice(cursor, cursor + 200);
    const fnM = FN_RE.exec(next);

    if (fnM?.[1] && !/\bconstructor\b/.test(args)) {
      const rustName = fnM[1];
      const jsNameMatch = JS_NAME_RE.exec(args);
      const jsName = jsNameMatch?.[1] ?? toCamelCase(rustName);
      out.push({ name: jsName, rangeStart: matchIndex });
    }

    m = napiRe.exec(rustSrc);
  }
  return out;
}

interface BlockRange {
  start: number;
  end: number;
}

interface ScanState {
  i: number;
  inString: boolean;
  inLineComment: boolean;
  inBlockComment: boolean;
}

/** Advance one character in a brace-balanced scan, tracking string/comment state. */
function advanceScan(rustSrc: string, state: ScanState): { depthDelta: number } {
  const ch = rustSrc.charAt(state.i);
  const next = rustSrc.charAt(state.i + 1);

  if (state.inLineComment) {
    if (ch === "\n") state.inLineComment = false;
    state.i++;
    return { depthDelta: 0 };
  }
  if (state.inBlockComment) {
    if (ch === "*" && next === "/") {
      state.inBlockComment = false;
      state.i += 2;
    } else {
      state.i++;
    }
    return { depthDelta: 0 };
  }
  if (state.inString) {
    if (ch === "\\") {
      state.i += 2;
    } else {
      if (ch === '"') state.inString = false;
      state.i++;
    }
    return { depthDelta: 0 };
  }
  if (ch === "/" && next === "/") {
    state.inLineComment = true;
    state.i += 2;
    return { depthDelta: 0 };
  }
  if (ch === "/" && next === "*") {
    state.inBlockComment = true;
    state.i += 2;
    return { depthDelta: 0 };
  }
  if (ch === '"') {
    state.inString = true;
    state.i++;
    return { depthDelta: 0 };
  }
  state.i++;
  if (ch === "{") return { depthDelta: 1 };
  if (ch === "}") return { depthDelta: -1 };
  return { depthDelta: 0 };
}

/**
 * Returns the byte-offset ranges of every `impl <Type> { ... }` block
 * body matching `implRe`. Pass `/^impl\s+Scp\s*\{/gm` for `impl Scp`,
 * or `/^impl\s+\w+\s*\{/gm` for any `impl <Type>` block.
 */
function findImplBlockRanges(rustSrc: string, implRe: RegExp): BlockRange[] {
  const out: BlockRange[] = [];
  let m: RegExpExecArray | null = implRe.exec(rustSrc);
  while (m !== null) {
    const bodyStart = m.index + m[0].length;
    const state: ScanState = {
      i: bodyStart,
      inString: false,
      inLineComment: false,
      inBlockComment: false,
    };
    let depth = 1;
    while (state.i < rustSrc.length && depth > 0) {
      depth += advanceScan(rustSrc, state).depthDelta;
    }
    if (depth === 0) {
      out.push({ start: bodyStart, end: state.i - 1 });
    }
    m = implRe.exec(rustSrc);
  }
  return out;
}

function isInRange(offset: number, ranges: BlockRange[]): boolean {
  return ranges.some((r) => offset >= r.start && offset < r.end);
}

interface NapiSurface {
  classMethods: Set<string>;
  freeFns: Set<string>;
}

/**
 * Returns two sets of JS-visible names:
 *   • classMethods — names declared as `#[napi] fn ...` inside `impl Scp { ... }`
 *                    blocks of `crates/scp-ffi/napi/src/scp.rs`.
 *   • freeFns      — names declared as `#[napi] pub fn ...` at module scope
 *                    in any other `crates/scp-ffi/napi/src/*.rs` file.
 */
function extractNapiSurface(): NapiSurface {
  const classMethods = new Set<string>();
  const freeFns = new Set<string>();

  // scp.rs — split inside vs outside impl Scp.
  const scpRs = readFileSync(SCP_RS, "utf8");
  const implScpRanges = findImplBlockRanges(scpRs, /^impl\s+Scp\s*\{/gm);
  for (const decl of extractNapiDecls(scpRs)) {
    if (isInRange(decl.rangeStart, implScpRanges)) {
      classMethods.add(decl.name);
    } else {
      freeFns.add(decl.name);
    }
  }

  // All other *.rs files in crates/scp-ffi/napi/src/. These contain a mix
  // of module-level `#[napi] pub fn ...` (free fns) and
  // `#[napi] impl <OtherType> { ... }` (methods on opaque handle classes
  // like NapiContextHandle, NapiIdentity, Relay, Node). Methods on those
  // handles are dispatched through the handle object itself, not via
  // `addon.X` or `native.X` — exclude them from both sets.
  for (const entry of readdirSync(NAPI_SRC_DIR)) {
    if (!entry.endsWith(".rs")) continue;
    if (entry === "scp.rs") continue;
    const src = readFileSync(join(NAPI_SRC_DIR, entry), "utf8");
    const otherImplRanges = findImplBlockRanges(src, /^impl\s+\w+\s*\{/gm);
    for (const decl of extractNapiDecls(src)) {
      if (isInRange(decl.rangeStart, otherImplRanges)) continue;
      freeFns.add(decl.name);
    }
  }

  return { classMethods, freeFns };
}

// ---------------------------------------------------------------------------
// Parse internal/native.ts dispatch sites
// ---------------------------------------------------------------------------

interface DispatchSite {
  handle: "addon" | "native";
  name: string;
  line: number;
}

const DISPATCH_RE = /(?<![A-Za-z0-9_$])(addon|native)\.([A-Za-z_$][A-Za-z0-9_$]*)/g;

function extractDispatchSitesFromLine(line: string, lineNo: number): DispatchSite[] {
  // Skip pure comment lines so documentation prose (e.g. `addon.X` cited
  // in the dispatcher routing-rule comment block) is not treated as a
  // dispatch site.
  const codeOnly = line.replace(/^\s*\/\/.*$/, "").replace(/^\s*\*.*$/, "");
  if (codeOnly.trim().length === 0) return [];
  const sites: DispatchSite[] = [];
  let m: RegExpExecArray | null = DISPATCH_RE.exec(codeOnly);
  while (m !== null) {
    const handle = m[1];
    const name = m[2];
    if ((handle === "addon" || handle === "native") && name) {
      sites.push({ handle, name, line: lineNo });
    }
    m = DISPATCH_RE.exec(codeOnly);
  }
  return sites;
}

function extractDispatchSites(): DispatchSite[] {
  const src = readFileSync(DISPATCHER_TS, "utf8");
  const lines = src.split("\n");
  const sites: DispatchSite[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line === undefined) continue;
    sites.push(...extractDispatchSitesFromLine(line, i + 1));
  }
  return sites;
}

// ---------------------------------------------------------------------------
// Per-site validation
// ---------------------------------------------------------------------------

function validateNativeSite(
  site: DispatchSite,
  classMethods: Set<string>,
  freeFns: Set<string>,
): string | null {
  if (classMethods.has(site.name)) return null;
  if (freeFns.has(site.name)) {
    return (
      `${DISPATCHER_TS}:${site.line}  uses \`native.${site.name}\` ` +
      `but '${site.name}' is a module-level NAPI free function ` +
      `(declared outside \`impl Scp\`). Use \`addon.${site.name}\` instead.`
    );
  }
  return (
    `${DISPATCHER_TS}:${site.line}  uses \`native.${site.name}\` ` +
    `but '${site.name}' is not declared anywhere in ` +
    `crates/scp-ffi/napi/src/. Either add the #[napi] export or fix the dispatcher.`
  );
}

function validateAddonSite(
  site: DispatchSite,
  classMethods: Set<string>,
  freeFns: Set<string>,
): string | null {
  // `addon.SCP` is the napi-rs class constructor — legitimately a top-level
  // export, not a method, even though it isn't a `#[napi] pub fn`.
  if (site.name === "SCP") return null;
  if (freeFns.has(site.name)) return null;
  if (classMethods.has(site.name)) {
    return (
      `${DISPATCHER_TS}:${site.line}  uses \`addon.${site.name}\` ` +
      `but '${site.name}' is a method on the SCP class ` +
      `(declared inside \`impl Scp\`). Use \`native.${site.name}\` instead.`
    );
  }
  return (
    `${DISPATCHER_TS}:${site.line}  uses \`addon.${site.name}\` ` +
    `but '${site.name}' is not declared anywhere in ` +
    `crates/scp-ffi/napi/src/. Either add the #[napi] export or fix the dispatcher.`
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("dispatcher invariant (ADR-048 §1 + §7)", () => {
  test("scp.rs is the sole `impl Scp` host", () => {
    // Sanity check: extractNapiSurface assumes `impl Scp` only lives in scp.rs.
    // If a future change moves `impl Scp` blocks to other files, the static
    // analysis below would silently misclassify those methods as free fns.
    for (const entry of readdirSync(NAPI_SRC_DIR)) {
      if (!entry.endsWith(".rs")) continue;
      if (entry === "scp.rs") continue;
      const src = readFileSync(join(NAPI_SRC_DIR, entry), "utf8");
      expect(/^impl\s+Scp\s*\{/m.test(src)).toBe(false);
    }
  });

  test("extracted surfaces are non-empty", () => {
    const { classMethods, freeFns } = extractNapiSurface();
    // If the parser regresses to zero matches, the test would pass trivially
    // (every dispatch site would fail closed). Guard the parser instead. The
    // thresholds are deliberate floors well below current counts (~180 class
    // methods, ~12 free fns) so they survive ordinary changes — they catch
    // a parser regression that goes from "many" to "few", not exact counts.
    expect(classMethods.size).toBeGreaterThan(50);
    expect(freeFns.size).toBeGreaterThan(8);
  });

  test("known anchors land in the correct surface", () => {
    const { classMethods, freeFns } = extractNapiSurface();

    expect(classMethods.has("identityCreate")).toBe(true);
    expect(classMethods.has("contextCreate")).toBe(true);
    expect(classMethods.has("scpidSign")).toBe(true);
    expect(classMethods.has("bridgeCreateShadow")).toBe(true);
    expect(classMethods.has("instanceId")).toBe(true);

    expect(freeFns.has("discoveryParseAddress")).toBe(true);
    expect(freeFns.has("metadataRecordFromJson")).toBe(true);
    expect(freeFns.has("templateGetParams")).toBe(true);
    expect(freeFns.has("validateAgainstTemplate")).toBe(true);
    expect(freeFns.has("validateContextParams")).toBe(true);
    expect(freeFns.has("contextDiscover")).toBe(true);
    expect(freeFns.has("bridgeRegister")).toBe(true);
    expect(freeFns.has("bridgeEvaluateTrust")).toBe(true);
    expect(freeFns.has("scpVersion")).toBe(true);
  });

  test("every (addon|native).X dispatch site routes to the correct handle", () => {
    const { classMethods, freeFns } = extractNapiSurface();
    const sites = extractDispatchSites();

    expect(sites.length).toBeGreaterThan(50);

    const errors: string[] = [];
    for (const site of sites) {
      const err =
        site.handle === "native"
          ? validateNativeSite(site, classMethods, freeFns)
          : validateAddonSite(site, classMethods, freeFns);
      if (err) errors.push(err);
    }

    if (errors.length > 0) {
      throw new Error(`Dispatcher invariant violations (${errors.length}):\n${errors.join("\n")}`);
    }
  });

  test("intentional class+free overlaps are accounted for", () => {
    // Some names are deliberately exported as BOTH an `Scp` method and a
    // module-level free fn — e.g. `check_scoped_capability` is a pure
    // helper exported both ways so callers may use either entry point.
    // The dispatcher's routing site is unambiguous as long as it routes
    // consistently (the per-site test above checks that). Track known
    // overlaps here so a NEW overlap surfaces as a test diff rather than
    // silently passing.
    const KNOWN_INTENTIONAL_OVERLAPS = new Set<string>([
      // crates/scp-ffi/napi/src/{scp.rs,context.rs} — pure helper exported
      // both as Scp::check_scoped_capability and as a free fn so callers
      // outside an SCP context (test harnesses, examples) can invoke it
      // without constructing an SCP. native.ts routes through the class.
      "checkScopedCapability",
      // crates/scp-ffi/napi/src/{scp.rs,identity.rs} — spec §3.5.4 step 1
      // resolves an issuer's DID document before any signature check, which
      // needs a per-instance resolver, so `Scp::identity_verify_link_attestation`
      // carries that operation. A module-level free fn of that same JS name
      // remains exported and DECLINES with `SCP-IDENT-1060`, because phase D
      // (#1695) deleted every process-wide default bridge instance and it
      // therefore reaches no resolver. Every SDK wrapper — scp.ts, native.ts,
      // Swift, and Kotlin — now routes through that per-instance class method,
      // and that declining free fn stays exported so a caller who reached it
      // by name receives SCP-IDENT-1060 rather than a silent verify-valid
      // (GitHub issue #2335 finding 2).
      //
      // ADR-048 authorizes neither half of this overlap: searching
      // .docs/adrs/ADR-048-scp-multi-instance.md for `verify_link_attestation`
      // returns zero matches, so that document names no identity-link
      // verification operation. GitHub issue #2335 finding 2 decided it, and
      // this entry records that decision rather than an ADR-048 clause.
      "identityVerifyLinkAttestation",
    ]);
    const { classMethods, freeFns } = extractNapiSurface();
    const observed: string[] = [];
    for (const name of classMethods) {
      if (freeFns.has(name)) observed.push(name);
    }
    const unexpected = observed.filter((n) => !KNOWN_INTENTIONAL_OVERLAPS.has(n));
    if (unexpected.length > 0) {
      throw new Error(
        `NAPI name(s) declared as both Scp method AND free fn (NEW overlap, not in known-intentional set): ${unexpected.join(", ")}. ` +
          "If the dual export is intentional, add to KNOWN_INTENTIONAL_OVERLAPS; " +
          "otherwise disambiguate at the Rust source (rename the free fn or remove the duplicate).",
      );
    }
  });
});
