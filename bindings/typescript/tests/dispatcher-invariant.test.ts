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
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

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
    expect(classMethods.has("instanceId")).toBe(true);

    expect(freeFns.has("discoveryParseAddress")).toBe(true);
    expect(freeFns.has("metadataRecordFromJson")).toBe(true);
    expect(freeFns.has("templateGetParams")).toBe(true);
    expect(freeFns.has("validateAgainstTemplate")).toBe(true);
    expect(freeFns.has("validateContextParams")).toBe(true);
    expect(freeFns.has("contextDiscover")).toBe(true);
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

// ---------------------------------------------------------------------------
// Loader invariant: `internal/native.ts` holds the only addon loader
// ---------------------------------------------------------------------------
//
// CRITERION: no file under `tests/` names a `@limn-works/scp-ts-napi-*` platform
// package in code, so every test loads the addon through `loadNativeAddon` in
// `src/internal/native.ts`, the loader CI's assert step verifies.
//
// A test file that builds its own specifier resolves a package the CI wiring
// step never creates — that file's `@limn-works/scp-ts-napi-linux-x64` against
// the loader's `@limn-works/scp-ts-napi-linux-x64-gnu` — catches the resolution
// error in its skip guard, and resolves its whole `describe` to `describe.skip`.
// `bun test` then exits 0 over zero executed NAPI assertions while the ci.yml
// step "Assert the downloaded addon loads and constructs" reports success,
// because that step calls `loadNativeAddon()` and so reads a different
// specifier than the skipped file read. The `SCP class (Phase 4)` suite in
// `scp-class.test.ts` and the whole of `e2e-fullstack.test.ts` skipped that way
// on every run of the `typescript-check` job until this invariant was enforced.

const TESTS_DIR = join(REPO_ROOT, "bindings", "typescript", "tests");
const NAPI_PACKAGE_PREFIX = "@limn-works/scp-ts-napi";

/** Removes block and line comments so prose naming a package is not a hit. */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}

describe("native addon loader invariant", () => {
  test("no file under tests/ names a platform addon package in code", () => {
    const offenders = readdirSync(TESTS_DIR)
      .filter((name) => name.endsWith(".ts"))
      // This file states the criterion, so it names the prefix in order to
      // search for it; every other file naming it resolves the addon itself.
      .filter((name) => name !== basename(__filename))
      .filter((name) =>
        stripComments(readFileSync(join(TESTS_DIR, name), "utf8")).includes(NAPI_PACKAGE_PREFIX),
      );
    expect(offenders).toEqual([]);
  });

  // Negative control: the scan above reports an empty list both when every test
  // routes through the loader and when the scan cannot see the string at all.
  // Reading the one file that must name the packages separates those two cases.
  test("the SDK loader names the platform addon packages", () => {
    expect(stripComments(readFileSync(DISPATCHER_TS, "utf8"))).toContain(NAPI_PACKAGE_PREFIX);
  });
});

// ---------------------------------------------------------------------------
// Skip invariant: only napi-guard.ts decides whether a test runs
// ---------------------------------------------------------------------------
//
// CRITERION: under `tests/`, only code in `napi-guard.ts` turns a test into one
// that does not run, and it does so only when the loader reports the addon
// absent (SCP-VALID-7081). Every real-NAPI file registers its suite through
// `napiSuite`, so an addon that fails to load, or one missing an export the
// file calls, fails the file instead of skipping it.
//
// Two checks enforce it on every `.ts` file under `tests/` except
// `napi-guard.ts`.
//
// 1. Registrar allowlist. Every reference to the `describe`, `test` or `it`
//    that `bun:test` provides is a direct call (`describe(...)`), or a member
//    in `ALLOWED_MEMBERS` that is called on the spot (`it.each(rows)(...)`).
//    The reference is resolved through the TypeScript checker, so a renamed
//    import (`import { describe as d }`) is followed and a local variable that
//    happens to be named `test` is not. An identifier with no declaration in
//    the file is bun's global registrar. Every other reference fails: `.skip`,
//    `.skipIf`, `.todo`, `.if`, `.only`, an element access, an alias, a
//    destructuring, an object shorthand, or passing the registrar as an
//    argument. A namespace, default or dynamic load of `bun:test`, a re-export
//    of it, and a read of a registrar off `globalThis`, `global`, `self` or
//    `window` also fail.
// 2. Load catches. Every `try` whose block contains, at any depth, a
//    `loadNativeAddon(...)` call or a `new SCP(...)` / `new <expr>.SCP(...)`
//    construction, and that has a `catch`, calls `skipReasonIfAddonAbsent(...)`
//    in that `catch`. This keeps a file from swallowing a load failure and then
//    registering its suite conditionally (`if (addon) describe(...)`).
//
// Neither check sees a skip reached through another function or module, such
// as a helper in another file that calls `describe.skip`, or a suite
// registered inside an `if` whose condition does not come from a load catch.

const REGISTRARS = new Set(["describe", "test", "it"]);
const ALLOWED_MEMBERS = new Set(["each", "failing"]);
const GLOBAL_OBJECTS = new Set(["globalThis", "global", "self", "window"]);
const BUN_TEST = "bun:test";
const NAPI_GUARD = "napi-guard.ts";

/** `source` bound by a checker of its own: no lib, no module resolution. */
function boundFile(name: string, source: string): { file: ts.SourceFile; checker: ts.TypeChecker } {
  const fileName = `/${name}`;
  const file = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true);
  const host: ts.CompilerHost = {
    getSourceFile: (n) => (n === fileName ? file : undefined),
    getDefaultLibFileName: () => "/lib.d.ts",
    writeFile: () => {},
    getCurrentDirectory: () => "/",
    getCanonicalFileName: (n) => n,
    useCaseSensitiveFileNames: () => true,
    getNewLine: () => "\n",
    fileExists: (n) => n === fileName,
    readFile: (n) => (n === fileName ? source : undefined),
  };
  const options: ts.CompilerOptions = { noLib: true, noResolve: true, types: [] };
  return { file, checker: ts.createProgram([fileName], options, host).getTypeChecker() };
}

/** Whether `node` names a member or key rather than referring to a value. */
function isNameSlot(node: ts.Identifier): boolean {
  const p = node.parent;
  return (
    ((ts.isPropertyAccessExpression(p) ||
      ts.isPropertyAssignment(p) ||
      ts.isMethodDeclaration(p) ||
      ts.isPropertyDeclaration(p) ||
      ts.isPropertySignature(p) ||
      ts.isMethodSignature(p) ||
      ts.isGetAccessorDeclaration(p) ||
      ts.isSetAccessorDeclaration(p) ||
      ts.isEnumMember(p)) &&
      p.name === node) ||
    (ts.isBindingElement(p) && p.propertyName === node) ||
    (ts.isQualifiedName(p) && p.right === node) ||
    ts.isImportSpecifier(p) ||
    ts.isExportSpecifier(p) ||
    ts.isLabeledStatement(p) ||
    ts.isBreakOrContinueStatement(p)
  );
}

/** Why the registrar reference `node` is not allowed, or `undefined` when it is. */
function referenceForm(node: ts.Identifier): string | undefined {
  const p = node.parent;
  if (ts.isCallExpression(p) && p.expression === node) return undefined;
  const member = ts.isPropertyAccessExpression(p) && p.expression === node ? p : undefined;
  if (
    member &&
    ALLOWED_MEMBERS.has(member.name.text) &&
    ts.isCallExpression(member.parent) &&
    member.parent.expression === member
  )
    return undefined;
  if (member && !ALLOWED_MEMBERS.has(member.name.text)) return `.${member.name.text}`;
  if (member) return `.${member.name.text} not called`;
  if (ts.isElementAccessExpression(p) && p.expression === node) return "element access";
  if (ts.isCallExpression(p) || ts.isNewExpression(p)) return "passed as an argument";
  return "alias";
}

/** The local symbols that `import { describe, test as t, ... }` binds to a registrar. */
function namedRegistrars(bindings: ts.NamedImports, checker: ts.TypeChecker): ts.Symbol[] {
  return bindings.elements.flatMap((el) => {
    const symbol = checker.getSymbolAtLocation(el.name);
    return symbol && REGISTRARS.has((el.propertyName ?? el.name).text) ? [symbol] : [];
  });
}

/**
 * The symbols of the registrars `file` imports from `bun:test`. Reports a
 * default import, a namespace import or a re-export of `bun:test` through `at`.
 */
function bunTestRegistrars(
  file: ts.SourceFile,
  checker: ts.TypeChecker,
  at: (node: ts.Node, form: string) => void,
): Set<ts.Symbol> {
  const imported = new Set<ts.Symbol>();
  for (const stmt of file.statements) {
    if (!ts.isImportDeclaration(stmt) && !ts.isExportDeclaration(stmt)) continue;
    const spec = stmt.moduleSpecifier;
    if (spec === undefined || !ts.isStringLiteral(spec) || spec.text !== BUN_TEST) continue;
    if (ts.isExportDeclaration(stmt)) at(stmt, "re-export of bun:test");
    if (!ts.isImportDeclaration(stmt)) continue;
    const clause = stmt.importClause;
    if (clause?.name) at(clause, "default import of bun:test");
    const bindings = clause?.namedBindings;
    if (bindings && ts.isNamespaceImport(bindings)) at(bindings, "namespace import of bun:test");
    if (bindings && ts.isNamedImports(bindings)) {
      for (const symbol of namedRegistrars(bindings, checker)) imported.add(symbol);
    }
  }
  return imported;
}

/** The disallowed `bun:test` registrar references in `source`, as `line: form`. */
function registrarViolations(name: string, source: string): string[] {
  const { file, checker } = boundFile(name, source);
  const found: string[] = [];
  const at = (node: ts.Node, form: string): void => {
    found.push(`${file.getLineAndCharacterOfPosition(node.getStart(file)).line + 1}: ${form}`);
  };
  const imported = bunTestRegistrars(file, checker, at);
  const isRegistrar = (node: ts.Identifier): boolean => {
    const p = node.parent;
    const symbol =
      ts.isShorthandPropertyAssignment(p) && p.name === node
        ? checker.getShorthandAssignmentValueSymbol(p)
        : checker.getSymbolAtLocation(node);
    if (symbol !== undefined) return imported.has(symbol);
    return REGISTRARS.has(node.text);
  };
  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) return;
    if (ts.isIdentifier(node) && !isNameSlot(node) && isRegistrar(node)) {
      const form = referenceForm(node);
      if (form !== undefined) at(node, form);
    }
    if (ts.isCallExpression(node)) {
      const callee = node.expression;
      const arg = node.arguments[0];
      const loads =
        callee.kind === ts.SyntaxKind.ImportKeyword ||
        (ts.isIdentifier(callee) && callee.text === "require");
      if (loads && arg !== undefined && ts.isStringLiteralLike(arg) && arg.text === BUN_TEST)
        at(node, "dynamic load of bun:test");
    }
    if (
      ts.isPropertyAccessExpression(node) &&
      ts.isIdentifier(node.expression) &&
      GLOBAL_OBJECTS.has(node.expression.text) &&
      REGISTRARS.has(node.name.text)
    )
      at(node, "registrar read off the global object");
    if (
      ts.isElementAccessExpression(node) &&
      ts.isIdentifier(node.expression) &&
      GLOBAL_OBJECTS.has(node.expression.text)
    )
      at(node, "key read off the global object");
    ts.forEachChild(node, visit);
  };
  visit(file);
  return found;
}

/** Whether `node` loads the native addon directly. */
function isAddonLoad(node: ts.Node): boolean {
  if (
    ts.isCallExpression(node) &&
    ts.isIdentifier(node.expression) &&
    node.expression.text === "loadNativeAddon"
  )
    return true;
  if (!ts.isNewExpression(node)) return false;
  const callee = node.expression;
  if (ts.isIdentifier(callee)) return callee.text === "SCP";
  if (ts.isPropertyAccessExpression(callee)) return callee.name.text === "SCP";
  return false;
}

/** Whether `node` calls `skipReasonIfAddonAbsent`. */
function isGuardCall(node: ts.Node): boolean {
  return (
    ts.isCallExpression(node) &&
    ts.isIdentifier(node.expression) &&
    node.expression.text === "skipReasonIfAddonAbsent"
  );
}

/** Whether `root` or any descendant satisfies `predicate`. */
function containsNode(root: ts.Node, predicate: (node: ts.Node) => boolean): boolean {
  if (predicate(root)) return true;
  return ts.forEachChild(root, (child) => containsNode(child, predicate) || undefined) === true;
}

/** The lines of load-reachable `try`/`catch` statements whose `catch` does not ask the guard. */
function unguardedLoadCatches(name: string, source: string): number[] {
  const file = ts.createSourceFile(name, source, ts.ScriptTarget.Latest, true);
  const lines: number[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isTryStatement(node) && node.catchClause && containsNode(node.tryBlock, isAddonLoad)) {
      const guarded = containsNode(node.catchClause.block, isGuardCall);
      if (!guarded) lines.push(file.getLineAndCharacterOfPosition(node.getStart(file)).line + 1);
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  return lines;
}

/** The `.ts` files under `tests/` that the skip invariant covers. */
function checkedTestFiles(): string[] {
  return readdirSync(TESTS_DIR).filter((name) => name.endsWith(".ts") && name !== NAPI_GUARD);
}

describe("test skip invariant", () => {
  test("every bun:test registrar reference outside napi-guard.ts is allowed", () => {
    const names = checkedTestFiles();
    // The check read real files, so it cannot pass over an empty file set.
    expect(names.length).toBeGreaterThan(0);
    const offenders = names.flatMap((name) =>
      registrarViolations(name, readFileSync(join(TESTS_DIR, name), "utf8")).map(
        (v) => `${name}:${v}`,
      ),
    );
    expect(offenders).toEqual([]);
  });

  test("every catch an addon load reaches outside napi-guard.ts calls skipReasonIfAddonAbsent", () => {
    const names = checkedTestFiles();
    expect(names.length).toBeGreaterThan(0);
    const offenders = names.flatMap((name) =>
      unguardedLoadCatches(name, readFileSync(join(TESTS_DIR, name), "utf8")).map(
        (l) => `${name}:${l}`,
      ),
    );
    expect(offenders).toEqual([]);
  });

  // The exclusion names the file that holds the one permitted skip; if that
  // file stopped skipping, the exclusion would name nothing.
  test("napi-guard.ts holds the one permitted skip", () => {
    const source = readFileSync(join(TESTS_DIR, NAPI_GUARD), "utf8");
    expect(registrarViolations(NAPI_GUARD, source)).toContainEqual(
      expect.stringMatching(/: \.skip$/),
    );
  });

  // Controls. Each appends one form to the real lifecycle.test.ts, which
  // imports `it` from bun:test and reaches `describe` and `test` as globals,
  // and expects exactly that form reported on the appended line.
  const LIFECYCLE = "lifecycle.test.ts";
  const lifecycle = readFileSync(join(TESTS_DIR, LIFECYCLE), "utf8");
  const appended = (extra: string): { source: string; line: number } => {
    const source = `${lifecycle}\n${extra}\n`;
    return { source, line: source.split("\n").length - 1 };
  };

  test("the real lifecycle.test.ts passes both checks", () => {
    expect(registrarViolations(LIFECYCLE, lifecycle)).toEqual([]);
    expect(unguardedLoadCatches(LIFECYCLE, lifecycle)).toEqual([]);
  });

  const rejected: [string, string, string][] = [
    ["a skip on the global describe", 'describe.skip("x", () => {});', ".skip"],
    ["a skip on the imported it", 'it.skip("x", () => {});', ".skip"],
    ["skipIf", 'test.skipIf(true)("x", () => {});', ".skipIf"],
    ["todo", 'test.todo("x");', ".todo"],
    ["if", 'describe.if(false)("x", () => {});', ".if"],
    ["only", 'test.only("x", () => {});', ".only"],
    [
      "an allowed member that is not called on the spot",
      "const rows = it.each;",
      ".each not called",
    ],
    ["an element access", 'it["skip"]("x", () => {});', "element access"],
    ["Reflect.get", 'Reflect.get(it, "skip")("x", () => {});', "passed as an argument"],
    ["an alias", 'const d = describe; d("x", () => {});', "alias"],
    ["a destructuring", "const { skip } = test;", "alias"],
    ["an object shorthand", "const registrars = { it };", "alias"],
    [
      "a read off globalThis",
      'globalThis.describe("x", () => {});',
      "registrar read off the global object",
    ],
    [
      "a key read off globalThis",
      'globalThis["describe"]("x", () => {});',
      "key read off the global object",
    ],
    ["a require of bun:test", 'require("bun:test");', "dynamic load of bun:test"],
    ["a dynamic import of bun:test", 'await import("bun:test");', "dynamic load of bun:test"],
  ];
  for (const [label, extra, form] of rejected) {
    test(`the registrar check rejects ${label}`, () => {
      const { source, line } = appended(extra);
      expect(registrarViolations(LIFECYCLE, source)).toEqual([`${line}: ${form}`]);
    });
  }

  const rejectedImports: [string, string, string][] = [
    [
      "a renamed import's skip",
      'import { describe as d } from "bun:test";\nd.skip("x", () => {});',
      ".skip",
    ],
    ["a namespace import", 'import * as bt from "bun:test";', "namespace import of bun:test"],
    ["a default import", 'import bt from "bun:test";', "default import of bun:test"],
    ["a re-export", 'export { describe } from "bun:test";', "re-export of bun:test"],
  ];
  for (const [label, extra, form] of rejectedImports) {
    test(`the registrar check rejects ${label}`, () => {
      const { source } = appended(extra);
      expect(registrarViolations(LIFECYCLE, source).map((v) => v.replace(/^\d+: /, ""))).toEqual([
        form,
      ]);
    });
  }

  const accepted: [string, string][] = [
    ["a called it.each", 'it.each([1])("x %d", () => {});'],
    ["a local variable named test", "{ const test = { skip: 1 }; test.skip; }"],
  ];
  for (const [label, extra] of accepted) {
    test(`the registrar check accepts ${label}`, () => {
      expect(registrarViolations(LIFECYCLE, appended(extra).source)).toEqual([]);
    });
  }

  const unguarded: [string, string][] = [
    ["loadNativeAddon", "try { const a = loadNativeAddon(); void a; } catch {}"],
    ["new SCP", 'try { new SCP({ storage: { type: "in_memory" } }); } catch {}'],
    ["new <expr>.SCP", 'try { new addon.SCP("{}"); } catch {}'],
  ];
  for (const [label, extra] of unguarded) {
    test(`the load-catch check flags a catch around ${label} that skips the guard`, () => {
      const { source, line } = appended(extra);
      expect(unguardedLoadCatches(LIFECYCLE, source)).toEqual([line]);
    });
  }

  test("the load-catch check accepts a catch that asks the guard", () => {
    const { source } = appended(
      "try { loadNativeAddon(); } catch (e) { skipReasonIfAddonAbsent(e); }",
    );
    expect(unguardedLoadCatches(LIFECYCLE, source)).toEqual([]);
  });
});
