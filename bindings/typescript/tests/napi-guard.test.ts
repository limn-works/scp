/**
 * Tests for the absent-versus-load-failed separation in the native addon
 * loader, the `SCP` wrapper's mapping of loader errors, and the skip rule
 * every real-NAPI test file applies (`tests/napi-guard.ts`).
 *
 * None of these tests needs the real addon: the loader tests build a package
 * in a temporary `node_modules`, and the guard tests pass a stand-in loader.
 */

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ScpError, ValidationError } from "../src/errors";
import {
  NATIVE_ADDON_ABSENT_CODE,
  NATIVE_ADDON_LOAD_FAILED_CODE,
  requireNativeAddon,
} from "../src/internal/native";
import { addonLoadError, requireAddonExport } from "../src/scp";
import { skipReasonIfAddonAbsent } from "./napi-guard";

const BROKEN_PACKAGE = "scp-broken-native-addon";
let root = "";

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "scp-napi-guard-"));
  const pkgDir = join(root, "node_modules", BROKEN_PACKAGE);
  mkdirSync(pkgDir, { recursive: true });
  writeFileSync(
    join(pkgDir, "package.json"),
    JSON.stringify({ name: BROKEN_PACKAGE, version: "0.0.0", main: "index.node" }),
  );
  // Not a shared library, so `dlopen` rejects it: the shape of an addon built
  // for another platform or truncated in transit.
  writeFileSync(join(pkgDir, "index.node"), "this is not a native addon");
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

describe("requireNativeAddon", () => {
  test("a package that does not resolve is reported as absent", () => {
    const req = createRequire(join(root, "entry.js"));
    let caught: unknown;
    try {
      requireNativeAddon("scp-native-addon-that-is-not-installed", req);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ValidationError);
    expect((caught as ScpError).code).toBe(NATIVE_ADDON_ABSENT_CODE);
  });

  test("a package that resolves and fails to load is reported as a load failure", () => {
    const req = createRequire(join(root, "entry.js"));
    let caught: unknown;
    try {
      requireNativeAddon(BROKEN_PACKAGE, req);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ScpError);
    expect(caught).not.toBeInstanceOf(ValidationError);
    expect((caught as ScpError).code).toBe(NATIVE_ADDON_LOAD_FAILED_CODE);
    expect((caught as ScpError).message).toContain(join(BROKEN_PACKAGE, "index.node"));
    expect((caught as Error & { cause?: unknown }).cause).toBeInstanceOf(Error);
  });
});

describe("SCP wrapper mapping of loader errors", () => {
  test("a load failure keeps the load-failure code", () => {
    const loadFailure = new ScpError("dlopen failed", NATIVE_ADDON_LOAD_FAILED_CODE);
    expect(addonLoadError(loadFailure)).toBe(loadFailure);
  });

  test("absence keeps the absence code and gains the reinstall instruction", () => {
    const mapped = addonLoadError(new ValidationError("not installed", NATIVE_ADDON_ABSENT_CODE));
    expect(mapped).toBeInstanceOf(ValidationError);
    expect(mapped.code).toBe(NATIVE_ADDON_ABSENT_CODE);
    expect(mapped.message).toContain("bun install");
  });

  test("an unclassified loader error is a load failure, never absence", () => {
    const cause = new Error("libc probe failed");
    const mapped = addonLoadError(cause);
    expect(mapped).toBeInstanceOf(ScpError);
    expect(mapped).not.toBeInstanceOf(ValidationError);
    expect(mapped.code).toBe(NATIVE_ADDON_LOAD_FAILED_CODE);
    expect((mapped as Error & { cause?: unknown }).cause).toBe(cause);
  });

  test("a thrown non-Error value is a load failure, never absence", () => {
    const mapped = addonLoadError("abi mismatch");
    expect(mapped.code).toBe(NATIVE_ADDON_LOAD_FAILED_CODE);
    expect(mapped.message).toContain("abi mismatch");
  });

  test("an ScpError with another code is returned unchanged", () => {
    const other = new ScpError("unsupported runtime", "SCP-VALID-7005");
    expect(addonLoadError(other)).toBe(other);
  });
});

describe("native-load codes", () => {
  // The Python SDK raises these same literals (scp_sdk/_extension.py), and
  // .docs/standards/sdk-common.md registers them. A skip guard in either SDK
  // keys on them, so each must be a registered in-range code, not a sentinel.
  test("absence and load failure carry the registered shared codes", () => {
    expect(NATIVE_ADDON_ABSENT_CODE).toBe("SCP-VALID-7081");
    expect(NATIVE_ADDON_LOAD_FAILED_CODE).toBe("SCP-VALID-7082");
  });
});

describe("SCP wrapper check of a loaded addon's exports", () => {
  const cases: Array<[string, string]> = [
    ["the SCP class", "SCP"],
    ["a module-level free function", "templateGetParams"],
  ];

  for (const [label, name] of cases) {
    test(`an addon that loaded without ${label} is a load failure, not absence`, () => {
      let caught: unknown;
      try {
        requireAddonExport({}, name);
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(ScpError);
      expect(caught).not.toBeInstanceOf(ValidationError);
      expect((caught as ScpError).code).toBe(NATIVE_ADDON_LOAD_FAILED_CODE);
      expect((caught as ScpError).message).toContain(name);
    });
  }

  test("an addon that exports the name returns it", () => {
    const fn = () => "ok";
    expect(requireAddonExport<typeof fn>({ SCP: fn }, "SCP")).toBe(fn);
  });
});

describe("skipReasonIfAddonAbsent", () => {
  const guardError = new Error("SCP wrapper constructor threw");

  test("returns a skip reason when the loader reports absence", () => {
    const reason = skipReasonIfAddonAbsent(guardError, () => {
      throw new ValidationError("no addon for this platform", NATIVE_ADDON_ABSENT_CODE);
    });
    expect(reason).toContain("no addon for this platform");
  });

  test("throws the loader's error when the addon is installed and failed to load", () => {
    const loadFailure = new ScpError("dlopen failed", NATIVE_ADDON_LOAD_FAILED_CODE);
    expect(() =>
      skipReasonIfAddonAbsent(guardError, () => {
        throw loadFailure;
      }),
    ).toThrow(loadFailure);
  });

  test("throws the guard's error when the addon loads", () => {
    expect(() => skipReasonIfAddonAbsent(guardError, () => ({}))).toThrow(guardError);
  });
});
