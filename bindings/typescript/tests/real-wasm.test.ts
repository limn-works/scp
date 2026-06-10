/**
 * WASM-path invariants for the SCP TypeScript SDK.
 *
 * Phase 4 PR 5 (#1549, ADR-048) collapsed this file from 28 bridge-level
 * integration tests to two module-level invariants. Two things happened
 * upstream that made every original test obsolete:
 *
 * 1. Agent A deleted every free-function shim on the module surface
 *    (`provenance_attach`, `event_log_query`, `ucan_validate`,
 *    `identity_create`, `context_create`, `context_join`,
 *    `context_leave`, `sync_classify_offline`, `bridge_evaluate_trust`,
 *    `version`, etc.). The WASM adapter in `src/internal/wasm.ts` now
 *    exists only to back SDK operations that are safe in the browser —
 *    the 28 tests here exercised it directly and have no API to call.
 *
 * 2. ADR-048 + ADR-034 wired the caller-owned `SCP` class onto the NAPI
 *    bridge only. `new SCP({ storage: { type: "in_memory" } })` is explicitly NOT supported on the WASM
 *    build: attempting it throws `ValidationError` with code
 *    `SCP-VALID-7005`. The browser build of `@limn-works/scp-ts` has no
 *    multi-instance surface — `SCP` state and context handles are
 *    intentionally NAPI-only.
 *
 * The residual tests in this file:
 *
 * - Assert that `new SCP({ storage: { type: "in_memory" } })` throws `SCP-VALID-7005` whenever the
 *   environment advertises itself as a non-Node runtime (i.e. the WASM
 *   build path). The check lives in `nativeScp()` inside `src/scp.ts`
 *   and runs before addon loading, so stubbing `process.versions.node`
 *   is sufficient to exercise it deterministically under Bun.
 *
 * - Exercise the pure-data validators that remain reachable from a
 *   browser (`validateBroadcastKeyHex`, `validateAdmission`). Those are
 *   module-level helpers with no bridge state, so they run on every
 *   target including WASM.
 *
 * Anything new that tests a WASM bridge path at the transport level
 * belongs in `e2e-cross-bridge.test.ts`, not here.
 */

import { describe, expect, test } from "bun:test";

import { validateAdmission, validateBroadcastKeyHex } from "../src/index";

// ---------------------------------------------------------------------------
// 1. `new SCP({ storage: { type: "in_memory" } })` throws `SCP-VALID-7005` on the WASM build path.
// ---------------------------------------------------------------------------
//
// The SCP class constructor calls `nativeScp()`, which short-circuits
// with `SCP-VALID-7005` when `process.versions.node` is unset — that is
// the WASM build path. `nativeScp()` caches the resolved addon in a
// module-level `_nativeScp`, so a simple in-process stub of
// `process.versions` only fires the check on the first `new SCP({ storage: { type: "in_memory" } })` in
// a bun worker. Other test files (e.g. `scp-class.test.ts`,
// `real-napi.test.ts`) race this one — whichever loads first wins the
// cache, so the stub is unreliable within the same process.
//
// Instead, we spawn a fresh Bun subprocess that loads the SCP module
// from scratch with a globally patched `process` object. The
// subprocess never touches the real NAPI addon, so the cache is
// irrelevant and the `SCP-VALID-7005` path runs deterministically.

describe("SCP class is unavailable on the WASM build path (ADR-034 / ADR-048)", () => {
  test("new SCP() throws ValidationError SCP-VALID-7005 when process.versions.node is absent", async () => {
    const script = `
      // Strip Node/Bun markers from process.versions BEFORE the SCP
      // module is imported, so the module-level cache never has a
      // chance to resolve the NAPI addon.
      const patched = { ...process.versions };
      delete patched.node;
      delete patched.bun;
      Object.defineProperty(process, "versions", { value: patched });

      const { SCP } = await import("${import.meta.dir}/../src/scp.ts");

      let code = null;
      let message = "";
      try {
        new SCP({ storage: { type: "in_memory" } });
      } catch (err) {
        code = err && typeof err === "object" && "code" in err ? err.code : null;
        message = err && typeof err === "object" && "message" in err ? String(err.message) : "";
      }

      process.stdout.write(JSON.stringify({ code, message }));
    `;
    const proc = Bun.spawn({
      cmd: ["bun", "-e", script],
      stdout: "pipe",
      stderr: "pipe",
    });
    const stdout = await new Response(proc.stdout).text();
    await proc.exited;

    expect(stdout).not.toBe("");
    const parsed = JSON.parse(stdout) as { code: string | null; message: string };
    expect(parsed.code).toBe("SCP-VALID-7005");
    expect(parsed.message).toMatch(/WASM/i);
  });
});

// ---------------------------------------------------------------------------
// 2. Pure-data validators remain reachable in a WASM/browser environment.
// ---------------------------------------------------------------------------
//
// These validators live in `src/types.ts` and do no FFI work — they run
// regardless of bridge target. Keeping a small suite here documents that
// the browser build still carries functional input validation so
// callers can fail fast before touching any transport.

describe("Pure-data validators (WASM-safe module-level helpers)", () => {
  describe("validateBroadcastKeyHex", () => {
    test("accepts a valid 64-char hex string", () => {
      const key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
      expect(() => validateBroadcastKeyHex(key)).not.toThrow();
    });

    test("accepts mixed-case hex", () => {
      const key = "AABBccDDeeFF001122334455667788990011223344556677889900AABBccDDeeFF";
      // 66 chars — too long. Use an exact 64-char mixed-case string.
      const mixed = "AaBbCcDdEeFf00112233445566778899aabbccddeeff0011223344556677AABB";
      // Sanity: the invalid key above is 66 chars; confirm our assertion
      // uses the 64-char variant.
      expect(key.length).toBe(66);
      expect(mixed.length).toBe(64);
      expect(() => validateBroadcastKeyHex(mixed)).not.toThrow();
    });

    test("rejects strings shorter than 64 chars", () => {
      expect(() => validateBroadcastKeyHex("abc")).toThrow(/64 hex characters/);
    });

    test("rejects strings longer than 64 chars", () => {
      const tooLong = "0".repeat(65);
      expect(() => validateBroadcastKeyHex(tooLong)).toThrow(/64 hex characters/);
    });

    test("rejects non-hex characters", () => {
      const bad = "zz112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
      expect(() => validateBroadcastKeyHex(bad)).toThrow(/64 hex characters/);
    });

    test("rejects the empty string", () => {
      expect(() => validateBroadcastKeyHex("")).toThrow(/64 hex characters/);
    });
  });

  describe("validateAdmission", () => {
    test("accepts 'open' and 'gated'", () => {
      expect(() => validateAdmission("open")).not.toThrow();
      expect(() => validateAdmission("gated")).not.toThrow();
    });

    test("accepts the capitalized spellings", () => {
      expect(() => validateAdmission("Open")).not.toThrow();
      expect(() => validateAdmission("Gated")).not.toThrow();
    });

    test("rejects unknown admission policies", () => {
      expect(() => validateAdmission("private")).toThrow(/Open|Gated/);
    });

    test("rejects the empty string", () => {
      expect(() => validateAdmission("")).toThrow(/Open|Gated/);
    });
  });
});
