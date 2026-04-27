/**
 * SCP-OUT-023 AC-7 conformance: InvocationCaveats round-trip through the
 * real NAPI FFI bridge into the UCAN JWT `nb` field.
 *
 * Mirrors `bindings/python/tests/test_caveats_roundtrip.py`. The test:
 *
 *   1. Builds an `InvocationCaveats` object with all 12 fields populated
 *      (camelCase SDK shape).
 *   2. Calls `bridge.ucanMint(handle, did, caps, proofs, caveatsJson)` on
 *      the real native NAPI bridge.
 *   3. base64url-decodes the JWT payload segment (middle dot-segment).
 *   4. Asserts every wire-form caveat field appears in `payload.nb` with
 *      the expected value, and that fields the SDK omitted are NOT present
 *      in `nb` (SCP-OUT-018 `skip_serializing_if = Option::is_none`).
 *
 * The test is gated on the native NAPI bridge being loadable. When the
 * native addon or platform-specific package is not present, all tests skip
 * cleanly — mirroring `pytest.importorskip` in the Python conformance
 * test.
 *
 * Provenance:
 *   - .docs/prds/outlet.json — SCP-OUT-023 AC-7
 *   - .docs/specs/07-trust-validation-and-capabilities.md §7.3.8
 *   - bindings/python/tests/test_caveats_roundtrip.py (reference)
 */

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import type { InvocationCaveats } from "../src/outlets";

// ---------------------------------------------------------------------------
// Native bridge availability guard — mirrors real-napi.test.ts.
// ---------------------------------------------------------------------------

type NativeBridge = Awaited<ReturnType<typeof import("../src/internal/bridge").getBridge>>;
type ServerAddon = {
  relayStartInMemory(): Promise<{
    readonly relayUrl: string;
    readonly relayPort: number;
    readonly isShutdown: boolean;
    shutdown(): void;
  }>;
  configureRelayTransport(relayUrl: string, localDid: string): Promise<void>;
};

let bridge: NativeBridge | null = null;
let serverAddon: ServerAddon | null = null;
let skipReason = "";

try {
  const { createNativeBridge } = await import("../src/internal/native.js");
  bridge = createNativeBridge();

  const { createRequire } = await import("node:module");
  const req = createRequire(import.meta.url);
  const platform = process.platform;
  const arch = process.arch;
  const platformMap: Record<string, string> = {
    "linux-x64": "@limn-works/scp-ts-napi-linux-x64-gnu",
    "linux-arm64": "@limn-works/scp-ts-napi-linux-arm64-gnu",
    "darwin-x64": "@limn-works/scp-ts-napi-darwin-x64",
    "darwin-arm64": "@limn-works/scp-ts-napi-darwin-arm64",
    "win32-x64": "@limn-works/scp-ts-napi-win32-x64-msvc",
  };
  const pkg = platformMap[`${platform}-${arch}`];
  if (pkg) {
    serverAddon = req(pkg) as ServerAddon;
  } else {
    skipReason = `No native addon for ${platform}-${arch}`;
  }
} catch (e: unknown) {
  const msg = e instanceof Error ? e.message : String(e);
  skipReason = `Native NAPI bridge not available: ${msg}`;
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/** base64url decode a string (with padding fixup) into a UTF-8 string. */
function base64urlDecode(input: string): string {
  // bun supports base64url natively via Buffer.from(..., "base64url").
  return Buffer.from(input, "base64url").toString("utf8");
}

/** Decode a UCAN JWT's payload (middle base64url segment) into an object. */
function decodeJwtPayload(encoded: string): Record<string, unknown> {
  const parts = encoded.split(".");
  if (parts.length !== 3) {
    throw new Error(`invalid JWT: expected 3 segments, got ${parts.length}`);
  }
  const payloadSegment = parts[1];
  if (payloadSegment === undefined || payloadSegment.length === 0) {
    throw new Error("JWT payload segment missing or empty");
  }
  return JSON.parse(base64urlDecode(payloadSegment)) as Record<string, unknown>;
}

/**
 * Serialize an `InvocationCaveats` into the bridge's wire JSON, mirroring
 * `caveatsToJson` in `bindings/typescript/src/ucan.ts`. Inlined here so the
 * test exercises the bridge contract directly without depending on the
 * SDK's mint wrapper indirection.
 */
function caveatsToWireJson(c: InvocationCaveats): string {
  const wire: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(c)) {
    if (value === undefined) continue;
    if (key === "rateWindow" && typeof value === "number") {
      wire[key] = { max: 1, windowSecs: value };
    } else {
      wire[key] = value;
    }
  }
  return JSON.stringify(wire);
}

// ---------------------------------------------------------------------------
// Test suite.
// ---------------------------------------------------------------------------

if (bridge === null || serverAddon === null) {
  describe("SCP-OUT-023 caveats round-trip (SKIPPED)", () => {
    test.skip(`real NAPI bridge unavailable: ${skipReason}`, () => {});
  });
} else {
  const napi = bridge;
  const addon = serverAddon;

  describe("SCP-OUT-023 AC-7: caveats round-trip via real NAPI", () => {
    let relayHandle: Awaited<ReturnType<typeof addon.relayStartInMemory>> | null = null;

    beforeAll(async () => {
      relayHandle = await addon.relayStartInMemory();
      // Bootstrap identity must precede configureRelayTransport so the
      // ContextManager OnceLock is initialised with a real DID.
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const bootstrap = await napi.identityCreate("in_memory");
      await addon.configureRelayTransport(relayHandle.relayUrl, bootstrap.did);
    });

    afterAll(async () => {
      await napi.shutdown(1000);
      if (relayHandle && !relayHandle.isShutdown) {
        relayHandle.shutdown();
      }
    });

    test("all 12 InvocationCaveats fields survive marshal-unmarshal in JWT nb", async () => {
      // Cross-delegation: admin mints for member (avoids ADR-039 self-mint).
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const admin = await napi.identityCreate("in_memory");
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const member = await napi.identityCreate("in_memory");
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const ctx = await napi.contextCreate(
        admin,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write"],
          memoryScope: "ephemeral",
        }),
      );

      // §7.3.8 mint-limit: at most MAX_POPULATED_CAVEATS = 8 non-origin_kind
      // fields populated per envelope (origin_kind is structural and exempt).
      // We populate 8 budgeted fields covering both numeric ceilings and the
      // two list fields, plus origin_kind — the maximum mintable shape.
      const caveats: InvocationCaveats = {
        amountMaxPerCall: 100,
        amountMaxCumulative: 1_000,
        validFrom: 1_700_000_000,
        validUntil: 1_700_003_600,
        maxCalls: 42,
        rateWindow: 60, // 60s — wrapped into {max: 1, windowSecs: 60} on the wire
        // hoursOfDay / daysOfWeek / inputSchema deliberately omitted to stay
        // within the 8-populated-field cap; the absent-field assertions below
        // verify they do not appear in `nb`.
        allowedAdapters: ["native", "openai-compatible"],
        allowedTargetDids: ["did:dht:zMember", "did:dht:zOther"],
        originKind: "Action", // not counted toward the 8-field budget
      };

      const caveatsJson = caveatsToWireJson(caveats);

      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const token = await napi.ucanMint(
        ctx,
        member.did,
        ["messages:write"],
        undefined,
        caveatsJson,
      );

      expect(token.encoded).toBeTruthy();
      expect(typeof token.encoded).toBe("string");

      const payload = decodeJwtPayload(token.encoded);
      expect(payload).toHaveProperty("nb");
      const nb = payload["nb"] as Record<string, unknown>;
      expect(nb).toBeTruthy();

      // AC-7: every populated input field round-trips byte-for-byte.
      expect(nb["amountMaxPerCall"]).toBe(100);
      expect(nb["amountMaxCumulative"]).toBe(1_000);
      expect(nb["validFrom"]).toBe(1_700_000_000);
      expect(nb["validUntil"]).toBe(1_700_003_600);
      expect(nb["maxCalls"]).toBe(42);
      // rateWindow is normalized to the {max, windowSecs} wire shape.
      expect(nb["rateWindow"]).toEqual({ max: 1, windowSecs: 60 });
      expect(nb["allowedAdapters"]).toEqual(["native", "openai-compatible"]);
      expect(nb["allowedTargetDids"]).toEqual(["did:dht:zMember", "did:dht:zOther"]);
      expect(nb["originKind"]).toBe("Action");

      // Absent fields are omitted, never serialized as null
      // (SCP-OUT-018: skip_serializing_if = "Option::is_none").
      expect(nb).not.toHaveProperty("hoursOfDay");
      expect(nb).not.toHaveProperty("daysOfWeek");
      expect(nb).not.toHaveProperty("inputSchema");
    });

    test("hoursOfDay, daysOfWeek, inputSchema also round-trip via nb", async () => {
      // The 8-populated-field cap (§7.3.8 mint-limits) prevents covering all 12
      // fields in a single mint. This second mint covers the three fields the
      // primary test omitted, so the two tests together exercise every field.
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const admin = await napi.identityCreate("in_memory");
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const member = await napi.identityCreate("in_memory");
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const ctx = await napi.contextCreate(admin, JSON.stringify({ ceiling: ["messages:read"] }));

      const caveats: InvocationCaveats = {
        hoursOfDay: 0x00ff_ffff, // 24-bit mask: every hour allowed
        daysOfWeek: 0x7f, // 7-bit mask: every day allowed
        inputSchema: {
          type: "object",
          properties: { x: { type: "number" } },
          required: ["x"],
        },
        originKind: "Query",
      };

      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const token = await napi.ucanMint(
        ctx,
        member.did,
        ["messages:read"],
        undefined,
        caveatsToWireJson(caveats),
      );
      const payload = decodeJwtPayload(token.encoded);
      const nb = payload["nb"] as Record<string, unknown>;
      expect(nb["hoursOfDay"]).toBe(0x00ff_ffff);
      expect(nb["daysOfWeek"]).toBe(0x7f);
      expect(nb["inputSchema"]).toEqual({
        type: "object",
        properties: { x: { type: "number" } },
        required: ["x"],
      });
      expect(nb["originKind"]).toBe("Query");

      // Fields the SDK did not populate must be omitted from `nb`.
      expect(nb).not.toHaveProperty("amountMaxPerCall");
      expect(nb).not.toHaveProperty("amountMaxCumulative");
      expect(nb).not.toHaveProperty("validFrom");
      expect(nb).not.toHaveProperty("validUntil");
      expect(nb).not.toHaveProperty("maxCalls");
      expect(nb).not.toHaveProperty("rateWindow");
      expect(nb).not.toHaveProperty("allowedAdapters");
      expect(nb).not.toHaveProperty("allowedTargetDids");
    });

    test("mint-limit violation surfaces SCP-TOOL-6114 slug (AC-6)", async () => {
      // Mirrors bindings/python/tests/test_caveats_roundtrip.py
      // ::test_mint_limit_violation_surfaces_slug. 9 populated non-origin
      // fields exceeds MAX_POPULATED_CAVEATS = 8.
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const admin = await napi.identityCreate("in_memory");
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const member = await napi.identityCreate("in_memory");
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const ctx = await napi.contextCreate(admin, JSON.stringify({ ceiling: ["messages:read"] }));

      const overCap: InvocationCaveats = {
        amountMaxPerCall: 1,
        amountMaxCumulative: 2,
        validFrom: 3,
        validUntil: 4,
        hoursOfDay: 0x00ff_ffff,
        daysOfWeek: 0x7f,
        maxCalls: 5,
        rateWindow: 60,
        inputSchema: { type: "object" }, // 9th populated field
      };

      await expect(
        // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
        napi.ucanMint(ctx, member.did, ["messages:read"], undefined, caveatsToWireJson(overCap)),
      ).rejects.toThrow(/caveat-mint-limit-exceeded/);
    });
  });
}
