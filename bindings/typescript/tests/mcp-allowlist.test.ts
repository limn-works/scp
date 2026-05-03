/**
 * Tests for the SDK-wrapper class's MCP allowlist methods.
 *
 * These verify the per-SDK ergonomic guards that round-2 added — most
 * importantly the `iTrustAllCommands` ceremony around
 * `mcpDisableStdioAllowlist`. The native NAPI surface is mocked via
 * `mountMockScp` so the tests run without a real `@limn-works/scp-ts-napi-*`
 * platform package.
 */

import { describe, expect, test } from "bun:test";

import { createMockNativeScp, mountMockScp } from "./mock-bridge";

describe("SCP.mcpDisableStdioAllowlist ceremony", () => {
  test("throws when iTrustAllCommands is not set", () => {
    const native = createMockNativeScp({ strict: false });
    native.__stub("mcpDisableStdioAllowlist", () => undefined);
    const { scp } = mountMockScp(native);

    expect(() => scp.mcpDisableStdioAllowlist()).toThrow(/iTrustAllCommands.*confirm/i);
    // Native must NOT be called when the ceremony fails.
    expect(native.__calls("mcpDisableStdioAllowlist")).toHaveLength(0);
  });

  test("throws when iTrustAllCommands is explicitly false", () => {
    const native = createMockNativeScp({ strict: false });
    native.__stub("mcpDisableStdioAllowlist", () => undefined);
    const { scp } = mountMockScp(native);

    expect(() => scp.mcpDisableStdioAllowlist({ iTrustAllCommands: false })).toThrow(
      /iTrustAllCommands.*confirm/i,
    );
    expect(native.__calls("mcpDisableStdioAllowlist")).toHaveLength(0);
  });

  test("succeeds when iTrustAllCommands is true and emits a console.warn", () => {
    const native = createMockNativeScp({ strict: false });
    native.__stub("mcpDisableStdioAllowlist", () => undefined);
    const { scp } = mountMockScp(native);

    const warnings: unknown[][] = [];
    const originalWarn = console.warn;
    console.warn = (...args: unknown[]) => {
      warnings.push(args);
    };
    try {
      expect(() => scp.mcpDisableStdioAllowlist({ iTrustAllCommands: true })).not.toThrow();
    } finally {
      console.warn = originalWarn;
    }

    expect(native.__calls("mcpDisableStdioAllowlist")).toHaveLength(1);
    expect(warnings.length).toBe(1);
    const warningMessage = String(warnings[0]?.[0] ?? "");
    expect(warningMessage).toMatch(/allowlist enforcement disabled/i);
  });
});

describe("SCP allowlist plumbing", () => {
  test("mcpConfigureStdioAllowlist forwards binaries to the native handle", () => {
    const native = createMockNativeScp({ strict: false });
    native.__stub("mcpConfigureStdioAllowlist", () => undefined);
    const { scp } = mountMockScp(native);

    scp.mcpConfigureStdioAllowlist(["my-server"]);

    const call = native.__lastCall("mcpConfigureStdioAllowlist");
    expect(call).toBeDefined();
    expect(call?.args[0]).toEqual(["my-server"]);
  });

  test("mcpResetStdioAllowlist forwards a no-arg call", () => {
    const native = createMockNativeScp({ strict: false });
    native.__stub("mcpResetStdioAllowlist", () => undefined);
    const { scp } = mountMockScp(native);

    scp.mcpResetStdioAllowlist();

    expect(native.__calls("mcpResetStdioAllowlist")).toHaveLength(1);
  });

  test("mcpGetStdioAllowlist returns the typed shape unchanged", () => {
    const native = createMockNativeScp({ strict: false });
    native.__stub("mcpGetStdioAllowlist", () => ({
      allowed: ["node", "npx"],
      unrestricted: false,
    }));
    const { scp } = mountMockScp(native);

    const state = scp.mcpGetStdioAllowlist();

    expect(state.allowed).toEqual(["node", "npx"]);
    expect(state.unrestricted).toBe(false);
  });
});
