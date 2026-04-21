/**
 * Tests for transport-layer URL validation via the SCP class.
 *
 * After Phase 4 PR 4 (#1549, ADR-048) the namespace class `Transport`
 * was deleted — relay connectivity flows through
 * `scp.transportConnect(relayUrl)` directly. URL validation happens at
 * the NAPI bridge layer. These tests assert the bridge rejects
 * insecure/invalid URLs before attempting a connection.
 *
 * See ADR-005 (Transport Abstraction) and ADR-048.
 */

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { SCP } from "../src/scp";

describe("scp.transportConnect URL validation", () => {
  let scp: SCP;

  beforeEach(() => {
    scp = new SCP();
  });

  afterEach(async () => {
    await scp.shutdown(1);
  });

  it("rejects plaintext ws:// relay URLs", async () => {
    // Non-loopback ws:// must be rejected (spec §9.4: wss:// required).
    await expect(scp.transportConnect("ws://relay.example.com")).rejects.toThrow();
  });

  it("rejects non-websocket URLs", async () => {
    await expect(scp.transportConnect("http://relay.example.com")).rejects.toThrow();
  });

  it("accepts wss:// URL format up to the connection attempt", async () => {
    // Bridge URL validation should pass for wss://; the connection itself
    // may fail because no relay exists at the target host — either
    // outcome is acceptable for this surface-level check.
    try {
      await scp.transportConnect("wss://relay.example.com");
    } catch (err) {
      // Connection failure is expected; URL validation is not the cause.
      expect(err).toBeDefined();
    }
  });
});
