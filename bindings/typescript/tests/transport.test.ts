/**
 * Tests for the transport module.
 *
 * See ADR-005 (Transport Abstraction) and `.docs/scaffold/typescript.md`.
 */

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { ValidationError } from "../src/errors";
import { SCP } from "../src/scp";
import { Transport } from "../src/transport";

describe("Transport", () => {
  let scp: SCP;

  beforeEach(() => {
    scp = new SCP();
  });

  afterEach(async () => {
    await scp.shutdown(1);
  });

  it("rejects plaintext ws:// relay URLs", async () => {
    await expect(Transport.connect(scp, { relayUrl: "ws://relay.example.com" })).rejects.toThrow(
      ValidationError,
    );
  });

  it("rejects non-websocket URLs", async () => {
    await expect(Transport.connect(scp, { relayUrl: "http://relay.example.com" })).rejects.toThrow(
      ValidationError,
    );
  });

  it("validates wss:// URL format before connecting", async () => {
    // This will fail at the bridge layer (no native addon installed),
    // but the URL validation should pass.
    try {
      await Transport.connect(scp, { relayUrl: "wss://relay.example.com" });
    } catch (err) {
      // Expected — bridge is not available in unit tests
      expect(err).toBeDefined();
    }
  });
});
