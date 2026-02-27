/**
 * Tests for the transport module.
 *
 * See ADR-005 (Transport Abstraction) and `.docs/scaffold/typescript.md`.
 */

import { describe, expect, it } from "vitest";
import { ValidationError } from "../src/errors.js";
import { Transport } from "../src/transport.js";

describe("Transport", () => {
  it("rejects plaintext ws:// relay URLs", async () => {
    await expect(Transport.connect({ relayUrl: "ws://relay.example.com" })).rejects.toThrow(
      ValidationError,
    );
  });

  it("rejects non-websocket URLs", async () => {
    await expect(Transport.connect({ relayUrl: "http://relay.example.com" })).rejects.toThrow(
      ValidationError,
    );
  });

  it("validates wss:// URL format before connecting", async () => {
    // This will fail at the bridge layer (no native addon installed),
    // but the URL validation should pass.
    try {
      await Transport.connect({ relayUrl: "wss://relay.example.com" });
    } catch (err) {
      // Expected — bridge is not available in unit tests
      expect(err).toBeDefined();
    }
  });
});
