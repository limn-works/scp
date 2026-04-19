/**
 * SCPID authentication tests for the TypeScript SDK.
 *
 * Tests the SCPID challenge-response authentication flow using the mock
 * bridge. Verifies SDK class logic, JSON serialization, error propagation,
 * and WASM fallback behavior.
 *
 * See spec section 3.11.
 */

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { scpidChallenge, scpidSign, scpidVerify } from "../src/auth";
import { IdentityError } from "../src/errors";
import { Identity } from "../src/identity";
import { _resetBridge, _setBridge } from "../src/internal/bridge";
import { SCP } from "../src/scp";
import { createMockBridge } from "./mock-bridge";

// ---------------------------------------------------------------------------
// Test setup — inject mock bridge
// ---------------------------------------------------------------------------

let mockBridge: ReturnType<typeof createMockBridge>;
let scp: SCP;

beforeEach(() => {
  scp = new SCP();
  mockBridge = createMockBridge();
  _setBridge(scp, mockBridge);
});

afterEach(async () => {
  _resetBridge();
  await scp.shutdown(1);
});

// ---------------------------------------------------------------------------
// Challenge generation
// ---------------------------------------------------------------------------

describe("scpidChallenge", () => {
  it("generates a valid challenge structure", async () => {
    const challenge = await scpidChallenge(scp, "https://example.com", 120);
    expect(challenge.protocol).toBe("scpid/1.0");
    expect(challenge.audience).toBe("https://example.com");
    expect(typeof challenge.nonce).toBe("string");
    expect(challenge.nonce.length).toBe(64);
    expect(typeof challenge.issued_at).toBe("number");
    expect(typeof challenge.expires_at).toBe("number");
    expect(challenge.expires_at).toBeGreaterThan(challenge.issued_at);
  });

  it("uses default TTL of 300 seconds", async () => {
    const challenge = await scpidChallenge(scp, "https://example.com");
    expect(challenge.expires_at - challenge.issued_at).toBe(300 * 1000);
  });

  it("rejects empty audience", async () => {
    await expect(scpidChallenge(scp, "", 60)).rejects.toThrow();
  });

  it("rejects zero TTL", async () => {
    await expect(scpidChallenge(scp, "https://example.com", 0)).rejects.toThrow();
  });

  it("rejects excessive TTL", async () => {
    await expect(scpidChallenge(scp, "https://example.com", 301)).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Full roundtrip: challenge -> sign -> verify
// ---------------------------------------------------------------------------

describe("scpid roundtrip", () => {
  it("challenge -> sign -> verify succeeds", async () => {
    const identity = await Identity.create(scp, { custody: "in_memory" });
    const challenge = await scpidChallenge(scp, "https://example.com", 120);

    const response = await scpidSign(identity, "#active", challenge);
    expect(response.protocol).toBe("scpid/1.0");
    expect(response.did).toBe(identity.did);
    expect(response.signing_key_id).toBe("#active");
    expect(response.audience).toBe("https://example.com");
    expect(response.nonce).toBe(challenge.nonce);

    const auth = await scpidVerify(scp, response, challenge);
    expect(auth.did).toBe(identity.did);
    expect(auth.signing_key_id).toBe("#active");
    expect(typeof auth.signed_at).toBe("number");
  });

  it("sign rejects invalid signing_key_id", async () => {
    const identity = await Identity.create(scp, { custody: "in_memory" });
    const challenge = await scpidChallenge(scp, "https://example.com", 60);

    await expect(scpidSign(identity, "#owner", challenge)).rejects.toThrow(/SCP-IDENT-1034/);
  });

  it("works with #agent signing key", async () => {
    const identity = await Identity.create(scp, { custody: "in_memory" });
    const challenge = await scpidChallenge(scp, "https://agent-service.example.com", 60);

    const response = await scpidSign(identity, "#agent", challenge);
    expect(response.signing_key_id).toBe("#agent");

    const auth = await scpidVerify(scp, response, challenge);
    expect(auth.did).toBe(identity.did);
    expect(auth.signing_key_id).toBe("#agent");
  });
});

// ---------------------------------------------------------------------------
// WASM fallback
// ---------------------------------------------------------------------------

describe("scpidVerify WASM fallback", () => {
  it("throws IdentityError when WASM bridge lacks verify", async () => {
    // Create a bridge that simulates WASM behavior (no verify)
    const wasmLikeBridge = createMockBridge();
    wasmLikeBridge.scpidVerify = (_responseJson: string, _challengeJson: string): string => {
      throw new Error("[SCP-IDENT-1033] SCPID verification is not available in the WASM bridge");
    };
    _resetBridge();
    _setBridge(scp, wasmLikeBridge);

    const identity = await Identity.create(scp, { custody: "in_memory" });
    const challenge = await scpidChallenge(scp, "https://example.com", 60);
    const response = await scpidSign(identity, "#active", challenge);

    await expect(scpidVerify(scp, response, challenge)).rejects.toThrow(IdentityError);
  });
});
