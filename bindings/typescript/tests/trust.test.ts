/**
 * Tests for the four-layer trust evaluation (`./trust`).
 *
 * Two groups:
 *
 * 1. **UCAN error classification** — pure unit tests over `__extractCoreError`,
 *    `__classifyUcanError`, and `__PASSED_BEFORE`, mirroring the Python SDK's
 *    `test_trust.py` so the cross-SDK classifier stays in lockstep.
 * 2. **`evaluateTrust` Layer-1/Layer-2 integration** — drives the composition
 *    through a Proxy-backed mock native handle (no addon), asserting that each
 *    independent `CapabilityValidation` field is set from the classified UCAN
 *    failure and that the behavioral record is populated from the event log.
 *
 * See ADR-017, spec §9.3, and `bindings/python/tests/test_trust.py`.
 */

import { describe, expect, it } from "bun:test";
import { Context } from "../src/context";
import { ValidationError } from "../src/errors";
import type { SCP } from "../src/scp";
import {
  __classifyUcanError,
  __extractCoreError,
  __PASSED_BEFORE,
  type CapabilityValidation,
  evaluateTrust,
} from "../src/trust";
import { mountMockScp } from "./mock-bridge";

// ---------------------------------------------------------------------------
// __extractCoreError
// ---------------------------------------------------------------------------

describe("__extractCoreError", () => {
  const ADVICE = " — check token format, signatures, time bounds, and capability chain";

  it("strips the code prefix and trailing advice", () => {
    expect(__extractCoreError(`[SCP-PERM-3001] permission error: token expired${ADVICE}`)).toBe(
      "token expired",
    );
  });

  it("strips trailing advice when there is no code prefix", () => {
    expect(__extractCoreError("token expired — advice text")).toBe("token expired");
  });

  it("strips the code prefix when there is no advice suffix", () => {
    expect(__extractCoreError("[SCP-PERM-3001] permission error: token expired")).toBe(
      "token expired",
    );
  });

  it("passes a bare message through unchanged", () => {
    expect(__extractCoreError("token expired")).toBe("token expired");
  });
});

// ---------------------------------------------------------------------------
// __classifyUcanError
// ---------------------------------------------------------------------------

describe("__classifyUcanError", () => {
  // -- Token parse (step 1) --
  it("classifies malformed token as token_parse", () => {
    expect(__classifyUcanError("malformed token: bad base64")).toBe("token_parse");
  });
  it("classifies deserialization failure as token_parse", () => {
    expect(__classifyUcanError("deserialization failed: invalid JSON")).toBe("token_parse");
  });
  it("classifies unsupported algorithm as token_parse", () => {
    expect(__classifyUcanError("unsupported algorithm: expected EdDSA, got RS256")).toBe(
      "token_parse",
    );
  });

  // -- Signature/chain (steps 2-7) --
  it("classifies signature failure as signatures", () => {
    expect(__classifyUcanError("signature verification failed")).toBe("signatures");
  });
  it("classifies audience mismatch as signatures", () => {
    expect(__classifyUcanError("audience mismatch: expected X, got Y")).toBe("signatures");
  });
  it("classifies delegation chain broken as signatures", () => {
    expect(__classifyUcanError("delegation chain broken: aud/iss mismatch")).toBe("signatures");
  });
  it("classifies Category A violation as signatures", () => {
    expect(__classifyUcanError("Category A violation: did_document:update by agent key")).toBe(
      "signatures",
    );
  });
  it("classifies DID-not-found (step 2) as signatures, not token_parse", () => {
    expect(__classifyUcanError("malformed token: DID not found: did:dht:z6MkMissing")).toBe(
      "signatures",
    );
  });
  it("classifies invalid DID document (step 2) as signatures", () => {
    expect(
      __classifyUcanError("malformed token: invalid DID document: BEP44 signature invalid"),
    ).toBe("signatures");
  });

  // -- Capability/ceiling (steps 6, 8) --
  it("classifies capability outside ceiling as ceiling", () => {
    expect(__classifyUcanError("capability outside ceiling: messages:admin")).toBe("ceiling");
  });
  it("classifies unparseable capability URI (step 6) as ceiling, not token_parse", () => {
    expect(
      __classifyUcanError("malformed token: unparseable capability URI in attestation: bad://uri"),
    ).toBe("ceiling");
  });

  // -- Nonce (step 9) --
  it("classifies nonce reused as nonce", () => {
    expect(__classifyUcanError("nonce reused: abc-123")).toBe("nonce");
  });
  it("classifies nonce tracker full as nonce", () => {
    expect(__classifyUcanError("nonce tracker full: capacity 100000 reached")).toBe("nonce");
  });

  // -- Revocation (step 10) --
  it("classifies token revoked as revoked", () => {
    expect(__classifyUcanError("token revoked: bafyabc123")).toBe("revoked");
  });

  // -- Expiry (step 11) --
  it("classifies token expired as expiry", () => {
    expect(__classifyUcanError("token expired")).toBe("expiry");
  });
  it("classifies token not yet valid as expiry", () => {
    expect(__classifyUcanError("token not yet valid")).toBe("expiry");
  });

  // -- Delegation-chain parent failures classify conservatively as signatures --
  it("classifies parent-token expiry (wrapped) as signatures", () => {
    expect(__classifyUcanError("delegation chain broken: parent token failed: token expired")).toBe(
      "signatures",
    );
  });
  it("classifies parent-token revocation (wrapped) as signatures", () => {
    expect(
      __classifyUcanError(
        "delegation chain broken: parent token failed: token revoked: bafyabc123",
      ),
    ).toBe("signatures");
  });

  // -- Unknown --
  it("classifies unrecognized errors as unknown", () => {
    expect(__classifyUcanError("something completely unexpected")).toBe("unknown");
  });

  // -- With full bridge formatting --
  it("handles full bridge prefix + suffix formatting", () => {
    const msg =
      "[SCP-PERM-3001] permission error: token revoked: bafyabc123" +
      " — check token format, signatures, time bounds, and capability chain";
    expect(__classifyUcanError(msg)).toBe("revoked");
  });
});

// ---------------------------------------------------------------------------
// __PASSED_BEFORE pipeline ordering
// ---------------------------------------------------------------------------

describe("__PASSED_BEFORE", () => {
  it("token_parse: nothing passed", () => {
    expect([...__PASSED_BEFORE.token_parse]).toEqual([]);
  });
  it("signatures: tokensValid passed", () => {
    expect([...__PASSED_BEFORE.signatures].sort()).toEqual(["tokensValid"]);
  });
  it("ceiling: tokens + sigs passed", () => {
    expect([...__PASSED_BEFORE.ceiling].sort()).toEqual(["signaturesValid", "tokensValid"]);
  });
  it("nonce: tokens + sigs + ceiling passed", () => {
    expect([...__PASSED_BEFORE.nonce].sort()).toEqual([
      "signaturesValid",
      "tokensValid",
      "withinCeiling",
    ]);
  });
  it("revoked: all except revoked + expiry passed", () => {
    expect([...__PASSED_BEFORE.revoked].sort()).toEqual([
      "nonceValid",
      "signaturesValid",
      "tokensValid",
      "withinCeiling",
    ]);
  });
  it("expiry: all except expiry passed", () => {
    expect([...__PASSED_BEFORE.expiry].sort()).toEqual([
      "nonceValid",
      "notRevoked",
      "signaturesValid",
      "tokensValid",
      "withinCeiling",
    ]);
  });
  it("unknown: nothing passed", () => {
    expect([...__PASSED_BEFORE.unknown]).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// evaluateTrust integration (mock native handle)
// ---------------------------------------------------------------------------

/** Builds a mounted SCP + a Context handle wired to its mock native. */
function mountWithContext(): {
  scp: SCP;
  native: ReturnType<typeof mountMockScp>["native"];
  context: Context;
} {
  const { scp, native } = mountMockScp();
  const rawHandle = { contextId: "ctx-test", state: "active", creatorDid: "did:dht:z6MkCreator" };
  const context = Context._fromHandle(scp, rawHandle, "did:dht:z6MkLocal");
  return { scp, native, context };
}

/**
 * Runs evaluateTrust with a single capability token whose validation fails
 * with `errorMsg`, returning the resulting Layer-1 CapabilityValidation.
 *
 * `errorMsg` must be the full bridge-formatted message string including the
 * `[SCP-PERM-NNNN]` prefix, because the real NAPI bridge throws a plain
 * `Error` (not `UcanPermissionError`) — it bypasses `mapBridgeError`.
 */
async function runLayer1(errorMsg: string): Promise<CapabilityValidation> {
  const { scp, native, context } = mountWithContext();
  native.__stub("ucanValidate", () =>
    // Simulate the real NAPI bridge: plain Error with the full formatted message.
    Promise.reject(new Error(errorMsg)),
  );
  // No event-log history for this subject — Layer 2 is non-fatal.
  native.__stub("eventLogQuery", () => Promise.resolve([]));

  const result = await evaluateTrust(scp, "did:dht:z6MkBob", context, ["fake-token"]);
  return result.capabilityValidation;
}

describe("evaluateTrust — Layer 1 field independence", () => {
  it("all fields pass when validation succeeds", async () => {
    const { scp, native, context } = mountWithContext();
    native.__stub("ucanValidate", () => Promise.resolve(undefined));
    native.__stub("eventLogQuery", () => Promise.resolve([]));

    const result = await evaluateTrust(scp, "did:dht:z6MkBob", context, ["good-token"]);
    const cv = result.capabilityValidation;
    expect(cv.tokensValid).toBe(true);
    expect(cv.signaturesValid).toBe(true);
    expect(cv.withinCeiling).toBe(true);
    expect(cv.nonceValid).toBe(true);
    expect(cv.notRevoked).toBe(true);
    expect(cv.timeBoundsValid).toBe(true);
  });

  it("revoked token: signatures valid, not_revoked false", async () => {
    const cv = await runLayer1("[SCP-PERM-3001] permission error: token revoked: bafyabc123");
    expect(cv.tokensValid).toBe(true);
    expect(cv.signaturesValid).toBe(true);
    expect(cv.withinCeiling).toBe(true);
    expect(cv.nonceValid).toBe(true);
    expect(cv.notRevoked).toBe(false);
    expect(cv.timeBoundsValid).toBe(false);
  });

  it("invalid signature: tokens valid, signatures false, rest false", async () => {
    const cv = await runLayer1("[SCP-PERM-3001] permission error: signature verification failed");
    expect(cv.tokensValid).toBe(true);
    expect(cv.signaturesValid).toBe(false);
    expect(cv.withinCeiling).toBe(false);
    expect(cv.nonceValid).toBe(false);
    expect(cv.notRevoked).toBe(false);
    expect(cv.timeBoundsValid).toBe(false);
  });

  it("expired token: everything else passed, time bounds false", async () => {
    const cv = await runLayer1("[SCP-PERM-3001] permission error: token expired");
    expect(cv.tokensValid).toBe(true);
    expect(cv.signaturesValid).toBe(true);
    expect(cv.withinCeiling).toBe(true);
    expect(cv.nonceValid).toBe(true);
    expect(cv.notRevoked).toBe(true);
    expect(cv.timeBoundsValid).toBe(false);
  });

  it("capability outside ceiling: tokens + sigs valid, ceiling false", async () => {
    const cv = await runLayer1(
      "[SCP-PERM-3001] permission error: capability outside ceiling: messages:admin",
    );
    expect(cv.tokensValid).toBe(true);
    expect(cv.signaturesValid).toBe(true);
    expect(cv.withinCeiling).toBe(false);
    expect(cv.nonceValid).toBe(false);
    expect(cv.notRevoked).toBe(false);
    expect(cv.timeBoundsValid).toBe(false);
  });

  it("malformed token: all false", async () => {
    const cv = await runLayer1("[SCP-PERM-3001] permission error: malformed token: bad base64");
    expect(cv.tokensValid).toBe(false);
    expect(cv.signaturesValid).toBe(false);
    expect(cv.withinCeiling).toBe(false);
    expect(cv.nonceValid).toBe(false);
    expect(cv.notRevoked).toBe(false);
    expect(cv.timeBoundsValid).toBe(false);
  });

  it("nonce reused: parse + sig + ceiling passed, nonce false", async () => {
    const cv = await runLayer1("[SCP-PERM-3001] permission error: nonce reused: abc-123");
    expect(cv.tokensValid).toBe(true);
    expect(cv.signaturesValid).toBe(true);
    expect(cv.withinCeiling).toBe(true);
    expect(cv.nonceValid).toBe(false);
    expect(cv.notRevoked).toBe(false);
    expect(cv.timeBoundsValid).toBe(false);
  });

  it("unknown error: conservatively all false", async () => {
    const cv = await runLayer1("[SCP-PERM-3001] permission error: something completely unexpected");
    expect(cv.tokensValid).toBe(false);
    expect(cv.signaturesValid).toBe(false);
    expect(cv.withinCeiling).toBe(false);
    expect(cv.nonceValid).toBe(false);
    expect(cv.notRevoked).toBe(false);
    expect(cv.timeBoundsValid).toBe(false);
  });

  it("multiple tokens — first valid, second revoked — returns notRevoked: false with prior fields true", async () => {
    const { scp, native, context } = mountWithContext();
    let callCount = 0;
    native.__stub("ucanValidate", () => {
      callCount += 1;
      if (callCount === 1) {
        // First token passes.
        return Promise.resolve(undefined);
      }
      // Second token is revoked.
      return Promise.reject(
        new Error(
          "[SCP-PERM-3001] permission error: token revoked: tok2" +
            " — check token format, signatures, time bounds, and capability chain",
        ),
      );
    });
    native.__stub("eventLogQuery", () => Promise.resolve([]));

    const result = await evaluateTrust(scp, "did:dht:z6MkBob", context, ["token1", "token2"]);
    const cv = result.capabilityValidation;
    // Stages that passed before the revocation failure.
    expect(cv.tokensValid).toBe(true);
    expect(cv.signaturesValid).toBe(true);
    expect(cv.withinCeiling).toBe(true);
    expect(cv.nonceValid).toBe(true);
    // Revocation stage — failed on the second token.
    expect(cv.notRevoked).toBe(false);
    // timeBoundsValid is after revocation in the pipeline — also false.
    expect(cv.timeBoundsValid).toBe(false);
    // Both tokens were presented to ucanValidate.
    expect(native.__calls("ucanValidate")).toHaveLength(2);
  });

  it("no tokens: all fields stay default false", async () => {
    const { scp, native, context } = mountWithContext();
    native.__stub("eventLogQuery", () => Promise.resolve([]));
    // ucanValidate must never be called when no tokens are supplied.
    native.__stub("ucanValidate", () => {
      throw new Error("ucanValidate should not be called with no tokens");
    });

    const result = await evaluateTrust(scp, "did:dht:z6MkBob", context);
    const cv = result.capabilityValidation;
    expect(cv.tokensValid).toBe(false);
    expect(cv.signaturesValid).toBe(false);
    expect(cv.withinCeiling).toBe(false);
    expect(cv.nonceValid).toBe(false);
    expect(cv.notRevoked).toBe(false);
    expect(cv.timeBoundsValid).toBe(false);
    expect(native.__calls("ucanValidate")).toHaveLength(0);
  });

  it("non-UCAN error propagates (not silently classified)", async () => {
    const { scp, native, context } = mountWithContext();
    native.__stub("ucanValidate", () =>
      Promise.reject(
        new ValidationError("context_id contains control characters", "SCP-VALID-7001"),
      ),
    );
    native.__stub("eventLogQuery", () => Promise.resolve([]));

    await expect(
      evaluateTrust(scp, "did:dht:z6MkBob", context, ["fake-token"]),
    ).rejects.toBeInstanceOf(ValidationError);
  });
});

describe("evaluateTrust — Layer 2 behavioral record", () => {
  it("populates the behavioral record from event-log tool invocations", async () => {
    const { scp, native, context } = mountWithContext();
    native.__stub("eventLogQuery", () =>
      Promise.resolve([
        {
          eventType: "ToolInvoked",
          actorDid: "did:dht:z6MkBob",
          timestamp: 1,
          payloadJson: "{}",
          sequence: 1,
        },
        {
          eventType: "MessageSent",
          actorDid: "did:dht:z6MkBob",
          timestamp: 2,
          payloadJson: "{}",
          sequence: 2,
        },
        {
          eventType: "ToolInvoked",
          actorDid: "did:dht:z6MkBob",
          timestamp: 3,
          payloadJson: "{}",
          sequence: 3,
        },
      ]),
    );

    const result = await evaluateTrust(scp, "did:dht:z6MkBob", context);

    expect(result.behavioralRecord).not.toBeNull();
    expect(result.behavioralRecord?.contextsParticipated).toBe(1);
    // Only the two ToolInvoked events are counted.
    expect(result.behavioralRecord?.toolInvocations).toHaveLength(2);
    expect(result.behavioralRecord?.toolInvocations.every((t) => t.type === "ToolInvoked")).toBe(
      true,
    );

    // The event-log query forwarded the context handle and an actor_did filter.
    const call = native.__lastCall("eventLogQuery");
    expect(call?.args[0]).toBe(context._rawHandle);
    expect(JSON.parse(call?.args[1] as string)).toEqual({ actor_did: "did:dht:z6MkBob" });
  });

  it("leaves behavioral record null when the event-log query raises a context error", async () => {
    const { scp, native, context } = mountWithContext();
    // Simulate the real NAPI bridge: plain Error with the [SCP-CTX-NNNN] prefix,
    // because eventLogQuery bypasses mapBridgeError and throws plain Error objects.
    native.__stub("eventLogQuery", () =>
      Promise.reject(
        new Error("[SCP-CTX-1001] context error: not a member — check membership status"),
      ),
    );

    const result = await evaluateTrust(scp, "did:dht:z6MkBob", context);
    expect(result.behavioralRecord).toBeNull();
  });

  it("Layer 2 — non-context error propagates instead of swallowing to null", async () => {
    const { scp, native, context } = mountWithContext();
    // ucanValidate resolves (passes Layer 1)
    native.__stub("ucanValidate", () => Promise.resolve(undefined));
    // eventLogQuery rejects with a non-[SCP-CTX-] error (e.g. a network failure)
    const networkError = new Error("Network timeout");
    native.__stub("eventLogQuery", () => Promise.reject(networkError));

    // The catch block in Layer 2 must re-throw non-context errors — it must NOT
    // swallow them into behavioralRecord: null (which would hide genuine faults).
    await expect(evaluateTrust(scp, "did:dht:z6MkBob", context)).rejects.toBe(networkError);
  });
});

describe("evaluateTrust — result shape", () => {
  it("records the subject DID, context ID, and empty Layer 3/4 collections", async () => {
    const { scp, native, context } = mountWithContext();
    native.__stub("eventLogQuery", () => Promise.resolve([]));

    const result = await evaluateTrust(scp, "did:dht:z6MkBob", context);
    expect(result.subjectDid).toBe("did:dht:z6MkBob");
    expect(result.contextId).toBe("ctx-test");
    expect(result.attestations).toEqual([]);
    expect(result.endorsements).toEqual([]);
    expect(result.challengeResults).toEqual([]);
    expect(result.consequenceStructure).toBeNull();
  });
});
