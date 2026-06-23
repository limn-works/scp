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
import { ScpError, UcanPermissionError, ValidationError } from "../src/errors";
import type { SCP } from "../src/scp";
import {
  __classifyUcanError,
  __extractAllCapabilityUris,
  __extractCoreError,
  __PASSED_BEFORE,
  type CapabilityValidation,
  evaluateTrust,
} from "../src/trust";
import { mountMockScp } from "./mock-bridge";

// ---------------------------------------------------------------------------
// Mock UCAN token construction
// ---------------------------------------------------------------------------

/**
 * The capability URI declared by {@link makeMockToken}. `evaluateTrust` extracts
 * `att[0].with` from the (unverified) JWT payload and passes it to
 * `scp.ucanValidate`, so a mock token must carry a real `att` entry.
 */
const MOCK_CAP_URI = "scp:ctx:test-context/messages:write";

/**
 * Builds a minimally-valid UCAN JWT string: a `header.payload.signature`
 * triple whose base64url payload declares one capability in `att[0].with`.
 * The signature segment is a placeholder — the mock `ucanValidate` never
 * verifies it; `evaluateTrust` only reads the payload to pick the URI.
 */
function makeMockToken(capUri: string = MOCK_CAP_URI): string {
  const b64url = (obj: unknown): string =>
    Buffer.from(JSON.stringify(obj), "utf8").toString("base64url");
  const header = b64url({ alg: "EdDSA", typ: "JWT", ucv: "0.10.0" });
  const payload = b64url({ att: [{ with: capUri, can: "messages/write" }] });
  return `${header}.${payload}.sig`;
}

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
// __extractAllCapabilityUris
// ---------------------------------------------------------------------------

describe("__extractAllCapabilityUris", () => {
  const b64url = (obj: unknown): string =>
    Buffer.from(JSON.stringify(obj), "utf8").toString("base64url");

  it("returns all att[i].with values from a multi-att JWT payload", () => {
    const token = `${b64url({ alg: "EdDSA" })}.${b64url({
      att: [
        { with: "scp:ctx:c/a:read" },
        { with: "scp:ctx:c/b:write" },
        { with: "scp:ctx:c/c:admin" },
      ],
    })}.sig`;
    expect(__extractAllCapabilityUris(token)).toEqual([
      "scp:ctx:c/a:read",
      "scp:ctx:c/b:write",
      "scp:ctx:c/c:admin",
    ]);
  });

  it("returns [uri] for a single-att JWT payload", () => {
    const token = `${b64url({ alg: "EdDSA" })}.${b64url({
      att: [{ with: "scp:ctx:c/messages:write" }],
    })}.sig`;
    expect(__extractAllCapabilityUris(token)).toEqual(["scp:ctx:c/messages:write"]);
  });

  it("skips att entries where with is missing or empty", () => {
    const token = `${b64url({ alg: "EdDSA" })}.${b64url({
      att: [{ can: "x" }, { with: "scp:ctx:c/a:read" }, { with: "" }],
    })}.sig`;
    expect(__extractAllCapabilityUris(token)).toEqual(["scp:ctx:c/a:read"]);
  });

  it("returns null for a token that is not a JWT triple", () => {
    expect(__extractAllCapabilityUris("not-a-jwt")).toBeNull();
  });

  it("returns null when the payload is not valid base64url JSON", () => {
    expect(__extractAllCapabilityUris("header.@@@notbase64@@@.sig")).toBeNull();
  });

  it("returns null when att is empty", () => {
    const token = `${b64url({ alg: "EdDSA" })}.${b64url({ att: [] })}.sig`;
    expect(__extractAllCapabilityUris(token)).toBeNull();
  });

  it("returns null when all att entries have missing/empty with", () => {
    const token = `${b64url({ alg: "EdDSA" })}.${b64url({
      att: [{ can: "x" }, { with: "" }],
    })}.sig`;
    expect(__extractAllCapabilityUris(token)).toBeNull();
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
 * `[SCP-PERM-NNNN]` prefix. The native bridge throws a plain `Error`;
 * `scp.ucanValidate` wraps it via `mapBridgeError` into a typed `ScpError`
 * whose message preserves that prefix, and trust.ts classifies on the prefix.
 */
async function runLayer1(errorMsg: string): Promise<CapabilityValidation> {
  const { scp, native, context } = mountWithContext();
  native.__stub("ucanValidate", () =>
    // Simulate the native bridge: plain Error with the full formatted message.
    // The SDK wrapper re-types it; the message (and prefix) survive verbatim.
    Promise.reject(new Error(errorMsg)),
  );
  // No event-log history for this subject — Layer 2 is non-fatal.
  native.__stub("eventLogQuery", () => Promise.resolve([]));

  const result = await evaluateTrust(scp, "did:dht:z6MkBob", context, [makeMockToken()]);
  return result.capabilityValidation;
}

describe("evaluateTrust — Layer 1 field independence", () => {
  it("all fields pass when validation succeeds", async () => {
    const { scp, native, context } = mountWithContext();
    native.__stub("ucanValidate", () => Promise.resolve(undefined));
    native.__stub("eventLogQuery", () => Promise.resolve([]));

    const result = await evaluateTrust(scp, "did:dht:z6MkBob", context, [makeMockToken()]);
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

    const result = await evaluateTrust(scp, "did:dht:z6MkBob", context, [
      makeMockToken(),
      makeMockToken(),
    ]);
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

  it("multi-att token — evaluateLayer1 validates att[0] only; att[1] is NOT sent to the bridge", async () => {
    // evaluateLayer1 validates only att[0].with per token. Full multi-att
    // validation (checking every att[i]) requires a single bridge call that
    // consumes the nonce once — that op does not exist yet. Only att[0] is
    // checked; att[1] is never sent to ucanValidate.
    const b64url = (obj: unknown): string =>
      Buffer.from(JSON.stringify(obj), "utf8").toString("base64url");
    const header = b64url({ alg: "EdDSA", typ: "JWT", ucv: "0.10.0" });
    const payload = b64url({
      att: [
        { with: "scp:ctx:c/messages:read", can: "messages/read" },
        { with: "scp:ctx:c/messages:admin", can: "messages/admin" },
      ],
    });
    const multiAttToken = `${header}.${payload}.sig`;

    const { scp, native, context } = mountWithContext();
    const urisSeen: string[] = [];
    native.__stub("ucanValidate", (...args: unknown[]) => {
      const capUri = args[2] as string;
      urisSeen.push(capUri);
      return Promise.resolve(undefined); // att[0] passes
    });
    native.__stub("eventLogQuery", () => Promise.resolve([]));

    const result = await evaluateTrust(scp, "did:dht:z6MkBob", context, [multiAttToken]);
    const cv = result.capabilityValidation;
    // att[0] passed — all fields true.
    expect(cv.tokensValid).toBe(true);
    expect(cv.signaturesValid).toBe(true);
    expect(cv.withinCeiling).toBe(true);
    expect(cv.nonceValid).toBe(true);
    expect(cv.notRevoked).toBe(true);
    expect(cv.timeBoundsValid).toBe(true);
    // Only att[0] URI was sent to ucanValidate; att[1] was NOT.
    expect(urisSeen).toContain("scp:ctx:c/messages:read");
    expect(urisSeen).not.toContain("scp:ctx:c/messages:admin");
    expect(urisSeen).toHaveLength(1);
  });

  it("multi-att token: att[0] expiry failure — att[1] is NOT sent to bridge; verdict from att[0] only", async () => {
    // att[0] fails at step 11 (expiry): timeBoundsValid=false. evaluateLayer1
    // validates att[0] only and returns the narrowed verdict immediately
    // (fail-fast). att[1] is never sent to ucanValidate.
    const b64url = (obj: unknown): string =>
      Buffer.from(JSON.stringify(obj), "utf8").toString("base64url");
    const header = b64url({ alg: "EdDSA", typ: "JWT", ucv: "0.10.0" });
    const payload = b64url({
      att: [
        { with: "scp:ctx:c/messages:read", can: "messages/read" },
        { with: "scp:ctx:c/messages:write", can: "messages/write" },
      ],
    });
    const multiAttToken = `${header}.${payload}.sig`;

    const { scp, native, context } = mountWithContext();
    const urisSeen: string[] = [];
    native.__stub("ucanValidate", (...args: unknown[]) => {
      const capUri = args[2] as string;
      urisSeen.push(capUri);
      return Promise.reject(new Error("[SCP-PERM-3001] permission error: token expired"));
    });
    native.__stub("eventLogQuery", () => Promise.resolve([]));

    const result = await evaluateTrust(scp, "did:dht:z6MkBob", context, [multiAttToken]);
    const cv = result.capabilityValidation;
    // att[0] fails at expiry: tokens+sigs+ceiling+nonce+notRevoked=true, timeBounds=false.
    expect(cv.tokensValid).toBe(true);
    expect(cv.signaturesValid).toBe(true);
    expect(cv.withinCeiling).toBe(true);
    expect(cv.nonceValid).toBe(true);
    expect(cv.notRevoked).toBe(true);
    expect(cv.timeBoundsValid).toBe(false);
    // Only att[0] was sent to ucanValidate; att[1] was NOT.
    expect(urisSeen).toContain("scp:ctx:c/messages:read");
    expect(urisSeen).not.toContain("scp:ctx:c/messages:write");
    expect(urisSeen).toHaveLength(1);
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

  it("malformed JWT token: all false, ucanValidate never called", async () => {
    // A token that is not a `header.payload.signature` triple cannot have its
    // capability extracted, so it is treated as invalid and never reaches the
    // bridge. This is the fail-closed path for `"*"` no longer being passed.
    const { scp, native, context } = mountWithContext();
    native.__stub("ucanValidate", () => {
      throw new Error("ucanValidate should not be called for a malformed token");
    });
    native.__stub("eventLogQuery", () => Promise.resolve([]));

    const result = await evaluateTrust(scp, "did:dht:z6MkBob", context, ["not-a-jwt"]);
    const cv = result.capabilityValidation;
    expect(cv.tokensValid).toBe(false);
    expect(cv.signaturesValid).toBe(false);
    expect(cv.withinCeiling).toBe(false);
    expect(cv.nonceValid).toBe(false);
    expect(cv.notRevoked).toBe(false);
    expect(cv.timeBoundsValid).toBe(false);
    expect(native.__calls("ucanValidate")).toHaveLength(0);
  });

  it("token with empty att: all false, ucanValidate never called", async () => {
    // A structurally-valid JWT that declares no capabilities grants nothing,
    // so there is no capability URI to validate against and the bridge is
    // never called.
    const { scp, native, context } = mountWithContext();
    native.__stub("ucanValidate", () => {
      throw new Error("ucanValidate should not be called when att is empty");
    });
    native.__stub("eventLogQuery", () => Promise.resolve([]));

    const emptyAttToken = `${Buffer.from(JSON.stringify({ alg: "EdDSA" }), "utf8").toString(
      "base64url",
    )}.${Buffer.from(JSON.stringify({ att: [] }), "utf8").toString("base64url")}.sig`;
    const result = await evaluateTrust(scp, "did:dht:z6MkBob", context, [emptyAttToken]);
    const cv = result.capabilityValidation;
    expect(cv.tokensValid).toBe(false);
    expect(cv.signaturesValid).toBe(false);
    expect(cv.withinCeiling).toBe(false);
    expect(cv.nonceValid).toBe(false);
    expect(cv.notRevoked).toBe(false);
    expect(cv.timeBoundsValid).toBe(false);
    expect(native.__calls("ucanValidate")).toHaveLength(0);
  });

  it("passes the token's declared capability URI to ucanValidate", async () => {
    // Regression: `evaluateTrust` must validate the token against its own
    // declared capability (`att[0].with`), never the bogus `"*"` literal that
    // the bridge rejects with `InvalidCapabilityUri`.
    const { scp, native, context } = mountWithContext();
    native.__stub("ucanValidate", () => Promise.resolve(undefined));
    native.__stub("eventLogQuery", () => Promise.resolve([]));

    await evaluateTrust(scp, "did:dht:z6MkBob", context, [makeMockToken()]);
    const call = native.__lastCall("ucanValidate");
    // args: (handle, token, capability, ...)
    expect(call?.args[2]).toBe(MOCK_CAP_URI);
  });

  it("non-UCAN error propagates (not silently classified)", async () => {
    const { scp, native, context } = mountWithContext();
    // Native bridge throws a plain Error whose message carries the
    // `[SCP-VALID-NNNN]` prefix; `scp.ucanValidate` re-types it to
    // `ValidationError` via `mapBridgeError`. trust.ts only classifies
    // `[SCP-PERM-]` errors, so this propagates unchanged.
    native.__stub("ucanValidate", () =>
      Promise.reject(new Error("[SCP-VALID-7001] context_id contains control characters")),
    );
    native.__stub("eventLogQuery", () => Promise.resolve([]));

    let threw = false;
    try {
      await evaluateTrust(scp, "did:dht:z6MkBob", context, [makeMockToken()]);
    } catch (err) {
      threw = true;
      expect(err).toBeInstanceOf(ValidationError);
    }
    expect(threw).toBe(true);
  });

  it("PERM-3030 handle-affinity error re-throws instead of being classified", async () => {
    // PERM-3030 errors indicate caller misuse (handle belongs to a different SCP
    // instance) and must propagate to the caller rather than being silently
    // mapped to a failed CapabilityValidation. Mirrors Python's
    // test_evaluate_trust_reraises_perm_3030_handle_affinity_error.
    const { scp, native, context } = mountWithContext();
    const message = "[SCP-PERM-3030] permission error: handle belongs to a different SCP instance";
    // The native bridge throws a plain Error; `scp.ucanValidate` wraps it via
    // `mapBridgeError` into a typed `UcanPermissionError` (message preserved),
    // and trust.ts re-throws that typed error by identity.
    native.__stub("ucanValidate", () => Promise.reject(new Error(message)));
    native.__stub("eventLogQuery", () => Promise.resolve([]));

    let threw = false;
    try {
      await evaluateTrust(scp, "did:dht:z6MkBob", context, [makeMockToken()]);
    } catch (err) {
      threw = true;
      expect(err).toBeInstanceOf(UcanPermissionError);
      expect((err as UcanPermissionError).code).toBe("SCP-PERM-3030");
      expect((err as UcanPermissionError).message).toBe(message);
    }
    expect(threw).toBe(true);
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
    expect(result.behavioralRecord?.contextsParticipated).toBe(0);
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
    // Native bridge throws a plain Error with the [SCP-CTX-NNNN] prefix;
    // `scp.eventLogQuery` re-types it via `mapBridgeError` (message preserved),
    // and trust.ts Layer 2 classifies the context error on that prefix.
    native.__stub("eventLogQuery", () =>
      Promise.reject(
        new Error("[SCP-CTX-2001] context error: not a member — check membership status"),
      ),
    );

    const result = await evaluateTrust(scp, "did:dht:z6MkBob", context);
    expect(result.behavioralRecord).toBeNull();
  });

  it("Layer 2 — non-context error propagates instead of swallowing to null", async () => {
    const { scp, native, context } = mountWithContext();
    // ucanValidate resolves (passes Layer 1)
    native.__stub("ucanValidate", () => Promise.resolve(undefined));
    // eventLogQuery rejects with a non-[SCP-CTX-] error (e.g. a network failure).
    // `scp.eventLogQuery` wraps it via `mapBridgeError` into a base `ScpError`
    // (no recognized prefix → SCP-UNKNOWN-0000), with the message preserved.
    const message = "Network timeout";
    native.__stub("eventLogQuery", () => Promise.reject(new Error(message)));

    // The catch block in Layer 2 must re-throw non-context errors — it must NOT
    // swallow them into behavioralRecord: null (which would hide genuine faults).
    let threw = false;
    try {
      await evaluateTrust(scp, "did:dht:z6MkBob", context);
    } catch (err) {
      threw = true;
      expect(err).toBeInstanceOf(ScpError);
      expect((err as ScpError).message).toBe(message);
    }
    expect(threw).toBe(true);
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
