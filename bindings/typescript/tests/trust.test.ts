/**
 * Tests for the structured trust-signal consumer (ADR-057, spec §7.2.4).
 *
 * `scp.ucanEvaluate` is the read-only, structured diagnostic counterpart to
 * `ucanValidate`: it returns six per-stage `CapabilityValidation` booleans
 * instead of throwing, and never records the token's nonce. `scp.evaluateTrust`
 * AND-combines those booleans across a token set (Layer 1) and folds in the
 * event-log behavioral record (Layer 2).
 *
 * These tests drive the public `SCP` methods through the Proxy-backed mock
 * native handle (`mountMockScp` / `createMockNativeScp`), stubbing
 * `ucanEvaluate` / `eventLogQuery`. The `ucanEvaluate` stub models the
 * read-only nonce contract: it returns `nonceValid: true` even on repeated
 * calls for the same token (it is a read-only probe, not an echo/tautology and
 * not a nonce-consuming gate), which is what lets `evaluateTrust` be
 * idempotent.
 *
 * See `.docs/adrs/phase-2.md` ADR-057 and `.docs/specs/07-trust-validation-and-capabilities.md` §7.2.4.
 */

import { afterEach, describe, expect, it } from "bun:test";
import type { CapabilityValidation } from "../src/types";
import { createMockNativeScp, mountMockScp } from "./mock-bridge";

/** A fully-passing CapabilityValidation — the all-`true` identity element. */
const ALL_PASS: CapabilityValidation = {
  tokensValid: true,
  signaturesValid: true,
  withinCeiling: true,
  nonceValid: true,
  notRevoked: true,
  timeBoundsValid: true,
};

/**
 * Builds a fake `NapiParticipationRecord`-shaped object (the native
 * `participationRecord` return). The 11 fields map 1:1 to the SDK
 * `BehavioralRecord`. Defaults model an empty event log; pass `overrides` to
 * pin specific facts.
 */
function fakeParticipationRecord(
  overrides: Partial<Record<string, number | string | boolean>> = {},
): Record<string, number | string | boolean> {
  return {
    subjectDid: "did:dht:subject",
    participationDurationSecs: 0,
    governanceActionsAgainst: 0,
    governanceActionsBy: 0,
    toolInvocationCount: 0,
    toolInvocationCountAnchored: false,
    contextCreationCount: 0,
    roleProgressionCount: 0,
    attestationCount: 0,
    attestationCountAnchored: false,
    computedAt: 1,
    eventLogRoot: "00",
    ...overrides,
  };
}

/**
 * Builds a stateful, read-only `ucanEvaluate` mock keyed by token.
 *
 * The model is the production contract: evaluation is a read-only probe that
 * NEVER records the nonce, so re-evaluating the same token returns
 * `nonceValid: true` on every call (no first-call-true / second-call-false
 * nonce-consumption). It records each call so tests can assert how many times a
 * token was probed. `overrides` lets a test mark a specific token as failing a
 * particular stage.
 */
function statefulUcanEvaluate(
  overrides: Readonly<Record<string, Partial<CapabilityValidation>>> = {},
): {
  fn: (...args: readonly unknown[]) => Promise<CapabilityValidation>;
  evaluateCountFor: (token: string) => number;
} {
  const counts = new Map<string, number>();
  return {
    fn: async (...args: readonly unknown[]): Promise<CapabilityValidation> => {
      // SCP.ucanEvaluate(handle, token, presentingAgentDid, capability, proofTokens)
      const token = args[1] as string;
      counts.set(token, (counts.get(token) ?? 0) + 1);
      const override = overrides[token] ?? {};
      // Read-only: nonceValid stays true regardless of how many times the same
      // token is probed (the diagnostic records nothing).
      return { ...ALL_PASS, ...override };
    },
    evaluateCountFor: (token: string): number => counts.get(token) ?? 0,
  };
}

describe("scp.ucanEvaluate — structured read-only diagnostic", () => {
  let cleanup: (() => Promise<void>) | undefined;
  afterEach(async () => {
    await cleanup?.();
    cleanup = undefined;
  });

  it("returns the six camelCase per-stage booleans verbatim", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("ucanEvaluate", async () => ({
      tokensValid: true,
      signaturesValid: false,
      withinCeiling: true,
      nonceValid: true,
      notRevoked: false,
      timeBoundsValid: true,
    }));

    const result = await scp.ucanEvaluate("handle", "token-a", "did:dht:agent", "tool:invoke:*");
    expect(result).toEqual({
      tokensValid: true,
      signaturesValid: false,
      withinCeiling: true,
      nonceValid: true,
      notRevoked: false,
      timeBoundsValid: true,
    });
  });

  it("forwards the presenting-agent DID and proof tokens", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("ucanEvaluate", async () => ALL_PASS);

    await scp.ucanEvaluate("handle", "token-a", "did:dht:agent", "*", ["proof-1"]);
    const call = native.__lastCall("ucanEvaluate");
    expect(call).toBeDefined();
    // Native wire order: handle, token, capability, presentingAgentDid, proofTokens
    expect(call?.args[2]).toBe("*");
    expect(call?.args[3]).toBe("did:dht:agent");
    expect(call?.args[4]).toEqual(["proof-1"]);
  });

  it("normalizes the omitted capability and proof tokens to null on the wire", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("ucanEvaluate", async () => ALL_PASS);

    // presentingAgentDid is required; capability and proofTokens are omitted.
    await scp.ucanEvaluate("handle", "token-a", "did:dht:agent");
    const call = native.__lastCall("ucanEvaluate");
    expect(call?.args[2]).toBeNull();
    expect(call?.args[3]).toBe("did:dht:agent");
    expect(call?.args[4]).toBeNull();
  });
});

describe("scp.evaluateTrust — Layer 1 AND-combination + Layer 2 behavioral", () => {
  let cleanup: (() => Promise<void>) | undefined;
  afterEach(async () => {
    await cleanup?.();
    cleanup = undefined;
  });

  it("is idempotent: re-evaluating the same token keeps nonceValid true (read-only)", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    const probe = statefulUcanEvaluate();
    native.__stub("ucanEvaluate", probe.fn);
    native.__stub("participationRecord", () => fakeParticipationRecord());

    const first = await scp.evaluateTrust("handle", "did:dht:subject", "ctx-1", ["token-a"]);
    const second = await scp.evaluateTrust("handle", "did:dht:subject", "ctx-1", ["token-a"]);

    // The read-only diagnostic records nothing: the same token probed twice
    // reports nonceValid:true both times, so the aggregate is stable.
    expect(first.capabilityValidation).toEqual(ALL_PASS);
    expect(second.capabilityValidation).toEqual(ALL_PASS);
    expect(first.capabilityValidation.nonceValid).toBe(true);
    expect(second.capabilityValidation.nonceValid).toBe(true);
    // The token WAS probed on each call (read-only, but not skipped).
    expect(probe.evaluateCountFor("token-a")).toBe(2);
  });

  it("ANDs the six booleans across tokens: token B failing within_ceiling fails the aggregate", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    const probe = statefulUcanEvaluate({
      // token-a passes everything; token-b is outside the ceiling.
      "token-b": { withinCeiling: false },
    });
    native.__stub("ucanEvaluate", probe.fn);
    native.__stub("participationRecord", () => fakeParticipationRecord());

    const result = await scp.evaluateTrust("handle", "did:dht:subject", "ctx-1", [
      "token-a",
      "token-b",
    ]);

    // withinCeiling is the conjunction: true (A) && false (B) === false.
    expect(result.capabilityValidation.withinCeiling).toBe(false);
    // Every other stage passed on both tokens, so the conjunction stays true.
    expect(result.capabilityValidation.tokensValid).toBe(true);
    expect(result.capabilityValidation.signaturesValid).toBe(true);
    expect(result.capabilityValidation.nonceValid).toBe(true);
    expect(result.capabilityValidation.notRevoked).toBe(true);
    expect(result.capabilityValidation.timeBoundsValid).toBe(true);
    // Both tokens were probed exactly once.
    expect(probe.evaluateCountFor("token-a")).toBe(1);
    expect(probe.evaluateCountFor("token-b")).toBe(1);
  });

  it("with no tokens, every Layer-1 field is false (no stage observed to pass)", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    // ucanEvaluate must NOT be called when no tokens are supplied; leave it
    // unstubbed (strict mode would throw if it were called).
    native.__stub("participationRecord", () => fakeParticipationRecord());

    const result = await scp.evaluateTrust("handle", "did:dht:subject", "ctx-1");
    expect(result.capabilityValidation).toEqual({
      tokensValid: false,
      signaturesValid: false,
      withinCeiling: false,
      nonceValid: false,
      notRevoked: false,
      timeBoundsValid: false,
    });
    // No token probe happened.
    expect(native.__calls("ucanEvaluate").length).toBe(0);
  });

  it("RECEIVES the Layer-2 behavioral record from the core (no client-side classify)", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    // The behavioral record is now flattened ONCE in the Rust core and surfaced
    // by the native `participationRecord` op. The SDK projects the 11 typed
    // fields straight through — it never re-aggregates an event-log collection.
    native.__stub("participationRecord", () =>
      fakeParticipationRecord({
        participationDurationSecs: 300,
        governanceActionsAgainst: 2,
        governanceActionsBy: 1,
        toolInvocationCount: 2,
        contextCreationCount: 1,
        roleProgressionCount: 3,
        attestationCount: 0,
        eventLogRoot: "deadbeef",
      }),
    );

    const result = await scp.evaluateTrust("handle", "did:dht:subject", "ctx-1");
    expect(result.behavioralRecord.subjectDid).toBe("did:dht:subject");
    expect(result.behavioralRecord.participationDurationSecs).toBe(300);
    expect(result.behavioralRecord.governanceActionsAgainst).toBe(2);
    expect(result.behavioralRecord.governanceActionsBy).toBe(1);
    expect(result.behavioralRecord.toolInvocationCount).toBe(2);
    // tool_invocation_count is NOT Merkle-anchored until ADR-051.
    expect(result.behavioralRecord.toolInvocationCountAnchored).toBe(false);
    expect(result.behavioralRecord.contextCreationCount).toBe(1);
    expect(result.behavioralRecord.roleProgressionCount).toBe(3);
    // attestation_count is a credential-layer fact; evaluateTrust passes no
    // cached attestations, so it is 0 (honest, verifier-relative).
    expect(result.behavioralRecord.attestationCount).toBe(0);
    expect(result.behavioralRecord.eventLogRoot).toBe("deadbeef");
    expect(result.subjectDid).toBe("did:dht:subject");
    expect(result.contextId).toBe("ctx-1");
  });

  it("dispatches participationRecord with the subject, context, and an empty attestation set", async () => {
    const mock = createMockNativeScp();
    const { scp } = mountMockScp(mock);
    cleanup = () => scp.shutdown(0);
    mock.__stub("participationRecord", () => fakeParticipationRecord());

    await scp.evaluateTrust("handle", "did:dht:subject", "ctx-1");
    const call = mock.__lastCall("participationRecord");
    expect(call).toBeDefined();
    // participationRecord(contextId, subjectDid, cachedAttestationsJson)
    expect(call?.args[0]).toBe("ctx-1");
    expect(call?.args[1]).toBe("did:dht:subject");
    // evaluateTrust passes no cached attestations → empty JSON array.
    expect(call?.args[2]).toBe("[]");
  });

  it("exposes participationRecord directly, projecting the typed core facts", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("participationRecord", () =>
      fakeParticipationRecord({
        subjectDid: "did:dht:alice",
        participationDurationSecs: 42,
        attestationCount: 5,
      }),
    );

    const record = await scp.participationRecord("ctx-1", "did:dht:alice");
    expect(record.subjectDid).toBe("did:dht:alice");
    expect(record.participationDurationSecs).toBe(42);
    expect(record.attestationCount).toBe(5);
    expect(record.toolInvocationCountAnchored).toBe(false);
    // attestationCount is credential-layer, never Merkle-anchored.
    expect(record.attestationCountAnchored).toBe(false);
  });

  it("folds an empty event log (SCP-CTX-2076) into a zeroed behavioral record", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    // The core surfaces the dedicated SCP-CTX-2076 code for "no recorded
    // participation facts" — the SDK branches on the structured code, NOT prose.
    native.__stub("participationRecord", () => {
      throw new Error("[SCP-CTX-2076] context error: no recorded participation facts");
    });

    const result = await scp.evaluateTrust("handle", "did:dht:subject", "ctx-1");
    const record = result.behavioralRecord;
    // Non-null, fully-zeroed record — identical shape to the populated case.
    expect(record.subjectDid).toBe("did:dht:subject");
    expect(record.participationDurationSecs).toBe(0);
    expect(record.governanceActionsAgainst).toBe(0);
    expect(record.governanceActionsBy).toBe(0);
    expect(record.toolInvocationCount).toBe(0);
    expect(record.toolInvocationCountAnchored).toBe(false);
    expect(record.contextCreationCount).toBe(0);
    expect(record.roleProgressionCount).toBe(0);
    expect(record.attestationCount).toBe(0);
    expect(record.attestationCountAnchored).toBe(false);
    expect(record.computedAt).toBe(0);
    expect(record.eventLogRoot).toBe("");
  });

  it("propagates a genuine (non-2076) ContextError instead of swallowing it", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    // A real failure (e.g. an uninitialized/invalid context) must NOT be folded
    // into a zeroed record — only the dedicated empty-log code is graceful.
    native.__stub("participationRecord", () => {
      throw new Error("[SCP-CTX-2001] context error: not initialized");
    });

    await expect(scp.evaluateTrust("handle", "did:dht:subject", "ctx-1")).rejects.toThrow(
      /not initialized/i,
    );
  });
});

describe("scp.participationRecord — typed cached-attestation input", () => {
  let cleanup: (() => Promise<void>) | undefined;
  afterEach(async () => {
    await cleanup?.();
    cleanup = undefined;
  });

  it("defaults to an empty array, serialized as '[]' on the wire", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("participationRecord", () => fakeParticipationRecord());

    const record = await scp.participationRecord("ctx-1", "did:dht:subject");
    // No attestations seeded → count 0, and the bridge receives "[]".
    expect(record.attestationCount).toBe(0);
    const call = native.__lastCall("participationRecord");
    expect(call?.args[2]).toBe("[]");
  });

  it("JSON.stringifies a typed CachedAttestation[] straight onto the wire", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("participationRecord", () => fakeParticipationRecord({ attestationCount: 1 }));

    const cached = [
      {
        attestation: {
          id: "att-1",
          attestation_type: "IdentityLink",
          issuer: "did:dht:issuer",
          subject: "did:dht:subject",
          claim: { platform: "github" },
          issued_at: 1000,
          revocation_status: "Active",
          signature: [1, 2, 3],
        },
        verified_at: 1234,
        ttl_secs: 300,
      },
    ] as const;

    const record = await scp.participationRecord("ctx-1", "did:dht:subject", cached);
    expect(record.attestationCount).toBe(1);
    const call = native.__lastCall("participationRecord");
    // The SDK stringifies the typed input verbatim (the Python `list[dict]`
    // analogue) — the wire string round-trips to the same structure.
    expect(call?.args[2]).toBe(JSON.stringify(cached));
    expect(JSON.parse(call?.args[2] as string)).toEqual(cached as unknown as unknown[]);
  });
});
