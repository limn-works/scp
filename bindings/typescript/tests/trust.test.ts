/**
 * Tests for the structured trust-signal consumer (ADR-059, spec §7.2.4).
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
 * See `.docs/adrs/phase-2.md` ADR-059 and `.docs/specs/07-trust-validation-and-capabilities.md` §7.2.4.
 */

import { afterEach, describe, expect, it } from "bun:test";
import type { Context } from "../src/context";
import { ValidationError } from "../src/errors";
import type { SCP } from "../src/scp";
import type {
  AttestorInfo,
  CachedAttestation,
  CachedAttestationEnvelope,
  CapabilityValidation,
  ChallengeRequest,
  ChallengeResponse,
  ChallengeVerification,
  EventLogEntry,
  ExpectedOutput,
  ParticipationProfile,
  RequireParticipation,
  TestCase,
  ThresholdRequirement,
} from "../src/types";
import {
  ANSWER_KEY_MISMATCH_CODE,
  decodeCaseResults,
  decodeChallengeRequest,
  decodeChallengeResponse,
  decodeChallengeVerification,
  encodeAttestation,
  encodeAttestorSets,
  encodeCapabilityRequirements,
  encodeChallengeRequest,
  encodeChallengeResponse,
  encodeChallengeVerifications,
  encodeEventLogEntries,
  encodeMerkleRoot,
  encodeParticipationProfile,
  encodeRequireParticipation,
  encodeTestCases,
  encodeTestOutputs,
  encodeThresholdRequirements,
  GRADING_CAPACITY_EXHAUSTED_CODE,
  GRADING_LEASE_LOST_CODE,
  NON_CANONICAL_IDENTIFIER_CODE,
  TOO_MANY_CAPABILITY_REQUIREMENTS_CODE,
} from "../src/types";
import { createMockNativeScp, mockContext, mountMockScp } from "./mock-bridge";

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
    outletInvocationCount: 0,
    outletInvocationCountAnchored: false,
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

/**
 * Creates a mock SCP instance paired with a minimal Context handle for tests
 * that exercise methods requiring a context (e.g. `evaluateTrust` Layer 1+2).
 */
function mountWithContext() {
  const { scp, native } = mountMockScp();
  const context = mockContext(scp, "ctx-test");
  return { scp, native, context };
}

/**
 * Thin wrapper so tests can call `evaluateTrust(scp, did, ctx, tokens?)` rather
 * than `scp.evaluateTrust(ctx, did, tokens?)` — mirrors Python's
 * standalone `evaluate_trust(scp, did, ctx, tokens)` helper convention.
 */
function evaluateTrust(
  scp: SCP,
  subjectDid: string,
  context: Context,
  tokens?: readonly string[],
): ReturnType<SCP["evaluateTrust"]> {
  return scp.evaluateTrust(context, subjectDid, tokens);
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

    const result = await scp.ucanEvaluate(
      mockContext(scp),
      "token-a",
      "did:dht:agent",
      "outlet:call:*",
    );
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

    await scp.ucanEvaluate(mockContext(scp), "token-a", "did:dht:agent", "*", ["proof-1"]);
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
    await scp.ucanEvaluate(mockContext(scp), "token-a", "did:dht:agent");
    const call = native.__lastCall("ucanEvaluate");
    expect(call?.args[2]).toBeNull();
    expect(call?.args[3]).toBe("did:dht:agent");
    expect(call?.args[4]).toBeNull();
  });

  it("PERM-3030 handle-affinity error re-throws instead of being classified", async () => {
    // PERM-3030 errors indicate caller misuse (handle belongs to a different SCP
    // instance) and must propagate to the caller rather than being silently
    // mapped to a failed CapabilityValidation. Mirrors Python's
    // test_evaluate_trust_reraises_perm_3030_handle_affinity_error.
    const { scp, native, context } = mountWithContext();
    const perm3030 = new Error(
      "[SCP-PERM-3030] permission error: handle belongs to a different SCP instance",
    );
    // scp.evaluateTrust calls this.ucanEvaluate (read-only probe), not ucanValidate.
    native.__stub("ucanEvaluate", () => Promise.reject(perm3030));

    let threw = false;
    try {
      await evaluateTrust(scp, "did:dht:z6MkBob", context, ["fake-token"]);
    } catch (err) {
      threw = true;
      // mapBridgeError re-wraps the raw error; check the preserved message.
      expect((err as Error).message).toContain("[SCP-PERM-3030]");
    }
    expect(threw).toBe(true);
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

    const first = await scp.evaluateTrust(mockContext(scp, "ctx-1"), "did:dht:subject", [
      "token-a",
    ]);
    const second = await scp.evaluateTrust(mockContext(scp, "ctx-1"), "did:dht:subject", [
      "token-a",
    ]);

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

    const result = await scp.evaluateTrust(mockContext(scp, "ctx-1"), "did:dht:subject", [
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

    const result = await scp.evaluateTrust(mockContext(scp, "ctx-1"), "did:dht:subject");
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
        outletInvocationCount: 2,
        contextCreationCount: 1,
        roleProgressionCount: 3,
        attestationCount: 0,
        eventLogRoot: "deadbeef",
      }),
    );

    const result = await scp.evaluateTrust(mockContext(scp, "ctx-1"), "did:dht:subject");
    expect(result.behavioralRecord.subjectDid).toBe("did:dht:subject");
    expect(result.behavioralRecord.participationDurationSecs).toBe(300);
    expect(result.behavioralRecord.governanceActionsAgainst).toBe(2);
    expect(result.behavioralRecord.governanceActionsBy).toBe(1);
    expect(result.behavioralRecord.outletInvocationCount).toBe(2);
    // outlet_invocation_count is NOT Merkle-anchored until ADR-051.
    expect(result.behavioralRecord.outletInvocationCountAnchored).toBe(false);
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

    await scp.evaluateTrust(mockContext(scp, "ctx-1"), "did:dht:subject");
    const call = mock.__lastCall("participationRecord");
    expect(call).toBeDefined();
    // participationRecord(contextId, subjectDid, cachedAttestationsJson)
    expect(call?.args[0]).toBe("ctx-1");
    expect(call?.args[1]).toBe("did:dht:subject");
    // evaluateTrust passes no cached attestations → empty JSON array.
    expect(call?.args[2]).toBe("[]");
  });

  it("labels the result with — and keys Layer 2 by — the handle's context", async () => {
    const mock = createMockNativeScp();
    const { scp } = mountMockScp(mock);
    cleanup = () => scp.shutdown(0);
    mock.__stub("participationRecord", () => fakeParticipationRecord());

    // The evaluation resolves its context solely from the handle (no separate
    // context-id argument exists, matching Swift/Kotlin). The returned record
    // is labeled with that resolved context AND the Layer-2 lookup is keyed by
    // it, so the two can never disagree.
    const result = await scp.evaluateTrust(mockContext(scp, "ctx-A"), "did:dht:subject");
    expect(result.contextId).toBe("ctx-A");

    // The Layer-2 lookup hits the resolved context.
    const call = mock.__lastCall("participationRecord");
    expect(call?.args[0]).toBe("ctx-A");
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
    expect(record.outletInvocationCountAnchored).toBe(false);
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

    const result = await scp.evaluateTrust(mockContext(scp, "ctx-1"), "did:dht:subject");
    const record = result.behavioralRecord;
    // Non-null, fully-zeroed record — identical shape to the populated case.
    expect(record.subjectDid).toBe("did:dht:subject");
    expect(record.participationDurationSecs).toBe(0);
    expect(record.governanceActionsAgainst).toBe(0);
    expect(record.governanceActionsBy).toBe(0);
    expect(record.outletInvocationCount).toBe(0);
    expect(record.outletInvocationCountAnchored).toBe(false);
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

    await expect(scp.evaluateTrust(mockContext(scp, "ctx-1"), "did:dht:subject")).rejects.toThrow(
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

  it("maps a typed camelCase CachedAttestation[] to the snake_case wire shape", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("participationRecord", () => fakeParticipationRecord({ attestationCount: 1 }));

    // Developer-facing fields are camelCase (matching the Swift/Kotlin SDKs and
    // the other typed TS types). The full optional set is exercised to pin the
    // camelCase → snake_case boundary mapping.
    const cached: readonly CachedAttestation[] = [
      {
        attestation: {
          id: "att-1",
          attestationType: "IdentityLink",
          issuer: "did:dht:issuer",
          subject: "did:dht:subject",
          claim: { platform: "github" },
          evidence: { evidenceType: "oauth", data: { handle: "octocat" } },
          issuedAt: 1000,
          expiresAt: 5000,
          renewalInterval: { secs: 86400, nanos: 0 },
          renewedAt: 2000,
          revocationStatus: "Active",
          signature: [1, 2, 3],
        },
        verifiedAt: 1234,
        ttlSecs: 300,
      },
    ];

    const record = await scp.participationRecord("ctx-1", "did:dht:subject", cached);
    expect(record.attestationCount).toBe(1);
    const call = native.__lastCall("participationRecord");
    // The bridge deserializes serde-canonical snake_case; the SDK maps the
    // camelCase developer-facing fields at the serialization boundary
    // (mirroring the Swift `CodingKeys` / Kotlin `buildJsonObject` convention).
    expect(JSON.parse(call?.args[2] as string)).toEqual([
      {
        attestation: {
          id: "att-1",
          attestation_type: "IdentityLink",
          issuer: "did:dht:issuer",
          subject: "did:dht:subject",
          claim: { platform: "github" },
          evidence: { evidence_type: "oauth", data: { handle: "octocat" } },
          issued_at: 1000,
          expires_at: 5000,
          renewal_interval: { secs: 86400, nanos: 0 },
          renewed_at: 2000,
          revocation_status: "Active",
          signature: [1, 2, 3],
        },
        verified_at: 1234,
        ttl_secs: 300,
      },
    ]);
  });
});

describe("scp.checkCapabilityRequirements — capability admission (§7.3.4.4)", () => {
  let cleanup: (() => Promise<void>) | undefined;
  afterEach(async () => {
    await cleanup?.();
    cleanup = undefined;
  });

  it("passes no requirements: the bridge reads them from the context's governance", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("checkCapabilityRequirements", () => undefined);

    const records = [makeRecord()];
    const result = await scp.checkCapabilityRequirements(
      "ctx-1",
      "did:dht:subject",
      ["scp:capability:schema-validation/v1"],
      records,
    );
    expect(result).toBeUndefined();

    const call = native.__lastCall("checkCapabilityRequirements");
    expect(call?.args).toEqual([
      "ctx-1",
      "did:dht:subject",
      JSON.stringify(["scp:capability:schema-validation/v1"]),
      encodeChallengeVerifications(records),
    ]);
  });

  it("propagates a thrown admission error", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("checkCapabilityRequirements", () => {
      throw new Error("missing required capability");
    });

    await expect(
      scp.checkCapabilityRequirements("ctx-1", "did:dht:subject", [], []),
    ).rejects.toThrow("missing required capability");
  });
});

describe("scp.verifyParticipationRequirements — participation admission (§7.3.2.1)", () => {
  let cleanup: (() => Promise<void>) | undefined;
  afterEach(async () => {
    await cleanup?.();
    cleanup = undefined;
  });

  it("serializes typed requirements and profiles to the serde wire shape", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("verifyParticipationRequirements", () => undefined);

    const requirements: readonly RequireParticipation[] = [
      {
        fact: "OutletInvocationCount",
        threshold: { AtLeast: 100 },
        maxAgeSecs: 86_400,
        minContexts: 2,
      },
    ];
    const profiles: readonly ParticipationProfile[] = [makeProfile()];

    const result = scp.verifyParticipationRequirements("did:dht:subject", requirements, profiles);
    expect(result).toBeUndefined();

    const call = native.__lastCall("verifyParticipationRequirements");
    expect(call?.args).toEqual([
      "did:dht:subject",
      JSON.stringify([
        {
          fact: "OutletInvocationCount",
          threshold: { AtLeast: 100 },
          max_age_secs: 86_400,
          min_contexts: 2,
        },
      ]),
      encodeParticipationProfile(profiles),
    ]);
  });

  it("propagates a thrown admission error", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("verifyParticipationRequirements", () => {
      throw new Error("participation admission verification failed");
    });

    expect(() => scp.verifyParticipationRequirements("did:dht:subject", [], [])).toThrow(
      "participation admission verification failed",
    );
  });
});

// ---------------------------------------------------------------------------
// Encoder wire-shape unit tests (ADR-058)
//
// These pin the encoders against the exact `serde_json::to_string` shapes the
// Rust bridge deserializes (crates/scp-ffi/napi/src/trust.rs fixtures): bare
// variant strings, `{ "<Op>": u64 }` thresholds, snake_case struct fields, and
// byte arrays as JSON number arrays.
// ---------------------------------------------------------------------------

/** A structurally-valid `ParticipationProfile` with real 32/32/64 byte arrays. */
function makeProfile(overrides: Partial<ParticipationProfile> = {}): ParticipationProfile {
  return {
    subjectDid: "did:dht:subject",
    participationDurationSecs: 3_600,
    governanceActionsAgainst: 0,
    governanceActionsBy: 1,
    outletInvocationCount: 150,
    outletInvocationCountAnchored: false,
    contextCreationCount: 2,
    roleProgressionCount: 3,
    attestationCount: 4,
    updatedAt: 1_700_000_000,
    eventLogRoot: Array.from({ length: 32 }, (_, i) => i),
    signerPublicKey: Array.from({ length: 32 }, (_, i) => i + 100),
    signature: Array.from({ length: 64 }, () => 7),
    ...overrides,
  };
}

describe("encodeCapabilityRequirements", () => {
  it("emits the snake_case requirement with empty verifiers and no cap by default", () => {
    const parsed = JSON.parse(
      encodeCapabilityRequirements([
        { capability: "scp:capability:schema-validation/v1", verificationLevel: "SelfAttested" },
      ]),
    );
    expect(parsed).toEqual([
      {
        capability: "scp:capability:schema-validation/v1",
        verification_level: "SelfAttested",
        trusted_verifiers: [],
        retry_cap: null,
      },
    ]);
  });

  it("emits trusted verifiers and the retry cap", () => {
    const parsed = JSON.parse(
      encodeCapabilityRequirements([
        {
          capability: "scp:capability:schema-validation/v1",
          verificationLevel: "ChallengeVerified",
          trustedVerifiers: ["did:dht:zVerifier"],
          retryCap: { maxRetries: 1, minCooldownSecs: 600 },
        },
      ]),
    );
    expect(parsed).toEqual([
      {
        capability: "scp:capability:schema-validation/v1",
        verification_level: "ChallengeVerified",
        trusted_verifiers: ["did:dht:zVerifier"],
        retry_cap: { max_retries: 1, min_cooldown_secs: 600 },
      },
    ]);
  });

  it("rejects a retry cap outside u32 before any bridge call", () => {
    expect(() =>
      encodeCapabilityRequirements([
        {
          capability: "scp:capability:schema-validation/v1",
          verificationLevel: "ChallengeVerified",
          trustedVerifiers: ["did:dht:zVerifier"],
          retryCap: { maxRetries: -1, minCooldownSecs: 600 },
        },
      ]),
    ).toThrow("RetryCap.maxRetries must be an integer");
  });

  it("Layer 2 — non-context error propagates instead of swallowing to null", async () => {
    const { scp, native, context } = mountWithContext();
    // No tokens → Layer 1 skipped. scp.evaluateTrust calls participationRecord for Layer 2.
    const networkError = new Error("Network timeout");
    native.__stub("participationRecord", () => {
      throw networkError;
    });

    // The catch block in Layer 2 must re-throw non-context errors — it must NOT
    // swallow them into behavioralRecord: null (which would hide genuine faults).
    // mapBridgeError re-wraps the raw error; check the preserved message.
    await expect(evaluateTrust(scp, "did:dht:z6MkBob", context)).rejects.toThrow("Network timeout");
  });
});

describe("encodeRequireParticipation", () => {
  it("passes `fact`/`threshold` through and snake_cases the scalar fields", () => {
    const reqs: readonly RequireParticipation[] = [
      {
        fact: "GovernanceActionsBy",
        threshold: { GreaterThan: 5 },
        maxAgeSecs: 604_800,
        minContexts: 3,
      },
    ];
    expect(JSON.parse(encodeRequireParticipation(reqs))).toEqual([
      {
        fact: "GovernanceActionsBy",
        threshold: { GreaterThan: 5 },
        max_age_secs: 604_800,
        min_contexts: 3,
      },
    ]);
  });
});

describe("encodeParticipationProfile", () => {
  it("snake_cases all 13 fields and emits byte arrays as number arrays", () => {
    const parsed = JSON.parse(encodeParticipationProfile([makeProfile()]));
    expect(parsed).toEqual([
      {
        subject_did: "did:dht:subject",
        participation_duration_secs: 3_600,
        governance_actions_against: 0,
        governance_actions_by: 1,
        outlet_invocation_count: 150,
        outlet_invocation_count_anchored: false,
        context_creation_count: 2,
        role_progression_count: 3,
        attestation_count: 4,
        updated_at: 1_700_000_000,
        event_log_root: Array.from({ length: 32 }, (_, i) => i),
        signer_public_key: Array.from({ length: 32 }, (_, i) => i + 100),
        signature: Array.from({ length: 64 }, () => 7),
      },
    ]);
    // Byte arrays keep their exact lengths — the Rust side rejects wrong-length
    // `[u8; 32]` / `[u8; 64]` fields at deserialize time.
    expect(parsed[0].event_log_root).toHaveLength(32);
    expect(parsed[0].signer_public_key).toHaveLength(32);
    expect(parsed[0].signature).toHaveLength(64);
  });

  it("rejects wrong-length byte arrays before any bridge call", () => {
    expect(() => encodeParticipationProfile([makeProfile({ eventLogRoot: [1, 2, 3] })])).toThrow(
      "ParticipationProfile.eventLogRoot must be exactly 32 elements, got 3",
    );
    expect(() =>
      encodeParticipationProfile([makeProfile({ signerPublicKey: Array(33).fill(0) })]),
    ).toThrow("ParticipationProfile.signerPublicKey must be exactly 32 elements, got 33");
    expect(() =>
      encodeParticipationProfile([makeProfile({ signature: Array(63).fill(0) })]),
    ).toThrow("ParticipationProfile.signature must be exactly 64 elements, got 63");
  });
});

/** The 22-field wire form of a graded record, as the bridge emits it. */
const recordWire = {
  verification_id: "ab".repeat(32),
  verifier: "did:dht:zVerifier",
  subject: "did:dht:zResponder",
  capability_uri: "scp:capability:schema-validation/v1",
  definition_digest: "c8".repeat(32),
  suite_digest: "cd".repeat(32),
  challenge_id: "01".repeat(32),
  attempt: 2,
  response_digest: "02".repeat(32),
  max_retries: 2,
  cooldown_secs: 300,
  pass_threshold_bps: 9_000,
  min_category_cases: 0,
  passed: true,
  score: 9_500,
  test_count: 20,
  pass_count: 19,
  challenge_created_at: 1_699_999_000,
  challenge_expires_at: 1_700_003_600,
  timestamp: 1_700_000_000,
  expires_at: 1_700_086_400,
  context_id: "ctx-admission",
  verifier_signature: Array.from({ length: 64 }, () => 9),
};

/** The typed form of `recordWire`, with `overrides` applied. */
function makeRecord(overrides: Partial<ChallengeVerification> = {}): ChallengeVerification {
  return {
    verificationId: "ab".repeat(32),
    verifier: "did:dht:zVerifier",
    subject: "did:dht:zResponder",
    capabilityUri: "scp:capability:schema-validation/v1",
    definitionDigest: "c8".repeat(32),
    suiteDigest: "cd".repeat(32),
    challengeId: "01".repeat(32),
    attempt: 2,
    responseDigest: "02".repeat(32),
    maxRetries: 2,
    cooldownSecs: 300,
    passThresholdBps: 9_000,
    minCategoryCases: 0,
    passed: true,
    score: 9_500,
    testCount: 20,
    passCount: 19,
    challengeCreatedAt: 1_699_999_000,
    challengeExpiresAt: 1_700_003_600,
    timestamp: 1_700_000_000,
    expiresAt: 1_700_086_400,
    contextId: "ctx-admission",
    verifierSignature: Array.from({ length: 64 }, () => 9),
    ...overrides,
  };
}

describe("encodeChallengeVerifications / decodeChallengeVerification", () => {
  it("emits every field in snake_case and nothing else", () => {
    expect(JSON.parse(encodeChallengeVerifications([makeRecord()]))).toEqual([recordWire]);
    expect(Object.keys(recordWire)).toHaveLength(23);
  });

  it("decodes the bridge record back to the typed record", () => {
    expect(decodeChallengeVerification(JSON.stringify(recordWire))).toEqual(makeRecord());
  });

  it("decode rejects a non-hex id, a score above 10000, a short signature and a missing field", () => {
    expect(() =>
      decodeChallengeVerification(
        JSON.stringify({ ...recordWire, verification_id: "AB".repeat(32) }),
      ),
    ).toThrow("ChallengeVerification.verification_id must be 64 lowercase hex characters");
    expect(() =>
      decodeChallengeVerification(JSON.stringify({ ...recordWire, score: 10_001 })),
    ).toThrow("ChallengeVerification.score must be an integer in [0, 10000]");
    expect(
      decodeChallengeVerification(JSON.stringify({ ...recordWire, score: 10_000 })).score,
    ).toBe(10_000);
    expect(() =>
      decodeChallengeVerification(JSON.stringify({ ...recordWire, verifier_signature: [1, 2] })),
    ).toThrow("ChallengeVerification.verifier_signature must be exactly 64 byte values");
    const { attempt: _attempt, ...withoutAttempt } = recordWire;
    expect(() => decodeChallengeVerification(JSON.stringify(withoutAttempt))).toThrow(
      "ChallengeVerification.attempt must be an integer",
    );
  });

  it("rejects a wrong-length signature or a non-hex digest before any bridge call", () => {
    expect(() =>
      encodeChallengeVerifications([makeRecord({ verifierSignature: Array(63).fill(9) })]),
    ).toThrow("ChallengeVerification.verifierSignature must be exactly 64 elements, got 63");
    expect(() => encodeChallengeVerifications([makeRecord({ suiteDigest: "cd" })])).toThrow(
      "ChallengeVerification.suiteDigest must be 64 lowercase hex characters",
    );
    expect(() => encodeChallengeVerifications([makeRecord({ responseDigest: "02" })])).toThrow(
      "ChallengeVerification.responseDigest must be 64 lowercase hex characters",
    );
  });
});

// ---------------------------------------------------------------------------
// Trust aggregation input encoders + call-through (§7.3, ADR-058)
// ---------------------------------------------------------------------------

/** A structurally-valid `EventLogEntry` with real 32/64 byte arrays. */
function makeEventLogEntry(overrides: Partial<EventLogEntry> = {}): EventLogEntry {
  return {
    eventType: "MessageSent",
    actorDid: "did:dht:actor",
    timestamp: 1_700_000_000,
    sequence: 0,
    payload: { data: [] },
    prevHash: Array.from({ length: 32 }, () => 0),
    signature: Array.from({ length: 64 }, () => 5),
    ...overrides,
  };
}

describe("encodeEventLogEntries", () => {
  it("emits the full 7-field snake_case signed event", () => {
    const parsed = JSON.parse(
      encodeEventLogEntries([
        makeEventLogEntry({
          payload: { data: [1, 2, 3] },
          prevHash: Array.from({ length: 32 }, (_, i) => i),
        }),
      ]),
    );
    expect(parsed).toEqual([
      {
        event_type: "MessageSent",
        actor_did: "did:dht:actor",
        timestamp: 1_700_000_000,
        sequence: 0,
        payload: { data: [1, 2, 3] },
        prev_hash: Array.from({ length: 32 }, (_, i) => i),
        signature: Array.from({ length: 64 }, () => 5),
      },
    ]);
  });

  it("rejects wrong-length prevHash / signature before any bridge call", () => {
    expect(() => encodeEventLogEntries([makeEventLogEntry({ prevHash: [1, 2, 3] })])).toThrow(
      "EventLogEntry.prevHash must be exactly 32 elements, got 3",
    );
    expect(() =>
      encodeEventLogEntries([makeEventLogEntry({ signature: Array(63).fill(5) })]),
    ).toThrow("EventLogEntry.signature must be exactly 64 elements, got 63");
  });
});

describe("encodeMerkleRoot", () => {
  it("passes a 32-byte root through as a number array", () => {
    const root = Array.from({ length: 32 }, (_, i) => i);
    expect(JSON.parse(encodeMerkleRoot(root))).toEqual(root);
  });

  it("rejects a wrong-length root before any bridge call", () => {
    expect(() => encodeMerkleRoot([1, 2, 3])).toThrow(
      "AggregationInput.merkleRoot must be exactly 32 elements, got 3",
    );
  });
});

describe("encodeThresholdRequirements", () => {
  it("keys by bare AttestationType strings and snake_cases the fields", () => {
    const requirements: Partial<Record<string, ThresholdRequirement>> = {
      Endorsement: {
        requiredCount: 2,
        totalAttestors: 3,
        independenceThreshold: 0.5,
        sharedContextPenalty: 0.2,
        sharedContextPenaltyCap: 0.6,
        mutualEndorsementPenalty: 0.3,
      },
    };
    expect(JSON.parse(encodeThresholdRequirements(requirements))).toEqual({
      Endorsement: {
        required_count: 2,
        total_attestors: 3,
        independence_threshold: 0.5,
        shared_context_penalty: 0.2,
        shared_context_penalty_cap: 0.6,
        mutual_endorsement_penalty: 0.3,
      },
    });
  });

  it("fills the three penalty fields with the Rust serde defaults when omitted", () => {
    const parsed = JSON.parse(
      encodeThresholdRequirements({
        AgentCapability: { requiredCount: 1, totalAttestors: 1, independenceThreshold: 0 },
      }),
    );
    expect(parsed.AgentCapability.shared_context_penalty).toBe(0.1);
    expect(parsed.AgentCapability.shared_context_penalty_cap).toBe(0.5);
    expect(parsed.AgentCapability.mutual_endorsement_penalty).toBe(0.2);
  });
});

describe("encodeAttestorSets", () => {
  it("encodes attestors with an explicit-null absent attestation", () => {
    const attestor: AttestorInfo = {
      did: "did:dht:attestor",
      contextMemberships: ["ctx-1", "ctx-2"],
      endorsements: ["did:dht:other"],
    };
    expect(JSON.parse(encodeAttestorSets({ Endorsement: [attestor] }))).toEqual({
      Endorsement: [
        {
          did: "did:dht:attestor",
          context_memberships: ["ctx-1", "ctx-2"],
          endorsements: ["did:dht:other"],
          attestation: null,
        },
      ],
    });
  });

  it("encodes a nested attestation envelope in the serde snake_case shape", () => {
    const attestor: AttestorInfo = {
      did: "did:dht:attestor",
      contextMemberships: [],
      endorsements: [],
      attestation: {
        id: "att-1",
        attestationType: "Endorsement",
        issuer: "did:dht:attestor",
        subject: "did:dht:subject",
        claim: { endorsed: true },
        issuedAt: 1000,
        revocationStatus: "Active",
        signature: [1, 2, 3],
      },
    };
    const parsed = JSON.parse(encodeAttestorSets({ Endorsement: [attestor] }));
    expect(parsed.Endorsement[0].attestation).toEqual({
      id: "att-1",
      attestation_type: "Endorsement",
      issuer: "did:dht:attestor",
      subject: "did:dht:subject",
      claim: { endorsed: true },
      issued_at: 1000,
      revocation_status: "Active",
      signature: [1, 2, 3],
    });
  });
});

describe("scp.aggregateTrustInput — typed trust-aggregation inputs (§7.3)", () => {
  let cleanup: (() => Promise<void>) | undefined;
  afterEach(async () => {
    await cleanup?.();
    cleanup = undefined;
  });

  it("serializes every typed input to the serde wire shape before crossing FFI", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("aggregateTrustInput", () => "{}");

    const events = [makeEventLogEntry()];
    const merkleRoot = Array.from({ length: 32 }, () => 7);
    const challengeResults: readonly ChallengeVerification[] = [makeRecord()];

    const result = await scp.aggregateTrustInput(
      "ctx-1",
      "did:dht:subject",
      events,
      merkleRoot,
      [],
      { Endorsement: { requiredCount: 1, totalAttestors: 1, independenceThreshold: 0 } },
      { Endorsement: [{ did: "did:dht:a", contextMemberships: [], endorsements: [] }] },
      [],
      challengeResults,
    );
    expect(result).toBe("{}");

    // The native bridge receives serde-canonical JSON strings, not the typed
    // objects — the SDK serializes internally (ADR-058).
    const call = native.__lastCall("aggregateTrustInput");
    expect(call?.args[0]).toBe("ctx-1");
    expect(call?.args[1]).toBe("did:dht:subject");
    expect(call?.args[2]).toBe(encodeEventLogEntries(events));
    expect(call?.args[3]).toBe(JSON.stringify(merkleRoot));
    expect(call?.args[4]).toBe("[]");
    expect(JSON.parse(call?.args[5] as string)).toEqual({
      Endorsement: {
        required_count: 1,
        total_attestors: 1,
        independence_threshold: 0,
        shared_context_penalty: 0.1,
        shared_context_penalty_cap: 0.5,
        mutual_endorsement_penalty: 0.2,
      },
    });
    expect(JSON.parse(call?.args[6] as string)).toEqual({
      Endorsement: [
        { did: "did:dht:a", context_memberships: [], endorsements: [], attestation: null },
      ],
    });
    expect(call?.args[7]).toBe("[]");
    expect(call?.args[8]).toBe(encodeChallengeVerifications(challengeResults));
  });

  it("defaults every optional collection to an empty wire value", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("aggregateTrustInput", () => "{}");

    await scp.aggregateTrustInput(
      "ctx-1",
      "did:dht:subject",
      [],
      Array.from({ length: 32 }, () => 0),
    );

    const call = native.__lastCall("aggregateTrustInput");
    expect(call?.args.slice(2)).toEqual([
      "[]",
      JSON.stringify(Array.from({ length: 32 }, () => 0)),
      "[]",
      "{}",
      "{}",
      "[]",
      "[]",
    ]);
  });
});

// ---------------------------------------------------------------------------
// Challenge trust-input encoders + call-through (§7.3.4, ADR-058)
// ---------------------------------------------------------------------------

/** A structurally-valid attestation envelope. */
const attestationEnvelope: CachedAttestationEnvelope = {
  id: "att-1",
  attestationType: "AgentCapability",
  issuer: "did:dht:issuer",
  subject: "did:dht:subject",
  claim: { capability: "scp:capability:schema-validation/v1" },
  issuedAt: 1_700_000_000,
  revocationStatus: "Active",
  signature: Array.from({ length: 64 }, () => 3),
};

const SCHEMA_URI = "scp:capability:schema-validation/v1";

/** `n` exact-match cases whose weights sum to 10000. */
function makeTestCases(n: number): TestCase[] {
  const weight = Math.floor(10_000 / n);
  return Array.from({ length: n }, (_, i) => ({
    testId: `t${i}`,
    input: { i },
    expected: { kind: "ExactMatch", value: { ok: true } },
    category: "basic",
    weight: i === 0 ? 10_000 - weight * (n - 1) : weight,
  }));
}

/** A structurally-valid ChallengeRequest with a real 64-byte signature. */
function makeChallengeRequest(overrides: Partial<ChallengeRequest> = {}): ChallengeRequest {
  return {
    challengeId: "ab".repeat(32),
    capabilityUri: SCHEMA_URI,
    definitionDigest: "c8".repeat(32),
    testCases: makeTestCases(20).map((c) => ({
      testId: c.testId,
      input: c.input,
      category: c.category,
      weight: c.weight,
      answerCommitment: "3f".repeat(32),
    })),
    createdAt: 1_700_000_000,
    expiresAt: 1_700_003_600,
    maxRetries: 2,
    cooldownSecs: 300,
    passThresholdBps: 9_000,
    contextId: "ctx-1",
    verifier: "did:dht:verifier",
    subject: "did:dht:subject",
    verifierSignature: Array.from({ length: 64 }, () => 8),
    ...overrides,
  };
}

/** A structurally-valid ChallengeResponse with a real 64-byte signature. */
function makeChallengeResponse(overrides: Partial<ChallengeResponse> = {}): ChallengeResponse {
  return {
    challengeId: "ab".repeat(32),
    requestDigest: "5e".repeat(32),
    subject: "did:dht:subject",
    attempt: 1,
    outputs: [{ testId: "t0", output: { ok: true } }],
    subjectSignature: Array.from({ length: 64 }, () => 4),
    ...overrides,
  };
}

describe("encodeAttestation", () => {
  it("emits the single-envelope serde snake_case shape", () => {
    expect(JSON.parse(encodeAttestation(attestationEnvelope))).toEqual({
      id: "att-1",
      attestation_type: "AgentCapability",
      issuer: "did:dht:issuer",
      subject: "did:dht:subject",
      claim: { capability: "scp:capability:schema-validation/v1" },
      issued_at: 1_700_000_000,
      revocation_status: "Active",
      signature: Array.from({ length: 64 }, () => 3),
    });
  });
});

describe("encodeChallengeRequest / decodeChallengeRequest / encodeTestCases", () => {
  it("emits the 13-field snake_case request whose cases carry commitments, never answers", () => {
    const encoded = JSON.parse(encodeChallengeRequest(makeChallengeRequest()));
    expect(Object.keys(encoded).sort()).toEqual([
      "capability_uri",
      "challenge_id",
      "context_id",
      "cooldown_secs",
      "created_at",
      "definition_digest",
      "expires_at",
      "max_retries",
      "pass_threshold_bps",
      "subject",
      "test_cases",
      "verifier",
      "verifier_signature",
    ]);
    expect(encoded.test_cases[1]).toEqual({
      test_id: "t1",
      input: { i: 1 },
      category: "basic",
      weight: 500,
      answer_commitment: "3f".repeat(32),
    });
  });

  it("decodes the request back to the typed request", () => {
    const request = makeChallengeRequest();
    expect(decodeChallengeRequest(encodeChallengeRequest(request))).toEqual(request);
  });

  it("encodes every ExpectedOutput variant externally tagged", () => {
    const variants: [ExpectedOutput, unknown][] = [
      [{ kind: "ExactMatch", value: [1, "a"] }, { ExactMatch: { value: [1, "a"] } }],
      [
        { kind: "SchemaMatch", schema: { type: "object" } },
        { SchemaMatch: { schema: { type: "object" } } },
      ],
      [{ kind: "ContainsAll", required: ["a", "b"] }, { ContainsAll: { required: ["a", "b"] } }],
      [{ kind: "ContainsNone", forbidden: ["x"] }, { ContainsNone: { forbidden: ["x"] } }],
      [
        { kind: "CustomEval", evaluatorOutletId: "o-1" },
        { CustomEval: { evaluator_outlet_id: "o-1" } },
      ],
    ];
    for (const [expected, wire] of variants) {
      const testCases: TestCase[] = [
        { testId: "t", input: null, expected, category: "c", weight: 10_000 },
      ];
      expect(JSON.parse(encodeTestCases(testCases))[0]).toEqual({
        test_id: "t",
        input: null,
        expected: wire,
        category: "c",
        weight: 10_000,
      });
    }
  });

  it("rejects a wrong-length signature, a non-hex id or commitment before any bridge call", () => {
    expect(() =>
      encodeChallengeRequest(makeChallengeRequest({ verifierSignature: [1, 2, 3] })),
    ).toThrow("ChallengeRequest.verifierSignature must be exactly 64 elements, got 3");
    expect(() => encodeChallengeRequest(makeChallengeRequest({ challengeId: "chal-1" }))).toThrow(
      "ChallengeRequest.challengeId must be 64 lowercase hex characters",
    );
    const [first, ...rest] = makeChallengeRequest().testCases;
    const badCase = { ...(first as ChallengeRequest["testCases"][number]), answerCommitment: "x" };
    expect(() =>
      encodeChallengeRequest(makeChallengeRequest({ testCases: [badCase, ...rest] })),
    ).toThrow("ChallengeCase.answerCommitment must be 64 lowercase hex characters");
  });

  it("decode refuses a case that carries no answer commitment", () => {
    const wire = JSON.parse(encodeChallengeRequest(makeChallengeRequest()));
    delete wire.test_cases[0].answer_commitment;
    expect(() => decodeChallengeRequest(JSON.stringify(wire))).toThrow(
      "ChallengeCase.answer_commitment must be 64 lowercase hex characters",
    );
  });
});

describe("encodeChallengeResponse / decodeChallengeResponse / decodeCaseResults", () => {
  it("emits the 6-field snake_case response and decodes it back", () => {
    const response = makeChallengeResponse();
    expect(JSON.parse(encodeChallengeResponse(response))).toEqual({
      challenge_id: "ab".repeat(32),
      request_digest: "5e".repeat(32),
      subject: "did:dht:subject",
      attempt: 1,
      outputs: [{ test_id: "t0", output: { ok: true } }],
      subject_signature: Array.from({ length: 64 }, () => 4),
    });
    expect(decodeChallengeResponse(encodeChallengeResponse(response))).toEqual(response);
  });

  it("rejects a wrong-length signature or a negative attempt before any bridge call", () => {
    expect(() =>
      encodeChallengeResponse(makeChallengeResponse({ subjectSignature: Array(63).fill(4) })),
    ).toThrow("ChallengeResponse.subjectSignature must be exactly 64 elements, got 63");
    expect(() => encodeChallengeResponse(makeChallengeResponse({ attempt: -1 }))).toThrow(
      "ChallengeResponse.attempt must be an integer",
    );
  });

  it("decodes case results, with an absent reason as null", () => {
    expect(
      decodeCaseResults(
        JSON.stringify([
          { passed: true, reason: null },
          { passed: false, reason: "no" },
        ]),
      ),
    ).toEqual([
      { passed: true, reason: null },
      { passed: false, reason: "no" },
    ]);
    expect(() => decodeCaseResults(JSON.stringify([{ reason: null }]))).toThrow(
      "CaseResult.passed must be a boolean",
    );
  });
});

describe("scp.trustCreateChallenge / trustRespondToChallenge / trustGradeResponse — typed inputs", () => {
  let cleanup: (() => Promise<void>) | undefined;
  afterEach(async () => {
    await cleanup?.();
    cleanup = undefined;
  });

  it("serializes the typed attestation envelope before crossing FFI", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("trustVerifyAttestation", () => ({
      valid: false,
      chainDepth: 0,
      errorMessage: "unresolvable issuer",
    }));

    await scp.trustVerifyAttestation("ctx-1", attestationEnvelope);
    const call = native.__lastCall("trustVerifyAttestation");
    expect(call?.args).toEqual(["ctx-1", encodeAttestation(attestationEnvelope)]);
  });

  it("trustCreateChallenge passes the context, window and options and decodes the request", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    const request = makeChallengeRequest();
    native.__stub("trustCreateChallenge", async () => ({
      challengeId: request.challengeId,
      requestJson: encodeChallengeRequest(request),
    }));

    const testCases = makeTestCases(20);
    const created = await scp.trustCreateChallenge(
      "did:dht:v",
      "did:dht:s",
      SCHEMA_URI,
      testCases,
      "ctx-1",
      3_600,
      { policy: { maxRetries: 1, cooldownSecs: 600 }, evaluatorContextId: "ctx-eval" },
    );
    expect(created).toEqual(request);
    expect(native.__lastCall("trustCreateChallenge")?.args).toEqual([
      "did:dht:v",
      "did:dht:s",
      SCHEMA_URI,
      encodeTestCases(testCases),
      3_600,
      "ctx-1",
      "ctx-eval",
      { maxRetries: 1, cooldownSecs: 600 },
    ]);

    await scp.trustCreateChallenge("did:dht:v", "did:dht:s", SCHEMA_URI, testCases, "ctx-1", 60);
    expect(native.__lastCall("trustCreateChallenge")?.args.slice(5)).toEqual([
      "ctx-1",
      undefined,
      undefined,
    ]);
  });

  it("trustRespondToChallenge serializes the request and outputs and decodes the response", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    const response = makeChallengeResponse();
    native.__stub("trustRespondToChallenge", async () => encodeChallengeResponse(response));

    const request = makeChallengeRequest();
    const outputs = [{ testId: "t0", output: { ok: true } }];
    expect(await scp.trustRespondToChallenge("did:dht:subject", request, outputs, 1)).toEqual(
      response,
    );
    expect(native.__lastCall("trustRespondToChallenge")?.args).toEqual([
      "did:dht:subject",
      encodeChallengeRequest(request),
      encodeTestOutputs(outputs),
      1,
    ]);
  });

  it("trustGradeResponse serializes both records and decodes the record and case results", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("trustGradeResponse", async () => ({
      recordJson: JSON.stringify(recordWire),
      reasonsJson: JSON.stringify([{ passed: false, reason: "mismatch" }]),
      trustStoreError: "disk full",
    }));

    const request = makeChallengeRequest();
    const response = makeChallengeResponse();
    const graded = await scp.trustGradeResponse("did:dht:verifier", request, response);
    expect(graded).toEqual({
      record: makeRecord(),
      caseResults: [{ passed: false, reason: "mismatch" }],
      trustStoreError: "disk full",
    });
    expect(native.__lastCall("trustGradeResponse")?.args).toEqual([
      "did:dht:verifier",
      encodeChallengeRequest(request),
      encodeChallengeResponse(response),
    ]);
  });

  it("a bridge refusal keeps its code through each operation", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    for (const code of [
      ANSWER_KEY_MISMATCH_CODE,
      GRADING_CAPACITY_EXHAUSTED_CODE,
      NON_CANONICAL_IDENTIFIER_CODE,
      TOO_MANY_CAPABILITY_REQUIREMENTS_CODE,
      GRADING_LEASE_LOST_CODE,
    ]) {
      native.__stub("trustGradeResponse", () => {
        throw new Error(`[${code}] refused`);
      });
      const refusal = scp.trustGradeResponse(
        "did:dht:v",
        makeChallengeRequest(),
        makeChallengeResponse(),
      );
      await expect(refusal).rejects.toBeInstanceOf(ValidationError);
      await expect(refusal).rejects.toMatchObject({ code });
    }
  });
});
