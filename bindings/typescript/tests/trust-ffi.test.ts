/**
 * Real-FFI call-through tests for the typed trust-input wrappers (ADR-058,
 * spec §7.3 / §7.3.4).
 *
 * These drive `scp.aggregateTrustInput`, `scp.trustVerifyAttestation`, and
 * the challenge operations (`scp.trustCreateChallenge`,
 * `scp.trustRespondToChallenge`, `scp.trustGradeResponse`,
 * `scp.checkCapabilityRequirements`) against the real NAPI addon, proving the
 * types.ts-serialized JSON parses and evaluates on the real Rust
 * deserializers — not just that the encoders emit the pinned shapes
 * (`trust.test.ts` covers that with the mock bridge). Mirrors the Kotlin
 * `TrustAggregateFfiTest` / Swift call-through suites scenario-for-scenario.
 *
 * If the native addon is not available, all tests are skipped gracefully
 * (same guard as `e2e-relay.test.ts`).
 */

import { describe, expect, test } from "bun:test";
import { ScpError } from "../src/errors";
import { SCP } from "../src/scp";
import type { CachedAttestationEnvelope, EventLogEntry, TestCase } from "../src/types";
import { CHALLENGE_SUITE_BELOW_MINIMUM_CODE, encodeCapabilityRequirements } from "../src/types";

const SCHEMA_URI = "scp:capability:schema-validation/v1";

/** `n` exact-match cases whose weights sum to 10000. */
function testCases(n: number): TestCase[] {
  const weight = Math.floor(10_000 / n);
  return Array.from({ length: n }, (_, i) => ({
    testId: `t${i}`,
    input: { i },
    expected: { kind: "ExactMatch", value: { ok: true } },
    category: "basic",
    weight: i === 0 ? 10_000 - weight * (n - 1) : weight,
  }));
}

import { createInMemoryIdentity } from "./harness-custody";
import { skipReasonIfAddonAbsent } from "./napi-guard";

// ---------------------------------------------------------------------------
// Guard: skip if native addon unavailable
// ---------------------------------------------------------------------------

let scp: SCP | null = null;
let skipReason = "";

try {
  scp = new SCP({ storage: { type: "in_memory" } });
} catch (e: unknown) {
  skipReason = skipReasonIfAddonAbsent(e);
}

/** A genesis `MemberJoined` event for the aggregated subject. */
const genesisMemberJoined: EventLogEntry = {
  eventType: "MemberJoined",
  actorDid: "did:dht:zSubject",
  timestamp: 1_700_000_000,
  sequence: 0,
  payload: { data: [] },
  prevHash: Array.from({ length: 32 }, () => 0),
  signature: Array.from({ length: 64 }, () => 0),
};

if (scp === null) {
  describe("Trust FFI call-through (SKIPPED)", () => {
    test.skip(`all tests skipped: ${skipReason}`, () => {});
  });
} else {
  const live = scp;

  describe("scp.aggregateTrustInput — real-FFI call-through", () => {
    test("typed inputs cross FFI and aggregate", async () => {
      const resultJson = await live.aggregateTrustInput(
        "ctx-aggregate-ffi",
        "did:dht:zSubject",
        [genesisMemberJoined],
        Array.from({ length: 32 }, () => 0),
      );
      const result = JSON.parse(resultJson) as Record<string, unknown>;
      expect(result).toHaveProperty("participation_record");
      expect(result).toHaveProperty("challenge_results");
    });

    test("typed threshold and attestor maps parse on the Rust HashMap deserializers", async () => {
      const resultJson = await live.aggregateTrustInput(
        "ctx-aggregate-ffi",
        "did:dht:zSubject",
        [genesisMemberJoined],
        Array.from({ length: 32 }, () => 0),
        [],
        { Endorsement: { requiredCount: 1, totalAttestors: 1, independenceThreshold: 0 } },
        {
          Endorsement: [
            {
              did: "did:dht:zAttestor",
              contextMemberships: ["ctx-aggregate-ffi"],
              endorsements: [],
            },
          ],
        },
      );
      const result = JSON.parse(resultJson) as Record<string, unknown>;
      expect(result).toHaveProperty("threshold_counts");
    });
  });

  describe("scp.trustVerifyAttestation and the challenge operations — real-FFI call-through", () => {
    /** A typed envelope whose 64-byte signature is all zeros. */
    const zeroSignedAttestation = (issuer: string): CachedAttestationEnvelope => ({
      id: "att-ffi-1",
      attestationType: "AgentCapability",
      issuer,
      subject: "did:dht:zSubject",
      claim: { capability: "scp:capability:schema-validation/v1" },
      issuedAt: 1_700_000_000,
      revocationStatus: "Active",
      signature: Array.from({ length: 64 }, () => 0),
    });

    test("an instance without a DID resolver fails closed with SCP-VALID-7052", async () => {
      // A fresh instance: no identity, so no DID resolver. The issuer's
      // #active key cannot be resolved, which is an error, never a verdict.
      // The issuer DID in the message proves the envelope parsed (a parse
      // failure is SCP-VALID-7012 and names no issuer).
      const bare = new SCP({ storage: { type: "in_memory" } });
      let caught: unknown;
      try {
        await bare.trustVerifyAttestation("ctx-ffi-1", zeroSignedAttestation("did:dht:zIssuer"));
      } catch (e: unknown) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(ScpError);
      expect((caught as ScpError).code).toBe("SCP-VALID-7052");
      expect((caught as ScpError).message).toContain("did:dht:zIssuer");
    });

    test("a resolvable issuer with an invalid signature is a valid: false verdict", async () => {
      // The issuer is an identity on this instance, so its #active key
      // resolves and verification runs to a structured rejection.
      const own = new SCP({ storage: { type: "in_memory" } });
      const issuer = await createInMemoryIdentity(own);
      const result = (await own.trustVerifyAttestation(
        "ctx-ffi-1",
        zeroSignedAttestation(issuer.did),
      )) as { valid: boolean; errorMessage: string };
      expect(result.valid).toBe(false);
      expect(result.errorMessage).toContain("signature");
    });

    /** A context on `live` whose governance requires `SCHEMA_URI` graded by `verifier`. */
    async function requiringContext(verifierDid: string): Promise<string> {
      const creator = await createInMemoryIdentity(live);
      const ctx = await live.contextCreate(
        creator,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write"],
          memoryScope: "ephemeral",
          governance: "single_admin",
          capabilityRequirements: encodeCapabilityRequirements([
            {
              capability: SCHEMA_URI,
              verificationLevel: "ChallengeVerified",
              trustedVerifiers: [verifierDid],
            },
          ]),
        }),
      );
      return ctx.contextId;
    }

    test("trustCreateChallenge refuses a protocol suite below its minimum with SCP-VALID-7039", async () => {
      const verifier = await createInMemoryIdentity(live);
      const subject = await createInMemoryIdentity(live);
      const contextId = await requiringContext(verifier.did);
      let caught: unknown;
      try {
        await live.trustCreateChallenge(
          verifier.did,
          subject.did,
          SCHEMA_URI,
          testCases(19),
          contextId,
          3_600,
        );
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(ScpError);
      expect((caught as ScpError).code).toBe(CHALLENGE_SUITE_BELOW_MINIMUM_CODE);
    });

    // Test 38: one challenge from creation to admission through the real
    // bridge. The context's governance requires the capability, so the
    // subject is refused before it holds a record and admitted after.
    test("challenge_round_trip", async () => {
      const verifier = await createInMemoryIdentity(live);
      const subject = await createInMemoryIdentity(live);
      const contextId = await requiringContext(verifier.did);
      const cases = testCases(20);

      const request = await live.trustCreateChallenge(
        verifier.did,
        subject.did,
        SCHEMA_URI,
        cases,
        contextId,
        3_600,
      );
      expect(request.verifier).toBe(verifier.did);
      expect(request.subject).toBe(subject.did);
      expect(request.contextId).toBe(contextId);
      expect(request.capabilityUri).toBe(SCHEMA_URI);
      expect(request.testCases.map((c) => c.testId)).toEqual(cases.map((c) => c.testId));
      expect(request.expiresAt - request.createdAt).toBe(3_600);
      // The request commits to each answer and never carries it.
      expect(JSON.stringify(request)).not.toContain("ExactMatch");

      await expect(
        live.checkCapabilityRequirements(contextId, subject.did, [], []),
      ).rejects.toMatchObject({ code: "SCP-VALID-7076" });

      const response = await live.trustRespondToChallenge(
        subject.did,
        request,
        cases.map((c) => ({ testId: c.testId, output: { ok: true } })),
        1,
      );
      expect(response.challengeId).toBe(request.challengeId);
      expect(response.subject).toBe(subject.did);
      expect(response.attempt).toBe(1);

      const graded = await live.trustGradeResponse(verifier.did, request, response);
      expect(graded.trustStoreError).toBeNull();
      expect(graded.caseResults).toHaveLength(20);
      expect(graded.caseResults.every((c) => c.passed)).toBe(true);
      const record = graded.record;
      expect(record.passed).toBe(true);
      expect(record.attempt).toBe(1);
      expect(record.passCount).toBe(20);
      expect(record.testCount).toBe(20);
      expect(record.challengeId).toBe(request.challengeId);
      expect(record.verifier).toBe(verifier.did);
      expect(record.subject).toBe(subject.did);
      expect(record.contextId).toBe(contextId);

      await expect(
        live.checkCapabilityRequirements(contextId, subject.did, [], [record]),
      ).resolves.toBeUndefined();
      // Every field is signed: a record whose attempt was altered is dropped.
      await expect(
        live.checkCapabilityRequirements(contextId, subject.did, [], [{ ...record, attempt: 2 }]),
      ).rejects.toMatchObject({ code: "SCP-VALID-7076" });
    });

    test("a forged response is refused and grades nothing", async () => {
      const verifier = await createInMemoryIdentity(live);
      const subject = await createInMemoryIdentity(live);
      const contextId = await requiringContext(verifier.did);
      const cases = testCases(20);
      const request = await live.trustCreateChallenge(
        verifier.did,
        subject.did,
        SCHEMA_URI,
        cases,
        contextId,
        3_600,
      );
      const response = await live.trustRespondToChallenge(
        subject.did,
        request,
        cases.map((c) => ({ testId: c.testId, output: { ok: true } })),
        1,
      );
      let caught: unknown;
      try {
        await live.trustGradeResponse(verifier.did, request, {
          ...response,
          subjectSignature: Array.from({ length: 64 }, () => 0),
        });
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(ScpError);
      // The forgery took no attempt: the real response still grades as attempt 1.
      const graded = await live.trustGradeResponse(verifier.did, request, response);
      expect(graded.record.attempt).toBe(1);
      expect(graded.record.passed).toBe(true);
    });
  });
}
