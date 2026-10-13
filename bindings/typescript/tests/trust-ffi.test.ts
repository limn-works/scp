/**
 * Real-FFI call-through tests for the typed trust-input wrappers (ADR-058,
 * spec §7.3 / §7.3.4).
 *
 * These drive `scp.aggregateTrustInput`, `scp.trustVerifyAttestation`, and
 * `scp.trustCreateChallenge` and `scp.trustVerifyResponse` against the real NAPI addon, proving the
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
import type {
  CachedAttestationEnvelope,
  ChallengeRequest,
  ChallengeResponse,
  EventLogEntry,
  TestCase,
} from "../src/types";
import { CHALLENGE_SUITE_BELOW_MINIMUM_CODE, decodeChallengeRequest } from "../src/types";

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

  describe("scp.trustVerifyAttestation / scp.trustVerifyResponse — real-FFI call-through", () => {
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

    test("trustCreateChallenge refuses a protocol suite below its minimum with SCP-VALID-7039", async () => {
      const verifier = await createInMemoryIdentity(live);
      const subject = await createInMemoryIdentity(live);
      let caught: unknown;
      try {
        await live.trustCreateChallenge(verifier.did, subject.did, SCHEMA_URI, testCases(19));
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(ScpError);
      expect((caught as ScpError).code).toBe(CHALLENGE_SUITE_BELOW_MINIMUM_CODE);
    });

    test("a created request decodes into the SDK types; a forged response is refused", async () => {
      const verifier = await createInMemoryIdentity(live);
      const subject = await createInMemoryIdentity(live);
      const cases = testCases(20);
      const created = await live.trustCreateChallenge(verifier.did, subject.did, SCHEMA_URI, cases);
      const challenge: ChallengeRequest = decodeChallengeRequest(created.challengeJson);
      expect(challenge.challengeId).toBe(created.challengeId);
      expect(challenge.verifier).toBe(verifier.did);
      expect(challenge.subject).toBe(subject.did);
      expect(challenge.testCases).toEqual(cases);
      expect(challenge.verifierSignature).toHaveLength(64);

      const response: ChallengeResponse = {
        challengeId: challenge.challengeId,
        responderDid: subject.did,
        result: { passed: true, score: 10_000, test_count: 20, pass_count: 20 },
        completedAt: Math.floor(Date.now() / 1000),
        signature: Array.from({ length: 64 }, () => 0),
      };
      let caught: unknown;
      try {
        await live.trustVerifyResponse(verifier.did, challenge, response, "ctx-ffi");
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(ScpError);
      expect((caught as ScpError).code).toBe("SCP-VALID-7003");
    });
  });
}
