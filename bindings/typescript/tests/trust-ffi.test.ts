/**
 * Real-FFI call-through tests for the typed trust-input wrappers (ADR-058,
 * spec §7.3 / §7.3.4).
 *
 * These drive `scp.aggregateTrustInput`, `scp.trustVerifyAttestation`, and
 * `scp.trustVerifyResponse` against the real NAPI addon, proving the
 * types.ts-serialized JSON parses and evaluates on the real Rust
 * deserializers — not just that the encoders emit the pinned shapes
 * (`trust.test.ts` covers that with the mock bridge). Mirrors the Kotlin
 * `TrustAggregateFfiTest` / Swift call-through suites scenario-for-scenario.
 *
 * If the native addon is not available, all tests are skipped gracefully
 * (same guard as `e2e-relay.test.ts`).
 */

import { describe, expect, test } from "bun:test";
import { SCP } from "../src/scp";
import type {
  CachedAttestationEnvelope,
  ChallengeRequest,
  ChallengeResponse,
  EventLogEntry,
} from "../src/types";

// ---------------------------------------------------------------------------
// Guard: skip if native addon unavailable
// ---------------------------------------------------------------------------

let scp: SCP | null = null;
let skipReason = "";

try {
  scp = new SCP({ storage: { type: "in_memory" } });
} catch (e: unknown) {
  const msg = e instanceof Error ? e.message : String(e);
  skipReason = `Native NAPI bridge not available: ${msg}`;
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
    test("typed inputs cross FFI and aggregate", () => {
      const resultJson = live.aggregateTrustInput(
        "ctx-aggregate-ffi",
        "did:dht:zSubject",
        [genesisMemberJoined],
        Array.from({ length: 32 }, () => 0),
      );
      const result = JSON.parse(resultJson) as Record<string, unknown>;
      expect(result).toHaveProperty("participation_record");
      expect(result).toHaveProperty("challenge_results");
    });

    test("typed threshold and attestor maps parse on the Rust HashMap deserializers", () => {
      const resultJson = live.aggregateTrustInput(
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
    test("a typed attestation envelope parses and verification runs (invalid signature)", () => {
      const attestation: CachedAttestationEnvelope = {
        id: "att-ffi-1",
        attestationType: "AgentCapability",
        issuer: "did:dht:zIssuer",
        subject: "did:dht:zSubject",
        claim: { capability: "scp:capability:schema-validation/v1" },
        issuedAt: 1_700_000_000,
        revocationStatus: "Active",
        signature: Array.from({ length: 64 }, () => 0),
      };
      // The dummy signature cannot verify — but a structured `valid: false`
      // result (not a parse error) proves the serialized envelope reached the
      // real verifier.
      const result = live.trustVerifyAttestation(attestation) as {
        valid: boolean;
        errorMessage: string;
      };
      expect(result.valid).toBe(false);
      expect(result.errorMessage.length).toBeGreaterThan(0);
    });

    test("a typed challenge pair parses and verification runs (invalid signature)", () => {
      const challenge: ChallengeRequest = {
        challengeId: "chal-ffi-1",
        challengeType: "scp:capability:schema-validation/v1",
        challengerDid: "did:dht:zChallenger",
        subjectDid: "did:dht:zSubject",
        capabilityUri: "scp:capability:schema-validation/v1",
        parameters: {},
        timeout: { secs: 300, nanos: 0 },
        signature: Array.from({ length: 64 }, () => 0),
      };
      const response: ChallengeResponse = {
        challengeId: "chal-ffi-1",
        responderDid: "did:dht:zSubject",
        result: { passed: true },
        completedAt: 1_700_000_100,
        signature: Array.from({ length: 64 }, () => 0),
      };
      // Dummy signatures cannot verify — the structured `false` (not a parse
      // error) proves both serialized records reached the real verifier.
      expect(live.trustVerifyResponse(challenge, response)).toBe(false);
    });
  });
}
