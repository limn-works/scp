/**
 * Regression tests for the free-function `evaluateTrust` facade
 * (`src/trust.ts`) and the `SCP.evaluateTrust` implementation it delegates to.
 *
 * ADR-059 ("Structured Capability/Trust Validation Across the FFI; SDKs Consume
 * Typed Results, Not Prose", Decision 3) forbids an SDK from reconstructing
 * which validation stage failed by matching error-message text. `src/trust.ts`
 * broke that rule until this suite landed: six prefix tables fed a
 * `__classifyUcanError` helper that decided a security outcome with
 * `String.prototype.startsWith` over Rust `Display` text, so rewording one Rust
 * error message silently reclassified the verdict.
 *
 * The suite pins three properties:
 *
 * 1. Rewording a bridge error message changes no trust outcome
 *    (`stays identical when the bridge error message is reworded`). Each case
 *    below reuses a message the deleted prefix tables matched, paired with a
 *    rewording of the same failure. A reader who reintroduces message-branching
 *    makes the paired outcomes diverge and this test fails.
 * 2. The verdict comes from the six typed `CapabilityValidation` booleans that
 *    cross the FFI as data.
 * 3. Layer 1 evaluates every attenuation the token declares: it supplies no
 *    challenge capability, so it never selects `att[0].with`.
 */

import { describe, expect, it } from "bun:test";
import type { Context } from "../src/context";
import { ContextError, ScpError, UcanPermissionError } from "../src/errors";
import { SCP } from "../src/scp";
import { evaluateTrust } from "../src/trust";
import type { BehavioralRecord, CapabilityValidation } from "../src/types";

const SUBJECT = "did:dht:subject";
const CONTEXT_ID = "ctx-1";

/** A token declaring two attenuations, so `att[0]` selection is observable. */
function twoAttenuationToken(): string {
  const b64 = (o: unknown) =>
    Buffer.from(JSON.stringify(o), "utf8")
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  return [
    b64({ alg: "EdDSA", typ: "JWT", ucv: "0.10.0" }),
    b64({
      iss: "did:dht:issuer",
      aud: SUBJECT,
      att: [
        { with: "scp:ctx:ctx-1/messages:read", can: "read" },
        { with: "scp:ctx:ctx-1/messages:write", can: "write" },
      ],
    }),
    b64({ sig: "unused" }),
  ].join(".");
}

const ALL_TRUE: CapabilityValidation = {
  tokensValid: true,
  signaturesValid: true,
  withinCeiling: true,
  nonceValid: true,
  notRevoked: true,
  timeBoundsValid: true,
};

const REAL_FACTS: BehavioralRecord = {
  subjectDid: SUBJECT,
  participationDurationSecs: 4207,
  governanceActionsAgainst: 2,
  governanceActionsBy: 5,
  outletInvocationCount: 11,
  outletInvocationCountAnchored: false,
  contextCreationCount: 3,
  roleProgressionCount: 1,
  attestationCount: 4,
  attestationCountAnchored: false,
  computedAt: 1_700_000_000,
  eventLogRoot: "ab".repeat(32),
};

/** Records every `ucanEvaluate` call so the test can inspect its arguments. */
interface EvaluateCall {
  readonly token: string;
  readonly presentingAgentDid: string;
  readonly capability: string | null | undefined;
  readonly argCount: number;
}

interface Doubles {
  readonly ucanEvaluate: (...args: readonly unknown[]) => Promise<CapabilityValidation>;
  readonly participationRecord?: (ctx: string, subj: string) => Promise<BehavioralRecord>;
}

/**
 * Builds an object that runs the REAL `SCP.evaluateTrust` body while its two
 * collaborators (`ucanEvaluate`, `participationRecord`) are test doubles. Own
 * properties shadow the prototype methods, so the implementation under test is
 * the shipped one rather than a copy.
 */
function scpWith(doubles: Doubles): { scp: SCP; calls: EvaluateCall[] } {
  const calls: EvaluateCall[] = [];
  const scp = Object.create(SCP.prototype) as SCP;
  Object.assign(scp, {
    ucanEvaluate: async (...args: readonly unknown[]) => {
      calls.push({
        token: args[1] as string,
        presentingAgentDid: args[2] as string,
        capability: args[3] as string | null | undefined,
        argCount: args.length,
      });
      return await doubles.ucanEvaluate(...args);
    },
    participationRecord:
      doubles.participationRecord ?? (async (): Promise<BehavioralRecord> => REAL_FACTS),
  });
  return { scp, calls };
}

const CONTEXT = {
  _rawHandle: { contextId: CONTEXT_ID } as object,
  contextId: CONTEXT_ID,
} as unknown as Context;

/**
 * Message pairs. Each pair states one failure twice: the left string is a
 * spelling the deleted prefix tables matched, and the right string is the same
 * failure reworded. Prose-driven classification produces different outcomes
 * within a pair; typed-code classification produces the same outcome.
 */
const REWORDED_PAIRS: readonly (readonly [string, string])[] = [
  ["token expired", "the token's validity window has already closed"],
  ["nonce reused: abc123", "this nonce was already presented"],
  ["signature verification failed", "the Ed25519 signature does not verify"],
  ["capability outside ceiling: scp:ctx:x/a:b", "the capability exceeds the context ceiling"],
  ["token revoked: bafkreiabc", "the issuer withdrew this token"],
  ["malformed token: DID not found", "the issuer DID could not be resolved"],
];

describe("evaluateTrust — Layer 1 reads typed booleans, never message text", () => {
  it("derives the verdict from the six CapabilityValidation booleans", async () => {
    const structured: CapabilityValidation = { ...ALL_TRUE, nonceValid: false };
    const { scp } = scpWith({ ucanEvaluate: async () => structured });

    const result = await evaluateTrust(scp, SUBJECT, CONTEXT, [twoAttenuationToken()]);

    expect(result.capabilityValidation).toEqual(structured);
  });

  it("AND-combines the booleans across the token set", async () => {
    const perToken: CapabilityValidation[] = [
      { ...ALL_TRUE, withinCeiling: false },
      { ...ALL_TRUE, notRevoked: false },
    ];
    let index = 0;
    const { scp } = scpWith({
      ucanEvaluate: async () => {
        const v = perToken[index];
        index += 1;
        if (v === undefined) throw new Error("unexpected extra ucanEvaluate call");
        return v;
      },
    });

    const result = await evaluateTrust(scp, SUBJECT, CONTEXT, ["token-a", "token-b"]);

    expect(result.capabilityValidation).toEqual({
      ...ALL_TRUE,
      withinCeiling: false,
      notRevoked: false,
    });
  });

  // THE REGRESSION THIS SUITE EXISTS FOR: rewording a Rust error message must
  // not move a trust outcome. Each pair states one failure two ways.
  for (const [tableSpelling, reworded] of REWORDED_PAIRS) {
    it(`stays identical when the bridge error message is reworded: "${tableSpelling}"`, async () => {
      const outcomes = await Promise.all(
        [tableSpelling, reworded].map(async (core) => {
          const { scp } = scpWith({
            ucanEvaluate: async () => {
              throw new UcanPermissionError(
                `[SCP-PERM-3001] permission error: ${core} — check token format`,
                "SCP-PERM-3001",
              );
            },
          });
          try {
            await evaluateTrust(scp, SUBJECT, CONTEXT, [twoAttenuationToken()]);
            return { rejected: false, code: null as string | null };
          } catch (error) {
            return {
              rejected: true,
              code: error instanceof ScpError ? error.code : null,
            };
          }
        }),
      );

      // Both spellings of the same failure produce the same outcome. The
      // deleted prose classifier turned the left spelling into a partially-true
      // verdict and the right spelling into an all-false one.
      expect(outcomes[0]).toEqual(outcomes[1] as (typeof outcomes)[0]);
      expect(outcomes[0]?.rejected).toBe(true);
      expect(outcomes[0]?.code).toBe("SCP-PERM-3001");
    });
  }
});

describe("evaluateTrust — Layer 1 considers every attenuation", () => {
  it("supplies no challenge capability, so it never selects att[0].with", async () => {
    const token = twoAttenuationToken();
    const { scp, calls } = scpWith({ ucanEvaluate: async () => ALL_TRUE });

    await evaluateTrust(scp, SUBJECT, CONTEXT, [token]);

    expect(calls).toHaveLength(1);
    const call = calls[0];
    // Intrinsic-validity mode: `evaluate_ucan` parses the FULL `att` set and
    // runs the ceiling and Category-A checks over every granted capability
    // (crates/scp-protocol/src/crypto/ucan/validate.rs). Passing a capability
    // here would impose an invoked-capability grant-match the caller never
    // asked for, and passing `att[0].with` would ignore `att[1]`.
    expect(call?.capability).toBeUndefined();
    expect(call?.argCount).toBe(3);
    expect(call?.token).toBe(token);
    expect(call?.presentingAgentDid).toBe(SUBJECT);
  });

  it("evaluates each supplied token exactly once", async () => {
    const { scp, calls } = scpWith({ ucanEvaluate: async () => ALL_TRUE });

    await evaluateTrust(scp, SUBJECT, CONTEXT, ["token-a", "token-b", "token-c"]);

    expect(calls.map((c) => c.token)).toEqual(["token-a", "token-b", "token-c"]);
  });

  it("reports every field false when no tokens are supplied", async () => {
    const { scp, calls } = scpWith({
      ucanEvaluate: async () => {
        throw new Error("the bridge must not be called with no tokens");
      },
    });

    const result = await evaluateTrust(scp, SUBJECT, CONTEXT);

    expect(calls).toHaveLength(0);
    expect(result.capabilityValidation).toEqual({
      tokensValid: false,
      signaturesValid: false,
      withinCeiling: false,
      nonceValid: false,
      notRevoked: false,
      timeBoundsValid: false,
    });
  });
});

describe("evaluateTrust — Layer 2 reports the core's participation facts", () => {
  it("surfaces the Rust-computed counts rather than a hardcoded zero", async () => {
    const { scp } = scpWith({ ucanEvaluate: async () => ALL_TRUE });

    const result = await evaluateTrust(scp, SUBJECT, CONTEXT);

    expect(result.behavioralRecord).toEqual(REAL_FACTS);
    expect(result.contextId).toBe(CONTEXT_ID);
    expect(result.subjectDid).toBe(SUBJECT);
  });

  it("passes the handle's context id to the participation-record lookup", async () => {
    const seen: string[][] = [];
    const { scp } = scpWith({
      ucanEvaluate: async () => ALL_TRUE,
      participationRecord: async (ctx, subj) => {
        seen.push([ctx, subj]);
        return REAL_FACTS;
      },
    });

    await evaluateTrust(scp, SUBJECT, CONTEXT);

    expect(seen).toEqual([[CONTEXT_ID, SUBJECT]]);
  });

  it("zeroes the record on the structured no-facts code, whatever the message says", async () => {
    const messages = [
      "[SCP-CTX-2076] context error: no participation facts",
      "[SCP-CTX-2076] context error: the event log holds nothing for this subject",
    ];
    const records = await Promise.all(
      messages.map(async (message) => {
        const { scp } = scpWith({
          ucanEvaluate: async () => ALL_TRUE,
          participationRecord: async () => {
            throw new ContextError(message, "SCP-CTX-2076");
          },
        });
        return (await evaluateTrust(scp, SUBJECT, CONTEXT)).behavioralRecord;
      }),
    );

    expect(records[0]).toEqual(records[1] as BehavioralRecord);
    expect(records[0]?.participationDurationSecs).toBe(0);
    expect(records[0]?.outletInvocationCount).toBe(0);
    expect(records[0]?.attestationCount).toBe(0);
  });

  it("propagates a context error carrying any other code", async () => {
    const { scp } = scpWith({
      ucanEvaluate: async () => ALL_TRUE,
      participationRecord: async () => {
        throw new ContextError("[SCP-CTX-2001] context error: not initialized", "SCP-CTX-2001");
      },
    });

    await expect(evaluateTrust(scp, SUBJECT, CONTEXT)).rejects.toThrow("SCP-CTX-2001");
  });
});
