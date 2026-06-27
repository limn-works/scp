/**
 * Tests for the structured trust-signal consumer (ADR-055, spec §7.2.4).
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
 * See `.docs/adrs/phase-2.md` ADR-055 and `.docs/specs/07-trust-validation-and-capabilities.md` §7.2.4.
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
      // SCP.ucanEvaluate(handle, token, capability, presentingAgentDid, proofTokens)
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

    const result = await scp.ucanEvaluate("handle", "token-a", "tool:invoke:*");
    expect(result).toEqual({
      tokensValid: true,
      signaturesValid: false,
      withinCeiling: true,
      nonceValid: true,
      notRevoked: false,
      timeBoundsValid: true,
    });
  });

  it("forwards the optional presenting-agent DID and proof tokens", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("ucanEvaluate", async () => ALL_PASS);

    await scp.ucanEvaluate("handle", "token-a", "*", "did:dht:agent", ["proof-1"]);
    const call = native.__lastCall("ucanEvaluate");
    expect(call).toBeDefined();
    // handle, token, capability, presentingAgentDid, proofTokens
    expect(call?.args[3]).toBe("did:dht:agent");
    expect(call?.args[4]).toEqual(["proof-1"]);
  });

  it("normalizes omitted optionals to null on the wire", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("ucanEvaluate", async () => ALL_PASS);

    await scp.ucanEvaluate("handle", "token-a", "*");
    const call = native.__lastCall("ucanEvaluate");
    expect(call?.args[3]).toBeNull();
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
    native.__stub("eventLogQuery", async () => []);

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
    native.__stub("eventLogQuery", async () => []);

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
    native.__stub("eventLogQuery", async () => []);

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

  it("builds the Layer-2 behavioral record from ToolInvoked events", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    // The mock returns the REAL NAPI/WASM bridge shape that `eventLogQuery`
    // dispatches verbatim — `{eventType, actorDid, timestamp, payloadJson (a
    // JSON STRING), sequence}`. The bridge never emits a `payload` OBJECT, and
    // the queryable payloadJson carries no tool id, so all ToolInvoked events
    // bucket under the literal "ToolInvoked" key (spec §7.2.4; per-tool-type
    // keying awaits ADR-051's richer payload).
    native.__stub("eventLogQuery", async () => [
      {
        eventType: "ToolInvoked",
        actorDid: "did:dht:subject",
        timestamp: 1,
        payloadJson: JSON.stringify({ hash: "aa" }),
        sequence: 0,
      },
      {
        eventType: "ToolInvoked",
        actorDid: "did:dht:subject",
        timestamp: 2,
        payloadJson: JSON.stringify({ hash: "bb" }),
        sequence: 1,
      },
      {
        eventType: "GovernanceActionExecuted",
        actorDid: "did:dht:subject",
        timestamp: 3,
        payloadJson: JSON.stringify({ hash: "cc" }),
        sequence: 2,
      },
    ]);

    const result = await scp.evaluateTrust("handle", "did:dht:subject", "ctx-1");
    expect(result.behavioralRecord.participationCount).toBe(3);
    expect(result.behavioralRecord.toolInvocations).toEqual({ ToolInvoked: 2 });
    expect(result.behavioralRecord.governanceActionsBy).toBe(1);
    expect(result.subjectDid).toBe("did:dht:subject");
    expect(result.contextId).toBe("ctx-1");
  });

  it("scopes the Layer-2 event-log query to the subject DID", async () => {
    const mock = createMockNativeScp();
    const { scp } = mountMockScp(mock);
    cleanup = () => scp.shutdown(0);
    mock.__stub("eventLogQuery", async () => []);

    await scp.evaluateTrust("handle", "did:dht:subject", "ctx-1");
    const call = mock.__lastCall("eventLogQuery");
    expect(call).toBeDefined();
    // The filter is the second arg, serialized as JSON with the actorDid.
    const filter = JSON.parse(call?.args[1] as string) as { actorDid?: string };
    expect(filter.actorDid).toBe("did:dht:subject");
  });
});
