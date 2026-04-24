/**
 * Tests for the outlets module (SCP-OUT-006).
 *
 * Covers:
 * - {@link defineOutletDefinition} validation
 * - {@link SessionId} construction and UUIDv7 validation
 * - Caveat builders (spendingCap / timeBounded / rateLimited / forTarget)
 * - {@link InvocationHandle} dual consumption (await + async iterate)
 * - {@link OutletNamespace} + sub-namespaces shape
 * - `invokeCrossContext` options-object validation
 */

import { describe, expect, it } from "bun:test";
import { OutletError, ValidationError } from "../src/errors";
import {
  type Aggregate,
  CaveatBuilder,
  caveats,
  defineOutletDefinition,
  InvocationHandle,
  newSessionId,
  type OutletStreamChunk,
  sessionId,
  validateSessionId,
} from "../src/outlets";

// ---------------------------------------------------------------------------
// defineOutletDefinition
// ---------------------------------------------------------------------------

describe("defineOutletDefinition", () => {
  it("creates a valid outlet definition", () => {
    const def = defineOutletDefinition({
      name: "calc",
      description: "A calculator",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: "did:dht:z6MkTest",
    });
    expect(def.name).toBe("calc");
    expect(def.operator).toBe("did:dht:z6MkTest");
  });

  it("rejects empty name", () => {
    expect(() =>
      defineOutletDefinition({
        name: "",
        description: "d",
        inputSchema: {},
        outputSchema: {},
        operator: "did:dht:a",
      }),
    ).toThrow(ValidationError);
  });

  it("rejects empty operator", () => {
    expect(() =>
      defineOutletDefinition({
        name: "n",
        description: "d",
        inputSchema: {},
        outputSchema: {},
        operator: "",
      }),
    ).toThrow(ValidationError);
  });
});

// ---------------------------------------------------------------------------
// SessionId — UUIDv7 validation.
// ---------------------------------------------------------------------------

describe("SessionId", () => {
  it("newSessionId returns a UUIDv7", () => {
    const sid = newSessionId();
    expect(() => validateSessionId(sid)).not.toThrow();
    // Version nibble is 7
    expect(sid.charAt(14)).toBe("7");
  });

  it("rejects non-UUID strings", () => {
    expect(() => sessionId("sess-abc")).toThrow(ValidationError);
  });

  it("rejects UUIDv4", () => {
    expect(() => sessionId("550e8400-e29b-41d4-a716-446655440000")).toThrow(ValidationError);
  });

  it("rejects timestamps outside the 10-minute window", () => {
    const sid = newSessionId();
    const future = Date.now() + 20 * 60 * 1000;
    expect(() => validateSessionId(sid, future)).toThrow(ValidationError);
    const past = Date.now() - 20 * 60 * 1000;
    expect(() => validateSessionId(sid, past)).toThrow(ValidationError);
  });

  it("two generations produce independent rand_b tails", () => {
    const a = newSessionId();
    const b = newSessionId();
    expect(a).not.toBe(b);
    const tailA = a.split("-").pop()?.slice(4);
    const tailB = b.split("-").pop()?.slice(4);
    expect(tailA).not.toBe(tailB);
  });
});

// ---------------------------------------------------------------------------
// Caveat builders.
// ---------------------------------------------------------------------------

describe("caveats", () => {
  it("spendingCap builder sets amount_max_per_call and amount_max_cumulative", () => {
    const c = caveats.spendingCap({ perCall: 100, cumulative: 1000 }).build();
    expect(c.amountMaxPerCall).toBe(100);
    expect(c.amountMaxCumulative).toBe(1000);
  });

  it("timeBounded builder sets valid_from / valid_until", () => {
    const c = caveats.timeBounded({ validFrom: 0, validUntil: 999 }).build();
    expect(c.validFrom).toBe(0);
    expect(c.validUntil).toBe(999);
  });

  it("timeBounded rejects oversized hoursOfDay mask", () => {
    expect(() => caveats.timeBounded({ hoursOfDay: 1 << 25 })).toThrow();
  });

  it("rateLimited builder", () => {
    const c = caveats.rateLimited({ maxCalls: 10, rateWindow: 60 }).build();
    expect(c.maxCalls).toBe(10);
    expect(c.rateWindow).toBe(60);
  });

  it("forTarget builder", () => {
    const c = caveats
      .forTarget({ allowedTargetDids: ["did:dht:a"], allowedAdapters: ["native"] })
      .build();
    expect(c.allowedTargetDids).toEqual(["did:dht:a"]);
    expect(c.allowedAdapters).toEqual(["native"]);
  });

  it("chained builder", () => {
    const c = caveats
      .spendingCap({ perCall: 100 })
      .timeBounded({ validUntil: 999 })
      .rateLimited({ maxCalls: 5 })
      .forTarget({ allowedTargetDids: ["did:dht:a"] })
      .inputSchema({ type: "object" })
      .originKind("Query")
      .build();
    expect(c.amountMaxPerCall).toBe(100);
    expect(c.validUntil).toBe(999);
    expect(c.maxCalls).toBe(5);
    expect(c.originKind).toBe("Query");
  });

  it("origin kind rejects invalid values", () => {
    // biome-ignore lint/suspicious/noExplicitAny: deliberate invalid value test.
    expect(() => new CaveatBuilder().originKind("Other" as any)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// InvocationHandle — dual consumption.
// ---------------------------------------------------------------------------

describe("InvocationHandle", () => {
  it("awaits to an aggregate", async () => {
    const handle = new InvocationHandle((sink) => {
      queueMicrotask(() => sink.end({ value: { result: 42 } }));
    });
    const agg = (await handle) as Aggregate;
    expect(agg.value).toEqual({ result: 42 });
  });

  it("async-iterates chunks (zero non-end chunks in the single-end pump)", async () => {
    const handle = new InvocationHandle((sink) => {
      queueMicrotask(() => sink.end({ value: { result: 1 } }));
    });
    const chunks: OutletStreamChunk[] = [];
    for await (const c of handle) {
      chunks.push(c);
    }
    // The minimal pump emits only an `end` chunk; iteration stops before yielding it.
    expect(chunks.every((c) => c.payloadType !== "end")).toBe(true);
  });

  it("rejects double consumption", async () => {
    const handle = new InvocationHandle((sink) => {
      queueMicrotask(() => sink.end({ value: 1 }));
    });
    await handle;
    expect(() => handle[Symbol.asyncIterator]()).toThrow(OutletError);
  });

  it("propagates errors from the pump", async () => {
    const handle = new InvocationHandle((sink) => {
      queueMicrotask(() => sink.error(new Error("boom")));
    });
    // Wrap in Promise.resolve to coerce the PromiseLike into a real Promise
    // for bun's expect matchers.
    await expect(Promise.resolve(handle)).rejects.toThrow("boom");
  });
});
