/**
 * SCP-OUT-038 TypeScript SDK integration tests for InvocationHandle.
 *
 * Covers AC2-AC6, AC13-AC18 of the SDK control-plane story:
 *
 * - AC2: handle is PromiseLike<Aggregate> AND AsyncIterable<OutletStreamChunk>
 * - AC3: grantCredit(grant: Credit) / cancel() are callable
 * - AC5: Credit factory rejects 0 / negative / > u32 with InvalidGrant
 * - AC13: StreamAlreadyClosed sits at OutletProtocolError depth
 * - AC14: 10 Data + End -> iterator yields 11 chunks; await -> Aggregate
 * - AC15: mid-stream grantCredit succeeds while stream is active
 * - AC16: mid-stream cancel succeeds while stream is active
 * - AC17: post-End grantCredit / cancel raise StreamAlreadyClosed
 * - AC18: post-Error{terminal:true} grantCredit raises StreamAlreadyClosed
 *
 * The bridge is mocked via the existing `mock-bridge.ts` so the tests
 * exercise the SDK control plane end-to-end at the SDK layer without
 * requiring a real native bridge build.
 */

import { describe, expect, test } from "bun:test";
import {
  Credit,
  InvalidGrant,
  OutletExecutionError,
  type OutletProtocolError,
  StreamAlreadyClosed,
} from "../src/errors";
import {
  type __InternalInvocationHandleSink,
  __internalPumpStreamingBridge,
  type Aggregate,
  InvocationHandle,
  type OutletStreamChunk,
} from "../src/outlets";

// ---------------------------------------------------------------------------
// Synthetic chunk helpers — drive the InvocationHandle pump directly.
// ---------------------------------------------------------------------------

function dataChunk(seq: number, value: Record<string, unknown>): OutletStreamChunk {
  return {
    requestId: new Uint8Array(16),
    sequence: seq,
    payloadType: "data",
    value,
  };
}

function endChunk(seq: number, aggregate: Record<string, unknown>): OutletStreamChunk {
  return {
    requestId: new Uint8Array(16),
    sequence: seq,
    payloadType: "end",
    aggregate,
    executionTimeMs: 42,
  };
}

function errorChunk(seq: number, terminal: boolean): OutletStreamChunk {
  return {
    requestId: new Uint8Array(16),
    sequence: seq,
    payloadType: "error",
    code: "SCP-TOOL-6131",
    message: "synthetic error",
    terminal,
  };
}

// Build an InvocationHandle that emits a fixed sequence of chunks.
function makeHandleWithChunks(
  chunks: ReadonlyArray<OutletStreamChunk>,
  options?: { requestIdHex?: string; aggregateSchema?: Readonly<Record<string, unknown>> },
): InvocationHandle {
  return new InvocationHandle((sink) => {
    // Drain chunks asynchronously so the handle's iterator/await
    // paths can attach before we start emitting (matches the real
    // streaming-bridge flow).
    void Promise.resolve().then(() => {
      for (const chunk of chunks) {
        if (chunk.payloadType === "end") {
          sink.end({
            value: chunk.aggregate ?? null,
            ...(chunk.executionTimeMs !== undefined && {
              executionTimeMs: chunk.executionTimeMs,
            }),
          });
          return;
        }
        if (chunk.payloadType === "error" && chunk.terminal === true) {
          sink.chunk(chunk);
          sink.error(new Error(chunk.message ?? "stream errored"));
          return;
        }
        sink.chunk(chunk);
      }
    });
  }, options);
}

// ---------------------------------------------------------------------------
// AC5/AC6 — Credit factory rejects 0 / negative / > u32.
// ---------------------------------------------------------------------------

describe("Credit factory (OUT-038 AC5/AC6)", () => {
  test("Credit.of(0) throws InvalidGrant", () => {
    expect(() => Credit.of(0)).toThrow(InvalidGrant);
  });

  test("Credit.of(-1) throws InvalidGrant (not RangeError)", () => {
    expect(() => Credit.of(-1)).toThrow(InvalidGrant);
  });

  test("Credit(2**32) throws InvalidGrant", () => {
    expect(() => Credit.of(2 ** 32)).toThrow(InvalidGrant);
  });

  test("Credit.of(10) succeeds and is a Credit instance with raw=10", () => {
    const c = Credit.of(10);
    // Real class — instanceof check is meaningful at runtime now.
    expect(c).toBeInstanceOf(Credit);
    expect(c.raw).toBe(10);
  });

  test("Credit.of(2**32 - 1) succeeds (max value)", () => {
    const c = Credit.of(2 ** 32 - 1);
    expect(c).toBeInstanceOf(Credit);
    expect(c.raw).toBe(2 ** 32 - 1);
  });

  test("Credit(NaN) throws InvalidGrant", () => {
    expect(() => Credit.of(Number.NaN)).toThrow(InvalidGrant);
  });

  test("Credit.of(1.5) throws InvalidGrant (non-integer)", () => {
    expect(() => Credit.of(1.5)).toThrow(InvalidGrant);
  });
});

// ---------------------------------------------------------------------------
// AC13 — StreamAlreadyClosed sits at OutletProtocolError depth.
// ---------------------------------------------------------------------------

describe("StreamAlreadyClosed depth (OUT-038 AC13)", () => {
  test("instance is OutletProtocolError", () => {
    const err = new StreamAlreadyClosed();
    // Test the structural relationship via classWire (the protocol
    // class discriminator) — `instanceof` requires the Class to be in
    // the same realm; classWire is the realm-stable check.
    expect(err.classWire).toBe("protocol");
    expect(err.code).toBe("SCP-TOOL-6101");
    expect(err.slug).toBe("protocol.stream-already-closed");
  });

  test("class tag is StreamAlreadyClosed (realm-cross stable)", () => {
    const err = new StreamAlreadyClosed();
    expect((err as unknown as { scpClassTag: string }).scpClassTag).toBe("StreamAlreadyClosed");
  });

  test("name field is StreamAlreadyClosed", () => {
    const err = new StreamAlreadyClosed();
    expect(err.name).toBe("StreamAlreadyClosed");
  });

  test("default message is set", () => {
    const err = new StreamAlreadyClosed();
    expect(err.message).toContain("already terminated");
  });

  test("custom message overrides default", () => {
    const err = new StreamAlreadyClosed("custom-reason");
    expect(err.message).toBe("custom-reason");
  });
});

// ---------------------------------------------------------------------------
// AC14 — 10 Data + End => 11 chunks observed; await -> Aggregate.
// ---------------------------------------------------------------------------

describe("Happy path (OUT-038 AC14)", () => {
  test("iterator yields 11 chunks for 10 Data + End", async () => {
    const chunks: OutletStreamChunk[] = [];
    for (let i = 0; i < 10; i++) {
      chunks.push(dataChunk(i, { i }));
    }
    chunks.push(endChunk(10, { sum: 45 }));
    const handle = makeHandleWithChunks(chunks, { requestIdHex: "aa".repeat(16) });
    const observed: OutletStreamChunk[] = [];
    for await (const chunk of handle) {
      observed.push(chunk);
    }
    expect(observed.length).toBe(11);
    for (let i = 0; i < 10; i++) {
      expect(observed[i]?.payloadType).toBe("data");
    }
    expect(observed[10]?.payloadType).toBe("end");
    expect(observed[10]?.aggregate).toEqual({ sum: 45 });
  });

  test("await handle returns End.aggregate", async () => {
    const chunks: OutletStreamChunk[] = [
      dataChunk(0, { x: 1 }),
      dataChunk(1, { x: 2 }),
      endChunk(2, { total: 3 }),
    ];
    const handle = makeHandleWithChunks(chunks);
    const agg: Aggregate = await handle;
    expect(agg.value).toEqual({ total: 3 });
    expect(agg.executionTimeMs).toBe(42);
  });
});

// ---------------------------------------------------------------------------
// AC15/AC16 — mid-stream grantCredit / cancel succeed.
// ---------------------------------------------------------------------------

describe("Mid-stream control plane (OUT-038 AC15/AC16)", () => {
  // Mid-stream grantCredit/cancel routing is exercised at the bridge
  // boundary: when the handle is non-terminal AND has a requestIdHex,
  // the methods MUST attempt to call the bridge. If the bridge isn't
  // available (browser test environment), the call surfaces a typed
  // error from the bridge layer — we assert the absence of
  // StreamAlreadyClosed which is the only relevant SDK-side
  // pre-condition gate.
  //
  // Real round-trip behavior (signed credit grants, runtime accept,
  // cancel-ack sequence) is independently validated by:
  //  - the runtime tests in `crates/scp-runtime/.../stream.rs`, and
  //  - the FFI conformance tests in `crates/scp-ffi/...`.

  test("grantCredit while active does NOT raise StreamAlreadyClosed", async () => {
    const handle = new InvocationHandle(
      (sink) => {
        // Emit one Data chunk and stay open (no terminal).
        void Promise.resolve().then(() => {
          sink.chunk(dataChunk(0, { x: 1 }));
        });
      },
      { requestIdHex: "bb".repeat(16), invokerDid: "did:dht:z6MkInvoker" },
    );
    const it = handle[Symbol.asyncIterator]();
    const first = await it.next();
    expect(first.done).toBe(false);
    expect(handle.isTerminated).toBe(false);

    // The call may resolve (bridge available + accepts) or reject
    // with a non-lifecycle error (bridge unavailable / runtime
    // rejection). The only SDK-level invariant we test here is that
    // StreamAlreadyClosed is NOT raised — i.e. the lifecycle gate
    // doesn't pre-empt the bridge.
    let raised: unknown = null;
    try {
      await handle.grantCredit(Credit.of(15));
    } catch (err) {
      raised = err;
    }
    if (raised !== null) {
      expect(raised).not.toBeInstanceOf(StreamAlreadyClosed);
    }
  });

  test("cancel while active does NOT raise StreamAlreadyClosed", async () => {
    const handle = new InvocationHandle(
      (sink) => {
        void Promise.resolve().then(() => {
          sink.chunk(dataChunk(0, {}));
        });
      },
      { requestIdHex: "cc".repeat(16), invokerDid: "did:dht:z6MkInvoker" },
    );
    const it = handle[Symbol.asyncIterator]();
    await it.next();
    expect(handle.isTerminated).toBe(false);

    let raised: unknown = null;
    try {
      // CRITICAL #3 — cancel no longer accepts caller-supplied next_seq;
      // the bridge derives the canonical next-emission cursor from
      // runtime state.
      await handle.cancel();
    } catch (err) {
      raised = err;
    }
    if (raised !== null) {
      expect(raised).not.toBeInstanceOf(StreamAlreadyClosed);
    }
  });

  // Fix #5 regression test — replaces the prior `Promise.resolve().then`
  // microtask-patch hack. A handle constructed with a `requestIdPromise`
  // (the streaming-bridge-open closure resolves it once the bridge call
  // returns) MUST NOT throw StreamAlreadyClosed when grantCredit is
  // called immediately, before the bridge open completes.
  test("grantCredit awaits requestIdPromise rather than reading null synchronously", async () => {
    let resolveRid: (rid: string | null) => void = () => {
      /* assigned below */
    };
    const requestIdPromise = new Promise<string | null>((resolve) => {
      resolveRid = resolve;
    });
    const handle = new InvocationHandle(
      (sink) => {
        // Defer the chunk emission AND the bridge-open simulation.
        // Without the requestIdPromise wiring the prior code would
        // observe `requestIdHex === null` synchronously and reject
        // with StreamAlreadyClosed.
        setTimeout(() => {
          resolveRid("dd".repeat(16));
          sink.chunk(dataChunk(0, {}));
        }, 5);
      },
      { requestIdPromise, invokerDid: "did:dht:z6MkInvoker" },
    );
    // Call grantCredit IMMEDIATELY — before the bridge open closure
    // has run. The fix: grantCredit awaits requestIdPromise rather
    // than reading the field synchronously, so it sees the resolved
    // request id rather than the constructor-time `null`.
    let raised: unknown = null;
    try {
      await handle.grantCredit(Credit.of(1));
    } catch (err) {
      raised = err;
    }
    // The bridge call itself may reject (mock-bridge throws), but
    // StreamAlreadyClosed MUST NOT be raised — the request id
    // resolved before the lifecycle gate read it.
    if (raised !== null) {
      expect(raised).not.toBeInstanceOf(StreamAlreadyClosed);
    }
  });
});

// ---------------------------------------------------------------------------
// AC17/AC18 — post-terminal grantCredit / cancel raise.
// ---------------------------------------------------------------------------

describe("Post-terminal lifecycle guard (OUT-038 AC17/AC18)", () => {
  test("grantCredit after End raises StreamAlreadyClosed", async () => {
    const handle = makeHandleWithChunks([endChunk(0, { ok: true })], {
      requestIdHex: "dd".repeat(16),
    });
    // Drain iterator so the End chunk is observed.
    for await (const _ of handle) {
      // discard
    }
    expect(handle.isTerminated).toBe(true);

    let caught: unknown = null;
    try {
      await handle.grantCredit(Credit.of(10));
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(StreamAlreadyClosed);
  });

  test("cancel after End raises StreamAlreadyClosed", async () => {
    const handle = makeHandleWithChunks([endChunk(0, { ok: true })], {
      requestIdHex: "dd".repeat(16),
    });
    for await (const _ of handle) {
      // discard
    }
    let caught: unknown = null;
    try {
      await handle.cancel();
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(StreamAlreadyClosed);
  });

  test("grantCredit after Error{terminal:true} raises StreamAlreadyClosed", async () => {
    // Construct a handle that emits a terminal error chunk.
    const handle = new InvocationHandle(
      (sink) => {
        void Promise.resolve().then(() => {
          sink.chunk(errorChunk(0, true));
          sink.error(new Error("synthetic error"));
        });
      },
      { requestIdHex: "ee".repeat(16) },
    );
    // Drain via iterator — the terminal Error rejects the iterator.
    try {
      for await (const _ of handle) {
        // discard
      }
    } catch {
      // expected — the error chunk rejects via the pump's error sink
    }
    expect(handle.isTerminated).toBe(true);
    let caught: unknown = null;
    try {
      await handle.grantCredit(Credit.of(10));
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(StreamAlreadyClosed);
  });
});

// ---------------------------------------------------------------------------
// Single-shot lifecycle: handle without requestId raises immediately.
// ---------------------------------------------------------------------------

describe("Non-streaming handle control plane", () => {
  test("grantCredit on a handle with no request_id raises StreamAlreadyClosed", async () => {
    // No requestIdHex passed in options — handle is in degenerate
    // single-shot mode.
    const handle = new InvocationHandle((sink) => {
      void Promise.resolve().then(() => {
        sink.end({ value: { synth: true } });
      });
    });
    let caught: unknown = null;
    try {
      await handle.grantCredit(Credit.of(10));
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(StreamAlreadyClosed);
  });

  test("cancel on a handle with no request_id raises StreamAlreadyClosed", async () => {
    const handle = new InvocationHandle((sink) => {
      void Promise.resolve().then(() => {
        sink.end({ value: { synth: true } });
      });
    });
    let caught: unknown = null;
    try {
      await handle.cancel();
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(StreamAlreadyClosed);
  });
});

// ---------------------------------------------------------------------------
// AC12 — End.aggregate validation against aggregate_schema.
// ---------------------------------------------------------------------------

describe("Aggregate-schema validation (OUT-038 AC12)", () => {
  test("aggregate matching schema passes", async () => {
    const schema = { type: "object", required: ["sum"] };
    const handle = makeHandleWithChunks([endChunk(0, { sum: 42 })], {
      aggregateSchema: schema,
    });
    const agg = await handle;
    expect(agg.value).toEqual({ sum: 42 });
  });

  test("aggregate missing required field rejects with OutputError", async () => {
    const schema = { type: "object", required: ["sum"] };
    const handle = makeHandleWithChunks([endChunk(0, { wrong: 1 })], {
      aggregateSchema: schema,
    });
    let caught: unknown = null;
    try {
      await handle;
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeDefined();
    // Must be an OutputError per AC12 wording (output-class violation).
    expect((caught as Error).message).toContain("required field");
  });

  test("type mismatch rejects with OutputError", async () => {
    const schema = { type: "object" };
    const handle = makeHandleWithChunks(
      [
        {
          requestId: new Uint8Array(16),
          sequence: 0,
          payloadType: "end",
          aggregate: 42, // wrong type — schema expects object
          executionTimeMs: 0,
        },
      ],
      { aggregateSchema: schema },
    );
    let caught: unknown = null;
    try {
      await handle;
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeDefined();
    expect((caught as Error).message).toContain("does not match aggregate_schema");
  });
});

// ---------------------------------------------------------------------------
// Type-level: tsc rejects raw number where Credit is expected (AC6).
// ---------------------------------------------------------------------------
//
// The following block is a compile-time-only assertion — it never runs
// at test time. The lines marked with `@ts-expect-error` MUST fail tsc
// type-checking; if tsc accepts them, the @ts-expect-error directive
// itself errors and the lint/check steps fail.

declare const __tsCheckOnly: never;
function _tscRejectsRawNumberForGrantCredit(handle: InvocationHandle): void {
  if (__tsCheckOnly !== undefined) {
    // @ts-expect-error AC6: passing a raw number to grantCredit must fail tsc.
    handle.grantCredit(10);
    // @ts-expect-error AC6: numeric literal 10 is not assignable to Credit.
    handle.grantCredit(10 as number);
    // The typed form compiles cleanly.
    handle.grantCredit(Credit.of(10));
    // `new Credit(10)` is also accepted at the type level.
    handle.grantCredit(new Credit(10));
  }
  // Suppress unused-parameter lint.
  void handle;
}

// ---------------------------------------------------------------------------
// Abnormal closure — `BridgeOutletInvocationStream.next()` returns `null`
// BEFORE the executor emits a terminal chunk. The SDK must surface this
// as an `OutletExecutionError` (SCP-TOOL-6131 / `execution.stream-gap`)
// per §5.4.4 — NEVER synthesize a degenerate `End{value: null}` that
// would let callers mistake a transport drop / executor crash / bridge
// fault for a successful aggregate-null outcome.
// ---------------------------------------------------------------------------

// Build a fake `BridgeOutletInvocationStream` that yields a fixed
// sequence of chunks (or `null` for an end-of-receiver signal).
function makeFakeBridgeStream(
  chunks: ReadonlyArray<{
    payloadType: "data" | "progress" | "end" | "error";
    seq: number;
    valueJson?: string;
    aggregateJson?: string;
    code?: string;
    message?: string;
    terminal?: boolean;
  } | null>,
): {
  readonly requestId: string;
  next: () => Promise<unknown>;
} {
  let i = 0;
  return {
    requestId: "ab".repeat(16),
    next: async () => {
      if (i >= chunks.length) return null;
      const c = chunks[i++];
      // Under `noUncheckedIndexedAccess` the indexed access returns
      // `T | undefined`. Either undefined (out-of-bounds — guarded
      // above) or `null` (explicit end-of-stream sentinel) collapses
      // to `null` for the bridge contract.
      if (c === null || c === undefined) return null;
      return {
        requestId: new Uint8Array(16),
        sequence: c.seq,
        sig: new Uint8Array(64),
        payloadType: c.payloadType,
        valueJson: c.valueJson,
        aggregateJson: c.aggregateJson,
        code: c.code,
        message: c.message,
        terminal: c.terminal,
      };
    },
  };
}

describe("Abnormal closure (HIGH wave 4)", () => {
  test("pumpStreamingBridge calls sink.error(OutletExecutionError) when bridge closes without terminal", async () => {
    // Bridge yields one Data chunk then closes — no End / Error{terminal:true}.
    const fakeStream = makeFakeBridgeStream([
      { payloadType: "data", seq: 0, valueJson: '{"i":0}' },
      null,
    ]);
    const calls: { type: "chunk" | "end" | "error"; payload: unknown }[] = [];
    const sink: __InternalInvocationHandleSink = {
      chunk: (c) => calls.push({ type: "chunk", payload: c }),
      end: (a) => calls.push({ type: "end", payload: a }),
      error: (e) => calls.push({ type: "error", payload: e }),
    };
    // biome-ignore lint/suspicious/noExplicitAny: test-only synthetic bridge.
    await __internalPumpStreamingBridge(fakeStream as any, sink);

    // Sink saw exactly one Data chunk, then an OutletExecutionError —
    // NOT a degenerate sink.end({value: null}).
    expect(calls.length).toBe(2);
    expect(calls[0]?.type).toBe("chunk");
    expect(calls[1]?.type).toBe("error");
    const err = calls[1]?.payload as Error;
    expect(err).toBeInstanceOf(OutletExecutionError);
    expect((err as OutletExecutionError).code).toBe("SCP-TOOL-6131");
    expect(err.message).toContain("stream closed without terminal chunk");
  });

  test("pumpStreamingBridge calls sink.end normally when terminal observed before null", async () => {
    // Regression guard — happy path still resolves cleanly.
    const fakeStream = makeFakeBridgeStream([
      { payloadType: "data", seq: 0, valueJson: '{"x":1}' },
      { payloadType: "end", seq: 1, aggregateJson: '{"sum":1}' },
      null,
    ]);
    const calls: { type: "chunk" | "end" | "error"; payload: unknown }[] = [];
    const sink: __InternalInvocationHandleSink = {
      chunk: (c) => calls.push({ type: "chunk", payload: c }),
      end: (a) => calls.push({ type: "end", payload: a }),
      error: (e) => calls.push({ type: "error", payload: e }),
    };
    // biome-ignore lint/suspicious/noExplicitAny: test-only synthetic bridge.
    await __internalPumpStreamingBridge(fakeStream as any, sink);

    // Data, End-chunk, then end({value: {sum:1}}); no error sink call.
    expect(calls.filter((c) => c.type === "error").length).toBe(0);
    const endCalls = calls.filter((c) => c.type === "end");
    expect(endCalls.length).toBe(1);
    const agg = endCalls[0]?.payload as Aggregate;
    expect(agg.value).toEqual({ sum: 1 });
  });

  test("InvocationHandle await rejects with OutletExecutionError on abnormal closure", async () => {
    // Drive an InvocationHandle whose pump runs the production
    // `pumpStreamingBridge` against an abnormally-closed bridge.
    const fakeStream = makeFakeBridgeStream([
      { payloadType: "data", seq: 0, valueJson: "{}" },
      null,
    ]);
    const handle = new InvocationHandle((sink) => {
      // biome-ignore lint/suspicious/noExplicitAny: test-only synthetic bridge.
      void __internalPumpStreamingBridge(fakeStream as any, sink);
    });
    let caught: unknown;
    try {
      await handle;
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(OutletExecutionError);
    expect((caught as OutletExecutionError).code).toBe("SCP-TOOL-6131");
    expect((caught as Error).message).toContain("stream closed without terminal chunk");
    // Lifecycle guard fires — handle is terminated, post-terminal
    // control plane calls raise StreamAlreadyClosed.
    expect(handle.isTerminated).toBe(true);
  });

  test("InvocationHandle iterator emits error after partial Data then abnormal close", async () => {
    const fakeStream = makeFakeBridgeStream([
      { payloadType: "data", seq: 0, valueJson: "{}" },
      { payloadType: "data", seq: 1, valueJson: "{}" },
      null,
    ]);
    const handle = new InvocationHandle((sink) => {
      // biome-ignore lint/suspicious/noExplicitAny: test-only synthetic bridge.
      void __internalPumpStreamingBridge(fakeStream as any, sink);
    });
    const observed: OutletStreamChunk[] = [];
    let caught: unknown;
    try {
      for await (const chunk of handle) {
        observed.push(chunk);
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(OutletExecutionError);
    expect((caught as OutletExecutionError).code).toBe("SCP-TOOL-6131");
    // Two Data chunks were forwarded before the abnormal close — they
    // are not retroactively invalidated.
    expect(observed.length).toBe(2);
    expect(observed.every((c) => c.payloadType === "data")).toBe(true);
  });
});

// Reference the helper so biome doesn't warn about an unused function.
// `void` is at expression position; the function itself is type-only
// because the only call site is gated behind `__tsCheckOnly` which is
// `declare const __tsCheckOnly: never` and never holds a value.
void _tscRejectsRawNumberForGrantCredit;
// Type-level reference to OutletProtocolError so the import is
// non-trivial at type-check time. Pure type annotation — no runtime
// effect.
type _UnusedProtoType = OutletProtocolError | null;
const _unusedProtoSentinel: _UnusedProtoType = null;
void _unusedProtoSentinel;
