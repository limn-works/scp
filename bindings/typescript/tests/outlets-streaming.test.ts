/**
 * Contract tests for the single-verb outlet streaming surface (SCP-OUT-038).
 *
 * These exercise the SDK-layer InvocationHandle contract — the
 * `PromiseLike<Aggregate>` + `AsyncIterable<OutletStreamChunk>` handle, the
 * `Credit` branded newtype, `grantCredit` / `cancel` control-plane methods,
 * and the lifecycle guard — against a scripted fake `#native` bridge that
 * plays back a JSON chunk sequence in the exact §5.4.5 `OutletStreamChunk`
 * wire shape (`serde_bytes` fields as integer arrays).
 *
 * The scripted bridge lets these tests validate ALL of the SDK's iteration /
 * aggregation / control-plane / lifecycle logic without a built NAPI addon —
 * mirroring `bindings/python/tests/test_outlets_streaming.py`. The fake is
 * mounted as the whole SCP `#native` via `__constructScpWithNativeForTests`,
 * so every test drives the REAL `ctx.outlets.invoke(...)` accessor path (not a
 * hand-built Outlets), exactly as an application would.
 */

import { describe, expect, it } from "bun:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { Context } from "../src/context";
import {
  ContextError,
  InvalidGrant,
  OutletError,
  ProtocolError,
  StreamAlreadyClosed,
  StreamGap,
  UcanPermissionError,
  ValidationError,
} from "../src/errors";
import {
  type Aggregate,
  Credit,
  InvocationHandle,
  OutletStreamChunk,
  type OutletStreamNative,
  Outlets,
} from "../src/outlets";
import { __constructScpWithNativeForTests } from "../src/scp";

// ---------------------------------------------------------------------------
// Wire-shape chunk builders (match §5.4.5 OutletStreamChunk serialization).
// ---------------------------------------------------------------------------

const REQUEST_ID: readonly number[] = new Array(16).fill(0x01);
const SIG: readonly number[] = new Array(64).fill(0x22);
const REQUEST_ID_HEX = "01".repeat(16);
const SIG_HEX = "22".repeat(64);

function chunk(sequence: number, payload: Record<string, unknown>): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({ request_id: REQUEST_ID, sequence, payload, sig: SIG }),
  );
}

function data(sequence: number, value: unknown): Uint8Array {
  return chunk(sequence, { "@type": "data", value });
}

function progress(sequence: number, pct: number, note?: string): Uint8Array {
  const payload: Record<string, unknown> = { "@type": "progress", pct };
  if (note !== undefined) {
    payload.note = note;
  }
  return chunk(sequence, payload);
}

function end(sequence: number, aggregate: unknown, executionTimeMs = 42): Uint8Array {
  return chunk(sequence, {
    "@type": "end",
    aggregate,
    provenance: { source: "outlet", quality: "verified" },
    execution_time_ms: executionTimeMs,
  });
}

function errorChunk(sequence: number, code: string, message: string, terminal = true): Uint8Array {
  return chunk(sequence, { "@type": "error", code, message, terminal });
}

// ---------------------------------------------------------------------------
// Scripted fake native bridge.
// ---------------------------------------------------------------------------

/**
 * A scripted stand-in for the NAPI `SCP` addon streaming surface.
 * `outletStreamPollNext` plays back `chunks` in order then returns `null`;
 * open / grant / cancel calls are recorded for assertions. Optional error
 * injection mirrors the Python `_RaisingOpenNative` / `_RaisingPollNative`.
 */
class FakeNative implements OutletStreamNative {
  readonly openCalls: unknown[][] = [];
  readonly grantCalls: [string, string, number][] = [];
  readonly cancelCalls: [string, string][] = [];
  openError: Error | null = null;
  pollError: Error | null = null;
  pollErrorAfter = Number.POSITIVE_INFINITY;
  #chunks: Uint8Array[];
  #i = 0;
  #polls = 0;
  #handleId: string;

  constructor(chunks: Uint8Array[], handleId = "stream-1") {
    this.#chunks = chunks;
    this.#handleId = handleId;
  }

  async outletStreamOpen(
    handle: unknown,
    outletId: string,
    inputJson: string,
    callerDid: string,
    ucanToken: string,
    _proofTokens?: readonly string[],
    _spendingUcan?: string,
    _timeoutMs?: number,
    estimatedChunkCount?: number,
  ): Promise<string> {
    this.openCalls.push([handle, outletId, inputJson, callerDid, ucanToken, estimatedChunkCount]);
    if (this.openError !== null) {
      throw this.openError;
    }
    return this.#handleId;
  }

  async outletStreamPollNext(_handleId: string): Promise<Uint8Array | null> {
    this.#polls += 1;
    if (this.#polls > this.pollErrorAfter && this.pollError !== null) {
      throw this.pollError;
    }
    if (this.#i >= this.#chunks.length) {
      return null;
    }
    const next = this.#chunks[this.#i];
    this.#i += 1;
    return next ?? null;
  }

  async outletStreamGrantCredit(handleId: string, callerDid: string, grant: number): Promise<void> {
    this.grantCalls.push([handleId, callerDid, grant]);
  }

  async outletStreamCancel(handleId: string, callerDid: string): Promise<void> {
    this.cancelCalls.push([handleId, callerDid]);
  }
}

/** A `_scp_core`-style bridge error whose bracketed code drives translation. */
function bridgeError(code: string, message: string): Error {
  return new Error(`[${code}] ${message}`);
}

// ---------------------------------------------------------------------------
// Context / invoke helpers — drive the real `ctx.outlets.invoke` accessor.
// ---------------------------------------------------------------------------

function makeCtx(fake: FakeNative, contextId = "ctx-1", identityDid = "did:dht:caller"): Context {
  const scp = __constructScpWithNativeForTests(fake);
  return Context._fromHandle(scp, { contextId, state: "active" } as never, identityDid);
}

interface InvokeOverrides {
  callerDid?: string;
}

function invoke(fake: FakeNative, overrides: InvokeOverrides = {}): InvocationHandle {
  const ctx = makeCtx(fake);
  return ctx.outlets.invoke("outlet-1", { q: "x" }, { ucanToken: "ucan-abc", ...overrides });
}

async function collect(handle: InvocationHandle): Promise<OutletStreamChunk[]> {
  const out: OutletStreamChunk[] = [];
  for await (const c of handle) {
    out.push(c);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Credit newtype.
// ---------------------------------------------------------------------------

describe("Credit", () => {
  it("accepts a non-zero u32", () => {
    expect(new Credit(1).value).toBe(1);
    expect(new Credit(10).value).toBe(10);
    expect(new Credit(2 ** 32 - 1).value).toBe(2 ** 32 - 1);
  });

  it("rejects zero with InvalidGrant", () => {
    expect(() => new Credit(0)).toThrow(InvalidGrant);
  });

  it("rejects a negative with InvalidGrant (not RangeError)", () => {
    expect(() => new Credit(-1)).toThrow(InvalidGrant);
    try {
      new Credit(-5);
      throw new Error("expected InvalidGrant");
    } catch (e) {
      expect(e).toBeInstanceOf(InvalidGrant);
      expect(e).not.toBeInstanceOf(RangeError);
    }
  });

  it("rejects >= 2**32 with InvalidGrant", () => {
    expect(() => new Credit(2 ** 32)).toThrow(InvalidGrant);
    expect(() => new Credit(2 ** 32 + 100)).toThrow(InvalidGrant);
  });

  it("rejects a non-integer with InvalidGrant", () => {
    expect(() => new Credit(1.5)).toThrow(InvalidGrant);
    // A non-number reaching the constructor via a JS/`any` caller.
    expect(() => new Credit("10" as unknown as number)).toThrow(InvalidGrant);
    expect(() => new Credit(Number.NaN)).toThrow(InvalidGrant);
  });
});

describe("error hierarchy", () => {
  it("InvalidGrant and StreamAlreadyClosed are Protocol-class OutletErrors", () => {
    const g = new InvalidGrant("x");
    const s = new StreamAlreadyClosed("y");
    expect(g).toBeInstanceOf(ProtocolError);
    expect(g).toBeInstanceOf(OutletError);
    expect(s).toBeInstanceOf(ProtocolError);
    expect(s).toBeInstanceOf(OutletError);
    expect(new ProtocolError("z")).toBeInstanceOf(OutletError);
  });
});

// ---------------------------------------------------------------------------
// ctx.outlets accessor + invoke() surface.
// ---------------------------------------------------------------------------

describe("ctx.outlets accessor", () => {
  it("returns an Outlets instance", () => {
    const ctx = makeCtx(new FakeNative([]));
    expect(ctx.outlets).toBeInstanceOf(Outlets);
  });

  it("throws ContextError when the Context has no bound SCP", () => {
    // A bare handle built with a null SCP (unreachable via the public factory,
    // whose `_fromHandle` always binds an SCP — this exercises the guard).
    const Ctor = Context as unknown as new (
      contextId: string,
      rawHandle: unknown,
      identityDid: string,
      scp: null,
    ) => { outlets: unknown };
    const bare = new Ctor("c", { contextId: "c", state: "active" }, "did:dht:x", null);
    expect(() => bare.outlets).toThrow(ContextError);
  });

  it("invoke returns a handle without opening the stream (lazy)", () => {
    const fake = new FakeNative([data(0, { n: 1 }), end(1, { n: 1 })]);
    const handle = invoke(fake);
    expect(handle).toBeInstanceOf(InvocationHandle);
    expect(fake.openCalls).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Iteration + aggregation.
// ---------------------------------------------------------------------------

describe("streaming iteration + aggregation", () => {
  it("async-iterates all chunks including Progress", async () => {
    const fake = new FakeNative([
      data(0, { n: 0 }),
      progress(1, 5000, "halfway"),
      data(2, { n: 1 }),
      end(3, { total: 2 }),
    ]);
    const collected = await collect(invoke(fake));

    expect(collected.map((c) => c.kind)).toEqual(["data", "progress", "data", "end"]);
    const p = collected[1] as OutletStreamChunk;
    expect(p.kind).toBe("progress");
    expect(p.payload.pct).toBe(5000);
    expect(p.payload.note).toBe("halfway");
    const first = collected[0] as OutletStreamChunk;
    expect(first.sequence).toBe(0);
    expect(first.requestId).toBe(REQUEST_ID_HEX);
    expect(first.signature).toBe(SIG_HEX);
    expect((collected[collected.length - 1] as OutletStreamChunk).isTerminal).toBe(true);
  });

  it("await handle resolves the Aggregate (End)", async () => {
    const fake = new FakeNative([data(0, { n: 1 }), end(1, { total: 1 }, 77)]);
    const result: Aggregate = await invoke(fake);
    expect(result.value).toEqual({ total: 1 });
    expect(result.executionTimeMs).toBe(77);
    expect(result.provenance).toEqual({ source: "outlet", quality: "verified" });
  });

  it("aggregate() is the primary drain verb and validates the End", async () => {
    const fake = new FakeNative([data(0, { n: 1 }), end(1, { total: 1 }, 55)]);
    const result = await invoke(fake).aggregate();
    expect(result.value).toEqual({ total: 1 });
    expect(result.executionTimeMs).toBe(55);
  });

  it("await after full iteration returns the cached Aggregate (no re-drain)", async () => {
    const chunks = [...Array(10)].map((_, i) => data(i, { n: i }));
    chunks.push(end(10, { total: 10 }));
    const fake = new FakeNative(chunks);
    const handle = invoke(fake);

    const collected = await collect(handle);
    expect(collected).toHaveLength(11);
    expect(collected.filter((c) => c.kind === "data")).toHaveLength(10);

    const result = await handle.aggregate();
    expect(result.value).toEqual({ total: 10 });
    // Poll count = 11 chunks + 1 terminal-null? No: terminal End closes on the
    // 11th poll, so exactly 11 polls happened and aggregate re-drains nothing.
    expect(fake.openCalls).toHaveLength(1);
  });

  it("aggregate-then-iterate yields nothing (already drained)", async () => {
    const fake = new FakeNative([data(0, { n: 1 }), end(1, { total: 1 })]);
    const handle = invoke(fake);
    await handle.aggregate();
    const after = await collect(handle);
    expect(after).toEqual([]);
  });

  it("partial-iterate then aggregate drains the remainder to End.aggregate", async () => {
    const chunks = [...Array(4)].map((_, i) => data(i, { n: i }));
    chunks.push(end(4, { total: 4 }));
    const fake = new FakeNative(chunks);
    const handle = invoke(fake);

    let seen = 0;
    for await (const _c of handle) {
      seen += 1;
      if (seen === 2) {
        break;
      }
    }
    const result = await handle.aggregate();
    expect(result.value).toEqual({ total: 4 });
  });

  it("opens the stream exactly once and forwards caller identity + ucan", async () => {
    const fake = new FakeNative([data(0, { n: 1 }), end(1, { n: 1 })]);
    await collect(invoke(fake));
    expect(fake.openCalls).toHaveLength(1);
    const [, outletId, inputJson, callerDid, ucanToken] = fake.openCalls[0] as unknown[];
    expect(outletId).toBe("outlet-1");
    expect(inputJson).toBe(JSON.stringify({ q: "x" }));
    expect(callerDid).toBe("did:dht:caller");
    expect(ucanToken).toBe("ucan-abc");
  });

  it("a terminal Error chunk rejects await with a typed OutletError carrying its code", async () => {
    const fake = new FakeNative([
      data(0, { n: 1 }),
      errorChunk(1, "SCP-OUTLET-6130", "handler panic"),
    ]);
    const handle = invoke(fake);
    try {
      await handle;
      throw new Error("expected OutletError");
    } catch (e) {
      expect(e).toBeInstanceOf(OutletError);
      expect((e as OutletError).code).toBe("SCP-OUTLET-6130");
      expect((e as OutletError).message).toContain("handler panic");
    }
  });

  it("a stream that closes without an End rejects with ProtocolError", async () => {
    const fake = new FakeNative([data(0, { n: 1 })]);
    await expect(invoke(fake).aggregate()).rejects.toBeInstanceOf(ProtocolError);
  });

  it("callerDid override is forwarded to open", async () => {
    const fake = new FakeNative([end(0, { ok: true })]);
    await invoke(fake, { callerDid: "did:dht:other" }).aggregate();
    expect((fake.openCalls[0] as unknown[])[3]).toBe("did:dht:other");
  });
});

// ---------------------------------------------------------------------------
// Control plane: grantCredit / cancel.
// ---------------------------------------------------------------------------

describe("control plane", () => {
  it("grantCredit forwards the grant to the bridge", async () => {
    const fake = new FakeNative([data(0, { n: 0 }), data(1, { n: 1 }), end(2, { n: 1 })]);
    const handle = invoke(fake);
    await handle.grantCredit(new Credit(4));
    expect(fake.grantCalls).toEqual([["stream-1", "did:dht:caller", 4]]);
  });

  it("grantCredit mid-stream reaches the bridge and the stream continues", async () => {
    const chunks = [...Array(4)].map((_, i) => data(i, { n: i }));
    chunks.push(end(4, { total: 4 }));
    const fake = new FakeNative(chunks);
    const handle = invoke(fake);

    let seen = 0;
    for await (const _c of handle) {
      seen += 1;
      if (seen === 2) {
        await handle.grantCredit(new Credit(8));
      }
    }
    expect(fake.grantCalls).toEqual([["stream-1", "did:dht:caller", 8]]);
    expect(seen).toBe(5);
  });

  it("grantCredit requires a Credit at runtime and never reaches the bridge for a raw number", async () => {
    const fake = new FakeNative([end(0, { n: 1 })]);
    const handle = invoke(fake);
    // @ts-expect-error - branded Credit: a raw number is not assignable to grantCredit
    await expect(handle.grantCredit(10)).rejects.toBeInstanceOf(InvalidGrant);
    expect(fake.grantCalls).toEqual([]);
  });

  it("cancel forwards to the bridge once the stream is open", async () => {
    const fake = new FakeNative([data(0, { n: 0 }), end(1, { n: 0 })]);
    const handle = invoke(fake);
    // Open the stream first (pull one chunk); cancel then signs at the bridge.
    await handle.next();
    await handle.cancel();
    expect(fake.cancelCalls).toEqual([["stream-1", "did:dht:caller"]]);
  });

  it("cancel mid-stream still lets a terminal chunk arrive and close", async () => {
    const fake = new FakeNative([
      data(0, { n: 0 }),
      data(1, { n: 1 }),
      end(2, { cancelled: true }),
    ]);
    const handle = invoke(fake);
    let seen = 0;
    for await (const _c of handle) {
      seen += 1;
      if (seen === 1) {
        await handle.cancel();
      }
    }
    expect(fake.cancelCalls).toEqual([["stream-1", "did:dht:caller"]]);
    expect(seen).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// Lifecycle guard: control plane after terminal rejects StreamAlreadyClosed.
// ---------------------------------------------------------------------------

describe("lifecycle guard", () => {
  it("grantCredit after End rejects with StreamAlreadyClosed", async () => {
    const fake = new FakeNative([data(0, { n: 1 }), end(1, { n: 1 })]);
    const handle = invoke(fake);
    await handle.aggregate();
    await expect(handle.grantCredit(new Credit(10))).rejects.toBeInstanceOf(StreamAlreadyClosed);
    expect(fake.grantCalls).toEqual([]);
  });

  it("cancel after End rejects with StreamAlreadyClosed", async () => {
    const fake = new FakeNative([end(0, { n: 1 })]);
    const handle = invoke(fake);
    await handle.aggregate();
    await expect(handle.cancel()).rejects.toBeInstanceOf(StreamAlreadyClosed);
    expect(fake.cancelCalls).toEqual([]);
  });

  it("grantCredit after a terminal Error (via iteration) rejects with StreamAlreadyClosed", async () => {
    const fake = new FakeNative([errorChunk(0, "SCP-OUTLET-6130", "boom", true)]);
    const handle = invoke(fake);
    const collected = await collect(handle);
    expect((collected[collected.length - 1] as OutletStreamChunk).kind).toBe("error");
    await expect(handle.grantCredit(new Credit(10))).rejects.toBeInstanceOf(StreamAlreadyClosed);
  });

  it("cancel after End reached via iteration rejects with StreamAlreadyClosed", async () => {
    const fake = new FakeNative([data(0, { n: 0 }), end(1, { n: 0 })]);
    const handle = invoke(fake);
    await collect(handle);
    await expect(handle.cancel()).rejects.toBeInstanceOf(StreamAlreadyClosed);
  });
});

// ---------------------------------------------------------------------------
// Bridge-error translation: data-plane FFI rejections surface as SDK types.
// ---------------------------------------------------------------------------

describe("bridge error translation (data plane)", () => {
  it("open UCAN denial surfaces as UcanPermissionError on first await", async () => {
    const fake = new FakeNative([]);
    fake.openError = bridgeError("SCP-PERM-3001", "authorization denied");
    await expect(invoke(fake).aggregate()).rejects.toBeInstanceOf(UcanPermissionError);
  });

  it("open input-schema violation surfaces as ValidationError on first iteration", async () => {
    const fake = new FakeNative([]);
    fake.openError = bridgeError("SCP-VALID-7050", "input schema");
    await expect(collect(invoke(fake))).rejects.toBeInstanceOf(ValidationError);
  });

  it("a mid-drain poll rejection surfaces as the matching SDK type", async () => {
    const fake = new FakeNative([data(0, { n: 0 })]);
    fake.pollError = bridgeError("SCP-CTX-2000", "no active stream");
    fake.pollErrorAfter = 1;
    await expect(collect(invoke(fake))).rejects.toBeInstanceOf(ContextError);
  });
});

// ---------------------------------------------------------------------------
// Concurrent-consumer guard: a second driver on the shared drain fails loud.
// ---------------------------------------------------------------------------

describe("concurrent-consumer guard", () => {
  it("a second concurrent driver rejects with ProtocolError", async () => {
    const fake = new FakeNative([...Array(5)].map((_, i) => data(i, { n: i })));
    const handle = invoke(fake);
    // Start a first drive; its synchronous prefix sets the drain guard before
    // it suspends at the open await.
    const first = handle.next();
    await expect(handle.next()).rejects.toBeInstanceOf(ProtocolError);
    await first; // let the legitimate first driver finish
  });
});

// ---------------------------------------------------------------------------
// cancel() before first open is a local no-op close (no stream open).
// ---------------------------------------------------------------------------

describe("cancel before open", () => {
  it("cancel before open opens nothing and is a local close", async () => {
    const fake = new FakeNative([data(0, { n: 0 }), end(1, { n: 0 })]);
    const handle = invoke(fake);
    await handle.cancel();
    expect(fake.openCalls).toEqual([]);
    expect(fake.cancelCalls).toEqual([]);
    // The handle is now closed: further control-plane calls are guarded.
    await expect(handle.cancel()).rejects.toBeInstanceOf(StreamAlreadyClosed);
    await expect(handle.grantCredit(new Credit(1))).rejects.toBeInstanceOf(StreamAlreadyClosed);
  });

  it("grantCredit before open DOES open the stream (a grant needs a live stream)", async () => {
    const fake = new FakeNative([end(0, { n: 0 })]);
    const handle = invoke(fake);
    await handle.grantCredit(new Credit(2));
    expect(fake.openCalls).toHaveLength(1);
    expect(fake.grantCalls).toEqual([["stream-1", "did:dht:caller", 2]]);
  });
});

// ---------------------------------------------------------------------------
// Chunk parsing.
// ---------------------------------------------------------------------------

describe("chunk parsing", () => {
  it("malformed bytes raise OutletError", () => {
    expect(() => OutletStreamChunk._fromBridgeBytes(new TextEncoder().encode("not json"))).toThrow(
      OutletError,
    );
  });

  it("accepts a hex-string request_id/sig", () => {
    const raw = new TextEncoder().encode(
      JSON.stringify({
        request_id: "aabb",
        sequence: 0,
        payload: { "@type": "data", value: 1 },
        sig: "ccdd",
      }),
    );
    const c = OutletStreamChunk._fromBridgeBytes(raw);
    expect(c.requestId).toBe("aabb");
    expect(c.signature).toBe("ccdd");
    expect(c.kind).toBe("data");
  });
});

// ---------------------------------------------------------------------------
// AC6 conformance-vector smoke: each of the 7 cross-layer streaming vectors
// (tests/conformance/vectors/outlet_stream_vectors.json) drives the fake and
// asserts the SDK reaches the vector's expected terminal.
// ---------------------------------------------------------------------------

interface VectorChunk {
  readonly sequence: number;
  readonly payload: Record<string, unknown>;
}
interface Vector {
  readonly name: string;
  readonly chunks: readonly VectorChunk[];
  readonly expected_end_status: string;
  readonly expected_error_code: string | null;
}

const VECTORS_PATH = join(
  import.meta.dir,
  "..",
  "..",
  "..",
  "tests",
  "conformance",
  "vectors",
  "outlet_stream_vectors.json",
);

function loadVectors(): Map<string, Vector> {
  const data = JSON.parse(readFileSync(VECTORS_PATH, "utf8")) as { vectors: Vector[] };
  return new Map(data.vectors.map((v) => [v.name, v]));
}

const VECTORS = loadVectors();
const EXPECTED_NAMES = new Set([
  "non_streaming",
  "multi_chunk",
  "cancellation",
  "error_terminal",
  "error_recoverable",
  "sequence_gap",
  "credit_exhaustion",
]);

function vec(name: string): Vector {
  const v = VECTORS.get(name);
  if (v === undefined) {
    throw new Error(`missing vector: ${name}`);
  }
  return v;
}

/** Serialize a vector's chunk list into the fake's wire-byte playback. */
function vectorChunks(v: Vector): Uint8Array[] {
  return v.chunks.map((c) => chunk(c.sequence, c.payload));
}

function endAggregate(v: Vector): unknown {
  return v.chunks.find((c) => c.payload["@type"] === "end")?.payload.aggregate;
}

/**
 * AC6: the 7 cross-layer streaming vectors -> the SDK's expected terminal.
 *
 * IMPORTANT boundary — where the terminal comes from:
 *
 * - `credit_exhaustion` and `cancellation` surface a terminal the BRIDGE
 *   delivers. The fake plays a framework terminal (a `terminal: true` Error for
 *   credit exhaustion; a cancel-ack `End` after the consumer cancels) and the
 *   SDK faithfully surfaces `pollNext`'s terminal — the SDK cannot itself stall
 *   an executor, so it does not synthesize these terminals.
 * - ONLY `sequence_gap` requires ACTIVE SDK-side detection: the drain tracks the
 *   expected sequence, detects the hole ITSELF, signs the cancel through the
 *   bridge, and throws {@link StreamGap}. The fake feeds NO pre-baked cancel-ack
 *   for that vector (that would be test-gaming) — the recorded cancel call
 *   proves the SDK generated it.
 */
describe("AC6 conformance-vector smoke", () => {
  it("covers exactly the seven vector names", () => {
    expect(new Set(VECTORS.keys())).toEqual(EXPECTED_NAMES);
  });

  it("non_streaming -> Ok, aggregate {sum:3}", async () => {
    const v = vec("non_streaming");
    const result = await invoke(new FakeNative(vectorChunks(v)));
    expect(result.value).toEqual({ sum: 3 });
    expect(result.value).toEqual(endAggregate(v));
  });

  it("multi_chunk -> Ok, aggregate {total:10}", async () => {
    const v = vec("multi_chunk");
    const result = await invoke(new FakeNative(vectorChunks(v)));
    expect(result.value).toEqual({ total: 10 });
    expect(result.value).toEqual(endAggregate(v));
  });

  it("error_recoverable -> Ok (non-terminal Error is yielded but does not close)", async () => {
    const v = vec("error_recoverable");
    const handle = invoke(new FakeNative(vectorChunks(v)));
    const collected = await collect(handle);
    expect(collected.map((c) => c.kind)).toEqual(["data", "error", "data", "data", "end"]);
    expect((collected[1] as OutletStreamChunk).payload.terminal).toBe(false);
    const result = await handle.aggregate();
    expect(result.value).toEqual(endAggregate(v));
  });

  it("error_terminal -> raises typed OutletError SCP-OUTLET-6130", async () => {
    const v = vec("error_terminal");
    expect(v.expected_error_code).toBe("SCP-OUTLET-6130");
    try {
      await invoke(new FakeNative(vectorChunks(v))).aggregate();
      throw new Error("expected OutletError");
    } catch (e) {
      expect(e).toBeInstanceOf(OutletError);
      expect((e as OutletError).code).toBe("SCP-OUTLET-6130");
    }
  });

  it("credit_exhaustion -> raises typed OutletError SCP-OUTLET-6133 (bridge terminal)", async () => {
    const v = vec("credit_exhaustion");
    expect(v.expected_error_code).toBe("SCP-OUTLET-6133");
    try {
      await invoke(new FakeNative(vectorChunks(v))).aggregate();
      throw new Error("expected OutletError");
    } catch (e) {
      expect(e).toBeInstanceOf(OutletError);
      expect((e as OutletError).code).toBe("SCP-OUTLET-6133");
    }
  });

  it("cancellation -> Cancelled (consumer cancels; bridge cancel-ack End terminates)", async () => {
    const v = vec("cancellation");
    const fake = new FakeNative(vectorChunks(v));
    const handle = invoke(fake);
    let idx = 0;
    for await (const _c of handle) {
      if (idx === 1) {
        await handle.cancel();
      }
      idx += 1;
    }
    expect(fake.cancelCalls).toEqual([["stream-1", "did:dht:caller"]]);
    expect(idx).toBe(v.chunks.length);
    const result = await handle.aggregate();
    expect(result.value).toEqual({ cancelled: true });
  });

  it("sequence_gap -> ACTIVE SDK detection: signed cancel + StreamGap SCP-OUTLET-6131", async () => {
    const v = vec("sequence_gap");
    expect(v.expected_error_code).toBe("SCP-OUTLET-6131");
    const fake = new FakeNative(vectorChunks(v));
    const handle = invoke(fake);
    try {
      await handle.aggregate();
      throw new Error("expected StreamGap");
    } catch (e) {
      expect(e).toBeInstanceOf(StreamGap);
      expect((e as StreamGap).code).toBe("SCP-OUTLET-6131");
    }
    // The SDK ITSELF signed the receiver cancel (not fed by the fake).
    expect(fake.cancelCalls).toEqual([["stream-1", "did:dht:caller"]]);
    // Terminal cache: the gap is sticky and control-plane is now guarded.
    await expect(handle.aggregate()).rejects.toBeInstanceOf(StreamGap);
    await expect(handle.grantCredit(new Credit(1))).rejects.toBeInstanceOf(StreamAlreadyClosed);
  });
});

// ---------------------------------------------------------------------------
// Public-surface invariant: no public invokeStream (SCP-OUT-006).
// ---------------------------------------------------------------------------

describe("public-surface invariant", () => {
  it("the outlets module exposes no invokeStream / free stream verbs", async () => {
    const mod = (await import("../src/outlets")) as Record<string, unknown>;
    expect(mod.invokeStream).toBeUndefined();
    expect(mod.pollNext).toBeUndefined();
    expect(mod.grantCredit).toBeUndefined();
    expect(
      (InvocationHandle.prototype as unknown as Record<string, unknown>).invokeStream,
    ).toBeUndefined();
  });

  it("no `invokeStream` token appears in the TS SDK source (outside comments)", () => {
    expect(offendingStreamVerbLines(join(import.meta.dir, "..", "src"))).toEqual([]);
  });
});

/** Collect `.ts` files under `dir`, skipping the internal/ bridge wrappers (per the SCP-OUT-006 AC exemption). */
function tsSourceFiles(dir: string): string[] {
  const files: string[] = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {
      if (name !== "internal") {
        files.push(...tsSourceFiles(full));
      }
    } else if (full.endsWith(".ts")) {
      files.push(full);
    }
  }
  return files;
}

/** A non-comment source line references a banned stream verb. */
function isStreamVerbLine(line: string): boolean {
  const trimmed = line.trimStart();
  const isComment = ["//", "*", "/*", '"', "'"].some((c) => trimmed.startsWith(c));
  if (isComment) {
    return false;
  }
  return line.includes("invokeStream") || line.includes("invoke_stream");
}

/** Lines under `srcDir` (outside comments) that name a public stream verb — must be empty. */
function offendingStreamVerbLines(srcDir: string): string[] {
  const offenders: string[] = [];
  for (const file of tsSourceFiles(srcDir)) {
    for (const line of readFileSync(file, "utf8").split("\n")) {
      if (isStreamVerbLine(line)) {
        offenders.push(`${file}: ${line.trim()}`);
      }
    }
  }
  return offenders;
}
