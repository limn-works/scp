/**
 * Contract tests for the §6.2.4 cross-context STREAMING saga SDK wrapper
 * (SCP-OUT-047) — `scp.outletInvokeCrossContextStreamingSaga(...)`, the
 * {@link StreamingSagaHandle} it returns, and
 * `scp.recoverStreamingSagaTruncatedClose(...)`.
 *
 * These exercise the SDK-layer handle contract — lazy open at first pull, the
 * `AsyncIterable<OutletStreamChunk>` + `PromiseLike<Aggregate>` drain, the
 * single-consumer guard, sequence-gap detection (no cross-context cancel plane),
 * open-time saga-terminal translation, and the invoker-gated recover — against a
 * scripted fake `#native` bridge that plays back a JSON chunk sequence in the
 * exact §5.4.5 `OutletStreamChunk` wire shape.
 *
 * Mirrors `bindings/python/tests/test_outlets_streaming_saga.py` and the
 * same-context `outlets-streaming.test.ts`. Runtime-level guarantees
 * (billed-count / execute-exactly-once) are proven Rust-side and are NOT
 * re-asserted at this SDK layer.
 */

import { describe, expect, it } from "bun:test";
import {
  ContextError,
  OutletError,
  ProtocolError,
  SagaAbortedError,
  StreamGap,
  UcanPermissionError,
  ValidationError,
} from "../src/errors";
import {
  type Aggregate,
  OutletStreamChunk,
  StreamingSagaHandle,
  type StreamingSagaNative,
} from "../src/outlets";
import { __constructScpWithNativeForTests } from "../src/scp";

// ---------------------------------------------------------------------------
// Wire-shape chunk builders (match §5.4.5 OutletStreamChunk serialization).
// ---------------------------------------------------------------------------

const REQUEST_ID: readonly number[] = new Array(16).fill(0x01);
const SIG: readonly number[] = new Array(64).fill(0x22);

function chunk(sequence: number, payload: Record<string, unknown>): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({ request_id: REQUEST_ID, sequence, payload, sig: SIG }),
  );
}

function data(sequence: number, value: unknown): Uint8Array {
  return chunk(sequence, { "@type": "data", value });
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
// Scripted fake native bridge — the StreamingSagaNative surface.
// ---------------------------------------------------------------------------

/** Records the positional open args so a handle-swap or reorder is caught. */
type OpenArgs = readonly unknown[];

class FakeSagaNative implements StreamingSagaNative {
  readonly openCalls: OpenArgs[] = [];
  readonly recoverCalls: [string, string][] = [];
  openError: Error | null = null;
  pollError: Error | null = null;
  pollErrorAfter = Number.POSITIVE_INFINITY;
  recoverError: Error | null = null;
  #chunks: Uint8Array[];
  #i = 0;
  #polls = 0;
  #sagaId: string;

  constructor(chunks: Uint8Array[], sagaId = "saga-1") {
    this.#chunks = chunks;
    this.#sagaId = sagaId;
  }

  async outletStreamingSagaOpen(
    sourceHandle: unknown,
    targetHandle: unknown,
    callerDid: string,
    outletRegistrationId: string,
    inputJson: string,
    assertedNonceHex: string,
    timestampMs: bigint,
    chainDepth: number,
    ucanToken: string,
    proofTokens?: readonly string[],
    ucanProofId?: string,
    timeoutMs?: number,
    estimatedChunkCount?: number,
  ): Promise<string> {
    this.openCalls.push([
      sourceHandle,
      targetHandle,
      callerDid,
      outletRegistrationId,
      inputJson,
      assertedNonceHex,
      timestampMs,
      chainDepth,
      ucanToken,
      proofTokens,
      ucanProofId,
      timeoutMs,
      estimatedChunkCount,
    ]);
    if (this.openError !== null) {
      throw this.openError;
    }
    return this.#sagaId;
  }

  async outletStreamingSagaPollNext(_sagaId: string): Promise<Uint8Array | null> {
    this.#polls += 1;
    if (this.pollError !== null && this.#polls > this.pollErrorAfter) {
      throw this.pollError;
    }
    if (this.#i >= this.#chunks.length) {
      return null;
    }
    return this.#chunks[this.#i++] ?? null;
  }

  async outletStreamingSagaRecoverTruncatedClose(sagaId: string, callerDid: string): Promise<void> {
    this.recoverCalls.push([sagaId, callerDid]);
    if (this.recoverError !== null) {
      throw this.recoverError;
    }
  }
}

// ---------------------------------------------------------------------------
// Test fixtures.
// ---------------------------------------------------------------------------

const SOURCE_HANDLE = { __h: "SRC" };
const TARGET_HANDLE = { __h: "TGT" };
const NONCE_HEX = "00".repeat(16);
const TS_MS = 1_700_000_000_000n;

function openSaga(
  fake: FakeSagaNative,
  overrides: Partial<{
    sourceHandle: unknown;
    targetHandle: unknown;
    timestampMs: bigint;
    chainDepth: number;
  }> = {},
): StreamingSagaHandle {
  const scp = __constructScpWithNativeForTests(fake);
  return scp.outletInvokeCrossContextStreamingSaga({
    sourceHandle: overrides.sourceHandle ?? SOURCE_HANDLE,
    targetHandle: overrides.targetHandle ?? TARGET_HANDLE,
    callerDid: "did:dht:caller",
    outletRegistrationId: "outlet-reg-1",
    input: { a: 1 },
    assertedNonceHex: NONCE_HEX,
    timestampMs: overrides.timestampMs ?? TS_MS,
    chainDepth: overrides.chainDepth ?? 0,
    ucanToken: "ucan-abc",
    estimatedChunkCount: 8,
  });
}

// ---------------------------------------------------------------------------
// Lazy open + progressive consumption.
// ---------------------------------------------------------------------------

describe("outletInvokeCrossContextStreamingSaga — lazy open", () => {
  it("returns a handle WITHOUT opening the saga (no I/O, sagaId null)", () => {
    const fake = new FakeSagaNative([data(0, { r: 1 }), end(1, { total: 1 })]);
    const handle = openSaga(fake);
    expect(handle).toBeInstanceOf(StreamingSagaHandle);
    expect(handle.sagaId).toBeNull();
    expect(fake.openCalls).toHaveLength(0);
  });

  it("opens on the FIRST pull and exposes the durable sagaId", async () => {
    const fake = new FakeSagaNative([end(0, { ok: true })], "saga-xyz");
    const handle = openSaga(fake);
    const iterator = handle[Symbol.asyncIterator]();
    const first = await iterator.next();
    expect(fake.openCalls).toHaveLength(1);
    expect(handle.sagaId).toBe("saga-xyz");
    expect(first.done).toBe(false);
  });

  it("progressively drains data chunks then the terminal End via iteration", async () => {
    const fake = new FakeSagaNative([data(0, { r: "a" }), data(1, { r: "b" }), end(2, { n: 2 })]);
    const handle = openSaga(fake);
    const kinds: string[] = [];
    for await (const c of handle) {
      kinds.push(c.kind);
    }
    expect(kinds).toEqual(["data", "data", "end"]);
    // Open happened exactly once for the whole drain.
    expect(fake.openCalls).toHaveLength(1);
  });

  it("await handle drains to the End aggregate", async () => {
    const fake = new FakeSagaNative([data(0, { r: 1 }), end(1, { total: 99 }, 55)]);
    const handle = openSaga(fake);
    const agg: Aggregate = await handle;
    expect(agg.value).toEqual({ total: 99 });
    expect(agg.executionTimeMs).toBe(55);
    expect(agg.provenance).toEqual({ source: "outlet", quality: "verified" });
  });

  it("forwards every open argument in NAPI order (input stringified, ts as bigint)", async () => {
    const fake = new FakeSagaNative([end(0, {})]);
    const scp = __constructScpWithNativeForTests(fake);
    const handle = scp.outletInvokeCrossContextStreamingSaga({
      sourceHandle: SOURCE_HANDLE,
      targetHandle: TARGET_HANDLE,
      callerDid: "caller-DID-aaa",
      outletRegistrationId: "outlet-reg-bbb",
      input: { in: "ccc" },
      assertedNonceHex: "dd".repeat(16),
      timestampMs: TS_MS,
      chainDepth: 7,
      ucanToken: "ucan-eee",
      proofTokens: ["p1", "p2"],
      ucanProofId: "proof-fff",
      timeoutMs: 1234,
      estimatedChunkCount: 16,
    });
    await handle.aggregate();
    expect(fake.openCalls[0]).toEqual([
      SOURCE_HANDLE,
      TARGET_HANDLE,
      "caller-DID-aaa",
      "outlet-reg-bbb",
      '{"in":"ccc"}',
      "dd".repeat(16),
      TS_MS,
      7,
      "ucan-eee",
      ["p1", "p2"],
      "proof-fff",
      1234,
      16,
    ]);
  });
});

// ---------------------------------------------------------------------------
// Open-time rejection translation (caller-principal binding / saga terminals).
// ---------------------------------------------------------------------------

describe("outletInvokeCrossContextStreamingSaga — open rejection", () => {
  it("maps a caller-mismatch SagaAborted (SCP-SAGA-13050) to SagaAbortedError on first pull", async () => {
    const fake = new FakeSagaNative([]);
    fake.openError = new Error(
      "[SCP-SAGA-13050] saga aborted: caller_did is not a member of the source context (retry_after_ms=null)",
    );
    const handle = openSaga(fake);
    const err = await handle.aggregate().catch((e) => e);
    expect(err).toBeInstanceOf(SagaAbortedError);
    expect((err as SagaAbortedError).code).toBe("SCP-SAGA-13050");
    // The receiver is never handed out — sagaId stays null.
    expect(handle.sagaId).toBeNull();
  });

  it("maps a non-saga bridge open rejection through mapBridgeError (UCAN denial)", async () => {
    const fake = new FakeSagaNative([]);
    fake.openError = new Error("[SCP-PERM-3001] permission error: invoker not authorized");
    const handle = openSaga(fake);
    const err = await handle.aggregate().catch((e) => e);
    expect(err).toBeInstanceOf(UcanPermissionError);
    expect((err as UcanPermissionError).code).toBe("SCP-PERM-3001");
  });
});

// ---------------------------------------------------------------------------
// Terminal Error chunk / stream gap / abnormal drop.
// ---------------------------------------------------------------------------

describe("StreamingSagaHandle — terminals", () => {
  it("raises the typed OutletError carried by a terminal Error chunk", async () => {
    const fake = new FakeSagaNative([data(0, {}), errorChunk(1, "SCP-OUTLET-6010", "boom")]);
    const handle = openSaga(fake);
    const err = await handle.aggregate().catch((e) => e);
    expect(err).toBeInstanceOf(OutletError);
    expect((err as OutletError).code).toBe("SCP-OUTLET-6010");
  });

  it("detects a sequence gap and raises StreamGap WITHOUT a cancel plane", async () => {
    // Sequence jumps 0 -> 2 (missing 1). There is no cross-context cancel op on
    // the native surface, so a gap must be a purely local terminal.
    const fake = new FakeSagaNative([data(0, {}), data(2, {})]);
    const handle = openSaga(fake);
    const err = await handle.aggregate().catch((e) => e);
    expect(err).toBeInstanceOf(StreamGap);
  });

  it("treats an abnormal sender drop (poll -> null) as a terminal without End", async () => {
    const fake = new FakeSagaNative([data(0, {})]); // no End, then null
    const handle = openSaga(fake);
    const err = await handle.aggregate().catch((e) => e);
    expect(err).toBeInstanceOf(ProtocolError);
  });
});

// ---------------------------------------------------------------------------
// Single-consumer guard + validation.
// ---------------------------------------------------------------------------

describe("StreamingSagaHandle — single consumer + validation", () => {
  it("rejects a second concurrent drain with ProtocolError", async () => {
    // A poll that never resolves keeps the first drain in-flight so the second
    // observes the #draining guard.
    const fake = new FakeSagaNative([]);
    let release: () => void = () => {};
    const gate = new Promise<void>((r) => {
      release = r;
    });
    fake.outletStreamingSagaPollNext = async () => {
      await gate;
      return null;
    };
    const handle = openSaga(fake);
    const first = handle.next();
    const second = await handle.next().catch((e) => e);
    expect(second).toBeInstanceOf(ProtocolError);
    release();
    await first;
  });

  it("rejects an out-of-range chainDepth synchronously (before returning a handle)", () => {
    const fake = new FakeSagaNative([]);
    expect(() => openSaga(fake, { chainDepth: 256 })).toThrow(ValidationError);
    expect(fake.openCalls).toHaveLength(0);
  });

  it("rejects a negative timestampMs synchronously", () => {
    const fake = new FakeSagaNative([]);
    expect(() => openSaga(fake, { timestampMs: -1n })).toThrow(ValidationError);
  });
});

// ---------------------------------------------------------------------------
// Recover truncated-close — call path + invoker-gate translation.
// ---------------------------------------------------------------------------

describe("recoverStreamingSagaTruncatedClose", () => {
  it("forwards (sagaId, callerDid) to the bridge recover op and resolves void", async () => {
    const fake = new FakeSagaNative([]);
    const scp = __constructScpWithNativeForTests(fake);
    await scp.recoverStreamingSagaTruncatedClose("saga-77", "did:dht:invoker");
    expect(fake.recoverCalls).toEqual([["saga-77", "did:dht:invoker"]]);
  });

  it("translates the SCP-PERM-3001 invoker-gate to UcanPermissionError with .code", async () => {
    const fake = new FakeSagaNative([]);
    fake.recoverError = new Error(
      "[SCP-PERM-3001] permission error: caller is hosted but is not the pinned invoker",
    );
    const scp = __constructScpWithNativeForTests(fake);
    const err = await scp
      .recoverStreamingSagaTruncatedClose("saga-77", "did:dht:stranger")
      .catch((e) => e);
    expect(err).toBeInstanceOf(UcanPermissionError);
    expect((err as UcanPermissionError).code).toBe("SCP-PERM-3001");
  });

  it("translates an unknown-saga rejection to ContextError", async () => {
    const fake = new FakeSagaNative([]);
    fake.recoverError = new Error("[SCP-CTX-2001] context error: unknown saga_id");
    const scp = __constructScpWithNativeForTests(fake);
    const err = await scp
      .recoverStreamingSagaTruncatedClose("nope", "did:dht:invoker")
      .catch((e) => e);
    expect(err).toBeInstanceOf(ContextError);
  });
});

// A minimal sanity check that the exported chunk type is reused, not re-declared.
describe("wire-shape reuse", () => {
  it("parses chunks through the shared OutletStreamChunk decoder", () => {
    const parsed = OutletStreamChunk._fromBridgeBytes(end(0, { x: 1 }));
    expect(parsed.kind).toBe("end");
    expect(parsed.isTerminal).toBe(true);
  });
});
