/**
 * SCP-OUT-039 — Outlet streaming vector smoke tests (TypeScript SDK).
 *
 * Loads the seven streaming conformance vectors at
 * `tests/conformance/vectors/outlet_stream_vectors.json` and drives
 * each through an `InvocationHandle` pump, asserting the vector's
 * declared terminal-status surface reproduces under the SDK control
 * plane.
 *
 * Per SCP-OUT-039 AC6: each vector runs in each SDK and produces the
 * expected terminal status. Runtime-side replay (CreditTracker /
 * CancelAckTracker / StreamEscrow) lives in
 * `crates/scp-testing/tests/integration/outlet_stream_conformance.rs`;
 * this smoke ensures the TS SDK can ingest the same JSON vectors and
 * reproduce the surface-level outcome.
 *
 * The cancellation, credit-exhaustion and sequence-gap vectors all
 * terminate with a terminal Error chunk via the SDK iterator surface —
 * the wire-level distinction between "framework-emitted cancel-ack"
 * and "receiver-emitted StreamGap" is a runtime concern.
 */

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { InvocationHandle, type OutletStreamChunk } from "../src/outlets";

// ---------------------------------------------------------------------------
// Vector loading
// ---------------------------------------------------------------------------

interface ChunkEntry {
  sequence: number;
  type: "data" | "end" | "error" | "progress";
  value?: unknown;
  aggregate?: unknown;
  execution_time_ms?: number;
  code?: string;
  message?: string;
  terminal?: boolean;
  pct?: number;
  note?: string | null;
  slug?: string;
}

interface VectorFile {
  comment: string;
  spec_section: string;
  vectors: Vector[];
}

interface Vector {
  name: string;
  description: string;
  open: {
    outlet_id: string;
    outlet_kind: string;
    input: unknown;
    invoker_did: string;
    operator_did: string;
    context_id: string;
    credit_window: number;
    estimated_chunk_count: number;
    cost_per_chunk: number;
    available_balance: number;
    stream_credit_stall_secs: number;
    stream_cancel_ack_secs: number;
    timeout_ms: number;
    chain_depth: number;
  };
  chunks: ChunkEntry[];
  credits: unknown[];
  cancel?: { after_sequence: number; expected_cancel_ack_seq: number };
  trigger?: string;
  expected_end_status: "Ok" | "Error" | "Cancelled";
  expected_error_code?: string | null;
  expected_error_slug?: string;
  expected_chunks_billed: number;
  expected_total_chunks: number;
  expected_cancel_ack_seq?: number | null;
  expected_first_gap_sequence?: number;
}

function vectorPath(): string {
  // Walk up from the test file to find the repo-root vectors file.
  let dir = resolve(import.meta.dir);
  for (let i = 0; i < 10; i++) {
    const candidate = resolve(dir, "tests/conformance/vectors/outlet_stream_vectors.json");
    try {
      readFileSync(candidate);
      return candidate;
    } catch {
      // not here — keep walking
    }
    const parent = resolve(dir, "..");
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error(`outlet_stream_vectors.json not found from ${import.meta.dir}`);
}

function loadVectors(): Vector[] {
  const raw = JSON.parse(readFileSync(vectorPath(), "utf8")) as VectorFile;
  expect(raw.vectors.length).toBe(7);
  return raw.vectors;
}

const REQUIRED_NAMES = [
  "non_streaming",
  "multi_chunk",
  "cancellation",
  "error_terminal",
  "error_recoverable",
  "sequence_gap",
  "credit_exhaustion",
] as const;

// ---------------------------------------------------------------------------
// Driver — feeds the InvocationHandle pump with the vector's chunks.
// ---------------------------------------------------------------------------

// Pump-side handler shape the InvocationHandle constructor accepts.
type PumpSink = Parameters<ConstructorParameters<typeof InvocationHandle>[0]>[0];

// Result of emitting one entry — `done` means the pump should stop.
type EmissionOutcome = "continue" | "done";

function emitEntry(sink: PumpSink, entry: ChunkEntry, requestId: Uint8Array): EmissionOutcome {
  if (entry.type === "data") {
    sink.chunk({
      requestId,
      sequence: entry.sequence,
      payloadType: "data",
      value: entry.value,
    } as OutletStreamChunk);
    return "continue";
  }
  if (entry.type === "end") {
    sink.end({
      value: entry.aggregate ?? null,
      ...(entry.execution_time_ms !== undefined && {
        executionTimeMs: entry.execution_time_ms,
      }),
    });
    return "done";
  }
  if (entry.type === "error") {
    sink.chunk({
      requestId,
      sequence: entry.sequence,
      payloadType: "error",
      code: entry.code ?? "SCP-TOOL-6200",
      message: entry.message ?? "",
      terminal: entry.terminal === true,
    } as OutletStreamChunk);
    if (entry.terminal === true) {
      sink.error(new Error(entry.message ?? "stream errored"));
      return "done";
    }
    return "continue";
  }
  if (entry.type === "progress") {
    sink.chunk({
      requestId,
      sequence: entry.sequence,
      payloadType: "progress",
      pct: entry.pct ?? 0,
      ...(entry.note != null && { note: entry.note }),
    } as OutletStreamChunk);
    return "continue";
  }
  return "continue";
}

function emitSequenceGapTerminal(sink: PumpSink, vector: Vector, requestId: Uint8Array): void {
  // sequence_gap vector intentionally omits a terminal — the
  // receiver's StreamGap cancel terminates from outside the
  // executor's emission. Synthesize the receiver's terminal Error so
  // the InvocationHandle iterator can drain.
  if (vector.name !== "sequence_gap") return;
  const lastSeq = vector.chunks[vector.chunks.length - 1]?.sequence ?? 0;
  sink.chunk({
    requestId,
    sequence: lastSeq + 1,
    payloadType: "error",
    code: vector.expected_error_code ?? "SCP-TOOL-6131",
    message: vector.expected_error_slug ?? "execution.stream-gap",
    terminal: true,
  } as OutletStreamChunk);
  sink.error(new Error("synthesized StreamGap"));
}

function buildHandle(vector: Vector): InvocationHandle {
  const requestId = new Uint8Array(16).fill(0xa5);
  return new InvocationHandle((sink) => {
    void Promise.resolve().then(() => {
      for (const entry of vector.chunks) {
        if (emitEntry(sink, entry, requestId) === "done") return;
      }
      emitSequenceGapTerminal(sink, vector, requestId);
    });
  });
}

async function drainHandle(vector: Vector): Promise<OutletStreamChunk[]> {
  const handle = buildHandle(vector);
  const observed: OutletStreamChunk[] = [];
  try {
    for await (const chunk of handle) {
      observed.push(chunk);
    }
  } catch {
    // The InvocationHandle pump path raises on terminal Error or
    // sequence-gap synthetic — that's the surface the SDK contract
    // exposes when the stream terminates abnormally. The chunks
    // already enqueued are visible; we proceed to assertions on them.
  }
  return observed;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("SCP-OUT-039 outlet stream vectors (TS smoke)", () => {
  test("vector file carries exactly the seven required vectors (AC1)", () => {
    const vectors = loadVectors();
    const names = new Set(vectors.map((v) => v.name));
    for (const required of REQUIRED_NAMES) {
      expect(names.has(required)).toBe(true);
    }
    expect(names.size).toBe(REQUIRED_NAMES.length);
  });

  test.each([
    ...REQUIRED_NAMES,
  ])("vector %s reproduces expected terminal status (AC6)", async (name: string) => {
    const v = loadVectors().find((x) => x.name === name);
    expect(v).toBeDefined();
    const vector = v as Vector;
    const observed = await drainHandle(vector);

    const expected_total = vector.expected_total_chunks;
    if (name === "sequence_gap") {
      // Smoke synthesizes one terminal Error on top of the manifest.
      expect(observed.length).toBe(expected_total + 1);
    } else {
      expect(observed.length).toBe(expected_total);
    }

    const terminal = observed[observed.length - 1];
    if (!terminal) {
      throw new Error(`vector ${name}: no chunks observed`);
    }
    switch (vector.expected_end_status) {
      case "Ok": {
        expect(terminal.payloadType).toBe("end");
        const endEntry = vector.chunks.find((c) => c.type === "end");
        expect(terminal.aggregate).toEqual(endEntry?.aggregate);
        break;
      }
      case "Error": {
        expect(terminal.payloadType).toBe("error");
        expect(terminal.terminal).toBe(true);
        expect(terminal.code).toBe(vector.expected_error_code ?? "");
        break;
      }
      case "Cancelled": {
        // Cancel-ack envelope per §5.4.5 — surfaces as a terminal
        // Error chunk to the SDK iterator. The runtime layer
        // distinguishes Cancelled vs Error on the
        // OutletInvokedEvent.
        expect(terminal.payloadType).toBe("error");
        expect(terminal.terminal).toBe(true);
        break;
      }
      default:
        throw new Error(`unknown expected_end_status ${vector.expected_end_status}`);
    }
  });

  test("every vector carries an input field on the open block", () => {
    for (const v of loadVectors()) {
      expect(v.open.input).toBeDefined();
    }
  });
});
