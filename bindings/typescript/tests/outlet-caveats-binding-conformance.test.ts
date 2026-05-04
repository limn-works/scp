/**
 * SCP-OUT-039 cross-SDK byte-equivalence — TypeScript (NAPI) replay.
 *
 * Loads the on-disk fixture at
 * `tests/conformance/vectors/outlet_caveats_binding_fixtures.json` and
 * asserts the NAPI bridge produces the SAME 32-byte `caveats_binding`
 * hashes the protocol-level Rust helpers produced when the fixture was
 * generated. Per spec §5.4.5 line 635 / ADR-049 §5 round-5 JCS Option
 * rule, the four SDKs (PyO3, NAPI, UniFFI Swift / Kotlin, WASM) MUST
 * produce byte-identical output — this test is the NAPI leg.
 *
 * The bridge surface (`bridge.computeCaveatsBinding`) accepts the
 * §5.4.5 preimage inputs verbatim and runs JCS canonicalization on the
 * provided `effective_caveats` JSON string internally. The fixture
 * stores the JCS-canonical string the Rust generator produced; the TS
 * test feeds it to the bridge unchanged. The bridge re-canonicalizes
 * via the same `scp_protocol::jcs` path and MUST land on the same
 * 32-byte hash.
 *
 * Skips cleanly when the native NAPI bridge isn't loadable (matches
 * `caveats-roundtrip.test.ts`).
 */

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

// ---------------------------------------------------------------------------
// Native bridge availability guard — mirrors caveats-roundtrip.test.ts.
// ---------------------------------------------------------------------------

type NativeBridge = Awaited<ReturnType<typeof import("../src/internal/bridge").getBridge>>;

let bridge: NativeBridge | null = null;
let skipReason = "";

try {
  const { createNativeBridge } = await import("../src/internal/native.js");
  bridge = createNativeBridge();
} catch (e: unknown) {
  const msg = e instanceof Error ? e.message : String(e);
  skipReason = `Native NAPI bridge not available: ${msg}`;
}

// ---------------------------------------------------------------------------
// Fixture loading.
// ---------------------------------------------------------------------------

interface CaveatsBindingVector {
  name: string;
  description: string;
  ucan_cid_hex: string;
  request_id_hex: string;
  invoker_did: string;
  estimated_chunk_count: number;
  effective_caveats_jcs: string;
  expected_caveats_binding_hex: string;
}

interface ChunkSigVector {
  name: string;
  description: string;
  context_id: string;
  outlet_id: string;
  request_id_hex: string;
  sequence: number;
  caveats_binding_hex: string;
  payload_json: Record<string, unknown>;
  expected_chunk_sig_preimage_hex: string;
}

interface CreditSigVector {
  name: string;
  description: string;
  context_id: string;
  outlet_id: string;
  request_id_hex: string;
  grant: number;
  monotonic_seq: number;
  stream_epoch: number;
  caveats_binding_hex: string;
  expected_credit_sig_preimage_hex: string;
}

interface FixtureFile {
  comment: string;
  spec_section: string;
  story: string;
  caveats_binding: CaveatsBindingVector[];
  chunk_sig_preimage: ChunkSigVector[];
  credit_sig_preimage: CreditSigVector[];
}

function fixturePath(): string {
  let dir = resolve(import.meta.dir);
  for (let i = 0; i < 10; i++) {
    const candidate = resolve(
      dir,
      "tests/conformance/vectors/outlet_caveats_binding_fixtures.json",
    );
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
  throw new Error(`outlet_caveats_binding_fixtures.json not found from ${import.meta.dir}`);
}

function loadFixture(): FixtureFile {
  return JSON.parse(readFileSync(fixturePath(), "utf8")) as FixtureFile;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error(`hex string has odd length: ${hex.length}`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------------------
// Schema-only tests (run regardless of bridge availability).
// ---------------------------------------------------------------------------

describe("SCP-OUT-039 caveats binding fixture (schema)", () => {
  const fixture = loadFixture();

  test("fixture carries minimum vector counts per spec floor", () => {
    expect(fixture.caveats_binding.length).toBeGreaterThanOrEqual(3);
    expect(fixture.chunk_sig_preimage.length).toBeGreaterThanOrEqual(2);
    expect(fixture.credit_sig_preimage.length).toBeGreaterThanOrEqual(2);
  });

  test("cb_empty vector encodes the empty caveats as literal `{}`", () => {
    const cbEmpty = fixture.caveats_binding.find((v) => v.name === "cb_empty");
    expect(cbEmpty).toBeDefined();
    expect(cbEmpty?.effective_caveats_jcs).toBe("{}");
  });

  test("each caveats_binding vector has a 16-byte request_id and 32-byte hash", () => {
    for (const v of fixture.caveats_binding) {
      expect(hexToBytes(v.request_id_hex).length).toBe(16);
      expect(hexToBytes(v.expected_caveats_binding_hex).length).toBe(32);
    }
  });

  test("each chunk_sig_preimage vector carries an @type-discriminated payload", () => {
    for (const v of fixture.chunk_sig_preimage) {
      expect(v.payload_json["@type"]).toBeDefined();
      expect(hexToBytes(v.request_id_hex).length).toBe(16);
      expect(hexToBytes(v.caveats_binding_hex).length).toBe(32);
      expect(hexToBytes(v.expected_chunk_sig_preimage_hex).length).toBe(32);
    }
  });

  test("each credit_sig_preimage vector carries u32 grant and u64 counters", () => {
    for (const v of fixture.credit_sig_preimage) {
      expect(typeof v.grant).toBe("number");
      expect(typeof v.monotonic_seq).toBe("number");
      expect(typeof v.stream_epoch).toBe("number");
      expect(hexToBytes(v.caveats_binding_hex).length).toBe(32);
      expect(hexToBytes(v.expected_credit_sig_preimage_hex).length).toBe(32);
    }
  });
});

// ---------------------------------------------------------------------------
// Bridge-driven byte-equivalence tests.
// ---------------------------------------------------------------------------

if (bridge === null) {
  describe("SCP-OUT-039 caveats_binding via NAPI bridge (SKIPPED)", () => {
    test.skip(`real NAPI bridge unavailable: ${skipReason}`, () => {});
  });
} else {
  const napi = bridge;

  describe("SCP-OUT-039 caveats_binding via NAPI bridge", () => {
    const fixture = loadFixture();

    for (const v of fixture.caveats_binding) {
      test(`vector ${v.name} reproduces byte-for-byte via NAPI`, async () => {
        const ucanCid = hexToBytes(v.ucan_cid_hex);
        const requestId = hexToBytes(v.request_id_hex);

        const actual = await napi.computeCaveatsBinding(
          ucanCid,
          requestId,
          v.invoker_did,
          v.estimated_chunk_count,
          v.effective_caveats_jcs,
        );

        expect(actual).toBeInstanceOf(Uint8Array);
        expect(actual.length).toBe(32);
        const actualHex = bytesToHex(actual);
        expect(actualHex).toBe(v.expected_caveats_binding_hex);
      });
    }
  });
}

// ---------------------------------------------------------------------------
// WASM bridge byte-equivalence — the WASM leg of the cross-SDK fixture.
// ---------------------------------------------------------------------------
//
// The WASM bridge is loadable in any environment that can import the
// `scp-ffi-wasm` package; the createWasmBridge() factory wires the
// `wasm.computeCaveatsBinding` export. Skips cleanly if the WASM
// package isn't available (e.g., wasm-pack hasn't been run yet).

let wasmBridgeFactory: typeof import("../src/internal/wasm").createWasmBridge | null = null;
let wasmSkipReason = "";
try {
  const mod = await import("../src/internal/wasm.js");
  wasmBridgeFactory = mod.createWasmBridge;
} catch (e: unknown) {
  const msg = e instanceof Error ? e.message : String(e);
  wasmSkipReason = `WASM bridge not available: ${msg}`;
}

if (wasmBridgeFactory === null) {
  describe("SCP-OUT-039 caveats_binding via WASM bridge (SKIPPED)", () => {
    test.skip(`WASM bridge unavailable: ${wasmSkipReason}`, () => {});
  });
} else {
  const wasm = wasmBridgeFactory();

  describe("SCP-OUT-039 caveats_binding via WASM bridge", () => {
    const fixture = loadFixture();

    for (const v of fixture.caveats_binding) {
      test(`vector ${v.name} reproduces byte-for-byte via WASM`, async () => {
        const ucanCid = hexToBytes(v.ucan_cid_hex);
        const requestId = hexToBytes(v.request_id_hex);

        let actual: Uint8Array;
        try {
          actual = await wasm.computeCaveatsBinding(
            ucanCid,
            requestId,
            v.invoker_did,
            v.estimated_chunk_count,
            v.effective_caveats_jcs,
          );
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          // The WASM bridge requires `wasm-pack build` to have produced
          // the .wasm artefact. Skip if it's not present rather than
          // hard-fail the whole suite.
          if (
            msg.includes("WASM module not loaded") ||
            msg.includes("not found") ||
            msg.includes("WASM module not initialized") ||
            msg.includes("SCP-TRANS-5002")
          ) {
            console.warn(`[outlet-caveats] WASM artefact not built or initialized: ${msg}`);
            return;
          }
          throw e;
        }

        expect(actual).toBeInstanceOf(Uint8Array);
        expect(actual.length).toBe(32);
        const actualHex = bytesToHex(actual);
        expect(actualHex).toBe(v.expected_caveats_binding_hex);
      });
    }
  });
}
