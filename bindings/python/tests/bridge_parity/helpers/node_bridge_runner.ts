#!/usr/bin/env bun
/**
 * Long-lived Bun JSON-RPC server for cross-bridge parity testing.
 *
 * Reads length-prefixed JSON requests on stdin, dispatches to either the
 * NAPI bridge or the WASM bridge based on the `bridge_mode` field, and
 * writes length-prefixed JSON responses on stdout.
 *
 * Wire format (HTTP-style):
 *
 *     Content-Length: N\r\n
 *     \r\n
 *     <N bytes of JSON>
 *
 * Request: `{id, op, args, bridge_mode}` where bridge_mode is "napi" or "wasm".
 * Response: either `{id, ok: true, result: {...}}` on success
 *           or `{id, ok: false, error: {type, code, message}}` on bridge error.
 *
 * Bridge selection is explicit — NO auto-fallback. If the requested bridge
 * cannot be loaded, the response is an error. The harness surfaces this
 * as a test failure, not a skip.
 *
 * Note: the field is named `bridge_mode` rather than `mode` to avoid a
 * name collision with the DOM `RequestMode` type (DOM types are pulled
 * in by the TypeScript default `lib`). TypeScript merges same-named
 * properties across declarations, and `Request` / `mode` are DOM globals.
 *
 * See ADR-046 and `../runner_client.py`.
 */

// ---------------------------------------------------------------------------
// Frame I/O
// ---------------------------------------------------------------------------

const decoder = new TextDecoder();
const encoder = new TextEncoder();

// Persistent reader and buffer. `Bun.stdin.stream()` must be called once
// for the lifetime of the process — calling it repeatedly loses bytes
// because each call returns a fresh ReadableStream that does not share
// position state with prior readers.
const stdinReader = Bun.stdin.stream().getReader();
let inputBuffer = new Uint8Array(0);

function appendToBuffer(chunk: Uint8Array): void {
  const out = new Uint8Array(inputBuffer.length + chunk.length);
  out.set(inputBuffer, 0);
  out.set(chunk, inputBuffer.length);
  inputBuffer = out;
}

function findSubsequence(haystack: Uint8Array, needle: Uint8Array): number {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

const HEADER_TERMINATOR = new Uint8Array([13, 10, 13, 10]);

/** Reads one length-prefixed frame from stdin. Returns null on EOF. */
async function readFrame(): Promise<unknown | null> {
  // Wait for header terminator.
  while (findSubsequence(inputBuffer, HEADER_TERMINATOR) < 0) {
    const { done, value } = await stdinReader.read();
    if (done) {
      if (inputBuffer.length === 0) return null;
      throw new Error(
        `EOF while reading header (buffer size=${inputBuffer.length})`,
      );
    }
    if (value) appendToBuffer(value);
  }

  const headerEnd = findSubsequence(inputBuffer, HEADER_TERMINATOR);
  const headerText = decoder.decode(inputBuffer.subarray(0, headerEnd));
  const match = headerText.match(/Content-Length:\s*(\d+)/i);
  if (!match) {
    throw new Error(`missing Content-Length header, got: ${headerText}`);
  }
  const lengthStr = match[1] ?? "";
  const contentLength = Number.parseInt(lengthStr, 10);

  const bodyStart = headerEnd + HEADER_TERMINATOR.length;

  // Wait until the body is fully in the buffer.
  while (inputBuffer.length - bodyStart < contentLength) {
    const { done, value } = await stdinReader.read();
    if (done) {
      throw new Error(
        `EOF while reading body (got ${inputBuffer.length - bodyStart}/${contentLength} bytes)`,
      );
    }
    if (value) appendToBuffer(value);
  }

  const body = inputBuffer.subarray(bodyStart, bodyStart + contentLength);
  const text = decoder.decode(body);

  // Advance the buffer past the consumed frame.
  inputBuffer = inputBuffer.slice(bodyStart + contentLength);

  return JSON.parse(text);
}

async function writeFrame(payload: unknown): Promise<void> {
  const body = JSON.stringify(payload);
  const bodyBytes = encoder.encode(body);
  const header = `Content-Length: ${bodyBytes.length}\r\n\r\n`;
  const headerBytes = encoder.encode(header);
  const out = new Uint8Array(headerBytes.length + bodyBytes.length);
  out.set(headerBytes, 0);
  out.set(bodyBytes, headerBytes.length);
  // Await the write so each frame is fully flushed before the next.
  await Bun.write(Bun.stdout, out);
}

// ---------------------------------------------------------------------------
// Bridge loading — explicit, no auto-fallback
// ---------------------------------------------------------------------------

// biome-ignore lint/suspicious/noExplicitAny: bridge interfaces are complex
type AnyBridge = any;

let napiBridge: AnyBridge | null = null;
let wasmBridge: AnyBridge | null = null;
let wasmModule: AnyBridge | null = null;

const NAPI_MODULE_PATH =
  "../../../../../bindings/typescript/src/internal/native";
const WASM_MODULE_PATH =
  "../../../../../bindings/typescript/src/internal/wasm";
const WASM_RAW_PATH =
  "../../../../../bindings/typescript/node_modules/@limn-works/scp-ts-wasm/scp_ffi_wasm.js";

async function loadNapi(): Promise<AnyBridge> {
  if (napiBridge !== null) return napiBridge;
  const { createNativeBridge } = await import(NAPI_MODULE_PATH);
  napiBridge = createNativeBridge();
  return napiBridge;
}

async function loadWasm(): Promise<{
  bridge: AnyBridge;
  raw: AnyBridge;
}> {
  if (wasmBridge !== null && wasmModule !== null) {
    return { bridge: wasmBridge, raw: wasmModule };
  }
  const wasmInternal = await import(WASM_MODULE_PATH);
  await wasmInternal.initWasm();
  wasmBridge = wasmInternal.createWasmBridge();
  // Bun resolves imports relative to the .ts file, not cwd. Use a
  // relative path so the @limn-works/scp-ts-wasm package is found via
  // bindings/typescript/node_modules (the only place we wire it).
  wasmModule = await import(WASM_RAW_PATH);
  return { bridge: wasmBridge, raw: wasmModule };
}

function resetBridgeCaches(): void {
  // Drop references so the next `load*()` call re-imports and re-
  // initializes. Bun's module cache still holds the underlying ESM, so
  // we are only resetting the SCP-side wrapper state (ContextManager,
  // identity registries, etc. that the bridges create at init time).
  napiBridge = null;
  wasmBridge = null;
  wasmModule = null;
}

/**
 * Emit a one-shot startup diagnostic so operators can see which bridge
 * modules resolved and where. This is the exact failure mode the harness
 * was built to catch: if a path typo or symlink causes WASM to be loaded
 * where NAPI was expected, this line makes it obvious.
 *
 * Paths are emitted as repo-root-relative so public CI logs do not leak
 * developer/runner filesystem layout (absolute home paths, hostnames,
 * runner IDs embedded in paths, etc.). We compute the repo root from
 * this file's location rather than trusting an env var, which keeps the
 * diagnostic correct regardless of caller cwd.
 */
async function emitStartupDiagnostic(): Promise<void> {
  const path = await import("node:path");
  // This file is bindings/python/tests/bridge_parity/helpers/
  // node_bridge_runner.ts, so the repo root is 5 levels up.
  const repoRoot = path.resolve(import.meta.dir, "../../../../..");
  const rel = (p: string): string => {
    const r = path.relative(repoRoot, p);
    // If the resolved path escapes the repo (shouldn't happen for the
    // in-tree bridges, but could for a symlinked node_modules), fall
    // back to a fingerprint rather than leaking the absolute path.
    if (r.startsWith("..") || path.isAbsolute(r)) {
      const hasher = new Bun.CryptoHasher("sha256");
      hasher.update(p);
      return `sha256:${hasher.digest("hex").slice(0, 16)}`;
    }
    return r;
  };
  // Each resolver is wrapped in its own try/catch so one failure does
  // not mask the other: if napi resolution throws, we still attempt
  // wasm resolution, and vice versa. The collision check below relies
  // on both variables being independently populated (or null on
  // individual failure), NOT on the whole block having succeeded.
  let napiResolved: string | null = null;
  let wasmResolved: string | null = null;
  let wasmRawResolved: string | null = null;
  const resolveErrors: Record<string, string> = {};
  try {
    napiResolved = Bun.resolveSync(NAPI_MODULE_PATH, import.meta.dir);
  } catch (err) {
    resolveErrors.napi = String(err);
  }
  try {
    wasmResolved = Bun.resolveSync(WASM_MODULE_PATH, import.meta.dir);
  } catch (err) {
    resolveErrors.wasm = String(err);
  }
  try {
    wasmRawResolved = Bun.resolveSync(WASM_RAW_PATH, import.meta.dir);
  } catch (err) {
    resolveErrors.wasm_raw = String(err);
  }
  if (Object.keys(resolveErrors).length > 0) {
    process.stderr.write(
      `${JSON.stringify({
        event: "bridge_parity_runner_resolve_error",
        errors: resolveErrors,
      })}\n`,
    );
  }
  process.stderr.write(
    `${JSON.stringify({
      event: "bridge_parity_runner_loaded",
      napi: napiResolved === null ? null : rel(napiResolved),
      wasm: wasmResolved === null ? null : rel(wasmResolved),
      wasm_raw: wasmRawResolved === null ? null : rel(wasmRawResolved),
    })}\n`,
  );
  // Defense-in-depth against the exact failure mode this diagnostic
  // exists to surface: if a symlink, typo, or misconfigured
  // node_modules layout causes NAPI and WASM to point at the same
  // byte-for-byte module, the harness can no longer tell the two
  // bridges apart — every "cross-bridge" test would silently be
  // same-bridge. Refuse to start in that case. This runs OUTSIDE the
  // resolve try/catch so a genuine collision fails hard even when
  // individual resolve paths happened to succeed.
  if (
    napiResolved !== null &&
    wasmResolved !== null &&
    napiResolved === wasmResolved
  ) {
    throw new Error(
      "bridge resolution collision: napi and wasm resolved to the same path — runner cannot distinguish them",
    );
  }
}

// ---------------------------------------------------------------------------
// Op dispatch
// ---------------------------------------------------------------------------

type BridgeMode = "napi" | "wasm";

// Named `BridgeRequest` (not `Request`) and the field `bridgeMode` (not
// `mode`) to avoid collisions with the DOM `Request` / `RequestMode`
// globals that Bun's type package pulls in transitively.
interface BridgeRequest {
  id: number;
  op: string;
  args: Record<string, unknown>;
  bridgeMode: BridgeMode;
}

interface OkResponse {
  id: number;
  ok: true;
  result: Record<string, unknown>;
}

interface ErrResponse {
  id: number;
  ok: false;
  error: { type: string; code: string; message: string };
}

function toErr(id: number, err: unknown): ErrResponse {
  if (err instanceof Error) {
    const codeMatch = err.message.match(/SCP-[A-Z]+-\d+/);
    return {
      id,
      ok: false,
      error: {
        type: err.constructor.name,
        code: codeMatch ? codeMatch[0] : "UNKNOWN",
        message: err.message,
      },
    };
  }
  return {
    id,
    ok: false,
    error: { type: "unknown", code: "UNKNOWN", message: String(err) },
  };
}

async function dispatch(req: BridgeRequest): Promise<OkResponse | ErrResponse> {
  try {
    switch (req.op) {
      case "identity_create":
        return { id: req.id, ok: true, result: await opIdentityCreate(req) };
      case "context_create":
        return { id: req.id, ok: true, result: await opContextCreate(req) };
      case "invalid_capability_rejected":
        return {
          id: req.id,
          ok: true,
          result: await opInvalidCapability(req),
        };
      case "event_log_append":
        return { id: req.id, ok: true, result: await opEventLogAppend(req) };
      case "sign_message":
        return { id: req.id, ok: true, result: await opSignMessage(req) };
      default:
        return {
          id: req.id,
          ok: false,
          error: {
            type: "UnknownOp",
            code: "SCP-PARITY-1001",
            message: `unknown op: ${req.op}`,
          },
        };
    }
  } catch (err: unknown) {
    return toErr(req.id, err);
  }
}

// ---------------------------------------------------------------------------
// Op implementations
// ---------------------------------------------------------------------------

async function opIdentityCreate(
  req: BridgeRequest,
): Promise<Record<string, unknown>> {
  const custody = String(req.args.custody ?? "in_memory");
  if (req.bridgeMode === "napi") {
    const bridge = await loadNapi();
    const handle = await bridge.identityCreate(custody);
    return { did: handle.did, custody };
  }
  const { raw } = await loadWasm();
  const handle = await raw.identity_create(custody);
  return { did: handle.did, custody };
}

async function opContextCreate(
  req: BridgeRequest,
): Promise<Record<string, unknown>> {
  const params = (req.args.params as Record<string, unknown>) ?? {
    name: "parity-test",
    mode: "encrypted",
  };
  if (req.bridgeMode === "napi") {
    const bridge = await loadNapi();
    const identity = await bridge.identityCreate("in_memory");
    const handle = await bridge.contextCreate(identity, JSON.stringify(params));
    return {
      context_id: handle.contextId,
      creator_did: identity.did,
      mode: String(params.mode),
    };
  }
  const { raw } = await loadWasm();
  const identity = await raw.identity_create("in_memory");
  const handle = await raw.context_create(identity.did, JSON.stringify(params));
  return {
    context_id: handle.contextId ?? handle.context_id,
    creator_did: identity.did,
    mode: String(params.mode),
  };
}

async function opInvalidCapability(
  req: BridgeRequest,
): Promise<Record<string, unknown>> {
  const fakeDid =
    "did:dht:znevercreatednevercreatednevercreatednevercreated";
  const badChallenge =
    '{"protocol":"scpid/1","nonce":"00","audience":"x","issued_at":0,"expires_at":0}';
  try {
    if (req.bridgeMode === "napi") {
      const bridge = await loadNapi();
      bridge.scpidSign(fakeDid, "#active", badChallenge);
    } else {
      const { raw } = await loadWasm();
      raw.scpid_sign(fakeDid, "#active", badChallenge);
    }
  } catch (err: unknown) {
    if (err instanceof Error) {
      const codeMatch = err.message.match(/SCP-[A-Z]+-\d+/);
      return {
        error: {
          type: err.constructor.name,
          code: codeMatch ? codeMatch[0] : "UNKNOWN",
          message: err.message,
        },
      };
    }
    return {
      error: { type: "unknown", code: "UNKNOWN", message: String(err) },
    };
  }
  return {
    error: { type: "none", code: "NONE", message: "no error raised" },
  };
}

async function opEventLogAppend(
  req: BridgeRequest,
): Promise<Record<string, unknown>> {
  if (req.bridgeMode === "napi") {
    const bridge = await loadNapi();
    const identity = await bridge.identityCreate("in_memory");
    const handle = await bridge.contextCreate(
      identity,
      JSON.stringify({ name: "parity-elog", mode: "encrypted" }),
    );
    const events = await bridge.eventLogQuery(handle, undefined);
    const first = events[0];
    if (!first) return { event_count: 0, first_event_type: "", first_sequence: 0 };
    return {
      event_count: events.length,
      first_event_type: String(first.eventType),
      first_sequence: Number(first.sequence ?? 0),
    };
  }
  const { raw } = await loadWasm();
  const identity = await raw.identity_create("in_memory");
  const handle = await raw.context_create(
    identity.did,
    JSON.stringify({ name: "parity-elog", mode: "encrypted" }),
  );
  const eventsJson = await raw.event_log_query(handle, undefined);
  const events = JSON.parse(eventsJson) as Array<{
    eventType?: string;
    event_type?: string;
    sequence?: number;
  }>;
  const first = events[0];
  if (!first) return { event_count: 0, first_event_type: "", first_sequence: 0 };
  return {
    event_count: events.length,
    first_event_type: String(first.eventType ?? first.event_type ?? ""),
    first_sequence: Number(first.sequence ?? 0),
  };
}

async function opSignMessage(req: BridgeRequest): Promise<Record<string, unknown>> {
  const audience = String(
    req.args.audience ?? "https://parity-test.example.com",
  );
  const ttl = Number(req.args.ttl_seconds ?? 60);
  if (req.bridgeMode === "napi") {
    const bridge = await loadNapi();
    const identity = await bridge.identityCreate("in_memory");
    const challenge = bridge.scpidChallenge(audience, ttl);
    const responseJson = bridge.scpidSign(identity.did, "#active", challenge);
    const response = JSON.parse(responseJson);
    return {
      protocol: response.protocol,
      did: response.did,
      signing_key_id: response.signing_key_id,
      signature: response.signature,
    };
  }
  const { raw } = await loadWasm();
  const identity = await raw.identity_create("in_memory");
  const challenge = raw.scpid_challenge(audience, ttl);
  const responseJson = raw.scpid_sign(identity.did, "#active", challenge);
  const response = JSON.parse(responseJson);
  return {
    protocol: response.protocol,
    did: response.did,
    signing_key_id: response.signing_key_id,
    signature: response.signature,
  };
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  await emitStartupDiagnostic();
  while (true) {
    let req: unknown;
    try {
      req = await readFrame();
    } catch (err) {
      await writeFrame({
        id: 0,
        ok: false,
        error: {
          type: "FrameError",
          code: "SCP-PARITY-1000",
          message: String(err),
        },
      });
      continue;
    }

    if (req === null) break; // EOF

    if (
      typeof req !== "object" ||
      req === null ||
      !("op" in req) ||
      !("bridgeMode" in req)
    ) {
      await writeFrame({
        id: 0,
        ok: false,
        error: {
          type: "ProtocolError",
          code: "SCP-PARITY-1002",
          message: "malformed request",
        },
      });
      continue;
    }

    const typed = req as BridgeRequest;

    if (typed.op === "shutdown") {
      await writeFrame({ id: typed.id ?? 0, ok: true, result: {} });
      break;
    }

    if (typed.op === "reset") {
      resetBridgeCaches();
      await writeFrame({ id: typed.id ?? 0, ok: true, result: {} });
      continue;
    }

    const response = await dispatch(typed);
    await writeFrame(response);
  }
}

main().catch((err) => {
  console.error("node_bridge_runner fatal:", err);
  process.exit(1);
});
