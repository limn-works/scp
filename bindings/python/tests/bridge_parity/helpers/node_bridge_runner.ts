#!/usr/bin/env bun
/**
 * Long-lived Bun JSON-RPC server for cross-bridge parity testing.
 *
 * Reads length-prefixed JSON requests on stdin, dispatches to the NAPI
 * bridge based on the `bridge_mode` field, and writes length-prefixed
 * JSON responses on stdout.
 *
 * Wire format (HTTP-style):
 *
 *     Content-Length: N\r\n
 *     \r\n
 *     <N bytes of JSON>
 *
 * Request: `{id, op, args, bridge_mode}` where bridge_mode is "napi".
 * Response: either `{id, ok: true, result: {...}}` on success
 *           or `{id, ok: false, error: {type, code, message}}` on bridge error.
 *
 * Bridge selection is explicit — NO auto-fallback. If a non-NAPI bridge
 * mode is requested, the response is an error. The harness surfaces this
 * as a test failure, not a skip. (The WASM bridge was removed per ADR-055, so
 * this NAPI harness is server-only; the browser runs the full protocol in-tab
 * over `scp-client-wasm` per ADR-057, not through this bridge.)
 *
 * ADR-048 / #1549 Phase 4 PR 4: NAPI ops construct a fresh `addon.SCP()`
 * per call and invoke per-instance methods on the resulting handle. The
 * pre-PR 4 free-function façade and the process-wide default instance
 * it routed to were both deleted.
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

// Frame-size caps. Matches `runner_client.py`'s MAX_HEADER_BYTES /
// MAX_FRAME_BYTES, and the Kotlin + Swift runners' equivalent limits —
// a misbehaving harness cannot OOM this process by sending a
// pathologically large `Content-Length` or a runaway header with no
// terminator.
const MAX_HEADER_BYTES = 4 * 1024;
const MAX_FRAME_BYTES = 16 * 1024 * 1024;

/** Reads one length-prefixed frame from stdin. Returns null on EOF. */
async function readFrame(): Promise<unknown | null> {
  // Wait for header terminator, bounded by MAX_HEADER_BYTES so a peer
  // that never sends \r\n\r\n can't grow `inputBuffer` unboundedly.
  while (findSubsequence(inputBuffer, HEADER_TERMINATOR) < 0) {
    if (inputBuffer.length > MAX_HEADER_BYTES) {
      throw new Error(
        `header exceeded ${MAX_HEADER_BYTES} bytes without terminator`,
      );
    }
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
  if (
    !Number.isFinite(contentLength) ||
    contentLength < 0 ||
    contentLength > MAX_FRAME_BYTES
  ) {
    throw new Error(
      `Content-Length out of range: ${lengthStr} (max ${MAX_FRAME_BYTES})`,
    );
  }

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

// Lazy handle to the raw napi-rs native addon. The SDK `createNativeBridge`
// requires a caller-supplied `SCP` (ADR-048 per-instance routing); the
// parity runner talks directly to the raw addon so each op can construct
// a fresh `addon.SCP()` and exercise the class methods under test.
// biome-ignore lint/suspicious/noExplicitAny: raw addon has no TS typings
let napiAddon: any = null;

async function loadNapiAddon(): Promise<typeof napiAddon> {
  if (napiAddon !== null) return napiAddon;
  const platformMap: Record<string, string> = {
    "linux-x64": "@limn-works/scp-ts-napi-linux-x64-gnu",
    "linux-arm64": "@limn-works/scp-ts-napi-linux-arm64-gnu",
    "darwin-x64": "@limn-works/scp-ts-napi-darwin-x64",
    "darwin-arm64": "@limn-works/scp-ts-napi-darwin-arm64",
    "win32-x64": "@limn-works/scp-ts-napi-win32-x64-msvc",
  };
  const key = `${process.platform}-${process.arch}`;
  const packageName = platformMap[key];
  if (packageName === undefined) {
    throw new Error(`parity runner: no NAPI addon for platform ${key}`);
  }
  const { createRequire } = await import("node:module");
  // Resolve via a file inside bindings/typescript so Node's module
  // resolution walks the TS workspace's node_modules tree (where CI
  // wires `@limn-works/scp-ts-napi-linux-x64-gnu`). `import.meta.url`
  // points into bindings/python/tests/bridge_parity/helpers/, which
  // sits in a different subtree and cannot see the NAPI addon package.
  const typescriptAnchor = new URL(
    "../../../../../bindings/typescript/package.json",
    import.meta.url,
  ).href;
  const req = createRequire(typescriptAnchor);
  napiAddon = req(packageName);
  if (typeof napiAddon.SCP !== "function") {
    throw new Error(
      "parity runner: NAPI addon does not expose the SCP class — " +
        "this addon was built before Phase 4 PR 1. Rebuild " +
        "`cargo build -p scp-ffi-napi` against the current tree.",
    );
  }
  return napiAddon;
}

/**
 * Constructs a fresh raw-NAPI `SCP` instance.
 *
 * Every NAPI op in this runner calls this to get a per-call bridge
 * instance. We intentionally do NOT cache: parity ops must be
 * independent, and ADR-048 places registry state on the instance.
 */
async function newNapiScp(): Promise<AnyBridge> {
  const addon = await loadNapiAddon();
  // Storage selection is required (spec §17.6): the raw NAPI constructor
  // takes a JSON storage-config string. Parity ops use explicit in-memory.
  // biome-ignore lint/suspicious/noExplicitAny: raw constructor is untyped
  return new (addon.SCP as new (configJson: string) => any)('{"type":"in_memory"}');
}

/** Rejects any bridge mode other than NAPI. The parity matrix only routes
 * `napi` to this runner (the WASM bridge was removed per ADR-055); a
 * non-NAPI mode reaching here is a harness wiring bug, surfaced loudly. */
function requireNapi(mode: BridgeMode): void {
  if (mode !== "napi") {
    throw new Error(
      `bun runner only serves the NAPI bridge; got bridge_mode '${mode}'`,
    );
  }
}

function resetBridgeCaches(): void {
  // Drop references so the next loader call re-imports. Bun's module
  // cache still holds the underlying ESM, so we are only clearing
  // runner-local closures. Per-op SCP instances are constructed fresh
  // regardless, so the "reset" semantics from the Python harness mean
  // "don't reuse cached bridge imports" — which this accomplishes.
  napiAddon = null;
}

/**
 * Emit a one-shot startup diagnostic so operators can see that the runner
 * came up. The bun runner serves only the NAPI bridge; the addon is loaded
 * lazily on first op, so there is no eager module path to report here.
 */
function emitStartupDiagnostic(): void {
  process.stderr.write(
    `${JSON.stringify({
      event: "bridge_parity_runner_loaded",
      runner: "bun",
      bridge: "napi",
    })}\n`,
  );
}

// ---------------------------------------------------------------------------
// Op dispatch
// ---------------------------------------------------------------------------

type BridgeMode = "napi";

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
      case "outlet_register":
        return { id: req.id, ok: true, result: await opOutletRegister(req) };
      case "ucan_mint":
        return { id: req.id, ok: true, result: await opUcanMint(req) };
      case "ucan_validate_malformed":
        return {
          id: req.id,
          ok: true,
          result: await opUcanValidateMalformed(req),
        };
      case "ucan_evaluate_malformed":
        return {
          id: req.id,
          ok: true,
          result: await opUcanEvaluateMalformed(req),
        };
      case "ucan_evaluate_structured":
        return {
          id: req.id,
          ok: true,
          result: await opUcanEvaluateStructured(req),
        };
      case "transport_status":
        return {
          id: req.id,
          ok: true,
          result: await opTransportStatus(req),
        };
      case "event_log_query_filtered":
        return {
          id: req.id,
          ok: true,
          result: await opEventLogQueryFiltered(req),
        };
      case "event_log_verify_inclusion":
        return {
          id: req.id,
          ok: true,
          result: await opEventLogVerifyInclusion(req),
        };
      case "event_log_absence_of_lifecycle_event_rejected":
        return {
          id: req.id,
          ok: true,
          result: await opEventLogAbsenceRejected(req),
        };
      case "event_log_absence_over_divergent_local_tree_rejected":
        return {
          id: req.id,
          ok: true,
          result: await opEventLogAbsenceOverDivergentLocalTree(req),
        };
      case "event_log_verify_malformed_claim_rejected":
        return {
          id: req.id,
          ok: true,
          result: await opEventLogVerifyMalformedClaim(req),
        };
      case "mcp_context_events_authoritative":
        return {
          id: req.id,
          ok: true,
          result: await opMcpContextEventsAuthoritative(req),
        };
      case "unregistered_did_rejected":
        return {
          id: req.id,
          ok: true,
          result: await opUnregisteredDidRejected(req),
        };
      default:
        return {
          id: req.id,
          ok: false,
          error: {
            type: "UnknownOp",
            code: "TEST-PARITY-1001",
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

// Converts a hex string (expected 64 chars = 32 bytes) to the native seed
// representation NAPI accepts (a Node `Buffer`). Surfaces in Rust as 32 bytes.
function seedFromHex(hex: string | undefined): unknown {
  if (hex === undefined) return undefined;
  if (hex.length !== 64) {
    throw new Error(
      `seed_hex must be 64 chars (32 bytes), got ${hex.length}`,
    );
  }
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return Buffer.from(bytes);
}

async function opIdentityCreate(
  req: BridgeRequest,
): Promise<Record<string, unknown>> {
  requireNapi(req.bridgeMode);
  const custody = String(req.args.custody ?? "in_memory");
  const seedHex =
    typeof req.args.seed_hex === "string" ? req.args.seed_hex : undefined;
  // ADR-048: every NAPI bridge operation routes through a per-instance
  // `SCP.identityCreate(custody, testingSeed?: Buffer)`. The raw addon
  // exposes `SCP` as a constructor; we instantiate it fresh per op so
  // parity cases are independent.
  const scp = await newNapiScp();
  const testingSeed = seedFromHex(seedHex);
  const handle = await scp.identityCreate(custody, testingSeed);
  return {
    did: handle.did,
    custody,
    verifying_key: handle.verifyingKey ?? handle.verifying_key ?? null,
  };
}

async function opContextCreate(
  req: BridgeRequest,
): Promise<Record<string, unknown>> {
  requireNapi(req.bridgeMode);
  const params = (req.args.params as Record<string, unknown>) ?? {
    name: "parity-test",
    mode: "encrypted",
  };
  const scp = await newNapiScp();
  const identity = await scp.identityCreate("in_memory");
  const handle = await scp.contextCreate(identity, JSON.stringify(params));
  return {
    context_id: handle.contextId,
    creator_did: identity.did,
    mode: String(params.mode),
  };
}

async function opInvalidCapability(
  req: BridgeRequest,
): Promise<Record<string, unknown>> {
  requireNapi(req.bridgeMode);
  const fakeDid =
    "did:dht:znevercreatednevercreatednevercreatednevercreated";
  const badChallenge =
    '{"protocol":"scpid/1","nonce":"00","audience":"x","issued_at":0,"expires_at":0}';
  try {
    const scp = await newNapiScp();
    scp.scpidSign(fakeDid, "#active", badChallenge, null);
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

// Shape-valid `did:dht:z…` DID guaranteed NOT to be in any bridge's
// identity registry. Mirrors
// `seed_operations.py::FAKE_UNREGISTERED_DID` — MUST match byte-for-byte
// so the parity harness lines every bridge up against the same input.
const FAKE_UNREGISTERED_DID =
  "did:dht:znever1never1never1never1never1never1never1never1never1never1neva";

async function opUnregisteredDidRejected(
  req: BridgeRequest,
): Promise<Record<string, unknown>> {
  requireNapi(req.bridgeMode);
  // Valid SCPID challenge (passes shape validation). Paired with a DID
  // that is NOT in this instance's identity registry, `scpidSign` must
  // reach the registry-lookup step and reject with SCP-IDENT-1001.
  // Matches `seed_operations.py::_py_unregistered_did_rejected`.
  //
  // Per-instance registries (ADR-048): every NAPI `SCP` starts with an
  // empty identity registry. A hard-coded FAKE_UNREGISTERED_DID is
  // therefore guaranteed to miss the lookup whether we create other
  // identities on this instance or not. We do not populate the registry
  // here — a fresh `SCP` is all the setup the op needs.
  const nowMs = Date.now();
  const challenge = JSON.stringify({
    protocol: "scpid/1.0",
    nonce: "aa".repeat(32),
    audience: "https://parity-test.example.com",
    issued_at: nowMs,
    expires_at: nowMs + 60_000,
  });
  try {
    const scp = await newNapiScp();
    scp.scpidSign(FAKE_UNREGISTERED_DID, "#active", challenge, null);
  } catch (err: unknown) {
    if (err instanceof Error) {
      const codeMatch = err.message.match(/SCP-[A-Z]+-\d+/);
      return {
        error: {
          type: err.constructor.name,
          code: codeMatch ? codeMatch[0] : "UNKNOWN",
        },
      };
    }
    return { error: { type: "unknown", code: "UNKNOWN" } };
  }
  return { error: { type: "none", code: "NONE" } };
}

async function opEventLogAppend(
  req: BridgeRequest,
): Promise<Record<string, unknown>> {
  requireNapi(req.bridgeMode);
  const scp = await newNapiScp();
  const identity = await scp.identityCreate("in_memory");
  const handle = await scp.contextCreate(
    identity,
    JSON.stringify({ name: "parity-elog", mode: "encrypted" }),
  );
  const events = await scp.eventLogQuery(handle, undefined);
  const first = events[0];
  if (!first) return { event_count: 0, first_event_type: "", first_sequence: 0 };
  return {
    event_count: events.length,
    first_event_type: String(first.eventType),
    first_sequence: Number(first.sequence ?? 0),
  };
}

// -- ops 6-10 -------------------------------------------------------------

// Shared outlet registration body — pinned across bridges in
// `seed_operations.py::OP_OUTLET_REGISTER`.
const PARITY_OUTLET_NAME = "parity_probe";
const PARITY_OUTLET_SCHEMA = {
  input: {
    type: "object",
    properties: {
      x: { type: "integer" },
      label: { type: "string" },
    },
  },
  output: {
    type: "object",
    properties: {
      y: { type: "integer" },
      status: { type: "string" },
    },
  },
};
const PARITY_OUTLET_CEILING = [
  "messages:read",
  "messages:write",
  "outlet:register",
  "outlet_call:*",
];

async function opOutletRegister(
  req: BridgeRequest,
): Promise<Record<string, unknown>> {
  requireNapi(req.bridgeMode);
  const ceiling = (req.args.ceiling as string[]) ?? PARITY_OUTLET_CEILING;
  const params = { name: "parity-outlets", mode: "encrypted", ceiling };
  const scp = await newNapiScp();
  const identity = await scp.identityCreate("in_memory");
  const handle = await scp.contextCreate(identity, JSON.stringify(params));
  // NapiOutletDefinition fields are camelCase on the JS side (napi-rs
  // renames `input_schema_json` → `inputSchemaJson`) and expect JSON
  // STRINGS, not nested objects. Matches
  // `crates/scp-ffi/napi/src/outlets.rs::NapiOutletDefinition`.
  // napi-rs `Option<T>` fields are serialized from JS `undefined`, not
  // `null` — passing `null` hits the non-null `FromNapiValue<String>`
  // path and errors with "Failed to convert JavaScript value `Null`".
  // Omit optional fields entirely; napi-rs reads them as `None`.
  const outletId = await scp.outletRegister(handle, {
    name: PARITY_OUTLET_NAME,
    description: "parity harness probe outlet",
    // Action = the historical default; keeps the deterministic outlet_id and
    // UCAN-stem preimage identical to pre-`kind` parity fixtures. Override via
    // the op payload to exercise Query outlets.
    kind: (req.args.kind as "query" | "action") ?? "action",
    inputSchemaJson: JSON.stringify(PARITY_OUTLET_SCHEMA.input),
    outputSchemaJson: JSON.stringify(PARITY_OUTLET_SCHEMA.output),
    operatorDid: identity.did,
  });
  return { outlet_id: outletId };
}

async function opUcanMint(req: BridgeRequest): Promise<Record<string, unknown>> {
  requireNapi(req.bridgeMode);
  const memberDid = String(req.args.member_did);
  const capabilities = (req.args.capabilities as string[]) ?? ["messages:read"];
  const ceiling = (req.args.ceiling as string[]) ?? ["messages:read"];
  const params = { name: "parity-ucan", mode: "encrypted", ceiling };
  const scp = await newNapiScp();
  const identity = await scp.identityCreate("in_memory");
  const handle = await scp.contextCreate(identity, JSON.stringify(params));
  const token = await scp.ucanMint(handle, memberDid, capabilities);
  return {
    issuer: token.issuer,
    audience: token.audience,
    capability_count: token.capabilities.length,
  };
}

async function opUcanValidateMalformed(
  req: BridgeRequest,
): Promise<Record<string, unknown>> {
  requireNapi(req.bridgeMode);
  const ceiling = (req.args.ceiling as string[]) ?? ["messages:read"];
  const params = { name: "parity-ucan-v", mode: "encrypted", ceiling };
  const badToken = "not.a.jwt";
  const capability = "scp:ctx:any/messages:read";
  try {
    const scp = await newNapiScp();
    const identity = await scp.identityCreate("in_memory");
    const handle = await scp.contextCreate(
      identity,
      JSON.stringify(params),
    );
    // Fail-closed presenting-agent gate: supply one so the malformed JWT is
    // rejected at PARSE (the behavior under test), not short-circuited.
    await scp.ucanValidate(handle, badToken, capability, identity.did);
  } catch (err: unknown) {
    if (err instanceof Error) {
      const codeMatch = err.message.match(/SCP-[A-Z]+-\d+/);
      return {
        error: {
          type: err.constructor.name,
          code: codeMatch ? codeMatch[0] : "UNKNOWN",
        },
      };
    }
    return { error: { type: "unknown", code: "UNKNOWN" } };
  }
  return { error: { type: "none", code: "NONE" } };
}

async function opUcanEvaluateMalformed(
  req: BridgeRequest,
): Promise<Record<string, unknown>> {
  requireNapi(req.bridgeMode);
  const ceiling = (req.args.ceiling as string[]) ?? ["messages:read"];
  const params = { name: "parity-ucan-e", mode: "encrypted", ceiling };
  const badToken = "not.a.jwt";
  const capability = "scp:ctx:any/messages:read";
  try {
    const scp = await newNapiScp();
    const identity = await scp.identityCreate("in_memory");
    const handle = await scp.contextCreate(
      identity,
      JSON.stringify(params),
    );
    // Fail-closed presenting-agent gate: supply one so the malformed JWT is
    // rejected at PARSE (the behavior under test), not short-circuited.
    await scp.ucanEvaluate(handle, badToken, capability, identity.did);
  } catch (err: unknown) {
    if (err instanceof Error) {
      const codeMatch = err.message.match(/SCP-[A-Z]+-\d+/);
      return {
        error: {
          type: err.constructor.name,
          code: codeMatch ? codeMatch[0] : "UNKNOWN",
        },
      };
    }
    return { error: { type: "unknown", code: "UNKNOWN" } };
  }
  return { error: { type: "none", code: "NONE" } };
}

async function opUcanEvaluateStructured(
  req: BridgeRequest,
): Promise<Record<string, unknown>> {
  requireNapi(req.bridgeMode);
  // Mint a VALID root token granting `messages:read`, then evaluate it
  // requiring `messages:write` (a capability the token does NOT grant). Core
  // `evaluate_ucan` short-circuits at grant-match, returning the partial-false
  // struct {tokensValid:true, signaturesValid:false, ...rest false} WITHOUT
  // throwing. This is the no-throw counterpart to opUcanEvaluateMalformed.
  const memberDid = String(req.args.member_did);
  const capabilities = (req.args.capabilities as string[]) ?? ["messages:read"];
  const requiredCap = String(req.args.required_capability ?? "messages:write");
  const ceiling = (req.args.ceiling as string[]) ?? ["messages:read"];
  const params = { name: "parity-ucan-es", mode: "encrypted", ceiling };
  const scp = await newNapiScp();
  const identity = await scp.identityCreate("in_memory");
  const handle = await scp.contextCreate(identity, JSON.stringify(params));
  const token = await scp.ucanMint(handle, memberDid, capabilities);
  const required = `scp:ctx:${handle.contextId}/${requiredCap}`;
  // Presenting agent is REQUIRED (fail-closed): pass the token's audience (the
  // minted member DID) so the step-5 audience check passes and the failing
  // stage is purely the grant-match, identical across bridges.
  const result = await scp.ucanEvaluate(handle, token.encoded, required, memberDid);
  return {
    tokens_valid: result.tokensValid,
    signatures_valid: result.signaturesValid,
    within_ceiling: result.withinCeiling,
    nonce_valid: result.nonceValid,
    not_revoked: result.notRevoked,
    time_bounds_valid: result.timeBoundsValid,
  };
}

async function opTransportStatus(
  req: BridgeRequest,
): Promise<Record<string, unknown>> {
  requireNapi(req.bridgeMode);
  // NAPI exposes a handleless transport probe via
  // `SCP.transportStatus(null)` — the `null` opts into the
  // BridgeInstance-level stateless snapshot.
  const scp = await newNapiScp();
  const status = await scp.transportStatus(null);
  return {
    connected: status.connected ?? false,
    relay_url: status.relayUrl ?? status.relay_url ?? null,
    latency_ms: status.latencyMs ?? status.latency_ms ?? null,
  };
}

async function opEventLogQueryFiltered(
  req: BridgeRequest,
): Promise<Record<string, unknown>> {
  requireNapi(req.bridgeMode);
  const filter = (req.args.filter as Record<string, unknown>) ?? {
    event_type: "ContextCreated",
  };
  const params = { name: "parity-elog-f", mode: "encrypted" };
  const scp = await newNapiScp();
  const identity = await scp.identityCreate("in_memory");
  const handle = await scp.contextCreate(identity, JSON.stringify(params));
  // Raw NAPI `eventLogQuery` takes `filter_json: Option<String>`, not
  // an Object. Pass a JSON-encoded filter.
  const events = await scp.eventLogQuery(handle, JSON.stringify(filter));
  const first = events[0];
  return {
    event_count: events.length,
    first_event_type: first ? String(first.eventType) : "",
  };
}

async function opEventLogVerifyInclusion(
  req: BridgeRequest,
): Promise<Record<string, unknown>> {
  requireNapi(req.bridgeMode);
  const params = { name: "parity-elog-v", mode: "encrypted" };
  const scp = await newNapiScp();
  const identity = await scp.identityCreate("in_memory");
  const handle = await scp.contextCreate(identity, JSON.stringify(params));
  // `ContextCreated` is leaf 0 of the AUTHORITATIVE log on every bridge.
  const proof = await scp.eventLogVerify(
    handle,
    JSON.stringify({ type: "inclusion", leaf_index: 0 }),
  );
  const details = JSON.parse(proof.detailsJson) as Record<string, unknown>;
  return {
    proof_type: String(proof.proofType),
    leaf_count: Number(details.leaf_count),
    has_leaf_hash: "leaf_hash" in details,
    has_path: "path" in details,
    has_root: "root" in details,
  };
}

async function opEventLogAbsenceRejected(
  req: BridgeRequest,
): Promise<Record<string, unknown>> {
  requireNapi(req.bridgeMode);
  const params = { name: "parity-elog-v", mode: "encrypted" };
  const scp = await newNapiScp();
  const identity = await scp.identityCreate("in_memory");
  const handle = await scp.contextCreate(identity, JSON.stringify(params));
  // Extract the `ContextCreated` leaf hash from the bridge's own
  // inclusion proof, so the absence claim provably names an event that
  // IS in the authoritative log.
  const inclusion = await scp.eventLogVerify(
    handle,
    JSON.stringify({ type: "inclusion", leaf_index: 0 }),
  );
  const details = JSON.parse(inclusion.detailsJson) as Record<string, unknown>;
  const leafHash = String(details.leaf_hash);
  try {
    await scp.eventLogVerify(
      handle,
      JSON.stringify({ type: "absence", event_hash: leafHash }),
    );
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

// Reproduces the authoritative-vs-bridge-local divergence precondition
// through the PUBLIC surface — the mechanical guard ops 12/13 CANNOT
// provide because they run on a pristine context whose bridge-local tree
// still equals the authoritative log. Diverges the trees via
// `provenanceAttach`, reads the AUTHORITATIVE ContextCreated hash from the
// query path (independent of the verify path under test), then claims it
// absent. A correct bridge proves over the authoritative log where the hash
// IS present and rejects with SCP-CTX-2139; a bridge regressed to the
// divergent local tree would mint a verifying absence proof. Mirrors
// `seed_operations.py::_py_event_log_absence_over_divergent_local_tree_rejected`.
async function opEventLogAbsenceOverDivergentLocalTree(
  req: BridgeRequest,
): Promise<Record<string, unknown>> {
  requireNapi(req.bridgeMode);
  const params = { name: "parity-elog-v", mode: "encrypted" };
  const scp = await newNapiScp();
  const identity = await scp.identityCreate("in_memory");
  const handle = await scp.contextCreate(identity, JSON.stringify(params));
  // Diverge the bridge-local tree from the authoritative log via a real
  // public bridge call. The source context is missing, so only the
  // `ProvenanceReceived` target-side leaf lands on the bridge-local tree (a
  // leaf NOT in the authoritative log); the source-side `ProvenanceAttached`
  // append is dropped best-effort.
  scp.provenanceAttach(
    "parity-prov-source",
    "persistent",
    "full",
    [identity.did],
    handle.contextId,
    identity.did,
  );
  // AUTHORITATIVE ContextCreated leaf hash, read from the query path —
  // independent of the verify path under test.
  const events = await scp.eventLogQuery(
    handle,
    JSON.stringify({ event_type: "ContextCreated" }),
  );
  const first = events[0];
  const payload = JSON.parse(String(first.payloadJson)) as Record<string, unknown>;
  const authHash = String(payload.hash);
  try {
    await scp.eventLogVerify(
      handle,
      JSON.stringify({ type: "absence", event_hash: authHash }),
    );
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

// The mechanical cross-bridge guard for malformed claim input: a malformed
// claim carries SCP-VALID-7000 on every bridge. Feeds a malformed inclusion
// claim (missing `leaf_index`) over a readable log and reports the code.
// Mirrors `seed_operations.py::_py_event_log_verify_malformed_claim`.
async function opEventLogVerifyMalformedClaim(
  req: BridgeRequest,
): Promise<Record<string, unknown>> {
  requireNapi(req.bridgeMode);
  const params = { name: "parity-elog-v", mode: "encrypted" };
  const scp = await newNapiScp();
  const identity = await scp.identityCreate("in_memory");
  const handle = await scp.contextCreate(identity, JSON.stringify(params));
  try {
    // `type` present and valid, `leaf_index` MISSING — malformed input the
    // inclusion arm rejects with VALID-7000 over a readable log.
    await scp.eventLogVerify(handle, JSON.stringify({ type: "inclusion" }));
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

// The direct cross-bridge regression guard for the `context_events` twin.
// Reads the AUTHORITATIVE root + count from the verify path, diverges the
// bridge-local tree via `provenanceAttach` (a `ProvenanceReceived` leaf NOT
// in the authoritative log), then asserts the `mcpContextEvents` summary
// STILL commits to the authoritative log. Raw `merkle_root` bytes are not
// compared cross-bridge (the fresh `ContextCreated` leaf carries a
// wall-clock timestamp); the SEMANTIC `root_matches_authoritative`
// invariant is. Mirrors
// `seed_operations.py::_py_mcp_context_events_authoritative`.
async function opMcpContextEventsAuthoritative(
  req: BridgeRequest,
): Promise<Record<string, unknown>> {
  requireNapi(req.bridgeMode);
  const params = { name: "parity-elog-v", mode: "encrypted" };
  const scp = await newNapiScp();
  const identity = await scp.identityCreate("in_memory");
  const handle = await scp.contextCreate(identity, JSON.stringify(params));
  // AUTHORITATIVE root + count from the verify path — independent of the MCP
  // summary surface under test.
  const proof = await scp.eventLogVerify(
    handle,
    JSON.stringify({ type: "inclusion", leaf_index: 0 }),
  );
  const details = JSON.parse(proof.detailsJson) as Record<string, unknown>;
  const authRoot = String(details.root);
  const authCount = Number(details.leaf_count);
  // Diverge the bridge-local tree via a real public bridge call (appends a
  // `ProvenanceReceived` leaf NOT in the authoritative log).
  scp.provenanceAttach(
    "parity-prov-source",
    "persistent",
    "full",
    [identity.did],
    handle.contextId,
    identity.did,
  );
  const summary = JSON.parse(scp.mcpContextEvents(handle)) as Record<
    string,
    unknown
  >;
  const ceRoot = summary.merkle_root;
  const ceCount = summary.event_count;
  return {
    event_count: typeof ceCount === "number" ? ceCount : -1,
    root_matches_authoritative: ceRoot === authRoot,
    count_matches_authoritative: ceCount === authCount,
  };
}

async function opSignMessage(req: BridgeRequest): Promise<Record<string, unknown>> {
  requireNapi(req.bridgeMode);
  const audience = String(
    req.args.audience ?? "https://parity-test.example.com",
  );
  const ttl = Number(req.args.ttl_seconds ?? 60);
  const seedHex =
    typeof req.args.seed_hex === "string" ? req.args.seed_hex : undefined;
  // Optional `signed_at_override` (ms since epoch). When present, the
  // bridge pins `signed_at` to that value so Ed25519 signatures are
  // byte-exact across PyO3/NAPI/UniFFI under the shared seed.
  const signedAtOverride =
    typeof req.args.signed_at_override === "number"
      ? Number(req.args.signed_at_override)
      : undefined;
  const scp = await newNapiScp();
  const testingSeed = seedFromHex(seedHex);
  const identity = await scp.identityCreate("in_memory", testingSeed);
  // `scpidChallenge` on the NAPI bridge is an `Scp` method after
  // ADR-048 Phase D — every entry point routes through the instance
  // for handle affinity. It is stateless (no registry lookup), but
  // still hangs off `scp` so the API surface is uniform.
  const challenge = scp.scpidChallenge(audience, ttl);
  const patched = patchChallengeForOverride(challenge, signedAtOverride);
  const overrideArg =
    signedAtOverride === undefined ? null : BigInt(signedAtOverride);
  const responseJson = scp.scpidSign(
    identity.did,
    "#active",
    patched,
    overrideArg,
  );
  const response = JSON.parse(responseJson);
  return {
    protocol: response.protocol,
    did: response.did,
    signing_key_id: response.signing_key_id,
    signature: response.signature,
  };
}

/// When a `signed_at_override` is supplied, the challenge must match
/// the pinned fixture used by the Python harness AND the scp-runtime
/// golden-value test. We REPLACE the bridge-issued challenge with the
/// pinned one so every bridge feeds `scpid_sign` the same canonical
/// hash inputs. `expires_at` is set far in the future (year 2286) so
/// wall-clock expiry can't trip the bridge-side expiry check.
function patchChallengeForOverride(
  _challengeJson: string,
  override: number | undefined,
): string {
  if (override === undefined) {
    return _challengeJson;
  }
  return JSON.stringify({
    protocol: "scpid/1.0",
    nonce: PARITY_NONCE_HEX,
    audience: "https://parity-test.example.com",
    issued_at: override,
    expires_at: PARITY_CHALLENGE_EXPIRES_AT_MS,
  });
}

/// Fixed 32-byte nonce used when `signed_at_override` pins the SCPID
/// response. Must match `bindings/python/tests/bridge_parity/seed_operations.py`
/// (PARITY_NONCE_HEX).
const PARITY_NONCE_HEX = "aa".repeat(32);
/// Year-2286 timestamp — far enough in the future that wall-clock
/// expiry cannot trip the SCPID expiry check. Must match the
/// Python harness's PARITY_CHALLENGE_EXPIRES_AT_MS.
const PARITY_CHALLENGE_EXPIRES_AT_MS = 9_999_999_999_000;

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

// Best-effort id extraction from a partially-parsed request.
function extractRequestId(value: unknown): number {
  if (
    value !== null &&
    typeof value === "object" &&
    "id" in value &&
    typeof (value as { id: unknown }).id === "number"
  ) {
    return (value as { id: number }).id;
  }
  return -1;
}

async function main(): Promise<void> {
  emitStartupDiagnostic();
  while (true) {
    let req: unknown;
    try {
      req = await readFrame();
    } catch (err) {
      await writeFrame({
        id: -1,
        ok: false,
        error: {
          type: "FrameError",
          code: "TEST-PARITY-1000",
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
        id: extractRequestId(req),
        ok: false,
        error: {
          type: "ProtocolError",
          code: "TEST-PARITY-1002",
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
