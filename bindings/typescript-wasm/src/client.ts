/**
 * {@link ScpBrowserClient} — the in-browser SCP participant façade over the
 * wasm-bindgen `WasmScpClient` (ADR-057 Slice 3).
 *
 * The full MLS protocol runs in-tab over `scp-client-wasm`; this façade marshals
 * every wasm export into idiomatic TS (flat result objects, `bigint` for the u64
 * observers, typed `ScpError`s) and owns the relay transport wiring. It is a
 * capability SUBSET — no governance / economy / saga coordination / media / DHT /
 * broadcast hosting (the `scp-runtime` scope fence). Those live in the
 * full-capability NAPI tier (`@limn-works/scp-ts`), never in-browser.
 */

import type { JsKeyCustody, JsSocket, JsStorage } from "./adapters/types";
import {
  WebSocketRelaySocket,
  type WebSocketRelaySocketOptions,
} from "./adapters/websocket-relay-socket";
import { mapBridgeError, type ScpError, ValidationError } from "./errors";
import type {
  AddMemberOutput,
  ContextStatus,
  ReceivedEvent,
  ReceiveOutput,
  SenderKeyDistribution,
} from "./types";
import wasmInit, {
  type InitInput,
  scp_init,
  scp_version,
  type WasmAddMemberOutput,
  type WasmReceivedEvent,
  type WasmReceiveOutput,
  WasmScpClient,
  type WasmSenderKeyDistribution,
  outletStreamComputeCaveatsBinding as wasmComputeCaveatsBinding,
  outletStreamVerifyChunkSignature as wasmVerifyChunkSignature,
} from "./wasm/scp_client_wasm.js";

// ---------------------------------------------------------------------------
// One-time wasm initialization
// ---------------------------------------------------------------------------

let initialized = false;

/**
 * Loads and initializes the wasm module, installing the redacting panic hook.
 *
 * Call once before constructing any client. {@link ScpBrowserClient.connect}
 * awaits it for you. Idempotent — a second call is a no-op (and ignores its
 * argument), so the first initialization wins.
 *
 * @param input - Optional wasm source (a `WebAssembly.Module`, bytes, URL, or
 *   `Response`). Omit in the browser to load the `.wasm` sibling shipped
 *   alongside the bundle via `new URL(..., import.meta.url)`. An embedder that
 *   fetches the wasm itself (Workers, a custom loader) passes it here.
 */
export async function initScp(input?: InitInput): Promise<void> {
  if (initialized) {
    return;
  }
  // Use the modern single-object init shape when an explicit source is given
  // (the raw-argument form is deprecated by wasm-bindgen); the no-arg default
  // path stays untouched so it resolves the shipped `.wasm` sibling.
  await wasmInit(input === undefined ? undefined : { module_or_path: input });
  // Redacting panic hook (never reads the panic payload — it may hold key
  // material or plaintext). Idempotent on the Rust side.
  scp_init();
  initialized = true;
}

/** Whether {@link initScp} has completed. */
export function isScpInitialized(): boolean {
  return initialized;
}

/** The wasm crate version string. Requires {@link initScp} to have completed. */
export function scpVersion(): string {
  assertInitialized();
  return scp_version();
}

function assertInitialized(): void {
  if (!initialized) {
    throw new ValidationError(
      "[SCP-VALID-7025] scp-ts-wasm is not initialized — await initScp() (or use ScpBrowserClient.connect, which awaits it) before constructing or using a client.",
      "SCP-VALID-7025",
    );
  }
}

// ---------------------------------------------------------------------------
// Wasm → flat-object marshalling
// ---------------------------------------------------------------------------

function marshalDistribution(d: WasmSenderKeyDistribution): SenderKeyDistribution {
  const out: SenderKeyDistribution = { targetDid: d.targetDid, ciphertext: d.ciphertext };
  d.free();
  return out;
}

function marshalDistributions(ds: WasmSenderKeyDistribution[]): SenderKeyDistribution[] {
  return ds.map(marshalDistribution);
}

function marshalAddMemberOutput(o: WasmAddMemberOutput): AddMemberOutput {
  const out: AddMemberOutput = {
    commit: o.commit,
    welcome: o.welcome,
    eventLog: o.eventLog,
    wrappingKeys: o.wrappingKeys,
    senderKeyDistributions: marshalDistributions(o.senderKeyDistributions),
  };
  o.free();
  return out;
}

function marshalReceiveOutput(o: WasmReceiveOutput): ReceiveOutput {
  const out: ReceiveOutput = {
    application: o.application,
    senderKeyDistributions: marshalDistributions(o.senderKeyDistributions),
  };
  o.free();
  return out;
}

function marshalEvent(e: WasmReceivedEvent): ReceivedEvent {
  const out: ReceivedEvent = { kind: e.kind, senderDid: e.senderDid, payload: e.payload };
  e.free();
  return out;
}

/** Runs a wasm call, re-throwing any thrown exception as a typed {@link ScpError}. */
function call<T>(fn: () => T): T {
  try {
    return fn();
  } catch (e) {
    throw mapBridgeError(e);
  }
}

// ---------------------------------------------------------------------------
// Construction options
// ---------------------------------------------------------------------------

/** Ports and options shared by every construction path. */
interface ScpBrowserClientCommonOptions {
  /** On-device key custody (its bound DID becomes this participant's identity). */
  readonly custody: JsKeyCustody;
  /** Durable or ephemeral key/value storage (see the adapters). */
  readonly storage: JsStorage;
}

/** Options for {@link ScpBrowserClient.create} (an embedder-supplied socket). */
export interface ScpBrowserClientCreateOptions extends ScpBrowserClientCommonOptions {
  /**
   * The outbound relay socket. The embedder is responsible for pumping inbound
   * relay frames into {@link ScpBrowserClient.handleRelayFrame} and calling
   * {@link ScpBrowserClient.resubscribeAll} on every socket (re)open.
   */
  readonly socket: JsSocket;
}

/** Options for {@link ScpBrowserClient.connect} (managed WebSocket transport). */
export interface ScpBrowserConnectOptions
  extends ScpBrowserClientCommonOptions,
    WebSocketRelaySocketOptions {
  /**
   * Optional wasm source forwarded to {@link initScp} on first init. Omit in the
   * browser to load the shipped `.wasm` sibling.
   */
  readonly wasmModule?: InitInput;
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

/**
 * The in-browser SCP participant client.
 *
 * Construct via {@link ScpBrowserClient.connect} (batteries-included WebSocket
 * transport) or {@link ScpBrowserClient.create} (bring-your-own `JsSocket`, e.g.
 * a Deno / Workers / `ws` embedder). Every method throws a typed
 * {@link ScpError} subclass on failure.
 */
export class ScpBrowserClient {
  readonly #inner: WasmScpClient;
  readonly #managedSocket: WebSocketRelaySocket | undefined;

  private constructor(inner: WasmScpClient, managedSocket?: WebSocketRelaySocket) {
    this.#inner = inner;
    this.#managedSocket = managedSocket;
  }

  /**
   * Constructs a client over an embedder-supplied outbound {@link JsSocket}.
   *
   * The embedder OWNS the inbound pump: on each relay `onmessage` it must call
   * {@link handleRelayFrame}, and on every socket (re)open it must call
   * {@link resubscribeAll} (else a reconnected/restored tab goes deaf — ADR-057
   * §Offline residual). For the batteries-included WebSocket path that wires this
   * automatically, use {@link connect} instead.
   *
   * Requires {@link initScp} to have completed.
   */
  static create(options: ScpBrowserClientCreateOptions): ScpBrowserClient {
    assertInitialized();
    // Loud guard against a silent footgun: WebSocketRelaySocket is the MANAGED
    // transport for connect(), which performs the two-phase attach (wires the
    // inbound pump + reconnect). Passing it to create() leaves it unattached —
    // send() would throw "not open" forever and no inbound frame ever arrives.
    // Fail closed with a clear pointer rather than a silently-dead client.
    if (options.socket instanceof WebSocketRelaySocket) {
      throw new ValidationError(
        "[SCP-VALID-7026] WebSocketRelaySocket is the managed transport for " +
          "ScpBrowserClient.connect() (it wires the inbound pump + reconnect). Passing it " +
          "to create() leaves it unattached — send() would throw forever with no inbound " +
          "flow. Use ScpBrowserClient.connect({ custody, storage, url }) for the managed " +
          "transport, or pass your OWN JsSocket to create() and pump handleRelayFrame / " +
          "resubscribeAll from its onmessage / onopen yourself.",
        "SCP-VALID-7026",
      );
    }
    const inner = new WasmScpClient(options.custody, options.storage, options.socket);
    return new ScpBrowserClient(inner);
  }

  /**
   * Constructs a client over a managed WebSocket relay transport and wires the
   * inbound pump (two-phase attach — resolves the circular construction: the
   * socket's `send` needs only the WebSocket, so it is built first; the pump
   * needs the client, so it is attached after).
   *
   * The pump wires `onopen → resubscribeAll` (fires on initial open AND every
   * reconnect — idempotent, best-effort), `onmessage → handleRelayFrame` (benign
   * drops return internally; a genuine error routes to `onError` and never kills
   * the pump), and `onclose → reconnect-with-backoff → re-fires onopen`.
   *
   * Awaits {@link initScp} for you.
   */
  static async connect(options: ScpBrowserConnectOptions): Promise<ScpBrowserClient> {
    await initScp(options.wasmModule);
    // Phase 1: the socket (its `send` needs only the WebSocket, not the client).
    const socket = new WebSocketRelaySocket(options);
    // Phase 2: the wasm client over the socket-as-JsSocket.
    const inner = new WasmScpClient(options.custody, options.storage, socket);
    const client = new ScpBrowserClient(inner, socket);
    // Phase 3: attach the pump now that the client exists. `onError` is spread
    // conditionally so an absent handler stays absent (exactOptionalPropertyTypes).
    socket.attach({
      onOpen: () => client.resubscribeAll(),
      onFrame: (frame) => client.handleRelayFrame(frame),
      ...(options.onError ? { onError: options.onError } : {}),
    });
    return client;
  }

  /** This participant's DID. */
  get did(): string {
    return this.#inner.did;
  }

  /**
   * Creates a new encrypted context with this participant as sole member.
   *
   * @throws {ContextError} `SCP-CTX-2002` if the id is already held.
   * @throws {CryptoError} on group-creation / leaf failure.
   * @throws {StorageError} `SCP-STORAGE-8010` if the snapshot write fails (poisons the context).
   */
  createContext(contextId: string): void {
    call(() => this.#inner.createContext(contextId));
  }

  /**
   * Generates a single-use `KeyPackage` so this participant can be added to
   * `contextId` by an existing member. Returns the public key-package bytes to
   * hand to the adder.
   */
  generateKeyPackageForJoin(contextId: string): Uint8Array {
    return call(() => this.#inner.generateKeyPackageForJoin(contextId));
  }

  /** Adds a member to `contextId` from their serialized `KeyPackage`. */
  addMember(contextId: string, keyPackageBytes: Uint8Array): AddMemberOutput {
    return call(() => marshalAddMemberOutput(this.#inner.addMember(contextId, keyPackageBytes)));
  }

  /**
   * Joins `contextId` from a Welcome, replaying the adder's event-log stream and
   * adopting its membership snapshot. Returns the sender-key distributions to
   * deliver to existing members.
   */
  joinContextEncrypted(
    contextId: string,
    welcomeBytes: Uint8Array,
    eventLogBytes: Uint8Array,
    wrappingKeysBytes: Uint8Array,
  ): SenderKeyDistribution[] {
    return call(() =>
      marshalDistributions(
        this.#inner.joinContextEncrypted(contextId, welcomeBytes, eventLogBytes, wrappingKeysBytes),
      ),
    );
  }

  /**
   * Encrypts an application message in `contextId` and fans it out over the
   * injected socket to every announced peer pseudonym (§9.10.4). No return value
   * — the ciphertext leaves via the socket, not the caller.
   *
   * @throws {ContextError} `SCP-CTX-2040` if no peer has announced a pseudonym yet (retryable).
   * @throws {TransportError} `SCP-TRANS-5010` if the socket rejects a frame.
   */
  sendMessage(contextId: string, plaintext: Uint8Array): void {
    call(() => this.#inner.sendMessage(contextId, plaintext));
  }

  /**
   * Feeds one inbound relay frame (the binary payload of a relay WebSocket
   * `onmessage`) into the driver. A frame for a routing id this client does not
   * track, or a self-echo, is dropped internally (not an error). The managed
   * {@link connect} transport calls this for you.
   */
  handleRelayFrame(frame: Uint8Array): void {
    call(() => this.#inner.handleRelayFrame(frame));
  }

  /**
   * Re-drives a `SUBSCRIBE` for every routing id this client tracks. Idempotent
   * and best-effort — it never throws. The managed {@link connect} transport
   * calls this from the WebSocket `onopen` on every (re)connect; an embedder
   * using {@link create} MUST call it from its own `onopen`.
   */
  resubscribeAll(): void {
    // The wasm surface is infallible here (returns `()`); the try/catch is
    // defense-in-depth so a best-effort re-subscribe never escapes to kill a pump.
    try {
      this.#inner.resubscribeAll();
    } catch {
      // Swallowed by contract: a failed re-subscribe is retried on the next onopen.
    }
  }

  /** Receives an inbound MLS message in `contextId` (out-of-band delivery path). */
  receiveMessage(contextId: string, ciphertext: Uint8Array): ReceiveOutput {
    return call(() => marshalReceiveOutput(this.#inner.receiveMessage(contextId, ciphertext)));
  }

  /** Drains all buffered receive events for `contextId` in FIFO order. */
  drainEvents(contextId: string): ReceivedEvent[] {
    return call(() => this.#inner.drainEvents(contextId).map(marshalEvent));
  }

  /** Closes and removes `contextId`, destroying its crypto state (forward secrecy). */
  closeContext(contextId: string): void {
    call(() => this.#inner.closeContext(contextId));
  }

  /**
   * Rotates this participant's §9.16 sender key and re-distributes it to every
   * member (§9.16.5). Returns the distributions to deliver.
   */
  rotateSenderKey(contextId: string): SenderKeyDistribution[] {
    return call(() => marshalDistributions(this.#inner.rotateSenderKey(contextId)));
  }

  /** The ids of every context this client holds (live and poisoned alike), sorted. */
  get contextIds(): string[] {
    return this.#inner.contextIds;
  }

  /** Whether `contextId` is `"live"`, `"poisoned"`, or `"absent"` (non-throwing). */
  contextStatus(contextId: string): ContextStatus {
    return this.#inner.contextStatus(contextId) as ContextStatus;
  }

  /** The member DIDs of `contextId`, or `undefined` if not held (or poisoned). */
  memberDids(contextId: string): string[] | undefined {
    return this.#inner.memberDids(contextId);
  }

  /** The event-log Merkle root (32 bytes) for `contextId`, or `undefined` if not held. */
  eventLogRoot(contextId: string): Uint8Array | undefined {
    return this.#inner.eventLogRoot(contextId);
  }

  /**
   * The event-log leaf count for `contextId` as a `bigint` (a u64 — never a lossy
   * `Number`, #1229), or `undefined` if not held.
   */
  eventLogLeafCount(contextId: string): bigint | undefined {
    return this.#inner.eventLogLeafCount(contextId);
  }

  /** The concatenated event-log leaf hashes (32 bytes each) for `contextId`, or `undefined`. */
  eventLogLeafHashes(contextId: string): Uint8Array | undefined {
    return this.#inner.eventLogLeafHashes(contextId);
  }

  /**
   * The MLS group epoch for `contextId` as a `bigint` (a u64 — #1229), or
   * `undefined` if the context is not held (or poisoned).
   *
   * Returns `undefined` for an absent/poisoned context — symmetric with the
   * sibling observers ({@link memberDids}, {@link eventLogRoot},
   * {@link eventLogLeafCount}, {@link eventLogLeafHashes}), which collapse
   * not-held/poisoned into `undefined` rather than throwing.
   */
  mlsEpoch(contextId: string): bigint | undefined {
    // Gate on the non-throwing status predicate so a not-held/poisoned context
    // yields `undefined` like the siblings, instead of the wasm surface's
    // `[SCP-CTX-2001]` / `[SCP-STORAGE-8013]` throw. Single-threaded driver, so
    // there is no status→epoch race.
    if (this.#inner.contextStatus(contextId) !== "live") {
      return undefined;
    }
    return call(() => this.#inner.mlsEpoch(contextId));
  }

  /**
   * Closes the managed transport (if this client was built via {@link connect}).
   * A no-op for a {@link create}d client with an embedder-owned socket. Does not
   * destroy context state — use {@link closeContext} for that.
   */
  disconnect(): void {
    this.#managedSocket?.close();
  }
}

// ---------------------------------------------------------------------------
// §5.4.5 outlet-streaming pure wrappers (the two operations a browser invoker
// can host — stateless scp-protocol predicates, mirroring the native bridges).
// ---------------------------------------------------------------------------

/**
 * Computes the §5.4.5 `caveatsBinding` (32 bytes) a browser invoker binds into
 * its outlet-stream open request. Deterministic SHA-256 over
 * `(ucanCid, requestId, invokerDid, estimatedChunkCount, effectiveCaveatsJcs)`.
 *
 * `effectiveCaveatsJcs` MUST be the RFC 8785 JCS encoding of the post-narrowing
 * caveats (this consumes those bytes as produced; it does not canonicalize).
 *
 * @throws {ValidationError} `SCP-VALID-7010` if `requestId` is not exactly 16 bytes.
 */
export function outletStreamComputeCaveatsBinding(
  ucanCid: Uint8Array,
  requestId: Uint8Array,
  invokerDid: string,
  estimatedChunkCount: number,
  effectiveCaveatsJcs: Uint8Array,
): Uint8Array {
  assertInitialized();
  return call(() =>
    wasmComputeCaveatsBinding(
      ucanCid,
      requestId,
      invokerDid,
      estimatedChunkCount,
      effectiveCaveatsJcs,
    ),
  );
}

/**
 * Verifies an outlet-stream chunk's operator signature (§5.4.5). Returns `true`
 * iff the signature is valid; a valid chunk that fails verification returns
 * `false` (a verification RESULT, not an error). `chunk` is the JSON-serialized
 * `OutletStreamChunk`; `operatorPk` and `caveatsBinding` are 32-byte values.
 *
 * @throws {ValidationError} `SCP-VALID-7010` on malformed input (unparseable
 *   chunk, a non-32-byte or non-Ed25519 `operatorPk`, a non-32-byte `caveatsBinding`).
 */
export function outletStreamVerifyChunkSignature(
  chunk: Uint8Array,
  operatorPk: Uint8Array,
  contextId: string,
  outletId: string,
  caveatsBinding: Uint8Array,
): boolean {
  assertInitialized();
  return call(() =>
    wasmVerifyChunkSignature(chunk, operatorPk, contextId, outletId, caveatsBinding),
  );
}
