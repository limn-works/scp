/**
 * Server-side SDK wrappers for relay and application node lifecycle.
 *
 * Provides {@link Relay} and {@link Node} classes that wrap the napi-rs
 * bridge functions `relayStartInMemory` / `relayStartLocal` and
 * `nodeStartInMemory` / `nodeStartLocal`.
 *
 * Both classes implement `AsyncDisposable` for `await using` automatic
 * cleanup:
 *
 * ```typescript
 * await using relay = await Relay.startInMemory();
 * console.log(relay.relayUrl);
 *
 * await using node = await Node.startInMemory();
 * console.log(node.relayUrl, node.did);
 * ```
 *
 * Server operations are native-only (Bun/Node.js). Not available for
 * WASM (ADR-034).
 *
 * @packageDocumentation
 */

import { createRequire } from "node:module";
import { TransportError } from "./errors";

// ---------------------------------------------------------------------------
// Native addon access — server operations bypass the Bridge interface
// ---------------------------------------------------------------------------

/** Shape of the napi-rs relay handle returned by the native addon. */
interface NativeRelayHandle {
  readonly relayUrl: string;
  readonly relayPort: number;
  readonly isShutdown: boolean;
  shutdown(): void;
}

/** Shape of the napi-rs node handle returned by the native addon. */
interface NativeNodeHandle {
  readonly relayUrl: string;
  readonly relayPort: number;
  readonly did: string;
  readonly isShutdown: boolean;
  shutdown(): void;
}

/** Typed subset of the native addon for server operations. */
interface ServerAddon {
  relayStartInMemory(): Promise<NativeRelayHandle>;
  relayStartLocal(dataDir: string): Promise<NativeRelayHandle>;
  nodeStartInMemory(): Promise<NativeNodeHandle>;
  nodeStartLocal(dataDir: string): Promise<NativeNodeHandle>;
  transportConnect(relayUrl: string): Promise<unknown>;
  configureLocalTransport(localDid: string): void;
}

/**
 * Resolves the platform-specific napi package name.
 *
 * Uses the same hardcoded map as `internal/native.ts` to correctly handle
 * Windows (`-msvc`) and Linux (`-gnu`) suffixes.
 */
function resolveNapiPackage(): string {
  const platform = process.platform;
  const arch = process.arch;

  const platformMap: Record<string, string> = {
    "linux-x64": "@limn-works/scp-ts-napi-linux-x64-gnu",
    "linux-arm64": "@limn-works/scp-ts-napi-linux-arm64-gnu",
    "darwin-x64": "@limn-works/scp-ts-napi-darwin-x64",
    "darwin-arm64": "@limn-works/scp-ts-napi-darwin-arm64",
    "win32-x64": "@limn-works/scp-ts-napi-win32-x64-msvc",
  };

  const key = `${platform}-${arch}`;
  const pkg = platformMap[key];

  if (pkg === undefined) {
    throw new TransportError(
      `No native addon available for platform ${key}. ` +
        "Install the appropriate @limn-works/scp-ts-napi-* package or use the WASM bridge in a browser environment.",
      "SCP-TRANS-5001",
    );
  }

  return pkg;
}

/** Cached addon instance. */
let _addon: ServerAddon | null = null;

function loadServerAddon(): ServerAddon {
  if (_addon !== null) return _addon;

  const packageName = resolveNapiPackage();
  try {
    const req = createRequire(import.meta.url);
    _addon = req(packageName) as ServerAddon;
    return _addon;
  } catch {
    throw new TransportError(
      `Failed to load native addon ${packageName}. ` +
        `Ensure the package is installed: bun add ${packageName}`,
      "SCP-TRANS-5001",
    );
  }
}

// ---------------------------------------------------------------------------
// Relay
// ---------------------------------------------------------------------------

/**
 * Opaque handle to a running SCP relay server.
 *
 * Use the static factory methods {@link Relay.startInMemory} or
 * {@link Relay.startLocal} to create an instance. Call {@link Relay.shutdown}
 * to stop the relay, or use `await using` for automatic cleanup.
 */
export class Relay implements AsyncDisposable {
  readonly #handle: NativeRelayHandle;

  private constructor(handle: NativeRelayHandle) {
    this.#handle = handle;
  }

  /** The WebSocket URL clients should connect to (e.g. `ws://127.0.0.1:PORT/scp/v1`). */
  get relayUrl(): string {
    return this.#handle.relayUrl;
  }

  /** The port the relay is listening on. */
  get relayPort(): number {
    return this.#handle.relayPort;
  }

  /** `true` if {@link shutdown} has already been called. */
  get isShutdown(): boolean {
    return this.#handle.isShutdown;
  }

  /**
   * Start a relay with in-memory blob storage on an OS-assigned port.
   *
   * @returns A `Relay` whose {@link relayUrl} property contains the
   * WebSocket URL for clients.
   */
  static async startInMemory(): Promise<Relay> {
    const addon = loadServerAddon();
    const handle = await addon.relayStartInMemory();
    return new Relay(handle);
  }

  /**
   * Start a relay with redb-backed blob storage on an OS-assigned port.
   *
   * Opens (or creates) a redb database at `<dataDir>/blobs.redb`.
   *
   * @param dataDir - Directory for persistent blob storage.
   */
  static async startLocal(dataDir: string): Promise<Relay> {
    const addon = loadServerAddon();
    const handle = await addon.relayStartLocal(dataDir);
    return new Relay(handle);
  }

  /**
   * Signal the relay to stop accepting new connections.
   *
   * In-flight connection handlers drain naturally. Idempotent.
   */
  async shutdown(): Promise<void> {
    this.#handle.shutdown();
  }

  /** `AsyncDisposable` support for `await using`. */
  async [Symbol.asyncDispose](): Promise<void> {
    await this.shutdown();
  }
}

// ---------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------

/**
 * Opaque handle to a running SCP application node.
 *
 * An application node includes a running relay server, a generated DID
 * identity, and (optionally) persistent storage. Use the static factory
 * methods {@link Node.startInMemory} or {@link Node.startLocal} to create
 * an instance.
 */
export class Node implements AsyncDisposable {
  readonly #handle: NativeNodeHandle;

  private constructor(handle: NativeNodeHandle) {
    this.#handle = handle;
  }

  /** The WebSocket URL for this node's relay (e.g. `ws://127.0.0.1:PORT/scp/v1`). */
  get relayUrl(): string {
    return this.#handle.relayUrl;
  }

  /** The port the node's relay is listening on. */
  get relayPort(): number {
    return this.#handle.relayPort;
  }

  /** The node's DID string (e.g. `did:dht:z6Mk...`). */
  get did(): string {
    return this.#handle.did;
  }

  /** `true` if {@link shutdown} has already been called. */
  get isShutdown(): boolean {
    return this.#handle.isShutdown;
  }

  /**
   * Start a full application node with in-memory storage.
   *
   * Auto-wires in-memory key custody, in-memory storage, in-memory DHT
   * client, self-signed TLS, and a relay on an OS-assigned port.
   */
  static async startInMemory(): Promise<Node> {
    const addon = loadServerAddon();
    const handle = await addon.nodeStartInMemory();
    return new Node(handle);
  }

  /**
   * Start a full application node with file-backed storage.
   *
   * Opens (or creates) persistent storage at `<dataDir>/storage/` and a
   * redb blob database at `<dataDir>/blobs.redb`.
   *
   * @param dataDir - Directory for persistent storage.
   */
  static async startLocal(dataDir: string): Promise<Node> {
    const addon = loadServerAddon();
    const handle = await addon.nodeStartLocal(dataDir);
    return new Node(handle);
  }

  /**
   * Signal the node to stop (relay + background tasks).
   *
   * In-flight connection handlers drain naturally. Idempotent.
   */
  async shutdown(): Promise<void> {
    this.#handle.shutdown();
  }

  /** `AsyncDisposable` support for `await using`. */
  async [Symbol.asyncDispose](): Promise<void> {
    await this.shutdown();
  }
}

// ---------------------------------------------------------------------------
// Transport helper for local relays
// ---------------------------------------------------------------------------

/**
 * Connects the SDK transport layer to a local relay.
 *
 * Unlike {@link Transport.connect}, this function accepts plaintext `ws://`
 * URLs because local relays (started via {@link Relay.startInMemory} or
 * {@link Node.startInMemory}) bind to `127.0.0.1` without TLS.
 *
 * @param relayUrl - The WebSocket URL of the relay (e.g. `ws://127.0.0.1:PORT/scp/v1`).
 */
export async function connectLocalTransport(relayUrl: string): Promise<void> {
  const addon = loadServerAddon();
  await addon.transportConnect(relayUrl);
}

// ---------------------------------------------------------------------------
// Local transport configuration (test helper)
// ---------------------------------------------------------------------------

/**
 * Pre-configures the SDK's `ContextManager` with `LocalTransportProvider`.
 *
 * With this provider, `contextSend` and `broadcastPublish` succeed locally
 * without a running relay server. The encrypted-and-signed pipeline still
 * executes in full (MLS group encryption, sender key signing, inner envelope
 * construction); only the final relay publish step is stubbed.
 *
 * **Must be called before any `identityCreate` followed by `contextCreate`.**
 * The `ContextManager` is initialized once per process (`OnceLock`), so the
 * first initialization call wins. If `configureLocalTransport` is called
 * after a `contextCreate`, the call is a no-op and the transport provider
 * remains `NotConfiguredTransportProvider`.
 *
 * @param localDid - A valid `did:dht:` DID string used as the MLS credential
 * identity. Typically the DID of the first identity created in the test.
 */
export function configureLocalTransport(localDid: string): void {
  const addon = loadServerAddon();
  addon.configureLocalTransport(localDid);
}
