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
import { __defaultScpForInternalUse, __getNativeScp, type SCP } from "./scp";
import type { SiteConfig } from "./types";
import { validateAdmission, validateBroadcastKeyHex, validateSiteConfig } from "./types";

// ---------------------------------------------------------------------------
// Native addon access — server operations bypass the Bridge interface
//
// Since ADR-048 (#1549 Phase 4 PR 4), relay/node factories dispatch
// through an `SCP` instance's class methods when one is supplied.
// Callers that omit the `scp` argument fall back to the shared
// process-wide default instance, which preserves legacy behavior.
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
  serve(bindAddr: string | null): Promise<string>;
  httpUrl(): Promise<string | null>;
  enableSiteProjection(
    contextId: string,
    admission: string,
    hostname: string,
    broadcastKeyHex: string | null,
    authorDid: string | null,
    indexPath: string | null,
    maxAssetsPerDeploy: number | null,
    maxDeploySizeBytes: number | null,
    deployRetentionCount: number | null,
    cspOverride: string | null,
  ): Promise<void>;
  commitDeploy(contextId: string, deployId: string): Promise<number>;
  rollbackDeploy(contextId: string, deployId: string): Promise<void>;
  disableSiteProjection(contextId: string): Promise<void>;
}

/** Typed subset of the native addon for server operations. */
interface ServerAddon {
  relayStartInMemory(): Promise<NativeRelayHandle>;
  relayStartLocal(dataDir: string): Promise<NativeRelayHandle>;
  nodeStartInMemory(identityDid: string | null): Promise<NativeNodeHandle>;
  nodeStartLocal(
    dataDir: string,
    identityDid: string | null,
    passphrase: string | null,
  ): Promise<NativeNodeHandle>;
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

  if (typeof process === "undefined" || typeof process.platform !== "string") {
    throw new TransportError("Server operations not available in browser/WASM", "SCP-TRANS-5002");
  }

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

/**
 * Returns a {@link ServerAddon} view backed by the given {@link SCP}
 * instance's class methods (ADR-048). Methods that have not yet been
 * ported onto the `Scp` class fall back to module-level free
 * functions.
 *
 * When `scp` is omitted, the shared process-wide default instance is
 * used — matching the legacy free-function façade behavior.
 */
function serverApi(scp?: SCP): ServerAddon {
  // Ensure the native addon is actually installed / loadable before we
  // extract `Scp` class method references — `loadServerAddon` throws
  // the same descriptive `TransportError` on failure, so the error
  // surface remains identical to the pre-ADR-048 path.
  loadServerAddon();
  const instance = scp ?? __defaultScpForInternalUse();
  // Type-erased native handle — every `Scp` class method shares the
  // `async (...args) => unknown` shape after FFI monomorphization.
  const native = __getNativeScp(instance) as unknown as Record<
    string,
    (...args: never[]) => unknown
  >;

  return {
    relayStartInMemory: native.relayStartInMemory as ServerAddon["relayStartInMemory"],
    relayStartLocal: native.relayStartLocal as ServerAddon["relayStartLocal"],
    nodeStartInMemory: native.nodeStartInMemory as ServerAddon["nodeStartInMemory"],
    nodeStartLocal: native.nodeStartLocal as ServerAddon["nodeStartLocal"],
    transportConnect: native.transportConnect as ServerAddon["transportConnect"],
    configureLocalTransport:
      native.configureLocalTransport as ServerAddon["configureLocalTransport"],
  };
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
   * @param scp Optional {@link SCP} wrapper whose bridge instance should
   *   own the relay. Defaults to the shared process-wide default
   *   instance when omitted (ADR-048).
   * @returns A `Relay` whose {@link relayUrl} property contains the
   * WebSocket URL for clients.
   */
  static async startInMemory(scp?: SCP): Promise<Relay> {
    const api = serverApi(scp);
    const handle = await api.relayStartInMemory();
    return new Relay(handle);
  }

  /**
   * Start a relay with redb-backed blob storage on an OS-assigned port.
   *
   * Opens (or creates) a redb database at `<dataDir>/blobs.redb`.
   *
   * @param dataDir - Directory for persistent blob storage.
   * @param scp Optional {@link SCP} wrapper whose bridge instance should
   *   own the relay. Defaults to the shared process-wide default
   *   instance when omitted (ADR-048).
   */
  static async startLocal(dataDir: string, scp?: SCP): Promise<Relay> {
    const api = serverApi(scp);
    const handle = await api.relayStartLocal(dataDir);
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
   *
   * When `identity` is provided, the node uses the pre-existing identity
   * (created via `identityCreate`) instead of generating a fresh one. This
   * enables identity portability -- the same DID persists across node
   * restarts. The `ContextManager` is also auto-initialized with the
   * node's relay as transport.
   *
   * Accepts any object with a `did` property (including the `Identity`
   * class from `identityCreate`), keeping the server module decoupled.
   *
   * @param identity - Optional identity object with a `.did` property.
   * @param scp - Optional {@link SCP} wrapper whose bridge instance
   *   should own the node. Defaults to the shared process-wide default
   *   instance when omitted (ADR-048).
   */
  static async startInMemory(identity?: { did: string }, scp?: SCP): Promise<Node> {
    const api = serverApi(scp);
    const handle = await api.nodeStartInMemory(identity?.did ?? null);
    return new Node(handle);
  }

  /**
   * Start a full application node with file-backed storage.
   *
   * Opens (or creates) persistent storage at `<dataDir>/storage/` and a
   * redb blob database at `<dataDir>/blobs.redb`.
   *
   * When `identity` is provided, the node uses the pre-existing identity
   * instead of generating a fresh one. When omitted, the node creates or
   * reloads a persistent identity via `FileKeyCustody`. The `passphrase`
   * parameter is required in this mode.
   *
   * No passphrase is required when `identity` is provided.
   *
   * @param dataDir - Directory for persistent storage.
   * @param identity - Optional identity object with a `.did` property.
   * @param passphrase - Passphrase for Argon2id key derivation. Required when
   *   identity is omitted.
   * @param scp - Optional {@link SCP} wrapper whose bridge instance
   *   should own the node. Defaults to the shared process-wide default
   *   instance when omitted (ADR-048).
   */
  static async startLocal(
    dataDir: string,
    identity?: { did: string },
    passphrase?: string,
    scp?: SCP,
  ): Promise<Node> {
    const api = serverApi(scp);
    const handle = await api.nodeStartLocal(dataDir, identity?.did ?? null, passphrase ?? null);
    return new Node(handle);
  }

  /**
   * Start the HTTP server in the background.
   *
   * Defaults to `127.0.0.1:8443` (loopback only) when `bindAddr` is not
   * provided. Pass `"0.0.0.0:PORT"` for network access.
   *
   * Returns the actual bound address as a raw string (e.g. `"127.0.0.1:8443"`).
   * Use {@link httpUrl} for the full URL form (`"http://127.0.0.1:8443"`).
   *
   * **Note:** The background server does not support TLS. For production
   * deployments requiring encryption, use the node binary's `serve()` with
   * TLS configuration.
   *
   * @param bindAddr - Socket address to bind (e.g. `"127.0.0.1:8080"`).
   * @returns The actual bound address as a string.
   * @throws {Error} If the server is already running or binding fails.
   */
  async serve(bindAddr?: string): Promise<string> {
    return this.#handle.serve(bindAddr ?? null);
  }

  /**
   * The HTTP URL of the background server, or `null` if not serving.
   *
   * Returns the literal bind address, which may contain `0.0.0.0` if the
   * server was bound to the unspecified address.
   */
  async httpUrl(): Promise<string | null> {
    return this.#handle.httpUrl();
  }

  // -------------------------------------------------------------------------
  // Broadcast deployment lifecycle (SCP-296, spec section 18.11.8)
  // -------------------------------------------------------------------------

  /**
   * Activate HTTP broadcast projection for a context.
   *
   * Three resolution modes:
   * 1. Both `broadcastKeyHex` **and** `authorDid` provided -- uses the
   *    explicit key with epoch 0.
   * 2. Only `authorDid` provided -- auto-resolves the broadcast key
   *    using that DID (useful when the author identity differs from the
   *    node identity).
   * 3. Neither provided -- auto-resolves using the node's identity DID.
   *
   * Providing `broadcastKeyHex` without `authorDid` is an error.
   *
   * @param contextId - The context ID to project.
   * @param admission - `"open"` or `"gated"`.
   * @param config - {@link SiteConfig} with hostname, index path, and deploy limits.
   * @param broadcastKeyHex - 32-byte AES-256 broadcast key as a 64-char hex string, or omit for auto-lookup.
   * @param authorDid - DID of the broadcast key owner, or omit for auto-lookup.
   * @throws {Error} If parameters are invalid.
   */
  async enableSiteProjection(
    contextId: string,
    admission: string,
    config: SiteConfig,
    broadcastKeyHex?: string,
    authorDid?: string,
  ): Promise<void> {
    validateAdmission(admission);
    if (broadcastKeyHex !== undefined && authorDid === undefined) {
      throw new Error(
        "broadcastKeyHex requires authorDid — provide the DID of the broadcast key owner, or omit both for auto-resolve",
      );
    }
    if (broadcastKeyHex !== undefined) {
      validateBroadcastKeyHex(broadcastKeyHex);
    }
    validateSiteConfig(config);
    await this.#handle.enableSiteProjection(
      contextId,
      admission,
      config.hostname,
      broadcastKeyHex ?? null,
      authorDid ?? null,
      config.indexPath ?? null,
      config.maxAssetsPerDeploy ?? null,
      config.maxDeploySizeBytes ?? null,
      config.deployRetentionCount ?? null,
      config.cspOverride ?? null,
    );
  }

  /**
   * Commit a deploy for a projected context (section 18.11.11).
   *
   * Scans blobs matching the `deployId`, decrypts each to extract metadata,
   * builds an immutable path index, and atomically swaps the serving pointer.
   *
   * @param contextId - The projected context ID.
   * @param deployId - The deploy identifier (hex, from publish).
   * @returns The number of assets in the committed deploy.
   * @throws {Error} If the context is not projected or commit fails.
   */
  async commitDeploy(contextId: string, deployId: string): Promise<number> {
    return this.#handle.commitDeploy(contextId, deployId);
  }

  /**
   * Roll back to a previous deploy for a projected context (section 18.11.11).
   *
   * Sets the path index pointer to a previous deploy within the retention window.
   *
   * @param contextId - The projected context ID.
   * @param deployId - The deploy identifier to roll back to.
   * @throws {Error} If the context is not projected or deploy not found.
   */
  async rollbackDeploy(contextId: string, deployId: string): Promise<void> {
    await this.#handle.rollbackDeploy(contextId, deployId);
  }

  /**
   * Deactivate HTTP broadcast projection for a context.
   *
   * Removes the projected context from the registry and drops all retained
   * epoch keys. Idempotent — calling on a non-projected context is a no-op.
   *
   * @param contextId - The context ID to stop projecting.
   */
  async disableSiteProjection(contextId: string): Promise<void> {
    await this.#handle.disableSiteProjection(contextId);
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
 * @param scp - Optional {@link SCP} wrapper whose bridge instance
 *   should own the transport. Defaults to the shared process-wide
 *   default instance when omitted (ADR-048).
 */
export async function connectLocalTransport(relayUrl: string, scp?: SCP): Promise<void> {
  const api = serverApi(scp);
  await api.transportConnect(relayUrl);
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
 * @param scp - Optional {@link SCP} wrapper whose bridge instance
 *   should be configured. Defaults to the shared process-wide default
 *   instance when omitted (ADR-048).
 */
export function configureLocalTransport(localDid: string, scp?: SCP): void {
  const api = serverApi(scp);
  api.configureLocalTransport(localDid);
}
