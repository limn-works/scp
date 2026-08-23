/**
 * Server-side SDK wrappers for relay and application node lifecycle.
 *
 * After Phase 4 PR 4 (#1549, ADR-048) Agent B1, {@link Relay} and
 * {@link Node} collapse to pure handle wrappers. The static factory
 * methods (`startInMemory` / `startLocal`) were deleted — callers
 * construct relays and nodes via the {@link SCP} class directly
 * (`scp.relayStartInMemory()`, `scp.relayStartLocal(dir)`,
 * `scp.nodeStartInMemory(identity?)`, `scp.nodeStartLocal(dir, identity?, passphrase?)`),
 * which internally calls `_fromHandle` to hydrate these wrappers.
 *
 * The handle-level methods remain: shutdown, serve, httpUrl,
 * enableSiteProjection, commitDeploy, rollbackDeploy,
 * disableSiteProjection — NAPI exposes all of those on the raw handle,
 * so they continue to work without going back through an `SCP`.
 *
 * Server operations require the native addon (Bun/Node.js).
 *
 * @packageDocumentation
 */

import type { SCP } from "./scp";
import type { SiteConfig } from "./types";
import { validateAdmission, validateBroadcastKeyHex, validateSiteConfig } from "./types";

// ---------------------------------------------------------------------------
// Native handle shapes
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

// ---------------------------------------------------------------------------
// Relay
// ---------------------------------------------------------------------------

/**
 * Opaque handle to a running SCP relay server.
 *
 * Construct via `scp.relayStartInMemory()` or `scp.relayStartLocal(dir)`;
 * those methods dispatch through the {@link SCP} class and call
 * `_fromHandle` to hydrate an instance. Call {@link Relay.shutdown} to
 * stop the relay, or use `await using` for automatic cleanup.
 */
export class Relay implements AsyncDisposable {
  readonly #handle: NativeRelayHandle;

  private constructor(handle: NativeRelayHandle) {
    this.#handle = handle;
  }

  /**
   * Constructs a `Relay` from a raw native NAPI relay handle.
   *
   * @param _scp Retained for API symmetry with the other `_fromHandle`
   *   statics — the relay is self-contained so the caller-owned `SCP`
   *   does not need to be stored here.
   *
   * @internal Phase 4 PR 4 (#1549, ADR-048).
   */
  static _fromHandle(raw: unknown, _scp: SCP): Relay {
    return new Relay(raw as NativeRelayHandle);
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
 * identity, and (optionally) persistent storage. Construct via
 * `scp.nodeStartInMemory(identity?)` or
 * `scp.nodeStartLocal(dir, identity?, passphrase?)`; those methods
 * dispatch through the {@link SCP} class and call `_fromHandle` to
 * hydrate an instance.
 */
export class Node implements AsyncDisposable {
  readonly #handle: NativeNodeHandle;

  private constructor(handle: NativeNodeHandle) {
    this.#handle = handle;
  }

  /**
   * Constructs a `Node` from a raw native NAPI node handle.
   *
   * @param _scp Retained for API symmetry with the other `_fromHandle`
   *   statics.
   *
   * @internal Phase 4 PR 4 (#1549, ADR-048).
   */
  static _fromHandle(raw: unknown, _scp: SCP): Node {
    return new Node(raw as NativeNodeHandle);
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
