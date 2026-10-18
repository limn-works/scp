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

import { StorageError, ValidationError } from "./errors";
import { Identity } from "./identity";
import type { SCP } from "./scp";
import type { SiteConfig } from "./types";
import { validateAdmission, validateBroadcastKeyHex, validateSiteConfig } from "./types";

// ---------------------------------------------------------------------------
// NodeStartConfig (construction.md §"Node start — NodeStartConfig", ADR-052)
// ---------------------------------------------------------------------------

/**
 * The code `nodeStart` returns for an invalid configuration (sdk-common.md
 * §"Node start error codes"). The SDK throws it for a config it cannot
 * encode, as the bridge does for a config it cannot read.
 */
export const NODE_START_INVALID_CONFIG_CODE = "SCP-STORAGE-8007";

/**
 * How the node is reached. `domain` is a DNS name the operator controls,
 * without a scheme, port or path. The bridge omits the core's `Tunnel` arm,
 * because the core does not thread its `public_url` into the published relay
 * URL.
 */
export type Reach =
  | { readonly kind: "domain"; readonly domain: string }
  | { readonly kind: "nat_traversal" }
  | { readonly kind: "local" };

/**
 * The relay's blob storage backend. `in_memory` is durability-only: the
 * node's blobs die with it (spec §17.17). `redb` and `sqlite` name a database
 * file whose parent directory `nodeStart` creates. S3 and Postgres are not
 * exposed.
 */
export type BlobBackend =
  | { readonly kind: "in_memory" }
  | { readonly kind: "redb"; readonly path: string }
  | { readonly kind: "sqlite"; readonly path: string };

/**
 * TLS selection. `acme`'s `email` is the ACME account contact; an absent or
 * `null` email selects headless ACME. The bridge rejects `plaintext` with a
 * `domain` reach. The core's `Custom` arm carries a trait object and is not
 * exposed.
 */
export type TlsMode =
  | { readonly kind: "self_signed" }
  | { readonly kind: "acme"; readonly email?: string | null }
  | { readonly kind: "plaintext" }
  | { readonly kind: "terminated" };

/**
 * DID-document publication. `disabled` is the only arm: the node runs its
 * relay and publishes no DID document (keri's scope ruling of 2026-10-13).
 */
export type DhtMode = { readonly kind: "disabled" };

/**
 * CORS origins for the node's public endpoints. `any_origin` allows every
 * origin (`*`) only because the caller names it; `allowlist` allows exactly
 * `origins`, such as `["https://app.example.org"]`.
 */
export type CorsOrigins =
  | { readonly kind: "any_origin" }
  | { readonly kind: "allowlist"; readonly origins: readonly string[] };

/**
 * NAT strategy. The core's `Custom` and `Tuned` arms carry trait objects and
 * are not exposed.
 */
export type Nat = { readonly kind: "auto" };

/**
 * The flat config {@link SCP.nodeStart} starts a production node from
 * (construction.md §"Node start — `NodeStartConfig`", ADR-052).
 *
 * Every field the bridge requires is required here, and the SDK supplies no
 * default for any of them. The config has no storage field: the node runs on
 * the `SCP` instance's own storage (spec §17.6), and an in-memory instance
 * store loses all node state when the node drops.
 *
 * Two error rules apply before the bridge runs. A value that is not a config
 * object, or an `identity` that is not an {@link Identity} this SDK returned,
 * throws {@link ValidationError} `SCP-VALID-7005`. A missing required field, a
 * key the config does not define, a sum-typed field holding a value outside
 * its arms, or a field of the wrong type throws {@link StorageError}
 * `SCP-STORAGE-8007`, the code the bridge returns for a malformed config.
 */
export interface NodeStartConfig {
  /** How the node is reached. */
  readonly reach: Reach;
  /**
   * The operator {@link Identity}, already created on the same `SCP`
   * instance; the bridge receives its DID and checks the handle under
   * ADR-048. Nodes have no identity of their own.
   */
  readonly identity: Identity;
  /** The relay's blob storage backend. */
  readonly blobStorage: BlobBackend;
  /** TLS selection. */
  readonly tls: TlsMode;
  /** DID-document publication; `{ kind: "disabled" }` is the only arm. */
  readonly dht: DhtMode;
  /**
   * CORS origins for the public endpoints. Required, because an absent list
   * would mean the permissive `*` origin.
   */
  readonly corsOrigins: CorsOrigins;
  /** Relay bind address such as `"127.0.0.1:0"`; absent binds `127.0.0.1:0`. */
  readonly bindAddr?: string | null;
  /** Public HTTP bind address; absent selects the core default. */
  readonly httpBindAddr?: string | null;
  /** NAT strategy; absent selects `{ kind: "auto" }`. */
  readonly nat?: Nat | null;
  /**
   * Per-IP rate limit for broadcast projection endpoints, an integer greater
   * than 0; absent selects the core default.
   */
  readonly projectionRateLimit?: number | null;
}

/** The value type of one arm field on the wire. */
type ArmFieldType = "string" | "optional_string" | "string_list";

/** The {@link ArmFieldType} of property `V` of an arm type. */
type ArmFieldTypeOf<V> = V extends readonly string[]
  ? "string_list"
  : undefined extends V
    ? "optional_string"
    : "string";

/**
 * The lowering table of union `U`: one entry per `kind`, each naming every
 * field of that arm with its wire type. An arm, kind or field `U` lacks fails
 * to compile, as does one the table omits.
 */
type ArmTable<U extends { readonly kind: string }> = {
  readonly [K in U["kind"]]: {
    readonly [F in Exclude<keyof Extract<U, { readonly kind: K }>, "kind">]-?: ArmFieldTypeOf<
      Extract<U, { readonly kind: K }>[F]
    >;
  };
};

/**
 * Every arm of every sum-typed field, keyed by the field's wire name and then
 * by the arm's `kind`, with each arm field's wire type. The type is derived
 * from the TS unions, so this table and the unions cannot differ, and the
 * lowering rejects an arm or arm field the table lacks.
 *
 * @internal Read by the wire-shape tests against the bridge fixture.
 */
export const NODE_START_ARMS: {
  readonly reach: ArmTable<Reach>;
  readonly blob_storage: ArmTable<BlobBackend>;
  readonly tls: ArmTable<TlsMode>;
  readonly dht: ArmTable<DhtMode>;
  readonly cors_origins: ArmTable<CorsOrigins>;
  readonly nat: ArmTable<Nat>;
} = {
  reach: { domain: { domain: "string" }, nat_traversal: {}, local: {} },
  blob_storage: { in_memory: {}, redb: { path: "string" }, sqlite: { path: "string" } },
  tls: { self_signed: {}, acme: { email: "optional_string" }, plaintext: {}, terminated: {} },
  dht: { disabled: {} },
  cors_origins: { any_origin: {}, allowlist: { origins: "string_list" } },
  nat: { auto: {} },
};

/** The value type of one top-level field on the wire. */
type FieldType = "identity" | "arm" | "string" | "u32";

/**
 * One top-level field: its {@link NodeStartConfig} property, its wire name,
 * its value type, and whether the bridge reads it as optional.
 */
interface FieldSpec {
  readonly key: keyof NodeStartConfig;
  readonly wire: string;
  readonly type: FieldType;
  readonly optional: boolean;
}

/**
 * The lowering spec of each {@link NodeStartConfig} property. `optional` is
 * typed from the interface, so a property the interface makes optional
 * cannot be lowered as required, or the reverse.
 */
const FIELD_SPECS: {
  readonly [K in keyof NodeStartConfig]-?: {
    readonly wire: string;
    readonly type: FieldType;
    readonly optional: undefined extends NodeStartConfig[K] ? true : false;
  };
} = {
  reach: { wire: "reach", type: "arm", optional: false },
  identity: { wire: "identity", type: "identity", optional: false },
  blobStorage: { wire: "blob_storage", type: "arm", optional: false },
  tls: { wire: "tls", type: "arm", optional: false },
  dht: { wire: "dht", type: "arm", optional: false },
  corsOrigins: { wire: "cors_origins", type: "arm", optional: false },
  bindAddr: { wire: "bind_addr", type: "string", optional: true },
  httpBindAddr: { wire: "http_bind_addr", type: "string", optional: true },
  nat: { wire: "nat", type: "arm", optional: true },
  projectionRateLimit: { wire: "projection_rate_limit", type: "u32", optional: true },
};

/**
 * The bridge's `NodeStartConfig` fields in declaration order.
 *
 * @internal Read by the wire-shape tests against the bridge fixture.
 */
export const NODE_START_FIELDS: readonly FieldSpec[] = (
  Object.keys(FIELD_SPECS) as (keyof NodeStartConfig)[]
).map((key) => ({ key, ...FIELD_SPECS[key] }));

function invalidConfig(message: string): StorageError {
  return new StorageError(message, NODE_START_INVALID_CONFIG_CODE);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Lowers one arm field, or throws `SCP-STORAGE-8007`. */
function lowerArmField(label: string, type: ArmFieldType, value: unknown): unknown {
  switch (type) {
    case "string":
      if (typeof value === "string") return value;
      break;
    case "optional_string":
      if (value === undefined || value === null) return null;
      if (typeof value === "string") return value;
      break;
    case "string_list":
      if (Array.isArray(value) && value.every((v) => typeof v === "string")) return [...value];
      break;
  }
  throw invalidConfig(`${label} must be a ${type.replace("_", " ")}`);
}

/**
 * Lowers one sum-typed field to `{ kind, ...fields }` in the table's field
 * order, or throws `SCP-STORAGE-8007` for a value outside its arms.
 */
function lowerArm(field: FieldSpec, value: unknown): Record<string, unknown> {
  const arms: Readonly<Record<string, Readonly<Record<string, ArmFieldType>>>> =
    (NODE_START_ARMS as Readonly<Record<string, typeof arms>>)[field.wire] ?? {};
  const label = `NodeStartConfig.${field.key}`;
  const kinds = Object.keys(arms).join(", ");
  const kind = isRecord(value) ? value.kind : undefined;
  const fields = typeof kind === "string" && Object.hasOwn(arms, kind) ? arms[kind] : undefined;
  if (!isRecord(value) || typeof kind !== "string" || fields === undefined) {
    throw invalidConfig(`${label} must be an object whose kind is one of ${kinds}`);
  }
  for (const key of Object.keys(value)) {
    if (key !== "kind" && !Object.hasOwn(fields, key)) {
      throw invalidConfig(`${label} (kind "${kind}") has no field ${key}`);
    }
  }
  const wire: Record<string, unknown> = { kind };
  for (const [name, type] of Object.entries(fields)) {
    wire[name] = lowerArmField(`${label}.${name}`, type, value[name]);
  }
  return wire;
}

/** Lowers one present top-level field that is not `identity`. */
function lowerField(field: FieldSpec, value: unknown): unknown {
  const label = `NodeStartConfig.${field.key}`;
  switch (field.type) {
    case "arm":
      return lowerArm(field, value);
    case "string":
      if (typeof value === "string") return value;
      throw invalidConfig(`${label} must be a string`);
    case "u32":
      if (
        typeof value === "number" &&
        Number.isInteger(value) &&
        value >= 0 &&
        value <= 0xffffffff
      ) {
        return value;
      }
      throw invalidConfig(`${label} must be an integer from 0 to 4294967295`);
    case "identity":
      throw invalidConfig(`${label} is lowered separately`);
  }
}

/**
 * Returns the object the bridge's `NodeStartConfig::from_json` reads: every
 * field under its wire name and in declaration order, `identity` lowered to
 * its DID, and an absent optional as `null`, which the bridge reads as
 * absent.
 *
 * @throws {ValidationError} `SCP-VALID-7005` when `config` is not an object
 *   or its `identity` is not an {@link Identity} this SDK returned. This
 *   check runs before any other.
 * @throws {StorageError} `SCP-STORAGE-8007` when a required field is absent,
 *   a key is not a config field, or a field holds a value outside its type.
 * @internal Called by {@link SCP.nodeStart}, and by the wire-shape tests.
 */
export function nodeStartConfigToWire(config: unknown): Record<string, unknown> {
  if (!isRecord(config)) {
    throw new ValidationError(
      "SCP.nodeStart() config must be a NodeStartConfig object",
      "SCP-VALID-7005",
    );
  }
  const identity = config.identity;
  if (!Identity._isIdentity(identity)) {
    throw new ValidationError(
      "NodeStartConfig.identity must be an Identity this SDK returned",
      "SCP-VALID-7005",
    );
  }
  const known = new Set<string>(NODE_START_FIELDS.map((f) => f.key));
  for (const key of Object.keys(config)) {
    if (!known.has(key)) throw invalidConfig(`NodeStartConfig has no field ${key}`);
  }
  const wire: Record<string, unknown> = {};
  for (const field of NODE_START_FIELDS) {
    const value = config[field.key];
    if (field.type === "identity") {
      wire[field.wire] = identity.did;
    } else if (value === undefined || value === null) {
      if (!field.optional) throw invalidConfig(`NodeStartConfig.${field.key} is required`);
      wire[field.wire] = null;
    } else {
      wire[field.wire] = lowerField(field, value);
    }
  }
  return wire;
}

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
 * An application node includes a running relay server and runs under an
 * operator identity. Construct a production node with
 * `scp.nodeStart(config)` ({@link NodeStartConfig}), or a development node
 * with `scp.nodeStartInMemory(identity?)` or
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
