/**
 * Context module for the SCP TypeScript SDK.
 *
 * Provides the `Context` class for context lifecycle management: creation,
 * joining, leaving, closing, sending messages, and receiving messages via
 * `AsyncIterable<Message>`.
 *
 * `Context` implements `AsyncDisposable` via `Symbol.asyncDispose` for
 * automatic cleanup with `await using`.
 *
 * See ADR-022 in `.docs/adrs/phase-4.md` and `.docs/scaffold/typescript.md`.
 */

import { ContextError, mapBridgeError, ValidationError } from "./errors";
import type { Identity } from "./identity";
import type { BridgeContextHandle } from "./internal/bridge";
import { getBridge, getBridgeSync } from "./internal/bridge";
import { safeJsonParse } from "./internal/json-utils";
import type {
  AssetEntry,
  BatchPublishResult,
  BroadcastAdmissionPolicy,
  ContextParams,
  GovernanceActionResult,
  MemberRole,
  Message,
  PublishResult,
  ToolDefinition,
  ToolVerificationResult,
} from "./types";

// ---------------------------------------------------------------------------
// EconomicPolicy schema validation (§19.3, ADR-034)
// ---------------------------------------------------------------------------

/**
 * Validates that a JSON string conforms to the `EconomicPolicy` schema.
 *
 * Defense-in-depth for the WASM path: the WASM bridge can only validate
 * that the input is well-formed JSON (ADR-034 prevents importing scp-core
 * types). This function checks required fields and basic types so schema
 * violations are caught before crossing the FFI boundary.
 *
 * @throws {ValidationError} if the JSON is malformed or missing required fields.
 * @internal Exported as `_validateEconomicPolicyJson` for testing.
 */
export function _validateEconomicPolicyJson(json: string): void {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new ValidationError("invalid economic policy JSON: syntax error", "SCP-VALID-7001");
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new ValidationError("invalid economic policy JSON: expected an object", "SCP-VALID-7001");
  }

  const obj = parsed as Record<string, unknown>;

  if (typeof obj.locked !== "boolean") {
    throw new ValidationError(
      "invalid economic policy JSON: 'locked' must be a boolean",
      "SCP-VALID-7001",
    );
  }

  if (typeof obj.cost_schedule !== "object" || obj.cost_schedule === null) {
    throw new ValidationError(
      "invalid economic policy JSON: 'cost_schedule' must be an object",
      "SCP-VALID-7001",
    );
  }

  if (!Array.isArray(obj.payment_adapters)) {
    throw new ValidationError(
      "invalid economic policy JSON: 'payment_adapters' must be an array",
      "SCP-VALID-7001",
    );
  }

  if (typeof obj.payee !== "string") {
    throw new ValidationError(
      "invalid economic policy JSON: 'payee' must be a string",
      "SCP-VALID-7001",
    );
  }
}

// ---------------------------------------------------------------------------
// Client-side validation (SCP-297, spec §18.11.9)
// ---------------------------------------------------------------------------

/** Maximum content path length in bytes. */
const MAX_CONTENT_PATH_BYTES = 1024;

/** Maximum deploy ID length in bytes. */
const MAX_DEPLOY_ID_BYTES = 128;

/**
 * Returns true for Unicode formatting/invisible characters.
 * Mirrors the Rust `is_unicode_formatting` helper.
 */
function _isUnicodeFormatting(cp: number): boolean {
  return (
    cp === 0x00a0 || // NBSP
    cp === 0x1680 || // Ogham space mark
    (cp >= 0x2000 && cp <= 0x200f) || // Typographic spaces (2000-200A) + ZWSP..RLM (200B-200F)
    cp === 0x2028 ||
    cp === 0x2029 ||
    (cp >= 0x202a && cp <= 0x202f) || // Bidi embedding controls + narrow no-break space
    cp === 0x205f ||
    (cp >= 0x2060 && cp <= 0x206f) ||
    cp === 0x3000 ||
    cp === 0xfeff ||
    cp === 0xfffe ||
    cp === 0xffff
  );
}

/** RFC 7230 §3.2.6 tchar test (minus '%'). */
const TCHAR_RE = /^[a-zA-Z0-9!#$&'*+\-.^_`|~]+$/;

/** Forbidden substrings in content paths, paired with error messages. */
const _CONTENT_PATH_FORBIDDEN: [string, string][] = [
  ["\\", "ContentPath must not contain backslashes"],
  ["%", "ContentPath must not contain percent-encoded bytes"],
  ["?", "ContentPath must not contain query strings ('?')"],
  ["#", "ContentPath must not contain fragments ('#')"],
  ["\0", "ContentPath must not contain null bytes"],
  ["//", "ContentPath must not contain '//'"],
];

/** Formats a code point as a zero-padded uppercase hex string. */
function _cpHex(cp: number): string {
  return cp.toString(16).toUpperCase().padStart(4, "0");
}

/** Checks for forbidden substrings, control characters, and formatting chars. */
function _contentPathCharError(path: string): string | null {
  for (const [sub, msg] of _CONTENT_PATH_FORBIDDEN) {
    if (path.includes(sub)) return msg;
  }
  for (const ch of path) {
    const cp = ch.codePointAt(0) ?? 0;
    // C0 controls (U+0000-U+001F), DEL (U+007F), and C1 controls (U+0080-U+009F)
    if (cp <= 0x1f || cp === 0x7f || (cp >= 0x80 && cp <= 0x9f)) {
      return `ContentPath must not contain control character U+${_cpHex(cp)}`;
    }
  }
  for (const ch of path) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp > 0x7f && _isUnicodeFormatting(cp)) {
      return `ContentPath must not contain non-ASCII whitespace/formatting U+${_cpHex(cp)}`;
    }
  }
  return null;
}

/** Checks structural rules (prefix, length, trailing slash, segments). */
function _contentPathStructureError(path: string): string | null {
  if (!path.startsWith("/")) return "ContentPath must start with '/'";
  if (new TextEncoder().encode(path).length > MAX_CONTENT_PATH_BYTES) {
    return `ContentPath exceeds ${MAX_CONTENT_PATH_BYTES} bytes`;
  }
  if (path.length > 1 && path.endsWith("/")) {
    return "ContentPath must not have trailing slash (except root '/')";
  }
  for (const segment of path.split("/").slice(1)) {
    if (segment === ".") return "ContentPath must not contain '.' segments";
    if (segment === "..") return "ContentPath must not contain '..' segments (directory traversal)";
  }
  return null;
}

/**
 * Validates a content path before FFI crossing (SCP-297).
 *
 * Mirrors the Rust `ContentPath::new` validation from
 * `crates/scp-core/src/context/broadcast_content.rs`.
 *
 * @throws {ValidationError} If the path is invalid.
 * @internal Exported for testing.
 */
export function _validateContentPath(path: string): void {
  // NFC-normalize before validation
  const normalized = path.normalize("NFC");
  const error = _contentPathStructureError(normalized) ?? _contentPathCharError(normalized);
  if (error) throw new ValidationError(error, "SCP-VALID-7010");
}

/**
 * Validates a MIME type before FFI crossing (SCP-297).
 *
 * Mirrors the Rust `MimeType::new` validation from
 * `crates/scp-core/src/context/broadcast_content.rs`.
 *
 * @throws {ValidationError} If the MIME type is invalid.
 * @internal Exported for testing.
 */
export function _validateMimeType(contentType: string): void {
  if (!contentType) {
    throw new ValidationError("MimeType must not be empty", "SCP-VALID-7011");
  }
  for (const ch of contentType) {
    const cp = ch.codePointAt(0) ?? 0;
    // C0 controls (U+0000-U+001F), DEL (U+007F), and C1 controls (U+0080-U+009F)
    if (cp <= 0x1f || cp === 0x7f || (cp >= 0x80 && cp <= 0x9f)) {
      throw new ValidationError(
        `MimeType must not contain control character U+${cp.toString(16).toUpperCase().padStart(4, "0")}`,
        "SCP-VALID-7011",
      );
    }
  }
  if (contentType.includes(";")) {
    throw new ValidationError(
      "MimeType must not contain parameters (';' not allowed)",
      "SCP-VALID-7011",
    );
  }
  const slashCount = [...contentType].filter((c) => c === "/").length;
  if (slashCount !== 1) {
    throw new ValidationError(
      "MimeType must be 'type/subtype' (exactly one '/')",
      "SCP-VALID-7011",
    );
  }
  const [typePart, subtypePart] = contentType.split("/", 2);
  if (!typePart || !subtypePart) {
    throw new ValidationError("MimeType type and subtype must both be non-empty", "SCP-VALID-7011");
  }
  // RFC 7230 §3.2.6 tchar validation
  if (!TCHAR_RE.test(typePart)) {
    throw new ValidationError("MimeType type part contains invalid characters", "SCP-VALID-7011");
  }
  if (!TCHAR_RE.test(subtypePart)) {
    throw new ValidationError(
      "MimeType subtype part contains invalid characters",
      "SCP-VALID-7011",
    );
  }
}

/**
 * Validates a deploy ID before FFI crossing (SCP-297).
 *
 * Mirrors the Rust `validate_deploy_id` from
 * `crates/scp-core/src/context/broadcast_content.rs`.
 *
 * @throws {ValidationError} If the deploy ID is invalid.
 * @internal Exported for testing.
 */
export function _validateDeployId(deployId: string): void {
  if (!deployId) {
    throw new ValidationError("deploy_id must not be empty", "SCP-VALID-7012");
  }
  if (new TextEncoder().encode(deployId).length > MAX_DEPLOY_ID_BYTES) {
    throw new ValidationError(`deploy_id exceeds ${MAX_DEPLOY_ID_BYTES} bytes`, "SCP-VALID-7012");
  }
  if (!/^[a-zA-Z0-9\-_]+$/.test(deployId)) {
    throw new ValidationError(
      "deploy_id must be ASCII alphanumeric, '-', or '_'",
      "SCP-VALID-7012",
    );
  }
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

/**
 * An SCP context — a bounded, encrypted interaction space.
 *
 * Context objects are created via `Context.create()` and implement
 * `AsyncDisposable` for automatic cleanup:
 *
 * ```typescript
 * await using ctx = await Context.create(identity, {
 *   ceiling: ["messages:read", "messages:write"],
 *   memoryScope: "ephemeral",
 * });
 * await ctx.send("hello");
 * // ctx.leave() is called automatically on scope exit
 * ```
 *
 * Messages are received via the `receive()` generator, which returns an
 * `AsyncIterable<Message>`:
 *
 * ```typescript
 * for await (const msg of ctx.receive()) {
 *   console.log(msg.senderDid, msg.content);
 * }
 * ```
 */
export class Context implements AsyncDisposable {
  /** The unique identifier for this context. */
  readonly contextId: string;

  /** @internal Opaque bridge handle — not part of the public API. */
  readonly _handle: BridgeContextHandle;

  /** The DID of the identity that created/joined this context. */
  private readonly _identityDid: string;

  /** Whether this context has been left or closed. */
  private _disposed = false;

  private constructor(contextId: string, handle: BridgeContextHandle, identityDid: string) {
    this.contextId = contextId;
    this._handle = handle;
    this._identityDid = identityDid;
  }

  /**
   * Constructs a Context from an existing bridge handle.
   *
   * @internal Testing only — not part of the public API.
   */
  static _fromHandle(handle: BridgeContextHandle, identityDid: string): Context {
    return new Context(handle.contextId, handle, identityDid);
  }

  /**
   * Creates a new SCP context.
   *
   * The context is created in the `"active"` state. The creating identity
   * becomes the first member (and admin under `"single_admin"` governance).
   *
   * @param identity - The identity creating the context.
   * @param params - Context creation parameters.
   * @returns A new `Context` instance in the `"active"` state.
   * @throws {ContextError} If context creation fails.
   * @throws {ValidationError} If parameters are invalid.
   */
  static async create(identity: Identity, params: ContextParams): Promise<Context> {
    try {
      const bridge = await getBridge();
      const paramsJson = JSON.stringify({
        ceiling: params.ceiling,
        tools: params.tools,
        roles: params.roles,
        ttlSeconds: params.ttl,
        memoryScope: params.memoryScope,
        governance: params.governance ?? "single_admin",
        mode: params.mode ?? "Encrypted",
        ceilingPolicy: params.ceilingPolicy ?? "immutable",
        promotionPolicy: params.promotionPolicy,
        economicPolicy: params.economicPolicy,
      });

      const handle = await bridge.contextCreate(identity._handle, paramsJson);
      return new Context(handle.contextId, handle, identity.did);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Joins an existing context.
   *
   * @param identity - The identity joining the context.
   * @throws {ContextError} If the context is not in `"active"` state.
   */
  async join(identity: Identity): Promise<void> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      await bridge.contextJoin(this._handle, identity.did);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Sends a message to the context.
   *
   * Accepts either a string (encoded as UTF-8) or a `Uint8Array` payload.
   *
   * @param payload - The message content.
   * @throws {ContextError} If the context is not `"active"` or send fails.
   */
  async send(payload: string | Uint8Array): Promise<void> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      const bytes = typeof payload === "string" ? new TextEncoder().encode(payload) : payload;
      await bridge.contextSend(this._handle, this._identityDid, bytes);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Returns an `AsyncIterable<Message>` that yields incoming messages.
   *
   * Messages are delivered in sequence order. Calling `break` on the
   * `for await...of` loop stops delivery and releases internal resources.
   *
   * Each call to `receive()` returns an independent iterable (fan-out).
   *
   * ```typescript
   * for await (const msg of ctx.receive()) {
   *   console.log(msg.senderDid, msg.content);
   * }
   * ```
   */
  async *receive(): AsyncIterable<Message> {
    this.assertActive();

    const queue: Message[] = [];
    let resolve: (() => void) | null = null;
    let done = false;

    try {
      const bridge = await getBridge();
      bridge.contextSubscribe(this._handle, this._identityDid, {
        onMessage: (msg: Message) => {
          if (!done) {
            queue.push(msg);
            resolve?.();
            resolve = null;
          }
        },
        onComplete: () => {
          done = true;
          resolve?.();
          resolve = null;
        },
      });

      while (!done || queue.length > 0) {
        if (queue.length === 0) {
          await new Promise<void>((r) => {
            resolve = r;
          });
        }
        const msg = queue.shift();
        if (msg !== undefined) {
          yield msg;
        }
      }
    } finally {
      done = true;
      queue.length = 0;
    }
  }

  /**
   * Registers a tool in this context.
   *
   * @param definition - The tool definition.
   * @returns The assigned tool ID.
   * @throws {ToolError} If registration fails.
   */
  async registerTool(definition: ToolDefinition): Promise<string> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      return await bridge.toolRegister(this._handle, definition);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Invokes a tool within this context.
   *
   * @param toolId - The ID of the tool to invoke.
   * @param input - Tool input parameters.
   * @param identity - The invoking identity.
   * @param ucanToken - JWT-encoded UCAN token authorizing the invocation.
   *   Must contain `tool_invoke:{toolId}` or `tool_invoke:*` capability scoped
   *   to this context. Required per spec section 7.2: every capability-gated
   *   action requires a valid UCAN token. See also section 6.2, section 8,
   *   and ADR-016.
   * @returns The tool output as a parsed JSON object.
   * @throws {ToolError} If invocation fails or the tool is not found.
   * @throws {UcanPermissionError} If the UCAN token is invalid, expired,
   *   revoked, or lacks the required tool invocation capability.
   */
  async invokeTool(
    toolId: string,
    input: Readonly<Record<string, unknown>>,
    identity: Identity,
    ucanToken: string,
  ): Promise<unknown> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      const resultJson = await bridge.toolInvoke(
        this._handle,
        toolId,
        JSON.stringify(input),
        identity.did,
        ucanToken,
      );
      return safeJsonParse(resultJson, "toolInvoke") as unknown;
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Verifies a tool against its registered test vectors.
   *
   * @param toolId - The ID of the tool to verify.
   * @returns The verification result.
   * @throws {ToolError} If verification fails.
   */
  async verifyTool(toolId: string): Promise<ToolVerificationResult> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      return await bridge.toolVerify(this._handle, toolId);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  // ---------------------------------------------------------------------------
  // Bidirectional consent protocol (spec section 6.2.0.1)
  // ---------------------------------------------------------------------------

  /**
   * Exposes a tool interface for cross-context sharing (step 1).
   *
   * The caller (admin of the source context) proposes sharing a specific
   * tool with a target context. The returned JSON interface has
   * `approved_by_source = true` and `approved_by_target = false`.
   *
   * @param toolId - The ID of the tool to expose.
   * @param targetContextId - The target context to expose the tool to.
   * @param rateLimitJson - Optional per-interface rate limit as a JSON string.
   * @returns The ToolInterface as a JSON string.
   * @throws {ToolError} If the caller is not an admin or the tool is not found.
   */
  async exposeToolInterface(
    toolId: string,
    targetContextId: string,
    rateLimitJson?: string,
  ): Promise<string> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      return await bridge.toolInterfaceExpose(this._handle, toolId, targetContextId, rateLimitJson);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Accepts a cross-context tool interface (step 4).
   *
   * Sets `approved_by_target = true`. Both `approved_by_source` and
   * `approved_by_target` must be `true` before calls are permitted.
   *
   * @param interfaceJson - The ToolInterface JSON string to accept.
   * @returns The updated ToolInterface as a JSON string.
   * @throws {ToolError} If the caller is not an admin or context mismatch.
   */
  async acceptToolInterface(interfaceJson: string): Promise<string> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      return await bridge.toolInterfaceAccept(this._handle, interfaceJson);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Revokes a cross-context tool interface (step 5).
   *
   * Either context may revoke unilaterally.
   *
   * @param interfaceIdHex - The 32-byte interface/offer ID as a hex string.
   * @returns The InterfaceRevoked event as a JSON string.
   * @throws {ValidationError} If interfaceIdHex is invalid.
   */
  async revokeToolInterface(interfaceIdHex: string): Promise<string> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      return await bridge.toolInterfaceRevoke(this._handle, interfaceIdHex);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  // ---------------------------------------------------------------------------
  // Membership queries
  // ---------------------------------------------------------------------------

  /**
   * Returns the number of members in this context.
   *
   * @returns The member count, or `null` if the context is not registered.
   * @throws {ContextError} If the context has been disposed.
   */
  async memberCount(): Promise<number | null> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      return await bridge.contextMemberCount(this._handle);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Checks whether a DID is a member of this context.
   *
   * @param did - The DID to check.
   * @returns `true` if the DID is a member.
   * @throws {ContextError} If the context has been disposed.
   */
  async isMember(did: string): Promise<boolean> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      return await bridge.contextIsMember(this._handle, did);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Returns all member DIDs in this context.
   *
   * @returns An array of DID strings.
   * @throws {ContextError} If the context has been disposed.
   */
  async memberDids(): Promise<readonly string[]> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      return await bridge.contextMemberDids(this._handle);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Returns the role of a member in this context.
   *
   * @param did - The DID of the member.
   * @returns The role as a `MemberRole`, or `null` if the member is not found.
   * @throws {ContextError} If the context has been disposed.
   */
  async memberRole(did: string): Promise<MemberRole | null> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      return await bridge.contextMemberRole(this._handle, did);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  // ---------------------------------------------------------------------------
  // Broadcast operations
  // ---------------------------------------------------------------------------

  /**
   * Subscribes a DID to this broadcast context.
   *
   * @param subscriberDid - The DID subscribing to broadcasts.
   * @throws {ContextError} If the context is not active or not broadcast.
   */
  async broadcastSubscribe(subscriberDid: string): Promise<void> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      await bridge.broadcastSubscribe(this._handle, subscriberDid);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Unsubscribes a DID from this broadcast context.
   *
   * @param subscriberDid - The DID to unsubscribe.
   * @param rotateKeys - When `true`, all authors rotate their broadcast keys.
   * @throws {ContextError} If the context is not active or not broadcast.
   */
  async broadcastUnsubscribe(subscriberDid: string, rotateKeys = false): Promise<void> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      await bridge.broadcastUnsubscribe(this._handle, subscriberDid, rotateKeys);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Publishes a message to this broadcast context.
   *
   * @param payload - The raw message payload.
   * @param authorDid - The DID of the author publishing the message.
   *   Defaults to the identity that created/joined the context.
   * @throws {ContextError} If the context is not active or not broadcast.
   */
  async broadcastPublish(payload: Uint8Array, authorDid?: string): Promise<void> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      await bridge.broadcastPublish(this._handle, authorDid ?? this._identityDid, payload);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Publishes a single asset to this broadcast context as structured content (SCP-290).
   *
   * Constructs a BroadcastContent from the asset entry, computes an ETag,
   * and publishes via the structured content path.
   *
   * @param asset - The asset entry containing path, contentType, and body.
   * @param authorDid - The DID of the author publishing the asset.
   *   Defaults to the identity that created/joined the context.
   * @param deployId - Optional deploy ID to group assets into atomic deploys.
   * @returns A PublishResult with blobId and etag.
   * @throws {ContextError} If the context is not active or not broadcast.
   * @throws {ValidationError} If path, contentType, or deployId is invalid (SCP-297).
   */
  async broadcastPublishAsset(
    asset: AssetEntry,
    authorDid?: string,
    deployId?: string,
  ): Promise<PublishResult> {
    this.assertActive();
    // SCP-297: Client-side validation before FFI crossing.
    _validateContentPath(asset.path);
    _validateMimeType(asset.contentType);
    if (deployId != null) {
      _validateDeployId(deployId);
    }
    try {
      const bridge = await getBridge();
      const result = await bridge.broadcastPublishAsset(
        this._handle,
        authorDid ?? this._identityDid,
        { path: asset.path, contentType: asset.contentType, body: Array.from(asset.body) },
        deployId ?? null,
      );
      return { blobId: result.blobId, etag: result.etag, deployId: result.deployId };
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Publishes multiple assets to this broadcast context as structured content (SCP-290, SCP-292).
   *
   * All assets are published with the same deployId (auto-generated if not provided).
   *
   * @param assets - The asset entries to publish.
   * @param authorDid - The DID of the author publishing the assets.
   *   Defaults to the identity that created/joined the context.
   * @param deployId - Optional deploy ID to group assets into atomic deploys.
   * @returns A BatchPublishResult with per-asset results and the shared deployId.
   * @throws {ContextError} If any asset fails validation or publish.
   * @throws {ValidationError} If any path, contentType, or deployId is invalid (SCP-297).
   */
  async broadcastPublishAssets(
    assets: AssetEntry[],
    authorDid?: string,
    deployId?: string,
  ): Promise<BatchPublishResult> {
    this.assertActive();
    // SCP-297: Client-side validation before FFI crossing.
    for (const asset of assets) {
      _validateContentPath(asset.path);
      _validateMimeType(asset.contentType);
    }
    if (deployId != null) {
      _validateDeployId(deployId);
    }
    try {
      const bridge = await getBridge();
      const napiAssets = assets.map((a) => ({
        path: a.path,
        contentType: a.contentType,
        body: Array.from(a.body),
      }));
      const batch = await bridge.broadcastPublishAssets(
        this._handle,
        authorDid ?? this._identityDid,
        napiAssets,
        deployId ?? null,
      );
      return {
        results: batch.results.map((r: { blobId: string; etag: string; deployId: string }) => ({
          blobId: r.blobId,
          etag: r.etag,
          deployId: r.deployId,
        })),
        deployId: batch.deployId,
      };
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Blocks a subscriber's read access in this broadcast context.
   *
   * @param subscriberDid - The DID of the subscriber to block.
   * @param blockerDid - The DID of the blocker.
   * @throws {ContextError} If the operation fails.
   */
  async broadcastBlockSubscriber(subscriberDid: string, blockerDid: string): Promise<void> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      await bridge.broadcastBlockSubscriber(this._handle, subscriberDid, blockerDid);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Unblocks a previously blocked subscriber in this broadcast context.
   *
   * Forward-only restoration (section 9.16.8): the unblocked subscriber can request
   * the current key on next pull but cannot decrypt content from the block period.
   *
   * @param subscriberDid - The DID of the subscriber to unblock.
   * @param unblockerDid - The DID of the author performing the unblock.
   * @throws {ContextError} If the operation fails.
   */
  async broadcastUnblockSubscriber(subscriberDid: string, unblockerDid: string): Promise<void> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      await bridge.broadcastUnblockSubscriber(this._handle, subscriberDid, unblockerDid);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Handles a broadcast key request from a subscriber.
   *
   * @param authorDid - The DID of the author handling the request.
   * @param requesterDid - The DID of the requester.
   * @returns A string describing the key request decision.
   * @throws {ContextError} If the operation fails.
   */
  async broadcastHandleKeyRequest(authorDid: string, requesterDid: string): Promise<string> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      return await bridge.broadcastHandleKeyRequest(this._handle, authorDid, requesterDid);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Returns the number of broadcast subscribers for this context.
   *
   * @returns The subscriber count, or `null` if not a broadcast context.
   * @throws {ContextError} If the context has been disposed.
   */
  async broadcastSubscriberCount(): Promise<number | null> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      return await bridge.broadcastSubscriberCount(this._handle);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Checks whether a DID is a broadcast subscriber.
   *
   * @param did - The DID to check.
   * @returns `true` if the DID is a subscriber.
   * @throws {ContextError} If the context has been disposed.
   */
  async broadcastIsSubscriber(did: string): Promise<boolean> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      return await bridge.broadcastIsSubscriber(this._handle, did);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Returns the broadcast admission policy for this context.
   *
   * @returns The policy (`"Open"` or `"Gated"`), or `null` if not broadcast.
   * @throws {ContextError} If the context has been disposed.
   */
  async broadcastAdmission(): Promise<BroadcastAdmissionPolicy | null> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      return await bridge.broadcastAdmission(this._handle);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  // ---------------------------------------------------------------------------
  // Economic policy (section 19)
  // ---------------------------------------------------------------------------

  /**
   * Sets the economic policy for this context.
   *
   * Validates the JSON against the `EconomicPolicy` schema before storing.
   * The policy controls per-tool-invoke costs, per-period budgets, and other
   * economic governance parameters.
   *
   * Schema validation is performed at the SDK layer as defense-in-depth:
   * the NAPI bridge validates via Rust deserialization, but the WASM bridge
   * can only check JSON syntax (ADR-034 prevents scp-core type imports).
   *
   * @param policyJson - The economic policy as a JSON string conforming to
   *   the `EconomicPolicy` schema (spec section 19).
   * @throws {ContextError} If the context has been disposed.
   * @throws {ValidationError} If the JSON is invalid or missing required fields.
   */
  async setEconomicPolicy(policyJson: string): Promise<void> {
    this.assertActive();
    _validateEconomicPolicyJson(policyJson);
    try {
      const bridge = await getBridge();
      await bridge.contextSetEconomicPolicy(this._handle, policyJson);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Returns the economic policy for this context as a JSON string.
   *
   * @returns The economic policy JSON, or `null` if no policy is set.
   * @throws {ContextError} If the context has been disposed.
   */
  async getEconomicPolicy(): Promise<string | null> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      return await bridge.contextGetEconomicPolicy(this._handle);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  // ---------------------------------------------------------------------------
  // Governance
  // ---------------------------------------------------------------------------

  /**
   * Executes a governance action on this context.
   *
   * @param proposalJson - JSON-serialized `GovernanceProposal`.
   * @returns A `GovernanceActionResult` string describing the outcome.
   * @throws {ContextError} If the context is not active or governance fails.
   */
  async executeGovernanceAction(proposalJson: string): Promise<GovernanceActionResult> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      const raw = await bridge.contextExecuteGovernanceAction(
        this._handle,
        proposalJson,
        this._identityDid,
      );
      return raw as GovernanceActionResult;
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Proposes a governance action for voting.
   *
   * For `SingleAdmin` contexts, the proposal is auto-approved and executed
   * immediately. For multi-admin models (Threshold, Majority, Unanimity),
   * the proposal enters `Pending` status and must accumulate votes.
   *
   * @param actionJson - JSON-serialized `GovernanceAction`.
   * @param proposerDid - DID of the proposer. Defaults to context identity.
   * @returns JSON string with `proposal_id`, `status`, and `execution_result`.
   * @throws {ContextError} If the context is not active or the proposal fails.
   */
  async proposeGovernanceAction(actionJson: string, proposerDid?: string): Promise<string> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      return await bridge.contextGovernancePropose(
        this._handle,
        actionJson,
        proposerDid ?? this._identityDid,
      );
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Casts an approval vote on a pending governance proposal.
   *
   * If the vote pushes the proposal past quorum, the action is auto-executed.
   *
   * @param proposalIdHex - Hex-encoded 32-byte proposal ID.
   * @param voterDid - DID of the voter. Defaults to context identity.
   * @returns JSON string with `status`.
   * @throws {ContextError} If the vote fails.
   */
  async approveGovernanceProposal(proposalIdHex: string, voterDid?: string): Promise<string> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      return await bridge.contextGovernanceApprove(
        this._handle,
        proposalIdHex,
        voterDid ?? this._identityDid,
      );
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Casts a rejection vote on a pending governance proposal.
   *
   * @param proposalIdHex - Hex-encoded 32-byte proposal ID.
   * @param voterDid - DID of the voter. Defaults to context identity.
   * @returns JSON string with `status`.
   * @throws {ContextError} If the vote fails.
   */
  async rejectGovernanceProposal(proposalIdHex: string, voterDid?: string): Promise<string> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      return await bridge.contextGovernanceReject(
        this._handle,
        proposalIdHex,
        voterDid ?? this._identityDid,
      );
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Withdraws a previously cast vote on a pending governance proposal.
   *
   * @param proposalIdHex - Hex-encoded 32-byte proposal ID.
   * @param voterDid - DID of the voter. Defaults to context identity.
   * @returns JSON string with `status`.
   * @throws {ContextError} If the withdrawal fails.
   */
  async withdrawGovernanceVote(proposalIdHex: string, voterDid?: string): Promise<string> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      return await bridge.contextGovernanceWithdraw(
        this._handle,
        proposalIdHex,
        voterDid ?? this._identityDid,
      );
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Retrieves a single governance proposal by its hex-encoded ID.
   *
   * @param proposalIdHex - Hex-encoded 32-byte proposal ID.
   * @returns JSON string with proposal details.
   * @throws {ContextError} If the proposal is not found (SCP-CTX-2045).
   */
  async getGovernanceProposal(proposalIdHex: string): Promise<string> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      return await bridge.contextGovernanceGetProposal(this._handle, proposalIdHex);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Lists all governance proposals for this context.
   *
   * @returns JSON array of proposals.
   * @throws {ContextError} If listing fails (SCP-CTX-2046).
   */
  async listGovernanceProposals(): Promise<string> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      return await bridge.contextGovernanceListProposals(this._handle);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  // ---------------------------------------------------------------------------
  // Ceiling modification, close, checkpoint, restore (#559)
  // ---------------------------------------------------------------------------

  /**
   * Applies a pending ceiling modification if the notification period has elapsed.
   *
   * @param currentTimestamp - Current Unix timestamp in seconds.
   * @returns `true` if the modification was applied, `false` otherwise.
   * @throws {ContextError} If the operation fails (SCP-CTX-2060).
   */
  async applyPendingCeilingModification(currentTimestamp: number): Promise<boolean> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      return await bridge.contextApplyPendingCeilingModification(this._handle, currentTimestamp);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Finalizes the cooperative close flow for a context in `Closing` state.
   *
   * Transitions from `Closing` to `Closed`, destroys keys per memory scope,
   * and records a `ContextClosed` event.
   *
   * @throws {ContextError} If the context is not in Closing state (SCP-CTX-2061).
   */
  async finalizeClose(): Promise<void> {
    try {
      const bridge = await getBridge();
      await bridge.contextFinalizeClose(this._handle);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Creates a governance checkpoint (ADR-031 section 9).
   *
   * @param params - Checkpoint parameters.
   * @param params.checkpointSeq - Sequence number in the event log.
   * @param params.merkleRootHex - Hex-encoded 32-byte Merkle root.
   * @param params.eventCount - Number of events included.
   * @param params.lastEventHashHex - Hex-encoded 32-byte hash.
   * @param params.stateSnapshotHashHex - Hex-encoded 32-byte hash.
   * @param params.creatorDid - DID of the creator. Defaults to context identity.
   * @param params.creatorSignatureHex - Hex-encoded Ed25519 signature.
   * @returns JSON string with the `ContextCheckpoint` object.
   * @throws {ContextError} If checkpoint creation fails (SCP-CTX-2062).
   */
  async createGovernanceCheckpoint(params: {
    checkpointSeq: number;
    merkleRootHex: string;
    eventCount: number;
    lastEventHashHex: string;
    stateSnapshotHashHex: string;
    creatorDid?: string;
    creatorSignatureHex: string;
  }): Promise<string> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      return await bridge.contextCreateGovernanceCheckpoint(
        this._handle,
        params.checkpointSeq,
        params.merkleRootHex,
        params.eventCount,
        params.lastEventHashHex,
        params.stateSnapshotHashHex,
        params.creatorDid ?? this._identityDid,
        params.creatorSignatureHex,
      );
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Adds a cosignature to an existing governance checkpoint (ADR-031 section 9).
   *
   * @param checkpointJson - JSON-serialized checkpoint.
   * @param signerDid - DID of the cosigner.
   * @param signatureHex - Hex-encoded Ed25519 signature.
   * @returns JSON string with `attestation_status` and updated `checkpoint`.
   * @throws {ContextError} If cosignature validation fails (SCP-CTX-2063).
   */
  async addCheckpointCosignature(
    checkpointJson: string,
    signerDid: string,
    signatureHex: string,
  ): Promise<string> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      return await bridge.contextAddCheckpointCosignature(
        this._handle,
        checkpointJson,
        signerDid,
        signatureHex,
      );
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  // ---------------------------------------------------------------------------
  // TTL
  // ---------------------------------------------------------------------------

  /**
   * Returns the configured TTL duration in seconds, or `null` if no TTL is set.
   *
   * Note: In the WASM bridge, this returns the current TTL value stored on the
   * context (which increases when extended), not a real-time countdown. The
   * native (NAPI) bridge does not support this operation.
   *
   * @returns The configured TTL duration in seconds, or `null` for persistent contexts.
   * @throws {ContextError} If the context has been disposed.
   * @throws {TransportError} If using the native (NAPI) bridge, which does not support this operation.
   */
  async ttlRemaining(): Promise<number | null> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      return await bridge.contextTtlRemaining(this._handle);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Extends the TTL by the given number of seconds.
   *
   * @param additionalSecs - Number of seconds to add to the TTL. Must be a finite positive number.
   * @returns `true` if the extension was applied.
   * @throws {ContextError} If the context has been disposed or extension fails.
   * @throws {ContextError} If `additionalSecs` is not a finite positive number.
   */
  async extendTtl(additionalSecs: number): Promise<boolean> {
    this.assertActive();
    if (!Number.isFinite(additionalSecs) || additionalSecs <= 0) {
      throw new ContextError("additionalSecs must be a finite positive number", "SCP-CTX-2031");
    }
    try {
      const bridge = await getBridge();
      return await bridge.contextExtendTtl(this._handle, additionalSecs);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Handles automatic TTL expiry for this context.
   *
   * Triggers the TTL expiry lifecycle: transitions the context to expired
   * state and notifies members. Typically called by a timer or scheduler
   * when the context's TTL has elapsed.
   *
   * @throws {ContextError} If the context is not active (SCP-CTX-2005).
   */
  async handleTtlExpiry(): Promise<void> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      await bridge.contextHandleTtlExpiry(this._handle);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Proposes a TTL extension for this context.
   *
   * Records consent from the given member for extending the context's TTL.
   * Returns `true` if the extension was unanimously approved by all members.
   *
   * @param extensionSecs - Number of seconds to extend the TTL by. Must be a finite positive number.
   * @param proposerDid - DID of the proposer. Defaults to the context identity.
   * @returns `true` if the extension was unanimously approved.
   * @throws {ContextError} If the context is not active or the proposal fails (SCP-CTX-2005).
   * @throws {ContextError} If `extensionSecs` is not a finite positive number.
   */
  async proposeTtlExtension(extensionSecs: number, proposerDid?: string): Promise<boolean> {
    this.assertActive();
    if (!Number.isFinite(extensionSecs) || extensionSecs <= 0) {
      throw new ContextError("extensionSecs must be a finite positive number", "SCP-CTX-2031");
    }
    try {
      const bridge = await getBridge();
      return await bridge.contextProposeTtlExtension(
        this._handle,
        proposerDid ?? this._identityDid,
        extensionSecs,
      );
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Resets the TTL timer for this context to a new duration.
   *
   * Replaces the current TTL countdown with a fresh timer of the specified
   * duration. Requires a core context handle.
   *
   * @param newDurationSecs - The new TTL duration in seconds. Must be a finite positive number.
   * @throws {ContextError} If the context does not have a core handle (SCP-CTX-2024).
   * @throws {ContextError} If `newDurationSecs` is not a finite positive number.
   */
  async resetTtlTimer(newDurationSecs: number): Promise<void> {
    this.assertActive();
    if (!Number.isFinite(newDurationSecs) || newDurationSecs <= 0) {
      throw new ContextError("newDurationSecs must be a finite positive number", "SCP-CTX-2031");
    }
    try {
      const bridge = await getBridge();
      await bridge.contextResetTtlTimer(this._handle, newDurationSecs);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  // ---------------------------------------------------------------------------
  // Export / Import
  // ---------------------------------------------------------------------------

  /**
   * Exports this context's full state as serialized bytes.
   *
   * Returns serialized `StoredValue<ContextExport>` bytes (spec section 17.5)
   * suitable for backup, migration, or transfer to another node.
   *
   * @returns The serialized context export as a `Uint8Array`.
   * @throws {ContextError} If the context has been disposed or export fails.
   */
  async export(): Promise<Uint8Array> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      return await bridge.contextExport(this._handle);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Imports a context from serialized bytes.
   *
   * The bytes must be a `StoredValue<ContextExport>` envelope (spec section
   * 17.5), as produced by {@link Context.prototype.export}.
   *
   * @param data - The serialized context export bytes.
   * @returns The context ID of the imported context.
   * @throws {ContextError} If deserialization, validation, or import fails.
   */
  static async import(data: Uint8Array): Promise<string> {
    try {
      const bridge = await getBridge();
      return await bridge.contextImport(data);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  // ---------------------------------------------------------------------------
  // Drain events
  // ---------------------------------------------------------------------------

  /**
   * Drains all pending events from this context's receive buffer.
   *
   * Returns events as an array of JSON strings. This is a non-blocking
   * alternative to the streaming `receive()` generator for batch processing.
   *
   * @returns An array of event JSON strings.
   * @throws {ContextError} If the context has been disposed.
   */
  async drainEvents(): Promise<readonly string[]> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      return await bridge.contextDrainEvents(this._handle);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Leaves the context.
   *
   * Sends a `MemberLeft` event and releases local resources.
   *
   * @throws {ContextError} If the context is not `"active"`.
   */
  async leave(): Promise<void> {
    if (this._disposed) {
      return;
    }
    this._disposed = true;
    try {
      const bridge = await getBridge();
      await bridge.contextLeave(this._handle, this._identityDid);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Closes the context.
   *
   * Terminates the context for all members. Subsequent operations throw
   * `ContextError`.
   *
   * @throws {ContextError} If the context is not `"active"`.
   */
  async close(): Promise<void> {
    if (this._disposed) {
      return;
    }
    this._disposed = true;
    try {
      const bridge = await getBridge();
      await bridge.contextClose(this._handle, this._identityDid);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Implements `AsyncDisposable` for automatic cleanup.
   *
   * When used with `await using`, the context is automatically left on
   * scope exit (including exceptions).
   */
  async [Symbol.asyncDispose](): Promise<void> {
    await this.leave();
  }

  /**
   * Asserts that the context has not been disposed.
   *
   * @throws {ContextError} If the context has been left or closed.
   */
  private assertActive(): void {
    if (this._disposed) {
      throw new ContextError(
        "Cannot operate on a disposed context — the context has been left or closed",
        "SCP-CTX-2030",
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Context restoration (#559)
// ---------------------------------------------------------------------------

/**
 * Restores a single persisted context from storage.
 *
 * @param contextId - The context ID to restore.
 * @throws {ContextError} If restoration fails (SCP-CTX-2064).
 */
export async function restoreContext(contextId: string): Promise<void> {
  try {
    const bridge = await getBridge();
    await bridge.contextRestore(contextId);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Restores all persisted contexts from storage.
 *
 * Only contexts in `Active` state are restored. Contexts in `Closing`,
 * `Closed`, or `Expired` states are skipped.
 *
 * @returns JSON array of restored context ID strings.
 * @throws {ContextError} If restoration fails (SCP-CTX-2065).
 */
export async function restoreAllContexts(): Promise<string> {
  try {
    const bridge = await getBridge();
    return await bridge.contextRestoreAll();
  } catch (error) {
    throw mapBridgeError(error);
  }
}

// ---------------------------------------------------------------------------
// App Sandboxing (spec §8.4.1, §8.4.2, issue #595)
// ---------------------------------------------------------------------------

/** Result of validating a capability declaration. */
export interface DeclarationValidationResult {
  valid: boolean;
  grantedCapabilities: readonly string[];
  error: string | null;
  appDid: string;
}

/**
 * Capability-restricted context handle (spec §8.4.2).
 *
 * Wraps a `Context` with a whitelist of allowed capabilities. All protocol
 * operations must check the whitelist before proceeding. An app cannot access
 * protocol operations beyond its declared capabilities.
 *
 * Once created, a `ScopedHandle` cannot gain additional capabilities
 * (no escalation guarantee, spec 8.4.2 rule 4).
 */
export class ScopedHandle {
  readonly context: Context;
  readonly grantedCapabilities: readonly string[];
  readonly appDid: string;

  constructor(context: Context, grantedCapabilities: readonly string[], appDid: string) {
    this.context = context;
    // Freeze to prevent mutation via Object.defineProperty or prototype tricks.
    this.grantedCapabilities = Object.freeze([...grantedCapabilities]);
    this.appDid = appDid;
  }

  /** Check whether a given capability is allowed. */
  hasCapability(capability: string): boolean {
    const bridge = getBridgeSync();
    return bridge.checkScopedCapability(this.grantedCapabilities, capability);
  }

  /** Throws `ContextError` if the capability is not granted. */
  checkCapability(capability: string): void {
    if (!this.hasCapability(capability)) {
      throw new ContextError(
        `capability denied: ${capability} not granted to app ${this.appDid}`,
        "SCP-CTX-2050",
      );
    }
  }
}

/**
 * Validates a capability declaration against a context ceiling and role capabilities.
 *
 * Returns a result object with validation outcome. See spec §8.4.1.
 * This is a synchronous operation -- no I/O is involved.
 */
export function validateCapabilityDeclaration(
  declarationJson: string,
  ceilingCapabilities: string[],
  roleCapabilities: string[],
): DeclarationValidationResult {
  const bridge = getBridgeSync();
  const resultJson = bridge.validateCapabilityDeclaration(
    declarationJson,
    ceilingCapabilities,
    roleCapabilities,
  );
  return JSON.parse(resultJson) as DeclarationValidationResult;
}

// ---------------------------------------------------------------------------
// Invitation evaluation (#614)
// ---------------------------------------------------------------------------

/**
 * Result of evaluating a context invitation.
 */
export interface InvitationEvaluationResult {
  /** The pipeline decision: `"auto_accept"` or `"prompt_agent"`. */
  readonly decision: "auto_accept" | "prompt_agent";
}

/**
 * Evaluates a context invitation through the sequential pipeline.
 *
 * Runs the 4-step evaluation pipeline:
 * 1. **Template check** -- validates params match the claimed template.
 * 2. **Economic policy check** -- verifies spending capability for paid contexts.
 * 3. **Auto-accept check** -- evaluates trust, TTL cap, and rate limit.
 * 4. **Agent prompt** -- falls through if no auto-accept matches.
 *
 * @param paramsJson - JSON-serialized `ContextParams` from the invitation.
 * @param inviterDid - DID string of the identity sending the invitation.
 * @param identityDid - DID string of the local identity receiving the invitation.
 * @param policyJson - Optional JSON-serialized `AutoAcceptPolicy`.
 * @param spendingJson - Optional JSON-serialized `SpendingContext`.
 * @param trustedDids - Optional array of trusted DID strings.
 * @returns The evaluation result with the pipeline decision.
 * @throws {ContextError} If pipeline evaluation fails.
 * @throws {ValidationError} If input validation fails.
 */
export async function evaluateInvitation(
  paramsJson: string,
  inviterDid: string,
  identityDid: string,
  policyJson?: string,
  spendingJson?: string,
  trustedDids?: readonly string[],
): Promise<InvitationEvaluationResult> {
  try {
    const bridge = await getBridge();
    const trustedDidsJson = trustedDids ? JSON.stringify(trustedDids) : undefined;
    const result = bridge.evaluateInvitation(
      paramsJson,
      inviterDid,
      identityDid,
      policyJson ?? null,
      spendingJson ?? null,
      trustedDidsJson ?? null,
    );
    // NAPI returns an object directly; WASM returns a JSON string promise.
    if (typeof result === "string") {
      return JSON.parse(result) as InvitationEvaluationResult;
    }
    // Handle promise (WASM)
    if (result && typeof (result as Promise<string>).then === "function") {
      const resolved = await (result as Promise<string>);
      if (typeof resolved === "string") {
        return JSON.parse(resolved) as InvitationEvaluationResult;
      }
      return resolved as unknown as InvitationEvaluationResult;
    }
    // NAPI returns object with decision field
    return result as unknown as InvitationEvaluationResult;
  } catch (error) {
    throw mapBridgeError(error);
  }
}

// ---------------------------------------------------------------------------
// MetadataRecord inspection (§5.7.2, #615)
// ---------------------------------------------------------------------------

/** Structural metadata fields -- always visible before joining. */
export interface StructuralMetadata {
  template_id: string | null;
  ceiling: string[];
  ceiling_policy: string;
  roles: unknown[];
  governance: string;
  ttl: number | null;
  promotion_policy: string;
  memory_scope: string;
  mode: string;
  visibility_policy: Record<string, string>;
}

/** Operational metadata fields -- visibility governed by policy. */
export interface OperationalMetadata {
  member_count: number | null;
  context_age_secs: number | null;
  creator_did: string | null;
  name: string | null;
  description: string | null;
  economic_policy: string | null;
  tool_count: number | null;
  child_contexts: string[] | null;
}

/** A signed context metadata record published for pre-join inspection (§5.7.2). */
export interface MetadataRecord {
  context_id: string;
  sequence: number;
  signer_did: string;
  timestamp: number;
  structural: StructuralMetadata;
  operational: OperationalMetadata;
  signature: number[];
}

/**
 * Serializes a MetadataRecord to a JSON string (spec §5.7.2).
 *
 * @param contextId - The context this metadata describes.
 * @param sequence - Monotonically increasing sequence number (starts at 1).
 * @param signerDid - DID of the admin who signed this record.
 * @param timestamp - Unix timestamp in milliseconds.
 * @param structural - Structural metadata object.
 * @param operational - Operational metadata object.
 * @param signatureHex - Ed25519 signature as hex string (128 hex chars).
 * @returns JSON string of the MetadataRecord.
 */
export function metadataRecordToJson(
  contextId: string,
  sequence: number,
  signerDid: string,
  timestamp: number,
  structural: StructuralMetadata,
  operational: OperationalMetadata,
  signatureHex: string,
): string {
  const bridge = getBridgeSync();
  return bridge.metadataRecordToJson(
    contextId,
    sequence,
    signerDid,
    timestamp,
    JSON.stringify(structural),
    JSON.stringify(operational),
    signatureHex,
  );
}

/**
 * Deserializes a MetadataRecord from a JSON string (spec §5.7.2).
 *
 * @param jsonStr - JSON string of a MetadataRecord.
 * @returns Parsed MetadataRecord object.
 */
export function metadataRecordFromJson(jsonStr: string): MetadataRecord {
  const bridge = getBridgeSync();
  const validated = bridge.metadataRecordFromJson(jsonStr);
  return JSON.parse(validated) as MetadataRecord;
}

// ---------------------------------------------------------------------------
// Context template inspection (§5.14, #615)
// ---------------------------------------------------------------------------

/**
 * Gets the canonical ContextParams for a well-known template (spec §5.12.1).
 *
 * @param templateId - One of: `BilateralEphemeral`, `BilateralPersistent`,
 *   `Coordination`, `GroupDiscussion`, `PublicBroadcast`, `GatedBroadcast`,
 *   `scp:template/tool-interface`, `PaidService`, `PaidBroadcast`,
 *   `DiscoveryContext`.
 * @returns ContextParams object.
 */
export function templateGetParams(templateId: string): ContextParams {
  const bridge = getBridgeSync();
  const result = bridge.templateGetParams(templateId);
  return JSON.parse(result) as ContextParams;
}

/**
 * Validates that ContextParams match their template definition.
 *
 * When `params` contains a `template_id`, every field is compared
 * against the canonical template definition.
 *
 * @param params - ContextParams to validate.
 * @returns `null` on success, or a string error message on failure.
 */
export function validateAgainstTemplate(params: ContextParams): string | null {
  const bridge = getBridgeSync();
  return bridge.validateAgainstTemplate(JSON.stringify(params));
}

/**
 * Validates cross-field invariants for ContextParams regardless of template.
 *
 * Currently enforces: `projection_policy` must be `null` for `Encrypted` contexts.
 *
 * @param params - ContextParams to validate.
 * @returns `null` on success, or a string error message on failure.
 */
export function validateContextParams(params: ContextParams): string | null {
  const bridge = getBridgeSync();
  return bridge.validateContextParams(JSON.stringify(params));
}
