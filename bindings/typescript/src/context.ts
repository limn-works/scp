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

import { ContextError, mapBridgeError } from "./errors.js";
import type { Identity } from "./identity.js";
import type { BridgeContextHandle } from "./internal/bridge.js";
import { getBridge } from "./internal/bridge.js";
import type {
  ContextParams,
  GovernanceActionResult,
  MemberRole,
  Message,
  ToolDefinition,
  ToolVerificationResult,
} from "./types.js";

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
   * @returns The tool output as a parsed JSON object.
   * @throws {ToolError} If invocation fails or the tool is not found.
   */
  async invokeTool(
    toolId: string,
    input: Readonly<Record<string, unknown>>,
    identity: Identity,
  ): Promise<unknown> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      const resultJson = await bridge.toolInvoke(
        this._handle,
        toolId,
        JSON.stringify(input),
        identity.did,
      );
      return JSON.parse(resultJson) as unknown;
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
   * @throws {ContextError} If the context is not active or not broadcast.
   */
  async broadcastPublish(payload: Uint8Array): Promise<void> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      await bridge.broadcastPublish(this._handle, payload);
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
  async broadcastAdmission(): Promise<string | null> {
    this.assertActive();
    try {
      const bridge = await getBridge();
      return await bridge.broadcastAdmission(this._handle);
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
      const raw = await bridge.contextExecuteGovernanceAction(this._handle, proposalJson);
      return raw as GovernanceActionResult;
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
