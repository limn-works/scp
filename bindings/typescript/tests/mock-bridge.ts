/**
 * Mock bridge for integration testing.
 *
 * Provides an in-memory implementation of the Bridge interface that simulates
 * real runtime behavior without requiring a compiled WASM module or native
 * addon. This enables testing SDK class logic, error propagation, and
 * data flow end-to-end.
 *
 * See ADR-022 in `.docs/adrs/phase-4.md`.
 */

import type {
  Bridge,
  BridgeContextHandle,
  BridgeIdentityHandle,
  BridgeTransportHandle,
  MessageCallback,
} from "../src/internal/bridge";
import type {
  Checkpoint,
  DIDDocument,
  Event,
  EventClaim,
  EventFilter,
  Proof,
  ToolDefinition,
  ToolVerificationResult,
  TransportStatus,
  UcanToken,
} from "../src/types";

// ---------------------------------------------------------------------------
// In-memory state stores
// ---------------------------------------------------------------------------

interface MockIdentity {
  did: string;
  custodyType: string;
}

interface MockContext {
  contextId: string;
  state: string;
  creatorDid: string;
  events: Event[];
  tools: Map<string, ToolDefinition & { handler?: (input: unknown) => unknown }>;
  members: Set<string>;
  subscriptions: MessageCallback[];
  ucans: Map<string, UcanToken>;
  revokedTokens: Set<string>;
  economicPolicy: string | null;
}

interface MockTransport {
  relayUrl: string;
  connected: boolean;
}

// ---------------------------------------------------------------------------
// Mock bridge factory
// ---------------------------------------------------------------------------

/**
 * Creates a mock Bridge implementation backed by in-memory state.
 *
 * Supports:
 * - Identity creation with deterministic DIDs
 * - Context creation, join, leave, close with event tracking
 * - Message send/receive with subscription callbacks
 * - Tool registration with optional handler, invocation, and verification
 * - UCAN minting, validation, and revocation
 * - Event log queries with filter support
 * - Transport connect/disconnect
 */
export function createMockBridge(): Bridge & {
  /** Access internal state for test assertions. */
  _identities: Map<string, MockIdentity>;
  _contexts: Map<string, MockContext>;
  _transports: Map<string, MockTransport>;
  _nextId: number;
  /** Register a tool handler for invocation testing. */
  _registerToolHandler(
    contextId: string,
    toolId: string,
    handler: (input: unknown) => unknown,
  ): void;
} {
  const identities = new Map<string, MockIdentity>();
  const contexts = new Map<string, MockContext>();
  const transports = new Map<string, MockTransport>();
  let nextId = 1;

  function generateDid(): string {
    const id = nextId++;
    // Generate a deterministic did:dht string with 52 lowercase base32 chars
    const base32Chars = "abcdefghijklmnopqrstuvwxyz234567";
    let suffix = "";
    let remaining = id;
    for (let i = 0; i < 52; i++) {
      suffix += base32Chars[remaining % 32];
      remaining = Math.floor(remaining / 32);
    }
    return `did:dht:${suffix}`;
  }

  function generateId(prefix: string): string {
    return `${prefix}-${nextId++}`;
  }

  function getContext(handle: BridgeContextHandle): MockContext {
    const ctx = contexts.get(handle.contextId);
    if (ctx === undefined) {
      throw new Error(`[SCP-CTX-2001] Context not found: ${handle.contextId}`);
    }
    if (ctx.state !== "active") {
      throw new Error(`[SCP-CTX-2030] Context is not active: ${handle.contextId}`);
    }
    return ctx;
  }

  const bridge: Bridge & {
    _identities: Map<string, MockIdentity>;
    _contexts: Map<string, MockContext>;
    _transports: Map<string, MockTransport>;
    _nextId: number;
    _registerToolHandler(
      contextId: string,
      toolId: string,
      handler: (input: unknown) => unknown,
    ): void;
  } = {
    _identities: identities,
    _contexts: contexts,
    _transports: transports,
    get _nextId() {
      return nextId;
    },

    _registerToolHandler(
      contextId: string,
      toolId: string,
      handler: (input: unknown) => unknown,
    ): void {
      const ctx = contexts.get(contextId);
      if (ctx === undefined) {
        throw new Error(`Context not found: ${contextId}`);
      }
      const tool = ctx.tools.get(toolId);
      if (tool === undefined) {
        throw new Error(`Tool not found: ${toolId}`);
      }
      (tool as ToolDefinition & { handler?: (input: unknown) => unknown }).handler = handler;
    },

    // Identity
    async identityCreate(custody: string): Promise<BridgeIdentityHandle> {
      const did = generateDid();
      const identity: MockIdentity = { did, custodyType: custody };
      identities.set(did, identity);
      return { did, custodyType: custody };
    },

    async identityLoad(did: string): Promise<BridgeIdentityHandle> {
      if (!did.startsWith("did:")) {
        throw new Error(`[SCP-IDENT-1001] Invalid DID format: ${did}`);
      }
      const existing = identities.get(did);
      if (existing !== undefined) {
        return { did: existing.did, custodyType: existing.custodyType };
      }
      // Create a synthetic handle for loaded DIDs
      const identity: MockIdentity = { did, custodyType: "in_memory" };
      identities.set(did, identity);
      return { did, custodyType: "in_memory" };
    },

    async identityResolve(did: string): Promise<DIDDocument> {
      if (!did.startsWith("did:")) {
        throw new Error(`[SCP-IDENT-1002] Cannot resolve invalid DID: ${did}`);
      }
      return {
        id: did,
        verificationMethods: [
          {
            id: `${did}#0`,
            type: "Ed25519VerificationKey2020",
            controller: did,
            publicKeyMultibase: "z6MkmockPublicKey",
          },
        ],
        authentication: [`${did}#0`],
        assertionMethods: [`${did}#0`],
        alsoKnownAs: [],
        serviceEndpoints: [],
        hasAgentKey: false,
      };
    },

    async identityRotateKey(handle: BridgeIdentityHandle): Promise<BridgeIdentityHandle> {
      const identity = identities.get(handle.did);
      if (identity === undefined) {
        throw new Error(`[SCP-IDENT-1003] Identity not found: ${handle.did}`);
      }
      // Return same DID with rotated key (in-memory, key material is opaque)
      return { did: handle.did, custodyType: handle.custodyType };
    },

    // Context
    async contextCreate(
      identity: BridgeIdentityHandle,
      paramsJson: string,
    ): Promise<BridgeContextHandle> {
      const _params = JSON.parse(paramsJson);
      const contextId = generateId("ctx");
      const ctx: MockContext = {
        contextId,
        state: "active",
        creatorDid: identity.did,
        events: [],
        tools: new Map(),
        members: new Set([identity.did]),
        subscriptions: [],
        ucans: new Map(),
        revokedTokens: new Set(),
        economicPolicy: null,
      };

      // Record ContextCreated event
      ctx.events.push({
        eventType: "ContextCreated",
        actorDid: identity.did,
        timestamp: Math.floor(Date.now() / 1000),
        payload: { contextId },
        sequence: ctx.events.length,
      });

      contexts.set(contextId, ctx);
      return { contextId, state: "active", creatorDid: identity.did };
    },

    async contextJoin(handle: BridgeContextHandle, identityDid: string): Promise<void> {
      const ctx = getContext(handle);
      ctx.members.add(identityDid);
      ctx.events.push({
        eventType: "MemberJoined",
        actorDid: identityDid,
        timestamp: Math.floor(Date.now() / 1000),
        payload: { memberDid: identityDid },
        sequence: ctx.events.length,
      });
    },

    async contextLeave(handle: BridgeContextHandle, identityDid: string): Promise<void> {
      const ctx = getContext(handle);
      ctx.members.delete(identityDid);
      ctx.events.push({
        eventType: "MemberLeft",
        actorDid: identityDid,
        timestamp: Math.floor(Date.now() / 1000),
        payload: { memberDid: identityDid },
        sequence: ctx.events.length,
      });
      // Notify subscriptions that context is done for this member
      for (const sub of ctx.subscriptions) {
        sub.onComplete();
      }
    },

    async contextClose(handle: BridgeContextHandle, identityDid: string): Promise<void> {
      const ctx = getContext(handle);
      ctx.state = "closed";
      ctx.events.push({
        eventType: "ContextClosed",
        actorDid: identityDid,
        timestamp: Math.floor(Date.now() / 1000),
        payload: {},
        sequence: ctx.events.length,
      });
      for (const sub of ctx.subscriptions) {
        sub.onComplete();
      }
    },

    async contextSend(
      handle: BridgeContextHandle,
      identityDid: string,
      payload: Uint8Array,
    ): Promise<void> {
      const ctx = getContext(handle);
      const sequence = ctx.events.length;
      const timestamp = Math.floor(Date.now() / 1000);

      ctx.events.push({
        eventType: "MessageSent",
        actorDid: identityDid,
        timestamp,
        payload: { size: payload.length },
        sequence,
      });

      // Deliver to subscribers
      for (const sub of ctx.subscriptions) {
        sub.onMessage({
          senderDid: identityDid,
          content: payload,
          timestamp,
          sequence,
          contextId: handle.contextId,
        });
      }
    },

    contextSubscribe(
      handle: BridgeContextHandle,
      _identityDid: string,
      callback: MessageCallback,
    ): void {
      const ctx = contexts.get(handle.contextId);
      if (ctx === undefined) {
        throw new Error(`[SCP-CTX-2001] Context not found: ${handle.contextId}`);
      }
      ctx.subscriptions.push(callback);
    },

    // Tools
    async toolRegister(handle: BridgeContextHandle, definition: ToolDefinition): Promise<string> {
      const ctx = getContext(handle);
      const toolId = generateId("tool");
      ctx.tools.set(toolId, { ...definition });

      ctx.events.push({
        eventType: "ToolRegistered",
        actorDid: handle.creatorDid,
        timestamp: Math.floor(Date.now() / 1000),
        payload: { toolId, toolName: definition.name },
        sequence: ctx.events.length,
      });

      return toolId;
    },

    async toolInvoke(
      handle: BridgeContextHandle,
      toolId: string,
      inputJson: string,
      identityDid: string,
      ucanToken?: string,
    ): Promise<string> {
      const ctx = getContext(handle);
      const tool = ctx.tools.get(toolId) as
        | (ToolDefinition & { handler?: (input: unknown) => unknown })
        | undefined;
      if (tool === undefined) {
        throw new Error(`[SCP-TOOL-6001] Tool not found: ${toolId}`);
      }

      // Validate UCAN token is provided (mirrors WASM bridge behavior)
      if (ucanToken === undefined || ucanToken === "") {
        throw new Error("[SCP-VALID-7000] ucan_token is required for tool invocation");
      }

      // Check token is not revoked
      if (ctx.revokedTokens.has(ucanToken)) {
        throw new Error("[SCP-PERM-3001] Token has been revoked");
      }

      const input = JSON.parse(inputJson) as unknown;
      let result: unknown;

      if (tool.handler !== undefined) {
        result = tool.handler(input);
      } else {
        // Default echo behavior when no handler is registered
        result = { echo: input };
      }

      ctx.events.push({
        eventType: "ToolInvoked",
        actorDid: identityDid,
        timestamp: Math.floor(Date.now() / 1000),
        payload: { toolId, toolName: tool.name, ucanProvided: true },
        sequence: ctx.events.length,
      });

      return JSON.stringify(result);
    },

    async toolVerify(handle: BridgeContextHandle, toolId: string): Promise<ToolVerificationResult> {
      const ctx = getContext(handle);
      const tool = ctx.tools.get(toolId) as
        | (ToolDefinition & { handler?: (input: unknown) => unknown })
        | undefined;
      if (tool === undefined) {
        throw new Error(`[SCP-TOOL-6002] Tool not found for verification: ${toolId}`);
      }

      const failures: string[] = [];

      if (tool.testVectors !== undefined && tool.handler !== undefined) {
        for (const vector of tool.testVectors) {
          const actual = tool.handler(vector.input);
          const actualJson = JSON.stringify(actual);
          const expectedJson = JSON.stringify(vector.expectedOutput);
          if (actualJson !== expectedJson) {
            failures.push(`Vector failed: expected ${expectedJson}, got ${actualJson}`);
          }
        }
      }

      return {
        toolId,
        passed: failures.length === 0,
        failures,
      };
    },

    // Transport
    async transportConnect(relayUrl: string): Promise<BridgeTransportHandle> {
      const transport: MockTransport = { relayUrl, connected: true };
      transports.set(relayUrl, transport);
      return { isConnected: true, relayUrl };
    },

    async transportStatus(handle: BridgeTransportHandle): Promise<TransportStatus> {
      return {
        connected: handle.isConnected,
        relayUrl: handle.relayUrl,
        latencyMs: handle.isConnected ? 42 : null,
      };
    },

    async transportDisconnect(handle: BridgeTransportHandle): Promise<void> {
      if (handle.relayUrl !== null) {
        const transport = transports.get(handle.relayUrl);
        if (transport !== undefined) {
          transport.connected = false;
        }
      }
    },

    // UCAN
    async ucanValidate(
      handle: BridgeContextHandle,
      token: string,
      capability: string,
    ): Promise<void> {
      const ctx = getContext(handle);

      if (ctx.revokedTokens.has(token)) {
        throw new Error(`[SCP-PERM-3001] Token has been revoked`);
      }

      // Find the token in minted tokens by encoded string
      let found = false;
      for (const [_id, ucan] of ctx.ucans) {
        if (ucan.encoded === token) {
          // Check if capability is in the token
          if (!ucan.capabilities.includes(capability)) {
            throw new Error(`[SCP-PERM-3002] Token does not grant capability: ${capability}`);
          }
          found = true;
          break;
        }
      }

      if (!found) {
        throw new Error(`[SCP-PERM-3003] Token not recognized in context`);
      }
    },

    async ucanMint(
      handle: BridgeContextHandle,
      memberDid: string,
      capabilities: readonly string[],
    ): Promise<UcanToken> {
      const ctx = getContext(handle);
      const tokenId = generateId("ucan");
      const encoded = `eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.${Buffer.from(
        JSON.stringify({
          iss: ctx.creatorDid,
          aud: memberDid,
          cap: capabilities,
          exp: Math.floor(Date.now() / 1000) + 3600,
        }),
      ).toString("base64url")}.mock-signature-${tokenId}`;

      const token: UcanToken = {
        id: tokenId,
        encoded,
        issuer: ctx.creatorDid,
        audience: memberDid,
        capabilities: [...capabilities],
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      };

      ctx.ucans.set(tokenId, token);
      return token;
    },

    async ucanRevoke(handle: BridgeContextHandle, token: string): Promise<void> {
      const ctx = getContext(handle);
      ctx.revokedTokens.add(token);
    },

    // Event Log
    async eventLogQuery(
      handle: BridgeContextHandle,
      filter: EventFilter | undefined,
    ): Promise<readonly Event[]> {
      const ctx = getContext(handle);
      let events = [...ctx.events];

      if (filter !== undefined) {
        if (filter.eventType !== undefined) {
          events = events.filter((e) => e.eventType === filter.eventType);
        }
        if (filter.actorDid !== undefined) {
          events = events.filter((e) => e.actorDid === filter.actorDid);
        }
        if (filter.afterSequence !== undefined) {
          const afterSeq = filter.afterSequence;
          events = events.filter((e) => e.sequence > afterSeq);
        }
        if (filter.beforeSequence !== undefined) {
          const beforeSeq = filter.beforeSequence;
          events = events.filter((e) => e.sequence < beforeSeq);
        }
        if (filter.limit !== undefined) {
          events = events.slice(0, filter.limit);
        }
      }

      return events;
    },

    async eventLogVerify(handle: BridgeContextHandle, claim: EventClaim): Promise<Proof> {
      const ctx = getContext(handle);

      if (claim.type === "inclusion" && claim.leafIndex !== undefined) {
        const exists = claim.leafIndex < ctx.events.length;
        return {
          verified: exists,
          proofType: "inclusion",
          details: {
            leafIndex: claim.leafIndex,
            treeSize: ctx.events.length,
          },
        };
      }

      return {
        verified: false,
        proofType: "absence",
        details: { reason: "Event not found" },
      };
    },

    async eventLogCheckpoint(handle: BridgeContextHandle): Promise<Checkpoint> {
      const ctx = getContext(handle);
      // Compute a simple mock root hash from event count
      const root = Buffer.from(`mock-root-${ctx.events.length}`).toString("hex");
      return {
        root,
        eventCount: ctx.events.length,
        timestamp: Math.floor(Date.now() / 1000),
      };
    },

    // TTL
    async contextTtlRemaining(_handle: BridgeContextHandle): Promise<number | null> {
      return null;
    },

    async contextExtendTtl(
      _handle: BridgeContextHandle,
      _additionalSecs: number,
    ): Promise<boolean> {
      return true;
    },

    // Economic policy (§19.3)
    async contextSetEconomicPolicy(handle: BridgeContextHandle, policyJson: string): Promise<void> {
      const ctx = getContext(handle);
      ctx.economicPolicy = policyJson;
    },

    async contextGetEconomicPolicy(handle: BridgeContextHandle): Promise<string | null> {
      const ctx = getContext(handle);
      return ctx.economicPolicy;
    },

    // Lifecycle
    version(): string {
      return "0.1.0-mock";
    },

    shutdown(_timeoutSecs: number): void {
      identities.clear();
      contexts.clear();
      transports.clear();
    },
  };

  return bridge;
}
