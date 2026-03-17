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

import type { BridgeMode, ShadowStatus } from "../src/bridge";
import type {
  Bridge,
  BridgeContextHandle,
  BridgeIdentityHandle,
  BridgeTransportHandle,
  MessageCallback,
} from "../src/internal/bridge";
import type {
  BroadcastAdmissionPolicy,
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

interface MockSession {
  sessionId: string;
  toolId: string;
  sourceContextId: string;
  callCount: number;
  ttlSeconds?: number;
  createdAt: number;
}

interface MockContext {
  contextId: string;
  state: string;
  creatorDid: string;
  receiveBuffer: Event[];
  eventLog: Event[];
  tools: Map<string, ToolDefinition & { handler?: (input: unknown) => unknown }>;
  members: Set<string>;
  subscriptions: MessageCallback[];
  ucans: Map<string, UcanToken>;
  revokedTokens: Set<string>;
  economicPolicy: string | null;
  ttlSecs: number | null;
  mode: string;
  broadcastSubscribers: Set<string>;
  broadcastBlockedSubscribers: Set<string>;
  broadcastAdmission: BroadcastAdmissionPolicy | null;
  sessions: Map<string, MockSession>;
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

  function getContextRaw(handle: BridgeContextHandle): MockContext {
    const ctx = contexts.get(handle.contextId);
    if (ctx === undefined) {
      throw new Error(`[SCP-CTX-2001] Context not found: ${handle.contextId}`);
    }
    return ctx;
  }

  function getContext(handle: BridgeContextHandle): MockContext {
    const ctx = getContextRaw(handle);
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
      const params = JSON.parse(paramsJson) as { ttlSeconds?: number; mode?: string };
      const contextId = generateId("ctx");
      const mode = params.mode ?? "Encrypted";
      const ctx: MockContext = {
        contextId,
        state: "active",
        creatorDid: identity.did,
        receiveBuffer: [],
        eventLog: [],
        tools: new Map(),
        members: new Set([identity.did]),
        subscriptions: [],
        ucans: new Map(),
        revokedTokens: new Set(),
        economicPolicy: null,
        ttlSecs: params.ttlSeconds ?? null,
        mode,
        broadcastSubscribers: new Set(),
        broadcastBlockedSubscribers: new Set(),
        broadcastAdmission: mode === "Broadcast" ? "Open" : null,
        sessions: new Map(),
      };

      // Record ContextCreated event
      const createdEvent: Event = {
        eventType: "ContextCreated",
        actorDid: identity.did,
        timestamp: Math.floor(Date.now() / 1000),
        payload: { contextId },
        sequence: ctx.eventLog.length,
      };
      ctx.receiveBuffer.push(createdEvent);
      ctx.eventLog.push(createdEvent);

      contexts.set(contextId, ctx);
      return { contextId, state: "active", creatorDid: identity.did };
    },

    async contextJoin(handle: BridgeContextHandle, identityDid: string): Promise<void> {
      const ctx = getContext(handle);
      ctx.members.add(identityDid);
      const joinedEvent: Event = {
        eventType: "MemberJoined",
        actorDid: identityDid,
        timestamp: Math.floor(Date.now() / 1000),
        payload: { memberDid: identityDid },
        sequence: ctx.eventLog.length,
      };
      ctx.receiveBuffer.push(joinedEvent);
      ctx.eventLog.push(joinedEvent);
    },

    async contextLeave(handle: BridgeContextHandle, identityDid: string): Promise<void> {
      const ctx = getContext(handle);
      ctx.members.delete(identityDid);
      const leftEvent: Event = {
        eventType: "MemberLeft",
        actorDid: identityDid,
        timestamp: Math.floor(Date.now() / 1000),
        payload: { memberDid: identityDid },
        sequence: ctx.eventLog.length,
      };
      ctx.receiveBuffer.push(leftEvent);
      ctx.eventLog.push(leftEvent);
      // Notify subscriptions that context is done for this member
      for (const sub of ctx.subscriptions) {
        sub.onComplete();
      }
    },

    async contextClose(handle: BridgeContextHandle, identityDid: string): Promise<void> {
      const ctx = getContext(handle);
      ctx.state = "closed";
      const closedEvent: Event = {
        eventType: "ContextClosed",
        actorDid: identityDid,
        timestamp: Math.floor(Date.now() / 1000),
        payload: {},
        sequence: ctx.eventLog.length,
      };
      ctx.receiveBuffer.push(closedEvent);
      ctx.eventLog.push(closedEvent);
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
      const sequence = ctx.eventLog.length;
      const timestamp = Math.floor(Date.now() / 1000);

      const sentEvent: Event = {
        eventType: "MessageSent",
        actorDid: identityDid,
        timestamp,
        payload: { size: payload.length },
        sequence,
      };
      ctx.receiveBuffer.push(sentEvent);
      ctx.eventLog.push(sentEvent);

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

      const registeredEvent: Event = {
        eventType: "ToolRegistered",
        actorDid: handle.creatorDid,
        timestamp: Math.floor(Date.now() / 1000),
        payload: { toolId, toolName: definition.name },
        sequence: ctx.eventLog.length,
      };
      ctx.receiveBuffer.push(registeredEvent);
      ctx.eventLog.push(registeredEvent);

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

      const invokedEvent: Event = {
        eventType: "ToolInvoked",
        actorDid: identityDid,
        timestamp: Math.floor(Date.now() / 1000),
        payload: { toolId, toolName: tool.name, ucanProvided: true },
        sequence: ctx.eventLog.length,
      };
      ctx.receiveBuffer.push(invokedEvent);
      ctx.eventLog.push(invokedEvent);

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

    // Cross-context tool invocation (spec section 6.2)
    async toolInvokeCrossContext(
      sourceHandle: BridgeContextHandle,
      targetHandle: BridgeContextHandle,
      toolId: string,
      inputJson: string,
      invokerDid: string,
      _ucanToken: string,
      chainDepth: number,
      _proofTokens?: readonly string[],
    ): Promise<string> {
      const sourceCtx = getContextRaw(sourceHandle);
      const targetCtx = getContextRaw(targetHandle);

      if (sourceCtx.state !== "active") {
        throw new Error(`[SCP-TOOL-6010] Source context in "${sourceCtx.state}" state`);
      }
      if (targetCtx.state !== "active") {
        throw new Error(`[SCP-TOOL-6011] Target context in "${targetCtx.state}" state`);
      }
      if (chainDepth > 5) {
        throw new Error(
          `[SCP-TOOL-6012] Chain depth ${chainDepth} exceeds protocol hard maximum 5`,
        );
      }

      const tool = targetCtx.tools.get(toolId);
      if (tool === undefined) {
        throw new Error(`[SCP-TOOL-6002] Tool '${toolId}' not found in target context`);
      }

      const input = JSON.parse(inputJson);
      if (tool.handler !== undefined) {
        const output = tool.handler(input);
        return JSON.stringify(output);
      }

      return JSON.stringify({
        tool: toolId,
        source_context: sourceCtx.contextId,
        target_context: targetCtx.contextId,
        status: "validated",
        chain_depth: chainDepth,
        invoker_did: invokerDid,
        validated_input: input,
      });
    },

    // Stateful tool sessions (spec section 6.2.1)
    async toolSessionCreate(
      handle: BridgeContextHandle,
      toolId: string,
      sourceContextId: string,
      ttlSeconds?: number,
    ): Promise<string> {
      const ctx = getContext(handle);
      if (ctx.state !== "active") {
        throw new Error(`[SCP-TOOL-6014] Cannot create session in context in "${ctx.state}" state`);
      }

      if (!ctx.tools.has(toolId)) {
        throw new Error(`[SCP-TOOL-6002] Tool '${toolId}' not found`);
      }

      // Per-caller session cap (5 per spec section 6.2.1)
      let callerSessions = 0;
      for (const session of ctx.sessions.values()) {
        if (session.sourceContextId === sourceContextId) callerSessions++;
      }
      if (callerSessions >= 5) {
        throw new Error(`[SCP-TOOL-6015] Session cap exceeded for caller '${sourceContextId}'`);
      }

      const sessionId = `session-${nextId++}`;
      const session: MockSession = {
        sessionId,
        toolId,
        sourceContextId,
        callCount: 0,
        createdAt: Date.now(),
      };
      if (ttlSeconds !== undefined) {
        session.ttlSeconds = ttlSeconds;
      }
      ctx.sessions.set(sessionId, session);
      return sessionId;
    },

    async toolSessionInvoke(
      handle: BridgeContextHandle,
      sessionId: string,
      inputJson: string,
      invokerDid: string,
      _ucanToken: string,
      _proofTokens?: readonly string[],
    ): Promise<string> {
      const ctx = getContext(handle);
      if (ctx.state !== "active") {
        throw new Error(`[SCP-TOOL-6017] Cannot invoke session in context in "${ctx.state}" state`);
      }

      const session = ctx.sessions.get(sessionId);
      if (session === undefined) {
        throw new Error(`[SCP-TOOL-6018] Session '${sessionId}' not found`);
      }

      // Check TTL expiry
      if (session.ttlSeconds !== undefined) {
        const elapsed = (Date.now() - session.createdAt) / 1000;
        if (elapsed > session.ttlSeconds) {
          ctx.sessions.delete(sessionId);
          throw new Error(`[SCP-TOOL-6019] Session '${sessionId}' has expired`);
        }
      }

      const tool = ctx.tools.get(session.toolId);
      const input = JSON.parse(inputJson);
      session.callCount++;

      if (tool?.handler !== undefined) {
        const output = tool.handler(input);
        return JSON.stringify(output);
      }

      return JSON.stringify({
        tool: session.toolId,
        session_id: sessionId,
        status: "validated",
        call_count: session.callCount,
        invoker_did: invokerDid,
        validated_input: input,
      });
    },

    async toolSessionClose(handle: BridgeContextHandle, sessionId: string): Promise<void> {
      const ctx = getContext(handle);
      if (!ctx.sessions.has(sessionId)) {
        throw new Error(`[SCP-TOOL-6021] Session '${sessionId}' not found`);
      }
      ctx.sessions.delete(sessionId);
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

    async ucanRevoke(
      handle: BridgeContextHandle,
      token: string,
      _revokerDid: string,
    ): Promise<void> {
      const ctx = getContext(handle);
      ctx.revokedTokens.add(token);
    },

    async ucanDelegate(
      handle: BridgeContextHandle,
      delegatorDid: string,
      delegateeDid: string,
      parentToken: string,
      capabilities: readonly string[],
    ): Promise<UcanToken> {
      const ctx = getContext(handle);

      // Find the parent token by encoded string
      let parentUcan: UcanToken | undefined;
      for (const [_id, ucan] of ctx.ucans) {
        if (ucan.encoded === parentToken) {
          parentUcan = ucan;
          break;
        }
      }
      if (parentUcan === undefined) {
        throw new Error("[SCP-PERM-3000] Parent token not recognized in context");
      }

      // Verify delegator matches parent audience (iss/aud chain linkage)
      if (parentUcan.audience !== delegatorDid) {
        throw new Error(
          `[SCP-PERM-3000] Delegator DID '${delegatorDid}' does not match parent token audience '${parentUcan.audience}'`,
        );
      }

      // Verify attenuation: requested capabilities must be subset of parent
      const parentCaps = new Set(parentUcan.capabilities);
      for (const cap of capabilities) {
        if (!parentCaps.has(cap)) {
          throw new Error(`[SCP-PERM-3000] Cannot delegate capability not in parent: ${cap}`);
        }
      }

      // Mint the delegated token
      const tokenId = generateId("ucan");
      const encoded = `eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.${Buffer.from(
        JSON.stringify({
          iss: delegatorDid,
          aud: delegateeDid,
          cap: capabilities,
          prf: [parentUcan.id],
          exp: Math.floor(Date.now() / 1000) + 3600,
        }),
      ).toString("base64url")}.mock-signature-${tokenId}`;

      const token: UcanToken = {
        id: tokenId,
        encoded,
        issuer: delegatorDid,
        audience: delegateeDid,
        capabilities: [...capabilities],
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      };

      ctx.ucans.set(tokenId, token);
      return token;
    },

    // Event Log
    async eventLogQuery(
      handle: BridgeContextHandle,
      filter: EventFilter | undefined,
    ): Promise<readonly Event[]> {
      const ctx = getContext(handle);
      let events = [...ctx.eventLog];

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
        const exists = claim.leafIndex < ctx.eventLog.length;
        return {
          verified: exists,
          proofType: "inclusion",
          details: {
            leafIndex: claim.leafIndex,
            treeSize: ctx.eventLog.length,
          },
        };
      }

      return {
        verified: false,
        proofType: "absence",
        details: { reason: "Event not found" },
      };
    },

    async eventLogCheckpoint(
      handle: BridgeContextHandle,
      _identityDid: string,
      _epoch: number,
    ): Promise<Checkpoint> {
      const ctx = getContext(handle);
      // Compute a simple mock root hash from event count
      const root = Buffer.from(`mock-root-${ctx.eventLog.length}`).toString("hex");
      return {
        root,
        eventCount: ctx.eventLog.length,
        timestamp: Math.floor(Date.now() / 1000),
      };
    },

    // TTL
    async contextTtlRemaining(_handle: BridgeContextHandle): Promise<number | null> {
      return null;
    },

    async contextExtendTtl(handle: BridgeContextHandle, additionalSecs: number): Promise<boolean> {
      const ctx = getContext(handle);
      if (ctx.ttlSecs !== null) {
        ctx.ttlSecs += additionalSecs;
      }
      return true;
    },

    async contextHandleTtlExpiry(handle: BridgeContextHandle): Promise<void> {
      const ctx = getContext(handle);
      ctx.state = "expired";
      const expiredEvent: Event = {
        eventType: "TtlExpired",
        actorDid: ctx.creatorDid,
        timestamp: Math.floor(Date.now() / 1000),
        payload: {},
        sequence: ctx.eventLog.length,
      };
      ctx.receiveBuffer.push(expiredEvent);
      ctx.eventLog.push(expiredEvent);
      for (const sub of ctx.subscriptions) {
        sub.onComplete();
      }
    },

    async contextProposeTtlExtension(
      handle: BridgeContextHandle,
      _proposerDid: string,
      extensionSecs: number,
    ): Promise<boolean> {
      const ctx = getContext(handle);
      // In the mock, single-member contexts auto-approve
      const approved = ctx.members.size <= 1;
      if (approved && ctx.ttlSecs !== null) {
        ctx.ttlSecs += extensionSecs;
      }
      return approved;
    },

    async contextResetTtlTimer(
      handle: BridgeContextHandle,
      newDurationSecs: number,
    ): Promise<void> {
      const ctx = getContext(handle);
      ctx.ttlSecs = newDurationSecs;
    },

    async contextExport(handle: BridgeContextHandle): Promise<Uint8Array> {
      const ctx = getContext(handle);
      const exportData = {
        snapshot: {
          context_id: ctx.contextId,
          creator_did: ctx.creatorDid,
          state: ctx.state,
          members: [...ctx.members],
          event_count: ctx.eventLog.length,
          mode: ctx.mode,
          broadcast_subscribers: [...ctx.broadcastSubscribers],
          broadcast_blocked_subscribers: [...ctx.broadcastBlockedSubscribers],
          broadcast_admission: ctx.broadcastAdmission,
        },
      };
      return new TextEncoder().encode(JSON.stringify(exportData));
    },

    async contextImport(data: Uint8Array): Promise<string> {
      const json = new TextDecoder().decode(data);
      let parsed: {
        snapshot?: {
          context_id?: string;
          creator_did?: string;
          members?: string[];
          mode?: string;
          broadcast_subscribers?: string[];
          broadcast_blocked_subscribers?: string[];
          broadcast_admission?: BroadcastAdmissionPolicy | null;
        };
      };
      try {
        parsed = JSON.parse(json) as typeof parsed;
      } catch {
        throw new Error("[SCP-CTX-2032] Invalid export data: malformed JSON");
      }
      const snapshot = parsed.snapshot;
      if (snapshot === undefined || snapshot.context_id === undefined) {
        throw new Error("[SCP-CTX-2032] Invalid export data: missing snapshot");
      }
      const contextId = snapshot.context_id;
      const creatorDid = snapshot.creator_did ?? "did:dht:unknown";
      const members = snapshot.members ?? [creatorDid];
      const mode = snapshot.mode ?? "Encrypted";
      const ctx: MockContext = {
        contextId,
        state: "active",
        creatorDid,
        receiveBuffer: [],
        eventLog: [],
        tools: new Map(),
        members: new Set(members),
        subscriptions: [],
        ucans: new Map(),
        revokedTokens: new Set(),
        economicPolicy: null,
        ttlSecs: null,
        mode,
        broadcastSubscribers: new Set(snapshot.broadcast_subscribers ?? []),
        broadcastBlockedSubscribers: new Set(snapshot.broadcast_blocked_subscribers ?? []),
        broadcastAdmission: snapshot.broadcast_admission ?? (mode === "Broadcast" ? "Open" : null),
        sessions: new Map(),
      };
      const importedEvent: Event = {
        eventType: "ContextImported",
        actorDid: creatorDid,
        timestamp: Math.floor(Date.now() / 1000),
        payload: { contextId },
        sequence: 0,
      };
      ctx.receiveBuffer.push(importedEvent);
      ctx.eventLog.push(importedEvent);
      contexts.set(contextId, ctx);
      return contextId;
    },

    async contextDrainEvents(handle: BridgeContextHandle): Promise<readonly string[]> {
      const ctx = getContext(handle);
      const events = ctx.receiveBuffer.map((e) => JSON.stringify(e));
      ctx.receiveBuffer.length = 0;
      return events;
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

    // Broadcast operations
    async broadcastSubscribe(handle: BridgeContextHandle, subscriberDid: string): Promise<void> {
      const ctx = getContext(handle);
      if (ctx.mode !== "Broadcast") {
        throw new Error("[SCP-CTX-2001] Context is not a broadcast context");
      }
      if (ctx.broadcastBlockedSubscribers.has(subscriberDid)) {
        throw new Error("[SCP-CTX-2001] Subscriber is blocked");
      }
      ctx.broadcastSubscribers.add(subscriberDid);

      const subscribedEvent: Event = {
        eventType: "BroadcastSubscribed",
        actorDid: subscriberDid,
        timestamp: Math.floor(Date.now() / 1000),
        payload: { subscriberDid },
        sequence: ctx.eventLog.length,
      };
      ctx.receiveBuffer.push(subscribedEvent);
      ctx.eventLog.push(subscribedEvent);
    },

    async broadcastUnsubscribe(
      handle: BridgeContextHandle,
      subscriberDid: string,
      rotateKeys?: boolean,
    ): Promise<void> {
      const ctx = getContext(handle);
      if (ctx.mode !== "Broadcast") {
        throw new Error("[SCP-CTX-2001] Context is not a broadcast context");
      }
      ctx.broadcastSubscribers.delete(subscriberDid);

      const unsubscribedEvent: Event = {
        eventType: "BroadcastUnsubscribed",
        actorDid: subscriberDid,
        timestamp: Math.floor(Date.now() / 1000),
        payload: { subscriberDid },
        sequence: ctx.eventLog.length,
      };
      ctx.receiveBuffer.push(unsubscribedEvent);
      ctx.eventLog.push(unsubscribedEvent);

      if (rotateKeys === true) {
        const rotateEvent: Event = {
          eventType: "BroadcastKeyRotated",
          actorDid: handle.creatorDid,
          timestamp: Math.floor(Date.now() / 1000),
          payload: { reason: "subscriber_removed", subscriberDid },
          sequence: ctx.eventLog.length,
        };
        ctx.receiveBuffer.push(rotateEvent);
        ctx.eventLog.push(rotateEvent);
      }
    },

    async broadcastPublish(
      handle: BridgeContextHandle,
      authorDid: string,
      payload: Uint8Array,
    ): Promise<void> {
      const ctx = getContext(handle);
      if (ctx.mode !== "Broadcast") {
        throw new Error("[SCP-CTX-2001] Context is not a broadcast context");
      }
      if (!ctx.members.has(authorDid)) {
        throw new Error("[SCP-CTX-2001] Author is not a member of the context");
      }

      const publishedEvent: Event = {
        eventType: "BroadcastPublished",
        actorDid: authorDid,
        timestamp: Math.floor(Date.now() / 1000),
        payload: { size: payload.length },
        sequence: ctx.eventLog.length,
      };
      ctx.receiveBuffer.push(publishedEvent);
      ctx.eventLog.push(publishedEvent);
    },

    async broadcastPublishAsset(
      handle: BridgeContextHandle,
      _authorDid: string,
      _asset: { path: string; contentType: string; body: number[] },
      _deployId: string | null,
    ): Promise<{ blobId: string; etag: string; deployId: string }> {
      const ctx = getContext(handle);
      if (ctx.mode !== "Broadcast") {
        throw new Error("[SCP-CTX-2001] Context is not a broadcast context");
      }
      const did = _deployId ?? `mock-deploy-${Date.now().toString(16)}`;
      return { blobId: `mock-blob-id-${ctx.eventLog.length}`, etag: "mock-etag", deployId: did };
    },

    async broadcastPublishAssets(
      handle: BridgeContextHandle,
      authorDid: string,
      assets: { path: string; contentType: string; body: number[] }[],
      deployId: string | null,
    ): Promise<{
      results: { blobId: string; etag: string; deployId: string }[];
      deployId: string;
    }> {
      const did = deployId ?? `mock-deploy-${Date.now().toString(16)}`;
      const results: { blobId: string; etag: string; deployId: string }[] = [];
      for (const asset of assets) {
        const result = await this.broadcastPublishAsset(handle, authorDid, asset, did);
        results.push(result);
      }
      return { results, deployId: did };
    },

    async broadcastBlockSubscriber(
      handle: BridgeContextHandle,
      subscriberDid: string,
      blockerDid: string,
    ): Promise<void> {
      const ctx = getContext(handle);
      if (ctx.mode !== "Broadcast") {
        throw new Error("[SCP-CTX-2001] Context is not a broadcast context");
      }
      ctx.broadcastSubscribers.delete(subscriberDid);
      ctx.broadcastBlockedSubscribers.add(subscriberDid);

      const blockedEvent: Event = {
        eventType: "BroadcastSubscriberBlocked",
        actorDid: blockerDid,
        timestamp: Math.floor(Date.now() / 1000),
        payload: { subscriberDid },
        sequence: ctx.eventLog.length,
      };
      ctx.receiveBuffer.push(blockedEvent);
      ctx.eventLog.push(blockedEvent);
    },

    async broadcastUnblockSubscriber(
      handle: BridgeContextHandle,
      subscriberDid: string,
      unblockerDid: string,
    ): Promise<void> {
      const ctx = getContext(handle);
      if (ctx.mode !== "Broadcast") {
        throw new Error("[SCP-CTX-2001] Context is not a broadcast context");
      }
      ctx.broadcastBlockedSubscribers.delete(subscriberDid);

      const unblockedEvent: Event = {
        eventType: "BroadcastSubscriberUnblocked",
        actorDid: unblockerDid,
        timestamp: Math.floor(Date.now() / 1000),
        payload: { subscriberDid },
        sequence: ctx.eventLog.length,
      };
      ctx.receiveBuffer.push(unblockedEvent);
      ctx.eventLog.push(unblockedEvent);
    },

    async broadcastHandleKeyRequest(
      handle: BridgeContextHandle,
      authorDid: string,
      requesterDid: string,
    ): Promise<string> {
      const ctx = getContext(handle);
      if (ctx.mode !== "Broadcast") {
        throw new Error("[SCP-CTX-2001] Context is not a broadcast context");
      }
      if (!ctx.members.has(authorDid)) {
        throw new Error("[SCP-CTX-2001] Author is not a member of the context");
      }

      let result: string;
      if (ctx.broadcastBlockedSubscribers.has(requesterDid)) {
        result = "Denied(Blocked)";
      } else if (ctx.broadcastSubscribers.has(requesterDid)) {
        result = "Granted";
      } else {
        result = "Denied(NotSubscribed)";
      }

      const keyRequestEvent: Event = {
        eventType: "BroadcastKeyRequestHandled",
        actorDid: authorDid,
        timestamp: Math.floor(Date.now() / 1000),
        payload: { requesterDid, result },
        sequence: ctx.eventLog.length,
      };
      ctx.receiveBuffer.push(keyRequestEvent);
      ctx.eventLog.push(keyRequestEvent);

      return result;
    },

    async broadcastSubscriberCount(handle: BridgeContextHandle): Promise<number | null> {
      const ctx = contexts.get(handle.contextId);
      if (ctx === undefined || ctx.mode !== "Broadcast") {
        return null;
      }
      return ctx.broadcastSubscribers.size;
    },

    async broadcastIsSubscriber(handle: BridgeContextHandle, did: string): Promise<boolean> {
      const ctx = contexts.get(handle.contextId);
      if (ctx === undefined || ctx.mode !== "Broadcast") {
        return false;
      }
      return ctx.broadcastSubscribers.has(did);
    },

    async broadcastAdmission(
      handle: BridgeContextHandle,
    ): Promise<BroadcastAdmissionPolicy | null> {
      const ctx = contexts.get(handle.contextId);
      if (ctx === undefined || ctx.mode !== "Broadcast") {
        return null;
      }
      return ctx.broadcastAdmission;
    },

    // Governance lifecycle (#559)
    async contextExecuteGovernanceAction(
      _handle: BridgeContextHandle,
      _actionJson: string,
      _proposerDid: string,
    ): Promise<string> {
      return JSON.stringify({ status: "executed" });
    },

    async contextGovernancePropose(
      _handle: BridgeContextHandle,
      _actionJson: string,
      _proposerDid: string,
    ): Promise<string> {
      return JSON.stringify({ proposal_id: generateId("proposal") });
    },

    async contextGovernanceApprove(
      _handle: BridgeContextHandle,
      _proposalIdHex: string,
      _voterDid: string,
    ): Promise<string> {
      return JSON.stringify({ status: "approved" });
    },

    async contextGovernanceReject(
      _handle: BridgeContextHandle,
      _proposalIdHex: string,
      _voterDid: string,
    ): Promise<string> {
      return JSON.stringify({ status: "rejected" });
    },

    async contextGovernanceWithdraw(
      _handle: BridgeContextHandle,
      _proposalIdHex: string,
      _voterDid: string,
    ): Promise<string> {
      return JSON.stringify({ status: "withdrawn" });
    },

    async contextGovernanceGetProposal(
      _handle: BridgeContextHandle,
      _proposalIdHex: string,
    ): Promise<string> {
      return JSON.stringify({ status: "pending", votes: [] });
    },

    async contextGovernanceListProposals(_handle: BridgeContextHandle): Promise<string> {
      return JSON.stringify([]);
    },

    async contextApplyPendingCeilingModification(
      _handle: BridgeContextHandle,
      _currentTimestamp: number,
    ): Promise<boolean> {
      return false;
    },

    async contextFinalizeClose(handle: BridgeContextHandle): Promise<void> {
      const ctx = contexts.get(handle.contextId);
      if (ctx !== undefined) {
        ctx.state = "closed";
      }
    },

    async contextCreateGovernanceCheckpoint(
      _handle: BridgeContextHandle,
      _checkpointSeq: number,
      _merkleRootHex: string,
      _eventCount: number,
      _lastEventHashHex: string,
      _stateSnapshotHashHex: string,
      _creatorDid: string,
      _creatorSignatureHex: string,
    ): Promise<string> {
      return JSON.stringify({ checkpoint_seq: _checkpointSeq, status: "created" });
    },

    async contextAddCheckpointCosignature(
      _handle: BridgeContextHandle,
      _checkpointJson: string,
      _signerDid: string,
      _signatureHex: string,
    ): Promise<string> {
      return JSON.stringify({ attestation_status: "cosigned" });
    },

    async contextRestore(_contextId: string): Promise<void> {
      // Mock: no-op
    },

    async contextRestoreAll(): Promise<string> {
      return JSON.stringify([]);
    },

    // Membership queries
    async contextMemberCount(handle: BridgeContextHandle): Promise<number | null> {
      const ctx = contexts.get(handle.contextId);
      if (ctx === undefined) return null;
      return ctx.members.size;
    },

    async contextIsMember(handle: BridgeContextHandle, did: string): Promise<boolean> {
      const ctx = contexts.get(handle.contextId);
      if (ctx === undefined) return false;
      return ctx.members.has(did);
    },

    async contextMemberDids(handle: BridgeContextHandle): Promise<readonly string[]> {
      const ctx = contexts.get(handle.contextId);
      if (ctx === undefined) return [];
      return [...ctx.members];
    },

    async contextMemberRole(
      _handle: BridgeContextHandle,
      _did: string,
    ): Promise<import("../src/types").MemberRole | null> {
      return null;
    },

    // SCPID authentication (§3.11)
    scpidChallenge(audience: string, ttlSeconds: number): string {
      if (audience === "") {
        throw new Error("[SCP-VALID-7000] audience must not be empty");
      }
      if (ttlSeconds <= 0 || ttlSeconds > 300) {
        throw new Error("[SCP-VALID-7000] ttl_seconds must be between 1 and 300");
      }
      const issuedAt = Date.now();
      const expiresAt = issuedAt + ttlSeconds * 1000;
      const nonce = Array.from({ length: 64 }, () =>
        Math.floor(Math.random() * 16).toString(16),
      ).join("");
      return JSON.stringify({
        protocol: "scpid/1.0",
        nonce,
        audience,
        issued_at: issuedAt,
        expires_at: expiresAt,
      });
    },

    scpidSign(did: string, signingKeyId: string, challengeJson: string): string {
      if (signingKeyId !== "#active" && signingKeyId !== "#agent") {
        throw new Error(
          `[SCP-IDENT-1034] invalid signing_key_id '${signingKeyId}': expected '#active' or '#agent'`,
        );
      }
      const challenge = JSON.parse(challengeJson) as {
        protocol: string;
        nonce: string;
        audience: string;
      };
      const signedAt = Date.now();
      const signature = Array.from({ length: 128 }, () =>
        Math.floor(Math.random() * 16).toString(16),
      ).join("");
      return JSON.stringify({
        protocol: challenge.protocol,
        did,
        signing_key_id: signingKeyId,
        nonce: challenge.nonce,
        audience: challenge.audience,
        signed_at: signedAt,
        signature,
      });
    },

    scpidVerify(responseJson: string, _challengeJson: string): string {
      const response = JSON.parse(responseJson) as {
        did: string;
        signing_key_id: string;
        signed_at: number;
      };
      return JSON.stringify({
        did: response.did,
        signing_key_id: response.signing_key_id,
        signed_at: response.signed_at,
      });
    },

    // Tool interface (§6.2.0.1)
    async toolInterfaceExpose(
      _handle: BridgeContextHandle,
      _toolId: string,
      _targetContextId: string,
      _rateLimitJson?: string,
    ): Promise<string> {
      return JSON.stringify({ interface_id: generateId("iface"), status: "exposed" });
    },

    async toolInterfaceAccept(
      _handle: BridgeContextHandle,
      _interfaceJson: string,
    ): Promise<string> {
      return JSON.stringify({ status: "accepted" });
    },

    async toolInterfaceRevoke(
      _handle: BridgeContextHandle,
      _interfaceIdHex: string,
    ): Promise<string> {
      return JSON.stringify({ status: "revoked" });
    },

    // Trust Aggregation
    async aggregateTrustInput(
      _contextId: string,
      _subjectDid: string,
      _eventsJson: string,
      _merkleRootJson: string,
      _consequenceRulesJson: string,
      _thresholdRequirementsJson: string,
      _attestorSetsJson: string,
      _cachedAttestationsJson: string,
      _challengeResultsJson: string,
    ): Promise<string> {
      return JSON.stringify({ trust_score: 1.0, details: {} });
    },

    // Bridge Connector
    bridgeRegister(
      contextId: string,
      operatorDid: string,
      _governanceDid: string,
      platform: string,
      mode: BridgeMode,
    ): {
      bridge_id: string;
      operator_did: string;
      platform: string;
      mode: BridgeMode;
      status: string;
      context_id: string;
    } {
      return {
        bridge_id: generateId("bridge"),
        operator_did: operatorDid,
        platform,
        mode,
        status: "active",
        context_id: contextId,
      };
    },

    bridgeEvaluateTrust(
      _isBridged: boolean,
      _isNativeTransport: boolean,
      _shadowStatus: ShadowStatus,
    ): number {
      return 3;
    },

    bridgeCreateShadow(
      bridgeId: string,
      platformHandle: string,
      _bridgeMode: BridgeMode,
      _contextId: string | undefined,
    ): {
      shadow_id: string;
      platform_handle: string;
      bridge_id: string;
      attributed_role: string;
      provenance_status: ShadowStatus;
    } {
      return {
        shadow_id: generateId("shadow"),
        platform_handle: platformHandle,
        bridge_id: bridgeId,
        attributed_role: "observer",
        provenance_status: "shadow",
      };
    },

    // Discovery
    discoveryParseAddress(address: string): string {
      return JSON.stringify({ address, parsed: true });
    },

    discoveryCreateQuery(
      _capabilities: string[] | undefined,
      _keywords: string[] | undefined,
      _minHistorySecs: number | undefined,
    ): string {
      return JSON.stringify({ query_id: generateId("query") });
    },

    discoveryNormalizeAddress(address: string): string {
      return address.toLowerCase().trim();
    },

    async contextDiscover(_query: string): Promise<string> {
      return JSON.stringify([]);
    },

    // Petnames (section 22.4)
    petnameSet(_ownerDid: string, _targetDid: string, _name: string): void {
      // no-op
    },

    petnameRemove(_ownerDid: string, _targetDid: string): void {
      // no-op
    },

    petnameSetContext(_ownerDid: string, _contextId: string, _name: string): void {
      // no-op
    },

    petnameRemoveContext(_ownerDid: string, _contextId: string): void {
      // no-op
    },

    petnameResolveDid(_ownerDid: string, _name: string): string {
      return "";
    },

    petnameResolveContext(_ownerDid: string, _name: string): string {
      return "";
    },

    petnameGetForDid(_ownerDid: string, _targetDid: string): string | null {
      return null;
    },

    petnameGetForContext(_ownerDid: string, _contextId: string): string | null {
      return null;
    },

    // Handle Registry (section 22.3.1)
    handleRegister(
      _discoveryContextId: string,
      handle: string,
      _targetJson: string,
      _registrantDid: string,
      _description: string | undefined,
      _tags: string[] | undefined,
    ): string {
      return JSON.stringify({ handle, status: "registered" });
    },

    handleLookup(
      _discoveryContextId: string,
      handle: string,
      _typeFilter: string | undefined,
    ): string {
      return JSON.stringify({ handle, results: [] });
    },

    handleDeregister(_discoveryContextId: string, handle: string, _did: string): string {
      return JSON.stringify({ handle, status: "deregistered" });
    },

    // Scope Registry (section 22.3.5, ADR-043)
    scopeRegister(
      _scopeContextId: string,
      _name: string,
      _targetContextId: string,
      _relayUrls: string[],
      _registrantDid: string,
      _description: string | undefined,
      _tags: string[] | undefined,
    ): string {
      return JSON.stringify({ status: "registered", entry_id: "scope-1" });
    },

    scopeLookup(_scopeContextId: string, _name: string): string {
      return JSON.stringify({ results: [] });
    },

    scopeDeregister(_scopeContextId: string, _name: string, _did: string): string {
      return JSON.stringify({ removed: true });
    },

    // Address Resolution (section 22.8)
    async addressResolve(
      _ownerDid: string,
      _address: string,
      _knownContextsJson: string | undefined,
    ): Promise<string> {
      return JSON.stringify([]);
    },

    // Provenance
    async evaluateProvenanceQuality(
      _sourceContext: string | undefined,
      _sourceType: string,
      _contextState: string,
      _counterparties: string[] | undefined,
    ): Promise<number> {
      return 1.0;
    },

    provenanceAttach(
      sourceContextId: string,
      _sourceType: string,
      _memoryScope: string,
      _members: string[],
      targetContextId: string,
      _actorDid: string,
      _existingChainDepth: number | undefined,
      _discoveryMethod: string | undefined,
      _purpose: string | undefined,
      _counterpartyPolicy: string | undefined,
    ): string {
      return JSON.stringify({
        source_context_id: sourceContextId,
        target_context_id: targetContextId,
        chain_depth: 1,
      });
    },

    provenanceCheckChainDepth(chainDepth: number, maxDepth: number | undefined): boolean {
      return maxDepth === undefined || chainDepth <= maxDepth;
    },

    // Sync
    syncClassifyOffline(_lastRelayContact: number, _now: number): string {
      return "online";
    },

    syncClassifyOfflineCustom(
      _lastRelayContact: number,
      _now: number,
      _tier1ThresholdSecs: number,
      _tier2ThresholdSecs: number,
    ): string {
      return "online";
    },

    syncGetPolicy(): {
      tier_1_threshold_secs: number;
      tier_2_threshold_secs: number;
      gap_timeout_secs: number;
      reorder_buffer_capacity: number;
      max_sequential_commits: number;
      commit_process_timeout_secs: number;
      sender_key_timeout_secs: number;
      reconnection_dedup_window_secs: number;
    } {
      return {
        tier_1_threshold_secs: 300,
        tier_2_threshold_secs: 3600,
        gap_timeout_secs: 30,
        reorder_buffer_capacity: 100,
        max_sequential_commits: 10,
        commit_process_timeout_secs: 5,
        sender_key_timeout_secs: 60,
        reconnection_dedup_window_secs: 10,
      };
    },

    // Identity Advanced
    async identityCreateWithAgentKey(custody: string): Promise<BridgeIdentityHandle> {
      const did = generateDid();
      const identity: MockIdentity = { did, custodyType: custody };
      identities.set(did, identity);
      return { did, custodyType: custody };
    },

    async identityAddAgentKey(handle: BridgeIdentityHandle): Promise<BridgeIdentityHandle> {
      return { did: handle.did, custodyType: handle.custodyType };
    },

    async identityRotateAgentKey(handle: BridgeIdentityHandle): Promise<BridgeIdentityHandle> {
      return { did: handle.did, custodyType: handle.custodyType };
    },

    async identityRemoveAgentKey(handle: BridgeIdentityHandle): Promise<BridgeIdentityHandle> {
      return { did: handle.did, custodyType: handle.custodyType };
    },

    async identityMigrate(handle: BridgeIdentityHandle): Promise<BridgeIdentityHandle> {
      const newDid = generateDid();
      identities.delete(handle.did);
      identities.set(newDid, { did: newDid, custodyType: handle.custodyType });
      return { did: newDid, custodyType: handle.custodyType };
    },

    async identityAttestDevice(_did: string): Promise<string> {
      return JSON.stringify({ attestation_token: "mock-token" });
    },

    async identityVerifyDeviceAttestation(_did: string, tokenBase64: string): Promise<boolean> {
      // Mock: valid tokens contain "mock-token", invalid ones don't
      return tokenBase64.includes("mock-token");
    },

    // Recovery and custody migration (#632, spec §9.12, §3.2.1)
    async identityExecuteRecovery(
      did: string,
      tier: string,
      _contextIds: string[],
    ): Promise<string> {
      return JSON.stringify({
        did,
        tier,
        completed_contexts: [],
        failed_contexts: [],
        key_rotation_completed: true,
      });
    },

    async identityExecuteCustodyMigration(
      did: string,
      target: string,
      _contextIds: string[],
    ): Promise<string> {
      const validTargets = ["platform_managed", "hardware", "software", "in_memory"];
      if (!validTargets.includes(target)) {
        throw new Error(`invalid custody migration target: ${target}`);
      }
      return JSON.stringify({
        did,
        target,
        key_generated: true,
        authorized: true,
        did_document_rotated: true,
        ucans_reissued: true,
        old_key_destroyed: true,
      });
    },

    // App Sandboxing (#595, spec §8.4.1, §8.4.2)
    validateCapabilityDeclaration(
      _declarationJson: string,
      _ceilingCapabilities: string[],
      _roleCapabilities: string[],
    ): string {
      return JSON.stringify({ valid: true, errors: [] });
    },

    checkScopedCapability(
      _grantedCapabilities: readonly string[],
      _requiredCapability: string,
    ): boolean {
      return true;
    },

    // Invitation evaluation (§5.x, context.ts)
    evaluateInvitation(
      _paramsJson: string,
      _inviterDid: string,
      _identityDid: string,
      _policyJson: string | null,
      _spendingJson: string | null,
      _trustedDidsJson: string | null,
    ): { decision: string } {
      return { decision: "accept" };
    },

    // MetadataRecord inspection (§5.7.2, #615)
    metadataRecordToJson(
      _contextId: string,
      _sequence: number,
      _signerDid: string,
      _timestamp: number,
      _structuralJson: string,
      _operationalJson: string,
      _signatureHex: string,
    ): string {
      return JSON.stringify({ context_id: _contextId, sequence: _sequence });
    },

    metadataRecordFromJson(_jsonStr: string): string {
      return JSON.stringify({ parsed: true });
    },

    // Context template inspection (§5.14, #615)
    templateGetParams(_templateId: string): string {
      return JSON.stringify({ params: {} });
    },

    validateAgainstTemplate(_paramsJson: string): string | null {
      return null;
    },

    validateContextParams(_paramsJson: string): string | null {
      return null;
    },

    // Economy (§19, ADR-033)
    economyEstimateCost(_policyJson: string, _actionType: string, _metricsJson: string): number {
      return 0;
    },

    economyPolicyRequiresPayment(_policyJson: string): boolean {
      return false;
    },

    economyAutoAcceptBlocked(_policyJson: string): boolean {
      return false;
    },

    economyCheckPolicyLock(_policyJson: string): boolean {
      return false;
    },

    economyValidatePolicyChange(_currentJson: string, _proposedJson: string): boolean {
      return true;
    },

    economyEvaluateFormula(_formulaJson: string, _metricsJson: string): number {
      return 0;
    },

    economyAdjustRelayPrice(
      _configJson: string,
      _utilizationPct: number,
    ): { newBasePrice: number; previousBasePrice: number; direction: string } {
      return { newBasePrice: 0, previousBasePrice: 0, direction: "unchanged" };
    },

    economyBudgetRemaining(_contextId: string, _did: string): number {
      return 0;
    },

    economyBudgetGrant(_contextId: string, _did: string, _amount: number): void {
      // no-op
    },

    economyBudgetRecordSpend(_contextId: string, _did: string, _amount: number): void {
      // no-op
    },

    economyAntispamRecord(_contextId: string, _senderDid: string, _timestamp: number): void {
      // no-op
    },

    economyAntispamVelocity(_contextId: string, _senderDid: string, _now: number): number {
      return 0;
    },

    economyAntispamEscalatedCost(
      _contextId: string,
      _senderDid: string,
      _now: number,
      baseCost: number,
      _thresholdsJson: string,
      _floor: number | null,
      _cap: number | null,
    ): number {
      return baseCost;
    },

    // Media (ADR-024)
    mediaCheckCapability(_ceiling: string[], _capability: string): boolean {
      return true;
    },

    mediaInitiateSession(
      _contextId: string,
      _ceiling: string[],
      _capabilities: string[],
      _participants: string[],
      _timestamp: number,
    ): string {
      return JSON.stringify({ session_id: generateId("media"), status: "initiated" });
    },

    mediaActivateSession(_sessionJson: string): string {
      return JSON.stringify({ status: "active" });
    },

    mediaJoinSession(_sessionJson: string, _participantDid: string): string {
      return JSON.stringify({ status: "joined" });
    },

    mediaEndSession(_sessionJson: string, _timestamp: number): string {
      return JSON.stringify({ status: "ended" });
    },

    mediaCreateOffer(_sessionId: string, _sdp: string, _senderDid: string): string {
      return JSON.stringify({ type: "offer", session_id: _sessionId });
    },

    mediaCreateAnswer(_sessionId: string, _sdp: string, _senderDid: string): string {
      return JSON.stringify({ type: "answer", session_id: _sessionId });
    },

    mediaCreateIceCandidate(
      _sessionId: string,
      _candidate: string,
      _senderDid: string,
      _sdpMid?: string,
      _sdpMlineIndex?: number,
    ): string {
      return JSON.stringify({ type: "ice_candidate", session_id: _sessionId });
    },

    mediaCreateSessionEnd(_sessionId: string, _senderDid: string): string {
      return JSON.stringify({ type: "session_end", session_id: _sessionId });
    },

    mediaSendSignaling(_signalingJson: string): string {
      return JSON.stringify({ status: "sent" });
    },

    mediaVerifySenderAttribution(_signalingJson: string, _envelopeSenderDid: string): boolean {
      return true;
    },

    // Trust — participation verification (SCP-BA-004, §7.3.2.1)
    verifyParticipationRequirements(_profileJson: string, _requirementsJson: string): boolean {
      // Mock: always succeeds. Tests that need failure behavior should override.
      return true;
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
