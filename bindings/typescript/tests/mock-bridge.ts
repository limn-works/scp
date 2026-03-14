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

    async eventLogCheckpoint(handle: BridgeContextHandle): Promise<Checkpoint> {
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
        },
      };
      return new TextEncoder().encode(JSON.stringify(exportData));
    },

    async contextImport(data: Uint8Array): Promise<string> {
      const json = new TextDecoder().decode(data);
      let parsed: { snapshot?: { context_id?: string; creator_did?: string; members?: string[] } };
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
        mode: "Encrypted",
        broadcastSubscribers: new Set(),
        broadcastBlockedSubscribers: new Set(),
        broadcastAdmission: null,
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
      if (rotateKeys === true) {
        // Record a key rotation event so tests can verify the parameter was observed.
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
      _payload: Uint8Array,
    ): Promise<void> {
      const ctx = getContext(handle);
      if (ctx.mode !== "Broadcast") {
        throw new Error("[SCP-CTX-2001] Context is not a broadcast context");
      }
      if (!ctx.members.has(authorDid)) {
        throw new Error("[SCP-CTX-2001] Author is not a member of the context");
      }
    },

    async broadcastBlockSubscriber(
      handle: BridgeContextHandle,
      subscriberDid: string,
      _blockerDid: string,
    ): Promise<void> {
      const ctx = getContext(handle);
      if (ctx.mode !== "Broadcast") {
        throw new Error("[SCP-CTX-2001] Context is not a broadcast context");
      }
      ctx.broadcastSubscribers.delete(subscriberDid);
      ctx.broadcastBlockedSubscribers.add(subscriberDid);
    },

    async broadcastUnblockSubscriber(
      handle: BridgeContextHandle,
      subscriberDid: string,
      _unblockerDid: string,
    ): Promise<void> {
      const ctx = getContext(handle);
      if (ctx.mode !== "Broadcast") {
        throw new Error("[SCP-CTX-2001] Context is not a broadcast context");
      }
      ctx.broadcastBlockedSubscribers.delete(subscriberDid);
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
      if (ctx.broadcastBlockedSubscribers.has(requesterDid)) {
        return "Denied(Blocked)";
      }
      if (ctx.broadcastSubscribers.has(requesterDid)) {
        return "Granted";
      }
      return "Denied(NotSubscribed)";
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
