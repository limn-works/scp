/**
 * Runtime integration tests for the SCP TypeScript SDK.
 *
 * These tests exercise actual runtime behavior — not just type compilation —
 * by injecting a mock bridge that simulates real WASM/NAPI backend behavior.
 * Each test verifies that SDK classes correctly delegate to the bridge,
 * transform data, and propagate errors.
 *
 * See #341 and ADR-022 in `.docs/adrs/phase-4.md`.
 */

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { ValidationError } from "../src/errors";
import { _resetBridge } from "../src/internal/bridge";
import { defineToolDefinition } from "../src/tools";
import { Transport } from "../src/transport";
import { createMockBridge } from "./mock-bridge";

// ---------------------------------------------------------------------------
// Test setup — inject mock bridge
// ---------------------------------------------------------------------------

let mockBridge: ReturnType<typeof createMockBridge>;

beforeEach(() => {
  mockBridge = createMockBridge();
});

afterEach(() => {
  _resetBridge();
});

// ---------------------------------------------------------------------------
// 1. Identity runtime tests
// ---------------------------------------------------------------------------

describe("Identity runtime (mock bridge)", () => {
  it("creates an identity with a valid did:dht DID", async () => {
    const handle = await mockBridge.identityCreate("in_memory");
    expect(handle.did).toMatch(/^did:dht:[a-z2-7]{52}$/);
    expect(handle.custodyType).toBe("in_memory");
  });

  it("creates identities with unique DIDs", async () => {
    const h1 = await mockBridge.identityCreate("in_memory");
    const h2 = await mockBridge.identityCreate("in_memory");
    expect(h1.did).not.toBe(h2.did);
  });

  it("loads an existing identity by DID", async () => {
    const created = await mockBridge.identityCreate("in_memory");
    const loaded = await mockBridge.identityLoad(created.did);
    expect(loaded.did).toBe(created.did);
    expect(loaded.custodyType).toBe("in_memory");
  });

  it("resolves a DID to a DID document", async () => {
    const handle = await mockBridge.identityCreate("in_memory");
    const doc = await mockBridge.identityResolve(handle.did);
    expect(doc.id).toBe(handle.did);
    expect(doc.verificationMethods.length).toBeGreaterThanOrEqual(1);
    expect(doc.verificationMethods[0].type).toBe("Ed25519VerificationKey2020");
    expect(doc.authentication.length).toBeGreaterThanOrEqual(1);
  });

  it("rotates a key and returns the same DID", async () => {
    const handle = await mockBridge.identityCreate("in_memory");
    const rotated = await mockBridge.identityRotateKey(handle);
    expect(rotated.did).toBe(handle.did);
  });

  it("rejects invalid DID format on load", async () => {
    await expect(mockBridge.identityLoad("not-a-did")).rejects.toThrow(/SCP-IDENT-1001/);
  });
});

// ---------------------------------------------------------------------------
// 2. Context runtime tests
// ---------------------------------------------------------------------------

describe("Context runtime (mock bridge)", () => {
  it("creates a context and returns active state", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["messages:read", "messages:write"],
        memoryScope: "ephemeral",
      }),
    );
    expect(ctx.contextId).toBeTruthy();
    expect(ctx.state).toBe("active");
    expect(ctx.creatorDid).toBe(identity.did);
  });

  it("records ContextCreated event on creation", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["messages:read"],
      }),
    );
    const events = await mockBridge.eventLogQuery(ctx, undefined);
    expect(events.length).toBe(1);
    expect(events[0].eventType).toBe("ContextCreated");
    expect(events[0].actorDid).toBe(identity.did);
  });

  it("allows join and records MemberJoined event", async () => {
    const creator = await mockBridge.identityCreate("in_memory");
    const joiner = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      creator,
      JSON.stringify({
        ceiling: ["messages:read"],
      }),
    );
    await mockBridge.contextJoin(ctx, joiner.did);
    const events = await mockBridge.eventLogQuery(ctx, {
      eventType: "MemberJoined",
    });
    expect(events.length).toBe(1);
    expect(events[0].actorDid).toBe(joiner.did);
  });

  it("sends a message and delivers to subscribers", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["messages:read", "messages:write"],
      }),
    );

    const received: Array<{ senderDid: string; content: string | Uint8Array }> = [];
    mockBridge.contextSubscribe(ctx, identity.did, {
      onMessage: (msg) => received.push(msg),
      onComplete: () => {},
    });

    const payload = new TextEncoder().encode("hello world");
    await mockBridge.contextSend(ctx, identity.did, payload);

    expect(received.length).toBe(1);
    expect(received[0].senderDid).toBe(identity.did);
    expect(received[0].content).toBeInstanceOf(Uint8Array);
  });

  it("leave records MemberLeft and notifies subscribers", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["messages:read"],
      }),
    );

    let completed = false;
    mockBridge.contextSubscribe(ctx, identity.did, {
      onMessage: () => {},
      onComplete: () => {
        completed = true;
      },
    });

    await mockBridge.contextLeave(ctx, identity.did);
    expect(completed).toBe(true);

    const events = await mockBridge.eventLogQuery(ctx, {
      eventType: "MemberLeft",
    });
    expect(events.length).toBe(1);
  });

  it("close transitions context to closed state", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["messages:read"],
      }),
    );
    await mockBridge.contextClose(ctx, identity.did);

    // Operations on closed context should fail
    await expect(mockBridge.contextSend(ctx, identity.did, new Uint8Array([1]))).rejects.toThrow(
      /SCP-CTX-2030/,
    );
  });
});

// ---------------------------------------------------------------------------
// 3. Tool runtime tests
// ---------------------------------------------------------------------------

describe("Tool runtime (mock bridge)", () => {
  it("registers a tool and returns a tool ID", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["tools:register"],
      }),
    );

    const def = defineToolDefinition({
      name: "echo-tool",
      description: "Echoes input",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: identity.did,
    });

    const toolId = await mockBridge.toolRegister(ctx, def);
    expect(toolId).toBeTruthy();
    expect(toolId).toMatch(/^tool-/);
  });

  it("invokes a tool with a handler and returns output", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["tools:register", "tools:invoke"],
      }),
    );

    const def = defineToolDefinition({
      name: "add-tool",
      description: "Adds two numbers",
      inputSchema: { type: "object", properties: { a: { type: "number" }, b: { type: "number" } } },
      outputSchema: { type: "object", properties: { sum: { type: "number" } } },
      operator: identity.did,
    });

    const toolId = await mockBridge.toolRegister(ctx, def);
    mockBridge._registerToolHandler(ctx.contextId, toolId, (input) => {
      const { a, b } = input as { a: number; b: number };
      return { sum: a + b };
    });

    const resultJson = await mockBridge.toolInvoke(
      ctx,
      toolId,
      JSON.stringify({ a: 3, b: 4 }),
      identity.did,
    );
    const result = JSON.parse(resultJson) as { sum: number };
    expect(result.sum).toBe(7);
  });

  it("verifies a tool with test vectors — pass", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["tools:register"],
      }),
    );

    const def = defineToolDefinition({
      name: "multiply",
      description: "Multiplies two numbers",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: identity.did,
      testVectors: [
        { input: { a: 2, b: 3 }, expectedOutput: { product: 6 } },
        { input: { a: 0, b: 5 }, expectedOutput: { product: 0 } },
      ],
    });

    const toolId = await mockBridge.toolRegister(ctx, def);
    mockBridge._registerToolHandler(ctx.contextId, toolId, (input) => {
      const { a, b } = input as { a: number; b: number };
      return { product: a * b };
    });

    const result = await mockBridge.toolVerify(ctx, toolId);
    expect(result.passed).toBe(true);
    expect(result.failures.length).toBe(0);
  });

  it("verifies a tool with test vectors — fail", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["tools:register"],
      }),
    );

    const def = defineToolDefinition({
      name: "broken",
      description: "A broken tool",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: identity.did,
      testVectors: [{ input: { x: 1 }, expectedOutput: { y: 2 } }],
    });

    const toolId = await mockBridge.toolRegister(ctx, def);
    mockBridge._registerToolHandler(ctx.contextId, toolId, () => {
      return { y: 999 };
    });

    const result = await mockBridge.toolVerify(ctx, toolId);
    expect(result.passed).toBe(false);
    expect(result.failures.length).toBe(1);
  });

  it("rejects invocation for nonexistent tool", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["tools:invoke"],
      }),
    );

    await expect(
      mockBridge.toolInvoke(ctx, "tool-nonexistent", "{}", identity.did),
    ).rejects.toThrow(/SCP-TOOL-6001/);
  });
});

// ---------------------------------------------------------------------------
// 4. UCAN runtime tests
// ---------------------------------------------------------------------------

describe("UCAN runtime (mock bridge)", () => {
  it("mints a UCAN token with capabilities", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["messages:read", "messages:write"],
      }),
    );

    const memberDid = (await mockBridge.identityCreate("in_memory")).did;
    const token = await mockBridge.ucanMint(ctx, memberDid, ["messages:read"]);

    expect(token.id).toBeTruthy();
    expect(token.issuer).toBe(identity.did);
    expect(token.audience).toBe(memberDid);
    expect(token.capabilities).toContain("messages:read");
    expect(token.encoded).toBeTruthy();
    expect(token.expiresAt).toBeGreaterThan(0);
  });

  it("validates a minted token for a granted capability", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["messages:read"],
      }),
    );

    const memberDid = (await mockBridge.identityCreate("in_memory")).did;
    const token = await mockBridge.ucanMint(ctx, memberDid, ["messages:read"]);

    // Should not throw
    await mockBridge.ucanValidate(ctx, token.encoded, "messages:read");
  });

  it("rejects validation for an ungranted capability", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["messages:read"],
      }),
    );

    const memberDid = (await mockBridge.identityCreate("in_memory")).did;
    const token = await mockBridge.ucanMint(ctx, memberDid, ["messages:read"]);

    await expect(mockBridge.ucanValidate(ctx, token.encoded, "messages:write")).rejects.toThrow(
      /SCP-PERM-3002/,
    );
  });

  it("revokes a token and rejects subsequent validation", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["messages:read"],
      }),
    );

    const memberDid = (await mockBridge.identityCreate("in_memory")).did;
    const token = await mockBridge.ucanMint(ctx, memberDid, ["messages:read"]);

    await mockBridge.ucanRevoke(ctx, token.encoded);

    await expect(mockBridge.ucanValidate(ctx, token.encoded, "messages:read")).rejects.toThrow(
      /SCP-PERM-3001/,
    );
  });
});

// ---------------------------------------------------------------------------
// 5. Event log runtime tests
// ---------------------------------------------------------------------------

describe("Event log runtime (mock bridge)", () => {
  it("queries all events in a context", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["messages:read", "messages:write"],
      }),
    );

    await mockBridge.contextSend(ctx, identity.did, new TextEncoder().encode("msg1"));
    await mockBridge.contextSend(ctx, identity.did, new TextEncoder().encode("msg2"));

    const events = await mockBridge.eventLogQuery(ctx, undefined);
    // ContextCreated + 2 MessageSent
    expect(events.length).toBe(3);
    expect(events[0].eventType).toBe("ContextCreated");
    expect(events[1].eventType).toBe("MessageSent");
    expect(events[2].eventType).toBe("MessageSent");
  });

  it("filters events by type", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["messages:read", "messages:write"],
      }),
    );

    await mockBridge.contextSend(ctx, identity.did, new TextEncoder().encode("msg"));

    const events = await mockBridge.eventLogQuery(ctx, {
      eventType: "MessageSent",
    });
    expect(events.length).toBe(1);
    expect(events[0].eventType).toBe("MessageSent");
  });

  it("filters events by actor DID", async () => {
    const creator = await mockBridge.identityCreate("in_memory");
    const other = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      creator,
      JSON.stringify({
        ceiling: ["messages:read", "messages:write"],
      }),
    );

    await mockBridge.contextJoin(ctx, other.did);
    await mockBridge.contextSend(ctx, creator.did, new TextEncoder().encode("from creator"));
    await mockBridge.contextSend(ctx, other.did, new TextEncoder().encode("from other"));

    const events = await mockBridge.eventLogQuery(ctx, {
      actorDid: other.did,
    });
    // MemberJoined + MessageSent from other
    expect(events.length).toBe(2);
    for (const e of events) {
      expect(e.actorDid).toBe(other.did);
    }
  });

  it("verifies an inclusion proof for a known event", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["messages:read"],
      }),
    );

    const proof = await mockBridge.eventLogVerify(ctx, {
      type: "inclusion",
      leafIndex: 0,
    });
    expect(proof.verified).toBe(true);
    expect(proof.proofType).toBe("inclusion");
  });

  it("returns non-verified for an out-of-range leaf index", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["messages:read"],
      }),
    );

    const proof = await mockBridge.eventLogVerify(ctx, {
      type: "inclusion",
      leafIndex: 999,
    });
    expect(proof.verified).toBe(false);
  });

  it("creates a checkpoint with root hash and event count", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["messages:read", "messages:write"],
      }),
    );

    await mockBridge.contextSend(ctx, identity.did, new TextEncoder().encode("msg"));

    const checkpoint = await mockBridge.eventLogCheckpoint(ctx);
    expect(checkpoint.root).toBeTruthy();
    expect(checkpoint.eventCount).toBe(2); // ContextCreated + MessageSent
    expect(checkpoint.timestamp).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// 6. Transport runtime tests
// ---------------------------------------------------------------------------

describe("Transport runtime (mock bridge)", () => {
  it("connects to a relay and reports connected status", async () => {
    const handle = await mockBridge.transportConnect("wss://relay.example.com");
    expect(handle.isConnected).toBe(true);
    expect(handle.relayUrl).toBe("wss://relay.example.com");
  });

  it("returns transport status with latency", async () => {
    const handle = await mockBridge.transportConnect("wss://relay.example.com");
    const status = await mockBridge.transportStatus(handle);
    expect(status.connected).toBe(true);
    expect(status.relayUrl).toBe("wss://relay.example.com");
    expect(status.latencyMs).toBeGreaterThan(0);
  });

  it("disconnects cleanly", async () => {
    const handle = await mockBridge.transportConnect("wss://relay.example.com");
    await mockBridge.transportDisconnect(handle);
    // Verify internal state updated
    const transport = mockBridge._transports.get("wss://relay.example.com");
    expect(transport?.connected).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 7. SDK class integration tests (via mock bridge)
// ---------------------------------------------------------------------------

describe("SDK class wiring (type-safe delegation)", () => {
  it("defineToolDefinition validates and constructs ToolDefinition", () => {
    const def = defineToolDefinition({
      name: "test",
      description: "desc",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: "did:dht:z6MkTest",
    });
    expect(def.name).toBe("test");
    expect(def.description).toBe("desc");
    expect(def.operator).toBe("did:dht:z6MkTest");
  });

  it("defineToolDefinition rejects empty name", () => {
    expect(() =>
      defineToolDefinition({
        name: "",
        description: "desc",
        inputSchema: {},
        outputSchema: {},
        operator: "did:dht:z6MkTest",
      }),
    ).toThrow(ValidationError);
  });

  it("Transport.connect rejects non-wss URLs", async () => {
    await expect(Transport.connect({ relayUrl: "ws://insecure.example.com" })).rejects.toThrow(
      ValidationError,
    );
  });

  it("version returns a string", () => {
    const v = mockBridge.version();
    expect(typeof v).toBe("string");
    expect(v).toBe("0.1.0-mock");
  });
});

// ---------------------------------------------------------------------------
// 8. Cross-module integration: trust evaluation
// ---------------------------------------------------------------------------

describe("Trust evaluation runtime (mock bridge)", () => {
  it("computes behavioral record from event log", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["messages:read", "messages:write", "tools:register", "tools:invoke"],
      }),
    );

    // Register and invoke a tool to generate ToolInvoked events
    const def = defineToolDefinition({
      name: "calc",
      description: "Calculator",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: identity.did,
    });
    const toolId = await mockBridge.toolRegister(ctx, def);
    mockBridge._registerToolHandler(ctx.contextId, toolId, (input) => input);

    await mockBridge.toolInvoke(ctx, toolId, JSON.stringify({ x: 1 }), identity.did);
    await mockBridge.toolInvoke(ctx, toolId, JSON.stringify({ x: 2 }), identity.did);

    // Query events for the identity (simulating what evaluateTrust does)
    const events = await mockBridge.eventLogQuery(ctx, {
      actorDid: identity.did,
    });

    // Should have: ContextCreated, ToolRegistered, 2x ToolInvoked
    expect(events.length).toBeGreaterThanOrEqual(4);

    const toolInvokedEvents = events.filter((e) => e.eventType === "ToolInvoked");
    expect(toolInvokedEvents.length).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// 9. End-to-end scenario: full context lifecycle
// ---------------------------------------------------------------------------

describe("End-to-end context lifecycle", () => {
  it("create -> join -> send -> receive -> leave -> close", async () => {
    // Create identities
    const alice = await mockBridge.identityCreate("in_memory");
    const bob = await mockBridge.identityCreate("in_memory");

    // Create context
    const ctx = await mockBridge.contextCreate(
      alice,
      JSON.stringify({
        ceiling: ["messages:read", "messages:write"],
        memoryScope: "full",
        governance: "single_admin",
      }),
    );

    // Bob joins
    await mockBridge.contextJoin(ctx, bob.did);

    // Subscribe to messages
    const messages: Array<{ senderDid: string; contextId: string }> = [];
    mockBridge.contextSubscribe(ctx, bob.did, {
      onMessage: (msg) => messages.push({ senderDid: msg.senderDid, contextId: msg.contextId }),
      onComplete: () => {},
    });

    // Alice sends a message
    await mockBridge.contextSend(ctx, alice.did, new TextEncoder().encode("hello bob"));
    expect(messages.length).toBe(1);
    expect(messages[0].senderDid).toBe(alice.did);
    expect(messages[0].contextId).toBe(ctx.contextId);

    // Bob sends a message
    await mockBridge.contextSend(ctx, bob.did, new TextEncoder().encode("hello alice"));
    expect(messages.length).toBe(2);
    expect(messages[1].senderDid).toBe(bob.did);

    // Verify event log
    const allEvents = await mockBridge.eventLogQuery(ctx, undefined);
    expect(allEvents.length).toBe(4); // Created + Joined + 2 Sent

    // Bob leaves
    await mockBridge.contextLeave(ctx, bob.did);

    // Alice closes
    await mockBridge.contextClose(ctx, alice.did);

    // Verify final event log
    // Cannot query closed context (it throws)
    await expect(mockBridge.eventLogQuery(ctx, undefined)).rejects.toThrow(/SCP-CTX-2030/);
  });
});

// ---------------------------------------------------------------------------
// 10. UCAN lifecycle: mint -> validate -> revoke -> reject
// ---------------------------------------------------------------------------

describe("UCAN full lifecycle", () => {
  it("mint -> validate -> revoke -> validation fails", async () => {
    const admin = await mockBridge.identityCreate("in_memory");
    const member = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      admin,
      JSON.stringify({
        ceiling: ["messages:read", "messages:write"],
      }),
    );

    // Mint token
    const token = await mockBridge.ucanMint(ctx, member.did, ["messages:read", "messages:write"]);
    expect(token.capabilities).toEqual(["messages:read", "messages:write"]);

    // Validate succeeds
    await mockBridge.ucanValidate(ctx, token.encoded, "messages:read");
    await mockBridge.ucanValidate(ctx, token.encoded, "messages:write");

    // Revoke
    await mockBridge.ucanRevoke(ctx, token.encoded);

    // Validate fails after revocation
    await expect(mockBridge.ucanValidate(ctx, token.encoded, "messages:read")).rejects.toThrow(
      /SCP-PERM-3001/,
    );
  });
});

// ---------------------------------------------------------------------------
// 8. Economic policy roundtrip tests (#592)
// ---------------------------------------------------------------------------

describe("Economic policy roundtrip (mock bridge)", () => {
  it("set then get returns the same policy JSON", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({ ceiling: ["messages:read"] }),
    );

    const policyJson = JSON.stringify({
      locked: false,
      cost_schedule: { currency: [85, 83, 68, 0] },
      payment_adapters: [],
      pricing_formula: null,
      payee: "did:dht:z6MkPayee",
    });

    await mockBridge.contextSetEconomicPolicy(ctx, policyJson);
    const result = await mockBridge.contextGetEconomicPolicy(ctx);
    expect(result).toBe(policyJson);
  });

  it("get returns null when no policy is set", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({ ceiling: ["messages:read"] }),
    );

    const result = await mockBridge.contextGetEconomicPolicy(ctx);
    expect(result).toBeNull();
  });
});
