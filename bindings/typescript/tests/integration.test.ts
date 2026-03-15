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
import { _validateEconomicPolicyJson, Context } from "../src/context";
import { ContextError, ValidationError } from "../src/errors";
import { _resetBridge, _setBridge } from "../src/internal/bridge";
import { defineToolDefinition } from "../src/tools";
import { Transport } from "../src/transport";
import { delegateUcan, mintUcan } from "../src/ucan";
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

    // Mint a UCAN token for tool invocation
    const ucan = await mockBridge.ucanMint(ctx, identity.did, ["tool_invoke:*"]);

    const resultJson = await mockBridge.toolInvoke(
      ctx,
      toolId,
      JSON.stringify({ a: 3, b: 4 }),
      identity.did,
      ucan.encoded,
    );
    const result = JSON.parse(resultJson) as { sum: number };
    expect(result.sum).toBe(7);
  });

  it("rejects tool invocation without a UCAN token", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["tools:register", "tools:invoke"],
      }),
    );

    const def = defineToolDefinition({
      name: "noop-tool",
      description: "Does nothing",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: identity.did,
    });

    const toolId = await mockBridge.toolRegister(ctx, def);

    await expect(mockBridge.toolInvoke(ctx, toolId, "{}", identity.did)).rejects.toThrow(
      /SCP-VALID-7000/,
    );
  });

  it("rejects tool invocation with an empty UCAN token", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["tools:register", "tools:invoke"],
      }),
    );

    const def = defineToolDefinition({
      name: "noop-tool-2",
      description: "Does nothing",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: identity.did,
    });

    const toolId = await mockBridge.toolRegister(ctx, def);

    await expect(mockBridge.toolInvoke(ctx, toolId, "{}", identity.did, "")).rejects.toThrow(
      /SCP-VALID-7000/,
    );
  });

  it("rejects tool invocation with a revoked UCAN token", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["tools:register", "tools:invoke"],
      }),
    );

    const def = defineToolDefinition({
      name: "revoked-test-tool",
      description: "Test revocation",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: identity.did,
    });

    const toolId = await mockBridge.toolRegister(ctx, def);

    const ucan = await mockBridge.ucanMint(ctx, identity.did, ["tool_invoke:*"]);

    // Revoke the token
    await mockBridge.ucanRevoke(ctx, ucan.encoded, identity.did);

    // Invocation should fail
    await expect(
      mockBridge.toolInvoke(ctx, toolId, "{}", identity.did, ucan.encoded),
    ).rejects.toThrow(/SCP-PERM-3001/);
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

    const ucan = await mockBridge.ucanMint(ctx, identity.did, ["tool_invoke:*"]);

    await expect(
      mockBridge.toolInvoke(ctx, "tool-nonexistent", "{}", identity.did, ucan.encoded),
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

    await mockBridge.ucanRevoke(ctx, token.encoded, identity.did);

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

    const checkpoint = await mockBridge.eventLogCheckpoint(ctx, identity.did, 0);
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

    // Mint a UCAN token for tool invocation
    const ucan = await mockBridge.ucanMint(ctx, identity.did, ["tool_invoke:*"]);

    await mockBridge.toolInvoke(ctx, toolId, JSON.stringify({ x: 1 }), identity.did, ucan.encoded);
    await mockBridge.toolInvoke(ctx, toolId, JSON.stringify({ x: 2 }), identity.did, ucan.encoded);

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

    // Revoke (revoker is the admin/context creator)
    await mockBridge.ucanRevoke(ctx, token.encoded, admin.did);

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

// ---------------------------------------------------------------------------
// 9. EconomicPolicy schema validation tests (#592, finding 7)
// ---------------------------------------------------------------------------

describe("EconomicPolicy schema validation", () => {
  it("accepts valid policy JSON", () => {
    const valid = JSON.stringify({
      locked: false,
      cost_schedule: { currency: [85, 83, 68, 0] },
      payment_adapters: [],
      pricing_formula: null,
      payee: "did:dht:z6MkPayee",
    });
    // Should not throw.
    _validateEconomicPolicyJson(valid);
  });

  it("rejects non-JSON input", () => {
    expect(() => _validateEconomicPolicyJson("not json")).toThrow(ValidationError);
  });

  it("rejects JSON array", () => {
    expect(() => _validateEconomicPolicyJson("[]")).toThrow(/expected an object/);
  });

  it("rejects missing locked field", () => {
    const json = JSON.stringify({ cost_schedule: {}, payment_adapters: [], payee: "did:test" });
    expect(() => _validateEconomicPolicyJson(json)).toThrow(/'locked' must be a boolean/);
  });

  it("rejects missing cost_schedule", () => {
    const json = JSON.stringify({ locked: false, payment_adapters: [], payee: "did:test" });
    expect(() => _validateEconomicPolicyJson(json)).toThrow(/'cost_schedule' must be an object/);
  });

  it("rejects missing payment_adapters", () => {
    const json = JSON.stringify({ locked: false, cost_schedule: {}, payee: "did:test" });
    expect(() => _validateEconomicPolicyJson(json)).toThrow(/'payment_adapters' must be an array/);
  });

  it("rejects missing payee", () => {
    const json = JSON.stringify({ locked: false, cost_schedule: {}, payment_adapters: [] });
    expect(() => _validateEconomicPolicyJson(json)).toThrow(/'payee' must be a string/);
  });
});

// ---------------------------------------------------------------------------
// 10. TTL expiry, proposal, and reset (bridge level)
// ---------------------------------------------------------------------------

describe("TTL operations (mock bridge)", () => {
  it("handleTtlExpiry transitions context to expired", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({ ceiling: ["messages:read"], ttlSeconds: 300 }),
    );

    await mockBridge.contextHandleTtlExpiry(ctx);
    const ctxState = mockBridge._contexts.get(ctx.contextId);
    expect(ctxState?.state).toBe("expired");
  });

  it("proposeTtlExtension returns true for single-member context", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({ ceiling: ["messages:read"], ttlSeconds: 300 }),
    );

    const approved = await mockBridge.contextProposeTtlExtension(ctx, identity.did, 120);
    expect(approved).toBe(true);
    expect(mockBridge._contexts.get(ctx.contextId)?.ttlSecs).toBe(420);
  });

  it("proposeTtlExtension returns false for multi-member context", async () => {
    const alice = await mockBridge.identityCreate("in_memory");
    const bob = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      alice,
      JSON.stringify({ ceiling: ["messages:read"], ttlSeconds: 300 }),
    );
    await mockBridge.contextJoin(ctx, bob.did);

    const approved = await mockBridge.contextProposeTtlExtension(ctx, alice.did, 120);
    expect(approved).toBe(false);
    expect(mockBridge._contexts.get(ctx.contextId)?.ttlSecs).toBe(300);
  });

  it("resetTtlTimer replaces TTL with new duration", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({ ceiling: ["messages:read"], ttlSeconds: 300 }),
    );

    await mockBridge.contextResetTtlTimer(ctx, 600);
    expect(mockBridge._contexts.get(ctx.contextId)?.ttlSecs).toBe(600);
  });
});

// ---------------------------------------------------------------------------
// 11. Context export/import (bridge level)
// ---------------------------------------------------------------------------

describe("Context export/import (mock bridge)", () => {
  it("exports and re-imports a context", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({ ceiling: ["messages:read", "messages:write"] }),
    );

    const exported = await mockBridge.contextExport(ctx);
    expect(exported).toBeInstanceOf(Uint8Array);
    expect(exported.length).toBeGreaterThan(0);

    const importedId = await mockBridge.contextImport(exported);
    expect(importedId).toBe(ctx.contextId);

    // The imported context should be active
    const importedCtx = mockBridge._contexts.get(importedId);
    expect(importedCtx?.state).toBe("active");
  });

  it("import rejects malformed data", async () => {
    await expect(mockBridge.contextImport(new TextEncoder().encode("not json{"))).rejects.toThrow(
      /SCP-CTX-2032/,
    );
  });

  it("import rejects missing snapshot", async () => {
    await expect(
      mockBridge.contextImport(new TextEncoder().encode(JSON.stringify({}))),
    ).rejects.toThrow(/SCP-CTX-2032/);
  });

  it("round-trips broadcast context with subscribers and blocked list", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(identity, JSON.stringify({ mode: "Broadcast" }));

    // Add subscribers and block one
    const sub1 = await mockBridge.identityCreate("in_memory");
    const sub2 = await mockBridge.identityCreate("in_memory");
    const blocked = await mockBridge.identityCreate("in_memory");

    await mockBridge.broadcastSubscribe(ctx, sub1.did);
    await mockBridge.broadcastSubscribe(ctx, sub2.did);
    await mockBridge.broadcastSubscribe(ctx, blocked.did);
    await mockBridge.broadcastBlockSubscriber(ctx, blocked.did, identity.did);

    // Verify pre-export state
    const original = mockBridge._contexts.get(ctx.contextId);
    expect(original?.mode).toBe("Broadcast");
    expect(original?.broadcastSubscribers.size).toBe(2);
    expect(original?.broadcastBlockedSubscribers.has(blocked.did)).toBe(true);
    expect(original?.broadcastAdmission).toBe("Open");

    // Export and re-import
    const exported = await mockBridge.contextExport(ctx);
    // Remove the original so import creates a fresh entry
    mockBridge._contexts.delete(ctx.contextId);

    const importedId = await mockBridge.contextImport(exported);
    expect(importedId).toBe(ctx.contextId);

    const imported = mockBridge._contexts.get(importedId);
    expect(imported?.mode).toBe("Broadcast");
    expect(imported?.broadcastSubscribers.size).toBe(2);
    expect(imported?.broadcastSubscribers.has(sub1.did)).toBe(true);
    expect(imported?.broadcastSubscribers.has(sub2.did)).toBe(true);
    expect(imported?.broadcastBlockedSubscribers.has(blocked.did)).toBe(true);
    expect(imported?.broadcastAdmission).toBe("Open");
  });

  it("round-trips encrypted context preserving mode", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({ ceiling: ["messages:read"] }),
    );

    const exported = await mockBridge.contextExport(ctx);
    mockBridge._contexts.delete(ctx.contextId);

    const importedId = await mockBridge.contextImport(exported);
    const imported = mockBridge._contexts.get(importedId);
    expect(imported?.mode).toBe("Encrypted");
    expect(imported?.broadcastSubscribers.size).toBe(0);
    expect(imported?.broadcastBlockedSubscribers.size).toBe(0);
    expect(imported?.broadcastAdmission).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 12. Drain events (bridge level)
// ---------------------------------------------------------------------------

describe("Drain events (mock bridge)", () => {
  it("drains events from context", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({ ceiling: ["messages:read", "messages:write"] }),
    );

    await mockBridge.contextSend(ctx, identity.did, new TextEncoder().encode("msg1"));
    await mockBridge.contextSend(ctx, identity.did, new TextEncoder().encode("msg2"));

    const events = await mockBridge.contextDrainEvents(ctx);
    expect(events.length).toBe(3); // ContextCreated + 2 MessageSent
    for (const e of events) {
      expect(typeof e).toBe("string");
      const parsed = JSON.parse(e);
      expect(parsed.eventType).toBeTruthy();
    }
  });

  it("drain clears receive buffer but preserves event log", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({ ceiling: ["messages:read", "messages:write"] }),
    );

    await mockBridge.contextSend(ctx, identity.did, new TextEncoder().encode("msg1"));

    const drained = await mockBridge.contextDrainEvents(ctx);
    expect(drained.length).toBeGreaterThan(0);

    const drained2 = await mockBridge.contextDrainEvents(ctx);
    expect(drained2.length).toBe(0);

    const logEvents = await mockBridge.eventLogQuery(ctx, undefined);
    expect(logEvents.length).toBe(drained.length);
  });
});

// ---------------------------------------------------------------------------
// 13. SDK Context class: TTL, export/import, drain (SDK wrapper level)
// ---------------------------------------------------------------------------

describe("Context SDK wrapper — TTL, export/import, drain", () => {
  beforeEach(() => {
    _setBridge(mockBridge);
  });

  it("handleTtlExpiry delegates to bridge", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const handle = await mockBridge.contextCreate(
      identity,
      JSON.stringify({ ceiling: ["messages:read"], ttlSeconds: 300 }),
    );
    const ctx = Context._fromHandle(handle, identity.did);

    await ctx.handleTtlExpiry();
    expect(mockBridge._contexts.get(handle.contextId)?.state).toBe("expired");
  });

  it("proposeTtlExtension delegates to bridge", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const handle = await mockBridge.contextCreate(
      identity,
      JSON.stringify({ ceiling: ["messages:read"], ttlSeconds: 300 }),
    );
    const ctx = Context._fromHandle(handle, identity.did);

    const approved = await ctx.proposeTtlExtension(120);
    expect(approved).toBe(true);
  });

  it("proposeTtlExtension rejects zero or negative seconds", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const handle = await mockBridge.contextCreate(
      identity,
      JSON.stringify({ ceiling: ["messages:read"], ttlSeconds: 300 }),
    );
    const ctx = Context._fromHandle(handle, identity.did);

    await expect(ctx.proposeTtlExtension(0)).rejects.toThrow(ContextError);
    await expect(ctx.proposeTtlExtension(-10)).rejects.toThrow(ContextError);
  });

  it("resetTtlTimer delegates to bridge", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const handle = await mockBridge.contextCreate(
      identity,
      JSON.stringify({ ceiling: ["messages:read"], ttlSeconds: 300 }),
    );
    const ctx = Context._fromHandle(handle, identity.did);

    await ctx.resetTtlTimer(600);
    expect(mockBridge._contexts.get(handle.contextId)?.ttlSecs).toBe(600);
  });

  it("resetTtlTimer rejects zero or negative seconds", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const handle = await mockBridge.contextCreate(
      identity,
      JSON.stringify({ ceiling: ["messages:read"], ttlSeconds: 300 }),
    );
    const ctx = Context._fromHandle(handle, identity.did);

    await expect(ctx.resetTtlTimer(0)).rejects.toThrow(ContextError);
    await expect(ctx.resetTtlTimer(-5)).rejects.toThrow(ContextError);
  });

  it("extendTtl rejects zero or negative seconds", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const handle = await mockBridge.contextCreate(
      identity,
      JSON.stringify({ ceiling: ["messages:read"], ttlSeconds: 300 }),
    );
    const ctx = Context._fromHandle(handle, identity.did);

    await expect(ctx.extendTtl(0)).rejects.toThrow(ContextError);
    await expect(ctx.extendTtl(-10)).rejects.toThrow(ContextError);
  });

  it("extendTtl rejects Infinity and -Infinity", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const handle = await mockBridge.contextCreate(
      identity,
      JSON.stringify({ ceiling: ["messages:read"], ttlSeconds: 300 }),
    );
    const ctx = Context._fromHandle(handle, identity.did);

    await expect(ctx.extendTtl(Infinity)).rejects.toThrow(ContextError);
    await expect(ctx.extendTtl(-Infinity)).rejects.toThrow(ContextError);
  });

  it("proposeTtlExtension rejects Infinity and -Infinity", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const handle = await mockBridge.contextCreate(
      identity,
      JSON.stringify({ ceiling: ["messages:read"], ttlSeconds: 300 }),
    );
    const ctx = Context._fromHandle(handle, identity.did);

    await expect(ctx.proposeTtlExtension(Infinity)).rejects.toThrow(ContextError);
    await expect(ctx.proposeTtlExtension(-Infinity)).rejects.toThrow(ContextError);
  });

  it("resetTtlTimer rejects Infinity and -Infinity", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const handle = await mockBridge.contextCreate(
      identity,
      JSON.stringify({ ceiling: ["messages:read"], ttlSeconds: 300 }),
    );
    const ctx = Context._fromHandle(handle, identity.did);

    await expect(ctx.resetTtlTimer(Infinity)).rejects.toThrow(ContextError);
    await expect(ctx.resetTtlTimer(-Infinity)).rejects.toThrow(ContextError);
  });

  it("export returns Uint8Array", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const handle = await mockBridge.contextCreate(
      identity,
      JSON.stringify({ ceiling: ["messages:read"] }),
    );
    const ctx = Context._fromHandle(handle, identity.did);

    const exported = await ctx.export();
    expect(exported).toBeInstanceOf(Uint8Array);
    expect(exported.length).toBeGreaterThan(0);
  });

  it("static import returns context ID", async () => {
    _setBridge(mockBridge);
    const identity = await mockBridge.identityCreate("in_memory");
    const handle = await mockBridge.contextCreate(
      identity,
      JSON.stringify({ ceiling: ["messages:read"] }),
    );
    const ctx = Context._fromHandle(handle, identity.did);

    const exported = await ctx.export();
    const importedId = await Context.import(exported);
    expect(importedId).toBe(handle.contextId);
  });

  it("drainEvents returns event strings", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const handle = await mockBridge.contextCreate(
      identity,
      JSON.stringify({ ceiling: ["messages:read", "messages:write"] }),
    );
    const ctx = Context._fromHandle(handle, identity.did);

    await mockBridge.contextSend(handle, identity.did, new TextEncoder().encode("hello"));

    const events = await ctx.drainEvents();
    expect(events.length).toBe(2); // ContextCreated + MessageSent
    for (const e of events) {
      expect(typeof e).toBe("string");
    }
  });

  it("methods throw on disposed context", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const handle = await mockBridge.contextCreate(
      identity,
      JSON.stringify({ ceiling: ["messages:read"], ttlSeconds: 300 }),
    );
    const ctx = Context._fromHandle(handle, identity.did);

    await ctx.leave();

    await expect(ctx.handleTtlExpiry()).rejects.toThrow(ContextError);
    await expect(ctx.proposeTtlExtension(120)).rejects.toThrow(ContextError);
    await expect(ctx.resetTtlTimer(600)).rejects.toThrow(ContextError);
    await expect(ctx.export()).rejects.toThrow(ContextError);
    await expect(ctx.drainEvents()).rejects.toThrow(ContextError);
  });
});

// ---------------------------------------------------------------------------
// 14. UCAN delegation via SDK wrapper
// ---------------------------------------------------------------------------

describe("UCAN delegation (SDK wrapper)", () => {
  beforeEach(() => {
    _setBridge(mockBridge);
  });

  it("delegateUcan delegates to bridge and returns delegated token", async () => {
    const admin = await mockBridge.identityCreate("in_memory");
    const handle = await mockBridge.contextCreate(
      admin,
      JSON.stringify({ ceiling: ["messages:read", "messages:write"] }),
    );
    const ctx = Context._fromHandle(handle, admin.did);

    const memberDid = (await mockBridge.identityCreate("in_memory")).did;
    const parentToken = await mintUcan(ctx, memberDid, ["messages:read", "messages:write"]);

    const delegateeDid = (await mockBridge.identityCreate("in_memory")).did;
    const delegated = await delegateUcan(ctx, parentToken, memberDid, delegateeDid, [
      "messages:read",
    ]);

    expect(delegated.issuer).toBe(memberDid);
    expect(delegated.audience).toBe(delegateeDid);
    expect(delegated.capabilities).toEqual(["messages:read"]);
    expect(delegated.encoded).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// Broadcast mutation operations (mock bridge)
// ---------------------------------------------------------------------------

describe("Broadcast mutation operations (mock bridge)", () => {
  async function createBroadcastContext() {
    _setBridge(mockBridge);
    const identity = await mockBridge.identityCreate("in_memory");
    const handle = await mockBridge.contextCreate(identity, JSON.stringify({ mode: "Broadcast" }));
    const ctx = Context._fromHandle(handle, identity.did);
    return { identity, handle, ctx };
  }

  it("broadcastSubscribe adds a subscriber", async () => {
    const { ctx } = await createBroadcastContext();
    const subscriber = await mockBridge.identityCreate("in_memory");

    await ctx.broadcastSubscribe(subscriber.did);

    expect(await ctx.broadcastIsSubscriber(subscriber.did)).toBe(true);
    expect(await ctx.broadcastSubscriberCount()).toBe(1);
  });

  it("broadcastSubscribe rejects non-broadcast context", async () => {
    _setBridge(mockBridge);
    const identity = await mockBridge.identityCreate("in_memory");
    const handle = await mockBridge.contextCreate(identity, JSON.stringify({ mode: "Encrypted" }));
    const ctx = Context._fromHandle(handle, identity.did);
    const subscriber = await mockBridge.identityCreate("in_memory");

    await expect(ctx.broadcastSubscribe(subscriber.did)).rejects.toThrow("not a broadcast context");
  });

  it("broadcastUnsubscribe removes a subscriber", async () => {
    const { ctx } = await createBroadcastContext();
    const subscriber = await mockBridge.identityCreate("in_memory");

    await ctx.broadcastSubscribe(subscriber.did);
    expect(await ctx.broadcastIsSubscriber(subscriber.did)).toBe(true);

    await ctx.broadcastUnsubscribe(subscriber.did);
    expect(await ctx.broadcastIsSubscriber(subscriber.did)).toBe(false);
    expect(await ctx.broadcastSubscriberCount()).toBe(0);
  });

  it("broadcastUnsubscribe with rotateKeys=false does not trigger key rotation", async () => {
    const { ctx, handle } = await createBroadcastContext();
    const subscriber = await mockBridge.identityCreate("in_memory");

    await ctx.broadcastSubscribe(subscriber.did);
    await ctx.broadcastUnsubscribe(subscriber.did, false);

    expect(await ctx.broadcastIsSubscriber(subscriber.did)).toBe(false);
    // No BroadcastKeyRotated event should be emitted when rotateKeys is false.
    const mockCtx = mockBridge._contexts.get(handle.contextId);
    expect(mockCtx).toBeDefined();
    const rotateEvents =
      mockCtx?.eventLog.filter((e) => e.eventType === "BroadcastKeyRotated") ?? [];
    expect(rotateEvents.length).toBe(0);
  });

  it("broadcastUnsubscribe with rotateKeys=true triggers key rotation", async () => {
    const { ctx, handle } = await createBroadcastContext();
    const subscriber = await mockBridge.identityCreate("in_memory");

    await ctx.broadcastSubscribe(subscriber.did);
    await ctx.broadcastUnsubscribe(subscriber.did, true);

    expect(await ctx.broadcastIsSubscriber(subscriber.did)).toBe(false);
    // A BroadcastKeyRotated event should be emitted when rotateKeys is true.
    const mockCtx = mockBridge._contexts.get(handle.contextId);
    expect(mockCtx).toBeDefined();
    const rotateEvents =
      mockCtx?.eventLog.filter((e) => e.eventType === "BroadcastKeyRotated") ?? [];
    expect(rotateEvents.length).toBe(1);
    expect(rotateEvents[0].payload.reason).toBe("subscriber_removed");
    expect(rotateEvents[0].payload.subscriberDid).toBe(subscriber.did);
  });

  it("broadcastPublish succeeds for context member", async () => {
    const { ctx, identity } = await createBroadcastContext();
    const payload = new Uint8Array([1, 2, 3]);

    // Should not throw — identity is the creator (a member)
    await ctx.broadcastPublish(payload, identity.did);
  });

  it("broadcastPublish rejects non-member author", async () => {
    const { ctx } = await createBroadcastContext();
    const nonMember = await mockBridge.identityCreate("in_memory");
    const payload = new Uint8Array([1, 2, 3]);

    await expect(ctx.broadcastPublish(payload, nonMember.did)).rejects.toThrow("not a member");
  });

  it("broadcastBlockSubscriber removes and blocks a subscriber", async () => {
    const { ctx, identity } = await createBroadcastContext();
    const subscriber = await mockBridge.identityCreate("in_memory");

    await ctx.broadcastSubscribe(subscriber.did);
    expect(await ctx.broadcastIsSubscriber(subscriber.did)).toBe(true);

    await ctx.broadcastBlockSubscriber(subscriber.did, identity.did);
    expect(await ctx.broadcastIsSubscriber(subscriber.did)).toBe(false);
    expect(await ctx.broadcastSubscriberCount()).toBe(0);
  });

  it("broadcastBlockSubscriber prevents re-subscribe", async () => {
    const { ctx, identity } = await createBroadcastContext();
    const subscriber = await mockBridge.identityCreate("in_memory");

    await ctx.broadcastSubscribe(subscriber.did);
    await ctx.broadcastBlockSubscriber(subscriber.did, identity.did);

    // Attempting to re-subscribe a blocked DID should fail
    await expect(ctx.broadcastSubscribe(subscriber.did)).rejects.toThrow("blocked");
  });

  it("broadcastUnblockSubscriber allows re-subscribe after unblock", async () => {
    const { ctx, identity } = await createBroadcastContext();
    const subscriber = await mockBridge.identityCreate("in_memory");

    await ctx.broadcastSubscribe(subscriber.did);
    await ctx.broadcastBlockSubscriber(subscriber.did, identity.did);

    // Unblock
    await ctx.broadcastUnblockSubscriber(subscriber.did, identity.did);

    // Should be able to re-subscribe after unblock
    await ctx.broadcastSubscribe(subscriber.did);
    expect(await ctx.broadcastIsSubscriber(subscriber.did)).toBe(true);
  });

  it("broadcastHandleKeyRequest grants key to subscribed DID", async () => {
    const { ctx, identity } = await createBroadcastContext();
    const subscriber = await mockBridge.identityCreate("in_memory");

    await ctx.broadcastSubscribe(subscriber.did);

    const decision = await ctx.broadcastHandleKeyRequest(identity.did, subscriber.did);
    expect(decision).toBe("Granted");
  });

  it("broadcastHandleKeyRequest denies key to non-subscribed DID", async () => {
    const { ctx, identity } = await createBroadcastContext();
    const nonSubscriber = await mockBridge.identityCreate("in_memory");

    const decision = await ctx.broadcastHandleKeyRequest(identity.did, nonSubscriber.did);
    expect(decision).toContain("Denied");
  });

  it("broadcastHandleKeyRequest denies key to blocked DID", async () => {
    const { ctx, identity } = await createBroadcastContext();
    const subscriber = await mockBridge.identityCreate("in_memory");

    await ctx.broadcastSubscribe(subscriber.did);
    await ctx.broadcastBlockSubscriber(subscriber.did, identity.did);

    const decision = await ctx.broadcastHandleKeyRequest(identity.did, subscriber.did);
    expect(decision).toContain("Denied");
    expect(decision).toContain("Blocked");
  });

  it("broadcastSubscriberCount returns null for non-broadcast context", async () => {
    _setBridge(mockBridge);
    const identity = await mockBridge.identityCreate("in_memory");
    const handle = await mockBridge.contextCreate(identity, JSON.stringify({ mode: "Encrypted" }));
    const ctx = Context._fromHandle(handle, identity.did);

    expect(await ctx.broadcastSubscriberCount()).toBeNull();
  });

  it("broadcastAdmission returns Open for broadcast context", async () => {
    const { ctx } = await createBroadcastContext();
    expect(await ctx.broadcastAdmission()).toBe("Open");
  });

  it("broadcastAdmission returns null for non-broadcast context", async () => {
    _setBridge(mockBridge);
    const identity = await mockBridge.identityCreate("in_memory");
    const handle = await mockBridge.contextCreate(identity, JSON.stringify({ mode: "Encrypted" }));
    const ctx = Context._fromHandle(handle, identity.did);

    expect(await ctx.broadcastAdmission()).toBeNull();
  });
});
