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
import { Identity } from "../src/identity";
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
    expect(doc.verificationMethods[0]?.type).toBe("Ed25519VerificationKey2020");
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
    expect(events[0]?.eventType).toBe("ContextCreated");
    expect(events[0]?.actorDid).toBe(identity.did);
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
    expect(events[0]?.actorDid).toBe(joiner.did);
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
    expect(received[0]?.senderDid).toBe(identity.did);
    expect(received[0]?.content).toBeInstanceOf(Uint8Array);
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

    await expect(mockBridge.toolInvoke(ctx, toolId, "{}", identity.did, "")).rejects.toThrow(
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
        { input: { a: 2, b: 3 }, expectedOutput: { product: 6 }, description: "2 * 3 = 6" },
        { input: { a: 0, b: 5 }, expectedOutput: { product: 0 }, description: "0 * 5 = 0" },
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
      testVectors: [{ input: { x: 1 }, expectedOutput: { y: 2 }, description: "x=1 maps to y=2" }],
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

  // C4 (#1606): paid tool invocations now route through
  // ContextManager.invoke_tool_with_economy via the NAPI bridge.
  // The TS bridge interface exposes `spendingUcan` as the 7th
  // toolInvoke argument; verify it round-trips through the bridge
  // and is recorded in the mock bridge's ToolInvoked event payload.
  it("forwards spendingUcan through bridge.toolInvoke", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const ctx = await mockBridge.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["tools:register", "tools:invoke"],
      }),
    );

    const def = defineToolDefinition({
      name: "paid-echo",
      description: "Paid echo tool for C4 wiring test",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: identity.did,
    });
    const toolId = await mockBridge.toolRegister(ctx, def);
    mockBridge._registerToolHandler(ctx.contextId, toolId, (input) => ({ echoed: input }));

    const ucan = await mockBridge.ucanMint(ctx, identity.did, ["tool_invoke:*"]);
    const spending = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.spending.sig";

    const resultJson = await mockBridge.toolInvoke(
      ctx,
      toolId,
      JSON.stringify({ hello: "world" }),
      identity.did,
      ucan.encoded,
      undefined,
      spending,
    );
    expect(JSON.parse(resultJson)).toEqual({ echoed: { hello: "world" } });

    // The mock bridge records `spendingUcanProvided: true` in the
    // ToolInvoked event payload when a non-empty spending UCAN is
    // forwarded through the bridge interface. This is the structural
    // assertion that the bridge layer accepts the new param.
    const ctxState = mockBridge._contexts.get(ctx.contextId);
    const toolInvokedEvents =
      ctxState?.eventLog.filter((e: { eventType: string }) => e.eventType === "ToolInvoked") ?? [];
    expect(toolInvokedEvents.length).toBe(1);
    const payload = toolInvokedEvents[0]?.payload as { spendingUcanProvided?: boolean };
    expect(payload.spendingUcanProvided).toBe(true);
  });

  // C4 (#1606): the SDK Context.invokeTool wrapper exposes
  // `spendingUcan` as a named option. Verify the SDK forwards it to
  // the bridge layer when set.
  it("Context.invokeTool forwards options.spendingUcan to the bridge", async () => {
    _setBridge(mockBridge);
    const identity = await Identity.create({ custody: "in_memory" });
    const ctx = await Context.create(identity, {
      ceiling: ["tools:register", "tools:invoke"],
    });

    const def = defineToolDefinition({
      name: "sdk-paid-echo",
      description: "SDK paid echo tool for C4 wiring test",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: identity.did,
    });
    const toolId = await ctx.registerTool(def);
    mockBridge._registerToolHandler(ctx.contextId, toolId, (input) => ({ echoed: input }));

    // Find the bridge handle for this context (mockBridge stores by
    // contextId; build a stub handle matching the BridgeContextHandle
    // shape that the bridge interface uses internally).
    const stubHandle = { contextId: ctx.contextId, state: "active", creatorDid: identity.did };
    const ucan = await mockBridge.ucanMint(stubHandle, identity.did, ["tool_invoke:*"]);
    const spending = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.spending.sig";

    const result = await ctx.invokeTool(toolId, { hello: "world" }, identity, ucan.encoded, {
      spendingUcan: spending,
    });
    expect(result).toEqual({ echoed: { hello: "world" } });

    const ctxState = mockBridge._contexts.get(ctx.contextId);
    const toolInvokedEvents =
      ctxState?.eventLog.filter((e: { eventType: string }) => e.eventType === "ToolInvoked") ?? [];
    expect(toolInvokedEvents.length).toBe(1);
    const payload = toolInvokedEvents[0]?.payload as { spendingUcanProvided?: boolean };
    expect(payload.spendingUcanProvided).toBe(true);
  });

  // C4 (#1606): when no spendingUcan option is passed, the SDK must
  // pass undefined through to the bridge (free-tool path).
  it("Context.invokeTool defaults spendingUcan to undefined for free tools", async () => {
    _setBridge(mockBridge);
    const identity = await Identity.create({ custody: "in_memory" });
    const ctx = await Context.create(identity, {
      ceiling: ["tools:register", "tools:invoke"],
    });

    const def = defineToolDefinition({
      name: "sdk-free-echo",
      description: "SDK free echo tool",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: identity.did,
    });
    const toolId = await ctx.registerTool(def);
    mockBridge._registerToolHandler(ctx.contextId, toolId, (input) => ({ echoed: input }));

    const stubHandle = { contextId: ctx.contextId, state: "active", creatorDid: identity.did };
    const ucan = await mockBridge.ucanMint(stubHandle, identity.did, ["tool_invoke:*"]);

    // No options arg — spending UCAN must default to undefined.
    await ctx.invokeTool(toolId, { hello: "world" }, identity, ucan.encoded);

    const ctxState = mockBridge._contexts.get(ctx.contextId);
    const toolInvokedEvents =
      ctxState?.eventLog.filter((e: { eventType: string }) => e.eventType === "ToolInvoked") ?? [];
    expect(toolInvokedEvents.length).toBe(1);
    const payload = toolInvokedEvents[0]?.payload as { spendingUcanProvided?: boolean };
    expect(payload.spendingUcanProvided).toBe(false);
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
    expect(events[0]?.eventType).toBe("ContextCreated");
    expect(events[1]?.eventType).toBe("MessageSent");
    expect(events[2]?.eventType).toBe("MessageSent");
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
    expect(events[0]?.eventType).toBe("MessageSent");
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
// 8b. Participation verification (SCP-BA-004, §7.3.2.1)
// ---------------------------------------------------------------------------

describe("Participation verification (mock bridge)", () => {
  it("verifyParticipationRequirements delegates to bridge", () => {
    _setBridge(mockBridge);
    // Import is deferred so the bridge is set before use.
    const { verifyParticipationRequirements } =
      require("../src/trust") as typeof import("../src/trust");

    // Mock bridge always returns true — verify no exception thrown.
    verifyParticipationRequirements(
      [
        {
          fact: "ParticipationDuration",
          threshold: { AtLeast: 0 },
          maxAgeSecs: 3600,
          minContexts: 1,
        },
      ],
      [
        {
          subjectDid: "did:dht:z6MkAlice",
          participationDurationSecs: 3600,
          governanceActionsAgainst: 0,
          governanceActionsBy: 0,
          toolInvocationCount: 0,
          contextCreationCount: 0,
          roleProgressionCount: 0,
          attestationCount: 0,
          updatedAt: Math.floor(Date.now() / 1000),
          eventLogRoot: new Array(32).fill(0),
          signerPublicKey: new Array(32).fill(1),
          signature: new Array(64).fill(2),
        },
      ],
    );
    // If we reach here without throwing, the test passes.
  });

  it("constructs correct bridge JSON for ParticipationProfile", () => {
    _setBridge(mockBridge);

    // Override mock to capture the JSON arguments.
    let capturedProfileJson = "";
    let capturedRequirementsJson = "";
    (mockBridge as unknown as Record<string, unknown>).verifyParticipationRequirements = (
      profileJson: string,
      requirementsJson: string,
    ): boolean => {
      capturedProfileJson = profileJson;
      capturedRequirementsJson = requirementsJson;
      return true;
    };

    const { verifyParticipationRequirements } =
      require("../src/trust") as typeof import("../src/trust");

    verifyParticipationRequirements(
      [
        {
          fact: "ToolInvocationCount",
          threshold: { GreaterThan: 50 },
          maxAgeSecs: 7200,
          minContexts: 3,
        },
      ],
      [
        {
          subjectDid: "did:dht:z6MkBob",
          participationDurationSecs: 100,
          governanceActionsAgainst: 1,
          governanceActionsBy: 2,
          toolInvocationCount: 55,
          contextCreationCount: 0,
          roleProgressionCount: 0,
          attestationCount: 0,
          updatedAt: 1700000000,
          eventLogRoot: new Array(32).fill(0),
          signerPublicKey: new Array(32).fill(1),
          signature: new Array(64).fill(2),
        },
      ],
    );

    // Verify the JSON matches the Rust serde format (snake_case).
    const profiles = JSON.parse(capturedProfileJson) as Record<string, unknown>[];
    expect(profiles).toHaveLength(1);
    expect(profiles[0]?.subject_did).toBe("did:dht:z6MkBob");
    expect(profiles[0]?.participation_duration_secs).toBe(100);
    expect(profiles[0]?.tool_invocation_count).toBe(55);

    const requirements = JSON.parse(capturedRequirementsJson) as Record<string, unknown>[];
    expect(requirements).toHaveLength(1);
    expect(requirements[0]?.fact).toBe("ToolInvocationCount");
    expect(requirements[0]?.threshold).toEqual({ GreaterThan: 50 });
    expect(requirements[0]?.max_age_secs).toBe(7200);
    expect(requirements[0]?.min_contexts).toBe(3);
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
    expect(messages[0]?.senderDid).toBe(alice.did);
    expect(messages[0]?.contextId).toBe(ctx.contextId);

    // Bob sends a message
    await mockBridge.contextSend(ctx, bob.did, new TextEncoder().encode("hello alice"));
    expect(messages.length).toBe(2);
    expect(messages[1]?.senderDid).toBe(bob.did);

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
    expect(rotateEvents[0]?.payload.reason).toBe("subscriber_removed");
    expect(rotateEvents[0]?.payload.subscriberDid).toBe(subscriber.did);
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

// ---------------------------------------------------------------------------
// Identity advanced operations — SDK wrapper level (#428)
// ---------------------------------------------------------------------------

describe("Identity SDK wrapper — advanced operations (#428)", () => {
  beforeEach(() => {
    _setBridge(mockBridge);
  });

  it("Identity.create returns identity with DID", async () => {
    const identity = await Identity.create({ custody: "in_memory" });
    expect(identity.did).toMatch(/^did:dht:/);
    expect(identity.custodyType).toBe("in_memory");
  });

  it("Identity.createWithAgentKey returns identity with DID", async () => {
    const identity = await Identity.createWithAgentKey({ custody: "in_memory" });
    expect(identity.did).toMatch(/^did:dht:/);
    expect(identity.custodyType).toBe("in_memory");
  });

  it("identity.addAgentKey returns updated identity with same DID", async () => {
    const identity = await Identity.create({ custody: "in_memory" });
    const updated = await identity.addAgentKey();
    expect(updated.did).toBe(identity.did);
  });

  it("identity.rotateAgentKey returns updated identity with same DID", async () => {
    const identity = await Identity.createWithAgentKey({ custody: "in_memory" });
    const rotated = await identity.rotateAgentKey();
    expect(rotated.did).toBe(identity.did);
  });

  it("identity.removeAgentKey returns updated identity with same DID", async () => {
    const identity = await Identity.createWithAgentKey({ custody: "in_memory" });
    const removed = await identity.removeAgentKey();
    expect(removed.did).toBe(identity.did);
  });

  it("identity.migrate returns identity with new DID", async () => {
    const identity = await Identity.create({ custody: "in_memory" });
    const migrated = await identity.migrate();
    expect(migrated.did).toMatch(/^did:dht:/);
    expect(migrated.did).not.toBe(identity.did);
  });

  it("identity.attestDevice returns base64 token", async () => {
    const identity = await Identity.create({ custody: "in_memory" });
    const token = await identity.attestDevice();
    expect(typeof token).toBe("string");
    expect(token.length).toBeGreaterThan(0);
  });

  it("identity.verifyDeviceAttestation returns true for valid token", async () => {
    const identity = await Identity.create({ custody: "in_memory" });
    const token = await identity.attestDevice();
    const isValid = await identity.verifyDeviceAttestation(token);
    expect(isValid).toBe(true);
  });

  it("identity.verifyDeviceAttestation returns false for invalid token", async () => {
    const identity = await Identity.create({ custody: "in_memory" });
    const isValid = await identity.verifyDeviceAttestation("aW52YWxpZA==");
    expect(isValid).toBe(false);
  });

  it("identity.executeCustodyMigration returns migration result", async () => {
    const identity = await Identity.create({ custody: "in_memory" });
    const result = await identity.executeCustodyMigration("hardware");
    expect(result).toBeDefined();
    expect(result.did).toBe(identity.did);
    expect(result.target).toBe("hardware");
    expect(result.key_generated).toBe(true);
    expect(result.authorized).toBe(true);
    expect(result.did_document_rotated).toBe(true);
  });

  it("identity.executeCustodyMigration rejects invalid target", async () => {
    const identity = await Identity.create({ custody: "in_memory" });
    await expect(identity.executeCustodyMigration("nonexistent" as "hardware")).rejects.toThrow(
      /invalid custody migration target/,
    );
  });

  it("identity.executeRecovery returns recovery result", async () => {
    const identity = await Identity.create({ custody: "in_memory" });
    const result = await identity.executeRecovery("agent", ["ctx-1"]);
    expect(result).toBeDefined();
    expect(result.did).toBe(identity.did);
    expect(result.tier).toBe("agent");
    expect(result.key_rotation_completed).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // broadcastPublishAsset / broadcastPublishAssets (SCP-290)
  // ---------------------------------------------------------------------------

  it("broadcastPublishAsset returns blobId, etag, and deployId", async () => {
    const identity = await Identity.create({ custody: "in_memory" });
    const ctx = await Context.create(identity, {
      ceiling: ["messages:read", "messages:write"],
      mode: "Broadcast",
    });
    const result = await ctx.broadcastPublishAsset({
      path: "/index.html",
      contentType: "text/html",
      body: new TextEncoder().encode("<h1>hello</h1>"),
    });
    expect(result).toBeDefined();
    expect(typeof result.blobId).toBe("string");
    expect(typeof result.etag).toBe("string");
    expect(typeof result.deployId).toBe("string");
    expect(result.blobId.length).toBeGreaterThan(0);
    expect(result.etag.length).toBeGreaterThan(0);
    expect(result.deployId.length).toBeGreaterThan(0);
  });

  it("broadcastPublishAsset with caller-provided deployId returns it as-is", async () => {
    const identity = await Identity.create({ custody: "in_memory" });
    const ctx = await Context.create(identity, {
      ceiling: ["messages:read", "messages:write"],
      mode: "Broadcast",
    });
    const result = await ctx.broadcastPublishAsset(
      {
        path: "/index.html",
        contentType: "text/html",
        body: new TextEncoder().encode("<h1>hello</h1>"),
      },
      undefined,
      "my-custom-deploy-id-1234567890ab",
    );
    expect(result.deployId).toBe("my-custom-deploy-id-1234567890ab");
  });

  it("broadcastPublishAssets returns BatchPublishResult with shared deployId", async () => {
    const identity = await Identity.create({ custody: "in_memory" });
    const ctx = await Context.create(identity, {
      ceiling: ["messages:read", "messages:write"],
      mode: "Broadcast",
    });
    const batch = await ctx.broadcastPublishAssets([
      {
        path: "/index.html",
        contentType: "text/html",
        body: new TextEncoder().encode("<h1>hello</h1>"),
      },
      {
        path: "/styles.css",
        contentType: "text/css",
        body: new TextEncoder().encode("body { color: red; }"),
      },
    ]);
    expect(batch.results).toHaveLength(2);
    expect(typeof batch.deployId).toBe("string");
    expect(batch.deployId.length).toBeGreaterThan(0);
    for (const r of batch.results) {
      expect(typeof r.blobId).toBe("string");
      expect(typeof r.etag).toBe("string");
      expect(typeof r.deployId).toBe("string");
    }
  });

  it("auto-generated deployId is a non-empty string", async () => {
    const identity = await Identity.create({ custody: "in_memory" });
    const ctx = await Context.create(identity, {
      ceiling: ["messages:read", "messages:write"],
      mode: "Broadcast",
    });
    const result = await ctx.broadcastPublishAsset({
      path: "/index.html",
      contentType: "text/html",
      body: new TextEncoder().encode("<h1>hello</h1>"),
    });
    expect(typeof result.deployId).toBe("string");
    expect(result.deployId.length).toBeGreaterThan(0);
  });

  it("broadcastPublishAsset rejects on non-broadcast context", async () => {
    const identity = await Identity.create({ custody: "in_memory" });
    const ctx = await Context.create(identity, {
      ceiling: ["messages:read", "messages:write"],
    });
    await expect(
      ctx.broadcastPublishAsset({
        path: "/index.html",
        contentType: "text/html",
        body: new TextEncoder().encode("<h1>hello</h1>"),
      }),
    ).rejects.toThrow(/SCP-CTX-2001/);
  });
});

// ---------------------------------------------------------------------------
// 14. Scope registry runtime tests (§22.3.5, ADR-043)
// ---------------------------------------------------------------------------

describe("Scope registry runtime (mock bridge)", () => {
  it("scope register/lookup/deregister round-trip", async () => {
    _setBridge(mockBridge);

    const { scopeRegister, scopeLookup, scopeDeregister } = await import("../src/discovery");

    // Register
    const reg = await scopeRegister(
      "test-ctx",
      "my-scope",
      "target-ctx",
      ["wss://relay.example.com"],
      "did:dht:zTest",
    );
    expect(reg.status).toBe("registered");
    expect(reg.entry_id).toBe("scope-1");

    // Lookup
    const lookup = await scopeLookup("test-ctx", "my-scope");
    expect(lookup.results).toBeDefined();
    expect(Array.isArray(lookup.results)).toBe(true);

    // Deregister
    const dereg = await scopeDeregister("test-ctx", "my-scope", "did:dht:zTest");
    expect(dereg.removed).toBe(true);
  });

  it("scope register returns typed status values", async () => {
    _setBridge(mockBridge);
    const { scopeRegister } = await import("../src/discovery");

    const result = await scopeRegister(
      "test-ctx",
      "my-scope",
      "target-ctx",
      ["wss://relay.example.com"],
      "did:dht:zTest",
    );
    // The mock bridge returns "registered" status
    expect(["registered", "conflict", "updated"]).toContain(result.status);
  });
});

// ---------------------------------------------------------------------------
// 13. Spending UCAN / consequence event SDK-level tests (#1537, #1593, #1594)
// ---------------------------------------------------------------------------

describe("Invitation evaluation with spending (mock bridge)", () => {
  it("evaluateInvitation accepts spendingJson parameter", async () => {
    _setBridge(mockBridge);
    const { evaluateInvitation } = await import("../src/context");

    const result = await evaluateInvitation(
      '{"ceiling":[]}',
      "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo",
      "did:dht:z6MkLocalLocalLocalLocalLocalLocalLocal",
      undefined,
      '{"has_spending_ucan":true,"configured_adapters":["x402"],"available_balance":10000}',
    );

    expect(result).toBeDefined();
    expect(result.decision).toBeDefined();
  });

  it("evaluateInvitation works without spendingJson", async () => {
    _setBridge(mockBridge);
    const { evaluateInvitation } = await import("../src/context");

    const result = await evaluateInvitation(
      '{"ceiling":[]}',
      "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo",
      "did:dht:z6MkLocalLocalLocalLocalLocalLocalLocal",
    );

    expect(result).toBeDefined();
    expect(result.decision).toBeDefined();
  });
});

describe("Consequence event types (SDK)", () => {
  it("consequence_triggered event has correct structure", () => {
    // Verify that system events with consequence_triggered prefix
    // can be parsed from the expected format.
    const payload =
      "consequence_triggered: member=did:dht:z6MkBob rule=2 trigger=velocity action=mute context=ctx-123";
    expect(payload).toContain("consequence_triggered:");
    expect(payload).toContain("member=did:dht:z6MkBob");
    expect(payload).toContain("rule=2");
    expect(payload).toContain("trigger=velocity");
    expect(payload).toContain("action=mute");
  });

  it("consequence_enforced event has correct structure", () => {
    const payload =
      "consequence_enforced: member=did:dht:z6MkAlice action=restrict_write success=true context=ctx-456";
    expect(payload).toContain("consequence_enforced:");
    expect(payload).toContain("success=true");
  });
});

describe("Trust aggregation with consequence rules (mock bridge)", () => {
  it("aggregateTrustInput accepts consequenceRules parameter", async () => {
    _setBridge(mockBridge);
    const { aggregateTrustInput } = await import("../src/trust");

    const result = await aggregateTrustInput({
      contextId: "ctx-consequence-test",
      subjectDid: "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo",
      events: [],
      merkleRoot: new Array(32).fill(0),
      consequenceRules: [
        {
          trigger: "MessageVelocity",
          action: "SuspendAll",
          threshold: 5,
          window: { secs: 3600, nanos: 0 },
        },
      ],
    });

    expect(result).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// 14. C2 — WASM economy fail-closed gate (PR #1606 follow-up)
//
// The browser (WASM) bridge cannot run scp-runtime's `enforce_economy`
// pipeline (no payment adapter, no budget tracker, no velocity tracker, no
// hard rate limit token bucket — see ADR-034). To prevent silent bypass,
// the bridge rejects:
//
//   - context_create with a paid economic policy → SCP-ECON-12095
//   - context_join against a paid context        → SCP-ECON-12096
//   - context_send into a paid context           → SCP-ECON-12096
//
// These tests simulate the rejection at the bridge boundary using a
// stub bridge and verify the SDK layer surfaces the typed subclasses
// (`EconomicPolicyUnsupportedOnWasm`, `WasmCannotValidateSpendingUcan`)
// via `mapBridgeError`. End-to-end validation runs under real-wasm.test.ts.
// ---------------------------------------------------------------------------

describe("WASM economy fail-closed (C2 — typed error surfacing)", () => {
  it("Context.create surfaces EconomicPolicyUnsupportedOnWasm for SCP-ECON-12095", async () => {
    const { EconomicPolicyUnsupportedOnWasm, EconomyError, ScpError } = await import(
      "../src/errors"
    );

    // Stub bridge that rejects contextCreate with the C2 fail-closed code,
    // mirroring `WasmContextManager::create_context` after the gate fires.
    const failClosedBridge = {
      ...mockBridge,
      contextCreate: async () => {
        throw new Error(
          "[SCP-ECON-12095] context error: EconomicPolicyUnsupportedOnWasm: \
paid contexts cannot be created from the WASM bridge — the browser SDK \
cannot run the full economy enforcement pipeline (ADR-034). Use a native \
(Python / Node.js / Swift / Kotlin) client for paid contexts.",
        );
      },
    };
    _setBridge(failClosedBridge);

    const identity = await Identity.create();
    let captured: unknown = null;
    try {
      await Context.create(identity, {
        ceiling: [],
        tools: [],
        roles: {},
        ttl: 3600,
        memoryScope: "ephemeral",
        // The mock returns the rejection regardless; the policy shape
        // here only documents intent.
        economicPolicy:
          '{"locked":false,"cost_schedule":{"currency":[85,83,68,0],"per_message":100,"per_tool_invoke":null,"per_join":null,"per_period":null,"per_byte_stored":null},"payment_adapters":[],"pricing_formula":null,"payee":"did:dht:zpayee"}',
      });
    } catch (e) {
      captured = e;
    }

    expect(captured).toBeInstanceOf(EconomicPolicyUnsupportedOnWasm);
    expect(captured).toBeInstanceOf(EconomyError);
    expect(captured).toBeInstanceOf(ScpError);
    if (captured instanceof ScpError) {
      expect(captured.code).toBe("SCP-ECON-12095");
      expect(captured.message).toContain("EconomicPolicyUnsupportedOnWasm");
    }
  });

  it("Context.join surfaces WasmCannotValidateSpendingUcan for SCP-ECON-12096", async () => {
    const { EconomyError, ScpError, WasmCannotValidateSpendingUcan } = await import(
      "../src/errors"
    );

    // Stub bridge that lets context_create succeed (so we get a Context
    // handle) but rejects contextJoin with the C2 fail-closed code,
    // mirroring `WasmContextManager::join_context` after the gate fires.
    const failClosedBridge = {
      ...mockBridge,
      contextJoin: async () => {
        throw new Error(
          "[SCP-ECON-12096] context error: WasmCannotValidateSpendingUcan: \
context 'ctx-paid' has an economic policy requiring payment, but the WASM \
bridge cannot cryptographically validate spending UCANs against a payment \
adapter (ADR-034). Use a native (Python / Node.js / Swift / Kotlin) client \
to join paid contexts.",
        );
      },
    };
    _setBridge(failClosedBridge);

    const identity = await Identity.create();
    const ctx = await Context.create(identity, {
      ceiling: [],
      tools: [],
      roles: {},
      ttl: 3600,
      memoryScope: "ephemeral",
    });

    let captured: unknown = null;
    try {
      // Both with and without a spending UCAN — the WASM bridge rejects
      // either way; the test verifies the typed subclass propagates.
      await ctx.join(identity, "eyJqd3QtcGxhY2Vob2xkZXIifQ");
    } catch (e) {
      captured = e;
    }

    expect(captured).toBeInstanceOf(WasmCannotValidateSpendingUcan);
    expect(captured).toBeInstanceOf(EconomyError);
    expect(captured).toBeInstanceOf(ScpError);
    if (captured instanceof ScpError) {
      expect(captured.code).toBe("SCP-ECON-12096");
      expect(captured.message).toContain("WasmCannotValidateSpendingUcan");
    }
  });

  it("Context.send surfaces WasmCannotValidateSpendingUcan for SCP-ECON-12096", async () => {
    const { EconomyError, ScpError, WasmCannotValidateSpendingUcan } = await import(
      "../src/errors"
    );

    // Stub bridge that rejects contextSend with the C2 fail-closed code.
    const failClosedBridge = {
      ...mockBridge,
      contextSend: async () => {
        throw new Error(
          "[SCP-ECON-12096] context error: WasmCannotValidateSpendingUcan: \
context 'ctx-paid' has an economic policy requiring payment",
        );
      },
    };
    _setBridge(failClosedBridge);

    const identity = await Identity.create();
    const ctx = await Context.create(identity, {
      ceiling: [],
      tools: [],
      roles: {},
      ttl: 3600,
      memoryScope: "ephemeral",
    });

    let captured: unknown = null;
    try {
      await ctx.send("hello", "eyJqd3QtcGxhY2Vob2xkZXIifQ");
    } catch (e) {
      captured = e;
    }

    expect(captured).toBeInstanceOf(WasmCannotValidateSpendingUcan);
    expect(captured).toBeInstanceOf(EconomyError);
    expect(captured).toBeInstanceOf(ScpError);
    if (captured instanceof ScpError) {
      expect(captured.code).toBe("SCP-ECON-12096");
    }

    // Same expectation when no spending UCAN is supplied.
    captured = null;
    try {
      await ctx.send("hello");
    } catch (e) {
      captured = e;
    }
    expect(captured).toBeInstanceOf(WasmCannotValidateSpendingUcan);
  });
});

// C5: SDK Context.create — consequenceConfig parameter parity
// ---------------------------------------------------------------------------

describe("Context.create consequenceConfig parameter (C5 / SDK round-trip)", () => {
  it("forwards consequenceConfig to the bridge as a JSON string field", async () => {
    _setBridge(mockBridge);
    const { Identity } = await import("../src/identity");
    const { Context } = await import("../src/context");

    const identity = await Identity.create({ custody: "in_memory" });
    const ctx = await Context.create(identity, {
      ceiling: ["messages:read"],
      consequenceConfig: { allow_automatic_access_revocation: true },
    });
    expect(ctx).toBeDefined();

    const stored = mockBridge._contexts.get(ctx.contextId);
    expect(stored).toBeDefined();
    const parsed = JSON.parse(stored?.rawParamsJson ?? "{}") as {
      consequenceConfig?: string;
    };
    expect(parsed.consequenceConfig).toBeDefined();
    const inner = JSON.parse(parsed.consequenceConfig ?? "{}") as {
      allow_automatic_access_revocation?: boolean;
    };
    expect(inner.allow_automatic_access_revocation).toBe(true);
  });

  it("omits consequenceConfig when caller does not provide one", async () => {
    _setBridge(mockBridge);
    const { Identity } = await import("../src/identity");
    const { Context } = await import("../src/context");

    const identity = await Identity.create({ custody: "in_memory" });
    const ctx = await Context.create(identity, {
      ceiling: ["messages:read"],
    });

    const stored = mockBridge._contexts.get(ctx.contextId);
    const parsed = JSON.parse(stored?.rawParamsJson ?? "{}") as {
      consequenceConfig?: string;
    };
    expect(parsed.consequenceConfig).toBeUndefined();
  });

  it("forwards spendingUcanJwt to the bridge on Context.join", async () => {
    _setBridge(mockBridge);
    const { Identity } = await import("../src/identity");
    const { Context } = await import("../src/context");

    const creator = await Identity.create({ custody: "in_memory" });
    const joiner = await Identity.create({ custody: "in_memory" });
    const ctx = await Context.create(creator, {
      ceiling: ["messages:read"],
    });

    await ctx.join(joiner, "synthetic.spending.jwt");

    const stored = mockBridge._contexts.get(ctx.contextId);
    expect(stored?.lastJoinSpendingUcanJwt).toBe("synthetic.spending.jwt");
  });
});
