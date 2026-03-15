/**
 * Tests for the tools module.
 *
 * Covers tool definition construction, cross-context invocation,
 * and stateful tool sessions.
 *
 * See ADR-010 (Tool Registry), spec sections 6.2 / 6.2.1,
 * and `.docs/scaffold/typescript.md`.
 */

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { ToolError, ValidationError } from "../src/errors";
import { _resetBridge, _setBridge } from "../src/internal/bridge";
import {
  defineToolDefinition,
  toolInvokeCrossContext,
  toolSessionClose,
  toolSessionCreate,
  toolSessionInvoke,
} from "../src/tools";
import { createMockBridge } from "./mock-bridge";

// ---------------------------------------------------------------------------
// defineToolDefinition
// ---------------------------------------------------------------------------

describe("defineToolDefinition", () => {
  it("creates a valid tool definition", () => {
    const def = defineToolDefinition({
      name: "test-tool",
      description: "A test tool",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: "did:dht:z6MkTest",
    });

    expect(def.name).toBe("test-tool");
    expect(def.description).toBe("A test tool");
    expect(def.operator).toBe("did:dht:z6MkTest");
  });

  it("includes optional fields when provided", () => {
    const testVectors = [{ input: { x: 1 }, expectedOutput: { y: 2 }, description: "maps x to y" }];
    const hash = new Uint8Array(32);

    const def = defineToolDefinition({
      name: "test-tool",
      description: "A test tool",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: "did:dht:z6MkTest",
      testVectors,
      implementationHash: hash,
    });

    expect(def.testVectors).toEqual(testVectors);
    expect(def.implementationHash).toBe(hash);
  });

  it("rejects empty tool name", () => {
    expect(() =>
      defineToolDefinition({
        name: "",
        description: "A test tool",
        inputSchema: { type: "object" },
        outputSchema: { type: "object" },
        operator: "did:dht:z6MkTest",
      }),
    ).toThrow(ValidationError);
  });

  it("rejects empty tool description", () => {
    expect(() =>
      defineToolDefinition({
        name: "test-tool",
        description: "",
        inputSchema: { type: "object" },
        outputSchema: { type: "object" },
        operator: "did:dht:z6MkTest",
      }),
    ).toThrow(ValidationError);
  });

  it("rejects empty operator DID", () => {
    expect(() =>
      defineToolDefinition({
        name: "test-tool",
        description: "A test tool",
        inputSchema: { type: "object" },
        outputSchema: { type: "object" },
        operator: "",
      }),
    ).toThrow(ValidationError);
  });
});

// ---------------------------------------------------------------------------
// Cross-context tool invocation (spec section 6.2)
// ---------------------------------------------------------------------------

describe("toolInvokeCrossContext", () => {
  let mockBridge: ReturnType<typeof createMockBridge>;

  beforeEach(async () => {
    mockBridge = createMockBridge();
    _setBridge(mockBridge);
  });

  afterEach(() => {
    _resetBridge();
  });

  it("invokes a tool across contexts and returns result", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const sourceHandle = await mockBridge.contextCreate(identity, "{}");
    const targetHandle = await mockBridge.contextCreate(identity, "{}");

    // Register a tool in the target context
    const toolId = await mockBridge.toolRegister(targetHandle, {
      name: "calculator",
      description: "Adds numbers",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: identity.did,
    });

    const result = await toolInvokeCrossContext(
      sourceHandle,
      targetHandle,
      toolId,
      '{"a": 1}',
      identity.did,
      "mock-ucan-token",
      0,
    );

    expect(result.sourceContextId).toBe(sourceHandle.contextId);
    expect(result.targetContextId).toBe(targetHandle.contextId);
    expect(result.invokerDid).toBe(identity.did);
    expect(result.chainDepth).toBe(0);
    expect(result.timestamp).toBeGreaterThan(0);

    const output = JSON.parse(result.output);
    expect(output.tool).toBe(toolId);
    expect(output.status).toBe("validated");
  });

  it("rejects chainDepth > 5 (protocol hard max per spec §24.4)", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const sourceHandle = await mockBridge.contextCreate(identity, "{}");
    const targetHandle = await mockBridge.contextCreate(identity, "{}");

    await expect(
      toolInvokeCrossContext(
        sourceHandle,
        targetHandle,
        "tool-test",
        "{}",
        identity.did,
        "token",
        6,
      ),
    ).rejects.toThrow(ValidationError);
  });

  it("accepts chainDepth at protocol hard max (5)", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const sourceHandle = await mockBridge.contextCreate(identity, "{}");
    const targetHandle = await mockBridge.contextCreate(identity, "{}");

    const toolId = await mockBridge.toolRegister(targetHandle, {
      name: "deep-tool",
      description: "Deep chain tool",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: identity.did,
    });

    const result = await toolInvokeCrossContext(
      sourceHandle,
      targetHandle,
      toolId,
      "{}",
      identity.did,
      "token",
      5,
    );

    expect(result.chainDepth).toBe(5);
  });

  it("rejects negative chainDepth", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const sourceHandle = await mockBridge.contextCreate(identity, "{}");
    const targetHandle = await mockBridge.contextCreate(identity, "{}");

    await expect(
      toolInvokeCrossContext(
        sourceHandle,
        targetHandle,
        "tool-test",
        "{}",
        identity.did,
        "token",
        -1,
      ),
    ).rejects.toThrow(ValidationError);
  });

  it("rejects non-integer chainDepth", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const sourceHandle = await mockBridge.contextCreate(identity, "{}");
    const targetHandle = await mockBridge.contextCreate(identity, "{}");

    await expect(
      toolInvokeCrossContext(
        sourceHandle,
        targetHandle,
        "tool-test",
        "{}",
        identity.did,
        "token",
        1.5,
      ),
    ).rejects.toThrow(ValidationError);
  });

  it("throws ToolError SCP-TOOL-6010 when source context is not active", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const sourceHandle = await mockBridge.contextCreate(identity, "{}");
    const targetHandle = await mockBridge.contextCreate(identity, "{}");

    // Close the source context to make it inactive
    await mockBridge.contextClose(sourceHandle, identity.did);

    await expect(
      toolInvokeCrossContext(
        sourceHandle,
        targetHandle,
        "tool-test",
        "{}",
        identity.did,
        "token",
        0,
      ),
    ).rejects.toThrow(ToolError);

    try {
      await toolInvokeCrossContext(
        sourceHandle,
        targetHandle,
        "tool-test",
        "{}",
        identity.did,
        "token",
        0,
      );
    } catch (error) {
      expect(error).toBeInstanceOf(ToolError);
      expect((error as ToolError).code).toBe("SCP-TOOL-6010");
    }
  });

  it("throws ToolError SCP-TOOL-6011 when target context is not active", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const sourceHandle = await mockBridge.contextCreate(identity, "{}");
    const targetHandle = await mockBridge.contextCreate(identity, "{}");

    // Close the target context to make it inactive
    await mockBridge.contextClose(targetHandle, identity.did);

    await expect(
      toolInvokeCrossContext(
        sourceHandle,
        targetHandle,
        "tool-test",
        "{}",
        identity.did,
        "token",
        0,
      ),
    ).rejects.toThrow(ToolError);

    try {
      await toolInvokeCrossContext(
        sourceHandle,
        targetHandle,
        "tool-test",
        "{}",
        identity.did,
        "token",
        0,
      );
    } catch (error) {
      expect(error).toBeInstanceOf(ToolError);
      expect((error as ToolError).code).toBe("SCP-TOOL-6011");
    }
  });
});

// ---------------------------------------------------------------------------
// Stateful tool sessions (spec section 6.2.1)
// ---------------------------------------------------------------------------

describe("toolSessionCreate", () => {
  let mockBridge: ReturnType<typeof createMockBridge>;

  beforeEach(async () => {
    mockBridge = createMockBridge();
    _setBridge(mockBridge);
  });

  afterEach(() => {
    _resetBridge();
  });

  it("creates a session and returns a session ID", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const handle = await mockBridge.contextCreate(identity, "{}");

    const toolId = await mockBridge.toolRegister(handle, {
      name: "stateful-tool",
      description: "A stateful tool",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: identity.did,
    });

    const result = await toolSessionCreate(handle, toolId, "source-ctx-1");

    expect(result.sessionId).toBeTruthy();
    expect(typeof result.sessionId).toBe("string");
  });

  it("creates a session with TTL", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const handle = await mockBridge.contextCreate(identity, "{}");

    const toolId = await mockBridge.toolRegister(handle, {
      name: "ttl-tool",
      description: "TTL tool",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: identity.did,
    });

    const result = await toolSessionCreate(handle, toolId, "source-ctx-1", 300);
    expect(result.sessionId).toBeTruthy();
  });

  it("rejects negative ttlSeconds", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const handle = await mockBridge.contextCreate(identity, "{}");

    await expect(toolSessionCreate(handle, "tool-test", "source-ctx-1", -1)).rejects.toThrow(
      ValidationError,
    );
  });

  it("rejects non-integer ttlSeconds", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const handle = await mockBridge.contextCreate(identity, "{}");

    await expect(toolSessionCreate(handle, "tool-test", "source-ctx-1", 1.5)).rejects.toThrow(
      ValidationError,
    );
  });
});

describe("toolSessionInvoke", () => {
  let mockBridge: ReturnType<typeof createMockBridge>;

  beforeEach(async () => {
    mockBridge = createMockBridge();
    _setBridge(mockBridge);
  });

  afterEach(() => {
    _resetBridge();
  });

  it("invokes a tool within a session and returns typed result with provenance", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const handle = await mockBridge.contextCreate(identity, "{}");

    const toolId = await mockBridge.toolRegister(handle, {
      name: "session-tool",
      description: "A session tool",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: identity.did,
    });

    const session = await toolSessionCreate(handle, toolId, "source-ctx-1");
    const result = await toolSessionInvoke(
      handle,
      session.sessionId,
      '{"x": 42}',
      identity.did,
      "mock-ucan-token",
    );

    // Verify provenance metadata on the result
    expect(result.sessionId).toBe(session.sessionId);
    expect(result.contextId).toBe(handle.contextId);
    expect(result.invokerDid).toBe(identity.did);
    expect(result.timestamp).toBeGreaterThan(0);

    // Verify the raw bridge output is in the output field
    const parsed = JSON.parse(result.output);
    expect(parsed.tool).toBe(toolId);
    expect(parsed.session_id).toBe(session.sessionId);
    expect(parsed.call_count).toBe(1);
    expect(parsed.status).toBe("validated");
  });

  it("increments call count across invocations", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const handle = await mockBridge.contextCreate(identity, "{}");

    const toolId = await mockBridge.toolRegister(handle, {
      name: "counter-tool",
      description: "Counts calls",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: identity.did,
    });

    const session = await toolSessionCreate(handle, toolId, "source-ctx-1");

    await toolSessionInvoke(handle, session.sessionId, "{}", identity.did, "token");
    const result2 = await toolSessionInvoke(handle, session.sessionId, "{}", identity.did, "token");

    const parsed = JSON.parse(result2.output);
    expect(parsed.call_count).toBe(2);
  });
});

describe("toolSessionClose", () => {
  let mockBridge: ReturnType<typeof createMockBridge>;

  beforeEach(async () => {
    mockBridge = createMockBridge();
    _setBridge(mockBridge);
  });

  afterEach(() => {
    _resetBridge();
  });

  it("closes a session successfully", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const handle = await mockBridge.contextCreate(identity, "{}");

    const toolId = await mockBridge.toolRegister(handle, {
      name: "closable-tool",
      description: "Can be closed",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: identity.did,
    });

    const session = await toolSessionCreate(handle, toolId, "source-ctx-1");
    await toolSessionClose(handle, session.sessionId);

    // Subsequent invocation should fail
    await expect(
      toolSessionInvoke(handle, session.sessionId, "{}", identity.did, "token"),
    ).rejects.toThrow(/SCP-TOOL-6018/);
  });

  it("rejects closing a non-existent session", async () => {
    const identity = await mockBridge.identityCreate("in_memory");
    const handle = await mockBridge.contextCreate(identity, "{}");

    await expect(toolSessionClose(handle, "nonexistent-session")).rejects.toThrow(/SCP-TOOL-6021/);
  });
});
