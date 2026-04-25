/**
 * Tests for the tools module.
 *
 * Covers tool definition construction, cross-context invocation, and
 * stateful tool sessions via the SCP class method surface.
 *
 * Phase 4 PR 4 (#1549, ADR-048) deleted the free-function shims
 * (`toolInvokeCrossContext`, `toolSessionCreate`, etc.) and the stateful
 * mock bridge. Tests now drive the SDK through the Proxy-backed mock
 * native handle (`mountMockScp` / `createMockNativeScp`) configuring
 * stubs that emulate the NAPI surface.
 *
 * See ADR-010 (Tool Registry), spec sections 6.2 / 6.2.1, and ADR-048.
 */

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { ValidationError } from "../src/errors";
import type { SCP } from "../src/scp";
import { defineToolDefinition } from "../src/tools";
import { type MockNativeScp, mountMockScp } from "./mock-bridge";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const IDENTITY_DID = "did:dht:z6MkTestIdentity";

/** Installs a baseline stub set that mirrors the NAPI tool surface. */
function installToolStubs(native: MockNativeScp): void {
  native.__stub("identityCreate", async () => ({
    did: IDENTITY_DID,
    custodyType: "in_memory",
  }));

  let ctxCounter = 0;
  native.__stub("contextCreate", async () => {
    ctxCounter += 1;
    return {
      contextId: `ctx-${ctxCounter}`,
      state: "active",
      creatorDid: IDENTITY_DID,
    };
  });

  const closedContexts = new Set<string>();
  native.__stub("contextClose", async (handleArg) => {
    const h = handleArg as { contextId: string };
    closedContexts.add(h.contextId);
  });

  let toolCounter = 0;
  native.__stub("toolRegister", async () => {
    toolCounter += 1;
    return `tool-${toolCounter}`;
  });

  native.__stub(
    "toolInvokeCrossContext",
    async (sourceArg, targetArg, toolIdArg, _inputJson, invokerDidArg, _ucan, depthArg) => {
      const source = sourceArg as { contextId: string };
      const target = targetArg as { contextId: string };
      const toolId = toolIdArg as string;
      const invokerDid = invokerDidArg as string;
      const chainDepth = depthArg as number;

      if (!Number.isInteger(chainDepth) || chainDepth < 0 || chainDepth > 255) {
        throw new Error(
          "[SCP-VALID-7002] chainDepth must be an integer in range 0-255 (u8 range per ADR-043)",
        );
      }
      if (closedContexts.has(source.contextId)) {
        throw new Error("[SCP-TOOL-6010] source context is not active");
      }
      if (closedContexts.has(target.contextId)) {
        throw new Error("[SCP-TOOL-6011] target context is not active");
      }
      return JSON.stringify({
        tool: toolId,
        status: "validated",
        invoker: invokerDid,
        chainDepth,
      });
    },
  );

  const sessions = new Map<string, { closed: boolean; callCount: number; toolId: string }>();
  let sessionCounter = 0;

  native.__stub("toolSessionCreate", async (_handle, toolIdArg, _source, ttlArg) => {
    const toolId = toolIdArg as string;
    const ttl = ttlArg as number | undefined | null;
    if (ttl !== undefined && ttl !== null) {
      if (!Number.isInteger(ttl) || ttl < 0) {
        throw new Error("[SCP-VALID-7003] ttlSeconds must be a non-negative integer");
      }
    }
    sessionCounter += 1;
    const sessionId = `session-${sessionCounter}`;
    sessions.set(sessionId, { closed: false, callCount: 0, toolId });
    return sessionId;
  });

  native.__stub("toolSessionInvoke", async (_handle, sessionIdArg) => {
    const sessionId = sessionIdArg as string;
    const state = sessions.get(sessionId);
    if (state === undefined) {
      throw new Error("[SCP-TOOL-6020] session does not exist");
    }
    if (state.closed) {
      throw new Error("[SCP-TOOL-6018] session is closed");
    }
    state.callCount += 1;
    return JSON.stringify({
      tool: state.toolId,
      session_id: sessionId,
      call_count: state.callCount,
      status: "validated",
    });
  });

  native.__stub("toolSessionClose", async (_handle, sessionIdArg) => {
    const sessionId = sessionIdArg as string;
    const state = sessions.get(sessionId);
    if (state === undefined) {
      throw new Error("[SCP-TOOL-6021] session does not exist");
    }
    state.closed = true;
  });
}

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
// Cross-context tool invocation (spec section 6.2) via scp.toolInvokeCrossContext
// ---------------------------------------------------------------------------

describe("scp.toolInvokeCrossContext", () => {
  let scp: SCP;
  let native: MockNativeScp;

  beforeEach(() => {
    const mount = mountMockScp();
    scp = mount.scp;
    native = mount.native;
    installToolStubs(native);
  });

  afterEach(async () => {
    await scp.shutdown(1);
  });

  it("invokes a tool across contexts and returns result", async () => {
    const identity = await scp.identityCreate("in_memory");
    const sourceHandle = await scp.contextCreate(identity, "{}");
    const targetHandle = await scp.contextCreate(identity, "{}");

    const toolId = await scp.toolRegister(targetHandle._rawHandle, {
      name: "calculator",
      description: "Adds numbers",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: identity.did,
    });

    const outputJson = await scp.toolInvokeCrossContext(
      sourceHandle._rawHandle,
      targetHandle._rawHandle,
      toolId,
      '{"a": 1}',
      identity.did,
      "mock-ucan-token",
      0,
    );
    const output = JSON.parse(outputJson) as { tool: string; status: string };
    expect(output.tool).toBe(toolId);
    expect(output.status).toBe("validated");
  });

  it("rejects chainDepth > 255 (u8 range per ADR-043)", async () => {
    const identity = await scp.identityCreate("in_memory");
    const sourceHandle = await scp.contextCreate(identity, "{}");
    const targetHandle = await scp.contextCreate(identity, "{}");

    await expect(
      scp.toolInvokeCrossContext(
        sourceHandle._rawHandle,
        targetHandle._rawHandle,
        "tool-test",
        "{}",
        identity.did,
        "token",
        256,
      ),
    ).rejects.toThrow(/SCP-VALID-7002/);
  });

  it("accepts chainDepth at u8 max (255)", async () => {
    const identity = await scp.identityCreate("in_memory");
    const sourceHandle = await scp.contextCreate(identity, "{}");
    const targetHandle = await scp.contextCreate(identity, "{}");

    const toolId = await scp.toolRegister(targetHandle._rawHandle, {
      name: "deep-tool",
      description: "Deep chain tool",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: identity.did,
    });

    const outputJson = await scp.toolInvokeCrossContext(
      sourceHandle._rawHandle,
      targetHandle._rawHandle,
      toolId,
      "{}",
      identity.did,
      "token",
      255,
    );
    const output = JSON.parse(outputJson) as { chainDepth: number };
    expect(output.chainDepth).toBe(255);
  });

  it("rejects negative chainDepth", async () => {
    const identity = await scp.identityCreate("in_memory");
    const sourceHandle = await scp.contextCreate(identity, "{}");
    const targetHandle = await scp.contextCreate(identity, "{}");

    await expect(
      scp.toolInvokeCrossContext(
        sourceHandle._rawHandle,
        targetHandle._rawHandle,
        "tool-test",
        "{}",
        identity.did,
        "token",
        -1,
      ),
    ).rejects.toThrow(/SCP-VALID-7002/);
  });

  it("rejects non-integer chainDepth", async () => {
    const identity = await scp.identityCreate("in_memory");
    const sourceHandle = await scp.contextCreate(identity, "{}");
    const targetHandle = await scp.contextCreate(identity, "{}");

    await expect(
      scp.toolInvokeCrossContext(
        sourceHandle._rawHandle,
        targetHandle._rawHandle,
        "tool-test",
        "{}",
        identity.did,
        "token",
        1.5,
      ),
    ).rejects.toThrow(/SCP-VALID-7002/);
  });

  it("surfaces SCP-TOOL-6010 when source context is not active", async () => {
    const identity = await scp.identityCreate("in_memory");
    const sourceHandle = await scp.contextCreate(identity, "{}");
    const targetHandle = await scp.contextCreate(identity, "{}");

    await scp.contextClose(sourceHandle._rawHandle, identity.did);

    await expect(
      scp.toolInvokeCrossContext(
        sourceHandle._rawHandle,
        targetHandle._rawHandle,
        "tool-test",
        "{}",
        identity.did,
        "token",
        0,
      ),
    ).rejects.toThrow(/SCP-TOOL-6010/);
  });

  it("surfaces SCP-TOOL-6011 when target context is not active", async () => {
    const identity = await scp.identityCreate("in_memory");
    const sourceHandle = await scp.contextCreate(identity, "{}");
    const targetHandle = await scp.contextCreate(identity, "{}");

    await scp.contextClose(targetHandle._rawHandle, identity.did);

    await expect(
      scp.toolInvokeCrossContext(
        sourceHandle._rawHandle,
        targetHandle._rawHandle,
        "tool-test",
        "{}",
        identity.did,
        "token",
        0,
      ),
    ).rejects.toThrow(/SCP-TOOL-6011/);
  });
});

// ---------------------------------------------------------------------------
// Stateful tool sessions (spec section 6.2.1) via scp.toolSession*
// ---------------------------------------------------------------------------

describe("scp.toolSessionCreate", () => {
  let scp: SCP;
  let native: MockNativeScp;

  beforeEach(() => {
    const mount = mountMockScp();
    scp = mount.scp;
    native = mount.native;
    installToolStubs(native);
  });

  afterEach(async () => {
    await scp.shutdown(1);
  });

  it("creates a session and returns a session ID", async () => {
    const identity = await scp.identityCreate("in_memory");
    const handle = await scp.contextCreate(identity, "{}");
    const toolId = await scp.toolRegister(handle._rawHandle, {
      name: "stateful-tool",
      description: "A stateful tool",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: identity.did,
    });

    const sessionId = await scp.toolSessionCreate(handle._rawHandle, toolId, "source-ctx-1");
    expect(typeof sessionId).toBe("string");
    expect(sessionId.length).toBeGreaterThan(0);
  });

  it("creates a session with TTL", async () => {
    const identity = await scp.identityCreate("in_memory");
    const handle = await scp.contextCreate(identity, "{}");
    const toolId = await scp.toolRegister(handle._rawHandle, {
      name: "ttl-tool",
      description: "TTL tool",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: identity.did,
    });

    const sessionId = await scp.toolSessionCreate(handle._rawHandle, toolId, "source-ctx-1", 300);
    expect(typeof sessionId).toBe("string");
  });

  it("rejects negative ttlSeconds", async () => {
    const identity = await scp.identityCreate("in_memory");
    const handle = await scp.contextCreate(identity, "{}");

    await expect(
      scp.toolSessionCreate(handle._rawHandle, "tool-test", "source-ctx-1", -1),
    ).rejects.toThrow(/SCP-VALID-7003/);
  });

  it("rejects non-integer ttlSeconds", async () => {
    const identity = await scp.identityCreate("in_memory");
    const handle = await scp.contextCreate(identity, "{}");

    await expect(
      scp.toolSessionCreate(handle._rawHandle, "tool-test", "source-ctx-1", 1.5),
    ).rejects.toThrow(/SCP-VALID-7003/);
  });
});

describe("scp.toolSessionInvoke", () => {
  let scp: SCP;
  let native: MockNativeScp;

  beforeEach(() => {
    const mount = mountMockScp();
    scp = mount.scp;
    native = mount.native;
    installToolStubs(native);
  });

  afterEach(async () => {
    await scp.shutdown(1);
  });

  it("invokes a tool within a session and returns result with call-count provenance", async () => {
    const identity = await scp.identityCreate("in_memory");
    const handle = await scp.contextCreate(identity, "{}");
    const toolId = await scp.toolRegister(handle._rawHandle, {
      name: "session-tool",
      description: "A session tool",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: identity.did,
    });

    const sessionId = await scp.toolSessionCreate(handle._rawHandle, toolId, "source-ctx-1");
    const outputJson = await scp.toolSessionInvoke(
      handle._rawHandle,
      sessionId,
      '{"x": 42}',
      identity.did,
      "mock-ucan-token",
    );
    const parsed = JSON.parse(outputJson) as {
      tool: string;
      session_id: string;
      call_count: number;
      status: string;
    };
    expect(parsed.tool).toBe(toolId);
    expect(parsed.session_id).toBe(sessionId);
    expect(parsed.call_count).toBe(1);
    expect(parsed.status).toBe("validated");
  });

  it("increments call count across invocations", async () => {
    const identity = await scp.identityCreate("in_memory");
    const handle = await scp.contextCreate(identity, "{}");
    const toolId = await scp.toolRegister(handle._rawHandle, {
      name: "counter-tool",
      description: "Counts calls",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: identity.did,
    });

    const sessionId = await scp.toolSessionCreate(handle._rawHandle, toolId, "source-ctx-1");

    await scp.toolSessionInvoke(handle._rawHandle, sessionId, "{}", identity.did, "token");
    const outputJson = await scp.toolSessionInvoke(
      handle._rawHandle,
      sessionId,
      "{}",
      identity.did,
      "token",
    );
    const parsed = JSON.parse(outputJson) as { call_count: number };
    expect(parsed.call_count).toBe(2);
  });
});

describe("scp.toolSessionClose", () => {
  let scp: SCP;
  let native: MockNativeScp;

  beforeEach(() => {
    const mount = mountMockScp();
    scp = mount.scp;
    native = mount.native;
    installToolStubs(native);
  });

  afterEach(async () => {
    await scp.shutdown(1);
  });

  it("closes a session successfully", async () => {
    const identity = await scp.identityCreate("in_memory");
    const handle = await scp.contextCreate(identity, "{}");
    const toolId = await scp.toolRegister(handle._rawHandle, {
      name: "closable-tool",
      description: "Can be closed",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: identity.did,
    });

    const sessionId = await scp.toolSessionCreate(handle._rawHandle, toolId, "source-ctx-1");
    await scp.toolSessionClose(handle._rawHandle, sessionId);

    await expect(
      scp.toolSessionInvoke(handle._rawHandle, sessionId, "{}", identity.did, "token"),
    ).rejects.toThrow(/SCP-TOOL-6018/);
  });

  it("rejects closing a non-existent session", async () => {
    const identity = await scp.identityCreate("in_memory");
    const handle = await scp.contextCreate(identity, "{}");

    await expect(scp.toolSessionClose(handle._rawHandle, "nonexistent-session")).rejects.toThrow(
      /SCP-TOOL-6021/,
    );
  });
});
