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
import {
  SagaAbortedError,
  SagaBusyError,
  SagaNeedsRepairError,
  ToolError,
  ValidationError,
} from "../src/errors";
import type { SCP } from "../src/scp";
import { defineToolDefinition } from "../src/tools";
import type { SagaResult } from "../src/types";
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
// §6.2.4 cross-context tool-invocation saga via scp.toolInvokeCrossContextSaga
// ---------------------------------------------------------------------------

const NONCE_HEX = "00".repeat(16);
const TS_MS = 1_700_000_000_000n;

describe("scp.toolInvokeCrossContextSaga", () => {
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

  /** Creates source + target context handles and returns the dispatch args. */
  async function handles(): Promise<{ did: string; source: unknown; target: unknown }> {
    const identity = await scp.identityCreate("in_memory");
    const sourceHandle = await scp.contextCreate(identity, "{}");
    const targetHandle = await scp.contextCreate(identity, "{}");
    return { did: identity.did, source: sourceHandle._rawHandle, target: targetHandle._rawHandle };
  }

  /** Invokes the saga with all-valid args, overriding only what a test cares about. */
  async function invoke(overrides: {
    source?: unknown;
    target?: unknown;
    timestampMs?: bigint;
    chainDepth?: number;
  }): Promise<SagaResult> {
    const { did, source, target } = await handles();
    return await scp.toolInvokeCrossContextSaga(
      overrides.source ?? source,
      overrides.target ?? target,
      did,
      "tool-reg-1",
      '{"a":1}',
      NONCE_HEX,
      overrides.timestampMs ?? TS_MS,
      overrides.chainDepth ?? 0,
    );
  }

  it("commits and returns sagaId plus receipt/output bytes", async () => {
    native.__stub("toolInvokeCrossContextSaga", async () => ({
      sagaId: "saga-abc",
      receipt: Buffer.from([1, 2, 3]),
      output: Buffer.from([4, 5, 6]),
    }));

    const result = await invoke({});
    expect(result.sagaId).toBe("saga-abc");
    expect(result.receipt).not.toBeNull();
    expect(result.output).not.toBeNull();
    expect(Array.from(result.receipt as Uint8Array)).toEqual([1, 2, 3]);
    expect(Array.from(result.output as Uint8Array)).toEqual([4, 5, 6]);
  });

  it("surfaces an omitted receipt as null (never synthesized)", async () => {
    native.__stub("toolInvokeCrossContextSaga", async () => ({
      sagaId: "saga-noreceipt",
      output: Buffer.from([9]),
    }));

    const result = await invoke({});
    expect(result.sagaId).toBe("saga-noreceipt");
    expect(result.receipt).toBeNull();
    expect(result.output).not.toBeNull();
  });

  it("accepts chainDepth at the u8 bounds (0 and 255)", async () => {
    native.__stub("toolInvokeCrossContextSaga", async () => ({ sagaId: "ok" }));

    expect((await invoke({ chainDepth: 0 })).sagaId).toBe("ok");
    expect((await invoke({ chainDepth: 255 })).sagaId).toBe("ok");
  });

  it("rejects chainDepth above the u8 range (256)", async () => {
    const err = await invoke({ chainDepth: 256 }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ValidationError);
    expect((err as ValidationError).code).toBe("SCP-VALID-7002");
  });

  it("rejects negative chainDepth", async () => {
    const err = await invoke({ chainDepth: -1 }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ValidationError);
    expect((err as ValidationError).code).toBe("SCP-VALID-7002");
  });

  it("rejects a negative bigint timestampMs", async () => {
    const err = await invoke({ timestampMs: -1n }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ValidationError);
    expect((err as ValidationError).code).toBe("SCP-VALID-7002");
  });

  it("rejects a non-bigint timestampMs", async () => {
    // The signature demands a bigint; a numeric caller is a type error the
    // runtime guard still rejects (parity with Python's lower-bound shape).
    const err = await invoke({ timestampMs: 123 as unknown as bigint }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ValidationError);
    expect((err as ValidationError).code).toBe("SCP-VALID-7002");
  });

  it("maps the aborted Display string to SagaAbortedError with retryAfterMs", async () => {
    native.__stub("toolInvokeCrossContextSaga", async () => {
      throw new Error("[SCP-SAGA-13067] saga aborted: rate limited (retry_after_ms=2500)");
    });

    const err = await invoke({}).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SagaAbortedError);
    expect((err as SagaAbortedError).retryAfterMs).toBe(2500);
  });

  it("maps a null retry_after_ms suffix to retryAfterMs null (never 0)", async () => {
    native.__stub("toolInvokeCrossContextSaga", async () => {
      throw new Error("[SCP-SAGA-13067] saga aborted: hard limit (retry_after_ms=null)");
    });

    const err = await invoke({}).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SagaAbortedError);
    expect((err as SagaAbortedError).retryAfterMs).toBeNull();
  });

  it("maps the needs-repair Display string to SagaNeedsRepairError with sagaId", async () => {
    native.__stub("toolInvokeCrossContextSaga", async () => {
      throw new Error("[SCP-SAGA-13065] saga needs repair: diverged (saga_id=repair-77)");
    });

    const err = await invoke({}).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SagaNeedsRepairError);
    expect((err as SagaNeedsRepairError).sagaId).toBe("repair-77");
  });

  it("maps the busy Display string to SagaBusyError with contendedContext", async () => {
    native.__stub("toolInvokeCrossContextSaga", async () => {
      throw new Error("[SCP-SAGA-13066] saga busy: overlap (contended_context=ctx-shared)");
    });

    const err = await invoke({}).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SagaBusyError);
    expect((err as SagaBusyError).contendedContext).toBe("ctx-shared");
  });

  it("maps a non-saga bridge error to ToolError (not a saga subclass)", async () => {
    native.__stub("toolInvokeCrossContextSaga", async () => {
      throw new Error("[SCP-TOOL-6011] tool error: target context is not active");
    });

    const err = await invoke({}).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect(err).not.toBeInstanceOf(SagaAbortedError);
    expect(err).not.toBeInstanceOf(SagaNeedsRepairError);
    expect(err).not.toBeInstanceOf(SagaBusyError);
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
