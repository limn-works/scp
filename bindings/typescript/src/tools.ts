/**
 * Tools module for the SCP TypeScript SDK.
 *
 * Provides helper functions for tool definition construction and validation,
 * plus module-level async functions for cross-context tool invocation and
 * stateful tool sessions:
 *
 * - {@link toolInvokeCrossContext} -- Invoke a tool across context boundaries.
 * - {@link toolSessionCreate} -- Create a stateful tool session.
 * - {@link toolSessionInvoke} -- Invoke a tool within an active session.
 * - {@link toolSessionClose} -- Close a stateful tool session.
 *
 * See ADR-010 (Tool Registry), ADR-022 in `.docs/adrs/phase-4.md`, and
 * spec sections 6.2 / 6.2.1 for cross-context invocation and stateful sessions.
 */

import { mapBridgeError, ValidationError } from "./errors";
import { getBridge } from "./internal/bridge";
import type { BridgeContextHandle } from "./internal/bridge";
import type {
  CrossContextInvocationResult,
  TestVector,
  ToolCost,
  ToolDefinition,
  ToolSessionResult,
} from "./types";

// ---------------------------------------------------------------------------
// Tool definition builder
// ---------------------------------------------------------------------------

/**
 * Creates a validated `ToolDefinition` object.
 *
 * Validates required fields and returns an immutable tool definition suitable
 * for registration via `Context.registerTool()`.
 *
 * @param params - Tool definition parameters.
 * @returns A validated `ToolDefinition`.
 * @throws {ValidationError} If required fields are missing or invalid.
 */
export function defineToolDefinition(params: {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Readonly<Record<string, unknown>>;
  readonly outputSchema: Readonly<Record<string, unknown>>;
  readonly operator: string;
  readonly testVectors?: readonly TestVector[];
  readonly implementationHash?: Uint8Array;
  readonly cost?: ToolCost;
}): ToolDefinition {
  if (params.name.length === 0) {
    throw new ValidationError("Tool name must not be empty", "SCP-VALID-7010");
  }

  if (params.description.length === 0) {
    throw new ValidationError("Tool description must not be empty", "SCP-VALID-7011");
  }

  if (params.operator.length === 0) {
    throw new ValidationError("Tool operator DID must not be empty", "SCP-VALID-7012");
  }

  const result: ToolDefinition = {
    name: params.name,
    description: params.description,
    inputSchema: params.inputSchema,
    outputSchema: params.outputSchema,
    operator: params.operator,
  };

  if (params.testVectors !== undefined) {
    (result as { testVectors: readonly TestVector[] }).testVectors = params.testVectors;
  }

  if (params.implementationHash !== undefined) {
    (result as { implementationHash: Uint8Array }).implementationHash = params.implementationHash;
  }

  if (params.cost !== undefined) {
    (result as { cost: ToolCost }).cost = params.cost;
  }

  return result;
}

// ---------------------------------------------------------------------------
// Cross-context tool invocation (spec section 6.2)
// ---------------------------------------------------------------------------

/**
 * Invokes a tool across context boundaries.
 *
 * The source context initiates the call and the target context contains the
 * tool. Both contexts must have approved the interface before calls are
 * permitted. Rate limits and chain depth are enforced per spec section 6.2.
 *
 * @param sourceHandle - Bridge handle for the calling context.
 * @param targetHandle - Bridge handle for the context containing the tool.
 * @param toolId - The ID of the tool to invoke.
 * @param inputJson - Input data as a JSON string matching the tool's input schema.
 * @param invokerDid - The DID of the participant invoking the tool.
 * @param ucanToken - JWT-encoded UCAN token authorizing the invocation.
 * @param chainDepth - Current cross-context chain depth (0 for first hop). Must be 0-255.
 * @param proofTokens - Optional list of encoded parent UCAN token strings.
 * @returns A {@link CrossContextInvocationResult} with the tool output and provenance.
 * @throws {ValidationError} If chainDepth is out of range.
 * @throws {ContextError} If the bridge is not available.
 */
export async function toolInvokeCrossContext(
  sourceHandle: BridgeContextHandle,
  targetHandle: BridgeContextHandle,
  toolId: string,
  inputJson: string,
  invokerDid: string,
  ucanToken: string,
  chainDepth = 0,
  proofTokens?: readonly string[],
): Promise<CrossContextInvocationResult> {
  if (!Number.isInteger(chainDepth) || chainDepth < 0 || chainDepth > 255) {
    throw new ValidationError(
      `chainDepth must be an integer in range 0-255, got ${chainDepth}`,
      "SCP-VALID-7002",
    );
  }

  const bridge = await getBridge();
  try {
    const output = await bridge.toolInvokeCrossContext(
      sourceHandle,
      targetHandle,
      toolId,
      inputJson,
      invokerDid,
      ucanToken,
      chainDepth,
      proofTokens,
    );
    return {
      output,
      sourceContextId: sourceHandle.contextId,
      targetContextId: targetHandle.contextId,
      invokerDid,
      chainDepth,
      timestamp: Date.now(),
    };
  } catch (error) {
    throw mapBridgeError(error);
  }
}

// ---------------------------------------------------------------------------
// Stateful tool sessions (spec section 6.2.1)
// ---------------------------------------------------------------------------

/**
 * Creates a stateful tool session.
 *
 * Sessions enable multi-turn workflows with state preservation across
 * invocations. Each session is subject to per-caller caps (default: 5
 * concurrent sessions per caller, per spec section 6.2.1).
 *
 * @param handle - Bridge handle for the context containing the tool.
 * @param toolId - The tool to create a session for.
 * @param sourceContextId - The calling context (session cap tracked per caller).
 * @param ttlSeconds - Optional time-to-live in seconds. Omit for context-lifetime session.
 * @returns A {@link ToolSessionResult} containing the session ID.
 * @throws {ValidationError} If ttlSeconds is negative or not an integer.
 * @throws {ContextError} If the bridge is not available.
 */
export async function toolSessionCreate(
  handle: BridgeContextHandle,
  toolId: string,
  sourceContextId: string,
  ttlSeconds?: number,
): Promise<ToolSessionResult> {
  if (ttlSeconds !== undefined) {
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 0) {
      throw new ValidationError(
        `ttlSeconds must be a non-negative integer, got ${ttlSeconds}`,
        "SCP-VALID-7002",
      );
    }
  }

  const bridge = await getBridge();
  try {
    const sessionId = await bridge.toolSessionCreate(handle, toolId, sourceContextId, ttlSeconds);
    return { sessionId };
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Invokes a tool within an active session.
 *
 * Each call is individually governed: the invoker must hold `ToolInvoke`
 * capability and present a valid UCAN token. Session state is carried forward
 * across invocations. The session's call count is incremented on each
 * successful invocation.
 *
 * @param handle - Bridge handle for the context containing the tool session.
 * @param sessionId - The session to invoke within.
 * @param inputJson - Input data as a JSON string matching the tool's input schema.
 * @param invokerDid - The DID of the invoker (capability checked per call).
 * @param ucanToken - JWT-encoded UCAN token authorizing the invocation.
 * @param proofTokens - Optional list of encoded parent UCAN token strings.
 * @returns The tool output as a JSON string.
 * @throws {ContextError} If the session is not found or has expired.
 */
export async function toolSessionInvoke(
  handle: BridgeContextHandle,
  sessionId: string,
  inputJson: string,
  invokerDid: string,
  ucanToken: string,
  proofTokens?: readonly string[],
): Promise<string> {
  const bridge = await getBridge();
  try {
    return await bridge.toolSessionInvoke(
      handle,
      sessionId,
      inputJson,
      invokerDid,
      ucanToken,
      proofTokens,
    );
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Closes a stateful tool session.
 *
 * Removes the session from the store, releasing the caller's session slot.
 * After closing, any further invocations with this session ID will fail.
 *
 * @param handle - Bridge handle for the context containing the tool session.
 * @param sessionId - The session to close.
 * @throws {ContextError} If the session is not found.
 */
export async function toolSessionClose(
  handle: BridgeContextHandle,
  sessionId: string,
): Promise<void> {
  const bridge = await getBridge();
  try {
    await bridge.toolSessionClose(handle, sessionId);
  } catch (error) {
    throw mapBridgeError(error);
  }
}
