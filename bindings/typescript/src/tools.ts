/**
 * Tools module for the SCP TypeScript SDK.
 *
 * Provides helper functions for tool definition construction and validation.
 * Tool registration, invocation, and verification are performed via the
 * `Context` class methods (`ctx.registerTool()`, `ctx.invokeTool()`,
 * `ctx.verifyTool()`).
 *
 * See ADR-010 (Tool Registry) and ADR-022 in `.docs/adrs/phase-4.md`.
 */

import { ValidationError } from "./errors";
import type { TestVector, ToolDefinition } from "./types";

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

  return result;
}
