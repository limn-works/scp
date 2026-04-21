/**
 * Tools module for the SCP TypeScript SDK.
 *
 * Provides {@link defineToolDefinition} — a pure helper that builds
 * validated {@link ToolDefinition} objects for registration via
 * `Context.registerTool()`.
 *
 * The cross-context and stateful-session entry points
 * (`toolInvokeCrossContext`, `toolSessionCreate`,
 * `toolSessionInvoke`, `toolSessionClose`) moved onto the {@link SCP}
 * class in Phase 4 PR 4 (#1549, ADR-048) as
 * `scp.toolInvokeCrossContext(...)`, `scp.toolSessionCreate(...)`,
 * `scp.toolSessionInvoke(...)`, `scp.toolSessionClose(...)`. The
 * free-function shims that predated ADR-048 were deleted in the same
 * commit.
 *
 * See ADR-010 (Tool Registry), ADR-022 in `.docs/adrs/phase-4.md`, and
 * spec sections 6.2 / 6.2.1 for cross-context invocation and stateful sessions.
 */

import { ValidationError } from "./errors";
import type { TestVector, ToolCost, ToolDefinition } from "./types";

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
