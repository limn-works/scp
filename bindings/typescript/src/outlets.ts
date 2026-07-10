/**
 * Outlets module for the SCP TypeScript SDK.
 *
 * Provides {@link defineOutletDefinition} — a pure helper that builds
 * validated {@link OutletDefinition} objects for registration via
 * `Context.registerOutlet()`.
 *
 * The cross-context and stateful-session entry points
 * (`outletInvokeCrossContext`, `outletSessionCreate`,
 * `outletSessionInvoke`, `outletSessionClose`) moved onto the {@link SCP}
 * class in Phase 4 PR 4 (#1549, ADR-048) as
 * `scp.outletInvokeCrossContext(...)`, `scp.outletSessionCreate(...)`,
 * `scp.outletSessionInvoke(...)`, `scp.outletSessionClose(...)`. The
 * free-function shims that predated ADR-048 were deleted in the same
 * commit.
 *
 * See ADR-010 (Outlet Registry), ADR-022 in `.docs/adrs/phase-4.md`, and
 * spec sections 6.2 / 6.2.1 for cross-context invocation and stateful sessions.
 */

import { ValidationError } from "./errors";
import type { OutletCost, OutletDefinition, TestVector } from "./types";

// ---------------------------------------------------------------------------
// Outlet definition builder
// ---------------------------------------------------------------------------

/**
 * Creates a validated `OutletDefinition` object.
 *
 * Validates required fields and returns an immutable outlet definition suitable
 * for registration via `Context.registerOutlet()`.
 *
 * @param params - Outlet definition parameters.
 * @returns A validated `OutletDefinition`.
 * @throws {ValidationError} If required fields are missing or invalid.
 */
export function defineOutletDefinition(params: {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Readonly<Record<string, unknown>>;
  readonly outputSchema: Readonly<Record<string, unknown>>;
  readonly operator: string;
  readonly testVectors?: readonly TestVector[];
  readonly implementationHash?: Uint8Array;
  readonly cost?: OutletCost;
}): OutletDefinition {
  if (params.name.length === 0) {
    throw new ValidationError("Outlet name must not be empty", "SCP-VALID-7010");
  }

  if (params.description.length === 0) {
    throw new ValidationError("Outlet description must not be empty", "SCP-VALID-7011");
  }

  if (params.operator.length === 0) {
    throw new ValidationError("Outlet operator DID must not be empty", "SCP-VALID-7012");
  }

  const result: OutletDefinition = {
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
    (result as { cost: OutletCost }).cost = params.cost;
  }

  return result;
}
