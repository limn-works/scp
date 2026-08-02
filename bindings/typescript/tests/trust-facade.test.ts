/**
 * Regression tests for the standalone four-layer `evaluateTrust` facade
 * (`src/trust.ts`) — specifically its Layer 2 behavioral record.
 *
 * SCP-OUT-006: the Layer 2 aggregation must filter the event stream on the
 * canonical `OutletInvoked` event type (`EventType::OutletInvoked` in
 * `scp-event-log`, matching the Python/Swift/Kotlin SDKs). A prior residual
 * `ToolInvoked` filter never matched any event, so `outletInvocations` was
 * always empty — a live functional bug. These tests pin the correct event type
 * so it cannot regress.
 */

import { describe, expect, it } from "bun:test";
import type { Context } from "../src/context";
import type { SCP } from "../src/scp";
import { evaluateTrust } from "../src/trust";

/** Builds a minimal SCP whose `eventLogQuery` returns the supplied events. */
function mockScpWithEvents(events: readonly { readonly eventType: string }[]): SCP {
  return {
    eventLogQuery: async (_handle: unknown, _filter: string) => events,
  } as unknown as SCP;
}

const CONTEXT = { _rawHandle: {} as object, contextId: "ctx-1" } as unknown as Context;

describe("evaluateTrust (four-layer facade) — Layer 2 behavioral record", () => {
  it("surfaces OutletInvoked events in outletInvocations (SCP-OUT-006)", async () => {
    const scp = mockScpWithEvents([
      { eventType: "OutletInvoked" },
      { eventType: "MessageSent" },
      { eventType: "OutletInvoked" },
    ]);

    const result = await evaluateTrust(scp, "did:dht:subject", CONTEXT);

    expect(result.behavioralRecord).not.toBeNull();
    // Only the two OutletInvoked events are surfaced (one entry each, count: 1).
    expect(result.behavioralRecord?.outletInvocations).toEqual([
      { type: "OutletInvoked", count: 1 },
      { type: "OutletInvoked", count: 1 },
    ]);
  });

  it("ignores the legacy `ToolInvoked` event type (regression guard)", async () => {
    // Before the fix, the facade filtered on "ToolInvoked" and this array would
    // have populated outletInvocations. It must now be empty.
    const scp = mockScpWithEvents([{ eventType: "ToolInvoked" }]);

    const result = await evaluateTrust(scp, "did:dht:subject", CONTEXT);

    expect(result.behavioralRecord?.outletInvocations).toEqual([]);
  });
});
