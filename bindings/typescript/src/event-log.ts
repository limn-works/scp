/**
 * Event log module for the SCP TypeScript SDK.
 *
 * Provides the `EventLog` class for querying context event logs, verifying
 * Merkle proofs, and creating consistency checkpoints.
 *
 * See ADR-011 (Event Log) and ADR-022 in `.docs/adrs/phase-4.md`.
 */

import type { Context } from "./context";
import { mapBridgeError } from "./errors";
import { getBridge } from "./internal/bridge";
import type { Checkpoint, Event, EventClaim, EventFilter, Proof } from "./types";

// ---------------------------------------------------------------------------
// EventLog
// ---------------------------------------------------------------------------

/**
 * Event log accessor for an SCP context.
 *
 * Event logs are append-only, Merkle-tree-backed logs of all protocol events
 * within a context. They provide verifiable audit trails and enable trust
 * evaluation based on observed behavior.
 *
 * ```typescript
 * const log = new EventLog(ctx);
 * const events = await log.query({ eventType: "MessageSent" });
 * const proof = await log.verify({ type: "inclusion", leafIndex: 0 });
 * const checkpoint = await log.checkpoint();
 * ```
 */
export class EventLog {
  /** @internal The context this event log belongs to. */
  private readonly _ctx: Context;

  /**
   * Creates an EventLog accessor for a context.
   *
   * @param ctx - The context whose event log to access.
   */
  constructor(ctx: Context) {
    this._ctx = ctx;
  }

  /**
   * Queries the event log with optional filter criteria.
   *
   * @param filter - Optional filter parameters. Pass `undefined` for all events.
   * @returns An array of matching events.
   * @throws {ContextError} If the query fails or the context is not active.
   */
  async query(filter?: EventFilter): Promise<readonly Event[]> {
    try {
      const bridge = await getBridge();
      return await bridge.eventLogQuery(this._ctx._handle, filter);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Verifies a claim against the event log (Merkle proof).
   *
   * Generates and verifies an inclusion or absence proof for the given claim.
   *
   * @param claim - The claim to verify.
   * @returns A proof with the verification result.
   * @throws {ContextError} If verification fails.
   */
  async verify(claim: EventClaim): Promise<Proof> {
    try {
      const bridge = await getBridge();
      return await bridge.eventLogVerify(this._ctx._handle, claim);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Creates a consistency checkpoint of the event log.
   *
   * Returns the current Merkle root hash, event count, and timestamp.
   *
   * @returns A checkpoint with the current log state.
   * @throws {ContextError} If checkpoint creation fails.
   */
  async checkpoint(): Promise<Checkpoint> {
    try {
      const bridge = await getBridge();
      return await bridge.eventLogCheckpoint(this._ctx._handle);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }
}
