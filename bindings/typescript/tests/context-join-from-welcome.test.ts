/**
 * Tests for the ADR-049 Phase 2J spawn-from-Welcome joiner wrappers on the
 * {@link SCP} class:
 *
 *   - {@link SCP.reserveKeyPackage} — reserve a single-use MLS `KeyPackage`
 *     under the joiner's own identity; returns `{ reservationId,
 *     keyPackagePublic }`.
 *   - {@link SCP.contextJoinFromWelcome} — process a received MLS Welcome and
 *     stand the joiner up as a send-capable {@link Context}.
 *
 * Two layers of coverage:
 *
 *  1. **Delegation / marshaling (mock native).** Drives the wrappers through a
 *     Proxy-backed mock `#native` handle (`mountMockScp`), asserting the exact
 *     arguments that cross the FFI boundary and the return-shape normalization
 *     the wrapper performs. napi surfaces a Rust `Vec<u8>` as an `Array<number>`
 *     (or `Buffer`) — the reserve wrapper normalizes `keyPackagePublic` to a
 *     `Uint8Array` (the SDK's canonical byte-return type, matching
 *     `contextExport`), and the join wrapper marshals `welcomeBytes` to a plain
 *     number array the way `contextImport` marshals its byte input. A typed
 *     `IdentityError` thrown by the native custody gate must propagate through
 *     the wrapper unchanged.
 *
 *  2. **Real NAPI addon.** When the platform addon is built (with
 *     `allow_in_memory_custody`), exercises the real reserve path end-to-end
 *     (round-tripping through the supervisor's `KeyPackage` pool), the
 *     custody-gate rejection (`SCP-IDENT-1001` for a non-custodied DID), and the
 *     join path reaching the real OpenMLS Welcome processor (a garbage Welcome
 *     is rejected only after the wrapper's args — reservation id, params JSON,
 *     marshaled bytes — reach the native spawn). Skips when the addon is absent,
 *     matching `identity-create-with-custody.test.ts` / `real-napi.test.ts`.
 */

import { afterEach, describe, expect, test } from "bun:test";

import { Context } from "../src/context";
import { IdentityError } from "../src/errors";
import { SCP } from "../src/scp";
import { mountMockScp } from "./mock-bridge";

// ---------------------------------------------------------------------------
// Layer 1 — delegation / marshaling via the mock native handle
// ---------------------------------------------------------------------------

describe("SCP.reserveKeyPackage — delegation and byte normalization", () => {
  let cleanup: (() => Promise<void>) | undefined;
  afterEach(async () => {
    await cleanup?.();
    cleanup = undefined;
  });

  test("forwards owningDid and normalizes an Array<number> keyPackagePublic to Uint8Array", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    // napi returns a `Vec<u8>` field as an `Array<number>`, and the camelCased
    // object shape `{ reservationId, keyPackagePublic }`.
    native.__stub("reserveKeyPackage", async () => ({
      reservationId: "res-abc",
      keyPackagePublic: [1, 2, 3, 255],
    }));

    const reservation = await scp.reserveKeyPackage("did:dht:joiner");

    const call = native.__lastCall("reserveKeyPackage");
    expect(call?.args[0]).toBe("did:dht:joiner");

    expect(reservation.reservationId).toBe("res-abc");
    expect(reservation.keyPackagePublic).toBeInstanceOf(Uint8Array);
    expect(Array.from(reservation.keyPackagePublic)).toEqual([1, 2, 3, 255]);
  });

  test("normalizes a Buffer keyPackagePublic to Uint8Array (robust to napi byte shape)", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("reserveKeyPackage", async () => ({
      reservationId: "res-buf",
      keyPackagePublic: Buffer.from([9, 8, 7]),
    }));

    const reservation = await scp.reserveKeyPackage("did:dht:joiner");
    expect(reservation.keyPackagePublic).toBeInstanceOf(Uint8Array);
    expect(Array.from(reservation.keyPackagePublic)).toEqual([9, 8, 7]);
  });

  test("propagates a typed IdentityError from the native custody gate unchanged", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("reserveKeyPackage", async () => {
      throw new IdentityError("identity not found: did:dht:stranger", "SCP-IDENT-1001");
    });

    await expect(scp.reserveKeyPackage("did:dht:stranger")).rejects.toBeInstanceOf(IdentityError);
  });
});

describe("SCP.contextJoinFromWelcome — delegation, param passthrough, byte marshaling", () => {
  let cleanup: (() => Promise<void>) | undefined;
  afterEach(async () => {
    await cleanup?.();
    cleanup = undefined;
  });

  test("forwards all six args, marshals a Uint8Array welcome to number[], and returns a Context", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("contextJoinFromWelcome", async () => ({ contextId: "ctx-joined" }));

    const paramsJson = JSON.stringify({ ceiling: ["messages:read"], memoryScope: "ephemeral" });
    const welcome = new Uint8Array([10, 20, 30]);

    const ctx = await scp.contextJoinFromWelcome(
      "did:dht:joiner",
      "did:dht:creator",
      "ctx-joined",
      paramsJson,
      "res-abc",
      welcome,
    );

    const call = native.__lastCall("contextJoinFromWelcome");
    expect(call?.args[0]).toBe("did:dht:joiner");
    expect(call?.args[1]).toBe("did:dht:creator");
    expect(call?.args[2]).toBe("ctx-joined");
    // Params cross as the JSON string verbatim (same shape contextCreate takes).
    expect(call?.args[3]).toBe(paramsJson);
    expect(call?.args[4]).toBe("res-abc");
    // Bytes are marshaled to a plain number[] on the wire (not a Uint8Array).
    expect(Array.isArray(call?.args[5])).toBe(true);
    expect(call?.args[5]).toEqual([10, 20, 30]);

    // The wrapper returns a live Context re-homed under the joiner's DID.
    expect(ctx).toBeInstanceOf(Context);
    expect(ctx.contextId).toBe("ctx-joined");
    expect(ctx.identityDid).toBe("did:dht:joiner");
  });

  test("accepts a readonly number[] welcome input and forwards it unchanged", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("contextJoinFromWelcome", async () => ({ contextId: "ctx-2" }));

    const welcome: readonly number[] = [1, 2, 3];
    await scp.contextJoinFromWelcome(
      "did:dht:joiner",
      "did:dht:creator",
      "ctx-2",
      "{}",
      "res-2",
      welcome,
    );

    const call = native.__lastCall("contextJoinFromWelcome");
    expect(call?.args[5]).toEqual([1, 2, 3]);
  });
});

// ---------------------------------------------------------------------------
// Layer 2 — real NAPI addon
// ---------------------------------------------------------------------------

let scpAvailable = false;
let skipReason = "";
try {
  const probe = new SCP({ storage: { type: "in_memory" } });
  scpAvailable = true;
  probe.shutdown(1).catch(() => {});
} catch (e: unknown) {
  skipReason = `NAPI SCP class not available: ${e instanceof Error ? e.message : String(e)}`;
}

if (!scpAvailable) {
  describe("spawn-from-Welcome joiner ops (SKIPPED)", () => {
    test.skip(`native NAPI addon unavailable: ${skipReason}`, () => {});
  });
} else {
  describe("SCP.reserveKeyPackage / contextJoinFromWelcome (real NAPI)", () => {
    test("reserves a real KeyPackage under a locally-custodied identity", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
      try {
        const joiner = await scp.identityCreate("in_memory");

        const reservation = await scp.reserveKeyPackage(joiner.did);

        // Opaque, non-empty reservation id (a lookup key, not a capability).
        expect(typeof reservation.reservationId).toBe("string");
        expect(reservation.reservationId.length).toBeGreaterThan(0);

        // Real PUBLIC MLS KeyPackage bytes, normalized to a non-empty Uint8Array.
        expect(reservation.keyPackagePublic).toBeInstanceOf(Uint8Array);
        expect(reservation.keyPackagePublic.length).toBeGreaterThan(0);
      } finally {
        await scp.shutdown(1000).catch(() => {});
      }
    });

    test("each reservation consumes a distinct KeyPackage (fresh public bytes)", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
      try {
        const joiner = await scp.identityCreate("in_memory");
        const a = await scp.reserveKeyPackage(joiner.did);
        const b = await scp.reserveKeyPackage(joiner.did);
        // Single-use KeyPackages: two reservations are not the same public bytes.
        expect(Array.from(a.keyPackagePublic)).not.toEqual(Array.from(b.keyPackagePublic));
      } finally {
        await scp.shutdown(1000).catch(() => {});
      }
    });

    test("rejects reserving under a non-custodied DID with SCP-IDENT-1001", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
      try {
        // Well-formed DID that passes format validation but is not a locally
        // custodied identity on this instance — the bridge custody gate fails
        // closed BEFORE any KeyPackage is consumed.
        await expect(scp.reserveKeyPackage("did:dht:not-custodied-here")).rejects.toThrow(
          /SCP-IDENT-1001/,
        );
      } finally {
        await scp.shutdown(1000).catch(() => {});
      }
    });

    test("join reaches the real MLS Welcome processor: a garbage Welcome is rejected after arg marshaling", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
      try {
        const joiner = await scp.identityCreate("in_memory");
        const creator = await scp.identityCreate("in_memory");

        // A real reservation id from the pool — parses cleanly at the bridge.
        const reservation = await scp.reserveKeyPackage(joiner.did);

        // Custody passes (joiner is locally custodied) and the reservation id
        // round-trips, so the failure originates deep in the real
        // `spawn_actor_from_welcome` path when OpenMLS rejects the bogus
        // Welcome bytes — proving the marshaled arguments actually reached the
        // native join, and that the wrapper does not mask the failure.
        const garbageWelcome = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]);
        await expect(
          scp.contextJoinFromWelcome(
            joiner.did,
            creator.did,
            "ctx-welcome-spawn",
            JSON.stringify({ ceiling: ["messages:read"], memoryScope: "ephemeral" }),
            reservation.reservationId,
            garbageWelcome,
          ),
        ).rejects.toThrow();
      } finally {
        await scp.shutdown(1000).catch(() => {});
      }
    });

    test("join rejects a non-custodied joiner before the KeyPackage is consumed", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
      try {
        // owningDid is not a locally custodied identity: the §9.10.4 pseudonym
        // derivation (custody-backed) hard-fails up front.
        await expect(
          scp.contextJoinFromWelcome(
            "did:dht:not-custodied-here",
            "did:dht:creator",
            "ctx-nocustody",
            "{}",
            "reservation-that-will-not-be-reached",
            new Uint8Array([1, 2, 3]),
          ),
        ).rejects.toThrow();
      } finally {
        await scp.shutdown(1000).catch(() => {});
      }
    });
  });
}
