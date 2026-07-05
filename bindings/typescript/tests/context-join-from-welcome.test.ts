/**
 * Tests for the ADR-049 Phase 2J / FFI-02 Option A invitation wrappers on the
 * {@link SCP} class:
 *
 *   - {@link SCP.reserveKeyPackage} — reserve a single-use MLS `KeyPackage`
 *     under the joiner's own identity; returns `{ reservationId,
 *     keyPackagePublic }`.
 *   - {@link SCP.inviteMember} — the creator seals a signed invitation bundle
 *     for an invitee `KeyPackage`; returns a discriminated
 *     {@link InviteMemberOutcome} (`sealed` | `requiresGovernanceApproval`).
 *   - {@link SCP.contextJoinFromWelcome} — open a received {@link
 *     SealedInvitation} bundle and stand the joiner up as a send-capable
 *     {@link Context}.
 *
 * Two layers of coverage:
 *
 *  1. **Delegation / marshaling (mock native).** Drives the wrappers through a
 *     Proxy-backed mock `#native` handle (`mountMockScp`), asserting the exact
 *     arguments that cross the FFI boundary and the return-shape normalization
 *     the wrapper performs. napi surfaces a Rust `Vec<u8>` as an `Array<number>`
 *     (or `Buffer`): the join wrapper marshals the sealed bundle's `enc` /
 *     `ciphertext` to plain number arrays on the wire, and the invite wrapper
 *     narrows the flat napi projection into the SDK's discriminated union
 *     (normalizing bytes to `Uint8Array`). A typed error thrown by the native
 *     custody gate must propagate through the wrapper unchanged, and an
 *     unrecognized outcome `kind` must fail closed (never a silent success).
 *
 *  2. **Real NAPI addon.** When the platform addon is built (with
 *     `allow_in_memory_custody`), exercises the real reserve → invite → join
 *     handshake: the SingleAdmin unilateral invite produces a real sealed bundle
 *     from a `reserveKeyPackage` KeyPackage (the invitee KP declares the 0xFF02
 *     context-binding extension), a malformed/garbage sealed bundle is rejected
 *     after arg marshaling, and the custody gates reject non-custodied
 *     inviter/joiner DIDs. Skips when the addon is absent, matching
 *     `identity-create-with-custody.test.ts` / `real-napi.test.ts`.
 */

import { afterEach, describe, expect, test } from "bun:test";

import { Context } from "../src/context";
import { ContextError, IdentityError } from "../src/errors";
import { SCP } from "../src/scp";
import type { SealedInvitation } from "../src/types";
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

describe("SCP.inviteMember — delegation and outcome narrowing", () => {
  let cleanup: (() => Promise<void>) | undefined;
  afterEach(async () => {
    await cleanup?.();
    cleanup = undefined;
  });

  test("narrows a napi sealed outcome into { kind: 'sealed' } and normalizes bytes to Uint8Array", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    // napi surfaces `enc`/`ciphertext` (Vec<u8>) as Array<number> / Buffer.
    native.__stub("inviteMember", async () => ({
      kind: "sealed",
      enc: [1, 2, 3],
      ciphertext: Buffer.from([4, 5, 6]),
      delivered: true,
      proposalId: null,
    }));

    const outcome = await scp.inviteMember(
      "ctx-1",
      "did:dht:creator",
      "did:dht:invitee",
      new Uint8Array([7, 7]),
      ["wss://relay.example"],
    );

    const call = native.__lastCall("inviteMember");
    expect(call?.args[0]).toBe("ctx-1");
    expect(call?.args[1]).toBe("did:dht:creator");
    expect(call?.args[2]).toBe("did:dht:invitee");
    // KeyPackage bytes marshaled to a plain number[] on the wire.
    expect(Array.isArray(call?.args[3])).toBe(true);
    expect(call?.args[3]).toEqual([7, 7]);
    expect(call?.args[4]).toEqual(["wss://relay.example"]);

    expect(outcome.kind).toBe("sealed");
    if (outcome.kind === "sealed") {
      expect(outcome.enc).toBeInstanceOf(Uint8Array);
      expect(Array.from(outcome.enc)).toEqual([1, 2, 3]);
      expect(outcome.ciphertext).toBeInstanceOf(Uint8Array);
      expect(Array.from(outcome.ciphertext)).toEqual([4, 5, 6]);
      expect(outcome.delivered).toBe(true);
    }
  });

  test("narrows a governance-deferred outcome into { kind: 'requiresGovernanceApproval' } as a SUCCESS (no throw)", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("inviteMember", async () => ({
      kind: "requiresGovernanceApproval",
      enc: null,
      ciphertext: null,
      delivered: null,
      proposalId: "deadbeef",
    }));

    const outcome = await scp.inviteMember(
      "ctx-vote",
      "did:dht:creator",
      "did:dht:invitee",
      new Uint8Array([1]),
      [],
    );

    expect(outcome.kind).toBe("requiresGovernanceApproval");
    if (outcome.kind === "requiresGovernanceApproval") {
      expect(outcome.proposalId).toBe("deadbeef");
    }
  });

  test("requiresGovernanceApproval with no tracked proposal id normalizes to null", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("inviteMember", async () => ({
      kind: "requiresGovernanceApproval",
      proposalId: null,
    }));

    const outcome = await scp.inviteMember(
      "ctx-vote",
      "did:dht:creator",
      "did:dht:invitee",
      new Uint8Array([1]),
      [],
    );
    expect(outcome.kind).toBe("requiresGovernanceApproval");
    if (outcome.kind === "requiresGovernanceApproval") {
      expect(outcome.proposalId).toBeNull();
    }
  });

  test("accepts a readonly number[] key package and forwards it unchanged", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("inviteMember", async () => ({
      kind: "sealed",
      enc: [],
      ciphertext: [],
      delivered: false,
    }));

    const kp: readonly number[] = [1, 2, 3];
    await scp.inviteMember("ctx", "did:dht:creator", "did:dht:invitee", kp, []);

    const call = native.__lastCall("inviteMember");
    expect(call?.args[3]).toEqual([1, 2, 3]);
  });

  test("fails closed on an unrecognized outcome kind (never a silent success)", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("inviteMember", async () => ({ kind: "bogus" }));

    await expect(
      scp.inviteMember("ctx", "did:dht:creator", "did:dht:invitee", new Uint8Array(), []),
    ).rejects.toBeInstanceOf(ContextError);
  });

  test("propagates a typed ContextError from the native invite unchanged", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("inviteMember", async () => {
      throw new ContextError("invite_member failed: not an admin", "SCP-CTX-2013");
    });

    await expect(
      scp.inviteMember("ctx", "did:dht:creator", "did:dht:invitee", new Uint8Array([1]), []),
    ).rejects.toBeInstanceOf(ContextError);
  });
});

describe("SCP.contextJoinFromWelcome — delegation, sealed-bundle marshaling", () => {
  let cleanup: (() => Promise<void>) | undefined;
  afterEach(async () => {
    await cleanup?.();
    cleanup = undefined;
  });

  test("forwards owningDid + reservationId and marshals the sealed bundle bytes to number[]", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("contextJoinFromWelcome", async () => ({ contextId: "ctx-joined" }));

    const sealed: SealedInvitation = {
      contextId: "ctx-joined",
      creatorDid: "did:dht:creator",
      enc: new Uint8Array([1, 2, 3]),
      ciphertext: new Uint8Array([9, 8, 7, 6]),
    };

    const ctx = await scp.contextJoinFromWelcome("did:dht:joiner", sealed, "res-abc");

    const call = native.__lastCall("contextJoinFromWelcome");
    expect(call?.args[0]).toBe("did:dht:joiner");
    const wireSealed = call?.args[1] as {
      contextId: string;
      creatorDid: string;
      enc: unknown;
      ciphertext: unknown;
    };
    expect(wireSealed.contextId).toBe("ctx-joined");
    expect(wireSealed.creatorDid).toBe("did:dht:creator");
    // Bytes marshaled to plain number[] on the wire (not a Uint8Array, which the
    // napi Vec<u8> deserializer would reject).
    expect(Array.isArray(wireSealed.enc)).toBe(true);
    expect(wireSealed.enc).toEqual([1, 2, 3]);
    expect(Array.isArray(wireSealed.ciphertext)).toBe(true);
    expect(wireSealed.ciphertext).toEqual([9, 8, 7, 6]);
    expect(call?.args[2]).toBe("res-abc");

    // The wrapper returns a live Context re-homed under the joiner's DID.
    expect(ctx).toBeInstanceOf(Context);
    expect(ctx.contextId).toBe("ctx-joined");
    expect(ctx.identityDid).toBe("did:dht:joiner");
  });

  test("propagates a typed IdentityError from the native custody gate unchanged", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("contextJoinFromWelcome", async () => {
      throw new IdentityError("non-custodied joiner", "SCP-IDENT-1054");
    });

    const sealed: SealedInvitation = {
      contextId: "ctx-x",
      creatorDid: "did:dht:creator",
      enc: new Uint8Array(32),
      ciphertext: new Uint8Array([1, 2, 3]),
    };

    await expect(
      scp.contextJoinFromWelcome("did:dht:joiner", sealed, "res-x"),
    ).rejects.toBeInstanceOf(IdentityError);
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
  describe("reserve → invite → join handshake (SKIPPED)", () => {
    test.skip(`native NAPI addon unavailable: ${skipReason}`, () => {});
  });
} else {
  describe("SCP.reserveKeyPackage (real NAPI)", () => {
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
  });

  describe("SCP.inviteMember (real NAPI)", () => {
    test("SingleAdmin unilateral invite returns a real sealed bundle for a reserved invitee KeyPackage", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
      try {
        const creator = await scp.identityCreate("in_memory");
        const invitee = await scp.identityCreate("in_memory");

        // Encrypted SingleAdmin context: the creator can invite unilaterally.
        // The SingleAdmin creator must hold the invite-relevant capabilities in
        // the ceiling (`member:invite` + `governance:propose`): the add is
        // routed through the actor's governance gate, which checks the
        // proposer's `governance:propose` capability before auto-executing
        // (mirrors the PyO3 reference `test_invite_member_seals_for_single_admin_context`).
        const ctx = await scp.contextCreate(
          creator,
          JSON.stringify({
            ceiling: [
              "messages:read",
              "messages:write",
              "role:assign",
              "member:invite",
              "member:remove",
              "governance:propose",
              "governance:vote",
              "context:close",
            ],
            memoryScope: "ephemeral",
            mode: "Encrypted",
            governance: "single_admin",
          }),
        );

        // The invitee reserves a single-use KeyPackage (declares the 0xFF02
        // context-binding extension) and hands the PUBLIC bytes to the creator.
        const reservation = await scp.reserveKeyPackage(invitee.did);

        const outcome = await scp.inviteMember(
          ctx.contextId,
          creator.did,
          invitee.did,
          reservation.keyPackagePublic,
          [],
        );

        expect(outcome.kind).toBe("sealed");
        if (outcome.kind === "sealed") {
          // RFC 9180 HPKE encapsulated key is exactly 32 bytes.
          expect(outcome.enc).toBeInstanceOf(Uint8Array);
          expect(outcome.enc.length).toBe(32);
          // Non-empty HPKE ciphertext of the signed InvitationBundle.
          expect(outcome.ciphertext).toBeInstanceOf(Uint8Array);
          expect(outcome.ciphertext.length).toBeGreaterThan(0);
          expect(typeof outcome.delivered).toBe("boolean");
        }
      } finally {
        await scp.shutdown(1000).catch(() => {});
      }
    });

    test("rejects inviting under a non-custodied creator DID", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
      try {
        const creator = await scp.identityCreate("in_memory");
        const invitee = await scp.identityCreate("in_memory");
        const ctx = await scp.contextCreate(
          creator,
          JSON.stringify({
            ceiling: ["messages:read"],
            memoryScope: "ephemeral",
            mode: "Encrypted",
            governance: "single_admin",
          }),
        );
        const reservation = await scp.reserveKeyPackage(invitee.did);

        // Well-formed DID that is not custodied on this instance: the invite is
        // signed under the inviter's `#active` key, so the identity-registry
        // lookup fails closed before the runtime driver call.
        await expect(
          scp.inviteMember(
            ctx.contextId,
            "did:dht:not-custodied-here",
            invitee.did,
            reservation.keyPackagePublic,
            [],
          ),
        ).rejects.toThrow();
      } finally {
        await scp.shutdown(1000).catch(() => {});
      }
    });
  });

  describe("SCP.contextJoinFromWelcome (real NAPI)", () => {
    test("join reaches the real bundle open: a garbage sealed bundle is rejected after arg marshaling", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
      try {
        const joiner = await scp.identityCreate("in_memory");
        const creator = await scp.identityCreate("in_memory");

        // A real reservation id from the pool — parses cleanly at the bridge.
        const reservation = await scp.reserveKeyPackage(joiner.did);

        // A 32-byte `enc` passes the fail-closed length gate; the garbage
        // ciphertext then fails deep in the real HPKE open / ConfirmConsume,
        // proving the marshaled sealed-bundle bytes actually reached the native
        // join and the wrapper does not mask the failure.
        const sealed: SealedInvitation = {
          contextId: "ctx-welcome-spawn",
          creatorDid: creator.did,
          enc: new Uint8Array(32),
          ciphertext: new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]),
        };
        await expect(
          scp.contextJoinFromWelcome(joiner.did, sealed, reservation.reservationId),
        ).rejects.toThrow();
      } finally {
        await scp.shutdown(1000).catch(() => {});
      }
    });

    test("join rejects a malformed (non-32-byte) enc at the boundary", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
      try {
        const joiner = await scp.identityCreate("in_memory");
        const creator = await scp.identityCreate("in_memory");
        const reservation = await scp.reserveKeyPackage(joiner.did);

        // enc length gate is fail-closed: a 3-byte enc is rejected up front.
        const sealed: SealedInvitation = {
          contextId: "ctx-badenc",
          creatorDid: creator.did,
          enc: new Uint8Array([1, 2, 3]),
          ciphertext: new Uint8Array([9]),
        };
        await expect(
          scp.contextJoinFromWelcome(joiner.did, sealed, reservation.reservationId),
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
        const sealed: SealedInvitation = {
          contextId: "ctx-nocustody",
          creatorDid: "did:dht:creator",
          enc: new Uint8Array(32),
          ciphertext: new Uint8Array([1, 2, 3]),
        };
        await expect(
          scp.contextJoinFromWelcome(
            "did:dht:not-custodied-here",
            sealed,
            "reservation-that-will-not-be-reached",
          ),
        ).rejects.toThrow();
      } finally {
        await scp.shutdown(1000).catch(() => {});
      }
    });
  });
}
