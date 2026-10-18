/**
 * Tests for the ADR-049 Phase 2J / FFI-02 Option A invitation wrappers on the
 * {@link SCP} class:
 *
 *   - {@link SCP.reserveKeyPackage} — reserve a single-use MLS `KeyPackage`
 *     under the joiner's own identity; returns `{ reservationId,
 *     keyPackagePublic }`.
 *   - {@link SCP.inviteMember} — the creator seals a signed invitation bundle
 *     for an invitee `KeyPackage`; returns a discriminated
 *     {@link InviteMemberOutcome} carrying the sealed `bundle` (directly
 *     join-usable) plus `delivered`.
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
 *     projects the flat napi object into the SDK outcome (normalizing the
 *     bundle's bytes to `Uint8Array`). A typed error thrown by the native
 *     custody gate — including the voting-context refusal — must propagate
 *     through the wrapper unchanged.
 *
 *  2. **Real NAPI addon.** When the platform addon is built (with
 *     `testing`), exercises the real reserve → invite → join
 *     handshake across two `SCP` instances: the SingleAdmin unilateral invite
 *     seals to the invitee KeyPackage's DHKEM(P-256) wrapping key (a 65-byte
 *     `enc`) and the invitee opens it and joins. A malformed `enc` or a
 *     garbage sealed bundle is rejected after arg marshaling, and the custody
 *     gates reject non-custodied inviter/joiner DIDs. Skips when the addon is absent, matching
 *     `identity-create-with-custody.test.ts` / `real-napi.test.ts`.
 */

import { afterEach, describe, expect, test } from "bun:test";
import { Context } from "../src/context";
import { ContextError, IdentityError } from "../src/errors";
import { SCP } from "../src/scp";
import type { SealedInvitation } from "../src/types";
import { createInMemoryIdentity } from "./harness-custody";
import { mountMockScp } from "./mock-bridge";
import { skipReasonIfAddonAbsent } from "./napi-guard";

/**
 * The P-256 generator, SEC1-uncompressed: a valid 65-byte DHKEM(P-256) `enc`
 * (spec 05 §5.12.3.1), so a join with it passes the runtime's `enc` check and
 * fails at a later gate.
 */
const P256_G = new Uint8Array(
  Buffer.from(
    "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
      "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    "hex",
  ),
);

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

  test("projects a napi sealed outcome into { bundle, delivered } and normalizes bytes to Uint8Array", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    // napi surfaces the `NapiSealedInvitation` bundle's `enc`/`ciphertext`
    // (Vec<u8>) as Array<number> / Buffer.
    native.__stub("inviteMember", async () => ({
      bundle: {
        contextId: "ctx-1",
        creatorDid: "did:dht:creator",
        enc: [1, 2, 3],
        ciphertext: Buffer.from([4, 5, 6]),
      },
      delivered: true,
    }));

    const outcome = await scp.inviteMember(
      "ctx-1",
      "did:dht:creator",
      "did:dht:invitee",
      new Uint8Array([7, 7]),
    );

    const call = native.__lastCall("inviteMember");
    expect(call?.args[0]).toBe("ctx-1");
    expect(call?.args[1]).toBe("did:dht:creator");
    expect(call?.args[2]).toBe("did:dht:invitee");
    // KeyPackage bytes marshaled to a plain number[] on the wire.
    expect(Array.isArray(call?.args[3])).toBe(true);
    expect(call?.args[3]).toEqual([7, 7]);
    // The runtime reads the context's stored relay set; no list crosses the
    // bridge.
    expect(call?.args).toHaveLength(4);

    // The `bundle` is a SealedInvitation directly usable as the join input.
    expect(outcome.bundle.contextId).toBe("ctx-1");
    expect(outcome.bundle.creatorDid).toBe("did:dht:creator");
    expect(outcome.bundle.enc).toBeInstanceOf(Uint8Array);
    expect(Array.from(outcome.bundle.enc)).toEqual([1, 2, 3]);
    expect(outcome.bundle.ciphertext).toBeInstanceOf(Uint8Array);
    expect(Array.from(outcome.bundle.ciphertext)).toEqual([4, 5, 6]);
    expect(outcome.delivered).toBe(true);
  });

  test("accepts a readonly number[] key package and forwards it unchanged", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("inviteMember", async () => ({
      bundle: {
        contextId: "ctx",
        creatorDid: "did:dht:creator",
        enc: [],
        ciphertext: [],
      },
      delivered: false,
    }));

    const kp: readonly number[] = [1, 2, 3];
    await scp.inviteMember("ctx", "did:dht:creator", "did:dht:invitee", kp);

    const call = native.__lastCall("inviteMember");
    expect(call?.args[3]).toEqual([1, 2, 3]);
  });

  test("propagates a typed ContextError from the native invite unchanged", async () => {
    const { scp, native } = mountMockScp();
    cleanup = () => scp.shutdown(0);
    native.__stub("inviteMember", async () => {
      throw new ContextError("invite_member failed: not an admin", "SCP-CTX-2013");
    });

    await expect(
      scp.inviteMember("ctx", "did:dht:creator", "did:dht:invitee", new Uint8Array([1])),
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
      enc: P256_G,
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
  skipReason = skipReasonIfAddonAbsent(e);
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
        const joiner = await createInMemoryIdentity(scp);

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
        const joiner = await createInMemoryIdentity(scp);
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
        const creator = await createInMemoryIdentity(scp);
        const invitee = await createInMemoryIdentity(scp);

        // Encrypted SingleAdmin context: the creator can invite unilaterally.
        // The invite is routed through the actor's governance gate, which checks
        // the proposer's `governance:propose` capability before auto-executing —
        // that is the ONLY capability enforced for the invite. The SingleAdmin
        // creator holds every capability in the declared ceiling, so the ceiling
        // below declares `governance:propose`; a ceiling without it cannot
        // invite. Mirrors the PyO3 reference
        // `test_invite_member_seals_for_single_admin_context`.
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
        );

        // The outcome carries a SealedInvitation `bundle` directly usable as the
        // join input (no re-assembly): its fields are exactly the
        // `contextJoinFromWelcome` `sealed` parameter shape. The join itself
        // runs in "reserve → invite → join handshake (real NAPI)": one instance
        // cannot self-join its own context (first-writer-wins rejects the
        // second actor for the same context id).
        expect(outcome.bundle.contextId).toBe(ctx.contextId);
        expect(outcome.bundle.creatorDid).toBe(creator.did);
        // A DHKEM(P-256) encapsulated key is a 65-byte uncompressed point.
        expect(outcome.bundle.enc).toBeInstanceOf(Uint8Array);
        expect(outcome.bundle.enc.length).toBe(65);
        expect(outcome.bundle.enc[0]).toBe(0x04);
        // Non-empty HPKE ciphertext of the signed InvitationBundle.
        expect(outcome.bundle.ciphertext).toBeInstanceOf(Uint8Array);
        expect(outcome.bundle.ciphertext.length).toBeGreaterThan(0);
        expect(typeof outcome.delivered).toBe("boolean");
      } finally {
        await scp.shutdown(1000).catch(() => {});
      }
    });

    test("rejects inviting under a non-custodied creator DID", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
      try {
        const creator = await createInMemoryIdentity(scp);
        const invitee = await createInMemoryIdentity(scp);
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
        const joiner = await createInMemoryIdentity(scp);
        const creator = await createInMemoryIdentity(scp);

        // A real reservation id from the pool — parses cleanly at the bridge.
        const reservation = await scp.reserveKeyPackage(joiner.did);

        // A valid P-256 point passes the runtime's `enc` check; the garbage
        // ciphertext then fails deep in the real HPKE open, proving the
        // marshaled sealed-bundle bytes actually reached the native join and
        // the wrapper does not mask the failure.
        const sealed: SealedInvitation = {
          contextId: "ctx-welcome-spawn",
          creatorDid: creator.did,
          enc: P256_G,
          ciphertext: new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]),
        };
        const err = await scp
          .contextJoinFromWelcome(joiner.did, sealed, reservation.reservationId)
          .then(
            () => undefined,
            (e: unknown) => e,
          );
        expect(err).toBeInstanceOf(Error);
        expect((err as Error).message).not.toMatch(/invitation enc/);
      } finally {
        await scp.shutdown(1000).catch(() => {});
      }
    });

    test("join rejects an enc that is not a 65-byte P-256 point", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
      try {
        const joiner = await createInMemoryIdentity(scp);
        const creator = await createInMemoryIdentity(scp);
        const reservation = await scp.reserveKeyPackage(joiner.did);

        // The runtime validates `enc` before any custody call or the
        // KeyPackage consume (spec 09 §9.16.2 Open step 1). The retired
        // 32-byte X25519 width is rejected like any other length.
        for (const enc of [new Uint8Array([1, 2, 3]), new Uint8Array(32)]) {
          const sealed: SealedInvitation = {
            contextId: "ctx-badenc",
            creatorDid: creator.did,
            enc,
            ciphertext: new Uint8Array([9]),
          };
          await expect(
            scp.contextJoinFromWelcome(joiner.did, sealed, reservation.reservationId),
          ).rejects.toThrow(/invitation enc/);
        }
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
          enc: P256_G,
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

  describe("reserve → invite → join handshake (real NAPI)", () => {
    test("bob seals to alice's P-256 wrapping key and alice joins from a second instance", async () => {
      // napi instances in one process share one DHT, so each resolves the
      // other's DID.
      const bobScp = new SCP({ storage: { type: "in_memory" } });
      const aliceScp = new SCP({ storage: { type: "in_memory" } });
      try {
        const bob = await createInMemoryIdentity(bobScp);
        const alice = await createInMemoryIdentity(aliceScp);
        const ctx = await bobScp.contextCreate(
          bob,
          JSON.stringify({
            ceiling: [
              "messages:read",
              "messages:write",
              "role:assign",
              "member:invite",
              "governance:propose",
              "governance:vote",
            ],
            memoryScope: "ephemeral",
            mode: "Encrypted",
            governance: "single_admin",
          }),
        );

        const reservation = await aliceScp.reserveKeyPackage(alice.did);
        // Bob verifies the KeyPackage's attestation against alice's resolved
        // `#active` and seals to its 0xFF01 key (spec 05 §5.12.3.1).
        const outcome = await bobScp.inviteMember(
          ctx.contextId,
          bob.did,
          alice.did,
          reservation.keyPackagePublic,
        );
        expect(outcome.bundle.enc.length).toBe(65);
        expect(outcome.bundle.enc[0]).toBe(0x04);

        // Alice opens through `dh_agree` on her custody wrapping handle (spec
        // 09 §9.16.2) and stands up the context.
        const joined = await aliceScp.contextJoinFromWelcome(
          alice.did,
          outcome.bundle,
          reservation.reservationId,
        );
        expect(joined).toBeInstanceOf(Context);
        expect(joined.contextId).toBe(ctx.contextId);
        expect(joined.identityDid).toBe(alice.did);
      } finally {
        await aliceScp.shutdown(1000).catch(() => {});
        await bobScp.shutdown(1000).catch(() => {});
      }
    });
  });
}
