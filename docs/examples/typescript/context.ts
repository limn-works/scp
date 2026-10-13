/**
 * Context creation and the invite-and-join handshake.
 *
 * Demonstrates creating an SCP context with governance parameters,
 * inviting a second identity, and joining from the sealed invitation.
 *
 * The creator and the joiner each run their own `SCP` instance with its own
 * database, as two devices would. Each passes its own `KeyCustodyProvider`,
 * which is how the `"os_keystore"` custody request of spec `03-identity.md`
 * §3.2.2 reaches a host key store.
 *
 * Prerequisites:
 *   bun add @limn-works/scp-ts
 *
 * Usage:
 *   import { contextExample } from "./context";
 *   await contextExample(aliceProvider, bobProvider, process.env.SCP_STORAGE_PASSPHRASE);
 */

import { type ContextParams, type KeyCustodyProvider, SCP } from "@limn-works/scp-ts";

export async function contextExample(
  aliceProvider: KeyCustodyProvider,
  bobProvider: KeyCustodyProvider,
  storagePassphrase: string,
): Promise<void> {
  const aliceNode = new SCP({
    storage: { type: "sqlite", path: "./scp-context-alice", passphrase: storagePassphrase },
  });
  const bobNode = new SCP({
    storage: { type: "sqlite", path: "./scp-context-bob", passphrase: storagePassphrase },
  });
  try {
    // 1. Each side creates its identity in its own node.
    const alice = await aliceNode.identityCreateWithCustody(aliceProvider);
    const bob = await bobNode.identityCreateWithCustody(bobProvider);
    console.log(`Alice DID: ${alice.did}`);
    console.log(`Bob DID:   ${bob.did}`);

    // 2. Alice creates a single-admin context. The ceiling caps what any
    //    member can hold. Inviting runs through the governance gate, so the
    //    ceiling must carry governance:propose.
    const params: ContextParams = {
      ceiling: [
        "messages:read",
        "messages:write",
        "member:invite",
        "member:remove",
        "governance:propose",
      ],
      memoryScope: "ephemeral",
      mode: "Encrypted",
      governance: "single_admin",
    };
    const ctx = await aliceNode.contextCreate(alice, JSON.stringify(params));
    console.log();
    console.log(`Context created: ${ctx.contextId}`);

    // 3. Bob reserves a single-use KeyPackage and hands Alice its public
    //    bytes out of band.
    const reservation = await bobNode.reserveKeyPackage(bob.did);

    // 4. Alice seals an invitation to that KeyPackage. The bundle carries
    //    the relay set the context stored when Alice created it.
    const outcome = await aliceNode.inviteMember(
      ctx.contextId,
      alice.did,
      bob.did,
      reservation.keyPackagePublic,
    );
    console.log(`  Invitation sealed for ${bob.did}`);

    // 5. Bob opens the sealed bundle and joins.
    const joined = await bobNode.contextJoinFromWelcome(
      bob.did,
      outcome.bundle,
      reservation.reservationId,
    );
    console.log();
    console.log(`Bob joined context: ${joined.contextId}`);

    console.log();
    console.log("Context lifecycle complete.");
  } finally {
    await bobNode.shutdown();
    await aliceNode.shutdown();
  }
}
