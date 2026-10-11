/**
 * Identity creation and DID document inspection.
 *
 * Demonstrates creating a new SCP identity using did:dht,
 * inspecting the resulting DID document, and resolving it.
 *
 * The TypeScript SDK ships no production key store: its one `CustodyType`,
 * `"in_memory"`, works only with an addon built with the `testing` feature,
 * and a shipped addon rejects it with SCP-IDENT-1008. A production caller
 * passes its own `KeyCustodyProvider`, such as one backed by an HSM or the
 * operating system's key store, to `identityCreateWithCustody`.
 *
 * Prerequisites:
 *   bun add @limn-works/scp-ts
 *
 * Usage:
 *   import { identityExample } from "./identity";
 *   await identityExample(myCustodyProvider, process.env.SCP_STORAGE_PASSPHRASE);
 */

import { type KeyCustodyProvider, SCP } from "@limn-works/scp-ts";

export async function identityExample(
  provider: KeyCustodyProvider,
  storagePassphrase: string,
): Promise<void> {
  const scp = new SCP({
    storage: { type: "sqlite", path: "./scp-identity-example", passphrase: storagePassphrase },
  });
  try {
    // 1. Create a new identity whose keys the caller's provider holds.
    const alice = await scp.identityCreateWithCustody(provider);

    console.log(`DID: ${alice.did}`);
    console.log(`Custody type: ${alice.custodyType}`);
    console.log();

    // 2. Resolve the DID to its document.
    //    This queries the DHT and returns a DIDDocument.
    const doc = await scp.identityResolve(alice.did);

    console.log("DID Document:");
    console.log(JSON.stringify(doc, null, 2));
    console.log();

    // 3. Add an agent key to the identity.
    const withAgent = await scp.identityAddAgentKey(alice);
    console.log(`Added agent key to: ${withAgent.did}`);

    // 4. Rotate the agent key.
    const rotated = await scp.identityRotateAgentKey(withAgent);
    console.log(`Rotated agent key for: ${rotated.did}`);

    // 5. Remove the agent key.
    const cleaned = await scp.identityRemoveAgentKey(rotated);
    console.log(`Removed agent key from: ${cleaned.did}`);

    // 7. Rotate the active signing key (Layer 1 rotation).
    const rotatedKey = await scp.identityRotateKey(cleaned);
    console.log(`Rotated signing key: ${rotatedKey.did}`);

    console.log();
    console.log("Identity operations complete.");
  } finally {
    await scp.shutdown();
  }
}
