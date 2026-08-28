/**
 * Identity creation and DID document inspection.
 *
 * Demonstrates creating a new SCP identity using did:dht,
 * inspecting the resulting DID document, and resolving it.
 *
 * Prerequisites:
 *   bun add @limn-works/scp-ts
 *
 * Usage:
 *   bun run identity.ts
 */

import { Identity } from "@limn-works/scp-ts";

async function main(): Promise<void> {
  // 1. Create a new identity with in-memory key custody.
  //    In production, inject a KeyCustodyProvider through
  //    scp.identityCreateWithCustody to hold the keys in an OS keystore.
  //    No custody string reaches one: the bridge answers "platform" with
  //    SCP-IDENT-1003. That call returns SCP-IDENT-1059 on a released
  //    addon, because no pre-rotation custody backend is wired yet.
  const alice = await Identity.create({ custody: "in_memory" });

  console.log(`DID: ${alice.did}`);
  console.log(`Custody type: ${alice.custodyType}`);
  console.log();

  // 2. Resolve the DID to its document.
  //    This queries the DHT and returns a DIDDocument.
  const doc = await Identity.resolve(alice.did);

  console.log("DID Document:");
  console.log(`  ID: ${doc.id}`);
  console.log(`  Verification methods: ${doc.verificationMethods.length}`);
  for (const vm of doc.verificationMethods) {
    console.log(`    - ${vm.id} (type: ${vm.type})`);
  }
  console.log(`  Service endpoints: ${doc.serviceEndpoints.length}`);
  console.log();

  // 3. Create an identity with an agent signing key (ADR-039).
  //    Agent keys enable human+agent shared DID patterns.
  const agentIdentity = await Identity.createWithAgentKey({
    custody: "in_memory",
  });
  console.log(`Agent identity DID: ${agentIdentity.did}`);
  console.log();

  // 4. Add an agent key to an existing identity.
  const withAgent = await alice.addAgentKey();
  console.log(`Added agent key to: ${withAgent.did}`);

  // 5. Rotate the agent key.
  const rotated = await withAgent.rotateAgentKey();
  console.log(`Rotated agent key for: ${rotated.did}`);

  // 6. Remove the agent key.
  const cleaned = await rotated.removeAgentKey();
  console.log(`Removed agent key from: ${cleaned.did}`);

  // 7. Rotate the active signing key (Layer 1 rotation).
  const rotatedKey = await alice.rotateKey();
  console.log(`Rotated signing key: ${rotatedKey.did}`);

  console.log();
  console.log("Identity operations complete.");
}

main().catch(console.error);
