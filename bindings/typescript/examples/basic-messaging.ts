/**
 * Basic messaging: create identity, create context, send and receive messages.
 */

import { Context, Identity } from "@limn-works/scp-ts";

async function main(): Promise<void> {
  // Create two identities
  const alice = await Identity.create({ custody: "platform" });
  const bob = await Identity.create({ custody: "platform" });
  console.log(`Alice DID: ${alice.did}`);
  console.log(`Bob DID: ${bob.did}`);

  // Alice creates a context
  const ctxAlice = await Context.create(alice, {
    ceiling: ["msg:send", "msg:receive"],
    ttl: 3600,
    governance: "single_admin",
  });
  console.log(`Context ID: ${ctxAlice.contextId}`);

  // Bob joins the context
  const ctxBob = await Context.join(bob, ctxAlice.contextId);

  // Alice sends a message
  await ctxAlice.send(new TextEncoder().encode("Hello Bob, this is Alice"));

  // Bob receives it
  for await (const msg of ctxBob.receive()) {
    const text = new TextDecoder().decode(msg.content as Uint8Array);
    console.log(`Bob received from ${msg.senderDid}: ${text}`);
    break;
  }

  // Cleanup
  await ctxBob.leave();
  await ctxAlice.close();
}

main().catch(console.error);
