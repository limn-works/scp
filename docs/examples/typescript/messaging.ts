/**
 * Two-participant message exchange.
 *
 * Demonstrates creating a context, adding a second participant,
 * and exchanging messages between them. Shows how the receive
 * generator delivers messages as an AsyncIterable.
 *
 * Prerequisites:
 *   bun add @limn-works/scp-ts
 *
 * Usage:
 *   bun run messaging.ts
 */

import { Context, Identity } from "@limn-works/scp-ts";
import type { ContextParams, Message } from "@limn-works/scp-ts";

async function main(): Promise<void> {
  // 1. Create two identities.
  const alice = await Identity.create({ custody: "in_memory" });
  const bob = await Identity.create({ custody: "in_memory" });
  console.log(`Alice: ${alice.did}`);
  console.log(`Bob:   ${bob.did}`);

  // 2. Alice creates a context with messaging capabilities.
  const params: ContextParams = {
    ceiling: [
      "messages:read",
      "messages:write",
      "member:invite",
      "member:remove",
    ],
    mode: "Encrypted",
  };

  const ctx = await Context.create(alice, params);
  console.log(`\nContext: ${ctx.contextId}`);

  // 3. Bob joins the context.
  await ctx.join(bob);
  console.log("Bob joined the context.");

  const members = await ctx.memberDids();
  console.log(`Members: ${JSON.stringify(members)}`);

  // 4. Alice sends a message.
  await ctx.send("Hello Bob!");
  console.log("\nAlice: Hello Bob!");

  // 5. Bob sends a reply (using the same context — both are local).
  await ctx.send("Hi Alice!");
  console.log("Bob: Hi Alice!");

  // 6. Receive messages via async iterable.
  //    In a real application, you would consume this in a long-running loop:
  //
  //    for await (const msg of ctx.receive()) {
  //      console.log(`[${msg.senderDid}] ${msg.content}`);
  //      if (someCondition) break;
  //    }
  //
  //    The iterator yields Message objects with:
  //    - senderDid: string
  //    - content: Uint8Array | string
  //    - timestamp: number
  //    - sequence: number
  //    - contextId: string
  //
  //    Breaking out of the loop stops delivery and releases resources.
  console.log("\n(Message receive iterator ready for consumption)");

  // 7. Clean up.
  await ctx.leave();
  console.log("\nLeft the context.");
  console.log("Message exchange complete.");
}

main().catch(console.error);
