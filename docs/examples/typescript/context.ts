/**
 * Context creation and lifecycle management.
 *
 * Demonstrates creating an SCP context with governance parameters,
 * inspecting its state, joining/leaving, and managing membership.
 *
 * Prerequisites:
 *   bun add @limn-works/scp-ts
 *
 * Usage:
 *   bun run context.ts
 */

import { Context, Identity } from "@limn-works/scp-ts";
import type { ContextParams } from "@limn-works/scp-ts";

async function main(): Promise<void> {
  // 1. Create the identity that will own the context.
  const alice = await Identity.create({ custody: "in_memory" });
  console.log(`Alice DID: ${alice.did}`);

  // 2. Define context parameters.
  const params: ContextParams = {
    ceiling: [
      "messages:read",
      "messages:write",
      "member:invite",
      "member:remove",
      "tool:register",
      "tool:invoke_all",
    ],
    mode: "Encrypted",
    memoryScope: "full",
    governance: "single_admin",
  };

  // 3. Create the context.
  //    Uses `await using` for automatic cleanup (AsyncDisposable).
  //    When scope exits, ctx.leave() is called automatically.
  {
    const ctx = await Context.create(alice, params);

    console.log();
    console.log(`Context created: ${ctx.contextId}`);

    // 4. Check membership -- the creator is automatically a member.
    const members = await ctx.memberDids();
    console.log(`  Members: ${JSON.stringify(members)}`);

    const count = await ctx.memberCount();
    console.log(`  Member count: ${count}`);

    const isAlice = await ctx.isMember(alice.did);
    console.log(`  Alice is member: ${isAlice}`);

    const role = await ctx.memberRole(alice.did);
    console.log(`  Alice role: ${role}`);

    // 5. Send a message to the context.
    await ctx.send("Hello, context!");
    console.log("  Message sent successfully.");

    // 6. Bob joins the context.
    const bob = await Identity.create({ custody: "in_memory" });
    await ctx.join(bob);
    console.log();
    console.log(`Bob joined the context.`);

    const membersAfter = await ctx.memberDids();
    console.log(`  Members after join: ${JSON.stringify(membersAfter)}`);

    // 7. Leave and close.
    await ctx.leave();
    console.log("Left the context.");
  }

  console.log();
  console.log("Context lifecycle complete.");
}

main().catch(console.error);
