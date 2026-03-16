/**
 * Multi-agent coordination: multiple agents collaborating in a shared context.
 */

import { Context, Identity, mintUcan } from "@limn-works/scp-ts";

async function runAgent(
  name: string,
  identity: Identity,
  ctx: Context,
): Promise<void> {
  await ctx.join(identity);
  console.log(`[${name}] Joined context ${ctx.contextId}`);

  await ctx.send(new TextEncoder().encode(`[${name}] reporting in`));

  let count = 0;
  for await (const msg of ctx.receive()) {
    const text = new TextDecoder().decode(msg.content as Uint8Array);
    console.log(`[${name}] Received from ${msg.senderDid.slice(0, 16)}...: ${text}`);
    count++;
    if (count >= 2) break;
  }

  await ctx.leave();
  console.log(`[${name}] Left context`);
}

async function main(): Promise<void> {
  // Create identities for coordinator and two agents
  const coordinator = await Identity.create({ custody: "in_memory" });
  const agentA = await Identity.create({ custody: "in_memory" });
  const agentB = await Identity.create({ custody: "in_memory" });

  // Coordinator creates the context with agent capabilities
  const ctx = await Context.create(coordinator, {
    ceiling: [
      "messages:read",
      "messages:write",
      "tool:invoke:*",
      "member:invite",
      "member:remove",
      "role:assign",
    ],
    roles: {
      agent: ["messages:write", "messages:read", "tool:invoke:*"],
    },
    memoryScope: "ephemeral",
    governance: "single_admin",
  });
  console.log(`Context created: ${ctx.contextId}`);

  // Mint UCANs for each agent (capability delegation)
  await mintUcan(ctx, agentA.did, ["messages:write", "messages:read"]);
  await mintUcan(ctx, agentB.did, ["messages:write", "messages:read"]);

  // Run agents concurrently
  await Promise.all([
    runAgent("Agent-A", agentA, ctx),
    runAgent("Agent-B", agentB, ctx),
  ]);

  await ctx.close();
}

main().catch(console.error);
