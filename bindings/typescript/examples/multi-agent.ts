/**
 * Multi-agent coordination: multiple agents collaborating in a shared context.
 */

import { Context, Identity } from "@scp/sdk";
import { mint } from "@scp/sdk/ucan";

async function runAgent(
  name: string,
  identity: Identity,
  contextId: string,
): Promise<void> {
  const ctx = await Context.join(identity, contextId);
  console.log(`[${name}] Joined context ${contextId}`);

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
  const coordinator = await Identity.create({ custody: "platform" });
  const agentA = await Identity.create({ custody: "platform" });
  const agentB = await Identity.create({ custody: "platform" });

  // Coordinator creates the context with agent capabilities
  const ctx = await Context.create(coordinator, {
    ceiling: ["msg:send", "msg:receive", "tool:invoke"],
    roles: {
      agent: ["msg:send", "msg:receive", "tool:invoke"],
    },
    governance: "single_admin",
  });
  console.log(`Context created: ${ctx.contextId}`);

  // Mint UCANs for each agent (capability delegation)
  await mint({
    issuer: coordinator,
    audience: agentA.did,
    capabilities: ["msg:send", "msg:receive"],
    contextId: ctx.contextId,
  });
  await mint({
    issuer: coordinator,
    audience: agentB.did,
    capabilities: ["msg:send", "msg:receive"],
    contextId: ctx.contextId,
  });

  // Run agents concurrently
  await Promise.all([
    runAgent("Agent-A", agentA, ctx.contextId),
    runAgent("Agent-B", agentB, ctx.contextId),
  ]);

  await ctx.close();
}

main().catch(console.error);
