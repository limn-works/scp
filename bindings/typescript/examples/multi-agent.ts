/**
 * Multi-agent coordination: multiple agents collaborating in a shared
 * context via UCAN-scoped capabilities.
 *
 * Post-Phase-4 (ADR-048): all bridge operations route through an
 * explicit `SCP` instance. The free-function `mintUcan` was removed —
 * use `scp.ucanMint(...)`.
 *
 * Run: bun run examples/multi-agent.ts
 */

import { SCP, type Context, type Identity } from "../src/index";

async function runAgent(
  name: string,
  scp: SCP,
  identity: Identity,
  ctx: Context,
): Promise<void> {
  await scp.contextJoin(ctx._rawHandle, identity.did, null);
  console.log(`[${name}] Joined context ${ctx.contextId}`);

  // Collect up to two inbound messages per agent. Subscription callbacks
  // run on the relay reader task — stash results and resolve a promise
  // when the count is reached.
  let resolveDone: (() => void) | null = null;
  const done = new Promise<void>((r) => {
    resolveDone = r;
  });
  let received = 0;
  await scp.contextSubscribe(ctx._rawHandle, identity.did, (raw) => {
    const msg = raw as { senderDid?: string; payload?: number[] | Uint8Array };
    if (msg?.senderDid !== undefined && msg.payload !== undefined) {
      const bytes = msg.payload instanceof Uint8Array ? msg.payload : new Uint8Array(msg.payload);
      console.log(
        `[${name}] Received from ${msg.senderDid.slice(0, 16)}...: ${new TextDecoder().decode(bytes)}`,
      );
      received += 1;
      if (received >= 2 && resolveDone !== null) {
        resolveDone();
        resolveDone = null;
      }
    }
  });

  await scp.contextSend(
    ctx._rawHandle,
    identity.did,
    new TextEncoder().encode(`[${name}] reporting in`),
    null,
  );

  // Race the expected two-message target against a short timeout so the
  // demo terminates even if the relay is backed up.
  await Promise.race([
    done,
    new Promise<void>((resolve) => setTimeout(resolve, 500)),
  ]);

  scp.contextCancelSubscription(ctx._rawHandle);
  await scp.contextLeave(ctx._rawHandle, identity.did);
  console.log(`[${name}] Left context`);
}

async function main(): Promise<void> {
  const scp = new SCP({ storage: { type: "in_memory" } });
  try {
    // Create identities for coordinator and two agents.
    const coordinator = await scp.identityCreate("encrypted_file");
    const agentA = await scp.identityCreate("encrypted_file");
    const agentB = await scp.identityCreate("encrypted_file");

    // Coordinator creates the context with agent capabilities.
    const ctx = await scp.contextCreate(
      coordinator,
      JSON.stringify({
        ceiling: [
          "messages:read",
          "messages:write",
          "outlet:call:*",
          "member:invite",
          "member:remove",
          "role:assign",
        ],
        roles: {
          agent: ["messages:write", "messages:read", "outlet:call:*"],
        },
        memoryScope: "ephemeral",
        governance: "single_admin",
      }),
    );
    console.log(`Context created: ${ctx.contextId}`);

    // Mint UCANs for each agent (capability delegation).
    await scp.ucanMint(ctx._rawHandle, agentA.did, ["messages:write", "messages:read"]);
    await scp.ucanMint(ctx._rawHandle, agentB.did, ["messages:write", "messages:read"]);

    // Run agents concurrently.
    await Promise.all([
      runAgent("Agent-A", scp, agentA, ctx),
      runAgent("Agent-B", scp, agentB, ctx),
    ]);

    await scp.contextClose(ctx._rawHandle, coordinator.did);
  } finally {
    await scp.shutdown(5);
  }
}

main().catch((error: unknown) => {
  console.error("Demo failed:", error);
  process.exit(1);
});
