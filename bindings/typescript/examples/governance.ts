/**
 * Governance demo.
 *
 * Starts an in-memory relay via the caller-owned `SCP`, creates an
 * identity, creates a governed context, executes a governance action
 * (role change), and reports the outcome.
 *
 * Post-Phase-4 (ADR-048): every SDK call routes through an explicit
 * `SCP` instance. The static `Relay.startInMemory()` factory was
 * removed — construct via `scp.relayStartInMemory()`.
 *
 * Run: bun run examples/governance.ts
 */

import { SCP } from "../src/index";

async function main(): Promise<void> {
  const scp = new SCP({ storage: { type: "in_memory" } });
  let relay: Awaited<ReturnType<SCP["relayStartInMemory"]>> | null = null;
  try {
    // 1. Start an in-memory relay.
    relay = await scp.relayStartInMemory();
    console.log(`Relay listening at ${relay.relayUrl}`);

    // 2. Create admin identity.
    const admin = await scp.identityCreate("in_memory");
    console.log(`Admin DID: ${admin.did}`);

    // 3. Wire the bridge's transport to the relay.
    await scp.configureRelayTransport(relay.relayUrl, admin.did);

    // 4. Create a context with governance enabled.
    const ctx = await scp.contextCreate(
      admin,
      JSON.stringify({
        ceiling: [
          "messages:read",
          "messages:write",
          "member:invite",
          "governance:propose",
          "governance:vote",
        ],
        memoryScope: "ephemeral",
        governance: "single_admin",
        ttl: 600,
      }),
    );
    console.log(`Governed context created: ${ctx.contextId}`);

    // 5. Create a second identity and have them join.
    const member = await scp.identityCreate("in_memory");
    await scp.contextJoin(ctx._rawHandle, member.did, null);
    console.log(`Member ${member.did} joined`);

    // 6. Admin proposes a governance action to change the member's role, then
    //    executes the tracked, approved proposal BY ID. Execution takes only
    //    the proposal id — the executor and consequence subject are resolved
    //    from the tracked proposal's proposer, never passed by the caller.
    try {
      const action = JSON.stringify({
        ChangeRole: { did: member.did, new_role: "moderator" },
      });
      const proposeResult = await scp.contextGovernancePropose(
        ctx._rawHandle,
        action,
        admin.did,
      );
      const proposalIdHex = JSON.parse(proposeResult).proposal_id as string;
      console.log(`Proposal created: ${proposalIdHex}`);

      const result = await scp.contextExecuteGovernanceAction(
        ctx._rawHandle,
        proposalIdHex,
      );
      console.log("Governance action result:", result);
    } catch (err) {
      console.log("Governance action:", err);
    }

    // 7. Cleanup.
    await scp.contextClose(ctx._rawHandle, admin.did);
    console.log("Context closed");
  } finally {
    if (relay !== null) {
      await relay.shutdown();
    }
    await scp.shutdown(5);
    console.log("Demo complete");
  }
}

main().catch((error: unknown) => {
  console.error("Demo failed:", error);
  process.exit(1);
});
