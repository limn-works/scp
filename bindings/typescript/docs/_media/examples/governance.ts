/**
 * Governance demo.
 *
 * Starts an in-memory relay, creates an identity, creates a governed
 * context, executes a governance action (role change), and verifies the
 * result.
 *
 * Run: bun run examples/governance.ts
 */

import { connectLocalTransport, Context, Identity, Relay } from "@limn-works/scp-ts";

async function main(): Promise<void> {
  // 1. Start an in-memory relay
  const relay = await Relay.startInMemory();
  try {
    console.log(`Relay listening at ${relay.relayUrl}`);

    // 1b. Connect transport to the relay
    await connectLocalTransport(relay.relayUrl);

    // 2. Create admin identity
    const admin = await Identity.create({ custody: "in_memory" });
    console.log(`Admin DID: ${admin.did}`);

    // 3. Create a context with governance enabled
    const ctx = await Context.create(admin, {
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
    });
    console.log(`Governed context created: ${ctx.contextId}`);

    // 4. Create a second identity and have them join
    const member = await Identity.create({ custody: "in_memory" });
    await ctx.join(member);
    console.log(`Member ${member.did} joined`);

    // 5. Admin executes a governance action to change the member's role
    try {
      const proposal = JSON.stringify({
        ChangeRole: { did: member.did, new_role: "moderator" },
      });
      const result = await ctx.executeGovernanceAction(proposal);
      console.log("Governance action result:", result);
    } catch (err) {
      console.log("Governance action:", err);
    }

    // 6. Cleanup
    await ctx.close();
    console.log("Context closed");
  } finally {
    await relay.shutdown();
    console.log("Demo complete");
  }
}

main().catch(console.error);
