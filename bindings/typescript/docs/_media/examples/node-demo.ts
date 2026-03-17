/**
 * Node.js/Bun demo for the SCP TypeScript SDK (NAPI backend).
 *
 * Demonstrates the core SCP workflow: create identities, create an encrypted
 * context, add a member, and verify membership.
 *
 * Prerequisites:
 *   1. Build the native addon:
 *      cargo build -p scp-ffi-napi --release --features allow_in_memory_custody
 *
 *   2. Wire it into node_modules (macOS arm64 — adjust for your platform):
 *      PKG_DIR="node_modules/@limn-works/scp-ts-napi-darwin-arm64"
 *      mkdir -p "$PKG_DIR"
 *      cp ../../target/release/libscp_ffi_napi.dylib "$PKG_DIR/index.node"
 *      echo '{"name":"@limn-works/scp-ts-napi-darwin-arm64","version":"0.1.0","main":"index.node"}' > "$PKG_DIR/package.json"
 *
 *   3. Run:
 *      bun run examples/node-demo.ts
 */

import { Context, Identity } from "../src/index";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function step(n: number, label: string): void {
  console.log(`\n--- Step ${n}: ${label} ---`);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log("SCP TypeScript SDK — Node.js/Bun Demo");
  console.log("======================================");

  // ---- Step 1: Create identities ----
  step(1, "Create identities (in-memory custody)");

  const alice = await Identity.create({ custody: "in_memory" });
  console.log(`Alice DID: ${alice.did}`);

  const bob = await Identity.create({ custody: "in_memory" });
  console.log(`Bob   DID: ${bob.did}`);

  // ---- Step 2: Alice creates an encrypted context ----
  step(2, "Create encrypted context");

  const ctx = await Context.create(alice, {
    ceiling: [
      "messages:read",
      "messages:write",
      "role:assign",
      "member:invite",
      "member:remove",
      "context:close",
    ],
    memoryScope: "ephemeral",
    governance: "single_admin",
    ttl: 3600,
  });
  console.log(`Context ID: ${ctx.contextId}`);

  // ---- Step 3: Add Bob to the context ----
  step(3, "Add Bob to context");

  await ctx.join(bob);
  console.log("Bob joined the context.");

  // ---- Step 4: Verify membership ----
  step(4, "Verify membership");

  const aliceIsMember = await ctx.isMember(alice.did);
  const bobIsMember = await ctx.isMember(bob.did);
  const memberCount = await ctx.memberCount();
  const memberDids = await ctx.memberDids();

  console.log(`Alice is member: ${aliceIsMember}`);
  console.log(`Bob   is member: ${bobIsMember}`);
  console.log(`Member count:    ${memberCount}`);
  console.log(`Member DIDs:     ${memberDids.map((d) => `${d.slice(0, 20)}...`).join(", ")}`);

  // ---- Step 5: Execute a governance action ----
  step(5, "Execute governance action (change Bob's role)");

  const changeBobRole = JSON.stringify({
    ChangeRole: { did: bob.did, new_role: "observer" },
  });
  const govResult = await ctx.executeGovernanceAction(changeBobRole);
  console.log(`Governance result: ${govResult}`);

  const bobRole = await ctx.memberRole(bob.did);
  console.log(`Bob's new role:  ${bobRole}`);

  // ---- Cleanup ----
  step(6, "Cleanup");

  await ctx.close();
  console.log("Context closed.");

  console.log("\nDemo complete.");
}

main().catch((error: unknown) => {
  console.error("Demo failed:", error);
  process.exit(1);
});
