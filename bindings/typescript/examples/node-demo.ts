/**
 * Node.js/Bun demo for the SCP TypeScript SDK (NAPI backend).
 *
 * Demonstrates the core SCP workflow: create identities, create an
 * encrypted context, add a member, verify membership, and execute a
 * governance action.
 *
 * Post-Phase-4 (ADR-048): every SDK call routes through an explicit
 * `SCP` instance. The old namespace factories (`Identity.create`,
 * `Context.create`) were removed — use `scp.identityCreate`,
 * `scp.contextCreate`, and the other `scp.*` methods directly.
 *
 * Prerequisites:
 *   1. Build the native addon:
 *      cargo build -p scp-ffi-napi --release --features testing
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

import { SCP } from "../src/index";

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

  const scp = new SCP({ storage: { type: "in_memory" } });
  try {
    // ---- Step 1: Create identities ----
    step(1, "Create identities (in-memory custody)");

    const alice = await scp.identityCreate("encrypted_file");
    console.log(`Alice DID: ${alice.did}`);

    const bob = await scp.identityCreate("encrypted_file");
    console.log(`Bob   DID: ${bob.did}`);

    // ---- Step 2: Alice creates an encrypted context ----
    step(2, "Create encrypted context");

    const ctx = await scp.contextCreate(
      alice,
      JSON.stringify({
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
      }),
    );
    console.log(`Context ID: ${ctx.contextId}`);

    // ---- Step 3: Add Bob to the context ----
    step(3, "Add Bob to context");

    await scp.contextJoin(ctx._rawHandle, bob.did, null);
    console.log("Bob joined the context.");

    // ---- Step 4: Verify membership ----
    step(4, "Verify membership");

    const aliceIsMember = await scp.contextIsMember(ctx._rawHandle, alice.did);
    const bobIsMember = await scp.contextIsMember(ctx._rawHandle, bob.did);
    const memberCount = await scp.contextMemberCount(ctx._rawHandle);
    const memberDids = await scp.contextMemberDids(ctx._rawHandle);

    console.log(`Alice is member: ${aliceIsMember}`);
    console.log(`Bob   is member: ${bobIsMember}`);
    console.log(`Member count:    ${memberCount}`);
    console.log(`Member DIDs:     ${memberDids.map((d) => `${d.slice(0, 20)}...`).join(", ")}`);

    // ---- Step 5: Execute a governance action ----
    step(5, "Execute governance action (change Bob's role)");

    const changeBobRole = JSON.stringify({
      ChangeRole: { did: bob.did, new_role: "observer" },
    });
    // Propose the action, then execute the tracked, approved proposal BY ID.
    // Execution takes only the proposal id — the executor and consequence
    // subject are resolved from the tracked proposal's proposer.
    const proposeResult = await scp.contextGovernancePropose(
      ctx._rawHandle,
      changeBobRole,
      alice.did,
    );
    const proposalIdHex = JSON.parse(proposeResult).proposal_id as string;
    const govResult = await scp.contextExecuteGovernanceAction(ctx._rawHandle, proposalIdHex);
    console.log(`Governance result: ${govResult}`);

    const bobRole = await scp.contextMemberRole(ctx._rawHandle, bob.did);
    console.log(`Bob's new role:  ${bobRole}`);

    // ---- Cleanup ----
    step(6, "Cleanup");

    await scp.contextClose(ctx._rawHandle, alice.did);
    console.log("Context closed.");

    console.log("\nDemo complete.");
  } finally {
    await scp.shutdown(5);
  }
}

main().catch((error: unknown) => {
  console.error("Demo failed:", error);
  process.exit(1);
});
