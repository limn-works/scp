/**
 * Minimal SCP agent in Node.js/Bun.
 *
 * Creates a DID identity and opens an encrypted context, through the NAPI
 * native addon.
 *
 * The TypeScript SDK ships no production key store: its one custody string,
 * `"in_memory"`, works only with an addon built with the `testing` feature,
 * and a shipped addon rejects it with `SCP-IDENT-1008`. `runAgent` therefore
 * takes a `KeyCustodyProvider` that your application implements over its own
 * key store.
 *
 * Usage:
 *   import { runAgent } from "./index";
 *   await runAgent(myProvider, process.env.SCP_STORAGE_PASSPHRASE);
 */

import { type ContextParams, type KeyCustodyProvider, SCP } from "@limn-works/scp-ts";

export async function runAgent(
  provider: KeyCustodyProvider,
  storagePassphrase: string,
): Promise<void> {
  const scp = new SCP({
    storage: { type: "sqlite", path: "./scp-data", passphrase: storagePassphrase },
  });
  try {
    // 1. Create a DID identity whose keys the provider holds.
    const identity = await scp.identityCreateWithCustody(provider);
    console.log(`Created identity: ${identity.did}`);

    // 2. Create an encrypted context with messaging capabilities.
    const params: ContextParams = {
      ceiling: ["messages:read", "messages:write", "role:assign", "member:invite"],
      memoryScope: "ephemeral",
      mode: "Encrypted",
      governance: "single_admin",
    };
    const ctx = await scp.contextCreate(identity, JSON.stringify(params));
    console.log(`Created context: ${ctx.contextId}`);

    console.log("\nAgent complete.");
  } finally {
    await scp.shutdown();
  }
}
