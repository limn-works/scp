/**
 * Minimal SCP agent in Node.js/Bun.
 *
 * Creates a DID identity and opens an encrypted context, through the NAPI
 * native addon.
 *
 * `runAgent` takes a `KeyCustodyProvider` that your application implements
 * over its own key store: the `"os_keystore"` custody request of spec
 * `03-identity.md` §3.2.2 reaches a host key store only through such a
 * provider.
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
