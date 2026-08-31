// The quick start from `bindings/typescript/README.md`, verbatim apart from the
// import path (the README names the published package; this file names the
// source it is published from).
//
// `readme-quickstart.test.ts` spawns this file with `SCP_KEY_PASSPHRASE` and a
// scratch `HOME` set, because the Rust side reads the NATIVE process
// environment and a `process.env` write inside a running Bun process does not
// reach it. A change to either copy that the other does not mirror fails
// review, so the README stops drifting from what runs.

import { SCP } from "../../src/scp";

// Every call routes through an SCP instance (ADR-048). Name a storage
// backend: this constructor has no default.
const scp = new SCP({ storage: { type: "in_memory" } });

// Create a cryptographic identity (DID). Name a custody backend too —
// `identityCreate` has no default either (spec §17.17.1, SCP-CAPSEL-8000).
// `"file"` encrypts $HOME/.scp/keys.bin under SCP_KEY_PASSPHRASE (Argon2id +
// AES-256-GCM, spec §17.8), so this process owns its keys with no injected
// provider. `"platform"` and `"software"` instead require a
// KeyCustodyProvider you wire through `identityCreateWithCustody`.
const identity = await scp.identityCreate("file");
console.log(`DID: ${identity.did}`);

// Create an encrypted context. The ceiling bounds every capability any member
// of this context can ever hold, so it must carry `context:close` for the
// `contextClose` call below to pass its capability check.
const ctx = await scp.contextCreate(
  identity,
  JSON.stringify({
    ceiling: ["messages:read", "messages:write", "context:close"],
    memoryScope: "ephemeral",
    governance: "single_admin",
    ttl: 3600,
  }),
);

// Send a message (MLS-encrypted, signed, provenance-tagged).
await scp.contextSend(
  ctx._rawHandle,
  identity.did,
  new TextEncoder().encode("Hello from SCP"),
  null,
);

await scp.contextClose(ctx._rawHandle, identity.did);
await scp.shutdown(5);
