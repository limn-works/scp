# SCP TypeScript Node Scaffold

Minimal Node.js/Bun agent using the SCP TypeScript SDK with NAPI binding. Creates a DID identity and opens an encrypted context.

## Prerequisites

- Bun 1.0+ or Node.js 22+
- SCP TypeScript SDK (`@limn-works/scp-ts`)
- A `KeyCustodyProvider` implementation over your own key store

## Build and Run

```bash
cd scaffolds/typescript-node
bun install
bun run typecheck
```

`src/index.ts` exports `runAgent(provider, storagePassphrase)`. Call it from your
application with your `KeyCustodyProvider`:

```typescript
import { runAgent } from "./src/index";

await runAgent(myProvider, process.env.SCP_STORAGE_PASSPHRASE ?? "");
```

The SDK ships no production key store. Its one custody string, `"in_memory"`,
works only with an addon built with the `testing` feature; a shipped addon
rejects it with `SCP-IDENT-1008`.

## What This Does

1. Opens one `SCP` instance over a SQLCipher database in `./scp-data`
2. Creates a `did:dht` identity whose keys your provider holds
3. Opens an encrypted single-admin context
4. Shuts the instance down

## Next Steps

- Invite a second identity with `reserveKeyPackage`, `inviteMember` and
  `contextJoinFromWelcome` (see `docs/examples/typescript/context.ts`)
- See `docs/examples/typescript/` for more detailed examples
