# SCP TypeScript Node Scaffold

Minimal Node.js/Bun agent using the SCP TypeScript SDK with NAPI binding. Creates a DID identity, opens an encrypted context, and sends a message.

## Prerequisites

- Bun 1.0+ or Node.js 22+
- SCP TypeScript SDK (`@limn-works/scp-ts`)

## Build and Run

```bash
cd scaffolds/typescript-node
bun install
bun run start
```

## What This Does

1. Creates a `did:dht` identity with in-memory key custody
2. Opens an encrypted context with messaging capabilities
3. Sends a message
4. Cleans up by leaving the context

## Next Steps

- Replace `"in_memory"` custody with `"platform"` for production
- Add tool registration with `defineToolDefinition()`
- Connect to a relay with `Transport.connect()` for real networking
- See `docs/examples/typescript/` for more detailed examples
