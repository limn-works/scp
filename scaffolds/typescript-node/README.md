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

1. Creates a `did:dht` identity with encrypted-key-file custody
2. Opens an encrypted context with messaging capabilities
3. Sends a message
4. Cleans up by leaving the context

## Next Steps

- This scaffold passes `"encrypted_file"`, the on-disk key store SCP implements, and the bridge reads its passphrase from `SCP_KEY_PASSPHRASE`. Reach the operating system's key store instead with `"os_keystore"` plus your own `KeyCustodyProvider` for the operating system's key store. §3.2.2 of the identity spec, the custody vocabulary, states those two values. Either call throws `SCP-IDENT-1059` on a released addon, because no pre-rotation custody backend is wired yet
- Add tool registration with `defineToolDefinition()`
- Connect to a relay with `Transport.connect()` for real networking
- See `docs/examples/typescript/` for more detailed examples
