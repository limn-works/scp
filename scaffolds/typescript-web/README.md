# SCP TypeScript Web Scaffold

Minimal browser app using the SCP TypeScript SDK as a remote thin client. The protocol engine runs server-side (an scp-node); the browser app drives it over the network. Creates a DID identity, opens an encrypted context, and sends a message.

## Prerequisites

- Bun 1.0+
- SCP TypeScript SDK (`@limn-works/scp-ts`)

## Build and Run

```bash
cd scaffolds/typescript-web
bun install
bun run start
```

## What This Does

1. Connects to a server-side scp-node as a remote thin client
2. Creates a `did:dht` identity with in-memory key custody
3. Opens an encrypted context with messaging capabilities
4. Sends a message and displays the result

## Next Steps

- Persist identity server-side via the scp-node's storage backend
- Connect to a relay via WebSocket/WebTransport for real networking
- Add a second participant and implement real-time message display
- See `docs/examples/typescript/` for more detailed examples
