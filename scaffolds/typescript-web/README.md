# SCP TypeScript Web Scaffold

Minimal SCP TypeScript SDK example. It creates a DID identity, opens an
encrypted context, and sends a message.

This example runs the protocol engine **in-process** via the `@limn-works/scp-ts`
NAPI native addon, which loads only under **Node.js / Bun** — not in a browser.
It is therefore a server-side example: run it with `bun run start`, not by opening
the page in a browser.

> **Browser support is forthcoming, and not what this example does today.** Per
> ADR-055, the intended browser model is a *remote thin client*: a browser
> connects to a server-side `scp-node` over an RPC/WebSocket boundary and issues
> protocol operations remotely; the node holds the MLS group state, runtime,
> custody, and event log. There is no in-browser protocol execution. The
> remote-thin-client transport that would let this UI run in a browser does not
> exist yet — until it lands, `src/index.ts` and `index.html` are a server-side
> (Node/Bun) example whose DOM scaffolding previews that future browser UI.

## Prerequisites

- Bun 1.0+ (or Node.js) — the NAPI addon is Node/Bun-only
- SCP TypeScript SDK (`@limn-works/scp-ts`)

## Build and Run

```bash
cd scaffolds/typescript-web
bun install
bun run start
```

`bun run start` builds and runs the example under Bun. (`open index.html` would
load the bundle in a browser, where the NAPI addon cannot load — that path waits
on the ADR-055 remote-thin-client transport.)

## What This Does

1. Creates a `did:dht` identity with in-memory key custody (in-process via NAPI)
2. Opens an encrypted context with messaging capabilities
3. Sends a message and displays the result

## Next Steps

- Persist identity via a NAPI-backed storage backend
- Connect to a relay via WebSocket/WebTransport for real networking
- Add a second participant and implement real-time message display
- For the browser, adopt the forthcoming ADR-055 remote-thin-client transport to
  a server-side `scp-node`
- See `docs/examples/typescript/` for more detailed examples
