# SCP TypeScript SDK

> `@limn-works/scp-ts` -- Shared Context Protocol for TypeScript

Cryptographic identity, encrypted contexts, capability-based auth, and tool invocation for AI agents. Dual-target: browser (WASM) and Bun/Node (native addon).

## Install

```bash
npm install @limn-works/scp-ts
# or
bun add @limn-works/scp-ts
```

## Quick Start

```typescript
import { Identity, Context } from "@limn-works/scp-ts";

// Create a cryptographic identity (DID)
const identity = await Identity.create({ custody: "platform" });
console.log(`DID: ${identity.did}`);

// Create an encrypted context
const ctx = await Context.create(identity, {
  ceiling: ["msg:send", "msg:receive"],
  ttl: 3600,
});

// Send a message (MLS-encrypted, signed, provenance-tagged)
await ctx.send(new TextEncoder().encode("Hello from SCP"));

// Receive messages
for await (const msg of ctx.receive()) {
  console.log(`${msg.senderDid}: ${msg.content}`);
  break;
}

await ctx.close();
```

## Runtime Support

| Target | FFI Bridge | Runtime |
|--------|-----------|---------|
| Browser | wasm-bindgen (WASM) | Any modern browser |
| Server | napi-rs (native addon) | Bun >= 1.0, Node >= 22 |

Bridge selection is automatic at import time. The public API is identical across targets.

## API Reference

Generated from source via `typedoc`. Build locally:

```bash
npx typedoc src/index.ts
```

Published API docs are generated on every release by CI.

## Type Declarations

Ships `.d.ts` type declarations for full IDE autocompletion and static analysis. Types are bundled in the `dist/` directory and referenced via `package.json` `"types"` field.

## Examples

See [`examples/`](./examples/) for runnable scripts:

| File | Description |
|------|-------------|
| `basic-messaging.ts` | Create identity, context, send/receive messages |
| `tool-invocation.ts` | Register and invoke a tool with test vectors |
| `mcp-integration.ts` | Expose SCP tools via MCP JSON-RPC server |
| `multi-agent.ts` | Coordinate multiple agents in a shared context |

## Error Handling

All errors extend `ScpError` with a machine-readable `code` field:

```typescript
import { ScpError, ContextError } from "@limn-works/scp-ts";

try {
  await ctx.send(payload);
} catch (e) {
  if (e instanceof ContextError) {
    console.error(`[${e.code}] ${e.message}`);
  }
}
```

## Source

- Scaffold: `.docs/scaffold/typescript.md`
- Standards: `.docs/standards/typescript.md`
- API sketch: `.docs/sketch.md`
