# SCP TypeScript SDK Examples

Demonstrates the core operations of the SCP TypeScript SDK: identity management,
context lifecycle, messaging, and tool invocation.

## Prerequisites

1. **Bun runtime** (project uses Bun, not npm/npx):
   ```bash
   curl -fsSL https://bun.sh/install | bash
   ```

2. **Install the SDK**:
   ```bash
   bun add @limn-works/scp-ts
   ```

   Or link the local build:
   ```bash
   cd bindings/typescript
   bun run build
   bun link
   ```

## Running the Examples

Each example is a standalone TypeScript script:

```bash
# Identity creation and DID document inspection
bun run identity.ts

# Context creation and lifecycle management
bun run context.ts

# Two-party message exchange
bun run messaging.ts

# Tool registration and invocation
bun run tools.ts
```

## Examples

| File | Description |
|------|-------------|
| `identity.ts` | Create identity, resolve DID, inspect document, agent key management |
| `context.ts` | Create context, configure capabilities, join/leave, membership queries |
| `messaging.ts` | Two-party message exchange with `AsyncIterable` receive |
| `tools.ts` | Define tools with `defineToolDefinition`, UCAN-authorized invocation |

## Key Patterns

- **Server in-process**: On Bun/Node the SDK runs the protocol engine in-process via the napi-rs native addon. In the browser the full protocol runs in-tab via the sibling wasm tier `@limn-works/scp-ts-wasm`, keys on-device (ADR-057); a remote custodial thin client is an optional mode.
- **AsyncDisposable**: `Context` implements `Symbol.asyncDispose` for `await using` cleanup.
- **Typed params**: Use `ContextParams`, `ToolDefinition`, `Message` types for safety.
- **UCAN authorization**: Tool invocation requires a valid UCAN token (spec section 7.2).
- **Receive generator**: `ctx.receive()` returns `AsyncIterable<Message>` for streaming.
- **Error hierarchy**: `ScpError`, `ContextError`, `ToolError`, `IdentityError`, etc.

## SDK Reference

- TypeScript SDK source: `bindings/typescript/src/`
- NAPI bridge: `crates/scp-ffi/napi/`
- Protocol spec: `.docs/specs/`
