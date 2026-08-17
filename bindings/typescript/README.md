# SCP TypeScript SDK

> `@limn-works/scp-ts` -- Shared Context Protocol for TypeScript

Cryptographic identity, encrypted contexts, capability-based auth, and outlet invocation for AI agents. Runs on Bun/Node via a native addon. In the browser, the full protocol runs in-tab via the sibling wasm tier [`@limn-works/scp-ts-wasm`](../typescript-wasm), keys on-device (ADR-057); a remote custodial thin client is now only an optional mode, not the definitive browser story.

## Install

```bash
npm install @limn-works/scp-ts
# or
bun add @limn-works/scp-ts
```

## Quick Start

Set `SCP_KEY_PASSPHRASE` before you run this. `"file"` custody protects
`$HOME/.scp/keys.bin` with that passphrase and reads it from the environment;
without it `identityCreate` throws `ValidationError`.

```bash
export SCP_KEY_PASSPHRASE='a passphrase you keep'
```

```typescript
import { SCP } from "@limn-works/scp-ts";

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
```

Receiving messages needs a relay, because a subscription reads what a relay
holds. Call `transportConnect` before `contextSubscribe`, or
`contextSubscribe` throws `TransportError` with `SCP-TRANS-5010`:

```typescript
await scp.transportConnect("ws://127.0.0.1:9000");
await scp.contextSubscribe(ctx._rawHandle, identity.did, (msg) => {
  console.log(msg);
});
```

### One call this SDK answers closed today

`identityCreate` commits a pre-rotation commitment at creation, which spec
§9.7.4.1 §3 makes mandatory. No production `PreRotationCustody` backend exists
yet, so an addon published from npm answers every `identityCreate` call —
whichever custody you name — with:

```
[SCP-IDENT-1059] no production pre-rotation custody backend available
```

That is the protocol failing closed rather than minting a test-only stand-in
(`.docs/adrs/ADR-062-capability-injection.md` §Decision 6). Issue #1729 and RFC
#2130 track the real backend. To run the quick start above before that backend
lands, build the addon from source with the `testing` feature:

```bash
cargo build -p scp-ffi-napi --release --features testing
```

`tests/readme-quickstart.test.ts` runs the block above verbatim, so this README
stops drifting from what runs.

## Runtime Support

| Target | FFI Bridge | Runtime |
|--------|-----------|---------|
| Server | napi-rs (native addon) | Bun >= 1.0, Node >= 22 |

In the browser, the full SCP/MLS protocol runs **in-tab** with keys on-device via the sibling wasm tier [`@limn-works/scp-ts-wasm`](../typescript-wasm) (ADR-057, which amends ADR-055's earlier remote-thin-client model) — a capability subset of this package's surface. Running the protocol engine server-side and driving it from the browser as a remote custodial thin client remains available as an optional mode, but is no longer the only browser story. Browser developers should install `@limn-works/scp-ts-wasm`; install exactly one tier per environment.

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
| `outlet-invocation.ts` | Register and invoke a outlet with test vectors |
| `mcp-integration.ts` | Expose SCP outlets via MCP JSON-RPC server |
| `multi-agent.ts` | Coordinate multiple agents in a shared context |
| `node-demo.ts` | End-to-end NAPI demo: identity, context, messaging, membership |

### Quick Start (Node.js/Bun)

```bash
# Build the native addon
cargo build -p scp-ffi-napi --release --features testing

# Wire into node_modules (macOS arm64 — adjust for your platform)
PKG_DIR="node_modules/@limn-works/scp-ts-napi-darwin-arm64"
mkdir -p "$PKG_DIR"
cp ../../target/release/libscp_ffi_napi.dylib "$PKG_DIR/index.node"
echo '{"name":"@limn-works/scp-ts-napi-darwin-arm64","version":"0.1.0","main":"index.node"}' > "$PKG_DIR/package.json"

# Run the demo
bun run examples/node-demo.ts
```

## Error Handling

All errors extend `ScpError` with a machine-readable `code` field:

```typescript
import { ScpError, ContextError } from "@limn-works/scp-ts";

try {
  await scp.contextSend(ctx._rawHandle, identity.did, payload, null);
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
