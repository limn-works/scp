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

The identity below asks for `"encrypted_file"` custody (spec `03-identity.md` §3.2.2): its keys live in the encrypted key file `$HOME/.scp/keys.bin`, sealed under the passphrase in the `SCP_KEY_PASSPHRASE` environment variable, so set that variable before you run it. The quick start runs only with a native addon built with the `testing` feature (`cargo build -p scp-ffi-napi --features testing`), because a published addon has no independent next-set substrate and answers `"encrypted_file"`, and a `KeyCustodyProvider`, with `SCP-IDENT-1100`. For a key store you own, pass a `KeyCustodyProvider` to `identityCreateWithCustody`, which creates an `"os_keystore"` identity.

```typescript
import { SCP } from "@limn-works/scp-ts";

// Every call goes through an SCP instance, which takes a required storage backend.
const scp = new SCP({ storage: { type: "in_memory" } });

// Create a cryptographic identity (DID) whose keys live in the encrypted key file.
const identity = await scp.identityCreate("encrypted_file");
console.log(`DID: ${identity.did}`);

// Create an encrypted context that this identity administers.
const ctx = await scp.contextCreate(
  identity,
  JSON.stringify({
    ceiling: ["messages:read", "messages:write", "context:close"],
    memoryScope: "ephemeral",
    governance: "single_admin",
  }),
);
console.log(`Context: ${ctx.contextId}`);

await scp.shutdown(5);
```

`tests/readme-quickstart.test.ts` reads the block above from this file and runs it.

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

### Running the examples

Each example creates `"encrypted_file"` identities, so it needs `SCP_KEY_PASSPHRASE` set and writes their keys to `$HOME/.scp/keys.bin`. The commands below point `HOME` at a scratch directory so the run leaves no key file in your home directory.

```bash
# Build the native addon
cargo build -p scp-ffi-napi --release --features testing

# Wire into node_modules (macOS arm64 — adjust for your platform)
PKG_DIR="node_modules/@limn-works/scp-ts-napi-darwin-arm64"
mkdir -p "$PKG_DIR"
cp ../../target/release/libscp_ffi_napi.dylib "$PKG_DIR/index.node"
echo '{"name":"@limn-works/scp-ts-napi-darwin-arm64","version":"0.1.0","main":"index.node"}' > "$PKG_DIR/package.json"

# Run an example (replace node-demo.ts with any file in examples/)
HOME=$(mktemp -d) SCP_KEY_PASSPHRASE=example-passphrase bun run examples/node-demo.ts
```

## Error Handling

`SCP` methods throw subclasses of `ScpError`, each with a machine-readable `code`. Here `contextCreate` rejects an unknown governance model with `ValidationError` code `SCP-VALID-7000`. Like the quick start, this example needs `SCP_KEY_PASSPHRASE` set and a native addon built with the `testing` feature.

```typescript
import { SCP, ValidationError } from "@limn-works/scp-ts";

const scp = new SCP({ storage: { type: "in_memory" } });
const identity = await scp.identityCreate("encrypted_file");
try {
  await scp.contextCreate(
    identity,
    JSON.stringify({
      ceiling: ["messages:read"],
      memoryScope: "ephemeral",
      governance: "dictator",
    }),
  );
} catch (e) {
  if (!(e instanceof ValidationError)) throw e;
  console.error(`contextCreate rejected the params: ${e.code}`);
} finally {
  await scp.shutdown(5);
}
```

`tests/readme-quickstart.test.ts` runs this block too.

## Source

- Scaffold: `.docs/scaffold/typescript.md`
- Standards: `.docs/standards/typescript.md`
- API sketch: `.docs/sketch.md`
