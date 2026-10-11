# SCP TypeScript SDK Examples

Demonstrates identity creation and the context invite-and-join handshake in the
SCP TypeScript SDK.

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

Each example exports one async function that takes a `KeyCustodyProvider` and
a storage passphrase. The SDK ships no production key store for Bun or Node:
its one `CustodyType`, `"in_memory"`, works only with an addon built with the
`testing` feature, and a shipped addon rejects it with `SCP-IDENT-1008`. Pass a
provider backed by your own key store, such as an HSM or the operating
system's keychain:

```ts
import { identityExample } from "./identity";
import { contextExample } from "./context";

const passphrase = process.env.SCP_STORAGE_PASSPHRASE;
if (!passphrase) throw new Error("set SCP_STORAGE_PASSPHRASE");

await identityExample(myProvider, passphrase);
await contextExample(aliceProvider, bobProvider, passphrase);
```

## Examples

| File | Description |
|------|-------------|
| `identity.ts` | Create identity, resolve DID, inspect document, agent key management |
| `context.ts` | Create a context, reserve a KeyPackage, invite a member, join from the sealed invitation |

No example sends messages, registers outlets, or mints UCAN tokens. Every `SCP`
method that does, such as `contextSend`, `outletRegister` and `ucanMint`, takes
the context's bridge handle, and the `Context` object `contextCreate` returns
exposes that handle only through the internal `_rawHandle` field.

## Key Patterns

- **Server in-process**: On Bun/Node the SDK runs the protocol engine in-process via the napi-rs native addon. In the browser the full protocol runs in-tab via the sibling wasm tier `@limn-works/scp-ts-wasm`, keys on-device (ADR-057); a remote custodial thin client is an optional mode.
- **One `SCP` instance per node**: every operation is a method on `SCP`. Call
  `shutdown()` in a `finally` block.
- **Typed params**: build a `ContextParams` object and pass `JSON.stringify(params)`
  to `contextCreate`.
- **Error hierarchy**: `ScpError`, `ContextError`, `IdentityError`, and the other
  subclasses carry an `SCP-*` code.

## SDK Reference

- TypeScript SDK source: `bindings/typescript/src/`
- NAPI bridge: `crates/scp-ffi/napi/`
- Protocol spec: `.docs/specs/`
