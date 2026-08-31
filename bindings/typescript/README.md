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

```typescript
import { SCP } from "@limn-works/scp-ts";
import type { KeyCustodyProvider } from "@limn-works/scp-ts";

// Storage selection is required — there is no default (spec §17.6).
const scp = new SCP({ storage: { type: "in_memory" } });

// Create a cryptographic identity (DID). `keychain` is your own
// KeyCustodyProvider over the OS keystore — see "Key custody" below. On a
// released addon this call throws SCP-IDENT-1059 — read "No shipped build
// creates an identity yet" below before you run it.
declare const keychain: KeyCustodyProvider;
const identity = await scp.identityCreateWithCustody(keychain);
console.log(`DID: ${identity.did}`);

// Create an encrypted context
const ctx = await scp.contextCreate(
  identity,
  JSON.stringify({ ceiling: ["msg:send", "msg:receive"], ttl: 3600 }),
);

// Send a message (MLS-encrypted, signed, provenance-tagged)
await scp.contextSend(ctx, identity.did, new TextEncoder().encode("Hello from SCP"));

await scp.contextClose(ctx, identity.did);
await scp.shutdown(5);
```

## Key custody

Section 3.2.2 of the identity spec, "The Custody Vocabulary", states the two
values `CustodyType` carries. `"encrypted_file"` selects the on-disk key store
SCP implements, which derives the file key with Argon2id and encrypts
`$HOME/.scp/keys.bin` with AES-256-GCM; export `SCP_KEY_PASSPHRASE` before the
call or the addon throws a `ValidationError`. `"os_keystore"` selects the
operating system's own key store, which SCP reaches through the platform
key-custody callback you supply. Every other string throws a `ValidationError`
carrying `SCP-VALID-7005`, and that includes `"platform"`, `"software"`,
`"file"`, `"platform_managed"`, and `"hardware"`.

`scp.identityCreate("os_keystore")` throws an `IdentityError` carrying
`SCP-IDENT-1003`, because that call supplies no provider and the bridge falls
back to neither the encrypted key file nor an in-memory store. Reaching the
operating system's key store runs through `scp.identityCreateWithCustody(provider)`
instead. Implement the `KeyCustodyProvider` interface over the key store you
want — an OS keychain, a hardware token, an HSM wrapper — and the private key
material never crosses into the native core, because the core delegates every
cryptographic operation back to your callbacks (ADR-006, the platform
abstraction). That method is where a real platform backend lands, and it is the
only entry point that takes an injected provider.

An addon carrying the bridge's `testing` cargo feature additionally accepts the
raw string `"in_memory"`, which reaches the test-only in-memory key store. No
`CustodyType` member spells it, a test that needs it passes the raw string to
the bridge, and a released addon throws an `IdentityError` carrying
`SCP-IDENT-1008`.

## The published custody value

`scp.identityPublishedCustody(did)` returns the published-vocabulary custody
value for that DID's `#active` key, read off the backend running in this
process. Section 3.2.2 states that value as whether the key can leave its store
and which factor unlocks it: `"non-extractable-biometric"`,
`"non-extractable-pin"`, or `"extractable-passphrase"`. It returns `null` when
the backend holding the `#active` key reports a pair the published vocabulary
states no value for.

The bridge derives the value from the running backend, so the value states what
that backend reported: `KeyCustodyProvider.keyIsExtractable` and
`KeyCustodyProvider.unlockFactor` answer the two questions for an injected
provider, and the encrypted key file answers them for itself.

The call reads no DID document. Nothing SCP ships writes a custody attestation
into one — `ScpKeyCustodyAttestation::derive` and
`DidDocument::set_custody_attestation` have no caller outside tests — so a
stranger resolving the DID finds no custody service entry, and this call answers
only for an identity this instance created. Section 3.2.2.1 of the identity spec
records that as divergence D18, and its open question OQ-17 asks which component
writes the entry.

It throws an `IdentityError` carrying `SCP-IDENT-1001` for a DID this instance
retains no custody for, and the same code when the injected provider throws
while answering either question.

## No shipped build creates an identity yet

`identityCreateWithCustody` throws an `IdentityError` carrying `SCP-IDENT-1059`
on every released addon, and `identityCreate("encrypted_file")` throws it too
once `SCP_KEY_PASSPHRASE` is set. Section 9.7.4.1 of the security model,
pre-rotation key custody, makes every identity commit a pre-rotation commitment
when it is created. That commitment needs a `PreRotationCustody` backend, and
the only implementation is the test-harness `InMemoryPreRotationCustody`, which
the bridge's `testing` feature severs from
production, so `crates/scp-ffi/napi/src/scp.rs` returns the typed error rather
than minting the test double. ADR-062, capability injection and prove-absent
dev backends, records that state as accepted in its §Decision 6 and holds the
real backend out of its own scope. The Quick Start above therefore runs against
an addon built with the `testing` feature.

Two separate gaps produce those codes, and closing one does not close the
other. `SCP-IDENT-1003`, `SCP-IDENT-1008`, and `SCP-VALID-7005` say that the
custody value you passed names no key store this bridge builds. `SCP-IDENT-1059` says that no
pre-rotation custody backend exists for any create path to use. A wired
platform provider clears the first gap; a real pre-rotation backend clears the
second.

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
