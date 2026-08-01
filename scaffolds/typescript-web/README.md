# SCP TypeScript Web Scaffold

A minimal single-tab **in-browser** SCP participant over
[`@limn-works/scp-ts-wasm`](../../bindings/typescript-wasm). The full MLS protocol
runs in-tab, keys on-device — the browser is a real participant, not a remote thin
client (ADR-057). This scaffold is **structural**: it wires identity, storage, the
managed relay transport, a context, a `sendMessage` path, and a `drainEvents`
render loop, with no application logic on top (spec §21.12 — scaffolds are
structural, templates are functional).

## Prerequisites

- Bun 1.0+
- A running SCP relay (its `wss://` URL).
- A **pre-provisioned participant DID.** The wasm tier does **not** mint DIDs
  in-tab — create the DID with your identity flow (e.g. the native
  `@limn-works/scp-ts` tier or a `scp-node`) and paste it into the form.

## Build and run

The scaffold depends on the local `@limn-works/scp-ts-wasm` package via a
`file:` link, so build that package once first (it compiles the wasm and emits
`dist/`), then install and run the scaffold:

```bash
# 1. Build the local wasm SDK package (one-time; produces its dist/).
cd ../../bindings/typescript-wasm
bun install
bun run build

# 2. Install and run the scaffold.
cd ../../scaffolds/typescript-web
bun install
bun run dev      # Vite dev server
# or
bun run build    # production bundle (dist/)
```

Open the dev server URL, paste your DID, relay URL, and a context id, then
Connect. The activity log renders your own sent messages and any inbound
`MessageReceived` events the driver drains.

## What this does

1. Creates on-device **WebCrypto key custody** bound to your pre-provisioned DID
   (`WebCryptoCustody.create`).
2. Opens **IndexedDB storage** (`IndexedDbStorage.open`).
3. Connects the **managed WebSocket relay transport**
   (`ScpBrowserClient.connect`) — it wires the inbound pump and reconnect.
4. Creates a sole-member encrypted **context** (`createContext`).
5. Sends messages (`sendMessage`) and renders inbound events via a
   `drainEvents` polling loop.

## Deferred capabilities (honest absence)

This scaffold is deliberately single-tab and structural. The following are **not**
implemented here and are tracked under **#2187** and the package's own caveats:

- **No in-browser DID creation.** The wasm tier cannot mint a DID in-tab; you must
  pre-provision one. See ADR-057.
- **No cross-party invitation-join.** Relay-mediated native↔browser
  invitation-join / HPKE-open custody and the §9.7.1 DID-VM KeyPackage binding are
  deferred to **#2187**. `src/main.ts` marks the exact seam where the join wires
  once that lands (`generateKeyPackageForJoin` / `addMember` /
  `joinContextEncrypted`, which the package already exports). Because no second
  participant joins, `sendMessage` surfaces a retryable `SCP-CTX-2040` ("no peer
  pseudonym announced yet") — the scaffold reports this honestly rather than
  hiding it.
- **MLS signing key is currently extractable in the wasm tier.** Despite the
  `WebCryptoCustody` name, the MLS signing key still lives in wasm linear memory
  and is extractable pre-#1980 — do not rely on WebCrypto non-extractability for
  signing-key protection this release. See the
  [package caveats](../../bindings/typescript-wasm/README.md#caveats-as-built).

A functional two-party browser **chat template** (`templates/chat/typescript/`) is
forthcoming under **#2187**, once relay-mediated invitation-join is available.

## Next steps

- Provision DIDs and a relay for two browsers, then implement the #2187 join seam
  in `src/main.ts` to exchange messages across tabs.
- See [`bindings/typescript-wasm/examples/browser-roundtrip.ts`](../../bindings/typescript-wasm/examples/browser-roundtrip.ts)
  for the complete create → add → join → send → receive wiring.
