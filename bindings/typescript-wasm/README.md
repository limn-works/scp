# SCP TypeScript SDK — browser (wasm) tier

> `@limn-works/scp-ts-wasm` — the in-browser Shared Context Protocol participant client.

The full SCP/MLS protocol runs **in-tab**, keys **on-device** — the browser is a real
participant, not a remote thin client (ADR-057, which amends ADR-055's earlier
remote-thin-client browser model). This is the **wasm-mechanism tier** of
[`@limn-works/scp-ts`](../typescript): a capability **subset** with no governance,
economy/payment, cross-context saga coordination, media, DHT, or broadcast hosting
(all behind the `scp-runtime` scope fence). For that full surface, use
`@limn-works/scp-ts` on Node/Bun.

Install exactly one tier for your environment:

```bash
bun add @limn-works/scp-ts-wasm   # browser / Deno / Workers / edge
# or
bun add @limn-works/scp-ts        # Node / Bun (full capability)
```

The package is self-contained: it bundles its own copy of the shared core and ships
the `.wasm` as a dist sibling. There is no runtime peer dependency and no transparent
native→wasm fallback — the reduced tier is a deliberate, legible choice.

## Quick start

```typescript
import { ScpBrowserClient, WebCryptoCustody, IndexedDbStorage } from "@limn-works/scp-ts-wasm";

// On-device key custody (WebCrypto) + durable storage (IndexedDB) are explicit,
// injected ports — the SDK never reaches for a hidden default. `did` comes from
// your identity flow.
const custody = WebCryptoCustody.create({ did: myDid });
const storage = await IndexedDbStorage.open();

// The managed transport wires the inbound pump + reconnect: on every (re)open it
// re-drives SUBSCRIBEs (resubscribeAll); on every relay frame it feeds
// handleRelayFrame; on drop it reconnects with backoff.
const client = await ScpBrowserClient.connect({
  custody,
  storage,
  url: "wss://relay.example",
  onError: (err) => console.error(`[scp] ${err.code}:`, err.message),
});

client.createContext("my-context");
// …add members, exchange sender keys, send, receive…
```

A complete two-party wiring (create → add → join → sender-key exchange → send →
receive) is in [`examples/browser-roundtrip.ts`](./examples/browser-roundtrip.ts).

## Ports (embedder-supplied)

`ScpBrowserClient` takes three injected ports; the browser defaults are exported, and a
Deno / Cloudflare Workers / `ws` / edge embedder can supply its own implementation of
the first-class `JsSocket` / `JsKeyCustody` / `JsStorage` interfaces:

| Port | Browser default | Notes |
|------|-----------------|-------|
| Socket | `WebSocketRelaySocket` | outbound relay sink + inbound pump + reconnect |
| Custody | `WebCryptoCustody` | binds the DID (`did()`); signing lands with #1980 |
| Storage | `IndexedDbStorage` (durable) / `InMemoryStorage` (ephemeral) | `InMemoryStorage` is a legitimate ephemeral choice, not a stand-in |

### Bring your own socket (`create`)

`ScpBrowserClient.create({ custody, storage, socket })` is the bring-your-own-`JsSocket`
path — for a Deno / Workers / `ws` embedder. You own the inbound pump. Do NOT pass the
managed `WebSocketRelaySocket` here (it would never get attached — `create()` throws
`SCP-VALID-7026` telling you to use `connect()`); instead wire your own socket's
`onmessage` → `handleRelayFrame` and `onopen` → `resubscribeAll`:

```typescript
const ws = new WebSocket("wss://relay.example");
ws.binaryType = "arraybuffer";

// A JsSocket is just `{ send(frame: Uint8Array): void }` — throw when not open so
// the client surfaces SCP-TRANS-5010 rather than silently dropping a frame.
const socket = {
  send(frame: Uint8Array) {
    if (ws.readyState !== WebSocket.OPEN) throw new Error("relay socket not open");
    ws.send(frame);
  },
};

const client = ScpBrowserClient.create({ custody, storage, socket });

// You own the pump:
ws.onopen = () => client.resubscribeAll();                  // on EVERY (re)open
ws.onmessage = (evt) => client.handleRelayFrame(new Uint8Array(evt.data as ArrayBuffer));
```

## Caveats (as-built)

- **Non-extractable on-device key custody is NOT yet in effect (lands with #1980).** Despite
  the `WebCryptoCustody` name, in this release the MLS signing key still lives in `scp-mls`
  (wasm linear memory) and is **extractable** — it is not held in non-extractable WebCrypto
  storage. Do NOT rely on WebCrypto non-extractability for signing-key protection this
  release; that property arrives with the MLS-signing-key → WebCrypto move (#1980).
- **Native↔browser invitation join / HPKE-open custody is deferred to #1980.** Opening an
  `InvitationBundle` needs a DH against the invitee's on-device custody key, which the
  browser does not hold pre-#1980. `WebCryptoCustody`'s `sign` / `dhAgree` /
  `getPublicKey` / `generateKeypair` are typed custody **seams that fail closed** (no
  driver call site this slice) — an honest absence, never a stand-in. `did()` is the one
  wired custody call.
- **Same-human native↔browser pseudonym equality does not hold pre-#1980** (the browser
  keys on the per-context MLS key, native on the identity key). Cross-target *algorithm*
  determinism holds and is KAT-pinned (ADR-057 A1).
- **Fail-closed decrypt rests on the `--release` build** (ADR-057 Prereq-4): the shipped
  wasm is always built `--release` so openmls's decrypt `debug_assert!` is compiled out
  and a tampered ciphertext surfaces a typed `[SCP-CRYPTO-4010]` error, not a tab-abort.

## License

Apache-2.0. See [LICENSE](./LICENSE).
