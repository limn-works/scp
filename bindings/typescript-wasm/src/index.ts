/**
 * `@limn-works/scp-ts-wasm` — the in-browser Shared Context Protocol participant
 * SDK.
 *
 * The full MLS protocol runs in-tab over `scp-client-wasm`, keys on-device
 * (ADR-057). This is the wasm-mechanism tier of `@limn-works/scp-ts`: a
 * capability SUBSET — no governance, economy/payment, cross-context saga
 * coordination, media, DHT, or broadcast hosting (all behind the `scp-runtime`
 * scope fence). For that full surface, use the NAPI tier `@limn-works/scp-ts` on
 * Node/Bun. The two tiers share one developer API shape; you install exactly one.
 *
 * ## Quick start (browser)
 *
 * ```typescript
 * import { ScpBrowserClient, WebCryptoCustody, IndexedDbStorage } from "@limn-works/scp-ts-wasm";
 *
 * const custody = WebCryptoCustody.create({ did: myDid });
 * const storage = await IndexedDbStorage.open();
 * const client = await ScpBrowserClient.connect({ custody, storage, url: "wss://relay.example" });
 *
 * client.createContext("my-context");
 * // …add members, send, receive…
 * ```
 *
 * @packageDocumentation
 */

// Browser-default adapters (opt-in exports the embedder injects — NOT silent
// defaults; D1/D4 injected-port model).
export { InMemoryStorage } from "./adapters/in-memory-storage";
export { IndexedDbStorage, type IndexedDbStorageOptions } from "./adapters/indexeddb-storage";

// The three platform-port interfaces (embedders implement these to inject their
// own custody / storage / socket on Deno / Workers / edge).
export type { JsKeyCustody, JsSocket, JsStorage } from "./adapters/types";
export { WebCryptoCustody, type WebCryptoCustodyOptions } from "./adapters/web-crypto-custody";
export {
  type RelayPumpHandlers,
  type WebSocketLike,
  type WebSocketRelayReconnectOptions,
  WebSocketRelaySocket,
  type WebSocketRelaySocketOptions,
} from "./adapters/websocket-relay-socket";
// The client façade, one-time init, and the pure §5.4.5 outlet-stream invoker
// predicates (SCP-OUT-037 caveats/chunk + SCP-OUT-048 credit signing; cancel is
// node-delegated per ADR-057, see BrowserInvokerStreamSession).
export {
  type InitInput,
  initScp,
  isScpInitialized,
  type OutletStreamCreditPreimageParams,
  type OutletStreamSignCreditParams,
  outletStreamComputeCaveatsBinding,
  outletStreamComputeCreditPreimage,
  outletStreamSignCredit,
  outletStreamVerifyChunkSignature,
  ScpBrowserClient,
  type ScpBrowserClientCreateOptions,
  type ScpBrowserConnectOptions,
  scpVersion,
} from "./client";
// The branded, validating stream-credit grant (mirrors the native `Credit`).
export { Credit } from "./credit";
// The cross-SDK error hierarchy + prefix dispatch (single-sourced from the
// shared core, bundled in).
export {
  AttestationError,
  ContextError,
  CryptoError,
  EconomyError,
  GovernanceError,
  IdentityError,
  InvalidGrant,
  McpError,
  mapBridgeError,
  OutletError,
  ScpError,
  StorageError,
  TransportError,
  UcanPermissionError,
  ValidationError,
} from "./errors";
// The browser-invoker streaming-saga session (node-delegated coordination;
// in-tab signing + on-device decrypt/verify — ADR-057 scope fence, SCP-OUT-048).
export {
  BrowserInvokerStreamSession,
  type BrowserInvokerStreamSessionOptions,
  type NodeStreamCoordinator,
  type OutletStreamChunkView,
  type OutletStreamOpenRequest,
  type StreamAggregate,
} from "./outlet-stream-session";
// Flat result types.
export type {
  AddMemberOutput,
  ContextStatus,
  OutletStreamCredit,
  ReceivedEvent,
  ReceiveOutput,
  SenderKeyDistribution,
} from "./types";
