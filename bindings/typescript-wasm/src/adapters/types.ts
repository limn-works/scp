/**
 * The three platform-port interfaces the in-browser wasm client injects
 * (ADR-057 component 3). Each mirrors, VERBATIM, a `#[wasm_bindgen] extern "C"`
 * contract in `crates/scp-client-wasm/src/{socket,custody,storage}.rs`. They are
 * first-class exports so a Deno / Cloudflare Workers / `ws` / edge embedder can
 * supply its own implementation instead of the browser-default adapters — the
 * "no silent security defaults; the embedder injects the ports" model (D1/D4).
 *
 * Every method is SYNCHRONOUS: the wasm driver calls these ports inline under
 * `&mut self` and cannot await. The durable-store adapters bridge async backends
 * behind a synchronous in-memory mirror (see {@link JsStorage}).
 *
 * Fail-closed is the contract: a method that cannot honor its call MUST THROW
 * (surfaced as a typed `[SCP-…]` error at the client boundary), never return a
 * silent stand-in that masks the failure.
 */

/**
 * Outbound relay socket — the driver's `RelaySink`
 * (`crates/scp-client-wasm/src/socket.rs`, `JsSocket`).
 *
 * Outbound only: the driver never reads through it. Inbound relay frames flow
 * the other way, JS-pumped into `handleRelayFrame`. The browser default is
 * {@link WebSocketRelaySocket}.
 */
export interface JsSocket {
  /**
   * Writes one serialized relay `ClientMessage` frame to the socket.
   *
   * MUST throw if the frame cannot be enqueued (the socket is not OPEN, a
   * buffering fault). A thrown exception surfaces as `[SCP-TRANS-5005]` at the
   * client boundary; it MUST NOT silently drop the frame.
   */
  send(frame: Uint8Array): void;
}

/**
 * On-device key custody — the driver's `Signer`
 * (`crates/scp-client-wasm/src/custody.rs`, `JsKeyCustody`), backed by WebCrypto.
 *
 * In this slice only {@link JsKeyCustody.did} has a driver call site (the bound
 * DID becomes the participant identity). `sign` / `getPublicKey` /
 * `generateKeypair` / `destroyKey` / `dhAgree` are the typed custody SEAM the
 * MLS-signing-key→WebCrypto move (#1980) consumes next; they are declared so an
 * embedder satisfies the whole contract, but no driver signing call site exists
 * yet (the MLS key still lives in `scp-mls`, per the Rust module docs). The
 * browser default is {@link WebCryptoCustody}.
 */
export interface JsKeyCustody {
  /**
   * The participant's DID string (e.g. `did:dht:z6Mk…`). MUST throw if the
   * custody object has no bound identity (fail-closed — no anonymous default).
   */
  did(): string;

  /**
   * Signs `data` with the key identified by `keyId`, returning the signature
   * bytes. The private key never leaves the custody backend. SEAM (#1980): no
   * driver call site in this slice.
   */
  sign(keyId: string, data: Uint8Array): Uint8Array;

  /** Raw public key bytes for `keyId`. Throws if absent. SEAM (#1980). */
  getPublicKey(keyId: string): Uint8Array;

  /**
   * Generates a keypair of type `keyType` (`"ed25519"` / `"x25519"`) and
   * returns its opaque `keyId`. SEAM (#1980).
   */
  generateKeypair(keyType: string): string;

  /** Destroys the key identified by `keyId`, zeroing its material. Idempotent. SEAM (#1980). */
  destroyKey(keyId: string): void;

  /**
   * X25519 DH agreement against `peerPublic`, returning the 32-byte shared
   * secret. SEAM (#1980).
   */
  dhAgree(keyId: string, peerPublic: Uint8Array): Uint8Array;
}

/**
 * Key/value storage — the driver's `Storage`
 * (`crates/scp-client-wasm/src/storage.rs`, `JsStorage`).
 *
 * SYNCHRONOUS by contract, but a browser's durable store (IndexedDB) is async.
 * The mandated pattern: preload the `scp-client/*` keyspace into an in-memory
 * `Map` on init, serve get/set/delete/listKeys synchronously from it, and
 * write-behind each mutation to the durable store in FIFO order (a
 * crash-safety obligation — join/close ordering). A durable-write fault surfaces
 * on a LATER call as a throw (`[SCP-STORAGE-8010]`). The browser defaults are
 * {@link IndexedDbStorage} (durable) and {@link InMemoryStorage} (ephemeral).
 */
export interface JsStorage {
  /**
   * The value under `key`, or `undefined` if genuinely absent. MUST THROW on a
   * backend access fault — a fault is NOT "absent" (`undefined`); swallowing it
   * as absence would silently drop durable state and defeat fail-closed restore.
   */
  get(key: string): Uint8Array | undefined;

  /** Stores `value` under `key`, replacing any existing value. Throws on fault/quota. */
  set(key: string, value: Uint8Array): void;

  /** Removes the value under `key`. Idempotent. Throws on fault. */
  delete(key: string): void;

  /** Every key starting with `prefix`, in unspecified order. Throws on fault. */
  listKeys(prefix: string): string[];
}
