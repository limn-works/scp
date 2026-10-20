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
 * The type of a custody key: `"ed25519"`, `"x25519"`, `"p256"` (ECDSA P-256
 * signing) or `"hpke-p256"` (P-256 ECDH for HPKE). The same four strings as the
 * native SDK's `CustodyKeyType`.
 */
export type CustodyKeyType = "ed25519" | "x25519" | "p256" | "hpke-p256";

/**
 * On-device key custody — the driver's `Signer`
 * (`crates/scp-client-wasm/src/custody.rs`, `JsKeyCustody`), backed by WebCrypto.
 *
 * In this slice only {@link JsKeyCustody.did} has a driver call site (the bound
 * DID becomes the participant identity). `sign` / `getPublicKey` /
 * `generateKeypair` / `destroyKey` / `dhAgree` are the typed custody SEAM the
 * MLS-signing-key→WebCrypto move consumes next; they are declared so an
 * embedder satisfies the whole contract, but no driver signing call site exists
 * yet (the MLS key still lives in `scp-mls`, per the Rust module docs). The
 * browser default is {@link WebCryptoCustody}.
 *
 * This seam's shape is not the native host contract (`KeyCustodyProvider` in
 * the native SDK): {@link JsKeyCustody.getPublicKey} returns bare bytes with no
 * key type or role, and {@link JsKeyCustody.generateKeypair} takes no role. The
 * slice that wires a caller changes this seam to the native contract and routes
 * every call through the shared `scp_ffi_common::callback_custody` flows, so an
 * embedder written against this shape changes with it.
 */
export interface JsKeyCustody {
  /**
   * The participant's DID string (e.g. `did:dht:z6Mk…`). MUST throw if the
   * custody object has no bound identity (fail-closed — no anonymous default).
   */
  did(): string;

  /**
   * Signs `data` with the key identified by `keyId`, returning the signature
   * bytes. The private key never leaves the custody backend.
   *
   * An `"ed25519"` key signs `data` itself and returns the 64-byte signature.
   * A `"p256"` key receives the 32-byte digest as `data` and signs that digest
   * with no second SHA-256 (spec 09 §9.5.1), returning either the 64-byte raw
   * `r || s` or DER, with either `s`. The native bridges pass that result
   * through the shared `scp_ffi_common::callback_custody` flow, which
   * normalises it to low-`s` and verifies it strictly under the key's public
   * key. This browser seam has no Rust caller yet and checks nothing: a result
   * is not converted from DER, normalised or verified until the slice that
   * wires a caller routes it through that flow. An `"x25519"` or `"hpke-p256"`
   * key does not sign.
   *
   * The P-256 nonce rules, quoted from spec 09 §9.5:
   *
   * > A signer that runs in software, other than a platform signer, MUST
   * > derive its per-signature nonce deterministically under RFC 6979 with
   * > SHA-256.
   *
   * > A platform signer MAY draw its per-signature nonce from the operating
   * > system's random source in place of RFC 6979, and from no other source.
   * > A platform signer is one of two signers that the operating system
   * > provides and SCP's code does not implement. The first is Android
   * > Keystore at whatever security level the device provides, including the
   * > software Keystore of an emulator or a low-end device. The second is
   * > Apple's Security framework or CryptoKit on an Apple platform without a
   * > Secure Enclave, such as the Simulator or an Intel Mac without a T2 chip.
   *
   * §9.5 also states that a hardware signer draws its own nonce.
   *
   * Three facts about a WebCrypto P-256 key. §9.5 names two platform
   * signers, and WebCrypto is neither. WebCrypto does not specify RFC 6979,
   * and browsers draw randomized nonces. WebCrypto `ECDSA` hashes its input
   * and has no prehash mode, so a WebCrypto key cannot sign the 32-byte
   * digest this method receives as §9.5 requires. {@link WebCryptoCustody}
   * leaves this method failing closed.
   *
   * SEAM: no driver call site in this slice.
   */
  sign(keyId: string, data: Uint8Array): Uint8Array;

  /**
   * Raw public key bytes for `keyId`: 32 bytes for `"ed25519"` and
   * `"x25519"`, the 33-byte compressed SEC1 point for `"p256"`, and the
   * 65-byte uncompressed SEC1 point for `"hpke-p256"`. Throws if `keyId`
   * names no key; no error type or code is fixed for that throw until the
   * seam is wired. SEAM.
   */
  getPublicKey(keyId: string): Uint8Array;

  /**
   * Generates a keypair of type `keyType` (`"ed25519"`, `"x25519"`, `"p256"`
   * for ECDSA P-256 signing, or `"hpke-p256"` for P-256 ECDH under HPKE) and
   * returns its opaque `keyId`. SEAM.
   */
  generateKeypair(keyType: CustodyKeyType): string;

  /** Destroys the key identified by `keyId`, zeroing its material. Idempotent. SEAM. */
  destroyKey(keyId: string): void;

  /**
   * DH agreement against `peerPublic`, returning the 32-byte shared secret:
   * X25519 for an `"x25519"` key (32-byte peer key), P-256 ECDH for an
   * `"hpke-p256"` key (65-byte uncompressed SEC1 peer point; the secret is
   * the x-coordinate). An `"ed25519"` or `"p256"` key does not agree. Before
   * calling the host, the native bridges reject an X25519 peer that is not 32
   * bytes and a P-256 peer that is not a 65-byte uncompressed point on the
   * curve; after the call they reject a result that is not 32 bytes. This
   * browser seam has no Rust caller yet and validates neither the peer nor
   * the result. SEAM.
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
