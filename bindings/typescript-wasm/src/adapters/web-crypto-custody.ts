/**
 * {@link WebCryptoCustody} — the browser-default {@link JsKeyCustody}: on-device
 * key custody backed by WebCrypto (`SubtleCrypto`), ADR-057 component 3.
 *
 * ## What this slice wires, and what lands with #1980
 *
 * The driver's identity abstraction (`Signer`) reads ONLY `did()` in this slice —
 * that is the single method with a driver call site. `did()` returns the bound
 * participant DID (created by the identity flow and bound here). That is all the
 * driver needs today, so this custody binds the DID and nothing else.
 *
 * On-device **key custody and signing land with #1980** (the MLS-signing-key →
 * WebCrypto move). Until then the MLS signing key lives in `scp-mls`, so
 * `sign` / `getPublicKey` / `generateKeypair` / `dhAgree` are typed custody SEAMS
 * with NO driver call site — and WebCrypto's `SubtleCrypto` is asynchronous, so it
 * cannot satisfy the driver's synchronous seam signature anyway. They FAIL CLOSED
 * with a clear #1980 message rather than fabricate a signature/secret: an honest
 * "not yet wired" absence, never a stand-in that masks a missing backend.
 *
 * This slice deliberately generates NO key: an eager `crypto.subtle.generateKey`
 * would (a) produce a key no code path consumes (the MLS key is in `scp-mls`),
 * (b) not be bound to the DID or persisted, and (c) throw on platforms without
 * WebCrypto Ed25519 (Safari <17-class) — breaking the `create({ did })` quickstart
 * for a key nobody uses. Key generation and binding are #1980's job; this slice
 * verifies WebCrypto is present (so #1980 can wire it) and binds the DID.
 */

import type { JsKeyCustody } from "./types";

/** Options for {@link WebCryptoCustody.create}. */
export interface WebCryptoCustodyOptions {
  /**
   * The participant DID this custody is bound to (e.g. `did:dht:z6Mk…`),
   * created by the identity flow and bound here. REQUIRED — no anonymous
   * default (fail-closed).
   */
  readonly did: string;
  /** The `Crypto` implementation. Defaults to `globalThis.crypto`. */
  readonly crypto?: Crypto;
}

/** The message thrown by every #1980 custody seam that has no driver call site yet. */
function unwiredSeam(method: string): Error {
  return new Error(
    `[#1980] WebCryptoCustody.${method} is a custody seam not wired in this slice — ` +
      "the MLS signing key lives in scp-mls and has no browser custody call site " +
      "(ADR-057 custody friction). WebCrypto's SubtleCrypto is asynchronous and " +
      "cannot satisfy the driver's synchronous seam today; it fails closed rather " +
      "than fabricate a value. On-device key custody + signing land with the " +
      "MLS-signing-key→WebCrypto move (#1980).",
  );
}

export class WebCryptoCustody implements JsKeyCustody {
  readonly #did: string;

  private constructor(did: string) {
    this.#did = did;
  }

  /**
   * Binds the participant DID.
   *
   * Fails closed if WebCrypto (`crypto.subtle`) is unavailable or no DID is
   * bound — the two preconditions on-device custody requires. This slice does
   * NOT generate a key (see the module note): key custody + signing land with
   * #1980; verifying WebCrypto is present is what lets that later slice wire it.
   */
  static create(options: WebCryptoCustodyOptions): WebCryptoCustody {
    const crypto = options.crypto ?? globalThis.crypto;
    if (!crypto?.subtle) {
      throw new Error(
        "WebCrypto (crypto.subtle) is unavailable in this environment — cannot back " +
          "on-device key custody. Supply options.crypto or use a host that provides WebCrypto (fails closed).",
      );
    }
    if (options.did.trim() === "") {
      throw new Error(
        "WebCryptoCustody requires a bound participant DID — none was provided (fails closed).",
      );
    }
    return new WebCryptoCustody(options.did);
  }

  /** The bound participant DID. Throws if unbound (fail-closed — no anonymous default). */
  did(): string {
    if (this.#did.trim() === "") {
      throw new Error("WebCryptoCustody has no bound DID identity (fails closed).");
    }
    return this.#did;
  }

  /** #1980 seam — no driver call site this slice; fails closed. */
  sign(_keyId: string, _data: Uint8Array): Uint8Array {
    throw unwiredSeam("sign");
  }

  /** #1980 seam — no driver call site this slice; fails closed. */
  getPublicKey(_keyId: string): Uint8Array {
    throw unwiredSeam("getPublicKey");
  }

  /** #1980 seam — no driver call site this slice; fails closed. */
  generateKeypair(_keyType: string): string {
    throw unwiredSeam("generateKeypair");
  }

  /** #1980 seam — no driver call site this slice; fails closed. */
  dhAgree(_keyId: string, _peerPublic: Uint8Array): Uint8Array {
    throw unwiredSeam("dhAgree");
  }

  /**
   * No-op in this slice: there is no held key material to destroy (key custody
   * lands with #1980). Kept to satisfy the {@link JsKeyCustody} contract;
   * idempotent and synchronous.
   */
  destroyKey(_keyId: string): void {
    // Intentionally empty — no key is held this slice.
  }
}
