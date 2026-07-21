/**
 * {@link WebCryptoCustody} — the browser-default {@link JsKeyCustody}: on-device
 * key custody backed by WebCrypto (`SubtleCrypto`), ADR-057 component 3.
 *
 * ## What this slice wires, and what is a #1980 seam
 *
 * The driver's identity abstraction (`Signer`) only reads `did()` in this slice
 * — that is the ONE method with a driver call site. `did()` returns the bound
 * participant DID (created elsewhere and bound here) and is fully wired.
 *
 * `sign` / `getPublicKey` / `generateKeypair` / `dhAgree` are the typed custody
 * SEAM the MLS-signing-key→WebCrypto move (#1980) consumes next. They have NO
 * driver call site in this slice (the MLS signing key still lives in `scp-mls`,
 * per the Rust module docs), and WebCrypto's `SubtleCrypto` operations are
 * ASYNCHRONOUS — they cannot satisfy the driver's SYNCHRONOUS seam signature
 * today. So they FAIL CLOSED with a clear #1980 message rather than fabricate a
 * signature/secret: an honest "not yet wired" absence, never a stand-in that
 * masks a missing backend on a reachable path. When #1980 lands the custody port
 * (an async signing boundary), these route the real on-device key through
 * WebCrypto without a shape change on the caller.
 *
 * The identity key is generated **non-extractable** where the platform supports
 * it, so the private key never leaves WebCrypto — the design intent (ADR-022,
 * carried into ADR-057) the seam preserves.
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
  /**
   * An existing non-extractable identity keypair to bind, instead of generating
   * a fresh one. Supply this to reattach to a key already held on-device.
   */
  readonly identityKeyPair?: CryptoKeyPair;
}

/** The message thrown by every #1980 custody seam that has no driver call site yet. */
function unwiredSeam(method: string): Error {
  return new Error(
    `[#1980] WebCryptoCustody.${method} is a custody seam not wired in this slice — ` +
      "the MLS signing key lives in scp-mls and has no browser custody call site " +
      "(ADR-057 custody friction). WebCrypto's SubtleCrypto is asynchronous and " +
      "cannot satisfy the driver's synchronous seam today; it fails closed rather " +
      "than fabricate a value. The MLS-signing-key→WebCrypto move (#1980) wires it.",
  );
}

export class WebCryptoCustody implements JsKeyCustody {
  readonly #did: string;
  #identityKeyPair: CryptoKeyPair | undefined;

  private constructor(did: string, identityKeyPair: CryptoKeyPair | undefined) {
    this.#did = did;
    this.#identityKeyPair = identityKeyPair;
  }

  /**
   * Binds the participant DID and holds a non-extractable on-device identity key
   * in WebCrypto.
   *
   * Fails closed if WebCrypto (`crypto.subtle`) is unavailable or no DID is
   * bound — the two preconditions a real on-device custody requires.
   */
  static async create(options: WebCryptoCustodyOptions): Promise<WebCryptoCustody> {
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

    let keyPair = options.identityKeyPair;
    if (!keyPair) {
      // Non-extractable Ed25519 identity key: the private key never leaves
      // WebCrypto. If the platform lacks Ed25519 in WebCrypto, custody cannot be
      // backed as specified — fail closed rather than hold a weaker key silently.
      keyPair = (await crypto.subtle.generateKey({ name: "Ed25519" }, false, [
        "sign",
        "verify",
      ])) as CryptoKeyPair;
    }

    return new WebCryptoCustody(options.did, keyPair);
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
   * Drops the held identity key handle. Idempotent. The non-extractable private
   * key is released to WebCrypto's GC; there is no exportable material to zero.
   * (Synchronous and safe — unlike the async signing seams, this needs no
   * SubtleCrypto call, so it is genuinely wired even in this slice.)
   */
  destroyKey(_keyId: string): void {
    this.#identityKeyPair = undefined;
  }
}
