/**
 * {@link WebCryptoCustody} — the browser-default {@link JsKeyCustody}: on-device
 * key custody backed by WebCrypto (`SubtleCrypto`), ADR-057 component 3.
 *
 * ## Security posture in this slice (READ THIS)
 *
 * The class NAME describes the #1980 target end-state, NOT the current release.
 * In THIS slice the MLS signing key still lives in `scp-mls` (wasm linear memory)
 * and is **EXTRACTABLE**. **Non-extractable on-device WebCrypto key custody is NOT
 * yet in effect** — it lands with #1980 (the MLS-signing-key → WebCrypto move).
 * Callers MUST NOT rely on WebCrypto non-extractability for signing-key protection
 * in this release: the signing key is not in WebCrypto and is not non-extractable.
 * The custody seams already fail closed (no false code-level guarantee), but the
 * NAME could mislead — hence this explicit statement.
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
 * for a key nobody uses. Key generation and binding are #1980's job.
 *
 * ## The `crypto.subtle` precondition is this type's OWN identity, not #1980
 *
 * `create()` requires a WebCrypto environment (`crypto.subtle`) to exist and
 * rejects (fail-closed) when it does not — the same way it rejects an empty DID.
 * This is a precondition of *what this type IS*, independent of #1980: a
 * `WebCryptoCustody` is, by definition, the WebCrypto-backed custody, so
 * constructing one where WebCrypto is absent is a contradiction. The check stands
 * on its own identity contract; it is NOT scaffolding that verifies WebCrypto "so
 * a later slice can wire it."
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
  /**
   * The `Crypto` implementation. Defaults to `globalThis.crypto`. Used for the
   * `crypto.subtle` presence check and as the injection point for tests /
   * non-standard hosts that supply their own `Crypto`.
   */
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
   * Fails closed on either of this custody's two construction preconditions: a
   * WebCrypto environment (`crypto.subtle`) must exist — a `WebCryptoCustody` is
   * WebCrypto-backed by definition, so its absence is a type-identity
   * contradiction, NOT a #1980 concern — and a non-empty DID must be provided.
   * This slice generates NO key (key generation is #1980's custody-model redesign;
   * see the module note); `did()` is the one live custody call.
   */
  static create(options: WebCryptoCustodyOptions): WebCryptoCustody {
    const crypto = options.crypto ?? globalThis.crypto;
    if (!crypto?.subtle) {
      throw new Error(
        "WebCrypto (crypto.subtle) is unavailable in this environment — a " +
          "WebCryptoCustody is WebCrypto-backed by definition and cannot be constructed " +
          "without it. Supply options.crypto or use a host that provides WebCrypto (fails closed).",
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
