/**
 * Real P-256 ECDH for the test custody providers' `hpke-p256` keys, over
 * `crypto.createECDH("prime256v1")`.
 *
 * The bridge hands `dhAgree` the 65-byte uncompressed peer point (RFC 9180
 * §7.1.1) and expects the 32-byte x-coordinate of the shared point, which is
 * what `ECDH.computeSecret` returns. `computeSecret` throws on a peer that is
 * not a point on the curve.
 *
 * The RFC 5903 §8.1 vector below is the one `scp_crypto::p256::testing`
 * pins (`ECDH_VECTOR_*`); the TypeScript fakes are checked against the same
 * hex.
 */

import * as crypto from "node:crypto";

import { KeyNotFoundError } from "../src/errors";

/** RFC 5903 §8.1 initiator private scalar. */
export const ECDH_VECTOR_SCALAR_I =
  "c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433";
/** RFC 5903 §8.1 responder private scalar. */
export const ECDH_VECTOR_SCALAR_R =
  "c6ef9c5d78ae012a011164acb397ce2088685d8f06bf9be0b283ab46476bee53";
/** RFC 5903 §8.1 initiator public point, uncompressed. */
export const ECDH_VECTOR_PUBLIC_I =
  "04dad0b65394221cf9b051e1feca5787d098dfe637fc90b9ef945d0c37725811805271a0461cdb8252d61f1c456fa3e59ab1f45b33accf5f58389e0577b8990bb3";
/** RFC 5903 §8.1 responder public point, uncompressed. */
export const ECDH_VECTOR_PUBLIC_R =
  "04d12dfb5289c8d4f81208b70270398c342296970a0bccb74c736fc7554494bf6356fbf3ca366cc23e8157854c13c58d6aac23f046ada30f8353e74f33039872ab";
/** RFC 5903 §8.1 shared x-coordinate. */
export const ECDH_VECTOR_SHARED_X =
  "d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de";

/** `hpke-p256` private scalars by key id. */
export class HpkeP256Keys {
  #scalars = new Map<string, Buffer>();

  /** Mints a fresh scalar under `keyId`. */
  generate(keyId: string): void {
    const ecdh = crypto.createECDH("prime256v1");
    ecdh.generateKeys();
    this.#scalars.set(keyId, ecdh.getPrivateKey());
  }

  has(keyId: string): boolean {
    return this.#scalars.has(keyId);
  }

  delete(keyId: string): void {
    this.#scalars.get(keyId)?.fill(0);
    this.#scalars.delete(keyId);
  }

  #ecdh(keyId: string): crypto.ECDH {
    const scalar = this.#scalars.get(keyId);
    if (scalar === undefined) throw new KeyNotFoundError(`unknown key id: ${keyId}`);
    const ecdh = crypto.createECDH("prime256v1");
    ecdh.setPrivateKey(scalar);
    return ecdh;
  }

  /** The 65-byte uncompressed public point. */
  publicKey(keyId: string): Uint8Array {
    return new Uint8Array(this.#ecdh(keyId).getPublicKey());
  }

  /** The 32-byte shared x-coordinate with a 65-byte uncompressed peer. */
  agree(keyId: string, peerPublic: Uint8Array): Uint8Array {
    if (peerPublic.length !== 65 || peerPublic[0] !== 0x04) {
      throw new Error(
        `hpke-p256 peer must be a 65-byte uncompressed point, got ${peerPublic.length} bytes`,
      );
    }
    return new Uint8Array(this.#ecdh(keyId).computeSecret(Buffer.from(peerPublic)));
  }
}
