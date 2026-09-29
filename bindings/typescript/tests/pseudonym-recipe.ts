/**
 * Canonical software-custody pseudonym derivation (spec §9.10.4.A, §25.19).
 *
 * Test-only reference that gives the custody fixtures the context seeds and
 * the P-256 helper tests an independent prehash signer. HMAC/HKDF come from `node:crypto`; `d * G` comes from
 * `createECDH("prime256v1")`; prehash ECDSA is RFC 6979 with BigInt modular
 * arithmetic, because node has no API that signs a digest without hashing it
 * again. Nothing here is constant-time.
 *
 *   pseudonym_secret = HKDF-SHA256(ikm, salt = "scp-pseudonym-secret-v1", info = "", 32)
 *   seed_v1 = HMAC-SHA256(secret, context_id || "scp-pseudonym")
 *   seed_v2 = HMAC-SHA256(secret, context_id || BE64(epoch) || "scp-pseudonym-v2")
 *   d = int(HKDF-Expand-SHA256(prk = seed, info = "SCP-PSEUDONYM-P256-V1", 48)) mod (n - 1) + 1
 *   public_key = SEC1-compressed(d * G)                     (33 bytes)
 *
 * `d` and `public_key` come from the production helpers `p256PseudonymScalar`
 * and `p256PublicKey`; this module signs with a given `d`.
 */

import * as crypto from "node:crypto";

export const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

const PSEUDONYM_SECRET_SALT = "scp-pseudonym-secret-v1";
const PSEUDONYM_V1_INFO = "scp-pseudonym";
const PSEUDONYM_V2_INFO = "scp-pseudonym-v2";

export function bytesToBigInt(bytes: Uint8Array): bigint {
  return bytes.length === 0 ? 0n : BigInt(`0x${Buffer.from(bytes).toString("hex")}`);
}

export function bigIntTo32(x: bigint): Buffer {
  return Buffer.from(x.toString(16).padStart(64, "0"), "hex");
}

function hmac256(key: Uint8Array, data: Uint8Array): Buffer {
  return crypto.createHmac("sha256", key).update(data).digest();
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

function pointOf(d: bigint, format: "compressed" | "uncompressed"): Buffer {
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.setPrivateKey(bigIntTo32(d));
  return ecdh.getPublicKey(null, format);
}

/** RFC 6979 §3.2 nonce for P-256 with HMAC-SHA-256. */
function rfc6979Nonce(d: bigint, digest: Uint8Array): bigint {
  const x = bigIntTo32(d);
  const h = bigIntTo32(bytesToBigInt(digest) % P256_N);
  let v: Buffer = Buffer.alloc(32, 0x01);
  let k: Buffer = Buffer.alloc(32, 0x00);
  k = hmac256(k, Buffer.concat([v, Buffer.from([0x00]), x, h]));
  v = hmac256(k, v);
  k = hmac256(k, Buffer.concat([v, Buffer.from([0x01]), x, h]));
  v = hmac256(k, v);
  for (;;) {
    v = hmac256(k, v);
    const candidate = bytesToBigInt(v);
    if (candidate >= 1n && candidate < P256_N) return candidate;
    k = hmac256(k, Buffer.concat([v, Buffer.from([0x00])]));
    v = hmac256(k, v);
  }
}

/** Sign a 32-byte digest with no second hash: 64-byte low-s `r || s` (§9.5.1). */
export function p256SignPrehash(d: bigint, digest: Uint8Array): Uint8Array {
  if (digest.length !== 32) throw new Error(`prehash must be 32 bytes, got ${digest.length}`);
  const z = bytesToBigInt(digest);
  const k = rfc6979Nonce(d, digest);
  const r = bytesToBigInt(pointOf(k, "uncompressed").subarray(1, 33)) % P256_N;
  let s = (modPow(k, P256_N - 2n, P256_N) * (z + r * d)) % P256_N;
  if (s > P256_N / 2n) s = P256_N - s;
  return new Uint8Array(Buffer.concat([bigIntTo32(r), bigIntTo32(s)]));
}

/** The 32-byte `pseudonym_secret` of the identity key material `ikm`. */
export function pseudonymSecret(ikm: Uint8Array): Buffer {
  return Buffer.from(
    crypto.hkdfSync(
      "sha256",
      Buffer.from(ikm),
      Buffer.from(PSEUDONYM_SECRET_SALT),
      Buffer.alloc(0),
      32,
    ),
  );
}

/** The v1 (static) 32-byte context seed. */
export function pseudonymSeedV1(ikm: Uint8Array, contextId: Uint8Array): Buffer {
  return hmac256(
    pseudonymSecret(ikm),
    Buffer.concat([Buffer.from(contextId), Buffer.from(PSEUDONYM_V1_INFO)]),
  );
}

/** The v2 (rotatable) 32-byte context seed for `epoch`. */
export function pseudonymSeedV2(ikm: Uint8Array, contextId: Uint8Array, epoch: bigint): Buffer {
  const be = Buffer.alloc(8);
  be.writeBigUInt64BE(epoch);
  return hmac256(
    pseudonymSecret(ikm),
    Buffer.concat([Buffer.from(contextId), be, Buffer.from(PSEUDONYM_V2_INFO)]),
  );
}
