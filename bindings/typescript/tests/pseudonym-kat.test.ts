/**
 * Byte-level Known-Answer Test (KAT) for cross-platform per-context pseudonym
 * derivation (spec §9.10.4.A, §25.19 vectors 30 & 31).
 *
 * Software-custody pseudonym derivation is cross-platform deterministic: every
 * SDK (Rust, Swift, Kotlin, TypeScript) MUST reproduce the exact public-key
 * bytes the spec pins for a given identity seed, `context_id`, and epoch
 * (§25.19). This test re-implements the canonical recipe in pure JS using
 * `node:crypto` and asserts the resulting bytes equal the spec literals — both
 * the static (v1) and rotatable (v2, epoch 1) keys.
 *
 * Canonical recipe (spec §25.19, matching `crates/scp-crypto/src/pseudonym.rs`):
 *   pseudonym_secret  = HKDF-SHA256(ikm = ed25519_seed, salt = "scp-pseudonym-secret-v1",
 *                                   info = "", len = 32)
 *   context_seed_v1   = HMAC-SHA256(secret, context_id || "scp-pseudonym")
 *   context_seed_v2   = HMAC-SHA256(secret, context_id || BE64(epoch) || "scp-pseudonym-v2")
 *   pseudonym_pub_key = Ed25519_keygen(context_seed[0..32]).public_key
 *
 * Pure JS — no native NAPI addon required — so it runs under plain `bun test`.
 * The fixture is the same `KeyCustodyProvider` shape the bridge drives, proving
 * the TS SDK's documented custody contract derives the canonical bytes.
 */

import { describe, expect, test } from "bun:test";
import * as crypto from "node:crypto";

import type { KeyCustodyProvider } from "../src/scp";

// 16-byte Ed25519 PKCS8 DER prefix; prepended to a 32-byte seed yields a valid
// PKCS8 encoding that `crypto.createPrivateKey` accepts (the OKP JWK import path
// would additionally require the public `x`, which we do not have yet).
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

const PSEUDONYM_SECRET_SALT = "scp-pseudonym-secret-v1";
const PSEUDONYM_V1_INFO = "scp-pseudonym";
const PSEUDONYM_V2_INFO = "scp-pseudonym-v2";

/**
 * Canonical software-custody fixture implementing {@link KeyCustodyProvider}.
 *
 * Keys are seeded deterministically via {@link storeSeed} so the KAT can pin a
 * known identity seed (§25.19 vectors) rather than a random one.
 */
class CanonicalKeychain implements KeyCustodyProvider {
  #seeds = new Map<string, Uint8Array>();
  #next = 1;

  /** Register a known 32-byte Ed25519 seed and return its opaque id. */
  storeSeed(seed: Uint8Array): string {
    const kid = String(this.#next++);
    this.#seeds.set(kid, new Uint8Array(seed));
    return kid;
  }

  generateKeypair(_keyType: string): string {
    const { privateKey } = crypto.generateKeyPairSync("ed25519");
    const jwk = privateKey.export({ format: "jwk" }) as { d: string };
    return this.storeSeed(new Uint8Array(Buffer.from(jwk.d, "base64url")));
  }

  #keyObjectFromSeed(seed: Uint8Array): crypto.KeyObject {
    const der = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]);
    return crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  }

  #publicKeyFromSeed(seed: Uint8Array): Buffer {
    const jwk = crypto.createPublicKey(this.#keyObjectFromSeed(seed)).export({ format: "jwk" }) as {
      x: string;
    };
    return Buffer.from(jwk.x, "base64url");
  }

  sign(keyId: string, message: Uint8Array): Uint8Array {
    return new Uint8Array(crypto.sign(null, Buffer.from(message), this.#keyObject(keyId)));
  }

  #keyObject(keyId: string): crypto.KeyObject {
    const seed = this.#seeds.get(keyId);
    if (seed === undefined) throw new Error(`unknown key id: ${keyId}`);
    return this.#keyObjectFromSeed(seed);
  }

  getPublicKey(keyId: string): Uint8Array {
    const seed = this.#seeds.get(keyId);
    if (seed === undefined) throw new Error(`unknown key id: ${keyId}`);
    return new Uint8Array(this.#publicKeyFromSeed(seed));
  }

  destroyKey(keyId: string): void {
    this.#seeds.delete(keyId);
  }

  dhAgree(keyId: string, peerPublic: Uint8Array): Uint8Array {
    // Not exercised by the KAT; a deterministic stand-in keeps the surface
    // complete (pseudonym derivation does not depend on it).
    const seed = this.#seeds.get(keyId) ?? new Uint8Array(32);
    return new Uint8Array(
      crypto
        .createHash("sha256")
        .update(Buffer.from(seed))
        .update(Buffer.from(peerPublic))
        .digest(),
    );
  }

  #pseudonymSecret(keyId: string): Buffer {
    const seed = this.#seeds.get(keyId);
    if (seed === undefined) throw new Error(`unknown key id: ${keyId}`);
    return Buffer.from(
      crypto.hkdfSync(
        "sha256",
        Buffer.from(seed),
        Buffer.from(PSEUDONYM_SECRET_SALT),
        Buffer.alloc(0),
        32,
      ),
    );
  }

  #registerContextSeed(contextSeed: Buffer): Uint8Array {
    const pub = this.#publicKeyFromSeed(contextSeed);
    const kid = String(this.#next++);
    this.#seeds.set(kid, new Uint8Array(contextSeed));
    return new Uint8Array(Buffer.concat([pub, Buffer.from(kid, "utf-8")]));
  }

  derivePseudonym(keyId: string, contextId: Uint8Array): Uint8Array {
    const data = Buffer.concat([Buffer.from(contextId), Buffer.from(PSEUDONYM_V1_INFO)]);
    const contextSeed = crypto
      .createHmac("sha256", this.#pseudonymSecret(keyId))
      .update(data)
      .digest();
    return this.#registerContextSeed(contextSeed);
  }

  deriveRotatablePseudonym(
    keyId: string,
    contextId: Uint8Array,
    pseudonymEpoch: bigint,
  ): Uint8Array {
    const be = Buffer.alloc(8);
    be.writeBigUInt64BE(pseudonymEpoch);
    const data = Buffer.concat([Buffer.from(contextId), be, Buffer.from(PSEUDONYM_V2_INFO)]);
    const contextSeed = crypto
      .createHmac("sha256", this.#pseudonymSecret(keyId))
      .update(data)
      .digest();
    return this.#registerContextSeed(contextSeed);
  }

  exportSigningKeyBytes(keyId: string): Uint8Array {
    const seed = this.#seeds.get(keyId);
    if (seed === undefined) throw new Error(`unknown key id: ${keyId}`);
    return new Uint8Array(seed);
  }

  custodyType(_keyId: string): string {
    return "software";
  }

  // This fixture keeps every seed in a process-memory map and hands it back
  // through `exportSigningKeyBytes`, so the key leaves the store, and nothing
  // gates that map. Section 3.2.2 of the identity spec states that a backend
  // reporting a pair the published vocabulary states no value for "publishes
  // no custody attestation at all".
  keyIsExtractable(_keyId: string): boolean {
    return true;
  }

  unlockFactor(_keyId: string): string {
    return "unprotected";
  }
}

// Extract the 32-byte public key from the `publicKey(32) || keyIdUtf8` blob the
// provider returns.
function pseudonymPublicKeyHex(blob: Uint8Array): string {
  return Buffer.from(blob.subarray(0, 32)).toString("hex");
}

// §25.19 context_id, shared by both vectors.
const CONTEXT_ALPHA = new Uint8Array(Buffer.from("context-alpha", "utf-8"));

// §25.19 vectors. Seeds and expected public keys taken verbatim from the spec.
interface Kat {
  name: string;
  seed: Uint8Array;
  v1: string;
  v2Epoch1: string;
}

const VECTORS: readonly Kat[] = [
  {
    name: "Vector 30 (seed 0x01 x 32)",
    seed: new Uint8Array(Buffer.alloc(32, 0x01)),
    v1: "fddc04882a48aa39888f6dbec622f9c5aa6f06b2e40820a69a2e0e89b5f09ac2",
    v2Epoch1: "43e50a947c4b2be44f871e309c7edc64afaf4207b9a589c9b01f61c01158090f",
  },
  {
    name: "Vector 31 (seed 0x9d,0x01..0x1f)",
    seed: new Uint8Array(
      Buffer.from("9d0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex"),
    ),
    v1: "ff6e2e909a008318f97bb2c26c1d787ceb9aa2996f746766335e10ba7e2213cc",
    v2Epoch1: "edd47319719e2350d1db9488e0189f2405267d7dc243489cfd9aa6f3ac3fc639",
  },
] as const;

describe("per-context pseudonym derivation KAT (§25.19)", () => {
  for (const vec of VECTORS) {
    test(`${vec.name}: v1 static pseudonym matches spec bytes`, () => {
      const kc = new CanonicalKeychain();
      const keyId = kc.storeSeed(vec.seed);
      const blob = kc.derivePseudonym(keyId, CONTEXT_ALPHA);
      expect(pseudonymPublicKeyHex(blob)).toBe(vec.v1);
    });

    test(`${vec.name}: v2 rotatable pseudonym (epoch 1) matches spec bytes`, () => {
      const kc = new CanonicalKeychain();
      const keyId = kc.storeSeed(vec.seed);
      const blob = kc.deriveRotatablePseudonym(keyId, CONTEXT_ALPHA, 1n);
      expect(pseudonymPublicKeyHex(blob)).toBe(vec.v2Epoch1);
    });

    test(`${vec.name}: v1 and v2 derive distinct keys`, () => {
      const kc = new CanonicalKeychain();
      const keyId = kc.storeSeed(vec.seed);
      const v1 = pseudonymPublicKeyHex(kc.derivePseudonym(keyId, CONTEXT_ALPHA));
      const v2 = pseudonymPublicKeyHex(kc.deriveRotatablePseudonym(keyId, CONTEXT_ALPHA, 1n));
      expect(v1).not.toBe(v2);
    });
  }
});
