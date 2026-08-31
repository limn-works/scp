/**
 * Integration test for `SCP.identityCreateWithCustody` (ADR-006).
 *
 * Exercises the caller-provided {@link KeyCustodyProvider} path end-to-end on
 * the NAPI backend: a JS custody object backed by Node/Bun's built-in Ed25519
 * (`node:crypto`) generates a real keypair, the native bridge drives
 * `DidDht::create` against it (signing the DID document through the provider's
 * `sign` callback via threadsafe functions), and the resulting `Identity`
 * carries a `did:dht:` value plus the provider-derived verifying key.
 *
 * The keys are real Ed25519: `DidDht::create` self-certifies the document, so a
 * fake signature would fail document validation — this proves the full callback
 * contract (generateKeypair → getPublicKey → sign), not just argument plumbing.
 *
 * Skips when the platform NAPI addon is not built/installed (the `SCP` class
 * probe fails), matching `real-napi.test.ts`.
 */

import { describe, expect, test } from "bun:test";
import * as crypto from "node:crypto";

import type { KeyCustodyProvider } from "../src/scp";
import { SCP } from "../src/scp";

// ---------------------------------------------------------------------------
// Probe: is the NAPI-backed SCP class available in this environment?
// ---------------------------------------------------------------------------

let scpAvailable = false;
let skipReason = "";
try {
  const probe = new SCP({ storage: { type: "in_memory" } });
  scpAvailable = true;
  probe.shutdown(1).catch(() => {});
} catch (e: unknown) {
  skipReason = `NAPI SCP class not available: ${e instanceof Error ? e.message : String(e)}`;
}

// ---------------------------------------------------------------------------
// Real-Ed25519 custody provider backed by node:crypto
// ---------------------------------------------------------------------------

class CryptoKeychain implements KeyCustodyProvider {
  #seeds = new Map<string, Uint8Array>();
  #next = 1;

  generateKeypair(_keyType: string): string {
    const { privateKey } = crypto.generateKeyPairSync("ed25519");
    const jwk = privateKey.export({ format: "jwk" }) as { d: string };
    const kid = String(this.#next++);
    this.#seeds.set(kid, new Uint8Array(Buffer.from(jwk.d, "base64url")));
    return kid;
  }

  // Reconstruct an Ed25519 private key from a raw 32-byte seed via the standard
  // PKCS8 DER encoding. Node's OKP JWK import requires the public `x` too; the
  // PKCS8 form needs only the seed.
  #keyObjectFromSeed(seed: Uint8Array): crypto.KeyObject {
    const der = Buffer.concat([
      // 16-byte Ed25519 PKCS8 prefix + 32-byte seed = valid PKCS8 DER.
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.from(seed),
    ]);
    return crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  }

  #keyObject(keyId: string): crypto.KeyObject {
    const seed = this.#seeds.get(keyId);
    if (seed === undefined) throw new Error(`unknown key id: ${keyId}`);
    return this.#keyObjectFromSeed(seed);
  }

  sign(keyId: string, message: Uint8Array): Uint8Array {
    return new Uint8Array(crypto.sign(null, Buffer.from(message), this.#keyObject(keyId)));
  }

  getPublicKey(keyId: string): Uint8Array {
    const pub = crypto.createPublicKey(this.#keyObject(keyId));
    const jwk = pub.export({ format: "jwk" }) as { x: string };
    return new Uint8Array(Buffer.from(jwk.x, "base64url"));
  }

  destroyKey(keyId: string): void {
    this.#seeds.delete(keyId);
  }

  dhAgree(keyId: string, peerPublic: Uint8Array): Uint8Array {
    // Not exercised by identity creation; a deterministic stand-in keeps the
    // protocol surface complete.
    const seed = this.#seeds.get(keyId) ?? new Uint8Array(32);
    const h = crypto.createHash("sha256");
    h.update(Buffer.from(seed));
    h.update(Buffer.from(peerPublic));
    return new Uint8Array(h.digest());
  }

  // Canonical per-context pseudonym secret (spec §9.10.4.A / §25.19):
  //   pseudonym_secret = HKDF-SHA256(ikm = seed, salt = "scp-pseudonym-secret-v1",
  //                                  info = "", len = 32)
  #pseudonymSecret(keyId: string): Buffer {
    const seed = this.#seeds.get(keyId);
    if (seed === undefined) throw new Error(`unknown key id: ${keyId}`);
    return Buffer.from(
      crypto.hkdfSync(
        "sha256",
        Buffer.from(seed),
        Buffer.from("scp-pseudonym-secret-v1"),
        Buffer.alloc(0),
        32,
      ),
    );
  }

  // Register a derived 32-byte context seed as a fresh signing key and return
  // `publicKey(32) || keyIdUtf8` — the wire layout the native bridge unpacks.
  #pseudonymFromContextSeed(contextSeed: Buffer): Uint8Array {
    const pubJwk = crypto
      .createPublicKey(this.#keyObjectFromSeed(contextSeed))
      .export({ format: "jwk" }) as { x: string };
    const pub = Buffer.from(pubJwk.x, "base64url");
    const kid = String(this.#next++);
    this.#seeds.set(kid, new Uint8Array(contextSeed));
    return new Uint8Array(Buffer.concat([pub, Buffer.from(kid, "utf-8")]));
  }

  derivePseudonym(keyId: string, contextId: Uint8Array): Uint8Array {
    // v1 (static): context_seed = HMAC-SHA256(secret, context_id || "scp-pseudonym")
    const data = Buffer.concat([Buffer.from(contextId), Buffer.from("scp-pseudonym")]);
    const contextSeed = crypto
      .createHmac("sha256", this.#pseudonymSecret(keyId))
      .update(data)
      .digest();
    return this.#pseudonymFromContextSeed(contextSeed);
  }

  deriveRotatablePseudonym(
    keyId: string,
    contextId: Uint8Array,
    pseudonymEpoch: bigint,
  ): Uint8Array {
    // v2 (rotatable): context_seed = HMAC-SHA256(
    //   secret, context_id || BE64(epoch) || "scp-pseudonym-v2")
    const be = Buffer.alloc(8);
    be.writeBigUInt64BE(pseudonymEpoch);
    const data = Buffer.concat([Buffer.from(contextId), be, Buffer.from("scp-pseudonym-v2")]);
    const contextSeed = crypto
      .createHmac("sha256", this.#pseudonymSecret(keyId))
      .update(data)
      .digest();
    return this.#pseudonymFromContextSeed(contextSeed);
  }

  exportSigningKeyBytes(keyId: string): Uint8Array {
    const seed = this.#seeds.get(keyId);
    if (seed === undefined) throw new Error(`unknown key id: ${keyId}`);
    return seed;
  }

  custodyType(_keyId: string): string {
    return "software";
  }

  // This double keeps every seed in `#seeds` and hands it back through
  // `exportSigningKeyBytes`, so the key leaves the store.
  keyIsExtractable(_keyId: string): boolean {
    return true;
  }

  // Nothing gates `#seeds`: no biometric reading, no PIN, no passphrase.
  // Section 3.2.2 of the identity spec states that a backend reporting a pair
  // the published vocabulary states no value for "publishes no custody
  // attestation at all", and (extractable, unprotected) is such a pair.
  unlockFactor(_keyId: string): string {
    return "unprotected";
  }
}

// A keychain that signs but REFUSES to export raw key bytes — the shape of a
// real OS keychain / HSM / secure-enclave custody. `exportSigningKeyBytes`
// throws, so any operation that depends on extracting the raw private key would
// fail; only operations routed through the `sign` callback can succeed.
class SignOnlyKeychain extends CryptoKeychain {
  override exportSigningKeyBytes(_keyId: string): Uint8Array {
    throw new Error("sign-only custody: raw key export is not permitted");
  }

  // A store that refuses raw export holds a key that cannot leave it.
  override keyIsExtractable(_keyId: string): boolean {
    return false;
  }

  // This double stands in for an OS keychain that releases key material only
  // after a biometric reading, which is the pair section 3.2.2 of the identity
  // spec publishes as `"non-extractable-biometric"`.
  override unlockFactor(_keyId: string): string {
    return "biometric";
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

if (!scpAvailable) {
  describe("identityCreateWithCustody (SKIPPED)", () => {
    test.skip(`native NAPI addon unavailable: ${skipReason}`, () => {});
  });
} else {
  describe("SCP.identityCreateWithCustody (real NAPI)", () => {
    test("creates a did:dht identity backed by a JS custody provider", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
      try {
        const provider = new CryptoKeychain();
        const identity = await scp.identityCreateWithCustody(provider);
        expect(identity.did).toMatch(/^did:dht:/);
        expect(identity.custodyType).toBe("os_keystore");
      } finally {
        await scp.shutdown(1000).catch(() => {});
      }
    });

    test("rejects a provider missing required methods", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
      try {
        // Intentionally incomplete — only `sign` is present.
        const bad = { sign: () => new Uint8Array(64) } as unknown as KeyCustodyProvider;
        await expect(scp.identityCreateWithCustody(bad)).rejects.toThrow();
      } finally {
        await scp.shutdown(1000).catch(() => {});
      }
    });

    // Spec §23.16.8 / ADR-050: a context created under callback (platform)
    // custody must be able to produce an Ed25519-signed export whose snapshot
    // signature verifies on import. Export signing is delegated to the custody
    // `sign` callback — NOT to raw key export — so a callback identity reaches
    // parity with an in-memory one for signed export/import.
    test("callback-custody identity exports a signed snapshot that imports", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
      try {
        const identity = await scp.identityCreateWithCustody(new CryptoKeychain());
        const ctx = await scp.contextCreate(
          identity,
          JSON.stringify({
            ceiling: ["messages:read", "context:close"],
            memoryScope: "ephemeral",
          }),
        );

        const data = await scp.contextExport(ctx._rawHandle);
        expect(data.length).toBeGreaterThan(0);

        // Close so import_context sees a terminal state and allows reimport.
        await scp.contextClose(ctx._rawHandle, identity.did);

        // Import verifies the snapshot signature against the creator's #active
        // verifying key. Success proves the callback-custody-produced signature
        // is spec-valid.
        const importedContextId = await scp.contextImport(data, identity.did);
        expect(typeof importedContextId).toBe("string");
        expect(importedContextId.length).toBeGreaterThan(0);
      } finally {
        await scp.shutdown(1000).catch(() => {});
      }
    });

    // The decisive regression guard: with a custody that signs but REFUSES to
    // export raw key bytes (the keychain/HSM shape), export still succeeds
    // because signing is routed through `KeyCustody::sign`. Under the previous
    // raw-key-extraction path this export would have failed with an
    // exportSigningKeyBytes error.
    test("sign-only (no raw-key-export) custody can still produce a signed export", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
      try {
        const identity = await scp.identityCreateWithCustody(new SignOnlyKeychain());
        const ctx = await scp.contextCreate(
          identity,
          JSON.stringify({
            ceiling: ["messages:read", "context:close"],
            memoryScope: "ephemeral",
          }),
        );

        // Must NOT throw: signing the §23.16.8 digest goes through the `sign`
        // callback, never through the throwing `exportSigningKeyBytes`.
        const data = await scp.contextExport(ctx._rawHandle);
        expect(data.length).toBeGreaterThan(0);

        await scp.contextClose(ctx._rawHandle, identity.did);

        const importedContextId = await scp.contextImport(data, identity.did);
        expect(typeof importedContextId).toBe("string");
        expect(importedContextId.length).toBeGreaterThan(0);
      } finally {
        await scp.shutdown(1000).catch(() => {});
      }
    });
  });
}
