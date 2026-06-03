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
 * probe fails), matching `real-napi.test.ts`. The browser/WASM build does not
 * expose the `SCP` class at all (ADR-034 / ADR-048).
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
  const probe = new SCP();
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

  #keyObject(keyId: string): crypto.KeyObject {
    const seed = this.#seeds.get(keyId);
    if (seed === undefined) throw new Error(`unknown key id: ${keyId}`);
    // Reconstruct an Ed25519 private key from the raw 32-byte seed via the
    // standard PKCS8 DER encoding. Node's OKP JWK import requires the public
    // `x` too; the PKCS8 form needs only the seed.
    const der = Buffer.concat([
      // 16-byte Ed25519 PKCS8 prefix + 32-byte seed = valid PKCS8 DER.
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.from(seed),
    ]);
    const priv = crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    return priv;
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

  derivePseudonym(keyId: string, contextId: Uint8Array): Uint8Array {
    const seed = this.#seeds.get(keyId) ?? new Uint8Array(32);
    const h = crypto.createHash("sha256");
    h.update(Buffer.from(seed));
    h.update(Buffer.from(contextId));
    const pseudoSeed = h.digest(); // 32 bytes
    // Reconstruct the derived Ed25519 key from the seed via PKCS8 DER (the OKP
    // JWK import path requires the public `x`; PKCS8 needs only the seed).
    const der = Buffer.concat([
      // 16-byte Ed25519 PKCS8 prefix + 32-byte seed = valid PKCS8 DER.
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.from(pseudoSeed),
    ]);
    const priv = crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    const pubJwk = crypto.createPublicKey(priv).export({ format: "jwk" }) as { x: string };
    const pub = Buffer.from(pubJwk.x, "base64url");
    const kid = String(this.#next++);
    this.#seeds.set(kid, new Uint8Array(pseudoSeed));
    return new Uint8Array(Buffer.concat([pub, Buffer.from(kid, "utf-8")]));
  }

  exportSigningKeyBytes(keyId: string): Uint8Array {
    const seed = this.#seeds.get(keyId);
    if (seed === undefined) throw new Error(`unknown key id: ${keyId}`);
    return seed;
  }

  custodyType(_keyId: string): string {
    return "software";
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
      const scp = new SCP();
      try {
        const provider = new CryptoKeychain();
        const identity = await scp.identityCreateWithCustody(provider);
        expect(identity.did).toMatch(/^did:dht:/);
        expect(identity.custodyType).toBe("callback");
      } finally {
        await scp.shutdown(1000).catch(() => {});
      }
    });

    test("rejects a provider missing required methods", async () => {
      const scp = new SCP();
      try {
        // Intentionally incomplete — only `sign` is present.
        const bad = { sign: () => new Uint8Array(64) } as unknown as KeyCustodyProvider;
        await expect(scp.identityCreateWithCustody(bad)).rejects.toThrow();
      } finally {
        await scp.shutdown(1000).catch(() => {});
      }
    });
  });
}
