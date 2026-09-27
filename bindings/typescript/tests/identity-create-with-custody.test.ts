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

import { ScpError } from "../src/errors";
import type { KeyCustodyProvider, PseudonymResult } from "../src/scp";
import { SCP } from "../src/scp";
import {
  p256Compressed,
  p256SignPrehash,
  pseudonymScalar,
  pseudonymSeedV1,
  pseudonymSeedV2,
} from "./pseudonym-recipe";

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

/** A host fault the fixture can inject into its pseudonym results. */
type PseudonymFault = "legacy32" | "wrongPublicKey";

class CryptoKeychain implements KeyCustodyProvider {
  #seeds = new Map<string, Uint8Array>();
  // Pseudonym key ids → P-256 private scalar (§9.10.4.A).
  #pseudonyms = new Map<string, bigint>();
  #next = 1;
  readonly #fault: PseudonymFault | undefined;

  constructor(fault?: PseudonymFault) {
    this.#fault = fault;
  }

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
    const d = this.#pseudonyms.get(keyId);
    if (d !== undefined) return p256SignPrehash(d, message);
    return new Uint8Array(crypto.sign(null, Buffer.from(message), this.#keyObject(keyId)));
  }

  getPublicKey(keyId: string): Uint8Array {
    const d = this.#pseudonyms.get(keyId);
    if (d !== undefined) {
      const point = p256Compressed(d);
      // A host whose handle answers with a different point than its derivation.
      if (this.#fault === "wrongPublicKey") point[0] = point[0] === 0x02 ? 0x03 : 0x02;
      return point;
    }
    const pub = crypto.createPublicKey(this.#keyObject(keyId));
    const jwk = pub.export({ format: "jwk" }) as { x: string };
    return new Uint8Array(Buffer.from(jwk.x, "base64url"));
  }

  destroyKey(keyId: string): void {
    this.#seeds.delete(keyId);
    this.#pseudonyms.delete(keyId);
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

  #identitySeed(keyId: string): Uint8Array {
    const seed = this.#seeds.get(keyId);
    if (seed === undefined) throw new Error(`unknown key id: ${keyId}`);
    return seed;
  }

  // Register the §9.10.4.A P-256 pseudonym of a context seed as a new key.
  // Native software custody keys the recipe on the Ed25519 identity seed.
  #registerPseudonym(contextSeed: Uint8Array): PseudonymResult {
    const d = pseudonymScalar(contextSeed);
    const keyId = String(this.#next++);
    this.#pseudonyms.set(keyId, d);
    const point = p256Compressed(d);
    // A host still on the retired 32-byte Ed25519 pseudonym shape.
    const publicKey = this.#fault === "legacy32" ? point.subarray(1) : point;
    return { publicKey, keyId };
  }

  derivePseudonym(keyId: string, contextId: Uint8Array): PseudonymResult {
    return this.#registerPseudonym(pseudonymSeedV1(this.#identitySeed(keyId), contextId));
  }

  deriveRotatablePseudonym(
    keyId: string,
    contextId: Uint8Array,
    pseudonymEpoch: bigint,
  ): PseudonymResult {
    return this.#registerPseudonym(
      pseudonymSeedV2(this.#identitySeed(keyId), contextId, pseudonymEpoch),
    );
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

// A keychain that signs but REFUSES to export raw key bytes — the shape of a
// real OS keychain / HSM / secure-enclave custody. `exportSigningKeyBytes`
// throws, so any operation that depends on extracting the raw private key would
// fail; only operations routed through the `sign` callback can succeed.
class SignOnlyKeychain extends CryptoKeychain {
  override exportSigningKeyBytes(_keyId: string): Uint8Array {
    throw new Error("sign-only custody: raw key export is not permitted");
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
        expect(identity.custodyType).toBe("callback");
      } finally {
        await scp.shutdown(1000).catch(() => {});
      }
    });

    // §9.10.4: the bridge fails closed on a host pseudonym it cannot trust —
    // a retired 32-byte key, or a key id whose getPublicKey disagrees with the
    // point the derivation returned — with SCP-IDENT-1055 and the cause.
    for (const [fault, cause] of [
      ["legacy32", "33-byte compressed P-256 point, got 32 bytes"],
      ["wrongPublicKey", "does not match the derived pseudonym point"],
    ] as const) {
      test(`an encrypted context create fails with SCP-IDENT-1055 on host fault ${fault}`, async () => {
        const scp = new SCP({ storage: { type: "in_memory" } });
        try {
          const identity = await scp.identityCreateWithCustody(new CryptoKeychain(fault));
          let caught: unknown;
          try {
            await scp.contextCreate(
              identity,
              JSON.stringify({ ceiling: ["messages:read"], memoryScope: "ephemeral" }),
            );
          } catch (err) {
            caught = err;
          }
          expect(caught).toBeInstanceOf(ScpError);
          expect((caught as ScpError).code).toBe("SCP-IDENT-1055");
          expect((caught as ScpError).message).toContain(cause);
        } finally {
          await scp.shutdown(1000).catch(() => {});
        }
      });
    }

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
