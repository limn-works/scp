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
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { CryptoError, KeyNotFoundError, ScpError } from "../src/errors";
import type {
  CustodyKeyRole,
  CustodyKeyType,
  CustodyPublicKey,
  KeyCustodyProvider,
} from "../src/scp";
import { p256SoftwarePseudonymPoint, SCP } from "../src/scp";
import {
  ECDH_VECTOR_PUBLIC_I,
  ECDH_VECTOR_PUBLIC_R,
  ECDH_VECTOR_SCALAR_I,
  ECDH_VECTOR_SHARED_X,
  HpkeP256Keys,
} from "./hpke-p256-keys";
import { napiSuite } from "./napi-guard";

// ---------------------------------------------------------------------------
// Probe: is the NAPI-backed SCP class available in this environment?
// ---------------------------------------------------------------------------

const suite = await napiSuite(() => {
  const probe = new SCP({ storage: { type: "in_memory" } });
  probe.shutdown(1).catch(() => {});
});

// ---------------------------------------------------------------------------
// Persistent storage: callback custody refuses storage that does not persist
// (spec §17.3), so every instance that creates with a provider is SQLite.
// ---------------------------------------------------------------------------

const SQLITE_KEY = new Uint8Array(32).fill(0x5c);

async function freshDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), "scp-callback-custody-"));
}

function sqliteScp(dir: string): SCP {
  return new SCP({ storage: { type: "sqlite", path: dir, key: SQLITE_KEY } });
}

/** The bridge code a rejected promise carries. */
async function rejectionCode(p: Promise<unknown>): Promise<string | undefined> {
  try {
    await p;
  } catch (err) {
    return (err as ScpError).code;
  }
  throw new Error("expected the call to reject");
}

// ---------------------------------------------------------------------------
// Real-Ed25519 and real-P-256 custody provider backed by node:crypto
// ---------------------------------------------------------------------------

/** A host fault the fixture can inject into its pseudonym results. */
type PseudonymFault = "legacy32" | "deriveKeyNotFound";

class CryptoKeychain implements KeyCustodyProvider {
  /** Ed25519 identity seeds. */
  #seeds = new Map<string, Uint8Array>();
  /** HPKE P-256 keys (the identity wrapping key). */
  #hpke = new HpkeP256Keys();
  // Key id -> the role generateKeypair minted it in.
  #roles = new Map<string, CustodyKeyRole>();
  #next = 1;
  readonly #fault: PseudonymFault | undefined;

  constructor(fault?: PseudonymFault) {
    this.#fault = fault;
  }

  generateKeypair(keyType: CustodyKeyType, role: CustodyKeyRole): string {
    if (keyType !== "ed25519" && keyType !== "hpke-p256") {
      throw new Error(`this keychain holds ed25519 and hpke-p256 keys, not ${keyType}`);
    }
    const kid = String(this.#next++);
    this.#roles.set(kid, role);
    if (keyType === "hpke-p256") {
      this.#hpke.generate(kid);
      return kid;
    }
    const { privateKey } = crypto.generateKeyPairSync("ed25519");
    const jwk = privateKey.export({ format: "jwk" }) as { d: string };
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
    if (seed === undefined) throw new KeyNotFoundError(`unknown key id: ${keyId}`);
    return this.#keyObjectFromSeed(seed);
  }

  sign(keyId: string, message: Uint8Array): Uint8Array {
    return new Uint8Array(crypto.sign(null, Buffer.from(message), this.#keyObject(keyId)));
  }

  getPublicKey(keyId: string): CustodyPublicKey {
    if (this.#hpke.has(keyId)) {
      return {
        keyType: "hpke-p256",
        publicKey: this.#hpke.publicKey(keyId),
        role: this.#role(keyId),
      };
    }
    const pub = crypto.createPublicKey(this.#keyObject(keyId));
    const jwk = pub.export({ format: "jwk" }) as { x: string };
    return {
      keyType: "ed25519",
      publicKey: new Uint8Array(Buffer.from(jwk.x, "base64url")),
      role: this.#role(keyId),
    };
  }

  #role(keyId: string): CustodyKeyRole {
    const role = this.#roles.get(keyId);
    if (role === undefined) throw new KeyNotFoundError(`no role recorded for ${keyId}`);
    return role;
  }

  destroyKey(keyId: string): void {
    this.#seeds.delete(keyId);
    this.#hpke.delete(keyId);
    this.#roles.delete(keyId);
  }

  dhAgree(keyId: string, peerPublic: Uint8Array): Uint8Array {
    if (!this.#hpke.has(keyId)) {
      if (this.#seeds.has(keyId)) throw new Error(`key ${keyId} is ed25519; it cannot agree`);
      throw new KeyNotFoundError(`unknown key id: ${keyId}`);
    }
    return this.#hpke.agree(keyId, peerPublic);
  }

  #identitySeed(keyId: string): Uint8Array {
    const seed = this.#seeds.get(keyId);
    if (seed === undefined) throw new KeyNotFoundError(`unknown key id: ${keyId}`);
    return seed;
  }

  // The §9.10.4.A P-256 pseudonym point. Native software custody keys the
  // recipe on the Ed25519 identity seed; the SDK's software helper derives the
  // point and nothing is stored.
  #pseudonymPoint(keyId: string, contextId: Uint8Array, epoch?: bigint): Uint8Array {
    const point = p256SoftwarePseudonymPoint(this.#identitySeed(keyId), contextId, epoch);
    // A host still on the retired 32-byte Ed25519 pseudonym shape.
    return this.#fault === "legacy32" ? point.subarray(1) : point;
  }

  derivePseudonym(keyId: string, contextId: Uint8Array): Uint8Array {
    // A host whose key is gone reports the contract's key-not-found code.
    if (this.#fault === "deriveKeyNotFound") {
      throw new CryptoError(`key not found: ${keyId}`, "SCP-CRYPTO-4006");
    }
    return this.#pseudonymPoint(keyId, contextId);
  }

  deriveRotatablePseudonym(
    keyId: string,
    contextId: Uint8Array,
    pseudonymEpoch: bigint,
  ): Uint8Array {
    return this.#pseudonymPoint(keyId, contextId, pseudonymEpoch);
  }

  custodyType(_keyId: string): string {
    return "software";
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// The keychain's hpke-p256 keys are real P-256: agreement is symmetric, and
// the ECDH it runs reproduces the RFC 5903 §8.1 vector `scp_crypto` pins.
describe("CryptoKeychain hpke-p256", () => {
  test("agrees symmetrically and matches the pinned ECDH vector", () => {
    const keychain = new CryptoKeychain();
    const a = keychain.generateKeypair("hpke-p256", "operational");
    const b = keychain.generateKeypair("hpke-p256", "operational");
    const aPub = keychain.getPublicKey(a);
    const bPub = keychain.getPublicKey(b);
    expect(aPub.keyType).toBe("hpke-p256");
    expect(aPub.publicKey.length).toBe(65);
    expect(Buffer.from(keychain.dhAgree(a, bPub.publicKey)).toString("hex")).toBe(
      Buffer.from(keychain.dhAgree(b, aPub.publicKey)).toString("hex"),
    );

    const ecdh = crypto.createECDH("prime256v1");
    ecdh.setPrivateKey(Buffer.from(ECDH_VECTOR_SCALAR_I, "hex"));
    expect(ecdh.getPublicKey("hex")).toBe(ECDH_VECTOR_PUBLIC_I);
    expect(ecdh.computeSecret(Buffer.from(ECDH_VECTOR_PUBLIC_R, "hex")).toString("hex")).toBe(
      ECDH_VECTOR_SHARED_X,
    );
    // The keychain's agreement with the vector's point is the one the
    // vector's scalar computes against the keychain's point.
    expect(
      Buffer.from(keychain.dhAgree(a, Buffer.from(ECDH_VECTOR_PUBLIC_I, "hex"))).toString("hex"),
    ).toBe(ecdh.computeSecret(Buffer.from(aPub.publicKey)).toString("hex"));
  });

  test("refuses a peer that is not a 65-byte curve point, and an ed25519 key", () => {
    const keychain = new CryptoKeychain();
    const a = keychain.generateKeypair("hpke-p256", "operational");
    const point = Buffer.from(ECDH_VECTOR_PUBLIC_I, "hex");
    const offCurve = Buffer.from(point);
    offCurve[64] = (offCurve[64] ?? 0) ^ 1;
    const bad = [
      point.subarray(1, 33),
      point.subarray(1),
      Buffer.concat([point, Buffer.alloc(1)]),
      offCurve,
      Buffer.alloc(65),
    ];
    for (const peer of bad) {
      expect(() => keychain.dhAgree(a, peer)).toThrow();
    }
    const ed = keychain.generateKeypair("ed25519", "identity");
    expect(() => keychain.dhAgree(ed, point)).toThrow();
  });
});

suite.describe("identityCreateWithCustody", () => {
  describe("SCP.identityCreateWithCustody (real NAPI)", () => {
    test("creates a did:dht identity backed by a JS custody provider", async () => {
      const dir = await freshDir();
      const scp = sqliteScp(dir);
      try {
        const provider = new CryptoKeychain();
        const identity = await scp.identityCreateWithCustody(provider);
        expect(identity.did).toMatch(/^did:dht:/);
        expect(identity.custodyType).toBe("os_keystore");
      } finally {
        await scp.shutdown(1000).catch(() => {});
        await rm(dir, { recursive: true, force: true });
      }
    });

    // §9.10.4.A: a host that reports key-not-found while deriving fails the
    // production context create with that code, not a derivation identity code.
    test("an encrypted context create fails with SCP-CRYPTO-4006 when the host reports key-not-found", async () => {
      const dir = await freshDir();
      const scp = sqliteScp(dir);
      try {
        const identity = await scp.identityCreateWithCustody(
          new CryptoKeychain("deriveKeyNotFound"),
        );
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
        expect((caught as ScpError).code).toBe("SCP-CRYPTO-4006");
      } finally {
        await scp.shutdown(1000).catch(() => {});
        await rm(dir, { recursive: true, force: true });
      }
    });

    // §9.10.4: the bridge fails closed with SCP-IDENT-1055 on host pseudonym
    // bytes that are not a compressed P-256 point, such as a retired 32-byte key.
    test("an encrypted context create fails with SCP-IDENT-1055 on a 32-byte host pseudonym", async () => {
      const dir = await freshDir();
      const scp = sqliteScp(dir);
      try {
        const identity = await scp.identityCreateWithCustody(new CryptoKeychain("legacy32"));
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
        expect((caught as ScpError).message).toContain("got 32 bytes");
      } finally {
        await scp.shutdown(1000).catch(() => {});
        await rm(dir, { recursive: true, force: true });
      }
    });

    test("rejects a provider missing required methods", async () => {
      const dir = await freshDir();
      const scp = sqliteScp(dir);
      try {
        // Intentionally incomplete — only `sign` is present.
        const bad = { sign: () => new Uint8Array(64) } as unknown as KeyCustodyProvider;
        await expect(scp.identityCreateWithCustody(bad)).rejects.toThrow();
      } finally {
        await scp.shutdown(1000).catch(() => {});
        await rm(dir, { recursive: true, force: true });
      }
    });

    // Spec §23.16.8 / ADR-050: a context created under callback (platform)
    // custody must be able to produce an Ed25519-signed export whose snapshot
    // signature verifies on import. Export signing is delegated to the custody
    // `sign` callback — NOT to raw key export — so a callback identity reaches
    // parity with an in-memory one for signed export/import.
    test("callback-custody identity exports a signed snapshot that imports", async () => {
      const dir = await freshDir();
      const scp = sqliteScp(dir);
      try {
        const identity = await scp.identityCreateWithCustody(new CryptoKeychain());
        const ctx = await scp.contextCreate(
          identity,
          JSON.stringify({
            ceiling: ["messages:read", "context:close"],
            memoryScope: "ephemeral",
          }),
        );

        const data = await scp.contextExport(ctx);
        expect(data.length).toBeGreaterThan(0);

        // Close so import_context sees a terminal state and allows reimport.
        await scp.contextClose(ctx, identity.did);

        // Import verifies the snapshot signature against the creator's #active
        // verifying key. Success proves the callback-custody-produced signature
        // is spec-valid.
        const importedContextId = await scp.contextImport(data, identity.did);
        expect(typeof importedContextId).toBe("string");
        expect(importedContextId.length).toBeGreaterThan(0);
      } finally {
        await scp.shutdown(1000).catch(() => {});
        await rm(dir, { recursive: true, force: true });
      }
    });

    // ADR-049 Decision 7a: governance signs through `KeyCustody::sign`, so a
    // callback custody, which only signs, proposes, and the single-admin
    // proposal auto-executes after the engine verifies the custody signature.
    test("callback custody proposes governance through sign", async () => {
      const dir = await freshDir();
      const scp = sqliteScp(dir);
      try {
        const identity = await scp.identityCreateWithCustody(new CryptoKeychain());
        const ctx = await scp.contextCreate(
          identity,
          JSON.stringify({
            ceiling: ["messages:read", "messages:write", "governance:propose", "member:ban"],
            memoryScope: "ephemeral",
            governance: "single_admin",
          }),
        );
        const response = await scp.contextGovernancePropose(
          ctx,
          JSON.stringify({
            SuspendCapability: { did: identity.did, capabilities: ["MessagesWrite"] },
          }),
          identity.did,
        );
        expect(JSON.parse(response).status).toBe("Approved");
      } finally {
        await scp.shutdown(1000).catch(() => {});
        await rm(dir, { recursive: true, force: true });
      }
    });

    // ADR-049 Decision 7a: a send signs its inner envelope through
    // `KeyCustody::sign`, so a callback custody, which only signs, sends.
    test("callback custody sends through sign", async () => {
      const dir = await freshDir();
      const scp = sqliteScp(dir);
      try {
        const identity = await scp.identityCreateWithCustody(new CryptoKeychain());
        const ctx = await scp.contextCreate(
          identity,
          JSON.stringify({
            ceiling: ["messages:read", "messages:write"],
            memoryScope: "ephemeral",
            governance: "single_admin",
          }),
        );
        await scp.contextSend(ctx, identity.did, new TextEncoder().encode("sign-only send"));
      } finally {
        await scp.shutdown(1000).catch(() => {});
        await rm(dir, { recursive: true, force: true });
      }
    });
  });

  // Spec §17.3 (SCP-345 decision D1): the identity's custody entry carries
  // its namespace, so a new instance over the same directory reaches the
  // keys the earlier one minted.
  describe("SCP.identityLoadWithCustody (real NAPI)", () => {
    /** A {@link CryptoKeychain} that counts the signatures it makes. */
    class CountingKeychain extends CryptoKeychain {
      signCalls = 0;

      override sign(keyId: string, message: Uint8Array): Uint8Array {
        this.signCalls += 1;
        return super.sign(keyId, message);
      }
    }

    test("a new instance loads the identity with its provider and signs with its earlier key", async () => {
      const dir = await freshDir();
      const provider = new CountingKeychain();
      try {
        const first = sqliteScp(dir);
        let did: string;
        try {
          did = (await first.identityCreateWithCustody(provider)).did;
        } finally {
          await first.shutdown(1000);
        }

        const second = sqliteScp(dir);
        try {
          expect(await rejectionCode(second.identityLoad(did))).toBe("SCP-IDENT-1003");
          const loaded = await second.identityLoadWithCustody(did, provider);
          expect(loaded.did).toBe(did);
          expect(loaded.custodyType).toBe("os_keystore");
          // The identity key was minted by the first instance; its record
          // lives under the stored namespace, so the loaded adapter resolves
          // it, and the proposal signs through `provider`.
          const ctx = await second.contextCreate(
            loaded,
            JSON.stringify({
              ceiling: ["messages:read", "messages:write", "governance:propose", "member:ban"],
              memoryScope: "ephemeral",
              governance: "single_admin",
            }),
          );
          const signsBefore = provider.signCalls;
          const response = await second.contextGovernancePropose(
            ctx,
            JSON.stringify({
              SuspendCapability: { did, capabilities: ["MessagesWrite"] },
            }),
            did,
          );
          expect(JSON.parse(response).status).toBe("Approved");
          expect(provider.signCalls).toBeGreaterThan(signsBefore);
          expect(await rejectionCode(second.identityLoadWithCustody(did, provider))).toBe(
            "SCP-IDENT-1008",
          );
        } finally {
          await second.shutdown(1000).catch(() => {});
        }
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });

    // Spec §17.3: every operation that changes a callback custody identity
    // rewrites its stored entry. A new instance resolves the document a
    // rotation alone published, and after an agent key's addition to the
    // loaded identity, a third instance resolves that document, never the
    // one an earlier write stored.
    test("a reload after a rotation and an agent key carries the changed keys", async () => {
      const dir = await freshDir();
      const provider = new CryptoKeychain();
      try {
        const first = sqliteScp(dir);
        let did: string;
        let rotatedDocument: unknown;
        try {
          const created = await first.identityCreateWithCustody(provider);
          const createdDocument = await first.identityResolve(created.did);
          const rotated = await first.identityRotateKey(created);
          did = rotated.did;
          rotatedDocument = await first.identityResolve(did);
          expect(rotatedDocument).not.toEqual(createdDocument);
        } finally {
          await first.shutdown(1000);
        }

        const second = sqliteScp(dir);
        let changedDocument: unknown;
        try {
          const loaded = await second.identityLoadWithCustody(did, provider);
          expect(await second.identityResolve(did)).toEqual(rotatedDocument);
          await second.identityAddAgentKey(loaded);
          changedDocument = await second.identityResolve(did);
          expect(changedDocument).not.toEqual(rotatedDocument);
        } finally {
          await second.shutdown(1000).catch(() => {});
        }

        const third = sqliteScp(dir);
        try {
          await third.identityLoadWithCustody(did, provider);
          expect(await third.identityResolve(did)).toEqual(changedDocument);
        } finally {
          await third.shutdown(1000).catch(() => {});
        }
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });

    test("in-memory storage refuses a callback custody create and load with SCP-STORAGE-8000", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
      try {
        const provider = new CryptoKeychain();
        expect(await rejectionCode(scp.identityCreateWithCustody(provider))).toBe(
          "SCP-STORAGE-8000",
        );
        expect(
          await rejectionCode(
            scp.identityLoadWithCustody(
              "did:dht:ab3ii3ef4mbcu5rmhkbf5yctwnodzx6a65ghazmtu1ydzhfzezby",
              provider,
            ),
          ),
        ).toBe("SCP-STORAGE-8000");
      } finally {
        await scp.shutdown(1000).catch(() => {});
      }
    });
  });
});
