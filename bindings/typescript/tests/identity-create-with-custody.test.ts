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

import { CryptoError, KeyNotFoundError, ScpError } from "../src/errors";
import type {
  CustodyKeyRole,
  CustodyKeyType,
  CustodyPublicKey,
  KeyCustodyProvider,
} from "../src/scp";
import { p256SoftwarePseudonymPoint, SCP } from "../src/scp";
import { skipReasonIfAddonAbsent } from "./napi-guard";

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
  skipReason = skipReasonIfAddonAbsent(e);
}

// ---------------------------------------------------------------------------
// Real-Ed25519 custody provider backed by node:crypto
// ---------------------------------------------------------------------------

/** A host fault the fixture can inject into its pseudonym results. */
type PseudonymFault = "legacy32" | "deriveKeyNotFound";

class CryptoKeychain implements KeyCustodyProvider {
  #seeds = new Map<string, Uint8Array>();
  // Key id -> the role generateKeypair minted it in.
  #roles = new Map<string, CustodyKeyRole>();
  #next = 1;
  readonly #fault: PseudonymFault | undefined;

  constructor(fault?: PseudonymFault) {
    this.#fault = fault;
  }

  generateKeypair(_keyType: CustodyKeyType, role: CustodyKeyRole): string {
    const { privateKey } = crypto.generateKeyPairSync("ed25519");
    const jwk = privateKey.export({ format: "jwk" }) as { d: string };
    const kid = String(this.#next++);
    this.#roles.set(kid, role);
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
    this.#roles.delete(keyId);
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

    // §9.10.4.A: a host that reports key-not-found while deriving fails the
    // production context create with that code, not a derivation identity code.
    test("an encrypted context create fails with SCP-CRYPTO-4006 when the host reports key-not-found", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
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
      }
    });

    // §9.10.4: the bridge fails closed with SCP-IDENT-1055 on host pseudonym
    // bytes that are not a compressed P-256 point, such as a retired 32-byte key.
    test("an encrypted context create fails with SCP-IDENT-1055 on a 32-byte host pseudonym", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
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
      }
    });

    // ADR-049 Decision 7a: governance signs through `KeyCustody::sign`, so a
    // callback custody, which only signs, proposes, and the single-admin
    // proposal auto-executes after the engine verifies the custody signature.
    test("callback custody proposes governance through sign", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
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
      }
    });

    // ADR-049 Decision 7a: a send signs its inner envelope through
    // `KeyCustody::sign`, so a callback custody, which only signs, sends.
    test("callback custody sends through sign", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
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
      }
    });
  });
}
