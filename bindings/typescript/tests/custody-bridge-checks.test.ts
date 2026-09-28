/**
 * The napi callback-custody adapter's pseudonym checks (§9.5, §9.10.4),
 * driven through the SDK's production custody record
 * (`toNativeCustodyProvider`) and the napi `TestingCallbackCustody` hook.
 *
 * Each test fails if the check it names is removed from the adapter
 * (`crates/scp-ffi/napi/src/custody.rs` over `CallbackKeyRegistry` in
 * `crates/scp-ffi/common/src/callback_custody.rs`):
 *   - `p256_digest`: a pseudonym key signs only a 32-byte digest, and a
 *     shorter input never reaches the host;
 *   - `p256_host_signature`: a high-s host signature comes out as the low-s
 *     form;
 *   - `begin_destroy` and `end_destroy`: a destroyed id can carry a new point,
 *     and the id is no longer live when the host's `destroyKey` runs;
 *   - `retire_pseudonyms_of`: destroying an identity retires its pseudonyms,
 *     so they sign nothing and a host may reuse their ids.
 *
 * The host-failure tests fail if `hostCall` in
 * `src/internal/custody-adapter.ts` stops turning a host failure into a typed
 * rejection: a host throw (including a thrown value with no readable
 * message), a Promise return and a wrongly typed return must each reject the
 * SDK call with a typed error (key-not-found `SCP-CRYPTO-4006` for a host
 * error carrying that code, the custody error `SCP-CRYPTO-4060` otherwise)
 * and never reach the process as an uncaught exception or an unhandled
 * rejection.
 *
 * It also runs the §25.19 Vector 30 and 31 identity scalars through the
 * bridge's production pseudonym derivation and compares each v1 routing id to
 * the spec.
 */

import { describe, expect, test } from "bun:test";
import * as crypto from "node:crypto";

import { CryptoError, mapBridgeError } from "../src/errors";
import { toNativeCustodyProvider } from "../src/internal/custody-adapter";
import { loadNativeAddon } from "../src/internal/native";
import type { CustodyPublicKey, KeyCustodyProvider, PseudonymResult } from "../src/scp";
import {
  bigIntTo32,
  bytesToBigInt,
  P256_N,
  p256Compressed,
  p256SignPrehash,
  pseudonymScalar,
  pseudonymSeedV1,
} from "./pseudonym-recipe";

interface TestingCustody {
  generateKeypair(): Promise<string>;
  derivePseudonym(identityKeyId: string, contextId: string): Promise<PseudonymResult>;
  sign(keyId: string, data: Buffer): Promise<Buffer>;
  destroyKey(keyId: string): Promise<void>;
  isBound(keyId: string): boolean;
}

type TestingCustodyCtor = new (
  provider: ReturnType<typeof toNativeCustodyProvider>,
) => TestingCustody;

let native: Record<string, unknown> = {};
let skipReason = "";
try {
  native = loadNativeAddon();
  if (typeof native.TestingCallbackCustody !== "function") {
    skipReason = "native addon built without the `testing` feature";
  }
} catch (e: unknown) {
  skipReason = `native addon not available: ${e instanceof Error ? e.message : String(e)}`;
}

/** A host fault the store injects into pseudonym signing or key ids. */
type Fault = "highS" | "fixedId" | "signThrows" | "sign4001";

/** The host's key store, with a count of `sign` calls that reach it. */
class Store {
  seeds = new Map<string, Uint8Array>();
  pseudonyms = new Map<string, bigint>();
  /** Pseudonym key id -> the identity key id it was derived from. */
  pseudonymOwner = new Map<string, string>();
  /** Key id -> the role `generateKeypair` minted it in. */
  roles = new Map<string, string>();
  next = 1;
  signCalls = 0;
  /** Called with the key id at the start of the host's `destroyKey`. */
  destroyProbe?: (keyId: string) => void;
}

class StoreKeychain implements KeyCustodyProvider {
  constructor(
    readonly store: Store,
    readonly fault?: Fault,
  ) {}

  generateKeypair(_keyType: string, role: string): string {
    const kid = String(this.store.next++);
    this.store.seeds.set(kid, new Uint8Array(crypto.randomBytes(32)));
    this.store.roles.set(kid, role);
    return kid;
  }

  sign(keyId: string, message: Uint8Array): Uint8Array {
    this.store.signCalls++;
    if (this.fault === "signThrows") throw new Error("keystore offline");
    if (this.fault === "sign4001") throw new CryptoError("hsm offline", "SCP-CRYPTO-4001");
    const d = this.store.pseudonyms.get(keyId);
    // The contract's key-not-found signal (`KeyCustodyProvider` in `src/scp.ts`).
    if (d === undefined) throw new CryptoError(`key not found: ${keyId}`, "SCP-CRYPTO-4006");
    const sig = p256SignPrehash(d, message);
    if (this.fault !== "highS") return sig;
    const s = bytesToBigInt(sig.subarray(32));
    return new Uint8Array(
      Buffer.concat([Buffer.from(sig.subarray(0, 32)), bigIntTo32(P256_N - s)]),
    );
  }

  getPublicKey(keyId: string): CustodyPublicKey {
    const d = this.store.pseudonyms.get(keyId);
    if (d !== undefined) {
      return { keyType: "p256", publicKey: p256Compressed(d), role: "operational" };
    }
    const seed = this.store.seeds.get(keyId);
    if (seed !== undefined) {
      return {
        keyType: "ed25519",
        publicKey: ed25519Public(seed),
        role: this.store.roles.get(keyId) ?? "missing",
      };
    }
    throw new Error(`unknown key id: ${keyId}`);
  }

  destroyKey(keyId: string): void {
    this.store.destroyProbe?.(keyId);
    this.store.seeds.delete(keyId);
    this.store.roles.delete(keyId);
    this.store.pseudonyms.delete(keyId);
    this.store.pseudonymOwner.delete(keyId);
    // A pseudonym dies with its identity (§9.10.4.A).
    for (const [kid, owner] of [...this.store.pseudonymOwner]) {
      if (owner !== keyId) continue;
      this.store.pseudonyms.delete(kid);
      this.store.pseudonymOwner.delete(kid);
    }
  }

  dhAgree(_keyId: string, _peerPublic: Uint8Array): Uint8Array {
    throw new Error("unused");
  }

  derivePseudonym(keyId: string, contextId: Uint8Array): PseudonymResult {
    const seed = this.store.seeds.get(keyId);
    if (seed === undefined) throw new Error(`unknown key id: ${keyId}`);
    const d = pseudonymScalar(pseudonymSeedV1(seed, contextId));
    // Deterministic per (identity, context), as the provider contract requires;
    // `fixedId` names every pseudonym "777" to reuse one id across contexts.
    const h = crypto.createHash("sha256").update(`${keyId}|`).update(contextId).digest();
    const pseudonymId =
      this.fault === "fixedId" ? "777" : (h.readBigUInt64BE(0) | (1n << 63n)).toString();
    this.store.pseudonyms.set(pseudonymId, d);
    this.store.pseudonymOwner.set(pseudonymId, keyId);
    return { publicKey: p256Compressed(d), keyId: pseudonymId };
  }

  deriveRotatablePseudonym(): PseudonymResult {
    throw new Error("unused");
  }

  exportSigningKeyBytes(_keyId: string): Uint8Array {
    throw new Error("unused");
  }

  custodyType(_keyId: string): string {
    return "software";
  }
}

/** The Ed25519 public key of a 32-byte seed, through a PKCS#8 import. */
function ed25519Public(seed: Uint8Array): Uint8Array {
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  const key = crypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const spki = crypto.createPublicKey(key).export({ format: "der", type: "spki" });
  return new Uint8Array(spki.subarray(spki.length - 32));
}

function adapter(store: Store, fault?: Fault): TestingCustody {
  const Ctor = native.TestingCallbackCustody as TestingCustodyCtor;
  return new Ctor(toNativeCustodyProvider(new StoreKeychain(store, fault)));
}

/**
 * A provider over `store` whose `overrides` replace some methods, typed
 * loosely so a test can return what a misbehaving host returns.
 */
function adapterWith(store: Store, overrides: Record<string, () => unknown>): TestingCustody {
  const Ctor = native.TestingCallbackCustody as TestingCustodyCtor;
  const provider = Object.assign(new StoreKeychain(store), overrides) as KeyCustodyProvider;
  return new Ctor(toNativeCustodyProvider(provider));
}

const DIGEST = crypto.createHash("sha256").update("custody-bridge-checks").digest();

/**
 * Runs `body` and returns every error that reached the process as an uncaught
 * exception or an unhandled rejection meanwhile, waiting two macrotasks for a
 * late report.
 */
async function uncaughtDuring(body: () => Promise<void>): Promise<unknown[]> {
  const seen: unknown[] = [];
  const record = (e: unknown) => seen.push(e);
  process.on("uncaughtException", record);
  process.on("unhandledRejection", record);
  try {
    await body();
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));
  } finally {
    process.off("uncaughtException", record);
    process.off("unhandledRejection", record);
  }
  return seen;
}

/** Awaits `call`, returning its rejection mapped to an SDK error. */
async function rejectionOf(call: () => Promise<unknown>): Promise<Error & { code?: string }> {
  let err: unknown;
  const escaped = await uncaughtDuring(async () => {
    err = await call().then(
      () => undefined,
      (e: unknown) => e,
    );
  });
  expect(escaped).toEqual([]);
  expect(err).toBeDefined();
  return mapBridgeError(err);
}

describe.skipIf(skipReason !== "")("napi callback custody pseudonym checks", () => {
  test("a pseudonym key signs a 32-byte digest and nothing shorter reaches the host", async () => {
    const store = new Store();
    const custody = adapter(store);
    const identity = await custody.generateKeypair();
    const pseudonym = await custody.derivePseudonym(identity, "ctx");
    expect((await custody.sign(pseudonym.keyId, DIGEST)).length).toBe(64);
    const calls = store.signCalls;
    const err = await custody.sign(pseudonym.keyId, Buffer.alloc(12)).catch((e: unknown) => e);
    expect(mapBridgeError(err).code).toBe("SCP-CRYPTO-4060");
    expect(store.signCalls).toBe(calls);
  });

  test("a high-s host signature comes out as the low-s form", async () => {
    const store = new Store();
    const custody = adapter(store, "highS");
    const identity = await custody.generateKeypair();
    const pseudonym = await custody.derivePseudonym(identity, "ctx");
    const sig = await custody.sign(pseudonym.keyId, DIGEST);
    expect(sig.length).toBe(64);
    expect(bytesToBigInt(sig.subarray(32)) <= P256_N / 2n).toBe(true);
    const d = store.pseudonyms.get(pseudonym.keyId);
    if (d === undefined) throw new Error("pseudonym missing from the store");
    expect(Buffer.from(sig).equals(Buffer.from(p256SignPrehash(d, DIGEST)))).toBe(true);
  });

  test("destroying a pseudonym unbinds its id", async () => {
    const store = new Store();
    const custody = adapter(store, "fixedId");
    const identity = await custody.generateKeypair();
    const alpha = await custody.derivePseudonym(identity, "alpha");
    await custody.destroyKey(alpha.keyId);
    // "777" now carries a different point; a stale binding would reject it.
    const beta = await custody.derivePseudonym(identity, "beta");
    expect(beta.keyId).toBe(alpha.keyId);
    expect(Buffer.from(beta.publicKey).equals(Buffer.from(alpha.publicKey))).toBe(false);
    expect((await custody.sign(beta.keyId, DIGEST)).length).toBe(64);
  });

  test("a destroyed identity's pseudonym rejects sign with key-not-found (§9.10.4.A)", async () => {
    const store = new Store();
    const custody = adapter(store);
    const identity = await custody.generateKeypair();
    const other = await custody.generateKeypair();
    const pseudonym = await custody.derivePseudonym(identity, "ctx");
    const kept = await custody.derivePseudonym(other, "ctx");
    expect((await custody.sign(pseudonym.keyId, DIGEST)).length).toBe(64);
    await custody.destroyKey(identity);
    let err: unknown;
    const uncaught = await uncaughtDuring(async () => {
      err = await custody.sign(pseudonym.keyId, DIGEST).catch((e: unknown) => e);
    });
    expect(uncaught).toEqual([]);
    const mapped = mapBridgeError(err);
    expect(mapped).toBeInstanceOf(CryptoError);
    expect(mapped.code).toBe("SCP-CRYPTO-4006");
    expect((await custody.sign(kept.keyId, DIGEST)).length).toBe(64);
  });

  test("a host method that throws another error rejects with a custody error", async () => {
    const store = new Store();
    const custody = adapter(store, "signThrows");
    const identity = await custody.generateKeypair();
    const pseudonym = await custody.derivePseudonym(identity, "ctx");
    let err: unknown;
    const uncaught = await uncaughtDuring(async () => {
      err = await custody.sign(pseudonym.keyId, DIGEST).catch((e: unknown) => e);
    });
    expect(uncaught).toEqual([]);
    const mapped = mapBridgeError(err);
    expect(mapped.code).toBe("SCP-CRYPTO-4060");
    expect(mapped.message).toContain("keystore offline");
  });

  test("a host error carrying the generic SCP-CRYPTO-4001 is a custody error, not key-not-found", async () => {
    const store = new Store();
    const custody = adapter(store, "sign4001");
    const identity = await custody.generateKeypair();
    const pseudonym = await custody.derivePseudonym(identity, "ctx");
    const err = await custody.sign(pseudonym.keyId, DIGEST).catch((e: unknown) => e);
    const mapped = mapBridgeError(err);
    expect(mapped.code).toBe("SCP-CRYPTO-4060");
    expect(mapped.message).toContain("SCP-CRYPTO-4001");
    expect(mapped.message).toContain("hsm offline");
  });

  test("an async host method's rejection is a custody error, never an unhandled rejection", async () => {
    const store = new Store();
    const custody = adapterWith(store, {
      sign: () => Promise.reject(new Error("async keystore offline")),
    });
    const identity = await custody.generateKeypair();
    const pseudonym = await custody.derivePseudonym(identity, "ctx");
    const mapped = await rejectionOf(() => custody.sign(pseudonym.keyId, DIGEST));
    expect(mapped).toBeInstanceOf(CryptoError);
    expect(mapped.code).toBe("SCP-CRYPTO-4060");
    expect(mapped.message).toContain("Promise");
  });

  test("a wrongly typed or asynchronous host return is a custody error", async () => {
    const wrongType = adapterWith(new Store(), { generateKeypair: () => 42 });
    const mapped = await rejectionOf(() => wrongType.generateKeypair());
    expect(mapped).toBeInstanceOf(CryptoError);
    expect(mapped.code).toBe("SCP-CRYPTO-4060");
    expect(mapped.message).toContain("not a string");

    const asyncKeypair = adapterWith(new Store(), { generateKeypair: () => Promise.resolve("1") });
    expect((await rejectionOf(() => asyncKeypair.generateKeypair())).code).toBe("SCP-CRYPTO-4060");

    // A thenable whose `then` rejects is settled against a no-op handler.
    const thenable = adapterWith(new Store(), {
      generateKeypair: () => ({
        // biome-ignore lint/suspicious/noThenProperty: a host-returned thenable is the case under test
        then: (_: unknown, reject: (e: unknown) => void) => reject(new Error("late")),
      }),
    });
    expect((await rejectionOf(() => thenable.generateKeypair())).code).toBe("SCP-CRYPTO-4060");
  });

  test("a thrown value with no readable message is a custody error", async () => {
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    for (const thrown of [Object.create(null), proxy, Object.assign(new Error(), { message: 7 })]) {
      const store = new Store();
      const custody = adapterWith(store, {
        sign: () => {
          throw thrown;
        },
      });
      const identity = await custody.generateKeypair();
      const pseudonym = await custody.derivePseudonym(identity, "ctx");
      const mapped = await rejectionOf(() => custody.sign(pseudonym.keyId, DIGEST));
      expect(mapped).toBeInstanceOf(CryptoError);
      expect(mapped.code).toBe("SCP-CRYPTO-4060");
    }
  });

  test("the adapter unbinds a pseudonym before the host's destroyKey runs", async () => {
    const store = new Store();
    const custody = adapter(store);
    const identity = await custody.generateKeypair();
    const pseudonym = await custody.derivePseudonym(identity, "ctx");
    expect(custody.isBound(pseudonym.keyId)).toBe(true);
    let boundDuringHostDestroy: boolean | undefined;
    store.destroyProbe = (keyId) => {
      boundDuringHostDestroy = custody.isBound(keyId);
    };
    await custody.destroyKey(pseudonym.keyId);
    expect(boundDuringHostDestroy).toBe(false);
  });

  test("destroying an identity retires its pseudonyms", async () => {
    const store = new Store();
    const custody = adapter(store, "fixedId");
    const first = await custody.generateKeypair();
    const alpha = await custody.derivePseudonym(first, "alpha");
    expect(custody.isBound(alpha.keyId)).toBe(true);
    await custody.destroyKey(first);
    expect(custody.isBound(alpha.keyId)).toBe(false);
    // The host still holds the pseudonym key; the adapter must not reach it.
    // The pseudonym died with its identity (§9.10.4.A), so it is key-not-found.
    const calls = store.signCalls;
    const err = await custody.sign(alpha.keyId, DIGEST).catch((e: unknown) => e);
    expect(mapBridgeError(err).code).toBe("SCP-CRYPTO-4006");
    expect(store.signCalls).toBe(calls);
    // A new identity's pseudonym reuses id "777" with a different point.
    const second = await custody.generateKeypair();
    const beta = await custody.derivePseudonym(second, "beta");
    expect(beta.keyId).toBe(alpha.keyId);
    expect(Buffer.from(beta.publicKey).equals(Buffer.from(alpha.publicKey))).toBe(false);
    expect((await custody.sign(beta.keyId, DIGEST)).length).toBe(64);
  });

  // §25.19 Vectors 30 and 31: each identity scalar, installed as the native
  // custody's Ed25519 seed (the §9.10.4.A native interim ikm), then derived on
  // "context-alpha" by the production pseudonym path. No bridge path derives a
  // v2 pseudonym in production; scp-crypto's §25.19 KAT covers v2.
  const SPEC_25_19_V1 = [
    {
      name: "Vector 30",
      scalar: "32c69e4a096fadd1a8d0a21e0a97f124d5c4c8c5b15b96027beadb91c2f3ec64",
      routingId: "b7faa05dea2cef1b7aff6a48fa5b7b9ffe217b25f3152d78d597bb9078e98307",
    },
    {
      name: "Vector 31",
      scalar: "65d56a863d03d31ea15ade82f677058d5bbe53afedc6ff7d2b8846aa25a1bc2b",
      routingId: "cab5ff45d21b6d0425fa7657e89fc68514965cbb4ca2b9549f4ccf430d581e7c",
    },
  ];
  for (const vector of SPEC_25_19_V1) {
    test(`§25.19 ${vector.name} v1 routing id through the bridge's pseudonym derivation`, async () => {
      const routingId = await (
        native.testingPseudonymRoutingIdFromSeed as (s: Buffer, c: string) => Promise<Buffer>
      )(Buffer.from(vector.scalar, "hex"), "context-alpha");
      expect(Buffer.from(routingId).toString("hex")).toBe(vector.routingId);
    });
  }
});
