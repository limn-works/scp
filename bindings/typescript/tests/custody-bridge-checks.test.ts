/**
 * The napi callback-custody adapter's pseudonym checks (§9.5, §9.10.4),
 * driven through the SDK's production custody record
 * (`toNativeCustodyProvider`) and the napi `TestingCallbackCustody` hook.
 *
 * Each test fails if the check it names is removed from
 * `crates/scp-ffi/napi/src/custody.rs`:
 *   - `check_sign_input`: a pseudonym key signs only a 32-byte digest, and a
 *     shorter input never reaches the host;
 *   - `check_signature`: a high-s host signature is rejected;
 *   - `unbind` in `destroy_key`: a destroyed id can carry a new point, and
 *     the id is already unbound when the host's `destroyKey` runs.
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
 * A failed `getPublicKey(keyId)` confirmation call inside a pseudonym bind
 * (a host error with any code, key-not-found included, or a wrongly typed
 * return) rejects the derivation with `SCP-IDENT-1055` (ADR-021 2026-09-27).
 */

import { describe, expect, test } from "bun:test";
import * as crypto from "node:crypto";

import { CryptoError, IdentityError, mapBridgeError } from "../src/errors";
import { toNativeCustodyProvider } from "../src/internal/custody-adapter";
import { loadNativeAddon } from "../src/internal/native";
import type { KeyCustodyProvider, PseudonymResult } from "../src/scp";
import { p256PseudonymScalar, p256PublicKey, p256SignPrehashRfc6979 } from "../src/scp";
import { bigIntTo32, bytesToBigInt, P256_N, pseudonymSeedV1 } from "./pseudonym-recipe";

interface TestingCustody {
  generateKeypair(): Promise<string>;
  derivePseudonym(identityKeyId: string, contextId: string): Promise<PseudonymResult>;
  sign(keyId: string, data: Buffer): Promise<Buffer>;
  destroyKey(keyId: string): Promise<void>;
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
type Fault = "highS" | "fixedId" | "signThrows" | "sign4001" | "lookup4006" | "lookupThrows";

/** The host's key store, with a count of `sign` calls that reach it. */
class Store {
  seeds = new Map<string, Uint8Array>();
  /** Pseudonym key id -> its 32-byte P-256 scalar (§9.10.4). */
  pseudonyms = new Map<string, Uint8Array>();
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

  generateKeypair(_keyType: string): string {
    const kid = String(this.store.next++);
    this.store.seeds.set(kid, new Uint8Array(crypto.randomBytes(32)));
    return kid;
  }

  sign(keyId: string, message: Uint8Array): Uint8Array {
    this.store.signCalls++;
    if (this.fault === "signThrows") throw new Error("keystore offline");
    if (this.fault === "sign4001") throw new CryptoError("hsm offline", "SCP-CRYPTO-4001");
    const d = this.store.pseudonyms.get(keyId);
    // The contract's key-not-found signal (`KeyCustodyProvider` in `src/scp.ts`).
    if (d === undefined) throw new CryptoError(`key not found: ${keyId}`, "SCP-CRYPTO-4006");
    const sig = p256SignPrehashRfc6979(d, message);
    if (this.fault !== "highS") return sig;
    const s = bytesToBigInt(sig.subarray(32));
    return new Uint8Array(
      Buffer.concat([Buffer.from(sig.subarray(0, 32)), bigIntTo32(P256_N - s)]),
    );
  }

  getPublicKey(keyId: string): Uint8Array {
    const d = this.store.pseudonyms.get(keyId);
    if (d !== undefined && this.fault === "lookup4006") {
      throw new CryptoError(`lookup lost ${keyId}`, "SCP-CRYPTO-4006");
    }
    if (d !== undefined && this.fault === "lookupThrows") throw new Error(`lookup lost ${keyId}`);
    if (d !== undefined) return p256PublicKey(d);
    if (this.store.seeds.has(keyId)) return new Uint8Array(32);
    throw new Error(`unknown key id: ${keyId}`);
  }

  destroyKey(keyId: string): void {
    this.store.destroyProbe?.(keyId);
    this.store.seeds.delete(keyId);
    this.store.pseudonyms.delete(keyId);
  }

  dhAgree(_keyId: string, _peerPublic: Uint8Array): Uint8Array {
    throw new Error("unused");
  }

  derivePseudonym(keyId: string, contextId: Uint8Array): PseudonymResult {
    const seed = this.store.seeds.get(keyId);
    if (seed === undefined) throw new Error(`unknown key id: ${keyId}`);
    // The host computes the context seed; the SDK helper maps it to the scalar.
    const d = p256PseudonymScalar(pseudonymSeedV1(seed, contextId));
    // Deterministic per (identity, context), as the provider contract requires;
    // `fixedId` names every pseudonym "777" to reuse one id across contexts.
    const h = crypto.createHash("sha256").update(`${keyId}|`).update(contextId).digest();
    const pseudonymId =
      this.fault === "fixedId" ? "777" : (h.readBigUInt64BE(0) | (1n << 63n)).toString();
    this.store.pseudonyms.set(pseudonymId, d);
    return { publicKey: p256PublicKey(d), keyId: pseudonymId };
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

function adapter(store: Store, fault?: Fault): TestingCustody {
  const Ctor = native.TestingCallbackCustody as TestingCustodyCtor;
  return new Ctor(toNativeCustodyProvider(new StoreKeychain(store, fault)));
}

/**
 * A provider over `store` whose `overrides` replace some methods, typed
 * loosely so a test can return what a misbehaving host returns.
 */
function adapterWith(
  store: Store,
  overrides: Record<string, (...args: unknown[]) => unknown>,
): TestingCustody {
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

  test("a high-s host signature is rejected", async () => {
    const store = new Store();
    const custody = adapter(store, "highS");
    const identity = await custody.generateKeypair();
    const pseudonym = await custody.derivePseudonym(identity, "ctx");
    const err = await custody.sign(pseudonym.keyId, DIGEST).catch((e: unknown) => e);
    expect(mapBridgeError(err).code).toBe("SCP-CRYPTO-4060");
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

  test("a host key-not-found on a pseudonym sign rejects with CryptoError SCP-CRYPTO-4006 and nothing uncaught", async () => {
    const store = new Store();
    const custody = adapter(store);
    const identity = await custody.generateKeypair();
    const pseudonym = await custody.derivePseudonym(identity, "ctx");
    expect((await custody.sign(pseudonym.keyId, DIGEST)).length).toBe(64);
    // The host no longer holds the scalar (as after it destroys the identity
    // that owns the pseudonym) while the bridge still has the id bound.
    store.pseudonyms.delete(pseudonym.keyId);
    let err: unknown;
    const uncaught = await uncaughtDuring(async () => {
      err = await custody.sign(pseudonym.keyId, DIGEST).catch((e: unknown) => e);
    });
    expect(uncaught).toEqual([]);
    const mapped = mapBridgeError(err);
    expect(mapped).toBeInstanceOf(CryptoError);
    expect(mapped.code).toBe("SCP-CRYPTO-4006");
  });

  test("a failed getPublicKey(keyId) confirmation rejects the pseudonym with SCP-IDENT-1055", async () => {
    for (const fault of ["lookup4006", "lookupThrows"] as const) {
      const custody = adapter(new Store(), fault);
      const identity = await custody.generateKeypair();
      const mapped = await rejectionOf(() => custody.derivePseudonym(identity, "ctx"));
      expect(mapped).toBeInstanceOf(IdentityError);
      expect(mapped.code).toBe("SCP-IDENT-1055");
      expect(mapped.message).toContain("lookup lost");
    }
    const wrongType = adapterWith(new Store(), { getPublicKey: () => 42 });
    const identity = await wrongType.generateKeypair();
    const mapped = await rejectionOf(() => wrongType.derivePseudonym(identity, "ctx"));
    expect(mapped).toBeInstanceOf(IdentityError);
    expect(mapped.code).toBe("SCP-IDENT-1055");
  });

  test("a non-canonical key id is SCP-CRYPTO-4060 from generateKeypair and SCP-IDENT-1055 from derivePseudonym", async () => {
    const generated = adapterWith(new Store(), { generateKeypair: () => "007" });
    const onGenerate = await rejectionOf(() => generated.generateKeypair());
    expect(onGenerate).toBeInstanceOf(CryptoError);
    expect(onGenerate.code).toBe("SCP-CRYPTO-4060");
    expect(onGenerate.message).toContain("non-canonical key_id");

    const store = new Store();
    const host = new StoreKeychain(store);
    const derived = adapterWith(store, {
      derivePseudonym: (...args: unknown[]) => {
        const [keyId, contextId] = args as [string, Uint8Array];
        const result = host.derivePseudonym(keyId, contextId);
        store.pseudonyms.set("007", store.pseudonyms.get(result.keyId) as Uint8Array);
        return { publicKey: result.publicKey, keyId: "007" };
      },
    });
    const identity = await derived.generateKeypair();
    const onDerive = await rejectionOf(() => derived.derivePseudonym(identity, "ctx"));
    expect(onDerive).toBeInstanceOf(IdentityError);
    expect(onDerive.code).toBe("SCP-IDENT-1055");
    expect(onDerive.message).toContain("non-canonical key_id");
  });

  test("a lookup that reports success with no value names get_public_key, not the derivation", async () => {
    const store = new Store();
    // The raw native record, so the bridge itself sees `{ ok: true }` with no value.
    const record = toNativeCustodyProvider(new StoreKeychain(store));
    const lookup = record.getPublicKey;
    const Ctor = native.TestingCallbackCustody as TestingCustodyCtor;
    // Typed loosely: `{ ok: true }` with no value is the misbehaviour under test.
    const broken: Record<string, unknown> = {
      ...record,
      getPublicKey: (keyId: string) => (store.pseudonyms.has(keyId) ? { ok: true } : lookup(keyId)),
    };
    const custody = new Ctor(broken as ReturnType<typeof toNativeCustodyProvider>);
    const identity = await custody.generateKeypair();
    const mapped = await rejectionOf(() => custody.derivePseudonym(identity, "ctx"));
    expect(mapped).toBeInstanceOf(IdentityError);
    expect(mapped.code).toBe("SCP-IDENT-1055");
    expect(mapped.message).toContain(
      "KeyCustodyProvider.derive_pseudonym: get_public_key(key_id) failed",
    );
    expect(mapped.message).toContain(
      "KeyCustodyProvider.get_public_key reported success with no value",
    );
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
    // Observed through behaviour: a bound pseudonym id rejects a 5-byte input
    // in `check_sign_input` before the host is called (SCP-CRYPTO-4060, no host
    // `sign`); an unbound id passes the input to the host's `sign`. The testing
    // `sign` runs that check on the JS thread before it returns, so a `sign`
    // issued inside the host's `destroyKey` reads the binding table as it
    // stands during that host call.
    const store = new Store();
    const custody = adapter(store);
    const identity = await custody.generateKeypair();
    const pseudonym = await custody.derivePseudonym(identity, "ctx");
    const short = Buffer.alloc(5);
    const whileBound = await rejectionOf(() => custody.sign(pseudonym.keyId, short));
    expect(whileBound.code).toBe("SCP-CRYPTO-4060");
    expect(store.signCalls).toBe(0);

    let duringHostDestroy: Promise<Buffer> | undefined;
    store.destroyProbe = (keyId) => {
      duringHostDestroy = custody.sign(keyId, short);
      // Marks it handled now: its rejection can land before `rejectionOf`
      // attaches, which bun would report as unhandled. `rejectionOf` still
      // reads the rejection from the same promise.
      duringHostDestroy.catch(() => undefined);
    };
    await custody.destroyKey(pseudonym.keyId);
    expect(duringHostDestroy).toBeDefined();
    const mapped = await rejectionOf(() => duringHostDestroy as Promise<Buffer>);
    // Reached the host (already unbound), which by then had deleted the key.
    expect(store.signCalls).toBe(1);
    expect(mapped.code).toBe("SCP-CRYPTO-4006");
  });
});
