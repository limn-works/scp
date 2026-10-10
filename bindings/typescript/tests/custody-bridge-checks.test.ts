/**
 * The napi callback-custody adapter (§9.10.4), driven through the SDK's
 * production custody record (`toNativeCustodyProvider`) and the napi
 * `TestingCallbackCustody` hook, whose derivations return the 32-byte routing
 * id the bridge computes from the host's point.
 *
 * The forwarding test fails if `derive_pseudonym` or
 * `derive_rotatable_pseudonym` in `crates/scp-ffi/napi/src/custody.rs`, or
 * `derivePseudonym` or `deriveRotatablePseudonym` in
 * `src/internal/custody-adapter.ts`, hands the host anything but the caller's
 * context bytes and epoch, routes v2 to the v1 callback, or computes any
 * routing id but §25.19 Vector 30's from the host's point.
 *
 * The derivation-failure tests fail if the bridge accepts host bytes that are
 * not a compressed P-256 point (`SCP-IDENT-1055`) or reports a host
 * key-not-found as anything but `SCP-CRYPTO-4006`.
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
 * The secret-wipe tests fail if `dhAgree` or `exportSigningKeyBytes` in
 * `src/internal/custody-adapter.ts` stops zero-filling the adapter's copy of
 * the host secret once napi-rs has read it, wipes it before the bridge reads
 * it (the bridge would then return zeros), or writes to the host's buffer.
 */

import { describe, expect, test } from "bun:test";
import * as crypto from "node:crypto";

import { CryptoError, IdentityError, mapBridgeError } from "../src/errors";
import { toNativeCustodyProvider } from "../src/internal/custody-adapter";
import { loadNativeAddon } from "../src/internal/native";
import type { KeyCustodyProvider } from "../src/scp";
import { p256SoftwarePseudonymPoint } from "../src/scp";

interface TestingCustody {
  generateKeypair(): Promise<string>;
  /** Returns the 32-byte routing id of the host's v1 point. */
  derivePseudonym(identityKeyId: string, contextId: string): Promise<Buffer>;
  /** Returns the 32-byte routing id of the host's v2 point. */
  deriveRotatablePseudonym(
    identityKeyId: string,
    contextId: string,
    epoch: bigint,
  ): Promise<Buffer>;
  sign(keyId: string, data: Buffer): Promise<Buffer>;
  /** Returns the 32-byte shared secret the bridge read from the host. */
  dhAgree(keyId: string, peerPublic: Buffer): Promise<Buffer>;
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

/** A host fault the keychain injects into signing or derivation. */
type Fault = "signThrows" | "sign4001" | "legacy32";

/** A host keychain of Ed25519 identity seeds; it stores no pseudonym. */
class StoreKeychain implements KeyCustodyProvider {
  seeds = new Map<string, Uint8Array>();
  next = 1;

  constructor(readonly fault?: Fault) {}

  generateKeypair(_keyType: string): string {
    const kid = String(this.next++);
    this.seeds.set(kid, new Uint8Array(crypto.randomBytes(32)));
    return kid;
  }

  #seed(keyId: string): Uint8Array {
    const seed = this.seeds.get(keyId);
    // The contract's key-not-found signal (`KeyCustodyProvider` in `src/scp.ts`).
    if (seed === undefined) throw new CryptoError(`key not found: ${keyId}`, "SCP-CRYPTO-4006");
    return seed;
  }

  sign(keyId: string, message: Uint8Array): Uint8Array {
    if (this.fault === "signThrows") throw new Error("keystore offline");
    if (this.fault === "sign4001") throw new CryptoError("hsm offline", "SCP-CRYPTO-4001");
    const der = Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.from(this.#seed(keyId)),
    ]);
    const key = crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    return new Uint8Array(crypto.sign(null, Buffer.from(message), key));
  }

  getPublicKey(_keyId: string): Uint8Array {
    throw new Error("unused");
  }

  destroyKey(keyId: string): void {
    this.seeds.delete(keyId);
  }

  dhAgree(_keyId: string, _peerPublic: Uint8Array): Uint8Array {
    throw new Error("unused");
  }

  derivePseudonym(keyId: string, contextId: Uint8Array): Uint8Array {
    // The SDK's software helper derives the point; the host stores nothing.
    const point = p256SoftwarePseudonymPoint(this.#seed(keyId), contextId);
    // A host still on the retired 32-byte Ed25519 pseudonym shape.
    return this.fault === "legacy32" ? point.subarray(1) : point;
  }

  deriveRotatablePseudonym(): Uint8Array {
    throw new Error("unused");
  }

  exportSigningKeyBytes(_keyId: string): Uint8Array {
    throw new Error("unused");
  }

  custodyType(_keyId: string): string {
    return "software";
  }
}

function adapter(host: StoreKeychain): TestingCustody {
  const Ctor = native.TestingCallbackCustody as TestingCustodyCtor;
  return new Ctor(toNativeCustodyProvider(host));
}

/**
 * A provider whose `overrides` replace some methods, typed loosely so a test
 * can return what a misbehaving host returns.
 */
function adapterWith(overrides: Record<string, (...args: unknown[]) => unknown>): TestingCustody {
  const Ctor = native.TestingCallbackCustody as TestingCustodyCtor;
  const provider = Object.assign(new StoreKeychain(), overrides) as KeyCustodyProvider;
  return new Ctor(toNativeCustodyProvider(provider));
}

const MESSAGE = Buffer.from("custody-bridge-checks");

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

describe.skipIf(skipReason !== "")("napi callback custody", () => {
  test("the host receives the caller's context and epoch unchanged and the bridge returns the §25.19 Vector 30 routing ids", async () => {
    // §25.19 Vector 30 (`context_id` = "context-alpha", epoch 1): the points
    // and routing ids, copied verbatim from the spec.
    const V1 = "0367e9d3809d6f9bc6854132aff27c2a399463bb516db76f844d79a7b0453c8f72";
    const V2 = "0276c50b92dacbe6ae1a3761d007b7fe75016a4c076f214694c95d13162ff24479";
    const V1_ROUTING = "b7faa05dea2cef1b7aff6a48fa5b7b9ffe217b25f3152d78d597bb9078e98307";
    const V2_ROUTING = "b19754a5e88c993683f99e48646ba518cba80dec0693f920c5671263650b6ae9";
    const received: unknown[][] = [];
    const custody = adapterWith({
      derivePseudonym: (...args: unknown[]) => {
        received.push(["v1", ...args]);
        return new Uint8Array(Buffer.from(V1, "hex"));
      },
      deriveRotatablePseudonym: (...args: unknown[]) => {
        received.push(["v2", ...args]);
        return new Uint8Array(Buffer.from(V2, "hex"));
      },
    });
    const identity = await custody.generateKeypair();
    const v1 = await custody.derivePseudonym(identity, "context-alpha");
    const v2 = await custody.deriveRotatablePseudonym(identity, "context-alpha", 1n);
    const context = new Uint8Array(Buffer.from("context-alpha"));
    expect(received).toEqual([
      ["v1", identity, context],
      ["v2", identity, context, 1n],
    ]);
    expect(Buffer.from(v1).toString("hex")).toBe(V1_ROUTING);
    expect(Buffer.from(v2).toString("hex")).toBe(V2_ROUTING);
  });

  test("host pseudonym bytes that are not a compressed P-256 point reject with SCP-IDENT-1055", async () => {
    const custody = adapter(new StoreKeychain("legacy32"));
    const identity = await custody.generateKeypair();
    const mapped = await rejectionOf(() => custody.derivePseudonym(identity, "ctx"));
    expect(mapped).toBeInstanceOf(IdentityError);
    expect(mapped.code).toBe("SCP-IDENT-1055");
    expect(mapped.message).toContain("got 32 bytes");
  });

  test("deriving under a destroyed identity rejects with CryptoError SCP-CRYPTO-4006", async () => {
    const custody = adapter(new StoreKeychain());
    const identity = await custody.generateKeypair();
    await custody.derivePseudonym(identity, "ctx");
    await custody.destroyKey(identity);
    const mapped = await rejectionOf(() => custody.derivePseudonym(identity, "ctx"));
    expect(mapped).toBeInstanceOf(CryptoError);
    expect(mapped.code).toBe("SCP-CRYPTO-4006");
  });

  test("a non-canonical key id from generateKeypair is SCP-CRYPTO-4060", async () => {
    const generated = adapterWith({ generateKeypair: () => "007" });
    const onGenerate = await rejectionOf(() => generated.generateKeypair());
    expect(onGenerate).toBeInstanceOf(CryptoError);
    expect(onGenerate.code).toBe("SCP-CRYPTO-4060");
    expect(onGenerate.message).toContain("non-canonical key_id");
  });

  test("a host method that throws another error rejects with a custody error", async () => {
    const custody = adapter(new StoreKeychain("signThrows"));
    const identity = await custody.generateKeypair();
    let err: unknown;
    const uncaught = await uncaughtDuring(async () => {
      err = await custody.sign(identity, MESSAGE).catch((e: unknown) => e);
    });
    expect(uncaught).toEqual([]);
    const mapped = mapBridgeError(err);
    expect(mapped.code).toBe("SCP-CRYPTO-4060");
    expect(mapped.message).toContain("keystore offline");
  });

  test("a host error carrying the generic SCP-CRYPTO-4001 is a custody error, not key-not-found", async () => {
    const custody = adapter(new StoreKeychain("sign4001"));
    const identity = await custody.generateKeypair();
    const err = await custody.sign(identity, MESSAGE).catch((e: unknown) => e);
    const mapped = mapBridgeError(err);
    expect(mapped.code).toBe("SCP-CRYPTO-4060");
    expect(mapped.message).toContain("SCP-CRYPTO-4001");
    expect(mapped.message).toContain("hsm offline");
  });

  test("an async host method's rejection is a custody error, never an unhandled rejection", async () => {
    const custody = adapterWith({
      sign: () => Promise.reject(new Error("async keystore offline")),
    });
    const identity = await custody.generateKeypair();
    const mapped = await rejectionOf(() => custody.sign(identity, MESSAGE));
    expect(mapped).toBeInstanceOf(CryptoError);
    expect(mapped.code).toBe("SCP-CRYPTO-4060");
    expect(mapped.message).toContain("Promise");
  });

  test("a wrongly typed or asynchronous host return is a custody error", async () => {
    const wrongType = adapterWith({ generateKeypair: () => 42 });
    const mapped = await rejectionOf(() => wrongType.generateKeypair());
    expect(mapped).toBeInstanceOf(CryptoError);
    expect(mapped.code).toBe("SCP-CRYPTO-4060");
    expect(mapped.message).toContain("not a string");

    const asyncKeypair = adapterWith({ generateKeypair: () => Promise.resolve("1") });
    expect((await rejectionOf(() => asyncKeypair.generateKeypair())).code).toBe("SCP-CRYPTO-4060");

    // A thenable whose `then` rejects is settled against a no-op handler.
    const thenable = adapterWith({
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
      const custody = adapterWith({
        sign: () => {
          throw thrown;
        },
      });
      const identity = await custody.generateKeypair();
      const mapped = await rejectionOf(() => custody.sign(identity, MESSAGE));
      expect(mapped).toBeInstanceOf(CryptoError);
      expect(mapped.code).toBe("SCP-CRYPTO-4060");
    }
  });

  test("the bridge reads the host's shared secret intact, then the adapter's copy is zeroed", async () => {
    // A secret no wipe or truncation produces: 32 distinct non-zero bytes.
    const secret = Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + i);
    const peer = Buffer.alloc(32, 0x5c);
    const seen: unknown[][] = [];
    const custody = adapterWith({
      dhAgree: (...args: unknown[]) => {
        seen.push(args);
        return secret;
      },
    });
    const identity = await custody.generateKeypair();
    const shared = await custody.dhAgree(identity, peer);
    expect(Buffer.from(shared).toString("hex")).toBe(Buffer.from(secret).toString("hex"));
    expect(seen).toEqual([[identity, new Uint8Array(peer)]]);
    // The host's own buffer is the host's to wipe.
    expect(secret.every((b, i) => b === 0xa0 + i)).toBe(true);
  });

  for (const method of ["dhAgree", "exportSigningKeyBytes"] as const) {
    test(`${method}: the adapter's copy of the host secret is zero after the bridge's synchronous read`, async () => {
      const secret = Uint8Array.from({ length: 32 }, (_, i) => 0x40 + i);
      const provider = Object.assign(new StoreKeychain(), {
        [method]: () => secret,
      }) as KeyCustodyProvider;
      const record = toNativeCustodyProvider(provider);
      const result =
        method === "dhAgree"
          ? record.dhAgree(["1", Array.from(Buffer.alloc(32, 1))])
          : record.exportSigningKeyBytes("1");
      if (!result.ok) throw new Error(`host call failed: ${result.message}`);
      const copy = result.value;
      // What napi-rs copies into Rust as the callback returns.
      expect(copy).toEqual(Array.from(secret));
      await new Promise((resolve) => setTimeout(resolve, 0));
      expect(copy).toEqual(new Array(32).fill(0));
      expect(secret.every((b, i) => b === 0x40 + i)).toBe(true);
    });
  }
});
