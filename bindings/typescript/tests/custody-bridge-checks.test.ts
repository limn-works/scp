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
 * It also runs the §25.19 Vector 30 identity scalar through the bridge's
 * production pseudonym derivation and compares the routing id to the spec.
 */

import { describe, expect, test } from "bun:test";
import * as crypto from "node:crypto";

import { toNativeCustodyProvider } from "../src/internal/custody-adapter";
import { loadNativeAddon } from "../src/internal/native";
import type { KeyCustodyProvider, PseudonymResult } from "../src/scp";
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
type Fault = "highS" | "fixedId";

/** The host's key store, with a count of `sign` calls that reach it. */
class Store {
  seeds = new Map<string, Uint8Array>();
  pseudonyms = new Map<string, bigint>();
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
    const d = this.store.pseudonyms.get(keyId);
    if (d === undefined) throw new Error(`not a pseudonym key: ${keyId}`);
    const sig = p256SignPrehash(d, message);
    if (this.fault !== "highS") return sig;
    const s = bytesToBigInt(sig.subarray(32));
    return new Uint8Array(
      Buffer.concat([Buffer.from(sig.subarray(0, 32)), bigIntTo32(P256_N - s)]),
    );
  }

  getPublicKey(keyId: string): Uint8Array {
    const d = this.store.pseudonyms.get(keyId);
    if (d !== undefined) return p256Compressed(d);
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
    const d = pseudonymScalar(pseudonymSeedV1(seed, contextId));
    // Deterministic per (identity, context), as the provider contract requires;
    // `fixedId` names every pseudonym "777" to reuse one id across contexts.
    const h = crypto.createHash("sha256").update(`${keyId}|`).update(contextId).digest();
    const pseudonymId =
      this.fault === "fixedId" ? "777" : (h.readBigUInt64BE(0) | (1n << 63n)).toString();
    this.store.pseudonyms.set(pseudonymId, d);
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

function adapter(store: Store, fault?: Fault): TestingCustody {
  const Ctor = native.TestingCallbackCustody as TestingCustodyCtor;
  return new Ctor(toNativeCustodyProvider(new StoreKeychain(store, fault)));
}

const DIGEST = crypto.createHash("sha256").update("custody-bridge-checks").digest();

describe.skipIf(skipReason !== "")("napi callback custody pseudonym checks", () => {
  test("a pseudonym key signs a 32-byte digest and nothing shorter reaches the host", async () => {
    const store = new Store();
    const custody = adapter(store);
    const identity = await custody.generateKeypair();
    const pseudonym = await custody.derivePseudonym(identity, "ctx");
    expect((await custody.sign(pseudonym.keyId, DIGEST)).length).toBe(64);
    const calls = store.signCalls;
    await expect(custody.sign(pseudonym.keyId, Buffer.alloc(12))).rejects.toThrow(/32-byte/);
    expect(store.signCalls).toBe(calls);
  });

  test("a high-s host signature is rejected", async () => {
    const store = new Store();
    const custody = adapter(store, "highS");
    const identity = await custody.generateKeypair();
    const pseudonym = await custody.derivePseudonym(identity, "ctx");
    await expect(custody.sign(pseudonym.keyId, DIGEST)).rejects.toThrow();
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

  test("§25.19 Vector 30 routing id through the bridge's pseudonym derivation", async () => {
    // The §25.19 identity scalar of Vector 30, installed as the native custody's
    // Ed25519 seed (the §9.10.4.A native interim ikm), then derived on
    // "context-alpha" by the production pseudonym path.
    const scalar = Buffer.from(
      "32c69e4a096fadd1a8d0a21e0a97f124d5c4c8c5b15b96027beadb91c2f3ec64",
      "hex",
    );
    const routingId = await (
      native.testingPseudonymRoutingIdFromSeed as (s: Buffer, c: string) => Promise<Buffer>
    )(scalar, "context-alpha");
    expect(Buffer.from(routingId).toString("hex")).toBe(
      "b7faa05dea2cef1b7aff6a48fa5b7b9ffe217b25f3152d78d597bb9078e98307",
    );
  });
});
