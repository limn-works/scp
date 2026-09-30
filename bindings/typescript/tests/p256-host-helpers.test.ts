/**
 * The SDK's P-256 custody-host helpers (`p256PseudonymPoint`,
 * `p256SoftwarePseudonymPoint`, `p256PseudonymScalar`, `p256PublicKey`,
 * `p256SignPrehashRfc6979`, exported from the package root) against pinned
 * outputs:
 *   - spec §25.19 Vectors 30 and 31: each `identity_scalar` over
 *     "context-alpha" gives the v1 point, and at epoch 1 the v2 point; each
 *     context seed gives its point directly;
 *   - spec §25.19 Vectors 30 and 31: each `context_seed_v1` and
 *     `context_seed_v2` maps through `p256PseudonymScalar` (whose
 *     `SCP-PSEUDONYM-P256-V1` label is fixed inside the helper) and
 *     `p256PublicKey` to the spec's v1 and v2 points;
 *   - RFC 6979 A.2.5 (P-256, SHA-256, "sample"): the RFC's `r`, and the low-s
 *     form of the RFC's `s` (the two sum to `n`, §9.5);
 *   - the independent recipe in `./pseudonym-recipe`, which signs the same
 *     bytes for the same scalar and digest;
 *   - malformed input rejected with `SCP-VALID-7005` or `SCP-CRYPTO-4001`.
 *
 * Skips when the native addon is not installed.
 */

import { describe, expect, test } from "bun:test";
import * as crypto from "node:crypto";

import { CryptoError, type ScpError, ValidationError } from "../src/errors";
import {
  p256PseudonymPoint,
  p256PseudonymScalar,
  p256PublicKey,
  p256SignPrehashRfc6979,
  p256SoftwarePseudonymPoint,
} from "../src/index";
import { loadNativeAddon } from "../src/internal/native";
import { __p256HostInvokeForTests } from "../src/scp";
import { bytesToBigInt, P256_N, p256SignPrehash } from "./pseudonym-recipe";

let skipReason = "";
try {
  if (typeof loadNativeAddon().p256SoftwarePseudonymPoint !== "function") {
    skipReason = "native addon predates the P-256 host helpers";
  }
} catch (e: unknown) {
  skipReason = `native addon not available: ${e instanceof Error ? e.message : String(e)}`;
}

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const unhex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));

// §25.19 values, copied verbatim from the spec.
const VECTORS = [
  {
    name: "Vector 30",
    identityScalar: "32c69e4a096fadd1a8d0a21e0a97f124d5c4c8c5b15b96027beadb91c2f3ec64",
    seedV1: "47ea801c24e8a4d577f04837eca0674fbbf160127fa2d1a4bb1420150b0a048b",
    v1: "0367e9d3809d6f9bc6854132aff27c2a399463bb516db76f844d79a7b0453c8f72",
    seedV2: "6ab63aa150992ff032f6963c31dc9f5a8bd4e9518516f9fbd3bea7bc07f64b38",
    v2: "0276c50b92dacbe6ae1a3761d007b7fe75016a4c076f214694c95d13162ff24479",
  },
  {
    name: "Vector 31",
    identityScalar: "65d56a863d03d31ea15ade82f677058d5bbe53afedc6ff7d2b8846aa25a1bc2b",
    seedV1: "5157d14a2362044199ba88d66d6a52a4bfbe0598ebe921c5fb9c362d3bebaedd",
    v1: "0239f7c3213f3567183fd2fcf7aec6c884bc70e0e694c42053284a4b5ebef4fe2d",
    seedV2: "8133a9d716dcbe729b1f447ac0efccf3795e8bf28da2db4744090d0316ead730",
    v2: "037967cfe8d3111cdd72288ea3f444c15b710300323162fec63ca9036af73754e3",
  },
];

describe.skipIf(skipReason !== "")(`P-256 host helpers ${skipReason}`, () => {
  const contextAlpha = new TextEncoder().encode("context-alpha");

  for (const v of VECTORS) {
    test(`${v.name}: software pseudonym point reproduces spec 25.19`, () => {
      const ikm = unhex(v.identityScalar);
      expect(hex(p256SoftwarePseudonymPoint(ikm, contextAlpha))).toBe(v.v1);
      expect(hex(p256SoftwarePseudonymPoint(ikm, contextAlpha, 1n))).toBe(v.v2);
      expect(hex(ikm)).toBe(v.identityScalar);
    });

    test(`${v.name}: pseudonym point reproduces spec 25.19`, () => {
      expect(hex(p256PseudonymPoint(unhex(v.seedV1)))).toBe(v.v1);
      expect(hex(p256PseudonymPoint(unhex(v.seedV2)))).toBe(v.v2);
    });
  }

  test("point helpers reject a wrong-length seed with SCP-VALID-7005", () => {
    for (const size of [0, 31, 33]) {
      for (const call of [
        () => p256PseudonymPoint(new Uint8Array(size)),
        () => p256SoftwarePseudonymPoint(new Uint8Array(size), contextAlpha),
      ]) {
        let caught: unknown;
        try {
          call();
        } catch (e: unknown) {
          caught = e;
        }
        expect(caught).toBeInstanceOf(ValidationError);
        expect((caught as ScpError).code).toBe("SCP-VALID-7005");
      }
    }
  });

  test("a negative epoch is rejected with SCP-VALID-7005", () => {
    let caught: unknown;
    try {
      p256SoftwarePseudonymPoint(new Uint8Array(32).fill(1), contextAlpha, -1n);
    } catch (e: unknown) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ValidationError);
    expect((caught as ScpError).code).toBe("SCP-VALID-7005");
  });

  for (const v of VECTORS) {
    test(`${v.name}: context seeds map to the spec's v1 and v2 points`, () => {
      const d1 = p256PseudonymScalar(unhex(v.seedV1));
      expect(d1.length).toBe(32);
      expect(hex(p256PublicKey(d1))).toBe(v.v1);
      expect(hex(p256PublicKey(p256PseudonymScalar(unhex(v.seedV2))))).toBe(v.v2);
    });
  }

  test("returns a fresh scalar on each call and leaves the caller's seed intact", () => {
    // §25.19 Vector 30, v1.
    const seedHex = "47ea801c24e8a4d577f04837eca0674fbbf160127fa2d1a4bb1420150b0a048b";
    const seed = unhex(seedHex);
    const d = p256PseudonymScalar(seed);
    const dHex = hex(d);
    expect(hex(seed)).toBe(seedHex);
    // Wiping the returned scalar must not reach a later call's result.
    d.fill(0);
    expect(hex(p256PseudonymScalar(seed))).toBe(dHex);
  });

  test("RFC 6979 A.2.5: the RFC's r and the low-s form of its s", () => {
    const x = unhex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
    const digest = new Uint8Array(crypto.createHash("sha256").update("sample").digest());
    const sig = p256SignPrehashRfc6979(x, digest);
    expect(sig.length).toBe(64);
    expect(hex(sig.subarray(0, 32))).toBe(
      "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
    );
    const rfcS = 0xf7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8n;
    expect(bytesToBigInt(sig.subarray(32)) + rfcS).toBe(P256_N);
    expect(hex(p256SignPrehashRfc6979(x, digest))).toBe(hex(sig));
  });

  test("signatures equal the independent recipe's for the same scalar and digest", () => {
    const d = p256PseudonymScalar(
      unhex("47ea801c24e8a4d577f04837eca0674fbbf160127fa2d1a4bb1420150b0a048b"),
    );
    for (let i = 0; i < 8; i++) {
      const digest = new Uint8Array(crypto.createHash("sha256").update(`msg-${i}`).digest());
      expect(hex(p256SignPrehashRfc6979(d, digest))).toBe(
        hex(p256SignPrehash(bytesToBigInt(d), digest)),
      );
    }
  });

  test("malformed input is rejected with its code", () => {
    const expectCode = (
      f: () => unknown,
      cls: new (...args: never[]) => ScpError,
      code: string,
    ) => {
      let caught: unknown;
      try {
        f();
      } catch (e: unknown) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(cls);
      expect((caught as ScpError).code).toBe(code);
    };
    expectCode(() => p256PseudonymScalar(new Uint8Array(31)), ValidationError, "SCP-VALID-7005");
    expectCode(() => p256PublicKey(new Uint8Array(33).fill(1)), ValidationError, "SCP-VALID-7005");
    expectCode(() => p256PublicKey(new Uint8Array(32)), CryptoError, "SCP-CRYPTO-4001");
    expectCode(() => p256PublicKey(new Uint8Array(32).fill(0xff)), CryptoError, "SCP-CRYPTO-4001");
    expectCode(
      () => p256SignPrehashRfc6979(new Uint8Array(32).fill(1), new Uint8Array(12)),
      ValidationError,
      "SCP-VALID-7005",
    );
  });
});

describe("P-256 host call wiping (stubbed native function)", () => {
  const seed = new Uint8Array(32).fill(0x11);
  const digest = new Uint8Array(32).fill(0x22);

  test("passes number[] copies of the arguments, then wipes them and leaves the caller's seed intact", () => {
    let passed: number[][] = [];
    let valuesAtCall: number[][] = [];
    __p256HostInvokeForTests(
      (...a) => {
        passed = a;
        valuesAtCall = a.map((r) => r.slice());
        return new Array<number>(32).fill(0x33);
      },
      [seed, digest],
    );
    expect(valuesAtCall).toEqual([Array.from(seed), Array.from(digest)]);
    expect(passed.length).toBe(2);
    for (const r of passed) {
      expect(r).toEqual(new Array<number>(32).fill(0));
    }
    expect(seed.every((b) => b === 0x11)).toBe(true);
  });

  test("copies a number[] result into the returned Uint8Array, then wipes the number[]", () => {
    const result = new Array<number>(32).fill(0x44);
    const out = __p256HostInvokeForTests(() => result, [seed]);
    expect(out).toBeInstanceOf(Uint8Array);
    expect(Array.from(out)).toEqual(new Array<number>(32).fill(0x44));
    expect(result).toEqual(new Array<number>(32).fill(0));
  });

  test("wipes the argument copies when the native function throws", () => {
    let passed: number[][] = [];
    expect(() =>
      __p256HostInvokeForTests(
        (...a) => {
          passed = a;
          throw new Error("boom");
        },
        [seed, digest],
      ),
    ).toThrow();
    expect(passed.length).toBe(2);
    for (const r of passed) {
      expect(r).toEqual(new Array<number>(32).fill(0));
    }
  });
});
