/**
 * Byte-level Known-Answer Test (KAT) for per-context pseudonym derivation
 * (spec §9.10.4.A, §25.19 vectors 30 & 31).
 *
 * The shared TypeScript recipe in `./pseudonym-recipe` gives the identity
 * scalar, `pseudonym_secret` and both context seeds, each checked against the
 * §25.19 literal as setup. The production helpers `p256PseudonymScalar` and
 * `p256PublicKey` (the napi exports of `scp_ffi_common::p256_host`) then map
 * each seed to the 33-byte compressed public key, and both points and both
 * routing ids are compared to the literal §25.19 bytes, so a label or
 * reduction change in the production helper fails these tests. The §25.19
 * vectors map the identity seed to a scalar with the §25.2 label
 * `"SCP-TEST-VECTOR-KEY-V1"`; that 32-byte scalar is the ikm.
 *
 * The point checks skip when the native addon is not installed. The
 * production bridge path (Vector 30 through the napi pseudonym derivation) is
 * checked in `custody-bridge-checks.test.ts`.
 */

import { describe, expect, test } from "bun:test";

import { p256PseudonymScalar, p256PublicKey } from "../src/index";
import { loadNativeAddon } from "../src/internal/native";
import {
  bigIntTo32,
  pseudonymRoutingId,
  pseudonymSecret,
  pseudonymSeedV1,
  pseudonymSeedV2,
  seedToScalar,
} from "./pseudonym-recipe";

let skipReason = "";
try {
  if (typeof loadNativeAddon().p256PseudonymScalar !== "function") {
    skipReason = "native addon predates the P-256 host helpers";
  }
} catch (e: unknown) {
  skipReason = `native addon not available: ${e instanceof Error ? e.message : String(e)}`;
}

const CONTEXT_ALPHA = new Uint8Array(Buffer.from("context-alpha", "utf-8"));
const IDENTITY_LABEL = "SCP-TEST-VECTOR-KEY-V1";

interface Kat {
  name: string;
  seed: Uint8Array;
  scalar: string;
  secret: string;
  seedV1: string;
  v1: string;
  ridV1: string;
  seedV2: string;
  v2: string;
  ridV2: string;
}

// §25.19 vectors, every value copied verbatim from the spec.
const VECTORS: readonly Kat[] = [
  {
    name: "Vector 30 (seed 0x01 x 32)",
    seed: new Uint8Array(Buffer.alloc(32, 0x01)),
    scalar: "32c69e4a096fadd1a8d0a21e0a97f124d5c4c8c5b15b96027beadb91c2f3ec64",
    secret: "b88e781bb954a6681abc9016f8f69939f0e624311aeaa7e8f1b145857f58de82",
    seedV1: "47ea801c24e8a4d577f04837eca0674fbbf160127fa2d1a4bb1420150b0a048b",
    v1: "0367e9d3809d6f9bc6854132aff27c2a399463bb516db76f844d79a7b0453c8f72",
    ridV1: "b7faa05dea2cef1b7aff6a48fa5b7b9ffe217b25f3152d78d597bb9078e98307",
    seedV2: "6ab63aa150992ff032f6963c31dc9f5a8bd4e9518516f9fbd3bea7bc07f64b38",
    v2: "0276c50b92dacbe6ae1a3761d007b7fe75016a4c076f214694c95d13162ff24479",
    ridV2: "b19754a5e88c993683f99e48646ba518cba80dec0693f920c5671263650b6ae9",
  },
  {
    name: "Vector 31 (seed 0x9d,0x01..0x1f)",
    seed: new Uint8Array(
      Buffer.from("9d0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex"),
    ),
    scalar: "65d56a863d03d31ea15ade82f677058d5bbe53afedc6ff7d2b8846aa25a1bc2b",
    secret: "17ef25ad3e5be8adad38c4c5a1c68d3daca80015e81bdcae2ae8940645774739",
    seedV1: "5157d14a2362044199ba88d66d6a52a4bfbe0598ebe921c5fb9c362d3bebaedd",
    v1: "0239f7c3213f3567183fd2fcf7aec6c884bc70e0e694c42053284a4b5ebef4fe2d",
    ridV1: "cab5ff45d21b6d0425fa7657e89fc68514965cbb4ca2b9549f4ccf430d581e7c",
    seedV2: "8133a9d716dcbe729b1f447ac0efccf3795e8bf28da2db4744090d0316ead730",
    v2: "037967cfe8d3111cdd72288ea3f444c15b710300323162fec63ca9036af73754e3",
    ridV2: "3c0ac4dec86c0dafe38195a7b66cdfec6b0ae0d44834c6e8b6b6129e097b5e27",
  },
] as const;

const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const ikmOf = (vec: Kat): Uint8Array => bigIntTo32(seedToScalar(IDENTITY_LABEL, vec.seed));

describe("per-context pseudonym derivation KAT (§25.19)", () => {
  for (const vec of VECTORS) {
    test(`${vec.name}: identity scalar and pseudonym_secret match spec`, () => {
      const ikm = ikmOf(vec);
      expect(hex(ikm)).toBe(vec.scalar);
      expect(hex(pseudonymSecret(ikm))).toBe(vec.secret);
    });

    test.skipIf(skipReason !== "")(
      `${vec.name}: v1 seed, production point and routing id match spec ${skipReason}`,
      () => {
        const ikm = ikmOf(vec);
        const seed = pseudonymSeedV1(ikm, CONTEXT_ALPHA);
        expect(hex(seed)).toBe(vec.seedV1);
        const point = p256PublicKey(p256PseudonymScalar(seed));
        expect(hex(point)).toBe(vec.v1);
        expect(hex(pseudonymRoutingId(point))).toBe(vec.ridV1);
      },
    );

    test.skipIf(skipReason !== "")(
      `${vec.name}: v2 (epoch 1) seed, production point and routing id match spec ${skipReason}`,
      () => {
        const ikm = ikmOf(vec);
        const seed = pseudonymSeedV2(ikm, CONTEXT_ALPHA, 1n);
        expect(hex(seed)).toBe(vec.seedV2);
        const point = p256PublicKey(p256PseudonymScalar(seed));
        expect(hex(point)).toBe(vec.v2);
        expect(hex(pseudonymRoutingId(point))).toBe(vec.ridV2);
      },
    );
  }
});
