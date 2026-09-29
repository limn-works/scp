/**
 * Byte-level Known-Answer Test (KAT) for per-context pseudonym derivation
 * (spec §9.10.4.A, §25.19 vectors 30 & 31).
 *
 * Each test feeds a vector's literal §25.19 `seed_v1` or `seed_v2` (epoch 1)
 * to the production helpers `p256PseudonymScalar` and `p256PublicKey` (the
 * napi exports of `scp_ffi_common::p256_host`) and compares the 33-byte
 * compressed point to the spec's `v1` or `v2`, so a label or reduction change
 * in that helper fails them. They skip when the native addon is not
 * installed. No test here checks the `pseudonym_secret` or context-seed step
 * on its own; the production bridge path (Vector 30 through the napi
 * pseudonym derivation, compared to the spec's routing id) is checked in
 * `custody-bridge-checks.test.ts`.
 */

import { describe, expect, test } from "bun:test";

import { p256PseudonymScalar, p256PublicKey } from "../src/index";
import { loadNativeAddon } from "../src/internal/native";

let skipReason = "";
try {
  if (typeof loadNativeAddon().p256PseudonymScalar !== "function") {
    skipReason = "native addon predates the P-256 host helpers";
  }
} catch (e: unknown) {
  skipReason = `native addon not available: ${e instanceof Error ? e.message : String(e)}`;
}

interface Kat {
  name: string;
  seedV1: string;
  v1: string;
  seedV2: string;
  v2: string;
}

// §25.19 vectors (context_id "context-alpha"), every value copied verbatim from the spec.
const VECTORS: readonly Kat[] = [
  {
    name: "Vector 30 (seed 0x01 x 32)",
    seedV1: "47ea801c24e8a4d577f04837eca0674fbbf160127fa2d1a4bb1420150b0a048b",
    v1: "0367e9d3809d6f9bc6854132aff27c2a399463bb516db76f844d79a7b0453c8f72",
    seedV2: "6ab63aa150992ff032f6963c31dc9f5a8bd4e9518516f9fbd3bea7bc07f64b38",
    v2: "0276c50b92dacbe6ae1a3761d007b7fe75016a4c076f214694c95d13162ff24479",
  },
  {
    name: "Vector 31 (seed 0x9d,0x01..0x1f)",
    seedV1: "5157d14a2362044199ba88d66d6a52a4bfbe0598ebe921c5fb9c362d3bebaedd",
    v1: "0239f7c3213f3567183fd2fcf7aec6c884bc70e0e694c42053284a4b5ebef4fe2d",
    seedV2: "8133a9d716dcbe729b1f447ac0efccf3795e8bf28da2db4744090d0316ead730",
    v2: "037967cfe8d3111cdd72288ea3f444c15b710300323162fec63ca9036af73754e3",
  },
] as const;

const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const pointOf = (seedHex: string): string =>
  hex(p256PublicKey(p256PseudonymScalar(new Uint8Array(Buffer.from(seedHex, "hex")))));

describe("per-context pseudonym derivation KAT (§25.19)", () => {
  for (const vec of VECTORS) {
    test.skipIf(skipReason !== "")(
      `${vec.name}: production helpers map seed_v1 to the spec's v1 point ${skipReason}`,
      () => {
        expect(pointOf(vec.seedV1)).toBe(vec.v1);
      },
    );

    test.skipIf(skipReason !== "")(
      `${vec.name}: production helpers map seed_v2 (epoch 1) to the spec's v2 point ${skipReason}`,
      () => {
        expect(pointOf(vec.seedV2)).toBe(vec.v2);
      },
    );
  }
});
