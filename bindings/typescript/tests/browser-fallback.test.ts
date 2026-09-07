/**
 * Executes the browser branch of `trust.ts`'s base64url decoder by deleting
 * `globalThis.Buffer`.
 *
 * `__decodeBase64UrlToUtf8` in `../src/trust` picks `Buffer.from(...)` whenever
 * `typeof Buffer !== "undefined"`, which is every runtime the rest of this suite
 * runs under, so the `globalThis.atob` branch below it never executes. That
 * branch is what an in-browser consumer reaches, and `bindings/typescript-wasm/`
 * already bundles one file out of `bindings/typescript/src/` into the browser
 * package, so the branch is reachable code rather than a hypothetical. These
 * tests delete the global, call
 * {@link __extractFirstCapabilityUri} (the only exported caller of the decoder),
 * and restore the global in a `finally`.
 *
 * See `.docs/lessons/typescript-node-only-globals-break-browser.md`.
 */

import { describe, expect, it } from "bun:test";
import { __extractFirstCapabilityUri } from "../src/trust";

/**
 * A JWT-shaped token whose payload segment exercises both properties the
 * browser branch has to handle that the `Buffer` branch does not: base64url's
 * `-` and `_` alphabet, which `atob` rejects until the decoder rewrites them to
 * `+` and `/`, and a length that is not a multiple of four, which `atob` rejects
 * until the decoder re-pads it.
 *
 * The payload decodes to
 * `{"att":[{"with":"scp:ctx:c0ffee/msg:send"}],"nnc":"ÿ¾?>"}`.
 */
const PAYLOAD_SEGMENT =
  "eyJhdHQiOlt7IndpdGgiOiJzY3A6Y3R4OmMwZmZlZS9tc2c6c2VuZCJ9XSwibm5jIjoiw7_Cvj8-In0";
const TOKEN = `eyJhbGciOiJFZERTQSJ9.${PAYLOAD_SEGMENT}.c2ln`;
const EXPECTED_URI = "scp:ctx:c0ffee/msg:send";

/** Runs `body` with `globalThis.Buffer` deleted, restoring it afterwards. */
function withoutBuffer<T>(body: () => T): T {
  const saved = (globalThis as { Buffer?: unknown }).Buffer;
  // `delete` rather than an assignment of `undefined`: the decoder branches on
  // `typeof Buffer !== "undefined"`, and only removing the property reproduces
  // what a browser presents.
  delete (globalThis as { Buffer?: unknown }).Buffer;
  try {
    return body();
  } finally {
    (globalThis as { Buffer?: unknown }).Buffer = saved;
  }
}

describe("trust.ts base64url decoding without a Node Buffer global", () => {
  it("decodes a base64url payload through the atob branch", () => {
    const uri = withoutBuffer(() => {
      expect(typeof (globalThis as { Buffer?: unknown }).Buffer).toBe("undefined");
      return __extractFirstCapabilityUri(TOKEN);
    });
    expect(uri).toBe(EXPECTED_URI);
  });

  it("returns the same URI with and without the Buffer global", () => {
    const withBuffer = __extractFirstCapabilityUri(TOKEN);
    const withoutIt = withoutBuffer(() => __extractFirstCapabilityUri(TOKEN));
    expect(withBuffer).toBe(EXPECTED_URI);
    expect(withoutIt).toBe(withBuffer);
  });

  it("restores the Buffer global after the branch runs", () => {
    withoutBuffer(() => __extractFirstCapabilityUri(TOKEN));
    expect(typeof (globalThis as { Buffer?: unknown }).Buffer).not.toBe("undefined");
  });

  it("still fails closed on a malformed token when Buffer is absent", () => {
    const uri = withoutBuffer(() => __extractFirstCapabilityUri("not-a-jwt"));
    expect(uri).toBeNull();
  });
});
