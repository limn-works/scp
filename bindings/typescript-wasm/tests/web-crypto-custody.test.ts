/**
 * Unit tests for {@link WebCryptoCustody} — the DID binding is wired; the
 * signing seams fail closed (#1980); construction fails closed on missing
 * preconditions. This slice generates NO key (key custody + signing land with
 * #1980), so `create` is synchronous and there is no key path to test.
 */

import { expect, test } from "bun:test";
import { WebCryptoCustody } from "../src/index";

const DID = "did:dht:z6MkExampleParticipantIdentityAAAAAAAAAAAA";

test("did() returns the bound DID (the one wired driver call site)", () => {
  const custody = WebCryptoCustody.create({ did: DID });
  expect(custody.did()).toBe(DID);
});

test("create fails closed when no DID is bound", () => {
  expect(() => WebCryptoCustody.create({ did: "" })).toThrow(/bound.*DID/i);
  expect(() => WebCryptoCustody.create({ did: "   " })).toThrow(/bound.*DID/i);
});

test("create fails closed when WebCrypto (crypto.subtle) is unavailable", () => {
  const noSubtle = {} as unknown as Crypto;
  expect(() => WebCryptoCustody.create({ did: DID, crypto: noSubtle })).toThrow(
    /WebCrypto.*unavailable/i,
  );
});

test("the #1980 signing seams fail closed (no driver call site this slice)", () => {
  const custody = WebCryptoCustody.create({ did: DID });
  const data = new Uint8Array([1, 2, 3]);
  expect(() => custody.sign("k", data)).toThrow(/#1980/);
  expect(() => custody.getPublicKey("k")).toThrow(/#1980/);
  expect(() => custody.generateKeypair("ed25519")).toThrow(/#1980/);
  expect(() => custody.dhAgree("k", data)).toThrow(/#1980/);
});

test("destroyKey is a no-op this slice (no key held) and idempotent", () => {
  const custody = WebCryptoCustody.create({ did: DID });
  expect(() => custody.destroyKey("k")).not.toThrow();
  expect(() => custody.destroyKey("k")).not.toThrow();
  expect(custody.did()).toBe(DID); // identity is the DID; unaffected
});
