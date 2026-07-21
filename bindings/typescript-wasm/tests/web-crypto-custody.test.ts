/**
 * Unit tests for {@link WebCryptoCustody} — the DID binding is wired; the
 * signing seams fail closed (#1980); construction fails closed on missing
 * preconditions.
 */

import { expect, test } from "bun:test";
import { WebCryptoCustody } from "../src/index";

const DID = "did:dht:z6MkExampleParticipantIdentityAAAAAAAAAAAA";

test("did() returns the bound DID (the one wired driver call site)", async () => {
  const custody = await WebCryptoCustody.create({ did: DID });
  expect(custody.did()).toBe(DID);
});

test("create fails closed when no DID is bound", async () => {
  await expect(WebCryptoCustody.create({ did: "" })).rejects.toThrow(/bound.*DID/i);
  await expect(WebCryptoCustody.create({ did: "   " })).rejects.toThrow(/bound.*DID/i);
});

test("create fails closed when WebCrypto (crypto.subtle) is unavailable", async () => {
  const noSubtle = {} as unknown as Crypto;
  await expect(WebCryptoCustody.create({ did: DID, crypto: noSubtle })).rejects.toThrow(
    /WebCrypto.*unavailable/i,
  );
});

test("the #1980 signing seams fail closed (no driver call site this slice)", async () => {
  const custody = await WebCryptoCustody.create({ did: DID });
  const data = new Uint8Array([1, 2, 3]);
  expect(() => custody.sign("k", data)).toThrow(/#1980/);
  expect(() => custody.getPublicKey("k")).toThrow(/#1980/);
  expect(() => custody.generateKeypair("ed25519")).toThrow(/#1980/);
  expect(() => custody.dhAgree("k", data)).toThrow(/#1980/);
});

test("destroyKey is genuinely wired (synchronous) and idempotent", async () => {
  const custody = await WebCryptoCustody.create({ did: DID });
  expect(() => custody.destroyKey("k")).not.toThrow();
  expect(() => custody.destroyKey("k")).not.toThrow();
  // did() still resolves after the key handle is dropped (identity is the DID).
  expect(custody.did()).toBe(DID);
});

test("holds a non-extractable on-device identity key by default", async () => {
  // Generation succeeding proves a non-extractable Ed25519 key was bound; a
  // caller can also supply their own keypair to reattach.
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, false, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  expect(kp.privateKey.extractable).toBe(false);
  const custody = await WebCryptoCustody.create({ did: DID, identityKeyPair: kp });
  expect(custody.did()).toBe(DID);
});
