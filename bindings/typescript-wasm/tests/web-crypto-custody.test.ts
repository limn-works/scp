/**
 * Unit tests for {@link WebCryptoCustody} — the DID binding is wired; the
 * signing SEAMs fail closed; construction fails closed on missing
 * preconditions. This slice generates NO key (key custody + signing land with
 * the MLS-signing-key → WebCrypto move), so `create` is synchronous and there is no key path to test.
 */

import { expect, test } from "bun:test";
import {
  CryptoError,
  type CustodyKeyType,
  type JsKeyCustody,
  KeyEventKeyRefusedError,
  mapBridgeError,
  ScpError,
  WebCryptoCustody,
} from "../src/index";

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
  // A WebCryptoCustody is WebCrypto-backed by definition — absent crypto.subtle is
  // a type-identity precondition failure (like an empty DID), NOT the move's concern.
  // The injected `crypto` option is the seam that makes this precondition testable.
  const noSubtle = {} as unknown as Crypto;
  expect(() => WebCryptoCustody.create({ did: DID, crypto: noSubtle })).toThrow(
    /WebCrypto.*by definition|WebCrypto.*unavailable/i,
  );
});

test("the unwired signing SEAMs fail closed (no driver call site this slice)", () => {
  const custody = WebCryptoCustody.create({ did: DID });
  const data = new Uint8Array([1, 2, 3]);
  expect(() => custody.sign("k", data)).toThrow(
    /WebCryptoCustody\.sign is an unwired custody SEAM/,
  );
  expect(() => custody.getPublicKey("k")).toThrow(
    /WebCryptoCustody\.getPublicKey is an unwired custody SEAM/,
  );
  expect(() => custody.generateKeypair("ed25519")).toThrow(
    /WebCryptoCustody\.generateKeypair is an unwired custody SEAM/,
  );
  expect(() => custody.dhAgree("k", data)).toThrow(
    /WebCryptoCustody\.dhAgree is an unwired custody SEAM/,
  );
});

test("destroyKey is a no-op this slice (no key held) and idempotent", () => {
  const custody = WebCryptoCustody.create({ did: DID });
  expect(() => custody.destroyKey("k")).not.toThrow();
  expect(() => custody.destroyKey("k")).not.toThrow();
  expect(custody.did()).toBe(DID); // identity is the DID; unaffected
});

test("JsKeyCustody.generateKeypair accepts only the four custody key types", () => {
  const custody: JsKeyCustody = WebCryptoCustody.create({ did: DID });
  // `bun run check` type-checks this file: the line below compiles only while
  // `keyType` is the CustodyKeyType union, so widening it to `string` fails
  // the check on an unused directive.
  // @ts-expect-error "rsa" is not a CustodyKeyType.
  expect(() => custody.generateKeypair("rsa")).toThrow(/unwired custody SEAM/);
});

test("generateKeypair refuses a key-event key with the typed refusal, not the unwired SEAM", () => {
  const custody = WebCryptoCustody.create({ did: DID });
  let thrown: unknown;
  try {
    // @ts-expect-error "p256-key-event" is not a CustodyKeyType; the runtime check refuses it.
    custody.generateKeypair("p256-key-event");
  } catch (e) {
    thrown = e;
  }
  expect(thrown).toBeInstanceOf(KeyEventKeyRefusedError);
  expect(thrown).toBeInstanceOf(CryptoError);
  expect(thrown).toBeInstanceOf(ScpError);
  const refusal = thrown as KeyEventKeyRefusedError;
  expect(refusal.code).toBe("SCP-CRYPTO-4060");
  expect(refusal.keyType).toBe("p256-key-event");
  expect(refusal.message).toMatch(/^\[SCP-CRYPTO-4060\] /);
  expect(refusal.message).not.toMatch(/unwired custody SEAM/);
  // mapBridgeError passes the typed refusal through, and classifies its message
  // to a CryptoError with the same code when it arrives as a plain Error.
  expect(mapBridgeError(refusal)).toBe(refusal);
  const mapped = mapBridgeError(new Error(refusal.message));
  expect(mapped).toBeInstanceOf(CryptoError);
  expect(mapped.code).toBe("SCP-CRYPTO-4060");
});

test("CustodyKeyType does not admit the key-event key type", () => {
  // `bun run check` type-checks this file: adding "p256-key-event" to
  // CustodyKeyType leaves the directive unused and fails the check.
  // @ts-expect-error "p256-key-event" is not a CustodyKeyType.
  const t: CustodyKeyType = "p256-key-event";
  expect(t as string).toBe("p256-key-event");
});
