/**
 * A+ Full-stack encrypt/decrypt roundtrip tests via real NAPI bridge.
 *
 * These tests exercise the COMPLETE protocol stack through the real native
 * addon: FullStackNetwork -> E2eCryptoProvider (real MLS + sender keys) ->
 * ContextManager -> CapturingTransport -> decrypt.
 *
 * Prerequisites:
 * - The NAPI bridge must be compiled with `allow_in_memory_custody` feature.
 * - The platform-specific `@limn-works/scp-ts-napi-*` package must be loadable.
 *
 * If the native addon is not available, all tests are skipped gracefully.
 */

import { describe, expect, test } from "bun:test";
import { createRequire } from "node:module";

// ---------------------------------------------------------------------------
// Load the raw native addon (not the Bridge wrapper — we need the
// fullstack_* functions which are not part of the Bridge interface).
// ---------------------------------------------------------------------------

// biome-ignore lint/suspicious/noExplicitAny: dynamic native addon loading
let addon: any = null;
let skipReason = "";

try {
  const platform = process.platform;
  const arch = process.arch;
  const platformMap: Record<string, string> = {
    darwin: "darwin",
    linux: "linux",
    win32: "win32",
  };
  const archMap: Record<string, string> = {
    arm64: "arm64",
    x64: "x64",
  };
  const os = platformMap[platform] ?? platform;
  const cpu = archMap[arch] ?? arch;
  const packageName = `@limn-works/scp-ts-napi-${os}-${cpu}`;

  const req = createRequire(import.meta.url);
  addon = req(packageName);

  // Verify that fullstack functions are available (feature-gated).
  if (typeof addon.fullstackCreateNode !== "function") {
    throw new Error("fullstackCreateNode not found — rebuild with allow_in_memory_custody feature");
  }
} catch (e: unknown) {
  const msg = e instanceof Error ? e.message : String(e);
  skipReason = `Native NAPI bridge not available or missing fullstack functions: ${msg}`;
}

if (addon === null) {
  describe("A+ Full-stack encrypt/decrypt roundtrip (SKIPPED)", () => {
    test.skip(`all tests skipped: ${skipReason}`, () => {});
  });
} else {
  const napi = addon;

  describe("A+ Full-stack encrypt/decrypt roundtrip", () => {
    test("Alice sends, Bob decrypts, plaintext matches", () => {
      const alice = napi.fullstackCreateNode("did:dht:z6MkAliceE2E");
      const bob = napi.fullstackCreateNode("did:dht:z6MkBobE2E");

      const ctxId = napi.fullstackCreateContext(
        alice,
        "test-ctx-alice-bob",
        JSON.stringify({
          ceiling: [
            "messages:read",
            "messages:write",
            "role:assign",
            "member:invite",
            "member:remove",
            "context:close",
          ],
          governance: "single_admin",
        }),
      );

      napi.fullstackAddMember(alice, ctxId, bob.did);
      napi.fullstackJoinFromWelcome(bob, ctxId);

      const plaintext = Buffer.from("Hello from Alice!");
      const ciphertext = napi.fullstackSendMessage(alice, ctxId, plaintext);

      // Ciphertext must differ from plaintext
      expect(Buffer.from(ciphertext)).not.toEqual(plaintext);
      expect(ciphertext.length).toBeGreaterThan(plaintext.length);

      // Bob decrypts -- THE A+ ASSERTION
      const decrypted = napi.fullstackDecryptMessage(bob, ctxId, ciphertext, alice.did);
      expect(Buffer.from(decrypted)).toEqual(plaintext);
    });

    test("Bob sends, Alice decrypts (bidirectional)", () => {
      const alice = napi.fullstackCreateNode("did:dht:z6MkAliceBidir");
      const bob = napi.fullstackCreateNode("did:dht:z6MkBobBidir");

      const ctxId = napi.fullstackCreateContext(
        alice,
        "test-ctx-bidir",
        JSON.stringify({
          ceiling: [
            "messages:read",
            "messages:write",
            "role:assign",
            "member:invite",
            "member:remove",
            "context:close",
          ],
          governance: "single_admin",
        }),
      );

      napi.fullstackAddMember(alice, ctxId, bob.did);
      napi.fullstackJoinFromWelcome(bob, ctxId);

      // Sync sender keys so both nodes can decrypt each other's messages.
      napi.fullstackSyncSenderKeys(alice, bob, ctxId);

      // Bob sends a message.
      const plaintext = Buffer.from("Hello from Bob!");
      const ciphertext = napi.fullstackSendMessage(bob, ctxId, plaintext);

      // Ciphertext must differ from plaintext.
      expect(Buffer.from(ciphertext)).not.toEqual(plaintext);

      // Alice decrypts Bob's message.
      const decrypted = napi.fullstackDecryptMessage(alice, ctxId, ciphertext, bob.did);
      expect(Buffer.from(decrypted)).toEqual(plaintext);
    });

    test("three-party: Alice sends, Bob and Carol both decrypt", () => {
      const alice = napi.fullstackCreateNode("did:dht:z6MkAlice3Party");
      const bob = napi.fullstackCreateNode("did:dht:z6MkBob3Party");
      const carol = napi.fullstackCreateNode("did:dht:z6MkCarol3Party");

      const ctxId = napi.fullstackCreateContext(
        alice,
        "test-ctx-3party",
        JSON.stringify({
          ceiling: [
            "messages:read",
            "messages:write",
            "role:assign",
            "member:invite",
            "member:remove",
          ],
        }),
      );

      // Alice adds Bob, then Carol.
      napi.fullstackAddMember(alice, ctxId, bob.did);
      napi.fullstackJoinFromWelcome(bob, ctxId);

      napi.fullstackAddMember(alice, ctxId, carol.did);
      napi.fullstackJoinFromWelcome(carol, ctxId);

      const plaintext = Buffer.from("Hello everyone from Alice!");
      const ciphertext = napi.fullstackSendMessage(alice, ctxId, plaintext);

      // Both Bob and Carol decrypt the same ciphertext.
      const bobDecrypted = napi.fullstackDecryptMessage(bob, ctxId, ciphertext, alice.did);
      expect(Buffer.from(bobDecrypted)).toEqual(plaintext);

      const carolDecrypted = napi.fullstackDecryptMessage(carol, ctxId, ciphertext, alice.did);
      expect(Buffer.from(carolDecrypted)).toEqual(plaintext);
    });

    test("multiple messages maintain correct roundtrip", () => {
      const alice = napi.fullstackCreateNode("did:dht:z6MkAliceMulti");
      const bob = napi.fullstackCreateNode("did:dht:z6MkBobMulti");

      const ctxId = napi.fullstackCreateContext(
        alice,
        "test-ctx-multi",
        JSON.stringify({
          ceiling: ["messages:read", "messages:write", "role:assign", "member:invite"],
        }),
      );

      napi.fullstackAddMember(alice, ctxId, bob.did);
      napi.fullstackJoinFromWelcome(bob, ctxId);

      // Send 5 messages and verify each roundtrips correctly.
      for (let i = 0; i < 5; i++) {
        const msg = Buffer.from(`Message number ${i}`);
        const ciphertext = napi.fullstackSendMessage(alice, ctxId, msg);
        const decrypted = napi.fullstackDecryptMessage(bob, ctxId, ciphertext, alice.did);
        expect(Buffer.from(decrypted)).toEqual(msg);
      }
    });

    test("removed member cannot decrypt new messages", () => {
      const alice = napi.fullstackCreateNode("did:dht:z6MkAliceRemove");
      const bob = napi.fullstackCreateNode("did:dht:z6MkBobRemove");

      const ctxId = napi.fullstackCreateContext(
        alice,
        "test-ctx-remove",
        JSON.stringify({
          ceiling: [
            "messages:read",
            "messages:write",
            "role:assign",
            "member:invite",
            "member:remove",
          ],
        }),
      );

      napi.fullstackAddMember(alice, ctxId, bob.did);
      napi.fullstackJoinFromWelcome(bob, ctxId);

      // Bob can decrypt a pre-removal message.
      const preRemovalMsg = Buffer.from("Before removal");
      const preRemovalCt = napi.fullstackSendMessage(alice, ctxId, preRemovalMsg);
      const preDecrypted = napi.fullstackDecryptMessage(bob, ctxId, preRemovalCt, alice.did);
      expect(Buffer.from(preDecrypted)).toEqual(preRemovalMsg);

      // Remove Bob.
      napi.fullstackRemoveMember(alice, ctxId, bob.did);

      // Alice sends after removal.
      const postRemovalMsg = Buffer.from("After removal");
      const postRemovalCt = napi.fullstackSendMessage(alice, ctxId, postRemovalMsg);

      // Bob MUST NOT be able to decrypt (MLS forward secrecy).
      expect(() => {
        napi.fullstackDecryptMessage(bob, ctxId, postRemovalCt, alice.did);
      }).toThrow();
    });

    test("ciphertext is non-deterministic (IND-CPA)", () => {
      const alice = napi.fullstackCreateNode("did:dht:z6MkAliceIND");
      const bob = napi.fullstackCreateNode("did:dht:z6MkBobIND");

      const ctxId = napi.fullstackCreateContext(
        alice,
        "test-ctx-indcpa",
        JSON.stringify({
          ceiling: ["messages:read", "messages:write", "role:assign", "member:invite"],
        }),
      );

      napi.fullstackAddMember(alice, ctxId, bob.did);
      napi.fullstackJoinFromWelcome(bob, ctxId);

      const msg = Buffer.from("same message twice");

      const ct1 = napi.fullstackSendMessage(alice, ctxId, msg);
      const ct2 = napi.fullstackSendMessage(alice, ctxId, msg);

      // Two encryptions of the same plaintext must produce different
      // ciphertexts (random nonce / IND-CPA property).
      expect(Buffer.from(ct1)).not.toEqual(Buffer.from(ct2));

      // Both must decrypt to the same plaintext.
      const d1 = napi.fullstackDecryptMessage(bob, ctxId, ct1, alice.did);
      const d2 = napi.fullstackDecryptMessage(bob, ctxId, ct2, alice.did);
      expect(Buffer.from(d1)).toEqual(msg);
      expect(Buffer.from(d2)).toEqual(msg);
    });
  });
}
