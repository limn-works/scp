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
 *
 * Post-ADR-048 (#1549 Phase 4 PR 4): The `fullstack_*` free functions on the
 * raw addon were deleted. Every fullstack operation now dispatches through a
 * caller-owned `SCP` instance's class methods. This file constructs a fresh
 * `new addon.SCP()` per test and shuts it down in `afterEach` so handle
 * affinity holds within each case and resources are released between cases.
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { createRequire } from "node:module";

// ---------------------------------------------------------------------------
// Load the raw native addon — the fullstack methods live on `SCP` (gated
// behind the `allow_in_memory_custody` feature). We call them through a
// per-test `SCP` instance instead of module-level free functions.
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

  if (typeof addon.SCP !== "function") {
    throw new Error("SCP class not exported from native addon — rebuild with the Phase 4 changes");
  }

  // Verify that fullstack methods are available (feature-gated on the SCP
  // class). Instantiate a throwaway SCP because feature-gated methods are
  // defined on the class, not on the addon module.
  const probe = new addon.SCP(JSON.stringify({ type: "in_memory" }));
  if (typeof probe.fullstackCreateNode !== "function") {
    throw new Error(
      "SCP.fullstackCreateNode not found — rebuild with allow_in_memory_custody feature",
    );
  }
} catch (e: unknown) {
  const msg = e instanceof Error ? e.message : String(e);
  skipReason = `Native NAPI bridge not available or missing fullstack methods: ${msg}`;
}

if (addon === null) {
  describe("A+ Full-stack encrypt/decrypt roundtrip (SKIPPED)", () => {
    test.skip(`all tests skipped: ${skipReason}`, () => {});
  });
} else {
  describe("A+ Full-stack encrypt/decrypt roundtrip", () => {
    // Per-test SCP instance. A fresh instance isolates each case's
    // `FullStackNetwork` and handles from neighbours, matching the lifecycle
    // pattern used by `tests/scp-class.test.ts` (commit 176bd94d8).
    // biome-ignore lint/suspicious/noExplicitAny: the native SCP class is untyped
    let scp: any;

    beforeEach(() => {
      scp = new addon.SCP(JSON.stringify({ type: "in_memory" }));
    });

    afterEach(async () => {
      // `shutdown` takes `bigint` milliseconds (napi-rs u64 on the wire,
      // #1692). 1000 ms drains pending tasks without stalling the suite.
      await scp.shutdown(1000n);
    });

    test("Alice sends, Bob decrypts, plaintext matches", () => {
      const alice = scp.fullstackCreateNode("did:dht:z6MkAliceE2E");
      const bob = scp.fullstackCreateNode("did:dht:z6MkBobE2E");

      const ctxId = scp.fullstackCreateContext(
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

      scp.fullstackAddMember(alice, ctxId, bob.did);
      scp.fullstackJoinFromWelcome(bob, ctxId);

      const plaintext = Buffer.from("Hello from Alice!");
      const ciphertext = scp.fullstackSendMessage(alice, ctxId, plaintext);

      // Ciphertext must differ from plaintext
      expect(Buffer.from(ciphertext)).not.toEqual(plaintext);
      expect(ciphertext.length).toBeGreaterThan(plaintext.length);

      // Bob decrypts -- THE A+ ASSERTION
      const decrypted = scp.fullstackDecryptMessage(bob, ctxId, ciphertext, alice.did);
      expect(Buffer.from(decrypted)).toEqual(plaintext);
    });

    test("Bob sends, Alice decrypts (bidirectional)", () => {
      const alice = scp.fullstackCreateNode("did:dht:z6MkAliceBidir");
      const bob = scp.fullstackCreateNode("did:dht:z6MkBobBidir");

      const ctxId = scp.fullstackCreateContext(
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

      scp.fullstackAddMember(alice, ctxId, bob.did);
      scp.fullstackJoinFromWelcome(bob, ctxId);

      // Joiner-sends is not yet supported under the actor-per-context model:
      // a node that joined via Welcome has no actor-backed send handle
      // (no spawn-from-Welcome entrypoint — tracked as the Welcome-Delivery
      // work). The send must fail closed with a clean error rather than
      // silently producing unverifiable crypto.
      //
      // INTENTIONAL TRIPWIRE: this positive fail-closed assertion verifies the
      // CURRENT one-way contract and is meant to trip loudly the moment the
      // behavior changes. When the Welcome-Delivery / spawn-from-Welcome
      // entrypoint lands and joiner-send starts working, this assertion MUST be
      // rewritten into a real bidirectional roundtrip (Bob sends, Alice
      // decrypts) — not deleted or relaxed.
      expect(() => scp.fullstackSendMessage(bob, ctxId, Buffer.from("Hello from Bob!"))).toThrow(
        /not found in node's handles/,
      );
    });

    test("three-party: Alice sends, Bob and Carol both decrypt", () => {
      const alice = scp.fullstackCreateNode("did:dht:z6MkAlice3Party");
      const bob = scp.fullstackCreateNode("did:dht:z6MkBob3Party");
      const carol = scp.fullstackCreateNode("did:dht:z6MkCarol3Party");

      const ctxId = scp.fullstackCreateContext(
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
      scp.fullstackAddMember(alice, ctxId, bob.did);
      scp.fullstackJoinFromWelcome(bob, ctxId);

      scp.fullstackAddMember(alice, ctxId, carol.did);
      scp.fullstackJoinFromWelcome(carol, ctxId);

      const plaintext = Buffer.from("Hello everyone from Alice!");
      const ciphertext = scp.fullstackSendMessage(alice, ctxId, plaintext);

      // Both Bob and Carol decrypt the same ciphertext.
      const bobDecrypted = scp.fullstackDecryptMessage(bob, ctxId, ciphertext, alice.did);
      expect(Buffer.from(bobDecrypted)).toEqual(plaintext);

      const carolDecrypted = scp.fullstackDecryptMessage(carol, ctxId, ciphertext, alice.did);
      expect(Buffer.from(carolDecrypted)).toEqual(plaintext);
    });

    test("multiple messages maintain correct roundtrip", () => {
      const alice = scp.fullstackCreateNode("did:dht:z6MkAliceMulti");
      const bob = scp.fullstackCreateNode("did:dht:z6MkBobMulti");

      const ctxId = scp.fullstackCreateContext(
        alice,
        "test-ctx-multi",
        JSON.stringify({
          ceiling: ["messages:read", "messages:write", "role:assign", "member:invite"],
        }),
      );

      scp.fullstackAddMember(alice, ctxId, bob.did);
      scp.fullstackJoinFromWelcome(bob, ctxId);

      // Send 5 messages and verify each roundtrips correctly.
      for (let i = 0; i < 5; i++) {
        const msg = Buffer.from(`Message number ${i}`);
        const ciphertext = scp.fullstackSendMessage(alice, ctxId, msg);
        const decrypted = scp.fullstackDecryptMessage(bob, ctxId, ciphertext, alice.did);
        expect(Buffer.from(decrypted)).toEqual(msg);
      }
    });

    test("removed member cannot decrypt new messages", () => {
      const alice = scp.fullstackCreateNode("did:dht:z6MkAliceRemove");
      const bob = scp.fullstackCreateNode("did:dht:z6MkBobRemove");

      const ctxId = scp.fullstackCreateContext(
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

      scp.fullstackAddMember(alice, ctxId, bob.did);
      scp.fullstackJoinFromWelcome(bob, ctxId);

      // Bob can decrypt a pre-removal message.
      const preRemovalMsg = Buffer.from("Before removal");
      const preRemovalCt = scp.fullstackSendMessage(alice, ctxId, preRemovalMsg);
      const preDecrypted = scp.fullstackDecryptMessage(bob, ctxId, preRemovalCt, alice.did);
      expect(Buffer.from(preDecrypted)).toEqual(preRemovalMsg);

      // Remove Bob.
      scp.fullstackRemoveMember(alice, ctxId, bob.did);

      // Alice sends after removal.
      const postRemovalMsg = Buffer.from("After removal");
      const postRemovalCt = scp.fullstackSendMessage(alice, ctxId, postRemovalMsg);

      // Bob MUST NOT be able to decrypt (MLS forward secrecy).
      expect(() => {
        scp.fullstackDecryptMessage(bob, ctxId, postRemovalCt, alice.did);
      }).toThrow();
    });

    test("ciphertext is non-deterministic (IND-CPA)", () => {
      const alice = scp.fullstackCreateNode("did:dht:z6MkAliceIND");
      const bob = scp.fullstackCreateNode("did:dht:z6MkBobIND");

      const ctxId = scp.fullstackCreateContext(
        alice,
        "test-ctx-indcpa",
        JSON.stringify({
          ceiling: ["messages:read", "messages:write", "role:assign", "member:invite"],
        }),
      );

      scp.fullstackAddMember(alice, ctxId, bob.did);
      scp.fullstackJoinFromWelcome(bob, ctxId);

      const msg = Buffer.from("same message twice");

      const ct1 = scp.fullstackSendMessage(alice, ctxId, msg);
      const ct2 = scp.fullstackSendMessage(alice, ctxId, msg);

      // Two encryptions of the same plaintext must produce different
      // ciphertexts (random nonce / IND-CPA property).
      expect(Buffer.from(ct1)).not.toEqual(Buffer.from(ct2));

      // Both must decrypt to the same plaintext.
      const d1 = scp.fullstackDecryptMessage(bob, ctxId, ct1, alice.did);
      const d2 = scp.fullstackDecryptMessage(bob, ctxId, ct2, alice.did);
      expect(Buffer.from(d1)).toEqual(msg);
      expect(Buffer.from(d2)).toEqual(msg);
    });
  });
}
