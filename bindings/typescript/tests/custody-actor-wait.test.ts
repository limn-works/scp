/**
 * Spec 09 §9.16.1 with a JavaScript callback custody: Alice's identity
 * wrapping key lives in a host keychain, so the actor turn that opens Bob's
 * sender-key `KeyResponse` awaits the host's `dhAgree` through the custody's
 * ThreadsafeFunction. While that callback runs on the JS thread, it asks the
 * same actor for its member count with `contextMemberCount`. The query is
 * queued behind the turn that is waiting on the callback, so it can settle
 * only if the bridge awaits the actor without holding the JS thread: the
 * callback returns, the `KeyResponse` installs Bob's sender key, and then the
 * count resolves.
 *
 * A bridge call that blocked the JS thread on the actor's reply (a sync getter
 * over `block_on`) would deadlock here: the turn waits on a callback the
 * blocked thread can never run, and the call waits on the turn.
 *
 * Bob runs on a second instance whose context sends are captured, and Alice
 * receives them through the actor's relay receive path
 * (`testingDeliverIncoming`), so the test holds the exact bytes without a
 * relay. Requires the addon built with `testing`; skips otherwise.
 */

import { describe, expect, test } from "bun:test";
import * as crypto from "node:crypto";

import { KeyNotFoundError } from "../src/errors";
import { toNativeCustodyProvider } from "../src/internal/custody-adapter";
import { loadNativeAddon } from "../src/internal/native";
import {
  type CustodyKeyRole,
  type CustodyKeyType,
  type CustodyPublicKey,
  type KeyCustodyProvider,
  p256SoftwarePseudonymPoint,
} from "../src/scp";
import { HpkeP256Keys } from "./hpke-p256-keys";
import { skipReasonIfAddonAbsent } from "./napi-guard";

// biome-ignore lint/suspicious/noExplicitAny: the native addon is untyped
let addon: any = null;
let skipReason = "";
try {
  addon = loadNativeAddon();
  const probe = new addon.SCP(JSON.stringify({ type: "in_memory" }));
  if (typeof probe.testingDeliverIncoming !== "function") {
    addon = null;
    skipReason = "native addon built without the `testing` feature";
  }
} catch (e: unknown) {
  addon = null;
  skipReason = skipReasonIfAddonAbsent(e);
}

/** Ed25519 PKCS8 DER prefix; the 32-byte seed follows. */
const ED25519_PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");
/** X25519 PKCS8 DER prefix; the 32-byte scalar follows. */
const X25519_PKCS8 = Buffer.from("302e020100300506032b656e04220420", "hex");
/** X25519 SPKI DER prefix; the 32-byte point follows. */
const X25519_SPKI = Buffer.from("302a300506032b656e032100", "hex");

/**
 * Ed25519 identity seeds and real HPKE P-256 keys. An Ed25519 key agrees as
 * its RFC 7748 X25519 mapping, which opens a Welcome sealed to the identity
 * key. `onWrappingAgree`, when set, runs once inside the next `hpke-p256`
 * agreement, before the host answers.
 */
class WrappingAgreeKeychain implements KeyCustodyProvider {
  #seeds = new Map<string, Uint8Array>();
  #hpke = new HpkeP256Keys();
  #roles = new Map<string, CustodyKeyRole>();
  #next = 1;
  /** What happened, in order: `agree:start`, `agree:done`, `count`. */
  readonly events: string[] = [];
  onWrappingAgree: (() => void) | undefined;

  generateKeypair(keyType: CustodyKeyType, role: CustodyKeyRole): string {
    if (keyType !== "ed25519" && keyType !== "hpke-p256") {
      throw new Error(`this keychain holds ed25519 and hpke-p256 keys, not ${keyType}`);
    }
    const kid = String(this.#next++);
    this.#roles.set(kid, role);
    if (keyType === "hpke-p256") this.#hpke.generate(kid);
    else this.#seeds.set(kid, new Uint8Array(crypto.randomBytes(32)));
    return kid;
  }

  #seed(keyId: string): Uint8Array {
    const seed = this.#seeds.get(keyId);
    if (seed === undefined) throw new KeyNotFoundError(`unknown key id: ${keyId}`);
    return seed;
  }

  #role(keyId: string): CustodyKeyRole {
    const role = this.#roles.get(keyId);
    if (role === undefined) throw new KeyNotFoundError(`unknown key id: ${keyId}`);
    return role;
  }

  #edKey(keyId: string): crypto.KeyObject {
    const der = Buffer.concat([ED25519_PKCS8, Buffer.from(this.#seed(keyId))]);
    return crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  }

  sign(keyId: string, message: Uint8Array): Uint8Array {
    return new Uint8Array(crypto.sign(null, Buffer.from(message), this.#edKey(keyId)));
  }

  getPublicKey(keyId: string): CustodyPublicKey {
    if (this.#hpke.has(keyId)) {
      return {
        keyType: "hpke-p256",
        publicKey: this.#hpke.publicKey(keyId),
        role: this.#role(keyId),
      };
    }
    const jwk = crypto.createPublicKey(this.#edKey(keyId)).export({ format: "jwk" }) as {
      x: string;
    };
    return {
      keyType: "ed25519",
      publicKey: new Uint8Array(Buffer.from(jwk.x, "base64url")),
      role: this.#role(keyId),
    };
  }

  destroyKey(keyId: string): void {
    this.#seeds.delete(keyId);
    this.#hpke.delete(keyId);
    this.#roles.delete(keyId);
  }

  dhAgree(keyId: string, peerPublic: Uint8Array): Uint8Array {
    if (this.#hpke.has(keyId)) {
      const hook = this.onWrappingAgree;
      this.onWrappingAgree = undefined;
      if (hook !== undefined) {
        this.events.push("agree:start");
        hook();
      }
      const shared = this.#hpke.agree(keyId, peerPublic);
      if (hook !== undefined) this.events.push("agree:done");
      return shared;
    }
    // RFC 8032 §5.1.5: the X25519 scalar is the first half of SHA-512(seed);
    // X25519 clamps it.
    const scalar = crypto.createHash("sha512").update(this.#seed(keyId)).digest().subarray(0, 32);
    const privateKey = crypto.createPrivateKey({
      key: Buffer.concat([X25519_PKCS8, scalar]),
      format: "der",
      type: "pkcs8",
    });
    const publicKey = crypto.createPublicKey({
      key: Buffer.concat([X25519_SPKI, Buffer.from(peerPublic)]),
      format: "der",
      type: "spki",
    });
    return new Uint8Array(crypto.diffieHellman({ privateKey, publicKey }));
  }

  derivePseudonym(keyId: string, contextId: Uint8Array): Uint8Array {
    return p256SoftwarePseudonymPoint(this.#seed(keyId), contextId);
  }

  deriveRotatablePseudonym(keyId: string, contextId: Uint8Array, epoch: bigint): Uint8Array {
    return p256SoftwarePseudonymPoint(this.#seed(keyId), contextId, epoch);
  }

  custodyType(_keyId: string): string {
    return "software";
  }
}

/** One payload's result from `testingDeliverIncoming`. */
interface DeliveryResult {
  outcome?: string;
  plaintext?: Buffer;
  error?: string;
}

/** Resolves with `promise`, or rejects once `ms` pass. */
function within<T>(promise: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${what} did not settle within ${ms} ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

const CEILING = [
  "messages:read",
  "messages:write",
  "role:assign",
  "member:invite",
  "governance:propose",
  "governance:vote",
];

if (addon === null) {
  describe("callback custody under a concurrent actor wait (SKIPPED)", () => {
    test.skip(`native NAPI addon unavailable: ${skipReason}`, () => {});
  });
} else {
  describe("callback custody under a concurrent actor wait", () => {
    test("a KeyResponse turn awaiting the host's dhAgree completes while JS awaits contextMemberCount on the same actor", async () => {
      const alice = new addon.SCP(JSON.stringify({ type: "in_memory" }));
      const bob = new addon.SCP(JSON.stringify({ type: "in_memory" }));
      try {
        const host = new WrappingAgreeKeychain();
        const aliceId = await alice.identityCreateWithCustody(toNativeCustodyProvider(host));
        const bobId = await bob.identityCreate("in_memory");
        const sent = bob.testingCaptureContextSends(bobId.did);

        // Bob creates X and adds Alice; her join opens the Welcome through her host.
        const params = { ceiling: CEILING, mode: "Encrypted", governance: "single_admin" };
        const bobCtx = await bob.contextCreate(bobId, JSON.stringify(params));
        // What Bob published before Alice's epoch never reaches her.
        sent.take();
        const reservation = await alice.reserveKeyPackage(aliceId.did);
        const invite = await bob.inviteMember(
          bobCtx.contextId,
          bobId.did,
          aliceId.did,
          Array.from(reservation.keyPackagePublic as Uint8Array),
          [],
        );
        const aliceCtx = await alice.contextJoinFromWelcome(
          aliceId.did,
          invite.bundle,
          reservation.reservationId,
        );
        // No relay carries Alice's routing announcement in this test.
        await bob.contextSeedPeerPseudonym(bobCtx, aliceId.did, Buffer.alloc(32, 0x41));
        await bob.contextSend(bobCtx, bobId.did, Array.from(Buffer.from("hello alice")), null);
        // The add's Commit, Bob's KeyResponse sealed to Alice's wrapping key, his message.
        const published: Buffer[] = sent.take();
        expect(published.length).toBe(3);
        await addon.testingAdmitJoinedMember(alice, bob, aliceCtx.contextId, aliceId.did);

        // Inside the KeyResponse turn's dhAgree, ask the same actor for its count.
        let count: Promise<number> | undefined;
        host.onWrappingAgree = () => {
          count = alice.contextMemberCount(aliceCtx).then((n: number) => {
            host.events.push("count");
            return n;
          });
        };
        const results = await within<DeliveryResult[]>(
          alice.testingDeliverIncoming(aliceCtx.contextId, published),
          10_000,
          "delivery",
        );
        expect(count).toBeDefined();
        expect(await within(count as Promise<number>, 10_000, "contextMemberCount")).toBe(2);
        // The host answered before the queued query ran.
        expect(host.events).toEqual(["agree:start", "agree:done", "count"]);

        expect(results.length).toBe(3);
        const [commit, keyResponse, message] = results as [
          DeliveryResult,
          DeliveryResult,
          DeliveryResult,
        ];
        // The add's Commit goes out as bare MLS bytes, not an outer envelope, so
        // the envelope receive path refuses it; Alice joined at its epoch
        // through her Welcome and needs it from no path.
        expect(commit.error).toContain("outer envelope");
        expect(keyResponse).toMatchObject({ outcome: "handled" });
        // Bob's message opens only under his sender key, so it opening without
        // an error shows the KeyResponse installed that key. Alice never saw
        // the message Bob sent when he created X (sequence 1), so this one
        // (sequence 2) may be held in her reorder buffer ("handled") rather
        // than surfaced ("application"); runs have produced both.
        expect(message.error ?? null).toBeNull();
        expect(["handled", "application"]).toContain(message.outcome ?? "");
      } finally {
        await alice.shutdown(1000n).catch(() => {});
        await bob.shutdown(1000n).catch(() => {});
      }
    }, 30_000);
  });
}
