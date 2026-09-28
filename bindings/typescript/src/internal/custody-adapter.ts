// custody-adapter.ts — the native-shaped custody record napi-rs expects for a
// caller's KeyCustodyProvider (ADR-006). `SCP.identityCreateWithCustody` passes
// it to the bridge; the bridge-check tests drive the same record through the
// napi `TestingCallbackCustody` hook.

import type { KeyCustodyProvider, PseudonymResult } from "../scp";

/** The shape napi-rs marshals for a `CustodyPublicKey`: bytes as a number array. */
export interface NativeCustodyPublicKey {
  keyType: string;
  publicKey: number[];
}

/** The shape napi-rs marshals for a {@link PseudonymResult}: bytes as a number array. */
export interface NativePseudonymResult {
  publicKey: number[];
  keyId: string;
}

/**
 * The one outcome shape every custody callback hands the bridge. A host
 * failure travels as `{ ok: false, code?, message }`, never as a thrown
 * exception: napi-rs turns an exception thrown inside a threadsafe-function
 * callback into a process-level uncaught exception. The bridge maps a failure
 * whose `code` is `"SCP-CRYPTO-4006"` to key-not-found and any other failure
 * to a custody error.
 */
export type NativeHostResult<T> =
  | { ok: true; value: T }
  | { ok: false; code?: string; message: string };

/** Runs one host call and returns its outcome; a throw becomes the failure arm. */
function hostCall<T>(call: () => T): NativeHostResult<T> {
  try {
    return { ok: true, value: call() };
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : String(e);
    const code =
      typeof e === "object" && e !== null && "code" in e && typeof e.code === "string"
        ? e.code
        : undefined;
    return code === undefined ? { ok: false, message } : { ok: false, code, message };
  }
}

function toNativePseudonym(result: PseudonymResult): NativePseudonymResult {
  return { publicKey: Array.from(result.publicKey), keyId: result.keyId };
}

/**
 * Wraps `provider` in the record the napi `NapiKeyCustodyProvider` object
 * reads.
 */
export function toNativeCustodyProvider(provider: KeyCustodyProvider) {
  // NAPI marshals each provider method as a ThreadsafeFunction WITHOUT
  // preserving `this`, and Rust `Vec<u8>` crosses the wire as a JS
  // `Array<number>` (not `Uint8Array`). The adapter below (a) closes over
  // `provider` in each arrow so `this` is bound, (b) converts byte args
  // inbound (`Array<number>` → `Uint8Array`) and byte returns outbound
  // (`Uint8Array` → `Array<number>`), and (c) runs every host call, conversion
  // included, through `hostCall`, so a host throw reaches Rust as a
  // structured failure. napi-rs delivers a multi-element Rust tuple
  // (`(String, Vec<u8>)`) to the JS callback as a SINGLE `[keyId, bytes]`
  // array argument, not as two positional args, so the tuple callbacks
  // (`sign`, `dhAgree`, `derivePseudonym`, `deriveRotatablePseudonym`) accept
  // one array and destructure it.
  return {
    generateKeypair: (keyType: string): NativeHostResult<string> =>
      hostCall(() => provider.generateKeypair(keyType)),
    sign: ([keyId, message]: [string, number[]]): NativeHostResult<number[]> =>
      hostCall(() => Array.from(provider.sign(keyId, Uint8Array.from(message)))),
    getPublicKey: (keyId: string): NativeHostResult<NativeCustodyPublicKey> =>
      hostCall(() => {
        const { keyType, publicKey } = provider.getPublicKey(keyId);
        return { keyType, publicKey: Array.from(publicKey) };
      }),
    destroyKey: (keyId: string): NativeHostResult<undefined> =>
      hostCall(() => {
        provider.destroyKey(keyId);
        return undefined;
      }),
    dhAgree: ([keyId, peerPublic]: [string, number[]]): NativeHostResult<number[]> =>
      hostCall(() => Array.from(provider.dhAgree(keyId, Uint8Array.from(peerPublic)))),
    derivePseudonym: ([keyId, contextId]: [
      string,
      number[],
    ]): NativeHostResult<NativePseudonymResult> =>
      hostCall(() =>
        toNativePseudonym(provider.derivePseudonym(keyId, Uint8Array.from(contextId))),
      ),
    // The Rust `(String, Vec<u8>, u64)` tuple likewise arrives as a single
    // `[keyId, contextId, epoch]` array; the `u64` epoch crosses as a JS
    // `bigint`.
    deriveRotatablePseudonym: ([keyId, contextId, epoch]: [
      string,
      number[],
      bigint,
    ]): NativeHostResult<NativePseudonymResult> =>
      hostCall(() =>
        toNativePseudonym(
          provider.deriveRotatablePseudonym(keyId, Uint8Array.from(contextId), epoch),
        ),
      ),
    // A sign-only / hardware / secure-enclave custody throws here to signal it
    // cannot export raw private-key bytes (ADR-006). The failure reaches Rust
    // as an error: §9.10.4 best-effort paths (the post-create / post-import
    // `PseudonymAnnouncement`, which signs via the exported key) skip, and
    // required callers surface a custody error. Signing never uses this path;
    // it goes through `KeyCustody::sign`, so sign-only custody can still
    // produce a signed export.
    exportSigningKeyBytes: (keyId: string): NativeHostResult<number[]> =>
      hostCall(() => Array.from(provider.exportSigningKeyBytes(keyId))),
    custodyType: (keyId: string): NativeHostResult<string> =>
      hostCall(() => provider.custodyType(keyId)),
  };
}
