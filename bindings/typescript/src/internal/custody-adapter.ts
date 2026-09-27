// custody-adapter.ts — the native-shaped custody record napi-rs expects for a
// caller's KeyCustodyProvider (ADR-006). `SCP.identityCreateWithCustody` passes
// it to the bridge; the bridge-check tests drive the same record through the
// napi `TestingCallbackCustody` hook.

import type { KeyCustodyProvider, PseudonymResult } from "../scp";

/** The shape napi-rs marshals for a {@link PseudonymResult}: bytes as a number array. */
export interface NativePseudonymResult {
  publicKey: number[];
  keyId: string;
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
  // `provider` in each arrow so `this` is bound, and (b) converts byte args
  // inbound (`Array<number>` → `Uint8Array`) and byte returns outbound
  // (`Uint8Array` → `Array<number>`). Methods with no byte payload
  // (`generateKeypair`, `destroyKey`, `custodyType`) pass through unchanged.
  // Additionally, napi-rs delivers a multi-element Rust tuple
  // (`(String, Vec<u8>)`) to the JS callback as a SINGLE `[keyId, bytes]`
  // array argument — not as two positional args — so the tuple callbacks
  // (`sign`, `dhAgree`, `derivePseudonym`) accept one array and destructure
  // it. Single-value callbacks receive their positional argument normally.
  return {
    generateKeypair: (keyType: string): string => provider.generateKeypair(keyType),
    // napi-rs delivers a `(String, Vec<u8>)` tuple as a single `[keyId, bytes]`
    // array arg (not positional), so the two-value callbacks destructure it.
    sign: ([keyId, message]: [string, number[]]): number[] =>
      Array.from(provider.sign(keyId, Uint8Array.from(message))),
    getPublicKey: (keyId: string): number[] => Array.from(provider.getPublicKey(keyId)),
    destroyKey: (keyId: string): void => provider.destroyKey(keyId),
    dhAgree: ([keyId, peerPublic]: [string, number[]]): number[] =>
      Array.from(provider.dhAgree(keyId, Uint8Array.from(peerPublic))),
    derivePseudonym: ([keyId, contextId]: [string, number[]]): NativePseudonymResult =>
      toNativePseudonym(provider.derivePseudonym(keyId, Uint8Array.from(contextId))),
    // The Rust `(String, Vec<u8>, u64)` tuple likewise arrives as a single
    // `[keyId, contextId, epoch]` array; the `u64` epoch crosses as a JS
    // `bigint` (the field's declared `ts_type`).
    deriveRotatablePseudonym: ([keyId, contextId, epoch]: [
      string,
      number[],
      bigint,
    ]): NativePseudonymResult =>
      toNativePseudonym(
        provider.deriveRotatablePseudonym(keyId, Uint8Array.from(contextId), epoch),
      ),
    // A sign-only / hardware / secure-enclave custody throws here to signal it
    // cannot export raw private-key bytes (ADR-006). Translate that into the
    // native error channel by returning an empty array (the Rust bridge's
    // 32-byte check then yields `Err`): §9.10.4 best-effort paths — e.g. the
    // post-create / post-import `PseudonymAnnouncement`, which signs via the
    // exported key — skip gracefully, while required callers surface a custody
    // error. Returning a value rather than re-throwing keeps the provider's
    // synchronous exception from leaking into the host's unhandled-exception
    // tracking (which would spuriously fail tests) while preserving the
    // fail-closed contract. Signing itself never uses this path — it goes
    // through `KeyCustody::sign` — so sign-only custody can still produce a
    // signed export.
    exportSigningKeyBytes: (keyId: string): number[] => {
      try {
        return Array.from(provider.exportSigningKeyBytes(keyId));
      } catch {
        return [];
      }
    },
    custodyType: (keyId: string): string => provider.custodyType(keyId),
  };
}
