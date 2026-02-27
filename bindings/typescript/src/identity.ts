/**
 * Identity module for the SCP TypeScript SDK.
 *
 * Provides the `Identity` class for DID lifecycle management: creation,
 * loading, resolution, and key rotation. All operations delegate to the
 * runtime-selected bridge (napi-rs or WASM).
 *
 * See ADR-022 in `.docs/adrs/phase-4.md` and `.docs/scaffold/typescript.md`.
 */

import { mapBridgeError } from "./errors.js";
import type { BridgeIdentityHandle } from "./internal/bridge.js";
import { getBridge } from "./internal/bridge.js";
import type { DIDDocument } from "./types.js";

// ---------------------------------------------------------------------------
// CustodyType
// ---------------------------------------------------------------------------

/** Supported custody methods for identity key management. */
export type CustodyType = "platform" | "in_memory" | "software";

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/**
 * An SCP identity backed by a DID.
 *
 * Identity objects are created via the static factory methods `create()` and
 * `load()`. They hold an opaque bridge handle that retains the key material
 * (for in-memory custody) or a reference to the platform key store.
 *
 * # Usage
 *
 * ```typescript
 * const identity = await Identity.create({ custody: "in_memory" });
 * console.log(identity.did); // "did:dht:z6Mk..."
 * ```
 */
export class Identity {
  /** The DID string for this identity (e.g., `"did:dht:z6Mk..."`). */
  readonly did: string;

  /** The custody type used at identity creation. */
  readonly custodyType: string;

  /** @internal Opaque bridge handle — not part of the public API. */
  readonly _handle: BridgeIdentityHandle;

  private constructor(did: string, custodyType: string, handle: BridgeIdentityHandle) {
    this.did = did;
    this.custodyType = custodyType;
    this._handle = handle;
  }

  /**
   * Creates a new DID identity with the specified custody method.
   *
   * For `"in_memory"` custody, key material is stored in heap memory. This is
   * suitable for testing and CLI usage but NOT for production on devices with
   * HSM capability. Use `"platform"` custody on iOS/Android.
   *
   * @param options - Identity creation options.
   * @param options.custody - The custody method. Defaults to `"platform"`.
   * @returns A new `Identity` instance.
   * @throws {IdentityError} If identity creation fails.
   * @throws {ValidationError} If the custody type is not recognized.
   */
  static async create(options: { custody?: CustodyType } = {}): Promise<Identity> {
    const custody = options.custody ?? "platform";
    try {
      const bridge = await getBridge();
      const handle = await bridge.identityCreate(custody);
      return new Identity(handle.did, handle.custodyType, handle);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Loads an existing identity from a DID string.
   *
   * Validates the DID format and returns an identity handle. Key operations
   * require a wired `KeyCustodyProvider` callback for platform/software
   * custody types.
   *
   * @param did - The DID string to load (e.g., `"did:dht:z6Mk..."`).
   * @returns The loaded `Identity` instance.
   * @throws {IdentityError} If the DID format is invalid or loading fails.
   */
  static async load(did: string): Promise<Identity> {
    try {
      const bridge = await getBridge();
      const handle = await bridge.identityLoad(did);
      return new Identity(handle.did, handle.custodyType, handle);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Resolves a DID to its DID Document.
   *
   * Queries the DHT for the DID document. Requires network connectivity.
   *
   * @param did - The DID string to resolve.
   * @returns The resolved DID document.
   * @throws {IdentityError} If the DID cannot be resolved.
   */
  static async resolve(did: string): Promise<DIDDocument> {
    try {
      const bridge = await getBridge();
      return await bridge.identityResolve(did);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Rotates the active signing key for this identity.
   *
   * Generates a new Active Signing Key, updates the DID document, and
   * returns an updated identity with the same DID but a new key.
   *
   * @returns A new `Identity` instance with the rotated key.
   * @throws {IdentityError} If key rotation fails.
   */
  async rotateKey(): Promise<Identity> {
    try {
      const bridge = await getBridge();
      const handle = await bridge.identityRotateKey(this._handle);
      return new Identity(handle.did, handle.custodyType, handle);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }
}
