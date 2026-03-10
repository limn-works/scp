/**
 * Identity module for the SCP TypeScript SDK.
 *
 * Provides the `Identity` class for DID lifecycle management: creation,
 * loading, resolution, and key rotation. All operations delegate to the
 * runtime-selected bridge (napi-rs or WASM).
 *
 * See ADR-022 in `.docs/adrs/phase-4.md` and `.docs/scaffold/typescript.md`.
 */

import { mapBridgeError } from "./errors";
import type { BridgeIdentityHandle } from "./internal/bridge";
import { getBridge } from "./internal/bridge";
import type { DIDDocument } from "./types";

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

  /**
   * Creates a new identity with an agent signing key (ADR-039).
   *
   * Creates a DID identity with both the standard signing key and an
   * `#agent` verification method in the DID document.
   *
   * @param options - Creation options.
   * @param options.custody - The custody method. Defaults to `"platform"`.
   * @returns A new `Identity` with an agent key.
   * @throws {IdentityError} If creation fails.
   */
  static async createWithAgentKey(options: { custody?: CustodyType } = {}): Promise<Identity> {
    const custody = options.custody ?? "platform";
    try {
      const bridge = await getBridge();
      const handle = await bridge.identityCreateWithAgentKey(custody);
      return new Identity(handle.did, handle.custodyType, handle);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Adds an agent signing key to this identity (ADR-039).
   *
   * @returns A new `Identity` with the agent key added.
   * @throws {IdentityError} If this identity already has an agent key.
   */
  async addAgentKey(): Promise<Identity> {
    try {
      const bridge = await getBridge();
      const handle = await bridge.identityAddAgentKey(this._handle);
      return new Identity(handle.did, handle.custodyType, handle);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Rotates the agent signing key for this identity (ADR-039).
   *
   * @returns A new `Identity` with the rotated agent key.
   * @throws {IdentityError} If this identity has no agent key.
   */
  async rotateAgentKey(): Promise<Identity> {
    try {
      const bridge = await getBridge();
      const handle = await bridge.identityRotateAgentKey(this._handle);
      return new Identity(handle.did, handle.custodyType, handle);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Removes the agent signing key from this identity (ADR-039).
   *
   * @returns A new `Identity` with the agent key removed.
   * @throws {IdentityError} If this identity has no agent key.
   */
  async removeAgentKey(): Promise<Identity> {
    try {
      const bridge = await getBridge();
      const handle = await bridge.identityRemoveAgentKey(this._handle);
      return new Identity(handle.did, handle.custodyType, handle);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Migrates this identity to a new DID (Layer 2 rotation).
   *
   * Creates a new DID using the pre-rotation key. The old DID document
   * is updated with an `alsoKnownAs` pointing to the new DID.
   *
   * @returns A new `Identity` with the new DID.
   * @throws {IdentityError} If migration fails.
   */
  async migrate(): Promise<Identity> {
    try {
      const bridge = await getBridge();
      const handle = await bridge.identityMigrate(this._handle);
      return new Identity(handle.did, handle.custodyType, handle);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Generates a device attestation token for this identity.
   *
   * @returns The attestation token as a base64-encoded string.
   * @throws {IdentityError} If attestation generation fails.
   */
  async attestDevice(): Promise<string> {
    try {
      const bridge = await getBridge();
      return await bridge.identityAttestDevice(this.did);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Verifies a device attestation token.
   *
   * @param tokenBase64 - The base64-encoded attestation token.
   * @returns `true` if valid, `false` otherwise.
   * @throws {IdentityError} If verification fails.
   */
  async verifyDeviceAttestation(tokenBase64: string): Promise<boolean> {
    try {
      const bridge = await getBridge();
      return await bridge.identityVerifyDeviceAttestation(this.did, tokenBase64);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }
}
