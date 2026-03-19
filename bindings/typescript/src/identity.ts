/**
 * Identity module for the SCP TypeScript SDK.
 *
 * Provides the `Identity` class for DID lifecycle management: creation,
 * loading, resolution, and key rotation. All operations delegate to the
 * runtime-selected bridge (napi-rs or WASM).
 *
 * See ADR-022 in `.docs/adrs/phase-4.md` and `.docs/scaffold/typescript.md`.
 */

import { IdentityError, mapBridgeError } from "./errors";
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

  /**
   * Executes the compromise recovery protocol for this identity.
   *
   * Runs the 6-step recovery protocol from spec section 9.12.
   *
   * @param tier - Compromise tier: `"agent"`, `"active_signing"`, or `"identity_key"`.
   * @param contextIds - Context IDs where this DID is a member.
   * @returns The recovery result as a parsed object.
   * @throws {IdentityError} If recovery fails.
   */
  async executeRecovery(
    tier: "agent" | "active_signing" | "identity_key",
    contextIds: string[] = [],
  ): Promise<Record<string, unknown>> {
    try {
      const bridge = await getBridge();
      const json = await bridge.identityExecuteRecovery(this.did, tier, contextIds);
      return JSON.parse(json);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Executes the custody migration protocol for this identity.
   *
   * Runs the 5-step migration protocol from spec section 3.2.1.
   *
   * @param target - Target custody type: `"platform_managed"`, `"hardware"`, `"software"`, or `"in_memory"`.
   * @param contextIds - Context IDs where this DID is a member.
   * @returns The migration result as a parsed object.
   * @throws {IdentityError} If migration fails.
   */
  async executeCustodyMigration(
    target: "platform_managed" | "hardware" | "software" | "in_memory",
    contextIds: string[] = [],
  ): Promise<Record<string, unknown>> {
    try {
      const bridge = await getBridge();
      const json = await bridge.identityExecuteCustodyMigration(this.did, target, contextIds);
      return JSON.parse(json);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  // ---------------------------------------------------------------------------
  // Identity Link Attestations (§3.5)
  // ---------------------------------------------------------------------------

  /**
   * Creates an identity link attestation for an external platform (§3.5).
   *
   * Cryptographically binds this DID to an external platform identity.
   * The proof is platform-specific evidence of ownership.
   *
   * @param options - Attestation creation options.
   * @param options.platform - Platform identifier (e.g., `"github.com"`).
   * @param options.handle - Platform-specific handle or username.
   * @param options.proof - Platform-specific proof of ownership.
   * @param options.platformId - Optional platform-assigned unique identifier.
   * @returns The created `IdentityAttestation`.
   * @throws {IdentityError} If the bridge function is not available.
   */
  async createAttestation(options: {
    platform: string;
    handle: string;
    proof: string;
    platformId?: string;
  }): Promise<IdentityAttestation> {
    try {
      const bridge = await getBridge();
      const fn = (bridge as unknown as Record<string, unknown>).identityCreateAttestation as
        | ((
            did: string,
            platform: string,
            handle: string,
            proof: string,
            platformId: string | undefined,
          ) => Promise<string>)
        | undefined;
      if (!fn) {
        throw new IdentityError(
          "Identity link attestation creation is not yet available in the bridge",
          "SCP-ATTEST-9001",
        );
      }
      const json = await fn(
        this.did,
        options.platform,
        options.handle,
        options.proof,
        options.platformId,
      );
      return IdentityAttestation._fromJson(json);
    } catch (error) {
      throw error instanceof IdentityError ? error : mapBridgeError(error);
    }
  }

  /**
   * Lists all identity link attestations for this identity.
   *
   * @returns An array of `IdentityAttestation` objects.
   * @throws {IdentityError} If the bridge function is not available.
   */
  async listAttestations(): Promise<readonly IdentityAttestation[]> {
    try {
      const bridge = await getBridge();
      const fn = (bridge as unknown as Record<string, unknown>).identityListAttestations as
        | ((did: string) => Promise<string>)
        | undefined;
      if (!fn) {
        throw new IdentityError(
          "Identity link attestation listing is not yet available in the bridge",
          "SCP-ATTEST-9002",
        );
      }
      const json = await fn(this.did);
      const items = JSON.parse(json) as Record<string, unknown>[];
      return items.map((item) => IdentityAttestation._fromRecord(item));
    } catch (error) {
      throw error instanceof IdentityError ? error : mapBridgeError(error);
    }
  }

  /**
   * Removes an identity link attestation by ID.
   *
   * @param attestationId - The deterministic attestation ID to remove.
   * @returns `true` if the attestation was found and removed.
   * @throws {IdentityError} If the bridge function is not available.
   */
  async removeAttestation(attestationId: string): Promise<boolean> {
    try {
      const bridge = await getBridge();
      const fn = (bridge as unknown as Record<string, unknown>).identityRemoveAttestation as
        | ((did: string, attestationId: string) => Promise<boolean>)
        | undefined;
      if (!fn) {
        throw new IdentityError(
          "Identity link attestation removal is not yet available in the bridge",
          "SCP-ATTEST-9003",
        );
      }
      return await fn(this.did, attestationId);
    } catch (error) {
      throw error instanceof IdentityError ? error : mapBridgeError(error);
    }
  }

  /**
   * Renews an identity link attestation with a fresh `verifiedAt`.
   *
   * @param attestation - The attestation to renew.
   * @returns A new `IdentityAttestation` with updated `verifiedAt`.
   * @throws {IdentityError} If the bridge function is not available.
   */
  async renewAttestation(attestation: IdentityAttestation): Promise<IdentityAttestation> {
    try {
      const bridge = await getBridge();
      const fn = (bridge as unknown as Record<string, unknown>).identityRenewAttestation as
        | ((did: string, attestationId: string) => Promise<string>)
        | undefined;
      if (!fn) {
        throw new IdentityError(
          "Identity link attestation renewal is not yet available in the bridge",
          "SCP-ATTEST-9004",
        );
      }
      const json = await fn(this.did, attestation.id);
      return IdentityAttestation._fromJson(json);
    } catch (error) {
      throw error instanceof IdentityError ? error : mapBridgeError(error);
    }
  }
}

// ---------------------------------------------------------------------------
// IdentityAttestation
// ---------------------------------------------------------------------------

/** Data for an identity link attestation (§3.5). */
export interface IdentityAttestationData {
  /** Deterministic attestation ID. */
  readonly id: string;
  /** Platform identifier (e.g., `"github.com"`). */
  readonly platform: string;
  /** Platform handle or username. */
  readonly platformHandle: string;
  /** DID verification method that signed this attestation. */
  readonly verificationMethod: string;
  /** Unix timestamp (seconds) when the evidence was last verified. */
  readonly verifiedAt: number;
  /** Revocation status: `"active"`, `"revoked"`, or `"expired"`. */
  readonly revocationStatus: string;
  /** Optional platform-assigned unique identifier. */
  readonly platformId?: string | undefined;
}

/**
 * An identity link attestation binding a DID to an external platform (§3.5).
 *
 * Represents a cryptographically signed claim that the DID owner also
 * controls an identity on an external platform (e.g., GitHub, X, LinkedIn).
 */
export class IdentityAttestation implements IdentityAttestationData {
  /** Deterministic attestation ID. */
  readonly id: string;
  /** Platform identifier (e.g., `"github.com"`). */
  readonly platform: string;
  /** Platform handle or username. */
  readonly platformHandle: string;
  /** DID verification method that signed this attestation. */
  readonly verificationMethod: string;
  /** Unix timestamp (seconds) when the evidence was last verified. */
  readonly verifiedAt: number;
  /** Revocation status: `"active"`, `"revoked"`, or `"expired"`. */
  readonly revocationStatus: string;
  /** Optional platform-assigned unique identifier. */
  readonly platformId?: string | undefined;

  constructor(data: IdentityAttestationData) {
    this.id = data.id;
    this.platform = data.platform;
    this.platformHandle = data.platformHandle;
    this.verificationMethod = data.verificationMethod;
    this.verifiedAt = data.verifiedAt;
    this.revocationStatus = data.revocationStatus;
    this.platformId = data.platformId;
  }

  /**
   * Verifies this attestation's signature and validity.
   *
   * Delegates to the bridge's `trust_verify_attestation` function.
   *
   * @returns `true` if the attestation is valid.
   * @throws {IdentityError} If the bridge function is not available.
   */
  async verify(): Promise<boolean> {
    try {
      const bridge = await getBridge();
      const fn = (bridge as unknown as Record<string, unknown>).trustVerifyAttestation as
        | ((json: string) => Promise<string>)
        | undefined;
      if (!fn) {
        throw new IdentityError(
          "Attestation verification is not yet available in the bridge",
          "SCP-ATTEST-9005",
        );
      }
      const resultJson = await fn(JSON.stringify(this._toBridgeRecord()));
      const result = JSON.parse(resultJson) as { valid?: boolean };
      return result.valid === true;
    } catch (error) {
      throw error instanceof IdentityError ? error : mapBridgeError(error);
    }
  }

  /** @internal */
  _toBridgeRecord(): Record<string, unknown> {
    const rec: Record<string, unknown> = {
      id: this.id,
      platform: this.platform,
      platform_handle: this.platformHandle,
      verification_method: this.verificationMethod,
      verified_at: this.verifiedAt,
      revocation_status: this.revocationStatus,
    };
    if (this.platformId !== undefined) {
      rec.platform_id = this.platformId;
    }
    return rec;
  }

  /** @internal */
  static _fromJson(json: string): IdentityAttestation {
    const data = JSON.parse(json) as Record<string, unknown>;
    return IdentityAttestation._fromRecord(data);
  }

  /** @internal */
  static _fromRecord(data: Record<string, unknown>): IdentityAttestation {
    return new IdentityAttestation({
      id: data.id as string,
      platform: data.platform as string,
      platformHandle: (data.platform_handle ?? data.platformHandle) as string,
      verificationMethod: (data.verification_method ?? data.verificationMethod) as string,
      verifiedAt: (data.verified_at ?? data.verifiedAt) as number,
      revocationStatus: ((data.revocation_status ?? data.revocationStatus) as string) || "active",
      platformId: (data.platform_id ?? data.platformId) as string | undefined,
    });
  }
}
