/**
 * Identity module for the SCP TypeScript SDK.
 *
 * After Phase 4 PR 4 (#1549, ADR-048) Agent B1, the `Identity`,
 * `IdentityAttestation`, and `RevocationStatus` types collapse to pure
 * handle/value types: no `#scp` backing, no instance methods that
 * touch the bridge, no static factories. All lifecycle and attestation
 * operations live on the {@link SCP} class.
 *
 * See ADR-022 in `.docs/adrs/phase-4.md`, ADR-048, and
 * `.docs/scaffold/typescript.md`.
 */

import { ValidationError } from "./errors";
import type { BridgeIdentityHandle } from "./internal/bridge";
import type { SCP } from "./scp";

// ---------------------------------------------------------------------------
// IdentityLinkAttestation
// ---------------------------------------------------------------------------

/** An identity link attestation proving ownership of an external platform identity (§3.5.1). */
export interface IdentityLinkAttestation {
  /** Deterministic attestation ID. */
  id: string;
  /** Always `"identity_link"`. */
  type: string;
  /** The DID that issued this attestation. */
  issuer: string;
  /** Same as issuer for self-attestations. */
  subject: string;
  /** Unix timestamp (seconds) when created. */
  issued_at: number;
  /** Platform identity claim. */
  claim: {
    platform: string;
    platform_handle: string;
    platform_id?: string;
    link_type: string;
  };
  /** Evidence supporting the claim. */
  evidence: {
    method: string;
    /** Opaque proof string per spec §3.5.2 — verifiers MUST use as-is in signature scope. */
    proof: string;
    /** Unix timestamp (integer seconds) when the claim was verified. */
    verified_at: number;
    verifier_did?: string;
  };
  /** Revocation status: `"Active"` or `{ Revoked: { revoked_at, reason, revoked_by } }`. */
  revocation_status:
    | "Active"
    | {
        Revoked: {
          /** Unix timestamp (integer seconds) when the attestation was revoked. */
          revoked_at: number;
          reason: string;
          revoked_by: string;
        };
      };
  /** Ed25519 signature bytes. */
  signature: number[];
}

// ---------------------------------------------------------------------------
// CustodyType
// ---------------------------------------------------------------------------

/**
 * The custody request an identity-creating {@link SCP} method sends to the
 * NAPI bridge: the backend that holds the identity's private keys (spec
 * `03-identity.md` §3.2.2, custody request vocabulary).
 *
 * - `"encrypted_file"` keeps the keys in the encrypted key file
 *   `$HOME/.scp/keys.bin`, sealed under the passphrase in the
 *   `SCP_KEY_PASSPHRASE` environment variable (Argon2id plus AES-256-GCM). An
 *   unset, empty or relative `HOME`, or an unset or empty passphrase, rejects
 *   with a `ValidationError` carrying `SCP-VALID-7001`; a key file that does not
 *   open (a wrong passphrase, a failed integrity check) rejects with an
 *   `IdentityError` carrying `SCP-IDENT-1008`.
 * - `"os_keystore"` keeps the keys in the host's own key store, reached only
 *   through the `KeyCustodyProvider` you pass to
 *   {@link SCP.identityCreateWithCustody}, and an identity created that way
 *   reports `"os_keystore"`. {@link SCP.identityCreate} has no provider to
 *   reach, so it answers `"os_keystore"` with an `IdentityError` carrying
 *   `SCP-IDENT-1003`. The value promises that every use of a key goes through
 *   the provider; it promises no hardware backing.
 *
 * The union carries these two values and no other (§3.2.2). An addon built
 * with the bridge's `testing` feature also accepts the string `"in_memory"`,
 * which reaches a plaintext in-memory key store; that string is a test-harness
 * affordance, not a value of this type, and a shipped addon answers it with an
 * `IdentityError` carrying `SCP-IDENT-1008`.
 *
 * The bridge answers any other string, `"platform"`, `"software"`, `"file"`
 * and `"callback"` included, with a `ValidationError` carrying
 * `SCP-VALID-7005`. A shipped addon has no independent next-set substrate, so it
 * answers `"encrypted_file"` with an `IdentityError` carrying `SCP-IDENT-1100`
 * once the inputs resolve and before the key file opens.
 *
 * No SDK method defaults custody: the caller names the key store, and a call
 * that passes none rejects with an `IdentityError` carrying `SCP-IDENT-1116`
 * before any bridge call (SCP-294).
 */
export type CustodyType = "encrypted_file" | "os_keystore";

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/**
 * An opaque handle to an SCP identity.
 *
 * `Identity` is a pure data/handle type: it carries the DID string, the
 * custody type, and the raw bridge handle. All lifecycle operations
 * (`create`, `load`, `resolve`, `rotateKey`, agent-key management,
 * migrate, attestation CRUD, recovery, custody migration) live as
 * methods on the {@link SCP} class. Pass an `Identity` as an argument
 * wherever the underlying bridge call needs access to key material.
 *
 * ```typescript
 * const identity = await scp.identityCreate("encrypted_file");
 * console.log(identity.did); // "did:dht:z6Mk..."
 * await scp.identityRotateKey(identity);
 * ```
 */
export class Identity {
  /** The DID string for this identity (e.g., `"did:dht:z6Mk..."`). */
  readonly did: string;

  /**
   * The custody request the identity was created with (`"encrypted_file"` or
   * `"os_keystore"`; see {@link CustodyType}), or `"external"` for an identity
   * loaded with no retained key material. A test harness on a `testing` addon
   * also sees `"in_memory"`.
   */
  readonly custodyType: string;

  /** The opaque bridge handle; private, so it also brands real instances. */
  readonly #rawHandle: BridgeIdentityHandle;

  private constructor(did: string, custodyType: string, rawHandle: BridgeIdentityHandle) {
    this.did = did;
    this.custodyType = custodyType;
    this.#rawHandle = rawHandle;
  }

  /** @internal Opaque bridge handle — not part of the public API. */
  get _rawHandle(): BridgeIdentityHandle {
    return this.#rawHandle;
  }

  /**
   * Reports whether `value` is an `Identity` this SDK constructed. The check
   * reads a private field, so an object that copies an `Identity`'s public
   * fields, or one built from `Identity.prototype`, does not pass.
   *
   * @internal Used by the `SCP` methods to reject a wrong argument with
   *   `SCP-VALID-7005` before any bridge call.
   */
  static _isIdentity(value: unknown): value is Identity {
    return typeof value === "object" && value !== null && #rawHandle in value;
  }

  /**
   * The serialized `scp_identity::DidRotationEvent` produced by
   * {@link SCP.identityMigrate}. Present only on identities returned by
   * `identityMigrate`; `undefined` for all other operations.
   *
   * Callers **MUST** distribute this rotation event to all active context
   * members per spec §9.12 (Identity Key Migration) so peers can update their routing
   * tables.
   */
  get rotationEventJson(): string | undefined {
    return this._rawHandle.rotationEventJson;
  }

  /**
   * Constructs an `Identity` from a raw native NAPI handle.
   *
   * The native addon returns an opaque class instance with at least
   * `did` and `custodyType` fields; this helper narrows `unknown` into
   * an `Identity` wrapper. The `scp` parameter is retained for API
   * symmetry with the other `_fromHandle` statics — the handle itself
   * is self-contained so no `SCP` reference is stored.
   *
   * @internal Phase 4 PR 4 (#1549, ADR-048) — used by `SCP` method
   *   forwarders that return identity-typed results.
   */
  static _fromHandle(_scp: SCP, raw: unknown): Identity {
    const handle = raw as BridgeIdentityHandle;
    return new Identity(handle.did, handle.custodyType, handle);
  }
}

// ---------------------------------------------------------------------------
// RevocationStatus
// ---------------------------------------------------------------------------

/**
 * Revocation status for an identity attestation (§3.5).
 *
 * Mirrors the Rust `RevocationStatus` enum:
 *
 * - `Active` -> `RevocationStatus({ status: "active" })`
 * - `Revoked { revoked_at, reason }` ->
 *   `RevocationStatus({ status: "revoked", revokedAt: ..., reason: ... })`
 */
export type RevocationStatusData =
  | { readonly status: "active" }
  | { readonly status: "revoked"; readonly revokedAt: number; readonly reason?: string };

/**
 * Revocation status for an identity attestation (§3.5).
 *
 * Immutable value object. Use `RevocationStatus.active()` or
 * `RevocationStatus.revoked(revokedAt, reason?)` factory methods.
 */
export class RevocationStatus {
  /** Status string: `"active"` or `"revoked"`. */
  readonly status: "active" | "revoked";

  /**
   * Unix timestamp (seconds) when the attestation was revoked.
   * Only present when `status === "revoked"`.
   */
  readonly revokedAt: number | undefined;

  /**
   * Optional human-readable revocation reason.
   * Only present when `status === "revoked"`.
   */
  readonly reason: string | undefined;

  private constructor(data: RevocationStatusData) {
    this.status = data.status;
    if (data.status === "revoked") {
      this.revokedAt = data.revokedAt;
      this.reason = data.reason;
    } else {
      this.revokedAt = undefined;
      this.reason = undefined;
    }
  }

  /** Creates an active revocation status. */
  static active(): RevocationStatus {
    return new RevocationStatus({ status: "active" });
  }

  /** Creates a revoked revocation status. */
  static revoked(revokedAt: number, reason?: string): RevocationStatus {
    if (!Number.isInteger(revokedAt) || revokedAt < 0) {
      throw new ValidationError("revoked_at must be a non-negative integer", "SCP-VALID-7005");
    }
    const truncated = revokedAt;
    const data: RevocationStatusData =
      reason !== undefined
        ? { status: "revoked", revokedAt: truncated, reason }
        : { status: "revoked", revokedAt: truncated };
    return new RevocationStatus(data);
  }

  /** @internal Convert to bridge-compatible representation. */
  _toBridgeValue(): unknown {
    if (this.status === "revoked") {
      const revoked: Record<string, unknown> = {};
      if (this.revokedAt !== undefined) {
        revoked.revoked_at = this.revokedAt;
      }
      if (this.reason !== undefined) {
        revoked.reason = this.reason;
      }
      return { Revoked: revoked };
    }
    return "Active";
  }

  /** @internal Parse from bridge JSON representation. */
  static _fromBridgeValue(raw: unknown): RevocationStatus {
    if (typeof raw === "object" && raw !== null && "Revoked" in raw) {
      const revoked = (raw as Record<string, Record<string, unknown>>).Revoked;
      const revokedAtRaw = revoked?.revoked_at as number | undefined;
      if (revokedAtRaw === undefined) {
        throw new Error("Bridge returned Revoked status without revoked_at timestamp");
      }
      if (!Number.isInteger(revokedAtRaw) || revokedAtRaw < 0) {
        throw new ValidationError("revoked_at must be a non-negative integer", "SCP-VALID-7005");
      }
      return RevocationStatus.revoked(revokedAtRaw, revoked?.reason as string | undefined);
    }
    if (typeof raw === "string") {
      const lower = raw.toLowerCase();
      if (lower === "active") {
        return RevocationStatus.active();
      }
      if (lower === "revoked") {
        throw new Error("Bridge returned bare 'revoked' string without revocation metadata");
      }
    }
    throw new Error(`Unknown revocation status from bridge: ${String(raw)}`);
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
  /** Revocation status. */
  readonly revocationStatus: RevocationStatus;
  /** Optional platform-assigned unique identifier. */
  readonly platformId?: string | undefined;
}

/**
 * An identity link attestation binding a DID to an external platform (§3.5).
 *
 * Pure data/value class after Phase 4 PR 4 Agent B1 — no `#scp`
 * backing, no `verify()` method. Call
 * `scp.identityVerifyLinkAttestation(...)` with the raw attestation
 * JSON when signature verification is needed.
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
  /** Revocation status. */
  readonly revocationStatus: RevocationStatus;
  /** Optional platform-assigned unique identifier. */
  readonly platformId?: string | undefined;

  /** @internal Raw JSON string from the bridge for roundtrip verification. */
  readonly _rawJson?: string | undefined;

  constructor(data: IdentityAttestationData, rawJson?: string) {
    if (!Number.isInteger(data.verifiedAt) || data.verifiedAt < 0) {
      throw new ValidationError("verified_at must be a non-negative integer", "SCP-VALID-7005");
    }
    this.id = data.id;
    this.platform = data.platform;
    this.platformHandle = data.platformHandle;
    this.verificationMethod = data.verificationMethod;
    this.verifiedAt = data.verifiedAt;
    this.revocationStatus = data.revocationStatus;
    this.platformId = data.platformId;
    this._rawJson = rawJson;
  }

  /** @internal */
  _toBridgeRecord(): Record<string, unknown> {
    const rec: Record<string, unknown> = {
      id: this.id,
      platform: this.platform,
      platform_handle: this.platformHandle,
      verification_method: this.verificationMethod,
      verified_at: this.verifiedAt,
      revocation_status: this.revocationStatus._toBridgeValue(),
    };
    if (this.platformId !== undefined) {
      rec.platform_id = this.platformId;
    }
    return rec;
  }

  /** @internal */
  static _fromJson(json: string): IdentityAttestation {
    const data = JSON.parse(json) as Record<string, unknown>;
    return IdentityAttestation._fromRecord(data, json);
  }

  /** @internal */
  static _fromRecord(data: Record<string, unknown>, rawJson?: string): IdentityAttestation {
    // Read from nested `claim` and `evidence` structures when present
    // (full attestation JSON), with fallback to flat keys.
    const claim = (data.claim ?? {}) as Record<string, unknown>;
    const evidence = (data.evidence ?? {}) as Record<string, unknown>;

    const platform = (claim.platform ?? data.platform) as string;
    const platformHandle = (claim.platform_handle ??
      data.platform_handle ??
      data.platformHandle) as string;
    const platformId = (claim.platform_id ?? data.platform_id ?? data.platformId) as
      | string
      | undefined;
    const verificationMethod = (evidence.method ??
      data.verification_method ??
      data.verificationMethod) as string;
    const verifiedAtRaw = (evidence.verified_at ?? data.verified_at ?? data.verifiedAt) as number;
    if (!Number.isInteger(verifiedAtRaw) || verifiedAtRaw < 0) {
      throw new ValidationError("verified_at must be a non-negative integer", "SCP-VALID-7005");
    }
    const verifiedAt = verifiedAtRaw;
    const rawRs = data.revocation_status ?? data.revocationStatus ?? "active";
    const revocationStatus =
      rawRs instanceof RevocationStatus ? rawRs : RevocationStatus._fromBridgeValue(rawRs);

    return new IdentityAttestation(
      {
        id: data.id as string,
        platform,
        platformHandle,
        verificationMethod,
        verifiedAt,
        revocationStatus,
        platformId,
      },
      rawJson,
    );
  }
}
