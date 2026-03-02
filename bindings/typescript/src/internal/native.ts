/**
 * napi-rs native addon bridge adapter for Bun/Node.js.
 *
 * This module wraps the napi-rs native addon (`@scp/sdk-napi-{platform}`)
 * into the unified `Bridge` interface consumed by the TypeScript SDK.
 *
 * The native addon is loaded via `createRequire` from the platform-specific
 * optional dependency. If the package is not installed, loading fails with
 * a `TransportError` and an actionable message.
 *
 * See ADR-022 in `.docs/adrs/phase-4.md`.
 */

import { createRequire } from "node:module";

import { TransportError } from "../errors.js";
import type {
  Checkpoint,
  DIDDocument,
  Event,
  EventClaim,
  EventFilter,
  Message,
  Proof,
  ToolDefinition,
  ToolVerificationResult,
  TransportStatus,
  UcanToken,
} from "../types.js";
import type {
  Bridge,
  BridgeContextHandle,
  BridgeIdentityHandle,
  BridgeTransportHandle,
  MessageCallback,
} from "./bridge.js";

// ---------------------------------------------------------------------------
// Platform detection
// ---------------------------------------------------------------------------

/**
 * Resolves the platform-specific napi package name.
 *
 * Maps `process.platform` and `process.arch` to the napi-rs naming convention:
 * `@scp/sdk-napi-{os}-{arch}-{libc}`.
 */
function resolveNapiPackage(): string {
  const platform = process.platform;
  const arch = process.arch;

  const platformMap: Record<string, string> = {
    "linux-x64": "@scp/sdk-napi-linux-x64-gnu",
    "linux-arm64": "@scp/sdk-napi-linux-arm64-gnu",
    "darwin-x64": "@scp/sdk-napi-darwin-x64",
    "darwin-arm64": "@scp/sdk-napi-darwin-arm64",
    "win32-x64": "@scp/sdk-napi-win32-x64-msvc",
  };

  const key = `${platform}-${arch}`;
  const pkg = platformMap[key];

  if (pkg === undefined) {
    throw new TransportError(
      `No native addon available for platform ${key}. ` +
        "Install the appropriate @scp/sdk-napi-* package or use the WASM bridge in a browser environment.",
      "SCP-TRANS-5001",
    );
  }

  return pkg;
}

// ---------------------------------------------------------------------------
// Native addon loading
// ---------------------------------------------------------------------------

/** Shape of the native addon's exported functions. */
type NativeAddon = Record<string, (...args: never[]) => unknown>;

/**
 * Loads the platform-specific native addon via `createRequire`.
 *
 * Uses the Node.js `module.createRequire` API for ESM compatibility.
 * Falls back to a helpful error message if the package is not installed.
 */
function loadNativeAddon(): NativeAddon {
  const packageName = resolveNapiPackage();

  try {
    const req = createRequire(import.meta.url);
    return req(packageName) as NativeAddon;
  } catch {
    throw new TransportError(
      `Failed to load native addon ${packageName}. ` +
        `Ensure the package is installed: npm install ${packageName}`,
      "SCP-TRANS-5001",
    );
  }
}

// ---------------------------------------------------------------------------
// Bridge factory
// ---------------------------------------------------------------------------

/**
 * Creates a `Bridge` implementation backed by the napi-rs native addon.
 *
 * The returned bridge delegates all calls to the native addon's exported
 * functions, translating between the TypeScript `Bridge` interface and
 * the napi-rs flat function surface.
 */
export function createNativeBridge(): Bridge {
  const addon = loadNativeAddon();

  return {
    // Identity
    async identityCreate(custody: string): Promise<BridgeIdentityHandle> {
      const handle = await (addon.identityCreate as (c: string) => Promise<BridgeIdentityHandle>)(
        custody,
      );
      return handle;
    },

    async identityLoad(did: string): Promise<BridgeIdentityHandle> {
      const handle = await (addon.identityLoad as (d: string) => Promise<BridgeIdentityHandle>)(
        did,
      );
      return handle;
    },

    async identityResolve(did: string): Promise<DIDDocument> {
      const doc = await (
        addon.identityResolve as (d: string) => Promise<{
          id: string;
          authentication: string[];
          assertionMethods: string[];
          alsoKnownAs: string[];
          serviceEndpoints: string[];
        }>
      )(did);

      return {
        id: doc.id,
        verificationMethods: doc.authentication.map((auth) => ({
          id: auth,
          type: "Ed25519VerificationKey2020",
          controller: doc.id,
          publicKeyMultibase: "",
        })),
        authentication: doc.authentication,
        assertionMethods: doc.assertionMethods,
        alsoKnownAs: doc.alsoKnownAs,
        serviceEndpoints: doc.serviceEndpoints,
      };
    },

    async identityRotateKey(handle: BridgeIdentityHandle): Promise<BridgeIdentityHandle> {
      const result = await (
        addon.rotateKey as (h: BridgeIdentityHandle) => Promise<BridgeIdentityHandle>
      )(handle);
      return result;
    },

    // Context
    async contextCreate(
      identity: BridgeIdentityHandle,
      paramsJson: string,
    ): Promise<BridgeContextHandle> {
      const handle = await (
        addon.contextCreate as (id: BridgeIdentityHandle, p: string) => Promise<BridgeContextHandle>
      )(identity, paramsJson);
      return handle;
    },

    async contextJoin(handle: BridgeContextHandle, identityDid: string): Promise<void> {
      await (addon.contextJoin as (h: BridgeContextHandle, d: string) => Promise<void>)(
        handle,
        identityDid,
      );
    },

    async contextLeave(handle: BridgeContextHandle, identityDid: string): Promise<void> {
      await (addon.contextLeave as (h: BridgeContextHandle, d: string) => Promise<void>)(
        handle,
        identityDid,
      );
    },

    async contextClose(handle: BridgeContextHandle, identityDid: string): Promise<void> {
      await (addon.contextClose as (h: BridgeContextHandle, d: string) => Promise<void>)(
        handle,
        identityDid,
      );
    },

    async contextSend(
      handle: BridgeContextHandle,
      identityDid: string,
      payload: Uint8Array,
    ): Promise<void> {
      await (
        addon.contextSend as (h: BridgeContextHandle, d: string, p: Uint8Array) => Promise<void>
      )(handle, identityDid, payload);
    },

    contextSubscribe(
      handle: BridgeContextHandle,
      identityDid: string,
      callback: MessageCallback,
    ): void {
      (
        addon.contextSubscribe as (
          h: BridgeContextHandle,
          d: string,
          cb: (msg: Message | null) => void,
        ) => void
      )(handle, identityDid, (msg) => {
        if (msg === null) {
          callback.onComplete();
        } else {
          callback.onMessage(msg);
        }
      });
    },

    // Tools
    async toolRegister(handle: BridgeContextHandle, definition: ToolDefinition): Promise<string> {
      const toolId = await (
        addon.toolRegister as (h: BridgeContextHandle, d: ToolDefinition) => Promise<string>
      )(handle, definition);
      return toolId;
    },

    async toolInvoke(
      handle: BridgeContextHandle,
      toolId: string,
      inputJson: string,
      identityDid: string,
    ): Promise<string> {
      const result = await (
        addon.toolInvoke as (
          h: BridgeContextHandle,
          t: string,
          i: string,
          d: string,
        ) => Promise<string>
      )(handle, toolId, inputJson, identityDid);
      return result;
    },

    async toolVerify(handle: BridgeContextHandle, toolId: string): Promise<ToolVerificationResult> {
      const result = await (
        addon.toolVerify as (h: BridgeContextHandle, t: string) => Promise<ToolVerificationResult>
      )(handle, toolId);
      return result;
    },

    // Transport
    async transportConnect(relayUrl: string): Promise<BridgeTransportHandle> {
      const handle = await (
        addon.transportConnect as (u: string) => Promise<BridgeTransportHandle>
      )(relayUrl);
      return handle;
    },

    async transportStatus(handle: BridgeTransportHandle): Promise<TransportStatus> {
      const status = await (
        addon.transportStatus as (h: BridgeTransportHandle) => Promise<TransportStatus>
      )(handle);
      return status;
    },

    async transportDisconnect(handle: BridgeTransportHandle): Promise<void> {
      await (addon.transportDisconnect as (h: BridgeTransportHandle) => Promise<void>)(handle);
    },

    // UCAN
    async ucanValidate(
      handle: BridgeContextHandle,
      token: string,
      capability: string,
    ): Promise<void> {
      await (addon.ucanValidate as (h: BridgeContextHandle, t: string, c: string) => Promise<void>)(
        handle,
        token,
        capability,
      );
    },

    async ucanMint(
      handle: BridgeContextHandle,
      memberDid: string,
      capabilities: readonly string[],
    ): Promise<UcanToken> {
      const token = await (
        addon.ucanMint as (
          h: BridgeContextHandle,
          d: string,
          c: readonly string[],
        ) => Promise<UcanToken>
      )(handle, memberDid, capabilities);
      return token;
    },

    async ucanRevoke(handle: BridgeContextHandle, token: string): Promise<void> {
      await (addon.ucanRevoke as (h: BridgeContextHandle, t: string) => Promise<void>)(
        handle,
        token,
      );
    },

    // Event Log
    async eventLogQuery(
      handle: BridgeContextHandle,
      filter: EventFilter | undefined,
    ): Promise<readonly Event[]> {
      const filterJson = filter !== undefined ? JSON.stringify(filter) : undefined;
      const events = await (
        addon.eventLogQuery as (
          h: BridgeContextHandle,
          f: string | undefined,
        ) => Promise<readonly Event[]>
      )(handle, filterJson);
      return events;
    },

    async eventLogVerify(handle: BridgeContextHandle, claim: EventClaim): Promise<Proof> {
      const claimJson = JSON.stringify(claim);
      const proof = await (
        addon.eventLogVerify as (h: BridgeContextHandle, c: string) => Promise<Proof>
      )(handle, claimJson);
      return proof;
    },

    async eventLogCheckpoint(handle: BridgeContextHandle): Promise<Checkpoint> {
      const checkpoint = await (
        addon.eventLogCheckpoint as (h: BridgeContextHandle) => Promise<Checkpoint>
      )(handle);
      return checkpoint;
    },

    // Lifecycle
    version(): string {
      return (addon.scpVersion as () => string)();
    },

    shutdown(timeoutSecs: number): void {
      (addon.scpShutdown as (t: number) => void)(timeoutSecs);
    },
  };
}
