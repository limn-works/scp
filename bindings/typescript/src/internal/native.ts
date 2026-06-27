/**
 * napi-rs native addon bridge adapter for Bun/Node.js.
 *
 * This module wraps the napi-rs native addon (`@limn-works/scp-ts-napi-{platform}`)
 * into the unified `Bridge` interface consumed by the TypeScript SDK.
 *
 * The native addon is loaded via `createRequire` from the platform-specific
 * optional dependency. If the package is not installed, loading fails with
 * a `TransportError` and an actionable message.
 *
 * Since ADR-048 (#1549 Phase 4 PR 4), all calls route through the caller-
 * supplied {@link SCP} instance's class methods rather than module-level
 * free functions. The process-wide default-instance fallback was deleted
 * alongside `SCP.default()` in PR 4 — every bridge is constructed with an
 * explicit SCP. The handful of stateless helpers that remain as addon
 * free functions (e.g. `scpid_*`, pure validation helpers) do not need an
 * SCP because they touch no registry state.
 *
 * See ADR-022 in `.docs/adrs/phase-4.md` and ADR-048 for the
 * multi-instance routing design.
 */

import { createRequire } from "node:module";

import type { BridgeMode, ShadowStatus } from "../bridge";
import { TransportError } from "../errors";
import { __getNativeScp, type SCP } from "../scp";
import type {
  BroadcastAdmissionPolicy,
  CapabilityValidation,
  Checkpoint,
  DIDDocument,
  Event,
  EventClaim,
  EventFilter,
  MemberRole,
  Message,
  Proof,
  ToolDefinition,
  ToolVerificationResult,
  TransportStatus,
  UcanToken,
} from "../types";
import type {
  Bridge,
  BridgeContextHandle,
  BridgeIdentityHandle,
  BridgeTransportHandle,
  MessageCallback,
} from "./bridge";
import { wrapBridgeErrors } from "./bridge";
import { safeJsonParse } from "./json-utils";

// ---------------------------------------------------------------------------
// Platform detection
// ---------------------------------------------------------------------------

/**
 * Resolves the platform-specific napi package name.
 *
 * Maps `process.platform` and `process.arch` to the napi-rs naming convention:
 * `@limn-works/scp-ts-napi-{os}-{arch}-{libc}`.
 */
function resolveNapiPackage(): string {
  const platform = process.platform;
  const arch = process.arch;

  const platformMap: Record<string, string> = {
    "linux-x64": "@limn-works/scp-ts-napi-linux-x64-gnu",
    "linux-arm64": "@limn-works/scp-ts-napi-linux-arm64-gnu",
    "darwin-x64": "@limn-works/scp-ts-napi-darwin-x64",
    "darwin-arm64": "@limn-works/scp-ts-napi-darwin-arm64",
    "win32-x64": "@limn-works/scp-ts-napi-win32-x64-msvc",
  };

  const key = `${platform}-${arch}`;
  const pkg = platformMap[key];

  if (pkg === undefined) {
    throw new TransportError(
      `No native addon available for platform ${key}. ` +
        "Install the appropriate @limn-works/scp-ts-napi-* package for this platform.",
      "SCP-TRANS-5001",
    );
  }

  return pkg;
}

// ---------------------------------------------------------------------------
// Native addon loading
// ---------------------------------------------------------------------------

/**
 * Shape of the native addon as observed at the bridge layer. Both module-
 * level NAPI free functions and the `SCP` class constructor live on the
 * same object; sibling modules narrow at the use-site.
 */
export type NativeAddon = Record<string, unknown>;

// why: one-time FFI addon load cache. Holds the raw napi-rs object whose
// keys carry both the SCP class constructor (`addon.SCP`) and the
// module-level free-function exports (templateGetParams, scpVersion,
// discoveryParseAddress, …) per ADR-048 §1. A single shared cache is the
// only way to guarantee `internal/native.ts` and `scp.ts` see the same
// frozen handle — a second loader would call `createRequire(...)` again
// and `require.cache` could be tampered with by a compromised dep
// between calls. Allowlisted in scripts/check-no-ts-mutable-globals.sh.
let _nativeAddon: NativeAddon | null = null;

/**
 * Loads (or returns the cached) platform-specific native addon. The
 * returned object is `Object.freeze`d post-load so any code path that
 * later holds a reference cannot mutate the export shape (defence
 * against require-cache tampering between loader calls — see round-3
 * `_nativeScp` hardening discussion in ADR-048 §7).
 *
 * Both `internal/native.ts` and `scp.ts` route through this single
 * loader — the cache discipline only holds because there is exactly one
 * loader. Adding a second loader anywhere in the SDK is a regression.
 */
export function loadNativeAddon(): NativeAddon {
  if (_nativeAddon !== null) {
    return _nativeAddon;
  }

  const packageName = resolveNapiPackage();
  let addon: NativeAddon;
  try {
    const req = createRequire(import.meta.url);
    addon = req(packageName) as NativeAddon;
  } catch {
    throw new TransportError(
      `Failed to load native addon ${packageName}. ` +
        `Ensure the package is installed: npm install ${packageName}`,
      "SCP-TRANS-5001",
    );
  }

  // Freeze before caching: any later code path holding the addon
  // reference (the `addon` closure local in createNativeBridge, or any
  // `nativeFreeFn` lookup in scp.ts) reads from the same frozen object.
  // This blocks post-load monkey-patching of the addon's named exports
  // — a defense-in-depth control against a compromised optional dep
  // attempting to swap a free function for a malicious one between
  // loads. The freeze is shallow (its own properties); the SCP class's
  // prototype is left mutable because napi-rs constructs handles by
  // dispatching through it.
  Object.freeze(addon);
  _nativeAddon = addon;
  return _nativeAddon;
}

// ---------------------------------------------------------------------------
// Bridge factory
// ---------------------------------------------------------------------------

/**
 * Creates a `Bridge` implementation backed by the napi-rs native addon.
 *
 * The returned bridge delegates method calls to the given {@link SCP}
 * instance's class methods (ADR-048 per-instance routing) and falls back
 * to module-level free functions for the handful of bridge operations
 * that have not yet been ported onto the `SCP` class.
 *
 * @param scp The {@link SCP} wrapper whose native handle should receive
 *   all routable method calls. Required — the legacy process-wide
 *   default-instance fallback was removed in Phase 4 PR 4 (#1549)
 *   demolition.
 *
 * @internal
 */
export function createNativeBridge(scp: SCP): Bridge {
  const addon = loadNativeAddon();
  // Type-erased native handle — every NAPI `Scp` class method shares
  // the `async (...args) => unknown` shape after FFI monomorphization,
  // and routing requires dynamic lookup by camelCase method name.
  //
  // Dispatcher routing rule (ADR-048 §1 + §7, enforced by
  // bindings/typescript/tests/dispatcher-invariant.test.ts):
  //   • `native.X` → method on the per-instance SCP class
  //                  (Rust source: `impl Scp { #[napi] fn X(&self) }`
  //                   in crates/scp-ffi/napi/src/scp.rs)
  //   • `addon.X`  → module-level NAPI free function
  //                  (Rust source: `#[napi] pub fn X()` in any other
  //                   crates/scp-ffi/napi/src/*.rs file)
  // Routing through the wrong handle becomes `(undefined)(args)` at
  // runtime; a previous regression masked exactly this bug class —
  // fixed in 97051e32e + 176763958. The dispatcher invariant test
  // statically reads both source files and fails CI if any site uses
  // the wrong handle.
  const native = __getNativeScp(scp) as unknown as Record<string, (...args: never[]) => unknown>;

  const bridge: Bridge = {
    // Identity
    async identityCreate(custody: string): Promise<BridgeIdentityHandle> {
      const handle = await (native.identityCreate as (c: string) => Promise<BridgeIdentityHandle>)(
        custody,
      );
      return handle;
    },

    async identityLoad(did: string): Promise<BridgeIdentityHandle> {
      const handle = await (native.identityLoad as (d: string) => Promise<BridgeIdentityHandle>)(
        did,
      );
      return handle;
    },

    async identityResolve(did: string): Promise<DIDDocument> {
      const doc = await (
        native.identityResolve as (d: string) => Promise<{
          id: string;
          verificationMethods: readonly {
            id: string;
            type: string;
            controller: string;
            publicKeyMultibase: string;
          }[];
          authentication: string[];
          assertionMethods: string[];
          alsoKnownAs: string[];
          serviceEndpoints: string[];
          hasAgentKey: boolean;
          agentPublicKey: string | null;
        }>
      )(did);

      const result: DIDDocument = {
        id: doc.id,
        verificationMethods: doc.verificationMethods.map((vm) => ({
          id: vm.id,
          type: vm.type,
          controller: vm.controller,
          publicKeyMultibase: vm.publicKeyMultibase,
        })),
        authentication: doc.authentication,
        assertionMethods: doc.assertionMethods,
        alsoKnownAs: doc.alsoKnownAs,
        serviceEndpoints: doc.serviceEndpoints,
        hasAgentKey: doc.hasAgentKey,
        ...(doc.agentPublicKey != null ? { agentPublicKey: doc.agentPublicKey } : {}),
      };
      return result;
    },

    async identityRotateKey(handle: BridgeIdentityHandle): Promise<BridgeIdentityHandle> {
      const result = await (
        handle as unknown as { rotateKey(): Promise<BridgeIdentityHandle> }
      ).rotateKey();
      return result;
    },

    // Context
    async contextCreate(
      identity: BridgeIdentityHandle,
      paramsJson: string,
    ): Promise<BridgeContextHandle> {
      const handle = await (
        native.contextCreate as (
          id: BridgeIdentityHandle,
          p: string,
        ) => Promise<BridgeContextHandle>
      )(identity, paramsJson);
      return handle;
    },

    async contextJoin(
      handle: BridgeContextHandle,
      identityDid: string,
      spendingUcanJwt?: string | null,
    ): Promise<void> {
      await (
        native.contextJoin as (h: BridgeContextHandle, d: string, s: string | null) => Promise<void>
      )(handle, identityDid, spendingUcanJwt ?? null);
    },

    async contextLeave(handle: BridgeContextHandle, identityDid: string): Promise<void> {
      await (native.contextLeave as (h: BridgeContextHandle, d: string) => Promise<void>)(
        handle,
        identityDid,
      );
    },

    async contextClose(handle: BridgeContextHandle, identityDid: string): Promise<void> {
      await (native.contextClose as (h: BridgeContextHandle, d: string) => Promise<void>)(
        handle,
        identityDid,
      );
    },

    async contextSend(
      handle: BridgeContextHandle,
      identityDid: string,
      payload: Uint8Array,
      spendingUcanJwt?: string | null,
    ): Promise<void> {
      // NAPI Vec<u8> maps to number[] in JS, not Uint8Array.
      const payloadArray = Array.from(payload) as unknown as number[];
      await (
        native.contextSend as (
          h: BridgeContextHandle,
          d: string,
          p: number[],
          s: string | null,
        ) => Promise<void>
      )(handle, identityDid, payloadArray, spendingUcanJwt ?? null);
    },

    async contextSubscribe(
      handle: BridgeContextHandle,
      identityDid: string,
      callback: MessageCallback,
    ): Promise<void> {
      // NAPI `context_subscribe` is `async` after coder H's #1549 Phase 4
      // PR 1 changes — the subscription task is now registered against
      // the bridge's `JoinSet` / cancel token so shutdown drains it
      // deterministically. The returned Promise resolves once the
      // subscription task is registered (not when it completes).
      await (
        native.contextSubscribe as (
          h: BridgeContextHandle,
          d: string,
          cb: (msg: Message | null) => void,
        ) => Promise<void>
      )(handle, identityDid, (msg) => {
        if (msg === null) {
          callback.onComplete();
        } else {
          callback.onMessage(msg);
        }
      });
    },

    contextCancelSubscription(handle: BridgeContextHandle): void {
      (native.contextCancelSubscription as (h: BridgeContextHandle) => void)(handle);
    },

    // Membership queries
    async contextMemberCount(handle: BridgeContextHandle): Promise<number | null> {
      const result = await (
        native.contextMemberCount as (h: BridgeContextHandle) => Promise<number | null>
      )(handle);
      return result;
    },

    async contextIsMember(handle: BridgeContextHandle, did: string): Promise<boolean> {
      return await (
        native.contextIsMember as (h: BridgeContextHandle, d: string) => Promise<boolean>
      )(handle, did);
    },

    async contextMemberDids(handle: BridgeContextHandle): Promise<readonly string[]> {
      return await (
        native.contextMemberDids as (h: BridgeContextHandle) => Promise<readonly string[]>
      )(handle);
    },

    async contextMemberRole(handle: BridgeContextHandle, did: string): Promise<MemberRole | null> {
      const raw = await (
        native.contextMemberRole as (h: BridgeContextHandle, d: string) => Promise<string | null>
      )(handle, did);
      if (raw === null) return null;
      // The NAPI bridge returns lowercase ("admin", "member") but the Bridge
      // interface expects PascalCase ("Admin", "Member"). Normalize here.
      // Closes #1236.
      return (raw.charAt(0).toUpperCase() + raw.slice(1)) as MemberRole;
    },

    // Broadcast operations
    async broadcastSubscribe(handle: BridgeContextHandle, subscriberDid: string): Promise<void> {
      await (native.broadcastSubscribe as (h: BridgeContextHandle, d: string) => Promise<void>)(
        handle,
        subscriberDid,
      );
    },

    async broadcastUnsubscribe(
      handle: BridgeContextHandle,
      subscriberDid: string,
      rotateKeys?: boolean,
    ): Promise<void> {
      await (
        native.broadcastUnsubscribe as (
          h: BridgeContextHandle,
          d: string,
          r: boolean | undefined,
        ) => Promise<void>
      )(handle, subscriberDid, rotateKeys);
    },

    async broadcastPublish(
      handle: BridgeContextHandle,
      authorDid: string,
      payload: Uint8Array,
    ): Promise<void> {
      // NAPI Vec<u8> maps to number[] in JS, not Uint8Array.
      const payloadArray = Array.from(payload) as unknown as number[];
      await (
        native.broadcastPublish as (h: BridgeContextHandle, d: string, p: number[]) => Promise<void>
      )(handle, authorDid, payloadArray);
    },

    async broadcastPublishAsset(
      handle: BridgeContextHandle,
      authorDid: string,
      asset: { path: string; contentType: string; body: number[] },
      deployId: string | null,
    ): Promise<{ blobId: string; etag: string; deployId: string }> {
      return await (
        native.broadcastPublishAsset as (
          h: BridgeContextHandle,
          d: string,
          a: { path: string; contentType: string; body: number[] },
          did: string | null,
        ) => Promise<{ blobId: string; etag: string; deployId: string }>
      )(handle, authorDid, asset, deployId);
    },

    async broadcastPublishAssets(
      handle: BridgeContextHandle,
      authorDid: string,
      assets: { path: string; contentType: string; body: number[] }[],
      deployId: string | null,
    ): Promise<{
      results: { blobId: string; etag: string; deployId: string }[];
      deployId: string;
    }> {
      return await (
        native.broadcastPublishAssets as (
          h: BridgeContextHandle,
          d: string,
          a: { path: string; contentType: string; body: number[] }[],
          did: string | null,
        ) => Promise<{
          results: { blobId: string; etag: string; deployId: string }[];
          deployId: string;
        }>
      )(handle, authorDid, assets, deployId);
    },

    async broadcastBlockSubscriber(
      handle: BridgeContextHandle,
      subscriberDid: string,
      blockerDid: string,
    ): Promise<void> {
      await (
        native.broadcastBlockSubscriber as (
          h: BridgeContextHandle,
          s: string,
          b: string,
        ) => Promise<void>
      )(handle, subscriberDid, blockerDid);
    },

    async broadcastUnblockSubscriber(
      handle: BridgeContextHandle,
      subscriberDid: string,
      unblockerDid: string,
    ): Promise<void> {
      await (
        native.broadcastUnblockSubscriber as (
          h: BridgeContextHandle,
          s: string,
          u: string,
        ) => Promise<void>
      )(handle, subscriberDid, unblockerDid);
    },

    async broadcastHandleKeyRequest(
      handle: BridgeContextHandle,
      authorDid: string,
      requesterDid: string,
      wrappingPubkey: Uint8Array,
    ): Promise<string | null> {
      // NAPI Vec<u8> IN params map to number[] in JS, not Uint8Array.
      const wrappingArray = Array.from(wrappingPubkey) as unknown as number[];
      return await (
        native.broadcastHandleKeyRequest as (
          h: BridgeContextHandle,
          a: string,
          r: string,
          w: number[],
        ) => Promise<string | null>
      )(handle, authorDid, requesterDid, wrappingArray);
    },

    async broadcastOpenKey(sealedJson: string, wrappingSecret: Uint8Array): Promise<Uint8Array> {
      // Free NAPI function (`#[napi] pub fn broadcast_open_key` in
      // crates/scp-ffi/napi/src/context.rs) — routed through `addon.X`, not
      // the per-instance `native.X`, per the ADR-048 dispatcher rule. The
      // Rust fn is synchronous (`Result<Vec<u8>>`); its Vec<u8> IN param maps
      // to number[] in JS, and the Vec<u8> return is a Buffer (a Uint8Array).
      const secretArray = Array.from(wrappingSecret) as unknown as number[];
      return (addon.broadcastOpenKey as (s: string, w: number[]) => Uint8Array)(
        sealedJson,
        secretArray,
      );
    },

    async broadcastSubscriberCount(handle: BridgeContextHandle): Promise<number | null> {
      return await (
        native.contextBroadcastSubscriberCount as (h: BridgeContextHandle) => Promise<number | null>
      )(handle);
    },

    async broadcastIsSubscriber(handle: BridgeContextHandle, did: string): Promise<boolean> {
      return await (
        native.contextIsBroadcastSubscriber as (
          h: BridgeContextHandle,
          d: string,
        ) => Promise<boolean>
      )(handle, did);
    },

    async broadcastAdmission(
      handle: BridgeContextHandle,
    ): Promise<BroadcastAdmissionPolicy | null> {
      return await (
        native.contextBroadcastAdmission as (
          h: BridgeContextHandle,
        ) => Promise<BroadcastAdmissionPolicy | null>
      )(handle);
    },

    // Governance
    async contextExecuteGovernanceAction(
      handle: BridgeContextHandle,
      proposalIdHex: string,
    ): Promise<string> {
      return await (
        native.contextExecuteGovernanceAction as (
          h: BridgeContextHandle,
          p: string,
        ) => Promise<string>
      )(handle, proposalIdHex);
    },

    // Governance lifecycle (#559)
    async contextApplyPendingCeilingModification(
      handle: BridgeContextHandle,
      currentTimestamp: number,
    ): Promise<boolean> {
      return await (
        native.contextApplyPendingCeilingModification as (
          h: BridgeContextHandle,
          t: number,
        ) => Promise<boolean>
      )(handle, currentTimestamp);
    },

    async contextFinalizeClose(handle: BridgeContextHandle): Promise<void> {
      await (native.contextFinalizeClose as (h: BridgeContextHandle) => Promise<void>)(handle);
    },

    async contextCreateGovernanceCheckpoint(
      handle: BridgeContextHandle,
      checkpointSeq: number,
      merkleRootHex: string,
      eventCount: number,
      lastEventHashHex: string,
      stateSnapshotHashHex: string,
      creatorDid: string,
      creatorSignatureHex: string,
    ): Promise<string> {
      return await (
        native.contextCreateGovernanceCheckpoint as (
          h: BridgeContextHandle,
          seq: number,
          root: string,
          count: number,
          lastHash: string,
          stateHash: string,
          creator: string,
          sig: string,
        ) => Promise<string>
      )(
        handle,
        checkpointSeq,
        merkleRootHex,
        eventCount,
        lastEventHashHex,
        stateSnapshotHashHex,
        creatorDid,
        creatorSignatureHex,
      );
    },

    async contextAddCheckpointCosignature(
      handle: BridgeContextHandle,
      checkpointJson: string,
      signerDid: string,
      signatureHex: string,
    ): Promise<string> {
      return await (
        native.contextAddCheckpointCosignature as (
          h: BridgeContextHandle,
          c: string,
          s: string,
          sig: string,
        ) => Promise<string>
      )(handle, checkpointJson, signerDid, signatureHex);
    },

    async contextRestore(contextId: string): Promise<void> {
      await (native.contextRestore as (id: string) => Promise<void>)(contextId);
    },

    async contextRestoreAll(): Promise<string> {
      return await (native.contextRestoreAll as () => Promise<string>)();
    },

    // Governance proposal lifecycle (#621)
    async contextGovernancePropose(
      handle: BridgeContextHandle,
      actionJson: string,
      proposerDid: string,
    ): Promise<string> {
      return await (
        native.contextGovernancePropose as (
          h: BridgeContextHandle,
          a: string,
          p: string,
        ) => Promise<string>
      )(handle, actionJson, proposerDid);
    },
    async contextGovernanceApprove(
      handle: BridgeContextHandle,
      proposalIdHex: string,
      voterDid: string,
    ): Promise<string> {
      return await (
        native.contextGovernanceApprove as (
          h: BridgeContextHandle,
          p: string,
          v: string,
        ) => Promise<string>
      )(handle, proposalIdHex, voterDid);
    },
    async contextGovernanceReject(
      handle: BridgeContextHandle,
      proposalIdHex: string,
      voterDid: string,
    ): Promise<string> {
      return await (
        native.contextGovernanceReject as (
          h: BridgeContextHandle,
          p: string,
          v: string,
        ) => Promise<string>
      )(handle, proposalIdHex, voterDid);
    },
    async contextGovernanceWithdraw(
      handle: BridgeContextHandle,
      proposalIdHex: string,
      voterDid: string,
    ): Promise<string> {
      return await (
        native.contextGovernanceWithdraw as (
          h: BridgeContextHandle,
          p: string,
          v: string,
        ) => Promise<string>
      )(handle, proposalIdHex, voterDid);
    },
    async contextGovernanceGetProposal(
      handle: BridgeContextHandle,
      proposalIdHex: string,
    ): Promise<string> {
      return await (
        native.contextGovernanceGetProposal as (
          h: BridgeContextHandle,
          p: string,
        ) => Promise<string>
      )(handle, proposalIdHex);
    },
    async contextGovernanceListProposals(handle: BridgeContextHandle): Promise<string> {
      return await (
        native.contextGovernanceListProposals as (h: BridgeContextHandle) => Promise<string>
      )(handle);
    },

    // TTL operations
    async contextExtendTtl(
      _handle: BridgeContextHandle,
      _additionalSecs: number,
    ): Promise<boolean> {
      // The NAPI bridge does not export contextExtendTtl — scp-core's
      // ContextManager uses contextProposeTtlExtension (governance-aware) or
      // contextResetTtlTimer instead. These are exposed separately above.
      throw new TransportError(
        "contextExtendTtl is not available in the native (NAPI) bridge. " +
          "Use contextProposeTtlExtension (governance-aware) or " +
          "contextResetTtlTimer for TTL management in native environments.",
        "SCP-TRANS-5004",
      );
    },

    async contextHandleTtlExpiry(handle: BridgeContextHandle): Promise<void> {
      await (native.contextHandleTtlExpiry as (h: BridgeContextHandle) => Promise<void>)(handle);
    },

    async contextProposeTtlExtension(
      handle: BridgeContextHandle,
      proposerDid: string,
      extensionSecs: number,
    ): Promise<boolean> {
      return await (
        native.contextProposeTtlExtension as (
          h: BridgeContextHandle,
          d: string,
          s: number,
        ) => Promise<boolean>
      )(handle, proposerDid, extensionSecs);
    },

    async contextResetTtlTimer(
      handle: BridgeContextHandle,
      newDurationSecs: number,
    ): Promise<void> {
      await (native.contextResetTtlTimer as (h: BridgeContextHandle, s: number) => Promise<void>)(
        handle,
        newDurationSecs,
      );
    },

    // Economic policy (§19.3)
    async contextSetEconomicPolicy(handle: BridgeContextHandle, policyJson: string): Promise<void> {
      await (
        native.contextSetEconomicPolicy as (h: BridgeContextHandle, p: string) => Promise<void>
      )(handle, policyJson);
    },

    async contextGetEconomicPolicy(handle: BridgeContextHandle): Promise<string | null> {
      const result = await (
        native.contextGetEconomicPolicy as (h: BridgeContextHandle) => Promise<string | null>
      )(handle);
      return result ?? null;
    },

    // Context export/import
    async contextExport(handle: BridgeContextHandle): Promise<Uint8Array> {
      const data = await (native.contextExport as (h: BridgeContextHandle) => Promise<Buffer>)(
        handle,
      );
      return new Uint8Array(data);
    },

    async contextImport(data: Uint8Array, importerDid: string): Promise<string> {
      // NAPI Vec<u8> maps to number[] in JS, not Uint8Array.
      const dataArray = Array.from(data) as unknown as number[];
      return await (native.contextImport as (d: number[], did: string) => Promise<string>)(
        dataArray,
        importerDid,
      );
    },

    async contextSeedPeerPseudonym(
      handle: BridgeContextHandle,
      peerDid: string,
      pseudonym: Uint8Array,
    ): Promise<void> {
      // NAPI takes a Buffer for the 32-byte pseudonym; a Uint8Array is accepted
      // directly by napi-rs Buffer params.
      await (
        native.contextSeedPeerPseudonym as (
          h: BridgeContextHandle,
          d: string,
          p: Uint8Array,
        ) => Promise<void>
      )(handle, peerDid, pseudonym);
    },

    // Drain events
    async contextDrainEvents(handle: BridgeContextHandle): Promise<readonly string[]> {
      return await (
        native.contextDrainEvents as (h: BridgeContextHandle) => Promise<readonly string[]>
      )(handle);
    },

    // Tools
    async toolRegister(handle: BridgeContextHandle, definition: ToolDefinition): Promise<string> {
      // NapiToolDefinition has different field names from the Bridge ToolDefinition.
      const napiDef = {
        name: definition.name,
        description: definition.description,
        inputSchemaJson: JSON.stringify(definition.inputSchema),
        outputSchemaJson: JSON.stringify(definition.outputSchema),
        operatorDid: definition.operator,
        testVectorsJson: definition.testVectors
          ? JSON.stringify(definition.testVectors)
          : undefined,
        implementationHash: definition.implementationHash
          ? Array.from(definition.implementationHash)
          : undefined,
        cost: definition.cost
          ? {
              amount: definition.cost.amount,
              currency: definition.cost.currency,
              payee: definition.cost.payee,
              costFormula: definition.cost.costFormula,
            }
          : undefined,
      };
      const toolId = await (
        native.toolRegister as (h: BridgeContextHandle, d: typeof napiDef) => Promise<string>
      )(handle, napiDef);
      return toolId;
    },

    async toolInvoke(
      handle: BridgeContextHandle,
      toolId: string,
      inputJson: string,
      identityDid: string,
      ucanToken: string,
      proofTokens?: readonly string[],
      spendingUcan?: string,
    ): Promise<string> {
      // C4 (#1606): NAPI tool_invoke now routes through
      // ContextManager.invoke_tool_with_economy. The bridge accepts an
      // optional spendingUcan JWT for AND-composition with the action
      // UCAN under spec section 19.5.
      const result = await (
        native.toolInvoke as (
          h: BridgeContextHandle,
          t: string,
          i: string,
          d: string,
          u: string,
          p: readonly string[] | undefined,
          s: string | undefined,
        ) => Promise<string>
      )(handle, toolId, inputJson, identityDid, ucanToken, proofTokens, spendingUcan);
      return result;
    },

    async toolVerify(handle: BridgeContextHandle, toolId: string): Promise<ToolVerificationResult> {
      const result = await (
        native.toolVerify as (h: BridgeContextHandle, t: string) => Promise<ToolVerificationResult>
      )(handle, toolId);
      return result;
    },

    // Bidirectional consent protocol (§6.2.0.1)
    async toolInterfaceExpose(
      handle: BridgeContextHandle,
      toolId: string,
      targetContextId: string,
      rateLimitJson?: string,
    ): Promise<string> {
      return await (
        native.toolInterfaceExpose as (
          h: BridgeContextHandle,
          t: string,
          tc: string,
          rl?: string,
        ) => Promise<string>
      )(handle, toolId, targetContextId, rateLimitJson);
    },

    async toolInterfaceAccept(handle: BridgeContextHandle, interfaceJson: string): Promise<string> {
      return await (
        native.toolInterfaceAccept as (h: BridgeContextHandle, ij: string) => Promise<string>
      )(handle, interfaceJson);
    },

    async toolInterfaceRevoke(
      handle: BridgeContextHandle,
      interfaceIdHex: string,
    ): Promise<string> {
      return await (
        native.toolInterfaceRevoke as (h: BridgeContextHandle, id: string) => Promise<string>
      )(handle, interfaceIdHex);
    },

    // Cross-context tool invocation (spec section 6.2)
    async toolInvokeCrossContext(
      sourceHandle: BridgeContextHandle,
      targetHandle: BridgeContextHandle,
      toolId: string,
      inputJson: string,
      invokerDid: string,
      ucanToken: string,
      chainDepth: number,
      proofTokens?: readonly string[],
    ): Promise<string> {
      return await (
        native.toolInvokeCrossContext as (
          s: BridgeContextHandle,
          t: BridgeContextHandle,
          tool: string,
          input: string,
          did: string,
          ucan: string,
          depth: number,
          proofs: readonly string[] | undefined,
        ) => Promise<string>
      )(
        sourceHandle,
        targetHandle,
        toolId,
        inputJson,
        invokerDid,
        ucanToken,
        chainDepth,
        proofTokens,
      );
    },

    // Stateful tool sessions (spec section 6.2.1)
    async toolSessionCreate(
      handle: BridgeContextHandle,
      toolId: string,
      sourceContextId: string,
      ttlSeconds?: number,
    ): Promise<string> {
      return await (
        native.toolSessionCreate as (
          h: BridgeContextHandle,
          t: string,
          s: string,
          ttl: number | undefined,
        ) => Promise<string>
      )(handle, toolId, sourceContextId, ttlSeconds);
    },

    async toolSessionInvoke(
      handle: BridgeContextHandle,
      sessionId: string,
      inputJson: string,
      invokerDid: string,
      ucanToken: string,
      proofTokens?: readonly string[],
    ): Promise<string> {
      return await (
        native.toolSessionInvoke as (
          h: BridgeContextHandle,
          sid: string,
          input: string,
          did: string,
          ucan: string,
          proofs: readonly string[] | undefined,
        ) => Promise<string>
      )(handle, sessionId, inputJson, invokerDid, ucanToken, proofTokens);
    },

    async toolSessionClose(handle: BridgeContextHandle, sessionId: string): Promise<void> {
      await (native.toolSessionClose as (h: BridgeContextHandle, sid: string) => Promise<void>)(
        handle,
        sessionId,
      );
    },

    // Transport
    async transportConnect(relayUrl: string): Promise<BridgeTransportHandle> {
      const handle = await (
        native.transportConnect as (u: string) => Promise<BridgeTransportHandle>
      )(relayUrl);
      return handle;
    },

    async transportStatus(handle: BridgeTransportHandle): Promise<TransportStatus> {
      const status = await (
        native.transportStatus as (h: BridgeTransportHandle) => Promise<TransportStatus>
      )(handle);
      return status;
    },

    async transportDisconnect(handle: BridgeTransportHandle): Promise<void> {
      await (native.transportDisconnect as (h: BridgeTransportHandle) => Promise<void>)(handle);
    },

    // UCAN
    async ucanValidate(
      handle: BridgeContextHandle,
      token: string,
      capability: string,
    ): Promise<void> {
      await (
        native.ucanValidate as (h: BridgeContextHandle, t: string, c: string) => Promise<void>
      )(handle, token, capability);
    },

    async ucanEvaluate(
      handle: BridgeContextHandle,
      token: string,
      capability?: string | null,
      presentingAgentDid?: string,
      proofTokens?: readonly string[],
    ): Promise<CapabilityValidation> {
      // NAPI `ucanEvaluate` (scp.rs) returns a NapiCapabilityValidation
      // #[napi(object)] whose fields are already camelCased — no remap. The
      // optional params map to `null` for the napi-rs `Option<…>` signature;
      // a `null` capability runs the intrinsic-validity diagnostic (no
      // invoked-capability grant-match challenge).
      const raw = await (
        native.ucanEvaluate as (
          h: BridgeContextHandle,
          t: string,
          c: string | null,
          pa: string | null,
          pt: readonly string[] | null,
        ) => Promise<CapabilityValidation>
      )(handle, token, capability ?? null, presentingAgentDid ?? null, proofTokens ?? null);
      return {
        tokensValid: raw.tokensValid,
        signaturesValid: raw.signaturesValid,
        withinCeiling: raw.withinCeiling,
        nonceValid: raw.nonceValid,
        notRevoked: raw.notRevoked,
        timeBoundsValid: raw.timeBoundsValid,
      };
    },

    async ucanMint(
      handle: BridgeContextHandle,
      memberDid: string,
      capabilities: readonly string[],
      proofs?: readonly string[],
    ): Promise<UcanToken> {
      const token = await (
        native.ucanMint as (
          h: BridgeContextHandle,
          d: string,
          c: readonly string[],
          p: readonly string[] | null,
        ) => Promise<UcanToken>
      )(handle, memberDid, capabilities, proofs ?? null);
      return token;
    },

    async ucanRevoke(
      handle: BridgeContextHandle,
      token: string,
      revokerDid: string,
    ): Promise<void> {
      await (native.ucanRevoke as (h: BridgeContextHandle, t: string, r: string) => Promise<void>)(
        handle,
        token,
        revokerDid,
      );
    },

    async ucanDelegate(
      handle: BridgeContextHandle,
      delegatorDid: string,
      delegateeDid: string,
      parentToken: string,
      capabilities: readonly string[],
    ): Promise<UcanToken> {
      return await (
        native.ucanDelegate as (
          h: BridgeContextHandle,
          from: string,
          to: string,
          parent: string,
          caps: readonly string[],
        ) => Promise<UcanToken>
      )(handle, delegatorDid, delegateeDid, parentToken, capabilities);
    },

    // Trust Aggregation
    async aggregateTrustInput(
      contextId: string,
      subjectDid: string,
      eventsJson: string,
      merkleRootJson: string,
      consequenceRulesJson: string,
      thresholdRequirementsJson: string,
      attestorSetsJson: string,
      cachedAttestationsJson: string,
      challengeResultsJson: string,
    ): Promise<string> {
      return (
        native.aggregateTrustInput as (
          contextId: string,
          subjectDid: string,
          eventsJson: string,
          merkleRootJson: string,
          consequenceRulesJson: string,
          thresholdRequirementsJson: string,
          attestorSetsJson: string,
          cachedAttestationsJson: string,
          challengeResultsJson: string,
        ) => string
      )(
        contextId,
        subjectDid,
        eventsJson,
        merkleRootJson,
        consequenceRulesJson,
        thresholdRequirementsJson,
        attestorSetsJson,
        cachedAttestationsJson,
        challengeResultsJson,
      );
    },

    // Event Log
    async eventLogQuery(
      handle: BridgeContextHandle,
      filter: EventFilter | undefined,
    ): Promise<readonly Event[]> {
      // Convert camelCase filter keys to snake_case for the Rust bridge.
      let filterJson: string | undefined;
      if (filter !== undefined) {
        const snakeFilter: Record<string, unknown> = {};
        if (filter.eventType !== undefined) snakeFilter.event_type = filter.eventType;
        if (filter.actorDid !== undefined) snakeFilter.actor_did = filter.actorDid;
        if (filter.afterSequence !== undefined) snakeFilter.after_sequence = filter.afterSequence;
        if (filter.beforeSequence !== undefined)
          snakeFilter.before_sequence = filter.beforeSequence;
        if (filter.limit !== undefined) snakeFilter.limit = filter.limit;
        filterJson = JSON.stringify(snakeFilter);
      }
      const raw = await (
        native.eventLogQuery as (
          h: BridgeContextHandle,
          f: string | undefined,
        ) => Promise<
          readonly {
            eventType: string;
            actorDid: string;
            timestamp: number;
            payloadJson: string;
            sequence: number;
          }[]
        >
      )(handle, filterJson);
      // NAPI #[napi(object)] returns camelCase keys, but payloadJson is a JSON
      // string that needs to be parsed into the `payload` object.
      return raw.map((e) => ({
        eventType: e.eventType,
        actorDid: e.actorDid,
        timestamp: e.timestamp,
        payload: safeJsonParse(e.payloadJson, "eventLogQuery") as Readonly<Record<string, unknown>>,
        sequence: e.sequence,
      }));
    },

    async eventLogVerify(handle: BridgeContextHandle, claim: EventClaim): Promise<Proof> {
      // Convert camelCase claim keys to snake_case for the Rust bridge.
      const snakeClaim: Record<string, unknown> = { type: claim.type };
      if (claim.leafIndex !== undefined) snakeClaim.leaf_index = claim.leafIndex;
      if (claim.eventHash !== undefined) snakeClaim.event_hash = claim.eventHash;
      const claimJson = JSON.stringify(snakeClaim);
      const raw = await (
        native.eventLogVerify as (
          h: BridgeContextHandle,
          c: string,
        ) => Promise<{ verified: boolean; proofType: string; detailsJson: string }>
      )(handle, claimJson);
      // NAPI returns detailsJson as a JSON string; parse into the details object.
      return {
        verified: raw.verified,
        proofType: raw.proofType as "inclusion" | "absence",
        details: safeJsonParse(raw.detailsJson, "eventLogVerify") as Readonly<
          Record<string, unknown>
        >,
      };
    },

    async eventLogCheckpoint(
      handle: BridgeContextHandle,
      identityDid: string,
      epoch: number,
    ): Promise<Checkpoint> {
      // Use eventLogCheckpointByDid which accepts a DID string and looks up
      // the identity from the global registry. This avoids the need to pass
      // the NapiIdentity JS object through the event log API. See #1144 (C4).
      const raw = await (
        native.eventLogCheckpointByDid as (
          h: BridgeContextHandle,
          did: string,
          epoch: number,
        ) => Promise<{
          contextId: string;
          senderDid: string;
          merkleRoot: string;
          eventCount: number;
          epoch: number | null;
          timestamp: number;
          signature: string;
        }>
      )(handle, identityDid, epoch);
      return {
        contextId: raw.contextId,
        senderDid: raw.senderDid,
        merkleRoot: raw.merkleRoot,
        eventCount: raw.eventCount,
        // The NAPI bridge surfaces `epoch` as `null` for Broadcast contexts;
        // normalize to `undefined` to match the `Checkpoint` optional field.
        epoch: raw.epoch ?? undefined,
        timestamp: raw.timestamp,
        // The NAPI bridge signs the checkpoint in-process; surface the Ed25519
        // signature (hex). See the `Checkpoint` type doc.
        signature: raw.signature,
      };
    },

    // Bridge Connector — `bridgeRegister` and `bridgeEvaluateTrust` are
    // module-level NAPI free fns in bridge_connector.rs and dispatch
    // through `addon.X`. `bridgeCreateShadow` is on the SCP class
    // (scp.rs:3727) and dispatches through `native.X`. The dispatcher
    // routing rule above governs.
    bridgeRegister(
      contextId: string,
      operatorDid: string,
      governanceDid: string,
      platform: string,
      mode: BridgeMode,
    ) {
      // napi-rs #[napi(object)] returns camelCase keys; Bridge interface expects snake_case.
      const raw = (
        addon.bridgeRegister as (
          c: string,
          o: string,
          g: string,
          p: string,
          m: BridgeMode,
        ) => {
          bridgeId: string;
          operatorDid: string;
          platform: string;
          mode: string;
          status: string;
          contextId: string;
        }
      )(contextId, operatorDid, governanceDid, platform, mode);
      return {
        bridge_id: raw.bridgeId,
        operator_did: raw.operatorDid,
        platform: raw.platform,
        mode: raw.mode as BridgeMode,
        status: raw.status,
        context_id: raw.contextId,
      };
    },

    bridgeEvaluateTrust(
      isBridged: boolean,
      isNativeTransport: boolean,
      shadowStatus: ShadowStatus,
    ) {
      return (addon.bridgeEvaluateTrust as (b: boolean, n: boolean, s: ShadowStatus) => number)(
        isBridged,
        isNativeTransport,
        shadowStatus,
      );
    },

    bridgeCreateShadow(
      bridgeId: string,
      platformHandle: string,
      bridgeMode: BridgeMode,
      contextId: string | undefined,
    ) {
      // napi-rs #[napi(object)] returns camelCase keys; Bridge interface expects snake_case.
      const raw = (
        native.bridgeCreateShadow as (
          b: string,
          p: string,
          m: BridgeMode,
          c: string | undefined,
        ) => {
          shadowId: string;
          platformHandle: string;
          bridgeId: string;
          attributedRole: string;
          provenanceStatus: string;
        }
      )(bridgeId, platformHandle, bridgeMode, contextId);
      return {
        shadow_id: raw.shadowId,
        platform_handle: raw.platformHandle,
        bridge_id: raw.bridgeId,
        attributed_role: raw.attributedRole,
        provenance_status: raw.provenanceStatus as ShadowStatus,
      };
    },

    // Discovery — pure protocol helpers per ADR-048 §1. These are
    // module-level NAPI free fns in discovery.rs; the dispatcher
    // routing rule (top of createNativeBridge) routes them through
    // `addon.X`.
    discoveryParseAddress(address: string) {
      return (addon.discoveryParseAddress as (a: string) => string)(address);
    },

    discoveryCreateQuery(
      capabilities: string[] | undefined,
      keywords: string[] | undefined,
      minHistorySecs: number | undefined,
    ) {
      return (
        addon.discoveryCreateQuery as (
          c: string[] | undefined,
          k: string[] | undefined,
          m: number | undefined,
        ) => string
      )(capabilities, keywords, minHistorySecs);
    },

    discoveryNormalizeAddress(address: string) {
      return (addon.discoveryNormalizeAddress as (a: string) => string)(address);
    },

    async contextDiscover(query: string): Promise<string> {
      return await (addon.contextDiscover as (q: string) => Promise<string>)(query);
    },

    // Petnames (§22.4)
    petnameSet(ownerDid: string, targetDid: string, name: string): void {
      (native.petnameSet as (o: string, t: string, n: string) => void)(ownerDid, targetDid, name);
    },

    petnameRemove(ownerDid: string, targetDid: string): void {
      (native.petnameRemove as (o: string, t: string) => void)(ownerDid, targetDid);
    },

    petnameSetContext(ownerDid: string, contextId: string, name: string): void {
      (native.petnameSetContext as (o: string, c: string, n: string) => void)(
        ownerDid,
        contextId,
        name,
      );
    },

    petnameRemoveContext(ownerDid: string, contextId: string): void {
      (native.petnameRemoveContext as (o: string, c: string) => void)(ownerDid, contextId);
    },

    petnameResolveDid(ownerDid: string, name: string): string {
      return (native.petnameResolveDid as (o: string, n: string) => string)(ownerDid, name);
    },

    petnameResolveContext(ownerDid: string, name: string): string {
      return (native.petnameResolveContext as (o: string, n: string) => string)(ownerDid, name);
    },

    petnameGetForDid(ownerDid: string, targetDid: string): string | null {
      return (native.petnameGetForDid as (o: string, t: string) => string | null)(
        ownerDid,
        targetDid,
      );
    },

    petnameGetForContext(ownerDid: string, contextId: string): string | null {
      return (native.petnameGetForContext as (o: string, c: string) => string | null)(
        ownerDid,
        contextId,
      );
    },

    petnameApplyEvent(ownerDid: string, eventJson: string): void {
      (native.petnameApplyEvent as (o: string, e: string) => void)(ownerDid, eventJson);
    },

    petnameDidCount(ownerDid: string): number {
      return (native.petnameDidCount as (o: string) => number)(ownerDid);
    },

    petnameContextCount(ownerDid: string): number {
      return (native.petnameContextCount as (o: string) => number)(ownerDid);
    },

    // Handle Registry (§22.3.1)
    handleRegister(
      discoveryContextId: string,
      handle: string,
      targetJson: string,
      registrantDid: string,
      description: string | undefined,
      tags: string[] | undefined,
    ): string {
      return (
        native.handleRegister as (
          d: string,
          h: string,
          t: string,
          r: string,
          desc: string | undefined,
          tags: string[] | undefined,
        ) => string
      )(discoveryContextId, handle, targetJson, registrantDid, description, tags);
    },

    handleLookup(
      discoveryContextId: string,
      handle: string,
      typeFilter: string | undefined,
    ): string {
      return (native.handleLookup as (d: string, h: string, f: string | undefined) => string)(
        discoveryContextId,
        handle,
        typeFilter,
      );
    },

    handleDeregister(discoveryContextId: string, handle: string, did: string): string {
      return (native.handleDeregister as (d: string, h: string, did: string) => string)(
        discoveryContextId,
        handle,
        did,
      );
    },

    // Scope Registry (§22.3.5, ADR-043)
    scopeRegister(
      scopeContextId: string,
      name: string,
      targetContextId: string,
      relayUrls: string[],
      registrantDid: string,
      description: string | undefined,
      tags: string[] | undefined,
    ): string {
      return (
        native.scopeRegister as (
          sc: string,
          n: string,
          tc: string,
          r: string[],
          rd: string,
          d: string | undefined,
          t: string[] | undefined,
        ) => string
      )(scopeContextId, name, targetContextId, relayUrls, registrantDid, description, tags);
    },

    scopeLookup(scopeContextId: string, name: string): string {
      return (native.scopeLookup as (sc: string, n: string) => string)(scopeContextId, name);
    },

    scopeDeregister(scopeContextId: string, name: string, did: string): string {
      return (native.scopeDeregister as (sc: string, n: string, d: string) => string)(
        scopeContextId,
        name,
        did,
      );
    },

    // Address Resolution (§22.8)
    async addressResolve(
      ownerDid: string,
      address: string,
      knownContextsJson: string | undefined,
    ): Promise<string> {
      return await (
        native.addressResolve as (o: string, a: string, k: string | undefined) => Promise<string>
      )(ownerDid, address, knownContextsJson);
    },

    // Provenance
    async evaluateProvenanceQuality(
      sourceContext: string | undefined,
      sourceType: string,
      contextState: string,
      counterparties: string[] | undefined,
    ): Promise<number> {
      return await (
        native.evaluateProvenanceQuality as (
          sc: string | undefined,
          st: string,
          cs: string,
          cp: string[] | undefined,
        ) => Promise<number>
      )(sourceContext, sourceType, contextState, counterparties);
    },

    provenanceAttach(
      sourceContextId: string,
      sourceType: string,
      memoryScope: string,
      members: string[],
      targetContextId: string,
      actorDid: string,
      existingChainDepth: number | undefined,
      discoveryMethod: string | undefined,
      purpose: string | undefined,
      counterpartyPolicy: string | undefined,
    ) {
      return (
        native.provenanceAttach as (
          sc: string,
          st: string,
          ms: string,
          m: string[],
          tc: string,
          ad: string,
          e: number | undefined,
          dm: string | undefined,
          p: string | undefined,
          cp: string | undefined,
        ) => string
      )(
        sourceContextId,
        sourceType,
        memoryScope,
        members,
        targetContextId,
        actorDid,
        existingChainDepth,
        discoveryMethod,
        purpose,
        counterpartyPolicy,
      );
    },

    provenanceCheckChainDepth(chainDepth: number, maxDepth: number | undefined) {
      return (native.provenanceCheckChainDepth as (c: number, m: number | undefined) => boolean)(
        chainDepth,
        maxDepth,
      );
    },

    // Sync
    syncClassifyOffline(lastRelayContact: number, now: number) {
      return (native.syncClassifyOffline as (l: number, n: number) => string)(
        lastRelayContact,
        now,
      );
    },

    syncClassifyOfflineCustom(
      lastRelayContact: number,
      now: number,
      tier1ThresholdSecs: number,
      tier2ThresholdSecs: number,
    ) {
      return (
        native.syncClassifyOfflineCustom as (l: number, n: number, t1: number, t2: number) => string
      )(lastRelayContact, now, tier1ThresholdSecs, tier2ThresholdSecs);
    },

    syncGetPolicy() {
      const raw = (
        native.syncGetPolicy as () => {
          tier1ThresholdSecs: number;
          tier2ThresholdSecs: number;
          gapTimeoutSecs: number;
          reorderBufferCapacity: number;
          maxSequentialCommits: number;
          commitProcessTimeoutSecs: number;
          senderKeyTimeoutSecs: number;
          reconnectionDedupWindowSecs: number;
        }
      )();
      return {
        tier_1_threshold_secs: raw.tier1ThresholdSecs,
        tier_2_threshold_secs: raw.tier2ThresholdSecs,
        gap_timeout_secs: raw.gapTimeoutSecs,
        reorder_buffer_capacity: raw.reorderBufferCapacity,
        max_sequential_commits: raw.maxSequentialCommits,
        commit_process_timeout_secs: raw.commitProcessTimeoutSecs,
        sender_key_timeout_secs: raw.senderKeyTimeoutSecs,
        reconnection_dedup_window_secs: raw.reconnectionDedupWindowSecs,
      };
    },

    // Identity Advanced
    async identityCreateWithAgentKey(custody: string): Promise<BridgeIdentityHandle> {
      return await (
        native.identityCreateWithAgentKey as (c: string) => Promise<BridgeIdentityHandle>
      )(custody);
    },

    async identityAddAgentKey(handle: BridgeIdentityHandle): Promise<BridgeIdentityHandle> {
      return await (
        handle as unknown as { addAgentKey(): Promise<BridgeIdentityHandle> }
      ).addAgentKey();
    },

    async identityRotateAgentKey(handle: BridgeIdentityHandle): Promise<BridgeIdentityHandle> {
      return await (
        handle as unknown as { rotateAgentKey(): Promise<BridgeIdentityHandle> }
      ).rotateAgentKey();
    },

    async identityRemoveAgentKey(handle: BridgeIdentityHandle): Promise<BridgeIdentityHandle> {
      return await (
        handle as unknown as { removeAgentKey(): Promise<BridgeIdentityHandle> }
      ).removeAgentKey();
    },

    async identityMigrate(handle: BridgeIdentityHandle): Promise<BridgeIdentityHandle> {
      // The NAPI bridge returns a `NapiIdentity` class instance whose
      // `rotationEventJson` getter exposes the JSON-serialized
      // `DidRotationEvent` (spec §9.12, ADR-003 §4b/4c). Returning the
      // live class instance preserves the handle for downstream
      // operations (rotateKey, addAgentKey, etc.) AND satisfies the
      // `BridgeIdentityHandle.rotationEventJson` field via the NAPI
      // getter — no own-property mutation needed (NAPI class
      // properties are readonly, so `Object.assign` would throw
      // `TypeError: Attempted to assign to readonly property.`).
      return await (handle as unknown as { migrate(): Promise<BridgeIdentityHandle> }).migrate();
    },

    async identityAttestDevice(did: string): Promise<string> {
      return await (native.identityAttestDevice as (d: string) => Promise<string>)(did);
    },

    async identityVerifyDeviceAttestation(did: string, tokenBase64: string): Promise<boolean> {
      return await (
        native.identityVerifyDeviceAttestation as (d: string, t: string) => Promise<boolean>
      )(did, tokenBase64);
    },

    // Identity link attestation (§3.5.1)
    async identityCreateLinkAttestation(
      did: string,
      platform: string,
      handle: string,
      proof: string,
      verificationMethod: string,
      platformId: string | null,
    ): Promise<string> {
      return await (
        native.identityCreateLinkAttestation as (
          d: string,
          p: string,
          h: string,
          pr: string,
          vm: string,
          pid: string | null,
        ) => Promise<string>
      )(did, platform, handle, proof, verificationMethod, platformId);
    },

    identityLinkAttestations(did: string): string {
      return (native.identityLinkAttestations as (d: string) => string)(did);
    },

    identityRemoveLinkAttestation(did: string, attestationId: string): boolean {
      return (native.identityRemoveLinkAttestation as (d: string, a: string) => boolean)(
        did,
        attestationId,
      );
    },

    identityRemove(did: string): void {
      (native.identityRemove as (d: string) => void)(did);
    },

    identityRemoveIfPresent(did: string): boolean {
      return (native.identityRemoveIfPresent as (d: string) => boolean)(did);
    },

    async identityVerifyLinkAttestation(
      attestationJson: string,
      issuerPublicKeyHex: string,
    ): Promise<boolean> {
      // Module-level NAPI free fn (per ADR-048 §1) — route through `addon`.
      // The previous `Scp::identity_verify_link_attestation` method (with its
      // `let _ = &self.inner;` gate-defang) was deleted in PR-E #28.
      return (addon.identityVerifyLinkAttestation as (j: string, k: string) => boolean)(
        attestationJson,
        issuerPublicKeyHex,
      );
    },

    // Recovery and custody migration (#632, spec §9.12, §3.2.1)
    async identityExecuteRecovery(
      did: string,
      tier: string,
      contextIds: string[],
    ): Promise<string> {
      return await (
        native.identityExecuteRecovery as (d: string, t: string, c: string[]) => Promise<string>
      )(did, tier, contextIds);
    },

    async identityExecuteCustodyMigration(
      did: string,
      target: string,
      contextIds: string[],
    ): Promise<string> {
      return await (
        native.identityExecuteCustodyMigration as (
          d: string,
          t: string,
          c: string[],
        ) => Promise<string>
      )(did, target, contextIds);
    },

    // App Sandboxing (#595, spec §8.4.1, §8.4.2)
    validateCapabilityDeclaration(
      declarationJson: string,
      ceilingCapabilities: string[],
      roleCapabilities: string[],
    ): string {
      return (
        native.validateCapabilityDeclaration as (d: string, c: string[], r: string[]) => string
      )(declarationJson, ceilingCapabilities, roleCapabilities);
    },

    checkScopedCapability(
      grantedCapabilities: readonly string[],
      requiredCapability: string,
    ): boolean {
      // Module-level free function (per ADR-048 §1) — route through
      // `addon`, not `native`. The previous routing through the per-
      // instance handle was incorrect after PR-E #28 deleted the
      // `Scp::check_scoped_capability` method on the napi side; the
      // dispatcher-invariant test catches this exactly.
      return (addon.checkScopedCapability as unknown as (g: string[], r: string) => boolean)(
        [...grantedCapabilities],
        requiredCapability,
      );
    },

    // Invitation evaluation
    evaluateInvitation(
      paramsJson: string,
      inviterDid: string,
      identityDid: string,
      policyJson: string | null,
      spendingJson: string | null,
    ) {
      return (
        native.evaluateInvitation as (
          p: string,
          i: string,
          id: string,
          pol: string | null,
          sp: string | null,
        ) => { decision: string }
      )(paramsJson, inviterDid, identityDid, policyJson, spendingJson);
    },

    // MetadataRecord inspection (§5.7.2, #615)
    metadataRecordToJson(
      contextId: string,
      sequence: number,
      signerDid: string,
      timestamp: number,
      structuralJson: string,
      operationalJson: string,
      signatureHex: string,
    ): string {
      return (
        native.metadataRecordToJson as (
          c: string,
          s: number,
          sd: string,
          t: number,
          st: string,
          op: string,
          sig: string,
        ) => string
      )(contextId, sequence, signerDid, timestamp, structuralJson, operationalJson, signatureHex);
    },

    // Pure protocol helpers per ADR-048 §1 — module-level NAPI free
    // fns (template/metadata/validate-* in context.rs). Routed through
    // `addon.X` per the dispatcher routing rule. Earlier variants were
    // `native.<name>` and silently became `(undefined)(args)` at
    // runtime — fixed in #1543 batch 3a (97051e32e + 176763958).
    metadataRecordFromJson(jsonStr: string): string {
      return (addon.metadataRecordFromJson as (j: string) => string)(jsonStr);
    },

    // Context template inspection (§5.14, #615) — pure helpers per ADR-048 §1.
    templateGetParams(templateId: string): string {
      return (addon.templateGetParams as (t: string) => string)(templateId);
    },

    validateAgainstTemplate(paramsJson: string): string | null {
      return (addon.validateAgainstTemplate as (p: string) => string | null)(paramsJson);
    },

    validateContextParams(paramsJson: string): string | null {
      return (addon.validateContextParams as (p: string) => string | null)(paramsJson);
    },

    // Economy (§19, ADR-033)
    economyEstimateCost(policyJson: string, actionType: string, metricsJson: string): number {
      return (native.economyEstimateCost as (p: string, a: string, m: string) => number)(
        policyJson,
        actionType,
        metricsJson,
      );
    },

    economyPolicyRequiresPayment(policyJson: string): boolean {
      return (native.economyPolicyRequiresPayment as (p: string) => boolean)(policyJson);
    },

    economyAutoAcceptBlocked(policyJson: string): boolean {
      return (native.economyAutoAcceptBlocked as (p: string) => boolean)(policyJson);
    },

    economyCheckPolicyLock(policyJson: string): boolean {
      return (native.economyCheckPolicyLock as (p: string) => boolean)(policyJson);
    },

    economyValidatePolicyChange(currentJson: string, proposedJson: string): boolean {
      return (native.economyValidatePolicyChange as (c: string, p: string) => boolean)(
        currentJson,
        proposedJson,
      );
    },

    economyEvaluateFormula(formulaJson: string, metricsJson: string): number {
      return (native.economyEvaluateFormula as (f: string, m: string) => number)(
        formulaJson,
        metricsJson,
      );
    },

    economyBudgetRemaining(contextId: string, did: string): number {
      return (native.economyBudgetRemaining as (c: string, d: string) => number)(contextId, did);
    },

    economyBudgetGrant(contextId: string, did: string, amount: number): void {
      (native.economyBudgetGrant as (c: string, d: string, a: number) => void)(
        contextId,
        did,
        amount,
      );
    },

    economyBudgetRecordSpend(contextId: string, did: string, amount: number): void {
      (native.economyBudgetRecordSpend as (c: string, d: string, a: number) => void)(
        contextId,
        did,
        amount,
      );
    },

    economyAntispamRecord(contextId: string, senderDid: string, timestamp: number): void {
      (native.economyAntispamRecord as (c: string, s: string, t: number) => void)(
        contextId,
        senderDid,
        timestamp,
      );
    },

    economyAntispamVelocity(contextId: string, senderDid: string, now: number): number {
      return (native.economyAntispamVelocity as (c: string, s: string, n: number) => number)(
        contextId,
        senderDid,
        now,
      );
    },

    economyAntispamEscalatedCost(
      contextId: string,
      senderDid: string,
      now: number,
      baseCost: number,
      thresholdsJson: string,
      floor: number | null,
      cap: number | null,
    ): number {
      return (
        native.economyAntispamEscalatedCost as (
          c: string,
          s: string,
          n: number,
          b: number,
          t: string,
          f: number | null,
          cp: number | null,
        ) => number
      )(contextId, senderDid, now, baseCost, thresholdsJson, floor, cap);
    },

    economyVerifyPaymentReceipts(receiptsJson: string): string {
      return (native.economyVerifyPaymentReceipts as (r: string) => string)(receiptsJson);
    },

    // Media (ADR-024)
    mediaCheckCapability(ceiling: string[], capability: string): boolean {
      return (native.mediaCheckCapability as (c: string[], cap: string) => boolean)(
        ceiling,
        capability,
      );
    },

    mediaInitiateSession(
      contextId: string,
      ceiling: string[],
      capabilities: string[],
      participants: string[],
      timestamp: number,
    ): string {
      return (
        native.mediaInitiateSession as (
          c: string,
          cl: string[],
          caps: string[],
          p: string[],
          t: number,
        ) => string
      )(contextId, ceiling, capabilities, participants, timestamp);
    },

    mediaActivateSession(sessionJson: string): string {
      return (native.mediaActivateSession as (s: string) => string)(sessionJson);
    },

    mediaJoinSession(sessionJson: string, participantDid: string): string {
      return (native.mediaJoinSession as (s: string, p: string) => string)(
        sessionJson,
        participantDid,
      );
    },

    mediaEndSession(sessionJson: string, timestamp: number): string {
      return (native.mediaEndSession as (s: string, t: number) => string)(sessionJson, timestamp);
    },

    mediaCreateOffer(sessionId: string, sdp: string, senderDid: string): string {
      return (native.mediaCreateOffer as (s: string, sdp: string, d: string) => string)(
        sessionId,
        sdp,
        senderDid,
      );
    },

    mediaCreateAnswer(sessionId: string, sdp: string, senderDid: string): string {
      return (native.mediaCreateAnswer as (s: string, sdp: string, d: string) => string)(
        sessionId,
        sdp,
        senderDid,
      );
    },

    mediaCreateIceCandidate(
      sessionId: string,
      candidate: string,
      senderDid: string,
      sdpMid?: string,
      sdpMlineIndex?: number,
    ): string {
      return (
        native.mediaCreateIceCandidate as (
          s: string,
          c: string,
          d: string,
          m: string | undefined,
          i: number | undefined,
        ) => string
      )(sessionId, candidate, senderDid, sdpMid, sdpMlineIndex);
    },

    mediaCreateSessionEnd(sessionId: string, senderDid: string): string {
      return (native.mediaCreateSessionEnd as (s: string, d: string) => string)(
        sessionId,
        senderDid,
      );
    },

    mediaSendSignaling(signalingJson: string): string {
      return (native.mediaSendSignaling as (s: string) => string)(signalingJson);
    },

    mediaVerifySenderAttribution(signalingJson: string, envelopeSenderDid: string): boolean {
      return (native.mediaVerifySenderAttribution as (s: string, e: string) => boolean)(
        signalingJson,
        envelopeSenderDid,
      );
    },

    // SCPID authentication (§3.11) — methods on the SCP class
    // (scp.rs:3749, 3761, 3781). Routed through `native.X` per the
    // dispatcher routing rule.
    scpidChallenge(audience: string, ttlSeconds: number): string {
      return (native.scpidChallenge as (a: string, t: number) => string)(audience, ttlSeconds);
    },

    scpidSign(did: string, signingKeyId: string, challengeJson: string): string {
      return (native.scpidSign as (d: string, k: string, c: string) => string)(
        did,
        signingKeyId,
        challengeJson,
      );
    },

    scpidVerify(responseJson: string, challengeJson: string): string {
      return (native.scpidVerify as (r: string, c: string) => string)(responseJson, challengeJson);
    },

    // Trust — participation verification (SCP-BA-004, §7.3.2.1)
    verifyParticipationRequirements(profileJson: string, requirementsJson: string): boolean {
      return (native.verifyParticipationRequirements as (p: string, r: string) => boolean)(
        profileJson,
        requirementsJson,
      );
    },

    // Lifecycle
    //
    // `version()` stays on the module-level `scpVersion` free function —
    // it is not instance-scoped and has no equivalent on the `Scp`
    // class. Suspend / resume / shutdown now dispatch to the wrapped
    // `SCP` instance's class methods (ADR-048), so per-instance
    // bridges hit their own state instead of the process-wide
    // singleton.
    version(): string {
      return (addon.scpVersion as () => string)();
    },

    async shutdown(timeoutMillis: number): Promise<void> {
      // NAPI `shutdown(timeoutMillis: u64)` — napi-rs exposes `u64`
      // as JS `BigInt` on the wire, so the `number` at this layer is
      // coerced to `bigint` before hitting the native binding. The SDK
      // public surface (`BridgeApi.shutdown`, `SCP.shutdown`) keeps
      // `number` so the mock path stays uniform.
      const millis = BigInt(Math.max(0, Math.trunc(timeoutMillis)));
      await (native.shutdown as (t: bigint) => Promise<void>)(millis);
    },

    suspend(): void {
      (native.suspend as () => void)();
    },

    resume(): Promise<void> {
      // `Scp::resume` is `async fn` since #1678 — forwarding the
      // promise preserves the await chain so transport-reconnect and
      // persisted-context-restoration failures surface at the SDK
      // boundary instead of fire-and-forget.
      return (native.resume as () => Promise<void>)();
    },
  };
  // Single error chokepoint: convert raw FFI errors thrown by any bridge
  // method into typed ScpError subclasses at exactly one site (ADR-055).
  return wrapBridgeErrors(bridge);
}
