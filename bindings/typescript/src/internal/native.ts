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
 * See ADR-022 in `.docs/adrs/phase-4.md`.
 */

import { createRequire } from "node:module";

import type { BridgeMode, ShadowStatus } from "../bridge";
import { TransportError } from "../errors";
import type {
  BroadcastAdmissionPolicy,
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
        "Install the appropriate @limn-works/scp-ts-napi-* package or use the WASM bridge in a browser environment.",
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
      // NAPI Vec<u8> maps to number[] in JS, not Uint8Array.
      const payloadArray = Array.from(payload) as unknown as number[];
      await (
        addon.contextSend as (h: BridgeContextHandle, d: string, p: number[]) => Promise<void>
      )(handle, identityDid, payloadArray);
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

    // Membership queries
    async contextMemberCount(handle: BridgeContextHandle): Promise<number | null> {
      const result = await (
        addon.contextMemberCount as (h: BridgeContextHandle) => Promise<number | null>
      )(handle);
      return result;
    },

    async contextIsMember(handle: BridgeContextHandle, did: string): Promise<boolean> {
      return await (
        addon.contextIsMember as (h: BridgeContextHandle, d: string) => Promise<boolean>
      )(handle, did);
    },

    async contextMemberDids(handle: BridgeContextHandle): Promise<readonly string[]> {
      return await (
        addon.contextMemberDids as (h: BridgeContextHandle) => Promise<readonly string[]>
      )(handle);
    },

    async contextMemberRole(handle: BridgeContextHandle, did: string): Promise<MemberRole | null> {
      return await (
        addon.contextMemberRole as (h: BridgeContextHandle, d: string) => Promise<MemberRole | null>
      )(handle, did);
    },

    // Broadcast operations
    async broadcastSubscribe(handle: BridgeContextHandle, subscriberDid: string): Promise<void> {
      await (addon.broadcastSubscribe as (h: BridgeContextHandle, d: string) => Promise<void>)(
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
        addon.broadcastUnsubscribe as (
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
        addon.broadcastPublish as (h: BridgeContextHandle, d: string, p: number[]) => Promise<void>
      )(handle, authorDid, payloadArray);
    },

    async broadcastBlockSubscriber(
      handle: BridgeContextHandle,
      subscriberDid: string,
      blockerDid: string,
    ): Promise<void> {
      await (
        addon.broadcastBlockSubscriber as (
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
        addon.broadcastUnblockSubscriber as (
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
    ): Promise<string> {
      return await (
        addon.broadcastHandleKeyRequest as (
          h: BridgeContextHandle,
          a: string,
          r: string,
        ) => Promise<string>
      )(handle, authorDid, requesterDid);
    },

    async broadcastSubscriberCount(handle: BridgeContextHandle): Promise<number | null> {
      return await (
        addon.contextBroadcastSubscriberCount as (h: BridgeContextHandle) => Promise<number | null>
      )(handle);
    },

    async broadcastIsSubscriber(handle: BridgeContextHandle, did: string): Promise<boolean> {
      return await (
        addon.contextIsBroadcastSubscriber as (
          h: BridgeContextHandle,
          d: string,
        ) => Promise<boolean>
      )(handle, did);
    },

    async broadcastAdmission(
      handle: BridgeContextHandle,
    ): Promise<BroadcastAdmissionPolicy | null> {
      return await (
        addon.contextBroadcastAdmission as (
          h: BridgeContextHandle,
        ) => Promise<BroadcastAdmissionPolicy | null>
      )(handle);
    },

    // Governance
    async contextExecuteGovernanceAction(
      handle: BridgeContextHandle,
      actionJson: string,
      proposerDid: string,
    ): Promise<string> {
      return await (
        addon.contextExecuteGovernanceAction as (
          h: BridgeContextHandle,
          a: string,
          p: string,
        ) => Promise<string>
      )(handle, actionJson, proposerDid);
    },

    // Governance proposal lifecycle (#621)
    async contextGovernancePropose(
      handle: BridgeContextHandle,
      actionJson: string,
      proposerDid: string,
    ): Promise<string> {
      return await (
        addon.contextGovernancePropose as (
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
        addon.contextGovernanceApprove as (
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
        addon.contextGovernanceReject as (
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
        addon.contextGovernanceWithdraw as (
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
        addon.contextGovernanceGetProposal as (h: BridgeContextHandle, p: string) => Promise<string>
      )(handle, proposalIdHex);
    },
    async contextGovernanceListProposals(handle: BridgeContextHandle): Promise<string> {
      return await (
        addon.contextGovernanceListProposals as (h: BridgeContextHandle) => Promise<string>
      )(handle);
    },

    // TTL operations
    async contextTtlRemaining(_handle: BridgeContextHandle): Promise<number | null> {
      // The NAPI bridge does not export contextTtlRemaining — scp-core's
      // ContextManager tracks TTL internally and does not expose a "remaining"
      // query. Use contextProposeTtlExtension or contextResetTtlTimer instead.
      throw new TransportError(
        "contextTtlRemaining is not available in the native (NAPI) bridge. " +
          "TTL remaining is a WASM-only concept. Use contextProposeTtlExtension " +
          "or contextResetTtlTimer for TTL management in native environments.",
        "SCP-TRANS-5004",
      );
    },

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
      await (addon.contextHandleTtlExpiry as (h: BridgeContextHandle) => Promise<void>)(handle);
    },

    async contextProposeTtlExtension(
      handle: BridgeContextHandle,
      proposerDid: string,
      extensionSecs: number,
    ): Promise<boolean> {
      return await (
        addon.contextProposeTtlExtension as (
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
      await (addon.contextResetTtlTimer as (h: BridgeContextHandle, s: number) => Promise<void>)(
        handle,
        newDurationSecs,
      );
    },

    // Economic policy (§19.3)
    async contextSetEconomicPolicy(handle: BridgeContextHandle, policyJson: string): Promise<void> {
      await (
        addon.contextSetEconomicPolicy as (h: BridgeContextHandle, p: string) => Promise<void>
      )(handle, policyJson);
    },

    async contextGetEconomicPolicy(handle: BridgeContextHandle): Promise<string | null> {
      const result = await (
        addon.contextGetEconomicPolicy as (h: BridgeContextHandle) => Promise<string | null>
      )(handle);
      return result ?? null;
    },

    // Context export/import
    async contextExport(handle: BridgeContextHandle): Promise<Uint8Array> {
      const data = await (addon.contextExport as (h: BridgeContextHandle) => Promise<Buffer>)(
        handle,
      );
      return new Uint8Array(data);
    },

    async contextImport(data: Uint8Array): Promise<string> {
      // NAPI Vec<u8> maps to number[] in JS, not Uint8Array.
      const dataArray = Array.from(data) as unknown as number[];
      return await (addon.contextImport as (d: number[]) => Promise<string>)(dataArray);
    },

    // Drain events
    async contextDrainEvents(handle: BridgeContextHandle): Promise<readonly string[]> {
      return await (
        addon.contextDrainEvents as (h: BridgeContextHandle) => Promise<readonly string[]>
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
      };
      const toolId = await (
        addon.toolRegister as (h: BridgeContextHandle, d: typeof napiDef) => Promise<string>
      )(handle, napiDef);
      return toolId;
    },

    async toolInvoke(
      handle: BridgeContextHandle,
      toolId: string,
      inputJson: string,
      identityDid: string,
      ucanToken: string,
    ): Promise<string> {
      const result = await (
        addon.toolInvoke as (
          h: BridgeContextHandle,
          t: string,
          i: string,
          d: string,
          u: string,
          p: string[] | undefined,
        ) => Promise<string>
      )(handle, toolId, inputJson, identityDid, ucanToken, undefined);
      return result;
    },

    async toolVerify(handle: BridgeContextHandle, toolId: string): Promise<ToolVerificationResult> {
      const result = await (
        addon.toolVerify as (h: BridgeContextHandle, t: string) => Promise<ToolVerificationResult>
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
        addon.toolInterfaceExpose as (
          h: BridgeContextHandle,
          t: string,
          tc: string,
          rl?: string,
        ) => Promise<string>
      )(handle, toolId, targetContextId, rateLimitJson);
    },

    async toolInterfaceAccept(
      handle: BridgeContextHandle,
      interfaceJson: string,
    ): Promise<string> {
      return await (
        addon.toolInterfaceAccept as (h: BridgeContextHandle, ij: string) => Promise<string>
      )(handle, interfaceJson);
    },

    async toolInterfaceRevoke(
      handle: BridgeContextHandle,
      interfaceIdHex: string,
    ): Promise<string> {
      return await (
        addon.toolInterfaceRevoke as (h: BridgeContextHandle, id: string) => Promise<string>
      )(handle, interfaceIdHex);
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

    async ucanDelegate(
      handle: BridgeContextHandle,
      delegatorDid: string,
      delegateeDid: string,
      parentToken: string,
      capabilities: readonly string[],
    ): Promise<UcanToken> {
      return await (
        addon.ucanDelegate as (
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
        addon.aggregateTrustInput as (
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
        addon.eventLogQuery as (
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
        addon.eventLogVerify as (
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
      // The NAPI Rust function requires (handle, identity, epoch).
      // identity is passed as an object matching the NapiIdentity shape.
      const raw = await (
        addon.eventLogCheckpoint as (
          h: BridgeContextHandle,
          identity: { did: string; custodyType: string },
          epoch: number,
        ) => Promise<{
          merkleRoot: string;
          eventCount: number;
          timestamp: number;
        }>
      )(handle, { did: identityDid, custodyType: "in_memory" }, epoch);
      return {
        root: raw.merkleRoot,
        eventCount: raw.eventCount,
        timestamp: raw.timestamp,
      };
    },

    // Bridge Connector
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
        addon.bridgeCreateShadow as (
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

    // Discovery
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
      (addon.petnameSet as (o: string, t: string, n: string) => void)(ownerDid, targetDid, name);
    },

    petnameRemove(ownerDid: string, targetDid: string): void {
      (addon.petnameRemove as (o: string, t: string) => void)(ownerDid, targetDid);
    },

    petnameSetContext(ownerDid: string, contextId: string, name: string): void {
      (addon.petnameSetContext as (o: string, c: string, n: string) => void)(
        ownerDid,
        contextId,
        name,
      );
    },

    petnameRemoveContext(ownerDid: string, contextId: string): void {
      (addon.petnameRemoveContext as (o: string, c: string) => void)(ownerDid, contextId);
    },

    petnameResolveDid(ownerDid: string, name: string): string {
      return (addon.petnameResolveDid as (o: string, n: string) => string)(ownerDid, name);
    },

    petnameResolveContext(ownerDid: string, name: string): string {
      return (addon.petnameResolveContext as (o: string, n: string) => string)(ownerDid, name);
    },

    petnameGetForDid(ownerDid: string, targetDid: string): string | null {
      return (addon.petnameGetForDid as (o: string, t: string) => string | null)(
        ownerDid,
        targetDid,
      );
    },

    petnameGetForContext(ownerDid: string, contextId: string): string | null {
      return (addon.petnameGetForContext as (o: string, c: string) => string | null)(
        ownerDid,
        contextId,
      );
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
        addon.handleRegister as (
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
      return (addon.handleLookup as (d: string, h: string, f: string | undefined) => string)(
        discoveryContextId,
        handle,
        typeFilter,
      );
    },

    handleDeregister(discoveryContextId: string, handle: string, did: string): string {
      return (addon.handleDeregister as (d: string, h: string, did: string) => string)(
        discoveryContextId,
        handle,
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
        addon.addressResolve as (o: string, a: string, k: string | undefined) => Promise<string>
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
        addon.evaluateProvenanceQuality as (
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
      existingChainDepth: number | undefined,
      discoveryMethod: string | undefined,
      purpose: string | undefined,
      counterpartyPolicy: string | undefined,
    ) {
      return (
        addon.provenanceAttach as (
          sc: string,
          st: string,
          ms: string,
          m: string[],
          tc: string,
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
        existingChainDepth,
        discoveryMethod,
        purpose,
        counterpartyPolicy,
      );
    },

    provenanceCheckChainDepth(chainDepth: number, maxDepth: number | undefined) {
      return (addon.provenanceCheckChainDepth as (c: number, m: number | undefined) => boolean)(
        chainDepth,
        maxDepth,
      );
    },

    // Sync
    syncClassifyOffline(lastRelayContact: number, now: number) {
      return (addon.syncClassifyOffline as (l: number, n: number) => string)(lastRelayContact, now);
    },

    syncClassifyOfflineCustom(
      lastRelayContact: number,
      now: number,
      tier1ThresholdSecs: number,
      tier2ThresholdSecs: number,
    ) {
      return (
        addon.syncClassifyOfflineCustom as (l: number, n: number, t1: number, t2: number) => string
      )(lastRelayContact, now, tier1ThresholdSecs, tier2ThresholdSecs);
    },

    syncGetPolicy() {
      const raw = (
        addon.syncGetPolicy as () => {
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
        addon.identityCreateWithAgentKey as (c: string) => Promise<BridgeIdentityHandle>
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
      return await (handle as unknown as { migrate(): Promise<BridgeIdentityHandle> }).migrate();
    },

    async identityAttestDevice(did: string): Promise<string> {
      return await (addon.identityAttestDevice as (d: string) => Promise<string>)(did);
    },

    async identityVerifyDeviceAttestation(did: string, tokenBase64: string): Promise<boolean> {
      return await (
        addon.identityVerifyDeviceAttestation as (d: string, t: string) => Promise<boolean>
      )(did, tokenBase64);
    },

    // Recovery and custody migration (#632, spec §9.12, §3.2.1)
    async identityExecuteRecovery(
      did: string,
      tier: string,
      contextIds: string[],
    ): Promise<string> {
      return await (
        addon.identityExecuteRecovery as (d: string, t: string, c: string[]) => Promise<string>
      )(did, tier, contextIds);
    },

    async identityExecuteCustodyMigration(
      did: string,
      target: string,
      contextIds: string[],
    ): Promise<string> {
      return await (
        addon.identityExecuteCustodyMigration as (
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
        addon.validateCapabilityDeclaration as (d: string, c: string[], r: string[]) => string
      )(declarationJson, ceilingCapabilities, roleCapabilities);
    },

    checkScopedCapability(
      grantedCapabilities: readonly string[],
      requiredCapability: string,
    ): boolean {
      return (addon.checkScopedCapability as (g: string[], r: string) => boolean)(
        [...grantedCapabilities],
        requiredCapability,
      );
    },

    // SCPID authentication (§3.11)
    scpidChallenge(audience: string, ttlSeconds: number): string {
      return (addon.scpidChallenge as (a: string, t: number) => string)(audience, ttlSeconds);
    },

    scpidSign(did: string, signingKeyId: string, challengeJson: string): string {
      return (addon.scpidSign as (d: string, k: string, c: string) => string)(
        did,
        signingKeyId,
        challengeJson,
      );
    },

    scpidVerify(responseJson: string, challengeJson: string): string {
      return (addon.scpidVerify as (r: string, c: string) => string)(responseJson, challengeJson);
    },

    // Trust — participation verification (SCP-BA-004, §7.3.2.1)
    verifyParticipationRequirements(profileJson: string, requirementsJson: string): boolean {
      return (addon.verifyParticipationRequirements as (p: string, r: string) => boolean)(
        profileJson,
        requirementsJson,
      );
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
