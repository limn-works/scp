/**
 * wasm-bindgen WASM bridge adapter for browser environments.
 *
 * This module wraps the wasm-bindgen generated module (`@limn-works/scp-ts-wasm`)
 * into the unified `Bridge` interface consumed by the TypeScript SDK.
 *
 * WASM initialization is performed lazily via `initWasm()`, which must be
 * called once before any bridge functions are invoked. The `getBridge()`
 * function in `bridge.ts` handles this automatically.
 *
 * See ADR-022 in `.docs/adrs/phase-4.md`.
 */

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
  Proof,
  ToolDefinition,
  ToolVerificationResult,
  TransportStatus,
  UcanToken,
  VerificationMethod,
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
// WASM module types
// ---------------------------------------------------------------------------

/** The shape of the wasm-bindgen generated module. */
interface WasmModule {
  default: () => Promise<void>;
  scp_init: () => void;
  scp_version: () => string;
  identity_create: (custody: string) => Promise<{ did: string; custodyType: string }>;
  identity_load: (did: string) => Promise<{ did: string; custodyType: string }>;
  identity_resolve: (did: string) => Promise<{
    id: string;
    verificationMethodsJson: string;
    servicesJson: string;
    alsoKnownAsJson: string;
    authenticationJson: string;
    assertionMethodsJson: string;
  }>;
  context_create: (
    identityDid: string,
    paramsJson: string,
  ) => Promise<{ contextId: string; state: string; creatorDid: string }>;
  context_join: (handle: BridgeContextHandle, identityDid: string) => Promise<void>;
  context_leave: (handle: BridgeContextHandle, identityDid: string) => Promise<void>;
  context_close: (handle: BridgeContextHandle, identityDid: string) => Promise<void>;
  context_send: (
    handle: BridgeContextHandle,
    identityDid: string,
    payloadBase64: string,
  ) => Promise<void>;
  context_subscribe: (
    handle: BridgeContextHandle,
    callback: {
      onMessage: (msg: {
        senderDid: string;
        payloadBase64: string;
        timestamp: number;
        contextId: string;
      }) => void;
      onComplete: () => void;
    },
  ) => void;
  tool_register: (handle: BridgeContextHandle, definitionJson: string) => Promise<string>;
  tool_invoke: (
    handle: BridgeContextHandle,
    toolId: string,
    inputJson: string,
    identityDid: string,
    ucanToken: string | undefined,
  ) => Promise<string>;
  tool_verify: (
    handle: BridgeContextHandle,
    toolId: string,
  ) => Promise<{ toolId: string; passed: boolean; failuresJson: string }>;
  transport_connect: (relayUrl: string) => Promise<{
    connected: boolean;
    relayUrl: string | null;
    latencyMs: number | null;
  }>;
  transport_disconnect: () => Promise<void>;
  event_log_query: (handle: BridgeContextHandle, filterJson: string | undefined) => Promise<string>;
  event_log_verify: (
    handle: BridgeContextHandle,
    claimJson: string,
  ) => Promise<{ verified: boolean; proofType: string; detailsJson: string }>;
  ucan_validate: (
    handle: BridgeContextHandle,
    token: string,
    capability: string,
    expectedAudDid: string,
    proofTokensJson: string | undefined,
  ) => Promise<void>;
  ucan_mint: (
    handle: BridgeContextHandle,
    memberDid: string,
    capabilitiesJson: string,
  ) => Promise<{
    tokenId: string;
    issuer: string;
    audience: string;
    capabilitiesJson: string;
    expiresAt: number | null;
    encoded: string;
  }>;
  ucan_revoke: (handle: BridgeContextHandle, token: string) => Promise<void>;
  // Bridge Connector
  bridge_register: (
    contextId: string,
    operatorDid: string,
    governanceDid: string,
    platform: string,
    mode: BridgeMode,
  ) => ReturnType<Bridge["bridgeRegister"]>;
  bridge_evaluate_trust: (
    isBridged: boolean,
    isNativeTransport: boolean,
    shadowStatus: ShadowStatus,
  ) => number;
  bridge_create_shadow: (
    bridgeId: string,
    platformHandle: string,
    bridgeMode: BridgeMode,
    contextId: string | undefined,
  ) => ReturnType<Bridge["bridgeCreateShadow"]>;
  // Discovery
  discovery_parse_address: (address: string) => string;
  discovery_create_query: (
    capabilitiesJson: string | undefined,
    keywordsJson: string | undefined,
    minHistorySecs: number | undefined,
  ) => string;
  discovery_normalize_address: (address: string) => string;
  context_discover: (query: string) => Promise<string>;
  // Petnames (§22.4)
  petname_set: (ownerDid: string, targetDid: string, name: string) => void;
  petname_remove: (ownerDid: string, targetDid: string) => void;
  petname_set_context: (ownerDid: string, contextId: string, name: string) => void;
  petname_remove_context: (ownerDid: string, contextId: string) => void;
  petname_resolve_did: (ownerDid: string, name: string) => string;
  petname_resolve_context: (ownerDid: string, name: string) => string;
  petname_get_for_did: (ownerDid: string, targetDid: string) => unknown;
  petname_get_for_context: (ownerDid: string, contextId: string) => unknown;
  // Handle Registry (§22.3.1)
  handle_register: (
    discoveryContextId: string,
    handle: string,
    targetJson: string,
    registrantDid: string,
    description: string | undefined,
    tagsJson: string | undefined,
  ) => string;
  handle_lookup: (
    discoveryContextId: string,
    handle: string,
    typeFilter: string | undefined,
  ) => string;
  handle_deregister: (discoveryContextId: string, handle: string, did: string) => string;
  // Address Resolution (§22.8)
  address_resolve: (
    ownerDid: string,
    address: string,
    knownContextsJson: string | undefined,
  ) => string;
  // Provenance
  evaluate_provenance_quality: (
    sourceContext: string | undefined,
    sourceType: string,
    contextState: string,
    counterpartiesJson: string | undefined,
  ) => number;
  provenance_attach: (
    sourceContextId: string,
    sourceType: string,
    memoryScope: string,
    membersJson: string,
    targetContextId: string,
    existingChainDepth: number,
    existingChainPathJson: string,
    discoveryMethod: string | undefined,
    purpose: string | undefined,
  ) => string;
  provenance_check_chain_depth: (chainDepth: number, maxDepth: number | undefined) => boolean;
  // Sync
  sync_classify_offline: (lastRelayContact: number, now: number) => string;
  sync_classify_offline_custom: (
    lastRelayContact: number,
    now: number,
    tier1ThresholdSecs: number,
    tier2ThresholdSecs: number,
  ) => string;
  sync_get_policy: () => ReturnType<Bridge["syncGetPolicy"]>;
  // Identity Advanced
  identity_create_with_agent_key: (
    custody: string,
  ) => Promise<{ did: string; custodyType: string }>;
  identity_add_agent_key: (identity: { did: string; custodyType: string }) => {
    did: string;
    custodyType: string;
  };
  identity_rotate_agent_key: (identity: { did: string; custodyType: string }) => {
    did: string;
    custodyType: string;
  };
  identity_remove_agent_key: (identity: { did: string; custodyType: string }) => {
    did: string;
    custodyType: string;
  };
  identity_migrate: (identity: {
    did: string;
    custodyType: string;
  }) => Promise<{ did: string; custodyType: string }>;
  identity_attest_device: (did: string) => Promise<string>;
  identity_verify_device_attestation: (did: string, tokenBase64: string) => Promise<boolean>;
  // Membership queries
  context_member_count: (handle: BridgeContextHandle) => number | null;
  context_is_member: (handle: BridgeContextHandle, did: string) => boolean;
  context_member_dids: (handle: BridgeContextHandle) => string;
  context_member_role: (handle: BridgeContextHandle, did: string) => string | null;
  // Broadcast operations
  broadcast_subscribe: (handle: BridgeContextHandle, subscriberDid: string) => Promise<void>;
  broadcast_unsubscribe: (handle: BridgeContextHandle, subscriberDid: string) => Promise<void>;
  broadcast_publish: (
    handle: BridgeContextHandle,
    authorDid: string,
    payloadBase64: string,
  ) => Promise<void>;
  broadcast_block: (
    handle: BridgeContextHandle,
    subscriberDid: string,
    blockerDid: string,
  ) => Promise<void>;
  broadcast_unblock: (
    handle: BridgeContextHandle,
    subscriberDid: string,
    unblockerDid: string,
  ) => Promise<void>;
  broadcast_subscriber_count: (handle: BridgeContextHandle) => number | null;
  broadcast_is_subscriber: (handle: BridgeContextHandle, did: string) => boolean;
  broadcast_admission: (handle: BridgeContextHandle) => string | null;
  broadcast_handle_key_request: (
    handle: BridgeContextHandle,
    authorDid: string,
    requesterDid: string,
  ) => Promise<string>;
  // Identity key rotation
  identity_rotate_key: (identity: { did: string; custodyType: string }) => {
    did: string;
    custodyType: string;
  };
  // Governance
  context_execute_governance: (
    handle: BridgeContextHandle,
    initiatorDid: string,
    proposalId: string,
    actionJson: string,
  ) => Promise<string>;
  // Governance proposal lifecycle (#621)
  context_governance_propose: (
    handle: BridgeContextHandle,
    proposerDid: string,
    proposalId: string,
    actionJson: string,
  ) => Promise<string>;
  context_governance_approve: (
    handle: BridgeContextHandle,
    proposalId: string,
    voterDid: string,
  ) => Promise<string>;
  context_governance_reject: (
    handle: BridgeContextHandle,
    proposalId: string,
    voterDid: string,
  ) => Promise<string>;
  context_governance_withdraw: (
    handle: BridgeContextHandle,
    proposalId: string,
    voterDid: string,
  ) => Promise<string>;
  context_governance_get_proposal: (
    handle: BridgeContextHandle,
    proposalId: string,
  ) => Promise<string>;
  context_governance_list_proposals: (handle: BridgeContextHandle) => Promise<string>;
  // Event log checkpoint
  event_log_checkpoint: (
    handle: BridgeContextHandle,
    identityDid: string,
    epoch: number,
  ) => Promise<{
    contextId: string;
    senderDid: string;
    eventCount: number;
    merkleRoot: string;
    epoch: number | null;
    timestamp: number;
    signingPayloadHash: string;
  }>;
  // Context drain/export/import
  context_drain_events: (handle: BridgeContextHandle) => string;
  context_export: (handle: BridgeContextHandle) => Promise<Uint8Array>;
  context_import: (data: Uint8Array) => Promise<string>;
  // TTL
  context_ttl_remaining: (handle: BridgeContextHandle) => number | null;
  context_extend_ttl: (handle: BridgeContextHandle, additionalSecs: number) => Promise<boolean>;
  context_handle_ttl_expiry: (handle: BridgeContextHandle) => Promise<void>;
  context_propose_ttl_extension: (
    handle: BridgeContextHandle,
    proposerDid: string,
    extensionSecs: number,
  ) => Promise<boolean>;
  context_reset_ttl_timer: (handle: BridgeContextHandle, newDurationSecs: number) => Promise<void>;
  // UCAN delegate
  ucan_delegate: (
    handle: BridgeContextHandle,
    delegatorDid: string,
    delegateeDid: string,
    parentToken: string,
    capabilitiesJson: string,
  ) => Promise<{
    tokenId: string;
    issuer: string;
    audience: string;
    capabilitiesJson: string;
    expiresAt: number | null;
    encoded: string;
  }>;
  // Economic policy (§19.3)
  context_set_economic_policy: (handle: BridgeContextHandle, policyJson: string) => void;
  context_get_economic_policy: (handle: BridgeContextHandle) => string | undefined;
}

// ---------------------------------------------------------------------------
// WASM initialization
// ---------------------------------------------------------------------------

let _wasmModule: WasmModule | null = null;
let _initPromise: Promise<void> | null = null;

/**
 * Initializes the WASM module.
 *
 * Loads and instantiates the wasm-bindgen generated module. This must be
 * called once before any bridge functions are invoked. The `getBridge()`
 * function handles this automatically.
 *
 * This function is idempotent -- calling it multiple times returns the same
 * initialization promise.
 */
export async function initWasm(): Promise<void> {
  if (_wasmModule !== null) {
    return;
  }

  if (_initPromise !== null) {
    return _initPromise;
  }

  _initPromise = (async () => {
    try {
      // Dynamic import of the wasm-bindgen generated package.
      // This package is produced by `wasm-pack build --target bundler`
      // and may not be installed in all environments.
      const mod = (await import(
        /* webpackIgnore: true */ "@limn-works/scp-ts-wasm"
      )) as unknown as WasmModule;
      await mod.default();
      mod.scp_init();
      _wasmModule = mod;
    } catch (err) {
      _initPromise = null;
      throw new TransportError(
        `Failed to initialize WASM module: ${err instanceof Error ? err.message : String(err)}. ` +
          "Ensure @limn-works/scp-ts-wasm is installed and the WASM binary is accessible.",
        "SCP-TRANS-5002",
      );
    }
  })();

  return _initPromise;
}

/**
 * Returns the initialized WASM module, throwing if not yet initialized.
 */
function getWasm(): WasmModule {
  if (_wasmModule === null) {
    throw new TransportError(
      "WASM module not initialized -- call initWasm() first",
      "SCP-TRANS-5002",
    );
  }
  return _wasmModule;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Converts a Uint8Array to a base64 string for WASM boundary crossing. */
function uint8ToBase64(bytes: Uint8Array): string {
  // Use Buffer in Node.js/Bun, or manual conversion in browser.
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return globalThis.btoa(binary);
}

/** Converts a base64 string back to a Uint8Array. */
function base64ToUint8(base64: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(base64, "base64"));
  }
  const binary = globalThis.atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Generates a 64-character hex-encoded proposal ID (256-bit random).
 *
 * Native bridges receive hex-encoded SHA-256 hashes (64-char hex) from
 * scp-core's `compute_proposal_id()`. This function produces a 256-bit
 * random value in the same format for cross-bridge interop.
 */
function generateProposalIdHex(): string {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(32));
  let hex = "";
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, "0");
  }
  return hex;
}

// ---------------------------------------------------------------------------
// Bridge factory
// ---------------------------------------------------------------------------

/**
 * Creates a `Bridge` implementation backed by the wasm-bindgen WASM module.
 */
export function createWasmBridge(): Bridge {
  return {
    // Identity
    async identityCreate(custody: string): Promise<BridgeIdentityHandle> {
      const wasm = getWasm();
      const handle = await wasm.identity_create(custody);
      return { did: handle.did, custodyType: handle.custodyType };
    },

    async identityLoad(did: string): Promise<BridgeIdentityHandle> {
      const wasm = getWasm();
      const handle = await wasm.identity_load(did);
      return { did: handle.did, custodyType: handle.custodyType };
    },

    async identityResolve(did: string): Promise<DIDDocument> {
      const wasm = getWasm();
      const doc = await wasm.identity_resolve(did);
      // Derive agent key state from verificationMethodsJson — check for an
      // `#agent` verification method, consistent with the NAPI bridge which
      // uses `document.has_agent_key()` / `document.agent_verification_method()`.
      const verificationMethods: VerificationMethod[] = safeJsonParse(
        doc.verificationMethodsJson,
        "identity_resolve",
      ) as VerificationMethod[];
      const agentVm = verificationMethods.find((vm) => vm.id.endsWith("#agent"));
      return {
        id: doc.id,
        verificationMethods: verificationMethods as DIDDocument["verificationMethods"],
        authentication: safeJsonParse(
          doc.authenticationJson,
          "identity_resolve",
        ) as DIDDocument["authentication"],
        assertionMethods: safeJsonParse(
          doc.assertionMethodsJson,
          "identity_resolve",
        ) as DIDDocument["assertionMethods"],
        alsoKnownAs: safeJsonParse(
          doc.alsoKnownAsJson,
          "identity_resolve",
        ) as DIDDocument["alsoKnownAs"],
        serviceEndpoints: safeJsonParse(
          doc.servicesJson,
          "identity_resolve",
        ) as DIDDocument["serviceEndpoints"],
        hasAgentKey: agentVm !== undefined,
        ...(agentVm !== undefined && {
          agentPublicKey: agentVm.publicKeyMultibase,
        }),
      };
    },

    async identityRotateKey(handle: BridgeIdentityHandle): Promise<BridgeIdentityHandle> {
      const wasm = getWasm();
      const result = wasm.identity_rotate_key({
        did: handle.did,
        custodyType: handle.custodyType,
      });
      return { did: result.did, custodyType: result.custodyType };
    },

    // Context
    async contextCreate(
      identity: BridgeIdentityHandle,
      paramsJson: string,
    ): Promise<BridgeContextHandle> {
      const wasm = getWasm();
      // WASM bridge uses identity.did since wasm_bindgen context_create takes a DID string.
      const handle = await wasm.context_create(identity.did, paramsJson);
      return {
        contextId: handle.contextId,
        state: handle.state,
        creatorDid: handle.creatorDid,
      };
    },

    async contextJoin(handle: BridgeContextHandle, identityDid: string): Promise<void> {
      const wasm = getWasm();
      await wasm.context_join(handle, identityDid);
    },

    async contextLeave(handle: BridgeContextHandle, identityDid: string): Promise<void> {
      const wasm = getWasm();
      await wasm.context_leave(handle, identityDid);
    },

    async contextClose(handle: BridgeContextHandle, identityDid: string): Promise<void> {
      const wasm = getWasm();
      await wasm.context_close(handle, identityDid);
    },

    async contextSend(
      handle: BridgeContextHandle,
      identityDid: string,
      payload: Uint8Array,
    ): Promise<void> {
      const wasm = getWasm();
      const payloadBase64 = uint8ToBase64(payload);
      await wasm.context_send(handle, identityDid, payloadBase64);
    },

    contextSubscribe(
      handle: BridgeContextHandle,
      _identityDid: string,
      callback: MessageCallback,
    ): void {
      const wasm = getWasm();
      wasm.context_subscribe(handle, {
        onMessage: (msg) => {
          callback.onMessage({
            senderDid: msg.senderDid,
            content: base64ToUint8(msg.payloadBase64),
            timestamp: msg.timestamp,
            sequence: 0,
            contextId: msg.contextId,
          });
        },
        onComplete: () => {
          callback.onComplete();
        },
      });
    },

    // Membership queries — delegate to WASM runtime
    async contextMemberCount(handle: BridgeContextHandle): Promise<number | null> {
      const wasm = getWasm();
      const count = wasm.context_member_count(handle);
      return count ?? null;
    },

    async contextIsMember(handle: BridgeContextHandle, did: string): Promise<boolean> {
      const wasm = getWasm();
      return wasm.context_is_member(handle, did);
    },

    async contextMemberDids(handle: BridgeContextHandle): Promise<readonly string[]> {
      const wasm = getWasm();
      const json = wasm.context_member_dids(handle);
      return safeJsonParse(json, "context_member_dids") as string[];
    },

    async contextMemberRole(handle: BridgeContextHandle, did: string): Promise<MemberRole | null> {
      const wasm = getWasm();
      const role = wasm.context_member_role(handle, did);
      return (role as MemberRole | null) ?? null;
    },

    // Broadcast operations — delegate to WASM runtime
    async broadcastSubscribe(handle: BridgeContextHandle, subscriberDid: string): Promise<void> {
      const wasm = getWasm();
      await wasm.broadcast_subscribe(handle, subscriberDid);
    },

    async broadcastUnsubscribe(
      handle: BridgeContextHandle,
      subscriberDid: string,
      rotateKeys?: boolean,
    ): Promise<void> {
      if (rotateKeys === true) {
        throw new TransportError(
          "WASM bridge does not support key rotation on broadcastUnsubscribe. " +
            "Use the native (napi-rs) bridge for rotateKeys support.",
          "SCP-TRANS-5003",
        );
      }
      const wasm = getWasm();
      await wasm.broadcast_unsubscribe(handle, subscriberDid);
    },

    async broadcastPublish(
      handle: BridgeContextHandle,
      authorDid: string,
      payload: Uint8Array,
    ): Promise<void> {
      const wasm = getWasm();
      const payloadBase64 = uint8ToBase64(payload);
      await wasm.broadcast_publish(handle, authorDid, payloadBase64);
    },

    async broadcastBlockSubscriber(
      handle: BridgeContextHandle,
      subscriberDid: string,
      blockerDid: string,
    ): Promise<void> {
      const wasm = getWasm();
      await wasm.broadcast_block(handle, subscriberDid, blockerDid);
    },

    async broadcastUnblockSubscriber(
      handle: BridgeContextHandle,
      subscriberDid: string,
      unblockerDid: string,
    ): Promise<void> {
      const wasm = getWasm();
      await wasm.broadcast_unblock(handle, subscriberDid, unblockerDid);
    },

    async broadcastHandleKeyRequest(
      handle: BridgeContextHandle,
      authorDid: string,
      requesterDid: string,
    ): Promise<string> {
      const wasm = getWasm();
      return await wasm.broadcast_handle_key_request(handle, authorDid, requesterDid);
    },

    async broadcastSubscriberCount(handle: BridgeContextHandle): Promise<number | null> {
      const wasm = getWasm();
      const count = wasm.broadcast_subscriber_count(handle);
      return count ?? null;
    },

    async broadcastIsSubscriber(handle: BridgeContextHandle, did: string): Promise<boolean> {
      const wasm = getWasm();
      return wasm.broadcast_is_subscriber(handle, did);
    },

    async broadcastAdmission(
      handle: BridgeContextHandle,
    ): Promise<BroadcastAdmissionPolicy | null> {
      const wasm = getWasm();
      const admission = wasm.broadcast_admission(handle);
      if (admission == null) return null;
      return admission as BroadcastAdmissionPolicy;
    },

    // Governance — delegate to WASM runtime
    async contextExecuteGovernanceAction(
      handle: BridgeContextHandle,
      actionJson: string,
      proposerDid: string,
    ): Promise<string> {
      const wasm = getWasm();
      // Generate a 64-char hex proposal ID (256-bit) matching native bridge
      // format (SHA-256 hex from scp-core's compute_proposal_id).
      const proposalId = generateProposalIdHex();
      return await wasm.context_execute_governance(handle, proposerDid, proposalId, actionJson);
    },

    // Governance proposal lifecycle (#621)
    async contextGovernancePropose(
      handle: BridgeContextHandle,
      actionJson: string,
      proposerDid: string,
    ): Promise<string> {
      const wasm = getWasm();
      const proposalId = generateProposalIdHex();
      return await wasm.context_governance_propose(handle, proposerDid, proposalId, actionJson);
    },
    async contextGovernanceApprove(
      handle: BridgeContextHandle,
      proposalIdHex: string,
      voterDid: string,
    ): Promise<string> {
      const wasm = getWasm();
      return await wasm.context_governance_approve(handle, proposalIdHex, voterDid);
    },
    async contextGovernanceReject(
      handle: BridgeContextHandle,
      proposalIdHex: string,
      voterDid: string,
    ): Promise<string> {
      const wasm = getWasm();
      return await wasm.context_governance_reject(handle, proposalIdHex, voterDid);
    },
    async contextGovernanceWithdraw(
      handle: BridgeContextHandle,
      proposalIdHex: string,
      voterDid: string,
    ): Promise<string> {
      const wasm = getWasm();
      return await wasm.context_governance_withdraw(handle, proposalIdHex, voterDid);
    },
    async contextGovernanceGetProposal(
      handle: BridgeContextHandle,
      proposalIdHex: string,
    ): Promise<string> {
      const wasm = getWasm();
      return await wasm.context_governance_get_proposal(handle, proposalIdHex);
    },
    async contextGovernanceListProposals(handle: BridgeContextHandle): Promise<string> {
      const wasm = getWasm();
      return await wasm.context_governance_list_proposals(handle);
    },

    // TTL operations
    async contextTtlRemaining(handle: BridgeContextHandle): Promise<number | null> {
      const wasm = getWasm();
      const remaining = wasm.context_ttl_remaining(handle);
      return remaining ?? null;
    },

    async contextExtendTtl(handle: BridgeContextHandle, additionalSecs: number): Promise<boolean> {
      const wasm = getWasm();
      return await wasm.context_extend_ttl(handle, additionalSecs);
    },

    async contextHandleTtlExpiry(handle: BridgeContextHandle): Promise<void> {
      const wasm = getWasm();
      await wasm.context_handle_ttl_expiry(handle);
    },

    async contextProposeTtlExtension(
      handle: BridgeContextHandle,
      proposerDid: string,
      extensionSecs: number,
    ): Promise<boolean> {
      const wasm = getWasm();
      return await wasm.context_propose_ttl_extension(handle, proposerDid, extensionSecs);
    },

    async contextResetTtlTimer(
      handle: BridgeContextHandle,
      newDurationSecs: number,
    ): Promise<void> {
      const wasm = getWasm();
      await wasm.context_reset_ttl_timer(handle, newDurationSecs);
    },

    // Economic policy (§19.3)
    async contextSetEconomicPolicy(handle: BridgeContextHandle, policyJson: string): Promise<void> {
      const wasm = getWasm();
      wasm.context_set_economic_policy(handle, policyJson);
    },

    async contextGetEconomicPolicy(handle: BridgeContextHandle): Promise<string | null> {
      const wasm = getWasm();
      return wasm.context_get_economic_policy(handle) ?? null;
    },

    // Context export/import
    async contextExport(handle: BridgeContextHandle): Promise<Uint8Array> {
      const wasm = getWasm();
      // WASM export returns Uint8Array directly — no base64 conversion needed.
      return await wasm.context_export(handle);
    },

    async contextImport(data: Uint8Array): Promise<string> {
      const wasm = getWasm();
      // WASM import takes Uint8Array directly — no base64 conversion needed.
      return await wasm.context_import(data);
    },

    // Drain events
    async contextDrainEvents(handle: BridgeContextHandle): Promise<readonly string[]> {
      const wasm = getWasm();
      // context_drain_events is synchronous in the WASM export — no await needed.
      const json = wasm.context_drain_events(handle);
      return safeJsonParse(json, "context_drain_events") as string[];
    },

    // Tools -- delegates to WASM runtime registry
    async toolRegister(handle: BridgeContextHandle, definition: ToolDefinition): Promise<string> {
      const wasm = getWasm();
      const definitionJson = JSON.stringify({
        name: definition.name,
        description: definition.description,
        schema: {
          input: definition.inputSchema,
          output: definition.outputSchema,
        },
        operatorDid: definition.operator,
        testVectors: definition.testVectors?.map((tv) => ({
          input: tv.input,
          expectedOutput: tv.expectedOutput,
          description: tv.description,
        })),
      });
      return await wasm.tool_register(handle, definitionJson);
    },

    async toolInvoke(
      handle: BridgeContextHandle,
      toolId: string,
      inputJson: string,
      identityDid: string,
      ucanToken: string,
    ): Promise<string> {
      const wasm = getWasm();
      return await wasm.tool_invoke(handle, toolId, inputJson, identityDid, ucanToken);
    },

    async toolVerify(handle: BridgeContextHandle, toolId: string): Promise<ToolVerificationResult> {
      const wasm = getWasm();
      const result = await wasm.tool_verify(handle, toolId);
      return {
        toolId: result.toolId,
        passed: result.passed,
        failures: safeJsonParse(
          result.failuresJson,
          "tool_verify",
        ) as ToolVerificationResult["failures"],
      };
    },

    // Transport
    async transportConnect(relayUrl: string): Promise<BridgeTransportHandle> {
      const wasm = getWasm();
      const status = await wasm.transport_connect(relayUrl);
      return { isConnected: status.connected, relayUrl: status.relayUrl };
    },

    async transportStatus(handle: BridgeTransportHandle): Promise<TransportStatus> {
      return { connected: handle.isConnected, relayUrl: handle.relayUrl, latencyMs: null };
    },

    async transportDisconnect(_handle: BridgeTransportHandle): Promise<void> {
      const wasm = getWasm();
      await wasm.transport_disconnect();
    },

    // UCAN -- delegates to WASM 11-step validation pipeline
    async ucanValidate(
      handle: BridgeContextHandle,
      token: string,
      capability: string,
    ): Promise<void> {
      const wasm = getWasm();
      // The WASM bridge expects an audience DID for step 5 validation.
      // Use the context creator DID as the expected audience.
      await wasm.ucan_validate(handle, token, capability, handle.creatorDid, undefined);
    },

    async ucanMint(
      handle: BridgeContextHandle,
      memberDid: string,
      capabilities: readonly string[],
    ): Promise<UcanToken> {
      const wasm = getWasm();
      const capabilitiesJson = JSON.stringify(capabilities);
      const result = await wasm.ucan_mint(handle, memberDid, capabilitiesJson);
      const token: UcanToken = {
        id: result.tokenId,
        encoded: result.encoded,
        issuer: result.issuer,
        audience: result.audience,
        capabilities: safeJsonParse(result.capabilitiesJson, "ucan_mint") as string[],
      };
      if (result.expiresAt != null) {
        return { ...token, expiresAt: result.expiresAt };
      }
      return token;
    },

    async ucanRevoke(handle: BridgeContextHandle, token: string): Promise<void> {
      const wasm = getWasm();
      await wasm.ucan_revoke(handle, token);
    },

    async ucanDelegate(
      handle: BridgeContextHandle,
      delegatorDid: string,
      delegateeDid: string,
      parentToken: string,
      capabilities: readonly string[],
    ): Promise<UcanToken> {
      const wasm = getWasm();
      const capabilitiesJson = JSON.stringify(capabilities);
      const result = await wasm.ucan_delegate(
        handle,
        delegatorDid,
        delegateeDid,
        parentToken,
        capabilitiesJson,
      );
      const token: UcanToken = {
        id: result.tokenId,
        encoded: result.encoded,
        issuer: result.issuer,
        audience: result.audience,
        capabilities: safeJsonParse(result.capabilitiesJson, "ucan_delegate") as string[],
      };
      if (result.expiresAt != null) {
        return { ...token, expiresAt: result.expiresAt };
      }
      return token;
    },

    // Event Log -- delegates to WASM-local Merkle tree
    async eventLogQuery(
      handle: BridgeContextHandle,
      filter: EventFilter | undefined,
    ): Promise<readonly Event[]> {
      const wasm = getWasm();
      const filterJson = filter ? JSON.stringify(filter) : undefined;
      const resultJson = await wasm.event_log_query(handle, filterJson);
      const events = safeJsonParse(resultJson, "event_log_query") as Array<{
        eventType: string;
        actorDid: string;
        timestamp: number;
        payloadJson: string;
        sequence: number;
      }>;
      return events.map((e) => ({
        eventType: e.eventType,
        actorDid: e.actorDid,
        timestamp: e.timestamp,
        payload: safeJsonParse(e.payloadJson, "event_log_query") as Event["payload"],
        sequence: e.sequence,
      }));
    },

    async eventLogVerify(handle: BridgeContextHandle, claim: EventClaim): Promise<Proof> {
      const wasm = getWasm();
      const claimJson = JSON.stringify(claim);
      const result = await wasm.event_log_verify(handle, claimJson);
      return {
        verified: result.verified,
        proofType: result.proofType as "inclusion" | "absence",
        details: safeJsonParse(result.detailsJson, "event_log_verify") as Proof["details"],
      };
    },

    async eventLogCheckpoint(
      handle: BridgeContextHandle,
      identityDid: string,
      epoch: number,
    ): Promise<Checkpoint> {
      const wasm = getWasm();
      const result = await wasm.event_log_checkpoint(handle, identityDid, epoch);
      return {
        root: result.merkleRoot,
        eventCount: result.eventCount,
        timestamp: result.timestamp,
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
      const wasm = getWasm();
      return wasm.bridge_register(contextId, operatorDid, governanceDid, platform, mode);
    },

    bridgeEvaluateTrust(
      isBridged: boolean,
      isNativeTransport: boolean,
      shadowStatus: ShadowStatus,
    ) {
      const wasm = getWasm();
      return wasm.bridge_evaluate_trust(isBridged, isNativeTransport, shadowStatus);
    },

    bridgeCreateShadow(
      bridgeId: string,
      platformHandle: string,
      bridgeMode: BridgeMode,
      contextId: string | undefined,
    ) {
      const wasm = getWasm();
      return wasm.bridge_create_shadow(bridgeId, platformHandle, bridgeMode, contextId);
    },

    // Discovery
    discoveryParseAddress(address: string) {
      const wasm = getWasm();
      return wasm.discovery_parse_address(address);
    },

    discoveryCreateQuery(
      capabilities: string[] | undefined,
      keywords: string[] | undefined,
      minHistorySecs: number | undefined,
    ) {
      const wasm = getWasm();
      return wasm.discovery_create_query(
        capabilities ? JSON.stringify(capabilities) : undefined,
        keywords ? JSON.stringify(keywords) : undefined,
        minHistorySecs,
      );
    },

    discoveryNormalizeAddress(address: string) {
      const wasm = getWasm();
      return wasm.discovery_normalize_address(address);
    },

    async contextDiscover(query: string): Promise<string> {
      const wasm = getWasm();
      return await wasm.context_discover(query);
    },

    // Petnames (§22.4)
    petnameSet(ownerDid: string, targetDid: string, name: string): void {
      const wasm = getWasm();
      wasm.petname_set(ownerDid, targetDid, name);
    },

    petnameRemove(ownerDid: string, targetDid: string): void {
      const wasm = getWasm();
      wasm.petname_remove(ownerDid, targetDid);
    },

    petnameSetContext(ownerDid: string, contextId: string, name: string): void {
      const wasm = getWasm();
      wasm.petname_set_context(ownerDid, contextId, name);
    },

    petnameRemoveContext(ownerDid: string, contextId: string): void {
      const wasm = getWasm();
      wasm.petname_remove_context(ownerDid, contextId);
    },

    petnameResolveDid(ownerDid: string, name: string): string {
      const wasm = getWasm();
      return wasm.petname_resolve_did(ownerDid, name);
    },

    petnameResolveContext(ownerDid: string, name: string): string {
      const wasm = getWasm();
      return wasm.petname_resolve_context(ownerDid, name);
    },

    petnameGetForDid(ownerDid: string, targetDid: string): string | null {
      const wasm = getWasm();
      const result = wasm.petname_get_for_did(ownerDid, targetDid);
      if (result == null || result === undefined) return null;
      return result as string;
    },

    petnameGetForContext(ownerDid: string, contextId: string): string | null {
      const wasm = getWasm();
      const result = wasm.petname_get_for_context(ownerDid, contextId);
      if (result == null || result === undefined) return null;
      return result as string;
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
      const wasm = getWasm();
      return wasm.handle_register(
        discoveryContextId,
        handle,
        targetJson,
        registrantDid,
        description,
        tags ? JSON.stringify(tags) : undefined,
      );
    },

    handleLookup(
      discoveryContextId: string,
      handle: string,
      typeFilter: string | undefined,
    ): string {
      const wasm = getWasm();
      return wasm.handle_lookup(discoveryContextId, handle, typeFilter);
    },

    handleDeregister(discoveryContextId: string, handle: string, did: string): string {
      const wasm = getWasm();
      return wasm.handle_deregister(discoveryContextId, handle, did);
    },

    // Address Resolution (§22.8)
    async addressResolve(
      ownerDid: string,
      address: string,
      knownContextsJson: string | undefined,
    ): Promise<string> {
      const wasm = getWasm();
      return await wasm.address_resolve(ownerDid, address, knownContextsJson);
    },

    // Provenance
    async evaluateProvenanceQuality(
      sourceContext: string | undefined,
      sourceType: string,
      contextState: string,
      counterparties: string[] | undefined,
    ): Promise<number> {
      const wasm = getWasm();
      return wasm.evaluate_provenance_quality(
        sourceContext,
        sourceType,
        contextState,
        counterparties ? JSON.stringify(counterparties) : undefined,
      );
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
      _counterpartyPolicy: string | undefined,
    ) {
      const wasm = getWasm();
      // WASM bridge uses f64 for existing_chain_depth (-1 means first hop)
      // and a separate existing_chain_path_json parameter.
      const depth = existingChainDepth !== undefined ? existingChainDepth : -1;
      // counterpartyPolicy is intentionally not forwarded to the WASM bridge.
      // The WASM bridge re-implements provenance locally (no scp-core dependency
      // per ADR-034) and its provenance_attach Rust export does not accept a
      // counterpartyPolicy parameter. The counterparty list is still included
      // in the record (via the members/counterparties_json param); only the
      // *policy* controlling how counterparties are represented (full /
      // pseudonymized / redacted) is unavailable in the WASM path. Callers
      // needing counterpartyPolicy support should use the native (napi-rs)
      // bridge.
      return wasm.provenance_attach(
        sourceContextId,
        sourceType,
        memoryScope,
        JSON.stringify(members),
        targetContextId,
        depth,
        "[]",
        discoveryMethod ?? undefined,
        purpose ?? undefined,
      );
    },

    provenanceCheckChainDepth(chainDepth: number, maxDepth: number | undefined) {
      const wasm = getWasm();
      return wasm.provenance_check_chain_depth(chainDepth, maxDepth);
    },

    // Sync
    syncClassifyOffline(lastRelayContact: number, now: number) {
      const wasm = getWasm();
      return wasm.sync_classify_offline(lastRelayContact, now);
    },

    syncClassifyOfflineCustom(
      lastRelayContact: number,
      now: number,
      tier1ThresholdSecs: number,
      tier2ThresholdSecs: number,
    ) {
      const wasm = getWasm();
      return wasm.sync_classify_offline_custom(
        lastRelayContact,
        now,
        tier1ThresholdSecs,
        tier2ThresholdSecs,
      );
    },

    syncGetPolicy() {
      const wasm = getWasm();
      return wasm.sync_get_policy();
    },

    // Identity Advanced
    async identityCreateWithAgentKey(custody: string): Promise<BridgeIdentityHandle> {
      const wasm = getWasm();
      const handle = await wasm.identity_create_with_agent_key(custody);
      return { did: handle.did, custodyType: handle.custodyType };
    },

    async identityAddAgentKey(handle: BridgeIdentityHandle): Promise<BridgeIdentityHandle> {
      const wasm = getWasm();
      const updated = wasm.identity_add_agent_key(handle);
      return { did: updated.did, custodyType: updated.custodyType };
    },

    async identityRotateAgentKey(handle: BridgeIdentityHandle): Promise<BridgeIdentityHandle> {
      const wasm = getWasm();
      const updated = wasm.identity_rotate_agent_key(handle);
      return { did: updated.did, custodyType: updated.custodyType };
    },

    async identityRemoveAgentKey(handle: BridgeIdentityHandle): Promise<BridgeIdentityHandle> {
      const wasm = getWasm();
      const updated = wasm.identity_remove_agent_key(handle);
      return { did: updated.did, custodyType: updated.custodyType };
    },

    async identityMigrate(handle: BridgeIdentityHandle): Promise<BridgeIdentityHandle> {
      const wasm = getWasm();
      const updated = await wasm.identity_migrate(handle);
      return { did: updated.did, custodyType: updated.custodyType };
    },

    async identityAttestDevice(did: string): Promise<string> {
      const wasm = getWasm();
      return await wasm.identity_attest_device(did);
    },

    async identityVerifyDeviceAttestation(did: string, tokenBase64: string): Promise<boolean> {
      const wasm = getWasm();
      return await wasm.identity_verify_device_attestation(did, tokenBase64);
    },

    // Lifecycle
    version(): string {
      const wasm = getWasm();
      return wasm.scp_version();
    },

    shutdown(_timeoutSecs: number): void {
      // No-op in the WASM bridge -- browser manages resource cleanup.
    },
  };
}
