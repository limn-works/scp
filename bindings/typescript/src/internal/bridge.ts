/**
 * Runtime detection and unified bridge interface for the SCP TypeScript SDK.
 *
 * This module selects the correct FFI backend at import time based on the
 * runtime environment:
 *
 * - **Bun/Node.js** -> napi-rs native addon (`./native.js`)
 * - **Browser** -> wasm-bindgen WASM module (`./wasm.js`)
 *
 * Bridge selection is synchronous — no top-level await — to preserve CJS
 * compatibility. The actual bridge module is loaded lazily on first use via
 * `getBridge()`.
 *
 * Application code never imports from `internal/`. The public API classes
 * (`Identity`, `Context`, etc.) call `getBridge()` internally on their async
 * factory methods.
 *
 * See ADR-022 in `.docs/adrs/phase-4.md`.
 */

import type { BridgeMode, ShadowStatus } from "../bridge";
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

// ---------------------------------------------------------------------------
// Bridge interface — the contract both native and WASM bridges implement
// ---------------------------------------------------------------------------

/**
 * Unified bridge interface that both the native (napi-rs) and WASM
 * (wasm-bindgen) bridges must satisfy.
 *
 * Each method maps to a flat bridge function exposed by the Rust FFI crate.
 * The TypeScript wrapper classes (`Identity`, `Context`, etc.) delegate to
 * these methods.
 */
export interface Bridge {
  // Identity
  identityCreate(custody: string): Promise<BridgeIdentityHandle>;
  identityLoad(did: string): Promise<BridgeIdentityHandle>;
  identityResolve(did: string): Promise<DIDDocument>;
  identityRotateKey(handle: BridgeIdentityHandle): Promise<BridgeIdentityHandle>;

  // Context

  /**
   * Creates a new context owned by the given identity.
   *
   * Takes a full `BridgeIdentityHandle` (not a DID string) because context
   * creation requires access to the identity's key material for MLS group
   * setup. The remaining context methods (`contextJoin`, `contextLeave`, etc.)
   * take a plain `identityDid: string` since they operate on an already-
   * established context.
   *
   * WASM bridge implementers: the underlying `context_create` WASM export
   * still accepts a DID string — extract `identity.did` before calling it.
   */
  contextCreate(identity: BridgeIdentityHandle, paramsJson: string): Promise<BridgeContextHandle>;
  contextJoin(handle: BridgeContextHandle, identityDid: string): Promise<void>;
  contextLeave(handle: BridgeContextHandle, identityDid: string): Promise<void>;
  contextClose(handle: BridgeContextHandle, identityDid: string): Promise<void>;
  contextSend(handle: BridgeContextHandle, identityDid: string, payload: Uint8Array): Promise<void>;
  contextSubscribe(
    handle: BridgeContextHandle,
    identityDid: string,
    callback: MessageCallback,
  ): void;

  // Membership queries
  contextMemberCount(handle: BridgeContextHandle): Promise<number | null>;
  contextIsMember(handle: BridgeContextHandle, did: string): Promise<boolean>;
  contextMemberDids(handle: BridgeContextHandle): Promise<readonly string[]>;
  contextMemberRole(handle: BridgeContextHandle, did: string): Promise<MemberRole | null>;

  // Broadcast operations
  broadcastSubscribe(handle: BridgeContextHandle, subscriberDid: string): Promise<void>;
  broadcastUnsubscribe(
    handle: BridgeContextHandle,
    subscriberDid: string,
    rotateKeys?: boolean,
  ): Promise<void>;
  broadcastPublish(
    handle: BridgeContextHandle,
    authorDid: string,
    payload: Uint8Array,
  ): Promise<void>;
  broadcastBlockSubscriber(
    handle: BridgeContextHandle,
    subscriberDid: string,
    blockerDid: string,
  ): Promise<void>;
  broadcastUnblockSubscriber(
    handle: BridgeContextHandle,
    subscriberDid: string,
    unblockerDid: string,
  ): Promise<void>;
  broadcastHandleKeyRequest(
    handle: BridgeContextHandle,
    authorDid: string,
    requesterDid: string,
  ): Promise<string>;
  broadcastSubscriberCount(handle: BridgeContextHandle): Promise<number | null>;
  broadcastIsSubscriber(handle: BridgeContextHandle, did: string): Promise<boolean>;
  broadcastAdmission(handle: BridgeContextHandle): Promise<BroadcastAdmissionPolicy | null>;

  // Governance
  contextExecuteGovernanceAction(
    handle: BridgeContextHandle,
    actionJson: string,
    proposerDid: string,
  ): Promise<string>;

  // Governance proposal lifecycle (#621)
  contextGovernancePropose(
    handle: BridgeContextHandle,
    actionJson: string,
    proposerDid: string,
  ): Promise<string>;
  contextGovernanceApprove(
    handle: BridgeContextHandle,
    proposalIdHex: string,
    voterDid: string,
  ): Promise<string>;
  contextGovernanceReject(
    handle: BridgeContextHandle,
    proposalIdHex: string,
    voterDid: string,
  ): Promise<string>;
  contextGovernanceWithdraw(
    handle: BridgeContextHandle,
    proposalIdHex: string,
    voterDid: string,
  ): Promise<string>;
  contextGovernanceGetProposal(handle: BridgeContextHandle, proposalIdHex: string): Promise<string>;
  contextGovernanceListProposals(handle: BridgeContextHandle): Promise<string>;

  // TTL operations
  contextTtlRemaining(handle: BridgeContextHandle): Promise<number | null>;
  contextExtendTtl(handle: BridgeContextHandle, additionalSecs: number): Promise<boolean>;
  contextHandleTtlExpiry(handle: BridgeContextHandle): Promise<void>;
  contextProposeTtlExtension(
    handle: BridgeContextHandle,
    proposerDid: string,
    extensionSecs: number,
  ): Promise<boolean>;
  contextResetTtlTimer(handle: BridgeContextHandle, newDurationSecs: number): Promise<void>;

  // Economic policy (§19.3)
  contextSetEconomicPolicy(handle: BridgeContextHandle, policyJson: string): Promise<void>;
  contextGetEconomicPolicy(handle: BridgeContextHandle): Promise<string | null>;

  // Context export/import
  contextExport(handle: BridgeContextHandle): Promise<Uint8Array>;
  contextImport(data: Uint8Array): Promise<string>;

  // Drain events
  contextDrainEvents(handle: BridgeContextHandle): Promise<readonly string[]>;

  // Tools
  toolRegister(handle: BridgeContextHandle, definition: ToolDefinition): Promise<string>;
  toolInvoke(
    handle: BridgeContextHandle,
    toolId: string,
    inputJson: string,
    identityDid: string,
    ucanToken: string,
  ): Promise<string>;
  toolVerify(handle: BridgeContextHandle, toolId: string): Promise<ToolVerificationResult>;

  // Transport
  transportConnect(relayUrl: string): Promise<BridgeTransportHandle>;
  transportStatus(handle: BridgeTransportHandle): Promise<TransportStatus>;
  transportDisconnect(handle: BridgeTransportHandle): Promise<void>;

  // UCAN
  ucanValidate(handle: BridgeContextHandle, token: string, capability: string): Promise<void>;
  ucanMint(
    handle: BridgeContextHandle,
    memberDid: string,
    capabilities: readonly string[],
  ): Promise<UcanToken>;
  ucanRevoke(handle: BridgeContextHandle, token: string): Promise<void>;
  ucanDelegate(
    handle: BridgeContextHandle,
    delegatorDid: string,
    delegateeDid: string,
    parentToken: string,
    capabilities: readonly string[],
  ): Promise<UcanToken>;

  // Event Log
  eventLogQuery(
    handle: BridgeContextHandle,
    filter: EventFilter | undefined,
  ): Promise<readonly Event[]>;
  eventLogVerify(handle: BridgeContextHandle, claim: EventClaim): Promise<Proof>;
  eventLogCheckpoint(
    handle: BridgeContextHandle,
    identityDid: string,
    epoch: number,
  ): Promise<Checkpoint>;

  // Bridge Connector
  bridgeRegister(
    contextId: string,
    operatorDid: string,
    governanceDid: string,
    platform: string,
    mode: BridgeMode,
  ): {
    bridge_id: string;
    operator_did: string;
    platform: string;
    mode: BridgeMode;
    status: string;
    context_id: string;
  };
  bridgeEvaluateTrust(
    isBridged: boolean,
    isNativeTransport: boolean,
    shadowStatus: ShadowStatus,
  ): number;
  bridgeCreateShadow(
    bridgeId: string,
    platformHandle: string,
    bridgeMode: BridgeMode,
    contextId: string | undefined,
  ): {
    shadow_id: string;
    platform_handle: string;
    bridge_id: string;
    attributed_role: string;
    provenance_status: ShadowStatus;
  };

  // Discovery
  discoveryParseAddress(address: string): string;
  discoveryCreateQuery(
    capabilities: string[] | undefined,
    keywords: string[] | undefined,
    minHistorySecs: number | undefined,
  ): string;
  discoveryNormalizeAddress(address: string): string;
  contextDiscover(query: string): Promise<string>;

  // Petnames (section 22.4)
  petnameSet(ownerDid: string, targetDid: string, name: string): void;
  petnameRemove(ownerDid: string, targetDid: string): void;
  petnameSetContext(ownerDid: string, contextId: string, name: string): void;
  petnameRemoveContext(ownerDid: string, contextId: string): void;
  petnameResolveDid(ownerDid: string, name: string): string;
  petnameResolveContext(ownerDid: string, name: string): string;
  petnameGetForDid(ownerDid: string, targetDid: string): string | null;
  petnameGetForContext(ownerDid: string, contextId: string): string | null;

  // Handle Registry (section 22.3.1)
  handleRegister(
    discoveryContextId: string,
    handle: string,
    targetJson: string,
    registrantDid: string,
    description: string | undefined,
    tags: string[] | undefined,
  ): string;
  handleLookup(discoveryContextId: string, handle: string, typeFilter: string | undefined): string;
  handleDeregister(discoveryContextId: string, handle: string, did: string): string;

  // Address Resolution (section 22.8)
  addressResolve(
    ownerDid: string,
    address: string,
    knownContextsJson: string | undefined,
  ): Promise<string>;

  // Provenance
  evaluateProvenanceQuality(
    sourceContext: string | undefined,
    sourceType: string,
    contextState: string,
    counterparties: string[] | undefined,
  ): Promise<number>;
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
  ): string;
  provenanceCheckChainDepth(chainDepth: number, maxDepth: number | undefined): boolean;

  // Sync
  syncClassifyOffline(lastRelayContact: number, now: number): string;
  syncClassifyOfflineCustom(
    lastRelayContact: number,
    now: number,
    tier1ThresholdSecs: number,
    tier2ThresholdSecs: number,
  ): string;
  syncGetPolicy(): {
    tier_1_threshold_secs: number;
    tier_2_threshold_secs: number;
    gap_timeout_secs: number;
    reorder_buffer_capacity: number;
    max_sequential_commits: number;
    commit_process_timeout_secs: number;
    sender_key_timeout_secs: number;
    reconnection_dedup_window_secs: number;
  };

  // Identity Advanced
  identityCreateWithAgentKey(custody: string): Promise<BridgeIdentityHandle>;
  identityAddAgentKey(handle: BridgeIdentityHandle): Promise<BridgeIdentityHandle>;
  identityRotateAgentKey(handle: BridgeIdentityHandle): Promise<BridgeIdentityHandle>;
  identityRemoveAgentKey(handle: BridgeIdentityHandle): Promise<BridgeIdentityHandle>;
  identityMigrate(handle: BridgeIdentityHandle): Promise<BridgeIdentityHandle>;
  identityAttestDevice(did: string): Promise<string>;
  identityVerifyDeviceAttestation(did: string, tokenBase64: string): Promise<boolean>;

  // App Sandboxing (#595, spec §8.4.1, §8.4.2)
  validateCapabilityDeclaration(
    declarationJson: string,
    ceilingCapabilities: string[],
    roleCapabilities: string[],
  ): string;
  checkScopedCapability(grantedCapabilities: string[], requiredCapability: string): boolean;

  // Lifecycle
  version(): string;
  shutdown(timeoutSecs: number): void;
}

// ---------------------------------------------------------------------------
// Opaque bridge handle types
// ---------------------------------------------------------------------------

/** Opaque handle to an identity in the bridge layer. */
export interface BridgeIdentityHandle {
  readonly did: string;
  readonly custodyType: string;
}

/** Opaque handle to a context in the bridge layer. */
export interface BridgeContextHandle {
  readonly contextId: string;
  readonly state: string;
  readonly creatorDid: string;
}

/** Opaque handle to a transport manager in the bridge layer. */
export interface BridgeTransportHandle {
  readonly isConnected: boolean;
  readonly relayUrl: string | null;
}

// ---------------------------------------------------------------------------
// Message callback interface (used by contextSubscribe)
// ---------------------------------------------------------------------------

/** Callback interface for receiving messages from a context subscription. */
export interface MessageCallback {
  onMessage(message: Message): void;
  onComplete(): void;
}

// ---------------------------------------------------------------------------
// Runtime detection
// ---------------------------------------------------------------------------

/** The detected bridge target: `"native"` for Bun/Node, `"wasm"` for browser. */
export type BridgeTarget = "native" | "wasm";

/**
 * Detects the runtime environment synchronously.
 *
 * - Bun exposes `process.versions.bun`.
 * - Node.js exposes `process.versions.node` but not `bun`.
 * - Browsers have neither.
 *
 * This function contains no top-level await and no I/O — it is safe to call
 * at module import time, preserving CJS compatibility.
 */
function detectBridge(): BridgeTarget {
  if (typeof process !== "undefined" && process.versions?.bun) {
    return "native";
  }
  if (typeof process !== "undefined" && process.versions?.node) {
    return "native";
  }
  return "wasm";
}

/** The detected bridge target, computed once at import time. */
export const BRIDGE_TARGET: BridgeTarget = detectBridge();

// ---------------------------------------------------------------------------
// Lazy bridge loading
// ---------------------------------------------------------------------------

/** Cached bridge instance. `null` until first `getBridge()` call. */
let _bridge: Bridge | null = null;

/**
 * Returns the initialized bridge instance, loading it lazily on first call.
 *
 * - For `"native"` targets: dynamically imports `./native.js`.
 * - For `"wasm"` targets: dynamically imports `./wasm.js` and calls
 *   `initWasm()` for one-time WASM initialization.
 *
 * Subsequent calls return the cached instance — no re-initialization.
 *
 * @returns The initialized `Bridge` instance.
 */
export async function getBridge(): Promise<Bridge> {
  if (_bridge !== null) {
    return _bridge;
  }

  if (BRIDGE_TARGET === "native") {
    const mod = await import("./native.js");
    _bridge = mod.createNativeBridge();
  } else {
    const mod = await import("./wasm.js");
    await mod.initWasm();
    _bridge = mod.createWasmBridge();
  }

  return _bridge;
}

/**
 * Resets the cached bridge instance.
 *
 * This is intended for testing only — it allows tests to re-initialize the
 * bridge with a mock or a different target.
 *
 * @internal
 */
export function _resetBridge(): void {
  _bridge = null;
}

/**
 * Injects a bridge instance for testing.
 *
 * This is intended for testing only — it allows tests to inject a mock bridge
 * so that SDK classes (`Context`, `Identity`, etc.) use the mock instead of
 * loading a native or WASM bridge.
 *
 * @internal
 */
export function _setBridge(bridge: Bridge): void {
  _bridge = bridge;
}
