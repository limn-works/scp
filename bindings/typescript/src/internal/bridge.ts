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
  /**
   * Joins an existing context.
   *
   * `spendingUcanJwt` is optional and may be omitted, `undefined`, or
   * explicitly `null`. The bridge implementations (NAPI, WASM, mock) all
   * normalize the absent case so consumers can call without a third argument
   * for the common no-payment join. See ADR-033 §19 and #1531 for the
   * join-cost AND-composition flow.
   *
   * Note: this is the SDK's internal contract — SDK wrappers always normalize
   * to `null` before calling, so bridge implementations should treat
   * `undefined` and `null` as equivalent.
   */
  contextJoin(
    handle: BridgeContextHandle,
    identityDid: string,
    spendingUcanJwt?: string | null,
  ): Promise<void>;
  contextLeave(handle: BridgeContextHandle, identityDid: string): Promise<void>;
  contextClose(handle: BridgeContextHandle, identityDid: string): Promise<void>;
  /**
   * Sends a message to a context.
   *
   * `spendingUcanJwt` is optional and may be omitted, `undefined`, or
   * explicitly `null`. SDK wrappers always normalize to `null`; bridge
   * implementations treat `undefined` and `null` as equivalent. See ADR-033
   * §19 for the per-send spending UCAN flow.
   */
  contextSend(
    handle: BridgeContextHandle,
    identityDid: string,
    payload: Uint8Array,
    spendingUcanJwt?: string | null,
  ): Promise<void>;
  contextSubscribe(
    handle: BridgeContextHandle,
    identityDid: string,
    callback: MessageCallback,
  ): Promise<void>;
  contextCancelSubscription(handle: BridgeContextHandle): void;

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
  broadcastPublishAsset(
    handle: BridgeContextHandle,
    authorDid: string,
    asset: { path: string; contentType: string; body: number[] },
    deployId: string | null,
  ): Promise<{ blobId: string; etag: string; deployId: string }>;
  broadcastPublishAssets(
    handle: BridgeContextHandle,
    authorDid: string,
    assets: { path: string; contentType: string; body: number[] }[],
    deployId: string | null,
  ): Promise<{
    results: { blobId: string; etag: string; deployId: string }[];
    deployId: string;
  }>;
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

  // Governance lifecycle (#559)
  contextApplyPendingCeilingModification(
    handle: BridgeContextHandle,
    currentTimestamp: number,
  ): Promise<boolean>;
  contextFinalizeClose(handle: BridgeContextHandle): Promise<void>;
  contextCreateGovernanceCheckpoint(
    handle: BridgeContextHandle,
    checkpointSeq: number,
    merkleRootHex: string,
    eventCount: number,
    lastEventHashHex: string,
    stateSnapshotHashHex: string,
    creatorDid: string,
    creatorSignatureHex: string,
  ): Promise<string>;
  contextAddCheckpointCosignature(
    handle: BridgeContextHandle,
    checkpointJson: string,
    signerDid: string,
    signatureHex: string,
  ): Promise<string>;
  contextRestore(contextId: string): Promise<void>;
  contextRestoreAll(): Promise<string>;

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
    proofTokens?: readonly string[],
    spendingUcan?: string,
  ): Promise<string>;
  toolVerify(handle: BridgeContextHandle, toolId: string): Promise<ToolVerificationResult>;

  // Bidirectional consent protocol (§6.2.0.1)
  toolInterfaceExpose(
    handle: BridgeContextHandle,
    toolId: string,
    targetContextId: string,
    rateLimitJson?: string,
  ): Promise<string>;
  toolInterfaceAccept(handle: BridgeContextHandle, interfaceJson: string): Promise<string>;
  toolInterfaceRevoke(handle: BridgeContextHandle, interfaceIdHex: string): Promise<string>;

  // SCP-OUT-041d — outlet_error_new + outlet_catalog_rotation_validator
  outletErrorNew(
    handle: BridgeContextHandle,
    outletId: string,
    registrationEventIdHex: string,
    catalogKey: string,
    classStr: string,
    code: string,
    slug: string,
    retryStr: string,
    padNonceHex: string,
    detailJson?: string,
    sourceChainJson?: string,
  ): Promise<string>;

  outletCatalogRotationValidator(
    priorCatalogJson: string,
    newCatalogJson: string,
    priorAppendTimeSecs: number,
    newAppendTimeSecs: number,
  ): Promise<string>;

  // Cross-context tool invocation (spec section 6.2)
  toolInvokeCrossContext(
    sourceHandle: BridgeContextHandle,
    targetHandle: BridgeContextHandle,
    toolId: string,
    inputJson: string,
    invokerDid: string,
    ucanToken: string,
    chainDepth: number,
    proofTokens?: readonly string[],
  ): Promise<string>;

  // Stateful tool sessions (spec section 6.2.1)
  toolSessionCreate(
    handle: BridgeContextHandle,
    toolId: string,
    sourceContextId: string,
    ttlSeconds?: number,
  ): Promise<string>;
  toolSessionInvoke(
    handle: BridgeContextHandle,
    sessionId: string,
    inputJson: string,
    invokerDid: string,
    ucanToken: string,
    proofTokens?: readonly string[],
  ): Promise<string>;
  toolSessionClose(handle: BridgeContextHandle, sessionId: string): Promise<void>;

  // ---------------------------------------------------------------------------
  // §5.4.5 progressive-output streaming (SCP-OUT-037).
  //
  // Only the NAPI bridge implements these for now. The WASM bridge throws
  // `OutletError` with code `SCP-TOOL-6020` and message
  // `"streaming outlet invocation is not yet implemented in the WASM bridge"`
  // until the WASM portion of SCP-OUT-037 lands. SDK callers that need
  // streaming must therefore run on the native (NAPI) bridge.
  // ---------------------------------------------------------------------------

  /**
   * Opens a §5.4.5 streaming outlet invocation and returns a JS object
   * that satisfies the async-iterator protocol via its `next()` method
   * plus a `requestId` getter for the §5.4.5 16-byte `request_id`
   * (rendered as 32-char lowercase hex).
   *
   * Per AC3 the returned object is wrapped at the SDK layer to surface
   * `Symbol.asyncIterator` (the napi-rs `#[napi]` macro does not expose
   * Symbol-keyed methods directly, so the iterator-protocol shim lives
   * in the SDK).
   */
  contextOutletInvokeStream(
    handle: BridgeContextHandle,
    outletId: string,
    inputJson: string,
    identityDid: string,
    ucanToken: string,
    caveatsBindingHex: string,
    streamEpoch: number,
    proofTokens?: readonly string[],
    creditWindow?: number,
    estimatedChunkCount?: number,
  ): Promise<BridgeOutletInvocationStream>;

  /**
   * Signs and applies an `OutletStreamCredit` grant against an active
   * stream (§5.4.5 SCP-OUTLET-CREDIT-V1). Returns the new total credit
   * remaining at the executor. `callerDid` MUST match the pinned
   * invoker DID recorded at stream open — CRITICAL #1: any in-process
   * code with a `requestIdHex` could otherwise drain credit on any
   * concurrent stream because the bridge wields the invoker's signing
   * key. The bridge rejects mismatched callers as
   * `authorization.denied`.
   */
  outletStreamGrantCredit(requestIdHex: string, callerDid: string, grant: number): Promise<number>;

  /**
   * Applies an `OutletCancel` to an active stream (§5.4.5 cancel-ack).
   * Returns the recorded `cancel_ack_seq`, or `null` if the stream had
   * already terminated when the cancel arrived (idempotent).
   *
   * `callerDid` MUST match the pinned invoker DID. CRITICAL #3 fix:
   * `next_seq` is no longer caller-supplied — the bridge derives the
   * canonical next-emission cursor from runtime state (a caller-input
   * value let the caller forge `cancel_ack_seq`).
   */
  outletStreamCancel(requestIdHex: string, callerDid: string): Promise<number | null>;

  /**
   * Forces a terminal `Error{terminal:true}` chunk into the active
   * stream (§5.4.5 receiver-side revocation re-check, `RevokedMidStream`
   * / `SCP-TOOL-6110`). Called by the SDK framework's periodic UCAN
   * re-check loop when it observes the opening UCAN has been revoked
   * since stream open. The runtime emits a synthetic terminal Error
   * chunk under the pinned operator key; the SDK's chunk consumer
   * receives it as the next chunk and the stream closes naturally.
   *
   * `callerDid` MUST match the pinned invoker DID at stream open.
   */
  outletStreamTerminate(
    requestIdHex: string,
    callerDid: string,
    slug: string,
    code: string,
    message: string,
  ): Promise<void>;

  /**
   * Verifies a chunk's `SCP-OUTLET-CHUNK-SIG-V1:` signature
   * (§5.4.5 per-chunk operator signature block). `chunkJson` is the
   * canonical JSON of the full `OutletStreamChunk`. Returns `true` for
   * valid signatures, `false` otherwise. Throws on malformed inputs
   * (wrong-length pubkey / caveats_binding, malformed JSON).
   */
  verifyChunkSignature(
    chunkJson: string,
    operatorPk: Uint8Array,
    contextId: string,
    outletId: string,
    caveatsBinding: Uint8Array,
  ): Promise<boolean>;

  /**
   * Recomputes the §5.4.5 `caveats_binding` 32-byte SHA-256 over the
   * `SCP-OUTLET-CAVEAT-BIND-V1:` preimage. The bridge runs RFC 8785 JCS
   * over `effectiveCaveatsJson` so SDK callers do not need an
   * in-language JCS implementation. Returns 32 bytes.
   */
  computeCaveatsBinding(
    ucanCid: Uint8Array,
    requestId: Uint8Array,
    invokerDid: string,
    estimatedChunkCount: number,
    effectiveCaveatsJson: string,
  ): Promise<Uint8Array>;

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
    proofs?: readonly string[],
    caveatsJson?: string,
  ): Promise<UcanToken>;
  ucanRevoke(handle: BridgeContextHandle, token: string, revokerDid: string): Promise<void>;
  ucanDelegate(
    handle: BridgeContextHandle,
    delegatorDid: string,
    delegateeDid: string,
    parentToken: string,
    capabilities: readonly string[],
  ): Promise<UcanToken>;
  /**
   * Narrow a parent UCAN by attaching attenuated §7.3.8 caveats
   * (SCP-OUT-023). `childCaveatsJson` MUST be canonical JSON matching the
   * `InvocationCaveats` wire format.
   */
  ucanNarrow(
    handle: BridgeContextHandle,
    parentToken: string,
    childCaveatsJson: string,
  ): Promise<UcanToken>;

  // Trust Aggregation
  aggregateTrustInput(
    contextId: string,
    subjectDid: string,
    eventsJson: string,
    merkleRootJson: string,
    consequenceRulesJson: string,
    thresholdRequirementsJson: string,
    attestorSetsJson: string,
    cachedAttestationsJson: string,
    challengeResultsJson: string,
  ): Promise<string>;

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

  // Scope Registry (section 22.3.5, ADR-043)
  scopeRegister(
    scopeContextId: string,
    name: string,
    targetContextId: string,
    relayUrls: string[],
    registrantDid: string,
    description: string | undefined,
    tags: string[] | undefined,
  ): string;
  scopeLookup(scopeContextId: string, name: string): string;
  scopeDeregister(scopeContextId: string, name: string, did: string): string;

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
    actorDid: string,
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

  // Identity link attestation (§3.5.1)
  identityCreateLinkAttestation(
    did: string,
    platform: string,
    handle: string,
    proof: string,
    verificationMethod: string,
    platformId: string | null,
  ): Promise<string>;
  identityLinkAttestations(did: string): string;
  identityRemoveLinkAttestation(did: string, attestationId: string): boolean;
  identityVerifyLinkAttestation(
    attestationJson: string,
    issuerPublicKeyHex: string,
  ): Promise<boolean>;

  // Recovery and custody migration (#632, spec §9.12, §3.2.1)
  identityExecuteRecovery(did: string, tier: string, contextIds: string[]): Promise<string>;
  identityExecuteCustodyMigration(
    did: string,
    target: string,
    contextIds: string[],
  ): Promise<string>;

  // App Sandboxing (#595, spec §8.4.1, §8.4.2)
  validateCapabilityDeclaration(
    declarationJson: string,
    ceilingCapabilities: string[],
    roleCapabilities: string[],
  ): string;
  checkScopedCapability(
    grantedCapabilities: readonly string[],
    requiredCapability: string,
  ): boolean;

  // Invitation evaluation (§5.x, context.ts)
  evaluateInvitation(
    paramsJson: string,
    inviterDid: string,
    identityDid: string,
    policyJson: string | null,
    spendingJson: string | null,
    trustedDidsJson: string | null,
  ): string | { decision: string } | Promise<string | { decision: string }>;

  // MetadataRecord inspection (§5.7.2, #615)
  metadataRecordToJson(
    contextId: string,
    sequence: number,
    signerDid: string,
    timestamp: number,
    structuralJson: string,
    operationalJson: string,
    signatureHex: string,
  ): string;
  metadataRecordFromJson(jsonStr: string): string;

  // Context template inspection (§5.14, #615)
  templateGetParams(templateId: string): string;
  validateAgainstTemplate(paramsJson: string): string | null;
  validateContextParams(paramsJson: string): string | null;

  // Economy (§19, ADR-033)
  economyEstimateCost(policyJson: string, actionType: string, metricsJson: string): number;
  economyPolicyRequiresPayment(policyJson: string): boolean;
  economyAutoAcceptBlocked(policyJson: string): boolean;
  economyCheckPolicyLock(policyJson: string): boolean;
  economyValidatePolicyChange(currentJson: string, proposedJson: string): boolean;
  economyEvaluateFormula(formulaJson: string, metricsJson: string): number;
  economyBudgetRemaining(contextId: string, did: string): number;
  economyBudgetGrant(contextId: string, did: string, amount: number): void;
  economyBudgetRecordSpend(contextId: string, did: string, amount: number): void;
  economyAntispamRecord(contextId: string, senderDid: string, timestamp: number): void;
  economyAntispamVelocity(contextId: string, senderDid: string, now: number): number;
  economyAntispamEscalatedCost(
    contextId: string,
    senderDid: string,
    now: number,
    baseCost: number,
    thresholdsJson: string,
    floor: number | null,
    cap: number | null,
  ): number;

  // Media (ADR-024)
  mediaCheckCapability(ceiling: string[], capability: string): boolean;
  mediaInitiateSession(
    contextId: string,
    ceiling: string[],
    capabilities: string[],
    participants: string[],
    timestamp: number,
  ): string;
  mediaActivateSession(sessionJson: string): string;
  mediaJoinSession(sessionJson: string, participantDid: string): string;
  mediaEndSession(sessionJson: string, timestamp: number): string;
  mediaCreateOffer(sessionId: string, sdp: string, senderDid: string): string;
  mediaCreateAnswer(sessionId: string, sdp: string, senderDid: string): string;
  mediaCreateIceCandidate(
    sessionId: string,
    candidate: string,
    senderDid: string,
    sdpMid?: string,
    sdpMlineIndex?: number,
  ): string;
  mediaCreateSessionEnd(sessionId: string, senderDid: string): string;
  mediaSendSignaling(signalingJson: string): string;
  mediaVerifySenderAttribution(signalingJson: string, envelopeSenderDid: string): boolean;

  // SCPID authentication (§3.11)
  scpidChallenge(audience: string, ttlSeconds: number): string;
  scpidSign(did: string, signingKeyId: string, challengeJson: string): string;
  scpidVerify(responseJson: string, challengeJson: string): string;

  // Trust — participation verification (SCP-BA-004, §7.3.2.1)
  verifyParticipationRequirements(profileJson: string, requirementsJson: string): boolean;

  // Lifecycle
  version(): string;
  /**
   * Gracefully shuts down the default bridge instance.
   *
   * Awaits in-flight tasks up to `timeoutMillis` milliseconds, aborts any
   * remaining tasks when the deadline expires, clears registries,
   * disconnects transport, and runs shutdown hooks. The unit is
   * milliseconds after the #1549 Phase 4 unit unification — pass `1000`
   * for a 1-second deadline, not `1`.
   *
   * Returns a `Promise<void>` — **callers must `await` it**. Previously
   * the NAPI implementation was synchronous; a fire-and-forget call
   * worked by accident. After the async migration, fire-and-forget leaves
   * the shutdown running in the background and clears bridge state under
   * later tests/requests, causing spurious registry-miss failures.
   */
  shutdown(timeoutMillis: number): Promise<void>;
  suspend(): void;
  /**
   * Resumes the bridge. On the NAPI path this is a real async call
   * (#1678) — the bridge reconnects transport from pending relay URLs
   * and restores persisted context snapshots before the promise
   * settles. The WASM path is a no-op, but still returns a resolved
   * promise to keep the interface uniform and to let callers
   * `await bridge.resume()` without branching on target.
   */
  resume(): Promise<void>;
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
// §5.4.5 streaming bridge types (SCP-OUT-037)
// ---------------------------------------------------------------------------

/**
 * One chunk yielded by `BridgeOutletInvocationStream.next()`.
 *
 * Mirrors the §5.4.5 wire form on a per-variant basis. SDK callers branch
 * on `payloadType` and read variant fields directly. `sequence` and
 * `executionTimeMs` are surfaced as `number` (lossless within `2^53`).
 */
export interface BridgeOutletStreamChunk {
  readonly requestId: Uint8Array;
  readonly sequence: number;
  readonly sig: Uint8Array;
  readonly payloadType: "data" | "progress" | "end" | "error";
  readonly valueJson?: string;
  readonly pct?: number;
  readonly note?: string;
  readonly aggregateJson?: string;
  readonly provenanceJson?: string;
  readonly executionTimeMs?: number;
  readonly code?: string;
  readonly message?: string;
  readonly terminal?: boolean;
}

/**
 * Async-iterator-shaped handle returned by `contextOutletInvokeStream`.
 *
 * `next()` resolves to the next chunk or `null` at end-of-stream (terminal
 * `End` / `Error{terminal:true}` chunk, cancellation, or receiver close).
 * `requestId` is the §5.4.5 16-byte `request_id` rendered as 32-char
 * lowercase hex — used to address the stream from `outletStreamGrantCredit`
 * and `outletStreamCancel`.
 *
 * The SDK wraps this object in an `AsyncIterable` adapter that surfaces
 * `Symbol.asyncIterator` (the napi-rs `#[napi]` macro does not expose
 * Symbol-keyed methods directly).
 */
export interface BridgeOutletInvocationStream {
  readonly requestId: string;
  next(): Promise<BridgeOutletStreamChunk | null>;
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
 * Returns the cached bridge instance synchronously.
 *
 * This is safe to call only after at least one async SDK method has completed
 * (which triggers `getBridge()` and caches the bridge). If called before
 * initialization, throws an error.
 *
 * Used by synchronous SDK functions (`ScopedHandle.hasCapability`,
 * `validateCapabilityDeclaration`) that cannot await.
 *
 * @returns The cached `Bridge` instance.
 * @throws {Error} If the bridge has not been initialized yet.
 */
export function getBridgeSync(): Bridge {
  if (_bridge === null) {
    throw new Error("Bridge not initialized — call an async SCP function first");
  }
  return _bridge;
}

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
