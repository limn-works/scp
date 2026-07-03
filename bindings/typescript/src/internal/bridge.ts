/**
 * Unified bridge interface for the SCP TypeScript SDK.
 *
 * The SDK has a single FFI backend: the napi-rs native addon (`./native.js`),
 * which runs in Bun/Node.js. Browser clients connect to a node as remote thin
 * clients over the network (ADR-055) and do not load an in-process bridge.
 *
 * The actual bridge module is loaded lazily on first use via `getBridge()`.
 *
 * Application code never imports from `internal/`. The public API classes
 * (`Identity`, `Context`, etc.) call `getBridge()` internally on their async
 * factory methods.
 *
 * See ADR-022 in `.docs/adrs/phase-4.md`, ADR-048, and ADR-055.
 */

import type { BridgeMode, ShadowStatus } from "../bridge";
import { mapBridgeError } from "../errors";
import type { SCP } from "../scp";
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
  SagaResult,
  ToolDefinition,
  ToolVerificationResult,
  TransportStatus,
  UcanToken,
} from "../types";

// ---------------------------------------------------------------------------
// Shared CapabilityValidation projection
// ---------------------------------------------------------------------------

/**
 * Projects a bridge `ucan_evaluate` result onto the SDK
 * {@link CapabilityValidation} shape.
 *
 * The NAPI bridge result (`NapiCapabilityValidation`) already exposes the six
 * camelCase booleans, so this is a field-for-field copy that pins the canonical
 * six-field shape in ONE place — the native bridge factory calls it, so a field
 * can never be silently dropped or re-spelled (ADR-057 / spec §7.2.4). The copy
 * (rather than returning `raw`) keeps the SDK object's own identity and strips
 * any extra bridge fields.
 */
export function toCapabilityValidation(raw: CapabilityValidation): CapabilityValidation {
  return {
    tokensValid: raw.tokensValid,
    signaturesValid: raw.signaturesValid,
    withinCeiling: raw.withinCeiling,
    nonceValid: raw.nonceValid,
    notRevoked: raw.notRevoked,
    timeBoundsValid: raw.timeBoundsValid,
  };
}

// ---------------------------------------------------------------------------
// Bridge interface — the contract the native bridge implements
// ---------------------------------------------------------------------------

/**
 * Unified bridge interface that the native (napi-rs) bridge satisfies.
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
   */
  contextCreate(identity: BridgeIdentityHandle, paramsJson: string): Promise<BridgeContextHandle>;
  /**
   * Joins an existing context.
   *
   * `spendingUcanJwt` is optional and may be omitted, `undefined`, or
   * explicitly `null`. The bridge implementations (NAPI, mock) all
   * normalize the absent case so consumers can call without a third argument
   * for the common no-payment join. See ADR-033 §19 for the
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
    wrappingPubkey: Uint8Array,
  ): Promise<string | null>;
  broadcastOpenKey(sealedJson: string, wrappingSecret: Uint8Array): Promise<Uint8Array>;
  broadcastSubscriberCount(handle: BridgeContextHandle): Promise<number | null>;
  broadcastIsSubscriber(handle: BridgeContextHandle, did: string): Promise<boolean>;
  broadcastAdmission(handle: BridgeContextHandle): Promise<BroadcastAdmissionPolicy | null>;

  // Governance
  contextExecuteGovernanceAction(
    handle: BridgeContextHandle,
    proposalIdHex: string,
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
  // §9.10.4: `importerDid` identifies the importing member so the native
  // bridge can derive that identity's per-context pseudonym routing ID.
  contextImport(data: Uint8Array, importerDid: string): Promise<string>;

  // §9.10.4 test-only: inject a peer's per-member pseudonym routing ID into this
  // context's registry (simulating the peer's PseudonymAnnouncement) so a
  // co-located encrypted send can fan out to it. Feature-gated to dev/test builds.
  contextSeedPeerPseudonym(
    handle: BridgeContextHandle,
    peerDid: string,
    pseudonym: Uint8Array,
  ): Promise<void>;

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

  // The §6.2.4 atomic cross-context tool-invocation saga (ADR-049 §3a)
  toolInvokeCrossContextSaga(
    sourceHandle: BridgeContextHandle,
    targetHandle: BridgeContextHandle,
    callerDid: string,
    toolRegistrationId: string,
    inputJson: string,
    assertedNonceHex: string,
    timestampMs: bigint,
    chainDepth: number,
    ucanProofId?: string,
  ): Promise<SagaResult>;

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

  // Transport
  transportConnect(relayUrl: string): Promise<BridgeTransportHandle>;
  transportStatus(handle: BridgeTransportHandle): Promise<TransportStatus>;
  transportDisconnect(handle: BridgeTransportHandle): Promise<void>;

  // UCAN
  /**
   * Enforcing UCAN gate. FAIL CLOSED: `presentingAgentDid` is required by the
   * bridge (it will not default to the token's own `aud`, which would make the
   * step-5 audience check a tautology and inflate trust). Omitting it makes the
   * bridge reject the call.
   */
  ucanValidate(
    handle: BridgeContextHandle,
    token: string,
    capability: string,
    presentingAgentDid?: string,
    proofTokens?: readonly string[],
  ): Promise<void>;
  /**
   * Read-only, structured counterpart to {@link ucanValidate}: runs the same
   * 11-step ADR-016 pipeline but resolves to a {@link CapabilityValidation}
   * (six per-stage booleans) instead of throwing on a capability outcome, and
   * never records the token's nonce (spec §7.2.4, ADR-057). It still rejects
   * for malformed FFI inputs (bad token / capability / DID strings).
   *
   * `capability` is OPTIONAL: `null`/`undefined` (or empty) evaluates the
   * token's intrinsic validity with no invoked-capability grant-match challenge
   * — the mode the trust signal uses; a value additionally requires the token
   * grants it.
   */
  ucanEvaluate(
    handle: BridgeContextHandle,
    token: string,
    capability?: string | null,
    presentingAgentDid?: string,
    proofTokens?: readonly string[],
  ): Promise<CapabilityValidation>;
  ucanMint(
    handle: BridgeContextHandle,
    memberDid: string,
    capabilities: readonly string[],
    proofs?: readonly string[],
  ): Promise<UcanToken>;
  ucanRevoke(handle: BridgeContextHandle, token: string, revokerDid: string): Promise<void>;
  ucanDelegate(
    handle: BridgeContextHandle,
    delegatorDid: string,
    delegateeDid: string,
    parentToken: string,
    capabilities: readonly string[],
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
  petnameApplyEvent(ownerDid: string, eventJson: string): void;
  petnameDidCount(ownerDid: string): number;
  petnameContextCount(ownerDid: string): number;

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

  /**
   * Removes a DID from this instance's SCP-side identity registry.
   * Idempotent — does nothing when the DID is not present.
   */
  identityRemove(did: string): void;

  /**
   * Removes a DID from the identity registry if present. Returns `true`
   * if the identity was found and removed, `false` otherwise.
   */
  identityRemoveIfPresent(did: string): boolean;
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
  economyVerifyPaymentReceipts(receiptsJson: string): string;

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
  verifyParticipationRequirements(
    expectedSubject: string,
    requirementsJson: string,
    profileJson: string,
  ): void;

  // Trust — capability admission verification (§7.3.4.4, SCP-ACR-008)
  checkCapabilityRequirements(
    contextId: string,
    subjectDid: string,
    requirementsJson: string,
    agentCapabilitiesJson: string,
    challengeVerificationsJson: string,
  ): void;

  // Lifecycle
  version(): string;
  /**
   * Gracefully shuts down this bridge instance.
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
   * Resumes the bridge. On the NAPI path this is a real async call —
   * the bridge reconnects transport from pending relay URLs and
   * restores persisted context snapshots before the promise settles.
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
  /**
   * JSON-serialized `scp_did::DidRotationEvent`, present only on
   * handles produced by `identityMigrate` (spec §9.12, ADR-003 §4b/4c).
   * SDK callers MUST distribute this event to active context members
   * per spec §3.2.1 step 4b. `undefined` for any handle minted by
   * other operations (`identityCreate`, `identityRotateKey`, agent-key
   * ops, external load) — those do not change the DID, so no
   * `DidRotationEvent` is constructed.
   */
  readonly rotationEventJson?: string;
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
// Bridge target
// ---------------------------------------------------------------------------

/**
 * The bridge target. The SDK has a single in-process backend — the napi-rs
 * native addon (Bun/Node.js). Retained as a diagnostics constant on the
 * public surface.
 */
export type BridgeTarget = "native";

/** The bridge target. Always `"native"` — the SDK is napi-only (ADR-055). */
export const BRIDGE_TARGET: BridgeTarget = "native";

// ---------------------------------------------------------------------------
// Single bridge-error chokepoint
// ---------------------------------------------------------------------------

/**
 * Wraps a bridge object so that every raw FFI error thrown by one of its own
 * function-valued properties is converted into a typed {@link ScpError}
 * subclass via the single {@link mapBridgeError} function, applied at one site
 * per dispatch surface — here, this `wrapBridgeErrors` Proxy over both bridge
 * factories (and, separately, the SCP-class methods that dispatch through the
 * raw addon directly).
 *
 * {@link createNativeBridge} returns its bridge object through this wrapper, so
 * callers (e.g. `discovery.ts`, `trust.ts`) no longer need per-method
 * `try/catch { throw mapBridgeError(e) }` sprinkled across the SDK — the
 * conversion happens once, here.
 *
 * Behaviour:
 * - Only the bridge's **own function properties** are wrapped. Non-function
 *   properties (and inherited/runtime-hook lookups) pass through untouched.
 * - Sync-vs-async is preserved without ahead-of-time knowledge: the wrapper
 *   calls the method, and if the result is a thenable it attaches a `.catch`
 *   that re-maps the rejection; otherwise it returns the synchronous value as
 *   is (mapping any synchronous throw). A synchronous throw from an `async`
 *   bridge method (e.g. an argument guard that throws before the first
 *   `await`) is still mapped.
 * - Returned **handle objects are NOT deep-proxied.** Methods like
 *   `identityRotateKey` resolve to a live NAPI handle whose own methods
 *   (`handle.rotateKey()`) must keep their identity for handle-affinity
 *   enforcement; wrapping only the bridge surface leaves those handles intact.
 *
 * @param bridge The freshly constructed bridge object to guard.
 * @returns A `Proxy` over `bridge` whose function members map their errors.
 */
export function wrapBridgeErrors(bridge: Bridge): Bridge {
  return new Proxy(bridge, {
    get(target, prop, receiver): unknown {
      const value = Reflect.get(target, prop, receiver);
      if (typeof value !== "function") {
        return value;
      }
      // Re-bind to the underlying bridge so `this` inside a method (and any
      // closure captured at factory time) stays correct.
      const method = value as (...args: unknown[]) => unknown;
      return (...args: unknown[]): unknown => {
        let result: unknown;
        try {
          result = method.apply(target, args);
        } catch (error) {
          // Synchronous throw — including a guard that fires before the first
          // `await` inside an async bridge method.
          throw mapBridgeError(error);
        }
        // Preserve async vs sync: only attach error mapping when the method
        // actually returned a thenable. A plain (sync) return value — including
        // a returned handle object — passes through verbatim, never deep-proxied.
        if (
          result !== null &&
          typeof result === "object" &&
          typeof (result as { then?: unknown }).then === "function"
        ) {
          return (result as Promise<unknown>).then(
            (v) => v,
            (error: unknown) => {
              throw mapBridgeError(error);
            },
          );
        }
        return result;
      };
    },
  });
}

// ---------------------------------------------------------------------------
// Per-SCP native bridge cache
// ---------------------------------------------------------------------------

/**
 * Per-SCP bridge cache for the NAPI path. Keyed weakly so bridges
 * are garbage-collected with their owning `SCP` instance. Every
 * `SCP` gets its own bridge — no process-wide shared state.
 *
 * This eliminates the parallel-test bridge-poisoning failure mode:
 * previously a single `_bridge` cache was shared across all tests,
 * so a `shutdown()` in one test tore down state under concurrent
 * tests. With per-SCP caching, each test's `new SCP()` owns a
 * disjoint bridge.
 */
const _nativeBridgeForScp = new WeakMap<SCP, Bridge>();

/**
 * Returns the cached bridge instance synchronously, scoped to an SCP.
 *
 * This is safe to call only after at least one async SDK method has completed
 * (which triggers `getBridge()` and caches the bridge). If called before
 * initialization, throws an error.
 *
 * Used by synchronous SDK functions (`ScopedHandle.hasCapability`,
 * `validateCapabilityDeclaration`) that cannot await.
 *
 * @param scp The SCP instance whose bridge should be returned.
 * @returns The cached `Bridge` instance.
 * @throws {Error} If the bridge has not been initialized yet.
 */
export function getBridgeSync(scp: SCP): Bridge {
  const bridge = _nativeBridgeForScp.get(scp);
  if (bridge === undefined) {
    throw new Error("Bridge not initialized — call an async SCP function first");
  }
  return bridge;
}

/**
 * Returns the initialized bridge instance for the given {@link SCP},
 * loading it lazily on first call.
 *
 * Dynamically imports `./native.js` and instantiates a per-SCP bridge keyed
 * against the supplied wrapper. Subsequent calls for the same `SCP` return
 * the cached instance — no re-initialization.
 *
 * Each `SCP` instance owns an independent bridge (ADR-048 multi-
 * instance routing), which eliminates cross-test state poisoning in
 * parallel test runners.
 *
 * @returns The initialized `Bridge` instance.
 */
export async function getBridge(scp: SCP): Promise<Bridge> {
  let bridge = _nativeBridgeForScp.get(scp);
  if (bridge === undefined) {
    const mod = await import("./native.js");
    bridge = mod.createNativeBridge(scp);
    _nativeBridgeForScp.set(scp, bridge);
  }
  return bridge;
}
