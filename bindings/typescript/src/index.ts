/**
 * @limn-works/scp-ts — Shared Context Protocol TypeScript SDK.
 *
 * Dual-target architecture: browser (WASM) and Bun/Node (napi-rs native
 * addon). The correct backend is selected automatically at runtime.
 *
 * ## Quick start
 *
 * ```typescript
 * import { SCP, Identity, Context } from "@limn-works/scp-ts";
 *
 * const scp = new SCP();
 * try {
 *   const identity = await Identity.create(scp, { custody: "in_memory" });
 *
 *   await using ctx = await Context.create(identity, {
 *     ceiling: ["messages:read", "messages:write"],
 *     memoryScope: "ephemeral",
 *   });
 *
 *   await ctx.send("hello world");
 *
 *   for await (const msg of ctx.receive()) {
 *     console.log(msg.senderDid, msg.content);
 *     break;
 *   }
 * } finally {
 *   await scp.shutdown(5);
 * }
 * ```
 *
 * See ADR-022 in `.docs/adrs/phase-4.md`, ADR-048
 * (`.docs/adrs/ADR-048-scp-multi-instance.md`), and
 * `.docs/scaffold/typescript.md`.
 *
 * @packageDocumentation
 */

// ---------------------------------------------------------------------------
// SCPID Authentication
// ---------------------------------------------------------------------------

export type { ScpIdAuthentication, ScpIdChallenge, ScpIdResponse } from "./auth";
export { scpidChallenge, scpidSign, scpidVerify } from "./auth";

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

export type { CustodyType, IdentityAttestationData, IdentityLinkAttestation } from "./identity";
export { Identity, IdentityAttestation, RevocationStatus } from "./identity";

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

export type {
  DeclarationValidationResult,
  InvitationEvaluationResult,
  MetadataRecord,
  OperationalMetadata,
  StructuralMetadata,
} from "./context";
export {
  Context,
  evaluateInvitation,
  metadataRecordFromJson,
  metadataRecordToJson,
  restoreAllContexts,
  restoreContext,
  ScopedHandle,
  templateGetParams,
  validateAgainstTemplate,
  validateCapabilityDeclaration,
  validateContextParams,
} from "./context";

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

export {
  defineToolDefinition,
  toolInvokeCrossContext,
  toolSessionClose,
  toolSessionCreate,
  toolSessionInvoke,
} from "./tools";

// ---------------------------------------------------------------------------
// Trust
// ---------------------------------------------------------------------------

export type { AggregatedTrustInput, AggregationInput } from "./trust";
export { aggregateTrustInput, evaluateTrust, verifyParticipationRequirements } from "./trust";

// ---------------------------------------------------------------------------
// Event Log
// ---------------------------------------------------------------------------

export { EventLog } from "./event-log";

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

export { Transport } from "./transport";

// ---------------------------------------------------------------------------
// UCAN
// ---------------------------------------------------------------------------

export { delegateUcan, mintUcan, revokeUcan, validateUcan } from "./ucan";

// ---------------------------------------------------------------------------
// MCP
// ---------------------------------------------------------------------------

export type { McpClient, McpServer } from "./mcp";
export { connectMcp, connectMcpStdio, serveMcp } from "./mcp";

// ---------------------------------------------------------------------------
// Bridge Connector
// ---------------------------------------------------------------------------

export type { BridgeMode, BridgeRegistration, ShadowIdentity, ShadowStatus } from "./bridge";
export { bridgeCreateShadow, bridgeEvaluateTrust, bridgeRegister } from "./bridge";

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

export type {
  DiscoveryResult,
  HandleDeregisterResult,
  HandleLookupResult,
  HandleRegisterResult,
  ParsedAddress,
  ScopeDeregisterResult,
  ScopeEntry,
  ScopeLookupResult,
  ScopeMetadata,
  ScopeRegisterResult,
  ScopeTarget,
} from "./discovery";
export {
  addressResolve,
  createQuery,
  discoverContexts,
  handleDeregister,
  handleLookup,
  handleRegister,
  normalizeAddress,
  parseAddress,
  petnameGetForContext,
  petnameGetForDid,
  petnameRemove,
  petnameRemoveContext,
  petnameResolveContext,
  petnameResolveDid,
  petnameSet,
  petnameSetContext,
  resolveAddress,
  scopeDeregister,
  scopeLookup,
  scopeRegister,
} from "./discovery";

// ---------------------------------------------------------------------------
// Media
// ---------------------------------------------------------------------------

export type {
  EndSessionResult,
  MediaSession,
  SendSignalingResult,
  SessionMetadata,
  SignalingResult,
} from "./media";
export {
  mediaActivateSession,
  mediaCheckCapability,
  mediaCreateAnswer,
  mediaCreateIceCandidate,
  mediaCreateOffer,
  mediaCreateSessionEnd,
  mediaEndSession,
  mediaInitiateSession,
  mediaJoinSession,
  mediaSendSignaling,
  mediaVerifySenderAttribution,
} from "./media";

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

export type { DiscoveryMethod, ProvenanceRecord } from "./provenance";
export {
  evaluateProvenanceQuality,
  provenanceAttach,
  provenanceCheckChainDepth,
} from "./provenance";

// ---------------------------------------------------------------------------
// Economy
// ---------------------------------------------------------------------------

export type { ObservableMetrics, PaidActionType } from "./economy";
export {
  antispamEscalatedCost,
  antispamRecord,
  antispamVelocity,
  autoAcceptBlocked,
  budgetGrant,
  budgetRecordSpend,
  budgetRemaining,
  checkPolicyLock,
  estimateCost,
  evaluateFormula,
  policyRequiresPayment,
  validatePolicyChange,
} from "./economy";

// ---------------------------------------------------------------------------
// Sync
// ---------------------------------------------------------------------------

export type { SyncPolicy } from "./sync";
export { classifyOffline, classifyOfflineCustom, getSyncPolicy } from "./sync";

// ---------------------------------------------------------------------------
// Server (relay + node lifecycle)
// ---------------------------------------------------------------------------

export { connectLocalTransport, Node, Relay } from "./server";

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

// Suspend and resume are methods on SCP itself — `scp.suspend()` / `await scp.resume()`.
// Phase 4 PR 4 (#1549, ADR-048) deleted the free-function wrappers to
// keep a single happy path across all SDKs.

// ---------------------------------------------------------------------------
// SCP multi-instance handle (ADR-048)
// ---------------------------------------------------------------------------

export type { ScpOptions, StorageConfig } from "./scp";
export { SCP } from "./scp";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export {
  AttestationError,
  ContextError,
  CryptoError,
  EconomicPolicyUnsupportedOnWasm,
  EconomyError,
  GovernanceError,
  IdentityError,
  McpError,
  mapBridgeError,
  PermissionError,
  ScpError,
  StorageError,
  ToolError,
  TransportError,
  UcanPermissionError,
  ValidationError,
  WasmCannotValidateSpendingUcan,
} from "./errors";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type {
  AddressResolution,
  AssetEntry,
  AttestationSummary,
  BatchPublishResult,
  BehavioralRecord,
  BroadcastAdmissionPolicy,
  Capability,
  Checkpoint,
  ContextParams,
  CrossContextInvocationResult,
  DIDDocument,
  Event,
  EventClaim,
  EventFilter,
  GovernanceActionResult,
  McpClientConfig,
  McpServerConfig,
  MemberRole,
  Message,
  ParticipationFact,
  ParticipationProfile,
  ParticipationThreshold,
  Proof,
  Provenance,
  PublishResult,
  RequireParticipation,
  ResolutionLayer,
  ResolutionPath,
  SiteConfig,
  TestVector,
  ToolCost,
  ToolDefinition,
  ToolSessionInvokeResult,
  ToolSessionResult,
  ToolVerificationResult,
  TransportConfig,
  TransportStatus,
  TrustEvaluation,
  TrustLevel,
  UcanToken,
  VerificationMethod,
} from "./types";

export { validateAdmission, validateBroadcastKeyHex, validateSiteConfig } from "./types";

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

export type { StorageInterface, VfsType } from "./storage/index";
export { InMemorySqliteStorage, prefixSuccessor, WasmSqliteStorage } from "./storage/index";

// ---------------------------------------------------------------------------
// Internal — bridge target detection (read-only, for diagnostics)
// ---------------------------------------------------------------------------

export type { BridgeTarget } from "./internal/bridge";
export { BRIDGE_TARGET } from "./internal/bridge";
