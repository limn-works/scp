/**
 * @limn-works/scp-ts — Shared Context Protocol TypeScript SDK.
 *
 * Dual-target architecture: browser (WASM) and Bun/Node (napi-rs native
 * addon). The correct backend is selected automatically at runtime.
 *
 * ## Quick start
 *
 * ```typescript
 * import { Identity, Context, Transport } from "@limn-works/scp-ts";
 *
 * const identity = await Identity.create({ custody: "in_memory" });
 *
 * await using ctx = await Context.create(identity, {
 *   ceiling: ["messages:read", "messages:write"],
 *   memoryScope: "ephemeral",
 * });
 *
 * await ctx.send("hello world");
 *
 * for await (const msg of ctx.receive()) {
 *   console.log(msg.senderDid, msg.content);
 * }
 * ```
 *
 * See ADR-022 in `.docs/adrs/phase-4.md` and `.docs/scaffold/typescript.md`.
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

export type { CustodyType } from "./identity";
export { Identity } from "./identity";

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
  ScopedHandle,
  evaluateInvitation,
  metadataRecordFromJson,
  metadataRecordToJson,
  templateGetParams,
  validateAgainstTemplate,
  validateCapabilityDeclaration,
  validateContextParams,
} from "./context";

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

export { defineToolDefinition } from "./tools";

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

export type { ObservableMetrics, PaidActionType, RelayPriceAdjustment } from "./economy";
export {
  adjustRelayPrice,
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
// Errors
// ---------------------------------------------------------------------------

export {
  AttestationError,
  ContextError,
  CryptoError,
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
} from "./errors";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type {
  AddressResolution,
  AttestationSummary,
  BehavioralRecord,
  BroadcastAdmissionPolicy,
  Capability,
  Checkpoint,
  ContextParams,
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
  RequireParticipation,
  ResolutionLayer,
  ResolutionPath,
  TestVector,
  ToolDefinition,
  ToolVerificationResult,
  TransportConfig,
  TransportStatus,
  TrustEvaluation,
  TrustLevel,
  UcanToken,
  VerificationMethod,
} from "./types";

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
