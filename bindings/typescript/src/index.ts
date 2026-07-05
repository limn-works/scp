/**
 * @limn-works/scp-ts — Shared Context Protocol TypeScript SDK.
 *
 * Runs on Bun/Node.js via the napi-rs native addon. Browser clients connect
 * to a node as remote thin clients over the network (ADR-055).
 *
 * ## Quick start
 *
 * ```typescript
 * import { SCP } from "@limn-works/scp-ts";
 *
 * // Storage selection is required — there is no default (spec §17.6).
 * const scp = new SCP({ storage: { type: "in_memory" } });
 * try {
 *   const identity = await scp.identityCreate("in_memory");
 *
 *   const ctx = await scp.contextCreate(identity, JSON.stringify({
 *     ceiling: ["messages:read", "messages:write"],
 *     memoryScope: "ephemeral",
 *   }));
 *   try {
 *     await scp.contextSend(ctx, identity.did, new TextEncoder().encode("hello world"));
 *   } finally {
 *     await scp.contextLeave(ctx, identity.did);
 *   }
 * } finally {
 *   await scp.shutdown(5);
 * }
 * ```
 *
 * Phase 4 PR 4 (#1549, ADR-048) moved every NAPI bridge operation onto
 * the {@link SCP} class and collapsed the namespace classes
 * (`Identity`, `Context`, `Relay`, `Node`) to pure handle types. The
 * module-level free-function shims and class-level instance/static
 * method fan-out were deleted. Pure helpers that do not touch bridge
 * state (e.g. {@link defineToolDefinition}, {@link parseAddress})
 * remain as free functions.
 *
 * @packageDocumentation
 */

// ---------------------------------------------------------------------------
// SCPID Authentication — types only (entry points moved to SCP)
// ---------------------------------------------------------------------------

export type { ScpIdAuthentication, ScpIdChallenge, ScpIdResponse } from "./auth";

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
export { Context } from "./context";

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

export { defineToolDefinition } from "./tools";

// ---------------------------------------------------------------------------
// Trust — types only (entry points moved to SCP)
// ---------------------------------------------------------------------------

export type { AggregatedTrustInput, AggregationInput } from "./trust";

// ---------------------------------------------------------------------------
// Event Log — types only (entry points moved to SCP)
// ---------------------------------------------------------------------------
//
// The `./event-log` module was deleted in Phase 4 PR 4 Agent B1 (#1549,
// ADR-048). Call `scp.eventLogQuery(...)`, `scp.eventLogVerify(...)`,
// `scp.eventLogCheckpoint(...)` / `scp.eventLogCheckpointByDid(...)`
// directly on the SCP instance.

// ---------------------------------------------------------------------------
// Transport — types only (entry points moved to SCP)
// ---------------------------------------------------------------------------
//
// The `./transport` module was deleted in Phase 4 PR 4 Agent B1 (#1549,
// ADR-048). Call `scp.transportConnect(...)`,
// `scp.transportStatus(...)`, `scp.transportDisconnect(...)` directly.
// The transport handle is returned as an opaque `unknown` and passed
// back verbatim to subsequent `SCP` methods. `TransportStatus` lives in
// `./types` and is re-exported below.

// ---------------------------------------------------------------------------
// UCAN — types only (entry points moved to SCP)
// ---------------------------------------------------------------------------
//
// The `./ucan` module was deleted in Phase 4 PR 4 Agent B1 (#1549,
// ADR-048). `UcanToken` lives in `./types` and is re-exported below.

// ---------------------------------------------------------------------------
// MCP — types only (entry points moved to SCP)
// ---------------------------------------------------------------------------

export type { McpClient, McpServer, NativeMcpClientHandle, NativeMcpServerHandle } from "./mcp";

// ---------------------------------------------------------------------------
// Bridge Connector — types + the bridgeRegister entry point
// ---------------------------------------------------------------------------

export type {
  BridgeCredential,
  BridgeMode,
  BridgeRegistration,
  ShadowIdentity,
  ShadowStatus,
} from "./bridge";
export { bridgeEvaluateTrust, bridgeRegister } from "./bridge";

// ---------------------------------------------------------------------------
// Discovery — types + pure helpers (entry points for stateful ops moved to SCP)
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
  createQuery,
  discoverContexts,
  normalizeAddress,
  parseAddress,
  resolveAddress,
} from "./discovery";

// ---------------------------------------------------------------------------
// Media — types only (entry points moved to SCP)
// ---------------------------------------------------------------------------

export type {
  EndSessionResult,
  MediaSession,
  SendSignalingResult,
  SessionMetadata,
  SignalingResult,
} from "./media";

// ---------------------------------------------------------------------------
// Provenance — types only (entry points moved to SCP)
// ---------------------------------------------------------------------------

export type { DiscoveryMethod, ProvenanceRecord } from "./provenance";

// ---------------------------------------------------------------------------
// Economy — types + display helper (stateful entry points moved to SCP)
// ---------------------------------------------------------------------------

export type { ObservableMetrics, PaidActionType } from "./economy";
export { formatAmount } from "./economy";

// ---------------------------------------------------------------------------
// Sync — types only (entry points moved to SCP)
// ---------------------------------------------------------------------------

export type { SyncPolicy } from "./sync";

// ---------------------------------------------------------------------------
// Server (relay + node lifecycle)
// ---------------------------------------------------------------------------

export { Node, Relay } from "./server";

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

// Suspend and resume are methods on SCP itself — `scp.suspend()` / `await scp.resume()`.

// ---------------------------------------------------------------------------
// SCP multi-instance handle (ADR-048)
// ---------------------------------------------------------------------------

export type {
  ContextReconnectResult,
  KeyCustodyProvider,
  ReconnectReport,
  ScpOptions,
  StorageConfig,
} from "./scp";
export { SCP } from "./scp";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export {
  AttestationError,
  ContextError,
  CryptoError,
  EconomyError,
  GovernanceError,
  IdentityError,
  McpError,
  mapBridgeError,
  mapSagaError,
  PermissionError,
  SagaAbortedError,
  SagaBusyError,
  SagaNeedsRepairError,
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
  AssetEntry,
  AttestationSummary,
  AttestationType,
  AttestorInfo,
  BatchPublishResult,
  BehavioralRecord,
  BroadcastAdmissionPolicy,
  CachedAttestation,
  CachedAttestationDuration,
  CachedAttestationEnvelope,
  CachedAttestationEvidence,
  Capability,
  CapabilityRequirement,
  CapabilityValidation,
  ChallengeRequest,
  ChallengeResponse,
  ChallengeVerification,
  ChallengeVerificationMethod,
  Checkpoint,
  ContextParams,
  CrossContextInvocationResult,
  DIDDocument,
  Event,
  EventClaim,
  EventFilter,
  EventLogEntry,
  EventLogEntryPayload,
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
  SagaResult,
  SiteConfig,
  TestVector,
  ThresholdRequirement,
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
  VerificationLevel,
  VerificationMethod,
} from "./types";

export { allValid, validateAdmission, validateBroadcastKeyHex, validateSiteConfig } from "./types";

// ---------------------------------------------------------------------------
// Internal — bridge target detection (read-only, for diagnostics)
// ---------------------------------------------------------------------------

export type { BridgeTarget } from "./internal/bridge";
export { BRIDGE_TARGET } from "./internal/bridge";
