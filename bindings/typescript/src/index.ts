/**
 * @limn-works/scp-ts — Shared Context Protocol TypeScript SDK.
 *
 * Runs on Bun/Node.js via the napi-rs native addon. Browser clients run the
 * full protocol in-tab, keys on-device, via the sibling `@limn-works/scp-ts-wasm`
 * package (the in-browser SCP client over `scp-client-wasm`, ADR-057 — which
 * amends ADR-055's earlier remote-thin-client browser model).
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
 * state (e.g. {@link defineOutletDefinition}, {@link parseAddress})
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
// Outlets
// ---------------------------------------------------------------------------

export type {
  Aggregate,
  InvokeOptions,
  StreamingSagaNative,
  StreamingSagaOptions,
} from "./outlets";
export {
  Credit,
  defineOutletDefinition,
  InvocationHandle,
  OutletStreamChunk,
  Outlets,
  StreamingSagaHandle,
} from "./outlets";

// ---------------------------------------------------------------------------
// Trust — types only (entry points moved to SCP)
// ---------------------------------------------------------------------------

export type {
  AggregatedTrustInput,
  AggregationInput,
  Attestation,
  BehavioralRecord,
  CapabilityValidation,
  ChallengeResult,
  Endorsement,
  TrustEvaluation,
} from "./trust";
export { evaluateTrust } from "./trust";

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
// Bridge Connector — types + bridge-provenance trust tier
// ---------------------------------------------------------------------------
//
// Stateful entry points (`bridgeCreateShadow`, credentials) live on SCP.
// `evaluateTrust` (exported here as `bridgeEvaluateTrust` to disambiguate
// from the four-layer `evaluateTrust` in `./trust`, mirroring the Python
// SDK's `bridge_evaluate_trust` re-export name) is the pure bridge-provenance
// trust-tier classifier (spec §12).

export type {
  BridgeCredential,
  BridgeMode,
  BridgeRegistration,
  BridgeTrustLevel,
  BridgeTrustOptions,
  ShadowIdentity,
  ShadowStatus,
} from "./bridge";
export { evaluateTrust as bridgeEvaluateTrust, bridgeRegister } from "./bridge";

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

export type {
  ObservableMetrics,
  PaidActionType,
  PaymentReceiptVerificationEntry,
  PaymentReceiptVerificationResult,
} from "./economy";
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
  KeyPackageReservation,
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
  InvalidGrant,
  McpError,
  mapBridgeError,
  mapSagaError,
  OutletError,
  PermissionError,
  ProtocolError,
  SagaAbortedError,
  SagaBusyError,
  SagaNeedsRepairError,
  ScpError,
  StorageError,
  StreamAlreadyClosed,
  StreamGap,
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
  InviteMemberOutcome,
  McpClientConfig,
  McpServerConfig,
  MemberRole,
  Message,
  OutletCost,
  OutletDefinition,
  OutletKind,
  OutletSessionInvokeResult,
  OutletSessionResult,
  OutletVerificationResult,
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
  SealedInvitation,
  SiteConfig,
  TestVector,
  ThresholdRequirement,
  TransportConfig,
  TransportStatus,
  TrustLevel,
  UcanToken,
  VerificationLevel,
  VerificationMethod,
} from "./types";

export {
  allValid,
  Capabilities,
  outletCall,
  outletQuery,
  validateAdmission,
  validateBroadcastKeyHex,
  validateSiteConfig,
} from "./types";

// ---------------------------------------------------------------------------
// Internal — bridge target detection (read-only, for diagnostics)
// ---------------------------------------------------------------------------

export type { BridgeTarget } from "./internal/bridge";
export { BRIDGE_TARGET } from "./internal/bridge";
