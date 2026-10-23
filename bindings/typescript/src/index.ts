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
 *   const identity = await scp.identityCreate("encrypted_file");
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

// `BehavioralRecord` and `TrustEvaluation` moved to the `./types` export block
// below. They are the shapes `SCP.participationRecord` and `SCP.evaluateTrust`
// return; `./trust` declared a second, incompatible pair under the same two
// names, and this block exported that pair. `BehavioralRecord` mirrors the
// participation facts §7.3.2 of the trust spec defines, so its field set is
// specified. The `TrustEvaluation` composite is NOT defined by any spec section
// or ADR — the only artifact describing it is the `SCP.Trust.evaluate` section
// of `.docs/sketch.md`, which self-describes as a working sketch and still
// carries the pre-§7.3.2 field set. Read that gap as open, not as settled.
//
// `evaluateTrust` is no longer exported here. §7 of ADR-048 requires a stateful
// operation to be a method on `SCP` in every SDK; call `scp.evaluateTrust(...)`.
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
// MCP — handle types (entry points live on SCP)
// ---------------------------------------------------------------------------

export { McpClient, McpServer } from "./mcp";

// ---------------------------------------------------------------------------
// Transport — handle type (entry points live on SCP)
// ---------------------------------------------------------------------------

export { TransportManager } from "./transport";

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

export type {
  BlobBackend,
  CorsOrigins,
  DhtMode,
  Nat,
  NodeStartConfig,
  Reach,
  TlsMode,
} from "./server";
export { NODE_START_INVALID_CONFIG_CODE, Node, Relay } from "./server";

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

// Suspend and resume are methods on SCP itself — `await scp.suspend()` / `await scp.resume()`.

// ---------------------------------------------------------------------------
// SCP multi-instance handle (ADR-048)
// ---------------------------------------------------------------------------

export type {
  ContextReconnectResult,
  CustodyKeyRole,
  CustodyKeyType,
  CustodyPublicKey,
  KeyCustodyProvider,
  KeyPackageReservation,
  ReconnectReport,
  ScpOptions,
  StorageConfig,
} from "./scp";
export {
  p256PseudonymPoint,
  p256SoftwarePseudonymPoint,
  SCP,
} from "./scp";

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
  KeyNotFoundError,
  McpError,
  mapBridgeError,
  mapSagaError,
  OutletError,
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
  UnknownGovernanceOutcomeError,
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
  BuiltInRole,
  CachedAttestation,
  CachedAttestationDuration,
  CachedAttestationEnvelope,
  CachedAttestationEvidence,
  Capability,
  CapabilityRequirement,
  CapabilityValidation,
  CaseResult,
  ChallengeCase,
  ChallengePolicy,
  ChallengeRequest,
  ChallengeResponse,
  ChallengeVerification,
  ChallengeVerifiedRequirement,
  Checkpoint,
  ContextParams,
  CreateChallengeConfig,
  CrossContextInvocationResult,
  CustomRole,
  DIDDocument,
  Event,
  EventClaim,
  EventFilter,
  EventLogEntry,
  EventLogEntryPayload,
  ExpectedOutput,
  GovernanceActionResult,
  GradedChallenge,
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
  ProposalStatus,
  Provenance,
  PseudonymRotationPolicy,
  PublishResult,
  RejectionReason,
  RequireParticipation,
  ResolutionLayer,
  ResolutionPath,
  RetryCap,
  SagaResult,
  SealedInvitation,
  SelfAttestedRequirement,
  SiteConfig,
  TestCase,
  TestOutput,
  TestVector,
  ThresholdRequirement,
  TransportConfig,
  TransportStatus,
  TrustEvaluation,
  TrustLevel,
  UcanToken,
  VerificationLevel,
  VerificationMethod,
} from "./types";

export {
  ADMISSION_REQUIREMENT_UNMET_CODE,
  ATTEMPT_OUT_OF_ORDER_CODE,
  allValid,
  BUILT_IN_ROLES,
  CAPABILITY_DEFINITION_UNAVAILABLE_CODE,
  Capabilities,
  CHALLENGE_CLOSED_CODE,
  CHALLENGE_EXPIRED_CODE,
  CHALLENGE_NOT_OPEN_CODE,
  CHALLENGE_NOT_YET_GRADABLE_CODE,
  CHALLENGE_SUITE_BELOW_MINIMUM_CODE,
  CHALLENGE_WINDOW_OPEN_CODE,
  COOLDOWN_ACTIVE_CODE,
  checkProposalResponse,
  DEFINITION_EQUIVOCATION_CODE,
  DID_RESOLUTION_FAILED_CODE,
  decodeCaseResults,
  decodeChallengeRequest,
  decodeChallengeResponse,
  decodeChallengeVerification,
  EMPTY_SUBJECT_DID_CODE,
  EVALUATOR_UNAVAILABLE_CODE,
  encodeChallengeRequest,
  encodeChallengeResponse,
  encodeChallengeVerifications,
  encodeTestCases,
  encodeTestOutputs,
  GOVERNANCE_ACTION_RESULTS,
  GRADING_CAPACITY_EXHAUSTED_CODE,
  GRADING_IN_PROGRESS_CODE,
  GRADING_LEASE_LOST_CODE,
  governanceActionResultFromBridge,
  INVALID_REQUIREMENT_CODE,
  isRetryable,
  JSON_SCHEMA_VALIDATION_FAILED_CODE,
  MALFORMED_AGENT_CAPABILITIES_CODE,
  MALFORMED_CHALLENGE_VERIFICATIONS_CODE,
  memberRoleFromBridge,
  NON_CANONICAL_IDENTIFIER_CODE,
  OUTPUTS_MISMATCH_CODE,
  outletCall,
  outletQuery,
  POLICY_OUTSIDE_DEFINITION_CODE,
  PROPOSAL_STATUSES,
  proposalStatusFromBridge,
  REJECTION_REASONS,
  RESPONSE_TOO_LARGE_CODE,
  RETRIES_EXHAUSTED_CODE,
  rejectionReasonFromBridge,
  retryAfter,
  SCHEMA_REJECTED_CODE,
  SELF_CHALLENGE_CODE,
  STANDARD_NOT_GRADABLE_CODE,
  TOO_MANY_CAPABILITY_REQUIREMENTS_CODE,
  UNKNOWN_CHALLENGE_CODE,
  UNTRUSTED_VERIFIER_CODE,
  validateAdmission,
  validateBroadcastKeyHex,
  validateSiteConfig,
} from "./types";

// ---------------------------------------------------------------------------
// Internal — bridge target detection (read-only, for diagnostics)
// ---------------------------------------------------------------------------

export type { BridgeTarget } from "./internal/bridge";
export { BRIDGE_TARGET } from "./internal/bridge";
