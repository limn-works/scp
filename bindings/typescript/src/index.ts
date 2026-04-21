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
 *   const identity = await scp.identityCreate("in_memory");
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
 * Phase 4 PR 4 (#1549, ADR-048) moved every NAPI bridge operation onto
 * the {@link SCP} class; the module-level free-function shims were
 * deleted. Pure helpers that do not touch bridge state (e.g.
 * {@link defineToolDefinition}, {@link parseAddress}) remain as
 * free functions.
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
export { Context, ScopedHandle } from "./context";

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

export { defineToolDefinition } from "./tools";

// ---------------------------------------------------------------------------
// Trust — types only (entry points moved to SCP)
// ---------------------------------------------------------------------------

export type { AggregatedTrustInput, AggregationInput } from "./trust";

// ---------------------------------------------------------------------------
// Event Log
// ---------------------------------------------------------------------------

export { EventLog } from "./event-log";

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

export { Transport } from "./transport";

// ---------------------------------------------------------------------------
// UCAN — types only (entry points moved to SCP)
// ---------------------------------------------------------------------------

// The `./ucan` module is empty after ADR-048 demolition; `UcanToken` is
// re-exported from `./types` below.

// ---------------------------------------------------------------------------
// MCP — types only (entry points moved to SCP)
// ---------------------------------------------------------------------------

export type { McpClient, McpServer } from "./mcp";

// ---------------------------------------------------------------------------
// Bridge Connector — types only (entry points moved to SCP)
// ---------------------------------------------------------------------------

export type { BridgeMode, BridgeRegistration, ShadowIdentity, ShadowStatus } from "./bridge";

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
// Economy — types only (entry points moved to SCP)
// ---------------------------------------------------------------------------

export type { ObservableMetrics, PaidActionType } from "./economy";

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
