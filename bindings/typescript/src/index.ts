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
// Identity
// ---------------------------------------------------------------------------

export type { CustodyType } from "./identity";
export { Identity } from "./identity";

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

export { Context } from "./context";

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

export { defineToolDefinition } from "./tools";

// ---------------------------------------------------------------------------
// Trust
// ---------------------------------------------------------------------------

export { evaluateTrust, verifyParticipationRequirements } from "./trust";

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

export type { DiscoveryResult, ParsedAddress } from "./discovery";
export {
  createQuery,
  discoverContexts,
  normalizeAddress,
  parseAddress,
  resolveAddress,
} from "./discovery";

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

export type { ProvenanceRecord } from "./provenance";
export {
  evaluateProvenanceQuality,
  provenanceAttach,
  provenanceCheckChainDepth,
} from "./provenance";

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
