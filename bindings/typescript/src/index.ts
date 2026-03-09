/**
 * @scp/sdk — Shared Context Protocol TypeScript SDK.
 *
 * Dual-target architecture: browser (WASM) and Bun/Node (napi-rs native
 * addon). The correct backend is selected automatically at runtime.
 *
 * ## Quick start
 *
 * ```typescript
 * import { Identity, Context, Transport } from "@scp/sdk";
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

export type { CustodyType } from "./identity.js";
export { Identity } from "./identity.js";

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

export { Context } from "./context.js";

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

export { defineToolDefinition } from "./tools.js";

// ---------------------------------------------------------------------------
// Trust
// ---------------------------------------------------------------------------

export { evaluateTrust } from "./trust.js";

// ---------------------------------------------------------------------------
// Event Log
// ---------------------------------------------------------------------------

export { EventLog } from "./event-log.js";

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

export { Transport } from "./transport.js";

// ---------------------------------------------------------------------------
// UCAN
// ---------------------------------------------------------------------------

export { delegateUcan, mintUcan, revokeUcan, validateUcan } from "./ucan.js";

// ---------------------------------------------------------------------------
// MCP
// ---------------------------------------------------------------------------

export type { McpClient, McpServer } from "./mcp.js";
export { connectMcp, connectMcpStdio, serveMcp } from "./mcp.js";

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
} from "./errors.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type {
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
  Proof,
  Provenance,
  TestVector,
  ToolDefinition,
  ToolVerificationResult,
  TransportConfig,
  TransportStatus,
  TrustEvaluation,
  UcanToken,
  VerificationMethod,
} from "./types.js";

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

export type { StorageInterface, VfsType } from "./storage/index.js";
export { InMemorySqliteStorage, prefixSuccessor, WasmSqliteStorage } from "./storage/index.js";

// ---------------------------------------------------------------------------
// Internal — bridge target detection (read-only, for diagnostics)
// ---------------------------------------------------------------------------

export type { BridgeTarget } from "./internal/bridge.js";
export { BRIDGE_TARGET } from "./internal/bridge.js";
