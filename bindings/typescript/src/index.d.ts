/**
 * @limn-works/scp-ts -- Shared Context Protocol SDK for TypeScript
 *
 * Type declarations for IDE autocompletion and static analysis.
 * Generated from the SCP API surface defined in .docs/sketch.md.
 */

// -- Error hierarchy ----------------------------------------------------------

export declare class ScpError extends Error {
  readonly code: string;
  constructor(message: string, code: string);
}

export declare class IdentityError extends ScpError {
  readonly name: "IdentityError";
}

export declare class ContextError extends ScpError {
  readonly name: "ContextError";
}

export declare class UcanPermissionError extends ScpError {
  readonly name: "UcanPermissionError";
}

/** @deprecated Use `UcanPermissionError` instead. */
export declare const PermissionError: typeof UcanPermissionError;

export declare class CryptoError extends ScpError {
  readonly name: "CryptoError";
}

export declare class TransportError extends ScpError {
  readonly name: "TransportError";
}

export declare class ToolError extends ScpError {
  readonly name: "ToolError";
}

export declare class ValidationError extends ScpError {
  readonly name: "ValidationError";
}

export declare class StorageError extends ScpError {
  readonly name: "StorageError";
}

export declare class AttestationError extends ScpError {
  readonly name: "AttestationError";
}

export declare class McpError extends ScpError {
  readonly name: "McpError";
}

// -- Value types --------------------------------------------------------------

export interface Message {
  readonly senderDid: string;
  readonly content: string | Uint8Array;
  readonly timestamp: number;
  readonly sequence: number;
  readonly contextId: string;
  readonly provenance?: Provenance;
}

export interface Provenance {
  readonly sourceDid: string;
  readonly sourceContextId?: string;
  readonly timestamp: number;
  readonly signature: Uint8Array;
}

export interface ToolCost {
  readonly amount: number;
  readonly currency: string;
  readonly payee: string;
  readonly costFormula?: string;
}

export interface ToolDefinition {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Record<string, unknown>;
  readonly outputSchema: Record<string, unknown>;
  readonly operator: Identity | string;
  readonly testVectors?: TestVector[];
  readonly implementationHash?: Uint8Array;
  readonly cost?: ToolCost;
}

export interface TestVector {
  readonly input: Record<string, unknown>;
  readonly expectedOutput: Record<string, unknown>;
  readonly description: string;
}

export interface ToolResult {
  readonly output: Record<string, unknown>;
  readonly provenance: Provenance;
}

export interface ContextParams {
  readonly ceiling: string[];
  readonly tools?: ToolDefinition[];
  readonly roles?: Record<string, string[]>;
  readonly ttl?: number;
  readonly memoryScope?: "ephemeral" | "summary" | "full";
  readonly governance?: "single_admin" | "threshold" | "majority" | "unanimity";
  /**
   * Minimum protocol version required to join (spec §13.4).
   * Encoded as `[major, minor]`, e.g., `[1, 0]` for SCP/1.0.
   */
  readonly minProtocolVersion?: readonly [number, number];
}

export interface TrustEvaluation {
  readonly targetDid: string;
  readonly score: number;
  readonly factors: Record<string, number>;
}

export interface DIDDocument {
  readonly id: string;
  readonly verificationMethods: VerificationMethod[];
  readonly authentication: string[];
  readonly assertionMethods: string[];
  readonly alsoKnownAs: string[];
  readonly serviceEndpoints: string[];
  readonly hasAgentKey: boolean;
  readonly agentPublicKey?: string;
}

export interface VerificationMethod {
  readonly id: string;
  readonly type: string;
  readonly controller: string;
  readonly publicKeyMultibase: string;
}

export interface UcanToken {
  readonly id: string;
  readonly encoded: string;
  readonly issuer: string;
  readonly audience: string;
  readonly capabilities: string[];
  readonly expiresAt?: number;
}

export interface EventLogEvent {
  readonly eventType: string;
  readonly actorDid: string;
  readonly timestamp: number;
  readonly payload: unknown;
  readonly sequence: number;
}

export interface EventLogProof {
  readonly verified: boolean;
  readonly proofType: string;
  readonly details: unknown;
}

export interface TransportConfig {
  readonly relayUrl: string;
  readonly protocol?: string;
}

// -- Address Resolution (§22.2.1, §22.7) -------------------------------------
// Canonical definitions live in types.ts; re-exported here for declaration consumers.

export type { AddressResolution, ResolutionLayer, ResolutionPath, TrustLevel } from "./types";

// `resolveAddress` now takes an explicit `SCP` instance per ADR-048.
// The authoritative declaration lives alongside the implementation in
// `./discovery.ts`; this file no longer redeclares it.

// -- Identity -----------------------------------------------------------------
//
// Phase 4 PR 4 Agent B1 (#1549, ADR-048) collapsed `Identity` to a
// pure handle type. Lifecycle operations (create, load, resolve,
// rotateKey, agent-key CRUD, attestations, recovery, custody
// migration) live on the `SCP` class — call `scp.identityCreate(...)`,
// `scp.identityLoad(...)`, `scp.identityResolve(...)`,
// `scp.identityRotateKey(identity)`, etc.

export declare class Identity {
  readonly did: string;
  readonly custodyType: string;
}

// -- Context ------------------------------------------------------------------
//
// Phase 4 PR 4 Agent B1 collapsed `Context` to a pure handle type.
// Lifecycle and content operations (create, import, join, send,
// receive, leave, close, tool registration, governance, broadcast,
// economic policy, TTL, event drain, etc.) live on the `SCP` class —
// call `scp.contextCreate(...)`, `scp.contextSend(...)`, etc.

export declare class Context {
  readonly contextId: string;
  readonly identityDid: string;
}

// -- UCAN ---------------------------------------------------------------------
//
// UCAN lifecycle entry points moved onto the SCP class in Phase 4 PR 4
// (#1549, ADR-048). Call `scp.ucanValidate(...)`, `scp.ucanMint(...)`,
// `scp.ucanRevoke(...)`, and `scp.ucanDelegate(...)` directly.

// -- Trust --------------------------------------------------------------------
//
// Trust evaluation sugar moved onto the SCP class in Phase 4 PR 4.
// `scp.aggregateTrustInput(...)`, `scp.verifyParticipationRequirements(...)`
// and related primitives are now available directly on the SCP instance.

// -- Event Log ----------------------------------------------------------------
//
// Phase 4 PR 4 Agent B1 deleted the `EventLog` class. Call
// `scp.eventLogQuery(handle, filter)`,
// `scp.eventLogVerify(handle, claimJson)`, and
// `scp.eventLogCheckpoint(handle, identity, epoch)` /
// `scp.eventLogCheckpointByDid(handle, did, epoch)` directly.

// -- Transport ----------------------------------------------------------------
//
// Phase 4 PR 4 Agent B1 deleted the `Transport` class and the free-
// function `connect`. Call `scp.transportConnect(relayUrl)` directly;
// the returned opaque handle is passed back to
// `scp.transportStatus(handle)` and `scp.transportDisconnect(handle)`.

// -- MCP ----------------------------------------------------------------------
//
// MCP server/client entry points moved onto the SCP class in Phase 4 PR 4
// (#1549, ADR-048). Call `scp.mcpServerCreate(...)`,
// `scp.mcpClientConnectStdio(...)`, `scp.mcpClientConnectSse(...)` and
// `scp.mcpClientInvoke(...)` directly. `McpServer` and `McpClient` are
// pure handle types in `./mcp.ts`.

// -- SCP multi-instance handle (#1549 Phase 4 PR 1, ADR-048) -----------------

/**
 * Storage configuration forwarded to `SCP.withStorage` / `new SCP({storage})`.
 *
 * Phase 4 PR 1 accepts only `{ type: "in_memory" }`; PR 3 adds SQLite
 * variants. Unknown types raise `SCP-VALID-7005`.
 */
export type StorageConfig = { type: "in_memory" } | { type: string; [k: string]: unknown };

/** Constructor options for `new SCP(...)`. */
export interface ScpOptions {
  storage?: StorageConfig;
  persistence?: unknown;
}

/**
 * Caller-owned SCP instance — the sole SDK entry point.
 *
 * Each `SCP` wraps an independent native `BridgeInstance` (registries,
 * transport, context manager). Phase 4 PR 4 (#1549, ADR-048) deleted
 * the process-wide default-instance façade and the free-function
 * shorthands that used it; callers construct an explicit `new SCP()`
 * and call methods on it directly. Agent B1 collapsed the namespace
 * classes (`Identity`, `Context`, `Relay`, `Node`) to pure handle
 * types so there is now a single API surface.
 *
 * `SCP` is a NAPI-only feature — constructing it in a WASM/browser
 * environment throws `ValidationError` (`SCP-VALID-7005`).
 */
export declare class SCP {
  /** Constructs a fresh `SCP` instance (NAPI-only). */
  constructor(options?: ScpOptions);
  /**
   * Monotonic u64 id as a base-10 string (u64 exceeds JS safe-integer
   * range). Unique per `new SCP()`.
   */
  readonly instanceId: string;
  suspend(): void;
  resume(): Promise<void>;
  /**
   * @param timeoutSecs Maximum seconds to wait for in-flight tasks.
   *   Defaults to 5.
   */
  shutdown(timeoutSecs?: number): Promise<void>;
}
