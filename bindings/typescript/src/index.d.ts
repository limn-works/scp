/**
 * @scp/sdk -- Shareable Context Protocol SDK for TypeScript
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

export declare class PermissionError extends ScpError {
  readonly name: "PermissionError";
}

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

export interface ToolDefinition {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Record<string, unknown>;
  readonly outputSchema: Record<string, unknown>;
  readonly operator: Identity | string;
  readonly testVectors?: TestVector[];
  readonly implementationHash?: Uint8Array;
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
  readonly governance?: "single_admin";
}

export interface TrustEvaluation {
  readonly targetDid: string;
  readonly score: number;
  readonly factors: Record<string, number>;
}

export interface DIDDocument {
  readonly id: string;
  readonly verificationMethods: VerificationMethod[];
  readonly services: Service[];
  readonly alsoKnownAs: string[];
  readonly authentication: string[];
  readonly assertionMethods: string[];
}

export interface VerificationMethod {
  readonly id: string;
  readonly type: string;
  readonly controller: string;
  readonly publicKeyMultibase: string;
}

export interface Service {
  readonly id: string;
  readonly type: string;
  readonly serviceEndpoint: string;
}

export interface UcanToken {
  readonly tokenId: string;
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

// -- Identity -----------------------------------------------------------------

export declare class Identity {
  readonly did: string;
  readonly custodyType: string;

  static create(options?: { custody?: string }): Promise<Identity>;
  static load(did: string): Promise<Identity>;
  static resolve(did: string): Promise<DIDDocument>;

  rotateKey(): Promise<Identity>;
}

// -- Context ------------------------------------------------------------------

export declare class Context {
  readonly contextId: string;
  readonly state: string;

  static create(
    identity: Identity,
    params: ContextParams,
  ): Promise<Context>;

  static join(
    identity: Identity,
    contextId: string,
  ): Promise<Context>;

  send(payload: Uint8Array | string): Promise<void>;
  receive(): AsyncIterable<Message>;
  invokeTool(
    toolId: string,
    input: Record<string, unknown>,
  ): Promise<ToolResult>;
  leave(): Promise<void>;
  close(): Promise<void>;
}

// -- UCAN ---------------------------------------------------------------------

export declare function mint(options: {
  issuer: Identity;
  audience: string;
  capabilities: string[];
  contextId: string;
}): Promise<UcanToken>;

export declare function validate(
  contextId: string,
  token: string,
  capability: string,
): Promise<void>;

export declare function revoke(
  contextId: string,
  tokenId: string,
): Promise<void>;

export declare function delegate(options: {
  issuer: Identity;
  audience: string;
  parentToken: string;
  capabilities: string[];
}): Promise<UcanToken>;

// -- Trust --------------------------------------------------------------------

export declare function evaluateTrust(
  context: Context,
  targetDid: string,
): Promise<TrustEvaluation>;

// -- Event Log ----------------------------------------------------------------

export declare class EventLog {
  query(filter?: {
    eventType?: string;
    actorDid?: string;
    afterSequence?: number;
    beforeSequence?: number;
    limit?: number;
  }): Promise<EventLogEvent[]>;

  verify(claim: {
    type: string;
    leafIndex: number;
    eventHash: string;
  }): Promise<EventLogProof>;
}

// -- Transport ----------------------------------------------------------------

export declare function connect(config: TransportConfig): Promise<void>;

// -- MCP ----------------------------------------------------------------------

export declare function serveMcp(
  context: Context,
  options?: { transport?: "stdio" | "ws"; port?: number },
): Promise<McpServer>;

export declare class McpServer {
  stop(): Promise<void>;
}

export declare class McpClient {
  static connect(url: string): Promise<McpClient>;
  listTools(): Promise<ToolDefinition[]>;
  callTool(
    name: string,
    input: Record<string, unknown>,
  ): Promise<Record<string, unknown>>;
  close(): Promise<void>;
}
