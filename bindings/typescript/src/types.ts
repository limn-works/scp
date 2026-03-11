/**
 * Shared type definitions for the SCP TypeScript SDK.
 *
 * These types are used across all SDK modules. They map to the protocol types
 * defined in `.docs/specs/` and `.docs/sketch.md`.
 *
 * See ADR-022 in `.docs/adrs/phase-4.md` and `.docs/scaffold/typescript.md`.
 */

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

/** Parameters for creating a new SCP context. */
export interface ContextParams {
  /** Capability ceiling — maximum capabilities available in this context. */
  readonly ceiling: readonly string[];
  /** Tool definitions to register at context creation. */
  readonly tools?: readonly ToolDefinition[];
  /** Role definitions: role name to capability list mapping. */
  readonly roles?: Readonly<Record<string, readonly string[]>>;
  /** Time-to-live in seconds. Omit for persistent contexts. */
  readonly ttl?: number;
  /** Memory scope for context data retention. */
  readonly memoryScope?: "ephemeral" | "summary" | "full";
  /** Governance model for the context. */
  readonly governance?: "single_admin" | "threshold" | "majority" | "unanimity";
  /** Context mode: encrypted MLS group or broadcast. */
  readonly mode?: "Encrypted" | "Broadcast";
  /** Ceiling policy: immutable or governed. */
  readonly ceilingPolicy?: "immutable" | "governed";
  /** Promotion policy for TTL-bound contexts. */
  readonly promotionPolicy?: "no_promotion" | "promotable";
  /** Economic policy for the context. */
  readonly economicPolicy?: string;
  /**
   * Minimum protocol version required to join (spec §13.4).
   * Encoded as `[major, minor]`, e.g., `[1, 0]` for SCP/1.0.
   * Omit for default SCP/1.0 baseline.
   */
  readonly minProtocolVersion?: readonly [number, number];
}

// ---------------------------------------------------------------------------
// Membership
// ---------------------------------------------------------------------------

/**
 * Role assigned to a member within a context (spec section 5.5).
 *
 * Mirrors `scp_core::context::roles::Role`.
 */
export type MemberRole = "Admin" | "Moderator" | "Member" | "Observer" | "Custom";

// ---------------------------------------------------------------------------
// Broadcast
// ---------------------------------------------------------------------------

/**
 * Admission policy for a broadcast context.
 *
 * - `"Open"` — any DID can subscribe without authorization.
 * - `"Gated"` — subscription requires a valid `messagesRead` UCAN.
 */
export type BroadcastAdmissionPolicy = "Open" | "Gated";

// ---------------------------------------------------------------------------
// Governance
// ---------------------------------------------------------------------------

/**
 * Result of executing a governance action (ADR-031).
 *
 * Each variant corresponds to one of the 28 governance action outcomes.
 */
export type GovernanceActionResult =
  | "MemberAdded"
  | "MemberRemoved"
  | "RoleChanged"
  | "ToolRegistered"
  | "ToolRemoved"
  | "CeilingModified"
  | "ContextClosed"
  | "TtlExtended"
  | "PruningPolicyModified"
  | "AdminTransferred"
  | "SignerAdded"
  | "SignerRemoved"
  | "ThresholdModified"
  | "ChildContextCreated"
  | "ToolInterfaceEstablished"
  | "MemberReset"
  | "ConflictResolved"
  | "ContextPromoted"
  | "ReadAccessRevoked"
  | "ReadAccessRestored"
  | "WriteAccessRevoked"
  | "WriteAccessRestored"
  | "ContentKeysRotated"
  | "GovernanceReconfigured"
  | "AuthorBlocked"
  | "SubscriberBanned"
  | "SubscriberUnbanned"
  | "Executed";

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/** A message received from an SCP context. */
export interface Message {
  /** DID of the message sender. */
  readonly senderDid: string;
  /** Message content (decoded from the transport payload). */
  readonly content: string | Uint8Array;
  /** Unix timestamp (seconds since epoch) when the message was created. */
  readonly timestamp: number;
  /** Monotonic sequence number within the context event log. */
  readonly sequence: number;
  /** Context ID this message belongs to. */
  readonly contextId: string;
  /** Optional provenance metadata. */
  readonly provenance?: Provenance;
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

/** Provenance metadata for a message or data artifact. */
export interface Provenance {
  /** DID of the original data source. */
  readonly sourceDid: string;
  /** Context ID where the data originated. */
  readonly sourceContextId: string;
  /** Cryptographic signature over the provenance chain. */
  readonly signature: Uint8Array;
  /** Chain depth — how many cross-context hops this data has traversed. */
  readonly chainDepth: number;
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/** A DID Document returned by identity resolution. */
export interface DIDDocument {
  /** The DID string this document describes. */
  readonly id: string;
  /** Verification methods in the document. */
  readonly verificationMethods: readonly VerificationMethod[];
  /** Authentication method references. */
  readonly authentication: readonly string[];
  /** Assertion method references. */
  readonly assertionMethods: readonly string[];
  /** Alternative DID identifiers for this subject. */
  readonly alsoKnownAs: readonly string[];
  /** Service endpoint entries. */
  readonly serviceEndpoints: readonly string[];
  /** Whether this document contains an `#agent` verification method (ADR-039). */
  readonly hasAgentKey: boolean;
  /** The agent key's public key as a multibase-encoded string, or `undefined` if no agent key exists (ADR-039). */
  readonly agentPublicKey?: string;
}

/** A verification method from a DID Document. */
export interface VerificationMethod {
  /** Verification method ID. */
  readonly id: string;
  /** Verification method type (e.g., `"Ed25519VerificationKey2020"`). */
  readonly type: string;
  /** Controller DID. */
  readonly controller: string;
  /** Public key in multibase encoding. */
  readonly publicKeyMultibase: string;
}

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

/** A UCAN capability definition. */
export interface Capability {
  /** The resource URI the capability grants access to. */
  readonly resource: string;
  /** The action allowed on the resource (e.g., `"read"`, `"write"`). */
  readonly action: string;
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

/** Definition of a tool that can be registered in a context. */
export interface ToolDefinition {
  /** Human-readable tool name. */
  readonly name: string;
  /** Tool description. */
  readonly description: string;
  /** JSON Schema for tool input. */
  readonly inputSchema: Readonly<Record<string, unknown>>;
  /** JSON Schema for tool output. */
  readonly outputSchema: Readonly<Record<string, unknown>>;
  /** DID of the tool operator (responsible party) or Identity reference. */
  readonly operator: string;
  /** Test vectors for integrity verification. */
  readonly testVectors?: readonly TestVector[];
  /** SHA-256 hash of the implementation binary. */
  readonly implementationHash?: Uint8Array;
}

/** A test vector for tool verification. */
export interface TestVector {
  /** Test input as a JSON object. */
  readonly input: Readonly<Record<string, unknown>>;
  /** Expected output as a JSON object. */
  readonly expectedOutput: Readonly<Record<string, unknown>>;
}

// ---------------------------------------------------------------------------
// Tool invocation
// ---------------------------------------------------------------------------

/** Result of verifying a tool against its test vectors. */
export interface ToolVerificationResult {
  /** The verified tool's ID. */
  readonly toolId: string;
  /** `true` if all test vectors passed. */
  readonly passed: boolean;
  /** Failure messages for vectors that did not pass. Empty on success. */
  readonly failures: readonly string[];
}

// ---------------------------------------------------------------------------
// UCAN
// ---------------------------------------------------------------------------

/** A UCAN token with metadata. */
export interface UcanToken {
  /** Unique token identifier. */
  readonly id: string;
  /** The encoded JWT string. */
  readonly encoded: string;
  /** Issuer DID. */
  readonly issuer: string;
  /** Audience DID. */
  readonly audience: string;
  /** Capability URIs granted by this token. */
  readonly capabilities: readonly string[];
  /** Expiry timestamp (seconds since epoch). `undefined` means no expiry. */
  readonly expiresAt?: number;
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/** Transport connection status. */
export interface TransportStatus {
  /** `true` if the transport is currently connected to a relay. */
  readonly connected: boolean;
  /** The relay URL if connected. `null` if disconnected. */
  readonly relayUrl: string | null;
  /** Round-trip latency in milliseconds. `null` if not measured. */
  readonly latencyMs: number | null;
}

/** Configuration for establishing a transport connection. */
export interface TransportConfig {
  /** The relay URL to connect to. Must use the `wss://` scheme. */
  readonly relayUrl: string;
}

// ---------------------------------------------------------------------------
// Event Log
// ---------------------------------------------------------------------------

/** A protocol event from the context event log. */
export interface Event {
  /** Event type (e.g., `"ContextCreated"`, `"MessageSent"`, `"ToolInvoked"`). */
  readonly eventType: string;
  /** DID of the actor who produced this event. */
  readonly actorDid: string;
  /** Unix timestamp (seconds since epoch). */
  readonly timestamp: number;
  /** Event-specific data. */
  readonly payload: Readonly<Record<string, unknown>>;
  /** Monotonic sequence number within the log. */
  readonly sequence: number;
}

/** A Merkle proof from the event log. */
export interface Proof {
  /** `true` if the claim was verified successfully. */
  readonly verified: boolean;
  /** Proof type: `"inclusion"` or `"absence"`. */
  readonly proofType: "inclusion" | "absence";
  /** Proof details (Merkle path or sorted neighbors). */
  readonly details: Readonly<Record<string, unknown>>;
}

/** A consistency checkpoint from the event log. */
export interface Checkpoint {
  /** The Merkle root hash as a hex string. */
  readonly root: string;
  /** The number of events in the log at checkpoint time. */
  readonly eventCount: number;
  /** Timestamp of the checkpoint (seconds since epoch). */
  readonly timestamp: number;
}

/** Filter parameters for event log queries. */
export interface EventFilter {
  /** Filter by event type. */
  readonly eventType?: string;
  /** Filter by actor DID. */
  readonly actorDid?: string;
  /** Return events with sequence greater than this value. */
  readonly afterSequence?: number;
  /** Return events with sequence less than this value. */
  readonly beforeSequence?: number;
  /** Maximum number of events to return. */
  readonly limit?: number;
}

/** A claim to verify against the event log. */
export interface EventClaim {
  /** Claim type: `"inclusion"` or `"absence"`. */
  readonly type: "inclusion" | "absence";
  /** Leaf index for inclusion proofs. */
  readonly leafIndex?: number;
  /** Event hash (hex) for absence proofs. */
  readonly eventHash?: string;
}

// ---------------------------------------------------------------------------
// Trust
// ---------------------------------------------------------------------------

/** Trust evaluation input for a participant. */
export interface TrustEvaluation {
  /** The subject DID being evaluated. */
  readonly subjectDid: string;
  /** The context ID in which trust is being evaluated. */
  readonly contextId: string;
  /** Behavioral record computed from the event log. */
  readonly behavioralRecord: BehavioralRecord;
  /** Attestations for the subject. */
  readonly attestations: readonly AttestationSummary[];
}

/** Behavioral record computed from a context event log. */
export interface BehavioralRecord {
  /** Number of messages sent or actions taken. */
  readonly participationCount: number;
  /** Duration of participation in seconds. */
  readonly participationDurationSeconds: number;
  /** Tool invocations keyed by tool ID. */
  readonly toolInvocations: Readonly<Record<string, number>>;
  /** Governance actions initiated by this participant. */
  readonly governanceActionsBy: number;
  /** Governance actions targeting this participant. */
  readonly governanceActionsAgainst: number;
}

/** Summary of an attestation. */
export interface AttestationSummary {
  /** Attestation type. */
  readonly type: string;
  /** Issuer DID. */
  readonly issuer: string;
  /** Whether the attestation is currently valid. */
  readonly valid: boolean;
  /** Whether the attestation has been revoked. */
  readonly revoked: boolean;
}

// ---------------------------------------------------------------------------
// Participation (spec section 9.3, SCP-BA-004)
// ---------------------------------------------------------------------------

/** A verified participation fact used in admission evaluation. */
export interface ParticipationFact {
  /** Type of participation fact (e.g., `"context_membership"`). */
  readonly factType: string;
  /** DID of the participant this fact pertains to. */
  readonly participantDid: string;
  /** Context ID where the fact was observed. */
  readonly contextId: string;
  /** Numeric value of the fact (e.g., participation count). */
  readonly value: number;
}

/** A threshold requirement for context admission. */
export interface ParticipationThreshold {
  /** The fact type this threshold applies to. */
  readonly factType: string;
  /** Minimum value required to satisfy the threshold. */
  readonly minimum: number;
  /** Optional maximum value constraint. */
  readonly maximum?: number;
}

/** A participant's aggregated participation profile. */
export interface ParticipationProfile {
  /** DID of the participant. */
  readonly participantDid: string;
  /** Verified participation facts. */
  readonly facts: readonly ParticipationFact[];
}

/** Participation-based admission requirement for a context. */
export interface RequireParticipation {
  /** Thresholds that must be met for admission. */
  readonly thresholds: readonly ParticipationThreshold[];
  /** Whether ALL thresholds must be met (true) or ANY (false). */
  readonly requireAll: boolean;
}

// ---------------------------------------------------------------------------
// Discovery — Address Resolution (§22.2.1, §22.7)
// ---------------------------------------------------------------------------

/**
 * Trust level indicating the strength and source of a handle-to-identifier
 * binding. Every resolution result carries a trust level.
 *
 * Trust levels are not strictly ordered -- their relative strength is
 * context-dependent. The SDK exposes them to consumers; consumers decide
 * what is sufficient.
 *
 * Modeled as a discriminated union so that `multi_layer_corroborated` can
 * carry its required `sources` field (§22.7).
 *
 * See §22.7 Trust Levels.
 */
export type TrustLevel =
  | { readonly kind: "unverified" }
  | { readonly kind: "petname_only" }
  | { readonly kind: "discovery_context_verified" }
  | { readonly kind: "domain_verified" }
  | { readonly kind: "attestation_verified" }
  | { readonly kind: "direct_exchange" }
  | { readonly kind: "multi_layer_corroborated"; readonly sources: readonly ResolutionPath[] };

/**
 * The resolution layer that produced an address resolution result.
 *
 * Exactly four values per §22.7 `ResolutionPath.layer`. Uses spec snake_case.
 *
 * See §22.7 Resolution Path.
 */
export type ResolutionLayer = "petname" | "discovery_context" | "attestation" | "domain";

/**
 * Structured metadata recording which layer resolved an address.
 *
 * This is provenance for the resolution itself: which layer, what source,
 * and when.
 *
 * See §22.7 Resolution Path.
 */
export interface ResolutionPath {
  /** The resolution layer that produced this result. */
  readonly layer: ResolutionLayer;
  /** Human-readable source identifier (discovery context name, domain, platform). */
  readonly source: string;
  /** Discovery context ID (hex), present only for the `DiscoveryContext` layer. */
  readonly sourceId: string | null;
  /** Unix timestamp (seconds) when resolution occurred. */
  readonly resolvedAt: number;
}

/**
 * A single resolution result from the addressing layer.
 *
 * An address may resolve to an identity (DID) or a context (context ID +
 * relay URLs). Each result carries a trust level and the resolution path
 * that produced it.
 *
 * See §22.2.1 Address Types.
 */
export type AddressResolution =
  | {
      /** Discriminant for identity resolution. */
      readonly type: "Identity";
      /** The resolved DID. */
      readonly did: string;
      /** Trust level of this resolution. */
      readonly trustLevel: TrustLevel;
      /** How this resolution was produced. */
      readonly resolutionPath: ResolutionPath;
    }
  | {
      /** Discriminant for context resolution. */
      readonly type: "Context";
      /** The context ID (hex-encoded). */
      readonly contextId: string;
      /** Relay URLs for reaching this context. */
      readonly relayUrls: readonly string[];
      /** The context mode, if known. */
      readonly mode: string | null;
      /** Trust level of this resolution. */
      readonly trustLevel: TrustLevel;
      /** How this resolution was produced. */
      readonly resolutionPath: ResolutionPath;
    };

// ---------------------------------------------------------------------------
// MCP
// ---------------------------------------------------------------------------

/** Configuration for an MCP server. */
export interface McpServerConfig {
  /** Tools to expose via MCP. */
  readonly tools: readonly ToolDefinition[];
  /** Port to listen on. */
  readonly port?: number;
  /** Host to bind to. */
  readonly host?: string;
}

/** Configuration for an MCP client. */
export interface McpClientConfig {
  /** URL of the MCP server to connect to. */
  readonly serverUrl: string;
}
