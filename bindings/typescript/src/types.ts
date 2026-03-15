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
 * - `"Gated"` — subscription requires a valid `messages:read` UCAN.
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
  /** Optional per-invocation cost metadata (spec section 5.4.1). */
  readonly cost?: ToolCost;
}

/** Per-invocation cost metadata for a tool (spec section 5.4.1). */
export interface ToolCost {
  /** Cost per invocation in the smallest currency unit. */
  readonly amount: number;
  /** ISO 4217 or protocol-defined currency code. */
  readonly currency: string;
  /** DID of the payment recipient. May differ from the tool operator. */
  readonly payee: string;
  /** Optional pricing formula identifier for dynamic pricing (spec section 19.4). */
  readonly costFormula?: string;
}

/** A test vector for tool verification. */
export interface TestVector {
  /** Test input as a JSON object. */
  readonly input: Readonly<Record<string, unknown>>;
  /** Expected output as a JSON object. */
  readonly expectedOutput: Readonly<Record<string, unknown>>;
  /** Human-readable description of what this test vector verifies. */
  readonly description: string;
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

/** Result of creating a stateful tool session (spec section 6.2.1). */
export interface ToolSessionResult {
  /** The unique session ID (UUID). */
  readonly sessionId: string;
}

/** Result of invoking a tool within a stateful session, with provenance metadata (spec section 6.2.1). */
export interface ToolSessionInvokeResult {
  /** The serialized output from the tool invocation (JSON string). */
  readonly output: string;
  /** The session ID this invocation was executed within. */
  readonly sessionId: string;
  /** The context ID in which the tool was invoked. */
  readonly contextId: string;
  /** The DID of the invoker. */
  readonly invokerDid: string;
  /** Unix timestamp (milliseconds since epoch) of the invocation. */
  readonly timestamp: number;
}

/** Result of a cross-context tool invocation (spec section 6.2). */
export interface CrossContextInvocationResult {
  /** The serialized output from the tool invocation (JSON string). */
  readonly output: string;
  /** The source context ID. */
  readonly sourceContextId: string;
  /** The target context ID. */
  readonly targetContextId: string;
  /** The DID of the invoker. */
  readonly invokerDid: string;
  /** Chain depth of the cross-context invocation. */
  readonly chainDepth: number;
  /** Unix timestamp (milliseconds since epoch) of the invocation. */
  readonly timestamp: number;
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
// Participation (spec §7.3.2.1, SCP-BA-004)
// ---------------------------------------------------------------------------

/**
 * Which category of participation fact to evaluate for admission.
 *
 * Each variant corresponds to one of the 7 fact categories in a
 * `ParticipationProfile`. See §7.3.2.1.
 *
 * Values match the Rust `ParticipationFact` enum in `scp-core`.
 */
export type ParticipationFact =
  | "ParticipationDuration"
  | "GovernanceActionsAgainst"
  | "GovernanceActionsBy"
  | "ToolInvocationCount"
  | "ContextCreationCount"
  | "RoleProgressionCount"
  | "AttestationCount";

/**
 * Comparison operator and value for participation admission thresholds.
 *
 * Used in `RequireParticipation` to specify the comparison a fact value
 * must satisfy. See §7.3.2.1.
 *
 * Serialization matches the Rust `ParticipationThreshold` enum:
 * `{ "GreaterThan": 50 }`, `{ "AtLeast": 100 }`, etc.
 */
export type ParticipationThreshold =
  | { readonly GreaterThan: number }
  | { readonly LessThan: number }
  | { readonly AtLeast: number }
  | { readonly AtMost: number }
  | { readonly Equals: number };

/**
 * A context-hosted participation profile attesting to a member's
 * verifiable participation facts.
 *
 * Produced by contexts for opted-in members. The profile is signed by a
 * context-specific Ed25519 key (derived with domain separation) so that
 * verifiers cannot correlate which contexts share a signer.
 *
 * See §7.3.2.1.
 */
export interface ParticipationProfile {
  /** DID of the member this profile is about. */
  readonly subjectDid: string;
  /** Total seconds of context participation. */
  readonly participationDurationSecs: number;
  /** Count of governance actions taken against this identity. */
  readonly governanceActionsAgainst: number;
  /** Count of governance actions initiated by this identity. */
  readonly governanceActionsBy: number;
  /** Total tool invocations across all tool types. */
  readonly toolInvocationCount: number;
  /** Number of contexts created. */
  readonly contextCreationCount: number;
  /** Number of role transitions. */
  readonly roleProgressionCount: number;
  /** Number of attestation events. */
  readonly attestationCount: number;
  /** Unix timestamp (seconds) of the last update to this profile. */
  readonly updatedAt: number;
  /** Merkle root of the context's event log at profile computation time (32 bytes). */
  readonly eventLogRoot: readonly number[];
  /** Context-specific Ed25519 public key used to sign this profile (32 bytes). */
  readonly signerPublicKey: readonly number[];
  /** Ed25519 signature over all fields except this one (64 bytes). */
  readonly signature: readonly number[];
}

/**
 * A participation admission requirement declared by a context.
 *
 * Contexts include one or more `RequireParticipation` entries in their
 * `ContextParams` admission requirements. Each entry specifies a
 * participation fact, a threshold, a freshness requirement, and a minimum
 * number of independent source contexts. See §7.3.2.1.
 */
export interface RequireParticipation {
  /** Which participation category to evaluate. */
  readonly fact: ParticipationFact;
  /** Comparison operator and value. */
  readonly threshold: ParticipationThreshold;
  /** Maximum age in seconds for the profile's `updatedAt` timestamp. */
  readonly maxAgeSecs: number;
  /** Minimum number of independent source contexts (distinct signer keys). */
  readonly minContexts: number;
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
 * Modeled as a discriminated union so that `MultiLayerCorroborated` can
 * carry its required `sources` field (§22.7).
 *
 * Variant names use PascalCase matching the spec definitions.
 *
 * See §22.7 Trust Levels.
 */
export type TrustLevel =
  | { readonly kind: "DirectExchange" }
  | { readonly kind: "LocalPetname" }
  | { readonly kind: "DomainVerified" }
  | { readonly kind: "AttestationVerified" }
  | { readonly kind: "DiscoveryContextVerified" }
  | { readonly kind: "MultiLayerCorroborated"; readonly sources: readonly ResolutionPath[] };

/**
 * The resolution layer that produced an address resolution result.
 *
 * Five values per §22.11.3 `ResolutionLayer`. Uses spec PascalCase.
 *
 * See §22.11.3 Address Resolution.
 */
export type ResolutionLayer =
  | "Petname"
  | "DiscoveryContext"
  | "Attestation"
  | "Domain"
  | "MultiLayerCorroborated";

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
