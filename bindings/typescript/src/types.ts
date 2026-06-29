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
  /** Maximum cross-context chain depth (ADR-043). Default 8, range [1, 255]. */
  readonly maxChainDepth?: number;
  /** Maximum context nesting depth (§5.13.8). Omit for unbounded. */
  readonly maxNestingDepth?: number;
  /** Per-caller session cap (§6.2.1). Default 1000. */
  readonly sessionCap?: number;
  /**
   * Consequence rules for automated governance enforcement (ADR-017, §9.3, #1531).
   *
   * Each rule is a typed {@link ConsequenceRule} discriminated union (no
   * stringly-typed JSON). The SDK serializes the array to JSON at the bridge
   * boundary; bridge implementations parse and validate before forwarding to
   * `ContextManager`.
   */
  readonly consequenceRules?: readonly ConsequenceRule[];
  /**
   * Per-context consequence config governing which enforcement severities
   * the rules may reference (ADR-017, #1531).
   *
   * When omitted, the protocol default applies
   * (`allow_automatic_access_revocation = false`). Must opt in explicitly to
   * permit `RevokeAccess` rules.
   */
  readonly consequenceConfig?: ConsequenceConfig;
}

// ---------------------------------------------------------------------------
// Consequence rules (ADR-017, §9.3, #1531)
// ---------------------------------------------------------------------------

/**
 * A registered tool capability (`tool:invoke:<id>`) within a context.
 *
 * Mirrors the `Capability::ToolInvoke(ToolId)` newtype. Carries the tool ID
 * (an opaque string) and serializes as `{"ToolInvoke": "id"}` to match the
 * Rust serde tagging.
 */
export interface ToolInvokeCapability {
  /** Discriminant. */
  readonly kind: "ToolInvoke";
  /** Opaque tool identifier matching a registered ToolDefinition. */
  readonly toolId: string;
}

/**
 * A custom (context-specific) capability not enumerated by the protocol.
 *
 * Mirrors the `Capability::Custom(String)` newtype variant. Serializes as
 * `{"Custom": "name"}` to match the Rust serde tagging.
 */
export interface CustomCapability {
  /** Discriminant. */
  readonly kind: "Custom";
  /** Custom capability name. */
  readonly name: string;
}

/**
 * The unit-variant capabilities defined by the protocol (no payload).
 *
 * Each member matches a `scp_protocol::context::roles::Capability` unit
 * variant. The string values use the canonical PascalCase variant names —
 * NOT the colon-separated wire names like `"messages:read"` — because the
 * Rust enum serializes via default serde, which preserves variant names.
 */
export type UnitCapability =
  | "MessagesRead"
  | "MessagesWrite"
  | "ToolInvokeAll"
  | "ToolRegister"
  | "MemberInvite"
  | "MemberRemove"
  | "RoleAssign"
  | "GovernancePropose"
  | "GovernanceVote"
  | "ContextClose"
  | "ChildContextCreate"
  | "ToolInterface"
  | "Bridging"
  | "MediaVoice"
  | "MediaVideo"
  | "MediaScreenShare"
  | "MemberBan"
  | "MetadataEdit";

/**
 * Typed capability matching `scp_protocol::context::roles::Capability`.
 *
 * Either a unit-variant string or an object discriminated by `kind` for
 * payload-bearing variants (`ToolInvoke`, `Custom`). The SDK encoder converts
 * each variant to the matching Rust serde JSON shape:
 *
 * - `"MessagesRead"` → `"MessagesRead"`
 * - `{ kind: "ToolInvoke", toolId: "calculator" }` → `{"ToolInvoke": "calculator"}`
 * - `{ kind: "Custom", name: "foo" }` → `{"Custom": "foo"}`
 */
export type ConsequenceCapability = UnitCapability | ToolInvokeCapability | CustomCapability;

/**
 * The condition that triggers a consequence rule (ADR-017 §6).
 *
 * Mirrors `scp_protocol::trust::consequence::ConsequenceTrigger`. Three
 * unit variants count event-log entries; `Custom` carries a string key.
 *
 * Variant names match the Rust enum exactly. Renaming any variant breaks
 * wire compatibility — the {@link CONSEQUENCE_TRIGGER_VARIANTS} pin freezes
 * the set so future renames produce a type error here.
 */
export type ConsequenceTrigger =
  | { readonly kind: "MessageVelocity" }
  | { readonly kind: "ToolRateExceeded" }
  | { readonly kind: "WarningCount" }
  | { readonly kind: "Custom"; readonly key: string };

/**
 * Frozen set of {@link ConsequenceTrigger} variant names. Imported by the
 * SDK round-trip tests so renaming a variant trips a compile error.
 */
export const CONSEQUENCE_TRIGGER_VARIANTS = [
  "MessageVelocity",
  "ToolRateExceeded",
  "WarningCount",
  "Custom",
] as const satisfies readonly ConsequenceTrigger["kind"][];

/**
 * Read/Write/Both scope for `RevokeAccess` enforcement.
 *
 * Mirrors `scp_protocol::context::governance::AccessScope`.
 */
export type AccessScope = "Read" | "Write" | "Both";

/**
 * Unified enforcement severity for consequence rules and governance actions
 * (ADR-017, ADR-031).
 *
 * Mirrors `scp_protocol::trust::consequence::EnforcementSeverity`. Four tiers
 * ordered from least to most severe:
 *
 * 1. `SuspendCapability` — application-level block on a specific capability set
 * 2. `SuspendAccess` — application-level block on all member capabilities
 * 3. `RevokeAccess` — cryptographic revocation (forward-only)
 * 4. `RemoveMember` — MLS group ejection (governance-only)
 *
 * Consequence rules may only reference `SuspendCapability` and `SuspendAccess`
 * by default. `RevokeAccess` requires
 * `consequenceConfig.allowAutomaticAccessRevocation = true`. `RemoveMember` is
 * never allowed in a consequence rule.
 */
export type EnforcementSeverity =
  | { readonly kind: "SuspendCapability"; readonly capabilities: readonly ConsequenceCapability[] }
  | { readonly kind: "SuspendAccess" }
  | { readonly kind: "RevokeAccess"; readonly did: string; readonly access: AccessScope }
  | { readonly kind: "RemoveMember"; readonly did: string; readonly reason?: string };

/**
 * Frozen set of {@link EnforcementSeverity} variant names. Imported by the
 * SDK round-trip tests so renaming a variant trips a compile error.
 */
export const ENFORCEMENT_SEVERITY_VARIANTS = [
  "SuspendCapability",
  "SuspendAccess",
  "RevokeAccess",
  "RemoveMember",
] as const satisfies readonly EnforcementSeverity["kind"][];

/**
 * The action taken when a {@link ConsequenceRule} fires.
 *
 * Mirrors `scp_protocol::trust::consequence::ConsequenceAction`. Two
 * families:
 *
 * - `Enforcement` — apply an {@link EnforcementSeverity} tier to the subject.
 * - `AssignRole` — replace the subject's role.
 */
export type ConsequenceAction =
  | { readonly kind: "Enforcement"; readonly severity: EnforcementSeverity }
  | { readonly kind: "AssignRole"; readonly toRole: string };

/**
 * Frozen set of {@link ConsequenceAction} variant names. Imported by the
 * SDK round-trip tests so renaming a variant trips a compile error.
 */
export const CONSEQUENCE_ACTION_VARIANTS = [
  "Enforcement",
  "AssignRole",
] as const satisfies readonly ConsequenceAction["kind"][];

/**
 * A declared consequence rule (ADR-017 §1).
 *
 * Mirrors `scp_protocol::trust::consequence::ConsequenceRule`. Each rule
 * specifies a trigger condition, an enforcement action, a numeric threshold,
 * and a time window (in seconds) for counting events.
 *
 * Rules are visible to all participants before they join — the opt-in
 * contract for consequences. The SDK serializes the array to the wire JSON
 * shape expected by the Rust bridge.
 */
export interface ConsequenceRule {
  /** Trigger condition discriminated by `kind`. */
  readonly trigger: ConsequenceTrigger;
  /** Enforcement action discriminated by `kind`. */
  readonly action: ConsequenceAction;
  /**
   * Threshold count: when matching events within the time window meet or
   * exceed this value, the consequence fires. Must be > 0.
   */
  readonly threshold: number;
  /** Time window in seconds. Only events in `[now - windowSecs, now]` count. */
  readonly windowSecs: number;
}

/**
 * Per-context configuration governing which enforcement severities
 * consequence rules may reference (ADR-017, #1531).
 *
 * Mirrors `scp_protocol::context::params::ConsequenceConfig`. Defaults to
 * `allowAutomaticAccessRevocation = false`: contexts must explicitly opt in
 * to permit `RevokeAccess` rules. `RemoveMember` is never allowed in
 * consequence rules regardless of this flag.
 */
export interface ConsequenceConfig {
  /**
   * If `true`, consequence rules may reference
   * `EnforcementSeverity.RevokeAccess` — i.e., automatic cryptographic
   * revocation of a member's access keys. Defaults to `false`.
   */
  readonly allowAutomaticAccessRevocation: boolean;
}

/**
 * Encodes a typed {@link ConsequenceRule} array to the JSON wire shape
 * expected by the Rust bridge.
 *
 * Public for SDK call sites that need to forward pre-serialized rules
 * (e.g. invitation evaluation) and for tests that pin the discriminated
 * union shapes against the Rust serde format.
 *
 * @throws {Error} If a variant has an unknown `kind`.
 */
export function encodeConsequenceRules(rules: readonly ConsequenceRule[]): string {
  return JSON.stringify(rules.map(encodeConsequenceRule));
}

/**
 * Encodes a typed {@link ConsequenceConfig} to the JSON wire shape expected
 * by the Rust bridge. Field names are snake_cased to match
 * `serde_json::to_string(&ConsequenceConfig)`.
 */
export function encodeConsequenceConfig(config: ConsequenceConfig): string {
  return JSON.stringify({
    allow_automatic_access_revocation: config.allowAutomaticAccessRevocation,
  });
}

function encodeConsequenceRule(rule: ConsequenceRule): Record<string, unknown> {
  return {
    trigger: encodeConsequenceTrigger(rule.trigger),
    action: encodeConsequenceAction(rule.action),
    threshold: rule.threshold,
    window: { secs: rule.windowSecs, nanos: 0 },
  };
}

function encodeConsequenceTrigger(trigger: ConsequenceTrigger): unknown {
  switch (trigger.kind) {
    case "MessageVelocity":
    case "ToolRateExceeded":
    case "WarningCount":
      return trigger.kind;
    case "Custom":
      return { Custom: trigger.key };
    default: {
      const exhaustive: never = trigger;
      throw new Error(`unknown ConsequenceTrigger kind: ${JSON.stringify(exhaustive)}`);
    }
  }
}

function encodeConsequenceAction(action: ConsequenceAction): unknown {
  switch (action.kind) {
    case "Enforcement":
      return { Enforcement: encodeEnforcementSeverity(action.severity) };
    case "AssignRole":
      return { AssignRole: { to_role: action.toRole } };
    default: {
      const exhaustive: never = action;
      throw new Error(`unknown ConsequenceAction kind: ${JSON.stringify(exhaustive)}`);
    }
  }
}

function encodeEnforcementSeverity(severity: EnforcementSeverity): unknown {
  switch (severity.kind) {
    case "SuspendAccess":
      return "SuspendAccess";
    case "SuspendCapability":
      return {
        SuspendCapability: {
          capabilities: severity.capabilities.map(encodeConsequenceCapability),
        },
      };
    case "RevokeAccess":
      return {
        RevokeAccess: {
          did: severity.did,
          access: severity.access,
        },
      };
    case "RemoveMember":
      return {
        RemoveMember: {
          did: severity.did,
          reason: severity.reason ?? null,
        },
      };
    default: {
      const exhaustive: never = severity;
      throw new Error(`unknown EnforcementSeverity kind: ${JSON.stringify(exhaustive)}`);
    }
  }
}

function encodeConsequenceCapability(capability: ConsequenceCapability): unknown {
  if (typeof capability === "string") {
    return capability;
  }
  if (capability.kind === "ToolInvoke") {
    return { ToolInvoke: capability.toolId };
  }
  if (capability.kind === "Custom") {
    return { Custom: capability.name };
  }
  const exhaustive: never = capability;
  throw new Error(`unknown ConsequenceCapability variant: ${JSON.stringify(exhaustive)}`);
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

/**
 * An asset to publish to a broadcast context (SCP-290, spec section 18.11.8).
 *
 * Typed interface to prevent positional transposition of path/contentType/body.
 */
export interface AssetEntry {
  /** Validated URL path (e.g., `/index.html`, `/styles.css`). */
  readonly path: string;
  /** Validated MIME type (e.g., `text/html`, `text/css`). */
  readonly contentType: string;
  /** Raw content bytes. */
  readonly body: Uint8Array;
}

/**
 * Result of publishing an asset to a broadcast context (SCP-290).
 *
 * Returned by `broadcastPublishAsset` and `broadcastPublishAssets`.
 */
export interface PublishResult {
  /** Hex-encoded SHA-256 of the serialized broadcast envelope. */
  readonly blobId: string;
  /** Hex-encoded SHA-256 of the asset body. */
  readonly etag: string;
  /** The deploy ID for this asset (auto-generated or caller-provided). */
  readonly deployId: string;
}

/**
 * Result of publishing multiple assets to a broadcast context (SCP-292).
 *
 * Returned by \`broadcastPublishAssets\`.
 */
export interface BatchPublishResult {
  /** Per-asset publish results. */
  readonly results: PublishResult[];
  /** The shared deploy ID for this batch. */
  readonly deployId: string;
}

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
  | "MemberSuspended"
  | "AccessRevoked"
  | "AccessRestored"
  | "ContentKeysRotated"
  | "GovernanceReconfigured"
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
  /** Event type (e.g., `"ContextCreated"`, `"MemberJoined"`, `"GovernanceActionExecuted"`). */
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

/**
 * A consistency checkpoint from the event log.
 *
 * The NAPI (Node/Bun) runtime signs the canonical checkpoint payload
 * in-process with the identity's `#active` Ed25519 key, so a checkpoint
 * always carries a hex `signature` over the canonical checkpoint hash.
 * Identities are Rust-custodied; the private key never crosses the FFI
 * boundary (ADR-006). The field set matches the flat signed checkpoint
 * returned by the Python (`SignedCheckpoint`), Swift, and Kotlin SDKs.
 */
export interface Checkpoint {
  /** The context this checkpoint belongs to. */
  readonly contextId: string;
  /** The DID of the member who generated this checkpoint. */
  readonly senderDid: string;
  /** The Merkle root hash at checkpoint time, as a hex string. */
  readonly merkleRoot: string;
  /** The number of events in the log at checkpoint time. */
  readonly eventCount: number;
  /** Current MLS epoch. `undefined` for Broadcast contexts. */
  readonly epoch?: number | undefined;
  /** Timestamp of the checkpoint (seconds since epoch). */
  readonly timestamp: number;
  /** Ed25519 signature over the canonical checkpoint hash (hex, 64 bytes / 128 chars). */
  readonly signature: string;
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
  /**
   * Whether `toolInvocationCount` is anchored in the canonical Merkle log.
   *
   * `false` until ADR-051 makes `ToolInvoked` a convergent leaf: the count is
   * computed from per-author local events, not the Merkle log (§7.3.2; ADR-011
   * amendment exclusion taxonomy §2). Consumers MUST NOT treat the count as
   * Merkle-proven while this is `false`.
   */
  readonly toolInvocationCountAnchored: boolean;
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
  | { readonly kind: "HandleRegistryVerified" }
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
  | "HandleRegistry"
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
  /** Human-readable source identifier (context name, domain, platform). */
  readonly source: string;
  /** Context ID (hex), present only for the `HandleRegistry` layer. */
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
// Broadcast Site Configuration
// ---------------------------------------------------------------------------

/**
 * Node-local site configuration for broadcast projection (spec section 18.11.12).
 *
 * Passed to `enableSiteProjection` to configure path-based HTTP serving of
 * broadcast content. NOT part of governance -- deployment concern only.
 *
 * Mirrors `scp_node::projection::SiteConfig`.
 */
export interface SiteConfig {
  /** Virtual host hostname (e.g., `"mysite.example.com"`). RFC 1123 validated. */
  readonly hostname: string;
  /** Default path for directory requests (default: `"/index.html"`). */
  readonly indexPath?: string;
  /** Maximum assets per deploy (default: 10,000). */
  readonly maxAssetsPerDeploy?: number;
  /** Maximum total deploy size in bytes (default: 536,870,912 = 512 MiB). */
  readonly maxDeploySizeBytes?: number;
  /** Number of deploys to retain (default: 2, max 8). */
  readonly deployRetentionCount?: number;
  /** Optional CSP override. Validated: no `unsafe-eval`, `unsafe-inline`, `unsafe-hashes`, bare `*`, `data:`, `blob:`. */
  readonly cspOverride?: string;
}

/**
 * Validates a {@link SiteConfig} at the SDK layer before FFI.
 *
 * Checks:
 * - `hostname` is non-empty, valid RFC 1123 DNS name (max 253 chars, labels
 *   max 63 chars, alphanumeric + hyphens, no leading/trailing hyphens).
 * - `deployRetentionCount` is 1-8 (if provided).
 * - `cspOverride` does not contain `unsafe-eval`, `unsafe-inline`,
 *   `unsafe-hashes`, bare `*`, `data:`, or `blob:` (if provided).
 *
 * @throws {Error} If any field fails validation.
 */
export function validateSiteConfig(config: SiteConfig): void {
  validateHostname(config.hostname);
  if (config.maxAssetsPerDeploy !== undefined) {
    if (!Number.isInteger(config.maxAssetsPerDeploy) || config.maxAssetsPerDeploy < 1) {
      throw new Error(
        `maxAssetsPerDeploy must be a positive integer, got ${config.maxAssetsPerDeploy}`,
      );
    }
  }
  if (config.maxDeploySizeBytes !== undefined) {
    if (!Number.isInteger(config.maxDeploySizeBytes) || config.maxDeploySizeBytes < 1) {
      throw new Error(
        `maxDeploySizeBytes must be a positive integer, got ${config.maxDeploySizeBytes}`,
      );
    }
  }
  if (config.deployRetentionCount !== undefined) {
    if (
      !Number.isInteger(config.deployRetentionCount) ||
      config.deployRetentionCount < 1 ||
      config.deployRetentionCount > 8
    ) {
      throw new Error(
        `deployRetentionCount must be an integer between 1 and 8, got ${config.deployRetentionCount}`,
      );
    }
  }
  if (config.cspOverride !== undefined) {
    validateCsp(config.cspOverride);
  }
}

/**
 * Validates a hostname per RFC 1123.
 *
 * @throws {Error} If the hostname is invalid.
 */
function validateHostname(hostname: string): void {
  if (hostname.length === 0) {
    throw new Error("hostname must not be empty");
  }
  if (hostname.length > 253) {
    throw new Error("hostname exceeds 253 characters");
  }
  for (const label of hostname.split(".")) {
    if (label.length === 0 || label.length > 63) {
      throw new Error(`invalid hostname label: '${label}'`);
    }
    if (!/^[a-zA-Z0-9-]+$/.test(label)) {
      throw new Error(`hostname label contains invalid characters: '${label}'`);
    }
    if (label.startsWith("-") || label.endsWith("-")) {
      throw new Error(`hostname label starts or ends with '-': '${label}'`);
    }
  }
}

/**
 * Validates an admission policy string before FFI.
 *
 * Accepts both casings (`"Open"`/`"open"`, `"Gated"`/`"gated"`) because
 * the Rust bridge normalizes via `.to_lowercase()`.
 *
 * @throws {Error} If admission is not a valid policy.
 */
export function validateAdmission(admission: string): void {
  const lower = admission.toLowerCase();
  if (lower !== "open" && lower !== "gated") {
    throw new Error(`admission must be "Open" or "Gated" (case-insensitive), got "${admission}"`);
  }
}

/**
 * Validates a broadcast key hex string before FFI.
 *
 * Must be exactly 64 hex characters (32 bytes AES-256 key).
 *
 * @throws {Error} If the string is not a valid 64-char hex string.
 */
export function validateBroadcastKeyHex(broadcastKeyHex: string): void {
  if (!/^[0-9a-fA-F]{64}$/.test(broadcastKeyHex)) {
    throw new Error("broadcastKeyHex must be exactly 64 hex characters (32 bytes)");
  }
}

/**
 * Validates a CSP override string.
 *
 * Rejects `unsafe-eval`, `unsafe-inline`, `unsafe-hashes`, bare `*`,
 * `data:`, and `blob:` as sources.
 *
 * @throws {Error} If the CSP is invalid.
 */
function validateCsp(csp: string): void {
  const FORBIDDEN_KEYWORDS = ["unsafe-eval", "unsafe-inline", "unsafe-hashes"];
  const lower = csp.toLowerCase();
  for (const keyword of FORBIDDEN_KEYWORDS) {
    if (lower.includes(keyword)) {
      throw new Error(`CSP must not contain '${keyword}'`);
    }
  }
  for (const token of lower.split(/\s+/)) {
    if (token === "*") {
      throw new Error("CSP must not contain bare wildcard '*'");
    }
    if (token === "data:") {
      throw new Error("CSP must not contain 'data:' source");
    }
    if (token === "blob:") {
      throw new Error("CSP must not contain 'blob:' source");
    }
  }
}

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
