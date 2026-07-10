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
  /** Outlet definitions to register at context creation. */
  readonly outlets?: readonly OutletDefinition[];
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
 * A registered outlet capability (`tool:invoke:<id>`) within a context.
 *
 * Mirrors the `Capability::ToolInvoke(ToolId)` newtype. Carries the outlet ID
 * (an opaque string) and serializes as `{"ToolInvoke": "id"}` to match the
 * Rust serde tagging.
 */
export interface ToolInvokeCapability {
  /** Discriminant. */
  readonly kind: "ToolInvoke";
  /** Opaque outlet identifier matching a registered OutletDefinition. */
  readonly outletId: string;
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
 * payload-bearing variants (`OutletInvoke`, `Custom`). The SDK encoder converts
 * each variant to the matching Rust serde JSON shape:
 *
 * - `"MessagesRead"` → `"MessagesRead"`
 * - `{ kind: "ToolInvoke", outletId: "calculator" }` → `{"ToolInvoke": "calculator"}`
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
    return { ToolInvoke: capability.outletId };
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
// Invitations (ADR-049 Phase 2J / FFI-02 Option A)
// ---------------------------------------------------------------------------

/**
 * A sealed, signed context invitation bundle produced by
 * {@link SCP.inviteMember} on the creator side and consumed by
 * {@link SCP.contextJoinFromWelcome} on the joiner side.
 *
 * Flat named-field object mirroring the runtime wire type and the PyO3/UniFFI
 * reference bridges. `enc` is the RFC 9180 HPKE encapsulated key (32 bytes) and
 * `ciphertext` is the HPKE ciphertext (`ct = ciphertext || tag`) of the
 * serialized, signed `InvitationBundle` carrying the authoritative genesis
 * params + MLS Welcome. Both are opaque bytes — the joiner does not interpret
 * them; the native core opens the bundle and authenticates it.
 *
 * `contextId` / `creatorDid` are UNTRUSTED binding hints used only to rebuild
 * the HPKE `info`/`aad`; the joiner's authority derives from the signed bundle
 * after it is opened, never from these fields.
 */
export interface SealedInvitation {
  /** Binding hint: the context id the bundle was sealed for. */
  readonly contextId: string;
  /** Binding hint: the creator DID the bundle was sealed by. */
  readonly creatorDid: string;
  /** RFC 9180 HPKE encapsulated key (`enc`) — exactly 32 bytes. */
  readonly enc: Uint8Array;
  /** RFC 9180 HPKE ciphertext (`ct = ciphertext || tag`). */
  readonly ciphertext: Uint8Array;
}

/**
 * The outcome of {@link SCP.inviteMember}.
 *
 * `inviteMember` supports only `SingleAdmin` contexts today: the invite is
 * unilateral and yields a sealed `bundle` the caller (or transport) delivers to
 * the invitee. A voting-governed context THROWS instead (governed-context
 * invitations are not yet implemented) rather than surfacing here.
 *
 * `bundle` is directly usable as the `sealed` argument to
 * {@link SCP.contextJoinFromWelcome} — no re-assembly. Mirrors the runtime
 * `InviteMemberOutcome` and the PyO3/napi reference bridges' `{ bundle,
 * delivered }` projection.
 */
export interface InviteMemberOutcome {
  /**
   * The sealed invitation bundle — pass it directly to
   * {@link SCP.contextJoinFromWelcome}.
   */
  readonly bundle: SealedInvitation;
  /**
   * `true` if the native core published the sealed bundle to the invitee's
   * routing id; `false` if the caller must deliver `bundle`.
   */
  readonly delivered: boolean;
}

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
// Outlets
// ---------------------------------------------------------------------------

/** Definition of a outlet that can be registered in a context. */
export interface OutletDefinition {
  /** Human-readable outlet name. */
  readonly name: string;
  /** Outlet description. */
  readonly description: string;
  /** JSON Schema for outlet input. */
  readonly inputSchema: Readonly<Record<string, unknown>>;
  /** JSON Schema for outlet output. */
  readonly outputSchema: Readonly<Record<string, unknown>>;
  /** DID of the outlet operator (responsible party) or Identity reference. */
  readonly operator: string;
  /** Test vectors for integrity verification. */
  readonly testVectors?: readonly TestVector[];
  /** SHA-256 hash of the implementation binary. */
  readonly implementationHash?: Uint8Array;
  /** Optional per-invocation cost metadata (spec section 5.4.1). */
  readonly cost?: OutletCost;
}

/** Per-invocation cost metadata for a outlet (spec section 5.4.1). */
export interface OutletCost {
  /**
   * Cost per invocation in the smallest currency unit.
   *
   * A `bigint` so the full `u64` range round-trips exactly across the FFI
   * boundary — a JS `number` loses precision above 2^53 (ADR-060 native-integer
   * money surface).
   */
  readonly amount: bigint;
  /** ISO 4217 or protocol-defined currency code. */
  readonly currency: string;
  /** DID of the payment recipient. May differ from the outlet operator. */
  readonly payee: string;
  /** Optional pricing formula identifier for dynamic pricing (spec section 19.4). */
  readonly costFormula?: string;
}

/** A test vector for outlet verification. */
export interface TestVector {
  /** Test input as a JSON object. */
  readonly input: Readonly<Record<string, unknown>>;
  /** Expected output as a JSON object. */
  readonly expectedOutput: Readonly<Record<string, unknown>>;
  /** Human-readable description of what this test vector verifies. */
  readonly description: string;
}

// ---------------------------------------------------------------------------
// Outlet invocation
// ---------------------------------------------------------------------------

/** Result of verifying a outlet against its test vectors. */
export interface OutletVerificationResult {
  /** The verified outlet's ID. */
  readonly outletId: string;
  /** `true` if all test vectors passed. */
  readonly passed: boolean;
  /** Failure messages for vectors that did not pass. Empty on success. */
  readonly failures: readonly string[];
}

/** Result of creating a stateful outlet session (spec section 6.2.1). */
export interface OutletSessionResult {
  /** The unique session ID (UUID). */
  readonly sessionId: string;
}

/** Result of invoking a outlet within a stateful session, with provenance metadata (spec section 6.2.1). */
export interface OutletSessionInvokeResult {
  /** The serialized output from the outlet invocation (JSON string). */
  readonly output: string;
  /** The session ID this invocation was executed within. */
  readonly sessionId: string;
  /** The context ID in which the outlet was invoked. */
  readonly contextId: string;
  /** The DID of the invoker. */
  readonly invokerDid: string;
  /** Unix timestamp (milliseconds since epoch) of the invocation. */
  readonly timestamp: number;
}

/** Result of a cross-context outlet invocation (spec section 6.2). */
export interface CrossContextInvocationResult {
  /** The serialized output from the outlet invocation (JSON string). */
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

/**
 * The committed terminal of a §6.2.4 cross-context outlet-invocation saga
 * (ADR-049 §3a).
 *
 * Returned by `SCP.outletInvokeCrossContextSaga` only on a `Committed` terminal —
 * every non-committed terminal rejects with a typed saga error
 * (`SagaAbortedError`, `SagaNeedsRepairError`, or `SagaBusyError`) instead.
 *
 * `receipt` and `output` are a faithful pass-through of the bridge result:
 * surfaced exactly as the bridge returns them (`null` when the bridge omits
 * them — never synthesized). The bytes arrive as a native `Buffer`, a faithful
 * `Uint8Array` subtype, so a caller can verify the receipt signature and
 * recompute the output hash without re-serialization. See spec §6.2.4.
 */
export interface SagaResult {
  /** The durable saga identifier (supervisor-minted, never a caller input). */
  readonly sagaId: string;
  /** The target's signed `CrossContextOutletReceipt` bytes (JCS), or `null`. */
  readonly receipt: Uint8Array | null;
  /**
   * The captured outlet output bytes (the receipt's canonical `output_jcs`),
   * or `null`.
   */
  readonly output: Uint8Array | null;
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

/**
 * Layer 1 of the trust model: protocol-enforcement results (mechanical,
 * pass/fail). Each field is one stage of the 11-step ADR-016 UCAN
 * validation pipeline, surfaced by the read-only `ucanEvaluate` diagnostic
 * (spec §7.2.4, ADR-059 Decision 3).
 *
 * The six booleans cross the FFI already camelCased (the NAPI
 * `NapiCapabilityValidation` `#[napi(object)]`), so the SDK consumes them
 * directly and never reverse-engineers *which* check failed by parsing
 * human-readable error prose. All fields must be `true` for the subject to be
 * considered protocol-compliant.
 */
export interface CapabilityValidation {
  /** Step 1: UCAN tokens parse and have valid structure. */
  readonly tokensValid: boolean;
  /**
   * Steps 2-7: signatures, the full delegation chain, root issuer, audience,
   * key scope, Category-A enforcement, and attenuation verify. The
   * invoked-capability grant-match (step 6) is included ONLY when a challenge
   * capability is supplied; in the diagnostic's intrinsic-validity mode
   * (`evaluateTrust`'s mode — no challenge), step 6 is SKIPPED and this field
   * reflects only the structural checks, not grant-match.
   */
  readonly signaturesValid: boolean;
  /** Step 8: every granted capability is within the context's ceiling. */
  readonly withinCeiling: boolean;
  /** Step 9: nonce format, freshness, and uniqueness passed (probed read-only — the nonce is NOT recorded). */
  readonly nonceValid: boolean;
  /** Step 10: no token's revocation CID is on the revocation list. */
  readonly notRevoked: boolean;
  /** Step 11: `exp`/`nbf` time bounds are valid (within clock-skew tolerance). */
  readonly timeBoundsValid: boolean;
}

/**
 * `true` iff every per-stage check in `v` passed.
 *
 * The one obvious correct happy-path call: collapses the six per-stage booleans
 * of {@link CapabilityValidation} with a logical AND so consumers do not
 * hand-roll the conjunction (and cannot silently omit a field when a new stage
 * is added). A token is protocol-compliant only when all six are `true`.
 * Mirrors the Python `CapabilityValidation.all_valid` accessor.
 *
 * SECURITY: this is a DIAGNOSTIC, NEVER an authorization decision. It reports
 * that the UCAN tokens are *intrinsically well-formed and valid*; it does NOT
 * authorize any action. In intrinsic mode (capability = `null`/none — no
 * challenge capability supplied, the mode `evaluateTrust` uses), the
 * invoked-capability grant-match (step 6) is SKIPPED, so `allValid` (and
 * `signaturesValid` / `withinCeiling`) returning `true` does NOT assert that any
 * specific capability is granted. The diagnostic is also read-only: the nonce is
 * probed but NOT consumed, so the evaluated tokens remain replayable against the
 * enforcing path — another reason this is never an authorization decision. To
 * gate an action, pass the concrete capability to `ucanEvaluate` (which then
 * includes grant-match in `signaturesValid`) — or use the enforcing UCAN
 * validation path (which consumes the nonce). Treating `allValid` as "the agent
 * may do X" is a security error.
 */
export function allValid(v: CapabilityValidation): boolean {
  return (
    v.tokensValid &&
    v.signaturesValid &&
    v.withinCeiling &&
    v.nonceValid &&
    v.notRevoked &&
    v.timeBoundsValid
  );
}

/** Trust evaluation input for a participant. */
export interface TrustEvaluation {
  /** The subject DID being evaluated. */
  readonly subjectDid: string;
  /** The context ID in which trust is being evaluated. */
  readonly contextId: string;
  /**
   * Layer 1: protocol enforcement (mechanical pass/fail). The six per-stage
   * booleans are AND-combined across the evaluated capability-token set, so a
   * single token failing a stage makes that aggregate field `false`. When no
   * tokens were supplied every field is `false` (no stage was observed to
   * pass).
   */
  readonly capabilityValidation: CapabilityValidation;
  /**
   * Layer 2: behavioral record. The Rust-computed participation facts
   * (§7.3.2), RECEIVED from the core via {@link "./scp".SCP.participationRecord}
   * — never recomputed client-side, so every binding observes the identical
   * facts for the same context/subject.
   */
  readonly behavioralRecord: BehavioralRecord;
  /** Layer 3: attestations for the subject. */
  readonly attestations: readonly AttestationSummary[];
}

/**
 * The participation facts (§7.3.2) for a subject DID in a context.
 *
 * The scalar projection of scp-core's `ParticipationRecord`, computed ONCE in
 * the shared Rust core and surfaced through the NAPI `participationRecord` op
 * (`NapiParticipationRecord`). The SDK RECEIVES these facts rather than
 * re-aggregating event-log collections — eliminating cross-binding divergence
 * by construction. Mirrors the Python SDK `BehavioralRecord` shape and the
 * Rust `ParticipationFacts` 1:1.
 */
export interface BehavioralRecord {
  /** The DID whose participation is summarized. */
  readonly subjectDid: string;
  /** Total seconds of context participation (§7.3.2). */
  readonly participationDurationSecs: number;
  /** Count of governance actions taken against this identity. */
  readonly governanceActionsAgainst: number;
  /** Count of governance actions initiated by this identity. */
  readonly governanceActionsBy: number;
  /** Total outlet invocations across all outlet types. */
  readonly toolInvocationCount: number;
  /**
   * Whether {@link toolInvocationCount} is anchored in the canonical Merkle
   * log. `false` until ADR-051 makes `ToolInvoked` a convergent leaf
   * (§7.3.2; ADR-011 amendment exclusion taxonomy §2). Consumers MUST NOT
   * treat the count as Merkle-proven while this is `false`.
   */
  readonly toolInvocationCountAnchored: boolean;
  /** Number of contexts created by the subject (`ChildContextCreated`). */
  readonly contextCreationCount: number;
  /** Number of role transitions for the subject (`RoleAssigned`). */
  readonly roleProgressionCount: number;
  /**
   * Number of accessible, currently-valid credential-layer attestations
   * (§7.4) for the subject. A credential-layer fact, NOT a context-event
   * count and NOT Merkle-anchored — verifier-relative (two agents may
   * compute different counts from different accessible attestation sets).
   */
  readonly attestationCount: number;
  /**
   * Whether {@link attestationCount} is anchored in / verifiable against a
   * context Merkle root. Always `false`: it is a credential-layer,
   * verifier-relative fact (§7.4), never a context-event-log count (§7.3.2).
   * The parallel of {@link toolInvocationCountAnchored}; consumers MUST NOT
   * treat the count as Merkle-proven while this is `false`.
   */
  readonly attestationCountAnchored: boolean;
  /** Unix timestamp (seconds) when the record was computed. */
  readonly computedAt: number;
  /** Merkle root (hex) of the event log at computation time. */
  readonly eventLogRoot: string;
}

/**
 * Optional evidence supporting a {@link CachedAttestationEnvelope}.
 *
 * Developer-facing fields are camelCase, matching the Swift
 * `CachedAttestationEvidence` and Kotlin convention. {@link encodeCachedAttestations}
 * maps `evidenceType` to the serde-canonical `evidence_type` on the wire.
 */
export interface CachedAttestationEvidence {
  /** The evidence type discriminator. */
  readonly evidenceType: string;
  /** Type-specific evidence data. */
  readonly data: unknown;
}

/**
 * A `std::time::Duration` as the Rust core's serde representation
 * (`{ secs, nanos }`), used for a renewable attestation's renewal interval.
 * `secs`/`nanos` are the Rust field names and are identical on the wire.
 */
export interface CachedAttestationDuration {
  /** Whole seconds. */
  readonly secs: number;
  /** Sub-second nanoseconds. */
  readonly nanos: number;
}

/**
 * Attestation envelope (ADR-017 §7.4.1).
 *
 * Developer-facing fields are camelCase, matching the other typed SDK output
 * types ({@link BehavioralRecord}, {@link CapabilityValidation}) and the Swift
 * `CachedAttestationEnvelope` `CodingKeys` / Kotlin convention. The wire format
 * the Rust bridge deserializes is serde-canonical snake_case;
 * {@link encodeCachedAttestations} performs the camelCase → snake_case mapping
 * at the serialization boundary.
 */
export interface CachedAttestationEnvelope {
  /** Unique attestation identifier. */
  readonly id: string;
  /** Attestation type (serde tag, e.g. `"IdentityLink"`). */
  readonly attestationType: string;
  /** DID of the attestation issuer. */
  readonly issuer: string;
  /** DID of the attestation subject. */
  readonly subject: string;
  /** Type-specific claim data. */
  readonly claim: unknown;
  /** Optional evidence supporting the attestation. */
  readonly evidence?: CachedAttestationEvidence | null;
  /** Unix timestamp (seconds) when the attestation was issued. */
  readonly issuedAt: number;
  /** Optional expiry timestamp (seconds). */
  readonly expiresAt?: number | null;
  /** Optional renewal interval (`std::time::Duration` → `{ secs, nanos }`). */
  readonly renewalInterval?: CachedAttestationDuration | null;
  /** Timestamp (seconds) of the last renewal, if renewable. */
  readonly renewedAt?: number | null;
  /** Current revocation status (serde-tagged). */
  readonly revocationStatus: unknown;
  /** Ed25519 signature over the attestation content (64 bytes). */
  readonly signature: readonly number[];
}

/**
 * A verified attestation with cache TTL metadata (ADR-017).
 *
 * Pass an array of these to {@link SCP.participationRecord} to seed the
 * bridge's trust store before it sources the subject's verified set. Mirrors
 * the Rust `CachedAttestation` and the Swift/Kotlin `CachedAttestation` types
 * 1:1 (camelCase developer-facing fields; {@link encodeCachedAttestations}
 * serializes to the snake_case wire shape). An empty array (the default) seeds
 * nothing — the bridge reports only what it already holds (verifier-relative,
 * §7.4).
 */
export interface CachedAttestation {
  /** The verified attestation envelope. */
  readonly attestation: CachedAttestationEnvelope;
  /** Unix timestamp (seconds) when the attestation was last verified. */
  readonly verifiedAt: number;
  /** Time-to-live in seconds for the cache entry. */
  readonly ttlSecs: number;
}

/**
 * Encodes a typed {@link CachedAttestation} array to the JSON wire shape the
 * Rust bridge deserializes.
 *
 * The developer-facing types are camelCase (matching the other typed SDK types
 * and the Swift/Kotlin SDKs), but the bridge expects serde-canonical
 * snake_case. This maps `attestationType → attestation_type`,
 * `issuedAt → issued_at`, `verifiedAt → verified_at`, etc., mirroring the Swift
 * `CodingKeys` and Kotlin `buildJsonObject` mappings. The `renewalInterval`
 * `{ secs, nanos }` shape is identical on the wire (Rust `Duration` field
 * names), so it passes through unchanged.
 *
 * Public for SDK call sites that serialize cached attestations onto the wire
 * (e.g. {@link SCP.participationRecord}) and for tests that pin the wire shape
 * against the Rust serde format.
 */
export function encodeCachedAttestations(cachedAttestations: readonly CachedAttestation[]): string {
  return JSON.stringify(cachedAttestations.map(encodeCachedAttestation));
}

function encodeCachedAttestation(cached: CachedAttestation): Record<string, unknown> {
  return {
    attestation: encodeCachedAttestationEnvelope(cached.attestation),
    verified_at: cached.verifiedAt,
    ttl_secs: cached.ttlSecs,
  };
}

function encodeCachedAttestationEnvelope(
  envelope: CachedAttestationEnvelope,
): Record<string, unknown> {
  const wire: Record<string, unknown> = {
    id: envelope.id,
    attestation_type: envelope.attestationType,
    issuer: envelope.issuer,
    subject: envelope.subject,
    claim: envelope.claim,
    issued_at: envelope.issuedAt,
    revocation_status: envelope.revocationStatus,
    signature: envelope.signature,
  };
  if (envelope.evidence != null) {
    wire.evidence = {
      evidence_type: envelope.evidence.evidenceType,
      data: envelope.evidence.data,
    };
  }
  if (envelope.expiresAt != null) {
    wire.expires_at = envelope.expiresAt;
  }
  if (envelope.renewalInterval != null) {
    wire.renewal_interval = {
      secs: envelope.renewalInterval.secs,
      nanos: envelope.renewalInterval.nanos,
    };
  }
  if (envelope.renewedAt != null) {
    wire.renewed_at = envelope.renewedAt;
  }
  return wire;
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
  /** Total outlet invocations across all outlet types. */
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

/**
 * Encodes a typed {@link RequireParticipation} array to the JSON wire shape
 * expected by the Rust bridge (`Vec<RequireParticipation>`).
 *
 * Field names are snake_cased to match `serde_json::to_string`. `fact` is a
 * bare variant string and `threshold` is already the serde-canonical
 * `{ "<Op>": value }` shape, so both pass through unchanged.
 */
export function encodeRequireParticipation(requirements: readonly RequireParticipation[]): string {
  return JSON.stringify(
    requirements.map((r) => ({
      fact: r.fact,
      threshold: r.threshold,
      max_age_secs: r.maxAgeSecs,
      min_contexts: r.minContexts,
    })),
  );
}

/**
 * Throws when a fixed-length byte-array field has the wrong number of
 * elements, so a malformed profile/verification fails at encode time with a
 * field-named error instead of surfacing as a Rust `[u8; N]` deserialization
 * error after the bridge call. Mirrors the Python SDK's construction-time
 * checks (ADR-058 misuse resistance).
 */
function requireByteLength(
  typeName: string,
  fieldName: string,
  expectedLength: number,
  actual: readonly number[],
): void {
  if (actual.length !== expectedLength) {
    throw new Error(
      `${typeName}.${fieldName} must be exactly ${expectedLength} elements, got ${actual.length}`,
    );
  }
}

/**
 * Encodes a typed {@link ParticipationProfile} array to the JSON wire shape
 * expected by the Rust bridge (`Vec<ParticipationProfile>`).
 *
 * Field names are snake_cased to match `serde_json::to_string`. Byte-array
 * fields (`eventLogRoot`, `signerPublicKey`, `signature`) pass through as
 * number arrays.
 *
 * @throws Error if `eventLogRoot` / `signerPublicKey` are not exactly 32
 *   elements or `signature` is not exactly 64 elements (before any bridge
 *   call).
 */
export function encodeParticipationProfile(profiles: readonly ParticipationProfile[]): string {
  for (const p of profiles) {
    requireByteLength("ParticipationProfile", "eventLogRoot", 32, p.eventLogRoot);
    requireByteLength("ParticipationProfile", "signerPublicKey", 32, p.signerPublicKey);
    requireByteLength("ParticipationProfile", "signature", 64, p.signature);
  }
  return JSON.stringify(
    profiles.map((p) => ({
      subject_did: p.subjectDid,
      participation_duration_secs: p.participationDurationSecs,
      governance_actions_against: p.governanceActionsAgainst,
      governance_actions_by: p.governanceActionsBy,
      tool_invocation_count: p.toolInvocationCount,
      tool_invocation_count_anchored: p.toolInvocationCountAnchored,
      context_creation_count: p.contextCreationCount,
      role_progression_count: p.roleProgressionCount,
      attestation_count: p.attestationCount,
      updated_at: p.updatedAt,
      event_log_root: p.eventLogRoot,
      signer_public_key: p.signerPublicKey,
      signature: p.signature,
    })),
  );
}

// ---------------------------------------------------------------------------
// Capability admission (§7.3.4.4, SCP-ACR-008, ADR-058)
// ---------------------------------------------------------------------------

/**
 * How a capability must be verified for admission.
 *
 * Mirrors the Rust `VerificationLevel` enum (`scp-core`). Serializes as the
 * bare variant name string.
 *
 * - `"SelfAttested"` — the agent claims the capability (present in their
 *   capability list); no challenge proof required.
 * - `"ChallengeVerified"` — the capability was verified through the
 *   challenge-response protocol. Also satisfies `SelfAttested`.
 */
export type VerificationLevel = "SelfAttested" | "ChallengeVerified";

/**
 * A single admission requirement: a capability URI and the minimum
 * verification level needed.
 *
 * Mirrors the Rust `CapabilityRequirement` struct (`scp-core`). See §7.3.4.4.
 */
export interface CapabilityRequirement {
  /** The capability URI that must be present. */
  readonly capability: string;
  /** The minimum verification level required. */
  readonly verificationLevel: VerificationLevel;
}

/**
 * How a capability was verified, as recorded in a {@link ChallengeVerification}.
 *
 * Mirrors the Rust `VerificationMethod` enum (`scp-core`). Serializes as the
 * bare string `"SelfAttested"` or the tagged
 * `{ "ChallengeVerified": { "challenge_type": <uri> } }`.
 *
 * SECURITY: `verificationMethod` is NOT covered by the verifier signature
 * (ADR-017 caveat) — consumers MUST NOT key trust decisions on it.
 */
export type ChallengeVerificationMethod =
  | { readonly kind: "SelfAttested" }
  | { readonly kind: "ChallengeVerified"; readonly challengeType: string };

/**
 * A signed record that a specific verifier tested a capability and the agent
 * passed (spec §7.3.4.2, ADR-017).
 *
 * Mirrors the Rust `ChallengeVerification` struct (`scp-core`). Pass a list of
 * these to {@link SCP.checkCapabilityRequirements} to satisfy `ChallengeVerified`
 * requirements.
 *
 * SECURITY (ADR-017 caveat): only the *signed* fields bind trust —
 * `verificationId`, `verifierDid`, `subjectDid`, `capabilityUri`,
 * `challengeType`, `passed`, `score`, `testCount`, `passCount`, `verifiedAt`,
 * `expiresAt`, `contextId`. The `result`, `completedAt`, and
 * `verificationMethod` fields are NOT signed and can be altered after minting
 * without invalidating the signature. Consumers MUST NOT key trust decisions
 * on those unsigned fields.
 */
export interface ChallengeVerification {
  /** Unique verification identifier (derived from the challenge ID). */
  readonly verificationId: string;
  /** DID of the verifier who issued and verified the challenge. */
  readonly verifierDid: string;
  /** DID of the subject who answered the challenge. */
  readonly subjectDid: string;
  /** The capability URI that was verified. */
  readonly capabilityUri: string;
  /** The type of challenge that was verified (a capability URI string). */
  readonly challengeType: string;
  /** How the capability was verified (unsigned metadata). */
  readonly verificationMethod: ChallengeVerificationMethod;
  /** Whether the subject passed the challenge overall. */
  readonly passed: boolean;
  /** Total number of test cases in the challenge. */
  readonly testCount: number;
  /** Number of test cases the subject passed. */
  readonly passCount: number;
  /** The challenge-specific result from the response (arbitrary JSON, unsigned). */
  readonly result: unknown;
  /** Unix timestamp (seconds) when the response was completed (unsigned). */
  readonly completedAt: number;
  /** Unix timestamp (seconds) when the verification was performed. */
  readonly verifiedAt: number;
  /** Unix timestamp (seconds) when this verification expires. */
  readonly expiresAt: number;
  /** Ed25519 signature by the verifier over the verification record (64 bytes). */
  readonly verifierSignature: readonly number[];
  /** Optional numeric score (0–100) for graded challenges. */
  readonly score?: number | null;
  /** Context in which the challenge was issued, if any. */
  readonly contextId?: string | null;
}

/**
 * Encodes a typed {@link CapabilityRequirement} array to the JSON wire shape
 * expected by the Rust bridge (`Vec<CapabilityRequirement>`).
 *
 * `verificationLevel` serializes as the bare variant string.
 */
export function encodeCapabilityRequirements(
  requirements: readonly CapabilityRequirement[],
): string {
  return JSON.stringify(
    requirements.map((r) => ({
      capability: r.capability,
      verification_level: r.verificationLevel,
    })),
  );
}

function encodeChallengeVerificationMethod(method: ChallengeVerificationMethod): unknown {
  switch (method.kind) {
    case "SelfAttested":
      return "SelfAttested";
    case "ChallengeVerified":
      return { ChallengeVerified: { challenge_type: method.challengeType } };
    default: {
      const exhaustive: never = method;
      throw new Error(`unknown ChallengeVerificationMethod kind: ${JSON.stringify(exhaustive)}`);
    }
  }
}

/**
 * Encodes a typed {@link ChallengeVerification} array to the JSON wire shape
 * expected by the Rust bridge (`Vec<ChallengeVerification>`).
 *
 * Field names are snake_cased to match `serde_json::to_string`. The
 * `verificationMethod` discriminated union is encoded to the serde-tagged
 * shape; `verifierSignature` passes through as a number array. `score` and
 * `contextId` default to `null` when absent.
 *
 * @throws Error if `verifierSignature` is not exactly 64 elements (before any
 *   bridge call).
 */
export function encodeChallengeVerifications(
  verifications: readonly ChallengeVerification[],
): string {
  for (const v of verifications) {
    requireByteLength("ChallengeVerification", "verifierSignature", 64, v.verifierSignature);
  }
  return JSON.stringify(
    verifications.map((v) => ({
      verification_id: v.verificationId,
      verifier_did: v.verifierDid,
      subject_did: v.subjectDid,
      capability_uri: v.capabilityUri,
      challenge_type: v.challengeType,
      verification_method: encodeChallengeVerificationMethod(v.verificationMethod),
      passed: v.passed,
      score: v.score ?? null,
      test_count: v.testCount,
      pass_count: v.passCount,
      result: v.result,
      completed_at: v.completedAt,
      verified_at: v.verifiedAt,
      expires_at: v.expiresAt,
      context_id: v.contextId ?? null,
      verifier_signature: v.verifierSignature,
    })),
  );
}

// ---------------------------------------------------------------------------
// Trust aggregation inputs (§7.3, ADR-058)
// ---------------------------------------------------------------------------

/**
 * Attestation type (ADR-017).
 *
 * Mirrors the Rust `AttestationType` enum (`scp-core`) — the 8 unit variants
 * serialize as bare PascalCase strings, both as values and as
 * `thresholdRequirements` / `attestorSets` map keys.
 */
export type AttestationType =
  | "IdentityLink"
  | "CapabilityDelegation"
  | "ToolIntegrity"
  | "AgentCapability"
  | "Endorsement"
  | "RoleAssignment"
  | "ContextEndorsement"
  | "ParticipationWitness";

/**
 * Frozen set of {@link AttestationType} variant names. Imported by the SDK
 * round-trip tests so renaming a variant trips a compile error.
 */
export const ATTESTATION_TYPE_VARIANTS = [
  "IdentityLink",
  "CapabilityDelegation",
  "ToolIntegrity",
  "AgentCapability",
  "Endorsement",
  "RoleAssignment",
  "ContextEndorsement",
  "ParticipationWitness",
] as const satisfies readonly AttestationType[];

/**
 * Type-specific data carried by an {@link EventLogEntry}.
 *
 * Mirrors the Rust `EventPayload` (`scp-event-log`): opaque payload bytes as
 * a JSON number array (`serde_bytes`). An empty `data` array is the canonical
 * representation for non-parameterized events.
 */
export interface EventLogEntryPayload {
  /** Opaque payload bytes. Interpretation depends on the event type. */
  readonly data: readonly number[];
}

/**
 * A full signed protocol event in a context event log (ADR-011).
 *
 * Mirrors the Rust `Event` (`scp-event-log`) serde wire shape the bridge
 * deserializes for {@link SCP.aggregateTrustInput} (`Vec<Event>`). This is
 * the INPUT wire form — distinct from the projected {@link Event} the
 * event-log query surface returns, which omits the hash-chain and signature
 * fields. Developer-facing fields are camelCase;
 * {@link encodeEventLogEntries} maps to the snake_case wire shape.
 */
export interface EventLogEntry {
  /** Event type — a Rust `EventType` variant name (e.g. `"MessageSent"`). */
  readonly eventType: string;
  /** DID of the actor who produced this event. */
  readonly actorDid: string;
  /** Unix timestamp (seconds) when the event was created. */
  readonly timestamp: number;
  /** Monotonic event sequence number within the log (0-indexed). */
  readonly sequence: number;
  /** Type-specific event data. */
  readonly payload: EventLogEntryPayload;
  /**
   * SHA-256 hash of the previous event (hash chain), exactly 32 bytes as a
   * number array. `[0; 32]` for the first event (genesis sentinel).
   */
  readonly prevHash: readonly number[];
  /**
   * Ed25519 signature over the serialized event content (64 bytes as a
   * number array).
   */
  readonly signature: readonly number[];
}

/**
 * N-of-M threshold requirement for attestation verification (ADR-017 §7.3.5).
 *
 * Mirrors the Rust `ThresholdRequirement` struct (`scp-core`). The three
 * penalty fields carry the Rust serde defaults when omitted;
 * {@link encodeThresholdRequirements} emits them explicitly so the wire form
 * is identical across bindings.
 */
export interface ThresholdRequirement {
  /** The minimum number of valid attestations required (N). */
  readonly requiredCount: number;
  /** The total number of attestors in the set (M). Must be >= `requiredCount`. */
  readonly totalAttestors: number;
  /** Minimum independence score, in [0.0, 1.0]. */
  readonly independenceThreshold: number;
  /** Independence penalty per shared context membership. Default: 0.1. */
  readonly sharedContextPenalty?: number;
  /** Maximum total shared-context penalty for a single pair. Default: 0.5. */
  readonly sharedContextPenaltyCap?: number;
  /** Independence penalty per mutual endorsement direction. Default: 0.2. */
  readonly mutualEndorsementPenalty?: number;
}

/**
 * Information about an attestor used for independence scoring (ADR-017
 * §7.3.5).
 *
 * Mirrors the Rust `AttestorInfo` struct (`scp-core`). The optional
 * `attestation` is the full attestation envelope
 * ({@link CachedAttestationEnvelope}); only attestations matching the
 * required type are considered.
 */
export interface AttestorInfo {
  /** The DID of the attestor. */
  readonly did: string;
  /** Context IDs the attestor is a member of. */
  readonly contextMemberships: readonly string[];
  /** DIDs this attestor has endorsed (mutual endorsements reduce independence). */
  readonly endorsements: readonly string[];
  /** The attestation provided by this attestor, if any. */
  readonly attestation?: CachedAttestationEnvelope | null;
}

/**
 * Encodes a typed {@link EventLogEntry} array to the JSON wire shape the
 * Rust bridge deserializes (`Vec<scp_event_log::Event>`).
 *
 * Field names are snake_cased to match `serde_json::to_string`; `prevHash` /
 * `signature` / `payload.data` pass through as number arrays.
 *
 * @throws Error if `prevHash` is not exactly 32 elements or `signature` is
 *   not exactly 64 elements (before any bridge call).
 */
export function encodeEventLogEntries(events: readonly EventLogEntry[]): string {
  for (const e of events) {
    requireByteLength("EventLogEntry", "prevHash", 32, e.prevHash);
    requireByteLength("EventLogEntry", "signature", 64, e.signature);
  }
  return JSON.stringify(
    events.map((e) => ({
      event_type: e.eventType,
      actor_did: e.actorDid,
      timestamp: e.timestamp,
      sequence: e.sequence,
      payload: { data: e.payload.data },
      prev_hash: e.prevHash,
      signature: e.signature,
    })),
  );
}

/**
 * Encodes a 32-byte Merkle root to the JSON wire shape the Rust bridge
 * deserializes (`[u8; 32]` as a number array).
 *
 * @throws Error if `merkleRoot` is not exactly 32 elements (before any
 *   bridge call).
 */
export function encodeMerkleRoot(merkleRoot: readonly number[]): string {
  requireByteLength("AggregationInput", "merkleRoot", 32, merkleRoot);
  return JSON.stringify(merkleRoot);
}

/**
 * Encodes a typed per-attestation-type {@link ThresholdRequirement} map to
 * the JSON wire shape the Rust bridge deserializes
 * (`HashMap<AttestationType, ThresholdRequirement>`).
 *
 * Map keys are the bare {@link AttestationType} variant strings; the three
 * optional penalty fields default to the Rust serde defaults (0.1 / 0.5 /
 * 0.2) and are always emitted explicitly.
 */
export function encodeThresholdRequirements(
  requirements: Readonly<Partial<Record<AttestationType, ThresholdRequirement>>>,
): string {
  const wire: Record<string, unknown> = {};
  for (const [attestationType, requirement] of Object.entries(requirements)) {
    if (requirement === undefined) {
      continue;
    }
    wire[attestationType] = {
      required_count: requirement.requiredCount,
      total_attestors: requirement.totalAttestors,
      independence_threshold: requirement.independenceThreshold,
      shared_context_penalty: requirement.sharedContextPenalty ?? 0.1,
      shared_context_penalty_cap: requirement.sharedContextPenaltyCap ?? 0.5,
      mutual_endorsement_penalty: requirement.mutualEndorsementPenalty ?? 0.2,
    };
  }
  return JSON.stringify(wire);
}

/**
 * Encodes a typed per-attestation-type {@link AttestorInfo} map to the JSON
 * wire shape the Rust bridge deserializes
 * (`HashMap<AttestationType, Vec<AttestorInfo>>`).
 *
 * Map keys are the bare {@link AttestationType} variant strings; the nested
 * attestation envelope (when present) is encoded exactly as
 * {@link encodeCachedAttestations} encodes it. An absent `attestation`
 * serializes as explicit `null` (matching `serde_json::to_string` of the
 * Rust `Option<Attestation>`).
 */
export function encodeAttestorSets(
  attestorSets: Readonly<Partial<Record<AttestationType, readonly AttestorInfo[]>>>,
): string {
  const wire: Record<string, unknown> = {};
  for (const [attestationType, attestors] of Object.entries(attestorSets)) {
    if (attestors === undefined) {
      continue;
    }
    wire[attestationType] = attestors.map((a) => ({
      did: a.did,
      context_memberships: a.contextMemberships,
      endorsements: a.endorsements,
      attestation: a.attestation != null ? encodeCachedAttestationEnvelope(a.attestation) : null,
    }));
  }
  return JSON.stringify(wire);
}

// ---------------------------------------------------------------------------
// Challenge trust inputs (§7.3.4, ADR-058)
// ---------------------------------------------------------------------------

/**
 * A challenge request for capability verification (ADR-017, spec §7.3.4).
 *
 * Mirrors the Rust `ChallengeRequest` struct (`scp-core`) serde wire shape
 * the bridge deserializes for {@link SCP.trustVerifyResponse}.
 * `challengeType` is a bare capability URI string (the Rust `ChallengeType`
 * serializes as its URI string); `timeout` is the Rust `std::time::Duration`
 * serde shape ({@link CachedAttestationDuration}).
 */
export interface ChallengeRequest {
  /** Unique challenge identifier (UUID v4). */
  readonly challengeId: string;
  /** The type of challenge being issued (a capability URI string). */
  readonly challengeType: string;
  /** DID of the entity issuing the challenge. */
  readonly challengerDid: string;
  /** DID of the entity being challenged. */
  readonly subjectDid: string;
  /** The capability URI being tested (spec §7.3.4.1). */
  readonly capabilityUri: string;
  /** Challenge-specific parameters (schema, test vectors, limits, etc.). */
  readonly parameters: unknown;
  /** Maximum time allowed for the subject to respond (`{ secs, nanos }`). */
  readonly timeout: CachedAttestationDuration;
  /** Ed25519 signature over the canonical challenge bytes (64 bytes). */
  readonly signature: readonly number[];
}

/**
 * A response to a challenge request (ADR-017, spec §7.3.4).
 *
 * Mirrors the Rust `ChallengeResponse` struct (`scp-core`) serde wire shape
 * the bridge deserializes for {@link SCP.trustVerifyResponse}.
 */
export interface ChallengeResponse {
  /** The challenge ID this response corresponds to. */
  readonly challengeId: string;
  /** DID of the entity responding to the challenge. */
  readonly responderDid: string;
  /** Challenge-specific result data (pass/fail, metrics, evidence, etc.). */
  readonly result: unknown;
  /** Unix timestamp (seconds) when the response was completed. */
  readonly completedAt: number;
  /** Ed25519 signature over the canonical response bytes (64 bytes). */
  readonly signature: readonly number[];
}

/**
 * Encodes a single typed attestation envelope
 * ({@link CachedAttestationEnvelope}) to the JSON wire shape the Rust bridge
 * deserializes for {@link SCP.trustVerifyAttestation} (`Attestation`) —
 * exactly the shape {@link encodeCachedAttestations} nests per entry.
 */
export function encodeAttestation(attestation: CachedAttestationEnvelope): string {
  return JSON.stringify(encodeCachedAttestationEnvelope(attestation));
}

/**
 * Encodes a typed {@link ChallengeRequest} to the JSON wire shape the Rust
 * bridge deserializes (`ChallengeRequest`).
 *
 * @throws Error if `signature` is not exactly 64 elements (before any bridge
 *   call).
 */
export function encodeChallengeRequest(challenge: ChallengeRequest): string {
  requireByteLength("ChallengeRequest", "signature", 64, challenge.signature);
  return JSON.stringify({
    challenge_id: challenge.challengeId,
    challenge_type: challenge.challengeType,
    challenger_did: challenge.challengerDid,
    subject_did: challenge.subjectDid,
    capability_uri: challenge.capabilityUri,
    parameters: challenge.parameters,
    timeout: { secs: challenge.timeout.secs, nanos: challenge.timeout.nanos },
    signature: challenge.signature,
  });
}

/**
 * Encodes a typed {@link ChallengeResponse} to the JSON wire shape the Rust
 * bridge deserializes (`ChallengeResponse`).
 *
 * @throws Error if `signature` is not exactly 64 elements (before any bridge
 *   call).
 */
export function encodeChallengeResponse(response: ChallengeResponse): string {
  requireByteLength("ChallengeResponse", "signature", 64, response.signature);
  return JSON.stringify({
    challenge_id: response.challengeId,
    responder_did: response.responderDid,
    result: response.result,
    completed_at: response.completedAt,
    signature: response.signature,
  });
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
  /** Outlets to expose via MCP. */
  readonly outlets: readonly OutletDefinition[];
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
