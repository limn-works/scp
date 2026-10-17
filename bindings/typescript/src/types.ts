/**
 * Shared type definitions for the SCP TypeScript SDK.
 *
 * These types are used across all SDK modules. They map to the protocol types
 * defined in `.docs/specs/` and `.docs/sketch.md`.
 *
 * See ADR-022 in `.docs/adrs/phase-4.md` and `.docs/scaffold/typescript.md`.
 */

import { UnknownGovernanceOutcomeError, ValidationError } from "./errors";
import type { Identity } from "./identity";

// ---------------------------------------------------------------------------
// Capability strings
// ---------------------------------------------------------------------------

/**
 * Canonical protocol capability strings and parameterised constructors.
 *
 * These are the SDK-facing colon-separated forms accepted by `Capability::new`
 * in Rust (e.g. `"messages:write"`, `"outlet:call:*"`) — the shape used in
 * `ContextParams.ceiling`, role capability lists, and UCAN capability arrays.
 * Parameterised capabilities are plain strings built by {@link outletQuery} and
 * {@link outletCall}.
 *
 * The pre-rename outlet-prefixed stems (invoke / register / interface) are deleted
 * with no transitional alias; the protocol hard-rejects them at construction
 * time (ADR-049 §1).
 */
export const Capabilities = {
  MESSAGES_READ: "messages:read",
  MESSAGES_WRITE: "messages:write",
  /** Query outlet capability — read-only; never billed. */
  OUTLET_QUERY_ALL: "outlet:query:*",
  /** Action outlet capability — the outlet may mutate state and may incur cost (billable). */
  OUTLET_CALL_ALL: "outlet:call:*",
  OUTLET_REGISTER: "outlet:register",
  MEMBER_INVITE: "member:invite",
  MEMBER_REMOVE: "member:remove",
  ROLE_ASSIGN: "role:assign",
  GOVERNANCE_PROPOSE: "governance:propose",
  GOVERNANCE_VOTE: "governance:vote",
  CONTEXT_CLOSE: "context:close",
  CHILD_CONTEXT_CREATE: "context:child:create",
  OUTLET_INTERFACE: "outlet:interface",
  MEDIA_VOICE: "media:voice",
  MEDIA_VIDEO: "media:video",
  MEDIA_SCREEN_SHARE: "media:screen_share",
  MEMBER_BAN: "member:ban",
  METADATA_EDIT: "metadata:edit",
} as const;

/**
 * Build the capability string for invoking a specific Query (read-only) outlet.
 *
 * Query outlet capability — read-only; never billed.
 *
 * Per spec §5.4.2.1 the `outletId` suffix must match `^[a-z0-9_-]{1,128}$`.
 */
export function outletQuery(outletId: string): string {
  return `outlet:query:${outletId}`;
}

/**
 * Build the capability string for invoking a specific Action (mutating) outlet.
 *
 * Action outlet capability — the outlet may mutate state and may incur cost (billable).
 *
 * Per spec §5.4.2.1 the `outletId` suffix must match `^[a-z0-9_-]{1,128}$`.
 */
export function outletCall(outletId: string): string {
  return `outlet:call:${outletId}`;
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

/** Parameters for creating a new SCP context. */
export interface ContextParams {
  /**
   * Capability ceiling — maximum capabilities available in this context.
   *
   * Required and non-empty. `contextCreate` rejects params JSON whose
   * `ceiling` is absent or `null` with `SCP-VALID-7004` and one whose
   * `ceiling` is an empty array with `SCP-VALID-7005`; no default ceiling is
   * substituted.
   */
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
  /**
   * The context's admission capability requirements (spec 07 §7.3.4.4).
   * Omit for none. {@link SCP.contextCreate} reads this field from the params
   * JSON as typed {@link CapabilityRequirement}s and encodes them to the
   * bridge's wire form itself; it refuses a JSON string or a snake_case wire
   * list here with `SCP-VALID-7001`. {@link SCP.checkCapabilityRequirements}
   * reads the requirements from the context's governance at each check, and
   * {@link SCP.contextGovernanceModifyCapabilityRequirements} replaces them.
   */
  readonly capabilityRequirements?: readonly CapabilityRequirement[];
  /**
   * Pseudonym rotation policy (spec 09 §9.10.4.1). Omit or pass `null` to
   * disable rotation: members keep one relay routing ID for the context's
   * lifetime. A policy with no trigger, an `intervalSecs` under 600, an
   * unknown key, or a missing `onMembershipChange` fails `contextCreate`
   * with `SCP-VALID-7000`.
   */
  readonly pseudonymRotation?: PseudonymRotationPolicy | null;
}

/**
 * When members of a context rotate their relay routing ID (spec 09 §9.10.4.1).
 * At least one trigger must be set.
 */
export interface PseudonymRotationPolicy {
  /**
   * Interval trigger in seconds: members rotate at each multiple of the
   * interval after context creation. When set, at least 600. Omit or pass
   * `null` for no interval trigger.
   */
  readonly intervalSecs?: number | null;
  /**
   * Membership trigger: every member except the added or removed one rotates
   * once after each committed `AddMember` or `RemoveMember`.
   */
  readonly onMembershipChange: boolean;
}

// ---------------------------------------------------------------------------
// Consequence rules (ADR-017, §9.3, #1531)
// ---------------------------------------------------------------------------

/**
 * A registered Action-outlet capability (`outlet:call:<id>`) within a context.
 *
 * Mirrors the `Capability::OutletCall(OutletId)` newtype. Carries the outlet ID
 * (an opaque string) and serializes as `{"OutletCall": "id"}` to match the
 * Rust serde tagging.
 */
export interface OutletCallCapability {
  /** Discriminant. */
  readonly kind: "OutletCall";
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
  | "OutletQueryAll"
  | "OutletCallAll"
  | "OutletRegister"
  | "MemberInvite"
  | "MemberRemove"
  | "RoleAssign"
  | "GovernancePropose"
  | "GovernanceVote"
  | "ContextClose"
  | "ChildContextCreate"
  | "OutletInterface"
  | "MediaVoice"
  | "MediaVideo"
  | "MediaScreenShare"
  | "MemberBan"
  | "MetadataEdit";

/**
 * Typed capability matching `scp_protocol::context::roles::Capability`.
 *
 * Either a unit-variant string or an object discriminated by `kind` for
 * payload-bearing variants (`OutletCall`, `Custom`). The SDK encoder converts
 * each variant to the matching Rust serde JSON shape:
 *
 * - `"MessagesRead"` → `"MessagesRead"`
 * - `{ kind: "OutletCall", outletId: "calculator" }` → `{"OutletCall": "calculator"}`
 * - `{ kind: "Custom", name: "foo" }` → `{"Custom": "foo"}`
 */
export type ConsequenceCapability = UnitCapability | OutletCallCapability | CustomCapability;

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
  | { readonly kind: "OutletRateExceeded" }
  | { readonly kind: "WarningCount" }
  | { readonly kind: "Custom"; readonly key: string };

/**
 * Frozen set of {@link ConsequenceTrigger} variant names. Imported by the
 * SDK round-trip tests so renaming a variant trips a compile error.
 */
export const CONSEQUENCE_TRIGGER_VARIANTS = [
  "MessageVelocity",
  "OutletRateExceeded",
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
    case "OutletRateExceeded":
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
  if (capability.kind === "OutletCall") {
    return { OutletCall: capability.outletId };
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
 * The six protocol-defined roles (spec section 5.5), one per name
 * `RESERVED_ROLE_NAMES` in `crates/scp-protocol/src/context/roles.rs`
 * reserves. No custom role may take any of them, so a member holding one of
 * these names holds the protocol-defined role of that name.
 */
export const BUILT_IN_ROLES = [
  "Admin",
  "Moderator",
  "Member",
  "Observer",
  "Author",
  "Subscriber",
] as const;

/** A protocol-defined role; see {@link BUILT_IN_ROLES}. */
export type BuiltInRole = (typeof BUILT_IN_ROLES)[number];

/** A role a context's governance defined, carrying the name governance gave it. */
export interface CustomRole {
  readonly kind: "Custom";
  /** The role's name, for example `"night-shift-reviewer"`. */
  readonly name: string;
}

/**
 * Role assigned to a member within a context (spec section 5.5): a
 * {@link BuiltInRole}, or a {@link CustomRole} carrying its name.
 */
export type MemberRole = BuiltInRole | CustomRole;

/**
 * A custom role name `validate_role_name` in
 * `crates/scp-protocol/src/context/roles.rs` admits: 1 to 64 bytes of
 * lowercase ASCII letters, digits, hyphens, and underscores, neither starting
 * nor ending with a hyphen or underscore.
 */
const CUSTOM_ROLE_NAME = /^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$/;

/**
 * Parses a bridge-layer role name into a {@link MemberRole}.
 *
 * Every bridge reports `RoleAssignment.role_name`, which stores a built-in
 * role in lowercase (`"author"`) and a custom role under the name governance
 * gave it. Matching is exact. Swift's `MemberRole.fromBridge` and Python's
 * `MemberRole.from_bridge` parse the same way.
 *
 * @throws {UnknownGovernanceOutcomeError} `SCP-GOV-11040` when `raw` is
 *   neither a built-in role name nor a name `validate_role_name` admits for a
 *   custom role.
 */
export function memberRoleFromBridge(raw: string): MemberRole {
  const builtIn = BUILT_IN_ROLES.find((role) => role.toLowerCase() === raw);
  if (builtIn !== undefined) return builtIn;
  if (!CUSTOM_ROLE_NAME.test(raw)) {
    throw new UnknownGovernanceOutcomeError(
      `bridge reported role name ${JSON.stringify(raw)}, which is neither a built-in nor a valid custom role name`,
      raw,
    );
  }
  return { kind: "Custom", name: raw };
}

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
 * Every governance outcome a bridge reports (ADR-031). Each entry is the name
 * `governance_action_result_name` in
 * `crates/scp-ffi/common/src/governance_result.rs` gives one variant of
 * `scp_core::context::state::GovernanceActionResult`.
 * `crates/scp-testing/tests/governance_outcome_parity.rs` fails when this list
 * and that function list different names.
 */
export const GOVERNANCE_ACTION_RESULTS = [
  "MemberAdded",
  "MemberRemoved",
  "RoleChanged",
  "OutletRegistered",
  "OutletRemoved",
  "CeilingModified",
  "ContextClosed",
  "TtlExtended",
  "PruningPolicyModified",
  "AdminTransferred",
  "SignerAdded",
  "SignerRemoved",
  "ThresholdModified",
  "ChildContextCreated",
  "OutletInterfaceEstablished",
  "MemberReset",
  "ConflictResolved",
  "ContextPromoted",
  "MemberSuspended",
  "AccessRevoked",
  "AccessRestored",
  "ContentKeysRotated",
  "GovernanceReconfigured",
  "SubscriberBanned",
  "SubscriberUnbanned",
  "Executed",
  "MigrationProposed",
  "MigrationCancelled",
  "ContextTombstoned",
] as const;

/** Result of executing a governance action (ADR-031). */
export type GovernanceActionResult = (typeof GOVERNANCE_ACTION_RESULTS)[number];

/**
 * Every proposal status a bridge reports: the names `proposal_status_name`
 * gives the variants of `scp_core::context::governance::ProposalStatus`.
 */
export const PROPOSAL_STATUSES = [
  "Pending",
  "Approved",
  "Rejected",
  "Expired",
  "Cancelled",
  "Invalidated",
] as const;

/** Lifecycle status of a governance proposal (ADR-031). */
export type ProposalStatus = (typeof PROPOSAL_STATUSES)[number];

/**
 * Every rejection reason a bridge reports: the names `rejection_reason_name`
 * gives the variants of `scp_core::context::governance::RejectionReason`.
 */
export const REJECTION_REASONS = [
  "AdminRejected",
  "MajorityRejected",
  "UnanimityBroken",
  "ApprovalImpossible",
  "InsufficientParticipation",
] as const;

/** Reason a governance proposal was rejected (ADR-031). */
export type RejectionReason = (typeof REJECTION_REASONS)[number];

function parseGovernanceName<T extends string>(kind: string, known: readonly T[], raw: string): T {
  const found = known.find((name) => name === raw);
  if (found === undefined) {
    throw new UnknownGovernanceOutcomeError(
      `bridge reported ${kind} ${JSON.stringify(raw)}, which this SDK version does not name; ` +
        `known names: ${known.join(", ")}. Upgrade the SDK to the version of the bridge it calls.`,
      raw,
    );
  }
  return found;
}

/**
 * Parses the outcome name a bridge's governance execute returns.
 *
 * @throws {UnknownGovernanceOutcomeError} `SCP-GOV-11040` when `raw` names no
 *   entry of {@link GOVERNANCE_ACTION_RESULTS}. The action ran and this SDK
 *   cannot say which action it was, so it never reports `"Executed"` in its
 *   place.
 */
export function governanceActionResultFromBridge(raw: string): GovernanceActionResult {
  return parseGovernanceName("governance outcome", GOVERNANCE_ACTION_RESULTS, raw);
}

/**
 * Parses a proposal status name a bridge reports.
 *
 * @throws {UnknownGovernanceOutcomeError} `SCP-GOV-11040` when `raw` names no
 *   entry of {@link PROPOSAL_STATUSES}.
 */
export function proposalStatusFromBridge(raw: string): ProposalStatus {
  return parseGovernanceName("proposal status", PROPOSAL_STATUSES, raw);
}

/**
 * Parses a rejection reason name a bridge reports.
 *
 * @throws {UnknownGovernanceOutcomeError} `SCP-GOV-11040` when `raw` names no
 *   entry of {@link REJECTION_REASONS}.
 */
export function rejectionReasonFromBridge(raw: string): RejectionReason {
  return parseGovernanceName("rejection reason", REJECTION_REASONS, raw);
}

/**
 * Checks every name in a governance proposal response and returns `raw`.
 *
 * Propose, approve, reject, and withdraw each return a JSON object
 * `{status, reason?, rejector?}`; propose adds `proposal_id` and
 * `execution_result`. This function parses `status`, the `reason` of a
 * `"Rejected"` status, and a non-null `execution_result`. An `"Invalidated"`
 * status carries free-text `reason`, which must be a string.
 *
 * @throws {UnknownGovernanceOutcomeError} `SCP-GOV-11040` when `raw` is not a
 *   JSON object, a required name is missing or is not a string, or a name
 *   matches no entry of its list.
 */
export function checkProposalResponse(raw: string): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    parsed = undefined;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new UnknownGovernanceOutcomeError(
      "governance proposal response is not a JSON object, so this SDK cannot read its status",
      raw,
    );
  }
  const body = parsed as Record<string, unknown>;
  if (typeof body.status !== "string") {
    throw new UnknownGovernanceOutcomeError(
      "governance proposal response carries no string status",
      raw,
    );
  }
  const status = proposalStatusFromBridge(body.status);
  if (status === "Rejected" || status === "Invalidated") {
    if (typeof body.reason !== "string") {
      throw new UnknownGovernanceOutcomeError(
        `governance proposal response has status ${status} and no string reason`,
        raw,
      );
    }
    if (status === "Rejected") {
      rejectionReasonFromBridge(body.reason);
    }
  }
  const executionResult = body.execution_result;
  if (executionResult !== undefined && executionResult !== null) {
    if (typeof executionResult !== "string") {
      throw new UnknownGovernanceOutcomeError(
        "governance proposal response carries an execution_result that is neither a string nor null",
        raw,
      );
    }
    governanceActionResultFromBridge(executionResult);
  }
  return raw;
}

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

/**
 * Outlet semantic class (spec section 5.4.2). A Query outlet is a read-only
 * lookup; an Action outlet may cause side effects. Crosses the FFI wire as the
 * lowercase string `"query"` or `"action"` — identical across all four
 * bindings and the UCAN capability-stem preimage (SCP-OUT-014).
 */
export type OutletKind = "query" | "action";

/** Definition of an outlet that can be registered in a context. */
export interface OutletDefinition {
  /** Human-readable outlet name. */
  readonly name: string;
  /** Outlet description. */
  readonly description: string;
  /**
   * Outlet semantic class (spec section 5.4.2). REQUIRED — omitting `kind` is
   * a TypeScript compile error; the NAPI bridge re-enforces it at runtime.
   */
  readonly kind: OutletKind;
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

/** Per-invocation cost metadata for an outlet (spec section 5.4.1). */
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

/** Result of verifying an outlet against its test vectors. */
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

/** Result of invoking an outlet within a stateful session, with provenance metadata (spec section 6.2.1). */
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
  /**
   * Layer 3: attestations for the subject.
   *
   * {@link "./scp".SCP.evaluateTrust} always leaves this empty. That op takes
   * no attestation set and returns no attestation list, so an empty array here
   * reports that the op carries no Layer-3 list — it does NOT report that the
   * subject holds no attestations. Read
   * {@link BehavioralRecord.attestationCount} for the count the Rust core
   * computed, and call {@link "./scp".SCP.aggregateTrustInput} for the
   * verified attestation list. Python, Swift, and Kotlin leave the field empty
   * on the same op, so the shape matches across bindings (ADR-059 Decision 1).
   */
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
  readonly outletInvocationCount: number;
  /**
   * Whether {@link outletInvocationCount} is anchored in the canonical Merkle
   * log. `false` until ADR-051 makes `OutletInvoked` a convergent leaf
   * (§7.3.2; ADR-011 amendment exclusion taxonomy §2). Consumers MUST NOT
   * treat the count as Merkle-proven while this is `false`.
   */
  readonly outletInvocationCountAnchored: boolean;
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
   * The parallel of {@link outletInvocationCountAnchored}; consumers MUST NOT
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
  | "OutletInvocationCount"
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
  readonly outletInvocationCount: number;
  /**
   * Whether `outletInvocationCount` is anchored in the canonical Merkle log.
   *
   * `false` until ADR-051 makes `OutletInvoked` a convergent leaf: the count is
   * computed from per-author local events, not the Merkle log (§7.3.2; ADR-011
   * amendment exclusion taxonomy §2). Consumers MUST NOT treat the count as
   * Merkle-proven while this is `false`.
   */
  readonly outletInvocationCountAnchored: boolean;
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
      outlet_invocation_count: p.outletInvocationCount,
      outlet_invocation_count_anchored: p.outletInvocationCountAnchored,
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
 * - `"ChallengeVerified"` — a challenger the requirement trusts graded the
 *   capability (spec 07 §7.3.4). Also satisfies `SelfAttested`.
 */
export type VerificationLevel = "SelfAttested" | "ChallengeVerified";

/**
 * The loosest retry policy a requirement accepts in a record (spec 07
 * §7.3.4.4): a record whose `maxRetries` is above `maxRetries`, or whose
 * `cooldownSecs` is below `minCooldownSecs`, does not satisfy it.
 *
 * Mirrors the Rust `RetryCap` struct (`scp-core`).
 */
export interface RetryCap {
  /** The most retries after the first attempt a record may allow. */
  readonly maxRetries: number;
  /** The shortest cooldown, in seconds, a record may allow. */
  readonly minCooldownSecs: number;
}

/**
 * An admission requirement that the subject's self-attested capability list
 * meets (spec 07 §7.3.4.4). It names no verifiers and no retry cap.
 */
export interface SelfAttestedRequirement {
  /** Discriminant. */
  readonly kind: "SelfAttested";
  /** The capability URI that must be present. */
  readonly capability: string;
}

/**
 * An admission requirement that only a passing challenge record signed by
 * one of `trustedVerifiers` meets (spec 07 §7.3.4.4).
 */
export interface ChallengeVerifiedRequirement {
  /** Discriminant. */
  readonly kind: "ChallengeVerified";
  /** The capability URI that must be verified. */
  readonly capability: string;
  /**
   * DIDs of the challengers whose records satisfy the requirement; at least
   * one. The SDK refuses an empty list with {@link INVALID_REQUIREMENT_CODE}
   * before any bridge call.
   */
  readonly trustedVerifiers: readonly [string, ...string[]];
  /** The loosest retry policy a record may carry; absent accepts any. */
  readonly retryCap?: RetryCap;
}

/**
 * A single admission requirement of a context (spec 07 §7.3.4.4): either
 * {@link SelfAttestedRequirement} or {@link ChallengeVerifiedRequirement}.
 *
 * The SDK encodes it to the Rust `RawCapabilityRequirement` wire form. The
 * bridge refuses a verifier DID that is not the canonical spelling of its key
 * with {@link NON_CANONICAL_IDENTIFIER_CODE}.
 */
export type CapabilityRequirement = SelfAttestedRequirement | ChallengeVerifiedRequirement;

/**
 * A signed record of one graded challenge attempt (spec 07 §7.3.4, ADR-017).
 *
 * Mirrors the Rust `ChallengeVerification` struct (`scp-core`).
 * {@link SCP.trustGradeResponse} returns one for every attempt, pass or
 * fail; pass a list of them to {@link SCP.checkCapabilityRequirements} to
 * satisfy `ChallengeVerified` requirements.
 *
 * The verifier's signature covers every field except `verifierSignature`, so
 * altering any field invalidates the record.
 */
export interface ChallengeVerification {
  /** The record id, as 64 lowercase hex characters. */
  readonly verificationId: string;
  /** DID of the challenger who graded the attempt. */
  readonly verifier: string;
  /** DID of the subject who answered. */
  readonly subject: string;
  /** The capability URI that was tested. */
  readonly capabilityUri: string;
  /** Digest of the capability definition the challenge followed, as 64 lowercase hex characters. */
  readonly definitionDigest: string;
  /** Digest of the request's cases, as 64 lowercase hex characters. */
  readonly suiteDigest: string;
  /** The graded request's id, as 64 lowercase hex characters. */
  readonly challengeId: string;
  /** The attempt number, starting at 1. */
  readonly attempt: number;
  /** Digest of the graded response, as 64 lowercase hex characters. */
  readonly responseDigest: string;
  /** Retries after the first attempt the challenge allowed. */
  readonly maxRetries: number;
  /** Seconds the subject had to wait between attempts. */
  readonly cooldownSecs: number;
  /** Score in basis points at or above which an attempt passes. */
  readonly passThresholdBps: number;
  /** Fewest cases per category the definition requires (0 when it sets none). */
  readonly minCategoryCases: number;
  /** Whether the attempt passed. */
  readonly passed: boolean;
  /** Score in basis points, 0-10000 (10000 is perfect). */
  readonly score: number;
  /** Number of cases graded. */
  readonly testCount: number;
  /** Number of cases the subject passed. */
  readonly passCount: number;
  /** Unix seconds when the challenge was created. */
  readonly challengeCreatedAt: number;
  /** Unix seconds when the challenge stopped accepting attempts. */
  readonly challengeExpiresAt: number;
  /** Unix seconds when the attempt was graded. */
  readonly timestamp: number;
  /** Unix seconds when the record expires, at most 90 days after `timestamp`. */
  readonly expiresAt: number;
  /** The context where the challenge was administered. */
  readonly contextId: string;
  /** The verifier's 64-byte signature. */
  readonly verifierSignature: readonly number[];
}

/**
 * Encodes typed {@link CapabilityRequirement}s to the JSON wire form the Rust
 * bridge deserializes (`Vec<RawCapabilityRequirement>`):
 * `[{capability, verification_level, trusted_verifiers, retry_cap}]`, with
 * `trusted_verifiers: []` and `retry_cap: null` for a `SelfAttested`
 * requirement.
 *
 * Internal to the SDK: {@link SCP.contextCreate} and
 * {@link SCP.contextGovernanceModifyCapabilityRequirements} call it. It
 * checks every value at runtime, because a JavaScript caller bypasses the
 * types.
 *
 * @throws ValidationError {@link INVALID_REQUIREMENT_CODE} for a
 *   `ChallengeVerified` requirement with no trusted verifier, or a
 *   `SelfAttested` requirement that names verifiers or a retry cap;
 *   `SCP-VALID-7001` for any other malformed value.
 */
export function encodeCapabilityRequirements(requirements: readonly unknown[]): string {
  if (!Array.isArray(requirements)) {
    throw malformedRequirement("the requirements must be an array", requirements);
  }
  return JSON.stringify(requirements.map(encodeCapabilityRequirement));
}

function malformedRequirement(what: string, value: unknown): ValidationError {
  return new ValidationError(
    `CapabilityRequirement: ${what}, got ${JSON.stringify(value)}`,
    MALFORMED_SDK_INPUT_CODE,
  );
}

function encodeCapabilityRequirement(value: unknown): unknown {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw malformedRequirement("each requirement must be an object", value);
  }
  const r = value as Record<string, unknown>;
  if (typeof r.capability !== "string") {
    throw malformedRequirement("capability must be a string", r.capability);
  }
  switch (r.kind) {
    case "SelfAttested":
      if (r.trustedVerifiers !== undefined || r.retryCap !== undefined) {
        throw new ValidationError(
          "CapabilityRequirement: a SelfAttested requirement names no trusted verifiers and no retry cap",
          INVALID_REQUIREMENT_CODE,
        );
      }
      return {
        capability: r.capability,
        verification_level: "SelfAttested",
        trusted_verifiers: [],
        retry_cap: null,
      };
    case "ChallengeVerified": {
      const verifiers = r.trustedVerifiers;
      if (!Array.isArray(verifiers) || !verifiers.every((v) => typeof v === "string")) {
        throw malformedRequirement("trustedVerifiers must be an array of DID strings", verifiers);
      }
      if (verifiers.length === 0) {
        throw new ValidationError(
          "CapabilityRequirement: a ChallengeVerified requirement names at least one trusted verifier",
          INVALID_REQUIREMENT_CODE,
        );
      }
      return {
        capability: r.capability,
        verification_level: "ChallengeVerified",
        trusted_verifiers: verifiers,
        retry_cap: r.retryCap === undefined ? null : encodeRetryCap(r.retryCap),
      };
    }
    default:
      throw malformedRequirement('kind must be "SelfAttested" or "ChallengeVerified"', r.kind);
  }
}

function encodeRetryCap(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    throw malformedRequirement("retryCap must be an object", value);
  }
  const cap = value as Record<string, unknown>;
  for (const field of ["maxRetries", "minCooldownSecs"] as const) {
    const n = cap[field];
    if (typeof n !== "number" || !Number.isInteger(n) || n < 0 || n > U32_MAX) {
      throw malformedRequirement(`retryCap.${field} must be an integer in [0, ${U32_MAX}]`, n);
    }
  }
  return { max_retries: cap.maxRetries, min_cooldown_secs: cap.minCooldownSecs };
}

/** The code the SDK gives a malformed typed input it refuses before the bridge. */
const MALFORMED_SDK_INPUT_CODE = "SCP-VALID-7001";

const U32_MAX = 0xffff_ffff;

const LOWER_HEX_32 = /^[0-9a-f]{64}$/;

function requireLowerHex32(typeName: string, fieldName: string, value: unknown): string {
  if (typeof value !== "string" || !LOWER_HEX_32.test(value)) {
    throw new Error(
      `${typeName}.${fieldName} must be 64 lowercase hex characters, got ${JSON.stringify(value)}`,
    );
  }
  return value;
}

function requireUint(typeName: string, fieldName: string, value: unknown, max: number): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > max) {
    throw new Error(
      `${typeName}.${fieldName} must be an integer in [0, ${max}], got ${JSON.stringify(value)}`,
    );
  }
  return value;
}

function requireString(typeName: string, fieldName: string, value: unknown): string {
  if (typeof value !== "string") {
    throw new Error(`${typeName}.${fieldName} must be a string, got ${JSON.stringify(value)}`);
  }
  return value;
}

function requireSignature(typeName: string, fieldName: string, value: unknown): number[] {
  if (
    !Array.isArray(value) ||
    value.length !== 64 ||
    !value.every((b) => Number.isInteger(b) && b >= 0 && b <= 255)
  ) {
    throw new Error(`${typeName}.${fieldName} must be exactly 64 byte values`);
  }
  return value as number[];
}

function requireRecord(typeName: string, value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${typeName} must be a JSON object, got ${JSON.stringify(value)}`);
  }
  return value as Record<string, unknown>;
}

function requireArray(typeName: string, fieldName: string, value: unknown): unknown[] {
  if (!Array.isArray(value)) {
    throw new Error(`${typeName}.${fieldName} must be an array, got ${JSON.stringify(value)}`);
  }
  return value;
}

function challengeVerificationWire(v: ChallengeVerification): unknown {
  const t = "ChallengeVerification";
  requireByteLength(t, "verifierSignature", 64, v.verifierSignature);
  return {
    verification_id: requireLowerHex32(t, "verificationId", v.verificationId),
    verifier: v.verifier,
    subject: v.subject,
    capability_uri: v.capabilityUri,
    definition_digest: requireLowerHex32(t, "definitionDigest", v.definitionDigest),
    suite_digest: requireLowerHex32(t, "suiteDigest", v.suiteDigest),
    challenge_id: requireLowerHex32(t, "challengeId", v.challengeId),
    attempt: requireUint(t, "attempt", v.attempt, U32_MAX),
    response_digest: requireLowerHex32(t, "responseDigest", v.responseDigest),
    max_retries: requireUint(t, "maxRetries", v.maxRetries, U32_MAX),
    cooldown_secs: requireUint(t, "cooldownSecs", v.cooldownSecs, U32_MAX),
    pass_threshold_bps: requireUint(t, "passThresholdBps", v.passThresholdBps, U32_MAX),
    min_category_cases: requireUint(t, "minCategoryCases", v.minCategoryCases, U32_MAX),
    passed: v.passed,
    score: requireUint(t, "score", v.score, U32_MAX),
    test_count: requireUint(t, "testCount", v.testCount, U32_MAX),
    pass_count: requireUint(t, "passCount", v.passCount, U32_MAX),
    challenge_created_at: requireUint(
      t,
      "challengeCreatedAt",
      v.challengeCreatedAt,
      Number.MAX_SAFE_INTEGER,
    ),
    challenge_expires_at: requireUint(
      t,
      "challengeExpiresAt",
      v.challengeExpiresAt,
      Number.MAX_SAFE_INTEGER,
    ),
    timestamp: requireUint(t, "timestamp", v.timestamp, Number.MAX_SAFE_INTEGER),
    expires_at: requireUint(t, "expiresAt", v.expiresAt, Number.MAX_SAFE_INTEGER),
    context_id: v.contextId,
    verifier_signature: v.verifierSignature,
  };
}

/**
 * Encodes typed {@link ChallengeVerification}s to the JSON wire shape the
 * Rust bridge deserializes (`Vec<ChallengeVerification>`).
 *
 * @throws Error if `verifierSignature` is not exactly 64 elements, an id or
 *   digest is not 64 lowercase hex characters, or a number is out of its
 *   range (before any bridge call).
 */
export function encodeChallengeVerifications(
  verifications: readonly ChallengeVerification[],
): string {
  return JSON.stringify(verifications.map(challengeVerificationWire));
}

function challengeVerificationFromWire(value: unknown): ChallengeVerification {
  const t = "ChallengeVerification";
  const raw = requireRecord(t, value);
  return {
    verificationId: requireLowerHex32(t, "verification_id", raw.verification_id),
    verifier: requireString(t, "verifier", raw.verifier),
    subject: requireString(t, "subject", raw.subject),
    capabilityUri: requireString(t, "capability_uri", raw.capability_uri),
    definitionDigest: requireLowerHex32(t, "definition_digest", raw.definition_digest),
    suiteDigest: requireLowerHex32(t, "suite_digest", raw.suite_digest),
    challengeId: requireLowerHex32(t, "challenge_id", raw.challenge_id),
    attempt: requireUint(t, "attempt", raw.attempt, U32_MAX),
    responseDigest: requireLowerHex32(t, "response_digest", raw.response_digest),
    maxRetries: requireUint(t, "max_retries", raw.max_retries, U32_MAX),
    cooldownSecs: requireUint(t, "cooldown_secs", raw.cooldown_secs, U32_MAX),
    passThresholdBps: requireUint(t, "pass_threshold_bps", raw.pass_threshold_bps, U32_MAX),
    minCategoryCases: requireUint(t, "min_category_cases", raw.min_category_cases, U32_MAX),
    passed: requireBoolean(t, "passed", raw.passed),
    score: requireUint(t, "score", raw.score, 10_000),
    testCount: requireUint(t, "test_count", raw.test_count, U32_MAX),
    passCount: requireUint(t, "pass_count", raw.pass_count, U32_MAX),
    challengeCreatedAt: requireUint(
      t,
      "challenge_created_at",
      raw.challenge_created_at,
      Number.MAX_SAFE_INTEGER,
    ),
    challengeExpiresAt: requireUint(
      t,
      "challenge_expires_at",
      raw.challenge_expires_at,
      Number.MAX_SAFE_INTEGER,
    ),
    timestamp: requireUint(t, "timestamp", raw.timestamp, Number.MAX_SAFE_INTEGER),
    expiresAt: requireUint(t, "expires_at", raw.expires_at, Number.MAX_SAFE_INTEGER),
    contextId: requireString(t, "context_id", raw.context_id),
    verifierSignature: requireSignature(t, "verifier_signature", raw.verifier_signature),
  };
}

/**
 * Decodes the Rust `ChallengeVerification` JSON into a typed
 * {@link ChallengeVerification}.
 *
 * @throws Error if a field is missing or out of range: a non-hex id or
 *   digest, a count outside u32, a score above 10000, or a signature that is
 *   not 64 bytes.
 */
export function decodeChallengeVerification(json: string): ChallengeVerification {
  return challengeVerificationFromWire(JSON.parse(json));
}

function requireBoolean(typeName: string, fieldName: string, value: unknown): boolean {
  if (typeof value !== "boolean") {
    throw new Error(`${typeName}.${fieldName} must be a boolean, got ${JSON.stringify(value)}`);
  }
  return value;
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
  | "OutletIntegrity"
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
  "OutletIntegrity",
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

// Challenge and admission error codes. Each maps from the Rust variants its
// comment names, through `trust_error_code` and `admission_error_code` in
// `scp-ffi-common` (`error_codes.rs`).

/**
 * A signer's key could not be resolved: the instance has no DID resolver, or a
 * supplied `ChallengeVerification` could not be checked (DID resolution
 * failed, spec 03). Maps from `AdmissionError::VerificationUnavailable` and a
 * missing instance resolver.
 */
export const DID_RESOLUTION_FAILED_CODE = "SCP-IDENT-1033";

/**
 * The registry's JSON schema validation error, which the bridges also raise
 * for every trust error without a code of its own: a challenge, response or
 * verification whose signature does not verify, a record bound to another
 * verifier, subject, context or window, a caller who is not a member or has
 * not opted in, or a failed ledger write. Maps from each `TrustError` variant
 * `trust_error_code` does not name.
 */
export const JSON_SCHEMA_VALIDATION_FAILED_CODE = "SCP-VALID-7003";

/**
 * Code the bridge raises when a protocol capability URI's request has fewer
 * test cases than the URI's standard requires (spec 07 §7.3.4.3; for
 * `scp:capability:multilingual/v1`, fewer than five cases in some
 * `category`). Maps from `TrustError::ChallengeSuiteBelowMinimum`.
 */
export const CHALLENGE_SUITE_BELOW_MINIMUM_CODE = "SCP-VALID-7039";

/**
 * The agent capabilities JSON of a capability admission check does not decode
 * as a list of capability URIs.
 */
export const MALFORMED_AGENT_CAPABILITIES_CODE = "SCP-VALID-7074";

/**
 * The challenge verifications JSON of a capability admission check does not
 * decode as a list of `ChallengeVerification` records.
 */
export const MALFORMED_CHALLENGE_VERIFICATIONS_CODE = "SCP-VALID-7075";

/**
 * A capability requirement is unmet: the subject lacks a required capability,
 * or a `ChallengeVerified` requirement has no record that admits the subject.
 * Maps from `AdmissionError::MissingCapability` and
 * `AdmissionError::VerificationRequired`.
 */
export const ADMISSION_REQUIREMENT_UNMET_CODE = "SCP-VALID-7076";

/**
 * A capability admission check names an empty subject DID. Maps from
 * `AdmissionError::EmptySubjectDid`.
 */
export const EMPTY_SUBJECT_DID_CODE = "SCP-VALID-7077";

/**
 * Code the bridge raises when the challenger's ledger already holds the most
 * open challenges it may hold, so it opens no new one; retry after one
 * closes. Maps from `TrustError::ChallengeNotOpen`.
 */
export const CHALLENGE_NOT_OPEN_CODE = "SCP-VALID-7099";

/**
 * Code the bridge raises when a response or a grading falls outside the
 * challenge window. Maps from `TrustError::ChallengeExpired`.
 */
export const CHALLENGE_EXPIRED_CODE = "SCP-VALID-7102";

/**
 * Code the bridge raises when an attempt number is not the last graded
 * attempt plus one. Maps from `TrustError::AttemptOutOfOrder`.
 */
export const ATTEMPT_OUT_OF_ORDER_CODE = "SCP-VALID-7103";

/**
 * Code the bridge raises when an attempt number exceeds `1 + maxRetries`.
 * Maps from `TrustError::RetriesExhausted`.
 */
export const RETRIES_EXHAUSTED_CODE = "SCP-VALID-7104";

/**
 * Code the bridge raises when the cooldown since the last graded attempt or
 * grading fault has not passed; {@link retryAfter} reads the first second the
 * next attempt is accepted. Maps from `TrustError::CooldownActive`.
 */
export const COOLDOWN_ACTIVE_CODE = "SCP-VALID-7105";

/**
 * Code the bridge raises when the challenge closed after a pass or after its
 * last allowed attempt. Maps from `TrustError::ChallengeClosed`.
 */
export const CHALLENGE_CLOSED_CODE = "SCP-VALID-7106";

/**
 * Code the bridge raises when the challenger's ledger holds no live challenge
 * with the request's id, request digest and subject. Maps from
 * `TrustError::UnknownChallenge`.
 */
export const UNKNOWN_CHALLENGE_CODE = "SCP-VALID-7107";

/**
 * Code the bridge raises when a response names another challenge or request
 * digest, or its outputs do not match the cases one for one and in order.
 * Maps from `TrustError::OutputsMismatch`.
 */
export const OUTPUTS_MISMATCH_CODE = "SCP-VALID-7108";

/**
 * Code the bridge raises when a `CustomEval` evaluator outlet is unregistered
 * in its evaluator context, has no handler, or may not be called by the
 * challenger. Maps from `TrustError::EvaluatorUnavailable`.
 */
export const EVALUATOR_UNAVAILABLE_CODE = "SCP-VALID-7109";

/**
 * A required capability has no passing record from a trusted challenger: the
 * only passing record comes from a verifier the requirement does not trust.
 * Maps from `AdmissionError::UntrustedVerifier`.
 */
export const UNTRUSTED_VERIFIER_CODE = "SCP-VALID-7121";

/**
 * Code the bridge raises when the challenger and the subject decode to the
 * same key. Maps from `TrustError::SelfChallenge` and
 * `AdmissionError::SelfChallenge`.
 */
export const SELF_CHALLENGE_CODE = "SCP-VALID-7127";

/**
 * Code the bridge raises when the capability URI names a standard whose pass
 * condition cannot be computed from the subject's outputs, or a system
 * capability (`scp:system:*`). Maps from `TrustError::StandardNotGradable`.
 */
export const STANDARD_NOT_GRADABLE_CODE = "SCP-VALID-7128";

/**
 * Code the bridge raises when no capability definition can be obtained for
 * the capability URI; the code reports an outage, not a judgment on the
 * subject. Maps from `TrustError::CapabilityDefinitionUnavailable`.
 */
export const CAPABILITY_DEFINITION_UNAVAILABLE_CODE = "SCP-VALID-7129";

/**
 * Code the bridge raises when a policy value lies outside the capability
 * definition's limits or the protocol bounds, or a record allows more retries
 * or a shorter cooldown than a requirement's retry cap. Maps from
 * `TrustError::PolicyOutsideDefinition` and
 * `AdmissionError::RetryCapExceeded`.
 */
export const POLICY_OUTSIDE_DEFINITION_CODE = "SCP-VALID-7137";

/**
 * Code the bridge raises when a `SchemaMatch` case's schema is not
 * admissible. Maps from `TrustError::SchemaRejected`.
 */
export const SCHEMA_REJECTED_CODE = "SCP-VALID-7138";

/**
 * Code the bridge raises when another grading of the same challenge holds a
 * live lease; retry later. Maps from `TrustError::GradingInProgress`.
 */
export const GRADING_IN_PROGRESS_CODE = "SCP-VALID-7139";

/**
 * Code the bridge raises when a response exceeds the protocol's byte or JSON
 * depth limit. Maps from `TrustError::ResponseTooLarge`.
 */
export const RESPONSE_TOO_LARGE_CODE = "SCP-VALID-7143";

/**
 * Code the bridge raises when two validly signed capability definitions for
 * one URI differ. Maps from `TrustError::DefinitionEquivocation`.
 */
export const DEFINITION_EQUIVOCATION_CODE = "SCP-VALID-7144";

/**
 * Code the bridge raises when every grading permit of the challenger is held;
 * retry the grading later. Maps from `TrustError::GradingCapacityExhausted`.
 */
export const GRADING_CAPACITY_EXHAUSTED_CODE = "SCP-VALID-7146";

/**
 * Code the bridge raises when a DID is not the canonical spelling of its key
 * (a challenger, a subject, or a requirement's trusted verifier). Maps from
 * `TrustError::NonCanonicalIdentifier` and
 * `AdmissionError::NonCanonicalIdentifier`.
 */
export const NON_CANONICAL_IDENTIFIER_CODE = "SCP-VALID-7147";

/**
 * Code the bridge raises when a context names more capability requirements
 * than the protocol allows. Maps from
 * `AdmissionError::TooManyCapabilityRequirements`.
 */
export const TOO_MANY_CAPABILITY_REQUIREMENTS_CODE = "SCP-VALID-7148";

/**
 * Code the bridge raises when a grading's lease expired or was replaced
 * before its commit; nothing was written, and the grading may be retried.
 * Maps from `TrustError::GradingLeaseLost`.
 */
export const GRADING_LEASE_LOST_CODE = "SCP-VALID-7149";

/**
 * Code the bridge raises when a capability requirement breaks a spec 07
 * §7.3.4.4 rule, such as a `ChallengeVerified` requirement with no trusted
 * verifier; the SDK raises it too, before the bridge. Maps from
 * `AdmissionError::InvalidRequirement`.
 */
export const INVALID_REQUIREMENT_CODE = "SCP-VALID-7150";

/**
 * Code the bridge raises when the challenger's last challenge to this subject
 * for this capability is still inside its window; {@link retryAfter} reads
 * the second a new one may be created. Maps from
 * `TrustError::ChallengeWindowOpen`.
 */
export const CHALLENGE_WINDOW_OPEN_CODE = "SCP-VALID-7151";

/**
 * Code the bridge raises when an attempt is graded in the second its
 * challenge was created; {@link retryAfter} reads the first second grading
 * may succeed. Maps from `TrustError::ChallengeNotYetGradable`.
 */
export const CHALLENGE_NOT_YET_GRADABLE_CODE = "SCP-VALID-7153";

const RETRYABLE_CODES: ReadonlySet<string> = new Set([
  CHALLENGE_NOT_OPEN_CODE,
  COOLDOWN_ACTIVE_CODE,
  GRADING_IN_PROGRESS_CODE,
  GRADING_CAPACITY_EXHAUSTED_CODE,
  GRADING_LEASE_LOST_CODE,
  CHALLENGE_WINDOW_OPEN_CODE,
  CHALLENGE_NOT_YET_GRADABLE_CODE,
]);

/**
 * Reports whether a challenge refusal with `code` may succeed when the same
 * call is made again later: true for {@link CHALLENGE_NOT_OPEN_CODE},
 * {@link COOLDOWN_ACTIVE_CODE}, {@link GRADING_IN_PROGRESS_CODE},
 * {@link GRADING_CAPACITY_EXHAUSTED_CODE}, {@link GRADING_LEASE_LOST_CODE},
 * {@link CHALLENGE_WINDOW_OPEN_CODE} and {@link CHALLENGE_NOT_YET_GRADABLE_CODE},
 * and false for every other code.
 */
export function isRetryable(code: string): boolean {
  return RETRYABLE_CODES.has(code);
}

const RETRY_AFTER_SUFFIX = /\(retry_after=(\d+)\)/g;

/**
 * The first Unix second at which a refused challenge call may succeed, read
 * from the `(retry_after=N)` suffix the bridge appends to the message of a
 * {@link COOLDOWN_ACTIVE_CODE}, {@link CHALLENGE_WINDOW_OPEN_CODE} or
 * {@link CHALLENGE_NOT_YET_GRADABLE_CODE} refusal. Returns `null` when the
 * message of `error` (an `Error`, or a message string) carries no suffix.
 */
export function retryAfter(error: unknown): number | null {
  const message = typeof error === "string" ? error : error instanceof Error ? error.message : null;
  if (message === null) {
    return null;
  }
  let seconds: number | null = null;
  for (const match of message.matchAll(RETRY_AFTER_SUFFIX)) {
    const n = Number(match[1]);
    seconds = Number.isSafeInteger(n) ? n : null;
  }
  return seconds;
}

/**
 * What a test case's output must satisfy (spec 07 §7.3.4). Encoded
 * externally tagged, `{"<Variant>": {<fields>}}`, the Rust `ExpectedOutput`
 * wire form. `CustomEval` names an evaluator outlet the challenger chooses,
 * and the context where the challenger calls it; the SDK ships no evaluator.
 */
export type ExpectedOutput =
  | { readonly kind: "ExactMatch"; readonly value: unknown }
  | { readonly kind: "SchemaMatch"; readonly schema: unknown }
  | { readonly kind: "ContainsAll"; readonly required: readonly string[] }
  | { readonly kind: "ContainsNone"; readonly forbidden: readonly string[] }
  | {
      readonly kind: "CustomEval";
      /** The evaluator outlet that grades the case. */
      readonly evaluatorOutletId: string;
      /**
       * The context where the challenger calls `evaluatorOutletId`. Every
       * `CustomEval` case of one challenge names the same context; the
       * wire form of the case does not carry it.
       */
      readonly evaluatorContextId: string;
    };

/**
 * One test case of a challenge with its answer, written by the challenger
 * (spec 07 §7.3.4). The answer never leaves the challenger: the request
 * carries a {@link ChallengeCase}, which has no answer.
 *
 * A request's weights sum to 10000. Numbers in `input` and in the expected
 * output must lie within ±(2^53 - 1) (I-JSON); the bridge refuses others.
 * For `scp:capability:multilingual/v1`, `category` is a BCP 47 language tag
 * and each distinct category needs at least five cases.
 */
export interface TestCase {
  /** Identifier, unique within the request. */
  readonly testId: string;
  /** JSON input given to the subject. */
  readonly input: unknown;
  /** What constitutes passing this case. */
  readonly expected: ExpectedOutput;
  /** Test category. */
  readonly category: string;
  /** Importance weight in basis points. */
  readonly weight: number;
}

/**
 * One test case as the signed request carries it: the input, never the
 * answer (spec 07 §7.3.4).
 *
 * Mirrors the Rust `ChallengeCase` struct (`scp-core`).
 */
export interface ChallengeCase {
  /** Identifier, unique within the request. */
  readonly testId: string;
  /** JSON input given to the subject. */
  readonly input: unknown;
  /** Test category. */
  readonly category: string;
  /** Importance weight in basis points. */
  readonly weight: number;
}

/**
 * A challenger's retry policy for one challenge (spec 07 §7.3.4.6). A policy
 * may only tighten the capability definition, on any URI: at most the
 * definition's retries, and at least its cooldown. An absent field takes the
 * definition's value, and omitting the policy takes both.
 */
export interface ChallengePolicy {
  /** Retries after the first attempt; at most the definition's. */
  readonly maxRetries?: number;
  /** Seconds between graded attempts; at least the definition's. */
  readonly cooldownSecs?: number;
}

/** The one argument of {@link SCP.trustCreateChallenge}. */
export interface CreateChallengeConfig {
  /** The challenger: an identity of this instance, whose custody signs the request. */
  readonly verifier: Identity;
  /** DID of the identity being challenged. */
  readonly subject: string;
  /** The capability URI under test, in canonical form. */
  readonly capabilityUri: string;
  /**
   * The challenger-written cases, with their answers; their weights sum to
   * 10000. Every `CustomEval` case names the same `evaluatorContextId`.
   */
  readonly testCases: readonly TestCase[];
  /** The context where the challenge is administered. */
  readonly contextId: string;
  /** The grading window: seconds from creation during which attempts are graded. */
  readonly windowSecs: number;
  /** A retry policy that tightens the capability definition's; omit to take the definition's. */
  readonly policy?: ChallengePolicy;
}

/**
 * The one evaluator context the `CustomEval` cases of `testCases` name, or
 * `undefined` when no case is `CustomEval`.
 *
 * @throws ValidationError `SCP-VALID-7001` when two cases name different
 *   evaluator contexts, or a `CustomEval` case names none.
 */
export function evaluatorContextOf(testCases: readonly TestCase[]): string | undefined {
  let context: string | undefined;
  for (const c of testCases) {
    if (c.expected.kind !== "CustomEval") {
      continue;
    }
    const id: unknown = c.expected.evaluatorContextId;
    if (typeof id !== "string" || id.length === 0) {
      throw new ValidationError(
        `TestCase ${JSON.stringify(c.testId)}: a CustomEval case must name its evaluatorContextId`,
        MALFORMED_SDK_INPUT_CODE,
      );
    }
    if (context !== undefined && context !== id) {
      throw new ValidationError(
        `TestCase ${JSON.stringify(c.testId)}: CustomEval cases of one challenge name one evaluator context, got ${JSON.stringify(context)} and ${JSON.stringify(id)}`,
        MALFORMED_SDK_INPUT_CODE,
      );
    }
    context = id;
  }
  return context;
}

/**
 * A signed challenge request (spec 07 §7.3.4, ADR-017).
 *
 * Mirrors the Rust `ChallengeRequest` struct (`scp-core`). The challenger's
 * signature covers every other field, so pass the request back to the
 * bridge unchanged.
 */
export interface ChallengeRequest {
  /** The 32-byte random id as 64 lowercase hex characters. */
  readonly challengeId: string;
  /** The capability URI under test (spec 07 §7.3.4.1). */
  readonly capabilityUri: string;
  /** Digest of the capability definition the challenge follows, as 64 lowercase hex characters. */
  readonly definitionDigest: string;
  /** The cases, without their answers. */
  readonly testCases: readonly ChallengeCase[];
  /** Unix seconds when the challenge was created. */
  readonly createdAt: number;
  /** Unix seconds after which no attempt is graded. */
  readonly expiresAt: number;
  /** Retries after the first attempt. */
  readonly maxRetries: number;
  /** Seconds the subject waits between attempts. */
  readonly cooldownSecs: number;
  /** Score in basis points at or above which an attempt passes. */
  readonly passThresholdBps: number;
  /** The context where the challenge is administered. */
  readonly contextId: string;
  /** DID of the challenger. */
  readonly verifier: string;
  /** DID of the subject. */
  readonly subject: string;
  /** The challenger's 64-byte signature. */
  readonly verifierSignature: readonly number[];
}

/** The subject's output for one case. Mirrors the Rust `TestOutput` struct. */
export interface TestOutput {
  /** The case's `testId`. */
  readonly testId: string;
  /** The subject's JSON output for the case. */
  readonly output: unknown;
}

/**
 * The subject's signed answers to one attempt of a challenge (spec 07
 * §7.3.4 step 2, ADR-017).
 *
 * Mirrors the Rust `ChallengeResponse` struct (`scp-core`).
 * {@link SCP.trustRespondToChallenge} builds and signs it.
 */
export interface ChallengeResponse {
  /** The request's `challengeId`. */
  readonly challengeId: string;
  /** Digest of the signed request, as 64 lowercase hex characters. */
  readonly requestDigest: string;
  /** DID of the subject. */
  readonly subject: string;
  /** The attempt number, starting at 1. */
  readonly attempt: number;
  /** One output per case. */
  readonly outputs: readonly TestOutput[];
  /** The subject's 64-byte signature. */
  readonly subjectSignature: readonly number[];
}

/** The grade of one case. Mirrors the Rust `CaseResult` struct; never signed. */
export interface CaseResult {
  /** Whether the case passed. */
  readonly passed: boolean;
  /** Why it failed, or the evaluator's reason, when there is one. */
  readonly reason: string | null;
}

/** What {@link SCP.trustGradeResponse} returns. */
export interface GradedChallenge {
  /** The signed record of the attempt, pass or fail. */
  readonly record: ChallengeVerification;
  /** The per-case grades, in request order; not signed. */
  readonly caseResults: readonly CaseResult[];
  /**
   * Why the record could not be written to this instance's trust store, with
   * its error code, when it could not. The record is signed and the attempt
   * used either way.
   */
  readonly trustStoreError: { readonly code: string; readonly message: string } | null;
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

function encodeExpectedOutput(expected: ExpectedOutput): unknown {
  switch (expected.kind) {
    case "ExactMatch":
      return { ExactMatch: { value: expected.value } };
    case "SchemaMatch":
      return { SchemaMatch: { schema: expected.schema } };
    case "ContainsAll":
      return { ContainsAll: { required: expected.required } };
    case "ContainsNone":
      return { ContainsNone: { forbidden: expected.forbidden } };
    case "CustomEval":
      return { CustomEval: { evaluator_outlet_id: expected.evaluatorOutletId } };
    default: {
      const exhaustive: never = expected;
      throw new Error(`unknown ExpectedOutput kind: ${JSON.stringify(exhaustive)}`);
    }
  }
}

/**
 * Encodes typed {@link TestCase}s to the JSON wire shape the Rust bridge
 * deserializes (`Vec<TestCase>`).
 *
 * @throws Error if a `weight` is not an integer in the u32 range.
 */
export function encodeTestCases(testCases: readonly TestCase[]): string {
  return JSON.stringify(
    testCases.map((c) => ({
      test_id: c.testId,
      input: c.input,
      expected: encodeExpectedOutput(c.expected),
      category: c.category,
      weight: requireUint("TestCase", "weight", c.weight, U32_MAX),
    })),
  );
}

/** Encodes typed {@link TestOutput}s to the Rust `Vec<TestOutput>` wire shape. */
export function encodeTestOutputs(outputs: readonly TestOutput[]): string {
  return JSON.stringify(outputs.map((o) => ({ test_id: o.testId, output: o.output })));
}

/**
 * Encodes a typed {@link ChallengeRequest} to the JSON wire shape the Rust
 * bridge deserializes (`ChallengeRequest`).
 *
 * @throws Error if `verifierSignature` is not exactly 64 elements, an id
 *   or digest is not 64 lowercase hex characters, or a number is
 *   out of its range (before any bridge call).
 */
export function encodeChallengeRequest(request: ChallengeRequest): string {
  const t = "ChallengeRequest";
  requireByteLength(t, "verifierSignature", 64, request.verifierSignature);
  return JSON.stringify({
    challenge_id: requireLowerHex32(t, "challengeId", request.challengeId),
    capability_uri: request.capabilityUri,
    definition_digest: requireLowerHex32(t, "definitionDigest", request.definitionDigest),
    test_cases: request.testCases.map((c) => ({
      test_id: c.testId,
      input: c.input,
      category: c.category,
      weight: requireUint("ChallengeCase", "weight", c.weight, U32_MAX),
    })),
    created_at: requireUint(t, "createdAt", request.createdAt, Number.MAX_SAFE_INTEGER),
    expires_at: requireUint(t, "expiresAt", request.expiresAt, Number.MAX_SAFE_INTEGER),
    max_retries: requireUint(t, "maxRetries", request.maxRetries, U32_MAX),
    cooldown_secs: requireUint(t, "cooldownSecs", request.cooldownSecs, U32_MAX),
    pass_threshold_bps: requireUint(t, "passThresholdBps", request.passThresholdBps, U32_MAX),
    context_id: request.contextId,
    verifier: request.verifier,
    subject: request.subject,
    verifier_signature: request.verifierSignature,
  });
}

/**
 * Decodes the signed request JSON the bridge returns into a typed
 * {@link ChallengeRequest}.
 *
 * @throws Error if a field is missing or malformed.
 */
export function decodeChallengeRequest(json: string): ChallengeRequest {
  const t = "ChallengeRequest";
  const raw = requireRecord(t, JSON.parse(json));
  return {
    challengeId: requireLowerHex32(t, "challenge_id", raw.challenge_id),
    capabilityUri: requireString(t, "capability_uri", raw.capability_uri),
    definitionDigest: requireLowerHex32(t, "definition_digest", raw.definition_digest),
    testCases: requireArray(t, "test_cases", raw.test_cases).map((value) => {
      const c = requireRecord("ChallengeCase", value);
      return {
        testId: requireString("ChallengeCase", "test_id", c.test_id),
        input: c.input,
        category: requireString("ChallengeCase", "category", c.category),
        weight: requireUint("ChallengeCase", "weight", c.weight, U32_MAX),
      };
    }),
    createdAt: requireUint(t, "created_at", raw.created_at, Number.MAX_SAFE_INTEGER),
    expiresAt: requireUint(t, "expires_at", raw.expires_at, Number.MAX_SAFE_INTEGER),
    maxRetries: requireUint(t, "max_retries", raw.max_retries, U32_MAX),
    cooldownSecs: requireUint(t, "cooldown_secs", raw.cooldown_secs, U32_MAX),
    passThresholdBps: requireUint(t, "pass_threshold_bps", raw.pass_threshold_bps, U32_MAX),
    contextId: requireString(t, "context_id", raw.context_id),
    verifier: requireString(t, "verifier", raw.verifier),
    subject: requireString(t, "subject", raw.subject),
    verifierSignature: requireSignature(t, "verifier_signature", raw.verifier_signature),
  };
}

/**
 * Encodes a typed {@link ChallengeResponse} to the JSON wire shape the Rust
 * bridge deserializes (`ChallengeResponse`).
 *
 * @throws Error if `subjectSignature` is not exactly 64 elements, an id or
 *   digest is not 64 lowercase hex characters, or `attempt` is out of the
 *   u32 range (before any bridge call).
 */
export function encodeChallengeResponse(response: ChallengeResponse): string {
  const t = "ChallengeResponse";
  requireByteLength(t, "subjectSignature", 64, response.subjectSignature);
  return JSON.stringify({
    challenge_id: requireLowerHex32(t, "challengeId", response.challengeId),
    request_digest: requireLowerHex32(t, "requestDigest", response.requestDigest),
    subject: response.subject,
    attempt: requireUint(t, "attempt", response.attempt, U32_MAX),
    outputs: response.outputs.map((o) => ({ test_id: o.testId, output: o.output })),
    subject_signature: response.subjectSignature,
  });
}

/**
 * Decodes the signed response JSON the bridge returns into a typed
 * {@link ChallengeResponse}.
 *
 * @throws Error if a field is missing or malformed.
 */
export function decodeChallengeResponse(json: string): ChallengeResponse {
  const t = "ChallengeResponse";
  const raw = requireRecord(t, JSON.parse(json));
  return {
    challengeId: requireLowerHex32(t, "challenge_id", raw.challenge_id),
    requestDigest: requireLowerHex32(t, "request_digest", raw.request_digest),
    subject: requireString(t, "subject", raw.subject),
    attempt: requireUint(t, "attempt", raw.attempt, U32_MAX),
    outputs: requireArray(t, "outputs", raw.outputs).map((value) => {
      const o = requireRecord("TestOutput", value);
      return { testId: requireString("TestOutput", "test_id", o.test_id), output: o.output };
    }),
    subjectSignature: requireSignature(t, "subject_signature", raw.subject_signature),
  };
}

/**
 * Decodes the bridge's per-case grades (JSON array of the Rust `CaseResult`).
 *
 * @throws Error if an entry is malformed.
 */
export function decodeCaseResults(json: string): CaseResult[] {
  return requireArray("CaseResults", "", JSON.parse(json)).map((value) => {
    const c = requireRecord("CaseResult", value);
    const reason = c.reason ?? null;
    return {
      passed: requireBoolean("CaseResult", "passed", c.passed),
      reason: reason === null ? null : requireString("CaseResult", "reason", reason),
    };
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
