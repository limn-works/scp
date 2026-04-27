//! Context parameter types for SCP context creation and governance.
//!
//! Defines [`ContextParams`] and its constituent types: [`ContextMode`],
//! [`CeilingPolicy`], [`PromotionPolicy`], [`MemoryScope`], [`GovernanceModel`],
//! [`TemplateId`], [`FieldVisibility`], [`MetadataVisibilityPolicy`],
//! [`ProjectionRule`], [`ProjectionOverride`], [`ProjectionPolicy`],
//! [`PublicMetadata`], and [`RuntimeMetadata`].
//! These types capture the full configuration surface of an SCP context at
//! creation time. [`PublicMetadata`] is the filtered projection returned by
//! [`ContextParams::public_metadata()`] for pre-join observers (spec §5.7).
//! See ADR-008 in `.docs/adrs/phase-2.md`.

use std::time::Duration;

use scp_primitives::DID;
use serde::{Deserialize, Serialize};

use crate::bridge::BridgeMode;
use crate::economy::{Amount, EconomicPolicy};
use crate::provenance::CounterpartyPolicy;
use crate::trust::RequireParticipation;

pub use super::close::IncompleteVerificationPolicy;

// ---------------------------------------------------------------------------
// Capability (unified type from roles module)
// ---------------------------------------------------------------------------

/// Re-export of the unified [`Capability`] type.
///
/// This was previously a separate `Capability(String)` newtype. It is now the
/// same enum used in `roles.rs`, supporting well-known variants (e.g.,
/// `MessagesRead`, `MessagesWrite`) plus `Custom(String)`. Use
/// [`Capability::new`] to construct from a string name.
pub use super::roles::Capability;

// ---------------------------------------------------------------------------
// RoleDefinition (re-export from roles module)
// ---------------------------------------------------------------------------

/// Re-export of the full [`RoleDefinition`] type from `roles.rs`,
/// which includes `name` and `capabilities: HashSet<Capability>`.
/// See ADR-009 in `.docs/adrs/phase-2.md`.
pub use super::roles::RoleDefinition;

// ---------------------------------------------------------------------------
// OutletRegistration (re-export from tools/registry module)
// ---------------------------------------------------------------------------

/// Re-export of the full [`OutletRegistration`] type from
/// `tools/registry.rs`, which includes `outlet_id`, `name`,
/// `description`, `schema`, `implementation_hash`, `test_vectors`,
/// `operator_did`, and `cost`. See ADR-010 in
/// `.docs/adrs/phase-2.md`.
pub use super::outlets::OutletRegistration;

// ---------------------------------------------------------------------------
// OutletInterfaceDefaults (re-export — spec §6.2.0.2 classification-aware
// rate tiers, SCP-OUT-016)
// ---------------------------------------------------------------------------

/// Re-export of [`super::outlets::interface::OutletInterfaceDefaults`] —
/// the §6.2.0.2 classification-aware cross-context rate-tier defaults.
///
/// `OutletInterfaceDefaults::for_kind(OutletKind::Query)` returns
/// `(per_interface = 600, per_caller = 100)`;
/// `OutletInterfaceDefaults::for_kind(OutletKind::Action)` returns
/// `(60, 10)` — the pre-classification baseline preserved for the Action
/// tier per §6.2.0.2. Callers MUST use this helper rather than hardcoding
/// `60` or `600` so a future spec revision that adjusts the tiers updates
/// one helper and every call site follows.
///
/// See [`super::outlets::interface::OutletInterfaceDefaults`] and
/// SCP-OUT-016 for full rationale.
pub use super::outlets::interface::OutletInterfaceDefaults;

// ---------------------------------------------------------------------------
// ContextMode
// ---------------------------------------------------------------------------

/// Context processing mode. Immutable after creation.
///
/// Determines the encryption strategy for the context:
/// - [`Encrypted`](ContextMode::Encrypted): Full MLS-backed encryption with
///   sender-side keys and forward secrecy. This is the default and recommended
///   mode for private contexts.
/// - [`Broadcast`](ContextMode::Broadcast): Per-author AES-256-GCM broadcast
///   keys without MLS group creation. Designed for one-to-many publishing
///   scenarios with unlimited subscriber count. See spec section 5.14.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContextMode {
    /// MLS-backed encryption with sender-side keys and full forward secrecy.
    /// This is the default mode.
    #[default]
    Encrypted,
    /// Per-author AES-256-GCM broadcast keys. No MLS group is created.
    /// Subscriber count is unlimited. See spec section 5.14.
    Broadcast,
}

// ---------------------------------------------------------------------------
// CeilingPolicy
// ---------------------------------------------------------------------------

/// Ceiling mutability policy. Declared at creation, immutable thereafter.
///
/// Determines whether the capability ceiling can be modified after context
/// creation. See ADR-008 and spec section 5.3.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum CeilingPolicy {
    /// Ceiling is fixed at creation. Any attempt to modify returns
    /// `ContextError::CeilingImmutable`. This is the default and the
    /// security-conservative choice -- members see the ceiling before
    /// joining, and it cannot change (no bait-and-switch).
    #[default]
    Immutable,
    /// Ceiling can be modified through the context's governance model
    /// (admin, multi-sig, consensus). Changes are logged in the event
    /// log and visible to all members before taking effect. Members who
    /// joined under a narrower ceiling are notified and may leave before
    /// an expansion takes effect. See spec section 5.3.
    Governed,
}

// ---------------------------------------------------------------------------
// PromotionPolicy
// ---------------------------------------------------------------------------

/// Context promotion policy. Declared at creation, immutable thereafter.
///
/// Controls whether a context can be promoted (e.g., from ephemeral to
/// persistent, or from child to standalone). See ADR-008.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PromotionPolicy {
    /// Context cannot be promoted. Immutable lifecycle constraints.
    NoPromotion,
    /// Context can be promoted through governance approval. Promotion
    /// conditions and requirements are governed by the context's
    /// governance model.
    Promotable,
}

// ---------------------------------------------------------------------------
// MemoryScope
// ---------------------------------------------------------------------------

/// Memory scope for a context, controlling data retention behavior after
/// context closure.
///
/// - [`Ephemeral`](MemoryScope::Ephemeral): All data is destroyed on close.
///   Keys are destroyed immediately, making content physically unreadable.
/// - [`Summary`](MemoryScope::Summary): A verified summary is generated during
///   the closing window, then keys are destroyed. Only the summary persists.
/// - [`Full`](MemoryScope::Full): All data and keys are retained after close.
///   Content remains readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryScope {
    /// All data is destroyed on context close. Keys are destroyed immediately.
    Ephemeral,
    /// A verified summary is generated during the closing window, then keys
    /// are destroyed. Only the summary persists.
    Summary,
    /// All data and keys are retained after context close.
    Full,
}

impl std::fmt::Display for MemoryScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ephemeral => write!(f, "Ephemeral"),
            Self::Summary => write!(f, "Summary"),
            Self::Full => write!(f, "Full"),
        }
    }
}

// ---------------------------------------------------------------------------
// GovernanceModel
// ---------------------------------------------------------------------------

/// Governance model for a context, controlling how administrative decisions
/// are made.
///
/// Four concrete models are supported (ADR-031, spec §5.9):
/// - `SingleAdmin` — single admin authority, proposals auto-execute.
/// - `Threshold` — M-of-N approval from designated signers.
/// - `Majority` — >50% approval from eligible voters.
/// - `Unanimity` — all eligible voters must approve.
///
/// The model is declared at creation and immutable thereafter. Changing the
/// governance model requires creating a new context.
///
/// Note: this enum is a *selector* — it carries the creation-time parameters
/// needed to instantiate a [`GovernanceEngine`](super::governance::GovernanceEngine).
/// The richer [`GovernanceModelConfig`](super::governance::GovernanceModelConfig)
/// carries runtime state (e.g., `admin_did`) and is not suitable for
/// `ContextParams` (templates cannot know `admin_did` at definition time).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceModel {
    /// A single administrator controls all governance decisions. The context
    /// creator is the admin by default.
    SingleAdmin,

    /// M-of-N threshold approval. A fixed set of designated signers;
    /// a proposal passes when at least `threshold` of them approve.
    ///
    /// Validation: `threshold` must be in `[1, signers.len()]`.
    /// `signers` must be non-empty.
    Threshold {
        /// Minimum number of approvals required.
        threshold: u32,
        /// The set of DIDs authorized to vote.
        signers: Vec<DID>,
    },

    /// Majority vote among eligible voters. Proposal passes when
    /// approvals > 50% of `eligible_voters`.
    ///
    /// `eligible_voters` must be non-empty.
    Majority {
        /// The set of DIDs eligible to vote.
        eligible_voters: Vec<DID>,
    },

    /// Unanimity among eligible voters. Every voter must approve;
    /// a single rejection defeats the proposal immediately.
    ///
    /// `eligible_voters` must be non-empty.
    Unanimity {
        /// The set of DIDs that must all approve.
        eligible_voters: Vec<DID>,
    },
}

// ---------------------------------------------------------------------------
// TemplateId
// ---------------------------------------------------------------------------

/// Well-known context templates (spec section 5.12.1).
///
/// Templates are protocol constants -- not user-extensible. When present, all
/// other [`ContextParams`] fields must match the template definition exactly.
/// Template validation is enforced during context creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TemplateId {
    /// Messaging-only, ephemeral memory, TTL required.
    BilateralEphemeral,
    /// Messaging-only, full memory, no TTL.
    BilateralPersistent,
    /// Messaging + tools, summary memory, TTL required.
    Coordination,
    /// Messaging + invites, full memory, optional TTL.
    GroupDiscussion,
    /// Broadcast mode, open subscriber registration (spec section 5.14).
    PublicBroadcast,
    /// Broadcast mode, UCAN-gated subscriber access (spec section 5.14).
    GatedBroadcast,
    /// Cross-context tool interface template (spec section 5.12.1, 6.2).
    /// Messaging + tools + tool interface exposure, full memory, TTL optional.
    #[serde(rename = "scp:template/outlet-interface")]
    OutletInterfaceTemplate,
    /// Tool invocation context with per-invoke cost. Extends `tool-interface`.
    /// Requires `economic_policy` with `per_outlet_call` set at creation.
    ///
    /// See spec section 19.10 and ADR-033.
    #[serde(rename = "scp:template/paid-service")]
    PaidService,
    /// Subscription-based broadcast context. Extends `gated-broadcast`.
    /// Requires `economic_policy` with `per_period` set at creation.
    ///
    /// See spec section 19.10 and ADR-033.
    #[serde(rename = "scp:template/paid-broadcast")]
    PaidBroadcast,
    /// Handle registry template. Encrypted mode with messaging + tool invocation
    /// ceiling, discoverable by default. Used for human-readable addressing
    /// and agent discovery via standardized tool schemas (ADR-020, §22).
    #[serde(
        rename = "scp:template/handle-registry",
        alias = "scp:template/discovery-context"
    )]
    HandleRegistry,
}

// ---------------------------------------------------------------------------
// FieldVisibility
// ---------------------------------------------------------------------------

/// Controls whether metadata fields are visible before joining a context.
///
/// Used by [`MetadataVisibilityPolicy`] to declare per-field visibility.
/// Structural fields (ceiling, governance, mode, etc.) are always visible
/// regardless of this setting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldVisibility {
    /// Visible to anyone with the `context_id` (pre-join legibility).
    #[default]
    PreJoin,
    /// Visible only to context members.
    MemberOnly,
}

// ---------------------------------------------------------------------------
// MetadataVisibilityPolicy
// ---------------------------------------------------------------------------

/// Per-field metadata visibility policy (spec section 5.7).
///
/// Structural fields (ceiling, governance, mode, etc.) are always visible.
/// This policy governs operational fields only. By default, all operational
/// fields are [`FieldVisibility::PreJoin`] -- visible to anyone with the
/// `context_id`, supporting informed consent before joining.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataVisibilityPolicy {
    /// Visibility of the context's member count.
    pub member_count: FieldVisibility,
    /// Visibility of the context's age (time since creation).
    pub context_age: FieldVisibility,
    /// Visibility of the context creator's identity (DID).
    pub creator_identity: FieldVisibility,
    /// Visibility of the context's human-readable name.
    pub name: FieldVisibility,
    /// Visibility of the context's description.
    pub description: FieldVisibility,
    /// Visibility of the context's economic policy.
    pub economic_policy: FieldVisibility,
    /// Visibility of the count of registered tool interfaces.
    pub outlet_interface_count: FieldVisibility,
    /// Visibility of child context summary information.
    pub child_context_info: FieldVisibility,
}

// ---------------------------------------------------------------------------
// ProjectionRule / ProjectionPolicy
// ---------------------------------------------------------------------------

/// Rule for HTTP broadcast projection access control (spec section 18.11.2.1).
///
/// Controls whether projected broadcast content requires authentication to access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProjectionRule {
    /// Content served without authentication.
    Public,
    /// Content requires valid `messagesRead` UCAN in Authorization header.
    Gated,
    /// Author chooses their own projection rule.
    AuthorChoice,
}

/// Per-author projection access override.
///
/// Allows individual authors within a broadcast context to have a projection
/// rule that differs from the context's default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionOverride {
    /// The DID of the author this override applies to.
    pub did: DID,
    /// The projection rule for this specific author.
    pub rule: ProjectionRule,
}

/// Per-author projection access policy for broadcast contexts (spec section 18.11.2.1).
///
/// Controls whether projected content requires authentication, with per-author
/// overrides within the bounds of the context's admission mode. Only meaningful
/// for [`ContextMode::Broadcast`] contexts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionPolicy {
    /// Default rule for all authors without an explicit override.
    pub default_rule: ProjectionRule,
    /// Per-author overrides.
    pub overrides: Vec<ProjectionOverride>,
}

// ---------------------------------------------------------------------------
// BridgeDirectionality (§5.7)
// ---------------------------------------------------------------------------

/// Directionality of a bridge connector (spec §5.7).
///
/// Determines whether the bridge relays content in both directions or
/// one. Visible in context metadata before opt-in so prospective members
/// can evaluate trust implications of bridge presence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeDirectionality {
    /// Platform-to-SCP and SCP-to-platform.
    Full,
    /// Platform-to-SCP only (external content enters SCP,
    /// but SCP messages are not forwarded to the platform).
    ReadOnly,
    /// SCP-to-platform only (SCP messages are forwarded to the
    /// platform, but no external content enters SCP).
    WriteOnly,
}

// ---------------------------------------------------------------------------
// BridgeCapability (§5.7)
// ---------------------------------------------------------------------------

/// Capabilities a bridge connector can exercise in a context (spec §5.7).
///
/// These are the four protocol-defined bridge capabilities. A bridge's
/// `capabilities` field declares which of these it exercises, providing
/// legibility to prospective members before they join.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeCapability {
    /// Relay messages between SCP and the external platform.
    RelayMessages,
    /// Create shadow participants for external users.
    CreateShadows,
    /// Attest external user identities.
    AttestIdentities,
    /// Forward presence/typing indicators.
    ForwardPresence,
}

// ---------------------------------------------------------------------------
// BridgeMetadata (§5.7)
// ---------------------------------------------------------------------------

/// Metadata for an active bridge connector as defined in spec §5.7.
///
/// This is the spec-aligned bridge metadata type that provides
/// directionality and capabilities information to prospective members.
/// Complements [`BridgeInfo`] which carries the implementation-level
/// bridge mode (Relay/Puppet/Api/Cooperative). `BridgeMetadata` is
/// the pre-join legibility surface; `BridgeInfo` is the runtime
/// structural data.
///
/// Structural field — always visible before joining (legibility tenet).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeMetadata {
    /// External platform name (e.g., `"discord"`, `"slack"`, `"x"`).
    pub platform: String,
    /// DID of the bridge operator — the human accountable for bridge
    /// behavior (spec §12.2).
    pub bridge_did: DID,
    /// Capabilities the bridge exercises in this context.
    pub capabilities: Vec<BridgeCapability>,
    /// Directionality of the bridge.
    pub mode: BridgeDirectionality,
}

// ---------------------------------------------------------------------------
// BridgeInfo
// ---------------------------------------------------------------------------

/// Summary of an active bridge connector visible in context metadata.
///
/// Bridge presence, operator identity, connected platform, and operating mode
/// are visible to all context members and in context metadata before opt-in
/// (spec §12.2, §12.6.1). This is a structural field -- always visible
/// regardless of `MetadataVisibilityPolicy`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeInfo {
    /// Unique identifier for this bridge instance.
    pub bridge_id: String,
    /// DID of the human operator accountable for this bridge.
    pub operator_did: DID,
    /// Name of the external platform (e.g., `"discord"`, `"slack"`).
    pub platform: String,
    /// Operating mode of the bridge (Relay, Puppet, Api, Cooperative).
    pub mode: BridgeMode,
}

// ---------------------------------------------------------------------------
// MigrationSource (§5.11A.2)
// ---------------------------------------------------------------------------

/// Records the provenance of a context created via migration (§5.11A.2).
///
/// When a context is created as the destination of a migration, this struct
/// records the source context ID and the governance proposal ID that
/// authorized the migration. This provides provenance for why the destination
/// exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationSource {
    /// The source context ID that this context was migrated from.
    pub source_context_id: String,
    /// The governance proposal ID (hex-encoded) that authorized the migration.
    pub proposal_id: [u8; 32],
}

// ---------------------------------------------------------------------------
// PublicMetadata
// ---------------------------------------------------------------------------

/// Metadata visible to pre-join observers (spec section 5.7).
///
/// Structural fields are always included — they are the parameters a
/// prospective member needs to evaluate whether to join. Operational fields
/// are included only when the corresponding [`FieldVisibility`] in the
/// context's [`MetadataVisibilityPolicy`] is [`FieldVisibility::PreJoin`];
/// otherwise they are `None`.
///
/// Constructed via [`ContextParams::public_metadata()`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicMetadata {
    // --- Structural fields (always visible) ---
    /// Well-known template identifier, if created from a template.
    pub template_id: Option<TemplateId>,
    /// Capability ceiling.
    pub ceiling: Vec<Capability>,
    /// Ceiling mutability policy.
    pub ceiling_policy: CeilingPolicy,
    /// Role definitions.
    pub roles: Vec<RoleDefinition>,
    /// Governance model.
    pub governance: GovernanceModel,
    /// Context processing mode.
    pub mode: ContextMode,
    /// Time-to-live, if set.
    pub ttl: Option<Duration>,
    /// Promotion policy.
    pub promotion_policy: PromotionPolicy,
    /// Memory scope.
    pub memory_scope: MemoryScope,
    /// The visibility policy itself (so prospective members know what's hidden).
    pub metadata_visibility: MetadataVisibilityPolicy,
    /// Minimum protocol version required to join this context (spec §13.4).
    ///
    /// Encoded as `(major, minor)`, e.g., `(1, 0)` for SCP/1.0. Structural
    /// field — always visible before joining so prospective members can
    /// evaluate SDK compatibility. When `None`, defaults to `(1, 0)`.
    #[serde(default)]
    pub min_protocol_version: Option<(u8, u8)>,

    /// Active bridge connectors registered in this context (spec §12.2, §12.6.1).
    ///
    /// Bridge presence is always visible in context metadata before opt-in
    /// (legibility tenet). This is a structural field -- not governed by
    /// `MetadataVisibilityPolicy`.
    #[serde(default)]
    pub bridges: Vec<BridgeInfo>,

    // --- Structural fields (runtime, always visible) ---
    /// DIDs of active bridge operators registered in this context.
    ///
    /// Always visible (never filtered by `MetadataVisibilityPolicy`) because
    /// bridge presence is a trust signal required for informed consent before
    /// joining (spec §12.6.1: "Context metadata (§5.7) MUST include
    /// `bridge_operator_did` when a bridge is registered").
    ///
    /// Empty when no bridges are registered. Multiple entries when multiple
    /// bridges from different operators are active. Deduplicated — the same
    /// operator DID appears only once even if they operate multiple bridges.
    /// On bridge revocation, the operator's DID is removed if they have no
    /// remaining active bridges.
    #[serde(default)]
    pub bridge_operator_dids: Vec<DID>,

    // --- Operational fields (governed by MetadataVisibilityPolicy) ---
    /// Current member count. `None` when hidden by `MemberOnly` or unavailable.
    pub member_count: Option<u64>,
    /// Context age in seconds since creation. `None` when hidden by `MemberOnly` or unavailable.
    pub context_age: Option<u64>,
    /// Creator's DID. `None` when hidden by `MemberOnly` or unavailable.
    pub creator_identity: Option<DID>,
    /// Human-readable name. `None` when hidden by `MemberOnly` or unavailable.
    pub name: Option<String>,
    /// Human-readable description. `None` when hidden by `MemberOnly` or unavailable.
    pub description: Option<String>,
    /// Economic policy. `None` when hidden by `MemberOnly`, absent, or unavailable.
    pub economic_policy: Option<EconomicPolicy>,
    /// Count of registered tool interfaces. `None` when hidden by `MemberOnly` or unavailable.
    pub outlet_interface_count: Option<u32>,
    /// Child context summary information. `None` when hidden by `MemberOnly` or unavailable.
    pub child_context_info: Option<Vec<String>>,
}

/// Runtime context state that is not captured in [`ContextParams`] but may
/// be published as operational metadata. Pass to
/// [`ContextParams::public_metadata()`] to populate the corresponding fields.
#[derive(Debug, Clone, Default)]
pub struct RuntimeMetadata {
    /// Current member count.
    pub member_count: Option<u64>,
    /// Context age in seconds since creation.
    pub context_age: Option<u64>,
    /// Creator's DID.
    pub creator_identity: Option<DID>,
    /// Human-readable context name.
    pub name: Option<String>,
    /// Human-readable context description.
    pub description: Option<String>,
    /// Count of registered tool interfaces.
    pub outlet_interface_count: Option<u32>,
    /// Child context summary information (e.g., parent context IDs, summaries).
    pub child_context_info: Option<Vec<String>>,
    /// Active bridge connectors registered in this context (spec §12.2, §12.6.1).
    ///
    /// Bridges are a structural metadata field -- always visible before opt-in.
    /// Defaults to empty when no bridges are registered.
    pub bridges: Vec<BridgeInfo>,
    /// DIDs of active bridge operators registered in this context (spec §12.6.1).
    ///
    /// Populated from `BridgeRegistry::bridge_operator_dids()`. Empty vec means
    /// no active bridges. This is always visible in `PublicMetadata` (structural,
    /// not filtered by `MetadataVisibilityPolicy`).
    #[allow(clippy::struct_field_names)]
    pub bridge_operator_dids: Vec<DID>,
}

// ---------------------------------------------------------------------------
// filter_field helper
// ---------------------------------------------------------------------------

/// Returns `value` when `visibility` is [`FieldVisibility::PreJoin`], or
/// `None` when it is [`FieldVisibility::MemberOnly`].
fn filter_field<T>(visibility: FieldVisibility, value: Option<T>) -> Option<T> {
    match visibility {
        FieldVisibility::PreJoin => value,
        FieldVisibility::MemberOnly => None,
    }
}

// ---------------------------------------------------------------------------
// ContextParams
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ConsequenceConfig (B3 per-context opt-in)
// ---------------------------------------------------------------------------

/// Per-context configuration for automatic consequence-rule dispatch.
///
/// Controls which [`EnforcementSeverity`](crate::trust::consequence::EnforcementSeverity)
/// tiers a [`ConsequenceRule`](crate::trust::consequence::ConsequenceRule)
/// may reference. See ADR-017 and the Group B plan for the rationale.
///
/// Default: all flags `false`. Consequence rules may reference only the
/// least-severe tiers (`SuspendCapability`, `SuspendAccess`) by default;
/// cryptographic revocation and MLS ejection are governance-only unless the
/// context explicitly opts in at creation time.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsequenceConfig {
    /// If `true`, consequence rules may reference
    /// [`EnforcementSeverity::RevokeAccess`](crate::trust::consequence::EnforcementSeverity::RevokeAccess)
    /// — i.e., automatic cryptographic revocation of a member's access keys.
    ///
    /// When `false` (the default), `RevokeAccess` is rejected at rule
    /// validation time. It remains callable as an explicit governance action
    /// regardless of this flag.
    ///
    /// `EnforcementSeverity::RemoveMember` is **never** allowed in a
    /// consequence rule regardless of this flag. MLS ejection is permanent
    /// and must always originate from a deliberate governance proposal.
    #[serde(default)]
    pub allow_automatic_access_revocation: bool,
}

/// Full configuration for an SCP context, declared at creation time.
///
/// `ContextParams` captures every parameter that defines a context's behavior:
/// encryption mode, capability ceiling, roles, tools, time-to-live, memory
/// retention, and governance model. Most fields are immutable after creation.
///
/// For template-based creation, all fields must match the template definition
/// exactly. For explicit creation, the caller specifies all parameters directly.
///
/// See ADR-008 in `.docs/adrs/phase-2.md` for the full specification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextParams {
    /// Context processing mode: [`Encrypted`](ContextMode::Encrypted) (default)
    /// or [`Broadcast`](ContextMode::Broadcast). Immutable after creation.
    pub mode: ContextMode,

    /// Capability ceiling -- the maximum set of capabilities any participant
    /// can hold in this context. Individual role capabilities must be subsets
    /// of this ceiling.
    pub ceiling: Vec<Capability>,

    /// Whether the capability ceiling can be modified after creation.
    /// Defaults to [`Immutable`](CeilingPolicy::Immutable).
    pub ceiling_policy: CeilingPolicy,

    /// Whether the context can be promoted (e.g., from ephemeral to persistent).
    ///
    /// Immutable after context creation. No API exists to change this field
    /// post-creation. The value is declared at context creation time and
    /// governs the context's entire lifecycle. See spec §5.10.
    pub promotion_policy: PromotionPolicy,

    /// Role definitions with permission sets. Each role maps to a subset of
    /// the capability ceiling.
    pub roles: Vec<RoleDefinition>,

    /// Initial tool registrations available within this context.
    pub tools: Vec<OutletRegistration>,

    /// Optional time-to-live. When set, the context automatically expires
    /// after this duration. Extension requires unanimous member consent.
    /// See spec section 5.10.
    pub ttl: Option<Duration>,

    /// Memory scope controlling data retention after context closure.
    pub memory_scope: MemoryScope,

    /// Governance model controlling administrative decisions.
    pub governance: GovernanceModel,

    /// Well-known template identifier, if this context was created from a
    /// template. When present, all other fields must match the template
    /// definition exactly.
    pub template_id: Option<TemplateId>,

    /// Economic policy for this context. `None` means the context is free
    /// (no economic policy). When present, defines costs, accepted payment
    /// adapters, optional dynamic pricing, and the payee DID.
    ///
    /// See spec section 19.3 and ADR-033.
    #[serde(default)]
    pub economic_policy: Option<EconomicPolicy>,

    /// Per-field metadata visibility policy controlling which operational fields
    /// are visible before joining (spec section 5.7). Structural fields are
    /// always visible regardless. Defaults to all fields [`FieldVisibility::PreJoin`].
    #[serde(default)]
    pub metadata_visibility: MetadataVisibilityPolicy,

    /// Projection access policy for broadcast contexts (spec section 18.11.2.1).
    /// Controls whether projected HTTP content requires authentication, with
    /// per-author overrides. `None` for non-broadcast contexts.
    #[serde(default)]
    pub projection_policy: Option<ProjectionPolicy>,

    /// Whether this context should be published for discovery (§5.14.11).
    ///
    /// When `true` and the context is a broadcast context, the creator's DID
    /// document will include an `SCPBroadcastContext` service entry advertising
    /// this context. Encrypted context IDs MUST NOT be published (§9.10).
    ///
    /// Defaults to `false`.
    #[serde(default)]
    pub discoverable: bool,
    /// Maximum cross-context chain depth for provenance enforcement (spec §24.4).
    ///
    /// When `None`, the default of 8 hops applies (ADR-043). The u8 type
    /// naturally bounds the range to [0, 255].
    ///
    /// This bounds the worst-case amplification factor for cross-context tool
    /// call chains originating from or passing through this context.
    #[serde(default)]
    pub max_chain_depth: Option<u8>,

    /// Maximum nesting depth for child contexts (spec §5.13.8, ADR-043).
    ///
    /// When `None`, nesting depth is unbounded (no limit). When `Some(n)`,
    /// child contexts at depth > n are rejected. Immutable after creation.
    #[serde(default)]
    pub max_nesting_depth: Option<u32>,

    /// Maximum concurrent sessions per calling context (spec §6.2.1, ADR-043).
    ///
    /// When `None`, the default of 1000 applies. When `Some(n)`, at most `n`
    /// concurrent sessions per caller are allowed. Uses `u32` (not `usize`)
    /// for cross-platform serialization compatibility (`wasm32`, `UniFFI`).
    #[serde(default)]
    pub session_cap: Option<u32>,

    /// Counterparty privacy policy for outbound provenance (§7.7.1, §24.3.1).
    ///
    /// Controls how membership DIDs appear in provenance records when data
    /// crosses this context's boundary:
    /// - `Full` — real DIDs included (opt-in for public contexts).
    /// - `Pseudonymized` — context-scoped pseudonyms (§9.10.4).
    /// - `Redacted` — empty list (default, most privacy-preserving).
    ///
    /// Default is `Redacted` per §7.7.1: contexts must opt in to share
    /// counterparty information.
    #[serde(default)]
    pub counterparty_policy: CounterpartyPolicy,

    /// Participation admission requirements (spec §7.3.2.1).
    ///
    /// When non-empty, joining members must present [`crate::trust::participation::ParticipationProfile`]
    /// attestations satisfying every entry. Empty means no participation
    /// requirements (the default).
    #[serde(default)]
    pub participation_requirements: Vec<RequireParticipation>,

    /// Policy for handling incomplete summary verification at window expiry.
    ///
    /// Only relevant for `MemoryScope::Summary` contexts. Determines whether
    /// close proceeds or the window is extended when not all members have
    /// verified. Defaults to [`IncompleteVerificationPolicy::Proceed`].
    ///
    /// See issue #365.
    #[serde(default)]
    pub incomplete_verification_policy: IncompleteVerificationPolicy,

    /// Minimum protocol version required to join this context (spec §13.4).
    ///
    /// Encoded as `(major, minor)`, e.g., `(1, 0)` for SCP/1.0. When set,
    /// the SDK MUST reject attempts to join a context whose
    /// `min_protocol_version` exceeds the SDK's supported version. The check
    /// is client-side — the SDK compares `min_protocol_version` against
    /// [`SCP_PROTOCOL_VERSION`](crate::envelope::SCP_PROTOCOL_VERSION) and
    /// refuses to join if incompatible.
    ///
    /// When `None`, defaults to `(1, 0)` — SCP/1.0 baseline.
    ///
    /// This field is visible in context structural metadata alongside the
    /// capability ceiling and governance model (§5.7, §13.4).
    #[serde(default)]
    pub min_protocol_version: Option<(u8, u8)>,

    /// Migration provenance (§5.11A.2).
    ///
    /// When this context was created as the destination of a migration, this
    /// field records the source context ID and the governance proposal ID
    /// that authorized the migration. `None` for non-migration contexts.
    #[serde(default)]
    pub migration_source: Option<MigrationSource>,

    /// Consequence rules declared at context creation (ADR-017, #1531).
    ///
    /// Visible before joining (part of the opt-in contract). Protocol-enforced,
    /// verifiable. No hidden penalties. Empty means no consequence rules.
    #[serde(default)]
    pub consequence_rules: Vec<crate::trust::consequence::ConsequenceRule>,

    /// Per-context configuration for consequence-rule enforcement severity
    /// (Group B3 opt-in, ADR-017).
    ///
    /// Controls whether
    /// [`EnforcementSeverity::RevokeAccess`](crate::trust::consequence::EnforcementSeverity::RevokeAccess)
    /// may be referenced by automatic consequence rules. Defaults to
    /// `allow_automatic_access_revocation = false`, meaning cryptographic
    /// revocation is governance-only unless this context explicitly opts
    /// in at creation time. `RemoveMember` is never allowed in a consequence
    /// rule regardless of this configuration.
    #[serde(default)]
    pub consequence_config: ConsequenceConfig,

    /// Per-context Sybil resistance policy (spec §9.3, #1530).
    ///
    /// When `Some`, joining members are evaluated against the policy's trust
    /// signal requirements. When `None` (the default), no Sybil resistance
    /// check is performed — any valid DID can join.
    #[serde(default)]
    pub sybil_policy: Option<crate::trust::sybil::ContextSybilPolicy>,

    /// Scalar multiplier for the §6.2.0.1 round-6 population-weighted
    /// interface-spam floor (registered in §9.18.B "Configurable Parameters",
    /// ADR-049 round 6 §"Cluster detection 4th predicate + population-weighted
    /// floor").
    ///
    /// Combined with `ceil(log2(member_count + 1))` to produce the local
    /// floor:
    ///
    /// ```text
    /// interface_base_cost_floor(ctx) = max(
    ///     currency_atomic_unit(ctx.currency),
    ///     ceil(log2(member_count + 1)) × ContextParams::base_cost_scale,
    /// )
    /// ```
    ///
    /// Replaces the round-5 flat `interface_base_cost_minimum`. A larger
    /// context pays a proportionally larger floor on its first same-cluster
    /// interface, closing the round-5 MAJOR-5 cluster-detection bypass
    /// residual-risk where small-N sybil contexts could pay only the
    /// constant currency-atomic-unit fee.
    ///
    /// Default: `Amount(1)` — the absolute currency-atomic-unit lower bound
    /// every currency Amount represents. Deployers SHOULD raise this to a
    /// currency-meaningful value (e.g. `Amount(100)` for a USD-cent
    /// denomination, `Amount(10_000)` for a BTC-satoshi denomination).
    /// Range per §9.18.B: `[currency_atomic_unit, 1_000 ×
    /// currency_atomic_unit]`.
    #[serde(default = "default_base_cost_scale")]
    pub base_cost_scale: Amount,

    /// Maximum seconds an `OutletError` envelope stays in the outbound
    /// queue during the `Frozen` window of an admin-removal-induced
    /// `InterfaceSaltRotated` commit (spec §6.2.0.1, registered in §9.18.B,
    /// ADR-049 round 6 §"Admin-removal rotation TOCTOU closure").
    ///
    /// Overflow drops the buffered envelope with an internal audit-log
    /// entry `governance.remove-member-buffer-overflow` and escalates the
    /// governance-removal timeout. Default 30 s, range `[5, 300]`.
    #[serde(default = "default_outlet_error_buffer_max_secs")]
    pub outlet_error_buffer_max_secs: u32,

    /// Default initial credit window for streaming outlet invocations
    /// (§5.4.5 credit-based backpressure, registered in §9.18.B). The
    /// executor may emit up to this many `Data`/`Progress` chunks before
    /// it must wait for an `OutletStreamCredit` grant. `End` and `Error`
    /// chunks are terminal and do not consume credit. Default `32`,
    /// range `[1, 4096]`.
    #[serde(default = "default_stream_window_default")]
    pub stream_window_default: u32,

    /// Maximum seconds a stream may sit at zero credit before the
    /// framework cancels it with
    /// `OutletErrorClass::Execution::CreditStall`
    /// (`SCP-TOOL-6133` / `execution.credit-stall`). §5.4.5
    /// Credit-based backpressure, registered in §9.18.B. Default `30`,
    /// range `[1, 600]`.
    #[serde(default = "default_stream_credit_stall_secs")]
    pub stream_credit_stall_secs: u32,

    /// Maximum seconds the executor framework waits between receiving
    /// `OutletCancel` and emitting the terminal cancel-ack chunk before
    /// it forces closure with
    /// `OutletErrorClass::Execution::CancelAckTimeout` (`SCP-TOOL-6135`
    /// / `execution.cancel-ack-timeout`). §5.4.5 Cancellation and
    /// billing boundary, registered in §9.18.B. Default `5`, range
    /// `[1, 60]`.
    #[serde(default = "default_stream_cancel_ack_secs")]
    pub stream_cancel_ack_secs: u32,

    /// Period (seconds) for the receiver-side framework to re-check the
    /// opening UCAN's revocation status during the lifetime of an
    /// active stream. §5.4.5 Revocation re-check cadence, registered in
    /// §9.18.B. On revocation the stream closes with
    /// `OutletErrorClass::Authorization::RevokedMidStream`
    /// (`SCP-TOOL-6110` / `authorization.revoked-mid-stream`). Default
    /// `10`, range `[1, 60]`.
    #[serde(default = "default_stream_ucan_recheck_secs")]
    pub stream_ucan_recheck_secs: u32,

    /// Maximum number of streams the immediate-previous-hop invoker DID
    /// may have open concurrently against any outlet in this context
    /// (§5.4.5 per-context concurrent-stream bounds, registered in
    /// §9.18.B). Breach rejects with `Transport::RateLimited` slug
    /// `transport.concurrent-streams-per-invoker`. Default `8`, range
    /// `[1, 1024]`.
    #[serde(default = "default_max_concurrent_inbound_streams_per_invoker")]
    pub max_concurrent_inbound_streams_per_invoker: u32,

    /// Maximum number of streams the outermost caller DID in the
    /// delegation chain may have open concurrently against any outlet
    /// hosted by this operator DID (§5.4.5, tracked at operator scope).
    /// Breach rejects with `Transport::RateLimited` slug
    /// `transport.concurrent-streams-per-origin-invoker`. Default `16`,
    /// range `[1, 1024]`.
    #[serde(default = "default_max_concurrent_inbound_streams_per_origin_invoker")]
    pub max_concurrent_inbound_streams_per_origin_invoker: u32,

    /// Maximum number of streams open concurrently against a single
    /// outlet (across all invokers) — §5.4.5, registered in §9.18.B.
    /// Breach rejects with `Transport::RateLimited` slug
    /// `transport.concurrent-streams-per-outlet`. Default `128`, range
    /// `[1, 1024]`.
    #[serde(default = "default_max_concurrent_inbound_streams_per_outlet")]
    pub max_concurrent_inbound_streams_per_outlet: u32,
}

/// Default for [`ContextParams::base_cost_scale`] — the absolute
/// currency-atomic-unit lower bound (`Amount(1)`). Deployers raise this
/// per §9.18.B for currency-meaningful spam pricing.
const fn default_base_cost_scale() -> Amount {
    Amount(1)
}

/// Default for [`ContextParams::outlet_error_buffer_max_secs`] — 30 s,
/// per §9.18.B Configurable Parameters and §6.2.0.1 atomic-removal queue
/// discipline.
const fn default_outlet_error_buffer_max_secs() -> u32 {
    30
}

/// Default for [`ContextParams::stream_window_default`] — `32`, per
/// §5.4.5 Credit-based backpressure / §9.18.B.
const fn default_stream_window_default() -> u32 {
    32
}

/// Default for [`ContextParams::stream_credit_stall_secs`] — `30` s,
/// per §5.4.5 Credit-based backpressure / §9.18.B.
const fn default_stream_credit_stall_secs() -> u32 {
    30
}

/// Default for [`ContextParams::stream_cancel_ack_secs`] — `5` s, per
/// §5.4.5 Cancellation and billing boundary / §9.18.B.
const fn default_stream_cancel_ack_secs() -> u32 {
    5
}

/// Default for [`ContextParams::stream_ucan_recheck_secs`] — `10` s,
/// per §5.4.5 Revocation re-check cadence / §9.18.B.
const fn default_stream_ucan_recheck_secs() -> u32 {
    10
}

/// Default for
/// [`ContextParams::max_concurrent_inbound_streams_per_invoker`] — `8`,
/// per §5.4.5 per-context concurrent-stream bounds / §9.18.B.
const fn default_max_concurrent_inbound_streams_per_invoker() -> u32 {
    8
}

/// Default for
/// [`ContextParams::max_concurrent_inbound_streams_per_origin_invoker`]
/// — `16`, per §5.4.5 per-context concurrent-stream bounds / §9.18.B.
const fn default_max_concurrent_inbound_streams_per_origin_invoker() -> u32 {
    16
}

/// Default for
/// [`ContextParams::max_concurrent_inbound_streams_per_outlet`] —
/// `128`, per §5.4.5 per-context concurrent-stream bounds / §9.18.B.
const fn default_max_concurrent_inbound_streams_per_outlet() -> u32 {
    128
}

impl Default for ContextParams {
    fn default() -> Self {
        Self {
            mode: ContextMode::default(),
            ceiling: Vec::new(),
            ceiling_policy: CeilingPolicy::default(),
            promotion_policy: PromotionPolicy::NoPromotion,
            roles: Vec::new(),
            tools: Vec::new(),
            ttl: None,
            memory_scope: MemoryScope::Ephemeral,
            governance: GovernanceModel::SingleAdmin,
            template_id: None,
            economic_policy: None,
            metadata_visibility: MetadataVisibilityPolicy::default(),
            projection_policy: None,
            discoverable: false,
            max_chain_depth: None,
            max_nesting_depth: None,
            session_cap: None,
            counterparty_policy: CounterpartyPolicy::default(),
            participation_requirements: Vec::new(),
            incomplete_verification_policy: IncompleteVerificationPolicy::default(),
            min_protocol_version: None,
            migration_source: None,
            consequence_rules: Vec::new(),
            consequence_config: ConsequenceConfig::default(),
            sybil_policy: None,
            base_cost_scale: default_base_cost_scale(),
            outlet_error_buffer_max_secs: default_outlet_error_buffer_max_secs(),
            stream_window_default: default_stream_window_default(),
            stream_credit_stall_secs: default_stream_credit_stall_secs(),
            stream_cancel_ack_secs: default_stream_cancel_ack_secs(),
            stream_ucan_recheck_secs: default_stream_ucan_recheck_secs(),
            max_concurrent_inbound_streams_per_invoker:
                default_max_concurrent_inbound_streams_per_invoker(),
            max_concurrent_inbound_streams_per_origin_invoker:
                default_max_concurrent_inbound_streams_per_origin_invoker(),
            max_concurrent_inbound_streams_per_outlet:
                default_max_concurrent_inbound_streams_per_outlet(),
        }
    }
}

/// Decodes a packed `u16` protocol version (e.g., `0x0100`) into its
/// `(major, minor)` components.
#[must_use]
pub const fn decode_protocol_version(packed: u16) -> (u8, u8) {
    ((packed >> 8) as u8, (packed & 0xFF) as u8)
}

/// Encodes a `(major, minor)` pair into the packed `u16` wire format
/// used by [`SCP_PROTOCOL_VERSION`](crate::envelope::SCP_PROTOCOL_VERSION).
#[must_use]
pub const fn encode_protocol_version(major: u8, minor: u8) -> u16 {
    ((major as u16) << 8) | (minor as u16)
}

impl ContextParams {
    /// Returns the effective minimum protocol version for this context.
    ///
    /// When `min_protocol_version` is `None`, returns `(1, 0)` — the SCP/1.0
    /// baseline per spec §13.4.
    #[must_use]
    pub const fn effective_min_protocol_version(&self) -> (u8, u8) {
        match self.min_protocol_version {
            Some(v) => v,
            None => (1, 0),
        }
    }

    /// Checks whether the given SDK protocol version satisfies this context's
    /// minimum protocol version requirement (spec §13.4).
    ///
    /// Returns `Ok(())` if the SDK version is >= the context's minimum, or
    /// [`ContextError::VersionIncompatible`](super::ContextError::VersionIncompatible)
    /// if the SDK version is too low.
    ///
    /// # Arguments
    ///
    /// * `sdk_version` — The SDK's protocol version as a packed `u16`
    ///   (e.g., [`SCP_PROTOCOL_VERSION`](crate::envelope::SCP_PROTOCOL_VERSION)).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::VersionIncompatible`](super::ContextError::VersionIncompatible)
    /// when the SDK version does not meet the context's minimum requirement.
    pub const fn check_version_compatibility(
        &self,
        sdk_version: u16,
    ) -> Result<(), super::ContextError> {
        let (req_major, req_minor) = self.effective_min_protocol_version();
        let (sdk_major, sdk_minor) = decode_protocol_version(sdk_version);

        // Exact major match is intentional: different major versions have
        // incompatible wire formats per §13.1. This rejects both lower AND
        // higher majors. Minor version must be >=.
        if sdk_major != req_major || sdk_minor < req_minor {
            return Err(super::ContextError::VersionIncompatible {
                required_major: req_major,
                required_minor: req_minor,
                supported_major: sdk_major,
                supported_minor: sdk_minor,
            });
        }

        Ok(())
    }

    /// Return metadata filtered by the visibility policy (spec section 5.7).
    ///
    /// Structural fields are always included. Operational fields are included
    /// only when the corresponding [`FieldVisibility`] is
    /// [`FieldVisibility::PreJoin`]; otherwise the field is `None`.
    ///
    /// Fields that live on `ContextParams` (e.g., `economic_policy`) are
    /// filtered directly. Fields that are runtime state (member count, context
    /// age, creator identity, name, description, tool interface count, child
    /// context info) must be supplied via [`RuntimeMetadata`].
    #[must_use]
    pub fn public_metadata(&self, runtime: &RuntimeMetadata) -> PublicMetadata {
        let vis = &self.metadata_visibility;

        PublicMetadata {
            // Structural fields — always visible.
            template_id: self.template_id,
            ceiling: self.ceiling.clone(),
            ceiling_policy: self.ceiling_policy,
            roles: self.roles.clone(),
            governance: self.governance.clone(),
            mode: self.mode,
            ttl: self.ttl,
            promotion_policy: self.promotion_policy,
            memory_scope: self.memory_scope,
            metadata_visibility: self.metadata_visibility.clone(),
            min_protocol_version: self.min_protocol_version,
            bridges: runtime.bridges.clone(),
            bridge_operator_dids: runtime.bridge_operator_dids.clone(),

            // Operational fields — filtered by visibility policy.
            member_count: filter_field(vis.member_count, runtime.member_count),
            context_age: filter_field(vis.context_age, runtime.context_age),
            creator_identity: filter_field(vis.creator_identity, runtime.creator_identity.clone()),
            name: filter_field(vis.name, runtime.name.clone()),
            description: filter_field(vis.description, runtime.description.clone()),
            economic_policy: filter_field(vis.economic_policy, self.economic_policy.clone()),
            outlet_interface_count: filter_field(
                vis.outlet_interface_count,
                runtime.outlet_interface_count,
            ),
            child_context_info: filter_field(
                vis.child_context_info,
                runtime.child_context_info.clone(),
            ),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreadable_literal
)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::context::outlets::OutletSchema;

    #[test]
    fn context_mode_default_is_encrypted() {
        assert_eq!(ContextMode::default(), ContextMode::Encrypted);
    }

    #[test]
    fn ceiling_policy_default_is_immutable() {
        assert_eq!(CeilingPolicy::default(), CeilingPolicy::Immutable);
    }

    #[test]
    fn context_params_default_has_expected_values() {
        let params = ContextParams::default();
        assert_eq!(params.mode, ContextMode::Encrypted);
        assert!(params.ceiling.is_empty());
        assert_eq!(params.ceiling_policy, CeilingPolicy::Immutable);
        assert_eq!(params.promotion_policy, PromotionPolicy::NoPromotion);
        assert!(params.roles.is_empty());
        assert!(params.tools.is_empty());
        assert!(params.ttl.is_none());
        assert_eq!(params.memory_scope, MemoryScope::Ephemeral);
        assert_eq!(params.governance, GovernanceModel::SingleAdmin);
        assert!(params.template_id.is_none());
        assert!(params.economic_policy.is_none());
        assert_eq!(
            params.metadata_visibility,
            MetadataVisibilityPolicy::default()
        );
        assert!(params.projection_policy.is_none());
        assert!(params.participation_requirements.is_empty());
    }

    #[test]
    fn context_params_construction_with_all_fields() {
        let params = ContextParams {
            mode: ContextMode::Broadcast,
            ceiling: vec![
                Capability::new("messages:read").expect("known capability"),
                Capability::new("messages:write").expect("known capability"),
            ],
            ceiling_policy: CeilingPolicy::Governed,
            promotion_policy: PromotionPolicy::Promotable,
            roles: vec![
                RoleDefinition {
                    name: "admin".to_owned(),
                    capabilities: HashSet::from([
                        Capability::MessagesRead,
                        Capability::MessagesWrite,
                    ]),
                },
                RoleDefinition {
                    name: "member".to_owned(),
                    capabilities: HashSet::from([Capability::MessagesRead]),
                },
            ],
            tools: vec![OutletRegistration {
                outlet_id: "recipe-search".to_owned(),
                kind: crate::context::outlets::OutletKind::Action,
                name: "recipe-search".to_owned(),
                description: "Search for recipes".to_owned(),
                schema: OutletSchema {
                    input_schema: serde_json::json!({"type": "object"}),
                    output_schema: serde_json::json!({"type": "object"}),
                    aggregate_schema: None,
                },
                implementation_hash: [0u8; 32],
                test_vectors: vec![],
                operator_did: "did:dht:z6MkTestOperator".into(),
                cost: None,
                registered_at: 0,
                signature: Vec::new(),
                message_catalog: Vec::new(),
            }],
            ttl: Some(Duration::from_hours(1)),
            memory_scope: MemoryScope::Full,
            governance: GovernanceModel::SingleAdmin,
            template_id: Some(TemplateId::PublicBroadcast),
            economic_policy: None,
            metadata_visibility: MetadataVisibilityPolicy::default(),
            projection_policy: None,
            discoverable: false,
            max_chain_depth: None,
            max_nesting_depth: None,
            session_cap: None,
            counterparty_policy: CounterpartyPolicy::default(),
            participation_requirements: Vec::new(),
            incomplete_verification_policy: IncompleteVerificationPolicy::default(),
            min_protocol_version: None,
            migration_source: None,
            consequence_rules: Vec::new(),
            consequence_config: ConsequenceConfig::default(),
            sybil_policy: None,
            base_cost_scale: Amount::new(100),
            outlet_error_buffer_max_secs: 30,
            stream_window_default: 32,
            stream_credit_stall_secs: 30,
            stream_cancel_ack_secs: 5,
            stream_ucan_recheck_secs: 10,
            max_concurrent_inbound_streams_per_invoker: 8,
            max_concurrent_inbound_streams_per_origin_invoker: 16,
            max_concurrent_inbound_streams_per_outlet: 128,
        };

        assert_eq!(params.mode, ContextMode::Broadcast);
        assert_eq!(params.ceiling.len(), 2);
        assert_eq!(params.ceiling[0].name(), "messages:read");
        assert_eq!(params.ceiling_policy, CeilingPolicy::Governed);
        assert_eq!(params.promotion_policy, PromotionPolicy::Promotable);
        assert_eq!(params.roles.len(), 2);
        assert_eq!(params.tools.len(), 1);
        assert_eq!(params.ttl, Some(Duration::from_hours(1)));
        assert_eq!(params.memory_scope, MemoryScope::Full);
        assert_eq!(params.template_id, Some(TemplateId::PublicBroadcast));
        assert!(params.economic_policy.is_none());
    }

    #[test]
    fn capability_new_and_name() {
        let cap = Capability::new("messages:write").expect("known capability");
        assert_eq!(cap.name(), "messages:write");
    }

    #[test]
    fn role_definition_clone_eq() {
        let role = RoleDefinition {
            name: "admin".to_owned(),
            capabilities: HashSet::from([Capability::MessagesRead]),
        };
        let cloned = role.clone();
        assert_eq!(role, cloned);
    }

    #[test]
    fn outlet_registration_clone_eq() {
        let tool = OutletRegistration {
            outlet_id: "search".to_owned(),
            kind: crate::context::outlets::OutletKind::Action,
            name: "search".to_owned(),
            description: "Search tool".to_owned(),
            schema: OutletSchema {
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: serde_json::json!({"type": "object"}),
                aggregate_schema: None,
            },
            implementation_hash: [0u8; 32],
            test_vectors: vec![],
            operator_did: "did:dht:z6MkTestOperator".into(),
            cost: None,
            registered_at: 0,
            signature: Vec::new(),
            message_catalog: Vec::new(),
        };
        let cloned = tool.clone();
        assert_eq!(tool, cloned);
    }

    #[test]
    fn context_mode_serialization_roundtrip() {
        let mode = ContextMode::Broadcast;
        let json = serde_json::to_string(&mode).ok();
        assert!(json.is_some());
        let deserialized: Result<ContextMode, _> =
            serde_json::from_str(json.as_deref().unwrap_or(""));
        assert_eq!(deserialized.ok(), Some(ContextMode::Broadcast));
    }

    #[test]
    fn template_id_variants_are_distinct() {
        let variants = [
            TemplateId::BilateralEphemeral,
            TemplateId::BilateralPersistent,
            TemplateId::Coordination,
            TemplateId::GroupDiscussion,
            TemplateId::PublicBroadcast,
            TemplateId::GatedBroadcast,
            TemplateId::PaidService,
            TemplateId::PaidBroadcast,
            TemplateId::HandleRegistry,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn template_id_handle_registry_deserializes_from_old_name() {
        // The HandleRegistry variant was originally serialized as
        // "scp:template/discovery-context". The serde alias ensures
        // existing stored data can still deserialize.
        let json = r#""scp:template/discovery-context""#;
        let deserialized: TemplateId = serde_json::from_str(json).unwrap();
        assert_eq!(deserialized, TemplateId::HandleRegistry);

        // Current canonical name also works.
        let json = r#""scp:template/handle-registry""#;
        let deserialized: TemplateId = serde_json::from_str(json).unwrap();
        assert_eq!(deserialized, TemplateId::HandleRegistry);

        // Serialization always uses the canonical name.
        let serialized = serde_json::to_string(&TemplateId::HandleRegistry).unwrap();
        assert_eq!(serialized, r#""scp:template/handle-registry""#);
    }

    #[test]
    fn memory_scope_variants_are_distinct() {
        assert_ne!(MemoryScope::Ephemeral, MemoryScope::Summary);
        assert_ne!(MemoryScope::Summary, MemoryScope::Full);
        assert_ne!(MemoryScope::Ephemeral, MemoryScope::Full);
    }

    #[test]
    fn context_params_serialization_roundtrip() {
        let params = ContextParams {
            mode: ContextMode::Encrypted,
            ceiling: vec![Capability::new("messages:read").expect("known capability")],
            ceiling_policy: CeilingPolicy::Immutable,
            promotion_policy: PromotionPolicy::NoPromotion,
            roles: vec![RoleDefinition {
                name: "member".to_owned(),
                capabilities: HashSet::from([Capability::MessagesRead]),
            }],
            tools: vec![],
            ttl: Some(Duration::from_mins(5)),
            memory_scope: MemoryScope::Summary,
            governance: GovernanceModel::SingleAdmin,
            template_id: Some(TemplateId::BilateralEphemeral),
            economic_policy: None,
            metadata_visibility: MetadataVisibilityPolicy::default(),
            projection_policy: None,
            discoverable: false,
            max_chain_depth: None,
            max_nesting_depth: None,
            session_cap: None,
            counterparty_policy: CounterpartyPolicy::default(),
            participation_requirements: Vec::new(),
            incomplete_verification_policy: IncompleteVerificationPolicy::default(),
            min_protocol_version: None,
            migration_source: None,
            consequence_rules: Vec::new(),
            consequence_config: ConsequenceConfig::default(),
            sybil_policy: None,
            base_cost_scale: Amount::new(1),
            outlet_error_buffer_max_secs: 30,
            stream_window_default: 32,
            stream_credit_stall_secs: 30,
            stream_cancel_ack_secs: 5,
            stream_ucan_recheck_secs: 10,
            max_concurrent_inbound_streams_per_invoker: 8,
            max_concurrent_inbound_streams_per_origin_invoker: 16,
            max_concurrent_inbound_streams_per_outlet: 128,
        };

        let json = serde_json::to_string(&params).ok();
        assert!(json.is_some());
        let deserialized: Result<ContextParams, _> =
            serde_json::from_str(json.as_deref().unwrap_or(""));
        assert_eq!(deserialized.ok(), Some(params));
    }

    #[test]
    fn context_params_with_economic_policy_serde_roundtrip() {
        use crate::economy::{
            Amount, Coefficient, CostSchedule, CurrencyCode, EconomicPolicy, PricingFormula,
            PricingMetric, PricingVariable,
        };

        let params = ContextParams {
            mode: ContextMode::Encrypted,
            ceiling: vec![Capability::new("messages:read").expect("known capability")],
            ceiling_policy: CeilingPolicy::Immutable,
            promotion_policy: PromotionPolicy::NoPromotion,
            roles: vec![],
            tools: vec![],
            ttl: None,
            memory_scope: MemoryScope::Full,
            governance: GovernanceModel::SingleAdmin,
            template_id: None,
            economic_policy: Some(EconomicPolicy {
                locked: false,
                cost_schedule: CostSchedule {
                    currency: CurrencyCode::from("USD"),
                    per_message: Some(Amount(1)),
                    per_outlet_call: None,
                    per_join: Some(Amount(100)),
                    per_period: None,
                    per_byte_stored: None,
                },
                payment_adapters: vec!["x402".to_owned()],
                pricing_formula: Some(PricingFormula {
                    base_cost: Amount(10),
                    variables: vec![PricingVariable::Linear {
                        metric: PricingMetric::MemberCount,
                        coefficient: Coefficient(500_000),
                    }],
                    cap: Some(Amount(1000)),
                    floor: None,
                }),
                payee: DID::from("did:dht:z6MkPayee"),
            }),
            metadata_visibility: MetadataVisibilityPolicy::default(),
            projection_policy: None,
            discoverable: false,
            max_chain_depth: None,
            max_nesting_depth: None,
            session_cap: None,
            counterparty_policy: CounterpartyPolicy::default(),
            participation_requirements: Vec::new(),
            incomplete_verification_policy: IncompleteVerificationPolicy::default(),
            min_protocol_version: None,
            migration_source: None,
            consequence_rules: Vec::new(),
            consequence_config: ConsequenceConfig::default(),
            sybil_policy: None,
            base_cost_scale: Amount::new(1),
            outlet_error_buffer_max_secs: 30,
            stream_window_default: 32,
            stream_credit_stall_secs: 30,
            stream_cancel_ack_secs: 5,
            stream_ucan_recheck_secs: 10,
            max_concurrent_inbound_streams_per_invoker: 8,
            max_concurrent_inbound_streams_per_origin_invoker: 16,
            max_concurrent_inbound_streams_per_outlet: 128,
        };

        let json = serde_json::to_string(&params).unwrap();
        let deserialized: ContextParams = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, params);
        assert!(deserialized.economic_policy.is_some());
    }

    #[test]
    fn context_params_deserialize_without_economic_policy_field() {
        // Verify that JSON without economic_policy field still deserializes
        // (backwards compatibility via #[serde(default)]).
        let json = r#"{
            "mode": "Encrypted",
            "ceiling": [],
            "ceiling_policy": "Immutable",
            "promotion_policy": "NoPromotion",
            "roles": [],
            "tools": [],
            "ttl": null,
            "memory_scope": "Ephemeral",
            "governance": "SingleAdmin",
            "template_id": null
        }"#;
        let params: ContextParams = serde_json::from_str(json).unwrap();
        assert!(params.economic_policy.is_none());
        // New fields should also get defaults via #[serde(default)].
        assert_eq!(
            params.metadata_visibility,
            MetadataVisibilityPolicy::default()
        );
        assert!(params.projection_policy.is_none());
        assert!(params.participation_requirements.is_empty());
    }

    // -----------------------------------------------------------------------
    // FieldVisibility
    // -----------------------------------------------------------------------

    #[test]
    fn field_visibility_default_is_pre_join() {
        assert_eq!(FieldVisibility::default(), FieldVisibility::PreJoin);
    }

    #[test]
    fn field_visibility_serialization_roundtrip() {
        for vis in [FieldVisibility::PreJoin, FieldVisibility::MemberOnly] {
            let json = serde_json::to_string(&vis).unwrap();
            let deserialized: FieldVisibility = serde_json::from_str(&json).unwrap();
            assert_eq!(vis, deserialized);
        }
    }

    // -----------------------------------------------------------------------
    // MetadataVisibilityPolicy
    // -----------------------------------------------------------------------

    #[test]
    fn metadata_visibility_policy_default_all_pre_join() {
        let policy = MetadataVisibilityPolicy::default();
        assert_eq!(policy.member_count, FieldVisibility::PreJoin);
        assert_eq!(policy.context_age, FieldVisibility::PreJoin);
        assert_eq!(policy.creator_identity, FieldVisibility::PreJoin);
        assert_eq!(policy.name, FieldVisibility::PreJoin);
        assert_eq!(policy.description, FieldVisibility::PreJoin);
        assert_eq!(policy.economic_policy, FieldVisibility::PreJoin);
        assert_eq!(policy.outlet_interface_count, FieldVisibility::PreJoin);
        assert_eq!(policy.child_context_info, FieldVisibility::PreJoin);
    }

    #[test]
    fn metadata_visibility_policy_serialization_roundtrip() {
        let policy = MetadataVisibilityPolicy {
            member_count: FieldVisibility::MemberOnly,
            context_age: FieldVisibility::PreJoin,
            creator_identity: FieldVisibility::MemberOnly,
            name: FieldVisibility::PreJoin,
            description: FieldVisibility::PreJoin,
            economic_policy: FieldVisibility::MemberOnly,
            outlet_interface_count: FieldVisibility::PreJoin,
            child_context_info: FieldVisibility::MemberOnly,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: MetadataVisibilityPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, deserialized);
    }

    // -----------------------------------------------------------------------
    // ProjectionRule / ProjectionPolicy
    // -----------------------------------------------------------------------

    #[test]
    fn projection_rule_serialization_roundtrip() {
        for rule in [
            ProjectionRule::Public,
            ProjectionRule::Gated,
            ProjectionRule::AuthorChoice,
        ] {
            let json = serde_json::to_string(&rule).unwrap();
            let deserialized: ProjectionRule = serde_json::from_str(&json).unwrap();
            assert_eq!(rule, deserialized);
        }
    }

    #[test]
    fn projection_policy_serialization_roundtrip() {
        let policy = ProjectionPolicy {
            default_rule: ProjectionRule::Gated,
            overrides: vec![ProjectionOverride {
                did: DID::from("did:dht:z6MkAuthor1"),
                rule: ProjectionRule::Public,
            }],
        };
        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: ProjectionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, deserialized);
    }

    #[test]
    fn projection_override_equality() {
        let a = ProjectionOverride {
            did: DID::from("did:dht:z6MkA"),
            rule: ProjectionRule::Public,
        };
        let b = ProjectionOverride {
            did: DID::from("did:dht:z6MkA"),
            rule: ProjectionRule::Public,
        };
        let c = ProjectionOverride {
            did: DID::from("did:dht:z6MkB"),
            rule: ProjectionRule::Gated,
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // -----------------------------------------------------------------------
    // PublicMetadata / public_metadata()
    // -----------------------------------------------------------------------

    /// Helper: build a `RuntimeMetadata` with all fields populated.
    fn full_runtime() -> RuntimeMetadata {
        RuntimeMetadata {
            member_count: Some(42),
            context_age: Some(86400),
            creator_identity: Some(DID::from("did:dht:z6MkCreator")),
            name: Some("Test Context".to_owned()),
            description: Some("A test context".to_owned()),
            outlet_interface_count: Some(3),
            child_context_info: Some(vec!["child-1".to_owned(), "child-2".to_owned()]),
            bridges: Vec::new(),
            bridge_operator_dids: Vec::new(),
        }
    }

    #[test]
    fn public_metadata_default_policy_returns_all_fields() {
        // Default MetadataVisibilityPolicy has all fields PreJoin,
        // so public_metadata() should return everything.
        let params = ContextParams {
            ceiling: vec![Capability::new("messages:read").expect("known capability")],
            mode: ContextMode::Encrypted,
            ..ContextParams::default()
        };
        let runtime = full_runtime();
        let meta = params.public_metadata(&runtime);

        // Structural fields always present.
        assert_eq!(meta.ceiling, params.ceiling);
        assert_eq!(meta.ceiling_policy, CeilingPolicy::Immutable);
        assert_eq!(meta.mode, ContextMode::Encrypted);
        assert_eq!(meta.promotion_policy, PromotionPolicy::NoPromotion);
        assert_eq!(meta.memory_scope, MemoryScope::Ephemeral);
        assert_eq!(meta.governance, GovernanceModel::SingleAdmin);
        assert!(meta.template_id.is_none());
        assert!(meta.ttl.is_none());
        assert!(meta.roles.is_empty());
        assert_eq!(
            meta.metadata_visibility,
            MetadataVisibilityPolicy::default()
        );

        // Operational fields all visible (PreJoin default).
        assert_eq!(meta.member_count, Some(42));
        assert_eq!(meta.context_age, Some(86400));
        assert_eq!(
            meta.creator_identity,
            Some(DID::from("did:dht:z6MkCreator"))
        );
        assert_eq!(meta.name, Some("Test Context".to_owned()));
        assert_eq!(meta.description, Some("A test context".to_owned()));
        assert_eq!(meta.outlet_interface_count, Some(3));
        assert_eq!(
            meta.child_context_info,
            Some(vec!["child-1".to_owned(), "child-2".to_owned()])
        );
    }

    #[test]
    fn public_metadata_member_count_hidden_when_member_only() {
        let params = ContextParams {
            metadata_visibility: MetadataVisibilityPolicy {
                member_count: FieldVisibility::MemberOnly,
                ..MetadataVisibilityPolicy::default()
            },
            ..ContextParams::default()
        };
        let runtime = full_runtime();
        let meta = params.public_metadata(&runtime);

        // member_count hidden.
        assert!(meta.member_count.is_none());

        // Other operational fields still visible.
        assert_eq!(meta.context_age, Some(86400));
        assert_eq!(
            meta.creator_identity,
            Some(DID::from("did:dht:z6MkCreator"))
        );
        assert_eq!(meta.name, Some("Test Context".to_owned()));
    }

    #[test]
    fn public_metadata_name_hidden_when_member_only() {
        let params = ContextParams {
            metadata_visibility: MetadataVisibilityPolicy {
                name: FieldVisibility::MemberOnly,
                ..MetadataVisibilityPolicy::default()
            },
            ..ContextParams::default()
        };
        let runtime = full_runtime();
        let meta = params.public_metadata(&runtime);

        assert!(meta.name.is_none());
        // Description still visible.
        assert_eq!(meta.description, Some("A test context".to_owned()));
    }

    #[test]
    fn public_metadata_structural_fields_always_present_regardless_of_policy() {
        // Even with all operational fields MemberOnly, structural fields persist.
        let params = ContextParams {
            ceiling: vec![
                Capability::new("messages:read").expect("known capability"),
                Capability::new("messages:write").expect("known capability"),
            ],
            ceiling_policy: CeilingPolicy::Governed,
            mode: ContextMode::Broadcast,
            ttl: Some(Duration::from_hours(2)),
            promotion_policy: PromotionPolicy::Promotable,
            memory_scope: MemoryScope::Full,
            governance: GovernanceModel::SingleAdmin,
            template_id: Some(TemplateId::PublicBroadcast),
            roles: vec![RoleDefinition {
                name: "admin".to_owned(),
                capabilities: HashSet::from([Capability::MessagesRead, Capability::MessagesWrite]),
            }],
            metadata_visibility: MetadataVisibilityPolicy {
                member_count: FieldVisibility::MemberOnly,
                context_age: FieldVisibility::MemberOnly,
                creator_identity: FieldVisibility::MemberOnly,
                name: FieldVisibility::MemberOnly,
                description: FieldVisibility::MemberOnly,
                economic_policy: FieldVisibility::MemberOnly,
                outlet_interface_count: FieldVisibility::MemberOnly,
                child_context_info: FieldVisibility::MemberOnly,
            },
            ..ContextParams::default()
        };
        let runtime = full_runtime();
        let meta = params.public_metadata(&runtime);

        // Structural fields present.
        assert_eq!(meta.ceiling.len(), 2);
        assert_eq!(meta.ceiling_policy, CeilingPolicy::Governed);
        assert_eq!(meta.mode, ContextMode::Broadcast);
        assert_eq!(meta.ttl, Some(Duration::from_hours(2)));
        assert_eq!(meta.promotion_policy, PromotionPolicy::Promotable);
        assert_eq!(meta.memory_scope, MemoryScope::Full);
        assert_eq!(meta.governance, GovernanceModel::SingleAdmin);
        assert_eq!(meta.template_id, Some(TemplateId::PublicBroadcast));
        assert_eq!(meta.roles.len(), 1);
        assert_eq!(
            meta.metadata_visibility.member_count,
            FieldVisibility::MemberOnly
        );

        // All operational fields hidden.
        assert!(meta.member_count.is_none());
        assert!(meta.context_age.is_none());
        assert!(meta.creator_identity.is_none());
        assert!(meta.name.is_none());
        assert!(meta.description.is_none());
        assert!(meta.economic_policy.is_none());
        assert!(meta.outlet_interface_count.is_none());
        assert!(meta.child_context_info.is_none());
    }

    #[test]
    fn public_metadata_economic_policy_filtered_from_context_params() {
        // economic_policy is the one operational field that lives on ContextParams,
        // not on RuntimeMetadata.
        use crate::economy::{Amount, CostSchedule, CurrencyCode, EconomicPolicy};

        let policy = EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: CurrencyCode::from("USD"),
                per_message: Some(Amount(1)),
                per_outlet_call: None,
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec!["x402".to_owned()],
            pricing_formula: None,
            payee: DID::from("did:dht:z6MkPayee"),
        };

        // Visible when PreJoin.
        let params = ContextParams {
            economic_policy: Some(policy.clone()),
            metadata_visibility: MetadataVisibilityPolicy::default(),
            ..ContextParams::default()
        };
        let meta = params.public_metadata(&RuntimeMetadata::default());
        assert_eq!(meta.economic_policy, Some(policy.clone()));

        // Hidden when MemberOnly.
        let params_hidden = ContextParams {
            economic_policy: Some(policy),
            metadata_visibility: MetadataVisibilityPolicy {
                economic_policy: FieldVisibility::MemberOnly,
                ..MetadataVisibilityPolicy::default()
            },
            ..ContextParams::default()
        };
        let meta_hidden = params_hidden.public_metadata(&RuntimeMetadata::default());
        assert!(meta_hidden.economic_policy.is_none());
    }

    #[test]
    fn public_metadata_runtime_none_stays_none_even_when_pre_join() {
        // When runtime doesn't supply a value, field is None regardless of policy.
        let params = ContextParams::default();
        let runtime = RuntimeMetadata::default();
        let meta = params.public_metadata(&runtime);

        assert!(meta.member_count.is_none());
        assert!(meta.context_age.is_none());
        assert!(meta.creator_identity.is_none());
        assert!(meta.name.is_none());
        assert!(meta.description.is_none());
        assert!(meta.outlet_interface_count.is_none());
        assert!(meta.child_context_info.is_none());
    }

    #[test]
    fn public_metadata_selective_field_hiding() {
        // Hide member_count, context_age, and creator_identity (bilateral-ephemeral style).
        let params = ContextParams {
            metadata_visibility: MetadataVisibilityPolicy {
                member_count: FieldVisibility::MemberOnly,
                context_age: FieldVisibility::MemberOnly,
                creator_identity: FieldVisibility::MemberOnly,
                ..MetadataVisibilityPolicy::default()
            },
            ..ContextParams::default()
        };
        let runtime = full_runtime();
        let meta = params.public_metadata(&runtime);

        // These three are hidden.
        assert!(meta.member_count.is_none());
        assert!(meta.context_age.is_none());
        assert!(meta.creator_identity.is_none());

        // Remaining operational fields still visible.
        assert_eq!(meta.name, Some("Test Context".to_owned()));
        assert_eq!(meta.description, Some("A test context".to_owned()));
        assert_eq!(meta.outlet_interface_count, Some(3));
        assert_eq!(
            meta.child_context_info,
            Some(vec!["child-1".to_owned(), "child-2".to_owned()])
        );
    }

    #[test]
    fn public_metadata_gated_broadcast_template_hides_member_count() {
        use crate::context::templates::template_params;
        let params = template_params(&TemplateId::GatedBroadcast);
        let runtime = full_runtime();
        let meta = params.public_metadata(&runtime);

        // Gated-broadcast template: member_count MemberOnly, all others PreJoin.
        assert!(meta.member_count.is_none(), "member_count should be hidden");
        // Other operational fields remain visible.
        assert!(meta.name.is_some());
        assert!(meta.description.is_some());
        assert!(meta.context_age.is_some());
        assert!(meta.creator_identity.is_some());
    }

    #[test]
    fn public_metadata_bilateral_ephemeral_template_hides_private_fields() {
        use crate::context::templates::template_params;
        let params = template_params(&TemplateId::BilateralEphemeral);
        let runtime = full_runtime();
        let meta = params.public_metadata(&runtime);

        // Bilateral-ephemeral: member_count, context_age, creator_identity
        // (and description, economic_policy, outlet_interface_count, child_context_info)
        // are all MemberOnly. Only name is PreJoin.
        assert!(meta.member_count.is_none(), "member_count should be hidden");
        assert!(meta.context_age.is_none(), "context_age should be hidden");
        assert!(
            meta.creator_identity.is_none(),
            "creator_identity should be hidden"
        );
        assert!(
            meta.description.is_none(),
            "description should be hidden for bilateral-ephemeral"
        );
        // Name is PreJoin.
        assert!(meta.name.is_some(), "name should be visible");
        // Structural fields always present.
        assert!(!meta.ceiling.is_empty());
    }

    #[test]
    fn public_metadata_serialization_roundtrip() {
        let params = ContextParams {
            ceiling: vec![Capability::new("messages:read").expect("known capability")],
            ..ContextParams::default()
        };
        let runtime = full_runtime();
        let meta = params.public_metadata(&runtime);

        let json = serde_json::to_string(&meta).unwrap();
        let deserialized: PublicMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(meta, deserialized);
    }

    // -----------------------------------------------------------------------
    // bridge_operator_dids in PublicMetadata (SCP-BCH-013, §12.6.1)
    // -----------------------------------------------------------------------

    #[test]
    fn public_metadata_bridge_operator_dids_empty_by_default() {
        let params = ContextParams::default();
        let runtime = RuntimeMetadata::default();
        let meta = params.public_metadata(&runtime);
        assert!(
            meta.bridge_operator_dids.is_empty(),
            "bridge_operator_dids should be empty when no bridges registered"
        );
    }

    #[test]
    fn public_metadata_bridge_operator_dids_populated_from_runtime() {
        let params = ContextParams::default();
        let runtime = RuntimeMetadata {
            bridge_operator_dids: vec![
                DID::from("did:dht:z6MkOperator1"),
                DID::from("did:dht:z6MkOperator2"),
            ],
            ..RuntimeMetadata::default()
        };
        let meta = params.public_metadata(&runtime);
        assert_eq!(meta.bridge_operator_dids.len(), 2);
        assert!(
            meta.bridge_operator_dids
                .contains(&DID::from("did:dht:z6MkOperator1"))
        );
        assert!(
            meta.bridge_operator_dids
                .contains(&DID::from("did:dht:z6MkOperator2"))
        );
    }

    #[test]
    fn public_metadata_bridge_operator_dids_always_visible() {
        // bridge_operator_dids is a structural field — always visible
        // regardless of MetadataVisibilityPolicy. Verify it's present even
        // when all operational fields are MemberOnly.
        let params = ContextParams {
            metadata_visibility: MetadataVisibilityPolicy {
                member_count: FieldVisibility::MemberOnly,
                context_age: FieldVisibility::MemberOnly,
                creator_identity: FieldVisibility::MemberOnly,
                name: FieldVisibility::MemberOnly,
                description: FieldVisibility::MemberOnly,
                economic_policy: FieldVisibility::MemberOnly,
                outlet_interface_count: FieldVisibility::MemberOnly,
                child_context_info: FieldVisibility::MemberOnly,
            },
            ..ContextParams::default()
        };
        let runtime = RuntimeMetadata {
            bridge_operator_dids: vec![DID::from("did:dht:z6MkBridgeOp")],
            member_count: Some(10),
            ..RuntimeMetadata::default()
        };
        let meta = params.public_metadata(&runtime);

        // Operational fields hidden.
        assert!(meta.member_count.is_none());
        // Bridge operator DIDs always visible.
        assert_eq!(meta.bridge_operator_dids.len(), 1);
        assert_eq!(
            meta.bridge_operator_dids[0],
            DID::from("did:dht:z6MkBridgeOp")
        );
    }

    #[test]
    fn public_metadata_bridge_operator_dids_serialization_roundtrip() {
        let params = ContextParams::default();
        let runtime = RuntimeMetadata {
            bridge_operator_dids: vec![DID::from("did:dht:z6MkOp1"), DID::from("did:dht:z6MkOp2")],
            ..RuntimeMetadata::default()
        };
        let meta = params.public_metadata(&runtime);

        let json = serde_json::to_string(&meta).unwrap();
        let deserialized: PublicMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(meta.bridge_operator_dids, deserialized.bridge_operator_dids);
    }

    // -----------------------------------------------------------------------
    // participation_requirements (SCP-BA-002, §7.3.2.1)
    // -----------------------------------------------------------------------

    #[test]
    fn participation_requirements_serde_roundtrip() {
        use crate::trust::{ParticipationFact, ParticipationThreshold, RequireParticipation};

        let params = ContextParams {
            participation_requirements: vec![
                RequireParticipation {
                    fact: ParticipationFact::OutletInvocationCount,
                    threshold: ParticipationThreshold::AtLeast(100),
                    max_age_secs: 86400,
                    min_contexts: 2,
                },
                RequireParticipation {
                    fact: ParticipationFact::ParticipationDuration,
                    threshold: ParticipationThreshold::GreaterThan(3600),
                    max_age_secs: 172800,
                    min_contexts: 1,
                },
            ],
            ..ContextParams::default()
        };

        let json = serde_json::to_string(&params).unwrap();
        let deserialized: ContextParams = serde_json::from_str(&json).unwrap();
        assert_eq!(params, deserialized);
        assert_eq!(deserialized.participation_requirements.len(), 2);
    }

    #[test]
    fn participation_requirements_backwards_compat() {
        // JSON without participation_requirements field deserializes to empty vec.
        let json = r#"{
            "mode": "Encrypted",
            "ceiling": [],
            "ceiling_policy": "Immutable",
            "promotion_policy": "NoPromotion",
            "roles": [],
            "tools": [],
            "ttl": null,
            "memory_scope": "Ephemeral",
            "governance": "SingleAdmin",
            "template_id": null
        }"#;
        let params: ContextParams = serde_json::from_str(json).unwrap();
        assert!(params.participation_requirements.is_empty());
    }

    // -----------------------------------------------------------------------
    // Version negotiation (spec §13.4, issue #607)
    // -----------------------------------------------------------------------

    #[test]
    fn decode_protocol_version_scp_1_0() {
        let (major, minor) = decode_protocol_version(0x0100);
        assert_eq!(major, 1);
        assert_eq!(minor, 0);
    }

    #[test]
    fn decode_protocol_version_scp_1_2() {
        let (major, minor) = decode_protocol_version(0x0102);
        assert_eq!(major, 1);
        assert_eq!(minor, 2);
    }

    #[test]
    fn encode_protocol_version_roundtrip() {
        for major in [0u8, 1, 2, 255] {
            for minor in [0u8, 1, 127, 255] {
                let packed = encode_protocol_version(major, minor);
                let (m, n) = decode_protocol_version(packed);
                assert_eq!((m, n), (major, minor));
            }
        }
    }

    #[test]
    fn context_params_default_min_protocol_version_is_none() {
        let params = ContextParams::default();
        assert!(params.min_protocol_version.is_none());
    }

    #[test]
    fn effective_min_protocol_version_defaults_to_1_0() {
        let params = ContextParams::default();
        assert_eq!(params.effective_min_protocol_version(), (1, 0));
    }

    #[test]
    fn effective_min_protocol_version_returns_set_value() {
        let params = ContextParams {
            min_protocol_version: Some((1, 2)),
            ..ContextParams::default()
        };
        assert_eq!(params.effective_min_protocol_version(), (1, 2));
    }

    #[test]
    fn check_version_compatibility_passes_for_matching_version() {
        let params = ContextParams {
            min_protocol_version: Some((1, 0)),
            ..ContextParams::default()
        };
        assert!(params.check_version_compatibility(0x0100).is_ok());
    }

    #[test]
    fn check_version_compatibility_passes_for_higher_minor_version() {
        let params = ContextParams {
            min_protocol_version: Some((1, 0)),
            ..ContextParams::default()
        };
        // SDK version 1.2 meets context requirement of 1.0.
        assert!(params.check_version_compatibility(0x0102).is_ok());
    }

    #[test]
    fn check_version_compatibility_fails_for_lower_minor_version() {
        let params = ContextParams {
            min_protocol_version: Some((1, 2)),
            ..ContextParams::default()
        };
        // SDK version 1.0 does not meet context requirement of 1.2.
        let result = params.check_version_compatibility(0x0100);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("1.2"),
            "error should mention required 1.2: {msg}"
        );
        assert!(
            msg.contains("1.0"),
            "error should mention supported 1.0: {msg}"
        );
    }

    #[test]
    fn check_version_compatibility_fails_for_different_major_version() {
        let params = ContextParams {
            min_protocol_version: Some((2, 0)),
            ..ContextParams::default()
        };
        // SDK version 1.0 does not meet context requirement of 2.0.
        let result = params.check_version_compatibility(0x0100);
        assert!(result.is_err());
    }

    #[test]
    fn check_version_compatibility_none_defaults_to_1_0_and_passes() {
        let params = ContextParams::default();
        // SDK version 1.0 (0x0100) meets default requirement of 1.0.
        assert!(params.check_version_compatibility(0x0100).is_ok());
    }

    #[test]
    fn min_protocol_version_serialization_roundtrip() {
        let params = ContextParams {
            min_protocol_version: Some((1, 3)),
            ..ContextParams::default()
        };
        let json = serde_json::to_string(&params).unwrap();
        let deserialized: ContextParams = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.min_protocol_version, Some((1, 3)));
    }

    #[test]
    fn min_protocol_version_backwards_compat_deserialization() {
        // JSON without min_protocol_version field deserializes to None.
        let json = r#"{
            "mode": "Encrypted",
            "ceiling": [],
            "ceiling_policy": "Immutable",
            "promotion_policy": "NoPromotion",
            "roles": [],
            "tools": [],
            "ttl": null,
            "memory_scope": "Ephemeral",
            "governance": "SingleAdmin",
            "template_id": null
        }"#;
        let params: ContextParams = serde_json::from_str(json).unwrap();
        assert!(params.min_protocol_version.is_none());
    }

    #[test]
    fn public_metadata_includes_min_protocol_version() {
        let params = ContextParams {
            min_protocol_version: Some((1, 2)),
            ..ContextParams::default()
        };
        let meta = params.public_metadata(&RuntimeMetadata::default());
        assert_eq!(meta.min_protocol_version, Some((1, 2)));
    }

    #[test]
    fn public_metadata_min_protocol_version_none_when_unset() {
        let params = ContextParams::default();
        let meta = params.public_metadata(&RuntimeMetadata::default());
        assert!(meta.min_protocol_version.is_none());
    }
}
