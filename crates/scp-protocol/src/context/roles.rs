//! Capability ceiling, role definitions, and role assignment for SCP contexts.
//!
//! This module implements the UCAN-based capability model from ADR-009 in
//! `.docs/adrs/phase-2.md`. Every action in a context requires a valid UCAN
//! capability token. The capability ceiling bounds the maximum set of operations
//! possible in a context, and roles define subsets of the ceiling that specific
//! agents can exercise.
//!
//! # Types
//!
//! - [`Capability`] -- Enumeration of all protocol-defined capabilities.
//! - [`CapabilityCeiling`] -- Immutable set of capabilities declared at context
//!   creation.
//! - [`RoleDefinition`] -- Named role mapping to a capability subset.
//! - [`UcanToken`] -- Lightweight UCAN token representation that populates the
//!   local `member_capabilities` cache (spec §7.2.2 Tier 2). See the type docs
//!   for why it carries no per-token signature.
//! - [`RoleError`] -- Error type for role and capability operations.
//!
//! # Built-in Roles
//!
//! Built-in roles are always available in every context:
//! - `admin` -- all capabilities in the ceiling.
//! - `moderator` -- `MessagesRead`, `MessagesWrite`, `OutletQueryAll`,
//!   `OutletCallAll`, `MemberRemove`, `GovernancePropose` (§5.9 elected
//!   moderators).
//! - `member` -- `MessagesRead`, `MessagesWrite`, `OutletQueryAll`,
//!   `OutletCallAll`.
//! - `observer` -- `MessagesRead` only.
//!
//! Broadcast-specific roles:
//! - `author` -- `MessagesWrite`, `MessagesRead`, `OutletQueryAll`,
//!   `OutletCallAll`.
//! - `subscriber` -- `MessagesRead` only.
//!
//! Custom roles are defined at context creation with arbitrary capability
//! subsets of the ceiling.
//!
//! See ADR-009 in `.docs/adrs/phase-2.md` for the full specification.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use scp_clock::Clock;

use super::ContextError;
use crate::crypto::ucan::nonce::generate_nonce;

// ---------------------------------------------------------------------------
// OutletId
// ---------------------------------------------------------------------------

/// Identifier for an outlet registered within a context.
///
/// This is a simple string type alias. The full `OutletRegistration` type is
/// defined in `params.rs`; this type identifies a specific outlet for
/// capability scoping (e.g., `OutletCall(outlet_id)`, `OutletQuery(outlet_id)`).
pub type OutletId = String;

// ---------------------------------------------------------------------------
// Capability
// ---------------------------------------------------------------------------

/// A single protocol-defined capability within an SCP context.
///
/// Capabilities define the atomic operations a participant can perform.
/// Every action in a context requires a valid UCAN token scoped to the
/// corresponding capability. Capabilities are mode-agnostic: `MessagesRead`
/// and `MessagesWrite` apply to both Encrypted and Broadcast context modes.
///
/// See ADR-009 acceptance criterion 1 and spec sections 5.3, 5.5, 7.2.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum Capability {
    /// Read messages in the context.
    MessagesRead,
    /// Write (send) messages in the context.
    MessagesWrite,
    /// Invoke a specific registered Query (read-only) outlet, identified by
    /// [`OutletId`] (§5.4.2).
    OutletQuery(OutletId),
    /// Invoke any registered Query outlet in the context (§5.4.2).
    OutletQueryAll,
    /// Invoke a specific registered Action (mutating) outlet, identified by
    /// [`OutletId`] (§5.4.2).
    OutletCall(OutletId),
    /// Invoke any registered Action outlet in the context (§5.4.2).
    OutletCallAll,
    /// Register new outlets in the context.
    OutletRegister,
    /// Invite new members to the context.
    MemberInvite,
    /// Remove members from the context.
    MemberRemove,
    /// Assign roles to members.
    RoleAssign,
    /// Propose governance actions.
    GovernancePropose,
    /// Vote on governance proposals.
    GovernanceVote,
    /// Close the context.
    ContextClose,
    /// Create child contexts with this context as parent (spec section 5.13).
    ChildContextCreate,
    /// Cross-context outlet interface exposure (spec section 6.2).
    OutletInterface,
    /// Bridge connector participation (spec section 12).
    Bridging,
    /// Real-time voice communication via delegated media transport (spec section 10.9.1).
    MediaVoice,
    /// Real-time video communication via delegated media transport (spec section 10.9.1).
    MediaVideo,
    /// Screen sharing via delegated media transport (spec section 10.9.1).
    MediaScreenShare,
    /// Ban a member from the context, revoking all access permanently (spec section 5.3).
    /// Gates the `Revoke` governance action.
    MemberBan,
    /// Edit context operational metadata (spec section 5.7, §5.3.1).
    MetadataEdit,
    /// Context-specific custom capability.
    Custom(String),
}

/// Validates an outlet-stem suffix against §5.4.2.1 step 2.
///
/// Returns `Some(suffix.to_owned())` if `suffix` matches the regex
/// `^[a-z0-9_-]{1,128}$`. Returns `None` for the empty string, suffixes
/// longer than 128 bytes, suffixes containing characters outside
/// `[a-z0-9_-]` (uppercase, colons, dots, etc.), or any other shape.
///
/// The wildcard `*` is NOT handled here — exact-name match handles it.
/// This helper is for the parameterized `outlet_query:{id}` /
/// `outlet_call:{id}` form only.
///
/// # Spec reference
///
/// `.docs/specs/05-contexts.md` §5.4.2.1 UCAN Capability Stem Parser
/// (step 2: opaque suffix with `outlet_id` validation). Identical bounds
/// must apply across every bridge per the parser-differential guard.
fn parse_outlet_suffix(suffix: &str) -> Option<String> {
    // Step 2a: length bound. Empty and >128 byte suffixes fail. The
    // length check uses bytes (UTF-8 is irrelevant — the alphabet is
    // ASCII) and `len()` matches the regex `{1,128}` quantifier.
    if suffix.is_empty() || suffix.len() > 128 {
        return None;
    }
    // Step 2b: character class. Every byte must be in `[a-z0-9_-]`.
    // Uppercase, colons, dots, slashes, plus signs, and any non-ASCII
    // bytes all reject. Walking bytes (rather than chars) is correct
    // because every accepted character is exactly one byte in UTF-8.
    if !suffix
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        return None;
    }
    Some(suffix.to_owned())
}

impl Capability {
    /// Creates a capability from a string name, applying strict validation
    /// for parameterized stems.
    ///
    /// Returns `None` if the input fails the §5.4.2.1 two-step parser for
    /// the `outlet_query:` / `outlet_call:` stems (or their SDK-facing
    /// `outlet:query:` / `outlet:call:` aliases), if it uses the deleted
    /// `outlet:invoke:` / `outlet_invoke:` stem (hard break per ADR-049 §1
    /// and SCP-OUT-014), or if it parses any pre-rename `tool:invoke:` /
    /// `tool_invoke:` legacy form. Otherwise returns `Some(capability)`.
    ///
    /// # Recognized exact names
    ///
    /// User-facing colon form (spec §5.3.1 table): `"messages:read"`,
    /// `"messages:write"`, `"outlet:query:*"`, `"outlet:call:*"`,
    /// `"outlet:register"`, `"member:invite"`, `"member:remove"`,
    /// `"role:assign"`, `"governance:propose"`, `"governance:vote"`,
    /// `"context:close"`, `"context:child:create"`, `"outlet:interface"`,
    /// `"bridging"`, `"media:voice"`, `"media:video"`, `"media:screen_share"`,
    /// `"member:ban"`, `"metadata:edit"`.
    ///
    /// It ALSO recognizes the **UCAN wire form** (the `{resource}:{action}`
    /// output of [`ucan_capability_name`](Self::ucan_capability_name), §7.3.4)
    /// for the multi-segment built-ins whose spelling differs from colon form:
    /// `"outlet_query:*"` (== `OutletQueryAll`), `"outlet_call:*"`
    /// (== `OutletCallAll`), `"context_child:create"` (== `ChildContextCreate`),
    /// and `"bridging:*"` (== `Bridging`). Recognizing these is what lets a
    /// context's STORED ceiling (kept in canonical UCAN form) round-trip back to
    /// the proper built-in enum.
    ///
    /// # Parameterized prefixes (strict — §5.4.2.1)
    ///
    /// - `"outlet:query:{id}"` and `"outlet_query:{id}"` parse as
    ///   [`OutletQuery(id)`](Self::OutletQuery).
    /// - `"outlet:call:{id}"` and `"outlet_call:{id}"` parse as
    ///   [`OutletCall(id)`](Self::OutletCall).
    ///
    /// The suffix after the stem prefix must be the literal wildcard `*` or
    /// match the regex `^[a-z0-9_-]{1,128}$`. Suffixes that contain a colon
    /// (`outlet_query:call:foo`), are empty (`outlet_query:`), use uppercase
    /// (`outlet_query:FOO`), or exceed the 128-byte length bound all return
    /// `None`. This is the parser-differential guard required by spec
    /// §5.4.2.1 step 2.
    ///
    /// # Custom prefix
    ///
    /// Names starting with `"custom:"` parse as `Custom(remainder)`. Anything
    /// else (with no recognized prefix) maps to `Custom(name)`.
    ///
    /// # Hard-break prefixes (always `None`)
    ///
    /// - `"outlet:invoke:..."` / `"outlet_invoke:..."` — deleted in
    ///   SCP-OUT-014 (no transitional alias, ADR-049 §1).
    /// - `"tool:invoke:..."` / `"tool_invoke:..."` — pre-rename legacy form
    ///   removed in SCP-OUT-002 (no transitional alias).
    /// - `"tool:register"`, `"tool:interface"` — pre-rename legacy form.
    ///
    /// [`name`](Self::name) and [`Display`](std::fmt::Display) always emit the
    /// canonical colon form, so `new(name())` and `new(to_string())` round-trip.
    #[must_use]
    pub fn new(name: impl AsRef<str>) -> Option<Self> {
        let n = name.as_ref();
        // Hard-break forms must NEVER parse — checked before any prefix
        // splitting so a `outlet_invoke:foo` cannot reach the Custom
        // catch-all below (ADR-049 §1, SCP-OUT-014).
        if n.starts_with("outlet:invoke:") || n.starts_with("outlet_invoke:") {
            return None;
        }
        if n == "outlet:invoke:*" || n == "outlet_invoke:*" {
            return None;
        }
        if n.starts_with("tool:invoke:") || n.starts_with("tool_invoke:") {
            return None;
        }
        if matches!(
            n,
            "tool:register" | "tool:interface" | "tool_register" | "tool_interface"
        ) {
            return None;
        }

        match n {
            // Built-in categories. Each arm lists the user-facing colon spelling
            // (spec §5.3.1 table) AND, for the multi-segment built-ins, the
            // equivalent UCAN wire spelling (the underscore-joined-resource output
            // of `ucan_capability_name`, §7.3.4) — the two spellings of the SAME
            // enumerated category. No valid custom collides: the custom grammar is
            // kebab-only (no `_` in the resource, §5.3.1.1).
            "messages:read" => Some(Self::MessagesRead),
            "messages:write" => Some(Self::MessagesWrite),
            "outlet:query:*" | "outlet_query:*" => Some(Self::OutletQueryAll),
            "outlet:call:*" | "outlet_call:*" => Some(Self::OutletCallAll),
            "outlet:register" => Some(Self::OutletRegister),
            "member:invite" => Some(Self::MemberInvite),
            "member:remove" => Some(Self::MemberRemove),
            "role:assign" => Some(Self::RoleAssign),
            "governance:propose" => Some(Self::GovernancePropose),
            "governance:vote" => Some(Self::GovernanceVote),
            "context:close" => Some(Self::ContextClose),
            "context:child:create" | "context_child:create" => Some(Self::ChildContextCreate),
            "outlet:interface" => Some(Self::OutletInterface),
            "bridging" | "bridging:*" => Some(Self::Bridging),
            "media:voice" => Some(Self::MediaVoice),
            "media:video" => Some(Self::MediaVideo),
            "media:screen_share" => Some(Self::MediaScreenShare),
            "member:ban" => Some(Self::MemberBan),
            "metadata:edit" => Some(Self::MetadataEdit),
            // Strict §5.4.2.1 parser for the four valid outlet-stem prefixes.
            // The wildcard `*` form is matched as an exact name above; the
            // remaining suffix must satisfy `parse_outlet_suffix`. Invalid
            // suffixes return `None` rather than falling back to Custom —
            // this is what distinguishes `outlet_query:call:foo` (parser-
            // differential rejection) from a Custom capability.
            _ if n.starts_with("outlet:query:") => {
                parse_outlet_suffix(&n["outlet:query:".len()..]).map(Self::OutletQuery)
            }
            _ if n.starts_with("outlet_query:") => {
                parse_outlet_suffix(&n["outlet_query:".len()..]).map(Self::OutletQuery)
            }
            _ if n.starts_with("outlet:call:") => {
                parse_outlet_suffix(&n["outlet:call:".len()..]).map(Self::OutletCall)
            }
            _ if n.starts_with("outlet_call:") => {
                parse_outlet_suffix(&n["outlet_call:".len()..]).map(Self::OutletCall)
            }
            // Custom prefix and bare custom names. The Custom catch-all is
            // unreachable for outlet-stem inputs because the four prefixes
            // above (and the hard-break checks at the top) already cover
            // every `outlet:` / `outlet_` shape.
            _ => Some(n.strip_prefix("custom:").map_or_else(
                || Self::Custom(n.to_owned()),
                |custom_name| Self::Custom(custom_name.to_owned()),
            )),
        }
    }

    /// Returns the canonical input name of this capability.
    ///
    /// For [`OutletQuery`](Self::OutletQuery) and [`OutletCall`](Self::OutletCall)
    /// variants, includes the outlet ID (e.g. `"outlet:query:my_outlet"`,
    /// `"outlet:call:my_outlet"`). For [`Custom`](Self::Custom) variants,
    /// returns the raw name without prefix (e.g. `"foo"`, not `"custom:foo"`).
    ///
    /// **Note:** This differs from [`Display`](std::fmt::Display) for Custom
    /// variants — Display prefixes `"custom:"` for disambiguation in logs.
    /// Both `new(name())` and `new(to_string())` roundtrip correctly.
    #[must_use]
    pub fn name(&self) -> std::borrow::Cow<'_, str> {
        match self {
            Self::MessagesRead => std::borrow::Cow::Borrowed("messages:read"),
            Self::MessagesWrite => std::borrow::Cow::Borrowed("messages:write"),
            Self::OutletQuery(id) => std::borrow::Cow::Owned(format!("outlet:query:{id}")),
            Self::OutletQueryAll => std::borrow::Cow::Borrowed("outlet:query:*"),
            Self::OutletCall(id) => std::borrow::Cow::Owned(format!("outlet:call:{id}")),
            Self::OutletCallAll => std::borrow::Cow::Borrowed("outlet:call:*"),
            Self::OutletRegister => std::borrow::Cow::Borrowed("outlet:register"),
            Self::MemberInvite => std::borrow::Cow::Borrowed("member:invite"),
            Self::MemberRemove => std::borrow::Cow::Borrowed("member:remove"),
            Self::RoleAssign => std::borrow::Cow::Borrowed("role:assign"),
            Self::GovernancePropose => std::borrow::Cow::Borrowed("governance:propose"),
            Self::GovernanceVote => std::borrow::Cow::Borrowed("governance:vote"),
            Self::ContextClose => std::borrow::Cow::Borrowed("context:close"),
            Self::ChildContextCreate => std::borrow::Cow::Borrowed("context:child:create"),
            Self::OutletInterface => std::borrow::Cow::Borrowed("outlet:interface"),
            Self::Bridging => std::borrow::Cow::Borrowed("bridging"),
            Self::MediaVoice => std::borrow::Cow::Borrowed("media:voice"),
            Self::MediaVideo => std::borrow::Cow::Borrowed("media:video"),
            Self::MediaScreenShare => std::borrow::Cow::Borrowed("media:screen_share"),
            Self::MemberBan => std::borrow::Cow::Borrowed("member:ban"),
            Self::MetadataEdit => std::borrow::Cow::Borrowed("metadata:edit"),
            Self::Custom(name) => std::borrow::Cow::Borrowed(name.as_str()),
        }
    }

    /// Returns the `(resource, action)` pair for UCAN capability URIs.
    ///
    /// The canonical user-facing format uses colons (e.g., `"outlet:call:*"`),
    /// but UCAN URIs use `{resource}:{action}` where `resource` is a single
    /// underscore-joined token. This method bridges the two formats:
    ///
    /// - `outlet:query:*`          -> `("outlet_query", "*")`
    /// - `outlet:query:calculator` -> `("outlet_query", "calculator")`
    /// - `outlet:call:*`           -> `("outlet_call", "*")`
    /// - `outlet:call:calculator`  -> `("outlet_call", "calculator")`
    /// - `context:child:create`    -> `("context_child", "create")`
    /// - `messages:write`          -> `("messages", "write")`
    /// - `context:close`           -> `("context", "close")`
    /// - `role:assign`             -> `("role", "assign")`
    /// - `bridging`                -> `("bridging", "*")`
    ///
    /// The returned strings are suitable for constructing
    /// [`CapabilityUri`](crate::crypto::ucan::capability::CapabilityUri) values
    /// and for building ceiling string sets (`{resource}:{action}`).
    ///
    /// See §5.4.2.1 for the outlet stem parser semantics.
    #[must_use]
    pub fn ucan_resource_action(&self) -> (std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>) {
        match self {
            Self::MessagesRead => (
                std::borrow::Cow::Borrowed("messages"),
                std::borrow::Cow::Borrowed("read"),
            ),
            Self::MessagesWrite => (
                std::borrow::Cow::Borrowed("messages"),
                std::borrow::Cow::Borrowed("write"),
            ),
            Self::OutletQuery(id) => (
                std::borrow::Cow::Borrowed("outlet_query"),
                std::borrow::Cow::Borrowed(id.as_str()),
            ),
            Self::OutletQueryAll => (
                std::borrow::Cow::Borrowed("outlet_query"),
                std::borrow::Cow::Borrowed("*"),
            ),
            Self::OutletCall(id) => (
                std::borrow::Cow::Borrowed("outlet_call"),
                std::borrow::Cow::Borrowed(id.as_str()),
            ),
            Self::OutletCallAll => (
                std::borrow::Cow::Borrowed("outlet_call"),
                std::borrow::Cow::Borrowed("*"),
            ),
            Self::OutletRegister => (
                std::borrow::Cow::Borrowed("outlet"),
                std::borrow::Cow::Borrowed("register"),
            ),
            Self::MemberInvite => (
                std::borrow::Cow::Borrowed("member"),
                std::borrow::Cow::Borrowed("invite"),
            ),
            Self::MemberRemove => (
                std::borrow::Cow::Borrowed("member"),
                std::borrow::Cow::Borrowed("remove"),
            ),
            Self::RoleAssign => (
                std::borrow::Cow::Borrowed("role"),
                std::borrow::Cow::Borrowed("assign"),
            ),
            Self::GovernancePropose => (
                std::borrow::Cow::Borrowed("governance"),
                std::borrow::Cow::Borrowed("propose"),
            ),
            Self::GovernanceVote => (
                std::borrow::Cow::Borrowed("governance"),
                std::borrow::Cow::Borrowed("vote"),
            ),
            Self::ContextClose => (
                std::borrow::Cow::Borrowed("context"),
                std::borrow::Cow::Borrowed("close"),
            ),
            Self::ChildContextCreate => (
                std::borrow::Cow::Borrowed("context_child"),
                std::borrow::Cow::Borrowed("create"),
            ),
            Self::OutletInterface => (
                std::borrow::Cow::Borrowed("outlet"),
                std::borrow::Cow::Borrowed("interface"),
            ),
            Self::Bridging => (
                std::borrow::Cow::Borrowed("bridging"),
                std::borrow::Cow::Borrowed("*"),
            ),
            Self::MediaVoice => (
                std::borrow::Cow::Borrowed("media"),
                std::borrow::Cow::Borrowed("voice"),
            ),
            Self::MediaVideo => (
                std::borrow::Cow::Borrowed("media"),
                std::borrow::Cow::Borrowed("video"),
            ),
            Self::MediaScreenShare => (
                std::borrow::Cow::Borrowed("media"),
                std::borrow::Cow::Borrowed("screen_share"),
            ),
            Self::MemberBan => (
                std::borrow::Cow::Borrowed("member"),
                std::borrow::Cow::Borrowed("ban"),
            ),
            Self::MetadataEdit => (
                std::borrow::Cow::Borrowed("metadata"),
                std::borrow::Cow::Borrowed("edit"),
            ),
            Self::Custom(name) => {
                // Custom capabilities use the `{resource}:{action}` form. Split on
                // the last colon to separate resource from action.
                if let Some((resource, action)) = name.rsplit_once(':') {
                    (
                        std::borrow::Cow::Owned(resource.replace(':', "_")),
                        std::borrow::Cow::Borrowed(action),
                    )
                } else {
                    // No colon. Well-formed ceiling entries are validated at
                    // context creation (`validate_ceiling_entry`, spec §5.3.1.1),
                    // so a no-colon custom can NEVER reach this point as a stored
                    // ceiling entry — it is rejected up front with
                    // `InvalidCeilingCategory`. This branch therefore never
                    // synthesizes the silent `name → name:*` wildcard that
                    // previously widened a no-colon custom: a defensive fallback
                    // maps the whole token to BOTH resource and action (a
                    // concrete, non-wildcard `name:name`), so even if a no-colon
                    // custom is constructed directly (e.g. in a test or via the
                    // raw enum), it can match only that one exact capability and
                    // can never grant `name:*`.
                    (
                        std::borrow::Cow::Borrowed(name.as_str()),
                        std::borrow::Cow::Borrowed(name.as_str()),
                    )
                }
            }
        }
    }

    /// Returns the UCAN capability name string in `{resource}:{action}` format.
    ///
    /// This is the format used in capability ceiling sets and
    /// [`CapabilityUri::capability_name()`](crate::crypto::ucan::capability::CapabilityUri::capability_name).
    /// Unlike [`name()`](Self::name) which returns the canonical user-facing
    /// colon format, this returns the UCAN-internal format with underscores
    /// for multi-segment resources.
    ///
    /// # Examples
    ///
    /// ```
    /// use scp_protocol::context::roles::Capability;
    ///
    /// assert_eq!(Capability::OutletCallAll.ucan_capability_name(), "outlet_call:*");
    /// assert_eq!(Capability::OutletQueryAll.ucan_capability_name(), "outlet_query:*");
    /// assert_eq!(Capability::MessagesWrite.ucan_capability_name(), "messages:write");
    /// assert_eq!(Capability::ChildContextCreate.ucan_capability_name(), "context_child:create");
    /// ```
    #[must_use]
    pub fn ucan_capability_name(&self) -> String {
        let (resource, action) = self.ucan_resource_action();
        format!("{resource}:{action}")
    }

    /// Validates this capability as a ceiling entry against the ceiling-entry
    /// grammar (spec §5.3.1.1).
    ///
    /// Built-in variants are well-formed by construction (they correspond to
    /// rows of the §5.3.1 table). [`OutletQuery`](Self::OutletQuery),
    /// [`OutletCall`](Self::OutletCall), and [`Custom`](Self::Custom) variants
    /// carry caller-supplied text, so they are
    /// reconstructed to their user-facing entry string ([`name`](Self::name)) and
    /// validated via [`validate_ceiling_entry`]. This is the enum-form entry point
    /// onto the single canonical string validator, so a malformed custom (e.g. a
    /// no-colon `Custom("payments")` or `Custom("*:*")`) is rejected at ceiling
    /// construction rather than silently widened or stored.
    ///
    /// # No privileged-built-in collision (the sole authoritative mechanism, §5.3.1.1)
    ///
    /// A [`Custom`](Self::Custom) wraps an arbitrary string that an untrusted peer
    /// can put on the wire (`Capability` derives a plain `Deserialize` with no
    /// normalization, so `{"Custom":"outlet:call:*"}` deserializes verbatim). Such
    /// a `Custom` projects through [`ucan_capability_name`](Self::ucan_capability_name)
    /// onto the EXACT canonical UCAN form of a privileged built-in — e.g.
    /// `Custom("outlet:call:*")` → `"outlet_call:*"` (== [`OutletCallAll`](Self::OutletCallAll))
    /// — so a non-conformant `Custom` could masquerade as "call any outlet" if it
    /// reached the stored ceiling. Plain grammar validation
    /// ([`validate_ceiling_entry`]) does NOT catch this: it early-accepts a built-in's
    /// COLON spelling (`outlet:call:*`, `outlet:call:{id}`) and otherwise applies only
    /// the custom `{resource}:{action}` grammar, neither of which distinguishes a
    /// masquerading custom from a legitimate one.
    ///
    /// The sound, spelling-agnostic enforcement — and the **single authoritative
    /// mechanism** for §5.3.1.1 "No privileged-built-in collision" — is to re-resolve
    /// the `Custom` string through the canonical parser [`Capability::new`]: if it
    /// resolves to ANY non-[`Custom`](Self::Custom) variant, the string names a
    /// built-in in SOME spelling (colon OR UCAN form, including the parameterized
    /// `OutletQuery(id)` / `OutletCall(id)` family for any concrete `outlet_id`)
    /// and the `Custom` is
    /// rejected. A legitimate custom (`Custom("payments:read")`) re-resolves back to a
    /// `Custom` and proceeds to grammar validation. This covers EVERY built-in
    /// spelling by construction — the parser is the single authority on "what string
    /// is a built-in" — rather than enumerating forbidden spellings. It is applied
    /// here, at the point a `Custom` value is admitted, because that is the only place
    /// a masquerading `Custom` (including one materialized directly from untrusted
    /// deserialized bytes that never passed through the colon parser at create time)
    /// can enter the stored ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`CeilingEntryError::InvalidCeilingCategory`] if this capability
    /// would be a malformed ceiling entry, or if it is a [`Custom`](Self::Custom)
    /// whose string names a built-in capability in any spelling (§5.3.1.1).
    pub fn validate_as_ceiling_entry(&self) -> Result<(), CeilingEntryError> {
        match self {
            // A `Custom` carries an arbitrary, untrusted string. Before applying the
            // custom grammar, reject any `Custom` that names a built-in in ANY
            // spelling: re-resolve through the canonical parser and reject unless it
            // round-trips back to a `Custom`. This is closed by construction over
            // every built-in spelling (colon AND UCAN form, including the
            // parameterized `outlet:query:{id}` / `outlet:call:{id}` family) because
            // `Capability::new` is the single authority on which strings are
            // built-ins — see the "No privileged-built-in collision" doc section
            // above (§5.3.1.1). A string the parser hard-rejects (`None`, e.g. a
            // deleted `outlet:invoke:*` stem) is likewise rejected here: it is not a
            // legitimate custom and must never enter the stored ceiling.
            Self::Custom(name) => {
                if !matches!(Self::new(name), Some(Self::Custom(_))) {
                    return Err(CeilingEntryError::invalid(
                        name,
                        "custom ceiling entry names a built-in capability (it resolves to a \
                         built-in variant in its colon or canonical UCAN spelling), or names a \
                         deleted/invalid stem the parser rejects; a custom must not masquerade \
                         as a privileged built-in (§5.3.1.1 no privileged-built-in collision)",
                    ));
                }
                validate_ceiling_entry(name)
            }
            // `OutletQuery(id)` / `OutletCall(id)` carry caller-supplied text —
            // route through the canonical string grammar using their user-facing
            // entry form. Built-in variants are well-formed by construction.
            Self::OutletQuery(_) | Self::OutletCall(_) => {
                validate_ceiling_entry(self.name().as_ref())
            }
            _ => Ok(()),
        }
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MessagesRead => write!(f, "messages:read"),
            Self::MessagesWrite => write!(f, "messages:write"),
            Self::OutletQuery(id) => write!(f, "outlet:query:{id}"),
            Self::OutletQueryAll => write!(f, "outlet:query:*"),
            Self::OutletCall(id) => write!(f, "outlet:call:{id}"),
            Self::OutletCallAll => write!(f, "outlet:call:*"),
            Self::OutletRegister => write!(f, "outlet:register"),
            Self::MemberInvite => write!(f, "member:invite"),
            Self::MemberRemove => write!(f, "member:remove"),
            Self::RoleAssign => write!(f, "role:assign"),
            Self::GovernancePropose => write!(f, "governance:propose"),
            Self::GovernanceVote => write!(f, "governance:vote"),
            Self::ContextClose => write!(f, "context:close"),
            Self::ChildContextCreate => write!(f, "context:child:create"),
            Self::OutletInterface => write!(f, "outlet:interface"),
            Self::Bridging => write!(f, "bridging"),
            Self::MediaVoice => write!(f, "media:voice"),
            Self::MediaVideo => write!(f, "media:video"),
            Self::MediaScreenShare => write!(f, "media:screen_share"),
            Self::MemberBan => write!(f, "member:ban"),
            Self::MetadataEdit => write!(f, "metadata:edit"),
            Self::Custom(name) => write!(f, "custom:{name}"),
        }
    }
}

// ---------------------------------------------------------------------------
// CapabilityCeiling
// ---------------------------------------------------------------------------

/// The capability ceiling for an SCP context.
///
/// Declared at context creation and immutable for the lifetime of the context
/// (spec section 5.3). The ceiling bounds the maximum set of operations any
/// participant can perform. Role permission sets must be subsets of the
/// ceiling. Members see the ceiling before joining -- it is part of the
/// opt-in contract (spec section 5.7).
///
/// See ADR-009 acceptance criterion 1.
///
/// # Well-formedness is a construction *and* deserialization invariant
///
/// Every entry in a `CapabilityCeiling` is well-formed per the ceiling-entry
/// grammar (spec §5.3.1.1) — this is guaranteed BY THE TYPE, not by callers
/// remembering to validate. There are exactly two ways a value of this type can
/// come into existence in production, and both route through
/// [`validate_entries`](Self::validate_entries):
///
/// 1. **In-process construction.** The whole-ceiling writers
///    ([`ContextRoleState::new`], [`ContextRoleState::set_ceiling`]) call
///    [`validate_entries`](Self::validate_entries) before storing, so a malformed
///    ceiling built with [`new`](Self::new) is rejected at the write.
/// 2. **Deserialization (the FROM-BYTES path).** `Deserialize` is implemented via
///    `#[serde(try_from = "CapabilityCeilingRaw")]`: the raw set is parsed first,
///    then [`TryFrom`] runs [`validate_entries`](Self::validate_entries) and
///    REJECTS the whole deserialization on the first malformed entry. This closes
///    every untrusted byte loader by construction —
///    `serde_json::from_str::<CapabilityCeiling>(malformed)` returns `Err`, and so
///    does any struct that embeds one (e.g. [`ContextRoleState`], the signed
///    context-export snapshot decoded by `rmp_serde::from_slice`). No per-loader
///    re-validation is required: a signature authenticates an export's ORIGIN, not
///    the WELL-FORMEDNESS of its payload, but the type now refuses to even
///    materialize a malformed ceiling from bytes.
///
/// Serialization is unchanged — the field still emits a content-sorted array via
/// [`serde_sorted_set`](crate::serde_util::serde_sorted_set), so the signed
/// export digest is byte-stable and a valid ceiling round-trips to an identical
/// value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "CapabilityCeilingRaw")]
pub struct CapabilityCeiling {
    /// The set of capabilities permitted in this context.
    ///
    /// Serialized in a deterministic (content-sorted) order so the signed
    /// context-export digest is reproducible (§23.16.8, ADR-050).
    ///
    /// PRIVATE (`pub(crate)`) — ADR-049 §9: the ceiling is a downward-authorization
    /// Class-S surface (a ceiling tightening that a coalesce-window rollback
    /// re-widens silently re-grants authority the caller observed as narrowed).
    /// Privatizing the backing set forces every cross-crate read through the
    /// inspection methods ([`Self::contains`], [`Self::iter`], [`Self::intersect`],
    /// [`Self::to_ucan_string_set`]) and every whole-ceiling WRITE through a named,
    /// greppable mutator ([`ContextRoleState::set_ceiling`]) that lives only behind
    /// a whole `&mut ContextRoleState` (post-migration, reachable only inside a
    /// fail-closed-persisting combinator). No best-effort view exposes a `&mut` to
    /// it.
    #[serde(with = "crate::serde_util::serde_sorted_set")]
    pub(crate) capabilities: HashSet<Capability>,
}

/// Raw, UNVALIDATED deserialization mirror of [`CapabilityCeiling`].
///
/// This is the `#[serde(try_from)]` source type: serde deserializes the wire
/// bytes into this struct (which carries NO well-formedness guarantee), then
/// [`TryFrom<CapabilityCeilingRaw> for CapabilityCeiling`] runs
/// [`CapabilityCeiling::validate_entries`] and rejects a malformed ceiling. It is
/// PRIVATE and exists ONLY as the deserialization waypoint — no code constructs
/// or stores a `CapabilityCeilingRaw`, so the validated [`CapabilityCeiling`]
/// remains the single materializable form from bytes.
#[derive(Deserialize)]
struct CapabilityCeilingRaw {
    #[serde(with = "crate::serde_util::serde_sorted_set")]
    capabilities: HashSet<Capability>,
}

impl TryFrom<CapabilityCeilingRaw> for CapabilityCeiling {
    type Error = CeilingEntryError;

    /// Validates every deserialized entry against the ceiling-entry grammar
    /// (spec §5.3.1.1) before producing a [`CapabilityCeiling`]. A malformed
    /// entry fails the whole deserialization with [`CeilingEntryError`].
    fn try_from(raw: CapabilityCeilingRaw) -> Result<Self, Self::Error> {
        let ceiling = Self {
            capabilities: raw.capabilities,
        };
        ceiling.validate_entries()?;
        Ok(ceiling)
    }
}

impl CapabilityCeiling {
    /// Creates a new capability ceiling from an iterator of capabilities.
    #[must_use]
    pub fn new(capabilities: impl IntoIterator<Item = Capability>) -> Self {
        Self {
            capabilities: capabilities.into_iter().collect(),
        }
    }

    /// Returns `true` if the given capability is within the ceiling.
    ///
    /// This is the core ceiling check used during UCAN validation and role
    /// definition. `OutletQuery(id)` is considered within the ceiling if either
    /// `OutletQuery(id)` or `OutletQueryAll` is in the ceiling. Likewise
    /// `OutletCall(id)` is implied by `OutletCallAll`. The two classes are
    /// disjoint: `OutletQueryAll` does NOT cover `OutletCall(id)` and
    /// `OutletCallAll` does NOT cover `OutletQuery(id)` (query ≠ call, §5.4.2).
    #[must_use]
    pub fn contains(&self, capability: &Capability) -> bool {
        if self.capabilities.contains(capability) {
            return true;
        }
        // OutletQuery(id) is implicitly allowed if OutletQueryAll is in the ceiling.
        if let Capability::OutletQuery(_) = capability {
            return self.capabilities.contains(&Capability::OutletQueryAll);
        }
        // OutletCall(id) is implicitly allowed if OutletCallAll is in the ceiling.
        if let Capability::OutletCall(_) = capability {
            return self.capabilities.contains(&Capability::OutletCallAll);
        }
        false
    }

    /// Returns `true` if all capabilities in the given set are within the ceiling.
    #[must_use]
    pub fn contains_all(&self, capabilities: &HashSet<Capability>) -> bool {
        capabilities.iter().all(|cap| self.contains(cap))
    }

    /// Returns `true` if the ceiling has no capabilities.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }

    /// Returns the number of capabilities in the ceiling.
    #[must_use]
    pub fn len(&self) -> usize {
        self.capabilities.len()
    }

    /// Iterates the capabilities permitted by this ceiling (read-only).
    ///
    /// Replaces direct `ceiling.capabilities.iter()` field access now that the
    /// backing set is private (ADR-049 §9). A shared iterator cannot mutate the
    /// downward-auth ceiling, so it raises no fail-closed obligation.
    pub fn iter(&self) -> impl Iterator<Item = &Capability> {
        self.capabilities.iter()
    }

    /// Returns the set-intersection of this ceiling with `other` as a plain
    /// capability set (read-only over both ceilings).
    ///
    /// Replaces direct `a.capabilities.intersection(&b.capabilities)` field
    /// access (e.g. child-ceiling inheritance, §5.13.1) now that the backing set
    /// is private (ADR-049 §9).
    #[must_use]
    pub fn intersect(&self, other: &Self) -> HashSet<Capability> {
        self.capabilities
            .intersection(&other.capabilities)
            .cloned()
            .collect()
    }

    /// TEST-ONLY mutable access to the backing capability set.
    ///
    /// Gated `#[cfg(any(test, feature = "testing"))]` — never compiled into a
    /// production (non-`testing`) build. Used by determinism / canonicalization +
    /// tamper-detection tests (including downstream `scp-runtime` export tests,
    /// which enable `scp-protocol/testing`) that need to mutate the set in place.
    /// Production ceiling writes go through [`ContextRoleState::set_ceiling`], which
    /// replaces the WHOLE ceiling behind a fail-closed-persisting combinator
    /// (ADR-049 §9).
    #[cfg(any(test, feature = "testing"))]
    pub const fn capabilities_mut(&mut self) -> &mut HashSet<Capability> {
        &mut self.capabilities
    }

    /// Returns the capabilities as UCAN-formatted string names.
    ///
    /// Each capability is converted to its UCAN wire-format name via
    /// [`Capability::ucan_capability_name`]. Useful for passing ceilings
    /// to UCAN mint/delegate operations.
    #[must_use]
    pub fn to_ucan_string_set(&self) -> HashSet<String> {
        self.capabilities
            .iter()
            .map(Capability::ucan_capability_name)
            .collect()
    }

    /// Validates every entry in this ceiling against the ceiling-entry grammar
    /// (spec §5.3.1.1). Called at context creation so a malformed entry cannot be
    /// stored; the first malformed entry short-circuits with its error.
    ///
    /// # Errors
    ///
    /// Returns [`CeilingEntryError::InvalidCeilingCategory`] for the first entry
    /// that is not a recognized built-in category nor a well-formed custom
    /// capability.
    pub fn validate_entries(&self) -> Result<(), CeilingEntryError> {
        for cap in &self.capabilities {
            cap.validate_as_ceiling_entry()?;
        }
        Ok(())
    }
}

/// Returns the default capability ceiling for new contexts.
///
/// Includes all standard SCP capabilities: messaging, outlet management, role
/// assignment, membership control, governance, and context close. Used by
/// all FFI bridges when no explicit ceiling is provided.
#[must_use]
pub fn default_ceiling() -> CapabilityCeiling {
    CapabilityCeiling::new([
        Capability::MessagesRead,
        Capability::MessagesWrite,
        Capability::OutletRegister,
        Capability::OutletQueryAll,
        Capability::OutletCallAll,
        Capability::RoleAssign,
        Capability::MemberInvite,
        Capability::MemberRemove,
        Capability::GovernancePropose,
        Capability::GovernanceVote,
        Capability::ContextClose,
    ])
}

// ---------------------------------------------------------------------------
// Ceiling-entry grammar (spec §5.3.1.1)
// ---------------------------------------------------------------------------

/// Maximum byte length of a single ceiling entry string (spec §5.3.1.1 / §9.1A
/// "String field validation"). Entries exceeding this cap are rejected.
pub const MAX_CEILING_ENTRY_LENGTH: usize = 256;

/// Maximum byte length of an `outlet_id` in a parameterized
/// `outlet:query:{outlet_id}` / `outlet:call:{outlet_id}` built-in entry (spec
/// §5.4.1 `OutletRegistration.outlet_id`, `max 128 chars`).
const MAX_OUTLET_ID_LENGTH: usize = 128;

/// The exhaustive set of non-parameterized built-in capability category strings
/// (spec §5.3.1 table). These are matched exactly and case-sensitively. The
/// parameterized `outlet:query:{outlet_id}` / `outlet:call:{outlet_id}` and the
/// resource wildcards `outlet:query:*` / `outlet:call:*` are validated
/// separately (see [`validate_ceiling_entry`]).
const BUILTIN_CEILING_CATEGORIES: &[&str] = &[
    "messages:read",
    "messages:write",
    "outlet:register",
    "outlet:query:*",
    "outlet:call:*",
    "member:invite",
    "member:remove",
    "member:ban",
    "role:assign",
    "media:voice",
    "media:video",
    "media:screen_share",
    "bridging",
    "outlet:interface",
    "context:child:create",
    "governance:propose",
    "governance:vote",
    "context:close",
    "metadata:edit",
];

/// Error produced when a ceiling entry is not well-formed per the
/// ceiling-entry grammar (spec §5.3.1.1).
///
/// Surfaced at EVERY ceiling write — context creation
/// ([`ContextRoleState::new`]) and the whole-ceiling mutator
/// ([`ContextRoleState::set_ceiling`]) — so a malformed entry causes the write to
/// fail and can never be stored in a [`CapabilityCeiling`] by construction. The
/// single variant carries the spec-named `InvalidCeilingCategory` semantics plus
/// the offending entry and a human-readable reason for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CeilingEntryError {
    /// A ceiling entry is neither a recognized built-in category (spec §5.3.1)
    /// nor a well-formed custom capability (spec §5.3.1.1). This is the
    /// protocol's `InvalidCeilingCategory` error.
    #[error("InvalidCeilingCategory: ceiling entry {entry:?} is malformed ({reason})")]
    InvalidCeilingCategory {
        /// The offending ceiling entry, exactly as supplied.
        entry: String,
        /// Why the entry is malformed (which grammar rule it violated).
        reason: String,
    },
}

impl CeilingEntryError {
    /// Constructs an [`Self::InvalidCeilingCategory`] for `entry` with `reason`.
    fn invalid(entry: &str, reason: impl Into<String>) -> Self {
        Self::InvalidCeilingCategory {
            entry: entry.to_owned(),
            reason: reason.into(),
        }
    }
}

/// The exhaustive list of non-parameterized built-in [`Capability`] variants.
///
/// Single source of truth for "which capabilities are built-ins" — the
/// parameterized [`Capability::OutletQuery`] / [`Capability::OutletCall`] and
/// [`Capability::Custom`] carry caller text and are validated through the
/// grammar, so they are deliberately
/// excluded here. Used by [`validate_ucan_ceiling_string`] to recognize the
/// canonical UCAN-form spelling of every built-in (its
/// [`Capability::ucan_capability_name`]). Adding a built-in variant is a compile
/// error here only if this list is matched exhaustively; it is kept aligned with
/// the enum by the `builtin_capabilities_list_is_exhaustive` test.
const BUILTIN_CAPABILITIES: &[Capability] = &[
    Capability::MessagesRead,
    Capability::MessagesWrite,
    Capability::OutletQueryAll,
    Capability::OutletCallAll,
    Capability::OutletRegister,
    Capability::MemberInvite,
    Capability::MemberRemove,
    Capability::RoleAssign,
    Capability::GovernancePropose,
    Capability::GovernanceVote,
    Capability::ContextClose,
    Capability::ChildContextCreate,
    Capability::OutletInterface,
    Capability::Bridging,
    Capability::MediaVoice,
    Capability::MediaVideo,
    Capability::MediaScreenShare,
    Capability::MemberBan,
    Capability::MetadataEdit,
];

/// Validates a ceiling entry supplied in **UCAN wire form**
/// (`{resource}:{action}`, the output of [`Capability::ucan_capability_name`])
/// against the ceiling-entry grammar (spec §5.3.1.1).
///
/// This is the import-path counterpart to [`validate_ceiling_entry`]. The two
/// validators recognize the SAME set of capabilities but accept DIFFERENT
/// spellings, because the two paths carry different vocabularies:
///
/// - [`validate_ceiling_entry`] validates **user-facing colon form** (e.g.
///   `outlet:call:*`, `context:child:create`) — what `create_context` /
///   `ModifyCeiling` receive, where built-ins resolve to enum variants via
///   [`Capability::new`] and skip the string grammar entirely.
/// - This function validates **UCAN form** (e.g. `outlet_call:*`,
///   `context_child:create`) — what a context's stored ceiling string set and a
///   signed export snapshot carry. A built-in's UCAN spelling can contain `_`
///   (from a multi-segment resource), which the kebab grammar in
///   [`validate_ceiling_entry`] deliberately forbids for *custom* entries, so a
///   UCAN-form built-in must be recognized as a built-in rather than parsed as a
///   custom.
///
/// A UCAN-form entry is well-formed iff it is **exactly one** of:
/// 1. the [`Capability::ucan_capability_name`] of a non-parameterized built-in
///    ([`BUILTIN_CAPABILITIES`]);
/// 2. a parameterized `outlet_query:{outlet_id}` / `outlet_call:{outlet_id}`
///    whose `outlet_id` is a non-empty `[a-z0-9_-]` token (spec §5.4.1) —
///    `outlet_query:*` / `outlet_call:*` are already covered by rule 1 via
///    [`Capability::OutletQueryAll`] / [`Capability::OutletCallAll`];
/// 3. a well-formed custom `{resource}:{action}` accepted by the shared
///    [`validate_custom_ceiling_entry`] grammar core.
///
/// Every built-in UCAN form is recognized by rule 1 BEFORE the custom grammar
/// core is reached, so a legitimate built-in is never misclassified as a custom on
/// this path. The import path stores raw UCAN strings verbatim with no `Custom`
/// wrapper, so the §5.3.1.1 collision rule (which guards `Custom` values) has no
/// surface here.
///
/// # Errors
///
/// Returns [`CeilingEntryError::InvalidCeilingCategory`] if `entry` is not a
/// well-formed UCAN-form ceiling entry.
pub fn validate_ucan_ceiling_string(entry: &str) -> Result<(), CeilingEntryError> {
    // Length cap + character sanitization (§9.1A), shared with the colon-form
    // validator so both reject oversize/control/HTML/whitespace identically.
    validate_ceiling_entry_charset(entry)?;

    // 1. Built-in UCAN spelling — exact match against every built-in's
    //    `ucan_capability_name()`.
    if BUILTIN_CAPABILITIES
        .iter()
        .any(|c| c.ucan_capability_name() == entry)
    {
        return Ok(());
    }

    // 2. Parameterized `outlet_query:{outlet_id}` / `outlet_call:{outlet_id}`
    //    (UCAN form). The `*` wildcards are built-ins handled above; here
    //    `outlet_id` is a concrete id and MUST NOT contain `*`.
    if let Some(outlet_id) = entry
        .strip_prefix("outlet_query:")
        .or_else(|| entry.strip_prefix("outlet_call:"))
    {
        if outlet_id.len() > MAX_OUTLET_ID_LENGTH {
            return Err(CeilingEntryError::invalid(
                entry,
                format!("outlet_id exceeds maximum length of {MAX_OUTLET_ID_LENGTH} bytes"),
            ));
        }
        if is_outlet_id_token(outlet_id) {
            return Ok(());
        }
        return Err(CeilingEntryError::invalid(
            entry,
            "outlet_id must be a non-empty [a-z0-9_-] token (no '*', no ':', no whitespace)",
        ));
    }

    // 3. Custom capability: a valid custom's UCAN form equals its colon form
    //    (single colon, kebab resource — no conversion-introduced `_`), so the
    //    shared custom grammar accepts it verbatim. We call the custom core
    //    directly (NOT `validate_ceiling_entry`) so a non-canonical COLON-form
    //    built-in (e.g. `outlet:call:*`, `context:child:create`) is rejected on
    //    the UCAN/import path — the stored vocabulary is strictly UCAN form, and
    //    accepting a colon-form built-in here would let an import store a spelling
    //    that diverges from the canonical form every gate check matches against.
    validate_custom_ceiling_entry(entry)
}

/// Shared length-cap + character-sanitization prelude for BOTH ceiling-entry
/// validators ([`validate_ceiling_entry`] colon form and
/// [`validate_ucan_ceiling_string`] UCAN form), per §9.1A string-field
/// validation. Rejects, before any structural parse: an entry exceeding
/// [`MAX_CEILING_ENTRY_LENGTH`] bytes, any control character
/// (U+0000–U+001F / U+007F–U+009F), any whitespace, and any HTML-special
/// character (`< > & " '`). Both validators MUST reject these identically, so
/// the check lives in one place.
///
/// # Errors
///
/// Returns [`CeilingEntryError::InvalidCeilingCategory`] if `entry` is oversize
/// or contains a forbidden character.
fn validate_ceiling_entry_charset(entry: &str) -> Result<(), CeilingEntryError> {
    if entry.len() > MAX_CEILING_ENTRY_LENGTH {
        return Err(CeilingEntryError::invalid(
            entry,
            format!(
                "exceeds maximum length of {MAX_CEILING_ENTRY_LENGTH} bytes (got {} bytes)",
                entry.len()
            ),
        ));
    }
    for ch in entry.chars() {
        if ch.is_control() {
            return Err(CeilingEntryError::invalid(
                entry,
                "contains a control character (U+0000–U+001F / U+007F–U+009F)",
            ));
        }
        if ch.is_whitespace() {
            return Err(CeilingEntryError::invalid(entry, "contains whitespace"));
        }
        if matches!(ch, '<' | '>' | '&' | '"' | '\'') {
            return Err(CeilingEntryError::invalid(
                entry,
                "contains an HTML-special character (< > & \" ')",
            ));
        }
    }
    Ok(())
}

/// Returns `true` if every byte of `token` is in the kebab-case charset
/// `[a-z0-9-]` and `token` is non-empty (spec §5.3.1.1). No `:`, no `*`, no
/// whitespace, no uppercase — the charset is exact and closed.
fn is_kebab_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Returns `true` if every byte of `outlet_id` is in the §5.4.1 `outlet_id`
/// charset `[a-z0-9_-]` and `outlet_id` is non-empty. Differs from
/// [`is_kebab_token`] by also permitting `_` (underscore), per §5.4.1.
fn is_outlet_id_token(outlet_id: &str) -> bool {
    !outlet_id.is_empty()
        && outlet_id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Validates a single ceiling entry string against the ceiling-entry grammar.
///
/// This (spec §5.3.1.1) is the SINGLE canonical definition of "well-formed
/// ceiling entry"; every construction and bridge path routes through it (via
/// [`Capability::validate_as_ceiling_entry`] for enum-form entries) so a
/// malformed entry can never be stored.
///
/// A well-formed entry is **exactly one** of:
/// 1. a built-in category — exact, case-sensitive match against the §5.3.1
///    table (including parameterized `outlet:query:{outlet_id}` /
///    `outlet:call:{outlet_id}` and the resource wildcards `outlet:query:*` /
///    `outlet:call:*`);
/// 2. a custom `{resource}:{action}` — exactly one colon; both tokens non-empty
///    kebab-case `[a-z0-9-]+`;
/// 3. an explicit resource wildcard `{resource}:*` — `{resource}` kebab-case;
///    the action segment is the single literal `*`.
///
/// Everything else is rejected with [`CeilingEntryError::InvalidCeilingCategory`]:
/// single-token customs (no colon, e.g. `payments`), a stray `*` anywhere except
/// as a whole action segment (`*:*`, `*:read`, `pay*ments`, `payments:wr*`),
/// more than one colon (`payments:read:write`), empty resource/action, characters
/// outside the kebab charset, whitespace, control characters
/// (U+0000–U+001F / U+007F–U+009F), HTML-special characters (`< > & " '`), and
/// strings exceeding [`MAX_CEILING_ENTRY_LENGTH`] bytes. There is **no implicit
/// or silent wildcard** — a wildcard must be written explicitly as `:*`.
///
/// This validator checks **grammar only**. The §5.3.1.1 "No privileged-built-in
/// collision" rule is enforced separately, by canonical resolution at the point a
/// `Custom` value is admitted ([`Capability::validate_as_ceiling_entry`]).
///
/// # Errors
///
/// Returns [`CeilingEntryError::InvalidCeilingCategory`] if `entry` is not
/// well-formed per the ceiling-entry grammar (§5.3.1.1).
pub(crate) fn validate_ceiling_entry(entry: &str) -> Result<(), CeilingEntryError> {
    // Length cap + character sanitization (§9.1A), shared with the UCAN-form
    // validator so both reject oversize/control/HTML/whitespace identically.
    validate_ceiling_entry_charset(entry)?;

    // 1. Built-in categories: exact, case-sensitive match.
    if BUILTIN_CEILING_CATEGORIES.contains(&entry) {
        return Ok(());
    }

    // 1b. Parameterized built-in: `outlet:query:{outlet_id}` /
    // `outlet:call:{outlet_id}` (the `*` forms are in the table above). The
    // outlet_id follows §5.4.1's charset/length (allows `_`).
    if let Some(outlet_id) = entry
        .strip_prefix("outlet:query:")
        .or_else(|| entry.strip_prefix("outlet:call:"))
    {
        // `outlet:query:*` / `outlet:call:*` already matched as built-ins above;
        // here outlet_id is a concrete id and MUST NOT contain a `*`.
        if outlet_id.len() > MAX_OUTLET_ID_LENGTH {
            return Err(CeilingEntryError::invalid(
                entry,
                format!("outlet_id exceeds maximum length of {MAX_OUTLET_ID_LENGTH} bytes"),
            ));
        }
        if is_outlet_id_token(outlet_id) {
            return Ok(());
        }
        return Err(CeilingEntryError::invalid(
            entry,
            "outlet_id must be a non-empty [a-z0-9_-] token (no '*', no ':', no whitespace)",
        ));
    }

    // 2 & 3. Custom capability — delegated to the shared custom-grammar core so
    // the colon-form (this function) and the UCAN-form
    // ([`validate_ucan_ceiling_string`]) validators apply ONE definition of a
    // well-formed custom entry.
    validate_custom_ceiling_entry(entry)
}

/// Validates the CUSTOM `{resource}:{action}` portion of the ceiling-entry
/// grammar (spec §5.3.1.1) — the rules shared by [`validate_ceiling_entry`]
/// (colon form) and [`validate_ucan_ceiling_string`] (UCAN form) once the
/// built-in and parameterized `outlet_query` / `outlet_call` spellings have been excluded by the
/// caller. A well-formed custom entry has EXACTLY ONE colon, a non-empty
/// kebab-case `[a-z0-9-]+` resource, and an action that is either a kebab-case
/// token or the single literal `*` (explicit wildcard). There is no silent
/// widening — a no-colon token is rejected, not widened to a wildcard.
///
/// Note: a well-formed custom's UCAN spelling is byte-identical to its colon
/// spelling (the resource is single-segment, so no `:`→`_` conversion occurs),
/// which is why both validators can share this core.
///
/// This function performs the ceiling-entry **grammar** checks, plus the §5.3.1.1
/// "No built-in-resource wildcard shadow" rule (a custom `{resource}:*` whose
/// `{resource}` is a built-in resource token is rejected — see the inline comment
/// at that check). The separate §5.3.1.1 "No privileged-built-in collision" rule
/// (a custom that *names* a built-in in some spelling) is NOT enforced here: it is
/// enforced by canonical resolution at the point a `Custom` value is admitted — see
/// [`Capability::validate_as_ceiling_entry`], which re-resolves the string through
/// [`Capability::new`] and rejects anything that does not round-trip back to a
/// `Custom`.
///
/// # Errors
///
/// Returns [`CeilingEntryError::InvalidCeilingCategory`] if `entry` is not a
/// well-formed custom ceiling entry, or if it is a `{resource}:*` wildcard whose
/// `{resource}` is the resource token of a built-in capability (§5.3.1.1).
fn validate_custom_ceiling_entry(entry: &str) -> Result<(), CeilingEntryError> {
    let Some((resource, action)) = entry.split_once(':') else {
        return Err(CeilingEntryError::invalid(
            entry,
            "single-token custom (no colon); a custom capability must be \
             resource:action and is never silently widened to a wildcard",
        ));
    };

    // More than one colon is malformed (e.g. `payments:read:write`).
    if action.contains(':') {
        return Err(CeilingEntryError::invalid(
            entry,
            "more than one colon; a custom ceiling entry has exactly one colon",
        ));
    }

    // The resource token is always a kebab-case token (never `*`).
    if !is_kebab_token(resource) {
        return Err(CeilingEntryError::invalid(
            entry,
            "resource must be a non-empty kebab-case [a-z0-9-] token (no '*', no whitespace)",
        ));
    }

    // The action is either the single literal `*` (explicit wildcard) or a
    // kebab-case token. A `*` as a substring (e.g. `wr*`) is never accepted.
    if !(action == "*" || is_kebab_token(action)) {
        return Err(CeilingEntryError::invalid(
            entry,
            "action must be a non-empty kebab-case [a-z0-9-] token or the single literal '*'",
        ));
    }

    // §5.3.1.1 "No built-in-resource wildcard shadow": a custom shape-3 wildcard
    // `{resource}:*` whose `{resource}` is the resource token of any built-in is
    // rejected. Unlike the no-collision rule (enforced by canonical resolution in
    // `Capability::validate_as_ceiling_entry`), this rule IS enforced here in the
    // grammar core and IS reachable/load-bearing on the UCAN-import path: a raw
    // peer-export string like `member:*` flows `validate_ucan_ceiling_string` ->
    // rule 3 -> here, never wrapped in a `Custom` and never re-resolved. Such a
    // wildcard does not name a built-in (there is no `member:*` variant), so
    // canonical resolution cannot catch it; yet ceiling wildcard coverage
    // (`CapabilityUri::is_within_ceiling`: `ceiling.contains("{resource}:*")`) would
    // let it silently grant the privileged built-in actions in that family (e.g.
    // `member:ban`, which gates governance `Revoke`). The reserved set is the
    // built-in resource tokens under the SAME `{resource}` projection
    // `is_within_ceiling` matches against (`Capability::ucan_resource_action().0`),
    // so this is closed-by-construction over `BUILTIN_CAPABILITIES` — not a denylist.
    if action == "*"
        && BUILTIN_CAPABILITIES
            .iter()
            .any(|c| c.ucan_resource_action().0.as_ref() == resource)
    {
        return Err(CeilingEntryError::invalid(
            entry,
            "custom resource wildcard shadows a built-in capability family \
             (§5.3.1.1 no built-in-resource wildcard shadow)",
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// check_ceiling (free function)
// ---------------------------------------------------------------------------

/// Returns `true` if the given capability is within the ceiling.
///
/// This is the top-level convenience function called during every UCAN
/// validation and at role definition time. Delegates to
/// [`CapabilityCeiling::contains`].
///
/// See ADR-009 acceptance criterion 6.
#[must_use]
pub fn check_ceiling(ceiling: &CapabilityCeiling, capability: &Capability) -> bool {
    ceiling.contains(capability)
}

// ---------------------------------------------------------------------------
// RoleDefinition
// ---------------------------------------------------------------------------

/// Definition of a role within an SCP context.
///
/// A role maps a name to a set of capabilities that are a subset of the
/// context's capability ceiling. Roles are defined at context creation or
/// via role management operations. Built-in roles (`admin`, `member`,
/// `observer`) are always available.
///
/// See ADR-009 acceptance criterion 2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleDefinition {
    /// The role name (e.g., `"admin"`, `"member"`, `"observer"`).
    pub name: String,
    /// The set of capabilities granted to participants with this role.
    /// Must be a subset of the context's capability ceiling.
    ///
    /// Serialized in a deterministic (content-sorted) order so the signed
    /// context-export digest is reproducible (§23.16.8, ADR-050).
    #[serde(with = "crate::serde_util::serde_sorted_set")]
    pub capabilities: HashSet<Capability>,
}

impl RoleDefinition {
    /// Creates a new role definition.
    ///
    /// # Errors
    ///
    /// Returns [`RoleError::CapabilityOutsideCeiling`] if any capability in
    /// the role is not within the provided ceiling.
    pub fn new(
        name: impl Into<String>,
        capabilities: HashSet<Capability>,
        ceiling: &CapabilityCeiling,
    ) -> Result<Self, RoleError> {
        let name = name.into();
        validate_role_name(&name)?;
        for cap in &capabilities {
            if !ceiling.contains(cap) {
                return Err(RoleError::CapabilityOutsideCeiling {
                    role: name,
                    capability: cap.clone(),
                });
            }
        }
        Ok(Self { name, capabilities })
    }

    /// Creates a role definition without ceiling validation.
    ///
    /// Used internally for built-in role constructors where the capabilities
    /// are derived from the ceiling itself.
    fn new_unchecked(name: impl Into<String>, capabilities: HashSet<Capability>) -> Self {
        Self {
            name: name.into(),
            capabilities,
        }
    }
}

// ---------------------------------------------------------------------------
// Built-in role constructors
// ---------------------------------------------------------------------------

/// Returns the `admin` built-in role definition.
///
/// The admin role grants all capabilities in the ceiling. This is the most
/// privileged role -- context creators are typically assigned admin.
///
/// See ADR-009 acceptance criterion 2.
#[must_use]
pub fn builtin_admin(ceiling: &CapabilityCeiling) -> RoleDefinition {
    RoleDefinition::new_unchecked("admin", ceiling.capabilities.clone())
}

/// Returns the `member` built-in role definition.
///
/// Members can read and write messages and invoke any registered Query or
/// Action outlet. Capabilities are intersected with the ceiling -- if a
/// capability is not in the ceiling, it is not granted.
///
/// See ADR-009 acceptance criterion 2 and §5.5.1 / §5.4.2.
#[must_use]
pub fn builtin_member(ceiling: &CapabilityCeiling) -> RoleDefinition {
    let desired = HashSet::from([
        Capability::MessagesRead,
        Capability::MessagesWrite,
        Capability::OutletQueryAll,
        Capability::OutletCallAll,
    ]);
    let capabilities = desired
        .into_iter()
        .filter(|cap| ceiling.contains(cap))
        .collect();
    RoleDefinition::new_unchecked("member", capabilities)
}

/// Returns the `moderator` built-in role definition.
///
/// Moderators can read/write messages, invoke Query and Action outlets,
/// remove members, and propose governance actions. This fills the gap
/// between `member` (no moderation power) and `admin` (full control).
/// Referenced in §5.9 as "elected moderators" governance pattern.
/// Capabilities are intersected with the ceiling.
///
/// See ADR-009 acceptance criterion 2 and §5.5.1 / §5.4.2.
#[must_use]
pub fn builtin_moderator(ceiling: &CapabilityCeiling) -> RoleDefinition {
    let desired = HashSet::from([
        Capability::MessagesRead,
        Capability::MessagesWrite,
        Capability::OutletQueryAll,
        Capability::OutletCallAll,
        Capability::MemberRemove,
        Capability::GovernancePropose,
    ]);
    let capabilities = desired
        .into_iter()
        .filter(|cap| ceiling.contains(cap))
        .collect();
    RoleDefinition::new_unchecked("moderator", capabilities)
}

/// Returns the `observer` built-in role definition.
///
/// Observers can only read messages. The capability is intersected with the
/// ceiling.
///
/// See ADR-009 acceptance criterion 2.
#[must_use]
pub fn builtin_observer(ceiling: &CapabilityCeiling) -> RoleDefinition {
    let desired = HashSet::from([Capability::MessagesRead]);
    let capabilities = desired
        .into_iter()
        .filter(|cap| ceiling.contains(cap))
        .collect();
    RoleDefinition::new_unchecked("observer", capabilities)
}

/// Returns the `author` broadcast-specific role definition.
///
/// Authors can write and read messages and invoke any registered Query or
/// Action outlet. Designed for one-to-many publishing scenarios
/// (spec section 5.14). Capabilities are intersected with the ceiling.
///
/// See ADR-009 acceptance criterion 2 and §5.5.1 / §5.4.2.
#[must_use]
pub fn builtin_author(ceiling: &CapabilityCeiling) -> RoleDefinition {
    let desired = HashSet::from([
        Capability::MessagesWrite,
        Capability::MessagesRead,
        Capability::OutletQueryAll,
        Capability::OutletCallAll,
    ]);
    let capabilities = desired
        .into_iter()
        .filter(|cap| ceiling.contains(cap))
        .collect();
    RoleDefinition::new_unchecked("author", capabilities)
}

/// Returns the `subscriber` broadcast-specific role definition.
///
/// Subscribers can only read messages. Designed for broadcast contexts
/// (spec section 5.14). The capability is intersected with the ceiling.
///
/// See ADR-009 acceptance criterion 2.
#[must_use]
pub fn builtin_subscriber(ceiling: &CapabilityCeiling) -> RoleDefinition {
    let desired = HashSet::from([Capability::MessagesRead]);
    let capabilities = desired
        .into_iter()
        .filter(|cap| ceiling.contains(cap))
        .collect();
    RoleDefinition::new_unchecked("subscriber", capabilities)
}

/// Returns all standard built-in role definitions for a given ceiling.
///
/// Includes `admin`, `moderator`, `member`, and `observer`.
#[must_use]
pub fn builtin_roles(ceiling: &CapabilityCeiling) -> Vec<RoleDefinition> {
    vec![
        builtin_admin(ceiling),
        builtin_moderator(ceiling),
        builtin_member(ceiling),
        builtin_observer(ceiling),
    ]
}

/// Returns all broadcast-specific built-in role definitions for a given ceiling.
///
/// Includes `author` and `subscriber`.
#[must_use]
pub fn builtin_broadcast_roles(ceiling: &CapabilityCeiling) -> Vec<RoleDefinition> {
    vec![builtin_author(ceiling), builtin_subscriber(ceiling)]
}

// ---------------------------------------------------------------------------
// UcanToken
// ---------------------------------------------------------------------------

/// Lightweight role-capability token used to populate the local
/// `member_capabilities` cache (spec §7.2.2 Tier 2).
///
/// This is a deliberately distinct type from the JWT-encoded
/// [`crate::crypto::ucan::UcanToken`] (`header`/`payload`/`signature`/
/// `encoded`) that the Tier-1 11-step pipeline consumes. It carries the core
/// UCAN claim fields — `iss` (context creator), `aud` (member), `att`
/// (capability attestations), `nnc` (nonce) — and **intentionally carries no
/// signature.**
///
/// The missing signature is a complete design decision, **not a stub or a
/// deferral.** These tokens are never serialized as bearer credentials (the
/// MLS leaf credential's `ucan_token` is `None` in all production paths),
/// never cross a trust boundary, and are structurally incapable of entering
/// the Tier-1 pipeline — there is no conversion from this type into the JWT
/// `crypto::ucan::UcanToken`, so a role token can never anchor a delegation
/// chain or be presented at a token-presentation boundary. Their authority is
/// grounded in the *signed governance action* that performs the role
/// assignment (context creation for the creator's admin role; the signed
/// `AddMember`/`AssignRole` governance action thereafter) and in the signed
/// context snapshot (ADR-050) when role state is synced. Each member derives
/// its own cache locally from those signed events, so a capability cannot be
/// forged by presenting a token; a per-token signature would be redundant.
///
/// Do NOT "complete" this by adding an Ed25519 signature: it would duplicate
/// the governance signature that already authorizes the assignment and serve
/// no validation path. See spec §7.2.1–§7.2.2 and ADR-009 acceptance
/// criterion 3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UcanToken {
    /// Issuer DID -- the context creator who delegates the capability.
    pub iss: String,
    /// Audience DID -- the member who receives the capability.
    pub aud: String,
    /// Attestations -- list of capability attestation strings.
    /// Format: `scp:ctx:{context_id}/{capability}`.
    pub att: Vec<UcanAttestation>,
    /// Unique nonce preventing token replay (spec section 9.5).
    pub nnc: String,
}

/// A single UCAN attestation entry.
///
/// Each attestation grants a specific capability within a context.
/// Format follows ADR-009: `with` = `scp:ctx:{context_id}/{capability}`,
/// `can` = `"invoke"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UcanAttestation {
    /// Resource URI: `scp:ctx:{context_id}/{capability}`.
    pub with: String,
    /// Action: always `"invoke"` in the current protocol version.
    pub can: String,
}

// ---------------------------------------------------------------------------
// RoleError
// ---------------------------------------------------------------------------

/// Errors produced by role and capability operations.
///
/// Covers role validation failures, ceiling violations, and assignment errors.
/// See ADR-009 for the error conditions.
#[derive(Debug, thiserror::Error)]
pub enum RoleError {
    /// A role definition includes a capability that is not in the context's
    /// capability ceiling.
    #[error("role \"{role}\" includes capability {capability} which is outside the ceiling")]
    CapabilityOutsideCeiling {
        /// The role that contains the offending capability.
        role: String,
        /// The capability that exceeds the ceiling.
        capability: Capability,
    },

    /// The requested role does not exist in the context's role definitions.
    #[error("role \"{0}\" not found in context")]
    RoleNotFound(String),

    /// The assigner does not have the `RoleAssign` capability.
    #[error("assigner \"{0}\" does not have RoleAssign capability")]
    AssignerNotAuthorized(String),

    /// The member is not a participant in the context.
    #[error("member \"{0}\" is not in the context")]
    MemberNotInContext(String),

    /// A custom role name is invalid (empty, too long, uses reserved name,
    /// or contains invalid characters).
    #[error("invalid role name: {0}")]
    InvalidRoleName(String),

    /// A context lifecycle error occurred during role assignment.
    #[error("context error: {0}")]
    Context(#[from] ContextError),

    /// A ceiling entry supplied at context creation is not a recognized built-in
    /// category nor a well-formed custom capability (spec §5.3.1.1). Surfaces the
    /// protocol's `InvalidCeilingCategory` error so a malformed entry can never be
    /// stored in the ceiling.
    #[error(transparent)]
    InvalidCeilingCategory(#[from] CeilingEntryError),
}

// ---------------------------------------------------------------------------
// RoleAssignment
// ---------------------------------------------------------------------------

/// Tracks a member's assigned role and corresponding UCAN tokens.
///
/// Used internally to maintain the mapping of members to roles within a
/// context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleAssignment {
    /// The member's DID string.
    pub member_did: String,
    /// The name of the assigned role.
    pub role_name: String,
    /// The UCAN tokens minted for this assignment.
    pub tokens: Vec<UcanToken>,
}

// ---------------------------------------------------------------------------
// ContextRoleState
// ---------------------------------------------------------------------------

/// Encapsulates the role-related state for a context.
///
/// This type is designed to be held alongside the context handle and provides
/// all the state needed for role assignment operations without requiring
/// access to `ContextHandle` internals. It is the primary input for
/// [`assign_role`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextRoleState {
    /// The context's unique identifier.
    pub context_id: String,
    /// The DID of the context creator (UCAN root issuer).
    pub creator_did: String,
    /// The immutable capability ceiling.
    ///
    /// PRIVATE (`pub(crate)`) — ADR-049 §9 downward-authorization Class-S field. A
    /// ceiling tightening that a coalesce-window rollback re-widens silently
    /// re-grants authority the caller observed as narrowed. Cross-crate reads go
    /// through [`Self::ceiling`]; the whole-ceiling WRITE goes through the named
    /// [`Self::set_ceiling`] mutator (reachable only behind a whole
    /// `&mut ContextRoleState`, which post-migration exists only inside a
    /// fail-closed-persisting combinator). The Class-C role views expose `ceiling`
    /// READ-ONLY.
    pub(crate) ceiling: CapabilityCeiling,
    /// All role definitions (built-in and custom).
    pub role_definitions: HashMap<String, RoleDefinition>,
    /// Current role assignments: member DID -> assignment.
    pub assignments: HashMap<String, RoleAssignment>,
    /// Set of member DIDs currently in the context.
    ///
    /// Serialized in a deterministic (content-sorted) order so the signed
    /// context-export digest is reproducible (§23.16.8, ADR-050).
    #[serde(with = "crate::serde_util::serde_sorted_set")]
    pub members: HashSet<String>,
    /// Capabilities held by each member (derived from assignments).
    ///
    /// Each inner capability set is serialized in a deterministic
    /// (content-sorted) order so the signed context-export digest is
    /// reproducible (§23.16.8, ADR-050). The outer DID-keyed map is already
    /// canonicalized by RFC 8785 JCS object-key sorting.
    #[serde(with = "crate::serde_util::serde_sorted_set_map")]
    pub member_capabilities: HashMap<String, HashSet<Capability>>,
    /// Suspended capabilities per member DID. A member whose DID appears here
    /// is denied the listed capabilities even if their role grants them.
    ///
    /// Each inner capability set is serialized in a deterministic
    /// (content-sorted) order so the signed context-export digest is
    /// reproducible (§23.16.8, ADR-050).
    ///
    /// PRIVATE (`pub(crate)`) — ADR-049 §9 downward-authorization Class-S field. A
    /// suspension GROW that a coalesce-window rollback loses silently re-grants a
    /// capability the caller observed as denied. Cross-crate reads go through
    /// [`Self::suspended_for`]. The inherent GROW mutators
    /// ([`Self::suspend_capabilities`], [`Self::suspend_all`]) are `pub`, so they are
    /// reachable through ANY whole `&mut ContextRoleState` ("path B") AND via the
    /// runtime's consequence-only role view; EITHER way the §9 obligation is on the
    /// CALLER — persist the GROW fail-closed before ack (see those methods' docs).
    /// The runtime's general-purpose FIELD-GRANULAR Class-C role view deliberately
    /// exposes only the SHRINK-only [`Self::prune_suspensions_to_role_grants`] and a
    /// read — no GROW accessor — so a GROW through THAT view is a compile error; the
    /// privatization keeps OUTSIDE-CRATE code from writing the field directly.
    #[serde(default, with = "crate::serde_util::serde_sorted_set_map")]
    pub(crate) suspended_capabilities: HashMap<String, HashSet<Capability>>,
}

impl ContextRoleState {
    /// Creates a new `ContextRoleState` with the given parameters.
    ///
    /// Built-in roles are automatically added to the role definitions.
    /// The creator is automatically assigned the `admin` role.
    ///
    /// # Errors
    ///
    /// Returns [`RoleError::CapabilityOutsideCeiling`] if any custom role
    /// definition includes capabilities outside the ceiling.
    pub fn new(
        context_id: impl Into<String>,
        creator_did: impl Into<String>,
        ceiling: CapabilityCeiling,
        custom_roles: Vec<RoleDefinition>,
        clock: &dyn Clock,
    ) -> Result<Self, RoleError> {
        let context_id = context_id.into();
        let creator_did = creator_did.into();

        // Ceiling-entry grammar enforcement (spec §5.3.1.1). Every ceiling entry
        // must be a recognized built-in category or a well-formed custom
        // capability; a malformed entry (single-token custom, stray `*`,
        // multi-colon, bad charset, control/HTML char, oversize, …) fails
        // creation with `InvalidCeilingCategory` and is never stored. This is the
        // single canonical enforcement point — every context-creation path routes
        // through `ContextRoleState::new`.
        ceiling.validate_entries()?;

        // Validate custom roles: name format + capabilities against ceiling.
        for role in &custom_roles {
            validate_role_name(&role.name)?;
            for cap in &role.capabilities {
                if !ceiling.contains(cap) {
                    return Err(RoleError::CapabilityOutsideCeiling {
                        role: role.name.clone(),
                        capability: cap.clone(),
                    });
                }
            }
        }

        // Build role definitions map with built-in roles.
        let mut role_definitions = HashMap::new();
        for role in builtin_roles(&ceiling) {
            role_definitions.insert(role.name.clone(), role);
        }
        for role in builtin_broadcast_roles(&ceiling) {
            role_definitions.insert(role.name.clone(), role);
        }
        for role in custom_roles {
            role_definitions.insert(role.name.clone(), role);
        }

        let mut members = HashSet::new();
        members.insert(creator_did.clone());

        // Auto-assign creator as admin.
        let admin_role = role_definitions
            .get("admin")
            .cloned()
            .unwrap_or_else(|| builtin_admin(&ceiling));

        let tokens = mint_role_tokens(&context_id, &creator_did, &creator_did, &admin_role, clock);

        let mut assignments = HashMap::new();
        let assignment = RoleAssignment {
            member_did: creator_did.clone(),
            role_name: "admin".to_owned(),
            tokens,
        };
        assignments.insert(creator_did.clone(), assignment);

        let mut member_capabilities = HashMap::new();
        member_capabilities.insert(creator_did.clone(), admin_role.capabilities);

        Ok(Self {
            context_id,
            creator_did,
            ceiling,
            role_definitions,
            assignments,
            members,
            member_capabilities,
            suspended_capabilities: HashMap::new(),
        })
    }

    /// Construct an EMPTY `ContextRoleState` skeleton (ADR-049 §9). `#[doc(hidden)]`
    /// — a test-fixture constructor (the only callers are the actor test-state
    /// builders), exposed `pub` rather than `#[cfg(test)]` so cross-crate test
    /// fixtures can build the skeleton now that the fields are private. Production
    /// construction goes through [`Self::new`] (which validates the ceiling / role
    /// definitions and auto-assigns the creator to `admin`); this empty shape
    /// touches no role logic and grants no authority.
    #[doc(hidden)]
    #[must_use]
    pub fn empty_for_test() -> Self {
        Self {
            context_id: String::new(),
            creator_did: String::new(),
            ceiling: CapabilityCeiling::new(std::iter::empty()),
            role_definitions: HashMap::new(),
            assignments: HashMap::new(),
            members: HashSet::new(),
            member_capabilities: HashMap::new(),
            suspended_capabilities: HashMap::new(),
        }
    }

    /// Returns `true` if the given member has the specified capability.
    ///
    /// Suspension-aware: returns `false` if the capability is in the member's
    /// suspended set, even if their role grants it.
    #[must_use]
    pub fn member_has_capability(&self, member_did: &str, capability: &Capability) -> bool {
        // Check suspension first.
        if self
            .suspended_capabilities
            .get(member_did)
            .is_some_and(|suspended| suspended.contains(capability))
        {
            return false;
        }
        self.member_capabilities
            .get(member_did)
            .is_some_and(|caps| caps.contains(capability))
    }

    /// Suspends specific capabilities for a member.
    ///
    /// The capabilities are added to the member's suspended set. While
    /// suspended, `member_has_capability` returns `false` for these
    /// capabilities even if the member's role grants them.
    ///
    /// # §9 caller obligation (ADR-049 §9 — downward-auth GROW)
    ///
    /// This is a DOWNWARD-AUTHORIZATION GROW: it narrows a member's effective
    /// authority, and a coalesce-window crash that rolled it back would silently
    /// re-grant a capability the caller observed as denied. As an inherent `pub`
    /// method it is reachable through ANY whole `&mut ContextRoleState` (this is
    /// "path B" in the runtime's `class_s` module docs). The CALLER MUST persist the
    /// resulting `suspended_capabilities` GROW **fail-closed before ack**: hold the
    /// `&mut ContextRoleState` only inside a fail-closed-persisting combinator, or
    /// use the consequence-only role view
    /// (`scp_runtime::…::ConsequenceRoleStateMut`). Do NOT call this on a
    /// best-effort / coalesced path — the runtime's field-granular best-effort role
    /// view deliberately exposes no GROW accessor for exactly this reason.
    pub fn suspend_capabilities(
        &mut self,
        member_did: &str,
        capabilities: impl IntoIterator<Item = Capability>,
    ) {
        self.suspended_capabilities
            .entry(member_did.to_owned())
            .or_default()
            .extend(capabilities);
    }

    /// Restores previously suspended capabilities for a member.
    ///
    /// Removes the specified capabilities from the member's suspended set.
    /// If the member has no remaining suspensions, the entry is removed.
    pub fn restore_capabilities(&mut self, member_did: &str, capabilities: &[Capability]) {
        if let Some(suspended) = self.suspended_capabilities.get_mut(member_did) {
            for cap in capabilities {
                suspended.remove(cap);
            }
            if suspended.is_empty() {
                self.suspended_capabilities.remove(member_did);
            }
        }
    }

    /// Suspends ALL capabilities for a member.
    ///
    /// Copies every capability from the member's current capability set into
    /// their suspended set. Equivalent to a full application-level block.
    ///
    /// # §9 caller obligation (ADR-049 §9 — downward-auth GROW)
    ///
    /// Like [`Self::suspend_capabilities`], this is a DOWNWARD-AUTHORIZATION GROW
    /// reachable through any whole `&mut ContextRoleState` ("path B"). The CALLER
    /// MUST persist the resulting `suspended_capabilities` GROW **fail-closed before
    /// ack** (hold the `&mut` inside a fail-closed-persisting combinator, or use the
    /// consequence-only role view); do NOT call it on a best-effort / coalesced
    /// path, where a crash-window rollback would silently re-grant the blocked
    /// member's authority.
    pub fn suspend_all(&mut self, member_did: &str) {
        if let Some(caps) = self.member_capabilities.get(member_did) {
            let all_caps: HashSet<Capability> = caps.clone();
            self.suspended_capabilities
                .insert(member_did.to_owned(), all_caps);
        }
    }

    /// Prunes a member's suspended capabilities to only those that the
    /// `new_role_capabilities` set actually grants. Called by
    /// [`assign_role`] and [`system_assign_role`] after a role
    /// replacement so suspensions for capabilities the member no longer
    /// has become meaningless entries and are dropped.
    ///
    /// If all of a member's suspensions become meaningless, the entire
    /// entry is removed from the map to avoid leaving dangling empty
    /// sets.
    ///
    /// Semantics: suspensions PERSIST across role changes for
    /// capabilities the new role still grants (a banned voter who
    /// becomes an admin is still banned from voting), but are dropped
    /// for capabilities the new role no longer grants (a banned voter
    /// who becomes an observer has no vote to suspend).
    pub fn prune_suspensions_to_role_grants(
        &mut self,
        member_did: &str,
        new_role_capabilities: &HashSet<Capability>,
    ) {
        if let Some(suspended) = self.suspended_capabilities.get_mut(member_did) {
            suspended.retain(|cap| new_role_capabilities.contains(cap));
            if suspended.is_empty() {
                self.suspended_capabilities.remove(member_did);
            }
        }
    }

    /// Read-only access to the immutable capability ceiling (ADR-049 §9
    /// downward-auth Class-S — the backing field is private). Replaces direct
    /// `state.ceiling` field reads.
    #[must_use]
    pub const fn ceiling(&self) -> &CapabilityCeiling {
        &self.ceiling
    }

    /// Replace the WHOLE capability ceiling (ADR-049 §9 downward-auth Class-S
    /// mutator). NAMED and greppable: a ceiling modification is a
    /// downward-authorization transition (§5.3.2) that, in the runtime, runs only
    /// behind a whole `&mut ContextRoleState` inside a fail-closed-persisting
    /// combinator — there is no `set_ceiling` on any best-effort role view. A
    /// coalesce-window rollback of a ceiling tightening would silently re-widen the
    /// authorization envelope, which is why the WRITE is centralized here rather
    /// than via a public field.
    ///
    /// WELL-FORMEDNESS CONSTRUCTION INVARIANT (spec §5.3.1.1): every ceiling entry
    /// is validated against the canonical ceiling-entry grammar BEFORE the
    /// replacement is stored. This is the SINGLE whole-ceiling write chokepoint for
    /// the runtime, so routing the grammar check here makes "a malformed
    /// `CapabilityCeiling` can never be stored" true by construction on EVERY
    /// mutation path — not just at context creation
    /// ([`ContextRoleState::new`](Self::new)). A malformed entry (single-token
    /// custom, stray `*`, multi-colon, bad charset, control/HTML char, oversize, …)
    /// is rejected with [`CeilingEntryError::InvalidCeilingCategory`] and the prior
    /// ceiling is left UNCHANGED (fail-closed: a rejected write never widens or
    /// poisons the authorization envelope).
    ///
    /// # Errors
    ///
    /// Returns [`CeilingEntryError::InvalidCeilingCategory`] if any entry of
    /// `ceiling` is not a recognized built-in category nor a well-formed custom
    /// capability. The receiver is not mutated on error.
    pub fn set_ceiling(&mut self, ceiling: CapabilityCeiling) -> Result<(), CeilingEntryError> {
        // Validate the WHOLE replacement before storing any of it, so a partially
        // malformed ceiling cannot leave the state half-written.
        ceiling.validate_entries()?;
        self.ceiling = ceiling;
        Ok(())
    }

    /// TEST-ONLY mutable access to the ceiling (ADR-049 §9). Gated
    /// `#[cfg(any(test, feature = "testing"))]` — never compiled into a production
    /// build. Used by downstream tamper-detection tests (e.g. `scp-runtime`'s
    /// export tests, which enable `scp-protocol/testing`) that forge a ceiling
    /// mutation in a signed snapshot. Production code replaces the whole ceiling
    /// via [`Self::set_ceiling`] behind a fail-closed-persisting combinator.
    #[cfg(any(test, feature = "testing"))]
    pub const fn ceiling_mut(&mut self) -> &mut CapabilityCeiling {
        &mut self.ceiling
    }

    /// Read-only access to a member's suspended-capability set, if any (ADR-049 §9
    /// downward-auth Class-S — the backing map is private). Replaces direct
    /// `state.suspended_capabilities.get(member_did)` reads.
    #[must_use]
    pub fn suspended_for(&self, member_did: &str) -> Option<&HashSet<Capability>> {
        self.suspended_capabilities.get(member_did)
    }

    /// Mint and structurally apply a system-level role assignment over `self`
    /// (consequence-engine / membership path). Inherent-method form of the
    /// [`system_assign_role`] free function — operating on `self.*` so a
    /// field-granular role view can forward to it without a whole `&mut`
    /// `ContextRoleState`.
    ///
    /// Bypasses the `RoleAssign` capability check (the governance consequence
    /// engine must be able to demote regardless of who holds `RoleAssign`). The
    /// `member_capabilities` REPLACEMENT it performs is a downward-auth shrink on a
    /// demotion (ADR-049 §9) — the caller persists fail-closed when used on the
    /// consequence path; the SHRINK-only suspension prune it runs rolls back in
    /// lockstep with that same persist.
    ///
    /// # Errors
    ///
    /// Returns [`RoleError::MemberNotInContext`] if the member is not in the
    /// context, or [`RoleError::RoleNotFound`] if the role doesn't exist.
    pub fn system_assign_role(
        &mut self,
        member_did: &str,
        role_name: &str,
        clock: &dyn Clock,
    ) -> Result<Vec<UcanToken>, RoleError> {
        // 1. Verify member is in the context.
        if !self.members.contains(member_did) {
            return Err(RoleError::MemberNotInContext(member_did.to_owned()));
        }

        // 2. Look up the role definition.
        let role_def = self
            .role_definitions
            .get(role_name)
            .ok_or_else(|| RoleError::RoleNotFound(role_name.to_owned()))?
            .clone();

        // 2a. Mint-time ceiling enforcement (spec §7.2.1 step 8 — "the same
        // all-attestations rule applies at mint time"). EVERY capability in the
        // role definition must be within the context's immutable ceiling before
        // any token is minted, even on the system path. Mirrors the gate-local
        // re-check in `assign_role`.
        validate_role_definition(&role_def, &self.ceiling)?;

        // 3. Mint UCAN tokens for each capability in the role.
        let tokens = mint_role_tokens(
            &self.context_id,
            &self.creator_did,
            member_did,
            &role_def,
            clock,
        );

        // 4. Update state: replace any previous assignment.
        let assignment = RoleAssignment {
            member_did: member_did.to_owned(),
            role_name: role_name.to_owned(),
            tokens: tokens.clone(),
        };
        self.assignments.insert(member_did.to_owned(), assignment);
        self.member_capabilities
            .insert(member_did.to_owned(), role_def.capabilities.clone());

        // Same prune-suspensions-to-role-grants invariant as `assign_role` —
        // system-level reassignment must also clean up stale suspensions so a
        // consequence-engine-triggered demotion cannot leave dangling entries for
        // capabilities the demoted role no longer grants.
        self.prune_suspensions_to_role_grants(member_did, &role_def.capabilities);

        Ok(tokens)
    }

    /// Canonical teardown of ALL per-DID role state on member removal (spec §5.6.1
    /// clean-teardown). Drops the DID from `members`, `assignments`,
    /// `member_capabilities`, AND the downward-auth `suspended_capabilities`. Returns
    /// `true` if the DID was present in `members` (mirrors `HashSet::remove`), so a
    /// caller can fold this into a not-found guard; the other three drops are no-ops
    /// when the DID is absent.
    ///
    /// Per-DID state owned OUTSIDE this struct — the runtime
    /// `read_exclusion_list`, the access-key store, MLS sequence counters, and
    /// pseudonym routing — is NOT touched here; each caller drops those inline.
    ///
    /// # §9 caller obligation (ADR-049 §9 — downward-auth)
    ///
    /// This writes the `pub(crate)` downward-auth `suspended_capabilities` directly.
    /// A member removal is ITSELF a downward-authorization transition (the DID holds
    /// no role afterward), so dropping its suspension can never re-grant authority —
    /// a suspension only ever DENIES, and is meaningless once the DID holds no
    /// capabilities. The removal as a whole is nonetheless a state mutation a
    /// coalesce-window rollback could re-admit, so callers MUST invoke this inside
    /// their fail-closed-persisting (ADR-049 §9 `commit_class_s_keep`) combinator,
    /// exactly as they already do for the membership/`member_capabilities` strip this
    /// replaces.
    pub fn remove_member(&mut self, member_did: &str) -> bool {
        let was_member = self.members.remove(member_did);
        self.assignments.remove(member_did);
        self.member_capabilities.remove(member_did);
        self.suspended_capabilities.remove(member_did);
        was_member
    }

    /// Destructure `self` into DISJOINT field references for the cross-crate
    /// field-granular role views (ADR-049 §9). The downward-auth `ceiling` is
    /// handed out SHARED `&` (read-only); the suspended-capability map is handed
    /// out `&mut` ONLY so the holder can run the SHRINK-only prune (the GROW
    /// methods live on the consequence-only view that owns a fail-closed persist).
    /// `context_id` / `creator_did` are stable structural identity, shared `&`.
    ///
    /// This single destructure is what lets `scp-runtime` build the field-granular
    /// `RoleStateClassCMut` / consequence role view WITHOUT naming the private
    /// fields from outside this crate — the seam that admits the privatization of
    /// `ceiling` / `suspended_capabilities`.
    pub fn class_c_parts(&mut self) -> ContextRoleClassCParts<'_> {
        let Self {
            context_id,
            creator_did,
            ceiling,
            role_definitions,
            assignments,
            members,
            member_capabilities,
            suspended_capabilities,
        } = self;
        ContextRoleClassCParts {
            context_id,
            creator_did,
            ceiling,
            role_definitions,
            assignments,
            members,
            member_capabilities,
            suspended_capabilities,
        }
    }
}

/// DISJOINT field references over a [`ContextRoleState`], the cross-crate seam
/// for `scp-runtime`'s field-granular Class-C / consequence role views
/// (ADR-049 §9).
///
/// Produced by [`ContextRoleState::class_c_parts`]. The downward-authorization
/// `ceiling` is exposed SHARED `&` (read-only); the structural Class-C fields are
/// `&mut`; the per-member suspension map is `&mut` so the consumer can run the
/// SHRINK-only prune or (on the consequence-only view) a GROW. Because the
/// individual references are disjoint, the consumer can hold a read of `ceiling`
/// while writing the structural fields in one borrow.
///
/// # Seam contract — confinement is the CONSUMING VIEW's responsibility
///
/// This struct is intentionally NOT self-protecting: its fields are RAW `&mut`
/// (including the downward-auth `suspended_capabilities`, and `member_capabilities`
/// which is an authorization input). It does NOT itself enforce the §9
/// shrink/GROW-only narrowing — it is the disjoint-borrow PRIMITIVE, and the
/// confinement (no GROW accessor, SHRINK-only prune, fail-closed persist) is built
/// by the CONSUMING `scp-runtime` view that wraps it
/// (`RoleStateClassCMut` for best-effort, `ConsequenceRoleStateMut` for the
/// fail-closed consequence path). Today the SOLE consumers are those two runtime
/// views (plus this struct's own `system_assign_role` / SHRINK-only prune helpers).
/// A FUTURE second consumer MUST NOT assume the seam narrows anything for it: it has
/// to apply the same §9 discipline (expose no unpersisted downward-auth GROW; route
/// any `suspended_capabilities` / `member_capabilities` shrink through a fail-closed
/// persist). A full structural seal of this parts struct is deliberately out of
/// scope (single consumer set; sealing it would fight the disjoint-borrow ergonomics
/// it exists to provide).
///
/// ACCEPTED RESIDUAL (ADR-049 §9): both [`ContextRoleState::class_c_parts`] and
/// these `pub` raw `&mut` fields are `pub` (NOT `pub(crate)`) because `scp-runtime`
/// constructs the views CROSS-CRATE and must name them. That `pub` surface is
/// §9-safe NOT by access modifier but by REACHABILITY: producing a
/// `ContextRoleClassCParts` requires a `&mut ContextRoleState`, and in the actor
/// the only `&mut ContextRoleState` is reached through `ClassSCell` — which has NO
/// `DerefMut` and holds the role state behind PRIVATE fields, so no caller outside
/// the runtime's fail-closed view layer can obtain the `&mut` needed to call
/// `class_c_parts` in the first place. Tightening `class_c_parts` to `pub(crate)`
/// is therefore both impossible (cross-crate consumer) AND unnecessary (the cell's
/// `!DerefMut` + private fields already block the reach). The residual a maintainer
/// would have to introduce — a NEW production `&mut ContextRoleState` source outside
/// a fail-closed combinator — is an in-file-insider action, a code-review
/// responsibility.
pub struct ContextRoleClassCParts<'a> {
    /// Shared `&` to the context identifier (structural identity, stable).
    pub context_id: &'a str,
    /// Shared `&` to the creator DID (structural identity, stable).
    pub creator_did: &'a str,
    /// Shared `&` to the immutable capability ceiling — DOWNWARD-AUTH Class-S,
    /// read-only (ceiling modifications are fail-closed governance, §5.3.2).
    pub ceiling: &'a CapabilityCeiling,
    /// `&mut` to all role definitions (Class-C / structural).
    pub role_definitions: &'a mut HashMap<String, RoleDefinition>,
    /// `&mut` to the current role assignments (Class-C / structural).
    pub assignments: &'a mut HashMap<String, RoleAssignment>,
    /// `&mut` to the member DID set (Class-C / structural).
    pub members: &'a mut HashSet<String>,
    /// `&mut` to the per-member GRANTED capability sets. An authorization input
    /// (`member_has_capability` reads it), so a downward SHRINK is itself a §9
    /// hazard — the consuming view restricts how this is written (the runtime's
    /// best-effort role view exposes it READ-ONLY + a `system_assign_role` replace;
    /// a DEMOTION goes through the fail-closed consequence view).
    pub member_capabilities: &'a mut HashMap<String, HashSet<Capability>>,
    /// `&mut` to the per-member suspension map. DOWNWARD-AUTH Class-S. This RAW
    /// `&mut` does not itself confine anything: the consuming runtime view decides
    /// the surface — the general-purpose `RoleStateClassCMut` exposes only the
    /// SHRINK-only prune + a read (no GROW accessor), while the consequence-only
    /// `ConsequenceRoleStateMut` exposes the GROW (persisted fail-closed by its
    /// caller). The inherent `pub` `ContextRoleState::suspend_*` GROW is also
    /// reachable through a whole `&mut` ("path B"), persisted fail-closed by its
    /// combinator. Confinement is the consuming view's responsibility (see the type
    /// doc's seam contract).
    pub suspended_capabilities: &'a mut HashMap<String, HashSet<Capability>>,
}

impl ContextRoleClassCParts<'_> {
    /// SHRINK-only prune of a member's suspensions to the capabilities the
    /// `new_role_capabilities` set still grants (ADR-049 §9). Operates over the
    /// disjoint `suspended_capabilities` ref; can only REMOVE entries.
    pub fn prune_suspensions_to_role_grants(
        &mut self,
        member_did: &str,
        new_role_capabilities: &HashSet<Capability>,
    ) {
        if let Some(suspended) = self.suspended_capabilities.get_mut(member_did) {
            suspended.retain(|cap| new_role_capabilities.contains(cap));
            if suspended.is_empty() {
                self.suspended_capabilities.remove(member_did);
            }
        }
    }

    /// Mint + structurally apply a system-level role assignment over the disjoint
    /// field references (ADR-049 §9). The token-minting logic stays inside
    /// `scp-protocol` (it needs the private `mint_role_tokens`); the runtime
    /// field-granular role views delegate here so they need no whole
    /// `&mut ContextRoleState`. Reads `context_id` / `creator_did` /
    /// `role_definitions` shared; writes `assignments` / `member_capabilities`;
    /// runs the SHRINK-only suspension prune.
    ///
    /// # Errors
    ///
    /// [`RoleError::MemberNotInContext`] if the member is absent;
    /// [`RoleError::RoleNotFound`] if the role is undefined.
    pub fn system_assign_role(
        &mut self,
        member_did: &str,
        role_name: &str,
        clock: &dyn Clock,
    ) -> Result<Vec<UcanToken>, RoleError> {
        if !self.members.contains(member_did) {
            return Err(RoleError::MemberNotInContext(member_did.to_owned()));
        }
        let role_def = self
            .role_definitions
            .get(role_name)
            .ok_or_else(|| RoleError::RoleNotFound(role_name.to_owned()))?
            .clone();
        // Mint-time ceiling enforcement (spec §7.2.1 step 8): every capability in
        // the role definition must be within the immutable ceiling before any
        // token is minted, even on this field-granular system path.
        validate_role_definition(&role_def, self.ceiling)?;
        let tokens = mint_role_tokens(
            self.context_id,
            self.creator_did,
            member_did,
            &role_def,
            clock,
        );
        self.assignments.insert(
            member_did.to_owned(),
            RoleAssignment {
                member_did: member_did.to_owned(),
                role_name: role_name.to_owned(),
                tokens: tokens.clone(),
            },
        );
        self.member_capabilities
            .insert(member_did.to_owned(), role_def.capabilities.clone());
        self.prune_suspensions_to_role_grants(member_did, &role_def.capabilities);
        Ok(tokens)
    }
}

// ---------------------------------------------------------------------------
// assign_role
// ---------------------------------------------------------------------------

/// Assigns a role to a member within a context.
///
/// This is a free function that takes all needed state as parameters, per
/// the design instruction. It validates that:
/// 1. The assigner has the `RoleAssign` capability.
/// 2. The member is in the context's member set.
/// 3. The role exists in the context's role definitions.
///
/// On success, it updates the context role state in place and returns the
/// minted UCAN tokens. Integration points (MLS distribution, event log
/// append) are handled by the caller.
///
/// See ADR-009 acceptance criterion 3.
///
/// # Errors
///
/// - [`RoleError::AssignerNotAuthorized`] if the assigner lacks `RoleAssign`.
/// - [`RoleError::MemberNotInContext`] if the member is not in the context.
/// - [`RoleError::RoleNotFound`] if the role name is not defined.
pub fn assign_role(
    state: &mut ContextRoleState,
    member_did: &str,
    role_name: &str,
    assigner_did: &str,
    clock: &dyn Clock,
) -> Result<Vec<UcanToken>, RoleError> {
    // 1. Verify assigner has RoleAssign capability.
    if !state.member_has_capability(assigner_did, &Capability::RoleAssign) {
        return Err(RoleError::AssignerNotAuthorized(assigner_did.to_owned()));
    }

    // 2. Verify member is in the context.
    if !state.members.contains(member_did) {
        return Err(RoleError::MemberNotInContext(member_did.to_owned()));
    }

    // 3. Look up the role definition.
    let role_def = state
        .role_definitions
        .get(role_name)
        .ok_or_else(|| RoleError::RoleNotFound(role_name.to_owned()))?
        .clone();

    // 3a. Mint-time ceiling enforcement (spec §7.2.1 step 8 — "the same
    // all-attestations rule applies at mint time"). EVERY capability in the
    // role definition must be within the context's immutable ceiling before any
    // token is minted. Role definitions are ceiling-validated when they are
    // built (RoleDefinition::new / ContextRoleState::new /
    // validate_role_definition); this is the gate-local layer at mint time —
    // the producer-side counterpart to UCAN validation step 8 on the consumer
    // side — closing any path by which a role definition carrying an
    // out-of-ceiling capability (e.g. one built via new_unchecked) could reach
    // mint and emit out-of-ceiling attestations.
    validate_role_definition(&role_def, &state.ceiling)?;

    // 4. Mint UCAN tokens for each capability in the role.
    let tokens = mint_role_tokens(
        &state.context_id,
        &state.creator_did,
        member_did,
        &role_def,
        clock,
    );

    // 5. Update state: replace any previous assignment.
    let assignment = RoleAssignment {
        member_did: member_did.to_owned(),
        role_name: role_name.to_owned(),
        tokens: tokens.clone(),
    };
    state.assignments.insert(member_did.to_owned(), assignment);
    state
        .member_capabilities
        .insert(member_did.to_owned(), role_def.capabilities.clone());

    // Prune suspensions outside the new role's grant set. Otherwise
    // `suspended_capabilities` would retain entries for capabilities
    // the member no longer holds, which could accidentally re-engage
    // if the member cycles back to a granting role later.
    state.prune_suspensions_to_role_grants(member_did, &role_def.capabilities);

    Ok(tokens)
}

/// System-level role assignment that bypasses the `RoleAssign` capability check.
///
/// Used by the governance consequence engine when demoting a member. The system
/// must be able to enforce role demotions regardless of which member (if any)
/// currently holds `RoleAssign`. All other checks (member existence, role
/// existence) still apply.
///
/// # Errors
///
/// Returns [`RoleError::MemberNotInContext`] if the member is not in the
/// context, or [`RoleError::RoleNotFound`] if the role doesn't exist.
// SAFETY: Called only by governance consequence engine. Do not use for direct role assignment.
// This must remain `pub` (not `pub(crate)`) because scp-runtime calls it
// from enforce_assign_role(). Hidden from public API docs.
#[doc(hidden)]
pub fn system_assign_role(
    state: &mut ContextRoleState,
    member_did: &str,
    role_name: &str,
    clock: &dyn Clock,
) -> Result<Vec<UcanToken>, RoleError> {
    // Thin forwarder to the inherent method (ADR-049 §9): the body lives on
    // `ContextRoleState::system_assign_role` so a field-granular role view can
    // mint a role over its own disjoint fields without a whole `&mut`. Retained
    // `pub` (not removed) because `scp-runtime` and tests still call the free form.
    // Mint-time ceiling enforcement (spec §7.2.1 step 8) now lives inside that
    // inherent method, so the forwarder inherits it.
    state.system_assign_role(member_did, role_name, clock)
}

// ---------------------------------------------------------------------------
// Role name validation (M3)
// ---------------------------------------------------------------------------

/// Maximum length of a custom role name in bytes.
///
/// Role names are stored in `ContextSnapshot` and serialized into event log
/// entries. 64 bytes is generous for any practical role name while preventing
/// unbounded growth.
pub const MAX_ROLE_NAME_LENGTH: usize = 64;

/// Built-in role names that custom roles MUST NOT shadow.
///
/// These are the protocol-defined role names from §5.5 and §5.14. Custom
/// roles using these names would collide with built-in role constructors,
/// causing ambiguous role resolution.
const RESERVED_ROLE_NAMES: &[&str] = &[
    "admin",
    "moderator",
    "member",
    "observer",
    "author",
    "subscriber",
];

/// Validates a custom role name.
///
/// Role names MUST:
/// - Be non-empty.
/// - Not exceed [`MAX_ROLE_NAME_LENGTH`] bytes.
/// - Not collide with reserved built-in role names.
/// - Contain only lowercase ASCII letters, digits, hyphens, and underscores
///   (`[a-z0-9_-]`), and not start or end with a hyphen or underscore.
///
/// # Errors
///
/// Returns [`RoleError::InvalidRoleName`] on validation failure.
pub fn validate_role_name(name: &str) -> Result<(), RoleError> {
    if name.is_empty() {
        return Err(RoleError::InvalidRoleName(
            "role name must not be empty".into(),
        ));
    }

    if name.len() > MAX_ROLE_NAME_LENGTH {
        return Err(RoleError::InvalidRoleName(format!(
            "role name exceeds maximum length of {MAX_ROLE_NAME_LENGTH} bytes (got {} bytes)",
            name.len()
        )));
    }

    if RESERVED_ROLE_NAMES.contains(&name) {
        return Err(RoleError::InvalidRoleName(format!(
            "'{name}' is a reserved built-in role name"
        )));
    }

    // Format: lowercase ASCII letters, digits, hyphens, underscores.
    // Must not start or end with hyphen/underscore.
    let first = name.as_bytes()[0];
    if first == b'-' || first == b'_' {
        return Err(RoleError::InvalidRoleName(format!(
            "'{name}' must not start with a hyphen or underscore"
        )));
    }

    let last = name.as_bytes()[name.len() - 1];
    if last == b'-' || last == b'_' {
        return Err(RoleError::InvalidRoleName(format!(
            "'{name}' must not end with a hyphen or underscore"
        )));
    }

    for ch in name.chars() {
        if !matches!(ch, 'a'..='z' | '0'..='9' | '-' | '_') {
            return Err(RoleError::InvalidRoleName(format!(
                "'{name}' contains invalid character '{ch}' (only lowercase ASCII letters, digits, hyphens, and underscores allowed)"
            )));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// validate_role_definition
// ---------------------------------------------------------------------------

/// Validates that a role definition's capabilities are all within the ceiling.
///
/// This is called at context creation time and when custom roles are added.
///
/// # Errors
///
/// Returns [`RoleError::CapabilityOutsideCeiling`] if any capability in
/// the role is not within the ceiling.
pub fn validate_role_definition(
    role: &RoleDefinition,
    ceiling: &CapabilityCeiling,
) -> Result<(), RoleError> {
    for cap in &role.capabilities {
        if !ceiling.contains(cap) {
            return Err(RoleError::CapabilityOutsideCeiling {
                role: role.name.clone(),
                capability: cap.clone(),
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Mints UCAN tokens for all capabilities in a role.
///
/// Creates one [`UcanToken`] per capability in the role definition, following
/// the ADR-009 token format: `iss` = creator DID, `aud` = member DID,
/// `att` = capability attestation, `nnc` = unique nonce.
///
/// These role tokens intentionally carry no per-token signature — this is a
/// complete design decision, not a stub. See the [`UcanToken`] type docs for
/// the full rationale (authority is grounded in the signed governance action,
/// the tokens never cross a trust boundary, and they cannot enter the Tier-1
/// JWT validation pipeline). Callers MUST NOT add an Ed25519 signature here.
///
/// Every capability in `role` is guaranteed to be within the context ceiling at
/// every call site: the assignment paths ([`assign_role`],
/// [`system_assign_role`]) run [`validate_role_definition`] against the ceiling
/// immediately before minting, and the construction path
/// ([`ContextRoleState::new`]) mints only the `admin` role, whose definition is
/// already within the ceiling — a custom `admin` override is ceiling-validated
/// at construction, and the built-in fallback ([`builtin_admin`]) derives its
/// capabilities directly from the ceiling.
fn mint_role_tokens(
    context_id: &str,
    creator_did: &str,
    member_did: &str,
    role: &RoleDefinition,
    clock: &dyn Clock,
) -> Vec<UcanToken> {
    role.capabilities
        .iter()
        .map(|cap| {
            let (resource, action) = cap.ucan_resource_action();
            let att = UcanAttestation {
                with: format!("scp:ctx:{context_id}/{resource}:{action}"),
                can: action.into_owned(),
            };
            UcanToken {
                iss: creator_did.to_owned(),
                aud: member_did.to_owned(),
                att: vec![att],
                nnc: generate_nonce(clock),
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Creates a standard ceiling with common capabilities for testing.
    fn test_ceiling() -> CapabilityCeiling {
        CapabilityCeiling::new([
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::OutletCallAll,
            Capability::OutletRegister,
            Capability::MemberInvite,
            Capability::MemberRemove,
            Capability::RoleAssign,
            Capability::GovernancePropose,
            Capability::GovernanceVote,
            Capability::ContextClose,
            Capability::ChildContextCreate,
        ])
    }

    /// Creates a minimal ceiling with only messaging capabilities.
    fn minimal_ceiling() -> CapabilityCeiling {
        CapabilityCeiling::new([Capability::MessagesRead, Capability::MessagesWrite])
    }

    // -----------------------------------------------------------------------
    // Capability enum
    // -----------------------------------------------------------------------

    #[test]
    fn capability_variants_are_distinct() {
        let caps = vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::OutletCall("tool-1".to_owned()),
            Capability::OutletCallAll,
            Capability::OutletRegister,
            Capability::MemberInvite,
            Capability::MemberRemove,
            Capability::RoleAssign,
            Capability::GovernancePropose,
            Capability::GovernanceVote,
            Capability::ContextClose,
            Capability::ChildContextCreate,
            Capability::Custom("custom-1".to_owned()),
        ];
        for (i, a) in caps.iter().enumerate() {
            for (j, b) in caps.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b, "variants at index {i} and {j} should differ");
                }
            }
        }
    }

    #[test]
    fn capability_clone_preserves_equality() {
        let cap = Capability::OutletCall("my-tool".to_owned());
        let cloned = cap.clone();
        assert_eq!(cap, cloned);
    }

    #[test]
    fn capability_hash_consistent_with_equality() {
        use std::hash::{Hash, Hasher};
        let cap1 = Capability::Custom("test".to_owned());
        let cap2 = Capability::Custom("test".to_owned());
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        cap1.hash(&mut h1);
        cap2.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn capability_display_formats() {
        assert_eq!(format!("{}", Capability::MessagesRead), "messages:read");
        assert_eq!(format!("{}", Capability::MessagesWrite), "messages:write");
        assert_eq!(
            format!("{}", Capability::OutletCall("foo".to_owned())),
            "outlet:call:foo"
        );
        assert_eq!(format!("{}", Capability::OutletCallAll), "outlet:call:*");
        assert_eq!(
            format!("{}", Capability::OutletQuery("foo".to_owned())),
            "outlet:query:foo"
        );
        assert_eq!(format!("{}", Capability::OutletQueryAll), "outlet:query:*");
        assert_eq!(format!("{}", Capability::OutletRegister), "outlet:register");
        assert_eq!(format!("{}", Capability::MemberInvite), "member:invite");
        assert_eq!(format!("{}", Capability::MemberRemove), "member:remove");
        assert_eq!(format!("{}", Capability::RoleAssign), "role:assign");
        assert_eq!(
            format!("{}", Capability::GovernancePropose),
            "governance:propose"
        );
        assert_eq!(format!("{}", Capability::GovernanceVote), "governance:vote");
        assert_eq!(format!("{}", Capability::ContextClose), "context:close");
        assert_eq!(
            format!("{}", Capability::ChildContextCreate),
            "context:child:create"
        );
        assert_eq!(
            format!("{}", Capability::Custom("x".to_owned())),
            "custom:x"
        );
    }

    #[test]
    fn capability_display_new_roundtrip() {
        // All standard variants must roundtrip through Display → new.
        let standard_caps = vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::OutletCall("my-tool".to_owned()),
            Capability::OutletCallAll,
            Capability::OutletRegister,
            Capability::MemberInvite,
            Capability::MemberRemove,
            Capability::RoleAssign,
            Capability::GovernancePropose,
            Capability::GovernanceVote,
            Capability::ContextClose,
            Capability::ChildContextCreate,
            Capability::OutletInterface,
            Capability::Bridging,
            Capability::MediaVoice,
            Capability::MediaVideo,
            Capability::MediaScreenShare,
            Capability::MemberBan,
            Capability::MetadataEdit,
        ];
        for cap in &standard_caps {
            let displayed = cap.to_string();
            let roundtripped = Capability::new(&displayed);
            assert_eq!(
                Some(cap.clone()),
                roundtripped,
                "Display→new roundtrip failed for {cap:?} (displayed as {displayed:?})"
            );
        }

        // Custom variants must also roundtrip through Display → new.
        // This was a bug: Display output "custom:my-cap" but new() didn't
        // strip the "custom:" prefix, creating Custom("custom:my-cap").
        //
        // Note: Custom names starting with "custom:" are ambiguous through
        // new() — the prefix is always stripped. Avoid such names.
        let custom_caps = vec![
            Capability::Custom("my-cap".to_owned()),
            Capability::Custom("x".to_owned()),
            Capability::Custom("some:nested:name".to_owned()),
            Capability::Custom(String::new()),
        ];
        for cap in &custom_caps {
            let displayed = cap.to_string();
            let roundtripped = Capability::new(&displayed);
            assert_eq!(
                Some(cap.clone()),
                roundtripped,
                "Display→new roundtrip failed for {cap:?} (displayed as {displayed:?})"
            );
        }

        // name() → new() roundtrip: name() returns the raw name (no prefix
        // for Custom), and new() falls through to Custom(...) for unrecognized
        // names, so the roundtrip holds.
        for cap in standard_caps.iter().chain(&custom_caps) {
            let via_name = Capability::new(cap.name());
            assert_eq!(
                Some(cap.clone()),
                via_name,
                "name()→new() roundtrip failed for {cap:?} (name = {:?})",
                cap.name()
            );
        }
    }

    #[test]
    fn capability_serialization_roundtrip() {
        let caps = vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::OutletCall("search".to_owned()),
            Capability::OutletCallAll,
            Capability::MemberBan,
            Capability::Custom("my-cap".to_owned()),
        ];
        for cap in &caps {
            let json = serde_json::to_string(cap).unwrap();
            let deserialized: Capability = serde_json::from_str(&json).unwrap();
            assert_eq!(cap, &deserialized, "roundtrip failed for {cap:?}");
        }
    }

    #[test]
    fn member_ban_capability_new_and_name() {
        let cap = Capability::new("member:ban").expect("known capability");
        assert_eq!(cap, Capability::MemberBan);
        assert_eq!(cap.name(), "member:ban");
        assert_eq!(format!("{cap}"), "member:ban");
    }

    // -----------------------------------------------------------------------
    // CapabilityCeiling
    // -----------------------------------------------------------------------

    #[test]
    fn ceiling_new_creates_from_iterator() {
        let ceiling = CapabilityCeiling::new([Capability::MessagesRead, Capability::MessagesWrite]);
        assert_eq!(ceiling.len(), 2);
        assert!(!ceiling.is_empty());
    }

    #[test]
    fn ceiling_empty() {
        let ceiling = CapabilityCeiling::new(std::iter::empty());
        assert!(ceiling.is_empty());
        assert_eq!(ceiling.len(), 0);
    }

    #[test]
    fn ceiling_contains_direct_capability() {
        let ceiling = test_ceiling();
        assert!(ceiling.contains(&Capability::MessagesRead));
        assert!(ceiling.contains(&Capability::RoleAssign));
    }

    #[test]
    fn ceiling_does_not_contain_absent_capability() {
        let ceiling = minimal_ceiling();
        assert!(!ceiling.contains(&Capability::RoleAssign));
        assert!(!ceiling.contains(&Capability::MemberInvite));
    }

    #[test]
    fn ceiling_outlet_call_all_implies_specific_call() {
        let ceiling = CapabilityCeiling::new([Capability::OutletCallAll, Capability::MessagesRead]);
        assert!(ceiling.contains(&Capability::OutletCall("any-tool".to_owned())));
        assert!(ceiling.contains(&Capability::OutletCall("another-tool".to_owned())));
    }

    #[test]
    fn ceiling_specific_call_does_not_imply_all() {
        let ceiling = CapabilityCeiling::new([
            Capability::OutletCall("specific-tool".to_owned()),
            Capability::MessagesRead,
        ]);
        assert!(ceiling.contains(&Capability::OutletCall("specific-tool".to_owned())));
        assert!(!ceiling.contains(&Capability::OutletCall("other-tool".to_owned())));
        assert!(!ceiling.contains(&Capability::OutletCallAll));
    }

    #[test]
    fn ceiling_contains_all_succeeds_for_subset() {
        let ceiling = test_ceiling();
        let subset = HashSet::from([Capability::MessagesRead, Capability::MessagesWrite]);
        assert!(ceiling.contains_all(&subset));
    }

    #[test]
    fn ceiling_contains_all_fails_for_superset() {
        let ceiling = minimal_ceiling();
        let superset = HashSet::from([
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::RoleAssign,
        ]);
        assert!(!ceiling.contains_all(&superset));
    }

    #[test]
    fn ceiling_dedup_duplicates() {
        let ceiling = CapabilityCeiling::new([
            Capability::MessagesRead,
            Capability::MessagesRead,
            Capability::MessagesWrite,
        ]);
        assert_eq!(ceiling.len(), 2);
    }

    // -----------------------------------------------------------------------
    // check_ceiling (free function)
    // -----------------------------------------------------------------------

    #[test]
    fn check_ceiling_returns_true_for_present_capability() {
        let ceiling = test_ceiling();
        assert!(check_ceiling(&ceiling, &Capability::MessagesRead));
    }

    #[test]
    fn check_ceiling_returns_false_for_absent_capability() {
        let ceiling = minimal_ceiling();
        assert!(!check_ceiling(&ceiling, &Capability::ContextClose));
    }

    #[test]
    fn check_ceiling_outlet_call_all_covers_specific() {
        let ceiling = CapabilityCeiling::new([Capability::OutletCallAll]);
        assert!(check_ceiling(
            &ceiling,
            &Capability::OutletCall("test-tool".to_owned())
        ));
    }

    // -----------------------------------------------------------------------
    // RoleDefinition
    // -----------------------------------------------------------------------

    #[test]
    fn role_definition_new_validates_against_ceiling() {
        let ceiling = minimal_ceiling();
        let caps = HashSet::from([Capability::MessagesRead]);
        let result = RoleDefinition::new("reader", caps, &ceiling);
        assert!(result.is_ok());
        let role = result.unwrap();
        assert_eq!(role.name, "reader");
    }

    #[test]
    fn role_definition_new_rejects_capability_outside_ceiling() {
        let ceiling = minimal_ceiling();
        let caps = HashSet::from([Capability::MessagesRead, Capability::RoleAssign]);
        let result = RoleDefinition::new("bad-role", caps, &ceiling);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, RoleError::CapabilityOutsideCeiling { ref role, .. } if role == "bad-role")
        );
    }

    #[test]
    fn role_definition_serialization_roundtrip() {
        let ceiling = test_ceiling();
        let caps = HashSet::from([Capability::MessagesRead, Capability::MessagesWrite]);
        let role = RoleDefinition::new("custom", caps, &ceiling).unwrap();
        let json = serde_json::to_string(&role).unwrap();
        let deserialized: RoleDefinition = serde_json::from_str(&json).unwrap();
        assert_eq!(role, deserialized);
    }

    // -----------------------------------------------------------------------
    // Built-in roles
    // -----------------------------------------------------------------------

    #[test]
    fn builtin_admin_has_all_ceiling_capabilities() {
        let ceiling = test_ceiling();
        let admin = builtin_admin(&ceiling);
        assert_eq!(admin.name, "admin");
        assert_eq!(admin.capabilities, ceiling.capabilities);
    }

    #[test]
    fn builtin_member_has_expected_capabilities() {
        let ceiling = test_ceiling();
        let member = builtin_member(&ceiling);
        assert_eq!(member.name, "member");
        assert!(member.capabilities.contains(&Capability::MessagesRead));
        assert!(member.capabilities.contains(&Capability::MessagesWrite));
        assert!(member.capabilities.contains(&Capability::OutletCallAll));
        assert_eq!(member.capabilities.len(), 3);
    }

    #[test]
    fn builtin_observer_has_messages_read_only() {
        let ceiling = test_ceiling();
        let observer = builtin_observer(&ceiling);
        assert_eq!(observer.name, "observer");
        assert!(observer.capabilities.contains(&Capability::MessagesRead));
        assert_eq!(observer.capabilities.len(), 1);
    }

    #[test]
    fn builtin_moderator_has_expected_capabilities() {
        let ceiling = test_ceiling();
        let moderator = builtin_moderator(&ceiling);
        assert_eq!(moderator.name, "moderator");
        assert!(moderator.capabilities.contains(&Capability::MessagesRead));
        assert!(moderator.capabilities.contains(&Capability::MessagesWrite));
        assert!(moderator.capabilities.contains(&Capability::OutletCallAll));
        assert!(moderator.capabilities.contains(&Capability::MemberRemove));
        assert!(
            moderator
                .capabilities
                .contains(&Capability::GovernancePropose)
        );
        assert_eq!(moderator.capabilities.len(), 5);
    }

    #[test]
    fn builtin_moderator_respects_ceiling() {
        // If GovernancePropose is not in the ceiling, moderator should not have it.
        let ceiling = CapabilityCeiling::new([
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::OutletCallAll,
            Capability::MemberRemove,
        ]);
        let moderator = builtin_moderator(&ceiling);
        assert!(
            !moderator
                .capabilities
                .contains(&Capability::GovernancePropose)
        );
        assert_eq!(moderator.capabilities.len(), 4);
    }

    #[test]
    fn builtin_author_has_expected_capabilities() {
        let ceiling = test_ceiling();
        let author = builtin_author(&ceiling);
        assert_eq!(author.name, "author");
        assert!(author.capabilities.contains(&Capability::MessagesWrite));
        assert!(author.capabilities.contains(&Capability::MessagesRead));
        assert!(author.capabilities.contains(&Capability::OutletCallAll));
        assert_eq!(author.capabilities.len(), 3);
    }

    #[test]
    fn builtin_subscriber_has_messages_read_only() {
        let ceiling = test_ceiling();
        let subscriber = builtin_subscriber(&ceiling);
        assert_eq!(subscriber.name, "subscriber");
        assert!(subscriber.capabilities.contains(&Capability::MessagesRead));
        assert_eq!(subscriber.capabilities.len(), 1);
    }

    #[test]
    fn builtin_member_respects_ceiling() {
        // If OutletCallAll / OutletQueryAll are not in the ceiling, member should not have them.
        let ceiling = CapabilityCeiling::new([Capability::MessagesRead, Capability::MessagesWrite]);
        let member = builtin_member(&ceiling);
        assert!(!member.capabilities.contains(&Capability::OutletCallAll));
        assert_eq!(member.capabilities.len(), 2);
    }

    #[test]
    fn builtin_roles_returns_four_roles() {
        let ceiling = test_ceiling();
        let roles = builtin_roles(&ceiling);
        assert_eq!(roles.len(), 4);
        let names: Vec<&str> = roles.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"admin"));
        assert!(names.contains(&"moderator"));
        assert!(names.contains(&"member"));
        assert!(names.contains(&"observer"));
    }

    #[test]
    fn builtin_broadcast_roles_returns_two_roles() {
        let ceiling = test_ceiling();
        let roles = builtin_broadcast_roles(&ceiling);
        assert_eq!(roles.len(), 2);
        let names: Vec<&str> = roles.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"author"));
        assert!(names.contains(&"subscriber"));
    }

    // -----------------------------------------------------------------------
    // UcanToken
    // -----------------------------------------------------------------------

    #[test]
    fn ucan_token_serialization_roundtrip() {
        let token = UcanToken {
            iss: "did:dht:creator".to_owned(),
            aud: "did:dht:member".to_owned(),
            att: vec![UcanAttestation {
                with: "scp:ctx:ctx-1/messages:read".to_owned(),
                can: "invoke".to_owned(),
            }],
            nnc: "1708646400000-aabbccdd".to_owned(),
        };
        let json = serde_json::to_string(&token).unwrap();
        let deserialized: UcanToken = serde_json::from_str(&json).unwrap();
        assert_eq!(token, deserialized);
    }

    // -----------------------------------------------------------------------
    // ContextRoleState
    // -----------------------------------------------------------------------

    #[test]
    fn context_role_state_new_creates_with_builtins() {
        let ceiling = test_ceiling();
        let state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_clock::SystemClock,
        )
        .unwrap();

        // Creator is a member.
        assert!(state.members.contains("did:dht:creator"));

        // Creator is assigned admin role.
        let assignment = state.assignments.get("did:dht:creator").unwrap();
        assert_eq!(assignment.role_name, "admin");

        // Built-in roles are available.
        assert!(state.role_definitions.contains_key("admin"));
        assert!(state.role_definitions.contains_key("member"));
        assert!(state.role_definitions.contains_key("observer"));
        assert!(state.role_definitions.contains_key("author"));
        assert!(state.role_definitions.contains_key("subscriber"));
    }

    #[test]
    fn context_role_state_new_with_custom_role() {
        let ceiling = test_ceiling();
        let custom = RoleDefinition::new(
            "content-mod",
            HashSet::from([
                Capability::MessagesRead,
                Capability::MessagesWrite,
                Capability::MemberRemove,
            ]),
            &ceiling,
        )
        .unwrap();

        let state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![custom],
            &scp_clock::SystemClock,
        )
        .unwrap();
        assert!(state.role_definitions.contains_key("content-mod"));
        let mod_role = state.role_definitions.get("content-mod").unwrap();
        assert_eq!(mod_role.capabilities.len(), 3);
    }

    #[test]
    fn context_role_state_new_rejects_invalid_custom_role() {
        let ceiling = minimal_ceiling();
        let bad_custom = RoleDefinition::new_unchecked(
            "overpowered",
            HashSet::from([Capability::MessagesRead, Capability::RoleAssign]),
        );

        let result = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![bad_custom],
            &scp_clock::SystemClock,
        );
        assert!(result.is_err());
    }

    #[test]
    fn context_role_state_creator_has_all_ceiling_capabilities() {
        let ceiling = test_ceiling();
        let state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling.clone(),
            vec![],
            &scp_clock::SystemClock,
        )
        .unwrap();

        for cap in &ceiling.capabilities {
            assert!(
                state.member_has_capability("did:dht:creator", cap),
                "creator should have capability {cap:?}"
            );
        }
    }

    #[test]
    fn context_role_state_non_member_has_no_capabilities() {
        let ceiling = test_ceiling();
        let state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_clock::SystemClock,
        )
        .unwrap();

        assert!(!state.member_has_capability("did:dht:nobody", &Capability::MessagesRead));
    }

    // -----------------------------------------------------------------------
    // assign_role
    // -----------------------------------------------------------------------

    #[test]
    fn assign_role_succeeds_for_authorized_assigner() {
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_clock::SystemClock,
        )
        .unwrap();

        // Add a member to the context.
        state.members.insert("did:dht:alice".to_owned());

        let result = assign_role(
            &mut state,
            "did:dht:alice",
            "member",
            "did:dht:creator",
            &scp_clock::SystemClock,
        );
        assert!(result.is_ok());

        let tokens = result.unwrap();
        // member role has 3 capabilities -> 3 tokens.
        assert_eq!(tokens.len(), 3);

        // Alice should now have member capabilities.
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesRead));
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesWrite));
        assert!(state.member_has_capability("did:dht:alice", &Capability::OutletCallAll));
    }

    #[test]
    fn assign_role_rejects_role_definition_outside_ceiling() {
        // Mint-time ceiling enforcement (spec §7.2.1 step 8): even if a role
        // definition with an out-of-ceiling capability is introduced into
        // `role_definitions` by any path, `assign_role` must reject it before
        // minting and must NOT mutate the member's capabilities.
        //
        // Use `test_ceiling` (which includes RoleAssign) so the creator-admin
        // passes the step-1 authorization check; the smuggled role then carries
        // a Custom capability that is NOT in the ceiling, isolating the
        // mint-time ceiling gate.
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_clock::SystemClock,
        )
        .unwrap();

        state.members.insert("did:dht:alice".to_owned());

        // Inject a role whose capability set exceeds the ceiling.
        let out_of_ceiling = Capability::Custom("not-in-ceiling".to_owned());
        let smuggled = RoleDefinition::new_unchecked(
            "smuggled",
            [Capability::MessagesWrite, out_of_ceiling.clone()]
                .into_iter()
                .collect(),
        );
        state
            .role_definitions
            .insert("smuggled".to_owned(), smuggled);

        let result = assign_role(
            &mut state,
            "did:dht:alice",
            "smuggled",
            "did:dht:creator",
            &scp_clock::SystemClock,
        );
        assert!(
            matches!(
                result,
                Err(RoleError::CapabilityOutsideCeiling { ref role, ref capability })
                    if role == "smuggled" && *capability == out_of_ceiling
            ),
            "assign_role must reject an out-of-ceiling role definition at mint time: {result:?}"
        );

        // No tokens minted, no capabilities granted, no assignment recorded.
        assert!(!state.member_has_capability("did:dht:alice", &Capability::RoleAssign));
        assert!(!state.member_capabilities.contains_key("did:dht:alice"));
        assert!(!state.assignments.contains_key("did:dht:alice"));
    }

    #[test]
    fn system_assign_role_rejects_role_definition_outside_ceiling() {
        // Same mint-time ceiling enforcement on the system (governance) path,
        // which bypasses the RoleAssign authorization check but must NOT bypass
        // the ceiling.
        let ceiling = minimal_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_clock::SystemClock,
        )
        .unwrap();

        state.members.insert("did:dht:alice".to_owned());

        let smuggled = RoleDefinition::new_unchecked(
            "smuggled",
            [Capability::MessagesWrite, Capability::ContextClose]
                .into_iter()
                .collect(),
        );
        state
            .role_definitions
            .insert("smuggled".to_owned(), smuggled);

        let result = system_assign_role(
            &mut state,
            "did:dht:alice",
            "smuggled",
            &scp_clock::SystemClock,
        );
        assert!(
            matches!(
                result,
                Err(RoleError::CapabilityOutsideCeiling { ref role, ref capability })
                    if role == "smuggled" && *capability == Capability::ContextClose
            ),
            "system_assign_role must reject an out-of-ceiling role definition at mint time: {result:?}"
        );

        assert!(!state.member_has_capability("did:dht:alice", &Capability::ContextClose));
        assert!(!state.member_capabilities.contains_key("did:dht:alice"));
        assert!(!state.assignments.contains_key("did:dht:alice"));
    }

    #[test]
    fn assign_role_fails_for_unauthorized_assigner() {
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_clock::SystemClock,
        )
        .unwrap();

        // Add members.
        state.members.insert("did:dht:alice".to_owned());
        state.members.insert("did:dht:bob".to_owned());

        // Assign alice as member (no RoleAssign capability).
        assign_role(
            &mut state,
            "did:dht:alice",
            "member",
            "did:dht:creator",
            &scp_clock::SystemClock,
        )
        .unwrap();

        // Alice tries to assign bob -- should fail.
        let result = assign_role(
            &mut state,
            "did:dht:bob",
            "member",
            "did:dht:alice",
            &scp_clock::SystemClock,
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RoleError::AssignerNotAuthorized(ref did) if did == "did:dht:alice"
        ));
    }

    #[test]
    fn assign_role_fails_for_nonexistent_member() {
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_clock::SystemClock,
        )
        .unwrap();

        let result = assign_role(
            &mut state,
            "did:dht:nobody",
            "member",
            "did:dht:creator",
            &scp_clock::SystemClock,
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RoleError::MemberNotInContext(ref did) if did == "did:dht:nobody"
        ));
    }

    #[test]
    fn assign_role_fails_for_nonexistent_role() {
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_clock::SystemClock,
        )
        .unwrap();

        state.members.insert("did:dht:alice".to_owned());

        let result = assign_role(
            &mut state,
            "did:dht:alice",
            "nonexistent",
            "did:dht:creator",
            &scp_clock::SystemClock,
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RoleError::RoleNotFound(ref name) if name == "nonexistent"
        ));
    }

    #[test]
    fn assign_role_replaces_previous_assignment() {
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_clock::SystemClock,
        )
        .unwrap();

        state.members.insert("did:dht:alice".to_owned());

        // Assign as member first.
        assign_role(
            &mut state,
            "did:dht:alice",
            "member",
            "did:dht:creator",
            &scp_clock::SystemClock,
        )
        .unwrap();
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesWrite));

        // Reassign as observer.
        assign_role(
            &mut state,
            "did:dht:alice",
            "observer",
            "did:dht:creator",
            &scp_clock::SystemClock,
        )
        .unwrap();
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesRead));
        assert!(!state.member_has_capability("did:dht:alice", &Capability::MessagesWrite));

        let assignment = state.assignments.get("did:dht:alice").unwrap();
        assert_eq!(assignment.role_name, "observer");
    }

    #[test]
    fn assign_role_prunes_suspensions_outside_new_role_grants() {
        // Reassigning from a role that granted GovernanceVote to a
        // role that does NOT grant it must prune the now-meaningless
        // suspended-capability entry.
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-b5-prune",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_clock::SystemClock,
        )
        .unwrap();

        state.members.insert("did:dht:alice".to_owned());

        // Start Alice as member (grants MessagesWrite, GovernanceVote, etc).
        assign_role(
            &mut state,
            "did:dht:alice",
            "member",
            "did:dht:creator",
            &scp_clock::SystemClock,
        )
        .unwrap();

        // Suspend Alice's GovernanceVote capability.
        state.suspend_capabilities("did:dht:alice", [Capability::GovernanceVote]);
        assert!(
            state
                .suspended_capabilities
                .get("did:dht:alice")
                .unwrap()
                .contains(&Capability::GovernanceVote)
        );

        // Demote Alice to observer (which only grants MessagesRead).
        assign_role(
            &mut state,
            "did:dht:alice",
            "observer",
            "did:dht:creator",
            &scp_clock::SystemClock,
        )
        .unwrap();

        // The GovernanceVote suspension is meaningless now — observer
        // doesn't grant GovernanceVote. The prune should have dropped
        // the empty set entirely.
        assert!(
            !state.suspended_capabilities.contains_key("did:dht:alice"),
            "stale suspension set must be dropped when new role grants none of the suspended capabilities"
        );
    }

    #[test]
    fn assign_role_retains_suspensions_still_granted_by_new_role() {
        // Reassigning to a role that still grants the suspended
        // capability must keep the suspension in place: a banned
        // voter promoted to admin is still banned from voting.
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-b5-retain",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_clock::SystemClock,
        )
        .unwrap();

        state.members.insert("did:dht:alice".to_owned());

        // Start Alice as member.
        assign_role(
            &mut state,
            "did:dht:alice",
            "member",
            "did:dht:creator",
            &scp_clock::SystemClock,
        )
        .unwrap();

        // Suspend GovernanceVote.
        state.suspend_capabilities("did:dht:alice", [Capability::GovernanceVote]);

        // Promote Alice to admin (which also grants GovernanceVote).
        assign_role(
            &mut state,
            "did:dht:alice",
            "admin",
            "did:dht:creator",
            &scp_clock::SystemClock,
        )
        .unwrap();

        // The GovernanceVote suspension must still be in place.
        assert!(
            state
                .suspended_capabilities
                .get("did:dht:alice")
                .is_some_and(|s| s.contains(&Capability::GovernanceVote)),
            "suspension must persist across role change when new role still grants the capability"
        );
        assert!(
            !state.member_has_capability("did:dht:alice", &Capability::GovernanceVote),
            "member_has_capability must still block the suspended capability"
        );
    }

    #[test]
    fn assign_role_prunes_mixed_suspensions() {
        // When only some suspensions are outside the new role's
        // grants, only those specific entries are dropped — the
        // rest persist.
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-b5-mixed",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_clock::SystemClock,
        )
        .unwrap();

        state.members.insert("did:dht:alice".to_owned());
        assign_role(
            &mut state,
            "did:dht:alice",
            "member",
            "did:dht:creator",
            &scp_clock::SystemClock,
        )
        .unwrap();

        // Suspend BOTH GovernanceVote (not granted by observer) AND
        // MessagesRead (still granted by observer).
        state.suspend_capabilities(
            "did:dht:alice",
            [Capability::GovernanceVote, Capability::MessagesRead],
        );

        // Demote to observer.
        assign_role(
            &mut state,
            "did:dht:alice",
            "observer",
            "did:dht:creator",
            &scp_clock::SystemClock,
        )
        .unwrap();

        // GovernanceVote suspension → dropped (observer does not grant it).
        // MessagesRead suspension → retained (observer grants MessagesRead).
        let suspended = state
            .suspended_capabilities
            .get("did:dht:alice")
            .expect("suspension entry must still exist because MessagesRead is retained");
        assert!(!suspended.contains(&Capability::GovernanceVote));
        assert!(suspended.contains(&Capability::MessagesRead));
    }

    #[test]
    fn assign_role_mints_correct_token_format() {
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_clock::SystemClock,
        )
        .unwrap();

        state.members.insert("did:dht:alice".to_owned());

        let tokens = assign_role(
            &mut state,
            "did:dht:alice",
            "observer",
            "did:dht:creator",
            &scp_clock::SystemClock,
        )
        .unwrap();

        assert_eq!(tokens.len(), 1);
        let token = &tokens[0];
        assert_eq!(token.iss, "did:dht:creator");
        assert_eq!(token.aud, "did:dht:alice");
        assert_eq!(token.att.len(), 1);
        assert_eq!(token.att[0].with, "scp:ctx:ctx-1/messages:read");
        assert_eq!(token.att[0].can, "read");
        assert!(!token.nnc.is_empty());
        // Verify nonce format: {millis}-{hex}.
        assert!(token.nnc.contains('-'));
    }

    #[test]
    fn assign_role_admin_grants_all_ceiling_capabilities() {
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling.clone(),
            vec![],
            &scp_clock::SystemClock,
        )
        .unwrap();

        state.members.insert("did:dht:alice".to_owned());

        let tokens = assign_role(
            &mut state,
            "did:dht:alice",
            "admin",
            "did:dht:creator",
            &scp_clock::SystemClock,
        )
        .unwrap();

        // Admin gets all ceiling capabilities.
        assert_eq!(tokens.len(), ceiling.len());

        for cap in &ceiling.capabilities {
            assert!(
                state.member_has_capability("did:dht:alice", cap),
                "admin should have capability {cap:?}"
            );
        }
    }

    #[test]
    fn assign_role_custom_role() {
        let ceiling = test_ceiling();
        let custom = RoleDefinition::new(
            "content-mod",
            HashSet::from([
                Capability::MessagesRead,
                Capability::MessagesWrite,
                Capability::MemberRemove,
            ]),
            &ceiling,
        )
        .unwrap();

        let mut state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![custom],
            &scp_clock::SystemClock,
        )
        .unwrap();

        state.members.insert("did:dht:alice".to_owned());

        let tokens = assign_role(
            &mut state,
            "did:dht:alice",
            "content-mod",
            "did:dht:creator",
            &scp_clock::SystemClock,
        )
        .unwrap();
        assert_eq!(tokens.len(), 3);
        assert!(state.member_has_capability("did:dht:alice", &Capability::MemberRemove));
    }

    // `suspended_capabilities` fold must check the exact capability
    // being queried, so suspending one capability blocks only that
    // capability — other gates remain passable.

    #[test]
    fn suspension_blocks_only_the_exact_capability() {
        // Suspend MessagesWrite. MessagesRead and GovernanceVote
        // must remain passable.
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-b2-precise",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_clock::SystemClock,
        )
        .unwrap();
        state.members.insert("did:dht:alice".to_owned());
        // Use admin so alice has all ceiling capabilities (incl. GovernanceVote/Propose).
        assign_role(
            &mut state,
            "did:dht:alice",
            "admin",
            "did:dht:creator",
            &scp_clock::SystemClock,
        )
        .unwrap();

        // Sanity: admin has all four before suspension.
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesRead));
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesWrite));
        assert!(state.member_has_capability("did:dht:alice", &Capability::GovernanceVote));
        assert!(state.member_has_capability("did:dht:alice", &Capability::GovernancePropose));

        // Suspend only MessagesWrite.
        state.suspend_capabilities("did:dht:alice", [Capability::MessagesWrite]);

        // Only MessagesWrite is blocked. Everything else still passes.
        assert!(!state.member_has_capability("did:dht:alice", &Capability::MessagesWrite));
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesRead));
        assert!(state.member_has_capability("did:dht:alice", &Capability::GovernanceVote));
        assert!(state.member_has_capability("did:dht:alice", &Capability::GovernancePropose));
    }

    #[test]
    fn suspension_blocks_custom_capability_without_escalating() {
        // Suspending a `Capability::Custom` must block the exact
        // capability and leave standard variants passable —
        // surgical, not an escalation to "write access revoked".
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-b2-custom",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_clock::SystemClock,
        )
        .unwrap();
        state.members.insert("did:dht:alice".to_owned());
        assign_role(
            &mut state,
            "did:dht:alice",
            "member",
            "did:dht:creator",
            &scp_clock::SystemClock,
        )
        .unwrap();

        // Grant a custom capability by injecting it directly into the
        // member's capability set (roles.rs doesn't add custom
        // capabilities via the standard role flow but the fold must
        // handle them correctly if someone does).
        let custom = Capability::Custom("outlet:call:calculator".to_owned());
        state
            .member_capabilities
            .get_mut("did:dht:alice")
            .unwrap()
            .insert(custom.clone());
        assert!(state.member_has_capability("did:dht:alice", &custom));

        // Suspend the custom capability.
        state.suspend_capabilities("did:dht:alice", [custom.clone()]);

        // The custom capability is blocked; standard ones remain passable.
        assert!(!state.member_has_capability("did:dht:alice", &custom));
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesWrite));
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesRead));
    }

    #[test]
    fn suspension_of_mixed_standard_and_custom_capabilities() {
        // Suspending a set containing both a standard variant AND a
        // custom string must block both surgically without affecting
        // unrelated capabilities.
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-b2-mixed",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_clock::SystemClock,
        )
        .unwrap();
        state.members.insert("did:dht:alice".to_owned());
        // Use admin so alice has GovernanceVote/GovernancePropose.
        assign_role(
            &mut state,
            "did:dht:alice",
            "admin",
            "did:dht:creator",
            &scp_clock::SystemClock,
        )
        .unwrap();
        let custom = Capability::Custom("payments:approve".to_owned());
        state
            .member_capabilities
            .get_mut("did:dht:alice")
            .unwrap()
            .insert(custom.clone());

        state.suspend_capabilities(
            "did:dht:alice",
            [Capability::GovernanceVote, custom.clone()],
        );

        // Both suspended capabilities are blocked.
        assert!(!state.member_has_capability("did:dht:alice", &Capability::GovernanceVote));
        assert!(!state.member_has_capability("did:dht:alice", &custom));
        // Unrelated capabilities remain passable.
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesWrite));
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesRead));
        assert!(state.member_has_capability("did:dht:alice", &Capability::GovernancePropose));
    }

    #[test]
    fn restoring_capability_lifts_the_suspension() {
        // restore_capabilities removes entries from the suspended set
        // and drops the whole entry if empty. After restore, the gate
        // passes again.
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-b2-restore",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_clock::SystemClock,
        )
        .unwrap();
        state.members.insert("did:dht:alice".to_owned());
        assign_role(
            &mut state,
            "did:dht:alice",
            "member",
            "did:dht:creator",
            &scp_clock::SystemClock,
        )
        .unwrap();
        state.suspend_capabilities("did:dht:alice", [Capability::MessagesWrite]);
        assert!(!state.member_has_capability("did:dht:alice", &Capability::MessagesWrite));

        state.restore_capabilities("did:dht:alice", &[Capability::MessagesWrite]);
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesWrite));
        assert!(
            !state.suspended_capabilities.contains_key("did:dht:alice"),
            "empty suspension set should be removed after full restore"
        );
    }

    // -----------------------------------------------------------------------
    // validate_role_definition
    // -----------------------------------------------------------------------

    #[test]
    fn validate_role_definition_succeeds_for_valid_subset() {
        let ceiling = test_ceiling();
        let role =
            RoleDefinition::new_unchecked("custom", HashSet::from([Capability::MessagesRead]));
        assert!(validate_role_definition(&role, &ceiling).is_ok());
    }

    #[test]
    fn validate_role_definition_fails_for_capability_outside_ceiling() {
        let ceiling = minimal_ceiling();
        let role = RoleDefinition::new_unchecked(
            "bad",
            HashSet::from([Capability::MessagesRead, Capability::ContextClose]),
        );
        let result = validate_role_definition(&role, &ceiling);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RoleError::CapabilityOutsideCeiling { ref role, ref capability }
                if role == "bad" && *capability == Capability::ContextClose
        ));
    }

    // -----------------------------------------------------------------------
    // Ceiling immutability
    // -----------------------------------------------------------------------

    #[test]
    fn ceiling_immutability_error_variant_exists() {
        // Verify the ContextError::CeilingImmutable variant exists and has
        // the correct error message. This is defined in mod.rs but the
        // roles module depends on it.
        let err = ContextError::CeilingImmutable;
        assert_eq!(
            format!("{err}"),
            "capability ceiling is immutable and cannot be modified"
        );
    }

    // -----------------------------------------------------------------------
    // RoleError display messages
    // -----------------------------------------------------------------------

    #[test]
    fn role_error_display_messages() {
        let err = RoleError::CapabilityOutsideCeiling {
            role: "test".to_owned(),
            capability: Capability::RoleAssign,
        };
        assert!(format!("{err}").contains("test"));
        assert!(format!("{err}").contains("role:assign"));

        let err = RoleError::RoleNotFound("ghost".to_owned());
        assert!(format!("{err}").contains("ghost"));

        let err = RoleError::AssignerNotAuthorized("did:dht:bad".to_owned());
        assert!(format!("{err}").contains("did:dht:bad"));

        let err = RoleError::MemberNotInContext("did:dht:nobody".to_owned());
        assert!(format!("{err}").contains("did:dht:nobody"));
    }

    // -----------------------------------------------------------------------
    // Nonce uniqueness
    // -----------------------------------------------------------------------

    #[test]
    fn generated_nonces_are_unique() {
        let nonces: Vec<String> = (0..100)
            .map(|_| generate_nonce(&scp_clock::SystemClock))
            .collect();
        let unique: HashSet<&String> = nonces.iter().collect();
        assert_eq!(
            nonces.len(),
            unique.len(),
            "all generated nonces should be unique"
        );
    }

    #[test]
    fn nonce_format_is_valid() {
        let nonce = generate_nonce(&scp_clock::SystemClock);
        let parts: Vec<&str> = nonce.splitn(2, '-').collect();
        assert_eq!(parts.len(), 2, "nonce should have timestamp-hex format");
        // Timestamp part should be a valid number.
        assert!(
            parts[0].parse::<u128>().is_ok(),
            "timestamp portion should be numeric"
        );
        // Hex part should be 32 hex characters (16 bytes).
        assert_eq!(parts[1].len(), 32, "random hex should be 32 characters");
        assert!(
            parts[1].chars().all(|c| c.is_ascii_hexdigit()),
            "random portion should be hex"
        );
    }

    // -----------------------------------------------------------------------
    // Mode-agnostic capabilities
    // -----------------------------------------------------------------------

    #[test]
    fn messages_capabilities_work_in_both_modes() {
        // MessagesRead and MessagesWrite are mode-agnostic per ADR-009.
        // Verify they appear in both standard and broadcast role sets.
        let ceiling = test_ceiling();

        let member = builtin_member(&ceiling);
        let author = builtin_author(&ceiling);
        let observer = builtin_observer(&ceiling);
        let subscriber = builtin_subscriber(&ceiling);

        // Standard roles.
        assert!(member.capabilities.contains(&Capability::MessagesRead));
        assert!(member.capabilities.contains(&Capability::MessagesWrite));
        assert!(observer.capabilities.contains(&Capability::MessagesRead));

        // Broadcast roles use the same capability variants.
        assert!(author.capabilities.contains(&Capability::MessagesRead));
        assert!(author.capabilities.contains(&Capability::MessagesWrite));
        assert!(subscriber.capabilities.contains(&Capability::MessagesRead));
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn empty_ceiling_admin_has_no_capabilities() {
        let ceiling = CapabilityCeiling::new(std::iter::empty());
        let admin = builtin_admin(&ceiling);
        assert!(admin.capabilities.is_empty());
    }

    #[test]
    fn empty_ceiling_member_has_no_capabilities() {
        let ceiling = CapabilityCeiling::new(std::iter::empty());
        let member = builtin_member(&ceiling);
        assert!(member.capabilities.is_empty());
    }

    #[test]
    fn ceiling_with_custom_capability() {
        // Custom ceiling entries are well-formed `{resource}:{action}` per
        // §5.3.1.1 (no bare single-token customs).
        let ceiling = CapabilityCeiling::new([
            Capability::MessagesRead,
            Capability::Custom("special:action".to_owned()),
        ]);
        assert!(ceiling.contains(&Capability::Custom("special:action".to_owned())));
        assert!(!ceiling.contains(&Capability::Custom("other:action".to_owned())));
    }

    // -----------------------------------------------------------------------
    // Ceiling-entry grammar (spec §5.3.1.1)
    // -----------------------------------------------------------------------

    #[test]
    fn ceiling_entry_accepts_wellformed_custom_and_wildcard() {
        // Custom `{resource}:{action}` and explicit `{resource}:*` wildcard.
        validate_ceiling_entry("payments:approve").unwrap();
        validate_ceiling_entry("payments:*").unwrap();
        validate_ceiling_entry("a-b-c:d-e-f").unwrap();
        validate_ceiling_entry("r0:a0").unwrap();
    }

    #[test]
    fn ceiling_entry_accepts_builtin_categories() {
        for entry in [
            "messages:read",
            "messages:write",
            "outlet:register",
            "outlet:query:*",
            "outlet:call:*",
            "outlet:query:calc",
            "outlet:call:calc",
            "member:invite",
            "member:remove",
            "member:ban",
            "role:assign",
            "media:voice",
            "media:video",
            "media:screen_share",
            "bridging",
            "outlet:interface",
            "context:child:create",
            "governance:propose",
            "governance:vote",
            "context:close",
            "metadata:edit",
        ] {
            validate_ceiling_entry(entry)
                .unwrap_or_else(|e| panic!("built-in {entry:?} must be accepted: {e}"));
        }
    }

    #[test]
    fn ceiling_entry_rejects_single_token_custom() {
        // No colon, no action → malformed; never widened to `payments:*`.
        assert!(matches!(
            validate_ceiling_entry("payments"),
            Err(CeilingEntryError::InvalidCeilingCategory { .. })
        ));
    }

    #[test]
    fn ceiling_entry_rejects_stray_wildcards() {
        for entry in [
            "*:*",
            "*:read",
            "pay*ments",
            "payments:wr*",
            "*",
            "*:approve",
        ] {
            assert!(
                matches!(
                    validate_ceiling_entry(entry),
                    Err(CeilingEntryError::InvalidCeilingCategory { .. })
                ),
                "entry {entry:?} must be rejected"
            );
        }
    }

    #[test]
    fn ceiling_entry_rejects_multi_colon() {
        assert!(matches!(
            validate_ceiling_entry("payments:read:write"),
            Err(CeilingEntryError::InvalidCeilingCategory { .. })
        ));
    }

    #[test]
    fn ceiling_entry_rejects_empty_segments() {
        for entry in ["payments:", ":read", ":", ""] {
            assert!(
                matches!(
                    validate_ceiling_entry(entry),
                    Err(CeilingEntryError::InvalidCeilingCategory { .. })
                ),
                "entry {entry:?} must be rejected"
            );
        }
    }

    #[test]
    fn ceiling_entry_rejects_bad_charset_and_whitespace() {
        for entry in [
            "Payments:approve",  // uppercase
            "payments:Approve",  // uppercase action
            "pay ments:approve", // internal whitespace
            "payments:appr ove",
            "payments :approve",
            "pay_ments:approve", // underscore not in custom kebab charset
            "payments:appr_ove",
            "payménts:approve", // non-ASCII
        ] {
            assert!(
                matches!(
                    validate_ceiling_entry(entry),
                    Err(CeilingEntryError::InvalidCeilingCategory { .. })
                ),
                "entry {entry:?} must be rejected"
            );
        }
    }

    #[test]
    fn ceiling_entry_rejects_control_and_html_chars() {
        for entry in [
            "payments:appr\u{0000}ove",
            "payments:appr\u{001f}ove",
            "payments:appr\u{007f}ove",
            "payments:appr\u{009f}ove",
            "payments:<approve>",
            "payments:appr&ove",
            "payments:appr\"ove",
            "payments:appr'ove",
        ] {
            assert!(
                matches!(
                    validate_ceiling_entry(entry),
                    Err(CeilingEntryError::InvalidCeilingCategory { .. })
                ),
                "entry {entry:?} must be rejected"
            );
        }
    }

    #[test]
    fn ceiling_entry_rejects_oversize() {
        // 256 bytes is the cap; build a 257-byte well-charset entry.
        let resource = "r";
        let action = "a".repeat(MAX_CEILING_ENTRY_LENGTH); // r:aaa... → 1+1+256 = 258 bytes
        let entry = format!("{resource}:{action}");
        assert!(entry.len() > MAX_CEILING_ENTRY_LENGTH);
        assert!(matches!(
            validate_ceiling_entry(&entry),
            Err(CeilingEntryError::InvalidCeilingCategory { .. })
        ));
        // A 256-byte entry at the boundary is accepted (well-formed kebab).
        let at_cap = format!("r:{}", "a".repeat(MAX_CEILING_ENTRY_LENGTH - 2));
        assert_eq!(at_cap.len(), MAX_CEILING_ENTRY_LENGTH);
        validate_ceiling_entry(&at_cap).unwrap();
    }

    #[test]
    fn ceiling_entry_rejects_outlet_stem_with_stray_wildcard() {
        // `outlet:query:*` / `outlet:call:*` are the only wildcard outlet
        // built-ins; an embedded `*` in the outlet_id is malformed, as is an
        // empty outlet_id.
        for bad in [
            "outlet:call:ca*lc",
            "outlet:call:",
            "outlet:query:ca*lc",
            "outlet:query:",
        ] {
            assert!(
                matches!(
                    validate_ceiling_entry(bad),
                    Err(CeilingEntryError::InvalidCeilingCategory { .. })
                ),
                "outlet stem {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn capability_validate_as_ceiling_entry_rejects_malformed_custom() {
        // Enum-form entry point onto the canonical validator.
        assert!(
            Capability::Custom("payments".to_owned())
                .validate_as_ceiling_entry()
                .is_err()
        );
        assert!(
            Capability::Custom("*:*".to_owned())
                .validate_as_ceiling_entry()
                .is_err()
        );
        assert!(
            Capability::Custom("payments:approve".to_owned())
                .validate_as_ceiling_entry()
                .is_ok()
        );
        assert!(
            Capability::Custom("payments:*".to_owned())
                .validate_as_ceiling_entry()
                .is_ok()
        );
        // Built-ins are always well-formed.
        assert!(Capability::MessagesRead.validate_as_ceiling_entry().is_ok());
        assert!(
            Capability::OutletCallAll
                .validate_as_ceiling_entry()
                .is_ok()
        );
        assert!(
            Capability::OutletCall("calc".to_owned())
                .validate_as_ceiling_entry()
                .is_ok()
        );
        assert!(
            Capability::OutletCall("ca*lc".to_owned())
                .validate_as_ceiling_entry()
                .is_err()
        );
    }

    /// `Capability::new` recognizes a built-in in EITHER its colon spelling or
    /// its UCAN wire spelling, always yielding the proper built-in variant (never
    /// a `Custom` lookalike) — the multi-segment built-ins whose UCAN form differs
    /// from colon form (`outlet_query:*`, `outlet_call:*`, `outlet_call:{id}`,
    /// `context_child:create`, `bridging:*`) plus a representative sample of the
    /// identical-spelling built-ins. Without this, a context's STORED (canonical
    /// UCAN-form) ceiling re-parses to a `Custom` and fails re-validation
    /// (`InvalidCeilingCategory: outlet_call:* is malformed`), breaking context
    /// creation / outlet flow / cross-bridge parity.
    #[test]
    fn capability_new_parses_builtin_colon_and_ucan_spellings() {
        // Colon spelling → built-in variant.
        assert_eq!(
            Capability::new("outlet:call:*"),
            Some(Capability::OutletCallAll)
        );
        assert_eq!(
            Capability::new("outlet:query:*"),
            Some(Capability::OutletQueryAll)
        );
        assert_eq!(
            Capability::new("context:child:create"),
            Some(Capability::ChildContextCreate)
        );
        assert_eq!(Capability::new("bridging"), Some(Capability::Bridging));
        assert_eq!(
            Capability::new("outlet:call:calc"),
            Some(Capability::OutletCall("calc".to_owned()))
        );
        assert_eq!(
            Capability::new("outlet:query:calc"),
            Some(Capability::OutletQuery("calc".to_owned()))
        );

        // UCAN wire spelling → the SAME built-in variant (not a Custom).
        assert_eq!(
            Capability::new("outlet_call:*"),
            Some(Capability::OutletCallAll)
        );
        assert_eq!(
            Capability::new("outlet_query:*"),
            Some(Capability::OutletQueryAll)
        );
        assert_eq!(
            Capability::new("context_child:create"),
            Some(Capability::ChildContextCreate)
        );
        assert_eq!(Capability::new("bridging:*"), Some(Capability::Bridging));
        assert_eq!(
            Capability::new("outlet_call:calc"),
            Some(Capability::OutletCall("calc".to_owned()))
        );

        // Identical-spelling built-ins parse the same either way.
        assert_eq!(
            Capability::new("messages:read"),
            Some(Capability::MessagesRead)
        );
        assert_eq!(
            Capability::new("media:screen_share"),
            Some(Capability::MediaScreenShare)
        );

        // Every built-in's UCAN form round-trips back to its variant, so the
        // canonical STORED ceiling form re-parses to the proper enum.
        for cap in BUILTIN_CAPABILITIES {
            let ucan = cap.ucan_capability_name();
            assert_eq!(
                Capability::new(&ucan).as_ref(),
                Some(cap),
                "UCAN form {ucan:?} must parse back to {cap:?}"
            );
        }
    }

    /// A built-in supplied in EITHER spelling is a valid ceiling entry; a
    /// malformed custom is rejected in either parse. Mirrors the create-path
    /// `Capability::new(entry).validate_as_ceiling_entry()` the bridges run, and
    /// pins the regression: the canonical UCAN spellings (`outlet_call:*`,
    /// `outlet_query:*`, `context_child:create`, `bridging:*`, `outlet_call:{id}`)
    /// and the user-facing colon spellings must BOTH pass; underscore-resource
    /// customs and stray-wildcard / multi-colon customs must still fail.
    #[test]
    fn ceiling_entry_accepts_builtin_either_spelling_rejects_malformed_custom() {
        for good in [
            // Colon spellings (spec §5.3.1 table / SDK input).
            "messages:read",
            "outlet:call:*",
            "outlet:query:*",
            "outlet:call:calc",
            "outlet:query:calc",
            "context:child:create",
            "bridging",
            "media:screen_share",
            // UCAN wire spellings (canonical stored form).
            "outlet_call:*",
            "outlet_query:*",
            "outlet_call:calc",
            "context_child:create",
            "bridging:*",
            // Well-formed customs.
            "payments:approve",
            "payments:*",
        ] {
            Capability::new(good)
                .unwrap_or_else(|| panic!("ceiling entry {good:?} must parse"))
                .validate_as_ceiling_entry()
                .unwrap_or_else(|e| panic!("ceiling entry {good:?} must be accepted: {e}"));
        }

        for bad in [
            "payments",            // no-colon custom
            "*:*",                 // stray wildcard resource
            "*:read",              // stray wildcard resource
            "payments:read:write", // multi-colon custom
            "pay_ments:approve",   // underscore resource is NOT a valid custom
        ] {
            let cap = Capability::new(bad)
                .unwrap_or_else(|| panic!("custom {bad:?} must still parse to a Custom"));
            assert!(
                cap.validate_as_ceiling_entry().is_err(),
                "ceiling entry {bad:?} must be rejected"
            );
        }

        // Stray `*` in an outlet_id makes the whole stem UNPARSEABLE (the strict
        // §5.4.2.1 parser returns `None`), so these never even reach
        // `validate_as_ceiling_entry`.
        for unparseable in ["outlet_call:ca*lc", "outlet:call:ca*lc"] {
            assert_eq!(
                Capability::new(unparseable),
                None,
                "outlet stem {unparseable:?} with a stray '*' must fail the parser"
            );
        }
    }

    /// `BUILTIN_CAPABILITIES` must list every non-parameterized built-in variant
    /// (everything except `OutletQuery(_)` / `OutletCall(_)` and `Custom(_)`). An
    /// exhaustive match makes a newly-added built-in a compile error here, forcing
    /// it into the list so `validate_ucan_ceiling_string` recognizes its UCAN
    /// spelling.
    #[test]
    fn builtin_capabilities_list_is_exhaustive() {
        fn assert_listed(cap: &Capability) {
            // Exhaustive match: a new variant breaks compilation here.
            match cap {
                Capability::OutletQuery(_) | Capability::OutletCall(_) | Capability::Custom(_) => {
                    // Parameterized / custom — deliberately NOT in the built-in list.
                }
                Capability::MessagesRead
                | Capability::MessagesWrite
                | Capability::OutletQueryAll
                | Capability::OutletCallAll
                | Capability::OutletRegister
                | Capability::MemberInvite
                | Capability::MemberRemove
                | Capability::RoleAssign
                | Capability::GovernancePropose
                | Capability::GovernanceVote
                | Capability::ContextClose
                | Capability::ChildContextCreate
                | Capability::OutletInterface
                | Capability::Bridging
                | Capability::MediaVoice
                | Capability::MediaVideo
                | Capability::MediaScreenShare
                | Capability::MemberBan
                | Capability::MetadataEdit => {
                    assert!(
                        BUILTIN_CAPABILITIES.contains(cap),
                        "built-in {cap:?} missing from BUILTIN_CAPABILITIES"
                    );
                }
            }
        }
        for cap in BUILTIN_CAPABILITIES {
            assert_listed(cap);
        }
        assert_eq!(
            BUILTIN_CAPABILITIES.len(),
            19,
            "BUILTIN_CAPABILITIES should hold all 19 non-parameterized built-ins"
        );
    }

    /// `validate_ucan_ceiling_string` accepts the canonical UCAN spelling of
    /// every built-in (including the underscore forms `outlet_query:*`,
    /// `outlet_call:*`, `context_child:create`, `bridging:*`) plus parameterized
    /// outlet invokes and well-formed customs — and rejects malformed entries and
    /// non-canonical COLON-form built-ins.
    #[test]
    fn validate_ucan_ceiling_string_accepts_canonical_and_rejects_malformed() {
        // Every built-in's UCAN form round-trips through the UCAN validator.
        for cap in BUILTIN_CAPABILITIES {
            let ucan = cap.ucan_capability_name();
            validate_ucan_ceiling_string(&ucan)
                .unwrap_or_else(|e| panic!("built-in UCAN form {ucan:?} must validate: {e}"));
        }
        // Parameterized outlet invoke + well-formed customs.
        validate_ucan_ceiling_string("outlet_call:calc").unwrap();
        validate_ucan_ceiling_string("outlet_query:calc").unwrap();
        validate_ucan_ceiling_string("payments:approve").unwrap();
        validate_ucan_ceiling_string("billing:*").unwrap();

        // Malformed entries are rejected.
        for bad in [
            "payments",                // no colon
            "*:*",                     // stray wildcard resource
            "a:b:c",                   // multi-colon custom
            "custom_payments:approve", // underscore-resource custom (historical bug spelling)
            "outlet:call:*",           // non-canonical COLON-form built-in
            "context:child:create",    // non-canonical COLON-form built-in
        ] {
            assert!(
                validate_ucan_ceiling_string(bad).is_err(),
                "UCAN-form validator must reject {bad:?}"
            );
        }
    }

    /// The enum-form entry point: a `Custom` carrying a built-in's spelling
    /// (`bridging:*`, whose canonical UCAN form is the [`Capability::Bridging`]
    /// built-in) is rejected. The rejection comes from the `validate_as_ceiling_entry`
    /// re-resolution check — `Capability::new("bridging:*")` resolves to the
    /// `Bridging` variant (not a `Custom`) — which is the sole authoritative §5.3.1.1
    /// "No privileged-built-in collision" mechanism, so the reason is the "names a
    /// built-in" §5.3.1.1 guard. (A `Custom("bridging:*")` is constructed only by
    /// bypassing `new`, e.g. via untrusted deserialization — exactly the surface this
    /// guard defends.)
    #[test]
    fn validate_as_ceiling_entry_rejects_custom_colliding_with_builtin() {
        let err = Capability::Custom("bridging:*".to_owned())
            .validate_as_ceiling_entry()
            .expect_err("Custom(\"bridging:*\") names the Bridging built-in");
        let CeilingEntryError::InvalidCeilingCategory { entry, reason } = err;
        assert_eq!(entry, "bridging:*");
        assert!(
            reason.contains("names a built-in") && reason.contains("§5.3.1.1"),
            "rejection must be the §5.3.1.1 built-in-collision guard (reason was {reason:?})"
        );
    }

    /// A non-colliding well-formed custom is still accepted on BOTH validators —
    /// the collision backstop must not over-reject. `payments:read` and `payments:*`
    /// do not project onto any built-in.
    #[test]
    fn ceiling_entry_accepts_noncolliding_custom_on_both_validators() {
        for good in ["payments:read", "payments:*"] {
            validate_ceiling_entry(good)
                .unwrap_or_else(|e| panic!("colon-form custom {good:?} must be accepted: {e}"));
            validate_ucan_ceiling_string(good)
                .unwrap_or_else(|e| panic!("UCAN-form custom {good:?} must be accepted: {e}"));
        }
    }

    /// `Capability::new("bridging:*")` resolves to the `Bridging` enum variant (not
    /// `Custom`), so the normal colon `create_context` path is unaffected by the
    /// collision backstop — the backstop only matters for raw ceiling STRINGS that
    /// bypass `Capability::new`.
    #[test]
    fn capability_new_bridging_wildcard_resolves_to_builtin_not_custom() {
        assert_eq!(Capability::new("bridging:*"), Some(Capability::Bridging));
        assert_eq!(Capability::new("bridging"), Some(Capability::Bridging));
    }

    /// A built-in's own UCAN string is accepted as a BUILT-IN by the UCAN-form
    /// validator (matched by rule 1 BEFORE the shared custom grammar core is
    /// reached), so a legitimate built-in is never misclassified as a custom on the
    /// UCAN/import path. `bridging:*` is the worked example.
    #[test]
    fn validate_ucan_ceiling_string_accepts_builtin_form_not_false_rejected() {
        validate_ucan_ceiling_string("bridging:*")
            .expect("built-in UCAN form `bridging:*` must be accepted on the UCAN path");
        // Every built-in's UCAN form likewise validates (early-exclusion by rule 1).
        for cap in BUILTIN_CAPABILITIES {
            let ucan = cap.ucan_capability_name();
            validate_ucan_ceiling_string(&ucan).unwrap_or_else(|e| {
                panic!("built-in UCAN form {ucan:?} must be accepted on the UCAN path: {e}")
            });
        }
    }

    /// §5.3.1.1 HIGH-severity regression: a `Custom` whose string is the COLON
    /// spelling of the privileged `outlet:call:*` built-in must be rejected by the
    /// enum-form entry point. The colon spelling early-accepts inside
    /// [`validate_ceiling_entry`] (`outlet:call:*` is in
    /// [`BUILTIN_CEILING_CATEGORIES`]), so plain grammar validation would let it
    /// through; the rejection here comes from the `validate_as_ceiling_entry`
    /// re-resolution check (the string resolves to [`Capability::OutletCallAll`],
    /// not a `Custom`). Without this guard, `Custom("outlet:call:*")` would store
    /// `outlet_call:*` — "call any Action outlet" — onto the ceiling fed to UCAN
    /// minting. The reason text is asserted so the test proves the §5.3.1.1 guard
    /// rejected it.
    #[test]
    fn validate_as_ceiling_entry_rejects_custom_naming_outlet_call_all_builtin() {
        let err = Capability::Custom("outlet:call:*".to_owned())
            .validate_as_ceiling_entry()
            .expect_err("Custom(\"outlet:call:*\") names the OutletCallAll built-in");
        let CeilingEntryError::InvalidCeilingCategory { entry, reason } = err;
        assert_eq!(entry, "outlet:call:*");
        assert!(
            reason.contains("names a built-in") && reason.contains("§5.3.1.1"),
            "rejection must be the §5.3.1.1 built-in-collision guard (reason was {reason:?})"
        );
    }

    /// §5.3.1.1 HIGH-severity regression: a `Custom` naming the parameterized
    /// `outlet:call:{outlet_id}` built-in family (here `outlet:call:calc`) must be
    /// rejected. The colon spelling early-accepts as a parameterized built-in inside
    /// [`validate_ceiling_entry`] (rule 1b), so plain grammar validation would let it
    /// through; the rejection comes from the `validate_as_ceiling_entry` re-resolution
    /// check (the string resolves to `Capability::OutletCall("calc")`, not a
    /// `Custom`). Confirms the parameterized family is covered for a concrete
    /// `outlet_id`.
    #[test]
    fn validate_as_ceiling_entry_rejects_custom_naming_parameterized_outlet_call_builtin() {
        let err = Capability::Custom("outlet:call:calc".to_owned())
            .validate_as_ceiling_entry()
            .expect_err("Custom(\"outlet:call:calc\") names the OutletCall(id) built-in family");
        let CeilingEntryError::InvalidCeilingCategory { entry, reason } = err;
        assert_eq!(entry, "outlet:call:calc");
        assert!(
            reason.contains("names a built-in") && reason.contains("§5.3.1.1"),
            "rejection must be the §5.3.1.1 built-in-collision guard (reason was {reason:?})"
        );
    }

    /// The §5.3.1.1 guard covers EVERY built-in spelling a `Custom` could carry —
    /// not just `outlet:call:*` and `bridging:*`. For every built-in, both its
    /// user-facing colon spelling ([`Capability::name`]) and its canonical UCAN
    /// spelling ([`Capability::ucan_capability_name`]), wrapped in a `Custom`, must
    /// be rejected by the re-resolution backstop. This is the general property the
    /// HIGH finding demanded: the check applies regardless of which grammar arm the
    /// string would otherwise match.
    #[test]
    fn validate_as_ceiling_entry_rejects_custom_naming_any_builtin_either_spelling() {
        // Non-parameterized built-ins, both spellings.
        for cap in BUILTIN_CAPABILITIES {
            for spelling in [cap.name().into_owned(), cap.ucan_capability_name()] {
                let result = Capability::Custom(spelling.clone()).validate_as_ceiling_entry();
                let Err(CeilingEntryError::InvalidCeilingCategory { reason, .. }) = result else {
                    panic!("Custom({spelling:?}) names built-in {cap:?} and must be rejected");
                };
                assert!(
                    reason.contains("names a built-in"),
                    "Custom({spelling:?}) must be rejected by the §5.3.1.1 guard \
                     (reason was {reason:?})"
                );
            }
        }
        // Parameterized `OutletQuery(id)` / `OutletCall(id)` families, both
        // spellings, for a concrete id.
        for outlet in [
            Capability::OutletCall("calc".to_owned()),
            Capability::OutletQuery("calc".to_owned()),
        ] {
            for spelling in [outlet.name().into_owned(), outlet.ucan_capability_name()] {
                assert!(
                    Capability::Custom(spelling.clone())
                        .validate_as_ceiling_entry()
                        .is_err(),
                    "Custom({spelling:?}) names the parameterized outlet built-in and must be \
                     rejected"
                );
            }
        }
    }

    /// §5.3.1.1 "No built-in-resource wildcard shadow": a custom shape-3 wildcard
    /// `{resource}:*` whose `{resource}` is a built-in resource token is rejected on
    /// EVERY validation surface — the enum entry point, the raw UCAN-import validator,
    /// and the deserialize boundary. Without this, `member:*` (which does NOT resolve
    /// to a built-in, so the collision rule misses it) would be stored and, via ceiling
    /// wildcard coverage, silently grant the privileged built-in actions in that family
    /// (e.g. `member:ban`, which gates governance `Revoke`). Driven from
    /// `BUILTIN_CAPABILITIES` (closed-by-construction), restricted to the kebab resource
    /// tokens a custom can actually spell.
    #[test]
    fn ceiling_rejects_custom_wildcard_shadowing_builtin_resource() {
        use std::collections::BTreeSet;
        let mut shadowable: BTreeSet<String> = BTreeSet::new();
        for cap in BUILTIN_CAPABILITIES {
            let resource = cap.ucan_resource_action().0.into_owned();
            // A custom resource is kebab `[a-z0-9-]`; built-in resources containing
            // `_` (e.g. `outlet_query`, `outlet_call`, `context_child`) can never be
            // spelled by a custom, so they are not reachable shadow targets. The
            // `outlet` resource (from `OutletRegister` / `OutletInterface`) IS kebab
            // and therefore shadowable.
            if is_kebab_token(&resource) {
                shadowable.insert(resource);
            }
        }
        for expected in [
            "member",
            "messages",
            "media",
            "outlet",
            "role",
            "governance",
            "context",
            "metadata",
        ] {
            assert!(
                shadowable.contains(expected),
                "expected built-in resource {expected:?} in shadowable set {shadowable:?}"
            );
        }
        for resource in &shadowable {
            let wildcard = format!("{resource}:*");
            // `bridging` is the one shadowable resource whose `{resource}:*` is ALSO a
            // built-in's own canonical UCAN form (`Bridging` == `bridging:*`). For it,
            // `Custom("bridging:*")` is rejected one rule earlier — by the no-collision
            // re-resolution rule (it resolves to `Bridging`), reason "names a built-in"
            // — and the raw UCAN-import string `bridging:*` is the LEGITIMATE built-in
            // form and is accepted. Every other shadowable resource has no `{r}:*`
            // built-in, so it is caught by the wildcard-shadow rule on every surface.
            let wildcard_is_builtin_form = BUILTIN_CAPABILITIES
                .iter()
                .any(|c| c.ucan_capability_name() == wildcard);

            // Enum entry point: rejected on both paths (collision OR shadow).
            let err = Capability::Custom(wildcard.clone())
                .validate_as_ceiling_entry()
                .expect_err("custom wildcard over a built-in resource must be rejected");
            let CeilingEntryError::InvalidCeilingCategory { reason, .. } = err;
            if wildcard_is_builtin_form {
                assert!(
                    reason.contains("names a built-in"),
                    "{wildcard:?} is itself a built-in UCAN form; must be rejected by the \
                     no-collision rule (reason {reason:?})"
                );
            } else {
                assert!(
                    reason.contains("shadows a built-in"),
                    "rejection of {wildcard:?} must be the wildcard-shadow rule (reason {reason:?})"
                );
            }

            // UCAN-import raw string: a `{r}:*` that is a legitimate built-in form is
            // accepted (it IS the built-in, no `Custom` wrapper, no masquerade);
            // otherwise it must be rejected by the wildcard-shadow rule.
            let ucan_result = validate_ucan_ceiling_string(&wildcard);
            if wildcard_is_builtin_form {
                assert!(
                    ucan_result.is_ok(),
                    "{wildcard:?} is the legitimate built-in UCAN form and must be accepted on \
                     the import path; got {ucan_result:?}"
                );
            } else {
                assert!(
                    ucan_result.is_err(),
                    "UCAN-import validator must reject wildcard-shadow {wildcard:?}"
                );
            }

            // Deserialize boundary: a `Custom` wrapper is always rejected (the wrapper
            // is the masquerade surface, regardless of which §5.3.1.1 rule fires).
            let bad = CapabilityCeiling::new([Capability::Custom(wildcard.clone())]);
            let json = serde_json::to_string(&bad).expect("serialize unchecked value");
            let parsed: Result<CapabilityCeiling, _> = serde_json::from_str(&json);
            assert!(
                parsed.is_err(),
                "deserializing a ceiling with a Custom {wildcard:?} must fail; got {parsed:?}"
            );
        }
    }

    /// The wildcard-shadow rule MUST NOT over-reject: a custom NON-wildcard action
    /// under a built-in resource (shape 2) grants only itself via exact match and is
    /// accepted; a custom wildcard over a NON-built-in resource is accepted.
    #[test]
    fn ceiling_accepts_nonshadowing_customs() {
        for good in ["member:promote", "messages:archive", "governance:draft"] {
            Capability::Custom(good.to_owned())
                .validate_as_ceiling_entry()
                .unwrap_or_else(|e| {
                    panic!("custom action {good:?} under a built-in resource must be accepted: {e}")
                });
        }
        for good in ["payments:*", "a-b-c:*", "billing:*"] {
            Capability::Custom(good.to_owned())
                .validate_as_ceiling_entry()
                .unwrap_or_else(|e| {
                    panic!("custom wildcard {good:?} over a non-built-in resource must be accepted: {e}")
                });
            assert!(
                validate_ucan_ceiling_string(good).is_ok(),
                "UCAN-import validator must accept non-shadowing wildcard {good:?}"
            );
        }
    }

    /// The untrusted-bytes backstop: a [`CapabilityCeiling`] DESERIALIZED from JSON
    /// carrying a `Custom` that names a privileged built-in (`outlet:call:*` and the
    /// parameterized `outlet:call:calc`) is REJECTED at the `#[serde(try_from)]` /
    /// `validate_entries` boundary. This is the exact attack surface the HIGH finding
    /// described: `Capability` derives a plain `Deserialize` with no normalization,
    /// so `{"Custom":"outlet:call:*"}` deserializes verbatim; the type-level
    /// validating `Deserialize` must refuse to materialize it. `bridging:*` is
    /// included so the deserialize guard is shown to catch the whole family — like
    /// the other masquerade strings, it is rejected by the `validate_as_ceiling_entry`
    /// re-resolution check (`Capability::new("bridging:*")` resolves to the `Bridging`
    /// built-in), not by the custom grammar (which `bridging:*` satisfies).
    #[test]
    fn ceiling_deserialize_rejects_custom_naming_builtin() {
        for masquerade in ["outlet:call:*", "outlet:call:calc", "bridging:*"] {
            // `CapabilityCeiling::new` does NOT validate (validation happens at the
            // write/deserialize boundary), so this constructs the exact bytes a
            // non-conformant peer could sign and export.
            let bad = CapabilityCeiling::new([
                Capability::MessagesRead,
                Capability::Custom(masquerade.to_owned()),
            ]);
            let json = serde_json::to_string(&bad).expect("serialize unchecked value");
            // Sanity: the malformed entry really is on the wire verbatim as a Custom.
            assert!(
                json.contains(&format!("\"Custom\":\"{masquerade}\"")),
                "expected verbatim {{\"Custom\":{masquerade:?}}} in {json}"
            );
            let result: Result<CapabilityCeiling, _> = serde_json::from_str(&json);
            assert!(
                result.is_err(),
                "deserializing a ceiling with a Custom naming the {masquerade:?} built-in must \
                 fail at the type boundary; got {result:?}"
            );
        }
    }

    /// The §5.3.1.1 guard must NOT over-reject: a legitimate custom whose string is
    /// not a built-in in any spelling re-resolves back to a `Custom` and is accepted
    /// on both the enum entry point and the raw-string validators. `payments:read`
    /// and `payments:*` do not name or project onto any built-in.
    #[test]
    fn validate_as_ceiling_entry_accepts_legitimate_custom_not_a_builtin() {
        for good in ["payments:read", "payments:*"] {
            Capability::Custom(good.to_owned())
                .validate_as_ceiling_entry()
                .unwrap_or_else(|e| panic!("legitimate Custom({good:?}) must be accepted: {e}"));
            // The raw-string validators agree (no false reject on either path).
            validate_ceiling_entry(good)
                .unwrap_or_else(|e| panic!("colon-form custom {good:?} must be accepted: {e}"));
            validate_ucan_ceiling_string(good)
                .unwrap_or_else(|e| panic!("UCAN-form custom {good:?} must be accepted: {e}"));
        }
    }

    #[test]
    fn ceiling_validate_entries_rejects_first_malformed() {
        let ceiling = CapabilityCeiling::new([
            Capability::MessagesRead,
            Capability::Custom("payments".to_owned()),
        ]);
        assert!(matches!(
            ceiling.validate_entries(),
            Err(CeilingEntryError::InvalidCeilingCategory { .. })
        ));
    }

    #[test]
    fn context_role_state_new_rejects_malformed_ceiling_entry() {
        // End-to-end: context creation fails (does not store) a malformed entry.
        let clock = scp_clock::SystemClock;
        let ceiling = CapabilityCeiling::new([
            Capability::MessagesRead,
            Capability::Custom("payments".to_owned()),
        ]);
        let result = ContextRoleState::new("ctx-1", "did:scp:creator", ceiling, vec![], &clock);
        assert!(matches!(
            result,
            Err(RoleError::InvalidCeilingCategory(
                CeilingEntryError::InvalidCeilingCategory { .. }
            ))
        ));
    }

    #[test]
    fn context_role_state_new_accepts_wellformed_custom_ceiling() {
        let clock = scp_clock::SystemClock;
        let ceiling = CapabilityCeiling::new([
            Capability::MessagesRead,
            Capability::Custom("payments:approve".to_owned()),
            Capability::Custom("billing:*".to_owned()),
            Capability::OutletCall("calc".to_owned()),
        ]);
        ContextRoleState::new("ctx-1", "did:scp:creator", ceiling, vec![], &clock).unwrap();
    }

    #[test]
    fn set_ceiling_rejects_malformed_entry_and_leaves_prior_unchanged() {
        // Construction invariant: `set_ceiling` validates the WHOLE replacement
        // against the ceiling-entry grammar before storing, so a malformed
        // `CapabilityCeiling` can never be stored via the mutation path either.
        let clock = scp_clock::SystemClock;
        let initial = CapabilityCeiling::new([
            Capability::MessagesRead,
            Capability::Custom("payments:approve".to_owned()),
        ]);
        let mut state =
            ContextRoleState::new("ctx-1", "did:scp:creator", initial.clone(), vec![], &clock)
                .unwrap();

        for malformed in [
            Capability::Custom("payments".to_owned()), // no colon
            Capability::Custom("*:*".to_owned()),      // stray wildcard resource
            Capability::Custom("a:b:c".to_owned()),    // multi-colon (3 segments)
        ] {
            let bad = CapabilityCeiling::new([Capability::MessagesRead, malformed]);
            assert!(matches!(
                state.set_ceiling(bad),
                Err(CeilingEntryError::InvalidCeilingCategory { .. })
            ));
            // Fail-closed: the prior ceiling is left UNCHANGED on a rejected write.
            assert_eq!(state.ceiling(), &initial);
        }
    }

    #[test]
    fn set_ceiling_accepts_wellformed_replacement() {
        let clock = scp_clock::SystemClock;
        let initial = CapabilityCeiling::new([Capability::MessagesRead]);
        let mut state =
            ContextRoleState::new("ctx-1", "did:scp:creator", initial, vec![], &clock).unwrap();

        let replacement = CapabilityCeiling::new([
            Capability::MessagesRead,
            Capability::Custom("payments:approve".to_owned()),
            Capability::Custom("billing:*".to_owned()),
            Capability::OutletCall("calc".to_owned()),
        ]);
        state.set_ceiling(replacement.clone()).unwrap();
        assert_eq!(state.ceiling(), &replacement);
    }

    #[test]
    fn ceiling_mint_and_validate_agree_on_custom_action() {
        // Mint-side: ucan string set for a well-formed custom `{resource}:{action}`.
        let cap = Capability::Custom("payments:approve".to_owned());
        let ceiling = CapabilityCeiling::new([cap.clone()]);
        let ucan_set = ceiling.to_ucan_string_set();
        // Validate-side: a UCAN capability URI for the same {resource}:{action}
        // is within the ceiling.
        let uri =
            crate::crypto::ucan::capability::CapabilityUri::new("ctx-1", "payments", "approve");
        assert!(uri.is_within_ceiling(&ucan_set));
        // Mint-side enum check agrees: the exact capability is in the ceiling.
        assert!(ceiling.contains(&cap));
    }

    #[test]
    fn ceiling_mint_and_validate_agree_on_wildcard() {
        // Explicit `{resource}:*` wildcard.
        let cap = Capability::Custom("payments:*".to_owned());
        let ceiling = CapabilityCeiling::new([cap]);
        let ucan_set = ceiling.to_ucan_string_set();
        // Validate-side: a concrete action under the wildcard resource is covered.
        let uri =
            crate::crypto::ucan::capability::CapabilityUri::new("ctx-1", "payments", "refund");
        assert!(uri.is_within_ceiling(&ucan_set));
        // A different resource is NOT covered (no resource wildcard).
        let other =
            crate::crypto::ucan::capability::CapabilityUri::new("ctx-1", "billing", "refund");
        assert!(!other.is_within_ceiling(&ucan_set));
    }

    #[test]
    fn ceiling_serialization_roundtrip() {
        let ceiling = test_ceiling();
        let json = serde_json::to_string(&ceiling).unwrap();
        let deserialized: CapabilityCeiling = serde_json::from_str(&json).unwrap();
        assert_eq!(ceiling, deserialized);
    }

    /// A well-formed custom ceiling round-trips through serialize → deserialize
    /// to the identical value — the validating `Deserialize` (via
    /// `#[serde(try_from)]`) is transparent to valid ceilings.
    #[test]
    fn ceiling_deserialize_accepts_and_roundtrips_wellformed_custom() {
        let ceiling = CapabilityCeiling::new([
            Capability::MessagesRead,
            Capability::Custom("payments:approve".to_owned()),
            Capability::Custom("billing:*".to_owned()),
            Capability::OutletCall("calc".to_owned()),
        ]);
        let json = serde_json::to_string(&ceiling).unwrap();
        let deserialized: CapabilityCeiling = serde_json::from_str(&json).unwrap();
        assert_eq!(
            ceiling, deserialized,
            "a well-formed ceiling must deserialize to an identical value"
        );
    }

    /// TYPE-LEVEL invariant: `serde_json::from_str::<CapabilityCeiling>` REJECTS a
    /// ceiling carrying a malformed entry at DESERIALIZE time — so no untrusted
    /// byte loader (import, restore, any future loader) can ever materialize a
    /// malformed ceiling. The malformed value is built via the unchecked
    /// constructor + test mutator (simulating a non-conformant peer's serialized
    /// bytes), serialized, then deserialized.
    #[test]
    fn ceiling_deserialize_rejects_malformed_entry() {
        for malformed in [
            Capability::Custom("payments".to_owned()),      // no colon
            Capability::Custom("*:*".to_owned()),           // stray wildcard resource
            Capability::Custom("a:b:c".to_owned()),         // multi-colon (3 segments)
            Capability::Custom("bad\u{7f}:cap".to_owned()), // control character
        ] {
            // `CapabilityCeiling::new` does NOT validate (validation happens at the
            // write/deserialize boundary), so this constructs the malformed value a
            // non-conformant peer could serialize.
            let bad = CapabilityCeiling::new([Capability::MessagesRead, malformed.clone()]);
            let json = serde_json::to_string(&bad).unwrap();
            let result: Result<CapabilityCeiling, _> = serde_json::from_str(&json);
            assert!(
                result.is_err(),
                "deserializing a ceiling with malformed entry {malformed:?} must fail; got {result:?}"
            );
        }
    }

    /// The TYPE-LEVEL invariant holds for `MessagePack` too, not just JSON: the
    /// signed context-export snapshot is decoded via `rmp_serde::from_slice`, so
    /// the validating `Deserialize` (`#[serde(try_from)]`) must reject a malformed
    /// ceiling in BOTH the array (`to_vec`) and named-map (`to_vec_named`)
    /// `MessagePack` encodings.
    #[test]
    fn ceiling_deserialize_rejects_malformed_entry_msgpack() {
        let bad = CapabilityCeiling::new([
            Capability::MessagesRead,
            Capability::Custom("payments".to_owned()), // no colon — malformed
        ]);

        let array_bytes = rmp_serde::to_vec(&bad).expect("serialize (array) a value");
        let array_result: Result<CapabilityCeiling, _> = rmp_serde::from_slice(&array_bytes);
        assert!(
            array_result.is_err(),
            "rmp_serde (array) must reject a malformed ceiling at deserialize"
        );

        let named_bytes = rmp_serde::to_vec_named(&bad).expect("serialize (named) a value");
        let named_result: Result<CapabilityCeiling, _> = rmp_serde::from_slice(&named_bytes);
        assert!(
            named_result.is_err(),
            "rmp_serde (named) must reject a malformed ceiling at deserialize"
        );

        // And a well-formed ceiling still round-trips through MessagePack.
        let good = CapabilityCeiling::new([
            Capability::MessagesRead,
            Capability::Custom("payments:approve".to_owned()),
        ]);
        let good_bytes = rmp_serde::to_vec_named(&good).expect("serialize a valid ceiling");
        let decoded: CapabilityCeiling =
            rmp_serde::from_slice(&good_bytes).expect("a valid ceiling round-trips via msgpack");
        assert_eq!(good, decoded);
    }

    /// The validating `Deserialize` propagates through any struct that EMBEDS a
    /// `CapabilityCeiling`: a `ContextRoleState` carrying a malformed ceiling is
    /// rejected at deserialize (covering the signed context-export snapshot, which
    /// embeds a `ContextRoleState`). No per-field re-validation is needed.
    #[test]
    fn context_role_state_deserialize_rejects_malformed_ceiling() {
        let clock = scp_clock::SystemClock;
        let mut state = ContextRoleState::new(
            "ctx-1",
            "did:scp:creator",
            CapabilityCeiling::new([Capability::MessagesRead]),
            vec![],
            &clock,
        )
        .unwrap();
        // Inject a malformed entry into the backing set via the test mutator,
        // simulating a corrupt/non-conformant serialized snapshot.
        state
            .ceiling_mut()
            .capabilities_mut()
            .insert(Capability::Custom("payments".to_owned()));
        let json = serde_json::to_string(&state).unwrap();
        let result: Result<ContextRoleState, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "deserializing a ContextRoleState with a malformed ceiling must fail; got a value"
        );

        // And a well-formed ContextRoleState still deserializes.
        let good = ContextRoleState::new(
            "ctx-1",
            "did:scp:creator",
            CapabilityCeiling::new([
                Capability::MessagesRead,
                Capability::Custom("payments:approve".to_owned()),
            ]),
            vec![],
            &clock,
        )
        .unwrap();
        let good_json = serde_json::to_string(&good).unwrap();
        let _: ContextRoleState = serde_json::from_str(&good_json)
            .expect("a well-formed ContextRoleState must deserialize");
    }

    #[test]
    fn multiple_role_assignments_tracked_independently() {
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_clock::SystemClock,
        )
        .unwrap();

        state.members.insert("did:dht:alice".to_owned());
        state.members.insert("did:dht:bob".to_owned());

        assign_role(
            &mut state,
            "did:dht:alice",
            "member",
            "did:dht:creator",
            &scp_clock::SystemClock,
        )
        .unwrap();
        assign_role(
            &mut state,
            "did:dht:bob",
            "observer",
            "did:dht:creator",
            &scp_clock::SystemClock,
        )
        .unwrap();

        // Alice is member.
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesWrite));
        // Bob is observer -- no write.
        assert!(!state.member_has_capability("did:dht:bob", &Capability::MessagesWrite));
        assert!(state.member_has_capability("did:dht:bob", &Capability::MessagesRead));
    }

    // -----------------------------------------------------------------------
    // MessagePack roundtrip -- SCP-PERSIST-001
    // -----------------------------------------------------------------------

    /// SCP-PERSIST-001: `ContextRoleState` survives `MessagePack` roundtrip.
    #[test]
    fn context_role_state_msgpack_roundtrip() {
        let ceiling = test_ceiling();
        let custom = RoleDefinition::new(
            "content-mod",
            HashSet::from([
                Capability::MessagesRead,
                Capability::MessagesWrite,
                Capability::MemberRemove,
            ]),
            &ceiling,
        )
        .unwrap();

        let mut state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![custom],
            &scp_clock::SystemClock,
        )
        .unwrap();

        // Add a second member with a non-admin role.
        state.members.insert("did:dht:alice".to_owned());
        assign_role(
            &mut state,
            "did:dht:alice",
            "content-mod",
            "did:dht:creator",
            &scp_clock::SystemClock,
        )
        .unwrap();

        // Serialize to MessagePack.
        let bytes = rmp_serde::to_vec(&state).expect("ContextRoleState serialization failed");
        assert!(!bytes.is_empty());

        // Deserialize back.
        let decoded: ContextRoleState =
            rmp_serde::from_slice(&bytes).expect("ContextRoleState deserialization failed");

        assert_eq!(state, decoded);
    }

    // -----------------------------------------------------------------------
    // validate_role_name (M3)
    // -----------------------------------------------------------------------

    #[test]
    fn validate_role_name_accepts_valid_names() {
        assert!(validate_role_name("custom-role").is_ok());
        assert!(validate_role_name("my-role-1").is_ok());
        assert!(validate_role_name("role123").is_ok());
        assert!(validate_role_name("a").is_ok());
        assert!(validate_role_name("role_with_underscores").is_ok());
    }

    #[test]
    fn validate_role_name_rejects_empty() {
        let err = validate_role_name("").unwrap_err();
        assert!(matches!(err, RoleError::InvalidRoleName(_)));
    }

    #[test]
    fn validate_role_name_rejects_too_long() {
        let long_name = "a".repeat(MAX_ROLE_NAME_LENGTH + 1);
        let err = validate_role_name(&long_name).unwrap_err();
        assert!(
            matches!(&err, RoleError::InvalidRoleName(msg) if msg.contains("maximum length")),
            "expected max length error, got: {err}"
        );
    }

    #[test]
    fn validate_role_name_rejects_reserved_names() {
        for name in &[
            "admin",
            "moderator",
            "member",
            "observer",
            "author",
            "subscriber",
        ] {
            let err = validate_role_name(name).unwrap_err();
            assert!(
                matches!(&err, RoleError::InvalidRoleName(msg) if msg.contains("reserved")),
                "expected reserved name error for '{name}', got: {err}"
            );
        }
    }

    #[test]
    fn validate_role_name_rejects_uppercase() {
        let err = validate_role_name("Admin").unwrap_err();
        assert!(matches!(err, RoleError::InvalidRoleName(_)));
    }

    #[test]
    fn validate_role_name_rejects_leading_hyphen() {
        let err = validate_role_name("-leading").unwrap_err();
        assert!(matches!(err, RoleError::InvalidRoleName(_)));
    }

    #[test]
    fn validate_role_name_rejects_trailing_underscore() {
        let err = validate_role_name("trailing_").unwrap_err();
        assert!(matches!(err, RoleError::InvalidRoleName(_)));
    }

    #[test]
    fn validate_role_name_rejects_spaces() {
        let err = validate_role_name("has space").unwrap_err();
        assert!(matches!(err, RoleError::InvalidRoleName(_)));
    }

    #[test]
    fn role_definition_new_validates_name() {
        let ceiling = test_ceiling();
        let caps = HashSet::from([Capability::MessagesRead]);
        let err = RoleDefinition::new("admin", caps, &ceiling).unwrap_err();
        assert!(
            matches!(&err, RoleError::InvalidRoleName(msg) if msg.contains("reserved")),
            "expected reserved name error, got: {err}"
        );
    }

    #[test]
    fn context_role_state_rejects_reserved_custom_role() {
        let ceiling = test_ceiling();
        let custom =
            RoleDefinition::new_unchecked("member", HashSet::from([Capability::MessagesRead]));
        let err = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![custom],
            &scp_clock::SystemClock,
        )
        .unwrap_err();
        assert!(
            matches!(&err, RoleError::InvalidRoleName(msg) if msg.contains("reserved")),
            "expected reserved name error, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // ucan_resource_action (#1293)
    // -----------------------------------------------------------------------

    #[test]
    fn ucan_resource_action_outlet_call_all() {
        let (resource, action) = Capability::OutletCallAll.ucan_resource_action();
        assert_eq!(resource.as_ref(), "outlet_call");
        assert_eq!(action.as_ref(), "*");

        let (resource, action) = Capability::OutletQueryAll.ucan_resource_action();
        assert_eq!(resource.as_ref(), "outlet_query");
        assert_eq!(action.as_ref(), "*");
    }

    #[test]
    fn ucan_resource_action_outlet_call_specific() {
        let cap = Capability::OutletCall("calculator".to_owned());
        let (resource, action) = cap.ucan_resource_action();
        assert_eq!(resource.as_ref(), "outlet_call");
        assert_eq!(action.as_ref(), "calculator");

        let cap = Capability::OutletQuery("calculator".to_owned());
        let (resource, action) = cap.ucan_resource_action();
        assert_eq!(resource.as_ref(), "outlet_query");
        assert_eq!(action.as_ref(), "calculator");
    }

    #[test]
    fn ucan_resource_action_messages() {
        let (resource, action) = Capability::MessagesRead.ucan_resource_action();
        assert_eq!(resource.as_ref(), "messages");
        assert_eq!(action.as_ref(), "read");

        let (resource, action) = Capability::MessagesWrite.ucan_resource_action();
        assert_eq!(resource.as_ref(), "messages");
        assert_eq!(action.as_ref(), "write");
    }

    #[test]
    fn ucan_resource_action_context_close() {
        let (resource, action) = Capability::ContextClose.ucan_resource_action();
        assert_eq!(resource.as_ref(), "context");
        assert_eq!(action.as_ref(), "close");
    }

    #[test]
    fn ucan_resource_action_child_context_create() {
        let (resource, action) = Capability::ChildContextCreate.ucan_resource_action();
        assert_eq!(resource.as_ref(), "context_child");
        assert_eq!(action.as_ref(), "create");
    }

    #[test]
    fn ucan_resource_action_role_assign() {
        let (resource, action) = Capability::RoleAssign.ucan_resource_action();
        assert_eq!(resource.as_ref(), "role");
        assert_eq!(action.as_ref(), "assign");
    }

    #[test]
    fn ucan_resource_action_bridging() {
        let (resource, action) = Capability::Bridging.ucan_resource_action();
        assert_eq!(resource.as_ref(), "bridging");
        assert_eq!(action.as_ref(), "*");
    }

    #[test]
    fn ucan_resource_action_from_name_string() {
        // Parsing from the canonical colon name produces the correct UCAN pair.
        let cap = Capability::new("outlet:call:*").expect("valid wildcard");
        let (resource, action) = cap.ucan_resource_action();
        assert_eq!(resource.as_ref(), "outlet_call");
        assert_eq!(action.as_ref(), "*");
    }

    #[test]
    fn ucan_resource_action_outlet_call_specific_from_name() {
        let cap = Capability::new("outlet:call:calculator").expect("valid call");
        let (resource, action) = cap.ucan_resource_action();
        assert_eq!(resource.as_ref(), "outlet_call");
        assert_eq!(action.as_ref(), "calculator");
    }

    #[test]
    fn ucan_capability_name_format() {
        assert_eq!(
            Capability::OutletCallAll.ucan_capability_name(),
            "outlet_call:*"
        );
        assert_eq!(
            Capability::OutletQueryAll.ucan_capability_name(),
            "outlet_query:*"
        );
        assert_eq!(
            Capability::MessagesWrite.ucan_capability_name(),
            "messages:write"
        );
        assert_eq!(
            Capability::ChildContextCreate.ucan_capability_name(),
            "context_child:create"
        );
        assert_eq!(
            Capability::OutletCall("calc".to_owned()).ucan_capability_name(),
            "outlet_call:calc"
        );
        assert_eq!(Capability::Bridging.ucan_capability_name(), "bridging:*");
        assert_eq!(
            Capability::OutletRegister.ucan_capability_name(),
            "outlet:register"
        );
    }

    #[test]
    fn ucan_resource_action_custom_with_colons() {
        let cap = Capability::Custom("some:nested:name".to_owned());
        let (resource, action) = cap.ucan_resource_action();
        assert_eq!(resource.as_ref(), "some_nested");
        assert_eq!(action.as_ref(), "name");
    }

    #[test]
    fn ucan_resource_action_custom_no_colons_does_not_widen_to_wildcard() {
        // Regression: a no-colon custom MUST NOT be silently widened to
        // `{name}:*` (spec §5.3.1.1 — "no implicit or silent wildcard"). Such an
        // entry is rejected at context creation (see
        // `ceiling_entry_rejects_single_token_custom`); the residual
        // `ucan_resource_action` fallback maps it to the concrete, non-wildcard
        // `name:name` so even a directly-constructed no-colon custom can never
        // grant `name:*`.
        let cap = Capability::Custom("single".to_owned());
        let (resource, action) = cap.ucan_resource_action();
        assert_eq!(resource.as_ref(), "single");
        assert_ne!(
            action.as_ref(),
            "*",
            "no-colon custom must not widen to '*'"
        );
        assert_eq!(action.as_ref(), "single");
    }

    #[test]
    fn ucan_resource_action_custom_simple_colon() {
        let cap = Capability::Custom("foo:bar".to_owned());
        let (resource, action) = cap.ucan_resource_action();
        assert_eq!(resource.as_ref(), "foo");
        assert_eq!(action.as_ref(), "bar");
    }

    #[test]
    fn ucan_resource_action_all_standard_variants() {
        // Every standard variant must produce a non-empty resource and action.
        let caps = vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::OutletCall("test".to_owned()),
            Capability::OutletCallAll,
            Capability::OutletRegister,
            Capability::MemberInvite,
            Capability::MemberRemove,
            Capability::RoleAssign,
            Capability::GovernancePropose,
            Capability::GovernanceVote,
            Capability::ContextClose,
            Capability::ChildContextCreate,
            Capability::OutletInterface,
            Capability::Bridging,
            Capability::MediaVoice,
            Capability::MediaVideo,
            Capability::MediaScreenShare,
            Capability::MemberBan,
            Capability::MetadataEdit,
        ];
        for cap in &caps {
            let (resource, action) = cap.ucan_resource_action();
            assert!(!resource.is_empty(), "empty resource for {cap:?}");
            assert!(!action.is_empty(), "empty action for {cap:?}");
            // Resource must not contain colons (UCAN uses underscores).
            assert!(
                !resource.contains(':'),
                "resource for {cap:?} contains colon: {resource}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Regression tests — consequence enforcement is per-context opt-in and
    // app-level only (spec §7.3.7). A `SuspendAll` consequence MUST NOT
    // remove the target from the context membership set (that would be an
    // `RemoveMember` governance action, O(N), MLS-level) and MUST block every
    // capability including governance participation. These tests pin that
    // contract so a future refactor cannot accidentally escalate a
    // consequence-tier suspension into a membership-destroying action.
    // -----------------------------------------------------------------------

    /// `suspend_all` MUST NOT remove the member from
    /// `ContextRoleState.members` or clear their granted
    /// `member_capabilities`. The suspension is an overlay in
    /// `suspended_capabilities`; the underlying role state is intact and
    /// can be reversed by `restore_capabilities`. This is the protocol-
    /// level analogue of "MLS membership preserved" at the spec layer
    /// (§7.3.7, §5.9) — the crypto provider's MLS group is never touched
    /// by a consequence path.
    #[test]
    fn consequence_suspend_all_preserves_membership_and_roles() {
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-suspend-membership",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_clock::SystemClock,
        )
        .unwrap();

        // Add alice and give her the member role so she has concrete
        // capabilities to suspend.
        state.members.insert("did:dht:alice".to_owned());
        let _ = assign_role(
            &mut state,
            "did:dht:alice",
            "member",
            "did:dht:creator",
            &scp_clock::SystemClock,
        )
        .expect("creator can assign member role");

        // Sanity — alice is a member and has role-granted caps before suspension.
        assert!(state.members.contains("did:dht:alice"));
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesWrite));
        let pre_caps = state
            .member_capabilities
            .get("did:dht:alice")
            .cloned()
            .expect("alice has role-granted capability set");

        // Apply the consequence.
        state.suspend_all("did:dht:alice");

        // Membership set: UNCHANGED. A consequence does not destroy
        // membership.
        assert!(
            state.members.contains("did:dht:alice"),
            "consequence SuspendAll must not remove the subject from members; \
             that is a RemoveMember governance action"
        );

        // Role-granted capability set: UNCHANGED. Suspension is an overlay
        // in `suspended_capabilities`, not a role mutation — so the
        // underlying capability set survives and `restore_capabilities`
        // can reverse it.
        assert_eq!(
            state.member_capabilities.get("did:dht:alice"),
            Some(&pre_caps),
            "consequence SuspendAll must not purge the member's role-granted \
             capabilities — it overlays suspensions, not mutates roles"
        );

        // Every capability alice was granted via her role is now gated by
        // the suspension check.
        for cap in &pre_caps {
            assert!(
                !state.member_has_capability("did:dht:alice", cap),
                "capability {cap:?} should be blocked after SuspendAll"
            );
        }
    }

    /// `suspend_all` MUST block governance participation capabilities
    /// (`GovernancePropose`, `GovernanceVote`) so a suspended member
    /// cannot submit proposals or vote. This pins the §7.3.7 contract
    /// that `SuspendAll` is a full app-level gate block — not just
    /// messaging, but every capability the member holds.
    #[test]
    fn consequence_suspend_all_blocks_governance_participation() {
        let ceiling = CapabilityCeiling {
            capabilities: std::collections::HashSet::from([
                Capability::MessagesRead,
                Capability::MessagesWrite,
                Capability::GovernancePropose,
                Capability::GovernanceVote,
            ]),
        };
        let mut state = ContextRoleState::new(
            "ctx-governance-suspension",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_clock::SystemClock,
        )
        .unwrap();

        // Creator is admin and has the full ceiling. Precondition: the
        // creator can propose and vote.
        assert!(state.member_has_capability("did:dht:creator", &Capability::GovernancePropose));
        assert!(state.member_has_capability("did:dht:creator", &Capability::GovernanceVote));
        assert!(state.member_has_capability("did:dht:creator", &Capability::MessagesWrite));

        // Apply the consequence against the creator (standing in for a
        // policy-violating participant).
        state.suspend_all("did:dht:creator");

        // Governance participation is blocked.
        assert!(
            !state.member_has_capability("did:dht:creator", &Capability::GovernancePropose),
            "SuspendAll must block governance:propose — suspended members cannot submit proposals"
        );
        assert!(
            !state.member_has_capability("did:dht:creator", &Capability::GovernanceVote),
            "SuspendAll must block governance:vote — suspended members cannot vote"
        );
        // And messaging is also blocked, for completeness.
        assert!(
            !state.member_has_capability("did:dht:creator", &Capability::MessagesWrite),
            "SuspendAll must block messages:write"
        );
        // But the subject is still a context member (spec §7.3.7: app-level
        // consequence, not a membership action).
        assert!(
            state.members.contains("did:dht:creator"),
            "SuspendAll must preserve membership — that's what RemoveMember is for"
        );
    }

    // -----------------------------------------------------------------------
    // remove_member (spec §5.6.1 clean teardown)
    // -----------------------------------------------------------------------

    #[test]
    fn remove_member_clears_all_per_did_role_state() {
        // Spec §5.6.1: removing a member drops members, assignments,
        // member_capabilities, AND suspended_capabilities for that DID.
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_clock::SystemClock,
        )
        .unwrap();

        state.members.insert("did:dht:alice".to_owned());
        state
            .system_assign_role("did:dht:alice", "member", &scp_clock::SystemClock)
            .unwrap();
        // Suspend a capability the role grants, so a dangling suspension is
        // possible if removal does not clear it.
        state.suspend_capabilities("did:dht:alice", [Capability::MessagesWrite]);

        // Preconditions: present in all four maps.
        assert!(state.members.contains("did:dht:alice"));
        assert!(state.assignments.contains_key("did:dht:alice"));
        assert!(state.member_capabilities.contains_key("did:dht:alice"));
        assert!(state.suspended_for("did:dht:alice").is_some());

        let was_member = state.remove_member("did:dht:alice");
        assert!(
            was_member,
            "remove_member returns true for a present member"
        );

        // Postconditions: absent from ALL four maps, including the
        // pub(crate) suspended_capabilities (the dangling-suspension fix).
        assert!(!state.members.contains("did:dht:alice"));
        assert!(!state.assignments.contains_key("did:dht:alice"));
        assert!(!state.member_capabilities.contains_key("did:dht:alice"));
        assert!(
            state.suspended_for("did:dht:alice").is_none(),
            "remove_member MUST clear the suspended_capabilities entry (spec §5.6.1)"
        );
    }

    #[test]
    fn remove_member_returns_was_present() {
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_clock::SystemClock,
        )
        .unwrap();

        state.members.insert("did:dht:alice".to_owned());

        // Present -> true.
        assert!(state.remove_member("did:dht:alice"));
        // Idempotent no-op when absent -> false.
        assert!(!state.remove_member("did:dht:alice"));
        // Never-present DID -> false.
        assert!(!state.remove_member("did:dht:nobody"));
    }

    #[test]
    fn remove_then_readmit_same_did_has_no_stale_suspension() {
        // Core regression (spec §5.6.1): a re-admitted same-DID member is a fresh
        // admission and MUST NOT inherit a phantom suspension from a prior tenure.
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_clock::SystemClock,
        )
        .unwrap();

        // First tenure: join, get the member role, then suspend a granted cap.
        state.members.insert("did:dht:alice".to_owned());
        state
            .system_assign_role("did:dht:alice", "member", &scp_clock::SystemClock)
            .unwrap();
        state.suspend_capabilities("did:dht:alice", [Capability::MessagesWrite]);
        assert!(
            !state.member_has_capability("did:dht:alice", &Capability::MessagesWrite),
            "suspension denies the capability during the first tenure"
        );

        // Remove.
        assert!(state.remove_member("did:dht:alice"));

        // Re-admit the SAME DID with the SAME role.
        state.members.insert("did:dht:alice".to_owned());
        state
            .system_assign_role("did:dht:alice", "member", &scp_clock::SystemClock)
            .unwrap();

        // The re-admitted member holds the capability their new role grants —
        // no phantom suspension survived the removal.
        assert!(
            state.member_has_capability("did:dht:alice", &Capability::MessagesWrite),
            "re-admitted same-DID member MUST NOT inherit a phantom suspension (spec §5.6.1)"
        );
    }

    // -----------------------------------------------------------------------
    // SCP-OUT-014 — split outlet stems, strict §5.4.2.1 parser, attenuation
    // -----------------------------------------------------------------------

    #[test]
    fn out014_capability_new_returns_some_for_outlet_query_id() {
        // Capability::new("outlet:query:{outlet_id}") returns Some(OutletQuery(..)).
        assert_eq!(
            Capability::new("outlet:query:my-outlet"),
            Some(Capability::OutletQuery("my-outlet".to_owned()))
        );
        assert_eq!(
            Capability::new("outlet:query:lookup_users"),
            Some(Capability::OutletQuery("lookup_users".to_owned()))
        );
    }

    #[test]
    fn out014_capability_new_returns_some_for_outlet_call_id() {
        // Capability::new("outlet:call:{outlet_id}") returns Some(OutletCall(..)).
        assert_eq!(
            Capability::new("outlet:call:send_payment"),
            Some(Capability::OutletCall("send_payment".to_owned()))
        );
    }

    #[test]
    fn out014_capability_new_wildcards_round_trip_both_forms() {
        // Capability::new("outlet:query:*") / "outlet:call:*" return the wildcard
        // variants. Both wire (`outlet_query:*`) and SDK (`outlet:query:*`) forms
        // are accepted.
        assert_eq!(
            Capability::new("outlet:query:*"),
            Some(Capability::OutletQueryAll)
        );
        assert_eq!(
            Capability::new("outlet_query:*"),
            Some(Capability::OutletQueryAll)
        );
        assert_eq!(
            Capability::new("outlet:call:*"),
            Some(Capability::OutletCallAll)
        );
        assert_eq!(
            Capability::new("outlet_call:*"),
            Some(Capability::OutletCallAll)
        );
    }

    #[test]
    fn out014_capability_new_returns_none_for_outlet_invoke_hard_break() {
        // Capability::new("outlet:invoke:{outlet_id}") returns None (hard break,
        // ADR-049 §1 / SCP-OUT-014 — no transitional alias).
        assert_eq!(Capability::new("outlet:invoke:foo"), None);
        assert_eq!(Capability::new("outlet:invoke:*"), None);
        assert_eq!(Capability::new("outlet_invoke:foo"), None);
        assert_eq!(Capability::new("outlet_invoke:*"), None);
    }

    #[test]
    fn out014_capability_new_returns_none_for_pre_rename_tool_forms() {
        // The pre-rename `tool:*` legacy forms are removed with no transitional
        // alias (SCP-OUT-002 / SCP-OUT-014).
        assert_eq!(Capability::new("tool:invoke:foo"), None);
        assert_eq!(Capability::new("tool:invoke:*"), None);
        assert_eq!(Capability::new("tool_invoke:foo"), None);
        assert_eq!(Capability::new("tool_invoke:*"), None);
        assert_eq!(Capability::new("tool:register"), None);
        assert_eq!(Capability::new("tool:interface"), None);
    }

    #[test]
    fn out014_capability_new_returns_none_for_inner_colon_in_suffix() {
        // A colon inside the outlet_id (an extra segment) is a parser-differential
        // rejection, NOT a Custom fallback.
        assert_eq!(Capability::new("outlet_query:call:foo"), None);
        assert_eq!(Capability::new("outlet:query:call:foo"), None);
        assert_eq!(Capability::new("outlet_call:invoke:bar"), None);
        assert_eq!(Capability::new("outlet:call:do:something"), None);
    }

    #[test]
    fn out014_capability_new_returns_none_for_empty_suffix() {
        assert_eq!(Capability::new("outlet_query:"), None);
        assert_eq!(Capability::new("outlet:query:"), None);
        assert_eq!(Capability::new("outlet_call:"), None);
        assert_eq!(Capability::new("outlet:call:"), None);
    }

    #[test]
    fn out014_capability_new_returns_none_for_uppercase_suffix() {
        assert_eq!(Capability::new("outlet_query:FOO"), None);
        assert_eq!(Capability::new("outlet:call:Bar"), None);
        assert_eq!(Capability::new("outlet_call:abcDEF"), None);
    }

    #[test]
    fn out014_capability_new_returns_none_for_oversized_suffix() {
        // A 129-char suffix returns None; 128 chars (the bound) MUST parse.
        let oversized: String = "a".repeat(129);
        let input = format!("outlet_query:{oversized}");
        assert_eq!(Capability::new(&input), None);
        let max: String = "a".repeat(128);
        let ok = format!("outlet_query:{max}");
        assert_eq!(Capability::new(&ok), Some(Capability::OutletQuery(max)));
    }

    #[test]
    fn out014_capability_new_rejects_non_ascii_and_punctuation() {
        // Defense-in-depth: characters outside [a-z0-9_-] reject.
        assert_eq!(Capability::new("outlet_query:hello world"), None);
        assert_eq!(Capability::new("outlet_call:foo.bar"), None);
        assert_eq!(Capability::new("outlet_query:foo/bar"), None);
        assert_eq!(Capability::new("outlet_query:foo+bar"), None);
        assert_eq!(Capability::new("outlet_query:héllo"), None); // non-ASCII
    }

    #[test]
    fn out014_ucan_wire_form_uses_underscore() {
        // UCAN wire form is `outlet_query:{id}` / `outlet_call:{id}`.
        let cap = Capability::OutletQuery("calc".to_owned());
        let (resource, action) = cap.ucan_resource_action();
        assert_eq!(resource.as_ref(), "outlet_query");
        assert_eq!(action.as_ref(), "calc");
        assert_eq!(cap.ucan_capability_name(), "outlet_query:calc");

        let cap2 = Capability::OutletCall("send".to_owned());
        assert_eq!(cap2.ucan_capability_name(), "outlet_call:send");
    }

    #[test]
    fn out014_sdk_form_uses_colon() {
        // SDK-facing display form is `outlet:query:{id}` / `outlet:call:{id}`.
        let cap = Capability::OutletQuery("calc".to_owned());
        assert_eq!(cap.name().as_ref(), "outlet:query:calc");
        assert_eq!(format!("{cap}"), "outlet:query:calc");

        let cap2 = Capability::OutletCall("send".to_owned());
        assert_eq!(cap2.name().as_ref(), "outlet:call:send");
    }

    #[test]
    fn out014_round_trip_capability_new_to_display() {
        // The SDK-facing colon form round-trips through Display.
        let originals = [
            Capability::OutletQuery("my-outlet".to_owned()),
            Capability::OutletQueryAll,
            Capability::OutletCall("send_log".to_owned()),
            Capability::OutletCallAll,
        ];
        for cap in &originals {
            let displayed = cap.to_string();
            let reparsed = Capability::new(&displayed);
            assert_eq!(
                reparsed.as_ref(),
                Some(cap),
                "round-trip failed for {cap:?}"
            );
        }
    }

    #[test]
    fn out014_round_trip_wire_form_through_new() {
        // The wire form `outlet_query:{id}` must also round-trip through new().
        let pairs = [
            (
                "outlet_query:my-outlet",
                Capability::OutletQuery("my-outlet".to_owned()),
            ),
            ("outlet_query:*", Capability::OutletQueryAll),
            (
                "outlet_call:send_payment",
                Capability::OutletCall("send_payment".to_owned()),
            ),
            ("outlet_call:*", Capability::OutletCallAll),
        ];
        for (wire, expected) in &pairs {
            let parsed = Capability::new(wire);
            assert_eq!(
                parsed.as_ref(),
                Some(expected),
                "wire form {wire:?} did not parse to {expected:?}"
            );
        }
    }

    #[test]
    fn out014_attenuation_query_all_to_query_specific_is_valid() {
        // parent(OutletQueryAll) → child(OutletQuery(x)) is valid.
        // CapabilityCeiling::contains is the protocol-level subset check.
        let ceiling = CapabilityCeiling::new([Capability::OutletQueryAll]);
        assert!(ceiling.contains(&Capability::OutletQuery("any-outlet".to_owned())));
        assert!(ceiling.contains(&Capability::OutletQuery("other".to_owned())));
        assert!(ceiling.contains(&Capability::OutletQueryAll));
    }

    #[test]
    fn out014_attenuation_query_all_does_not_grant_call() {
        // parent(OutletQueryAll) → child(OutletCall(x)) is REJECTED (cross-class).
        let ceiling = CapabilityCeiling::new([Capability::OutletQueryAll]);
        assert!(!ceiling.contains(&Capability::OutletCall("any-outlet".to_owned())));
        assert!(!ceiling.contains(&Capability::OutletCallAll));
    }

    #[test]
    fn out014_attenuation_call_all_does_not_grant_query() {
        // Mirror: parent(OutletCallAll) → child(OutletQuery(x)) is REJECTED.
        let ceiling = CapabilityCeiling::new([Capability::OutletCallAll]);
        assert!(!ceiling.contains(&Capability::OutletQuery("any-outlet".to_owned())));
        assert!(!ceiling.contains(&Capability::OutletQueryAll));
    }

    #[test]
    fn out014_capability_uri_matches_rejects_cross_class() {
        // The UCAN-layer attenuation check (CapabilityUri::matches) MUST reject
        // cross-class because the resource strings differ.
        use crate::crypto::ucan::capability::CapabilityUri;
        let parent_query_all = CapabilityUri::new("ctx-1", "outlet_query", "*");
        let child_call_specific = CapabilityUri::new("ctx-1", "outlet_call", "outlet");
        assert!(
            !parent_query_all.matches(&child_call_specific),
            "outlet_query:* must NOT match outlet_call:outlet — cross-class attenuation"
        );

        let parent_call_all = CapabilityUri::new("ctx-1", "outlet_call", "*");
        let child_query_specific = CapabilityUri::new("ctx-1", "outlet_query", "outlet");
        assert!(
            !parent_call_all.matches(&child_query_specific),
            "outlet_call:* must NOT match outlet_query:outlet — cross-class attenuation"
        );

        // Same-class attenuation MUST succeed.
        let parent_query_all = CapabilityUri::new("ctx-1", "outlet_query", "*");
        let child_query_specific = CapabilityUri::new("ctx-1", "outlet_query", "outlet");
        assert!(
            parent_query_all.matches(&child_query_specific),
            "outlet_query:* MUST match outlet_query:outlet — same-class wildcard"
        );
    }

    #[test]
    fn out014_no_outlet_invoke_variant_remains() {
        // The Capability enum does NOT have variants OutletInvoke / OutletInvokeAll.
        // Enforced statically by the enum definition; also verified by construction
        // that the deleted forms cannot be produced by the parser.
        for input in [
            "outlet:invoke:*",
            "outlet:invoke:any",
            "outlet_invoke:*",
            "outlet_invoke:any",
        ] {
            assert_eq!(
                Capability::new(input),
                None,
                "deleted stem {input:?} must not parse"
            );
        }
    }

    #[test]
    fn out014_role_defaults_double_grant_query_and_call() {
        // A query-capable role can BOTH query and call: member / moderator /
        // author role defaults grant both `OutletQueryAll` AND `OutletCallAll`
        // when the ceiling permits them.
        let ceiling = CapabilityCeiling::new([
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::OutletQueryAll,
            Capability::OutletCallAll,
            Capability::MemberRemove,
            Capability::GovernancePropose,
        ]);
        for role in [
            builtin_member(&ceiling),
            builtin_moderator(&ceiling),
            builtin_author(&ceiling),
        ] {
            assert!(
                role.capabilities.contains(&Capability::OutletQueryAll),
                "role {:?} must grant OutletQueryAll",
                role.name
            );
            assert!(
                role.capabilities.contains(&Capability::OutletCallAll),
                "role {:?} must grant OutletCallAll",
                role.name
            );
        }
    }
}
