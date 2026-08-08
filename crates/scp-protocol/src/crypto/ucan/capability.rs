//! Capability URI parsing, wildcard matching, and ceiling intersection for
//! SCP UCAN tokens.
//!
//! SCP capability URIs follow the format `scp:ctx:{context_id}/{capability}`,
//! where `{capability}` is `{resource}:{action}`. Wildcards are supported:
//! `scp:ctx:*/messages:write` matches any context.
//!
//! # URI Format
//!
//! ```text
//! scp:ctx:{context_id}/{resource}:{action}
//! ```
//!
//! - `context_id`: The context identifier, or `*` for wildcard (all contexts).
//! - `resource`: The resource type (e.g., `messages`, `outlet_call`, `member`,
//!   `role`, `context`).
//! - `action`: The action on the resource (e.g., `read`, `write`, `invite`,
//!   `assign`, `close`, `assistant`).
//!
//! # Examples
//!
//! ```
//! use scp_protocol::crypto::ucan::capability::CapabilityUri;
//!
//! // Parse a specific context capability
//! let uri: CapabilityUri = "scp:ctx:abc123/messages:write".parse().unwrap();
//! assert_eq!(uri.context_id(), Some("abc123"));
//! assert_eq!(uri.resource(), "messages");
//! assert_eq!(uri.action(), "write");
//!
//! // Parse a wildcard capability
//! let wildcard: CapabilityUri = "scp:ctx:*/messages:write".parse().unwrap();
//! assert!(wildcard.is_wildcard());
//! assert!(wildcard.matches_context("any-context-id"));
//! ```
//!
//! See ADR-016 acceptance criterion 9 in `.docs/adrs/phase-3.md`.

use std::collections::HashSet;
use std::fmt;
use std::hash::BuildHasher;
use std::str::FromStr;

use super::UcanError;

// ---------------------------------------------------------------------------
// CapabilityUri
// ---------------------------------------------------------------------------

/// A parsed SCP capability URI.
///
/// Parsed from the string format `scp:ctx:{context_id}/{resource}:{action}`.
/// When `context_id` is `*`, the capability applies to all contexts (wildcard).
///
/// # Parsing
///
/// Implements [`FromStr`] for parsing from string. Use `.parse()` or
/// `CapabilityUri::from_str()`.
///
/// # Matching
///
/// - [`matches_context`](CapabilityUri::matches_context): Checks if the URI
///   matches a specific context ID (wildcards match any context).
/// - [`matches`](CapabilityUri::matches): Full match against another
///   `CapabilityUri`, considering wildcards.
/// - [`is_within_ceiling`](CapabilityUri::is_within_ceiling): Checks if the
///   capability's `{resource}:{action}` is in the context's capability ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CapabilityUri {
    /// The context identifier, or `None` for wildcard (`*`).
    context_id: Option<String>,
    /// The resource type (e.g., `"messages"`, `"outlet_call"`, `"member"`).
    resource: String,
    /// The action on the resource (e.g., `"read"`, `"write"`, `"invite"`).
    action: String,
}

impl CapabilityUri {
    /// Creates a new `CapabilityUri` with a specific context ID.
    ///
    /// For wildcard URIs (all contexts), use [`CapabilityUri::wildcard`].
    #[must_use]
    pub fn new(
        context_id: impl Into<String>,
        resource: impl Into<String>,
        action: impl Into<String>,
    ) -> Self {
        Self {
            context_id: Some(context_id.into()),
            resource: resource.into(),
            action: action.into(),
        }
    }

    /// Creates a new wildcard `CapabilityUri` that matches all contexts.
    #[must_use]
    pub fn wildcard(resource: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            context_id: None,
            resource: resource.into(),
            action: action.into(),
        }
    }

    /// Returns the context ID, or `None` if this is a wildcard URI.
    #[must_use]
    pub fn context_id(&self) -> Option<&str> {
        self.context_id.as_deref()
    }

    /// Returns the resource type (e.g., `"messages"`, `"outlet_call"`).
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// Returns the action (e.g., `"read"`, `"write"`, `"invite"`).
    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }

    /// Returns `true` if this capability's resource is an outlet stem
    /// (`outlet_query` or `outlet_call`).
    ///
    /// Outlet stems are the ONLY capabilities that the §7.3.8 invocation
    /// caveats (`max_calls`, `amount_max_*`, `rate_window`, `origin_kind`,
    /// `valid_*`, `hours_of_day`, `days_of_week`, `allowed_adapters`,
    /// `allowed_target_dids`, `input_schema`) scope to: those caveats bound
    /// outlet *invocation* and are meaningless on a non-outlet capability
    /// (e.g. `messages:write`). A token whose capability set contains NO
    /// outlet stem therefore carries NO invocation caveats — its `nb` MUST be
    /// `None`. This classifier is the single shared predicate used by both the
    /// delegation mint and the per-edge validator to decide whether an edge is
    /// "outlet scoped" so the two stay symmetric (§5.4.2, SCP-OUT-014).
    #[must_use]
    pub fn is_outlet_stem(&self) -> bool {
        matches!(self.resource.as_str(), "outlet_query" | "outlet_call")
    }

    /// Returns `true` if this is a wildcard URI (`scp:ctx:*/{capability}`).
    #[must_use]
    pub const fn is_wildcard(&self) -> bool {
        self.context_id.is_none()
    }

    /// Returns the capability string in `{resource}:{action}` format.
    ///
    /// This is the format used in capability ceiling sets.
    #[must_use]
    pub fn capability_name(&self) -> String {
        format!("{}:{}", self.resource, self.action)
    }

    /// Checks if this capability URI matches a specific context ID.
    ///
    /// Wildcard URIs match any context ID. Specific URIs match only the
    /// exact context ID.
    #[must_use]
    pub fn matches_context(&self, context_id: &str) -> bool {
        self.context_id.as_ref().is_none_or(|id| id == context_id)
    }

    /// Checks if this capability URI matches another capability URI.
    ///
    /// A wildcard URI matches any URI with the same resource and action.
    /// A specific URI matches only URIs with the same context ID, resource,
    /// and action. A wildcard action (`"*"`) on the granting URI matches any
    /// action on the same resource (e.g., `outlet_call:*` grants
    /// `outlet_call:calculator`).
    ///
    /// This is used during capability matching in UCAN validation: a token's
    /// attenuation must match the required capability.
    #[must_use]
    pub fn matches(&self, required: &Self) -> bool {
        // Resource must always match exactly.
        if self.resource != required.resource {
            return false;
        }

        // Action: wildcard "*" on the granting side matches any required action.
        // Otherwise, actions must match exactly.
        if self.action != "*" && self.action != required.action {
            return false;
        }

        // Wildcard granting URI matches any required context.
        // Specific granting URI must match the required context exactly.
        match (&self.context_id, &required.context_id) {
            // Wildcard grants to any context
            (None, _) => true,
            // Specific grant matches specific requirement
            (Some(granted), Some(req)) => granted == req,
            // Specific grant cannot satisfy a wildcard requirement
            (Some(_), None) => false,
        }
    }

    /// Checks if this capability is within the context's capability ceiling.
    ///
    /// The ceiling is a set of capability names in `{resource}:{action}` format
    /// (e.g., `"messages:write"`, `"outlet_call:assistant"`). This performs a
    /// constant-time set membership test as specified by ADR-016.
    ///
    /// A wildcard entry `{resource}:*` in the ceiling covers all actions on
    /// that resource. For example, `"outlet_call:*"` in the ceiling allows
    /// `outlet_call:calculator`, `outlet_call:assistant`, etc.
    ///
    /// # Arguments
    ///
    /// * `ceiling` - The context's immutable capability ceiling, represented as
    ///   a set of capability name strings.
    #[must_use]
    pub fn is_within_ceiling<S: BuildHasher>(&self, ceiling: &HashSet<String, S>) -> bool {
        ucan_name_within_ceiling(&self.resource, &self.action, ceiling)
    }
}

/// THE ceiling-coverage relation, over a `{resource}:{action}` name pair and a
/// ceiling projected to its UCAN name set.
///
/// [`CapabilityUri::is_within_ceiling`] is this function; so is the #2028
/// genesis-ceiling-currency gate in `scp-runtime`
/// (`context::state::check_genesis_ceiling_still_current`). Coverage is decided
/// HERE, once, so an authorization decision and a gate that must agree with it
/// cannot drift.
///
/// Deciding coverage on the NAME projection rather than on
/// [`Capability`](crate::context::roles::Capability) enum-set membership is
/// load-bearing in both directions:
///
/// - a `{resource}:*` entry is a first-class specced ceiling shape (§5.3.1.1
///   shape 3) that covers every action on that resource; and
/// - several BUILT-IN variants project onto a wildcard name — `OutletQueryAll`
///   (`outlet_query:*`), `OutletCallAll` (`outlet_call:*`), `Bridging`
///   (`bridging:*`) — so a built-in in the ceiling covers a concrete `Custom`
///   entry in its family (`Custom("bridging:foo")`). Enum-set membership cannot
///   see either relationship.
///
/// The §5.3.1.1 "no built-in-resource wildcard shadow" rule
/// (`validate_custom_ceiling_entry`) is what keeps this sound: no `Custom`
/// entry whose action is `*` may name a built-in resource, so a custom wildcard
/// can never silently subsume a privileged built-in family.
#[must_use]
pub fn ucan_name_within_ceiling<S: BuildHasher>(
    resource: &str,
    action: &str,
    ceiling: &HashSet<String, S>,
) -> bool {
    // Exact match first (fast path).
    if ceiling.contains(&format!("{resource}:{action}")) {
        return true;
    }
    // Wildcard: {resource}:* covers all actions on this resource.
    ceiling.contains(&format!("{resource}:*"))
}

/// Returns `true` if ANY attestation in `att` carries an outlet stem
/// (`outlet_query:*` / `outlet_call:*`) resource.
///
/// This is the §7.3.8 "outlet-scoped" classifier for a whole capability set,
/// shared verbatim by the delegation mint and the per-edge validator so the
/// two never diverge. Invocation caveats are outlet-scoped: a token whose
/// capability set contains no outlet stem carries no invocation caveats and
/// MUST have `nb = None`. A token that DOES carry an outlet stem is on an
/// "outlet edge" and its `nb` participates in the full §7.3.8 narrowing /
/// `origin_kind`-materialization gate.
///
/// # Errors
///
/// Fail-closed: returns [`UcanError::MalformedToken`] if any attestation URI
/// is unparseable, so a corrupted/forged attestation can never be silently
/// treated as "non-outlet" (which would let it launder an ancestor's caveats).
pub fn att_set_has_outlet_stem(att: &[super::Attenuation]) -> Result<bool, UcanError> {
    for a in att {
        let uri: CapabilityUri = a.with.parse().map_err(|e: UcanError| {
            UcanError::MalformedToken(format!(
                "unparseable capability URI '{}' while classifying outlet scope: {e}",
                a.with
            ))
        })?;
        if uri.is_outlet_stem() {
            return Ok(true);
        }
    }
    Ok(false)
}

impl FromStr for CapabilityUri {
    type Err = UcanError;

    /// Parses a capability URI from the string format
    /// `scp:ctx:{context_id}/{resource}:{action}`.
    ///
    /// # Errors
    ///
    /// Returns [`UcanError::InvalidCapabilityUri`] if the string does not match
    /// the expected format.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Strip the "scp:ctx:" prefix
        let rest = s.strip_prefix("scp:ctx:").ok_or_else(|| {
            UcanError::InvalidCapabilityUri(format!("missing 'scp:ctx:' prefix in '{s}'"))
        })?;

        // Split on the first '/' to separate context_id from capability
        let (ctx_part, capability_part) = rest.split_once('/').ok_or_else(|| {
            UcanError::InvalidCapabilityUri(format!(
                "missing '/' separator between context ID and capability in '{s}'"
            ))
        })?;

        // Validate context ID is non-empty
        if ctx_part.is_empty() {
            return Err(UcanError::InvalidCapabilityUri(format!(
                "empty context ID in '{s}'"
            )));
        }

        // Parse context ID: "*" means wildcard
        let context_id = if ctx_part == "*" {
            None
        } else {
            Some(ctx_part.to_owned())
        };

        // Split capability on ':' to separate resource from action
        let (resource, action) = capability_part.split_once(':').ok_or_else(|| {
            UcanError::InvalidCapabilityUri(format!(
                "missing ':' separator between resource and action in '{s}'"
            ))
        })?;

        // Validate resource and action are non-empty
        if resource.is_empty() {
            return Err(UcanError::InvalidCapabilityUri(format!(
                "empty resource in '{s}'"
            )));
        }
        if action.is_empty() {
            return Err(UcanError::InvalidCapabilityUri(format!(
                "empty action in '{s}'"
            )));
        }

        Ok(Self {
            context_id,
            resource: resource.to_owned(),
            action: action.to_owned(),
        })
    }
}

impl fmt::Display for CapabilityUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ctx = self.context_id.as_ref().map_or("*", |id| id.as_str());
        write!(f, "scp:ctx:{ctx}/{}:{}", self.resource, self.action)
    }
}

/// Checks whether all capabilities in a list are within the context's ceiling.
///
/// This is a batch version of [`CapabilityUri::is_within_ceiling`] for
/// verifying an entire token's attestation list against the ceiling.
///
/// # Arguments
///
/// * `capabilities` - The capability URIs to check (from a token's attestations).
/// * `ceiling` - The context's immutable capability ceiling.
///
/// # Returns
///
/// `Ok(())` if all capabilities are within the ceiling, or
/// `Err(UcanError::CapabilityOutsideCeiling)` with the first offending
/// capability name.
///
/// # Errors
///
/// Returns [`UcanError::CapabilityOutsideCeiling`] if any capability is not
/// in the ceiling set.
pub fn verify_ceiling_compliance<S: BuildHasher>(
    capabilities: &[CapabilityUri],
    ceiling: &HashSet<String, S>,
) -> Result<(), UcanError> {
    for cap in capabilities {
        if !cap.is_within_ceiling(ceiling) {
            return Err(UcanError::CapabilityOutsideCeiling(cap.capability_name()));
        }
    }
    Ok(())
}

/// Checks whether a required capability is granted by any of the provided
/// attestation URIs.
///
/// Iterates through the granted capabilities and returns `Ok(())` if any
/// of them [`matches`](CapabilityUri::matches) the required capability.
///
/// # Arguments
///
/// * `granted` - The capability URIs granted by a token's attestations.
/// * `required` - The capability URI required for the current action.
///
/// # Returns
///
/// `Ok(())` if the required capability is matched by at least one granted
/// capability, or `Err(UcanError::CapabilityNotGranted)`.
///
/// # Errors
///
/// Returns [`UcanError::CapabilityNotGranted`] if no granted capability
/// matches the required one.
pub fn check_capability_match(
    granted: &[CapabilityUri],
    required: &CapabilityUri,
) -> Result<(), UcanError> {
    for cap in granted {
        if cap.matches(required) {
            return Ok(());
        }
    }
    Err(UcanError::CapabilityNotGranted(required.to_string()))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::iter_on_single_items
)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // CapabilityUri::from_str — valid URIs
    // -----------------------------------------------------------------------

    #[test]
    fn parse_specific_context_messages_write() {
        let uri: CapabilityUri = "scp:ctx:abc123/messages:write".parse().unwrap();
        assert_eq!(uri.context_id(), Some("abc123"));
        assert_eq!(uri.resource(), "messages");
        assert_eq!(uri.action(), "write");
        assert!(!uri.is_wildcard());
    }

    #[test]
    fn parse_specific_context_messages_read() {
        let uri: CapabilityUri = "scp:ctx:abc123/messages:read".parse().unwrap();
        assert_eq!(uri.context_id(), Some("abc123"));
        assert_eq!(uri.resource(), "messages");
        assert_eq!(uri.action(), "read");
    }

    #[test]
    fn parse_outlet_call_assistant() {
        let uri: CapabilityUri = "scp:ctx:abc123/outlet_call:assistant".parse().unwrap();
        assert_eq!(uri.context_id(), Some("abc123"));
        assert_eq!(uri.resource(), "outlet_call");
        assert_eq!(uri.action(), "assistant");
    }

    #[test]
    fn parse_member_invite() {
        let uri: CapabilityUri = "scp:ctx:abc123/member:invite".parse().unwrap();
        assert_eq!(uri.context_id(), Some("abc123"));
        assert_eq!(uri.resource(), "member");
        assert_eq!(uri.action(), "invite");
    }

    #[test]
    fn parse_role_assign() {
        let uri: CapabilityUri = "scp:ctx:abc123/role:assign".parse().unwrap();
        assert_eq!(uri.context_id(), Some("abc123"));
        assert_eq!(uri.resource(), "role");
        assert_eq!(uri.action(), "assign");
    }

    #[test]
    fn parse_context_close() {
        let uri: CapabilityUri = "scp:ctx:abc123/context:close".parse().unwrap();
        assert_eq!(uri.context_id(), Some("abc123"));
        assert_eq!(uri.resource(), "context");
        assert_eq!(uri.action(), "close");
    }

    #[test]
    fn parse_wildcard_context() {
        let uri: CapabilityUri = "scp:ctx:*/messages:write".parse().unwrap();
        assert!(uri.is_wildcard());
        assert_eq!(uri.context_id(), None);
        assert_eq!(uri.resource(), "messages");
        assert_eq!(uri.action(), "write");
    }

    #[test]
    fn parse_context_id_with_hyphens() {
        let uri: CapabilityUri = "scp:ctx:ctx-abc-123/messages:read".parse().unwrap();
        assert_eq!(uri.context_id(), Some("ctx-abc-123"));
    }

    #[test]
    fn parse_context_id_with_long_hash() {
        let uri: CapabilityUri = "scp:ctx:a1b2c3d4e5f6a1b2c3d4e5f6/messages:write"
            .parse()
            .unwrap();
        assert_eq!(uri.context_id(), Some("a1b2c3d4e5f6a1b2c3d4e5f6"));
    }

    // -----------------------------------------------------------------------
    // CapabilityUri::from_str — invalid URIs
    // -----------------------------------------------------------------------

    #[test]
    fn parse_rejects_missing_prefix() {
        let result: Result<CapabilityUri, _> = "abc123/messages:write".parse();
        assert!(result.is_err());
    }

    #[test]
    fn parse_rejects_wrong_prefix() {
        let result: Result<CapabilityUri, _> = "http:ctx:abc123/messages:write".parse();
        assert!(result.is_err());
    }

    #[test]
    fn parse_rejects_missing_slash() {
        let result: Result<CapabilityUri, _> = "scp:ctx:abc123messages:write".parse();
        assert!(result.is_err());
    }

    #[test]
    fn parse_rejects_missing_colon_in_capability() {
        let result: Result<CapabilityUri, _> = "scp:ctx:abc123/messageswrite".parse();
        assert!(result.is_err());
    }

    #[test]
    fn parse_rejects_empty_context_id() {
        let result: Result<CapabilityUri, _> = "scp:ctx:/messages:write".parse();
        assert!(result.is_err());
    }

    #[test]
    fn parse_rejects_empty_resource() {
        let result: Result<CapabilityUri, _> = "scp:ctx:abc123/:write".parse();
        assert!(result.is_err());
    }

    #[test]
    fn parse_rejects_empty_action() {
        let result: Result<CapabilityUri, _> = "scp:ctx:abc123/messages:".parse();
        assert!(result.is_err());
    }

    #[test]
    fn parse_rejects_empty_string() {
        let result: Result<CapabilityUri, _> = "".parse();
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Display
    // -----------------------------------------------------------------------

    #[test]
    fn display_specific_context() {
        let uri = CapabilityUri::new("abc123", "messages", "write");
        assert_eq!(uri.to_string(), "scp:ctx:abc123/messages:write");
    }

    #[test]
    fn display_wildcard_context() {
        let uri = CapabilityUri::wildcard("messages", "write");
        assert_eq!(uri.to_string(), "scp:ctx:*/messages:write");
    }

    #[test]
    fn parse_display_roundtrip() {
        let uris = [
            "scp:ctx:abc123/messages:write",
            "scp:ctx:abc123/messages:read",
            "scp:ctx:abc123/outlet_call:assistant",
            "scp:ctx:abc123/member:invite",
            "scp:ctx:abc123/role:assign",
            "scp:ctx:abc123/context:close",
            "scp:ctx:*/messages:write",
        ];
        for uri_str in &uris {
            let parsed: CapabilityUri = uri_str.parse().unwrap();
            assert_eq!(&parsed.to_string(), uri_str);
        }
    }

    // -----------------------------------------------------------------------
    // capability_name
    // -----------------------------------------------------------------------

    #[test]
    fn capability_name_format() {
        let uri = CapabilityUri::new("abc123", "messages", "write");
        assert_eq!(uri.capability_name(), "messages:write");
    }

    #[test]
    fn capability_name_same_for_wildcard_and_specific() {
        let specific = CapabilityUri::new("abc123", "messages", "write");
        let wildcard = CapabilityUri::wildcard("messages", "write");
        assert_eq!(specific.capability_name(), wildcard.capability_name());
    }

    // -----------------------------------------------------------------------
    // matches_context
    // -----------------------------------------------------------------------

    #[test]
    fn matches_context_specific_matches_same() {
        let uri = CapabilityUri::new("abc123", "messages", "write");
        assert!(uri.matches_context("abc123"));
    }

    #[test]
    fn matches_context_specific_does_not_match_different() {
        let uri = CapabilityUri::new("abc123", "messages", "write");
        assert!(!uri.matches_context("def456"));
    }

    #[test]
    fn matches_context_wildcard_matches_any() {
        let uri = CapabilityUri::wildcard("messages", "write");
        assert!(uri.matches_context("abc123"));
        assert!(uri.matches_context("def456"));
        assert!(uri.matches_context("any-context-id"));
    }

    // -----------------------------------------------------------------------
    // matches (full capability matching)
    // -----------------------------------------------------------------------

    #[test]
    fn matches_exact_same_uri() {
        let granted = CapabilityUri::new("abc123", "messages", "write");
        let required = CapabilityUri::new("abc123", "messages", "write");
        assert!(granted.matches(&required));
    }

    #[test]
    fn matches_wildcard_grants_specific() {
        let granted = CapabilityUri::wildcard("messages", "write");
        let required = CapabilityUri::new("abc123", "messages", "write");
        assert!(granted.matches(&required));
    }

    #[test]
    fn matches_wildcard_grants_any_context() {
        let granted = CapabilityUri::wildcard("messages", "write");
        let required_1 = CapabilityUri::new("ctx-1", "messages", "write");
        let required_2 = CapabilityUri::new("ctx-2", "messages", "write");
        assert!(granted.matches(&required_1));
        assert!(granted.matches(&required_2));
    }

    #[test]
    fn matches_specific_does_not_satisfy_wildcard_requirement() {
        let granted = CapabilityUri::new("abc123", "messages", "write");
        let required = CapabilityUri::wildcard("messages", "write");
        assert!(!granted.matches(&required));
    }

    #[test]
    fn matches_different_resource_fails() {
        let granted = CapabilityUri::new("abc123", "messages", "write");
        let required = CapabilityUri::new("abc123", "member", "write");
        assert!(!granted.matches(&required));
    }

    #[test]
    fn matches_different_action_fails() {
        let granted = CapabilityUri::new("abc123", "messages", "write");
        let required = CapabilityUri::new("abc123", "messages", "read");
        assert!(!granted.matches(&required));
    }

    #[test]
    fn matches_different_context_fails() {
        let granted = CapabilityUri::new("abc123", "messages", "write");
        let required = CapabilityUri::new("def456", "messages", "write");
        assert!(!granted.matches(&required));
    }

    #[test]
    fn matches_wildcard_action_grants_specific_action() {
        // outlet_call:* grants outlet_call:calculator (#1326)
        let granted = CapabilityUri::new("abc123", "outlet_call", "*");
        let required = CapabilityUri::new("abc123", "outlet_call", "calculator");
        assert!(granted.matches(&required));
    }

    #[test]
    fn matches_wildcard_action_grants_any_action_on_same_resource() {
        let granted = CapabilityUri::new("abc123", "outlet_call", "*");
        let required_a = CapabilityUri::new("abc123", "outlet_call", "assistant");
        let required_b = CapabilityUri::new("abc123", "outlet_call", "calculator");
        assert!(granted.matches(&required_a));
        assert!(granted.matches(&required_b));
    }

    #[test]
    fn matches_wildcard_action_does_not_cross_resources() {
        let granted = CapabilityUri::new("abc123", "outlet_call", "*");
        let required = CapabilityUri::new("abc123", "messages", "write");
        assert!(!granted.matches(&required));
    }

    #[test]
    fn matches_wildcard_action_with_wildcard_context() {
        let granted = CapabilityUri::wildcard("outlet_call", "*");
        let required = CapabilityUri::new("any-ctx", "outlet_call", "calculator");
        assert!(granted.matches(&required));
    }

    #[test]
    fn matches_specific_action_does_not_satisfy_wildcard_action_requirement() {
        // A specific grant cannot satisfy a wildcard action requirement.
        let granted = CapabilityUri::new("abc123", "outlet_call", "calculator");
        let required = CapabilityUri::new("abc123", "outlet_call", "*");
        assert!(!granted.matches(&required));
    }

    // -----------------------------------------------------------------------
    // is_within_ceiling
    // -----------------------------------------------------------------------

    #[test]
    fn is_within_ceiling_when_present() {
        let ceiling: HashSet<String> = [
            "messages:read".to_owned(),
            "messages:write".to_owned(),
            "outlet_call:assistant".to_owned(),
        ]
        .into_iter()
        .collect();

        let uri = CapabilityUri::new("abc123", "messages", "write");
        assert!(uri.is_within_ceiling(&ceiling));
    }

    #[test]
    fn is_within_ceiling_when_absent() {
        let ceiling: HashSet<String> = ["messages:read".to_owned(), "messages:write".to_owned()]
            .into_iter()
            .collect();

        let uri = CapabilityUri::new("abc123", "role", "assign");
        assert!(!uri.is_within_ceiling(&ceiling));
    }

    #[test]
    fn is_within_ceiling_wildcard_checked_by_capability_name() {
        let ceiling: HashSet<String> = ["messages:write".to_owned()].into_iter().collect();

        // Wildcard URI checks by capability name, not full URI
        let uri = CapabilityUri::wildcard("messages", "write");
        assert!(uri.is_within_ceiling(&ceiling));
    }

    #[test]
    fn is_within_ceiling_empty_ceiling() {
        let ceiling: HashSet<String> = HashSet::new();
        let uri = CapabilityUri::new("abc123", "messages", "write");
        assert!(!uri.is_within_ceiling(&ceiling));
    }

    #[test]
    fn is_within_ceiling_wildcard_action_covers_specific() {
        // "outlet_call:*" in ceiling allows outlet_call:calculator (#1326)
        let ceiling: HashSet<String> = ["outlet_call:*".to_owned()].into_iter().collect();
        let uri = CapabilityUri::new("abc123", "outlet_call", "calculator");
        assert!(uri.is_within_ceiling(&ceiling));
    }

    #[test]
    fn is_within_ceiling_wildcard_action_does_not_cross_resources() {
        let ceiling: HashSet<String> = ["outlet_call:*".to_owned()].into_iter().collect();
        let uri = CapabilityUri::new("abc123", "messages", "write");
        assert!(!uri.is_within_ceiling(&ceiling));
    }

    #[test]
    fn is_within_ceiling_exact_match_preferred_over_wildcard() {
        // Both exact and wildcard are present — exact match takes the fast path.
        let ceiling: HashSet<String> = [
            "outlet_call:calculator".to_owned(),
            "outlet_call:*".to_owned(),
        ]
        .into_iter()
        .collect();
        let uri = CapabilityUri::new("abc123", "outlet_call", "calculator");
        assert!(uri.is_within_ceiling(&ceiling));
    }

    // -----------------------------------------------------------------------
    // verify_ceiling_compliance
    // -----------------------------------------------------------------------

    #[test]
    fn verify_ceiling_compliance_all_within() {
        let ceiling: HashSet<String> = [
            "messages:read".to_owned(),
            "messages:write".to_owned(),
            "outlet_call:assistant".to_owned(),
        ]
        .into_iter()
        .collect();

        let capabilities = vec![
            CapabilityUri::new("abc123", "messages", "read"),
            CapabilityUri::new("abc123", "messages", "write"),
        ];

        assert!(verify_ceiling_compliance(&capabilities, &ceiling).is_ok());
    }

    #[test]
    fn verify_ceiling_compliance_one_outside() {
        let ceiling: HashSet<String> = ["messages:read".to_owned(), "messages:write".to_owned()]
            .into_iter()
            .collect();

        let capabilities = vec![
            CapabilityUri::new("abc123", "messages", "read"),
            CapabilityUri::new("abc123", "role", "assign"),
        ];

        let err = verify_ceiling_compliance(&capabilities, &ceiling).unwrap_err();
        assert!(matches!(err, UcanError::CapabilityOutsideCeiling(ref c) if c == "role:assign"));
    }

    #[test]
    fn verify_ceiling_compliance_empty_capabilities_passes() {
        let ceiling: HashSet<String> = ["messages:read".to_owned()].into_iter().collect();
        assert!(verify_ceiling_compliance(&[], &ceiling).is_ok());
    }

    #[test]
    fn multi_colon_custom_uri_action_keeps_remainder_and_fails_closed() {
        // A custom capability URI with extra colons: from_str splits on the
        // FIRST ':' between resource and action, so the action retains the
        // remainder verbatim ("write:extra"). The ceiling membership test uses
        // capability_name() ("messages:write:extra"), which is the same
        // representation a ceiling entry would be built from — so the two agree.
        let uri: CapabilityUri = "scp:ctx:abc/messages:write:extra".parse().unwrap();
        assert_eq!(uri.resource(), "messages");
        assert_eq!(uri.action(), "write:extra");
        assert_eq!(uri.capability_name(), "messages:write:extra");

        // Fail-closed: a ceiling that grants only the plain "messages:write"
        // does NOT cover the multi-colon variant — the extra segment is treated
        // as outside the ceiling, not silently truncated to a granted form.
        let plain_ceiling: HashSet<String> = std::iter::once("messages:write".to_owned()).collect();
        assert!(!uri.is_within_ceiling(&plain_ceiling));
        let err =
            verify_ceiling_compliance(std::slice::from_ref(&uri), &plain_ceiling).unwrap_err();
        assert!(
            matches!(err, UcanError::CapabilityOutsideCeiling(ref c) if c == "messages:write:extra")
        );

        // Only an exact ceiling entry for the full capability_name admits it.
        let exact_ceiling: HashSet<String> =
            std::iter::once("messages:write:extra".to_owned()).collect();
        assert!(uri.is_within_ceiling(&exact_ceiling));
    }

    // -----------------------------------------------------------------------
    // check_capability_match
    // -----------------------------------------------------------------------

    #[test]
    fn check_capability_match_exact_match() {
        let granted = vec![
            CapabilityUri::new("abc123", "messages", "read"),
            CapabilityUri::new("abc123", "messages", "write"),
        ];
        let required = CapabilityUri::new("abc123", "messages", "write");

        assert!(check_capability_match(&granted, &required).is_ok());
    }

    #[test]
    fn check_capability_match_wildcard_grants() {
        let granted = vec![CapabilityUri::wildcard("messages", "write")];
        let required = CapabilityUri::new("abc123", "messages", "write");

        assert!(check_capability_match(&granted, &required).is_ok());
    }

    #[test]
    fn check_capability_match_no_match() {
        let granted = vec![CapabilityUri::new("abc123", "messages", "read")];
        let required = CapabilityUri::new("abc123", "messages", "write");

        let err = check_capability_match(&granted, &required).unwrap_err();
        assert!(matches!(err, UcanError::CapabilityNotGranted(_)));
    }

    #[test]
    fn check_capability_match_empty_grants() {
        let required = CapabilityUri::new("abc123", "messages", "write");
        let err = check_capability_match(&[], &required).unwrap_err();
        assert!(matches!(err, UcanError::CapabilityNotGranted(_)));
    }

    // -----------------------------------------------------------------------
    // CapabilityUri constructors
    // -----------------------------------------------------------------------

    #[test]
    fn new_creates_specific_uri() {
        let uri = CapabilityUri::new("ctx-1", "messages", "write");
        assert_eq!(uri.context_id(), Some("ctx-1"));
        assert_eq!(uri.resource(), "messages");
        assert_eq!(uri.action(), "write");
        assert!(!uri.is_wildcard());
    }

    #[test]
    fn wildcard_creates_wildcard_uri() {
        let uri = CapabilityUri::wildcard("messages", "write");
        assert!(uri.is_wildcard());
        assert_eq!(uri.context_id(), None);
        assert_eq!(uri.resource(), "messages");
        assert_eq!(uri.action(), "write");
    }

    // -----------------------------------------------------------------------
    // CapabilityUri Hash / Eq
    // -----------------------------------------------------------------------

    #[test]
    fn capability_uri_hash_set_dedup() {
        let mut set = HashSet::new();
        set.insert(CapabilityUri::new("abc123", "messages", "write"));
        set.insert(CapabilityUri::new("abc123", "messages", "write"));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn capability_uri_hash_set_distinct() {
        let mut set = HashSet::new();
        set.insert(CapabilityUri::new("abc123", "messages", "write"));
        set.insert(CapabilityUri::new("abc123", "messages", "read"));
        set.insert(CapabilityUri::wildcard("messages", "write"));
        assert_eq!(set.len(), 3);
    }

    // -----------------------------------------------------------------------
    // proptest — roundtrip and matching invariants
    // -----------------------------------------------------------------------

    mod proptest_tests {
        use super::*;
        use proptest::prelude::*;

        fn arb_identifier() -> impl Strategy<Value = String> {
            "[a-zA-Z0-9_-]{1,32}".prop_map(String::from)
        }

        fn arb_resource() -> impl Strategy<Value = String> {
            prop_oneof![
                Just("messages".to_owned()),
                Just("outlet_call".to_owned()),
                Just("member".to_owned()),
                Just("role".to_owned()),
                Just("context".to_owned()),
            ]
        }

        fn arb_action() -> impl Strategy<Value = String> {
            prop_oneof![
                Just("read".to_owned()),
                Just("write".to_owned()),
                Just("invoke".to_owned()),
                Just("invite".to_owned()),
                Just("assign".to_owned()),
                Just("close".to_owned()),
                Just("assistant".to_owned()),
            ]
        }

        proptest! {
            #[test]
            #[allow(clippy::unwrap_used)]
            fn parse_display_roundtrip_specific(
                ctx_id in arb_identifier(),
                resource in arb_resource(),
                action in arb_action(),
            ) {
                let uri = CapabilityUri::new(&ctx_id, &resource, &action);
                let displayed = uri.to_string();
                let parsed: CapabilityUri = displayed.parse().unwrap();
                prop_assert_eq!(uri, parsed);
            }

            #[test]
            #[allow(clippy::unwrap_used)]
            fn parse_display_roundtrip_wildcard(
                resource in arb_resource(),
                action in arb_action(),
            ) {
                let uri = CapabilityUri::wildcard(&resource, &action);
                let displayed = uri.to_string();
                let parsed: CapabilityUri = displayed.parse().unwrap();
                prop_assert_eq!(uri, parsed);
            }

            #[test]
            fn wildcard_matches_any_context(
                ctx_id in arb_identifier(),
                resource in arb_resource(),
                action in arb_action(),
            ) {
                let wildcard = CapabilityUri::wildcard(&resource, &action);
                let specific = CapabilityUri::new(&ctx_id, &resource, &action);
                prop_assert!(wildcard.matches(&specific));
            }

            #[test]
            fn specific_matches_self(
                ctx_id in arb_identifier(),
                resource in arb_resource(),
                action in arb_action(),
            ) {
                let uri = CapabilityUri::new(&ctx_id, &resource, &action);
                prop_assert!(uri.matches(&uri.clone()));
            }

            #[test]
            fn ceiling_membership_uses_capability_name(
                ctx_id in arb_identifier(),
                resource in arb_resource(),
                action in arb_action(),
            ) {
                let uri = CapabilityUri::new(&ctx_id, &resource, &action);
                let cap_name = uri.capability_name();
                let ceiling: HashSet<String> = [cap_name].into_iter().collect();
                prop_assert!(uri.is_within_ceiling(&ceiling));
            }
        }
    }
}
