//! Flat-config front-end for context creation (ADR-052 / construction.md).
//!
//! This module is the **options-object** entry that lowers into the existing
//! protocol [`ContextParams`] and calls the existing creation engine
//! ([`Supervisor::create_context`](crate::context::supervisor::Supervisor::create_context)).
//! It closes the documented Rust-SDK divergence: Python/TypeScript/Swift
//! already pass an options object, while the Rust SDK previously exposed only
//! the raw `ContextParams` entry. See `.docs/standards/construction.md`
//! (§"Context — `ContextConfig`") and `.docs/standards/sdk-common.md`
//! (§"Context Creation").
//!
//! The shape follows the construction standard's five mechanical rules:
//!
//! - **M2 (security-critical choice is required, per-variant):** the
//!   template-vs-explicit selection is the security-critical choice, modeled as
//!   the required [`ContextCreation`] enum with no `Default`. Within
//!   [`ContextCreation::Explicit`] the permission `ceiling` is a required field
//!   (no over-broad default ceiling); [`ContextCreation::Template`] resolves
//!   only to the named template's fail-safe parameters.
//! - **M4 (no whole-struct `Default`):** [`ContextConfig`] does **not**
//!   implement `Default`, because `creation` is a required security-critical
//!   choice with no safe default. The [`ContextConfig::defaults`] factory takes
//!   the irreducible required field and fills the rest with fail-safe defaults,
//!   enabling the spread idiom `ContextConfig { ttl, ..ContextConfig::defaults(creation) }`.

use std::time::Duration;

use scp_did::DID;
use scp_protocol::context::params::{
    Capability, ContextParams, GovernanceModel, MemoryScope, OutletRegistration, RoleDefinition,
    TemplateId,
};

// ---------------------------------------------------------------------------
// ContextCreation
// ---------------------------------------------------------------------------

/// The required template-vs-explicit choice for context creation (M2).
///
/// This is the security-critical selection for a context: a required enum with
/// **no** `Default`. `Template` resolves to a named, fail-safe template's
/// parameters; `Explicit` requires the caller to name the permission `ceiling`
/// directly (no over-broad default).
///
/// `TemplateId` is reused directly as the template selector — it *is* the
/// protocol's template enum (`scp_protocol::context::params::TemplateId`).
#[derive(Debug, Clone)]
pub enum ContextCreation {
    /// Create the context from a well-known protocol template.
    ///
    /// The template resolves the full parameter set; the caller supplies only
    /// what varies. The optional `peer` is the bilateral counterparty DID,
    /// carried for the invitation step. The creation engine itself does not
    /// consume it (see [`ContextConfig::into_params`], which returns it
    /// alongside the lowered params). The engine entry
    /// [`Supervisor::create`](crate::context::supervisor::Supervisor::create)
    /// does **not** silently drop it: until the invitation/Welcome-delivery
    /// path is wired, supplying `peer: Some(_)` is a loud
    /// [`ContextCreationError::BilateralPeerNotSupported`](scp_protocol::context::builder::ContextCreationError::BilateralPeerNotSupported),
    /// not an ignored field.
    Template {
        /// The well-known template to resolve parameters from.
        template: TemplateId,
        /// Optional bilateral peer DID, used by the invitation flow. Carried
        /// through [`ContextConfig::into_params`]; rejected loud (never
        /// dropped) by the engine entry until invitation delivery is wired.
        peer: Option<DID>,
    },
    /// Create the context from explicit parameters (advanced path).
    ///
    /// No template ID is attached. The caller specifies every governance-
    /// relevant parameter directly. `ceiling` is required (M2 per-variant):
    /// there is no over-broad default capability ceiling.
    Explicit {
        /// Capability ceiling — the maximum set of capabilities any participant
        /// can hold. Required (M2): no over-broad default.
        ceiling: Vec<Capability>,
        /// Role definitions, each a subset of the ceiling.
        roles: Vec<RoleDefinition>,
        /// Governance model controlling administrative decisions.
        governance: GovernanceModel,
        /// Memory scope controlling data retention after close.
        memory_scope: MemoryScope,
    },
}

// ---------------------------------------------------------------------------
// ContextConfig
// ---------------------------------------------------------------------------

// M4: intentionally NO `impl Default for ContextConfig` — `creation` is a
// required security-critical choice with no safe default. Use
// `ContextConfig::defaults(creation)` for the spread idiom.

/// Flat options-object for context creation (ADR-052 / construction.md).
///
/// Carries the required [`ContextCreation`] choice plus the shared optional
/// fields (`ttl`, `outlets`). Lower it into protocol [`ContextParams`] with
/// [`ContextConfig::into_params`], or pass it directly to
/// [`Supervisor::create`](crate::context::supervisor::Supervisor::create).
///
/// Per M4, this struct does **not** implement a whole-struct `Default`: the
/// `creation` field is a required security-critical choice. Use
/// [`ContextConfig::defaults`] to obtain a base for the spread idiom:
///
/// ```
/// use scp_runtime::context::{ContextConfig, ContextCreation};
/// use scp_protocol::context::params::TemplateId;
/// use std::time::Duration;
///
/// let config = ContextConfig {
///     ttl: Some(Duration::from_secs(300)),
///     ..ContextConfig::defaults(ContextCreation::Template {
///         template: TemplateId::BilateralEphemeral,
///         peer: None,
///     })
/// };
/// ```
#[derive(Debug, Clone)]
pub struct ContextConfig {
    /// The required template-vs-explicit creation choice (M2).
    pub creation: ContextCreation,
    /// Optional time-to-live. When set, the context auto-expires after this
    /// duration. Templates that require a TTL reject `None`; templates that
    /// forbid a TTL reject `Some(_)` at creation (fail-loud).
    pub ttl: Option<Duration>,
    /// Outlet registrations available within the context. For the template path,
    /// supplied outlets override the template's own outlets only when non-empty
    /// (see [`ContextConfig::into_params`]).
    pub outlets: Vec<OutletRegistration>,
}

impl ContextConfig {
    /// Returns a [`ContextConfig`] with the required `creation` choice and
    /// fail-safe defaults for the remaining fields (`ttl: None`, no outlets).
    ///
    /// This is the M4 `defaults(required…)` factory: it takes the irreducible
    /// required field so the spread idiom
    /// `ContextConfig { ttl, ..ContextConfig::defaults(creation) }` compiles.
    #[must_use]
    pub const fn defaults(creation: ContextCreation) -> Self {
        Self {
            creation,
            ttl: None,
            outlets: Vec::new(),
        }
    }

    /// Lowers this flat config into the protocol [`ContextParams`] consumed by
    /// the existing creation engine, plus the optional bilateral peer DID
    /// (carried for the invitation step; the engine itself does not take it).
    ///
    /// Lowering per variant:
    ///
    /// - **`Template`** — starts from [`ContextParams::from_template`] (the
    ///   canonical template resolution; templates return `ttl: None`), applies
    ///   the config `ttl` override, and overrides `outlets` **only when the caller
    ///   supplied outlets**. Empty `outlets` leaves the template's own outlets intact,
    ///   so a template that disallows outlets is not corrupted into a mismatch;
    ///   the protocol's `validate_against_template` then fails loud if supplied
    ///   outlets do not match a template that defines its own. The template's
    ///   `template_id` is preserved. The bilateral `peer` is returned to the
    ///   caller.
    /// - **`Explicit`** — fills the four explicit fields and leaves
    ///   `template_id = None` (no template attached); everything else comes from
    ///   [`ContextParams::default`]. No peer is carried (`None`).
    #[must_use]
    pub fn into_params(self) -> (ContextParams, Option<DID>) {
        let Self {
            creation,
            ttl,
            outlets,
        } = self;
        match creation {
            ContextCreation::Template { template, peer } => {
                let mut params = ContextParams::from_template(template);
                params.ttl = ttl;
                if !outlets.is_empty() {
                    params.outlets = outlets;
                }
                (params, peer)
            }
            ContextCreation::Explicit {
                ceiling,
                roles,
                governance,
                memory_scope,
            } => {
                let params = ContextParams {
                    ceiling,
                    roles,
                    governance,
                    memory_scope,
                    outlets,
                    ttl,
                    template_id: None,
                    ..ContextParams::default()
                };
                (params, None)
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Template lowering equivalence
    // -----------------------------------------------------------------------

    #[test]
    fn template_no_ttl_no_outlets_lowers_to_from_template() {
        // BilateralPersistent forbids a TTL, so `ttl: None` is the valid form.
        // The lowered params must equal the equivalent
        // `ContextParams::from_template` path — proving the front-end produces
        // the same context the raw `ContextParams` path would.
        let config = ContextConfig::defaults(ContextCreation::Template {
            template: TemplateId::BilateralPersistent,
            peer: None,
        });
        let (params, peer) = config.into_params();
        assert_eq!(
            params,
            ContextParams::from_template(TemplateId::BilateralPersistent)
        );
        assert_eq!(peer, None);
    }

    #[test]
    fn template_ttl_override_is_only_delta_from_from_template() {
        // BilateralEphemeral requires a TTL. The only delta between the lowered
        // params and `from_template` must be the `ttl` field.
        let ttl = Duration::from_mins(5);
        let config = ContextConfig {
            ttl: Some(ttl),
            ..ContextConfig::defaults(ContextCreation::Template {
                template: TemplateId::BilateralEphemeral,
                peer: None,
            })
        };
        let (params, _peer) = config.into_params();

        let mut expected = ContextParams::from_template(TemplateId::BilateralEphemeral);
        assert_eq!(expected.ttl, None, "template returns ttl: None");
        expected.ttl = Some(ttl);

        assert_eq!(params, expected);
        assert_eq!(params.ttl, Some(ttl));
    }

    // -----------------------------------------------------------------------
    // Explicit lowering
    // -----------------------------------------------------------------------

    #[test]
    fn explicit_lowers_with_ceiling_and_no_template_id() {
        let config = ContextConfig::defaults(ContextCreation::Explicit {
            ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
            roles: vec![],
            governance: GovernanceModel::SingleAdmin,
            memory_scope: MemoryScope::Summary,
        });
        let (params, peer) = config.into_params();

        assert_eq!(
            params.ceiling,
            vec![Capability::MessagesRead, Capability::MessagesWrite]
        );
        assert_eq!(params.template_id, None);
        assert_eq!(params.governance, GovernanceModel::SingleAdmin);
        assert_eq!(params.memory_scope, MemoryScope::Summary);
        assert_eq!(peer, None);
    }

    #[test]
    fn explicit_carries_ttl_and_outlets() {
        let ttl = Duration::from_hours(1);
        let config = ContextConfig {
            ttl: Some(ttl),
            outlets: Vec::new(),
            creation: ContextCreation::Explicit {
                ceiling: vec![Capability::MessagesRead],
                roles: vec![],
                governance: GovernanceModel::SingleAdmin,
                memory_scope: MemoryScope::Full,
            },
        };
        let (params, _peer) = config.into_params();
        assert_eq!(params.ttl, Some(ttl));
        assert_eq!(params.memory_scope, MemoryScope::Full);
    }

    // -----------------------------------------------------------------------
    // Peer preservation
    // -----------------------------------------------------------------------

    #[test]
    fn template_peer_is_preserved_through_lowering() {
        let bob = DID::from("did:example:bob");
        let config = ContextConfig::defaults(ContextCreation::Template {
            template: TemplateId::BilateralPersistent,
            peer: Some(bob.clone()),
        });
        let (_params, peer) = config.into_params();
        assert_eq!(peer, Some(bob));
    }

    #[test]
    fn explicit_carries_no_peer() {
        let config = ContextConfig::defaults(ContextCreation::Explicit {
            ceiling: vec![Capability::MessagesRead],
            roles: vec![],
            governance: GovernanceModel::SingleAdmin,
            memory_scope: MemoryScope::Summary,
        });
        let (_params, peer) = config.into_params();
        assert_eq!(peer, None);
    }

    // -----------------------------------------------------------------------
    // M4: defaults factory requires the `creation` arg
    // -----------------------------------------------------------------------

    #[test]
    fn defaults_factory_requires_creation_and_fills_fail_safe_rest() {
        // The `defaults` factory takes the irreducible required `creation`
        // field (M4) and fills the rest with fail-safe defaults. There is no
        // whole-struct `Default` for `ContextConfig` — `creation` has no safe
        // default — so this factory is the only base for the spread idiom.
        let config = ContextConfig::defaults(ContextCreation::Template {
            template: TemplateId::Coordination,
            peer: None,
        });
        assert_eq!(config.ttl, None);
        assert!(config.outlets.is_empty());
        match config.creation {
            ContextCreation::Template { template, peer } => {
                assert_eq!(template, TemplateId::Coordination);
                assert_eq!(peer, None);
            }
            ContextCreation::Explicit { .. } => panic!("expected Template variant"),
        }
    }
}
