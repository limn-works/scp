#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! B4: Context lifecycle integration tests.
//!
//! Exercises `ContextHandle`, `ContextState` transitions, `ContextParams` defaults
//! and serialization, `TemplateId`/`template_params`, `MembershipState`,
//! `CapabilityCeiling`, builtin roles, TTL checking, nesting depth validation,
//! and ceiling intersection.

use std::collections::HashSet;
use std::time::Duration;

use scp_core::context::nesting::ParentRef;
use scp_core::context::params::{
    CeilingPolicy, ConsequenceConfig, GovernanceModel, MemoryScope, PromotionPolicy,
};
use scp_core::context::ttl::{TtlError, TtlPolicy};
use scp_core::context::{
    Capability, CapabilityCeiling, ContextError, ContextHandle, ContextMode, ContextParams,
    ContextState, ExtensionConsentMode, MembershipState, TemplateId, TtlExtensionProposal,
    builtin_admin, builtin_author, builtin_member, builtin_observer, builtin_subscriber, check_ttl,
    compute_ceiling_intersection, consent_mode_for_member_count, template_params,
    validate_child_ttl, validate_nesting_depth,
};

// ---------------------------------------------------------------------------
// 1. context_handle_creation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn context_handle_creation() {
    let params = ContextParams::default();
    let handle = ContextHandle::new("ctx-b4-001".to_owned(), params);

    assert_eq!(handle.context_id(), "ctx-b4-001");
    assert_eq!(handle.state().await, ContextState::Creating);
    assert_eq!(handle.params().mode, ContextMode::Encrypted);
}

// ---------------------------------------------------------------------------
// 2. state_transitions_happy_path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn state_transitions_happy_path() {
    let handle = ContextHandle::new("ctx-b4-002".to_owned(), ContextParams::default());

    // Creating -> Active
    let new = handle.transition_to(&ContextState::Active).await.unwrap();
    assert_eq!(new, ContextState::Active);
    assert_eq!(handle.state().await, ContextState::Active);

    // Active -> Closing
    let new = handle.transition_to(&ContextState::Closing).await.unwrap();
    assert_eq!(new, ContextState::Closing);
    assert_eq!(handle.state().await, ContextState::Closing);

    // Closing -> Closed
    let new = handle.transition_to(&ContextState::Closed).await.unwrap();
    assert_eq!(new, ContextState::Closed);
    assert_eq!(handle.state().await, ContextState::Closed);
}

// ---------------------------------------------------------------------------
// 3. state_transition_active_to_expired
// ---------------------------------------------------------------------------

#[tokio::test]
async fn state_transition_active_to_expired() {
    let handle = ContextHandle::new("ctx-b4-003".to_owned(), ContextParams::default());
    handle.transition_to(&ContextState::Active).await.unwrap();

    let new = handle.transition_to(&ContextState::Expired).await.unwrap();
    assert_eq!(new, ContextState::Expired);
    assert_eq!(handle.state().await, ContextState::Expired);
}

// ---------------------------------------------------------------------------
// 4. invalid_state_transitions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalid_state_transitions() {
    // Closed -> Active
    let handle = ContextHandle::new("ctx-b4-004a".to_owned(), ContextParams::default());
    handle.transition_to(&ContextState::Active).await.unwrap();
    handle.transition_to(&ContextState::Closing).await.unwrap();
    handle.transition_to(&ContextState::Closed).await.unwrap();

    let result = handle.transition_to(&ContextState::Active).await;
    assert!(result.is_err());
    assert!(
        matches!(
            result.unwrap_err(),
            ContextError::InvalidTransition {
                from: ContextState::Closed,
                to: ContextState::Active,
            }
        ),
        "Closed -> Active should return InvalidTransition"
    );
    assert_eq!(handle.state().await, ContextState::Closed);

    // Expired -> Active
    let handle2 = ContextHandle::new("ctx-b4-004b".to_owned(), ContextParams::default());
    handle2.transition_to(&ContextState::Active).await.unwrap();
    handle2.transition_to(&ContextState::Expired).await.unwrap();

    let result2 = handle2.transition_to(&ContextState::Active).await;
    assert!(result2.is_err());
    assert!(
        matches!(
            result2.unwrap_err(),
            ContextError::InvalidTransition {
                from: ContextState::Expired,
                to: ContextState::Active,
            }
        ),
        "Expired -> Active should return InvalidTransition"
    );
    assert_eq!(handle2.state().await, ContextState::Expired);
}

// ---------------------------------------------------------------------------
// 5. context_params_defaults
// ---------------------------------------------------------------------------

#[tokio::test]
async fn context_params_defaults() {
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
    assert!(params.projection_policy.is_none());
    assert!(!params.discoverable);
    assert!(params.max_chain_depth.is_none());
    assert!(params.participation_requirements.is_empty());
}

// ---------------------------------------------------------------------------
// 6. context_params_all_fields
// ---------------------------------------------------------------------------

#[tokio::test]
async fn context_params_all_fields() {
    let params = ContextParams {
        mode: ContextMode::Broadcast,
        ceiling: vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::OutletCallAll,
            Capability::OutletRegister,
        ],
        ceiling_policy: CeilingPolicy::Governed,
        promotion_policy: PromotionPolicy::Promotable,
        roles: Vec::new(),
        tools: Vec::new(),
        ttl: Some(Duration::from_hours(1)),
        memory_scope: MemoryScope::Full,
        governance: GovernanceModel::SingleAdmin,
        template_id: Some(TemplateId::PublicBroadcast),
        economic_policy: None,
        metadata_visibility: scp_core::context::params::MetadataVisibilityPolicy::default(),
        projection_policy: None,
        discoverable: true,
        max_chain_depth: Some(3),
        max_nesting_depth: None,
        session_cap: None,
        counterparty_policy: scp_core::provenance::CounterpartyPolicy::default(),
        participation_requirements: Vec::new(),
        incomplete_verification_policy:
            scp_core::context::params::IncompleteVerificationPolicy::default(),
        min_protocol_version: None,
        migration_source: None,
        consequence_rules: Vec::new(),
        consequence_config: ConsequenceConfig::default(),
        sybil_policy: None,
    };

    assert_eq!(params.mode, ContextMode::Broadcast);
    assert_eq!(params.ceiling.len(), 4);
    assert_eq!(params.ceiling_policy, CeilingPolicy::Governed);
    assert_eq!(params.promotion_policy, PromotionPolicy::Promotable);
    assert_eq!(params.ttl, Some(Duration::from_hours(1)));
    assert_eq!(params.memory_scope, MemoryScope::Full);
    assert_eq!(params.template_id, Some(TemplateId::PublicBroadcast));
    assert!(params.discoverable);
    assert_eq!(params.max_chain_depth, Some(3));
}

// ---------------------------------------------------------------------------
// 7. context_params_backward_compat
// ---------------------------------------------------------------------------

#[tokio::test]
async fn context_params_backward_compat() {
    // JSON with only the required fields — new fields should deserialize to defaults
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
    assert_eq!(params.mode, ContextMode::Encrypted);
    assert!(params.economic_policy.is_none());
    assert!(params.projection_policy.is_none());
    assert!(!params.discoverable);
    assert!(params.max_chain_depth.is_none());
    assert!(params.participation_requirements.is_empty());
}

// ---------------------------------------------------------------------------
// 8. all_template_ids
// ---------------------------------------------------------------------------

#[tokio::test]
async fn all_template_ids() {
    let templates = [
        TemplateId::BilateralEphemeral,
        TemplateId::BilateralPersistent,
        TemplateId::Coordination,
        TemplateId::GroupDiscussion,
        TemplateId::PublicBroadcast,
        TemplateId::GatedBroadcast,
        TemplateId::OutletInterfaceTemplate,
        TemplateId::PaidService,
        TemplateId::PaidBroadcast,
        TemplateId::HandleRegistry,
    ];

    for template in &templates {
        let params = template_params(template);
        // template_id in the returned params should match the input
        assert_eq!(
            params.template_id.as_ref(),
            Some(template),
            "template_params should set template_id for {template:?}"
        );
        // ceiling should be non-empty (every template defines capabilities)
        assert!(
            !params.ceiling.is_empty(),
            "template {template:?} should have a non-empty ceiling"
        );
    }
}

// ---------------------------------------------------------------------------
// 9. membership_state_add_remove
// ---------------------------------------------------------------------------

#[tokio::test]
async fn membership_state_add_remove() {
    let mut state = MembershipState::new();
    assert_eq!(state.count(), 0);

    state.add_member("did:key:alice".into(), "admin".into(), vec![]);
    state.add_member("did:key:bob".into(), "member".into(), vec![]);
    assert_eq!(state.count(), 2);
    assert!(state.contains("did:key:alice"));
    assert!(state.contains("did:key:bob"));
    assert!(!state.contains("did:key:carol"));

    assert!(state.remove_member("did:key:alice"));
    assert_eq!(state.count(), 1);
    assert!(!state.contains("did:key:alice"));
    assert!(state.contains("did:key:bob"));

    // Removing non-existent returns false
    assert!(!state.remove_member("did:key:carol"));
}

// ---------------------------------------------------------------------------
// 10. membership_member_info
// ---------------------------------------------------------------------------

#[tokio::test]
async fn membership_member_info() {
    let mut state = MembershipState::new();
    state.add_member("did:key:alice".into(), "moderator".into(), vec![]);

    let info = state.get("did:key:alice").unwrap();
    assert_eq!(info.did, "did:key:alice");
    assert_eq!(info.role_name, "moderator");
    assert_eq!(info.sequence_number, 0);

    // Sequence number increments
    assert_eq!(state.next_sequence_number("did:key:alice"), Some(1));
    assert_eq!(state.next_sequence_number("did:key:alice"), Some(2));

    let info_after = state.get("did:key:alice").unwrap();
    assert_eq!(info_after.sequence_number, 2);
}

// ---------------------------------------------------------------------------
// 11. capability_ceiling_contains
// ---------------------------------------------------------------------------

#[tokio::test]
async fn capability_ceiling_contains() {
    let ceiling = CapabilityCeiling::new([
        Capability::MessagesRead,
        Capability::MessagesWrite,
        Capability::OutletCallAll,
    ]);

    assert!(ceiling.contains(&Capability::MessagesRead));
    assert!(ceiling.contains(&Capability::MessagesWrite));
    assert!(ceiling.contains(&Capability::OutletCallAll));

    // ToolInvoke("foo") is implicitly contained when ToolInvokeAll is present
    assert!(ceiling.contains(&Capability::OutletCall("foo".to_owned())));

    // Not in ceiling
    assert!(!ceiling.contains(&Capability::MemberInvite));
    assert!(!ceiling.contains(&Capability::ContextClose));
    assert!(!ceiling.contains(&Capability::GovernanceVote));
}

// ---------------------------------------------------------------------------
// 12. all_capability_variants
// ---------------------------------------------------------------------------

#[tokio::test]
async fn all_capability_variants() {
    let capabilities = vec![
        (Capability::MessagesRead, "messages:read"),
        (Capability::MessagesWrite, "messages:write"),
        (Capability::OutletCallAll, "outlet:call:*"),
        (Capability::OutletRegister, "outlet:register"),
        (Capability::MemberInvite, "member:invite"),
        (Capability::MemberRemove, "member:remove"),
        (Capability::RoleAssign, "role:assign"),
        (Capability::GovernancePropose, "governance:propose"),
        (Capability::GovernanceVote, "governance:vote"),
        (Capability::ContextClose, "context:close"),
        (Capability::ChildContextCreate, "context:child:create"),
        (Capability::OutletInterface, "outlet:interface"),
        (Capability::Bridging, "bridging"),
        (Capability::MediaVoice, "media:voice"),
        (Capability::MediaVideo, "media:video"),
        (Capability::MediaScreenShare, "media:screen_share"),
        (Capability::MemberBan, "member:ban"),
        (
            Capability::OutletCall("my-tool".to_owned()),
            "outlet:call:my-tool",
        ),
        (Capability::Custom("special".to_owned()), "special"),
    ];

    for (cap, expected_name) in &capabilities {
        assert_eq!(
            cap.name(),
            *expected_name,
            "Capability::name() mismatch for {cap:?}"
        );
    }

    // Verify Capability::new round-trips for well-known names
    assert_eq!(Capability::new("messages:read"), Capability::MessagesRead);
    assert_eq!(Capability::new("context:close"), Capability::ContextClose);
    assert_eq!(
        Capability::new("outlet:call:my-tool"),
        Capability::OutletCall("my-tool".to_owned())
    );
    assert_eq!(
        Capability::new("unknown-cap"),
        Capability::Custom("unknown-cap".to_owned())
    );
}

// ---------------------------------------------------------------------------
// 13. builtin_roles_capabilities
// ---------------------------------------------------------------------------

#[tokio::test]
async fn builtin_roles_capabilities() {
    let ceiling = CapabilityCeiling::new([
        Capability::MessagesRead,
        Capability::MessagesWrite,
        Capability::OutletCallAll,
        Capability::MemberInvite,
        Capability::MemberRemove,
        Capability::RoleAssign,
        Capability::GovernancePropose,
        Capability::GovernanceVote,
        Capability::ContextClose,
    ]);

    // Admin gets all ceiling capabilities
    let admin = builtin_admin(&ceiling);
    assert_eq!(admin.name, "admin");
    assert_eq!(admin.capabilities, ceiling.capabilities);

    // Observer gets only MessagesRead
    let observer = builtin_observer(&ceiling);
    assert_eq!(observer.name, "observer");
    assert!(observer.capabilities.contains(&Capability::MessagesRead));
    assert!(!observer.capabilities.contains(&Capability::MessagesWrite));
    assert_eq!(observer.capabilities.len(), 1);

    // Member gets MessagesRead, MessagesWrite, ToolInvokeAll
    let member = builtin_member(&ceiling);
    assert_eq!(member.name, "member");
    assert!(member.capabilities.contains(&Capability::MessagesRead));
    assert!(member.capabilities.contains(&Capability::MessagesWrite));
    assert!(member.capabilities.contains(&Capability::OutletCallAll));
    assert_eq!(member.capabilities.len(), 3);

    // Broadcast roles
    let author = builtin_author(&ceiling);
    assert_eq!(author.name, "author");
    assert!(author.capabilities.contains(&Capability::MessagesWrite));
    assert!(author.capabilities.contains(&Capability::MessagesRead));

    let subscriber = builtin_subscriber(&ceiling);
    assert_eq!(subscriber.name, "subscriber");
    assert!(subscriber.capabilities.contains(&Capability::MessagesRead));
    assert!(!subscriber.capabilities.contains(&Capability::MessagesWrite));
}

// ---------------------------------------------------------------------------
// 14. ttl_check
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ttl_check() {
    // No TTL policy: always valid
    assert!(check_ttl(1000, TtlPolicy::None, None, 999_999).is_ok());

    // Finite TTL, not expired
    let created_at = 1000;
    let ttl = TtlPolicy::Finite(Duration::from_hours(1));
    assert!(check_ttl(created_at, ttl, None, 2000).is_ok());

    // Finite TTL, expired (now >= created_at + ttl_secs)
    let result = check_ttl(created_at, ttl, None, 5000);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), TtlError::Expired));

    // Extended TTL: extended_until takes precedence
    assert!(check_ttl(created_at, ttl, Some(6000), 5500).is_ok());
    let result = check_ttl(created_at, ttl, Some(6000), 6001);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// 15. ttl_extension_proposal
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ttl_extension_proposal() {
    let _proposal = TtlExtensionProposal::new(
        "did:key:alice".into(),
        Duration::from_hours(2),
        2, // bilateral context
        GovernanceModel::SingleAdmin,
    );

    // Proposal should be constructed without panic
    // Verify the consent mode: 2 members -> AllMember
    assert_eq!(
        consent_mode_for_member_count(2),
        ExtensionConsentMode::AllMember
    );

    // 3+ members -> Governance
    assert_eq!(
        consent_mode_for_member_count(3),
        ExtensionConsentMode::Governance
    );
    assert_eq!(
        consent_mode_for_member_count(100),
        ExtensionConsentMode::Governance
    );

    // 1 member -> AllMember
    assert_eq!(
        consent_mode_for_member_count(1),
        ExtensionConsentMode::AllMember
    );
}

// ---------------------------------------------------------------------------
// 16. nesting_depth_validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn nesting_depth_validation() {
    // Unbounded by default (ADR-043) — any depth is valid with no limit.
    for depth in [0, 1, 3, 10, 100, u32::MAX] {
        assert!(
            validate_nesting_depth(depth, None).is_ok(),
            "depth {depth} should be valid when unbounded"
        );
    }

    // Context-configurable limit enforced.
    assert!(validate_nesting_depth(5, Some(5)).is_ok());
    let result = validate_nesting_depth(6, Some(5));
    assert!(result.is_err());

    // Depth 0 with Some(0) should fail (depth > max).
    // Actually 0 == 0, so depth 0 with max 0 is ok.
    assert!(validate_nesting_depth(0, Some(0)).is_ok());
    let result = validate_nesting_depth(1, Some(0));
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// 17. ceiling_intersection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ceiling_intersection() {
    use std::collections::BTreeSet;

    use scp_core::context::nesting::OnSeverPolicy;

    let parent_a = ParentRef {
        context_id: "parent-a".to_owned(),
        ceiling: CapabilityCeiling::new([
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::OutletCallAll,
            Capability::ChildContextCreate,
        ]),
        governance_config: scp_core::context::nesting::ParentGovernanceConfig {
            can_close_child: true,
            can_evict_members: false,
            can_restrict_ceiling: false,
            requires_approval_for: BTreeSet::default(),
            on_sever: OnSeverPolicy::EvictUniqueMembers,
        },
        members: HashSet::from(["did:key:alice".into()]),
    };

    let parent_b = ParentRef {
        context_id: "parent-b".to_owned(),
        ceiling: CapabilityCeiling::new([
            Capability::MessagesRead,
            Capability::OutletCallAll,
            Capability::MemberInvite,
            Capability::ChildContextCreate,
        ]),
        governance_config: scp_core::context::nesting::ParentGovernanceConfig {
            can_close_child: false,
            can_evict_members: false,
            can_restrict_ceiling: false,
            requires_approval_for: BTreeSet::default(),
            on_sever: OnSeverPolicy::PreserveMembership,
        },
        members: HashSet::from(["did:key:alice".into()]),
    };

    let intersection = compute_ceiling_intersection(&[parent_a, parent_b]);

    // Only MessagesRead, ToolInvokeAll, and ChildContextCreate are in both
    assert!(intersection.contains(&Capability::MessagesRead));
    assert!(intersection.contains(&Capability::OutletCallAll));
    assert!(intersection.contains(&Capability::ChildContextCreate));

    // MessagesWrite is only in parent A, MemberInvite only in parent B
    assert!(!intersection.contains(&Capability::MessagesWrite));
    assert!(!intersection.contains(&Capability::MemberInvite));
}

// ---------------------------------------------------------------------------
// 18. child_ttl_validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn child_ttl_validation() {
    // Child TTL <= parent TTL: ok
    let result = validate_child_ttl(
        Some(Duration::from_hours(1)),
        &[Some(Duration::from_hours(2))],
    );
    assert!(result.is_ok());

    // Child TTL == parent TTL: ok
    let result = validate_child_ttl(
        Some(Duration::from_hours(1)),
        &[Some(Duration::from_hours(1))],
    );
    assert!(result.is_ok());

    // Child TTL > parent TTL: error
    let result = validate_child_ttl(
        Some(Duration::from_hours(2)),
        &[Some(Duration::from_hours(1))],
    );
    assert!(result.is_err());

    // Multiple parents: child must not exceed the minimum
    let result = validate_child_ttl(
        Some(Duration::from_secs(5000)),
        &[Some(Duration::from_hours(2)), Some(Duration::from_hours(1))],
    );
    assert!(result.is_err()); // 5000 > min(7200, 3600) = 3600

    // No parent has TTL: child with no TTL is ok
    let result = validate_child_ttl(None, &[None, None]);
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// 19. context_close_lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn context_close_lifecycle() {
    let handle = ContextHandle::new("ctx-b4-019".to_owned(), ContextParams::default());

    // Creating -> Active
    handle.transition_to(&ContextState::Active).await.unwrap();
    assert_eq!(handle.state().await, ContextState::Active);

    // Active -> Closing
    handle.transition_to(&ContextState::Closing).await.unwrap();
    assert_eq!(handle.state().await, ContextState::Closing);

    // Closing -> Closed
    handle.transition_to(&ContextState::Closed).await.unwrap();
    assert_eq!(handle.state().await, ContextState::Closed);

    // Verify terminal: cannot go back to Active or Closing
    assert!(handle.transition_to(&ContextState::Active).await.is_err());
    assert!(handle.transition_to(&ContextState::Closing).await.is_err());
    assert!(handle.transition_to(&ContextState::Creating).await.is_err());
    assert_eq!(handle.state().await, ContextState::Closed);
}
