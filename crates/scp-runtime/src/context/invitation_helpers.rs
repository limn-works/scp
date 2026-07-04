//! Runtime assembly + delivery glue for the signed §5.12.3 `InvitationBundle`
//! flow (ADR-049 Phase 2J, FFI-02 Option A).
//!
//! The pure protocol layer
//! ([`scp_protocol::context::invitation_bundle`]) owns the wire structs, the
//! JCS signing-hash, and Ed25519 `sign`/`verify`. This runtime layer owns the
//! parts that need live context state and the network:
//!
//! - [`build_metadata_snapshot`] — projects the genesis [`ContextParams`] into
//!   the visibility-filtered [`MetadataSnapshot`] carried in the bundle. Its
//!   `structural` fields are copied verbatim from `params` so the bundle always
//!   passes [`InvitationBundle::verify_structural_consistency`]; its
//!   `operational` fields are filtered by the context's
//!   [`MetadataVisibilityPolicy`] exactly as
//!   [`ContextParams::public_metadata`](scp_protocol::context::ContextParams::public_metadata)
//!   filters `PublicMetadata` (§5.7).
//! - [`SealedInvitation`] — the on-wire delivery envelope published to the
//!   invitee's `scp-invitations` routing id. It carries the HPKE `(enc, ct)`
//!   plus the `context_id` / `creator_did` **binding hints** the joiner needs to
//!   rebuild the HPKE `info`/`aad` BEFORE it can open (they cannot come from
//!   inside the ciphertext). Those hints are UNTRUSTED until the open succeeds
//!   (AEAD-authenticated) AND they are cross-checked against the decrypted,
//!   signature-verified bundle — see `Supervisor::spawn_actor_from_welcome`.
//!
//! HPKE seal/open themselves live in
//! [`scp_protocol::crypto::envelope_seal`]; the signing-key resolution, the DID
//! `#active` verifying-key resolution, and the transport publish are the
//! `Supervisor` methods.

use serde::{Deserialize, Serialize};

use scp_primitives::DID;
use scp_protocol::context::metadata::{MetadataSnapshot, OperationalMetadata, StructuralMetadata};
use scp_protocol::context::params::{ContextParams, FieldVisibility};
use scp_protocol::economy::EconomicPolicy;

/// Operational runtime facts (not present in [`ContextParams`]) the creator
/// injects into the invitation's visibility-filtered metadata snapshot.
///
/// Fields with no runtime source are `None`; the visibility policy then filters
/// what remains. The `structural` half of the snapshot is derived entirely from
/// `params` and is never affected by these facts.
#[derive(Debug, Clone, Default)]
pub(crate) struct SnapshotRuntimeFacts {
    /// Current member count (from `Supervisor::member_count`).
    pub member_count: Option<u64>,
    /// Context age in seconds since creation.
    pub context_age_secs: Option<u64>,
    /// Creator DID (always available at invite time).
    pub creator_did: Option<DID>,
    /// Human-readable context name, if any.
    pub name: Option<String>,
    /// Human-readable context description, if any.
    pub description: Option<String>,
    /// Number of registered tool interfaces.
    pub tool_count: Option<u64>,
    /// Child context ids, if this is a parent context.
    pub child_contexts: Option<Vec<String>>,
}

/// Applies [`FieldVisibility`] to an operational field: `PreJoin` keeps the
/// value, `MemberOnly` omits it. Mirrors
/// `scp_protocol::context::params::filter_field` (private there).
fn filter<T>(visibility: FieldVisibility, value: Option<T>) -> Option<T> {
    match visibility {
        FieldVisibility::PreJoin => value,
        FieldVisibility::MemberOnly => None,
    }
}

/// Builds the [`StructuralMetadata`] verbatim from genesis [`ContextParams`].
///
/// Every field is copied directly so the resulting snapshot satisfies
/// [`InvitationBundle::verify_structural_consistency`](scp_protocol::context::InvitationBundle::verify_structural_consistency)
/// (which compares each `structural.*` against the corresponding `params.*`).
/// `ttl` is projected `Duration -> seconds` to match the structural encoding.
fn structural_from_params(params: &ContextParams) -> StructuralMetadata {
    StructuralMetadata {
        template_id: params.template_id,
        ceiling: params.ceiling.clone(),
        ceiling_policy: params.ceiling_policy,
        roles: params.roles.clone(),
        governance: params.governance.clone(),
        ttl: params.ttl.map(|d| d.as_secs()),
        promotion_policy: params.promotion_policy,
        memory_scope: params.memory_scope,
        mode: params.mode,
        visibility_policy: params.metadata_visibility.clone(),
    }
}

/// A compact, deterministic display summary of an [`EconomicPolicy`] for the
/// operational metadata view. The authoritative, complete policy is authenticated
/// separately as part of `context_params` inside the bundle signature; this is a
/// lossy human-readable hint only.
fn summarize_economic_policy(policy: &EconomicPolicy) -> String {
    let payee: &str = policy.payee.as_ref();
    format!(
        "payee={}; adapters={}; locked={}",
        payee,
        policy.payment_adapters.len(),
        policy.locked
    )
}

/// Projects genesis [`ContextParams`] + runtime `facts` into the
/// visibility-filtered [`MetadataSnapshot`] carried in the invitation bundle
/// (spec §5.12.3.1). Structural fields are always present (copied from
/// `params`); operational fields are filtered per `params.metadata_visibility`.
pub(crate) fn build_metadata_snapshot(
    params: &ContextParams,
    facts: SnapshotRuntimeFacts,
) -> MetadataSnapshot {
    let vis = &params.metadata_visibility;
    let operational = OperationalMetadata {
        member_count: filter(vis.member_count, facts.member_count),
        context_age_secs: filter(vis.context_age, facts.context_age_secs),
        creator_did: filter(vis.creator_identity, facts.creator_did),
        name: filter(vis.name, facts.name),
        description: filter(vis.description, facts.description),
        economic_policy: filter(
            vis.economic_policy,
            params
                .economic_policy
                .as_ref()
                .map(summarize_economic_policy),
        ),
        tool_count: filter(vis.tool_interface_count, facts.tool_count),
        child_contexts: filter(vis.child_context_info, facts.child_contexts),
    };
    MetadataSnapshot {
        structural: structural_from_params(params),
        operational,
    }
}

/// The on-wire delivery envelope for a sealed invitation, published to the
/// invitee's `scp-invitations` routing id (spec §5.12.3.3) and consumed by the
/// joiner to build a `WelcomeJoinRequest`.
///
/// `enc` / `ciphertext` are the RFC 9180 HPKE outputs of sealing the
/// MessagePack-serialized [`InvitationBundle`](scp_protocol::context::InvitationBundle).
/// `context_id` / `creator_did` are the **binding hints** the joiner needs to
/// rebuild the HPKE `info`/`aad` before opening; they are UNTRUSTED until the
/// open succeeds (they are AEAD-authenticated) and the joiner additionally
/// cross-checks them against the decrypted, signature-verified bundle. They are
/// carried in cleartext only because HPKE `info`/`aad` are keying inputs and so
/// cannot be recovered from inside the ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedInvitation {
    /// Binding hint: the context id used to build the HPKE `info`/`aad`.
    pub context_id: String,
    /// Binding hint: the creator did used to build the HPKE `info`/`aad`.
    pub creator_did: DID,
    /// HPKE encapsulated key (`enc`).
    #[serde(with = "serde_bytes")]
    pub enc: Vec<u8>,
    /// HPKE ciphertext (`ct = ciphertext || tag`) of the serialized bundle.
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

impl SealedInvitation {
    /// Serializes to the `MessagePack` delivery envelope.
    ///
    /// # Errors
    ///
    /// Returns the `rmp_serde` error string on failure.
    pub fn to_wire_bytes(&self) -> Result<Vec<u8>, String> {
        rmp_serde::to_vec_named(self).map_err(|e| e.to_string())
    }

    /// Deserializes from the `MessagePack` delivery envelope.
    ///
    /// # Errors
    ///
    /// Returns the `rmp_serde` error string on failure.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, String> {
        rmp_serde::from_slice(bytes).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::time::Duration;

    use scp_protocol::context::InvitationBundle;
    use scp_protocol::context::params::{
        CeilingPolicy, ContextMode, FieldVisibility, GovernanceModel, MemoryScope,
        MetadataVisibilityPolicy, PromotionPolicy, TemplateId,
    };
    use scp_protocol::context::roles::Capability;

    use super::*;

    fn params_fixture() -> ContextParams {
        ContextParams {
            mode: ContextMode::Encrypted,
            ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
            ceiling_policy: CeilingPolicy::Immutable,
            promotion_policy: PromotionPolicy::NoPromotion,
            roles: Vec::new(),
            ttl: Some(Duration::from_mins(5)),
            memory_scope: MemoryScope::Ephemeral,
            governance: GovernanceModel::SingleAdmin,
            template_id: Some(TemplateId::BilateralEphemeral),
            ..ContextParams::default()
        }
    }

    #[test]
    fn snapshot_structural_matches_params_and_passes_consistency() {
        let params = params_fixture();
        let facts = SnapshotRuntimeFacts {
            member_count: Some(1),
            creator_did: Some(DID::from("did:dht:z6MkCreator")),
            ..SnapshotRuntimeFacts::default()
        };
        let snapshot = build_metadata_snapshot(&params, facts);

        // A minimal signed bundle carrying this snapshot must pass the
        // in-bundle structural-consistency predicate.
        let bundle = InvitationBundle {
            context_id: "ctx:x".to_owned(),
            creator_did: DID::from("did:dht:z6MkCreator"),
            relay_urls: vec![],
            welcome_message: vec![1, 2, 3],
            key_material: scp_protocol::context::InvitationKeyMaterial {
                context_metadata_key: [0u8; 32],
                sender_key_seed: None,
            },
            context_params: params,
            metadata_snapshot: snapshot,
            signature: vec![0u8; 64],
        };
        assert!(bundle.verify_structural_consistency().is_ok());
    }

    #[test]
    fn member_only_operational_fields_are_filtered() {
        let mut params = params_fixture();
        params.metadata_visibility = MetadataVisibilityPolicy {
            member_count: FieldVisibility::MemberOnly,
            creator_identity: FieldVisibility::MemberOnly,
            ..MetadataVisibilityPolicy::default()
        };
        let facts = SnapshotRuntimeFacts {
            member_count: Some(7),
            creator_did: Some(DID::from("did:dht:z6MkCreator")),
            name: Some("visible".to_owned()),
            ..SnapshotRuntimeFacts::default()
        };
        let snapshot = build_metadata_snapshot(&params, facts);
        assert_eq!(snapshot.operational.member_count, None);
        assert_eq!(snapshot.operational.creator_did, None);
        // `name` defaults to PreJoin, so it survives.
        assert_eq!(snapshot.operational.name.as_deref(), Some("visible"));
    }

    #[test]
    fn sealed_invitation_wire_round_trip() {
        let inv = SealedInvitation {
            context_id: "ctx:x".to_owned(),
            creator_did: DID::from("did:dht:z6MkCreator"),
            enc: vec![9u8; 32],
            ciphertext: vec![1, 2, 3, 4, 5],
        };
        let bytes = inv.to_wire_bytes().unwrap();
        let decoded = SealedInvitation::from_wire_bytes(&bytes).unwrap();
        assert_eq!(decoded, inv);
    }
}
