//! SCP protocol + runtime — unified API surface.
//!
//! Merges [`scp_protocol`] (pure sync types) and [`scp_runtime`] (async
//! orchestration) into a single namespace. Downstream crates depend on
//! `scp-core` alone.
//!
//! MAINTENANCE: When adding a public module to scp-protocol or scp-runtime,
//! add the corresponding re-export here. The CI check and structural test
//! in `tests/facade_completeness.rs` will catch omissions.

// --- Modules that exist ONLY in scp-protocol (no conflict) ---
pub use scp_protocol::jcs;
pub use scp_protocol::serde_util;
pub use scp_protocol::time;
pub use scp_protocol::uri;

// --- Modules that exist ONLY in scp-runtime (no conflict) ---
pub use scp_runtime::event_log;
pub use scp_runtime::metrics;
pub use scp_runtime::store;
pub use scp_runtime::well_known;

// --- Modules split across both crates (explicit sub-module merging) ---

pub mod crypto {
    pub use scp_protocol::crypto::canonical;
    pub use scp_protocol::crypto::ed25519;
    pub use scp_protocol::crypto::envelope_seal;
    pub use scp_protocol::crypto::key_continuity;
    pub use scp_protocol::crypto::tofu;
    pub use scp_runtime::crypto::mls;
    pub mod sender_keys {
        pub use scp_protocol::crypto::sender_keys::*;
        pub use scp_runtime::crypto::sender_keys::key_protocol;
        pub use scp_runtime::crypto::sender_keys::key_protocol::{
            handle_sender_key_request, open_sender_key_response, publish_sender_key_epoch_advance,
            request_sender_key, send_block_notification,
        };
    }
    pub mod access_keys {
        pub use scp_protocol::crypto::access_keys::*;
        pub use scp_runtime::crypto::access_keys::lifecycle;
        pub use scp_runtime::crypto::access_keys::wire;
    }
    pub mod ucan {
        pub use scp_protocol::crypto::ucan::*;
        pub use scp_runtime::crypto::ucan::mint;
    }
}

pub mod context {
    // All pure types from scp-protocol::context (includes params, roles, etc.)
    pub use scp_protocol::context::*;
    // Async modules from scp-runtime
    pub use scp_runtime::context::app_sandbox;
    pub use scp_runtime::context::builder;
    pub use scp_runtime::context::export_import;
    pub use scp_runtime::context::manager;
    pub use scp_runtime::context::policy;
    pub use scp_runtime::context::providers;
    pub use scp_runtime::context::ttl;
    pub use scp_runtime::context::ttl::{
        ExtensionConsentMode, TtlExtensionProposal, check_ttl, consent_mode_for_member_count,
    };
    // Key runtime types re-exported at this level.
    pub use scp_protocol::context::builder::{
        AddMemberOutput, ContextCreationError, ContextCryptoProvider,
    };
    pub use scp_runtime::context::ContextHandle;
    pub use scp_runtime::context::builder::{
        ContextEventLogProvider, ContextTransportProvider, LocalTransportProvider,
        NotConfiguredTransportProvider,
    };
    pub use scp_runtime::context::manager::ContextManager;
    // Broadcast content types (previously at context level).
    pub use scp_protocol::context::broadcast_content::{
        BROADCAST_CONTENT_MAGIC, BROADCAST_CONTENT_VERSION, BroadcastContent,
        BroadcastContentError, ContentMetadata, ContentPath, MimeType, compute_etag,
        deserialize_broadcast_content, serialize_broadcast_content, validate_deploy_id,
        verify_etag,
    };
    pub mod governance {
        pub use scp_protocol::context::governance::*;
        pub use scp_runtime::context::governance::timeout;
    }
    pub mod tools {
        pub use scp_protocol::context::tools::*;
        pub use scp_runtime::context::tools::invoke;
        pub use scp_runtime::context::tools::invoke::{
            InvocationError, has_tool_invoke_capability, invoke_tool,
            invoke_tool_with_cancellation, validate_tool_invocation_ucan,
        };
        pub use scp_runtime::context::tools::session;
        pub use scp_runtime::context::tools::session::{
            DEFAULT_SESSION_CAP_PER_CALLER, SessionStore, ToolSession, cleanup_expired,
            create_session, invoke_session,
        };
    }
}

pub mod trust {
    pub use scp_protocol::trust::*;
    pub use scp_runtime::trust::ProtocolRepositoryTrustBridge;
    // Re-export all submodule types at this level for backward compatibility.
    pub use scp_protocol::trust::admission::{
        AdmissionError, CapabilityRequirement, VerificationLevel, check_capability_requirements,
    };
    pub use scp_protocol::trust::attestation::{
        Attestation, AttestationEvidence, AttestationRevocationChecker, AttestorInfo,
        DidPublicKeyResolver, FreshnessStatus, IdentityDidPublicKeyResolver, NoOpRevocationChecker,
        RevocationStatus, ThresholdRequirement, ThresholdResult, check_attestation_freshness,
        check_threshold_attestation, verify_attestation, verify_attestation_with_revocation,
    };
    pub use scp_protocol::trust::challenge::{
        ChallengeRequest, ChallengeResponse, ChallengeSigner, ChallengeType, ChallengeVerification,
        VerificationMethod, issue_challenge, verify_challenge_response,
    };
    pub use scp_protocol::trust::consequence::{
        ConsequenceAction, ConsequenceEvidence, ConsequenceRule, ConsequenceTrigger,
        ConsequenceValidationError, TriggeredConsequence, evaluate_consequence_rules,
    };
    pub use scp_protocol::trust::participation::{
        PARTICIPATION_STATEMENTS_SERVICE_TYPE, ParticipationFact, ParticipationProfile,
        ParticipationRecord, ParticipationThreshold, RequireParticipation,
        compute_participation_record, verify_participation_requirements,
    };
    pub use scp_protocol::trust::sybil::{
        ContextSybilPolicy, RequiredSignal, SybilResistanceError, evaluate_sybil_resistance,
    };
}

pub mod identity {
    pub use scp_protocol::identity::*;
    pub use scp_runtime::identity::blocking;
    pub use scp_runtime::identity::custody_migration;
    pub use scp_runtime::identity::recovery;
    pub use scp_runtime::identity::scpid;
    pub use scp_runtime::identity::scpid::{
        ScpIdChallenge, ScpIdError, ScpIdResponse, scpid_challenge, scpid_sign, scpid_verify,
    };
}

pub mod economy {
    pub use scp_protocol::economy::*;
    // Re-export all items from each submodule at this level.
    pub use scp_protocol::economy::antispam::*;
    pub use scp_protocol::economy::budget::*;
    pub use scp_protocol::economy::estimate::*;
    pub use scp_protocol::economy::policy::*;
    pub use scp_protocol::economy::pricing::*;
    pub use scp_protocol::economy::types::*;
    // Async modules from scp-runtime.
    pub use scp_runtime::economy::adapter;
    pub use scp_runtime::economy::adapter::*;
    pub use scp_runtime::economy::credentials;
    pub use scp_runtime::economy::integration;
    pub use scp_runtime::economy::integration::*;
    pub use scp_runtime::economy::receipt;
}

pub mod discovery {
    pub use scp_protocol::discovery::*;
    // Re-export all items from each submodule at this level.
    // Note: handles::* and petnames::* items are already re-exported
    // from scp_protocol::discovery via pub use statements in mod.rs.
    pub use scp_protocol::discovery::context::*;
    pub use scp_protocol::discovery::push::*;
    pub use scp_protocol::discovery::scope::*;
    // Async modules from scp-runtime.
    pub use scp_runtime::discovery::addressing;
    pub use scp_runtime::discovery::addressing::*;
    pub use scp_runtime::discovery::bootstrap;
    pub use scp_runtime::discovery::bootstrap::*;
    pub use scp_runtime::discovery::dht_context;
    pub use scp_runtime::discovery::dht_context::*;
    pub use scp_runtime::discovery::did_capabilities;
    pub use scp_runtime::discovery::search;
}

pub mod envelope {
    pub use scp_protocol::envelope::*;
    pub use scp_runtime::envelope::pseudonym;
    pub use scp_runtime::envelope::pseudonym::derive_pseudonym;
    pub mod inner {
        pub use scp_protocol::envelope::inner::*;
        pub use scp_runtime::envelope::inner::sign;
        pub use scp_runtime::envelope::inner::sign::create_inner_envelope;
    }
    pub mod outer {
        pub use scp_protocol::envelope::outer::*;
        pub use scp_runtime::envelope::outer::ops;
        pub use scp_runtime::envelope::outer::ops::{open_envelope, seal_envelope};
    }
    pub use scp_runtime::envelope::inner::sign::create_inner_envelope;
    pub use scp_runtime::envelope::outer::ops::seal_envelope;
}

pub mod sync {
    pub use scp_protocol::sync::*;
    pub use scp_runtime::sync::days_offline;
    pub use scp_runtime::sync::hours_offline;
    pub use scp_runtime::sync::weeks_offline;
}

pub mod bridge {
    pub use scp_protocol::bridge::*;
    pub use scp_runtime::bridge::credentials;
    pub use scp_runtime::bridge::oauth;
}

pub mod provenance {
    pub use scp_protocol::provenance::*;
}
