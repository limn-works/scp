//! Auto-accept policy persistence for SCP context invitations.
//!
//! Policies are stored locally via the SDK's [`Storage`] trait (same backend as
//! protocol state). Key convention: `policy/{identity_did}/auto_accept`. Policies
//! are device-local -- cross-device sync is not supported. Each device configures
//! independently. Policies are never transmitted over the network.
//!
//! On SDK initialization, policies are loaded from storage and applied to the
//! invitation evaluation pipeline.
//!
//! **Hard constraints (non-overridable):**
//! - Auto-accept NEVER applies to contexts whose ceiling includes any tool-related
//!   capability (`ToolInvokeAll`, `ToolInvoke(_)`, `ToolRegister`). See
//!   `.docs/standards/sdk-common.md` Auto-Accept Policies.
//! - Auto-accept NEVER applies to contexts with economic policy requiring payment.
//!   See `.docs/specs/19-economic-governance.md` section 19.3, 19.14.
//!
//! See `.docs/standards/sdk-common.md` section "Auto-Accept Policies" and
//! "Auto-accept persistence".

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::context::params::{Capability, ContextParams, TemplateId};
use crate::identity::DID;
use scp_platform::traits::Storage;
use scp_platform::PlatformError;

// ---------------------------------------------------------------------------
// Storage key convention
// ---------------------------------------------------------------------------

/// Builds the storage key for an identity's auto-accept policy.
///
/// Key convention: `policy/{identity_did}/auto_accept`.
fn storage_key(identity: &DID) -> String {
    format!("policy/{}/auto_accept", identity.0)
}

// ---------------------------------------------------------------------------
// TrustRequirement
// ---------------------------------------------------------------------------

/// Trust requirement for auto-accept policy evaluation.
///
/// Determines the minimum trust level an inviter must meet for the policy to
/// trigger automatic acceptance. See `.docs/standards/sdk-common.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustRequirement {
    /// Accept from any identity. Least restrictive.
    Any,
    /// Accept only from identities that share at least one active context
    /// with this identity.
    SharedContext,
    /// Accept only from identities explicitly listed by DID.
    Explicit(Vec<DID>),
}

// ---------------------------------------------------------------------------
// RateLimit
// ---------------------------------------------------------------------------

/// Rate limit for auto-accept policy evaluation.
///
/// Limits how frequently auto-accept can trigger within a rolling window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimit {
    /// Maximum number of auto-accepts allowed within `window`.
    pub max_count: u32,
    /// Rolling window duration.
    pub window: Duration,
}

impl RateLimit {
    /// Creates a rate limit of `count` auto-accepts per hour.
    #[must_use]
    pub fn per_hour(count: u32) -> Self {
        Self {
            max_count: count,
            window: Duration::from_secs(3600),
        }
    }
}

// ---------------------------------------------------------------------------
// AutoAcceptPolicy
// ---------------------------------------------------------------------------

/// Auto-accept policy for incoming context invitations.
///
/// Configured per-identity and stored locally (never transmitted). When the
/// SDK receives a context invitation, the auto-accept evaluation pipeline
/// checks for a matching policy. If all conditions pass, the invitation is
/// accepted automatically.
///
/// See `.docs/standards/sdk-common.md` section "Auto-Accept Policies".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoAcceptPolicy {
    /// The template this policy applies to. Only invitations for contexts
    /// matching this template trigger auto-accept evaluation.
    pub template: TemplateId,
    /// Trust requirement the inviter must satisfy.
    pub from: TrustRequirement,
    /// Maximum TTL for auto-accepted contexts. Invitations for contexts with
    /// TTL exceeding this value are not auto-accepted. `None` means no TTL cap.
    pub max_ttl: Option<Duration>,
    /// Rate limit on auto-accept triggers. `None` means no rate limit.
    pub rate_limit: Option<RateLimit>,
}

// ---------------------------------------------------------------------------
// Hard rule checks
// ---------------------------------------------------------------------------

/// Returns `true` if the context params contain any tool-related capability
/// in the ceiling.
///
/// Tool-related capabilities: `ToolInvokeAll`, `ToolInvoke(_)`, `ToolRegister`.
///
/// **Non-overridable hard constraint:** Auto-accept NEVER applies to contexts
/// whose ceiling includes any of these capabilities. See
/// `.docs/standards/sdk-common.md`.
#[must_use]
pub fn has_tool_capabilities(params: &ContextParams) -> bool {
    params.ceiling.iter().any(|cap| matches!(
        cap,
        Capability::ToolInvokeAll | Capability::ToolInvoke(_) | Capability::ToolRegister
    ))
}

/// Returns `true` if the context params have an economic policy that requires
/// payment (any non-zero cost in the cost schedule).
///
/// **Non-overridable hard constraint:** Auto-accept NEVER applies to contexts
/// with economic policy requiring payment. See
/// `.docs/specs/19-economic-governance.md` section 19.3, 19.14.
#[must_use]
pub fn requires_payment(params: &ContextParams) -> bool {
    let Some(ref econ) = params.economic_policy else {
        return false;
    };
    let cs = &econ.cost_schedule;
    cs.per_message.is_some()
        || cs.per_tool_invoke.is_some()
        || cs.per_join.is_some()
        || cs.per_period.is_some()
        || cs.per_byte_stored.is_some()
}

/// Checks whether auto-accept is allowed for the given context params.
///
/// Returns `false` if any hard constraint is violated:
/// - Context ceiling includes tool-related capabilities.
/// - Context has an economic policy requiring payment.
///
/// Returns `true` if auto-accept evaluation may proceed (further checks like
/// template match, trust requirement, TTL cap, and rate limit are the caller's
/// responsibility).
#[must_use]
pub fn auto_accept_allowed(params: &ContextParams) -> bool {
    !has_tool_capabilities(params) && !requires_payment(params)
}

// ---------------------------------------------------------------------------
// StorageError wrapper
// ---------------------------------------------------------------------------

/// Error type for auto-accept policy storage operations.
///
/// Wraps [`PlatformError`] to provide a dedicated error type for policy
/// persistence, keeping the API clean and following the SCP error hierarchy
/// pattern.
#[derive(Debug, thiserror::Error)]
pub enum PolicyStorageError {
    /// The underlying storage operation failed.
    #[error("policy storage error: {0}")]
    Storage(#[from] PlatformError),

    /// Serialization or deserialization of the policy failed.
    #[error("policy serialization error: {0}")]
    Serialization(String),
}

// ---------------------------------------------------------------------------
// CRUD operations
// ---------------------------------------------------------------------------

/// Persists an auto-accept policy for the given identity.
///
/// Storage key: `policy/{identity_did}/auto_accept`. Overwrites any existing
/// policy for this identity.
///
/// # Errors
///
/// Returns [`PolicyStorageError`] if the storage write or serialization fails.
pub async fn set_auto_accept_policy(
    storage: &impl Storage,
    identity: &DID,
    policy: &AutoAcceptPolicy,
) -> Result<(), PolicyStorageError> {
    let key = storage_key(identity);
    let data = serde_json::to_vec(policy)
        .map_err(|e| PolicyStorageError::Serialization(e.to_string()))?;
    storage.store(&key, &data).await?;
    Ok(())
}

/// Retrieves the auto-accept policy for the given identity.
///
/// Returns `None` if no policy is configured (opt-in model).
///
/// # Errors
///
/// Returns [`PolicyStorageError`] if the storage read or deserialization fails.
pub async fn get_auto_accept_policy(
    storage: &impl Storage,
    identity: &DID,
) -> Result<Option<AutoAcceptPolicy>, PolicyStorageError> {
    let key = storage_key(identity);
    let data = storage.retrieve(&key).await?;
    match data {
        None => Ok(None),
        Some(bytes) => {
            let policy = serde_json::from_slice(&bytes)
                .map_err(|e| PolicyStorageError::Serialization(e.to_string()))?;
            Ok(Some(policy))
        }
    }
}

/// Deletes the auto-accept policy for the given identity.
///
/// No-op if no policy exists.
///
/// # Errors
///
/// Returns [`PolicyStorageError`] if the storage delete fails.
pub async fn delete_auto_accept_policy(
    storage: &impl Storage,
    identity: &DID,
) -> Result<(), PolicyStorageError> {
    let key = storage_key(identity);
    storage.delete(&key).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::context::params::ContextParams;
    use crate::economy::{Amount, CostSchedule, CurrencyCode, EconomicPolicy};
    use scp_platform::testing::InMemoryStorage;

    // --- CRUD roundtrip ---

    #[tokio::test]
    async fn set_and_get_roundtrip() {
        let storage = InMemoryStorage::new();
        let identity = DID::from("did:dht:z6MkAlice");
        let policy = AutoAcceptPolicy {
            template: TemplateId::BilateralEphemeral,
            from: TrustRequirement::SharedContext,
            max_ttl: Some(Duration::from_secs(600)),
            rate_limit: Some(RateLimit::per_hour(5)),
        };

        set_auto_accept_policy(&storage, &identity, &policy).await.unwrap();
        let retrieved = get_auto_accept_policy(&storage, &identity).await.unwrap();
        assert_eq!(retrieved, Some(policy));
    }

    // --- Persistence across re-initialization ---

    #[tokio::test]
    async fn policy_persists_across_reinitialization() {
        // InMemoryStorage simulates a persistent backend: the same instance
        // represents the same storage. Re-accessing via the CRUD functions
        // after "re-initialization" (a fresh function call stack) must return
        // the same data.
        let storage = InMemoryStorage::new();
        let identity = DID::from("did:dht:z6MkBob");
        let policy = AutoAcceptPolicy {
            template: TemplateId::BilateralPersistent,
            from: TrustRequirement::Any,
            max_ttl: None,
            rate_limit: None,
        };

        // "First initialization" — set the policy.
        set_auto_accept_policy(&storage, &identity, &policy).await.unwrap();

        // "Second initialization" — read from same storage (simulates restart
        // where the storage backend persists).
        let retrieved = get_auto_accept_policy(&storage, &identity).await.unwrap();
        assert_eq!(retrieved, Some(policy));
    }

    // --- Absent policy returns None ---

    #[tokio::test]
    async fn absent_policy_returns_none() {
        let storage = InMemoryStorage::new();
        let identity = DID::from("did:dht:z6MkNoPolicy");
        let retrieved = get_auto_accept_policy(&storage, &identity).await.unwrap();
        assert_eq!(retrieved, None);
    }

    // --- Delete policy ---

    #[tokio::test]
    async fn delete_removes_policy() {
        let storage = InMemoryStorage::new();
        let identity = DID::from("did:dht:z6MkAlice");
        let policy = AutoAcceptPolicy {
            template: TemplateId::BilateralEphemeral,
            from: TrustRequirement::Any,
            max_ttl: None,
            rate_limit: None,
        };

        set_auto_accept_policy(&storage, &identity, &policy).await.unwrap();
        delete_auto_accept_policy(&storage, &identity).await.unwrap();
        let retrieved = get_auto_accept_policy(&storage, &identity).await.unwrap();
        assert_eq!(retrieved, None);
    }

    #[tokio::test]
    async fn delete_nonexistent_is_noop() {
        let storage = InMemoryStorage::new();
        let identity = DID::from("did:dht:z6MkNobody");
        // Should not error.
        delete_auto_accept_policy(&storage, &identity).await.unwrap();
    }

    // --- Hard rule: tool capabilities ---

    #[test]
    fn tool_capability_blocks_auto_accept() {
        let params = ContextParams {
            ceiling: vec![
                Capability::MessagesRead,
                Capability::MessagesWrite,
                Capability::ToolInvokeAll,
            ],
            ..ContextParams::default()
        };
        assert!(has_tool_capabilities(&params));
        assert!(!auto_accept_allowed(&params));
    }

    #[test]
    fn tool_invoke_specific_blocks_auto_accept() {
        let params = ContextParams {
            ceiling: vec![
                Capability::MessagesRead,
                Capability::ToolInvoke("search".to_owned()),
            ],
            ..ContextParams::default()
        };
        assert!(has_tool_capabilities(&params));
        assert!(!auto_accept_allowed(&params));
    }

    #[test]
    fn tool_register_blocks_auto_accept() {
        let params = ContextParams {
            ceiling: vec![
                Capability::MessagesRead,
                Capability::ToolRegister,
            ],
            ..ContextParams::default()
        };
        assert!(has_tool_capabilities(&params));
        assert!(!auto_accept_allowed(&params));
    }

    #[test]
    fn no_tool_capability_allows_auto_accept() {
        let params = ContextParams {
            ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
            ..ContextParams::default()
        };
        assert!(!has_tool_capabilities(&params));
        assert!(auto_accept_allowed(&params));
    }

    // --- Hard rule: economic policy ---

    #[test]
    fn paid_context_blocks_auto_accept() {
        let params = ContextParams {
            ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
            economic_policy: Some(EconomicPolicy {
                locked: false,
                cost_schedule: CostSchedule {
                    currency: CurrencyCode::from("USD"),
                    per_message: Some(Amount(1)),
                    per_tool_invoke: None,
                    per_join: None,
                    per_period: None,
                    per_byte_stored: None,
                },
                payment_adapters: vec!["x402".to_owned()],
                pricing_formula: None,
                payee: DID::from("did:dht:z6MkPayee"),
            }),
            ..ContextParams::default()
        };
        assert!(requires_payment(&params));
        assert!(!auto_accept_allowed(&params));
    }

    #[test]
    fn free_context_allows_auto_accept() {
        let params = ContextParams {
            ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
            economic_policy: None,
            ..ContextParams::default()
        };
        assert!(!requires_payment(&params));
        assert!(auto_accept_allowed(&params));
    }

    #[test]
    fn economic_policy_with_no_costs_allows_auto_accept() {
        // Economic policy present but all cost fields are None (free context).
        let params = ContextParams {
            ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
            economic_policy: Some(EconomicPolicy {
                locked: true,
                cost_schedule: CostSchedule {
                    currency: CurrencyCode::from("USD"),
                    per_message: None,
                    per_tool_invoke: None,
                    per_join: None,
                    per_period: None,
                    per_byte_stored: None,
                },
                payment_adapters: vec![],
                pricing_formula: None,
                payee: DID::from("did:dht:z6MkFree"),
            }),
            ..ContextParams::default()
        };
        assert!(!requires_payment(&params));
        assert!(auto_accept_allowed(&params));
    }

    // --- Combined hard rules ---

    #[test]
    fn tool_and_payment_both_block_auto_accept() {
        let params = ContextParams {
            ceiling: vec![
                Capability::MessagesRead,
                Capability::MessagesWrite,
                Capability::ToolInvokeAll,
            ],
            economic_policy: Some(EconomicPolicy {
                locked: false,
                cost_schedule: CostSchedule {
                    currency: CurrencyCode::from("USD"),
                    per_message: None,
                    per_tool_invoke: Some(Amount(10)),
                    per_join: None,
                    per_period: None,
                    per_byte_stored: None,
                },
                payment_adapters: vec!["x402".to_owned()],
                pricing_formula: None,
                payee: DID::from("did:dht:z6MkPayee"),
            }),
            ..ContextParams::default()
        };
        assert!(has_tool_capabilities(&params));
        assert!(requires_payment(&params));
        assert!(!auto_accept_allowed(&params));
    }

    // --- Storage key format ---

    #[test]
    fn storage_key_format() {
        let did = DID::from("did:dht:z6MkAlice");
        assert_eq!(storage_key(&did), "policy/did:dht:z6MkAlice/auto_accept");
    }

    // --- Serialization roundtrip ---

    #[test]
    fn auto_accept_policy_serde_roundtrip() {
        let policy = AutoAcceptPolicy {
            template: TemplateId::BilateralEphemeral,
            from: TrustRequirement::SharedContext,
            max_ttl: Some(Duration::from_secs(600)),
            rate_limit: Some(RateLimit::per_hour(5)),
        };
        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: AutoAcceptPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, deserialized);
    }

    #[test]
    fn trust_requirement_explicit_serde_roundtrip() {
        let policy = AutoAcceptPolicy {
            template: TemplateId::Coordination,
            from: TrustRequirement::Explicit(vec![
                DID::from("did:dht:z6MkAlice"),
                DID::from("did:dht:z6MkBob"),
            ]),
            max_ttl: None,
            rate_limit: None,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: AutoAcceptPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, deserialized);
    }

    // --- Multiple identities have independent policies ---

    #[tokio::test]
    async fn multiple_identities_independent_policies() {
        let storage = InMemoryStorage::new();
        let alice = DID::from("did:dht:z6MkAlice");
        let bob = DID::from("did:dht:z6MkBob");

        let alice_policy = AutoAcceptPolicy {
            template: TemplateId::BilateralEphemeral,
            from: TrustRequirement::Any,
            max_ttl: Some(Duration::from_secs(300)),
            rate_limit: None,
        };
        let bob_policy = AutoAcceptPolicy {
            template: TemplateId::BilateralPersistent,
            from: TrustRequirement::SharedContext,
            max_ttl: None,
            rate_limit: Some(RateLimit::per_hour(10)),
        };

        set_auto_accept_policy(&storage, &alice, &alice_policy).await.unwrap();
        set_auto_accept_policy(&storage, &bob, &bob_policy).await.unwrap();

        let retrieved_alice = get_auto_accept_policy(&storage, &alice).await.unwrap();
        let retrieved_bob = get_auto_accept_policy(&storage, &bob).await.unwrap();

        assert_eq!(retrieved_alice, Some(alice_policy));
        assert_eq!(retrieved_bob, Some(bob_policy));
    }

    // --- Overwrite existing policy ---

    #[tokio::test]
    async fn set_overwrites_existing_policy() {
        let storage = InMemoryStorage::new();
        let identity = DID::from("did:dht:z6MkAlice");

        let policy_v1 = AutoAcceptPolicy {
            template: TemplateId::BilateralEphemeral,
            from: TrustRequirement::Any,
            max_ttl: None,
            rate_limit: None,
        };
        let policy_v2 = AutoAcceptPolicy {
            template: TemplateId::BilateralPersistent,
            from: TrustRequirement::SharedContext,
            max_ttl: Some(Duration::from_secs(600)),
            rate_limit: Some(RateLimit::per_hour(3)),
        };

        set_auto_accept_policy(&storage, &identity, &policy_v1).await.unwrap();
        set_auto_accept_policy(&storage, &identity, &policy_v2).await.unwrap();

        let retrieved = get_auto_accept_policy(&storage, &identity).await.unwrap();
        assert_eq!(retrieved, Some(policy_v2));
    }

    // --- Per-join cost blocks auto-accept ---

    #[test]
    fn per_join_cost_blocks_auto_accept() {
        let params = ContextParams {
            ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
            economic_policy: Some(EconomicPolicy {
                locked: false,
                cost_schedule: CostSchedule {
                    currency: CurrencyCode::from("USD"),
                    per_message: None,
                    per_tool_invoke: None,
                    per_join: Some(Amount(100)),
                    per_period: None,
                    per_byte_stored: None,
                },
                payment_adapters: vec!["x402".to_owned()],
                pricing_formula: None,
                payee: DID::from("did:dht:z6MkPayee"),
            }),
            ..ContextParams::default()
        };
        assert!(requires_payment(&params));
        assert!(!auto_accept_allowed(&params));
    }
}
