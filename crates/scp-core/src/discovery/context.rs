//! Discovery context standard tool implementations and two-tier membership.
//!
//! Discovery contexts are standard SCP contexts with standardized tool schemas
//! for search, registration, and deregistration. Two-tier membership separates
//! writers (MLS members, bounded at 500) from readers (DID-authenticated,
//! unbounded).
//!
//! Standard tool schemas (conventions per ADR-020):
//! - `agent_search(query) -> { results }` -- search the registry.
//! - `agent_register(did, capabilities, metadata) -> { registered, entry_id }` -- register an agent.
//! - `agent_deregister(did) -> { removed }` -- deregister an agent.
//!
//! Custom tools (reputation scoring, category browsing, geographic filtering)
//! are allowed beyond the standard set.
//!
//! See ADR-020 in `.docs/adrs/phase-4.md`, acceptance criteria 3-10.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::{ContextId, DID, RegistrationEntry};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of writer-tier (MLS) members in a discovery context.
pub const MAX_WRITERS: usize = 500;

/// Standard tool name for agent search.
pub const TOOL_AGENT_SEARCH: &str = "agent_search";

/// Standard tool name for agent registration.
pub const TOOL_AGENT_REGISTER: &str = "agent_register";

/// Standard tool name for agent deregistration.
pub const TOOL_AGENT_DEREGISTER: &str = "agent_deregister";

// ---------------------------------------------------------------------------
// MembershipTier
// ---------------------------------------------------------------------------

/// Membership tier in a discovery context.
///
/// Writers are MLS group members who process registrations and manage the
/// registry. Readers are DID-authenticated participants who can query via
/// tool endpoints without joining the MLS group.
///
/// See ADR-020 acceptance criterion 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MembershipTier {
    /// MLS group member. Can process registrations and record events.
    /// Bounded at [`MAX_WRITERS`].
    Writer,
    /// DID-authenticated reader. Can query via tool endpoints. Unbounded.
    Reader,
}

// ---------------------------------------------------------------------------
// DiscoveryContextError
// ---------------------------------------------------------------------------

/// Errors produced by discovery context operations.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryContextError {
    /// The writer tier is at capacity.
    #[error("writer tier full: maximum {MAX_WRITERS} writers allowed")]
    WriterTierFull,

    /// The DID is not authenticated (empty or malformed).
    #[error("DID not authenticated: \"{did}\"")]
    DidNotAuthenticated {
        /// The DID that failed authentication.
        did: String,
    },

    /// The agent is already registered.
    #[error("agent already registered: \"{did}\"")]
    AlreadyRegistered {
        /// The DID that is already registered.
        did: String,
    },

    /// The agent is not registered (for update/deregister operations).
    #[error("agent not registered: \"{did}\"")]
    NotRegistered {
        /// The DID that is not registered.
        did: String,
    },

    /// The requester DID does not match the entry owner DID.
    #[error("DID mismatch: requester \"{requester}\" does not own entry for \"{owner}\"")]
    OwnershipMismatch {
        /// The DID of the requester.
        requester: String,
        /// The DID of the entry owner.
        owner: String,
    },

    /// The requester is not a writer and cannot perform this operation.
    #[error("writer tier required for this operation")]
    WriterRequired,

    /// A custom tool name conflicts with a standard tool name.
    #[error("tool name \"{name}\" conflicts with standard discovery tool")]
    StandardToolConflict {
        /// The conflicting tool name.
        name: String,
    },
}

// ---------------------------------------------------------------------------
// AgentSearchParams
// ---------------------------------------------------------------------------

/// Parameters for the `agent_search` standard tool.
///
/// All fields are optional filters. An empty query matches all entries.
///
/// See ADR-020 acceptance criterion 3.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentSearchParams {
    /// Filter by capability strings. Only agents advertising all listed
    /// capabilities are returned.
    pub capability_filter: Option<Vec<String>>,
    /// Free-text keyword filter applied to metadata.
    pub keywords: Option<Vec<String>>,
    /// Maximum number of results to return.
    pub limit: Option<usize>,
}

// ---------------------------------------------------------------------------
// AgentSearchResult
// ---------------------------------------------------------------------------

/// Result of an `agent_search` tool invocation.
///
/// See ADR-020 acceptance criterion 3.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentSearchResult {
    /// Matching registration entries.
    pub entries: Vec<RegistrationEntry>,
    /// Total number of matches (may exceed `entries.len()` if limited).
    pub total_matches: usize,
}

// ---------------------------------------------------------------------------
// AgentRegisterParams
// ---------------------------------------------------------------------------

/// Parameters for the `agent_register` standard tool.
///
/// Sent as a DID-signed request by a reader. A writer verifies the signature
/// and records the registration in the event log as an application message.
/// The registrant does NOT become an MLS member.
///
/// See ADR-020 acceptance criterion 5.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentRegisterParams {
    /// The DID of the agent to register.
    pub did: DID,
    /// Capabilities to advertise in this registry.
    pub capabilities: Vec<String>,
    /// Arbitrary metadata for the registration.
    pub metadata: serde_json::Value,
}

// ---------------------------------------------------------------------------
// AgentRegisterResult
// ---------------------------------------------------------------------------

/// Result of an `agent_register` tool invocation.
///
/// See ADR-020 acceptance criterion 5.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentRegisterResult {
    /// Whether the registration was successful.
    pub registered: bool,
    /// The unique entry ID assigned to the registration.
    pub entry_id: String,
}

// ---------------------------------------------------------------------------
// AgentDeregisterParams
// ---------------------------------------------------------------------------

/// Parameters for the `agent_deregister` standard tool.
///
/// Privacy: registration is withdrawable via this tool. The agent must
/// authenticate as the entry owner.
///
/// See ADR-020 acceptance criterion 9.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentDeregisterParams {
    /// The DID of the agent to deregister.
    pub did: DID,
}

// ---------------------------------------------------------------------------
// AgentDeregisterResult
// ---------------------------------------------------------------------------

/// Result of an `agent_deregister` tool invocation.
///
/// See ADR-020 acceptance criterion 9.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentDeregisterResult {
    /// Whether the entry was removed.
    pub removed: bool,
}

// ---------------------------------------------------------------------------
// RegistrationEvent
// ---------------------------------------------------------------------------

/// Event payload for registration operations recorded in the Merkle event log.
///
/// All writes to the discovery context are recorded in the context's Merkle
/// event log (ADR-011). Readers can request inclusion proofs to verify
/// registration and audit registry integrity.
///
/// See ADR-020 acceptance criterion 10.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RegistrationEvent {
    /// An agent was registered.
    Registered {
        /// The registration entry.
        entry: RegistrationEntry,
        /// The DID of the writer that processed the registration.
        processed_by: DID,
    },
    /// An agent's registration was updated.
    Updated {
        /// The updated registration entry.
        entry: RegistrationEntry,
        /// The DID of the writer that processed the update.
        processed_by: DID,
    },
    /// An agent was deregistered.
    Deregistered {
        /// The DID of the deregistered agent.
        did: DID,
        /// The entry ID that was removed.
        entry_id: String,
        /// The DID of the writer that processed the deregistration.
        processed_by: DID,
    },
}

// ---------------------------------------------------------------------------
// DiscoveryContext
// ---------------------------------------------------------------------------

/// A discovery context: a standard SCP context with standardized tool schemas
/// and two-tier membership.
///
/// Writers (MLS members, bounded at [`MAX_WRITERS`]) process registrations as
/// MLS application messages. Readers (DID-authenticated, unbounded) query via
/// tool endpoints without MLS join.
///
/// See ADR-020 acceptance criteria 3-10.
pub struct DiscoveryContext {
    /// The context ID of this discovery context.
    context_id: ContextId,
    /// Writer-tier members (MLS group members).
    writers: Vec<DID>,
    /// Reader-tier members (DID-authenticated).
    readers: Vec<DID>,
    /// Registered agent entries, keyed by DID.
    registry: HashMap<DID, RegistrationEntry>,
    /// Event log of all registration operations, in order.
    events: Vec<RegistrationEvent>,
    /// Custom tool names registered beyond the standard set.
    custom_tools: Vec<String>,
    /// Monotonic counter for generating unique entry IDs.
    next_entry_id: u64,
}

impl DiscoveryContext {
    /// Creates a new discovery context with the given context ID and initial
    /// writer DID.
    ///
    /// The initial writer is the creator of the context.
    #[must_use]
    pub fn new(context_id: ContextId, creator_did: DID) -> Self {
        Self {
            context_id,
            writers: vec![creator_did],
            readers: Vec::new(),
            registry: HashMap::new(),
            events: Vec::new(),
            custom_tools: Vec::new(),
            next_entry_id: 1,
        }
    }

    /// Returns the context ID.
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Returns the current writers.
    #[must_use]
    pub fn writers(&self) -> &[DID] {
        &self.writers
    }

    /// Returns the current readers.
    #[must_use]
    pub fn readers(&self) -> &[DID] {
        &self.readers
    }

    /// Returns the number of registered entries.
    #[must_use]
    pub fn registry_len(&self) -> usize {
        self.registry.len()
    }

    /// Returns the recorded events.
    #[must_use]
    pub fn events(&self) -> &[RegistrationEvent] {
        &self.events
    }

    /// Returns the custom tool names.
    #[must_use]
    pub fn custom_tools(&self) -> &[String] {
        &self.custom_tools
    }

    /// Returns the membership tier for a given DID, or `None` if the DID
    /// is not a member.
    #[must_use]
    pub fn membership_tier(&self, did: &str) -> Option<MembershipTier> {
        if self.writers.iter().any(|w| w == did) {
            Some(MembershipTier::Writer)
        } else if self.readers.iter().any(|r| r == did) {
            Some(MembershipTier::Reader)
        } else {
            None
        }
    }

    /// Returns whether the given DID is a writer.
    #[must_use]
    pub fn is_writer(&self, did: &str) -> bool {
        self.writers.iter().any(|w| w == did)
    }

    /// Returns a registration entry by DID, if it exists.
    #[must_use]
    pub fn get_entry(&self, did: &str) -> Option<&RegistrationEntry> {
        self.registry.get(did)
    }

    // -- Writer management ------------------------------------------------

    /// Adds a writer to the discovery context (MLS member join).
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryContextError::WriterTierFull`] if the writer tier
    /// is at capacity ([`MAX_WRITERS`]).
    /// Returns [`DiscoveryContextError::DidNotAuthenticated`] if the DID is
    /// empty or does not start with `"did:"`.
    pub fn add_writer(&mut self, did: DID) -> Result<(), DiscoveryContextError> {
        validate_did(&did)?;

        if self.writers.len() >= MAX_WRITERS {
            return Err(DiscoveryContextError::WriterTierFull);
        }

        if !self.writers.iter().any(|w| w == &did) {
            self.writers.push(did);
        }

        Ok(())
    }

    // -- Reader management ------------------------------------------------

    /// Adds a reader to the discovery context (DID-authenticated).
    ///
    /// Readers are unbounded. Duplicate DIDs are ignored.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryContextError::DidNotAuthenticated`] if the DID is
    /// empty or does not start with `"did:"`.
    pub fn add_reader(&mut self, did: DID) -> Result<(), DiscoveryContextError> {
        validate_did(&did)?;

        if !self.readers.iter().any(|r| r == &did) {
            self.readers.push(did);
        }

        Ok(())
    }

    // -- Standard tool: agent_search --------------------------------------

    /// Executes the `agent_search` standard tool.
    ///
    /// Any DID-authenticated member (reader or writer) can search. All fields
    /// in [`AgentSearchParams`] are optional filters.
    ///
    /// See ADR-020 acceptance criterion 3.
    #[must_use]
    pub fn agent_search(&self, params: &AgentSearchParams) -> AgentSearchResult {
        let mut matches: Vec<&RegistrationEntry> = self.registry.values().collect();

        // Filter by capabilities (all must match).
        if let Some(ref caps) = params.capability_filter {
            matches.retain(|entry| {
                caps.iter()
                    .all(|cap| entry.capabilities.iter().any(|c| c == cap))
            });
        }

        // Filter by keywords (any keyword matches any capability or metadata).
        if let Some(ref keywords) = params.keywords {
            matches.retain(|entry| {
                keywords.iter().any(|kw| {
                    let kw_lower = kw.to_lowercase();
                    entry
                        .capabilities
                        .iter()
                        .any(|c| c.to_lowercase().contains(&kw_lower))
                        || entry
                            .metadata
                            .to_string()
                            .to_lowercase()
                            .contains(&kw_lower)
                })
            });
        }

        let total_matches = matches.len();

        // Apply limit.
        if let Some(limit) = params.limit {
            matches.truncate(limit);
        }

        AgentSearchResult {
            entries: matches.into_iter().cloned().collect(),
            total_matches,
        }
    }

    // -- Standard tool: agent_register ------------------------------------

    /// Executes the `agent_register` standard tool.
    ///
    /// Registration flow per ADR-020 acceptance criterion 5:
    /// 1. Reader sends DID-signed request.
    /// 2. Writer verifies signature and records in event log as application
    ///    message.
    /// 3. Registrant does NOT become an MLS member.
    ///
    /// The `writer_did` parameter is the DID of the writer processing the
    /// registration. The `params.did` is the registrant's DID. The caller
    /// is responsible for verifying the DID signature before calling this
    /// method.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryContextError::WriterRequired`] if `writer_did` is
    /// not a writer.
    /// Returns [`DiscoveryContextError::AlreadyRegistered`] if the agent is
    /// already registered.
    /// Returns [`DiscoveryContextError::DidNotAuthenticated`] if the
    /// registrant DID is invalid.
    pub fn agent_register(
        &mut self,
        params: &AgentRegisterParams,
        writer_did: &str,
        timestamp: u64,
    ) -> Result<AgentRegisterResult, DiscoveryContextError> {
        // Verify writer.
        if !self.is_writer(writer_did) {
            return Err(DiscoveryContextError::WriterRequired);
        }

        // Validate registrant DID.
        validate_did(&params.did)?;

        // Check for duplicate.
        if self.registry.contains_key(&params.did) {
            return Err(DiscoveryContextError::AlreadyRegistered {
                did: params.did.to_string(),
            });
        }

        // Generate entry ID.
        let entry_id = format!("reg-{}", self.next_entry_id);
        self.next_entry_id += 1;

        let entry = RegistrationEntry {
            did: params.did.clone(),
            capabilities: params.capabilities.clone(),
            metadata: params.metadata.clone(),
            entry_id: entry_id.clone(),
            registered_at: timestamp,
        };

        // Record event.
        self.events.push(RegistrationEvent::Registered {
            entry: entry.clone(),
            processed_by: writer_did.into(),
        });

        // Store entry.
        self.registry.insert(params.did.clone(), entry);

        Ok(AgentRegisterResult {
            registered: true,
            entry_id,
        })
    }

    // -- Self-service update ----------------------------------------------

    /// Updates a registered agent's entry via DID-authenticated request.
    ///
    /// Writers verify DID matches entry owner before applying update. The
    /// agent can publish different capability subsets to different registries.
    ///
    /// See ADR-020 acceptance criterion 6.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryContextError::WriterRequired`] if `writer_did` is
    /// not a writer.
    /// Returns [`DiscoveryContextError::NotRegistered`] if the agent is not
    /// registered.
    /// Returns [`DiscoveryContextError::OwnershipMismatch`] if the requester
    /// DID does not match the entry owner.
    pub fn agent_update(
        &mut self,
        requester_did: &str,
        capabilities: Vec<String>,
        metadata: serde_json::Value,
        writer_did: &str,
        timestamp: u64,
    ) -> Result<(), DiscoveryContextError> {
        // Verify writer.
        if !self.is_writer(writer_did) {
            return Err(DiscoveryContextError::WriterRequired);
        }

        // Look up existing entry.
        let entry = self.registry.get(requester_did).ok_or_else(|| {
            DiscoveryContextError::NotRegistered {
                did: requester_did.into(),
            }
        })?;

        // Verify ownership.
        if entry.did != requester_did {
            return Err(DiscoveryContextError::OwnershipMismatch {
                requester: requester_did.to_owned(),
                owner: entry.did.to_string(),
            });
        }

        let entry_id = entry.entry_id.clone();

        // Apply update.
        let updated_entry = RegistrationEntry {
            did: requester_did.into(),
            capabilities,
            metadata,
            entry_id,
            registered_at: timestamp,
        };

        // Record event.
        self.events.push(RegistrationEvent::Updated {
            entry: updated_entry.clone(),
            processed_by: writer_did.into(),
        });

        self.registry
            .insert(DID::from(requester_did), updated_entry);

        Ok(())
    }

    // -- Standard tool: agent_deregister ----------------------------------

    /// Executes the `agent_deregister` standard tool.
    ///
    /// Privacy: registration is opt-in per discovery context and withdrawable
    /// via this tool. The agent must authenticate as the entry owner.
    ///
    /// See ADR-020 acceptance criterion 9.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryContextError::WriterRequired`] if `writer_did` is
    /// not a writer.
    /// Returns [`DiscoveryContextError::NotRegistered`] if the agent is not
    /// registered.
    /// Returns [`DiscoveryContextError::OwnershipMismatch`] if the requester
    /// DID does not match the entry owner.
    pub fn agent_deregister(
        &mut self,
        params: &AgentDeregisterParams,
        requester_did: &str,
        writer_did: &str,
    ) -> Result<AgentDeregisterResult, DiscoveryContextError> {
        // Verify writer.
        if !self.is_writer(writer_did) {
            return Err(DiscoveryContextError::WriterRequired);
        }

        // Look up existing entry.
        let entry =
            self.registry
                .get(&params.did)
                .ok_or_else(|| DiscoveryContextError::NotRegistered {
                    did: params.did.to_string(),
                })?;

        // Verify ownership.
        if entry.did != requester_did {
            return Err(DiscoveryContextError::OwnershipMismatch {
                requester: requester_did.to_owned(),
                owner: entry.did.to_string(),
            });
        }

        let entry_id = entry.entry_id.clone();

        // Remove entry.
        self.registry.remove(&params.did);

        // Record event.
        self.events.push(RegistrationEvent::Deregistered {
            did: params.did.clone(),
            entry_id,
            processed_by: writer_did.into(),
        });

        Ok(AgentDeregisterResult { removed: true })
    }

    // -- Custom tools -----------------------------------------------------

    /// Registers a custom tool name beyond the standard set.
    ///
    /// Custom tools (reputation scoring, category browsing, geographic
    /// filtering) are allowed per ADR-020 acceptance criterion 3.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryContextError::StandardToolConflict`] if the name
    /// matches a standard tool name.
    pub fn register_custom_tool(&mut self, name: String) -> Result<(), DiscoveryContextError> {
        if is_standard_tool(&name) {
            return Err(DiscoveryContextError::StandardToolConflict { name });
        }

        if !self.custom_tools.iter().any(|t| t == &name) {
            self.custom_tools.push(name);
        }

        Ok(())
    }

    // -- Standard tool schemas (JSON) -------------------------------------

    /// Returns the JSON Schema for the `agent_search` tool.
    #[must_use]
    pub fn agent_search_schema() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "capability_filter": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by capability strings"
                },
                "keywords": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Free-text keyword filter"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results"
                }
            }
        })
    }

    /// Returns the JSON Schema for the `agent_register` tool.
    #[must_use]
    pub fn agent_register_schema() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "required": ["did", "capabilities"],
            "properties": {
                "did": {
                    "type": "string",
                    "description": "The DID of the agent to register"
                },
                "capabilities": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Capabilities to advertise"
                },
                "metadata": {
                    "type": "object",
                    "description": "Arbitrary metadata"
                }
            }
        })
    }

    /// Returns the JSON Schema for the `agent_deregister` tool.
    #[must_use]
    pub fn agent_deregister_schema() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "required": ["did"],
            "properties": {
                "did": {
                    "type": "string",
                    "description": "The DID of the agent to deregister"
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Validates that a DID is non-empty and starts with `"did:"`.
fn validate_did(did: &str) -> Result<(), DiscoveryContextError> {
    if did.is_empty() || !did.starts_with("did:") {
        return Err(DiscoveryContextError::DidNotAuthenticated {
            did: did.to_owned(),
        });
    }
    Ok(())
}

/// Returns whether a tool name matches one of the standard discovery tool
/// names.
fn is_standard_tool(name: &str) -> bool {
    matches!(
        name,
        TOOL_AGENT_SEARCH | TOOL_AGENT_REGISTER | TOOL_AGENT_DEREGISTER
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const WRITER_DID: &str = "did:dht:z6MkWriter";
    const READER_DID: &str = "did:dht:z6MkReader";
    const AGENT_A_DID: &str = "did:dht:z6MkAgentA";
    const AGENT_B_DID: &str = "did:dht:z6MkAgentB";
    const CTX_ID: &str = "ctx-discovery-test";

    fn new_ctx() -> DiscoveryContext {
        DiscoveryContext::new(CTX_ID.into(), WRITER_DID.into())
    }

    fn register_params(did: &str, caps: &[&str]) -> AgentRegisterParams {
        AgentRegisterParams {
            did: did.into(),
            capabilities: caps.iter().map(|s| (*s).to_owned()).collect(),
            metadata: serde_json::json!({}),
        }
    }

    // -- DiscoveryContext creation -----------------------------------------

    #[test]
    fn new_context_has_creator_as_writer() {
        let ctx = new_ctx();
        assert_eq!(ctx.writers().len(), 1);
        assert_eq!(ctx.writers()[0], WRITER_DID);
        assert!(ctx.readers().is_empty());
        assert_eq!(ctx.registry_len(), 0);
        assert_eq!(ctx.context_id(), CTX_ID);
    }

    #[test]
    fn membership_tier_returns_correct_tier() {
        let mut ctx = new_ctx();
        ctx.add_reader(READER_DID.into()).unwrap();

        assert_eq!(
            ctx.membership_tier(WRITER_DID),
            Some(MembershipTier::Writer)
        );
        assert_eq!(
            ctx.membership_tier(READER_DID),
            Some(MembershipTier::Reader)
        );
        assert_eq!(ctx.membership_tier("did:dht:z6MkUnknown"), None);
    }

    // -- Writer management ------------------------------------------------

    #[test]
    fn add_writer_succeeds() {
        let mut ctx = new_ctx();
        let second_writer = "did:dht:z6MkWriter2";
        ctx.add_writer(second_writer.into()).unwrap();
        assert_eq!(ctx.writers().len(), 2);
        assert!(ctx.is_writer(second_writer));
    }

    #[test]
    fn add_writer_deduplicates() {
        let mut ctx = new_ctx();
        ctx.add_writer(WRITER_DID.into()).unwrap();
        assert_eq!(ctx.writers().len(), 1);
    }

    #[test]
    fn add_writer_rejects_invalid_did() {
        let mut ctx = new_ctx();
        let result = ctx.add_writer(DID::from(""));
        assert!(matches!(
            result,
            Err(DiscoveryContextError::DidNotAuthenticated { .. })
        ));

        let result = ctx.add_writer("not-a-did".into());
        assert!(matches!(
            result,
            Err(DiscoveryContextError::DidNotAuthenticated { .. })
        ));
    }

    #[test]
    fn add_writer_enforces_max_writers() {
        let mut ctx = new_ctx();
        // Fill to MAX_WRITERS (1 already exists: the creator).
        for i in 1..MAX_WRITERS {
            ctx.add_writer(format!("did:dht:z6MkWriter{i}").into()).unwrap();
        }
        assert_eq!(ctx.writers().len(), MAX_WRITERS);

        let result = ctx.add_writer("did:dht:z6MkWriterOverflow".into());
        assert!(matches!(result, Err(DiscoveryContextError::WriterTierFull)));
    }

    // -- Reader management ------------------------------------------------

    #[test]
    fn add_reader_succeeds() {
        let mut ctx = new_ctx();
        ctx.add_reader(READER_DID.into()).unwrap();
        assert_eq!(ctx.readers().len(), 1);
    }

    #[test]
    fn add_reader_deduplicates() {
        let mut ctx = new_ctx();
        ctx.add_reader(READER_DID.into()).unwrap();
        ctx.add_reader(READER_DID.into()).unwrap();
        assert_eq!(ctx.readers().len(), 1);
    }

    #[test]
    fn add_reader_rejects_invalid_did() {
        let mut ctx = new_ctx();
        let result = ctx.add_reader("bad-did".into());
        assert!(matches!(
            result,
            Err(DiscoveryContextError::DidNotAuthenticated { .. })
        ));
    }

    #[test]
    fn readers_are_unbounded() {
        let mut ctx = new_ctx();
        // Add more readers than the writer limit.
        for i in 0..(MAX_WRITERS + 100) {
            ctx.add_reader(format!("did:dht:z6MkReader{i}").into()).unwrap();
        }
        assert_eq!(ctx.readers().len(), MAX_WRITERS + 100);
    }

    // -- agent_register ---------------------------------------------------

    #[test]
    fn agent_register_succeeds() {
        let mut ctx = new_ctx();
        let params = register_params(AGENT_A_DID, &["code_review", "testing"]);

        let result = ctx
            .agent_register(&params, WRITER_DID, 1_700_000_000)
            .unwrap();
        assert!(result.registered);
        assert!(!result.entry_id.is_empty());

        // Verify entry is stored.
        let entry = ctx.get_entry(AGENT_A_DID).unwrap();
        assert_eq!(entry.did, AGENT_A_DID);
        assert_eq!(entry.capabilities, vec!["code_review", "testing"]);
        assert_eq!(ctx.registry_len(), 1);
    }

    #[test]
    fn agent_register_records_event() {
        let mut ctx = new_ctx();
        let params = register_params(AGENT_A_DID, &["testing"]);
        ctx.agent_register(&params, WRITER_DID, 1_700_000_000)
            .unwrap();

        assert_eq!(ctx.events().len(), 1);
        match &ctx.events()[0] {
            RegistrationEvent::Registered {
                entry,
                processed_by,
            } => {
                assert_eq!(entry.did, AGENT_A_DID);
                assert_eq!(processed_by, WRITER_DID);
            }
            other => panic!("expected Registered event, got {other:?}"),
        }
    }

    #[test]
    fn agent_register_rejects_non_writer() {
        let mut ctx = new_ctx();
        let params = register_params(AGENT_A_DID, &["testing"]);

        let result = ctx.agent_register(&params, "did:dht:z6MkNotWriter", 1_700_000_000);
        assert!(matches!(result, Err(DiscoveryContextError::WriterRequired)));
    }

    #[test]
    fn agent_register_rejects_duplicate() {
        let mut ctx = new_ctx();
        let params = register_params(AGENT_A_DID, &["testing"]);
        ctx.agent_register(&params, WRITER_DID, 1_700_000_000)
            .unwrap();

        let result = ctx.agent_register(&params, WRITER_DID, 1_700_000_001);
        assert!(matches!(
            result,
            Err(DiscoveryContextError::AlreadyRegistered { .. })
        ));
    }

    #[test]
    fn agent_register_rejects_invalid_did() {
        let mut ctx = new_ctx();
        let params = register_params("bad-did", &["testing"]);
        let result = ctx.agent_register(&params, WRITER_DID, 1_700_000_000);
        assert!(matches!(
            result,
            Err(DiscoveryContextError::DidNotAuthenticated { .. })
        ));
    }

    #[test]
    fn registrant_does_not_become_writer() {
        let mut ctx = new_ctx();
        let params = register_params(AGENT_A_DID, &["testing"]);
        ctx.agent_register(&params, WRITER_DID, 1_700_000_000)
            .unwrap();

        // Agent should NOT be a writer or reader.
        assert!(!ctx.is_writer(AGENT_A_DID));
        assert_eq!(ctx.writers().len(), 1);
    }

    #[test]
    fn agent_can_register_different_capabilities_in_different_contexts() {
        let mut ctx1 = DiscoveryContext::new("ctx-1".into(), WRITER_DID.into());
        let mut ctx2 = DiscoveryContext::new("ctx-2".into(), WRITER_DID.into());

        let params1 = register_params(AGENT_A_DID, &["code_review"]);
        let params2 = register_params(AGENT_A_DID, &["translation", "summarization"]);

        ctx1.agent_register(&params1, WRITER_DID, 1_700_000_000)
            .unwrap();
        ctx2.agent_register(&params2, WRITER_DID, 1_700_000_000)
            .unwrap();

        let entry1 = ctx1.get_entry(AGENT_A_DID).unwrap();
        let entry2 = ctx2.get_entry(AGENT_A_DID).unwrap();

        assert_eq!(entry1.capabilities, vec!["code_review"]);
        assert_eq!(entry2.capabilities, vec!["translation", "summarization"]);
    }

    // -- agent_search -----------------------------------------------------

    #[test]
    fn agent_search_returns_all_when_no_filters() {
        let mut ctx = new_ctx();
        ctx.agent_register(
            &register_params(AGENT_A_DID, &["code_review"]),
            WRITER_DID,
            100,
        )
        .unwrap();
        ctx.agent_register(&register_params(AGENT_B_DID, &["testing"]), WRITER_DID, 101)
            .unwrap();

        let result = ctx.agent_search(&AgentSearchParams::default());
        assert_eq!(result.total_matches, 2);
        assert_eq!(result.entries.len(), 2);
    }

    #[test]
    fn agent_search_filters_by_capability() {
        let mut ctx = new_ctx();
        ctx.agent_register(
            &register_params(AGENT_A_DID, &["code_review", "testing"]),
            WRITER_DID,
            100,
        )
        .unwrap();
        ctx.agent_register(&register_params(AGENT_B_DID, &["testing"]), WRITER_DID, 101)
            .unwrap();

        let params = AgentSearchParams {
            capability_filter: Some(vec!["code_review".to_owned()]),
            ..Default::default()
        };
        let result = ctx.agent_search(&params);
        assert_eq!(result.total_matches, 1);
        assert_eq!(result.entries[0].did, AGENT_A_DID);
    }

    #[test]
    fn agent_search_requires_all_capabilities() {
        let mut ctx = new_ctx();
        ctx.agent_register(
            &register_params(AGENT_A_DID, &["code_review", "testing"]),
            WRITER_DID,
            100,
        )
        .unwrap();
        ctx.agent_register(&register_params(AGENT_B_DID, &["testing"]), WRITER_DID, 101)
            .unwrap();

        let params = AgentSearchParams {
            capability_filter: Some(vec!["code_review".to_owned(), "testing".to_owned()]),
            ..Default::default()
        };
        let result = ctx.agent_search(&params);
        assert_eq!(result.total_matches, 1);
        assert_eq!(result.entries[0].did, AGENT_A_DID);
    }

    #[test]
    fn agent_search_filters_by_keyword() {
        let mut ctx = new_ctx();

        let mut params_a = register_params(AGENT_A_DID, &["code_review"]);
        params_a.metadata = serde_json::json!({"language": "rust"});
        ctx.agent_register(&params_a, WRITER_DID, 100).unwrap();

        let mut params_b = register_params(AGENT_B_DID, &["testing"]);
        params_b.metadata = serde_json::json!({"language": "python"});
        ctx.agent_register(&params_b, WRITER_DID, 101).unwrap();

        let search = AgentSearchParams {
            keywords: Some(vec!["rust".to_owned()]),
            ..Default::default()
        };
        let result = ctx.agent_search(&search);
        assert_eq!(result.total_matches, 1);
        assert_eq!(result.entries[0].did, AGENT_A_DID);
    }

    #[test]
    fn agent_search_respects_limit() {
        let mut ctx = new_ctx();
        for i in 0..10 {
            let did = format!("did:dht:z6MkAgent{i}");
            ctx.agent_register(&register_params(&did, &["testing"]), WRITER_DID, 100 + i)
                .unwrap();
        }

        let params = AgentSearchParams {
            limit: Some(3),
            ..Default::default()
        };
        let result = ctx.agent_search(&params);
        assert_eq!(result.total_matches, 10);
        assert_eq!(result.entries.len(), 3);
    }

    #[test]
    fn agent_search_empty_registry_returns_empty() {
        let ctx = new_ctx();
        let result = ctx.agent_search(&AgentSearchParams::default());
        assert_eq!(result.total_matches, 0);
        assert!(result.entries.is_empty());
    }

    // -- agent_update (self-service) --------------------------------------

    #[test]
    fn agent_update_succeeds() {
        let mut ctx = new_ctx();
        let params = register_params(AGENT_A_DID, &["code_review"]);
        ctx.agent_register(&params, WRITER_DID, 100).unwrap();

        ctx.agent_update(
            AGENT_A_DID,
            vec!["code_review".to_owned(), "testing".to_owned()],
            serde_json::json!({"updated": true}),
            WRITER_DID,
            200,
        )
        .unwrap();

        let entry = ctx.get_entry(AGENT_A_DID).unwrap();
        assert_eq!(entry.capabilities, vec!["code_review", "testing"]);
        assert_eq!(entry.registered_at, 200);
    }

    #[test]
    fn agent_update_records_event() {
        let mut ctx = new_ctx();
        let params = register_params(AGENT_A_DID, &["code_review"]);
        ctx.agent_register(&params, WRITER_DID, 100).unwrap();

        ctx.agent_update(
            AGENT_A_DID,
            vec!["testing".to_owned()],
            serde_json::json!({}),
            WRITER_DID,
            200,
        )
        .unwrap();

        assert_eq!(ctx.events().len(), 2);
        match &ctx.events()[1] {
            RegistrationEvent::Updated {
                entry,
                processed_by,
            } => {
                assert_eq!(entry.did, AGENT_A_DID);
                assert_eq!(processed_by, WRITER_DID);
            }
            other => panic!("expected Updated event, got {other:?}"),
        }
    }

    #[test]
    fn agent_update_rejects_non_writer() {
        let mut ctx = new_ctx();
        let params = register_params(AGENT_A_DID, &["code_review"]);
        ctx.agent_register(&params, WRITER_DID, 100).unwrap();

        let result = ctx.agent_update(
            AGENT_A_DID,
            vec![],
            serde_json::json!({}),
            "did:dht:z6MkNotWriter",
            200,
        );
        assert!(matches!(result, Err(DiscoveryContextError::WriterRequired)));
    }

    #[test]
    fn agent_update_rejects_non_registered() {
        let mut ctx = new_ctx();
        let result = ctx.agent_update(AGENT_A_DID, vec![], serde_json::json!({}), WRITER_DID, 200);
        assert!(matches!(
            result,
            Err(DiscoveryContextError::NotRegistered { .. })
        ));
    }

    #[test]
    fn agent_update_rejects_ownership_mismatch() {
        let mut ctx = new_ctx();
        let params = register_params(AGENT_A_DID, &["code_review"]);
        ctx.agent_register(&params, WRITER_DID, 100).unwrap();

        // Agent B tries to update Agent A's entry.
        let result = ctx.agent_update(AGENT_B_DID, vec![], serde_json::json!({}), WRITER_DID, 200);
        assert!(matches!(
            result,
            Err(DiscoveryContextError::NotRegistered { .. })
        ));
    }

    // -- agent_deregister -------------------------------------------------

    #[test]
    fn agent_deregister_succeeds() {
        let mut ctx = new_ctx();
        let params = register_params(AGENT_A_DID, &["testing"]);
        ctx.agent_register(&params, WRITER_DID, 100).unwrap();

        let deregister_params = AgentDeregisterParams {
            did: AGENT_A_DID.into(),
        };
        let result = ctx
            .agent_deregister(&deregister_params, AGENT_A_DID, WRITER_DID)
            .unwrap();
        assert!(result.removed);
        assert!(ctx.get_entry(AGENT_A_DID).is_none());
        assert_eq!(ctx.registry_len(), 0);
    }

    #[test]
    fn agent_deregister_records_event() {
        let mut ctx = new_ctx();
        let params = register_params(AGENT_A_DID, &["testing"]);
        ctx.agent_register(&params, WRITER_DID, 100).unwrap();

        let deregister_params = AgentDeregisterParams {
            did: AGENT_A_DID.into(),
        };
        ctx.agent_deregister(&deregister_params, AGENT_A_DID, WRITER_DID)
            .unwrap();

        assert_eq!(ctx.events().len(), 2);
        match &ctx.events()[1] {
            RegistrationEvent::Deregistered {
                did,
                entry_id,
                processed_by,
            } => {
                assert_eq!(did, AGENT_A_DID);
                assert!(!entry_id.is_empty());
                assert_eq!(processed_by, WRITER_DID);
            }
            other => panic!("expected Deregistered event, got {other:?}"),
        }
    }

    #[test]
    fn agent_deregister_rejects_non_writer() {
        let mut ctx = new_ctx();
        let params = register_params(AGENT_A_DID, &["testing"]);
        ctx.agent_register(&params, WRITER_DID, 100).unwrap();

        let deregister_params = AgentDeregisterParams {
            did: AGENT_A_DID.into(),
        };
        let result = ctx.agent_deregister(&deregister_params, AGENT_A_DID, "did:dht:z6MkNotWriter");
        assert!(matches!(result, Err(DiscoveryContextError::WriterRequired)));
    }

    #[test]
    fn agent_deregister_rejects_non_registered() {
        let mut ctx = new_ctx();
        let deregister_params = AgentDeregisterParams {
            did: AGENT_A_DID.into(),
        };
        let result = ctx.agent_deregister(&deregister_params, AGENT_A_DID, WRITER_DID);
        assert!(matches!(
            result,
            Err(DiscoveryContextError::NotRegistered { .. })
        ));
    }

    #[test]
    fn agent_deregister_rejects_ownership_mismatch() {
        let mut ctx = new_ctx();
        let params = register_params(AGENT_A_DID, &["testing"]);
        ctx.agent_register(&params, WRITER_DID, 100).unwrap();

        let deregister_params = AgentDeregisterParams {
            did: AGENT_A_DID.into(),
        };
        // Agent B tries to deregister Agent A.
        let result = ctx.agent_deregister(&deregister_params, AGENT_B_DID, WRITER_DID);
        assert!(matches!(
            result,
            Err(DiscoveryContextError::OwnershipMismatch { .. })
        ));
    }

    // -- Custom tools -----------------------------------------------------

    #[test]
    fn register_custom_tool_succeeds() {
        let mut ctx = new_ctx();
        ctx.register_custom_tool("reputation_score".to_owned())
            .unwrap();
        assert_eq!(ctx.custom_tools().len(), 1);
        assert_eq!(ctx.custom_tools()[0], "reputation_score");
    }

    #[test]
    fn register_custom_tool_deduplicates() {
        let mut ctx = new_ctx();
        ctx.register_custom_tool("reputation_score".to_owned())
            .unwrap();
        ctx.register_custom_tool("reputation_score".to_owned())
            .unwrap();
        assert_eq!(ctx.custom_tools().len(), 1);
    }

    #[test]
    fn register_custom_tool_rejects_standard_name() {
        let mut ctx = new_ctx();

        let result = ctx.register_custom_tool(TOOL_AGENT_SEARCH.to_owned());
        assert!(matches!(
            result,
            Err(DiscoveryContextError::StandardToolConflict { .. })
        ));

        let result = ctx.register_custom_tool(TOOL_AGENT_REGISTER.to_owned());
        assert!(matches!(
            result,
            Err(DiscoveryContextError::StandardToolConflict { .. })
        ));

        let result = ctx.register_custom_tool(TOOL_AGENT_DEREGISTER.to_owned());
        assert!(matches!(
            result,
            Err(DiscoveryContextError::StandardToolConflict { .. })
        ));
    }

    // -- Standard tool schemas --------------------------------------------

    #[test]
    fn agent_search_schema_is_valid_json_object() {
        let schema = DiscoveryContext::agent_search_schema();
        assert!(schema.is_object());
        assert_eq!(schema["type"], "object");
    }

    #[test]
    fn agent_register_schema_is_valid_json_object() {
        let schema = DiscoveryContext::agent_register_schema();
        assert!(schema.is_object());
        assert_eq!(schema["type"], "object");
        assert!(
            schema["required"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("did"))
        );
    }

    #[test]
    fn agent_deregister_schema_is_valid_json_object() {
        let schema = DiscoveryContext::agent_deregister_schema();
        assert!(schema.is_object());
        assert_eq!(schema["type"], "object");
        assert!(
            schema["required"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("did"))
        );
    }

    // -- Serialization roundtrips -----------------------------------------

    #[test]
    fn membership_tier_serialization_roundtrip() {
        for tier in [MembershipTier::Writer, MembershipTier::Reader] {
            let json = serde_json::to_string(&tier).unwrap();
            let deserialized: MembershipTier = serde_json::from_str(&json).unwrap();
            assert_eq!(tier, deserialized);
        }
    }

    #[test]
    fn agent_search_params_serialization_roundtrip() {
        let params = AgentSearchParams {
            capability_filter: Some(vec!["code_review".to_owned()]),
            keywords: Some(vec!["rust".to_owned()]),
            limit: Some(10),
        };
        let json = serde_json::to_string(&params).unwrap();
        let deserialized: AgentSearchParams = serde_json::from_str(&json).unwrap();
        assert_eq!(params, deserialized);
    }

    #[test]
    fn agent_register_params_serialization_roundtrip() {
        let params = AgentRegisterParams {
            did: AGENT_A_DID.into(),
            capabilities: vec!["testing".to_owned()],
            metadata: serde_json::json!({"key": "value"}),
        };
        let json = serde_json::to_string(&params).unwrap();
        let deserialized: AgentRegisterParams = serde_json::from_str(&json).unwrap();
        assert_eq!(params, deserialized);
    }

    #[test]
    fn agent_deregister_params_serialization_roundtrip() {
        let params = AgentDeregisterParams {
            did: AGENT_A_DID.into(),
        };
        let json = serde_json::to_string(&params).unwrap();
        let deserialized: AgentDeregisterParams = serde_json::from_str(&json).unwrap();
        assert_eq!(params, deserialized);
    }

    #[test]
    fn agent_register_result_serialization_roundtrip() {
        let result = AgentRegisterResult {
            registered: true,
            entry_id: "reg-1".to_owned(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: AgentRegisterResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }

    #[test]
    fn agent_deregister_result_serialization_roundtrip() {
        let result = AgentDeregisterResult { removed: true };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: AgentDeregisterResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }

    #[test]
    fn registration_event_serialization_roundtrip() {
        let entry = RegistrationEntry {
            did: AGENT_A_DID.into(),
            capabilities: vec!["testing".to_owned()],
            metadata: serde_json::json!({}),
            entry_id: "reg-1".to_owned(),
            registered_at: 1_700_000_000,
        };

        let event = RegistrationEvent::Registered {
            entry,
            processed_by: WRITER_DID.into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: RegistrationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, deserialized);
    }

    // -- Error display messages -------------------------------------------

    #[test]
    fn error_display_messages() {
        let err = DiscoveryContextError::WriterTierFull;
        assert!(err.to_string().contains("500"));

        let err = DiscoveryContextError::DidNotAuthenticated {
            did: "bad".into(),
        };
        assert!(err.to_string().contains("bad"));

        let err = DiscoveryContextError::AlreadyRegistered {
            did: AGENT_A_DID.into(),
        };
        assert!(err.to_string().contains(AGENT_A_DID));

        let err = DiscoveryContextError::NotRegistered {
            did: AGENT_A_DID.into(),
        };
        assert!(err.to_string().contains(AGENT_A_DID));

        let err = DiscoveryContextError::OwnershipMismatch {
            requester: AGENT_B_DID.to_owned(),
            owner: AGENT_A_DID.to_owned(),
        };
        assert!(err.to_string().contains(AGENT_B_DID));
        assert!(err.to_string().contains(AGENT_A_DID));

        let err = DiscoveryContextError::WriterRequired;
        assert!(err.to_string().contains("writer"));

        let err = DiscoveryContextError::StandardToolConflict {
            name: "agent_search".to_owned(),
        };
        assert!(err.to_string().contains("agent_search"));
    }

    // -- is_standard_tool -------------------------------------------------

    #[test]
    fn is_standard_tool_detects_standard_names() {
        assert!(is_standard_tool(TOOL_AGENT_SEARCH));
        assert!(is_standard_tool(TOOL_AGENT_REGISTER));
        assert!(is_standard_tool(TOOL_AGENT_DEREGISTER));
        assert!(!is_standard_tool("custom_tool"));
        assert!(!is_standard_tool(""));
    }

    // -- validate_did -----------------------------------------------------

    #[test]
    fn validate_did_accepts_valid() {
        assert!(validate_did("did:dht:z6MkTest").is_ok());
        assert!(validate_did("did:web:example.com").is_ok());
    }

    #[test]
    fn validate_did_rejects_empty() {
        assert!(validate_did("").is_err());
    }

    #[test]
    fn validate_did_rejects_missing_prefix() {
        assert!(validate_did("not-a-did").is_err());
    }

    // -- Entry ID generation is monotonic ---------------------------------

    #[test]
    fn entry_ids_are_unique_and_monotonic() {
        let mut ctx = new_ctx();

        let r1 = ctx
            .agent_register(&register_params(AGENT_A_DID, &["a"]), WRITER_DID, 100)
            .unwrap();
        let r2 = ctx
            .agent_register(&register_params(AGENT_B_DID, &["b"]), WRITER_DID, 101)
            .unwrap();

        assert_ne!(r1.entry_id, r2.entry_id);
        assert_eq!(r1.entry_id, "reg-1");
        assert_eq!(r2.entry_id, "reg-2");
    }

    // -- Full lifecycle: register -> search -> update -> search -> deregister

    #[test]
    fn full_lifecycle_register_search_update_deregister() {
        let mut ctx = new_ctx();

        // Register.
        let params = register_params(AGENT_A_DID, &["code_review"]);
        ctx.agent_register(&params, WRITER_DID, 100).unwrap();

        // Search finds the agent.
        let search = AgentSearchParams {
            capability_filter: Some(vec!["code_review".to_owned()]),
            ..Default::default()
        };
        let result = ctx.agent_search(&search);
        assert_eq!(result.total_matches, 1);

        // Update capabilities.
        ctx.agent_update(
            AGENT_A_DID,
            vec!["code_review".to_owned(), "testing".to_owned()],
            serde_json::json!({"version": 2}),
            WRITER_DID,
            200,
        )
        .unwrap();

        // Search with new capability filter.
        let search = AgentSearchParams {
            capability_filter: Some(vec!["testing".to_owned()]),
            ..Default::default()
        };
        let result = ctx.agent_search(&search);
        assert_eq!(result.total_matches, 1);

        // Deregister.
        let deregister_params = AgentDeregisterParams {
            did: AGENT_A_DID.into(),
        };
        ctx.agent_deregister(&deregister_params, AGENT_A_DID, WRITER_DID)
            .unwrap();

        // Search returns empty.
        let result = ctx.agent_search(&AgentSearchParams::default());
        assert_eq!(result.total_matches, 0);

        // Events logged all operations: register + update + deregister.
        assert_eq!(ctx.events().len(), 3);
    }

    // -- AgentSearchResult serialization ----------------------------------

    #[test]
    fn agent_search_result_serialization_roundtrip() {
        let result = AgentSearchResult {
            entries: vec![RegistrationEntry {
                did: AGENT_A_DID.into(),
                capabilities: vec!["testing".to_owned()],
                metadata: serde_json::json!({}),
                entry_id: "reg-1".to_owned(),
                registered_at: 1_700_000_000,
            }],
            total_matches: 1,
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: AgentSearchResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }
}
