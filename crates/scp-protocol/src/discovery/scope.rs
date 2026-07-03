//! Scope tools: register, lookup, and deregister namespace-to-context mappings.
//!
//! Implements §22.3.5 Scope Tools: three standard tool schemas for contexts that
//! serve as namespace registries. Scope tools map human-readable scope names
//! (e.g., `cooking-community`) to context IDs with relay URLs.
//!
//! All scope types are independent structs (ADR-043). `ScopeRegistry` uses
//! separate storage from `HandleRegistry` — scope entries and handle entries
//! never share storage. `ScopeTarget` is context-only by construction — no
//! identity variant exists.
//!
//! See ADR-043 for the design decision and security analysis.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use scp_clock::Clock;
use scp_did::DID;

use super::ContextId;
use super::addressing::AddressingError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Standard tool name for scope registration.
pub const TOOL_SCOPE_REGISTER: &str = "scope_register";

/// Standard tool name for scope lookup.
pub const TOOL_SCOPE_LOOKUP: &str = "scope_lookup";

/// Standard tool name for scope deregistration.
pub const TOOL_SCOPE_DEREGISTER: &str = "scope_deregister";

/// Maximum length for a scope name (§22.3.5).
const MAX_SCOPE_NAME_LENGTH: usize = 64;

/// Maximum length for a scope metadata description (§22.3.5).
const MAX_SCOPE_DESCRIPTION_LENGTH: usize = 1024;

/// Maximum number of tags in scope metadata (§22.3.5).
const MAX_SCOPE_TAGS_COUNT: usize = 20;

/// Maximum length for a single tag in scope metadata (§22.3.5).
const MAX_SCOPE_TAG_LENGTH: usize = 64;

/// Maximum number of relay URLs per scope target (§22.3.5).
const MAX_RELAY_URLS_COUNT: usize = 10;

/// Maximum number of entries in a single scope registry (§22.3.5).
const MAX_SCOPE_ENTRIES: usize = 10_000;

// ---------------------------------------------------------------------------
// ScopeRegisterParams / ScopeRegisterResult (§22.3.5)
// ---------------------------------------------------------------------------

/// Input parameters for the `scope_register` tool.
///
/// Registers a scope name (namespace) pointing to a context. The registrant's
/// DID is authenticated via the DID-signed request at the transport layer.
///
/// See §22.3.5 Scope Tools and ADR-043.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScopeRegisterParams {
    /// The scope name to register (e.g., `"cooking-community"`).
    /// Must match `[a-z0-9-]`, max 64 chars, no leading/trailing hyphens.
    pub name: String,
    /// Context the scope name resolves to (context-only by construction).
    pub target: ScopeTarget,
    /// Optional descriptive metadata.
    pub metadata: Option<ScopeMetadata>,
}

/// Optional metadata attached to a scope registration.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScopeMetadata {
    /// Human-readable description of the scope (max 1024 chars).
    pub description: Option<String>,
    /// Tags for categorization (max 20 items, each max 64 chars).
    pub tags: Option<Vec<String>>,
}

/// Output of the `scope_register` tool.
///
/// Returns an unambiguous status: `Registered` on success, `Conflict` when
/// another DID already holds the scope name, `Updated` when the same owner
/// re-registers (atomic update).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScopeRegisterResult {
    /// Outcome of the registration attempt.
    pub status: ScopeRegisterStatus,
    /// Present when `status` is `Registered` or `Updated`.
    pub entry_id: Option<String>,
}

/// The outcome of a scope registration attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScopeRegisterStatus {
    /// The scope name was successfully registered.
    Registered,
    /// Another DID already holds this scope name.
    Conflict,
    /// The same owner re-registered with updated target/metadata (atomic update).
    Updated,
}

// ---------------------------------------------------------------------------
// ScopeLookupParams / ScopeLookupResult (§22.3.5)
// ---------------------------------------------------------------------------

/// Input parameters for the `scope_lookup` tool.
///
/// Looks up a scope name in a scope registry. Available to readers
/// (DID-authenticated, unbounded tier).
///
/// See §22.3.5 Scope Tools.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScopeLookupParams {
    /// The scope name to look up (e.g., `"cooking-community"`).
    pub name: String,
}

/// Output of the `scope_lookup` tool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScopeLookupResult {
    /// The lookup results. All entries are context targets (enforced by
    /// `ScopeTarget` construction).
    pub results: Vec<ScopeEntry>,
}

// ---------------------------------------------------------------------------
// ScopeDeregisterParams / ScopeDeregisterResult (§22.3.5)
// ---------------------------------------------------------------------------

/// Input parameters for the `scope_deregister` tool.
///
/// Removes a scope registration. The `did` field is explicit (not inferred
/// from request signature) so the ownership check is visible in the interface.
///
/// See §22.3.5 Scope Tools.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScopeDeregisterParams {
    /// The scope name to deregister.
    pub name: String,
    /// The registrant's DID (must match the entry owner).
    pub did: DID,
}

/// Output of the `scope_deregister` tool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScopeDeregisterResult {
    /// Whether the scope was actually removed.
    pub removed: bool,
}

// ---------------------------------------------------------------------------
// ScopeEntry / ScopeTarget (§22.3.5)
// ---------------------------------------------------------------------------

/// A single scope entry in the registry.
///
/// Maps a scope name to a context ID with relay URLs. Context-only by
/// construction — `ScopeTarget` has no identity variant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScopeEntry {
    /// The scope name (normalized, validated).
    pub name: String,
    /// What the scope resolves to (context-only by construction).
    pub target: ScopeTarget,
    /// The DID that owns this registration.
    pub owner_did: DID,
    /// Unix timestamp (seconds) when registered.
    pub registered_at: u64,
    /// Descriptive metadata.
    pub metadata: ScopeMetadata,
    /// Unique entry identifier.
    pub entry_id: String,
}

/// What a scope name resolves to. Context-only by construction — has no
/// identity variant. See ADR-043.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScopeTarget {
    /// The context ID the scope points to.
    pub context_id: ContextId,
    /// Relay URLs for connecting to the context.
    pub relay_urls: Vec<String>,
}

// ---------------------------------------------------------------------------
// ScopeRegistrationEvent (§22.3.5)
// ---------------------------------------------------------------------------

/// Events produced by scope operations in the context event log.
///
/// These are scope-specific event types distinct from handle registration
/// events and governance events. Events are produced by the calling layer
/// when recording scope operations in the context event log, not by
/// `ScopeRegistry` methods directly (matching `HandleRegistry` pattern).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, tag = "type")]
pub enum ScopeRegistrationEvent {
    /// A scope name was registered.
    ScopeRegistered {
        /// The scope name.
        name: String,
        /// The target context ID.
        context_id: ContextId,
        /// Relay URLs for the target context.
        relay_urls: Vec<String>,
        /// The DID that registered the scope.
        owner_did: DID,
        /// Unique entry identifier.
        entry_id: String,
        /// Descriptive metadata.
        metadata: ScopeMetadata,
        /// Unix timestamp (seconds).
        timestamp: u64,
    },
    /// A scope entry was updated by the same owner.
    ScopeUpdated {
        /// The scope name.
        name: String,
        /// The updated target context ID.
        context_id: ContextId,
        /// The updated relay URLs.
        relay_urls: Vec<String>,
        /// The DID that owns the scope.
        owner_did: DID,
        /// Unique entry identifier (unchanged from original registration).
        entry_id: String,
        /// Updated descriptive metadata.
        metadata: ScopeMetadata,
        /// Unix timestamp (seconds).
        timestamp: u64,
    },
    /// A scope registration was removed.
    ScopeDeregistered {
        /// The scope name that was removed.
        name: String,
        /// The DID that owned the scope.
        owner_did: DID,
        /// The entry identifier that was removed.
        entry_id: String,
        /// Unix timestamp (seconds).
        timestamp: u64,
    },
}

// ---------------------------------------------------------------------------
// validate_scope_name
// ---------------------------------------------------------------------------

/// Validates a scope name per §22.3.5 rules.
///
/// Scope names are more constrained than general handle local-parts (§22.2):
/// - Charset: `[a-z0-9-]` only (no dots, no underscores)
/// - Length: 1-64 characters
/// - No leading or trailing hyphens
///
/// This is a **validator**, not a normalizer. It rejects non-conforming names
/// and returns an error. Callers must pass already-normalized names.
///
/// # Errors
///
/// Returns [`AddressingError`] if the name is invalid.
pub fn validate_scope_name(name: &str) -> Result<(), AddressingError> {
    if name.is_empty() {
        return Err(AddressingError::EmptyAddress);
    }
    if name.len() > MAX_SCOPE_NAME_LENGTH {
        return Err(AddressingError::LocalPartTooLong);
    }
    // Charset: [a-z0-9-] only
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(AddressingError::InvalidLocalPartCharacters);
    }
    // No leading or trailing hyphens
    if name.starts_with('-') || name.ends_with('-') {
        return Err(AddressingError::InvalidLocalPartBoundary);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// validate_scope_context_id
// ---------------------------------------------------------------------------

/// Validates a context ID for scope registration.
///
/// Context IDs must be non-empty, at most 256 characters, and contain only
/// ASCII alphanumeric characters, hyphens, or underscores.
///
/// # Errors
///
/// Returns [`ScopeRegistryError::Validation`] if the context ID is invalid.
fn validate_scope_context_id(context_id: &str) -> Result<(), ScopeRegistryError> {
    if context_id.is_empty() {
        return Err(ScopeRegistryError::Validation(
            "context_id must not be empty".into(),
        ));
    }
    if context_id.len() > 256 {
        return Err(ScopeRegistryError::Validation(
            "context_id exceeds 256 characters".into(),
        ));
    }
    if !context_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ScopeRegistryError::Validation(
            "context_id contains invalid characters: expected alphanumeric, hyphens, or underscores"
                .into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// validate_scope_metadata
// ---------------------------------------------------------------------------

/// Validates scope metadata bounds per §22.3.5 rules.
///
/// Checks description length (max 1024 chars) and tag constraints (max 20
/// tags, each non-empty and max 64 chars).
///
/// # Errors
///
/// Returns [`ScopeRegistryError::Validation`] if any constraint is violated.
fn validate_scope_metadata(metadata: &ScopeMetadata) -> Result<(), ScopeRegistryError> {
    if let Some(ref desc) = metadata.description
        && desc.len() > MAX_SCOPE_DESCRIPTION_LENGTH
    {
        return Err(ScopeRegistryError::Validation(format!(
            "description exceeds maximum length of {MAX_SCOPE_DESCRIPTION_LENGTH} characters"
        )));
    }
    if let Some(ref tags) = metadata.tags {
        if tags.len() > MAX_SCOPE_TAGS_COUNT {
            return Err(ScopeRegistryError::Validation(format!(
                "tags exceed maximum count of {MAX_SCOPE_TAGS_COUNT}"
            )));
        }
        for tag in tags {
            if tag.is_empty() {
                return Err(ScopeRegistryError::Validation(
                    "tag must not be empty".into(),
                ));
            }
            if tag.len() > MAX_SCOPE_TAG_LENGTH {
                return Err(ScopeRegistryError::Validation(format!(
                    "tag exceeds maximum length of {MAX_SCOPE_TAG_LENGTH} characters"
                )));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ScopeRegistry (in-memory reference implementation)
// ---------------------------------------------------------------------------

/// In-memory scope registry for a single context.
///
/// Enforces scope name uniqueness per the `validate_scope_name()` rules and
/// owner-only deregistration. Uses separate storage from `HandleRegistry` —
/// scope entries and handle entries never share storage.
///
/// Production implementations would back this with a persistent store and
/// event log recording.
///
/// See §22.3.5 Scope Tools and ADR-043.
#[derive(Debug)]
pub struct ScopeRegistry {
    /// The context ID this registry belongs to.
    context_id: ContextId,
    /// Scope entries keyed by normalized name.
    entries: HashMap<String, ScopeEntry>,
    /// Counter for generating entry IDs.
    next_entry_id: u64,
}

impl ScopeRegistry {
    /// Creates a new empty scope registry for the given context.
    #[must_use]
    pub fn new(context_id: ContextId) -> Self {
        Self {
            context_id,
            entries: HashMap::new(),
            next_entry_id: 1,
        }
    }

    /// Returns the context ID this registry belongs to.
    #[must_use]
    pub const fn context_id(&self) -> &ContextId {
        &self.context_id
    }

    /// Registers a scope name.
    ///
    /// The `registrant_did` is the DID of the authenticated caller (verified
    /// via DID-signed request at the transport layer).
    ///
    /// Returns `Registered` on success, `Conflict` if another DID already
    /// holds this scope name, or `Updated` if the same owner re-registers
    /// (atomic update to avoid TOCTOU race).
    ///
    /// Validates: scope name, `relay_urls` non-empty, metadata bounds.
    ///
    /// # Errors
    ///
    /// Returns [`AddressingError`] if the scope name is invalid.
    pub fn register(
        &mut self,
        params: &ScopeRegisterParams,
        registrant_did: &DID,
        clock: &dyn Clock,
    ) -> Result<ScopeRegisterResult, ScopeRegistryError> {
        // Validate the scope name
        validate_scope_name(&params.name)?;

        // Validate context_id
        validate_scope_context_id(&params.target.context_id)?;

        // Validate relay_urls non-empty
        if params.target.relay_urls.is_empty() {
            return Err(ScopeRegistryError::Validation(
                "relay_urls must contain at least one URL".to_owned(),
            ));
        }

        // Validate relay_urls count
        if params.target.relay_urls.len() > MAX_RELAY_URLS_COUNT {
            return Err(ScopeRegistryError::Validation(format!(
                "relay_urls exceeds maximum count of {MAX_RELAY_URLS_COUNT}"
            )));
        }

        // Validate individual relay URLs
        for url in &params.target.relay_urls {
            if url.len() > 2048 {
                return Err(ScopeRegistryError::Validation(
                    "relay URL exceeds 2048 characters".into(),
                ));
            }
            if url.bytes().any(|b| b == b'\r' || b == b'\n' || b < 0x20) {
                return Err(ScopeRegistryError::Validation(
                    "relay URL contains control characters".into(),
                ));
            }
            if !(url.starts_with("ws://")
                || url.starts_with("wss://")
                || url.starts_with("http://")
                || url.starts_with("https://"))
            {
                return Err(ScopeRegistryError::Validation(
                    "relay URL must use ws://, wss://, http://, or https:// scheme".into(),
                ));
            }
        }

        // Validate metadata bounds
        if let Some(ref metadata) = params.metadata {
            validate_scope_metadata(metadata)?;
        }

        let normalized = params.name.to_lowercase();
        let now = clock.now_secs();

        // Same-owner re-registration → atomic update (avoids TOCTOU race)
        if let Some(existing) = self.entries.get_mut(&normalized) {
            if existing.owner_did == *registrant_did {
                existing.target = params.target.clone();
                existing.metadata = params.metadata.clone().unwrap_or_default();
                existing.registered_at = now;
                return Ok(ScopeRegisterResult {
                    status: ScopeRegisterStatus::Updated,
                    entry_id: Some(existing.entry_id.clone()),
                });
            }
            // Different owner → conflict
            return Ok(ScopeRegisterResult {
                status: ScopeRegisterStatus::Conflict,
                entry_id: None,
            });
        }

        // Capacity check before new registration
        if self.entries.len() >= MAX_SCOPE_ENTRIES {
            return Err(ScopeRegistryError::Validation(
                "scope registry capacity exceeded (max 10,000 entries)".to_owned(),
            ));
        }

        // New registration
        //
        // NOTE: Sequential entry IDs are a known information leak — they reveal
        // registration volume to any observer. Production implementations SHOULD
        // use opaque IDs (e.g., UUIDs or random tokens) to avoid this. This
        // reference implementation uses sequential IDs to avoid adding a UUID
        // dependency.
        let entry_id = format!("scope-{}", self.next_entry_id);
        self.next_entry_id += 1;

        let entry = ScopeEntry {
            name: normalized.clone(),
            target: params.target.clone(),
            owner_did: registrant_did.clone(),
            registered_at: now,
            metadata: params.metadata.clone().unwrap_or_default(),
            entry_id: entry_id.clone(),
        };

        self.entries.insert(normalized, entry);

        Ok(ScopeRegisterResult {
            status: ScopeRegisterStatus::Registered,
            entry_id: Some(entry_id),
        })
    }

    /// Looks up a scope name.
    ///
    /// Returns matching entries. All entries are context targets by
    /// `ScopeTarget` construction.
    ///
    /// # Errors
    ///
    /// Returns [`ScopeRegistryError`] if the scope name is invalid.
    pub fn lookup(
        &self,
        params: &ScopeLookupParams,
    ) -> Result<ScopeLookupResult, ScopeRegistryError> {
        validate_scope_name(&params.name)?;
        let normalized = params.name.to_lowercase();

        let results = self.entries.get(&normalized).cloned().into_iter().collect();

        Ok(ScopeLookupResult { results })
    }

    /// Deregisters a scope name.
    ///
    /// Only succeeds if the provided DID matches the entry owner.
    ///
    /// # Errors
    ///
    /// Returns [`ScopeRegistryError`] if the scope name is invalid.
    pub fn deregister(
        &mut self,
        params: &ScopeDeregisterParams,
    ) -> Result<ScopeDeregisterResult, ScopeRegistryError> {
        validate_scope_name(&params.name)?;
        let normalized = params.name.to_lowercase();

        if let Some(entry) = self.entries.get(&normalized)
            && entry.owner_did == params.did
        {
            self.entries.remove(&normalized);
            return Ok(ScopeDeregisterResult { removed: true });
        }

        Ok(ScopeDeregisterResult { removed: false })
    }

    /// Returns the number of registered scopes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no scopes are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns an iterator over all scope entries.
    pub fn entries(&self) -> impl Iterator<Item = &ScopeEntry> {
        self.entries.values()
    }
}

// ---------------------------------------------------------------------------
// ScopeRegistryError
// ---------------------------------------------------------------------------

/// Errors produced by scope registry operations.
#[derive(Debug, thiserror::Error)]
pub enum ScopeRegistryError {
    /// The scope name failed validation.
    #[error("invalid scope name: {0}")]
    Addressing(#[from] AddressingError),

    /// A validation constraint was violated (`relay_urls`, metadata bounds).
    #[error("validation error: {0}")]
    Validation(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn make_target(context_id: &str) -> ScopeTarget {
        ScopeTarget {
            context_id: context_id.to_owned(),
            relay_urls: vec!["wss://relay.example.com".to_owned()],
        }
    }

    // -- ScopeRegisterParams serialization ------------------------------------

    #[test]
    fn scope_register_params_serialization_roundtrip() {
        let params = ScopeRegisterParams {
            name: "cooking-community".to_owned(),
            target: make_target("ctx-cooking"),
            metadata: Some(ScopeMetadata {
                description: Some("A cooking community".to_owned()),
                tags: Some(vec!["food".to_owned(), "recipes".to_owned()]),
            }),
        };

        let json = serde_json::to_string(&params).unwrap();
        let deserialized: ScopeRegisterParams = serde_json::from_str(&json).unwrap();
        assert_eq!(params, deserialized);
    }

    #[test]
    fn scope_register_result_serialization_roundtrip() {
        let result = ScopeRegisterResult {
            status: ScopeRegisterStatus::Registered,
            entry_id: Some("scope-1".to_owned()),
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: ScopeRegisterResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }

    #[test]
    fn scope_register_status_serde_lowercase() {
        let json = serde_json::to_string(&ScopeRegisterStatus::Registered).unwrap();
        assert_eq!(json, "\"registered\"");
        let json = serde_json::to_string(&ScopeRegisterStatus::Conflict).unwrap();
        assert_eq!(json, "\"conflict\"");
        let json = serde_json::to_string(&ScopeRegisterStatus::Updated).unwrap();
        assert_eq!(json, "\"updated\"");
    }

    // -- ScopeLookupResult serialization --------------------------------------

    #[test]
    fn scope_lookup_result_serialization_roundtrip() {
        let result = ScopeLookupResult {
            results: vec![ScopeEntry {
                name: "cooking-community".to_owned(),
                target: make_target("ctx-cooking"),
                owner_did: DID::from("did:dht:zAdmin"),
                registered_at: 1_700_000_000,
                metadata: ScopeMetadata::default(),
                entry_id: "scope-1".to_owned(),
            }],
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: ScopeLookupResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }

    // -- ScopeDeregisterResult serialization ----------------------------------

    #[test]
    fn scope_deregister_result_serialization_roundtrip() {
        let result = ScopeDeregisterResult { removed: true };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: ScopeDeregisterResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }

    // -- deny_unknown_fields enforcement --------------------------------------

    #[test]
    fn scope_lookup_result_rejects_unknown_fields() {
        let json = r#"{"results": [], "extra_field": true}"#;
        let result = serde_json::from_str::<ScopeLookupResult>(json);
        assert!(result.is_err());
    }

    #[test]
    fn scope_deregister_result_rejects_unknown_fields() {
        let json = r#"{"removed": true, "extra_field": true}"#;
        let result = serde_json::from_str::<ScopeDeregisterResult>(json);
        assert!(result.is_err());
    }

    // -- ScopeRegistrationEvent serialization ---------------------------------

    #[test]
    fn scope_registration_event_registered_roundtrip() {
        let event = ScopeRegistrationEvent::ScopeRegistered {
            name: "cooking".to_owned(),
            context_id: "ctx-cooking".to_owned(),
            relay_urls: vec!["wss://r.example.com".to_owned()],
            owner_did: DID::from("did:dht:zOwner"),
            entry_id: "scope-1".to_owned(),
            metadata: ScopeMetadata::default(),
            timestamp: 1_700_000_000,
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: ScopeRegistrationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, deserialized);
    }

    #[test]
    fn scope_registration_event_updated_roundtrip() {
        let event = ScopeRegistrationEvent::ScopeUpdated {
            name: "cooking".to_owned(),
            context_id: "ctx-cooking-v2".to_owned(),
            relay_urls: vec!["wss://r2.example.com".to_owned()],
            owner_did: DID::from("did:dht:zOwner"),
            entry_id: "scope-1".to_owned(),
            metadata: ScopeMetadata::default(),
            timestamp: 1_700_000_001,
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: ScopeRegistrationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, deserialized);
    }

    #[test]
    fn scope_registration_event_deregistered_roundtrip() {
        let event = ScopeRegistrationEvent::ScopeDeregistered {
            name: "cooking".to_owned(),
            owner_did: DID::from("did:dht:zOwner"),
            entry_id: "scope-1".to_owned(),
            timestamp: 1_700_000_002,
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: ScopeRegistrationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, deserialized);
    }

    // -- validate_scope_name --------------------------------------------------

    #[test]
    fn validate_scope_name_valid() {
        assert!(validate_scope_name("cooking-community").is_ok());
        assert!(validate_scope_name("a").is_ok());
        assert!(validate_scope_name("a-b-c").is_ok());
        assert!(validate_scope_name("abc123").is_ok());
        assert!(validate_scope_name("my-scope-42").is_ok());
    }

    #[test]
    fn validate_scope_name_rejects_empty() {
        assert!(matches!(
            validate_scope_name(""),
            Err(AddressingError::EmptyAddress)
        ));
    }

    #[test]
    fn validate_scope_name_rejects_too_long() {
        let long_name = "a".repeat(65);
        assert!(matches!(
            validate_scope_name(&long_name),
            Err(AddressingError::LocalPartTooLong)
        ));
    }

    #[test]
    fn validate_scope_name_accepts_max_length() {
        let max_name = "a".repeat(64);
        assert!(validate_scope_name(&max_name).is_ok());
    }

    #[test]
    fn validate_scope_name_rejects_dots() {
        assert!(matches!(
            validate_scope_name("cooking.community"),
            Err(AddressingError::InvalidLocalPartCharacters)
        ));
        assert!(matches!(
            validate_scope_name("a.b"),
            Err(AddressingError::InvalidLocalPartCharacters)
        ));
    }

    #[test]
    fn validate_scope_name_rejects_underscores() {
        assert!(matches!(
            validate_scope_name("cooking_community"),
            Err(AddressingError::InvalidLocalPartCharacters)
        ));
    }

    #[test]
    fn validate_scope_name_rejects_uppercase() {
        assert!(matches!(
            validate_scope_name("Cooking"),
            Err(AddressingError::InvalidLocalPartCharacters)
        ));
    }

    #[test]
    fn validate_scope_name_rejects_special_chars() {
        assert!(matches!(
            validate_scope_name("cook!ng"),
            Err(AddressingError::InvalidLocalPartCharacters)
        ));
        assert!(matches!(
            validate_scope_name("cook@ng"),
            Err(AddressingError::InvalidLocalPartCharacters)
        ));
        assert!(matches!(
            validate_scope_name("cook ng"),
            Err(AddressingError::InvalidLocalPartCharacters)
        ));
    }

    #[test]
    fn validate_scope_name_rejects_leading_hyphen() {
        assert!(matches!(
            validate_scope_name("-cooking"),
            Err(AddressingError::InvalidLocalPartBoundary)
        ));
    }

    #[test]
    fn validate_scope_name_rejects_trailing_hyphen() {
        assert!(matches!(
            validate_scope_name("cooking-"),
            Err(AddressingError::InvalidLocalPartBoundary)
        ));
    }

    // -- ScopeRegistry: register ----------------------------------------------

    #[test]
    fn register_scope_returns_registered_status() {
        let mut registry = ScopeRegistry::new("ctx-bootstrap".to_owned());
        let params = ScopeRegisterParams {
            name: "cooking-community".to_owned(),
            target: make_target("ctx-cooking"),
            metadata: None,
        };

        let result = registry
            .register(
                &params,
                &DID::from("did:dht:zAdmin"),
                &scp_clock::SystemClock,
            )
            .unwrap();
        assert_eq!(result.status, ScopeRegisterStatus::Registered);
        assert!(result.entry_id.is_some());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn register_scope_returns_conflict_for_different_owner() {
        let mut registry = ScopeRegistry::new("ctx-bootstrap".to_owned());
        let admin_did = DID::from("did:dht:zAdmin");
        let eve_did = DID::from("did:dht:zEve");

        let params = ScopeRegisterParams {
            name: "cooking-community".to_owned(),
            target: make_target("ctx-cooking"),
            metadata: None,
        };

        let r1 = registry
            .register(&params, &admin_did, &scp_clock::SystemClock)
            .unwrap();
        assert_eq!(r1.status, ScopeRegisterStatus::Registered);

        let params2 = ScopeRegisterParams {
            name: "cooking-community".to_owned(),
            target: make_target("ctx-evil"),
            metadata: None,
        };
        let r2 = registry
            .register(&params2, &eve_did, &scp_clock::SystemClock)
            .unwrap();
        assert_eq!(r2.status, ScopeRegisterStatus::Conflict);
        assert!(r2.entry_id.is_none());
        // Original entry unchanged
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn register_scope_same_owner_returns_updated() {
        let mut registry = ScopeRegistry::new("ctx-bootstrap".to_owned());
        let admin_did = DID::from("did:dht:zAdmin");

        let params = ScopeRegisterParams {
            name: "cooking-community".to_owned(),
            target: make_target("ctx-cooking-v1"),
            metadata: None,
        };
        let r1 = registry
            .register(&params, &admin_did, &scp_clock::SystemClock)
            .unwrap();
        assert_eq!(r1.status, ScopeRegisterStatus::Registered);
        let original_entry_id = r1.entry_id.unwrap();

        let params2 = ScopeRegisterParams {
            name: "cooking-community".to_owned(),
            target: make_target("ctx-cooking-v2"),
            metadata: Some(ScopeMetadata {
                description: Some("Updated".to_owned()),
                tags: None,
            }),
        };
        let r2 = registry
            .register(&params2, &admin_did, &scp_clock::SystemClock)
            .unwrap();
        assert_eq!(r2.status, ScopeRegisterStatus::Updated);
        assert_eq!(r2.entry_id.as_deref(), Some(original_entry_id.as_str()));

        // Entry count unchanged
        assert_eq!(registry.len(), 1);

        // Verify the entry was updated
        let lookup = registry
            .lookup(&ScopeLookupParams {
                name: "cooking-community".to_owned(),
            })
            .unwrap();
        assert_eq!(lookup.results.len(), 1);
        assert_eq!(lookup.results[0].target.context_id, "ctx-cooking-v2");
        assert_eq!(
            lookup.results[0].metadata.description.as_deref(),
            Some("Updated")
        );
    }

    #[test]
    fn register_scope_case_insensitive() {
        let mut registry = ScopeRegistry::new("ctx-bootstrap".to_owned());
        let admin_did = DID::from("did:dht:zAdmin");

        // Register with lowercase
        let params = ScopeRegisterParams {
            name: "cooking".to_owned(),
            target: make_target("ctx-cooking"),
            metadata: None,
        };
        registry
            .register(&params, &admin_did, &scp_clock::SystemClock)
            .unwrap();

        // Try to register same name — should return Updated (same owner)
        let params2 = ScopeRegisterParams {
            name: "cooking".to_owned(),
            target: make_target("ctx-cooking-v2"),
            metadata: None,
        };
        let r = registry
            .register(&params2, &admin_did, &scp_clock::SystemClock)
            .unwrap();
        assert_eq!(r.status, ScopeRegisterStatus::Updated);
    }

    #[test]
    fn register_scope_rejects_dot_in_name() {
        let mut registry = ScopeRegistry::new("ctx-bootstrap".to_owned());
        let result = registry.register(
            &ScopeRegisterParams {
                name: "cooking.community".to_owned(),
                target: make_target("ctx-cooking"),
                metadata: None,
            },
            &DID::from("did:dht:zAdmin"),
            &scp_clock::SystemClock,
        );
        assert!(result.is_err());
    }

    #[test]
    fn register_scope_rejects_empty_context_id() {
        let mut registry = ScopeRegistry::new("ctx-bootstrap".to_owned());
        let result = registry.register(
            &ScopeRegisterParams {
                name: "cooking".to_owned(),
                target: ScopeTarget {
                    context_id: String::new(),
                    relay_urls: vec!["wss://r.example.com".to_owned()],
                },
                metadata: None,
            },
            &DID::from("did:dht:zAdmin"),
            &scp_clock::SystemClock,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("context_id must not be empty"), "{err}");
    }

    #[test]
    fn register_scope_rejects_context_id_too_long() {
        let mut registry = ScopeRegistry::new("ctx-bootstrap".to_owned());
        let result = registry.register(
            &ScopeRegisterParams {
                name: "cooking".to_owned(),
                target: ScopeTarget {
                    context_id: "x".repeat(257),
                    relay_urls: vec!["wss://r.example.com".to_owned()],
                },
                metadata: None,
            },
            &DID::from("did:dht:zAdmin"),
            &scp_clock::SystemClock,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("context_id exceeds 256 characters"), "{err}");
    }

    #[test]
    fn register_scope_rejects_context_id_with_invalid_chars() {
        let mut registry = ScopeRegistry::new("ctx-bootstrap".to_owned());
        // Spaces are not allowed
        let result = registry.register(
            &ScopeRegisterParams {
                name: "cooking".to_owned(),
                target: ScopeTarget {
                    context_id: "ctx with spaces".to_owned(),
                    relay_urls: vec!["wss://r.example.com".to_owned()],
                },
                metadata: None,
            },
            &DID::from("did:dht:zAdmin"),
            &scp_clock::SystemClock,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("context_id contains invalid characters"),
            "{err}"
        );

        // Slashes are not allowed
        let result = registry.register(
            &ScopeRegisterParams {
                name: "cooking".to_owned(),
                target: ScopeTarget {
                    context_id: "ctx/path".to_owned(),
                    relay_urls: vec!["wss://r.example.com".to_owned()],
                },
                metadata: None,
            },
            &DID::from("did:dht:zAdmin"),
            &scp_clock::SystemClock,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("context_id contains invalid characters"),
            "{err}"
        );

        // Control characters are not allowed
        let result = registry.register(
            &ScopeRegisterParams {
                name: "cooking".to_owned(),
                target: ScopeTarget {
                    context_id: "ctx\x00evil".to_owned(),
                    relay_urls: vec!["wss://r.example.com".to_owned()],
                },
                metadata: None,
            },
            &DID::from("did:dht:zAdmin"),
            &scp_clock::SystemClock,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("context_id contains invalid characters"),
            "{err}"
        );
    }

    #[test]
    fn register_scope_accepts_max_length_context_id() {
        let mut registry = ScopeRegistry::new("ctx-bootstrap".to_owned());
        let result = registry.register(
            &ScopeRegisterParams {
                name: "cooking".to_owned(),
                target: ScopeTarget {
                    context_id: "x".repeat(256),
                    relay_urls: vec!["wss://r.example.com".to_owned()],
                },
                metadata: None,
            },
            &DID::from("did:dht:zAdmin"),
            &scp_clock::SystemClock,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn register_scope_rejects_empty_relay_urls() {
        let mut registry = ScopeRegistry::new("ctx-bootstrap".to_owned());
        let result = registry.register(
            &ScopeRegisterParams {
                name: "cooking".to_owned(),
                target: ScopeTarget {
                    context_id: "ctx-cooking".to_owned(),
                    relay_urls: vec![],
                },
                metadata: None,
            },
            &DID::from("did:dht:zAdmin"),
            &scp_clock::SystemClock,
        );
        assert!(result.is_err());
    }

    #[test]
    fn register_scope_rejects_description_too_long() {
        let mut registry = ScopeRegistry::new("ctx-bootstrap".to_owned());
        let result = registry.register(
            &ScopeRegisterParams {
                name: "cooking".to_owned(),
                target: make_target("ctx-cooking"),
                metadata: Some(ScopeMetadata {
                    description: Some("x".repeat(1025)),
                    tags: None,
                }),
            },
            &DID::from("did:dht:zAdmin"),
            &scp_clock::SystemClock,
        );
        assert!(result.is_err());
    }

    #[test]
    fn register_scope_rejects_too_many_tags() {
        let mut registry = ScopeRegistry::new("ctx-bootstrap".to_owned());
        let tags: Vec<String> = (0..21).map(|i| format!("tag-{i}")).collect();
        let result = registry.register(
            &ScopeRegisterParams {
                name: "cooking".to_owned(),
                target: make_target("ctx-cooking"),
                metadata: Some(ScopeMetadata {
                    description: None,
                    tags: Some(tags),
                }),
            },
            &DID::from("did:dht:zAdmin"),
            &scp_clock::SystemClock,
        );
        assert!(result.is_err());
    }

    #[test]
    fn register_scope_rejects_tag_too_long() {
        let mut registry = ScopeRegistry::new("ctx-bootstrap".to_owned());
        let result = registry.register(
            &ScopeRegisterParams {
                name: "cooking".to_owned(),
                target: make_target("ctx-cooking"),
                metadata: Some(ScopeMetadata {
                    description: None,
                    tags: Some(vec!["x".repeat(65)]),
                }),
            },
            &DID::from("did:dht:zAdmin"),
            &scp_clock::SystemClock,
        );
        assert!(result.is_err());
    }

    // -- ScopeRegistry: lookup ------------------------------------------------

    #[test]
    fn lookup_existing_scope_returns_entry() {
        let mut registry = ScopeRegistry::new("ctx-bootstrap".to_owned());
        let admin_did = DID::from("did:dht:zAdmin");

        registry
            .register(
                &ScopeRegisterParams {
                    name: "cooking-community".to_owned(),
                    target: make_target("ctx-cooking"),
                    metadata: None,
                },
                &admin_did,
                &scp_clock::SystemClock,
            )
            .unwrap();

        let lookup = registry
            .lookup(&ScopeLookupParams {
                name: "cooking-community".to_owned(),
            })
            .unwrap();
        assert_eq!(lookup.results.len(), 1);
        assert_eq!(lookup.results[0].name, "cooking-community");
        assert_eq!(lookup.results[0].target.context_id, "ctx-cooking");
        assert_eq!(lookup.results[0].owner_did, admin_did);
    }

    #[test]
    fn lookup_nonexistent_scope_returns_empty() {
        let registry = ScopeRegistry::new("ctx-bootstrap".to_owned());
        let lookup = registry
            .lookup(&ScopeLookupParams {
                name: "nonexistent".to_owned(),
            })
            .unwrap();
        assert!(lookup.results.is_empty());
    }

    // -- ScopeRegistry: deregister --------------------------------------------

    #[test]
    fn deregister_by_owner_succeeds() {
        let mut registry = ScopeRegistry::new("ctx-bootstrap".to_owned());
        let admin_did = DID::from("did:dht:zAdmin");

        registry
            .register(
                &ScopeRegisterParams {
                    name: "cooking".to_owned(),
                    target: make_target("ctx-cooking"),
                    metadata: None,
                },
                &admin_did,
                &scp_clock::SystemClock,
            )
            .unwrap();

        let result = registry
            .deregister(&ScopeDeregisterParams {
                name: "cooking".to_owned(),
                did: admin_did,
            })
            .unwrap();
        assert!(result.removed);
        assert!(registry.is_empty());
    }

    #[test]
    fn deregister_by_non_owner_fails() {
        let mut registry = ScopeRegistry::new("ctx-bootstrap".to_owned());
        let admin_did = DID::from("did:dht:zAdmin");
        let eve_did = DID::from("did:dht:zEve");

        registry
            .register(
                &ScopeRegisterParams {
                    name: "cooking".to_owned(),
                    target: make_target("ctx-cooking"),
                    metadata: None,
                },
                &admin_did,
                &scp_clock::SystemClock,
            )
            .unwrap();

        let result = registry
            .deregister(&ScopeDeregisterParams {
                name: "cooking".to_owned(),
                did: eve_did,
            })
            .unwrap();
        assert!(!result.removed);
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn deregister_nonexistent_scope_returns_false() {
        let mut registry = ScopeRegistry::new("ctx-bootstrap".to_owned());
        let result = registry
            .deregister(&ScopeDeregisterParams {
                name: "nonexistent".to_owned(),
                did: DID::from("did:dht:zAdmin"),
            })
            .unwrap();
        assert!(!result.removed);
    }

    // -- re-register after deregister -----------------------------------------

    #[test]
    fn re_register_after_deregister_succeeds() {
        let mut registry = ScopeRegistry::new("ctx-bootstrap".to_owned());
        let admin_did = DID::from("did:dht:zAdmin");
        let bob_did = DID::from("did:dht:zBob");

        registry
            .register(
                &ScopeRegisterParams {
                    name: "cooking".to_owned(),
                    target: make_target("ctx-cooking"),
                    metadata: None,
                },
                &admin_did,
                &scp_clock::SystemClock,
            )
            .unwrap();

        registry
            .deregister(&ScopeDeregisterParams {
                name: "cooking".to_owned(),
                did: admin_did,
            })
            .unwrap();

        let result = registry
            .register(
                &ScopeRegisterParams {
                    name: "cooking".to_owned(),
                    target: make_target("ctx-cooking-new"),
                    metadata: None,
                },
                &bob_did,
                &scp_clock::SystemClock,
            )
            .unwrap();
        assert_eq!(result.status, ScopeRegisterStatus::Registered);
    }

    // -- entry ID uniqueness --------------------------------------------------

    #[test]
    fn register_generates_unique_entry_ids() {
        let mut registry = ScopeRegistry::new("ctx-bootstrap".to_owned());

        let r1 = registry
            .register(
                &ScopeRegisterParams {
                    name: "scope-a".to_owned(),
                    target: make_target("ctx-a"),
                    metadata: None,
                },
                &DID::from("did:dht:zAdmin"),
                &scp_clock::SystemClock,
            )
            .unwrap();

        let r2 = registry
            .register(
                &ScopeRegisterParams {
                    name: "scope-b".to_owned(),
                    target: make_target("ctx-b"),
                    metadata: None,
                },
                &DID::from("did:dht:zAdmin"),
                &scp_clock::SystemClock,
            )
            .unwrap();

        assert_ne!(r1.entry_id, r2.entry_id);
    }

    // -- ScopeTarget serialization --------------------------------------------

    #[test]
    fn scope_target_serialization_roundtrip() {
        let target = ScopeTarget {
            context_id: "ctx-cooking".to_owned(),
            relay_urls: vec![
                "wss://r1.example.com".to_owned(),
                "wss://r2.example.com".to_owned(),
            ],
        };
        let json = serde_json::to_string(&target).unwrap();
        let deserialized: ScopeTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(target, deserialized);
    }

    // -- Metadata bounds acceptance -------------------------------------------

    #[test]
    fn register_scope_accepts_max_description() {
        let mut registry = ScopeRegistry::new("ctx-bootstrap".to_owned());
        let result = registry.register(
            &ScopeRegisterParams {
                name: "cooking".to_owned(),
                target: make_target("ctx-cooking"),
                metadata: Some(ScopeMetadata {
                    description: Some("x".repeat(1024)),
                    tags: None,
                }),
            },
            &DID::from("did:dht:zAdmin"),
            &scp_clock::SystemClock,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn register_scope_accepts_max_tags() {
        let mut registry = ScopeRegistry::new("ctx-bootstrap".to_owned());
        let tags: Vec<String> = (0..20).map(|i| format!("tag-{i}")).collect();
        let result = registry.register(
            &ScopeRegisterParams {
                name: "cooking".to_owned(),
                target: make_target("ctx-cooking"),
                metadata: Some(ScopeMetadata {
                    description: None,
                    tags: Some(tags),
                }),
            },
            &DID::from("did:dht:zAdmin"),
            &scp_clock::SystemClock,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn register_scope_accepts_max_tag_length() {
        let mut registry = ScopeRegistry::new("ctx-bootstrap".to_owned());
        let result = registry.register(
            &ScopeRegisterParams {
                name: "cooking".to_owned(),
                target: make_target("ctx-cooking"),
                metadata: Some(ScopeMetadata {
                    description: None,
                    tags: Some(vec!["x".repeat(64)]),
                }),
            },
            &DID::from("did:dht:zAdmin"),
            &scp_clock::SystemClock,
        );
        assert!(result.is_ok());
    }
}
